#!/usr/bin/env python3
#
# Writes the Security folder's ATT&CK coverage dashboard from the alert rules' labels: every rule
# with mitre_tactic/mitre_technique labels, in both vmalerts. A rule's `tested` annotation (the
# date it was triggered on purpose and reached ntfy) is what makes it count as coverage. Rules
# whose labels are templates (Falco's: the tactic and technique come from each event's tags) are
# listed apart.
#
# The dashboard's first panel is the ATT&CK matrix as ATT&CK Navigator draws it: a column per
# tactic, a cell per technique, coloured by its rules (tested, untested, none), marked when its
# alerts fired in the time range, filtered by the Platforms variable. It's a Business Text panel
# (marcusolsson-dynamictext-panel): attack-matrix.js (next to this script) draws it from the
# coverage this script puts in front of it, attack-matrix.css styles it. Below it, the rules as one
# table per tactic and what fired in the range.
#
# The matrix is Enterprise ATT&CK as of attack-enterprise.json (next to this script), made from
# MITRE's STIX data by --update-attack <version> (the versions: the Enterprise ATT&CK collection in
# https://github.com/mitre-attack/attack-stix-data's index.json). Every rule's technique has to be
# in it, under the rule's tactic, so a new version that revokes or moves one fails here and in lint
# until the rule is relabelled (the error names MITRE's replacement).
#
# It also writes the same rules as an ATT&CK Navigator layer (attack-navigator.json next to the
# dashboard; Grafana only loads the dashboards its kustomization lists): open it in
# https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload from local).
# Tested techniques score 2, untested 1, each with its rules' names as the comment; Falco's are
# left out.
#
# Lint runs it with --check, which fails when the dashboard or the layer is out of date with the
# rules (it doesn't download anything).
#
# Usage:
# attack-coverage.py [--check]
# attack-coverage.py --update-attack <version>    e.g. 20.0, then run it again without arguments

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RULES = sorted(ROOT.glob("apps/base/monitoring/vmalert*/rules/*.yml"))
OUTPUT = ROOT / "apps/base/monitoring/grafana/dashboards/Security/attack-coverage.json"
LAYER = ROOT / "apps/base/monitoring/grafana/dashboards/Security/attack-navigator.json"
ATTACK = HERE / "attack-enterprise.json"
MATRIX_JS = HERE / "attack-matrix.js"
MATRIX_CSS = HERE / "attack-matrix.css"
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)

# What the matrix shows by default (the Platforms variable): what runs here. A technique on none of
# the selected platforms is left out unless a rule covers it or it fired.
DEFAULT_PLATFORMS = ["Containers", "Identity Provider", "Linux", "Network Devices", "PRE"]


def attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref["external_id"]
    return None


def update_attack(version: str) -> None:
    """Writes attack-enterprise.json from MITRE's STIX bundle of that Enterprise ATT&CK version."""
    url = STIX_URL.format(version=version)
    with urllib.request.urlopen(url, timeout=300) as response:
        raw = response.read()
    objects = json.loads(raw)["objects"]
    by_ref = {o["id"]: o for o in objects}

    def live(o: dict) -> bool:
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix" and live(o))
    tactics = [
        {"id": attack_id(by_ref[ref]), "shortname": by_ref[ref]["x_mitre_shortname"], "name": by_ref[ref]["name"]}
        for ref in matrix["tactic_refs"]
    ]
    techniques = {}
    for o in objects:
        if o["type"] == "attack-pattern" and live(o) and attack_id(o):
            techniques[attack_id(o)] = {
                "name": o["name"],
                "tactics": [
                    p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"
                ],
                "platforms": sorted(o.get("x_mitre_platforms", [])),
            }
    # Revoked techniques and what replaced them (followed to one that's live), for the rules' and
    # the fired alerts' older IDs (Falco's tags).
    revoked_by = {}
    for r in objects:
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by":
            source, target = by_ref.get(r["source_ref"]), by_ref.get(r["target_ref"])
            if source and target and source["type"] == "attack-pattern" and attack_id(source) and attack_id(target):
                revoked_by[attack_id(source)] = attack_id(target)
    revoked = {}
    for old in revoked_by:
        new, seen = revoked_by[old], {old}
        while new in revoked_by and new not in seen:
            seen.add(new)
            new = revoked_by[new]
        if new in techniques:
            revoked[old] = new
    data = {
        "version": version,
        "source": url,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "revoked": dict(sorted(revoked.items())),
    }
    ATTACK.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"{ATTACK.relative_to(ROOT).as_posix()}: Enterprise ATT&CK {version}, {len(techniques)} techniques")


def load_attack() -> dict:
    if not ATTACK.exists():
        sys.exit(f"{ATTACK.relative_to(ROOT).as_posix()} is missing: run attack-coverage.py --update-attack <version>")
    return json.loads(ATTACK.read_text(encoding="utf-8"))


def technique_link(technique: str) -> str:
    return f"[{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)"


def detections(attack: dict) -> list[dict]:
    tactics = [t["shortname"] for t in attack["tactics"]]
    found = []
    for path in RULES:
        for group in yaml.safe_load(path.read_text(encoding="utf-8")).get("groups", []):
            for rule in group.get("rules", []):
                labels = rule.get("labels", {})
                if "alert" not in rule or "mitre_tactic" not in labels:
                    continue
                where = f"{path.relative_to(ROOT).as_posix()}: {rule['alert']}"
                tactic, technique = labels["mitre_tactic"], labels["mitre_technique"]
                dynamic = "{{" in tactic
                if not dynamic:
                    if tactic not in tactics:
                        sys.exit(f"{where}: mitre_tactic {tactic!r} isn't in ATT&CK {attack['version']}")
                    if technique not in attack["techniques"]:
                        replacement = attack["revoked"].get(technique)
                        hint = f" (revoked, replaced by {replacement})" if replacement else ""
                        sys.exit(f"{where}: mitre_technique {technique} isn't in ATT&CK {attack['version']}{hint}")
                    if tactic not in attack["techniques"][technique]["tactics"]:
                        sys.exit(
                            f"{where}: {technique} is under {', '.join(attack['techniques'][technique]['tactics'])} "
                            f"in ATT&CK {attack['version']}, not {tactic}"
                        )
                found.append(
                    {
                        "alert": rule["alert"],
                        "tactic": tactic,
                        "technique": technique,
                        "source": labels.get("source", ""),
                        "severity": labels.get("severity", ""),
                        "tested": str(rule.get("annotations", {}).get("tested", "")),
                        "file": path.relative_to(ROOT).as_posix(),
                        "dynamic": dynamic,
                    }
                )
    return found


def markdown(all_rules: list[dict], attack: dict) -> str:
    rules = [r for r in all_rules if not r["dynamic"]]
    dynamic = [r for r in all_rules if r["dynamic"]]
    tested = [r for r in rules if r["tested"]]
    covered = {r["tactic"] for r in tested}
    lines = [
        f"**{len(tested)} of {len(rules)} detections tested**, covering "
        f"{len({r['technique'] for r in tested})} techniques and {len(covered)} of "
        f"{len(attack['tactics'])} tactics. Untested rules alert, but don't count as coverage yet.",
        "",
        "| Tactic | Technique | Detection | Source | Severity | Tested |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for tactic in (t["shortname"] for t in attack["tactics"]):
        rows = sorted(
            (r for r in rules if r["tactic"] == tactic),
            key=lambda r: (r["technique"], r["alert"]),
        )
        if not rows:
            lines.append(f"| {tactic} | | *no detections* | | | |")
        for r in rows:
            lines.append(
                f"| {tactic} | {technique_link(r['technique'])} | {r['alert']} | {r['source']} | "
                f"{r['severity']} | {r['tested'] or '**no**'} |"
            )
    if dynamic:
        lines += [
            "",
            "**Detections that take their ATT&CK labels from each event** (not counted above): "
            "they cover whatever their source's own rules are tagged with, and show under "
            "*Fired in range* as they fire.",
            "",
            "| Detection | Source | Tested |",
            "| --- | --- | --- |",
        ]
        for r in sorted(dynamic, key=lambda r: r["alert"]):
            lines.append(f"| {r['alert']} | {r['source']} | {r['tested'] or '**no**'} |")
    return "\n".join(lines) + "\n"


def matrix(all_rules: list[dict], attack: dict) -> dict:
    """What attack-matrix.js draws: the tactics' techniques with their rules, platforms as bits."""
    techniques = attack["techniques"]
    platforms = sorted({p for t in techniques.values() for p in t["platforms"]})
    bits = {p: 1 << i for i, p in enumerate(platforms)}
    cells: dict[tuple[str, str], list[dict]] = {}
    for r in all_rules:
        if not r["dynamic"]:
            cells.setdefault((r["technique"], r["tactic"]), []).append(r)

    def entry(technique: str, tactic: str) -> dict:
        rules = sorted(cells.get((technique, tactic), []), key=lambda r: r["alert"])
        tested = [f"{r['alert']} ({r['tested']})" for r in rules if r["tested"]]
        untested = [r["alert"] for r in rules if not r["tested"]]
        text = []
        if tested:
            text.append("Tested: " + ", ".join(tested))
        if untested:
            text.append("Untested: " + ", ".join(untested))
        return {
            "id": technique,
            "n": techniques[technique]["name"],
            "pf": sum(bits[p] for p in techniques[technique]["platforms"]),
            "st": 2 if tested else 1 if untested else 0,
            "r": "\n".join(text),
        }

    def by_name(technique: str) -> str:
        return techniques[technique]["name"]

    columns = []
    for tactic in attack["tactics"]:
        short = tactic["shortname"]
        parents = sorted(
            (t for t, info in techniques.items() if "." not in t and short in info["tactics"]),
            key=by_name,
        )
        column = []
        for parent in parents:
            cell = entry(parent, short)
            cell["subs"] = [
                entry(sub, short)
                for sub in sorted(
                    (t for t, info in techniques.items() if t.startswith(parent + ".") and short in info["tactics"]),
                    key=by_name,
                )
            ]
            column.append(cell)
        columns.append({"id": tactic["id"], "n": tactic["name"], "t": column})

    rules = [r for r in all_rules if not r["dynamic"]]
    return {
        "version": attack["version"],
        "platforms": platforms,
        "defaultPlatforms": DEFAULT_PLATFORMS,
        "covered": len({r["technique"] for r in rules}),
        "tested": len({r["technique"] for r in rules if r["tested"]}),
        "revoked": attack["revoked"],
        "tactics": columns,
    }


def matrix_panel(all_rules: list[dict], attack: dict, datasource: dict) -> dict:
    data = json.dumps(matrix(all_rules, attack), ensure_ascii=False, separators=(",", ":"))
    return {
        "type": "marcusolsson-dynamictext-panel",
        "title": f"ATT&CK matrix (Enterprise {attack['version']})",
        "id": 3,
        "description": "Every technique on the selected platforms, as ATT&CK Navigator draws them. Green: a tested "
        "rule covers it (in that tactic), yellow: only untested rules, a coloured edge: only its "
        "sub-techniques are covered (they're listed under it). A red edge and count: its alerts that "
        "fired in the time range (ALERTS, any rule with this technique, Falco's included; revoked IDs "
        "count for their replacements). Hover for the rules, click for the technique on attack.mitre.org. "
        "Techniques a rule covers or that fired are shown whatever the platforms.",
        "datasource": datasource,
        "gridPos": {"h": 30, "w": 24, "x": 0, "y": 0},
        "targets": [
            {
                "refId": "A",
                "datasource": datasource,
                "instant": True,
                "format": "table",
                "expr": "count by (mitre_technique) "
                '(count_over_time(ALERTS{alertstate="firing", mitre_technique!=""}[$__range]))',
            }
        ],
        "options": {
            "renderMode": "allRows",
            "wrap": False,
            "content": "{{attackMatrix}}",
            "defaultContent": "{{attackMatrix}}",
            "helpers": f"const MATRIX = {data};\n\n" + MATRIX_JS.read_text(encoding="utf-8"),
            "afterRender": "",
            "styles": MATRIX_CSS.read_text(encoding="utf-8"),
            "editors": ["helpers", "styles"],
            "editor": {"format": "none", "language": "html"},
            "externalStyles": [],
            "contentPartials": [],
            "status": "",
        },
    }


def platform_variable(attack: dict) -> dict:
    platforms = sorted({p for t in attack["techniques"].values() for p in t["platforms"]})
    return {
        "type": "custom",
        "name": "platform",
        "label": "Platforms",
        "description": "The platforms whose techniques the matrix shows (ATT&CK Navigator's platform filter).",
        "multi": True,
        "includeAll": True,
        "query": ",".join(platforms),
        "current": {"text": DEFAULT_PLATFORMS, "value": DEFAULT_PLATFORMS},
        "options": [{"text": p, "value": p, "selected": p in DEFAULT_PLATFORMS} for p in platforms],
    }


def dashboard(rules: list[dict], attack: dict) -> dict:
    datasource = {"type": "prometheus", "uid": "prometheus"}
    return {
        "uid": "security-attack-coverage",
        "title": "ATT&CK coverage",
        "description": "Generated by .forgejo/scripts/attack-coverage.py from the alert rules' labels: "
        "don't edit it in Grafana, change the rules and run the script.",
        "tags": ["security"],
        "editable": False,
        "graphTooltip": 1,
        "time": {"from": "now-7d", "to": "now"},
        "timezone": "browser",
        "schemaVersion": 39,
        "templating": {"list": [platform_variable(attack)]},
        "annotations": {"list": []},
        "links": [
            {
                "title": "Security",
                "type": "dashboards",
                "tags": ["security"],
                "asDropdown": False,
            }
        ],
        "panels": [
            matrix_panel(rules, attack, datasource),
            {
                "type": "text",
                "title": "Detections by tactic",
                "id": 1,
                "description": "From the rules in {}. tested: the date the rule was last triggered on purpose "
                "and reached ntfy (its runbook annotation says how).".format(
                    ", ".join(sorted({r["file"].rsplit("/", 1)[0] for r in rules}))
                ),
                "gridPos": {"h": 24, "w": 16, "x": 0, "y": 30},
                "options": {"mode": "markdown", "content": markdown(rules, attack)},
            },
            {
                "type": "table",
                "title": "Fired in range",
                "id": 2,
                "description": "How many alert instances each detection raised in the time range "
                "(VictoriaMetrics keeps 7 days of ALERTS).",
                "datasource": datasource,
                "gridPos": {"h": 24, "w": 8, "x": 16, "y": 30},
                "targets": [
                    {
                        "refId": "A",
                        "datasource": datasource,
                        "instant": True,
                        "format": "table",
                        "expr": "count by (alertname, mitre_technique) "
                        '(count_over_time(ALERTS{alertstate="firing", mitre_tactic!=""}[$__range]))',
                    }
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {
                                "alertname": "Detection",
                                "mitre_technique": "Technique",
                                "Value": "Instances",
                            },
                        },
                    },
                    {
                        "id": "sortBy",
                        "options": {"sort": [{"field": "Instances", "desc": True}]},
                    },
                ],
                "fieldConfig": {"defaults": {"noValue": "None fired"}, "overrides": []},
                "options": {"showHeader": True, "cellHeight": "sm"},
            },
        ],
        "id": None,
    }


def layer(all_rules: list[dict], attack: dict) -> dict:
    """An ATT&CK Navigator layer (format 4.5): an entry per technique and tactic with a rule."""
    tactics = [t["shortname"] for t in attack["tactics"]]
    cells: dict[tuple[str, str], list[dict]] = {}
    for r in all_rules:
        if not r["dynamic"]:
            cells.setdefault((r["technique"], r["tactic"]), []).append(r)
    techniques = []
    for (technique, tactic), rules in sorted(
        cells.items(), key=lambda cell: (tactics.index(cell[0][1]), cell[0][0])
    ):
        rules.sort(key=lambda r: r["alert"])
        techniques.append(
            {
                "techniqueID": technique,
                "tactic": tactic,
                "score": 2 if any(r["tested"] for r in rules) else 1,
                "comment": "\n".join(
                    f"{r['alert']} ({'tested ' + r['tested'] if r['tested'] else 'untested'})"
                    for r in rules
                ),
                "enabled": True,
            }
        )
    return {
        "name": "Homelab detections",
        "versions": {"attack": attack["version"].split(".")[0], "navigator": "5.2.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated by .forgejo/scripts/attack-coverage.py from the alert rules' labels: "
        "2 tested (triggered on purpose and reached ntfy), 1 alerts but untested. Rules that take "
        "their labels from each event (Falco's) aren't in it.",
        "layout": {"layout": "side", "showID": True, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffe766", "#8ec843"], "minValue": 1, "maxValue": 2},
        "legendItems": [
            {"label": "Tested detection", "color": "#8ec843"},
            {"label": "Untested detection", "color": "#ffe766"},
        ],
    }


def main() -> None:
    if sys.argv[1:2] == ["--update-attack"]:
        if len(sys.argv) != 3:
            sys.exit("Usage: attack-coverage.py --update-attack <version>")
        update_attack(sys.argv[2])
        return
    attack = load_attack()
    rules = detections(attack)
    outputs = {
        OUTPUT: json.dumps(dashboard(rules, attack), indent=2, ensure_ascii=False) + "\n",
        LAYER: json.dumps(layer(rules, attack), indent=2) + "\n",
    }
    if sys.argv[1:] == ["--check"]:
        stale = [
            path.relative_to(ROOT).as_posix()
            for path, rendered in outputs.items()
            if not path.exists() or path.read_text(encoding="utf-8") != rendered
        ]
        if stale:
            sys.exit(
                f"{', '.join(stale)} out of date with the rules: "
                "run .forgejo/scripts/attack-coverage.py"
            )
        return
    for path, rendered in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
