#!/usr/bin/env python3
#
# Writes the Security folder's ATT&CK coverage dashboard from the alert rules' labels: every rule
# with mitre_tactic/mitre_technique labels, in both vmalerts, as one table per tactic in ATT&CK's
# order (tactics without a rule listed as gaps). A rule's `tested` annotation (the date it was
# triggered on purpose and reached ntfy) is what makes it count as coverage. Rules whose labels are
# templates (Falco's: the tactic and technique come from each event's tags) are listed apart.
#
# It also writes the same rules as an ATT&CK Navigator layer (attack-navigator.json next to the
# dashboard; Grafana only loads the dashboards its kustomization lists): open it in
# https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload from local).
# Tested techniques score 2, untested 1, each with its rules' names as the comment; Falco's are
# left out.
#
# Lint runs it with --check, which fails when the dashboard or the layer is out of date with the
# rules.
#
# Usage:
# attack-coverage.py [--check]

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = sorted(ROOT.glob("apps/base/monitoring/vmalert*/rules/*.yml"))
OUTPUT = ROOT / "apps/base/monitoring/grafana/dashboards/Security/attack-coverage.json"
LAYER = ROOT / "apps/base/monitoring/grafana/dashboards/Security/attack-navigator.json"

# Enterprise ATT&CK's tactics, in its order.
TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def technique_link(technique: str) -> str:
    return f"[{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)"


def detections() -> list[dict]:
    found = []
    for path in RULES:
        for group in yaml.safe_load(path.read_text(encoding="utf-8")).get("groups", []):
            for rule in group.get("rules", []):
                labels = rule.get("labels", {})
                if "alert" not in rule or "mitre_tactic" not in labels:
                    continue
                dynamic = "{{" in labels["mitre_tactic"]
                if not dynamic and labels["mitre_tactic"] not in TACTICS:
                    sys.exit(
                        f"{path}: {rule['alert']}: unknown mitre_tactic {labels['mitre_tactic']!r}"
                    )
                found.append(
                    {
                        "alert": rule["alert"],
                        "tactic": labels["mitre_tactic"],
                        "technique": labels["mitre_technique"],
                        "source": labels.get("source", ""),
                        "severity": labels.get("severity", ""),
                        "tested": str(rule.get("annotations", {}).get("tested", "")),
                        "file": path.relative_to(ROOT).as_posix(),
                        "dynamic": dynamic,
                    }
                )
    return found


def markdown(all_rules: list[dict]) -> str:
    rules = [r for r in all_rules if not r["dynamic"]]
    dynamic = [r for r in all_rules if r["dynamic"]]
    tested = [r for r in rules if r["tested"]]
    covered = {r["tactic"] for r in tested}
    lines = [
        f"**{len(tested)} of {len(rules)} detections tested**, covering "
        f"{len({r['technique'] for r in tested})} techniques and {len(covered)} of "
        f"{len(TACTICS)} tactics. Untested rules alert, but don't count as coverage yet.",
        "",
        "| Tactic | Technique | Detection | Source | Severity | Tested |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for tactic in TACTICS:
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


def dashboard(rules: list[dict]) -> dict:
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
        "templating": {"list": []},
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
            {
                "type": "text",
                "title": "Detections by tactic",
                "id": 1,
                "description": "From the rules in {}. tested: the date the rule was last triggered on purpose "
                "and reached ntfy (its runbook annotation says how).".format(
                    ", ".join(sorted({r["file"].rsplit("/", 1)[0] for r in rules}))
                ),
                "gridPos": {"h": 24, "w": 16, "x": 0, "y": 0},
                "options": {"mode": "markdown", "content": markdown(rules)},
            },
            {
                "type": "table",
                "title": "Fired in range",
                "id": 2,
                "description": "How many alert instances each detection raised in the time range "
                "(VictoriaMetrics keeps 7 days of ALERTS).",
                "datasource": datasource,
                "gridPos": {"h": 24, "w": 8, "x": 16, "y": 0},
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


def layer(all_rules: list[dict]) -> dict:
    """An ATT&CK Navigator layer (format 4.5): an entry per technique and tactic with a rule."""
    cells: dict[tuple[str, str], list[dict]] = {}
    for r in all_rules:
        if not r["dynamic"]:
            cells.setdefault((r["technique"], r["tactic"]), []).append(r)
    techniques = []
    for (technique, tactic), rules in sorted(
        cells.items(), key=lambda cell: (TACTICS.index(cell[0][1]), cell[0][0])
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
        "versions": {"navigator": "5.2.0", "layer": "4.5"},
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
    rules = detections()
    outputs = {
        OUTPUT: json.dumps(dashboard(rules), indent=2) + "\n",
        LAYER: json.dumps(layer(rules), indent=2) + "\n",
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
