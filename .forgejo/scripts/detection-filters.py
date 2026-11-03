#!/usr/bin/env python3
#
# Writes the Investigation dashboard's Detections queries from the alert rules (every rule with a
# mitre_tactic label, in both vmalerts), so that clicking a detection can set the Events filter to
# the lines its rule counts: its LogsQL before the first pipe. A metrics rule has no lines, it gets
# the Events filter's default.
#
# The queries are when each alert first and last fired (MetricsQL on ALERTS), with three labels for
# the link: filter (label_map on alertname, the filters as raw strings, so one can't have a
# backtick), and link_ip and link_user (the client and user, .* when the alert has none).
#
# Lint runs it with --check, which fails when the dashboard is out of date with the rules.
#
# Usage:
# detection-filters.py [--check]

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = sorted(ROOT.glob("apps/base/monitoring/vmalert*/rules/*.yml"))
DASHBOARD = ROOT / "apps/base/monitoring/grafana/dashboards/Security/investigation.json"

LABELS = "alertname, mitre_tactic, mitre_technique, severity, remote_ip, user, host"
ALERTS = 'ALERTS{alertstate="firing", mitre_tactic!="", remote_ip=~"${ip}", user=~"${user}"}[$__range]'

# Quoted strings (LogsQL's three quotes) and anything else but a pipe.
HEAD = re.compile(r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`|[^"'`|])*""")


def filters(default: str) -> dict[str, str]:
    """Each detection's filter: its query before the first pipe, on one line."""
    found = {}
    for path in RULES:
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            for rule in group["rules"]:
                if "mitre_tactic" not in rule.get("labels", {}):
                    continue
                logs = group.get("type") == "vlogs"
                query = " ".join(HEAD.match(rule["expr"])[0].split()) if logs else default
                if "`" in query:
                    sys.exit(f"{path.relative_to(ROOT).as_posix()}: {rule['alert']}: a backtick in its filter")
                found[rule["alert"]] = query
    return found


def query(agg: str, over_time: str, pairs: str) -> str:
    rows = f"{agg} by ({LABELS}) ({over_time}({ALERTS})) * 1000"
    rows = f'label_map(label_copy({rows}, "alertname", "filter"), "filter", {pairs})'
    for link, label in (("link_ip", "remote_ip"), ("link_user", "user")):
        rows = f'label_replace({rows}, "{link}", "$1", "{label}", "(.+)")'
        rows = f'label_replace({rows}, "{link}", ".*", "{link}", "")'
    return rows


def main() -> None:
    dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    default = next(v["query"] for v in dashboard["templating"]["list"] if v["name"] == "filter")
    pairs = ", ".join(f'"{name}", `{logsql}`' for name, logsql in sorted(filters(default).items()))
    panel = next(p for p in dashboard["panels"] if p.get("title") == "Detections" and p["type"] == "table")
    panel["targets"] = [
        {
            "refId": ref,
            "datasource": {"type": "prometheus", "uid": "prometheus"},
            "expr": query(agg, over_time, pairs),
            "instant": True,
            "format": "table",
        }
        for ref, agg, over_time in (("A", "min", "tfirst_over_time"), ("B", "max", "tlast_over_time"))
    ]
    rendered = json.dumps(dashboard, indent=2, ensure_ascii=False) + "\n"
    if sys.argv[1:] != ["--check"]:
        DASHBOARD.write_text(rendered, encoding="utf-8", newline="\n")
    elif DASHBOARD.read_text(encoding="utf-8") != rendered:
        sys.exit(f"{DASHBOARD.name} out of date with the rules: run .forgejo/scripts/detection-filters.py")


if __name__ == "__main__":
    main()
