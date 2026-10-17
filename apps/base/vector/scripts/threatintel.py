"""vector-aggregator's threat intel (config/aggregator/threat-intel.yaml), run by its init
container (aggregator.yaml): abuse.ch's ThreatFox recent domains and IP:ports (the last 48
hours, CC0) and URLhaus's host file (hosts serving malware now), as one CSV table in $TI_DIR
that Vector looks values up in exactly.

Each feed's last good copy is kept (<feed>.csv): a feed that can't be fetched, or comes back
empty, keeps its previous rows, so the aggregator always starts. With no copy at all, a feed
adds nothing and says so: the table is then only what the others had (possibly no rows).
The aggregator is restarted every 6 hours to fetch them again (aggregator-refresh.yaml).
"""

import csv
import io
import ipaddress
import os
import sys
import urllib.request
from datetime import datetime

TI_DIR = os.environ.get("TI_DIR", "/var/lib/vector/threat")
TIMEOUT = 60
COLUMNS = ["value", "type", "provider", "description", "confidence", "first_seen", "reference"]


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "hirednoobs-homelab/vector-aggregator"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", "replace")


def address_type(value):
    """ipv4-addr or ipv6-addr for an address, None for anything else (a domain)."""
    try:
        return "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
    except ValueError:
        return None


def confidence(level):
    """ThreatFox's 0-100 as ECS's threat.indicator.confidence."""
    try:
        level = int(level)
    except ValueError:
        return "Not Specified"
    return "High" if level >= 75 else "Medium" if level >= 50 else "Low"


def threatfox(url):
    """ThreatFox's CSV export: quoted fields after a "# ..." header."""
    rows = []
    lines = [line for line in fetch(url).splitlines() if line and not line.startswith("#")]
    for record in csv.reader(lines, skipinitialspace=True):
        if len(record) < 10:
            continue
        first_seen, ioc_id, value, ioc_type, threat_type, _malware, _alias, malware, _last, level = record[:10]
        if ioc_type == "ip:port":
            value = value.rsplit(":", 1)[0].strip("[]")
        value = value.strip().lower()
        kind = address_type(value) or ("domain-name" if ioc_type == "domain" else None)
        if not value or kind is None:
            continue
        try:
            seen = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            seen = ""
        rows.append({
            "value": value,
            "type": kind,
            "provider": "ThreatFox",
            "description": f"{malware} ({threat_type})",
            "confidence": confidence(level),
            "first_seen": seen,
            "reference": f"https://threatfox.abuse.ch/ioc/{ioc_id}/",
        })
    return rows


def urlhaus_hosts(url):
    """URLhaus's host file: "127.0.0.1<tab><host>" per host serving malware now."""
    rows = []
    for line in fetch(url).splitlines():
        parts = line.split()
        if line.startswith("#") or len(parts) != 2:
            continue
        host = parts[1].strip().lower()
        rows.append({
            "value": host,
            "type": address_type(host) or "domain-name",
            "provider": "URLhaus",
            "description": "Malware distribution (payload_delivery)",
            "confidence": "Not Specified",
            "first_seen": "",
            "reference": f"https://urlhaus.abuse.ch/host/{host}/",
        })
    return rows


FEEDS = {
    "threatfox-domains": lambda: threatfox("https://threatfox.abuse.ch/export/csv/domains/recent/"),
    "threatfox-ip-port": lambda: threatfox("https://threatfox.abuse.ch/export/csv/ip-port/recent/"),
    "urlhaus-hosts": lambda: urlhaus_hosts("https://urlhaus.abuse.ch/downloads/hostfile/"),
}


def write_csv(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, path)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    os.makedirs(TI_DIR, exist_ok=True)
    table = []
    for name, get in FEEDS.items():
        cached = os.path.join(TI_DIR, name + ".csv")
        try:
            rows = get()
            if not rows:
                raise ValueError("no indicators in it")
            write_csv(cached, rows)
            print(f"{name}: {len(rows)} indicators")
        except Exception as error:  # Any failure: keep the last good copy.
            if os.path.exists(cached):
                rows = read_csv(cached)
                age = datetime.fromtimestamp(os.path.getmtime(cached)).strftime("%Y-%m-%d %H:%M")
                print(f"{name}: can't fetch it ({error}), keeping {len(rows)} from {age}")
            else:
                rows = []
                print(f"{name}: can't fetch it ({error}), and no copy: matching nothing from it", file=sys.stderr)
        table.extend(rows)

    # One row per value and provider: find_enrichment_table_records returns each match.
    unique = {}
    for row in table:
        unique.setdefault((row["value"], row["provider"]), row)
    write_csv(os.path.join(TI_DIR, "indicators.csv"), list(unique.values()))
    print(f"indicators.csv: {len(unique)} rows")


if __name__ == "__main__":
    main()
