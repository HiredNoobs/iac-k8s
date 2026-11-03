"""vector-aggregator's threat intel (config/aggregator/threat-intel.yaml), run by its init container
and every 6 hours by its refresh container (aggregator.yaml): abuse.ch's ThreatFox domains and
IP:ports (its API, the last 2 days, CC0) and URLhaus's host file (hosts serving malware now), both
with the account's key ($ABUSECH_AUTH_KEY), and Spamhaus's DROP, IPv4 and IPv6 (networks run by
criminals, free to use under https://www.spamhaus.org/drop/terms/), as one CSV table in $TI_DIR
that Vector looks values up in (a name's parents and an address's networks too,
threat-intel.yaml).

Each feed's last good copy is kept (<feed>.csv): a feed that can't be fetched, or comes back
empty, keeps its previous rows, so the aggregator always starts. With no copy at all, a feed
adds nothing and says so: the table is then only what the others had (possibly no rows).
The table is replaced whole (os.replace), as Vector reloads it when it changes (--watch-config).
"""

import csv
import ipaddress
import json
import os
import sys
import urllib.request
from datetime import datetime

TI_DIR = os.environ.get("TI_DIR", "/var/lib/vector/threat")
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "")
TIMEOUT = 60
COLUMNS = ["value", "type", "provider", "description", "confidence", "first_seen", "reference"]


def fetch(url, data=None, headers=None):
    """GET, or POST data as JSON."""
    headers = {"User-Agent": "hirednoobs-homelab/vector-aggregator", **(headers or {})}
    if data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", "replace")


def abusech_key():
    if not ABUSECH_AUTH_KEY:
        raise ValueError("no ABUSECH_AUTH_KEY")
    return ABUSECH_AUTH_KEY


def redact(text):
    """The key never in a log line (an error with its URL in it)."""
    return text.replace(ABUSECH_AUTH_KEY, "<ABUSECH_AUTH_KEY>") if ABUSECH_AUTH_KEY else text


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
    except (TypeError, ValueError):
        return "Not Specified"
    return "High" if level >= 75 else "Medium" if level >= 50 else "Low"


def threatfox(url):
    """ThreatFox's API: the last 2 days' IOCs, as {"query_status", "data": [...]}. Only domains and
    IP:ports, its URLs and hashes aren't looked up."""
    response = json.loads(fetch(url, {"query": "get_iocs", "days": 2}, {"Auth-Key": abusech_key()}))
    status = response.get("query_status")
    if status == "no_result":
        return []
    if status != "ok":
        raise ValueError(f"query_status {status}")
    rows = []
    for ioc in response.get("data") or []:
        value, ioc_type = str(ioc.get("ioc") or ""), ioc.get("ioc_type")
        if ioc_type == "ip:port":
            value = value.rsplit(":", 1)[0].strip("[]")
        value = value.strip().lower()
        kind = address_type(value) or ("domain-name" if ioc_type == "domain" else None)
        if not value or kind is None:
            continue
        try:
            seen = datetime.strptime(ioc.get("first_seen") or "", "%Y-%m-%d %H:%M:%S UTC")
            seen = seen.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            seen = ""
        rows.append({
            "value": value,
            "type": kind,
            "provider": "ThreatFox",
            "description": f"{ioc.get('malware_printable')} ({ioc.get('threat_type')})",
            "confidence": confidence(ioc.get("confidence_level")),
            "first_seen": seen,
            "reference": f"https://threatfox.abuse.ch/ioc/{ioc.get('id')}/",
        })
    return rows


def urlhaus_hosts(url):
    """URLhaus's host file: a host serving malware now per line, as "127.0.0.1<tab><host>" or the
    host alone."""
    rows = []
    for line in fetch(url).splitlines():
        parts = line.split()
        if line.startswith("#") or len(parts) not in (1, 2):
            continue
        host = parts[-1].strip().lower()
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


# The prefix lengths threat-intel.yaml looks an address's networks up at.
PREFIXES = {4: range(8, 33), 6: range(16, 65)}


def spamhaus_drop(url):
    """Spamhaus's DROP as JSON lines: {"cidr", "sblid", "rir"} per network, then a metadata line.
    Networks are written as Vector's ip_subnet writes them (Python's and Rust's forms agree)."""
    rows = []
    for line in fetch(url).splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if "cidr" not in record:
            continue
        network = ipaddress.ip_network(record["cidr"], strict=False)
        if network.prefixlen not in PREFIXES[network.version]:
            print(f"{url}: {network} is outside the prefix lengths looked up, it can't match", file=sys.stderr)
            continue
        sbl = record.get("sblid", "")
        rows.append({
            "value": str(network),
            "type": "ipv6-addr" if network.version == 6 else "ipv4-addr",
            "provider": "Spamhaus",
            "description": f"DROP {sbl} ({network})",
            "confidence": "High",
            "first_seen": "",
            "reference": f"https://check.spamhaus.org/sbl/query/{sbl}",
        })
    return rows


FEEDS = {
    "threatfox": lambda: threatfox("https://threatfox-api.abuse.ch/api/v1/"),
    # The key in the URL.
    "urlhaus-hosts": lambda: urlhaus_hosts(f"https://urlhaus-api.abuse.ch/v2/files/exports/{abusech_key()}/hostfile.txt"),
    "spamhaus-drop-v4": lambda: spamhaus_drop("https://www.spamhaus.org/drop/drop_v4.json"),
    "spamhaus-drop-v6": lambda: spamhaus_drop("https://www.spamhaus.org/drop/drop_v6.json"),
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
            error = redact(str(error))
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
