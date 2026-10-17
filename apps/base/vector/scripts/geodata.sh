#!/bin/sh
# vector-aggregator's geo data (config/aggregator/geo.yaml), run by its init container
# (aggregator.yaml): DB-IP's IP to City Lite and IP to ASN Lite (https://db-ip.com/db/lite.php,
# CC BY 4.0, monthly) into $GEO_DIR as city.mmdb and asn.mmdb. Each file is this month's, else
# last month's (a new month's is out a few days in), else the copy already there: the pod starts
# with old data when DB-IP can't be reached, and only fails without any. A file that's already
# the newest month isn't downloaded again, so restarts are cheap (aggregator-refresh.yaml restarts
# the aggregator every 6 hours, for its threat intel).
set -eu

dir=${GEO_DIR:-/var/lib/vector/geo}
url=${GEO_URL:-https://download.db-ip.com/free}
mkdir -p "$dir"

month=$(date -u +%Y-%m)
year=${month%-*}
num=${month#*-}
num=${num#0}
if [ "$num" -eq 1 ]; then
  previous="$((year - 1))-12"
else
  previous=$(printf '%d-%02d' "$year" $((num - 1)))
fi

# fetch <DB-IP edition> <name>: $dir/<name>.mmdb, its month in $dir/<name>.month.
fetch() {
  edition=$1
  name=$2
  have=$(cat "$dir/$name.month" 2>/dev/null || true)
  for m in "$month" "$previous"; do
    if [ "$have" = "$m" ]; then
      echo "$name: $m, up to date"
      return 0
    fi
    # A step at a time, each failure with its exit code and message (137: killed, out of memory).
    rm -f "$dir/$name.gz" "$dir/$name.tmp"
    rc=0
    out=$(wget -q -T 60 -O "$dir/$name.gz" "$url/$edition-$m.mmdb.gz" 2>&1) || rc=$?
    if [ "$rc" -ne 0 ]; then
      echo "$name: $m: download failed (exit $rc): $out"
      continue
    fi
    out=$(gunzip -c "$dir/$name.gz" 2>&1 > "$dir/$name.tmp") || rc=$?
    if [ "$rc" -ne 0 ]; then
      echo "$name: $m: unpacking failed (exit $rc): $out"
      continue
    fi
    # The smallest, ASN, is about 9 MB: anything under 1 MB isn't the database.
    size=$(wc -c < "$dir/$name.tmp")
    if [ "$size" -lt 1000000 ]; then
      echo "$name: $m: only $size bytes"
      continue
    fi
    mv "$dir/$name.tmp" "$dir/$name.mmdb"
    rm -f "$dir/$name.gz"
    echo "$m" > "$dir/$name.month"
    echo "$name: downloaded $m ($size bytes)"
    return 0
  done
  rm -f "$dir/$name.gz" "$dir/$name.tmp"
  if [ -s "$dir/$name.mmdb" ]; then
    echo "$name: keeping ${have:-an older copy}"
    return 0
  fi
  echo "$name: no data, the aggregator can't start without it" >&2
  return 1
}

fetch dbip-city-lite city
fetch dbip-asn-lite asn
