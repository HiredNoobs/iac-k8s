#!/bin/sh
# vector-aggregator's geo data (config/aggregator/geo.yaml), run by its init container
# (aggregator.yaml): DB-IP's IP to City Lite and IP to ASN Lite (https://db-ip.com/db/lite.php,
# CC BY 4.0, monthly) into $GEO_DIR as city.mmdb and asn.mmdb. Each file is this month's, else
# last month's (a new month's is out a few days in), else the copy already there: the pod starts
# with old data when DB-IP can't be reached. Without any copy (a new volume), an empty database:
# Vector can't start without the file, and with this one its lines just have no geo fields until
# a later start downloads the data (vmalert-logs' VectorGeoDataMissing). A file that's already
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

# byte <n>...: those bytes. str <s>: s as an MMDB string (its type and length, then the text).
byte() {
  for b; do printf %b "\\0$(printf %03o "$((b))")"; done
}
str() {
  byte $((0x40 + ${#1}))
  printf %s "$1"
}

# empty <file>: an MMDB database with no networks in it
# (https://maxmind.github.io/MaxMind-DB/), which finds nothing for any address.
empty() {
  {
    # The search tree: one node, both its 24-bit records 1, the node count, which means no data.
    byte 0 0 1 0 0 1
    # The 16 zero bytes before the data section, which is empty, then the metadata's marker.
    byte 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    byte 0xab 0xcd 0xef
    printf MaxMind.com
    # The metadata, a map of 9. A uint16 is 0xa0 + its length in bytes, a uint32 0xc0 + it; a
    # uint64 and an array are 0 + their length then their extended type (2, 4); 0xe0 an empty map.
    byte 0xe9
    str binary_format_major_version; byte 0xa1 2
    str binary_format_minor_version; byte 0xa0
    str build_epoch; byte 0 2
    str database_type; str empty
    str description; byte 0xe0
    str ip_version; byte 0xa1 6
    str languages; byte 0 4
    str node_count; byte 0xc1 1
    str record_size; byte 0xa1 24
  } > "$1"
}

# fetch <DB-IP edition> <name>: $dir/<name>.mmdb, its month in $dir/<name>.month (none for the
# empty database).
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
  if [ "$have" != none ] && [ -s "$dir/$name.mmdb" ]; then
    echo "$name: keeping ${have:-an older copy}"
    return 0
  fi
  empty "$dir/$name.mmdb"
  echo none > "$dir/$name.month"
  echo "$name: no data, starting without it" >&2
}

fetch dbip-city-lite city
fetch dbip-asn-lite asn
