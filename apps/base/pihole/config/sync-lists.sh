#!/usr/bin/env bash
#
# Keeps Pi-hole's lists and domains in line with the pihole-lists ConfigMap, anything
# not in the files is removed. Runs next to Pi-hole in each pod using the local API.
#
#   adlists.txt      Block lists (URLs)
#   allow.txt        Allowed domains (exact)
#   deny.txt         Denied domains (exact)
#   allow-regex.txt  Allowed domains (regex)
#   deny-regex.txt   Denied domains (regex)
#
# One entry per line, blank lines and lines starting with # are ignored. Missing files
# are treated as empty. Pi-hole isn't marked ready until the first sync has finished.

set -uo pipefail

API="http://127.0.0.1/api"
LISTS_DIR="${LISTS_DIR:-/etc/pihole-lists}"
READY_FILE="${READY_FILE:-/run/pihole-sync/ready}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
# Re-sync without changes to the files every so often, e.g. to undo edits made in the web UI.
RESYNC_INTERVAL="${RESYNC_INTERVAL:-3600}"
COMMENT="Managed by iac-k8s"

SID=""
LISTS_CHANGED=0

# -----------------------------------------------------
# Helper functions
# -----------------------------------------------------

function log {
  echo "$(date '+%Y-%m-%dT%H:%M:%S') $*"
}

# Usage: api <method> <path> [json body]
# API_TIMEOUT can be set for long running calls.
function api {
  local method="$1" path="$2" body="${3:-}"
  local args=(-fsS -X "$method" --max-time "${API_TIMEOUT:-30}")

  [[ -n "$SID" ]] && args+=(-H "X-FTL-SID: $SID")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data "$body")

  curl "${args[@]}" "$API$path"
}

function uri {
  jq -rn --arg value "$1" '$value | @uri'
}

# Entries from a list file.
function desired {
  local file="$LISTS_DIR/$1"

  [[ -f "$file" ]] || return 0
  # [[:space:]] also strips the CR from files with Windows line endings.
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$file" | grep -v -e '^#' -e '^$' | sort -u
}

# Lines in $1 that aren't in $2.
function only_in {
  local -A exclude=()
  local line

  while IFS= read -r line; do
    [[ -n "$line" ]] && exclude["$line"]=1
  done <<< "$2"

  while IFS= read -r line; do
    [[ -n "$line" && -z "${exclude["$line"]:-}" ]] && echo "$line"
  done <<< "$1" | sort -u
}

function login {
  local response

  SID=""
  # No password means the API doesn't need a session.
  [[ -z "${PIHOLE_PASSWORD:-}" ]] && return 0

  response=$(curl -fsS --max-time 30 -X POST "$API/auth" \
             --data "$(jq -n --arg password "$PIHOLE_PASSWORD" '{password: $password}')") || return 1
  SID=$(jq -r '.session.sid // empty' <<< "$response")
  [[ -n "$SID" ]]
}

function logout {
  [[ -n "$SID" ]] && api DELETE /auth > /dev/null 2>&1
  SID=""
}

# -----------------------------------------------------
# Sync functions
# -----------------------------------------------------

function sync_adlists {
  local current wanted address

  current=$(api GET "/lists?type=block" | jq -r '.lists[] | select(.type == "block") | .address') || return 1
  wanted=$(desired adlists.txt)

  while IFS= read -r address; do
    [[ -n "$address" ]] || continue
    log "Adding block list $address"
    api POST "/lists?type=block" "$(jq -n --arg address "$address" --arg comment "$COMMENT" \
      '{address: $address, comment: $comment, enabled: true}')" > /dev/null || return 1
    LISTS_CHANGED=1
  done <<< "$(only_in "$wanted" "$current")"

  while IFS= read -r address; do
    [[ -n "$address" ]] || continue
    log "Removing block list $address"
    api DELETE "/lists/$(uri "$address")?type=block" > /dev/null || return 1
    LISTS_CHANGED=1
  done <<< "$(only_in "$current" "$wanted")"
}

# Usage: sync_domains <allow|deny> <exact|regex> <file>
function sync_domains {
  local type="$1" kind="$2" file="$3" current wanted domain

  current=$(api GET "/domains/$type/$kind" | jq -r '.domains[].domain') || return 1
  wanted=$(desired "$file")

  # Pi-hole stores exact domains in lowercase, match that so they aren't re-added every sync.
  if [[ "$kind" == "exact" ]]; then
    wanted=$(tr '[:upper:]' '[:lower:]' <<< "$wanted" | sort -u)
  fi

  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    log "Adding $type ($kind) $domain"
    api POST "/domains/$type/$kind" "$(jq -n --arg domain "$domain" --arg comment "$COMMENT" \
      '{domain: $domain, comment: $comment, enabled: true}')" > /dev/null || return 1
  done <<< "$(only_in "$wanted" "$current")"

  while IFS= read -r domain; do
    [[ -n "$domain" ]] || continue
    log "Removing $type ($kind) $domain"
    api DELETE "/domains/$type/$kind/$(uri "$domain")" > /dev/null || return 1
  done <<< "$(only_in "$current" "$wanted")"
}

function blocked_domains {
  api GET /stats/summary | jq -r '.gravity.domains_being_blocked // 0'
}

function sync {
  local blocked

  LISTS_CHANGED=0

  if ! login; then
    log "Failed to log in to the Pi-hole API."
    return 1
  fi

  if ! { sync_adlists &&
         sync_domains allow exact allow.txt &&
         sync_domains deny exact deny.txt &&
         sync_domains allow regex allow-regex.txt &&
         sync_domains deny regex deny-regex.txt; }; then
    logout
    return 1
  fi

  # Block lists are only downloaded by a gravity update, also covers a fresh pod.
  blocked=$(blocked_domains) || blocked=0
  if (( LISTS_CHANGED )) || { [[ -n "$(desired adlists.txt)" ]] && (( blocked <= 0 )); }; then
    log "Updating gravity..."
    if ! API_TIMEOUT=900 api POST /action/gravity > /dev/null; then
      logout
      return 1
    fi
    log "Gravity updated, $(blocked_domains) domains blocked."
  fi

  logout
}

function checksum {
  cat "$LISTS_DIR"/*.txt 2> /dev/null | sha256sum | cut -d' ' -f1
}

# -----------------------------------------------------
# Main
# -----------------------------------------------------

log "Waiting for the Pi-hole API..."
until curl -s -o /dev/null --max-time 5 "$API/auth"; do
  sleep 2
done

last_checksum=""
last_sync=0

# ConfigMap volumes are updated in place, so changes are picked up without a restart.
while true; do
  current_checksum=$(checksum)
  now=$(date +%s)

  if [[ "$current_checksum" != "$last_checksum" ]] || (( now - last_sync >= RESYNC_INTERVAL )); then
    if sync; then
      last_checksum="$current_checksum"
      last_sync="$now"

      if [[ ! -f "$READY_FILE" ]]; then
        touch "$READY_FILE"
        log "Initial sync complete."
      fi
    else
      log "Sync failed, retrying in ${CHECK_INTERVAL}s."
    fi
  fi

  sleep "$CHECK_INTERVAL"
done
