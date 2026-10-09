#!/usr/bin/env bash
#
# Renovate's postUpgradeTask (renovate.json, allowed by the global config in the renovate repo's
# workflow), run in each branch after its version bumps. Fills in what Renovate can't:
#
#   - lint.yml: the checksum of each download whose URL uses a version that changed.
#   - Vendored release manifests: re-downloaded when the image in their kustomization's patch
#     changed, with the URL and checksum in its comment.
#
# Only pins whose version changed in the branch are touched: an unchanged version keeps its
# committed checksum, so a file replaced upstream still fails lint instead of being trusted. The
# new checksums are of whatever was downloaded (trust on first use), compare them with upstream's
# published ones when reviewing the PR.
#
# Usage (from anywhere in the repo, after editing versions, uncommitted):
# bash .forgejo/scripts/update-pins.sh

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

LINT=.forgejo/workflows/lint.yml

# Vendored manifests: directory, file, image (its tag is the release's, without the v).
VENDORED=(
  "infrastructure/controllers/kubelet-serving-cert-approver standalone-install.yaml ghcr.io/alex1989hu/kubelet-serving-cert-approver"
  "infrastructure/operators/rabbitmq-topology-operator messaging-topology-operator-with-certmanager.yaml ghcr.io/rabbitmq/messaging-topology-operator"
)

function log {
  echo "update-pins: $*" >&2
}

function sha256_of_url {
  local tmp sum
  tmp=$(mktemp)
  curl -fsSL -o "$tmp" "$1"
  sum=$(sha256sum "$tmp" | cut -d' ' -f1)
  rm -f "$tmp"
  echo "$sum"
}

# NAME=value for each variable in lint.yml's env block, read from stdin.
function lint_env {
  awk '/^env:/ { f = 1; next }
       f && /^[^ #]/ { f = 0 }
       f && /^  [A-Z0-9_]+: / { k = $1; sub(/:$/, "", k); v = $2; gsub(/"/, "", v); print k "=" v }'
}

function update_lint_checksums {
  local -A new old urls
  local k v file url var expanded changed sum

  while IFS='=' read -r k v; do new[$k]=$v; done < <(lint_env < "$LINT")
  while IFS='=' read -r k v; do old[$k]=$v; done < <(git show "HEAD:$LINT" | lint_env)

  # Each download is `curl -fsSLo <file> "<url>"` followed by
  # `echo "${<CHECKSUM>}  <file>" | sha256sum -c -`, possibly over continued lines.
  local joined
  joined=$(sed -e ':a' -e '/\\$/N; s/\\\n[[:space:]]*/ /; ta' "$LINT")

  while read -r file url; do
    urls[$file]=$url
  done < <(sed -nE 's/.*curl -fsSLo ([^ ]+) +"([^"]+)".*/\1 \2/p' <<< "$joined")

  while read -r var file; do
    url=${urls[$file]:-}
    if [[ -z $url ]]; then
      log "no download found for $file ($var), skipping"
      continue
    fi

    changed=false
    expanded=$url
    for k in $(grep -oE '[{][A-Z0-9_]+[}]' <<< "$url" | tr -d '{}' | sort -u); do
      [[ ${new[$k]:-} != "${old[$k]:-}" ]] && changed=true
      expanded=${expanded//"\${$k}"/${new[$k]:-}}
    done
    $changed || continue

    log "$var: downloading $expanded"
    sum=$(sha256_of_url "$expanded")
    sed -i -E "s/^(  $var: )\"[0-9a-f]*\"/\1\"$sum\"/" "$LINT"
    log "$var: $sum"
  done < <(sed -nE 's/.*echo "\$\{([A-Z0-9_]+)\}  ([^ ]+)" \| sha256sum.*/\1 \2/p' <<< "$joined")
}

# Replaces a vendored manifest with the release matching its image's new tag.
function update_vendored {
  local dir=$1 file=$2 image=$3
  local kustomization=$dir/kustomization.yaml
  local tag old_tag old_url new_url sum

  tag=$(sed -nE "s#^ *image: $image:([^@]+)@.*#\1#p" "$kustomization")
  old_tag=$(git show "HEAD:$kustomization" | sed -nE "s#^ *image: $image:([^@]+)@.*#\1#p")
  [[ $tag == "$old_tag" ]] && return 0

  old_url=$(sed -nE "s@^# (https://[^ ]+/$file)\$@\1@p" "$kustomization")
  if [[ -z $old_url || $old_url != *"$old_tag"* ]]; then
    log "$kustomization: no URL for $file with $old_tag in it, update it by hand"
    return 1
  fi
  new_url=${old_url//"$old_tag"/$tag}

  log "$file: downloading $new_url"
  curl -fsSL -o "$dir/$file" "$new_url"
  sum=$(sha256sum "$dir/$file" | cut -d' ' -f1)

  # The URL's comment line, and the checksum on the line after it.
  awk -v old="# $old_url" -v new="# $new_url" -v sum="$sum" '
    $0 == old { print new; next_line = 1; next }
    next_line { sub(/sha256 [0-9a-f]+/, "sha256 " sum); next_line = 0 }
    { print }' "$kustomization" > "$kustomization.tmp"
  mv "$kustomization.tmp" "$kustomization"
  log "$file: $sum"
}

update_lint_checksums

for entry in "${VENDORED[@]}"; do
  # shellcheck disable=SC2086 # Space-separated on purpose.
  update_vendored $entry
done
