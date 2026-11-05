#!/usr/bin/env bash
#
# Renovate's postUpgradeTask (renovate.json, allowed by the global config in the renovate repo's
# workflow), run in each branch after its version bumps. Fills in what Renovate can't:
#
#   - lint.yml: the checksum of each download whose URL uses a version that changed, from the
#     checksums upstream publishes with the release (SUMS_FILES), or else of the file downloaded.
#   - Vendored release manifests: re-downloaded when the image in their kustomization's patch
#     changed, with the URL and checksum in its comment.
#   - Images a chart runs (`# update-pins: image=<name>` above their tag): the chart's appVersion
#     when the chart's version changed, with the digest the registry serves for it. Renovate would
#     bump them separately: it holds back images whose registry gives no release date, not charts.
#
# Only pins whose version changed in the branch are touched: an unchanged version keeps its
# committed checksum, so a file replaced upstream still fails lint instead of being trusted. A
# checksum of a download is of whatever was downloaded (trust on first use), review those diffs.
#
# Usage (from anywhere in the repo, after editing versions, uncommitted):
# bash .forgejo/scripts/update-pins.sh

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

LINT=.forgejo/workflows/lint.yml

# lint.yml's downloads whose release publishes their checksums: the checksum variable, and the
# checksums file's name (with lint.yml's variables) next to the download, which it lists by name.
# shellcheck disable=SC2016 # Expanded by expand.
declare -A SUMS_FILES=(
  [KUSTOMIZE_SHA256]='checksums.txt'
  [KUBECONFORM_SHA256]='CHECKSUMS'
  [FLUX_CRD_SCHEMAS_SHA256]='flux_${FLUX_VERSION}_checksums.txt'
  [VECTOR_SHA256]='vector-${VECTOR_VERSION}-SHA256SUMS'
)

# Vendored manifests: directory, file, image (its tag is the release's, without the v).
VENDORED=(
  "infrastructure/controllers/kubelet-serving-cert-approver standalone-install.yaml ghcr.io/alex1989hu/kubelet-serving-cert-approver"
  "infrastructure/operators/rabbitmq-topology-operator messaging-topology-operator-with-certmanager.yaml rabbitmqoperator/messaging-topology-operator"
)

function log {
  echo "update-pins: $*" >&2
}

# NAME=value for each variable in lint.yml's env block, read from stdin.
function lint_env {
  awk '/^env:/ { f = 1; next }
       f && /^[^ #]/ { f = 0 }
       f && /^  [A-Z0-9_]+: / { k = $1; sub(/:$/, "", k); v = $2; gsub(/"/, "", v); print k "=" v }'
}

# $1 with each ${NAME} replaced by its value in the associative array named $2.
function expand {
  local -n values=$2
  local s=$1 k
  for k in "${!values[@]}"; do
    s=${s//"\${$k}"/${values[$k]}}
  done
  echo "$s"
}

function update_lint_checksums {
  local -A new old urls
  local k v file url var expanded sums_url sum

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

    # The URL changes with any version in it.
    expanded=$(expand "$url" new)
    [[ $expanded != "$(expand "$url" old)" ]] || continue

    if [[ -n ${SUMS_FILES[$var]:-} ]]; then
      sums_url="${expanded%/*}/$(expand "${SUMS_FILES[$var]}" new)"
      log "$var: reading $sums_url"
      sum=$(curl -fsSL "$sums_url" | awk -v name="${expanded##*/}" '$2 == name || $2 == "*" name { print $1 }')
    else
      log "$var: downloading $expanded"
      sum=$(curl -fsSL "$expanded" | sha256sum | cut -d' ' -f1)
    fi
    if [[ ! $sum =~ ^[0-9a-f]{64}$ ]]; then
      log "$var: no checksum found"
      return 1
    fi
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

# "<chart> <version> <HelmRepository>" of the HelmRelease in YAML on stdin.
function chart_release {
  awk '!chart && /^ +chart: [^ ]/ { chart = $2 }
       chart && !version && /^ +version: / { version = $2; gsub(/"/, "", version) }
       /^ +sourceRef:/ { source = 1 }
       source && !name && /^ +name: / { name = $2 }
       END { print chart, version, name }'
}

# "<image> <tag>" for each `# update-pins: image=<name>` in file $1, from the `tag:` line below it.
function chart_images {
  sed -nE '/# update-pins: image=/ { s/.*image=([^[:space:]]+).*/\1/; N; s/\n[[:space:]]*tag: "?([^@"[:space:]]+).*/ \1/p }' "$1" | sort -u
}

# The URL of the HelmRepository named $1, if the repo has one by that name (or several, all with
# the same URL).
function helm_repository {
  local urls
  # shellcheck disable=SC2016 # awk's fields, through xargs.
  urls=$(git grep -l '^kind: HelmRepository' -- apps infrastructure | xargs awk -v name="$1" '
    FNR == 1 || /^---/ { repository = found = 0 }
    /^kind: HelmRepository/ { repository = 1 }
    repository && $1 == "name:" && $2 == name { found = 1 }
    found && $1 == "url:" { sub(/\/$/, "", $2); print $2; found = 0 }' | sort -u)
  [[ -n $urls && $urls != *$'\n'* ]] && echo "$urls"
}

# The appVersion of chart $2 version $3, from the index of the Helm repository at $1.
function app_version {
  local index
  index=$(curl -fsSL "$1/index.yaml")
  awk -v chart="$2" -v version="$3" '
    function item_end() {
      # exit runs END, which ends the item again.
      if (in_chart && item_version == version && app != "") { print app; in_chart = 0; exit }
      item_version = app = ""
    }
    function value(s) { sub(/^[^:]*: */, "", s); gsub(/["\047]/, "", s); return s }
    /^entries:/ { entries = 1; next }
    !entries { next }
    /^[^ ]/ { item_end(); entries = 0; next }
    /^  [^ -]/ { item_end(); in_chart = ($1 == chart ":"); indent = 0; next }
    !in_chart { next }
    {
      # Each version is a list item, its keys indented to where the first one starts. Lists in an
      # item (keywords, urls) are at that indent too.
      line = $0
      if (match(line, /^ *- /) && (!indent || RLENGTH == indent)) {
        item_end()
        indent = RLENGTH
        line = sprintf("%" indent "s", "") substr(line, indent + 1)
      }
      if (!indent || substr(line, 1, indent) ~ /[^ ]/) next
      key = substr(line, indent + 1)
      if (key ~ /^appVersion:/) app = value(key)
      else if (key ~ /^version:/) item_version = value(key)
    }
    END { item_end() }' <<< "$index"
}

# The digest of image $1's tag $2, as the registry serves it to an anonymous pull: the multi-arch
# index where there is one.
function image_digest {
  local image=$1 tag=$2 registry repository url challenge realm service scope token
  local -a auth=()
  # The index first, the image's own manifest for single-platform images.
  local accept=application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json
  accept+=,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json

  if [[ $image == *.*/* ]]; then
    registry=${image%%/*}
    repository=${image#*/}
  else
    registry="registry-1.docker.io"
    repository=$image
    [[ $repository == */* ]] || repository=library/$repository
  fi
  url="https://$registry/v2/$repository/manifests/$tag"

  # Registries that want a token say where to get one.
  challenge=$(curl -sSI -H "Accept: $accept" "$url" | sed -nE 's/^[Ww]{3}-[Aa]uthenticate: Bearer (.*)\r$/\1/p')
  if [[ -n $challenge ]]; then
    realm=$(sed -nE 's/.*realm="([^"]*)".*/\1/p' <<< "$challenge")
    service=$(sed -nE 's/.*service="([^"]*)".*/\1/p' <<< "$challenge")
    scope=$(sed -nE 's/.*scope="([^"]*)".*/\1/p' <<< "$challenge")
    token=$(curl -fsSL -G "$realm" --data-urlencode "service=$service" \
      --data-urlencode "scope=${scope:-repository:$repository:pull}" | sed -nE 's/.*"(access_)?token" *: *"([^"]+)".*/\2/p')
    auth=(-H "Authorization: Bearer $token")
  fi

  # The last response's, after redirects (registry.k8s.io's).
  curl -fsSIL -H "Accept: $accept" "${auth[@]}" "$url" \
    | sed -nE 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: (sha256:[0-9a-f]{64})\r$/\1/p' | tail -n1
}

# Sets the images pinned in a HelmRelease to its chart's appVersion if the chart's version changed.
function update_chart_images {
  local file=$1 chart version source old_version repository app image tag new_tag digest

  read -r chart version source < <(chart_release < "$file")
  old_version=$(git show "HEAD:$file" | chart_release | cut -d' ' -f2)
  [[ $version == "$old_version" ]] && return 0

  if ! repository=$(helm_repository "$source"); then
    log "$file: no single HelmRepository $source"
    return 1
  fi
  if ! app=$(app_version "$repository" "$chart" "$version") || [[ -z $app ]]; then
    log "$chart $version: no appVersion in $repository"
    return 1
  fi

  while read -r image tag; do
    # Some charts' appVersion leaves out the tags' v.
    new_tag=$app
    [[ $tag == v* && $app != v* ]] && new_tag=v$app
    [[ $new_tag == "$tag" ]] && continue

    if ! digest=$(image_digest "$image" "$new_tag") || [[ ! $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
      log "$image:$new_tag: no digest found"
      return 1
    fi
    # From the comment to the digest, on the tag's line (tag@digest) or a digest:/sha: line after it.
    sed -i -E "\\@# update-pins: image=${image//./\\.}[[:space:]]*\$@,/sha256:/ {
      s/(tag: \"?)[^@\"[:space:]]+/\\1$new_tag/
      s/sha256:[0-9a-f]{64}/$digest/
    }" "$file"
    log "$image: $new_tag@$digest"
  done < <(chart_images "$file")
}

update_lint_checksums

for entry in "${VENDORED[@]}"; do
  # shellcheck disable=SC2086 # Space-separated on purpose.
  update_vendored $entry
done

for release in $(git grep -l '# update-pins: image=' -- apps infrastructure); do
  update_chart_images "$release"
done
