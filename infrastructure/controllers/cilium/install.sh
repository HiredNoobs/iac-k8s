#!/usr/bin/env bash
#
# Installs Cilium on a new cluster (docs/rebuild.md), whose nodes have no network, and so no Flux,
# until it runs: the HelmRelease's chart (repository.yaml's, checked against its digest) with its
# values (release.yaml's), then waits for every node to be Ready. Flux takes the release over on
# its first reconcile.
#
# Needs helm 4, python3 with PyYAML (it comes with Ansible) and kubectl on the new cluster's
# context.
#
# Usage (from anywhere):
# bash infrastructure/controllers/cilium/install.sh
set -euo pipefail

dir=$(dirname "$0")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The chart's URL, tag and digest and the release's name and namespace; its values to a file.
fields=$(python3 - "$dir" "$tmp/values.yaml" <<'EOF'
import sys, yaml

dir, values = sys.argv[1:]
chart = yaml.safe_load(open(f"{dir}/repository.yaml"))["spec"]
release = yaml.safe_load(open(f"{dir}/release.yaml"))
with open(values, "w") as out:
    yaml.safe_dump(release["spec"]["values"], out)
print(chart["url"], chart["ref"]["tag"], chart["ref"]["digest"],
      release["metadata"]["name"], release["metadata"]["namespace"])
EOF
)
read -r url tag digest name namespace <<<"$fields"

pulled=$(helm pull "$url" --version "$tag" --destination "$tmp" 2>&1)
echo "$pulled"
if ! grep -q -x "Digest: $digest" <<<"$pulled"; then
  echo "The chart's digest isn't repository.yaml's ($digest)." >&2
  exit 1
fi

echo "Installing $name $tag in $namespace on $(kubectl config current-context)"
helm install "$name" "$tmp/${url##*/}-$tag.tgz" --namespace "$namespace" --values "$tmp/values.yaml"
kubectl wait --for=condition=Ready nodes --all --timeout=10m
