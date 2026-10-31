#!/usr/bin/env python3
#
# Prints the path of each Flux Kustomization in clusters/, the directories lint builds the way
# Flux does (clusters/ itself is read as plain manifests). Fails if a kustomization.yaml isn't
# reached from one of them through resources/components: Flux never applies it, so lint wouldn't
# check it either.
#
# Usage (from the repo's root):
# flux-paths.py

import sys
from pathlib import Path

import yaml


def kustomizations(directory: Path):
    """The directory and every kustomization it pulls in."""
    yield directory
    k = yaml.safe_load((directory / "kustomization.yaml").read_text()) or {}
    for entry in k.get("resources", []) + k.get("components", []):
        if (directory / entry / "kustomization.yaml").is_file():
            yield from kustomizations((directory / entry).resolve())


def main() -> None:
    paths = {
        Path(doc["spec"]["path"])
        for file in Path("clusters").rglob("*.yaml")
        for doc in yaml.safe_load_all(file.read_text())
        if doc and doc.get("apiVersion", "").startswith("kustomize.toolkit.fluxcd.io/")
    }
    roots = sorted(path for path in paths if path.parts[0] != "clusters")

    reached = {d for root in roots for d in kustomizations(root.resolve())}
    unreached = sorted(
        str(file.parent)
        for file in Path().rglob("kustomization.yaml")
        if file.parts[0] != "clusters" and file.parent.resolve() not in reached
    )

    if unreached:
        for path in unreached:
            print(f"flux-paths: {path} isn't reached from a Flux Kustomization's path", file=sys.stderr)
        sys.exit(1)
    print(*roots, sep="\n")


if __name__ == "__main__":
    main()
