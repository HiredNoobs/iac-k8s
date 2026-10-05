#!/usr/bin/env python3
#
# Converts the CRDs in YAML files to JSON schemas for kubeconform, one per served version, named
# like Flux's (<kind>-<group prefix>-<version>.json) so -schema-location
# "<dir>/{{.ResourceKind}}{{.KindSuffix}}.json" finds them.
#
# Like kubeconform's openapi2jsonschema.py, unknown fields are rejected (additionalProperties:
# false) unless the CRD preserves them. That script also adds it to fields named "properties"
# (ESO's crd provider has one), which breaks the schema, this one only walks schema keywords.
#
# Usage:
# crd-schemas.py <OUTPUT DIR> <CRD FILE> ... <CRD FILE>

import json
import os
import sys

import yaml


def strict(schema: dict) -> None:
    if not isinstance(schema, dict):
        return

    if "properties" in schema and not schema.get("x-kubernetes-preserve-unknown-fields"):
        schema.setdefault("additionalProperties", False)

    for child in schema.get("properties", {}).values():
        strict(child)
    for keyword in ("items", "additionalProperties", "not"):
        strict(schema.get(keyword))
    for keyword in ("allOf", "anyOf", "oneOf"):
        for child in schema.get(keyword, []):
            strict(child)


def main() -> None:
    out_dir, files = sys.argv[1], sys.argv[2:]
    os.makedirs(out_dir, exist_ok=True)

    for path in files:
        with open(path) as file:
            docs = [doc for doc in yaml.safe_load_all(file) if doc]

        for crd in docs:
            if crd.get("kind") != "CustomResourceDefinition":
                continue

            kind = crd["spec"]["names"]["kind"].lower()
            group = crd["spec"]["group"].split(".")[0]

            for version in crd["spec"]["versions"]:
                if not version.get("served"):
                    continue

                schema = version["schema"]["openAPIV3Schema"]
                strict(schema)

                name = f"{kind}-{group}-{version['name']}.json"
                with open(os.path.join(out_dir, name), "w") as file:
                    json.dump(schema, file)
                print(name)


if __name__ == "__main__":
    main()
