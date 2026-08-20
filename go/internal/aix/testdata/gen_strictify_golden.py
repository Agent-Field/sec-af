#!/usr/bin/env python3
"""Golden generator for aix.Strictify.

Runs the REAL Python SDK function that aix.Strictify ports —
``agentfield.agent_ai._strictify_openai_schema`` — over

  1. every committed pydantic schema fixture under
     ``go/internal/harnessx/testdata/schemas/`` (the exact documents
     ``aix.Structured`` strictifies at runtime), writing the results as one
     ``{"<ClassName>": <strictified schema>}`` object, and
  2. a hand-written edge-case document that exercises the branches the real
     fixtures do not: a properties-bearing node with NO "type" key (must be
     strictified), a node with a LIST-valued "type" (must NOT be), an "anyOf"
     branch, a nested "items", and a pre-existing wrong "required"/
     "additionalProperties" pair that the walk must overwrite.

Run from the repo root:

    ~/.agentfield/packages/sec-af/venv/bin/python \
        go/internal/aix/testdata/gen_strictify_golden.py

Deterministic: rerunning writes identical bytes unless the SDK function or a
schema fixture changed.
"""

from __future__ import annotations

import json
import os

from agentfield.agent_ai import _strictify_openai_schema

_HERE = os.path.dirname(os.path.abspath(__file__))
_GO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_FIXTURES = os.path.join(_GO, "internal", "harnessx", "testdata", "schemas")

# Exercises every branch of the walk. Key order is irrelevant to the assertion
# (the Go test compares decoded documents), but the required lists it produces
# are order-sensitive, so this file is written sorted to match Go's sorted
# `required` — see aix.Strictify's doc comment.
EDGE_CASES = {
    "$defs": {
        "NoTypeNode": {
            # No "type" key at all -> `"type" not in node` -> strictified.
            "properties": {
                "b": {"type": "string"},
                "a": {"type": "integer"},
            },
        },
        "ListTypeNode": {
            # type is a LIST -> neither `== "object"` nor `not in` -> untouched.
            "type": ["object", "null"],
            "properties": {"z": {"type": "string"}},
        },
        "AlreadyStrict": {
            "type": "object",
            "additionalProperties": True,
            "required": ["stale"],
            "properties": {"kept": {"type": "string"}},
        },
        "Leaf": {
            "type": "object",
            "properties": {"v": {"type": "number"}},
        },
    },
    "type": "object",
    "properties": {
        "nested": {"$ref": "#/$defs/Leaf"},
        "list_of_objects": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"inner": {"type": "string"}},
            },
        },
        "nullable_object": {
            "anyOf": [
                {"type": "object", "properties": {"x": {"type": "string"}}},
                {"type": "null"},
            ]
        },
        "plain": {"type": "string"},
        # A non-dict "properties" value must not trip the isinstance check.
        "decoy": {"type": "object", "properties": "not-a-dict"},
    },
}


def main() -> None:
    strictified: dict[str, object] = {}
    for entry in sorted(os.listdir(_FIXTURES)):
        if not entry.endswith(".json"):
            continue
        with open(os.path.join(_FIXTURES, entry), encoding="utf-8") as f:
            schema = json.load(f)
        strictified[entry[: -len(".json")]] = _strictify_openai_schema(schema)

    out = os.path.join(_HERE, "strictified_fixtures.json")
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps(strictified, indent=2, sort_keys=True) + "\n")
    print(f"wrote {os.path.basename(out)} ({len(strictified)} schemas)")

    # Round-trip through sorted JSON FIRST so the dict Python walks has the same
    # key order the Go test will read off disk. `list(props.keys())` is
    # insertion-ordered, so without this the golden `required` lists would carry
    # the literal's declaration order while Go produced sorted ones.
    edge_input = json.loads(json.dumps(EDGE_CASES, sort_keys=True))
    with open(os.path.join(_HERE, "edgecases_input.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(edge_input, indent=2, sort_keys=True) + "\n")
    with open(os.path.join(_HERE, "edgecases_strict.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(_strictify_openai_schema(edge_input), indent=2, sort_keys=True) + "\n")
    print("wrote edgecases_input.json / edgecases_strict.json")


if __name__ == "__main__":
    main()
