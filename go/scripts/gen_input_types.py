#!/usr/bin/env python3
"""Capture the (type, default) pairs the Python SDK validates every reasoner body against.

REPRODUCE (from the repo root of the worktree):

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python \
        go/scripts/gen_input_types.py \
        > go/internal/reasoners/testdata/python_input_types.json

WHY A CAPTURE AND NOT A DERIVATION
----------------------------------
``@router.reasoner()`` / ``@app.reasoner()`` store
``{param: (annotation, default)}`` for every parameter of the decorated function
(``agentfield/agent.py``, ``input_fields``), and ``_validate_handler_input``
runs over exactly that dict on every request.  Which BRANCH of that method a
parameter takes is decided by a chain of ``is``-comparisons against ``int`` /
``float`` / ``str`` / ``bool`` / ``dict`` / ``list``, preceded by ONE unwrap
that only fires for ``typing.Union`` -- a PEP 604 ``int | None`` is a
``types.UnionType`` with no ``__origin__``, so it is NEVER unwrapped and falls
through to the pass-through branch.  Re-deriving that from the Go structs would
"fix" the quirk; capturing it preserves it.

The capture records, per reasoner, an ORDERED list of parameters (the dict is in
signature order, and ``_validate_handler_input`` raises on the FIRST offending
one, so order is observable):

    name      the JSON key
    kind      which coercion branch the parameter takes:
              "str" | "int" | "float" | "bool" | "dict" | "list" | "any"
    required  True when the parameter has NO default (``default is ...``)
    default   the Python default, for documentation and cross-checks
              (omitted when required)
    annotation  the repr of the annotation, so a human can diff the file

Regenerate only when the PYTHON signatures change.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Union

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _kind(annotation: Any) -> str:
    """Name the branch ``_validate_handler_input`` takes for this annotation.

    Mirrors agent.py:1192-1236 exactly, including the Union unwrap that only
    applies to ``typing.Union`` (never to PEP 604).
    """
    actual = annotation
    origin = getattr(annotation, "__origin__", None)
    if origin is Union:
        # typing.Optional[X] / typing.Union[X, None].  No parameter in this node
        # is spelled that way today; the branch is kept so a future one is
        # classified rather than silently mislabelled.
        raise SystemExit(
            f"gen_input_types: typing.Union annotation {annotation!r} is not modelled "
            "on the Go side; extend handler_input.go before regenerating"
        )
    if actual is int:
        return "int"
    if actual is float:
        return "float"
    if actual is str:
        return "str"
    if actual is bool:
        return "bool"
    if actual is dict or getattr(actual, "__origin__", None) is dict:
        return "dict"
    if actual is list or getattr(actual, "__origin__", None) is list:
        return "list"
    if hasattr(actual, "model_validate"):
        raise SystemExit(
            f"gen_input_types: pydantic-model annotation {annotation!r} is not modelled "
            "on the Go side; extend handler_input.go before regenerating"
        )
    return "any"


def main() -> None:
    from sec_af.app import app

    out: dict[str, list[dict[str, Any]]] = {}
    for name in sorted(app._reasoner_registry):  # pyright: ignore[reportPrivateUsage]
        entry = app._reasoner_registry[name]  # pyright: ignore[reportPrivateUsage]
        params: list[dict[str, Any]] = []
        for param, (annotation, default) in entry.input_types.items():
            row: dict[str, Any] = {
                "name": param,
                "kind": _kind(annotation),
                "annotation": str(annotation),
                "required": default is Ellipsis,
            }
            if default is not Ellipsis:
                row["default"] = default
            params.append(row)
        out[name] = params

    print(json.dumps(out, indent=1, sort_keys=False))


if __name__ == "__main__":
    main()
