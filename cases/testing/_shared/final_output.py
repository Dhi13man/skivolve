"""Shared contracts for objective final-output verifiers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_artifact() -> dict[str, object] | None:
    if os.environ.get("EVAL_ARTIFACT_KIND") != "final_output_json":
        return None
    try:
        value = json.loads(
            Path(os.environ["EVAL_ARTIFACT_PATH"]).read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (KeyError, OSError, UnicodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def flatten_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(flatten_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(flatten_text(item) for item in value.values())
    return ""


def agent_workspace_unchanged() -> bool:
    return os.environ.get("EVAL_AGENT_WORKSPACE_MUTATED") == "0"


def assertion(identifier: str, passed: bool, evidence: str) -> dict[str, object]:
    return {"id": identifier, "passed": bool(passed), "evidence": evidence}


def emit(assertions: Iterable[dict[str, object]]) -> None:
    values = list(assertions)
    print(
        json.dumps(
            {
                "passed": all(item["passed"] is True for item in values),
                "assertions": values,
                "metrics": {},
            },
            sort_keys=True,
        )
    )
