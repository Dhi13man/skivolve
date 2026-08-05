from __future__ import annotations

import os
import sys


sys.path.insert(0, os.environ["EVAL_SHARED_ROOT"])

from final_output import (  # noqa: E402
    agent_workspace_unchanged,
    assertion,
    emit,
    flatten_text,
    read_artifact,
)


EXPECTED_KEYS = {"decision", "supported_facts", "unknowns", "next_check"}
ALLOWED_SOURCES = {"decision_rule.txt", "pilot_primary.txt", "pilot_counter.txt"}


def main() -> None:
    artifact = read_artifact()
    values = artifact or {}
    decision = flatten_text(values.get("decision", "")).lower()
    facts = values.get("supported_facts")
    facts_text = flatten_text(facts).lower()
    unknowns = values.get("unknowns")
    unknowns_text = flatten_text(unknowns).lower()
    next_check = flatten_text(values.get("next_check", "")).lower()

    fact_objects = (
        facts
        if isinstance(facts, list)
        and 2 <= len(facts) <= 6
        and all(isinstance(item, dict) for item in facts)
        else []
    )
    sources = {
        item.get("source")
        for item in fact_objects
        if isinstance(item.get("source"), str)
    }
    balanced_facts = (
        bool(fact_objects)
        and sources <= ALLOWED_SOURCES
        and {"pilot_primary.txt", "pilot_counter.txt"} <= sources
        and "18%" in facts_text
        and "median" in facts_text
        and "tail" in facts_text
        and "9%" in facts_text
        and "p99" in facts_text
    )
    material_unknowns = (
        isinstance(unknowns, list)
        and 2 <= len(unknowns) <= 4
        and "p99" in unknowns_text
        and "production" in unknowns_text
        and any(token in unknowns_text for token in ("q-17", "release candidate"))
        and any(word in unknowns_text for word in ("whether", "identity", "matches"))
    )
    resolving_check = (
        "p99" in next_check
        and "production" in next_check
        and any(
            token in next_check
            for token in ("q-17", "exact release candidate", "exact release-candidate")
        )
        and any(
            word in next_check for word in ("run", "measure", "compare", "benchmark")
        )
    )
    restrained = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and any(
            phrase in decision
            for phrase in ("do_not_replace", "do not replace", "not replace", "unmet")
        )
        and sources <= ALLOWED_SOURCES
        and "confidence" not in flatten_text(artifact).lower()
        and agent_workspace_unchanged()
    )

    emit(
        [
            assertion(
                "balanced-source-facts",
                balanced_facts,
                "facts cover the primary median result and p99 counter-evidence",
            ),
            assertion(
                "material-uncertainty",
                material_unknowns,
                "unknowns preserve production p99 and release identity gaps",
            ),
            assertion(
                "decision-resolving-check",
                resolving_check,
                "next check measures exact-candidate p99 on production-shaped load",
            ),
            assertion(
                "research-output-restraint",
                restrained,
                "decision is evidence-bounded, exact-schema, and read-only",
            ),
        ]
    )


if __name__ == "__main__":
    main()
