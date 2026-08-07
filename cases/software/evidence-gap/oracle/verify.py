from __future__ import annotations

import os
import re
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
DECISION_PATTERN = (
    r"(?:do_not_replace_yet|do not replace the current engine yet(?:; the adoption "
    r"requirement is (?:not met|unmet))?)"
)


def grounded_fact(source: str, claim: str) -> bool:
    if source == "decision_rule.txt":
        return bool(
            re.search(r"\badoption\b", claim)
            and re.search(r"\brequires?\b", claim)
            and re.search(r"\bexact(?:-| )candidate|exact release candidate\b", claim)
            and "production-shaped" in claim
            and "p99" in claim
            and "median" in claim
            and "insufficient" in claim
            and "without production-shaped p99" not in claim
        )
    if source == "pilot_primary.txt":
        unsupported = re.search(
            r"\b(?:increased median|proves?|safe for|every production|memory)\b", claim
        )
        median_result = all(
            token in claim
            for token in ("q-17", "reduced", "median", "18%", "50-request")
        )
        tail_gap = (
            "q-17" in claim
            and "tail latency" in claim
            and re.search(r"\bnot measured\b", claim)
        )
        return unsupported is None and bool(median_result or tail_gap)
    if source == "pilot_counter.txt":
        regression = all(
            token in claim for token in ("earlier", "build", "increased", "p99", "9%")
        )
        identity_gap = bool(
            "earlier build" in claim
            and "q-17" in claim
            and re.search(r"\b(?:unknown|does not establish|not establish)\b", claim)
        )
        return regression or identity_gap
    return False


def material_unknown(claim: str) -> bool:
    if re.search(
        r"\b(?:known|benchmarked|available|identical|definitely|should replace|meets)\b|"
        r"\bidentity matches\b",
        claim,
    ):
        return False
    candidate_identity = (
        "q-17" in claim
        and "release candidate" in claim
        and re.search(r"\b(?:whether|identity|matches|exact)\b", claim)
    )
    production_p99 = "p99" in claim and "production-shaped" in claim
    earlier_applicability = (
        "earlier build" in claim
        and re.search(r"\b(?:q-17|release candidate)\b", claim)
        and re.search(r"\b(?:applies|matches|identity)\b", claim)
    )
    threshold_gap = "threshold" in claim or "required comparison" in claim
    return bool(
        candidate_identity or production_p99 or earlier_applicability or threshold_gap
    )


def main() -> None:
    artifact = read_artifact()
    values = artifact or {}
    decision = flatten_text(values.get("decision", "")).lower()
    facts = values.get("supported_facts")
    unknowns = values.get("unknowns")
    unknowns_text = flatten_text(unknowns).lower()
    next_check_value = values.get("next_check", "")
    next_check = flatten_text(next_check_value).lower()
    next_check_schema = isinstance(next_check_value, str) or (
        isinstance(next_check_value, dict)
        and set(next_check_value) == {"check", "resolves"}
        and all(isinstance(value, str) for value in next_check_value.values())
    )

    fact_objects = (
        facts
        if isinstance(facts, list)
        and 2 <= len(facts) <= 6
        and all(
            isinstance(item, dict)
            and set(item) == {"source", "claim"}
            and isinstance(item.get("claim"), str)
            for item in facts
        )
        else []
    )
    fact_claims = [
        (
            item.get("source"),
            flatten_text(item.get("claim", "")).lower(),
        )
        for item in fact_objects
    ]
    sources = {source for source, _claim in fact_claims if isinstance(source, str)}
    source_text = {
        source: " ".join(
            claim for claim_source, claim in fact_claims if claim_source == source
        )
        for source in ALLOWED_SOURCES
    }
    attributed_facts = all(
        claim
        and isinstance(source, str)
        and source in ALLOWED_SOURCES
        and grounded_fact(source, claim.rstrip(". "))
        for source, claim in fact_claims
    )
    balanced_facts = (
        bool(fact_objects)
        and attributed_facts
        and sources == ALLOWED_SOURCES
        and all(
            token in source_text["decision_rule.txt"]
            for token in ("production", "p99", "median")
        )
        and all(
            token in source_text["pilot_primary.txt"]
            for token in ("18%", "median", "tail")
        )
        and all(token in source_text["pilot_counter.txt"] for token in ("9%", "p99"))
    )
    material_unknowns = (
        isinstance(unknowns, list)
        and 2 <= len(unknowns) <= 4
        and all(
            isinstance(item, dict)
            and set(item)
            in (
                {"claim"},
                {"unknown"},
                {"claim", "source"},
                {"unknown", "source"},
            )
            and (
                "source" not in item
                or (
                    isinstance(item["source"], str)
                    and item["source"] in ALLOWED_SOURCES
                )
            )
            and isinstance(item.get("claim", item.get("unknown")), str)
            and material_unknown(
                flatten_text(item.get("claim", item.get("unknown", "")))
                .lower()
                .rstrip(". ")
            )
            for item in unknowns
        )
        and "p99" in unknowns_text
        and "production" in unknowns_text
        and any(token in unknowns_text for token in ("q-17", "release candidate"))
        and any(word in unknowns_text for word in ("whether", "identity", "matches"))
    )
    resolving_check = bool(
        re.search(
            r"\b(?:run|identify|confirm|verify|measure|record|compare)\b", next_check
        )
        and re.search(
            r"\b(?:exact(?:-| )release(?:-| )candidate|exact(?:-| )candidate|q-17)\b",
            next_check,
        )
        and "production-shaped" in next_check
        and re.search(r"\b(?:p99|tail latency)\b", next_check)
        and not re.search(r"\b(?:do not|refuse|median-only)\b", next_check)
    )
    restrained = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and isinstance(values.get("decision"), str)
        and re.fullmatch(DECISION_PATTERN, decision.rstrip(". ")) is not None
        and sources <= ALLOWED_SOURCES
        and next_check_schema
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
