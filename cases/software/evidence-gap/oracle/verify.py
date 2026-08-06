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
SOURCE_CLAIM_PATTERNS = {
    "decision_rule.txt": (
        r"adoption requires (?:evidence (?:for|on) the exact release candidate under "
        r"(?:the|a) production-shaped workload, including p99 latency|exact-candidate "
        r"production-shaped p99 evidence); median-only evidence is insufficient",
    ),
    "pilot_primary.txt": (
        r"(?:quartz prototype )?q-17 reduced median latency by 18% on a 50-request "
        r"(?:synthetic )?sample(?:(?:, but|\.) tail latency was not measured"
        r"(?: for q-17)?)?",
        r"tail latency was not measured for q-17",
    ),
    "pilot_counter.txt": (
        r"an earlier (?:quartz )?build increased p99(?: latency)? by 9%"
        r"(?: on a bursty workload)?(?:(?:;|,) (?:but )?(?:the (?:note|source) does "
        r"not establish (?:whether|that) (?:(?:that|this) (?:earlier )?build|it) "
        r"matches (?:release candidate )?q-17|(?:and )?its identity relative to q-17 "
        r"is unknown))?",
        r"the evidence does not establish whether that earlier build matches q-17",
    ),
}
UNKNOWN_CLAIM_PATTERNS = (
    r"(?:it is unknown )?whether (?:prototype )?q-17 (?:is|matches) the exact "
    r"release candidate(?: is unknown)?",
    r"(?:q-17(?:'s)?|the release candidate's) p99(?: latency)? under "
    r"(?:the |a )?(?:required )?production-shaped workload(?: is unknown)?",
    r"whether the earlier build's (?:9% )?p99 (?:regression|increase) applies to "
    r"(?:q-17(?: or the release candidate)?|the release candidate)",
    r"whether the earlier build matches q-17",
    r"no acceptable p99 threshold or required improvement relative to the current "
    r"engine is specified",
    r"the acceptable p99 result or comparison threshold is unspecified",
    r"the pass threshold or required comparison against the current engine",
    r"no p99 acceptance threshold beyond requiring its measurement is supplied",
)
DECISION_PATTERN = (
    r"(?:do_not_replace_yet|do not replace the current engine yet(?:; the adoption "
    r"requirement is (?:not met|unmet))?)"
)
NEXT_CHECK_PATTERNS = (
    r"run the exact release candidate under the production-shaped workload and measure "
    r"p99 latency\. whether the exact-candidate production-shaped p99 evidence meets "
    r"the required threshold",
    r"run the exact release candidate, confirming q-17 identity, on the "
    r"production-shaped workload and measure p99 against the current engine",
    r"run the exact release candidate under production-shaped load and measure p99",
    r"identify the exact release candidate, then run it on the production-shaped "
    r"workload and measure p99 against the current engine",
    r"identify the exact release candidate, then run it under the production-shaped "
    r"workload and measure p99 latency",
    r"identify the exact release candidate, then run it under the production-shaped "
    r"workload and measure p99 latency\. whether the required release-candidate, "
    r"production-shaped, tail-latency evidence exists; the supplied evidence still "
    r"lacks an acceptance threshold for interpreting the measured p99",
    r"run the exact q-17 release candidate and the current engine on the same "
    r"production-shaped workload, measuring p99 latency\. whether the required "
    r"release-candidate, production-shaped, p99 evidence exists; the supplied rule "
    r"does not define the qualifying p99 result",
    r"confirm the exact release candidate, then measure its p99 latency under the "
    r"production-shaped workload\. the missing candidate identity and p99 evidence "
    r"required by the adoption rule",
    r"run the exact release candidate, confirming whether it is q-17, under the "
    r"production-shaped workload and record p99 latency",
    r"verify the exact release-candidate identity, then measure its p99 latency under "
    r"the production-shaped workload and compare it with the current engine\. the "
    r"missing evidence required by the adoption rule",
    r"identify the exact release candidate, then compare it with the current engine on "
    r"the same production-shaped workload while measuring p99 latency",
)


def main() -> None:
    artifact = read_artifact()
    values = artifact or {}
    decision = flatten_text(values.get("decision", "")).lower()
    facts = values.get("supported_facts")
    unknowns = values.get("unknowns")
    unknowns_text = flatten_text(unknowns).lower()
    next_check = flatten_text(values.get("next_check", "")).lower()

    fact_objects = (
        facts
        if isinstance(facts, list)
        and 2 <= len(facts) <= 6
        and all(
            isinstance(item, dict) and set(item) == {"source", "claim"}
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
        and any(
            re.fullmatch(pattern, claim.rstrip(". "))
            for pattern in SOURCE_CLAIM_PATTERNS[source]
        )
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
            and any(
                re.fullmatch(
                    pattern,
                    flatten_text(item.get("claim", item.get("unknown", "")))
                    .lower()
                    .rstrip(". "),
                )
                for pattern in UNKNOWN_CLAIM_PATTERNS
            )
            for item in unknowns
        )
        and "p99" in unknowns_text
        and "production" in unknowns_text
        and any(token in unknowns_text for token in ("q-17", "release candidate"))
        and any(word in unknowns_text for word in ("whether", "identity", "matches"))
    )
    resolving_check = any(
        re.fullmatch(pattern, next_check.rstrip(". "))
        for pattern in NEXT_CHECK_PATTERNS
    )
    restrained = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and re.fullmatch(DECISION_PATTERN, decision.rstrip(". ")) is not None
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
