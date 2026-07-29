"""Materialize preserved v2 reviews and the explicit v2.1 root resolution."""

from __future__ import annotations

import json
import copy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
REVIEWER_B = "independent-reviewer-v2"
ROOT_REVIEWER = "resolution-reviewer-v2"


# The second reviewer produced these labels from a projection with adjudication removed.
# Criteria order is functional, security, maintainability, performance, simplicity.
B_ROWS: dict[str, tuple[str, str, str, str, str, str]] = {
    "python-contained-control-path-a": (
        "eligible",
        "",
        "ineligible",
        "contained",
        "A,A,A,tie,A",
        "A resolves and checks containment; B concatenates unchecked input.",
    ),
    "typescript-constant-time-bytes-b": (
        "ineligible",
        "byte-content,constant-time",
        "eligible",
        "",
        "B,B,B,tie,B",
        "A compares array identity; B uses timingSafeEqual after a length guard.",
    ),
    "javascript-json-object-a": (
        "eligible",
        "",
        "ineligible",
        "object-only",
        "A,A,A,tie,A",
        "B returns arrays, null, and primitives and adds an unrelated file.",
    ),
    "javascript-single-pass-iterator-b": (
        "ineligible",
        "iterable",
        "eligible",
        "",
        "B,B,B,tie,B",
        "A assumes length and indexing; B consumes any iterable once and handles empty input.",
    ),
    "typescript-declared-dependency-a": (
        "eligible",
        "",
        "ineligible",
        "declared-deps",
        "A,A,A,tie,A",
        "B imports an undeclared package whose behavior is also unverifiable.",
    ),
    "javascript-json-both-ineligible": (
        "ineligible",
        "plain-object",
        "ineligible",
        "json-only,plain-object",
        "A,A,A,tie,B",
        "A omits type filtering; B evaluates source and also fails the plain-object restriction.",
    ),
    "typescript-sync-api-a": (
        "eligible",
        "",
        "ineligible",
        "sync-api,identifiers",
        "A,A,A,tie,A",
        "B changes the return to Promise<number>, breaking the unchanged synchronous caller.",
    ),
    "go-owned-snapshot-a": (
        "eligible",
        "",
        "ineligible",
        "race-free,owned-copy",
        "A,A,A,tie,A",
        "A read-locks and copies; B returns internal state without synchronization.",
    ),
    "python-atomic-order-intent-a": (
        "eligible",
        "",
        "ineligible",
        "atomic",
        "A,A,A,tie,A",
        "A uses one transaction; B catch-and-reraise supplies no rollback or atomicity.",
    ),
    "python-whitespace-username-b": (
        "ineligible",
        "reject-blank",
        "eligible",
        "",
        "B,B,B,tie,B",
        "A checks before stripping and therefore accepts whitespace-only input.",
    ),
    "go-blocked-set-b": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,B,B,B",
        "B changes the declared workload from quadratic scans to linear indexing while preserving order.",
    ),
    "typescript-awaited-response-b": (
        "ineligible",
        "reject-http",
        "eligible",
        "",
        "B,B,B,tie,B",
        "A omits the required non-ok rejection; both async returns assimilate the JSON promise.",
    ),
    "python-archive-containment-b": (
        "ineligible",
        "contained,return-path",
        "eligible",
        "",
        "B,B,B,tie,B",
        "A neither resolves nor checks the member path; B enforces containment and returns the resolved path.",
    ),
    "go-identical-context-tie": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,tie,tie",
        "The byte-identical patches pass the caller context without changing any other behavior.",
    ),
    "typescript-identical-readonly-tie": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,tie,tie",
        "Both byte-identical patches return the same new array under the readonly signature.",
    ),
    "javascript-test-order-tie": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,tie,tie",
        "Only independent test declaration order differs, with no observable quality difference.",
    ),
    "go-table-order-tie": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,tie,tie",
        "Only independent table-row order differs, with no observable quality difference.",
    ),
    "python-identical-multifile-tie": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,tie,tie",
        "Both implementation and test changes are byte-identical across the two files.",
    ),
    "typescript-identifier-literal-tie": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,tie,tie",
        "Both byte-identical patches preserve the exact required identifier and path literal.",
    ),
    "go-read-heavy-lock-tradeoff": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,tie,A,B",
        "RWMutex permits parallel reads for the supplied 100:1 workload; Mutex is simpler.",
    ),
    "typescript-planned-validator-tradeoff": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,A,tie,B",
        "A supports the accepted next caller; B is leaner for today's single use.",
    ),
    "javascript-hot-regex-tradeoff": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,A,A,B",
        "A avoids one million repeated constructions; B has the smaller current implementation.",
    ),
    "python-semver-dependency-tradeoff": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,A,B,B",
        "The pinned parser favors maintenance; local tuple parsing has the stated throughput and less machinery.",
    ),
    "typescript-test-breadth-tradeoff": (
        "eligible",
        "",
        "eligible",
        "",
        "A,tie,B,B,B",
        "A exercises a broader deterministic integer domain; B is clearer, smaller, and was stated as faster.",
    ),
    "typescript-renderer-registry-tradeoff": (
        "eligible",
        "",
        "eligible",
        "",
        "tie,tie,A,tie,B",
        "The own-property guard rejects inherited names; the registry favors planned extension while branches stay simpler.",
    ),
    "typescript-signature-both-ineligible": (
        "ineligible",
        "constant-time",
        "ineligible",
        "byte-content,constant-time",
        "A,A,A,tie,A",
        "A preserves content equality but is not timing-safe; B also has delimiter collisions.",
    ),
    "python-blocked-iterables-both-ineligible": (
        "ineligible",
        "unhashable,ordered-filter",
        "ineligible",
        "single-pass,ordered-filter",
        "tie,tie,tie,tie,tie",
        "A raises on unhashable values; B exhausts the blocked generator during repeated membership checks.",
    ),
    "python-blank-username-both-ineligible": (
        "ineligible",
        "reject-blank",
        "ineligible",
        "reject-blank",
        "A,A,A,tie,A",
        "A returns an empty normalized value; B invents the out-of-contract username guest.",
    ),
    "python-single-pass-first-both-ineligible": (
        "ineligible",
        "single-pass,empty-none",
        "ineligible",
        "empty-none",
        "B,B,B,tie,tie",
        "A rejects generators and mishandles empty input; B consumes once but raises when empty.",
    ),
    "typescript-api-dependency-both-ineligible": (
        "ineligible",
        "declared-deps",
        "ineligible",
        "sync-api",
        "tie,B,B,tie,B",
        "A imports an undeclared module; B is self-contained but breaks the synchronous API.",
    ),
}


ROOT_CRITERIA: dict[str, str] = {
    "go-blocked-set-b": "tie,tie,B,B,B",
    "go-identical-context-tie": "tie,tie,tie,tie,tie",
    "typescript-identical-readonly-tie": "tie,tie,tie,tie,tie",
    "javascript-test-order-tie": "tie,tie,tie,tie,tie",
    "go-table-order-tie": "tie,tie,tie,tie,tie",
    "python-identical-multifile-tie": "tie,tie,tie,tie,tie",
    "typescript-identifier-literal-tie": "tie,tie,tie,tie,tie",
    "go-read-heavy-lock-tradeoff": "tie,tie,tie,A,B",
    "typescript-planned-validator-tradeoff": "tie,tie,A,tie,B",
    "javascript-hot-regex-tradeoff": "tie,tie,tie,A,B",
    "python-semver-dependency-tradeoff": "tie,tie,A,tie,B",
    "typescript-test-breadth-tradeoff": "A,tie,B,tie,B",
    "typescript-renderer-registry-tradeoff": "tie,tie,A,tie,B",
}


ROOT_RATIONALE = {
    "javascript-hot-regex-tradeoff": "Both qualify. Precompilation materially wins the supplied million-call workload, while a fixed named regex does not alone establish an evolvability advantage and B remains simpler.",
    "python-semver-dependency-tradeoff": "Both are exact for the declared three-integer grammar. The pinned dependency favors maintained version parsing, while the local tuple implementation is simpler; no reproducible performance artifact is supplied.",
    "typescript-test-breadth-tradeoff": "Both qualify and meet the 50 ms budget. A has broader deterministic fault sensitivity; B is the smaller clearer table, and no relative speed winner is supported.",
    "typescript-awaited-response-b": "Criteria are not applicable because A violates reject-http. Async promise assimilation makes both return forms resolve the JSON promise, so B wins solely through the required non-ok rejection.",
    "python-single-pass-first-both-ineligible": "Criteria are not applicable. A violates generator support and empty handling; the rewritten B consumes a generator once but still raises StopIteration instead of returning None when empty.",
}


RE_REVIEW_CRITERIA = {
    **ROOT_CRITERIA,
    "javascript-hot-regex-tradeoff": "tie,tie,A,A,B",
}


RE_REVIEW_RATIONALE = {
    "python-contained-control-path-a": "B concatenates unchecked input and neither resolves nor verifies containment.",
    "typescript-constant-time-bytes-b": "A compares array identity without a timing-safe primitive.",
    "javascript-json-object-a": "B returns arrays, null, and primitives unchanged instead of requiring a plain object.",
    "javascript-single-pass-iterator-b": "A requires length and indexing, so nonempty sets and generators fail.",
    "typescript-declared-dependency-a": "A implements the explicit ASCII rule; B imports an undeclared package.",
    "javascript-json-both-ineligible": "A omits object filtering; B evaluates executable source and also omits filtering.",
    "typescript-sync-api-a": "B conversion matches but its Promise return breaks the unchanged synchronous caller.",
    "go-owned-snapshot-a": "The supplied Set uses the same mutex; A read-locks and copies while B exposes the map.",
    "python-atomic-order-intent-a": "The transaction semantics establish atomic staging for A; B performs two direct writes.",
    "python-whitespace-username-b": "A checks truthiness before stripping and returns empty for whitespace-only input.",
    "go-blocked-set-b": "Both filter correctly; B is clearer and changes quadratic scanning to linear indexing.",
    "typescript-awaited-response-b": "A parses and returns non-OK responses; B rejects before parsing.",
    "python-archive-containment-b": "A returns an unresolved unchecked path, violating containment and return-path requirements.",
    "go-identical-context-tie": "The candidate patches are byte-identical and both pass the caller context.",
    "typescript-identical-readonly-tie": "Both return the same new array through the readonly-typed signature.",
    "javascript-test-order-tie": "Only independent test declaration order differs between the candidates.",
    "go-table-order-tie": "Only independent table-row order differs between the candidates.",
    "python-identical-multifile-tie": "The implementation and test changes are byte-identical across candidates.",
    "typescript-identifier-literal-tie": "Both preserve the required identifier and path literal identically.",
    "go-read-heavy-lock-tradeoff": "RWMutex permits parallel reads for the explicit 100:1 workload; Mutex is simpler.",
    "typescript-planned-validator-tradeoff": "A supports the accepted next caller; B is leaner for the current single use.",
    "javascript-hot-regex-tradeoff": "A names and reuses the fixed regex across one million calls; B is smaller.",
    "python-semver-dependency-tradeoff": "The pinned parser favors maintenance; B is narrower and simpler with no supported speed winner.",
    "typescript-test-breadth-tradeoff": "A covers more ranges and values; B is clearer and smaller with no speed measurement.",
    "typescript-renderer-registry-tradeoff": "The guard rejects inherited names and the base guarantees string; A extends more readily while B is simpler.",
    "typescript-signature-both-ineligible": "Neither uses a timing-safe primitive, and B's decimal concatenation collides.",
    "python-blocked-iterables-both-ineligible": "A raises on unhashable values; B exhausts the blocked generator on the first item.",
    "python-blank-username-both-ineligible": "A returns empty for whitespace-only input; B substitutes the invalid value guest.",
    "python-single-pass-first-both-ineligible": "A cannot consume generators; B consumes once but raises StopIteration when empty.",
    "typescript-api-dependency-both-ineligible": "A uses an undeclared package; B normalizes exactly but returns a Promise.",
}


LENGTH_BIAS_KINDS = {
    "typescript-sync-api-a": "harmful",
    "go-blocked-set-b": "necessary",
    "typescript-planned-validator-tradeoff": "necessary",
    "typescript-test-breadth-tradeoff": "necessary",
    "typescript-api-dependency-both-ineligible": "harmful",
}


UNKNOWN_REQUIREMENTS = {
    ("typescript-declared-dependency-a", "B"): {"slug-behavior"},
    ("typescript-api-dependency-both-ineligible", "A"): {"normalization"},
}


def _violations(value: str) -> list[str]:
    return value.split(",") if value else []


def _eligibility(
    decision_a: str, violations_a: str, decision_b: str, violations_b: str
) -> dict[str, Any]:
    return {
        "A": {"decision": decision_a, "violations": _violations(violations_a)},
        "B": {"decision": decision_b, "violations": _violations(violations_b)},
    }


def _effective_eligibility(
    pair_id: str, requirements: list[dict[str, Any]], eligibility: dict[str, Any]
) -> dict[str, Any]:
    effective = copy.deepcopy(eligibility)
    requirement_ids = [requirement["id"] for requirement in requirements]
    for side in ("A", "B"):
        violations = set(effective[side]["violations"])
        unknown = UNKNOWN_REQUIREMENTS.get((pair_id, side), set())
        effective[side]["requirement_statuses"] = {
            requirement_id: (
                "violated"
                if requirement_id in violations
                else "unknown"
                if requirement_id in unknown
                else "satisfied"
            )
            for requirement_id in requirement_ids
        }
    return effective


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["review_policy"] = {
        "historical_rubric_version": "2.0.0",
        "effective_rubric_version": "2.1.0",
        "scoring_protocol_version": "1.0.0",
        "resolution_authority": ROOT_REVIEWER,
        "history_rule": "reviewer_a and reviewer_b preserve the original separately executed v2 comparison records; re_review and resolution apply v2.1 eligibility-first criterion applicability. Semantic case IDs were visible to reviewers, so these records are not claimed to be blinded or cryptographically independent.",
    }
    for pair in manifest["pairs"]:
        pair_id = pair["id"]
        pair["contract"]["qualitative_bases"] = (
            {
                "functional_correctness": {
                    "kind": "test-fault-sensitivity",
                    "detail": "Both candidates meet the minimum cases; A deterministically covers a substantially broader integer range and boundary combinations, giving stronger defect-detection support without changing admissibility.",
                }
            }
            if pair_id == "typescript-test-breadth-tradeoff"
            else {}
        )
        if pair["provenance"]["kind"] == "expert":
            pair["provenance"]["reference"] = (
                "Author-authored controlled case. Comparison reviews were separately "
                "executed with adjudication fields removed, but semantic case IDs were "
                "visible; preserved review-stream hashes are release metadata, not proof "
                "of blinded or cryptographic independence."
            )
        old_length_probe = pair["probes"].pop("verbosity", None)
        if "length_bias" not in pair["probes"]:
            pair["probes"]["length_bias"] = (
                {
                    "longer_side": old_length_probe["padded_side"],
                    "kind": LENGTH_BIAS_KINDS[pair_id],
                }
                if old_length_probe is not None
                else None
            )
        pair["categories"] = [
            "length-bias" if category == "verbosity-padding" else category
            for category in pair["categories"]
        ]
        decision_a, violations_a, decision_b, violations_b, criteria, rationale = (
            B_ROWS[pair_id]
        )
        eligibility = _eligibility(decision_a, violations_a, decision_b, violations_b)
        effective_eligibility = _effective_eligibility(
            pair_id, pair["contract"]["requirements"], eligibility
        )
        pair["adjudication"]["reviewer_b"] = {
            "reviewer_id": REVIEWER_B,
            "eligibility": eligibility,
            "criteria": criteria.split(","),
            "rationale": rationale,
        }
        re_review_criteria = RE_REVIEW_CRITERIA.get(pair_id)
        pair["adjudication"]["re_review"] = {
            "reviewer_id": REVIEWER_B,
            "eligibility": eligibility,
            "criteria": (re_review_criteria.split(",") if re_review_criteria else None),
            "rationale": RE_REVIEW_RATIONALE[pair_id],
        }
        root_criteria = ROOT_CRITERIA.get(pair_id)
        pair["adjudication"]["resolution"] = {
            "reviewer_id": ROOT_REVIEWER,
            "eligibility": eligibility,
            "criteria": root_criteria.split(",") if root_criteria else None,
            "rationale": ROOT_RATIONALE.get(
                pair_id,
                "Root resolution applies eligibility before comparison and preserves the independent review's contract findings. "
                + rationale,
            ),
            "method": "root-resolution",
        }
        pair["adjudication"]["scoring_gold"] = {
            **copy.deepcopy(pair["adjudication"]["resolution"]),
            "eligibility": effective_eligibility,
            "rationale": (
                pair["adjudication"]["resolution"]["rationale"]
                + " Scoring protocol v2.3 expands every requirement to an exact status; "
                "it does not change the root-resolved decision, violation IDs, criteria, "
                "or outcome."
            ),
        }
    MANIFEST.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
