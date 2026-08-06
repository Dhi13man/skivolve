from __future__ import annotations

import os
from pathlib import Path
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


EXPECTED_KEYS = {"verdict", "root_cause", "evidence", "verification", "unverified"}
FAILURE_EVIDENCE_PATTERNS = (
    r"failure\.log:2",
    r"failure\.log:2 records expected retry but observed ok for attempts=0",
    r"failure\.log:2 expects retry for attempts=0 but observes ok",
    r"failure\.log:2 reports attempts=0, expected=retry, observed=ok",
    r"failure\.log:2 reports expected retry and observed ok for attempts=0",
)
WORKER_EVIDENCE_PATTERNS = (
    r"worker\.py:2",
    r"worker\.py:2-3",
    r"worker\.py:2-3 routes every attempts >= 0, including 0, to ok",
    r"worker\.py:2-4 returns ok when attempts >= 0 and retry only otherwise",
    r"worker\.py:2-3 classify nonnegative attempts as ok",
    r"worker\.py:2-3 routes all nonnegative attempts, including 0, to ok",
)
DIRECT_EVIDENCE_PATTERN = (
    r"direct evaluation produced outcome\(0\)=ok; boundary values were "
    r"\(-1, retry\), \(0, ok\), \(1, ok\)"
)
ZERO_PATTERN = r"(?:zero|attempts?\s*=\s*0|outcome\(0\)|initial attempt(?:\s*\(?0\)?)?)"
BOUND_PATTERN = r"(?:>=\s*0|nonnegative|inclusive nonnegative)"
INCLUSIVE_RELATION_PATTERNS = (
    rf"{BOUND_PATTERN}[^.;]{{0,50}}\b(?:includes?|captures?|covers?|treats?|"
    rf"classifies?)\b[^.;]{{0,40}}{ZERO_PATTERN}",
    rf"{ZERO_PATTERN}[^.;]{{0,50}}\b(?:satisfies?|meets?)\b[^.;]{{0,40}}"
    rf"{BOUND_PATTERN}",
    rf"{BOUND_PATTERN}(?:\s+(?:condition|guard))?[, ]+\b(?:so|therefore)\b"
    rf"[^.;]{{0,40}}{ZERO_PATTERN}",
    rf"{ZERO_PATTERN}[^.;]{{0,50}}\bbecause\b[^.;]{{0,40}}{BOUND_PATTERN}",
)
WRONG_BRANCH_PATTERNS = (
    rf"{ZERO_PATTERN}[^.;]{{0,80}}\breturns?\s+[\"']?ok\b",
    rf"{ZERO_PATTERN}[^.;]{{0,80}}\b(?:enters?|takes?)\s+(?:the\s+)?ok branch\b",
    rf"\btakes?\s+(?:the\s+)?ok branch\b[^.;]{{0,80}}{ZERO_PATTERN}",
    rf"{ZERO_PATTERN}[^.;]{{0,80}}\breaches?\b[^.;]{{0,40}}"
    r"\breturns?\s+[\"']?ok\b",
    rf"\b(?:treats?|classifies?)\b[^.;]{{0,50}}{ZERO_PATTERN}[^.;]{{0,30}}"
    r"\b(?:as\s+)?(?:ok|successful)\b",
)
NEGATED_WRONG_BRANCH_PATTERN = (
    r"\b(?:never|not|doesn't|does not|isn't|is not)\b[^.;]{0,30}"
    r"\b(?:return|enter|reach|take|treat|classif)\w*\b[^.;]{0,30}"
    r"\b(?:ok|success\w*)\b"
)
VERDICT_PATTERNS = (
    r"failed",
    r"the check fails because attempts=0 is classified as ok",
    r"the check fails because zero attempts are classified as successful",
)
UNVERIFIED_PATTERNS = (
    r"no broader behavior specification or test suite was supplied",
    r"the original check command and its broader environment were not supplied",
    r"the original check command and broader test suite were not supplied",
    r"no production traces were supplied",
    r"the original check command and its broader environment were not supplied, so only "
    r"the reported failure and local function behavior were verified",
    r"no independent test suite or broader behavior specification was supplied for other "
    r"attempt values",
    r"the executable check source is not supplied; only its recorded expectation is "
    r"available",
    r"the original check command and any broader test suite were not supplied",
    r"no separate specification or test file establishes the intended behavior beyond "
    r"failure\.log:2",
    r"no broader retry-boundary specification or test suite is supplied",
)


def main() -> None:
    artifact = read_artifact()
    values = artifact or {}
    verdict = flatten_text(values.get("verdict", "")).lower()
    cause = flatten_text(values.get("root_cause", "")).lower()
    evidence = values.get("evidence")
    evidence_items = (
        [
            flatten_text(item)
            .lower()
            .replace("`", "")
            .replace('"', "")
            .replace("'", "")
            for item in evidence
        ]
        if isinstance(evidence, list)
        else []
    )
    verification = flatten_text(values.get("verification", "")).lower()
    unverified = flatten_text(values.get("unverified", "")).lower()
    cause_plain = cause.replace("`", "").replace('"', "").replace("'", "")
    verification_plain = verification.replace("`", "").replace('"', "").replace("'", "")
    exact_schema = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and all(
            isinstance(artifact.get(field), str)
            for field in ("verdict", "root_cause", "verification", "unverified")
        )
        and isinstance(evidence, list)
        and 2 <= len(evidence) <= 3
        and all(isinstance(item, str) for item in evidence)
    )

    inclusive_matches = [
        match
        for pattern in INCLUSIVE_RELATION_PATTERNS
        if (match := re.search(pattern, cause_plain))
    ]
    bounded_zero = any(
        not re.search(r"\b(?:no|not|never)\b", match.group())
        for match in inclusive_matches
    )
    wrong_branch = any(
        re.search(pattern, cause_plain) for pattern in WRONG_BRANCH_PATTERNS
    ) and not re.search(NEGATED_WRONG_BRANCH_PATTERN, cause_plain)
    concrete_cause = (
        any(re.fullmatch(pattern, verdict.rstrip(". ")) for pattern in VERDICT_PATTERNS)
        and bounded_zero
        and wrong_branch
    )
    bounded_evidence = (
        isinstance(evidence, list)
        and 2 <= len(evidence) <= 3
        and all(isinstance(item, str) for item in evidence)
    )
    failure_matches = [
        any(
            re.fullmatch(pattern, item.strip(". "))
            for pattern in FAILURE_EVIDENCE_PATTERNS
        )
        for item in evidence_items
    ]
    worker_matches = [
        any(
            re.fullmatch(pattern, item.strip(". "))
            for pattern in WORKER_EVIDENCE_PATTERNS
        )
        for item in evidence_items
    ]
    direct_matches = [
        bool(re.fullmatch(DIRECT_EVIDENCE_PATTERN, item.strip(". ")))
        for item in evidence_items
    ]
    line_evidence = (
        bounded_evidence
        and any(failure_matches)
        and any(worker_matches)
        and all(
            failure or worker or direct
            for failure, worker, direct in zip(
                failure_matches, worker_matches, direct_matches, strict=True
            )
        )
    )
    verification_words = re.sub(r"[^a-z0-9()>=_-]+", " ", verification_plain)
    checked = (
        re.search(r"\b(?:run|evaluate|call|invoke|probe)\b", verification_words)
        and re.search(r"\boutcome\s*\(\s*0\s*\)", verification_words)
        and re.search(
            r"\bexpect(?:ed)?\s+(?:(?:the\s+)?"
            r"(?:output|return value|observed value)\s+)?ok"
            r"(?:\s+(?:rather than|not)\s+retry)?\s*$",
            verification_words,
        )
        and not re.search(
            r"\b(?:did not|do not|never|no check|unknown|false|retry instead)\b",
            verification_plain,
        )
    )
    workspace = Path(os.environ["EVAL_WORKSPACE"])
    try:
        worker_lines = (
            workspace.joinpath("worker.py").read_text(encoding="utf-8").splitlines()
        )
        failure_lines = (
            workspace.joinpath("failure.log").read_text(encoding="utf-8").splitlines()
        )
    except (OSError, UnicodeError):
        fixture_grounded = False
    else:
        fixture_grounded = (
            len(worker_lines) >= 4
            and worker_lines[1].strip() == "if attempts >= 0:"
            and worker_lines[2].strip() == 'return "ok"'
            and len(failure_lines) >= 2
            and failure_lines[1].strip()
            == "input.attempts=0 expected=retry observed=ok"
        )
    honest_gap = any(
        re.fullmatch(pattern, unverified.rstrip(". "))
        for pattern in UNVERIFIED_PATTERNS
    )
    restrained = exact_schema and bounded_evidence and agent_workspace_unchanged()

    emit(
        [
            assertion(
                "concrete-root-cause",
                concrete_cause,
                "diagnosis identifies the inclusive zero boundary and wrong branch",
            ),
            assertion(
                "minimal-line-evidence",
                line_evidence,
                "evidence cites only the failing log line and causal code line",
            ),
            assertion(
                "reproducible-verification-check",
                bool(checked) and fixture_grounded and honest_gap,
                "answer gives a reproducible check grounded by the supplied fixture",
            ),
            assertion(
                "diagnostic-report-restraint",
                restrained,
                "answer is bounded to the required schema and leaves files unchanged",
            ),
        ]
    )


if __name__ == "__main__":
    main()
