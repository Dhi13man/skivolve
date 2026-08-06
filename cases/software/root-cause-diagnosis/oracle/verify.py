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
ROOT_CAUSE_PATTERNS = (
    r"the >= 0 condition includes zero, so outcome\(0\) returns ok instead of retry",
    r"the condition attempts >= 0 includes zero, so outcome\(0\) returns ok instead of "
    r"(?:the )?expected retry",
    r"the nonnegative guard treats the initial attempt \(0\) as successful",
    r"the condition treats attempts=0 as successful because >= 0 is true",
    r"worker\.py:2 uses an inclusive nonnegative condition, so the initial attempt "
    r"enters the ok branch",
    r"the condition at worker\.py:2 uses >= 0, so attempts=0 reaches worker\.py:3 and "
    r"returns ok instead of retry",
)
VERIFICATION_PATTERNS = (
    r"executed outcome\(0\) and observed ok; python compilation passed",
    r"reproduced the mismatch with a python assertion, which failed with "
    r"assertionerror: ok",
    r"reproduced outcome\(0\)=ok",
    r"executed outcome\(0\); observed ok",
    r"reproduced the mismatch with a python assertion, which failed with "
    r"assertionerror: ok; parsed worker\.py successfully with python ast parsing\. no "
    r"workspace files remain beyond the supplied inputs",
    r"executed python3 -c from worker import outcome; print\(outcome\(0\)\); observed "
    r"ok\. python compilation also succeeded",
    r"reproduced outcome\(-1\)=retry, outcome\(0\)=ok, and outcome\(1\)=ok; python "
    r"compilation passed",
    r"python3 -m py_compile passed; runtime probes confirmed outcome\(0\) is ok, and "
    r"the expected-contract assertion failed as logged",
    r"executed outcome\(0\) and outcome\(-1\): results were ok and retry, respectively\. "
    r"the workspace remained unchanged",
    r"directly executed outcome\(0\) and outcome\(-1\): results were ok and retry, "
    r"respectively",
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

    concrete_cause = any(
        re.fullmatch(pattern, verdict.rstrip(". ")) for pattern in VERDICT_PATTERNS
    ) and any(
        re.fullmatch(pattern, cause_plain.rstrip(". "))
        for pattern in ROOT_CAUSE_PATTERNS
    )
    bounded_evidence = isinstance(evidence, list) and 2 <= len(evidence) <= 3
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
    checked = any(
        re.fullmatch(pattern, verification_plain.rstrip(". "))
        for pattern in VERIFICATION_PATTERNS
    )
    honest_gap = any(
        re.fullmatch(pattern, unverified.rstrip(". "))
        for pattern in UNVERIFIED_PATTERNS
    )
    restrained = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and bounded_evidence
        and agent_workspace_unchanged()
    )

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
                "honest-verification-label",
                checked and honest_gap,
                "answer distinguishes executed checks from a named remaining gap",
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
