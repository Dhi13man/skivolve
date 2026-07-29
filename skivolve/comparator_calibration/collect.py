"""Collect reference evidence through the release-pinned shared runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

SUITE_ROOT = Path(__file__).resolve().parents[2]
if str(SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(SUITE_ROOT))

from skivolve.comparator_runtime import (  # noqa: E402
    CalibrationError,
    ComparatorRuntime,
    EVIDENCE_TRIAL_KEYS,
    SandboxedClaudeExecutor,
    SpendLedger,
    atomic_write_private_json,
    build_request_bytes,
    canonical_sha256,
    evaluate_evidence,
    expected_transport_hashes,
    exact_object as _exact,
    integer as _integer,
    invocation_id,
    load_private_json,
    parse_raw_provider_response,
    text_value as _text,
    validate_release,
    validate_executor_evidence,
    validate_response,
)


def _provider_output(
    stdout: bytes | str,
) -> tuple[dict[str, Any], list[str], float, str]:
    try:
        raw = stdout.decode("utf-8") if isinstance(stdout, bytes) else stdout
    except UnicodeDecodeError as exc:
        raise CalibrationError("Claude CLI returned non-UTF-8 response bytes") from exc
    response, actual_models, cost_usd = parse_raw_provider_response(raw)
    return response, actual_models, cost_usd, raw


def _header(bundle: Any) -> dict[str, Any]:
    release_summary = validate_release(bundle)
    artifacts = release_summary["artifacts"]
    judge = bundle.release["judge"]
    return {
        "schema_version": 1,
        "release_sha256": release_summary["release_sha256"],
        "corpus_sha256": artifacts["corpus_sha256"],
        "rubric_sha256": artifacts["rubric_sha256"],
        "request_template_sha256": artifacts["request_template_sha256"],
        "response_schema_sha256": artifacts["response_schema_sha256"],
        "judge": {
            "provider": judge["provider"],
            "provider_version": judge["provider_version"],
            "requested_model": judge["requested_model"],
        },
        "spend_ledger": {
            "records": [],
            "records_sha256": canonical_sha256([]),
            "charged_usd": 0.0,
        },
        "trials": [],
    }


def _write_checkpoint(path: Path, evidence: dict[str, Any]) -> None:
    atomic_write_private_json(path, evidence)


def _validated_output_path(root: Path, output: Path) -> Path:
    calibration_root = root.resolve(strict=True)
    evidence_root = calibration_root / "evidence"
    candidate = Path(os.path.abspath(output))
    if candidate.parent != evidence_root:
        raise CalibrationError("collector output must be a direct child of evidence/")
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    metadata = evidence_root.lstat()
    if (
        evidence_root.resolve(strict=True) != evidence_root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise CalibrationError(
            "collector evidence/ directory is not private and stable"
        )
    return candidate


def _resume_trials(
    bundle: Any, path: Path, expected: dict[str, Any]
) -> dict[tuple[str, int, str], dict[str, Any]]:
    if not path.exists():
        return {}
    existing = load_private_json(path)
    ignored = {"trials", "spend_ledger"}
    if {key: value for key, value in existing.items() if key not in ignored} != {
        key: value for key, value in expected.items() if key not in ignored
    }:
        raise CalibrationError("checkpoint header differs from the locked release")
    trials = existing.get("trials")
    if not isinstance(trials, list):
        raise CalibrationError("checkpoint trials must be an array")
    pairs = {pair["id"]: pair for pair in bundle.manifest["pairs"]}
    recovered: dict[tuple[str, int, str], dict[str, Any]] = {}
    for index, raw_trial in enumerate(trials):
        location = f"checkpoint.trials[{index}]"
        trial = _exact(raw_trial, set(EVIDENCE_TRIAL_KEYS), location)
        pair_id = _text(trial["pair_id"], "checkpoint pair_id")
        repetition = _integer(trial["repetition"], "checkpoint repetition")
        order = trial["order"]
        if pair_id not in pairs or order not in {"AB", "BA"}:
            raise CalibrationError("checkpoint contains an unknown pair or order")
        pair = pairs[pair_id]
        if repetition >= pair["repetitions"]:
            raise CalibrationError("checkpoint repetition is outside the release")
        key = (pair_id, repetition, order)
        if key in recovered:
            raise CalibrationError("checkpoint contains a duplicate trial")
        expected_invocation = invocation_id(bundle.release, *key)
        expected_request = build_request_bytes(bundle, pair, repetition, order)
        request_text = _text(trial["request"], f"{location}.request", 2)
        try:
            preserved_request = request_text.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CalibrationError("checkpoint request is not canonical ASCII") from exc
        if preserved_request != expected_request:
            raise CalibrationError("checkpoint request bytes are stale")
        executable_sha256 = trial["executable_sha256"]
        stdin_sha256 = trial["stdin_sha256"]
        spend_attempt_id = trial["spend_attempt_id"]
        if (
            not isinstance(executable_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", executable_sha256) is None
            or not isinstance(spend_attempt_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", spend_attempt_id) is None
        ):
            raise CalibrationError(
                "checkpoint executable or spend provenance is invalid"
            )
        executor = validate_executor_evidence(
            bundle,
            trial["executor"],
            executable_sha256=executable_sha256,
            stdin_sha256=stdin_sha256,
            location=f"{location}.executor",
        )
        expected_transport = expected_transport_hashes(
            bundle, expected_request, executor["command_executable"]
        )
        raw_text = _text(trial["raw_response"], "checkpoint raw_response", 2)
        if (
            trial["invocation_id"] != expected_invocation
            or any(
                trial[field] != expected_hash
                for field, expected_hash in expected_transport.items()
            )
            or trial["raw_response_sha256"]
            != hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            or trial["parsed_response_sha256"] != canonical_sha256(trial["response"])
        ):
            raise CalibrationError("checkpoint invocation or content hash is stale")
        raw_response, raw_models, raw_cost = parse_raw_provider_response(raw_text)
        trial_cost = trial["cost_usd"]
        actual_models = trial["actual_models"]
        if (
            isinstance(trial_cost, bool)
            or not isinstance(trial_cost, (int, float))
            or not math.isfinite(float(trial_cost))
            or trial_cost < 0
            or trial_cost > bundle.release["execution_limits"]["per_invocation_max_usd"]
        ):
            raise CalibrationError("checkpoint cost provenance is invalid")
        if (
            canonical_sha256(raw_response) != canonical_sha256(trial["response"])
            or not isinstance(actual_models, list)
            or not actual_models
            or not all(isinstance(model, str) and model for model in actual_models)
            or len(actual_models) != len(set(actual_models))
            or raw_models != sorted(actual_models)
            or raw_cost != float(trial_cost)
        ):
            raise CalibrationError("checkpoint raw and parsed provenance differ")
        for field in ("provider", "provider_version", "requested_model"):
            if trial[field] != bundle.release["judge"][field]:
                raise CalibrationError("checkpoint provider provenance is stale")
        validate_response(bundle, pair, trial["response"], order)
        recovered[key] = trial
    return recovered


def collect(root: Path, release_name: str, output: Path) -> dict[str, Any]:
    output = _validated_output_path(root, output)
    runtime = ComparatorRuntime.load(root, release_name=release_name)
    bundle = runtime.bundle
    if bundle.release["test_release"]:
        raise CalibrationError("the production collector cannot run a test release")
    executor = SandboxedClaudeExecutor(
        executable="claude",
        repository_root=SUITE_ROOT,
        suite_root=SUITE_ROOT,
        isolation_root=root,
    )
    if executor.provider_version != bundle.release["judge"]["provider_version"]:
        raise CalibrationError("installed Claude CLI version differs from the release")
    evidence = _header(bundle)
    recovered = _resume_trials(bundle, output, evidence)
    evidence["trials"] = list(recovered.values())
    execution_limits = bundle.release["execution_limits"]
    ledger_path = output.with_name(f"{output.name}.spend.jsonl")
    spend_ledger = SpendLedger(execution_limits["run_max_usd"], ledger_path)
    if not spend_ledger.has_journal_records:
        for trial in recovered.values():
            spend_ledger.restore_reconciled(
                trial["spend_attempt_id"],
                execution_limits["per_invocation_max_usd"],
                float(trial["cost_usd"]),
                request_sha256=trial["request_sha256"],
                invocation_id=trial["invocation_id"],
            )
    for pair in bundle.manifest["pairs"]:
        for repetition in range(pair["repetitions"]):
            for order in ("AB", "BA"):
                key = (pair["id"], repetition, order)
                if key in recovered:
                    continue
                request_bytes = build_request_bytes(bundle, pair, repetition, order)
                judge = bundle.release["judge"]
                transport = runtime.run_transport(
                    pair=pair,
                    repetition=repetition,
                    order=order,
                    request_bytes=request_bytes,
                    requested_model=judge["requested_model"],
                    executor=executor,
                    spend_ledger=spend_ledger,
                )
                trial = {
                    "pair_id": pair["id"],
                    "repetition": repetition,
                    "order": order,
                    "invocation_id": invocation_id(
                        bundle.release, pair["id"], repetition, order
                    ),
                    "request": request_bytes.decode("ascii"),
                    "request_sha256": transport.request_sha256,
                    "raw_response": transport.raw_response,
                    "raw_response_sha256": transport.raw_response_sha256,
                    "parsed_response_sha256": transport.parsed_response_sha256,
                    "command_sha256": transport.command_sha256,
                    "stdin_sha256": transport.stdin_sha256,
                    "provider": transport.provider_name,
                    "provider_version": transport.provider_version,
                    "requested_model": transport.requested_model,
                    "actual_models": list(transport.actual_models),
                    "executable_sha256": transport.executor["executable_sha256"],
                    "spend_attempt_id": transport.spend_attempt_id,
                    "cost_usd": transport.cost_usd,
                    "executor": transport.executor,
                    "response": transport.response,
                }
                evidence["trials"].append(trial)
                _sync_spend_evidence(evidence, spend_ledger)
                _write_checkpoint(output, evidence)
    _sync_spend_evidence(evidence, spend_ledger)
    result = evaluate_evidence(bundle, evidence)
    _write_checkpoint(output, evidence)
    return result


def _sync_spend_evidence(evidence: dict[str, Any], spend_ledger: SpendLedger) -> None:
    records = spend_ledger.journal_records()
    evidence["spend_ledger"] = {
        "records": records,
        "records_sha256": canonical_sha256(records),
        "charged_usd": spend_ledger.spent_usd,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--release", default="release.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = collect(args.root, args.release, args.output)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
