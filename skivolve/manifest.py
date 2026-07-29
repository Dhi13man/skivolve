"""Manifest loading and strict validation for the evaluation harness."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .comparator_calibration import calibration as _calibration
from .comparator_profiles import (
    BUILTIN_PROFILE_IDS,
    ComparatorProfileError,
    ComparatorProfileResources,
    resolve_builtin_profile,
    resolve_profile_directory,
)
from .provider_capabilities import (
    ProviderCapabilityError,
    capabilities_for,
)


IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SKILL_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TOOL_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]*$")
CODEX_REASONING_EFFORTS = {
    "gpt-5.6-luna": frozenset({"low", "medium", "high", "xhigh", "max"}),
    "gpt-5.6-terra": frozenset({"low", "medium", "high", "xhigh", "max", "ultra"}),
}
BILLING_BASES = frozenset({"metered_api", "chatgpt_subscription"})
MAX_SUITE_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 60 * 60
SUITE_SCHEMA_VERSION = 1


class ManifestError(ValueError):
    """Raised when a suite manifest violates its executable contract."""


@dataclass(frozen=True)
class ProviderConfig:
    adapter_id: str
    kind: str
    model: str
    timeout_seconds: int
    executable: str | None = None
    max_budget_usd: float | None = None
    reasoning_effort: str | None = None
    billing_basis: str = "metered_api"
    protocol_lock: Path | None = None


@dataclass(frozen=True)
class VariantSpec:
    id: str
    kind: str
    git_ref: str | None = None
    root: Path | None = None
    source_ref: str | None = None


@dataclass(frozen=True)
class ComparisonSpec:
    id: str
    control: str
    treatment: str
    repetitions: int
    comparator_order: str


@dataclass(frozen=True)
class VerifierSpec:
    argv: tuple[str, ...]
    timeout_seconds: int
    required_tools: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactContractSpec:
    kind: str


@dataclass(frozen=True)
class CaseSpec:
    id: str
    skill: str
    bundle_source: PurePosixPath
    split: str
    prompt_file: Path
    fixture_dir: Path
    verifier: VerifierSpec
    context_files: tuple[PurePosixPath, ...]
    timeout_seconds: int
    critical_expectations: tuple[str, ...]
    comparator_contract: dict[str, Any] | None
    artifact_contract: ArtifactContractSpec


@dataclass(frozen=True)
class ComparatorProfileSpec:
    kind: str
    id: str
    root: Path | None
    resources: ComparatorProfileResources | None


@dataclass(frozen=True)
class SuiteSpec:
    path: Path
    root: Path
    repository_root: Path
    suite_id: str
    seed: int
    evaluation_mode: str
    provider: ProviderConfig
    comparator: ProviderConfig | None
    comparator_profile: ComparatorProfileSpec | None
    variants: tuple[VariantSpec, ...]
    comparisons: tuple[ComparisonSpec, ...]
    cases: tuple[CaseSpec, ...]
    shared_verifier_dir: Path | None
    holdout_comparison_ids: tuple[str, ...]
    manifest_hash: str
    raw_bytes: bytes
    raw: dict[str, Any]

    @property
    def variants_by_id(self) -> dict[str, VariantSpec]:
        return {variant.id: variant for variant in self.variants}

    def assert_unchanged(self) -> None:
        """Fail if the manifest path or exact loaded bytes drifted."""

        resolved, observed = _read_suite_file(self.path, action="reread")
        if resolved != self.path or observed != self.raw_bytes:
            raise ManifestError("suite manifest bytes drifted after load")


def _reject_constant(value: str) -> None:
    raise ManifestError(f"non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _file_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _read_suite_file(path: str | Path, *, action: str) -> tuple[Path, bytes]:
    supplied = Path(path).expanduser()
    try:
        metadata = supplied.lstat()
    except OSError as exc:
        raise ManifestError(f"cannot {action} suite manifest: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ManifestError("suite manifest must be a regular, non-symlink file")
    if metadata.st_size > MAX_SUITE_BYTES:
        raise ManifestError("suite manifest exceeds the 16 MiB size limit")

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(supplied, flags)
    except OSError as exc:
        raise ManifestError(f"cannot {action} suite manifest: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ManifestError("suite manifest must remain a regular file")
        if _file_fingerprint(opened) != _file_fingerprint(metadata):
            raise ManifestError("suite manifest changed while it was opened")

        chunks: list[bytes] = []
        remaining = MAX_SUITE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_bytes = b"".join(chunks)
        if len(raw_bytes) > MAX_SUITE_BYTES:
            raise ManifestError("suite manifest exceeds the 16 MiB size limit")
        if _file_fingerprint(os.fstat(descriptor)) != _file_fingerprint(opened):
            raise ManifestError("suite manifest changed while it was read")

        try:
            resolved = supplied.resolve(strict=True)
            resolved_metadata = resolved.stat()
        except OSError as exc:
            raise ManifestError(f"cannot resolve suite manifest: {exc}") from exc
        if _file_fingerprint(resolved_metadata) != _file_fingerprint(opened):
            raise ManifestError("suite manifest path changed while it was read")
        return resolved, raw_bytes
    except OSError as exc:
        raise ManifestError(f"cannot {action} suite manifest: {exc}") from exc
    finally:
        os.close(descriptor)


def _object(
    value: Any,
    location: str,
    *,
    required: set[str],
    allowed: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{location} must be an object")
    missing = sorted(required - value.keys())
    if missing:
        raise ManifestError(
            f"{location} is missing required keys: {', '.join(missing)}"
        )
    unknown = sorted(value.keys() - allowed)
    if unknown:
        raise ManifestError(f"{location} has unknown keys: {', '.join(unknown)}")
    return value


def _string(
    value: Any, location: str, *, pattern: re.Pattern[str] | None = None
) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{location} must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ManifestError(f"{location} has an invalid value: {value!r}")
    return value


def _integer(
    value: Any, location: str, *, minimum: int, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{location} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        bounds = (
            f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
        )
        raise ManifestError(f"{location} must be {bounds}")
    return value


def _number(
    value: Any, location: str, *, exclusive_minimum: float | None = None
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ManifestError(f"{location} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ManifestError(f"{location} must be finite")
    if exclusive_minimum is not None and result <= exclusive_minimum:
        raise ManifestError(f"{location} must be greater than {exclusive_minimum}")
    return result


def _list(value: Any, location: str, *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list):
        raise ManifestError(f"{location} must be an array")
    if len(value) < minimum:
        raise ManifestError(f"{location} must contain at least {minimum} item(s)")
    return value


def _suite_path(root: Path, value: Any, location: str, *, kind: str) -> Path:
    raw = _string(value, location)
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ManifestError(f"{location} must be relative to the suite root")
    logical = root / candidate
    resolved = logical.resolve()
    if not resolved.is_relative_to(root):
        raise ManifestError(f"{location} escapes the suite root")
    if kind == "file":
        if logical.is_symlink() or not resolved.is_file():
            raise ManifestError(f"{location} is not a regular, non-symlink file: {raw}")
    elif kind == "directory":
        if logical.is_symlink() or not resolved.is_dir():
            raise ManifestError(f"{location} is not a non-symlink directory: {raw}")
    else:
        raise AssertionError(f"unsupported path kind: {kind}")
    return resolved


def _suite_protocol_lock(root: Path, value: Any, location: str) -> Path:
    raw = _string(value, location)
    normalized = PurePosixPath(raw).as_posix()
    if normalized != raw or raw.startswith("/") or ".." in PurePosixPath(raw).parts:
        raise ManifestError(f"{location} must be a canonical suite-relative POSIX path")
    return _suite_path(root, raw, location, kind="file")


def _suite_profile_directory(root: Path, value: Any, location: str) -> Path:
    raw = _string(value, location)
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path == PurePosixPath(".")
        or ".." in path.parts
        or path.as_posix() != raw
        or raw.startswith("./")
    ):
        raise ManifestError(f"{location} must be a canonical suite-relative path")
    logical = root
    try:
        for part in path.parts:
            logical = logical / part
            if logical.is_symlink():
                raise ManifestError(f"{location} must not traverse a symlink")
        resolved = logical.resolve(strict=True)
    except OSError as exc:
        raise ManifestError(f"cannot resolve {location}: {exc}") from exc
    if not resolved.is_relative_to(root) or not resolved.is_dir():
        raise ManifestError(f"{location} must name a contained directory")
    return resolved


def _shared_verifier_directory(
    root: Path, value: Any, location: str = "shared_verifier_dir"
) -> Path | None:
    if value is None:
        return None
    raw = _string(value, location)
    try:
        raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ManifestError(f"{location} must be valid UTF-8 text") from exc
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path == PurePosixPath(".")
        or ".." in path.parts
        or path.as_posix() != raw
        or raw.startswith("./")
        or "//" in raw
        or raw.endswith("/")
        or "\\" in raw
        or any(ord(character) < 32 for character in raw)
    ):
        raise ManifestError(f"{location} must be a canonical suite-relative path")
    logical = root
    try:
        for part in path.parts:
            logical = logical / part
            if logical.is_symlink():
                raise ManifestError(f"{location} must not traverse a symlink")
        resolved = logical.resolve(strict=True)
    except OSError as exc:
        raise ManifestError(f"cannot resolve {location}: {exc}") from exc
    if not resolved.is_relative_to(root) or not resolved.is_dir():
        raise ManifestError(f"{location} must name a contained directory")
    return resolved


def _assert_shared_verifier_separation(
    shared_verifier_dir: Path | None,
    repository_root: Path,
    variants: tuple[VariantSpec, ...],
    cases: tuple[CaseSpec, ...],
) -> None:
    if shared_verifier_dir is None:
        return
    for case in cases:
        protected_paths = {case.prompt_file.parent, case.fixture_dir}
        source_roots = {repository_root} | {
            variant.root
            for variant in variants
            if variant.kind == "worktree" and variant.root is not None
        }
        for source_root in source_roots:
            protected_paths.add(
                (source_root / Path(*case.bundle_source.parts)).resolve()
            )
            protected_paths.update(
                (source_root / Path(*context_file.parts)).resolve()
                for context_file in case.context_files
            )
        if any(
            shared_verifier_dir.is_relative_to(protected_path)
            or protected_path.is_relative_to(shared_verifier_dir)
            for protected_path in protected_paths
        ):
            raise ManifestError(
                f"shared_verifier_dir overlaps case {case.id} or evaluated source"
            )


def _parse_comparator_profile(raw: Any, suite_root: Path) -> ComparatorProfileSpec:
    data = _object(
        raw,
        "comparator_profile",
        required={"kind"},
        allowed={"kind", "id", "path"},
    )
    kind = _string(data["kind"], "comparator_profile.kind")
    try:
        if kind == "builtin":
            exact = _object(
                data,
                "comparator_profile",
                required={"kind", "id"},
                allowed={"kind", "id"},
            )
            profile_id = _string(exact["id"], "comparator_profile.id")
            resources = resolve_builtin_profile(profile_id)
            return ComparatorProfileSpec(
                kind="builtin",
                id=profile_id,
                root=None,
                resources=resources,
            )
        if kind == "suite_local":
            exact = _object(
                data,
                "comparator_profile",
                required={"kind", "path"},
                allowed={"kind", "path"},
            )
            profile_root = _suite_profile_directory(
                suite_root,
                exact["path"],
                "comparator_profile.path",
            )
            resources = resolve_profile_directory(profile_root)
            if resources.descriptor.id in BUILTIN_PROFILE_IDS:
                raise ManifestError(
                    "suite-local comparator profile must not shadow a built-in id"
                )
            return ComparatorProfileSpec(
                kind="suite_local",
                id=resources.descriptor.id,
                root=profile_root,
                resources=resources,
            )
    except ComparatorProfileError as exc:
        raise ManifestError(f"invalid comparator profile: {exc}") from exc
    raise ManifestError("comparator_profile.kind must be 'builtin' or 'suite_local'")


def _root_path(root: Path, value: Any, location: str) -> Path:
    raw = _string(value, location)
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ManifestError(f"{location} must be relative to the suite root")
    resolved = (root / candidate).resolve()
    if not resolved.is_dir():
        raise ManifestError(f"{location} is not a directory: {raw}")
    return resolved


def _repository_path(value: Any, location: str) -> PurePosixPath:
    raw = _string(value, location)
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        raise ManifestError(
            f"{location} must be a repository-relative path without parent traversal"
        )
    return path


def _bundle_source_path(value: Any, location: str) -> PurePosixPath:
    raw = _string(value, location)
    try:
        raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ManifestError(f"{location} must be valid UTF-8 text") from exc
    path = _repository_path(raw, location)
    if (
        path.as_posix() != raw
        or raw.startswith("./")
        or "//" in raw
        or raw.endswith("/")
        or "\\" in raw
        or any(ord(character) < 32 for character in raw)
    ):
        raise ManifestError(f"{location} must be a canonical repository-relative path")
    return path


def _unique_ids(values: list[str], location: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise ManifestError(
            f"{location} contains duplicate ids: {', '.join(sorted(duplicates))}"
        )


def _parse_provider(
    raw: Any,
    location: str,
    suite_root: Path,
    *,
    role: str,
    allow_codex: bool = True,
) -> ProviderConfig:
    data = _object(
        raw,
        location,
        required={"adapter", "model", "timeout_seconds"},
        allowed={
            "adapter",
            "model",
            "timeout_seconds",
            "executable",
            "max_budget_usd",
            "reasoning_effort",
            "billing_basis",
            "protocol_lock",
        },
    )
    adapter_id = _string(data["adapter"], f"{location}.adapter")
    try:
        capabilities = capabilities_for(adapter_id, role=role)
    except ProviderCapabilityError as exc:
        raise ManifestError(str(exc)) from exc
    kind = capabilities.provider_kind
    if kind == "codex" and not allow_codex:
        raise ManifestError("comparator.kind must not be 'codex'")
    executable = None
    max_budget_usd = None
    reasoning_effort = None
    protocol_lock = None
    if "executable" in data:
        executable = _string(data["executable"], f"{location}.executable")
    if "max_budget_usd" in data:
        max_budget_usd = _number(
            data["max_budget_usd"], f"{location}.max_budget_usd", exclusive_minimum=0
        )
    if "reasoning_effort" in data:
        reasoning_effort = _string(
            data["reasoning_effort"], f"{location}.reasoning_effort"
        )
    billing_basis = _string(
        data.get("billing_basis", "metered_api"), f"{location}.billing_basis"
    )
    if billing_basis not in BILLING_BASES:
        raise ManifestError(
            f"{location}.billing_basis must be 'metered_api' or 'chatgpt_subscription'"
        )
    if "protocol_lock" in data:
        protocol_lock = _suite_protocol_lock(
            suite_root,
            data["protocol_lock"],
            f"{location}.protocol_lock",
        )
    if kind == "claude" and (executable is None or max_budget_usd is None):
        raise ManifestError(f"Claude {location} requires executable and max_budget_usd")
    if kind == "codex":
        missing = sorted(
            {
                "executable",
                "reasoning_effort",
                "billing_basis",
                "protocol_lock",
            }
            - data.keys()
        )
        if missing:
            raise ManifestError(f"Codex {location} requires {', '.join(missing)}")
        if max_budget_usd is not None:
            raise ManifestError(f"Codex {location} must not set max_budget_usd")
        model = _string(data["model"], f"{location}.model")
        supported_efforts = CODEX_REASONING_EFFORTS.get(model)
        if supported_efforts is None:
            raise ManifestError(
                f"{location}.model must be 'gpt-5.6-luna' or 'gpt-5.6-terra'"
            )
        if reasoning_effort not in supported_efforts:
            choices = ", ".join(sorted(supported_efforts))
            raise ManifestError(
                f"{location}.reasoning_effort must be one of: {choices}"
            )
        if billing_basis != "chatgpt_subscription":
            raise ManifestError(
                f"Codex {location}.billing_basis must be 'chatgpt_subscription'"
            )
    else:
        model = _string(data["model"], f"{location}.model")
        if reasoning_effort is not None or protocol_lock is not None:
            raise ManifestError(
                f"{location} reasoning_effort and protocol_lock are Codex-only"
            )
        if billing_basis != "metered_api":
            raise ManifestError(
                f"{location}.billing_basis must be 'metered_api' for {kind}"
            )
    return ProviderConfig(
        adapter_id=adapter_id,
        kind=kind,
        executable=executable,
        model=model,
        max_budget_usd=max_budget_usd,
        timeout_seconds=_integer(
            data["timeout_seconds"],
            f"{location}.timeout_seconds",
            minimum=1,
            maximum=MAX_TIMEOUT_SECONDS,
        ),
        reasoning_effort=reasoning_effort,
        billing_basis=billing_basis,
        protocol_lock=protocol_lock,
    )


def _parse_variants(raw: Any, suite_root: Path) -> tuple[VariantSpec, ...]:
    items = _list(raw, "variants", minimum=2)
    variants: list[VariantSpec] = []
    for index, item in enumerate(items):
        location = f"variants[{index}]"
        if not isinstance(item, dict):
            raise ManifestError(f"{location} must be an object")
        kind = _string(item.get("kind"), f"{location}.kind")
        common = {"id", "kind"}
        if kind == "without_skill":
            data = _object(item, location, required=common, allowed=common)
            variant = VariantSpec(
                _string(data["id"], f"{location}.id", pattern=IDENTIFIER_RE), kind
            )
        elif kind == "git_ref":
            data = _object(
                item,
                location,
                required=common | {"git_ref"},
                allowed=common | {"git_ref"},
            )
            variant = VariantSpec(
                _string(data["id"], f"{location}.id", pattern=IDENTIFIER_RE),
                kind,
                git_ref=_string(data["git_ref"], f"{location}.git_ref"),
            )
        elif kind == "worktree":
            data = _object(
                item,
                location,
                required=common | {"root", "source_ref"},
                allowed=common | {"root", "source_ref"},
            )
            variant = VariantSpec(
                _string(data["id"], f"{location}.id", pattern=IDENTIFIER_RE),
                kind,
                root=_root_path(suite_root, data["root"], f"{location}.root"),
                source_ref=_string(data["source_ref"], f"{location}.source_ref"),
            )
        else:
            raise ManifestError(f"{location}.kind has unsupported value: {kind!r}")
        variants.append(variant)
    _unique_ids([variant.id for variant in variants], "variants")
    return tuple(variants)


def _parse_comparisons(raw: Any, variant_ids: set[str]) -> tuple[ComparisonSpec, ...]:
    items = _list(raw, "comparisons", minimum=1)
    comparisons: list[ComparisonSpec] = []
    fields = {"id", "control", "treatment", "repetitions", "comparator_order"}
    for index, item in enumerate(items):
        location = f"comparisons[{index}]"
        data = _object(item, location, required=fields, allowed=fields)
        control = _string(data["control"], f"{location}.control", pattern=IDENTIFIER_RE)
        treatment = _string(
            data["treatment"], f"{location}.treatment", pattern=IDENTIFIER_RE
        )
        if control == treatment:
            raise ManifestError(f"{location} must compare two distinct variants")
        for field, value in (("control", control), ("treatment", treatment)):
            if value not in variant_ids:
                raise ManifestError(
                    f"{location}.{field} references unknown variant: {value}"
                )
        order = _string(data["comparator_order"], f"{location}.comparator_order")
        if order != "ab_ba":
            raise ManifestError(f"{location}.comparator_order must be 'ab_ba'")
        comparisons.append(
            ComparisonSpec(
                id=_string(data["id"], f"{location}.id", pattern=IDENTIFIER_RE),
                control=control,
                treatment=treatment,
                repetitions=_exact_repetitions(
                    data["repetitions"], f"{location}.repetitions"
                ),
                comparator_order=order,
            )
        )
    _unique_ids([comparison.id for comparison in comparisons], "comparisons")
    return tuple(comparisons)


def _parse_holdout_comparison_ids(
    raw: Any, comparisons: tuple[ComparisonSpec, ...]
) -> tuple[str, ...]:
    data = _object(
        raw,
        "holdout",
        required={"comparison_ids"},
        allowed={"comparison_ids"},
    )
    values = _list(data["comparison_ids"], "holdout.comparison_ids", minimum=1)
    selected = tuple(
        _string(
            value,
            f"holdout.comparison_ids[{index}]",
            pattern=IDENTIFIER_RE,
        )
        for index, value in enumerate(values)
    )
    if len(set(selected)) != len(selected):
        raise ManifestError("holdout.comparison_ids contains duplicates")
    comparison_ids = {comparison.id for comparison in comparisons}
    unknown = set(selected) - comparison_ids
    if unknown:
        raise ManifestError(
            "holdout.comparison_ids references unknown comparisons: "
            + ", ".join(sorted(unknown))
        )
    canonical = tuple(
        comparison.id for comparison in comparisons if comparison.id in set(selected)
    )
    if selected != canonical:
        raise ManifestError(
            "holdout.comparison_ids must follow canonical manifest comparison order"
        )
    return selected


def _parse_cases(
    raw: Any,
    suite_root: Path,
    *,
    require_comparator_contract: bool,
    comparator_contract_vocabulary: dict[str, frozenset[str]] | None,
) -> tuple[CaseSpec, ...]:
    items = _list(raw, "cases", minimum=1)
    cases: list[CaseSpec] = []
    case_fields = {
        "id",
        "skill",
        "bundle_source",
        "split",
        "prompt_file",
        "fixture_dir",
        "verifier",
        "context_files",
        "timeout_seconds",
        "critical_expectations",
        "comparator_contract",
        "artifact_contract",
    }
    required_case_fields = case_fields - {"comparator_contract"}
    if require_comparator_contract:
        required_case_fields.add("comparator_contract")
    allowed_case_fields = required_case_fields
    verifier_fields = {"argv", "timeout_seconds", "required_tools"}
    for index, item in enumerate(items):
        location = f"cases[{index}]"
        data = _object(
            item,
            location,
            required=required_case_fields,
            allowed=allowed_case_fields,
        )
        split = _string(data["split"], f"{location}.split")
        if split not in {"train", "validation", "holdout"}:
            raise ManifestError(
                f"{location}.split must be 'train', 'validation', or 'holdout'"
            )
        verifier_data = _object(
            data["verifier"],
            f"{location}.verifier",
            required=verifier_fields,
            allowed=verifier_fields,
        )
        argv_items = _list(
            verifier_data["argv"], f"{location}.verifier.argv", minimum=1
        )
        argv = tuple(
            _string(value, f"{location}.verifier.argv[{argv_index}]")
            for argv_index, value in enumerate(argv_items)
        )
        required_tool_items = _list(
            verifier_data["required_tools"],
            f"{location}.verifier.required_tools",
        )
        required_tools = tuple(
            _string(
                value,
                f"{location}.verifier.required_tools[{tool_index}]",
                pattern=TOOL_RE,
            )
            for tool_index, value in enumerate(required_tool_items)
        )
        if len(set(required_tools)) != len(required_tools):
            raise ManifestError(
                f"{location}.verifier.required_tools contains duplicates"
            )
        context_items = _list(data["context_files"], f"{location}.context_files")
        context_files = tuple(
            _repository_path(value, f"{location}.context_files[{context_index}]")
            for context_index, value in enumerate(context_items)
        )
        if len(set(context_files)) != len(context_files):
            raise ManifestError(f"{location}.context_files contains duplicates")
        critical_items = _list(
            data["critical_expectations"],
            f"{location}.critical_expectations",
            minimum=1,
        )
        critical = tuple(
            _string(
                value,
                f"{location}.critical_expectations[{critical_index}]",
                pattern=IDENTIFIER_RE,
            )
            for critical_index, value in enumerate(critical_items)
        )
        if len(set(critical)) != len(critical):
            raise ManifestError(f"{location}.critical_expectations contains duplicates")
        skill = _string(data["skill"], f"{location}.skill", pattern=SKILL_RE)
        cases.append(
            CaseSpec(
                id=_string(data["id"], f"{location}.id", pattern=IDENTIFIER_RE),
                skill=skill,
                bundle_source=_bundle_source_path(
                    data["bundle_source"], f"{location}.bundle_source"
                ),
                split=split,
                prompt_file=_suite_path(
                    suite_root,
                    data["prompt_file"],
                    f"{location}.prompt_file",
                    kind="file",
                ),
                fixture_dir=_suite_path(
                    suite_root,
                    data["fixture_dir"],
                    f"{location}.fixture_dir",
                    kind="directory",
                ),
                verifier=VerifierSpec(
                    argv=argv,
                    timeout_seconds=_integer(
                        verifier_data["timeout_seconds"],
                        f"{location}.verifier.timeout_seconds",
                        minimum=1,
                        maximum=MAX_TIMEOUT_SECONDS,
                    ),
                    required_tools=required_tools,
                ),
                context_files=context_files,
                timeout_seconds=_integer(
                    data["timeout_seconds"],
                    f"{location}.timeout_seconds",
                    minimum=1,
                    maximum=MAX_TIMEOUT_SECONDS,
                ),
                critical_expectations=critical,
                comparator_contract=(
                    _parse_comparator_contract(
                        data["comparator_contract"],
                        f"{location}.comparator_contract",
                        comparator_contract_vocabulary,
                    )
                    if require_comparator_contract
                    else None
                ),
                artifact_contract=_parse_artifact_contract(
                    data["artifact_contract"], f"{location}.artifact_contract"
                ),
            )
        )
    _unique_ids([case.id for case in cases], "cases")
    return tuple(cases)


def _parse_artifact_contract(raw: Any, location: str) -> ArtifactContractSpec:
    value = _object(raw, location, required={"kind"}, allowed={"kind"})
    kind = _string(value["kind"], f"{location}.kind")
    if kind not in {"workspace_diff", "final_output_text", "final_output_json"}:
        raise ManifestError(f"{location}.kind is unsupported")
    return ArtifactContractSpec(kind=kind)


def _exact_repetitions(value: Any, location: str) -> int:
    result = _integer(value, location, minimum=3, maximum=3)
    if result != 3:
        raise ManifestError(f"{location} must be exactly 3")
    return result


def _long_text(value: Any, location: str) -> str:
    result = _string(value, location)
    if len(result) < 20:
        raise ManifestError(f"{location} must contain at least 20 characters")
    return result


def _parse_comparator_contract(
    raw: Any,
    location: str,
    vocabulary: dict[str, frozenset[str]] | None,
) -> dict[str, Any]:
    if vocabulary is None:
        raise ManifestError(f"{location} has no comparator profile vocabulary")
    contract = _object(
        raw,
        location,
        required={"requirements", "performance_basis", "qualitative_bases"},
        allowed={"requirements", "performance_basis", "qualitative_bases"},
    )
    raw_requirements = _list(
        contract["requirements"], f"{location}.requirements", minimum=1
    )
    requirements: list[dict[str, str]] = []
    requirement_ids: list[str] = []
    for index, raw_requirement in enumerate(raw_requirements):
        item_location = f"{location}.requirements[{index}]"
        requirement = _object(
            raw_requirement,
            item_location,
            required={"id", "kind", "text"},
            allowed={"id", "kind", "text"},
        )
        kind = _string(requirement["kind"], f"{item_location}.kind")
        if kind not in vocabulary["requirement_kinds"]:
            raise ManifestError(f"{item_location}.kind is unsupported")
        requirement_id = _string(
            requirement["id"], f"{item_location}.id", pattern=IDENTIFIER_RE
        )
        requirement_ids.append(requirement_id)
        requirements.append(
            {
                "id": requirement_id,
                "kind": kind,
                "text": _long_text(requirement["text"], f"{item_location}.text"),
            }
        )
    _unique_ids(requirement_ids, f"{location}.requirements")
    performance_basis = contract["performance_basis"]
    parsed_performance: dict[str, str] | None = None
    if performance_basis is not None:
        basis = _object(
            performance_basis,
            f"{location}.performance_basis",
            required={"kind", "detail"},
            allowed={"kind", "detail"},
        )
        kind = _string(basis["kind"], f"{location}.performance_basis.kind")
        if kind not in vocabulary["performance_basis_kinds"]:
            raise ManifestError(f"{location}.performance_basis.kind is unsupported")
        parsed_performance = {
            "kind": kind,
            "detail": _long_text(
                basis["detail"], f"{location}.performance_basis.detail"
            ),
        }
    qualitative = contract["qualitative_bases"]
    if (
        not isinstance(qualitative, dict)
        or not set(qualitative) <= vocabulary["qualitative_basis_criteria"]
    ):
        raise ManifestError(f"{location}.qualitative_bases is invalid")
    parsed_qualitative: dict[str, dict[str, str]] = {}
    allowed_kinds = vocabulary["qualitative_basis_kinds"]
    for criterion, raw_basis in qualitative.items():
        basis_location = f"{location}.qualitative_bases.{criterion}"
        basis = _object(
            raw_basis,
            basis_location,
            required={"kind", "detail"},
            allowed={"kind", "detail"},
        )
        kind = _string(basis["kind"], f"{basis_location}.kind")
        if kind not in allowed_kinds:
            raise ManifestError(f"{basis_location}.kind is unsupported")
        parsed_qualitative[criterion] = {
            "kind": kind,
            "detail": _long_text(basis["detail"], f"{basis_location}.detail"),
        }
    return {
        "requirements": requirements,
        "performance_basis": parsed_performance,
        "qualitative_bases": parsed_qualitative,
    }


def _comparator_contract_vocabulary(
    profile: ComparatorProfileSpec | None,
) -> dict[str, frozenset[str]] | None:
    if profile is None:
        return None
    if profile.resources is None:
        return {
            "requirement_kinds": frozenset({"required_behavior", "hard_constraint"}),
            "performance_basis_kinds": frozenset(
                {"workload", "asymptotic", "measurement"}
            ),
            "qualitative_basis_criteria": frozenset(
                {"functional_correctness", "security_reliability"}
            ),
            "qualitative_basis_kinds": frozenset(
                {
                    "test-fault-sensitivity",
                    "behavioral-quality",
                    "defense-in-depth",
                    "failure-determinism",
                    "concurrency-margin",
                }
            ),
        }
    try:
        raw = profile.resources.read_bytes("semantic_contract").decode("utf-8")
        contract = _calibration.parse_json_object(
            raw, f"comparator profile {profile.id} semantic contract"
        )
        _calibration.validate_semantic_contract(contract)
        return {
            field: frozenset(contract[field])
            for field in (
                "requirement_kinds",
                "performance_basis_kinds",
                "qualitative_basis_criteria",
                "qualitative_basis_kinds",
            )
        }
    except (UnicodeDecodeError, _calibration.CalibrationError) as exc:
        raise ManifestError(
            f"comparator profile {profile.id} semantic contract is invalid: {exc}"
        ) from exc


def load_suite(path: str | Path) -> SuiteSpec:
    """Load a suite manifest and reject ambiguous or unsafe configuration."""

    manifest_path, raw_bytes = _read_suite_file(path, action="read")
    try:
        data = json.loads(
            raw_bytes,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ManifestError(f"suite manifest must be UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid suite JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("suite must be an object")
    schema_version = _integer(data.get("schema_version"), "schema_version", minimum=0)
    if schema_version != SUITE_SCHEMA_VERSION:
        raise ManifestError(f"schema_version must be {SUITE_SCHEMA_VERSION}")
    common_fields = {
        "$schema",
        "schema_version",
        "suite_id",
        "seed",
        "repository_root",
        "provider",
        "variants",
        "comparisons",
        "cases",
        "evaluation_mode",
        "shared_verifier_dir",
        "holdout",
    }
    evaluation_mode = _string(data.get("evaluation_mode"), "evaluation_mode")
    if evaluation_mode == "judged":
        mode_fields = {"comparator", "comparator_profile"}
        root = _object(
            data,
            "suite",
            required=(common_fields | mode_fields) - {"$schema"},
            allowed=common_fields | mode_fields,
        )
        comparator_profile = _parse_comparator_profile(
            root["comparator_profile"], manifest_path.parent
        )
    elif evaluation_mode == "objective_only":
        root = _object(
            data,
            "suite",
            required=common_fields - {"$schema"},
            allowed=common_fields,
        )
        comparator_profile = None
    else:
        raise ManifestError("evaluation_mode must be 'judged' or 'objective_only'")
    suite_root = manifest_path.parent
    repository_root = _root_path(suite_root, root["repository_root"], "repository_root")
    provider = _parse_provider(
        root["provider"],
        "provider",
        suite_root,
        role="generation",
    )
    comparator = (
        _parse_provider(
            root["comparator"],
            "comparator",
            suite_root,
            role="comparison",
            allow_codex=False,
        )
        if evaluation_mode == "judged"
        else None
    )
    if "$schema" in root:
        _string(root["$schema"], "$schema")
    variants = _parse_variants(root["variants"], suite_root)
    comparisons = _parse_comparisons(
        root["comparisons"], {variant.id for variant in variants}
    )
    holdout_comparison_ids = _parse_holdout_comparison_ids(root["holdout"], comparisons)
    cases = _parse_cases(
        root["cases"],
        suite_root,
        require_comparator_contract=evaluation_mode == "judged",
        comparator_contract_vocabulary=_comparator_contract_vocabulary(
            comparator_profile
        ),
    )
    shared_verifier_dir = _shared_verifier_directory(
        suite_root, root["shared_verifier_dir"]
    )
    _assert_shared_verifier_separation(
        shared_verifier_dir, repository_root, variants, cases
    )
    return SuiteSpec(
        path=manifest_path,
        root=suite_root,
        repository_root=repository_root,
        suite_id=_string(root["suite_id"], "suite_id", pattern=IDENTIFIER_RE),
        seed=_integer(root["seed"], "seed", minimum=0),
        evaluation_mode=evaluation_mode,
        provider=provider,
        comparator=comparator,
        comparator_profile=comparator_profile,
        variants=variants,
        comparisons=comparisons,
        cases=cases,
        shared_verifier_dir=shared_verifier_dir,
        holdout_comparison_ids=holdout_comparison_ids,
        manifest_hash=hashlib.sha256(raw_bytes).hexdigest(),
        raw_bytes=raw_bytes,
        raw=root,
    )
