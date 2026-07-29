"""Strict, package-safe comparator profile resource discovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, BinaryIO, Iterator, Mapping

from . import comparator_calibration, plain_language_calibration


BUILTIN_SOFTWARE_PROFILE_ID = "software-engineering-v1"
BUILTIN_PLAIN_LANGUAGE_PROFILE_ID = "plain-language-revision-v1"
MAX_PROFILE_DESCRIPTOR_BYTES = 64 * 1024
MAX_PROFILE_RESOURCE_BYTES = 4 * 1024 * 1024
MAX_PROFILE_ID_LENGTH = 128
MAX_RESOURCE_PATH_BYTES = 255
_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_PROFILE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DATA_RESOURCE_KEYS = frozenset(
    {
        "manifest",
        "manifest_schema",
        "rubric",
        "request_template",
        "response_schema",
        "evidence_schema",
        "semantic_contract",
        "production_release",
        "test_release",
    }
)
_BUILTIN_RESOURCE_KEYS = _DATA_RESOURCE_KEYS | {
    "calibration_engine",
    "collector",
    "certifier",
}
_BUILTIN_PROFILE_PACKAGES: Mapping[str, Any] = MappingProxyType(
    {
        BUILTIN_SOFTWARE_PROFILE_ID: comparator_calibration,
        BUILTIN_PLAIN_LANGUAGE_PROFILE_ID: plain_language_calibration,
    }
)
BUILTIN_PROFILE_IDS = frozenset(_BUILTIN_PROFILE_PACKAGES)
_LOCAL_ARTIFACT_RESOURCES = MappingProxyType(
    {
        "corpus_sha256": "manifest",
        "manifest_schema_sha256": "manifest_schema",
        "rubric_sha256": "rubric",
        "request_template_sha256": "request_template",
        "response_schema_sha256": "response_schema",
        "evidence_schema_sha256": "evidence_schema",
        "semantic_contract_sha256": "semantic_contract",
    }
)


class ComparatorProfileError(ValueError):
    """A comparator profile descriptor or packaged resource is invalid."""


@dataclass(frozen=True)
class ComparatorProfileDescriptor:
    """Validated, immutable identity and resource map for one profile."""

    schema_version: int
    id: str
    version: str
    engine_contract: str
    resources: tuple[tuple[str, str], ...]
    supported_artifact_kinds: tuple[str, ...]
    descriptor_sha256: str

    @property
    def resources_by_name(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.resources))


@dataclass(frozen=True)
class ComparatorProfileAuthorityBinding:
    """Reviewed package digests; callers must not treat this as authorization."""

    descriptor_sha256: str
    production_release_sha256: str
    test_release_sha256: str
    certification_contract_sha256: str
    requires_live_certification: bool
    authority_scope: str
    registry_sha256: str


@dataclass(frozen=True)
class ComparatorProfileResources:
    """One immutable snapshot of validated profile resources."""

    descriptor: ComparatorProfileDescriptor
    descriptor_bytes: bytes
    resource_snapshot: tuple[tuple[str, str, bytes], ...]
    authority_binding: ComparatorProfileAuthorityBinding | None

    def read_bytes(self, resource_name: str) -> bytes:
        for name, _relative, raw_bytes in self.resource_snapshot:
            if name == resource_name:
                return raw_bytes
        raise ComparatorProfileError(
            f"unknown comparator profile resource: {resource_name}"
        )

    @contextmanager
    def materialize(self) -> Iterator[Path]:
        """Copy the immutable snapshot into a temporary filesystem tree."""

        with tempfile.TemporaryDirectory(prefix="skivolve-profile-") as temporary:
            root = Path(temporary)
            files = (("profile.json", self.descriptor_bytes),) + tuple(
                (relative, raw_bytes)
                for _name, relative, raw_bytes in self.resource_snapshot
            )
            for relative, raw_bytes in files:
                destination = root.joinpath(*PurePosixPath(relative).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with destination.open("xb") as writer:
                        writer.write(raw_bytes)
                except OSError as exc:
                    raise ComparatorProfileError(
                        f"cannot materialize comparator profile resource: {relative}"
                    ) from exc
            yield root


def _reject_constant(value: str) -> None:
    raise ComparatorProfileError(f"non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ComparatorProfileError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _canonical_resource_path(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComparatorProfileError(f"{location} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_RESOURCE_PATH_BYTES:
        raise ComparatorProfileError(f"{location} exceeds the path byte limit")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path == PurePosixPath(".")
        or ".." in path.parts
        or path.as_posix() != value
        or value.startswith("./")
    ):
        raise ComparatorProfileError(
            f"{location} must be a canonical relative POSIX path"
        )
    return value


def _paths_collide(left: str, right: str) -> bool:
    left_parts = PurePosixPath(left).parts
    right_parts = PurePosixPath(right).parts
    shared = min(len(left_parts), len(right_parts))
    return left_parts[:shared] == right_parts[:shared]


def parse_profile_descriptor(
    raw_bytes: bytes, *, data_only: bool = False
) -> ComparatorProfileDescriptor:
    """Parse bounded exact descriptor bytes without accepting ambiguous JSON."""

    if not isinstance(raw_bytes, bytes):
        raise ComparatorProfileError("profile descriptor must be bytes")
    if len(raw_bytes) > MAX_PROFILE_DESCRIPTOR_BYTES:
        raise ComparatorProfileError("profile descriptor exceeds the byte limit")
    value = _strict_json_object(raw_bytes, "profile descriptor")
    expected = {
        "schema_version",
        "id",
        "version",
        "engine_contract",
        "resources",
        "supported_artifact_kinds",
    }
    if set(value) != expected:
        raise ComparatorProfileError("profile descriptor fields are invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ComparatorProfileError("profile descriptor schema version is invalid")
    profile_id = value["id"]
    if (
        not isinstance(profile_id, str)
        or len(profile_id) > MAX_PROFILE_ID_LENGTH
        or _PROFILE_ID_RE.fullmatch(profile_id) is None
    ):
        raise ComparatorProfileError("profile descriptor id is invalid")
    version = value["version"]
    if (
        not isinstance(version, str)
        or len(version) > 64
        or _PROFILE_VERSION_RE.fullmatch(version) is None
    ):
        raise ComparatorProfileError("profile descriptor version is invalid")
    engine_contract = value["engine_contract"]
    if (
        not isinstance(engine_contract, str)
        or len(engine_contract) > MAX_PROFILE_ID_LENGTH
        or _PROFILE_ID_RE.fullmatch(engine_contract) is None
    ):
        raise ComparatorProfileError("profile engine contract is invalid")
    resource_map = value["resources"]
    if not isinstance(resource_map, dict):
        raise ComparatorProfileError("profile resource fields are invalid")
    resource_keys = set(resource_map)
    valid_resource_keys = (
        resource_keys == _DATA_RESOURCE_KEYS
        if data_only
        else resource_keys in {_DATA_RESOURCE_KEYS, _BUILTIN_RESOURCE_KEYS}
    )
    if not valid_resource_keys:
        raise ComparatorProfileError("profile resource fields are invalid")
    parsed_resources = tuple(
        (name, _canonical_resource_path(resource_map[name], f"resources.{name}"))
        for name in sorted(resource_map)
    )
    paths = ["profile.json", *(path for _name, path in parsed_resources)]
    if any(
        _paths_collide(left, right)
        for index, left in enumerate(paths)
        for right in paths[index + 1 :]
    ):
        raise ComparatorProfileError(
            "profile resources must name distinct non-overlapping files"
        )
    if value["supported_artifact_kinds"] != ["workspace_diff"]:
        raise ComparatorProfileError(
            "profile supported artifact kinds must be ['workspace_diff']"
        )
    return ComparatorProfileDescriptor(
        schema_version=1,
        id=profile_id,
        version=version,
        engine_contract=engine_contract,
        resources=parsed_resources,
        supported_artifact_kinds=("workspace_diff",),
        descriptor_sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def _strict_json_object(raw_bytes: bytes, location: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw_bytes,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ComparatorProfileError(f"{location} must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ComparatorProfileError(f"invalid {location} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ComparatorProfileError(f"{location} must contain a JSON object")
    return value


def _bounded_read(reader: BinaryIO, limit: int, location: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = reader.read(min(64 * 1024, limit - total + 1))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ComparatorProfileError(f"{location} exceeds the byte limit")


def _descriptor_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
    )


def _read_path_resource(root: Path, relative: str, limit: int) -> bytes:
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(root, directory_flags))
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
        descriptors.append(file_descriptor)
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ComparatorProfileError(
                f"comparator profile resource is invalid: {relative}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_descriptor, min(64 * 1024, limit - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ComparatorProfileError(
                    f"comparator profile resource exceeds the byte limit: {relative}"
                )
        after = os.fstat(file_descriptor)
        if _descriptor_identity(before) != _descriptor_identity(after):
            raise ComparatorProfileError(
                f"comparator profile resource changed while reading: {relative}"
            )
        return b"".join(chunks)
    except ComparatorProfileError:
        raise
    except OSError as exc:
        raise ComparatorProfileError(
            f"cannot read comparator profile resource: {relative}"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_resource_bytes(root: Any, relative: str, limit: int) -> bytes:
    if isinstance(root, Path):
        return _read_path_resource(root, relative, limit)
    resource = root.joinpath(*PurePosixPath(relative).parts)
    if not resource.is_file():
        raise ComparatorProfileError(
            f"comparator profile resource is missing or not a file: {relative}"
        )
    try:
        with resource.open("rb") as reader:
            return _bounded_read(reader, limit, relative)
    except ComparatorProfileError:
        raise
    except OSError as exc:
        raise ComparatorProfileError(
            f"cannot read comparator profile resource: {relative}"
        ) from exc


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _authority_binding(profile_id: str) -> ComparatorProfileAuthorityBinding:
    import skivolve as harness_package

    registry_bytes = _read_resource_bytes(
        resources.files(harness_package),
        "comparator-profile-authority.json",
        MAX_PROFILE_DESCRIPTOR_BYTES,
    )
    registry = _strict_json_object(registry_bytes, "profile authority registry")
    if (
        set(registry) != {"schema_version", "profiles"}
        or registry["schema_version"] != 1
    ):
        raise ComparatorProfileError("profile authority registry fields are invalid")
    profiles = registry["profiles"]
    if not isinstance(profiles, list):
        raise ComparatorProfileError("profile authority registry profiles are invalid")
    matches = [
        profile
        for profile in profiles
        if isinstance(profile, dict) and profile.get("id") == profile_id
    ]
    if len(matches) != 1:
        raise ComparatorProfileError(
            "profile authority registry must contain one matching profile"
        )
    profile = matches[0]
    expected = {
        "id",
        "descriptor_sha256",
        "production_release_sha256",
        "test_release_sha256",
        "certification_contract_sha256",
        "requires_live_certification",
        "authority_scope",
    }
    if (
        set(profile) != expected
        or profile["requires_live_certification"] is not True
        or not isinstance(profile["authority_scope"], str)
        or profile["authority_scope"] not in {"production", "test"}
    ):
        raise ComparatorProfileError("profile authority binding fields are invalid")
    digests = [
        profile["descriptor_sha256"],
        profile["production_release_sha256"],
        profile["test_release_sha256"],
        profile["certification_contract_sha256"],
    ]
    if not all(
        isinstance(digest, str)
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
        for digest in digests
    ):
        raise ComparatorProfileError("profile authority binding digests are invalid")
    return ComparatorProfileAuthorityBinding(
        descriptor_sha256=digests[0],
        production_release_sha256=digests[1],
        test_release_sha256=digests[2],
        certification_contract_sha256=digests[3],
        requires_live_certification=True,
        authority_scope=profile["authority_scope"],
        registry_sha256=hashlib.sha256(registry_bytes).hexdigest(),
    )


def _review_hashes(manifest: dict[str, Any]) -> dict[str, str]:
    try:
        pairs = manifest["pairs"]
        return {
            field: _canonical_sha256(
                [
                    {"pair_id": pair["id"], "record": pair["adjudication"][field]}
                    for pair in pairs
                ]
            )
            for field in (
                "reviewer_a",
                "reviewer_b",
                "re_review",
                "resolution",
                "scoring_gold",
            )
        }
    except (KeyError, TypeError) as exc:
        raise ComparatorProfileError(
            "profile calibration manifest review streams are invalid"
        ) from exc


def _validate_release_resources(
    descriptor: ComparatorProfileDescriptor,
    snapshot: Mapping[str, bytes],
    authority: ComparatorProfileAuthorityBinding | None,
) -> None:
    if authority is not None and (
        hashlib.sha256(snapshot["evidence_schema"]).hexdigest()
        != authority.certification_contract_sha256
    ):
        raise ComparatorProfileError(
            "profile certification contract differs from the authority registry"
        )
    parsed = {
        name: _strict_json_object(snapshot[name], f"profile resource {name}")
        for name in (
            "manifest",
            "manifest_schema",
            "rubric",
            "request_template",
            "response_schema",
            "evidence_schema",
            "semantic_contract",
        )
    }
    semantic_contract = parsed["semantic_contract"]
    compatible_engine_contracts = {
        "software-change-comparator-v1": "eligibility-pareto-v1",
        "eligibility-pareto-v1": "eligibility-pareto-v1",
    }
    if compatible_engine_contracts.get(
        descriptor.engine_contract
    ) != semantic_contract.get("engine_strategy") or semantic_contract.get(
        "artifact_kinds"
    ) != list(descriptor.supported_artifact_kinds):
        raise ComparatorProfileError(
            "profile descriptor differs from its semantic engine contract"
        )
    reviews = _review_hashes(parsed["manifest"])
    release_ids: set[str] = set()
    release_contracts = (
        (
            "production_release",
            False,
            (authority.production_release_sha256 if authority is not None else None),
        ),
        (
            "test_release",
            True,
            authority.test_release_sha256 if authority is not None else None,
        ),
    )
    for (
        resource_name,
        expected_test_release,
        expected_release_sha256,
    ) in release_contracts:
        raw_release = snapshot[resource_name]
        if (
            expected_release_sha256 is not None
            and hashlib.sha256(raw_release).hexdigest() != expected_release_sha256
        ):
            raise ComparatorProfileError(
                f"{resource_name} differs from the authority registry"
            )
        release = _strict_json_object(raw_release, resource_name)
        artifacts = release.get("artifacts")
        evaluator = release.get("evaluator")
        if (
            release.get("test_release") is not expected_test_release
            or not isinstance(artifacts, dict)
            or not isinstance(evaluator, dict)
            or artifacts.get("profile_descriptor_sha256")
            != descriptor.descriptor_sha256
        ):
            raise ComparatorProfileError(
                f"{resource_name} is not bound to the profile descriptor"
            )
        expected_hashes = {
            field: _canonical_sha256(parsed[resource_name])
            for field, resource_name in _LOCAL_ARTIFACT_RESOURCES.items()
        }
        system_prompt = parsed["request_template"].get("system_prompt")
        if not isinstance(system_prompt, str):
            raise ComparatorProfileError("profile system prompt is invalid")
        expected_hashes["system_prompt_sha256"] = hashlib.sha256(
            system_prompt.encode("utf-8")
        ).hexdigest()
        expected_hashes.update(
            {f"{field}_sha256": digest for field, digest in reviews.items()}
        )
        if any(
            artifacts.get(field) != digest for field, digest in expected_hashes.items()
        ):
            raise ComparatorProfileError(
                f"{resource_name} profile artifact lock is stale or mismatched"
            )
        expected_sources = {
            "source_sha256": "calibration_engine",
            "collector_source_sha256": "collector",
            "certifier_source_sha256": "certifier",
        }
        evaluator_sources_match = (
            all(name in snapshot for name in expected_sources.values())
            and all(
                evaluator.get(field) == hashlib.sha256(snapshot[name]).hexdigest()
                for field, name in expected_sources.items()
            )
        ) or (
            all(name not in snapshot for name in expected_sources.values())
            and all(
                isinstance(evaluator.get(field), str)
                and _SHA256_RE.fullmatch(evaluator[field]) is not None
                for field in expected_sources
            )
        )
        if not evaluator_sources_match:
            raise ComparatorProfileError(
                f"{resource_name} profile source lock is stale or mismatched"
            )
        release_id = release.get("release_id")
        if not isinstance(release_id, str) or not release_id:
            raise ComparatorProfileError(f"{resource_name} release id is invalid")
        release_ids.add(release_id)
    if len(release_ids) != 2:
        raise ComparatorProfileError(
            "production and test profile releases must have distinct ids"
        )


def resolve_builtin_profile(profile_id: str) -> ComparatorProfileResources:
    """Resolve and snapshot one code-owned built-in profile registration."""

    if not isinstance(profile_id, str):
        raise ComparatorProfileError("comparator profile id must be a string")
    try:
        package = _BUILTIN_PROFILE_PACKAGES[profile_id]
    except KeyError as exc:
        raise ComparatorProfileError(
            f"unknown built-in comparator profile: {profile_id}"
        ) from exc
    root = resources.files(package)
    descriptor_bytes = _read_resource_bytes(
        root, "profile.json", MAX_PROFILE_DESCRIPTOR_BYTES
    )
    descriptor = parse_profile_descriptor(descriptor_bytes)
    if descriptor.id != profile_id:
        raise ComparatorProfileError(
            "comparator profile descriptor id differs from its registry id"
        )
    authority = _authority_binding(profile_id)
    if descriptor.descriptor_sha256 != authority.descriptor_sha256:
        raise ComparatorProfileError(
            "comparator profile descriptor differs from the authority registry"
        )
    snapshot = tuple(
        (
            name,
            relative,
            _read_resource_bytes(root, relative, MAX_PROFILE_RESOURCE_BYTES),
        )
        for name, relative in descriptor.resources
    )
    snapshot_by_name = MappingProxyType(
        {name: raw_bytes for name, _relative, raw_bytes in snapshot}
    )
    _validate_release_resources(descriptor, snapshot_by_name, authority)
    return ComparatorProfileResources(
        descriptor=descriptor,
        descriptor_bytes=descriptor_bytes,
        resource_snapshot=snapshot,
        authority_binding=authority,
    )


def resolve_profile_directory(root: Path) -> ComparatorProfileResources:
    """Resolve a contained data-only profile without granting release authority."""

    profile_root = Path(root)
    descriptor_bytes = _read_resource_bytes(
        profile_root, "profile.json", MAX_PROFILE_DESCRIPTOR_BYTES
    )
    descriptor = parse_profile_descriptor(descriptor_bytes, data_only=True)
    snapshot = tuple(
        (
            name,
            relative,
            _read_resource_bytes(profile_root, relative, MAX_PROFILE_RESOURCE_BYTES),
        )
        for name, relative in descriptor.resources
    )
    snapshot_by_name = MappingProxyType(
        {name: raw_bytes for name, _relative, raw_bytes in snapshot}
    )
    _validate_release_resources(descriptor, snapshot_by_name, None)
    return ComparatorProfileResources(
        descriptor=descriptor,
        descriptor_bytes=descriptor_bytes,
        resource_snapshot=snapshot,
        authority_binding=None,
    )
