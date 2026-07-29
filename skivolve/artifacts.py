"""Bounded canonical artifacts selected by suite case contracts."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any

import rfc8785

MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_MEMBERS = 10_000
MAX_JSON_NUMBER_TOKEN_BYTES = 128
MAX_JSON_STRING_BYTES = 256 * 1024
SUPPORTED_ARTIFACT_KINDS = frozenset(
    {"final_output_json", "final_output_text", "workspace_diff"}
)


class ArtifactError(ValueError):
    """Raised when a declared output cannot produce one trusted artifact."""


@dataclass(frozen=True)
class NormalizedArtifact:
    kind: str
    media_type: str
    filename: str
    canonicalization: str
    content: bytes
    raw_byte_count: int

    @property
    def byte_count(self) -> int:
        return len(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def as_evidence(self) -> dict[str, Any]:
        return {
            "byte_count": self.byte_count,
            "canonicalization": self.canonicalization,
            "filename": self.filename,
            "kind": self.kind,
            "media_type": self.media_type,
            "raw_byte_count": self.raw_byte_count,
            "sha256": self.sha256,
        }

    def assert_content(self, observed: bytes) -> None:
        if observed != self.content:
            raise ArtifactError("normalized artifact content drifted")


def normalize_artifact(kind: str, raw: str | bytes) -> NormalizedArtifact:
    if kind == "workspace_diff":
        content, raw_size = _strict_utf8_bytes(raw, "workspace diff")
        return _artifact(
            kind=kind,
            media_type="text/x-diff; charset=utf-8",
            filename="artifact.txt",
            canonicalization="skivolve-workspace-diff-v1",
            content=content,
            raw_byte_count=raw_size,
        )
    if kind == "final_output_text":
        content, raw_size = _strict_utf8_bytes(raw, "final text")
        content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        return _artifact(
            kind=kind,
            media_type="text/plain; charset=utf-8",
            filename="artifact.txt",
            canonicalization="skivolve-text-lf-v1",
            content=content,
            raw_byte_count=raw_size,
        )
    if kind == "final_output_json":
        content, raw_size = _strict_utf8_bytes(raw, "final JSON")
        value = _parse_bounded_json(content)
        try:
            canonical = rfc8785.dumps(value)
        except (rfc8785.CanonicalizationError, RecursionError) as exc:
            raise ArtifactError(f"final JSON cannot be canonicalized: {exc}") from exc
        try:
            repeated = rfc8785.dumps(_parse_bounded_json(canonical))
        except (ArtifactError, rfc8785.CanonicalizationError, RecursionError) as exc:
            raise ArtifactError("final JSON canonical form is not stable") from exc
        if repeated != canonical:
            raise ArtifactError("final JSON canonical form is not idempotent")
        return _artifact(
            kind=kind,
            media_type="application/json",
            filename="artifact.json",
            canonicalization="rfc8785",
            content=canonical,
            raw_byte_count=raw_size,
        )
    raise ArtifactError(f"unsupported artifact kind: {kind}")


def _artifact(
    *,
    kind: str,
    media_type: str,
    filename: str,
    canonicalization: str,
    content: bytes,
    raw_byte_count: int,
) -> NormalizedArtifact:
    if len(content) > MAX_ARTIFACT_BYTES:
        raise ArtifactError("normalized artifact exceeds the 1 MiB size limit")
    return NormalizedArtifact(
        kind=kind,
        media_type=media_type,
        filename=filename,
        canonicalization=canonicalization,
        content=content,
        raw_byte_count=raw_byte_count,
    )


def _strict_utf8_bytes(raw: str | bytes, label: str) -> tuple[bytes, int]:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ArtifactError(f"{label} is not valid UTF-8 text") from exc
    elif isinstance(raw, bytes):
        encoded = raw
        try:
            encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ArtifactError(f"{label} is not valid UTF-8 text") from exc
    else:
        raise ArtifactError(f"{label} must be text or bytes")
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ArtifactError(f"{label} exceeds the 1 MiB raw size limit")
    if encoded.startswith(b"\xef\xbb\xbf"):
        raise ArtifactError(f"{label} must not start with a UTF-8 BOM")
    return encoded, len(encoded)


def _parse_bounded_json(raw: bytes) -> dict[str, Any] | list[Any]:
    text = raw.decode("utf-8", errors="strict")

    def bounded_int(token: str) -> int:
        _check_number_token(token)
        return int(token)

    def bounded_float(token: str) -> float:
        _check_number_token(token)
        value = float(token)
        if not math.isfinite(value):
            raise ArtifactError("final JSON number is outside the finite range")
        return value

    def reject_constant(token: str) -> None:
        raise ArtifactError(f"final JSON contains non-finite number {token}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ArtifactError(f"final JSON contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=bounded_float,
            parse_int=bounded_int,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ArtifactError(f"final JSON is invalid: {exc}") from exc
    if not isinstance(value, (dict, list)):
        raise ArtifactError("final JSON must be an object or array")
    _validate_json_shape(value)
    return value


def _check_number_token(token: str) -> None:
    if len(token.encode("ascii")) > MAX_JSON_NUMBER_TOKEN_BYTES:
        raise ArtifactError("final JSON number token exceeds 128 bytes")


def _validate_json_shape(root: dict[str, Any] | list[Any]) -> None:
    members = 0
    stack: list[tuple[Any, int]] = [(root, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ArtifactError("final JSON exceeds maximum depth 64")
        if isinstance(value, dict):
            members += len(value)
            for key, child in value.items():
                _check_json_string(key)
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            members += len(value)
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            _check_json_string(value)
        if members > MAX_JSON_MEMBERS:
            raise ArtifactError("final JSON exceeds 10000 aggregate members")


def _check_json_string(value: str) -> None:
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise ArtifactError("final JSON contains an invalid Unicode string") from exc
    if size > MAX_JSON_STRING_BYTES:
        raise ArtifactError("final JSON string exceeds 256 KiB")
