"""Reviewed provider adapter capabilities and authority scopes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


class ProviderCapabilityError(ValueError):
    """Raised when a provider adapter is absent from the reviewed registry."""


@dataclass(frozen=True)
class ProviderCapabilities:
    adapter_id: str
    provider_kind: str
    contract_revision: int
    roles: tuple[str, ...]
    concurrency: str
    sandbox_kind: str
    authority_scope: str
    billing_basis: str
    cost_evidence: str
    budget_mechanism: str
    quota_evidence: str
    provenance_fields: tuple[str, ...]
    artifact_outputs: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "artifact_outputs": list(self.artifact_outputs),
            "authority_scope": self.authority_scope,
            "billing": {
                "basis": self.billing_basis,
                "budget_mechanism": self.budget_mechanism,
                "cost_evidence": self.cost_evidence,
                "quota_evidence": self.quota_evidence,
            },
            "concurrency": self.concurrency,
            "contract_revision": self.contract_revision,
            "provider_kind": self.provider_kind,
            "provenance_fields": list(self.provenance_fields),
            "roles": list(self.roles),
            "sandbox_kind": self.sandbox_kind,
            "schema_version": 1,
        }

    @property
    def sha256(self) -> str:
        encoded = json.dumps(
            self.as_json(), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


_CAPABILITIES: Mapping[str, ProviderCapabilities] = MappingProxyType(
    {
        "claude-cli": ProviderCapabilities(
            adapter_id="claude-cli",
            provider_kind="claude",
            contract_revision=1,
            roles=("comparison", "generation"),
            concurrency="concurrent",
            sandbox_kind="systemd-run-user+claude-native-tool-sandbox",
            authority_scope="production",
            billing_basis="metered_api",
            cost_evidence="required",
            budget_mechanism="per-invocation-usd-ceiling",
            quota_evidence="forbidden",
            provenance_fields=(
                "executable_sha256",
                "provider_version",
                "requested_model",
                "sandbox_runtime",
            ),
            artifact_outputs=(
                "final_output_json",
                "final_output_text",
                "workspace_diff",
            ),
        ),
        "codex-app-server": ProviderCapabilities(
            adapter_id="codex-app-server",
            provider_kind="codex",
            contract_revision=1,
            roles=("generation",),
            concurrency="serialized",
            sandbox_kind="systemd-run-user+codex-permission-profile",
            authority_scope="diagnostic",
            billing_basis="chatgpt_subscription",
            cost_evidence="forbidden",
            budget_mechanism="subscription-quota",
            quota_evidence="required",
            provenance_fields=(
                "account_id",
                "codex_cli_version",
                "credential_source_revision",
                "endpoint",
                "executable_sha256",
                "organization_id",
                "project_id",
                "protocol_lock_sha256",
                "quota_identity",
                "requested_model",
                "runtime_bundle_sha256",
                "schema_sha256",
            ),
            artifact_outputs=(
                "final_output_json",
                "final_output_text",
                "workspace_diff",
            ),
        ),
        "deterministic-fake": ProviderCapabilities(
            adapter_id="deterministic-fake",
            provider_kind="fake",
            contract_revision=1,
            roles=("comparison", "generation"),
            concurrency="concurrent",
            sandbox_kind="fake",
            authority_scope="test",
            billing_basis="metered_api",
            cost_evidence="required",
            budget_mechanism="none",
            quota_evidence="forbidden",
            provenance_fields=("provider_version", "requested_model"),
            artifact_outputs=(
                "final_output_json",
                "final_output_text",
                "workspace_diff",
            ),
        ),
    }
)


def capabilities_for(
    adapter_id: str, *, role: str | None = None
) -> ProviderCapabilities:
    try:
        capabilities = _CAPABILITIES[adapter_id]
    except KeyError as exc:
        raise ProviderCapabilityError(
            f"unknown reviewed provider adapter: {adapter_id}"
        ) from exc
    if role is not None and role not in capabilities.roles:
        raise ProviderCapabilityError(
            f"provider adapter {adapter_id} does not support the {role} role"
        )
    return capabilities


def reviewed_capabilities() -> Mapping[str, ProviderCapabilities]:
    return _CAPABILITIES
