"""Reusable A/B evaluation system for agent skills and instruction bundles."""

from .manifest import (
    ArtifactContractSpec,
    ManifestError,
    ProviderConfig,
    SuiteSpec,
    load_suite,
)
from .provider_capabilities import (
    ProviderCapabilities,
    ProviderCapabilityError,
    capabilities_for,
    reviewed_capabilities,
)
from .providers import (
    ClaudeCliProvider,
    FakeProvider,
    ProviderError,
    ProviderExecutionPolicy,
    ProviderResult,
    execution_policy_for,
)
from .runner import EvalRunner, RunSelection, RunnerError

__version__ = "0.7.0"

__all__ = [
    "ClaudeCliProvider",
    "ArtifactContractSpec",
    "EvalRunner",
    "FakeProvider",
    "ManifestError",
    "ProviderConfig",
    "ProviderCapabilities",
    "ProviderCapabilityError",
    "ProviderError",
    "ProviderExecutionPolicy",
    "ProviderResult",
    "RunSelection",
    "RunnerError",
    "SuiteSpec",
    "capabilities_for",
    "execution_policy_for",
    "load_suite",
    "reviewed_capabilities",
    "__version__",
]
