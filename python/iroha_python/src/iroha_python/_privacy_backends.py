"""Exact native verifier-registry labels shared by Python SDK surfaces."""

from __future__ import annotations

import re
from typing import Any, Final, Literal

VerifierBackendTag = Literal["native-pipa-r-pasta", "stark"]

_PIPA_R_PASTA_REGISTRY_LABELS_V1: Final[frozenset[str]] = frozenset(
    {
        "pipa-r/pasta",
        "pipa-r/pasta/kaigi-authorization-v1",
        "pipa-r/pasta/kaigi-usage-v1",
        "pipa-r/pasta/confidential-transfer-v1",
        "pipa-r/pasta/confidential-unshield-full-v1",
        "pipa-r/pasta/confidential-unshield-change-v1",
    }
)
_STARK_REGISTRY_LABELS_V1: Final[frozenset[str]] = frozenset(
    {
        "stark/fri/poseidon-x7-goldilocks-6x64-v1",
    }
)

# Public within the package so parity tests can compare this exact closed set.
_VERIFIER_BACKEND_REGISTRY_LABELS_V1: Final[frozenset[str]] = (
    _STARK_REGISTRY_LABELS_V1 | _PIPA_R_PASTA_REGISTRY_LABELS_V1
)
_STARK_FRI_PRODUCTION_BACKEND_LABELS = _STARK_REGISTRY_LABELS_V1

_PRODUCTION_CLAIM_BACKEND_FRAGMENTS = (
    "productionready",
    "productionhardened",
    "productionenabled",
    "productionapproved",
    "productioncertified",
    "productionclaim",
    "claimedproduction",
    "mainnetready",
    "mainnetcomplete",
    "mainnetclaim",
    "claimedmainnet",
    "mainnetcertified",
    "mainnetapproved",
    "mainnetrelease",
    "auditedproduction",
    "externallyaudited",
    "thirdpartyaudited",
    "boiaudited",
    "auditedmainnet",
    "externalaudit",
    "auditpassed",
    "auditapproved",
    "auditsignoff",
    "auditclaim",
    "claimedaudit",
    "securityreviewpassed",
    "securityauditpassed",
    "securityaudited",
    "externalsecurityreview",
    "certifiedproduction",
    "certifiedmainnet",
    "releaseready",
    "releaseapproved",
    "releasecertified",
)

_TRUSTED_SETUP_BACKEND_TOKENS = frozenset(
    {
        "groth16",
        "kzg",
        "bn254",
        "bn256",
        "bls12",
        "bls12381",
        "srs",
        "crs",
        "ptau",
        "ceremony",
        "trustedsetup",
        "structuredreferencestring",
        "universalsrs",
        "powersoftau",
    }
)

_DEVELOPER_ONLY_EMBEDDED_BACKEND_TOKENS = (
    "debug",
    "mock",
    "fixture",
    "dev",
    "todo",
    "draft",
    "pending",
    "replace",
)
_DEVELOPER_ONLY_EXACT_BACKEND_TOKENS = frozenset(
    {"test", "dummy", "fake", "stub", "sample", "placeholder", "todo", "draft"}
)
_DEVELOPER_ONLY_COMPACT_BACKEND_FRAGMENTS = (
    "notforproduction",
    "notproduction",
    "notproductionready",
    "notready",
    "replacebeforeproduction",
    "replacebeforemainnet",
    "draftonly",
)


def _verifier_backend_registry_tag_v1(value: Any) -> VerifierBackendTag | None:
    """Resolve one exact registry label to its low-level proof engine."""

    if not isinstance(value, str):
        return None
    if value in _PIPA_R_PASTA_REGISTRY_LABELS_V1:
        return "native-pipa-r-pasta"
    if value in _STARK_REGISTRY_LABELS_V1:
        return "stark"
    return None


def _is_verifier_backend_registry_label_v1(value: Any) -> bool:
    """Return whether ``value`` is one byte-exact registry-v1 label."""

    return _verifier_backend_registry_tag_v1(value) is not None


def _require_verifier_backend_registry_label_v1(value: Any, context: str) -> str:
    """Require one byte-exact registry-v1 label and return it unchanged."""

    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    if not _is_verifier_backend_registry_label_v1(value):
        raise ValueError(
            f"{context} uses unsupported verifier-registry label {value}"
        )
    return value


def _compact_privacy_backend_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _is_production_claim_backend_label(value: str) -> bool:
    compact = _compact_privacy_backend_label(value)
    return any(
        fragment in compact for fragment in _PRODUCTION_CLAIM_BACKEND_FRAGMENTS
    )


def _is_trusted_setup_backend_label(value: str) -> bool:
    label = value.lower()
    compact = _compact_privacy_backend_label(label)
    return any(
        token in _TRUSTED_SETUP_BACKEND_TOKENS
        for token in re.findall(r"[a-z0-9]+", label)
    ) or any(token in compact for token in _TRUSTED_SETUP_BACKEND_TOKENS)


def _is_developer_only_backend_run(value: str) -> bool:
    return any(
        token in value for token in _DEVELOPER_ONLY_EMBEDDED_BACKEND_TOKENS
    ) or value in _DEVELOPER_ONLY_EXACT_BACKEND_TOKENS


def _is_developer_only_backend_label(value: str) -> bool:
    label = value.lower()
    compact = _compact_privacy_backend_label(label)
    if any(
        fragment in compact
        for fragment in _DEVELOPER_ONLY_COMPACT_BACKEND_FRAGMENTS
    ):
        return True

    letter_run: list[str] = []
    for token in re.findall(r"[a-z0-9]+", label):
        if _is_developer_only_backend_run(token):
            return True
        if len(token) == 1:
            letter_run.append(token)
        else:
            if _is_developer_only_backend_run("".join(letter_run)):
                return True
            letter_run = []
    return _is_developer_only_backend_run("".join(letter_run))


def _is_portable_verify_backend_label(value: str) -> bool:
    return bool(
        re.fullmatch(r"[a-z0-9/_.:-]+", value)
        and re.match(r"[a-z0-9]", value)
        and re.search(r"[a-z0-9]$", value)
        and not any(
            separator in value
            for separator in ("//", "::", "..", "/:", ":/", "/.", "./", ":.", ".:")
        )
    )


def _is_production_verify_backend_label(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    backend = value
    if (
        not backend
        or backend.strip() != backend
        or not _is_portable_verify_backend_label(backend)
        or _is_production_claim_backend_label(backend)
        or _is_trusted_setup_backend_label(backend)
        or _is_developer_only_backend_label(backend)
    ):
        return False
    return _is_verifier_backend_registry_label_v1(backend)


def _require_production_verify_backend_label(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    backend = value
    if not backend.strip():
        raise ValueError(f"{context} must be a non-empty string")
    if backend.strip() != backend:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    if not _is_production_verify_backend_label(backend):
        raise ValueError(
            f"{context} uses unsupported production verifier backend {backend}"
        )
    return backend
