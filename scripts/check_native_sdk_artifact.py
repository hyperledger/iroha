#!/usr/bin/env python3
"""Record and verify fail-closed ABI-29 native SDK artifact evidence.

This checker is intentionally host-only.  It authenticates the exact native
artifact exercised by a Node, Python, C/JNI, or C# test lane, calls that
artifact's ABI probe, verifies its required entrypoints, enforces the exact
privacy C export inventory for bridge-bearing lanes, and binds the result to
the artifact bytes plus one canonical clean-source manifest. Apple and Android
release packages continue to use ``check_mobile_sdk_artifacts.sh``, which
additionally authenticates every cross-compiled slice and its transitive source
seal.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import locale
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import NoReturn

if __package__:
    from .compute_workspace_source_manifest import (
        native_artifact_workspace_source_manifest as workspace_source_manifest,
    )
else:
    _manifest_module_path = Path(__file__).resolve(strict=True).with_name(
        "compute_workspace_source_manifest.py"
    )
    _manifest_module_spec = importlib.util.spec_from_file_location(
        "_iroha_compute_workspace_source_manifest",
        _manifest_module_path,
    )
    if _manifest_module_spec is None or _manifest_module_spec.loader is None:
        raise ImportError(
            f"unable to load workspace source manifest helper: {_manifest_module_path}"
        )
    _manifest_module = importlib.util.module_from_spec(_manifest_module_spec)
    _manifest_module_spec.loader.exec_module(_manifest_module)
    workspace_source_manifest = (
        _manifest_module.native_artifact_workspace_source_manifest
    )


SCHEMA = "iroha.native-sdk-abi29-artifact.v1"
REQUIRED_BRIDGE_ABI_VERSION = 29
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SYMBOL_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_ABI_PROBE_OUTPUT_BYTES = 4096
MAX_PROBE_STDERR_BYTES = 4096
MAX_EXPORTED_SYMBOLS = 1_000_000
MAX_EVIDENCE_DIRECTORY_PATH_BYTES = 4 * 1024
MAX_EVIDENCE_DIRECTORY_COMPONENTS = 64
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
TARGET_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,127}")
SDK_VALUES = frozenset({"c-jni", "csharp", "node", "python"})
EXACT_PRIVACY_C_EXPORT_SDKS = frozenset({"c-jni", "csharp"})
_BINARY_OPEN_FLAG = getattr(os, "O_BINARY", 0)

APPROVED_PRIVACY_C_EXPORTS = (
    "iroha_privacy_compiled_profile_catalog_v1",
    "iroha_privacy_validate_compiled_profile_catalog_v1",
    "iroha_privacy_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_capability_manifest_v1",
    "iroha_privacy_free_buffer",
)
KAGEMUSHA_WALLET_C_EXPORTS = (
    "connect_norito_kagemusha_wallet_revision_v1",
    "connect_norito_kagemusha_wallet_open_begin_v1",
    "connect_norito_kagemusha_wallet_open_finish_v1",
    "connect_norito_kagemusha_wallet_open_cancel_v1",
    "connect_norito_kagemusha_wallet_close_v1",
    "connect_norito_kagemusha_wallet_activity_v1",
    "connect_norito_kagemusha_wallet_setup_v1",
    "connect_norito_kagemusha_wallet_execute_v1",
    "connect_norito_kagemusha_wallet_load_original_validate_v1",
    "connect_norito_kagemusha_wallet_request_status_v1",
    "connect_norito_kagemusha_wallet_retry_v1",
    "connect_norito_kagemusha_wallet_resume_v1",
    "connect_norito_kagemusha_wallet_fold_v1",
    "connect_norito_kagemusha_wallet_credit_status_v1",
    "connect_norito_kagemusha_wallet_snapshot_v1",
    "connect_norito_kagemusha_wallet_review_v1",
    "connect_norito_kagemusha_wallet_execute_reviewed_v1",
    "connect_norito_kagemusha_wallet_discard_review_v1",
    "connect_norito_kagemusha_wallet_installation_begin_v1",
    "connect_norito_kagemusha_wallet_installation_register_v1",
    "connect_norito_kagemusha_wallet_installation_close_v1",
    "connect_norito_kagemusha_wallet_registration_source_relocate_v1",
    "connect_norito_kagemusha_wallet_observe_v1",
    "connect_norito_kagemusha_wallet_account_original_v1",
    "connect_norito_kagemusha_wallet_account_display_v1",
    "connect_norito_kagemusha_wallet_enrollment_v1",
    "connect_norito_kagemusha_wallet_enrollment_refusal_v1",
)
KAGEMUSHA_WALLET_JNI_EXPORTS = (
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_revision",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_openBegin",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_openFinish",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_openCancel",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_close",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_activity",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_call",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_setup",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_enrollment",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_enrollmentRefusal",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_execute",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_snapshot",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_beginInstallation",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_registerInstallation",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_closeInstallation",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_relocateRegistrationSource",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletObservationNativeV1_observe",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_review",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_executeReviewed",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_discardReview",
)
KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS = (
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletLoadOriginalNativeV1_validate",
)
# Retired with the Google first-device sign-up key at bridge ABI 29; never re-exported.
RETIRED_FIRST_DEVICE_AUTH_JNI_EXPORTS = (
    "Java_org_hyperledger_iroha_sdk_crypto_keystore_NativeFirstDeviceAuthKeyJniV1_reserve",
    "Java_org_hyperledger_iroha_sdk_crypto_keystore_NativeFirstDeviceAuthKeyJniV1_restore",
)
RETIRED_KAGEMUSHA_C_PREFIX = (
    "connect_norito_" + "_".join(reversed(("cash", "offline"))) + "_"
)
RETIRED_KAGEMUSHA_EXPORT_PREFIXES = (
    RETIRED_KAGEMUSHA_C_PREFIX,
    "connect_norito_kagemusha_",
    "Java_org_hyperledger_iroha_sdk_offline_Kagemusha",
    "Java_org_hyperledger_iroha_sdk_offline_probe_Kagemusha",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_Kagemusha",
    "Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_",
)
STALE_PRIVACY_ABI_MARKER_RE = re.compile(
    r"(?:abi[_-]?(?:21|22|23|24|25|26)|(?:^|_)v(?:21|22|23|24|25|26)(?:$|_))",
    re.IGNORECASE,
)
DUMPBIN_EXPORT_RE = re.compile(
    rb"^\s*\d+\s+[0-9a-f]+\s+[0-9a-f]+\s+(\S+)(?:\s+.*)?$",
    re.IGNORECASE,
)

CONFIDENTIAL_PROVER_C_EXPORTS = tuple(
    "connect_norito_confidential_prover_" + suffix + "_v1"
    for suffix in (
        "revision", "create", "close", "job_create", "job_input", "job_output",
        "job_commitments", "job_paths", "job_prove", "job_close",
    )
)
CONFIDENTIAL_PROVER_JNI_EXPORTS = tuple(
    "Java_org_hyperledger_iroha_sdk_privacy_ConfidentialProverNative_" + method
    for method in (
        "revision", "create", "close", "jobCreate", "jobInput", "jobOutput",
        "jobCommitments", "jobPaths", "jobProve", "jobClose",
    )
)

REQUIRED_SYMBOLS: Mapping[str, tuple[str, ...]] = {
    "c-jni": (
        *CONFIDENTIAL_PROVER_C_EXPORTS,
        *KAGEMUSHA_WALLET_C_EXPORTS,
        *CONFIDENTIAL_PROVER_JNI_EXPORTS,
        *KAGEMUSHA_WALLET_JNI_EXPORTS,
        *KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS,
        "connect_norito_bridge_abi_version",
        "connect_norito_domain_id_validate_v1",
        "connect_norito_free",
        "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeBridgeAbiVersion",
        "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeIntentHashV1",
        "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeAssessmentMarkerV1",
        "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_nativeDecodeAssessmentV1",
        "connect_norito_retail_fee_intent_hash_v1",
        "connect_norito_retail_fee_assessment_marker_v1",
        "connect_norito_retail_fee_assessment_decode_v1",
        "connect_norito_validation_fee_current_policy_proof_request_v1",
        "connect_norito_validation_fee_current_policy_proof_verify_v1",
        "connect_norito_private_settlement_committee_proof_response_verify_v1",
        "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
        "connect_norito_private_settlement_audit_approval_response_verify_v1",
        "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeBridgeAbiVersion",
        "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyCommitteeProofResponseV1",
        "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyAuditorCapsuleResponseWithRequestV1",
        "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyAuditApprovalResponseV1",
        "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
    ),
    "csharp": (
        *CONFIDENTIAL_PROVER_C_EXPORTS,
        *KAGEMUSHA_WALLET_C_EXPORTS,
        "connect_norito_confidential_note_derivation_revision_v3",
        "connect_norito_confidential_default_diversifier_v3",
        "connect_norito_confidential_diversifier_derive_v3",
        "connect_norito_confidential_owner_tag_derive_v3",
        "connect_norito_confidential_note_commitment_derive_v3",
        "connect_norito_confidential_merkle_path_derive_v3",
        "connect_norito_bridge_abi_version",
        "connect_norito_domain_id_validate_v1",
        "connect_norito_free",
        "connect_norito_retail_fee_intent_hash_v1",
        "connect_norito_retail_fee_assessment_marker_v1",
        "connect_norito_retail_fee_assessment_decode_v1",
        "connect_norito_validation_fee_current_policy_proof_request_v1",
        "connect_norito_validation_fee_current_policy_proof_verify_v1",
        "connect_norito_private_settlement_committee_proof_response_verify_v1",
        "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
        "connect_norito_private_settlement_audit_approval_response_verify_v1",
        "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
        *APPROVED_PRIVACY_C_EXPORTS,
    ),
    "node": (
        "connectNoritoBridgeAbiVersion",
        "inspectSorafsOrderbookSubmissionForDiscriminantV1",
        "privateSettlementVerifyAuditApprovalResponseV1",
        "privateSettlementVerifyAuditorCapsuleResponseWithRequestV1",
        "privateSettlementVerifyCommitteeProofResponseV1",
        "sorafsValidateAppealFinanceCancelAssetLockJson",
        "validationFeeCurrentPolicyProofRequestV1",
        "validationFeeVerifyCurrentPolicyProofV1",
        "verifySorafsOrderbookSubmissionReceiptV1",
    ),
    "python": (
        "connect_norito_bridge_abi_version",
        "inspect_sorafs_orderbook_submission_for_discriminant_v1",
        "private_settlement_verify_audit_approval_response_v1",
        "private_settlement_verify_auditor_capsule_response_with_request_v1",
        "private_settlement_verify_committee_proof_response_v1",
        "sorafs_validate_appeal_finance_cancel_asset_lock_json",
        "verify_sorafs_orderbook_submission_receipt_v1",
    ),
}

RETIRED_PROTOCOL_SYMBOLS: Mapping[str, tuple[str, ...]] = {
    "c-jni": (
        "connect_norito_validation_fee_hijiri_quote_request_v1",
        "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
        "connect_norito_kagemusha_device_response_authenticator_v1_verify",
        "Java_org_hyperledger_iroha_sdk_offline_KagemushaDeviceLifecycleBridgeV1_00024NativeEndpoint_nativeVerifyResponseAuthenticatorV1",
        "connect_norito_private_settlement_auditor_capsule_response_verify_v1",
        "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyAuditorCapsuleResponseV1",
        "Java_org_hyperledger_iroha_android_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyAuditorCapsuleResponseV1",
        *RETIRED_FIRST_DEVICE_AUTH_JNI_EXPORTS,
    ),
    "csharp": (
        "connect_norito_validation_fee_hijiri_quote_request_v1",
        "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
        "connect_norito_kagemusha_device_response_authenticator_v1_verify",
        "connect_norito_private_settlement_auditor_capsule_response_verify_v1",
    ),
    "node": (
        "privateSettlementVerifyAuditorCapsuleResponseV1",
        "validationFeeHijiriQuoteRequestV1",
        "validationFeeVerifyHijiriQuoteResponseV1",
    ),
    "python": (
        "private_settlement_verify_auditor_capsule_response_v1",
        "validation_fee_hijiri_quote_request_v1",
        "validation_fee_verify_hijiri_quote_response_v1",
    ),
}


class ArtifactContractError(RuntimeError):
    """Raised when native SDK artifact evidence is incomplete or stale."""


def _windows_host_semantics() -> bool:
    """Return whether pathname and descriptor ctime values are incomparable."""

    return os.name == "nt"


def fail(message: str) -> NoReturn:
    """Raise one stable checker error."""

    raise ArtifactContractError(message)


def _plain_object(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def _reject_duplicate_object_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"native artifact manifest contains duplicate key {key!r}")
        result[key] = value
    return result


def _run_git(root: Path, arguments: Sequence[str]) -> str:
    environment = os.environ.copy()
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        fail(
            "native artifact source state could not be authenticated"
            + (f": {detail}" if detail else "")
        )
    return result.stdout


def source_state(root: Path) -> tuple[str, bool]:
    """Return the exact Git commit and whole-tree cleanliness."""

    commit = _run_git(root, ("rev-parse", "--verify", "HEAD")).strip()
    if COMMIT_RE.fullmatch(commit) is None:
        fail("native artifact source commit is not canonical lowercase Git SHA-1")
    status = _run_git(
        root,
        ("status", "--porcelain=v1", "--untracked-files=all"),
    )
    return commit, not bool(status.strip())


def workspace_source_manifest_sha256(root: Path) -> str:
    """Compute the repository's canonical checkout source-manifest digest."""

    try:
        digest = workspace_source_manifest(root)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        detail = str(error).strip()
        raise ArtifactContractError(
            "native artifact workspace source manifest could not be authenticated"
            + (f": {detail}" if detail else "")
        ) from error
    if SHA256_RE.fullmatch(digest) is None or digest == "0" * 64:
        fail("native artifact workspace source manifest SHA-256 is not canonical")
    return digest


def stable_artifact_identity(path: Path) -> tuple[str, int]:
    """Hash one regular, non-linked file while detecting replacement races."""

    try:
        before = path.lstat()
    except OSError as error:
        raise ArtifactContractError(
            f"native artifact is unavailable: {path}"
        ) from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
    ):
        fail("native artifact must be one non-empty regular file with one hard link")

    flags = (
        os.O_RDONLY
        | _BINARY_OPEN_FLAG
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ArtifactContractError(f"native artifact could not be opened: {path}") from error
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail("native artifact changed while it was opened")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
        opened.st_nlink,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    )
    if identity_before != identity_after:
        fail("native artifact changed while it was hashed")
    return digest.hexdigest(), opened.st_size


def stable_bounded_file_bytes(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    """Read one bounded regular file without following or racing replacements."""

    try:
        before = path.lstat()
    except OSError as error:
        raise ArtifactContractError(f"{label} is unavailable: {path}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        fail(f"{label} must be one bounded regular file with one hard link")

    flags = (
        os.O_RDONLY
        | _BINARY_OPEN_FLAG
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ArtifactContractError(f"{label} could not be opened: {path}") from error
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail(f"{label} changed while it was opened")
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(
        metadata: os.stat_result,
        *,
        compare_ctime: bool = True,
    ) -> tuple[int, ...]:
        stable = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_nlink,
        )
        return (*stable, metadata.st_ctime_ns) if compare_ctime else stable

    try:
        current = path.lstat()
    except OSError as error:
        raise ArtifactContractError(f"{label} changed while it was read") from error
    descriptor_changed = identity(opened) != identity(after)
    pathname_changed = identity(before) != identity(current)
    compare_path_ctime = not _windows_host_semantics()
    cross_api_changed = identity(
        before,
        compare_ctime=compare_path_ctime,
    ) != identity(
        opened,
        compare_ctime=compare_path_ctime,
    )
    if (
        descriptor_changed
        or pathname_changed
        or cross_api_changed
        or not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(opened.st_mode)
        or opened.st_nlink != 1
    ):
        fail(f"{label} changed while it was read")
    raw = b"".join(chunks)
    if len(raw) != opened.st_size or len(raw) > maximum_bytes:
        fail(f"{label} changed size or exceeded its byte limit while it was read")
    return raw


def _symbol_tool_commands(path: Path) -> tuple[tuple[str, tuple[str, ...], str], ...]:
    rendered = str(path)
    if sys.platform == "darwin":
        return (
            ("nm", ("-gUj", rendered), "macho-lines"),
            (
                "llvm-nm",
                ("--defined-only", "--extern-only", "-j", rendered),
                "macho-lines",
            ),
        )
    if _windows_host_semantics():
        return (
            (
                "llvm-readobj",
                ("--coff-exports", rendered),
                "llvm-coff-exports",
            ),
            ("dumpbin", ("/nologo", "/exports", rendered), "dumpbin"),
        )
    return (
        ("nm", ("-D", "--defined-only", "-j", rendered), "lines"),
        (
            "llvm-nm",
            ("--defined-only", "--extern-only", "-j", rendered),
            "lines",
        ),
    )


def _parse_symbol_tool_output(raw: bytes, output_format: str) -> tuple[str, ...]:
    if len(raw) > MAX_SYMBOL_TOOL_OUTPUT_BYTES:
        fail("native artifact exported-symbol inventory exceeds its byte limit")
    symbols: list[str] = []
    for line in raw.splitlines():
        if output_format == "dumpbin":
            match = DUMPBIN_EXPORT_RE.fullmatch(line)
            if match is None:
                continue
            encoded = match.group(1)
        elif output_format == "llvm-coff-exports":
            encoded = line.strip()
            prefix = b"Name: "
            if not encoded.startswith(prefix):
                continue
            encoded = encoded[len(prefix) :]
            if not encoded:
                fail("native artifact exported-symbol inventory is malformed")
        else:
            encoded = line.strip()
            if not encoded:
                continue
            if output_format == "macho-lines" and encoded.startswith(b"_"):
                encoded = encoded[1:]
        try:
            symbol = encoded.decode("ascii")
        except UnicodeDecodeError as error:
            raise ArtifactContractError(
                "native artifact exported-symbol inventory is not ASCII"
            ) from error
        symbols.append(symbol)
        if len(symbols) > MAX_EXPORTED_SYMBOLS:
            fail("native artifact exported-symbol inventory exceeds its entry limit")
    return tuple(symbols)


class _ProbeOutputLimitExceeded(subprocess.SubprocessError):
    """An owned probe exceeded its independently bounded stdout or stderr."""


def _windows_pipe_available(descriptor: int) -> int | None:
    """Peek one owned Windows pipe without blocking (including Python 3.10).

    None means that the writer has closed. Zero means no bytes are ready yet.
    Unlike selectors/os.set_blocking, this API supports pre-3.12 Windows pipes.
    """
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    peek = kernel.PeekNamedPipe
    peek.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                     wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    peek.restype = wintypes.BOOL
    available = wintypes.DWORD()
    if not peek(msvcrt.get_osfhandle(descriptor), None, 0, None, ctypes.byref(available), None):
        error = ctypes.get_last_error()
        if error in (109, 233):  # ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED
            return None
        raise ctypes.WinError(error)
    return available.value


def _read_probe_pipe(descriptor: int, maximum: int) -> bytes | None:
    """Read one bounded available chunk, returning None when it would block."""
    if os.name == "nt":
        available = _windows_pipe_available(descriptor)
        if available is None:
            return b""
        if not available:
            return None
        maximum = min(maximum, available)
    try:
        return os.read(descriptor, maximum)
    except (BlockingIOError, InterruptedError):
        return None


def _stop_owned_probe(process: subprocess.Popen) -> None:
    """Terminate/reap only this invocation's direct child, preserving its owner."""
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def _run_bounded_probe(command: Sequence[str], *, stdout_limit: int,
                       stderr_limit: int, timeout_seconds: float = 30,
                       env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess:
    """Drain actual probe streams within byte/wall limits before allocating more.

    There are no queues, reader threads, unbounded communicate calls or output
    spool files. POSIX uses nonblocking reads; Windows peeks the owned anonymous
    pipes before reading. Both preserve the caller's process group/session so
    an outer producer can stop the complete invocation. This helper reaps its
    direct child; it does not claim standalone arbitrary-descendant containment.
    Inherited writers still hit the same finite deadline and fail.
    """
    if (any(type(value) is not int or not 0 <= value <= MAX_SYMBOL_TOOL_OUTPUT_BYTES
            for value in (stdout_limit, stderr_limit))
            or type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30):
        raise ValueError("invalid bounded native probe limits")
    buffers = (bytearray(), bytearray())
    limits = (stdout_limit, stderr_limit)
    process = None
    streams = []
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(list(command), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0, close_fds=True, env=env,
                                   start_new_session=False)
        streams = [process.stdout, process.stderr]
        if os.name != "nt":
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
        pending = {0, 1}
        while pending or process.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(list(command), timeout_seconds,
                                                output=bytes(buffers[0]), stderr=bytes(buffers[1]))
            progressed = False
            for index in tuple(pending):
                raw = _read_probe_pipe(streams[index].fileno(), min(65536, limits[index] - len(buffers[index]) + 1))
                if raw is None:
                    continue
                progressed = True
                if not raw:
                    pending.remove(index)
                    continue
                if len(raw) > limits[index] - len(buffers[index]):
                    raise _ProbeOutputLimitExceeded(
                        "native probe " + ("stdout" if index == 0 else "stderr") + " exceeded its byte limit")
                buffers[index].extend(raw)
            if not progressed:
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        return subprocess.CompletedProcess(list(command), process.wait(timeout=0),
                                           bytes(buffers[0]), bytes(buffers[1]))
    except BaseException:
        if process is not None:
            _stop_owned_probe(process)
        raise
    finally:
        for stream in streams:
            stream.close()


def inspect_exported_symbols(path: Path, *, required: bool) -> tuple[str, ...] | None:
    """Read a native binary's export table with the host platform's tooling."""

    failures: list[str] = []
    for tool, arguments, output_format in _symbol_tool_commands(path):
        executable = shutil.which(tool)
        if executable is None:
            continue
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        try:
            result = _run_bounded_probe(
                [executable, *arguments],
                stdout_limit=MAX_SYMBOL_TOOL_OUTPUT_BYTES,
                stderr_limit=MAX_PROBE_STDERR_BYTES,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as error:
            failures.append(f"{tool}: {error}")
            continue
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()[:1024]
            failures.append(f"{tool}: {detail or f'exit {result.returncode}'}")
            continue
        symbols = _parse_symbol_tool_output(result.stdout, output_format)
        if symbols:
            return symbols
        failures.append(f"{tool}: no exported symbols")
    if required:
        detail = "; ".join(failures[:2])
        fail(
            "native bridge exported-symbol inventory could not be inspected"
            + (f": {detail}" if detail else ": no supported symbol tool is available")
        )
    return None


def validate_privacy_c_exports(
    symbols: Sequence[str],
    *,
    require_exact: bool,
) -> tuple[str, ...]:
    """Reject duplicate, stale, or unexpected native privacy C exports."""

    observed: list[str] = []
    for symbol in symbols:
        if type(symbol) is not str or not symbol or "\x00" in symbol:
            fail("native artifact exported-symbol inventory is malformed")
        lowered = symbol.lower()
        if (
            "privacy" in lowered or "connect_norito_bridge" in lowered
        ) and STALE_PRIVACY_ABI_MARKER_RE.search(lowered):
            fail(f"native artifact exports stale privacy/bridge ABI marker: {symbol}")
        if symbol.startswith("iroha_privacy_"):
            observed.append(symbol)
        elif "iroha_privacy_" in symbol:
            fail(f"native artifact exports decorated privacy C symbol variant: {symbol}")

    duplicates = sorted(
        symbol for symbol, count in Counter(observed).items() if count != 1
    )
    if duplicates:
        fail(
            "native artifact exports duplicate privacy C symbols: "
            + ", ".join(duplicates)
        )
    unexpected = sorted(set(observed) - set(APPROVED_PRIVACY_C_EXPORTS))
    if unexpected:
        fail(
            "native artifact exports unexpected privacy C symbols: "
            + ", ".join(unexpected)
        )
    if require_exact:
        missing = [
            symbol for symbol in APPROVED_PRIVACY_C_EXPORTS if symbol not in observed
        ]
        if missing:
            fail(
                "native bridge artifact is missing approved privacy C symbols: "
                + ", ".join(missing)
            )
    return tuple(symbol for symbol in APPROVED_PRIVACY_C_EXPORTS if symbol in observed)


def is_retired_kagemusha_export(symbol: str) -> bool:
    """Reject all retired or unknown KAGEMUSHA exports outside the current API."""
    return (
        symbol.startswith(RETIRED_KAGEMUSHA_EXPORT_PREFIXES)
        and symbol not in KAGEMUSHA_WALLET_C_EXPORTS
        and symbol not in KAGEMUSHA_WALLET_JNI_EXPORTS
        and symbol not in KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS
    )


def validate_retired_protocol_symbols(symbols: Sequence[str], *, sdk: str) -> None:
    """Reject first-release artifacts that expose retired protocol entrypoints."""

    explicitly_retired = set(RETIRED_PROTOCOL_SYMBOLS[sdk])
    retired = sorted(
        {
            symbol
            for symbol in symbols
            if symbol in explicitly_retired
            or (sdk == "c-jni" and symbol.startswith("Java_org_hyperledger_iroha_android_"))
            or is_retired_kagemusha_export(symbol)
        }
    )
    if retired:
        fail("native artifact exports retired protocol symbols: " + ", ".join(retired))


def probe_c_abi(
    path: Path,
    required_symbols: Sequence[str],
    *,
    forbidden_symbols: Sequence[str] = (),
) -> int:
    """Load one C ABI library and require its exact exported inventory."""

    try:
        library = ctypes.CDLL(str(path))
    except OSError as error:
        raise ArtifactContractError(f"native C ABI artifact could not be loaded: {path}") from error
    missing = [symbol for symbol in required_symbols if not hasattr(library, symbol)]
    if missing:
        fail("native C ABI artifact is missing required symbols: " + ", ".join(missing))
    retired = [symbol for symbol in forbidden_symbols if hasattr(library, symbol)]
    if retired:
        fail("native C ABI artifact exports retired symbols: " + ", ".join(retired))
    probe = getattr(library, "connect_norito_bridge_abi_version")
    probe.argtypes = []
    probe.restype = ctypes.c_uint32
    return int(probe())


def _probe_subprocess(
    command: Sequence[str],
    *,
    label: str,
) -> int:
    try:
        result = _run_bounded_probe(command, stdout_limit=MAX_ABI_PROBE_OUTPUT_BYTES,
                                    stderr_limit=MAX_PROBE_STDERR_BYTES)
    except (OSError, subprocess.SubprocessError) as error:
        raise ArtifactContractError(f"{label} failed: {error}") from error
    # Preserve subprocess text=True's locale decoding and universal newlines.
    encoding = locale.getpreferredencoding(False)
    stderr = result.stderr.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
    stdout = result.stdout.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
    if result.returncode != 0:
        detail = stderr.strip()[:4096]
        fail(f"{label} failed" + (f": {detail}" if detail else ""))
    raw = stdout.strip()
    if not raw.isascii() or not raw.isdecimal():
        fail(f"{label} returned a noncanonical ABI version")
    return int(raw)


def probe_node_abi(
    path: Path,
    required_symbols: Sequence[str],
    *,
    forbidden_symbols: Sequence[str] = (),
    node: str = "node",
) -> int:
    """Load one Node addon and call its exact ABI-29 probe."""

    source = r"""
const artifact = process.argv[1];
const required = JSON.parse(process.argv[2]);
const forbidden = JSON.parse(process.argv[3]);
let binding;
if (/\.(?:cjs|js)$/iu.test(artifact)) {
  binding = require(artifact);
} else {
  const nativeModule = { exports: {} };
  process.dlopen(nativeModule, artifact);
  binding = nativeModule.exports;
}
const missing = required.filter((name) => typeof binding[name] !== "function");
if (missing.length !== 0) {
  process.stderr.write("missing required exports: " + missing.join(", "));
  process.exit(2);
}
const retiredPrefix = "connect_norito_" + ["cash", "offline"].reverse().join("_") + "_";
const retired = Object.getOwnPropertyNames(binding).filter(
  (name) => forbidden.includes(name) || name.startsWith(retiredPrefix),
);
if (retired.length !== 0) {
  process.stderr.write("retired exports: " + retired.join(", "));
  process.exit(3);
}
const version = binding.connectNoritoBridgeAbiVersion();
if (!Number.isSafeInteger(version) || version < 0) {
  process.stderr.write("ABI probe returned a non-integer");
  process.exit(4);
}
process.stdout.write(String(version));
"""
    return _probe_subprocess(
        (
            node,
            "--eval",
            source,
            str(path),
            json.dumps(list(required_symbols)),
            json.dumps(list(forbidden_symbols)),
        ),
        label="native Node ABI probe",
    )


def probe_python_abi(
    path: Path,
    required_symbols: Sequence[str],
    *,
    forbidden_symbols: Sequence[str] = (),
    python: str = sys.executable,
) -> int:
    """Load one Python extension directly and call its exact ABI-29 probe."""

    source = r"""
import importlib.machinery
import importlib.util
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
required = json.loads(sys.argv[2])
forbidden = json.loads(sys.argv[3])
if path.suffix == ".py":
    name = "_iroha_native_abi29_fixture"
    loader = importlib.machinery.SourceFileLoader(name, str(path))
else:
    name = "iroha_native._crypto"
    loader = importlib.machinery.ExtensionFileLoader(name, str(path))
spec = importlib.util.spec_from_loader(name, loader)
if spec is None:
    raise SystemExit("native extension has no import specification")
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
missing = [name for name in required if not callable(getattr(module, name, None))]
if missing:
    raise SystemExit("missing required exports: " + ", ".join(missing))
retired_prefix = "connect_norito_" + "_".join(reversed(("cash", "offline"))) + "_"
retired = [
    name
    for name in dir(module)
    if name in forbidden
    or name.startswith(retired_prefix)
]
if retired:
    raise SystemExit("retired exports: " + ", ".join(retired))
version = module.connect_norito_bridge_abi_version()
if type(version) is not int or version < 0:
    raise SystemExit("ABI probe returned a non-integer")
print(version, end="")
"""
    return _probe_subprocess(
        (
            python,
            "-I",
            "-B",
            "-c",
            source,
            str(path),
            json.dumps(list(required_symbols)),
            json.dumps(list(forbidden_symbols)),
        ),
        label="native Python ABI probe",
    )


def probe_artifact(
    sdk: str,
    path: Path,
    *,
    node: str = "node",
    python: str = sys.executable,
) -> int:
    """Probe the exact host artifact selected for one SDK lane."""

    required = REQUIRED_SYMBOLS[sdk]
    forbidden = RETIRED_PROTOCOL_SYMBOLS[sdk]
    if sdk == "node":
        return probe_node_abi(
            path,
            required,
            forbidden_symbols=forbidden,
            node=node,
        )
    if sdk == "python":
        return probe_python_abi(
            path,
            required,
            forbidden_symbols=forbidden,
            python=python,
        )
    return probe_c_abi(path, required, forbidden_symbols=forbidden)


def _require_exact_abi(version: int) -> None:
    if type(version) is not int or version != REQUIRED_BRIDGE_ABI_VERSION:
        fail(
            "native artifact bridge ABI must be exactly "
            f"{REQUIRED_BRIDGE_ABI_VERSION}; found {version!r}"
        )


def build_manifest(
    *,
    sdk: str,
    target: str,
    artifact_path: Path,
    source_root: Path,
    probe: Callable[[str, Path], int] = probe_artifact,
    symbol_inventory: Callable[[Path], Sequence[str] | None] | None = None,
) -> dict[str, object]:
    """Authenticate one artifact and return its canonical evidence manifest."""

    if sdk not in SDK_VALUES:
        fail(f"unsupported native SDK lane: {sdk!r}")
    if TARGET_RE.fullmatch(target) is None:
        fail("native SDK target must be a bounded lowercase target token")
    commit_before, clean_before = source_state(source_root)
    if not clean_before:
        fail("native SDK artifacts must be built and tested from a clean source tree")
    source_manifest_before = workspace_source_manifest_sha256(source_root)
    digest, size = stable_artifact_identity(artifact_path)
    version = probe(sdk, artifact_path)
    _require_exact_abi(version)
    exact_privacy_exports = sdk in EXACT_PRIVACY_C_EXPORT_SDKS
    if symbol_inventory is None:
        symbols = inspect_exported_symbols(
            artifact_path,
            required=exact_privacy_exports,
        )
    else:
        symbols = symbol_inventory(artifact_path)
    privacy_exports_inspected = symbols is not None
    if symbols is not None:
        validate_retired_protocol_symbols(symbols, sdk=sdk)
    privacy_exports = validate_privacy_c_exports(
        () if symbols is None else symbols,
        require_exact=exact_privacy_exports,
    )
    digest_after, size_after = stable_artifact_identity(artifact_path)
    if (digest_after, size_after) != (digest, size):
        fail("native artifact changed while its ABI and exports were probed")
    source_manifest_after = workspace_source_manifest_sha256(source_root)
    commit_after, clean_after = source_state(source_root)
    if (
        commit_after != commit_before
        or not clean_after
        or source_manifest_after != source_manifest_before
    ):
        fail("native SDK source changed while artifact evidence was collected")
    return {
        "artifact_sha256": digest,
        "artifact_size": size,
        "bridge_abi_version": version,
        "privacy_c_exports": list(privacy_exports),
        "privacy_c_exports_inspected": privacy_exports_inspected,
        "required_symbols": list(REQUIRED_SYMBOLS[sdk]),
        "schema": SCHEMA,
        "sdk": sdk,
        "source_commit": commit_before,
        "workspace_source_manifest_sha256": source_manifest_before,
        "source_tree_clean": True,
        "target": target,
    }


def canonical_manifest_bytes(manifest: Mapping[str, object]) -> bytes:
    """Encode one already validated evidence manifest canonically."""

    validated = validate_manifest(dict(manifest))
    return (
        json.dumps(validated, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def validate_manifest(value: object) -> dict[str, object]:
    """Validate the exact ABI-29 artifact evidence schema."""

    manifest = _plain_object(value, "native artifact manifest")
    expected_keys = {
        "artifact_sha256",
        "artifact_size",
        "bridge_abi_version",
        "privacy_c_exports",
        "privacy_c_exports_inspected",
        "required_symbols",
        "schema",
        "sdk",
        "source_commit",
        "source_tree_clean",
        "target",
        "workspace_source_manifest_sha256",
    }
    if set(manifest) != expected_keys:
        fail("native artifact manifest field inventory is not exact")
    sdk = manifest["sdk"]
    if type(sdk) is not str or sdk not in SDK_VALUES:
        fail("native artifact manifest SDK lane is unsupported")
    target = manifest["target"]
    if type(target) is not str or TARGET_RE.fullmatch(target) is None:
        fail("native artifact manifest target is not canonical")
    digest = manifest["artifact_sha256"]
    if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
        fail("native artifact manifest SHA-256 is not canonical")
    size = manifest["artifact_size"]
    if type(size) is not int or size <= 0:
        fail("native artifact manifest size must be a positive integer")
    version = manifest["bridge_abi_version"]
    _require_exact_abi(version)
    commit = manifest["source_commit"]
    if type(commit) is not str or COMMIT_RE.fullmatch(commit) is None:
        fail("native artifact manifest source commit is not canonical")
    source_manifest = manifest["workspace_source_manifest_sha256"]
    if (
        type(source_manifest) is not str
        or SHA256_RE.fullmatch(source_manifest) is None
        or source_manifest == "0" * 64
    ):
        fail("native artifact manifest source-manifest SHA-256 is not canonical")
    if manifest["source_tree_clean"] is not True:
        fail("native artifact manifest must attest a clean source tree")
    if manifest["schema"] != SCHEMA:
        fail("native artifact manifest schema is unsupported")
    required = manifest["required_symbols"]
    if type(required) is not list or tuple(required) != REQUIRED_SYMBOLS[sdk]:
        fail("native artifact required-symbol inventory is not exact")
    privacy_exports = manifest["privacy_c_exports"]
    privacy_exports_inspected = manifest["privacy_c_exports_inspected"]
    if type(privacy_exports_inspected) is not bool or type(privacy_exports) is not list:
        fail("native artifact privacy C export evidence is malformed")
    validated_privacy_exports = validate_privacy_c_exports(
        privacy_exports,
        require_exact=sdk in EXACT_PRIVACY_C_EXPORT_SDKS,
    )
    if tuple(privacy_exports) != validated_privacy_exports:
        fail("native artifact privacy C export inventory is not canonical")
    if sdk in EXACT_PRIVACY_C_EXPORT_SDKS and not privacy_exports_inspected:
        fail("native bridge manifest must attest inspected privacy C exports")
    if not privacy_exports_inspected and privacy_exports:
        fail("uninspected native privacy C export evidence must be empty")
    return dict(manifest)


def load_manifest(path: Path) -> dict[str, object]:
    """Read one bounded, canonical evidence manifest."""

    raw = stable_bounded_file_bytes(
        path,
        label="native artifact manifest",
        maximum_bytes=MAX_MANIFEST_BYTES,
    )
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_object_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactContractError(
            f"native artifact manifest is unreadable: {path}"
        ) from error
    validated = validate_manifest(parsed)
    if raw != canonical_manifest_bytes(validated):
        fail("native artifact manifest JSON is not canonical")
    return validated


def verify_manifest(
    manifest: Mapping[str, object],
    *,
    artifact_path: Path,
    source_root: Path,
    probe: Callable[[str, Path], int] = probe_artifact,
    symbol_inventory: Callable[[Path], Sequence[str] | None] | None = None,
) -> None:
    """Re-authenticate source, artifact bytes, exports, and exact ABI."""

    expected = validate_manifest(dict(manifest))
    commit_before, clean_before = source_state(source_root)
    if (
        not clean_before
        or commit_before != expected["source_commit"]
        or expected["source_tree_clean"] is not True
    ):
        fail("native artifact manifest does not match the current clean source revision")
    source_manifest_before = workspace_source_manifest_sha256(source_root)
    if source_manifest_before != expected["workspace_source_manifest_sha256"]:
        fail("native artifact manifest does not match the current source manifest")
    digest, size = stable_artifact_identity(artifact_path)
    if digest != expected["artifact_sha256"] or size != expected["artifact_size"]:
        fail("native artifact bytes do not match the evidence manifest")
    version = probe(str(expected["sdk"]), artifact_path)
    _require_exact_abi(version)
    if version != expected["bridge_abi_version"]:
        fail("native artifact ABI probe does not match the evidence manifest")
    sdk = str(expected["sdk"])
    must_inspect = sdk in EXACT_PRIVACY_C_EXPORT_SDKS or bool(
        expected["privacy_c_exports_inspected"]
    )
    if symbol_inventory is None:
        symbols = inspect_exported_symbols(artifact_path, required=must_inspect)
    else:
        symbols = symbol_inventory(artifact_path)
    if symbols is not None:
        validate_retired_protocol_symbols(symbols, sdk=sdk)
    privacy_exports = validate_privacy_c_exports(
        () if symbols is None else symbols,
        require_exact=sdk in EXACT_PRIVACY_C_EXPORT_SDKS,
    )
    if bool(expected["privacy_c_exports_inspected"]):
        if symbols is None or list(privacy_exports) != expected["privacy_c_exports"]:
            fail("native artifact privacy C exports do not match the evidence manifest")
    digest_after, size_after = stable_artifact_identity(artifact_path)
    if (digest_after, size_after) != (digest, size):
        fail("native artifact changed while its ABI and exports were verified")
    source_manifest_after = workspace_source_manifest_sha256(source_root)
    commit_after, clean_after = source_state(source_root)
    if (
        commit_after != commit_before
        or not clean_after
        or source_manifest_after != source_manifest_before
    ):
        fail("native SDK source changed while artifact evidence was verified")


def _exclusive_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | _BINARY_OPEN_FLAG
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ArtifactContractError(
            f"native artifact manifest output must be fresh: {path}"
        ) from error
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_real_directory_ancestry(path: Path, *, label: str) -> None:
    """Require an existing absolute directory path without symlink components."""

    if not path.is_absolute():
        fail(f"{label} must be absolute")
    anchor = Path(path.anchor)
    current = anchor
    for component in path.parts[len(anchor.parts) :]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ArtifactContractError(
                f"{label} ancestry is unavailable: {current}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} ancestry must not contain symlinks: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} ancestry must contain only directories: {current}")


def _require_descriptor_staging_support() -> None:
    """Fail unless Unix descriptor-relative no-follow staging is available."""

    dir_fd_functions = getattr(os, "supports_dir_fd", ())
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not getattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not getattr(os, "O_NOFOLLOW")
        or os.open not in dir_fd_functions
    ):
        fail(
            "native artifact staging requires Unix dir_fd, O_DIRECTORY, "
            "and O_NOFOLLOW support"
        )


def _open_pinned_directory_ancestry(path: Path, *, label: str) -> int:
    """Open every component beneath a trusted anchor without following links."""

    if not path.is_absolute():
        fail(f"{label} must be absolute")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    anchor = Path(path.anchor)
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(anchor, flags))
        for component in path.parts[len(anchor.parts) :]:
            descriptors.append(
                os.open(component, flags, dir_fd=descriptors[-1])
            )
        return descriptors.pop()
    except OSError as error:
        raise ArtifactContractError(
            f"{label} ancestry could not be pinned without following symlinks"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def stage_unique_artifact(
    source: Path,
    canonical_destination: Path,
) -> tuple[Path, str, int]:
    """Copy a pinned build output into one fresh single-link artifact.

    Cargo may hard-link its top-level dynamic-library output to the hashed
    artifact under ``deps``.  Such build outputs are valid staging inputs but
    are not valid authenticated SDK artifacts.  Pin the source descriptor and
    its metadata revision, create the destination exclusively beneath a pinned
    parent, and prove the staged bytes match the source digest and size.
    """

    _require_descriptor_staging_support()
    source = Path(os.path.abspath(source))
    canonical_destination = Path(os.path.abspath(canonical_destination))
    if source == canonical_destination:
        fail("native artifact staging source and destination must differ")

    def source_revision(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_nlink,
        )

    try:
        source_before = source.lstat()
    except OSError as error:
        raise ArtifactContractError(
            f"native artifact staging source is unavailable: {source}"
        ) from error
    if (
        stat.S_ISLNK(source_before.st_mode)
        or not stat.S_ISREG(source_before.st_mode)
        or source_before.st_size <= 0
        or source_before.st_nlink < 1
    ):
        fail("native artifact staging source must be one non-empty regular file")

    canonical_parent = canonical_destination.parent

    read_flags = (
        os.O_RDONLY
        | _BINARY_OPEN_FLAG
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    write_flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | _BINARY_OPEN_FLAG
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    parent_descriptor: int | None = None
    digest = hashlib.sha256()
    copied_size = 0
    result: tuple[Path, str, int] | None = None
    failure: ArtifactContractError | None = None
    try:
        parent_descriptor = _open_pinned_directory_ancestry(
            canonical_parent,
            label="native artifact staging directory",
        )
        parent_opened = os.fstat(parent_descriptor)
        parent_named = canonical_parent.lstat()
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or stat.S_ISLNK(parent_named.st_mode)
            or (parent_opened.st_dev, parent_opened.st_ino)
            != (parent_named.st_dev, parent_named.st_ino)
        ):
            fail("native artifact staging directory changed before creation")

        source_descriptor = os.open(source, read_flags)
        source_opened = os.fstat(source_descriptor)
        if source_revision(source_opened) != source_revision(source_before):
            fail("native artifact staging source changed while it was opened")

        try:
            destination_descriptor = os.open(
                canonical_destination.name,
                write_flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError as error:
            raise ArtifactContractError(
                "native artifact staging destination must be one fresh path: "
                f"{canonical_destination}"
            ) from error
        destination_opened = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(destination_opened.st_mode)
            or destination_opened.st_nlink != 1
            or destination_opened.st_size != 0
            or stat.S_IMODE(destination_opened.st_mode) & 0o077 != 0
        ):
            fail("staged native artifact was not created as one private regular file")

        pinned_size = source_opened.st_size
        while copied_size < pinned_size:
            chunk = os.read(
                source_descriptor,
                min(1024 * 1024, pinned_size - copied_size),
            )
            if not chunk:
                fail("native artifact staging source was truncated while it was copied")
            digest.update(chunk)
            copied_size += len(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    fail("staged native artifact could not be written completely")
                offset += written
        if os.read(source_descriptor, 1):
            fail("native artifact staging source grew while it was copied")
        os.fsync(destination_descriptor)

        source_after = os.fstat(source_descriptor)
        source_named_after = source.lstat()
        if (
            source_revision(source_after) != source_revision(source_opened)
            or source_revision(source_named_after) != source_revision(source_opened)
        ):
            fail("native artifact staging source changed while it was copied")

        destination_after = os.fstat(destination_descriptor)
        destination_named_after = canonical_destination.lstat()
        if (
            not stat.S_ISREG(destination_after.st_mode)
            or destination_after.st_nlink != 1
            or destination_after.st_size != copied_size
            or copied_size != pinned_size
            or stat.S_IMODE(destination_after.st_mode) & 0o077 != 0
            or (destination_after.st_dev, destination_after.st_ino)
            != (destination_opened.st_dev, destination_opened.st_ino)
            or (destination_named_after.st_dev, destination_named_after.st_ino)
            != (destination_opened.st_dev, destination_opened.st_ino)
            or destination_named_after.st_size != copied_size
            or destination_named_after.st_nlink != 1
        ):
            fail("staged native artifact changed while it was copied")

        parent_after = os.fstat(parent_descriptor)
        parent_named_after = canonical_parent.lstat()
        if (
            (parent_after.st_dev, parent_after.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
            or (parent_named_after.st_dev, parent_named_after.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
        ):
            fail("native artifact staging directory changed while it was used")
        source_digest = digest.hexdigest()
        staged_digest, staged_size = stable_artifact_identity(canonical_destination)
        if staged_digest != source_digest or staged_size != copied_size:
            fail("staged native artifact does not match the pinned build output")
        result = canonical_destination, source_digest, copied_size
    except ArtifactContractError as error:
        failure = error
    except OSError as error:
        failure = ArtifactContractError(
            "native artifact could not be staged through pinned file descriptors"
        )
        failure.__cause__ = error
    finally:
        # POSIX has no portable atomic "unlink this name only if it still names
        # this inode" operation.  Once the exclusive destination is visible,
        # retain it on failure rather than risk deleting a replacement installed
        # between a metadata check and pathname-based unlink.
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)

    if failure is not None:
        raise failure
    if result is None:
        fail("native artifact staging completed without an authenticated result")
    return result


def _exclusive_write_at(directory: int, name: str, payload: bytes) -> None:
    """Create one private regular file relative to an authenticated directory."""

    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | _BINARY_OPEN_FLAG
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    except OSError as error:
        raise ArtifactContractError(
            f"retained native artifact manifest output must be fresh: {name}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail("retained native artifact manifest must be one regular file")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        if (
            not stat.S_ISREG(written.st_mode)
            or stat.S_IMODE(written.st_mode) & 0o077 != 0
            or written.st_nlink != 1
            or written.st_size != len(payload)
        ):
            fail("retained native artifact manifest changed while it was written")
    finally:
        os.close(descriptor)


def retain_verified_manifest(
    manifest: Mapping[str, object],
    *,
    artifact_path: Path,
    evidence_directory: Path,
    source_root: Path,
    probe: Callable[[str, Path], int] = probe_artifact,
) -> Path:
    """Re-authenticate and retain a manifest in one fresh private directory.

    The output directory is deliberately fresh and external to the
    authenticated source tree so retaining evidence cannot invalidate the
    clean-tree claim.
    """

    validated = validate_manifest(dict(manifest))
    verify_manifest(
        validated,
        artifact_path=artifact_path,
        source_root=source_root,
        probe=probe,
    )
    path_text = os.fspath(evidence_directory)
    try:
        encoded_path = os.fsencode(path_text)
    except UnicodeError as error:
        raise ArtifactContractError(
            "native artifact evidence directory path is not representable"
        ) from error
    if (
        not evidence_directory.is_absolute()
        or len(encoded_path) == 0
        or len(encoded_path) > MAX_EVIDENCE_DIRECTORY_PATH_BYTES
        or len(evidence_directory.parts) > MAX_EVIDENCE_DIRECTORY_COMPONENTS
        or any(component in {".", ".."} for component in evidence_directory.parts)
        or evidence_directory == Path(evidence_directory.anchor)
    ):
        fail("native artifact evidence directory must be a bounded absolute leaf path")

    parent = evidence_directory.parent
    _require_real_directory_ancestry(
        parent,
        label="native artifact evidence directory",
    )
    try:
        evidence_directory.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ArtifactContractError(
            f"native artifact evidence directory is unavailable: {evidence_directory}"
        ) from error
    else:
        fail(
            "native artifact evidence directory must be fresh and must not be a symlink"
        )

    canonical_source = source_root.resolve(strict=True)
    canonical_parent = parent.resolve(strict=True)
    canonical_output = canonical_parent / evidence_directory.name
    if canonical_output == canonical_source or canonical_source in canonical_output.parents:
        fail("native artifact evidence directory must be outside the source tree")

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(canonical_parent, directory_flags)
    except OSError as error:
        raise ArtifactContractError(
            "native artifact evidence directory parent could not be opened"
        ) from error
    directory_descriptor: int | None = None
    try:
        parent_identity = os.fstat(parent_descriptor)
        current_parent = canonical_parent.lstat()
        if (
            not stat.S_ISDIR(parent_identity.st_mode)
            or stat.S_ISLNK(current_parent.st_mode)
            or (parent_identity.st_dev, parent_identity.st_ino)
            != (current_parent.st_dev, current_parent.st_ino)
        ):
            fail("native artifact evidence directory parent changed before creation")
        try:
            os.mkdir(evidence_directory.name, 0o700, dir_fd=parent_descriptor)
            directory_descriptor = os.open(
                evidence_directory.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            raise ArtifactContractError(
                "native artifact evidence directory must be created as one fresh directory"
            ) from error
        created = os.fstat(directory_descriptor)
        current = canonical_output.lstat()
        if (
            not stat.S_ISDIR(created.st_mode)
            or stat.S_IMODE(created.st_mode) & 0o077 != 0
            or stat.S_ISLNK(current.st_mode)
            or (created.st_dev, created.st_ino) != (current.st_dev, current.st_ino)
        ):
            fail("native artifact evidence directory changed while it was created")
        output_name = f"{validated['sdk']}-native-abi29.json"
        _exclusive_write_at(
            directory_descriptor,
            output_name,
            canonical_manifest_bytes(validated),
        )
        current_after_write = canonical_output.lstat()
        if (
            stat.S_ISLNK(current_after_write.st_mode)
            or (created.st_dev, created.st_ino)
            != (current_after_write.st_dev, current_after_write.st_ino)
        ):
            fail("native artifact evidence directory changed while evidence was written")
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        os.close(parent_descriptor)

    retained_path = canonical_output / f"{validated['sdk']}-native-abi29.json"
    if load_manifest(retained_path) != validated:
        fail("retained native artifact manifest does not match verified evidence")
    return retained_path


def parse_args() -> argparse.Namespace:
    """Parse the record/verify command line."""

    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("record", "verify"))
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--sdk", choices=tuple(sorted(SDK_VALUES)))
    parser.add_argument("--target")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--stage-artifact", type=Path)
    return parser.parse_args()


def main() -> int:
    """Run the selected fail-closed artifact operation."""

    args = parse_args()
    # Preserve the final path component so ``stable_artifact_identity`` can
    # reject a symlink rather than silently authenticating its target.
    artifact = Path(os.path.abspath(args.artifact))
    if not artifact.exists() and not artifact.is_symlink():
        fail(f"native artifact is unavailable: {artifact}")
    source_root = args.source_root.resolve(strict=True)
    probe = lambda sdk, path: probe_artifact(
        sdk,
        path,
        node=args.node,
        python=args.python,
    )
    if args.mode == "record":
        if args.evidence_dir is not None:
            fail("record mode does not accept --evidence-dir")
        if args.sdk is None or args.target is None:
            fail("record mode requires --sdk and --target")
        staged_source_identity: tuple[str, int] | None = None
        if args.stage_artifact is not None:
            stage_destination = Path(os.path.abspath(args.stage_artifact))
            try:
                canonical_stage_parent = stage_destination.parent.resolve(strict=True)
            except OSError as error:
                raise ArtifactContractError(
                    "native artifact staging directory is unavailable: "
                    f"{stage_destination.parent}"
                ) from error
            canonical_stage = canonical_stage_parent / stage_destination.name
            if canonical_stage == source_root or source_root in canonical_stage.parents:
                fail("staged native artifact must be outside the source tree")
            staged_artifact, staged_digest, staged_size = stage_unique_artifact(
                artifact,
                canonical_stage,
            )
            if (
                staged_artifact != canonical_stage
                or staged_artifact == source_root
                or source_root in staged_artifact.parents
            ):
                fail("returned staged native artifact must remain outside the source tree")
            artifact = staged_artifact
            staged_source_identity = staged_digest, staged_size
        manifest = build_manifest(
            sdk=args.sdk,
            target=args.target,
            artifact_path=artifact,
            source_root=source_root,
            probe=probe,
        )
        if staged_source_identity is not None and (
            manifest["artifact_sha256"],
            manifest["artifact_size"],
        ) != staged_source_identity:
            fail("recorded native artifact does not match the pinned staging source")
        _exclusive_write(args.manifest, canonical_manifest_bytes(manifest))
    else:
        if args.stage_artifact is not None:
            fail("verify mode does not accept --stage-artifact")
        if args.sdk is not None or args.target is not None:
            fail("verify mode reads SDK and target from the manifest")
        manifest = load_manifest(Path(os.path.abspath(args.manifest)))
        if args.evidence_dir is not None:
            retain_verified_manifest(
                manifest,
                artifact_path=artifact,
                evidence_directory=args.evidence_dir,
                source_root=source_root,
                probe=probe,
            )
        else:
            verify_manifest(
                manifest,
                artifact_path=artifact,
                source_root=source_root,
                probe=probe,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArtifactContractError as error:
        print(f"native SDK ABI-29 artifact check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
