#!/usr/bin/env python3
"""Freeze the sole Kotlin JNI signatures, bodies, attributes and privacy inventory."""

from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
JNI_SOURCE = REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni/part_3.rs"
SDK_PREFIX = "Java_org_hyperledger_iroha_sdk_"
ANDROID_PREFIX = "Java_org_hyperledger_iroha_android_"
EXPECTED_GOVERNANCE_SOURCE_DIGEST = "a13b0664abdf988946a4b48740c44f7352b815d16faf981ca06fec2d52a483fa"
EXPECTED_GOVERNANCE_METHODS = (
    "nativeBridgeAbiVersion", "nativeVerifyCastingProofV1", "nativeVerifyCastingProofPageV1",
    "nativeRegistrationFromProofV1", "nativeBallotFromProofV1",
)
EXPECTED_ABI_DIGEST = "dc78a30d4283897a423abcba22ee6a9e4f1cf4e372ffe05c48f22a5e48ccad66"
EXPECTED_ATTRIBUTE_DIGEST = "c80e87e1a878a1263dd1cb7708bc8ec335cb7e4e5461934708561466f7a2d795"

EXPECTED_METHODS = {
    "crypto_NativeSignerBridge": (
        "nativePublicKeyFromPrivate",
        "nativeBridgeAbiVersion",
        "nativeSignerContractRevision",
        "nativeKeypairFromSeed",
        "nativeSignDetached",
        "nativeVerifyDetached",
        "nativeAccountReadPermissionMultisigPayloadHash",
        "nativeFinalizeAccountReadPermissionMultisig",
        "nativeEncodeRegisterZkAssetSignedTransaction",
    ),
    "privacy_PrivacyNativeBridge": (
        "nativeBridgeAbiVersion",
        "nativeCompiledProfileCatalog",
        "nativeValidateCompiledProfileCatalog",
        "nativeValidateExact12CapabilityManifestForNetworkV1",
        "nativeInspectExact12CapabilityManifest",
        "nativeRequireExact12CapabilityTupleForNetworkV1",
        "nativeValidateExact12SubmitProofConstructionForNetworkV1",
        "nativeExact12FixtureBundle",
        "nativeValidateExact12FixtureBundle",
    ),
    "sorafs_SorafsReferenceValidators": (
        "nativeBridgeAbiVersion",
        "nativeHasGovernanceDagSymbols",
        "nativeHasGovernanceLogNodeSymbols",
        "nativeHasFixtureBundleSymbols",
        "nativeHasAppealFinanceSymbols",
        "nativeValidateOrderbookPayloadJson",
        "nativeValidatePopPayloadJson",
        "nativeValidateHedgingPayloadJson",
        "nativeValidateAppealFinanceCancelAssetLockJson",
        "nativeValidateFixtureBundleJson",
        "nativeValidateGovernanceLogNodeJson",
        "nativeValidateGovernanceDagBlockJson",
        "nativeValidateGovernanceDagHeadChainJson",
        "nativeSignOrderbookPayload",
        "nativeDeriveOrderbookOrderId",
        "nativeBuildSignedOrderbookOrderRequest",
        "nativeBuildSignedOrderbookOrderCancel",
        "nativeBuildSignedOrderbookSettlementReceipt",
        "nativeValidatePdpPayloadJson",
        "nativeValidatePdpCommitmentChallengeJson",
        "nativeValidatePdpChallengeProofJson",
        "nativeValidatePdpBundleJson",
    ),
}
EXPECTED_SUFFIXES = tuple(
    f"{bridge}_{method}"
    for bridge, methods in EXPECTED_METHODS.items()
    for method in methods
)


EXPECTED_SDK_ONLY_SUFFIXES = tuple(
    "privacy_PrivacyNativeBridge_" + method
    for method in EXPECTED_METHODS["privacy_PrivacyNativeBridge"]
)
EXPECTED_COMMON_SUFFIXES = tuple(
    suffix for suffix in EXPECTED_SUFFIXES if suffix not in EXPECTED_SDK_ONLY_SUFFIXES
)
CONFIDENTIAL_PRIVACY_METHODS = (
    "nativeConfidentialDerivationContractRevisionV3",
    "nativeDefaultConfidentialDiversifierV3",
    "nativeDeriveConfidentialDiversifierV3",
    "nativeDeriveConfidentialOwnerTagV3",
    "nativeDeriveConfidentialAssetTagV3",
    "nativeDeriveConfidentialNetworkTagV3",
    "nativeDeriveConfidentialNoteCommitmentV3",
    "nativeDeriveConfidentialNullifierV3",
    "nativeDeriveConfidentialMerklePathV3",
    "nativeVerifyConfidentialMerklePathV3",
)
SDK_ONLY_MARKER = "// Canonical privacy JNI exports are owned only by the Kotlin SDK.\n"


def audit_confidential_source(source: str) -> None:
    """Require the exact sole Kotlin confidential JNI declaration inventory."""
    if "Java_org_hyperledger_iroha_android_privacy_PrivacyNativeBridge_" in source:
        raise AuditError("retired Android confidential privacy JNI owner is present")
    names = re.findall(r"Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_([A-Za-z0-9_]+)", source)
    if tuple(names) != CONFIDENTIAL_PRIVACY_METHODS:
        raise AuditError("canonical confidential privacy JNI inventory changed")


class AuditError(ValueError):
    """Raised when the current Kotlin JNI source contract is no longer exact."""


@dataclass(frozen=True)
class AuditResult:
    """Summary of the exact current Kotlin source inventory."""

    sdk_count: int
    privacy_count: int
    abi_digest: str
    attribute_digest: str
    governance_count: int
    governance_digest: str


def _skip_quoted(source: str, index: int) -> int | None:
    """Return the first byte after a Rust string or character literal."""

    raw_start = index
    if source.startswith("br", index):
        raw_start += 2
    elif source.startswith("r", index):
        raw_start += 1
    else:
        raw_start = -1
    if raw_start >= 0:
        hashes = 0
        while raw_start + hashes < len(source) and source[raw_start + hashes] == "#":
            hashes += 1
        quote = raw_start + hashes
        if quote < len(source) and source[quote] == '"':
            terminator = '"' + "#" * hashes
            end = source.find(terminator, quote + 1)
            if end < 0:
                raise AuditError("unterminated raw string while scanning JNI source")
            return end + len(terminator)
    if source[index] == '"':
        cursor = index + 1
        while cursor < len(source):
            if source[cursor] == "\\":
                cursor += 2
            elif source[cursor] == '"':
                return cursor + 1
            else:
                cursor += 1
        raise AuditError("unterminated string while scanning JNI source")
    if source[index] == "'":
        if index + 1 < len(source) and source[index + 1] == "\\":
            cursor = index + 2
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                elif source[cursor] == "'":
                    return cursor + 1
                else:
                    cursor += 1
            raise AuditError("unterminated character literal while scanning JNI source")
        if index + 2 < len(source) and source[index + 2] == "'":
            return index + 3
    return None


def _matching_brace(source: str, opening: int) -> int:
    """Find the closing brace while ignoring comments and quoted braces."""

    if opening >= len(source) or source[opening] != "{":
        raise AuditError("brace scanner did not start on an opening brace")
    depth = 0
    cursor = opening
    block_comment_depth = 0
    while cursor < len(source):
        if block_comment_depth:
            if source.startswith("/*", cursor):
                block_comment_depth += 1
                cursor += 2
            elif source.startswith("*/", cursor):
                block_comment_depth -= 1
                cursor += 2
            else:
                cursor += 1
            continue
        if source.startswith("//", cursor):
            newline = source.find("\n", cursor + 2)
            cursor = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", cursor):
            block_comment_depth = 1
            cursor += 2
            continue
        quoted_end = _skip_quoted(source, cursor)
        if quoted_end is not None:
            cursor = quoted_end
            continue
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor
            if depth < 0:
                break
        cursor += 1
    raise AuditError("unbalanced braces in paired JNI source")


def _attribute_text(fragment: str, platform: str) -> str:
    """Validate and canonicalize the attribute lines before one wrapper."""

    attributes = []
    for raw_line in fragment.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not (line.startswith("///") or (line.startswith("#[") and line.endswith("]"))):
            raise AuditError(f"unexpected {platform} wrapper preamble: {line}")
        if raw_line != line:
            raise AuditError(f"{platform} wrapper attributes must stay at item indentation")
        attributes.append(line + "\n")
    return "".join(attributes)


def _sdk_inventory(source: str) -> tuple[list[str], list[str], list[str]]:
    """Read the direct Kotlin declarations without expanding a legacy macro."""
    if ANDROID_PREFIX in source:
        raise AuditError("retired Android JNI owner is present")
    if "jni_sdk_android_pairs" in source or "android:" in source or "sdk:" in source:
        raise AuditError("retired paired JNI macro is present")
    if source.count(SDK_ONLY_MARKER) != 1:
        raise AuditError("canonical SDK-only privacy inventory changed")
    cursor = 0
    observed = []
    abi_records = []
    attributes = []
    for suffix in (*EXPECTED_COMMON_SUFFIXES, *EXPECTED_SDK_ONLY_SUFFIXES):
        if suffix == EXPECTED_SDK_ONLY_SUFFIXES[0]:
            marker = source.find(SDK_ONLY_MARKER, cursor)
            if marker < 0 or source[cursor:marker].strip():
                raise AuditError("canonical SDK-only privacy boundary changed")
            cursor = marker + len(SDK_ONLY_MARKER)
        item = source.find('pub unsafe extern "system" fn ', cursor)
        if item < 0:
            raise AuditError("canonical Kotlin JNI inventory changed")
        preamble = _attribute_text(source[cursor:item], "SDK")
        if preamble.count("#[unsafe(no_mangle)]\n") != 1:
            raise AuditError("SDK wrapper must retain exactly one unsafe no_mangle attribute")
        match = re.match(r'pub unsafe extern "system" fn (Java_org_hyperledger_iroha_sdk_[A-Za-z0-9_]+)\(', source[item:])
        expected = SDK_PREFIX + suffix
        if match is None or match.group(1) != expected or source.count(expected + "(") != 1:
            raise AuditError("canonical Kotlin JNI inventory changed")
        opening = source.find("{", item + match.end())
        closing = _matching_brace(source, opening)
        function = source[item:closing + 1]
        observed.append(suffix)
        abi_records.append(suffix + "\0" + function.replace(expected, "__JNI_EXPORT__", 1))
        attributes.append(suffix + "\0" + preamble)
        cursor = closing + 1
    governance_source = source[cursor:].strip()
    governance_names = re.findall(
        r'pub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_governance_ParliamentTimedOvnNativeEndpointV1_([A-Za-z0-9_]+)\(',
        governance_source,
    )
    governance_digest = hashlib.sha256(governance_source.encode()).hexdigest()
    if (tuple(governance_names) != EXPECTED_GOVERNANCE_METHODS
            or governance_digest != EXPECTED_GOVERNANCE_SOURCE_DIGEST):
        raise AuditError("unexpected source after the canonical Kotlin JNI inventory: "
                         "governance helper/signature/body contract changed")
    return observed, abi_records, attributes


def audit_source(source: str) -> AuditResult:
    """Require exact current ownership with unchanged Kotlin signatures and bodies."""
    observed, abi_records, attributes = _sdk_inventory(source)
    abi_digest = hashlib.sha256("\0\0".join(sorted(abi_records)).encode()).hexdigest()
    if abi_digest != EXPECTED_ABI_DIGEST:
        raise AuditError("Kotlin JNI signature/body contract changed: "
                         f"expected {EXPECTED_ABI_DIGEST}, found {abi_digest}")
    attribute_digest = hashlib.sha256("\0\0".join(sorted(attributes)).encode()).hexdigest()
    if attribute_digest != EXPECTED_ATTRIBUTE_DIGEST:
        raise AuditError("Kotlin JNI documentation/attribute contract changed: "
                         f"expected {EXPECTED_ATTRIBUTE_DIGEST}, found {attribute_digest}")
    return AuditResult(len(observed), len(EXPECTED_SDK_ONLY_SUFFIXES), abi_digest,
                       attribute_digest, len(EXPECTED_GOVERNANCE_METHODS), EXPECTED_GOVERNANCE_SOURCE_DIGEST)


def main() -> int:
    """Audit the repository JNI source and report the frozen inventory."""

    try:
        if JNI_SOURCE.is_symlink() or not JNI_SOURCE.is_file():
            raise AuditError(f"JNI source is unavailable: {JNI_SOURCE}")
        result = audit_source(JNI_SOURCE.read_text(encoding="utf-8"))
        confidential_source = JNI_SOURCE.parents[1] / "confidential_note_ffi.rs"
        if confidential_source.is_symlink() or not confidential_source.is_file():
            raise AuditError("confidential JNI source is unavailable")
        audit_confidential_source(confidential_source.read_text(encoding="utf-8"))
    except (AuditError, OSError, UnicodeError) as error:
        print(f"Kotlin JNI source guard failed: {error}", file=sys.stderr)
        return 1
    print(
        "Kotlin JNI source guard passed: "
        f"sdk={result.sdk_count} governance={result.governance_count} privacy={result.privacy_count} abi_sha256={result.abi_digest} "
        f"attributes_sha256={result.attribute_digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
