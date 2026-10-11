#!/usr/bin/env python3
"""Audit fail-closed Exact12 capability-manifest admission across SDKs.

ABI25 intentionally has exactly six privacy C exports. Its no-argument
compiled-profile getter can expose only immutable local build metadata; it
cannot manufacture Torii's committed height, lifecycle, or registered release
and network qualification. The capability-manifest validator accepts only
caller-supplied canonical bytes and verifies their complete signed evidence.
Consequently an SDK is release-ready only when it preserves Torii's canonical
manifest bytes, validates them, and compares the selected row's complete
compiled-profile tuple with the native local catalog before constructing a
privacy transaction.

The default mode reports source readiness without weakening the build.  Pass
``--require-ready`` as a prerequisite in a qualification lane to fail until
every SDK has the complete admission path.  This source audit is never native
execution evidence or release authority.  Structural safety violations always
fail, including an unreviewed ABI export or a retained-protocol builder which lacks
an explicit capability-admission guard.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


APPROVED_PRIVACY_EXPORTS = frozenset(
    {
        "iroha_privacy_compiled_profile_catalog_v1",
        "iroha_privacy_validate_compiled_profile_catalog_v1",
        "iroha_privacy_exact12_fixture_bundle_v1",
        "iroha_privacy_validate_exact12_fixture_bundle_v1",
        "iroha_privacy_validate_exact12_capability_manifest_v1",
        "iroha_privacy_free_buffer",
    }
)

RUST_BRIDGE = "crates/connect_norito_bridge/src/lib.rs"
_RUST_BRIDGE_PLATFORM_JNI = "crates/connect_norito_bridge/src/platform_jni.rs"
_RUST_BRIDGE_PLATFORM_JNI_PARTS = (
    "crates/connect_norito_bridge/src/platform_jni/part_1.rs",
    "crates/connect_norito_bridge/src/platform_jni/part_2.rs",
    "crates/connect_norito_bridge/src/platform_jni/part_3.rs",
    "crates/connect_norito_bridge/src/platform_jni/private_settlement.rs",
)
_RUST_BRIDGE_SOURCE_FILES = (
    RUST_BRIDGE,
    _RUST_BRIDGE_PLATFORM_JNI,
    *_RUST_BRIDGE_PLATFORM_JNI_PARTS,
)
_RUST_BRIDGE_PLATFORM_JNI_INCLUDES = (
    "platform_jni/part_1.rs",
    "platform_jni/part_2.rs",
    "platform_jni/part_3.rs",
    "platform_jni/private_settlement.rs",
)
C_HEADER = "crates/connect_norito_bridge/include/connect_norito_bridge.h"
_JAVASCRIPT_CAPABILITIES = "javascript/iroha_js/src/privacyCapabilities.js"
_JAVASCRIPT_NATIVE = "javascript/iroha_js/src/native.js"
_JAVASCRIPT_NATIVE_BROWSER = "javascript/iroha_js/src/native.browser.js"
_JAVASCRIPT_PACKAGE = "javascript/iroha_js/package.json"
_JAVASCRIPT_TRANSACTION = "javascript/iroha_js/src/transaction.js"
_JAVASCRIPT_TEST = (
    "javascript/iroha_js/test/privacyExact12CapabilityManifest.test.js"
)
_PYTHON_CRYPTO = "python/iroha_python/src/iroha_python/crypto.py"
_PYTHON_CLIENT = "python/iroha_python/src/iroha_python/client.py"
_PYTHON_TRANSACTION = "python/iroha_python/src/iroha_python/tx.py"
_PYTHON_RUST_MANIFEST = (
    "python/iroha_python/iroha_python_rs/src/privacy_capability_manifest.rs"
)
_PYTHON_RUST_BRIDGE = "python/iroha_python/iroha_python_rs/src/lib.rs"


class AuditError(RuntimeError):
    """The source tree violates a fail-closed release invariant."""


@dataclass(frozen=True)
class SdkContract:
    name: str
    model_files: tuple[str, ...]
    native_files: tuple[str, ...]
    transaction_files: tuple[str, ...]
    manifest_markers: tuple[str, ...]
    native_markers: tuple[str, ...]
    tuple_markers: tuple[str, ...]


SDK_CONTRACTS = (
    SdkContract(
        "javascript-napi",
        (_JAVASCRIPT_CAPABILITIES,),
        (
            _JAVASCRIPT_NATIVE,
            _JAVASCRIPT_CAPABILITIES,
            "crates/iroha_js_host/src/lib.rs",
        ),
        (_JAVASCRIPT_TRANSACTION,),
        (
            "PrivacyExact12CapabilityManifestV1",
            "manifest_digest",
            "operation_schema",
            "execution_mode",
            "privacy_feature_mask",
            "qualification",
            "parsePrivacyExact12QualificationV1",
        ),
        (
            "privacyValidateExact12CapabilityManifestV1",
            "validate_privacy_capability_archive_v1",
        ),
        ("requirePrivacyExact12CapabilityTupleV1", "compiledProfileCatalogV1"),
    ),
    SdkContract(
        "python-pyo3",
        (_PYTHON_CRYPTO, _PYTHON_RUST_MANIFEST),
        (_PYTHON_CRYPTO, _PYTHON_RUST_MANIFEST, _PYTHON_RUST_BRIDGE),
        (_PYTHON_CLIENT, _PYTHON_TRANSACTION, _PYTHON_RUST_BRIDGE),
        (
            "PrivacyExact12CapabilityManifestV1",
            "canonical_archive",
            "manifest_digest",
            "operation_schema",
            "execution_mode",
            "privacy_feature_mask",
            "ProductionQualified",
        ),
        (
            "privacy_validate_exact12_capability_manifest_v1",
            "validate_privacy_capability_archive_v1",
        ),
        ("require_network_profile", "compiled_privacy_profile_v1"),
    ),
    SdkContract(
        "jvm-android",
        (
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/PrivacyCapabilitiesV1.kt",
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/PrivacyExact12CapabilityManifestV1.kt",
        ),
        (
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/PrivacyNativeBridge.kt",
            *_RUST_BRIDGE_SOURCE_FILES,
        ),
        (
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/client/HttpClientTransport.kt",
            "java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/HttpClientTransport.java",
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/InstructionBox.kt",
            "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/tx/norito/TransactionPayloadAdapter.kt",
            "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/InstructionBox.java",
            "java/iroha_android/src/main/java/org/hyperledger/iroha/android/norito/TransactionPayloadAdapter.java",
        ),
        (
            "PrivacyExact12CapabilityManifestV1",
            "manifestDigest",
            "operationSchema",
            "executionMode",
            "privacyFeatureMask",
            "qualification",
            "PrivacyExact12QualificationRecordV1",
        ),
        (
            "nativeValidateExact12CapabilityManifest",
            "validate_privacy_capability_archive_v1",
        ),
        ("requireExact12CapabilityTupleV1", "compiledProfileCatalogTypedV1"),
    ),
    SdkContract(
        "csharp",
        (
            "csharp/src/Hyperledger.Iroha.Sdk/Privacy/PrivacyExact12CapabilityManifestV1.cs",
        ),
        ("csharp/src/Hyperledger.Iroha.Sdk/Privacy/PrivacyNative.cs",),
        (
            "csharp/src/Hyperledger.Iroha.Sdk/Transactions/TransactionBuilder.cs",
        ),
        (
            "PrivacyExact12CapabilityManifestV1",
            "ManifestDigest",
            "OperationSchema",
            "ExecutionMode",
            "PrivacyFeatureMask",
            "Qualification",
            "PrivacyExact12QualificationRecordV1",
        ),
        (
            "ValidateExact12CapabilityManifestV1",
            "ValidateCompiledProfileCatalogV1",
            "iroha_privacy_validate_exact12_capability_manifest_v1",
        ),
        ("RequireExact12CapabilityTupleV1", "CompiledProfileCatalogV1"),
    ),
    SdkContract(
        "swift",
        (
            "IrohaSwift/Sources/IrohaSwift/PrivacyExact12CapabilityManifestV1.swift",
        ),
        (
            "IrohaSwift/Sources/IrohaSwift/PrivacyNativeBridge.swift",
            "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift",
        ),
        ("IrohaSwift/Sources/IrohaSwift/TxBuilder.swift",),
        (
            "PrivacyExact12CapabilityManifestV1",
            "manifestDigest",
            "operationSchema",
            "executionMode",
            "privacyFeatureMask",
            "qualification",
            "PrivacyExact12QualificationRecordV1",
        ),
        ("validateExact12CapabilityManifestV1", "validateCompiledProfileCatalogV1"),
        ("requireExact12CapabilityTupleV1", "compiledProfileCatalogV1"),
    ),
)

_RETAINED_BUILDER = re.compile(
    r"\b(?:build|construct|sign|submit)\w*"
    r"(?:Exact12|ZkAce|AnonymousPgc|VeRange|ZkAms|ZkX509|Jindo|"
    r"Bootle|Lantern|Orchard|Fcmp|PrivateNote|PqMasp)\w*\b",
    re.IGNORECASE,
)
_ADMISSION_MARKER = re.compile(r"Exact12Capability(?:Tuple)?Admission", re.IGNORECASE)

_JVM_MODEL = (
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/"
    "PrivacyExact12CapabilityManifestV1.kt"
)
_JVM_KOTLIN_BRIDGE = (
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/PrivacyNativeBridge.kt"
)
_RETIRED_JVM_JAVA_BRIDGE = (
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/privacy/"
    "PrivacyNativeBridge.java"
)
_JVM_KOTLIN_TRANSPORT = (
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/client/HttpClientTransport.kt"
)
_JVM_JAVA_TRANSPORT = (
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/"
    "HttpClientTransport.java"
)
_JVM_KOTLIN_INSTRUCTION = (
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/core/model/InstructionBox.kt"
)
_JVM_KOTLIN_TRANSACTION_ADAPTER = (
    "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/tx/norito/"
    "TransactionPayloadAdapter.kt"
)
_JVM_JAVA_INSTRUCTION = (
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/model/InstructionBox.java"
)
_JVM_JAVA_TRANSACTION_ADAPTER = (
    "java/iroha_android/src/main/java/org/hyperledger/iroha/android/norito/"
    "TransactionPayloadAdapter.java"
)
_SWIFT_MODEL = "IrohaSwift/Sources/IrohaSwift/PrivacyExact12CapabilityManifestV1.swift"
_SWIFT_BRIDGE = "IrohaSwift/Sources/IrohaSwift/PrivacyNativeBridge.swift"
_SWIFT_NATIVE = "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
_SWIFT_TRANSACTION = "IrohaSwift/Sources/IrohaSwift/TxBuilder.swift"
_SWIFT_ENCODER = "IrohaSwift/Sources/IrohaSwift/TransactionEncoder.swift"
_SWIFT_TORII = "IrohaSwift/Sources/IrohaSwift/ToriiClient.swift"
_SWIFT_TEST = (
    "IrohaSwift/Tests/IrohaSwiftTests/PrivacyExact12CapabilityManifestV1Tests.swift"
)

# These source prerequisites pin the transport-to-construction authority chain.
# They do not certify cryptographic execution, caller-provided transport code,
# or freshness beyond the authenticated response and final ledger admission.
_NETWORK_AUTHORITY_REQUIREMENTS = {
    "javascript-napi": {
        "javascript/iroha_js/src/privacyCapabilityTransport.js": (
            "const transports = new WeakMap();",
            "const receipts = new WeakMap();",
            "const transport = transports.get(client);",
            "receipts.delete(receipt);",
        ),
        _JAVASCRIPT_CAPABILITIES: (
            "const transport = consumePrivacyExact12CapabilityManifestTransportV1(receipt);",
            "state.expectedNetworkId = Uint8Array.from(transport.expectedNetworkId);",
            "byte === qualification.genesis_hash[index]",
            "protocolId, Uint8Array.from(state.expectedNetworkId)",
        ),
        "javascript/iroha_js/src/toriiClient.js": (
            "registerPrivacyExact12CapabilityManifestTransportV1(",
            'origin.protocol !== "https:"',
            "this._localSigningContext?.networkId,",
            'redirect: "error",',
            'cache: "no-store",',
            "responseRedirected || responseUrl !== expectedUrl",
            'const response = await this.#request("GET", "/v1/privacy/capabilities", {',
            "await this.#expectStatus(response, [200], { signal });",
            "const { bytes } = await this.#readBoundedResponseBytes(",
            "(auth, context) => ToriiClient.#normalizeCanonicalAuth(auth, context)",
        ),
        "crates/iroha_js_host/src/lib.rs": (
            "expected_network_id: Uint8Array,",
            "require_privacy_exact12_network_v1(",
            "if actual != expected || genesis_hash != expected.as_bytes()",
        ),
    },
    "python-pyo3": {
        _PYTHON_RUST_MANIFEST: (
            "authenticated_network_id: Option<NetworkId>",
            "authenticated_network_id: None,",
            "fn from_authenticated_torii(archive: &[u8], expected_network_id: NetworkId)",
            "qualification.deployment_qualification.network_id != expected_network_id",
            "decoded.authenticated_network_id = Some(expected_network_id);",
            "if network_id != expected_network_id",
            'client.get_type().is(&owner.getattr("ToriiClient")?)',
            '.getattr("_fetch_authenticated_privacy_capabilities_archive_v1")?',
            ".call1((client, canonical_auth))?",
        ),
        _PYTHON_CLIENT: (
            "if type(client) is not ToriiClient:",
            "client._require_local_signing_context(context).network_id",
            'urlparse(client._base_url).scheme != "https"',
            "canonical_auth.network_id != expected_network.literal",
            'response.url != f"{client._base_url}/v1/privacy/capabilities" or response.history',
            '"Cache-Control": "no-store",',
            "_read_bounded_response_body(response, 256 * 1024, context)",
        ),
        _PYTHON_RUST_BRIDGE: (
            "manifest.require_authenticated_network(self.network_id)?;",
        ),
    },
    "jvm-android": {
        _JVM_MODEL: (
            "class PrivacyExact12CapabilityManifestV1 private constructor(",
            "private val authenticatedNetworkId: NetworkId? = null,",
            "@JvmSynthetic\n        internal fun fromAuthenticatedTorii(",
            "val networkId = manifest.requireAuthenticatedNetwork()",
            "require(expectedNetworkId == networkId)",
            "admission.expectedNetworkId,",
        ),
        _JVM_KOTLIN_TRANSPORT: (
            'require(config.baseUri().scheme == "https")',
            "val expectedNetworkId = config.requireLocalSigningContext().networkId()",
            "requestNoStore = true,",
            "requireExactResponseProvenance = true,",
            "PrivacyExact12CapabilityManifestV1.fromAuthenticatedTorii(archive, expectedNetworkId)",
        ),
        _JVM_KOTLIN_TRANSACTION_ADAPTER: (
            "it.requirePrivacyExact12Network(value.networkId)",
            "it.instruction.requirePrivacyExact12Network(value.networkId)",
        ),
        _JVM_KOTLIN_INSTRUCTION: (
            "is WirePayload -> WireInstructionPayload(payload.wireName, payload.payloadBytes)",
        ),
        _RUST_BRIDGE_PLATFORM_JNI_PARTS[1]: (
            "if !java_privacy_manifest_network_matches(&manifest, expected_network)",
            "network.as_bytes() == expected_network",
            "genesis_hash == expected_network",
            ".context()\n            .network_id\n            .as_bytes()\n            == expected_network",
        ),
        _RUST_BRIDGE_PLATFORM_JNI_PARTS[2]: (
            "nativeValidateExact12CapabilityManifestForNetworkV1(",
            "nativeRequireExact12CapabilityTupleForNetworkV1(",
            "nativeValidateExact12SubmitProofConstructionForNetworkV1(",
        ),
    },
    "swift": {
        _SWIFT_MODEL: (
            "fileprivate let authenticatedNetworkId: NetworkId?",
            "authenticatedNetworkId: NetworkId? = nil",
            "guard let expectedNetworkId = manifest.authenticatedNetworkId else",
            "networkId == expectedNetworkId else",
            "deployment.networkId == expectedNetworkId,",
            "deployment.genesisHash == expectedNetworkId.bytes else",
            "guard genesisHash.count == 32, genesisHash == networkId.bytes else",
            "for index in 0..<13",
            "guard fields[0] == proofWireMagic, fields[1] == exact12CatalogCommitment else",
            "fields[11], protocolId: row.protocolId, expectedNetworkId: expectedNetworkId",
        ),
        _SWIFT_TORII: (
            "guard let localSigningContext else",
            "data, expectedNetworkId: localSigningContext.networkId",
            "response.url?.absoluteString == request.url?.absoluteString",
            "let request = try makePrivacyExact12CapabilityRequestV1(canonicalAuth: canonicalAuth)",
        ),
        _SWIFT_TRANSACTION: (
            "guard let privacyProtocolId, let privacyAdmission, let expectedNetworkId else",
            "expectedNetworkId: expectedNetworkId,",
        ),
        _SWIFT_ENCODER: (
            "encodeBatchExecutable(entries, expectedNetworkId: networkId)",
            "frame.compactInstructionBoxPayload(expectedNetworkId: expectedNetworkId)",
        ),
    },
}


def _authenticated_network_authority(root: Path, sdk: str) -> bool:
    """Reject source drift in the sealed transport and expected-network path."""

    required = _NETWORK_AUTHORITY_REQUIREMENTS[sdk]
    if not all(
        marker in _read(root, path)
        for path, markers in required.items()
        for marker in markers
    ):
        return False
    if sdk == "javascript-napi":
        source = _read(root, _JAVASCRIPT_CAPABILITIES)
        decoder = source[source.find("export function decodePrivacyExact12CapabilityManifestV1("):
                         source.find("export async function getPrivacyExact12CapabilityManifestV1(")]
        return bool(decoder) and "bindPrivacyExact12CapabilityAdmissionV1(" not in decoder
    if sdk == "python-pyo3":
        return _read(root, _PYTHON_RUST_BRIDGE).count(
            "manifest.require_authenticated_network(self.network_id)?;"
        ) >= 2
    if sdk == "jvm-android":
        bridge = _read(root, _RUST_BRIDGE_PLATFORM_JNI_PARTS[2])
        return not re.search(
            r"_native(?:ValidateExact12CapabilityManifest|RequireExact12CapabilityTuple|"
            r"ValidateExact12SubmitProofConstruction)\(",
            bridge,
        )
    if sdk == "swift":
        source = _read(root, _SWIFT_TORII)
        start = source.find("    func makePrivacyExact12CapabilityRequestV1(")
        end = _swift_member_end(source, start)
        request = source[start:end] if 0 <= start < end else ""
        return all(marker in request for marker in (
            '"Cache-Control": "no-cache, no-store",',
            "request.cachePolicy = .reloadIgnoringLocalCacheData",
            "try applyCanonicalAuth(canonicalAuth, to: &request, body: nil)",
        ))
    return True


_SWIFT_MEMBER_FUNCTION = re.compile(
    r"^    (?:(?:public|private|fileprivate|internal)\s+)?(?:static\s+)?func\s", re.M
)


def _swift_member_end(source: str, start: int) -> int:
    """Return the offset of the member function declared after ``start``, or -1."""
    if start < 0:
        return -1
    match = _SWIFT_MEMBER_FUNCTION.search(source, start + 1)
    return match.start() if match else -1


def _read(root: Path, relative: str) -> str:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _combined(root: Path, files: Iterable[str]) -> str:
    return "\n".join(_read(root, relative) for relative in files)


def _read_required_source(root: Path, relative: str) -> str:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise AuditError(f"required Rust bridge source is unavailable: {relative}")
    return _read(root, relative)


def _rust_bridge_source(root: Path) -> str:
    """Read the exact split Rust bridge closure after authenticating its includes."""

    bridge = _read_required_source(root, RUST_BRIDGE)
    if len(re.findall(r"^mod platform_jni;$", bridge, flags=re.MULTILINE)) != 1:
        raise AuditError("Rust bridge must own exactly one platform_jni module")
    platform_jni = _read_required_source(root, _RUST_BRIDGE_PLATFORM_JNI)
    observed_includes = tuple(
        re.findall(r'^include!\("([^"]+)"\);$', platform_jni, flags=re.MULTILINE)
    )
    if observed_includes != _RUST_BRIDGE_PLATFORM_JNI_INCLUDES:
        raise AuditError(
            "Rust bridge platform_jni include closure differs from the exact "
            f"approved inventory: found {observed_includes}"
        )
    parts = tuple(
        _read_required_source(root, path) for path in _RUST_BRIDGE_PLATFORM_JNI_PARTS
    )
    return "\n".join((bridge, platform_jni) + parts)


def _rust_exports(source: str) -> frozenset[str]:
    return frozenset(
        re.findall(
            r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(iroha_privacy_[A-Za-z0-9_]+)',
            source,
        )
    )


def _header_exports(source: str) -> frozenset[str]:
    return frozenset(
        re.findall(
            r"\b(iroha_privacy_[A-Za-z0-9_]+)\s*\(",
            re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.DOTALL),
        )
    )


def _require_exact_abi25(root: Path) -> None:
    rust = _rust_exports(_rust_bridge_source(root))
    header = _header_exports(_read(root, C_HEADER))
    if rust != APPROVED_PRIVACY_EXPORTS:
        raise AuditError(
            "Rust ABI25 privacy exports differ from the exact approved six: "
            f"found {sorted(rust)}"
        )
    if header != APPROVED_PRIVACY_EXPORTS:
        raise AuditError(
            "C ABI25 privacy declarations differ from the exact approved six: "
            f"found {sorted(header)}"
        )


def _require_authority_boundary(root: Path) -> None:
    bridge = _rust_bridge_source(root)
    header = _read(root, C_HEADER)
    combined = bridge + "\n" + header
    forbidden = (
        "iroha_privacy_capabilities_v1",
        "iroha_privacy_validate_capabilities_v1",
        "iroha_privacy_exact12_capability_manifest_v1",
    )
    if any(symbol in combined for symbol in forbidden):
        raise AuditError("ABI25 added a capability authority getter or retired alias")
    if "compiled_privacy_profile_catalog_v1" not in bridge:
        raise AuditError("ABI25 local catalog is no longer derived from native Rust profiles")
    if "contains no committed height" not in combined.lower():
        raise AuditError("ABI25 local catalog lost its explicit non-authority contract")


def _require_rust_manifest_contract(root: Path) -> None:
    model = _read(root, "crates/iroha_data_model/src/privacy/capability_manifest.rs")
    protocol = _read(root, "crates/iroha_data_model/src/privacy/protocol.rs")
    torii = _read(root, "crates/iroha_torii/src/runtime.rs")
    required = (
        "PrivacyExact12CapabilityManifestV1",
        "manifest_digest",
        "operation_schema",
        "execution_mode",
        "privacy_feature_mask",
        "readiness",
        "PrivacyCapabilityUnavailableReasonV1",
        "qualification",
        "PrivacyExact12QualificationRecordV1",
        "InvalidProductionQualification",
    )
    if not all(marker in model for marker in required):
        raise AuditError("Rust canonical Exact12 manifest contract is incomplete")
    if "validate_privacy_capability_archive_v1" not in protocol:
        raise AuditError("Rust canonical Exact12 manifest archive validator is absent")
    if "exact12_capability_manifest_v1" not in torii:
        raise AuditError("Torii does not project committed state into the Exact12 manifest")
    if "production_qualification" in model:
        raise AuditError("Rust Exact12 activation still carries caller-owned qualification")


def _javascript_cutover_gates(root: Path) -> dict[str, bool]:
    """Require Exact12 to use only the authenticated N-API loader."""

    capabilities = _read(root, _JAVASCRIPT_CAPABILITIES)
    native = _read(root, _JAVASCRIPT_NATIVE)
    native_browser = _read(root, _JAVASCRIPT_NATIVE_BROWSER)
    package = _read(root, _JAVASCRIPT_PACKAGE)
    transaction = _read(root, _JAVASCRIPT_TRANSACTION)
    tests = _read(root, _JAVASCRIPT_TEST)
    authority_start = capabilities.find("function requirePrivacyExact12NativeV1()")
    authority_end = capabilities.find(
        "function callPrivacyExact12NativeV1(", authority_start
    )
    authority = (
        capabilities[authority_start:authority_end]
        if authority_start >= 0 and authority_end > authority_start
        else ""
    )
    browser_start = native_browser.find("export function getNativeBinding()")
    browser_end = native_browser.find(
        "/**\n * Native binding verification", browser_start
    )
    browser_loader = (
        native_browser[browser_start:browser_end]
        if browser_start >= 0 and browser_end > browser_start
        else ""
    )

    canonical_model = all(
        marker in capabilities
        for marker in (
            "class PrivacyExact12CapabilityManifestV1",
            "PRIVACY_EXACT12_MANIFEST_CONSTRUCTOR",
            "privacyExact12ManifestState",
            "canonicalArchive: Uint8Array.from(canonicalArchive)",
            "manifest_digest",
            "operation_schema",
            "execution_mode",
            "privacy_feature_mask",
            "qualification",
            "parsePrivacyExact12QualificationV1",
            "invalid-production-qualification",
            "missing-production-qualification",
        )
    )
    authenticated_native_authority = all(
        (
            'import { getNativeBinding } from "./native.js";' in capabilities,
            "native = getNativeBinding();" in authority,
            authority.count("getNativeBinding()") == 1,
            authority.count("native =") == 1,
            authority.count("return native;") == 1,
            "??" not in authority,
            "globalThis" not in authority,
            "__IROHA_NATIVE_BINDING__" not in capabilities,
            "verifyNativeBindingInternal(" in native,
            "assertLoadableSourceProvenance(" in native,
            "materializeVerifiedSnapshot(" in native,
            "cachedBinding = require(snapshot.path)" in native,
        )
    )
    native_validation = authenticated_native_authority and all(
        marker in capabilities + "\n" + native
        for marker in (
            "privacyValidateExact12CapabilityManifestV1",
            "privacyExact12CapabilityManifestJsonV1",
            "privacyRequireExact12CapabilityTupleV1",
            "requires exact ABI25",
        )
    )
    exact_tuple_match = all(
        marker in capabilities
        for marker in (
            "readiness !== \"production-qualified\"",
            "manifest.qualification === null",
            "qualificationMatchesCapabilityRowV1",
            "row.compiled_profile.status !== \"available\"",
            "compiledProfileCatalogFromNativeV1(native)",
            '"privacyRequireExact12CapabilityTupleV1"',
            "admitted !== true",
        )
    )
    transaction_admission = all(
        (
            "bindPrivacyExact12CapabilityAdmissionV1(" in capabilities,
            "admitPrivacyExact12CapabilityTupleV1(manifest, protocolId)" in capabilities,
            "privacyExact12ManifestState.get(manifest)" in capabilities,
            "requirePrivacyExact12CapabilityAdmissionV1" in transaction,
        )
    )
    browser_binding_match = re.search(
        r"^export function getNativeBinding\(\) \{(?P<body>.*?)^\}",
        browser_loader,
        flags=re.MULTILINE | re.DOTALL,
    )
    browser_binding = browser_binding_match.group("body") if browser_binding_match else ""
    browser_fail_closed = all(
        (
            '"./dist/native.js": "./dist/native.browser.js"' in package,
            bool(browser_binding),
            "const error = new Error(" in browser_binding,
            'code: { value: "ERR_IROHA_NATIVE_BINDING", enumerable: true }' in browser_binding,
            'nativeStatus: { value: "browser_unavailable", enumerable: true }' in browser_binding,
            "throw error;" in browser_binding,
            "return" not in browser_binding,
            "globalThis" not in browser_loader,
            "mutable global bindings cannot authorize Exact12 native admission" in tests,
            "browser Exact12 exports fail closed even when a fake global binding exists"
            in tests,
        )
    )
    return {
        "canonical_manifest_model": canonical_model,
        "native_canonical_manifest_validation": native_validation,
        "exact_native_local_tuple_match": exact_tuple_match,
        "transaction_admission_guard": transaction_admission,
        "authenticated_native_authority": authenticated_native_authority,
        "browser_fail_closed": browser_fail_closed,
    }


def _python_cutover_gates(root: Path) -> dict[str, bool]:
    """Include the Python/PyO3 admission path in Exact12 source parity."""

    crypto = _read(root, _PYTHON_CRYPTO)
    client = _read(root, _PYTHON_CLIENT)
    transaction = _read(root, _PYTHON_TRANSACTION)
    manifest = _read(root, _PYTHON_RUST_MANIFEST)
    bridge = _read(root, _PYTHON_RUST_BRIDGE)

    canonical_model = all(
        marker in crypto + "\n" + manifest
        for marker in (
            "PyPrivacyExact12CapabilityManifestV1",
            "canonical_archive",
            "manifest_digest",
            "protocol_tuples",
            "operation_schema",
            "execution_mode",
            "privacy_feature_mask",
            "ProductionQualified",
            "MissingProductionQualification",
        )
    )
    native_validation = all(
        (
            "_crypto = load_crypto_extension()" in crypto,
            "if not _has_privacy_bridge_abi(_crypto):" in crypto,
            "privacy_validate_exact12_capability_manifest_v1(canonical)" in crypto,
            "manifest = decoder(canonical)" in crypto,
            "if bytes(returned) != canonical:" in crypto,
            "validate_privacy_capability_archive_v1(archive)" in manifest,
            "canonical_archive.as_slice() != archive" in manifest,
        )
    )
    exact_tuple_match = all(
        marker in manifest
        for marker in (
            "if !row.is_network_available()",
            "compiled_privacy_profile_v1(protocol_id)",
            "if network_profile != local_snapshot",
            "self.require_network_profile(protocol_id)?",
        )
    )
    transaction_admission = all(
        (
            "manifest must be a native PrivacyExact12CapabilityManifestV1" in transaction,
            "builder.bind_privacy_exact12_capability_manifest_v1(" in transaction,
            "Option<privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1>"
            in bridge,
            "manifest.require_network_profile(protocol_id)?" in bridge,
            "requires a validated Torii Exact12 capability manifest" in bridge,
            "PyRef<'_, privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1>"
            in bridge,
            '"Accept": "application/x-norito"' in client,
            'response.headers.get("Content-Type") != "application/x-norito"' in client,
            "_fetch_privacy_exact12_capability_manifest_v1(" in client,
        )
    )
    return {
        "canonical_manifest_model": canonical_model,
        "native_canonical_manifest_validation": native_validation,
        "exact_native_local_tuple_match": exact_tuple_match,
        "transaction_admission_guard": transaction_admission,
    }


def _jvm_cutover_gates(root: Path) -> dict[str, bool]:
    """Audit the JVM cutover's authority-bearing statements, not documentation markers."""

    model = _read(root, _JVM_MODEL)
    kotlin_bridge = _read(root, _JVM_KOTLIN_BRIDGE)
    rust_bridge = _rust_bridge_source(root)
    rust_manifest_admission = _read(root, _RUST_BRIDGE_PLATFORM_JNI_PARTS[1])
    kotlin_transport = _read(root, _JVM_KOTLIN_TRANSPORT)
    java_transport = _read(root, _JVM_JAVA_TRANSPORT)
    kotlin_instruction = _read(root, _JVM_KOTLIN_INSTRUCTION)
    kotlin_adapter = _read(root, _JVM_KOTLIN_TRANSACTION_ADAPTER)
    java_instruction = _read(root, _JVM_JAVA_INSTRUCTION)
    java_adapter = _read(root, _JVM_JAVA_TRANSACTION_ADAPTER)
    transports = kotlin_transport + "\n" + java_transport

    canonical_model = all(
        marker in model
        for marker in (
            "class PrivacyExact12CapabilityManifestV1 private constructor",
            "canonicalArchive.copyOf()",
            "fun canonicalBytes(): ByteArray = archive.copyOf()",
            "protocols.size == expected.size",
            "row.protocolId == expected[index]",
            "PrivacyOperationSchemaV1",
            "PrivacyExecutionModeV1",
            "privacyFeatureMask",
            "compiledProfile",
            "manifestDigest",
            "PrivacySecurityModelV1",
            "PrivacySecurityClaimV1",
            "PrivacyExact12QualificationRecordV1",
            "PrivacyExact12ReleaseManifestV1",
            "PrivacyExact12DeploymentQualificationV1",
            "qualificationMatchesCapabilityRowV1",
            "ProductionQualified",
            "MissingProductionQualification",
            "InvalidProductionQualification",
        )
    ) and all(
        retired not in model
        for retired in (
            "PrivacyProtocolProductionQualificationV1",
            "productionQualification",
            '"production_qualification"',
        )
    )
    native_validation = all(
        (
            "nativeValidateExact12CapabilityManifestForNetworkV1" in kotlin_bridge,
            "nativeInspectExact12CapabilityManifest" in kotlin_bridge,
            "check(nativeAvailable)" in kotlin_bridge,
            not (root / _RETIRED_JVM_JAVA_BRIDGE).exists(),
            "if !validate_privacy_capability_archive_v1(archive).is_valid()"
            in rust_manifest_admission,
            "PrivacyExact12CapabilityManifestV1>(archive)" in rust_bridge,
            "Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_"
            "nativeValidateExact12CapabilityManifestForNetworkV1" in rust_bridge,
            "Java_org_hyperledger_iroha_android_privacy_PrivacyNativeBridge_" not in rust_bridge,
        )
    )
    exact_tuple_match = all(
        (
            "committed.protocol_id == local.protocol_id" in rust_bridge,
            "committed.compiled_profile == local.compiled_profile" in rust_bridge,
            '"local_compiled_tuple_matches"' in rust_bridge,
            "require(row.localCompiledTupleMatches)" in model,
            "compiledProfileCatalogTypedV1" in model,
        )
    )
    admission_guard = all(
        (
            "class PrivacyExact12CapabilityTupleAdmissionV1 private constructor" in model,
            "private val SEAL = Any()" in model,
            "require(row.isNetworkAvailable())" in model,
            "fun requireForConstruction(" in model,
            "PrivacyNativeBridge.requireExact12CapabilityTuple(" in model,
            "PrivacyNativeBridge.requireExact12SubmitProofConstruction(" in model,
            "nativeRequireExact12CapabilityTupleForNetworkV1" in kotlin_bridge,
            "nativeValidateExact12SubmitProofConstructionForNetworkV1" in kotlin_bridge,
            "import org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1;" in java_instruction,
            "import org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridge;" in java_transport,
            "import org.hyperledger.iroha.sdk.privacy.PrivacyProtocolIdV1;" in java_transport,
            "fromPrivacyExact12WirePayload" in kotlin_instruction,
            "requirePrivacyExact12ConstructionAdmission" in kotlin_instruction,
            "value.requirePrivacyExact12ConstructionAdmission()" in kotlin_adapter,
            "fromPrivacyExact12WirePayload" in java_instruction,
            "requirePrivacyExact12ConstructionAdmission" in java_instruction,
            "value.requirePrivacyExact12ConstructionAdmission();" in java_adapter,
            "requirePrivacyExact12CapabilityAdmission" in kotlin_transport,
            "requirePrivacyExact12CapabilityAdmission" in java_transport,
            "buildExactNoritoGetRequest(" in kotlin_transport,
            "buildExactNoritoGetRequest(" in java_transport,
            "PrivacyExact12CapabilityManifestV1.fromAuthenticatedTorii(archive, expectedNetworkId)" in kotlin_transport,
            "PrivacyNativeBridge::decodeExact12CapabilityManifestV1" in java_transport,
            "application/x-norito" in kotlin_transport,
            "application/x-norito" in java_transport,
            "PrivacyCapabilitySnapshotJsonV1" not in transports,
        )
    )
    return {
        "canonical_manifest_model": canonical_model,
        "native_canonical_manifest_validation": native_validation,
        "exact_native_local_tuple_match": exact_tuple_match,
        "transaction_admission_guard": admission_guard,
    }


def _swift_cutover_gates(root: Path) -> dict[str, bool]:
    """Audit Swift's canonical Rust validator and mandatory local catalog anchor.

    The manifest validator must authenticate the complete signed qualification
    before managed projection. Every fetch, admission, construction, and final
    encode also re-enters native validation before exact tuple comparison.
    """

    model = _read(root, _SWIFT_MODEL)
    bridge = _read(root, _SWIFT_BRIDGE)
    native = _read(root, _SWIFT_NATIVE)
    transaction = _read(root, _SWIFT_TRANSACTION)
    encoder = _read(root, _SWIFT_ENCODER)
    torii = _read(root, _SWIFT_TORII)
    tests = _read(root, _SWIFT_TEST)
    admission_start = model.find(
        "public final class PrivacyExact12CapabilityTupleAdmissionV1"
    )
    admission_end = model.find(
        "/// The sole path from a committed manifest",
        admission_start,
    )
    admission = (
        model[admission_start:admission_end]
        if admission_start >= 0 and admission_end > admission_start
        else ""
    )
    origin_factory_start = model.find("    static func fromAuthenticatedToriiResponseV1(")
    origin_factory_end = model.find("    public func canonicalBytes()", origin_factory_start)
    origin_factory = (
        model[origin_factory_start:origin_factory_end]
        if origin_factory_start >= 0 and origin_factory_end > origin_factory_start
        else ""
    )
    network_admission_start = model.find("    public static func requireExact12CapabilityTupleV1(")
    network_admission_end = model.find("        let row = current.row(", network_admission_start)
    network_admission = (
        model[network_admission_start:network_admission_end]
        if network_admission_start >= 0 and network_admission_end > network_admission_start
        else ""
    )
    fetch_start = torii.find("    public func getPrivacyExact12CapabilityManifestV1(")
    fetch_end = _swift_member_end(
        torii, torii.find("    func makePrivacyExact12CapabilityRequestV1(", fetch_start)
    )
    fetch = (
        torii[fetch_start:fetch_end]
        if fetch_start >= 0 and fetch_end > fetch_start
        else ""
    )

    canonical_model = all(
        marker in model
        for marker in (
            "public final class PrivacyExact12CapabilityManifestV1",
            "fileprivate init(",
            "private let archive: Data",
            "public func canonicalBytes() -> Data",
            "PrivacyConsensusPolicyV1",
            "maxActionsPerTransaction",
            "maxActionsPerBlock",
            "maxProofBytesPerAction",
            "maxActionBytes",
            "maxPrivacyBytesPerTransaction",
            "maxPrivacyBytesPerBlock",
            "maxStatementAndEncryptedOutputBytesPerTransaction",
            "maxNullifiersPerAction",
            "maxCommitmentsPerAction",
            "retainedRootCount",
            "pendingTightening",
            "PrivacyProtocolActivationRecordV1",
            "proofSystemId",
            "engineId",
            "parameterId",
            "parameterDigest",
            "verifierDigest",
            "statementSchemaDigest",
            "engineManifestDigest",
            "lifecycle",
            "protocolLimits",
            "pendingProtocolLimitsTightening",
            "public let qualification: PrivacyExact12QualificationRecordV1?",
            "PrivacySecurityModelV1",
            "PrivacySecurityClaimV1",
            "PrivacyExact12QualificationRecordV1",
            "PrivacyExact12ReleaseManifestV1",
            "PrivacyExact12DeploymentQualificationV1",
            "qualificationMatches(",
            "missingProductionQualification",
            "invalidProductionQualification",
            "productionQualified",
            "canonicalNorito",
            "protocols must contain exactly 12 rows",
            "protocol rows are missing, duplicated, or reordered",
            "manifest digest does not bind the canonical archive",
            "strictFrame(",
        )
    ) and all(
        retired not in model
        for retired in (
            "PrivacyProtocolProductionQualificationV1",
            "productionQualification",
        )
    )
    native_backed_validation = all(
        (
            "validateExact12CapabilityManifestV1" in bridge,
            ".privacyExact12CapabilityManifestValidationStatusV1(archive)" in bridge,
            "guard status == 0 else" in bridge,
            "localCatalog = try compiledProfileCatalogV1()" in bridge,
            "let archive = try NoritoNativeBridge.shared.privacyCompiledProfileCatalogV1()"
            in bridge,
            "return try requireCompiledProfileCatalogV1(archive)" in bridge,
            "privacyCompiledProfileCatalogValidationStatusV1(archive)" in bridge,
            "PrivacyExact12CapabilityManifestCodecV1.decode(" in bridge,
            "privacyCompiledProfileCatalogV1()" in bridge,
            "requiredBridgeABIVersion: UInt32 = 25" in bridge,
            "loadedBridgeAbiVersion == PrivacyNativeBridge.requiredBridgeABIVersion"
            in native,
            "privacyNativeProbeOk" in native,
            all(symbol in native for symbol in APPROVED_PRIVACY_EXPORTS),
        )
    )
    exact_tuple_match = all(
        marker in model
        for marker in (
            "guard compiledBytes == localCompiledProfile",
            "activation proof system differs from the compiled tuple",
            "profile.engineManifestDigest",
            "guard binding == expectedBindings[index]",
            "submit-proof envelope differs from the admitted compiled profile tuple",
            "PrivacyNativeBridge.validateExact12CapabilityManifestV1(",
            "row.localCompiledTupleMatches",
        )
    )
    transaction_admission = all(
        (
            "private init(" in admission,
            "private static let authenticSeal" in admission,
            not re.search(r"\b(?:Codable|Decodable)\b", admission),
            "public static func requireExact12CapabilityTupleV1" in model,
            "fileprivate let authenticatedNetworkId: NetworkId?" in model,
            "authenticatedNetworkId: NetworkId? = nil" in model,
            "let validated = try PrivacyNativeBridge.validateExact12CapabilityManifestV1(archive)"
            in origin_factory,
            "authenticatedNetworkId: expectedNetworkId" in origin_factory,
            re.search(
                r"guard let expectedNetworkId = manifest\.authenticatedNetworkId else\s*\{\s*"
                r"throw PrivacyExact12CapabilityManifestErrorV1\.invalidAdmission\s*\}",
                network_admission,
            )
            is not None,
            model.count("PrivacyNativeBridge.validateExact12CapabilityManifestV1(") >= 2,
            re.search(
                r"public struct TransactionInstructionFrame:[^\n]*"
                r"\b(?:Codable|Decodable)\b",
                transaction,
            )
            is None,
            "wireName != PrivacyExact12FixtureCodecV1.submitProofWireId" in transaction,
            "public static func privacyExact12SubmitProof" in transaction,
            "private let privacyAdmission" in transaction,
            "func compactInstructionBoxPayload(expectedNetworkId: NetworkId? = nil) throws" in transaction,
            transaction.count(
                "PrivacyExact12CapabilityAdmissionV1.requireForConstruction("
            ) >= 2,
            "try frame.compactInstructionBoxPayload(expectedNetworkId: expectedNetworkId)" in encoder,
            "canonicalAuth: ToriiCanonicalRequestAuth" in fetch,
            'baseURL.scheme?.lowercased() == "https"' in fetch,
            'path: "/v1/privacy/capabilities"' in fetch,
            "try applyCanonicalAuth(canonicalAuth" in fetch,
            "_ = try PrivacyNativeBridge.compiledProfileCatalogV1()" in fetch,
            'contentType == "application/x-norito"' in fetch,
            "return try PrivacyExact12CapabilityManifestV1.fromAuthenticatedToriiResponseV1("
            in fetch,
            "ToriiRejectRedirectTaskDelegate.shared" in torii,
            "let (data, response) = try await sendBoundedResponse(" in fetch,
            "guard let declaredLength = try Self.validatedContentLength(" in fetch,
            "maximumBytes: PrivacyExact12CapabilityManifestV1.maximumArchiveBytes" in fetch,
            "declaredLength > 0, declaredLength == data.count" in fetch,
            "testEveryTruncationAndOneByteSuffixFailClosed" in tests,
            "testGenericInstructionConstructionCannotBypassPrivacyAdmission" in tests,
        )
    )
    return {
        "canonical_manifest_model": canonical_model,
        "native_canonical_manifest_validation": native_backed_validation,
        "exact_native_local_tuple_match": exact_tuple_match,
        "transaction_admission_guard": transaction_admission,
    }


def _sdk_result(root: Path, contract: SdkContract) -> dict[str, object]:
    model = _combined(root, contract.model_files)
    native = _combined(root, contract.native_files)
    transactions = _combined(root, contract.transaction_files)
    manifest_model = all(marker in model for marker in contract.manifest_markers)
    native_validation = all(marker in native for marker in contract.native_markers)
    tuple_match = all(marker in model + "\n" + native for marker in contract.tuple_markers)
    transaction_admission = bool(_ADMISSION_MARKER.search(transactions))
    extra_gates: dict[str, bool] = {}
    if contract.name in _NETWORK_AUTHORITY_REQUIREMENTS:
        extra_gates["authenticated_network_authority"] = (
            _authenticated_network_authority(root, contract.name)
        )
    if contract.name == "javascript-napi" and _read(root, _JAVASCRIPT_CAPABILITIES):
        javascript = _javascript_cutover_gates(root)
        manifest_model = manifest_model and javascript["canonical_manifest_model"]
        native_validation = (
            native_validation
            and javascript["native_canonical_manifest_validation"]
        )
        tuple_match = tuple_match and javascript["exact_native_local_tuple_match"]
        transaction_admission = javascript["transaction_admission_guard"]
        extra_gates.update({
            "authenticated_native_authority": javascript[
                "authenticated_native_authority"
            ],
            "browser_fail_closed": javascript["browser_fail_closed"],
        })
    if contract.name == "python-pyo3" and _read(root, _PYTHON_RUST_MANIFEST):
        python = _python_cutover_gates(root)
        manifest_model = manifest_model and python["canonical_manifest_model"]
        native_validation = python["native_canonical_manifest_validation"]
        tuple_match = tuple_match and python["exact_native_local_tuple_match"]
        transaction_admission = python["transaction_admission_guard"]
    if contract.name == "jvm-android":
        jvm = _jvm_cutover_gates(root)
        manifest_model = manifest_model and jvm["canonical_manifest_model"]
        native_validation = (
            native_validation and jvm["native_canonical_manifest_validation"]
        )
        tuple_match = tuple_match and jvm["exact_native_local_tuple_match"]
        transaction_admission = (
            transaction_admission and jvm["transaction_admission_guard"]
        )
    if contract.name == "swift":
        swift = _swift_cutover_gates(root)
        manifest_model = manifest_model and swift["canonical_manifest_model"]
        native_validation = (
            native_validation and swift["native_canonical_manifest_validation"]
        )
        tuple_match = tuple_match and swift["exact_native_local_tuple_match"]
        transaction_admission = (
            transaction_admission and swift["transaction_admission_guard"]
        )
    if contract.name == "csharp":
        evidence_start = native.find("internal static void RequireValidCapabilityArchive(")
        evidence_end = native.find("    [DllImport(", evidence_start)
        evidence_validation = (
            native[evidence_start:evidence_end]
            if evidence_start >= 0 and evidence_end > evidence_start
            else ""
        )
        native_validation = native_validation and all(
            marker in evidence_validation
            for marker in (
                "NativeValidateExact12CapabilityManifest(",
                "if (status != 0)",
                "The mandatory native Exact12 capability validator is unavailable.",
            )
        ) and (
            "RequireValidCapabilityArchive(snapshot);" in native
            and "PrivacyNative.RequireValidCapabilityArchive(archive);" in model
        )
        manifest_model = manifest_model and all(
            marker in model
            for marker in (
                "ParseQualificationOption(",
                "QualificationMatches(",
                "InvalidProductionQualification",
            )
        ) and all(
            retired not in model
            for retired in (
                "ValidateProductionQualificationOption",
                "HasProductionQualification",
            )
        )
        fetch_start = model.find("    internal static async Task<PrivacyExact12CapabilityManifestV1> FetchAuthenticatedToriiAsync(")
        fetch_end = model.find("    private static void RequireExactNoritoContentType(", fetch_start)
        fetch = model[fetch_start:fetch_end] if fetch_start >= 0 and fetch_end > fetch_start else ""
        token_start = model.find("public sealed class PrivacyExact12CapabilityTupleAdmissionV1")
        token_end = model.find("public static class PrivacyExact12CapabilityAdmissionV1", token_start)
        token = model[token_start:token_end] if token_start >= 0 and token_end > token_start else ""
        extra_gates["authenticated_network_authority"] = all((
            "private PrivacyExact12CapabilityManifestV1(" in model,
            "public NetworkId NetworkId { get; }" in model,
            "client.Options.NetworkId ?? throw" in fetch,
            "decoded.Qualification, expectedNetworkId" in fetch,
            "private readonly byte[] manifestArchive;" in token,
            "private readonly object seal;" in token,
            "decoded.Qualification, manifest.NetworkId, requireQualification: true" in token,
            "|| !NetworkId.Equals(expectedNetworkId)" in token,
            "decoded.Qualification, expectedNetworkId, requireQualification: true" in token,
            "PrivacyNative.RequireValidCapabilityArchive(manifestArchive);" in token,
            "PrivacyNative.CompiledProfileCatalogV1().NoritoBytes" in token,
            "if (!genesisHash.SequenceEqual(networkId.AsSpan()))" in model,
            "if (!qualification.DeploymentQualification.NetworkId.Equals(expectedNetworkId))" in model,
            "admission.RequireAuthentic(protocol, expectedNetworkId);" in model,
            "internal void RequireExact12CapabilityAdmission(" in transactions,
            "RequireForConstruction(admission, protocol, NetworkId)" in transactions,
        ))
    retained_builders = sorted(set(_RETAINED_BUILDER.findall(transactions)))
    fail_closed = not retained_builders or transaction_admission
    if not fail_closed:
        raise AuditError(
            f"{contract.name} exposes a retained-protocol builder without an "
            "Exact12 capability-admission guard"
        )
    gates = {
        "canonical_manifest_model": manifest_model,
        "native_canonical_manifest_validation": native_validation,
        "exact_native_local_tuple_match": tuple_match,
        "transaction_admission_guard": transaction_admission,
        "fail_closed_without_admission": fail_closed,
        **extra_gates,
    }
    blockers = [name for name, passed in gates.items() if not passed]
    return {
        "ready": not blockers,
        "gates": gates,
        "blockers": blockers,
    }


def audit(root: Path) -> dict[str, object]:
    root = root.resolve()
    _require_exact_abi25(root)
    _require_authority_boundary(root)
    _require_rust_manifest_contract(root)
    sdks = {contract.name: _sdk_result(root, contract) for contract in SDK_CONTRACTS}
    blockers = [name for name, result in sdks.items() if not result["ready"]]
    return {
        "schema_version": 1,
        "evidence_level": "source-prerequisite-not-native-release-authority",
        "abi25_privacy_exports": sorted(APPROVED_PRIVACY_EXPORTS),
        "authority": "torii-committed-canonical-manifest-bytes",
        "local_catalog_authorizes_network": False,
        "ready": not blockers,
        "sdk": sdks,
        "blockers": blockers,
    }


def _format_human(report: dict[str, object]) -> str:
    lines = [
        "Exact12 cross-SDK capability-manifest parity: "
        + ("READY" if report["ready"] else "NOT READY"),
        "ABI25 privacy exports: exact six",
        "Network authority: Torii committed canonical manifest bytes",
    ]
    sdks = report["sdk"]
    assert isinstance(sdks, dict)
    for name, result in sdks.items():
        assert isinstance(result, dict)
        state = "ready" if result["ready"] else "blocked"
        lines.append(f"- {name}: {state}")
        for blocker in result["blockers"]:
            lines.append(f"  - missing {blocker}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = audit(args.root)
    except AuditError as error:
        print(f"privacy Exact12 SDK manifest safety violation: {error}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(_format_human(report))
    return 1 if args.require_ready and not report["ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
