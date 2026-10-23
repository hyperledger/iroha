from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "check_privacy_exact12_sdk_manifest_parity.py"
SPEC = importlib.util.spec_from_file_location("privacy_exact12_sdk_manifest_parity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize("sdk", tuple(MODULE._CATALOG_CONSUMER_FILES))
def test_native_catalog_identity_requires_full_kat_and_current_width(
    monkeypatch: pytest.MonkeyPatch, sdk: str
) -> None:
    original_read = MODULE._read
    assert MODULE._native_catalog_identity(ROOT, sdk)
    rust = "crates/iroha_crypto/src/privacy.rs"
    model = "crates/iroha_data_model/src/privacy.rs"
    mutations = [
        (rust, "0x5b, 0xcf, 0x36, 0x6f", "0x5a, 0xcf, 0x36, 0x6f"),
        (rust, "PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1: [u8; 32]", "PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1: [u8; 48]"),
        (model, "PrivacyExact12CatalogCommitmentV1([u8; 32]);", "PrivacyExact12CatalogCommitmentV1([u8; 48]);"),
    ]
    paths = MODULE._CATALOG_CONSUMER_FILES[sdk]
    if sdk in ("javascript-napi", "python-pyo3"):
        mutations.append((paths[0], MODULE._NATIVE_CATALOG_HEX, "00" + MODULE._NATIVE_CATALOG_HEX[2:]))
    elif sdk == "jvm-android":
        mutations.extend([
            (paths[0], "0x5b, 0xcf.toByte(), 0x36", "0x5a, 0xcf.toByte(), 0x36"),
            (paths[1], "CATALOG_COMMITMENT_BYTES = 32", "CATALOG_COMMITMENT_BYTES = 48"),
        ])
    elif sdk == "swift":
        mutations.extend((path, "0x5b, 0xcf, 0x36", "0x5a, 0xcf, 0x36") for path in paths)
        mutations.extend((paths[0], f'maximum: 32,\n            label: "{label}"',
                          f'maximum: 48,\n            label: "{label}"')
                         for label in ("release catalog commitment", "security claim catalog commitment"))
    else:
        mutations.append((paths[0], MODULE._NATIVE_CATALOG_HEX.upper(), "00" + MODULE._NATIVE_CATALOG_HEX[2:].upper()))
    for relative, needle, replacement in mutations:
        original = original_read(ROOT, relative)
        assert needle in original
        with monkeypatch.context() as context:
            context.setattr(MODULE, "_read", lambda root, path: original.replace(needle, replacement)
                            if path == relative else original_read(root, path))
            assert MODULE._native_catalog_identity(ROOT, sdk) is False


@pytest.mark.parametrize("sdk", tuple(MODULE._CATALOG_CONSUMER_FILES))
def test_native_catalog_identity_refuses_missing_owner(tmp_path: Path, sdk: str) -> None:
    assert MODULE._native_catalog_identity(tmp_path, sdk) is False


def _minimal_safe_tree(tmp_path: Path) -> Path:
    exports = "\n".join(
        f'#[unsafe(no_mangle)] pub extern "C" fn {name}() {{}}'
        for name in sorted(MODULE.APPROVED_PRIVACY_EXPORTS)
    )
    _write(
        tmp_path / MODULE.RUST_BRIDGE,
        "mod platform_jni;\n"
        "compiled_privacy_profile_catalog_v1\n"
        "The catalog contains no committed height.\n"
        + exports,
    )
    _write(
        tmp_path / MODULE._RUST_BRIDGE_PLATFORM_JNI,
        "".join(
            f'include!("{path}");\n'
            for path in MODULE._RUST_BRIDGE_PLATFORM_JNI_INCLUDES
        ),
    )
    for path in MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS:
        _write(tmp_path / path, "// authenticated test bridge part\n")
    declarations = "\n".join(
        f"void {name}(void);" for name in sorted(MODULE.APPROVED_PRIVACY_EXPORTS)
    )
    _write(
        tmp_path / MODULE.C_HEADER,
        "The catalog contains no committed height.\n" + declarations,
    )
    _write(
        tmp_path / "crates/iroha_data_model/src/privacy/capability_manifest.rs",
        " ".join(
            (
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
        ),
    )
    _write(
        tmp_path / "crates/iroha_data_model/src/privacy/protocol.rs",
        "validate_privacy_capability_archive_v1",
    )
    _write(
        tmp_path / "crates/iroha_torii/src/runtime.rs",
        "exact12_capability_manifest_v1",
    )
    return tmp_path


def test_missing_sdk_paths_report_not_ready_but_remain_fail_closed(tmp_path: Path) -> None:
    report = MODULE.audit(_minimal_safe_tree(tmp_path))
    assert report["ready"] is False
    assert report["evidence_level"] == "source-prerequisite-not-native-release-authority"
    assert report["local_catalog_authorizes_network"] is False
    assert report["blockers"] == [contract.name for contract in MODULE.SDK_CONTRACTS]
    for result in report["sdk"].values():
        assert result["gates"]["fail_closed_without_admission"] is True


def test_unreviewed_privacy_export_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    bridge = root / MODULE.RUST_BRIDGE
    bridge.write_text(
        bridge.read_text(encoding="utf-8")
        + '\n#[unsafe(no_mangle)] pub extern "C" fn iroha_privacy_capabilities_v1() {}\n',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.AuditError, match="exact approved six"):
        MODULE.audit(root)


def test_missing_native_capability_validator_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    bridge = root / MODULE.RUST_BRIDGE
    bridge.write_text(
        bridge.read_text(encoding="utf-8").replace(
            '#[unsafe(no_mangle)] pub extern "C" fn '
            'iroha_privacy_validate_exact12_capability_manifest_v1() {}',
            '',
        ),
        encoding="utf-8",
    )
    with pytest.raises(MODULE.AuditError, match="exact approved six"):
        MODULE.audit(root)


@pytest.mark.parametrize(
    ("file_kind", "needle", "replacement"),
    (
        ("native", "RequireValidCapabilityArchive(snapshot);", "SkipEvidence(snapshot);"),
        ("native", "NativeValidateExact12CapabilityManifest(", "UncheckedManifestStatus("),
        ("native", "if (status != 0)", "if (status == 0)"),
        (
            "model",
            "PrivacyNative.RequireValidCapabilityArchive(archive);",
            "SkipEvidence(archive);",
        ),
    ),
)
def test_csharp_native_evidence_validation_cannot_be_removed(
    monkeypatch: pytest.MonkeyPatch, file_kind: str, needle: str, replacement: str
) -> None:
    contract = next(contract for contract in MODULE.SDK_CONTRACTS if contract.name == "csharp")
    sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in (*contract.model_files, *contract.native_files, *contract.transaction_files)
    }
    target = contract.native_files[0] if file_kind == "native" else contract.model_files[0]
    assert needle in sources[target]
    sources[target] = sources[target].replace(needle, replacement)
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    assert MODULE._sdk_result(ROOT, contract)["gates"]["native_canonical_manifest_validation"] is False


def test_incomplete_rust_bridge_platform_closure_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    platform_jni = root / MODULE._RUST_BRIDGE_PLATFORM_JNI
    platform_jni.write_text(
        'include!("platform_jni/part_1.rs");\n',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.AuditError, match="exact approved inventory"):
        MODULE.audit(root)


@pytest.mark.parametrize("part", MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS)
def test_bridge_part_cannot_hide_an_unreviewed_privacy_export(tmp_path: Path, part: str) -> None:
    root = _minimal_safe_tree(tmp_path)
    _write(
        root / part,
        '#[unsafe(no_mangle)] pub extern "C" fn iroha_privacy_unchecked_v1() {}\n',
    )
    with pytest.raises(MODULE.AuditError, match="exact approved six"):
        MODULE.audit(root)


def test_unreviewed_rust_bridge_include_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    platform_jni = root / MODULE._RUST_BRIDGE_PLATFORM_JNI
    platform_jni.write_text(
        platform_jni.read_text(encoding="utf-8") + 'include!("platform_jni/unchecked.rs");\n',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.AuditError, match="exact approved inventory"):
        MODULE.audit(root)


def test_retained_builder_without_admission_guard_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    transaction = root / MODULE.SDK_CONTRACTS[0].transaction_files[0]
    _write(transaction, "export function buildZkAmsTransaction() {}\n")
    with pytest.raises(MODULE.AuditError, match="without an Exact12 capability-admission guard"):
        MODULE.audit(root)


def test_retained_builder_with_explicit_admission_stays_fail_closed(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    transaction = root / MODULE.SDK_CONTRACTS[0].transaction_files[0]
    _write(
        transaction,
        "function requireExact12CapabilityAdmission() {}\n"
        "export function buildZkAmsTransaction() { "
        "requireExact12CapabilityAdmission(); }\n",
    )
    report = MODULE.audit(root)
    assert report["sdk"]["javascript-napi"]["gates"]["fail_closed_without_admission"]
    assert report["ready"] is False


def test_live_jvm_cutover_satisfies_strict_source_contract() -> None:
    gates = MODULE._jvm_cutover_gates(ROOT)
    assert gates == {
        "canonical_manifest_model": True,
        "native_canonical_manifest_validation": True,
        "exact_native_local_tuple_match": True,
        "transaction_admission_guard": True,
    }


def test_live_javascript_cutover_uses_only_authenticated_native_authority() -> None:
    gates = MODULE._javascript_cutover_gates(ROOT)
    assert gates == {
        "canonical_manifest_model": True,
        "native_canonical_manifest_validation": True,
        "exact_native_local_tuple_match": True,
        "transaction_admission_guard": True,
        "authenticated_native_authority": True,
        "browser_fail_closed": True,
    }


def test_live_python_pyo3_admission_is_included_in_source_parity() -> None:
    gates = MODULE._python_cutover_gates(ROOT)
    assert gates == {
        "canonical_manifest_model": True,
        "native_canonical_manifest_validation": True,
        "exact_native_local_tuple_match": True,
        "transaction_admission_guard": True,
    }
    report = MODULE.audit(ROOT)
    assert report["sdk"]["python-pyo3"]["ready"] is True


@pytest.mark.parametrize("sdk", tuple(MODULE._NETWORK_AUTHORITY_REQUIREMENTS))
def test_live_sdk_binds_transport_authority_to_expected_network(sdk: str) -> None:
    assert MODULE._authenticated_network_authority(ROOT, sdk) is True
    assert MODULE.audit(ROOT)["sdk"][sdk]["gates"]["authenticated_network_authority"] is True


@pytest.mark.parametrize(
    ("sdk", "relative", "needle", "replacement"),
    (
        ("javascript-napi", "javascript/iroha_js/src/privacyCapabilityTransport.js",
         "receipts.delete(receipt);", "// reusable receipt"),
        ("javascript-napi", "javascript/iroha_js/src/privacyCapabilityTransport.js",
         "const transport = transports.get(client);", "const transport = client.transport;"),
        ("javascript-napi", MODULE._JAVASCRIPT_CAPABILITIES,
         "protocolId, Uint8Array.from(state.expectedNetworkId)", "protocolId"),
        ("javascript-napi", "javascript/iroha_js/src/toriiClient.js",
         "responseRedirected || responseUrl !== expectedUrl", "false"),
        ("javascript-napi", "javascript/iroha_js/src/toriiClient.js",
         'const response = await this.#request("GET", "/v1/privacy/capabilities", {',
         'const response = await this._request("GET", "/v1/privacy/capabilities", {'),
        ("javascript-napi", "javascript/iroha_js/src/toriiClient.js",
         "await this.#expectStatus(response, [200], { signal });",
         "await this._expectStatus(response, [200], { signal });"),
        ("javascript-napi", "javascript/iroha_js/src/toriiClient.js",
         "const { bytes } = await this.#readBoundedResponseBytes(",
         "const { bytes } = await this._readBoundedResponseBytes("),
        ("javascript-napi", "javascript/iroha_js/src/toriiClient.js",
         "(auth, context) => ToriiClient.#normalizeCanonicalAuth(auth, context)",
         "(auth, context) => ToriiClient._normalizeCanonicalAuth(auth, context)"),
        ("javascript-napi", "crates/iroha_js_host/src/lib.rs",
         "if actual != expected || genesis_hash != expected.as_bytes()", "if false"),
        ("python-pyo3", MODULE._PYTHON_RUST_MANIFEST,
         "authenticated_network_id: None,", "authenticated_network_id: Some(network),"),
        ("python-pyo3", MODULE._PYTHON_RUST_MANIFEST,
         "if network_id != expected_network_id", "if false"),
        ("python-pyo3", MODULE._PYTHON_RUST_MANIFEST,
         'client.get_type().is(&owner.getattr("ToriiClient")?)', "true"),
        ("python-pyo3", MODULE._PYTHON_RUST_BRIDGE,
         "manifest.require_authenticated_network(self.network_id)?;", "// unbound builder"),
        ("python-pyo3", MODULE._PYTHON_CLIENT,
         "canonical_auth.network_id != expected_network.literal", "False"),
        ("jvm-android", MODULE._JVM_MODEL,
         "private val authenticatedNetworkId: NetworkId? = null,", "val authenticatedNetworkId: NetworkId? = null,"),
        ("jvm-android", MODULE._JVM_MODEL,
         "val networkId = manifest.requireAuthenticatedNetwork()", "val networkId = caller.networkId"),
        ("jvm-android", MODULE._JVM_KOTLIN_TRANSACTION_ADAPTER,
         "it.requirePrivacyExact12Network(value.networkId)", "Unit"),
        ("jvm-android", MODULE._JVM_KOTLIN_TRANSACTION_ADAPTER,
         "it.instruction.requirePrivacyExact12Network(value.networkId)", "Unit"),
        ("jvm-android", MODULE._JVM_KOTLIN_INSTRUCTION,
         "is WirePayload -> WireInstructionPayload(payload.wireName, payload.payloadBytes)", "is WirePayload -> payload"),
        ("jvm-android", MODULE._JVM_KOTLIN_TRANSPORT,
         "requireExactResponseProvenance = true,", "requireExactResponseProvenance = false,"),
        ("jvm-android", MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS[1],
         "genesis_hash == expected_network", "true"),
        ("jvm-android", MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS[2],
         "nativeRequireExact12CapabilityTupleForNetworkV1(", "nativeRequireExact12CapabilityTuple("),
        ("swift", MODULE._SWIFT_MODEL,
         "deployment.networkId == expectedNetworkId,", "true,"),
        ("swift", MODULE._SWIFT_MODEL,
         "deployment.genesisHash == expectedNetworkId.bytes else", "true else"),
        ("swift", MODULE._SWIFT_MODEL,
         "for index in 0..<13", "for index in 0..<11"),
        ("swift", MODULE._SWIFT_MODEL,
         "guard fields[0] == proofWireMagic, fields[1] == exact12CatalogCommitment else", "guard true else"),
        ("swift", MODULE._SWIFT_MODEL,
         "fields[11], protocolId: row.protocolId, expectedNetworkId: expectedNetworkId", "fields[11], protocolId: row.protocolId, expectedNetworkId: callerNetworkId"),
        ("swift", MODULE._SWIFT_ENCODER,
         "encodeBatchExecutable(entries, expectedNetworkId: networkId)", "encodeBatchExecutable(entries, expectedNetworkId: anotherNetwork)"),
        ("swift", MODULE._SWIFT_TORII,
         '"Cache-Control": "no-cache, no-store",', '"Cache-Control": "max-age=600",'),
        ("swift", MODULE._SWIFT_TORII,
         "request.cachePolicy = .reloadIgnoringLocalCacheData", "request.cachePolicy = .useProtocolCachePolicy"),
    ),
)
def test_sdk_origin_network_or_final_wire_regressions_fail_source_gate(
    monkeypatch: pytest.MonkeyPatch,
    sdk: str,
    relative: str,
    needle: str,
    replacement: str,
) -> None:
    original_read = MODULE._read
    original = original_read(ROOT, relative)
    assert needle in original
    monkeypatch.setattr(
        MODULE, "_read",
        lambda root, path: original.replace(needle, replacement)
        if path == relative else original_read(root, path),
    )
    assert MODULE._authenticated_network_authority(ROOT, sdk) is False


def test_javascript_offline_decoder_cannot_install_admission_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read = MODULE._read
    path = MODULE._JAVASCRIPT_CAPABILITIES
    source = original_read(ROOT, path)
    marker = "export async function getPrivacyExact12CapabilityManifestV1("
    assert marker in source
    source = source.replace(marker, "bindPrivacyExact12CapabilityAdmissionV1(archive);\n" + marker)
    monkeypatch.setattr(MODULE, "_read", lambda root, p: source if p == path else original_read(root, p))
    assert MODULE._authenticated_network_authority(ROOT, "javascript-napi") is False


@pytest.mark.parametrize(
    ("relative", "needle", "replacement", "failed_gate"),
    (
        (
            MODULE._JAVASCRIPT_CAPABILITIES,
            "native = getNativeBinding();",
            "native = globalThis.__IROHA_NATIVE_BINDING__ ?? getNativeBinding();",
            "authenticated_native_authority",
        ),
        (
            MODULE._JAVASCRIPT_CAPABILITIES,
            "native = getNativeBinding();",
            "native = fakeNativeBinding ?? getNativeBinding();",
            "authenticated_native_authority",
        ),
        (
            MODULE._JAVASCRIPT_NATIVE_BROWSER,
            "throw error;",
            "return globalThis.__IROHA_NATIVE_BINDING__;",
            "browser_fail_closed",
        ),
        (
            MODULE._JAVASCRIPT_NATIVE_BROWSER,
            "throw error;",
            "return {};",
            "browser_fail_closed",
        ),
        (
            MODULE._JAVASCRIPT_NATIVE_BROWSER,
            'nativeStatus: { value: "browser_unavailable", enumerable: true }',
            'nativeStatus: { value: "available", enumerable: true }',
            "browser_fail_closed",
        ),
        (
            MODULE._JAVASCRIPT_PACKAGE,
            '"./dist/native.js": "./dist/native.browser.js"',
            '"./dist/native.js": "./dist/native.js"',
            "browser_fail_closed",
        ),
        (
            MODULE._JAVASCRIPT_CAPABILITIES,
            "admitted !== true",
            "false",
            "exact_native_local_tuple_match",
        ),
    ),
)
def test_javascript_native_authority_regressions_fail_source_parity(
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    needle: str,
    replacement: str,
    failed_gate: str,
) -> None:
    paths = (
        MODULE._JAVASCRIPT_CAPABILITIES,
        MODULE._JAVASCRIPT_NATIVE,
        MODULE._JAVASCRIPT_NATIVE_BROWSER,
        MODULE._JAVASCRIPT_PACKAGE,
        MODULE._JAVASCRIPT_TRANSACTION,
        MODULE._JAVASCRIPT_TEST,
    )
    sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in paths}
    assert needle in sources[relative]
    sources[relative] = sources[relative].replace(needle, replacement)
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    assert MODULE._javascript_cutover_gates(ROOT)[failed_gate] is False


@pytest.mark.parametrize(
    ("relative", "needle", "replacement", "failed_gate"),
    (
        (
            MODULE._PYTHON_RUST_MANIFEST,
            "if !row.is_network_available()",
            "if false",
            "exact_native_local_tuple_match",
        ),
        (
            MODULE._PYTHON_RUST_BRIDGE,
            "manifest.require_network_profile(protocol_id)?",
            "drop(manifest);",
            "transaction_admission_guard",
        ),
        (
            MODULE._PYTHON_CRYPTO,
            "manifest = decoder(canonical)",
            "manifest = object()",
            "native_canonical_manifest_validation",
        ),
    ),
)
def test_python_pyo3_admission_regressions_fail_source_parity(
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    needle: str,
    replacement: str,
    failed_gate: str,
) -> None:
    paths = (
        MODULE._PYTHON_CRYPTO,
        MODULE._PYTHON_CLIENT,
        MODULE._PYTHON_TRANSACTION,
        MODULE._PYTHON_RUST_MANIFEST,
        MODULE._PYTHON_RUST_BRIDGE,
    )
    sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in paths}
    assert needle in sources[relative]
    sources[relative] = sources[relative].replace(needle, replacement)
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    assert MODULE._python_cutover_gates(ROOT)[failed_gate] is False


def test_live_swift_cutover_satisfies_strict_source_contract() -> None:
    gates = MODULE._swift_cutover_gates(ROOT)
    assert gates == {
        "canonical_manifest_model": True,
        "native_canonical_manifest_validation": True,
        "exact_native_local_tuple_match": True,
        "transaction_admission_guard": True,
    }


@pytest.mark.parametrize(
    ("relative", "needle", "replacement", "failed_gate"),
    (
        (
            MODULE._SWIFT_MODEL,
            "maxStatementAndEncryptedOutputBytesPerTransaction",
            "droppedConsensusField",
            "canonical_manifest_model",
        ),
        (
            MODULE._SWIFT_MODEL,
            "public let qualification: PrivacyExact12QualificationRecordV1?",
            "public let droppedQualification: PrivacyExact12QualificationRecordV1?",
            "canonical_manifest_model",
        ),
        (
            MODULE._SWIFT_BRIDGE,
            ".privacyExact12CapabilityManifestValidationStatusV1(archive)",
            ".uncheckedCapabilityManifestStatusV1(archive)",
            "native_canonical_manifest_validation",
        ),
        (
            MODULE._SWIFT_BRIDGE,
            "localCatalog = try compiledProfileCatalogV1()",
            "localCatalog = Data()",
            "native_canonical_manifest_validation",
        ),
        (
            MODULE._SWIFT_BRIDGE,
            "return try requireCompiledProfileCatalogV1(archive)",
            "return Data(archive)",
            "native_canonical_manifest_validation",
        ),
        (
            MODULE._SWIFT_MODEL,
            "guard compiledBytes == localCompiledProfile",
            "guard !compiledBytes.isEmpty",
            "exact_native_local_tuple_match",
        ),
        (
            MODULE._SWIFT_MODEL,
            "private static let authenticSeal",
            "public static let authenticSeal",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_MODEL,
            "fileprivate let authenticatedNetworkId: NetworkId?",
            "public var authenticatedNetworkId: NetworkId?",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_MODEL,
            "authenticatedNetworkId: NetworkId? = nil",
            "authenticatedNetworkId: NetworkId? = .unchecked",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_MODEL,
            "    static func fromAuthenticatedToriiResponseV1(",
            "    public static func fromAuthenticatedToriiResponseV1(",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_MODEL,
            "let validated = try PrivacyNativeBridge.validateExact12CapabilityManifestV1(archive)",
            "let validated = try uncheckedManifest(archive)",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_MODEL,
            "guard let expectedNetworkId = manifest.authenticatedNetworkId else {",
            "guard true else {",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TRANSACTION,
            "TransactionInstructionFrame: Equatable, Sendable",
            "TransactionInstructionFrame: Equatable, Codable, Sendable",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TRANSACTION,
            "wireName != PrivacyExact12FixtureCodecV1.submitProofWireId",
            "!wireName.isEmpty",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TRANSACTION,
            "PrivacyExact12CapabilityAdmissionV1.requireForConstruction(",
            "acceptWithoutExact12Admission(",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TORII,
            "_ = try PrivacyNativeBridge.compiledProfileCatalogV1()",
            "// native preflight removed",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TORII,
            "guard let declaredLength = try Self.validatedContentLength(",
            "guard let declaredLength = try uncheckedContentLength(",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TORII,
            "declaredLength > 0, declaredLength == data.count",
            "declaredLength > 0",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_TORII,
            "return try PrivacyExact12CapabilityManifestV1.fromAuthenticatedToriiResponseV1(",
            "return try PrivacyNativeBridge.validateExact12CapabilityManifestV1(data)",
            "transaction_admission_guard",
        ),
        (
            MODULE._SWIFT_ENCODER,
            "try frame.compactInstructionBoxPayload(expectedNetworkId: expectedNetworkId)",
            "frame.framedPayload",
            "transaction_admission_guard",
        ),
    ),
)
def test_swift_cutover_hostile_source_regressions_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    needle: str,
    replacement: str,
    failed_gate: str,
) -> None:
    paths = (
        MODULE._SWIFT_MODEL,
        MODULE._SWIFT_BRIDGE,
        MODULE._SWIFT_NATIVE,
        MODULE._SWIFT_TRANSACTION,
        MODULE._SWIFT_ENCODER,
        MODULE._SWIFT_TORII,
        MODULE._SWIFT_TEST,
    )
    sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in paths}
    assert needle in sources[relative]
    sources[relative] = sources[relative].replace(needle, replacement)
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    assert MODULE._swift_cutover_gates(ROOT)[failed_gate] is False


@pytest.mark.parametrize(
    ("relative", "needle", "replacement", "failed_gate"),
    (
        (
            MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS[1],
            "committed.compiled_profile == local.compiled_profile",
            "committed.compiled_profile != local.compiled_profile",
            "exact_native_local_tuple_match",
        ),
        (
            MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS[1],
            "validate_privacy_capability_archive_v1(archive)",
            "accept_unchecked_privacy_capability_archive_v1(archive)",
            "native_canonical_manifest_validation",
        ),
        (
            MODULE._JVM_MODEL,
            "canonicalArchive.copyOf()",
            "canonicalArchive",
            "canonical_manifest_model",
        ),
        (
            MODULE._JVM_MODEL,
            "require(row.isNetworkAvailable())",
            "check(true)",
            "transaction_admission_guard",
        ),
        (
            MODULE._JVM_KOTLIN_TRANSPORT,
            "class HttpClientTransport private constructor(",
            "// PrivacyCapabilitySnapshotJsonV1\nclass HttpClientTransport private constructor(",
            "transaction_admission_guard",
        ),
        (
            MODULE._JVM_KOTLIN_TRANSACTION_ADAPTER,
            "value.requirePrivacyExact12ConstructionAdmission()",
            "Unit",
            "transaction_admission_guard",
        ),
    ),
)
def test_jvm_cutover_hostile_source_regressions_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    needle: str,
    replacement: str,
    failed_gate: str,
) -> None:
    sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in (
            MODULE._JVM_MODEL,
            MODULE._JVM_KOTLIN_BRIDGE,
            MODULE._JVM_KOTLIN_TRANSPORT,
            MODULE._JVM_JAVA_TRANSPORT,
            MODULE._JVM_KOTLIN_INSTRUCTION,
            MODULE._JVM_KOTLIN_TRANSACTION_ADAPTER,
            MODULE._JVM_JAVA_INSTRUCTION,
            MODULE._JVM_JAVA_TRANSACTION_ADAPTER,
            *MODULE._RUST_BRIDGE_SOURCE_FILES,
        )
    }
    assert needle in sources[relative]
    sources[relative] = sources[relative].replace(needle, replacement)
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    assert MODULE._jvm_cutover_gates(ROOT)[failed_gate] is False


@pytest.mark.parametrize(
    ("file_kind", "needle", "replacement"),
    (
        ("model", "client.Options.NetworkId ?? throw", "guessedNetworkId ?? throw"),
        ("model", "decoded.Qualification, expectedNetworkId", "decoded.Qualification, guessedNetworkId"),
        ("model", "|| !NetworkId.Equals(expectedNetworkId)", "|| false"),
        ("model", "PrivacyNative.RequireValidCapabilityArchive(manifestArchive);", "SkipEvidence(manifestArchive);"),
        ("model", "if (!genesisHash.SequenceEqual(networkId.AsSpan()))", "if (false)"),
        ("model", "if (!qualification.DeploymentQualification.NetworkId.Equals(expectedNetworkId))", "if (false)"),
        ("transaction", "RequireForConstruction(admission, protocol, NetworkId)", "RequireForConstruction(admission, protocol, guessedNetworkId)"),
    ),
)
def test_csharp_authenticated_network_boundary_cannot_be_removed(
    monkeypatch: pytest.MonkeyPatch, file_kind: str, needle: str, replacement: str
) -> None:
    contract = next(contract for contract in MODULE.SDK_CONTRACTS if contract.name == "csharp")
    sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in (*contract.model_files, *contract.native_files, *contract.transaction_files)
    }
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    assert MODULE._sdk_result(ROOT, contract)["gates"]["authenticated_network_authority"] is True
    target = contract.model_files[0] if file_kind == "model" else contract.transaction_files[0]
    assert needle in sources[target]
    sources[target] = sources[target].replace(needle, replacement)
    assert MODULE._sdk_result(ROOT, contract)["gates"]["authenticated_network_authority"] is False


def test_live_c_privacy_inventory_matches_its_single_approved_owner() -> None:
    MODULE._require_exact_abi31(ROOT)
    assert len(MODULE.APPROVED_PRIVACY_EXPORTS) == 6


def test_missing_c_capability_validator_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    header = root / MODULE.C_HEADER
    declaration = "void iroha_privacy_validate_exact12_capability_manifest_v1(void);"
    assert declaration in header.read_text()
    header.write_text(header.read_text().replace(declaration, ""), encoding="utf-8")
    with pytest.raises(MODULE.AuditError, match="C ABI31.*exact approved six"):
        MODULE._require_exact_abi31(root)


def test_unapproved_c_privacy_export_is_rejected(tmp_path: Path) -> None:
    root = _minimal_safe_tree(tmp_path)
    header = root / MODULE.C_HEADER
    header.write_text(header.read_text() + "\nvoid iroha_privacy_unapproved_v1(void);\n", encoding="utf-8")
    with pytest.raises(MODULE.AuditError, match="C ABI31.*exact approved six"):
        MODULE._require_exact_abi31(root)


@pytest.mark.parametrize("mutation", ("java-owner", "android-export", "kotlin-validator", "java-transport-owner", "java-id-owner"))
def test_jvm_canonical_owner_regressions_fail_source_parity(tmp_path, monkeypatch, mutation):
    sources = {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in (
            MODULE._JVM_MODEL, MODULE._JVM_KOTLIN_BRIDGE,
            MODULE._JVM_KOTLIN_TRANSPORT, MODULE._JVM_JAVA_TRANSPORT,
            MODULE._JVM_KOTLIN_INSTRUCTION, MODULE._JVM_KOTLIN_TRANSACTION_ADAPTER,
            MODULE._JVM_JAVA_INSTRUCTION, MODULE._JVM_JAVA_TRANSACTION_ADAPTER,
            MODULE._RUST_BRIDGE_PLATFORM_JNI_PARTS[1],
        )
    }
    bridge = MODULE._rust_bridge_source(ROOT)
    monkeypatch.setattr(MODULE, "_read", lambda _root, path: sources.get(path, ""))
    monkeypatch.setattr(MODULE, "_rust_bridge_source", lambda _root: bridge)
    assert all(MODULE._jvm_cutover_gates(tmp_path).values())
    failed_gate = "native_canonical_manifest_validation"
    if mutation == "java-owner":
        _write(tmp_path / MODULE._RETIRED_JVM_JAVA_BRIDGE, "retired owner")
    elif mutation == "android-export":
        bridge += "\nJava_org_hyperledger_iroha_android_privacy_PrivacyNativeBridge_nativeBridgeAbiVersion"
    elif mutation == "kotlin-validator":
        key = MODULE._JVM_KOTLIN_BRIDGE
        sources[key] = sources[key].replace("nativeValidateExact12CapabilityManifestForNetworkV1", "uncheckedManifest")
    else:
        failed_gate = "transaction_admission_guard"
        key = MODULE._JVM_JAVA_TRANSPORT if mutation == "java-transport-owner" else MODULE._JVM_JAVA_INSTRUCTION
        sources[key] = sources[key].replace("org.hyperledger.iroha.sdk.privacy.", "org.hyperledger.iroha.android.privacy.")
    assert MODULE._jvm_cutover_gates(tmp_path)[failed_gate] is False
