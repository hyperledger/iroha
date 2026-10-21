#!/usr/bin/env python3
"""Original Android demo provenance remains bound during explicit HEAD drift."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'android_device_demo', ROOT / 'scripts/mobile_sdk_android_device_demo.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ORIGINAL_COMMIT = 'a' * 40
NEW_HEAD = 'b' * 40


class DeviceDemoHeadDriftTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='android-demo-provenance.')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'source'
        self.artifact = self.base / 'qualified'
        self.producer = self.base / 'producer'
        self.ndk = self.base / 'ndk'
        for path in (self.root, self.artifact, self.producer, self.ndk):
            path.mkdir(mode=0o700)
        self.write(self.root / 'kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/crypto/NativeSignerBridge.kt',
                   b'external fun inspect(input: ByteArray): ByteArray\n')
        self.write(self.ndk / 'source.properties', b'Pkg.Revision = 28.0.12674087\n')
        self.strip = self.ndk / 'toolchains/llvm/prebuilt/fixture/bin/llvm-strip'
        self.nm = self.strip.with_name('llvm-nm')
        self.write(self.strip, b'fixture strip tool\n')
        self.write(self.nm, b'fixture symbol tool\n')
        raw = bytearray(256)
        raw[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQIHHHHHH', raw, 16,
                         3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, 256, 256, 16384)
        self.raw = bytes(raw)
        self.native = self.raw + b'canonical-strip-fixture'
        self.promoted = self.producer / 'gradle-build/iroha_kotlin_sdk/client-android/native/cargo-ndk/production/arm64-v8a/libconnect_norito_bridge.so'
        self.write(self.promoted, self.raw)
        self.write(self.artifact / MODULE.RAW, self.raw)
        self.write(self.artifact / MODULE.LIB, self.native)
        docs = {
            'source-seal.json': {
                'schema': 'iroha.norito-bridge-source-seal.v1', 'platform': 'android',
                'source_commit': ORIGINAL_COMMIT, 'source_fingerprint_sha256': 'c' * 64},
            'build-environment.json': {
                'environment_profile': 'android-cargo', 'cargo_build_jobs': 1,
                'rust_toolchain_channel': '1.93.1', 'wallet_runtime_authority': 'fixture-authority',
                'wallet_runtime_trust_ed25519_hex': 'd' * 64,
                'android_ndk_source_properties_sha256': MODULE.digest((self.ndk / 'source.properties').read_bytes())},
            'producer-receipt.json': {
                'status': 'running', 'sourceCommit': ORIGINAL_COMMIT,
                'sourceRoot': str(self.root), 'artifactRoot': str(self.producer)},
            'compiler-command.json': {
                'sourceCommit': ORIGINAL_COMMIT, 'target': MODULE.TARGET,
                'argv': ['rustc', '--crate-name', 'connect_norito_bridge']},
            'cabi-receipt.json': {
                'status': 'passed', 'exitCode': 0, 'serial': 'fixture-device',
                'inputs': {str(self.promoted): MODULE.digest(self.raw)},
                'currentDtoFieldCompatible': True, 'truncatedInputRejected': True,
                'appleHostInspectionExactlyEqual': True},
            'jni-receipt.json': {
                'status': 'passed', 'exitCode': 0, 'serial': 'fixture-device',
                'inputs': {str(self.promoted): MODULE.digest(self.raw)},
                'result': {'nativeAvailable': True, 'malformedNativeInputRefused': True,
                           'oldNineFieldOutputRefused': True}},
        }
        evidence = {}
        for name, doc in docs.items():
            data = json.dumps(doc).encode()
            self.write(self.artifact / name, data)
            evidence[name] = MODULE.digest(data)
        self.receipt = {
            'schema': MODULE.SCHEMA, 'artifact_scope': 'physical-device-demo',
            'status': 'qualified-arm64-device-demo', 'abi': MODULE.ABI,
            'target': MODULE.TARGET, 'native_bridge_abi_version': 31,
            'native_signer_contract_revision': 7, 'source_root': str(self.root),
            'source_commit': ORIGINAL_COMMIT, 'source_fingerprint_sha256': 'c' * 64,
            'producer_artifact_root': str(self.producer),
            'producer_stage': 'arm64-promoted-full-producer-continues', 'evidence': evidence,
            'library': {'path': MODULE.LIB, 'raw_path': MODULE.RAW,
                        'bytes': len(self.native), 'sha256': MODULE.digest(self.native),
                        'raw_bytes': len(self.raw), 'raw_sha256': MODULE.digest(self.raw)},
        }
        self.save_receipt()
        self.head = ORIGINAL_COMMIT
        self.exports = 'T Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_inspect\nT connect_norito_detached_transaction_scaffold_inspect_v1\n'
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(os.environ, {
            'MOBILE_SDK_WALLET_RUNTIME_AUTHORITY': 'fixture-authority',
            'MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX': 'd' * 64}).start()
        self.check_output = mock.patch.object(MODULE.subprocess, 'check_output', side_effect=self.output).start()
        self.run = mock.patch.object(MODULE.subprocess, 'run', side_effect=self.strip_copy).start()

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def save_receipt(self):
        self.write(self.artifact / 'receipt.json', json.dumps(self.receipt).encode())

    def change_evidence(self, name, change):
        path = self.artifact / name
        doc = json.loads(path.read_bytes())
        change(doc)
        path.write_text(json.dumps(doc))
        self.receipt['evidence'][name] = MODULE.digest(path.read_bytes())
        self.save_receipt()

    def output(self, argv, **kwargs):
        if argv == ['git', '-C', str(self.root), 'rev-parse', 'HEAD']:
            return self.head + '\n'
        self.assertEqual(argv, [str(self.nm), '-D', '--defined-only', str(self.artifact / MODULE.LIB)])
        return self.exports

    def strip_copy(self, argv, **kwargs):
        self.assertEqual(argv[:2], [str(self.strip), '--strip-unneeded'])
        self.assertEqual(Path(argv[2]).read_bytes(), self.raw)
        Path(argv[2]).write_bytes(self.native)
        return types.SimpleNamespace(returncode=0)

    def validate(self, allow=False):
        return MODULE.validate(self.artifact, self.root, self.ndk, allow)

    def test_matching_head_remains_strict_by_default(self):
        result = self.validate()
        report = result['consumer_validation']
        self.assertFalse(report['allow_source_head_drift'])
        self.assertFalse(report['source_head_drifted'])
        self.assertEqual(report['artifact_source_commit'], ORIGINAL_COMMIT)

    def test_changed_head_refuses_by_default_before_external_tools(self):
        self.head = NEW_HEAD
        with self.assertRaisesRegex(ValueError, 'current selected source commit'):
            self.validate()
        self.run.assert_not_called()

    def test_explicit_drift_retains_original_commit_and_receipt(self):
        self.head = NEW_HEAD
        original = (self.artifact / 'receipt.json').read_bytes()
        result = self.validate(True)
        self.assertEqual(result['source_commit'], ORIGINAL_COMMIT)
        self.assertEqual(result['consumer_validation'], {
            'schema': 'iroha.android-device-demo-consumption.v1',
            'artifact_receipt_sha256': MODULE.digest(original),
            'artifact_source_commit': ORIGINAL_COMMIT, 'current_source_head': NEW_HEAD,
            'allow_source_head_drift': True, 'source_head_drifted': True,
            'scope': 'physical-device-demo-consumption; original producer evidence, not current-source or release qualification'})
        self.assertEqual((self.artifact / 'receipt.json').read_bytes(), original)
        self.run.assert_called_once()

    def test_drift_does_not_reanchor_original_evidence_to_current_head(self):
        self.head = NEW_HEAD
        for name, field in [('source-seal.json', 'source_commit'),
                            ('producer-receipt.json', 'sourceCommit'),
                            ('compiler-command.json', 'sourceCommit')]:
            with self.subTest(name=name):
                self.change_evidence(name, lambda d: d.update({field: NEW_HEAD}))
                with self.assertRaisesRegex(ValueError, 'mismatch'):
                    self.validate(True)
                self.change_evidence(name, lambda d: d.update({field: ORIGINAL_COMMIT}))

    def test_original_commit_must_be_canonical_full_hex(self):
        self.head = NEW_HEAD
        for value in ['A' * 40, 'a' * 39, 'g' * 40, None, 123]:
            with self.subTest(value=value):
                self.receipt['source_commit'] = value
                self.save_receipt()
                with self.assertRaisesRegex(ValueError, 'Invalid original source commit'):
                    self.validate(True)

    def test_capture_cannot_use_drift_even_before_reading_inputs(self):
        with self.assertRaisesRegex(ValueError, 'consumer-only'):
            MODULE.capture(types.SimpleNamespace(allow_source_head_drift=True))

    def test_drift_preserves_runtime_trust_check(self):
        self.head = NEW_HEAD
        with mock.patch.dict(os.environ, {'MOBILE_SDK_WALLET_RUNTIME_AUTHORITY': 'wrong'}):
            with self.assertRaisesRegex(ValueError, 'Runtime trust selection differs'):
                self.validate(True)

    def test_drift_preserves_native_byte_check(self):
        self.head = NEW_HEAD
        (self.artifact / MODULE.LIB).write_bytes(self.native + b'changed')
        with self.assertRaisesRegex(ValueError, 'Native library byte mismatch'):
            self.validate(True)

    def test_drift_preserves_promoted_original_check(self):
        self.head = NEW_HEAD
        self.promoted.write_bytes(self.raw + b'changed')
        with self.assertRaisesRegex(ValueError, 'genuine promoted original'):
            self.validate(True)

    def test_drift_preserves_elf_load_alignment(self):
        self.head = NEW_HEAD
        malformed = bytearray(self.native)
        struct.pack_into('<Q', malformed, 64 + 48, 4096)
        (self.artifact / MODULE.LIB).write_bytes(malformed)
        self.receipt['library']['sha256'] = MODULE.digest(malformed)
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'non-16KB LOAD segment'):
            self.validate(True)

    def test_drift_preserves_canonical_strip_reproduction(self):
        self.head = NEW_HEAD
        self.run.side_effect = lambda argv, **kwargs: Path(argv[2]).write_bytes(b'wrong strip output')
        with self.assertRaisesRegex(ValueError, 'Stripped bytes do not reproduce'):
            self.validate(True)

    def test_drift_preserves_required_jni_exports(self):
        self.head = NEW_HEAD
        self.exports = ''
        with self.assertRaisesRegex(ValueError, 'Missing current JNI/C exports'):
            self.validate(True)

    def test_drift_preserves_abi_version(self):
        self.head = NEW_HEAD
        self.receipt['native_bridge_abi_version'] = 32
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'Wrong native ABI'):
            self.validate(True)

    def test_drift_preserves_physical_probe_binding(self):
        self.head = NEW_HEAD
        self.change_evidence('jni-receipt.json', lambda d: d.update(inputs={str(self.promoted): '0' * 64}))
        with self.assertRaisesRegex(ValueError, 'different raw bytes'):
            self.validate(True)

    def test_head_moving_during_validation_refuses(self):
        def moving(argv, **kwargs):
            answer = self.output(argv, **kwargs)
            if argv[0] == str(self.nm):
                self.head = NEW_HEAD
            return answer
        self.check_output.side_effect = moving
        with self.assertRaisesRegex(ValueError, 'HEAD changed during'):
            self.validate(True)

    def test_invalid_current_head_refuses_even_when_drift_allowed(self):
        self.head = 'not-a-canonical-commit'
        with self.assertRaisesRegex(ValueError, 'Invalid current source HEAD'):
            self.validate(True)

    def test_receipt_mutation_during_validation_refuses(self):
        self.head = NEW_HEAD
        def mutating_strip(argv, **kwargs):
            result = self.strip_copy(argv, **kwargs)
            self.receipt['source_commit'] = NEW_HEAD
            self.save_receipt()
            return result
        self.run.side_effect = mutating_strip
        with self.assertRaisesRegex(ValueError, 'Artifact receipt changed during'):
            self.validate(True)

    def test_consumer_assets_keep_original_and_separate_drift_report(self):
        self.head = NEW_HEAD
        original = (self.artifact / 'receipt.json').read_bytes()
        build_root = self.base / 'consumer'
        build_root.mkdir()
        output = build_root / 'gradle-build/iroha_kotlin_sdk/client-android/generated/deviceDemoNative'
        argv = ['device-demo', '--root', str(self.root), '--ndk', str(self.ndk),
                '--artifact-dir', str(self.artifact), '--output-dir', str(output),
                '--allow-source-head-drift']
        with mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, {
                'MOBILE_SDK_ANDROID_ARTIFACT_DIR': str(build_root)}), contextlib.redirect_stdout(io.StringIO()) as stdout:
            MODULE.main()
        reported = json.loads(stdout.getvalue())['consumer_validation']
        self.assertEqual((output / 'assets/iroha/android-device-demo-native-v1.json').read_bytes(), original)
        self.assertEqual(json.loads((output / 'assets/iroha/android-device-demo-consumption-v1.json').read_bytes()), reported)
        self.assertEqual((self.artifact / 'receipt.json').read_bytes(), original)
        self.assertEqual((output / MODULE.LIB).read_bytes(), self.native)
        self.assertEqual(reported['current_source_head'], NEW_HEAD)
        self.assertEqual(reported['artifact_source_commit'], ORIGINAL_COMMIT)


if __name__ == '__main__':
    unittest.main()
