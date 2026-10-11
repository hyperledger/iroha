"""Exercise local Apple path/scope admission without building or faking a bridge."""
from pathlib import Path
import importlib.util
import hashlib
import shlex
import json
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


policy = module('norito_bridge_local_integration')
validator = module('validate_norito_bridge_xcframework')
seal = module('norito_bridge_source_seal')


class LocalAppleIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.lane = self.root / policy.LANE
        self.lane.mkdir(parents=True, mode=0o700)
        for name in ('cargo', 'build', 'artifacts', 'projections'):
            (self.lane / name).mkdir(mode=0o700)
        self.git = mock.patch.object(policy.subprocess, 'run', side_effect=self.git_read)
        self.git.start()
        self.addCleanup(self.git.stop)

    @staticmethod
    def git_read(argv, **kwargs):
        if 'ls-files' in argv:
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        if 'check-ignore' in argv:
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        raise AssertionError('unexpected command in path-policy test')

    def test_each_role_is_confined_to_its_owned_canonical_directory(self):
        for role, name in [('cargo', 'cargo'), ('build', 'build'), ('artifact', 'artifacts'), ('projection', 'projections')]:
            with self.subTest(role=role):
                self.assertEqual(policy.directory(self.root, self.lane / name, role), self.lane / name)
                with self.assertRaises(ValueError):
                    policy.directory(self.root, self.root, role)
        with self.assertRaises(ValueError):
            policy.directory(self.root, self.lane / 'build', 'cargo')

    def test_builder_stage_is_allowed_only_inside_the_artifact_root(self):
        stage = self.lane / 'artifacts/.NoritoBridge.publish.fixture'
        stage.mkdir(mode=0o700)
        for role in ('artifact', 'projection'):
            self.assertEqual(policy.directory(self.root, stage, role), stage)
        stage.parent.chmod(0o755)
        with self.assertRaises(ValueError):
            policy.directory(self.root, stage, 'artifact')
        stage.parent.chmod(0o700)
        wrong = self.lane / 'build/.NoritoBridge.publish.fixture'
        wrong.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            policy.directory(self.root, wrong, 'artifact')

    def test_local_directory_symlink_or_permissive_mode_is_rejected(self):
        cargo = self.lane / 'cargo'
        cargo.rmdir()
        cargo.symlink_to(self.lane / 'build', target_is_directory=True)
        with self.assertRaises(ValueError):
            policy.directory(self.root, cargo, 'cargo')
        cargo.unlink()
        cargo.mkdir(mode=0o700)
        cargo.chmod(0o755)
        with self.assertRaises(ValueError):
            policy.directory(self.root, cargo, 'cargo')

    def test_local_lane_cannot_share_another_owner(self):
        cache = self.lane / 'build/cargo-home'
        cache.mkdir(mode=0o700)
        with mock.patch.object(policy.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError):
                policy.directory(self.root, self.lane / 'cargo', 'cargo')
            with self.assertRaises(ValueError):
                policy.cargo_home(self.root, cache, local_integration=True)

    def test_forced_tracked_output_and_unignored_lane_are_rejected(self):
        for tracked, ignored in [(b'target/norito-bridge-local/source.rs\0', 0), (b'', 1)]:
            def reply(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0 if 'ls-files' in argv else ignored, tracked if 'ls-files' in argv else b'', b'')
            with mock.patch.object(policy.subprocess, 'run', side_effect=reply):
                with self.assertRaisesRegex(ValueError, 'ignored.*tracked'):
                    policy.directory(self.root, self.lane / 'cargo', 'cargo')

    def test_reused_lane_does_not_delete_or_change_existing_cargo_output(self):
        retained = self.lane / 'cargo/retained-output'
        retained.write_bytes(b'previous compilation')
        self.assertEqual(policy.directory(self.root, self.lane / 'cargo', 'cargo'), retained.parent)
        self.assertEqual(retained.read_bytes(), b'previous compilation')

    def test_builder_validator_and_checker_argument_forwarding(self):
        """Run only command assembly, with capture functions in place of tools."""
        self.git.stop()
        source = (ROOT / 'scripts/build_norito_xcframework.sh').read_text()
        fragment = source.split('\nrun_isolated_python \\\n  "$ROOT_DIR/scripts/validate_norito_bridge_xcframework.py"', 1)[1]
        fragment = ('run_isolated_python \\\n  "$ROOT_DIR/scripts/validate_norito_bridge_xcframework.py"' + fragment.split('\nassert_bridge_source_seal "staged artifact validation"', 1)[0])
        checker_commands = re.findall(r'bash "\$ROOT_DIR/scripts/check_mobile_sdk_artifacts.sh" --root "\$ROOT_DIR" --lockfile-path "\$CARGO_LOCKFILE" --apple-only \\\n[^\n]+', source)
        self.assertEqual(len(checker_commands), 2)
        for local in (False, True):
            setup = '\n'.join([
                'run_isolated_python() { printf "%s\\n" "$@"; }',
                'capture() { printf "%s\\n" "$@"; }',
                'ROOT_DIR=/fixture', 'CARGO_LOCKFILE=/fixture/Cargo.lock', 'PUBLISH_XCFRAMEWORK=/framework',
                'PUBLISH_MANIFEST=/manifest', 'PUBLISH_MANIFEST_LINK=/link',
                'CANONICAL_MANIFEST_RELATIVE_TARGET=canonical',
                'PUBLISH_PROSPECTIVE_LOADER=/loader',
                'LOCAL_INTEGRATION_ARGS=(--local-integration)' if local else 'LOCAL_INTEGRATION_ARGS=()',
            ])
            for command in [fragment, *(item.replace('bash ', 'capture ', 1) for item in checker_commands)]:
                result = subprocess.run(['/bin/bash', '-eu', '-c', setup + '\n' + command], capture_output=True, text=True, check=True)
                arguments = result.stdout.splitlines()
                self.assertNotIn('+', arguments)
                self.assertNotIn('', arguments)
                self.assertEqual(arguments.count('--local-integration'), int(local))
                self.assertEqual(arguments[0], '/fixture/scripts/' + ('validate_norito_bridge_xcframework.py' if command == fragment else 'check_mobile_sdk_artifacts.sh'))

    def test_apple_cargo_command_uses_stock_root_manifest_without_overrides(self):
        self.git.stop()
        source = (ROOT / 'scripts/build_norito_xcframework.sh').read_text()
        function = re.search(r'^run_hermetic_apple_cargo\(\) \{.*?^\}', source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(function)
        setup = '\n'.join([
            'run_isolated_python() { printf "%s\\n" "$@"; }',
            'assert_selected_cargo_lock() { :; }',
            'ROOT_DIR=/fixture', 'HERMETIC_RUNNER=/fixture/runner',
            f'STAGE_DIR={shlex.quote(str(self.lane / "build"))}',
            'CARGO_LOCKFILE=/fixture/Cargo.lock', 'CARGO_BINARY=/fixture/cargo',
            'RUSTC_BINARY=/fixture/rustc', 'RUSTDOC_BINARY=/fixture/rustdoc',
            'MOBILE_CARGO_HOME=/fixture/cargo-home', 'CARGO_TARGET_DIR=/fixture/target',
            'EMBEDDED_SOURCE_COMMIT=' + '1' * 40, 'USER_HOME_DIR=/fixture/home',
            'MOBILE_RUSTUP_HOME=/fixture/rustup', 'MOBILE_TMPDIR=/fixture/tmp',
            'XCODE_DEVELOPER_DIR=/fixture/Xcode', 'MACOSX_DEPLOYMENT_TARGET=15.0',
            'CARGO_BUILD_JOBS=1',
            'WALLET_RUNTIME_AUTHORITY=bpng-taira-v7',
            'WALLET_RUNTIME_TRUST_PUBLIC_HEX=' + '3' * 64,
        ])
        command = setup + '\n' + function.group(0) + '\n' + (
            'run_hermetic_apple_cargo apple-macos /fixture/sdk build '
            '--target aarch64-apple-darwin -p connect_norito_bridge\n'
        )
        subprocess.run(['/bin/bash', '-eu', '-c', command], check=True, capture_output=True, text=True)
        args = (self.lane / 'build/cargo-messages/aarch64-apple-darwin.jsonl').read_text().splitlines()
        cargo = args.index('--') + 1
        self.assertEqual(args[cargo:], [
            '/fixture/cargo', 'build', '--manifest-path', '/fixture/Cargo.toml',
            '--message-format=json-render-diagnostics',
            '--target', 'aarch64-apple-darwin', '-p', 'connect_norito_bridge',
        ])
        for forbidden in ('-Z', '--lockfile-path', '--config', 'RUSTC_BOOTSTRAP=1'):
            self.assertNotIn(forbidden, args)
        self.assertIn('CARGO_HOME=/fixture/cargo-home', args)

    def test_apple_builder_rejects_any_bootstrap_assignment(self):
        self.git.stop()
        source = (ROOT / 'scripts/build_norito_xcframework.sh').read_text()
        fragment = source.split('if [[ "${CARGO_BUILD_JOBS:-}"', 1)[1]
        fragment = 'if [[ "${CARGO_BUILD_JOBS:-}"' + fragment.split('if [[ -z "${CARGO_TARGET_DIR:-}"', 1)[0]
        environment = dict(os.environ, CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true')
        environment.pop('RUSTC_BOOTSTRAP', None)
        accepted = subprocess.run(['/bin/bash', '-eu', '-c', fragment], env=environment, capture_output=True, text=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for value in ('', '0', '1'):
            refused = subprocess.run(['/bin/bash', '-eu', '-c', fragment], env=dict(environment, RUSTC_BOOTSTRAP=value), capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('RUSTC_BOOTSTRAP must be unset', refused.stderr)

    def test_apple_host_macro_and_target_strip_settings_are_source_owned(self):
        self.git.stop()
        import tomllib
        manifest = tomllib.loads((ROOT / 'Cargo.toml').read_text())
        self.assertEqual(manifest['profile']['release']['build-override']['strip'], 'none')
        self.assertEqual(manifest['profile']['apple-release']['strip'], 'none')
        self.assertEqual(manifest['profile']['apple-release']['package']['connect_norito_bridge']['strip'], 'none')
        builder = (ROOT / 'scripts/build_norito_xcframework.sh').read_text()
        self.assertNotIn('apple_proc_macro_rustc_wrapper', builder)
        self.assertNotIn('build.rustc-wrapper', builder)
        self.assertNotIn('build.rustc-workspace-wrapper', builder)

    def payload(self, dirty=False):
        return {
            'version': '0.1.0', 'native_bridge_abi_version': 29,
            'privacy_production_enabled': True, 'cargo_features': ['privacy-production-enabled'],
            'build_environment': {}, 'source_commit': '1' * 40, 'embedded_source_commit': '1' * 40,
            'source_tree_dirty': dirty, 'source_fingerprint_sha256': '2' * 64,
            'cargo_lock_sha256': '3' * 64, 'bridge_header_sha256': '4' * 64,
            'required_symbols': validator.EXPECTED_REQUIRED_SYMBOLS,
            'forbidden_symbols': validator.EXPECTED_FORBIDDEN_SYMBOLS,
            'hashes': {key: '5' * 64 for key in validator.EXPECTED_SLICES},
        }

    def load_payload(self, payload, local=False):
        # These mocks isolate manifest field admission. They do not produce a
        # framework or assert repository/tool/native artifact qualification.
        path = self.lane / 'manifest-unit-input.json'
        path.write_text(json.dumps(payload))
        with mock.patch.object(validator, '_validate_build_environment'), mock.patch.object(validator, '_validate_root_identity'):
            return validator._load_manifest(path, self.root, self.root / 'Cargo.lock', local_integration=local)

    def test_clean_and_dirty_local_manifests_remain_explicitly_non_release(self):
        for dirty in (False, True):
            payload = self.payload(dirty)
            payload['artifact_scope'] = 'local-integration'
            self.assertEqual(self.load_payload(payload, True)['source_tree_dirty'], dirty)
            with self.assertRaisesRegex(validator.ValidationError, 'field inventory'):
                self.load_payload(payload)

    def test_local_scope_is_required_and_release_manifest_cannot_be_relabelled_by_cli(self):
        payload = self.payload()
        self.assertNotIn('artifact_scope', self.load_payload(payload))
        with self.assertRaisesRegex(validator.ValidationError, 'scope marker'):
            self.load_payload(payload, True)
        for marker in (False, True, 'release', 1):
            payload['artifact_scope'] = marker
            with self.assertRaises(validator.ValidationError):
                self.load_payload(payload, True)

    def test_local_mode_preserves_exact_abi_feature_and_symbol_checks(self):
        for field, value in [('native_bridge_abi_version', 22), ('cargo_features', []), ('required_symbols', [])]:
            payload = self.payload()
            payload['artifact_scope'] = 'local-integration'
            payload[field] = value
            with self.assertRaises(validator.ValidationError):
                self.load_payload(payload, True)

    def test_local_flag_does_not_allow_unverified_dirty_provenance(self):
        with self.assertRaisesRegex(validator.ValidationError, 'repository provenance'):
            validator.validate(root=self.root, lockfile_path=self.root / 'Cargo.lock', xcframework=self.root, manifest_path=self.root,
                               manifest_link=self.root, expected_link_target='',
                               local_integration=True, allow_dirty_source=True)

    def test_builder_local_root_lock_and_release_graph_admission(self):
        """Execute only the actual lock-admission shell fragment, without Cargo."""
        self.git.stop()
        fixture_root = self.root / 'source'
        fixture_root.mkdir()
        lockfile = fixture_root / 'Cargo.lock'
        lockfile.write_bytes(b'version = 4\n')
        digest = hashlib.sha256(lockfile.read_bytes()).hexdigest()
        graph_owner = fixture_root / 'ci/privacy_sdk_cargo_lockfile.sh'
        graph_owner.parent.mkdir()
        graph_owner.write_text('readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"' + digest + '"\n')
        external_lock = self.root / 'external-Cargo.lock'
        external_lock.write_bytes(lockfile.read_bytes())
        external_lock.chmod(0o400)
        source = (ROOT / 'scripts/build_norito_xcframework.sh').read_text()
        fragment = 'selected_cargo_lock_sha256() {' + source.split('selected_cargo_lock_sha256() {', 1)[1].split('assert_selected_cargo_lock() {', 1)[0]
        def admit(local, selected):
            setup = '\n'.join([
                'run_isolated_python() { ' + shlex.quote(os.sys.executable) + ' -I -S -B "$@"; }',
                'ROOT_DIR=' + shlex.quote(str(fixture_root)),
                'SOURCE_SEAL_SCRIPT=' + shlex.quote(str(ROOT / 'scripts/norito_bridge_source_seal.py')),
                'CARGO_GRAPH_OWNER=' + shlex.quote(str(graph_owner)),
                'CARGO_LOCKFILE=' + shlex.quote(str(selected)),
                'PRIVACY_PRODUCTION_ENABLED=1', 'LOCAL_INTEGRATION=' + str(int(local)),
            ])
            return subprocess.run(['/bin/bash', '-eu', '-c', setup + '\n' + fragment], capture_output=True, text=True)
        self.assertEqual(admit(True, lockfile).returncode, 0)
        self.assertNotEqual(admit(False, lockfile).returncode, 0)
        lockfile.chmod(0o400)
        rejected = admit(False, lockfile)
        self.assertIn('external canonical graph snapshot', rejected.stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(admit(False, external_lock).returncode, 0)
        self.assertNotEqual(admit(True, external_lock).returncode, 0)
        external_lock.chmod(0o600)
        self.assertIn('read-only', admit(False, external_lock).stderr)
        link = fixture_root / 'alias.lock'
        link.symlink_to(lockfile)
        self.assertNotEqual(admit(True, link).returncode, 0)
        self.assertNotEqual(admit(True, Path('Cargo.lock')).returncode, 0)
        self.assertEqual(lockfile.read_bytes(), b'version = 4\n')

    def test_local_manifest_root_lock_preserves_digest_and_release_restrictions(self):
        """Exercise root identity checks with real unit-fixture files."""
        lockfile = self.root / 'Cargo.lock'
        lockfile.write_bytes(b'version = 4\n')
        header = self.root / 'crates/connect_norito_bridge/include/connect_norito_bridge.h'
        header.parent.mkdir(parents=True)
        header.write_text('#define CONNECT_NORITO_BRIDGE_ABI_VERSION 29\n')
        bridge = self.root / 'crates/connect_norito_bridge/src/lib.rs'
        bridge.parent.mkdir(parents=True)
        bridge.write_text('const CONNECT_NORITO_BRIDGE_ABI_VERSION: u32 = PRIVACY_BRIDGE_ABI_VERSION_V1;\n')
        protocol = self.root / 'crates/iroha_data_model/src/privacy/protocol.rs'
        protocol.parent.mkdir(parents=True)
        protocol.write_text('pub const PRIVACY_BRIDGE_ABI_VERSION_V1: u32 = 29;\n')
        payload = self.payload()
        payload['cargo_lock_sha256'] = hashlib.sha256(lockfile.read_bytes()).hexdigest()
        payload['bridge_header_sha256'] = hashlib.sha256(header.read_bytes()).hexdigest()
        validator._validate_root_identity(self.root, payload, lockfile, local_integration=True)
        with self.assertRaisesRegex(validator.ValidationError, 'external canonical graph snapshot'):
            validator._validate_root_identity(self.root, payload, lockfile)
        selected = self.root / 'other.lock'
        selected.write_bytes(lockfile.read_bytes())
        with self.assertRaisesRegex(validator.ValidationError, 'explicitly selected root'):
            validator._validate_root_identity(self.root, payload, selected, local_integration=True)
        with self.assertRaisesRegex(validator.ValidationError, 'read-only'):
            validator._validate_root_identity(self.root, payload, selected)
        lockfile.write_bytes(b'changed graph\n')
        with self.assertRaisesRegex(validator.ValidationError, 'digest'):
            validator._validate_root_identity(self.root, payload, lockfile, local_integration=True)

    def test_only_the_three_fallback_digests_normalize_for_pin_integration(self):
        keys = sorted(seal.SWIFT_NATIVE_BRIDGE_HASH_KEYS)
        loader = ('    private static let expectedHashes: [String: String] = [\n'
                  + ',\n'.join(f'        "{key}": "' + '0' * 64 + '"' for key in keys)
                  + '\n    ]\nfunc retainedLogic() {}\n').encode()
        replacement = seal.rewrite_swift_native_bridge_hash_pins(loader, {key: 'a' * 64 for key in keys})
        self.assertNotEqual(loader, replacement)
        self.assertEqual(seal.normalize_swift_native_bridge_hash_pins(loader), seal.normalize_swift_native_bridge_hash_pins(replacement))
        changed_logic = replacement.replace(b'retainedLogic', b'changedLogic')
        self.assertNotEqual(seal.normalize_swift_native_bridge_hash_pins(loader), seal.normalize_swift_native_bridge_hash_pins(changed_logic))


if __name__ == '__main__':
    unittest.main()
