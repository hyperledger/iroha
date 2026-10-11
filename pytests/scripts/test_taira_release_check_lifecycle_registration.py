"""Verify real grouped Cargo registration and exact lifecycle names without Cargo."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_taira_release_check as existing

gate = existing.gate
REPO = Path(__file__).resolve().parents[2]
PACKAGE = Path('crates/iroha_torii')


class LifecycleRegistrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for relative in ('Cargo.toml', 'tests/grouped/nexus_sorafs.rs', 'tests/nexus_lifecycle_endpoint.rs'):
            target = self.root / PACKAGE / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / PACKAGE / relative).read_bytes())

    def replace(self, relative, old, new):
        path = self.root / PACKAGE / relative
        source = path.read_text()
        self.assertIn(old, source)
        path.write_text(source.replace(old, new))

    def test_real_manifest_module_source_and_both_scope_selectors_match(self):
        gate.validate_torii_lifecycle_test_registration(REPO)
        gate.validate_torii_lifecycle_test_registration(self.root)
        self.assertEqual(gate.HARNESS_TARGETS['torii-lifecycle'][1:], (
            'torii_nexus_sorafs', 'test', ['-p', 'iroha_torii', '--test', 'torii_nexus_sorafs']))
        for scope in gate.QUALIFICATION_SCOPES:
            tests = [name for _, names in gate.qualification_stages(scope)['torii-lifecycle'] for name in names]
            self.assertEqual(len(tests), 5)
            self.assertTrue(all(name.startswith('nexus_lifecycle_endpoint::') for name in tests))

    def test_missing_or_duplicate_explicit_target_is_rejected(self):
        for replacement in ('removed_target', 'torii_nexus_sorafs'):
            with self.subTest(replacement=replacement):
                path = self.root / PACKAGE / 'Cargo.toml'
                path.write_bytes((REPO / PACKAGE / 'Cargo.toml').read_bytes())
                if replacement == 'removed_target':
                    self.replace('Cargo.toml', 'name = "torii_nexus_sorafs"', 'name = "removed_target"')
                else:
                    path.write_text(path.read_text() + '\n[[test]]\nname = "torii_nexus_sorafs"\npath = "tests/grouped/nexus_sorafs.rs"\n')
                with self.assertRaisesRegex(gate.CheckError, 'explicitly registered once'):
                    gate.validate_torii_lifecycle_test_registration(self.root)

    def test_standalone_filename_is_not_an_implicit_target(self):
        with patch.dict(gate.HARNESS_TARGETS, {'torii-lifecycle': (
            'lifecycle', 'nexus_lifecycle_endpoint', 'test',
            ['-p', 'iroha_torii', '--test', 'nexus_lifecycle_endpoint'])}):
            with self.assertRaisesRegex(gate.CheckError, 'explicitly registered once'):
                gate.validate_torii_lifecycle_test_registration(self.root)

    def test_unqualified_selector_is_rejected(self):
        stages = (('bad selector', ('lifecycle_get_returns_valid_exact_json_status',)),)
        with patch.object(gate, 'TORII_LIFECYCLE_STAGES', stages):
            with self.assertRaisesRegex(gate.CheckError, 'module prefix or test'):
                gate.validate_torii_lifecycle_test_registration(self.root)

    def test_removed_module_or_function_is_rejected(self):
        for kind in ('module', 'function'):
            with self.subTest(kind=kind):
                for relative in ('tests/grouped/nexus_sorafs.rs', 'tests/nexus_lifecycle_endpoint.rs'):
                    (self.root / PACKAGE / relative).write_bytes((REPO / PACKAGE / relative).read_bytes())
                if kind == 'module':
                    self.replace('tests/grouped/nexus_sorafs.rs', 'mod nexus_lifecycle_endpoint;', 'mod removed_lifecycle;')
                else:
                    self.replace('tests/nexus_lifecycle_endpoint.rs', 'async fn lifecycle_get_returns_valid_exact_json_status(', 'async fn removed_json_test(')
                with self.assertRaisesRegex(gate.CheckError, 'source registration failed'):
                    gate.validate_torii_lifecycle_test_registration(self.root)

    def test_module_path_outside_package_is_rejected(self):
        self.replace('tests/grouped/nexus_sorafs.rs', '../nexus_lifecycle_endpoint.rs', '/outside/lifecycle.rs')
        with self.assertRaisesRegex(gate.CheckError, 'module path leaves package'):
            gate.validate_torii_lifecycle_test_registration(self.root)

    def test_required_feature_removed_from_selected_closure_is_rejected(self):
        self.replace('Cargo.toml', 'default = ["node-api"]', 'default = []')
        with self.assertRaisesRegex(gate.CheckError, 'unselected features'):
            gate.validate_torii_lifecycle_test_registration(self.root)

    def test_registration_failure_stops_before_source_subprocesses_or_rustc(self):
        self.replace('Cargo.toml', 'name = "torii_nexus_sorafs"', 'name = "removed_target"')
        # This fixture carries only the Torii package; MV registration has its
        # own real-source coverage and runs first in the same lexical phase.
        with patch.object(gate, 'validate_mv_test_registration') as mv, \
             patch.object(gate.subprocess, 'run') as child, \
             patch.object(gate, 'validate_native_consensus_test_registration') as rust, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(gate.CheckError, 'explicitly registered once'):
                gate.run_lifecycle_source_checks(self.root, {}, ())
        mv.assert_called_once_with(self.root)
        child.assert_not_called()
        rust.assert_not_called()

    def test_fixture_authority_is_explicit_in_tests_and_absent_from_shipping_defaults(self):
        selection = gate.native_harness_selection(("torii-lifecycle",))
        self.assertEqual(selection, ["-p", "iroha_torii", "--test", "torii_nexus_sorafs",
                                     "--features", "iroha_torii/test-fixtures"])
        self.assertIn('default = ["node-api"]', (REPO / PACKAGE / 'Cargo.toml').read_text())
        gate.validate_torii_lifecycle_test_registration(self.root)
        with patch.object(gate, 'native_harness_selection', return_value=selection[:-2]):
            with self.assertRaisesRegex(gate.CheckError, 'unselected features'):
                gate.validate_torii_lifecycle_test_registration(self.root)

    def test_undeclared_selected_feature_and_unselected_required_feature_are_rejected(self):
        for kind in ('undeclared', 'unselected'):
            with self.subTest(kind=kind):
                (self.root / PACKAGE / 'Cargo.toml').write_bytes((REPO / PACKAGE / 'Cargo.toml').read_bytes())
                if kind == 'undeclared':
                    self.replace('Cargo.toml', 'test-fixtures = ["iroha_core/iroha-core-tests"]',
                                 'removed-fixtures = ["iroha_core/iroha-core-tests"]')
                    expected = 'selected feature is not declared'
                else:
                    self.replace('Cargo.toml', 'required-features = ["app_api", "test-fixtures"]',
                                 'required-features = ["app_api", "test-fixtures", "ws_integration_tests"]')
                    expected = 'unselected features'
                with self.assertRaisesRegex(gate.CheckError, expected):
                    gate.validate_torii_lifecycle_test_registration(self.root)
