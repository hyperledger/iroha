"""Cheap source-inventory and pre-I/O optimized-mode refusal controls."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import custody


class CustodyTests(unittest.TestCase):
    def test_generated_registry_is_observed_data_not_source_authority(self):
        manifest = custody.checked_sources()
        self.assertNotIn(custody.GENERATED_DATA, manifest['sources'])
        before = custody.observed_generated_data()
        read_bytes = custody.Path.read_bytes
        def substituted(path):
            raw = read_bytes(path)
            return raw + b'\nchanged DATA' if path == custody.ROOT/custody.GENERATED_DATA else raw
        with patch.object(custody.Path, 'read_bytes', substituted):
            self.assertEqual(custody.checked_sources(), manifest)
            after = custody.observed_generated_data()
        self.assertNotEqual(before['sha256'], after['sha256'])
        self.assertEqual(before['role'], 'unqualified generated DATA')
        with patch.object(custody.Path, 'is_symlink', return_value=True):
            with self.assertRaisesRegex(ValueError, 'regular file'):
                custody.observed_generated_data()
        changed = copy.deepcopy(manifest)
        changed['sources'][custody.GENERATED_DATA] = before['sha256']
        with self.assertRaisesRegex(ValueError, 'dependency inventory'):
            custody.validate_manifest(changed)
        for name in ('crates/iroha_plonk/build_support/source_identity.rs',
                     'crates/iroha_plonk/src/keys/keygen/builtin.rs'):
            def changed_owner(path, selected=custody.ROOT/name):
                raw = read_bytes(path)
                return raw + b'\nchanged owner' if path == selected else raw
            with self.subTest(source=name):
                with patch.object(custody.Path, 'read_bytes', changed_owner):
                    with self.assertRaisesRegex(ValueError, 'changed source '+name):
                        custody.checked_sources()

    def test_exact_inventory_rejects_missing_extra_or_noncanonical_pins(self):
        manifest = custody.checked_sources()
        for role in ('files', 'sources'):
            changed = copy.deepcopy(manifest)
            del changed[role][next(iter(changed[role]))]
            with self.assertRaisesRegex(ValueError, 'inventory'):
                custody.validate_manifest(changed)
            changed = copy.deepcopy(manifest)
            changed[role]['outside.py'] = '0'*64
            with self.assertRaisesRegex(ValueError, 'inventory'):
                custody.validate_manifest(changed)
        # Newly exported exact-source reconstruction is part of the key authority.
        # Missing roles or changed bodies must not pass by refreshing unrelated pins.
        reconstruction = (
            'crates/iroha_plonk/src/keys/keygen/rebuild.rs',
            'crates/iroha_plonk/src/keys/mod.rs',
            'crates/iroha_plonk/src/keys/source_fingerprint.rs',
        )
        read_bytes = custody.Path.read_bytes
        for name in (*reconstruction, *sorted(custody.DELEGATED_SOURCES)):
            self.assertIn(name, manifest['sources'])
            changed = copy.deepcopy(manifest)
            del changed['sources'][name]
            with self.subTest(source=name, mutation='missing'):
                with self.assertRaisesRegex(ValueError, 'dependency inventory'):
                    custody.validate_manifest(changed)
            def substituted(path, selected=custody.ROOT/name):
                raw = read_bytes(path)
                return raw + b'\nchanged' if path == selected else raw
            with self.subTest(source=name, mutation='body'):
                with patch.object(custody.Path, 'read_bytes', substituted):
                    with self.assertRaisesRegex(ValueError, 'changed source '+name):
                        custody.checked_sources()
        changed = copy.deepcopy(manifest)
        changed['files'][next(iter(changed['files']))] = 'F'*64
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            custody.validate_manifest(changed)

    def test_optimized_execution_refuses_before_manifest_read(self):
        with patch.object(custody.sys, 'flags', SimpleNamespace(optimize=1)):
            with patch.object(custody.Path, 'read_text', side_effect=RuntimeError('unexpected read')):
                with self.assertRaisesRegex(ValueError, 'unoptimized'):
                    custody.checked_sources()
