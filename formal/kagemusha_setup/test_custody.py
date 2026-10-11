"""Cheap source-inventory and pre-I/O optimized-mode refusal controls."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import custody


class CustodyTests(unittest.TestCase):
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
        for name in reconstruction:
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
