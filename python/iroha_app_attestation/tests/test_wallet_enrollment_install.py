"""Explicit installer uses the real durable store and never repairs unavailable custody."""
from contextlib import closing, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hashlib
import json

from iroha_app_attestation.attestation import AttestationRejected, VerificationUnavailable
from iroha_app_attestation.revocation import (
    DENYLIST_CUSTODY, DenylistUpdateRejected, OperatorDenylistCustody,
)
from iroha_app_attestation.wallet_enrollment_install import (
    denylist, denylist_main, initialize_new, main,
)
from iroha_app_attestation.wallet_enrollment_store import E1CounterStore


class InstallTests(unittest.TestCase):
    def directory(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        store = root / "store"
        store.mkdir(mode=0o700)
        return root, store

    def test_initialize_reopen_and_second_install_never_clobbers(self):
        _, store = self.directory()
        initialize_new(store)
        original = {p.name: p.read_bytes() for p in store.iterdir()}
        fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            owner = E1CounterStore(store, fd)
            try:
                self.assertEqual(len(owner.incarnation), 32)
                with closing(owner._connect()) as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts")
                                     .fetchone(), (0,))
            finally:
                owner.close()
        finally:
            os.close(fd)
        with self.assertRaises(FileExistsError):
            initialize_new(store)
        self.assertEqual({p.name: p.read_bytes() for p in store.iterdir()}, original)

    def test_missing_relative_and_alias_paths_are_not_created_or_followed(self):
        root, store = self.directory()
        alias = root / "alias"
        alias.symlink_to(store, target_is_directory=True)
        for path in (root / "missing", Path("relative-store"), alias, store / ".." / "store"):
            with self.subTest(path=path):
                with self.assertRaises((OSError, VerificationUnavailable)):
                    initialize_new(path)
                self.assertEqual(list(store.iterdir()), [])
        self.assertFalse((root / "missing").exists())

    def test_shared_mode_and_foreign_owner_refuse_before_any_write(self):
        _, store = self.directory()
        store.chmod(0o755)
        with self.assertRaises(VerificationUnavailable):
            initialize_new(store)
        self.assertEqual(list(store.iterdir()), [])
        store.chmod(0o700)
        original_fstat = os.fstat
        selected = store.stat()
        def foreign(descriptor):
            value = original_fstat(descriptor)
            if (value.st_dev, value.st_ino) == (selected.st_dev, selected.st_ino):
                fields = list(value)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return value
        with patch("iroha_app_attestation.wallet_enrollment_store.os.fstat", foreign):
            with self.assertRaises(VerificationUnavailable):
                initialize_new(store)
        self.assertEqual(list(store.iterdir()), [])

    def test_existing_files_links_and_lost_database_are_not_a_new_store(self):
        root, store = self.directory()
        outside = root / "retained"
        outside.write_bytes(b"retained original")
        linked = store / "wallet-e1.generation"
        for kind in ("hard", "symbolic", "unrelated"):
            with self.subTest(kind=kind):
                if kind == "hard":
                    os.link(outside, linked)
                elif kind == "symbolic":
                    linked.symlink_to(outside)
                else:
                    linked.write_bytes(b"unrelated retained original")
                with self.assertRaises(FileExistsError):
                    initialize_new(store)
                self.assertEqual(outside.read_bytes(), b"retained original")
                self.assertEqual(len(list(store.iterdir())), 1)
                linked.unlink()
        initialize_new(store)
        original = linked.read_bytes()
        (store / "wallet-e1.sqlite3").unlink()
        with self.assertRaises(FileExistsError):
            initialize_new(store)
        self.assertEqual(linked.read_bytes(), original)
        self.assertFalse((store / "wallet-e1.sqlite3").exists())

    def test_directory_replacement_before_creation_does_not_retarget_held_owner(self):
        root, store = self.directory()
        initialize = E1CounterStore.initialize
        def replace(directory, descriptor):
            directory.rename(root / "retained-store")
            directory.mkdir(mode=0o700)
            return initialize(directory, descriptor)
        with patch.object(E1CounterStore, "initialize", side_effect=replace):
            with self.assertRaises(VerificationUnavailable):
                initialize_new(store)
        self.assertEqual(list(store.iterdir()), [])
        self.assertEqual(list((root / "retained-store").iterdir()), [])

    def test_partial_initialization_is_retained_and_refuses_retry(self):
        _, store = self.directory()
        with patch.object(E1CounterStore, "_open_rw", side_effect=sqlite3.OperationalError("injected")):
            with self.assertRaises(sqlite3.OperationalError):
                initialize_new(store)
        original = {p.name: p.read_bytes() for p in store.iterdir()}
        self.assertIn("wallet-e1.generation", original)
        with self.assertRaises(FileExistsError):
            initialize_new(store)
        self.assertEqual({p.name: p.read_bytes() for p in store.iterdir()}, original)

    def test_actual_module_command_is_explicit_and_reports_refusal(self):
        _, store = self.directory()
        command = [sys.executable, "-m", "iroha_app_attestation.wallet_enrollment_install",
                   "--store-directory", str(store)]
        first = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout.strip(), "private E1 store initialized")
        originals = {p.name: p.read_bytes() for p in store.iterdir()}
        second = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(second.stdout, "")
        self.assertIn("not repaired", second.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in store.iterdir()}, originals)

    def test_main_refusal_never_prints_selected_path_or_retained_bytes(self):
        _, store = self.directory()
        secret = store / "private-secret"
        secret.write_bytes(b"private original must not be logged")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(main(["--store-directory", str(store)]), 1)
        self.assertNotIn(str(store), stderr.getvalue())
        self.assertNotIn(secret.read_text(), stderr.getvalue())
        self.assertTrue(stat.S_ISREG(secret.stat().st_mode))


class DenylistInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.store = self.root / "store"
        self.store.mkdir(mode=0o700)

    def original(self, sequence, *entries):
        path = self.root / f"denylist-{sequence}.json"
        value = json.dumps({"version": 1, "sequence": sequence, "entries": list(entries)},
                           separators=(",", ":")).encode()
        path.write_bytes(value)
        return path, hashlib.sha256(value).hexdigest()

    def test_denylist_custody_needs_an_existing_store_a_pin_and_follows_rollback_rules(self):
        first, first_pin = self.original(1)
        # Only an existing, complete E1 store receives custody.
        with self.assertRaises(FileNotFoundError):
            denylist(self.store, first, first_pin, initialize=True)
        initialize_new(self.store)
        with self.assertRaisesRegex(AttestationRejected, "differs from its pin"):
            denylist(self.store, first, "00" * 32, initialize=True)
        self.assertFalse((self.store / DENYLIST_CUSTODY).exists())
        self.assertEqual(denylist(self.store, first, first_pin, initialize=True), "initialized")
        with self.assertRaises(FileExistsError):
            denylist(self.store, first, first_pin, initialize=True)
        self.assertEqual(denylist(self.store, first, first_pin, initialize=False), "unchanged")
        second, second_pin = self.original(2, {"serial": "2a"})
        self.assertEqual(denylist(self.store, second, second_pin, initialize=False), "accepted")
        with self.assertRaises(DenylistUpdateRejected):
            denylist(self.store, first, first_pin, initialize=False)
        fd = os.open(self.store, os.O_RDONLY)
        try:
            self.assertEqual(OperatorDenylistCustody(self.store, fd).active().sequence, 2)
        finally:
            os.close(fd)

    def test_denylist_command_reports_without_printing_paths(self):
        initialize_new(self.store)
        first, first_pin = self.original(1)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(denylist_main(["--store-directory", str(self.store), "--original", str(first),
                                            "--sha256", first_pin, "--initialize"]), 0)
        self.assertEqual(stdout.getvalue(), "operator denylist initialized\n")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(denylist_main(["--store-directory", str(self.store), "--original", str(first),
                                            "--sha256", "ab" * 32]), 1)
        self.assertNotIn(str(first), stderr.getvalue())
        self.assertIn("active custody unchanged", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
