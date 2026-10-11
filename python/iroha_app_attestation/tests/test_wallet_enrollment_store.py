"""Real SQLite custody/loss cases for the private verifier's existing-only journal."""
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from iroha_app_attestation.attestation import VerificationUnavailable
from iroha_app_attestation.wallet_enrollment_store import E1CounterStore


class StoreTests(unittest.TestCase):
    def directory(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name).resolve()
        path.chmod(0o700)
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        return path, fd

    def test_ordinary_open_never_creates_an_absent_store(self):
        path, fd = self.directory()
        with self.assertRaises(FileNotFoundError):
            E1CounterStore(path, fd)
        self.assertEqual(list(path.iterdir()), [])

    def test_explicit_initialization_preserves_generation_and_retained_rows_on_restart(self):
        path, fd = self.directory()
        owner = E1CounterStore.initialize(path, fd)
        with closing(owner._connect()) as connection:
            connection.execute("INSERT INTO wallet_e1_attempts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (b"operation", b"preparation", b"configuration", b"r" * 32,
                                b"b" * 32, b"original", b"s" * 64, b"\1" * 8, "evidence", b"result", None))
        original = (path / "wallet-e1.generation").read_bytes()
        owner.close()
        owner.close()
        with self.assertRaises(FileExistsError):
            E1CounterStore.initialize(path, fd)
        restarted = E1CounterStore(path, fd)
        self.addCleanup(restarted.close)
        with closing(restarted._connect()) as connection:
            self.assertEqual(connection.execute("SELECT original, result FROM wallet_e1_attempts").fetchall(),
                             [(b"original", b"result")])
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone(), (2,))
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        self.assertEqual((path / "wallet-e1.generation").read_bytes(), original)

    def test_partial_claims_cannot_pass_nullable_sqlite_checks(self):
        path, fd = self.directory()
        owner = E1CounterStore.initialize(path, fd)
        self.addCleanup(owner.close)
        complete = [b"operation", b"preparation", b"configuration", b"r" * 32,
                    b"b" * 32, b"original", b"s" * 64, b"\1" * 8, None, None, None]
        insert = "INSERT INTO wallet_e1_attempts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        with closing(owner._connect()) as connection:
            # SQLite CHECK accepts NULL. Each mandatory claim field needs an explicit
            # non-NULL predicate so a partly written claim can never resemble preparation.
            for index in (3, 4, 5, 6, 7):
                with self.subTest(missing=index):
                    row = complete.copy()
                    row[index] = None
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(insert, row)
                    self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (0,))
            # Exactly one outcome state: a result only with evidence, a code 1–10 only when refused.
            for outcome, result, code in (("evidence", None, None), ("refused", None, None),
                                          ("refused", None, 11), ("refused", None, 0),
                                          ("refused", b"result", 5), ("unavailable", b"result", None),
                                          ("unavailable", None, 5), ("issued", b"result", None),
                                          (None, b"result", None), (None, None, 5),
                                          ("refused", None, 5.5)):
                with self.subTest(outcome=outcome, result=result, code=code):
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(insert, complete[:8] + [outcome, result, code])
            for index, (outcome, result, code) in enumerate((("evidence", b"result", None),
                                                              ("refused", None, 10),
                                                              ("unavailable", None, None))):
                connection.execute(insert, [b"claimed%d" % index, *complete[1:3],
                                            bytes([index]) * 32, bytes([index + 8]) * 32,
                                            *complete[5:8], outcome, result, code])
            connection.execute(insert, complete)
            # An unclaimed preparation carries no dispatch time or outcome.
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(insert, [b"bad", b"prepared only", b"configuration", None, None,
                                            None, None, b"\1" * 8, None, None, None])
            connection.execute("INSERT INTO wallet_e1_attempts (operation_id, preparation, config_sha256) VALUES (?, ?, ?)",
                               (b"other", b"prepared only", b"configuration"))
            self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (5,))

    def test_lost_database_is_unavailable_and_generation_forbids_reinitialization(self):
        path, fd = self.directory()
        E1CounterStore.initialize(path, fd).close()
        original = (path / "wallet-e1.generation").read_bytes()
        (path / "wallet-e1.sqlite3").unlink()
        with self.assertRaises(FileNotFoundError):
            E1CounterStore(path, fd)
        with self.assertRaises(FileExistsError):
            E1CounterStore.initialize(path, fd)
        self.assertFalse((path / "wallet-e1.sqlite3").exists())
        self.assertEqual((path / "wallet-e1.generation").read_bytes(), original)

    def test_lost_generation_and_partial_initialization_are_not_repaired(self):
        path, fd = self.directory()
        E1CounterStore.initialize(path, fd).close()
        (path / "wallet-e1.generation").unlink()
        with self.assertRaises(FileNotFoundError):
            E1CounterStore(path, fd)
        with self.assertRaises(FileExistsError):
            E1CounterStore.initialize(path, fd)
        self.assertFalse((path / "wallet-e1.generation").exists())
        partial, partial_fd = self.directory()
        with patch.object(E1CounterStore, "_open_rw", side_effect=sqlite3.OperationalError("injected")):
            with self.assertRaises(sqlite3.OperationalError):
                E1CounterStore.initialize(partial, partial_fd)
        self.assertTrue((partial / "wallet-e1.generation").exists())
        with self.assertRaises(VerificationUnavailable):
            E1CounterStore(partial, partial_fd)
        with self.assertRaises(FileExistsError):
            E1CounterStore.initialize(partial, partial_fd)

    def test_missing_tables_and_added_triggers_are_never_repaired_or_executed(self):
        for mutation in ("DROP TABLE apple_client_data", "DROP TABLE wallet_e1_attempts",
                         "CREATE TRIGGER erase_attempts AFTER INSERT ON apple_keys "
                         "BEGIN DELETE FROM wallet_e1_attempts; END"):
            with self.subTest(mutation=mutation):
                path, fd = self.directory()
                E1CounterStore.initialize(path, fd).close()
                with closing(sqlite3.connect(path / "wallet-e1.sqlite3")) as connection:
                    connection.execute(mutation)
                    connection.commit()
                    original = connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall()
                with self.assertRaises(VerificationUnavailable):
                    E1CounterStore(path, fd)
                with closing(sqlite3.connect(path / "wallet-e1.sqlite3")) as connection:
                    self.assertEqual(connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall(), original)

    def test_foreign_database_generation_and_changed_marker_are_refused(self):
        path, fd = self.directory()
        other, other_fd = self.directory()
        E1CounterStore.initialize(path, fd).close()
        E1CounterStore.initialize(other, other_fd).close()
        shutil.copyfile(other / "wallet-e1.sqlite3", path / "wallet-e1.sqlite3")
        with self.assertRaisesRegex(VerificationUnavailable, "generation differs"):
            E1CounterStore(path, fd)
        owner = E1CounterStore(other, other_fd)
        self.addCleanup(owner.close)
        marker = other / "wallet-e1.generation"
        original = marker.read_bytes()
        marker.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(VerificationUnavailable, "generation changed"):
            owner.recheck()

    def test_missing_between_check_and_sqlite_open_is_not_created(self):
        path, fd = self.directory()
        owner = E1CounterStore.initialize(path, fd)
        self.addCleanup(owner.close)
        open_rw = E1CounterStore._open_rw
        def remove_before_open(selected):
            selected.unlink()
            return open_rw(selected)
        with patch.object(E1CounterStore, "_open_rw", side_effect=remove_before_open):
            with self.assertRaises(sqlite3.OperationalError):
                owner._connect()
        self.assertFalse((path / "wallet-e1.sqlite3").exists())

    def test_initializer_refuses_preexisting_symlink_and_private_owner_mismatch(self):
        path, fd = self.directory()
        (path / "wallet-e1.sqlite3").symlink_to(path / "missing")
        with self.assertRaises(FileExistsError):
            E1CounterStore.initialize(path, fd)
        self.assertFalse((path / "wallet-e1.generation").exists())
        path.chmod(0o750)
        with self.assertRaises(VerificationUnavailable):
            E1CounterStore.initialize(path, fd)
        path.chmod(0o700)

    def test_initialization_sync_failure_retains_generation_and_never_retries_creation(self):
        path, fd = self.directory()
        fsync = os.fsync
        def unavailable_parent(descriptor):
            if descriptor == fd:
                raise OSError("injected directory sync failure")
            fsync(descriptor)
        with patch("os.fsync", side_effect=unavailable_parent):
            with self.assertRaises(OSError):
                E1CounterStore.initialize(path, fd)
        self.assertTrue((path / "wallet-e1.generation").exists())
        self.assertFalse((path / "wallet-e1.sqlite3").exists())
        with self.assertRaises(FileNotFoundError):
            E1CounterStore(path, fd)
        with self.assertRaises(FileExistsError):
            E1CounterStore.initialize(path, fd)

    def test_generation_aliases_and_shared_modes_cannot_reopen_the_store(self):
        path, fd = self.directory()
        E1CounterStore.initialize(path, fd).close()
        marker = path / "wallet-e1.generation"
        alias = path / "alias"
        os.link(marker, alias)
        with self.assertRaises(VerificationUnavailable):
            E1CounterStore(path, fd)
        alias.unlink()
        marker.chmod(0o640)
        with self.assertRaises(VerificationUnavailable):
            E1CounterStore(path, fd)
        marker.chmod(0o600)
        marker.rename(alias)
        marker.symlink_to(alias)
        with self.assertRaises(OSError):
            E1CounterStore(path, fd)


if __name__ == "__main__":
    unittest.main()
