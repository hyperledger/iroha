"""Explicit initialization and existing-only custody for the private E1 journal.

Initialization is an operator installation action for a genuinely new store. It is never
inferred from missing storage by a serving verifier. The durable generation original is
created first; an interrupted initialization remains unavailable and cannot silently reset
an old register. Privileged rollback of the whole directory remains outside this primitive.

A claimed attempt records its first dispatch time and exactly one outcome state: in flight
(NULL, unknown after any interruption), ``unavailable`` (a typed outage before any effect,
resumable while E1 is live), ``evidence`` (the retained verified projection) or ``refused``
(one closed refusal code). Only ``evidence`` and ``refused`` are terminal.
"""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import stat

from .attestation import DurableAppleAssertionCounterStore, VerificationUnavailable, require

_DATABASE = "wallet-e1.sqlite3"
_GENERATION = "wallet-e1.generation"
_PREFIX = b"iroha.wallet-e1.store.v2\x00"
_SCHEMA = {
    "apple_keys": """CREATE TABLE apple_keys (
        key_id BLOB PRIMARY KEY NOT NULL,
        point BLOB NOT NULL,
        app_id TEXT NOT NULL,
        environment TEXT NOT NULL,
        counter INTEGER NOT NULL CHECK(counter >= 0 AND counter < 4294967296)
    )""",
    "apple_client_data": """CREATE TABLE apple_client_data (
        client_data_sha256 BLOB PRIMARY KEY NOT NULL,
        key_id BLOB NOT NULL
    )""",
    "wallet_e1_attempts": """CREATE TABLE wallet_e1_attempts (
        operation_id BLOB PRIMARY KEY NOT NULL,
        preparation BLOB NOT NULL,
        config_sha256 BLOB NOT NULL,
        request_sha256 BLOB UNIQUE,
        key_binding BLOB UNIQUE,
        original BLOB,
        account_signature BLOB,
        first_dispatch BLOB,
        outcome TEXT,
        result BLOB,
        refusal_code INTEGER,
        CHECK ((request_sha256 IS NULL AND key_binding IS NULL AND original IS NULL
                AND account_signature IS NULL AND first_dispatch IS NULL AND outcome IS NULL
                AND result IS NULL AND refusal_code IS NULL)
            OR (request_sha256 IS NOT NULL AND length(request_sha256) = 32
                AND key_binding IS NOT NULL AND length(key_binding) = 32
                AND original IS NOT NULL
                AND account_signature IS NOT NULL AND length(account_signature) = 64
                AND first_dispatch IS NOT NULL AND length(first_dispatch) = 8)),
        CHECK ((outcome IS NULL AND result IS NULL AND refusal_code IS NULL)
            OR (outcome IS 'unavailable' AND result IS NULL AND refusal_code IS NULL)
            OR (outcome IS 'evidence' AND result IS NOT NULL AND refusal_code IS NULL)
            OR (outcome IS 'refused' AND result IS NULL AND typeof(refusal_code) IS 'integer'
                AND refusal_code >= 1 AND refusal_code <= 10))
    )""",
    "wallet_e1_store": """CREATE TABLE wallet_e1_store (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
        generation BLOB NOT NULL CHECK(length(generation) = 32)
    )""",
}
_INDEXES = {
    ("index", "sqlite_autoindex_apple_keys_1", "apple_keys", None),
    ("index", "sqlite_autoindex_apple_client_data_1", "apple_client_data", None),
    ("index", "sqlite_autoindex_wallet_e1_attempts_1", "wallet_e1_attempts", None),
    ("index", "sqlite_autoindex_wallet_e1_attempts_2", "wallet_e1_attempts", None),
    ("index", "sqlite_autoindex_wallet_e1_attempts_3", "wallet_e1_attempts", None),
}


def require_custody(condition, message):
    if not condition:
        raise VerificationUnavailable(message)


class E1CounterStore(DurableAppleAssertionCounterStore):
    """Open an existing complete counter/attempt register without creating or repairing it."""

    @staticmethod
    def _directory(directory: Path, directory_fd: int):
        require_custody(directory.is_absolute() and directory.resolve(strict=True) == directory,
                "invalid private store path")
        held, path = os.fstat(directory_fd), directory.stat()
        identity = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid)
        require_custody(stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid()
                and held.st_mode & 0o077 == 0 and identity(held) == identity(path),
                "private store directory changed")
        return identity(held)

    @staticmethod
    def _private(value):
        require_custody(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
                and value.st_mode & 0o077 == 0 and value.st_nlink == 1,
                "private E1 journal custody unavailable")
        return value.st_dev, value.st_ino

    @classmethod
    def initialize(cls, directory: Path, directory_fd: int):
        """Initialize once under the installation owner's independently authorized new-store action.

        Refuse any existing generation, database or sidecar. Neither serving startup nor a
        recovery request calls this method. On failure, retain every created original; a
        partially initialized directory requires explicit operator reconciliation.
        """
        selected = cls._directory(directory, directory_fd)
        for name in (_DATABASE, _DATABASE + "-journal", _DATABASE + "-wal", _DATABASE + "-shm"):
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError("private E1 journal already exists")
        generation = os.urandom(32)
        require_custody(any(generation), "private store generation unavailable")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        marker = os.open(_GENERATION, flags, 0o600, dir_fd=directory_fd)
        try:
            original = _PREFIX + generation
            offset = 0
            while offset < len(original):
                count = os.write(marker, original[offset:])
                require_custody(count > 0, "private store generation write failed")
                offset += count
            os.fsync(marker)
        finally:
            os.close(marker)
        os.fsync(directory_fd)
        require_custody(cls._directory(directory, directory_fd) == selected,
                "private store directory changed")
        database = os.open(_DATABASE, flags, 0o600, dir_fd=directory_fd)
        try:
            identity = cls._private(os.fstat(database))
            with closing(cls._open_rw(directory / _DATABASE)) as connection:
                require_custody(cls._private(os.stat(_DATABASE, dir_fd=directory_fd, follow_symlinks=False))
                        == identity, "private E1 journal replaced")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _SCHEMA.values():
                        connection.execute(statement)
                    connection.execute("INSERT INTO wallet_e1_store VALUES (1, ?)", (generation,))
                    connection.execute("COMMIT")
                except Exception:
                    connection.execute("ROLLBACK")
                    raise
            os.fsync(database)
            require_custody(cls._private(os.stat(_DATABASE, dir_fd=directory_fd, follow_symlinks=False))
                    == identity, "private E1 journal replaced")
        finally:
            os.close(database)
        os.fsync(directory_fd)
        require_custody(cls._directory(directory, directory_fd) == selected,
                "private store directory changed")
        return cls(directory, directory_fd)

    def __init__(self, directory: Path, directory_fd: int):
        self.directory, self.directory_fd = directory, directory_fd
        self.directory_identity = self._directory(directory, directory_fd)
        self.path = directory / _DATABASE
        self.generation_fd = self.database_fd = -1
        try:
            self.generation_fd = os.open(_GENERATION, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            metadata = os.fstat(self.generation_fd)
            self.generation_identity = self._private(metadata)
            self.generation_original = os.pread(self.generation_fd, len(_PREFIX) + 33, 0)
            require_custody(metadata.st_size == len(_PREFIX) + 32
                    and len(self.generation_original) == metadata.st_size
                    and self.generation_original.startswith(_PREFIX)
                    and any(self.generation_original[len(_PREFIX):]),
                    "invalid private store generation")
            self.incarnation = self.generation_original[len(_PREFIX):]
            self.database_fd = os.open(_DATABASE, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            self.file_identity = self._private(os.fstat(self.database_fd))
            # Deliberately do not call the base initializer: it creates missing tables.
            with closing(self._connect()):
                pass
        except Exception:
            self.close()
            raise

    def recheck_directory(self):
        require_custody(self._directory(self.directory, self.directory_fd) == self.directory_identity,
                "private store directory changed")

    def require_incarnation(self, connection, incarnation):
        """Bind prepared operations to this explicitly initialized, retained generation."""
        require(type(incarnation) is bytes and incarnation == self.incarnation,
                "journal incarnation differs")
        require_custody(connection.execute("SELECT singleton, generation FROM wallet_e1_store").fetchall()
                == [(1, self.incarnation)], "private E1 journal generation differs")

    def database_identity(self):
        return self._private(os.stat(_DATABASE, dir_fd=self.directory_fd, follow_symlinks=False))

    def recheck(self):
        self.recheck_directory()
        require_custody(self._private(os.fstat(self.database_fd)) == self.file_identity
                and self.database_identity() == self.file_identity,
                "private E1 journal replaced")
        require_custody(self._private(os.fstat(self.generation_fd)) == self.generation_identity
                and self._private(os.stat(_GENERATION, dir_fd=self.directory_fd, follow_symlinks=False))
                == self.generation_identity
                and os.pread(self.generation_fd, len(self.generation_original) + 1, 0)
                == self.generation_original, "private store generation changed")
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                value = os.stat(_DATABASE + suffix, dir_fd=self.directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            require_custody(suffix == "-journal", "unsupported private journal sidecar")
            self._private(value)

    @staticmethod
    def _open_rw(path):
        # SQLite's default mode creates missing files, including in a check/open race.
        connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                     isolation_level=None, timeout=30)
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
            require_custody(connection.execute("PRAGMA trusted_schema").fetchone() == (0,),
                    "private SQLite runtime lacks schema protection")
            require_custody(connection.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",),
                    "private SQLite journal mode unavailable")
            connection.execute("PRAGMA synchronous=FULL")
            require_custody(connection.execute("PRAGMA synchronous").fetchone() == (2,),
                    "private SQLite durability unavailable")
            return connection
        except Exception:
            connection.close()
            raise

    def _connect(self):
        self.recheck()
        connection = self._open_rw(self.path)
        try:
            self.recheck()
            expected = _INDEXES | {("table", name, name, sql) for name, sql in _SCHEMA.items()}
            require_custody(set(connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master")) == expected,
                    "invalid E1 journal schema")
            require_custody(connection.execute("SELECT singleton, generation FROM wallet_e1_store").fetchall()
                    == [(1, self.generation_original[len(_PREFIX):])],
                    "private E1 journal generation differs")
            self.recheck()
            return connection
        except Exception:
            connection.close()
            raise

    def close(self):
        """Release held originals; the caller retains ownership of the directory descriptor."""
        for name in ("database_fd", "generation_fd"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)
