"""Explicit offline installation of a private E1 store and its operator denylist custody.

Serving never imports or invokes these commands. They create neither a directory nor a
replacement store, and delegate every durable operation to its sole owner.
"""
import argparse
import hashlib
import os
from pathlib import Path
import sqlite3
import sys

from .attestation import AttestationRejected, VerificationUnavailable
from .revocation import MAX_DENYLIST_BYTES, OperatorDenylistCustody
from .wallet_enrollment_store import E1CounterStore


def _held_directory(directory: Path) -> int:
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise VerificationUnavailable("canonical existing private directory required")
    if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        raise VerificationUnavailable("descriptor-relative installation is unavailable")
    return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def initialize_new(directory: Path) -> None:
    """Initialize once in an existing, empty, private, canonical directory.

    Every created original is retained on failure. Missing or damaged storage is never
    interpreted as permission to repair, reset counters, or retry a fresh generation.
    """
    descriptor = _held_directory(directory)
    try:
        # Reuse the serving store's exact directory custody primitive. The empty-directory
        # precondition is an installation constraint, never a serving absence heuristic.
        E1CounterStore._directory(directory, descriptor)
        if os.listdir(descriptor):
            raise FileExistsError("new private store directory must be empty")
        owner = E1CounterStore.initialize(directory, descriptor)
        try:
            owner.recheck()
        finally:
            owner.close()
        E1CounterStore._directory(directory, descriptor)
    finally:
        os.close(descriptor)


def _authenticated_original(path: Path, sha256_hex: str) -> bytes:
    """Read the operator's reviewed denylist original and check its independent pin."""
    if (type(sha256_hex) is not str or len(sha256_hex) != 64
            or any(c not in "0123456789abcdef" for c in sha256_hex) or not path.is_absolute()):
        raise AttestationRejected("absolute denylist original and lowercase SHA-256 pin required")
    with path.open("rb") as original:
        value = original.read(MAX_DENYLIST_BYTES + 1)
    if hashlib.sha256(value).hexdigest() != sha256_hex:
        raise AttestationRejected("denylist original differs from its pin")
    return value


def denylist(directory: Path, original: Path, sha256_hex: str, *, initialize: bool) -> str:
    """Initialize or update the operator denylist custody of an existing Android E1 store.

    The original must match the operator-supplied SHA-256 pin. Initialization refuses any
    existing custody; an update follows the rollback rules and never repairs lost custody.
    """
    value = _authenticated_original(original, sha256_hex)
    descriptor = _held_directory(directory)
    try:
        # Only an existing, complete E1 store receives denylist custody.
        E1CounterStore(directory, descriptor).close()
        custody = OperatorDenylistCustody(directory, descriptor)
        if initialize:
            custody.initialize(value)
            return "initialized"
        return custody.offer(value)
    finally:
        os.close(descriptor)


def main(argv=None) -> int:
    """Run the explicit store installation; errors never remove or alter retained originals."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store-directory", type=Path, required=True,
                        help="absolute existing empty private directory owned by the service UID")
    arguments = parser.parse_args(argv)
    try:
        initialize_new(arguments.store_directory)
    except (OSError, ValueError, sqlite3.Error, VerificationUnavailable):
        print("private E1 store initialization refused; retained originals were not repaired",
              file=sys.stderr)
        return 1
    print("private E1 store initialized")
    return 0


def denylist_main(argv=None) -> int:
    """Install or update the operator denylist custody of an Android E1 store."""
    parser = argparse.ArgumentParser(description=denylist.__doc__)
    parser.add_argument("--store-directory", type=Path, required=True,
                        help="absolute existing private Android E1 store directory")
    parser.add_argument("--original", type=Path, required=True,
                        help="absolute path of the reviewed operator denylist original")
    parser.add_argument("--sha256", required=True,
                        help="independently reviewed SHA-256 of the original, lowercase hex")
    parser.add_argument("--initialize", action="store_true",
                        help="create the first custody; refused when custody exists")
    arguments = parser.parse_args(argv)
    try:
        outcome = denylist(arguments.store_directory, arguments.original, arguments.sha256,
                           initialize=arguments.initialize)
    except (OSError, ValueError, sqlite3.Error):
        print("operator denylist installation refused; active custody unchanged", file=sys.stderr)
        return 1
    print("operator denylist " + outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
