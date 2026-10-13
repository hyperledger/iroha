"""Synthetic fixtures for Torii's real Linux descriptor-worker test, never an issuer.

No worker mock, clock replacement or production admission is provided here. The separate
production zipapp does not include this file or synthetic_pki.py. All private keys are fresh
throwaway test keys retained only in the test's owner-only output directory.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys

PACKAGE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PACKAGE / "src"), str(PACKAGE / "tests")]

from iroha_app_attestation.attestation import children, der_one, primitive
from iroha_app_attestation.wallet_enrollment_install import initialize_new
from synthetic_pki import SignedEnvelope, apple_assertion, apple_object


class ExistingEnvelope(SignedEnvelope):
    """Reopen only this test's synthetic keys; never generate replacements on recovery."""

    def __init__(self, directory: Path, openssl: Path):
        self.directory, self.openssl = directory, openssl
        spki = children(der_one((directory / "leaf.spki").read_bytes()))
        self.point = primitive(spki[1], 3)[1:]


def snapshot(store: Path) -> dict:
    """Read the durable originals without changing or repairing the worker database."""
    with closing(sqlite3.connect((store / "wallet-e1.sqlite3").as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        def rows(table: str, order: str):
            cursor = connection.execute(f"SELECT * FROM {table} ORDER BY {order}")
            names = [entry[0] for entry in cursor.description]
            return [dict(zip(names, (value.hex() if isinstance(value, bytes) else value
                                     for value in row))) for row in cursor.fetchall()]
        return {"attempts": rows("wallet_e1_attempts", "operation_id"),
                "keys": rows("apple_keys", "key_id"),
                "consumed": rows("apple_client_data", "client_data_sha256"),
                "store": rows("wallet_e1_store", "singleton")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("initialize", "evidence", "snapshot"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--challenge")
    parser.add_argument("--binding")
    parser.add_argument("--app-id")
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.directory.resolve(strict=True)
    if directory != args.directory or args.openssl.resolve(strict=True) != args.openssl:
        raise ValueError("test paths must be canonical")
    if args.action == "initialize":
        if any(value is not None for value in (args.challenge, args.binding, args.app_id)):
            raise ValueError("unexpected fixture argument")
        # The caller created both empty private directories. This is the production
        # one-time installer, separate from the serving worker's no-reset path.
        SignedEnvelope(directory / "pki", args.openssl).root_der()
        initialize_new(directory / "store")
    elif args.action == "evidence":
        challenge, binding = bytes.fromhex(args.challenge), bytes.fromhex(args.binding)
        if len(challenge) != 32 or len(binding) != 32 or not args.app_id:
            raise ValueError("bounded challenge/binding/app fixture inputs required")
        fixture = ExistingEnvelope(directory / "pki", args.openssl)
        attestation, key_id, _ = apple_object(fixture, challenge, app_id=args.app_id)
        assertion = apple_assertion(fixture, binding, 1, app_id=args.app_id)
        for name, value in (("attestation.bin", attestation), ("key-id.bin", key_id),
                            ("assertion.bin", assertion)):
            with (directory / "pki" / name).open("xb") as output:
                output.write(value)
    else:
        if any(value is not None for value in (args.challenge, args.binding, args.app_id)):
            raise ValueError("unexpected fixture argument")
        print(json.dumps(snapshot(directory / "store"), sort_keys=True))


if __name__ == "__main__":
    main()
