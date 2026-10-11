"""Build the sole current private verifier archive from explicit source originals.

This produces unsigned bytes only. Native runtime admission selects and rechecks the exact
configured archive/executable originals; these hashes do not attest the host dependency closure.
"""
import argparse
import hashlib
import json
import os
import stat
import zipfile
from contextlib import ExitStack
from pathlib import Path

SOURCES = ("__init__.py", "attestation.py", "revocation.py", "native_time_interval.py",
           "wallet_policy.py", "wallet_enrollment.py", "wallet_enrollment_store.py",
           "wallet_enrollment_worker.py")


def build(package: Path, destination: Path):
    root = package / "src" / "iroha_app_attestation"
    if not root.is_absolute() or root.resolve(strict=True)!=root:
        raise ValueError("package source owner traverses an alias")
    if not destination.is_absolute() or destination.parent.resolve(strict=True) != destination.parent:
        raise ValueError("destination parent traverses an alias")
    def read_original(name, stack):
        source=root/name
        before=source.lstat()
        identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns,v.st_nlink)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=2*1024*1024:
            raise ValueError("source is not an original bounded regular file")
        held = stack.enter_context(source.open("rb"))
        def recheck():
            if identity(os.fstat(held.fileno()))!=identity(before):
                raise ValueError("source changed before read")
            if identity(os.fstat(held.fileno()))!=identity(before) or identity(source.lstat())!=identity(before):
                raise ValueError("source changed during read")
        recheck()
        value=held.read(2*1024*1024+1)
        if len(value) != before.st_size:
            raise ValueError("source changed during read")
        recheck()
        return value, recheck
    with ExitStack() as stack:
        originals, checks = {}, []
        for name in SOURCES:
            value, recheck = read_original(name, stack)
            originals["iroha_app_attestation/" + name] = value
            checks.append(recheck)
        originals["__main__.py"] = (b"from iroha_app_attestation.wallet_enrollment_worker import main\n"
            b"try:\n    main()\nexcept Exception:\n    raise SystemExit(1) from None\n")
        with destination.open("xb+") as original:
            with zipfile.ZipFile(original, "w", compression=zipfile.ZIP_STORED) as archive:
                for name in sorted(originals):
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.external_attr = 0o100444 << 16
                    archive.writestr(info, originals[name])
            for recheck in checks:
                recheck()
            original.flush()
            os.fchmod(original.fileno(), 0o444)
            os.fsync(original.fileno())
            identity = lambda m: (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns, m.st_mode)
            sealed = identity(os.fstat(original.fileno()))
            original.seek(0)
            value = original.read()
            for recheck in checks:
                recheck()
            if identity(os.fstat(original.fileno())) != sealed or identity(destination.lstat()) != sealed:
                raise ValueError("archive changed during seal")
            return {"schema": "iroha.kagemusha.wallet-e1-verifier-unsigned-build.v1",
                "archive_sha256": hashlib.sha256(value).hexdigest(),
                "sources": {name: hashlib.sha256(value).hexdigest() for name, value in sorted(originals.items())},
                "signed_runtime_admission": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    args.inventory.write_text(json.dumps(build(args.package, args.output), indent=2) + "\n")
