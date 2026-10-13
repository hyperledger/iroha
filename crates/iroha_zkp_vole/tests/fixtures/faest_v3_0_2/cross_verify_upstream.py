#!/usr/bin/env python3
"""Exchange fresh reference-mode signatures with unmodified FAEST v3.0.2.

Diagnostic only. Deterministic keys in the output are public test material.
The official C API is called through explicitly typed ctypes bindings; Rust
verification is a separate executable, and both return values are checked.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request

COMMIT = "4fb6b71143b37764546b7c7729440d9cd8898a5e"
ARCHIVE_SHA256 = "3caa4ee6f915edda17f8800be3ab77c69c12766651e320a8a8f453fa015d5cbd"
ARCHIVE_URL = f"https://codeload.github.com/faest-sign/faest-ref/tar.gz/{COMMIT}"
SEED = b"iroha FAEST v3.0.2 direct cross-verification / 2026-10-13 / v1"
SETS = [f"faest_{em}{bits}{speed}" for em in ("", "em_")
        for bits in (128, 192, 256) for speed in ("s", "f")]
MESON_OPTIONS = ["-Dbuildtype=release", "-Dopenssl=disabled", "-Daesni=disabled",
                 "-DSHA3=opt64", "-Dbenchmarks=disabled", "-Dcatch2=disabled",
                 "-Ddocs=disabled", "-Dtv-generators=disabled", "-Dvalgrind=disabled"]
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def material(label: str, length: int) -> bytes:
    return hashlib.shake_256(SEED + b"\0" + label.encode("ascii")).digest(length)


def fresh_secret_key(name: str) -> bytes:
    level = int(name.split("_")[-1][:-1]) // 8
    input_bytes = level if "_em_" in name else 16
    result = bytearray(material(name + "/secret-key", input_bytes + level))
    result[input_bytes] &= 0xFE  # Public test key satisfies k[0] * k[1] = 0.
    return bytes(result)


def negative_cases(pk: bytes, msg: bytes, sig: bytes, layout: list[tuple[str, int, int]]):
    """Length-preserving key/message changes and every reference signature field."""
    yield "wrong-message", pk, bytes([msg[0] ^ 1]) + msg[1:], sig
    yield "wrong-public-key", bytes([pk[0] ^ 1]) + pk[1:], msg, sig
    for label, offset, length in layout:
        if length <= 0 or not 0 <= offset < len(sig):
            raise ValueError("invalid field layout")
        changed = bytearray(sig)
        changed[offset] ^= 1
        yield f"flip-{label}", pk, msg, bytes(changed)
    for length in (0, 1, len(sig) // 2, len(sig) - 1):
        yield f"truncate-{length}", pk, msg, sig[:length]
    yield "trailing-byte", pk, msg, sig + b"\0"


class Commands:
    def __init__(self, log: Path):
        self.log = log
        self.log.write_text("", encoding="utf-8")

    def run(self, args, expected=0, env=None):
        args = list(map(str, args))
        result = subprocess.run(args, capture_output=True, text=True, timeout=1200, env=env)
        with self.log.open("a", encoding="utf-8") as log:
            log.write(json.dumps(args) + "\n" + result.stdout + result.stderr
                      + f"exit={result.returncode}\n")
        if result.returncode != expected:
            raise RuntimeError(f"{args}: expected {expected}, got {result.returncode}: "
                               f"{result.stdout}{result.stderr}")
        return result.stdout.strip()


def build_upstream(work: Path, meson: Path, ninja: Path, commands: Commands) -> tuple[Path, Path]:
    archive = work / "upstream.tar.gz"
    if not archive.exists():
        urllib.request.urlretrieve(ARCHIVE_URL, archive)
    if sha256(archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("upstream archive SHA-256 mismatch")
    # Extract each run: the pin must describe the sources actually compiled.
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            if (member.issym() or member.islnk() or member.name.startswith("/")
                    or ".." in Path(member.name).parts):
                raise ValueError("unexpected archive path")
        source.extractall(work, filter="data")
    source_dir = work / f"faest-ref-{COMMIT}"
    build = work / "build"
    env = dict(os.environ, PATH=str(ninja.parent) + os.pathsep + os.environ.get("PATH", ""))
    setup = [meson, "setup", build, source_dir, *MESON_OPTIONS]
    if (build / "build.ninja").exists():
        setup.append("--reconfigure")
    commands.run(setup, env=env)
    library_name = "libfaest.2.dylib" if platform.system() == "Darwin" else "libfaest.so.2.0.0"
    commands.run([ninja, "-C", build, library_name], env=env)
    return source_dir, build / library_name


class Upstream:
    """Exact public faest_param.h.in ABI (pointers never alias output buffers)."""

    def __init__(self, library: Path, name: str, signature_bytes: int):
        self.library = ctypes.CDLL(str(library))
        self.signature_bytes = signature_bytes
        self.sign_fn = getattr(self.library, name + "_sign_with_randomness")
        self.sign_fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_size_t)]
        self.sign_fn.restype = ctypes.c_int
        self.verify_fn = getattr(self.library, name + "_verify")
        self.verify_fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t]
        self.verify_fn.restype = ctypes.c_int
        self.validate_fn = getattr(self.library, name + "_validate_keypair")
        self.validate_fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.validate_fn.restype = ctypes.c_int

    def sign(self, sk: bytes, message: bytes, rho: bytes) -> bytes:
        output = ctypes.create_string_buffer(self.signature_bytes)
        length = ctypes.c_size_t(self.signature_bytes)
        code = self.sign_fn(sk, message, len(message), rho, len(rho), output, ctypes.byref(length))
        if code != 0 or length.value != self.signature_bytes:
            raise RuntimeError(f"upstream sign returned {code}, length {length.value}")
        return output.raw

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> int:
        return self.verify_fn(pk, message, len(message), signature, len(signature))


def source_inventory() -> dict[str, str]:
    paths = list((ROOT / "crates/iroha_zkp_vole/src").rglob("*.rs"))
    paths += list((ROOT / "vendor/aes").rglob("*.rs"))
    paths += [ROOT / value for value in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
              "crates/iroha_zkp_vole/Cargo.toml", "crates/iroha_zkp_vole/examples/faest_cross_verify.rs")]
    paths += [HERE / "cross_verify_upstream.py"]
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()) for path in sorted(paths)}


def append_case(path: Path, record: dict) -> None:
    """Retain completed cases before any later case or source guard can fail."""
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())


def retain_report(path: Path, report: dict, before: dict, after: dict) -> None:
    """Always preserve an unqualified report; refuse successful publication on drift."""
    changes = {name: {"before": before.get(name), "after": after.get(name)}
               for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)}
    report = dict(report, source_guard_passed=not changes, source_changes=changes,
                  publication_status="rejected_source_drift" if changes else "diagnostic_complete",
                  security_qualified=False)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    if changes:
        raise RuntimeError(f"source changed during campaign; unqualified report retained at {path}")


def campaign(work: Path, library: Path, binaries: dict[str, Path], commands: Commands) -> list[dict]:
    records = []
    checkpoint = work / "case_results.jsonl"
    checkpoint.write_text("", encoding="utf-8")
    for name in SETS:
        row = work / name
        row.mkdir(exist_ok=True)
        sk = fresh_secret_key(name)
        (row / "sk").write_bytes(sk)
        commands.run([binaries["portable"], "public-key", name, row / "sk", row / "pk"])
        pk = (row / "pk").read_bytes()
        layout = [tuple(line.split()) for line in commands.run([binaries["portable"], "layout", name]).splitlines()]
        layout = [(label, int(offset), int(length)) for label, offset, length in layout]
        size = sum(length for _, _, length in layout)
        if any(offset != sum(previous[2] for previous in layout[:i])
               for i, (_, offset, _) in enumerate(layout)):
            raise ValueError("noncontiguous reference layout")
        upstream = Upstream(library, name, size)
        if upstream.validate_fn(pk, sk) != 0:
            raise RuntimeError(f"upstream rejected fresh keypair for {name}")
        for origin, msg_len in (("upstream", 137), ("rust", 273)):
            msg = material(name + "/" + origin + "/message", msg_len)
            rho = material(name + "/" + origin + "/rho", int(name.split("_")[-1][:-1]) // 8)
            (row / "message").write_bytes(msg)
            (row / "rho").write_bytes(rho)
            if origin == "upstream":
                sig = upstream.sign(sk, msg, rho)
            else:
                commands.run([binaries["portable"], "sign", name, row / "sk", row / "message",
                              row / "rho", row / "signature"])
                sig = (row / "signature").read_bytes()
            if len(sig) != size:
                raise RuntimeError("wrong signature length")
            # Every fresh proof is independently verified by C and BOTH Rust builds.
            # The result does not depend on comparing signature bytes.
            if upstream.verify(pk, msg, sig) != 0:
                raise RuntimeError(f"C verifier rejected {origin} proof for {name}")
            (row / "signature").write_bytes(sig)
            for binary in binaries.values():
                commands.run([binary, "verify", name, row / "pk", row / "message", row / "signature"])
            # Accelerated signing independently creates the Rust-origin proof too.
            if origin == "rust":
                commands.run([binaries["accel"], "sign", name, row / "sk", row / "message",
                              row / "rho", row / "accelerated-signature"])
                accelerated = (row / "accelerated-signature").read_bytes()
                if upstream.verify(pk, msg, accelerated) != 0 or accelerated != sig:
                    raise RuntimeError("accelerated Rust proof rejected or differs")
            rejects = []
            for label, bad_pk, bad_msg, bad_sig in negative_cases(pk, msg, sig, layout):
                code = upstream.verify(bad_pk, bad_msg, bad_sig)
                if code == 0:
                    raise RuntimeError(f"C accepted negative {name}/{origin}/{label}")
                (row / "negative-pk").write_bytes(bad_pk)
                (row / "negative-message").write_bytes(bad_msg)
                (row / "negative-signature").write_bytes(bad_sig)
                for binary in binaries.values():
                    commands.run([binary, "verify", name, row / "negative-pk", row / "negative-message",
                                  row / "negative-signature"], expected=1)
                rejects.append({"case": label, "upstream_return": code, "rust_portable_exit": 1,
                                "rust_accel_exit": 1})
            records.append({"set": name, "origin": origin, "secret_key_hex": sk.hex(),
                            "public_key_hex": pk.hex(), "message_hex": msg.hex(), "rho_hex": rho.hex(),
                            "signature_hex": sig.hex(), "signature_bytes": size,
                            "signature_sha256": sha256(sig), "field_layout": layout,
                            "accepted_by": ["upstream", "rust-portable", "rust-accel"],
                            "accelerated_signing_verified_by_upstream": origin == "rust",
                            "negative_cases": rejects})
            append_case(checkpoint, records[-1])
            print(f"{name} {origin}: all verifiers accepted; {len(rejects)} negatives rejected by each", flush=True)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--meson", type=Path, required=True)
    parser.add_argument("--ninja", type=Path, required=True)
    parser.add_argument("--rust-portable", type=Path, required=True)
    parser.add_argument("--rust-accel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    commands = Commands(work / "commands.txt")
    binaries = {mode: getattr(args, "rust_" + mode).resolve() for mode in ("portable", "accel")}
    before = source_inventory()
    for mode, binary in binaries.items():
        if commands.run([binary, "identity"]) != mode:
            raise RuntimeError(f"wrong Rust feature identity for {mode}")
    source, library = build_upstream(work, args.meson.resolve(), args.ninja.resolve(), commands)
    records = campaign(work, library, binaries, commands)
    report = {"scope": "reference FAEST only; finite interoperability evidence, not security qualification",
              "seed_utf8": SEED.decode(), "upstream_commit": COMMIT,
              "upstream_archive_url": ARCHIVE_URL, "upstream_archive_sha256": ARCHIVE_SHA256,
              "upstream_library_sha256": sha256(library.read_bytes()),
              "upstream_api_source_sha256": sha256((source / "faest_param.c.in").read_bytes()),
              "meson_options": MESON_OPTIONS, "platform": platform.platform(),
              "python": platform.python_version(), "clang": commands.run(["clang", "--version"]),
              "rustc": commands.run(["rustc", "-Vv"]),
              "meson": commands.run([args.meson.resolve(), "--version"]),
              "ninja": commands.run([args.ninja.resolve(), "--version"]),
              "rust_binary_sha256": {mode: sha256(binary.read_bytes()) for mode, binary in binaries.items()},
              "rust_and_driver_source_sha256": before,
              "upstream_compiler_commands_sha256": sha256((library.parent / "compile_commands.json").read_bytes()),
              "command_log_sha256": sha256(commands.log.read_bytes()), "records": records}
    retain_report(args.output, report, before, source_inventory())
    print(f"PASS: {len(records)} fresh proofs, {sum(len(r['negative_cases']) for r in records)} negative inputs; "
          "C plus portable and accelerated Rust verification")


if __name__ == "__main__":
    main()
