#!/usr/bin/env python3
"""Inspect an original armv7 diagnostic ELF with the selected NDK llvm-nm.

Python 3.12, standard library only. Called by compileArmv7Diagnostic after the
pinned native recipe and around exact diagnostic source-seal verification.
Requires explicit canonical library/tool paths; never builds, loads, publishes,
signs, installs, or promotes JNI/AAR bytes. Output grants no release admission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess


MAX_ORIGINAL_BYTES = 512 * 1024 * 1024
REQUIRED_BRIDGE_EXPORTS = {"connect_norito_bridge_abi_version", "connect_norito_free"}


def original(path: Path, *, executable: bool = False) -> tuple[bytes, tuple[int, ...]]:
    """Read a bounded original descriptor without links or file substitutions."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("diagnostic original path must be absolute and canonical")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_ORIGINAL_BYTES
            or (executable and not os.access(path, os.X_OK))):
        raise ValueError("diagnostic original must be a bounded single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        expected = identity(before)
        if identity(os.fstat(source.fileno())) != expected:
            raise ValueError("diagnostic original changed before descriptor admission")
        payload = source.read(MAX_ORIGINAL_BYTES + 1)
        if (len(payload) != before.st_size
                or identity(os.fstat(source.fileno())) != expected
                or identity(path.lstat()) != expected):
            raise ValueError("diagnostic original changed while reading")
    return payload, expected


def check_elf32_arm(payload: bytes) -> dict[str, object]:
    """Check ELF32 ARM shared-library identity and every bounded LOAD segment."""
    if len(payload) < 52 or payload[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("armv7 diagnostic requires little-endian ELF32")
    kind, machine, version, _, phoff, _, flags, ehsize, phsize, phcount, *_ = (
        struct.unpack_from("<HHIIIIIHHHHHH", payload, 16)
    )
    if kind != 3 or machine != 40 or version != 1:
        raise ValueError("armv7 diagnostic requires an ARM machine-40 shared library")
    if (ehsize != 52 or phsize != 32 or phcount in (0, 65535) or phoff < 52
            or phoff + phcount * phsize > len(payload)):
        raise ValueError("armv7 diagnostic has malformed ELF32 program headers")
    loads = []
    for index in range(phcount):
        kind, offset, address, _, filesz, memsz, _, alignment = struct.unpack_from(
            "<IIIIIIII", payload, phoff + index * phsize,
        )
        if kind != 1:
            continue
        if (alignment < 4096 or alignment & (alignment - 1)
                or (address - offset) % alignment or filesz > memsz
                or offset > len(payload) or filesz > len(payload) - offset):
            raise ValueError("armv7 diagnostic has a malformed or unaligned LOAD segment")
        loads.append({"alignmentBytes": alignment, "fileOffset": offset,
                      "virtualAddress": address, "fileBytes": filesz,
                      "memoryBytes": memsz})
    if not loads:
        raise ValueError("armv7 diagnostic has no LOAD segments")
    return {"class": "ELF32", "machine": machine, "flags": flags,
            "loadSegments": loads,
            "allLoadsAligned16KiB": all(item["alignmentBytes"] >= 16384 for item in loads)}


def inspect(library: Path, inspector: Path) -> dict[str, object]:
    """Retain actual exports without claiming JNI completeness or qualification."""
    payload, library_identity = original(library)
    tool, tool_identity = original(inspector, executable=True)
    elf = check_elf32_arm(payload)
    argv = [str(inspector), "--dynamic", "--defined-only", "--extern-only",
            "--format=just-symbols", str(library)]
    result = subprocess.run(argv, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                            capture_output=True, timeout=30, check=False)
    if (original(library) != (payload, library_identity)
            or original(inspector, executable=True) != (tool, tool_identity)):
        raise ValueError("diagnostic original changed during symbol inspection")
    if (result.returncode or result.stderr or not result.stdout
            or len(result.stdout) > 16 * 1024 * 1024):
        raise ValueError("selected NDK symbol inspector did not complete cleanly")
    raw = result.stdout.decode("utf-8", errors="strict")
    if not raw.endswith("\n") or "\r" in raw or "\x00" in raw:
        raise ValueError("diagnostic symbol output is malformed")
    symbols = raw[:-1].split("\n")
    if (len(symbols) != len(set(symbols)) or
            any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:@@?[A-Za-z0-9_.]+)?", item)
                for item in symbols)):
        raise ValueError("diagnostic symbol inventory is malformed")
    if not REQUIRED_BRIDGE_EXPORTS.issubset(symbols):
        raise ValueError("armv7 diagnostic lacks the baseline native bridge exports")
    return {
        "schema": "iroha.android-armv7-diagnostic.v1",
        "artifact_scope": "android-local-diagnostic",
        "abi": "armeabi-v7a", "target": "armv7-linux-androideabi",
        "release_admitted": False,
        "library": {"path": str(library), "sha256": hashlib.sha256(payload).hexdigest(),
                    "sizeBytes": len(payload), "elf": elf},
        "symbolInspector": {"path": str(inspector), "sha256": hashlib.sha256(tool).hexdigest(),
                            "argv": argv, "exitCode": result.returncode,
                            "stdoutSha256": hashlib.sha256(result.stdout).hexdigest()},
        "nativeExports": symbols,
        "jniExportCount": sum(item.startswith("Java_") for item in symbols),
        "limits": ["static_original_ELF_and_export_observation_only",
                   "no_AAR_JNI_promotion_or_release_admission",
                   "JNI_completeness_proofs_runtime_memory_and_physical_support_unqualified"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--symbol-inspector", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.library, args.symbol_inspector), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"armv7 diagnostic inspection failed: {error}") from error
