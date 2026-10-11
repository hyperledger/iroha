#!/usr/bin/env python3
"""Check compiled Kotlin declarations against the native bridge's export table.

Requires Python 3.10+ and compiled main class directories for all three SDK
modules. Host checks use nm/llvm-nm (or Windows export tooling). Android checks
require an explicit canonical llvm-nm executable, its SHA-256 and byte size, an
ABI, and a fresh original-inspection output directory. No JVM classes or native
code are loaded. No environment variables are required or accepted by the
pinned Android subprocess.

This checks declaration ownership, JDK 8 bytecode, release API constraints, and
exact JNI export ownership. Export names alone cannot attest native argument
types or receiver semantics. The report seals the inspected class files and
library; it does not replace signature validation, source-bound build provenance,
native execution, or hardware qualification. C exports are checked by
check_native_sdk_artifact.py.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from typing import Sequence


def _load_sibling(name: str):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


JVM = _load_sibling("jvm_classfile")
ARTIFACT = _load_sibling("check_native_sdk_artifact")
MODULES = ("core-jvm", "client-android", "kagemusha-wallet-android")
SDK_PACKAGE = "org/hyperledger/iroha/sdk/"
MAX_CLASS_FILES = 20_000
ANDROID_MACHINES = {"arm64-v8a": 183, "armeabi-v7a": 40, "x86_64": 62}
ANDROID_ELF_CLASSES = {"arm64-v8a": 2, "armeabi-v7a": 1, "x86_64": 2}
ANDROID_SYMBOL_ENVIRONMENT = {"PATH": "/usr/bin:/bin", "TMPDIR": "/tmp",
                              "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
ANDROID_SYMBOL_ARGUMENTS = ("--dynamic", "--defined-only", "--extern-only", "--format=just-symbols")
MAX_PINNED_TOOL_BYTES = 128 * 1024 * 1024
MAX_ANDROID_LIBRARY_BYTES = 1024 * 1024 * 1024


class AuditError(ValueError):
    """The compiled SDK and the library do not form the canonical JNI boundary."""


def _file_metadata(value: os.stat_result) -> dict[str, int]:
    """Record identity and mutation counters from one actual file observation."""
    return {name: getattr(value, "st_" + name) for name in
            ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")}


@contextmanager
def _sealed_input(path: Path, *, label: str, maximum: int,
                  expected_sha256: str | None = None, expected_size: int | None = None,
                  executable: bool = False):
    """Hold and seal a canonical single-link file; never follow a substituted link."""
    if not path.is_absolute() or str(path) != str(path.resolve(strict=True)):
        raise AuditError(f"{label} must be an absolute canonical path without symlinks")
    original = path.lstat()
    if (not stat.S_ISREG(original.st_mode) or original.st_nlink != 1
            or original.st_mode & 0o022
            or (executable and not original.st_mode & 0o111)
            or not 0 < original.st_size <= maximum):
        raise AuditError(f"{label} must be a bounded regular single-link file with safe permissions")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = _file_metadata(original)

        def observe():
            if (str(path) != str(path.resolve(strict=True))
                    or _file_metadata(os.fstat(stream.fileno())) != metadata
                    or _file_metadata(path.lstat()) != metadata):
                raise AuditError(f"{label} changed during inspection")
            stream.seek(0)
            digest, count, prefix = hashlib.sha256(), 0, b""
            while chunk := stream.read(min(1024 * 1024, maximum - count + 1)):
                if not prefix:
                    prefix = chunk[:64]
                count += len(chunk)
                if count > maximum:
                    raise AuditError(f"{label} exceeded its byte limit")
                digest.update(chunk)
            if (count != original.st_size or _file_metadata(os.fstat(stream.fileno())) != metadata
                    or _file_metadata(path.lstat()) != metadata):
                raise AuditError(f"{label} changed during inspection")
            return digest.hexdigest(), count, prefix

        digest, size, prefix = observe()
        if ((expected_sha256 is not None and digest != expected_sha256)
                or (expected_size is not None and size != expected_size)):
            raise AuditError(f"{label} does not match its explicit SHA-256 and size pin")
        record = {"path": str(path), "sha256": digest, "size_bytes": size, "identity": metadata}

        def recheck():
            if observe()[:2] != (digest, size):
                raise AuditError(f"{label} changed during inspection")

        yield record, prefix, recheck


def _write_original(directory: Path, name: str, raw: bytes) -> dict[str, object]:
    """Retain exact owned bytes exclusively, with no overwrite or symlink follow."""
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def _json_original(directory: Path, name: str, value: object) -> dict[str, object]:
    """Retain a producer-authored record separately from actual child streams."""
    return _write_original(directory, name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def _collect_symbol_probe(command: Sequence[str], *, timeout_seconds: float = 30) -> tuple[bytes, bytes, dict[str, object]]:
    """Collect a POSIX symbol-tool child within finite stream and wall limits."""
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
        raise AuditError("invalid bounded symbol-tool deadline")
    buffers = [bytearray(), bytearray()]
    limits = (ARTIFACT.MAX_SYMBOL_TOOL_OUTPUT_BYTES, ARTIFACT.MAX_PROBE_STDERR_BYTES)
    outcome = {"started_at": datetime.now(timezone.utc).isoformat(), "exit_code": None,
               "transport_error": None, "streams_complete": False}
    process = None
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(ANDROID_SYMBOL_ENVIRONMENT),
                                   close_fds=True, bufsize=0)
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"symbol-tool probe exceeded its {timeout_seconds} second deadline")
                for key, _ in selector.select(min(remaining, 0.1)):
                    index = key.data
                    try:
                        raw = os.read(key.fd, min(65536, limits[index] - len(buffers[index]) + 1))
                    except BlockingIOError:
                        continue
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[index].extend(raw)
                    if len(buffers[index]) > limits[index]:
                        raise AuditError("symbol-tool " + ("stdout" if index == 0 else "stderr")
                                         + " exceeded its byte limit; retained stream is incomplete")
            outcome["exit_code"] = process.wait(timeout=0)
            outcome["streams_complete"] = True
    except (OSError, subprocess.SubprocessError, AuditError) as error:
        outcome["transport_error"] = {"kind": type(error).__name__, "message": str(error)}
    finally:
        if process is not None:
            ARTIFACT._stop_owned_probe(process)
            outcome["exit_code"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        outcome["completed_at"] = datetime.now(timezone.utc).isoformat()
    return bytes(buffers[0]), bytes(buffers[1]), outcome


def inspect_pinned_android_symbols(library: Path, *, abi: str, tool: Path,
                                   tool_sha256: str, tool_size_bytes: int,
                                   output: Path) -> tuple[tuple[str, ...], dict[str, object]]:
    """Inspect an Android ELF using only the explicit tool and preserve originals."""
    if (os.name != "posix" or abi not in ANDROID_MACHINES
            or type(tool_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", tool_sha256)
            or tool_sha256 == "0" * 64 or type(tool_size_bytes) is not int
            or not 0 < tool_size_bytes <= MAX_PINNED_TOOL_BYTES):
        raise AuditError("pinned Android inspection requires a POSIX host, exact ABI and nonzero tool SHA-256/size")
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not output.parent.is_dir() or str(output.parent) != str(output.parent.resolve(strict=True))):
        raise AuditError("inspection output must be fresh beneath an absolute canonical existing directory")
    with _sealed_input(tool, label="symbol tool", maximum=MAX_PINNED_TOOL_BYTES,
                       expected_sha256=tool_sha256, expected_size=tool_size_bytes, executable=True) as tool_input:
        with _sealed_input(library, label="Android library", maximum=MAX_ANDROID_LIBRARY_BYTES) as library_input:
            tool_record, _, recheck_tool = tool_input
            library_record, header, recheck_library = library_input
            elf_class = ANDROID_ELF_CLASSES[abi]
            header_size = 52 if elf_class == 1 else 64
            if (len(header) < header_size
                    or header[:7] != b"\x7fELF" + bytes((elf_class, 1, 1))
                    or int.from_bytes(header[16:18], "little") != 3
                    or int.from_bytes(header[18:20], "little") != ANDROID_MACHINES[abi]
                    or int.from_bytes(header[20:24], "little") != 1):
                raise AuditError("Android library must be a little-endian ET_DYN with the exact ABI ELF class and machine")
            command = [str(tool), *ANDROID_SYMBOL_ARGUMENTS, str(library)]
            invocation = {"schema": "iroha.android.jni-symbol-inspection.v1", "android_abi": abi,
                          "tool": tool_record, "library": library_record, "argv": command,
                          "environment": dict(ANDROID_SYMBOL_ENVIRONMENT)}
            output.mkdir(mode=0o700)
            originals = {"invocation": _json_original(output, "invocation.json", invocation)}
            recheck_tool()
            recheck_library()
            stdout, stderr, outcome = _collect_symbol_probe(command)
            originals["stdout"] = _write_original(output, "stdout.bin", stdout)
            originals["stderr"] = _write_original(output, "stderr.bin", stderr)
            originals["result"] = _json_original(output, "result.json", outcome)
            try:
                recheck_tool()
                recheck_library()
            except (AuditError, OSError) as error:
                _json_original(output, "input-guards.json", {"valid": False, "error": str(error)})
                raise
            originals["input_guards"] = _json_original(output, "input-guards.json", {"valid": True})
            if (outcome["transport_error"] is not None or not outcome["streams_complete"]
                    or outcome["exit_code"] != 0 or stderr):
                raise AuditError(f"pinned Android symbol inspection failed; original streams/results retained in {output}")
            try:
                symbols = tuple(stdout.decode("ascii").splitlines())
            except UnicodeDecodeError as error:
                raise AuditError("pinned Android symbol inventory is not ASCII") from error
            if (not symbols or len(symbols) > 100_000
                    or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) for symbol in symbols)):
                raise AuditError("pinned Android symbol inventory contains empty, decorated or malformed symbols")
            return symbols, {**invocation, "originals": originals, "tool_pinned": True}


def jni_escape(value: str) -> str:
    """Mangle a JVM internal name using UTF-16 code units, including nested types."""
    escaped = []
    for character in value:
        # JNI Design, "Resolving Native Method Names": digit 0..3 at
        # the start or after a slash escape makes native lookup fail.
        if character in "0123" and (not escaped or escaped[-1].endswith("_")):
            raise AuditError(f"JNI name cannot be resolved: {value!r}")
        if character == "/":
            escaped.append("_")
        elif character in {"_", ";", "["}:
            escaped.append({"_": "_1", ";": "_2", "[": "_3"}[character])
        elif character.isascii() and character.isalnum():
            escaped.append(character)
        else:
            encoded = character.encode("utf-16-be")
            escaped.extend("_0" + encoded[i:i + 2].hex() for i in range(0, len(encoded), 2))
    return "".join(escaped)


def native_operations(class_file) -> tuple[dict[str, object], ...]:
    """Derive the exact JNI symbol for every native method in one class."""
    natives = [method for method in class_file.methods if method.native]
    names = Counter(method.name for method in natives)
    operations = []
    for method in natives:
        symbol = "Java_" + jni_escape(class_file.name) + "_" + jni_escape(method.name)
        if names[method.name] > 1:
            parameters, _ = JVM.method_descriptor(method.descriptor)
            symbol += "__" + jni_escape("".join(parameters))
        operations.append({
            "class": class_file.name,
            "method": method.name,
            "descriptor": method.descriptor,
            "static": method.static,
            "symbol": symbol,
        })
    return tuple(operations)


def validate_retired_privacy_witness_classes(classes: dict[str, object]) -> None:
    """Reject orphan archive owners and historical test fixtures in compiled main outputs."""
    for owner, class_file in classes.items():
        if "PrivacyConfidential" in owner or "PrivacyConfidentialWitness" in (class_file.source_file or ""):
            raise AuditError(f"retired confidential witness or test fixture in main classes: {owner}")


def validate_privacy_api(classes: dict[str, object]) -> None:
    """Check the shared privacy method contract from class metadata, never reflection."""
    validate_retired_privacy_witness_classes(classes)
    privacy_name = SDK_PACKAGE + "privacy/PrivacyNativeBridge"
    if privacy_name not in classes:
        raise AuditError(f"required SDK class is missing: {privacy_name}")
    privacy = classes[privacy_name]
    for name, descriptor in (
        ("nativeValidateCompiledProfileCatalog", "([B)I"),
        ("nativeExact12FixtureBundle", "()[B"),
        ("nativeValidateExact12FixtureBundle", "([B)I"),
        ("nativeValidateExact12CapabilityManifestForNetworkV1", "([B[B)I"),
        ("nativeRequireExact12CapabilityTupleForNetworkV1", "([BI[B)Z"),
        ("nativeValidateExact12SubmitProofConstructionForNetworkV1", "([BI[B[B)Z"),
    ):
        matches = [method for method in privacy.methods if method.name == name]
        if len(matches) != 1 or matches[0].descriptor != descriptor or not matches[0].native or not matches[0].static:
            raise AuditError(f"privacy operation must retain its native declaration: {name}{descriptor}")
    for owner, class_file in classes.items():
        if owner in (privacy_name, privacy_name + "$Companion"):
            for method in class_file.methods:
                if any(fragment in method.name for fragment in ("ProofRequest", "BuildProof", "VerifyProof")) or method.name in ("buildProof", "verifyProof"):
                    raise AuditError(f"unqualified generic privacy proof method: {owner}.{method.name}")
                if method.name in (
                    "nativeValidateExact12CapabilityManifest",
                    "nativeRequireExact12CapabilityTuple",
                    "nativeValidateExact12SubmitProofConstruction",
                ):
                    raise AuditError(f"retired privacy method lacks network binding: {owner}.{method.name}")


def audit_privacy_classfiles(root: Path) -> dict[str, object]:
    """Inspect the privacy API and seal main classes for absence of retired witness fixtures."""
    root = root.resolve(strict=True)
    classes = {}
    records = []
    for suffix in ("", "$Companion"):
        name = SDK_PACKAGE + "privacy/PrivacyNativeBridge" + suffix
        path = root / (name + ".class")
        if path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(root):
            raise AuditError(f"invalid compiled privacy owner: {path}")
        with path.open("rb") as stream:
            raw = stream.read(JVM.MAX_CLASS_BYTES + 1)
        declaration = JVM.parse_class(raw)
        if declaration.name != name or declaration.major != 52 or declaration.source_file != "PrivacyNativeBridge.kt":
            raise AuditError(f"privacy class must be the canonical Kotlin JDK8 owner: {path}")
        classes[name] = declaration
        records.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "class": name})
    paths = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise AuditError(f"class output contains a symlink: {path}")
        if path.suffix == ".class":
            if not path.is_file():
                raise AuditError(f"class input is not a regular file: {path}")
            paths.append(path)
            if len(paths) > MAX_CLASS_FILES:
                raise AuditError("compiled class inventory exceeds the entry limit")
    for path in sorted(paths):
        name = path.relative_to(root).as_posix()[:-6]
        if name in classes:
            continue
        with path.open("rb") as stream:
            raw = stream.read(JVM.MAX_CLASS_BYTES + 1)
        declaration = JVM.parse_class(raw)
        if declaration.name != name:
            raise AuditError(f"class path and declared owner differ: {path}")
        classes[name] = declaration
        records.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "class": name})
    validate_privacy_api(classes)
    if set(paths) != set(root.rglob("*.class")):
        raise AuditError("compiled main class inventory changed while inspected")
    if any(hashlib.sha256(Path(record["path"]).read_bytes()).hexdigest() != record["sha256"] for record in records):
        raise AuditError("compiled privacy classes changed while inspected")
    return {"scope": "compiled privacy API metadata only", "native_executed": False, "release_qualified": False, "classes": records}


def validate_release_api(classes: dict[str, object]) -> None:
    """Retain fail-closed privacy and explicit signing context API assertions."""
    privacy_name = SDK_PACKAGE + "privacy/PrivacyNativeBridge"
    signer_name = SDK_PACKAGE + "crypto/NativeSignerBridge"
    codec_name = SDK_PACKAGE + "tx/norito/NoritoJavaCodecAdapter"
    for required in (privacy_name, signer_name, codec_name):
        if required not in classes:
            raise AuditError(f"required SDK class is missing: {required}")
    if any(method.name == "<init>" and method.descriptor == "()V"
           and method.flags & JVM.ACC_PUBLIC for method in classes[codec_name].methods):
        raise AuditError("codec adapter construction requires explicit chain context")
    validate_privacy_api(classes)
    for owner, class_file in classes.items():
        if owner in (signer_name, signer_name + "$Companion"):
            for method in class_file.methods:
                if method.name in {
                    prefix + operation + "SignedTransaction"
                    for prefix in ("encode", "nativeEncode")
                    for operation in ("Shield", "ZkTransfer", "Unshield")
                }:
                    raise AuditError(f"retired transaction signer method: {owner}.{method.name}")
    for retired in ("ShieldInstruction", "ZkTransferInstruction", "UnshieldInstruction"):
        if SDK_PACKAGE + "core/model/instructions/" + retired in classes:
            raise AuditError(f"retired instruction class: {retired}")
    signer = classes[signer_name]
    account_validation = [method for method in signer.methods
                          if method.name == "nativeValidateAccountAddressCanonical"]
    if (len(account_validation) != 1
            or account_validation[0].descriptor != "([B)[B"
            or not account_validation[0].native
            or not account_validation[0].static):
        raise AuditError("complete account admission requires the canonical static native byte-array boundary")
    for owner, class_file in classes.items():
        if owner in (SDK_PACKAGE + "address/AccountAddress", SDK_PACKAGE + "address/AccountAddress$Companion"):
            if any(method.name == "configureCurveSupport" or method.name.endswith("IgnoringCurveSupport")
                   for method in class_file.methods):
                raise AuditError("account identity must use the fixed V1 algorithm catalog")
    if SDK_PACKAGE + "address/CurveSupportConfig" in classes:
        raise AuditError("retired global account curve configuration is present")
    public = [method for owner, class_file in classes.items()
              if owner in (signer_name, signer_name + "$Companion")
              for method in class_file.methods
              if method.name == "encodeRegisterZkAssetSignedTransaction" and method.flags & JVM.ACC_PUBLIC]
    native = [method for method in signer.methods
              if method.name == "nativeEncodeRegisterZkAssetSignedTransaction" and method.native]
    if not public or len(native) != 1:
        raise AuditError("canonical register-asset signer declarations are missing")
    for method, network_type in [
        *((method, "L" + SDK_PACKAGE + "core/model/NetworkId;") for method in public),
        *((method, "[B") for method in native),
    ]:
        parameters, _ = JVM.method_descriptor(method.descriptor)
        if len(parameters) < 3 or parameters[1:3] != (network_type, "I"):
            raise AuditError("register-asset signing requires explicit network identity and chain discriminant")


def scan_classes(roots: dict[str, Sequence[Path]]) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Scan every module's supplied main output, rejecting omitted or duplicate inputs."""
    if set(roots) != set(MODULES) or any(not roots[module] for module in MODULES):
        raise AuditError("compiled main classes are required for all three Kotlin SDK modules")
    classes = {}
    records = []
    seen_roots = set()
    for module in MODULES:
        for root in roots[module]:
            root = root.resolve(strict=True)
            if root in seen_roots or not root.is_dir():
                raise AuditError(f"invalid or repeated class directory: {root}")
            seen_roots.add(root)
            paths = []
            for entry in root.rglob("*"):
                # pathlib does not descend through directory symlinks. Reject
                # them explicitly so they cannot hide retired declarations.
                if entry.is_symlink():
                    raise AuditError(f"class output contains a symlink: {entry}")
                if entry.suffix == ".class":
                    if not entry.is_file():
                        raise AuditError(f"class input is not a regular file: {entry}")
                    paths.append(entry)
                    if len(records) + len(paths) > MAX_CLASS_FILES:
                        raise AuditError("compiled class inventory exceeds the entry limit")
            paths.sort()
            if not paths:
                raise AuditError(f"class directory is empty: {root}")
            for path in paths:
                if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
                    raise AuditError(f"class file escapes its build output: {path}")
                with path.open("rb") as stream:
                    raw = stream.read(JVM.MAX_CLASS_BYTES + 1)
                declaration = JVM.parse_class(raw)
                if path.relative_to(root).as_posix() != declaration.name + ".class":
                    raise AuditError(f"class path and declared owner differ: {path}")
                if declaration.name in classes:
                    raise AuditError(f"duplicate compiled class: {declaration.name}")
                if declaration.major != 52:
                    raise AuditError(f"SDK bytecode must target JDK 8: {declaration.name} has major {declaration.major}")
                natives = native_operations(declaration)
                if natives and (not declaration.name.startswith(SDK_PACKAGE)
                                or not declaration.source_file
                                or not declaration.source_file.endswith(".kt")):
                    raise AuditError(f"native declarations must belong to the Kotlin SDK: {declaration.name}")
                classes[declaration.name] = declaration
                records.append({"module": module, "class": declaration.name,
                                "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                                "source_file": declaration.source_file,
                                "operations": list(natives)})
    if not any(record["operations"] for record in records):
        raise AuditError("compiled SDK declares no native methods")
    validate_release_api(classes)
    return classes, records


def validate_exports(operations: Sequence[dict[str, object]], symbols: Sequence[str]) -> None:
    """Require exact JNI ownership; stale namespaces and undeclared methods fail."""
    expected = [operation["symbol"] for operation in operations]
    if not expected or len(set(expected)) != len(expected):
        raise AuditError("JNI declarations are empty or have colliding mangled symbols")
    observed = [symbol for symbol in symbols if symbol.startswith("Java_")]
    if len(set(observed)) != len(observed):
        raise AuditError("native library contains duplicate JNI export symbols")
    missing = sorted(set(expected) - set(observed))
    unowned = sorted(set(observed) - set(expected))
    if missing or unowned:
        details = []
        if missing:
            details.append(f"{len(missing)} missing JNI exports: " + ", ".join(missing[:20]))
        if unowned:
            details.append(f"{len(unowned)} unowned JNI exports: " + ", ".join(unowned[:20]))
        raise AuditError("; ".join(details))


def audit(roots: dict[str, Sequence[Path]], library: Path, *, platform: str = "host",
          android_abi: str | None = None, symbol_tool: Path | None = None,
          symbol_tool_sha256: str | None = None, symbol_tool_size_bytes: int | None = None,
          inspection_output: Path | None = None) -> dict[str, object]:
    """Seal the inspected inputs around a complete compiled declaration/export check."""
    pinned_arguments = (android_abi, symbol_tool, symbol_tool_sha256, symbol_tool_size_bytes, inspection_output)
    if platform not in ("host", "android") or (platform == "host" and any(value is not None for value in pinned_arguments)):
        raise AuditError("explicit pinned symbol-tool arguments belong only to --platform android")
    if platform == "android" and any(value is None for value in pinned_arguments):
        raise AuditError("Android inspection requires explicit ABI, symbol-tool SHA-256/size/path and original output")
    if inspection_output is not None and any(
        inspection_output.resolve().is_relative_to(root.resolve()) for paths in roots.values() for root in paths
    ):
        raise AuditError("inspection output must be outside compiled class inputs")
    _, records = scan_classes(roots)
    if platform == "host":
        library = library.resolve(strict=True)
    digest, size = ARTIFACT.stable_artifact_identity(library)
    if platform == "android":
        symbols, inspection = inspect_pinned_android_symbols(
            library, abi=android_abi, tool=symbol_tool, tool_sha256=symbol_tool_sha256,
            tool_size_bytes=symbol_tool_size_bytes, output=inspection_output)
        if (inspection["library"]["sha256"], inspection["library"]["size_bytes"]) != (digest, size):
            raise AuditError("native library changed before pinned inspection")
    else:
        symbols = ARTIFACT.inspect_exported_symbols(library, required=True)
        inspection = {"tool_pinned": False, "scope": "host_platform_tool_discovery"}
    operations = [dict(operation, module=record["module"]) for record in records
                  for operation in record["operations"]]
    validate_exports(operations, symbols)
    if ARTIFACT.stable_artifact_identity(library) != (digest, size):
        raise AuditError("native library changed during inspection")
    _, after = scan_classes(roots)
    if records != after:
        raise AuditError("compiled SDK classes changed during inspection")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": 1,
        "valid": True,
        "scope": "compiled_kotlin_declarations_and_exact_jni_export_ownership",
        "platform": platform,
        "symbol_inspection": inspection,
        "native_signatures_qualified": False,
        "native_execution_qualified": False,
        "source_build_provenance_qualified": False,
        "library": {"path": str(library), "sha256": digest, "size_bytes": size},
        "class_inventory_sha256": hashlib.sha256(encoded).hexdigest(),
        "class_count": len(records),
        "native_method_count": len(operations),
        "operations": sorted(operations, key=lambda operation: operation["symbol"]),
        "classes": [{key: value for key, value in record.items() if key != "operations"}
                    for record in records],
    }


def write_report(path: Path, result: dict[str, object]) -> None:
    """Atomically publish evidence without truncating a hardlinked build input."""
    if path.is_symlink():
        raise AuditError("report destination must not be a symlink")
    if path.exists():
        inputs = [Path(result["library"]["path"]),
                  *(Path(record["path"]) for record in result["classes"])]
        if result.get("symbol_inspection", {}).get("tool_pinned"):
            inputs.append(Path(result["symbol_inspection"]["tool"]["path"]))
        if any(path.samefile(source) for source in inputs):
            raise AuditError("report must not alias an inspected build input")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="." + path.name + ".", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Check explicit build outputs; write evidence only after a successful check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classes", action="append", required=True, metavar="MODULE=DIR",
                        help="main class output for each SDK module; repeat for multiple outputs")
    parser.add_argument("--library", type=Path, required=True, help="fresh connect_norito_bridge library")
    parser.add_argument("--platform", choices=("host", "android"), default="host",
                        help="Android requires an explicit pinned llvm-nm; host discovery is unpinned")
    parser.add_argument("--android-abi", choices=tuple(ANDROID_MACHINES), help="exact Android ELF ABI")
    parser.add_argument("--symbol-tool", type=Path, help="absolute canonical reviewed NDK llvm-nm executable")
    parser.add_argument("--symbol-tool-sha256", help="exact lowercase SHA-256 of the reviewed executable")
    parser.add_argument("--symbol-tool-size-bytes", type=int, help="exact executable byte size")
    parser.add_argument("--inspection-output", type=Path, help="fresh directory for actual pinned child originals")
    parser.add_argument("--report", type=Path, help="optional JSON evidence destination")
    arguments = parser.parse_args(argv)
    roots = {module: [] for module in MODULES}
    for value in arguments.classes:
        module, separator, path = value.partition("=")
        if not separator or module not in roots or not path:
            parser.error("--classes must be MODULE=DIR for a Kotlin SDK module")
        roots[module].append(Path(path))
    try:
        if arguments.report:
            report = arguments.report.resolve()
            if (report == arguments.library.resolve()
                or (arguments.symbol_tool is not None and report == arguments.symbol_tool.resolve())
                or (arguments.inspection_output is not None and report.is_relative_to(arguments.inspection_output.resolve()))
                or any(
                report.is_relative_to(root.resolve()) for paths in roots.values() for root in paths
            )):
                raise AuditError("report must not overwrite an inspected build input")
        result = audit(roots, arguments.library, platform=arguments.platform,
                       android_abi=arguments.android_abi, symbol_tool=arguments.symbol_tool,
                       symbol_tool_sha256=arguments.symbol_tool_sha256,
                       symbol_tool_size_bytes=arguments.symbol_tool_size_bytes,
                       inspection_output=arguments.inspection_output)
        if arguments.report:
            write_report(arguments.report, result)
    except (AuditError, JVM.ClassFileError, ARTIFACT.ArtifactContractError, OSError) as error:
        print(f"Kotlin JNI check failed: {error}", file=sys.stderr)
        return 1
    print(f"Kotlin JNI check passed: {result['native_method_count']} declarations, {result['class_count']} classes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
