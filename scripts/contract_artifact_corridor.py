#!/usr/bin/env python3
"""Build, lock and verify the SCCP v1 EVM (Ethereum and BSC) contract artifact.

`specs/sccp.md` §5.2.5, §5.5: `contracts/evm/sccp/SccpTairaXor.sol` and the one
library it imports, `contracts/evm/sccp/lib/BLS12_381.sol`, are compiled by the
Ethereum `solc` 0.8.31+commit.fd3a2265 with the legacy pipeline, `evmVersion:
cancun`, optimizer runs 200 and no metadata hash or CBOR trailer. The same
creation code serves Ethereum and BSC, so there is one target, `evm`. The
compiler ships native macOS universal (arm64 + x86-64), Linux x86-64 and Linux
arm64 binaries; the corridor runs them natively and refuses Rosetta
translation. Docker is not involved.

Requires Python 3.9+ and HTTPS access to the pinned compiler URL on the first
run; the verified compiler is cached by SHA-256 under
`target/sccp-contract-tooling/compilers`. Every cached or downloaded executable
is re-authenticated before each execution. No environment configuration or
runtime secret is used.

Commands:

* `build`   compile, verify the result against `artifact-lock.json` and
            publish `sccp-contract-artifacts-v1.json` (default directory
            `target/sccp-contract-artifacts`).
* `verify`  re-authenticate a published manifest against the compiler lock, the
            artifact lock and the checkout sources.
* `lock`    compile and rewrite the reviewed artifact lock, which records the
            creation code of `SccpTairaXor` (`SCCP_EVM_CREATION_CODE`), its
            runtime template and its named immutable references.
* `materialize`, `compile-input` serve the Node test harnesses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COMPILER_LOCK = ROOT / "scripts" / "contract_tooling" / "compiler-lock.json"
DEFAULT_ARTIFACT_LOCK = ROOT / "scripts" / "contract_tooling" / "artifact-lock.json"
DEFAULT_OUTPUT_DIR = ROOT / "target" / "sccp-contract-artifacts"
DEFAULT_COMPILER_CACHE = ROOT / "target" / "sccp-contract-tooling" / "compilers"
MANIFEST_NAME = "sccp-contract-artifacts-v1.json"
DEFAULT_MANIFEST = DEFAULT_OUTPUT_DIR / MANIFEST_NAME
MANIFEST_SCHEMA = "iroha.sccp.contract-artifacts.v1"
ARTIFACT_LOCK_SCHEMA = "iroha.sccp.contract-artifact-lock.v1"
COMPILER_LOCK_SCHEMA = "iroha.sccp.contract-compiler-lock.v1"
TARGETS = ("evm",)
PLATFORMS = ("linux-amd64", "linux-arm64", "macos-universal")
SOLIDITY_VERSION_PRAGMA = "pragma solidity 0.8.31;"
SCCP_SOURCE = "contracts/evm/sccp/SccpTairaXor.sol"
SCCP_CONTRACT = SCCP_SOURCE + ":SccpTairaXor"
# §5.2.4 hash-to-G2 library: the only file `SccpTairaXor.sol` may import. Its
# functions are internal, so it is inlined and never linked or deployed.
SCCP_LIBRARY_SOURCE = "contracts/evm/sccp/lib/BLS12_381.sol"
SCCP_LIBRARY = SCCP_LIBRARY_SOURCE + ":BLS12_381"
SCCP_LIBRARY_IMPORT = 'import {BLS12_381} from "./lib/BLS12_381.sol";'
SCCP_SOURCES = (SCCP_SOURCE, SCCP_LIBRARY_SOURCE)
# §5.2.1 constructor arguments, stored as the §5.2.3 immutables that
# `iroha sccp deployment verify` fills into the runtime template.
EXPECTED_IMMUTABLES = (
    "CONSENSUS_INSTANCE",
    "INITIAL_COMMITTEE_ROOT",
    "INITIAL_GENERATION",
    "INITIAL_START_HEIGHT",
    "INITIAL_UNTIL_MS",
    "MAX_WRAPPED_SUPPLY",
    "NETWORK_TAG",
    "ROUTE_REVISION",
    "TAIRA_NETWORK_ID",
)
OUTPUT_SELECTION = {
    "*": {
        "": ["ast"],
        "*": [
            "abi",
            "metadata",
            "evm.bytecode.object",
            "evm.bytecode.linkReferences",
            "evm.deployedBytecode.object",
            "evm.deployedBytecode.immutableReferences",
            "evm.deployedBytecode.linkReferences",
        ],
    }
}
EXPECTED_SETTINGS = {
    "evmVersion": "cancun",
    "metadata": {"appendCBOR": False, "bytecodeHash": "none"},
    "optimizer": {"enabled": True, "runs": 200},
    "outputSelection": OUTPUT_SELECTION,
    "viaIR": False,
}
# Reviewed SHA-256 pins; the values match binaries.soliditylang.org/<platform>/list.json.
EXPECTED_COMPILERS = {
    "evm": {
        "identity": "solc-0.8.31+commit.fd3a2265",
        "banner": "solc, the solidity compiler commandline interface",
        "reported_version": "0.8.31+commit.fd3a2265",
        "artifacts": {
            "linux-amd64": {
                "url": "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.31+commit.fd3a2265",
                "sha256": "aac9cd0116e9ae0cd3d8f64a8641381845dc9f12e2a52653de36fb619323e557",
                "format": "elf-x86-64",
                "reported_version": "0.8.31+commit.fd3a2265.Linux.g++",
            },
            "linux-arm64": {
                "url": "https://binaries.soliditylang.org/linux-arm64/solc-linux-arm64-v0.8.31+commit.fd3a2265",
                "sha256": "acf358d82da7db033debb2f4db11e1c9cfcb02b0cb5b5ddbb9635ad817b41bdd",
                "format": "elf-aarch64",
                "reported_version": "0.8.31+commit.fd3a2265.Linux.g++",
            },
            "macos-universal": {
                "url": "https://binaries.soliditylang.org/macosx-amd64/solc-macosx-amd64-v0.8.31+commit.fd3a2265",
                "sha256": "f5a243d6b2dd8fba307e36c5fefa2d8eb3ae74ba81036d1c17c971b5d346ade9",
                "format": "macho-universal-arm64-x86-64",
                "reported_version": "0.8.31+commit.fd3a2265.Darwin.appleclang",
            },
        },
    },
}
EXECUTABLE_FORMATS = ("elf-x86-64", "elf-aarch64", "macho-universal-arm64-x86-64")
MAX_COMPILER_BYTES = 64 * 1024 * 1024
MAX_COMPILER_INPUT_BYTES = 16 * 1024 * 1024
MAX_COMPILER_OUTPUT_BYTES = 128 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
AST_ID_RE = re.compile(r"^(0|[1-9][0-9]*)$")
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
ELF_MACHINE_X86_64 = 0x3E
ELF_MACHINE_AARCH64 = 0xB7


class CorridorError(ValueError):
    """A bounded, user-actionable contract-corridor failure."""


@dataclass(frozen=True)
class NativeCompilerArtifact:
    """One authenticated native compiler executable for one host platform."""

    url: str
    sha256: str
    format: str
    reported_version: str


@dataclass(frozen=True)
class CompilerSpec:
    """One compiler identity with exact native platform pins."""

    target: str
    identity: str
    banner: str
    reported_version: str
    artifacts: Mapping[str, NativeCompilerArtifact]


def compiler_identity(spec: CompilerSpec) -> Mapping[str, object]:
    """Return the platform-independent compiler admission record."""

    return {
        "identity": spec.identity,
        "banner": spec.banner,
        "reported_version": spec.reported_version,
        "artifacts": {name: asdict(value) for name, value in sorted(spec.artifacts.items())},
    }


def _darwin_translated() -> bool:
    """Return whether this macOS process runs under Rosetta translation.

    A kernel without the `sysctl.proc_translated` key (nonzero exit) has no
    Rosetta; a probe that cannot run at all fails closed.
    """

    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"],
            capture_output=True,
            check=False,
            timeout=10,
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CorridorError("cannot determine whether this process runs under Rosetta") from error
    return result.returncode == 0 and result.stdout.strip() == b"1"


def native_compiler_platform() -> str:
    """Select the native compiler platform of this host; Rosetta translation is refused."""

    system, machine = platform.system(), platform.machine().lower()
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux-amd64"
    if system == "Linux" and machine in ("aarch64", "arm64"):
        return "linux-arm64"
    if system == "Darwin" and machine in ("arm64", "x86_64"):
        if _darwin_translated():
            raise CorridorError("SCCP compilers run natively; this Python process runs under Rosetta")
        return "macos-universal"
    raise CorridorError("native SCCP compilers require Linux x86-64/arm64 or macOS arm64/x86-64")


@dataclass(frozen=True)
class CorridorConfig:
    """Strict compiler, source and size configuration."""

    compilers: Mapping[str, CompilerSpec]
    settings: Mapping[str, object]
    sources: Mapping[str, Tuple[str, ...]]
    size_limits: Mapping[str, Mapping[str, int]]
    canonical_sha256: str


def _reject_constant(value: str) -> object:
    raise CorridorError(f"JSON numeric constant is not allowed: {value}")


def _unique_object(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CorridorError(f"JSON object contains duplicate key `{key}`")
        result[key] = value
    return result


def parse_json_bytes(payload: bytes, label: str) -> object:
    """Parse bounded UTF-8 JSON while rejecting duplicate keys and nonfinite numbers."""

    if not payload:
        raise CorridorError(f"{label} must not be empty")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CorridorError(f"{label} must be UTF-8 JSON") from error
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except json.JSONDecodeError as error:
        raise CorridorError(f"{label} is malformed JSON") from error


def canonical_json_bytes(value: object) -> bytes:
    """Return the corridor's root-independent canonical JSON encoding."""

    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise CorridorError("value cannot be encoded as canonical JSON") from error


def sha256_hex(payload: bytes) -> str:
    """Return one lowercase SHA-256 digest."""

    return hashlib.sha256(payload).hexdigest()


_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_MASK_64 = (1 << 64) - 1


def _rotate_left_64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK_64
    return ((value << shift) | (value >> (64 - shift))) & _MASK_64


def _keccak_f1600(state: List[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        deltas = [columns[(x - 1) % 5] ^ _rotate_left_64(columns[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]
        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate_left_64(state[x + 5 * y], _KECCAK_ROTATIONS[x][y])
        for y in range(5):
            row = rotated[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])) & _MASK_64
        state[0] ^= round_constant


def keccak256(payload: bytes) -> bytes:
    """Return legacy Keccak-256, not the distinct NIST SHA3-256 function."""

    rate = 136
    padded = bytearray(payload)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _keccak_f1600(state)
    output = bytearray()
    for lane in range(4):
        output.extend(state[lane].to_bytes(8, "little"))
    return bytes(output)


def keccak256_hex(payload: bytes) -> str:
    """Return one lowercase Keccak-256 digest."""

    return keccak256(payload).hex()


def _require_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise CorridorError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(value: Mapping[str, object], expected: Iterable[str], label: str) -> None:
    if set(value) != set(expected):
        raise CorridorError(f"{label} has missing or unknown fields")


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CorridorError(f"{label} must be one nonempty canonical string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise CorridorError(f"{label} must not contain control characters")
    return value


def _require_count(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CorridorError(f"{label} must be a nonnegative integer")
    return value


def canonical_source_path(value: object, label: str) -> str:
    """Validate one portable, repository-relative POSIX source path."""

    path = _require_string(value, label)
    if "\\" in path or path.startswith("/") or unicodedata.normalize("NFC", path) != path:
        raise CorridorError(f"{label} must be a normalized repository-relative POSIX path")
    if any(
        segment in ("", ".", "..") or not SAFE_PATH_SEGMENT_RE.fullmatch(segment)
        for segment in path.split("/")
    ):
        raise CorridorError(f"{label} contains an unsafe or nonportable path segment")
    return path


def _collision_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _compiler_spec(target: str, value: object) -> CompilerSpec:
    compiler = _require_object(value, f"{target} compiler")
    _require_exact_keys(compiler, ("identity", "banner", "reported_version", "artifacts"), f"{target} compiler")
    if compiler != EXPECTED_COMPILERS[target]:
        raise CorridorError(f"{target} compiler must be the reviewed native Solidity 0.8.31 release")
    artifacts = _require_object(compiler["artifacts"], f"{target} compiler artifacts")
    if set(artifacts) != set(PLATFORMS):
        raise CorridorError(f"{target} compiler must pin every native platform")
    checked: Dict[str, NativeCompilerArtifact] = {}
    for name, entry in artifacts.items():
        record = _require_object(entry, f"{target} {name} compiler")
        _require_exact_keys(record, ("url", "sha256", "format", "reported_version"), f"{target} {name} compiler")
        url = _require_string(record["url"], f"{target} {name} compiler URL")
        if not url.startswith("https://"):
            raise CorridorError(f"{target} {name} compiler URL must use HTTPS")
        if not isinstance(record["sha256"], str) or not HEX_32_RE.fullmatch(record["sha256"]):
            raise CorridorError(f"{target} {name} compiler SHA-256 pin is malformed")
        if record["format"] not in EXECUTABLE_FORMATS:
            raise CorridorError(f"{target} {name} compiler format is unsupported")
        checked[name] = NativeCompilerArtifact(**record)
    return CompilerSpec(
        target=target,
        identity=compiler["identity"],
        banner=compiler["banner"],
        reported_version=compiler["reported_version"],
        artifacts=checked,
    )


def load_corridor_config(path: Path = DEFAULT_COMPILER_LOCK) -> CorridorConfig:
    """Load and strictly validate the committed compiler lock."""

    parsed = _require_object(parse_json_bytes(path.read_bytes(), "compiler lock"), "compiler lock")
    _require_exact_keys(parsed, ("schema", "compilers", "settings", "sources", "size_limits"), "compiler lock")
    if parsed["schema"] != COMPILER_LOCK_SCHEMA:
        raise CorridorError("compiler lock schema is unsupported")
    compiler_values = _require_object(parsed["compilers"], "compiler lock compilers")
    source_values = _require_object(parsed["sources"], "compiler lock sources")
    limit_values = _require_object(parsed["size_limits"], "compiler lock size limits")
    for label, values in (("compilers", compiler_values), ("sources", source_values), ("size limits", limit_values)):
        if set(values) != set(TARGETS):
            raise CorridorError(f"compiler lock {label} must define exactly the EVM target")

    compilers: Dict[str, CompilerSpec] = {}
    sources: Dict[str, Tuple[str, ...]] = {}
    size_limits: Dict[str, Mapping[str, int]] = {}
    for target in TARGETS:
        compilers[target] = _compiler_spec(target, compiler_values[target])
        source_list = source_values[target]
        if not isinstance(source_list, list) or not source_list:
            raise CorridorError(f"{target} source list must be one nonempty array")
        paths = tuple(canonical_source_path(value, f"{target} source path") for value in source_list)
        if paths != tuple(sorted(paths)):
            raise CorridorError(f"{target} source paths must be sorted")
        keys = [_collision_key(value) for value in paths]
        if len(keys) != len(set(keys)):
            raise CorridorError(f"{target} source paths contain a portable path collision")
        if paths != SCCP_SOURCES:
            raise CorridorError(f"{target} sources must be exactly {SCCP_SOURCE} and {SCCP_LIBRARY_SOURCE}")
        sources[target] = paths
        limits = _require_object(limit_values[target], f"{target} size limits")
        _require_exact_keys(limits, ("creation_bytecode_bytes", "runtime_bytecode_bytes"), f"{target} size limits")
        checked_limits: Dict[str, int] = {}
        for name, value in limits.items():
            if _require_count(value, f"{target} {name} limit") == 0:
                raise CorridorError(f"{target} {name} limit must be positive")
            checked_limits[name] = value
        size_limits[target] = checked_limits

    settings = _require_object(parsed["settings"], "compiler settings")
    if settings != EXPECTED_SETTINGS:
        raise CorridorError("compiler settings must be the reviewed §5.5 cancun legacy-pipeline settings")
    return CorridorConfig(
        compilers=compilers,
        settings=settings,
        sources=sources,
        size_limits=size_limits,
        canonical_sha256=sha256_hex(canonical_json_bytes(parsed)),
    )


# ---------------------------------------------------------------------------
# Native compiler acquisition and execution
# ---------------------------------------------------------------------------

CompilerFetcher = Callable[[str], bytes]
CompilerRunner = Callable[[Path, CompilerSpec, bytes], Mapping[str, object]]


def _network_fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "iroha-sccp-contract-corridor/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError as error:
                raise CorridorError("compiler server returned an invalid Content-Length") from error
            if length <= 0 or length > MAX_COMPILER_BYTES:
                raise CorridorError("compiler download exceeds the bounded size policy")
        return response.read(MAX_COMPILER_BYTES + 1)


def validate_executable_format(payload: bytes, expected: str) -> None:
    """Require the pinned native executable container and CPU architecture(s)."""

    if expected in ("elf-x86-64", "elf-aarch64"):
        if len(payload) < 64 or payload[:4] != b"\x7fELF" or payload[4] != 2 or payload[5] != 1:
            raise CorridorError("native compiler is not a 64-bit little-endian ELF executable")
        machine = int.from_bytes(payload[18:20], "little")
        wanted = ELF_MACHINE_X86_64 if expected == "elf-x86-64" else ELF_MACHINE_AARCH64
        if machine != wanted:
            raise CorridorError("native compiler ELF architecture does not match its pin")
        return
    if expected == "macho-universal-arm64-x86-64":
        if len(payload) < 8 or payload[:4] != b"\xca\xfe\xba\xbe":
            raise CorridorError("native compiler is not a universal Mach-O executable")
        count = int.from_bytes(payload[4:8], "big")
        if not 1 <= count <= 8 or len(payload) < 8 + 20 * count:
            raise CorridorError("native compiler universal Mach-O header is malformed")
        cpus = {int.from_bytes(payload[8 + 20 * i : 12 + 20 * i], "big") for i in range(count)}
        if not {CPU_TYPE_ARM64, CPU_TYPE_X86_64} <= cpus:
            raise CorridorError("native compiler universal Mach-O must contain arm64 and x86-64 slices")
        return
    raise CorridorError("native compiler format is unsupported")


def _write_private_file(destination: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    destination.chmod(mode)


def _cached_compiler(cache_dir: Optional[Path], artifact: NativeCompilerArtifact) -> Optional[bytes]:
    if cache_dir is None:
        return None
    candidate = cache_dir / artifact.sha256
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise CorridorError(f"compiler cache entry must be a regular file: {candidate}")
    payload = _read_stable_regular_file(candidate, MAX_COMPILER_BYTES, "cached native compiler")
    if sha256_hex(payload) != artifact.sha256:
        # A corrupted cache entry is discarded and re-authenticated from the pinned URL.
        candidate.unlink()
        return None
    return payload


def _store_cached_compiler(cache_dir: Optional[Path], artifact: NativeCompilerArtifact, payload: bytes) -> None:
    if cache_dir is None:
        return
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sccp-solc-", dir=cache_dir) as staging:
        staged = Path(staging) / "solc"
        _write_private_file(staged, payload, 0o400)
        os.replace(staged, cache_dir / artifact.sha256)


def authenticated_compiler_bytes(
    spec: CompilerSpec,
    fetcher: CompilerFetcher = _network_fetch,
    cache_dir: Optional[Path] = DEFAULT_COMPILER_CACHE,
) -> bytes:
    """Return the pinned native compiler of this host, from the SHA-256 cache or its URL."""

    artifact = spec.artifacts[native_compiler_platform()]
    payload = _cached_compiler(cache_dir, artifact)
    if payload is None:
        payload = fetcher(artifact.url)
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_COMPILER_BYTES:
            raise CorridorError("compiler download is empty or exceeds the bounded size policy")
        if sha256_hex(payload) != artifact.sha256:
            raise CorridorError("authenticated compiler SHA-256 digest mismatch")
        validate_executable_format(payload, artifact.format)
        _store_cached_compiler(cache_dir, artifact, payload)
    validate_executable_format(payload, artifact.format)
    return payload


def materialize_verified_compiler(
    spec: CompilerSpec,
    destination: Path,
    fetcher: CompilerFetcher = _network_fetch,
    cache_dir: Optional[Path] = DEFAULT_COMPILER_CACHE,
) -> Path:
    """Publish one authenticated compiler at a new private path."""

    if destination.exists() or destination.is_symlink():
        raise CorridorError("compiler destination collision")
    payload = authenticated_compiler_bytes(spec, fetcher, cache_dir)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_private_file(destination, payload, 0o500)
    if sha256_hex(_read_stable_regular_file(destination, MAX_COMPILER_BYTES, "native compiler")) != sha256_hex(payload):
        destination.unlink(missing_ok=True)
        raise CorridorError("verified compiler changed during publication")
    return destination


def _stable_file_identity(info: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_stable_regular_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    """Read one stable regular inode, with explicit bounds for resource inputs."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CorridorError(f"{label} must be a readable direct regular file") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CorridorError(f"{label} must be a direct regular file")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise CorridorError(f"{label} is empty or exceeds the bounded size policy")
        chunks: List[bytes] = []
        remaining = before.st_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _stable_file_identity(before) != _stable_file_identity(after):
        raise CorridorError(f"{label} changed while it was being read")
    if len(payload) != before.st_size or len(payload) > maximum_bytes:
        raise CorridorError(f"{label} changed outside its bounded size policy")
    return payload


def validate_native_compiler_input(payload: bytes, settings: Mapping[str, object]) -> None:
    """Admit content-only Solidity sources compiled with exactly the locked settings."""

    if not payload or len(payload) > MAX_COMPILER_INPUT_BYTES:
        raise CorridorError("standard-json compiler input is empty or exceeds 16 MiB")
    value = _require_object(parse_json_bytes(payload, "native compiler input"), "native compiler input")
    _require_exact_keys(value, ("language", "sources", "settings"), "native compiler input")
    if value["language"] != "Solidity":
        raise CorridorError("native compiler input must use Solidity")
    sources = _require_object(value["sources"], "native compiler sources")
    if not sources:
        raise CorridorError("native compiler sources must not be empty")
    for name, entry in sources.items():
        canonical_source_path(name, "native compiler source path")
        source = _require_object(entry, "native compiler source")
        _require_exact_keys(source, ("content",), "native compiler source")
        content = source["content"]
        if not isinstance(content, str) or not content:
            raise CorridorError("native compiler source content must be nonempty UTF-8 text")
        try:
            content.encode("utf-8")
        except UnicodeEncodeError as error:
            raise CorridorError("native compiler source content must be UTF-8 text") from error
    if value["settings"] != settings:
        raise CorridorError("native compiler input must use exactly the locked settings")


def _run_native_command(executable: Path, arguments: List[str], payload: bytes, directory: Path, limit: int) -> bytes:
    """Capture one bounded native compiler result without a shell or import callback."""

    output_path, error_path = directory / "output.json", directory / "stderr.txt"
    with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
        try:
            result = subprocess.run(
                [str(executable), *arguments],
                input=payload,
                stdout=stdout,
                stderr=stderr,
                cwd=directory,
                check=False,
                timeout=300,
                env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CorridorError("authenticated native compiler could not complete") from error
    if result.returncode != 0 or error_path.stat().st_size:
        with error_path.open("rb") as errors:
            message = errors.read(MAX_DIAGNOSTIC_BYTES).decode("utf-8", errors="replace").strip()
        raise CorridorError(message or "authenticated native compiler failed")
    if not 0 < output_path.stat().st_size <= limit:
        raise CorridorError("authenticated native compiler output exceeds the bounded size policy")
    return output_path.read_bytes()


def run_native_solc(
    compiler_path: Path,
    spec: CompilerSpec,
    compiler_input: bytes,
    settings: Mapping[str, object] = EXPECTED_SETTINGS,
) -> Mapping[str, object]:
    """Run exact native bytes from a private immutable copy after digest, format and banner checks."""

    if not compiler_input or len(compiler_input) > MAX_COMPILER_INPUT_BYTES:
        raise CorridorError("standard-json compiler input is empty or exceeds 16 MiB")
    validate_native_compiler_input(compiler_input, settings)
    artifact = spec.artifacts[native_compiler_platform()]
    compiler = _read_stable_regular_file(compiler_path, MAX_COMPILER_BYTES, "native compiler")
    if sha256_hex(compiler) != artifact.sha256:
        raise CorridorError("authenticated native compiler SHA-256 digest mismatch before execution")
    validate_executable_format(compiler, artifact.format)
    with tempfile.TemporaryDirectory(prefix="iroha-sccp-native-solc-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        executable = directory / "solc"
        _write_private_file(executable, compiler, 0o500)
        expected_banner = f"{spec.banner}\nVersion: {artifact.reported_version}\n".encode()
        version = _run_native_command(executable, ["--version"], b"", directory, 4096)
        if version != expected_banner:
            raise CorridorError("authenticated native compiler reported an unexpected version or target")
        raw = _run_native_command(executable, ["--standard-json"], compiler_input, directory, MAX_COMPILER_OUTPUT_BYTES)
    return _require_object(parse_json_bytes(raw, "standard-json compiler output"), "standard-json compiler output")


# ---------------------------------------------------------------------------
# Source policy
# ---------------------------------------------------------------------------


def _mask_solidity_comments_and_strings(source: str, relative: str) -> str:
    """Mask comments and string literals while preserving offsets for lexical policy checks."""

    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == "/" and following in ("/", "*"):
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment" if following == "/" else "block-comment"
                continue
            if character in ("'", '"'):
                quote = character
                output[index] = " "
                state = "string"
            index += 1
        elif state == "line-comment":
            if character == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
        elif state == "block-comment":
            if character == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if character != "\n":
                output[index] = " "
            index += 1
        else:
            if character == "\\" and following:
                output[index] = " "
                if following != "\n":
                    output[index + 1] = " "
                index += 2
                continue
            output[index] = " " if character != "\n" else "\n"
            index += 1
            if character == quote:
                state = "code"
    if state in ("block-comment", "string"):
        raise CorridorError(f"contract source contains an unterminated lexical region: {relative}")
    return "".join(output)


def validate_solidity_source_policy(source: str, relative: str) -> None:
    """Require the exact 0.8.31 pragma and reject the §5.5 legacy-pipeline bug patterns.

    `SccpTairaXor.sol` contains exactly one import, the §5.2.4 library; every
    other source is self-contained.
    """

    masked = _mask_solidity_comments_and_strings(source, relative)
    if not source.startswith("// SPDX-License-Identifier: "):
        raise CorridorError(f"contract source must start with an SPDX license identifier: {relative}")
    pragma_tokens = list(re.finditer(r"\bpragma\b", masked))
    directives = list(re.finditer(r"\bpragma\b[^;]*;", masked))
    if len(pragma_tokens) != len(directives):
        raise CorridorError(f"contract source contains an incomplete or obfuscated pragma: {relative}")
    rendered = [source[match.start() : match.end()] for match in directives]
    if rendered != [SOLIDITY_VERSION_PRAGMA]:
        raise CorridorError(
            f"contract source must use exactly {SOLIDITY_VERSION_PRAGMA!r} and no other pragma: {relative}"
        )
    if re.search(r"\bdelete\b", masked):
        raise CorridorError(f"contract source must not use `delete` (0.8.31 legacy-pipeline policy): {relative}")
    if re.search(r"\blayout\s+at\b", masked):
        raise CorridorError(f"contract source must not declare a custom storage layout: {relative}")
    import_tokens = list(re.finditer(r"\bimport\b", masked))
    imports = list(re.finditer(r"\bimport\b[^;]*;", masked))
    if len(import_tokens) != len(imports):
        raise CorridorError(f"contract source contains an incomplete or obfuscated import: {relative}")
    rendered_imports = [source[match.start() : match.end()] for match in imports]
    if relative == SCCP_SOURCE:
        if rendered_imports != [SCCP_LIBRARY_IMPORT]:
            raise CorridorError(f"contract source must import exactly {SCCP_LIBRARY_IMPORT!r}: {relative}")
    elif rendered_imports:
        raise CorridorError(f"contract source must be self-contained without imports: {relative}")


def _read_source(
    repo_root: Path, relative: str, *, maximum_bytes: int = MAX_COMPILER_INPUT_BYTES
) -> bytes:
    """Read exact source bytes within the remaining total compiler-input envelope."""
    root = repo_root.resolve(strict=True)
    candidate = repo_root / relative
    try:
        info = candidate.lstat()
    except FileNotFoundError as error:
        raise CorridorError(f"required contract source is missing: {relative}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise CorridorError(f"contract source must be a direct regular file: {relative}")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise CorridorError(f"contract source escapes the repository root: {relative}") from error
    # Raw source bytes are a lower bound on serialized compiler input. Refuse an
    # impossible input before allocation; JSON escapes and overhead are admitted
    # separately against the same total input envelope.
    payload = _read_stable_regular_file(candidate, maximum_bytes, f"contract source {relative}")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CorridorError(f"contract source must be UTF-8: {relative}") from error
    validate_solidity_source_policy(source, relative)
    return payload


def standard_json_input(
    repo_root: Path, config: CorridorConfig, target: str
) -> Tuple[Mapping[str, object], List[Mapping[str, object]]]:
    """Construct one root-independent standard-json input and its source inventory."""

    if target not in TARGETS:
        raise CorridorError("unknown contract compilation target")
    source_map: Dict[str, object] = {}
    inventory: List[Mapping[str, object]] = []
    remaining_source_bytes = MAX_COMPILER_INPUT_BYTES
    for relative in config.sources[target]:
        payload = _read_source(repo_root, relative, maximum_bytes=remaining_source_bytes)
        remaining_source_bytes -= len(payload)
        source_map[relative] = {"content": payload.decode("utf-8")}
        inventory.append(
            {
                "path": relative,
                "byte_length": len(payload),
                "sha256_hex": sha256_hex(payload),
                "keccak256_hex": keccak256_hex(payload),
            }
        )
    return {"language": "Solidity", "sources": source_map, "settings": config.settings}, inventory


# ---------------------------------------------------------------------------
# Compiler output normalization
# ---------------------------------------------------------------------------


def _safe_diagnostic(entry: Mapping[str, object]) -> str:
    value = entry.get("formattedMessage", entry.get("message", "compiler diagnostic"))
    if not isinstance(value, str):
        return "compiler diagnostic"
    return "".join(c if c in "\n\t" or ord(c) >= 0x20 else "?" for c in value)[:2048]


def _reject_compiler_diagnostics(output: Mapping[str, object], target: str) -> None:
    diagnostics = output.get("errors", [])
    if diagnostics is None:
        diagnostics = []
    if not isinstance(diagnostics, list):
        raise CorridorError(f"{target} compiler diagnostics must be an array")
    rejected: List[str] = []
    for value in diagnostics:
        entry = _require_object(value, f"{target} compiler diagnostic")
        severity = entry.get("severity")
        if severity in ("warning", "error"):
            rejected.append(_safe_diagnostic(entry))
        elif severity != "info":
            raise CorridorError(f"{target} compiler returned an unknown diagnostic severity")
    if rejected:
        raise CorridorError(f"{target} compiler emitted a warning or error:\n" + "\n".join(rejected))


def _decode_bytecode(value: object, label: str) -> Tuple[str, bytes]:
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise CorridorError(f"{label} must be an even-length hexadecimal string")
    if not re.fullmatch(r"[0-9a-f]*", value):
        raise CorridorError(f"{label} contains unresolved links or noncanonical hexadecimal")
    return "0x" + value, bytes.fromhex(value)


def _metadata_record(value: object, label: str, compiler_version: str) -> Tuple[object, bytes]:
    if not isinstance(value, str):
        raise CorridorError(f"{label} metadata must be JSON text")
    metadata = _require_object(parse_json_bytes(value.encode("utf-8"), f"{label} metadata"), f"{label} metadata")
    compiler = _require_object(metadata.get("compiler"), f"{label} metadata compiler")
    if compiler.get("version") != compiler_version:
        raise CorridorError(f"{label} metadata compiler identity mismatch")
    settings = _require_object(metadata.get("settings"), f"{label} metadata settings")
    if settings.get("evmVersion") != EXPECTED_SETTINGS["evmVersion"] or settings.get("viaIR", False):
        raise CorridorError(f"{label} metadata reports an unexpected EVM version or pipeline")
    return metadata, canonical_json_bytes(metadata)


def _bytecode_record(bytecode: bytes, encoded: str) -> Mapping[str, object]:
    return {
        "hex": encoded,
        "byte_length": len(bytecode),
        "sha256_hex": sha256_hex(bytecode),
        "keccak256_hex": keccak256_hex(bytecode),
    }


def immutable_names(output: Mapping[str, object]) -> Mapping[str, str]:
    """Map every immutable state variable's AST id to its name from the compiler AST."""

    names: Dict[str, str] = {}
    stack: List[object] = []
    sources = _require_object(output.get("sources"), "compiler source outputs")
    for entry in sources.values():
        stack.append(_require_object(entry, "compiler source output").get("ast"))
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("nodeType") == "VariableDeclaration" and node.get("mutability") == "immutable":
                identifier, name = node.get("id"), node.get("name")
                if not isinstance(identifier, int) or not isinstance(name, str) or not IDENTIFIER_RE.fullmatch(name):
                    raise CorridorError("compiler AST contains a malformed immutable declaration")
                names[str(identifier)] = name
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return names


def runtime_immutable_references(
    value: object, runtime: bytes, names: Mapping[str, str], label: str
) -> List[Mapping[str, object]]:
    """Normalize compiler-reported immutable patches; every patch window of the template is zero."""

    references = _require_object({} if value is None else value, f"{label} immutable references")
    normalized: List[Mapping[str, object]] = []
    for ast_id, locations in references.items():
        if not isinstance(ast_id, str) or not AST_ID_RE.fullmatch(ast_id) or ast_id not in names:
            raise CorridorError(f"{label} immutable reference AST id is unknown or noncanonical")
        if not isinstance(locations, list) or not locations:
            raise CorridorError(f"{label} immutable reference locations must be nonempty")
        for location_value in locations:
            location = _require_object(location_value, f"{label} immutable reference")
            _require_exact_keys(location, ("start", "length"), f"{label} immutable reference")
            start = _require_count(location["start"], f"{label} immutable start")
            length = _require_count(location["length"], f"{label} immutable length")
            if length != 32 or start + length > len(runtime):
                raise CorridorError(f"{label} immutable reference is outside runtime bytecode")
            if any(runtime[start : start + length]):
                raise CorridorError(f"{label} runtime template is not zero at an immutable reference")
            normalized.append({"name": names[ast_id], "ast_id": ast_id, "start": start, "length": length})
    normalized.sort(key=lambda entry: (entry["start"], entry["length"]))
    for previous, current in zip(normalized, normalized[1:]):
        if previous["start"] + previous["length"] > current["start"]:
            raise CorridorError(f"{label} immutable runtime references overlap")
    return normalized


def _validate_normalized_immutable_references(value: object, runtime: bytes, label: str) -> None:
    if not isinstance(value, list):
        raise CorridorError(f"{label} immutable references must be an array")
    rebuilt: Dict[str, List[Mapping[str, object]]] = {}
    names: Dict[str, str] = {}
    for entry_value in value:
        entry = _require_object(entry_value, f"{label} immutable reference")
        _require_exact_keys(entry, ("name", "ast_id", "start", "length"), f"{label} immutable reference")
        ast_id = entry["ast_id"]
        if not isinstance(ast_id, str) or not isinstance(entry["name"], str):
            raise CorridorError(f"{label} immutable reference identity is malformed")
        if names.setdefault(ast_id, entry["name"]) != entry["name"]:
            raise CorridorError(f"{label} immutable reference names are inconsistent")
        rebuilt.setdefault(ast_id, []).append({"start": entry["start"], "length": entry["length"]})
    if value != runtime_immutable_references(rebuilt, runtime, names, label):
        raise CorridorError(f"{label} immutable references are not canonical")


def _build_contract_records(
    output: Mapping[str, object],
    target: str,
    spec: CompilerSpec,
    limits: Mapping[str, int],
    source_paths: Sequence[str],
) -> List[Mapping[str, object]]:
    contracts = _require_object(output.get("contracts"), f"{target} compiler contracts")
    names = immutable_names(output)
    source_set = set(source_paths)
    records: List[Mapping[str, object]] = []
    for source_path in sorted(contracts):
        if canonical_source_path(source_path, f"{target} compiler source path") not in source_set:
            raise CorridorError(f"{target} compiler emitted an undeclared source path")
        source_contracts = _require_object(contracts[source_path], f"{target} contracts for {source_path}")
        for contract_name in sorted(source_contracts):
            if not IDENTIFIER_RE.fullmatch(contract_name):
                raise CorridorError(f"{target} compiler emitted an invalid contract identifier")
            fqn = f"{source_path}:{contract_name}"
            artifact = _require_object(source_contracts[contract_name], f"{target} artifact {fqn}")
            abi = artifact.get("abi")
            if not isinstance(abi, list):
                raise CorridorError(f"{fqn} ABI must be an array")
            evm = _require_object(artifact.get("evm"), f"{fqn} EVM output")
            creation = _require_object(evm.get("bytecode"), f"{fqn} creation bytecode")
            runtime = _require_object(evm.get("deployedBytecode"), f"{fqn} runtime bytecode")
            for link_label, link_value in (
                ("creation", creation.get("linkReferences")),
                ("runtime", runtime.get("linkReferences")),
            ):
                if link_value not in ({}, None):
                    raise CorridorError(f"{fqn} has unresolved {link_label} link references")
            creation_hex, creation_bytes = _decode_bytecode(creation.get("object"), f"{fqn} creation bytecode")
            runtime_hex, runtime_bytes = _decode_bytecode(runtime.get("object"), f"{fqn} runtime bytecode")
            if len(creation_bytes) > limits["creation_bytecode_bytes"]:
                raise CorridorError(f"{fqn} creation bytecode exceeds its ceiling")
            if len(runtime_bytes) > limits["runtime_bytecode_bytes"]:
                raise CorridorError(f"{fqn} runtime bytecode exceeds its ceiling")
            references = runtime_immutable_references(runtime.get("immutableReferences"), runtime_bytes, names, fqn)
            if fqn == SCCP_CONTRACT and tuple(sorted({r["name"] for r in references})) != EXPECTED_IMMUTABLES:
                raise CorridorError(f"{fqn} must reference exactly the §5.2.3 immutables")
            metadata, metadata_bytes = _metadata_record(artifact.get("metadata"), fqn, spec.reported_version)
            records.append(
                {
                    "fully_qualified_name": fqn,
                    "source_path": source_path,
                    "contract_name": contract_name,
                    "abi": abi,
                    "creation_bytecode": _bytecode_record(creation_bytes, creation_hex),
                    "runtime_bytecode": _bytecode_record(runtime_bytes, runtime_hex),
                    "runtime_immutable_references": references,
                    "metadata": metadata,
                    "metadata_sha256_hex": sha256_hex(metadata_bytes),
                    "metadata_keccak256_hex": keccak256_hex(metadata_bytes),
                }
            )
    if {record["fully_qualified_name"] for record in records} != {SCCP_CONTRACT, SCCP_LIBRARY}:
        raise CorridorError(f"{target} compiler must emit exactly {SCCP_CONTRACT} and {SCCP_LIBRARY}")
    return records


def compile_target(
    repo_root: Path,
    config: CorridorConfig,
    target: str,
    compiler_path: Path,
    runner: CompilerRunner = run_native_solc,
) -> Mapping[str, object]:
    """Compile one target through its exact compiler and return its normalized manifest."""

    standard_input, source_inventory = standard_json_input(repo_root, config, target)
    input_bytes = canonical_json_bytes(standard_input)
    output = runner(compiler_path, config.compilers[target], input_bytes)
    _reject_compiler_diagnostics(output, target)
    contracts = _build_contract_records(
        output, target, config.compilers[target], config.size_limits[target], config.sources[target]
    )
    return {
        "target": target,
        "compiler": compiler_identity(config.compilers[target]),
        "settings": config.settings,
        "settings_sha256_hex": sha256_hex(canonical_json_bytes(config.settings)),
        "standard_json_input_sha256_hex": sha256_hex(input_bytes),
        "sources": source_inventory,
        "contracts": contracts,
    }


def compile_corridor(
    repo_root: Path,
    config: CorridorConfig,
    fetcher: CompilerFetcher = _network_fetch,
    runner: CompilerRunner = run_native_solc,
    cache_dir: Optional[Path] = DEFAULT_COMPILER_CACHE,
) -> Mapping[str, object]:
    """Compile the EVM target with its authenticated native compiler."""

    with tempfile.TemporaryDirectory(prefix="iroha-sccp-authenticated-compilers-") as temporary:
        temp_root = Path(temporary)
        os.chmod(temp_root, 0o700)
        compiled: Dict[str, Mapping[str, object]] = {}
        for target in TARGETS:
            compiler_path = materialize_verified_compiler(
                config.compilers[target], temp_root / f"{target}-solc", fetcher, cache_dir
            )
            compiled[target] = compile_target(repo_root, config, target, compiler_path, runner)
    return {
        "schema": MANIFEST_SCHEMA,
        "compiler_lock_sha256_hex": config.canonical_sha256,
        "targets": compiled,
    }


# ---------------------------------------------------------------------------
# Artifact lock
# ---------------------------------------------------------------------------


def _locked_contract(contract: Mapping[str, object]) -> Mapping[str, object]:
    fqn = _require_string(contract.get("fully_qualified_name"), "contract FQN")
    creation = _require_object(contract.get("creation_bytecode"), f"{fqn} creation")
    runtime = _require_object(contract.get("runtime_bytecode"), f"{fqn} runtime")
    return {
        "creation_bytecode_bytes": creation.get("byte_length"),
        "creation_bytecode_hex": creation.get("hex"),
        "creation_bytecode_keccak256_hex": creation.get("keccak256_hex"),
        "runtime_bytecode_bytes": runtime.get("byte_length"),
        "runtime_template_hex": runtime.get("hex"),
        "runtime_template_keccak256_hex": runtime.get("keccak256_hex"),
        "immutable_references": contract.get("runtime_immutable_references"),
        "abi_sha256_hex": sha256_hex(canonical_json_bytes(contract.get("abi"))),
    }


def artifact_lock_from_manifest(manifest: Mapping[str, object]) -> Mapping[str, object]:
    """Derive the reviewable lock of `SccpTairaXor`.

    It records the creation code (`SCCP_EVM_CREATION_CODE`, §4.14.3 P4), the
    runtime template, the named immutables and their digests. The inlined
    library is bound through the compiler input and manifest digests.
    """

    targets = _require_object(manifest.get("targets"), "corridor manifest targets")
    locked_targets: Dict[str, object] = {}
    for target in TARGETS:
        target_manifest = _require_object(targets.get(target), f"{target} target manifest")
        contracts = target_manifest.get("contracts")
        if not isinstance(contracts, list):
            raise CorridorError(f"{target} target contracts must be an array")
        locked_targets[target] = {
            "standard_json_input_sha256_hex": target_manifest.get("standard_json_input_sha256_hex"),
            "contracts": {
                SCCP_CONTRACT: _locked_contract(value)
                for value in contracts
                if _require_object(value, f"{target} contract").get("fully_qualified_name") == SCCP_CONTRACT
            },
        }
    return {
        "schema": ARTIFACT_LOCK_SCHEMA,
        "compiler_lock_sha256_hex": manifest.get("compiler_lock_sha256_hex"),
        "targets": locked_targets,
        "corridor_manifest_sha256_hex": sha256_hex(canonical_json_bytes(manifest)),
    }


def validate_artifact_lock(manifest: Mapping[str, object], artifact_lock: Mapping[str, object]) -> None:
    """Fail closed on compiler, input, creation code, template, immutable, ABI or manifest digest drift."""

    _require_exact_keys(
        artifact_lock, ("schema", "compiler_lock_sha256_hex", "targets", "corridor_manifest_sha256_hex"), "artifact lock"
    )
    if artifact_lock["schema"] != ARTIFACT_LOCK_SCHEMA:
        raise CorridorError("artifact lock schema is unsupported")
    expected = artifact_lock_from_manifest(manifest)
    if artifact_lock["compiler_lock_sha256_hex"] != expected["compiler_lock_sha256_hex"]:
        raise CorridorError("compiler lock digest drift")
    locked_targets = _require_object(artifact_lock["targets"], "artifact lock targets")
    if set(locked_targets) != set(TARGETS):
        raise CorridorError("artifact lock must contain exactly the EVM target")
    for target in TARGETS:
        locked = _require_object(locked_targets[target], f"{target} artifact lock")
        _require_exact_keys(locked, ("standard_json_input_sha256_hex", "contracts"), f"{target} artifact lock")
        actual = expected["targets"][target]
        if locked["standard_json_input_sha256_hex"] != actual["standard_json_input_sha256_hex"]:
            raise CorridorError(f"{target} compiler input/settings digest drift")
        locked_contracts = _require_object(locked["contracts"], f"{target} locked contracts")
        if set(locked_contracts) != set(actual["contracts"]):
            raise CorridorError(f"{target} locked contract set drift")
        for fqn, record in actual["contracts"].items():
            entry = _require_object(locked_contracts[fqn], f"{fqn} lock")
            for field, value in record.items():
                if entry.get(field) != value:
                    raise CorridorError(f"{target} {fqn} {field} drift")
            _require_exact_keys(entry, record.keys(), f"{fqn} lock")
    digest = artifact_lock["corridor_manifest_sha256_hex"]
    if not isinstance(digest, str) or not HEX_32_RE.fullmatch(digest):
        raise CorridorError("artifact lock manifest digest is malformed")
    if digest != expected["corridor_manifest_sha256_hex"]:
        raise CorridorError("corridor artifact digest drift")


# ---------------------------------------------------------------------------
# Manifest integrity
# ---------------------------------------------------------------------------


def _validate_hash_record(record: Mapping[str, object], label: str) -> bytes:
    _require_exact_keys(record, ("hex", "byte_length", "sha256_hex", "keccak256_hex"), label)
    encoded = record.get("hex")
    if not isinstance(encoded, str) or not encoded.startswith("0x"):
        raise CorridorError(f"{label} hex is malformed")
    canonical, payload = _decode_bytecode(encoded[2:], label)
    if canonical != encoded or record.get("byte_length") != len(payload):
        raise CorridorError(f"{label} byte length is inconsistent")
    if record.get("sha256_hex") != sha256_hex(payload):
        raise CorridorError(f"{label} SHA-256 is inconsistent")
    if record.get("keccak256_hex") != keccak256_hex(payload):
        raise CorridorError(f"{label} Keccak-256 is inconsistent")
    return payload


def validate_manifest_integrity(manifest: Mapping[str, object], config: CorridorConfig) -> None:
    """Recompute every embedded artifact hash before a runtime consumes the manifest."""

    _require_exact_keys(manifest, ("schema", "compiler_lock_sha256_hex", "targets"), "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise CorridorError("contract artifact manifest schema is unsupported")
    if manifest["compiler_lock_sha256_hex"] != config.canonical_sha256:
        raise CorridorError("contract artifact manifest compiler lock digest mismatch")
    targets = _require_object(manifest["targets"], "manifest targets")
    if set(targets) != set(TARGETS):
        raise CorridorError("manifest must contain exactly the EVM target")
    for target in TARGETS:
        value = _require_object(targets[target], f"{target} target manifest")
        _require_exact_keys(
            value,
            ("target", "compiler", "settings", "settings_sha256_hex", "standard_json_input_sha256_hex", "sources", "contracts"),
            f"{target} target manifest",
        )
        if value["target"] != target:
            raise CorridorError(f"{target} target manifest role mismatch")
        if value["compiler"] != compiler_identity(config.compilers[target]):
            raise CorridorError(f"{target} native compiler identity mismatch")
        if value["settings"] != config.settings or value["settings_sha256_hex"] != sha256_hex(
            canonical_json_bytes(value["settings"])
        ):
            raise CorridorError(f"{target} compiler settings digest mismatch")
        contracts = value["contracts"]
        if not isinstance(contracts, list) or not contracts:
            raise CorridorError(f"{target} contracts must be a nonempty array")
        seen: set = set()
        for artifact_value in contracts:
            artifact = _require_object(artifact_value, f"{target} contract artifact")
            _require_exact_keys(
                artifact,
                (
                    "fully_qualified_name",
                    "source_path",
                    "contract_name",
                    "abi",
                    "creation_bytecode",
                    "runtime_bytecode",
                    "runtime_immutable_references",
                    "metadata",
                    "metadata_sha256_hex",
                    "metadata_keccak256_hex",
                ),
                f"{target} contract artifact",
            )
            fqn = _require_string(artifact["fully_qualified_name"], "contract FQN")
            if fqn != f"{artifact['source_path']}:{artifact['contract_name']}" or _collision_key(fqn) in seen:
                raise CorridorError(f"{target} manifest contract identity is inconsistent or duplicated")
            seen.add(_collision_key(fqn))
            _validate_hash_record(_require_object(artifact["creation_bytecode"], f"{fqn} creation"), f"{fqn} creation")
            runtime = _validate_hash_record(_require_object(artifact["runtime_bytecode"], f"{fqn} runtime"), f"{fqn} runtime")
            _validate_normalized_immutable_references(artifact["runtime_immutable_references"], runtime, fqn)
            metadata_bytes = canonical_json_bytes(artifact["metadata"])
            if artifact["metadata_sha256_hex"] != sha256_hex(metadata_bytes):
                raise CorridorError(f"{fqn} metadata SHA-256 mismatch")
            if artifact["metadata_keccak256_hex"] != keccak256_hex(metadata_bytes):
                raise CorridorError(f"{fqn} metadata Keccak-256 mismatch")
            if fqn == SCCP_CONTRACT:
                named = tuple(sorted({entry["name"] for entry in artifact["runtime_immutable_references"]}))
                if named != EXPECTED_IMMUTABLES:
                    raise CorridorError(f"{fqn} must reference exactly the §5.2.3 immutables")
        if seen != {_collision_key(SCCP_CONTRACT), _collision_key(SCCP_LIBRARY)}:
            raise CorridorError(f"{target} manifest must hold exactly {SCCP_CONTRACT} and {SCCP_LIBRARY}")


def validate_manifest_source_inputs(manifest: Mapping[str, object], config: CorridorConfig, repo_root: Path) -> None:
    """Bind a published manifest to the sources of the checkout that consumes it."""

    targets = _require_object(manifest.get("targets"), "manifest targets")
    for target in TARGETS:
        target_manifest = _require_object(targets.get(target), f"{target} target manifest")
        standard_input, source_inventory = standard_json_input(repo_root, config, target)
        if target_manifest.get("standard_json_input_sha256_hex") != sha256_hex(canonical_json_bytes(standard_input)):
            raise CorridorError(f"{target} manifest is stale for the current source input")
        if target_manifest.get("sources") != source_inventory:
            raise CorridorError(f"{target} manifest source inventory drift")


def load_artifact_lock(path: Path = DEFAULT_ARTIFACT_LOCK) -> Mapping[str, object]:
    """Load the reviewed artifact lock."""

    return _require_object(parse_json_bytes(path.read_bytes(), "artifact lock"), "artifact lock")


def load_manifest(path: Path) -> Mapping[str, object]:
    """Load one published manifest through a stable no-follow read."""

    payload = _read_stable_regular_file(path, MAX_COMPILER_OUTPUT_BYTES, "contract artifact manifest")
    return _require_object(parse_json_bytes(payload, "contract artifact manifest"), "manifest")


# ---------------------------------------------------------------------------
# Publication
# ---------------------------------------------------------------------------


def write_canonical_file(path: Path, value: object) -> None:
    """Write one canonical JSON file without following an existing path."""

    if path.exists() or path.is_symlink():
        raise CorridorError(f"refusing output path collision: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical_json_bytes(value) + b"\n")
        output.flush()
        os.fsync(output.fileno())


def render_artifact_lock(lock: Mapping[str, object]) -> bytes:
    """Render the reviewed artifact lock with sorted keys and indentation for review diffs."""

    return (json.dumps(lock, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def replace_file_atomically(path: Path, payload: bytes) -> None:
    """Replace one regular file (or create it) through a same-directory rename."""

    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CorridorError(f"refusing to replace a non-regular path: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sccp-lock-", dir=path.parent) as staging:
        staged = Path(staging) / path.name
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(staged, path)


def publish_manifest(output_dir: Path, manifest: Mapping[str, object]) -> Path:
    """Atomically publish one manifest into a new directory or one holding only a manifest."""

    if output_dir.is_symlink() or (output_dir.exists() and not output_dir.is_dir()):
        raise CorridorError("manifest output directory collides with a non-directory path")
    if output_dir.exists() and any(entry.name != MANIFEST_NAME for entry in output_dir.iterdir()):
        raise CorridorError("manifest output directory must be empty or hold only a previous manifest")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sccp-contract-artifacts-", dir=output_dir.parent) as staging_text:
        staging = Path(staging_text)
        write_canonical_file(staging / MANIFEST_NAME, manifest)
        if output_dir.exists():
            shutil.rmtree(output_dir)
        os.replace(staging, output_dir)
        # TemporaryDirectory cleanup expects its path; recreate an empty placeholder.
        staging.mkdir()
    return output_dir / MANIFEST_NAME


def build_and_validate(
    repo_root: Path,
    compiler_lock_path: Path,
    artifact_lock_path: Path,
    fetcher: CompilerFetcher = _network_fetch,
    runner: CompilerRunner = run_native_solc,
    cache_dir: Optional[Path] = DEFAULT_COMPILER_CACHE,
) -> Tuple[Mapping[str, object], CorridorConfig]:
    """Compile and fail closed unless the result matches the reviewed artifact lock."""

    config = load_corridor_config(compiler_lock_path)
    manifest = compile_corridor(repo_root, config, fetcher, runner, cache_dir)
    validate_manifest_integrity(manifest, config)
    validate_artifact_lock(manifest, load_artifact_lock(artifact_lock_path))
    return manifest, config


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _cache(args: argparse.Namespace) -> Optional[Path]:
    return None if args.no_compiler_cache else args.compiler_cache


def _build_command(args: argparse.Namespace) -> None:
    manifest, _ = build_and_validate(args.repo_root, args.compiler_lock, args.artifact_lock, cache_dir=_cache(args))
    output = publish_manifest(args.output_dir, manifest)
    print(f"wrote authenticated SCCP contract manifest: {output}")


def _lock_command(args: argparse.Namespace) -> None:
    config = load_corridor_config(args.compiler_lock)
    manifest = compile_corridor(args.repo_root, config, cache_dir=_cache(args))
    validate_manifest_integrity(manifest, config)
    lock = artifact_lock_from_manifest(manifest)
    validate_artifact_lock(manifest, lock)
    replace_file_atomically(args.output, render_artifact_lock(lock))
    if args.manifest_output is not None:
        write_canonical_file(args.manifest_output, manifest)
    print(f"wrote reviewed artifact lock: {args.output}")


def _verify_command(args: argparse.Namespace) -> None:
    config = load_corridor_config(args.compiler_lock)
    manifest = load_manifest(args.manifest)
    validate_manifest_integrity(manifest, config)
    validate_artifact_lock(manifest, load_artifact_lock(args.artifact_lock))
    validate_manifest_source_inputs(manifest, config, args.repo_root)
    print(f"verified authenticated SCCP contract manifest: {args.manifest}")


def _materialize_command(args: argparse.Namespace) -> None:
    spec = load_corridor_config().compilers[args.target]
    materialize_verified_compiler(spec, args.output, cache_dir=_cache(args))
    print(spec.artifacts[native_compiler_platform()].sha256)


def _compile_input_command(args: argparse.Namespace) -> None:
    config = load_corridor_config()
    payload = sys.stdin.buffer.read(MAX_COMPILER_INPUT_BYTES + 1)
    result = run_native_solc(args.compiler, config.compilers[args.target], payload, config.settings)
    sys.stdout.buffer.write(canonical_json_bytes(result))


def parser() -> argparse.ArgumentParser:
    """Return the corridor command-line parser."""

    result = argparse.ArgumentParser(
        description="Build, lock and verify the SCCP EVM contract with the authenticated native Solidity compiler."
    )
    subcommands = result.add_subparsers(dest="command", required=True)

    def add_cache(command: argparse.ArgumentParser) -> None:
        command.add_argument("--compiler-cache", type=Path, default=DEFAULT_COMPILER_CACHE)
        command.add_argument("--no-compiler-cache", action="store_true", help="always download the pinned compiler")

    build = subcommands.add_parser("build", help="compile, verify against the lock, and publish the manifest")
    build.add_argument("--repo-root", type=Path, default=ROOT)
    build.add_argument("--compiler-lock", type=Path, default=DEFAULT_COMPILER_LOCK)
    build.add_argument("--artifact-lock", type=Path, default=DEFAULT_ARTIFACT_LOCK)
    build.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    add_cache(build)
    build.set_defaults(handler=_build_command)

    lock = subcommands.add_parser("lock", help="recompile and rewrite the reviewed artifact lock")
    lock.add_argument("--repo-root", type=Path, default=ROOT)
    lock.add_argument("--compiler-lock", type=Path, default=DEFAULT_COMPILER_LOCK)
    lock.add_argument("--output", type=Path, default=DEFAULT_ARTIFACT_LOCK)
    lock.add_argument("--manifest-output", type=Path)
    add_cache(lock)
    lock.set_defaults(handler=_lock_command)

    verify = subcommands.add_parser("verify", help="verify a manifest against both locks and the checkout sources")
    verify.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    verify.add_argument("--compiler-lock", type=Path, default=DEFAULT_COMPILER_LOCK)
    verify.add_argument("--artifact-lock", type=Path, default=DEFAULT_ARTIFACT_LOCK)
    verify.add_argument("--repo-root", type=Path, default=ROOT)
    verify.set_defaults(handler=_verify_command)

    materialize = subcommands.add_parser("materialize", help="authenticate and publish the native compiler")
    materialize.add_argument("--target", choices=TARGETS, required=True)
    materialize.add_argument("--output", type=Path, required=True)
    add_cache(materialize)
    materialize.set_defaults(handler=_materialize_command)

    compile_input = subcommands.add_parser("compile-input", help="compile bounded standard JSON with the pinned compiler")
    compile_input.add_argument("--target", choices=TARGETS, required=True)
    compile_input.add_argument("--compiler", type=Path, required=True)
    compile_input.set_defaults(handler=_compile_input_command)
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run one corridor command; failures are reported without a traceback."""

    args = parser().parse_args(argv)
    try:
        args.handler(args)
    except (CorridorError, OSError) as error:
        print(f"SCCP contract artifact corridor failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
