"""Unit and adversarial tests for `scripts/contract_artifact_corridor.py` (SCCP v1, `specs/sccp.md` §5.5).

The corridor pins the native Solidity 0.8.31 compiler for Ethereum and BSC,
compiles `contracts/evm/sccp/SccpTairaXor.sol` and its one imported library
with the cancun legacy-pipeline settings, and locks the creation code and the
runtime template with its named immutable references. These tests use a
synthetic compiler and outputs; the real-compiler round trip runs only when the
pinned compiler is already in the corridor cache.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Mapping, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import contract_artifact_corridor as corridor  # noqa: E402


SOURCE_HEADER = "// SPDX-License-Identifier: Apache-2.0\npragma solidity 0.8.31;\n"
CONTRACT_HEADER = SOURCE_HEADER + corridor.SCCP_LIBRARY_IMPORT + "\n"
LIBRARY_TEXT = SOURCE_HEADER + "library BLS12_381 {}\n"
IMMUTABLE_IDS = {name: str(100 + index) for index, name in enumerate(corridor.EXPECTED_IMMUTABLES)}


def fake_executable(tag: bytes) -> bytes:
    """Return a minimal executable header for this host's native platform followed by `tag`."""

    platform_name = corridor.native_compiler_platform()
    if platform_name == "macos-universal":
        header = bytearray(b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big"))
        for cpu in (corridor.CPU_TYPE_X86_64, corridor.CPU_TYPE_ARM64):
            header += cpu.to_bytes(4, "big") + bytes(16)
        return bytes(header) + tag
    machine = corridor.ELF_MACHINE_X86_64 if platform_name == "linux-amd64" else corridor.ELF_MACHINE_AARCH64
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header) + tag


def fake_spec(target: str, payload: bytes) -> corridor.CompilerSpec:
    platform_name = corridor.native_compiler_platform()
    fmt = "macho-universal-arm64-x86-64" if platform_name == "macos-universal" else (
        "elf-x86-64" if platform_name == "linux-amd64" else "elf-aarch64"
    )
    artifact = corridor.NativeCompilerArtifact(
        url=f"https://example.invalid/{target}-solc",
        sha256=hashlib.sha256(payload).hexdigest(),
        format=fmt,
        reported_version=f"0.8.31+commit.{target}.Test",
    )
    return corridor.CompilerSpec(
        target=target,
        identity=f"test-{target}",
        banner=f"{target} test banner",
        reported_version=f"0.8.31+commit.{target}",
        artifacts={platform_name: artifact},
    )


EVM_COMPILER = fake_executable(b"fake evm compiler")


def fake_config(**overrides: object) -> corridor.CorridorConfig:
    config = corridor.CorridorConfig(
        compilers={"evm": fake_spec("evm", EVM_COMPILER)},
        settings=corridor.EXPECTED_SETTINGS,
        sources={"evm": corridor.SCCP_SOURCES},
        size_limits={"evm": {"creation_bytecode_bytes": 49152, "runtime_bytecode_bytes": 24576}},
        canonical_sha256="a" * 64,
    )
    return replace(config, **overrides)


def fake_repo(tmp_path: Path, body: str = "contract SccpTairaXor {}\n") -> Path:
    """Write the contract (header, library import, `body`) and an empty library."""

    source = tmp_path / corridor.SCCP_SOURCE
    library = tmp_path / corridor.SCCP_LIBRARY_SOURCE
    library.parent.mkdir(parents=True)
    source.write_text(CONTRACT_HEADER + body)
    library.write_text(LIBRARY_TEXT)
    return tmp_path


def immutable_ast() -> Mapping[str, object]:
    return {
        "nodeType": "SourceUnit",
        "nodes": [
            {
                "nodeType": "ContractDefinition",
                "nodes": [
                    {"nodeType": "VariableDeclaration", "mutability": "immutable", "id": int(ast_id), "name": name}
                    for name, ast_id in IMMUTABLE_IDS.items()
                ]
                + [{"nodeType": "VariableDeclaration", "mutability": "mutable", "id": 7, "name": "opCount"}],
            }
        ],
    }


def fake_output(runtime_tail: str = "aa") -> Mapping[str, object]:
    """Synthetic standard-json output: the contract with every §5.2.3 immutable referenced once, and the library."""

    runtime = bytearray(32 * len(IMMUTABLE_IDS)) + bytes.fromhex(runtime_tail)
    references = {ast_id: [{"start": 32 * index, "length": 32}] for index, ast_id in enumerate(IMMUTABLE_IDS.values())}
    metadata = json.dumps({"compiler": {"version": "0.8.31+commit.evm"}, "settings": {"evmVersion": "cancun"}})
    library_runtime = "73" + "00" * 20 + "3014"
    return {
        "sources": {
            corridor.SCCP_SOURCE: {"id": 0, "ast": immutable_ast()},
            corridor.SCCP_LIBRARY_SOURCE: {"id": 1, "ast": {"nodeType": "SourceUnit", "nodes": []}},
        },
        "contracts": {
            corridor.SCCP_SOURCE: {
                "SccpTairaXor": {
                    "abi": [{"type": "function", "name": "opCount", "inputs": [], "outputs": []}],
                    "metadata": metadata,
                    "evm": {
                        "bytecode": {"object": "6080" + runtime_tail, "linkReferences": {}},
                        "deployedBytecode": {
                            "object": runtime.hex(),
                            "linkReferences": {},
                            "immutableReferences": references,
                        },
                    },
                }
            },
            corridor.SCCP_LIBRARY_SOURCE: {
                "BLS12_381": {
                    "abi": [],
                    "metadata": metadata,
                    "evm": {
                        "bytecode": {"object": "6015" + library_runtime, "linkReferences": {}},
                        "deployedBytecode": {"object": library_runtime, "linkReferences": {}, "immutableReferences": {}},
                    },
                }
            },
        },
    }


def fake_runner(output: Mapping[str, object]):
    calls: List[str] = []

    def run(compiler_path: Path, spec: corridor.CompilerSpec, payload: bytes) -> Mapping[str, object]:
        compiled = corridor._read_stable_regular_file(compiler_path, corridor.MAX_COMPILER_BYTES, "compiler")
        assert hashlib.sha256(compiled).hexdigest() == spec.artifacts[corridor.native_compiler_platform()].sha256
        corridor.validate_native_compiler_input(payload, corridor.EXPECTED_SETTINGS)
        calls.append(spec.target)
        return copy.deepcopy(output)

    run.calls = calls  # type: ignore[attr-defined]
    return run


def fake_fetcher(url: str) -> bytes:
    assert url == "https://example.invalid/evm-solc"
    return EVM_COMPILER


def compile_fake(tmp_path: Path, output: Optional[Mapping[str, object]] = None):
    repo = fake_repo(tmp_path / "repo")
    config = fake_config()
    runner = fake_runner(fake_output() if output is None else output)
    manifest = corridor.compile_corridor(repo, config, fake_fetcher, runner, cache_dir=None)
    assert runner.calls == ["evm"], "one authenticated compiler process compiles the single target"
    return repo, config, manifest


def contract_output(output: Mapping[str, object]) -> Dict[str, object]:
    """The mutable `evm` output of `SccpTairaXor` inside a synthetic compiler output."""

    return output["contracts"][corridor.SCCP_SOURCE]["SccpTairaXor"]["evm"]  # type: ignore[index]


# ---------------------------------------------------------------------------
# Hashing and JSON
# ---------------------------------------------------------------------------


def test_keccak256_matches_ethereum_vectors() -> None:
    assert corridor.keccak256_hex(b"") == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert corridor.keccak256_hex(b"abc") == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert corridor.keccak256_hex(b"controlNonce()")[:8] == "4faac8ca"
    assert corridor.keccak256_hex(b"a" * 136) == corridor.keccak256(b"a" * 136).hex()
    assert len(corridor.keccak256(b"x" * 1000)) == 32
    # Ethereum Keccak-256 uses the original 0x01 padding, not NIST SHA3-256's 0x06.
    for payload in (b"", b"abc", b"a" * 136):
        assert corridor.keccak256_hex(payload) != hashlib.sha3_256(payload).hexdigest()


def test_json_parsing_rejects_duplicates_constants_and_empty_input() -> None:
    assert corridor.parse_json_bytes(b'{"a": 1}', "x") == {"a": 1}
    for payload in (b"", b'{"a": 1, "a": 2}', b'{"a": NaN}', b"\xff", b"{"):
        with pytest.raises(corridor.CorridorError):
            corridor.parse_json_bytes(payload, "x")
    assert corridor.canonical_json_bytes({"b": 1, "a": [2]}) == b'{"a":[2],"b":1}'


# ---------------------------------------------------------------------------
# Compiler lock
# ---------------------------------------------------------------------------


def test_committed_compiler_lock_pins_only_the_evm_compiler() -> None:
    config = corridor.load_corridor_config()
    assert corridor.TARGETS == ("evm",)
    assert config.settings == corridor.EXPECTED_SETTINGS
    assert config.settings["evmVersion"] == "cancun" and config.settings["viaIR"] is False
    assert config.settings["metadata"] == {"appendCBOR": False, "bytecodeHash": "none"}
    assert config.sources == {
        "evm": ("contracts/evm/sccp/SccpTairaXor.sol", "contracts/evm/sccp/lib/BLS12_381.sol")
    }
    assert config.size_limits == {"evm": {"creation_bytecode_bytes": 49152, "runtime_bytecode_bytes": 24576}}
    assert set(config.compilers) == {"evm"}
    assert set(config.compilers["evm"].artifacts) == set(corridor.PLATFORMS)
    assert config.compilers["evm"].reported_version == "0.8.31+commit.fd3a2265"
    lock = json.loads(corridor.DEFAULT_COMPILER_LOCK.read_text(encoding="utf-8"))
    assert set(lock) == {"schema", "compilers", "settings", "sources", "size_limits"}


def test_compiler_lock_rejects_a_second_target(tmp_path: Path) -> None:
    path = tmp_path / "compiler-lock.json"
    for section in ("compilers", "sources", "size_limits"):
        lock = json.loads(corridor.DEFAULT_COMPILER_LOCK.read_text(encoding="utf-8"))
        lock[section]["other"] = copy.deepcopy(lock[section]["evm"])
        path.write_text(json.dumps(lock), encoding="utf-8")
        with pytest.raises(corridor.CorridorError, match="exactly the EVM target"):
            corridor.load_corridor_config(path)
    assert set(corridor.EXPECTED_COMPILERS) == {"evm"}


def test_expected_immutables_are_the_nine_constructor_arguments() -> None:
    # `specs/sccp.md` §5.2.1 constructor arguments in declaration order.
    constructor = (
        "TAIRA_NETWORK_ID",
        "CONSENSUS_INSTANCE",
        "NETWORK_TAG",
        "ROUTE_REVISION",
        "MAX_WRAPPED_SUPPLY",
        "INITIAL_GENERATION",
        "INITIAL_COMMITTEE_ROOT",
        "INITIAL_START_HEIGHT",
        "INITIAL_UNTIL_MS",
    )
    assert len(corridor.EXPECTED_IMMUTABLES) == 9
    assert corridor.EXPECTED_IMMUTABLES == tuple(sorted(constructor))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda lock: lock["settings"].__setitem__("evmVersion", "osaka"),
        lambda lock: lock["settings"].__setitem__("viaIR", True),
        lambda lock: lock["settings"]["metadata"].__setitem__("bytecodeHash", "ipfs"),
        lambda lock: lock["compilers"]["evm"]["artifacts"]["linux-amd64"].__setitem__("sha256", "0" * 64),
        lambda lock: lock["compilers"]["evm"]["artifacts"]["macos-universal"].__setitem__("url", "http://x"),
        lambda lock: lock["compilers"]["evm"]["artifacts"].pop("linux-arm64"),
        lambda lock: lock["sources"].__setitem__("evm", ["contracts/evm/sccp/Other.sol"]),
        lambda lock: lock["sources"].__setitem__("evm", [corridor.SCCP_SOURCE]),
        lambda lock: lock["sources"].__setitem__("evm", [corridor.SCCP_LIBRARY_SOURCE]),
        lambda lock: lock["sources"]["evm"].append("contracts/evm/sccp/lib/Other.sol"),
        lambda lock: lock["sources"]["evm"].reverse(),
        lambda lock: lock["sources"].__setitem__("evm", []),
        lambda lock: lock["sources"].__setitem__("evm", ["../escape.sol"]),
        lambda lock: lock["size_limits"]["evm"].__setitem__("runtime_bytecode_bytes", 0),
        lambda lock: lock["size_limits"]["evm"].pop("creation_bytecode_bytes"),
        lambda lock: lock.__setitem__("schema", "iroha.sccp.contract-compiler-lock.v0"),
        lambda lock: lock.__setitem__("extra", 1),
    ],
)
def test_compiler_lock_mutations_fail_closed(tmp_path: Path, mutate) -> None:
    lock = json.loads(corridor.DEFAULT_COMPILER_LOCK.read_text())
    mutate(lock)
    path = tmp_path / "compiler-lock.json"
    path.write_text(json.dumps(lock))
    with pytest.raises(corridor.CorridorError):
        corridor.load_corridor_config(path)


def test_committed_compiler_lock_is_exactly_the_reviewed_native_releases() -> None:
    config = corridor.load_corridor_config()
    for target in corridor.TARGETS:
        assert corridor.compiler_identity(config.compilers[target]) == corridor.EXPECTED_COMPILERS[target]


@pytest.mark.parametrize("target", corridor.TARGETS)
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("identity", "solc-0.8.30+commit.73712a01"),
        ("banner", "solc, the solidity compiler commandline interface (patched)"),
        ("reported_version", "0.8.30+commit.73712a01"),
        ("sha256", "00" * 32),
        ("url", "https://example.invalid/unapproved-native-solc"),
        ("format", "elf-aarch64"),
        ("artifact_reported_version", "0.8.30+commit.73712a01.Linux.g++"),
    ],
)
def test_compiler_lock_rejects_every_identity_or_digest_downgrade(
    tmp_path: Path, target: str, field: str, replacement: str
) -> None:
    lock = json.loads(corridor.DEFAULT_COMPILER_LOCK.read_text(encoding="utf-8"))
    artifact = lock["compilers"][target]["artifacts"]["linux-amd64"]
    if field == "artifact_reported_version":
        artifact["reported_version"] = replacement
    elif field in artifact and field != "reported_version":
        artifact[field] = replacement
    else:
        lock["compilers"][target][field] = replacement
    path = tmp_path / "compiler-lock.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(corridor.CorridorError, match="reviewed native Solidity 0.8.31 release"):
        corridor.load_corridor_config(path)


def test_compiler_lock_rejects_portable_source_path_collisions(tmp_path: Path) -> None:
    lock = json.loads(corridor.DEFAULT_COMPILER_LOCK.read_text(encoding="utf-8"))
    lock["sources"]["evm"] = sorted(
        lock["sources"]["evm"] + ["contracts/COLLISION/Test.sol", "contracts/collision/test.sol"]
    )
    path = tmp_path / "compiler-lock.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(corridor.CorridorError, match="collision"):
        corridor.load_corridor_config(path)
    lock["sources"]["evm"] = list(reversed(lock["sources"]["evm"]))
    path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(corridor.CorridorError, match="sorted"):
        corridor.load_corridor_config(path)


def test_canonical_source_paths() -> None:
    assert corridor.canonical_source_path("contracts/evm/sccp/SccpTairaXor.sol", "p") == corridor.SCCP_SOURCE
    for bad in ("/abs.sol", "a/../b.sol", "a//b.sol", "a\\b.sol", "a/b c.sol", "", " a.sol"):
        with pytest.raises(corridor.CorridorError):
            corridor.canonical_source_path(bad, "p")


# ---------------------------------------------------------------------------
# Native platform and executable authentication
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("system", "machine", "translated", "expected"),
    [
        ("Linux", "x86_64", False, "linux-amd64"),
        ("Linux", "aarch64", False, "linux-arm64"),
        ("Darwin", "arm64", False, "macos-universal"),
        ("Darwin", "x86_64", False, "macos-universal"),
    ],
)
def test_native_platform_selection(monkeypatch, system, machine, translated, expected) -> None:
    monkeypatch.setattr(corridor.platform, "system", lambda: system)
    monkeypatch.setattr(corridor.platform, "machine", lambda: machine)
    monkeypatch.setattr(corridor, "_darwin_translated", lambda: translated)
    assert corridor.native_compiler_platform() == expected


def test_native_platform_refuses_rosetta_and_unknown_hosts(monkeypatch) -> None:
    monkeypatch.setattr(corridor.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(corridor.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(corridor, "_darwin_translated", lambda: True)
    with pytest.raises(corridor.CorridorError, match="Rosetta"):
        corridor.native_compiler_platform()
    monkeypatch.setattr(corridor.platform, "system", lambda: "Windows")
    with pytest.raises(corridor.CorridorError):
        corridor.native_compiler_platform()


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (subprocess.CompletedProcess([], 0, b"1\n", b""), True),
        (subprocess.CompletedProcess([], 0, b"0\n", b""), False),
        (subprocess.CompletedProcess([], 1, b"", b"sysctl: unknown oid 'sysctl.proc_translated'"), False),
        (OSError("sysctl is unavailable"), None),
        (subprocess.TimeoutExpired(["/usr/sbin/sysctl"], 10), None),
    ],
)
def test_rosetta_probe(monkeypatch, outcome: object, expected: Optional[bool]) -> None:
    calls: List[Mapping[str, object]] = []

    def run(arguments, **kwargs):
        calls.append({"arguments": arguments, **kwargs})
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(corridor.subprocess, "run", run)
    if expected is None:
        with pytest.raises(corridor.CorridorError, match="Rosetta"):
            corridor._darwin_translated()
    else:
        assert corridor._darwin_translated() is expected
    assert calls == [
        {
            "arguments": ["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"],
            "capture_output": True,
            "check": False,
            "timeout": 10,
            "env": {"LANG": "C", "LC_ALL": "C"},
        }
    ]


def test_executable_format_validation() -> None:
    elf = bytearray(64)
    elf[:6] = b"\x7fELF\x02\x01"
    elf[18:20] = corridor.ELF_MACHINE_X86_64.to_bytes(2, "little")
    corridor.validate_executable_format(bytes(elf), "elf-x86-64")
    with pytest.raises(corridor.CorridorError):
        corridor.validate_executable_format(bytes(elf), "elf-aarch64")
    universal = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big")
    universal += corridor.CPU_TYPE_X86_64.to_bytes(4, "big") + bytes(16)
    universal += corridor.CPU_TYPE_ARM64.to_bytes(4, "big") + bytes(16)
    corridor.validate_executable_format(universal, "macho-universal-arm64-x86-64")
    x86_only = b"\xca\xfe\xba\xbe" + (1).to_bytes(4, "big") + corridor.CPU_TYPE_X86_64.to_bytes(4, "big") + bytes(16)
    for payload, fmt in ((x86_only, "macho-universal-arm64-x86-64"), (b"#!/bin/sh\n", "elf-x86-64"), (universal, "pe")):
        with pytest.raises(corridor.CorridorError):
            corridor.validate_executable_format(payload, fmt)


def test_compiler_download_is_authenticated_and_cached(tmp_path: Path) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    cache = tmp_path / "cache"
    fetched: List[str] = []

    def fetch(url: str) -> bytes:
        fetched.append(url)
        return EVM_COMPILER

    assert corridor.authenticated_compiler_bytes(spec, fetch, cache) == EVM_COMPILER
    assert corridor.authenticated_compiler_bytes(spec, fetch, cache) == EVM_COMPILER
    assert len(fetched) == 1, "the second call is served from the SHA-256 cache"
    cached = cache / spec.artifacts[corridor.native_compiler_platform()].sha256
    assert stat.S_IMODE(cached.stat().st_mode) == 0o400
    cached.chmod(0o600)
    cached.write_bytes(b"corrupted")
    assert corridor.authenticated_compiler_bytes(spec, fetch, cache) == EVM_COMPILER
    assert len(fetched) == 2, "a corrupted cache entry is discarded and re-fetched"
    with pytest.raises(corridor.CorridorError, match="digest mismatch"):
        corridor.authenticated_compiler_bytes(spec, lambda url: EVM_COMPILER + b"x", None)
    with pytest.raises(corridor.CorridorError):
        corridor.authenticated_compiler_bytes(spec, lambda url: b"", None)
    cached.unlink()
    cached.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(corridor.CorridorError, match="regular file"):
        corridor.authenticated_compiler_bytes(spec, fetch, cache)


def test_compiler_download_rejects_unpinned_bytes_and_leaves_no_executable(tmp_path: Path) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    destination = tmp_path / "compiler-native"
    with pytest.raises(corridor.CorridorError, match="digest mismatch"):
        corridor.materialize_verified_compiler(spec, destination, lambda _url: EVM_COMPILER + b"tampered", None)
    assert not destination.exists()
    host = corridor.native_compiler_platform()
    drifted = replace(spec, artifacts={host: replace(spec.artifacts[host], sha256="00" * 32)})
    with pytest.raises(corridor.CorridorError, match="digest mismatch"):
        corridor.materialize_verified_compiler(drifted, destination, lambda _url: EVM_COMPILER, None)
    assert not destination.exists()
    oversized = replace(spec, artifacts={host: replace(spec.artifacts[host], sha256=hashlib.sha256(b"x").hexdigest())})
    with pytest.raises(corridor.CorridorError, match="bounded size"):
        corridor.authenticated_compiler_bytes(oversized, lambda _url: b"x" * (corridor.MAX_COMPILER_BYTES + 1), None)


class FakeHttpResponse:
    """Minimal `urlopen` response: headers plus a bounded `read`."""

    def __init__(self, body: bytes, content_length: Optional[str]) -> None:
        self.body = body
        self.headers = {} if content_length is None else {"Content-Length": content_length}
        self.requested: List[int] = []

    def __enter__(self) -> "FakeHttpResponse":
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def read(self, amount: int) -> bytes:
        self.requested.append(amount)
        return self.body[:amount]


@pytest.mark.parametrize(
    ("content_length", "body", "message"),
    [
        ("65", b"x" * 65, "bounded size"),
        ("0", b"", "bounded size"),
        ("-1", b"x", "bounded size"),
        ("sixty", b"x", "invalid Content-Length"),
        ("", b"x", "invalid Content-Length"),
    ],
)
def test_network_fetch_rejects_invalid_or_oversized_content_length(
    monkeypatch, content_length: str, body: bytes, message: str
) -> None:
    monkeypatch.setattr(corridor, "MAX_COMPILER_BYTES", 64)
    response = FakeHttpResponse(body, content_length)
    monkeypatch.setattr(corridor.urllib.request, "urlopen", lambda request, timeout: response)
    with pytest.raises(corridor.CorridorError, match=message):
        corridor._network_fetch("https://example.invalid/solc")
    assert response.requested == [], "the body is not read once the declared length is refused"


def test_network_fetch_reads_at_most_one_byte_past_the_bound(monkeypatch) -> None:
    monkeypatch.setattr(corridor, "MAX_COMPILER_BYTES", 64)
    seen: List[object] = []

    def urlopen(request, timeout):
        seen.append((request.full_url, request.get_header("User-agent"), timeout))
        return responses.pop(0)

    responses = [FakeHttpResponse(b"x" * 64, "64"), FakeHttpResponse(b"y" * 500, None)]
    monkeypatch.setattr(corridor.urllib.request, "urlopen", urlopen)
    assert corridor._network_fetch("https://example.invalid/solc") == b"x" * 64
    undeclared = corridor._network_fetch("https://example.invalid/solc")
    assert undeclared == b"y" * 65, "an undeclared length is cut one byte past the bound"
    assert seen == [("https://example.invalid/solc", "iroha-sccp-contract-corridor/1", 120)] * 2
    spec = fake_spec("evm", undeclared)
    with pytest.raises(corridor.CorridorError, match="bounded size"):
        corridor.authenticated_compiler_bytes(spec, lambda _url: undeclared, None)


def test_materialized_compiler_is_private_and_collision_free(tmp_path: Path) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    destination = tmp_path / "bin" / "solc"
    corridor.materialize_verified_compiler(spec, destination, lambda url: EVM_COMPILER, None)
    assert destination.read_bytes() == EVM_COMPILER
    assert stat.S_IMODE(destination.stat().st_mode) == 0o500
    with pytest.raises(corridor.CorridorError, match="collision"):
        corridor.materialize_verified_compiler(spec, destination, lambda url: EVM_COMPILER, None)


def test_run_native_solc_rejects_mutated_compiler_before_execution(tmp_path: Path) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    compiler = tmp_path / "solc"
    compiler.write_bytes(EVM_COMPILER + b"\n")
    payload = corridor.canonical_json_bytes(
        {"language": "Solidity", "sources": {"a.sol": {"content": "x"}}, "settings": corridor.EXPECTED_SETTINGS}
    )
    with pytest.raises(corridor.CorridorError, match="digest mismatch before execution"):
        corridor.run_native_solc(compiler, spec, payload)
    with pytest.raises(corridor.CorridorError):
        corridor.run_native_solc(compiler, spec, b"")


def test_native_compiler_input_admission() -> None:
    good = {"language": "Solidity", "sources": {"a/B.sol": {"content": "x"}}, "settings": corridor.EXPECTED_SETTINGS}
    corridor.validate_native_compiler_input(corridor.canonical_json_bytes(good), corridor.EXPECTED_SETTINGS)
    bad_inputs = [
        {**good, "language": "Yul"},
        {**good, "extra": 1},
        {**good, "sources": {}},
        {**good, "sources": {"a/B.sol": {"urls": ["file:///etc/passwd"]}}},
        {**good, "sources": {"../B.sol": {"content": "x"}}},
        {**good, "settings": {**corridor.EXPECTED_SETTINGS, "evmVersion": "osaka"}},
        {**good, "settings": {**corridor.EXPECTED_SETTINGS, "outputSelection": {"*": {"*": ["*"]}}}},
        {**good, "settings": {**corridor.EXPECTED_SETTINGS, "remappings": ["/=../../"]}},
        {**good, "settings": {**corridor.EXPECTED_SETTINGS, "viaIR": True}},
        {**good, "sources": {"a/B.sol": {"content": "x", "keccak256": "0x00"}}},
        {**good, "sources": {"a/B.sol": {"content": ""}}},
    ]
    for value in bad_inputs:
        with pytest.raises(corridor.CorridorError):
            corridor.validate_native_compiler_input(corridor.canonical_json_bytes(value), corridor.EXPECTED_SETTINGS)


def native_input() -> bytes:
    """Content-only standard JSON under exactly the locked settings."""

    return corridor.canonical_json_bytes(
        {"language": "Solidity", "sources": {"Test.sol": {"content": "contract Test {}"}}, "settings": corridor.EXPECTED_SETTINGS}
    )


def expected_banner(spec: corridor.CompilerSpec) -> bytes:
    version = spec.artifacts[corridor.native_compiler_platform()].reported_version
    return f"{spec.banner}\nVersion: {version}\n".encode()


def test_native_version_and_compile_share_one_private_verified_copy(tmp_path: Path, monkeypatch) -> None:
    original = tmp_path / "native-solc"
    original.write_bytes(EVM_COMPILER)
    spec = fake_spec("evm", EVM_COMPILER)
    calls: List[Path] = []

    def command(executable: Path, arguments: List[str], payload: bytes, directory: Path, limit: int) -> bytes:
        calls.append(executable)
        assert executable != original and executable.parent == directory
        assert executable.read_bytes() == EVM_COMPILER
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(executable.stat().st_mode) == 0o500
        if arguments == ["--version"]:
            assert payload == b"" and limit == 4096
            original.write_bytes(b"replaced after authentication")
            return expected_banner(spec)
        assert arguments == ["--standard-json"]
        assert payload == native_input() and limit == corridor.MAX_COMPILER_OUTPUT_BYTES
        return b'{"contracts":{}}'

    monkeypatch.setattr(corridor, "_run_native_command", command)
    assert corridor.run_native_solc(original, spec, native_input()) == {"contracts": {}}
    assert len(calls) == 2 and calls[0] == calls[1]
    assert not calls[0].exists(), "the private executable copy is removed after the run"


@pytest.mark.parametrize("case", ("symlink", "digest", "format", "target-version", "input"))
def test_native_runner_rejects_untrusted_bytes_and_wrong_target(tmp_path: Path, monkeypatch, case: str) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    executable = tmp_path / "compiler"
    executable.write_bytes(EVM_COMPILER)
    payload = native_input()
    if case == "symlink":
        link = tmp_path / "link"
        link.symlink_to(executable)
        executable = link
    elif case == "digest":
        executable.write_bytes(EVM_COMPILER + b"tampered")
    elif case == "format":
        executable.write_bytes(b"not native")
        spec = fake_spec("evm", b"not native")
    elif case == "input":
        payload = b"x" * (corridor.MAX_COMPILER_INPUT_BYTES + 1)
    calls: List[object] = []

    def command(*args: object) -> bytes:
        calls.append(args)
        return b"solc.fork, the solidity compiler commandline interface\nVersion: wrong\n"

    monkeypatch.setattr(corridor, "_run_native_command", command)
    with pytest.raises(corridor.CorridorError):
        corridor.run_native_solc(executable, spec, payload)
    assert len(calls) == (1 if case == "target-version" else 0)


FAKE_SOLC_SCRIPT = """#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\\nVersion: %s\\n' '{banner}' '{version}'
  exit 0
fi
{standard_json}
"""


def script_compiler(tmp_path: Path, monkeypatch, banner: str, version: str, standard_json: str):
    """Publish a `/bin/sh` stand-in compiler whose bytes the spec pins (format check stubbed)."""

    payload = FAKE_SOLC_SCRIPT.format(banner=banner, version=version, standard_json=standard_json).encode()
    path = tmp_path / "solc-script"
    path.write_bytes(payload)
    monkeypatch.setattr(corridor, "validate_executable_format", lambda _payload, _expected: None)
    return path, fake_spec("evm", payload)


def test_run_native_solc_executes_the_private_copy_and_checks_its_banner(tmp_path: Path, monkeypatch) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    version = spec.artifacts[corridor.native_compiler_platform()].reported_version
    path, spec = script_compiler(
        tmp_path, monkeypatch, spec.banner, version, """printf '{"contracts":{},"cwd":"%s"}' "$(pwd -P)\""""
    )
    result = corridor.run_native_solc(path, spec, native_input())
    assert result["contracts"] == {}
    assert Path(result["cwd"]).name.startswith("iroha-sccp-native-solc-")
    assert not Path(result["cwd"]).exists()

    wrong_dir = tmp_path / "wrong"
    wrong_dir.mkdir()
    # A fork compiler's banner under the EVM spec: right version, wrong target.
    wrong, wrong_spec = script_compiler(
        wrong_dir, monkeypatch, "solc.fork, the solidity compiler commandline interface", version,
        """printf '{"contracts":{}}'""",
    )
    assert wrong_spec.banner == spec.banner
    with pytest.raises(corridor.CorridorError, match="unexpected version or target"):
        corridor.run_native_solc(wrong, wrong_spec, native_input())


@pytest.mark.parametrize(
    ("standard_json", "message"),
    [
        ("""printf 'Warning: loose' >&2; printf '{"contracts":{}}'""", "Warning: loose"),
        ("exit 3", "authenticated native compiler failed"),
        ("printf 'not json'", "malformed JSON"),
        (":", "bounded size policy"),
    ],
)
def test_run_native_solc_fails_closed_on_compiler_misbehaviour(
    tmp_path: Path, monkeypatch, standard_json: str, message: str
) -> None:
    spec = fake_spec("evm", EVM_COMPILER)
    version = spec.artifacts[corridor.native_compiler_platform()].reported_version
    path, spec = script_compiler(tmp_path, monkeypatch, spec.banner, version, standard_json)
    with pytest.raises(corridor.CorridorError, match=message):
        corridor.run_native_solc(path, spec, native_input())


def test_native_subprocess_has_clean_environment_and_bounded_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/untrusted/compiler-hook.so")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/untrusted/compiler-hook.dylib")
    program = "import os,sys;sys.stdout.write(','.join(sorted(os.environ)))"
    actual = corridor._run_native_command(Path(sys.executable), ["-c", program], b"", tmp_path, 4096)
    names = set(actual.decode().split(","))
    assert {"LANG", "LC_ALL", "TZ"} <= names
    # macOS CoreFoundation adds its own text-encoding marker to every process.
    assert names <= {"LANG", "LC_ALL", "TZ", "__CF_USER_TEXT_ENCODING"}
    echoed = corridor._run_native_command(
        Path(sys.executable), ["-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"], b"{}", tmp_path, 4096
    )
    assert echoed == b"{}"
    for code, limit, message in (
        ("print('too much output')", 2, None),
        ("import sys;sys.stderr.write('warning: diagnostic')", 4096, "warning: diagnostic"),
        ("raise SystemExit(1)", 4096, "authenticated native compiler failed"),
        ("pass", 4096, "bounded size policy"),
    ):
        with pytest.raises(corridor.CorridorError, match=message):
            corridor._run_native_command(Path(sys.executable), ["-c", code], b"", tmp_path, limit)
        assert (tmp_path / "output.json").stat().st_size <= limit
        assert (tmp_path / "stderr.txt").stat().st_size <= limit


def test_native_command_timeout_fails_closed(tmp_path: Path, monkeypatch) -> None:
    def timeout(*args: object, **kwargs: object):
        assert kwargs["timeout"] == 300
        assert kwargs["env"] == {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
        raise subprocess.TimeoutExpired(args[0], 300)

    monkeypatch.setattr(corridor.subprocess, "run", timeout)
    with pytest.raises(corridor.CorridorError, match="could not complete"):
        corridor._run_native_command(Path("solc"), ["--version"], b"", tmp_path, 4096)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is required for the native compiler adapter")
@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("input", "standard-json compiler input must be a string"),
        ("missing", "absolute authenticated native compiler path is required"),
        ("relative", "absolute authenticated native compiler path is required"),
        ("target", "compiler target must be evm"),
        ("tampered", "digest mismatch before execution"),
    ],
)
def test_node_native_adapter_rejects_unadmitted_compilers(tmp_path: Path, case: str, message: str) -> None:
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"untrusted native compiler")
    environment = dict(os.environ)
    options = {"pythonBin": sys.executable}
    if case == "relative":
        options["compilerPath"] = "relative-solc"
    elif case in ("tampered", "target", "input"):
        options["compilerPath"] = str(compiler)
    if case == "target":
        options["target"] = "wasm"
    expression = "{}" if case == "input" else json.dumps(native_input().decode())
    script = (
        "require('./scripts/contract_native_solc.js')"
        f".compileNativeSolidity({expression}, {json.dumps(options)})"
    )
    result = subprocess.run(
        ["node", "-e", script], cwd=ROOT, env=environment, capture_output=True, text=True, check=False, timeout=60
    )
    assert result.returncode != 0
    assert message in result.stderr


# ---------------------------------------------------------------------------
# Source policy
# ---------------------------------------------------------------------------


def test_source_policy_accepts_the_committed_sources() -> None:
    for relative in corridor.SCCP_SOURCES:
        source = (ROOT / relative).read_text(encoding="utf-8")
        corridor.validate_solidity_source_policy(source, relative)


def test_source_policy_admits_only_the_bls_library_import() -> None:
    assert corridor.SCCP_LIBRARY_IMPORT == 'import {BLS12_381} from "./lib/BLS12_381.sol";'
    body = "contract SccpTairaXor {}\n"
    corridor.validate_solidity_source_policy(CONTRACT_HEADER + body, corridor.SCCP_SOURCE)
    corridor.validate_solidity_source_policy(LIBRARY_TEXT, corridor.SCCP_LIBRARY_SOURCE)
    # A comment or string that spells an import is not a directive.
    corridor.validate_solidity_source_policy(
        CONTRACT_HEADER + '// import "./Other.sol";\ncontract SccpTairaXor { string s = "import"; }\n',
        corridor.SCCP_SOURCE,
    )
    for directives in (
        "",
        corridor.SCCP_LIBRARY_IMPORT + "\n" + corridor.SCCP_LIBRARY_IMPORT + "\n",
        corridor.SCCP_LIBRARY_IMPORT + '\nimport "./lib/Other.sol";\n',
        'import "./lib/BLS12_381.sol";\n',
        'import {BLS12_381} from "lib/BLS12_381.sol";\n',
        'import {BLS12_381} from "./lib/BLS12_381.sol" ;\n',
        'import {BLS12_381 as B} from "./lib/BLS12_381.sol";\n',
        'import {BLS12_381} from /* hidden */ "./lib/BLS12_381.sol";\n',
        'import * as B from "./lib/BLS12_381.sol";\n',
        'import {BLS12_381} from "./lib/../lib/BLS12_381.sol";\n',
        'import {BLS12_381} from "https://example.invalid/BLS12_381.sol";\n',
    ):
        with pytest.raises(corridor.CorridorError, match="must import exactly"):
            corridor.validate_solidity_source_policy(SOURCE_HEADER + directives + body, corridor.SCCP_SOURCE)
    with pytest.raises(corridor.CorridorError, match="incomplete or obfuscated import"):
        corridor.validate_solidity_source_policy(CONTRACT_HEADER + "contract SccpTairaXor { import\n", corridor.SCCP_SOURCE)
    # The library, and any other source, imports nothing: not even the library itself.
    for relative in (corridor.SCCP_LIBRARY_SOURCE, "contracts/evm/sccp/Other.sol"):
        with pytest.raises(corridor.CorridorError, match="self-contained without imports"):
            corridor.validate_solidity_source_policy(CONTRACT_HEADER + "library BLS12_381 {}\n", relative)
    for pattern, message in (("delete", "delete"), ("layout at", "storage layout")):
        text = SOURCE_HEADER + f"library BLS12_381 {{ function f() internal {{ {pattern} }} }}\n"
        with pytest.raises(corridor.CorridorError, match=message):
            corridor.validate_solidity_source_policy(text, corridor.SCCP_LIBRARY_SOURCE)
    with pytest.raises(corridor.CorridorError, match="pragma"):
        corridor.validate_solidity_source_policy(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.25;\nlibrary BLS12_381 {}\n",
            corridor.SCCP_LIBRARY_SOURCE,
        )


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("pragma solidity 0.8.31;\ncontract A {}\n", "SPDX"),
        ("// SPDX-License-Identifier: Apache-2.0\npragma solidity ^0.8.31;\ncontract A {}\n", "pragma"),
        (SOURCE_HEADER + "pragma abicoder v2;\ncontract A {}\n", "pragma"),
        (SOURCE_HEADER + "contract A { function f(bytes memory b) internal pure { delete b[0]; } }\n", "delete"),
        (SOURCE_HEADER + "contract A layout at 0x10 {}\n", "storage layout"),
        (SOURCE_HEADER + 'import "./B.sol";\ncontract A {}\n', "imports"),
        (SOURCE_HEADER + "contract A {} /* unterminated\n", "unterminated"),
        (SOURCE_HEADER + "contract A { pragma\n", "pragma"),
    ],
)
def test_source_policy_rejects_legacy_pipeline_bug_patterns(source: str, message: str) -> None:
    with pytest.raises(corridor.CorridorError, match=message):
        corridor.validate_solidity_source_policy(source, "x.sol")


def test_source_policy_ignores_comments_and_strings() -> None:
    source = SOURCE_HEADER + '// delete layout at import pragma\ncontract A { string s = "delete import"; }\n'
    corridor.validate_solidity_source_policy(source, "x.sol")


def test_source_reader_refuses_symlinks_and_escapes(tmp_path: Path) -> None:
    repo = fake_repo(tmp_path / "repo")
    corridor._read_source(repo, corridor.SCCP_SOURCE)
    outside = tmp_path / "outside.sol"
    outside.write_text(SOURCE_HEADER)
    link = repo / "contracts" / "link.sol"
    link.symlink_to(outside)
    with pytest.raises(corridor.CorridorError):
        corridor._read_source(repo, "contracts/link.sol")
    with pytest.raises(corridor.CorridorError, match="missing"):
        corridor._read_source(repo, "contracts/missing.sol")
    (repo / "contracts" / "latin1.sol").write_bytes(SOURCE_HEADER.encode() + b"// \xff\n")
    with pytest.raises(corridor.CorridorError, match="UTF-8"):
        corridor._read_source(repo, "contracts/latin1.sol")


def test_large_source_trivia_preserves_exact_compiler_input(tmp_path: Path) -> None:
    repo = fake_repo(tmp_path / "repo", "//" + "x" * (2 * 1024 * 1024) + "\ncontract SccpTairaXor {}\n")
    expected = (repo / corridor.SCCP_SOURCE).read_bytes()
    assert corridor._read_source(repo, corridor.SCCP_SOURCE) == expected
    value, inventory = corridor.standard_json_input(repo, fake_config(), "evm")
    payload = corridor.canonical_json_bytes(value)
    assert len(payload) < corridor.MAX_COMPILER_INPUT_BYTES
    corridor.validate_native_compiler_input(payload, corridor.EXPECTED_SETTINGS)
    assert value["sources"][corridor.SCCP_SOURCE]["content"].encode() == expected
    assert inventory[0]["byte_length"] == len(expected)
    assert inventory[0]["sha256_hex"] == hashlib.sha256(expected).hexdigest()


def test_compiler_input_resource_bound_and_utf8_remain_required() -> None:
    with pytest.raises(corridor.CorridorError, match="exceeds 16 MiB"):
        corridor.validate_native_compiler_input(b" " * (corridor.MAX_COMPILER_INPUT_BYTES + 1), corridor.EXPECTED_SETTINGS)
    value = {"language": "Solidity", "sources": {"Test.sol": {"content": "\ud800"}}, "settings": corridor.EXPECTED_SETTINGS}
    with pytest.raises(corridor.CorridorError, match="UTF-8"):
        corridor.validate_native_compiler_input(json.dumps(value).encode(), corridor.EXPECTED_SETTINGS)


def test_source_reader_refuses_impossible_total_input_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = fake_repo(tmp_path / "repo")
    source = repo / corridor.SCCP_SOURCE
    with source.open("wb") as handle:
        handle.truncate(corridor.MAX_COMPILER_INPUT_BYTES + 1)

    def unexpected_read(*args: object) -> bytes:
        pytest.fail("an inode larger than the total compiler envelope must not be read")

    monkeypatch.setattr(corridor.os, "read", unexpected_read)
    with pytest.raises(corridor.CorridorError, match="bounded size policy"):
        corridor._read_source(repo, corridor.SCCP_SOURCE)


def test_source_map_uses_remaining_aggregate_compiler_input_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = fake_repo(tmp_path / "repo", "//" + "x" * 1000 + "\ncontract SccpTairaXor {}\n")
    other = "contracts/Other.sol"
    (repo / other).write_text(SOURCE_HEADER + "//" + "y" * 1000 + "\ncontract Other {}\n")
    config = fake_config(sources={"evm": (corridor.SCCP_SOURCE, other)})
    first_size = (repo / corridor.SCCP_SOURCE).stat().st_size
    second_size = (repo / other).stat().st_size
    total_budget = first_size + second_size - 1
    monkeypatch.setattr(corridor, "MAX_COMPILER_INPUT_BYTES", total_budget)
    read = corridor._read_stable_regular_file
    admitted_budgets = []

    def record_budget(path: Path, maximum_bytes: int, label: str) -> bytes:
        admitted_budgets.append(maximum_bytes)
        return read(path, maximum_bytes, label)

    monkeypatch.setattr(corridor, "_read_stable_regular_file", record_budget)
    with pytest.raises(corridor.CorridorError, match="bounded size policy"):
        corridor.standard_json_input(repo, config, "evm")
    assert admitted_budgets == [total_budget, second_size - 1]

    # Raw bytes alone can fit while the serialized object does not. JSON
    # overhead still passes through the exact final compiler-input admission.
    monkeypatch.setattr(corridor, "MAX_COMPILER_INPUT_BYTES", first_size)
    value, _ = corridor.standard_json_input(repo, fake_config(sources={"evm": (corridor.SCCP_SOURCE,)}), "evm")
    with pytest.raises(corridor.CorridorError, match="exceeds 16 MiB"):
        corridor.validate_native_compiler_input(corridor.canonical_json_bytes(value), corridor.EXPECTED_SETTINGS)


@pytest.mark.parametrize(
    "directive",
    (
        "pragma solidity 0.8.30;",
        "pragma solidity 0.7.6;",
        "pragma solidity ^0.8.31;",
        "pragma solidity =0.8.31;",
        "pragma  solidity 0.8.31;",
        "pragma solidity /* hidden range */ >=0.8.31 <0.9.0;",
        "pragma solidity 0.8.31/* hidden terminator */;",
        "pragma solidity 0.8.31;\npragma solidity 0.8.31;",
        "pragma solidity 0.8.31;\npragma experimental ABIEncoderV2;",
        "pragma solidity 0.8.31;\npragma abicoder v1;",
        "pragma solidity\n0.8.31;",
        "pragma solidity 0.8.31",
    ),
)
def test_source_policy_rejects_noncanonical_duplicate_and_obfuscated_pragmas(tmp_path: Path, directive: str) -> None:
    repo = fake_repo(tmp_path)
    source = repo / corridor.SCCP_SOURCE
    source.write_text(f"// SPDX-License-Identifier: Apache-2.0\n{directive}\ncontract SccpTairaXor {{}}\n")
    with pytest.raises(corridor.CorridorError, match="pragma"):
        corridor.standard_json_input(repo, fake_config(), "evm")


def test_source_policy_ignores_fake_pragmas_in_comments_and_strings(tmp_path: Path) -> None:
    repo = fake_repo(tmp_path)
    source = repo / corridor.SCCP_SOURCE
    text = (
        "// SPDX-License-Identifier: Apache-2.0\n"
        "// pragma solidity ^0.8.0;\n"
        "/* pragma experimental ABIEncoderV2; */\n"
        "pragma solidity 0.8.31;\n"
        f"{corridor.SCCP_LIBRARY_IMPORT}\n"
        'contract SccpTairaXor { string constant TEXT = "pragma solidity ^0.7.0; \\" delete"; }\n'
    )
    source.write_text(text)
    standard_input, inventory = corridor.standard_json_input(repo, fake_config(), "evm")
    assert list(standard_input["sources"]) == list(corridor.SCCP_SOURCES)
    assert standard_input["sources"][corridor.SCCP_SOURCE]["content"] == text
    assert standard_input["sources"][corridor.SCCP_LIBRARY_SOURCE]["content"] == LIBRARY_TEXT
    assert standard_input["settings"] == corridor.EXPECTED_SETTINGS
    assert inventory == [
        {
            "path": relative,
            "byte_length": len(content.encode()),
            "sha256_hex": hashlib.sha256(content.encode()).hexdigest(),
            "keccak256_hex": corridor.keccak256_hex(content.encode()),
        }
        for relative, content in ((corridor.SCCP_SOURCE, text), (corridor.SCCP_LIBRARY_SOURCE, LIBRARY_TEXT))
    ]
    with pytest.raises(corridor.CorridorError, match="unknown contract compilation target"):
        corridor.standard_json_input(repo, fake_config(), "wasm")


# ---------------------------------------------------------------------------
# Output normalization, immutables and the artifact lock
# ---------------------------------------------------------------------------


def test_immutable_names_come_from_the_ast() -> None:
    names = corridor.immutable_names({"sources": {"a": {"ast": immutable_ast()}}})
    assert names == {ast_id: name for name, ast_id in IMMUTABLE_IDS.items()}
    malformed = {"sources": {"a": {"ast": {"nodeType": "VariableDeclaration", "mutability": "immutable", "id": "1", "name": "X"}}}}
    with pytest.raises(corridor.CorridorError):
        corridor.immutable_names(malformed)


def test_runtime_immutable_references_are_zero_windows_without_overlap() -> None:
    names = {"1": "A", "2": "B"}
    runtime = bytes(96)
    refs = corridor.runtime_immutable_references({"2": [{"start": 64, "length": 32}], "1": [{"start": 0, "length": 32}]}, runtime, names, "x")
    assert refs == [
        {"name": "A", "ast_id": "1", "start": 0, "length": 32},
        {"name": "B", "ast_id": "2", "start": 64, "length": 32},
    ]
    for value, code in (
        ({"1": [{"start": 0, "length": 32}]}, b"\x01" + bytes(95)),
        ({"1": [{"start": 80, "length": 32}]}, runtime),
        ({"1": [{"start": 0, "length": 20}]}, runtime),
        ({"3": [{"start": 0, "length": 32}]}, runtime),
        ({"1": [{"start": 0, "length": 32}], "2": [{"start": 16, "length": 32}]}, runtime),
        ({"1": []}, runtime),
    ):
        with pytest.raises(corridor.CorridorError):
            corridor.runtime_immutable_references(value, code, names, "x")


def test_compile_corridor_records_templates_and_named_immutables(tmp_path: Path) -> None:
    _, config, manifest = compile_fake(tmp_path)
    corridor.validate_manifest_integrity(manifest, config)
    record = manifest["targets"]["evm"]["contracts"][0]
    assert record["fully_qualified_name"] == corridor.SCCP_CONTRACT
    assert sorted({ref["name"] for ref in record["runtime_immutable_references"]}) == list(corridor.EXPECTED_IMMUTABLES)
    library = manifest["targets"]["evm"]["contracts"][1]
    assert library["fully_qualified_name"] == corridor.SCCP_LIBRARY
    assert library["runtime_immutable_references"] == []
    lock = corridor.artifact_lock_from_manifest(manifest)
    locked = lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT]
    assert locked["runtime_template_hex"] == record["runtime_bytecode"]["hex"]
    assert locked["immutable_references"] == record["runtime_immutable_references"]
    corridor.validate_artifact_lock(manifest, lock)


def test_artifact_lock_records_the_creation_code(tmp_path: Path) -> None:
    _, _, manifest = compile_fake(tmp_path)
    lock = corridor.artifact_lock_from_manifest(manifest)
    assert list(lock["targets"]) == ["evm"]
    # The key path `iroha_cli` reads; the inlined library is not a deployable artifact.
    contracts = lock["targets"]["evm"]["contracts"]
    assert list(contracts) == ["contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor"]
    entry = contracts[corridor.SCCP_CONTRACT]
    assert set(entry) == {
        "creation_bytecode_bytes",
        "creation_bytecode_hex",
        "creation_bytecode_keccak256_hex",
        "runtime_bytecode_bytes",
        "runtime_template_hex",
        "runtime_template_keccak256_hex",
        "immutable_references",
        "abi_sha256_hex",
    }
    assert entry["creation_bytecode_hex"] == "0x6080aa"
    creation = bytes.fromhex(entry["creation_bytecode_hex"][2:])
    assert entry["creation_bytecode_bytes"] == len(creation) == 3
    assert entry["creation_bytecode_keccak256_hex"] == corridor.keccak256_hex(creation)
    rendered = json.loads(corridor.render_artifact_lock(lock))
    assert rendered["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT]["creation_bytecode_hex"] == "0x6080aa"
    # A different creation code with the same runtime is a different lock.
    other = fake_output()
    contract_output(other)["bytecode"]["object"] = "6081aa"
    _, _, changed = compile_fake(tmp_path / "changed", other)
    with pytest.raises(corridor.CorridorError, match="creation_bytecode_hex drift"):
        corridor.validate_artifact_lock(changed, lock)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__("runtime_template_hex", "0x00"),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT]["immutable_references"].pop(),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__("abi_sha256_hex", "0" * 64),
        lambda lock: lock["targets"]["evm"].__setitem__("standard_json_input_sha256_hex", "0" * 64),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__("runtime_bytecode_bytes", 1),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__("creation_bytecode_bytes", 1),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__("creation_bytecode_hex", "0x6080ab"),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].pop("creation_bytecode_hex"),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__(
            "creation_bytecode_keccak256_hex", "0" * 64
        ),
        lambda lock: lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT].__setitem__("unreviewed", True),
        lambda lock: lock["targets"]["evm"]["contracts"].pop(corridor.SCCP_CONTRACT),
        lambda lock: lock["targets"]["evm"]["contracts"].__setitem__(
            corridor.SCCP_LIBRARY, copy.deepcopy(lock["targets"]["evm"]["contracts"][corridor.SCCP_CONTRACT])
        ),
        lambda lock: lock["targets"].pop("evm"),
        lambda lock: lock["targets"].__setitem__("other", copy.deepcopy(lock["targets"]["evm"])),
        lambda lock: lock.__setitem__("corridor_manifest_sha256_hex", "not-hex"),
        lambda lock: lock["targets"]["evm"]["contracts"].__setitem__("x.sol:X", {}),
        lambda lock: lock.__setitem__("corridor_manifest_sha256_hex", "0" * 64),
        lambda lock: lock.__setitem__("compiler_lock_sha256_hex", "0" * 64),
        lambda lock: lock.__setitem__("schema", "v0"),
    ],
)
def test_artifact_lock_drift_fails_closed(tmp_path: Path, mutate) -> None:
    _, _, manifest = compile_fake(tmp_path)
    lock = json.loads(json.dumps(corridor.artifact_lock_from_manifest(manifest)))
    mutate(lock)
    with pytest.raises(corridor.CorridorError):
        corridor.validate_artifact_lock(manifest, lock)


def test_compiler_warnings_wrong_immutables_links_and_contract_sets_fail(tmp_path: Path) -> None:
    warning = fake_output()
    warning["errors"] = [{"severity": "warning", "formattedMessage": "Warning: unused"}]
    with pytest.raises(corridor.CorridorError, match="warning"):
        compile_fake(tmp_path / "w", warning)
    for name in corridor.EXPECTED_IMMUTABLES:
        missing = fake_output()
        contract_output(missing)["deployedBytecode"]["immutableReferences"].pop(IMMUTABLE_IDS[name])
        with pytest.raises(corridor.CorridorError, match="immutables"):
            compile_fake(tmp_path / f"m-{name}", missing)
    # A tenth immutable (for example a bound that §5.2.1 keeps a constant) is refused as well.
    extra_immutable = fake_output()
    extra_immutable["sources"][corridor.SCCP_SOURCE]["ast"]["nodes"][0]["nodes"].append(
        {"nodeType": "VariableDeclaration", "mutability": "immutable", "id": 200, "name": "MAX_VALIDITY_MS"}
    )
    runtime = contract_output(extra_immutable)["deployedBytecode"]
    runtime["immutableReferences"]["200"] = [{"start": len(runtime["object"]) // 2, "length": 32}]
    runtime["object"] += "00" * 32
    with pytest.raises(corridor.CorridorError, match="immutables"):
        compile_fake(tmp_path / "x", extra_immutable)
    linked = fake_output()
    contract_output(linked)["bytecode"]["object"] = "60__$lib$__"
    with pytest.raises(corridor.CorridorError):
        compile_fake(tmp_path / "l", linked)
    referenced = fake_output()
    contract_output(referenced)["bytecode"]["linkReferences"] = {
        corridor.SCCP_LIBRARY_SOURCE: {"BLS12_381": [{"start": 1, "length": 20}]}
    }
    with pytest.raises(corridor.CorridorError, match="unresolved creation link references"):
        compile_fake(tmp_path / "r", referenced)
    undeclared = fake_output()
    undeclared["contracts"]["contracts/evm/sccp/Other.sol"] = {}
    with pytest.raises(corridor.CorridorError, match="undeclared source path"):
        compile_fake(tmp_path / "u", undeclared)
    no_library = fake_output()
    no_library["contracts"].pop(corridor.SCCP_LIBRARY_SOURCE)
    with pytest.raises(corridor.CorridorError, match="must emit exactly"):
        compile_fake(tmp_path / "n", no_library)
    no_contract = fake_output()
    no_contract["contracts"].pop(corridor.SCCP_SOURCE)
    with pytest.raises(corridor.CorridorError, match="must emit exactly"):
        compile_fake(tmp_path / "c", no_contract)
    second = fake_output()
    second["contracts"][corridor.SCCP_SOURCE]["Helper"] = copy.deepcopy(
        second["contracts"][corridor.SCCP_LIBRARY_SOURCE]["BLS12_381"]
    )
    with pytest.raises(corridor.CorridorError, match="must emit exactly"):
        compile_fake(tmp_path / "s", second)


@pytest.mark.parametrize(("field", "limit"), (("creation_bytecode_bytes", 2), ("runtime_bytecode_bytes", 256)))
def test_bytecode_size_ceilings_fail_closed(tmp_path: Path, field: str, limit: int) -> None:
    repo = fake_repo(tmp_path / "repo")
    limits = {"evm": {"creation_bytecode_bytes": 49152, "runtime_bytecode_bytes": 24576}}
    limits["evm"][field] = limit
    config = fake_config(size_limits=limits)
    with pytest.raises(corridor.CorridorError, match="exceeds its ceiling"):
        corridor.compile_corridor(repo, config, fake_fetcher, fake_runner(fake_output()), cache_dir=None)


def test_compiler_diagnostics_and_metadata_are_strict() -> None:
    corridor._reject_compiler_diagnostics({"errors": [{"severity": "info", "message": "note"}]}, "evm")
    corridor._reject_compiler_diagnostics({"errors": None}, "evm")
    corridor._reject_compiler_diagnostics({}, "evm")
    for output, message in (
        ({"errors": [{"severity": "error", "formattedMessage": "Error: x\x1b[31m"}]}, "Error: x\\?\\[31m"),
        ({"errors": [{"severity": "fatal"}]}, "unknown diagnostic severity"),
        ({"errors": {"severity": "warning"}}, "must be an array"),
    ):
        with pytest.raises(corridor.CorridorError, match=message):
            corridor._reject_compiler_diagnostics(output, "evm")
    good = json.dumps({"compiler": {"version": "0.8.31+commit.x"}, "settings": {"evmVersion": "cancun"}})
    metadata, encoded = corridor._metadata_record(good, "x", "0.8.31+commit.x")
    assert encoded == corridor.canonical_json_bytes(metadata)
    for value, message in (
        (good, "compiler identity mismatch"),
        (json.dumps({"compiler": {"version": "0.8.31+commit.y"}, "settings": {"evmVersion": "prague"}}), "EVM version"),
        (json.dumps({"compiler": {"version": "0.8.31+commit.y"}, "settings": {"evmVersion": "cancun", "viaIR": True}}), "pipeline"),
        ({"compiler": {}}, "JSON text"),
    ):
        with pytest.raises(corridor.CorridorError, match=message):
            corridor._metadata_record(value, "x", "0.8.31+commit.y")


def test_manifest_integrity_and_source_binding(tmp_path: Path) -> None:
    repo, config, manifest = compile_fake(tmp_path)
    corridor.validate_manifest_source_inputs(manifest, config, repo)
    tampered = copy.deepcopy(manifest)
    tampered["targets"]["evm"]["contracts"][0]["runtime_bytecode"]["hex"] += "00"
    with pytest.raises(corridor.CorridorError):
        corridor.validate_manifest_integrity(tampered, config)
    tampered = copy.deepcopy(manifest)
    tampered["targets"]["evm"]["contracts"][1]["metadata"]["x"] = 1
    with pytest.raises(corridor.CorridorError, match="metadata"):
        corridor.validate_manifest_integrity(tampered, config)
    for mutate, message in (
        (lambda value: value["targets"]["evm"]["contracts"][0]["runtime_bytecode"].__setitem__("sha256_hex", "00" * 32), "SHA-256"),
        (lambda value: value["targets"]["evm"]["contracts"][0]["creation_bytecode"].__setitem__("keccak256_hex", "00" * 32), "Keccak-256"),
        (lambda value: value["targets"]["evm"]["contracts"][0].__setitem__("unreviewed", True), "missing or unknown"),
        (
            lambda value: value["targets"]["evm"]["contracts"][0].__setitem__(
                "runtime_immutable_references", [{"name": "X", "ast_id": "1", "start": 280, "length": 32}]
            ),
            "outside runtime bytecode",
        ),
        (
            lambda value: value["targets"]["evm"]["contracts"][0]["runtime_immutable_references"].pop(),
            "§5.2.3 immutables",
        ),
        (
            lambda value: value["targets"]["evm"]["contracts"][0]["runtime_immutable_references"][0].__setitem__(
                "name", "OWNER"
            ),
            "§5.2.3 immutables",
        ),
        (lambda value: value["targets"]["evm"]["contracts"][0]["runtime_immutable_references"].reverse(), "not canonical"),
        (lambda value: value["targets"]["evm"].__setitem__("target", "other"), "role mismatch"),
        (lambda value: value["targets"]["evm"]["compiler"].__setitem__("identity", "x"), "compiler identity"),
        (lambda value: value["targets"]["evm"].__setitem__("settings_sha256_hex", "00" * 32), "settings digest"),
        (lambda value: value.__setitem__("compiler_lock_sha256_hex", "00" * 32), "compiler lock digest"),
        (lambda value: value["targets"]["evm"]["contracts"].pop(1), "must hold exactly"),
        (lambda value: value["targets"]["evm"]["contracts"].pop(0), "must hold exactly"),
        (lambda value: value["targets"]["evm"]["contracts"].append(copy.deepcopy(value["targets"]["evm"]["contracts"][0])), "duplicated"),
        (lambda value: value["targets"].__setitem__("other", copy.deepcopy(value["targets"]["evm"])), "exactly the EVM target"),
        (lambda value: value["targets"]["evm"]["contracts"][0].__setitem__("contract_name", "Other"), "identity is inconsistent"),
    ):
        tampered = copy.deepcopy(manifest)
        mutate(tampered)
        with pytest.raises(corridor.CorridorError, match=message):
            corridor.validate_manifest_integrity(tampered, config)
    tampered = copy.deepcopy(manifest)
    tampered["targets"]["evm"]["sources"][1]["sha256_hex"] = "00" * 32
    with pytest.raises(corridor.CorridorError, match="source inventory drift"):
        corridor.validate_manifest_source_inputs(tampered, config, repo)
    source = repo / corridor.SCCP_SOURCE
    source.write_text(source.read_text() + "// stale\n")
    with pytest.raises(corridor.CorridorError, match="stale"):
        corridor.validate_manifest_source_inputs(manifest, config, repo)
    # The library is bound as tightly as the contract.
    library_repo, library_config, library_manifest = compile_fake(tmp_path / "library")
    library = library_repo / corridor.SCCP_LIBRARY_SOURCE
    library.write_text(library.read_text() + "// stale\n")
    with pytest.raises(corridor.CorridorError, match="stale"):
        corridor.validate_manifest_source_inputs(library_manifest, library_config, library_repo)


# ---------------------------------------------------------------------------
# Publication and command line
# ---------------------------------------------------------------------------


def test_publication_is_atomic_and_refuses_collisions(tmp_path: Path) -> None:
    _, _, manifest = compile_fake(tmp_path / "c")
    output = tmp_path / "out"
    path = corridor.publish_manifest(output, manifest)
    assert corridor.load_manifest(path) == manifest
    corridor.publish_manifest(output, manifest)
    (output / "other").write_text("x")
    with pytest.raises(corridor.CorridorError):
        corridor.publish_manifest(output, manifest)
    with pytest.raises(corridor.CorridorError):
        corridor.write_canonical_file(path, manifest)
    lock_path = tmp_path / "lock.json"
    corridor.replace_file_atomically(lock_path, b"{}\n")
    corridor.replace_file_atomically(lock_path, b"{\"a\": 1}\n")
    assert lock_path.read_bytes() == b"{\"a\": 1}\n"
    link = tmp_path / "link.json"
    link.symlink_to(lock_path)
    with pytest.raises(corridor.CorridorError):
        corridor.replace_file_atomically(link, b"{}")
    rendered = corridor.render_artifact_lock({"b": 1, "a": 2})
    assert rendered.decode().startswith('{\n  "a": 2')


def test_builds_in_separate_roots_are_byte_identical_and_complete(tmp_path: Path) -> None:
    _, config, first = compile_fake(tmp_path / "first-checkout")
    _, _, second = compile_fake(tmp_path / "different" / "second-checkout")
    assert corridor.canonical_json_bytes(first) == corridor.canonical_json_bytes(second)
    lock = corridor.artifact_lock_from_manifest(first)
    corridor.validate_manifest_integrity(second, config)
    corridor.validate_artifact_lock(second, lock)
    first_path = corridor.publish_manifest(tmp_path / "first-output", first)
    second_path = corridor.publish_manifest(tmp_path / "second-output", second)
    assert first_path.read_bytes() == second_path.read_bytes()
    assert str(tmp_path) not in first_path.read_text(), "manifests are checkout-root independent"
    for target in corridor.TARGETS:
        target_manifest = first["targets"][target]
        assert target_manifest["compiler"]["artifacts"]
        assert len(target_manifest["standard_json_input_sha256_hex"]) == 64
        artifact = target_manifest["contracts"][0]
        assert artifact["abi"] and artifact["metadata"]
        for bytecode_name in ("creation_bytecode", "runtime_bytecode"):
            bytecode = artifact[bytecode_name]
            assert bytecode["hex"].startswith("0x")
            assert len(bytecode["sha256_hex"]) == 64 and len(bytecode["keccak256_hex"]) == 64


# ---------------------------------------------------------------------------
# Stable manifest reads
# ---------------------------------------------------------------------------


def published_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b'{"generation":"original"}\n')
    return manifest


def test_manifest_read_rejects_a_non_object_document(tmp_path: Path) -> None:
    manifest = published_manifest(tmp_path)
    manifest.write_bytes(b"[]\n")
    with pytest.raises(corridor.CorridorError, match="JSON object"):
        corridor.load_manifest(manifest)


def test_manifest_read_rejects_source_path_replacement_during_read(tmp_path: Path, monkeypatch) -> None:
    manifest = published_manifest(tmp_path)
    replacement = b'{"generation":"replaced"}\n'
    replacement_path = tmp_path / "replacement.json"
    replacement_path.write_bytes(replacement)
    real_read = corridor.os.read
    replaced = False

    def replacing_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        payload = real_read(descriptor, count)
        if payload and not replaced:
            replaced = True
            os.replace(replacement_path, manifest)
        return payload

    monkeypatch.setattr(corridor.os, "read", replacing_read)
    with pytest.raises(corridor.CorridorError, match="changed while it was being read"):
        corridor.load_manifest(manifest)
    assert replaced and manifest.read_bytes() == replacement


def test_manifest_read_rejects_in_place_mutation_during_read(tmp_path: Path, monkeypatch) -> None:
    manifest = published_manifest(tmp_path)
    real_read = corridor.os.read
    mutated = False

    def mutating_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        payload = real_read(descriptor, count)
        if payload and not mutated:
            mutated = True
            manifest.write_bytes(b'{"generation":"tampered"}\n')
        return payload

    monkeypatch.setattr(corridor.os, "read", mutating_read)
    with pytest.raises(corridor.CorridorError, match="changed while it was being read"):
        corridor.load_manifest(manifest)
    assert mutated


def test_cli_reports_failures_without_traceback(tmp_path: Path, capsys) -> None:
    assert corridor.main(["verify", "--manifest", str(tmp_path / "missing.json")]) == 1
    assert "SCCP contract artifact corridor failed" in capsys.readouterr().err


def test_committed_artifact_lock_covers_the_single_v1_contract() -> None:
    lock = corridor.load_artifact_lock()
    assert lock["schema"] == corridor.ARTIFACT_LOCK_SCHEMA
    assert lock["compiler_lock_sha256_hex"] == corridor.load_corridor_config().canonical_sha256
    assert list(lock["targets"]) == ["evm"]
    contracts = lock["targets"]["evm"]["contracts"]
    assert list(contracts) == [corridor.SCCP_CONTRACT]
    entry = contracts[corridor.SCCP_CONTRACT]
    assert sorted({ref["name"] for ref in entry["immutable_references"]}) == list(corridor.EXPECTED_IMMUTABLES)
    template = bytes.fromhex(entry["runtime_template_hex"][2:])
    assert len(template) == entry["runtime_bytecode_bytes"] <= 24576
    assert corridor.keccak256_hex(template) == entry["runtime_template_keccak256_hex"]
    creation = bytes.fromhex(entry["creation_bytecode_hex"][2:])
    assert len(creation) == entry["creation_bytecode_bytes"] <= 49152
    assert corridor.keccak256_hex(creation) == entry["creation_bytecode_keccak256_hex"]


def _cached_real_compilers() -> bool:
    try:
        config = corridor.load_corridor_config()
        platform_name = corridor.native_compiler_platform()
    except corridor.CorridorError:
        return False
    return all(
        (corridor.DEFAULT_COMPILER_CACHE / config.compilers[target].artifacts[platform_name].sha256).is_file()
        for target in corridor.TARGETS
    )


@pytest.mark.skipif(not _cached_real_compilers(), reason="pinned compilers are not cached; run the corridor build first")
def test_real_compilers_reproduce_the_committed_artifact_lock(tmp_path: Path) -> None:
    def offline(url: str) -> bytes:
        raise AssertionError(f"cached compilers must not be downloaded again: {url}")

    manifest, config = corridor.build_and_validate(
        ROOT, corridor.DEFAULT_COMPILER_LOCK, corridor.DEFAULT_ARTIFACT_LOCK, fetcher=offline
    )
    corridor.validate_manifest_source_inputs(manifest, config, ROOT)
    assert os.path.basename(corridor.SCCP_SOURCE) == "SccpTairaXor.sol"


@pytest.mark.skipif(not _cached_real_compilers(), reason="pinned compilers are not cached; run the corridor build first")
def test_real_cli_lock_build_verify_and_materialize_round_trip(tmp_path: Path, capsys) -> None:
    lock_path, lock_manifest = tmp_path / "artifact-lock.json", tmp_path / "lock-manifest.json"
    assert corridor.main(["lock", "--output", str(lock_path), "--manifest-output", str(lock_manifest)]) == 0
    assert lock_path.read_bytes() == corridor.DEFAULT_ARTIFACT_LOCK.read_bytes(), "the lock is reproducible"
    output_dir = tmp_path / "artifacts"
    assert corridor.main(["build", "--output-dir", str(output_dir)]) == 0
    published = output_dir / corridor.MANIFEST_NAME
    assert published.read_bytes() == lock_manifest.read_bytes()
    assert corridor.main(["verify", "--manifest", str(published)]) == 0
    stale = tmp_path / "stale-checkout"
    (stale / corridor.SCCP_LIBRARY_SOURCE).parent.mkdir(parents=True)
    (stale / corridor.SCCP_LIBRARY_SOURCE).write_bytes((ROOT / corridor.SCCP_LIBRARY_SOURCE).read_bytes())
    (stale / corridor.SCCP_SOURCE).write_bytes((ROOT / corridor.SCCP_SOURCE).read_bytes() + b"// stale\n")
    assert corridor.main(["verify", "--manifest", str(published), "--repo-root", str(stale)]) == 1
    assert "stale" in capsys.readouterr().err
    compiler = tmp_path / "solc-evm"
    assert corridor.main(["materialize", "--target", "evm", "--output", str(compiler)]) == 0
    platform_name = corridor.native_compiler_platform()
    assert capsys.readouterr().out.strip() == corridor.EXPECTED_COMPILERS["evm"]["artifacts"][platform_name]["sha256"]
    assert stat.S_IMODE(compiler.stat().st_mode) == 0o500


# ---------------------------------------------------------------------------
# Locked EVM runtime and the EVM smoke script
# ---------------------------------------------------------------------------


def assert_registry_locked(package_lock: Mapping[str, object]) -> None:
    packages = package_lock["packages"]
    for name, value in packages.items():
        if name and "resolved" in value and not value.get("link"):
            assert value["resolved"].startswith("https://registry.npmjs.org/"), name
            assert value.get("integrity", "").startswith("sha512-"), name


def test_evm_runtime_is_locked_audited_native_edr_that_mines_reverts() -> None:
    tooling = ROOT / "scripts" / "contract_tooling" / "evm-runtime"
    package = json.loads((tooling / "package.json").read_text(encoding="utf-8"))
    package_lock = json.loads((tooling / "package-lock.json").read_text(encoding="utf-8"))
    assert package["dependencies"] == {"@noble/curves": "1.2.0", "ethers": "6.16.0", "@nomicfoundation/edr": "0.12.1"}
    assert package["overrides"] == {"ws": "8.21.0"}
    assert_registry_locked(package_lock)
    assert package_lock["packages"][""]["dependencies"] == package["dependencies"]
    for name, version in package["dependencies"].items():
        assert package_lock["packages"][f"node_modules/{name}"]["version"] == version, name
    assert not {"node_modules/hardhat", "node_modules/adm-zip", "node_modules/solc"} & set(package_lock["packages"])
    provider = (tooling / "edr-provider.js").read_text(encoding="utf-8")
    for required in (
        'rawRequest("eth_chainId", [])',
        "reported the wrong chain id",
        'path.basename(packageRoot), "edr"',
        'path.basename(path.dirname(path.dirname(packageRoot))), "node_modules"',
        'metadata.version, "0.12.1"',
        "context.createProvider(edr.L1_CHAIN_TYPE",
        "bailOnTransactionFailure: true",
        "allowUnlimitedContractSize: false",
        "this.closed = true",
        "this.provider = null",
        'new Map([["prague", edr.SpecId.Prague], ["osaka", edr.SpecId.Osaka]])',
        "HARDFORKS.has(hardfork)",
        "...edr.l1GenesisState(specId)",
        "hardfork: edr.l1HardforkToString(specId)",
        "allowBlocksWithSameTimestamp: this.allowBlocksWithSameTimestamp",
    ):
        assert required in provider, required
    assert "edr.SpecId.Osaka)" not in provider, "no hardfork is fixed outside the option table"


def test_evm_smoke_script_uses_the_authenticated_corridor_and_audited_runtime() -> None:
    smoke = (ROOT / "scripts" / "sccp_evm_contract_smoke.sh").read_text(encoding="utf-8")
    for required in (
        '"$NPM_BIN" ci --ignore-scripts --no-audit --no-fund',
        '"$NPM_BIN" audit --omit=dev --audit-level=low',
        "scripts/contract_artifact_corridor.py build",
        "scripts/contract_artifact_corridor.py verify",
        "scripts/contract_artifact_corridor.py materialize",
        "digest mismatch before execution",
        "SCCP_CONTRACT_ARTIFACT_MANIFEST",
        'require_exact_sources contracts/evm/sccp "$CONTRACT_SOURCE"',
        'require_exact_sources contracts/evm/sccp/lib "$LIBRARY_SOURCE"',
        'for stale_source in "$CONTRACT_SOURCE" "$LIBRARY_SOURCE"; do',
        'mutated["targets"]["evm"]["contracts"]',
        "scripts/tests/contract_edr_provider_test.cjs",
        "contracts/evm/sccp/test/sccp_bls.test.js",
        "contracts/evm/sccp/test/sccp_v1_fixtures.test.js",
        "contracts/evm/sccp/test/sccp_taira_xor.test.js",
        "contracts/evm/sccp/test/sccp_gas.test.js",
        "contracts/evm/sccp/test/gas_baseline_v1.json",
        '{"prague", "osaka"}',
        '{"ethereum", "bsc"}',
    ):
        assert required in smoke, required
    # The suites must run against the committed lock and gate against the committed baseline.
    assert "unset SCCP_CONTRACT_ARTIFACT_LOCK SCCP_GAS_BASELINE SCCP_ERROR_COVERAGE_REPORT" in smoke
    for source, expected in (
        (smoke.split('CONTRACT_SOURCE="', 1)[1].split('"', 1)[0], corridor.SCCP_CONTRACT),
        (smoke.split('LIBRARY_SOURCE="', 1)[1].split('"', 1)[0], corridor.SCCP_LIBRARY),
    ):
        assert source == expected.split(":", 1)[0]
    completed = subprocess.run(["bash", "-n", str(ROOT / "scripts" / "sccp_evm_contract_smoke.sh")], check=False)
    assert completed.returncode == 0
