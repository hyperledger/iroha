#!/usr/bin/env python3
"""Pinned Acton 1.2.0 build, test and vector tooling for the SCCP v1 TON contracts.

Purpose
    Builds, formats, checks and tests `contracts/ton/sccp` (SccpTairaXorMinter,
    SccpTairaXorWallet, SccpConsumedBucket; specs/sccp.md §5.3, §5.5) with the
    native Acton 1.2.0 release that bundles Tolk 1.4.2. No Docker, Rosetta or
    container runtime is involved.

Toolchain
    The Acton release archive for the host (macOS arm64/x86-64, Linux
    arm64/x86-64) is downloaded from the official GitHub release once, verified
    against the SHA-256 pinned below, and unpacked into the ignored
    `contracts/ton/sccp/.toolchain/` cache. `--acton PATH` uses an existing
    executable instead; it must report the exact pinned version. `--offline`
    forbids downloads. No environment variable changes behaviour.

Commands
    toolchain   resolve (download and verify) Acton and print its path
    vectors     regenerate the three `tests/unit/sccp-*-vectors.gen.tolk`
                files from the committed
                JSON fixtures under `fixtures/sccp/` (`--check` only compares)
    fmt         check Tolk formatting of the SCCP sources (`--write` rewrites)
    build       compile the three contracts and print code hashes and depths
    wrappers    check that `wrappers/*.gen.tolk` match `acton wrapper --all`
                (`--write` regenerates them in place)
    test        run the Acton emulator suite `tests/unit`, write the gas the
                suites measured to the ignored `gas-current.json` and fail
                when the baseline is missing or a step exceeds 1.1 x its
                row of `gas-baseline.json` (specs/sccp.md §5.4); extra
                arguments go to `acton test`
    all         vectors --check, fmt, build, wrappers, test and the StateInit
                golden check (`generate_ton_sccp_stateinit_golden.py --check`)

Test vectors
    The three generated Tolk files are renderings of committed fixtures
    (`finality_v1.json`, `committee_transitions_v1.json`, `control_v1.json`,
    `bls_consensus_v1.json`, `bls_consensus_rust_v1.json`, `payload_v1.json`,
    `native_transfer_event_v1.json`, `commitment_tree_v1.json`,
    `history_v1.json`, `ton_stateinit_v1.json`, `finality_rust_v1.json`,
    `ton_boc_v1.json`, `fast_pause_v1.json`, `forgery_evidence_v1.json`).
    The builder derives no vector of its own: the
    fixtures are the truth shared with the Python, Rust and Solidity
    implementations, and a fixture change makes `vectors --check` fail until
    the files are regenerated. The test launcher independently checks the
    source evidence ids before Tolk replays their exact certificate bytes;
    source-only accountability rules are not destination authority.

Gas
    A suite reports a measured step with one output line
    `gas <label>: <used> (limit <limit>)`. `gas-current.json` and
    `gas-baseline.json` share one layout (schema `iroha.sccp.ton-gas.v1`), so
    a reviewed `gas-current.json` is recorded as the baseline by copying it.

The module also provides dependency-free Keccak-256, TON cell and BoC
primitives and the §3.7 committee and §5.3.1 minter data layouts shared with
`generate_ton_sccp_stateinit_golden.py`. Requires Python 3.9+ and nothing
outside the standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "contracts" / "ton" / "sccp"
TOOLCHAIN_DIR = PROJECT / ".toolchain"
UNIT_TESTS = PROJECT / "tests" / "unit"
FIXTURES = ROOT / "fixtures" / "sccp"
VECTORS_FILE = UNIT_TESTS / "sccp-test-vectors.gen.tolk"
CERT_VECTORS_FILE = UNIT_TESTS / "sccp-cert-vectors.gen.tolk"
BOC_VECTORS_FILE = UNIT_TESTS / "sccp-boc-vectors.gen.tolk"
GAS_BASELINE_FILE = PROJECT / "gas-baseline.json"
GAS_CURRENT_FILE = PROJECT / "gas-current.json"
GAS_SCHEMA = "iroha.sccp.ton-gas.v1"
# A measured step may use at most 1.1 x its baseline (specs/sccp.md §5.4).
GAS_TOLERANCE_NUMERATOR = 11
GAS_TOLERANCE_DENOMINATOR = 10

ACTON_VERSION = "1.2.0"
ACTON_REPORTED_VERSION = "acton 1.2.0 (16d49e1 2026-09-16)"
TOLK_VERSION = "1.4.2"
ACTON_RELEASE_URL = "https://github.com/ton-blockchain/acton/releases/download/v1.2.0/"
# (system, machine) -> (archive name, archive SHA-256) from the release `sha256.sum`.
ACTON_ARCHIVES: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("Darwin", "arm64"): (
        "acton-aarch64-apple-darwin.tar.gz",
        "cf87b7978d5e38687a3c1570aa2a737918b34777725600e361db39230c8a303f",
    ),
    ("Darwin", "x86_64"): (
        "acton-x86_64-apple-darwin.tar.gz",
        "8260cac4c8d4de7c43d4726d3849bb85235acf7c0c753c4f71b551f8da4764ec",
    ),
    ("Linux", "aarch64"): (
        "acton-aarch64-unknown-linux-gnu.tar.gz",
        "ae44c81b54996f74cbc80cb88c765f0e22341b9e83294c82f603309fad1983de",
    ),
    ("Linux", "arm64"): (
        "acton-aarch64-unknown-linux-gnu.tar.gz",
        "ae44c81b54996f74cbc80cb88c765f0e22341b9e83294c82f603309fad1983de",
    ),
    ("Linux", "x86_64"): (
        "acton-x86_64-unknown-linux-gnu.tar.gz",
        "c12c5ca622e1e41a26d7f7ebea024e4b8a716c65ee92ce7f9e220e7af0e08cd2",
    ),
}
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024

CONTRACTS = ("SccpTairaXorMinter", "SccpTairaXorWallet", "SccpConsumedBucket")
SOURCE_FILES = (
    "contracts/SccpTairaXorMinter.tolk",
    "contracts/SccpTairaXorWallet.tolk",
    "contracts/SccpConsumedBucket.tolk",
    "contracts/sccp-addresses.tolk",
    "contracts/sccp-cells.tolk",
    "contracts/sccp-constants.tolk",
    "contracts/sccp-crypto.tolk",
    "contracts/sccp-errors.tolk",
    "contracts/sccp-fees.tolk",
    "contracts/sccp-finality.tolk",
    "contracts/sccp-messages.tolk",
    "contracts/sccp-recovery.tolk",
    "contracts/sccp-recovery-wire.tolk",
    "contracts/sccp-storage.tolk",
    "contracts/sccp-verify.tolk",
    "scripts/stateinit-golden.tolk",
)
WRAPPER_FILES = tuple(f"wrappers/{name}.gen.tolk" for name in CONTRACTS)


class TonBuilderError(RuntimeError):
    """A bounded, user-facing failure."""


# ---------------------------------------------------------------------------
# Toolchain.


def host_archive() -> Tuple[str, str]:
    """Returns the pinned (archive name, SHA-256) for this host."""

    key = (platform.system(), platform.machine())
    if key not in ACTON_ARCHIVES:
        raise TonBuilderError(f"no pinned Acton {ACTON_VERSION} build for host {key[0]}/{key[1]}")
    return ACTON_ARCHIVES[key]


def sha256_file(path: Path) -> str:
    """Lower-hex SHA-256 of a file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_acton(archive: bytes, destination: Path) -> None:
    """Extracts exactly the `acton` executable from a verified release archive."""

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        names = sorted(m.name for m in members)
        if names not in (["./acton"], ["acton"]):
            raise TonBuilderError(f"unexpected Acton archive layout: {names}")
        source = tar.extractfile(members[0])
        if source is None:
            raise TonBuilderError("Acton archive member is unreadable")
        data = source.read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".partial")
    temporary.write_bytes(data)
    temporary.chmod(0o755)
    os.replace(temporary, destination)


def acton_version(executable: Path) -> str:
    """The first line of `acton --version`."""

    completed = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, timeout=60, check=False
    )
    if completed.returncode != 0:
        raise TonBuilderError(f"{executable} --version failed")
    return completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""


def resolve_acton(explicit: Optional[str] = None, offline: bool = False) -> Path:
    """Returns a verified Acton executable, downloading the pinned archive if needed."""

    if explicit:
        path = Path(explicit)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise TonBuilderError("--acton must name an absolute executable file")
        version = acton_version(path)
        if version != ACTON_REPORTED_VERSION:
            raise TonBuilderError(f"--acton reports {version!r}, expected {ACTON_REPORTED_VERSION!r}")
        return path

    archive_name, archive_sha = host_archive()
    install = TOOLCHAIN_DIR / f"acton-{ACTON_VERSION}-{archive_sha[:16]}"
    executable = install / "acton"
    stamp = install / "archive.sha256"
    if executable.is_file() and stamp.is_file() and stamp.read_text().strip() == archive_sha:
        version = acton_version(executable)
        if version == ACTON_REPORTED_VERSION:
            return executable
    if offline:
        raise TonBuilderError(f"Acton {ACTON_VERSION} is not cached and --offline forbids downloading")
    url = ACTON_RELEASE_URL + archive_name
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 - pinned https URL
        archive = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise TonBuilderError("Acton archive exceeds the size bound")
    actual = hashlib.sha256(archive).hexdigest()
    if actual != archive_sha:
        raise TonBuilderError(f"Acton archive SHA-256 mismatch: {actual} != {archive_sha}")
    extract_acton(archive, executable)
    stamp.write_text(archive_sha + "\n")
    version = acton_version(executable)
    if version != ACTON_REPORTED_VERSION:
        raise TonBuilderError(f"downloaded Acton reports {version!r}")
    return executable


def run_acton(acton: Path, arguments: Sequence[str], cwd: Path = PROJECT) -> str:
    """Runs Acton in `cwd`; raises with the tail of its output on failure."""

    completed = subprocess.run(
        [str(acton), "--color", "never", *arguments],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        tail = "\n".join(output.splitlines()[-80:])
        raise TonBuilderError(f"acton {' '.join(arguments)} failed:\n{tail}")
    return output


def check_tolk_stdlib(project: Path = PROJECT) -> None:
    """Checks that the project stdlib Acton installed is Tolk 1.4.2 / Acton 1.2.0."""

    version_file = project / ".acton" / ".version"
    common = project / ".acton" / "tolk-stdlib" / "common.tolk"
    if not version_file.is_file() or version_file.read_text().strip() != ACTON_VERSION:
        raise TonBuilderError(".acton/.version does not name Acton 1.2.0")
    header = [line.strip() for line in common.read_text(encoding="utf-8").splitlines()[:8]]
    if f"tolk {TOLK_VERSION}" not in header:
        raise TonBuilderError(f"Tolk stdlib header does not declare `tolk {TOLK_VERSION}`")


# ---------------------------------------------------------------------------
# Keccak-256 (Ethereum, not SHA3).

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_M64 = (1 << 64) - 1


def _rol(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _M64 if shift else value


def _keccak_f(state: List[List[int]]) -> List[List[int]]:
    for rc in _KECCAK_RC:
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        state = [[state[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _KECCAK_ROT[x][y])
        state = [
            [b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
            for x in range(5)
        ]
        state[0][0] ^= rc
    return state


def keccak256(data: bytes) -> bytes:
    """Ethereum Keccak-256."""

    rate = 136
    message = bytearray(data)
    message.append(0x01)
    while len(message) % rate:
        message.append(0)
    message[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(message), rate):
        block = message[offset:offset + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _keccak_f(state)
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def keccak_int(data: bytes) -> int:
    """Keccak-256 as a big-endian integer."""

    return int.from_bytes(keccak256(data), "big")


def u(value: int, width: int) -> bytes:
    """Big-endian unsigned integer of `width` bytes."""

    return value.to_bytes(width, "big")


# ---------------------------------------------------------------------------
# TON cells and bags of cells.


class Cell:
    """An ordinary (level-0) TON cell."""

    def __init__(self, bits: str, refs: Sequence["Cell"] = ()) -> None:
        if len(bits) > 1023 or len(refs) > 4 or set(bits) - {"0", "1"}:
            raise TonBuilderError("invalid cell shape")
        self.bits = bits
        self.refs = list(refs)
        self._hash: Optional[bytes] = None
        self._depth: Optional[int] = None

    def data_bytes(self) -> bytes:
        """Augmented data (completion tag when not byte-aligned)."""

        bits = self.bits
        if len(bits) % 8:
            bits += "1" + "0" * (7 - len(bits) % 8)
        return int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""

    def descriptors(self) -> bytes:
        return bytes([len(self.refs), (len(self.bits) + 7) // 8 + len(self.bits) // 8])

    @property
    def depth(self) -> int:
        if self._depth is None:
            self._depth = 0 if not self.refs else 1 + max(ref.depth for ref in self.refs)
        return self._depth

    @property
    def hash(self) -> bytes:
        if self._hash is None:
            material = self.descriptors() + self.data_bytes()
            material += b"".join(u(ref.depth, 2) for ref in self.refs)
            material += b"".join(ref.hash for ref in self.refs)
            self._hash = hashlib.sha256(material).digest()
        return self._hash

    def data_hex(self) -> str:
        """Hex of the data bits, zero-padded on the right to whole bytes."""

        bits = self.bits + "0" * (-len(self.bits) % 8)
        return int(bits, 2).to_bytes(len(bits) // 8, "big").hex() if bits else ""


class Builder:
    """Minimal cell builder mirroring TVM serialization."""

    def __init__(self) -> None:
        self.bits = ""
        self.refs: List[Cell] = []

    def uint(self, value: int, width: int) -> "Builder":
        if value < 0 or value >= 1 << width:
            raise TonBuilderError(f"{value} does not fit uint{width}")
        if width:
            self.bits += format(value, f"0{width}b")
        return self

    def int(self, value: int, width: int) -> "Builder":
        return self.uint(value % (1 << width), width)

    def raw(self, data: bytes) -> "Builder":
        """Appends whole bytes."""

        self.bits += "".join(format(byte, "08b") for byte in data)
        return self

    def bit(self, value: bool) -> "Builder":
        self.bits += "1" if value else "0"
        return self

    def coins(self, value: int) -> "Builder":
        length = (value.bit_length() + 7) // 8
        if length > 15:
            raise TonBuilderError("coins overflow")
        return self.uint(length, 4).uint(value, 8 * length)

    def address(self, workchain: int, account: int) -> "Builder":
        return self.uint(0b100, 3).int(workchain, 8).uint(account, 256)

    def ref(self, cell: Cell) -> "Builder":
        self.refs.append(cell)
        return self

    def maybe_ref(self, cell: Optional[Cell]) -> "Builder":
        self.bit(cell is not None)
        if cell is not None:
            self.refs.append(cell)
        return self

    def end(self) -> Cell:
        return Cell(self.bits, self.refs)


def parse_boc(data: bytes) -> Cell:
    """Parses a single-root bag of ordinary cells (`serialized_boc#b5ee9c72`)."""

    if data[:4] != bytes.fromhex("b5ee9c72"):
        raise TonBuilderError("not a serialized_boc")
    flags = data[4]
    has_index = bool(flags & 0x80)
    has_crc = bool(flags & 0x40)
    size = flags & 0x07
    offset_bytes = data[5]
    position = 6

    def read(width: int) -> int:
        nonlocal position
        value = int.from_bytes(data[position:position + width], "big")
        position += width
        return value

    cell_count = read(size)
    root_count = read(size)
    read(size)  # absent
    total_size = read(offset_bytes)
    roots = [read(size) for _ in range(root_count)]
    if root_count != 1:
        raise TonBuilderError("expected one BoC root")
    if has_index:
        position += cell_count * offset_bytes
    raw: List[Tuple[str, List[int]]] = []
    end = position + total_size
    while position < end:
        d1 = data[position]
        d2 = data[position + 1]
        position += 2
        ref_count = d1 & 7
        if d1 & 8 or d1 >> 5:
            raise TonBuilderError("exotic or leveled cells are not supported")
        byte_len = (d2 + 1) // 2
        payload = data[position:position + byte_len]
        position += byte_len
        bits = "".join(format(byte, "08b") for byte in payload)
        if d2 % 2:
            bits = bits.rstrip("0")[:-1]
        refs = [read(size) for _ in range(ref_count)]
        raw.append((bits, refs))
    if has_crc:
        position += 4
    if len(raw) != cell_count or position != len(data):
        raise TonBuilderError("malformed BoC")
    cells: List[Optional[Cell]] = [None] * cell_count
    for index in range(cell_count - 1, -1, -1):
        bits, refs = raw[index]
        cells[index] = Cell(bits, [cells[ref] for ref in refs])  # type: ignore[misc]
    root = cells[roots[0]]
    assert root is not None
    return root


def serialize_boc(root: Cell) -> bytes:
    """Serializes a cell tree as a single-root bag of cells.

    The form is the one of `iroha_sccp::v1::ton_cell::Cell::to_boc`, so both
    implementations produce the same bytes: no index, no CRC, minimal widths,
    one entry per distinct cell and parents before children, in the reversed
    post-order of a walk that visits the references of a cell last to first.
    Every cell of the tree must be known in full.
    """

    order: List[Cell] = []
    seen = set()
    # (cell, references already pushed): an explicit stack, so that the depth
    # of a tree is not bounded by the interpreter's recursion limit
    stack: List[Tuple[Cell, bool]] = [(root, False)]
    while stack:
        cell, expanded = stack.pop()
        if expanded:
            order.append(cell)
            continue
        if not isinstance(cell, Cell):
            raise TonBuilderError("a cell known only by hash and depth cannot be serialized")
        if cell.hash in seen:
            continue
        seen.add(cell.hash)
        stack.append((cell, True))
        # the stack pops last-pushed first, so pushing the references in
        # order visits them last to first
        stack.extend((ref, False) for ref in cell.refs)
    order.reverse()
    index = {cell.hash: position for position, cell in enumerate(order)}

    def width(value: int) -> int:
        return max(1, (value.bit_length() + 7) // 8)

    size_bytes = width(len(order))
    body = b""
    for cell in order:
        body += cell.descriptors() + cell.data_bytes()
        body += b"".join(u(index[ref.hash], size_bytes) for ref in cell.refs)
    offset_bytes = width(len(body))
    header = bytes.fromhex("b5ee9c72") + bytes([size_bytes, offset_bytes])
    header += u(len(order), size_bytes) + u(1, size_bytes) + u(0, size_bytes)
    header += u(len(body), offset_bytes) + u(0, size_bytes)
    return header + body


def cell_tree_size(root: Cell) -> Tuple[int, int]:
    """(unique cells, total data bits) of a cell tree."""

    seen: Dict[bytes, Cell] = {}
    stack = [root]
    while stack:
        cell = stack.pop()
        if cell.hash in seen:
            continue
        seen[cell.hash] = cell
        stack.extend(cell.refs)
    return len(seen), sum(len(cell.bits) for cell in seen.values())


def load_compiled_code(name: str, project: Path = PROJECT) -> Cell:
    """Code cell of a built contract; checks the hash Acton recorded."""

    record = json.loads((project / "build" / f"{name}.json").read_text(encoding="utf-8"))
    import base64

    code = parse_boc(base64.b64decode(record["code_boc64"]))
    if code.hash.hex() != record["hash"].lower():
        raise TonBuilderError(f"{name}: BoC hash does not match Acton's recorded hash")
    return code


# ---------------------------------------------------------------------------
# SCCP structures (§3.7, §5.3.1).

TAG_COMMITTEE = b"SCCP/COMMITTEE/V1"
KEY_BYTES = 48
KEYS_PER_CHUNK = 2
MIN_COMMITTEE_SIZE = 4
MAX_COMMITTEE_SIZE = 31


def is_committee_size(n: int) -> bool:
    """The committee size rule `n = 3f + 1` with `4 ≤ n ≤ 31` (§0)."""

    return MIN_COMMITTEE_SIZE <= n <= MAX_COMMITTEE_SIZE and (n - 1) % 3 == 0


def committee_quorum(n: int) -> int:
    """`q = n − f` with `f = (n − 1)/3` (§3.8 step 1)."""

    return n - (n - 1) // 3


def committee_root(keys: Sequence[bytes]) -> int:
    """§3.7 committee root `keccak256("SCCP/COMMITTEE/V1" ‖ u8 n ‖ PK_0 ‖ … ‖ PK_{n−1})`.

    Validates the committee size, the key length and the canonical order:
    compressed keys strictly ascending as byte strings.
    """

    n = len(keys)
    if not is_committee_size(n):
        raise TonBuilderError(f"invalid committee size {n}")
    for key in keys:
        if len(key) != KEY_BYTES:
            raise TonBuilderError("a compressed committee key has 48 bytes")
    for previous, key in zip(keys, keys[1:]):
        if not previous < key:
            raise TonBuilderError("committee keys are not strictly ascending")
    return keccak_int(TAG_COMMITTEE + u(n, 1) + b"".join(keys))


def key_chunks(keys: Sequence[bytes]) -> Cell:
    """Canonical `^KeyChunk` list (§5.3.1): two keys per chunk except the last."""

    if not keys or any(len(key) != KEY_BYTES for key in keys):
        raise TonBuilderError("a key list holds at least one 48-byte key")
    tail: Optional[Cell] = None
    for start in reversed(range(0, len(keys), KEYS_PER_CHUNK)):
        builder = Builder()
        for key in keys[start:start + KEYS_PER_CHUNK]:
            builder.raw(key)
        tail = builder.maybe_ref(tail).end()
    assert tail is not None
    return tail


def minter_initial_data(
    network_id: int,
    consensus_instance: int,
    route_revision: int,
    max_supply: int,
    generation: int,
    start_height: int,
    until_ms: int,
    keys: Sequence[bytes],
    wallet_code: Cell,
    bucket_code: Cell,
) -> Dict[str, Cell]:
    """Canonical initial minter data of §5.3.1 for a deployment pinned to a generation.

    Returns the named cells: `root` (`minter_data`), `config`, `initial_pin`,
    `committee`, `checkpoints`, `recovery` and `keys` (the first `KeyChunk`). The pinned
    root is the committee root of `keys`, so the stored committee is bound to
    the pin by construction.
    """

    if generation < 1 or start_height < 1:
        raise TonBuilderError("the pinned generation and start height are at least 1")
    root_word = committee_root(keys)
    pin = (
        Builder().uint(generation, 64).uint(root_word, 256).uint(start_height, 64)
        .uint(until_ms, 64).end()
    )
    config = (
        Builder().uint(network_id, 256).uint(consensus_instance, 256).uint(route_revision, 32)
        .coins(max_supply).ref(pin).ref(wallet_code).ref(bucket_code).end()
    )
    keys_cell = key_chunks(keys)
    # root, until_ms, start, high = start − 1, generation, n, keys
    committee = (
        Builder().uint(root_word, 256).uint(until_ms, 64).uint(start_height, 64)
        .uint(start_height - 1, 64).uint(generation, 64).uint(len(keys), 8).ref(keys_cell).end()
    )
    # count = 0 and no entry
    checkpoints = Builder().uint(0, 2).end()
    recovery = Builder().uint(1, 64).uint(0, 10).uint(0, 64).bit(False).end()
    # initialized, equivocated, total and pending supply, outbound nonce, op
    # count, control nonce, parliament pause, fast pause, deployed buckets,
    # then config, committee, checkpoints and the empty recovery book
    root = (
        Builder().bit(False).bit(False).coins(0).coins(0).uint(0, 64).uint(0, 64).uint(0, 64)
        .bit(False).uint(0, 64).uint(0, 64).ref(config).ref(committee).ref(checkpoints)
        .ref(recovery).end()
    )
    return {
        "root": root,
        "config": config,
        "initial_pin": pin,
        "committee": committee,
        "checkpoints": checkpoints,
        "recovery": recovery,
        "keys": keys_cell,
    }


def empty_recovery_receipts() -> Cell:
    """`RecoveryReceipts`: count:uint10 = 0, empty HashmapE 72."""

    return Builder().uint(0, 10).bit(False).end()


def state_init(code: Cell, data: Cell) -> Cell:
    """`StateInit` with only code and data (bits `00110`)."""

    return Builder().uint(0b00110, 5).ref(code).ref(data).end()


# ---------------------------------------------------------------------------
# Tolk test vectors.

#
# All three generated files render rows of the committed JSON fixtures. Nothing
# below derives a vector: a value that a fixture does not carry is not
# rendered, and the consistency checks only compare fixture rows with each
# other.

# Largest hex literal of one `"…".hexToSlice()`: a slice holds 1023 bits.
MAX_SLICE_LITERAL_BYTES = 127
# Finality header split of §5.3.2: `XHead` holds `X[0..109)`.
X_HEAD_BYTES = 109
# Split of the 165-byte Commit preimage `P` into its two builders (§5.3.4).
COMMIT_PREIMAGE_HEAD_BYTES = 101
# A table lookup of a generated file throws this for an index outside it.
VECTOR_BAD_INDEX_EXIT = 65000

TON_NETWORK = "ton-mainnet"
EVENT_BUILDERS = {
    "SccpCertificate",
    "SccpCheckpointed",
    "SccpCommitteeRotated",
    "SccpLatched",
    "SccpControlApplied",
    "SccpFinalized",
    "SccpVoided",
}


def load_fixture(name: str) -> Any:
    """A committed JSON fixture of `fixtures/sccp/`."""

    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _hex_body(value: Any) -> str:
    """The digits of a `0x`-prefixed lowercase hex byte string of a fixture."""

    if not isinstance(value, str) or not value.startswith("0x") or len(value) % 2:
        raise TonBuilderError(f"not a fixture byte string: {value!r}")
    body = value[2:]
    if body != body.lower() or set(body) - set("0123456789abcdef"):
        raise TonBuilderError(f"not a lowercase hex byte string: {value!r}")
    return body


def _slice(value: Any) -> str:
    """Tolk expression for a fixture byte string of at most 127 bytes."""

    body = _hex_body(value)
    if len(body) > 2 * MAX_SLICE_LITERAL_BYTES:
        raise TonBuilderError("a byte string of more than 127 bytes does not fit one slice")
    return f'"{body}".hexToSlice()' if body else "createEmptySlice()"


def _pieces(value: Any) -> List[str]:
    """Tolk slices of a fixture byte string in 127-byte pieces (a snake's chunks)."""

    body = _hex_body(value)
    step = 2 * MAX_SLICE_LITERAL_BYTES
    return [f'"{body[i:i + step]}".hexToSlice()' for i in range(0, len(body), step)]


def _word(value: Any) -> str:
    """Tolk integer literal for a fixture number: a JSON number, a decimal string or a hex word."""

    if isinstance(value, bool):
        raise TonBuilderError("a boolean is not a number")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.startswith("0x"):
        if len(value) == 2:
            raise TonBuilderError("an empty hex string is not a number")
        return f"0x{int(value, 16):x}"
    if isinstance(value, str) and value.isdigit():
        return str(int(value))
    raise TonBuilderError(f"not a fixture number: {value!r}")


def _bool(value: Any) -> str:
    """Tolk boolean literal for a fixture flag (`true`/`false` or `0`/`1`)."""

    if value in (True, 1):
        return "true"
    if value in (False, 0):
        return "false"
    raise TonBuilderError(f"not a fixture flag: {value!r}")


def _padded(value: Any, width: int) -> str:
    """A fixture hex integer as a byte string of exactly `width` bytes."""

    return "0x" + u(int(value, 16), width).hex()


def _words(label: str) -> List[str]:
    return [word for word in re.split(r"[^0-9A-Za-z]+", label) if word]


def _camel(label: str) -> str:
    """`n4_lowest_q` → `N4LowestQ`: the suffix of a generated function name."""

    return "".join(word[0].upper() + word[1:] for word in _words(label))


def _upper(label: str) -> str:
    """`n4_lowest_q` or `BadHeader` → `N4_LOWEST_Q`, `BAD_HEADER`: a constant name."""

    return "_".join(_words(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", label))).upper()


def _array(kind: str, items: Sequence[str], indent: str = "    ") -> str:
    """A Tolk `array<kind>` literal with one element per line."""

    if not items:
        return f"([] as array<{kind}>)"
    inner = "".join(f"{indent}    {item},\n" for item in items)
    return f"[\n{inner}{indent}]"


def _array_fun(name: str, kind: str, items: Sequence[str], doc: str) -> str:
    return f"/// {doc}\nfun {name}(): array<{kind}> {{\n    return {_array(kind, items)};\n}}\n\n"


def _lookup(name: str, result: str, rows: Sequence[Tuple[str, str]], doc: str) -> str:
    """A Tolk table function: `rows` are (comment, struct or expression) per index."""

    out = [f"/// {doc}\nfun {name}(index: int): {result} {{\n"]
    for index, (comment, value) in enumerate(rows):
        out.append(f"    // {comment}\n    if (index == {index}) {{\n        return {value};\n    }}\n")
    out.append("    throw VecErrors.BadIndex;\n}\n\n")
    return "".join(out)


def _struct(fields: Sequence[Tuple[str, str]], indent: str = "        ") -> str:
    """A Tolk object literal with one field per line."""

    inner = "".join(f"{indent}    {name}: {value},\n" for name, value in fields)
    return f"{{\n{inner}{indent}}}"


def exit_codes(transitions: Any) -> Dict[str, int]:
    """Outcome name → TON exit code of the shared table (`ok` is 0)."""

    table = transitions["error_codes"]
    codes = {name: code for name, code in table["shared"].items() if code is not None}
    for name, code in table["ton_only"].items():
        if name in codes:
            raise TonBuilderError(f"exit code {name} is listed twice")
        codes[name] = code
    codes["ok"] = 0
    return codes


def _exit(codes: Dict[str, int], outcome: Any) -> int:
    if outcome not in codes:
        raise TonBuilderError(f"outcome {outcome!r} has no TON exit code")
    return codes[outcome]


def _split_x(value: Any) -> Tuple[str, str]:
    """`X` as its `XHead` and `XTail` byte strings (§5.3.2)."""

    body = _hex_body(value)
    return "0x" + body[:2 * X_HEAD_BYTES], "0x" + body[2 * X_HEAD_BYTES:]


def _keys_of_root(committees: Any, root: str) -> List[str]:
    """Keys of the fixture committee with the given root."""

    for committee in committees.values():
        if committee["root"] == root:
            return committee["keys"]
    raise TonBuilderError(f"no fixture committee has root {root}")


def _replay_init_seconds(first_now_ms: int, until_ms: int, constants: Any) -> int:
    """A deployment time at or before a row's first step at which `sccp_init` accepts the pin.

    The fixtures describe a destination that already exists at its first
    step. When the pinned `until_ms` is acceptable at that step the minter is
    deployed then; a row that starts on an expired destination deploys one
    second before the expiry.
    """

    bound = constants["max_validity_ms"] + constants["max_init_slack_ms"]
    if first_now_ms % 1000:
        raise TonBuilderError("a destination clock value is a whole second")
    if first_now_ms < until_ms <= first_now_ms + bound:
        return first_now_ms // 1000
    if until_ms > first_now_ms:
        raise TonBuilderError("a row pins an expiry that no deployment time accepts")
    return (until_ms - 1000) // 1000


VECTORS_HEADER = """// Generated by `python3 scripts/ton_sccp_builder.py vectors`; do not edit.
//
// Rows of the committed reference fixtures under `fixtures/sccp/`, rendered
// as Tolk data for the Acton suite. The builder derives none of these values:
// they are the vectors that the Python reference, the Rust reference and the
// Solidity suites share (specs/sccp.md §11). Sources: `finality_v1.json`
// (verification context, constants, test keys, committees, the §11.2 worked
// examples and the header tables), `committee_transitions_v1.json` (exit
// codes, constants and the `sccp_init` bounds), `control_v1.json` (control
// leaves of the TON lane), `bls_consensus_v1.json` and `bls_consensus_rust_v1.json`
// (DST_SIG traces and all applicable verification rows), `payload_v1.json`
// (TON directions and every raw refusal with its TON error),
// `commitment_tree_v1.json` and `history_v1.json` (all roots, leaves, paths
// and confusion negatives), `native_transfer_event_v1.json` (exact TON ext-out
// body), `fast_pause_v1.json` (control leaves, expiry/clamp and stale nonce),
// `forgery_evidence_v1.json` (exact certificate bytes and source evidence-id
// association), and `ton_stateinit_v1.json` (canonical KeyChunk cell hashes).

"""


def _render_context(finality: Any, transitions: Any, control: Any) -> str:
    context = finality["verification_context"]
    constants = finality["constants"]
    limits = transitions["constants"]
    if context["ton"]["network"] != TON_NETWORK:
        raise TonBuilderError("the fixture TON context is not ton-mainnet")
    tag = lambda entry: "0x" + _hex_body(entry["hex"])  # noqa: E731
    lines = [
        "/// Errors of the generated tables.\n",
        "enum VecErrors {\n",
        "    /// A table function was called with an index outside its table.\n",
        f"    BadIndex = {VECTOR_BAD_INDEX_EXIT}\n",
        "}\n\n",
        "/// Taira `NetworkId`, consensus instance `I` and the placeholder minter\n",
        "/// account id that every TON row of the fixtures commits to.\n",
        f"const VEC_NETWORK_ID = {_word(context['taira_network_id'])}\n",
        f"const VEC_CONSENSUS_INSTANCE = {_word(context['consensus_instance'])}\n",
        f"const VEC_MINTER_ACCOUNT_ID = {_word(context['ton']['destination_word'])}\n\n",
        "/// Layout constants and tags of §3.6–§3.9 as the fixtures state them.\n",
        f"const VEC_X_BYTES = {constants['x_len']}\n",
        f"const VEC_X_HEAD_BYTES = {constants['x_head_len']}\n",
        f"const VEC_X_TAIL_BYTES = {constants['x_tail_len']}\n",
        f"const VEC_QC_FIXED_BYTES = {constants['qc_fixed_len']}\n",
        f"const VEC_COMMIT_PREIMAGE_BYTES = {constants['commit_preimage_len']}\n",
        f"const VEC_MAX_HISTORY_SIZE = {_word(constants['max_history_size'])}\n",
        f"const VEC_MAX_VALIDITY_MS = {_word(limits['max_validity_ms'])}\n",
        f"const VEC_MAX_INIT_SLACK_MS = {_word(limits['max_init_slack_ms'])}\n",
        f"const VEC_MAX_FAST_PAUSE_MS = {_word(control['max_fast_pause_ms'])}\n",
        f"const VEC_CHECKPOINT_SLOTS = {_word(limits['ton_checkpoint_slots'])}\n",
        f"const VEC_MAX_VOID_FROZEN_RANGE = {_word(limits['max_void_frozen_range_ton'])}\n",
        f"const VEC_X_MAGIC = {_word(tag(constants['x_magic']))}\n",
        f"const VEC_RESULT_TAG = {_word(tag(constants['result_tag']))}\n",
        f"const VEC_SIG_TAG = {_word(tag(constants['tag_sig']))}\n",
        f"const VEC_COMMITTEE_TAG = {_word('0x' + constants['committee_tag'].encode('ascii').hex())}\n\n",
    ]
    if constants["x_head_len"] != X_HEAD_BYTES or constants["x_len"] != 221:
        raise TonBuilderError("the fixture header layout is not the 109 + 112 byte split")
    if constants["max_validity_ms"] != limits["max_validity_ms"]:
        raise TonBuilderError("the fixtures disagree on MAX_VALIDITY_MS")
    return "".join(lines)


def _render_exit_codes(codes: Dict[str, int]) -> str:
    lines = ["/// Exit codes of §5.2.2 (`error_codes` of `committee_transitions_v1.json`).\n"]
    for name in sorted(name for name in codes if name != "ok"):
        lines.append(f"const VEC_EXIT_{_upper(name)} = {codes[name]}\n")
    return "".join(lines) + "\n"


def _render_test_keys(finality: Any) -> str:
    keys = finality["test_keys"]
    if [key["index"] for key in keys] != list(range(len(keys))):
        raise TonBuilderError("the fixture test keys are not indexed 0..")
    return (
        "/// Test keys of §11.3: `sk_i = KeyGen(SHA-256(\"sccp-finality-test-ikm\" ‖ u8 i))`.\n"
        f"const VEC_KEY_COUNT = {len(keys)}\n\n"
        + _array_fun("vecKeySecrets", "int", [_word(key["sk"]) for key in keys], "Secret scalar of each test key.")
        + _array_fun(
            "vecKeyPublics", "slice", [_slice(key["pk"]) for key in keys],
            "Compressed G1 public key (48 bytes) of each test key.",
        )
    )


def _render_committees(finality: Any, stateinit: Any) -> str:
    publics = [key["pk"] for key in finality["test_keys"]]
    out = []
    for name in sorted(finality["committees"]):
        committee = finality["committees"][name]
        indices = committee["test_key_indices"]
        if [publics[i] for i in indices] != committee["keys"] or len(indices) != committee["n"]:
            raise TonBuilderError(f"committee {name} does not list its test keys")
        out.append(
            _array_fun(
                f"vecCommittee{_camel(name)}", "int", [str(i) for i in indices],
                f"Committee `{name}` (n = {committee['n']}, q = {committee['q']}): the test key of "
                "each member in canonical order.",
            )
        )
        out.append(f"const VEC_COMMITTEE_{_upper(name)}_ROOT = {_word(committee['root'])}\n\n")
    out.append("/// Canonical KeyChunk list hashes from `ton_stateinit_v1.json`.\n")
    for vector in stateinit["vectors"]:
        name = vector["committee"]
        committee = finality["committees"][name]
        if vector["keys"] != [key[2:] for key in committee["keys"]]:
            raise TonBuilderError(f"StateInit vector {name} has other committee keys")
        out.append(
            f"const VEC_KEYS_{_upper(name)}_CELL_HASH = "
            f"{_word('0x' + vector['initial_data']['keys'][0]['hash'])}\n"
        )
    return "".join(out) + "\n"


def _render_worked_examples(finality: Any) -> str:
    worked = finality["worked_examples"]
    out = ["// §11.2 worked examples.\n\n"]
    for name in ("rotation", "heartbeat", "non_rotation", "inactive"):
        case = worked["cases"][name]
        head, tail = _split_x(case["x"])
        out.append(f"/// `X[0..109)` of the §11.2 case `{name}`.\n")
        out.append(f"fun vecX{_camel(name)}Head(): slice {{\n    return {_slice(head)};\n}}\n\n")
        out.append(f"/// `X[109..221)` of the §11.2 case `{name}`.\n")
        out.append(f"fun vecX{_camel(name)}Tail(): slice {{\n    return {_slice(tail)};\n}}\n\n")
        out.append(f"const VEC_X_{_upper(name)}_R = {_word(case['r'])}\n")
        if "checkpoint_id" in case:
            out.append(f"const VEC_X_{_upper(name)}_ID = {_word(case['checkpoint_id'])}\n")
        out.append("\n")
    if len({worked["cases"][name]["d_body"] for name in worked["cases"]}) != 1:
        raise TonBuilderError("the §11.2 cases do not share one D_body")
    commit = worked["commit"]
    preimage = _hex_body(commit["preimage"])
    cut = 2 * COMMIT_PREIMAGE_HEAD_BYTES
    encoded = _hex_body(worked["qc_fixed"]["encoded"])
    synthetic = worked["synthetic_committee_root"]
    out += [
        "/// `D_body`, the `result_body` of the §11.2 cases.\n",
        f"const VEC_X_D_BODY = {_word(worked['cases']['rotation']['d_body'])}\n\n",
        "/// The §11.2 Commit vote over the rotation case: its fields, the 165-byte\n",
        "/// preimage `P` in the two builders of §5.3.4, `R` and `m = SHA-256(P)`.\n",
        f"const VEC_COMMIT_EPOCH = {_word(commit['epoch'])}\n",
        f"const VEC_COMMIT_EPOCH_CONTEXT = {_word(commit['epoch_context'])}\n",
        f"const VEC_COMMIT_VIEW = {_word(commit['view'])}\n",
        f"const VEC_COMMIT_BLOCK_HASH = {_word(commit['block_hash'])}\n",
        f"const VEC_COMMIT_HEIGHT = {_word(commit['height'])}\n",
        f"const VEC_COMMIT_INSTANCE = {_word(commit['instance'])}\n",
        f"const VEC_COMMIT_R = {_word(commit['r'])}\n",
        f"const VEC_COMMIT_M = {_word(commit['m'])}\n\n",
        "/// `P[0..101)`: tag, kind, `I`, epoch, epoch context, height and view.\n",
        f"fun vecCommitPreimageHead(): slice {{\n    return {_slice('0x' + preimage[:cut])};\n}}\n\n",
        "/// `P[101..165)`: block hash and `R`.\n",
        f"fun vecCommitPreimageTail(): slice {{\n    return {_slice('0x' + preimage[cut:])};\n}}\n\n",
        "/// The §11.2 `QC_FIXED` (116 bytes): the 112 bytes of the `QcFixed` cell and\n",
        "/// the trailing `signers` word.\n",
        f"fun vecQcFixedCell(): slice {{\n    return {_slice('0x' + encoded[:-8])};\n}}\n\n",
        f"const VEC_QC_FIXED_SIGNERS = {_word(worked['qc_fixed']['fields']['signers'])}\n\n",
        _array_fun(
            "vecSyntheticCommitteeKeys", "slice", [_slice(key) for key in synthetic["keys"]],
            "The synthetic keys of the §3.7 committee root example.",
        ),
        f"const VEC_SYNTHETIC_COMMITTEE_ROOT = {_word(synthetic['root'])}\n\n",
    ]
    if len(preimage) != 2 * 165 or len(encoded) != 2 * 116:
        raise TonBuilderError("the §11.2 preimage or QC_FIXED has another length")
    if int(encoded[-8:], 16) != worked["qc_fixed"]["fields"]["signers"]:
        raise TonBuilderError("the §11.2 QC_FIXED does not end with its signers word")
    return "".join(out)


HEADER_FIELDS = (
    ("networkId", "network_id"),
    ("height", "height"),
    ("timestampMs", "timestamp_ms"),
    ("flags", "flags"),
    ("messageCount", "message_count"),
    ("sccpRoot", "sccp_root"),
    ("historySize", "history_size"),
    ("historyRoot", "history_root"),
    ("generation", "generation"),
    ("committeeRoot", "committee_root"),
    ("validityMs", "validity_ms"),
    ("nextCommitteeRoot", "next_committee_root"),
)


def _render_headers(finality: Any, codes: Dict[str, int]) -> str:
    headers = finality["headers"]
    out = [
        "/// A well-formed finality header of `headers.valid`: its two cells, its\n"
        "/// fields, its checkpoint id (0 for the inactive form, which has none) and\n"
        "/// the exit code a destination answers for a certificate that carries it\n"
        "/// (0 when it accepts the header).\n"
        "struct VecHeader {\n    head: slice\n    tail: slice\n    id: int\n    exit: int\n"
        + "".join(f"    {name}: int\n" for name, _ in HEADER_FIELDS)
        + "}\n\n",
        f"const VEC_VALID_HEADER_COUNT = {len(headers['valid'])}\n\n",
    ]
    rows = []
    for row in headers["valid"]:
        if _split_x(row["x"]) != (row["x_head"], row["x_tail"]):
            raise TonBuilderError(f"header {row['label']} is not split at byte 109")
        destination = "ok" if row["destination"] == "accept" else row["destination"]
        fields = [
            ("head", _slice(row["x_head"])),
            ("tail", _slice(row["x_tail"])),
            ("id", _word(row.get("checkpoint_id", 0))),
            ("exit", str(_exit(codes, destination))),
        ] + [(name, _word(row["fields"][key])) for name, key in HEADER_FIELDS]
        rows.append((row["label"], _struct(fields)))
    out.append(_lookup("vecValidHeader", "VecHeader", rows, "Row `index` of `headers.valid`."))
    out.append(
        "/// A header of `headers.invalid`: the bytes split at offset 109 (a length\n"
        "/// row gives an `XTail` of another size) and the exit code a destination\n"
        "/// answers for a certificate that carries it.\n"
        "struct VecInvalidHeader {\n    head: slice\n    tail: slice\n    exit: int\n}\n\n"
    )
    out.append(f"const VEC_INVALID_HEADER_COUNT = {len(headers['invalid'])}\n\n")
    rows = []
    for row in headers["invalid"]:
        head, tail = _split_x(row["x"])
        fields = [
            ("head", _slice(head)),
            ("tail", _slice(tail)),
            ("exit", str(_exit(codes, row["destination"]))),
        ]
        rows.append((f"{row['label']}: {row['error']}", _struct(fields)))
    out.append(
        _lookup(
            "vecInvalidHeader", "VecInvalidHeader", rows,
            "Row `index` of `headers.invalid` (label and first violated check in the comment).",
        )
    )
    return "".join(out)


def _render_hash_to_g2(bls: Any) -> str:
    rows = []
    for row in bls["hash_to_g2_dst_sig"]:
        uniform = _hex_body(row["uniform_bytes"])
        if len(uniform) != 2 * 256 or len(_hex_body(row["msg"])) != 64:
            raise TonBuilderError("a hash-to-G2 trace is not over a 32-byte message")
        blocks = [f"0x{uniform[i:i + 64]}" for i in range(0, len(uniform), 64)]
        element = lambda pair: "0x" + _padded(pair[0], 48)[2:] + _padded(pair[1], 48)[2:]  # noqa: E731
        fields = [
            ("m", _slice(row["msg"])),
            ("blocks", _array("int", blocks, "            ")),
            ("u0", _slice(element(row["u0"]))),
            ("u1", _slice(element(row["u1"]))),
            ("q", _slice(row["q"]["compressed"])),
        ]
        rows.append((row["label"], _struct(fields)))
    return (
        "/// A hash-to-G2 trace under `DST_SIG` (`hash_to_g2_dst_sig` of\n"
        "/// `bls_consensus_v1.json`): the 32-byte message, the eight SHA-256 blocks\n"
        "/// of `expand_message_xmd`, the field elements `u_0` and `u_1` as the 96\n"
        "/// bytes `c_0 ‖ c_1`, and the compressed point `hash_to_G2(m)`.\n"
        "struct VecHashToG2 {\n    m: slice\n    blocks: array<int>\n    u0: slice\n    u1: slice\n"
        "    q: slice\n}\n\n"
        f"const VEC_HASH_TO_G2_COUNT = {len(rows)}\n\n"
        + _lookup("vecHashToG2", "VecHashToG2", rows, "Row `index` of the hash-to-G2 traces.")
    )


def _render_control_leaves(control: Any, minter_word: str) -> str:
    rows = []
    for row in control["controls"]:
        if row["target"] != TON_NETWORK:
            continue
        if row["destination_word"] != minter_word:
            raise TonBuilderError("a TON control leaf commits to another destination word")
        if _hex_body(row["ton_b1"]) + _hex_body(row["ton_b2"]) != _hex_body(row["preimage"]):
            raise TonBuilderError("the TON builders of a control leaf are not its preimage")
        fields = [
            ("routeRevision", _word(row["route_revision"])),
            ("controlNonce", _word(row["control_nonce"])),
            ("track", _word(row["track"])),
            ("parliamentPaused", _bool(row["parliament_paused"])),
            ("fastPauseUntilMs", _word(row["fast_pause_until_ms"])),
            ("certificateId", _word(row["certificate_id"])),
            ("effectHash", _word(row["effect_hash"])),
            ("b1", _slice(row["ton_b1"])),
            ("b2", _slice(row["ton_b2"])),
            ("leaf", _word(row["leaf"])),
        ]
        comment = (
            f"nonce {row['control_nonce']}, track {row['track']}, "
            f"paused {row['parliament_paused']}, until {row['fast_pause_until_ms']}"
        )
        rows.append((comment, _struct(fields)))
    if not rows:
        raise TonBuilderError("control_v1.json holds no TON control leaf")
    return (
        "/// A §3.4 control leaf of the TON lane (`controls` of `control_v1.json`\n"
        "/// with target ton-mainnet, destination word `VEC_MINTER_ACCOUNT_ID`): its\n"
        "/// fields, the two `HASHEXT` builders of the 199-byte preimage (125 and 74\n"
        "/// bytes) and the leaf.\n"
        "struct VecControlLeaf {\n    routeRevision: int\n    controlNonce: int\n    track: int\n"
        "    parliamentPaused: bool\n    fastPauseUntilMs: int\n    certificateId: int\n"
        "    effectHash: int\n    b1: slice\n    b2: slice\n    leaf: int\n}\n\n"
        f"const VEC_CONTROL_LEAF_COUNT = {len(rows)}\n\n"
        + _lookup("vecControlLeaf", "VecControlLeaf", rows, "Row `index` of the TON control leaves.")
    )


def _render_payloads(payloads: Any) -> str:
    rows = {row["label"]: row for row in payloads["directions"]}
    inbound = rows[f"sora-taira->{TON_NETWORK}"]
    outbound = rows[f"{TON_NETWORK}->sora-taira"]
    account = lambda value: "0x" + _hex_body(value)[8:]  # noqa: E731
    for value in (inbound["recipient"], outbound["sender"]):
        if len(_hex_body(value)) != 72 or _hex_body(value)[:8] != "00000000":
            raise TonBuilderError("a TON account of payload_v1.json is not a workchain-0 account36")
    return "".join(
        [
            "// The §3.2 payloads of the TON lane (`directions` of `payload_v1.json`).\n\n",
            _array_fun(
                "vecInboundPayloadPieces", "slice", _pieces(inbound["payload"]),
                "The Taira→TON payload in 127-byte pieces.",
            ),
            f"const VEC_INBOUND_NONCE = {_word(inbound['nonce'])}\n",
            f"const VEC_INBOUND_REVISION = {_word(inbound['route_revision'])}\n",
            f"const VEC_INBOUND_DEADLINE_MS = {_word(inbound['deadline_ms'])}\n",
            f"const VEC_INBOUND_AMOUNT = {_word(inbound['amount'])}\n",
            f"const VEC_INBOUND_RECIPIENT = {_word(account(inbound['recipient']))}\n",
            f"const VEC_INBOUND_PAYLOAD_HASH = {_word(inbound['payload_hash'])}\n",
            f"const VEC_INBOUND_MESSAGE_ID = {_word(inbound['message_id'])}\n\n",
            _array_fun(
                "vecOutboundPayloadPieces", "slice", _pieces(outbound["payload"]),
                "The TON→Taira payload of a burn in 127-byte pieces.",
            ),
            _array_fun(
                "vecOutboundRecipientPieces", "slice", _pieces(outbound["recipient"]),
                "The `taira_account` recipient bytes of that burn.",
            ),
            f"const VEC_OUTBOUND_NONCE = {_word(outbound['nonce'])}\n",
            f"const VEC_OUTBOUND_REVISION = {_word(outbound['route_revision'])}\n",
            f"const VEC_OUTBOUND_AMOUNT = {_word(outbound['amount'])}\n",
            f"const VEC_OUTBOUND_SENDER = {_word(account(outbound['sender']))}\n",
            f"const VEC_OUTBOUND_PAYLOAD_HASH = {_word(outbound['payload_hash'])}\n",
            f"const VEC_OUTBOUND_MESSAGE_ID = {_word(outbound['message_id'])}\n\n",
        ]
    )


TREE_ROOT_COUNTS = 17
TREE_PATHS_COUNT = 5
TREE_FULL_COUNT = 512
HISTORY_SIZE = 40


def _render_trees(tree: Any, history: Any) -> str:
    trees = {entry["count"]: entry for entry in tree["trees"]}
    node = tree["examples"]["node"]
    full = trees[TREE_FULL_COUNT]
    last = TREE_FULL_COUNT - 1
    sized = {entry["size"]: entry for entry in history["sizes"]}[HISTORY_SIZE]
    first = history["leaves"][0]
    paths = [
        (f"leaf {index}", _array("int", [_word(word) for word in path], "        "))
        for index, path in enumerate(trees[TREE_PATHS_COUNT]["paths"])
    ]
    return "".join(
        [
            "// Promote-odd commitment trees of §3.4 (`commitment_tree_v1.json`). The leaf\n"
            "// values are opaque 32-byte words here.\n\n",
            f"const VEC_NODE_LEFT = {_word(node['left'])}\n",
            f"const VEC_NODE_RIGHT = {_word(node['right'])}\n",
            f"const VEC_NODE = {_word(node['node'])}\n\n",
            _array_fun(
                "vecTreeLeaves", "int", [_word(word) for word in tree["leaves"][:TREE_ROOT_COUNTS]],
                f"The first {TREE_ROOT_COUNTS} leaves of the fixture tree.",
            ),
            _array_fun(
                "vecTreeRoots", "int",
                [_word(trees[count]["root"]) for count in range(1, TREE_ROOT_COUNTS + 1)],
                f"Root of the first `i + 1` leaves, for `i` in 0..{TREE_ROOT_COUNTS}.",
            ),
            _lookup(
                "vecTree5Path", "array<int>", paths,
                f"Sibling path of leaf `index` in the tree of the first {TREE_PATHS_COUNT} leaves.",
            ),
            f"/// The tree of {TREE_FULL_COUNT} leaves: its root, its last leaf and that leaf's path.\n",
            f"const VEC_TREE_FULL_ROOT = {_word(full['root'])}\n",
            f"const VEC_TREE_FULL_LAST_LEAF = {_word(tree['leaves'][last])}\n\n",
            _array_fun(
                "vecTreeFullLastPath", "int", [_word(word) for word in full["paths"][last]],
                f"The {len(full['paths'][last])} siblings of leaf {last} of {TREE_FULL_COUNT}.",
            ),
            "// History accumulator of §3.5 (`history_v1.json`).\n\n",
            f"const VEC_HISTORY_HEIGHT = {_word(first['height'])}\n",
            f"const VEC_HISTORY_SCCP_ROOT = {_word(first['sccp_root'])}\n",
            f"const VEC_HISTORY_MESSAGE_COUNT = {_word(first['message_count'])}\n",
            f"const VEC_HISTORY_LEAF = {_word(first['leaf'])}\n\n",
            _array_fun(
                "vecHistoryLeaves", "int", [_word(row["leaf"]) for row in history["leaves"][:HISTORY_SIZE]],
                f"The first {HISTORY_SIZE} history leaves.",
            ),
            f"const VEC_HISTORY_ROOT = {_word(sized['root'])}\n\n",
            _array_fun(
                "vecHistoryFirstPath", "int", [_word(word) for word in sized["paths"][0]],
                f"Path of history leaf 0 at size {HISTORY_SIZE}.",
            ),
            _array_fun(
                "vecHistoryLastPath", "int", [_word(word) for word in sized["paths"][HISTORY_SIZE - 1]],
                f"Path of history leaf {HISTORY_SIZE - 1} at size {HISTORY_SIZE}.",
            ),
        ]
    )


def _render_init_bounds(transitions: Any, codes: Dict[str, int]) -> str:
    rows = transitions["init_bounds"]
    comment = ", ".join(row["label"] for row in rows)
    return "".join(
        [
            f"// `init_bounds` of `committee_transitions_v1.json`: {comment}.\n\n",
            f"const VEC_INIT_BOUND_COUNT = {len(rows)}\n\n",
            _array_fun("vecInitBoundNowMs", "int", [_word(row["now_ms"]) for row in rows], "`now_ms` of each row."),
            _array_fun(
                "vecInitBoundUntilMs", "int", [_word(row["until_ms"]) for row in rows],
                "Pinned `until_ms` of each row.",
            ),
            _array_fun(
                "vecInitBoundExits", "int", [str(_exit(codes, row["expected"])) for row in rows],
                "Exit code of `sccp_init` for each row (0 when it accepts the pin).",
            ),
        ]
    )


def fixture_coverage_counts() -> Dict[str, int]:
    """Every contract-visible row rendered for TON, independently pinned by the replay suite."""

    payload = load_fixture("payload_v1.json")
    tree = load_fixture("commitment_tree_v1.json")
    history = load_fixture("history_v1.json")
    native = load_fixture("native_transfer_event_v1.json")
    return {
        "payload_directions": sum(TON_NETWORK in row["label"] for row in payload["directions"]),
        "payload_rejections": len(payload["rejected_payloads"]),
        "tree_roots": len(tree["trees"]),
        "tree_paths": sum(len(row["paths"]) for row in tree["trees"]),
        "tree_negatives": len(tree["negatives"]),
        "history_roots": len(history["sizes"]),
        "history_paths": sum(len(row["paths"]) for row in history["sizes"]),
        "history_leaves": len(history["leaves"]),
        "native_transfers": sum(row["source_profile"] == TON_NETWORK for row in native["transfers"]),
        "bls_verifications": len(bls_verification_rows()),
        "fast_pause_controls": sum(row["network"] == TON_NETWORK for row in load_fixture("fast_pause_v1.json")["controls"]),
        "forgery_evidence": len(load_fixture("forgery_evidence_v1.json")["rows"]),
    }


def _fixture_table(cells: Sequence[Cell]) -> Cell:
    """Balanced reference tree preserving fixture order without TVM tuple-size limits."""

    if not cells:
        raise TonBuilderError("a fixture table must contain a row")
    if len(cells) == 1:
        return cells[0]
    middle = len(cells) // 2
    return Cell("", [_fixture_table(cells[:middle]), _fixture_table(cells[middle:])])


def _render_cell_table(name: str, cells: Sequence[Cell], doc: str) -> str:
    """Render bounded BoC pages with logarithmic selection inside each page."""

    pages = []
    page_size = 16
    for offset in range(0, len(cells), page_size):
        page = cells[offset:offset + page_size]
        encoded = serialize_boc(_fixture_table(page)).hex()
        pages.append((f"rows {offset}..{offset + len(page)}", f'parseCellFromHex("{encoded}")'))
    return (_lookup(name + "Page", "cell", pages, doc + " Paged at 16 rows per BoC literal.")
            + f"/// Selects one recorded row from {name}Page.\nfun {name}(index: int): cell {{\n"
            + f"    assert ((index >= 0) & (index < {len(cells)})) throw VecErrors.BadIndex;\n"
            + f"    val offset = (index / {page_size}) * {page_size};\n"
            + f"    return vecFixtureCell(index - offset, min({page_size}, {len(cells)} - offset), {name}Page(index / {page_size}));\n}}\n\n")


def _hash_path_cell(words: Sequence[str]) -> Cell:
    """A test-table path: at most three 256-bit words per linked cell."""

    head = Builder()
    for word in words[:3]:
        head.uint(int(word, 16), 256)
    if len(words) > 3:
        head.ref(_hash_path_cell(words[3:]))
    return head.end()


def _render_complete_merkle(tree: Any, history: Any) -> str:
    """All recorded paths and roots; no computed path substitutes for a fixture row."""

    out = [f"const VEC_ALL_HISTORY_EMPTY_ROOT = {_word(history['empty_root'])}\n\n"]
    for name, entries, count_key, leaves in (
        ("Tree", tree["trees"], "count", tree["leaves"]),
        ("History", history["sizes"], "size", [row["leaf"] for row in history["leaves"]]),
    ):
        if len({entry[count_key] for entry in entries}) != len(entries):
            raise TonBuilderError(f"duplicate {name} fixture count")
        cells = []
        for entry in entries:
            count = entry[count_key]
            if len(entry["paths"]) != count:
                raise TonBuilderError(f"{name} count {count} does not have every position")
            for index, path in enumerate(entry["paths"]):
                cells.append(Builder().uint(count, 32).uint(index, 32)
                             .uint(int(leaves[index], 16), 256).uint(int(entry["root"], 16), 256)
                             .uint(len(path), 8).ref(_hash_path_cell(path)).end())
        out.append(_render_cell_table(f"vecAll{name}Path", cells, f"Every recorded {name.lower()} root and path, count then position order."))
    negatives = []
    for row in tree["negatives"]:
        negatives.append((row["label"], _struct([
            ("leaf", _word(row["leaf"])), ("index", str(row["index"])), ("count", str(row["count"])),
            ("root", _word(row["expected_root"])),
            ("path", _array("int", [_word(word) for word in row["path"]], "            ")),
            ("computed", _word(row["result"].get("computed_root", 0))),
            ("malformed", _bool("error" in row["result"])),
        ])))
    out.append("struct VecTreeNegative {\n    leaf: int\n    index: int\n    count: int\n    root: int\n    path: array<int>\n    computed: int\n    malformed: bool\n}\n\n")
    out.append(_lookup("vecTreeNegative", "VecTreeNegative", negatives, "Every transfer/control/node confusion and structural refusal."))
    out.append(_lookup("vecAllHistoryLeaf", "[int, int, int, int]", [
        (f"history leaf {i}", f"[{_word(row['height'])}, {_word(row['sccp_root'])}, {_word(row['message_count'])}, {_word(row['leaf'])}]")
        for i, row in enumerate(history["leaves"])
    ], "Every history leaf's source fields and committed hash."))
    return "".join(out)


def _render_payload_rejections(payloads: Any, codes: Dict[str, int]) -> str:
    """Replay all raw rejected bytes with TON-specific first-failure outcomes."""

    rows = []
    for row in payloads["rejected_payloads"]:
        raw = bytes.fromhex(_hex_body(row["payload"]))
        # A foreign-lane payload is still presented unchanged: the minter must
        # reject its domain before reaching a foreign recipient codec/amount.
        outcome = "BadPayload"
        if not raw:
            outcome = "BadSnake"
        elif len(raw) >= 10 and int.from_bytes(raw[6:10], "big") == 4:
            if row["error"] == "BadRecipient":
                outcome = "BadRecipient"
        rows.append((f"{row['label']}: source {row['error']}; TON {outcome}", _struct([
            ("pieces", _array("slice", _pieces(row["payload"]), "            ")),
            ("exit", str(_exit(codes, outcome))),
        ])))
    return ("struct VecRejectedPayload {\n    pieces: array<slice>\n    exit: int\n}\n\n"
            + _lookup("vecRejectedPayload", "VecRejectedPayload", rows, "All raw payload refusals and the exact destination-specific TON error."))


def bls_verification_rows() -> List[Dict[str, Any]]:
    """Applicable fixture verification inputs and their explicit TON opcode verdicts.

    Key generation/signing, distinct-message aggregation, w3f PoP generation,
    and Rust context allowlist APIs do not exist at the destination boundary.
    Standard signing rows are consumed as verification of their recorded outputs.
    """

    bls = load_fixture("bls_consensus_v1.json")
    rust = load_fixture("bls_consensus_rust_v1.json")
    rows: List[Dict[str, Any]] = []
    groups = (
        "sign_verify.signatures", "sign_verify.negatives", "aggregates.fast_aggregate_verify",
        "ethereum_standard_inputs.signatures", "ethereum_standard_inputs.fast_aggregates",
        "rust.standard_vectors.sign", "rust.standard_vectors.verify", "rust.standard_vectors.fast_aggregate_verify",
        "ethereum_mainnet_sync_committee", "rust.negatives",
        "ethereum_malformed_inputs.g1_deserialization", "ethereum_malformed_inputs.g2_deserialization",
    )

    def add(label: str, keys: Sequence[str], message: str, signature: str, accepted: int) -> None:
        group = next(i for i, prefix in enumerate(groups) if label.startswith(prefix))
        rows.append({"label": label, "group": group, "keys": list(keys), "message": message,
                     "signature": signature, "ton_verdict": int(accepted)})

    single = bls["sign_verify"]
    for index, row in enumerate(single["signatures"]):
        add(f"sign_verify.signatures[{index}]", [single["keys"][row["key"]]["pk"]], row["msg"], row["signature"], row["verify"])
    for row in single["negatives"]:
        add("sign_verify.negatives." + row["label"], [row["pk"]], row["msg"], row["signature"], row["verify"])
    for row in bls["aggregates"]["fast_aggregate_verify"]:
        add("aggregates.fast_aggregate_verify." + row["label"], row["pks"], row["msg"], row["signature"], row["result"])
    standard = bls["ethereum_standard_inputs"]
    for index, row in enumerate(standard["signatures"]):
        add(f"ethereum_standard_inputs.signatures[{index}]", [standard["pubkeys"][row["key"]]], row["msg"], row["signature"], True)
    for index, row in enumerate(standard["fast_aggregates"]):
        add(f"ethereum_standard_inputs.fast_aggregates[{index}]", [standard["pubkeys"][key] for key in row["keys"]], row["msg"], row["signature"], row["fast_aggregate_verify"])
    malformed = bls["ethereum_malformed_inputs"]
    baseline = malformed["baseline"]
    for group in (1, 2):
        for row in malformed[f"g{group}_deserialization"]:
            key = row["encoding"] if group == 1 else baseline["pk"]
            signature = row["encoding"] if group == 2 else baseline["signature"]
            add(f"ethereum_malformed_inputs.g{group}_deserialization.{row['label']}",
                [key], baseline["msg"], signature, row["ton_verify"])
    rust_keys = [row["public_key"] for row in rust["keys"]]
    for section in ("sign", "verify", "fast_aggregate_verify"):
        for index, row in enumerate(rust["standard_vectors"][section]):
            keys = [rust_keys[key] for key in row.get("keys", [row.get("key", 0)])]
            add(f"rust.standard_vectors.{section}[{index}]", keys, row["message"], row["signature"], row.get("valid", True))
    mainnet = bls["ethereum_mainnet_sync_committee"]
    add("ethereum_mainnet_sync_committee", [mainnet["aggregate_public_key"]["compressed"]],
        mainnet["signing_root"], mainnet["signature"], mainnet["fast_aggregate_verify"])
    dropped = mainnet["negative_first_participant_dropped"]
    add("ethereum_mainnet_sync_committee.negative_first_participant_dropped",
        [dropped["aggregate_public_key"]["compressed"]], mainnet["signing_root"],
        mainnet["signature"], dropped["fast_aggregate_verify"])
    baseline = rust["standard_vectors"]["sign"][0]
    for row in rust["negatives"]:
        label = row["case"]
        keys = row.get("public_keys", [row.get("public_key", rust_keys[row.get("key", 0)])])
        message = row.get("message")
        if message is None:
            message = ("0x" + hashlib.sha256(bytes.fromhex(_hex_body(row["preimage"]))).hexdigest()
                       if "preimage" in row else baseline["message"])
        # The generic Rust API uses w3f. TON's POP opcode accepts this genuine
        # DST_SIG signature even though the generic Rust API refuses it.
        accepted = label == "dst_sig_signature_presented_to_generic_api"
        add("rust.negatives." + label, keys, message, row.get("signature", baseline["signature"]), accepted)
    if len({row["label"] for row in rows}) != len(rows):
        raise TonBuilderError("duplicate BLS verification label")
    return rows


def bls_skipped_rows() -> List[Dict[str, Any]]:
    """Rows whose operations are outside the destination POP verification interface."""

    bls = load_fixture("bls_consensus_v1.json")
    rust = load_fixture("bls_consensus_rust_v1.json")
    groups = [
        ("sign_verify.keys", len(bls["sign_verify"]["keys"]), "key generation is off chain; public keys are replay inputs"),
        ("aggregates.aggregate_verify", len(bls["aggregates"]["aggregate_verify"]), "distinct-message aggregation is outside CommitQC verification"),
        ("ethereum_standard_inputs.aggregate_verify", 1, "distinct-message aggregation is outside CommitQC verification"),
        ("ethereum_standard_inputs.privkeys", len(bls["ethereum_standard_inputs"]["privkeys"]), "key generation and signing are off chain"),
        ("consensus_allowlist", len(bls["consensus_allowlist"]), "Rust context allowlist API is not a destination operation"),
        ("imported_rfc9380.expand_message_xmd.vectors", len(bls["imported_rfc9380"]["expand_message_xmd"]["vectors"]), "alternate RFC DST is not the POP opcode DST"),
        ("imported_rfc9380.hash_to_g2.vectors", len(bls["imported_rfc9380"]["hash_to_g2"]["vectors"]), "alternate RFC DST is not the POP opcode DST"),
        ("rust.keys", len(rust["keys"]), "key and w3f PoP generation are off chain; public keys are replay inputs"),
        ("rust.allowlist", len(rust["allowlist"]), "Rust context allowlist API is not a destination operation"),
        ("rust.allowlist_rejections", len(rust["allowlist_rejections"]), "Rust context allowlist API is not a destination operation"),
        ("rust.standard_vectors.aggregate", len(rust["standard_vectors"]["aggregate"]), "signature aggregation is off chain; aggregate verification is replayed"),
        ("rust.standard_vectors.aggregate_verify", len(rust["standard_vectors"]["aggregate_verify"]), "distinct-message aggregation is outside CommitQC verification"),
    ]
    return [{"section": section, "count": count, "reason": reason} for section, count, reason in groups]


def _render_bls_verifications() -> str:
    """Render all applicable verification rows without signing or generating points."""

    rows = []
    for row in bls_verification_rows():
        rows.append((f"{row['label']}: TON opcode = {row['ton_verdict']}", _struct([
            ("keys", _array("slice", [_slice(key) for key in row["keys"]], "            ")),
            ("message", _slice(row["message"])), ("signature", _slice(row["signature"])),
            ("verdict", str(row["ton_verdict"])), ("group", str(row["group"])),
        ])))
    skips = "".join(f"// Skip {row['section']} ({row['count']} rows): {row['reason']}.\n" for row in bls_skipped_rows())
    return (skips + "// Skips: key generation and signing operations; distinct-message aggregation;\n"
            "// w3f PoP generation; Rust-only context allowlist APIs. Recorded standard\n"
            "// signatures are verified, including the Rust generic-API row's TON acceptance.\n"
            "struct VecBlsVerification {\n    keys: array<slice>\n    message: slice\n    signature: slice\n    verdict: int\n    group: int\n}\n\n"
            + _lookup("vecBlsVerification", "VecBlsVerification", rows, "All applicable POP verification rows from both BLS fixtures."))


def _render_native_transfers(native: Any) -> str:
    """The fixture's original ext-out BoC, compared to the minter's real output."""

    rows = []
    for row in native["transfers"]:
        if row["source_profile"] != TON_NETWORK:
            continue
        encoded = bytes.fromhex(_hex_body(row["ext_out_body"]))
        parse_boc(encoded)
        sender = bytes.fromhex(_hex_body(row["sender"]["bytes"]))
        if len(sender) != 36 or sender[:4] != b"\0" * 4:
            raise TonBuilderError("native TON event has another sender format")
        rows.append((f"native transfer nonce {row['nonce']}", _struct([
            ("networkId", _word(native["taira_network_id"])),
            ("revision", str(row["route_revision"])), ("nonce", str(row["nonce"])),
            ("owner", _word("0x" + sender[4:].hex())), ("amount", _word(row["amount"])),
            ("recipient", _array("slice", _pieces(row["recipient"]["bytes"]), "            ")),
            ("body", f'parseCellFromHex("{encoded.hex()}")'),
        ])))
    return ("struct VecNativeTransfer {\n    networkId: int\n    revision: int\n    nonce: int\n    owner: int\n    amount: int\n    recipient: array<slice>\n    body: cell\n}\n\n"
            + _lookup("vecNativeTransfer", "VecNativeTransfer", rows, "Every TON native event with the independently encoded exact ext-out body."))


def _render_fast_pause_controls(fixture: Any, codes: Dict[str, int]) -> str:
    """Render authenticated control inputs verbatim; compute no authorization or leaf."""

    rows = []
    for row in fixture["controls"]:
        if row["network"] != TON_NETWORK:
            continue
        fields, expected = row["fields"], row["expected"]
        raw = _hex_body(row["preimage"])
        rows.append((row["id"], _struct([
            ("networkId", _word(row["network_id"])), ("destinationWord", _word(row["destination_word"])),
            ("routeRevision", _word(fields["route_revision"])), ("controlNonce", _word(fields["control_nonce"])),
            ("track", _word(fields["track"])), ("parliamentPaused", _bool(fields["parliament_paused"])),
            ("fastPauseUntilMs", _word(fields["fast_pause_until_ms"])), ("certificateId", _word(fields["certificate_id"])),
            ("effectHash", _word(fields["effect_hash"])), ("previousNonce", _word(row["previous_control_nonce"])),
            ("nowMs", _word(row["now_ms"])), ("b1", _slice("0x" + raw[:250])), ("b2", _slice("0x" + raw[250:])),
            ("leaf", _word(row["leaf"])), ("appliedUntilMs", _word(expected["applied_until_ms"])),
            ("mintingPaused", _bool(expected["minting_paused"])),
            ("exit", "0" if expected["outcome"] == "Applied" else str(_exit(codes, expected["outcome"]))),
        ])))
    return ("struct VecFastPauseControl {\n    networkId: int\n    destinationWord: int\n    routeRevision: int\n"
            "    controlNonce: int\n    track: int\n    parliamentPaused: bool\n    fastPauseUntilMs: int\n"
            "    certificateId: int\n    effectHash: int\n    previousNonce: int\n    nowMs: int\n"
            "    b1: slice\n    b2: slice\n    leaf: int\n    appliedUntilMs: int\n    mintingPaused: bool\n    exit: int\n}\n\n"
            + _lookup("vecFastPauseControl", "VecFastPauseControl", rows,
                      "Every TON fast_pause_v1 control: authenticated id/effect inputs, leaf, expiry, clamp and nonce outcome."))


def _render_forgery_evidence(fixture: Any, codes: Dict[str, int]) -> str:
    """Render exact certificate bytes and source/destination outcomes without deriving hashes."""

    constants = fixture["constants"]
    rows = []
    for row in fixture["rows"]:
        inputs, expected = row["input"], row["expected"]
        header, qc = _hex_body(inputs["header"]), _hex_body(inputs["qc"])
        # ACTIVE is part of the destination wire boundary. Core's E0--E4,
        # retention and liability outcomes are not destination operations.
        destination_exit = 0 if int(header[128:130], 16) & 1 else _exit(codes, "BadHeader")
        rows.append((f"{row['label']}: Core {expected['outcome']}; TON certificate exit {destination_exit}", _struct([
            ("head", _slice("0x" + header[:218])), ("tail", _slice("0x" + header[218:])),
            ("qc", _slice("0x" + qc[:-8])), ("signers", _word(int(qc[-8:], 16))),
            ("signature", _slice(inputs["aggregate_signature"])), ("result", _word(expected["result"])),
            ("message", _slice(expected["message"])), ("evidenceId", _word(expected["evidence_id"])),
            ("exit", str(destination_exit)),
        ])))
    return (f"const VEC_FORGERY_NETWORK_ID = {_word(constants['network_id'])}\n"
            f"const VEC_FORGERY_INSTANCE = {_word(constants['consensus_instance'])}\n"
            f"const VEC_FORGERY_GENERATION = {_word(constants['generation'])}\n"
            f"const VEC_FORGERY_COMMITTEE_ROOT = {_word(constants['committee_root'])}\n\n"
            + _array_fun("vecForgeryKeys", "slice", [_slice(key) for key in constants["committee_keys"]], "The fixture's committed signer keys.")
            + "struct VecForgeryEvidence {\n    head: slice\n    tail: slice\n    qc: slice\n    signers: int\n"
            "    signature: slice\n    result: int\n    message: slice\n    evidenceId: int\n    exit: int\n}\n\n"
            + _lookup("vecForgeryEvidence", "VecForgeryEvidence", rows,
                      "Every forgery certificate. Evidence ids are checked by the suite launcher, since TON exposes no BLAKE2b-256 opcode."))


def _render_complete_fixture_replays(codes: Dict[str, int]) -> str:
    """Complete contract fixture tables; the hand-written suite pins every counter."""

    out = ['import "@acton/fmt"\n\n']
    for name, count in fixture_coverage_counts().items():
        out.append(f"const VEC_ALL_{_upper(name)} = {count}\n")
    out.append('''
/// Balanced fixture table lookup; fixture bytes are not recomputed by the harness.
fun vecFixtureCell(index: int, count: int, root: cell): cell {
    assert ((index >= 0) & (index < count)) throw VecErrors.BadIndex;
    var i = index;
    var n = count;
    var cur = root;
    while (n > 1) {
        val middle = n / 2;
        var s = cur.beginParse();
        val left = s.loadRef();
        val right = s.loadRef();
        if (i < middle) {
            cur = left;
            n = middle;
        } else {
            cur = right;
            i -= middle;
            n -= middle;
        }
    }
    return cur;
}

''')
    out.append(_render_complete_merkle(load_fixture("commitment_tree_v1.json"), load_fixture("history_v1.json")))
    out.append(_render_payload_rejections(load_fixture("payload_v1.json"), codes))
    out.append(_render_bls_verifications())
    out.append(_render_native_transfers(load_fixture("native_transfer_event_v1.json")))
    out.append(_render_fast_pause_controls(load_fixture("fast_pause_v1.json"), codes))
    out.append(_render_forgery_evidence(load_fixture("forgery_evidence_v1.json"), codes))
    return "".join(out)


def render_test_vectors() -> str:
    """Tolk source of `sccp-test-vectors.gen.tolk`: fixture data without any test logic."""

    finality = load_fixture("finality_v1.json")
    transitions = load_fixture("committee_transitions_v1.json")
    control = load_fixture("control_v1.json")
    codes = exit_codes(transitions)
    minter_word = finality["verification_context"]["ton"]["destination_word"]
    return "".join(
        [
            VECTORS_HEADER,
            _render_context(finality, transitions, control),
            _render_exit_codes(codes),
            _render_test_keys(finality),
            _render_committees(finality, load_fixture("ton_stateinit_v1.json")),
            _render_worked_examples(finality),
            _render_headers(finality, codes),
            _render_hash_to_g2(load_fixture("bls_consensus_v1.json")),
            _render_control_leaves(control, minter_word),
            _render_payloads(load_fixture("payload_v1.json")),
            _render_trees(load_fixture("commitment_tree_v1.json"), load_fixture("history_v1.json")),
            _render_init_bounds(transitions, codes),
            _render_complete_fixture_replays(codes),
        ]
    ).rstrip("\n") + "\n"


CERT_VECTORS_HEADER = """// Generated by `python3 scripts/ton_sccp_builder.py vectors`; do not edit.
//
// The certificates and the destination scenarios of the committed reference
// fixtures, rendered for the Acton suite (specs/sccp.md §11.1, §11.3, §11.4
// item 5). The builder derives none of these values.
//
// - `vecCertificate`, `vecCertificateFacts` and `vecNegativeCertificate` are
//   the rows of `certificates`, `negative_certificates` and
//   `flavor_specific_certificates` of `finality_v1.json` in their TON form.
//   `vecDeployCertificate` and `vecSubmitCertificate` run a row as the
//   fixture defines it: one `sccp_checkpoint` on a fresh minter deployed with
//   the row's pin at the row's time.
// - `vecRustNegativeCertificate` renders `finality_rust_v1.json`, with the
//   signed messages and checkpoint ids from that independent Rust fixture.
// - `vecScenario…` replay the TON scenarios of
//   `committee_transitions_v1.json` and its `ton_replayable` EVM scenarios
//   step by step on the minter at `0:35…35`, one message per step, and
//   compare the exit code, the external-out events and the state after
//   every step.
// - `vecScenarioTonControl…` replays all TON destination-effect rows of
//   `control_v1.json`, including their independent certificates and native effects.

import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@contracts/sccp-cells"
import "@contracts/sccp-storage"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// A certificate row of `finality_v1.json` in its TON form.
struct VecCertificate {
    /// The pin of the fresh deployment the row runs on, with the keys of the
    /// pinned committee in canonical order.
    pin: InitialPin
    pinKeys: array<slice>
    /// False when the row pins keys that `sccp_init` refuses (a list that is
    /// not strictly ascending or has another root): the deployment is then
    /// installed already initialized.
    initChecked: bool
    /// Destination clock of the deployment and of the call, in seconds.
    initSeconds: int
    nowSeconds: int
    /// Contents of `TairaCert`, `QcFixed`, `XHead` and `XTail`.
    signature: slice
    signers: int
    qc: slice
    head: slice
    tail: slice
    /// Exit code of `sccp_checkpoint` with this certificate (0 when it is
    /// accepted), or `VEC_EXIT_UNPINNED` when the fixture pins no TON outcome.
    exit: int
}

/// What verifying a positive certificate row derives, and who signed it.
struct VecCertificateFacts {
    /// Test key of each member of the signing committee in canonical order,
    /// and the canonical indices of the signers.
    committee: array<int>
    signerIndices: array<int>
    /// `R`, the signed message `m = SHA-256(P)` and `hash_to_G2(m)`.
    r: int
    m: slice
    hashToG2: slice
    /// `checkpoint_id(X)` and the fields of `X` an outcome depends on.
    id: int
    height: int
    generation: int
    flags: int
    timestampMs: int
    validityMs: int
    nextCommitteeRoot: int
    /// Test key of each member of the successor of a key-changing rotation in
    /// canonical order; empty for every other row.
    nextCommittee: array<int>
}

/// `VecCertificate.exit` of a row for which the fixture pins no TON outcome.
const VEC_EXIT_UNPINNED = -1

/// Deploys the fresh pinned minter of a certificate row at the row's
/// deployment time and moves the clock to the time of the call.
fun vecDeployCertificate(row: VecCertificate): Env {
    val env = row.initChecked
        ? replayDeploy(row.pin, row.pinKeys, TEST_MAX_SUPPLY, row.initSeconds)
        : replayDeployUnchecked(row.pin, row.pinKeys, TEST_MAX_SUPPLY, row.initSeconds);
    testing.setNow(row.nowSeconds);
    return env;
}

/// Sends the certificate of a row through `sccp_checkpoint`.
fun vecSubmitCertificate(env: Env, row: VecCertificate, nextKeys: cell?): SendResultList {
    return replayCheckpoint(
        env,
        certCell(row.signature, row.signers, row.qc, row.head, row.tail),
        nextKeys,
    );
}

"""


def _pin_expr(pin: Any) -> str:
    return (
        "InitialPin { "
        f"generation: {_word(pin['generation'])}, root: {_word(pin['committee_root'])}, "
        f"start: {_word(pin['start_height'])}, untilMs: {_word(pin['until_ms'])}"
        " }"
    )


def _passes_init(keys: Sequence[str], root: str) -> bool:
    """Whether `sccp_init` accepts `keys` under the pinned `root` (§5.3.1): a
    committee size, strictly ascending keys and their committee root. It selects
    how a row is deployed and is no vector."""

    try:
        return committee_root([bytes.fromhex(_hex_body(key)) for key in keys]) == int(root, 16)
    except TonBuilderError:
        return False


def _certificate_row(row: Any, committees: Any, codes: Dict[str, int], constants: Any) -> str:
    pin = row["pin"]
    keys = pin.get("keys") or _keys_of_root(committees, pin["committee_root"])
    ton = row["ton"]
    expected = row["expected"]["ton"]
    fields = [
        ("pin", _pin_expr(pin)),
        ("pinKeys", _array("slice", [_slice(key) for key in keys], "            ")),
        ("initChecked", _bool(_passes_init(keys, pin["committee_root"]))),
        ("initSeconds", str(_replay_init_seconds(row["now_ms"], pin["until_ms"], constants))),
        ("nowSeconds", str(row["now_ms"] // 1000)),
        ("signature", _slice(ton["signature"])),
        ("signers", _word(ton["signers"])),
        ("qc", _slice(ton["qc_fixed_cell"])),
        ("head", _slice(ton["x_head"])),
        ("tail", _slice(ton["x_tail"])),
        ("exit", "VEC_EXIT_UNPINNED" if expected is None else str(_exit(codes, expected))),
    ]
    return _struct(fields)


def _render_certificates(finality: Any, codes: Dict[str, int], constants: Any) -> str:
    committees = finality["committees"]
    by_root = {committee["root"]: committee for committee in committees.values()}
    positives, facts, index_names = [], [], []
    for index, row in enumerate(finality["certificates"]):
        if row["expected"]["ton"] != "ok":
            raise TonBuilderError(f"certificate {row['label']} is not accepted on TON")
        header = row["header_fields"]
        committee = committees[row["committee"]]
        successor = by_root.get(header["next_committee_root"])
        key_change = header["flags"] & 2 and header["next_committee_root"] != header["committee_root"]
        if key_change and successor is None:
            raise TonBuilderError(f"the successor keys of {row['label']} are not in the fixture")
        next_indices = [str(i) for i in successor["test_key_indices"]] if key_change else []
        positives.append((row["label"], _certificate_row(row, committees, codes, constants)))
        facts.append(
            (
                row["label"],
                _struct(
                    [
                        ("committee", _array("int", [str(i) for i in committee["test_key_indices"]], "            ")),
                        ("signerIndices", _array("int", [str(i) for i in row["signer_indices"]], "            ")),
                        ("r", _word(row["r"])),
                        ("m", _slice(row["m"])),
                        ("hashToG2", _slice(row["hash_to_g2_m"]["compressed"])),
                        ("id", _word(row["checkpoint_id"])),
                        ("height", _word(header["height"])),
                        ("generation", _word(header["generation"])),
                        ("flags", _word(header["flags"])),
                        ("timestampMs", _word(header["timestamp_ms"])),
                        ("validityMs", _word(header["validity_ms"])),
                        ("nextCommitteeRoot", _word(header["next_committee_root"])),
                        ("nextCommittee", _array("int", next_indices, "            ")),
                    ]
                ),
            )
        )
        index_names.append(f"const VEC_CERT_{_upper(row['label'])} = {index}\n")
    negatives, negative_names = [], []
    rows = finality["negative_certificates"] + finality["flavor_specific_certificates"]
    for index, row in enumerate(rows):
        expected = row["expected"]["ton"]
        outcome = "no TON outcome pinned" if expected is None else expected
        negatives.append((f"{row['label']}: {outcome}", _certificate_row(row, committees, codes, constants)))
        negative_names.append(f"const VEC_NEG_{_upper(row['label'])} = {index}\n")
    return "".join(
        [
            "/// Rows of `certificates`: every one is accepted on TON.\n",
            f"const VEC_CERTIFICATE_COUNT = {len(positives)}\n",
            *index_names,
            "\n",
            _lookup("vecCertificate", "VecCertificate", positives, "Row `index` of `certificates`."),
            _lookup(
                "vecCertificateFacts", "VecCertificateFacts", facts,
                "The derived values and the signers of row `index` of `certificates`.",
            ),
            "/// Rows of `negative_certificates` followed by `flavor_specific_certificates`.\n",
            f"const VEC_NEGATIVE_CERTIFICATE_COUNT = {len(negatives)}\n",
            *negative_names,
            "\n",
            _lookup(
                "vecNegativeCertificate", "VecCertificate", negatives,
                "Row `index` of the negative and flavour-specific certificates (label and TON "
                "outcome in the comment).",
            ),
        ]
    )


def _call(function: str, arguments: Sequence[str], indent: str = "    ") -> str:
    """A Tolk call with one argument per line, so that no line holds two hex literals."""

    inner = "".join(f"{indent}    {argument},\n" for argument in arguments)
    return f"{function}(\n{inner}{indent})"


def _keys_expr(keys: Sequence[str], indent: str) -> str:
    return _array("slice", [_slice(key) for key in keys], indent)


def _path_expr(words: Sequence[str], indent: str) -> str:
    return _array("int", [_word(word) for word in words], indent)


def _cert_expr(ton: Any, indent: str = "    ") -> str:
    return _call(
        "certCell",
        [
            _slice(ton["signature"]),
            _word(ton["signers"]),
            _slice(ton["qc_fixed_cell"]),
            _slice(ton["x_head"]),
            _slice(ton["x_tail"]),
        ],
        indent,
    )


def _block_expr(block: Any, indent: str) -> str:
    return _call(
        "blockRefCell",
        [
            _word(block["height"]),
            _word(block["sccpRoot"]),
            _word(block["messageCount"]),
            _word(block["historyIndex"]),
            _path_expr(block["historyPath"], indent + "    "),
        ],
        indent,
    )


def _state_lines(now_ms: int, state: Any, with_checkpoints: bool) -> List[str]:
    committee = state["committee"]
    pause = state["pause"]
    lines = [
        f"    replayExpectState(env, {now_ms}, {_word(committee['generation'])}, {_word(committee['root'])}, "
        f"{_word(committee['start'])}, {_word(committee['high'])}, {_word(committee['until_ms'])}, "
        f"{_bool(state['equivocated'])}, {_bool(state['live'])}, {_word(pause['control_nonce'])}, "
        f"{_bool(pause['parliament_paused'])}, {_word(pause['fast_pause_until_ms'])}, "
        f"{_bool(pause['effective'])}, {_word(state['op_count'])});\n"
    ]
    lines.append(f"    replayExpectValueState(env, {_word(state['total_supply'])}, {_array('int', [_word(nonce) for nonce in state['consumed']])});\n")
    if committee.get("keys") is not None:
        lines.append(f"    replayExpectKeys(env, {_keys_expr(committee['keys'], '    ')});\n")
    if with_checkpoints:
        slots = sorted(state["checkpoints"], key=lambda entry: entry["height"])
        arguments = [str(len(slots))]
        for slot in range(3):
            arguments.append(_word(slots[slot]["height"]) if slot < len(slots) else "0")
            arguments.append(_word(slots[slot]["id"]) if slot < len(slots) else "0")
        lines.append(f"    replayExpectCheckpoints(env, {', '.join(arguments)});\n")
    return lines


def _event_expr(event: Any, certs: Dict[str, str], state: Any) -> str:
    name = event["event"]
    if name not in EVENT_BUILDERS:
        raise TonBuilderError(f"event {name} has no TON replay form")
    if name == "SccpFinalized":
        return f"replayEventFinalized({_word(event['messageId'])}, {_word(event['nonce'])})"
    if name == "SccpVoided":
        return f"replayEventVoided({_word(event['messageId'])}, {_word(event['nonce'])}, 1)"
    if name == "SccpCertificate":
        return f"eventCertificate({_word(event['height'])}, {_word(event['generation'])}, {certs[event['certificate']]})"
    if name == "SccpCheckpointed":
        ids = [entry["id"] for entry in state["checkpoints"] if entry["height"] == event["height"]]
        if len(ids) != 1:
            raise TonBuilderError("a recorded checkpoint is missing from the state after its step")
        return f"eventCheckpointed({_word(event['height'])}, {_word(ids[0])})"
    if name == "SccpCommitteeRotated":
        return (
            f"eventRotated({_word(event['generation'])}, {_word(event['root'])}, "
            f"{_word(event['untilMs'])}, {_word(event['startHeight'])})"
        )
    if name == "SccpLatched":
        return (
            f"eventLatched({_word(event['reason'])}, {_word(event['generation'])}, {_word(event['height'])}, "
            f"{_word(event['a'])}, {_word(event['b'])})"
        )
    return (
        f"eventControlApplied({_word(event['controlNonce'])}, {_word(event['track'])}, "
        f"{_bool(event['parliamentPaused'])}, {_word(event['fastPauseUntilMs'])}, {_word(event['certificateId'])})"
    )


def _scenario_function(scenario: Any, transitions: Any, codes: Dict[str, int], context: Any) -> str:
    pool = transitions["certificates"]
    committees = transitions["committees"]
    constants = transitions["constants"]
    ton = scenario.get("flavor") == "ton"
    deployment = scenario["deployment"]
    pin = deployment["pin"]
    if (
        deployment["taira_network_id"] != context["taira_network_id"]
        or deployment["consensus_instance"] != context["consensus_instance"]
        or deployment["route_revision"] != 1
        or (ton and deployment["destination_word"] != context["ton"]["destination_word"])
    ):
        raise TonBuilderError(f"scenario {scenario['name']} runs in another verification context")
    keys = pin.get("keys") or _keys_of_root(committees, pin["committee_root"])
    steps = scenario["steps"]
    init_seconds = _replay_init_seconds(steps[0]["now_ms"], pin["until_ms"], constants)
    initial = dict(scenario["initial_state"], live=True)
    initial["pause"] = dict(initial["pause"], effective=False)
    flavor = "TON scenario" if ton else "EVM scenario marked `ton_replayable`"
    lines = [
        f"/// `{scenario['name']}` ({flavor}): {scenario['description']}.\n",
        f"fun vecScenario{_camel(scenario['name'])}() {{\n",
        "    val env = "
        + _call(
            "replayDeploy",
            [
                _pin_expr(pin),
                _keys_expr(keys, "        "),
                _word(deployment["max_wrapped_supply"]),
                str(init_seconds),
            ],
        )
        + ";\n",
    ]
    lines += _state_lines(init_seconds * 1000, initial, True)
    previous_now = init_seconds * 1000
    for index, step in enumerate(steps):
        call = step["call"]
        now_ms = step["now_ms"]
        if now_ms % 1000 or now_ms < previous_now:
            raise TonBuilderError(f"scenario {scenario['name']} moves its clock backwards or off a second")
        previous_now = now_ms
        expected = step["expected"]
        state = step["state_after"]
        # an EVM destination keeps every checkpoint and a TON minter three,
        # so a replayed EVM row compares the slots only while they all fit
        with_checkpoints = ton or len(state["checkpoints"]) <= constants["ton_checkpoint_slots"]
        lines.append(f"    testing.setNow({now_ms // 1000});\n")
        if call == "views":
            initial_pin = expected["initialCommittee"]
            lines.append(f"    // step {index}: views\n")
            lines.append(
                f"    replayExpectPin(env, {_word(initial_pin['generation'])}, {_word(initial_pin['root'])}, "
                f"{_word(initial_pin['start'])}, {_word(initial_pin['untilMs'])});\n"
            )
            lines += _state_lines(now_ms, state, with_checkpoints)
            continue
        outcome = expected["outcome"]
        lines.append(f"    // step {index}: {call} -> {outcome}\n")
        certs: Dict[str, str] = {}

        def bind(cert_id: str) -> str:
            name = f"cert{index}"
            if certs:
                raise TonBuilderError("a TON step carries one certificate")
            lines.append(f"    val {name} = {_cert_expr(pool[cert_id]['ton'])};\n")
            certs[cert_id] = name
            return name

        def source() -> Tuple[str, str]:
            if "certificate" in step:
                return bind(step["certificate"]), "null"
            head, tail = _split_x(step["checkpoint"]["header"])
            return "null", _call("checkpointRefCell", [_slice(head), _slice(tail)], "        ")

        def send(function: str, arguments: Sequence[str]) -> None:
            lines.append(f"    val res{index} = {_call(function, arguments)};\n")

        if call in ("sccp_checkpoint", "submitCheckpoints"):
            if len(step["certificates"]) != 1:
                raise TonBuilderError(f"scenario {scenario['name']} batches certificates")
            cert_id = step["certificates"][0]
            next_keys = step["next_keys"][0] if ton else pool[cert_id]["ton_next_keys"]
            if isinstance(next_keys, str):
                next_keys = committees[next_keys]["keys"]
            next_expr = "null" if next_keys is None else (
                f"sccpBuildKeys({_keys_expr(next_keys, '        ')})"
            )
            send("replayCheckpoint", ["env", bind(cert_id), next_expr])
        elif call in ("sccp_finalize", "sccp_finalize_checkpoint", "sccp_void_expired", "sccp_void_expired_checkpoint"):
            proof = step["proof"]
            cert_expr, ref_expr = source()
            proof_expr = _call(
                "messageProofCell",
                [
                    _word(proof["leafIndex"]),
                    _path_expr(proof["path"], "            "),
                    f"snakeFromPieces({_array('slice', _pieces(proof['payload']), '            ')})",
                    _block_expr(proof["block"], "            "),
                ],
                "        ",
            )
            if "void" in call:
                send("replayVoidExpired", ["env", _word(step["nonce"]), cert_expr, ref_expr, proof_expr])
            else:
                send("replayFinalize", ["env", cert_expr, ref_expr, proof_expr])
        elif call in ("sccp_apply_control", "sccp_apply_control_checkpoint"):
            proof = step["proof"]
            cert_expr, ref_expr = source()
            proof_expr = _call(
                "controlProofCell",
                [
                    _word(proof["controlNonce"]),
                    _word(proof["track"]),
                    _bool(proof["parliamentPaused"]),
                    _word(proof["fastPauseUntilMs"]),
                    _word(proof["certificateId"]),
                    _word(proof["effectHash"]),
                    _word(proof["leafIndex"]),
                    _path_expr(proof["path"], "            "),
                    _block_expr(proof["block"], "            "),
                ],
                "        ",
            )
            send("replayApplyControl", ["env", cert_expr, ref_expr, proof_expr])
        elif call == "sccp_void_frozen":
            first, count = int(step["firstNonce"]), int(step["count"])
            if first >= 1 << 64 or count >= 1 << 16:
                raise TonBuilderError("a void_frozen row does not fit the TON message")
            lines.append(f"    val res{index} = replayVoidFrozen(env, {first}, {count});\n")
        else:
            raise TonBuilderError(f"scenario {scenario['name']} has the unknown call {call}")
        lines.append(f"    expectOutcome(res{index}, {_exit(codes, outcome)});\n")
        events = [_event_expr(event, certs, state) for event in expected["events"]]
        if outcome != "ok" and events:
            raise TonBuilderError("a refused call emits no event")
        lines.append(f"    expectEvents(res{index}, {_array('cell', events)});\n")
        lines += _state_lines(now_ms, state, with_checkpoints)
    lines.append("}\n\n")
    return "".join(lines)


def _render_rust_negative_certificates(finality: Any, codes: Dict[str, int], constants: Any) -> str:
    """The independently generated Rust transcript negatives, including their derived facts."""

    rows = finality["negative_certificates"]
    names = [f"const VEC_RUST_NEG_{_upper(row['label'])} = {index}\n" for index, row in enumerate(rows)]
    return "".join(
        [
            "/// Rows of `finality_rust_v1.json`, generated by the Rust reference.\n",
            f"const VEC_RUST_NEGATIVE_CERTIFICATE_COUNT = {len(rows)}\n",
            *names,
            "\n",
            _lookup(
                "vecRustNegativeCertificate", "VecCertificate",
                [(row["label"], _certificate_row(row, finality["committees"], codes, constants)) for row in rows],
                "Row `index` of the Rust-generated negative certificates.",
            ),
            _array_fun("vecRustNegativeMessages", "int", [_word(row["m"]) for row in rows], "Signed message `m` of each Rust negative."),
            _array_fun("vecRustNegativeCheckpointIds", "int", [_word(row["checkpoint_id"]) for row in rows], "Checkpoint id of each Rust negative."),
            _array_fun("vecRustNegativeHeights", "int", [_word(row["header_fields"]["height"]) for row in rows], "Header height of each Rust negative."),
        ]
    )


def _render_scenario_counts(scenarios: Sequence[Any]) -> str:
    """Counts of the generated replay groups and the steps of every replayed scenario."""

    lines = ["/// Replayed rows of `committee_transitions_v1.json` and their step counts.\n"]
    for flavor, selected in (
        ("TON", [row for row in scenarios if row.get("flavor") == "ton"]),
        ("REPLAYABLE", [row for row in scenarios if row.get("flavor") != "ton"]),
    ):
        lines += [
            f"const VEC_{flavor}_SCENARIO_COUNT = {len(selected)}\n",
            f"const VEC_{flavor}_SCENARIO_STEPS = {sum(len(row['steps']) for row in selected)}\n",
        ]
    lines += [f"const VEC_SCENARIO_{_upper(row['name'])}_STEPS = {len(row['steps'])}\n" for row in scenarios]
    return "".join(lines) + "\n"


def render_cert_vectors() -> str:
    """Tolk source of `sccp-cert-vectors.gen.tolk`: certificate rows and scenario replays."""

    finality = load_fixture("finality_v1.json")
    transitions = load_fixture("committee_transitions_v1.json")
    codes = exit_codes(transitions)
    context = finality["verification_context"]
    scenarios = [
        scenario for scenario in transitions["scenarios"]
        if scenario.get("flavor") == "ton" or scenario.get("ton_replayable")
    ]
    names = "".join(f"//   vecScenario{_camel(scenario['name'])}\n" for scenario in scenarios)
    controls = load_fixture("control_v1.json")
    control_scenarios = controls["ton_destination_effects"]
    if not control_scenarios or any(row.get("flavor") != "ton" for row in control_scenarios):
        raise TonBuilderError("control_v1.json must contain native TON destination effects")
    control_context = {
        "certificates": controls["ton_certificates"],
        "committees": controls["committees"],
        "constants": transitions["constants"],
    }
    control_counts = (
        f"const VEC_TON_CONTROL_SCENARIO_COUNT = {len(control_scenarios)}\n"
        f"const VEC_TON_CONTROL_SCENARIO_STEPS = {sum(len(row['steps']) for row in control_scenarios)}\n"
        + "".join(f"const VEC_SCENARIO_{_upper(row['name'])}_STEPS = {len(row['steps'])}\n" for row in control_scenarios)
    )
    return "".join(
        [
            CERT_VECTORS_HEADER,
            _render_certificates(finality, codes, transitions["constants"]),
            _render_rust_negative_certificates(load_fixture("finality_rust_v1.json"), codes, transitions["constants"]),
            _render_scenario_counts(scenarios),
            f"// Scenario replays ({len(scenarios)}):\n{names}\n",
            *[_scenario_function(scenario, transitions, codes, context) for scenario in scenarios],
            control_counts,
            *[_scenario_function(scenario, control_context, codes, context) for scenario in control_scenarios],
        ]
    ).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# Commands.


def render_boc_vectors() -> str:
    """Import actual Rust wallet BoCs, checking every graph independently in Python."""

    fixture = load_fixture("ton_boc_v1.json")
    context = fixture["context"]
    rows = fixture["rows"]
    negatives = fixture["snake_negatives"]
    for group in (rows, negatives):
        if len({row["label"] for row in group}) != len(group):
            raise TonBuilderError("duplicate TON BoC fixture label")
        for row in group:
            encoded = bytes.fromhex(row["boc"])
            cell = parse_boc(encoded)
            if (cell.hash.hex(), len(cell.bits), cell.depth) != (row["hash"], row["bits"], row["depth"]):
                raise TonBuilderError(f"TON BoC {row['label']} disagrees with its Python cell graph")
            if serialize_boc(cell) != encoded:
                raise TonBuilderError(f"TON BoC {row['label']} is not canonically serialized")
    kinds = {
        "TairaCert", "MessageProof", "ControlProof", "SccpInit", "SccpDeployBuckets",
        "SccpRetry", "SccpVoidFrozen", "SccpFinalize", "SccpFinalizeCheckpoint",
        "SccpVoidExpired", "SccpVoidExpiredCheckpoint", "SccpApplyControl",
        "SccpApplyControlCheckpoint", "SccpCheckpoint", "SccpBurnToTaira", "KeyChunk",
    }
    if any(row["kind"] not in kinds for row in rows):
        raise TonBuilderError("unknown TON BoC native type")
    out = [
        '// Generated by `python3 scripts/ton_sccp_builder.py vectors`; do not edit.\n',
        '// Rust wallet BoCs; Python independently checks graph hashes and canonical bags.\n',
        'import "@acton/fmt"\nimport "@contracts/sccp-cells"\n',
        'import "@contracts/sccp-messages"\nimport "sccp-test-vectors.gen"\n\n',
        f"const VEC_BOC_COUNT = {len(rows)}\n",
        f"const VEC_BOC_NEGATIVE_COUNT = {len(negatives)}\n",
    ]
    for key, value in context.items():
        literal = _word("0x" + value if isinstance(value, str) else value)
        out.append(f"const VEC_BOC_{_upper(key)} = {literal}\n")
    for index, row in enumerate(rows):
        out.append(f"const VEC_BOC_{_upper(row['label'])} = {index}\n")
    out.append("\n")
    out.append(_lookup("vecBocCell", "cell", [
        (row["label"], f'parseCellFromHex("{row["boc"]}")') for row in rows
    ], "The original cell graph produced by the Rust wallet encoder."))
    out.append(_lookup("vecBocReencoded", "cell", [
        (row["label"], "sccpBuildKeys(sccpLoadKeys(vecBocCell(index), 4).keys)" if row["kind"] == "KeyChunk"
         else f"{row['kind']}.fromCell(vecBocCell(index)).toCell() as cell") for row in rows
    ], "Independently parse and re-encode through each native Tolk type."))
    for name, field in (("Hashes", "hash"), ("Bits", "bits"), ("Depths", "depth")):
        out.append(_array_fun(f"vecBoc{name}", "int", [
            _word("0x" + row[field] if field == "hash" else row[field]) for row in rows
        ], f"The Rust graph's root {field} for every row."))
    out.append(_lookup("vecBocNegativeCell", "cell", [
        (row["label"], f'parseCellFromHex("{row["boc"]}")') for row in negatives
    ], "The Rust model's rejected canonical-bag burn snakes."))
    codes = exit_codes(load_fixture("committee_transitions_v1.json"))
    out.append(_array_fun("vecBocNegativeExits", "int", [
        str(_exit(codes, row["expected"])) for row in negatives
    ], "Burn admission exits independently returned by the Rust model."))
    return "".join(out).rstrip("\n") + "\n"


def generated_vectors() -> Dict[Path, str]:
    """The generated Tolk vector files with the contents the fixtures give them."""

    return {
        VECTORS_FILE: render_test_vectors(),
        CERT_VECTORS_FILE: render_cert_vectors(),
        BOC_VECTORS_FILE: render_boc_vectors(),
    }


def command_vectors(check: bool) -> None:
    for path, rendered in generated_vectors().items():
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
                raise TonBuilderError(f"{path.relative_to(ROOT)} is stale; run `vectors`")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    if check:
        print("test vectors are current")


def format_targets() -> List[str]:
    """SCCP-owned Tolk sources (the retired files are excluded)."""

    targets = [path for path in SOURCE_FILES if (PROJECT / path).is_file()]
    targets += sorted(str(p.relative_to(PROJECT)) for p in UNIT_TESTS.glob("*.tolk") if not p.name.endswith(".gen.tolk"))
    return targets


def command_fmt(acton: Path, write: bool) -> None:
    targets = format_targets()
    run_acton(acton, ["fmt", *targets] if write else ["fmt", "--check", *targets])
    print("Tolk formatting is canonical" if not write else "formatted Tolk sources")


def command_build(acton: Path) -> Dict[str, Tuple[str, int]]:
    run_acton(acton, ["build"])
    check_tolk_stdlib()
    result = {}
    for name in CONTRACTS:
        code = load_compiled_code(name)
        cells, bits = cell_tree_size(code)
        result[name] = (code.hash.hex(), code.depth)
        print(f"{name}: code hash {code.hash.hex()} depth {code.depth} cells {cells} bits {bits}")
    return result


def _copy_project(destination: Path) -> None:
    for relative in ("Acton.toml", "contracts", "wrappers", "tests", "scripts"):
        source = PROJECT / relative
        if source.is_dir():
            shutil.copytree(source, destination / relative)
        elif source.is_file():
            shutil.copy2(source, destination / relative)


def command_wrappers(acton: Path, write: bool) -> None:
    if write:
        run_acton(acton, ["wrapper", "--all"])
        print("regenerated wrappers")
        return
    with tempfile.TemporaryDirectory(prefix="sccp-ton-wrappers-") as scratch:
        copy = Path(scratch) / "project"
        copy.mkdir()
        _copy_project(copy)
        run_acton(acton, ["wrapper", "--all"], cwd=copy)
        for relative in WRAPPER_FILES:
            if (copy / relative).read_bytes() != (PROJECT / relative).read_bytes():
                raise TonBuilderError(f"{relative} is stale; run `wrappers --write`")
    print("wrappers are current")


GAS_LINE = re.compile(r"^\s*gas (?P<label>.+): (?P<used>\d+) \(limit (?P<limit>\d+)\)\s*$")


def parse_gas_lines(output: str) -> Dict[str, Dict[str, int]]:
    """Measured steps of a test run: label → `{"gas", "limit"}`.

    A suite reports a measured step with one output line `gas <label>: <used>
    (limit <limit>)`, where the limit is the gas constant the contracts price
    that step with. A label measured more than once keeps its largest value;
    one label with two limits is an error.
    """

    rows: Dict[str, Dict[str, int]] = {}
    for line in output.splitlines():
        match = GAS_LINE.match(line)
        if match is None:
            continue
        label, used, limit = match["label"], int(match["used"]), int(match["limit"])
        previous = rows.get(label)
        if previous is not None and previous["limit"] != limit:
            raise TonBuilderError(f"gas label {label!r} is reported with two limits")
        if previous is None or used > previous["gas"]:
            rows[label] = {"gas": used, "limit": limit}
    return rows


def render_gas_report(rows: Dict[str, Dict[str, int]]) -> str:
    """Canonical JSON text of a gas report (`gas-current.json`, `gas-baseline.json`)."""

    return json.dumps({"schema": GAS_SCHEMA, "rows": rows}, indent=2, sort_keys=True) + "\n"


def load_gas_report(path: Path) -> Dict[str, Dict[str, int]]:
    """Reads a gas report and checks its layout."""

    record = json.loads(path.read_text(encoding="utf-8"))
    rows = record.get("rows") if isinstance(record, dict) else None
    if not isinstance(record, dict) or record.get("schema") != GAS_SCHEMA or not isinstance(rows, dict):
        raise TonBuilderError(f"{path.name} is not a {GAS_SCHEMA} report")
    for label, row in rows.items():
        if (
            not isinstance(row, dict) or set(row) != {"gas", "limit"}
            or not all(isinstance(row[key], int) and not isinstance(row[key], bool) and row[key] >= 0 for key in row)
        ):
            raise TonBuilderError(f"{path.name}: malformed row {label!r}")
    return rows


def compare_gas(
    current: Dict[str, Dict[str, int]], baseline: Dict[str, Dict[str, int]], complete: bool
) -> List[str]:
    """Gas failures of a run against the recorded baseline (§5.4), as messages.

    A step fails when it uses more than its own gas limit, when it uses more
    than 1.1 x its baseline row, or when the baseline has no row for it. A
    `complete` run (the whole suite) also fails for a baseline row that was
    not measured, so a measurement cannot disappear unnoticed.
    """

    problems = []
    for label in sorted(current):
        row = current[label]
        if row["gas"] > row["limit"]:
            problems.append(f"{label}: {row['gas']} gas exceeds the step limit {row['limit']}")
        if label not in baseline:
            problems.append(f"{label}: no baseline row")
            continue
        base = baseline[label]["gas"]
        if row["gas"] * GAS_TOLERANCE_DENOMINATOR > base * GAS_TOLERANCE_NUMERATOR:
            problems.append(f"{label}: {row['gas']} gas is above 1.1 x the baseline {base}")
    if complete:
        problems += [f"{label}: baseline row was not measured" for label in sorted(set(baseline) - set(current))]
    return problems


def record_gas(output: str, complete: bool) -> Dict[str, Dict[str, int]]:
    """Writes `gas-current.json` from a test run and applies the baseline comparison."""

    rows = parse_gas_lines(output)
    GAS_CURRENT_FILE.write_text(render_gas_report(rows), encoding="utf-8")
    print(f"wrote {GAS_CURRENT_FILE.name} ({len(rows)} measured steps)")
    if not GAS_BASELINE_FILE.is_file():
        raise TonBuilderError(f"required gas baseline is missing: {GAS_BASELINE_FILE}")
    problems = compare_gas(rows, load_gas_report(GAS_BASELINE_FILE), complete)
    if problems:
        raise TonBuilderError("gas check failed:\n" + "\n".join(problems))
    print(f"gas is within 1.1 x {GAS_BASELINE_FILE.name}")
    return rows


def check_forgery_evidence_ids() -> int:
    """Check source evidence ids against the exact certificate tuples replayed in Tolk.

    TON has SHA-256 and Keccak but no BLAKE2b-256 opcode. The launcher checks
    that source-only hash boundary using the independent Python reference;
    Tolk verifies R, m and the native CommitQC on those same row bytes. This
    does not confer Parliament authority or implement Core's evidence rules
    at a destination.
    """

    from sccp_reference.finality import commit_preimage, forgery_evidence_id, parse_header, parse_qc_fixed, result_r

    fixture = load_fixture("forgery_evidence_v1.json")
    constants = fixture["constants"]
    decode = lambda value: bytes.fromhex(_hex_body(value))  # noqa: E731
    labels = set()
    messages = {}
    for row in fixture["rows"]:
        label = row["label"]
        if label in labels:
            raise TonBuilderError("duplicate forgery evidence label")
        labels.add(label)
        inputs, expected = row["input"], row["expected"]
        raw = decode(inputs["header"])
        header, qc = parse_header(raw), parse_qc_fixed(decode(inputs["qc"]))
        result = result_r(raw, qc.result_body)
        message = hashlib.sha256(commit_preimage(decode(constants["consensus_instance"]), qc.epoch,
                                                 qc.epoch_context, header.height, qc.view, qc.block_hash, result)).digest()
        evidence = forgery_evidence_id(header.generation, message, qc.signers)
        for name, value in (("result", result), ("message", message), ("evidence_id", evidence)):
            if value != decode(expected[name]):
                raise TonBuilderError(f"forgery evidence {label}: {name} differs from the certificate bytes")
        messages[label] = message
    for row in fixture["deduplication"]:
        inputs = row["input"]
        evidence = forgery_evidence_id(inputs["generation"], messages["e2_future"], inputs["signers"])
        if evidence != decode(row["expected"]["evidence_id"]):
            raise TonBuilderError(f"forgery evidence {row['label']}: deduplication evidence_id differs")
    count = len(fixture["rows"]) + len(fixture["deduplication"])
    if count != 22:
        raise TonBuilderError(f"forgery evidence id coverage changed: expected 22, got {count}")
    return count


def command_test(acton: Path, extra: Sequence[str]) -> str:
    count = check_forgery_evidence_ids()
    print(f"forgery evidence ids: {count} source hashes match the exact certificate rows replayed by TON")
    output = run_acton(acton, ["test", "tests/unit", *extra])
    print("\n".join(line for line in output.splitlines() if line.strip()))
    # extra arguments select a part of the suite, so only a plain run is complete
    record_gas(output, complete=not extra)
    return output


def command_all(acton: Path) -> None:
    command_vectors(check=True)
    command_fmt(acton, write=False)
    command_build(acton)
    command_wrappers(acton, write=False)
    command_test(acton, [])
    sys.path.insert(0, str(ROOT / "scripts"))
    import generate_ton_sccp_stateinit_golden as golden  # noqa: E402

    golden.run(acton, check=True, build=False)
    print("SCCP TON contracts: build, wrappers, tests and StateInit golden all pass")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--acton", help="absolute Acton executable reporting exactly " + ACTON_REPORTED_VERSION)
    parser.add_argument("--offline", action="store_true", help="never download the pinned Acton archive")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("toolchain", help="resolve and print the pinned Acton executable")
    vectors = sub.add_parser("vectors", help="regenerate the Tolk test vectors")
    vectors.add_argument("--check", action="store_true")
    fmt = sub.add_parser("fmt", help="check (or --write) Tolk formatting")
    fmt.add_argument("--write", action="store_true")
    sub.add_parser("build", help="compile the contracts")
    wrappers = sub.add_parser("wrappers", help="check (or --write) generated wrappers")
    wrappers.add_argument("--write", action="store_true")
    sub.add_parser("test", help="run the Acton emulator suite (extra arguments go to `acton test`)")
    sub.add_parser("all", help="run every check (default)")
    return parser


def main(arguments: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""

    parser = _parser()
    parsed, extra = parser.parse_known_args(arguments)
    command = parsed.command or "all"
    if extra and command != "test":
        parser.error(f"unrecognized arguments for {command}")
    try:
        if command == "vectors":
            command_vectors(parsed.check)
            return 0
        acton = resolve_acton(parsed.acton, parsed.offline)
        if command == "toolchain":
            print(acton)
        elif command == "fmt":
            command_fmt(acton, parsed.write)
        elif command == "build":
            command_build(acton)
        elif command == "wrappers":
            command_wrappers(acton, parsed.write)
        elif command == "test":
            command_test(acton, extra)
        else:
            command_all(acton)
        return 0
    except TonBuilderError as error:
        print(f"TON SCCP builder failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
