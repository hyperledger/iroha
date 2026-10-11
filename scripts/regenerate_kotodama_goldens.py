#!/usr/bin/env python3
"""Build, validate, and publish the canonical Kotodama V1 goldens.

Prerequisites are freshly built ``koto`` and ``ivm_artifact_admit`` binaries. The script
never invokes Cargo or accepts signing material. Tool children create private files;
compiler staging stays mode 0600 and reviewed public outputs publish as 0644.
Scratch files are confined to
the selected staging root. ``--write`` requires an absent absolute output root
below the checkout's ignored ``target`` directory or outside the workspace.
Both locations use the same create-only sealed publication implementation.
The checked-in ``ivm_artifacts.tsv`` file is the authoritative ownership and
source-to-artifact map for every IVM program in the repository. Compiler staging
outputs retain the native writer's mode 0600; reviewed public renderings use
mode 0644. Independent admission manifests use 0600 and must match compiler
bytes exactly. This does not change checked-tree or publication modes.

``--check`` is the safe default: compile everything in two independent
temporary staging trees and fail unless their canonical path sets, bytes, and
modes are identical to each other and to the selected checked tree. ``--write``
uses the same two-pass proof before publishing the absent
``--output-root``. Its exact directory/file inventory is descriptor-bound and
the owner manifest is written last as the mandatory completion seal. Failed
publication runs leave unsealed, create-only residue. Checked-in outputs are
refreshed only by a reviewed identity-relative patch from a sealed tree and are
then verified with ``--check``. The signed prediction-market deployment
manifest is intentionally untracked and outside this workflow because private
signing input must remain runtime-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence


MAX_CYCLES = 1_000_000
HEADER_SIZE = 49
ZK_MODE_BIT = 0x01
VECTOR_MODE_BIT = 0x02
KNOWN_CONTRACT_MODE_BITS = ZK_MODE_BIT | VECTOR_MODE_BIT
MAP_PATH = Path("scripts/ivm_artifacts.tsv")
ATTRIBUTES_PATH = Path(".gitattributes")
TEST_SOURCE = Path("crates/ivm/docs/examples/19_contract_flow_test.test.ko")
FILTERED_TEST_FRAGMENT = "actor_helpers"
EXACT_TEST_NAME = "actor_helpers_roundtrip"
OWNER_MANIFEST_SCHEMA = "iroha.kotodama.generated-owner.v1"
PUBLICATION_MANIFEST_PATH = Path(".kotodama-v1-owner-manifest.json")
# `ADDI r0, r0, 0` is reserved by the Kotodama assembler as its one-word
# relocation placeholder. A deployable image may contain it only when it was
# deliberately emitted as a semantic no-op; V1 keeps such words below 1%.
RELOCATION_NOP_WORD = 0x2000_0000
MAX_RELOCATION_PADDING_PERCENT = 1
LITERAL_CRC16_POLYNOMIAL = 0x1021
LITERAL_CRC16_INITIAL = 0xFFFF
EXTRA_ZK_SOURCES = frozenset(
    {
        Path("tools/kotodama_linguist/samples/zk_bridge.ko"),
    }
)
COMPILER_MANIFESTS = {
    Path("crates/iroha/tests/fixtures/contract_code_readback/code_readback.ko"): Path(
        "crates/iroha/tests/fixtures/contract_code_readback/code_readback.manifest.json"
    ),
    Path("demo/authority_probe.ko"): Path("demo/authority_probe.manifest.json"),
    Path("crates/kotodama_lang/src/samples/irohaswap.ko"): Path(
        "demo/irohaswap.manifest.json"
    ),
    Path("demo/ivm_smoke.ko"): Path("demo/ivm_smoke.manifest.json"),
    Path("demo/prediction_market.ko"): Path(
        "demo/prediction_market.manifest.json"
    ),
}
FORBIDDEN_LEGACY_OUTPUTS = (
    Path("crates/iroha/tests/fixtures/contract_code_readback/provenance.json"),
    Path("crates/ivm/docs/examples/01_init.to"),
    Path("crates/ivm/docs/examples/02_entry_fn.to"),
    Path("crates/ivm/docs/examples/03_upgrade.to"),
    Path("crates/ivm/docs/examples/16_dynamic_take.to"),
    Path("crates/ivm/docs/examples/17_dynamic_range.to"),
    Path("crates/ivm/tests/data/dai.to"),
    Path("crates/kotodama_lang/src/samples/kotodama_jp.to"),
    Path("crates/kotodama_lang/src/samples/trigger_cat_and_mouse.to"),
    Path("integration_tests/fixtures/ivm/trigger_cat_and_mouse.to"),
)


class GoldenError(RuntimeError):
    """Raised when source inventory, compilation, or artifact validation fails."""


@dataclass(frozen=True)
class Golden:
    """One canonical source, execution mode, and checked-in destination."""

    mode: str
    source: Path
    destination: Path


@dataclass(frozen=True)
class ArtifactCodeMetrics:
    """Executable-region measurements used by the V1 size gate."""

    code_offset: int
    code_bytes: int
    instruction_words: int
    relocation_nop_words: int


@dataclass(frozen=True)
class RenderedFile:
    """One canonical generated destination, mode, and byte payload."""

    relative_path: Path
    mode: int
    payload: bytes


@dataclass(frozen=True)
class RenderedDirectory:
    """One canonical generated directory and its publication mode."""

    relative_path: Path
    mode: int = 0o755


@dataclass(frozen=True)
class FileSeal:
    """Stable identity and content digest for one generation input."""

    path: Path
    device: int
    inode: int
    mode: int
    uid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


def repository_root() -> Path:
    """Return the repository root containing this script's parent directory."""

    return Path(__file__).resolve().parents[1]


def _safe_relative(raw: str, suffix: str, context: str) -> Path:
    if (
        not raw
        or "\\" in raw
        or "\x00" in raw
        or raw != unicodedata.normalize("NFC", raw)
    ):
        raise GoldenError(f"invalid {context} path {raw!r}")
    path = Path(raw)
    if (
        path.is_absolute()
        or not path.parts
        or "." in path.parts
        or ".." in path.parts
        or path.suffix != suffix
        or path.as_posix() != raw
    ):
        raise GoldenError(f"invalid {context} path {raw!r}")
    return path


def _logical_path_identity(path: Path) -> str:
    """Return the platform-independent logical identity for a relative path."""

    return unicodedata.normalize("NFC", path.as_posix()).casefold()


def read_map(path: Path) -> list[Golden]:
    """Read and strictly validate the canonical TSV artifact map."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise GoldenError(f"failed to read golden map {path}: {error}") from error
    if not lines:
        raise GoldenError(f"golden map {path} is empty")

    rows: list[Golden] = []
    destinations: set[Path] = set()
    destination_identities: set[str] = set()
    source_modes: dict[Path, str] = {}
    source_identities: dict[str, Path] = {}
    for number, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise GoldenError(f"invalid golden map row {number}: {line!r}")
        if fields[0] in {"predecoder", "synthetic", "default"}:
            continue
        if fields[0] not in {"kotodama-standard", "kotodama-zk"}:
            raise GoldenError(f"invalid golden map row {number}: {line!r}")
        mode = fields[0].removeprefix("kotodama-")
        source = _safe_relative(fields[1], ".ko", f"row {number} source")
        destination = _safe_relative(fields[2], ".to", f"row {number} output")
        source_identity = _logical_path_identity(source)
        previous_source = source_identities.setdefault(source_identity, source)
        if previous_source != source:
            raise GoldenError(
                f"duplicate logical source identity: {previous_source} and {source}"
            )
        previous_mode = source_modes.setdefault(source, mode)
        if previous_mode != mode:
            raise GoldenError(f"source {source} has conflicting execution modes")
        if destination in destinations:
            raise GoldenError(f"duplicate golden destination {destination}")
        destination_identity = _logical_path_identity(destination)
        if destination_identity in destination_identities:
            raise GoldenError(
                f"duplicate logical golden destination {destination}"
            )
        destinations.add(destination)
        destination_identities.add(destination_identity)
        rows.append(Golden(mode, source, destination))
    if not rows:
        raise GoldenError(f"golden map {path} contains no Kotodama artifacts")
    return rows


def tracked_sources(root: Path) -> list[Path]:
    """Return every present versioned or newly added Kotodama source."""

    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.ko",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GoldenError(f"failed to inventory tracked Kotodama sources: {message}")
    candidates = [
        _safe_relative(raw.decode("utf-8"), ".ko", "source inventory")
        for raw in result.stdout.split(b"\0")
        if raw
    ]
    sources = [source for source in candidates if (root / source).is_file()]
    if not sources:
        raise GoldenError("repository contains no tracked Kotodama sources")
    return sorted(sources)


def partition_source_policy(
    root: Path,
    sources: Sequence[Path],
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    """Split canonical sources into checked code and byte-exact fixtures.

    ``.gitattributes`` is the repository-owned policy boundary: only an exact
    ``whitespace: unset`` result excludes an extracted fixture from formatter
    and standalone compiler checks. Every ordinary source must report the
    exact Git sentinel ``unspecified``. Any other value or malformed framing
    fails closed instead of silently widening either set.
    """

    command = [
        "git",
        "-C",
        str(root),
        "check-attr",
        "-z",
        "whitespace",
        "--",
        *(source.as_posix() for source in sources),
    ]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GoldenError(f"failed to classify Kotodama source policy: {message}")
    fields = result.stdout.split(b"\0")
    if not fields or fields[-1] != b"":
        raise GoldenError("malformed git check-attr framing for Kotodama sources")
    fields.pop()
    if len(fields) != len(sources) * 3:
        raise GoldenError("malformed git check-attr record count for Kotodama sources")

    checked: list[Path] = []
    byte_exact: list[Path] = []
    for index, expected in enumerate(sources):
        raw_path, raw_attribute, raw_value = fields[index * 3 : index * 3 + 3]
        try:
            path = raw_path.decode("utf-8")
            attribute = raw_attribute.decode("utf-8")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GoldenError(
                "malformed non-UTF-8 git check-attr output for Kotodama sources"
            ) from error
        if path != expected.as_posix() or attribute != "whitespace":
            raise GoldenError("malformed git check-attr identity for Kotodama sources")
        if value == "unspecified":
            checked.append(expected)
        elif value == "unset":
            byte_exact.append(expected)
        else:
            raise GoldenError(
                f"unsupported whitespace attribute for Kotodama source {expected}: "
                f"{value!r}"
            )
    return tuple(checked), tuple(byte_exact)


def tracked_outputs(root: Path) -> list[Path]:
    """Return every present versioned ``.to`` file, including staged additions."""

    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--",
            "*.to",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GoldenError(f"failed to inventory tracked .to outputs: {message}")
    candidates = [
        _safe_relative(raw.decode("utf-8"), ".to", "output inventory")
        for raw in result.stdout.split(b"\0")
        if raw
    ]
    return sorted(output for output in candidates if (root / output).is_file())


def compiler_owned_outputs(
    sources: Sequence[Path], outputs: Sequence[Path]
) -> list[Path]:
    """Select tracked ``.to`` files owned by the Kotodama compiler.

    Kotodama's primary outputs and copied aliases preserve the source filename
    stem. Therefore a tracked ``.to`` belongs to this workflow exactly when its
    stem matches a present ``.ko`` source stem. Other uses of the ``.to`` suffix
    (notably canonical Norito payloads and hand-authored IVM data fixtures) have
    no corresponding ``.ko`` stem and are deliberately outside this inventory.
    """

    source_stems = {source.stem for source in sources}
    return sorted(output for output in outputs if output.stem in source_stems)


def validate_output_inventory(
    rows: Sequence[Golden], sources: Sequence[Path], outputs: Sequence[Path]
) -> None:
    """Require every compiler-owned tracked artifact to have an explicit row."""

    mapped = {row.destination: row for row in rows}
    source_set = set(sources)
    owned = compiler_owned_outputs(sources, outputs)
    unmapped = [output for output in owned if output not in mapped]
    if unmapped:
        raise GoldenError(
            "compiler-owned tracked .to artifacts are missing explicit golden "
            "map rows: " + ", ".join(path.as_posix() for path in unmapped)
        )
    invalid = [
        output
        for output in owned
        if mapped[output].source not in source_set
        or mapped[output].source.stem != output.stem
    ]
    if invalid:
        raise GoldenError(
            "compiler-owned tracked .to artifacts have invalid source mappings: "
            + ", ".join(path.as_posix() for path in invalid)
        )


def unique_builds(rows: Sequence[Golden]) -> list[Golden]:
    """Deduplicate alias outputs and reject ambiguous staged file stems."""

    by_source: dict[Path, Golden] = {}
    by_stem: dict[str, Path] = {}
    for row in rows:
        by_source.setdefault(row.source, row)
        previous = by_stem.setdefault(row.source.stem, row.source)
        if previous != row.source:
            raise GoldenError(
                f"staged stem collision: {previous} and {row.source} both use "
                f"{row.source.stem!r}"
            )
    return sorted(by_source.values(), key=lambda row: row.source.as_posix())


def run(
    command: Sequence[os.PathLike[str] | str], root: Path, *, input: str | None = None
) -> str:
    """Run a tool with private child outputs without changing the parent umask."""

    rendered = [os.fspath(part) for part in command]
    result = subprocess.run(
        rendered,
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        umask=0o077,
        input=input,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise GoldenError(f"command failed ({' '.join(rendered)}):\n{details}")
    return result.stdout


def _read_sealed_regular(
    path: Path, context: str, *, maximum: int | None = None
) -> tuple[bytes, os.stat_result]:
    """Read one single-link regular file without following a symbolic link."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise GoldenError("sealed generation requires O_NOFOLLOW support")
    flags |= no_follow
    try:
        named_before = path.lstat()
        if not stat.S_ISREG(named_before.st_mode):
            raise GoldenError(f"{context} must be a regular non-symlink file: {path}")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise GoldenError(f"failed to open {context} {path}: {error}") from error
    try:
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(named_before.st_mode)
            or not stat.S_ISREG(opened_before.st_mode)
            or _metadata_identity(named_before)[:3]
            != _metadata_identity(opened_before)[:3]
            or opened_before.st_nlink != 1
            or opened_before.st_size < 0
        ):
            raise GoldenError(
                f"{context} must be one regular non-symlink file with one hard link: {path}"
            )
        if maximum is not None and opened_before.st_size > maximum:
            raise GoldenError(f"{context} exceeds its expected size: {path}")
        chunks: list[bytes] = []
        remaining = opened_before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise GoldenError(f"{context} was truncated while reading: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise GoldenError(f"{context} grew while reading: {path}")
        opened_after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            _metadata_identity(opened_before) != _metadata_identity(opened_after)
            or _metadata_identity(opened_after) != _metadata_identity(named_after)
        ):
            raise GoldenError(f"{context} identity changed while reading: {path}")
        return b"".join(chunks), opened_after
    finally:
        os.close(descriptor)


def seal_file(path: Path, context: str) -> FileSeal:
    """Return a stable identity and SHA-256 seal for one generation input."""

    payload, metadata = _read_sealed_regular(path, context)
    return FileSeal(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        links=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def generation_input_seals(
    root: Path,
    sources: Sequence[Path],
    koto: Path,
    admission_tool: Path,
) -> tuple[FileSeal, ...]:
    """Seal the exact source, map, owner, and executable inputs to generation."""

    inputs = [
        root / ATTRIBUTES_PATH,
        root / MAP_PATH,
        Path(__file__).resolve(strict=True),
        *(root / source for source in sources),
        koto,
        admission_tool,
    ]
    if len(inputs) != len(set(inputs)):
        raise GoldenError("generation input inventory contains duplicate paths")
    seals = tuple(
        seal_file(path, "generation input")
        for path in sorted(inputs, key=lambda value: os.fspath(value))
    )
    inode_identities = [(seal.device, seal.inode) for seal in seals]
    if len(inode_identities) != len(set(inode_identities)):
        raise GoldenError("generation inputs contain duplicate filesystem identities")
    return seals


def validate_noop_build_output(output: str, expected_fresh: int) -> None:
    """Require one unambiguous `fresh` notice for every requested source."""

    notices = [line.strip() for line in output.splitlines() if line.strip()]
    if len(notices) != expected_fresh or any(
        not notice.startswith("fresh ") or len(notice) == len("fresh ")
        for notice in notices
    ):
        raise GoldenError("no-op Kotodama graph performed compilation")


def literal_checksum(tag: str, body: str) -> str:
    """Return Norito's canonical four-hex-digit literal checksum."""

    checksum = LITERAL_CRC16_INITIAL
    for byte in f"{tag}:{body}".encode("ascii"):
        checksum ^= byte << 8
        for _ in range(8):
            checksum = (
                ((checksum << 1) ^ LITERAL_CRC16_POLYNOMIAL) & 0xFFFF
                if checksum & 0x8000
                else (checksum << 1) & 0xFFFF
            )
    return f"{checksum:04X}"


def manifest_abi_hash(path: Path) -> bytes:
    """Return the exact 32-byte ABI digest declared by a compiler manifest."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GoldenError(f"failed to read compiler manifest {path}: {error}") from error
    value = document.get("abi_hash") if isinstance(document, dict) else None
    if not isinstance(value, str) or not value.startswith("hash:"):
        raise GoldenError(f"{path} does not declare a canonical ABI hash")
    digest, separator, checksum = value[5:].partition("#")
    if (
        not separator
        or len(digest) != 64
        or len(checksum) != 4
        or any(character not in "0123456789ABCDEF" for character in digest + checksum)
    ):
        raise GoldenError(f"{path} contains a malformed ABI hash")
    if checksum != literal_checksum("hash", digest):
        raise GoldenError(f"{path} contains a noncanonical ABI hash checksum")
    return bytes.fromhex(digest)


def validate_artifact(path: Path, mode: str, expected_abi_hash: bytes) -> None:
    """Fail closed on a non-canonical V1 header or embedded debug section."""

    try:
        artifact = path.read_bytes()
    except OSError as error:
        raise GoldenError(f"failed to read staged artifact {path}: {error}") from error
    if len(artifact) < HEADER_SIZE + 8 or artifact[:4] != b"IVM\0":
        raise GoldenError(f"{path} is not an IVM artifact")
    if artifact[4:6] != b"\x01\x01":
        raise GoldenError(f"{path} does not use canonical IVM 1.1")
    if artifact[16] != 1:
        raise GoldenError(f"{path} does not use ABI v1")
    if len(expected_abi_hash) != 32 or artifact[17:HEADER_SIZE] != expected_abi_hash:
        raise GoldenError(f"{path} does not authenticate the compiler ABI hash")
    if struct.unpack_from("<Q", artifact, 8)[0] != MAX_CYCLES:
        raise GoldenError(f"{path} does not embed the {MAX_CYCLES}-cycle ceiling")
    header_mode = artifact[6]
    if header_mode & ~KNOWN_CONTRACT_MODE_BITS:
        raise GoldenError(f"{path} contains unknown execution-mode bits")
    if artifact[7] != 0:
        raise GoldenError(f"{path} contains a noncanonical vector-length override")
    is_zk = bool(header_mode & ZK_MODE_BIT)
    if is_zk != (mode == "zk"):
        raise GoldenError(f"{path} has the wrong ZK execution bit for mode {mode}")
    if artifact[HEADER_SIZE : HEADER_SIZE + 4] != b"CNTR":
        raise GoldenError(f"{path} is missing the required CNTR interface")
    interface_length = struct.unpack_from("<I", artifact, HEADER_SIZE + 4)[0]
    after_interface = HEADER_SIZE + 8 + interface_length
    if after_interface > len(artifact):
        raise GoldenError(f"{path} contains a truncated CNTR interface")
    if artifact[after_interface : after_interface + 4] == b"DBG1":
        raise GoldenError(f"{path} embeds forbidden debug metadata")


def artifact_code_metrics(path: Path) -> ArtifactCodeMetrics:
    """Locate and measure a canonical compiler-generated instruction region."""

    try:
        artifact = path.read_bytes()
    except OSError as error:
        raise GoldenError(f"failed to read staged artifact {path}: {error}") from error
    if len(artifact) < HEADER_SIZE + 8 or artifact[:4] != b"IVM\0":
        raise GoldenError(f"{path} is not an IVM artifact")

    offset = HEADER_SIZE
    if artifact[offset : offset + 4] != b"CNTR":
        raise GoldenError(f"{path} is missing the required CNTR interface")
    interface_length = struct.unpack_from("<I", artifact, offset + 4)[0]
    offset += 8 + interface_length
    if offset > len(artifact):
        raise GoldenError(f"{path} contains a truncated CNTR interface")
    if artifact[offset : offset + 4] == b"DBG1":
        raise GoldenError(f"{path} embeds forbidden debug metadata")

    if artifact[offset : offset + 4] == b"LTLB":
        if offset + 16 > len(artifact):
            raise GoldenError(f"{path} contains a truncated literal-table header")
        literal_count, alignment_padding, data_length = struct.unpack_from(
            "<III", artifact, offset + 4
        )
        if literal_count > 65_536 or alignment_padding > 3:
            raise GoldenError(f"{path} contains invalid literal-table dimensions")
        offset += 16 + literal_count * 8 + data_length + alignment_padding
        if offset > len(artifact):
            raise GoldenError(f"{path} contains a truncated literal table")

    code_bytes = len(artifact) - offset
    if code_bytes == 0 or code_bytes % 4 != 0:
        raise GoldenError(
            f"{path} executable region must be non-empty and word aligned, "
            f"got {code_bytes} bytes"
        )
    words = struct.iter_unpack("<I", artifact[offset:])
    relocation_nops = sum(word == RELOCATION_NOP_WORD for (word,) in words)
    return ArtifactCodeMetrics(
        code_offset=offset,
        code_bytes=code_bytes,
        instruction_words=code_bytes // 4,
        relocation_nop_words=relocation_nops,
    )


def validate_performance(
    stage: Path,
    builds: Sequence[Golden],
) -> None:
    """Enforce the deterministic relocation-padding acceptance gate."""

    for build in builds:
        artifact = stage / "release" / f"{build.source.stem}.to"
        metrics = artifact_code_metrics(artifact)
        # Strictly below 1%, expressed with integer arithmetic so boundary
        # behavior is deterministic on every host.
        if (
            metrics.relocation_nop_words * 100
            >= metrics.instruction_words * MAX_RELOCATION_PADDING_PERCENT
        ):
            raise GoldenError(
                f"{build.source} retains {metrics.relocation_nop_words}/"
                f"{metrics.instruction_words} relocation NOP words; V1 requires "
                "strictly less than 1%"
            )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return fields that must remain stable across a guarded publication."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def compare_payload(expected: bytes, destination: Path, expected_mode: int = 0o644) -> None:
    """Require one sealed destination to match canonical bytes and mode."""

    actual, metadata = _read_sealed_regular(destination, "generated destination")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise GoldenError(
            f"generated destination mode differs: {destination} "
            f"(expected {expected_mode:04o}, got {stat.S_IMODE(metadata.st_mode):04o})"
        )
    if actual != expected:
        raise GoldenError(f"stale Kotodama generated output: {destination}")


def read_compiler_output(source: Path) -> bytes:
    """Authenticate the native compiler's private staging output without chmod."""

    payload, metadata = _read_sealed_regular(source, "staged compiler output")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GoldenError(f"staged compiler output must use mode 0600: {source}")
    return payload


def compare_runtime_manifest(source: Path, destination: Path) -> None:
    """Compare private compiler bytes with an independently produced admission manifest."""

    expected = read_compiler_output(source)
    actual, metadata = _read_sealed_regular(
        destination, "runtime manifest", maximum=len(expected)
    )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GoldenError(f"runtime manifest must use mode 0600: {destination}")
    if actual != expected:
        raise GoldenError(f"runtime manifest differs from compiler output: {destination}")


def rendered_files(stage: Path, rows: Sequence[Golden]) -> tuple[RenderedFile, ...]:
    """Read private compiler outputs and declare their explicit public fixture modes."""

    sources: dict[Path, Path] = {}
    for row in rows:
        sources[row.destination] = stage / "release" / f"{row.source.stem}.to"
    for source, destination in COMPILER_MANIFESTS.items():
        if destination in sources:
            raise GoldenError(f"duplicate generated destination {destination}")
        sources[destination] = stage / "release" / f"{source.stem}.manifest.json"

    logical_identities = [_logical_path_identity(path) for path in sources]
    if len(logical_identities) != len(set(logical_identities)):
        raise GoldenError("generated destinations contain duplicate logical identities")

    rendered: list[RenderedFile] = []
    for destination in sorted(sources, key=lambda value: value.as_posix()):
        payload = read_compiler_output(sources[destination])
        # Compiler and admission work products stay owner-private. This owner explicitly
        # publishes public checked-in fixtures; the descriptor-bound publisher creates
        # separate files in the declared public mode without relaxing staging custody.
        rendered.append(RenderedFile(destination, 0o644, payload))
    return tuple(rendered)


def rendered_directories(
    rendered: Sequence[RenderedFile],
) -> tuple[RenderedDirectory, ...]:
    """Derive the complete sorted directory inventory for one rendering."""

    paths: set[Path] = set()
    file_paths = {output.relative_path for output in rendered}
    for output in rendered:
        parent = output.relative_path.parent
        while parent != Path("."):
            if parent in file_paths:
                raise GoldenError(
                    f"generated path is both a file and a directory: {parent}"
                )
            paths.add(parent)
            parent = parent.parent

    ordered = sorted(paths, key=lambda value: value.as_posix())
    identities = [_logical_path_identity(path) for path in (*ordered, *file_paths)]
    if len(identities) != len(set(identities)):
        raise GoldenError(
            "generated file and directory paths contain duplicate logical identities"
        )
    return tuple(RenderedDirectory(path) for path in ordered)


def owner_manifest(rendered: Sequence[RenderedFile]) -> bytes:
    """Render the deterministic owner manifest used for two-pass comparison."""

    document = {
        "schema": OWNER_MANIFEST_SCHEMA,
        "root_mode": "0700",
        "directories": [
            {
                "path": directory.relative_path.as_posix(),
                "mode": f"{directory.mode:04o}",
            }
            for directory in rendered_directories(rendered)
        ],
        "files": [
            {
                "path": output.relative_path.as_posix(),
                "mode": f"{output.mode:04o}",
                "size": len(output.payload),
                "sha256": hashlib.sha256(output.payload).hexdigest(),
            }
            for output in rendered
        ],
    }
    return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def compare_renderings(
    first: Sequence[RenderedFile], second: Sequence[RenderedFile]
) -> None:
    """Require two independent renders and manifests to be byte-for-byte equal."""

    first_paths = tuple(output.relative_path for output in first)
    second_paths = tuple(output.relative_path for output in second)
    if first_paths != second_paths:
        raise GoldenError("independent Kotodama renders have different path sets")
    for left, right in zip(first, second):
        if left.mode != right.mode:
            raise GoldenError(
                f"independent Kotodama renders differ in mode: {left.relative_path}"
            )
        if left.payload != right.payload:
            raise GoldenError(
                f"independent Kotodama renders differ in bytes: {left.relative_path}"
            )
    if owner_manifest(first) != owner_manifest(second):
        raise GoldenError("independent Kotodama owner manifests differ")


def build_command(
    koto: Path, stage: Path, mode: str, sources: Iterable[Path]
) -> list[str]:
    """Construct one deterministic batch build command."""

    command = [
        str(koto),
        "build",
        "--profile",
        "release",
        "--target-dir",
        str(stage),
        "--max-cycles",
        str(MAX_CYCLES),
    ]
    if mode == "zk":
        command.append("--zk")
    command.extend(path.as_posix() for path in sources)
    return command


def source_check_commands(
    koto: Path, standard_sources: Iterable[Path], zk_sources: Iterable[Path]
) -> list[list[os.PathLike[str] | str]]:
    """Return one strict diagnostics request per independent deployable root.

    Positional ``koto check`` inputs are one explicit source graph, so batching
    unrelated ``seiyaku`` files would either weaken the driver's one-root
    invariant or fail with ``E_MULTIPLE_SEIYAKU_ROOTS``.  Goldens are
    independent deployment roots; check each in its own request and reserve
    multi-file checking for an explicit locked project manifest.
    """

    commands: list[list[os.PathLike[str] | str]] = []
    for source in sorted(standard_sources):
        commands.append([koto, "check", "--format", "human", source])
    for source in sorted(zk_sources):
        commands.append([koto, "check", "--format", "human", "--zk", source])
    return commands


def validate_sources(
    koto: Path, root: Path, sources: Sequence[Path], staging_root: Path
) -> None:
    """Format-check and compile-check every tracked source under its V1 mode."""

    if TEST_SOURCE not in sources:
        raise GoldenError(f"missing canonical test module {TEST_SOURCE}")
    test_sources = [source for source in sources if source.name.endswith(".test.ko")]
    ordinary = [source for source in sources if source not in test_sources]
    zk_sources = sorted(
        {
            *EXTRA_ZK_SOURCES,
            *(
                row.source
                for row in read_map(root / MAP_PATH)
                if row.mode == "zk"
            ),
        }
    )
    missing_zk = sorted(set(zk_sources) - set(ordinary))
    if missing_zk:
        raise GoldenError(
            "configured ZK sources are missing: "
            + ", ".join(path.as_posix() for path in missing_zk)
        )
    standard_sources = sorted(set(ordinary) - set(zk_sources))

    run([koto, "fmt", "--check", *sources], root)
    for command in source_check_commands(koto, standard_sources, zk_sources):
        run(command, root)
    validate_additional_test_sources(koto, root, test_sources, staging_root)


def validate_additional_test_sources(
    koto: Path, root: Path, test_sources: Sequence[Path], staging_root: Path
) -> None:
    """Execute test modules in their real source or scaffold layout."""

    template = Path("crates/musubi/templates/contract.test.ko")
    for source in sorted(test_sources):
        if source == TEST_SOURCE:
            continue  # The canonical runner acceptance suite executes this below.
        command = [koto, "test", "run", "--jobs", "2", "--seed", "0", "--format", "json"]
        if source != template:
            run([*command, "--source-root", root, source], root)
            continue
        # Musubi installs this exact pair under contracts/ and tests/, preserving
        # the template's relative koto_test target without rewriting its source.
        with tempfile.TemporaryDirectory(prefix="musubi-tests.", dir=staging_root) as raw:
            stage = Path(raw)
            contract = stage / "contracts" / "scaffold.ko"
            test = stage / "tests" / "scaffold.test.ko"
            contract.parent.mkdir()
            test.parent.mkdir()
            contract.write_bytes((root / "crates/musubi/templates/contract.ko").read_bytes())
            test.write_bytes((root / source).read_bytes())
            run([*command, "--source-root", stage, test], stage)


def contract_test_commands(
    koto: Path, stage: Path
) -> tuple[list[os.PathLike[str] | str], ...]:
    """Return the exact fail-closed acceptance command inventory."""

    return (
        [koto, "test", "list", TEST_SOURCE],
        [
            koto,
            "test",
            "run",
            "--filter",
            FILTERED_TEST_FRAGMENT,
            TEST_SOURCE,
        ],
        [
            koto,
            "test",
            "run",
            "--filter",
            EXACT_TEST_NAME,
            "--exact",
            TEST_SOURCE,
        ],
        [
            koto,
            "test",
            "run",
            "--jobs",
            "2",
            "--seed",
            "0",
            "--format",
            "json",
            TEST_SOURCE,
        ],
        [
            koto,
            "test",
            "run",
            "--jobs",
            "2",
            "--seed",
            "0",
            "--junit",
            stage / "contract-flow-tests.xml",
            TEST_SOURCE,
        ],
    )


def run_contract_tests(koto: Path, root: Path, stage: Path) -> None:
    """Exercise list/filter/exact and parallel JSON/JUnit runner paths."""

    commands = contract_test_commands(koto, stage)
    for command in commands[:3]:
        run(command, root)
    json_output = run(commands[3], root)
    (stage / "contract-flow-tests.json").write_text(json_output, encoding="utf-8")
    run(commands[4], root)
    validate_contract_test_reports(
        json_output,
        stage / "contract-flow-tests.xml",
    )


def validate_contract_test_reports(json_output: str, junit_path: Path) -> None:
    """Require equivalent, successful canonical JSON and JUnit reports."""

    try:
        report = json.loads(json_output)
    except json.JSONDecodeError as error:
        raise GoldenError(f"koto test emitted invalid JSON: {error}") from error
    expected_report_keys = {"target", "seiyaku", "seed", "passed", "failed", "tests"}
    if not isinstance(report, dict) or set(report) != expected_report_keys:
        raise GoldenError("koto test JSON has a noncanonical report shape")
    tests = report["tests"]
    if (
        not isinstance(report["target"], str)
        or not report["target"]
        or not isinstance(report["seiyaku"], str)
        or not report["seiyaku"]
        or type(report["seed"]) is not int
        or report["seed"] != 0
        or isinstance(report["passed"], bool)
        or not isinstance(report["passed"], int)
        or isinstance(report["failed"], bool)
        or not isinstance(report["failed"], int)
        or not isinstance(tests, list)
        or not tests
        or report["passed"] != len(tests)
        or report["failed"] != 0
    ):
        raise GoldenError("koto test JSON does not describe a complete successful run")

    expected_test_keys = {
        "name", "file", "line", "column", "passed", "duration_ns", "gas", "cycles",
        "calls", "failure",
    }
    names: list[str] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != expected_test_keys:
            raise GoldenError("koto test JSON contains a noncanonical test result")
        if (
            not isinstance(test["name"], str)
            or not test["name"]
            or not isinstance(test["file"], str)
            or not test["file"]
            or any(
                type(test[field]) is not int or not 1 <= test[field] <= 2**64 - 1
                for field in ("line", "column")
            )
            or test["passed"] is not True
            or any(
                type(test[field]) is not int or not 0 <= test[field] <= 2**64 - 1
                for field in ("duration_ns", "gas", "cycles")
            )
            or not isinstance(test["calls"], list)
            or test["failure"] is not None
        ):
            raise GoldenError("koto test JSON contains an invalid successful test result")
        for call in test["calls"]:
            if (
                not isinstance(call, dict)
                or set(call) != {"kotoage", "gas", "cycles"}
                or not isinstance(call["kotoage"], str)
                or not call["kotoage"]
                or any(
                    type(call[field]) is not int or not 0 <= call[field] <= 2**64 - 1
                    for field in ("gas", "cycles")
                )
            ):
                raise GoldenError("koto test JSON contains a noncanonical call result")
        names.append(test["name"])
    if len(names) != len(set(names)):
        raise GoldenError("koto test JSON contains duplicate test names")

    try:
        suite = ElementTree.parse(junit_path).getroot()
    except (OSError, ElementTree.ParseError) as error:
        raise GoldenError(f"koto test emitted invalid JUnit XML: {error}") from error
    try:
        junit_tests = int(suite.attrib["tests"])
        junit_failures = int(suite.attrib["failures"])
        junit_seed = int(suite.attrib["seed"])
        junit_duration = float(suite.attrib["time"])
    except (KeyError, TypeError, ValueError) as error:
        raise GoldenError("koto test JUnit has invalid summary attributes") from error
    cases = list(suite)
    if (
        suite.tag != "testsuite"
        or set(suite.attrib) != {"name", "tests", "failures", "time", "seed"}
        or suite.attrib["name"] != report["seiyaku"]
        or junit_tests != len(tests)
        or junit_failures != 0
        or junit_seed != 0
        or not math.isfinite(junit_duration)
        or junit_duration < 0.0
        or len(cases) != len(tests)
    ):
        raise GoldenError("koto test JUnit does not match the successful JSON run")
    for case, test in zip(cases, tests):
        if (
            case.tag != "testcase"
            or set(case.attrib) != {"name", "classname", "file", "line", "time"}
        ):
            raise GoldenError("koto test JUnit contains a noncanonical test case")
        if case.attrib["name"] != test["name"]:
            raise GoldenError("koto test JSON and JUnit test inventories differ")
        if case.attrib["classname"] != test["file"] or case.attrib["file"] != test["file"]:
            raise GoldenError("koto test JSON and JUnit source locations differ")
        try:
            line = int(case.attrib["line"])
            duration = float(case.attrib["time"])
        except (KeyError, TypeError, ValueError) as error:
            raise GoldenError("koto test JUnit contains invalid case attributes") from error
        if line <= 0 or not math.isfinite(duration) or duration < 0.0:
            raise GoldenError("koto test JUnit contains invalid case values")
        if line != test["line"]:
            raise GoldenError("koto test JSON and JUnit source locations differ")
        children = list(case)
        if len(children) != 1 or children[0].tag != "properties" or children[0].attrib:
            raise GoldenError("koto test JUnit contains noncanonical test properties")
        properties = list(children[0])
        if len(properties) != 2:
            raise GoldenError("koto test JUnit contains noncanonical test properties")
        for entry, field in zip(properties, ("gas", "cycles")):
            if (
                entry.tag != "property"
                or set(entry.attrib) != {"name", "value"}
                or entry.attrib["name"] != field
                or list(entry)
            ):
                raise GoldenError("koto test JUnit contains noncanonical test properties")
            if entry.attrib["value"] != str(test[field]):
                raise GoldenError("koto test JSON and JUnit execution metrics differ")


def verify_runtime_manifests(
    admission_tool: Path, root: Path, stage: Path, builds: Sequence[Golden]
) -> None:
    """Cross-check compiler manifests through the canonical native admission owner."""

    verified = stage / "verified"
    verified.mkdir()
    for row in builds:
        stem = row.source.stem
        artifact = stage / "release" / f"{stem}.to"
        generated = stage / "release" / f"{stem}.manifest.json"
        runtime_manifest = verified / f"{stem}.manifest.json"
        run(
            [
                admission_tool,
                "--code-file",
                artifact,
                "--out",
                runtime_manifest,
            ],
            root,
        )
        compare_runtime_manifest(generated, runtime_manifest)


def build_and_validate(
    koto: Path,
    admission_tool: Path,
    root: Path,
    stage: Path,
    rows: Sequence[Golden],
    run_tests: bool,
) -> list[Golden]:
    """Build each unique source once, authenticate outputs, and prove no-op reuse."""

    builds = unique_builds(rows)
    commands: list[tuple[list[str], int]] = []
    for mode in ("standard", "zk"):
        selected = [row.source for row in builds if row.mode == mode]
        if selected:
            commands.append((build_command(koto, stage, mode, selected), len(selected)))
    for command, _ in commands:
        run(command, root)

    for row in builds:
        artifact = stage / "release" / f"{row.source.stem}.to"
        manifest = stage / "release" / f"{row.source.stem}.manifest.json"
        validate_artifact(artifact, row.mode, manifest_abi_hash(manifest))
    validate_performance(stage, builds)
    verify_runtime_manifests(admission_tool, root, stage, builds)
    if run_tests:
        run_contract_tests(koto, root, stage)

    before_paths = sorted(path for path in (stage / "release").rglob("*") if path.is_file())
    before = {path: path.stat().st_mtime_ns for path in before_paths}
    for command, expected_fresh in commands:
        output = run(command, root)
        validate_noop_build_output(output, expected_fresh)
    after_paths = sorted(path for path in (stage / "release").rglob("*") if path.is_file())
    if after_paths != before_paths:
        raise GoldenError("no-op Kotodama graph changed the generated output inventory")
    after = {path: path.stat().st_mtime_ns for path in before}
    if before != after:
        raise GoldenError("no-op Kotodama graph rewrote generated output")
    return builds


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """Return whether two metadata records name the same filesystem object."""

    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _open_canonical_publication_parent(path: Path) -> int:
    """Open and bind the canonical real parent of one publication path."""

    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise GoldenError(f"Kotodama publication path must be absolute and narrow: {path}")
    parent = path.parent
    try:
        lexical = parent.lstat()
        canonical = parent.resolve(strict=True)
    except OSError as error:
        raise GoldenError(f"Kotodama publication parent is unavailable: {parent}") from error
    if (
        stat.S_ISLNK(lexical.st_mode)
        or not stat.S_ISDIR(lexical.st_mode)
        or canonical != parent
    ):
        raise GoldenError(
            f"Kotodama publication parent must be one canonical real directory: {parent}"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
    except OSError as error:
        raise GoldenError(f"failed to bind Kotodama publication parent: {parent}") from error
    bound = os.fstat(descriptor)
    if not _same_file_identity(lexical, bound) or not stat.S_ISDIR(bound.st_mode):
        os.close(descriptor)
        raise GoldenError(f"Kotodama publication parent changed while opening: {parent}")
    return descriptor


def _revalidate_publication_boundary(
    path: Path, parent_descriptor: int, root_descriptor: int
) -> None:
    """Require the held parent and root to remain at the requested pathname."""

    parent_bound = os.fstat(parent_descriptor)
    root_bound = os.fstat(root_descriptor)
    try:
        parent_lexical = path.parent.lstat()
        root_from_parent = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        root_lexical = path.lstat()
    except OSError as error:
        raise GoldenError("Kotodama publication boundary changed during publication") from error
    if (
        not _same_file_identity(parent_bound, parent_lexical)
        or not _same_file_identity(root_bound, root_from_parent)
        or not _same_file_identity(root_bound, root_lexical)
        or stat.S_ISLNK(root_lexical.st_mode)
        or not stat.S_ISDIR(root_lexical.st_mode)
    ):
        raise GoldenError("Kotodama publication boundary changed during publication")


def _open_directory_beneath(
    root_descriptor: int, relative: Path, *, create: bool
) -> int:
    """Open a real directory beneath a bound root, optionally creating it."""

    if relative == Path("."):
        return os.dup(root_descriptor)
    if relative.is_absolute() or ".." in relative.parts:
        raise GoldenError(f"invalid generated directory: {relative}")
    descriptor = os.dup(root_descriptor)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in relative.parts:
            if component in {"", ".", ".."}:
                raise GoldenError(f"invalid generated directory: {relative}")
            if create:
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise GoldenError(
                    f"generated directory is missing or unsafe: {relative}"
                ) from error
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise GoldenError(f"generated directory is not real: {relative}")
            if create:
                os.fchmod(child, 0o755)
                metadata = os.fstat(child)
            if stat.S_IMODE(metadata.st_mode) != 0o755:
                os.close(child)
                raise GoldenError(f"generated directory has the wrong mode: {relative}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _create_file_beneath(
    root_descriptor: int, relative: Path, payload: bytes, mode: int = 0o644
) -> None:
    """Create, flush, and authenticate one file relative to a bound root."""

    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise GoldenError(f"invalid generated file: {relative}")
    parent = _open_directory_beneath(
        root_descriptor,
        relative.parent,
        create=False,
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        try:
            descriptor = os.open(relative.name, flags, mode, dir_fd=parent)
        except OSError as error:
            raise GoldenError(
                f"create-only generated destination exists or is unsafe: {relative}"
            ) from error
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != mode
                or metadata.st_size != len(payload)
            ):
                raise GoldenError(f"generated destination failed validation: {relative}")
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def _snapshot_bound_tree(
    root_descriptor: int,
    relative: Path = Path("."),
) -> dict[Path, tuple[str, int, bytes | None]]:
    """Read a complete no-follow tree inventory through held descriptors."""

    snapshot: dict[Path, tuple[str, int, bytes | None]] = {}
    directory = _open_directory_beneath(root_descriptor, relative, create=False)
    try:
        names = sorted(os.listdir(directory))
        for name in names:
            if name in {"", ".", ".."} or "/" in name:
                raise GoldenError("generated output tree contains an invalid path")
            child_path = Path(name) if relative == Path(".") else relative / name
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory,
                )
                try:
                    if not _same_file_identity(metadata, os.fstat(child)):
                        raise GoldenError(
                            f"generated directory changed while reading: {child_path}"
                        )
                finally:
                    os.close(child)
                snapshot[child_path] = (
                    "directory",
                    stat.S_IMODE(metadata.st_mode),
                    None,
                )
                snapshot.update(_snapshot_bound_tree(root_descriptor, child_path))
            elif stat.S_ISREG(metadata.st_mode):
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(name, flags, dir_fd=directory)
                try:
                    bound = os.fstat(descriptor)
                    if (
                        not _same_file_identity(metadata, bound)
                        or bound.st_nlink != 1
                    ):
                        raise GoldenError(
                            f"generated file is hard-linked or changed: {child_path}"
                        )
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    after = os.fstat(descriptor)
                    from_parent = os.stat(
                        name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                    if (
                        not _same_file_identity(bound, after)
                        or not _same_file_identity(bound, from_parent)
                        or bound.st_size != after.st_size
                    ):
                        raise GoldenError(
                            f"generated file changed while reading: {child_path}"
                        )
                    snapshot[child_path] = (
                        "file",
                        stat.S_IMODE(bound.st_mode),
                        b"".join(chunks),
                    )
                finally:
                    os.close(descriptor)
            else:
                raise GoldenError(
                    f"generated output tree contains a link or special file: {child_path}"
                )
    finally:
        os.close(directory)
    return snapshot


def _expected_publication_snapshot(
    rendered: Sequence[RenderedFile], *, complete: bool
) -> dict[Path, tuple[str, int, bytes | None]]:
    """Return the exact accepted publication inventory."""

    expected: dict[Path, tuple[str, int, bytes | None]] = {
        directory.relative_path: ("directory", directory.mode, None)
        for directory in rendered_directories(rendered)
    }
    for output in rendered:
        if output.relative_path in expected:
            raise GoldenError(f"duplicate generated path: {output.relative_path}")
        expected[output.relative_path] = ("file", output.mode, output.payload)
    if PUBLICATION_MANIFEST_PATH in expected:
        raise GoldenError(
            f"generated output collides with publication seal: {PUBLICATION_MANIFEST_PATH}"
        )
    if complete:
        expected[PUBLICATION_MANIFEST_PATH] = (
            "file",
            0o644,
            owner_manifest(rendered),
        )
    return expected


def _compare_publication_snapshot(
    actual: dict[Path, tuple[str, int, bytes | None]],
    expected: dict[Path, tuple[str, int, bytes | None]],
) -> None:
    """Require exact node paths, kinds, modes, and bytes."""

    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual), key=lambda value: value.as_posix())
        unexpected = sorted(set(actual) - set(expected), key=lambda value: value.as_posix())
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(path.as_posix() for path in missing))
        if unexpected:
            details.append(
                "unexpected " + ", ".join(path.as_posix() for path in unexpected)
            )
        raise GoldenError("generated output tree is not complete: " + "; ".join(details))
    for path in sorted(expected, key=lambda value: value.as_posix()):
        if actual[path] != expected[path]:
            raise GoldenError(
                f"generated output node differs in kind, mode, or bytes: {path}"
            )


def _validate_publication(
    path: Path, rendered: Sequence[RenderedFile]
) -> None:
    """Verify one completed publication tree through an inode-bound boundary."""

    parent = _open_canonical_publication_parent(path)
    root = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root = os.open(path.name, flags, dir_fd=parent)
        except OSError as error:
            raise GoldenError(
                f"completed Kotodama publication is missing or unsafe: {path}"
            ) from error
        metadata = os.fstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise GoldenError("Kotodama publication root must be a mode-0700 directory")
        _revalidate_publication_boundary(path, parent, root)
        actual = _snapshot_bound_tree(root)
        _compare_publication_snapshot(
            actual,
            _expected_publication_snapshot(rendered, complete=True),
        )
        _revalidate_publication_boundary(path, parent, root)
    finally:
        if root >= 0:
            os.close(root)
        os.close(parent)


def publish_create_only(
    path: Path,
    rendered: Sequence[RenderedFile],
    *,
    preseal: Callable[[], None] | None = None,
) -> int:
    """Create an immutable publication tree and write its completion seal last.

    The destination directory becomes visible when it is atomically reserved,
    but it is not a publication until the owner manifest exists. Every checker
    requires that final seal. Any failure leaves unsealed residue in place and
    never removes or overwrites a caller-selected path.
    """

    expected_incomplete = _expected_publication_snapshot(rendered, complete=False)
    parent = _open_canonical_publication_parent(path)
    root = -1
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise GoldenError(f"Kotodama publication is create-only: {path}")
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
        except OSError as error:
            raise GoldenError(f"failed to reserve Kotodama publication: {path}") from error
        os.fsync(parent)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        root = os.open(path.name, flags, dir_fd=parent)
        os.fchmod(root, 0o700)
        _revalidate_publication_boundary(path, parent, root)

        directories = sorted(
            rendered_directories(rendered),
            key=lambda value: (len(value.relative_path.parts), value.relative_path.as_posix()),
        )
        for directory in directories:
            descriptor = _open_directory_beneath(
                root,
                directory.relative_path,
                create=True,
            )
            os.fsync(descriptor)
            os.close(descriptor)
        for output in rendered:
            _revalidate_publication_boundary(path, parent, root)
            _create_file_beneath(
                root,
                output.relative_path,
                output.payload,
                output.mode,
            )

        _compare_publication_snapshot(
            _snapshot_bound_tree(root),
            expected_incomplete,
        )
        if preseal is not None:
            preseal()
        _revalidate_publication_boundary(path, parent, root)
        _create_file_beneath(
            root,
            PUBLICATION_MANIFEST_PATH,
            owner_manifest(rendered),
        )
        os.fsync(root)
        os.fsync(parent)
        _revalidate_publication_boundary(path, parent, root)
    finally:
        if root >= 0:
            os.close(root)
        os.close(parent)

    _validate_publication(path, rendered)
    return len(rendered)


def verify_rendered_tree(
    output_root: Path,
    rendered: Sequence[RenderedFile],
) -> int:
    """Check the repository or one completed sealed publication tree."""

    output_root = _prepare_real_directory(
        output_root,
        context="Kotodama golden output root",
        create=False,
    )
    strict_publication_root = output_root != repository_root().resolve(strict=True)
    if strict_publication_root:
        _validate_publication(output_root, rendered)
        return 0

    expected_paths = {output.relative_path for output in rendered}
    if len(expected_paths) != len(rendered):
        raise GoldenError("canonical rendering contains duplicate output paths")

    # Retired outputs are rejected, never migrated or removed.
    for retired in FORBIDDEN_LEGACY_OUTPUTS:
        path = _confined_destination(
            output_root,
            retired,
            missing_parent_ok=True,
        )
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise GoldenError(f"retired Kotodama artifact still exists: {retired}")

    for output in rendered:
        destination = _confined_destination(
            output_root,
            output.relative_path,
            missing_parent_ok=False,
        )
        try:
            destination.lstat()
        except FileNotFoundError:
            raise GoldenError(f"generated destination is missing: {destination}") from None
        else:
            compare_payload(output.payload, destination, output.mode)
    return 0


class _UniquePathAction(argparse.Action):
    """Reject repeated path options instead of silently accepting the last."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Path,
        option_string: str | None = None,
    ) -> None:
        supplied_marker = f"_{self.dest}_supplied"
        if getattr(namespace, supplied_marker, False):
            parser.error(f"{option_string or self.dest} was supplied more than once")
        setattr(namespace, supplied_marker, True)
        setattr(namespace, self.dest, values)


def _non_empty_path(value: str) -> Path:
    """Parse a required tool path without accepting an empty argument."""

    if not value or value.startswith("-"):
        raise argparse.ArgumentTypeError("path must be non-empty and must not be a flag")
    return Path(value)


def _explicit_root_path(value: str) -> Path:
    """Parse a deliberate non-broad root without normalizing symlinks."""

    if not value or value.startswith("-"):
        raise argparse.ArgumentTypeError("root path must be non-empty and must not be a flag")
    path = Path(value)
    if path in {Path("."), Path(path.anchor)} or ".." in path.parts:
        raise argparse.ArgumentTypeError(
            "explicit root must not be '.', a filesystem root, or contain '..'"
        )
    return path


def _absolute_output_root_path(value: str) -> Path:
    """Parse an absolute publication/check root without resolving it early."""

    path = _explicit_root_path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("output root must be absolute")
    return path


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse the discoverable command-line interface."""

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify without publishing (default)")
    mode.add_argument(
        "--write",
        action="store_true",
        help="create one prevalidated publication at an absent output root",
    )
    parser.add_argument(
        "--koto",
        type=_non_empty_path,
        action=_UniquePathAction,
        default=Path("target/debug/koto"),
    )
    parser.add_argument(
        "--admission-tool",
        type=_non_empty_path,
        action=_UniquePathAction,
        default=Path("target/debug/ivm_artifact_admit"),
        help="canonical ivm_artifact_admit executable (default: target/debug/ivm_artifact_admit)",
    )
    parser.add_argument(
        "--output-root",
        type=_absolute_output_root_path,
        action=_UniquePathAction,
        help="publish or compare below this absent absolute root (ignored target directory or outside workspace)",
    )
    parser.add_argument(
        "--staging-root",
        type=_explicit_root_path,
        action=_UniquePathAction,
        help="temporary compiler root (ignored target descendant or outside workspace)",
    )
    arguments = list(argv)
    if sum(argument in {"--check", "--write"} for argument in arguments) > 1:
        parser.error("select --check or --write at most once")
    parsed = parser.parse_args(arguments)
    if parsed.write and parsed.output_root is None:
        parser.error("--write requires --output-root <absent-absolute-root>")
    return parsed


def _resolve_tool(root: Path, path: Path, name: str) -> Path:
    tool = path if path.is_absolute() else root / path
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise GoldenError(f"{name} binary is missing or not executable: {tool}")
    return tool


def _rooted_path(root: Path, path: Path | None, default: Path) -> Path:
    """Resolve an optional CLI path relative to the live repository root."""

    selected = default if path is None else path
    return selected if selected.is_absolute() else root / selected


def _prepare_real_directory(
    path: Path,
    *,
    context: str,
    create: bool,
) -> Path:
    """Return the canonical boundary for a real, non-symlink directory."""

    if not path.is_absolute():
        raise GoldenError(f"{context} must be absolute: {path}")

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not create:
            raise GoldenError(f"{context} does not exist: {path}") from None
        path.mkdir(parents=True, exist_ok=True)
        metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise GoldenError(f"{context} must be a real directory: {path}")
    return path.resolve(strict=True)


def _preflight_create_only_output_path(path: Path) -> Path:
    """Validate an absent publication path without reserving it early."""

    parent = _open_canonical_publication_parent(path)
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return path
        raise GoldenError(f"Kotodama publication is create-only: {path}")
    finally:
        os.close(parent)


def _require_scratch_path(root: Path, path: Path) -> Path:
    """Allow canonical external scratch or untracked, ignored checkout target scratch.

    Recheck Git's actual ignore/index decision before the completion seal. Source
    directories and tracked files never become writable generation destinations.
    """

    if not path.is_absolute():
        raise GoldenError(f"Kotodama scratch root must be absolute: {path}")
    workspace = root.resolve(strict=True)
    if ".." in path.parts or path.resolve(strict=False) != path:
        raise GoldenError(f"Kotodama scratch root must have a canonical non-symlink path: {path}")
    if path == workspace or workspace in path.parents:
        if workspace / "target" not in path.parents:
            raise GoldenError(
                f"Kotodama scratch inside the workspace must be below ignored target: {path}"
            )
        relative = path.relative_to(workspace).as_posix()
        if run(["git", "ls-files", "--cached", "-z", "--", relative], workspace):
            raise GoldenError(f"Kotodama scratch contains tracked paths: {path}")
        # -z avoids Git's pathname quoting and makes the exact decision unambiguous.
        ignored = run(
            ["git", "check-ignore", "--no-index", "-z", "--stdin"],
            workspace,
            input=relative + "\0",
        )
        if ignored != relative + "\0":
            raise GoldenError(f"Kotodama scratch must be Git-ignored: {path}")
    return path


def _require_output_path(root: Path, path: Path) -> Path:
    """Require an allowed output path whose existing parent retains canonical custody."""

    _require_scratch_path(root, path)
    parent = _open_canonical_publication_parent(path)
    os.close(parent)
    return path


def _prepare_staging_directory(root: Path, requested: Path) -> Path:
    """Prepare scratch without granting authority to a substituted canonical path."""

    _require_scratch_path(root, requested)
    prepared = _prepare_real_directory(
        requested, context="Kotodama golden staging root", create=True
    )
    if prepared != requested:
        raise GoldenError("Kotodama staging path changed during preparation")
    _require_scratch_path(root, requested)
    return requested


def _confined_destination(
    root: Path,
    relative: Path,
    *,
    missing_parent_ok: bool,
) -> Path:
    """Return one existing destination after a no-symlink walk beneath ``root``."""

    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise GoldenError(f"invalid generated destination below {root}: {relative}")
    parent = root
    for part in relative.parent.parts:
        if part == ".":
            continue
        parent /= part
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            if missing_parent_ok:
                return root / relative
            raise GoldenError(f"generated output parent does not exist: {parent}") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise GoldenError(
                f"generated output parent must be a real directory: {parent}"
            )
    return root / relative


def main(argv: Sequence[str] | None = None) -> int:
    """Run the complete fail-closed golden pipeline."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = repository_root().resolve(strict=True)
    try:
        if args.output_root is None:
            output_root = root
        else:
            output_root = _require_output_path(root, args.output_root)
        staging_root = _rooted_path(
            root,
            args.staging_root,
            root / "target" / "kotodama",
        )
        if args.write:
            output_root = _preflight_create_only_output_path(output_root)
        else:
            output_root = _prepare_real_directory(
                output_root,
                context="Kotodama golden output root",
                create=False,
            )
        staging_root = _prepare_staging_directory(root, staging_root)
        rows = read_map(root / MAP_PATH)
        sources = tracked_sources(root)
        validate_output_inventory(rows, sources, tracked_outputs(root))
        koto = _resolve_tool(root, args.koto, "koto")
        admission_tool = _resolve_tool(root, args.admission_tool, "ivm_artifact_admit")
        sealed_inputs = generation_input_seals(root, sources, koto, admission_tool)
        checked_sources, byte_exact_sources = partition_source_policy(root, sources)
        if not checked_sources or not byte_exact_sources:
            raise GoldenError(
                "Kotodama source policy must contain checked and byte-exact sources"
            )
        if generation_input_seals(root, sources, koto, admission_tool) != sealed_inputs:
            raise GoldenError(
                "Kotodama generation inputs drifted during source classification"
            )
        validate_sources(koto, root, checked_sources, staging_root)
        with tempfile.TemporaryDirectory(
            prefix="v1-goldens-first.",
            dir=staging_root,
        ) as raw_first_stage, tempfile.TemporaryDirectory(
            prefix="v1-goldens-second.",
            dir=staging_root,
        ) as raw_second_stage:
            first_stage = Path(raw_first_stage)
            second_stage = Path(raw_second_stage)
            if first_stage.resolve(strict=True) == second_stage.resolve(strict=True):
                raise GoldenError("independent Kotodama staging roots alias each other")
            build_and_validate(
                koto,
                admission_tool,
                root,
                first_stage,
                rows,
                True,
            )
            build_and_validate(
                koto,
                admission_tool,
                root,
                second_stage,
                rows,
                False,
            )
            first_render = rendered_files(first_stage, rows)
            second_render = rendered_files(second_stage, rows)
            compare_renderings(first_render, second_render)

            def require_stable_inputs() -> None:
                _require_scratch_path(root, staging_root)
                if args.output_root is not None:
                    _require_output_path(root, output_root)
                if generation_input_seals(root, sources, koto, admission_tool) != sealed_inputs:
                    raise GoldenError("Kotodama generation inputs drifted during rendering")

            require_stable_inputs()
            if args.write:
                changed = publish_create_only(
                    output_root,
                    first_render,
                    preseal=require_stable_inputs,
                )
            else:
                changed = verify_rendered_tree(output_root, first_render)
                require_stable_inputs()
            manifest_sha256 = hashlib.sha256(owner_manifest(first_render)).hexdigest()
    except (GoldenError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    action = "published" if args.write else "verified"
    print(
        f"{action} {len(rows)} Kotodama V1 artifact mappings "
        f"({changed} changes; owner manifest sha256={manifest_sha256})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
