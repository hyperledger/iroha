#!/usr/bin/env python3
"""Recover public diagnostic ZIPs from Logcat; this does not verify attestation."""

import argparse
import base64
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MAX_ZIP_BYTES = 256 * 1024
MAX_EXPANDED_BYTES = 1024 * 1024
MAX_LOG_BYTES = 20 * 1024 * 1024
CHUNK_CHARACTERS = 1200
PREFIX = "IROHA_ATTESTATION "
ID = r"[A-Za-z0-9_-]{1,80}"
BOUNDARY = re.compile(
    rf"(BEGIN|END) id=({ID}) bytes=([1-9][0-9]{{0,5}}) "
    r"sha256=([0-9a-f]{64}) chunks=([1-9][0-9]{0,2})"
)
CHUNK = re.compile(rf"CHUNK id=({ID}) index=([0-9]{{1,3}}) data=([A-Za-z0-9+/=]{{1,1200}})")
PUBLIC_FILE = re.compile(
    r"(report\.txt|challenge\.bin|"
    r"(android-keystore|huawei-keystore)/(public-key\.spki\.der|public-key\.pem|"
    r"chain\.pem|challenge-signature\.der|certificate-[0-9]{1,2}\.der))"
)


def decode_log(text: str, capture_id: str | None = None) -> dict[str, bytes]:
    """Require complete, consistent frames; tolerate identical repeated emissions."""
    if len(text.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("Log exceeds 20 MiB")
    if capture_id is not None and re.fullmatch(ID, capture_id) is None:
        raise ValueError("Invalid capture ID")
    captures: dict[str, dict] = {}
    for line in text.splitlines():
        _, marker, payload = line.partition(PREFIX)
        if not marker or payload.startswith(("STATUS ", "ERROR ")):
            continue
        boundary = BOUNDARY.fullmatch(payload)
        chunk = CHUNK.fullmatch(payload)
        if boundary:
            kind, name, size, digest, count = boundary.groups()
            metadata = (int(size), digest, int(count))
        elif chunk:
            name, index, data = chunk.groups()
            kind = "CHUNK"
        else:
            raise ValueError("Malformed diagnostic log frame")
        if capture_id is not None and name != capture_id:
            continue
        group = captures.setdefault(name, {"chunks": {}})
        if len(captures) > 16:
            raise ValueError("Too many captures; select one with --capture-id")
        if kind == "CHUNK":
            position = int(index)
            if position >= 292:
                raise ValueError("Chunk index exceeds export bounds")
            previous = group["chunks"].setdefault(position, data)
            if previous != data:
                raise ValueError("Conflicting duplicate chunk")
        else:
            size, _, count = metadata
            expected_count = ((4 * ((size + 2) // 3)) + CHUNK_CHARACTERS - 1) // CHUNK_CHARACTERS
            if size > MAX_ZIP_BYTES or count != expected_count:
                raise ValueError("Export metadata exceeds bounds or has wrong chunk count")
            if group.setdefault(kind, metadata) != metadata:
                raise ValueError("Conflicting repeated boundary")
    if not captures:
        raise ValueError("No public diagnostic capture found")
    decoded = {}
    for name, group in captures.items():
        if "BEGIN" not in group or "END" not in group:
            raise ValueError(f"Incomplete capture {name}: missing BEGIN or END")
        if group["BEGIN"] != group["END"]:
            raise ValueError("BEGIN and END disagree")
        size, digest, count = group["BEGIN"]
        chunks = group["chunks"]
        if set(chunks) != set(range(count)):
            raise ValueError(f"Incomplete capture {name}: missing or extra chunks")
        for index in range(count - 1):
            if len(chunks[index]) != CHUNK_CHARACTERS:
                raise ValueError("Non-final chunk has wrong length")
        encoded = "".join(chunks[index] for index in range(count))
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise ValueError("Invalid Base64 export") from error
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError("Non-canonical Base64 export")
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Public ZIP size or SHA-256 mismatch")
        validated_members(raw)
        decoded[name] = raw
    return decoded


def validated_members(raw: bytes) -> dict[str, bytes]:
    """Inspect every member before writing; only the probe's public file set is accepted."""
    if not 0 < len(raw) <= MAX_ZIP_BYTES:
        raise ValueError("ZIP size exceeds bounds")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > 64 or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES:
                raise ValueError("ZIP expanded contents exceed bounds")
            result = {}
            for item in members:
                name = item.filename
                path = PurePosixPath(name)
                mode = stat.S_IFMT(item.external_attr >> 16)
                if (
                    path.is_absolute()
                    or any(part in ("", ".", "..") for part in name.split("/"))
                    or PUBLIC_FILE.fullmatch(name) is None
                    or mode not in (0, stat.S_IFREG)
                    or item.flag_bits & 1
                    or name in result
                ):
                    raise ValueError(f"Unsafe, unknown, encrypted, or duplicate ZIP member: {name!r}")
                result[name] = archive.read(item)
            if "report.txt" not in result or len(result.get("challenge.bin", b"")) != 32:
                raise ValueError("Missing report or 32-byte challenge")
            return result
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as error:
        raise ValueError("Invalid diagnostic ZIP") from error


def save_captures(captures: dict[str, bytes], output: Path) -> None:
    """Write to a new output directory; refuse existing paths and symbolic links."""
    members = {name: validated_members(raw) for name, raw in captures.items()}
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in captures.items():
        (output / f"{name}.zip").write_bytes(raw)
        destination = output / name
        destination.mkdir()
        for relative, data in members[name].items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logcat", type=Path)
    parser.add_argument("output", type=Path, help="New directory for verified transport bytes")
    parser.add_argument("--capture-id", help="Select one capture from a multi-session report")
    args = parser.parse_args()
    if args.logcat.stat().st_size > MAX_LOG_BYTES:
        parser.error("Log exceeds 20 MiB")
    try:
        captures = decode_log(args.logcat.read_text(encoding="utf-8"), args.capture_id)
        save_captures(captures, args.output)
    except (ValueError, OSError, UnicodeError) as error:
        parser.error(str(error))
    for name, raw in captures.items():
        print(f"{name}: bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}")
    print("Transport integrity verified. Diagnostic capture only; no enrollment decision.")


if __name__ == "__main__":
    main()
