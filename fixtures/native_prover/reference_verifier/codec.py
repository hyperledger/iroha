"""The bounded descriptor subset of Norito, independently from norito.md.

Only uncompressed, explicitly selected nominal descriptor frames are accepted.
Each child consumes its authoritative span; lengths never select another layout.
"""
from __future__ import annotations

import hashlib
from typing import Callable, TypeVar

from . import require

T = TypeVar('T')
MAX_FRAME = 16 * 1024 * 1024
MAX_COUNT = 65535


def crc64(payload: bytes) -> int:
    """CRC64-XZ, the reflected ECMA polynomial with all-ones init/xor."""
    value = (1 << 64) - 1
    for byte in payload:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xC96C5795D7870F42 if value & 1 else 0)
    return value ^ ((1 << 64) - 1)


class Cursor:
    """A finite byte span with explicit fixed/compact field lengths."""

    def __init__(self, data: bytes, compact: bool = True):
        require(isinstance(data, bytes), 'encoded byte span required')
        self.data = data
        self.position = 0
        self.compact = compact

    def read(self, count: int) -> bytes:
        """Borrow no bytes outside this span."""
        require(0 <= count <= len(self.data) - self.position, 'truncated span')
        start = self.position
        self.position += count
        return self.data[start:self.position]

    def integer(self, width: int, signed: bool = False) -> int:
        """Read an explicitly sized little-endian integer."""
        return int.from_bytes(self.read(width), 'little', signed=signed)

    def length(self) -> int:
        """Read a bounded canonical per-value length from the selected layout."""
        if not self.compact:
            length = self.integer(8)
        else:
            length = 0
            shift = 0
            while True:
                byte = self.integer(1)
                require(shift < 64 and (shift < 63 or byte <= 1), 'length overflow')
                length |= (byte & 127) << shift
                if byte < 128:
                    require(shift == 0 or byte != 0, 'nonminimal length')
                    break
                shift += 7
        require(length <= MAX_FRAME, 'length bound')
        return length

    def field(self, decode: Callable[[Cursor], T]) -> T:
        """Decode exactly one length-delimited field."""
        child = Cursor(self.read(self.length()), self.compact)
        value = decode(child)
        child.finish()
        return value

    def sequence(self, decode: Callable[[Cursor], T]) -> list[T]:
        """A fixed-u64 count and one framed span per non-byte element."""
        count = self.integer(8)
        require(count <= MAX_COUNT and count <= len(self.data) - self.position,
                'sequence count')
        return [self.field(decode) for _ in range(count)]

    def finish(self) -> None:
        """Reject logical tails, even zero-filled ones."""
        require(self.position == len(self.data), 'trailing span bytes')


def descriptor_frame(raw: bytes, version: int) -> Cursor:
    """Authenticate exact V1/V2 type, header, layout, length and checksum."""
    require(type(version) is int and version in (1, 2), 'explicit descriptor version')
    require(isinstance(raw, bytes), 'encoded descriptor required')
    require(40 <= len(raw) <= MAX_FRAME, 'descriptor frame bound')
    header = Cursor(raw[:40], False)
    require(header.read(6) == b'NRT0\0\0', 'Norito version')
    schema = hashlib.sha256(b'norito:v1:type-name\0' +
                            f'iroha.plonk.pipa.circuit_descriptor.v{version}'.encode()).digest()[:16]
    require(header.read(16) == schema, 'descriptor schema')
    require(header.integer(1) == 0, 'compressed descriptor unsupported')
    length = header.integer(8)
    checksum = header.integer(8)
    flags = header.integer(1)
    require(flags in (0, 2), 'descriptor layout')
    # These named records have eight-byte archive alignment; 40 is aligned.
    require(length == len(raw) - 40, 'descriptor frame length')
    require(crc64(raw[40:]) == checksum, 'descriptor checksum')
    return Cursor(raw[40:], flags == 2)
