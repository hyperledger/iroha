#!/usr/bin/env python3
"""Pure-Python BLAKE3 (unkeyed hash mode) for scripts/check_zk_primitive_workloads.py.

Requires Python 3.9+ and its standard library; no environment variables or
installed packages are needed. The module is read-only. The checker uses it to
recompute the BLAKE3-256 column of the candidate native-commitment vectors
without the Rust `blake3` crate, so the tracked digests are checked by two
independent implementations. Run on its own it checks itself against the
published BLAKE3 test vectors listed below and prints the digest of each file
named on the command line.

Scope: the default hash mode with any output length, single-threaded, written
for clarity. It is a test reference for inputs of a few kilobytes, not a
production hash; keyed and derive-key modes are not implemented.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Optional, Sequence

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)  # fmt: skip
MESSAGE_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
BLOCK_BYTES = 64
CHUNK_BYTES = 1024
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
MASK = 0xFFFFFFFF

# Official test vectors (BLAKE3 `test_vectors.json`): the input is the byte
# sequence 0, 1, ..., 250 repeated to the stated length; the value is the first
# 32 bytes of the hash-mode output.
PUBLISHED_VECTORS = {
    0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
}


def _rotate_right(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (32 - bits))) & MASK


def _quarter(state: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    state[a] = (state[a] + state[b] + x) & MASK
    state[d] = _rotate_right(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotate_right(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & MASK
    state[d] = _rotate_right(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotate_right(state[b] ^ state[c], 7)


def compress(chaining: Sequence[int], block: Sequence[int], counter: int, length: int, flags: int) -> list[int]:
    """The BLAKE3 compression function; returns the full 16-word state."""
    state = list(chaining) + list(IV[:4]) + [counter & MASK, (counter >> 32) & MASK, length, flags]
    words = list(block)
    for round_index in range(7):
        _quarter(state, 0, 4, 8, 12, words[0], words[1])
        _quarter(state, 1, 5, 9, 13, words[2], words[3])
        _quarter(state, 2, 6, 10, 14, words[4], words[5])
        _quarter(state, 3, 7, 11, 15, words[6], words[7])
        _quarter(state, 0, 5, 10, 15, words[8], words[9])
        _quarter(state, 1, 6, 11, 12, words[10], words[11])
        _quarter(state, 2, 7, 8, 13, words[12], words[13])
        _quarter(state, 3, 4, 9, 14, words[14], words[15])
        if round_index < 6:
            words = [words[index] for index in MESSAGE_PERMUTATION]
    for index in range(8):
        state[index] ^= state[index + 8]
        state[index + 8] ^= chaining[index]
    return state


def _words(block: bytes) -> list[int]:
    padded = block.ljust(BLOCK_BYTES, b"\0")
    return [int.from_bytes(padded[offset:offset + 4], "little") for offset in range(0, BLOCK_BYTES, 4)]


class _Output:
    """Inputs of the last compression of a subtree, from which its value is read."""

    def __init__(self, chaining: Sequence[int], block: Sequence[int], counter: int, length: int, flags: int) -> None:
        self.chaining, self.block, self.counter, self.length, self.flags = chaining, block, counter, length, flags

    def chaining_value(self) -> list[int]:
        return compress(self.chaining, self.block, self.counter, self.length, self.flags)[:8]

    def root_bytes(self, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            state = compress(self.chaining, self.block, counter, self.length, self.flags | ROOT)
            for word in state:
                out += word.to_bytes(4, "little")
            counter += 1
        return bytes(out[:length])


def _chunk_output(chunk: bytes, counter: int) -> _Output:
    chaining = list(IV)
    blocks = [chunk[offset:offset + BLOCK_BYTES] for offset in range(0, len(chunk), BLOCK_BYTES)] or [b""]
    for index, block in enumerate(blocks):
        flags = (CHUNK_START if index == 0 else 0) | (CHUNK_END if index == len(blocks) - 1 else 0)
        if index == len(blocks) - 1:
            return _Output(chaining, _words(block), counter, len(block), flags)
        chaining = compress(chaining, _words(block), counter, BLOCK_BYTES, flags)[:8]
    raise AssertionError("a chunk has at least one block")


def _subtree(data: bytes, first_chunk: int) -> _Output:
    """Output of the subtree over `data`, whose first chunk has index `first_chunk`."""
    if len(data) <= CHUNK_BYTES:
        return _chunk_output(data, first_chunk)
    # The left subtree holds the largest power-of-two number of chunks that
    # leaves at least one byte for the right subtree.
    chunks = (len(data) - 1) // CHUNK_BYTES
    left_chunks = 1 << (chunks.bit_length() - 1)
    split = left_chunks * CHUNK_BYTES
    left = _subtree(data[:split], first_chunk).chaining_value()
    right = _subtree(data[split:], first_chunk + left_chunks).chaining_value()
    return _Output(list(IV), left + right, 0, BLOCK_BYTES, PARENT)


def blake3(data: bytes, length: int = 32) -> bytes:
    """BLAKE3 hash of `data` in the default mode, `length` bytes long."""
    return _subtree(bytes(data), 0).root_bytes(length)


def self_check() -> list[str]:
    """Differences between this implementation and the published vectors."""
    errors = []
    for length, expected in PUBLISHED_VECTORS.items():
        message = bytes(index % 251 for index in range(length))
        actual = blake3(message).hex()
        if actual != expected:
            errors.append(f"BLAKE3 of the {length}-byte test input is {actual}, published {expected}")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Check the published vectors, then print the digest of each named file."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", type=Path, help="files to hash")
    args = parser.parse_args(argv)
    errors = self_check()
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    for path in args.paths:
        try:
            print(f"{blake3(path.read_bytes()).hex()}  {path}")
        except OSError as error:
            print(f"{path}: {error}", file=sys.stderr)
            return 1
    if not args.paths:
        print(f"{len(PUBLISHED_VECTORS)} published BLAKE3 vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
