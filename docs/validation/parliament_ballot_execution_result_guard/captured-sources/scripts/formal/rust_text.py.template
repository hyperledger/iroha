"""Pure Rust masking with bounded reuse of exact immutable text.

The limit covers retained source/result strings and the OrderedDict container,
not RSS, cold lexer temporaries, caller-owned inputs or other checker caches.
This module knows nothing about paths, Git, source authority or manifests.
"""

from __future__ import annotations

from collections import OrderedDict
import sys
from threading import Lock


_MAX_MASK_CACHE_BYTES = 64 * 1024 * 1024
_MAX_MASK_CACHE_ENTRIES = 2048


class _MaskCache:
    """An exact-string LRU; failed scans never publish a cache entry."""

    def __init__(self, max_bytes: int, max_entries: int) -> None:
        if max_bytes < sys.getsizeof(OrderedDict()) or max_entries < 1:
            raise ValueError("mask cache limits cannot hold an empty cache")
        self._max_bytes = max_bytes
        self._max_entries = max_entries
        self._values: OrderedDict[str, str] = OrderedDict()
        self._string_bytes = 0
        self._hits = 0
        self._misses = 0
        self._lock = Lock()

    def _retained_bytes(self) -> int:
        return self._string_bytes + sys.getsizeof(self._values)

    def _evict_oldest(self) -> None:
        source, masked = self._values.popitem(last=False)
        self._string_bytes -= sys.getsizeof(source) + sys.getsizeof(masked)
        if not self._values:
            # Release the dictionary's otherwise retained high-water storage.
            self._values = OrderedDict()

    def mask(self, source: str) -> str:
        # Restrict keys to immutable builtin strings, not user-defined equality.
        if type(source) is not str:
            raise TypeError("Rust mask source must be a builtin str")
        with self._lock:
            if source in self._values:
                self._hits += 1
                self._values.move_to_end(source)
                return self._values[source]
            self._misses += 1
        masked = _mask_rust_comments_uncached(source)
        weight = sys.getsizeof(source) + sys.getsizeof(masked)
        with self._lock:
            # Another caller may have published this exact text during the scan.
            if source in self._values:
                self._values.move_to_end(source)
                return self._values[source]
            if weight + sys.getsizeof(OrderedDict()) > self._max_bytes:
                return masked
            while self._values and (
                len(self._values) >= self._max_entries
                or self._retained_bytes() + weight > self._max_bytes
            ):
                self._evict_oldest()
            self._values[source] = masked
            self._string_bytes += weight
            # Account for actual container growth, not an estimated node size.
            while self._values and self._retained_bytes() > self._max_bytes:
                self._evict_oldest()
        return masked

    def clear(self) -> None:
        with self._lock:
            self._values = OrderedDict()
            self._string_bytes = self._hits = self._misses = 0

    def info(self) -> dict[str, int]:
        with self._lock:
            return {
                "entries": len(self._values),
                "retained_bytes": self._retained_bytes(),
                "hits": self._hits,
                "misses": self._misses,
                "max_bytes": self._max_bytes,
                "max_entries": self._max_entries,
            }


_MASK_CACHE = _MaskCache(_MAX_MASK_CACHE_BYTES, _MAX_MASK_CACHE_ENTRIES)


def mask_rust_comments(source: str) -> str:
    """Reuse only an exact text result; callers must authenticate source first."""
    return _MASK_CACHE.mask(source)


def _clear_mask_cache() -> None:
    _MASK_CACHE.clear()


def _mask_cache_info() -> dict[str, int]:
    return _MASK_CACHE.info()


def _mask_rust_comments_uncached(source: str) -> str:
    """Mask Rust comments and literals while preserving byte offsets and lines."""

    output = list(source)

    def mask(start: int, end: int) -> None:
        for offset in range(start, end):
            if output[offset] != "\n":
                output[offset] = " "

    index = 0
    length = len(source)
    state = "code"
    raw_hashes = 0
    literal_start = 0
    while index < length:
        char = source[index]
        pair = source[index : index + 2]
        if state == "string":
            if char == "\\":
                index += 2
            else:
                if char == '"':
                    index += 1
                    mask(literal_start, index)
                    state = "code"
                else:
                    index += 1
            continue
        if state == "char":
            if char == "\\":
                index += 2
            else:
                if char == "'":
                    index += 1
                    mask(literal_start, index)
                    state = "code"
                else:
                    index += 1
            continue
        if state == "raw-string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                index += len(terminator)
                mask(literal_start, index)
                state = "code"
            else:
                index += 1
            continue

        if pair == "//":
            end = source.find("\n", index + 2)
            end = length if end < 0 else end
            mask(index, end)
            index = end
            continue
        if pair == "/*":
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            mask(index, end)
            index = end
            continue
        raw_prefix = None
        for prefix in ("br", "cr", "r"):
            if source.startswith(prefix, index):
                cursor = index + len(prefix)
                while cursor < length and source[cursor] == "#":
                    cursor += 1
                if cursor < length and source[cursor] == '"':
                    raw_prefix = (cursor - index - len(prefix), cursor + 1)
                    break
        if raw_prefix is not None:
            literal_start = index
            raw_hashes, index = raw_prefix
            state = "raw-string"
            continue
        if source.startswith(('b"', 'c"'), index):
            literal_start = index
            state = "string"
            index += 2
            continue
        if char == '"':
            literal_start = index
            state = "string"
            index += 1
            continue
        char_quote = index + 1 if source.startswith("b'", index) else index
        if source[char_quote : char_quote + 1] == "'":
            value = char_quote + 1
            if value < length and source[value] == "\\":
                value += 1
                if source[value : value + 2] == "u{":
                    closing_brace = source.find("}", value + 2)
                    value = length if closing_brace < 0 else closing_brace + 1
                elif source[value : value + 1] == "x":
                    value += 3
                else:
                    value += 1
            else:
                value += 1
            is_char_literal = value < length and source[value] == "'"
        else:
            is_char_literal = False
        if is_char_literal:
            literal_start = index
            state = "char"
            index = char_quote + 1
            continue
        index += 1
    if state in {"string", "char", "raw-string"}:
        mask(literal_start, length)
    return "".join(output)
