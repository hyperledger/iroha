#!/usr/bin/env python3
"""Validate the FHE and plaintext consumer ownership inventory against the source tree.

Requires Python 3.9+ and its standard library; no environment variables or
installed packages are needed. In a Git checkout the file list comes from
`git ls-files` (tracked and unignored files); elsewhere the tree is walked.
The default inventory is specs/fhe_ownership_inventory.json relative to this
script's repository; it is the task C.1 output of specs/zk_delivery_plan.md.
The check is read-only. It establishes that the inventory matches the tree; it
does not establish cryptographic security or readiness.

The check fails when
* a listed path, Rust item, identifier or literal no longer exists;
* a recorded conditional-compilation chain or `test_only` flag differs from the
  one derived from the crate module tree, item attributes and embedding sites;
* a reusable primitive has no owner, more than one owner, a test-only canonical
  source, an owner above one of its implementations, or an implementation
  claimed by two entries;
* the layer list omits a manifest dependency between two listed crates;
* the recorded production callers of an implementation differ from the
  production functions that call it or pass it as a value;
* in an owner file (every production-compiled Rust file of an `every_function`
  scope, and every file holding a production primitive implementation) a
  production function is not assigned to exactly one primitive, distinct owner
  or protocol-logic component, or a test-gated function or inline test module
  is not assigned to exactly one test-only reference;
* elsewhere, a production function with an arithmetic kernel name is not listed;
* a protocol-logic component of the fail-closed ZK-AMS surface declares an
  executing operation, or that surface holds a ring-arithmetic implementation;
* a file is listed twice, its recorded detection patterns differ from a fresh
  scan, or the scan finds a file the inventory does not list;
* a file naming the RAM-LFE HKDF backend is recorded as unrelated HKDF, an HKDF
  file has no classification, a function that instantiates HKDF in a backend or
  plaintext-PRF file is unaccounted for, or the plaintext PRF shares a symbol
  with the backend;
* a required current-state claim, reference kind, preserved oracle, no-effect
  anchor or plaintext PRF entry is missing;
* a generated consumer or current-state claim loses its evidence;
* the planned destination crate exists while the inventory still records it as
  planned.

Limits of the check:
* Rust is read with a structural scanner, not a compiler. Functions that only a
  macro expansion creates are invisible, and only functions and inline test
  modules are assigned one by one: types, constants and statics are anchored
  where an entry names them.
* Callers are attributed without type inference. Where the receiver type of a
  method call or the definition behind a bare call cannot be established, the
  occurrence is not counted and the record is marked `callers_exhaustive: false`.
* Arithmetic outside the arithmetic scopes that matches no detection pattern is
  not inventoried (other proof fields, curves, signatures, erasure coding).

Maintainer modes (the default run changes nothing):
* `--print-scan` prints the fresh file-to-pattern scan as JSON.
* `--refresh` prints the inventory with every derived fact recomputed from the
  tree: file patterns, cfg chains, `test_only` flags, caller maps and the
  function assignment. Functions and files it cannot classify are put under
  `unassigned` and `unclassified` keys, which the check rejects until a
  maintainer moves them. Classifications are never changed.
* `--refresh --write` writes that result over the inventory file.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterable, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAP = "specs/fhe_ownership_inventory.json"
SCHEMA_VERSION = 2
SCOPE = "Inventory consistency only; not code or cryptographic qualification."

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Hits inside opaque payload runs (base64 and similar) are ignored; no Rust, Kotlin,
# Swift, JavaScript, Python or C# identifier in the tree is this long.
OPAQUE_RUN_LENGTH = 96
# Split identifiers into lower-case words at `_`, digit and camel-case boundaries.
WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+")

# A file matches a word pattern when one identifier in it contains every word of
# a listed sequence consecutively. Kebab-case tags are matched as literals.
WORD_PATTERNS: dict[str, tuple[tuple[str, ...], ...]] = {
    "ntt": (("ntt",), ("intt",)),
    "rns": (("rns",),),
    "bfv": (("bfv",),),
    "bgv": (("bgv",),),
    "mkhe": (("mkhe",),),
    "fhe": (("fhe",),),
    "negacyclic": (("negacyclic",),),
    "basis_conversion": (
        ("basis", "extension"),
        ("basis", "extend"),
        ("basis", "conversion"),
        ("basis", "convert"),
        ("crt", "reconstruct"),
        ("crt", "reconstruction"),
    ),
    "ram_lfe": (("ram", "lfe"), ("ramlfe",)),
    "hkdf": (("hkdf",),),
    "hkdf_ram_lfe": (
        ("hkdf", "sha", "3", "512", "prf"),
        ("evaluate", "hkdf", "prf"),
    ),
}
LITERAL_PATTERNS: dict[str, tuple[str, ...]] = {
    "ram_lfe": ("ram-lfe",),
    "hkdf_ram_lfe": ("hkdf-sha3-512-prf-v1",),
}
PATTERN_IDS = tuple(sorted(set(WORD_PATTERNS) | set(LITERAL_PATTERNS)))


def identifier_words(identifier: str) -> tuple[str, ...]:
    """Return the lower-case words of one snake-case or camel-case identifier."""
    return tuple(word.lower() for word in WORD.findall(identifier))


def _contains_sequence(words: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    span = len(sequence)
    return any(words[index : index + span] == sequence for index in range(len(words) - span + 1))


# The locator word of each sequence; rarer words keep the scan fast.
ANCHOR_WORDS: dict[str, tuple[str, ...]] = {
    "basis_conversion": ("basis", "crt"),
    "ram_lfe": ("lfe", "ramlfe"),
    "hkdf_ram_lfe": ("hkdf",),
}


def _anchor(pattern: str) -> tuple[tuple[str, ...], "re.Pattern[str]"]:
    sequences = WORD_PATTERNS[pattern]
    words = ANCHOR_WORDS.get(pattern) or tuple(sorted({sequence[0] for sequence in sequences}))
    if not all(any(word in sequence for word in words) for sequence in sequences):
        raise AssertionError(f"pattern {pattern} has a sequence without an anchor word")
    forms = sorted({form for word in words for form in (word, word.capitalize(), word.upper())})
    return words, re.compile("(?:" + "|".join(re.escape(form) for form in forms) + ")(?![a-z])")


# One literal-first locator per pattern; every hit is confirmed on the word
# boundaries of the identifier that surrounds it.
_ANCHORS = {pattern: _anchor(pattern) for pattern in WORD_PATTERNS}
_IDENTIFIER_RUN = re.compile(r"[A-Za-z0-9_]*")
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9+/=]*")


def _run_around(text: str, start: int, end: int, run: "re.Pattern[str]") -> tuple[int, int]:
    """Expand a hit over one alphabet, looking at most one opaque run length each way."""
    low = max(0, start - OPAQUE_RUN_LENGTH)
    before = run.match(text[low:start][::-1])
    after = run.match(text, end, min(len(text), end + OPAQUE_RUN_LENGTH))
    return start - (before.end() if before else 0), after.end() if after else end


def scan_text(text: str) -> list[str]:
    """Return the sorted detection pattern identifiers matched by one text."""
    lowered = text.lower()
    found = {
        pattern for pattern, literals in LITERAL_PATTERNS.items()
        if any(literal in lowered for literal in literals)
    }
    for pattern, (words, locator) in _ANCHORS.items():
        if pattern in found or not any(word in lowered for word in words):
            continue
        rejected: set[str] = set()
        for match in locator.finditer(text):
            start, end = _run_around(text, match.start(), match.end(), _IDENTIFIER_RUN)
            identifier = text[start:end]
            if identifier in rejected:
                continue
            rejected.add(identifier)
            if not any(_contains_sequence(identifier_words(identifier), sequence) for sequence in WORD_PATTERNS[pattern]):
                continue
            run_start, run_end = _run_around(text, match.start(), match.end(), _OPAQUE_RUN)
            if run_end - run_start < OPAQUE_RUN_LENGTH:
                found.add(pattern)
                break
    return sorted(found)


# ---------------------------------------------------------------------------
# Rust source structure
# ---------------------------------------------------------------------------

_RUST_SKIP = re.compile(
    r"""//[^\n]*
      | /\*
      | b?r(?P<hashes>\#*)"
      | b?c?"(?:[^"\\]|\\.)*"
      | b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|.)|[^\\'\n])'
    """,
    re.VERBOSE | re.DOTALL,
)


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def mask_rust(source: str) -> str:
    """Replace comments and literal contents with spaces, preserving offsets and lines."""
    pieces: list[str] = []
    cursor = 0
    length = len(source)
    while cursor < length:
        match = _RUST_SKIP.search(source, cursor)
        if match is None:
            pieces.append(source[cursor:])
            break
        start = match.start()
        pieces.append(source[cursor:start])
        token = match.group(0)
        if token == "/*":
            depth = 1
            end = start + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            pieces.append(_blank(source[start:end]))
            cursor = end
        elif token.startswith("//"):
            pieces.append(_blank(token))
            cursor = match.end()
        elif match.group("hashes") is not None:
            closing = '"' + match.group("hashes")
            end = source.find(closing, match.end())
            end = length if end < 0 else end + len(closing)
            pieces.append(_blank(source[start:end]))
            cursor = end
        else:
            pieces.append(_blank(token))
            cursor = match.end()
    return "".join(pieces)


_STRUCTURE = re.compile(r"[{}()\[\];]")
_ITEM = re.compile(
    r"""(?:pub(?:\s*\([^)]*\))?\s+)?
        (?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?
        (?P<kind>(?:fn|struct|enum|union|trait|mod|type|static|const|impl)\b|macro_rules\s*!)
        (?P<rest>.*)""",
    re.VERBOSE | re.DOTALL,
)
_NAME = re.compile(r"\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)")
_CFG = re.compile(r"#!?\[\s*cfg\s*\((.*)\)\s*\]\Z", re.DOTALL)
_PATH_ATTRIBUTE = re.compile(r'#\[\s*path\s*=\s*"([^"]*)"\s*\]')


_USE_STATEMENT = re.compile(r"(?<![A-Za-z0-9_])use\s+([^;{}]*(?:\{[^;]*\})?[^;{}]*);")
_USE_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|::|[{},*]")


def _parse_use_tree(tokens: list[str], position: int, prefix: tuple[str, ...],
                    bindings: list[tuple[tuple[str, ...], str]]) -> int:
    """Append the leaves of one use tree and return the position after it."""
    segments = list(prefix)
    while True:
        token = tokens[position]
        if token == "{":
            position += 1
            while tokens[position] != "}":
                position = _parse_use_tree(tokens, position, tuple(segments), bindings)
                if tokens[position] == ",":
                    position += 1
            return position + 1
        if token == "*":
            bindings.append((tuple(segments) + ("*",), "*"))
            return position + 1
        if token in ("::", ",", "}"):
            raise IndexError("path segment expected")
        segments.append(token)
        position += 1
        if position < len(tokens) and tokens[position] == "::":
            position += 1
            continue
        break
    bound = segments[-1]
    if position < len(tokens) and tokens[position] == "as":
        bound = tokens[position + 1]
        position += 2
    path = tuple(segments)
    if path[-1] == "self":
        # `module::{self}` and `module::{self as alias}` bind the module itself.
        path = path[:-1]
        if bound == "self":
            bound = path[-1] if path else "self"
    if path:
        bindings.append((path, bound))
    return position


def use_bindings(masked: str) -> list[tuple[tuple[str, ...], str]]:
    """Return `(path, local name)` for every leaf of every `use` declaration of a masked source.

    `use a::{b as c, d::{self as e, f}, g::*};` yields `(("a", "b"), "c")`,
    `(("a", "d"), "e")`, `(("a", "d", "f"), "f")` and `(("a", "g", "*"), "*")`.
    A declaration this small grammar cannot parse contributes nothing.
    """
    bindings: list[tuple[tuple[str, ...], str]] = []
    for statement in _USE_STATEMENT.finditer(masked):
        tokens = _USE_TOKEN.findall(statement.group(1))
        if tokens and tokens[0] == "::":
            tokens = tokens[1:]
        leaves: list[tuple[tuple[str, ...], str]] = []
        try:
            if _parse_use_tree(tokens, 0, (), leaves) != len(tokens):
                continue
        except IndexError:
            continue
        bindings.extend(leaves)
    return bindings


def normalize_cfg(expression: str) -> str:
    """Normalize one cfg predicate for comparison."""
    compact = re.sub(r"\s+", "", expression)
    compact = compact.replace(",)", ")")
    return compact.replace(",", ", ").replace("=", " = ")


class RustItem:
    """One Rust item or block with its attributes and enclosing item."""

    __slots__ = ("kind", "name", "start", "body_start", "end", "cfgs", "parent", "visibility", "path_attribute")

    def __init__(self, kind: str, name: str, start: int, body_start: Optional[int], end: int,
                 cfgs: tuple[str, ...], parent: Optional["RustItem"], visibility: str,
                 path_attribute: Optional[str]) -> None:
        self.kind = kind
        self.name = name
        self.start = start
        self.body_start = body_start
        self.end = end
        self.cfgs = cfgs
        self.parent = parent
        self.visibility = visibility
        self.path_attribute = path_attribute

    def cfg_chain(self) -> tuple[str, ...]:
        """Return cfg predicates from the outermost enclosing block to this item."""
        chain: list[str] = []
        node: Optional[RustItem] = self
        while node is not None:
            chain[0:0] = node.cfgs
            node = node.parent
        return tuple(chain)

    def ancestors(self) -> list["RustItem"]:
        """Return the enclosing items and blocks, innermost first."""
        result = []
        node = self.parent
        while node is not None:
            result.append(node)
            node = node.parent
        return result


def _split_attributes(raw: str, header: str, offset: int) -> tuple[list[str], int]:
    """Return leading attributes (with literal contents) and the offset after them."""
    attributes: list[str] = []
    cursor = 0
    length = len(header)
    while True:
        while cursor < length and header[cursor].isspace():
            cursor += 1
        if not (header.startswith("#[", cursor) or header.startswith("#![", cursor)):
            return attributes, cursor
        depth = 0
        end = cursor
        while end < length:
            if header[end] == "[":
                depth += 1
            elif header[end] == "]":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1
        attributes.append(raw[offset + cursor : offset + end])
        cursor = end


def _impl_name(rest: str) -> str:
    """Return the self type name of an impl header."""
    text = rest
    if text.lstrip().startswith("<"):
        depth = 0
        for index, character in enumerate(text):
            if character == "<":
                depth += 1
            elif character == ">" and text[index - 1] != "-":
                depth -= 1
                if depth == 0:
                    text = text[index + 1 :]
                    break
    text = re.split(r"\bwhere\b", text)[0]
    parts = re.split(r"\bfor\b", text)
    target = parts[-1].strip()
    target = re.sub(r"^(?:&\s*)?(?:'[A-Za-z_]+\s+)?(?:mut\s+)?(?:dyn\s+)?", "", target)
    match = re.match(r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Za-z_][A-Za-z0-9_]*)", target)
    return match.group(1) if match else ""


class RustSource:
    """Indexed items, bodiless statements and inner attributes of one Rust file."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.masked = mask_rust(source)
        self.items: list[RustItem] = []
        self.inner_cfgs: tuple[str, ...] = ()
        self._ordered: Optional[tuple[list[int], list[RustItem]]] = None
        self._use_bindings: Optional[list[tuple[tuple[str, ...], str]]] = None
        self._index()

    def use_bindings(self) -> list[tuple[tuple[str, ...], str]]:
        """Return `(path, local name)` for every leaf of every `use` declaration of the file."""
        if self._use_bindings is None:
            self._use_bindings = use_bindings(self.masked)
        return self._use_bindings

    def _make(self, raw_header_start: int, header_end: int, body_start: Optional[int],
              parent: Optional[RustItem]) -> RustItem:
        header = self.masked[raw_header_start:header_end]
        attributes, consumed = _split_attributes(self.source, header, raw_header_start)
        cfgs = []
        path_attribute = None
        for attribute in attributes:
            cfg = _CFG.match(attribute.strip())
            if cfg:
                cfgs.append(normalize_cfg(cfg.group(1)))
            path = _PATH_ATTRIBUTE.match(attribute.strip())
            if path:
                path_attribute = path.group(1)
        body = header[consumed:]
        start = raw_header_start + consumed
        match = _ITEM.match(body)
        kind = "block"
        name = ""
        visibility = ""
        if match:
            kind = "macro_rules" if match.group("kind").startswith("macro_rules") else match.group("kind")
            visibility_match = re.match(r"pub(?:\s*\([^)]*\))?", body)
            visibility = re.sub(r"\s+", "", visibility_match.group(0)) if visibility_match else ""
            if kind == "impl":
                name = _impl_name(match.group("rest"))
            else:
                named = _NAME.match(match.group("rest"))
                name = named.group(1) if named else ""
                if kind == "const" and name == "fn":
                    kind = "block"
            if not name:
                kind = "block"
        return RustItem(kind, name, start, body_start, header_end, tuple(cfgs), parent, visibility, path_attribute)

    def _index(self) -> None:
        masked = self.masked
        inner = []
        for attribute in re.finditer(r"#!\[\s*cfg\s*\(", masked):
            # Inner attributes apply only when they precede every item of the file.
            prefix = masked[: attribute.start()]
            if re.fullmatch(r"(?:\s|#!\[[^\]]*\])*", prefix):
                depth = 0
                end = attribute.start()
                while end < len(masked):
                    if masked[end] == "[":
                        depth += 1
                    elif masked[end] == "]":
                        depth -= 1
                        if depth == 0:
                            break
                    end += 1
                cfg = _CFG.match(self.source[attribute.start() : end + 1])
                if cfg:
                    inner.append(normalize_cfg(cfg.group(1)))
        self.inner_cfgs = tuple(inner)

        # Stack entries: (opener, item or None, statement start to restore on close).
        stack: list[tuple[str, Optional[RustItem], int]] = []
        statement_start = 0
        current: Optional[RustItem] = None
        for match in _STRUCTURE.finditer(masked):
            position = match.start()
            character = match.group(0)
            top = stack[-1][0] if stack else "{"
            if character in "([":
                stack.append((character, None, statement_start))
            elif character in ")]":
                if stack and stack[-1][0] in "([":
                    stack.pop()
            elif character == ";":
                if top == "{":
                    item = self._make(statement_start, position, None, current)
                    item.end = position + 1
                    if item.kind != "block":
                        self.items.append(item)
                    statement_start = position + 1
            elif character == "{":
                if top == "{":
                    item = self._make(statement_start, position, position, current)
                    self.items.append(item)
                    stack.append(("{", item, -1))
                    current = item
                else:
                    stack.append(("{", None, statement_start))
                statement_start = position + 1
            else:  # "}"
                while stack and stack[-1][0] in "([":
                    stack.pop()
                if stack:
                    _, item, restore = stack.pop()
                    if item is not None:
                        item.end = position + 1
                        current = item.parent
                        statement_start = position + 1
                    else:
                        statement_start = restore
                else:
                    statement_start = position + 1

    def named_items(self) -> list[RustItem]:
        """Return the items that carry a name, excluding anonymous blocks."""
        return [item for item in self.items if item.kind != "block"]

    def resolve(self, symbol: str) -> list[RustItem]:
        """Return the items named by `Name` or a `Container::Name` chain."""
        parts = symbol.split("::")
        candidates = [item for item in self.named_items() if item.name == parts[-1]]
        definitions = [item for item in candidates if item.kind != "impl"]
        if definitions:
            candidates = definitions
        if len(parts) == 1:
            return candidates
        result = []
        for item in candidates:
            containers = [ancestor.name for ancestor in item.ancestors() if ancestor.kind != "block"]
            expected = list(reversed(parts[:-1]))
            if containers[: len(expected)] == expected:
                result.append(item)
        if result:
            return result
        # Enum variants, struct fields and associated items declared without a body.
        owners = self.resolve("::".join(parts[:-1]))
        token = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(parts[-1]) + r"(?![A-Za-z0-9_])")
        for owner in owners:
            if owner.body_start is None:
                continue
            found = token.search(self.masked, owner.body_start, owner.end)
            if found:
                result.append(RustItem("member", parts[-1], found.start(), None, found.end(), (), owner, "", None))
        return result


# ---------------------------------------------------------------------------
# Repository files and Rust module reachability
# ---------------------------------------------------------------------------

NON_PRODUCTION_ROLES = ("test", "bench", "example")
_WALK_SKIP = {".git", "target", "node_modules", "build", ".gradle", "__pycache__", ".build", "dist"}


def list_repository_files(root: Path) -> list[str]:
    """Return tracked and unignored repository files as sorted POSIX paths."""
    if (root / ".git").exists():
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, capture_output=True, check=False,
        )
        if completed.returncode == 0:
            names = [name for name in completed.stdout.decode("utf-8", "surrogateescape").split("\0") if name]
            return sorted(name for name in set(names) if (root / name).is_file())
    names = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = sorted(name for name in subdirectories if name not in _WALK_SKIP)
        for name in files:
            names.append((Path(directory) / name).relative_to(root).as_posix())
    return sorted(names)


class Tree:
    """Cached read-only view of the repository files used by one check."""

    def __init__(self, root: Path, files: Optional[Iterable[str]] = None) -> None:
        self.root = root
        self.files = sorted(files) if files is not None else list_repository_files(root)
        self.file_set = set(self.files)
        self._text: dict[str, Optional[str]] = {}
        self._rust: dict[str, RustSource] = {}
        self._crates: dict[str, "CrateModules"] = {}
        self._embeds: Optional[dict[str, list[tuple[str, int]]]] = None
        self._embedded: dict[tuple[str, tuple[str, ...]], bool] = {}

    def embedding_sites(self) -> dict[str, list[tuple[str, int]]]:
        """Return, per embedded file, the Rust files and offsets that `include_str!` or `include_bytes!` it."""
        if self._embeds is None:
            sites: dict[str, list[tuple[str, int]]] = {}
            for path in self.files:
                if not path.endswith(".rs"):
                    continue
                try:
                    data = (self.root / path).read_bytes()
                except OSError:
                    continue
                if b"include_str" not in data and b"include_bytes" not in data:
                    continue
                text = data.decode("utf-8", "replace")
                directory = PurePosixPath(path).parent.as_posix()
                for match in _EMBED.finditer(text):
                    target = embedded_path(text, match.end(), "" if directory == "." else directory, self.crate_of(path))
                    if target is not None and target in self.file_set:
                        sites.setdefault(target, []).append((path, match.start()))
            self._embeds = sites
        return self._embeds

    def production_embedded(self, path: str, development_features: Iterable[str]) -> bool:
        """Return whether a production Rust item embeds a file through `include_str!` or `include_bytes!`."""
        features = tuple(sorted(development_features))
        key = (path, features)
        if key not in self._embedded:
            result = False
            for rust_path, offset in self.embedding_sites().get(path, []):
                source = self.rust(rust_path)
                if source is None or not source.masked.startswith("include_", offset):
                    continue
                if file_facts(self, rust_path, features)[1]:
                    continue
                item = _enclosing_item(source, offset)
                chain = item.cfg_chain() if item is not None else ()
                if not any(is_test_cfg(cfg, features) for cfg in chain):
                    result = True
                    break
            self._embedded[key] = result
        return self._embedded[key]

    def text(self, path: str) -> Optional[str]:
        """Return a file's text, or None for missing and binary files."""
        if path not in self._text:
            value: Optional[str] = None
            target = self.root / path
            if path in self.file_set and target.is_file():
                data = target.read_bytes()
                if b"\0" not in data[:8192]:
                    value = data.decode("utf-8", "replace")
            self._text[path] = value
        return self._text[path]

    def rust(self, path: str) -> Optional[RustSource]:
        """Return the indexed Rust source of a file, or None when it has no text."""
        if path not in self._rust:
            text = self.text(path)
            if text is None:
                return None
            self._rust[path] = RustSource(text)
        return self._rust[path]

    def crate_of(self, path: str) -> Optional[str]:
        """Return the directory of the nearest enclosing Cargo package."""
        parts = PurePosixPath(path).parts
        for depth in range(len(parts) - 1, -1, -1):
            directory = "/".join(parts[:depth])
            manifest = f"{directory}/Cargo.toml" if directory else "Cargo.toml"
            if manifest in self.file_set and "[package]" in (self.text(manifest) or ""):
                return directory
        return None

    def crate_modules(self, crate: str) -> "CrateModules":
        """Return the cached module resolver of one Cargo package."""
        if crate not in self._crates:
            self._crates[crate] = CrateModules(self, crate)
        return self._crates[crate]

    def reaches(self, path: str) -> list[tuple[str, tuple[str, ...]]]:
        """Return every (target role, cfg chain) through which a Rust file is compiled."""
        crate = self.crate_of(path)
        if crate is None:
            return []
        return self.crate_modules(crate).reaches(path)


_MANIFEST_SECTION = re.compile(r"^\[\[?([A-Za-z0-9_.\-\"' ]+)\]\]?\s*$")
_MANIFEST_PATH = re.compile(r'^path\s*=\s*"([^"]+)"')
_PLACED_CHILD = re.compile(r'(?:#\[\s*path\s*=\s*|\binclude\s*!\s*\(\s*)"([^"]+\.rs)"')
_ESCAPING_CHILD = re.compile(r'(?:#\[\s*path\s*=\s*|\binclude\s*!\s*\(\s*)"\.\./[^"]*\.rs"')
_EMBED = re.compile(r"\binclude_(?:str|bytes)\s*!\s*\(")
_STRING_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')


def normalize_path(*parts: str) -> str:
    """Join POSIX path parts and resolve `.` and `..` segments lexically."""
    normalized: list[str] = []
    for part in PurePosixPath(*[part for part in parts if part]).parts:
        if part == "..":
            if normalized:
                normalized.pop()
        elif part not in (".", "/"):
            normalized.append(part)
    return "/".join(normalized)


def embedded_path(text: str, start: int, directory: str, crate: Optional[str]) -> Optional[str]:
    """Resolve the file named by an `include_str!`/`include_bytes!` argument that begins at `start`.

    A plain literal is relative to the including file's directory. A
    `concat!(env!("CARGO_MANIFEST_DIR"), ...)` argument is relative to the
    package directory. Any other environment-derived path is not resolved.
    """
    depth = 1
    cursor = start
    limit = min(len(text), start + 1024)
    while cursor < limit and depth:
        character = text[cursor]
        if character == '"':
            literal = _STRING_LITERAL.match(text, cursor)
            cursor = literal.end() if literal else cursor + 1
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        cursor += 1
    if depth:
        return None
    argument = text[start : cursor - 1]
    literals = _STRING_LITERAL.findall(argument)
    if "env!" in argument:
        if "CARGO_MANIFEST_DIR" not in literals or crate is None:
            return None
        literals.remove("CARGO_MANIFEST_DIR")
        directory = crate
    if not literals:
        return None
    return normalize_path(directory, "".join(literals).lstrip("/"))


class CrateModules:
    """Resolve under which targets and cfg predicates a Cargo package compiles a file.

    Module files are parsed lazily: answering for one file reads only the
    module files on the way from each crate root to it.
    """

    def __init__(self, tree: Tree, crate: str) -> None:
        self.tree = tree
        self.crate = crate
        self.roots = self._roots()
        self._children: dict[tuple[str, bool], list[tuple[str, tuple[str, ...], bool]]] = {}
        self._reaches: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
        self._placements: dict[tuple[str, bool], tuple[str, tuple[str, ...]]] = {}
        self._escaping: Optional[tuple[str, ...]] = None

    _join = staticmethod(normalize_path)

    def _roots(self) -> list[tuple[str, str]]:
        tree = self.tree
        prefix = f"{self.crate}/" if self.crate else ""
        roots: dict[str, str] = {}

        def add(path: str, role: str) -> None:
            """Record an existing target root once, keeping its first role."""
            if path in tree.file_set and path not in roots:
                roots[path] = role

        section = ""
        for line in (tree.text(f"{prefix}Cargo.toml") or "").splitlines():
            header = _MANIFEST_SECTION.match(line.strip())
            if header:
                section = header.group(1).strip()
                continue
            declared = _MANIFEST_PATH.match(line.strip())
            if declared and section in ("lib", "bin", "test", "bench", "example"):
                add(self._join(self.crate, declared.group(1)), section)
        add(f"{prefix}src/lib.rs", "lib")
        add(f"{prefix}src/main.rs", "bin")
        add(f"{prefix}build.rs", "build")
        for path in tree.files:
            if not path.startswith(prefix) or not path.endswith(".rs"):
                continue
            relative = PurePosixPath(path[len(prefix):]).parts
            for directory, role in (("tests", "test"), ("benches", "bench"), ("examples", "example")):
                if relative[0] == directory and (len(relative) == 2 or (len(relative) == 3 and relative[2] == "main.rs")):
                    add(path, role)
            if relative[:2] == ("src", "bin") and (len(relative) == 3 or (len(relative) == 4 and relative[3] == "main.rs")):
                add(path, "bin")
        return sorted(roots.items())

    def _own_directory(self, path: str, is_root: bool) -> str:
        """Return the directory in which a module file's `mod name;` declarations resolve.

        `is_root` is true for target roots and for files reached through
        `#[path]` or `include!`: rustc treats all of them like `mod.rs`, so
        their child modules are siblings of the file.
        """
        file_path = PurePosixPath(path)
        directory = "" if file_path.parent.as_posix() == "." else file_path.parent.as_posix()
        return directory if is_root or file_path.name == "mod.rs" else self._join(directory, file_path.stem)

    def children(self, path: str, is_root: bool) -> list[tuple[str, tuple[str, ...], bool]]:
        """Return the files one module file declares or includes.

        Each entry carries the relative cfg chain and whether the child owns
        its directory (it was placed by `#[path]` or `include!`).
        """
        key = (path, is_root)
        if key in self._children:
            return self._children[key]
        result: list[tuple[str, tuple[str, ...], bool]] = []
        self._children[key] = result
        tree = self.tree
        source = tree.rust(path)
        if source is None:
            return result
        file_path = PurePosixPath(path)
        directory = "" if file_path.parent.as_posix() == "." else file_path.parent.as_posix()
        own_directory = self._own_directory(path, is_root)
        for item in source.items:
            if item.kind != "mod" or item.body_start is not None:
                continue
            inline = [ancestor.name for ancestor in reversed(item.ancestors()) if ancestor.kind == "mod"]
            if item.path_attribute is not None:
                base = self._join(own_directory, *inline) if inline else directory
                candidates = [self._join(base, item.path_attribute)]
            else:
                base = self._join(own_directory, *inline)
                candidates = [self._join(base, f"{item.name}.rs"), self._join(base, item.name, "mod.rs")]
            for candidate in candidates:
                if candidate in tree.file_set:
                    result.append((candidate, item.cfg_chain(), item.path_attribute is not None))
                    break
        for include in re.finditer(r"\binclude\s*!\s*\(\s*\"([^\"]+\.rs)\"\s*\)", source.source):
            if source.masked[include.start() : include.start() + 7] != "include":
                continue
            target = self._join(directory, include.group(1))
            if target not in tree.file_set:
                continue
            enclosing: tuple[str, ...] = ()
            for item in source.items:
                if item.body_start is not None and item.body_start < include.start() < item.end:
                    chain = item.cfg_chain()
                    if len(chain) >= len(enclosing):
                        enclosing = chain
            result.append((target, enclosing, True))
        return result

    def _placement(self, path: str, is_root: bool) -> tuple[str, tuple[str, ...]]:
        """Return the module's own directory and the files its `#[path]` and `include!` literals name.

        Only those two forms can place a child outside the own directory. The
        literals are read without parsing: a spurious candidate costs one parse.
        """
        key = (path, is_root)
        if key not in self._placements:
            own = self._own_directory(path, is_root)
            named: set[str] = set()
            text = self.tree.text(path) or ""
            if "#[path" in text or "include!(" in text:
                directory = PurePosixPath(path).parent.as_posix()
                directory = "" if directory == "." else directory
                for value in _PLACED_CHILD.findall(text):
                    for base in (directory, own):
                        candidate = self._join(base, value)
                        if candidate in self.tree.file_set:
                            named.add(candidate)
            self._placements[key] = (own, tuple(sorted(named)))
        return self._placements[key]

    def _escaping_files(self) -> tuple[str, ...]:
        """Return crate files whose `#[path]` or `include!` literal climbs out of its directory."""
        if self._escaping is None:
            prefix = f"{self.crate}/" if self.crate else ""
            found = []
            for path in self.tree.files:
                if path.startswith(prefix) and path.endswith(".rs"):
                    try:
                        data = (self.tree.root / path).read_bytes()
                    except OSError:
                        continue
                    if b'"../' in data and _ESCAPING_CHILD.search(data.decode("utf-8", "replace")):
                        found.append(path)
            self._escaping = tuple(found)
        return self._escaping

    def _may_contain(self, path: str, is_root: bool, target: str, seen: Optional[set[str]] = None) -> bool:
        """Return whether a module file can declare the target, directly or through descendants."""
        own, named = self._placement(path, is_root)
        if not own or target.startswith(own + "/"):
            return True
        seen = seen if seen is not None else {path}
        for child in named:
            if child == target:
                return True
            if child not in seen:
                seen.add(child)
                if self._may_contain(child, True, target, seen):
                    return True
        # A descendant declared in the standard layout may still climb out with `../`.
        return any(escaping.startswith(own + "/") for escaping in self._escaping_files())

    def _search(self, path: str, is_root: bool, role: str, chain: tuple[str, ...], target: str,
                found: list[tuple[str, tuple[str, ...]]], active: set[str]) -> None:
        if path == target:
            inner: tuple[str, ...] = ()
            if "#![cfg" in (self.tree.text(path) or ""):
                source = self.tree.rust(path)
                inner = source.inner_cfgs if source is not None else ()
            entry = (role, chain + inner)
            if entry not in found:
                found.append(entry)
            return
        if path in active or not self._may_contain(path, is_root, target):
            return
        active.add(path)
        source = self.tree.rust(path)
        inner_cfgs = source.inner_cfgs if source is not None else ()
        for child, relative, owns_directory in self.children(path, is_root):
            self._search(child, owns_directory, role, chain + inner_cfgs + relative, target, found, active)
        active.discard(path)

    def reaches(self, target: str) -> list[tuple[str, tuple[str, ...]]]:
        """Return every (target role, cfg chain) through which a file is compiled."""
        if target not in self._reaches:
            found: list[tuple[str, tuple[str, ...]]] = []
            for root, role in self.roots:
                self._search(root, True, role, (), target, found, set())
            self._reaches[target] = found
        return self._reaches[target]


# ---------------------------------------------------------------------------
# Source facts derived from the tree
# ---------------------------------------------------------------------------

# The inventory itself, this checker and the plan ledger quote identifiers
# without consuming them. Every other file is scanned, including the specs/ and
# docs/ trees. Markdown is prose: a Markdown file is listed only when it names
# the RAM-LFE HKDF backend that task R.6 retires, because that text must change
# with the code.
EXCLUDED_PATHS = (
    "scripts/check_fhe_ownership_map.py",
    "scripts/tests/check_fhe_ownership_map_test.py",
    "specs/fhe_ownership_inventory.json",
    "specs/zk_delivery_graph.json",
    "specs/zk_delivery_plan.md",
    "specs/zk_delivery_reconciliation.json",
    "todo_list.txt",
)
MARKDOWN_SUFFIXES = (".md",)
MARKDOWN_PATTERNS = ("hkdf", "hkdf_ram_lfe")
MARKDOWN_TRIGGER = "hkdf_ram_lfe"
GENERATED_REGISTRY = "generated-files.toml"
_TEST_DIRECTORIES = frozenset({"test", "tests", "Tests", "pytests", "testdata", "fixtures", "Fixtures"})

# Function names containing one of these word sequences denote ring, modular or
# proof-field arithmetic. The rule applies outside owner files, where every
# function is assigned individually whatever its name.
KERNEL_SEQUENCES: tuple[tuple[str, ...], ...] = (
    ("ntt",), ("intt",), ("invntt",), ("fft",), ("ifft",), ("negacyclic",),
    ("basis", "extend"), ("basis", "extension"), ("basis", "convert"), ("basis", "conversion"),
    ("crt",), ("garner",), ("montgomery",), ("barrett",), ("goldilocks",),
    ("mod", "add"), ("mod", "sub"), ("mod", "mul"), ("mod", "pow"), ("mod", "inv"), ("mod", "inverse"),
    ("mod", "neg"), ("mod", "q"), ("mod", "t"),
    ("add", "mod"), ("sub", "mod"), ("mul", "mod"), ("pow", "mod"), ("invert", "mod"), ("multiply", "mod"),
    ("poly", "add"), ("poly", "sub"), ("poly", "mul"), ("poly", "neg"), ("poly", "scalar"), ("poly", "pointwise"),
    ("automorphism",), ("bit", "reverse"), ("primitive", "root"), ("is", "prime"), ("decompose",),
    ("scale", "round"), ("scale", "and", "round"), ("div", "round"), ("lift",),
    ("twist",), ("untwist",), ("convolve",), ("reconstruct",), ("reduce",), ("rescale",),
    ("key", "switch"), ("keyswitch",), ("relinearize",), ("relinearization",),
    ("modulus", "switch"), ("mod", "switch"),
)


def is_kernel_name(name: str) -> bool:
    """Return whether a function name denotes a ring, modular or proof-field arithmetic kernel."""
    words = identifier_words(name)
    return any(_contains_sequence(words, sequence) for sequence in KERNEL_SEQUENCES)


def registered_generated_outputs(tree: Tree) -> set[str]:
    """Return output paths recorded by the generated file registry."""
    text = tree.text(GENERATED_REGISTRY) or ""
    outputs: set[str] = set()
    for block in re.finditer(r"(?ms)^outputs\s*=\s*\[(.*?)\]", text):
        outputs.update(re.findall(r'"([^"]+)"', block.group(1)))
    return outputs


def is_excluded(path: str) -> bool:
    """Return whether the scan ignores a path."""
    return path in EXCLUDED_PATHS


def scan_tree(tree: Tree) -> dict[str, list[str]]:
    """Return every unexcluded repository file that matches a detection pattern.

    A Markdown file is reported only when it names the RAM-LFE HKDF backend,
    and then with the HKDF patterns alone.
    """
    result: dict[str, list[str]] = {}
    for path in tree.files:
        if is_excluded(path):
            continue
        found = set(scan_text(path))
        try:
            data = (tree.root / path).read_bytes()
        except OSError:
            continue
        if b"\0" not in data[:8192]:
            found.update(scan_text(data.decode("latin-1")))
        if path.endswith(MARKDOWN_SUFFIXES):
            found = found & set(MARKDOWN_PATTERNS) if MARKDOWN_TRIGGER in found else set()
        if found:
            result[path] = sorted(found)
    return result


def is_test_cfg(expression: str, development_features: Iterable[str]) -> bool:
    """Return whether one cfg predicate holds only in tests, doctests or development fixtures."""
    if expression in ("test", "doctest") or expression.startswith(("all(test, ", "all(doctest, ")):
        return True
    match = re.fullmatch(r'any\(test, feature = "([^"]+)"\)', expression)
    return bool(match and match.group(1) in set(development_features))


def path_rule_test_only(path: str) -> bool:
    """Classify files outside a Cargo module tree by their directory convention."""
    parts = PurePosixPath(path).parts
    return any(part in _TEST_DIRECTORIES for part in parts[:-1])


def file_facts(tree: Tree, path: str, development_features: Iterable[str]) -> tuple[list[str], bool]:
    """Return the cfg predicates and test-only status under which a file is used.

    A Rust file follows the module tree of its package. Any other file follows
    its directory convention, except that a file embedded by a production Rust
    item through `include_str!` or `include_bytes!` is production.
    """
    if path.endswith(".rs"):
        reaches = tree.reaches(path)
        if reaches:
            test_only = all(
                role in NON_PRODUCTION_ROLES or any(is_test_cfg(cfg, development_features) for cfg in chain)
                for role, chain in reaches
            )
            return sorted({cfg for _, chain in reaches for cfg in chain}), test_only
        return [], path_rule_test_only(path)
    return [], path_rule_test_only(path) and not tree.production_embedded(path, development_features)


def qualified_name(item: RustItem) -> str:
    """Return an item's name prefixed by its enclosing named items."""
    names = [ancestor.name for ancestor in reversed(item.ancestors()) if ancestor.kind != "block"]
    return "::".join(names + [item.name])


def symbol_facts(tree: Tree, path: str, symbol: str, development_features: Iterable[str]) -> tuple[Optional[list[str]], bool, str]:
    """Resolve one symbol and return (item cfg chain, test-only status, error)."""
    text = tree.text(path)
    if text is None:
        return None, False, f"{path} is missing or binary"
    file_cfgs, file_test_only = file_facts(tree, path, development_features)
    if not path.endswith(".rs"):
        token = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])")
        if not token.search(text):
            return None, False, f"{path} does not contain identifier {symbol}"
        return [], file_test_only, ""
    source = tree.rust(path)
    assert source is not None
    items = source.resolve(symbol)
    if not items:
        return None, False, f"{path} does not define {symbol}"
    chains = {item.cfg_chain() for item in items}
    if len(chains) != 1:
        return None, False, f"{path} defines {symbol} under several cfg chains; qualify the symbol"
    chain = list(chains.pop())
    return chain, file_test_only or any(is_test_cfg(cfg, development_features) for cfg in chain), ""


def _enclosing_item(source: RustSource, offset: int) -> Optional[RustItem]:
    """Return the innermost item or block that contains an offset."""
    if source._ordered is None:
        ordered = sorted(source.items, key=lambda item: item.start)
        source._ordered = ([item.start for item in ordered], ordered)
    positions, ordered = source._ordered
    low, high = 0, len(positions)
    while low < high:
        middle = (low + high) // 2
        if positions[middle] <= offset:
            low = middle + 1
        else:
            high = middle
    item: Optional[RustItem] = ordered[low - 1] if low else None
    while item is not None and not (item.start <= offset < item.end):
        item = item.parent
    return item


def _enclosing_function(source: RustSource, offset: int) -> Optional[RustItem]:
    item = _enclosing_item(source, offset)
    while item is not None and item.kind != "fn":
        item = item.parent
    return item


def caller_scope(tree: Tree, path: str, listed: Iterable[str], visibility: str) -> list[str]:
    """Return the Rust files searched for callers of an item defined in `path`.

    A private item is visible to its module subtree, approximated by the files
    under the defining file's directory; `pub(...)` items to their crate; `pub`
    items also to every other listed Rust file.
    """
    crate = tree.crate_of(path)
    prefix = f"{crate}/" if crate else ""
    if not visibility:
        directory = PurePosixPath(path).parent.as_posix()
        prefix = "" if directory == "." else directory + "/"
    scope = {name for name in tree.files if name.endswith(".rs") and name.startswith(prefix)}
    if visibility == "pub":
        scope.update(name for name in listed if name.endswith(".rs"))
    return sorted(scope)


_IDENTIFIER_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_TRAILING_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_BINDING_KEYWORDS = frozenset({"fn", "let", "mut", "ref", "const", "static", "mod", "struct", "enum", "type", "trait", "for"})


def identifier_offsets(text: str, name: str) -> list[int]:
    """Return the offsets at which `name` occurs as a whole identifier."""
    offsets: list[int] = []
    length = len(name)
    position = text.find(name)
    while position >= 0:
        end = position + length
        if (position == 0 or text[position - 1] not in _IDENTIFIER_CHARACTERS) and (
            end == len(text) or text[end] not in _IDENTIFIER_CHARACTERS
        ):
            offsets.append(position)
        position = text.find(name, position + 1)
    return offsets


def _impl_owner(item: RustItem) -> Optional[str]:
    """Return the self type of the innermost impl or trait that encloses an item."""
    for ancestor in item.ancestors():
        if ancestor.kind in ("impl", "trait"):
            return ancestor.name
        if ancestor.kind == "mod":
            return None
    return None


def binds_locally(source: RustSource, function: RustItem, name: str) -> bool:
    """Return whether a function binds `name` as a parameter, local variable or closure parameter."""
    text = source.masked[function.start : function.end]
    identifier = re.escape(name)
    boundary = r"(?<![A-Za-z0-9_])" + identifier + r"(?![A-Za-z0-9_])"
    body = function.body_start - function.start if function.body_start is not None else len(text)
    if re.search(boundary + r"\s*:(?!:)", text[:body]):
        return True
    patterns = (
        r"\blet\b[^=;{]*" + boundary,
        r"\bfor\b[^{;]*?" + boundary + r"[^{;]*?\bin\b",
        r"(?<!\|)\|(?!\|)[^|;{}]*?" + boundary + r"(?!\s*\()[^|;{}]*?\|(?!\|)",
        boundary + r"\s*@",
    )
    return any(re.search(pattern, text[body:]) for pattern in patterns)


def classify_use(masked: str, offset: int, name: str) -> Optional[tuple[str, str]]:
    """Classify one occurrence of a callee name inside a function body.

    Returns `("bare", "")` for `name(...)` or `name` passed as a value,
    `("path", qualifier)` for `qualifier::name`, `("method", receiver)` for
    `receiver.name(...)`, and None for anything that is not a reference to a
    function: a binding, a field, a struct-literal key or a plain variable use.
    """
    before = masked[max(0, offset - 160) : offset].rstrip()
    after = masked[offset + len(name) : offset + len(name) + 400].lstrip()
    if after.startswith("::<"):
        depth = 0
        for index, character in enumerate(after):
            if character == "<":
                depth += 1
            elif character == ">" and after[index - 1] != "-":
                depth -= 1
                if depth == 0:
                    after = after[index + 1 :].lstrip()
                    break
    called = after.startswith("(")
    if before.endswith("::"):
        qualifier = _TRAILING_IDENTIFIER.search(before[:-2].rstrip())
        return ("path", qualifier.group(0) if qualifier else "?")
    if before.endswith(".") and not before.endswith(".."):
        if not called:
            return None
        receiver = _TRAILING_IDENTIFIER.search(before[:-1].rstrip())
        return ("method", receiver.group(0) if receiver else "?")
    previous = _TRAILING_IDENTIFIER.search(before)
    if previous and previous.group(0) in _BINDING_KEYWORDS:
        return None
    if called:
        return ("bare", "")
    if before.endswith(("(", ",")) and after.startswith((")", ",")):
        return ("bare", "")
    return None


def _typed_binding(source: RustSource, function: RustItem, receiver: str) -> Optional[str]:
    """Return the type name a function declares for a parameter or annotated local, if any."""
    text = source.masked[function.start : function.end]
    match = re.search(
        r"(?<![A-Za-z0-9_])" + re.escape(receiver)
        + r"\s*:\s*(?:&\s*)?(?:'[A-Za-z_]+\s+)?(?:mut\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Za-z_][A-Za-z0-9_]*)",
        text,
    )
    return match.group(1) if match else None


def _typed_constant(source: RustSource, receiver: str) -> Optional[str]:
    """Return the type name a file declares for a `const` or `static` item, if any."""
    match = re.search(
        r"(?<![A-Za-z0-9_])(?:const|static)\s+(?:mut\s+)?" + re.escape(receiver)
        + r"\s*:\s*(?:&\s*)?(?:'[A-Za-z_]+\s+)?(?:mut\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*([A-Za-z_][A-Za-z0-9_]*)",
        source.masked,
    )
    return match.group(1) if match else None


def renamed_imports(source: RustSource, name: str, modules: set[str]) -> tuple[dict[str, str], set[str]]:
    """Return the local names a file gives to `name` and to its defining modules by `use ... as`.

    The first result maps each alias of the item to the path segment that
    precedes the item in its `use` declaration (empty when there is none); the
    second holds the aliases of the modules. A renamed import hides the callee's
    own identifier at every call site, so callers are found through these.
    """
    items: dict[str, str] = {}
    module_aliases: set[str] = set()
    for path, bound in source.use_bindings():
        if bound in ("_", "*"):
            continue
        if path[-1] == name and bound != name:
            items[bound] = path[-2] if len(path) > 1 else ""
        if path[-1] in modules and bound not in modules:
            module_aliases.add(bound)
    return items, module_aliases


def import_qualifiers(source: RustSource, path: str, name: str) -> set[str]:
    """Return the modules through which a file imports `name` under its own name.

    The qualifier is the path segment before the name in the `use` declaration;
    `super` is resolved to the name of the file's parent module.
    """
    file_path = PurePosixPath(path)
    parent = file_path.parent.parent.name if file_path.name == "mod.rs" else file_path.parent.name
    qualifiers = set()
    for binding, bound in source.use_bindings():
        if binding[-1] == name and bound == name and len(binding) > 1:
            qualifiers.add(parent if binding[-2] == "super" else binding[-2])
    return qualifiers


# Path roots that can name a function of the file they appear in; "?" is an unparsed qualifier.
_RELATIVE_PATH_ROOTS = frozenset({"self", "crate", "super", "?"})


def _module_names(path: str) -> set[str]:
    """Return the module names under which other files can name a Rust file."""
    file_path = PurePosixPath(path)
    return {file_path.parent.name if file_path.name == "mod.rs" else file_path.stem}


def find_callers(tree: Tree, path: str, symbol: str, scope: Iterable[str],
                 development_features: Iterable[str]) -> tuple[dict[str, list[str]], bool]:
    """Return the production functions that call a callee and whether that list is exhaustive.

    An occurrence counts only as a call, a path expression or a function value;
    a local variable, field or binding that shares the callee's name does not.
    A method (`Type::name`) is attributed when the receiver is `self` inside an
    impl of the type, when the receiver is declared with the type, when the
    path names the type, or when the calling function names the type and no
    other type in the scope defines the same method. A free function is
    attributed in its own file unless the use is a path through another module,
    and elsewhere when no other free function of the scope bears the name or
    the use names the defining module.

    Renamed imports are followed: `use module::callee as alias` makes every
    call of `alias` a call of the callee, `use module as alias` and
    `module::{self as alias}` make `alias::callee` name the defining module,
    and `use Type as Alias` makes `Alias` name the type. A receiver that is a
    `const` or `static` of the file takes its declared type. A bare call in a
    file that imports the name only from another module of the scope which
    defines its own function of that name calls that function, not the callee.

    The list is exhaustive when exactly one production definition matches and
    no occurrence was left unattributed for lack of type information.
    """
    parts = symbol.split("::")
    name = parts[-1]
    owner = parts[-2] if len(parts) > 1 else None
    defining = tree.rust(path)
    resolved = [item for item in defining.resolve(symbol) if item.kind == "fn"] if defining is not None else []
    own_containers: set[str] = set()
    if resolved:
        # A function nested in an inline module is still a free function.
        owner = _impl_owner(resolved[0])
        own_containers = {ancestor.name for ancestor in resolved[0].ancestors() if ancestor.kind == "mod"}
    features = tuple(development_features)
    callers: dict[str, set[str]] = {}
    candidates: list[tuple[str, RustSource]] = []
    definitions: list[tuple[str, Optional[str]]] = []
    for candidate in scope:
        text = tree.text(candidate)
        if text is None or name not in text or not identifier_offsets(text, name):
            continue
        source = tree.rust(candidate)
        if source is None or file_facts(tree, candidate, features)[1]:
            continue
        candidates.append((candidate, source))
        for item in source.items:
            if item.kind == "fn" and item.name == name and not any(is_test_cfg(cfg, features) for cfg in item.cfg_chain()):
                definitions.append((candidate, _impl_owner(item)))
    matching = [entry for entry in definitions if entry == (path, owner)]
    other_types = {kind for _, kind in definitions if kind is not None and kind != owner}
    other_free = {file for file, kind in definitions if kind is None and file != path}
    own_modules = _module_names(path)
    other_modules = {module for file in other_free for module in _module_names(file)} - own_modules
    exhaustive = len(matching) == 1
    for candidate, source in candidates:
        own_free = any(file == candidate and kind is None for file, kind in definitions)
        if owner is None:
            item_aliases, module_aliases = renamed_imports(source, name, own_modules)
            owner_names = {owner}
        else:
            item_aliases, module_aliases = {}, set()
            # `use Type as Alias` names the owning type under another identifier.
            owner_names = {owner} | set(renamed_imports(source, owner, set())[0])
        naming_modules = own_modules | module_aliases
        imported_from = import_qualifiers(source, candidate, name) if owner is None else set()
        for offset in identifier_offsets(source.masked, name):
            function = _enclosing_function(source, offset)
            if function is None:
                continue
            if function.name == name and (function.body_start is None or offset < function.body_start):
                continue
            if any(is_test_cfg(cfg, features) for cfg in function.cfg_chain()):
                continue
            use = classify_use(source.masked, offset, name)
            if use is None:
                continue
            kind, detail = use
            enclosing_type = _impl_owner(function)
            verdict: Optional[bool]
            if owner is not None:
                if kind == "bare":
                    verdict = False
                elif kind == "path":
                    if detail in owner_names or (detail == "Self" and enclosing_type == owner):
                        verdict = True
                    elif detail == "?":
                        verdict = None
                    else:
                        verdict = False
                else:
                    declared = _typed_binding(source, function, detail) if detail not in ("?", "self") else None
                    if declared is None and detail not in ("?", "self"):
                        declared = _typed_constant(source, detail)
                    if declared == "Self":
                        declared = enclosing_type
                    text = source.masked[function.start : function.end]
                    names_owner = enclosing_type == owner or any(identifier_offsets(text, alias) for alias in owner_names)
                    names_other = enclosing_type in other_types or any(identifier_offsets(text, kind) for kind in other_types)
                    if detail == "self" and enclosing_type == owner:
                        verdict = True
                    elif detail == "self" and enclosing_type in other_types:
                        verdict = False
                    elif declared in owner_names:
                        verdict = True
                    elif declared in other_types:
                        verdict = False
                    elif names_owner and not names_other:
                        verdict = True
                    elif names_other and not names_owner:
                        verdict = False
                    else:
                        verdict = None
            elif kind == "method":
                verdict = False
            else:
                if kind == "path" and (detail == "Self" or detail[:1].isupper()):
                    verdict = False
                elif kind == "bare" and binds_locally(source, function, name):
                    verdict = False
                elif candidate == path:
                    # In its own file every use names the function, except a path through
                    # another module (`other::name`), which names that module's function.
                    verdict = kind != "path" or detail in naming_modules | own_containers | _RELATIVE_PATH_ROOTS
                elif kind == "path" and detail in naming_modules:
                    # The use names the defining module, by its own name or by an alias; this
                    # holds even in a file that defines a function of the same name.
                    verdict = True
                elif own_free:
                    verdict = False
                elif not other_free:
                    verdict = True
                elif kind == "bare" and imported_from and imported_from <= other_modules:
                    # The file imports the name from another module that defines its own function.
                    verdict = False
                else:
                    text = source.source
                    imported = any(
                        re.search(r"\b" + re.escape(module) + r"\s*::\s*(?:\{[^}]*\b" + re.escape(name) + r"\b|" + re.escape(name) + r"\b|\*)", text)
                        for module in own_modules
                    )
                    verdict = True if imported else None
            if verdict is True:
                callers.setdefault(candidate, set()).add(qualified_name(function))
            elif verdict is None:
                exhaustive = False
        # Calls through `use module::callee as alias`: the callee's own identifier appears
        # only in the `use` declaration, so each alias is searched like the name itself.
        for alias, qualifier in sorted(item_aliases.items()):
            for offset in identifier_offsets(source.masked, alias):
                function = _enclosing_function(source, offset)
                if function is None:
                    continue
                if any(is_test_cfg(cfg, features) for cfg in function.cfg_chain()):
                    continue
                use = classify_use(source.masked, offset, alias)
                if use is None or use[0] != "bare" or binds_locally(source, function, alias):
                    continue
                if qualifier in naming_modules or not other_free:
                    callers.setdefault(candidate, set()).add(qualified_name(function))
                elif qualifier not in other_modules:
                    # The alias may rename this callee or another function of the same name.
                    exhaustive = False
    return {key: sorted(value) for key, value in sorted(callers.items())}, exhaustive


def production_kernel_functions(tree: Tree, path: str, development_features: Iterable[str]) -> list[str]:
    """Return production functions of one Rust file whose names denote arithmetic kernels."""
    source = tree.rust(path)
    if source is None:
        return []
    _, file_test_only = file_facts(tree, path, development_features)
    if file_test_only:
        return []
    result = set()
    for item in source.items:
        if item.kind != "fn" or not is_kernel_name(item.name):
            continue
        if any(is_test_cfg(cfg, development_features) for cfg in item.cfg_chain()):
            continue
        result.add(qualified_name(item))
    return sorted(result)


MODULE_UNIT_PREFIX = "mod "


def function_units(tree: Tree, path: str, development_features: Iterable[str]) -> tuple[Counter, Counter]:
    """Return the production functions and the test-gated units of one Rust file, with multiplicity.

    Production functions are counted by qualified name. A test-gated unit is a
    test-gated function outside any test-gated inline module, or an outermost
    test-gated inline module, recorded as `mod <qualified name>`: unit tests
    inside such a module are not listed one by one.
    """
    production: Counter = Counter()
    gated: Counter = Counter()
    source = tree.rust(path)
    if source is None:
        return production, gated
    features = tuple(development_features)

    def is_gated(item: RustItem) -> bool:
        """Return whether an item is compiled only for tests or development fixtures."""
        return any(is_test_cfg(cfg, features) for cfg in item.cfg_chain())

    for item in source.items:
        if item.kind not in ("fn", "mod"):
            continue
        in_test_module = any(ancestor.kind == "mod" and is_gated(ancestor) for ancestor in item.ancestors())
        if item.kind == "fn":
            if not is_gated(item):
                production[qualified_name(item)] += 1
            elif not in_test_module:
                gated[qualified_name(item)] += 1
        elif item.body_start is not None and is_gated(item) and not in_test_module:
            gated[MODULE_UNIT_PREFIX + qualified_name(item)] += 1
    return production, gated


_HKDF_PRIMITIVE = re.compile(r"(?<![A-Za-z0-9_])Hkdf\s*::")


def hkdf_derivation_functions(tree: Tree, path: str, development_features: Iterable[str]) -> list[str]:
    """Return the production functions of a Rust file that instantiate the HKDF primitive."""
    source = tree.rust(path)
    if source is None or file_facts(tree, path, development_features)[1]:
        return []
    result = set()
    for match in _HKDF_PRIMITIVE.finditer(source.masked):
        function = _enclosing_function(source, match.start())
        if function is not None and not any(is_test_cfg(cfg, development_features) for cfg in function.cfg_chain()):
            result.add(qualified_name(function))
    return sorted(result)


def function_names(tree: Tree, path: str, symbol: str) -> list[str]:
    """Return the qualified names of the functions a symbol resolves to in a Rust file."""
    source = tree.rust(path) if path.endswith(".rs") else None
    if source is None:
        return []
    return sorted({qualified_name(item) for item in source.resolve(symbol) if item.kind == "fn"})


def manifest_dependencies(tree: Tree, crate: str) -> set[str]:
    """Return package names from the normal dependency tables of a manifest."""
    names: set[str] = set()
    section = ""
    nested_key = ""
    for line in (tree.text(f"{crate}/Cargo.toml") or "").splitlines():
        stripped = line.strip()
        header = re.match(r"^\[([^\]]+)\]$", stripped)
        if header:
            section = header.group(1).strip()
            nested = re.match(r"^(?:target\..*\.)?dependencies\.([A-Za-z0-9_\-]+)$", section)
            nested_key = nested.group(1) if nested else ""
            if nested_key:
                names.add(nested_key)
            continue
        renamed = re.search(r'\bpackage\s*=\s*"([^"]+)"', stripped)
        if nested_key:
            if renamed and stripped.startswith("package"):
                names.discard(nested_key)
                names.add(renamed.group(1))
            continue
        if section == "dependencies" or re.match(r"^target\..*\.dependencies$", section):
            entry = re.match(r"^([A-Za-z0-9_\-]+)\s*(?:=|\.)", stripped)
            if entry:
                names.add(renamed.group(1) if renamed else entry.group(1))
    return names


def development_feature_errors(tree: Tree, crate: str, feature: str) -> list[str]:
    """Check that a development feature exists and no normal dependency table enables it."""
    errors: list[str] = []
    manifest = tree.text(f"{crate}/Cargo.toml") or ""
    if not re.search(r"(?m)^" + re.escape(feature) + r"\s*=", manifest):
        errors.append(f"{crate}/Cargo.toml does not declare feature {feature}")
    name = PurePosixPath(crate).name
    quoted = re.compile(r'"' + re.escape(feature) + r'"')
    for path in tree.files:
        if not path.endswith("Cargo.toml"):
            continue
        section = ""
        for line in (tree.text(path) or "").splitlines():
            stripped = line.strip()
            header = re.match(r"^\[([^\]]+)\]$", stripped)
            if header:
                section = header.group(1).strip()
                continue
            if not quoted.search(stripped):
                continue
            if path == f"{crate}/Cargo.toml" and section == "features":
                if not stripped.startswith(feature):
                    errors.append(f"{path} enables development feature {feature} from another feature")
            elif stripped.startswith(name) and "dev-dependencies" not in section:
                errors.append(f"{path} enables development feature {feature} outside dev-dependencies")
    return errors


# ---------------------------------------------------------------------------
# Inventory structure
# ---------------------------------------------------------------------------

FILE_ROLES = (
    "fhe_implementation", "fhe_test_reference", "ram_lfe_implementation", "mkhe_implementation",
    "ring_arithmetic_implementation", "distinct_arithmetic", "consumer", "sdk", "generator",
    "generated_artifact", "fixture", "inventory", "documentation", "tooling", "build_manifest",
    "unrelated_hkdf", "incidental",
)
IMPLEMENTATION_ROLES = ("canonical", "duplicate", "consolidation_candidate", "test_only_reference")
# `shared_arithmetic` labels the references of the shared owner crate itself (its unit tests
# and canonical-vector oracle); it belongs to no protocol. `rns_bgv` is the exact modular
# RNS-BGV scheme of crates/iroha_fhe/src/bgv, the shared starting candidate of task C.3.
PROTOCOL_SCHEMES = ("bfv", "bgv_mkhe", "ram_lfe", "jindo", "bootle_lantern", "shared_arithmetic", "rns_bgv")
REFERENCE_KINDS = ("oracle", "key_generation_reference", "protocol_reference", "fixture", "candidate", "unit_tests")
REQUIRED_REFERENCE_KINDS = ("oracle", "key_generation_reference", "protocol_reference")
# What a protocol-logic component runs. A component that only validates,
# derives certificates, encodes, or refuses declares none of them.
EXECUTING_OPERATIONS = (
    "key_generation", "encryption", "decryption", "evaluation", "key_switching", "bootstrap",
    "ring_arithmetic", "plaintext_prf",
)
SCOPE_ASSIGNMENTS = ("every_function", "kernel_names")
HKDF_USER_KINDS = (
    "definition", "evaluator", "policy_branch", "consumer_rejection", "wire_tag", "generator", "test",
    "source_anchor", "documentation",
)
# The REQ-032 facts every revision of the inventory must anchor to source.
REQUIRED_CURRENT_STATE = (
    "bfv_backends_refused",
    "execution_proof_relation_unavailable",
    "signed_mode_and_receipt_attestations_exist",
    "sdk_input_encryption_unavailable",
)
UNCLASSIFIED_GROUP = "unclassified"
_SYMBOL_KEY_ORDER = ("path", "symbol", "cfg", "test_only", "role", "callers_exhaustive", "callers")
_FILE_KEY_ORDER = ("path", "patterns", "cfg", "test_only")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def symbol_records(document: dict[str, Any]) -> list[tuple[str, Any, dict[str, Any], bool]]:
    """Return (section, path, record, wants_callers) for every symbol record of an inventory."""
    found: list[tuple[str, Any, dict[str, Any], bool]] = []

    def add(section: str, path: Any, record: Any, wants_callers: bool = False) -> None:
        """Collect one well-formed symbol record."""
        if isinstance(record, dict) and isinstance(record.get("symbol"), str):
            found.append((section, path, record, wants_callers))

    for primitive in _list(document.get("primitives")):
        for record in _list(_dict(primitive).get("implementations")):
            add("primitives", _dict(record).get("path"), record, True)
    for entry in _list(document.get("distinct_arithmetic")):
        for record in _list(_dict(entry).get("symbols")):
            add("distinct_arithmetic", _dict(record).get("path"), record)
    for record in _list(document.get("unrelated_kernel_named")):
        add("unrelated_kernel_named", _dict(record).get("path"), record)
    for section in ("protocol_logic", "test_only_references"):
        for entry in _list(document.get(section)):
            for record in _list(_dict(entry).get("symbols")):
                add(section, _dict(entry).get("path"), record)
    for entry in _list(document.get("current_state")):
        for record in _list(_dict(entry).get("evidence")):
            add("current_state", _dict(record).get("path"), record)
    hkdf = _dict(document.get("hkdf"))
    backend = _dict(hkdf.get("ram_lfe_backend"))
    for user in _list(backend.get("users")):
        for record in _list(_dict(user).get("symbols")):
            add("hkdf", _dict(user).get("path"), record)
    for record in _list(backend.get("no_effect_evidence")):
        add("hkdf", _dict(record).get("path"), record)
    for entry in _list(_dict(hkdf.get("plaintext_prf")).get("entries")):
        for record in _list(_dict(entry).get("symbols")):
            add("hkdf", _dict(entry).get("path"), record, True)
    for record in _list(hkdf.get("other_derivations")):
        add("hkdf", _dict(record).get("path"), record)
    for generator in _list(_dict(document.get("generated_sdk_code")).get("runtime_generators")):
        for record in _list(_dict(generator).get("symbols")):
            add("generated_sdk_code", _dict(generator).get("generator"), record)
    return found


def listed_files(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return every file record of an inventory by path."""
    result: dict[str, dict[str, Any]] = {}
    for group in _list(document.get("file_groups")):
        for record in _list(_dict(group).get("files")):
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                result.setdefault(record["path"], record)
    return result


def declared_development_features(document: dict[str, Any]) -> list[str]:
    """Return the development-only feature names an inventory declares."""
    return [
        record["feature"] for record in _list(document.get("development_features"))
        if isinstance(record, dict) and isinstance(record.get("feature"), str)
    ]


def owner_files(tree: Tree, document: dict[str, Any], features: Iterable[str]) -> list[str]:
    """Return the Rust files whose functions the inventory must assign one by one.

    These are the production-compiled files under an `every_function` scope
    and the files that hold a production implementation of a primitive.
    """
    prefixes = tuple(
        scope["prefix"] for scope in _list(document.get("arithmetic_scopes"))
        if isinstance(scope, dict) and isinstance(scope.get("prefix"), str) and scope["prefix"]
        and scope.get("assignment") == "every_function"
    )
    candidates = {path for path in tree.files if path.endswith(".rs") and prefixes and path.startswith(prefixes)}
    for primitive in _list(document.get("primitives")):
        for record in _list(_dict(primitive).get("implementations")):
            path = _dict(record).get("path")
            if _dict(record).get("role") == "test_only_reference":
                continue
            if isinstance(path, str) and path.endswith(".rs") and path in tree.file_set:
                candidates.add(path)
    return sorted(path for path in candidates if not file_facts(tree, path, features)[1])


def claimed_functions(tree: Tree, document: dict[str, Any], path: str, features: Iterable[str]) -> dict[str, str]:
    """Return the production functions of a file that a primitive or a distinct owner claims, with the claimant."""
    claims: dict[str, str] = {}
    source = tree.rust(path)
    if source is None:
        return claims
    features = tuple(features)
    for section, record_path, record, _ in symbol_records(document):
        if record_path != path or section not in ("primitives", "distinct_arithmetic", "unrelated_kernel_named"):
            continue
        for item in source.resolve(record["symbol"]):
            if item.kind == "fn" and not any(is_test_cfg(cfg, features) for cfg in item.cfg_chain()):
                claims.setdefault(qualified_name(item), section)
    return claims


# ---------------------------------------------------------------------------
# Inventory validation
# ---------------------------------------------------------------------------


class MapChecker:
    """Validate one ownership inventory document against one repository tree."""

    def __init__(self, tree: Tree, document: Any, scan: Optional[dict[str, list[str]]] = None) -> None:
        self.tree = tree
        self.document = document if isinstance(document, dict) else {}
        self.errors: list[str] = []
        if not isinstance(document, dict):
            self.errors.append("map must be a JSON object")
        self.scan = scan if scan is not None else scan_tree(tree)
        self.features: list[str] = []
        self.listed: dict[str, dict[str, Any]] = {}
        self.crate_index: dict[str, int] = {}
        self.crate_paths: dict[str, str] = {}
        self.claimed: dict[tuple[str, str], str] = {}
        self.covered: dict[str, set[str]] = {}
        self.entry_functions: dict[str, dict[str, list[tuple[str, str]]]] = {"protocol_logic": {}, "test_only_references": {}}
        self.executes: dict[str, list[str]] = {}
        self.production_primitives: list[tuple[str, str]] = []

    # -- helpers ------------------------------------------------------------

    def error(self, message: str) -> None:
        """Record one inconsistency."""
        self.errors.append(message)

    def section(self, name: str, kind: type) -> Any:
        """Return a top-level section of the expected JSON type, or an empty one."""
        value = self.document.get(name)
        if not isinstance(value, kind):
            self.error(f"{name} must be a JSON {'object' if kind is dict else 'array'}")
            return kind()
        return value

    def claim(self, path: str, symbol: str, owner: str) -> None:
        """Record that one inventory entry accounts for a path and symbol."""
        previous = self.claimed.get((path, symbol))
        if previous is not None and previous != owner:
            self.error(f"{path}::{symbol} is claimed by both {previous} and {owner}")
        self.claimed[(path, symbol)] = owner
        self.covered.setdefault(path, set()).add(symbol)

    def check_symbol(self, label: str, path: Any, record: Any, expect_test_only: Optional[bool] = None) -> Optional[bool]:
        """Verify existence, cfg chain and test-only flag of one symbol record."""
        if not isinstance(path, str) or not isinstance(record, dict) or not isinstance(record.get("symbol"), str):
            self.error(f"{label} needs a path and a symbol")
            return None
        symbol = record["symbol"]
        if path not in self.listed:
            self.error(f"{label}: {path} is not listed in file_groups")
        chain, test_only, problem = symbol_facts(self.tree, path, symbol, self.features)
        if problem:
            self.error(f"{label}: {problem}")
            return None
        recorded_cfg = record.get("cfg", [])
        if recorded_cfg != chain:
            self.error(f"{label}: {path}::{symbol} cfg is {chain}, map records {recorded_cfg}")
        recorded = record.get("test_only", False)
        if recorded is not test_only:
            self.error(f"{label}: {path}::{symbol} test_only is {test_only}, map records {recorded}")
        if expect_test_only is not None and test_only is not expect_test_only:
            wanted = "test-only" if expect_test_only else "production"
            self.error(f"{label}: {path}::{symbol} must be {wanted}")
        return test_only

    def crate_layer(self, path: str) -> Optional[int]:
        """Return the layer index of the listed crate that contains a path."""
        best: Optional[str] = None
        for name, crate_path in self.crate_paths.items():
            if path.startswith(crate_path + "/") and (best is None or len(crate_path) > len(self.crate_paths[best])):
                best = name
        return None if best is None else self.crate_index[best]

    # -- sections -----------------------------------------------------------

    def check_header(self) -> None:
        """Verify the schema, the restated scan contract and the development features."""
        document = self.document
        if document.get("schema_version") != SCHEMA_VERSION:
            self.error(f"schema_version must be {SCHEMA_VERSION}")
        if document.get("task") != "C.1":
            self.error("task must be C.1")
        scan = document.get("scan")
        expected = {
            "patterns": list(PATTERN_IDS),
            "excluded_paths": list(EXCLUDED_PATHS),
            "markdown_patterns": list(MARKDOWN_PATTERNS),
            "generated_registry": GENERATED_REGISTRY,
        }
        if not isinstance(scan, dict) or {key: scan.get(key) for key in expected} != expected:
            self.error("scan must restate the checker's patterns and exclusions exactly")
        for record in self.section("development_features", list):
            if not isinstance(record, dict) or not isinstance(record.get("crate"), str) or not isinstance(record.get("feature"), str):
                self.error("development_features entries need crate and feature")
                continue
            self.errors.extend(development_feature_errors(self.tree, record["crate"], record["feature"]))
            self.features.append(record["feature"])

    def check_crates(self) -> None:
        """Verify the layer list against the manifests and the planned destination."""
        planned: list[str] = []
        records = [
            record for record in self.section("crates", list)
            if isinstance(record, dict) and isinstance(record.get("name"), str) and isinstance(record.get("path"), str)
        ]
        if len(records) != len(_list(self.document.get("crates"))):
            self.error("crates entries need name and path")
        names = {record["name"].replace("-", "_") for record in records}
        for index, record in enumerate(records):
            name, path = record["name"], record["path"]
            if name in self.crate_index:
                self.error(f"crate {name} is listed twice")
            dependencies = record.get("depends_on", [])
            if not _is_string_list(dependencies) and dependencies != []:
                self.error(f"crate {name} depends_on must be an array of crate names")
                dependencies = []
            for dependency in dependencies:
                if dependency not in self.crate_index:
                    self.error(f"crate {name} depends on {dependency}, which is not a lower layer in crates")
            manifest = f"{path}/Cargo.toml"
            if record.get("planned") is True:
                planned.append(name)
                if manifest in self.tree.file_set:
                    self.error(f"planned crate {name} now exists at {path}; record it as established and update owners")
            elif manifest not in self.tree.file_set:
                self.error(f"crate {name} has no manifest at {manifest}")
            else:
                declared = {item.replace("-", "_") for item in manifest_dependencies(self.tree, path)}
                recorded = {dependency.replace("-", "_") for dependency in dependencies}
                for dependency in sorted(recorded - declared):
                    self.error(f"{manifest} does not depend on {dependency}")
                missing = sorted((declared & names) - recorded - {name.replace("-", "_")})
                if missing:
                    self.error(f"crate {name} depends_on omits {missing}, which {manifest} depends on")
            self.crate_index[name] = index
            self.crate_paths[name] = path
        destination = self.section("destination", dict)
        target = destination.get("crate")
        if target not in self.crate_index:
            self.error("destination.crate must name an entry of crates")
        elif (destination.get("planned") is True) != (target in planned):
            self.error("destination.planned must agree with the crates entry")
        elif destination.get("path", self.crate_paths[target]) != self.crate_paths[target]:
            self.error("destination.path must equal the path of its crates entry")
        if not isinstance(destination.get("modules"), dict) or not destination.get("modules"):
            self.error("destination.modules must map module paths to their content")

    def check_file_groups(self) -> None:
        """Verify every listed file and that the fresh scan finds no other."""
        group_ids: set[str] = set()
        for group in self.section("file_groups", list):
            if not isinstance(group, dict) or not isinstance(group.get("id"), str):
                self.error("file_groups entries need an id")
                continue
            identifier = group["id"]
            if identifier in group_ids:
                self.error(f"file group {identifier} is listed twice")
            group_ids.add(identifier)
            role = group.get("role")
            if role not in FILE_ROLES:
                self.error(f"file group {identifier} has unknown role {role}")
            if not isinstance(group.get("summary"), str) or not group["summary"].strip():
                self.error(f"file group {identifier} needs a summary")
            files = group.get("files")
            if not isinstance(files, list) or not files:
                self.error(f"file group {identifier} needs files")
                continue
            for record in files:
                if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                    self.error(f"file group {identifier} has an entry without a path")
                    continue
                path = record["path"]
                if path in self.listed:
                    self.error(f"{path} is listed twice")
                    continue
                self.listed[path] = {"group": identifier, "role": role, "record": record}
                if path not in self.tree.file_set:
                    self.error(f"{path} is listed but does not exist")
                    continue
                fresh = self.scan.get(path)
                pinned = record.get("pinned")
                if fresh is None and not (isinstance(pinned, str) and pinned.strip()):
                    self.error(f"{path} is listed but no longer matches a detection pattern")
                elif fresh is not None and pinned is not None:
                    self.error(f"{path} matches {fresh} and must not be pinned")
                elif record.get("patterns") != (fresh or []):
                    self.error(f"{path} matches {fresh or []}, map records {record.get('patterns')}")
                cfgs, test_only = file_facts(self.tree, path, self.features)
                if record.get("cfg", []) != cfgs:
                    self.error(f"{path} is compiled under {cfgs}, map records {record.get('cfg', [])}")
                if record.get("test_only", False) is not test_only:
                    self.error(f"{path} test_only is {test_only}, map records {record.get('test_only', False)}")
                if role == "unrelated_hkdf" and fresh not in (None, ["hkdf"]):
                    self.error(f"{path} is recorded as unrelated HKDF but matches {fresh}")
                if role == "incidental":
                    evidence = record.get("evidence")
                    if not isinstance(evidence, str) or not evidence or evidence not in (self.tree.text(path) or ""):
                        self.error(f"{path} is recorded as incidental without evidence text found in the file")
        for path in sorted(set(self.scan) - set(self.listed)):
            self.error(f"{path} matches {self.scan[path]} but the map does not list it")

    def check_implementation(self, label: str, record: Any, owner_layer: Optional[int]) -> None:
        """Verify one implementation of a primitive, its layer and its callers."""
        if not isinstance(record, dict):
            self.error(f"{label} has a malformed implementation")
            return
        path, symbol, role = record.get("path"), record.get("symbol"), record.get("role")
        if role not in IMPLEMENTATION_ROLES:
            self.error(f"{label}: {path}::{symbol} has unknown role {role}")
        test_only = self.check_symbol(label, path, record)
        if test_only is None:
            return
        self.claim(path, symbol, label)
        if (role == "test_only_reference") is not test_only:
            self.error(f"{label}: {path}::{symbol} role {role} disagrees with test_only {test_only}")
        if not test_only:
            self.production_primitives.append((path, label))
        layer = self.crate_layer(path)
        if layer is None:
            self.error(f"{label}: {path} is not inside a crate listed in crates")
        elif owner_layer is not None and owner_layer > layer:
            self.error(f"{label}: owner is a higher layer than implementation {path}")
        self.check_callers(label, path, record, test_only)

    def check_callers(self, label: str, path: str, record: dict[str, Any], test_only: bool) -> None:
        """Verify the recorded production callers of one production Rust function."""
        symbol = record["symbol"]
        if test_only or not path.endswith(".rs"):
            if "callers" in record:
                self.error(f"{label}: {path}::{symbol} is test-only or not Rust and cannot record callers")
            return
        source = self.tree.rust(path)
        items = source.resolve(symbol) if source is not None else []
        if not items or items[0].kind != "fn":
            return
        scope = caller_scope(self.tree, path, self.listed, items[0].visibility)
        callers, exhaustive = find_callers(self.tree, path, symbol, scope, self.features)
        recorded = record.get("callers", {})
        if record.get("callers_exhaustive") is not exhaustive:
            self.error(f"{label}: {path}::{symbol} callers_exhaustive must be {exhaustive}")
        if not isinstance(recorded, dict):
            self.error(f"{label}: {path}::{symbol} callers must be an object")
        elif recorded != callers:
            self.error(f"{label}: {path}::{symbol} production callers are {callers}, map records {recorded}")

    def check_primitives(self) -> None:
        """Verify that each primitive has one owner and a consistent canonical source."""
        destination = _dict(self.document.get("destination"))
        modules = _dict(destination.get("modules"))
        identifiers: set[str] = set()
        for primitive in self.section("primitives", list):
            if not isinstance(primitive, dict) or not isinstance(primitive.get("id"), str):
                self.error("primitives entries need an id")
                continue
            label = f"primitive {primitive['id']}"
            if primitive["id"] in identifiers:
                self.error(f"{label} is listed twice")
            identifiers.add(primitive["id"])
            if "owners" in primitive:
                self.error(f"{label} must have exactly one owner")
            owner = primitive.get("owner")
            owner_layer: Optional[int] = None
            if not isinstance(owner, dict) or not isinstance(owner.get("crate"), str) or not isinstance(owner.get("module"), str):
                self.error(f"{label} must have exactly one owner with crate and module")
            elif owner["crate"] not in self.crate_index:
                self.error(f"{label} owner crate {owner['crate']} is not listed in crates")
            else:
                owner_layer = self.crate_index[owner["crate"]]
                if owner["crate"] == destination.get("crate") and owner["module"] not in modules:
                    self.error(f"{label} owner module {owner['module']} is not a destination module")
            implementations = primitive.get("implementations")
            if not isinstance(implementations, list) or not implementations:
                self.error(f"{label} needs implementations")
                implementations = []
            for record in implementations:
                self.check_implementation(label, record, owner_layer)
            canonical = [record for record in implementations if isinstance(record, dict) and record.get("role") == "canonical"]
            source = primitive.get("canonical_source")
            if source is None:
                if canonical:
                    self.error(f"{label} has canonical implementations but no canonical_source")
                if not isinstance(primitive.get("canonical_source_absent"), str):
                    self.error(f"{label} needs canonical_source or a canonical_source_absent reason")
                continue
            if not isinstance(source, dict) or not isinstance(source.get("path"), str) or not _is_string_list(source.get("symbols")):
                self.error(f"{label} canonical_source needs one path and its symbols")
                continue
            recorded = sorted(record.get("symbol") for record in canonical if record.get("path") == source["path"])
            if len(recorded) != len(canonical):
                self.error(f"{label} has canonical implementations outside {source['path']}")
            if recorded != sorted(source["symbols"]):
                self.error(f"{label} canonical_source symbols differ from its canonical implementations")

    def check_distinct(self) -> None:
        """Verify arithmetic that keeps a distinct owner and unrelated kernel-named functions."""
        for entry in self.section("distinct_arithmetic", list):
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                self.error("distinct_arithmetic entries need an id")
                continue
            label = f"distinct arithmetic {entry['id']}"
            owner = entry.get("owner")
            if not isinstance(owner, dict) or owner.get("crate") not in self.crate_index:
                self.error(f"{label} must have exactly one owner crate listed in crates")
            if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                self.error(f"{label} needs a reason for distinct ownership")
            symbols = entry.get("symbols")
            if not isinstance(symbols, list) or not symbols:
                self.error(f"{label} needs symbols")
                continue
            for record in symbols:
                path = record.get("path") if isinstance(record, dict) else None
                if self.check_symbol(label, path, record) is not None:
                    self.claim(path, record["symbol"], label)
        for record in self.section("unrelated_kernel_named", list):
            path = record.get("path") if isinstance(record, dict) else None
            if not isinstance(record, dict) or not isinstance(record.get("reason"), str) or not record["reason"].strip():
                self.error("unrelated_kernel_named entries need a reason")
            if self.check_symbol("unrelated_kernel_named", path, record) is not None:
                self.claim(path, record["symbol"], "unrelated_kernel_named")

    def check_protocol(self) -> None:
        """Verify protocol logic as production and references as test-only."""
        for name, production in (("protocol_logic", True), ("test_only_references", False)):
            identifiers: set[str] = set()
            kinds: set[Any] = set()
            for entry in self.section(name, list):
                if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                    self.error(f"{name} entries need an id")
                    continue
                label = f"{name} {entry['id']}"
                if entry["id"] in identifiers:
                    self.error(f"{label} is listed twice")
                identifiers.add(entry["id"])
                self.entry_functions[name].setdefault(entry["id"], [])
                if entry.get("scheme") not in PROTOCOL_SCHEMES:
                    self.error(f"{label} has unknown scheme {entry.get('scheme')}")
                if production:
                    executes = entry.get("executes")
                    if not isinstance(executes, list) or any(operation not in EXECUTING_OPERATIONS for operation in executes):
                        self.error(f"{label} needs executes, a list drawn from {list(EXECUTING_OPERATIONS)}")
                        executes = []
                    self.executes[entry["id"]] = executes
                else:
                    kinds.add(entry.get("kind"))
                    if entry.get("kind") not in REFERENCE_KINDS:
                        self.error(f"{label} has unknown kind {entry.get('kind')}")
                path = entry.get("path")
                symbols = entry.get("symbols")
                if not isinstance(symbols, list) or (path is not None and not isinstance(path, str)):
                    self.error(f"{label} needs symbols and, when it lists any, a path")
                    continue
                if not production and entry.get("whole_file") is True:
                    if path not in self.listed:
                        self.error(f"{label}: {path} is not listed in file_groups")
                    elif not file_facts(self.tree, path, self.features)[1]:
                        self.error(f"{label}: {path} is not test-only as a whole file")
                for record in symbols:
                    if self.check_symbol(label, path, record, expect_test_only=not production) is None:
                        continue
                    if production:
                        self.covered.setdefault(path, set()).add(record["symbol"])
                    self.entry_functions[name][entry["id"]].append((path, record["symbol"]))
            if not production:
                for kind in REQUIRED_REFERENCE_KINDS:
                    if kind not in kinds:
                        self.error(f"test_only_references needs at least one entry of kind {kind}")

    def check_zk_ams_distinct(self) -> None:
        """Verify the preserved test oracles and the fail-closed ZK-AMS production surface."""
        distinct = self.section("zk_ams_distinct", dict)
        named = distinct.get("preserve_as_test_oracles")
        kinds = {
            entry.get("id"): entry.get("kind") for entry in _list(self.document.get("test_only_references"))
            if isinstance(entry, dict)
        }
        if not _is_string_list(named) or not named:
            self.error("zk_ams_distinct.preserve_as_test_oracles must name at least one test-only reference")
            named = []
        for identifier in named:
            if identifier not in kinds:
                self.error(f"zk_ams_distinct preserves unknown test-only reference {identifier}")
            elif kinds[identifier] != "oracle":
                self.error(f"zk_ams_distinct preserves {identifier}, which is not recorded as an oracle")
        surface = distinct.get("production_surface")
        if not isinstance(surface, dict) or not isinstance(surface.get("prefix"), str) or not surface["prefix"] \
                or not isinstance(surface.get("claim"), str) or not surface["claim"].strip() \
                or not (_is_string_list(surface.get("allowed_primitives")) or surface.get("allowed_primitives") == []):
            self.error("zk_ams_distinct.production_surface needs a prefix, a claim and allowed_primitives")
            return
        prefix = surface["prefix"]
        scopes = [
            scope.get("prefix") for scope in _list(self.document.get("arithmetic_scopes"))
            if isinstance(scope, dict) and scope.get("assignment") == "every_function"
        ]
        if not any(isinstance(scope, str) and prefix.startswith(scope) for scope in scopes):
            self.error(f"zk_ams_distinct.production_surface {prefix} is not inside an every_function scope")
        allowed = {f"primitive {identifier}" for identifier in surface["allowed_primitives"]}
        for path, label in sorted(set(self.production_primitives)):
            if path.startswith(prefix) and label not in allowed:
                self.error(f"{label}: {path} holds a production implementation inside the fail-closed surface {prefix}")
        for (path, symbol), label in sorted(self.claimed.items()):
            if path.startswith(prefix) and not label.startswith("primitive "):
                self.error(f"{label} claims {path}::{symbol} inside the fail-closed surface {prefix}; only allowed primitives and protocol logic may own its functions")
        for entry in _list(self.document.get("function_assignment")):
            path = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path, str) or not path.startswith(prefix):
                continue
            for identifier, names in _dict(entry.get("production")).items():
                if names and self.executes.get(identifier):
                    self.error(
                        f"{path} assigns production functions to {identifier}, which executes "
                        f"{self.executes[identifier]} inside the fail-closed surface {prefix}"
                    )

    def check_current_state(self) -> None:
        """Verify the anchors of each current-state claim and that the required claims exist."""
        identifiers: set[str] = set()
        for entry in self.section("current_state", list):
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                self.error("current_state entries need an id")
                continue
            label = f"current_state {entry['id']}"
            if entry["id"] in identifiers:
                self.error(f"{label} is listed twice")
            identifiers.add(entry["id"])
            if not isinstance(entry.get("claim"), str) or not entry["claim"].strip():
                self.error(f"{label} needs a claim")
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                self.error(f"{label} needs evidence")
                evidence = []
            for record in evidence:
                path = record.get("path") if isinstance(record, dict) else None
                if not isinstance(path, str):
                    self.error(f"{label} evidence needs a path")
                elif "symbol" in record:
                    self.check_symbol(label, path, record, expect_test_only=False)
                elif not isinstance(record.get("literal"), str) or not record["literal"]:
                    self.error(f"{label} evidence for {path} needs a symbol or literal")
                elif path not in self.listed:
                    self.error(f"{label}: {path} is not listed in file_groups")
                elif record["literal"] not in (self.tree.text(path) or ""):
                    self.error(f"{label}: {path} does not contain {record['literal']!r}")
            for record in entry.get("absent", []):
                prefix = record.get("prefix") if isinstance(record, dict) else None
                literal = record.get("literal") if isinstance(record, dict) else None
                if not isinstance(prefix, str) or not isinstance(literal, str) or not literal:
                    self.error(f"{label} absent entries need a prefix and literal")
                    continue
                for path in sorted(self.listed):
                    if path.startswith(prefix) and literal in (self.tree.text(path) or ""):
                        self.error(f"{label}: {path} now contains {literal!r}")
        for identifier in REQUIRED_CURRENT_STATE:
            if identifier not in identifiers:
                self.error(f"current_state needs the claim {identifier}")

    def check_hkdf(self) -> None:
        """Verify the HKDF classifications against each other, the scan and the HKDF call sites."""
        hkdf = self.section("hkdf", dict)
        backend = _dict(hkdf.get("ram_lfe_backend"))
        plaintext = _dict(hkdf.get("plaintext_prf"))
        unrelated = _dict(hkdf.get("unrelated_preserve"))
        users = backend.get("users") if isinstance(backend.get("users"), list) else None
        derivations = plaintext.get("entries") if isinstance(plaintext.get("entries"), list) else None
        preserved = unrelated.get("entries") if isinstance(unrelated.get("entries"), list) else None
        if users is None or derivations is None or preserved is None:
            self.error("hkdf needs ram_lfe_backend.users, plaintext_prf.entries and unrelated_preserve.entries")
            return
        if not users:
            self.error("hkdf.ram_lfe_backend.users must list the backend's users")
        if not derivations:
            self.error("hkdf.plaintext_prf.entries must record the plaintext PRF")
        user_paths: set[str] = set()
        backend_symbols: set[tuple[str, str]] = set()
        accounted: dict[str, dict[str, list[str]]] = {}

        def account(path: str, symbol: str, owner: str) -> None:
            """Record which HKDF classification names a function."""
            for name in function_names(self.tree, path, symbol):
                accounted.setdefault(path, {}).setdefault(name, []).append(owner)

        for record in users:
            path = record.get("path") if isinstance(record, dict) else None
            if not isinstance(path, str):
                self.error("hkdf.ram_lfe_backend.users entries need a path")
                continue
            label = f"hkdf backend user {path}"
            user_paths.add(path)
            if record.get("kind") not in HKDF_USER_KINDS:
                self.error(f"{label} has unknown kind {record.get('kind')}")
            patterns = self.scan.get(path, [])
            if "hkdf" not in patterns:
                self.error(f"{label} does not match the hkdf pattern")
            text = self.tree.text(path) or ""
            literals = record.get("literals", [])
            symbols = record.get("symbols", [])
            if not _is_string_list(literals) and literals != []:
                self.error(f"{label} literals must be strings")
                literals = []
            for literal in literals:
                if literal not in text:
                    self.error(f"{label} does not contain {literal!r}")
            if not isinstance(symbols, list) or not (symbols or literals):
                self.error(f"{label} needs symbols or literals")
                continue
            if "hkdf_ram_lfe" not in patterns and not literals:
                self.error(f"{label} needs literal evidence because no backend identifier pattern matches")
            if path in self.listed and record.get("test_only", False) is not file_facts(self.tree, path, self.features)[1]:
                self.error(f"{label} test_only flag disagrees with the file")
            for symbol in symbols:
                if self.check_symbol(label, path, symbol) is not None:
                    backend_symbols.add((path, symbol["symbol"]))
        for path, symbol in sorted(backend_symbols):
            account(path, symbol, "the RAM-LFE backend")
        derivation_paths: set[str] = set()
        for record in derivations:
            path = record.get("path") if isinstance(record, dict) else None
            symbols = record.get("symbols") if isinstance(record, dict) else None
            if not isinstance(path, str) or not isinstance(symbols, list) or not symbols:
                self.error("hkdf.plaintext_prf.entries need a path and symbols")
                continue
            derivation_paths.add(path)
            for symbol in symbols:
                if self.check_symbol(f"hkdf plaintext PRF {path}", path, symbol, expect_test_only=False) is not None:
                    self.check_callers(f"hkdf plaintext PRF {path}", path, symbol, False)
                    account(path, symbol["symbol"], "the plaintext PRF")
                    if (path, symbol["symbol"]) in backend_symbols:
                        self.error(f"{path}::{symbol['symbol']} is recorded as both plaintext PRF and encrypted-evaluation backend")
        for record in _list(hkdf.get("other_derivations")):
            path = record.get("path") if isinstance(record, dict) else None
            if not isinstance(record, dict) or not isinstance(record.get("purpose"), str) or not record["purpose"].strip():
                self.error("hkdf.other_derivations entries need a purpose")
            if self.check_symbol("hkdf other derivation", path, record, expect_test_only=False) is not None:
                account(path, record["symbol"], "another derivation")
        preserved_paths: set[str] = set()
        for record in preserved:
            path = record.get("path") if isinstance(record, dict) else None
            if not isinstance(path, str) or not isinstance(record.get("purpose"), str) or not record["purpose"].strip():
                self.error("hkdf.unrelated_preserve.entries need a path and a purpose")
                continue
            preserved_paths.add(path)
            patterns = self.scan.get(path, [])
            if "hkdf" not in patterns:
                self.error(f"unrelated HKDF {path} does not match the hkdf pattern")
            if "hkdf_ram_lfe" in patterns and path not in user_paths:
                self.error(f"{path} names the RAM-LFE HKDF backend but is recorded as unrelated HKDF")
            if "ram_lfe" in patterns or "hkdf_ram_lfe" in patterns:
                evidence = record.get("evidence")
                if not isinstance(evidence, str) or not evidence or evidence not in (self.tree.text(path) or ""):
                    self.error(f"unrelated HKDF {path} also names RAM-LFE and needs evidence text found in the file")
        evidence = backend.get("no_effect_evidence")
        if not isinstance(evidence, list) or not evidence:
            self.error("hkdf.ram_lfe_backend.no_effect_evidence must anchor the consumers that reject the backend")
            evidence = []
        for record in evidence:
            path = record.get("path") if isinstance(record, dict) else None
            self.check_symbol("hkdf no-effect evidence", path, record, expect_test_only=False)
        for path in sorted(user_paths | derivation_paths):
            if not path.endswith(".rs") or path not in self.tree.file_set:
                continue
            owners = accounted.get(path, {})
            for name in hkdf_derivation_functions(self.tree, path, self.features):
                recorded = sorted(set(owners.get(name, [])))
                if not recorded:
                    self.error(
                        f"{path}::{name} instantiates HKDF but is recorded as neither the RAM-LFE backend, "
                        "the plaintext PRF nor another derivation"
                    )
                elif len(recorded) > 1:
                    self.error(f"{path}::{name} instantiates HKDF and is recorded as {' and '.join(recorded)}")
        for path, patterns in sorted(self.scan.items()):
            if "hkdf_ram_lfe" in patterns and path not in user_paths:
                self.error(f"{path} names the RAM-LFE HKDF backend but hkdf.ram_lfe_backend.users does not list it")
            if "hkdf" in patterns and path not in user_paths | derivation_paths | preserved_paths:
                self.error(f"{path} uses HKDF but no hkdf section classifies it")
        for path, info in self.listed.items():
            if info["role"] == "unrelated_hkdf" and path not in preserved_paths:
                self.error(f"{path} has role unrelated_hkdf but hkdf.unrelated_preserve does not list it")

    def check_generated(self) -> None:
        """Verify generated consumers, their evidence and the runtime generators."""
        registry = self.tree.text(GENERATED_REGISTRY) or ""
        seen: set[str] = set()
        for record in self.section("generated_consumers", list):
            path = record.get("path") if isinstance(record, dict) else None
            if not isinstance(path, str):
                self.error("generated_consumers entries need a path")
                continue
            if path in seen:
                self.error(f"generated consumer {path} is listed twice")
            seen.add(path)
            if path not in self.listed:
                self.error(f"generated consumer {path} is not listed in file_groups")
            if record.get("registered") is True and f'"{path}"' not in registry:
                self.error(f"generated consumer {path} is not an output in {GENERATED_REGISTRY}")
            evidence = record.get("evidence")
            if not isinstance(evidence, dict) or not isinstance(evidence.get("path"), str) or not isinstance(evidence.get("literal"), str):
                self.error(f"generated consumer {path} needs evidence with a path and literal")
            elif evidence["literal"] not in (self.tree.text(evidence["path"]) or ""):
                self.error(f"generated consumer {path}: {evidence['path']} does not contain {evidence['literal']!r}")
        generated_code = self.document.get("generated_sdk_code")
        generators = generated_code.get("runtime_generators", []) if isinstance(generated_code, dict) else []
        for record in generators if isinstance(generators, list) else []:
            generator = record.get("generator") if isinstance(record, dict) else None
            for symbol in record.get("symbols", []) if isinstance(record, dict) else []:
                self.check_symbol("runtime generator", generator, symbol, expect_test_only=False)
            for consumer in record.get("consumers", []) if isinstance(record, dict) else []:
                if consumer not in self.listed:
                    self.error(f"runtime generator consumer {consumer} is not listed in file_groups")
        registered = registered_generated_outputs(self.tree)
        for path, info in sorted(self.listed.items()):
            if info["role"] in ("generated_artifact", "fixture", "inventory") and path not in seen:
                self.error(f"{path} has role {info['role']} but generated_consumers does not list it")
            elif path in registered and path not in seen:
                self.error(f"{path} is a registered generated output but generated_consumers does not list it")

    def check_function_assignment(self) -> set[str]:
        """Verify that every function of every owner file has exactly one owner; return the owner files."""
        owners = owner_files(self.tree, self.document, self.features)
        entries: dict[str, dict[str, Any]] = {}
        for entry in self.section("function_assignment", list):
            path = entry.get("path") if isinstance(entry, dict) else None
            if not isinstance(path, str):
                self.error("function_assignment entries need a path")
            elif path in entries:
                self.error(f"function_assignment lists {path} twice")
            else:
                entries[path] = entry
        for path in sorted(set(entries) - set(owners)):
            self.error(f"function_assignment lists {path}, which is not a production-compiled owner file")
        sections = (("production", "protocol_logic"), ("test_gated", "test_only_references"))
        units: dict[str, tuple[Counter, Counter]] = {}
        used: set[tuple[str, str]] = set()
        for path in owners:
            production, gated = units[path] = function_units(self.tree, path, self.features)
            claims = claimed_functions(self.tree, self.document, path, self.features)
            entry = entries.get(path)
            if (production or gated) and path not in self.listed:
                self.error(f"{path} is an owner file but file_groups does not list it")
            if entry is None:
                unowned = sum(count for name, count in production.items() if name not in claims)
                if unowned or gated:
                    self.error(
                        f"{path} is an owner file with {unowned} unclaimed production functions and "
                        f"{sum(gated.values())} test-gated units but has no function_assignment entry"
                    )
                continue
            for key in ("production_unassigned", "test_gated_unassigned"):
                if entry.get(key):
                    self.error(f"{path} leaves {entry[key]} under {key}")
            for (key, section), actual, noun in zip(sections, (production, gated), ("production function", "test-gated unit")):
                recorded: Counter = Counter()
                assigned = entry.get(key, {})
                if not isinstance(assigned, dict):
                    self.error(f"{path} {key} must map entry ids to function names")
                    assigned = {}
                for identifier, names in assigned.items():
                    if identifier not in self.entry_functions[section]:
                        self.error(f"{path} assigns functions to {identifier}, which is not an entry of {section}")
                    if not _is_string_list(names):
                        self.error(f"{path} {key}.{identifier} must be a non-empty list of function names")
                        continue
                    used.add((section, identifier))
                    recorded.update(names)
                for name in sorted(set(actual) | set(recorded)):
                    claimed = key == "production" and name in claims
                    if name not in actual:
                        state = "test-gated or removed" if key == "production" else "ungated or removed"
                        self.error(f"{path} records {name} as a {noun}, but the source has none by that name ({state})")
                    elif claimed and recorded[name]:
                        self.error(f"{path}::{name} is claimed under {claims[name]} and also assigned as protocol logic")
                    elif not claimed and recorded[name] != actual[name]:
                        if not recorded[name]:
                            self.error(f"{path}::{name} is a {noun} with no owner in the inventory")
                        else:
                            self.error(f"{path}::{name} is assigned {recorded[name]} times but defined {actual[name]} times")
        for index, (key, section) in enumerate(sections):
            for identifier, symbols in self.entry_functions[section].items():
                for path, symbol in symbols:
                    if path not in units or path not in entries:
                        continue
                    names = _list(_dict(entries[path].get(key)).get(identifier))
                    for name in function_names(self.tree, path, symbol):
                        if name in units[path][index] and name not in names:
                            self.error(f"{section} {identifier} names {path}::{name}, but function_assignment does not assign it there")
            for entry in _list(self.document.get(section)):
                if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                    continue
                if not entry.get("symbols") and entry.get("whole_file") is not True and (section, entry["id"]) not in used:
                    self.error(f"{section} {entry['id']} names no symbol and owns no function")
        return set(owners)

    def check_kernel_coverage(self, owners: set[str]) -> None:
        """Verify that every production arithmetic-named function outside the owner files is accounted for."""
        prefixes: list[str] = []
        for record in self.section("arithmetic_scopes", list):
            prefix = record.get("prefix") if isinstance(record, dict) else None
            if not isinstance(prefix, str) or not prefix or not isinstance(record.get("reason"), str):
                self.error("arithmetic_scopes entries need a prefix and a reason")
            elif record.get("assignment") not in SCOPE_ASSIGNMENTS:
                self.error(f"arithmetic scope {prefix} needs assignment, one of {list(SCOPE_ASSIGNMENTS)}")
            elif not any(path.startswith(prefix) for path in self.tree.files):
                self.error(f"arithmetic scope {prefix} matches no file")
            else:
                prefixes.append(prefix)
        for path in self.tree.files:
            if path.endswith(".rs") and path not in self.listed and path not in owners and path.startswith(tuple(prefixes)):
                names = production_kernel_functions(self.tree, path, self.features) if prefixes else []
                if names:
                    self.error(f"{path} defines production arithmetic-named functions {names} inside an arithmetic scope but the map does not list it")
        for path in sorted(self.listed):
            if not path.endswith(".rs") or path not in self.tree.file_set or path in owners:
                continue
            covered = self.covered.get(path, set())
            for name in production_kernel_functions(self.tree, path, self.features):
                if not any(name == symbol or name.endswith("::" + symbol) for symbol in covered):
                    self.error(f"{path}::{name} is a production arithmetic-named function the map does not list")

    def run(self) -> list[str]:
        """Run every check and return the inconsistencies found."""
        self.check_header()
        self.check_crates()
        self.check_file_groups()
        self.check_primitives()
        self.check_distinct()
        self.check_protocol()
        owners = self.check_function_assignment()
        self.check_zk_ams_distinct()
        self.check_current_state()
        self.check_hkdf()
        self.check_generated()
        self.check_kernel_coverage(owners)
        return self.errors


def check(root: Path, document: Any, files: Optional[Iterable[str]] = None) -> list[str]:
    """Return every inconsistency between an inventory document and a repository tree."""
    return MapChecker(Tree(root, files), document).run()


# ---------------------------------------------------------------------------
# Maintainer refresh
# ---------------------------------------------------------------------------


def _ordered(record: dict[str, Any], order: tuple[str, ...]) -> dict[str, Any]:
    """Return a record with the known keys first, in a fixed order."""
    result = {key: record[key] for key in order if key in record}
    result.update((key, value) for key, value in record.items() if key not in result)
    return result


def _set_flags(record: dict[str, Any], cfgs: list[str], test_only: bool) -> None:
    record.pop("cfg", None)
    record.pop("test_only", None)
    if cfgs:
        record["cfg"] = cfgs
    if test_only:
        record["test_only"] = True


def refresh(tree: Tree, document: dict[str, Any], scan: Optional[dict[str, list[str]]] = None) -> dict[str, Any]:
    """Return a copy of an inventory with every derived fact recomputed from the tree.

    Classifications are kept. A listed file that no longer exists or no longer
    matches a pattern is dropped. A file the scan newly finds is put in the
    `unclassified` group, and a function of an owner file that nothing owns is
    put under `production_unassigned` or `test_gated_unassigned`; the check
    rejects all three until a maintainer classifies them. A new test-gated unit
    is assigned automatically only when its file already assigns every
    test-gated unit to one reference.
    """
    document = json.loads(json.dumps(document))
    scan = scan if scan is not None else scan_tree(tree)
    features = declared_development_features(document)
    seen: set[str] = set()
    groups = []
    for group in _list(document.get("file_groups")):
        if not isinstance(group, dict) or group.get("id") == UNCLASSIFIED_GROUP:
            continue
        files = []
        for record in _list(group.get("files")):
            path = record.get("path") if isinstance(record, dict) else None
            if not isinstance(path, str) or path in seen or path not in tree.file_set:
                continue
            fresh = scan.get(path)
            if fresh is None and not record.get("pinned"):
                continue
            if fresh is not None:
                record.pop("pinned", None)
            seen.add(path)
            record["patterns"] = fresh or []
            _set_flags(record, *file_facts(tree, path, features))
            files.append(_ordered(record, _FILE_KEY_ORDER))
        if files:
            group["files"] = files
            groups.append(group)
    unclassified = []
    for path in sorted(set(scan) - seen):
        record = {"path": path, "patterns": scan[path]}
        _set_flags(record, *file_facts(tree, path, features))
        unclassified.append(record)
    if unclassified:
        groups.append({
            "id": UNCLASSIFIED_GROUP, "role": UNCLASSIFIED_GROUP,
            "summary": "Files the scan newly finds. Move each into the group that describes it.",
            "files": unclassified,
        })
    document["file_groups"] = groups
    listed = set(listed_files(document))
    for _, path, record, wants_callers in symbol_records(document):
        if not isinstance(path, str):
            continue
        chain, test_only, problem = symbol_facts(tree, path, record["symbol"], features)
        if problem or chain is None:
            continue
        _set_flags(record, chain, test_only)
        record.pop("callers", None)
        record.pop("callers_exhaustive", None)
        source = tree.rust(path) if path.endswith(".rs") else None
        items = source.resolve(record["symbol"]) if source is not None else []
        if wants_callers and not test_only and items and items[0].kind == "fn":
            scope = caller_scope(tree, path, listed, items[0].visibility)
            record["callers"], record["callers_exhaustive"] = find_callers(tree, path, record["symbol"], scope, features)
        ordered = _ordered(record, _SYMBOL_KEY_ORDER)
        record.clear()
        record.update(ordered)
    for user in _list(_dict(_dict(document.get("hkdf")).get("ram_lfe_backend")).get("users")):
        if isinstance(user, dict) and isinstance(user.get("path"), str) and user["path"] in tree.file_set:
            user.pop("test_only", None)
            if file_facts(tree, user["path"], features)[1]:
                user["test_only"] = True
    previous = {
        entry["path"]: entry for entry in _list(document.get("function_assignment"))
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    assignment = []
    for path in owner_files(tree, document, features):
        production, gated = function_units(tree, path, features)
        if not production and not gated:
            continue
        claims = claimed_functions(tree, document, path, features)
        old = previous.get(path, {})
        entry: dict[str, Any] = {"path": path}
        for key, actual in (("production", production), ("test_gated", gated)):
            remaining = Counter({name: count for name, count in actual.items() if not (key == "production" and name in claims)})
            kept: dict[str, list[str]] = {}
            for identifier, names in _dict(old.get(key)).items():
                names = [name for name in _list(names) if isinstance(name, str)]
                taken = []
                for name in sorted(names):
                    if remaining[name] > 0:
                        remaining[name] -= 1
                        taken.append(name)
                if taken or names == []:
                    kept[identifier] = taken
            leftover = sorted(remaining.elements())
            if leftover and key == "test_gated" and len(kept) == 1:
                identifier = next(iter(kept))
                kept[identifier] = sorted(kept[identifier] + leftover)
                leftover = []
            entry[key] = kept
            if leftover:
                entry[key + "_unassigned"] = leftover
        assignment.append(entry)
    document["function_assignment"] = assignment
    return document


def render(value: Any, indent: int = 0) -> str:
    """Serialize an inventory deterministically: short containers on one line, long ones one item per line."""
    pad = " " * indent
    if isinstance(value, dict):
        flat = json.dumps(value, ensure_ascii=False)
        nested = any(isinstance(item, (dict, list)) and len(json.dumps(item, ensure_ascii=False)) > 110 for item in value.values())
        if len(flat) + indent <= 150 and not nested:
            return flat
        items = [f"{pad} {json.dumps(key, ensure_ascii=False)}: {render(item, indent + 1)}" for key, item in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + pad + "}"
    if isinstance(value, list):
        flat = json.dumps(value, ensure_ascii=False)
        if len(flat) + indent <= 150:
            return flat
        items = [f"{pad} {render(item, indent + 1)}" for item in value]
        return "[\n" + ",\n".join(items) + "\n" + pad + "]"
    return json.dumps(value, ensure_ascii=False)


def main(argv: Optional[list[str]] = None) -> int:
    """Run the command-line check and return its exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root (default: this script's repository)")
    parser.add_argument("--map", dest="map_path", default=DEFAULT_MAP, help="inventory path relative to the root")
    parser.add_argument("--print-scan", action="store_true", help="print the fresh detection scan as JSON and exit")
    parser.add_argument("--refresh", action="store_true",
                        help="print the inventory with every derived fact recomputed from the tree and exit")
    parser.add_argument("--write", action="store_true", help="with --refresh, write the result over the inventory file")
    arguments = parser.parse_args(argv)
    if arguments.write and not arguments.refresh:
        parser.error("--write requires --refresh")
    tree = Tree(arguments.root)
    if arguments.print_scan:
        json.dump(scan_tree(tree), sys.stdout, indent=1, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    target = arguments.root / arguments.map_path
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"cannot read {arguments.map_path}: {error}")
        return 1
    if arguments.refresh:
        if not isinstance(document, dict):
            print(f"{arguments.map_path} must hold a JSON object")
            return 1
        text = render(refresh(tree, document)) + "\n"
        if arguments.write:
            target.write_text(text, encoding="utf-8")
            print(f"refreshed {arguments.map_path}; run the check to see what still needs classifying")
        else:
            sys.stdout.write(text)
        return 0
    checker = MapChecker(tree, document)
    errors = checker.run()
    for message in errors:
        print(f"error: {message}")
    if errors:
        print(f"{len(errors)} inconsistencies between {arguments.map_path} and the tree. {SCOPE}")
        return 1
    primitives = len(document.get("primitives", []))
    print(f"{arguments.map_path}: {len(checker.listed)} files and {primitives} primitives match the tree. {SCOPE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
