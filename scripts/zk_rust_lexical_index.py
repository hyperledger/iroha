#!/usr/bin/env python3
"""Lexical index of Rust functions for scripts/check_zk_primitive_workloads.py.

Requires Python 3.9+ and its standard library; no environment variables or
installed packages are needed. The module is read-only and is imported by the
primitive and workload checker; run on its own it prints the functions of the
files named on the command line with their test-only status.

It answers two questions without compiling anything:
* which `fn` items a Rust file holds, with their body, return type and the
  attributes of the item and of every enclosing `mod`, `impl` or `trait` block;
* whether a file is compiled only for tests, from the `mod name;` declarations
  and `include!("file.rs")` splices of its crate (`#[cfg(test)]`,
  `#[path = "..."]`, inline modules).

Limits. The index is lexical: it does not expand macros, resolve `use` paths or
evaluate arbitrary cfg predicates. A function produced by a macro is invisible;
an item is test-only only when one of the attribute forms listed in
`TEST_ATTRIBUTE` guards it or an enclosing block, or when every `mod`
declaration that reaches its file is guarded that way. A file under `tests/`,
`benches/` or `examples/` is test-only by directory convention. A file under
`src/` that no declaration reaches is reported as unreached.
"""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Callable, Iterable, Optional, Sequence

# Attribute bodies that make an item, and everything inside it, test-only.
TEST_ATTRIBUTE = re.compile(r"(?:test|cfg\(\s*test\s*\)|cfg\(\s*all\(\s*test\b.*\)\s*\))\Z", re.S)
NON_PRODUCTION_DIRECTORIES = frozenset({"tests", "benches", "examples"})
_LEXEME = re.compile(
    r"//[^\n]*"
    r"|/\*"
    r'|(?<![A-Za-z0-9_])b?r(?P<raw>#*)"'
    r'|"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\\n]|\\(?:u\{[0-9A-Fa-f_]{1,8}\}|x[0-9A-Fa-f]{2}|.))'",
    re.S,
)
_COMMENT_EDGE = re.compile(r"/\*|\*/")
_ITEM = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r'(?:extern\s+(?:"[^"]*"\s+)?)?(fn|mod|impl|trait)\b\s*([^{;]*)',
    re.S,
)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MOD_DECLARATION = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
_DECLARES = re.compile(r"\bmod\s+[A-Za-z_][A-Za-z0-9_]*\s*;|\binclude\s*!")
_STRUCTURAL = re.compile(r"[{}()\[\];]")
_STATEMENT_EDGE = re.compile(r"[;{}]")
_INCLUDE = re.compile(r'\binclude\s*!\s*\(\s*"')
_ATTRIBUTE = re.compile(r"#\[")
_PATH_ATTRIBUTE = re.compile(r'path\s*=\s*"([^"]+)"\Z')


def _blank(text: str) -> str:
    """Spaces for every character of `text` except newlines."""
    return "".join("\n" if char == "\n" else " " for char in text) if "\n" in text else " " * len(text)


def mask(source: str) -> str:
    """Blank comments and the contents of string and character literals.

    Offsets and newlines are preserved, so a position in the result is the same
    position in `source`. Delimiters of literals are kept.
    """
    pieces: list[str] = []
    position = 0
    length = len(source)
    while True:
        match = _LEXEME.search(source, position)
        if match is None:
            pieces.append(source[position:])
            return "".join(pieces)
        start = match.start()
        pieces.append(source[position:start])
        text = match.group(0)
        if text.startswith("//"):
            end = match.end()
            pieces.append(_blank(text))
        elif text == "/*":
            depth, end = 1, match.end()
            while depth:
                nested = _COMMENT_EDGE.search(source, end)
                if nested is None:
                    end = length
                    break
                depth += 1 if nested.group(0) == "/*" else -1
                end = nested.end()
            pieces.append(_blank(source[start:end]))
        elif match.group("raw") is not None:
            closing = '"' + match.group("raw")
            close = source.find(closing, match.end())
            close = length if close < 0 else close
            end = min(length, close + len(closing))
            pieces.append(text + _blank(source[match.end():close]) + source[close:end])
        else:
            # A string or character literal: keep the delimiters, blank the contents.
            end = match.end()
            opening = text.index(text[-1]) + 1
            pieces.append(text[:opening] + _blank(text[opening:-1]) + text[-1])
        position = end


class Block:
    """One braced item: a function, module, impl or trait body, or another block."""

    __slots__ = ("kind", "name", "header_start", "body_start", "end", "attributes", "parent", "returns")

    def __init__(self, kind: str, name: str, header_start: int, body_start: int,
                 attributes: tuple[str, ...], parent: Optional["Block"], returns: str) -> None:
        self.kind = kind
        self.name = name
        self.header_start = header_start
        self.body_start = body_start
        self.end = body_start
        self.attributes = attributes
        self.parent = parent
        self.returns = returns

    def chain(self) -> list["Block"]:
        """This block and its enclosing blocks, innermost first."""
        result, node = [], self
        while node is not None:
            result.append(node)
            node = node.parent
        return result

    def test_only(self) -> bool:
        """Whether a test attribute guards this block or an enclosing one."""
        return any(TEST_ATTRIBUTE.match(attribute) for block in self.chain() for attribute in block.attributes)

    def qualified_name(self) -> str:
        """Names of the enclosing named items and of this one, joined by `::`."""
        return "::".join(block.name for block in reversed(self.chain()) if block.name)


def _attributes(original: str, masked: str, start: int, end: int) -> tuple[tuple[str, ...], int]:
    """Attribute bodies in `original[start:end]` and the offset after the last one."""
    found, position = [], start
    while True:
        match = _ATTRIBUTE.search(masked, position, end)
        if not match or masked[position:match.start()].strip():
            return tuple(found), position
        depth, cursor = 1, match.end()
        while cursor < end and depth:
            depth += {"[": 1, "]": -1}.get(masked[cursor], 0)
            cursor += 1
        found.append(" ".join(original[match.end():cursor - 1].split()))
        position = cursor


def _impl_name(rest: str) -> str:
    """Type name of an `impl` header: the type after `for`, or the first path."""
    depth, cleaned = 0, []
    for char in rest:
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            cleaned.append(char)
    text = "".join(cleaned).split(" where ")[0]
    target = text.split(" for ")[-1]
    names = _NAME.findall(target)
    return names[-1] if names else ""


def _return_type(source: str, start: int, end: int) -> str:
    """Return type written in the `fn` header `source[start:end]`, or an empty string."""
    round_depth = angle_depth = 0
    position = start
    while position < end:
        char = source[position]
        if char == "-" and source.startswith("->", position):
            if round_depth == 0 and angle_depth == 0:
                return " ".join(source[position + 2:end].split()).split(" where ")[0].strip()
            position += 2
            continue
        if char in "([":
            round_depth += 1
        elif char in ")]":
            round_depth -= 1
        elif char == "<":
            angle_depth += 1
        elif char == ">":
            angle_depth = max(0, angle_depth - 1)
        position += 1
    return ""


def blocks(source: str, masked: Optional[str] = None) -> list[Block]:
    """Every braced block of a Rust file in order of its opening brace."""
    masked = mask(source) if masked is None else masked
    result: list[Block] = []
    stack: list[Block] = []
    # Parenthesis and bracket depth of the current brace level; a `;` inside
    # `[u8; 32]` or a call argument does not end the statement.
    depths = [0]
    statement_start = 0
    for structural in _STRUCTURAL.finditer(masked):
        position, char = structural.start(), structural.group(0)
        if char in "([":
            depths[-1] += 1
        elif char in ")]":
            depths[-1] = max(0, depths[-1] - 1)
        elif char == "{":
            attributes, header = _attributes(source, masked, statement_start, position)
            text = masked[header:position]
            lead = len(text) - len(text.lstrip())
            item = _ITEM.match(text, lead)
            kind, name, returns = "block", "", ""
            if item:
                kind, rest = item.group(1), item.group(2)
                if kind == "impl":
                    name = _impl_name(rest)
                else:
                    found = _NAME.match(rest.strip())
                    name = found.group(0) if found else ""
                if kind == "fn":
                    returns = _return_type(masked, header + item.start(2), position)
                    if returns:
                        # Re-read from the source so string-typed generics are not blanked.
                        returns = _return_type(source, header + item.start(2), position) or returns
            block = Block(kind, name, header, position, attributes, stack[-1] if stack else None, returns)
            result.append(block)
            stack.append(block)
            depths.append(0)
            statement_start = position + 1
        elif char == "}":
            if stack:
                stack.pop().end = position + 1
            if len(depths) > 1:
                depths.pop()
            statement_start = position + 1
        elif depths[-1] == 0:
            statement_start = position + 1
    return result


def functions(source: str, masked: Optional[str] = None) -> list[Block]:
    """The `fn` items of a file that have a body."""
    return [block for block in blocks(source, masked) if block.kind == "fn" and block.name]


class CrateModules:
    """Which files of a set are compiled only for tests, from `mod` declarations."""

    def __init__(self, files: Iterable[str], read: Callable[[str], Optional[str]]) -> None:
        self.files = frozenset(path for path in files if path.endswith(".rs"))
        self.read = read
        self._declared: Optional[dict[str, list[tuple[str, bool]]]] = None
        self._status: dict[str, str] = {}

    @staticmethod
    def _child_directory(parent: str, inline: Sequence[str]) -> str:
        path = PurePosixPath(parent)
        base = path.parent if path.name in ("mod.rs", "lib.rs", "main.rs") else path.parent / path.stem
        for name in inline:
            base = base / name
        return base.as_posix()

    def _declarations(self) -> dict[str, list[tuple[str, bool]]]:
        """Child file -> [(declaring file, guarded by a test attribute)]."""
        if self._declared is not None:
            return self._declared
        declared: dict[str, list[tuple[str, bool]]] = {}
        for parent in sorted(self.files):
            source = self.read(parent)
            if source is None or not _DECLARES.search(source):
                continue
            masked = mask(source)
            every = blocks(source, masked)
            inline = [block for block in every if block.kind == "mod" and block.name]
            for match in _INCLUDE.finditer(masked):
                # `include!("x.rs")` splices a file into the enclosing item.
                closing = source.find('"', match.end())
                candidate = _normalize(
                    (PurePosixPath(parent).parent / source[match.end():closing]).as_posix()
                )
                guarded = any(
                    block.test_only() for block in every if block.body_start < match.start() < block.end
                )
                if candidate in self.files:
                    declared.setdefault(candidate, []).append((parent, guarded))
            for match in _MOD_DECLARATION.finditer(masked):
                # The attributes of the declaration sit between the previous statement and `mod`.
                start = 0
                for edge in _STATEMENT_EDGE.finditer(masked, max(0, match.start() - 2048), match.start()):
                    start = edge.end()
                attributes, _ = _attributes(source, masked, start, match.start())
                enclosing = [block for block in inline if block.body_start < match.start() < block.end]
                guarded = any(TEST_ATTRIBUTE.match(attribute) for attribute in attributes) or any(
                    block.test_only() for block in enclosing
                )
                explicit = next(
                    (found.group(1) for attribute in attributes
                     if (found := _PATH_ATTRIBUTE.match(attribute))), None
                )
                name = match.group(1)
                if explicit is not None:
                    directory = PurePosixPath(parent).parent
                    if enclosing:
                        directory = PurePosixPath(self._child_directory(parent, [b.name for b in enclosing]))
                    candidates = [_normalize((directory / explicit).as_posix())]
                else:
                    directory = self._child_directory(parent, [block.name for block in enclosing])
                    candidates = [f"{directory}/{name}.rs", f"{directory}/{name}/mod.rs"]
                for candidate in candidates:
                    if candidate in self.files:
                        declared.setdefault(candidate, []).append((parent, guarded))
        self._declared = declared
        return declared

    def status(self, path: str) -> str:
        """`production`, `test-only` or `unreached` for one Rust file."""
        if path in self._status:
            return self._status[path]
        self._status[path] = "unreached"  # breaks declaration cycles
        parts = PurePosixPath(path).parts
        name = parts[-1]
        if NON_PRODUCTION_DIRECTORIES & set(parts[:-1]):
            result = "test-only"
        elif name in ("lib.rs", "main.rs") or (len(parts) >= 3 and parts[-2] == "bin" and parts[-3] == "src"):
            result = "production"
        else:
            reached = [
                "test-only" if guarded else self.status(parent)
                for parent, guarded in self._declarations().get(path, [])
            ]
            if "production" in reached:
                result = "production"
            elif "test-only" in reached:
                result = "test-only"
            else:
                result = "unreached"
        self._status[path] = result
        return result


def _normalize(path: str) -> str:
    """Resolve `.` and `..` segments of a POSIX path lexically."""
    parts: list[str] = []
    for part in path.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Print the functions of the named files."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", type=Path, help="Rust files to index")
    args = parser.parse_args(argv)
    for path in args.paths:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            print(f"{path}: {error}", file=sys.stderr)
            return 1
        for function in functions(source):
            line = source.count("\n", 0, function.header_start) + 1
            marker = "test-only" if function.test_only() else "item"
            print(f"{path}:{line}\t{marker}\t{function.qualified_name()}\t{function.returns}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
