#!/usr/bin/env python3
"""Check the first-release history and cutover inventory against the source tree.

The inventory is `specs/first_release_history_cutover.json`; its contract is
`specs/first_release_history_cutover.md`. The check reads source text and the
pinned history fixture. It builds nothing, runs no test, decodes no stored
history and changes no file. It fails when:

- a history-bearing wire type admits a version other than its single listed one,
  or a `Version` implementation is not listed;
- a listed replay, restart or rejection test no longer exists, is ignored, is
  conditionally compiled, or names no package and target;
- a blocked test target's anchor no longer matches, so the entry is stale;
- the pinned history fixture differs from its manifest or from the digest the
  inventory records, or its generator or replay test is gone;
- a history loader defines or imports a compatibility-named item that is neither
  a listed rejection helper nor a classified definition;
- a retired decoder or shim identifier reappears, or a retired trait
  implementation (`impl <Trait> for <Type>`) is written again anywhere;
- a helper kept only for tests is referenced from production source;
- a retired store artifact refusal no longer exists, is no longer called from
  the Strict open path, refuses other names than the inventory lists, or a
  retired-artifact refusal exists that the inventory does not list;
- an incompatible-change surface lacks a concrete regeneration target with a
  generator or checking test that mentions it, or the contract table and the
  inventory list different surfaces or cutovers;
- the ABI V1 hash golden differs from the hash the inventory declares, a listed
  artifact of that surface does not carry the declared hash in every form its
  entry states (a text carrier exactly the stated number of times; a program
  file, artifact map, compiler capture or base64 fixture in the header of every
  program it holds), or the pinned history holds it while the declaration says
  no fresh genesis is needed;
- a probe or custody anchor of the obsolete-history evidence is gone;
- the contract section that states the rule for a future authenticated
  checkpoint changes, loses one of its listed statements, or the source site
  that marks restore as unimplemented is gone, without the inventory changing;
- a prerequisite of a listed test (a daemon build, its environment variable) no
  longer matches the source;
- an open finding no longer matches the source, so the inventory is stale.

Limits. The loader check is name-based: it sees definitions and `use ... as`
imports whose name says compatibility. It does not see a fallback written
inside an existing function, a version `match` outside the `Version` trait, or
a neutral name. The test check reads attributes on the test function only, not
on enclosing modules. Whether a retired artifact is still refused at run time,
and whether a history written by an earlier build still replays, is established
by the listed Rust tests, which read this inventory and the pinned fixture.
The ABI carrier check reads the listed carriers only: it does not search the
tree for another file that states the hash, and in a text carrier it counts the
declared hash without knowing which other fields could state one. A test-only
reference is matched as written: `decode_exact_versioned::<SignedBlock>` is
seen, the same call with an inferred type is not.

`--report` prints every open finding as `path:line` at the current source.
`--test-commands` prints one `cargo test` command per package and target that
runs exactly the listed tests; blocked targets are printed as comments. A
package with a listed prerequisite gets its build command first and its
environment on every command, so each printed line runs as printed from the
repository root. The future-checkpoint check pins the text of a rule; it does
not establish that checkpoints exist or work.

Requires Python 3.10+ and no third-party module. `--root` selects another
checkout (default: the repository containing this script).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys

INVENTORY = "specs/first_release_history_cutover.json"
SCHEMA = "iroha.first_release_history_cutover.v1"
CUTOVERS = ("fresh_genesis", "contract_redeployment", "fresh_genesis_when_stored")
ARTIFACT_LOCATIONS = {
    "blocks_root": "blocks_root.join(retired)",
    "store_root": "store_root.join(retired)",
}
ARTIFACT_KINDS = ("file", "directory")
SKIPPED_DIRECTORIES = frozenset(("target", "node_modules", ".git"))
TEST_PATH = re.compile(
    r"(?:^|/)(?:tests|benches|examples|fuzz)(?:/|$)"
    r"|_tests(?:/|\.rs$)"
    r"|(?:^|/)tests\.rs$"
)
TEST_ATTRIBUTE = re.compile(
    r"#\[\s*(?:cfg\s*\(\s*(?:test\b|all\s*\(\s*test\b|any\s*\(\s*test\b)"
    r"|(?:\w+::)*test\b)"
)
INNER_TEST_ATTRIBUTE = re.compile(r"^\s*#!\[\s*cfg\s*\(\s*test\s*\)\s*\]", re.MULTILINE)
IS_TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:\w+::)*test\b")
IGNORE_ATTRIBUTE = re.compile(r"#\[\s*(?:ignore\b|cfg_attr\b[^\]]*\bignore\b)")
CFG_ATTRIBUTE = re.compile(r"#\[\s*cfg\s*\((?P<predicate>.*)\)\s*\]\Z", re.DOTALL)
FUNCTION_QUALIFIER = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?|async|const|unsafe|extern)\s*\Z"
)
VERSION_IMPL = re.compile(
    r"\bimpl\b(?:\s*<[^{;]*?>)?\s*(?:\w+::)*Version\s+for\s+(?P<type>\w+)[^{;]*\{"
)
VERSION_IMPL_BYTES = re.compile(rb"\bVersion\s+for\s")
VERSION_LITERAL = re.compile(r"\bfn\s+version\s*\(\s*&self\s*\)\s*->\s*u8\s*\{\s*(\d+)\s*\}")
SUPPORTED_RANGE = re.compile(
    r"\bfn\s+supported_versions\s*\(\s*\)\s*->\s*[\w:]*Range\s*<\s*u8\s*>\s*\{"
    r"\s*(\d+)\s*\.\.\s*(\d+)\s*\}"
)
LAYOUT_WORD = r"layout|format|wire|header|schema|version|codec|encoding|decod|payload"
LAYOUT_WORD_UPPER = r"LAYOUT|FORMAT|WIRE|HEADER|SCHEMA|VERSION|CODEC|ENCODING|PAYLOAD"
LAYOUT_WORD_CAMEL = r"Layout|Format|Wire|Header|Schema|Version|Codec|Encoding|Payload|Block"
COMPATIBILITY_NAME = (
    r"[Ll]egacy|LEGACY|[Cc]ompat(?!ibl)|COMPAT(?!IBL)|[Mm]igrat|MIGRAT"
    r"|PreRelease|pre_release|PRE_RELEASE"
    r"|[Ss]him|SHIM|[Dd]eprecated|DEPRECATED|_v0\b|V0\b"
    r"|fallback_(?:decod|layout|format|wire)|(?:decod|layout|format|wire)\w*_fallback"
    # An earlier layout named as such: `decode_old_layout`, `PreviousHeader`, `PRIOR_FORMAT`.
    r"|(?<![a-z])(?:old|previous|prior)_(?:" + LAYOUT_WORD + r")"
    r"|(?:decode|decoder|parse|read|load|" + LAYOUT_WORD + r")_(?:old|previous|prior)(?![a-z])"
    r"|(?<![A-Z])(?:OLD|PREVIOUS|PRIOR)_(?:" + LAYOUT_WORD_UPPER + r")"
    r"|(?<![a-z])(?:Old|Previous|Prior)(?:" + LAYOUT_WORD_CAMEL + r")"
    # A second name for a layout: `wire_alias`, `alias_layout`, `LayoutAlias`.
    r"|(?:layout|format|wire|decoder|schema|version|compat)_alias(?![a-z])"
    r"|(?<![a-z])alias_(?:layout|format|wire|decoder|schema|version)"
    r"|(?:Layout|Format|Wire|Decoder|Schema|Version)Alias"
    r"|Alias(?:Layout|Format|Wire|Decoder|Schema|Version)"
)
COMPATIBILITY_DEFINITION = re.compile(
    r"\b(?:fn|struct|enum|type|const|static|mod|trait)\s+"
    r"(?P<name>\w*(?:" + COMPATIBILITY_NAME + r")\w*)"
)
COMPATIBILITY_WORD = re.compile(r"\w*(?:" + COMPATIBILITY_NAME + r")\w*\Z")
USE_STATEMENT = re.compile(r"\buse\b[^;]*;")
USE_ALIAS = re.compile(r"\bas\s+(?P<name>\w+)")
RETIRED_REFUSAL = re.compile(r"\bfn\s+(?P<name>(?:reject|ensure_no)_retired_\w+)")
INLINE_RETIRED_ARRAY = re.compile(r"\bfor\s+retired\s+in\s*\[")
SURFACE_ROW = re.compile(
    r"^\|\s*`(?P<id>[a-z_]+)`\s*\|[^|]*\|\s*`(?P<cutover>[a-z_]+)`[^|]*\|", re.MULTILINE
)
SURFACE_ID = re.compile(r"[a-z][a-z_]*\Z")
TEST_TARGET = re.compile(r"(?:lib|test:[A-Za-z0-9_]+)\Z")
BUILD_COMMAND = re.compile(r"cargo build -p [A-Za-z0-9_-]+ --bin [A-Za-z0-9_-]+\Z")
ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*\Z")
# A value a POSIX shell expands inside double quotes: no quote, backtick or command substitution.
ENVIRONMENT_VALUE = re.compile(r"[A-Za-z0-9_./:${}-]+\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
PLAIN_IDENTIFIER = re.compile(r"[A-Za-z_]\w*\Z")
# How a regeneration target carries the ABI V1 hash. Text forms: lower-case or upper-case
# hexadecimal, or hexadecimal split over adjacent string literals or lines; the hash occurs in
# each stated text form exactly as often as the entry's `occurrences` says (once by default).
# Program forms: the header of one IVM program, of every IVM program an artifact map lists in
# its third column, of every hexadecimal IVM program in the tab-separated rows of a compiler
# capture, or of every base64 IVM program embedded in a text fixture. An entry may state
# several forms; each must hold.
ABI_TEXT_FORMS = ("hex", "HEX", "hex_wrapped")
ABI_HASH_FORMS = (
    *ABI_TEXT_FORMS,
    "ivm_header",
    "artifact_map",
    "ivm_hex_rows",
    "ivm_base64",
)
# An IVM program starts with magic, version, mode, vector length, cycle bound and ABI version;
# the ABI hash is the last field of that fixed header.
IVM_MAGIC = b"IVM\0"
IVM_ABI_HASH_SPAN = (17, 49)
HEX_WRAPPING = re.compile(rb'[\s"]+')
IVM_MAGIC_HEX = IVM_MAGIC.hex()
HEX_TEXT = re.compile(r"(?:[0-9a-f]{2})+\Z")
# Base64 of a byte string that starts with the IVM magic: `SVZN` encodes `IVM` and the zero
# byte that follows fixes the next character to `A`.
IVM_BASE64 = re.compile(rb"(?<![A-Za-z0-9+/=])SVZNA[A-Za-z0-9+/]*={0,2}(?![A-Za-z0-9+/=])")
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]{1,8}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'")
LITERAL_START = re.compile(r"//|/\*|\"|'|\b[bc]?r#*\"")
BLOCK_COMMENT_EDGE = re.compile(r"/\*|\*/")
STRING_END = re.compile(r'(?:[^"\\]|\\.)*"', re.DOTALL)
NOT_NEWLINE = re.compile(r"[^\n]")
BRACE = re.compile(r"[{}]")
BRACKET = re.compile(r"[\[\]]")


def literal_spans(text: str) -> list[tuple[str, int, int, str]]:
    """Comments and literals of Rust source as `(kind, start, end, content)`.

    `kind` is `comment`, `string` or `char`; `content` is a string literal's text between its
    quotes (escapes are kept as written) and empty otherwise.
    """
    spans: list[tuple[str, int, int, str]] = []
    index = 0
    length = len(text)
    while True:
        found = LITERAL_START.search(text, index)
        if found is None:
            return spans
        start, token = found.start(), found.group()
        if token == "//":
            end = text.find("\n", start)
            end = length if end < 0 else end
            spans.append(("comment", start, end, ""))
        elif token == "/*":
            depth, end = 1, start + 2
            while depth:
                edge = BLOCK_COMMENT_EDGE.search(text, end)
                if edge is None:
                    end = length
                    break
                depth += 1 if edge.group() == "/*" else -1
                end = edge.end()
            spans.append(("comment", start, end, ""))
        elif token == '"':
            closing = STRING_END.match(text, start + 1)
            end = length if closing is None else closing.end()
            spans.append(("string", start, end, text[start + 1 : max(start + 1, end - 1)]))
        elif token == "'":
            literal = CHAR_LITERAL.match(text, start)
            if literal is None:
                # A lifetime or loop label, not a literal.
                index = start + 1
                continue
            end = literal.end()
            spans.append(("char", start, end, ""))
        else:
            closing = '"' + "#" * token.count("#")
            close_at = text.find(closing, found.end())
            end = length if close_at < 0 else close_at + len(closing)
            content_end = length if close_at < 0 else close_at
            spans.append(("string", start, end, text[found.end() : content_end]))
        index = end


def blank_rust_literals(text: str) -> str:
    """Blank comments and string/char literal contents, keeping length and newlines."""
    out: list[str] = []
    index = 0
    for _, start, end, _ in literal_spans(text):
        out.append(text[index:start])
        out.append(NOT_NEWLINE.sub(" ", text[start:end]))
        index = end
    out.append(text[index:])
    return "".join(out)


def matching_close(blanked: str, opening: int, pair: re.Pattern[str] = BRACE) -> int:
    """Return the index after the delimiter matching `blanked[opening]`, or the text length."""
    depth = 0
    for found in pair.finditer(blanked, opening):
        depth += 1 if found.group() in "{[" else -1
        if depth == 0:
            return found.end()
    return len(blanked)


def item_start(blanked: str, position: int) -> int:
    """Skip whitespace and attributes from `position` to the item they apply to."""
    while True:
        while position < len(blanked) and blanked[position].isspace():
            position += 1
        if not blanked.startswith("#[", position):
            return position
        position = matching_close(blanked, position + 1, BRACKET)


def item_end(blanked: str, start: int) -> int:
    """Return the index after the item starting at `start`: its block, or its `;`."""
    nesting = 0
    for index in range(start, len(blanked)):
        char = blanked[index]
        if char in "([":
            nesting += 1
        elif char in ")]":
            nesting -= 1
        elif char == "{":
            return matching_close(blanked, index)
        elif char == ";" and nesting <= 0:
            return index + 1
    return len(blanked)


def test_spans(blanked: str) -> list[tuple[int, int]]:
    """Character spans of items compiled only for tests (`cfg(test)` items and test functions)."""
    if INNER_TEST_ATTRIBUTE.search(blanked):
        return [(0, len(blanked))]
    spans: list[tuple[int, int]] = []
    covered = 0
    for attribute in TEST_ATTRIBUTE.finditer(blanked):
        if attribute.start() < covered:
            continue
        covered = item_end(blanked, item_start(blanked, attribute.start()))
        spans.append((attribute.start(), covered))
    return spans


def in_spans(position: int, spans: list[tuple[int, int]]) -> bool:
    """Whether `position` lies inside one of `spans`."""
    return any(start <= position < end for start, end in spans)


def line_of(text: str, position: int) -> int:
    """One-based line number of a character position."""
    return text.count("\n", 0, position) + 1


def is_test_path(relative: str) -> bool:
    """Whether a repository-relative Rust path is test, bench, example or fuzz source."""
    return TEST_PATH.search(relative) is not None


def rust_sources(root: Path, relative_roots: list[str]) -> list[Path]:
    """Every `.rs` file below the given files, directories or glob patterns, sorted."""
    found: set[Path] = set()
    for relative in relative_roots:
        if any(char in relative for char in "*?["):
            candidates = sorted(root.glob(relative))
        else:
            candidates = [root / relative]
        for candidate in candidates:
            if candidate.is_file():
                if candidate.suffix == ".rs":
                    found.add(candidate)
                continue
            for parent, directories, names in os.walk(candidate):
                directories[:] = sorted(set(directories) - SKIPPED_DIRECTORIES)
                found.update(Path(parent) / name for name in names if name.endswith(".rs"))
    return sorted(found)


def read(path: Path) -> str | None:
    """Read UTF-8 source, or `None` when the file is missing or unreadable."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


class Source:
    """One Rust source file: its text, the text with literals blanked, and its literals."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.literals = literal_spans(text)
        self.blanked = blank_rust_literals(text)
        self.tests = test_spans(self.blanked)

    def function(self, name: str) -> tuple[int, int] | None:
        """Span of the first production function `name`, from `fn` to the end of its body."""
        pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\s*(?:<[^>(]*>)?\s*\(")
        for found in pattern.finditer(self.blanked):
            if not in_spans(found.start(), self.tests):
                return found.start(), item_end(self.blanked, found.start())
        return None

    def strings(self, start: int, end: int) -> list[str]:
        """Contents of the string literals inside `[start, end)`."""
        return [
            content
            for kind, begin, finish, content in self.literals
            if kind == "string" and start <= begin and finish <= end
        ]


class Sources:
    """Rust sources of one checkout, lexed once."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.cache: dict[str, Source | None] = {}

    def get(self, relative: str) -> Source | None:
        """The lexed source at a repository-relative path, or `None` when unreadable."""
        if relative not in self.cache:
            text = read(self.root / relative)
            self.cache[relative] = None if text is None else Source(text)
        return self.cache[relative]


def load_inventory(root: Path) -> tuple[dict, list[str]]:
    """Load the inventory and report structural defects."""
    path = root / INVENTORY
    try:
        inventory = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return {}, [f"{INVENTORY}: unreadable inventory: {error}"]
    errors: list[str] = []
    if not isinstance(inventory, dict) or inventory.get("schema") != SCHEMA:
        return {}, [f"{INVENTORY}: schema must be {SCHEMA}"]
    required = {
        "contract": str,
        "history_wire": list,
        "test_only_version_impls": list,
        "replay_tests": list,
        "obsolete_layout_rejection_tests": list,
        "blocked_test_targets": list,
        "pinned_history": dict,
        "loader_paths": list,
        "loader_rejection_helpers": list,
        "loader_classified_definitions": list,
        "test_only_references": list,
        "retired_identifier_roots": list,
        "retired_identifiers": list,
        "retired_impls": list,
        "retired_store_artifacts": list,
        "incompatible_change_surfaces": list,
        "declared_abi_cutover": dict,
        "obsolete_history_evidence": dict,
        "future_checkpoint_rule": dict,
        "test_prerequisites": list,
        "open_findings": list,
    }
    for key, kind in required.items():
        if not isinstance(inventory.get(key), kind):
            errors.append(f"{INVENTORY}: `{key}` must be a {kind.__name__}")
    if errors:
        return {}, errors
    for key in (
        "history_wire",
        "replay_tests",
        "retired_identifiers",
        "loader_paths",
        "retired_store_artifacts",
        "incompatible_change_surfaces",
    ):
        if not inventory[key]:
            errors.append(f"{INVENTORY}: `{key}` must not be empty")
    if not (root / inventory["contract"]).is_file():
        errors.append(f"{INVENTORY}: contract {inventory['contract']} is missing")
    return inventory, errors


def version_impl_errors(
    relative: str,
    text: str,
    listed: dict[tuple[str, str], dict],
    test_only: set[tuple[str, str]],
    seen: set[tuple[str, str]],
) -> list[str]:
    """Check the `Version` implementations of one source file against the inventory."""
    errors: list[str] = []
    blanked = blank_rust_literals(text)
    for found in VERSION_IMPL.finditer(blanked):
        key = (relative, found.group("type"))
        seen.add(key)
        where = f"{relative}:{line_of(blanked, found.start())}"
        if key in test_only:
            continue
        entry = listed.get(key)
        if entry is None:
            errors.append(
                f"{where}: `Version` implementation for {key[1]} is not listed in "
                f"{INVENTORY}; a history-bearing wire type has exactly one version"
            )
            continue
        body = blanked[found.end() - 1 : matching_close(blanked, found.end() - 1)]
        version = VERSION_LITERAL.search(body)
        supported = SUPPORTED_RANGE.search(body)
        expected = entry["version"]
        if version is None or int(version.group(1)) != expected:
            errors.append(f"{where}: {key[1]}::version must be the literal {expected}")
        if supported is None or (int(supported.group(1)), int(supported.group(2))) != (
            expected,
            expected + 1,
        ):
            errors.append(
                f"{where}: {key[1]}::supported_versions must be exactly "
                f"{expected}..{expected + 1}; no second layout or version dispatch"
            )
    return errors


def reference_pattern(needle: str) -> str:
    """Regular expression matching a Rust path or cast written with any spacing."""
    words = [
        r"\s*::\s*".join(re.escape(piece) for piece in word.split("::"))
        for word in needle.split()
    ]
    return r"(?<!\w)" + r"\s+".join(words) + r"(?!\w)"


def retired_impl_pattern(trait: str, target: str) -> re.Pattern[str]:
    """Regular expression matching `impl <trait> for <target>` with any path or generics."""
    path = r"(?:\w+\s*::\s*)*"
    generics = r"(?:\s*<[^{;]*?>)?"
    return re.compile(
        r"\bimpl\b" + generics + r"\s*" + path + re.escape(trait) + generics
        + r"\s+for\s+" + path + re.escape(target) + r"(?!\w)"
    )


def retired_impl_errors(
    relative: str, text: str, retired: list[tuple[dict, re.Pattern[str]]]
) -> list[str]:
    """Retired trait implementations written again in one source file, tests included."""
    blanked = blank_rust_literals(text)
    return [
        f"{relative}:{line_of(blanked, found.start())}: retired implementation "
        f"`{entry['trait']} for {entry['type']}` reappeared"
        for entry, pattern in retired
        for found in pattern.finditer(blanked)
    ]


def test_only_reference_errors(
    relative: str, text: str, references: list[tuple[dict, re.Pattern[str]]]
) -> list[str]:
    """Production references in one source file to helpers kept only for tests."""
    if is_test_path(relative):
        return []
    errors: list[str] = []
    blanked = blank_rust_literals(text)
    spans = test_spans(blanked)
    for entry, pattern in references:
        for found in pattern.finditer(blanked):
            if in_spans(found.start(), spans):
                continue
            if re.search(r"\bfn\s+\Z", blanked[: found.start()]):
                continue
            errors.append(
                f"{relative}:{line_of(blanked, found.start())}: production source references "
                f"`{entry['needle']}`, which is kept only for tests ({entry['finding']})"
            )
    return errors


def check_sources(root: Path, inventory: dict) -> list[str]:
    """One pass over the scanned roots.

    Every `Version` implementation must be listed, and a history-bearing type admits exactly its
    one listed version. No retired decoder or shim identifier may appear anywhere, and no retired
    trait implementation may be written again. A helper kept only for tests has no reference in
    production source.
    """
    identifiers = [entry["identifier"] for entry in inventory["retired_identifiers"]]
    errors = [
        f"{INVENTORY}: retired identifier `{identifier}` is not a plain identifier"
        for identifier in identifiers
        if not re.fullmatch(r"\w+", identifier)
    ]
    findings = {entry["id"] for entry in inventory["open_findings"]}
    references: list[tuple[dict, re.Pattern[str]]] = []
    for entry in inventory["test_only_references"]:
        if entry["finding"] not in findings:
            errors.append(
                f"{INVENTORY}: test-only reference `{entry['needle']}` names the unknown "
                f"finding {entry['finding']}; when the helper is gone, delete the entry"
            )
        references.append((entry, re.compile(reference_pattern(entry["needle"]))))
    retired_impls: list[tuple[dict, re.Pattern[str]]] = []
    for entry in inventory["retired_impls"]:
        trait, target = str(entry.get("trait", "")), str(entry.get("type", ""))
        if not PLAIN_IDENTIFIER.match(trait) or not PLAIN_IDENTIFIER.match(target):
            errors.append(
                f"{INVENTORY}: retired implementation `{trait} for {target}` names a plain "
                "trait and a plain type"
            )
            continue
        if not entry.get("retired"):
            errors.append(
                f"{INVENTORY}: retired implementation `{trait} for {target}` states what was "
                "retired"
            )
        retired_impls.append((entry, retired_impl_pattern(trait, target)))
    if errors:
        return errors
    needles = [identifier.encode() for identifier in identifiers]
    retired = re.compile(rb"(?<![A-Za-z0-9])(?:" + b"|".join(needles) + rb")")
    # Every word of a reference must occur before the file is lexed for it.
    prefilters = [
        [piece.encode() for piece in re.split(r"\s+|::", entry["needle"]) if piece]
        for entry, _ in references
    ]
    listed = {(entry["path"], entry["type"]): entry for entry in inventory["history_wire"]}
    test_only = {(entry["path"], entry["type"]) for entry in inventory["test_only_version_impls"]}
    seen: set[tuple[str, str]] = set()
    for relative in inventory["retired_identifier_roots"]:
        if not (root / relative).is_dir():
            errors.append(f"{relative}: scan root is missing")
    for path in rust_sources(root, inventory["retired_identifier_roots"]):
        relative = path.relative_to(root).as_posix()
        try:
            data = path.read_bytes()
        except OSError:
            errors.append(f"{relative}: unreadable source")
            continue
        if any(needle in data for needle in needles):
            for found in retired.finditer(data):
                line = data.count(b"\n", 0, found.start()) + 1
                errors.append(
                    f"{relative}:{line}: retired first-release identifier "
                    f"`{found.group().decode()}` reappeared"
                )
        has_version = b"Version" in data and VERSION_IMPL_BYTES.search(data)
        has_reference = any(all(piece in data for piece in pieces) for pieces in prefilters)
        has_retired_impl = b"impl" in data and any(
            entry["trait"].encode() in data and entry["type"].encode() in data
            for entry, _ in retired_impls
        )
        if not has_version and not has_reference and not has_retired_impl:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            errors.append(f"{relative}: unreadable source")
            continue
        if has_version:
            errors += version_impl_errors(relative, text, listed, test_only, seen)
        if has_reference:
            errors += test_only_reference_errors(relative, text, references)
        if has_retired_impl:
            errors += retired_impl_errors(relative, text, retired_impls)
    for key in sorted((set(listed) | test_only) - seen):
        errors.append(f"{key[0]}: listed `Version` implementation for {key[1]} does not exist")
    return errors


def function_attributes(blanked: str, fn_start: int) -> list[str]:
    """The attributes applied to the function whose `fn` keyword is at `fn_start`."""
    position = fn_start
    while True:
        head = blanked[:position].rstrip()
        qualifier = FUNCTION_QUALIFIER.search(head)
        if qualifier is None or qualifier.start() == qualifier.end():
            break
        position = qualifier.start()
    attributes: list[str] = []
    while True:
        head = blanked[:position].rstrip()
        if not head.endswith("]"):
            return attributes
        depth = 0
        opening = -1
        for index in range(len(head) - 1, -1, -1):
            if head[index] == "]":
                depth += 1
            elif head[index] == "[":
                depth -= 1
                if depth == 0:
                    opening = index
                    break
        if opening < 1 or head[opening - 1] != "#":
            return attributes
        attributes.append(head[opening - 1 :])
        position = opening - 1


def check_tests_exist(sources: Sources, entries: list[dict], kind: str) -> list[str]:
    """Each listed test function exists, is a test, always compiles and is not ignored."""
    errors: list[str] = []
    for entry in entries:
        relative, name = entry["path"], entry["test"]
        if not isinstance(entry.get("package"), str) or not TEST_TARGET.match(
            str(entry.get("target", ""))
        ):
            errors.append(
                f"{INVENTORY}: {kind} test `{name}` must name its `package` and its `target` "
                "(`lib` or `test:<name>`)"
            )
        source = sources.get(relative)
        if source is None:
            errors.append(f"{relative}: {kind} test source is missing")
            continue
        declared = None
        for found in re.finditer(r"\bfn\s+" + re.escape(name) + r"\s*\(", source.blanked):
            attributes = function_attributes(source.blanked, found.start())
            if any(IS_TEST_ATTRIBUTE.match(attribute) for attribute in attributes):
                declared = attributes
                break
        if declared is None:
            errors.append(f"{relative}: {kind} test `{name}` no longer exists")
            continue
        if any(IGNORE_ATTRIBUTE.match(attribute) for attribute in declared):
            errors.append(f"{relative}: {kind} test `{name}` is ignored")
        for attribute in declared:
            condition = CFG_ATTRIBUTE.match(attribute)
            if condition and condition.group("predicate").strip() != "test":
                errors.append(
                    f"{relative}: {kind} test `{name}` is conditionally compiled "
                    f"(`{' '.join(attribute.split())}`)"
                )
    return errors


def listed_tests(inventory: dict) -> list[dict]:
    """Every replay and rejection test of the inventory."""
    return inventory["replay_tests"] + inventory["obsolete_layout_rejection_tests"]


def check_blocked_targets(root: Path, inventory: dict) -> list[str]:
    """A blocked test target still fails to build for the listed reason."""
    errors: list[str] = []
    targets = {(entry.get("package"), entry.get("target")) for entry in listed_tests(inventory)}
    for entry in inventory["blocked_test_targets"]:
        key = (entry["package"], entry["target"])
        label = f"{key[0]} ({key[1]})"
        if key not in targets:
            errors.append(f"{INVENTORY}: blocked test target {label} has no listed test")
        if not entry["owner"].startswith("outside-zk-plan:"):
            tasks = plan_tasks(root)
            if tasks is not None and entry["owner"] not in tasks:
                errors.append(f"{INVENTORY}: blocked test target {label} names an unknown owner")
        if not entry["anchors"]:
            errors.append(f"{INVENTORY}: blocked test target {label} has no anchor")
        for anchor in entry["anchors"]:
            if check_anchor(root, anchor["path"], anchor["contains"]) is None:
                errors.append(
                    f"{anchor['path']}: blocked test target {label} no longer matches the "
                    "source; delete the entry, run its listed tests and record the result"
                )
    return errors


def test_commands(inventory: dict) -> list[str]:
    """One `cargo test` command per package and target that runs exactly the listed tests."""
    blocked = {
        (entry["package"], entry["target"]): entry["reason"]
        for entry in inventory["blocked_test_targets"]
    }
    prerequisites = {entry["package"]: entry for entry in inventory.get("test_prerequisites", [])}
    groups: dict[tuple[str, str], list[str]] = {}
    for entry in listed_tests(inventory):
        groups.setdefault((entry["package"], entry["target"]), []).append(entry["test"])
    lines: list[str] = []
    built: set[str] = set()
    for (package, target), names in sorted(groups.items()):
        selector = "--lib" if target == "lib" else f"--test {target.split(':', 1)[1]}"
        command = f"cargo test -p {package} {selector} -- {' '.join(sorted(set(names)))}"
        prerequisite = prerequisites.get(package)
        prefix = "# " if (package, target) in blocked else ""
        if (package, target) in blocked:
            lines.append(f"# blocked: {blocked[(package, target)]}")
        if prerequisite is not None:
            if package not in built:
                built.add(package)
                lines.append(f"{prefix}{prerequisite['build']}")
            assignments = " ".join(
                f'{name}="{value}"' for name, value in sorted(prerequisite["environment"].items())
            )
            command = f"{assignments} {command}"
        lines.append(f"{prefix}{command}")
    return lines


def check_test_prerequisites(root: Path, inventory: dict) -> list[str]:
    """Each prerequisite of a listed test names a real build, variable and source anchor."""
    errors: list[str] = []
    packages = {entry.get("package") for entry in listed_tests(inventory)}
    seen: set[str] = set()
    for entry in inventory["test_prerequisites"]:
        package = str(entry.get("package", ""))
        label = f"{INVENTORY}: test prerequisite of `{package}`"
        if package not in packages or package in seen:
            errors.append(f"{label} names one package with a listed test, once")
        seen.add(package)
        if not BUILD_COMMAND.match(str(entry.get("build", ""))):
            errors.append(f"{label} needs `build` as `cargo build -p <package> --bin <binary>`")
        environment = entry.get("environment")
        if not isinstance(environment, dict) or not environment:
            errors.append(f"{label} needs a non-empty `environment`")
            environment = {}
        for name, value in environment.items():
            if not ENVIRONMENT_NAME.match(str(name)) or not ENVIRONMENT_VALUE.match(str(value)):
                errors.append(f"{label} has an environment entry a shell cannot take as printed")
        if not entry.get("reason"):
            errors.append(f"{label} states its `reason`")
        anchors = entry.get("anchors") or []
        if not anchors:
            errors.append(f"{label} has no source anchor")
        for anchor in anchors:
            if check_anchor(root, anchor["path"], anchor["contains"]) is None:
                errors.append(
                    f"{anchor['path']}: test prerequisite anchor `{anchor['contains']}` is "
                    "missing; the way the listed tests find their daemon changed"
                )
    return errors


def check_pinned_history(root: Path, sources: Sources, inventory: dict) -> list[str]:
    """The pinned history fixture is intact and is the one the inventory records."""
    pinned = inventory["pinned_history"]
    relative = pinned["manifest"]
    try:
        manifest = json.loads((root / relative).read_text(encoding="utf-8"))
        blocks = manifest["blocks"]
        recorded = manifest["history_sha256"]
        form = manifest["format"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        return [f"{relative}: unreadable pinned history manifest: {error}"]
    errors: list[str] = []
    if form != pinned["format"]:
        errors.append(f"{relative}: pinned history format must be {pinned['format']}")
    if not isinstance(blocks, list) or len(blocks) < 2:
        return errors + [f"{relative}: a pinned history is a genesis and at least one block"]
    history = hashlib.sha256()
    directory = (root / relative).parent
    for index, block in enumerate(blocks):
        name = str(block.get("file", ""))
        where = f"{directory.relative_to(root).as_posix()}/{name}"
        if block.get("height") != index + 1 or "/" in name or not name:
            errors.append(f"{relative}: pinned block {index + 1} is out of order or misnamed")
            continue
        try:
            frame = (directory / name).read_bytes()
        except OSError:
            errors.append(f"{where}: pinned frame is missing")
            continue
        if hashlib.sha256(frame).hexdigest() != block.get("sha256") or len(frame) != block.get(
            "bytes"
        ):
            errors.append(f"{where}: pinned frame differs from the digest its manifest records")
        history.update(frame)
    if not errors and history.hexdigest() != recorded:
        errors.append(f"{relative}: `history_sha256` differs from the pinned frames")
    if recorded != pinned["history_sha256"]:
        errors.append(
            f"{relative}: pinned history {recorded} is not the one {INVENTORY} records "
            f"({pinned['history_sha256']}); a regenerated history is a declared cutover: "
            "record its digest in the inventory in the same change"
        )
    generator = pinned["generator"]
    source = sources.get(generator["path"])
    if source is None or not re.search(
        r"\bfn\s+" + re.escape(generator["test"]) + r"\s*\(", source.blanked
    ):
        errors.append(f"{generator['path']}: pinned history generator `{generator['test']}` is gone")
    replay = pinned["replay_test"]
    if not any(
        (entry["path"], entry["test"]) == (replay["path"], replay["test"])
        for entry in inventory["replay_tests"]
    ):
        errors.append(
            f"{INVENTORY}: pinned history replay test `{replay['test']}` is not a listed replay test"
        )
    return errors


def check_loader_definitions(root: Path, sources: Sources, inventory: dict) -> list[str]:
    """History loaders define and import no unlisted compatibility-named item.

    Rejection helpers and classified definitions are the only exceptions, and every
    `reject_retired_*`/`ensure_no_retired_*` function is a listed refusal or helper.
    """
    errors: list[str] = []
    helpers = {(entry["path"], entry["name"]) for entry in inventory["loader_rejection_helpers"]}
    classified = {
        (entry["path"], entry["name"]) for entry in inventory["loader_classified_definitions"]
    }
    refusals = {
        (entry["path"], entry["refusal"])
        for entry in inventory["retired_store_artifacts"]
        if entry.get("kind") == "function"
    }
    allowed = helpers | classified
    seen: set[tuple[str, str]] = set()
    for relative in inventory["loader_paths"]:
        if not rust_sources(root, [relative]):
            errors.append(f"{relative}: listed history loader path has no Rust source")
    for path in rust_sources(root, inventory["loader_paths"]):
        relative = path.relative_to(root).as_posix()
        if is_test_path(relative):
            continue
        source = sources.get(relative)
        if source is None:
            errors.append(f"{relative}: unreadable history loader source")
            continue
        blanked, spans = source.blanked, source.tests
        for found in COMPATIBILITY_DEFINITION.finditer(blanked):
            if in_spans(found.start(), spans):
                continue
            key = (relative, found.group("name"))
            seen.add(key)
            if key not in allowed:
                errors.append(
                    f"{relative}:{line_of(blanked, found.start())}: history loader defines "
                    f"`{key[1]}`; old layouts are refused, never decoded, migrated or aliased"
                )
        for statement in USE_STATEMENT.finditer(blanked):
            if in_spans(statement.start(), spans):
                continue
            for alias in USE_ALIAS.finditer(statement.group()):
                name = alias.group("name")
                if COMPATIBILITY_WORD.match(name) and (relative, name) not in allowed:
                    position = statement.start() + alias.start()
                    errors.append(
                        f"{relative}:{line_of(blanked, position)}: history loader imports an "
                        f"item as `{name}`; a replaced layout keeps no compatibility alias"
                    )
        for found in RETIRED_REFUSAL.finditer(blanked):
            if in_spans(found.start(), spans):
                continue
            key = (relative, found.group("name"))
            seen.add(key)
            if key not in helpers and key not in refusals:
                errors.append(
                    f"{relative}:{line_of(blanked, found.start())}: retired-artifact refusal "
                    f"`{key[1]}` is not listed under `retired_store_artifacts` or "
                    "`loader_rejection_helpers`"
                )
    for key in sorted(helpers - seen):
        errors.append(f"{key[0]}: listed rejection helper `{key[1]}` no longer exists")
    for key in sorted(classified - seen):
        errors.append(f"{key[0]}: classified definition `{key[1]}` no longer exists; delete it")
    return errors


def check_anchor(root: Path, relative: str, anchor: str) -> int | None:
    """One-based line of the first `anchor` occurrence in a file, or `None`."""
    text = read(root / relative)
    if text is None:
        return None
    position = text.find(anchor)
    return None if position < 0 else line_of(text, position)


def inline_retired_arrays(source: Source, start: int, end: int) -> list[tuple[list[str], str]]:
    """Each `for retired in [..] {..}` of a span: its name literals and its loop body."""
    arrays: list[tuple[list[str], str]] = []
    for found in INLINE_RETIRED_ARRAY.finditer(source.blanked, start, end):
        opening = found.end() - 1
        closing = matching_close(source.blanked, opening, BRACKET)
        body_end = item_end(source.blanked, closing)
        arrays.append((source.strings(opening, closing), source.text[closing:body_end]))
    return arrays


def refusal_function_errors(sources: Sources, entry: dict, source: Source) -> list[str]:
    """One named refusal function refuses exactly its listed names and is still called."""
    name, relative = entry["refusal"], entry["path"]
    span = source.function(name)
    if span is None:
        return [f"{relative}: retired-artifact refusal `{name}` no longer exists"]
    errors: list[str] = []
    body = source.blanked[span[0] : span[1]]
    found = source.strings(*span)
    listed = entry["literals"] + entry["messages"]
    for literal in sorted(set(listed) - set(found)):
        errors.append(
            f"{relative}: retired-artifact refusal `{name}` no longer names `{literal}`; the "
            "artifact is no longer refused by name"
        )
    for literal in sorted(set(found) - set(listed)):
        errors.append(
            f"{relative}: retired-artifact refusal `{name}` names `{literal}`, which "
            f"{INVENTORY} does not list"
        )
    if entry["error"] not in body and not any(entry["error"] in literal for literal in found):
        errors.append(
            f"{relative}: retired-artifact refusal `{name}` no longer fails with `{entry['error']}`"
        )
    for constant in entry["constants"]:
        owner = sources.get(constant["path"])
        defined = owner is not None and re.search(
            r"\bconst\s+"
            + re.escape(constant["name"])
            + r"\s*:\s*&\s*(?:'static\s+)?str\s*=\s*\""
            + re.escape(constant["value"])
            + r"\"\s*;",
            owner.text,
        )
        if not defined:
            errors.append(
                f"{constant['path']}: retired artifact name `{constant['value']}` is no longer "
                f"the constant `{constant['name']}`"
            )
        user = constant.get("via", name)
        user_span = source.function(user)
        if user_span is None or not re.search(
            r"\b" + re.escape(constant["name"]) + r"\b", source.blanked[user_span[0] : user_span[1]]
        ):
            errors.append(
                f"{relative}: `{user}` no longer uses `{constant['name']}`; "
                f"`{constant['value']}` is no longer refused by name"
            )
        if user != name and not re.search(r"\b" + re.escape(user) + r"\s*\(", body):
            errors.append(f"{relative}: retired-artifact refusal `{name}` no longer calls `{user}`")
    if not entry["called_from"]:
        errors.append(f"{INVENTORY}: retired-artifact refusal `{name}` lists no call site")
    for site in entry["called_from"]:
        caller = sources.get(site["path"])
        caller_span = None if caller is None else caller.function(site["function"])
        if caller_span is None or not re.search(
            r"\b(?:Self|Kura)\s*::\s*" + re.escape(name) + r"\s*\(",
            caller.blanked[caller_span[0] : caller_span[1]],
        ):
            errors.append(
                f"{site['path']}: `{site['function']}` no longer calls the retired-artifact "
                f"refusal `{name}`"
            )
    return errors


def check_retired_store_artifacts(root: Path, sources: Sources, inventory: dict) -> list[str]:
    """Retired store artifacts are refused by the listed functions and arrays, and by no other."""
    errors: list[str] = []
    inline_listed: dict[str, int] = {}
    for entry in inventory["retired_store_artifacts"]:
        name, relative = entry["refusal"], entry["path"]
        if entry["location"] not in ARTIFACT_LOCATIONS:
            errors.append(f"{INVENTORY}: retired-artifact refusal `{name}` has an unknown location")
        if not entry["artifacts"]:
            errors.append(f"{INVENTORY}: retired-artifact refusal `{name}` lists no artifact")
        for artifact in entry["artifacts"]:
            plant = str(artifact.get("plant", ""))
            if (
                not artifact.get("name")
                or not plant
                or plant.startswith("/")
                or ".." in plant.split("/")
                or artifact.get("kind") not in ARTIFACT_KINDS
            ):
                errors.append(
                    f"{INVENTORY}: retired artifact of `{name}` needs a `name`, a relative "
                    "`plant` path and a `kind` of file or directory"
                )
        source = sources.get(relative)
        if source is None:
            errors.append(f"{relative}: retired-artifact refusal source is missing")
            continue
        if entry["kind"] == "function":
            errors += refusal_function_errors(sources, entry, source)
            continue
        if entry["kind"] != "inline_array":
            errors.append(f"{INVENTORY}: retired-artifact refusal `{name}` has an unknown kind")
            continue
        inline_listed[relative] = inline_listed.get(relative, 0) + 1
        span = source.function(name)
        arrays = [] if span is None else inline_retired_arrays(source, *span)
        if entry["index"] >= len(arrays):
            errors.append(
                f"{relative}: `{name}` no longer holds retired-artifact array {entry['index']}"
            )
            continue
        names, loop = arrays[entry["index"]]
        if sorted(names) != sorted(entry["literals"]):
            errors.append(
                f"{relative}: retired-artifact array {entry['index']} of `{name}` refuses "
                f"{sorted(names)}, {INVENTORY} lists {sorted(entry['literals'])}"
            )
        if ARTIFACT_LOCATIONS.get(entry["location"], "\0") not in loop or entry["error"] not in loop:
            errors.append(
                f"{relative}: retired-artifact array {entry['index']} of `{name}` no longer "
                f"refuses under {entry['location']} with `{entry['error']}`"
            )
    for path in rust_sources(root, inventory["loader_paths"]):
        relative = path.relative_to(root).as_posix()
        source = None if is_test_path(relative) else sources.get(relative)
        if source is None:
            continue
        found = sum(
            1
            for array in INLINE_RETIRED_ARRAY.finditer(source.blanked)
            if not in_spans(array.start(), source.tests)
        )
        if found != inline_listed.get(relative, 0):
            errors.append(
                f"{relative}: {found} inline retired-artifact arrays, {INVENTORY} lists "
                f"{inline_listed.get(relative, 0)}"
            )
    return errors


def carrier_forms(target: dict) -> tuple[str, ...] | None:
    """The forms in which a regeneration target states that it carries the ABI hash.

    `()` when the target is no carrier; `None` when `carries` is neither one known form nor a
    non-empty list of distinct known forms.
    """
    stated = target.get("carries")
    if stated is None:
        return ()
    forms = [stated] if isinstance(stated, str) else stated
    if (
        not isinstance(forms, list)
        or not forms
        or any(not isinstance(form, str) or form not in ABI_HASH_FORMS for form in forms)
        or len(set(forms)) != len(forms)
    ):
        return None
    return tuple(forms)


def regeneration_errors(root: Path, surface: str, target: dict) -> list[str]:
    """One regeneration target names a concrete artifact and what produces or checks it.

    `mention` ties the `generator` to the artifact. A `checked_by` source is tied by
    `check_mention` when the entry states one (the name of the test that fails on a stale
    artifact) and by `mention` otherwise.
    """
    artifact = str(target.get("artifact", ""))
    path = root / artifact
    if not artifact or not path.exists():
        return [f"{artifact}: regeneration target of `{surface}` is missing"]
    if path.is_dir() and "/" not in artifact.strip("/"):
        return [
            f"{artifact}: regeneration target of `{surface}` is a whole top-level directory; "
            "name the pinned artifact"
        ]
    forms = carrier_forms(target)
    if forms is None:
        return [
            f"{artifact}: regeneration target of `{surface}` carries the ABI hash in the unknown "
            f"form `{target.get('carries')}`; use one of {', '.join(ABI_HASH_FORMS)}, or a list "
            "of distinct ones"
        ]
    occurrences = target.get("occurrences")
    if occurrences is not None and (
        type(occurrences) is not int
        or occurrences < 1
        or not any(form in ABI_TEXT_FORMS for form in forms)
    ):
        return [
            f"{artifact}: `occurrences` is the positive number of times a text carrier "
            f"({', '.join(ABI_TEXT_FORMS)}) holds the ABI hash"
        ]
    if target.get("document"):
        if forms:
            return [
                f"{artifact}: a carrier of the ABI hash names its `generator` or `checked_by` "
                "source, not `document`"
            ]
        if not path.is_file():
            return [f"{artifact}: document regeneration target of `{surface}` must be a file"]
        return []
    mention = target.get("mention")
    owners = [
        (target[key], tie)
        for key, tie in (
            ("generator", mention),
            ("checked_by", target.get("check_mention") or mention),
        )
        if target.get(key)
    ]
    if not owners or not mention:
        return [
            f"{artifact}: regeneration target of `{surface}` needs a `generator` or `checked_by` "
            "source and the `mention` that ties it to the artifact"
        ]
    if target.get("check_mention") and not target.get("checked_by"):
        return [f"{artifact}: `check_mention` names what its `checked_by` source mentions"]
    errors: list[str] = []
    for owner, tie in owners:
        text = read(root / owner)
        if text is None:
            errors.append(f"{owner}: generator or check of `{artifact}` is missing")
        elif tie not in text:
            errors.append(f"{owner}: no longer mentions `{tie}`; it does not cover `{artifact}`")
    return errors


def check_surfaces(root: Path, inventory: dict) -> list[str]:
    """Incompatible-change surfaces are concrete, and the contract table lists the same ones."""
    errors: list[str] = []
    listed: dict[str, str] = {}
    for entry in inventory["incompatible_change_surfaces"]:
        identifier = str(entry.get("id", ""))
        surface = entry["surface"]
        if not SURFACE_ID.match(identifier) or identifier in listed:
            errors.append(f"{INVENTORY}: surface `{surface}` needs a unique lower-case `id`")
        listed[identifier] = entry["cutover"]
        if entry["cutover"] not in CUTOVERS:
            errors.append(f"{INVENTORY}: surface `{surface}` has unknown cutover")
        if not entry["anchors"]:
            errors.append(f"{INVENTORY}: surface `{surface}` has no source anchor")
        for anchor in entry["anchors"]:
            if check_anchor(root, anchor["path"], anchor["contains"]) is None:
                errors.append(
                    f"{anchor['path']}: surface `{surface}` anchor `{anchor['contains']}` "
                    "is missing; update the inventory with the moved owner"
                )
        if not entry["regenerate"]:
            errors.append(f"{INVENTORY}: surface `{surface}` lists nothing to regenerate")
        for target in entry["regenerate"]:
            errors += regeneration_errors(root, surface, target)
    contract = read(root / inventory["contract"]) or ""
    table = {row.group("id"): row.group("cutover") for row in SURFACE_ROW.finditer(contract)}
    for identifier in sorted(set(listed) - set(table)):
        errors.append(
            f"{inventory['contract']}: surface `{identifier}` of {INVENTORY} is missing from the "
            "contract table"
        )
    for identifier in sorted(set(table) - set(listed)):
        errors.append(
            f"{inventory['contract']}: contract table surface `{identifier}` is not in {INVENTORY}"
        )
    for identifier in sorted(set(table) & set(listed)):
        if table[identifier] != listed[identifier]:
            errors.append(
                f"{inventory['contract']}: surface `{identifier}` cutover is "
                f"`{table[identifier]}` in the contract and `{listed[identifier]}` in {INVENTORY}"
            )
    return errors


def ivm_program_abi_hash(program: bytes) -> bytes | None:
    """The ABI hash field of an IVM program header, or `None` when the bytes are no IVM program."""
    start, end = IVM_ABI_HASH_SPAN
    if len(program) < end or not program.startswith(IVM_MAGIC):
        return None
    return program[start:end]


def abi_carrier_errors(root: Path, target: dict, declared: str) -> list[str]:
    """One regeneration target carries the declared ABI hash in every form its entry states.

    A text form holds the hash exactly `occurrences` times (once by default), so a file with
    several statements of the hash cannot keep a stale one beside a regenerated one. A program
    form reads the header of every program it finds: each row of a capture, each base64 image
    of a fixture, each file of an artifact map.
    """
    artifact = target["artifact"]
    raw = bytes.fromhex(declared)
    try:
        data = (root / artifact).read_bytes()
    except OSError:
        return [f"{artifact}: carrier of the ABI hash is unreadable"]
    owner = target.get("generator") or target.get("checked_by") or "its generator"
    stale = (
        f"does not carry the declared ABI hash {declared}; regenerate it through {owner} in the "
        "change that declares the cutover"
    )
    expected = target.get("occurrences", 1)
    errors: list[str] = []
    for form in carrier_forms(target) or ():
        if form == "artifact_map":
            programs = 0
            for line in data.decode("utf-8", errors="replace").splitlines():
                if not line or line.startswith("#"):
                    continue
                fields = line.split("\t")
                if len(fields) != 3 or not fields[2]:
                    errors.append(
                        f"{artifact}: artifact map row `{line}` is not owner, source, artifact"
                    )
                    continue
                programs += 1
                try:
                    program = (root / fields[2]).read_bytes()
                except OSError:
                    errors.append(f"{fields[2]}: IVM program listed in {artifact} is missing")
                    continue
                if ivm_program_abi_hash(program) != raw:
                    errors.append(f"{fields[2]}: IVM program header {stale}")
            if not programs:
                errors.append(f"{artifact}: artifact map lists no IVM program")
        elif form == "ivm_hex_rows":
            rows = 0
            for number, line in enumerate(
                data.decode("utf-8", errors="replace").splitlines(), start=1
            ):
                if not line:
                    continue
                rows += 1
                programs = [
                    field for field in line.split("\t") if field.startswith(IVM_MAGIC_HEX)
                ]
                if not programs:
                    errors.append(f"{artifact}:{number}: capture row holds no IVM program")
                elif not all(
                    HEX_TEXT.match(program)
                    and ivm_program_abi_hash(bytes.fromhex(program)) == raw
                    for program in programs
                ):
                    errors.append(f"{artifact}:{number}: IVM program header {stale}")
            if not rows:
                errors.append(f"{artifact}: capture holds no row")
        elif form == "ivm_base64":
            images = IVM_BASE64.findall(data)
            if not images:
                errors.append(f"{artifact}: holds no base64 IVM program")
            for image in images:
                try:
                    program = base64.b64decode(image, validate=True)
                except ValueError:
                    program = b""
                if ivm_program_abi_hash(program) != raw:
                    errors.append(f"{artifact}: base64 IVM program header {stale}")
        elif form == "ivm_header":
            if ivm_program_abi_hash(data) != raw:
                errors.append(f"{artifact}: {stale}")
        else:
            if form == "hex":
                found = data.count(declared.encode())
            elif form == "HEX":
                found = data.count(declared.upper().encode())
            else:
                found = HEX_WRAPPING.sub(b"", data).count(declared.encode())
            if not found:
                errors.append(f"{artifact}: {stale}")
            elif found != expected:
                errors.append(
                    f"{artifact}: holds the declared ABI hash {found} times as `{form}`, its "
                    f"entry states {expected}; state `occurrences` or regenerate it through "
                    f"{owner}"
                )
    return errors


def pinned_frames(root: Path, inventory: dict) -> list[bytes]:
    """The readable frames of the pinned history; its own check reports what is missing."""
    relative = inventory["pinned_history"].get("manifest", "")
    try:
        manifest = json.loads((root / relative).read_text(encoding="utf-8"))
        names = [str(block["file"]) for block in manifest["blocks"]]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        return []
    frames: list[bytes] = []
    for name in names:
        try:
            frames.append(((root / relative).parent / name).read_bytes())
        except OSError:
            continue
    return frames


def check_abi_cutover(root: Path, inventory: dict) -> list[str]:
    """The ABI V1 hash in the tree is the one the inventory declares a cutover for.

    Admission compares a contract manifest with the ABI hash compiled into the node, so a
    changed hash is a `contract_redeployment` cutover. The inventory records the hash; the
    golden, every regeneration target that states how it `carries` the hash, and the inventory
    must agree, so a regenerated hash cannot land without its declaration and its carriers.
    The pinned history must not hold the hash unless the declaration says the cutover also took
    a fresh genesis. The check reads bytes; it computes no ABI hash and admits no contract.
    """
    declaration = inventory["declared_abi_cutover"]
    declared = str(declaration.get("abi_hash", ""))
    golden = declaration.get("golden")
    errors: list[str] = []
    if not SHA256_HEX.match(declared):
        errors.append(f"{INVENTORY}: `declared_abi_cutover` records `abi_hash` as 64 hex digits")
    if not isinstance(golden, dict) or not golden.get("path") or not golden.get("prefix"):
        errors.append(f"{INVENTORY}: `declared_abi_cutover` names the `golden` path and prefix")
    if not declaration.get("change"):
        errors.append(f"{INVENTORY}: `declared_abi_cutover` states the `change` it declares")
    if not isinstance(declaration.get("fresh_genesis"), bool) or not declaration.get(
        "fresh_genesis_reason"
    ):
        errors.append(
            f"{INVENTORY}: `declared_abi_cutover` states `fresh_genesis` and its reason"
        )
    surfaces = {
        str(entry.get("id")): entry for entry in inventory["incompatible_change_surfaces"]
    }
    surface = surfaces.get(str(declaration.get("surface", "")))
    if surface is None:
        errors.append(f"{INVENTORY}: `declared_abi_cutover` names a listed surface")
    elif declaration.get("cutover") != surface["cutover"]:
        errors.append(
            f"{INVENTORY}: `declared_abi_cutover` declares `{declaration.get('cutover')}`, but "
            f"the cutover of surface `{surface['id']}` is `{surface['cutover']}`"
        )
    for identifier, entry in surfaces.items():
        if entry is surface:
            continue
        for target in entry["regenerate"]:
            if target.get("carries") is not None:
                errors.append(
                    f"{target.get('artifact')}: only targets of the declared surface carry the "
                    f"ABI hash, not those of `{identifier}`"
                )
    if errors:
        return errors
    carriers = [
        target
        for target in surface["regenerate"]
        if carrier_forms(target) and not target.get("document")
    ]
    if golden["path"] not in {target["artifact"] for target in carriers}:
        errors.append(
            f"{INVENTORY}: the ABI golden {golden['path']} must be a regeneration target of "
            f"`{surface['id']}` that `carries` the hash"
        )
    text = read(root / golden["path"])
    if text is None or text.count(golden["prefix"]) != 1:
        errors.append(
            f"{golden['path']}: the ABI golden must hold `{golden['prefix']}` exactly once"
        )
    else:
        start = text.index(golden["prefix"]) + len(golden["prefix"])
        found = text[start : start + 64]
        if not SHA256_HEX.match(found):
            errors.append(f"{golden['path']}: the ABI golden is not 64 hex digits")
        elif found != declared:
            errors.append(
                f"{golden['path']}: ABI golden {found} is not the hash {INVENTORY} declares "
                f"({declared}); a regenerated ABI hash is a declared cutover: record it in the "
                "inventory and regenerate every carrier in the same change"
            )
    for target in carriers:
        # The golden is compared exactly above; the others carry the hash in their stated form.
        if target["artifact"] != golden["path"]:
            errors += abi_carrier_errors(root, target, declared)
    raw = bytes.fromhex(declared)
    held = any(raw in frame for frame in pinned_frames(root, inventory))
    if held and not declaration["fresh_genesis"]:
        errors.append(
            f"{inventory['pinned_history'].get('manifest')}: the pinned history holds the declared "
            "ABI hash (a contract or runtime-ABI record), so this cutover also needs a fresh "
            "genesis: regenerate the history and declare `fresh_genesis`"
        )
    return errors


def check_evidence(root: Path, inventory: dict) -> list[str]:
    """The obsolete-history evidence tool, its test and the mechanisms it relies on exist."""
    evidence = inventory["obsolete_history_evidence"]
    errors: list[str] = []
    tool = read(root / evidence["tool"])
    if tool is None:
        errors.append(f"{evidence['tool']}: obsolete-history evidence tool is missing")
    elif evidence["manifest_schema"] not in tool:
        errors.append(
            f"{evidence['tool']}: no longer writes the `{evidence['manifest_schema']}` manifest"
        )
    if not (root / evidence["tool_test"]).is_file():
        errors.append(f"{evidence['tool_test']}: obsolete-history evidence test is missing")
    for anchor in evidence["anchors"]:
        if check_anchor(root, anchor["path"], anchor["contains"]) is None:
            errors.append(
                f"{anchor['path']}: obsolete-history evidence anchor `{anchor['contains']}` is "
                "missing; the contract's diagnostic path changed"
            )
    return errors


def contract_section(contract: str, heading: str) -> str | None:
    """Body of the one `## heading` section of the contract, or `None` when it is not unique."""
    lines = contract.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == f"## {heading}"]
    if len(starts) != 1:
        return None
    body: list[str] = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    return " ".join(" ".join(body).split())


def check_checkpoint_rule(root: Path, inventory: dict) -> list[str]:
    """The contract still states the future-checkpoint rule, and restore is still marked open.

    The section is pinned by the digest of its text with whitespace collapsed, so any
    edit of the rule is a change of the inventory too. This preserves a stated
    constraint on future work; it does not show that a checkpoint exists or verifies.
    """
    rule = inventory["future_checkpoint_rule"]
    contract_path = inventory["contract"]
    errors: list[str] = []
    heading = str(rule.get("section", ""))
    statements = rule.get("statements") or []
    anchors = rule.get("anchors") or []
    if not heading or not statements or not all(isinstance(text, str) and text for text in statements):
        errors.append(f"{INVENTORY}: `future_checkpoint_rule` names its section and statements")
    if not SHA256_HEX.match(str(rule.get("section_sha256", ""))):
        errors.append(f"{INVENTORY}: `future_checkpoint_rule` records `section_sha256`")
    if not rule.get("owner") or not rule.get("summary"):
        errors.append(f"{INVENTORY}: `future_checkpoint_rule` states its owner and summary")
    if not anchors:
        errors.append(f"{INVENTORY}: `future_checkpoint_rule` has no source anchor")
    if errors:
        return errors
    section = contract_section(read(root / contract_path) or "", heading)
    if section is None:
        return [
            f"{contract_path}: the contract must have exactly one `## {heading}` section; it "
            "states the rule for a future authenticated checkpoint"
        ]
    for statement in statements:
        if " ".join(statement.split()) not in section:
            errors.append(
                f"{contract_path}: section `{heading}` no longer states `{statement}`; a future "
                "checkpoint must still specify its verified suffix and validate nothing below it"
            )
    if hashlib.sha256(section.encode("utf-8")).hexdigest() != rule["section_sha256"]:
        errors.append(
            f"{contract_path}: section `{heading}` differs from the text {INVENTORY} pins; "
            "review the future-checkpoint rule and record the new `section_sha256`"
        )
    for anchor in anchors:
        if check_anchor(root, anchor["path"], anchor["contains"]) is None:
            errors.append(
                f"{anchor['path']}: future-checkpoint anchor `{anchor['contains']}` is missing; "
                "if restore from a checkpoint now exists, it must implement the rule of "
                f"`{heading}` and the inventory must say where"
            )
    return errors


def open_findings(root: Path, inventory: dict) -> tuple[list[str], list[str]]:
    """Return `(report lines, errors)` for findings owned by other tasks."""
    report: list[str] = []
    errors: list[str] = []
    identifiers: set[str] = set()
    tasks = plan_tasks(root)
    for entry in inventory["open_findings"]:
        identifier, owner = entry["id"], entry["owner"]
        if identifier in identifiers:
            errors.append(f"{INVENTORY}: duplicate open finding {identifier}")
        identifiers.add(identifier)
        if not owner.startswith("outside-zk-plan:") and tasks is not None and owner not in tasks:
            errors.append(f"{INVENTORY}: open finding {identifier} names unknown task {owner}")
        line = check_anchor(root, entry["path"], entry["anchor"])
        if line is None:
            errors.append(
                f"{entry['path']}: open finding {identifier} no longer matches the source; "
                "delete it, or list what was removed under `retired_identifiers`"
            )
            continue
        report.append(f"{entry['path']}:{line}: {identifier} [{owner}] {entry['summary']}")
    return report, errors


def plan_tasks(root: Path) -> set[str] | None:
    """Task identifiers of the delivery graph, or `None` when the graph is unavailable."""
    try:
        graph = json.loads((root / "specs/zk_delivery_graph.json").read_text(encoding="utf-8"))
        return {task["id"] for task in graph["tasks"]}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        return None


def check(root: Path) -> tuple[str, ...]:
    """Check the inventory against `root` and return every violation."""
    inventory, errors = load_inventory(root)
    if not inventory:
        return tuple(errors)
    sources = Sources(root)
    errors += check_sources(root, inventory)
    errors += check_tests_exist(sources, inventory["replay_tests"], "replay")
    errors += check_tests_exist(
        sources, inventory["obsolete_layout_rejection_tests"], "obsolete-layout rejection"
    )
    errors += check_blocked_targets(root, inventory)
    errors += check_pinned_history(root, sources, inventory)
    errors += check_loader_definitions(root, sources, inventory)
    errors += check_retired_store_artifacts(root, sources, inventory)
    errors += check_surfaces(root, inventory)
    errors += check_abi_cutover(root, inventory)
    errors += check_evidence(root, inventory)
    errors += check_checkpoint_rule(root, inventory)
    errors += check_test_prerequisites(root, inventory)
    errors += open_findings(root, inventory)[1]
    return tuple(sorted(set(errors)))


def main() -> int:
    """Check the requested tree; optionally print the open findings or the test commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", action="store_true", help="print open findings as path:line")
    parser.add_argument(
        "--test-commands",
        action="store_true",
        help="print the cargo commands that run exactly the listed tests",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    errors = check(root)
    if args.report or args.test_commands:
        inventory, _ = load_inventory(root)
        if inventory and args.report:
            print("\n".join(open_findings(root, inventory)[0]))
        if inventory and args.test_commands:
            print("\n".join(test_commands(inventory)))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if not args.test_commands:
        print("first-release history and cutover inventory matches the source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
