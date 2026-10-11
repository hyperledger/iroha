#!/usr/bin/env python3
"""Check the current sealed Kotodama compiler test-source inventory.

Requires Python 3.10+ and a repository checkout; no Rust build or environment
variables are needed. The default is read-only. Use --write only after an
intentional fixture or test change to regenerate the reviewable V1 manifest.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import sys
from typing import Any, Iterable

FORMAT = "iroha.kotodama.test-sources"
SCHEMA_VERSION = 1
DEFAULT_MANIFEST = Path("crates/kotodama_lang/kotodama_fixtures_v1.manifest.json")
EXPECTED_SOURCES = (
    "crates/kotodama_lang/src/compiler.rs",
    "crates/kotodama_lang/src/semantic.rs",
    "crates/kotodama_lang/src/ir.rs",
)
OUT_OF_LINE_TEST_SOURCES = {
    "crates/kotodama_lang/src/compiler.rs": "crates/kotodama_lang/src/compiler/tests.rs",
}
# These exact Rust child modules are part of the compiler's one test owner.
EXPECTED_TEST_MODULES = {
    "crates/kotodama_lang/src/compiler.rs": (
        ("dead_operands", "crates/kotodama_lang/src/compiler/tests/dead_operands.rs"),
        ("literal_helpers", "crates/kotodama_lang/src/compiler/tests/literal_helpers.rs"),
        ("numeric_operands", "crates/kotodama_lang/src/compiler/tests/numeric_operands.rs"),
        ("rematerialized", "crates/kotodama_lang/src/compiler/tests/rematerialized.rs"),
        ("state_operands", "crates/kotodama_lang/src/compiler/tests/state_operands.rs"),
    ),
}
# The canonical pool fixture has independent folding, liveness, rematerialization,
# and borrowed numeric/state operand controls.
# No other fixture or consumer is permitted to share an include.
SHARED_EXTERNAL_FIXTURE_OWNERS = {
    "crates/iroha_core/src/validation_fee/fixtures/dlmm_pool.ko": frozenset({
        ("crates/kotodama_lang/src/compiler.rs", "canonical_dlmm_dead_operands_measure_actual_frame_and_byte_savings", True),
        ("crates/kotodama_lang/src/compiler.rs", "canonical_dlmm_literal_folding_measures_same_compiler_artifacts_and_public_metadata", True),
        ("crates/kotodama_lang/src/compiler.rs", "canonical_dlmm_borrowed_numeric_operands_measure_material_byte_reduction", True),
        ("crates/kotodama_lang/src/compiler.rs", "canonical_dlmm_borrowed_state_operands_measure_material_byte_reduction", True),
        ("crates/kotodama_lang/src/compiler.rs", "canonical_dlmm_rematerialization_measures_same_compiler_artifacts_and_metadata", True),
    }),
}
EXPECTED_TEST_INCLUDES = {
    "crates/kotodama_lang/src/compiler.rs": (
        "compiler/tests/staged_mint_access_hints.rs",
    ),
    "crates/kotodama_lang/src/semantic.rs": (
        "semantic/tests/numeric_rounding_modes.rs",
        "semantic/tests/trigger_semantics_tests.rs",
        "semantic_sum_tests.rs",
        "semantic/tests/call_labels_and_patterns.rs",
        "semantic/tests/call_identity.rs",
    ),
    "crates/kotodama_lang/src/ir.rs": (
        "ir/tests/public_argument_record_abi.rs",
        "ir_tail_tests.rs",
    ),
}
TEST_BATCH_MACROS = {
    "crates/kotodama_lang/src/semantic.rs": (
        "analyze_ok_tests",
        "analyze_test_ok_tests",
        "analyze_reject_code_tests",
        "analyze_reject_contains_tests",
        "analyze_test_reject_contains_tests",
        "analyze_reject_contains_diagnostic_tests",
        "analyze_error_code_message_tests",
        "analyze_error_code_cases",
    ),
}
TEST_SINGLE_CASE_MACROS = {
    "crates/kotodama_lang/src/ir.rs": ("alias_lowering_case",),
}
EXPECTED_FIXTURE_DIRECTORIES = {
    "crates/kotodama_lang/src/compiler.rs": (
        "crates/kotodama_lang/src/compiler/fixtures/v1",
    ),
    "crates/kotodama_lang/src/semantic.rs": (
        "crates/kotodama_lang/src/semantic/fixtures/v1",
        "crates/kotodama_lang/src/semantic/test_sources",
    ),
    "crates/kotodama_lang/src/ir.rs": (
        "crates/kotodama_lang/src/ir/fixtures/v1",
        "crates/kotodama_lang/src/ir/test_sources",
    ),
}
EXPECTED_EXTERNAL_FIXTURES = {
    "crates/kotodama_lang/src/compiler.rs": (
        "crates/ivm/docs/examples/02_view_public_fn.ko",
        "crates/ivm/docs/examples/04_foreach_map.ko",
        "crates/ivm/docs/examples/05_range_for.ko",
        "crates/ivm/docs/examples/14_map_sum_take2.ko",
        "crates/ivm/docs/examples/15_modulo.ko",
        "crates/ivm/docs/examples/18_ternary.ko",
        "crates/kotodama_lang/src/samples/tuple_return_demo.ko",
        "crates/kotodama_lang/src/samples/mint_rose_trigger.ko",
        "crates/kotodama_lang/src/samples/zk_vote_ballot.ko",
        "crates/kotodama_lang/fixtures/koto_v1/staged_mint_access_hints/001.ko",
        "crates/iroha_core/src/validation_fee/fixtures/dlmm_pool.ko",
    ),
}
ROOT_KEYS = frozenset(
    {
        "format",
        "schema_version",
        "fixtures_sha256",
        "test_inventory_sha256",
        "source_files",
        "fixtures",
    }
)
SOURCE_KEYS = frozenset(
    {
        "path",
        "fixture_directories",
        "external_fixtures",
        "test_includes",
        "test_modules",
        "test_names",
        "test_names_sha256",
    }
)
FIXTURE_KEYS = frozenset(
    {
        "ordinal",
        "owner_source",
        "owner_function",
        "owner_is_test",
        "asset",
        "include_path",
        "byte_len",
        "newline_count",
        "starts_with_lf",
        "ends_with_lf",
        "content_sha256",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RAW_STRING_RE = re.compile(r'(?<![A-Za-z0-9_])r(?P<hashes>#{0,255})"')
INCLUDE_STR_RE = re.compile(r'include_str!\(\s*"(?P<path>[^"]+)"\s*\)')
FUNCTION_RE = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?"
    r"(?:async[ \t]+)?(?:unsafe[ \t]+)?fn[ \t]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^;{]*\{"
)
TEST_FUNCTION_RE = re.compile(
    r"(?m)^[ \t]*#\[test\][ \t]*\n"
    r"(?:[ \t]*#\[[^\n]+\][ \t]*\n)*"
    r"[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?fn[ \t]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
TEST_INCLUDE_RE = re.compile(r'(?m)^[ \t]*include!\(\s*"(?P<path>[^"\n]+)"\s*\);')


class ValidationError(ValueError):
    """Raised when the fixture inventory is incomplete or inconsistent."""


@dataclass(frozen=True)
class FunctionSpan:
    """One Rust function in a masked source file."""

    name: str
    start: int
    end: int
    is_test: bool


@dataclass(frozen=True)
class ValidationStats:
    """Summary returned after a successful validation."""

    fixtures: int
    tests: int


def _fail(message: str) -> None:
    raise ValidationError(message)


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    actual = frozenset(value)
    if actual != expected:
        _fail(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer >= {minimum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _sha256(value: Any, label: str) -> str:
    digest = _string(value, label)
    if SHA256_RE.fullmatch(digest) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _relative_path(value: Any, label: str) -> str:
    raw = _string(value, label)
    if "\\" in raw:
        _fail(f"{label} must use POSIX separators")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != raw:
        _fail(f"{label} must be a canonical repository-relative path")
    return raw


def _resolved_include_path(source_path: str, value: Any, label: str) -> str:
    """Resolve one canonical Rust include path without escaping the repository."""

    raw = _string(value, label)
    if "\\" in raw:
        _fail(f"{label} must use POSIX separators")
    include = PurePosixPath(raw)
    if include.is_absolute() or include.as_posix() != raw:
        _fail(f"{label} must be a canonical source-relative path")
    components = list(PurePosixPath(source_path).parent.parts)
    for component in include.parts:
        if component == "..":
            if not components:
                _fail(f"{label} escapes the repository")
            components.pop()
        else:
            components.append(component)
    if not components:
        _fail(f"{label} does not name a repository file")
    return PurePosixPath(*components).as_posix()


def _digest_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mask_rust(source: str) -> str:
    """Blank comments and literals while preserving byte offsets and newlines."""

    masked = list(source)

    def blank(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] != "\n":
                masked[index] = " "

    cursor = 0
    while cursor < len(source):
        if source.startswith("//", cursor):
            end = source.find("\n", cursor + 2)
            end = len(source) if end < 0 else end
            blank(cursor, end)
            cursor = end
            continue
        if source.startswith("/*", cursor):
            start = cursor
            depth = 1
            cursor += 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                _fail("unterminated Rust block comment")
            blank(start, cursor)
            continue
        raw = RAW_STRING_RE.match(source, cursor)
        if raw is not None:
            marker = '"' + raw.group("hashes")
            end = source.find(marker, raw.end())
            if end < 0:
                _fail("unterminated Rust raw string")
            end += len(marker)
            blank(cursor, end)
            cursor = end
            continue
        quote = cursor + 1 if source.startswith('b"', cursor) else cursor
        if quote < len(source) and source[quote] == '"':
            start = cursor
            cursor = quote + 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                elif source[cursor] == '"':
                    cursor += 1
                    break
                else:
                    cursor += 1
            else:
                _fail("unterminated Rust string")
            blank(start, cursor)
            continue
        if source[cursor] == "'" and cursor + 2 < len(source):
            end = cursor + (3 if source[cursor + 1] == "\\" else 2)
            if end < len(source) and source[end] == "'":
                blank(cursor, end + 1)
                cursor = end + 1
                continue
        cursor += 1
    return "".join(masked)


def _function_spans(source: str) -> list[FunctionSpan]:
    masked = _mask_rust(source)
    test_starts = {
        match.start("name"): match.group("name")
        for match in TEST_FUNCTION_RE.finditer(masked)
    }
    spans: list[FunctionSpan] = []
    for match in FUNCTION_RE.finditer(masked):
        brace = masked.find("{", match.start(), match.end())
        depth = 0
        cursor = brace
        while cursor < len(masked):
            if masked[cursor] == "{":
                depth += 1
            elif masked[cursor] == "}":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        if depth:
            _fail(f"unterminated Rust function `{match.group('name')}`")
        name_start = match.start("name")
        spans.append(
            FunctionSpan(
                name=match.group("name"),
                start=match.start(),
                end=cursor + 1,
                is_test=name_start in test_starts,
            )
        )
    return spans


def _owner(spans: Iterable[FunctionSpan], position: int) -> FunctionSpan:
    owners = [span for span in spans if span.start <= position < span.end]
    if not owners:
        _fail(f"no Rust function owns source byte {position}")
    return min(owners, key=lambda span: span.end - span.start)


def _regular_bytes(path: Path, label: str) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} is not a regular file")
    return path.read_bytes()


def _closing_brace(masked: str, opening: int, label: str) -> int:
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor
    _fail(f"unterminated Rust macro invocation: {label}")


def _macro_test_events(source_path: str, masked: str) -> list[tuple[int, list[str]]]:
    events: list[tuple[int, list[str]]] = []
    for macro_name in TEST_BATCH_MACROS.get(source_path, ()):
        pattern = re.compile(rf"\b{re.escape(macro_name)}!\s*\{{")
        for invocation in pattern.finditer(masked):
            opening = masked.find("{", invocation.start(), invocation.end())
            closing = _closing_brace(masked, opening, macro_name)
            body = masked[opening + 1 : closing]
            names = [
                match.group(1)
                for match in re.finditer(
                    r"(?:\A|;)\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", body
                )
            ]
            if not names:
                _fail(f"Rust test macro invocation has no cases: {macro_name}")
            events.append((invocation.start(), names))
    for macro_name in TEST_SINGLE_CASE_MACROS.get(source_path, ()):
        pattern = re.compile(
            rf"\b{re.escape(macro_name)}!\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
        )
        events.extend(
            (invocation.start(), [invocation.group(1)])
            for invocation in pattern.finditer(masked)
        )
    return events


def _expanded_test_names(root: Path, source_path: str, source: str) -> list[str]:
    """Return tests in Rust lexical order, expanding the sealed child modules."""

    masked = _mask_rust(source)
    events: list[tuple[int, list[str]]] = [
        (match.start(), [match.group("name")])
        for match in TEST_FUNCTION_RE.finditer(masked)
    ]
    events.extend(_macro_test_events(source_path, masked))
    includes: list[tuple[re.Match[str], str]] = []
    for match in TEST_INCLUDE_RE.finditer(source):
        include_start = source.find("include!", match.start(), match.end())
        if masked[include_start : include_start + len("include!")] == "include!":
            includes.append((match, match.group("path")))
    observed_includes = tuple(path for _, path in includes)
    expected_includes = EXPECTED_TEST_INCLUDES.get(source_path, ())
    if observed_includes != expected_includes:
        _fail(
            f"Rust test include inventory changed in {source_path}: "
            f"expected={list(expected_includes)}, observed={list(observed_includes)}"
        )

    source_parent = PurePosixPath(source_path).parent
    for match, include_path in includes:
        relative = _relative_path(include_path, f"{source_path} test include")
        child_source_path = (source_parent / PurePosixPath(relative)).as_posix()
        child_path = root / child_source_path
        try:
            child_source = _regular_bytes(child_path, child_source_path).decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise ValidationError(
                f"failed to read Rust test include {child_source_path}: {error}"
            ) from error
        child_masked = _mask_rust(child_source)
        child_events: list[tuple[int, list[str]]] = [
            (child_match.start(), [child_match.group("name")])
            for child_match in TEST_FUNCTION_RE.finditer(child_masked)
        ]
        child_events.extend(_macro_test_events(source_path, child_masked))
        child_names = [
            name for _, event_names in sorted(child_events) for name in event_names
        ]
        if not child_names:
            _fail(f"Rust test include has no tests: {child_source_path}")
        nested_includes = [
            child_match.group("path")
            for child_match in TEST_INCLUDE_RE.finditer(child_source)
            if child_masked[
                child_source.find("include!", child_match.start(), child_match.end()) :
            ].startswith("include!")
        ]
        if nested_includes:
            _fail(
                f"Rust test include nesting is not sealed in {child_source_path}: "
                f"{nested_includes}"
            )
        events.append((match.start(), child_names))

    names = [name for _, event_names in sorted(events) for name in event_names]
    if len(names) != len(set(names)):
        _fail(f"Rust test name inventory contains duplicates in {source_path}")
    return names


def _macro_case_spans(source_path: str, source: str) -> list[FunctionSpan]:
    """Locate fixture ownership inside the explicitly registered Rust test macros."""

    masked = _mask_rust(source)
    spans: list[FunctionSpan] = []
    for macro_name in TEST_BATCH_MACROS.get(source_path, ()):
        pattern = re.compile(rf"\b{re.escape(macro_name)}!\s*\{{")
        for invocation in pattern.finditer(masked):
            opening = masked.find("{", invocation.start(), invocation.end())
            closing = _closing_brace(masked, opening, macro_name)
            cases = list(
                re.finditer(
                    r"(?:\A|;)\s*([A-Za-z_][A-Za-z0-9_]*)\s*:",
                    masked[opening + 1 : closing],
                )
            )
            for index, case in enumerate(cases):
                end = (
                    opening + 1 + cases[index + 1].start()
                    if index + 1 < len(cases)
                    else closing
                )
                spans.append(
                    FunctionSpan(
                        case.group(1),
                        opening + 1 + case.start(),
                        end,
                        True,
                    )
                )
    for macro_name in TEST_SINGLE_CASE_MACROS.get(source_path, ()):
        pattern = re.compile(
            rf"\b{re.escape(macro_name)}!\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
        )
        for invocation in pattern.finditer(masked):
            opening = masked.find("(", invocation.start(), invocation.end())
            depth = 0
            for closing in range(opening, len(masked)):
                depth += (masked[closing] == "(") - (masked[closing] == ")")
                if depth == 0:
                    spans.append(
                        FunctionSpan(invocation.group(1), opening, closing + 1, True)
                    )
                    break
            else:
                _fail(f"unterminated Rust test macro invocation: {macro_name}")
    return spans


def _logical_source(root: Path, source_path: str) -> str:
    """Read a sealed source owner together with its out-of-line test module.

    The manifest keys fixture ownership by the production source. Includes in
    its test module are rebased to that logical owner while retaining the same
    physical targets; the test module is mandatory, rather than a fallback.
    """

    source = _regular_bytes(root / source_path, source_path).decode("utf-8")
    test_path = OUT_OF_LINE_TEST_SOURCES.get(source_path)
    if test_path is None:
        return source
    relative = posixpath.relpath(test_path, str(PurePosixPath(source_path).parent))
    declaration = f'#[cfg(test)]\n#[path = "{relative}"]\nmod tests;'
    if source.count(declaration) != 1:
        _fail(f"out-of-line test declaration changed in {source_path}")
    test_source = _regular_bytes(root / test_path, test_path).decode("utf-8")
    modules = EXPECTED_TEST_MODULES.get(source_path, ())
    masked = _mask_rust(test_source)
    observed_modules = re.findall(r"\bmod\s+(?:r#)?([^\W\d]\w*)\s*;", masked)
    if observed_modules != [name for name, _ in modules]:
        _fail(f"Rust test module inventory changed in {test_path}: {observed_modules}")
    for name, child_path in modules:
        relative_child = posixpath.relpath(child_path, str(PurePosixPath(test_path).parent))
        child_declaration = f'#[path = "{relative_child}"]\nmod {name};'
        if test_source.count(child_declaration) != 1:
            _fail(f"Rust test module declaration changed in {test_path}: {name}")
        child_source = _regular_bytes(root / child_path, child_path).decode("utf-8")
        child_masked = _mask_rust(child_source)
        if re.search(r"\bmod\s+(?:r#)?([^\W\d]\w*)\s*;", child_masked):
            _fail(f"Rust test module nesting is not sealed in {child_path}")
        child_edits = []
        for match in re.finditer(
            r'\b(?P<macro>include|include_str|include_bytes)!\(\s*"(?P<path>[^"\n]+)"\s*\)',
            child_source,
        ):
            if not child_masked[match.start():].startswith(match.group("macro") + "!"):
                continue
            target = _resolved_include_path(child_path, match.group("path"), "test module include")
            rebased = posixpath.relpath(target, str(PurePosixPath(test_path).parent))
            child_edits.append((match.start("path"), match.end("path"), rebased))
        for start, end, rebased in reversed(child_edits):
            child_source = child_source[:start] + rebased + child_source[end:]
        test_source = test_source.replace(child_declaration, f"mod {name} {{\n{child_source}\n}}")
    masked = _mask_rust(test_source)
    includes = re.compile(
        r'\b(?P<macro>include|include_str|include_bytes)!\(\s*"(?P<path>[^"\n]+)"\s*\)'
    )
    edits: list[tuple[int, int, str]] = []
    for match in includes.finditer(test_source):
        if not masked[match.start() :].startswith(match.group("macro") + "!"):
            continue
        target = _resolved_include_path(test_path, match.group("path"), "test include")
        rebased = posixpath.relpath(target, str(PurePosixPath(source_path).parent))
        edits.append((match.start("path"), match.end("path"), rebased))
    for start, end, rebased in reversed(edits):
        test_source = test_source[:start] + rebased + test_source[end:]
    return source.replace(declaration, "mod tests {\n" + test_source + "\n}")


def _capture_manifest(root: Path) -> dict[str, Any]:
    """Capture current consumers; reject unowned, duplicate, or missing assets."""

    sources: list[dict[str, Any]] = []
    fixtures: list[dict[str, Any]] = []
    seen_assets: set[str] = set()
    shared_consumers: dict[str, set[tuple[str, str, bool]]] = {}
    for source_path in EXPECTED_SOURCES:
        source = _logical_source(root, source_path)
        names = _expanded_test_names(root, source_path, source)
        directories = EXPECTED_FIXTURE_DIRECTORIES[source_path]
        external = EXPECTED_EXTERNAL_FIXTURES.get(source_path, ())
        sources.append(
            {
                "path": source_path,
                "fixture_directories": list(directories),
                "external_fixtures": list(external),
                "test_includes": list(EXPECTED_TEST_INCLUDES[source_path]),
                "test_modules": [list(module) for module in EXPECTED_TEST_MODULES.get(source_path, ())],
                "test_names": names,
                "test_names_sha256": hashlib.sha256(
                    ("\n".join(names) + "\n").encode("utf-8")
                ).hexdigest(),
            }
        )
        consumers = [(source_path, source)]
        for include_path in EXPECTED_TEST_INCLUDES[source_path]:
            child_path = _resolved_include_path(
                source_path, include_path, "Rust test include"
            )
            consumers.append(
                (
                    child_path,
                    _regular_bytes(root / child_path, child_path).decode("utf-8"),
                )
            )
        root_assets: set[str] = set()
        for owner_source, text in consumers:
            masked = _mask_rust(text)
            spans = _function_spans(text) + _macro_case_spans(source_path, text)
            ordinal = 0
            for match in INCLUDE_STR_RE.finditer(text):
                if not masked[match.start() :].startswith("include_str!"):
                    continue
                include_path = match.group("path")
                if not include_path.endswith(".ko"):
                    continue
                asset = _resolved_include_path(
                    owner_source, include_path, "fixture include"
                )
                if (
                    PurePosixPath(asset).parent.as_posix() not in directories
                    and asset not in external
                ):
                    _fail(
                        f"fixture include is outside the owned fixture inventory: {asset}"
                    )
                owner = _owner(spans, match.start())
                consumer = (owner_source, owner.name, owner.is_test)
                shared = SHARED_EXTERNAL_FIXTURE_OWNERS.get(asset)
                if shared is not None:
                    observed = shared_consumers.setdefault(asset, set())
                    if consumer not in shared or consumer in observed:
                        _fail(f"shared fixture consumer changed: {asset} {consumer}")
                    observed.add(consumer)
                elif asset in seen_assets:
                    _fail(f"duplicate fixture include: {asset}")
                seen_assets.add(asset)
                root_assets.add(asset)
                try:
                    data = _regular_bytes(root / asset, asset)
                except FileNotFoundError:
                    _fail(f"fixture is missing: {asset}")
                if not data:
                    _fail(f"fixture is empty: {asset}")
                data.decode("utf-8")
                ordinal += 1
                fixtures.append(
                    {
                        "ordinal": ordinal,
                        "owner_source": owner_source,
                        "owner_function": owner.name,
                        "owner_is_test": owner.is_test,
                        "asset": asset,
                        "include_path": include_path,
                        "byte_len": len(data),
                        "newline_count": data.count(b"\n"),
                        "starts_with_lf": data.startswith(b"\n"),
                        "ends_with_lf": data.endswith(b"\n"),
                        "content_sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
        for directory in directories:
            observed = {
                path.relative_to(root).as_posix()
                for path in (root / directory).glob("*.ko")
            }
            referenced = {
                asset
                for asset in root_assets
                if PurePosixPath(asset).parent.as_posix() == directory
            }
            if observed != referenced:
                _fail(
                    f"fixture directory membership changed under {directory}: unreferenced={sorted(observed - referenced)}, missing={sorted(referenced - observed)}"
                )
        if set(external) - root_assets:
            _fail(f"external fixture include inventory changed in {source_path}")
    if shared_consumers != SHARED_EXTERNAL_FIXTURE_OWNERS:
        _fail("shared external fixture consumer inventory changed")
    return {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "fixtures_sha256": _digest_json(fixtures),
        "test_inventory_sha256": _digest_json(sources),
        "source_files": sources,
        "fixtures": fixtures,
    }


def validate_manifest(root: Path, manifest_path: Path) -> ValidationStats:
    """Validate exact current tests, source ownership, include paths, and bytes."""

    root = root.resolve()
    try:
        payload: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"failed to read manifest: {error}") from error
    payload = _exact_keys(payload, ROOT_KEYS, "manifest")
    if (
        payload["format"] != FORMAT
        or _integer(payload["schema_version"], "schema_version", minimum=1)
        != SCHEMA_VERSION
    ):
        _fail(f"manifest must use {FORMAT!r} schema_version {SCHEMA_VERSION}")
    sources = payload["source_files"]
    fixtures = payload["fixtures"]
    if not isinstance(sources, list) or not isinstance(fixtures, list) or not fixtures:
        _fail("manifest source_files and fixtures must be non-empty arrays")
    for index, source in enumerate(sources):
        _exact_keys(source, SOURCE_KEYS, f"source_files[{index}]")
    for index, fixture in enumerate(fixtures):
        _exact_keys(fixture, FIXTURE_KEYS, f"fixtures[{index}]")
        _integer(fixture["ordinal"], "fixture.ordinal", minimum=1)
        _relative_path(fixture["asset"], "fixture.asset")
        _relative_path(fixture["owner_source"], "fixture.owner_source")
        _string(fixture["owner_function"], "fixture.owner_function")
        _boolean(fixture["owner_is_test"], "fixture.owner_is_test")
        _integer(fixture["byte_len"], "fixture.byte_len", minimum=1)
        _integer(fixture["newline_count"], "fixture.newline_count")
        _boolean(fixture["starts_with_lf"], "fixture.starts_with_lf")
        _boolean(fixture["ends_with_lf"], "fixture.ends_with_lf")
        _sha256(fixture["content_sha256"], "fixture.content_sha256")
    if _sha256(payload["fixtures_sha256"], "fixtures_sha256") != _digest_json(fixtures):
        _fail("fixtures_sha256 does not authenticate the ordered fixture inventory")
    if _sha256(
        payload["test_inventory_sha256"], "test_inventory_sha256"
    ) != _digest_json(sources):
        _fail("test_inventory_sha256 does not authenticate the test inventory")
    observed = _capture_manifest(root)
    if len(sources) != len(observed["source_files"]):
        _fail("source inventory differs from the owned sources")
    for expected, actual in zip(sources, observed["source_files"]):
        if expected["test_names"] != actual["test_names"]:
            _fail(f"Rust test name/order inventory changed in {actual['path']}")
        if expected != actual:
            _fail(
                f"Rust source/include policy or test inventory hash changed in {actual['path']}"
            )
    if len(fixtures) != len(observed["fixtures"]):
        _fail("fixture include inventory differs from the sealed manifest")
    for expected, actual in zip(fixtures, observed["fixtures"]):
        asset = actual["asset"]
        for field, description in (
            ("asset", "fixture include order"),
            ("owner_source", "fixture source ownership"),
            ("owner_function", "fixture function ownership"),
            ("owner_is_test", "fixture test ownership"),
            ("ordinal", "fixture include ordinal"),
            ("include_path", "fixture include path"),
            ("byte_len", "byte length"),
            ("newline_count", "newline count"),
            ("starts_with_lf", "leading-LF policy"),
            ("ends_with_lf", "final-LF policy"),
            ("content_sha256", "content hash"),
        ):
            if expected[field] != actual[field]:
                _fail(f"{asset} {description} changed")
    return ValidationStats(
        fixtures=len(fixtures),
        tests=sum(len(source["test_names"]) for source in sources),
    )


def write_manifest(root: Path, manifest_path: Path) -> ValidationStats:
    """Regenerate the current seal only after all ownership checks succeed."""

    payload = _capture_manifest(root.resolve())
    manifest_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return validate_manifest(root, manifest_path)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: inferred from this script)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="manifest path, relative to --root by default",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="explicitly regenerate the current inventory after intentional fixture/test edits",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
        stats = (
            write_manifest(root, manifest)
            if args.write
            else validate_manifest(root, manifest)
        )
    except (OSError, UnicodeError, ValidationError) as error:
        print(
            f"ERROR: Kotodama test-source validation failed: {error}", file=sys.stderr
        )
        return 1
    print(f"kotodama_test_sources: fixtures={stats.fixtures} tests={stats.tests}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
