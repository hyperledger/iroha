#!/usr/bin/env python3
"""Validate the current compiled Kotodama IR source and fixture inventory.

This guard records current source ownership, public IR variants, helper bodies
and call sites, compiled test IDs, and included fixture bytes. It does not assert
a historical source size or require a Git preimage. Intentional IR changes must
refresh the reviewable manifest with this script's explicit ``--write`` command;
ordinary test execution is read-only and rejects drift, including fixture drift.
Runtime semantics are covered by the compiler and IVM acceptance tests.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = REPO_ROOT / "crates/kotodama_lang/src/ir.rs"
PUBLIC_LEAF = REPO_ROOT / "crates/kotodama_lang/src/ir/tests/public_argument_record_abi.rs"
TAIL_LEAF = REPO_ROOT / "crates/kotodama_lang/src/ir_tail_tests.rs"
SUM_LEAF = REPO_ROOT / "crates/kotodama_lang/src/ir/sum.rs"
FIXTURE_MANIFEST = REPO_ROOT / "crates/kotodama_lang/kotodama_fixtures_v1.manifest.json"
IR_MANIFEST = REPO_ROOT / "crates/kotodama_lang/kotodama_ir_v1.manifest.json"
HELPER_NAMES = (
    "emit_data_ref_into", "emit_data_ref", "emit_copy", "emit_binary",
    "emit_numeric_compare", "emit_pointer_eq", "emit_unary", "emit_load64_imm",
    "emit_store64_imm", "emit_tuple_get", "emit_tuple_pack", "emit_state_get",
    "emit_alloc", "emit_pointer_to_norito", "emit_pointer_from_norito",
    "append_value_word_types", "lower_map_fallback", "lower_take2_pair",
    "seal_unreachable_continuation",
)

PUBLIC_RE = re.compile(
    r"^pub(?:\(crate\))?\s+(?:const|struct|enum|type|fn)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
DIRECT_TEST_RE = re.compile(
    r"^\s*#\[test\]\s*\n"
    r"(?:\s*#\[[^\n]+\]\s*\n)*"
    r"\s*(?:pub(?:\([^\n)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
ALIAS_TEST_RE = re.compile(
    r"^\s*alias_lowering_case!\(\s*\n?\s*([a-z0-9_]+)\s*,",
    re.MULTILINE,
)
INCLUDE_STR_RE = re.compile(r'include_str!\(\s*"([^"]+)"\s*\)')
RUST_LITERAL_RE = re.compile(
    r'(?<![A-Za-z0-9_])(?:b)?"(?:\\.|[^"\\])*"'
    r'|(?<![A-Za-z0-9_])r(?P<hashes>#{0,16})".*?"(?P=hashes)',
    re.DOTALL,
)
RAW_STRING_START = re.compile(r'(?:b?r)(#*)"')
TEST_ANCHOR = "#[cfg(test)]\n"


class GuardError(AssertionError):
    """Raised when a protected source contract changes."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GuardError(message)


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _regular_bytes(path: Path, root: Path | None = None) -> bytes:
    _require(not path.is_symlink(), f"symlink is not allowed: {path}")
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise GuardError(f"cannot stat {path}: {error}") from error
    _require(stat.S_ISREG(mode), f"not a regular file: {path}")
    resolved = path.resolve(strict=True)
    if root is not None:
        try:
            resolved.relative_to(root.resolve(strict=True))
        except ValueError as error:
            raise GuardError(f"path escapes repository: {path}") from error
    return path.read_bytes()


def _skip_quoted(source: str, start: int) -> int:
    raw = RAW_STRING_START.match(source, start)
    if raw:
        terminator = '"' + raw.group(1)
        end = source.find(terminator, raw.end())
        if end < 0:
            raise GuardError("unterminated Rust raw string")
        return end + len(terminator)
    quote_start = start + (1 if source.startswith('b"', start) else 0)
    quote = source[quote_start]
    cursor = quote_start + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
        elif source[cursor] == quote:
            return cursor + 1
        else:
            cursor += 1
    raise GuardError("unterminated Rust string literal")


def _matching_delimiter(source: str, opening: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    cursor = opening
    while cursor < len(source):
        if source.startswith("//", cursor):
            newline = source.find("\n", cursor + 2)
            cursor = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", cursor):
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
            _require(depth == 0, "unterminated Rust block comment")
            continue
        if source[cursor] == '"' or source.startswith('b"', cursor):
            cursor = _skip_quoted(source, cursor)
            continue
        if RAW_STRING_START.match(source, cursor):
            cursor = _skip_quoted(source, cursor)
            continue
        if source[cursor] == "'" and cursor + 2 < len(source):
            close = cursor + 2 if source[cursor + 1] != "\\" else cursor + 3
            if close < len(source) and source[close] == "'":
                cursor = close + 1
                continue
        character = source[cursor]
        if character in pairs:
            stack.append(character)
        elif character in pairs.values():
            _require(
                bool(stack) and pairs[stack[-1]] == character,
                f"unbalanced Rust delimiter at byte {cursor}",
            )
            stack.pop()
            if not stack:
                return cursor
        cursor += 1
    raise GuardError("unterminated Rust delimiter")


def _item_region_at(source: str, start: int, label: str) -> str:
    try:
        brace = source.index("{", start)
    except ValueError as error:
        raise GuardError(f"missing opening brace: {label}") from error
    return source[start : _matching_delimiter(source, brace) + 1]


def _item_region(source: str, marker: str) -> str:
    try:
        start = source.index(marker)
    except ValueError as error:
        raise GuardError(f"missing item marker: {marker}") from error
    return _item_region_at(source, start, marker)


def _function_region(source: str, name: str) -> str:
    matches = list(re.finditer(rf"(?m)^fn {re.escape(name)}\s*\(", source))
    _require(len(matches) == 1, f"{name} definition count changed")
    return _item_region_at(source, matches[0].start(), name)


def _function_spans(source: str) -> list[tuple[int, int, str]]:
    pattern = re.compile(
        r"(?m)^[ \t]*(?:(?:pub(?:\([^\n)]*\))?)\s+)?"
        r"(?:(?:async|const|unsafe)\s+)*fn\s+([A-Za-z_]\w*)"
        r"(?:<[^\{\n]*>)?\s*\("
    )
    spans: list[tuple[int, int, str]] = []
    for match in pattern.finditer(source):
        opening_paren = source.find("(", match.start(), match.end())
        closing_paren = _matching_delimiter(source, opening_paren)
        opening_brace = source.find("{", closing_paren)
        _require(opening_brace >= 0, f"missing function body: {match.group(1)}")
        spans.append(
            (match.start(), _matching_delimiter(source, opening_brace), match.group(1))
        )
    return spans


def _helper_call_ledger(production: str) -> list[list[str]]:
    names = HELPER_NAMES
    pattern = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\s*\(")
    spans = _function_spans(production)
    ledger: list[list[str]] = []
    for match in pattern.finditer(production):
        before = production[max(0, match.start() - 20) : match.start()]
        if re.search(r"\bfn\s*$", before):
            continue
        opening = production.find("(", match.start(), match.end())
        closing = _matching_delimiter(production, opening)
        containers = [span for span in spans if span[0] <= match.start() <= span[1]]
        _require(bool(containers), f"helper call is outside a function: {match.group(1)}")
        caller = max(containers, key=lambda span: span[0])[2]
        call = re.sub(r"\s+", "", production[match.start() : closing + 1])
        ledger.append([caller, match.group(1), call])
    return ledger


def _fallback_routes(production: str) -> tuple[tuple[str, str], ...]:
    surface = _function_region(production, "lower_surface_builtin_call")
    pattern = re.compile(
        r"Builtin::(GetOrDefault|GetOr|Ensure)\s*=>\s*(?:\{\s*)?"
        r"lower_map_fallback\s*\("
    )
    routes: list[tuple[str, str]] = []
    for match in pattern.finditer(surface):
        opening = surface.find("(", match.start(), match.end())
        closing = _matching_delimiter(surface, opening)
        arguments = re.sub(r"\s+", "", surface[opening + 1 : closing])
        routes.append((match.group(1), arguments))
    return tuple(routes)


def _take2_routing_region(production: str) -> str:
    surface = _function_region(production, "lower_surface_builtin_call")
    start_marker = "        Builtin::KeysTake2 | Builtin::ValuesTake2 => {"
    end_marker = "        Builtin::TestInvokeEntrypoint"
    _require(surface.count(start_marker) == 1, "take2 combined arm changed")
    start = surface.index(start_marker)
    _require(surface.count(end_marker, start) == 1, "take2 routing terminator changed")
    return surface[start : surface.index(end_marker, start)]


def _split_candidate(source: str) -> tuple[str, str]:
    position = source.rfind(TEST_ANCHOR)
    _require(position >= 0, "final cfg(test) anchor is missing")
    return source[:position], source[position:]


def _enum_variants(source: str) -> tuple[str, ...]:
    region = _item_region(source, "pub enum Instr")
    return tuple(
        re.findall(r"^    ([A-Z][A-Za-z0-9_]*)\s*(?:\{|\(|,)", region, re.MULTILINE)
    )


def _leaf_test_names(source: str) -> tuple[str, ...]:
    return tuple(DIRECT_TEST_RE.findall(source))


def _test_inventory(
    source: str, public_leaf: str, tail_leaf: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    _, suffix = _split_candidate(source)
    events: list[tuple[int, tuple[str, ...], str]] = []
    for match in DIRECT_TEST_RE.finditer(suffix):
        events.append((match.start(), (match.group(1),), "direct"))
    for match in ALIAS_TEST_RE.finditer(suffix):
        events.append((match.start(), (match.group(1),), "alias"))

    public_names = _leaf_test_names(public_leaf)
    tail_names = _leaf_test_names(tail_leaf)
    for marker, names in (
        ('include!("ir/tests/public_argument_record_abi.rs")', public_names),
        ('include!("ir_tail_tests.rs")', tail_names),
    ):
        _require(suffix.count(marker) == 1, f"include contract changed: {marker}")
        events.append((suffix.index(marker), names, marker))

    all_names: list[str] = []
    main_names: list[str] = []
    for _, names, kind in sorted(events):
        all_names.extend(names)
        if kind in ("direct", "alias"):
            main_names.extend(names)
    return tuple(main_names), tuple(all_names)


def _validate_forbidden_seams(production: str) -> None:
    for token in (
        "macro_rules!",
        "$body",
        "$action",
        "$step",
        "$assertion",
        "rustfmt::skip",
        "include!",
        "include_str!",
        "include_bytes!",
        "#[path",
        "std::fs",
        "fs::read",
        "read_to_string",
    ):
        _require(token not in production, f"forbidden production token: {token}")
    for pattern in (
        r"\b(?:dyn|impl)\s+Fn(?:Mut|Once)?\b",
        r"(?:^|[=:,<(])\s*fn\s*\(",
        r"\b(?:struct|enum|type)\s+(?:Action|Step|Body|Assertion)\b",
        r"(?m)^\s*macro\s+[A-Za-z_]",
        r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_]\w*\s*;",
    ):
        _require(re.search(pattern, production, re.MULTILINE) is None, f"forbidden seam: {pattern}")


def _validate_v1_lowering_contract(production: str) -> None:
    """Bind reviewed V1 replacements before consulting the source byte seal."""

    for retired in (
        "fn lower_entrypoint_wrapper(", "__entrypoint_impl__", "fn runtime_word_is_pointer(",
        "return_pointer_mask", "returns_pointer:", "Builtin::UseAssetHandle",
        "DataRefKind::AssetHandle", "Instr::DecodeInt", "Instr::EncodeInt",
    ):
        _require(retired not in production, f"retired V1 lowering returned: {retired}")
    surface = re.sub(r"\s+", "", _function_region(production, "lower_surface_builtin_call"))
    numeric = (
        "builtin@(Builtin::Isqrt|Builtin::DivCeil|Builtin::Gcd|Builtin::Mean)"
        "=>{lower_direct_helper_call(ctx,builtin,args,vars)}"
    )
    _require(numeric in surface, "full-width numeric helper routing changed")
    _require("Builtin::Min|Builtin::Max|Builtin::Abs=>{"
             "lower_numeric_selection(ctx,builtin,args,vars)}" in surface,
             "exact numeric-domain selection routing changed")
    selection = _function_region(production, "lower_numeric_selection")
    _require(".map(|arg| lower_expr(ctx, arg, vars))" in selection
             and "lower_expr_as_" not in selection,
             "numeric selection arguments must evaluate once without narrowing")
    for operation in ("MIN", "MAX", "ABS"):
        _require(f"SYSCALL_INT_{operation}" in selection,
                 "integer selection must retain full-width kernels")
    direct = _function_region(production, "lower_direct_helper_call")
    _require("lowered_args.push(lower_expr(ctx, arg, vars));" in direct
             and "lower_expr_as_" not in direct,
             "full-width numeric arguments must not narrow")
    _require("Builtin::StageAnchoredSpend=>{letspend=lower_expr(ctx,&args[0],vars);"
             "ctx.current_instr(Instr::StageAnchoredSpend{spend});emit_i64_const(ctx,0)}"
             in surface, "anchored-spend lowering changed")
    _require("Builtin::ScExecuteSubmitBallot=>{letpayload=lower_expr(ctx,&args[0],vars);"
             "ctx.current_instr(Instr::VendorExecuteInstruction{payload,"
             "kind:VendorInstructionKind::SubmitBallot,});emit_i64_const(ctx,0)}"
             in surface, "typed submit-ballot instruction routing changed")
    _require("matched operation-specific instruction bridge" not in production,
             "typed submit-ballot lowering must not restore the panic lookup")
    expression = _function_region(production, "lower_expr")
    _require("let l = lower_expr(ctx, left, vars);\n            let r = lower_expr(ctx, right, vars);"
             in expression, "equality operands must lower once left-to-right")
    _require("let t = emit_typed_value_eq(ctx, l, r, &left.ty);" in expression
             and "let t2 = emit_unary(ctx, UnaryOp::Not, t);" in expression,
             "recursive equality/inequality routing changed")


def _source_ownership(owner_source: str | None = None) -> dict[str, object]:
    owner_path = "crates/kotodama_lang/src/lib.rs"
    owner = owner_source if owner_source is not None else _regular_bytes(REPO_ROOT / owner_path, REPO_ROOT).decode()
    _require(len(re.findall(r"(?m)^pub mod ir;$", owner)) == 1,
             "compiled IR owner must declare exactly one public ir module")
    _require(re.search(r'#\[path\s*=[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*pub mod ir;', owner) is None,
             "compiled IR owner must not redirect the module")
    return {"source": "crates/kotodama_lang/src/ir.rs", "owner": owner_path,
            "declaration": "pub mod ir;"}


def _asset_ledger(source: str, tail_leaf: str, overrides: dict[str, bytes] | None = None) -> list[dict[str, object]]:
    overrides = overrides or {}
    ledger = []
    for owner, text in ((SOURCE_PATH, source), (TAIL_LEAF, tail_leaf)):
        for include in INCLUDE_STR_RE.findall(text):
            path = owner.parent / include
            original = _regular_bytes(path, REPO_ROOT)
            relative = path.resolve().relative_to(REPO_ROOT).as_posix()
            data = overrides.get(relative, original)
            ledger.append({"path": relative, "owner": owner.relative_to(REPO_ROOT).as_posix(),
                           "bytes": len(data), "sha256": _sha256(data)})
    _require(len({row["path"] for row in ledger}) == len(ledger), "duplicate asset include")
    _require({Path(row["path"]).parent.as_posix() for row in ledger} == {
        "crates/kotodama_lang/src/ir/fixtures/v1", "crates/kotodama_lang/src/ir/test_sources"
    }, "asset directory ownership changed")
    return ledger


def _sum_module_inventory(production: str, sum_leaf: str) -> dict[str, object]:
    """Seal the sole compiled production child, including its own tests."""

    declaration = "\nmod sum;\n"
    _require(production.count(declaration) == 1,
             "compiled sum owner must declare exactly one local sum module")
    # The remaining production source retains the blanket prohibition on
    # unowned modules, redirections, includes and body-dispatch seams.
    _validate_forbidden_seams(production.replace(declaration, "\n", 1))
    child_production, child_tests = _split_candidate(sum_leaf)
    _validate_forbidden_seams(child_production)
    names = list(_leaf_test_names(child_tests))
    _require(bool(names) and len(names) == len(set(names)),
             "compiled sum test IDs must be present and unique")
    functions = re.findall(r"(?m)^(?:pub\(super\) )?fn ([A-Za-z_]\w*)\(", child_production)
    _require(len(functions) == len(set(functions)), "duplicate sum function")
    return {
        "owner": "crates/kotodama_lang/src/ir.rs", "declaration": "mod sum;",
        "source": "crates/kotodama_lang/src/ir/sum.rs",
        "bytes": len(sum_leaf.encode()), "sha256": _sha256(sum_leaf),
        "functions": functions, "tests": ["sum::tests::" + name for name in names],
    }


def _candidate_inventory(source: str, public_leaf: str, tail_leaf: str,
                         asset_overrides: dict[str, bytes] | None = None,
                         sum_leaf: str | None = None) -> dict[str, object]:
    production, suffix = _split_candidate(source)
    if sum_leaf is None:
        sum_leaf = _regular_bytes(SUM_LEAF, REPO_ROOT).decode("utf-8")
    production_modules = [_sum_module_inventory(production, sum_leaf)]
    _validate_v1_lowering_contract(production)
    _require("StateKeys" not in production and "Builtin::StateKeys" not in production,
             "retired offset traversal must not return")
    _require("StateScan {" in production and "state_value_cache" in production,
             "cursor traversal and durable-state cache ownership must remain explicit")
    _require(suffix.count('if *kind == DataRefKind::Json && value == "{}" {') == 1
             and 'value == "{}\\n"' not in suffix, "canonical JSON fixture spelling changed")
    _require("fn append(" not in production, "duplicated nested value-word traversal returned")
    _require("discard_empty_unreferenced_continuation" not in production,
             "stale continuation behavior returned")
    _require(production.count("crate::session::run_with_compiler_stack(move || {") == 1,
             "public lowering must use the bounded compiler worker exactly once")
    public_api = list(PUBLIC_RE.findall(production))
    variants = list(_enum_variants(production))
    _require(len(set(variants)) == len(variants), "duplicate Instr variant")
    main_tests, all_tests = _test_inventory(source, public_leaf, tail_leaf)
    _require(len(set(all_tests)) == len(all_tests), "duplicate compiled test ID")
    helpers = []
    for name in HELPER_NAMES:
        region = _function_region(production, name)
        _require(f"#[inline]\nfn {name}" not in production, "helper must not force inline expansion")
        helpers.append({"name": name, "sha256": _sha256(region),
                        "calls": len(re.findall(rf"\b{re.escape(name)}\s*\(", production)) - 1})
    return {
        "format": "iroha.kotodama.ir-source-inventory", "version": 1,
        "ownership": _source_ownership(),
        "production_modules": production_modules,
        "public_api": public_api, "instruction_variants": variants,
        "production_literals": sorted({match.group(0) for match in RUST_LITERAL_RE.finditer(production)}),
        "main_tests": list(main_tests), "compiled_tests": list(all_tests),
        "test_leaves": {"public": _sha256(public_leaf), "tail": _sha256(tail_leaf)},
        "assets": _asset_ledger(source, tail_leaf, asset_overrides),
        "helpers": helpers, "helper_calls": _helper_call_ledger(production),
        "map_fallback_routes": [list(route) for route in _fallback_routes(production)],
        "take2_routing_sha256": _sha256(_take2_routing_region(production)),
        "source": {"bytes": len(source.encode()), "sha256": _sha256(source)},
    }


def _validate_candidate(source: str, public_leaf: str, tail_leaf: str, *,
                        asset_overrides: dict[str, bytes] | None = None,
                        sum_leaf: str | None = None) -> None:
    expected = json.loads(_regular_bytes(IR_MANIFEST, REPO_ROOT))
    observed = _candidate_inventory(source, public_leaf, tail_leaf, asset_overrides, sum_leaf)
    _require(expected.keys() == observed.keys(), "IR inventory fields changed")
    for key, value in observed.items():
        _require(value == expected[key], f"IR inventory drift: {key}")
    fixtures = json.loads(_regular_bytes(FIXTURE_MANIFEST, REPO_ROOT))
    rows = [row for row in fixtures["source_files"] if row["path"] == "crates/kotodama_lang/src/ir.rs"]
    _require(len(rows) == 1 and rows[0]["test_names"] == observed["compiled_tests"],
             "IR test IDs must match the independently sealed compiler fixture inventory")


def _inputs() -> tuple[str, str, str]:
    return tuple(_regular_bytes(path, REPO_ROOT).decode("utf-8")
                 for path in (SOURCE_PATH, PUBLIC_LEAF, TAIL_LEAF))


class KotodamaIrCompactionSourceTest(unittest.TestCase):
    def test_repository_contract(self) -> None:
        _validate_candidate(*_inputs())


class KotodamaIrCompactionMutationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source, cls.public_leaf, cls.tail_leaf = _inputs()

    def rejects(self, old: str, new: str, message: str) -> None:
        mutated = self.source.replace(old, new, 1)
        self.assertNotEqual(mutated, self.source)
        with self.assertRaisesRegex(GuardError, message):
            _validate_candidate(mutated, self.public_leaf, self.tail_leaf)

    def test_api_variant_test_and_literal_drift(self) -> None:
        for old, new, message in (
            ("pub struct Temp", "pub struct Tamp", "public_api"),
            ("    Const {", "    Konst {", "instruction_variants"),
            ("fn malformed_typed_member_access_fails_closed_during_lowering",
             "fn malformed_typed_member_access_fails_shut_during_lowering", "main_tests"),
            ('"internal error: missing lowered parameter `{}`"',
             '"internal error: absent lowered parameter `{}`"', "production_literals"),
        ):
            self.rejects(old, new, message)

    def test_constructor_and_call_argument_drift(self) -> None:
        self.rejects("let table = emit_alloc(ctx, bytes);", "let table = emit_state_get(ctx, bytes);", "helpers")
        # get_or_insert is the sole fallback route: its third argument is the
        # lazy default, and an absent durable key must store that value.
        self.rejects("lower_map_fallback(ctx, &args[0], &args[1], &args[2], vars)",
                     "lower_map_fallback(ctx, &args[0], &args[1], &args[1], vars)", "helper_calls")
        self.rejects("let _ = lower_state_map_set_value(ctx, &base, key, &spec.key, &spec.value, default);",
                     "let _ = default;", "helpers")
        self.rejects("lower_map_fallback(ctx, &args[0], &args[1], &args[2],",
                     "lower_map_fallback(ctx, &args[1], &args[0], &args[2],", "helper_calls")
        self.rejects("let keep_going = emit_binary(ctx, BinaryOp::Lt, index, source_len);",
                     "let keep_going = emit_binary(ctx, BinaryOp::Lt, source_len, index);", "helper_calls")

    def test_asset_and_source_bytes_fail_closed(self) -> None:
        path = "crates/kotodama_lang/src/ir/fixtures/v1/i001.ko"
        with self.assertRaisesRegex(GuardError, "assets"):
            _validate_candidate(self.source, self.public_leaf, self.tail_leaf,
                                asset_overrides={path: (REPO_ROOT / path).read_bytes() + b" "})
        self.rejects("//! Intermediate representation for Kotodama programs.",
                     "//! Intermediate representation for Kotodama programs. ", "source")

    def test_v1_replacement_routes_cannot_regress(self) -> None:
        for old, new, message in (
            ("Builtin::Mean) => {\n            lower_direct_helper_call(ctx, builtin, args, vars)\n        }",
             "Builtin::Mean) => emit_i64_const(ctx, 0),", "full-width numeric helper routing"),
            ("lower_numeric_selection(ctx, builtin, args, vars)",
             "lower_direct_helper_call(ctx, builtin, args, vars)", "exact numeric-domain selection"),
            ('let kind = wide_numeric_kind_for_type(&args[0].ty).expect("typed selection operand");\n    let values = args\n        .iter()\n        .map(|arg| lower_expr(ctx, arg, vars))',
             'let kind = wide_numeric_kind_for_type(&args[0].ty).expect("typed selection operand");\n    let values = args\n        .iter()\n        .map(|arg| lower_expr_as_i64(ctx, arg, vars))',
             "selection arguments must evaluate once"),
            ("lowered_args.push(lower_expr(ctx, arg, vars));",
             "lowered_args.push(lower_expr_as_i64(ctx, arg, vars));", "must not narrow"),
            ("ctx.current_instr(Instr::StageAnchoredSpend { spend });",
             "ctx.current_instr(Instr::AxtCommit);", "anchored-spend lowering"),
            ("kind: VendorInstructionKind::SubmitBallot,",
             "kind: vendor_instruction_kind_for_builtin(builtin),",
             "typed submit-ballot instruction routing"),
            ("let l = lower_expr(ctx, left, vars);\n            let r = lower_expr(ctx, right, vars);",
             "let r = lower_expr(ctx, right, vars);\n            let l = lower_expr(ctx, left, vars);",
             "left-to-right"),
            ("let t = emit_typed_value_eq(ctx, l, r, &left.ty);",
             "let t = emit_pointer_eq(ctx, l, r);", "recursive equality"),
        ):
            with self.subTest(message=message):
                self.rejects(old, new, message)
        production, _ = _split_candidate(self.source)
        for retired in ("fn lower_entrypoint_wrapper(", "return_pointer_mask", "Builtin::UseAssetHandle"):
            with self.subTest(retired=retired):
                with self.assertRaisesRegex(GuardError, "retired V1 lowering"):
                    _validate_v1_lowering_contract(production + "\n// " + retired)
        with self.assertRaisesRegex(GuardError, "must not restore the panic lookup"):
            _validate_v1_lowering_contract(
                production + '\n// matched operation-specific instruction bridge'
            )

    def test_compiled_module_ownership_cannot_redirect(self) -> None:
        for owner in ('pub mod something_else;', '#[path = "other.rs"]\npub mod ir;',
                      '#[path = "other.rs"]\n#[allow(dead_code)]\npub mod ir;'):
            with self.assertRaisesRegex(GuardError, "compiled IR owner"):
                _source_ownership(owner)

    def test_current_sum_module_and_tests_are_sealed(self) -> None:
        sum_leaf = _regular_bytes(SUM_LEAF, REPO_ROOT).decode("utf-8")
        observed = _candidate_inventory(self.source, self.public_leaf, self.tail_leaf)
        self.assertEqual(len(observed["production_modules"]), 1)
        child = observed["production_modules"][0]
        self.assertEqual(child["source"], "crates/kotodama_lang/src/ir/sum.rs")
        self.assertEqual(child["functions"], [
            "sum_layout_for_type", "sum_active_payload_type", "emit_sum_value",
            "load_sum_tag", "load_sum_payload", "payload_word_address",
        ])
        self.assertEqual(child["tests"], [
            "sum::tests::payload_addresses_cross_the_immediate_boundary_without_truncation",
            "sum::tests::overflowing_payload_addresses_record_an_error_without_emitting_access",
            "sum::tests::wide_payload_construction_and_loading_share_the_complete_address_range",
        ])
        for before, after in (
            ("layout.validate_active_width(tag, actual_words)",
             "layout.validate_active_width(tag, 0)"),
            ("fn load_sum_tag(", "fn load_wrong_tag("),
            ("fn overflowing_payload_addresses_record_an_error_without_emitting_access",
             "fn overflowing_payload_addresses_are_ignored"),
        ):
            with self.subTest(before=before):
                self.assertEqual(sum_leaf.count(before), 1)
                with self.assertRaisesRegex(GuardError, "production_modules"):
                    _validate_candidate(self.source, self.public_leaf, self.tail_leaf,
                                        sum_leaf=sum_leaf.replace(before, after, 1))
        self.rejects("\nmod sum;\n", "\nmod other;\n", "compiled sum owner")
        self.rejects("\nmod sum;\n", "\nmod sum;\nmod other;\n", "forbidden seam")
        self.rejects("\nmod sum;\n", '\n#[path = "other.rs"]\nmod sum;\n',
                     "forbidden production token")
        with self.assertRaisesRegex(GuardError, "forbidden seam"):
            _validate_candidate(self.source, self.public_leaf, self.tail_leaf,
                                sum_leaf=sum_leaf.replace("use super::*;", "mod hidden;", 1))

    def test_forbidden_helpers_and_retired_traversal_fail(self) -> None:
        anchor = "//! Intermediate representation for Kotodama programs."
        self.rejects(anchor, "// impl Fn callback seam", "forbidden seam")
        self.rejects(anchor, 'include!("compacted_body.rs");', "forbidden production token")
        self.rejects("    StateScan {", "    StateKeys {", "retired offset traversal")
        self.rejects("fn runtime_value_word_types(ty: &Type) -> Vec<Type> {",
                     "fn append(ty: &Type, words: &mut Vec<Type>) {", "duplicated nested")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        inventory = _candidate_inventory(*_inputs())
        IR_MANIFEST.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        _validate_candidate(*_inputs())
        print(f"sealed {len(inventory['instruction_variants'])} IR variants, "
              f"{len(inventory['compiled_tests'])} tests, {len(inventory['assets'])} assets")
    else:
        unittest.main()
