#!/usr/bin/env python3
"""Fail closed on the Kotodama semantic-helper consolidation contract."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = Path("crates/kotodama_lang/src/semantic.rs")

# Source-size policy is retired; preserve the semantic owners and regressions.
OWNER_PATHS = (
    Path("crates/kotodama_lang/src/semantic/value_traits.rs"),
    Path("crates/kotodama_lang/src/semantic/trigger_lowering.rs"),
)

# Current compiler regressions cover labels, nominal errors, named patterns,
# rejection selectors and bounded map scanning.
TEST_MARKER = "#[cfg(test)]\nmod tests {"
TEST_LEAVES = (
    Path('crates/kotodama_lang/src/semantic/tests/numeric_rounding_modes.rs'),
    Path('crates/kotodama_lang/src/semantic/tests/trigger_semantics_tests.rs'),
    Path('crates/kotodama_lang/src/semantic_sum_tests.rs'),
    Path('crates/kotodama_lang/src/semantic/tests/call_labels_and_patterns.rs'),
)

RETIRED_BUILTINS = (
    "AnonymousEscrowAccept",
    "AnonymousEscrowCancel",
    "AnonymousEscrowMarkPaymentSent",
    "AnonymousEscrowOpenDispute",
    "AnonymousEscrowOpenOffer",
    "AnonymousEscrowRelease",
    "AnonymousEscrowResolveDispute",
    "BuildPathKeyNoritoDirect",
    "BuildUnshieldInline",
    "CreateTrigger",
    "DecodeInt",
    "EncodeInt",
    "UseAssetHandle",
    "JsonGetAccountIdDirect",
    "JsonGetAssetDefinitionIdDirect",
    "JsonGetBlobHexDirect",
    "JsonGetDecimalDirect",
    "JsonGetIntDirect",
    "JsonGetJsonDirect",
    "JsonGetNameDirect",
    "JsonGetNftIdDirect",
    "JsonGetQuantityDirect",
    "JsonSetAccountIdDirect",
    "JsonSetIntDirect",
    "RemoveTrigger",
    "ScExecuteUnshield",
    "SchemaDecodeDirect",
    "SchemaEncodeDirect",
    "SchemaInfoDirect",
    "SoracloudEgressFetch",
    "SoracloudReadCredential",
    "SoracloudReadSecret",
    "ZkVerifyTransfer",
    "ZkVerifyUnshield",
)


class GuardError(AssertionError):
    """Raised when the protected source contract changes."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GuardError(message)


def _read_repo_source(relative: Path) -> str:
    path = REPO_ROOT / relative
    _require(path.is_file() and not path.is_symlink(), f"invalid source path: {path}")
    try:
        path.resolve(strict=True).relative_to(REPO_ROOT)
    except ValueError as error:
        raise GuardError(f"source escapes repository root: {path}") from error
    return path.read_text(encoding="utf-8")


def _read_source() -> str:
    return _read_repo_source(SOURCE_PATH)


def _read_owners() -> dict[Path, str]:
    return {path: _read_repo_source(path) for path in OWNER_PATHS}






def _region(source: str, start: str, end: str) -> str:
    _require(source.count(start) == 1, f"expected one region start: {start!r}")
    start_index = source.index(start)
    _require(source.count(end, start_index) == 1, f"expected one region end: {end!r}")
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


def _test_records(source: str) -> list[tuple[tuple[str, ...], str]]:
    pattern = re.compile(
        r"(?m)^(?P<attrs>(?:[ \t]*#\[[^\n]+\][ \t]*\n)+)"
        r"[ \t]*(?:async[ \t]+)?fn[ \t]+(?P<name>[A-Za-z_]\w*)[ \t]*\("
    )
    records = []
    for match in pattern.finditer(source):
        attributes = tuple(re.findall(r"#\[[^\n]+\]", match.group("attrs")))
        if "#[test]" in attributes:
            records.append((attributes, match.group("name")))
    return records


def _builtin_variants(source: str) -> list[str]:
    return sorted(set(re.findall(r"Builtin::([A-Za-z0-9_]+)", source)))




def validate_source(source: str, owners: dict[Path, str] | None = None) -> None:
    """Validate the parent, its two cohesive owners and semantic invariants."""

    _require(source.count(TEST_MARKER) == 1, "test module marker changed")
    marker_index = source.index(TEST_MARKER)
    parent_production = source[:marker_index]
    test_suffix = source[marker_index:]
    owners = _read_owners() if owners is None else owners
    _require(set(owners) == set(OWNER_PATHS), "semantic owner inventory changed")
    for path in OWNER_PATHS:
        _require(not _test_records(owners[path]), f"tests relocated into production owner: {path}")
    for declaration in (
        "mod trigger_lowering;", "mod value_traits;",
        "use trigger_lowering::analyze_trigger;",
        "use value_traits::render_source_type_name;",
        "pub use value_traits::render_type_name;",
        "pub(crate) use value_traits::type_name;",
    ):
        _require(parent_production.count(declaration) == 1, f"semantic owner wiring changed: {declaration}")
    production = parent_production + "\n" + "\n".join(owners[path] for path in OWNER_PATHS)

    test_records = _test_records(test_suffix)
    _require(test_records and len({name for _, name in test_records}) == len(test_records),
             "direct test identities are empty or duplicated")
    for path in TEST_LEAVES:
        leaf_source = _read_repo_source(path)
        leaf_records = _test_records(leaf_source)
        _require(bool(leaf_records), f"test leaf has no executable coverage: {path}")
    value_traits = owners[OWNER_PATHS[0]]
    _require(value_traits.count("if left_name != right_name || left_fields.len() != right_fields.len()") == 2,
             "nominal type identity comparison missing")
    _require("while let Some((left, right)) = pending.pop()" in value_traits,
             "active typed equality traversal is not iterative")
    _require('code: "E_TRIGGER_INVALID_NAME"' in owners[OWNER_PATHS[1]],
             "trigger name rejection diagnostic missing")

    helper_region = _region(
        production,
        "fn typed_expr(",
        "\nfn enclosing_return_type(",
    )
    effect_region = _region(
        production,
        "fn block_effects(",
        "\nfn is_state_identifier(",
    )
    fixed_region = _region(
        helper_region,
        "fn fixed_builtin_message(",
        "\nfn fixed_builtin_arg_accepts(",
    )
    custom_start = "fn analyze_surface_builtin_call("
    _require(
        helper_region.count(custom_start) == 1,
        "surface Builtin analyzer boundary changed",
    )
    custom_region = helper_region[helper_region.index(custom_start) :]
    fixed_builtins = _builtin_variants(fixed_region)
    custom_builtins = _builtin_variants(custom_region)
    _require(bool(fixed_builtins), "fixed Builtin partition is empty")
    _require(bool(custom_builtins), "custom Builtin partition is empty")
    _require(
        not set(fixed_builtins).intersection(custom_builtins),
        "fixed and custom Builtin partitions overlap",
    )
    for retired in RETIRED_BUILTINS:
        _require(
            re.search(rf"\bBuiltin::{re.escape(retired)}\b", production) is None,
            f"retired Builtin returned: {retired}",
        )
    for token in (
        "macro_rules!",
        "$action",
        "$body",
        "$step",
        "dyn Fn",
        "impl Fn",
        ": fn(",
        "fn (",
        "#[rustfmt::skip]",
        "#[path =",
        "include!",
    ):
        _require(token not in helper_region + effect_region, f"forbidden helper token: {token}")

    _require(
        production.count("direct_effects: block_effects(") == 2,
        "effect summaries no longer use the unified walker exactly twice",
    )
    for old_name in (
        "block_contains_host_side_effects",
        "block_contains_instruction_emission",
        "block_mutates_durable_state",
        "statement_contains_host_side_effects",
        "statement_contains_instruction_emission",
        "statement_mutates_durable_state",
        "expr_contains_host_side_effects",
        "expr_contains_instruction_emission",
        "expr_mutates_durable_state",
    ):
        _require(old_name not in production, f"parallel effect walker returned: {old_name}")

    _require("*vars = loop_env;" not in production, "for-loop locals leaked into outer scope")

    for required in (
        "query page offset must be in 0..=i64::MAX",
        "query page offset plus limit must fit i64",
        ".or_else(|| value.try_to_u128().map(JsonNumber::U128))",
        "_ => analyze_fixed_builtin_call(builtin, arg_typed)",
        "effects.merge_from(statement_effects(context, statement));",
        "effects.mutates_durable_state |= typed_map_expr_is_state(context, map);",
        "let mut t1 = analyze_expr_in_context(context, then_expr, vars, expected, boundary)?;",
        "struct DefiniteInitExprFlow {",
        "fn continue_definite_init_expr(",
        "crate::checked_arithmetic::evaluate(&expression)",
        "Ok(Some(value)) => Ok(value.into_typed_expr())",
        "Ok(None) => Ok(expression)",
        "code: error.code()",
        "Builtin::StageAnchoredSpend",
        '"AxtAnchoredSpendV1" => ty == &Type::AxtAnchoredSpendV1',
    ):
        _require(required in production, f"required current semantic invariant missing: {required}")
    for required_test in (
        "fn param_type_enforcement_primitives(",
        "fn trigger_metadata_integer_domain_is_exact_through_u128(",
        "fn typed_aggregate_traits_are_spawn_free_for_flat_width(",
        "fn semantic_type_and_expression_traits_are_iterative_at_the_depth_boundary(",
        "fn public_semantic_apis_handoff_from_a_small_caller(",
        "fn ternary_literals_inherit_the_enclosing_numeric_context(",
        "fn raw_semantic_analysis_does_not_leak_range_iterators(",
        "fn scalar_state_initialization_checks_early_returns_inside_expressions(",
    ):
        _require(required_test in test_suffix, f"required regression test missing: {required_test}")
    for stale in (
        "query page offset must be non-negative and fit u64",
        "E_UNSHIELD_AMOUNT_RANGE",
    ):
        _require(stale not in production, f"stale donor semantic returned: {stale}")


def _replace_once(source: str, old: str, new: str) -> str:
    _require(source.count(old) == 1, f"mutation anchor changed: {old!r}")
    return source.replace(old, new, 1)


class KotodamaSemanticHelpersSourceTest(unittest.TestCase):
    """Authenticate the compact helpers and prove the guard fails closed."""

    def test_repository_source_contract(self) -> None:
        validate_source(_read_source())

    def test_whitespace_growth_preserves_semantic_contract(self) -> None:
        source = _read_source()
        changed = _replace_once(source, TEST_MARKER, "\n" * 20_000 + TEST_MARKER)
        validate_source(changed)

    def test_mutations_fail_closed(self) -> None:
        source = _read_source()
        owners = _read_owners()
        validate_source(source, owners)
        variant_anchor = (
            "        _ => return None,\n"
            "    })\n"
            "}\n\n"
            "fn fixed_builtin_arg_accepts"
        )
        mutations = {
            "fixed diagnostic": _replace_once(
                source,
                "query page offset plus limit must fit i64",
                "query page offset plus limit must fit u64",
            ),
            "u128 trigger metadata": _replace_once(
                source,
                ".or_else(|| value.try_to_u128().map(JsonNumber::U128))",
                ".or_else(|| value.try_to_u64().map(JsonNumber::U64))",
            ),
            "effect merge": _replace_once(
                source,
                "effects.merge_from(statement_effects(context, statement));",
                "let _ = statement;",
            ),
            "test identity": _replace_once(
                source,
                "fn param_type_enforcement_primitives(",
                "fn param_type_enforcement_primitives_mutated(",
            ),
            "retired variant": _replace_once(
                source,
                variant_anchor,
                "        Builtin::BuildUnshieldInline => unreachable!(),\n"
                + variant_anchor,
            ),
            "split effect walk": _replace_once(
                source,
                "direct_effects: block_effects(&context, &function.body)",
                "direct_effects: block_contains_host_side_effects(&function.body)",
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(mutated, source)
                with self.assertRaises(GuardError):
                    validate_source(mutated, owners)


    def test_owner_mutations_fail_closed(self) -> None:
        source = _read_source()
        owners = _read_owners()
        validate_source(source, owners)
        mutations = (
            (
                "trigger diagnostic", OWNER_PATHS[1],
                'code: "E_TRIGGER_INVALID_NAME"',
                'code: "E_TRIGGER_INVALID_NAME_CHANGED"',
                1,
            ),
            (
                "nominal type identity", OWNER_PATHS[0],
                "if left_name != right_name || left_fields.len() != right_fields.len()",
                "if left_fields.len() != right_fields.len()",
                2,
            ),
            (
                "active typed equality", OWNER_PATHS[0],
                "while let Some((left, right)) = pending.pop()",
                "while let Some((left, right)) = pending.first().copied()",
                1,
            ),
        )
        for label, path, old, new, expected_count in mutations:
            with self.subTest(label=label):
                mutated = dict(owners)
                self.assertEqual(owners[path].count(old), expected_count)
                mutated[path] = owners[path].replace(old, new, 1)
                with self.assertRaises(GuardError):
                    validate_source(source, mutated)

    def test_missing_owner_or_public_path_is_rejected(self) -> None:
        source = _read_source()
        owners = _read_owners()
        validate_source(source, owners)
        with self.assertRaises(GuardError):
            validate_source(source, {OWNER_PATHS[0]: owners[OWNER_PATHS[0]]})
        with self.assertRaises(GuardError):
            validate_source(
                _replace_once(source, "pub use value_traits::render_type_name;", ""),
                owners,
            )


if __name__ == "__main__":
    unittest.main()
