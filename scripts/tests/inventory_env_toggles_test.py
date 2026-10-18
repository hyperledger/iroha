"""Tests for the Rust environment-toggle inventory."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "inventory_env_toggles.py"
SPEC = importlib.util.spec_from_file_location("inventory_env_toggles", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_classify_scope_treats_included_test_shards_as_tests() -> None:
    """Test-only Rust shards under ``src`` must not become production toggles."""

    test_paths = (
        Path("crates/norito/src/core/sequence_plan_helper_tests.rs"),
        Path("crates/iroha_core/src/privacy_release_evidence/tests.rs"),
        Path("crates/iroha_core/src/tx/empty_instruction_test.rs"),
    )

    assert all(MODULE.classify_scope(path) == "test" for path in test_paths)


def test_classify_scope_does_not_match_test_as_an_arbitrary_substring() -> None:
    """Production names containing ``test`` remain production sources."""

    assert MODULE.classify_scope(Path("crates/example/src/contest.rs")) == "prod"


def test_classify_scope_preserves_build_and_directory_roles() -> None:
    """The filename rule must preserve existing build and directory policy."""

    assert MODULE.classify_scope(Path("crates/example/build.rs")) == "build"
    assert MODULE.classify_scope(Path("crates/example/tests/support.rs")) == "test"
    assert MODULE.classify_scope(Path("tools/example/src/main.rs")) == "tool"


@pytest.mark.parametrize(
    ("attribute", "expected"),
    [
        ("#[cfg(test)]", (True, False)),
        ("#[cfg(not(test))]", (False, False)),
        ('#[cfg(any(test, feature = "runtime"))]', (False, False)),
        ('#[cfg(all(test, feature = "runtime"))]', (True, False)),
        ('#[cfg(any(all(test, unix), all(test, windows)))]', (True, False)),
        ('#[cfg(not(any(not(test), feature = "runtime")))]', (True, False)),
        ('#[cfg(feature = "test")]', (False, False)),
        ('#[cfg(latest)]', (False, False)),
        ("#[cfg(debug_assertions)]", (False, True)),
        ("#[cfg(not(debug_assertions))]", (False, False)),
        ('#[cfg(any(debug_assertions, feature = "runtime"))]', (False, False)),
        ('#[cfg(all(debug_assertions, not(test)))]', (False, True)),
        ('#[cfg(all(test, debug_assertions))]', (True, True)),
        ("#[cfg(any(test, debug_assertions))]", (False, False)),
        ('#[cfg_attr(test, derive(Clone))]', (False, False)),
        ('#[cfg_attr(test, cfg(test))]', (False, False)),
        ('#[cfg_attr(not(test), cfg(test))]', (True, False)),
        ('#[cfg_attr(not(test), cfg(any()))]', (True, False)),
        ('#[cfg_attr(all(), cfg(test), allow(dead_code))]', (True, False)),
        ('#[cfg_attr(all(), cfg_attr(all(), cfg(debug_assertions)))]', (False, True)),
        ('#[cfg_attr(feature = "runtime", cfg(test))]', (False, False)),
        ('#[cfg_attr(not(debug_assertions), cfg(any()))]', (False, True)),
        ('#[cfg(unknown(test))]', (False, False)),
        ('#[cfg(not(test, unix))]', (False, False)),
        ('#[cfg(test) extra]', (False, False)),
        ('#[cfg_attr(test)]', (False, False)),
    ],
)
def test_cfg_conditions_require_the_classified_flag(attribute, expected) -> None:
    """Negation and alternative release paths must never hide runtime reads."""

    source = [attribute, "fn owner() {", 'std::env::var("KNOB");', "}"]
    assert MODULE.compute_cfg_masks(source)[2] == expected


def test_multiline_nested_and_stacked_cfg_attributes() -> None:
    """Balanced attributes retain their owner and inherited module conditions."""

    source = '''#[cfg(
    all(
        test,
        any(feature = "runtime", unix),
    )
)]
#[allow(dead_code)]
mod tests {
    #[cfg(not(debug_assertions))]
    fn owner(first: u8, second: [u8; 2]) {
        std::env::var("TEST_ONLY");
    }
}
fn production() {
    std::env::var("PRODUCTION");
}'''.splitlines()
    masks = MODULE.compute_cfg_masks(source)
    assert masks[10] == (True, False)
    assert masks[14] == (False, False)


def test_cfg_attribute_does_not_leak_from_declarations_or_fields() -> None:
    """An item without a body must release pending attributes at its boundary."""

    source = '''#[cfg(test)]
mod tests;
#[cfg(debug_assertions)]
use crate::debug;
struct Fixture {
    #[cfg(test)]
    unused: u8,
    ordinary: u8,
}
fn runtime() {
    std::env::var("RUNTIME");
}'''.splitlines()
    assert MODULE.compute_cfg_masks(source)[10] == (False, False)


def test_inner_attributes_apply_only_to_their_scope() -> None:
    """Crate and inline-module inner cfg attributes have bounded scope."""

    source = '''mod helper {
    #![cfg(test)]
    fn inner() { std::env::var("INNER"); }
}
fn runtime() { std::env::var("RUNTIME"); }'''.splitlines()
    masks = MODULE.compute_cfg_masks(source)
    assert masks[2] == (True, False)
    assert masks[4] == (False, False)
    assert MODULE.compute_cfg_masks(['#![cfg(debug_assertions)]', *source])[5] == (False, True)


@pytest.mark.parametrize(
    "decoy",
    [
        "// #[cfg(test)] {",
        "/* #[cfg(test)] { /* nested */ } */",
        'let text = "#[cfg(test)] {";',
        'let text = r##"#[cfg(test)] { " quoted"##;',
        'let text = br#"#[cfg(test)] {"#;',
        'let text = c"#[cfg(test)] {";',
        "let brace = '{'; let byte = b'}';",
        "let value: &'static str = \"ordinary\";",
        "if cfg!(test) { }",
        "if cfg!(not(debug_assertions)) { }",
    ],
)
def test_non_attribute_text_cannot_mask_following_runtime_reads(decoy) -> None:
    """Literal/comment braces and runtime cfg expressions carry no scope grant."""

    source = ["fn runtime() {", decoy, 'std::env::var("RUNTIME");', "}"]
    assert MODULE.compute_cfg_masks(source)[2] == (False, False)


def test_multiline_literals_comments_and_escaped_quotes_preserve_scope() -> None:
    """The scanner ignores structural decoys across lines and escaped quotes."""

    source = ['#[cfg(test)]', 'fn owner() {',
              'let text = r###"', '#[cfg(not(test))] }', '"###;',
              '/* nested /* } */ comment', '} */',
              'let escaped = "quote \\\" }";',
              'std::env::var("TEST_ONLY");', '}',
              'fn runtime() { std::env::var("RUNTIME"); }']
    masks = MODULE.compute_cfg_masks(source)
    assert masks[8] == (True, False)
    assert masks[10] == (False, False)


def test_mixed_scopes_on_same_line_remain_conservative() -> None:
    """Line-based inventory cannot prove one shared line exclusively test-only."""

    source = ['#[cfg(test)] fn test() {} fn runtime() { std::env::var("RUNTIME"); }']
    assert MODULE.compute_cfg_masks(source) == [(False, False)]
    assert MODULE.compute_cfg_masks(['#[cfg(test)] fn test() { std::env::var("TEST"); }']) == [(True, False)]


@pytest.mark.parametrize(
    "signature",
    [
        "fn owner(#[cfg(test)] only_test: u8, ordinary: u8) {",
        "fn owner(#[cfg(test)] only_test: u8) {",
        "fn owner(\n#[cfg(test)] only_test: u8,\nordinary: u8\n) {",
    ],
)
def test_parameter_attribute_never_gates_function_body(signature) -> None:
    """Parameter cfg applies to the parameter, not the enclosing function."""

    lines = (signature + '\nstd::env::var("RUNTIME");\n}').splitlines()
    assert MODULE.compute_cfg_masks(lines)[-2] == (False, False)
    assert MODULE.compute_cfg_masks(['#[cfg(debug_assertions)]', *lines])[-2] == (False, True)


def test_tuple_element_attribute_never_gates_following_expression() -> None:
    """Conservatively ignore attrs whose subordinate expression owner is unknown."""

    lines = ['fn owner() {', 'let values = (#[cfg(test)] 1,',
             'std::env::var("RUNTIME"));', '}']
    assert MODULE.compute_cfg_masks(lines)[2] == (False, False)


def test_predicate_unknowns_and_excessive_depth_remain_conservative() -> None:
    """Malformed or unsupported predicates do not become proof of a flag."""

    assert MODULE.cfg_arguments(["all", "(", "test", ",", ")"], "all") == [["test"]]
    assert MODULE.cfg_arguments(["all", "(", "test", "]", ")"], "all") is None
    assert MODULE.cfg_possible(["test"], "test") == {False}
    assert MODULE.cfg_possible(["unix"], "test") == {False, True}
    assert MODULE.cfg_possible(["test"], "test", depth=65) == {False, True}
    assert MODULE.cfg_attribute_possible(["cfg", "(", "test", ")"], "test", depth=65) == {False, True}


def test_rust_scope_tokens_preserve_real_token_lines() -> None:
    """Opaque literal tokens retain line positions without exposing braces."""

    tokens = MODULE.rust_scope_tokens('/* first\n nested /* } */ */\nfn owner() { "{"; }')
    assert tokens == [("fn", 2), ("owner", 2), ("(", 2), (")", 2),
                      ("{", 2), ("<literal>", 2), (";", 2), ("}", 2)]


@pytest.mark.parametrize("prefix", ["// dev_env_flag", "fn dev_env_flag() {}"])
def test_unrelated_helper_name_never_reclassifies_runtime_reference(tmp_path, monkeypatch, prefix) -> None:
    """Source proximity is not evidence that an environment read is debug-only."""

    monkeypatch.setattr(MODULE, "REPO_ROOT", tmp_path)
    path = tmp_path / "owner.rs"
    path.write_text(prefix + '\nfn runtime() { std::env::var("RUNTIME"); }\n')
    references = MODULE.extract_references(path)
    assert [(ref.name, ref.scope) for ref in references] == [("RUNTIME", "prod")]


def test_inventory_extracts_cfg_scopes_without_hiding_release_reads(tmp_path, monkeypatch) -> None:
    """The generated inventory observes test/debug evidence at actual read sites."""

    monkeypatch.setattr(MODULE, "REPO_ROOT", tmp_path)
    # The evidence runner keeps pytest temp files under target; this fixture is
    # the source root being tested, not a build-artifact traversal.
    monkeypatch.setattr(MODULE, "SKIP_DIRS", set())
    path = tmp_path / "owner.rs"
    path.write_text('''#[cfg(test)]
fn tests() { std::env::var("TEST_ONLY"); }
#[cfg(not(test))]
fn release() { std::env::var("RELEASE"); }
#[cfg(any(test, feature = "runtime"))]
fn optional() { std::env::var("OPTIONAL_TEST"); }
#[cfg(debug_assertions)]
fn debug() { std::env::var("DEBUG_ONLY"); }
''')
    assert [(ref.name, ref.scope) for ref in MODULE.collect_inventory(tmp_path)] == [
        ("DEBUG_ONLY", "debug"), ("OPTIONAL_TEST", "prod"),
        ("RELEASE", "prod"), ("TEST_ONLY", "test"),
    ]


@pytest.mark.parametrize("source", ["fn ordinary() {}", "fn dynamic(name: &str) { std::env::var(name); }"])
def test_sources_without_literal_reads_need_no_scope_scan(tmp_path, monkeypatch, source) -> None:
    """Files unable to emit inventory rows avoid the structural scanner entirely."""

    monkeypatch.setattr(MODULE, "REPO_ROOT", tmp_path)
    path = tmp_path / "owner.rs"
    path.write_text(source)

    def unexpected_scan(_lines):
        raise AssertionError("scope scan cannot contribute a literal reference")

    monkeypatch.setattr(MODULE, "compute_cfg_masks", unexpected_scan)
    assert MODULE.extract_references(path) == []
