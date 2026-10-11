"""Focused tests for canonical Kotodama syntax/editor/SDK regeneration."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "regenerate_kotodama_syntax.py"
SPEC = importlib.util.spec_from_file_location("regenerate_kotodama_syntax", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader  # pragma: no cover - defensive
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _copy_generator_inputs(destination: Path) -> None:
    source = MODULE.REPOSITORY_ROOT
    paths = {
        MODULE.DEFAULT_POLICY,
        *MODULE.GENERATED_TARGETS,
        Path("crates/ivm_abi/src/pointer_abi.rs"),
        Path("crates/iroha_primitives/src/numeric_abi.rs"),
    }
    policy = MODULE.load_policy(source)
    paths.add(policy.lexical_grammar)
    for relative in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


def _generated_body(text: str, prefix: str = "//") -> str:
    start = f"{prefix} BEGIN GENERATED: {MODULE.MARKER_NAME}"
    end = f"{prefix} END GENERATED: {MODULE.MARKER_NAME}"
    return text.split(start, 1)[1].split(end, 1)[0].strip()


def _marked_body(text: str, marker: str) -> str:
    return text.split(f"BEGIN GENERATED: {marker}", 1)[1].split(
        f"END GENERATED: {marker}", 1
    )[0]


def test_cli_rejects_repeated_modes_and_paths() -> None:
    options = MODULE.parse_args(
        [
            "--write",
            "--root",
            "/cache/repository",
            "--policy",
            "specs/kotodama_syntax_policy.json",
        ]
    )
    assert options.write
    assert options.root == Path("/cache/repository")

    for arguments in (
        ["--write", "--write"],
        ["--check", "--check"],
        ["--write", "--check"],
        ["--root", ""],
        ["--policy", ""],
        ["--root", "first", "--root", "second"],
        ["--policy", "first", "--policy", "second"],
        ["--root=--write"],
        ["--policy=-h"],
    ):
        with pytest.raises(SystemExit):
            MODULE.parse_args(arguments)


def test_policy_fixture_has_no_clock_or_provenance_fields() -> None:
    raw = json.loads(
        (MODULE.REPOSITORY_ROOT / MODULE.DEFAULT_POLICY).read_text(encoding="utf-8")
    )

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert keys(raw).isdisjoint(
        {"created_at", "generated_at", "timestamp", "updated_at", "provenance"}
    )


def test_final_policy_pins_quantity_without_an_abi_tombstone() -> None:
    policy = MODULE.load_policy(MODULE.REPOSITORY_ROOT)
    schemas = {schema.source_type: schema for schema in policy.numeric_schemas}
    dynamic_access = policy.dynamic_access_hints

    assert schemas["quantity"].rust_type == "Quantity"
    assert schemas["quantity"].pointer_id == 0x0010
    assert schemas["int"].pointer_id == 0x0011
    assert schemas["decimal"].pointer_id == 0x0012
    assert policy.unassigned_pointers == (0x000C, 0x0014)
    assert "quantity" in policy.active_source_types
    assert "Quantity" not in policy.active_source_types
    assert "Amount" in policy.retired_numeric_type_spellings
    assert policy.forbidden_source_identifiers == ("Amount",)
    assert "amount" in policy.ordinary_value_identifiers
    assert set(policy.forbidden_source_identifiers).isdisjoint(
        policy.ordinary_value_identifiers
    )
    assert policy.numeric_suffix_fixits == ("amt", "qty")
    assert {schema.source_type for schema in policy.numeric_schemas} == {
        "int",
        "decimal",
        "quantity",
    }
    assert dynamic_access.state_map_key_types == (
        "int",
        "decimal",
        "quantity",
        "bool",
        "string",
        "bytes",
        "DataSpaceId",
        "AccountId",
        "AssetDefinitionId",
        "AssetId",
        "NftId",
        "DomainId",
        "Name",
    )
    assert dynamic_access.bound_kinds == ("page", "take")
    assert dynamic_access.max_keys == 64
    assert dynamic_access.base_prefix == "state:"
    assert dynamic_access.base_identifier == "state_declaration_identifier"
    assert dynamic_access.base_reserved_prefixes == ("__kotodama_link_",)
    assert dynamic_access.requires_declared_state_map is True
    assert dynamic_access.scheduler_authoritative is False
    assert (
        policy.declaration_reserved_extras
        == MODULE.EXPECTED_DECLARATION_RESERVED_EXTRAS
    )
    assert {
        "Json",
        "AxtDescriptor",
        "AssetHandle",
        "ProofBlob",
        "SoracloudRequest",
        "SoracloudResponse",
    }.isdisjoint(dynamic_access.state_map_key_types)


def test_dynamic_access_policy_drift_fails_closed(tmp_path: Path) -> None:
    _copy_generator_inputs(tmp_path)
    policy_path = tmp_path / MODULE.DEFAULT_POLICY
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    raw["dynamic_access_hints"]["scheduler_authoritative"] = True
    policy_path.write_text(
        json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.GenerationError,
        match="must remain advisory",
    ):
        MODULE.load_policy(tmp_path)


def test_declaration_reserved_extras_drift_fails_closed(tmp_path: Path) -> None:
    _copy_generator_inputs(tmp_path)
    policy_path = tmp_path / MODULE.DEFAULT_POLICY
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    raw["declaration_reserved_extras"].remove("__kotodama_list_len")
    policy_path.write_text(
        json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.GenerationError,
        match="must exactly cover the compiler-owned V1 declaration vocabulary",
    ):
        MODULE.load_policy(tmp_path)


def test_forbidden_source_identifier_drift_fails_closed(tmp_path: Path) -> None:
    _copy_generator_inputs(tmp_path)
    policy_path = tmp_path / MODULE.DEFAULT_POLICY
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    raw["forbidden_source_identifiers"] = ["amount"]
    policy_path.write_text(
        json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        MODULE.GenerationError,
        match="must contain only exact uppercase Amount",
    ):
        MODULE.load_policy(tmp_path)


def test_dynamic_access_policy_is_generated_across_consumers_and_docs() -> None:
    root = MODULE.REPOSITORY_ROOT
    policy = MODULE.load_policy(root)
    grammar = MODULE.load_lexical_grammar(root, policy)
    semantic_policy = MODULE.render_semantic_policy(policy)
    assert "V1_DECLARATION_RESERVED_EXTRA_NAMES" in semantic_policy
    assert "pub const V1_FORBIDDEN_SOURCE_IDENTIFIERS" in semantic_policy
    assert "pub use" not in semantic_policy
    data_model_policy = MODULE.render_data_model_identifier_policy(policy)
    assert "const KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS" in data_model_policy
    assert "const KOTODAMA_V1_RESERVED_TYPE_DECLARATIONS" in data_model_policy
    for reserved_type in ("StatePage", "ListError", "Amount", "float"):
        assert f'"{reserved_type}"' in data_model_policy
    assert "pub const KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS" not in data_model_policy
    assert '&["Amount"]' in data_model_policy
    forbidden_table = data_model_policy.split("const KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS", 1)[1].split(";", 1)[0]
    assert '"amount"' not in forbidden_table
    for intrinsic in (
        "is_some",
        "is_none",
        "is_ok",
        "is_err",
        "unwrap_or",
        "unwrap_err_or",
        "expect",
    ):
        assert f'"{intrinsic}",' not in semantic_policy

    rust_policy = MODULE.render_ivm_abi_access_hint_policy(policy, grammar)
    assert "DYNAMIC_ACCESS_HINT_RESERVED_STATE_IDENTIFIERS_V1" in rust_policy
    assert "DYNAMIC_ACCESS_HINT_RESERVED_STATE_PREFIXES_V1" in rust_policy
    assert '"state",' in rust_policy
    assert '"int",' in rust_policy
    for intrinsic in (
        "is_some",
        "is_none",
        "is_ok",
        "is_err",
        "unwrap_or",
        "unwrap_err_or",
        "expect",
    ):
        assert f'"{intrinsic}",' not in rust_policy
    assert '"__kotodama_link_"' in rust_policy
    assert '"Amount",' not in rust_policy
    assert '"amount",' not in rust_policy
    assert '"誓約",' not in rust_policy

    validator_paths = (
        *MODULE.JAVASCRIPT_IDENTIFIER_PATHS,
        MODULE.PYTHON_MANIFEST_PATH,
        MODULE.KOTLIN_MANIFEST_PATH,
        MODULE.SWIFT_MANIFEST_PATH,
        MODULE.CSHARP_MANIFEST_PATH,
    )
    for path in validator_paths:
        body = _marked_body(
            (root / path).read_text(encoding="utf-8"),
            MODULE.VALIDATOR_MARKER_NAME,
        )
        assert "page" in body
        assert "take" in body
        assert "64" in body
        assert "DataSpaceId" in body
        assert "Name" in body

    typescript = _marked_body(
        (root / MODULE.TYPESCRIPT_PATH).read_text(encoding="utf-8"),
        "kotodama-v1-dynamic-access-policy",
    )
    assert "KOTODAMA_V1_STATE_MAP_KEY_TYPES" in typescript
    assert "KOTODAMA_V1_DYNAMIC_ACCESS_BOUND_KINDS" in typescript
    assert "KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS: 64" in typescript

    docs = (root / MODULE.GRAMMAR_DOC_PATH).read_text(encoding="utf-8")
    assert "| Dynamic-access bound kinds (ordered) | `page`, `take` |" in docs
    assert "| Dynamic-access key bound | `1..=64` |" in docs
    assert (
        "One direct declared top-level `StateMap`, encoded as "
        "`state:<state_declaration_identifier>`"
    ) in docs
    assert "Advisory only; never authorization or scheduler-authoritative evidence" in docs


def test_repository_generated_outputs_are_current_and_complete() -> None:
    policy = MODULE.load_policy(MODULE.REPOSITORY_ROOT)
    outputs = MODULE.render_outputs(MODULE.REPOSITORY_ROOT, policy)

    assert tuple(outputs) == MODULE.GENERATED_TARGETS
    assert len(outputs) == 17
    assert MODULE.apply_outputs(MODULE.REPOSITORY_ROOT, outputs, check=True) == 0


def test_javascript_runtime_and_declaration_policy_are_generated_from_one_mapping() -> (
    None
):
    root = MODULE.REPOSITORY_ROOT
    source_body = _generated_body(
        (root / MODULE.JAVASCRIPT_PATHS[0]).read_text(encoding="utf-8")
    )
    declarations = _generated_body(
        (root / MODULE.TYPESCRIPT_PATH).read_text(encoding="utf-8")
    )

    assert "pointerType: 0x0010" in source_body
    assert "readonly pointerType: 0x0010" in declarations
    assert "NUMERIC_V1_MAX_ASSIGNED_POINTER_TYPE = 0x0013" in source_body
    assert "0x0014" not in source_body
    assert "Amount" not in source_body


def test_textmate_policy_marks_only_attached_amt_and_qty_suffixes() -> None:
    grammar = json.loads(
        (MODULE.REPOSITORY_ROOT / MODULE.TEXTMATE_PATH).read_text(encoding="utf-8")
    )
    pattern = grammar["repository"]["retiredNumericSuffixes"]["patterns"][0]
    includes = [
        item.get("include") for item in grammar["patterns"] if isinstance(item, dict)
    ]

    assert includes.count("#retiredNumericSuffixes") == 1
    assert pattern["name"] == "invalid.deprecated.numeric.suffix.kotodama"
    assert "amt|qty" in pattern["match"]
    assert "amount" not in pattern["match"]
    assert "Amount" not in grammar["repository"]["types"]["patterns"][0]["match"]


def test_textmate_keywords_are_scoped_by_role_with_one_scope_per_branded_pair() -> None:
    policy = MODULE.load_policy(MODULE.REPOSITORY_ROOT)
    grammar = MODULE.load_lexical_grammar(MODULE.REPOSITORY_ROOT, policy)
    scopes = {}
    for match, scope in MODULE._keyword_patterns(grammar):
        body = match.split("(?:", 1)[1].rsplit(")(?!", 1)[0]
        for keyword in body.split("|"):
            assert keyword not in scopes, keyword
            scopes[keyword] = scope

    assert sorted(scopes) == sorted(value for value, _ in grammar.keywords)
    for romaji, kanji in (
        ("seiyaku", "誓約"),
        ("kotoage", "言挙げ"),
        ("hajimari", "始まり"),
        ("kaizen", "改善"),
    ):
        assert scopes[romaji] == scopes[kanji]
    assert scopes["true"] == scopes["false"] == "constant.language.boolean.kotodama"
    assert scopes["let"] == "storage.type.kotodama"
    assert scopes["return"] == "keyword.control.kotodama"


def test_textmate_punctuation_is_never_an_operator_and_double_colon_wins() -> None:
    policy = MODULE.load_policy(MODULE.REPOSITORY_ROOT)
    grammar = MODULE.load_lexical_grammar(MODULE.REPOSITORY_ROOT, policy)
    patterns = MODULE._operator_patterns(grammar)

    assert patterns[0][1] == "keyword.operator.kotodama"
    operators = patterns[0][0]
    for punctuation in ("\\{", "\\}", "\\(", "\\)", ";", ","):
        assert f"|{punctuation}|" not in f"|{operators[3:-1]}|"
    scopes = [scope for _, scope in patterns]
    assert scopes.index("punctuation.separator.namespace.kotodama") < scopes.index(
        "punctuation.separator.colon.kotodama"
    )


def test_check_detects_drift_write_repairs_it_and_second_check_is_clean(
    tmp_path: Path,
) -> None:
    _copy_generator_inputs(tmp_path)
    docs = tmp_path / MODULE.GRAMMAR_DOC_PATH
    docs.write_text(
        docs.read_text(encoding="utf-8").replace(
            "| `authorize` | `Authorize` |",
            "| `authorize` | `Broken` |",
            1,
        ),
        encoding="utf-8",
    )

    policy = MODULE.load_policy(tmp_path)
    outputs = MODULE.render_outputs(tmp_path, policy)
    assert MODULE.apply_outputs(tmp_path, outputs, check=True) == 1
    assert MODULE.apply_outputs(tmp_path, outputs, check=False) == 1

    second = MODULE.render_outputs(tmp_path, policy)
    assert MODULE.apply_outputs(tmp_path, second, check=True) == 0


def test_missing_or_duplicate_markers_fail_closed() -> None:
    with pytest.raises(MODULE.GenerationError, match="exactly one marker"):
        MODULE._replace_generated(
            "plain text",
            "BEGIN",
            "END",
            "body",
            path=Path("missing.txt"),
        )
    with pytest.raises(MODULE.GenerationError, match="exactly one marker"):
        MODULE._replace_generated(
            "BEGIN\nold\nEND\nBEGIN\nold\nEND\n",
            "BEGIN",
            "END",
            "body",
            path=Path("duplicate.txt"),
        )
    with pytest.raises(MODULE.GenerationError, match="precedes"):
        MODULE._replace_generated(
            "END\nold\nBEGIN\n",
            "BEGIN",
            "END",
            "body",
            path=Path("reversed.txt"),
        )


def test_sdk_validator_policy_forbids_exact_amount_globally() -> None:
    root = MODULE.REPOSITORY_ROOT
    policy = MODULE.load_policy(root)
    grammar = MODULE.load_lexical_grammar(root, policy)
    assert policy.forbidden_source_identifiers == ("Amount",)
    assert "amount" in policy.retired_numeric_type_spellings
    assert "amount" in policy.ordinary_value_identifiers
    assert "Amount" not in MODULE._declaration_names(policy)

    javascript = MODULE._javascript_validator_policy(policy, grammar)
    assert "const FORBIDDEN_SOURCE_IDENTIFIER_SET" in javascript
    assert "export const KOTODAMA_V1_FORBIDDEN_SOURCE_IDENTIFIERS" not in javascript
    assert '"Amount",' in javascript
    assert "KOTODAMA_V1_RETIRED_TYPE_NAMES" in javascript
    assert "NUMERIC_TYPE_KEYWORD_SET" not in javascript
    public_declarations = javascript.split(
        "export const KOTODAMA_V1_DECLARATION_RESERVED = Object.freeze([",
        1,
    )[1].split("]);", 1)[0]
    assert '"Amount",' not in public_declarations

    python = MODULE._python_validator_policy(policy, grammar)
    for spelling in policy.retired_numeric_type_spellings:
        assert f'"{spelling}",' in python
    assert '"Amount",' in python
    assert '"amount",' in python

    for rendered in (
        MODULE._kotlin_validator_policy(policy, grammar),
        MODULE._swift_validator_policy(policy, grammar),
        MODULE._csharp_validator_policy(policy, grammar),
    ):
        assert '"Amount",' in rendered
        assert '"amount",' in rendered
