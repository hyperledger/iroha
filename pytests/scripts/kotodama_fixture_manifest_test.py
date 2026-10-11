"""Tests for the sealed current Kotodama compiler test-source inventory."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_kotodama_test_sources.py"
MANIFEST = ROOT / "crates" / "kotodama_lang" / "kotodama_fixtures_v1.manifest.json"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_kotodama_test_sources", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


def _copy_fixture_tree(destination: Path) -> Path:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    relative_manifest = MANIFEST.relative_to(ROOT)
    copied_manifest = destination / relative_manifest
    copied_manifest.parent.mkdir(parents=True)
    shutil.copy2(MANIFEST, copied_manifest)
    for source in payload["source_files"]:
        source_path = ROOT / source["path"]
        copied_source = destination / source["path"]
        copied_source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, copied_source)
    for test_source in checker.OUT_OF_LINE_TEST_SOURCES.values():
        copied_source = destination / test_source
        copied_source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / test_source, copied_source)
    for source_path, includes in checker.EXPECTED_TEST_INCLUDES.items():
        source_parent = Path(source_path).parent
        for include in includes:
            included_source = source_parent / include
            copied_source = destination / included_source
            copied_source.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / included_source, copied_source)
    for modules in checker.EXPECTED_TEST_MODULES.values():
        for _, source_path in modules:
            copied_source = destination / source_path
            copied_source.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / source_path, copied_source)
    for fixture in payload["fixtures"]:
        asset = ROOT / fixture["asset"]
        copied_asset = destination / fixture["asset"]
        copied_asset.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(asset, copied_asset)
    return copied_manifest


def test_checked_in_inventory_seals_current_consumers() -> None:
    stats = checker.validate_manifest(ROOT, MANIFEST)
    assert stats.fixtures == 316
    assert stats.tests == 677


def test_corrupt_fixture_inventory_digest_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    payload["fixtures_sha256"] = "0" * 64
    copied_manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(checker.ValidationError, match="fixtures_sha256 does not authenticate"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_child_modules_seal_literal_and_canonical_pool_consumers() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    compiler = payload["source_files"][0]
    assert compiler["test_modules"] == [
        list(module) for module in checker.EXPECTED_TEST_MODULES[compiler["path"]]
    ]
    literal = next(
        fixture for fixture in payload["fixtures"]
        if fixture["asset"].endswith("/literal_homes.ko")
    )
    assert literal["owner_function"] == "rematerialized_literals_reduce_emitted_memory_traffic_and_authenticated_frames"
    assert literal["owner_is_test"] is True
    for asset, owners in checker.SHARED_EXTERNAL_FIXTURE_OWNERS.items():
        observed = [fixture for fixture in payload["fixtures"] if fixture["asset"] == asset]
        assert len(observed) == len(owners)
        assert {
            (fixture["owner_source"], fixture["owner_function"], fixture["owner_is_test"])
            for fixture in observed
        } == owners
        assert len({fixture["content_sha256"] for fixture in observed}) == 1


@pytest.mark.parametrize("mutation", ["missing", "wrong-path", "unsealed", "multiline", "tab", "spaced-semicolon", "raw"])
def test_child_module_declaration_drift_fails_closed(tmp_path: Path, mutation: str) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    parent = tmp_path / checker.OUT_OF_LINE_TEST_SOURCES[checker.EXPECTED_SOURCES[0]]
    declaration = '#[path = "tests/literal_helpers.rs"]\nmod literal_helpers;'
    source = parent.read_text(encoding="utf-8")
    if mutation == "missing":
        source = source.replace(declaration, "")
    elif mutation == "wrong-path":
        source = source.replace('"tests/literal_helpers.rs"', '"tests/unreviewed.rs"')
    else:
        declaration = {
            "unsealed": "mod unreviewed;",
            "multiline": "mod\n unreviewed;",
            "tab": "mod\tunreviewed;",
            "spaced-semicolon": "mod unreviewed ;",
            "raw": "mod r#unreviewed;",
        }[mutation]
        source += f"\n{declaration}\n"
    parent.write_text(source, encoding="utf-8")
    with pytest.raises(checker.ValidationError, match="test module (inventory|declaration) changed"):
        checker.validate_manifest(tmp_path, copied_manifest)


@pytest.mark.parametrize(
    "declaration",
    ["mod unreviewed;", "mod\n unreviewed;", "mod\tunreviewed;", "mod unreviewed ;", "mod r#unreviewed;"],
)
def test_child_module_cannot_add_out_of_line_children(tmp_path: Path, declaration: str) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    child_path = checker.EXPECTED_TEST_MODULES[checker.EXPECTED_SOURCES[0]][0][1]
    child = tmp_path / child_path
    child.write_text(child.read_text(encoding="utf-8") + f"\n{declaration}\n", encoding="utf-8")
    with pytest.raises(checker.ValidationError, match="test module nesting is not sealed"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_child_module_file_is_required(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    child = checker.EXPECTED_TEST_MODULES[checker.EXPECTED_SOURCES[0]][0][1]
    (tmp_path / child).unlink()
    with pytest.raises(FileNotFoundError):
        checker.validate_manifest(tmp_path, copied_manifest)


@pytest.mark.parametrize("mutation", ["owner", "duplicate"])
def test_shared_pool_fixture_requires_each_exact_test_consumer(tmp_path: Path, mutation: str) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    child = tmp_path / dict(checker.EXPECTED_TEST_MODULES[checker.EXPECTED_SOURCES[0]])["rematerialized"]
    source = child.read_text(encoding="utf-8")
    if mutation == "owner":
        source = source.replace(
            "fn canonical_dlmm_rematerialization_measures_same_compiler_artifacts_and_metadata()",
            "fn unreviewed_pool_consumer()",
        )
    else:
        include = 'include_str!("../../../../iroha_core/src/validation_fee/fixtures/dlmm_pool.ko")'
        source = source.replace(include, f"{{ let _ = {include}; {include} }}")
    child.write_text(source, encoding="utf-8")
    with pytest.raises(checker.ValidationError, match="shared fixture consumer changed"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_out_of_line_test_module_is_required(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    test_source = next(iter(checker.OUT_OF_LINE_TEST_SOURCES.values()))
    (tmp_path / test_source).unlink()
    with pytest.raises(FileNotFoundError):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_out_of_line_test_inventory_drift_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    test_source = next(iter(checker.OUT_OF_LINE_TEST_SOURCES.values()))
    source = tmp_path / test_source
    with source.open("a", encoding="utf-8") as output:
        output.write("\n#[test]\nfn unexpected_out_of_line_test() {}\n")
    with pytest.raises(checker.ValidationError, match="test name/order inventory changed"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_payload_corruption_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    asset = tmp_path / payload["fixtures"][0]["asset"]
    asset.write_bytes(asset.read_bytes() + b"\n")

    with pytest.raises(checker.ValidationError, match="byte length changed"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_unknown_manifest_key_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    copied_manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(checker.ValidationError, match="unknown=.*unexpected"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_included_test_inventory_drift_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    included_source = (
        tmp_path
        / "crates/kotodama_lang/src/compiler/tests/staged_mint_access_hints.rs"
    )
    source = included_source.read_text(encoding="utf-8")
    assert "fn staged_mint_helper_keeps_state_map_base_literals_after_call_propagation()" in source
    included_source.write_text(
        source.replace(
            "fn staged_mint_helper_keeps_state_map_base_literals_after_call_propagation()",
            "fn changed_staged_mint_test_name()",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        checker.ValidationError, match="test name/order inventory changed"
    ):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_trigger_semantics_include_inventory_drift_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    included_source = (
        tmp_path / "crates/kotodama_lang/src/semantic/tests/trigger_semantics_tests.rs"
    )
    source = included_source.read_text(encoding="utf-8")
    included_source.write_text(
        source.replace(
            "fn trigger_decl_builds_typed_metadata()",
            "fn changed_trigger_semantics_test_name()",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        checker.ValidationError, match="test name/order inventory changed"
    ):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_trigger_semantics_fixture_inventory_drift_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    included_source = (
        tmp_path / "crates/kotodama_lang/src/semantic/tests/trigger_semantics_tests.rs"
    )
    source = included_source.read_text(encoding="utf-8")
    included_source.write_text(
        source.replace(
            "../test_sources/trigger_decl_supports_data_filter_1.ko",
            "../test_sources/trigger_decl_supports_data_filter_changed.ko",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        checker.ValidationError,
        match="fixture is missing",
    ):
        checker.validate_manifest(tmp_path, copied_manifest)


@pytest.mark.parametrize(
    "retired_key, value",
    [
        ("retained_templates", []),
        ("retained_templates_sha256", "0" * 64),
        ("origin_merge", "0" * 40),
    ],
)
def test_retired_template_migration_seal_is_rejected(
    tmp_path: Path, retired_key: str, value: object
) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    payload[retired_key] = value
    copied_manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(checker.ValidationError, match=f"unknown=.*{retired_key}"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_named_payload_corruption_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    fixture = next(
        entry for entry in payload["fixtures"] if "/test_sources/" in entry["asset"]
    )
    asset = tmp_path / fixture["asset"]
    asset.write_bytes(asset.read_bytes() + b"\n")

    with pytest.raises(checker.ValidationError, match="byte length changed"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_named_payload_omission_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    fixture = next(
        entry for entry in payload["fixtures"] if "/test_sources/" in entry["asset"]
    )
    asset = tmp_path / fixture["asset"]
    asset.unlink()

    with pytest.raises(checker.ValidationError, match="fixture is missing"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_repository_paths_cannot_escape_the_root() -> None:
    with pytest.raises(checker.ValidationError, match="repository-relative"):
        checker._relative_path("../escape.ko", "test.path")


def test_child_include_paths_cannot_escape_the_root() -> None:
    with pytest.raises(checker.ValidationError, match="escapes the repository"):
        checker._resolved_include_path(
            "crates/kotodama_lang/src/semantic/tests/child.rs",
            "../../../../../../escape.ko",
            "test include",
        )


def test_named_macro_cases_and_external_samples_have_exact_owners() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    fixtures = {entry["asset"]: entry for entry in payload["fixtures"]}
    for suffix in ("1", "2"):
        entry = fixtures[
            "crates/kotodama_lang/src/semantic/test_sources/"
            f"trigger_metadata_json_parse_uses_json_literal_diagnostics_{suffix}.ko"
        ]
        assert (
            entry["owner_function"]
            == "trigger_metadata_json_parse_uses_json_literal_diagnostics"
        )
        assert entry["owner_source"].endswith(
            "semantic/tests/trigger_semantics_tests.rs"
        )
        assert entry["owner_is_test"] is True
    assert (
        set(checker.EXPECTED_EXTERNAL_FIXTURES[checker.EXPECTED_SOURCES[0]])
        <= fixtures.keys()
    )


@pytest.mark.parametrize(
    "field", ["raw_hashes", "raw_literal_sha256", "source_line_before_migration"]
)
def test_historical_raw_literal_fields_are_rejected(tmp_path: Path, field: str) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    payload["fixtures"][0][field] = 1
    copied_manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(checker.ValidationError, match=f"unknown=.*{field}"):
        checker.validate_manifest(tmp_path, copied_manifest)


@pytest.mark.parametrize(
    "field,value", [("owner_function", "different_owner"), ("ordinal", 2)]
)
def test_resealed_fixture_cannot_forge_its_current_owner(
    tmp_path: Path, field: str, value: object
) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    payload["fixtures"][0][field] = value
    payload["fixtures_sha256"] = checker._digest_json(payload["fixtures"])
    copied_manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        checker.ValidationError,
        match="fixture (function ownership|include ordinal) changed",
    ):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_manifest_omission_cannot_hide_a_referenced_fixture(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    payload["fixtures"].pop()
    payload["fixtures_sha256"] = checker._digest_json(payload["fixtures"])
    copied_manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        checker.ValidationError, match="fixture include inventory differs"
    ):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_duplicate_fixture_include_fails_closed(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    fixture = next(
        fixture for fixture in payload["fixtures"]
        if fixture["asset"] not in checker.SHARED_EXTERNAL_FIXTURE_OWNERS
    )
    owner = tmp_path / fixture["owner_source"]
    with owner.open("a", encoding="utf-8") as source:
        source.write(
            '\nfn duplicated_fixture() { let _ = include_str!("'
            + fixture["include_path"]
            + '"); }\n'
        )
    with pytest.raises(checker.ValidationError, match="duplicate fixture include"):
        checker.validate_manifest(tmp_path, copied_manifest)


def test_commented_out_includes_do_not_create_consumers(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    owner = tmp_path / checker.EXPECTED_SOURCES[0]
    with owner.open("a", encoding="utf-8") as source:
        source.write('\n// include_str!("../../../../outside.ko");\n')
    checker.validate_manifest(tmp_path, copied_manifest)


def test_write_reseals_intentional_changes_and_is_idempotent(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    original = copied_manifest.read_bytes()
    checker.write_manifest(tmp_path, copied_manifest)
    assert copied_manifest.read_bytes() == original
    payload = json.loads(original)
    asset = tmp_path / payload["fixtures"][0]["asset"]
    asset.write_bytes(asset.read_bytes() + b"// intended fixture update\n")
    with pytest.raises(checker.ValidationError, match="byte length changed"):
        checker.validate_manifest(tmp_path, copied_manifest)
    checker.write_manifest(tmp_path, copied_manifest)
    assert copied_manifest.read_bytes() != original
    checker.validate_manifest(tmp_path, copied_manifest)


def test_write_refuses_unreferenced_assets_without_changing_manifest(
    tmp_path: Path,
) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    original = copied_manifest.read_bytes()
    directory = checker.EXPECTED_FIXTURE_DIRECTORIES[checker.EXPECTED_SOURCES[0]][0]
    (tmp_path / directory / "unreferenced.ko").write_text(
        "fn unused() {}\n", encoding="utf-8"
    )
    with pytest.raises(
        checker.ValidationError, match="fixture directory membership changed"
    ):
        checker.write_manifest(tmp_path, copied_manifest)
    assert copied_manifest.read_bytes() == original


def test_symlink_fixture_is_not_a_regular_owned_asset(tmp_path: Path) -> None:
    copied_manifest = _copy_fixture_tree(tmp_path)
    payload = json.loads(copied_manifest.read_text(encoding="utf-8"))
    asset = tmp_path / payload["fixtures"][0]["asset"]
    other = asset.with_suffix(".saved")
    asset.rename(other)
    asset.symlink_to(other.name)
    with pytest.raises(checker.ValidationError, match="not a regular file"):
        checker.validate_manifest(tmp_path, copied_manifest)
