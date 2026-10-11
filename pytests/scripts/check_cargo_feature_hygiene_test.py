"""Tests for the Cargo feature-ownership guard."""

from __future__ import annotations

import copy
import importlib.util
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "check_cargo_feature_hygiene.py"
SPEC = importlib.util.spec_from_file_location("check_cargo_feature_hygiene", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
FEATURE_HYGIENE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FEATURE_HYGIENE)


def test_repository_feature_hygiene() -> None:
    assert FEATURE_HYGIENE.check_repository(ROOT) == []


def _manifest_path(package: str) -> Path:
    split_packages = {
        "iroha_cli_lib": "iroha_cli", "iroha_cli": "iroha_cli/bins",
        "irohad_lib": "irohad", "irohad": "irohad/bins",
    }
    return ROOT / "crates" / split_packages.get(package, package) / "Cargo.toml"


def _guarded_document(package: str) -> dict:
    return FEATURE_HYGIENE._load_toml(_manifest_path(package))


def _guarded_errors(package: str, document: dict) -> list[str]:
    return FEATURE_HYGIENE._check_expected_features(document, _manifest_path(package))


def test_model_json_dependencies_are_unconditional_and_reject_owner_removal() -> None:
    document = _guarded_document("iroha_data_model")
    assert _guarded_errors("iroha_data_model", document) == []
    for name in FEATURE_HYGIENE.MANDATORY_MODEL_JSON_DEPENDENCIES:
        for mutation in ("remove", "optional"):
            changed = copy.deepcopy(document)
            if mutation == "remove":
                del changed["dependencies"][name]
            else:
                changed["dependencies"][name]["optional"] = True
            assert changed != document
            errors = _guarded_errors("iroha_data_model", changed)
            assert any(
                f"mandatory model JSON dependency `{name}` must be a non-optional normal dependency"
                in error
                for error in errors
            ), (name, mutation, errors)


def test_model_json_dependencies_reject_disabled_protocol_features() -> None:
    document = _guarded_document("iroha_data_model")
    assert _guarded_errors("iroha_data_model", document) == []
    for name, required in FEATURE_HYGIENE.MANDATORY_MODEL_JSON_DEPENDENCIES.items():
        for feature in required:
            changed = copy.deepcopy(document)
            changed["dependencies"][name]["features"].remove(feature)
            assert changed != document
            errors = _guarded_errors("iroha_data_model", changed)
            assert any(
                f"mandatory model JSON dependency `{name}` must select {list(required)!r} unconditionally"
                in error
                for error in errors
            ), (name, feature, errors)


def test_model_json_feature_cannot_return_as_an_empty_alias() -> None:
    document = _guarded_document("iroha_data_model")
    assert _guarded_errors("iroha_data_model", document) == []
    changed = copy.deepcopy(document)
    changed["features"]["json"] = []
    assert changed != document
    assert any(
        "Cargo feature `json` is unclassified" in error
        for error in _guarded_errors("iroha_data_model", changed)
    )


def test_retired_kagemusha_switches_cannot_return_as_empty_aliases() -> None:
    for package, retired in (
        ("iroha", "kagemusha-ordinary-native"),
        ("iroha_core_zk", "kagemusha-production-prover"),
        ("iroha_core_zk", "kagemusha-real-proof-harness"),
    ):
        document = _guarded_document(package)
        assert retired not in document["features"]
        changed = copy.deepcopy(document)
        changed["features"][retired] = []
        assert any(f"Cargo feature `{retired}` is unclassified" in error for error in _guarded_errors(package, changed))


def test_production_exports_have_no_feature_opt_out() -> None:
    core = ROOT / "crates/iroha_core_zk/src"
    for source in core.rglob("*.rs"):
        assert 'feature = "kagemusha-production-prover"' not in source.read_text(), source
    core_entry = (core / "lib.rs").read_text()
    assert 'pub mod kagemusha_wallet_advance_v1;' in core_entry
    assert 'pub mod kagemusha_v1_recursion;' not in core_entry
    assert not (core / "kagemusha_v1_recursion").exists()
    assert 'mod kagemusha_v1_state;' not in core_entry
    assert not (core / "kagemusha_v1_state").exists()


def test_client_has_no_ordinary_native_surface() -> None:
    client = (ROOT / "crates/iroha/src/client.rs").read_text()
    assert "mod ordinary_native;" not in client
    assert "pub use ordinary_native::" not in client
    document = _guarded_document("iroha")
    assert _guarded_errors("iroha", document) == []
    assert "iroha_core_zk" not in document["dependencies"]
    assert "dev-tools" not in document["features"]
    assert "bin" not in document


NATIVE_CORE_OWNERS = (
    ("iroha_core", "kaigi_zk"),
    ("iroha_core_zk", "kaigi_zk"),
    ("iroha_core_zk", "iroha_plonk"),
    ("iroha_core_zk", "iroha_plonk_gadgets"),
    ("iroha_core_zk", "iroha_pasta"),
)


@pytest.mark.parametrize("package,owner", NATIVE_CORE_OWNERS)
def test_native_core_owner_is_mandatory_with_defaults_disabled(
    package: str, owner: str
) -> None:
    """Native backend ownership is independent of Cargo feature selection."""
    document = _guarded_document(package)
    assert _guarded_errors(package, document) == []
    assert document["dependencies"][owner].get("optional", False) is False
    changed = copy.deepcopy(document)
    changed["features"]["default"] = []
    owners = FEATURE_HYGIENE.MANDATORY_CORE_BACKENDS[package]
    assert owner in owners
    assert FEATURE_HYGIENE._check_mandatory_core_backends(
        changed, _manifest_path(package), owners
    ) == []


@pytest.mark.parametrize("package,owner", NATIVE_CORE_OWNERS)
@pytest.mark.parametrize(
    "mutation",
    ["remove", "optional", "dev-only", "build-only", "foreign-path", "foreign-package"],
)
def test_native_core_owner_rejects_optional_or_replaced_dependencies(
    package: str, owner: str, mutation: str
) -> None:
    """Every native backend must retain its canonical normal dependency."""
    document = _guarded_document(package)
    changed = copy.deepcopy(document)
    if mutation == "remove":
        del changed["dependencies"][owner]
    elif mutation == "optional":
        changed["dependencies"][owner]["optional"] = True
    elif mutation in ("dev-only", "build-only"):
        section = "dev-dependencies" if mutation == "dev-only" else "build-dependencies"
        changed.setdefault(section, {})[owner] = changed["dependencies"].pop(owner)
    elif mutation == "foreign-path":
        changed["dependencies"][owner]["path"] = "../unreviewed-owner"
    else:
        changed["dependencies"][owner]["package"] = "foreign_backend"
    assert changed != document
    assert any(
        f"mandatory Core backend `{owner}` must retain its non-optional local owner"
        in error
        for error in _guarded_errors(package, changed)
    ), (package, owner, mutation)


@pytest.mark.parametrize("package,owner", NATIVE_CORE_OWNERS)
def test_native_core_owner_accepts_explicit_canonical_package(
    package: str, owner: str
) -> None:
    document = copy.deepcopy(_guarded_document(package))
    document["dependencies"][owner]["package"] = owner
    assert _guarded_errors(package, document) == []


@pytest.mark.parametrize("feature", ["zk-halo2", "zk-halo2-ipa"])
@pytest.mark.parametrize("members", [[], ["dep:kaigi_zk"], ["zk-ipa-native"]])
def test_retired_node_backend_features_cannot_return(
    feature: str, members: list[str]
) -> None:
    """Retired backend aliases and dependency forwarders are prohibited."""
    document = _guarded_document("iroha_core")
    assert feature not in document["features"]
    changed = copy.deepcopy(document)
    changed["features"][feature] = members
    assert any(
        f"Cargo feature `{feature}` is unclassified" in error
        for error in _guarded_errors("iroha_core", changed)
    )


def test_core_backend_switches_cannot_return_or_remove_no_default_symbols() -> None:
    document = _guarded_document("iroha_core_zk")
    retired = ("proofs-halo2", "zk-halo2", "zk-halo2-ipa", "zk-ipa-native", "circuit-params")
    for name in retired:
        assert name not in document["features"]
        changed = copy.deepcopy(document)
        changed["features"][name] = []
        assert any(f"Cargo feature `{name}` is unclassified" in error for error in _guarded_errors("iroha_core_zk", changed)), name
    core = ROOT / "crates/iroha_core_zk/src"
    for source in core.rglob("*.rs"):
        for name in retired:
            assert f'feature = "{name}"' not in source.read_text(), (source, name)
    provider = (core / "kagemusha_wallet_advance_v1.rs").read_text()
    assert "KagemushaWalletProviderV1" in provider
    assert not (core / "kagemusha_v1_test_fixtures.rs").exists()


def test_stark_owns_optional_fastpq_dependency_and_rejects_mutations() -> None:
    """Native PIPA-R callers avoid FASTPQ while STARK retains its exact shared field codec."""

    package = "iroha_core_zk"
    document = _guarded_document(package)
    assert _guarded_errors(package, document) == []
    assert document["dependencies"]["fastpq_prover"]["optional"] is True
    assert FEATURE_HYGIENE.EXPECTED_FEATURES[package]["zk-stark"] == ("dep:fastpq_prover",)
    assert "fastpq_prover" not in FEATURE_HYGIENE.cargo_visible_features(document)
    for mutation in ("remove", "unconditional"):
        changed = copy.deepcopy(document)
        if mutation == "remove":
            del changed["dependencies"]["fastpq_prover"]
        else:
            changed["dependencies"]["fastpq_prover"]["optional"] = False
        assert any(
            "STARK field dependency `fastpq_prover` must be an optional normal dependency"
            in error
            for error in _guarded_errors(package, changed)
        ), mutation
    for members in ([], ["fastpq_prover"], ["fastpq_prover?/default"]):
        changed = copy.deepcopy(document)
        changed["features"]["zk-stark"] = members
        assert any(
            "feature `zk-stark` must be ['dep:fastpq_prover']" in error
            for error in _guarded_errors(package, changed)
        ), members


def test_rejects_unclassified_explicit_feature_omitted_from_default() -> None:
    document = copy.deepcopy(_guarded_document("iroha_core"))
    document["features"]["new-portable-production-capability"] = []

    errors = _guarded_errors("iroha_core", document)

    assert any(
        "Cargo feature `new-portable-production-capability` is unclassified" in error
        for error in errors
    )


def test_rejects_removed_algebraic_ipa_feature() -> None:
    for package in ("iroha_zkp_halo2", "ivm", "iroha_core", "iroha_torii"):
        document = copy.deepcopy(_guarded_document(package))
        document["features"]["goldilocks_backend"] = []
        assert any(
            "Cargo feature `goldilocks_backend` is unclassified" in error
            for error in _guarded_errors(package, document)
        ), package


def test_rejects_unclassified_implicit_optional_dependency_feature() -> None:
    document = copy.deepcopy(_guarded_document("iroha_core"))
    document["dependencies"]["new_optional_backend"] = {
        "version": "1",
        "optional": True,
    }

    errors = _guarded_errors("iroha_core", document)

    assert any(
        "Cargo feature `new_optional_backend` is unclassified" in error
        for error in errors
    )


def test_non_weak_optional_dependency_forward_activates_implicit_feature() -> None:
    document = {
        "features": {"default": ["backend/accelerated"]},
        "dependencies": {"backend": {"version": "1", "optional": True}},
    }
    features = FEATURE_HYGIENE.cargo_visible_features(document)

    assert FEATURE_HYGIENE.local_default_feature_closure(features) == frozenset(
        {"default", "backend"}
    )

    document["features"]["default"] = ["backend?/accelerated"]
    weak_features = FEATURE_HYGIENE.cargo_visible_features(document)
    assert FEATURE_HYGIENE.local_default_feature_closure(
        weak_features
    ) == frozenset({"default"})


def test_rejects_broken_portable_default_closure() -> None:
    document = copy.deepcopy(_guarded_document("iroha_core"))
    document["features"]["default"].remove("simd")

    errors = _guarded_errors("iroha_core", document)

    assert any(
        "portable feature `simd` is not reachable from `default`" in error
        for error in errors
    )


def test_rejects_exact_portable_forwarder_mutation() -> None:
    document = copy.deepcopy(_guarded_document("iroha_core"))
    document["features"]["gost"] = []

    errors = _guarded_errors("iroha_core", document)

    assert any("feature `gost` must be" in error for error in errors)


def test_rejects_unpinned_contextual_shipping_forwarder(monkeypatch) -> None:
    monkeypatch.delitem(
        FEATURE_HYGIENE.EXPECTED_FEATURES["iroha_data_model"],
        "transparent_api",
    )

    errors = _guarded_errors(
        "iroha_data_model", _guarded_document("iroha_data_model")
    )

    assert any(
        "contextual shipping feature `transparent_api` lacks an exact feature pin"
        in error
        for error in errors
    )


def test_rejects_contextual_shipping_forwarder_mutation() -> None:
    document = copy.deepcopy(_guarded_document("iroha_data_model"))
    document["features"]["transparent_api"] = []

    errors = _guarded_errors("iroha_data_model", document)

    assert any("feature `transparent_api` must be" in error for error in errors)


def test_rejects_contextual_shipping_feature_reachable_from_default() -> None:
    document = copy.deepcopy(_guarded_document("iroha_data_model"))
    document["features"]["default"].append("transparent_api")

    errors = _guarded_errors("iroha_data_model", document)

    assert any(
        "contextual shipping feature `transparent_api` is reachable from local "
        "`default`" in error
        for error in errors
    )


def test_rejects_explicit_opt_in_reachable_from_default() -> None:
    for feature in ("quic", "mutation-testing"):
        document = copy.deepcopy(_guarded_document("iroha_core"))
        document["features"]["default"].append(feature)

        errors = _guarded_errors("iroha_core", document)

        assert any(
            f"explicit opt-in feature `{feature}` is reachable from `default`" in error
            for error in errors
        ), errors


def test_rejects_stale_explicit_opt_in_name(monkeypatch) -> None:
    current = FEATURE_HYGIENE.EXPLICIT_OPT_IN_FEATURES["iroha_core"]
    monkeypatch.setitem(
        FEATURE_HYGIENE.EXPLICIT_OPT_IN_FEATURES,
        "iroha_core",
        tuple(sorted((*current, "retired-opt-in"))),
    )

    errors = _guarded_errors("iroha_core", _guarded_document("iroha_core"))

    assert any(
        "stale explicit opt-in feature `retired-opt-in`" in error for error in errors
    )


@pytest.mark.parametrize("members", [[], ["dep:pprof"], ["dep:bytes"], ["pprof", "dep:bytes"]])
def test_torii_profiling_retains_both_explicit_dependency_owners(members) -> None:
    """Profiling owns target pprof and host bytes without exporting a pprof alias."""
    document = _guarded_document("iroha_torii")
    assert _guarded_errors("iroha_torii", document) == []
    visible = FEATURE_HYGIENE.cargo_visible_features(document)
    assert "pprof" not in visible
    assert "profiling" not in FEATURE_HYGIENE.local_default_feature_closure(visible)
    document["features"]["profiling"] = members
    assert any(
        "feature `profiling` must be" in error
        for error in _guarded_errors("iroha_torii", document)
    )


def _member_rows(*, implicit_norito_defaults: bool = False) -> list[str]:
    rows = []
    for name in sorted(FEATURE_HYGIENE.FOUNDATIONAL_DEPENDENCIES):
        if implicit_norito_defaults and name == "norito":
            rows.append(
                f'{name} = {{ workspace = true, features = ["json"] }}'
            )
        else:
            rows.append(
                f"{name} = {{ workspace = true, default-features = false }}"
            )
    return rows


def _write_member(
    root: Path,
    member: str,
    rows: list[str],
    *,
    package_name: str | None = None,
) -> None:
    member_root = root / member
    member_root.mkdir(parents=True, exist_ok=True)
    (member_root / "Cargo.toml").write_text(
        "\n".join(
            [
                "[package]",
                f'name = "{package_name or member_root.name}"',
                'version = "0.1.0"',
                "",
                "[dependencies]",
                *rows,
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_fixture(
    root: Path,
    *,
    root_features: bool = False,
    member_defaults: bool = False,
    non_default_member_defaults: bool = False,
) -> None:
    dependency_rows = []
    for name in sorted(FEATURE_HYGIENE.FOUNDATIONAL_DEPENDENCIES):
        injected = ', features = ["broad"]' if root_features and name == "norito" else ""
        dependency_rows.append(
            f'{name} = {{ path = "deps/{name}", default-features = false{injected} }}'
        )

    (root / "Cargo.toml").write_text(
        "\n".join(
            [
                "[workspace]",
                'members = ["crates/*", "crates/consumer"]',
                'default-members = ["crates/consumer"]',
                'exclude = ["crates/excluded"]',
                "",
                "[workspace.dependencies]",
                *dependency_rows,
                "",
            ]
        ),
        encoding="utf-8",
    )
    _write_member(
        root,
        "crates/consumer",
        _member_rows(implicit_norito_defaults=member_defaults),
    )
    _write_member(
        root,
        "crates/excluded",
        _member_rows(implicit_norito_defaults=True),
    )
    if non_default_member_defaults:
        _write_member(
            root,
            "crates/tool",
            _member_rows(implicit_norito_defaults=True),
        )


def test_accepts_explicit_workspace_member_feature_ownership(tmp_path: Path) -> None:
    _write_fixture(tmp_path)

    assert FEATURE_HYGIENE.check_repository(tmp_path) == []


def test_rejects_irohad_normal_dependency_selecting_core_quic(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path)
    rows = _member_rows()
    rows[rows.index("iroha_core = { workspace = true, default-features = false }")] = (
        'iroha_core = { workspace = true, default-features = false, features = ["quic"] }'
    )
    _write_member(tmp_path, "crates/consumer", rows, package_name="irohad")

    errors = FEATURE_HYGIENE.check_repository(tmp_path)

    assert any(
        "package `irohad` [dependencies] dependency `iroha_core` selects explicit "
        "opt-in feature `quic`" in error
        for error in errors
    )


def test_rejects_stale_nonshipping_dependency_allowlist_entry(monkeypatch) -> None:
    current = FEATURE_HYGIENE.NONSHIPPING_EXPLICIT_OPT_IN_DEPENDENCY_ALLOWLIST
    monkeypatch.setattr(
        FEATURE_HYGIENE,
        "NONSHIPPING_EXPLICIT_OPT_IN_DEPENDENCY_ALLOWLIST",
        tuple(sorted((*current, ("irohad", "iroha_core", "quic")))),
    )

    errors = FEATURE_HYGIENE.check_repository(ROOT)

    assert any(
        "stale non-shipping explicit opt-in dependency allowlist entry "
        "`irohad -> iroha_core/quic`" in error
        for error in errors
    )


def test_workspace_members_expand_globs_deduplicate_and_respect_excludes(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path)
    workspace = FEATURE_HYGIENE._load_toml(tmp_path / "Cargo.toml")["workspace"]

    manifests = FEATURE_HYGIENE.workspace_member_manifests(tmp_path, workspace)

    assert [manifest.relative_to(tmp_path).as_posix() for manifest in manifests] == [
        "crates/consumer/Cargo.toml"
    ]


def test_rejects_workspace_feature_injection(tmp_path: Path) -> None:
    _write_fixture(tmp_path, root_features=True)

    errors = FEATURE_HYGIENE.check_repository(tmp_path)

    assert any(
        "workspace dependency `norito` must not inject features" in error
        for error in errors
    )


@pytest.mark.parametrize("defaults", [None, True])
def test_rejects_privacy_workspace_default_feature_drift(
    tmp_path: Path, defaults: bool | None,
) -> None:
    _write_fixture(tmp_path)
    assert FEATURE_HYGIENE.check_repository(tmp_path) == []
    manifest = tmp_path / "Cargo.toml"
    row = 'iroha_core_privacy = { path = "deps/iroha_core_privacy", default-features = false }'
    replacement = (
        'iroha_core_privacy = { path = "deps/iroha_core_privacy" }'
        if defaults is None else row.replace("false", "true")
    )
    source = manifest.read_text(encoding="utf-8")
    assert source.count(row) == 1
    manifest.write_text(source.replace(row, replacement), encoding="utf-8")

    assert FEATURE_HYGIENE.check_repository(tmp_path) == [
        f"{manifest}: workspace dependency `iroha_core_privacy` "
        "must set `default-features = false`"
    ]


@pytest.mark.parametrize("feature", ["simd", "zk-stark"])
def test_rejects_privacy_workspace_feature_injection(
    tmp_path: Path, feature: str,
) -> None:
    _write_fixture(tmp_path)
    assert FEATURE_HYGIENE.check_repository(tmp_path) == []
    manifest = tmp_path / "Cargo.toml"
    row = 'iroha_core_privacy = { path = "deps/iroha_core_privacy", default-features = false }'
    source = manifest.read_text(encoding="utf-8")
    assert source.count(row) == 1
    manifest.write_text(
        source.replace(row, row[:-2] + f', features = ["{feature}"] }}'),
        encoding="utf-8",
    )

    assert FEATURE_HYGIENE.check_repository(tmp_path) == [
        f"{manifest}: workspace dependency `iroha_core_privacy` "
        "must not inject features"
    ]


@pytest.mark.parametrize("defaults", [None, True])
def test_rejects_privacy_member_default_feature_drift(
    tmp_path: Path, defaults: bool | None,
) -> None:
    _write_fixture(tmp_path)
    assert FEATURE_HYGIENE.check_repository(tmp_path) == []
    rows = _member_rows()
    row = "iroha_core_privacy = { workspace = true, default-features = false }"
    rows[rows.index(row)] = (
        "iroha_core_privacy = { workspace = true }"
        if defaults is None else row.replace("false", "true")
    )
    _write_member(tmp_path, "crates/consumer", rows)

    assert FEATURE_HYGIENE.check_repository(tmp_path) == [
        f"{tmp_path / 'crates/consumer/Cargo.toml'}: [dependencies] "
        "`iroha_core_privacy` must set `default-features = false` "
        "and select features locally"
    ]


def test_rejects_implicit_default_features_in_default_member(tmp_path: Path) -> None:
    _write_fixture(tmp_path, member_defaults=True)

    errors = FEATURE_HYGIENE.check_repository(tmp_path)

    assert any(
        "[dependencies] `norito` must set `default-features = false`" in error
        for error in errors
    )


def test_rejects_implicit_defaults_in_non_default_member_with_local_features(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path, non_default_member_defaults=True)

    errors = FEATURE_HYGIENE.check_repository(tmp_path)

    assert any(
        "crates/tool/Cargo.toml" in error
        and "[dependencies] `norito` must set `default-features = false`" in error
        for error in errors
    )


def test_model_storage_boundary_rejects_direct_and_transitive_engines() -> None:
    for engine in ("mv", "concread"):
        direct = {"iroha_model_base": {"dependencies": {engine: "1"}}}
        assert FEATURE_HYGIENE._check_model_storage_boundary(direct, {})
        indirect = {
            "iroha_data_model": {"dependencies": {"iroha_crypto": {"path": "../iroha_crypto"}}},
            "iroha_crypto": {"dependencies": {"engine": {"package": engine, "optional": True}}},
        }
        errors = FEATURE_HYGIENE._check_model_storage_boundary(indirect, {})
        assert errors == [
            f"model storage dependency boundary: iroha_data_model -> iroha_crypto -> {engine}; "
            "model codecs must not depend on runtime storage"
        ]


def test_model_storage_boundary_resolves_workspace_aliases_and_targets() -> None:
    documents = {"iroha_model_base": {"target": {"cfg(unix)": {
        "dependencies": {"storage": {"workspace": True, "optional": True}}
    }}}}
    errors = FEATURE_HYGIENE._check_model_storage_boundary(
        documents, {"storage": {"package": "mv", "path": "crates/mv"}}
    )
    assert any("iroha_model_base -> mv" in error for error in errors)


def test_model_storage_boundary_allows_real_dev_storage_tests() -> None:
    documents = {
        "iroha_data_model": {"dependencies": {"iroha_model_base": "1", "norito": "1"},
                             "dev-dependencies": {"mv": "1"}},
        "iroha_model_base": {"dependencies": {"norito": "1"},
                             "target": {"cfg(unix)": {"dev-dependencies": {"concread": "1"}}}},
        "norito": {},
    }
    assert FEATURE_HYGIENE._check_model_storage_boundary(documents, {}) == []


def test_model_storage_boundary_includes_build_dependencies_and_terminates_cycles() -> None:
    documents = {
        "iroha_model_base": {"dependencies": {"codec": "1"}},
        "codec": {"dependencies": {"iroha_model_base": "1"},
                  "build-dependencies": {"mv": "1"}},
    }
    errors = FEATURE_HYGIENE._check_model_storage_boundary(documents, {})
    assert len(errors) == 1
    assert "iroha_model_base -> codec -> mv" in errors[0]


def test_repository_model_dependency_closure_excludes_storage() -> None:
    workspace = FEATURE_HYGIENE._load_toml(ROOT / "Cargo.toml")["workspace"]
    documents = {}
    for manifest in FEATURE_HYGIENE.workspace_member_manifests(ROOT, workspace):
        document = FEATURE_HYGIENE._load_toml(manifest)
        documents[document["package"]["name"]] = document
    assert FEATURE_HYGIENE._check_model_storage_boundary(
        documents, workspace.get("dependencies", {})
    ) == []


def test_cli_runtime_features_are_mandatory_normal_dependencies() -> None:
    document = _guarded_document("iroha_cli_lib")
    assert _guarded_errors("iroha_cli_lib", document) == []
    for name, required in FEATURE_HYGIENE.MANDATORY_CLI_RUNTIME_DEPENDENCIES.items():
        for mutation in ("remove", "optional", "remove-feature"):
            changed = copy.deepcopy(document)
            if mutation == "remove":
                del changed["dependencies"][name]
            elif mutation == "optional":
                changed["dependencies"][name]["optional"] = True
            else:
                changed["dependencies"][name]["features"].remove(required[0])
            assert any("mandatory CLI runtime dependency" in error
                       for error in _guarded_errors("iroha_cli_lib", changed)), (name, mutation)


def test_cli_library_rejects_retired_target_gate_aliases() -> None:
    for feature in ("cli", "dev-tools"):
        document = copy.deepcopy(_guarded_document("iroha_cli_lib"))
        document["features"][feature] = []
        assert any(f"Cargo feature `{feature}` is unclassified" in error
                   for error in _guarded_errors("iroha_cli_lib", document))


def test_cli_executable_keeps_only_real_target_and_option_features() -> None:
    document = _guarded_document("iroha_cli")
    assert _guarded_errors("iroha_cli", document) == []
    assert document["features"]["cli"] == []
    assert document["features"]["dev-tools"] == ["cli"]
    assert set(document["features"]["default"]) == {"cli", "bridge", "offline-visual-codecs"}


def test_bls_requires_explicit_arrayvec_dependency_forwarding() -> None:
    """BLS must activate the bounded threshold transcript's optional dependency."""

    document = _guarded_document("iroha_crypto")
    assert _guarded_errors("iroha_crypto", document) == []
    assert "dep:arrayvec" in document["features"]["bls"]
    changed = copy.deepcopy(document)
    changed["features"]["bls"].remove("dep:arrayvec")
    assert changed != document

    errors = _guarded_errors("iroha_crypto", changed)

    assert any(
        "feature `bls` must be" in error and "'dep:arrayvec'" in error
        for error in errors
    ), errors


def test_sample_fault_injection_is_dev_only_and_rejects_normal_dependency(
    monkeypatch,
) -> None:
    """The sample's test opt-in cannot leak back into its ordinary model graph."""

    manifest = ROOT / "data_model/samples/executor_custom_data_model/Cargo.toml"
    document = FEATURE_HYGIENE._load_toml(manifest)
    assert "fault_injection" not in document["dependencies"]["iroha_data_model"]["features"]
    assert "fault_injection" in document["dev-dependencies"]["iroha_data_model"]["features"]
    assert FEATURE_HYGIENE.check_repository(ROOT) == []
    changed = copy.deepcopy(document)
    changed["dependencies"]["iroha_data_model"]["features"].append("fault_injection")
    assert changed != document
    original_load = FEATURE_HYGIENE._load_toml

    def mutated_load(path: Path) -> dict:
        return copy.deepcopy(changed) if path == manifest else original_load(path)

    monkeypatch.setattr(FEATURE_HYGIENE, "_load_toml", mutated_load)
    errors = FEATURE_HYGIENE.check_repository(ROOT)

    assert any(
        "package `executor_custom_data_model` [dependencies] dependency `iroha_data_model`"
        in error
        and "selects explicit opt-in feature `fault_injection` from a non-dev dependency declaration"
        in error
        for error in errors
    ), errors


@pytest.mark.parametrize("mutation", ("remove", "optional", "weak", "wrong-platform", "extra-feature", "normal-only", "alias"))
def test_mandatory_daemon_cuda_target_dependency_is_exact(mutation: str) -> None:
    document = _guarded_document("irohad_lib")
    assert _guarded_errors("irohad_lib", document) == []
    changed = copy.deepcopy(document)
    scope = 'cfg(any(target_os = "linux", target_os = "windows"))'
    row = changed["target"][scope]["dependencies"]["ivm"]
    if mutation == "remove":
        del changed["target"][scope]["dependencies"]["ivm"]
    elif mutation == "optional":
        row["optional"] = True
    elif mutation == "weak":
        row["features"] = ["cuda?"]
    elif mutation == "wrong-platform":
        changed["target"]['cfg(target_os = "macos")'] = changed["target"].pop(scope)
    elif mutation == "extra-feature":
        row["features"] = ["cuda", "cuda-hardware-tests"]
    elif mutation == "normal-only":
        changed["dependencies"]["ivm"]["features"] = ["cuda"]
        del changed["target"][scope]["dependencies"]["ivm"]
    else:
        changed["features"]["ivm-cuda"] = ["ivm/cuda"]
    assert any("mandatory daemon CUDA" in error for error in _guarded_errors("irohad_lib", changed))


def test_contextual_cuda_pins_both_exact_dependency_members() -> None:
    document = _guarded_document("ivm")
    assert _guarded_errors("ivm", document) == []
    assert FEATURE_HYGIENE.EXPECTED_FEATURES["ivm"]["cuda"] == (
        "dep:cust", "iroha_accel/cuda",
    )
    assert "cuda" in FEATURE_HYGIENE.CONTEXTUAL_SHIPPING_FEATURES["ivm"]
    assert "cuda" not in FEATURE_HYGIENE.EXPLICIT_OPT_IN_FEATURES["ivm"]
    assert "cuda" not in FEATURE_HYGIENE.local_default_feature_closure(
        FEATURE_HYGIENE.cargo_visible_features(document)
    )
    for members in (
        [], ["dep:cust"], ["iroha_accel/cuda"],
        ["cust", "iroha_accel/cuda"],
        ["dep:cust", "iroha_accel?/cuda"],
        ["iroha_accel/cuda", "dep:cust"],
        ["dep:cust", "iroha_accel/cuda", "cuda-hardware-tests"],
    ):
        changed = copy.deepcopy(document)
        changed["features"]["cuda"] = members
        assert changed != document
        assert any(
            "feature `cuda` must be ['dep:cust', 'iroha_accel/cuda']" in error
            for error in _guarded_errors("ivm", changed)
        ), members


@pytest.mark.parametrize(
    ("package", "aggregates"),
    [
        ("irohad_lib", ("default", "daemon")),
        ("iroha", ("default",)),
        ("iroha_data_model", ("default", "application-model")),
        ("iroha_torii", ("default", "node-api")),
    ],
)
def test_unit_mutation_testing_is_empty_explicit_and_excluded_from_defaults(
    package: str, aggregates: tuple[str, ...],
) -> None:
    document = _guarded_document(package)
    assert _guarded_errors(package, document) == []
    assert FEATURE_HYGIENE.EXPECTED_FEATURES[package]["mutation-testing"] == ()
    assert document["features"]["mutation-testing"] == []
    assert "mutation-testing" in FEATURE_HYGIENE.EXPLICIT_OPT_IN_FEATURES[package]
    assert "mutation-testing" not in FEATURE_HYGIENE.CONTEXTUAL_SHIPPING_FEATURES[package]
    assert "mutation-testing" not in FEATURE_HYGIENE.local_default_feature_closure(
        FEATURE_HYGIENE.cargo_visible_features(document)
    )
    changed = copy.deepcopy(document)
    changed["features"]["mutation-testing"] = ["iroha_core/mutation-testing"]
    assert any(
        "feature `mutation-testing` must be []" in error
        for error in _guarded_errors(package, changed)
    )
    for aggregate in aggregates:
        changed = copy.deepcopy(document)
        changed["features"][aggregate].append("mutation-testing")
        assert any(
            "explicit opt-in feature `mutation-testing` is reachable from `default`" in error
            for error in _guarded_errors(package, changed)
        ), aggregate


@pytest.mark.parametrize("package", ["irohad_lib", "iroha", "iroha_data_model", "iroha_torii"])
def test_unit_mutation_dependency_is_nonshipping_even_through_an_alias(
    tmp_path: Path, package: str,
) -> None:
    _write_fixture(tmp_path)
    assert FEATURE_HYGIENE.check_repository(tmp_path) == []
    assert not any(
        owner == package and feature == "mutation-testing"
        for _consumer, owner, feature in
        FEATURE_HYGIENE.NONSHIPPING_EXPLICIT_OPT_IN_DEPENDENCY_ALLOWLIST
    )
    for section in ("dependencies", "build-dependencies", "dev-dependencies"):
        rows = _member_rows()
        if section != "dependencies":
            rows.extend(["", f"[{section}]"])
        rows.append(
            f'unit_owner = {{ package = "{package}", version = "0.1.0", '
            'default-features = false, features = ["mutation-testing"] }'
        )
        _write_member(tmp_path, "crates/consumer", rows)
        errors = FEATURE_HYGIENE.check_repository(tmp_path)
        if section == "dev-dependencies":
            assert errors == []
        else:
            assert any(
                f"package `consumer` [{section}] dependency `unit_owner` "
                f"(package `{package}`) selects explicit opt-in feature `mutation-testing` "
                "from a non-dev dependency declaration" in error
                for error in errors
            ), (section, errors)
