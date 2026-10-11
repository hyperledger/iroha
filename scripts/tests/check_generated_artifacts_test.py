"""Tests for scripts/check_generated_artifacts.py."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_generated_artifacts.py"


def _write_manifest(repo: Path, *, extra: str = "") -> None:
    (repo / "generated-files.toml").write_text(
        """
schema_version = 1

[policy]
forbidden_tracked_globs = [
  "dist/**",
  "**/node_modules/**",
  "**/.docusaurus/**",
  "**/__pycache__/**",
]
allowed_tracked_paths = ["dist/.gitkeep"]
generated_source_extensions = [".rs", ".py"]

[[generated]]
name = "demo"
kind = "file"
outputs = ["src/generated.rs"]
generator = "python3 scripts/generate.py"
generator_sources = ["scripts/generate.py"]
inputs = ["spec/*.toml"]
check = "python3 scripts/generate.py --check"
""".lstrip()
        + extra,
        encoding="utf-8",
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "spec").mkdir()
    shutil.copy2(SCRIPT, repo / "scripts" / "check_generated_artifacts.py")
    (repo / "scripts" / "generate.py").write_text(
        '"""Deterministic test generator."""\n',
        encoding="utf-8",
    )
    (repo / "spec" / "demo.toml").write_text("version = 1\n", encoding="utf-8")
    (repo / "src" / "generated.rs").write_text(
        "// @generated\npub const VALUE: u8 = 1;\n",
        encoding="utf-8",
    )
    _write_manifest(repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    return repo


def _run(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python3",
            str(repo / "scripts" / "check_generated_artifacts.py"),
            "--root",
            str(repo),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_valid_manifest_and_repository_pass(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)

    result = _run(repo)

    assert result.returncode == 0
    assert "1 outputs" in result.stdout


def test_repository_policy_forbids_dependency_and_portal_caches() -> None:
    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )

    assert {
        "**/node_modules/**",
        "**/.docusaurus/**",
    } <= set(manifest["policy"]["forbidden_tracked_globs"])


def test_sorafs_por_aggregate_fixtures_have_complete_unique_owner() -> None:
    fixture_root = ROOT / "fixtures" / "sorafs_manifest"
    managed_directories = (
        "governance",
        "moderation",
        "por",
        "potr",
        "reference_sdk",
        "repair",
    )
    expected_outputs = {
        fixture.relative_to(ROOT).as_posix()
        for directory in managed_directories
        for fixture in (fixture_root / directory).rglob("*")
        if fixture.is_file() and fixture.suffix in {".json", ".to"}
    }
    expected_outputs.add(
        "fixtures/sorafs_manifest/reference_sdk_validation_inventory_v1.json"
    )
    assert len(expected_outputs) == 61

    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )
    owners = [
        entry
        for entry in manifest["generated"]
        if expected_outputs.intersection(entry["outputs"])
    ]

    assert len(owners) == 1
    owner = owners[0]
    assert owner["name"] == "sorafs-por-aggregate-fixtures"
    assert owner["kind"] == "file"
    assert set(owner["outputs"]) == expected_outputs
    assert set(owner["generator_sources"]) == {
        "crates/sorafs_manifest/Cargo.toml",
        "crates/sorafs_manifest/src/bin/generate_por_fixtures.rs",
        "crates/sorafs_manifest/src/bin/generate_por_fixtures/pop_membership_structural.rs",
    }
    assert set(owner["inputs"]) == {
        "fixtures/sorafs_manifest/appeal_finance/**",
        "fixtures/sorafs_manifest/orderbook/**",
        "fixtures/sorafs_manifest/pdp/**",
        "fixtures/sorafs_manifest/provider_admission/**",
        "fixtures/sorafs_manifest/replication_order/**",
    }

    generator = owner["generator"]
    assert "--write" in generator
    assert "--output-dir" in generator
    assert "IROHA_SORAFS_MANIFEST_STAGE" in generator

    check = owner["check"]
    assert "--check" in check
    assert "--output-dir" not in check

    for command in (generator, check):
        assert command.startswith("NORITO_SKIP_BINDINGS_SYNC=1 ")
        assert "--locked" in command
        assert "--offline" in command
        assert "--jobs 1" in command
        assert "-Z unstable-options" in command
        assert "--lockfile-path Cargo.lock" in command
        assert "-p sorafs_manifest" in command
        assert "--features dev-tools" in command
        assert "--bin generate_por_fixtures" in command


def test_current_rust_contract_artifact_has_complete_unique_owner() -> None:
    output = "javascript/iroha_js/test/fixtures/current_rust_contract_artifact.json"
    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )
    owners = [entry for entry in manifest["generated"] if output in entry["outputs"]]

    assert len(owners) == 1
    owner = owners[0]
    assert owner["name"] == "javascript-current-rust-contract-artifact"
    assert owner["kind"] == "file"
    assert set(owner["generator_sources"]) == {
        "scripts/regenerate_current_rust_contract_artifact.py",
    }
    assert {
        ".cargo/config.toml",
        "Cargo.lock",
        "Cargo.toml",
        "javascript/iroha_js/test/fixtures/current_rust_contract_artifact.ko",
        "javascript/iroha_js/src/blake2b.js",
        "javascript/iroha_js/src/ivmArtifact.js",
        "javascript/iroha_js/src/kotodamaCompiler/normalize.js",
        "javascript/iroha_js/src/address.js",
        "javascript/iroha_js/src/addressErrors.js",
        "javascript/iroha_js/src/addressPrimitives.js",
        "javascript/iroha_js/src/commonLiterals.js",
        "javascript/iroha_js/src/contractAddress.js",
        "javascript/iroha_js/src/contractDeclarations.js",
        "javascript/iroha_js/src/contractErrorTypes.js",
        "javascript/iroha_js/src/contractManifestRules.js",
        "javascript/iroha_js/src/crc64Xz.js",
        "javascript/iroha_js/src/cryptoAlgorithms.js",
        "javascript/iroha_js/src/curveRegistry.js",
        "javascript/iroha_js/src/ed25519Strict.js",
        "javascript/iroha_js/src/entrypointSchema.js",
        "javascript/iroha_js/src/governanceSelector.js",
        "javascript/iroha_js/src/kotodamaCompiler/embeddedCallSchema.js",
        "javascript/iroha_js/src/kotodamaCompiler/embeddedNorito.js",
        "javascript/iroha_js/src/kotodamaCompiler/embeddedStateSchema.js",
        "javascript/iroha_js/src/kotodamaIdentifiers.js",
        "javascript/iroha_js/src/kotodamaProducts.js",
        "javascript/iroha_js/src/multisig.js",
        "javascript/iroha_js/src/native.js",
        "javascript/iroha_js/src/nativeArtifactHash.js",
        "javascript/iroha_js/src/nativeRuntime.js",
        "javascript/iroha_js/src/noritoContractCodecs.js",
        "javascript/iroha_js/src/noritoContractMetadata.js",
        "javascript/iroha_js/src/noritoGovernanceBoundary.js",
        "javascript/iroha_js/src/noritoRecordDecoder.js",
        "javascript/iroha_js/src/noritoValueCodecs.js",
        "javascript/iroha_js/src/normalizers.js",
        "javascript/iroha_js/src/numericV1.js",
        "javascript/iroha_js/src/strictLosslessJson.js",
        "javascript/iroha_js/src/validationError.js",
        "javascript/iroha_js/src/validationThrow.js",
        "rust-toolchain.toml",
        "crates/**",
        "vendor/**",
    } <= set(owner["inputs"])
    for field, mode in (("generator", "--write"), ("check", "--check")):
        command = owner[field]
        assert mode in command
        assert "--koto" in command
        assert "--git" in command
        assert "--cache-root" in command
        assert "IROHA_KOTODAMA_CACHE_ROOT" in command
        assert "IROHA_GIT" in command
        assert "--ivm-rlib" not in command
        assert "--rustc" not in command


def test_nexus_connect_transfer_fixture_has_closed_unique_staging_owner() -> None:
    output = "fixtures/sdk/nexus_connect_transfer_v1.json"
    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )
    owners = [entry for entry in manifest["generated"] if output in entry["outputs"]]

    assert len(owners) == 1
    owner = owners[0]
    assert owner["name"] == "nexus-connect-transfer-v1-fixture"
    assert owner["kind"] == "file"
    assert owner["outputs"] == [output]
    assert set(owner["generator_sources"]) == {
        "xtask/src/main.rs",
        "xtask/src/nexus.rs",
    }
    assert set(owner["inputs"]) == {
        "Cargo.toml",
        "crates/iroha/Cargo.toml",
        "crates/iroha/src/nexus_app.rs",
        "crates/iroha_crypto/src/**/*.rs",
        "crates/iroha_data_model/src/**/*.rs",
        "crates/iroha_model_base/Cargo.toml",
        "crates/iroha_model_base/src/**/*.rs",
        "crates/iroha_primitives/src/**/*.rs",
        "crates/norito/src/**/*.rs",
        "rust-toolchain.toml",
        "xtask/Cargo.toml",
    }

    generator = owner["generator"]
    assert generator.endswith("nexus-connect-fixture --print")
    assert "--write" not in generator
    assert "--output-root" not in generator
    assert "IROHA_NEXUS_CONNECT_FIXTURE_STAGE" not in generator
    assert "$PWD" not in generator
    assert output not in generator

    check = owner["check"]
    assert "nexus-connect-fixture --check" in check
    assert '--output-root "$PWD"' in check
    assert "IROHA_NEXUS_CONNECT_FIXTURE_STAGE" not in check

    for command in (generator, check):
        assert command.startswith("cargo run ")
        assert "--locked" in command
        assert "--offline" in command
        assert "--jobs 1" in command
        assert "-Z unstable-options" in command
        assert "--lockfile-path Cargo.lock" in command
        assert "-p xtask" in command
        assert "--features dev-tools" in command
        assert "--bin xtask" in command


def test_norito_rpc_fixtures_have_one_closed_two_root_owner() -> None:
    blob_names = {
        "asset_metadata_parity.norito",
        "burn_asset.norito",
        "executor_upgrade_demo.norito",
        "grant_revoke_permission.norito",
        "grant_revoke_role.norito",
        "grant_revoke_role_permission.norito",
        "mint_asset.norito",
        "mixed_executable_batch.norito",
        "register_asset_definition.norito",
        "register_nft_demo.norito",
        "register_peer_with_pop_demo.norito",
        "register_pipeline_trigger_demo.norito",
        "register_precommit_trigger_demo.norito",
        "register_role_demo.norito",
        "register_time_trigger_demo.norito",
        "repo_initiate_tri_party.norito",
        "repo_reverse_unwind.norito",
        "set_parameter_next_mode.norito",
        "settlement_dvp_atomic.norito",
        "settlement_pvp_net.norito",
        "transfer_asset.norito",
        "transfer_asset_definition.norito",
        "transfer_domain.norito",
        "transfer_nft_demo.norito",
        "trigger_repetitions_demo.norito",
        "typed_fee_payment_gas_limit.norito",
        "unregister_peer_demo.norito",
    }
    outputs = {
        "IrohaSwift/Fixtures/transaction_fixtures.manifest.json",
        "IrohaSwift/Fixtures/transaction_payloads.json",
        "fixtures/norito_rpc/alias_setup_v1/alias_setup_v1.json",
        "fixtures/norito_rpc/iroha_compact_hash_vector.properties",
        "fixtures/norito_rpc/schema_hashes.json",
        "fixtures/norito_rpc/transaction_fixtures.manifest.json",
        "fixtures/norito_rpc/transaction_payloads.json",
        "java/iroha_android/src/test/resources/transaction_fixtures.manifest.json",
        "java/iroha_android/src/test/resources/transaction_payloads.json",
        "python/iroha_python/tests/fixtures/transaction_fixtures.manifest.json",
        "python/iroha_python/tests/fixtures/transaction_payloads.json",
        *(f"fixtures/norito_rpc/{name}" for name in blob_names),
        *(
            f"java/iroha_android/src/test/resources/{name}"
            for name in blob_names
        ),
    }
    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )
    owner = next(
        entry
        for entry in manifest["generated"]
        if entry["name"] == "norito-rpc-fixtures"
    )

    assert len(outputs) == 65
    assert set(owner["outputs"]) == outputs
    for output in outputs:
        assert sum(output in entry["outputs"] for entry in manifest["generated"]) == 1
        assert output not in owner["generator"]
    assert set(owner["generator_sources"]) == {
        "crates/iroha/Cargo.toml",
        "crates/iroha/src/client.rs",
        "tools/norito_codegen_exporter/Cargo.toml",
        "tools/norito_codegen_exporter/src/lib.rs",
        "tools/norito_codegen_exporter/src/norito_rpc.rs",
        "xtask/Cargo.toml",
        "xtask/src/main.rs",
        "xtask/src/norito_rpc.rs",
        "xtask/src/norito_rpc/alias_setup_fixture.rs",
    }
    assert set(owner["inputs"]) == {
        "Cargo.lock",
        "Cargo.toml",
        "crates/iroha_crypto/src/**/*.rs",
        "crates/iroha_data_model/src/**/*.rs",
        "crates/iroha_model_base/Cargo.toml",
        "crates/iroha_model_base/src/**/*.rs",
        "crates/iroha_primitives/src/**/*.rs",
        "crates/norito/src/**/*.rs",
        "fixtures/norito_rpc/transaction_payloads.json",
        "rust-toolchain.toml",
    }
    generator = owner["generator"]
    check = owner["check"]
    assert "IROHA_NORITO_RPC_FIXTURE_STAGE" in generator
    assert "IROHA_NORITO_RPC_FIXTURE_STAGE" not in check
    assert "norito-rpc-fixtures" in generator
    assert "--output-root" in generator
    assert "norito-rpc-verify" in check
    for command in (generator, check):
        assert "IROHA_NORITO_RPC_FIXTURE_CARGO_TARGET_DIR" in command
        assert "cargo run" in command
        assert "--locked" in command
        assert "--offline" in command
        assert "--jobs 1" in command
        assert "-p xtask" in command
        assert "--features dev-tools" in command
        assert "--bin xtask" in command
        assert "-Z" not in command
        assert "--lockfile-path" not in command


def test_mochi_canonical_binary_fixtures_have_one_safe_external_stage_owner() -> None:
    outputs = {
        "mochi/mochi-core/tests/fixtures/canonical_block_wire.bin",
        "mochi/mochi-core/tests/fixtures/canonical_event_message.bin",
        "mochi/mochi-core/tests/fixtures/canonical_pipeline_event_message.bin",
        "mochi/mochi-core/tests/fixtures/canonical_data_event_message.bin",
    }
    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )
    owner = next(
        entry
        for entry in manifest["generated"]
        if entry["name"] == "mochi-canonical-torii-binary-fixtures"
    )

    assert set(owner["outputs"]) == outputs
    for output in outputs:
        assert sum(output in entry["outputs"] for entry in manifest["generated"]) == 1
        assert output not in owner["generator"]
    assert set(owner["generator_sources"]) == {
        "mochi/mochi-core/Cargo.toml",
        "mochi/mochi-core/src/torii.rs",
        "mochi/mochi-core/src/torii/tests/canonical_fixture_owner.rs",
        "mochi/mochi-core/src/torii/tests_part1.rs",
    }
    assert "IROHA_MOCHI_CANONICAL_FIXTURE_STAGE" in owner["generator"]
    for command in (owner["generator"], owner["check"]):
        assert "IROHA_MOCHI_CANONICAL_FIXTURE_CARGO_TARGET_DIR" in command
    assert "env -u IROHA_MOCHI_CANONICAL_FIXTURE_STAGE" in owner["check"]
    for command in (owner["generator"], owner["check"]):
        assert "cargo test" in command
        assert "--locked" in command
        assert "--offline" in command
        assert "-p mochi-core" in command
        assert "canonical_torii_binary_fixture_owner" in command
        assert "--ignored" in command


def test_mochi_replay_fixtures_have_one_safe_exact_owner_without_orphans() -> None:
    outputs = {
        "mochi/mochi-integration/tests/fixtures/torii_replay/status.json",
        "mochi/mochi-integration/tests/fixtures/torii_replay/sumeragi.json",
        "mochi/mochi-integration/tests/fixtures/torii_replay/sumeragi_diagnostics.json",
        "mochi/mochi-integration/tests/fixtures/torii_replay/configuration.json",
        "mochi/mochi-integration/tests/fixtures/torii_replay/metrics.prom",
        "mochi/mochi-integration/tests/fixtures/torii_replay/query.bin",
    }
    manifest = tomllib.loads(
        (ROOT / "generated-files.toml").read_text(encoding="utf-8")
    )
    owner = next(
        entry
        for entry in manifest["generated"]
        if entry["name"] == "mochi-torii-replay-fixtures"
    )

    assert set(owner["outputs"]) == outputs
    assert not any(
        output.endswith(("block.bin", "event.bin")) for output in owner["outputs"]
    )
    for output in outputs:
        assert sum(output in entry["outputs"] for entry in manifest["generated"]) == 1
        assert output not in owner["generator"]
    assert set(owner["generator_sources"]) == {
        "mochi/mochi-integration/Cargo.toml",
        "mochi/mochi-integration/src/mock_torii.rs",
        "mochi/mochi-integration/src/mock_torii/tests/replay_fixture_owner.rs",
    }
    assert "IROHA_MOCHI_REPLAY_FIXTURE_STAGE" in owner["generator"]
    for command in (owner["generator"], owner["check"]):
        assert "IROHA_MOCHI_REPLAY_FIXTURE_CARGO_TARGET_DIR" in command
    assert "env -u IROHA_MOCHI_REPLAY_FIXTURE_STAGE" in owner["check"]
    for command in (owner["generator"], owner["check"]):
        assert "cargo test" in command
        assert "--locked" in command
        assert "--offline" in command
        assert "-p mochi-integration" in command
        assert "torii_replay_fixture_owner" in command
        assert "--ignored" in command


def test_single_star_input_does_not_cross_directory_boundary(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    subprocess.run(["git", "rm", "-f", "spec/demo.toml"], cwd=repo, check=True)
    nested = repo / "spec" / "nested" / "demo.toml"
    nested.parent.mkdir(parents=True)
    nested.write_text("version = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", str(nested)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "inputs pattern matches no tracked regular files" in result.stderr


@pytest.mark.parametrize("nested", [False, True])
def test_globstar_input_matches_zero_or_more_directories(
    tmp_path: Path, nested: bool
) -> None:
    repo = _init_repo(tmp_path)
    manifest = repo / "generated-files.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'inputs = ["spec/*.toml"]',
            'inputs = ["spec/**/*.toml"]',
        ),
        encoding="utf-8",
    )
    if nested:
        subprocess.run(["git", "rm", "-f", "spec/demo.toml"], cwd=repo, check=True)
        fixture = repo / "spec" / "nested" / "demo.toml"
        fixture.parent.mkdir(parents=True)
        fixture.write_text("version = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", str(fixture)], cwd=repo, check=True)
    subprocess.run(["git", "add", str(manifest)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 0


@pytest.mark.parametrize(
    "relative_path",
    (
        "dist/bundle.js",
        "docs/portal/node_modules/package/index.js",
        "docs/portal/.docusaurus/cache.json",
    ),
)
def test_forbidden_tracked_build_artifact_fails(
    tmp_path: Path, relative_path: str
) -> None:
    repo = _init_repo(tmp_path)
    path = repo / relative_path
    path.parent.mkdir(parents=True)
    path.write_text("generated package output\n", encoding="utf-8")
    subprocess.run(["git", "add", str(path)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "forbidden generated/build artifacts" in result.stderr
    assert relative_path in result.stderr


def test_forbidden_tracked_docusaurus_cache_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    path = repo / "docs" / "portal" / ".docusaurus" / "client-manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "add", str(path)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "forbidden generated/build artifacts" in result.stderr
    assert "docs/portal/.docusaurus/client-manifest.json" in result.stderr


def test_allowed_directory_marker_passes(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    path = repo / "dist" / ".gitkeep"
    path.parent.mkdir()
    path.write_text("", encoding="utf-8")
    subprocess.run(["git", "add", "-f", str(path)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 0


def test_unregistered_generated_header_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    path = repo / "src" / "orphan.rs"
    path.write_text("// Code generated by demo; DO NOT EDIT.\n", encoding="utf-8")
    subprocess.run(["git", "add", str(path)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "generated source has no generated-files.toml owner" in result.stderr
    assert "src/orphan.rs" in result.stderr


def test_duplicate_output_ownership_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    with (repo / "generated-files.toml").open("a", encoding="utf-8") as manifest:
        manifest.write(
            """

[[generated]]
name = "duplicate"
kind = "regions"
outputs = ["src/generated.rs"]
generator = "python3 scripts/generate.py"
generator_sources = ["scripts/generate.py"]
inputs = ["spec/demo.toml"]
check = "python3 scripts/generate.py --check"
"""
        )
    subprocess.run(["git", "add", "generated-files.toml"], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "owned by both demo and duplicate" in result.stderr


def test_missing_generator_source_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    manifest = repo / "generated-files.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'generator_sources = ["scripts/generate.py"]',
            'generator_sources = ["scripts/missing.py"]',
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "generated-files.toml"], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "generator_sources is not a tracked regular file" in result.stderr


def test_tracked_elf_core_dump_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    path = repo / "crates" / "demo" / "core"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\x7fELF" + b"\0" * 32)
    subprocess.run(["git", "add", str(path)], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "executable core dumps are tracked" in result.stderr
    assert "crates/demo/core" in result.stderr


@pytest.mark.parametrize("invalid", ["../outside.rs", "/absolute.rs", "src//bad.rs"])
def test_non_normalized_output_path_fails(tmp_path: Path, invalid: str) -> None:
    repo = _init_repo(tmp_path)
    manifest = repo / "generated-files.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("src/generated.rs", invalid),
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "generated-files.toml"], cwd=repo, check=True)

    result = _run(repo)

    assert result.returncode == 1
    assert "normalized repository-relative path" in result.stderr
