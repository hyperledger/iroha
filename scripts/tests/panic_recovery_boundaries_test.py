"""Regression test for audited panic recovery boundaries."""

from __future__ import annotations

import importlib.util
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest


def load_guard_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/check_panic_recovery_boundaries.py"
    spec = importlib.util.spec_from_file_location("check_panic_recovery_boundaries", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_panic_recovery_boundary_guard() -> None:
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, str(root / "scripts/check_panic_recovery_boundaries.py")],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_pr_workflow_runs_panic_recovery_guard_and_regressions() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/pr.yml").read_text(encoding="utf-8")

    assert workflow.count("scripts/tests/panic_recovery_boundaries_test.py") == 1
    assert (
        workflow.count("python3 -I -S scripts/check_panic_recovery_boundaries.py")
        == 1
    )


@pytest.mark.parametrize(
    "relative",
    (
        "crates/irohad/src/sorafs_provider_ingest_runtime/https_source.rs",
        "crates/irohad/src/external_software_signer/musubi_attestation.rs",
        "crates/irohad/src/musubi_publication_service/private_tls_ingress.rs",
    ),
)
def test_daemon_recoverable_workers_have_no_bare_blocking(relative: str) -> None:
    module = load_guard_module()
    assert relative in module.NO_BARE_BLOCKING
    source = (module.ROOT / relative).read_text(encoding="utf-8")
    assert module._bare_blocking_lines(source) == []


@pytest.mark.parametrize(
    "relative",
    (
        "crates/iroha_core/src/executor_initial_permission_authority.rs",
        "crates/iroha_core/src/executor_execution_fee.rs",
        "crates/iroha_core/src/executor_execution_effects.rs",
        "crates/iroha_core/src/executor_raw_ivm_work_tests.rs",
        "crates/iroha_core/src/executor_effect_budget_tests.rs",
        "crates/iroha_core/src/executor_final_promotion_permission_tests.rs",
        "crates/iroha_core/src/executor_final_promotion_account_permission_tests.rs",
        "crates/iroha_core/src/executor_stream_token_custody_permission_tests.rs",
        "crates/iroha_core/src/executor_stream_token_direct_source_tests.rs",
        "crates/iroha_core/src/executor_contract_owner_permission_tests.rs",
        "crates/iroha_core/src/executor_fastpq_rejection_tail.rs",
        "crates/iroha_core/src/executor_fastpq_rejection_tail/tests.rs",
        "crates/iroha_core/src/executor_fastpq_rejection_tail/sponsored_alias_tests.rs",
        "crates/iroha_core/src/executor/resource_return_tests.rs",
        "crates/iroha_core/src/executor_asset_lock_admission_tests.rs",
        "crates/iroha_core/src/executor/root_scope.rs",
        "crates/iroha_core/src/executor/root_scope/tests.rs",
        "crates/iroha_core/src/executor_dpn_domain_enrollment_tests.rs",
        "crates/iroha_core/src/executor_opaque_sccp_record_tests.rs",
        "crates/iroha_core/src/executor/fee_sponsor_multisig.rs",
        "crates/iroha_core/src/executor/fee_sponsor_multisig_tests.rs",
    ),
)
def test_core_recovery_support_seals_exact_permission_include(
    tmp_path: Path, relative: str,
) -> None:
    module = load_guard_module()
    included = tmp_path / relative
    included.parent.mkdir(parents=True)
    executor = tmp_path / "crates/iroha_core/src/executor.rs"
    reference = included.relative_to(executor.parent).as_posix()
    executor.write_text(f'include!("{reference}");\n', encoding="utf-8")
    included.write_text("fn reviewed_permission() {}\n", encoding="utf-8")

    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert included.resolve() in sources
    records, _, counts = module.torii_boundary_inventory(tmp_path)
    assert any(record.startswith(relative + "\t") for record in records)

    included.write_text(
        "fn reviewed_permission() { changed_authority(); }\n", encoding="utf-8"
    )
    observed = module.torii_boundary_inventory(tmp_path)
    assert observed[2] == counts, "the control changes context without adding a boundary"
    errors = module.closed_torii_boundary_inventory_failures(
        tmp_path, records, observed_inventory=observed,
    )
    assert any("source inventory drifted" in error for error in errors), errors


def test_core_recovery_support_rejects_undeclared_permission_sibling(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source_root = tmp_path / "crates/iroha_core/src"
    source_root.mkdir(parents=True)
    executor = source_root / "executor.rs"
    sibling = source_root / "executor_unreviewed_permission.rs"
    executor.write_text(f'include!("{sibling.name}");\n', encoding="utf-8")
    sibling.write_text("fn unreviewed_permission() {}\n", encoding="utf-8")

    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert sibling.resolve() not in sources
    assert failures == [
        "crates/iroha_core/src/executor.rs:1: include! source path escapes "
        "the audited source roots: executor_unreviewed_permission.rs"
    ]



def test_core_recovery_seals_transitive_root_scope_and_asset_lock_sources(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    root_scope = parent / "executor/root_scope.rs"
    root_scope.parent.mkdir(parents=True)
    scope_tests = parent / "executor/root_scope/tests.rs"
    scope_tests.parent.mkdir()
    asset_tests = parent / "executor_asset_lock_admission_tests.rs"
    (parent / "executor.rs").write_text(
        'pub(crate) mod root_scope;\n'
        '#[cfg(test)] mod tests { include!("executor_asset_lock_admission_tests.rs"); }\n',
        encoding="utf-8",
    )
    root_scope.write_text("#[cfg(test)] mod tests;\n", encoding="utf-8")
    scope_tests.write_text("fn immutable_scope_control() {}\n", encoding="utf-8")
    asset_tests.write_text("fn asset_custody_control() {}\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert {root_scope.resolve(), scope_tests.resolve(), asset_tests.resolve()} <= set(sources)
    records, _, counts = module.torii_boundary_inventory(tmp_path)
    for path in (root_scope, scope_tests, asset_tests):
        relative = path.relative_to(tmp_path).as_posix()
        assert relative in {str(p) for p in module.CORE_RECOVERY_SUPPORT_PATHS}
        assert any(record.startswith(relative + "\t") for record in records)
        original = path.read_text(encoding="utf-8")
        path.write_text(original + "fn changed_custody() {}\n", encoding="utf-8")
        observed = module.torii_boundary_inventory(tmp_path)
        assert observed[2] == counts
        errors = module.closed_torii_boundary_inventory_failures(
            tmp_path, records, observed_inventory=observed,
        )
        assert any("source inventory drifted" in error for error in errors), errors
        path.write_text(original, encoding="utf-8")


@pytest.mark.parametrize(
    ("owner_relative", "unreviewed_relative"),
    (
        ("executor.rs", "executor/unreviewed.rs"),
        ("executor/root_scope.rs", "executor/root_scope/unreviewed.rs"),
    ),
)
def test_core_recovery_root_scope_does_not_admit_unreviewed_module_neighbors(
    tmp_path: Path, owner_relative: str, unreviewed_relative: str,
) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    owner = parent / owner_relative
    owner.parent.mkdir(parents=True)
    unknown = parent / unreviewed_relative
    unknown.parent.mkdir(parents=True, exist_ok=True)
    owner.write_text("mod unreviewed;\n", encoding="utf-8")
    unknown.write_text("fn unreviewed_custody() {}\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert unknown.resolve() not in sources
    assert failures == [
        f"crates/iroha_core/src/{owner_relative}:1: mod source path escapes "
        "the audited source roots: unreviewed.rs"
    ]

def test_shared_signer_fixture_is_an_exact_audited_source(tmp_path: Path) -> None:
    module = load_guard_module()
    relative = (
        "crates/sorafs_manifest/src/signer/final_promotion/tests/"
        "statement_fixture_support.rs"
    )
    fixture = tmp_path / relative
    fixture.parent.mkdir(parents=True)
    fixture.write_text("fn fixture() {}\n", encoding="utf-8")
    source = (
        tmp_path
        / "crates/irohad/src/signer_operation/tests/final_promotion.rs"
    )
    source.parent.mkdir(parents=True)
    source.write_text(
        'include!("../../../../sorafs_manifest/src/signer/final_promotion/tests/'
        'statement_fixture_support.rs");\n',
        encoding="utf-8",
    )
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert fixture.resolve() in {source.resolve() for source in sources}
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    fixture.write_text("fn changed_fixture() {}\n", encoding="utf-8")
    errors = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )
    assert any("source inventory drifted" in error for error in errors)


def test_stable_inventory_read_rejects_hardlinks_and_shared_writes(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "source.rs"
    source.write_text("fn reviewed() {}\n", encoding="utf-8")
    hardlink = tmp_path / "outside.rs"
    os.link(source, hardlink)
    with pytest.raises(RuntimeError, match="exactly one hard link"):
        module._stable_read_bytes(source)
    hardlink.unlink()

    source.chmod(0o664)
    with pytest.raises(RuntimeError, match="group- or world-writable"):
        module._stable_read_bytes(source)


@pytest.mark.parametrize(
    "relative",
    (
        "crates/iroha_core/src/executor.rs",
        "crates/iroha_core_zk/src/lib.rs",
        "crates/iroha_panic_hook/src/lib.rs",
    ),
)
@pytest.mark.parametrize(
    "payload",
    (
        "use std::panic::catch_unwind as recover;\n"
        "fn run() { let _ = recover(|| work()); }\n",
        "macro_rules! call { ($f:path) => { $f(|| work()) } }\n"
        "fn run() { let _ = call!(std::panic::catch_unwind); }\n",
    ),
)
def test_core_recovery_files_reject_alias_and_macro_boundary_bypasses(
    tmp_path: Path, relative: str, payload: str
) -> None:
    module = load_guard_module()
    source = tmp_path / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(payload, encoding="utf-8")
    sources, closure_failures = module.torii_rust_source_closure(tmp_path)
    assert not closure_failures
    failures = module.torii_boundary_alias_failures(tmp_path, sources)
    assert failures
    assert relative in failures[0]


def test_core_raw_catch_inventory_distinguishes_suppressed_calls() -> None:
    module = load_guard_module()
    assert module._direct_raw_catch_unwind_lines(
        "fn test_only() { std::panic::catch_unwind(|| work()); }\n"
    ) == [1]
    assert module._direct_raw_catch_unwind_lines(
        "fn reviewed() { iroha_panic_hook::catch_unwind_suppressed(work); }\n"
    ) == []


def test_closed_inventory_rejects_a_new_torii_module(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/new_worker.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() { tokio::task::spawn_blocking(|| 1); }\n", encoding="utf-8"
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii spawn_blocking site count drifted (expected 0, found 1)" in failures
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_rejects_a_new_daemon_module(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/irohad/src/new_provider_worker.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() { tokio::task::spawn_blocking(|| provider_call()); }\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii spawn_blocking site count drifted (expected 0, found 1)" in failures
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_rejects_a_new_untracked_git_module(tmp_path: Path) -> None:
    module = load_guard_module()
    tracked = tmp_path / "crates/iroha_torii/src/lib.rs"
    tracked.parent.mkdir(parents=True)
    tracked.write_text("fn stable() {}\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", str(tracked)], cwd=tmp_path, check=True)
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    untracked = tmp_path / "crates/iroha_torii/src/new_worker.rs"
    untracked.write_text(
        "fn run() { tokio::spawn(async { work().await }); }\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii task_spawn site count drifted (expected 0, found 1)" in failures
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_rejects_an_aliased_recovery_boundary(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/alias.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "use std::panic::catch_unwind as recover;\n"
        "fn run() { let _ = recover(|| 1); }\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii catch_unwind site count drifted (expected 0, found 1)" in failures
    assert any("source inventory drifted" in failure for failure in failures)
    assert module.torii_boundary_alias_failures(tmp_path) == [
        "crates/iroha_torii/src/alias.rs: catch_unwind boundary alias 'recover' "
        "is forbidden; use the audited spelling so cross-module calls remain visible"
    ]


def test_closed_inventory_binds_each_reviewed_call_site(tmp_path: Path) -> None:
    module = load_guard_module()
    relative = "crates/iroha_torii/src/critical_worker.rs"
    source = tmp_path / relative
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() { tokio::task::spawn_blocking(|| 1); }\n", encoding="utf-8"
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    assert (
        module.closed_torii_boundary_inventory_failures(
            tmp_path, expected_records
        )
        == []
    )

    source.write_text(
        "fn moved() { tokio::task::spawn_blocking(|| 1); }\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )
    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_source_inventory_hashes_the_exact_bytes_it_tokenizes(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/worker.rs"
    source.parent.mkdir(parents=True)
    reviewed = b"fn run() { tokio::spawn(work()); }\n"
    source.write_bytes(reviewed)
    reads = 0
    original = module._stable_read_bytes

    def mutate_after_read(path: Path) -> bytes:
        nonlocal reads
        payload = original(path)
        reads += 1
        if path == source:
            source.write_text("fn changed() {}\n", encoding="utf-8")
        return payload

    monkeypatch.setattr(module, "_stable_read_bytes", mutate_after_read)

    record, counts = module._source_inventory(source, tmp_path)

    assert reads == 1
    assert hashlib.sha256(reviewed).hexdigest() in record
    assert counts["task_spawn"] == 1


def test_closed_inventory_rejects_bare_joined_task_recovery(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/joined.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "async fn run() {\n"
        "    let task = tokio::spawn(async { panic!(\"request panic\") });\n"
        "    let _controlled = task.await.map_err(|_| \"controlled\");\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )
    assert "Torii task_spawn site count drifted (expected 0, found 1)" in failures
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_binds_join_handling_in_existing_spawn_unit(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/joined.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "async fn run() {\n"
        "    let task = tokio::spawn(async { do_work().await });\n"
        "    task.await.expect(\"supervisor task must not panic\");\n"
        "}\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    source.write_text(
        "async fn run() {\n"
        "    let task = tokio::spawn(async { do_work().await });\n"
        "    task.await.map_err(|_| \"controlled request error\")?;\n"
        "}\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_binds_complete_macro_recovery_unit(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/macro_worker.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "worker_test! { catches_worker_panic\n"
        "    let result = std::panic::catch_unwind(|| work());\n"
        "    assert!(result.is_err());\n"
        "}\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    source.write_text(
        "worker_test! { catches_worker_panic\n"
        "    let result = std::panic::catch_unwind(|| work());\n"
        "    return_controlled_error(result);\n"
        "}\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_binds_complete_macro_rules_definition(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/macro_definition.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "macro_rules! launch {\n"
        "    ($task:expr) => {{\n"
        "        let task = tokio::spawn($task);\n"
        "        task\n"
        "    }};\n"
        "}\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    source.write_text(
        "macro_rules! launch {\n"
        "    ($task:expr) => {{\n"
        "        let task = tokio::spawn($task);\n"
        "        task.await.map_err(|_| \"controlled\")\n"
        "    }};\n"
        "}\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_binds_parenthesized_macro_invocation(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/parenthesized_macro.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "worker_test!( catches_worker_panic\n"
        "    let task = tokio::spawn(work());\n"
        "    task.await.expect(\"supervisor task must not panic\");\n"
        ");\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    source.write_text(
        "worker_test!( catches_worker_panic\n"
        "    let task = tokio::spawn(work());\n"
        "    task.await.map_err(|_| \"controlled\")?;\n"
        ");\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_prefers_function_over_nested_macro_unit(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/nested_macro.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "async fn run() {\n"
        "    let task = make_task! { tokio::spawn(work()) };\n"
        "    task.await.expect(\"supervisor task must not panic\");\n"
        "}\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    source.write_text(
        "async fn run() {\n"
        "    let task = make_task! { tokio::spawn(work()) };\n"
        "    task.await.map_err(|_| \"controlled\")?;\n"
        "}\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_parses_array_return_signature(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/array_return.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "async fn run() -> [u8; 32] {\n"
        "    let task = tokio::spawn(work());\n"
        "    task.await.expect(\"supervisor task must not panic\")\n"
        "}\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    source.write_text(
        "async fn run() -> [u8; 32] {\n"
        "    let task = tokio::spawn(work());\n"
        "    task.await.map_err(|_| \"controlled\")?\n"
        "}\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_closed_inventory_rejects_spawn_local(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/local.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "async fn run() {\n"
        "    tokio::task::spawn_local(async { panic!(\"request panic\") })\n"
        "        .await\n"
        "        .map_err(|_| \"controlled\")?;\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii task_spawn site count drifted (expected 0, found 1)" in failures


def test_closed_inventory_rejects_unreviewed_websocket_upgrade_task(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/websocket.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn upgrade(ws: WebSocketUpgrade) {\n"
        "    ws.on_upgrade(|socket| async move { serve(socket).await });\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii upgrade_task site count drifted (expected 0, found 1)" in failures


def test_boundary_alias_is_forbidden_across_modules(tmp_path: Path) -> None:
    module = load_guard_module()
    aliases = tmp_path / "crates/iroha_torii/src/aliases.rs"
    caller = tmp_path / "crates/iroha_torii/src/caller.rs"
    aliases.parent.mkdir(parents=True)
    aliases.write_text("pub use tokio::spawn as launch;\n", encoding="utf-8")
    caller.write_text(
        "fn run(task: Task) { crate::aliases::launch(task); }\n", encoding="utf-8"
    )

    failures = module.torii_boundary_alias_failures(tmp_path)

    assert failures == [
        "crates/iroha_torii/src/aliases.rs: task_spawn boundary alias 'launch' "
        "is forbidden; use the audited spelling so cross-module calls remain visible"
    ]


def test_boundary_alias_check_does_not_treat_cast_as_import_alias(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/cast.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run(handle: Handle, task: Task) {\n"
        "    let _opaque = handle.spawn(task) as usize;\n"
        "}\n",
        encoding="utf-8",
    )

    assert module.torii_boundary_alias_failures(tmp_path) == []


def test_boundary_alias_check_rejects_local_function_item_alias(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/local_alias.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() {\n"
        "    let recover = std::panic::catch_unwind;\n"
        "    let _ = recover(|| provider_call());\n"
        "}\n",
        encoding="utf-8",
    )

    assert module.torii_boundary_alias_failures(tmp_path) == [
        "crates/iroha_torii/src/local_alias.rs: catch_unwind boundary alias "
        "'recover' is forbidden; use the audited spelling so cross-module calls "
        "remain visible"
    ]


def test_boundary_alias_check_rejects_compound_destructuring_aliases(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/compound_alias.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() {\n"
        "    let (recover, _) = (std::panic::catch_unwind, marker);\n"
        "    let [launch] = [tokio::spawn];\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.torii_boundary_alias_failures(tmp_path)

    assert any(
        "catch_unwind boundary alias 'recover' is forbidden" in failure
        for failure in failures
    )
    assert any(
        "task_spawn boundary alias 'launch' is forbidden" in failure
        for failure in failures
    )


def test_boundary_alias_check_rejects_match_for_and_closure_rebinding(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/pattern_aliases.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() {\n"
        "    match std::panic::catch_unwind { recover => recover(|| work()), }\n"
        "    for launch in [tokio::spawn] { launch(task()); }\n"
        "    std::iter::once(tokio::task::spawn_blocking)\n"
        "        .for_each(|blocking| { blocking(work); });\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.torii_boundary_alias_failures(tmp_path)

    assert sum("boundary function item" in failure for failure in failures) == 3
    assert any(
        "catch_unwind boundary function item 'catch_unwind'" in failure
        for failure in failures
    )
    assert any(
        "task_spawn boundary function item 'spawn'" in failure
        for failure in failures
    )
    assert any(
        "spawn_blocking boundary function item 'spawn_blocking'" in failure
        for failure in failures
    )


def test_boundary_alias_check_rejects_macro_colon_rebinding(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/macro_alias.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() {\n"
        "    bind!(std::panic::catch_unwind: recover);\n"
        "    recover(|| work());\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.torii_boundary_alias_failures(tmp_path)

    assert any(
        "catch_unwind boundary function item 'catch_unwind'" in failure
        for failure in failures
    )


def test_boundary_alias_check_does_not_treat_macro_use_tokens_as_use_items(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/macro_use.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run() {\n"
        "    call!(use std::panic::catch_unwind);\n"
        "    call!(prefix use tokio::task::spawn);\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.torii_boundary_alias_failures(tmp_path)

    assert sum("boundary function item" in failure for failure in failures) == 2
    assert any("function item 'catch_unwind'" in failure for failure in failures)
    assert any("function item 'spawn'" in failure for failure in failures)


def test_bare_blocking_check_rejects_join_set_method(tmp_path: Path) -> None:
    module = load_guard_module()
    source = (
        "fn run(tasks: &mut tokio::task::JoinSet<()>) {\n"
        "    tasks.spawn_blocking(|| provider_call());\n"
        "}\n"
    )

    assert module._bare_blocking_lines(source) == [2]


def test_bare_thread_check_rejects_direct_and_builder_spawns(tmp_path: Path) -> None:
    module = load_guard_module()
    source = (
        "fn run() {\n"
        "    std::thread::spawn(|| provider_call());\n"
        "    std::thread::Builder::new().spawn(|| provider_call());\n"
        "}\n"
    )

    assert module._bare_std_thread_lines(source) == [2, 3]


@pytest.mark.parametrize(
    "source",
    (
        "use std::thread as th;\nfn run() { th::spawn(work); }\n",
        "use std::thread::Builder as ThreadBuilder;\n"
        "fn run() { ThreadBuilder::new().spawn(work); }\n",
        "use std::thread::Builder;\nfn run() { Builder::new().spawn(work); }\n",
        "use {std::thread as th};\nfn run() { th::spawn(work); }\n",
        "use {foo, std::{thread as th}};\nfn run() { th::spawn(work); }\n",
        "use {std::{self, thread::{self as th}}};\n"
        "fn run() { th::spawn(work); }\n",
        "type ThreadBuilder = std::thread::Builder;\n"
        "fn run() { ThreadBuilder::new().spawn(work); }\n",
        "fn run() {\n"
        "    let builder = std::thread::Builder::new();\n"
        "    builder.spawn(work);\n"
        "}\n",
        "fn run() {\n"
        "    std::thread::scope(|scope| { scope.spawn(work); });\n"
        "}\n",
    ),
)
def test_bare_thread_check_rejects_std_thread_indirection(source: str) -> None:
    module = load_guard_module()

    assert module._bare_std_thread_lines(source)


def test_bare_thread_check_allows_builder_inside_reviewed_wrapper() -> None:
    module = load_guard_module()
    source = (
        "fn run() {\n"
        "    let thread = crate::panic_recovery::spawn_thread_recoverable(\n"
        "        std::thread::Builder::new(), work,\n"
        "    );\n"
        "}\n"
    )

    assert module._bare_std_thread_lines(source) == []


def test_inventory_counts_join_set_and_std_thread_boundaries(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/irohad/src/provider_worker.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run(tasks: &mut tokio::task::JoinSet<()>) {\n"
        "    tasks.spawn_blocking(|| provider_call());\n"
        "    std::thread::Builder::new().spawn(|| provider_call());\n"
        "}\n",
        encoding="utf-8",
    )

    _, _, counts = module.torii_boundary_inventory(tmp_path)

    assert counts["spawn_blocking"] == 1
    assert counts["task_spawn"] == 1


def test_closed_inventory_rejects_spawn_on_families(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/on.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run(runtime: Runtime, task: Task) {\n"
        "    runtime.spawn_on(task);\n"
        "    runtime.spawn_blocking_on(|| work());\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii task_spawn site count drifted (expected 0, found 1)" in failures
    assert "Torii spawn_blocking site count drifted (expected 0, found 1)" in failures


def test_closed_inventory_rejects_spawn_turbofish_and_comment(tmp_path: Path) -> None:
    module = load_guard_module()
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)
    source = tmp_path / "crates/iroha_torii/src/turbofish.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn run(handle: Handle, task: Task) {\n"
        "    handle.spawn::<_>(task);\n"
        "    handle.spawn /* spelling gap */ (task);\n"
        "}\n",
        encoding="utf-8",
    )

    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert "Torii task_spawn site count drifted (expected 0, found 2)" in failures


def test_closed_inventory_binds_external_build_support_source(tmp_path: Path) -> None:
    module = load_guard_module()
    manifest = tmp_path / "crates/iroha_torii/Cargo.toml"
    build_script = tmp_path / "crates/build-support/script.rs"
    build_library = tmp_path / "crates/build-support/src/lib.rs"
    manifest.parent.mkdir(parents=True)
    build_library.parent.mkdir(parents=True)
    manifest.write_text(
        '[package]\nname = "iroha_torii"\nbuild = "../build-support/script.rs"\n',
        encoding="utf-8",
    )
    build_script.write_text("fn main() { build_support::emit(); }\n", encoding="utf-8")
    build_library.write_text("pub fn emit() {}\n", encoding="utf-8")
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    build_library.write_text(
        "pub fn emit() { std::thread::spawn(|| panic!(\"build panic\")); }\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )

    assert any("source inventory drifted" in failure for failure in failures)


def test_source_closure_rejects_symlink_indirection(tmp_path: Path) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    build_support = tmp_path / "crates/build-support"
    outside = tmp_path / "outside.rs"
    torii.mkdir(parents=True)
    build_support.mkdir(parents=True)
    (torii / "Cargo.toml").write_text(
        '[package]\nname = "iroha_torii"\nbuild = "../build-support/script.rs"\n',
        encoding="utf-8",
    )
    (build_support / "script.rs").write_text("fn main() {}\n", encoding="utf-8")
    outside.write_text("pub fn outside() {}\n", encoding="utf-8")
    (torii / "outside.rs").symlink_to(outside)

    failures = module.torii_source_path_failures(tmp_path)

    assert failures == [
        "crates/iroha_torii/outside.rs: symlink is forbidden in the audited source closure"
    ]


def test_source_closure_rejects_shared_writable_parent_directory(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    build_support = tmp_path / "crates/build-support"
    torii.mkdir(parents=True)
    build_support.mkdir(parents=True)
    (torii / "Cargo.toml").write_text(
        '[package]\nname = "iroha_torii"\nbuild = "../build-support/script.rs"\n',
        encoding="utf-8",
    )
    (build_support / "script.rs").write_text("fn main() {}\n", encoding="utf-8")
    build_support.chmod(0o777)

    failures = module.torii_source_path_failures(tmp_path)

    assert (
        "crates/build-support: audited source parent must not be group- or "
        "world-writable"
    ) in failures


def test_source_closure_rejects_unreviewed_build_script_path(tmp_path: Path) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    build_support = tmp_path / "crates/build-support"
    torii.mkdir(parents=True)
    build_support.mkdir(parents=True)
    (build_support / "script.rs").write_text("fn main() {}\n", encoding="utf-8")
    (torii / "Cargo.toml").write_text(
        '[package]\nname = "iroha_torii"\nbuild = "../../outside.rs"\n',
        encoding="utf-8",
    )

    failures = module.torii_source_path_failures(tmp_path)

    assert (
        "crates/iroha_torii/Cargo.toml: package build script escapes the audited "
        "source roots: ../../outside.rs"
    ) in failures
    # Generic Cargo target closure remains the sole build-source boundary.
    assert len(failures) == 1


def test_source_closure_rejects_escaping_explicit_cargo_targets(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    build_support = tmp_path / "crates/build-support"
    torii.mkdir(parents=True)
    build_support.mkdir(parents=True)
    (build_support / "script.rs").write_text("fn main() {}\n", encoding="utf-8")
    (tmp_path / "outside.rs").write_text("fn main() {}\n", encoding="utf-8")
    (torii / "Cargo.toml").write_text(
        '[package]\nname = "iroha_torii"\nbuild = "../build-support/script.rs"\n'
        '[lib]\npath = "../../outside.rs"\n'
        '[[bin]]\nname = "escape"\npath = "../../outside.rs"\n'
        '[[example]]\nname = "escape"\npath = "../../outside.rs"\n'
        '[[test]]\nname = "escape"\npath = "../../outside.rs"\n'
        '[[bench]]\nname = "escape"\npath = "../../outside.rs"\n',
        encoding="utf-8",
    )

    failures = module.torii_source_path_failures(tmp_path)

    for label in (
        "lib target",
        "bin target #1",
        "example target #1",
        "test target #1",
        "bench target #1",
    ):
        assert any(
            f"Cargo.toml: {label} escapes the audited source roots: ../../outside.rs"
            in failure
            for failure in failures
        )


def test_source_closure_rejects_unsealed_explicit_cargo_target(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    build_support = tmp_path / "crates/build-support"
    source = torii / "src/generated.rs"
    source.parent.mkdir(parents=True)
    build_support.mkdir(parents=True)
    (build_support / "script.rs").write_text("fn main() {}\n", encoding="utf-8")
    source.write_text("fn main() {}\n", encoding="utf-8")
    manifest = torii / "Cargo.toml"
    manifest.write_text(
        '[package]\nname = "iroha_torii"\nbuild = "../build-support/script.rs"\n'
        '[[bin]]\nname = "generated"\npath = "src/generated.rs"\n',
        encoding="utf-8",
    )
    sealed = {manifest.resolve(), (build_support / "script.rs").resolve()}
    monkeypatch.setattr(
        module,
        "torii_audited_files",
        lambda _root: sorted(sealed),
    )

    failures = module.torii_source_path_failures(tmp_path)

    assert (
        "crates/iroha_torii/Cargo.toml: bin target #1 is outside the sealed "
        "repository-file inventory: src/generated.rs"
    ) in failures


def test_source_closure_rejects_gitlinks_under_audited_roots(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    torii.mkdir(parents=True)
    gitlink = Path("crates/iroha_torii/vendor/provider")
    monkeypatch.setattr(
        module,
        "_git_audited_entries",
        lambda _root: [("160000", gitlink)],
    )

    failures = module.torii_source_path_failures(tmp_path)

    assert (
        "crates/iroha_torii/vendor/provider: gitlink/submodule is forbidden in "
        "the audited source closure"
    ) in failures


def test_source_closure_rejects_unresolved_git_index_stages(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    torii.mkdir(parents=True)
    conflicted = Path("crates/iroha_torii/src/lib.rs")
    monkeypatch.setattr(
        module,
        "_git_audited_entries",
        lambda _root: [("conflict:2:100644", conflicted)],
    )

    failures = module.torii_source_path_failures(tmp_path)

    assert (
        "crates/iroha_torii/src/lib.rs: unresolved Git index stage 2 is forbidden "
        "in the audited source closure"
    ) in failures


def test_source_closure_inventories_transitive_non_rs_include(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/lib.rs"
    included = tmp_path / "crates/iroha_torii/src/worker.inc"
    source.parent.mkdir(parents=True)
    source.write_text('include!("worker.inc");\n', encoding="utf-8")
    included.write_text(
        "fn run() { tokio::spawn(async { work().await }); }\n",
        encoding="utf-8",
    )
    expected_records, _, counts = module.torii_boundary_inventory(tmp_path)

    assert any(
        record.startswith("crates/iroha_torii/src/worker.inc\t")
        for record in expected_records
    )
    assert counts["task_spawn"] == 1

    included.write_text(
        "fn run() { tokio::spawn(async { changed().await }); }\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )
    assert not any("site count drifted" in failure for failure in failures)
    assert any("source inventory drifted" in failure for failure in failures)


def test_source_closure_inventories_brace_and_bracket_includes(tmp_path: Path) -> None:
    module = load_guard_module()
    for label, invocation in (
        ("brace", 'include! { "worker.inc" }\n'),
        ("bracket", 'include!["worker.inc"]\n'),
    ):
        root = tmp_path / label
        source = root / "crates/iroha_torii/src/lib.rs"
        included = root / "crates/iroha_torii/src/worker.inc"
        source.parent.mkdir(parents=True)
        source.write_text(invocation, encoding="utf-8")
        included.write_text(
            "fn run() { tokio::spawn(async { work().await }); }\n",
            encoding="utf-8",
        )
        expected_records, _, counts = module.torii_boundary_inventory(root)
        assert any(
            record.startswith("crates/iroha_torii/src/worker.inc\t")
            for record in expected_records
        )
        assert counts["task_spawn"] == 1

        included.write_text(
            "fn run() { tokio::spawn(async { changed().await }); }\n",
            encoding="utf-8",
        )
        failures = module.closed_torii_boundary_inventory_failures(
            root, expected_records
        )
        assert not any("site count drifted" in failure for failure in failures)
        assert any("source inventory drifted" in failure for failure in failures)


def test_source_closure_rejects_escaped_include_and_path_attribute(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source_root = tmp_path / "crates/iroha_torii/src"
    source_root.mkdir(parents=True)
    (tmp_path / "outside.rs").write_text("fn outside() {}\n", encoding="utf-8")
    (source_root / "included.rs").write_text(
        'include!("../../../outside.rs");\n', encoding="utf-8"
    )
    (source_root / "module.rs").write_text(
        '#[path = "../../../outside.rs"]\nmod outside;\n', encoding="utf-8"
    )

    failures = module.torii_source_path_failures(tmp_path)

    assert any(
        "included.rs:1: include! source path escapes the audited source roots"
        in failure
        for failure in failures
    )
    assert any(
        "module.rs:1: #[path] source path escapes the audited source roots"
        in failure
        for failure in failures
    )


def test_source_closure_rejects_dynamic_include_path(tmp_path: Path) -> None:
    module = load_guard_module()
    source = tmp_path / "crates/iroha_torii/src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        'include!(concat!("worker", ".inc"));\n', encoding="utf-8"
    )

    failures = module.torii_source_path_failures(tmp_path)

    assert any(
        "lib.rs:1: include! must name one static local source file" in failure
        for failure in failures
    )


def test_complete_file_closure_binds_nested_inline_module_path_target(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    source_root = tmp_path / "crates/iroha_torii/src"
    nested = source_root / "outer/worker.inc"
    decoy = source_root / "worker.inc"
    nested.parent.mkdir(parents=True)
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "lib.rs").write_text(
        'mod outer { #[path = "worker.inc"] mod worker; }\n', encoding="utf-8"
    )
    decoy.write_text("fn decoy() {}\n", encoding="utf-8")
    nested.write_text(
        "fn run() { tokio::spawn(async { work().await }); }\n",
        encoding="utf-8",
    )
    expected_records, _, _ = module.torii_boundary_inventory(tmp_path)

    assert any(
        record.startswith("crates/iroha_torii/src/outer/worker.inc\t")
        for record in expected_records
    )
    nested.write_text(
        "fn run() { tokio::spawn(async { changed().await }); }\n",
        encoding="utf-8",
    )
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, expected_records
    )
    assert any("source inventory drifted" in failure for failure in failures)


def test_source_closure_rejects_ignored_conventional_module(tmp_path: Path) -> None:
    module = load_guard_module()
    source_root = tmp_path / "crates/iroha_torii/src"
    source_root.mkdir(parents=True)
    root_source = source_root / "lib.rs"
    hidden = source_root / "hidden.rs"
    root_source.write_text("mod hidden;\n", encoding="utf-8")
    hidden.write_text(
        "fn run() { tokio::task::spawn_blocking(|| provider_call()); }\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text(
        "crates/iroha_torii/src/hidden.rs\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "add", ".gitignore", "crates/iroha_torii/src/lib.rs"],
        cwd=tmp_path,
        check=True,
    )

    records, _, counts = module.torii_boundary_inventory(tmp_path)
    failures = module.torii_source_path_failures(tmp_path)

    assert any(
        record.startswith("crates/iroha_torii/src/hidden.rs\t")
        for record in records
    )
    assert counts["spawn_blocking"] == 1
    assert (
        "crates/iroha_torii/src/hidden.rs: textual module source is outside the "
        "sealed repository-file inventory"
    ) in failures


def test_source_closure_rejects_ignored_auto_discovered_cargo_target(
    tmp_path: Path,
) -> None:
    module = load_guard_module()
    crate_root = tmp_path / "crates/iroha_torii"
    hidden = crate_root / "src/bin/hidden.rs"
    hidden.parent.mkdir(parents=True)
    (crate_root / "Cargo.toml").write_text(
        '[package]\nname = "guard-fixture"\nversion = "0.0.0"\n'
        'build = "../build-support/script.rs"\n',
        encoding="utf-8",
    )
    build_script = tmp_path / "crates/build-support/script.rs"
    build_script.parent.mkdir(parents=True)
    build_script.write_text("fn main() {}\n", encoding="utf-8")
    hidden.write_text(
        "fn main() { tokio::task::spawn_blocking(|| provider_call()); }\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text(
        "crates/iroha_torii/src/bin/hidden.rs\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "add",
            ".gitignore",
            "crates/iroha_torii/Cargo.toml",
            "crates/build-support/script.rs",
        ],
        cwd=tmp_path,
        check=True,
    )

    records, _, counts = module.torii_boundary_inventory(tmp_path)
    failures = module.torii_source_path_failures(tmp_path)

    assert any(
        record.startswith("crates/iroha_torii/src/bin/hidden.rs\t")
        for record in records
    )
    assert counts["spawn_blocking"] == 1
    assert (
        "crates/iroha_torii/src/bin/hidden.rs: textual module source is outside "
        "the sealed repository-file inventory"
    ) in failures


@pytest.mark.parametrize(
    ("section", "auto_switch", "source_relative"),
    (
        ("bin", "autobins", "src/main.rs"),
        ("example", "autoexamples", "examples/hidden.rs"),
        ("test", "autotests", "tests/hidden.rs"),
        ("bench", "autobenches", "benches/hidden.rs"),
    ),
)
def test_source_closure_rejects_ignored_inferred_explicit_cargo_target(
    tmp_path: Path,
    section: str,
    auto_switch: str,
    source_relative: str,
) -> None:
    module = load_guard_module()
    crate_root = tmp_path / "crates/iroha_torii"
    hidden = crate_root / source_relative
    hidden.parent.mkdir(parents=True)
    (crate_root / "Cargo.toml").write_text(
        '[package]\nname = "guard-fixture"\nversion = "0.0.0"\n'
        f'{auto_switch} = false\nbuild = "../build-support/script.rs"\n\n'
        f'[[{section}]]\nname = "hidden"\n',
        encoding="utf-8",
    )
    build_script = tmp_path / "crates/build-support/script.rs"
    build_script.parent.mkdir(parents=True)
    build_script.write_text("fn main() {}\n", encoding="utf-8")
    hidden.write_text(
        "fn main() { tokio::task::spawn_blocking(|| provider_call()); }\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text(
        f"crates/iroha_torii/{source_relative}\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "add",
            ".gitignore",
            "crates/iroha_torii/Cargo.toml",
            "crates/build-support/script.rs",
        ],
        cwd=tmp_path,
        check=True,
    )

    records, _, counts = module.torii_boundary_inventory(tmp_path)
    failures = module.torii_source_path_failures(tmp_path)
    relative = f"crates/iroha_torii/{source_relative}"

    assert any(record.startswith(f"{relative}\t") for record in records)
    assert counts["spawn_blocking"] == 1
    assert any(
        relative in failure
        and "outside the sealed repository-file inventory" in failure
        for failure in failures
    )


@pytest.mark.parametrize(
    ("target_declaration", "target_root_relative", "real_module_relative"),
    (
        ('[lib]\npath = "src/custom.rs"\n', "src/custom.rs", "src/hidden.rs"),
        (
            'autobins = false\n\n[[bin]]\nname = "custom"\npath = "src/custom.rs"\n',
            "src/custom.rs",
            "src/hidden.rs",
        ),
        (
            'build = "../build-support/custom.rs"\n',
            "../build-support/custom.rs",
            "../build-support/hidden.rs",
        ),
    ),
)
def test_source_closure_resolves_modules_from_arbitrary_cargo_target_roots(
    tmp_path: Path,
    target_declaration: str,
    target_root_relative: str,
    real_module_relative: str,
) -> None:
    module = load_guard_module()
    crate_root = tmp_path / "crates/iroha_torii"
    manifest = crate_root / "Cargo.toml"
    target_root = crate_root / target_root_relative
    real_module = crate_root / real_module_relative
    decoy = target_root.parent / target_root.stem / "hidden.rs"
    manifest.parent.mkdir(parents=True)
    target_root.parent.mkdir(parents=True, exist_ok=True)
    real_module.parent.mkdir(parents=True, exist_ok=True)
    decoy.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        '[package]\nname = "guard-fixture"\nversion = "0.0.0"\n'
        + target_declaration,
        encoding="utf-8",
    )
    target_root.write_text("mod hidden;\n", encoding="utf-8")
    real_module.write_text(
        "fn run() { tokio::task::spawn_blocking(|| provider_call()); }\n",
        encoding="utf-8",
    )
    decoy.write_text("fn decoy() {}\n", encoding="utf-8")
    relative_real = real_module.resolve().relative_to(tmp_path.resolve()).as_posix()
    (tmp_path / ".gitignore").write_text(f"/{relative_real}\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "add", ".gitignore", str(manifest), str(target_root), str(decoy)],
        cwd=tmp_path,
        check=True,
    )

    records, _, counts = module.torii_boundary_inventory(tmp_path)
    failures = module.torii_source_path_failures(tmp_path)

    assert any(record.startswith(f"{relative_real}\t") for record in records)
    assert counts["spawn_blocking"] == 1
    assert any(
        relative_real in failure
        and "outside the sealed repository-file inventory" in failure
        for failure in failures
    )


def test_source_closure_resolves_nested_inline_path_before_sealing(tmp_path: Path) -> None:
    module = load_guard_module()
    source_root = tmp_path / "crates/iroha_torii/src"
    nested = source_root / "outer/worker.inc"
    decoy = source_root / "worker.inc"
    nested.parent.mkdir(parents=True)
    root_source = source_root / "lib.rs"
    root_source.write_text(
        'mod outer { #[path = "worker.inc"] mod worker; }\n', encoding="utf-8"
    )
    decoy.write_text("fn decoy() {}\n", encoding="utf-8")
    nested.write_text(
        "fn run() { tokio::task::spawn_blocking(|| provider_call()); }\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text(
        "crates/iroha_torii/src/outer/worker.inc\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "add",
            ".gitignore",
            "crates/iroha_torii/src/lib.rs",
            "crates/iroha_torii/src/worker.inc",
        ],
        cwd=tmp_path,
        check=True,
    )

    records, _, counts = module.torii_boundary_inventory(tmp_path)
    failures = module.torii_source_path_failures(tmp_path)

    assert any(
        record.startswith("crates/iroha_torii/src/outer/worker.inc\t")
        for record in records
    )
    assert counts["spawn_blocking"] == 1
    assert (
        "crates/iroha_torii/src/outer/worker.inc: textual module source is outside "
        "the sealed repository-file inventory"
    ) in failures


def test_relocated_token_issuance_retains_bounded_worker_owner() -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    relative = "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs"
    source = (root / relative).read_text(encoding="utf-8")
    parent = (root / "crates/iroha_torii/src/sorafs/api.rs").read_text(encoding="utf-8")
    assert relative in module.NO_BARE_BLOCKING
    assert parent.count('include!("api/storage_token_issuance.rs");') == 1
    assert "async fn handle_post_sorafs_storage_token_authenticated(" not in parent
    assert source.count("async fn handle_post_sorafs_storage_token_authenticated(") == 1
    assert source.count(".issue_token(") == 1
    assert module._bare_blocking_lines(source) == []
    assert module._required_recovery_marker_failures(relative, source) == []
    for required in module.REQUIRED_SNIPPETS[relative]:
        assert required in source
        tampered = source.replace(required, "removed_worker_boundary", 1)
        assert module._required_recovery_marker_failures(relative, tampered) == [
            f"{relative}: missing audited recovery marker {required!r}"
        ]


@pytest.mark.parametrize("raw_spawn", ["tokio::task::spawn_blocking", "handle.spawn_blocking"])
def test_relocated_token_issuance_rejects_bare_worker_substitution(raw_spawn: str) -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    relative = "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs"
    source = (root / relative).read_text(encoding="utf-8")
    guarded = 'sorafs_heavy_blocking_task(&state, "SoraFS token issuance", move ||'
    assert guarded in source
    tampered = source.replace(guarded, f"{raw_spawn}(move ||", 1)
    assert module._bare_blocking_lines(tampered)
    assert guarded not in tampered


def test_required_recovery_marker_helper_preserves_original_owner_diagnostics() -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    relative = "crates/iroha_torii/src/sorafs/api.rs"
    source = (root / relative).read_text(encoding="utf-8")
    assert module._required_recovery_marker_failures(relative, source) == []
    missing = module.REQUIRED_SNIPPETS[relative]
    for required in missing:
        source = source.replace(required, "removed_original_worker_owner")
    assert module._required_recovery_marker_failures(relative, source) == [
        f"{relative}: missing audited recovery marker {required!r}"
        for required in missing
    ]


@pytest.mark.parametrize("relative", [
    "crates/iroha_torii/src/sorafs/api/stream_token_enforcement.rs",
    "crates/iroha_torii/src/sorafs/api/stream_token_body.rs",
    "crates/iroha_torii/src/sorafs/stream_token_cleanup.rs",
])
def test_range_lease_workers_retain_physical_owner_markers(relative: str) -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    source = (root / relative).read_text(encoding="utf-8")
    assert relative in module.NO_BARE_BLOCKING
    assert module._bare_blocking_lines(source) == []
    assert module._required_recovery_marker_failures(relative, source) == []
    for required in module.REQUIRED_SNIPPETS[relative]:
        # Remove every occurrence: the body deliberately checks the lease twice.
        tampered = source.replace(required, "removed_range_lease_worker_boundary")
        assert module._required_recovery_marker_failures(relative, tampered) == [
            f"{relative}: missing audited recovery marker {required!r}"
        ]


@pytest.mark.parametrize("relative, guarded", [
    ("crates/iroha_torii/src/sorafs/api/stream_token_enforcement.rs",
     'sorafs_heavy_blocking_task(state, "SoraFS stream-token admission", move ||'),
    ("crates/iroha_torii/src/sorafs/api/stream_token_body.rs",
     'sorafs_heavy_blocking_task(state, "SoraFS chunk read", move ||'),
    ("crates/iroha_torii/src/sorafs/stream_token_cleanup.rs",
     "crate::panic_recovery::spawn_blocking_recoverable(move ||"),
])
@pytest.mark.parametrize("raw_spawn", ["tokio::task::spawn_blocking", "handle.spawn_blocking"])
def test_range_lease_workers_reject_bare_physical_substitution(
    relative: str, guarded: str, raw_spawn: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    source = (root / relative).read_text(encoding="utf-8")
    assert guarded in source
    assert module._bare_blocking_lines(source) == []
    tampered = source.replace(guarded, f"{raw_spawn}(move ||", 1)
    assert module._bare_blocking_lines(tampered)


@pytest.mark.parametrize("build", [None, False, "../build-support/script.rs", "build.rs"])
def test_source_closure_uses_actual_cargo_build_target_or_none(tmp_path: Path, build) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    support = tmp_path / "crates/build-support"
    (torii / "src").mkdir(parents=True)
    support.mkdir(parents=True)
    (torii / "src/lib.rs").write_text("pub fn library() {}\n", encoding="utf-8")
    manifest = '[package]\nname = "iroha_torii"\n'
    if build is False:
        manifest += 'build = false\n'
    elif build is not None:
        manifest += f'build = "{build}"\n'
        (torii / build).write_text("fn main() {}\n", encoding="utf-8")
    (torii / "Cargo.toml").write_text(manifest, encoding="utf-8")
    assert module.torii_source_path_failures(tmp_path) == []
    records, _, _ = module.torii_boundary_inventory(tmp_path)
    if isinstance(build, str):
        rel = (torii / build).resolve().relative_to(tmp_path).as_posix()
        assert any(record.startswith(rel + "\t") for record in records)
    else:
        assert not any("/build.rs\t" in record or "/script.rs\t" in record for record in records)


def test_source_closure_binds_auto_discovered_build_script(tmp_path: Path) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    torii.mkdir(parents=True)
    (tmp_path / "crates/build-support").mkdir(parents=True)
    (torii / "Cargo.toml").write_text('[package]\nname = "iroha_torii"\n', encoding="utf-8")
    script = torii / "build.rs"
    script.write_text("fn main() {}\n", encoding="utf-8")
    assert module.torii_source_path_failures(tmp_path) == []
    expected, _, _ = module.torii_boundary_inventory(tmp_path)
    script.write_text("fn main() { std::thread::spawn(|| {}); }\n", encoding="utf-8")
    failures = module.closed_torii_boundary_inventory_failures(tmp_path, expected)
    assert "Torii task_spawn site count drifted (expected 0, found 1)" in failures
    assert any("source inventory drifted" in failure for failure in failures)


def test_source_closure_rejects_ignored_auto_build_script(tmp_path: Path) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    torii.mkdir(parents=True)
    (tmp_path / "crates/build-support").mkdir(parents=True)
    (torii / "Cargo.toml").write_text('[package]\nname = "iroha_torii"\n', encoding="utf-8")
    (torii / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("build.rs\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "crates/iroha_torii/Cargo.toml"], cwd=tmp_path, check=True)
    failures = module.torii_source_path_failures(tmp_path)
    assert any("auto-discovered package build script is outside the sealed repository-file inventory: build.rs" in failure for failure in failures)


def test_source_closure_rejects_symlinked_auto_build_script(tmp_path: Path) -> None:
    module = load_guard_module()
    torii = tmp_path / "crates/iroha_torii"
    torii.mkdir(parents=True)
    (tmp_path / "crates/build-support").mkdir(parents=True)
    (torii / "Cargo.toml").write_text('[package]\nname = "iroha_torii"\n', encoding="utf-8")
    outside = tmp_path / "outside.rs"
    outside.write_text("fn main() {}\n", encoding="utf-8")
    (torii / "build.rs").symlink_to(outside)
    failures = module.torii_source_path_failures(tmp_path)
    assert any("symlink is forbidden" in failure for failure in failures)
    assert any("auto-discovered package build script escapes the audited source roots" in failure for failure in failures)



def test_token_issuance_finalized_policy_worker_accepts_nonsemantic_growth() -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    source = (root / "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs").read_text(encoding="utf-8")
    assert module._token_issuance_worker_policy_failures(source) == []
    grown = source.replace("let policy = account", "/* " + "\n" * 25_000 + " */\nlet policy = account", 1)
    assert len(grown) > len(source) + 25_000
    assert module._token_issuance_worker_policy_failures(grown) == []
    reformatted = source.replace("let issuance_result =", "let\n    issuance_result =")
    assert reformatted != source
    assert module._token_issuance_worker_policy_failures(reformatted) == []


def test_current_public_recovery_helpers_retain_audited_markers() -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    relative = "crates/iroha_torii/src/panic_recovery.rs"
    source = (root / relative).read_text(encoding="utf-8")
    assert module._required_recovery_marker_failures(relative, source) == []
    for marker in module.REQUIRED_SNIPPETS[relative]:
        assert marker in source
        mutated = source.replace(marker, "removed_audited_helper", 1)
        assert module._required_recovery_marker_failures(relative, mutated) == [
            f"{relative}: missing audited recovery marker {marker!r}"
        ]


def _rust_fragment_span(module, source: str, fragment: str) -> tuple[int, int]:
    """Locate the first code-token sequence, independent of Rust formatting and comments."""
    tokens = module._rust_tokens(source)
    expected = [token.text for token in module._rust_tokens(fragment)]
    assert expected
    for index in range(len(tokens) - len(expected) + 1):
        if [token.text for token in tokens[index:index + len(expected)]] == expected:
            return tokens[index].start, tokens[index + len(expected) - 1].end
    raise AssertionError(f"missing original Rust fragment: {fragment!r}")


@pytest.mark.parametrize("old,new", [
    ("let worker_state = state.state.clone();", "let worker_state = detached_state;"),
    ("let worker_issuer = Arc::clone(&issuer);", "let worker_issuer = issuer;"),
    ("let policy = account", "let policy = other_account"),
    (".transpose()?;", ".transpose().unwrap_or(None);"),
    ("let issuance_result = worker_issuer.issue_token(", "let issuance_result = detached_issuer.issue_token("),
    ("policy.as_ref(),", "None,"),
    ("if let Some(account) = &account {", "if false { let account = &account;"),
    ("if Some(current_account_read_policy(", "if Some(stale_account_read_policy("),
    ("            )?) != policy", "            ).ok()) != policy"),
    ("            )?) != policy", "            )?) == policy"),
    ('"account-read policy changed during token issuance"', '"ignore changed policy"'),
    ('StatusCode::FORBIDDEN, "account-read policy changed during token issuance"', 'StatusCode::OK, "account-read policy changed during token issuance"'),
    ("Ok(issuance_result) })", "Ok(foreign_issued) })"),
    ("Ok(issuance_result) => issuance_result, Err(response) => return response, };", "Ok(issuance_result) => issuance_result, Err(_response) => Ok(fallback_token()), };"),
])
def test_token_issuance_finalized_policy_worker_refuses_owner_and_policy_mutations(old: str, new: str) -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    source = (root / "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs").read_text(encoding="utf-8")
    start, end = _rust_fragment_span(module, source, old)
    mutated = source[:start] + new + source[end:]
    assert mutated != source
    assert module._token_issuance_worker_policy_failures(mutated) == [
        "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs: token issuance lost its bounded owned pre/post policy worker"
    ]


def test_token_issuance_policy_reads_cannot_be_reordered_or_move_outside_worker() -> None:
    root = Path(__file__).resolve().parents[2]
    module = load_guard_module()
    source = (root / "crates/iroha_torii/src/sorafs/api/storage_token_issuance.rs").read_text(encoding="utf-8")
    prefix, _ = _rust_fragment_span(module, source, "let policy = account")
    issue, _ = _rust_fragment_span(module, source, "let issuance_result = worker_issuer.issue_token(")
    recheck, _ = _rust_fragment_span(module, source, "if let Some(account) = &account {")
    result, _ = _rust_fragment_span(module, source, "Ok(issuance_result) })")
    policy = source[prefix:issue]
    issuance = source[issue:recheck]
    check = source[recheck:result]
    suffix = source[result:]
    mutations = [
        source[:prefix] + issuance + policy + check + suffix,
        source[:prefix] + policy + check + issuance + suffix,
        check + source[:recheck] + suffix,
        source[:recheck] + suffix + check,
        "/* " + check + " */\n" + source[:recheck] + suffix,
    ]
    for mutated in mutations:
        assert mutated != source
        assert module._token_issuance_worker_policy_failures(mutated)


@pytest.mark.parametrize("relative", [
    "crates/iroha_core/src/executor_stream_token_gateway_direct_source_tests.rs",
    "crates/iroha_core/src/executor_stream_token_gateway_permission_tests.rs",
    "crates/iroha_core/src/executor_stream_token_gateway_check_permission_tests.rs",
    "crates/iroha_core/src/executor/private_fees.rs",
])
def test_current_core_recovery_children_are_explicit_finite_support_paths(tmp_path: Path, relative: str) -> None:
    module = load_guard_module()
    assert module.CORE_RECOVERY_SUPPORT_PATHS.count(Path(relative)) == 1
    assert module.AUDITED_SOURCE_PATHS.count(Path(relative)) == 1
    assert Path("crates/iroha_core/src") not in module.AUDITED_SOURCE_PATHS
    test_core_recovery_support_seals_exact_permission_include(tmp_path, relative)


def test_current_raw_review_accepts_complete_shared_owner_move_and_refuses_legacy_return(
    tmp_path: Path,
) -> None:
    """Bind a reviewed current source move without an invented Git history chain."""
    module = load_guard_module()
    crate = tmp_path / "crates/iroha_core_zk"
    source = crate / "src"
    source.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "current_raw_move_fixture"\nversion = "0.0.0"\n'
        '[lib]\npath = "src/lib.rs"\n',
        encoding="utf-8",
    )
    (source / "lib.rs").write_text("mod claim;\n", encoding="utf-8")
    claim = source / "claim.rs"
    claim.write_text(
        "mod streaming;\npub(crate) fn run() { streaming::original_policy(); }\n",
        encoding="utf-8",
    )
    legacy = source / "claim/streaming.rs"
    legacy.parent.mkdir()
    implementation = "pub(crate) fn original_policy() { let checked = true; assert!(checked); }\n"
    legacy.write_text(implementation, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "crates/iroha_core_zk"], cwd=tmp_path, check=True)
    original = module.torii_boundary_inventory(tmp_path)
    assert original[2] == {kind: 0 for kind in module.BOUNDARY_IDENTIFIERS}
    assert module.closed_torii_boundary_inventory_failures(
        tmp_path, original[0], observed_inventory=original,
    ) == []

    # The caller now uses the one shared implementation; the retired path is gone.
    shared = source / "carrier.rs"
    shared.write_text(implementation, encoding="utf-8")
    legacy.unlink()
    (source / "lib.rs").write_text("mod carrier;\nmod claim;\n", encoding="utf-8")
    claim.write_text(
        "pub(crate) fn run() { crate::carrier::original_policy(); }\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "--all", "crates/iroha_core_zk"], cwd=tmp_path, check=True)
    sources, errors = module.torii_rust_source_closure(tmp_path)
    assert errors == []
    assert shared.resolve() in sources
    assert legacy not in sources
    current = module.torii_boundary_inventory(tmp_path)
    assert current[2] == original[2]
    assert current[1] != original[1]
    assert any("source inventory drifted" in failure for failure in
        module.closed_torii_boundary_inventory_failures(
            tmp_path, original[0], observed_inventory=current,
        ))

    # Approval is the exact current raw census, rather than unavailable historical
    # commits. The fixture deliberately has no HEAD or commit objects.
    no_head = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert no_head.returncode != 0
    reviewed = tmp_path / module.REVIEWED_TORII_BOUNDARY_INVENTORY
    reviewed.parent.mkdir(parents=True)
    reviewed.write_text("\n".join(current[0]) + "\n", encoding="utf-8")
    assert module.closed_torii_boundary_inventory_failures(
        tmp_path, observed_inventory=current,
    ) == []

    # Neither a parallel retired source nor a changed non-boundary caller can be
    # accepted merely because catch/task/blocking/upgrade counts still match.
    legacy.write_text(implementation, encoding="utf-8")
    returned = module.torii_boundary_inventory(tmp_path)
    assert returned[2] == current[2]
    assert any("source inventory drifted" in failure for failure in
        module.closed_torii_boundary_inventory_failures(
            tmp_path, observed_inventory=returned,
        ))
    legacy.unlink()
    claim.write_text(
        "pub(crate) fn run() { let ignored = true; assert!(ignored); }\n",
        encoding="utf-8",
    )
    changed_caller = module.torii_boundary_inventory(tmp_path)
    assert changed_caller[2] == current[2]
    assert any("source inventory drifted" in failure for failure in
        module.closed_torii_boundary_inventory_failures(
            tmp_path, observed_inventory=changed_caller,
        ))


def test_reviewed_native_sns_attempt_include_seals_full_raw_caller(tmp_path: Path) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    parent.mkdir(parents=True)
    executor = parent / "executor.rs"
    included = parent / "executor_sns_attempt_tests.rs"
    executor.write_text('#[cfg(test)] mod tests { include!("executor_sns_attempt_tests.rs"); }\n', encoding="utf-8")
    included.write_text("fn native_attempt_caller() { original_permission(); }\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert included.resolve() in sources
    assert Path("crates/iroha_core/src/executor_sns_attempt_tests.rs") in module.CORE_RECOVERY_SUPPORT_PATHS
    records, _, counts = module.torii_boundary_inventory(tmp_path, sources)
    included.write_text("fn native_attempt_caller() { substituted_permission(); }\n", encoding="utf-8")
    observed = module.torii_boundary_inventory(tmp_path)
    assert observed[2] == counts
    failures = module.closed_torii_boundary_inventory_failures(tmp_path, records, observed_inventory=observed)
    assert any("source inventory drifted" in error for error in failures), failures


def test_nested_amx_support_resolves_from_original_tests_module_directory(tmp_path: Path) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    scope = parent / "executor/root_scope.rs"
    tests = parent / "executor/root_scope/tests.rs"
    actual = parent / "executor/root_scope/tests/amx_roles.rs"
    actual.parent.mkdir(parents=True)
    (parent / "executor.rs").write_text("pub(crate) mod root_scope;\n", encoding="utf-8")
    scope.write_text("#[cfg(test)] mod tests;\n", encoding="utf-8")
    tests.write_text("#[cfg(test)] mod amx_roles;\n", encoding="utf-8")
    actual.write_text("fn original_amx_role() { permission_matrix(); }\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert {scope.resolve(), tests.resolve(), actual.resolve()} <= set(sources)
    assert Path("crates/iroha_core/src/executor/root_scope/tests/amx_roles.rs") in module.CORE_RECOVERY_SUPPORT_PATHS
    assert Path("crates/iroha_core/src/executor/root_scope/amx_roles.rs") not in module.CORE_RECOVERY_SUPPORT_PATHS
    records, _, counts = module.torii_boundary_inventory(tmp_path, sources)
    actual.write_text("fn original_amx_role() { substituted_permission_matrix(); }\n", encoding="utf-8")
    observed = module.torii_boundary_inventory(tmp_path)
    assert observed[2] == counts
    failures = module.closed_torii_boundary_inventory_failures(tmp_path, records, observed_inventory=observed)
    assert any("source inventory drifted" in error for error in failures), failures


def test_nested_amx_support_refuses_missing_original_even_with_guessed_sibling(tmp_path: Path) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    scope = parent / "executor/root_scope.rs"
    tests = parent / "executor/root_scope/tests.rs"
    guessed = parent / "executor/root_scope/amx_roles.rs"
    tests.parent.mkdir(parents=True)
    (parent / "executor.rs").write_text("pub(crate) mod root_scope;\n", encoding="utf-8")
    scope.write_text("#[cfg(test)] mod tests;\n", encoding="utf-8")
    tests.write_text("#[cfg(test)] mod amx_roles;\n", encoding="utf-8")
    guessed.write_text("fn guessed_unreviewed_role() {}\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert guessed.resolve() not in sources
    assert failures == ["crates/iroha_core/src/executor/root_scope/tests.rs:1: mod must name one static local source file"]


@pytest.mark.parametrize("name", ("asset_lock_admission", "sns_attempt"))
def test_support_include_seals_full_original_caller(tmp_path: Path, name: str) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    parent.mkdir(parents=True)
    executor = parent / "executor.rs"
    included = parent / f"executor_{name}_tests.rs"
    executor.write_text(
        f'#[cfg(test)] mod tests {{ include!("executor_{name}_tests.rs"); }}\n',
        encoding="utf-8",
    )
    included.write_text("fn sns_attempt() { original_root_and_scope(); }\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert included.resolve() in sources
    assert Path(f"crates/iroha_core/src/executor_{name}_tests.rs") in module.CORE_RECOVERY_SUPPORT_PATHS
    records, _, counts = module.torii_boundary_inventory(tmp_path, sources)
    included.write_text("fn sns_attempt() { substituted_root_and_scope(); }\n", encoding="utf-8")
    observed = module.torii_boundary_inventory(tmp_path)
    assert observed[2] == counts
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, records, observed_inventory=observed,
    )
    assert any("source inventory drifted" in error for error in failures), failures


@pytest.mark.parametrize("name", ("asset_lock_admission", "sns_attempt"))
def test_support_include_refuses_absence_and_guessed_sibling(tmp_path: Path, name: str) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    parent.mkdir(parents=True)
    executor = parent / "executor.rs"
    original = parent / f"executor_{name}_tests.rs"
    guessed = parent / f"executor_{name}s_tests.rs"
    executor.write_text(
        f'#[cfg(test)] mod tests {{ include!("executor_{name}_tests.rs"); }}\n',
        encoding="utf-8",
    )
    guessed.write_text("fn guessed_attempt() {}\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert original.resolve() not in sources
    assert guessed.resolve() not in sources
    assert Path(f"crates/iroha_core/src/executor_{name}s_tests.rs") not in module.CORE_RECOVERY_SUPPORT_PATHS
    assert failures == [
        "crates/iroha_core/src/executor.rs:1: include! source path is missing "
        f"or not a regular file: executor_{name}_tests.rs"
    ]


@pytest.mark.parametrize("wrapper", (
    "fn test_only() { CALL }",
    "#[cfg(test)] mod parameter_tests { fn test_only() { CALL } }",
    "#[cfg(any(test, feature = \"production\"))] mod parameters { fn run() { CALL } }",
    "fn outer() { { CALL } }",
    "unreviewed_macro! { fn run() { CALL } }",
))
def test_raw_parameter_catches_have_no_test_or_production_exception(wrapper: str) -> None:
    module = load_guard_module()
    source = wrapper.replace("CALL", "std::panic::catch_unwind(|| work());")
    assert module._direct_raw_catch_unwind_lines(source) == [1]
    safe = wrapper.replace("CALL", "iroha_panic_hook::catch_unwind_suppressed(work);")
    assert module._direct_raw_catch_unwind_lines(safe) == []


@pytest.mark.parametrize("name", (
    "executor_runtime_memory_tests.rs",
    "executor_public_pin_admission_tests.rs",
    "executor_opaque_monetary_tests.rs",
))
def test_current_executor_path_children_seal_full_original_callers(
    tmp_path: Path, name: str,
) -> None:
    module = load_guard_module()
    relative = Path("crates/iroha_core/src") / name
    assert module.CORE_RECOVERY_SUPPORT_PATHS.count(relative) == 1
    assert module.AUDITED_SOURCE_PATHS.count(relative) == 1
    assert Path("crates/iroha_core/src") not in module.AUDITED_SOURCE_PATHS
    parent = tmp_path / "crates/iroha_core/src"
    parent.mkdir(parents=True)
    executor = parent / "executor.rs"
    included = parent / name
    executor.write_text(
        f'#[cfg(test)]\n#[path = "{name}"]\nmod original_caller;\n',
        encoding="utf-8",
    )
    included.write_text("fn original_caller() { original_custody_policy(); }\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert failures == []
    assert included.resolve() in sources
    records, _, counts = module.torii_boundary_inventory(tmp_path, sources)
    assert any(record.startswith(relative.as_posix() + "\t") for record in records)
    included.write_text("fn original_caller() { substituted_custody_policy(); }\n", encoding="utf-8")
    observed = module.torii_boundary_inventory(tmp_path)
    assert observed[2] == counts, "a caller mutation must be detected without an added panic boundary"
    failures = module.closed_torii_boundary_inventory_failures(
        tmp_path, records, observed_inventory=observed,
    )
    assert any("source inventory drifted" in error for error in failures), failures


@pytest.mark.parametrize("name", (
    "executor_runtime_memory_tests.rs",
    "executor_public_pin_admission_tests.rs",
    "executor_opaque_monetary_tests.rs",
))
def test_current_executor_path_children_refuse_absence_and_guessed_neighbor(
    tmp_path: Path, name: str,
) -> None:
    module = load_guard_module()
    parent = tmp_path / "crates/iroha_core/src"
    parent.mkdir(parents=True)
    original = parent / name
    guessed = parent / ("guessed_" + name)
    (parent / "executor.rs").write_text(
        f'#[cfg(test)]\n#[path = "{name}"]\nmod original_caller;\n',
        encoding="utf-8",
    )
    guessed.write_text("fn unreviewed_neighbor() {}\n", encoding="utf-8")
    sources, failures = module.torii_rust_source_closure(tmp_path)
    assert original.resolve() not in sources
    assert guessed.resolve() not in sources
    assert guessed.relative_to(tmp_path) not in module.CORE_RECOVERY_SUPPORT_PATHS
    assert failures == [
        f"crates/iroha_core/src/executor.rs:2: #[path] source path is missing or not a regular file: {name}"
    ]
