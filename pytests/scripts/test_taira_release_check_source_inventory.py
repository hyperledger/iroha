"""Early selected source inventory checks; no Cargo or live network required."""

import importlib.util
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/taira_release_check.py"
SPEC = importlib.util.spec_from_file_location("taira_release_check_source_inventory", SCRIPT)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class SelectedSourceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        helper = Path("scripts/formal/rust_text.py")
        (self.root / helper).parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT.parent / "formal/rust_text.py", self.root / helper)

    def source(self, package, path, text):
        source = self.root / "crates" / package / path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(text)

    def test_core_account_key_and_governance_dto_controls_are_exact_required_in_both_scopes(self):
        root = SCRIPT.parents[1]
        names = ('state::account_key_refusal_tests::upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry', 'state::account_key_refusal_tests::governance_lock_account_key_preserves_original_refusal_fields_scope_and_same_source_retry', 'state::account_key_refusal_tests::governance_slash_account_key_preserves_original_refusal_fields_scope_and_same_source_retry', 'state::account_key_refusal_tests::governance_locks_dto_keeps_exact_json_layout_and_rejects_duplicate_account_keys', 'state::account_key_refusal_tests::governance_slash_dto_keeps_exact_json_layout_and_rejects_duplicate_account_keys')
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)
            current = [name for _, cases in selected["core"] for name in cases]
            for name in names:
                with self.subTest(scope=scope, name=name):
                    self.assertEqual(current.count(name), 1)
                    focused = gate.focused_regression_stages(scope, ("core=" + name,))
                    self.assertEqual(tuple(focused), ("core",))
                    self.assertEqual([item for _, cases in focused["core"] for item in cases], [name])
                    gate.validate_selected_source_test_inventory(root, focused)
                    gate.require_tests(name + ": test", focused["core"])
                    listing = "\n".join(item + ": test" for item in current if item != name)
                    with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                        gate.require_tests(listing, selected["core"])

    def test_direct_and_generated_test_declarations_cover_selected_stages(self):
        self.source("iroha_torii", "src/routing.rs", """
            routing_test! { async selected_route { } }
            #[tokio::test] async fn selected_torii_unit() { }
        """)
        self.source("iroha_torii", "tests/taira_app_contracts.rs", """
            #[tokio::test] async fn selected_torii_integration() { }
        """)
        self.source("iroha_core", "src/lib.rs", """
            state_test! { sync selected_state { } }
            state_test!(consensus_stack selected_stack, {});
            source_contract_test!(selected_contract);
            world_test!(selected_apply, {});
            scenario_test!(selected_scenario, "F35", scenarios::f35);
        """)
        stages = {
            "torii-unit": (("router", ("routing::tests::selected_route",
                                        "routing::tests::selected_torii_unit")),),
            "torii": (("endpoint", ("tests::selected_torii_integration",)),),
            "core": (("reducer", ("sumeragi::selected_state", "sumeragi::selected_stack",
                                    "sumeragi::selected_contract", "sumeragi::selected_apply",
                                    "sim::tests::selected_scenario")),),
        }
        gate.validate_selected_source_test_inventory(self.root, stages)

    def test_explicit_cargo_test_target_is_required_when_autotests_are_disabled(self):
        self.source("iroha_config", "tests/fixtures.rs", "#[test] fn actual_case() {}")
        self.source("iroha_config", "tests/iroha_config_integration.rs", "mod fixtures;")
        manifest = self.root / "crates/iroha_config/Cargo.toml"
        manifest.write_text('[package]\nname="iroha_config"\nautotests=false\n'
                            '[[test]]\nname="iroha_config_integration"\npath="tests/iroha_config_integration.rs"\n')
        stages = {"config-fixtures": (("current fixture", ("fixtures::actual_case",)),)}
        gate.validate_selected_source_test_inventory(self.root, stages)
        stale = ("stale fixture target", "fixtures", "test", ["-p", "iroha_config", "--test", "fixtures"])
        with patch.dict(gate.HARNESS_TARGETS, {"config-fixtures": stale}):
            with self.assertRaisesRegex(gate.CheckError, r"autotests=false.*target fixtures"):
                gate.validate_selected_source_test_inventory(self.root, stages)
        manifest.write_text(manifest.read_text().replace('tests/iroha_config_integration.rs', 'tests/missing.rs'))
        with self.assertRaisesRegex(gate.CheckError, "target source is absent"):
            gate.validate_selected_source_test_inventory(self.root, stages)

    def test_missing_torii_integration_function_fails_before_cargo(self):
        self.source("iroha_torii", "src/lib.rs", "#[test] fn unrelated() {}")
        stages = {"torii": (("endpoint", ("tests::exact_missing_torii_case",)),)}
        with self.assertRaisesRegex(gate.CheckError,
                                    "torii: tests::exact_missing_torii_case"):
            gate.validate_selected_source_test_inventory(self.root, stages)

    def test_missing_selection_stops_lifecycle_checks_before_subprocesses(self):
        self.source("iroha_torii", "src/lib.rs", "#[test] fn unrelated() {}")
        stages = {"torii": (("endpoint", ("tests::exact_missing_torii_case",)),)}
        with patch.object(gate, "validate_mv_test_registration") as mv, \
             patch.object(gate.subprocess, "run") as subprocess, \
             patch.object(gate, "validate_native_consensus_test_registration") as standalone:
            with self.assertRaisesRegex(gate.CheckError,
                                        "torii: tests::exact_missing_torii_case"):
                gate.run_lifecycle_source_checks(self.root, {}, (), stages)
        mv.assert_not_called()
        subprocess.assert_not_called()
        standalone.assert_not_called()

    def test_comments_and_literals_are_not_declarations(self):
        self.source("iroha_torii", "src/lib.rs", '''
            // #[test] fn absent_from_comment() {}
            const DESCRIPTION: &str = r#"routing_test! { sync absent_from_literal {} }"#;
        ''')
        stages = {"torii-unit": (("router", ("tests::absent_from_comment",
                                                 "tests::absent_from_literal")),)}
        with self.assertRaisesRegex(gate.CheckError, "2 selected test declarations absent"):
            gate.validate_selected_source_test_inventory(self.root, stages)

    def test_same_leaf_in_another_package_does_not_satisfy_selection(self):
        self.source("iroha_core", "src/lib.rs", "#[test] fn other_package_case() {}")
        self.source("iroha_torii", "src/lib.rs", "#[test] fn unrelated() {}")
        stages = {"torii-unit": (("router", ("routing::other_package_case",)),)}
        with self.assertRaisesRegex(gate.CheckError, "torii-unit: routing::other_package_case"):
            gate.validate_selected_source_test_inventory(self.root, stages)

    def test_duplicate_selected_name_fails(self):
        stages = {"torii": (("first", ("tests::duplicate",)),
                             ("second", ("tests::duplicate",)))}
        with self.assertRaisesRegex(gate.CheckError, "repeats a test in torii"):
            gate.validate_selected_source_test_inventory(self.root, stages)

    def test_missing_inventory_reports_every_case_in_one_preflight(self):
        self.source("iroha_torii", "src/lib.rs", "#[test] fn unrelated() {}")
        missing = tuple(f"tests::absent_{index}" for index in range(28))
        with self.assertRaises(gate.CheckError) as failure:
            gate.validate_selected_source_test_inventory(
                self.root, {"torii-unit": (("current handlers", missing),)})
        diagnostic = str(failure.exception)
        self.assertIn("28 selected test declarations absent", diagnostic)
        for name in missing:
            self.assertIn("torii-unit: " + name, diagnostic)

    def test_current_checkout_census_has_real_source_declarations_in_both_scopes(self):
        # Exercise the actual checkout, not a second list of expected strings.
        # Refactors must update the release census before source capture or Cargo.
        for scope in gate.QUALIFICATION_SCOPES:
            with self.subTest(scope=scope):
                gate.validate_selected_source_test_inventory(
                    SCRIPT.parents[1], gate.qualification_stages(scope))

    def test_current_amx_final_guard_and_maintenance_controls_are_exact_required_tests(self):
        root = SCRIPT.parents[1]
        controls = {
            "core": tuple("sumeragi::amx::proof_tests::" + leaf for leaf in (
                "persisted_amx_completed_proof_retains_exact_graph_through_final_namespace_refusal",
                "persisted_amx_authenticated_absence_retains_final_guard_and_one_shot_delivery",
            )),
            "cli": tuple("taira_public_reset::host::maintenance::tests::" + leaf for leaf in (
                "maintenance_scope_admits_all_four_observed_daemon_pins",
                "maintenance_scope_rejects_incomplete_or_crossed_observed_cohorts",
                "maintenance_predecessor_kind_is_explicit_and_never_inferred",
                "observed_daemon_hash_is_exact_size_and_deadline_bounded",
                "maintenance_scope_binds_v2_all_four_units_and_installed_runtime",
                "maintenance_scope_rejects_unsupported_update_contracts",
            )),
        }
        retired = ("taira_public_reset::host::maintenance::tests::"
                   "maintenance_scope_binds_all_four_units_and_failed_installed_runtime")
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)
            for harness, required in controls.items():
                names = [name for _, cases in selected[harness] for name in cases]
                self.assertNotIn(retired, names)
                for name in required:
                    with self.subTest(scope=scope, harness=harness, name=name):
                        self.assertEqual(names.count(name), 1)
                        focused = gate.focused_regression_stages(scope, (harness + "=" + name,))
                        self.assertEqual(tuple(focused), (harness,))
                        self.assertEqual([item for _, cases in focused[harness] for item in cases], [name])
                        gate.validate_selected_source_test_inventory(root, focused)
                        gate.require_tests(name + ": test", focused[harness])
                        listing = "\n".join(item + ": test" for item in names if item != name)
                        with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                            gate.require_tests(listing, selected[harness])

    def test_original_shared_history_consumers_are_selected_focusable_and_required(self):
        root = SCRIPT.parents[1]
        groups = {
            "data-model": gate.MODEL_SHARED_BLOCK_STAGES,
            "core": (gate.CORE_SHARED_BLOCK_HISTORY_STAGES
                     + gate.CORE_CANONICAL_XOR_STAGES
                     + gate.CORE_NATIVE_STAKING_PENALTY_STAGES
                     + gate.CORE_MONETARY_AUTHORITY_STAGES
                     + gate.CORE_STATE_VIEW_CONSUMER_STAGES
                     + gate.native_owner_stages("native lane read failure classification")
                     + gate.native_owner_stages("native original transaction history custody")
                     + gate.native_owner_stages("native complete State reader custody")
                     + gate.native_owner_stages("native publication refusal identity")
                     + gate.native_owner_stages("native durable archive recovery")),
            "kagami": gate.KAGAMI_CANONICAL_XOR_STAGES,
            "torii-unit": gate.TORII_SHARED_BLOCK_HISTORY_STAGES,
        }
        self.assertIn(
            "routing::multisig_contract_call_tests::"
            "original_contract_vrf_policy_refusal_is_unfinished_and_same_source_retries",
            [name for _, names in groups["torii-unit"] for name in names],
        )
        self.assertIn(
            "canonical_history::tests::"
            "original_block_proof_refusal_remains_retryable_instead_of_missing_or_corrupt",
            [name for _, names in groups["torii-unit"] for name in names],
        )
        self.assertIn(
            "sumeragi::evidence_history::lane::tests::"
            "native_lane_original_genesis_escrow_is_debited_only_by_delayed_authenticated_admission",
            [name for _, names in groups["core"] for name in names],
        )
        gate.validate_native_consensus_test_registration(root)
        gate.validate_selected_source_test_inventory(root, groups)
        hydration = "state::da_hydration::release_tests::hydration_source_reader_callbacks_follow_rebuild_fences_on_success_and_failure"
        self.assertIn(hydration, [name for _, names in groups["core"] for name in names])
        self.assertRegex((root / "crates/iroha_core/src/state/da_hydration.rs").read_text(),
                         r'#\[path = "da_hydration_release_tests.rs"\]\s*mod release_tests;')
        commit = "state::world_commit::tests::actual_state_commit_publishes_prepared_da_despite_ahead_cache"
        self.assertIn(commit, [name for _, names in groups["core"] for name in names])
        self.assertRegex((root / "crates/iroha_core/src/state/world_commit.rs").read_text(),
                         r'#\[path = "world_commit_tests.rs"\]\s*mod tests;')
        model_source = root / "crates/iroha_data_model/src/block/shared/tests.rs"
        model_leaves = set(re.findall(r"(?m)^fn (\w+)\(", model_source.read_text()))
        self.assertEqual(model_leaves, {name.rsplit("::", 1)[-1]
                                      for _, names in groups["data-model"] for name in names})
        kura_source = root / "crates/iroha_core/src/kura/tests/bounded_canonical_body_reads.rs"
        kura_leaves = set(re.findall(r"(?m)^fn (\w+)\(", kura_source.read_text()))
        self.assertEqual(kura_leaves, {name.rsplit("::", 1)[-1]
                                     for _, names in groups["core"] for name in names
                                     if name.startswith("kura::tests::")})
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)
            for harness, stages in groups.items():
                names = [name for _, cases in selected[harness] for name in cases]
                for _, cases in stages:
                    for name in cases:
                        with self.subTest(scope=scope, harness=harness, name=name):
                            self.assertEqual(names.count(name), 1)
                            focused = gate.focused_regression_stages(scope, (harness + "=" + name,))
                            self.assertEqual([item for _, tests in focused[harness] for item in tests], [name])
                            listing = "\n".join(item + ": test" for item in names if item != name)
                            with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                                gate.require_tests(listing, selected[harness])

    def test_public_rate_materialization_is_required_in_the_real_cli_harness(self):
        root = SCRIPT.parents[1]
        source = root / "crates/iroha_cli/src/taira_public_reset.rs"
        self.assertRegex(source.read_text(),
                         r'#\[path = "taira_public_reset_validator_config\.rs"\]\s*mod validator_config;')
        name = ("taira_public_reset::validator_config::tests::"
                "materialization_replaces_localnet_admission_with_distinct_public_clients")
        self.assertEqual(gate.HARNESS_TARGETS["cli"][3],
                         ["-p", "iroha_cli_lib", "--lib"])
        for scope in gate.QUALIFICATION_SCOPES:
            with self.subTest(scope=scope):
                selected = gate.qualification_stages(scope)["cli"]
                names = tuple(case for _, cases in selected for case in cases)
                self.assertEqual(names.count(name), 1)
                focused = gate.focused_regression_stages(scope, ("cli=" + name,))
                self.assertEqual(tuple(focused), ("cli",))
                self.assertEqual(tuple(case for _, cases in focused["cli"] for case in cases), (name,))
                gate.validate_selected_source_test_inventory(root, focused)
                listing = "\n".join(case + ": test" for case in names if case != name)
                with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                    gate.require_tests(listing, selected)

    def test_prepared_signature_fixture_equality_is_required_in_the_torii_harness(self):
        root = SCRIPT.parents[1]
        source = (root / "crates/iroha_torii/src/routing.rs").read_text()
        self.assertIn("mod prepared_transaction_signature_fixture_tests {", source)
        body = re.search(r"routing_test!\s*\{\s*sync prepared_transaction_signature_fixture_is_current\b(.*?)\n    \}",
                         source, re.DOTALL).group(1)
        self.assertIn("let fixture = build_fixture();", body)
        self.assertIn("/../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json", body)
        self.assertIn("assert_eq!(fixture, expected);", body)
        name = ("routing::prepared_transaction_signature_fixture_tests::"
                "prepared_transaction_signature_fixture_is_current")
        self.assertEqual(gate.HARNESS_TARGETS["torii-unit"][3],
                         ["-p", "iroha_torii", "--lib"])
        for scope in gate.QUALIFICATION_SCOPES:
            with self.subTest(scope=scope):
                selected = gate.qualification_stages(scope)["torii-unit"]
                names = tuple(case for _, cases in selected for case in cases)
                self.assertEqual(names.count(name), 1)
                focused = gate.focused_regression_stages(scope, ("torii-unit=" + name,))
                self.assertEqual(tuple(focused), ("torii-unit",))
                self.assertEqual(tuple(case for _, cases in focused["torii-unit"] for case in cases), (name,))
                gate.validate_selected_source_test_inventory(root, focused)
                listing = "\n".join(case + ": test" for case in names if case != name)
                with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                    gate.require_tests(listing, selected)

    def test_owner_authority_and_schema_suites_bind_real_bodies_to_native_harnesses(self):
        root = SCRIPT.parents[1]
        self.assertIn('include!("executor_contract_owner_permission_tests.rs");',
                      (root / "crates/iroha_core/src/executor.rs").read_text())
        core_source = root / "crates/iroha_core/src/executor_contract_owner_permission_tests.rs"
        core_names = tuple("executor::tests::" + name for name in re.findall(
            r"#\[test\]\s*fn\s+([A-Za-z_]\w*)\s*\(", core_source.read_text()))
        self.assertEqual(core_names, (
            "executor::tests::current_contract_owner_originates_and_revokes_exact_tokens_without_code_management",
            "executor::tests::suspended_contract_permissions_can_be_repaired_without_authorizing_invocation",
            "executor::tests::contract_owner_delegation_rejects_foreign_transferred_pending_and_parliament_authority",
            "executor::tests::ordinary_owner_self_grant_enables_guarded_call_and_revocation_closes_it",
            "executor::tests::scoped_permission_delegation_requires_current_declaration_and_exact_instance",
        ))
        groups = {
            "core": core_names,
            "schema": tuple(name for _, names in gate.SCHEMA_STAGES for name in names),
        }
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)
            _, plan, _ = gate.native_harness_plan(selected, ())
            for harness, required in groups.items():
                with self.subTest(scope=scope, harness=harness):
                    self.assertIn(harness, plan)
                    names = tuple(name for _, cases in selected[harness] for name in cases)
                    gate.validate_selected_source_test_inventory(root, {harness: selected[harness]})
                    for name in required:
                        self.assertEqual(names.count(name), 1)
                        focused = gate.focused_regression_stages(scope, (harness + "=" + name,))
                        self.assertEqual(tuple(focused), (harness,))
                        listing = "\n".join(case + ": test" for case in names if case != name)
                        with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                            gate.require_tests(listing, selected[harness])
        self.assertEqual(gate.HARNESS_TARGETS["schema"][3], ["-p", "iroha_schema_gen", "--lib"])

    def test_current_per_seat_bootstrap_suite_is_selected_once_with_real_test_bodies(self):
        root = SCRIPT.parents[1]
        module = root / "crates/irohad/src/beacon_bootstrap.rs"
        source = root / "crates/irohad/src/beacon_bootstrap_tests.rs"
        self.assertRegex(module.read_text(),
                         r'#\[path = "beacon_bootstrap_tests\.rs"\]\s*mod tests;')
        declared = tuple(re.findall(r"#\[test\]\s*fn\s+([A-Za-z_]\w*)\s*\(",
                                    source.read_text()))
        self.assertEqual(len(declared), 12)
        required = ["beacon_bootstrap::tests::" + leaf for leaf in declared]
        seat_root = root / "crates/irohad/src/beacon_bootstrap"
        self.assertIn("mod seat_attempt;", module.read_text())
        for child, leaves in {
            "finality": (
                "current_phase_pipe_accepts_real_work_and_rejects_replay",
                "rotation_phase_pipe_rejects_truncated_oversized_and_noncanonical_proofs",
            ),
            "input": ("bounded_phase_reader_consumes_exact_frame_without_advancing_next_frame",),
            "claim": ("one_shot_attempt_directory_cannot_reroll_after_restart",),
        }.items():
            self.assertIn("mod " + child + ";", (seat_root / "seat_attempt.rs").read_text())
            parent = seat_root / "seat_attempt" / (child + ".rs")
            self.assertRegex(parent.read_text(), r"#\[cfg\(test\)\]\s*mod tests;")
            body = (seat_root / "seat_attempt" / child / "tests.rs").read_text()
            for leaf in leaves:
                self.assertEqual(len(re.findall(r"#\[test\]\s*fn\s+" + re.escape(leaf) + r"\s*\(", body)), 1)
                required.append("beacon_bootstrap::seat_attempt::" + child + "::tests::" + leaf)
        for scope in gate.QUALIFICATION_SCOPES:
            selected = tuple(name for _, tests in gate.qualification_stages(scope)["daemon"]
                             for name in tests)
            for name in required:
                with self.subTest(scope=scope, test=name):
                    self.assertEqual(selected.count(name), 1)
                    without_case = "\n".join(case + ": test" for case in selected if case != name)
                    with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                        gate.require_tests(without_case, gate.qualification_stages(scope)["daemon"])

    def test_genesis_identity_publication_controls_are_required_in_both_scopes(self):
        cli_source = SCRIPT.parents[1] / "crates/iroha_cli/src"
        self.assertRegex((cli_source / "main_shared.rs").read_text(), r"(?m)^mod taira;")
        self.assertRegex((cli_source / "taira.rs").read_text(),
                         r'#\[path = "taira_parliament_seating\.rs"\]\s*pub\(crate\) mod parliament_seating;')
        self.assertRegex((cli_source / "taira_parliament_seating.rs").read_text(),
                         r'#\[path = "taira_parliament_seating_tests\.rs"\]\s*mod tests;')
        required = {"kagami": (
            "genesis::sign::tests::identity_drift_leaves_every_requested_output_unchanged",
            "genesis::sign::tests::expected_hash_output_matches_the_signed_consensus_header",
            "genesis::sign::tests::network_identity_publication_is_idempotent_and_refuses_drift",
            "genesis::sign::tests::existing_network_identity_requires_safe_single_link_custody",
            "genesis::sign::tests::guarded_replacement_publishes_consistent_genesis_bundle",
            "genesis::sign::tests::guarded_replacement_rejects_stale_missing_and_unsafe_prior_without_writes",
            "genesis::sign::tests::identity_guard_serializes_publishers_and_rejects_substitution",
            "genesis::sign::tests::interrupted_replacement_preserves_prior_identity_until_complete_retry",
            "genesis::sign::tests::replacement_requires_complete_explicit_output_bundle",
        ), "cli": (
            "taira::parliament_seating::tests::seat_parliament_seats_a_generated_network_once",
            "taira::parliament_seating::tests::resign_identity_requires_one_canonical_line",
        )}
        for scope in gate.QUALIFICATION_SCOPES:
            for harness, names in required.items():
                stages = gate.qualification_stages(scope)[harness]
                selected = tuple(name for _, tests in stages for name in tests)
                gate.validate_selected_source_test_inventory(SCRIPT.parents[1], {harness: stages})
                for name in names:
                    with self.subTest(scope=scope, harness=harness, test=name):
                        self.assertEqual(selected.count(name), 1)
                        focused = gate.focused_regression_stages(scope, (harness + "=" + name,))
                        self.assertEqual(tuple(focused), (harness,))
                        missing = "\n".join(case + ": test" for case in selected if case != name)
                        with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                            gate.require_tests(missing, stages)

    def test_generated_genesis_controls_follow_the_deploy_library_owner(self):
        required = (
            "genesis::staging::tests::default_genesis_staging_authenticates_catalog_and_reproduces_signed_context",
            "localnet::tests::generated_taira_genesis_grants_deployment_only_to_generated_client",
            "localnet::tests::localnet_assets_contain_only_explicit_requests",
            "localnet::tests::localnet_asset_validation_rejects_duplicate_identity_or_alias",
            "localnet::tests::canonical_taira_generation_binds_four_runtime_signers_to_validator_peers",
            "localnet::tests::localnet_runtime_bundle_separates_ledger_and_http_operator_custody",
            "localnet::tests::generated_nexus_localnet_serves_xor_faucet_from_client_signer",
            "localnet::tests::generated_permissioned_localnet_cannot_mint_additional_xor",
            "localnet::tests::generated_localnet_bootstraps_explicitly_requested_asset",
            "localnet::tests::generated_localnet_registers_requested_asset_definition_for_client_owner",
            "localnet::tests::private_dataspace_manifests_use_the_selected_lane_alias",
        )
        self.assertEqual(gate.HARNESS_TARGETS["deploy"][1:], (
            "iroha_deploy", "lib", ["-p", "iroha_deploy", "--lib"]))
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)
            stages = selected["deploy"]
            names = tuple(name for _, tests in stages for name in tests)
            self.assertEqual(names, required)
            kagami_leaves = {name.rsplit("::", 1)[-1]
                             for _, tests in selected["kagami"] for name in tests}
            self.assertTrue(kagami_leaves.isdisjoint(
                name.rsplit("::", 1)[-1] for name in required))
            gate.validate_selected_source_test_inventory(SCRIPT.parents[1], {"deploy": stages})
            for name in required:
                with self.subTest(scope=scope, test=name):
                    focused = gate.focused_regression_stages(scope, ("deploy=" + name,))
                    self.assertEqual(tuple(focused), ("deploy",))
                    missing = "\n".join(case + ": test" for case in names if case != name)
                    with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                        gate.require_tests(missing, stages)
            with patch.dict(gate.HARNESS_TARGETS, {"deploy": gate.HARNESS_TARGETS["kagami"]}):
                with self.assertRaisesRegex(gate.CheckError, "selected test declarations absent"):
                    gate.validate_selected_source_test_inventory(SCRIPT.parents[1], {"deploy": stages})

    def test_cli_seating_selectors_follow_actual_module_aliases_and_entrypoint(self):
        sources = {
            "Cargo.toml": '[package]\nname = "iroha_cli_lib"\n[lib]\nname = "iroha_cli"\npath = "src/main_shared.rs"\n',
            "src/main_shared.rs": 'mod taira;\n',
            "src/taira.rs": '#[path = "taira_parliament_seating.rs"]\npub(crate) mod parliament_seating;\n',
            "src/taira_parliament_seating.rs": '#[cfg(test)]\n#[path = "taira_parliament_seating_tests.rs"]\nmod tests;\n',
            "src/taira_parliament_seating_tests.rs": '#[test]\nfn seating_case() {}\n',
        }
        def write_sources():
            for path, text in sources.items():
                self.source("iroha_cli", path, text)
        def selected(name):
            return {"cli": (("seating", (name,)),)}
        correct = "taira::parliament_seating::tests::seating_case"
        write_sources()
        gate.validate_selected_source_test_inventory(self.root, selected(correct))
        for wrong in ("taira_parliament_seating::tests::seating_case", "unrelated::seating_case"):
            with self.subTest(selector=wrong), self.assertRaisesRegex(
                    gate.CheckError, "CLI seating selector lacks its registered module route"):
                gate.validate_selected_source_test_inventory(self.root, selected(wrong))

        # The guard derives the alias from source; it cannot merely compare
        # against a second hard-coded copy of the expected selector prefix.
        self.source("iroha_cli", "src/taira.rs", sources["src/taira.rs"].replace(
            "mod parliament_seating", "mod seated_parliament"))
        with self.assertRaisesRegex(gate.CheckError, "registered module route"):
            gate.validate_selected_source_test_inventory(self.root, selected(correct))
        gate.validate_selected_source_test_inventory(
            self.root, selected("taira::seated_parliament::tests::seating_case"))

        for path, replacement in (
            ("Cargo.toml", sources["Cargo.toml"].replace("src/main_shared.rs", "src/unused.rs")),
            ("Cargo.toml", sources["Cargo.toml"].replace('name = "iroha_cli"', 'name = "foreign_cli"')),
            ("src/main_shared.rs", '#[path = "foreign.rs"]\nmod taira;\n'),
            ("src/taira.rs", '/*\n' + sources["src/taira.rs"] + '*/\n'),
            ("src/taira_parliament_seating.rs", 'const DECOY: &str = r#"\n'
             + sources["src/taira_parliament_seating.rs"] + '"#;\n'),
        ):
            with self.subTest(edge=path):
                write_sources()
                self.source("iroha_cli", path, replacement)
                with self.assertRaisesRegex(gate.CheckError, "CLI seating"):
                    gate.validate_selected_source_test_inventory(self.root, selected(correct))
        write_sources()
        for target in (
            ("foreign package", "iroha_cli", "lib", ["-p", "other", "--lib"]),
            ("foreign library", "other", "lib", ["-p", "iroha_cli_lib", "--lib"]),
        ):
            with self.subTest(target=target), patch.dict(gate.HARNESS_TARGETS, {"cli": target}):
                with self.assertRaisesRegex(gate.CheckError, "CLI seating Cargo target registration"):
                    gate.validate_selected_source_test_inventory(self.root, selected(correct))

    def test_restarted_prepared_intent_controls_are_exact_required_in_both_scopes(self):
        required = (
            'query::native_context_archive::read::tests::original_intent_read_shares_exact_descriptor_capacity_and_prefix_custody',
            'query::native_context_archive::prepared_intents::tests::sole_intent_decoder_borrows_original_charged_ranges_and_refuses_framing_or_cumulative_limits',
            'sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_delivers_exact_native_prepared_relay_and_refunds_original_pool',
            'sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_final_namespace_refusal_retains_exact_funded_instruction_until_original_retry',
            'sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_original_pool_refusal_keeps_frame_and_selected_source_without_reread',
            'sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_rejects_substituted_authority_carrier_and_execution_claims',
            'sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_refuses_authenticated_row_subset_before_any_delivery',
        )
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)["core"]
            names = tuple(name for _, cases in selected for name in cases)
            for name in required:
                with self.subTest(scope=scope, selector=name):
                    self.assertEqual(names.count(name), 1)
                    focused = gate.focused_regression_stages(scope, ("core=" + name,))
                    self.assertEqual(tuple(focused), ("core",))
                    gate.validate_selected_source_test_inventory(SCRIPT.parents[1], focused)
                    listing = "\n".join(case + ": test" for case in names if case != name)
                    with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                        gate.require_tests(listing, selected)


    def test_returned_native_amx_context_controls_are_exact_required_in_both_scopes(self):
        required = (
            'sumeragi::amx::native::tests::returned_context::native_amx_returned_global_context_keeps_every_original_graph_charge_until_retirement',
            'sumeragi::amx::native::tests::returned_context::native_amx_returned_context_final_registration_refusal_keeps_original_graph_and_retry_pool',
        )
        for scope in gate.QUALIFICATION_SCOPES:
            selected = gate.qualification_stages(scope)["core"]
            names = tuple(name for _, cases in selected for name in cases)
            for name in required:
                with self.subTest(scope=scope, selector=name):
                    self.assertEqual(names.count(name), 1)
                    focused = gate.focused_regression_stages(scope, ("core=" + name,))
                    self.assertEqual(tuple(focused), ("core",))
                    gate.validate_selected_source_test_inventory(SCRIPT.parents[1], focused)
                    listing = "\n".join(case + ": test" for case in names if case != name)
                    with self.assertRaisesRegex(gate.CheckError, "required regressions missing"):
                        gate.require_tests(listing, selected)


if __name__ == "__main__":
    unittest.main()
