"""Exact native source ownership rejects stale declarations and wrong module edges."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("taira_native_inventory_test", ROOT / "scripts/taira_native_test_inventory.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class NativeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        helper = self.root / "scripts/formal/rust_text.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/formal/rust_text.py", helper)
        self.package = self.root / "crates/iroha_core/src"
        self.package.mkdir(parents=True)
        self.parent = self.package / "owner.rs"
        self.source = self.package / "tests.rs"
        self.parent.write_text('#[path = "tests.rs"]\nmod tests;\n')
        self.source.write_text('#[test]\nfn exact_case() {}\n')
        self.owners = (("authority", "owner.rs", "tests.rs", "tests", "owner::tests", ("exact_case",)),)

    def validate(self):
        return inventory.validate_native_source_inventory(self.root, owners=self.owners)

    def test_exact_owner_and_registered_source(self):
        self.assertEqual(self.validate(), {"owner::tests::exact_case"})

    def test_missing_extra_duplicate_and_comment_cases_fail(self):
        for source in ('', '#[test]\nfn other() {}', '#[test]\nfn exact_case() {}\n#[test]\nfn extra() {}',
                       '#[test]\nfn exact_case() {}\n#[test]\nfn exact_case() {}',
                       '// #[test]\n// fn exact_case() {}', 'const X: &str = "#[test] fn exact_case() {}";'):
            with self.subTest(source=source):
                self.source.write_text(source)
                with self.assertRaisesRegex(ValueError, "census differs"):
                    self.validate()

    def test_wrong_module_path_and_comment_registration_fail(self):
        for source in ('#[path = "other.rs"]\nmod tests;', '// #[path = "tests.rs"]\n// mod tests;',
                       'mod other;', '#[path = "tests.rs"] mod tests; #[path = "tests.rs"] mod tests;',
                       '// #[path = "tests.rs"]\nmod tests;',
                       '/* #[path = "tests.rs"] */ #[path = "foreign.rs"] mod tests;',
                       '#[path = "tests.rs"] #[path = "foreign.rs"] mod tests;'):
            with self.subTest(source=source):
                self.parent.write_text(source)
                with self.assertRaisesRegex(ValueError, "registration differs"):
                    self.validate()

    def test_inline_include_is_bound_to_its_registered_module(self):
        self.parent.write_text('mod tests { include!("tests.rs"); }')
        self.assertEqual(self.validate(), {"owner::tests::exact_case"})
        self.parent.write_text('mod tests {} mod other { include!("tests.rs"); }')
        with self.assertRaisesRegex(ValueError, "registration differs"):
            self.validate()

    def test_real_checkout_matches_every_reviewed_owner(self):
        names = inventory.validate_native_source_inventory(ROOT)
        self.assertEqual(len(names), sum(len(row[-1]) for row in inventory.NATIVE_CORE_TEST_OWNERS))
        self.assertEqual(len(names), 340)

    def test_current_native_owner_additions_reject_same_count_selector_replacement(self):
        expected = {
            'native proposal attestation policy': (
                ('sumeragi/executor.rs', 'sumeragi/executor_attestation_policy_tests.rs', 'attestation_policy_tests', 'sumeragi::executor::attestation_policy_tests'),
                (
                    'native_top_up_proposal_requires_attestation_before_an_epoch_boundary',
                    'ordinary_nonboundary_proposal_has_no_mint_attestation_requirement',
                    'ordinary_boundary_proposal_requires_its_authenticated_scheduled_attestation',
                    'executed_top_up_count_cannot_finalize_without_the_flag_even_if_static_work_is_ordinary',
                )),
            'native driver scheduling': (
                ('sumeragi/driver/tests/mod.rs', 'sumeragi/driver/tests/sched.rs', 'sched', 'sumeragi::driver::tests::sched'),
                (
                    'successor_build_waits_for_core_parent_activation_and_keeps_empty_readiness',
                    'successor_build_activation_preserves_arrival_and_rejects_another_height_or_view',
                    'activated_build_withdrawal_cancels_original_running_and_empty_owners',
                )),
            'native stored body custody': (
                ('sumeragi/block_store/body_read.rs', 'sumeragi/block_store/body_read_tests.rs', 'tests', 'sumeragi::block_store::body_read::tests'),
                ('stored_body_projection_accepts_the_payload_limit_and_refuses_one_over',)),
            'native preparation refusal identity': (
                ('sumeragi/executor/preparation.rs', 'sumeragi/executor/preparation/tests.rs', 'tests', 'sumeragi::executor::preparation::tests'),
                (
                    'original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine',
                    'native_source_publication_change_retries_without_recovery_or_quarantine',
                )),
            'native original execution and undo': (
                ('state/native_execution_tip.rs', 'state/native_execution_tip/tests.rs', 'tests', 'state::native_execution_tip::tests'),
                ('restore_rebuilds_sparse_history_checkpoints_from_verified_snapshot_prefix',)),
            'native beacon reporting control': (
                ('sumeragi/epoch_beacon/producer.rs', 'sumeragi/epoch_beacon/producer/readiness.rs', 'readiness', 'sumeragi::epoch_beacon::producer::readiness::tests'),
                (
                    'readiness_refresh_excludes_reader_until_validated_publication',
                    'readiness_failed_refresh_withdraws_old_positive_before_reader_returns',
                    'readiness_observation_requires_exact_even_generation_height_and_applied_cut',
                    'readiness_wait_expires_while_original_probe_guard_remains_held',
                    'readiness_poisoning_refuses_both_diagnostic_paths',
                )),
            'native publication custody': (
                ('sumeragi/executor.rs', 'sumeragi/executor_publication_tests.rs', 'publication_tests', 'sumeragi::executor::publication_tests'),
                (
                    'replay_completion_retirement_keeps_exact_source_and_original_pool_retry',
                    'original_prepared_signature_owner_survives_refusal_validation_publication_apply_and_replay',
                    'explicit_signature_preparation_rejection_retires_only_its_original_source',
                    'later_canonical_child_allocator_refusal_keeps_the_original_prepared_signature_owner',
                    'global_build_carries_a_transaction_of_the_payload_limit_less_the_reserve',
                )),
            'native local empty signature preparation': (
                ('sumeragi/executor.rs', 'sumeragi/executor_local_signature_preparation_tests.rs', 'local_signature_preparation_tests', 'sumeragi::executor::local_signature_preparation_tests'),
                (
                    'original_local_payload_signature_refusal_keeps_job_and_exact_release_owner',
                    'original_local_payload_wire_refusal_retains_completed_leaf_without_repreparation',
                )),
            'native completed decoded custody': (
                ('sumeragi/executor.rs', 'sumeragi/executor_decoded_custody_tests.rs', 'decoded_custody_tests', 'sumeragi::executor::decoded_custody_tests'),
                (
                    'completed_decoded_retry_borrows_original_graph_without_canonical_reentry',
                    'completed_decoded_foreign_pool_refusal_retains_exact_original_graph',
                    'completed_decoded_same_bytes_new_physical_source_cannot_replace_original',
                    'original_decoded_graph_survives_actual_prevalidation_policy_refusal_and_retry',
                    'original_validation_return_projection_refusal_keeps_typed_error_and_same_graph',
                    'original_validation_return_cannot_rebind_changed_header_to_authenticated_wire',
                    'explicit_completed_decoded_rejection_retires_only_original_height_view_hash',
                    'same_source_same_pool_distinct_prepared_signature_owner_is_refused_at_both_boundaries',
                )),
            'native completed replay identity': (
                ('sumeragi/executor/replay.rs', 'sumeragi/executor/replay/tests.rs', 'tests', 'sumeragi::executor::replay::tests'),
                (
                    'replay_completion_state_read_refusal_retains_original_receipt_and_retries_after_release',
                    'replay_committee_hash_streams_exact_counted_key_preimage',
                )),
            'native certified prefix authority': (
                ('sumeragi/certified_chain/tests.rs', 'sumeragi/certified_chain/prefix_tests.rs', 'prefix_tests', 'sumeragi::certified_chain::tests::prefix_tests'),
                (
                    'staged_certificate_prefix_preserves_reset_target_first_order_and_original_receipts',
                    'staged_certificate_prefix_refusal_preserves_cursor_and_target_before_gap_errors',
                    'scoped_reverse_walk_reads_all_original_frames_and_rechecks_corrupt_ancestors',
                    'checked_prefix_finish_matches_original_complete_step_and_authority',
                    'checked_prefix_finish_preserves_refusal_rejection_and_same_source_retry',
                    'admitted_prefix_finish_matches_original_step_and_retains_original_slot_until_finish',
                    'admitted_prefix_finish_preserves_original_pool_refusal_and_certificate_error_order',
                )),
        }
        for label, (edge, added) in expected.items():
            with self.subTest(owner=label):
                owner, = (row for row in inventory.NATIVE_CORE_TEST_OWNERS
                          if row[0] == label)
                self.assertEqual(owner[1:5], edge)
                for leaf in added:
                    self.assertEqual(owner[-1].count(leaf), 1)
                for relative in owner[1:3]:
                    target = self.package / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / "crates/iroha_core/src" / relative, target)
                source = self.package / owner[2]
                original = source.read_text()
                self.assertEqual(inventory.validate_native_source_inventory(
                    self.root, owners=(owner,)),
                    {owner[4] + "::" + leaf for leaf in owner[-1]})
                for leaf in added:
                    with self.subTest(leaf=leaf):
                        declaration = "fn " + leaf + "("
                        self.assertEqual(original.count(declaration), 1)
                        source.write_text(original.replace(
                            declaration, "fn unreviewed_native_replacement("))
                        with self.assertRaisesRegex(ValueError, "census differs") as refusal:
                            inventory.validate_native_source_inventory(self.root, owners=(owner,))
                        self.assertIn(leaf, str(refusal.exception))
                        self.assertIn("unreviewed_native_replacement", str(refusal.exception))
                source.write_text(original)

    def test_source_retries_and_replay_bind_only_current_executable_owners(self):
        expected = {
            "native execution producer source retries": (
                "sumeragi/driver/exec.rs", "sumeragi/driver/producer_retry_tests.rs",
                "producer_retry_tests", "sumeragi::driver::exec::producer_retry_tests", 12),
            "native witness admission": (
                "sumeragi/driver/mod.rs", "sumeragi/driver/tests/witness_admission.rs",
                "witness_admission_tests", "sumeragi::driver::witness_admission_tests", 11),
            "native completed replay identity": (
                "sumeragi/executor/replay.rs", "sumeragi/executor/replay/tests.rs",
                "tests", "sumeragi::executor::replay::tests", 8),
            "native dynamic VM projection refusal": (
                "pipeline/access/dynamic_execution.rs", "pipeline/access/dynamic_execution/tests.rs",
                "tests", "pipeline::access::dynamic_execution::tests", 5),
        }
        for label, (*edge, count) in expected.items():
            with self.subTest(owner=label):
                rows = [row for row in inventory.NATIVE_CORE_TEST_OWNERS if row[0] == label]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][1:5], tuple(edge))
                self.assertEqual(len(rows[0][-1]), count)
        self.assertFalse(any("strict_replay_retirement_tests" in field
                             for row in inventory.NATIVE_CORE_TEST_OWNERS for field in row[:5]))

    def test_startup_and_world_verification_retain_the_current_module_edges(self):
        expected = {
            "native beacon reporting control": (
                "sumeragi/epoch_beacon/producer.rs", "sumeragi/epoch_beacon/producer/readiness.rs",
                "readiness", "sumeragi::epoch_beacon::producer::readiness::tests", 7),
            "native beacon startup failure classification": (
                "sumeragi/executor.rs", "sumeragi/executor_control.rs",
                "control", "sumeragi::executor::control::tests", 2),
            "native complete World root verification": (
                "sumeragi/test_chain.rs", "sumeragi/test_chain/world_state_tests.rs",
                "world_state_tests", "sumeragi::test_chain::tests::world_state_tests", 6),
        }
        for label, (*edge, count) in expected.items():
            with self.subTest(owner=label):
                rows = [row for row in inventory.NATIVE_CORE_TEST_OWNERS if row[0] == label]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][1:5], tuple(edge))
                self.assertEqual(len(rows[0][-1]), count)

    def test_physical_history_checks_retain_the_exact_original_storage_owner(self):
        owners = [row for row in inventory.NATIVE_CORE_TEST_OWNERS
                  if row[0] == "native original transaction history custody"]
        self.assertEqual(len(owners), 1)
        owner = owners[0]
        self.assertEqual(owner[1:5], (
            "state/storage_transactions/history.rs",
            "state/storage_transactions/history_tests.rs",
            "tests",
            "state::storage_transactions::history::tests",
        ))
        self.assertEqual(len(owner[-1]), 22)
        self.assertEqual(owner[-1][:4], (
            "initial_native_tree_and_identity_have_one_exact_finite_admission",
            "independent_history_release_controls_stay_funded_through_last_observation",
            "physical_history_busy_ignores_logical_cleanup_and_retries_actual_release",
            "physical_admission_notifies_after_logical_unlock_on_success_refusal_and_unwind",
        ))

    def test_warmed_prefix_checks_have_the_exact_registered_native_owner(self):
        owners = [row for row in inventory.NATIVE_CORE_TEST_OWNERS
                  if row[0] == "native certified prefix authority"]
        self.assertEqual(len(owners), 1)
        owner = owners[0]
        self.assertEqual(owner[1:5], (
            "sumeragi/certified_chain/tests.rs",
            "sumeragi/certified_chain/prefix_tests.rs",
            "prefix_tests",
            "sumeragi::certified_chain::tests::prefix_tests",
        ))
        self.assertEqual(owner[-1], (
            "streamed_prefix_emits_genesis_execution_anchor_only_after_real_successor",
            "unsigned_changed_genesis_result_cannot_be_exported_by_streamed_reader",
            "streamed_prefix_checks_genuine_pasta_at_retained_empty_epoch_boundary",
            "warmed_epoch_shape_rejects_substituted_context_and_still_checks_each_qc",
            "warmed_reader_rechecks_durable_prefix_and_fresh_view_after_body_removal",
            "standalone_and_scoped_frame_reads_agree_without_skipping_shape_checks",
            'staged_certificate_prefix_preserves_reset_target_first_order_and_original_receipts',
            'staged_certificate_prefix_refusal_preserves_cursor_and_target_before_gap_errors',
            'scoped_reverse_walk_reads_all_original_frames_and_rechecks_corrupt_ancestors',
            'checked_prefix_finish_matches_original_complete_step_and_authority',
            'checked_prefix_finish_preserves_refusal_rejection_and_same_source_retry',
            'admitted_prefix_finish_matches_original_step_and_retains_original_slot_until_finish',
            'admitted_prefix_finish_preserves_original_pool_refusal_and_certificate_error_order',
        ))
