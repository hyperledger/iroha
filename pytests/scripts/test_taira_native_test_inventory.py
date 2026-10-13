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
        self.assertEqual(len(names), 561)

    def test_authenticated_epoch_schedule_stays_in_exact_boundary_census(self):
        owner, = (row for row in inventory.NATIVE_CORE_TEST_OWNERS
                  if row[0] == 'native certified history boundaries')
        leaf = 'npos_epoch_schedule_uses_committed_epoch_length'
        self.assertEqual(owner[-1].count(leaf), 1)
        for relative in owner[1:3]:
            target = self.package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'crates/iroha_core/src' / relative, target)
        self.assertEqual(inventory.validate_native_source_inventory(self.root, owners=(owner,)),
                         {owner[4] + '::' + name for name in owner[-1]})
        source = self.package / owner[2]
        original = source.read_text()
        declaration = 'fn ' + leaf + '('
        self.assertEqual(original.count(declaration), 1)
        source.write_text(original.replace(declaration, 'fn unreviewed_epoch_replacement('))
        with self.assertRaisesRegex(ValueError, 'census differs') as refusal:
            inventory.validate_native_source_inventory(self.root, owners=(owner,))
        self.assertIn(leaf, str(refusal.exception))
        self.assertIn('unreviewed_epoch_replacement', str(refusal.exception))

    def test_native_multisig_semantic_control_binds_its_exact_core_source_owner(self):
        row = next(row for row in inventory.NATIVE_CORE_TEST_OWNERS
                   if row[0] == 'native AMX typed multisig semantic rejection')
        self.assertEqual(row[1:], (
            'sumeragi/amx/native/tests.rs',
            'sumeragi/amx/native/tests/multisig_semantic.rs',
            'multisig_semantic', 'sumeragi::amx::native::tests::multisig_semantic',
            ('native_multisig_semantic_cause_is_terminal_and_preserves_exact_diagnostic',)))
        self.assertEqual(inventory.validate_native_source_inventory(ROOT, owners=(row,)),
                         {row[4] + '::' + row[5][0]})

    def test_amx_worker_retry_owner_binds_all_original_and_partial_controls(self):
        row = next(row for row in inventory.NATIVE_CORE_TEST_OWNERS
                   if row[0] == 'native original AMX Worker partial and completed retry custody')
        expected = ('native original AMX Worker partial and completed retry custody', 'sumeragi/executor.rs', 'sumeragi/executor_amx_retry_tests.rs', 'amx_retry_tests', 'sumeragi::executor::amx_retry_tests', ('original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry', 'completed_amx_worker_bank_refuses_replaced_source_parent_and_foreign_pool', 'completed_amx_worker_bank_preserves_equal_occurrences_and_metadata_refusal', 'original_paid_amx_worker_retry_reauthenticates_changed_native_parent', 'partial_amx_worker_leg_refusal_retains_original_controls_and_release_wait', 'partial_amx_worker_leg_refusal_retains_completed_source_prefix_without_reallocation', 'partial_amx_worker_leg_refusal_retains_original_multisig_member_prefix_without_reallocation', 'rejected_amx_worker_occurrence_retains_source_prefix_and_replays_before_later_partial_occurrence'))
        self.assertEqual(row, expected)
        self.assertEqual(inventory.validate_native_source_inventory(ROOT, owners=(row,)),
                         {expected[4] + '::' + leaf for leaf in expected[5]})

    def test_execution_attempt_owner_binds_json_and_instruction_bridge_controls(self):
        row = next(row for row in inventory.NATIVE_CORE_TEST_OWNERS
                   if row[0] == 'native original JSON attempt refusal and instruction bridge diagnostics')
        expected = ('native original JSON attempt refusal and instruction bridge diagnostics', 'execution_attempt.rs', 'execution_attempt/json_scoped_tests.rs', 'tests', 'execution_attempt::tests', ('json_scoped_refusal_preserves_original_context_source_and_retry', 'json_stale_scoped_refusal_keeps_its_original_tag_without_retry_authority', 'instruction_bridges_keep_original_refusal_without_discarded_diagnostic_allocations'))
        self.assertEqual(row, expected)
        self.assertEqual(inventory.validate_native_source_inventory(ROOT, owners=(row,)),
                         {expected[4] + '::' + leaf for leaf in expected[5]})

    def test_kaigi_record_deferral_owners_bind_all_three_actual_control_declarations(self):
        expected = {
            'native Kaigi record instruction deferral': (
                'smartcontracts/isi/kaigi.rs', 'smartcontracts/isi/kaigi/typed_deferral_tests.rs',
                'typed_deferral_tests', 'smartcontracts::isi::kaigi::typed_deferral_tests', (
                    'stored_record_refusal_is_sticky_and_retries_original_json_without_publication',
                    'indexed_record_refusal_preserves_unregister_guard_and_original_retry',
                )),
            'native Kaigi record World restore deferral': (
                'state/deserialize_world.rs', 'state/deserialize_world_kaigi_deferral_tests.rs',
                'kaigi_typed_deferral_tests', 'state::deserialize::kaigi_typed_deferral_tests', (
                    'restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot',
                )),
        }
        rows = {row[0]: row[1:] for row in inventory.NATIVE_CORE_TEST_OWNERS}
        for label, required in expected.items():
            self.assertEqual(rows[label], required)
        owners = tuple(row for row in inventory.NATIVE_CORE_TEST_OWNERS if row[0] in expected)
        names = inventory.validate_native_source_inventory(ROOT, owners=owners)
        self.assertEqual(names, {prefix + '::' + leaf for _, _, _, prefix, leaves in expected.values() for leaf in leaves})

    def test_kaigi_relay_deferral_owners_bind_all_nine_actual_control_declarations(self):
        expected = {
            'native Kaigi relay instruction and allowlist deferral': (
                'smartcontracts/isi/kaigi.rs', 'smartcontracts/isi/kaigi/relay_typed_deferral_tests.rs',
                'relay_typed_deferral_tests', 'smartcontracts::isi::kaigi::relay_typed_deferral_tests', (
                    'live_manifest_dependency_refusal_preserves_original_route_and_retry',
                    'lineage_refusal_preserves_original_relay_retirement_and_retry',
                    'primary_alias_refusal_preserves_original_registration_and_retry',
                    'registration_refusal_preserves_original_relay_retirement_and_retry',
                    'feedback_refusal_preserves_both_original_relay_rows_and_retry',
                    'allowlist_refusal_prevents_domain_metadata_publication_and_retries_original_json',
                    'checked_record_writer_refusal_keeps_original_create_unpublished_and_retries',
                )),
            'native Kaigi relay World restore deferral': (
                'state/deserialize_world.rs', 'state/deserialize_world_kaigi_relay_deferral_tests.rs',
                'kaigi_relay_typed_deferral_tests', 'state::deserialize::kaigi_relay_typed_deferral_tests', (
                    'restored_registration_refusal_retains_original_snapshot_and_retry',
                    'restored_allowlist_refusal_retains_original_snapshot_and_retry',
                )),
        }
        rows = {row[0]: row[1:] for row in inventory.NATIVE_CORE_TEST_OWNERS}
        for label, required in expected.items():
            self.assertEqual(rows[label], required)
        owners = tuple(row for row in inventory.NATIVE_CORE_TEST_OWNERS if row[0] in expected)
        names = inventory.validate_native_source_inventory(ROOT, owners=owners)
        self.assertEqual(names, {prefix + '::' + leaf for _, _, _, prefix, leaves in expected.values() for leaf in leaves})

    def test_world_constructor_owner_binds_all_four_actual_controls(self):
        row = next(row for row in inventory.NATIVE_CORE_TEST_OWNERS
                   if row[0] == 'native fallible World constructor custody')
        expected = ('native fallible World constructor custody', 'state.rs',
                    'state/world_construction_tests.rs', 'world_construction_tests',
                    'state::world_construction_tests', (
                        'world_constructor_registration_refusal_is_fallible_and_retries_original_source',
                        'world_constructor_record_refusal_is_fallible_and_retries_original_source',
                        'world_constructor_storage_refusal_preserves_release_before_entity_consumption_and_retries',
                        'world_constructor_rejects_malformed_kaigi_without_panicking',
                    ))
        self.assertEqual(row, expected)
        names = inventory.validate_native_source_inventory(ROOT, owners=(row,))
        self.assertEqual(names, {expected[4] + '::' + leaf for leaf in expected[5]})

    def test_current_native_owner_additions_reject_same_count_selector_replacement(self):
        expected = {
            'native Core account-key and governance table refusal': (
                ('state.rs', 'state/account_key_refusal_tests.rs', 'account_key_refusal_tests', 'state::account_key_refusal_tests'),
                ('upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry', 'governance_lock_account_key_preserves_original_refusal_fields_scope_and_same_source_retry', 'governance_slash_account_key_preserves_original_refusal_fields_scope_and_same_source_retry', 'governance_locks_dto_keeps_exact_json_layout_and_rejects_duplicate_account_keys', 'governance_slash_dto_keeps_exact_json_layout_and_rejects_duplicate_account_keys')),
            'native KAGEMUSHA wallet State and verifier-pack routing': (
                ('kagemusha_wallet_v1/tests.rs', 'kagemusha_wallet_v1/tests/wsv_tests.rs', 'wsv_tests', 'kagemusha_wallet_v1::tests::wsv_tests'),
                ('registration_requires_dedicated_asset_permission_and_reserve_consent', 'registration_rejects_a_foreign_network_before_creating_reserve_rows', 'registered_reserve_rejects_ordinary_transfer_burn_and_teardown', 'native_rejection_and_missing_source_anchor_cannot_activate', 'real_asset_batch_loads_once_and_failed_debit_rolls_back_ordinal', 'committed_reader_requires_an_original_cut_and_finite_limits', 'routing_uses_permanent_scope_and_refuses_missing_wallet_records', 'verifier_pack_routing_requires_the_exact_registered_asset_and_permanent_scope', 'verifier_install_routing_requires_the_registered_authorizing_asset_and_scheme', 'package_quota_charges_exact_native_calls_and_one_operation_at_the_boundary', 'package_quota_refusal_is_atomic_for_sigma_and_lineage_limits_and_overflow', 'lineage_call_quota_refuses_before_native_verifier_or_payout', 'unavailable_production_artifacts_retain_local_deferral_and_no_activation', 'verifier_install_requires_actual_reserve_owner_before_artifact_parsing', 'genuine_verifier_install_is_immutable_exact_retry_and_same_overlay_native_owner', 'verifier_install_rechecks_live_asset_permission_and_registered_scope', 'authorized_install_cannot_turn_missing_originals_into_a_verifier', 'package_quota_refuses_before_native_verifier_and_ledger_activation', 'real_reserve_pays_unload_once_and_online_controls_defer_without_consuming_it', 'real_fee_payout_requires_retained_history_and_never_requires_receive', 'corrupted_reserve_owner_and_mutated_registration_are_rejected', 'snapshot_requires_exact_reserve_indexes_and_reference_counts', 'private_root_load_rejects_before_debit_or_receipt_creation', 'ordinary_load_receipt_is_recovered_after_growth_and_local_qc_loss')),
            'native State preverify backend and key admission': (
                ('state.rs', 'state/state_preverify_backend_admission_tests.rs', 'state_preverify_backend_admission_tests', 'state::state_preverify_backend_admission_tests'),
                ('unsupported_retired_and_claimed_backends_fail_state_admission', 'stark_fri_profile_labels_require_enveloped_state_preverify_metadata', 'native_compiled_descriptor_refusal_preserves_key_admission_and_original_retry', 'native_state_payload_caps_commitments_and_metadata_precede_dedup_publication', 'genuine_stark_originals_preserve_independent_admission_and_key_activity', 'retired_ipa_profile_labels_refuse_even_native_envelope', 'native_and_stark_key_refusals_preserve_original_dedup_for_retry',
                 'original_state_preverify_refusal_does_not_publish_dedup_and_retries',
                 'proof_quota_preflight_is_nonmutating_and_registration_preserves_limits')),
            'native original Queue payload lease custody': (
                ('queue.rs', 'queue/payload_leases.rs', 'payload_leases', 'queue::payload_leases::tests'),
                ('pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue', 'pending_payload_selection_cannot_adopt_clear_and_readmission_during_selection', 'pending_payload_lease_retires_on_actual_certified_state_publication', 'pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap', 'pending_payload_selection_keeps_original_rows_across_unrelated_admissions', 'pending_payload_lease_keeps_exact_original_custody_across_unrelated_admissions', 'pending_payload_lease_prefix_keeps_original_backing_and_conservative_expiry', 'pending_payload_admission_exhaustion_refuses_before_input_publication')),
            'native original Queue resident custody': (
                ('queue.rs', 'queue/resident_owner_tests.rs', 'resident_owner_tests', 'queue::tests::resident_owner_tests'),
                ('removed_pending_owner_retains_original_resident_credit_until_last_reader', 'original_queue_shell_refusal_preserves_graph_and_exact_release_then_retries', 'first_queue_resident_ledger_refusal_keeps_original_input_and_retry_pool', 'every_queue_retirement_defers_original_refund_until_its_mutation_fence_releases', 'equal_limit_foreign_state_cannot_replace_original_queue_resident_pool', 'queue_drop_keeps_original_shell_and_ledger_charges_until_detached_last_owner', 'cold_queue_retirement_holds_original_fence_until_first_admission_can_publish')),
            'native borrowed paid AMX proof custody': (
                ('sumeragi/amx/native/tests.rs', 'sumeragi/amx/native/tests/paid_borrowed_custody.rs', 'paid_borrowed_custody', 'sumeragi::amx::native::tests::paid_borrowed_custody'),
                ('native_amx_persisted_paid_borrowed_prepared_proof_clone_retains_original_graph_and_lifetime', 'native_amx_original_begin_instruction_refusal_preserves_same_pool_and_last_owner_ledger', 'native_amx_paid_owned_queue_and_payload_clones_retain_original_proof_graph_and_last_owner_charge')),
            'native persisted AMX original proof custody': (
                ('sumeragi/amx/mod.rs', 'sumeragi/amx/proof_tests.rs', 'proof_tests', 'sumeragi::amx::proof_tests'),
                ('persisted_amx_records_survive_deadline_pruning_and_certified_replay',
                 'persisted_amx_proof_rejects_missing_corrupt_and_substituted_archives',
                 'persisted_amx_proof_refuses_original_pool_exhaustion_and_unverified_certificates',
                 'persisted_amx_original_read_retains_acquired_inode_and_exact_pool_through_decode_refusal',
                 'persisted_amx_completed_proof_retains_exact_graph_through_final_namespace_refusal',
                 'persisted_amx_authenticated_absence_retains_final_guard_and_one_shot_delivery')),
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
                    'published_execution_result_binds_the_original_header_and_body_digest',
                    'original_worker_world_cut_physical_allocator_refusal_retains_tail_and_publication',
                    'replay_completion_retirement_keeps_exact_source_and_original_pool_retry',
                    'original_prepared_signature_owner_survives_refusal_validation_publication_apply_and_replay',
                    'explicit_signature_preparation_rejection_retires_only_its_original_source',
                    'later_canonical_child_allocator_refusal_keeps_the_original_prepared_signature_owner',
                    'global_build_carries_a_transaction_of_the_payload_limit_less_the_reserve',
                )),
            'native validator return custody': (
                ('sumeragi/executor.rs', 'sumeragi/executor_validation_refusal_tests.rs', 'validation_refusal_tests', 'sumeragi::executor::validation_refusal_tests'),
                (
                    'original_prepared_certificate_read_refusal_retains_worker_owner_and_funded_execution',
                    'prepared_certificate_uses_bounded_signed_root_without_rewalking_execution_history',
                    'successor_context_uses_original_parent_and_bounded_signed_root_without_history_rewalk',
                    'original_post_merge_validation_refusal_retains_worker_owner_and_exact_available_retry',
                    'prepared_certificate_busy_retries_same_execution_after_original_reader_release',
                    'original_lane_finalizer_refusal_returns_same_graph_before_seal_and_publishes_after_retry',
                    'validated_witness_guard_failure_requires_recovery_without_reexecuting_original_source',
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
            'native lane signer custody': (
                ('sumeragi/lanes/custody.rs', 'sumeragi/lanes/custody/tests.rs', 'tests', 'sumeragi::lanes::custody::tests'),
                (
                    'lane_pool_refusal_adapters_preserve_exact_original_release_and_nonwaiting_demands',
                    'lane_admission_invariants_never_masquerade_as_allocator_or_semantic_failures',
                    'original_lane_state_admission_refusal_keeps_sample_and_signer_cut',
                    'original_signer_creation_refusal_preserves_exact_stake_cut_and_last_owner_charge',
                )),
            'native lane sample finalizer': (
                ('sumeragi/lanes/step.rs', 'sumeragi/lanes/step/sample_owner_tests.rs', 'sample_owner_tests', 'sumeragi::lanes::step::sample_owner_tests'),
                (
                    'sample_finalizer_foreign_pool_requires_recovery_without_source_or_refund_changes',
                    'sample_finalizer_exceeds_limit_retains_exact_requested_suffix_demand',
                )),
            'native certified prefix authority': (
                ('sumeragi/certified_chain/tests.rs', 'sumeragi/certified_chain/prefix_tests.rs', 'prefix_tests', 'sumeragi::certified_chain::tests::prefix_tests'),
                (
                    'staged_certificate_prefix_preserves_reset_target_first_order_and_original_receipts',
                    'staged_certificate_prefix_refusal_preserves_cursor_and_target_before_gap_errors',
                    'scoped_reverse_walk_reads_all_original_frames_and_rechecks_corrupt_ancestors',
                    'checked_prefix_finish_matches_original_complete_step_and_authority',
                    'checked_prefix_finish_preserves_refusal_rejection_and_same_source_retry',
                    'admitted_prefix_initializes_every_field_like_the_owned_constructor',
                    'admitted_prefix_finish_matches_original_step_and_retains_original_slot_until_finish',
                    'admitted_prefix_finish_preserves_original_pool_refusal_and_certificate_error_order',
                )),
            'native beacon custody': (
                ('sumeragi/epoch_beacon/producer.rs', 'sumeragi/epoch_beacon/producer/tests.rs', 'tests', 'sumeragi::epoch_beacon::producer::tests'),
                (
                    'parliament_attempt_admission_derives_the_slot_index_and_no_pulse_demand',
                    'readiness_horizon_is_native_only_with_pending_parliament_slots',
                )),
            'native executed beacon controls': (
                ('sumeragi/epoch_beacon/producer/tests.rs', 'sumeragi/epoch_beacon/producer/execution_tests.rs', 'execution_tests', 'sumeragi::epoch_beacon::producer::tests::execution_tests'),
                (
                    'sccp_panel_draw_reads_the_original_pulse_at_its_actual_carrying_height',
                    'pending_parliament_slots_create_no_native_control_demand_and_never_block_unrelated_work',
                    'npos_boundary_pulse_stays_mandatory_with_or_without_pending_parliament_slots',
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

    def test_current_sccp_restore_and_original_release_controls_have_exact_owners(self):
        """Every added custody rule is selected and rejects a same-count replacement."""
        expected = {
            'native funded driver wake': (
                ('sumeragi/driver/mod.rs', 'sumeragi/driver/wake.rs', 'wake', 'sumeragi::driver::wake::tests'),
                ('original_thread_capacity_release_unparks_after_final_latch_check_with_writer_retained',)),
            'native preparation refusal identity': (
                ('sumeragi/executor/preparation.rs', 'sumeragi/executor/preparation/tests.rs', 'tests', 'sumeragi::executor::preparation::tests'),
                ('immutable_result_foreign_budget_requires_recovery_with_original_diagnostic', 'immutable_result_excessive_preimage_requires_recovery_with_original_extent', 'immutable_result_encoding_failure_requires_recovery_with_original_cause', 'immutable_certificate_foreign_budget_requires_recovery_with_original_diagnostic', 'immutable_preparation_capacity_preserves_the_exact_original_release', 'immutable_preparation_allocator_refusal_never_invents_a_release', 'immutable_preparation_short_prepaid_parent_requires_recovery_without_losing_custody', 'producer_payload_errors_keep_original_release_and_terminal_classification',
                 'cold_prepare_keeps_original_recovery_refusal_after_execution_latches_recovery',
                 'native_initializer_invariant_keeps_original_across_validation_and_producer_recovery')),
            'native original execution and undo': (
                ('state/native_execution_tip.rs', 'state/native_execution_tip/tests.rs', 'tests', 'state::native_execution_tip::tests'),
                ('native_tip_snapshot_scope_is_mandatory_and_objects_are_closed',)),
            'native certified history': (
                ('sumeragi/certified_chain.rs', 'sumeragi/certified_chain/tests.rs', 'tests', 'sumeragi::certified_chain::tests'),
                ('current_result_frame_preserves_original_x_and_rejects_scope_time_and_retired_body', 'native_frame_requires_fixed_header_and_exact_block_binding', 'authenticated_scope_rejects_active_non_global_without_redecoding_result', 'original_signed_dataspace_scope_refuses_active_genesis_in_both_prefix_owners')),
            'native frozen epoch schedule': (
                ('sumeragi/schedule.rs', 'sumeragi/schedule/tests.rs', 'tests', 'sumeragi::schedule::tests'),
                ('sccp_epoch_floor_applies_even_when_disabled_and_after_genesis_initialization',
                 'due_work_parameter_changes_preserve_combined_margin_and_genesis_order_independence')),
            'native executed genesis registration': (
                ('sumeragi/schedule/execution.rs', 'sumeragi/schedule/execution_tests.rs', 'tests', 'sumeragi::schedule::execution::tests'),
                ('sccp_executed_genesis_rejects_work_budgets_that_starve_pause_enactment',
                 'executed_genesis_due_work_policy_cannot_be_bypassed_by_raw_state')),
        }
        for label, (edge, leaves) in expected.items():
            with self.subTest(owner=label):
                owner, = (row for row in inventory.NATIVE_CORE_TEST_OWNERS if row[0] == label)
                self.assertEqual(owner[1:5], edge)
                for leaf in leaves:
                    self.assertEqual(owner[-1].count(leaf), 1)
                for relative in owner[1:3]:
                    target = self.package / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / "crates/iroha_core/src" / relative, target)
                source = self.package / owner[2]
                original = source.read_text()
                self.assertEqual(inventory.validate_native_source_inventory(self.root, owners=(owner,)),
                                 {owner[4] + "::" + leaf for leaf in owner[-1]})
                for leaf in leaves:
                    with self.subTest(leaf=leaf):
                        declaration = "fn " + leaf + "("
                        self.assertEqual(original.count(declaration), 1)
                        source.write_text(original.replace(declaration, "fn unreviewed_current_rule_replacement("))
                        with self.assertRaisesRegex(ValueError, "census differs") as refusal:
                            inventory.validate_native_source_inventory(self.root, owners=(owner,))
                        self.assertIn(leaf, str(refusal.exception))
                        self.assertIn("unreviewed_current_rule_replacement", str(refusal.exception))
                source.write_text(original)

    def test_source_retries_and_replay_bind_only_current_executable_owners(self):
        expected = {
            "native execution producer source retries": (
                "sumeragi/driver/exec.rs", "sumeragi/driver/producer_retry_tests.rs",
                "producer_retry_tests", "sumeragi::driver::exec::producer_retry_tests", 13),
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
            "streamed_prefix_checks_exact_native_quorum_at_retained_empty_epoch_boundary",
            "warmed_epoch_shape_rejects_substituted_context_and_still_checks_each_qc",
            "warmed_reader_rechecks_durable_prefix_and_fresh_view_after_body_removal",
            "standalone_and_scoped_frame_reads_agree_without_skipping_shape_checks",
            'staged_certificate_prefix_preserves_reset_target_first_order_and_original_receipts',
            'staged_certificate_prefix_refusal_preserves_cursor_and_target_before_gap_errors',
            'scoped_reverse_walk_reads_all_original_frames_and_rechecks_corrupt_ancestors',
            'checked_prefix_finish_matches_original_complete_step_and_authority',
            'checked_prefix_finish_preserves_refusal_rejection_and_same_source_retry',
            'admitted_prefix_initializes_every_field_like_the_owned_constructor',
            'admitted_prefix_finish_matches_original_step_and_retains_original_slot_until_finish',
            'admitted_prefix_finish_preserves_original_pool_refusal_and_certificate_error_order',
            'walk_parent_link_retains_original_body_and_exact_native_continuity_without_result_copy',
        ))

    def test_reviewed_resume_restore_and_reader_additions_require_exact_source_owners(self):
        expected = {
            'native persisted AMX original proof custody': (
                'persisted_amx_detached_source_keeps_original_frame_pool_and_retry_after_view_drop',
                'persisted_amx_detach_pins_partial_inode_and_continues_without_original_view',
                'persisted_amx_detach_namespace_refusal_preserves_original_reader_for_retry',
                'persisted_amx_detach_after_final_guard_refusal_moves_completed_graph_without_work',
                'persisted_amx_detach_preserves_borrowed_probe_and_authenticated_absence',
                'persisted_amx_detached_source_rejects_substituted_uncertified_archive_fields',
            ),
            'native publication custody': (
                'context_proof_decoder_refusal_retains_original_inputs_and_retries',
                'native_context_archive_decoder_refusal_retains_original_execution_and_retries',
                'native_context_archive_corrupt_commitment_remains_sticky_recovery',
                'original_worker_world_cut_retains_completed_tail_after_final_control_refusal',
                'original_worker_completed_world_cut_refuses_changed_publication_source',
                'native_lane_proof_scratch_ceiling_remains_terminal_in_both_worker_stages',
            ),
            'native original execution and undo': (
                'restore_preserves_original_pool_refusal_release_and_same_source_retry',
                'restore_preserves_cumulative_prefix_decode_refusal_and_same_source_retry',
                'restore_keeps_corrupt_native_history_a_completed_schema_rejection',
            ),
            'native certified history': (
                'signed_genesis_initialization_does_not_repeat_completed_scope_decode',
            ),
            'native certified prefix authority': (
                'walk_parent_link_retains_original_body_and_exact_native_continuity_without_result_copy',
            ),
            'native driver scheduling': (
                'execution_certification_survives_parking',
            ),
            'native returned AMX context custody': (
                'native_amx_returned_global_context_keeps_every_original_graph_charge_until_retirement',
                'native_amx_returned_context_final_registration_refusal_keeps_original_graph_and_retry_pool',
            ),
            'native borrowed paid AMX proof custody': (
                'restarted_paid_intent_delivers_exact_native_prepared_relay_and_refunds_original_pool',
                'restarted_paid_intent_final_namespace_refusal_retains_exact_funded_instruction_until_original_retry',
                'restarted_paid_intent_original_pool_refusal_keeps_frame_and_selected_source_without_reread',
                'restarted_paid_intent_rejects_substituted_authority_carrier_and_execution_claims',
                'restarted_paid_intent_refuses_authenticated_row_subset_before_any_delivery',
            ),
            'native original archive and prepared intent frame custody': (
                'refused_archive_read_never_reopens_the_original_selected_inode',
                'archive_read_keeps_partial_prefix_and_exact_allocation_until_move_or_drop',
                'refused_archive_read_preserves_original_length_and_namespace_checks',
                'archive_pool_ceiling_refusal_retries_original_owner_but_record_limit_is_permanent',
                'one_shot_interruption_retries_the_original_partial_read_without_reopening',
                'returning_archive_cancels_pending_bytes_but_preserves_completed_byte_owner',
                'original_intent_read_shares_exact_descriptor_capacity_and_prefix_custody',
            ),
            'native canonical prepared intent framing and row identity': (
                'borrowed_intent_coordinates_declare_exact_owned_frame_without_erasing_nominal_lifetime',
                'borrowed_global_intent_keeps_exact_begin_locator_without_a_participant_parent',
                'original_prepared_key_selection_refuses_malformed_and_preserves_transaction',
                'borrowed_prepared_rows_use_canonical_sequence_and_refuse_changed_cardinality',
                'sole_intent_decoder_borrows_original_charged_ranges_and_refuses_framing_or_cumulative_limits',
            ),
        }
        for label, leaves in expected.items():
            with self.subTest(owner=label):
                owner, = (row for row in inventory.NATIVE_CORE_TEST_OWNERS if row[0] == label)
                for leaf in leaves:
                    self.assertEqual(owner[-1].count(leaf), 1)
                for relative in owner[1:3]:
                    target = self.package / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / "crates/iroha_core/src" / relative, target)
                source = self.package / owner[2]
                original = source.read_text()
                self.assertEqual(inventory.validate_native_source_inventory(self.root, owners=(owner,)),
                                 {owner[4] + "::" + leaf for leaf in owner[-1]})
                for leaf in leaves:
                    with self.subTest(leaf=leaf):
                        declaration = "fn " + leaf + "("
                        self.assertEqual(original.count(declaration), 1)
                        source.write_text(original.replace(declaration, "fn unreviewed_resume_replacement("))
                        with self.assertRaisesRegex(ValueError, "census differs") as refusal:
                            inventory.validate_native_source_inventory(self.root, owners=(owner,))
                        self.assertIn(leaf, str(refusal.exception))
                        self.assertIn("unreviewed_resume_replacement", str(refusal.exception))
                source.write_text(original)

    def test_clock_census_binds_every_original_control_and_module_edge(self):
        expected = (
            ('native original proposal recovery scheduling', 'sumeragi/driver/tests/mod.rs', 'sumeragi/driver/tests/proposal_recovery.rs', 'proposal_recovery', 'sumeragi::driver::tests::proposal_recovery', (
                'proposal_recovery_same_body_new_request_preserves_original_release_refusal',
                'proposal_recovery_discard_retires_original_waiter_before_decode_refund',
                'proposal_recovery_discard_cancels_only_matching_running_completion',
                'proposal_recovery_discard_preserves_terminal_original_failure',
                'proposal_recovery_replacement_rejects_stale_worker_and_retains_only_latest_body',
                'proposal_recovery_terminal_original_propagates_even_after_request_replacement',
                'proposal_recovery_waits_for_applied_parent_and_cannot_enter_commit_overlay',
                'proposal_recovery_applied_body_retires_obsolete_refusal_without_minting_admission',
                'proposal_recovery_kernel_routes_exact_body_to_native_worker_without_control_view',
            )),
            ('native original proposal publication admission', 'sumeragi/executor.rs', 'sumeragi/executor/proposal_publication.rs', 'proposal_publication', 'sumeragi::executor::proposal_publication::tests', (
                'native_original_proposal_rechecks_clock_after_worker_wait_and_restart',
            )),
            ('native original execution clock admission', 'sumeragi/executor.rs', 'sumeragi/executor/clock_tests.rs', 'clock_tests', 'sumeragi::executor::clock_tests', (
                'prepare_withheld_while_block_time_ahead',
                'authenticated_proposer_time_above_floor_executes_and_replays_without_restamping',
                'certified_execution_skips_clock_guards',
                'sccp_ct5_completion_resamples_clock_and_retains_original_for_certified_retry',
                'sccp_ct5_prepare_signing_resamples_original_after_valid_and_binds_every_coordinate',
            )),
            ('native original first Prepare admission', 'sumeragi/executor.rs', 'sumeragi/executor/prepare_admission_tests.rs', 'prepare_admission_tests', 'sumeragi::executor::prepare_admission_tests', (
                'ct1_native_first_prepare_rechecks_original_clock_after_execution',
                'ct5_post_encoding_clock_advance_rolls_back_actual_begin_and_fees_with_original_decode',
                'ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source',
                'ct5_admission_capacity_wait_keeps_encoded_original_then_rechecks_freshness',
            )),
            ('native lane proposal clock and payload admission', 'sumeragi/lanes/mod.rs', 'sumeragi/lanes/executor.rs', 'executor', 'sumeragi::lanes::executor::tests', (
                'lane_effective_timestamp_saturates_native_milliseconds',
                'lane_builder_effective_clock_retains_original_payload_across_clock_rewind',
                'lane_first_proposal_retains_timestamp_admission_through_authoring_and_recovery',
                'future_only_lane_work_retries_without_an_empty_answer_or_new_traffic',
                'lanes_discard_global_control_and_refuse_control_bearing_admission',
                'builds_executes_commits_and_deduplicates',
                'build_carries_a_transaction_of_the_payload_limit_less_the_framing_reserve',
                'build_trims_the_batch_to_the_lane_payload_limit',
                'payload_refusal_retains_selected_work_and_anchor_for_retry',
                'an_anchor_the_node_has_not_applied_is_never_a_verdict',
            )),
            ('native lane original execution and first Prepare custody', 'sumeragi/lanes/executor.rs', 'sumeragi/lanes/executor/native_decode_tests.rs', 'native_decode_tests', 'sumeragi::lanes::executor::native_decode_tests', (
                'signed_four_validator_lane_execution_refusal_never_caches_invalid_or_publishes',
                'anchor_read_refusal_retains_original_lane_body_until_capacity_returns',
                'signed_four_validator_lane_recovery_keeps_available_phase_and_exact_original_owners',
                'signed_lane_clock_retains_original_admission_until_exact_boundary_and_certified_replay',
                'signed_lane_clock_wait_cannot_reuse_a_foreign_anchor_identity',
                'native_lane_first_prepare_rechecks_pinned_clock_after_execution',
                'native_lane_first_prepare_admission_binds_original_source_and_retains_its_charge',
                'native_lane_first_prepare_owner_refusal_preserves_original_decoded_admission',
            )),
            ('native original proposal work and captured time', 'sumeragi/payload.rs', 'sumeragi/payload/work_tests.rs', 'work_tests', 'sumeragi::payload::work_tests', (
                'native_lane_merge_is_work_without_a_direct_network_execution_leaf',
                'outputs_and_empty_context_cannot_create_proposal_work',
                'fresh_proposal_progress_recheck_uses_captured_time_with_original_signed_input',
                'merge_floor_avoids_duplicate_original_parent_build_with_exact_wire_parity',
                'empty_work_and_cadence_overflow_refuse_before_any_parent_build',
            )),
        )
        by_label = {row[0]: row for row in inventory.NATIVE_CORE_TEST_OWNERS}
        for required in expected:
            with self.subTest(owner=required[0]):
                owner = by_label[required[0]]
                self.assertEqual(owner, required)
                for relative in owner[1:3]:
                    target = self.package / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / "crates/iroha_core/src" / relative, target)
                source = self.package / owner[2]
                source_text = source.read_text()
                self.assertEqual(
                    inventory.validate_native_source_inventory(self.root, owners=(owner,)),
                    {owner[4] + "::" + leaf for leaf in owner[5]},
                )
                for leaf in owner[5]:
                    with self.subTest(leaf=leaf):
                        declaration = "fn " + leaf + "("
                        self.assertEqual(source_text.count(declaration), 1)
                        source.write_text(source_text.replace(
                            declaration, "fn unreviewed_clock_replacement("))
                        with self.assertRaisesRegex(ValueError, "census differs") as refusal:
                            inventory.validate_native_source_inventory(self.root, owners=(owner,))
                        self.assertIn(leaf, str(refusal.exception))
                        self.assertIn("unreviewed_clock_replacement", str(refusal.exception))
                source.write_text(source_text)
                parent = self.package / owner[1]
                parent_text = parent.read_text()
                registration = "mod " + owner[3] + ";"
                self.assertEqual(parent_text.count(registration), 1)
                parent.write_text(parent_text.replace(
                    registration, "mod unreviewed_clock_owner;"))
                with self.assertRaisesRegex(ValueError, "registration differs"):
                    inventory.validate_native_source_inventory(self.root, owners=(owner,))
                parent.write_text(parent_text)
