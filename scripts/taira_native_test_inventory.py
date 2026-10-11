"""Exact current native test ownership for the Taira development gate.

This static census binds test declarations to registered Rust source owners.
It is not release evidence; executable --list verification and actual execution remain required.
Signed RS16 payload transport qualification remains open (specs/sumeragi_goals.md, question 8).
"""
from pathlib import Path
import re

# (coverage, parent source, test source, registered module, full module path, exact test leaves)
NATIVE_CORE_TEST_OWNERS = (
    ('native proposal attestation policy', 'sumeragi/executor.rs', 'sumeragi/executor_attestation_policy_tests.rs', 'attestation_policy_tests', 'sumeragi::executor::attestation_policy_tests', (
        'native_top_up_proposal_requires_attestation_before_an_epoch_boundary',
        'ordinary_nonboundary_proposal_has_no_mint_attestation_requirement',
        'ordinary_boundary_proposal_requires_its_authenticated_scheduled_attestation',
        'executed_top_up_count_cannot_finalize_without_the_flag_even_if_static_work_is_ordinary',
    )),
    ('native complete World root verification', 'sumeragi/test_chain.rs', 'sumeragi/test_chain/world_state_tests.rs', 'world_state_tests', 'sumeragi::test_chain::tests::world_state_tests', (
        'certified_results_bind_the_complete_world_and_the_emitted_events',
        'unwitnessed_world_divergence_changes_the_certified_result',
        'replay_rejects_a_tampered_world_and_startup_rejects_a_stale_accumulator',
        'replay_from_scratch_reproduces_the_world_state_accumulator',
        'world_root_verification_preserves_original_writer_refusal_and_exact_retry',
        'world_root_verification_preserves_original_capacity_refusal_and_exact_retry',
    )),
    ('native beacon startup failure classification', 'sumeragi/executor.rs', 'sumeragi/executor_control.rs', 'control', 'sumeragi::executor::control::tests', (
        'control_and_local_source_failures_never_authorize_transaction_quarantine',
        'readiness_allocator_failure_retains_concrete_non_source_error',
    )),
    ('native beacon reporting control', 'sumeragi/epoch_beacon/producer.rs', 'sumeragi/epoch_beacon/producer/readiness.rs', 'readiness', 'sumeragi::epoch_beacon::producer::readiness::tests', (
        'reporting_shell_retains_original_pool_charge_until_last_reader_drops',
        'reporting_policy_refusal_and_duplicate_attach_preserve_original_owner',
        'readiness_refresh_excludes_reader_until_validated_publication',
        'readiness_failed_refresh_withdraws_old_positive_before_reader_returns',
        'readiness_observation_requires_exact_even_generation_height_and_applied_cut',
        'readiness_wait_expires_while_original_probe_guard_remains_held',
        'readiness_poisoning_refuses_both_diagnostic_paths',
    )),
    ('native dynamic VM projection refusal', 'pipeline/access/dynamic_execution.rs', 'pipeline/access/dynamic_execution/tests.rs', 'tests', 'pipeline::access::dynamic_execution::tests', (
        'vm_stage_projection_keeps_original_capacity_release_and_completed_errors',
        'actual_state_prepass_refuses_original_pool_then_retries_without_a_verdict',
        'funded_prepass_constructor_uses_the_original_state_cache_and_reclaims',
        'raw_selector_preparation_refusal_retries_the_same_state_owner',
        'resource_refusal_keeps_outer_dynamic_access_conservative',
    )),
    ('native execution producer source retries', 'sumeragi/driver/exec.rs', 'sumeragi/driver/producer_retry_tests.rs', 'producer_retry_tests', 'sumeragi::driver::exec::producer_retry_tests', (
        'every_execution_producer_retains_original_source_until_actual_release',
        'scheduler_controls_admit_all_or_none_from_the_original_pool',
        'independent_blocked_partial_slots_keep_all_peers_and_original_occurrences',
        'accepted_share_accelerates_only_source_less_witness_retry',
        'payload_arrival_survives_source_wait_and_does_not_emit_false_empty',
        'complete_context_change_cancels_waits_and_stale_inflight_results',
        'identical_source_less_requests_keep_backoff_and_full_payload_changes_supersede',
        'worker_moves_inline_control_occurrence_and_rejects_replacement',
        'stale_success_cannot_emit_control_or_hide_terminal_recovery',
        'cancellation_stays_final_when_the_identical_context_and_request_return',
        'lane_sized_peer_inputs_above_global_bound_keep_independent_progress',
        'cancelling_and_dropping_scheduler_unlinks_all_waiters_before_original_refunds',
    )),
    ('native committed-head release retries', 'sumeragi/driver/exec.rs', 'sumeragi/driver/source_retry_tests.rs', 'source_retry_tests', 'sumeragi::driver::exec::source_retry_tests', (
        'committed_head_waits_for_original_release_across_prepare_append_and_commit',
        'replacing_a_refusal_cancels_old_source_and_recovery_cancels_current_source',
    )),
    ('native funded driver wake', 'sumeragi/driver/mod.rs', 'sumeragi/driver/wake.rs', 'wake', 'sumeragi::driver::wake::tests', (
        'original_wake_is_funded_before_startup_and_retained_by_its_waker',
        'inputs_and_original_release_keep_the_last_drain_to_park_edge',
        'original_release_wakes_actual_park_after_final_pending_check',
    )),

    ('native complete State reader custody', 'state/view_acquisition.rs', 'state/view_acquisition_tests.rs', 'tests', 'state::view_acquisition::tests', (
        'nonblocking_state_view_retains_exact_header_and_configuration_release_sources',
        'state_view_generation_busy_retains_its_actual_writer_release',
        'complete_state_view_defers_world_and_configuration_callbacks_beyond_fences',
        'execution_pool_lookup_does_not_acquire_or_release_the_configuration_reader',
        'snapshot_runtime_adapters_preserve_original_decoder_refusal',
    )),
    ('native lane read failure classification', 'block.rs', 'block/lane_storage_error_tests.rs', 'lane_storage_error_tests', 'block::lane_storage_error_tests', (
        'merge_state_view_failures_preserve_original_source_without_rejection',
        'lane_io_failure_retains_kind_and_original_source_without_rejection',
        'missing_lane_height_retains_recovery_classification',
        'malformed_lane_reference_remains_deterministically_invalid',
    )),
    ('native original transaction history custody', 'state/storage_transactions/history.rs', 'state/storage_transactions/history_tests.rs', 'tests', 'state::storage_transactions::history::tests', (
        'initial_native_tree_and_identity_have_one_exact_finite_admission',
        'independent_history_release_controls_stay_funded_through_last_observation',
        'physical_history_busy_ignores_logical_cleanup_and_retries_actual_release',
        'physical_admission_notifies_after_logical_unlock_on_success_refusal_and_unwind',
        'empty_successor_retains_exact_cursor_and_identity_layouts',
        'initial_successor_reserves_batch_identity_and_cursor_before_work',
        'capacity_retry_keeps_original_batch_identity_and_private_predecessor',
        'frozen_reader_clone_keeps_earlier_values_after_duplicate_promotions',
        'replacement_preserves_original_history_and_old_readers',
        'original_reader_and_journal_credits_refund_only_after_last_custody',
        'restored_equal_bytes_are_a_foreign_original_family_and_identity',
        'restore_capacity_is_typed_and_refunds_before_retrying_same_bytes',
        'unfundable_successor_is_permanent_before_batch_or_identity_allocation',
        'checked_out_preparation_is_exclusive_and_abort_wakes_after_clearing_loan',
        'physical_busy_return_resumes_exact_original_cursor_batch_and_identity',
        'native_physical_retry_and_unrelated_unwind_preserve_original_generation',
        'stale_return_cannot_displace_a_new_generation_preparation',
        'sequence_exhaustion_refuses_before_any_successor_allocation',
        'original_kura_pool_refuses_before_world_or_either_start_stage',
        'retired_pending_notice_outlives_both_preparation_locks_on_unwind',
        'original_identity_retirement_observer_is_lazy_and_never_retains_its_owner',
        'attached_publication_busy_retry_retains_original_cursor_charge_and_release_sources',
    )),
    ('native publication custody', 'sumeragi/executor.rs', 'sumeragi/executor_publication_tests.rs', 'publication_tests', 'sumeragi::executor::publication_tests', (
        'beacon_startup_retains_original_capacity_through_worker_channel_and_node',
        'prepared_block_moves_original_graph_and_rejects_replaced_shared_control',
        'reversible_publication_refusal_retains_original_overlay_capture_and_certified_frame',
        'prepared_certificate_cannot_be_rebound_to_another_epoch_context',
        'preparation_pins_original_even_against_discard_replacement_and_another_valid_quorum',
        'mismatching_certified_result_reports_original_without_reexecuting_or_pinning_it',
        'consuming_publication_failure_blocks_every_reexecution_path',
        'panic_after_actual_visibility_is_local_recovery_never_success_or_reexecution',
        'original_worker_consuming_failure_halts_driver_status_without_reexecution',
        'state_busy_retry_retains_original_metadata_snapshot_certificate_and_pool_custody',
        'context_proof_capacity_retry_retains_original_witness_inputs_and_execution',
        'result_encoding_capacity_retry_keeps_original_execution_and_allocation_custody',
        'result_encoding_foreign_pool_requires_recovery_and_retains_original_execution',
        'qc_encoding_refusal_retains_original_header_result_and_execution_until_capacity_returns',
        'certificate_control_refusal_retains_every_original_part_through_publication_retry',
        'native_control_is_attached_once_and_remote_refusal_preserves_the_original_owner',
        'native_control_never_displaces_the_original_prepared_publication',
        'quarantine_requires_the_exact_control_free_transaction_rejection_hash',
        'native_header_source_is_checked_against_the_pristine_committed_parent',
        'state_executor_serializes_real_control_requests_and_one_time_attachment',
        'native_attestation_attachment_retains_the_first_original_pool_mailbox',
        'native_prepare_checks_real_quorum_before_changing_original_publication_owners',
        'native_pasta_refusals_retain_original_execution_until_actual_receipt_publication',
        'native_pasta_discard_invalidates_the_receipt_before_releasing_its_original_execution',
        'native_context_archive_capacity_retry_retains_original_overlay_and_result',
        'native_context_archive_failure_preserves_original_bytes_until_durable_acknowledgement',
        'native_context_archive_preparation_refuses_foreign_pool_without_reexecuting',
        'availability_encoding_refusal_retains_original_header_qc_and_execution',
        'canonical_replay_origin_retains_transition_idempotence_through_publication_retry',
        'malformed_available_payload_remains_invalid_and_negatively_cached',
        'payload_decode_refusal_retains_available_owner_without_negative_cache',
        'original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry',
        'original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry',
        'replay_completion_retirement_keeps_exact_source_and_original_pool_retry',
        'original_prepared_signature_owner_survives_refusal_validation_publication_apply_and_replay',
        'explicit_signature_preparation_rejection_retires_only_its_original_source',
        'later_canonical_child_allocator_refusal_keeps_the_original_prepared_signature_owner',
        'global_build_carries_a_transaction_of_the_payload_limit_less_the_reserve',
    )),
    ('native local empty signature preparation', 'sumeragi/executor.rs', 'sumeragi/executor_local_signature_preparation_tests.rs', 'local_signature_preparation_tests', 'sumeragi::executor::local_signature_preparation_tests', (
        'original_local_payload_signature_refusal_keeps_job_and_exact_release_owner',
        'original_local_payload_wire_refusal_retains_completed_leaf_without_repreparation',
    )),
    ('native completed decoded custody', 'sumeragi/executor.rs', 'sumeragi/executor_decoded_custody_tests.rs', 'decoded_custody_tests', 'sumeragi::executor::decoded_custody_tests', (
        'completed_decoded_retry_borrows_original_graph_without_canonical_reentry',
        'completed_decoded_foreign_pool_refusal_retains_exact_original_graph',
        'completed_decoded_same_bytes_new_physical_source_cannot_replace_original',
        'original_decoded_graph_survives_actual_prevalidation_policy_refusal_and_retry',
        'original_validation_return_projection_refusal_keeps_typed_error_and_same_graph',
        'original_validation_return_cannot_rebind_changed_header_to_authenticated_wire',
        'explicit_completed_decoded_rejection_retires_only_original_height_view_hash',
        'same_source_same_pool_distinct_prepared_signature_owner_is_refused_at_both_boundaries',
    )),
    ('native completed replay identity', 'sumeragi/executor/replay.rs', 'sumeragi/executor/replay/tests.rs', 'tests', 'sumeragi::executor::replay::tests', (
        'completed_replay_rejects_altered_certificate_and_source_without_losing_exact_retry',
        'completed_replay_retains_exact_receipt_through_original_pool_scratch_refusal',
        'completed_replay_is_invalidated_by_the_next_original_forward_commit',
        'historical_replay_retires_original_pools_and_reader_notices_after_state_fences',
        'historical_replay_archive_failure_retries_exact_owner_then_retires_after_state_fences',
        'historical_replay_post_visibility_unwind_retires_originals_after_state_fences',
        'replay_completion_state_read_refusal_retains_original_receipt_and_retries_after_release',
        'replay_committee_hash_streams_exact_counted_key_preimage',
    )),
    ('native preparation refusal identity', 'sumeragi/executor/preparation.rs', 'sumeragi/executor/preparation/tests.rs', 'tests', 'sumeragi::executor::preparation::tests', (
        'certificate_capacity_refusal_reaches_scheduler_with_original_release_and_execution',
        'preparation_classification_preserves_real_limit_and_does_not_invent_release_for_allocator',
        'cold_prepare_refusal_retains_original_finishing_owner_and_exact_release',
        'cold_prepare_validation_refusals_retain_original_storage_owners',
        'validation_wrappers_keep_real_capacity_and_terminal_custody_distinct',
        'original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine',
        'native_source_publication_change_retries_without_recovery_or_quarantine',
    )),
    ('native publication refusal identity', 'sumeragi/executor/publication.rs', 'sumeragi/executor/publication/tests.rs', 'tests', 'sumeragi::executor::publication::tests', (
        'state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release',
        'state_execution_and_membership_refusals_preserve_actual_release_owners',
        'nonretryable_state_publication_error_requires_recovery',
    )),
    ('native durable archive recovery', 'sumeragi/executor.rs', 'sumeragi/executor/archive_tests.rs', 'archive_tests', 'sumeragi::executor::archive_tests', (
        'committed_archive_index_refusal_retains_original_release_and_exact_publication',
        'committed_archive_cold_history_refusal_retains_original_pool_and_exact_publication',
        'partial_archive_failure_retains_exact_decision_and_retries_without_reexecution_or_notifications',
        'pending_capture_rejects_substituted_header_qc_state_and_missing_certificate',
        'archive_attachment_captures_exact_tip_once_before_executor_work_and_survives_reopen',
        'below_quorum_current_frame_cannot_finish_pending_archive_capture',
        'restart_binds_archives_after_replay_and_captures_the_missing_tip_once',
        'binding_refuses_unpublished_execution_and_captures_the_published_tip',
    )),
    ('native original execution and undo', 'state/native_execution_tip.rs', 'state/native_execution_tip/tests.rs', 'tests', 'state::native_execution_tip::tests', (
        'original_genesis_and_worker_publish_exact_tip_with_undo',
        'rejected_original_preparation_and_discard_preserve_committed_tip',
        'replacement_reads_exact_tip_undo_and_abandonment_restores_original_cut',
        'execution_history_admits_each_actual_source_before_read',
        'restore_reauthenticates_native_current_and_undo_and_rejects_claim_substitution',
        'genesis_only_snapshot_cannot_decode_its_unsigned_result_into_authority',
        'funded_tip_admission_is_atomic_and_original_pool_bound',
        'snapshot_json_preserves_genesis_undo_absence_distinction',
        'restore_rebuilds_sparse_history_checkpoints_from_verified_snapshot_prefix',
    )),
    ('native certified history', 'sumeragi/certified_chain.rs', 'sumeragi/certified_chain/tests.rs', 'tests', 'sumeragi::certified_chain::tests', (
        'committed_and_certified_reads_of_a_real_chain',
        'uncommitted_heights_are_not_read',
        'frames_without_a_matching_header_preimage_or_certificate_are_refused',
        'certificates_that_do_not_certify_the_stored_block_are_refused',
        'two_valid_certificates_of_one_block_give_one_consensus_receipt',
        'a_view_of_another_network_is_refused',
        'historical_committee_material_cannot_bypass_global_voting_geometry',
        'genesis_signature_is_verified_even_when_its_header_hash_matches_the_view',
        'genesis_payload_is_bound_to_its_signed_header_before_authority_is_read',
        'installing_an_attestation_verifier_rechecks_the_previously_verified_prefix',
        'pinned_prefix_uses_the_exact_cut_without_a_world_authority',
        'pinned_prefix_rejects_empty_foreign_changed_and_unavailable_sources',
        'pinned_genesis_result_is_unsigned_until_a_real_successor_authenticates_it',
        'portable_committee_uses_the_authenticated_original_epoch_members',
        'borrowed_native_frames_use_the_same_verifier_and_exact_cut',
        'borrowed_native_frames_reject_changed_result_even_under_unchanged_header_hash',
        'certified_reader_rejects_missing_foreign_and_corrupt_signed_availability',
        'durable_certificate_read_rejects_checksum_valid_corruption_after_cache_warm',
    )),
    ('native certified history boundaries', 'sumeragi/certified_chain/tests.rs', 'sumeragi/certified_chain/boundary_tests.rs', 'boundaries', 'sumeragi::certified_chain::tests::boundaries', (
        'rotated_away_committee_verifies_from_authenticated_boundaries_with_bounded_authority',
        'retained_generation_still_binds_new_epoch_and_fresh_leader_randomness',
        'historical_authority_missing_reordered_or_forged_proofs_fail_closed',
        'boundary_authority_and_parent_links_cannot_self_authorize',
        'nonempty_boundary_requires_flagged_attestation_and_exact_fresh_pulse',
        'unsigned_genesis_result_cannot_substitute_the_signed_epoch_root',
        'result_pulses_require_exact_height_network_session_and_parent_bindings',
        'pinned_restoration_reuses_full_boundary_verification_and_one_authority_cursor',
        'historical_pulse_requires_signed_header_bytes_and_complete_native_context',
    )),
    ('native certified prefix authority', 'sumeragi/certified_chain/tests.rs', 'sumeragi/certified_chain/prefix_tests.rs', 'prefix_tests', 'sumeragi::certified_chain::tests::prefix_tests', (
        'streamed_prefix_emits_genesis_execution_anchor_only_after_real_successor',
        'unsigned_changed_genesis_result_cannot_be_exported_by_streamed_reader',
        'streamed_prefix_checks_genuine_pasta_at_retained_empty_epoch_boundary',
        'warmed_epoch_shape_rejects_substituted_context_and_still_checks_each_qc',
        'warmed_reader_rechecks_durable_prefix_and_fresh_view_after_body_removal',
        'standalone_and_scoped_frame_reads_agree_without_skipping_shape_checks',
        'staged_certificate_prefix_preserves_reset_target_first_order_and_original_receipts',
        'staged_certificate_prefix_refusal_preserves_cursor_and_target_before_gap_errors',
        'scoped_reverse_walk_reads_all_original_frames_and_rechecks_corrupt_ancestors',
        'checked_prefix_finish_matches_original_complete_step_and_authority',
        'checked_prefix_finish_preserves_refusal_rejection_and_same_source_retry',
        'admitted_prefix_finish_matches_original_step_and_retains_original_slot_until_finish',
        'admitted_prefix_finish_preserves_original_pool_refusal_and_certificate_error_order',
    )),
    ('native pending original execution', 'sumeragi/test_chain.rs', 'sumeragi/test_chain/pending_execution_tests.rs', 'pending_execution_tests', 'sumeragi::test_chain::tests::pending_execution_tests', (
        'pending_execution_retains_one_source_and_publishes_once',
        'original_wire_witness_and_world_tampering_fail_before_durable_staging',
        'pending_execution_rejects_inexact_quorum_without_publication',
        'discarded_unprepared_execution_leaves_original_state_unchanged',
        'prepared_genesis_derives_then_enforces_both_signed_native_policies',
        'changed_original_genesis_configuration_is_rejected_before_publication',
    )),
    ('native original publication', 'sumeragi/test_chain.rs', 'sumeragi/test_chain/native_publication_tests.rs', 'native_publication_tests', 'sumeragi::test_chain::tests::native_publication_tests', (
        'original_genesis_and_successor_have_exact_native_execution_authority',
        'foreign_execution_certificate_cannot_prepare_original_worker',
        'publication_requires_the_original_nonempty_captured_witness',
        'original_signed_genesis_refuses_foreign_validator_custody',
        'missing_genesis_authority_is_created_by_its_original_signed_registration',
    )),
    ('native witness admission', 'sumeragi/driver/mod.rs', 'sumeragi/driver/tests/witness_admission.rs', 'witness_admission_tests', 'sumeragi::driver::witness_admission_tests', (
        'pending_remote_frame_preserves_original_backing_and_never_enters_core_early',
        'pending_slot_rejects_foreign_owners_and_retained_handle_cannot_revive_stopped_instance',
        'closed_instance_releases_original_witnesses_even_with_a_retained_handle',
        'pending_capacity_requires_original_release_despite_foreign_wake_and_huge_clock',
        'pending_buffer_to_control_refusal_keeps_exact_owner_and_replaces_source',
        'original_pool_release_before_ingress_registration_is_not_lost',
        'source_less_ingress_admission_retains_typed_error_and_bounded_deadline',
        'pending_shutdown_cancels_source_before_retained_handle_and_last_owner_refund',
        'ingress_waiter_one_byte_short_refuses_spawn_before_any_worker',
        'pending_last_handle_drop_cancels_before_original_message_refunds',
        'admitted_ingress_eviction_refunds_only_after_pending_and_ingress_mutexes_release',
    )),
    ('native lane merge authority', 'sumeragi/lanes/merge.rs', 'sumeragi/lanes/merge_tests.rs', 'tests', 'sumeragi::lanes::merge::tests', (
        'global_blocks_merge_fresh_lane_blocks_and_drop_what_they_must_not_execute',
        'malformed_merges_are_invalid_and_missing_blocks_pending',
        'expansion_consumes_only_the_exact_original_proposal',
        'expansion_refuses_equivalent_foreign_state_and_changed_publication',
        'merged_rejection_event_retains_the_original_native_proposal_header',
        'leader_proposal_preserves_local_storage_error_instead_of_omitting_lane_work',
    )),
    ('native lane signer custody', 'sumeragi/lanes/custody.rs', 'sumeragi/lanes/custody/tests.rs', 'tests', 'sumeragi::lanes::custody::tests', (
        'lane_obligation_never_moves_to_a_later_registration_sharing_key_and_account',
        'every_original_incarnation_must_finish_its_delay_before_custody_releases',
        'malformed_original_deadline_cannot_release_retained_custody',
        'original_signer_binding_requires_positive_custody_and_survives_policy_member_order',
        'retirement_marks_exact_boundary_and_policy_extension_precedes_withdrawal',
        'creation_pins_once_and_capacity_is_reclaimed_only_after_retirement_delay',
        'pending_original_evidence_delays_reclamation_without_native_height_arithmetic',
        'retirement_keeps_the_final_same_carrier_merge_after_the_live_record_is_removed',
        'an_existing_frontier_cannot_regress_or_switch_hash_or_result_at_the_same_native_height',
        'original_signer_pinning_refuses_then_retries_the_same_pool_and_stake_cut',
        'original_signer_state_handoff_retains_backing_and_refuses_foreign_pool',
        'original_signer_world_handoff_admits_both_generations_before_replacing_either',
        'original_signer_state_constructor_refuses_before_cloning_unfunded_world',
        'sample_state_admission_refuses_unfunded_source',
        'original_sample_state_constructor_refuses_with_typed_sample_cause',
        'original_sample_world_handoff_admits_both_generations_before_replacing_either',
    )),
    ('native lane signer restore custody', 'state/deserialize_world.rs', 'state/deserialize_world_lane_custody_tests.rs', 'native_lane_custody_tests', 'state::deserialize::native_lane_custody_tests', (
        'native_lane_signer_snapshot_retains_exact_raw_source_until_both_cuts_are_funded',
        'native_lane_signer_snapshot_rejects_noncanonical_fields_without_consuming_source',
        'native_lane_signer_snapshot_decode_refusal_retains_category_and_original_field',
        'native_lane_sample_snapshot_retains_raw_source_through_both_cut_refusal_and_retry',
    )),
    ('native lane signer restore errors', 'snapshot/errors.rs', 'snapshot/errors/native_lane_custody_tests.rs', 'native_lane_custody_tests', 'snapshot::errors::native_lane_custody_tests', (
        'restore_lane_custody_refusal_keeps_original_typed_local_error',
    )),
    ('native beacon custody', 'sumeragi/epoch_beacon/producer.rs', 'sumeragi/epoch_beacon/producer/tests.rs', 'tests', 'sumeragi::epoch_beacon::producer::tests', (
        'all_seats_drive_real_shares_once_and_followers_use_only_transported_pulse',
        'wrong_source_sender_and_proof_never_change_the_owned_round',
        'explicitly_anchored_no_demand_needs_neither_session_nor_fake_observer_key',
        'refusal_classification_keeps_remote_faults_out_of_local_recovery',
        'native_invalid_local_share_is_never_retained_or_counted',
        'native_transient_signer_refusal_retains_remote_progress_and_exact_retry_payload',
        'native_mandatory_slot_starts_without_transaction_work_and_missing_key_refuses',
        'native_active_session_from_a_foreign_real_committee_refuses_before_signing',
        'readiness_reprobes_same_applied_cut_without_signing_and_excludes_stale_generation',
        'readiness_no_demand_does_not_require_a_beacon_session',
        'control_retries_use_original_tip_without_decoding_history_again',
        'control_requires_original_tip_and_matching_published_hash_journal',
    )),
    ('native executed beacon controls', 'sumeragi/epoch_beacon/producer/tests.rs', 'sumeragi/epoch_beacon/producer/execution_tests.rs', 'execution_tests', 'sumeragi::epoch_beacon::producer::tests::execution_tests', (
        'transported_pulse_executes_once_and_cold_replay_reproduces_the_certified_result',
        'native_pulse_refusals_preserve_the_exact_predecessor_and_require_actual_work',
    )),
    ('native frozen epoch schedule', 'sumeragi/schedule.rs', 'sumeragi/schedule/tests.rs', 'tests', 'sumeragi::schedule::tests', (
        'chain_params_record_round_trips_the_core_and_on_chain_forms',
        'chain_params_validation_uses_the_chain_transport_limit',
        'consensus_key_maps_bls_peers_both_ways_and_rejects_others',
        'canonical_committee_sorts_by_core_key_and_dedups',
        'parameter_changes_validate_after_genesis_only',
        'genesis_committee_reads_the_signed_validator_registrations',
        'signed_genesis_requires_exact_global_geometry_without_observer_padding',
        'genesis_committee_rejects_bad_registrations',
        'global_committees_have_exact_bounded_geometry_and_equal_vote_quorums',
        'native_epoch_binds_core_authority_and_rejects_missing_reordered_or_changed_original_proofs',
        'boundary_application_is_the_only_cut_that_replaces_pending_authority',
        'scheduled_slot_json_requires_its_canonical_variant_tag',
        'restored_schedule_keeps_original_generation_and_full_epoch_graph',
        'genesis_outcome_cannot_supply_an_arbitrary_epoch_or_boundary',
    )),
    ('native executed genesis registration', 'sumeragi/schedule/execution.rs', 'sumeragi/schedule/execution_tests.rs', 'tests', 'sumeragi::schedule::execution::tests', (
        'executed_genesis_must_retain_every_exact_signed_registration',
        'executed_genesis_rejects_an_extra_voting_registration',
        'executed_genesis_fee_scope_decode_refusal_defers_and_retries_same_authority',
        'boundary_capture_attempts_retain_capacity_release_and_deterministic_errors',
    )),
    ('native driver persistence', 'sumeragi/driver/tests/mod.rs', 'sumeragi/driver/tests/file_stores.rs', 'file_stores', 'sumeragi::driver::tests::file_stores', (
        'file_stores_survive_disk_errors',
    )),
    ('native driver scheduling', 'sumeragi/driver/tests/mod.rs', 'sumeragi/driver/tests/sched.rs', 'sched', 'sumeragi::driver::tests::sched', (
        'most_recent_first_and_parking',
        'discard_cancels_waiting_and_running',
        'commit_during_execution_executes_once',
        'commit_answers_a_queued_execution',
        'missing_cache_recomputes_and_mismatch_diverges',
        'apply_failures_are_retried',
        'build_after_parent_apply_and_payload_ready',
        'arrival_during_a_build_follows_an_empty_answer',
        'successor_build_waits_for_core_parent_activation_and_keeps_empty_readiness',
        'successor_build_activation_preserves_arrival_and_rejects_another_height_or_view',
        'activated_build_withdrawal_cancels_original_running_and_empty_owners',
        'applied_heights_answer_waiting_requests',
        'every_execute_is_answered_exactly_once',
        'executor_panics_become_local_failures',
        'apply_runs_alone_while_backing_off',
        'failed_commit_prepares_again_without_a_second_append',
        'repeated_commit_failures_preserve_backoff_and_reset_after_success',
        'commit_backoff_survives_a_failed_reprepare',
        'discards_merge_and_rejections_are_bounded',
        'terminal_publication_errors_stop_all_scheduled_work',
        'cached_result_mismatch_diverges_without_reexecution',
        'original_boundary_config_survives_retry_and_is_delivered_atomically',
        'control_build_refusal_keeps_exact_request_and_does_not_block_transaction_work',
        'control_build_view_change_cancels_queued_and_running_retry',
        'all_validator_control_waits_for_applied_parent_and_shares_do_not_starve_work',
        'application_control_ingress_has_a_hard_protocol_cap',
        'control_worker_unwind_requires_recovery_and_cannot_invent_empty',
        'due_control_build_progresses_under_replenished_drive_and_partial_ingress',
    )),
    ('native driver kernel', 'sumeragi/driver/tests/mod.rs', 'sumeragi/driver/tests/kernel.rs', 'kernel', 'sumeragi::driver::tests::kernel', (
        'kernel_refuses_unfunded_waiter_before_constructing_consensus',
        'tick_first_then_local_then_messages',
        'own_and_foreign_messages_are_dropped',
        'barrier_and_ordered_persistence',
        'served_bodies_become_local_events',
        'serving_is_bounded_and_the_nodes_fetch_goes_first',
        'failing_disk_bounds_the_queues_and_releases_in_batches',
        'publication_recovery_halts_before_poll_and_preserves_safety_persistence',
        'frame_limits_cover_both_atomic_boundary_configs_without_pending_fallback',
        'core_discard_routes_the_same_authorized_keep_set_to_payload_lifetime',
    )),
    ('native driver fault conformance', 'sumeragi/driver/tests/mod.rs', 'sumeragi/driver/tests/conformance.rs', 'conformance', 'sumeragi::driver::tests::conformance', (
        'f09_loss_duplication_reordering',
        'f13_crash_restart_churn',
        'f14_whole_cluster_restart',
        'f27_storage_faults_retried',
        'f29_cpu_flood',
        'f32_cluster_restart_lock_or_cqc',
        'f37_flagged_blocks',
        'o2_kill_at_each_write_completion',
        'long_write_failure_keeps_queues_bounded',
    )),
    ('native lane sample finalizer', 'sumeragi/lanes/step.rs', 'sumeragi/lanes/step/sample_owner_tests.rs', 'sample_owner_tests', 'sumeragi::lanes::step::sample_owner_tests', (
        'sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix',
        'sample_finalizer_borrowed_lane_selection_preserves_boundaries_and_saturation',
    )),
    ('native lane sample publication', 'state.rs', 'state/lane_sample_owner_tests.rs', 'lane_sample_owner_tests', 'state::lane_sample_owner_tests', (
        'sample_world_rollback_publication_and_readers_retain_original_pool',
    )),
    ('native lane sample restore errors', 'snapshot/errors.rs', 'snapshot/errors/native_lane_sample_tests.rs', 'native_lane_sample_tests', 'snapshot::errors::native_lane_sample_tests', (
        'restore_lane_sample_refusal_keeps_original_typed_local_error',
    )),
    ('native stored body custody', 'sumeragi/block_store/body_read.rs', 'sumeragi/block_store/body_read_tests.rs', 'tests', 'sumeragi::block_store::body_read::tests', (
        'stored_body_retains_original_certificate_and_projected_payload_across_refusals',
        'absence_foreign_pool_and_corrupt_storage_are_separate_outcomes',
        'requested_hash_cannot_be_replaced_by_the_stored_certificate',
        'canonical_but_invalid_author_signature_never_becomes_available_custody',
        'stored_result_decode_refusal_retains_original_decoded_owners_and_retries',
        'malformed_result_preimage_remains_terminal_storage_corruption',
        'stored_certificate_allocator_refusal_keeps_original_read_and_retries',
        'stored_body_projection_accepts_the_payload_limit_and_refuses_one_over',
    )),
    ('native committed read custody', 'sumeragi/block_store/committed_read.rs', 'sumeragi/block_store/committed_read_tests.rs', 'tests', 'sumeragi::block_store::committed_read::tests', (
        'committed_read_returns_original_qc_backing_after_projection_refusal_and_retry',
        'body_only_read_releases_original_qc_witness_before_returning_ready',
        'committed_result_decode_refusal_keeps_original_read_slot_and_retries',
        'committed_certificate_allocator_refusal_retains_original_slot_and_retries',
    )),
 )

def native_owner_stages(label=None, *, exclude=()):
    """Return explicitly selected static suites, independent of filesystem availability."""
    return tuple((coverage, tuple(prefix + "::" + leaf for leaf in leaves))
                 for coverage, _, _, _, prefix, leaves in NATIVE_CORE_TEST_OWNERS
                 if (label is None or coverage == label) and coverage not in exclude)


def rust_source_masker(root):
    """Use retained authenticated code in preparation, or explicit mutable development code."""
    if __name__ == "taira_captured_native_inventory":
        return _captured_mask_rust_comments
    helper = Path(root) / "scripts/formal/rust_text.py"
    namespace = {"__name__": "native_inventory_rust_text", "__file__": str(helper)}
    exec(compile(helper.read_bytes(), str(helper), "exec"), namespace)
    return namespace["mask_rust_comments"]


def validate_native_source_inventory(root, *, owners=NATIVE_CORE_TEST_OWNERS):
    """Require the complete reviewed native declaration census and parent registration."""
    mask = rust_source_masker(root)
    package = Path(root) / "crates/iroha_core/src"
    declarations = re.compile(r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\(")
    seen = set()
    for coverage, parent, source, module, prefix, expected in owners:
        for relative in (parent, source):
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("native source owner leaves package: " + relative)
        if not expected or len(expected) != len(set(expected)):
            raise ValueError("native owner has empty or duplicated census: " + source)
        selected = {prefix + "::" + name for name in expected}
        if seen & selected:
            raise ValueError("native owners repeat exact test selectors")
        seen.update(selected)
        parent_text = (package / parent).read_text()
        parent_mask = mask(parent_text)
        registrations = list(re.finditer(r"\bmod\s+" + re.escape(module) + r"\s*([;{])", parent_mask))
        target = (package / source).resolve()
        bound = []
        for registration in registrations:
            if registration.group(1) == "{":
                # Included flat suites are bound inside this actual inline module body.
                start = registration.end()
                depth, end = 1, start
                while depth and end < len(parent_mask):
                    depth += (parent_mask[end] == "{") - (parent_mask[end] == "}")
                    end += 1
                for include in re.finditer(r'include!\("([^"\n]+)"\)', parent_text[start:end]):
                    offset = start + include.start()
                    if parent_mask[offset:offset + 8] == "include!":
                        bound.append((package / parent).parent / include.group(1))
            else:
                boundary = max(parent_mask.rfind(";", 0, registration.start()),
                               parent_mask.rfind("}", 0, registration.start())) + 1
                attributes = parent_text[boundary:registration.start()]
                paths = [match for match in re.finditer(r'#\[path\s*=\s*"([^"\n]+)"\]', attributes)
                         if parent_mask[boundary + match.start():boundary + match.start() + 6] == "#[path"]
                if len(paths) > 1:
                    raise ValueError("native test module source registration differs: " + prefix)
                if paths:
                    bound.append((package / parent).parent / paths[0].group(1))
                else:
                    base = (package / parent).parent
                    if Path(parent).name != "mod.rs":
                        base /= Path(parent).stem
                    bound.append(base / (module + ".rs"))
        if len(bound) != 1 or bound[0].resolve() != target:
            raise ValueError("native test module source registration differs: " + prefix)
        actual = tuple(declarations.findall(mask((package / source).read_text())))
        if set(actual) != set(expected) or len(actual) != len(expected):
            raise ValueError(f"native source census differs for {source}: missing={sorted(set(expected)-set(actual))}, extra={sorted(set(actual)-set(expected))}")
    return seen
