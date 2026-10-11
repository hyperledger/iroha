#!/usr/bin/env python3
"""Sumeragi mutation gate: the meta-check of spec §13.4 for each implementation owner.

Purpose
    Every mutation of §13.4 exists in the crate only as a `cfg(sumeragi_mutation = "<ID>")`
    switch, compiled in when the crate feature `mutation-testing` is on and the environment
    variable `SUMERAGI_MUTATION=<ID>` is set (see `crates/iroha_sumeragi/build.rs`). For each
    mutation this script builds the mutated crate and runs

        SUMERAGI_MUTATION=<ID> cargo test --locked -p iroha_sumeragi --release \\
            --features mutation-testing,sim --lib -- <named det test(s)>

    expecting a FAILURE, then (unless --fast) the mutation's randomized scenario(s) with
    SUMERAGI_SIM_SEEDS=200, again expecting a failure. It also runs the unmutated build once
    (every named test and every listed scenario), expecting success. `--lib` only skips the
    doctest pass; every named test is a unit test of the library.

    A mutation is
      killed_by_test           at least one of its named tests failed (the §13.4 requirement);
      killed_by_scenario_only  its named tests passed, a listed scenario failed;
      survived                 nothing failed;
      error                    build/execution failed, timed out, or a filter matched no
                               executed test. A process failure is not a mutation kill.

    Deadlines classify execution as an error. After a deadline the runner waits for
    its owned Cargo child to exit naturally and retains the output without sending
    termination signals. A late completed result never counts as a mutation kill.

    The table MUTATIONS mirrors §13.4 (MS*/ML* rows, the MA* rows of the commit-attestation
    extension, §3.7, and the MX* rows of the simulator's toy AMX application, §11) plus ME*
    (the as-built rules E1-E7 of Appendix E, with their regression tests) and MR-* (revision-4
    rules with det_r4 tests).

    `--core` selects the Core unit-test owner and `SUMERAGI_CORE_MUTATION`;
    `--daemon` selects the daemon unit-test owner and `SUMERAGI_DAEMON_MUTATION`.
    Each test-only feature guards only its own crate, without mutating dependencies.

Prerequisites
    Python 3.9+ (stdlib only) and a working `cargo` for the workspace. Builds go to a dedicated
    target directory (default `<repo>/target/sumeragi-mutants`), one sub-directory per job
    (`job0`, `job1`, ...), so only this crate rebuilds between mutations and parallel jobs never
    share a build lock. Nothing outside that directory is written; the source tree is never
    modified.

Outputs
    <target-dir>/report.json   per-mutation results and a summary
    <target-dir>/logs/*.log    full cargo output of every step

Exit status
    0 when the baseline passes and no mutation survived or errored; 1 otherwise. With --strict
    (the literal §13.4 CI rule) a mutation killed only by its scenario also fails the gate.
    Strict runs require the unmutated baseline; --skip-baseline is a diagnostic option.

Examples
    scripts/sumeragi_mutation_gate.py --jobs 4
    scripts/sumeragi_mutation_gate.py --only MS2,MS27 --fast
    scripts/sumeragi_mutation_gate.py --list
    scripts/sumeragi_mutation_gate.py --core --strict --jobs 1
    scripts/sumeragi_mutation_gate.py --daemon --only HC93 --strict --jobs 1
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CRATE = "iroha_sumeragi"
CRATE_SRC = REPO / "crates" / CRATE / "src"
FEATURES = "mutation-testing,sim"

# Randomized scenarios of §13.3 (test functions in `sim::tests`).
SCENARIOS = {
    "f01": "sim::tests::f01_crashed_leaders",
    "f02": "sim::tests::f02_silent_proxy_tail",
    "f03": "sim::tests::f03_withholding_proxy_tail",
    "f04": "sim::tests::f04_silent_or_slow_set_a",
    "f05": "sim::tests::f05_equivocating_leader",
    "f06": "sim::tests::f06_vote_withholders",
    "f07": "sim::tests::f07_adversarial_tc_composition",
    "f08": "sim::tests::f08_split_brain",
    "f09": "sim::tests::f09_loss_dup_reorder",
    "f10": "sim::tests::f10_delay_spikes",
    "f11": "sim::tests::f11_partitions",
    "f12": "sim::tests::f12_clock_skew_drift",
    "f13": "sim::tests::f13_crash_restart_churn",
    "f14": "sim::tests::f14_whole_cluster_restart",
    "f15": "sim::tests::f15_slow_executors",
    "f16": "sim::tests::f16_validator_set_change",
    "f17": "sim::tests::f17_far_behind_joiner",
    "f18": "sim::tests::f18_floods",
    "f19": "sim::tests::f19_poison_payload",
    "f20": "sim::tests::f20_cross_instance_replay",
    "f21": "sim::tests::f21_divergent_executor",
    "f22": "sim::tests::f22_idle_chain",
    "f23": "sim::tests::f23_non_3f1_committees",
    "f24": "sim::tests::f24_record_corruption_and_loss",
    "f25": "sim::tests::f25_relay_tampering",
    "f26": "sim::tests::f26_byzantine_responders",
    "f27": "sim::tests::f27_storage_faults",
    "f28": "sim::tests::f28_key_rotation",
    "f29": "sim::tests::f29_cpu_flood",
    "f30": "sim::tests::f30_max_size_blocks",
    "f31": "sim::tests::f31_amx_two_phase_commit",
    "f32": "sim::tests::f32_cluster_restart_lock_or_cqc",
    "f33": "sim::tests::f33_hidden_pqc",
    "f34": "sim::tests::f34_late_entrants",
    "f35": "sim::tests::f35_local_queue_asymmetry",
    "f36": "sim::tests::f36_late_leaders",
    "f37": "sim::tests::f37_commit_attestation",
    # F9 variant for ML5a: a vote blackout ending at GST (sim/mutation_group_2.rs).
    "f09r": "sim::mutation_group_2::f09r_vote_blackout_until_gst",
    # F32 with up to f proposers of the needed blocks kept down after the restart (ML10).
    "f32s": "sim::mutation_group_3::f32s_cluster_restart_without_proposers",
    # F21 with the O3 halt oracle: the divergent node must halt by ApplyDiverged (MS34).
    "f21h": "sim::mutation_group_1::f21_divergent_executor_halts",
}


@dataclass(frozen=True)
class Mutation:
    id: str
    site: str
    tests: tuple
    scenarios: tuple


def m(mid, site, tests, scenarios=()):
    return Mutation(mid, site, tuple(tests), tuple(scenarios))


# id, site and change, named deterministic test(s), randomized scenario(s) — mirrors §13.4.
MUTATIONS = [
    # ---- safety rules (one mutation per rule of §7.1)
    m("MS1", "propose/restore: rule 0 skipped, a restarted leader builds a new block",
      ["det_s1_leader_restart_no_second_proposal"], ["f13"]),
    m("MS2", "try_prepare: condition 2 (sign-once on safety.prepare) deleted",
      ["det_s2_s27_prepare_once_across_restart"], ["f05"]),
    m("MS3", "advance_to keeps proposal and try_prepare ignores proposal.view",
      ["det_s3_no_prepare_for_old_view_proposal"], ["f10", "f33"]),
    m("MS4", "try_prepare/try_commit: timeout fence deleted",
      ["det_s4_fence_across_restart"], ["f07", "f13"]),
    m("MS5", "try_commit: high_pqc.view == view deleted",
      ["det_s5_no_commit_stale_qc"], ["f08"]),
    m("MS7", "on_qc 2a: high_pqc = c unconditionally",
      ["det_s7_lock_monotone"], ["f07"]),
    m("MS8", "sign_timeout: carries None instead of high_pqc",
      ["det_s8_timeout_carries_lock"], ["f08"]),
    m("MS9", "on_tick rebroadcast 1: re-signs the timeout with the current lock",
      ["det_s9_timeout_resend_exact"], ["f09", "f07"]),
    m("MS10a", "propose rule 2 always fresh and on_proposal checks TC proposals as fresh",
      ["det_s10a_tc_rule_forces_reproposal"], ["f08"]),
    m("MS10b", "on_proposal step 6: TC-rule branch deleted",
      ["det_s10b_voter_rejects_tc_violation"], ["f08"]),
    m("MS11", "form_tc: lowest-hq entries and the lowest non-None hq's PrepareQC",
      ["det_s11_tc_max_hq"], ["f07"]),
    m("MS12", "verify_tc: high_pqc.view == max(hq) deleted",
      ["det_s12_tc_verify_rejects_low_high_pqc"], ["f07"]),
    m("MS13", "quorum(n) returns 2f + 1",
      ["det_s13_quorum_n5"], ["f23"]),
    m("MS14", "verify_qc accepts popcount >= q - 1",
      ["det_s14_qc_popcount"], ["f03", "f18"]),
    m("MS15", "verify_qc callers pass the configuration of tip.height",
      ["det_s15_committee_of_height"], ["f16"]),
    m("MS16", "vote/prop/tmo preimages omit the instance id",
      ["det_s16_cross_instance_replay"], ["f20"]),
    m("MS17", "vote_preimage omits R",
      ["det_s17_result_bound"], ["f03"]),
    m("MS18", "on_proposal step 1: signature of any member of C_h accepted",
      ["det_s18_non_leader_proposal_dropped"], ["f18"]),
    m("MS19", "on_proposal steps 5-6: parent_qc/parent_hash/parent_result checks deleted",
      ["det_s19_wrong_parent_rejected"], ["f05"]),
    m("MS20", "actual received-row digest equality skipped (shape retained)",
      ["acquisition_rejects_corrupt_actual_row_before_counting_custody"], ["f26"]),
    m("MS20b", "acquisition/restoration independent source identity checks skipped",
      ["source_bound_storage_job_never_confuses_refusal_with_absence_or_rebinds_source"]),
    m("MS20c", "actual payload hash equality skipped (length retained)",
      ["signed_inconsistent_codeword_and_payload_commitments_are_rejected"]),
    m("MS20d", "reconstructed codeword row commitments skipped (shape retained)",
      ["signed_inconsistent_codeword_and_payload_commitments_are_rejected"]),
    m("MS20e", "complete re-encoded codeword row commitments skipped (shape retained)",
      ["stored_body_restoration_checks_actual_codeword_without_resigning_or_copying_payload",
       "signed_inconsistent_codeword_and_payload_commitments_are_rejected"]),
    m("MS21", "commit_height: no verification for Status / parent_qc CommitQCs",
      ["det_s21_forged_commitqc_via_status", "det_s21_forged_commitqc_via_parent_qc"],
      ["f18"]),
    m("MS22", "sync: block_hash and parent-link checks deleted",
      ["det_s22_sync_forged_block"], ["f17"]),
    m("MS23", "try_prepare: vote routed before persist()",
      ["det_s23_crash_between_persist_and_durable"], ["f13"]),
    m("MS24", "fake driver: O2 barrier holds only Send/Broadcast",
      ["det_s24_local_cqc_not_exposed_before_durable_strong",
       "det_s24_o2_barrier_holds_every_effect"], ["f13"]),
    m("MS25", "persist: lock not copied into the record",
      ["det_s25_lock_persisted_with_commit"], ["f08"]),
    m("MS26", "sign_timeout: safety.timeout not recorded",
      ["det_s26_forget_timeout"], ["f13"]),
    m("MS27", "try_prepare: safety.prepare not recorded",
      ["det_s2_s27_prepare_once_across_restart"], ["f05"]),
    m("MS29", "propose: safety.proposal not recorded",
      ["det_s29_forget_proposal"], ["f13"]),
    m("MS30", "restore: high_pqc not restored from the record's lock",
      ["det_s30_lock_restored"], ["f08"]),
    m("MS31", "restore: Absent classified as R3",
      ["det_s31_deleted_record_abstains"], ["f24"]),
    m("MS31b", "restore R2: anchored at once from the local tip, no probe",
      ["det_s31b_record_and_store_lost"], ["f24"]),
    m("MS31c", "on_status: probes answered while unanchored or abstaining",
      ["det_s31c_abstaining_node_does_not_answer"], ["f24"]),
    m("MS31d", "on_status: every member Status counts as a probe reply",
      ["det_s31d_stale_status_is_not_a_reply"], ["f24"]),
    m("MS31e", "on_status step 1: echo signature not verified",
      ["det_s31e_echo_signature"], ["f24"]),
    m("MS32a", "restore R5: parent_commit_qc committed without verification",
      ["det_s32a_r5_forged_parent_qc"], ["f24"]),
    m("MS32b", "restore: R6 classified as R3",
      ["det_s32b_store_behind_record"], ["f27"]),
    m("MS32c", "pending_apply flush: parent-link check deleted",
      ["det_s32c_r5_block_not_extending_tip"], []),
    m("MS33a", "fake driver record store: one file per instance for all keys",
      ["det_s33_key_rotation_restart"], ["f28"]),
    m("MS33b", "enter_height: the first configured key signs regardless of membership",
      ["det_s33_key_rotation_restart"], ["f28"]),
    m("MS33c", "restore: keys classified against the pre-R5 tip (no composition)",
      ["det_s33_key_rotation_restart"], ["f28"]),
    m("MS33d", "fake driver record store: store-id comparison deleted",
      ["det_s33d_installation_log_rollback"], ["f24"]),
    m("MS34", "fake driver apply: commitment comparison skipped",
      ["det_s34_apply_divergence_halts_strong"], ["f21h"]),
    m("MS35", "on_manifest_rejected: unsigned carrier rejection times out the held proposal",
      ["det_s35_relay_tamper_no_evidence"], ["f25"]),
    m("MS36a", "on_executed step 3: certified mismatch handled like uncertified Invalid",
      ["det_s36_certified_mismatch_is_local"], ["f21"]),
    m("MS36b", "on_executed step 2: Failed handled like Invalid",
      ["det_s36_certified_mismatch_is_local"], ["f15"]),
    m("MS37", "on_qc step 1: safety-monitor branch deleted",
      ["det_s37_conflicting_commitqc_halts"], []),
    m("MS38", "on_vote: pooled without the signature check",
      ["det_s38_forged_votes_never_pooled"], ["f18"]),
    m("MS39", "verify_qc_signatures accepts more than q genuine signers",
      ["det_s39_qc_exact_signer_count"], []),
    m("MS40", "verify_tc accepts more than q genuine timeout entries",
      ["det_s40_tc_exact_signer_count"], []),
    m("MS41", "form_qc emits certificates from more than q votes",
      ["det_s41_form_qc_exact_signer_count"], []),
    m("MS49", "native codec erases typed local decode resource refusals",
      ["scoped_decode_refusal_is_not_malformed_native_evidence",
       "codec_resource_errors_survive_lossless_norito_conversion"], []),
    m("MS50", "static byte-domain bounds become retryable local decode refusals",
      ["protocol_byte_lengths_are_terminal_codec_errors"], []),
    # ---- liveness rules
    m("ML1", "level returns start(h)", ["det_l1_levels_grow"], ["f15"]),
    m("ML2", "on_tick rebroadcast 1 deleted", ["det_l2_lost_timeout_resent"], ["f09"]),
    m("ML3", "try_prepare/try_commit: 'set A or stage >= 1' becomes 'set A'",
      ["det_l3_setb_joins_stage1"], ["f06"]),
    m("ML4", "stage-2 triggers (a) and (c) deleted", ["det_l4_stage2_timing"], ["f03"]),
    m("ML5a", "on_tick: vote retransmit deleted", ["det_l5_lost_vote_retransmitted_strong"],
      ["f09", "f09r"]),
    m("ML5b", "on_vote step 2 (PrepareQC answer) deleted",
      ["det_l5_lost_vote_retransmitted"], ["f09"]),
    m("ML6", "start-level decay branch deleted", ["det_l6_level_decays"], ["f15"]),
    m("ML7", "demoted_set returns the empty set", ["det_l7_demotion_golden"], ["f01"]),
    m("ML8", "timeout_insert: join rule deleted", ["det_l8_join_f_plus_1"], ["f11"]),
    m("ML9", "persist: high_tc not copied", ["det_l9_restart_after_tc_entry"], ["f13", "f11"]),
    m("ML10", "on_proposal step 8: StoreBody omitted",
      ["det_l10_cluster_restart_lock_no_cqc_strong"], ["f32", "f32s"]),
    m("ML11", "on_block_request ignores heights <= tip.height",
      ["det_l11_pending_apply_after_peers_moved_on"], ["f16"]),
    m("ML12", "fake driver scheduler: FIFO ingress without O5 lanes",
      ["det_l12_tick_ahead_of_flood"], ["f29"]),
    m("ML13", "fresh payload building suppressed after view 0",
      ["det_l13_late_views_build_nonempty_work"], ["f19"]),
    m("ML14", "fake builder ignores PayloadRejected", ["det_l14_poison_quarantined_strong"],
      ["f19"]),
    m("ML15", "Status at keepalive cadence only", ["det_l15_unsettled_status_rate"], ["f11"]),
    m("ML16", "initial_stage returns 0", ["det_l16_hint_from_parent_commitqc"], ["f06"]),
    m("ML17", "discard_exec keeps the exec entries", ["det_l17_hidden_pqc_reexecutes"], ["f33"]),
    m("ML18", "leader: views over permutation slots",
      ["det_l18_f_plus_1_distinct_leaders"], ["f01"]),
    m("ML19a", "request_proposal clause (a) deleted", ["det_l19_late_entrant_repush"], ["f34"]),
    m("ML19b", "on_status: late-entrant re-push deleted", ["det_l19_late_entrant_repush"], ["f34"]),
    m("ML19c", "on_status: proposal request after the rate limit",
      ["det_l19_late_entrant_repush"], ["f34"]),
    m("ML20", "commit_height step 1a deleted", ["det_l20_p_broadcasts_commitqc"], ["f09"]),
    m("ML21", "anchor: revision-3 t_tx term restored",
      ["det_r4_payload_ready_moves_no_timer", "det_l21_idle_work_wakes_without_heartbeat"], ["f35"]),
    m("ML22", "stage-1 trigger (a): Commit-phase clause deleted",
      ["det_l3_setb_joins_stage1"], ["f06"]),
    m("ML23", "commit: the committed block's pending execution dropped",
      ["det_l23_commit_before_own_execution"], ["f34"]),
    m("ML24", "request_proposal clause (b) deleted", ["det_l24_lost_proposal_copy"], ["f09"]),
    m("ML25", "sign_timeout/on_commit: raise on a timeout with a held proposal restored",
      ["det_l26_raise_only_on_slow_commit_or_exec"], ["f05"]),
    m("ML26", "on_proposal step 2: no early timeout on proven leader equivocation",
      ["det_l25_equivocating_leader_early_timeout"], ["f05"]),
    m("ML27", "discard_exec/commit_height: a pending execution records nothing",
      ["det_l27_pending_execution_counts"], ["f15"]),
    m("ML28", "record_exec keeps the last execution of the height, not the maximum",
      ["det_l28_exec_duration_is_the_height_maximum", "det_l26_raise_only_on_slow_commit_or_exec",
       "det_l27_pending_execution_counts"], ["f15"]),
    m("ML29", "commit_height: d_c measured from the anchor (E40)",
      ["det_l29_late_leader_does_not_raise"], ["f36"]),
    m("ML30", "commit_height: d_c measured from t_prop of any held proposal",
      ["det_l29_late_leader_does_not_raise"], ["f36"]),
    m("MS42", "original publication recovery does not halt the core",
      ["det_s42_original_publication_recovery_halts"], []),
    m("MS43", "signing domains omit epoch identity and complete context", ["det_s43_every_signature_binds_epoch_and_complete_context"], []),
    m("MS44", "ordinary lag-two scheduling installs a future epoch", ["det_s44_lag_two_cannot_install_next_epoch_early"], []),
    m("MS45", "request_authoring imposes a mandatory epoch-boundary attestation flag",
      ["det_s45_unflagged_boundary_commits_without_attestation",
       "det_s45_boundary_proposal_carries_only_the_builders_flag"], []),
    m("MS46", "header signatures omit application control", ["det_s46_control_witness_is_bound_by_header_hash_and_proposal_signature"], []),
    m("MS47", "real work invents an absent authenticated control response", ["det_s47_nonempty_work_waits_for_independent_control_and_preserves_attestation"], []),
    m("MS48", "control response accepts another exact source", ["det_s48_control_response_requires_exact_request_epoch_view_and_parent_source"], []),
    # ---- commit-attestation rules (§3.7, SR39-SR42)
    m("MA1", "on_vote (attested): a flagged Commit vote is pooled without a verifying attestation",
      ["det_a2_unattested_commit_votes_not_counted"], ["f37"]),
    m("MA2", "verify_qc: the attestation check of a flagged CommitQC skipped",
      ["det_a4_commitqc_attestations_checked"], ["f37"]),
    m("MA3", "att_preimage omits R", ["det_a3_attestation_binds_result"], []),
    m("MA4", "att_preimage omits h", ["golden_attestation_preimage"], []),
    m("MA5", "try_commit: a node without authority Commit-votes without an attestation",
      ["det_a5_no_authority_abstains_from_commit_only"], ["f37"]),
    m("MA6", "vote_preimage omits the flag", ["det_a6_flag_is_signed"], ["f37"]),
    m("MA7", "propose_fresh: the builder's flag is dropped",
      ["det_a1_flagged_block_commits_with_attestations"], ["f37"]),
    m("MA8", "on_proposal: zero-payload signed-defect rejection omitted",
      ["det_a7_empty_proposals_are_rejected_at_every_view"], []),
    m("MA9", "restore_round: the recorded Prepare is rebuilt unflagged",
      ["det_a8_restart_resends_identical_attested_votes"], []),
    m("MA10", "try_commit: an attestation the node's own verifier rejects is used anyway",
      ["det_a5_no_authority_abstains_from_commit_only"], ["f37"]),
    m("MA11", "verify_attestations: a flagged CommitQC with more than q signers accepted",
      ["det_a4_flagged_commitqc_has_exactly_q_signers", "det_a4_commitqc_attestations_checked"],
      ["f37"]),
    m("MA12", "on_outcome: no try_commit after the lock's block executes (Pending attestor)",
      ["det_a9_pending_attestor_commits_after_execution"], []),
    m("MA13", "form_qc accepts distinct shared result witnesses",
      ["form_qc_carries_attestations"], []),
    # ---- as-built rules of Appendix E (E1-E7) and their regression tests
    m("ME1", "on_status: rate-limited Status drops its fresh CommitQC (E1)",
      ["rate_limited_status_still_delivers_a_fresh_commit_qc"], ["f03"]),
    m("ME2", "restore_round: record inconsistent with the store not halted (E2)",
      ["resume_rejects_a_record_inconsistent_with_the_store"], ["f24"]),
    m("ME3", "sync: buffered entries above a gap kept (E3)",
      ["sync_refetches_a_gap_left_by_a_dropped_forged_prefix"], ["f17"]),
    m("ME4", "on_payload_ready: readiness during an outstanding build dropped (E4)",
      ["payload_ready_during_an_outstanding_build_ends_the_idle_wait"], ["f02"]),
    m("ME5", "unsettled: stage-2 clause deleted (E5)",
      ["stage_two_makes_a_node_unsettled"], ["f03"]),
    m("ME6", "on_block_applied: anchoring re-check deleted (E6)",
      ["anchoring_is_checked_when_the_next_configuration_is_known"], ["f24"]),
    m("ME7", "prune_probe: probe table cleared while C_{t'+2} is unknown (E7)",
      ["det_s31e_echo_signature"], ["f24"]),
    # ---- revision-4 rules with det_r4 tests
    m("MR-block-applied", "on_block_applied: height/header/hash checks deleted",
      ["det_r4_block_applied_checks"], []),
    m("MR-tc-locks-only", "on_qc: a TC's high_pqc runs all of step 2",
      ["det_r4_tc_high_pqc_locks_only"], ["f07"]),
    m("MR-exec-budget", "exec_budget depends on the level",
      ["det_r4_exec_budget_level_independent"], ["f15"]),
    m("MR-stage-resend", "raise_stage: retransmit schedule not restarted",
      ["det_r4_stage_entry_resend_restarts_schedule"], ["f03"]),
    m("MR-unverified-target", "unsettled: an unverified sync target counts",
      ["det_r4_unverified_target_never_unsettles"], ["f18"]),
    m("MR-sync-late", "on_sync_response: only the outstanding peer is heard",
      ["det_r4_sync_responses_from_requested_sources"], ["f17"]),
    m("MR-restore-commit", "restore_round: final try_commit deleted",
      ["det_r4_restore_recommits_identical"], ["f13"]),
    m("MR-probe-status", "status_message: probe nonce not carried",
      ["det_r4_probe_statuses_and_echoes", "det_s31_deleted_record_abstains"], ["f24"]),
    m("MR-request-asked", "request_proposal: asked not set (asks every call)",
      ["det_r4_request_proposal_conditions"], ["f34"]),
    m("MR-repush-recipients", "repush_on_request: recipient check deleted",
      ["det_r4_repush_only_to_recipients_once"], []),
    m("MR-advance-prune", "advance_to: reported keys not pruned",
      ["det_r4_advance_to_prunes_blocks_and_reported"], ["f18"]),
    m("MR-window-init", "Core::new: W fixed at 128 instead of Init.demotion_window",
      ["det_r4_demotion_window_from_init"], ["f01"]),
    m("MR-cert-lru", "cert cache: a hit is not refreshed (FIFO, not LRU)",
      ["det_r4_cert_cache_lru_cleared_on_entry"], []),
    m("MR-monitor-prev", "monitor: the tip.height - 1 branch deleted",
      ["det_r4_monitor_previous_height"], []),
    m("MR-fetch-cycle", "fetch: sources not cycled",
      ["det_r4_fetch_sources_cycle"], ["f26"]),
    m("MR-restart-leader", "restore_round: leader rules (propose) deleted",
      ["det_r4_restart_leader_rules"], ["f14"]),
    m("MR-nested-pqc", "on_timeout: nested PrepareQC cheap-rejected like a top-level one",
      ["det_r4_nested_pqc_timeout_counted", "det_s7_lock_monotone"], ["f07"]),
    m("MR-fresh-nonce", "fake driver: Init.nonce not fresh per start",
      ["det_r4_fresh_nonce_per_init"], ["f24"]),
    # ---- the toy AMX application of the simulator (§11, sim/amx.rs), oracle O-AMX
    m("MX1", "GlobalState::vote: one Yes decides Commit",
      ["det_amx_commit_needs_every_yes"], ["f31"]),
    m("MX2", "GlobalState::vote: Commit after the deadline",
      ["det_amx_no_commit_after_deadline"], ["f31"]),
    m("MX3", "GlobalState::expire: no deadline abort",
      ["det_amx_deadline_aborts_at_d_plus_1"], ["f31"]),
    m("MX4", "GlobalState::begin: a second Begin replaces the transaction",
      ["det_amx_second_begin_rejected"], ["f31"]),
    m("MX5", "GlobalState::vote: a vote counts without verifying its proof",
      ["det_amx_forged_vote_rejected"], ["f31"]),
    m("MX6", "DataspaceState::prepare: a second inclusion of x prepares again",
      ["det_amx_prepare_once"], ["f31"]),
    m("MX7", "DataspaceState::prepare: a held decision is ignored",
      ["det_amx_held_decision_votes_no"], ["f31"]),
    m("MX8", "DataspaceState::settle: a Yes escrow is applied whatever the decision",
      ["det_amx_settle_follows_decision"], ["f31"]),
    m("MX9", "DataspaceState::observe: a local timeout releases a Yes escrow",
      ["det_amx_no_release_without_abort_proof"], ["f31"]),
    m("MX10", "Tracker::context: the epoch need not contain the certified height",
      ["det_amx_tracker_epoch_window"], []),
    m("MX11", "Tracker::handoff: C_{J,e-1} is not kept",
      ["det_amx_handoff_keeps_previous_epoch"], []),
    m("MX12", "Tracker::verify: the result-preimage check deleted",
      ["det_amx_record_bound_to_result"], ["f31"]),
]

# Core-owned rules use the same strict harness classifier; no simulator hook can stand in
# for production State/custody admission. Opt in explicitly with --core.
CORE_MUTATIONS = [
    m("HC1", "evidence: use native lane height instead of original retirement for replay pruning",
      ["sumeragi::evidence::tests::lane_terminal_replay_fence_uses_immutable_retirement_deadline_and_original_incarnation"]),
    m("HC2", "staking: omit original lane custody and exact registration revalidation",
      ["sumeragi::penalties::tests::original_lane_liability_checks_exact_registration_before_exposure",
       "sumeragi::penalties::tests::lane_liability_rejects_changed_incarnation_policy_and_same_tenure_escrow"]),
    m("HC3", "penalties: use native lane subject height as the global admission-delay clock",
      ["sumeragi::penalties::tests::original_lane_liability_slashes_retired_owner_without_using_native_height",
       "sumeragi::evidence_history::lane::tests::native_lane_original_genesis_escrow_is_debited_only_by_delayed_authenticated_admission"]),
    m("HC4", "admission: omit the original lane retirement deadline preflight",
      ["sumeragi::evidence_history::lane::tests::lane_admission_capture_checks_inclusive_deadline_and_missing_original_incarnation"]),
    m("HC5", "admission: retain terminal source failures as locally retryable jobs",
      ["sumeragi::evidence_history::lane::tests::terminal_lane_source_failure_cannot_pin_competing_original_admission_forever",
       "sumeragi::evidence_history::lane::tests::local_proposer_skips_terminal_lane_source_without_deleting_observation"]),
    m("HC6", "history: discard original completed owner on decoder-limit handoff refusal",
      ["sumeragi::evidence_history::lane_read::tests::completed_lane_history_retains_original_owner_on_finish_decode_refusal"]),
    m("HC7", "evidence: classify typed local decoder refusal as invalid original proof",
      ["sumeragi::evidence::codec_tests::native_decode_refusal_refunds_capture_without_blaming_original_proof",
       "sumeragi::evidence::codec_tests::persisted_root_decode_refusal_retains_original_validation_cut_for_retry"]),
    m("HC8", "executor: classify local payload decode refusal as cached invalid data",
      ["sumeragi::executor::publication_tests::payload_decode_refusal_retains_available_owner_without_negative_cache"]),
    m("HC9", "evidence: retain native result witnesses without original-pool admission",
      ["sumeragi::evidence::admission::witness_tests::retained_native_evidence_witnesses_belong_to_original_preparation_pool"]),
    m("HC10", "history: skip original query scratch admission before signed RS16 reconstruction",
      ["sumeragi::certified_chain::tests::state_certificate::state_certificate_signed_availability_scratch_uses_original_query_allowance"]),
    m("HC11", "history: use a warm decoded body instead of rereading the pinned durable certificate",
      ["sumeragi::certified_chain::tests::durable_certificate_read_rejects_checksum_valid_corruption_after_cache_warm"]),
    m("HC12", "beacon: allocate children before complete original prepaid session admission",
      ["beacon::validation::tests::beacon_verification_reserves_exact_buffers_and_refuses_before_unfunded_work"]),
    m("HC13", "certificate query: construct aggregate pairing scratch without original request admission",
      ["sumeragi::certified_chain::tests::state_certificate::state_certificate_pairing_constructor_refusal_preserves_original_source_for_retry"]),
    m("HC14", "certificate reader: reuse an original decoded result for different witness bytes",
      ["sumeragi::certified_chain::artifacts::tests::original_result_witness_rejects_foreign_canonical_bytes_before_borrowing_graph"]),
    m("HC15", "committed body reader: duplicate the original decoded quorum certificate at handoff",
      ["sumeragi::block_store::committed_read::tests::committed_read_returns_original_qc_backing_after_projection_refusal_and_retry"]),
    m("HC16", "lane custody: clone decoded signers without original-pool admission",
      ["sumeragi::lanes::custody::tests::original_signer_state_handoff_retains_backing_and_refuses_foreign_pool",
       "sumeragi::lanes::custody::tests::original_signer_world_handoff_admits_both_generations_before_replacing_either",
       "state::deserialize::native_lane_custody_tests::native_lane_signer_snapshot_retains_exact_raw_source_until_both_cuts_are_funded"]),
    m("HC17", "native control: accept an execution tip from another published hash journal",
      ["sumeragi::epoch_beacon::producer::tests::control_requires_original_tip_and_matching_published_hash_journal"]),
    m("HC18", "lane samples: retain or append samples without original-pool admission",
      ["sumeragi::lanes::custody::tests::sample_state_admission_refuses_unfunded_source",
       "sumeragi::lanes::step::sample_owner_tests::sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix",
       "state::deserialize::native_lane_custody_tests::native_lane_sample_snapshot_retains_raw_source_through_both_cut_refusal_and_retry"]),
    m("HC19", "AMX: classify local decoder refusal as a deterministic instruction failure",
      ["sumeragi::amx::tests::amx_anchor_decode_refusal_cannot_publish_even_when_instruction_error_is_caught",
       "sumeragi::amx::tests::amx_relay_decode_refusal_keeps_original_undecided_record_and_retries_proof"]),
    m("HC20", "stored result reader: classify local decoder refusal as corrupt storage",
      ["sumeragi::block_store::body_read::tests::stored_result_decode_refusal_retains_original_decoded_owners_and_retries",
       "sumeragi::block_store::committed_read::tests::committed_result_decode_refusal_keeps_original_read_slot_and_retries"]),
    m("HC21", "root startup: substitute a foreign Kura for the original State store",
      ["sumeragi::node::tests::root_owner_tests::prepared_root_uses_original_state_store"]),
    m("HC22", "queue: omit the original signed entrypoint security-domain check",
      ["queue::tests::queue_rejects_preaccepted_foreign_external_before_custody",
       "queue::tests::queue_rejects_preaccepted_foreign_commitment_before_custody",
       "queue::tests::queue_rejects_preaccepted_foreign_reveal_before_custody"]),
    m("HC24", "stored result reader: allocate a replacement diagnostic after local refusal",
      ["sumeragi::block_store::body_read::tests::stored_result_decode_refusal_retains_original_decoded_owners_and_retries",
       "sumeragi::block_store::committed_read::tests::committed_result_decode_refusal_keeps_original_read_slot_and_retries"]),
    m("HC23", "P2P startup: ignore refusal by the original retained subscription actor",
      ["sumeragi::node::tests::p2p_owner_tests::network_start_rejects_closed_retained_actor_before_driver_files"]),
    m("HC25", "stored certificate decoder: classify physical allocator refusal as corruption",
      ["sumeragi::block_store::body_read::tests::stored_certificate_allocator_refusal_keeps_original_read_and_retries",
       "sumeragi::block_store::committed_read::tests::committed_certificate_allocator_refusal_retains_original_slot_and_retries"]),
    m("HC26", "AMX: grant global coordinator authority to private-root bootstrap",
      ["sumeragi::node::tests::dataspace_roots::amx_scope_tests::signed_private_genesis_cannot_install_global_amx_coordinator",
       "executor::root_scope::tests::amx_roles::every_amx_coordinator_instruction_rejects_private_execution_before_proof_decoding"]),
    m("HC27", "execution root: discard local metadata decode refusal before publication",
      ["sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_work_keeps_scope_decode_refusal_local_and_retries_original_carrier"]),
    m("HC28", "read-only scope: turn local decoder refusal into a completed query/VM error",
      ["sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_manifest_query_does_not_turn_scope_refusal_into_permanent_error",
       "sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_host_query_keeps_scope_refusal_out_of_completed_vm_errors"]),
    m("HC29", "lane batch: classify local decoder refusal as malformed or Invalid",
      ["sumeragi::lanes::tests::original_signed_batch_decode_preserves_exact_local_refusal_and_terminal_limits",
       "sumeragi::lanes::registry::tests::authenticated_registry_batch_decode_refusal_is_retryable_not_byzantine",
       "sumeragi::lanes::executor::native_decode_tests::signed_four_validator_lane_execution_refusal_never_caches_invalid_or_publishes",
       "sumeragi::lanes::executor::native_decode_tests::signed_four_validator_lane_recovery_keeps_available_phase_and_exact_original_owners"]),
    m("HC31", "lane canonicalization: allocate replacement input and output payloads",
      ["sumeragi::lanes::tests::signed_lane_batch_canonical_validation_preserves_original_bytes_without_new_allocations"]),
    m("HC30", "registry: turn original scope or permission decode refusal into a completed fee or authorization outcome",
      ['sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_contract_lookup_does_not_turn_scope_refusal_into_vm_permission_denial',
       'sumeragi::node::tests::dataspace_roots::scope_refusal_tests::signed_private_account_permission_read_defers_without_constructing_a_json_token',
       'validation_fee::tests::registry_refusal_tests::signed_fee_runtime_read_does_not_turn_scope_refusal_into_a_nonmatching_origin',
       'validation_fee::tests::registry_refusal_tests::original_retained_fee_registry_does_not_publish_local_decode_refusal_as_malformed',
       'smartcontracts::isi::world::isi::tests::signed_payout_scope_refusal_cannot_publish_a_parliament_terminal_outcome']),
    m("HC32", "reward credit readers: turn original alias or owner decode refusal into malformed durable leaves",
      ["validation_fee_rewards::tests::original_fee_credit_alias_decode_refusal_preserves_balance_and_retries",
       "validation_fee_rewards::tests::original_fee_credit_owner_decode_refusal_preserves_exact_binding_and_retries"]),
    m("HC33", "credit refusal classifier: borrow any active scope for a global or inner format limit",
      ["execution_attempt::tests::norito_global_archive_cap_is_terminal_inside_an_outer_decode_scope",
       "execution_attempt::tests::norito_inner_format_limits_are_terminal_under_a_wider_outer_scope"]),
    m("HC35", "SNS permission projection: turn original local refusal into a completed permission rejection",
      ["executor::tests::original_sns_alias_domain_permission_refusal_retries_without_a_rejection",
       "executor::tests::original_sns_domain_transfer_permission_refusal_retries_without_a_rejection"]),
    m("HC36", "claim fee exemption: turn original metadata or alias read refusal into a paid fee verdict",
      ["executor::tests::original_claim_metadata_refusal_defers_fee_quote_and_retries_exact_payload",
       "executor::tests::original_claim_alias_refusal_after_metadata_defers_fee_quote_and_retries"]),
    m("HC37", "fee selector: turn canonical account or NPoS currency read refusal into absence",
      ["block::original_canonical_account_refusal_does_not_fall_through_to_alias_absence",
       "executor::tests::original_network_xor_pin_refusal_defers_quote_and_retries_same_parameter"]),
    m("HC34", "native maintenance: omit applied native transcripts from dedicated pool accounting",
      ['fastpq::source_reservation::admission::tests::native_authorization_has_no_entry_until_an_applied_transcript_and_drops_atomically',
       'fastpq::source_reservation::admission::tests::native_pool_overflow_cannot_borrow_ordinary_or_governance_reservations']),


    m("HC38", "routing: publish an original SNS read refusal as a completed route error",
      ["queue::router::tests::original_dataspace_alias_read_refusal_keeps_routing_retryable",
       "queue::router::tests::original_physical_policy_read_refusal_never_enters_captured_row",
       "executor::root_scope::tests::original_private_instruction_routing_refusal_latches_before_scope_verdict"]),
    m("HC39", "native routing: publish original scope or policy JSON refusal as invalid context",
      ["state::network_policy_routes::tests::original_root_scope_read_refusal_does_not_publish_invalid_native_context",
       "state::network_policy_routes::tests::original_lane_policy_read_refusal_after_root_keeps_exact_capture_retryable"]),

    m("HC40", "account routing: turn original SNS or canonical account read refusal into a completed mismatch",
      ['queue::router::tests::account_refusal_tests::original_account_target_refusal_never_selects_the_default_route', 'queue::router::tests::account_refusal_tests::original_canonical_account_matcher_preserves_decode_refusal_and_retry', 'queue::router::tests::account_refusal_tests::original_signed_account_matcher_refusal_is_not_a_mismatch_or_panic', 'queue::router::tests::account_refusal_tests::original_native_policy_account_matcher_retains_refusal_before_route_selection']),

    m("HC41", "parameter control: use a private account rule for global physical policy",
      ["queue::router::alias_registry_routing_tests::parameter_control_preserves_global_physical_route_before_private_account_rule",
       "queue::router::alias_registry_routing_tests::alias_registry_routing_paid_post_genesis_dataspace_domain_and_renewal",
       "queue::router::alias_registry_routing_tests::alias_registry_routing_cold_replay_with_expanded_catalog_preserves_paid_bootstrap"]),

    m("HC42", "SNS auto-renew: reject exact current-owner replacement after authenticated account rekey",
      ['smartcontracts::isi::sns::rekey_auto_renew_tests::signed_rekey_current_owner_can_replace_stale_auto_renew_configuration', 'smartcontracts::isi::sns::rekey_auto_renew_tests::signed_rekey_same_configuration_requires_owner_replacement_cas', 'smartcontracts::isi::sns::rekey_auto_renew_tests::signed_rekey_disabled_clean_record_requires_exact_owner_revision']),
    m("HC43", "certified history: classify an original local read refusal as malformed committed input",
      ['sumeragi::certified_chain::refusal_tests::original_result_frame_refusal_is_local_and_same_bytes_retry', 'sumeragi::certified_chain::refusal_tests::original_successor_history_refusal_is_local_and_same_source_retries', 'sumeragi::certified_chain::tests::state_certificate::state_certificate_native_qc_decode_refusal_is_capacity_and_retries_original_source']),
    m("HC45", "payload worker: discard the original typed local decoder refusal",
      ["sumeragi::executor::payload_refusal_tests::original_available_payload_local_decode_refusal_keeps_typed_worker_reason_and_retry"]),
    m("HC46", "decode classifier: reject a valid original under a surviving narrower caller depth",
      ["execution_attempt::tests::original_surviving_narrow_decode_depth_refusal_retries_identical_bytes",
       "sumeragi::executor::payload_refusal_tests::original_available_payload_narrow_depth_refusal_keeps_typed_worker_reason_and_retry"]),
    m("HC44", "execution worker: discard original validation and certificate read refusal before retry diagnostics",
      ["sumeragi::executor::validation_refusal_tests::original_post_merge_validation_refusal_retains_worker_owner_and_exact_available_retry",
       "sumeragi::executor::validation_refusal_tests::original_prepared_certificate_read_refusal_retains_worker_owner_and_funded_execution"]),
    m("HC49", "staking payload: erase original evidence and State preparation refusal owners",
      ["sumeragi::penalties::tests::original_staking_payload_refusal_retains_evidence_pool_and_exact_assembly_retry",
       "sumeragi::executor::publication_tests::original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry"]),


    m("HC47", "availability attempts: discard original local read or queued retry ownership",
      ['sumeragi::certified_chain::refusal_tests::original_availability_history_refusal_is_pending_without_corruption', 'sumeragi::certified_chain::refusal_tests::original_availability_constructor_refusal_retries_without_installing_authority', 'sumeragi::driver::exec::refusal_tests::append_refusal_keeps_original_commit_and_release_owner_until_durable', 'sumeragi::driver::serve::tests::refused_metadata_owner_cannot_be_replaced_by_another_peer_during_backoff']),
    m("HC51", "lane history: erase original archive, prefix, evidence or proposal policy refusal",
      ['sumeragi::runtime_availability::history::source_refusal_tests::original_archive_read_refusal_preserves_pool_release_and_same_lane_prefix', 'sumeragi::runtime_availability::history::source_refusal_tests::original_certificate_projection_refusal_preserves_pool_release_and_exact_carrier', 'sumeragi::runtime_availability::history::source_refusal_tests::original_lane_evidence_handoff_preserves_actual_decode_refusal_and_exact_cut', 'sumeragi::lanes::registry::tests::original_native_lane_authority_refusal_reaches_merge_and_original_pool_retry', 'sumeragi::evidence::tests::original_lane_history_refusal_reaches_evidence_without_recovery_or_rejection', 'sumeragi::executor::publication_tests::original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry']),
    m("HC87", "stake-index quantities: release original magnitude charges before their physical owners",
      ["smartcontracts::isi::staking::tests::stake_index_quantities_prepaid_and_borrowed_from_original_pool"]),
    m("HC94", "replay completion: accept replacement source configuration after receipt retirement",
      ["sumeragi::executor::publication_tests::replay_completion_retirement_keeps_exact_source_and_original_pool_retry"]),
    m("HC53", "network time: omit host suspension from admission time and probe custody",
      ['time::tests::suspend_inclusive_clock_advances_admission_and_expires_retained_probes', 'time::tests::suspend_inclusive_clock_counts_entire_probe_round_trip']),
    m("HC48", "incumbent authority and key lifecycle: turn local read refusal into completed instruction failure",
      ['state::validator_committee::tests::refusal::original_incumbent_history_refusal_keeps_authority_and_same_source_retry', 'state::validator_committee::tests::refusal::original_candidate_authority_refusal_keeps_command_and_same_source_retry', 'state::validator_committee::tests::refusal::original_candidate_command_decode_refusal_has_no_publication_and_retries', 'state::validator_committee::tests::refusal::original_beacon_public_state_decode_refusal_defers_before_installation', 'state::validator_committee::tests::refusal::original_tle_public_state_decode_refusal_defers_before_installation', 'state::validator_committee::tests::refusal::original_staking_authority_refusal_keeps_exit_overlay_and_same_signed_retry']),
    m("HC50", "original NPoS policy: erase local decoder refusal as absent authority",
      ['state::validator_committee::tests::refusal::original_npos_parameter_refusal_does_not_become_missing_staking_policy', 'state::validator_committee::tests::refusal::original_npos_exit_policy_refusal_keeps_stake_and_same_signed_retry', 'state::validator_committee::tests::refusal::original_npos_reserve_validation_refuses_without_changing_current_or_undo', 'smartcontracts::ivm::host::return_resource_tests::original_npos_policy_refusal_preserves_host_seed_projection_and_retries', 'sumeragi::evidence::tests::original_npos_policy_refusal_cannot_prune_retained_evidence', 'state::validator_committee::tests::refusal::late_original_npos_activation_read_refusal_rolls_back_and_same_signed_retry', 'sumeragi::evidence_history::lane::tests::original_lane_observer_late_policy_refusal_retains_observation_and_retries']),

    m("HC52", "checkpoint reader: turn original binary decoder refusal into completed invalidity",
      ['sumeragi::finality::tests::original_checkpoint_binary_refusal_is_local_and_retries_exact_original_source']),
    m("HC54", "beacon custody: accept a genuine same-roster DKG from another authority generation",
      ['state::validator_committee::tests::generation::committee_bootstrap_rejects_genuine_dkg_from_another_generation', 'state::validator_committee::tests::generation::committee_restore_rejects_genuine_dkg_from_another_generation']),
    m("HC95", "native AMX participant: let a certified Begin authorize a different signed debit source",
      ["sumeragi::amx::native::tests::native_amx_paid_commit_survives_certified_restart_and_rejects_bypass"]),
    m("HC55", "fee reward claims: ignore signed custody, entitlement and beneficiary preconditions",
      ['validation_fee_rewards::tests::signed_fee_reward_claim_rejects_every_changed_binding_before_mutation']),
    m("HC56", "shared custody: omit fee obligations from the combined staking and reward reserve floor",
      ['validation_fee_rewards::tests::shared_fee_stake_reward_custody_is_additive']),
    m("HC57", "startup replay: acknowledge a changed certificate or availability source as an exact retry",
      ['sumeragi::executor::replay::tests::completed_replay_rejects_altered_certificate_and_source_without_losing_exact_retry']),
    m("HC58", "shared network currency: admit substitute, scoped or wrong-precision XOR custody",
      ['validation_fee_rewards::tests::canonical_network_xor_is_required_before_fee_reward_state_changes',
       'state::network_xor::tests::network_xor_rejects_wrong_definition_scope_and_precision',
       'smartcontracts::isi::staking::tests::staking_registration_rejects_wrong_xor_shape_with_transaction_rollback',
       'smartcontracts::isi::staking::tests::reward_claim_rejects_wrong_xor_shape_with_transaction_rollback']),
    m("HC59", "beacon reducer: retain a well-formed but unverified partial signature",
      ['beacon::tests::threshold_beacon_inline_reducer_rejects_invalid_share_without_losing_original_slots']),
    m("HC60", "publication preparation: erase the original pool refusal at scheduler handoff",
      ['sumeragi::executor::preparation::tests::certificate_capacity_refusal_reaches_scheduler_with_original_release_and_execution']),
    m("HC61", "lane anchor history: turn original pool refusal into an invalid anchor verdict",
      ['sumeragi::lanes::executor::native_decode_tests::anchor_read_refusal_retains_original_lane_body_until_capacity_returns',
       'sumeragi::lanes::evidence::tests::anchor_history_refusal_retains_exact_source_through_lane_evidence_retry']),
    m("HC62", "prepared block custody: accept a different shared control carrying identical certified bytes",
      ['sumeragi::executor::publication_tests::prepared_block_moves_original_graph_and_rejects_replaced_shared_control']),
    m("HC63", "State publication: erase original physical lock or allocation refusal before scheduler retry",
      ['sumeragi::executor::publication::tests::state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release',
       'sumeragi::executor::publication::tests::state_execution_and_membership_refusals_preserve_actual_release_owners']),
    m("HC64", "committed archive capture: erase original history or archive index refusal",
      ['sumeragi::executor::archive_tests::committed_archive_index_refusal_retains_original_release_and_exact_publication',
       'sumeragi::executor::archive_tests::committed_archive_cold_history_refusal_retains_original_pool_and_exact_publication']),
    m("HC65", "cold publication preparation: erase the original execution refusal before scheduler retry",
      ['sumeragi::executor::preparation::tests::cold_prepare_refusal_retains_original_finishing_owner_and_exact_release',
       'sumeragi::executor::preparation::tests::cold_prepare_validation_refusals_retain_original_storage_owners']),
    m("HC66", "opaque host and replay effects: derive unsigned staking monetary plans",
      ['executor::opaque_monetary_tests::raw_ivm_staking_trigger_requires_signed_monetary_plan',
       'executor::opaque_monetary_tests::supplied_proved_staking_effects_require_signed_monetary_plan']),
    m("HC67", "live multisig proposal: classify a local decoder refusal as malformed authority",
      ['smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_decode_refusal_retries_original_signed_xor_claim']),
    m("HC68", "retained multisig proposal: accept an unapproved body or rebound physical row",
      ['smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_body_binding_rolls_back_original_signed_xor_claim',
       'smartcontracts::isi::multisig::tests::proposal_attempt::proposal_migration_validates_original_physical_key_and_body_before_writes',
       'queue::router::tests::persisted_multisig_body_binding_and_local_refusal_reach_signed_queue_admission',
       'state::deserialize::decode_tests::restored_multisig_proposals_require_exact_body_and_preserve_local_read_refusal']),
    m("HC69", "multisig cancellation and expiry: treat unfinished custom decoding as a nonmatch",
      ['smartcontracts::isi::multisig::tests::proposal_attempt::cancel_wrapper_decode_refusal_rolls_back_and_retries_original_signed_approval',
       'smartcontracts::isi::multisig::tests::proposal_attempt::expiry_child_decode_refusal_rolls_back_and_retries_original_signed_approval']),
    m("HC70", "multisig queue traversal: ignore the native deferred execution depth bound",
      ['queue::router::tests::persisted_multisig_chain_is_checked_in_linear_expansions']),
    m("HC71", "original World Cell acquisition: discard typed physical contention through infallible initialization",
      ['sumeragi::executor::preparation::tests::cold_prepare_validation_refusals_retain_original_storage_owners']),
    m("HC72", "prepared certificate reader: stringify actual State view contention",
      ['sumeragi::executor::validation_refusal_tests::prepared_certificate_busy_retries_same_execution_after_original_reader_release']),
    m("HC73", "physical history contention: substitute logical membership cleanup as the retry source",
      ['state::storage_transactions::history::tests::physical_history_busy_ignores_logical_cleanup_and_retries_actual_release',
       'sumeragi::executor::publication::tests::state_publication_lock_refusals_reach_scheduler_with_original_execution_and_release']),
    m("HC74", "committed-head retry: let a timer replace the original refusing source",
      ["sumeragi::driver::exec::source_retry_tests::committed_head_waits_for_original_release_across_prepare_append_and_commit"]),
    m("HC75", "DA cold reconstruction: refund original allocation while physical writers remain held",
      ["state::da_hydration::release_tests::original_cold_da_refunds_follow_all_rebuild_and_rewind_writers"]),
    m("HC76", "execution producer retry: let timers replace original physical refusal custody",
      ["sumeragi::driver::exec::producer_retry_tests::every_execution_producer_retains_original_source_until_actual_release"]),
    m("HC78", "execution producer cancellation: resurrect an original in-flight request when its context returns",
      ["sumeragi::driver::exec::producer_retry_tests::cancellation_stays_final_when_the_identical_context_and_request_return"]),

    m("HC77", "pending ingress admission: let loop progress replace the original refusing source",
      ["sumeragi::driver::witness_admission_tests::pending_capacity_requires_original_release_despite_foreign_wake_and_huge_clock"]),
    m("HC80", "admitted ingress eviction: refund original capacity beneath pending and ingress mutexes",
      ["sumeragi::driver::witness_admission_tests::admitted_ingress_eviction_refunds_only_after_pending_and_ingress_mutexes_release"]),
    m("HC79", "completed replay acknowledgement: stringify original encoding capacity refusal",
      ["sumeragi::executor::replay::tests::completed_replay_retains_exact_receipt_through_original_pool_scratch_refusal"]),
    m("HC81", "native beacon readiness: stringify the original startup control refusal",
      ["sumeragi::executor::publication_tests::beacon_startup_retains_original_capacity_through_worker_channel_and_node"]),
    m("HC82", "cold World-root verification: stringify the original storage refusal",
      ["sumeragi::test_chain::tests::world_state_tests::world_root_verification_preserves_original_writer_refusal_and_exact_retry",
       "sumeragi::test_chain::tests::world_state_tests::world_root_verification_preserves_original_capacity_refusal_and_exact_retry"]),
    m("HC83", "scheduler retirement: refund original controls before cancelling all registered waiters",
      ["sumeragi::driver::exec::producer_retry_tests::cancelling_and_dropping_scheduler_unlinks_all_waiters_before_original_refunds"]),
    m("HC84", "startup committed history: collapse original cold-read refusal into invalid configuration",
      ["kura::tests::startup_history_retains_original_cold_kura_refusal_and_exact_retry"]),
    m("HC85", "beacon: reuse authenticated shared session under a substituted current binding",
      ["beacon::session_owner::validated::tests::shared_authenticated_session_rechecks_every_current_external_binding"]),
    m("HC86", "native execution: retry an original local custody invariant instead of requiring recovery",
      ["sumeragi::executor::preparation::tests::original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine"]),
    m("HC88", "beacon decoder: collapse original surviving decode scope refusal into invalid input",
      ["beacon::tests::session_decoder_preserves_actual_local_scope_without_invalidity_or_fabricated_pool"]),
    m("HC89", "credential decoder: reject original inherited-scope or physical allocation refusal",
      ["beacon::credential::tests::credential_decoder_captures_original_scope_before_unwind_and_retries_unchanged_bytes",
       "beacon::credential::tests::credential_decoder_physical_refusal_keeps_exact_allocator_cause_and_retries"]),
    m("HC90", "native journal: replace original block-control capacity refusal with invalid evidence",
      ["sumeragi::native_journal::tests::native_cursor_preserves_original_pool_refusal_and_retries_identical_prefix"]),
    m("HC91", "live DKG: reconstruct signature output only after the durable attempt claim and RNG",
      ["beacon::dkg_local_seat::ownership_tests::prepared_local_outputs_are_complete_before_randomness_at_four_and_thirty_one"]),
    m("HC92", "credential output: allocate a second whole secret frame after private extraction",
      ["beacon::credential::prepared_output::tests::prepared_credential_uses_exact_original_output_without_late_growth_at_four_and_thirty_one"]),
    m("HC96", "validation-fee permission guard: treat a failed protected registry read as unrestricted delegation",
      ["validation_fee::tests::permission_guard_tests::malformed_protected_registry_rejects_account_grant_before_permission_mutation"]),
    m("HC97", "validation-fee trigger permission guard: discard a recognized trigger payload decode error and permit delegation",
      ["validation_fee::tests::permission_guard_tests::trigger_permission_guard_tests::malformed_trigger_permission_rejects_account_grant_before_mutation"]),
    m("HC98", "native source publication: halt instead of reacquiring ordinary State publication",
      ["sumeragi::executor::preparation::tests::native_source_publication_change_retries_without_recovery_or_quarantine"]),
    m("HC99", "native source publication: replace the original local capacity refusal",
      ["block::valid::native_header_source_tests::native_local_refusal_after_source_publication_retains_original_capacity"]),
    m("HC100", "election rank: bind candidate selection to E+1 instead of the frozen E+2 target",
      ["sumeragi::epoch_election::tests::genuine_candidate_pools_choose_largest_equal_vote_committee"]),
    m("HC101", "committee readiness: one funded target substitutes for every frozen target seat",
      ["sumeragi::epoch_election::tests::prepared_boundary_readiness_requires_every_frozen_seat_custody"]),
    m("HC102", "committee readiness: target quorum substitutes for the complete signed readiness roster",
      ["sumeragi::epoch_election::tests::prepared_boundary_readiness_requires_every_frozen_seat_custody"]),
    m("HC103", "retention: demand fresh incumbent BLS publications for the retained authority generation",
      ["sumeragi::epoch_election::tests::frozen_boundary_refusal_returns_original_pool_and_does_not_need_fresh_incumbent_keys"]),
    m("HC104", "DKG checkpoint: allow a foreign native clock to supply generation source authority",
      ["beacon::dkg_local_seat::checkpoint_authority::tests::signed_genesis_authority_keeps_original_wider_cutoff_and_authenticates_no_h1_result"]),
    m("HC108", "DKG checkpoint: extend the original signed genesis cutoff",
      ["beacon::dkg_local_seat::checkpoint_authority::tests::signed_genesis_authority_keeps_original_wider_cutoff_and_authenticates_no_h1_result"]),
    m("HC112", "DKG delivery restore: retire the original polynomial before its durable publication barriers",
      ["beacon::dkg_local_seat::restore::tests::actual_native_heads_restore_original_delivery_then_acceptance_without_signing_or_growth"]),
    m("HC113", "DKG acceptance restore: omit original signed capsule decryption and private component equality",
      ["beacon::dkg_local_seat::restore::tests::original_signed_capsule_relation_is_checked_before_any_accepted_owner_or_row_moves"]),
    m("HC114", "DKG aggregate authority: omit the actual finalized native-tip height binding",
      ["beacon::dkg_local_seat::aggregate::tests::aggregate_checked_context_refuses_nonfinal_native_tip_zero_intent_and_changed_original_checkpoint"]),
    m("HC115", "DKG aggregate production: erase original contributions and acknowledgments before durable handoff",
      ["beacon::dkg_local_seat::aggregate::tests::actual_native_h4_aggregate_stays_original_until_explicit_retirement_and_restores_small_owner"]),
    m("HC118", "native journal source: omit the original prepared source pool binding",
      ["sumeragi::native_journal::tests::source_tests::native_reader_rejects_foreign_prepared_source_pool_before_decode_or_control_admission"]),
    m("HC120", "signed evidence root: collapse original immutable-root JSON refusal into invalid input",
      ["sumeragi::evidence::tests::original_signed_evidence_root_scope_refusal_stays_local_and_retries_same_state",
       "sumeragi::evidence::tests::original_root_observation_refusal_keeps_pending_bytes_and_same_state_retry"]),
    m("HC121", "quantity source: replace original invocation dataspace with temporary fee-storage namespace",
      ["sumeragi::lanes::merge::tests::paid_quantity_source::paid_merged_lane_burn_keeps_original_nonuniversal_source",
       "state::output_capacity::producer::internal::root_scope_tests::original_invocation_capture_keeps_fee_storage_separate_and_rejects_call_lane_confusion"]),
    m("HC122", "lane registry: retain a retired historical ready store after its final reader closes",
      ["sumeragi::lanes::registry::tests::retired_historical_ready_store_releases_last_owner_after_completed_reader"]),
    m("HC123", "lane retirement: drop original pending read and publication owners before batch population",
      ["sumeragi::lanes::registry::tests::retired_ready_store_preserves_original_read_refusal_before_batch_population",
       "sumeragi::lanes::registry::tests::retired_ready_store_preserves_original_unfinished_publication_until_exact_retry",
       "sumeragi::lanes::store::retirement_probe_tests::retirement_pending_work_probe_retains_each_held_mutex_without_waiting"]),
    m("HC124", "lane opening: erase a historical join when its runtime recovery retires",
      ["sumeragi::lanes::registry::tests::historical_join_of_runtime_opening_retains_original_recovery_after_lane_retirement"]),
    m("HC125", "lane source tip: return cached height despite original read authentication failure or refusal",
      ["sumeragi::lanes::registry::tests::ready_tip_preserves_same_original_authentication_failure_without_reopening",
       "sumeragi::lanes::registry::tests::ready_tip_retains_original_pool_refusal_and_completed_read_until_normal_consumption"]),

    m("HC126", "BLS admission: reuse a local key credential under a changed proof of possession",
      ["sumeragi::crypto::tests::repeated_exact_pop_admission_retains_original_credential",
       "sumeragi::crypto::tests::repeated_committee_admission_retains_owners_and_failed_batch_is_atomic"]),

    m("HC127", "Core Nexus snapshot: write retained runtime undo without its explicit present-value frame",
      ["state::tests::snapshot_runtime_requires_exact_retained_predecessor_and_roundtrips_both_cuts"]),
    m("HC130", "execution retry: discard original completed decoded proposal and reenter canonical decoding",
      ["sumeragi::executor::decoded_custody_tests::completed_decoded_retry_borrows_original_graph_without_canonical_reentry"]),
    m("HC131", "execution custody: accept a distinct same-source same-pool prepared signature control",
      ["sumeragi::executor::decoded_custody_tests::same_source_same_pool_distinct_prepared_signature_owner_is_refused_at_both_boundaries"]),

    m("HC128", "local payload: publish canonical wire before original-pool empty signature preparation",
      ["sumeragi::executor::local_signature_preparation_tests::original_local_payload_signature_refusal_keeps_job_and_exact_release_owner"]),

    m("HC129", "native validation: retry after a consuming unwind lost its original graph",
      ["sumeragi::executor::tests::consuming_validation_unwind_requires_recovery_after_original_owner_is_lost"]),
    m("HC132", "native proposal: omit the required top-up seal outside an epoch boundary",
      ["sumeragi::executor::attestation_policy_tests::native_top_up_proposal_requires_attestation_before_an_epoch_boundary"]),

]


# Daemon integration rules execute only in the owning daemon unit-test crate.
DAEMON_MUTATIONS = [
    m("HC105", "DKG generation restore: ignore original input marker or later producer intent",
      ["beacon_bootstrap::seat_attempt::durable_tests::input_marker_or_later_intent_cannot_restore_generation_or_grant_a_new_interval"]),
    m("HC106", "DKG generation restore: accept a replaced inherited input stream",
      ["beacon_bootstrap::seat_attempt::durable_tests::generation_reload_rejects_foreign_provider_original_cutoff_fake_h1_result_and_replaced_input"]),
    m("HC107", "DKG generation restore: replace original native expiry with a fresh caller interval",
      ["beacon_bootstrap::seat_attempt::durable_deadline::tests::actual_native_boot_origin_freeze_restore_cannot_extend_admitted_deadline"]),
    m("HC109", "DKG generation restore: treat visible complete files as already durable",
      ["beacon_bootstrap::seat_attempt::durable::tests::visible_complete_original_head_is_synced_before_restored_claim_and_publication"]),
    m("HC110", "DKG target proof: consume the once-verified original FIFO frame before durable preservation",
      ["beacon_bootstrap::seat_attempt::finality::tests::original_verified_target_proof_publication_refusal_retains_frame_and_never_advances_twice"]),
    m("HC111", "DKG later restore: ignore a surviving partial extraction or final-session intent",
      ["beacon_bootstrap::seat_attempt::later_restore_tests::complete_original_later_head_never_reopens_partial_next_read_or_extraction_intent"]),
    m("HC116", "DKG aggregate restore: omit original held-source file and directory durability barriers",
      ["beacon_bootstrap::seat_attempt::aggregate_tests::original_complete_aggregate_and_four_output_heads_restore_genuine_h3_h4_ancestry_same_claim_and_exact_private_bytes"]),
    m("HC117", "DKG aggregate export restore: treat a partial output set as an empty fresh destination",
      ["beacon_bootstrap::seat_attempt::aggregate_tests::original_aggregate_head_rejects_partial_final_output_prefix_before_private_export_adoption"]),
    m("HC119", "DKG native replay: pin a foreign charged proof source before checking its original pool",
      ["beacon_bootstrap::seat_attempt::finality::tests::durable_native_replay_rejects_foreign_source_pool_without_pinning_or_advancing"]),
    m("HC93", "broker beacon operation: reconstruct the authenticated session at every phase",
      ["runtime_provider_broker::protocol::platform::tests::beacon_operation_reuses_original_graph_across_ingress_dispatch_and_response"]),
]


def index_mutations(mutations):
    """Reject duplicate ids before selecting a test or counting a mutation kill."""
    indexed = {}
    for mutation in mutations:
        if mutation.id in indexed:
            raise ValueError(f"duplicate mutation id {mutation.id}")
        indexed[mutation.id] = mutation
    return indexed


BY_ID = index_mutations(MUTATIONS)



def package_options(args):
    """Select the actual implementation owner without propagating a mutation to dependencies."""
    if getattr(args, "daemon", False):
        return "irohad_lib", "mutation-testing", "SUMERAGI_DAEMON_MUTATION"
    if getattr(args, "core", False):
        return "iroha_core", "mutation-testing,iroha-core-tests", "SUMERAGI_CORE_MUTATION"
    return CRATE, FEATURES, "SUMERAGI_MUTATION"

TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", re.M)
TEST_COMPLETION = re.compile(r"^test result: (ok|FAILED)\. \d+ passed; \d+ failed;", re.M)


@dataclass
class Step:
    status: str  # pass | fail | build-error | execution-error | timeout | missing-test | skipped
    seconds: float = 0.0
    failed: list = field(default_factory=list)
    ran: list = field(default_factory=list)
    detail: list = field(default_factory=list)
    log: str = ""


def cargo_test(args, target_dir, mutation, filters, seeds, timeout, log_path, no_run=False):
    """Run `cargo test` for the crate; returns (returncode or None on timeout, output)."""
    env = dict(os.environ)
    env.pop("SUMERAGI_MUTATION", None)
    env.pop("SUMERAGI_CORE_MUTATION", None)
    env.pop("SUMERAGI_DAEMON_MUTATION", None)
    crate, features, mutation_env = package_options(args)
    env.pop("SUMERAGI_SIM_SEED", None)
    env.pop("SUMERAGI_SIM_SEED_BASE", None)
    if mutation:
        env[mutation_env] = mutation
    if seeds is not None:
        env["SUMERAGI_SIM_SEEDS"] = str(seeds)
    else:
        env.pop("SUMERAGI_SIM_SEEDS", None)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    profile = getattr(args, "core_profile", None) if getattr(args, "core", False) else None
    profile_options = ["--profile", profile] if profile else ["--release"]
    cmd = ["cargo", "test", "--locked", "-p", crate, *profile_options, "--features", features, "--lib"]
    if no_run:
        cmd.append("--no-run")
    else:
        cmd += ["--"] + list(filters)
    started = time.monotonic()
    # Own this child session, but never signal Cargo when a deadline is missed.
    proc = subprocess.Popen(cmd, cwd=REPO, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout or None)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        # Keep the deadline verdict even if the naturally completed harness later
        # passes or reports a failed test; neither can qualify a late mutation.
        out, _ = proc.communicate()
        code = None
    elapsed = time.monotonic() - started
    # Spawning and completion processing also belong to this original deadline.
    # Keep all output, but a naturally completed late command cannot qualify.
    if timeout and elapsed > timeout:
        code = None
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as f:
        f.write(f"$ {' '.join(cmd)}\n# {mutation_env}={mutation or ''} "
                f"SUMERAGI_SIM_SEEDS={seeds or ''} CARGO_TARGET_DIR={target_dir}\n")
        f.write(out or "")
        f.write(f"\n# exit {code} after {elapsed:.1f}s\n")
    return code, out or "", elapsed


def run_step(args, target_dir, mutation, filters, seeds, timeout, log_path):
    code, out, elapsed = cargo_test(args, target_dir, mutation, filters, seeds, timeout, log_path)
    results = TEST_LINE.findall(out)
    ran = sorted({name for name, verdict in results if verdict != "ignored"})
    failed = sorted({name for name, verdict in results if verdict == "FAILED"})
    step = Step(status="pass", seconds=round(elapsed, 1), failed=failed, ran=ran,
                log=str(log_path))
    missing = [flt for flt in filters if not any(flt in name for name in ran)]
    if code is None:
        step.status = "timeout"
        step.detail.append(f"timed out after {timeout}s")
    elif "error[E" in out or "could not compile" in out:
        step.status = "build-error"
        step.detail = [line for line in out.splitlines() if line.startswith("error")][:5]
    elif code not in (0, 101) or (code != 0 and not failed):
        step.status = "execution-error"
        step.detail.append(f"cargo exited {code} without a normal completed test failure")
    elif failed:
        step.status = "fail"
        seeds_failed = re.findall(r"failing seeds (\[[^\]]*\])", out)
        violations = re.findall(r"violation: (.*)", out)
        panics = re.findall(r"panicked at [^\n]*\n([^\n]*)", out)
        step.detail = (seeds_failed[:3] + violations[:3] + panics[:3])[:6]
    if missing and step.status in ("pass", "fail"):
        step.detail.append(f"no executed test matched: {missing}")
        step.status = "missing-test"
    if step.status in ("pass", "fail"):
        expected = "FAILED" if step.status == "fail" else "ok"
        if TEST_COMPLETION.findall(out) != [expected] or code != (101 if failed else 0):
            step.status = "execution-error"
            step.detail.append("cargo did not complete exactly one expected test harness")
    return step


def build(args, target_dir, mutation, log_path):
    code, out, elapsed = cargo_test(args, target_dir, mutation, [], None, args.timeout_build,
                                    log_path, no_run=True)
    ok = code == 0
    detail = [] if ok else ([line for line in out.splitlines() if line.startswith("error")][:5]
                            or ["timeout" if code is None else f"cargo exited {code}"])
    return Step(status="pass" if ok else "build-error", seconds=round(elapsed, 1),
                detail=detail, log=str(log_path))


def has_switch(mid, *, core=False, daemon=False):
    if core and daemon:
        raise ValueError("a mutation has exactly one implementation owner")
    if daemon:
        cfg, source = "sumeragi_daemon_mutation", REPO / "crates" / "irohad" / "src"
    else:
        cfg = "sumeragi_core_mutation" if core else "sumeragi_mutation"
        source = REPO / "crates" / "iroha_core" / "src" if core else CRATE_SRC
    needle = f'{cfg} = "{mid}"'
    return any(needle in p.read_text() for p in source.rglob("*.rs"))


def evaluate(args, target_dir, mu):
    logs = args.target_dir / "logs"
    result = {"id": mu.id, "site": mu.site, "named_tests": list(mu.tests),
              "scenarios": [SCENARIOS[s] for s in mu.scenarios]}
    started = time.monotonic()
    if getattr(args, "daemon", False):
        present = has_switch(mu.id, daemon=True)
    else:
        present = has_switch(mu.id, core=True) if getattr(args, "core", False) else has_switch(mu.id)
    if not present:
        result.update(verdict="error", reason="no cfg switch for this id in the crate")
        return result
    b = build(args, target_dir, mu.id, logs / f"{mu.id}.build.log")
    result["build"] = b.__dict__
    if b.status != "pass":
        result.update(verdict="error", reason="mutant does not build")
        return result
    named = run_step(args, target_dir, mu.id, mu.tests, None, args.timeout_test,
                     logs / f"{mu.id}.named.log")
    result["named"] = named.__dict__
    killed_by_test = named.status == "fail"
    scen = None
    if mu.scenarios and not args.fast:
        filters = [SCENARIOS[s] for s in mu.scenarios]
        scen = run_step(args, target_dir, mu.id, filters, args.seeds, args.timeout_scenario,
                        logs / f"{mu.id}.scenario.log")
        result["scenario"] = scen.__dict__
    killed_by_scenario = scen is not None and scen.status == "fail"
    if named.status not in ("pass", "fail"):
        result.update(verdict="error", reason=f"named tests: {named.status}")
    elif scen is not None and scen.status not in ("pass", "fail"):
        result.update(verdict="error", reason=f"scenarios: {scen.status}")
    elif killed_by_test:
        result["verdict"] = "killed_by_test"
    elif killed_by_scenario:
        result["verdict"] = "killed_by_scenario_only"
    else:
        result["verdict"] = "survived"
    result["seconds"] = round(time.monotonic() - started, 1)
    return result


def evaluate_baseline(args, target_dir, mutations):
    logs = args.target_dir / "logs"
    result = {"id": "baseline"}
    b = build(args, target_dir, None, logs / "baseline.build.log")
    result["build"] = b.__dict__
    if b.status != "pass":
        result["verdict"] = "error"
        return result
    tests = sorted({t for mu in mutations for t in mu.tests})
    named = run_step(args, target_dir, None, tests, None, args.timeout_test,
                     logs / "baseline.named.log")
    result["named"] = named.__dict__
    ok = named.status == "pass"
    scenarios = sorted({s for mu in mutations for s in mu.scenarios})
    if scenarios and not args.fast:
        filters = [SCENARIOS[s] for s in scenarios]
        scen = run_step(args, target_dir, None, filters, args.seeds,
                        args.timeout_scenario, logs / "baseline.scenario.log")
        result["scenario"] = scen.__dict__
        ok = ok and scen.status == "pass"
    result["verdict"] = "pass" if ok else "fail"
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Sumeragi §13.4 mutation gate: every mutation must be killed by its named "
                    "deterministic test (then by its randomized scenario); the unmutated build "
                    "must pass.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    owner = parser.add_mutually_exclusive_group()
    owner.add_argument("--core", action="store_true",
                       help="qualify registered production iroha_core rules with their Core tests")
    owner.add_argument("--daemon", action="store_true",
                       help="qualify registered irohad_lib integration rules with daemon unit tests")
    parser.add_argument("--only", help="comma-separated mutation ids (default: all)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="parallel jobs, each with its own target sub-directory")
    parser.add_argument("--fast", action="store_true",
                        help="named deterministic tests only (skip the randomized scenarios)")
    parser.add_argument("--seeds", type=int, default=200,
                        help="SUMERAGI_SIM_SEEDS for the scenarios (default 200)")
    parser.add_argument("--target-dir", type=Path,
                        help="dedicated target root (default: target/sumeragi-mutants; --core: target/sumeragi-core-mutants; --daemon: target/sumeragi-daemon-mutants)")
    parser.add_argument("--skip-baseline", action="store_true",
                        help="do not run the unmutated build")
    parser.add_argument("--strict", action="store_true",
                        help="also fail when a mutation is killed only by its scenario "
                             "(the literal §13.4 CI rule)")
    parser.add_argument("--core-profile", choices=("release", "test"),
                        help="Core-only build profile (default: release); identical for baseline and mutant")
    parser.add_argument("--timeout-build", type=int, default=1200,
                        help="seconds per build deadline (0 disables its deadline)")
    parser.add_argument("--timeout-test", type=int, default=900,
                        help="seconds per named-test deadline (0 disables its deadline)")
    parser.add_argument("--timeout-scenario", type=int, default=3600,
                        help="seconds per scenario deadline (0 disables its deadline)")
    parser.add_argument("--list", action="store_true", help="print the mutation table and exit")
    args = parser.parse_args()
    if args.strict and args.skip_baseline:
        parser.error("--strict requires the unmutated baseline")
    if args.target_dir is None:
        name = ("sumeragi-daemon-mutants" if args.daemon else
                "sumeragi-core-mutants" if args.core else "sumeragi-mutants")
        args.target_dir = REPO / "target" / name
    args.target_dir = args.target_dir.resolve()
    if args.core_profile is not None and not args.core:
        parser.error("--core-profile requires --core; protocol and daemon qualification use release")
    table = DAEMON_MUTATIONS if args.daemon else CORE_MUTATIONS if args.core else MUTATIONS
    by_id = index_mutations(table)
    if min(args.timeout_build, args.timeout_test, args.timeout_scenario) < 0:
        parser.error("timeouts must be nonnegative; 0 waits without terminating a command")

    if args.list:
        for mu in table:
            print(f"{mu.id:22} {', '.join(mu.tests):60} {' '.join(mu.scenarios) or '-':10} "
                  f"{mu.site}")
        return 0

    selected = table
    if args.only:
        wanted = [x.strip() for x in args.only.split(",") if x.strip()]
        unknown = [x for x in wanted if x not in by_id]
        if unknown:
            parser.error(f"unknown mutation id(s): {', '.join(unknown)}")
        selected = [by_id[x] for x in wanted]
    args.target_dir.mkdir(parents=True, exist_ok=True)

    work = queue.Queue()
    if not args.skip_baseline:
        work.put(("baseline", None))
    for mu in selected:
        work.put(("mutation", mu))
    results = {}
    lock = threading.Lock()
    total = len(selected) + (0 if args.skip_baseline else 1)
    done = [0]

    def worker(index):
        target_dir = args.target_dir / f"job{index}"
        while True:
            try:
                kind, mu = work.get_nowait()
            except queue.Empty:
                return
            if kind == "baseline":
                res = evaluate_baseline(args, target_dir, selected)
            else:
                res = evaluate(args, target_dir, mu)
            with lock:
                results[res["id"]] = res
                done[0] += 1
                extra = res.get("reason", "")
                failed = res.get("named", {}).get("failed", [])
                print(f"[{done[0]}/{total}] {res['id']}: {res['verdict']} {extra} "
                      f"{' '.join(t.split('::')[-1] for t in failed)}", flush=True)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(max(1, args.jobs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    verdicts = {}
    for mu in selected:
        verdicts.setdefault(results[mu.id]["verdict"], []).append(mu.id)
    baseline = results.get("baseline")
    summary = {
        "baseline": baseline["verdict"] if baseline else "skipped",
        "mutations": len(selected),
        "killed_by_test": verdicts.get("killed_by_test", []),
        "killed_by_scenario_only": verdicts.get("killed_by_scenario_only", []),
        "survived": verdicts.get("survived", []),
        "error": verdicts.get("error", []),
        "scenario_missed": [mu.id for mu in selected
                            if results[mu.id].get("scenario", {}).get("status") == "pass"],
    }
    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "command": sys.argv,
        "package": package_options(args)[0],
        "profile": (args.core_profile or "release") if args.core else "release",
        "seeds": None if args.fast else args.seeds,
        "fast": args.fast,
        "summary": summary,
        "baseline": baseline,
        "mutations": [results[mu.id] for mu in selected],
    }
    report_path = args.target_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=1))
    print(json.dumps(summary, indent=1))
    print(f"report: {report_path}")
    failed = (summary["baseline"] not in ("pass", "skipped")
              or summary["survived"] or summary["error"]
              or (args.strict and summary["killed_by_scenario_only"]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
