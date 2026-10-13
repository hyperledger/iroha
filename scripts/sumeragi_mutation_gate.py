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
                               declared control. A process failure is not a mutation kill.

    Deadlines classify execution as an error. After a deadline the runner waits for
    its owned Cargo child to exit naturally and retains the output without sending
    termination signals. A late completed result never counts as a mutation kill.
    Each step discovers its actual filtered test names first and accounts for every
    terminal result and the complete libtest summary. Discovery and execution share
    the original step deadline; ignored or incomplete controls cannot establish a kill.
    A named step is a mutation's exact selector tuple. Baselines run each distinct
    tuple once; baseline and mutant randomized steps run one distinct scenario each.
    Qualified selectors require their exact full test path; leaf selectors require
    every exact final path segment in discovery. Cargo substring-selected extras
    remain fully accounted, but their failures cannot replace a declared control.
    These independent invocations retain the configured per-step deadlines, and any
    step error prevents the aggregate result from qualifying.

    The table MUTATIONS mirrors §13.4 (MS*/ML* rows and the MX* rows of the simulator's toy AMX application, §11) plus ME*
    (the as-built rules E1-E7 of Appendix E, with their regression tests) and MR-* (revision-4
    rules with det_r4 tests).

    `--core` selects the Core unit-test owner in the test profile and
    `SUMERAGI_CORE_MUTATION`;
    `--daemon` selects the daemon unit-test owner and `SUMERAGI_DAEMON_MUTATION`.
    `--model` selects DataModel unit tests in the test profile and its separate `SUMERAGI_MODEL_MUTATION`.
    `--sdk` and `--deploy` select their own unit-test crates in the test profile, with
    `SUMERAGI_SDK_MUTATION` and `SUMERAGI_DEPLOY_MUTATION`.
    `--torii` selects Torii canonical-outcome custody unit tests in the test profile
    with `SUMERAGI_TORII_MUTATION`.
    `--norito` selects canonical decode-origin unit tests in the test profile
    with `SUMERAGI_NORITO_MUTATION`.
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
    scripts/sumeragi_mutation_gate.py --torii --only TOR1 --strict --jobs 1
    scripts/sumeragi_mutation_gate.py --norito --strict --jobs 1
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
    "f39": "sim::tests::f39_clock_guard",
    "exact-quorum": "sim::tests::exact_quorum_under_genuine_superset_attack",
    # F9 variant for ML5a: a vote blackout ending at GST (sim/mutation_group_2.rs).
    "f09r": "sim::mutation_group_2::f09r_vote_blackout_until_gst",
    # F32 with up to f proposers of the needed blocks kept down after the restart (ML10).
    "f32s": "sim::mutation_group_3::f32s_cluster_restart_without_proposers",
    # F21 with the O3 halt oracle: the divergent node must halt by ApplyDiverged (MS34).
    "f21h": "sim::mutation_group_1::f21_divergent_executor_halts",
}


@dataclass(frozen=True)
class ExpectedFailure:
    """One declared assertion, with an optional original worker and fixture join."""
    cause: str
    source: str
    worker_thread: str = ""
    join_source: str = ""
    join_message: str = ""


@dataclass(frozen=True)
class Mutation:
    id: str
    site: str
    tests: tuple
    scenarios: tuple
    causes: tuple = ()


def m(mid, site, tests, scenarios=(), *, causes=()):
    tests, causes = tuple(tests), tuple(causes)
    if causes:
        if len(causes) != len(tests) or len(set(tests)) != len(tests) or any("::" not in name for name in tests):
            raise ValueError("causal mutations require one exact expectation per qualified control")
        for expected in causes:
            if (not isinstance(expected, ExpectedFailure) or not expected.cause or not expected.source
                    or bool(expected.worker_thread) != bool(expected.join_source)
                    or bool(expected.worker_thread) != bool(expected.join_message)):
                raise ValueError("causal mutation expectation is incomplete")
    return Mutation(mid, site, tests, tuple(scenarios), causes)


# id, site and change, named deterministic test(s), randomized scenario(s) — mirrors §13.4.
MUTATIONS = [
    m("MS71", "first Prepare signs without consulting its original application admission",
      ["machine::tests::signing::det_ct5_cached_execution_waits_for_stage_and_checks_actual_first_signing_time",
       "sim::world::clock_guard::tests::det_ct5_world_retained_execution_rechecks_clock_at_first_prepare"], [], causes=(
          ExpectedFailure("cached Valid cannot bypass first-Prepare freshness after stage delay",
              "crates/iroha_sumeragi/src/machine/tests/signing.rs"),
          ExpectedFailure("a retained World result must not sign after its actual wall clock advances",
              "crates/iroha_sumeragi/src/sim/world/clock_guard/tests.rs"))),
    m("MS72", "restore synthesizes a successful signature from an unsigned Prepare reservation",
      ["machine::tests::signing::det_ct5_unsigned_prepare_reservation_restart_never_synthesizes_first_signature"], [], causes=(ExpectedFailure("a durable unsigned reservation cannot synthesize a first Prepare without fresh source-bound execution or a genuine matching PQC",
          "crates/iroha_sumeragi/src/machine/tests/signing.rs"),)),
    m("MS73", "restore accepts a checksummed fabricated successful Prepare signature",
      ["machine::tests::signing::det_ct5_successful_prepare_signature_is_exact_durable_and_authenticated_on_restart"], [], causes=(ExpectedFailure("a checksummed fabricated successful signature is not restart authority",
          "crates/iroha_sumeragi/src/machine/tests/signing.rs"),)),
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
    m("MS39", "verify_qc accepts more than q genuine signers",
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
    # The application clock guard of §4.5: the core's `Execute.certified` flag (MS51) and the
    # simulator's model of the node executor's CT1 (MS52, a fake-driver mutation; the
    # production guard is the planned Core case SC5).
    m("MS51", "request_exec: emits Execute{certified: false} for a block a held PrepareQC certifies",
      ["f33_hidden_prepareqc_due_work_block_commits_after_lag",
       "det_s51_execute_certified_flag"], ["f39"]),
    m("MS52", "fake driver executor: the application clock guard CT1 deleted",
      ["clock_guard_certified_time_within_two_drifts",
       "clock_guard_liveness_with_f_plus_one_slow_clocks"], ["f39"]),
    m("MS65", "simulated execution and first-Prepare admission: the stale due-work clock guard CT5 deleted",
      ["clock_guard_due_work_lower_bound_at_first_prepare"], ["f39"]),
    m("MS66", "fake driver executor: CT1 omits the allowed clock drift",
      ["clock_guard_accepts_exact_drift_allowance",
       "clock_guard_liveness_with_f_plus_one_slow_clocks"], ["f39"]),
    m("MS67", "Prepare signer context: mistake a durable reservation for a certified value",
      ["machine::tests::signing::det_prepare_context_restart_reservation_alone_is_uncertified"],
      causes=(ExpectedFailure("a restarted durable Prepare reservation must not grant certified clock exemption",
          "crates/iroha_sumeragi/src/machine/tests/signing.rs"),)),
    m("MS68", "CT3 simulator builder: publish before the original canonical clock floor",
      ["sim::world::clock_guard::tests::clock_guard_committed_parent_wait_retains_work_until_clock_recovery"],
      causes=(ExpectedFailure("CT3 must retain original work without publishing before the parent and creation floors",
          "crates/iroha_sumeragi/src/sim/world/clock_guard/tests.rs"),)),
    m("MS69", "CT3 simulator builder: skip completed-payload clock recheck",
      ["sim::world::clock_guard::tests::clock_guard_completed_payload_waits_after_build_latency_backstep"],
      causes=(ExpectedFailure("CT3 must retain the original completed payload after a build-latency clock backstep",
          "crates/iroha_sumeragi/src/sim/world/clock_guard/tests.rs"),)),
    m("MS70", "CT3 simulator builder: sign a fresh proposal after its authored-queue clock backstep",
      ["sim::world::clock_guard::tests::clock_guard_fresh_proposal_waits_after_authored_queue_backstep"],
      causes=(ExpectedFailure("CT3 must not sign or publish a fresh proposal after an authored-queue clock backstep",
          "crates/iroha_sumeragi/src/sim/world/clock_guard/tests.rs"),)),
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
    m("ML31", "validate_chain: omits the outer sync response allowance",
      ["det_l31_chain_parameters_leave_a_feasible_sync_frame_budget"], []),
    m("ML32", "process_sync_buffer: existing body wants never learn sync responders",
      ["det_l32_sync_enriches_restored_body_want",
       "f28_seed177_restored_empty_body_want_catches_up"], ["f28"]),
    m("ML33", "process_sync_buffer: a verified donor is excluded by saturated source history",
      ["det_l33_verified_sync_donor_survives_saturated_history"], []),
    m("ML34", "process_sync_buffer: rejected deferred donor cannot refresh the missing height",
      ["det_l34_deferred_sync_donor_failure_refetches_current_height"], []),
    m("MS42", "original publication recovery does not halt the core",
      ["det_s42_original_publication_recovery_halts"], []),
    m("MS43", "signing domains omit epoch identity and complete context", ["det_s43_every_signature_binds_epoch_and_complete_context"], []),
    m("MS44", "ordinary lag-two scheduling installs a future epoch", ["det_s44_lag_two_cannot_install_next_epoch_early"], []),
    m("MS46", "header signatures omit application control", ["det_s46_control_witness_is_bound_by_header_hash_and_proposal_signature"], []),
    m("MS47", "real work invents an absent authenticated control response", ["det_s47_nonempty_work_waits_for_independent_control_and_preserves_original_payload"], []),
    m("MS48", "control response accepts another exact source", ["det_s48_control_response_requires_exact_request_epoch_view_and_parent_source"], []),
    m("MS53", "on_proposal: zero-payload signed-defect rejection omitted",
      ["empty_proposals_are_rejected_at_every_view"], []),
    m("MS54", "local signing refusal becomes a publishable and pooled signature",
      ["det_signing_refusal_prepare_preserves_reservation_without_pooling"], []),
    m("MS55", "aggregation refusal becomes a locally trusted certificate",
      ["det_aggregation_refusal_retains_verified_votes_without_certificates"], []),
    m("MS56", "safety envelope accepts another signature suite or certified-result contract",
      ["det_s56_safety_record_refuses_other_protocol_identity"], []),
    m("MS57", "restore installs retained or nested certificates without current-suite verification",
      ["det_s57_restart_verifies_every_retained_certificate",
       "det_s57_recommit_refuses_unverified_retained_lock_before_advancing_tip"], []),
    m("MS58", "retained verified quorums are never retried after local aggregation refusal",
      ["det_aggregation_refusal_retains_verified_votes_without_certificates"], []),
    m("MS59", "RS16 authoring substitutes a signature for a local signing refusal",
      ["det_signing_refusal_manifest_retains_original_request",
       "det_signing_refusal_row_retains_completed_signatures"], []),
    m("MS60", "reserved local signatures are never retried on the rebroadcast cadence",
      ["det_signing_refusal_proposal_preserves_reservation_without_publication",
       "det_signing_refusal_timeout_preserves_original_high_qc_on_retry"], []),
    m("MS61", "Status intake throttling consumes a failed probe Echo signing attempt",
      ["det_signing_refusal_echo_does_not_consume_rate_limit"], []),
    m("MS62", "an earlier successful Timeout suppresses retry of a refused current-view Timeout",
      ["det_signing_refusal_current_timeout_retries_with_prior_timeout_retained"], []),
    m("MS63", "a proposal signing retry consumes its reservation before the original body arrives",
      ["det_signing_retry_retains_restored_proposal_until_delayed_body_arrives"], []),
    m("MS64", "parent-only recommit waits for authority that the parent itself activates",
      ["det_s64_recommit_parent_only_record_authenticates_boundary_before_resuming",
       "det_s33_key_rotation_restart"], []),
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
    m("MX13", "Relayer: omit authenticated Begin's actionable expiry work",
      ["sim::tests::amx_final_payment::amx_final_payment_silent_participant_requires_actionable_abort"],
      causes=(ExpectedFailure("healthy global root must resolve the due final obligation without unrelated height advancement",
          "crates/iroha_sumeragi/src/sim/tests/amx_final_payment.rs"),)),
    m("MX14", "GlobalState::vote: permit Commit at or after the signed time expiry",
      ["sim::amx::tests::det_amx_time_expiry_orders_last_yes_and_expire_identically"],
      causes=(ExpectedFailure("signed time expiry must dominate the last Yes at the exact boundary regardless of payload order",
          "crates/iroha_sumeragi/src/sim/amx/tests.rs"),)),
    m("MX15", "AMX carrier classification: omit Begin and Vote from stale-time admission",
      ["sim::amx::tests::det_amx_time_sensitive_carriers_refuse_stale_time_but_certified_replay_is_exempt"],
      causes=(ExpectedFailure("Begin and Vote carriers must enforce certified-time freshness alongside Expire",
          "crates/iroha_sumeragi/src/sim/amx/tests.rs"),)),
]

# Core-owned rules use the same strict harness classifier; no simulator hook can stand in
# for production State/custody admission. Opt in explicitly with --core.
CORE_MUTATIONS = [
    m("HC343", "Private root role removal: omit canonical local role deletion",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::read_roles::native_private_read_role_removal_preserves_debit_and_survives_certified_restart"],
      causes=(ExpectedFailure("bank management must delete its dedicated read role through ordinary native authorization",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/read_roles.rs"),)),

    m("HC334", "omit native final freshness after original encoding and admission waits",
      ["sumeragi::executor::prepare_admission_tests::ct5_post_encoding_clock_advance_rolls_back_actual_begin_and_fees_with_original_decode",
       "sumeragi::executor::clock_tests::sccp_ct5_completion_resamples_clock_and_retains_original_for_certified_retry"],
      causes=(ExpectedFailure("time-sensitive effects must be locally deferred after the last encoding wait",
          "crates/iroha_core/src/sumeragi/executor/prepare_admission_tests.rs"),
          ExpectedFailure("CT5 must resample after completing the original execution before returning Valid",
          "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
          worker_thread="sumeragi-publication-test",
          join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          join_message="publication worker fixture: Any { .. }"))),

    m("HC335", "reuse cached native Valid without checking the actual wall clock",
      ["sumeragi::executor::prepare_admission_tests::ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source"], causes=(ExpectedFailure("cached native Valid cannot bypass a fresh local clock check",
          "crates/iroha_core/src/sumeragi/executor/prepare_admission_tests.rs"),)),
    m("HC336", "allow a first-Prepare request to substitute the original native result",
      ["sumeragi::executor::prepare_admission_tests::ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source"], causes=(ExpectedFailure("a certificate flag cannot substitute another result",
          "crates/iroha_core/src/sumeragi/executor/prepare_admission_tests.rs"),)),
    m("HC337", "omit native first-signing freshness after execution",
      ["sumeragi::executor::prepare_admission_tests::ct5_cached_native_valid_rechecks_freshness_and_exact_signing_source",
       "sumeragi::executor::clock_tests::sccp_ct5_prepare_signing_resamples_original_after_valid_and_binds_every_coordinate"],
      causes=(ExpectedFailure("native first signing must recheck the actual wall clock after execution",
          "crates/iroha_core/src/sumeragi/executor/prepare_admission_tests.rs"),
          ExpectedFailure("CT5 must resample the original clock at Prepare signing after Valid was delivered",
          "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
          worker_thread="sumeragi-publication-test",
          join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          join_message="publication worker fixture: Any { .. }"))),
    m("HC257", "Full State executor: omit the uncertified CT1 clock-ahead guard",
      ["sumeragi::executor::clock_tests::prepare_withheld_while_block_time_ahead"],
      causes=(ExpectedFailure("uncertified future block must defer before execution",
          "crates/iroha_core/src/sumeragi/executor/clock_tests.rs",
          worker_thread="sumeragi-publication-test",
          join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          join_message="publication worker fixture: Any { .. }"),)),
    m("HC258", "Driver Execute: drop the authenticated certified flag before application execution",
      ["sumeragi::driver::tests::sched::certified_execution_flag_reaches_the_application_without_inference"],
      causes=(ExpectedFailure("certified Execute flag reaches the application unchanged",
          "crates/iroha_core/src/sumeragi/driver/tests/sched.rs"),)),
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
    m("HC10", "history: skip original caller scratch admission before proposal/RS16 reconstruction",
      ["sumeragi::certified_chain::tests::state_certificate::state_certificate_signed_availability_scratch_uses_original_query_allowance",
       "sumeragi::certified_chain::terminal_selection::tests::terminal_amx_prefix_refuses_original_payload_scratch_without_advancing",
       "sumeragi::certified_chain::terminal_selection::tests::terminal_amx_prefix_refuses_original_rs16_scratch_without_advancing"]),
    m("HC11", "history: use a warm decoded body instead of rereading the pinned durable certificate",
      ["sumeragi::certified_chain::tests::durable_certificate_read_rejects_checksum_valid_corruption_after_cache_warm"]),
    m("HC12", "beacon: allocate children before complete original prepaid session admission",
      ["beacon::validation::tests::beacon_verification_reserves_exact_buffers_and_refuses_before_unfunded_work"]),
    m("HC13", "certificate query: construct aggregate pairing scratch without original request admission",
      ["sumeragi::certified_chain::tests::state_certificate::state_certificate_pairing_constructor_refusal_preserves_original_source_for_retry"]),
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
    m("HC32", "original decode refusals: erase reward-credit, native worker and Kaigi retryability",
      ["validation_fee_rewards::tests::original_fee_credit_alias_decode_refusal_preserves_balance_and_retries",
       "validation_fee_rewards::tests::original_fee_credit_owner_decode_refusal_preserves_exact_binding_and_retries",
       "sumeragi::executor::publication_tests::context_proof_decoder_refusal_retains_original_inputs_and_retries",
       "sumeragi::executor::publication_tests::native_context_archive_decoder_refusal_retains_original_execution_and_retries",
       'smartcontracts::isi::kaigi::typed_deferral_tests::stored_record_refusal_is_sticky_and_retries_original_json_without_publication',
       'smartcontracts::isi::kaigi::typed_deferral_tests::indexed_record_refusal_preserves_unregister_guard_and_original_retry',
       'state::deserialize::kaigi_typed_deferral_tests::restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::registration_refusal_preserves_original_relay_retirement_and_retry',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::feedback_refusal_preserves_both_original_relay_rows_and_retry',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::allowlist_refusal_prevents_domain_metadata_publication_and_retries_original_json',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::checked_record_writer_refusal_keeps_original_create_unpublished_and_retries',
       'state::deserialize::kaigi_relay_typed_deferral_tests::restored_registration_refusal_retains_original_snapshot_and_retry',
       'state::deserialize::kaigi_relay_typed_deferral_tests::restored_allowlist_refusal_retains_original_snapshot_and_retry',
       'state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source',
       'state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::lineage_refusal_preserves_original_relay_retirement_and_retry',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::primary_alias_refusal_preserves_original_registration_and_retry',
       'execution_attempt::tests::json_scoped_refusal_preserves_original_context_source_and_retry',
       'smartcontracts::isi::kaigi::relay_typed_deferral_tests::live_manifest_dependency_refusal_preserves_original_route_and_retry']),
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
      ["sumeragi::executor::payload_refusal_tests::original_available_payload_local_decode_refusal_transfers_typed_original_reason_and_retry"]),
    m("HC46", "decode classifier: reject a valid original under a surviving narrower caller depth",
      ["execution_attempt::tests::original_surviving_narrow_decode_depth_refusal_retries_identical_bytes",
       "sumeragi::executor::payload_refusal_tests::original_available_payload_narrow_depth_refusal_transfers_typed_original_reason_and_retry"]),
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
      ['state::validator_committee::tests::refusal::original_incumbent_history_refusal_keeps_authority_and_same_source_retry', 'state::validator_committee::tests::refusal::original_credentials_authority_refusal_keeps_command_and_same_source_retry', 'state::validator_committee::tests::refusal::original_credentials_command_decode_refusal_has_no_publication_and_retries', 'state::validator_committee::tests::refusal::original_beacon_public_state_decode_refusal_defers_before_installation', 'state::validator_committee::tests::refusal::original_tle_public_state_decode_refusal_defers_before_installation', 'state::validator_committee::tests::refusal::original_staking_authority_refusal_keeps_exit_overlay_and_same_signed_retry']),
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
       'validation_fee_rewards::tests::public_fee_reward_claim_rejects_wrong_network_xor_without_writes_and_retries_original_plan']),
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
      ['smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_decode_refusal_retries_original_signed_xor_transfer']),
    m("HC68", "retained multisig proposal: accept an unapproved body or rebound physical row",
      ['smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_body_binding_rolls_back_original_signed_xor_transfer',
       'smartcontracts::isi::multisig::tests::proposal_attempt::live_multisig_proposal_missing_malformed_and_rebound_state_are_not_deferrals',
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
      ["sumeragi::executor::preparation::tests::original_local_custody_invariant_halts_worker_without_fee_result_or_quarantine",
       "sumeragi::certified_chain::funded_authority::tests::native_authority_prepaid_custody_errors_require_recovery"]),
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

    m("SC4", "consensus signing: use the retired generic BLS transcript",
      ["sumeragi::crypto::tests::consensus_signature_matches_dst_sig_fixture",
       "sumeragi::crypto::tests::production_consensus_suite_refuses_generic_and_nonallowlisted_signatures"]),
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
    m("HC133", "native lane finalizer: finish the output seal after original lane preparation refused",
      ["sumeragi::executor::validation_refusal_tests::original_lane_finalizer_refusal_returns_same_graph_before_seal_and_publishes_after_retry"]),
    m("HC134", "native witness handoff: promise retry after the original witness owner is absent or source-invalid",
      ["sumeragi::executor::validation_refusal_tests::validated_witness_guard_failure_requires_recovery_without_reexecuting_original_source"]),

    m("HC135", "borrowed transaction custody: deep-copy the original accepted entrypoint graph",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::native_amx_persisted_paid_borrowed_prepared_proof_clone_retains_original_graph_and_lifetime"]),

    m("HC136", "native lane admission: erase the original signer or sample finite-pool refusal",
      ["sumeragi::lanes::custody::tests::original_signer_pinning_refuses_then_retries_the_same_pool_and_stake_cut",
       "sumeragi::lanes::step::sample_owner_tests::sample_finalizer_refusal_preserves_exact_source_and_retry_funds_only_suffix"]),

    m("HC137", "Queue resident custody: refund original accepted residence before its last shared owner",
      ["queue::tests::resident_owner_tests::removed_pending_owner_retains_original_resident_credit_until_last_reader"]),

    m("HC138", "Queue cold custody: inspect absent resident owner without the original mutation fence",
      ["queue::tests::resident_owner_tests::cold_queue_retirement_holds_original_fence_until_first_admission_can_publish"]),

    m("HC139", "native root selection: rewalk executed ancestry for signed-genesis identity on each successor",
      ["sumeragi::executor::validation_refusal_tests::prepared_certificate_uses_bounded_signed_root_without_rewalking_execution_history",
       "sumeragi::executor::validation_refusal_tests::successor_context_uses_original_parent_and_bounded_signed_root_without_history_rewalk"]),

    m("HC140", "Queue payload lease: permit original inputs after a different committed State generation",
      ["queue::payload_leases::tests::pending_payload_lease_retires_on_actual_certified_state_publication"]),

    m("HC141", "Queue payload lease: adopt clear/readmission during the original selection",
      ["queue::payload_leases::tests::pending_payload_selection_cannot_adopt_clear_and_readmission_during_selection"]),

    m("HC142", "Queue payload lease: lend original selected inputs through a different Queue",
      ["queue::payload_leases::tests::pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue"]),

    m("HC143", "Queue payload lease: treat actual expired inputs as currently lendable",
      ["queue::payload_leases::tests::pending_payload_lease_uses_original_backing_and_retires_on_expiry_withdrawal_or_foreign_queue"]),

    m("HC144", "Queue payload lease: erase original capture admission refusal as absent work",
      ["queue::payload_leases::tests::pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap"]),

    m("HC145", "Queue payload lease: wrap the original admission high-water instead of latching refusal",
      ["queue::payload_leases::tests::pending_payload_lease_preserves_original_capacity_refusal_and_refuses_generation_wrap",
       "queue::payload_leases::tests::pending_payload_admission_exhaustion_refuses_before_input_publication"]),

    m("HC146", "State preverify: omit exact compiled native descriptor/key admission before dedup publication",
      ["state::state_preverify_backend_admission_tests::unsupported_retired_and_claimed_backends_fail_state_admission",
       "state::state_preverify_backend_admission_tests::native_compiled_descriptor_refusal_preserves_key_admission_and_original_retry"]),

    m("HC147", "native AMX record acquisition: erase the original ordinary-write pool refusal",
      ["sumeragi::amx::proof_tests::persisted_amx_original_read_retains_acquired_inode_and_exact_pool_through_decode_refusal"]),

    m("HC148", "native AMX record acquisition: drop the acquired original archive after decode refusal",
      ["sumeragi::amx::proof_tests::persisted_amx_original_read_retains_acquired_inode_and_exact_pool_through_decode_refusal"]),

    m("HC149", "native AMX leg decode: substitute a foreign pool for the actual execution owner",
      ["sumeragi::amx::native::tests::native_leg_decode_refuses_occupied_original_pool_before_any_copy_and_retries_exact_source"]),

    m("HC150", "native AMX Worker retry: retire the completed original leg and decoder controls",
      ["sumeragi::executor::amx_retry_tests::original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry"]),

    m("HC151", "native AMX Worker retry: accept a physically replaced original SignedBlock graph",
      ["sumeragi::executor::amx_retry_tests::completed_amx_worker_bank_refuses_replaced_source_parent_and_foreign_pool"]),

    m("HC152", "native AMX Worker retry: collapse distinct equal Prepare instruction occurrences",
      ["sumeragi::executor::amx_retry_tests::completed_amx_worker_bank_preserves_equal_occurrences_and_metadata_refusal"]),

    m("HC153", "State membership capture: substitute the committed view for the staged original successor",
      ["state::storage_transactions::authority::tests::original_publication_pair_matches_real_advance_replace_and_repeat"]),

    m("HC154", "State membership capture: retain the repeated tip in the original successor rollback",
      ["state::storage_transactions::authority::tests::original_publication_pair_matches_real_advance_replace_and_repeat"]),

    m("HC155", "State membership capture: lend a terminal prepared publication writer",
      ["state::storage_transactions::block::capture::publication_capture_phase_tests::original_membership_cut_refuses_started_published_unwind_and_completed_phases",
       "state::storage_transactions::block::detached_publication::publication_capture_phase_tests::detached_membership_cut_refuses_started_published_unwind_and_released_phases"]),

    m("HC156", "State membership capture: accept a refund scope belonging to another original pool",
      ["state::authority_registry::complete::transaction_membership::tests::original_membership_scope_partial_foreign_and_released_owners_refuse"]),

    m("HC157", "State membership capture: accept a prepared writer from foreign membership storage",
      ["state::authority_registry::complete::transaction_membership::tests::original_membership_scope_partial_foreign_and_released_owners_refuse"]),

    m("HC158", "State membership capture: accept a membership replacement beside an ordinary frozen World",
      ["state::authority_registry::complete::transaction_membership::tests::original_membership_scope_partial_foreign_and_released_owners_refuse"]),
    m("HC159", "native AMX outbound proof: discard the completed original graph after final namespace refusal",
      ["sumeragi::amx::proof_tests::persisted_amx_completed_proof_retains_exact_graph_through_final_namespace_refusal"]),
    m("HC160", "pending consensus penalty: erase the original physical compact-key allocator refusal",
      ["sumeragi::penalties::tests::pending_penalty_peer_key_allocator_refusal_preserves_original_source_and_retries"]),

    m("HC161", "AMX deadline publication: erase the original typed record resource refusal",
      ["sumeragi::amx::tests::amx_deadline_record_refusal_keeps_original_pending_state_and_typed_retry"]),

    m("HC162", "AMX deadline finalizer: turn local resource refusal into protocol rejection",
      ["block::valid::tests::amx_deadline_finalizer_preserves_exact_local_refusal_without_rejection"]),

    m("HC167", "native AMX Worker retry: bind immutable decoded legs to a stale State visibility publication",
      ["sumeragi::executor::amx_retry_tests::original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry"]),

    m("HC168", "retained State package read: reset cumulative traversal work on retry",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_package_read_tests::original_package_read_same_limit_retry_preserves_monotonic_work_and_exact_source"]),
    m("HC169", "retained State package read: discard completed current positions on later undo allocation refusal",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_package_read_tests::original_package_read_retains_completed_current_index_on_later_physical_refusal"]),
    m("HC170", "retained State reader retirement: report success while actual original readers remain",
      ["state::block_field::retained_read::tests::retained_field_readers_and_positions_refuse_thaw_without_a_writer_wait"]),
    m("HC171", "retained State group callback: return a result after the original State source changes",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_musubi_group_tests::original_musubi_group_callback_state_publication_refuses_and_drops_exact_result"]),

    m("HC172", "retained State revision: accept equal staged allocations under the same predecessor",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_musubi_group_tests::original_musubi_group_equal_same_predecessor_revision_substitution_retains_original_pair"]),
    m("HC173", "retained State Cell retirement: report success while actual original revision readers remain",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_musubi_group_tests::original_musubi_group_revision_reader_refusal_retains_completed_tables_and_exact_scope"]),

    m("HC174", "retained State predecessor merge: select current instead of undo at an equal key",
      ["state::publication::retained_rows::predecessor::tests::retained_predecessor_ordered_merge_matches_exact_original_before_rows_in_both_modes"]),
    m("HC175", "retained State predecessor retry: discard completed descriptor backing and frontiers on later work refusal",
      ["state::publication::retained_rows::predecessor::tests::retained_predecessor_later_work_refusal_preserves_descriptor_heads_frontiers_and_pool"]),

    m("HC176", "retained semantic capture: discard original completed canonical rows on later local refusal",
      ["state::authority_registry::leaf::paired::retained_semantic::tests::retained_semantic_original_rows_and_cursor_survive_later_refusal"]),

    m("HC177", "retained State publication: discard successful Musubi validation on later writer refusal",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_state_successful_musubi_validation_survives_late_writer_refusal"]),

    m("HC178", "retained State publication: discard successful live validation after universal scratch refuses",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::retained_state_live_musubi_success_survives_universal_capacity_refusal"]),

    m("HC179", "retained World cut: discard completed original tail after final shared control refusal",
      ["sumeragi::executor::publication_tests::original_worker_world_cut_retains_completed_tail_after_final_control_refusal"]),
    m("HC180", "verified evidence attribution: substitute a fresh pool for the original offender graph",
      ["sumeragi::evidence_history::lane::tests::lane_verified_offender_graph_refuses_occupied_original_pool_and_retries"]),
    m("HC181", "World evidence COW: recopy the original proof and offender graph instead of sharing its immutable body",
      ["sumeragi::evidence::lifecycle_tests::world_evidence_current_undo_and_cow_retain_original_proof_and_offender_allocations"]),
    m("HC182", "detached native AMX source: discard its original acquired archive frame on transfer",
      ["sumeragi::amx::proof_tests::persisted_amx_detached_source_keeps_original_frame_pool_and_retry_after_view_drop"]),
    m("HC183", "native Prepared publication: acknowledge the original commit without its durable outbound intent",
      ["sumeragi::executor::amx_intent_tests::original_paid_prepared_commit_captures_durable_intent_before_acknowledgement"]),
    m("HC184", "off-chain G1 status source: substitute the State execution pool for the original admitted query frame pool",
      ["smartcontracts::isi::tx::native_carrier_reader_tests::genesis_status_prefix_retains_original_admitted_pool_and_cumulative_refusal_work"]),
    m("HC185", "owned native AMX issuer: reopen the original archive descriptor after its first refused poll",
      ["query::native_receipts::amx_read::issuer_tests::owned_issuer_retains_first_refused_archive_descriptor_after_original_view_drop"]),
    m("HC186", "terminal native AMX source: discard acquired original frame after shared body-control refusal",
      ["query::native_receipts::amx_read::certification_tests::terminal_amx_raw_frame_survives_original_shared_shell_refusal"]),
    m("HC187", "original native slot: ignore captured start during same-inode relocation",
      ["kura::native_execution_read_tests::native_frame_original_start_refuses_same_inode_relocation_before_body_admission"]),
    m("HC188", "terminal native AMX selection: forget decoded original target after a later predecessor refusal",
      ["query::native_receipts::amx_read::certification_tests::terminal_amx_target_survives_original_later_gap_capacity_and_proof_retry"]),
    m("HC189", "native queue admission: omit original global driver wake",
      ["sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_global_driver_after_empty"]),
    m("HC190", "native queue admission: omit original live lane runner wake",
      ["sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_live_lane_after_empty"]),
    m("HC191", "native queue startup: omit early exclusive original-owner refusal",
      ["sumeragi::node::tests::queue_wake_tests::native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart"]),
    m("HC192", "native queue startup: omit cold reserved original-pool admission binding",
      ["queue::sumeragi_wake::tests::reserved_original_pool_refuses_foreign_resident_admission_before_allocation"]),
    m("HC193", "native queue startup: omit existing resident original-pool binding",
      ["sumeragi::node::tests::queue_wake_tests::native_queue_reservation_refuses_foreign_funded_pool_without_changing_original_pending"]),
    m("HC194", "native queue retirement: omit terminal admission refusal",
      ["sumeragi::node::tests::queue_wake_tests::native_queue_owner_refuses_duplicate_prepared_start_and_requires_fresh_queue_restart"]),
    m("HC195", "durable lane publication: omit original global merge wake",
      ["sumeragi::node::tests::queue_wake_tests::native_queue_admission_wakes_original_live_lane_after_empty"]),
    m("HC196", "durable lane merge source: omit original cold State pool binding",
      ["sumeragi::lanes::store::publication_tests::lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry"]),
    m("HC197", "durable lane merge source: accept a foreign original Queue identity",
      ["sumeragi::lanes::store::publication_tests::lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry"]),
    m("HC199", "completed certified lane payload: discard original source and output on same-scope build retry",
      ["sumeragi::executor::payload_owner::tests::completed_certified_lane_payload_keeps_original_output_across_same_scope_build_retry"]),
    m("HC201", "block-event execution source: repeat the completed genesis prefix under the original finite allowance",
      ["smartcontracts::isi::tx::native_carrier_reader_tests::event_carrier_reads_recent_certified_source_under_original_finite_work"]),
    m("HC202", "block-event State capture: spin across original publication instead of returning its actual release",
      ["state::event_carrier_tests::event_carrier_returns_from_original_writer_refusal_without_waiting"]),




    m("HC203", "status actor prelude: spin on original State publication instead of returning its local refusal",
      ["telemetry::tests::classified_status_tests::status_prelude_refuses_original_publication_before_service_deadline",
       "telemetry::tests::classified_status_tests::status_final_world_sample_refuses_publication_after_verified_chunk"]),
    m("HC204", "initial native AMX certification: discard the original genesis acquisition on constructor refusal",
      ["query::native_receipts::amx_read::issuer_tests::public_amx_initial_shell_refusal_retains_original_genesis_frame_without_reread"]),
    m("HC205", "authenticated genesis scope: repeat completed metadata decoding after canonical epoch validation",
      ["sumeragi::certified_chain::tests::signed_genesis_initialization_does_not_repeat_completed_scope_decode"]),

    m("HC206", "native carrier preflight: erase original cumulative durable metadata refusal",
      ["smartcontracts::isi::tx::native_carrier_reader_tests::full_prefix_carrier_preserves_original_cumulative_metadata_refusal",
       "smartcontracts::isi::tx::native_carrier_reader_tests::event_carrier_preserves_original_cumulative_metadata_refusal",
       "smartcontracts::isi::tx::native_carrier_reader_tests::bounded_native_extent_preserves_original_cumulative_metadata_refusal",
       "state::block_proofs::native_proof_reader_tests::native_block_proof_preserves_original_cumulative_metadata_refusal",
       "sumeragi::finality::compact_source::tests::compact_source_preserves_original_cumulative_metadata_refusal_before_body_io"]),

    m("HC207", "restricted home admission: omit original authenticated private-root binding",
      ["smartcontracts::isi::domain::isi::private_root_home_tests::restricted_home_requires_original_private_root_not_global_missing_or_foreign_scope"]),
    m("HC208", "restricted private home admission: omit both original captured route coordinates",
      ["smartcontracts::isi::domain::isi::private_root_home_tests::original_private_home_requires_both_exact_captured_routes"]),
    m("HC209", "restricted private home admission: omit canonical original physical geometry",
      ["smartcontracts::isi::domain::isi::private_root_home_tests::original_private_home_requires_canonical_single_root_geometry"]),
    m("HC210", "finite finality interval: discard completed original prefix between consecutive outputs",
      ["sumeragi::finality::proof_reader_tests::finite_finality_interval_under_original_codec_checks_each_real_quorum_once"]),
    m("HC211", "finite finality interval: omit final original raw source join",
      ["sumeragi::finality::interval::tests::finite_interval_rejects_earlier_real_qc_changed_after_verification_before_publication"]),
    m("HC212", "finite finality interval: omit original deadline and cancellation stop",
      ["sumeragi::finality::interval::tests::finite_interval_stop_retires_real_original_cursor_without_next_native_read"]),
    m("HC213", "portable proof destination: omit actual original compact public-key backing charge",
      ["sumeragi::finality::proof_destination::tests::original_proof_destination_charges_each_actual_compact_key_before_clone_and_refunds"]),
    m("HC214", "finite finality State source: omit final one-shot captured-generation membership join",
      ["state::finality_proof_interval::tests::interval_post_read_writer_refusal_retires_response_and_preserves_original_release"]),

    m("HC215", "native AMX original policy: discard completed signed policy on metadata refusal retry",
      ["query::native_receipts::amx_read::issuer_tests::public_amx_signed_policy_retains_completed_npos_stage_on_metadata_refusal"]),
    m("HC216", "native execution tip restore: erase original history deferral into a schema rejection",
      ["state::native_execution_tip::tests::restore_preserves_original_pool_refusal_release_and_same_source_retry",
       "state::native_execution_tip::tests::restore_preserves_cumulative_prefix_decode_refusal_and_same_source_retry"]),
    m("HC217", "restarted native Prepared intent: omit final original namespace join after instruction admission",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_delivers_exact_native_prepared_relay_and_refunds_original_pool",
       "sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_final_namespace_refusal_retains_exact_funded_instruction_until_original_retry"]),
    m("HC218", "restarted native Prepared intent: omit authenticated full-witness completeness before delivery",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::restarted_paid_intent_refuses_authenticated_row_subset_before_any_delivery"]),
    m("HC219", "returned native AMX context: replace original-pool retained graph with the uncharged epoch clone",
      ["sumeragi::amx::native::tests::returned_context::native_amx_returned_global_context_keeps_every_original_graph_charge_until_retirement"]),

    m("HC220", "Core upload account key: erase original decoder refusal into a terminal diagnostic",
      ["state::account_key_refusal_tests::upload_account_key_preserves_original_refusal_fields_scope_and_same_source_retry"]),

    m("HC221", "Fallible World construction: restore expect on the original shared initializer result",
      ['state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source',
       'state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source',
       'state::world_construction_tests::world_constructor_rejects_malformed_kaigi_without_panicking']),

    m("HC222", "partial native AMX Worker decode: retire original controls and member prefix after refusal",
      ["sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_original_controls_and_release_wait",
       "sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_completed_source_prefix_without_reallocation",
       "sumeragi::executor::amx_retry_tests::partial_amx_worker_leg_refusal_retains_original_multisig_member_prefix_without_reallocation"]),

    m("HC223", "original AMX Worker replay: omit resumption of a preceding parked original occurrence",
      ["sumeragi::executor::amx_retry_tests::rejected_amx_worker_occurrence_retains_source_prefix_and_replays_before_later_partial_occurrence"]),

    m("HC224", "native pulse demand: treat a committed Parliament slot row as mandatory control",
      ["sumeragi::epoch_beacon::producer::tests::execution_tests::pending_parliament_slots_create_no_native_control_demand_and_never_block_unrelated_work"]),

    m("HC225", "SCCP outbound: ignore the committed parent degradation run",
      ["smartcontracts::isi::sccp::outbound::tests::degraded_parent_refuses_before_money_nonce_or_leaf_and_recovers"]),
    m("HC226", "SCCP rotation X: certify the successor generation at the outgoing height",
      ["smartcontracts::isi::sccp::hook::tests::native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor"]),
    m("HC227", "SCCP G7: end the old generation at recovery time instead of the authenticated parent time",
      ["smartcontracts::isi::sccp::generations::tests::resync_uses_real_native_parent_time_then_boundary_rotates_again"]),
    m("HC228", "SCCP A1: omit the original parent anchor append including degraded heights",
      ["smartcontracts::isi::sccp::hook::tests::degraded_hook_still_appends_original_parent_anchor_and_recovers_without_rotation"]),
    m("HC229", "SCCP S0: advance liability by the full halt duration instead of the bounded increment",
      ["smartcontracts::isi::sccp::hook::tests::begin_block_clamps_halt_time_using_original_native_parent"]),
    m("HC230", "SCCP G6: resolve frozen registration tenure at execution height instead of generation start",
      ["smartcontracts::isi::sccp::generations::tests::handoff_resolves_original_registration_for_successor_tenure_and_freezes_it"]),
    m("HC231", "SCCP height custody: substitute an unfunded canonical graph for the original retained schedule",
      ["smartcontracts::isi::sccp::height::tests::height_capture_preserves_original_graph_without_admission_at_full_pool"]),

    m("HC232", "terminal native verification custody: discard retained receipt/result slots after late refusal",
      ["sumeragi::certified_chain::terminal_selection::tests::terminal_target_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel",
       "sumeragi::certified_chain::terminal_selection::tests::terminal_gap_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel"]),

    m("HC233", "native cursor initialization: discard original acquisition and verification slots after refusal",
      ["sumeragi::finality::cursor::tests::native_cursor_genesis_result_slot_refusal_retains_original_source_until_release"]),
    m("HC234", "native cursor successor: discard original output, acquisition and verification slots after refusal",
      ["sumeragi::finality::cursor::tests::native_cursor_successor_result_slot_refusal_retains_original_source_until_release"]),
    m("HC235", "native cursor final projection: discard original output and source owners after late refusal",
      ["sumeragi::finality::cursor::tests::native_cursor_output_shell_refusal_retains_projection_and_observes_new_tip"]),
    m("HC236", "native cursor checkpoint preparation: discard partial proof, envelope and checkpoint after refusal",
      ["sumeragi::finality::cursor::tests::native_cursor_pending_last_key_refusal_retains_original_graph_and_release",
       "sumeragi::finality::cursor::tests::native_cursor_pending_envelope_refusal_retains_original_graph_and_release",
       "sumeragi::finality::cursor::tests::native_cursor_pending_checkpoint_refusal_retains_original_graph_and_release"]),
    m("HC237", "SCCP control cause: substitute proposal ID for the exact enacting certificate ID",
      ["smartcontracts::isi::world::isi::tests::parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state"]),
    m("HC238", "SCCP control recorder: omit the actual active destination fast-pause expiry",
      ["smartcontracts::isi::world::isi::tests::parliament_due_sccp_control_binds_exact_certificate_and_complete_pause_state"]),
    m("HC239", "native epoch construction: leak the original ledger after partial payload unwind",
      ["sumeragi::epoch_election::owned::tests::partial_epoch_committee_unwind_refunds_retired_nested_backing"]),
    m("HC250", "SCCP G6 resolves liability outside the canonical global election lane",
      ["smartcontracts::isi::sccp::generations::tests::global_member_binding_ignores_participant_staking_registration"]),
    m("HC251", "SCCP destination clearance traverses already cleared generation history",
      ["smartcontracts::isi::sccp::generations::tests::destination_clearance_visits_only_bounded_pending_index_after_cleared_history"]),


    m('HC240', 'SCCP retained fast Taira pause: omit the active network hold from original consumers',
      ['smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects', 'smartcontracts::isi::sccp::settle::tests::taira_fast_pause_holds_inbound_only_without_losing_proof_money_or_retry', 'smartcontracts::isi::sccp::settle::tests::taira_fast_pause_keeps_void_refund_pending_without_stranding_or_moving_money']),
    m('HC241', 'SCCP retained destination pause: omit the active exact-revision outbound hold',
      ['smartcontracts::isi::sccp::outbound::tests::record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects']),
    m('HC242', 'SCCP committed pause time: substitute the executing timestamp for the original native prefix',
      ['smartcontracts::isi::sccp::hold::tests::committed_pause_time_binds_original_native_prefix_and_ignores_executing_header']),
    m('HC243', 'SCCP eligibility: replace original pre-block facts with the executing writes',
      ['smartcontracts::isi::sccp::eligibility_tests::original_eligibility_preimages_survive_siblings_rollback_and_replacement']),

    m('HC244', 'Network failure-fee settlement: swallow the original local execution deferral as a completed rejection',
      ['state::output_capacity::producer::tests::network::fees::sccp_failure_fee_decoder_refusal_keeps_original_deferral_and_retry', 'state::output_capacity::producer::tests::network::fees::ordinary_failure_fee_decoder_refusal_keeps_original_deferral_and_retry', 'state::output_capacity::producer::tests::network::penalties::refusal::fee_decoder_refusal_after_actual_ballot_penalty_rolls_back_and_retries_once']),
    m('HC245', 'Network ballot-penalty settlement: swallow the original local execution deferral as a completed rejection',
      ['state::output_capacity::producer::tests::network::penalties::refusal::actual_ballot_penalty_decoder_refusal_keeps_original_deferral_and_retry']),
    m('HC246', 'SCCP fast-pause lifecycle: omit Global G4 expiry cleanup after enactments',
      ['smartcontracts::isi::sccp::read::native::control_producer_tests::lapse_tests::native_fast_pause_lapse_uses_exact_time_and_preserves_parliament_confirmation', 'smartcontracts::isi::sccp::read::native::control_producer_tests::lapse_tests::native_fast_pause_lapse_cancellation_keeps_original_record_and_retries_once'],
      causes=(
          ExpectedFailure('the first native block at expiry must remove the original fast-pause record', 'crates/iroha_core/src/smartcontracts/isi/sccp/read/native/control_producer_tests/lapse_tests.rs'),
          ExpectedFailure('the original native execution must stage lapse before publication', 'crates/iroha_core/src/smartcontracts/isi/sccp/read/native/control_producer_tests/lapse_tests.rs'),
      )),

    m('HC247', 'Payload producer retry: erase the original resource refusal at the driver boundary',
      ['sumeragi::executor::publication_tests::original_lane_policy_proposal_refusal_retains_worker_owner_and_exact_queued_retry', 'sumeragi::executor::publication_tests::original_staking_payload_worker_retains_pool_refusal_and_exact_queued_retry'],
      causes=(
          ExpectedFailure('original lane policy refusal must reach the driver as a typed deferral', 'crates/iroha_core/src/sumeragi/executor_publication_tests.rs', worker_thread="sumeragi-publication-test", join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs", join_message="publication worker fixture: Any { .. }"),
          ExpectedFailure('original staking capacity must reach the driver as a typed deferral', 'crates/iroha_core/src/sumeragi/executor_publication_tests.rs', worker_thread="sumeragi-publication-test", join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs", join_message="publication worker fixture: Any { .. }"),
      )),

    m("HC248", "Native parent-service retry: drop the original source and authority preparation on refusal",
      ['sumeragi::executor::parent_service_custody_tests::parent_service_validation_retains_original_receipts_without_waking_its_own_retry', 'sumeragi::executor::parent_service_custody_tests::parent_service_assembly_retains_original_parent_and_queue_before_capacity_retry'],
      causes=(
          ExpectedFailure('parent-service validation keeps original receipts instead of refunding its own waiter', 'crates/iroha_core/src/sumeragi/executor_parent_service_custody_tests.rs', worker_thread="sumeragi-publication-test", join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs", join_message="publication worker fixture: Any { .. }"),
          ExpectedFailure('parent-service assembly retains original receipt charges at first refusal', 'crates/iroha_core/src/sumeragi/executor_parent_service_custody_tests.rs', worker_thread="sumeragi-publication-test", join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs", join_message="publication worker fixture: Any { .. }"),
      )),

    m("HC249", "Native successor authority: relabel impossible prepaid custody as active pool capacity",
      ["sumeragi::certified_chain::funded_authority::tests::native_authority_prepaid_custody_errors_require_recovery"],
      causes=(ExpectedFailure("prepaid authority custody violations must require recovery",
          "crates/iroha_core/src/sumeragi/certified_chain/funded_authority/tests.rs"),)),

    m("HC252", "Native commit retry: keep callback-delayed polling while original execution writers remain retained",
      ["sumeragi::executor::payload_owner::tests::retained_partial_payload_idle_expiry_wakes_original_commit_with_live_execution"],
      causes=(ExpectedFailure("actual original-pool retirement permits the same committed head to retry",
          "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
          worker_thread="sumeragi-publication-test",
          join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          join_message="publication worker fixture: Any { .. }"),)),

    m("HC265", "Direct payment replay: charge another execution fee for an already consumed business identity",
      ["executor::settlement_replay::tests::direct_payment_replay_two_carriers_charge_once_and_recover_after_certified_restart"],
      causes=(ExpectedFailure("same direct payment identity charges one execution fee across distinct carriers",
          "crates/iroha_core/src/executor/settlement_replay_tests.rs"),)),

    m("HC345", "Queue SCCP classification: acquire committed history for ordinary nonexempt work",
      ["queue::tests::ordinary_sccp_admission_needs_no_history_but_exempt_shapes_bind_original_time"],
      causes=(ExpectedFailure("ordinary fee-paying work has no SCCP committed-history dependency",
          "crates/iroha_core/src/queue/current_admission_tests.rs"),)),

    m("HC348", "Lane registry retirement and recovery: notify the original pool under its registry lock",
      ['sumeragi::lanes::registry::tests::original_runtime_opening_explicit_retirement_refunds_after_registry_unlock',
       'sumeragi::lanes::registry::tests::original_runtime_opening_applied_retirement_refunds_after_registry_unlock',
       'sumeragi::lanes::registry::tests::original_runtime_opening_recovery_refunds_after_registry_unlock',
       'sumeragi::lanes::registry::tests::original_runtime_retirement_refunds_after_registry_and_runner_unlock'],
      causes=tuple(ExpectedFailure(cause, "crates/iroha_core/src/sumeragi/lanes/registry/tests.rs")
          for cause in [
              *(["original lane store refund must run after the registry lock releases"] * 3),
              "original lane retirement refund must wait for both registry and runner unlock",
          ])),

    m("HC352", "Geometry claim release: wake original watch callbacks under physical publication owners",
      ['kura::lane_geometry::tests::original_watch_release_tests::original_geometry_captured_rollback_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_applied_rollback_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_catalog_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_pure_drop_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_partial_error_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_unwind_watch_follows_physical_cleanup', 'state::tests::geometry_completion_tests::original_watch_release_tests::original_geometry_watch_follows_direct_state_completion', 'state::tests::geometry_completion_tests::original_watch_release_tests::original_geometry_watch_follows_all_state_sibling_owners', 'state::tests::geometry_completion_tests::original_watch_release_tests::original_geometry_watch_follows_all_state_sibling_unwind', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_capture_error_watch_follows_physical_cleanup', 'kura::lane_geometry::tests::original_watch_release_tests::original_geometry_capture_unwind_watch_follows_physical_cleanup'],
      causes=tuple(ExpectedFailure('original geometry watch must wait for all physical owners', path)
          for path in ['crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/state/geometry_completion_tests.rs', 'crates/iroha_core/src/state/geometry_completion_tests.rs', 'crates/iroha_core/src/state/geometry_completion_tests.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs', 'crates/iroha_core/src/kura/lane_geometry_tests/08_raw_attempt.rs'])),

    m("HC355", "Native frame reads: notify original physical waiters under sibling storage fences",
      ['kura::native_frame_release_tests::original_native_frame_metadata_success_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_metadata_absence_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_metadata_refusal_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_body_success_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_body_refusal_notifies_after_storage_fences', 'kura::native_frame_release_tests::original_native_frame_partial_refusals_retain_exact_storage_errors', 'kura::native_frame_release_tests::original_native_frame_unwind_notifies_after_each_acquired_prefix'],
      causes=tuple(ExpectedFailure('original native frame notice must wait for every storage fence',
          'crates/iroha_core/src/kura/native_frame_release_tests.rs') for _ in range(7))),

    m("HC354", "Geometry recovery: notify original physical waiters under sibling fences",
      ['kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_preflight_success_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_preflight_refusal_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_replay_success_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_replay_refusal_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_startup_success_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_startup_refusal_notifies_after_all_fences', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_recovery_partial_refusals_keep_exact_errors_and_release_sources', 'kura::lane_geometry::tests::original_recovery_release_tests::original_geometry_recovery_unwind_notifies_after_every_acquired_fence'],
      causes=tuple(ExpectedFailure("original geometry recovery notice must wait for every physical fence",
          "crates/iroha_core/src/kura/lane_geometry_tests/09_recovery_releases.rs")
          for _ in range(8))),

    m("HC353", "Native lane authority: notify original State readers under scan and registry locks",
      ['sumeragi::lanes::registry::tests::original_native_history_reader_success_reenters_after_scan_unlock', 'sumeragi::lanes::registry::tests::original_native_history_reader_absence_reenters_after_scan_unlock', 'sumeragi::lanes::registry::tests::original_native_history_reader_error_reenters_after_scan_unlock', 'sumeragi::lanes::registry::tests::original_native_history_reader_reentry_preserves_concurrent_ready_owner', 'sumeragi::lanes::registry::tests::original_native_history_partial_reader_refusal_retains_exact_source_after_unlock', 'sumeragi::lanes::registry::tests::original_authority_recheck_retains_reentrant_opening_and_historical_interest'],
      causes=tuple(ExpectedFailure("original State reader notices must follow scan and registry unlock",
          "crates/iroha_core/src/sumeragi/lanes/registry/tests.rs")
          for _ in range(6))),

    m("HC351", "Native lane history: refund original authenticated scan owners under the scan mutex",
      ['sumeragi::runtime_availability::refund_tests::original_history_scan_progress_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_finish_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_cancellation_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_stale_cut_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_terminal_cleanup_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_cancelled_error_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_invalid_prefix_refunds_after_scan_unlock', 'sumeragi::runtime_availability::refund_tests::original_history_scan_refused_retry_refunds_after_scan_unlock'],
      causes=tuple(ExpectedFailure("original history refund must wait for scan unlock",
          "crates/iroha_core/src/sumeragi/runtime_availability/refund_tests.rs")
          for _ in range(8))),

    m("HC350", "Lane store completion: release original charged owners under state or enclosing batch guards",
      ['sumeragi::lanes::store::refund_tests::original_lane_body_refund_waits_for_state_unlock',
       'sumeragi::lanes::store::refund_tests::original_lane_batch_refund_waits_for_both_original_guards',
       'sumeragi::lanes::store::refund_tests::original_lane_entry_refund_waits_for_state_unlock',
       'sumeragi::lanes::store::refund_tests::original_lane_authenticated_height_refund_waits_for_state_unlock',
       'sumeragi::lanes::store::refund_tests::original_lane_append_refund_waits_for_state_unlock',
       'sumeragi::lanes::store::refund_tests::original_lane_repeated_append_refund_waits_for_state_unlock',
       'sumeragi::lanes::store::refund_tests::original_lane_rejected_append_refund_waits_for_state_unlock',
       'sumeragi::lanes::store::refund_tests::original_lane_opening_refund_follows_complete_recovery_cleanup'],
      causes=tuple(ExpectedFailure(cause, "crates/iroha_core/src/sumeragi/lanes/store/refund_tests.rs")
          for cause in [
              *(["original lane operation refund must wait for both state and batch unlock"] * 7),
              "original lane opening refund must wait for completed recovery cleanup",
          ])),

    m("HC349", "Lane reconciliation: retain the running topology lock through original store retirement",
      ["sumeragi::lanes::registry::tests::original_runtime_retirement_refunds_after_registry_and_runner_unlock"],
      causes=(ExpectedFailure("original lane retirement refund must wait for both registry and runner unlock",
          "crates/iroha_core/src/sumeragi/lanes/registry/tests.rs"),)),

    m("HC347", "Ingress route retirement: refund the original sink under the route writer",
      ["sumeragi::net::tests::ingress_unregister_refunds_outside_original_route_lock"],
      causes=(ExpectedFailure("original ingress refund must run after the route lock releases",
          "crates/iroha_core/src/sumeragi/net.rs"),)),

    m("HC346", "Native Queue sampling: acquire SCCP history before an eligible candidate needs it",
      ["queue::tests::native_sampling_only_requires_original_time_for_live_sccp_candidates"],
      causes=(ExpectedFailure("ordinary native sampling has no SCCP committed-history dependency",
          "crates/iroha_core/src/queue/pressure_resync_tests.rs"),)),

    m("HC344", "Native lane merge: replace an authenticated sealed reveal with its inner external transaction",
      ["sumeragi::lanes::merge::tests::sealed_entrypoints::certified_merge_retains_sealed_carrier_and_enforces_original_salt_before_execution"],
      causes=(ExpectedFailure("certified lane merge retains the complete original entrypoint",
          "crates/iroha_core/src/sumeragi/lanes/merge_tests/sealed_entrypoints.rs"),)),

    m("HC270", "AMX discovery: require an AMX coordinates file for authenticated zero-record history",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::discovery::native_amx_discovery_advances_ordinary_global_height_then_delivers_both_final_tip_decisions"],
      causes=(ExpectedFailure("authenticated zero-record height must advance without an AMX coordinates file",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/discovery.rs"),)),

    m("HC330", "AMX handoff discovery: omit authenticated final epoch boundaries without AMX records",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::handoffs::native_amx_handoff_discovery_delivers_final_boundary_without_record_and_replays_both_roots"],
      causes=(ExpectedFailure("authenticated final epoch boundary must deliver its handoff without an AMX row or successor",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/handoffs.rs"),)),

    m("HC341", "AMX approval scope: omit the exact direct private-root consent classifier",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::authorization::native_amx_exact_owner_grant_revocation_and_separate_relay_preserve_settlement",
       "sumeragi::amx::native::tests::paid_borrowed_custody::approval_proof::native_amx_approval_proof_requires_owner_grant_and_rechecks_exact_private_cut"],
      causes=(
          ExpectedFailure("actual debit owner grants the exact native AMX intent",
              "crates/iroha_core/src/sumeragi/amx/native/tests.rs"),
          ExpectedFailure("actual debit owner grants the exact native AMX intent",
              "crates/iroha_core/src/sumeragi/amx/native/tests.rs"),)),

    m("HC342", "AMX discovery: acquire another destination's target graph before route selection",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::route_discovery::native_amx_route_discovery_retains_refused_handoff_while_another_destination_advances"],
      causes=(ExpectedFailure("requested route must be selected before unrelated target graph acquisition",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/route_discovery.rs"),)),

    m("HC338", "AMX expiry recovery: accept a Decision source from the wrong root",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::expiry_recovery::native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive"],
      causes=(ExpectedFailure("a child root cannot authenticate the Global expiry decision",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/expiry_recovery.rs"),)),

    m("HC339", "AMX expiry recovery: promote a cached positive height without a fresh authenticated read",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::expiry_recovery::native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive"],
      causes=(ExpectedFailure("cached positive height must reauthenticate original proof before suppressing a carrier",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/expiry_recovery.rs"),)),

    m("HC333", "Routing lane first Prepare: accept a substituted execution source",
      ["sumeragi::lanes::executor::native_decode_tests::native_lane_first_prepare_admission_binds_original_source_and_retains_its_charge"],
      causes=(ExpectedFailure("certification never exempts source substitution",
          "crates/iroha_core/src/sumeragi/lanes/executor/native_decode_tests.rs"),)),

    m("HC328", "Fresh proposer: omit captured time while retaining original signed inputs",
      ["sumeragi::executor::payload_owner::tests::fresh_view_refreshes_authenticated_block_time_without_replacing_signed_input"],
      causes=(ExpectedFailure("fresh view must refresh certified time without another signed transaction",
          "crates/iroha_core/src/sumeragi/executor/payload_owner.rs"),)),

    m("HC329", "Native execution: reject authenticated proposer time above the required floor",
      ["sumeragi::executor::clock_tests::authenticated_proposer_time_above_floor_executes_and_replays_without_restamping"],
      causes=(ExpectedFailure("authenticated proposer time above the input floor must execute",
          "crates/iroha_core/src/sumeragi/executor/clock_tests.rs"),)),

    m("HC327", "Routing lane: lend retained payload after its original Queue admission retires",
      ["sumeragi::lanes::executor::queue_lease_tests::lane_original_queue_lease_retires_expiry_and_withdrawal_during_clock_wait",
       "sumeragi::lanes::executor::queue_lease_tests::lane_original_queue_lease_rechecks_withdrawal_after_actual_encoding",
       "sumeragi::lanes::executor::queue_lease_tests::lane_original_queue_lease_preserves_same_output_across_clock_rewind_and_retires_readmission"],
      causes=(ExpectedFailure("lane clock retry must retire expired or withdrawn original Queue admission",
          "crates/iroha_core/src/sumeragi/lanes/executor/queue_lease_tests.rs"),
          ExpectedFailure("lane retained output must not outlive its original Queue admission",
          "crates/iroha_core/src/sumeragi/lanes/executor/queue_lease_tests.rs"),
          ExpectedFailure("same-hash readmission must not revive the retained lane Queue lease",
          "crates/iroha_core/src/sumeragi/lanes/executor/queue_lease_tests.rs"))),

    m("HC283", "SCCP native registration: omit the retained forgery generation floor",
      ["smartcontracts::isi::sccp::governance::registration::tests::native_forgery_publication_requires_a_strictly_newer_pin"],
      causes=(ExpectedFailure("SCCP registration must exclude the retained forged generation",
          "crates/iroha_core/src/smartcontracts/isi/sccp/governance/registration/tests.rs"),)),

    m("HC284", "SCCP route proposal: bypass the Parliament ballot gate with proposer permission",
      ["smartcontracts::isi::world::isi::tests::sccp_route_governance_proposal_requires_permission_or_bond"],
      causes=(ExpectedFailure("SCCP proposer permission must not bypass the Parliament ballot gate",
          "crates/iroha_core/src/smartcontracts/isi/world_sccp_governance_tests.rs"),)),

    m("HC285", "SCCP deployment attestation: lower a retained forgery floor",
      ["smartcontracts::isi::sccp::governance::holds::tests::native_offence_release_and_later_attestation_never_lower_the_floor"],
      causes=(ExpectedFailure("SCCP attestation must never lower the retained forgery floor",
          "crates/iroha_core/src/smartcontracts/isi/sccp/governance/holds/tests.rs"),)),

    m("HC286", "SCCP quarantine: replace the original permanent cause",
      ["smartcontracts::isi::sccp::governance::holds::tests::quarantine_retains_its_original_cause_across_replays_and_progress"],
      causes=(ExpectedFailure("SCCP quarantine must preserve its original permanent cause",
          "crates/iroha_core/src/smartcontracts/isi/sccp/governance/holds/tests.rs"),)),

    m("HC287", "SCCP forged mint: omit authenticated finalization payload binding",
      ["smartcontracts::isi::sccp::reconciliation::tests::forged_mint_requires_exact_registered_event_and_payload_binding"],
      causes=(ExpectedFailure("a different payload id must not count forged supply",
          "crates/iroha_core/src/smartcontracts/isi/sccp/reconciliation/tests.rs"),)),

    m("HC288", "SCCP retirement: retire a quarantined revision before reconciliation",
      ["smartcontracts::isi::sccp::governance::holds::tests::quarantined_retirement_requires_the_single_completed_reconciliation_window"],
      causes=(ExpectedFailure("SCCP quarantined retirement must await reconciliation",
          "crates/iroha_core/src/smartcontracts/isi/sccp/governance/holds/tests.rs"),)),

    m("HC295", "SCCP panel seats: replace originals before the acceptance deadline",
      ["smartcontracts::isi::sccp::fast_pause::tests::sccp_pause_seats_replace_only_unaccepted_in_primary_then_backup_order_at_deadline"],
      causes=(ExpectedFailure("reserve replacement must wait until the exact acceptance deadline",
          "crates/iroha_core/src/smartcontracts/isi/sccp/fast_pause/tests.rs"),)),

    m("HC296", "SCCP pause certification: count revoked endorsers toward quorum",
      ["smartcontracts::isi::sccp::fast_pause::certification::tests::sccp_pause_certification_rechecks_revoked_members_and_exact_close_after_halt"],
      causes=(ExpectedFailure("revoked endorsers must not count toward certification quorum",
          "crates/iroha_core/src/smartcontracts/isi/sccp/fast_pause/certification/tests.rs"),)),

    m("HC297", "SCCP pause certification: retain endorsements past their exact close",
      ["smartcontracts::isi::sccp::fast_pause::certification::tests::sccp_pause_certification_rechecks_revoked_members_and_exact_close_after_halt"],
      causes=(ExpectedFailure("endorsement windows must expire at the exact close even after a halt",
          "crates/iroha_core/src/smartcontracts/isi/sccp/fast_pause/certification/tests.rs"),)),

    m("HC298", "SCCP pause lift: ignore the approving ballot's original casting-open position",
      ["smartcontracts::isi::sccp::fast_pause::tests::sccp_pause_lift_compares_original_height_position_and_removes_only_the_matching_part"],
      causes=(ExpectedFailure("a resume cannot lift a pause enacted at or after its original casting-open position",
          "crates/iroha_core/src/smartcontracts/isi/sccp/fast_pause/tests.rs"),)),

    m("HC299", "SCCP fast-pause suspension: clear an already active hold",
      ["smartcontracts::isi::sccp::fast_pause::tests::sccp_pause_suspension_never_clears_active_parts_and_zero_removes_only_suspension"],
      causes=(ExpectedFailure("suspension must preserve every active fast-pause part",
          "crates/iroha_core/src/smartcontracts/isi/sccp/fast_pause/tests.rs"),)),

    m("HC306", "SCCP bundled admission: skip each signed advance state expectation",
      ["smartcontracts::isi::sccp::self_claim::bundled_tests::signed_bundle_uses_original_overlay_and_checks_each_advance_cas"],
      causes=(ExpectedFailure("SCCP bundled admission must enforce each signed advance state expectation",
          "crates/iroha_core/src/smartcontracts/isi/sccp/self_claim/bundled_tests.rs"),)),

    m("HC307", "SCCP local allocation refusal: replace the original deferral with rejection",
      ["smartcontracts::isi::sccp::self_claim::bundled_tests::exhausted_bundle_admission_preserves_original_deferral_and_retry"],
      causes=(ExpectedFailure("SCCP local allocation refusal must remain an original deferred attempt",
          "crates/iroha_core/src/smartcontracts/isi/sccp/self_claim/bundled_tests.rs"),)),

    m("HC308", "SC1 SCCP result: omit the original fixed header from ordinary voting",
      ["sumeragi::executor::publication_tests::published_execution_result_binds_the_original_header_and_body_digest"],
      causes=(ExpectedFailure("SC1 ordinary voting must bind the original finality header and body digest",
          "crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          worker_thread="sumeragi-publication-test",
          join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          join_message="publication worker fixture: Any { .. }"),)),

    m("HC309", "SC3 SCCP key change: omit native boundary rotation",
      ["smartcontracts::isi::sccp::generations::tests::key_change_before_heartbeat_requires_rotation_at_the_original_boundary"],
      causes=(ExpectedFailure("a changed native boundary committee must rotate before the heartbeat deadline",
          "crates/iroha_core/src/smartcontracts/isi/sccp/generations/tests.rs"),)),

    m("HC310", "SC10 SCCP unavailable inputs: invalidate ordinary execution instead of degrading",
      ["smartcontracts::isi::sccp::hook::tests::degraded_block_without_leaves_keeps_history_and_records_failure"],
      causes=(ExpectedFailure("missing SCCP inputs must degrade the extension without invalidating ordinary execution",
          "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs"),)),

    m("HC311", "SC11 SCCP unchanged committee: disable due heartbeat rotation",
      ["smartcontracts::isi::sccp::hook::tests::native_heartbeat_certificate_keeps_outgoing_generation_then_uses_successor"],
      causes=(ExpectedFailure("a due heartbeat must rotate the unchanged native committee",
          "crates/iroha_core/src/smartcontracts/isi/sccp/hook.rs"),)),

    m("HC312", "SC7 SCCP heartbeat: ignore the original due timestamp",
      ["smartcontracts::isi::sccp::keepalive::tests::heartbeat_due_rejects_early_progress_and_includes_the_exact_deadline"],
      causes=(ExpectedFailure("SC7 heartbeat must wait for the original inclusive deadline",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),

    m("HC313", "SC8 SCCP due work: omit the original fast-pause conclusion leg",
      ["smartcontracts::isi::sccp::keepalive::tests::governance_due_keeps_the_original_fast_pause_leg_when_heartbeat_is_disabled"],
      causes=(ExpectedFailure("SC8 due work must retain the original fast-pause conclusion leg",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),

    m("HC314", "SC16 SCCP Keepalive: admit a carrier without established due work",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_admission_requires_established_due_work_before_assigning_exemption"],
      causes=(ExpectedFailure("SC16 Keepalive admission must reject a carrier without established due work",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),

    m("HC315", "SC13 SCCP forgery: ignore the signed result-body digest",
      ["smartcontracts::isi::sccp::forgery::tests::signed_body_digest_only_forgery_is_e4_against_original_anchor"],
      causes=(ExpectedFailure("SC13 signed D_body mismatch must remain punishable E4 evidence",
          "crates/iroha_core/src/smartcontracts/isi/sccp/forgery/tests.rs"),)),

    m("HC316", "SC14 SCCP forgery: accept evidence outside original generation liability",
      ["smartcontracts::isi::sccp::forgery::tests::generation_lookup_and_inclusive_liability_use_captured_values_only"],
      causes=(ExpectedFailure("SC14 expired captured generation must fail E0 before signature verification",
          "crates/iroha_core/src/smartcontracts/isi/sccp/forgery/tests.rs"),)),

    m("HC317", "SC18 SCCP forgery: replace original core anchor with outer Iroha block hash",
      ["smartcontracts::isi::sccp::forgery::tests::genuine_native_certificate_uses_core_anchor_instead_of_outer_block_hash"],
      causes=(ExpectedFailure("SC18 genuine native certificate cannot become E3 through outer block hash substitution",
          "crates/iroha_core/src/smartcontracts/isi/sccp/forgery/tests.rs"),)),

    m("HC318", "SC21 SCCP penalty: use attacker-selected certificate height for liability",
      ["sumeragi::penalties::tests::sccp_penalty_uses_captured_tuple_start_and_record_delay_without_generation_or_peer_map"],
      causes=(ExpectedFailure("SC21 forged height cannot replace original generation liability start",
          "crates/iroha_core/src/sumeragi/penalties/sccp_tests.rs"),)),

    m("HC319", "SC21 SCCP penalty: replace captured registration with current peer-key mapping",
      ["sumeragi::penalties::tests::sccp_penalty_ignores_late_peer_mapping_and_keeps_original_g6_custody"],
      causes=(ExpectedFailure("SC21 only the original captured registration remains slashable",
          "crates/iroha_core/src/sumeragi/penalties/sccp_tests.rs"),)),

    m("HC320", "SC15 SCCP unbond: omit the original generation liability barrier",
      ["smartcontracts::isi::staking::tests::sccp_liable_unbond_keeps_exact_pending_request_and_both_balances"],
      causes=(ExpectedFailure("SC15 must retain an unbond while its original SCCP generation is liable",
          "crates/iroha_core/src/smartcontracts/isi/staking_sccp_liability_tests.rs"),)),

    m("HC321", "SC15 SCCP unbond: omit the exact pending offence barrier",
      ["smartcontracts::isi::sccp::liability::tests::pending_exact_offence_survives_liability_expiry_and_only_applied_releases_it"],
      causes=(ExpectedFailure("SC15 must retain an unbond while its exact recorded SCCP penalty is pending",
          "crates/iroha_core/src/smartcontracts/isi/sccp/liability/tests.rs"),)),

    m("HC322", "SC20 SCCP liability: omit original destination-progress clearance",
      ["smartcontracts::isi::sccp::liability::tests::current_generation_and_parent_clearance_cannot_be_shortened_by_block_writes"],
      causes=(ExpectedFailure("SC20 must retain liability until original destination clearance or the progress cap",
          "crates/iroha_core/src/smartcontracts/isi/sccp/liability/tests.rs"),)),

    m("HC323", "SC25 SCCP holds: ignore the retained maximum forgery generation",
      ["smartcontracts::isi::sccp::hold::forgery_tests::forgery_floor_is_inclusive_and_u64_max_is_not_a_release_sentinel"],
      causes=(ExpectedFailure("SC25 must hold every revision whose original forgery floor is not above the maximum offence",
          "crates/iroha_core/src/smartcontracts/isi/sccp/hold/forgery_tests.rs"),)),

    m("HC324", "SC23 SCCP generation: disable missed-boundary resynchronization",
      ["smartcontracts::isi::sccp::generations::tests::resync_uses_real_native_parent_time_then_boundary_rotates_again"],
      causes=(ExpectedFailure("SC23 a missed committee change must create the original resync generation",
          "crates/iroha_core/src/smartcontracts/isi/sccp/generations/tests.rs"),)),

    m("HC325", "SC2 SCCP rotation: substitute the successor for the outgoing committee root",
      ["smartcontracts::isi::sccp::generations::tests::key_change_before_heartbeat_requires_rotation_at_the_original_boundary"],
      causes=(ExpectedFailure("SC2 boundary header must retain the outgoing committee root",
          "crates/iroha_core/src/smartcontracts/isi/sccp/generations/tests.rs"),)),

    m("HC326", "SCCP TON registration: accept caller-substituted contract code at its matching address",
      ["smartcontracts::isi::sccp::governance::registration::tests::ton_deployment_refuses_substituted_code_at_its_matching_state_init_address"],
      causes=(ExpectedFailure("SCCP TON deployment must refuse substituted code even at its matching StateInit address",
          "crates/iroha_core/src/smartcontracts/isi/sccp/governance/registration/tests.rs"),)),

    m("HC305", "SCCP genesis: permit a committee signer without an original global staking binding",
      ["smartcontracts::isi::sccp::init::tests::sccp_genesis_requires_every_original_signer_to_have_one_staking_binding"],
      causes=(ExpectedFailure("SCCP genesis must refuse any signer without its original global staking binding",
          "crates/iroha_core/src/smartcontracts/isi/sccp/init.rs"),)),

    m("HC303", "SCCP panel draw: require the committee boundary instead of the native pulse carrying height",
      ["sumeragi::epoch_beacon::producer::tests::execution_tests::sccp_panel_draw_reads_the_original_pulse_at_its_actual_carrying_height"],
      causes=(ExpectedFailure("panel draws must receive the original verified pulse at its native carrying height",
          "crates/iroha_core/src/sumeragi/epoch_beacon/producer/execution_tests.rs"),)),

    m("HC304", "SCCP clock policy: accept a budget that can recertify but never enact a pause",
      ["sumeragi::schedule::execution::tests::sccp_executed_genesis_rejects_work_budgets_that_starve_pause_enactment"],
      causes=(ExpectedFailure("genesis must reject budgets that cannot certify six rounds and enact one pause",
          "crates/iroha_core/src/sumeragi/schedule/execution_tests.rs"),)),

    m("HC302", "SCCP keepalive: replace the original parent pause-due set with the overlay",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_pause_conclusion_stays_due_through_expiry_and_reads_original_parent"],
      causes=(ExpectedFailure("new fast-pause work cannot replace the original parent due-work observation",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),

    m("HC301", "SCCP fast-pause enactment: ignore previously occupied block leaves",
      ["smartcontracts::isi::sccp::fast_pause::certification::tests::sccp_pause_controls_preflight_capacity_nonce_and_every_live_part_before_effects"],
      causes=(ExpectedFailure("every fast-pause control must fit the remaining original block leaf capacity",
          "crates/iroha_core/src/smartcontracts/isi/sccp/fast_pause/certification/tests.rs"),)),

    m("HC300", "SCCP panel execution: rearm a consumed direct signed instruction",
      ["state::sccp_forgery_entrypoint::tests::pause_direct_source_binds_each_signed_slot_and_cannot_be_rearmed_or_substituted"],
      causes=(ExpectedFailure("a consumed signed panel instruction cannot be rearmed",
          "crates/iroha_core/src/state/sccp_forgery_entrypoint/tests.rs"),)),

    m("HC292", "SCCP generation pruning: retire a generation with a pending original penalty",
      ["smartcontracts::isi::sccp::pruning::tests::pruning_keeps_pending_exact_generation_until_penalty_is_applied"],
      causes=(ExpectedFailure("pruning must retain a generation with an exact Pending SCCP penalty",
          "crates/iroha_core/src/smartcontracts/isi/sccp/pruning/tests.rs"),)),

    m("HC293", "SCCP anchor pruning: delete roots at or above the retained generation boundary",
      ["smartcontracts::isi::sccp::pruning::tests::pruning_anchor_boundary_uses_minimum_retained_start_and_is_strict"],
      causes=(ExpectedFailure("pruning must retain a chunk ending at the minimum retained generation start",
          "crates/iroha_core/src/smartcontracts/isi/sccp/pruning/tests.rs"),)),

    m("HC289", "SCCP reconciliation: let claims consume pending refund backing",
      ["smartcontracts::isi::sccp::settle::tests::reconciliation_reserves_refunds_and_later_claims_exhaust_only_priced_backing"],
      causes=(ExpectedFailure("reconciled claim must preserve pending refund backing",
          "crates/iroha_core/src/smartcontracts/isi/sccp/settle/tests.rs"),)),

    m("HC290", "SCCP reconciliation: advance face accounting after a refused credit",
      ["smartcontracts::isi::sccp::settle::tests::reconciliation_pending_credit_retry_recomputes_rounding_without_spending_face"],
      causes=(ExpectedFailure("refused reconciled credit must not advance settled face",
          "crates/iroha_core/src/smartcontracts/isi/sccp/settle/tests.rs"),)),

    m("HC276", "SCCP EVM registration: omit the exact locked CREATE2 destination-address check",
      ["smartcontracts::isi::sccp::governance::registration::tests::evm_address_binds_original_identity_network_pin_revision_and_cap"],
      causes=(ExpectedFailure("SCCP EVM deployment must bind exact locked CREATE2 address",
          "crates/iroha_core/src/smartcontracts/isi/sccp/governance/registration/tests.rs"),)),

    m("HC277", "Shared Keepalive: accept a second carrier in one block",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_k1_counts_carriers_independently_of_outcomes"],
      causes=(ExpectedFailure("K1 must reject every second Keepalive",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),
    m("HC278", "Shared Keepalive: continue heartbeat after two degraded parent heights",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_k2_uses_parent_heartbeat_and_degraded_run"],
      causes=(ExpectedFailure("K2 must stop after two degraded parent heights",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),
    m("HC279", "Shared Keepalive: ignore signed authority and empty fee-intent shape",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_k3_k5_require_standalone_ed25519_due_time_and_empty_fee"],
      causes=(ExpectedFailure("K3 must reject fee-bearing Keepalive",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),
    m("HC280", "Shared Keepalive: retain carriers older than half the agreed lag",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_k4_refreshes_after_half_lag_and_preserves_boundary"],
      causes=(ExpectedFailure("K4 must replace a carrier older than half the maximum lag",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),
    m("HC281", "Shared clock: omit uncertified stale due-work refusal",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_ct5_stale_due_work_is_a_local_refusal"],
      causes=(ExpectedFailure("CT5 must refuse stale uncertified due work",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),
    m("HC282", "Shared clock: apply local wall-clock refusal to certified execution",
      ["smartcontracts::isi::sccp::keepalive::tests::keepalive_ct5_certified_execution_ignores_the_local_wall_clock"],
      causes=(ExpectedFailure("CT5 must exempt genuine certified execution",
          "crates/iroha_core/src/smartcontracts/isi/sccp/keepalive/tests.rs"),)),

    m("HC275", "Native append: discard the original physical State authority read release",
      ["state::tests::publication_effect_manifest_tests::original_append_driver_retains_manifest_release_without_timer_or_foreign_wake"],
      causes=(ExpectedFailure("the original append scheduler must retain its physical State release",
          "crates/iroha_core/src/state/publication_effect_manifest_tests.rs"),)),

    m("HC274", "Kura publication cleanup: notify before enclosing original State owners release",
      ["state::tests::publication_effect_kura_tests::original_kura_partial_refusal_callbacks_follow_all_state_siblings",
       "state::tests::publication_effect_kura_tests::original_kura_success_callbacks_follow_all_state_siblings",
       "state::tests::publication_effect_kura_tests::original_kura_unwind_callbacks_follow_all_state_siblings"],
      causes=tuple(ExpectedFailure("original Kura notifications must wait for complete State cleanup",
          "crates/iroha_core/src/state/publication_effect_kura_tests.rs") for _ in range(3))),

    m("HC273", "Lifecycle preflight: discard the original manifest writer refusal",
      ["state::tests::publication_effect_manifest_tests::signed_lifecycle_manifest_writer_refusal_retains_preflight_and_original_retry"],
      causes=(ExpectedFailure("the signed manifest preflight must retain its original local refusal",
          "crates/iroha_core/src/state/publication_effect_manifest_tests.rs"),)),

    m("HC272", "State publication: make original effect-index contention irreversible before visibility",
      ["state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::effect_retry_tests::actual_state_effect_reader_refusal_retains_original_and_retries_after_release",
       "state::acquisition_fixture_tests::direct_commit_musubi_scratch_tests::effect_retry_tests::actual_state_effect_writer_refusal_retains_original_and_retries_after_release",
       "state::tests::publication_effect_lifecycle_tests::signed_lifecycle_index_refusal_precedes_geometry_and_replays_final_cursor_journal"],
      causes=(ExpectedFailure("the original index blocker must defer before visibility",
          "crates/iroha_core/src/state/publication_effect_retry_tests.rs"),
          ExpectedFailure("the original index blocker must defer before visibility",
          "crates/iroha_core/src/state/publication_effect_retry_tests.rs"),
          ExpectedFailure("the signed lifecycle index blocker must defer before geometry",
          "crates/iroha_core/src/state/publication_effect_lifecycle_tests.rs"))),

    m("HC271", "Begin delivery: skip original source revalidation after funded Prepare admission",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::begins::native_amx_begin_delivery_final_namespace_refusal_preserves_original_instruction"],
      causes=(ExpectedFailure("source namespace must be rechecked after instruction admission",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody/begins.rs"),)),

    m("HC267", "Decision delivery: skip original source revalidation after funded instruction admission",
      ["sumeragi::amx::native::tests::paid_borrowed_custody::native_amx_decision_delivery_final_namespace_refusal_preserves_original_instruction"],
      causes=(ExpectedFailure("Decision delivery must recheck original namespace after instruction admission",
          "crates/iroha_core/src/sumeragi/amx/native/tests/paid_borrowed_custody.rs"),)),

    m("HC259", "Proposer clock: select future signed inputs on Global and routing lanes",
      ["sumeragi::payload::resource_contract_tests::proposer_clock_selection_retains_future_signed_inputs_until_the_exact_time",
       "sumeragi::payload::resource_contract_tests::lane_proposer_clock_selection_preserves_future_inputs_and_resumes_after_advance"],
      causes=(ExpectedFailure("global proposer must leave future signed input queued",
          "crates/iroha_core/src/sumeragi/payload/resource_contract_tests.rs"),
          ExpectedFailure("lane proposer must leave future signed input queued",
          "crates/iroha_core/src/sumeragi/payload/resource_contract_tests.rs"))),

    m("HC268", "Routing lane executor: omit the uncertified effective-clock guard",
      ["sumeragi::lanes::executor::native_decode_tests::signed_lane_clock_retains_original_admission_until_exact_boundary_and_certified_replay"],
      causes=(ExpectedFailure("uncertified lane must wait at its authenticated effective clock boundary",
          "crates/iroha_core/src/sumeragi/lanes/executor/native_decode_tests.rs"),)),

    m("HC269", "Routing lane builder: publish before its authenticated effective timestamp",
      ["sumeragi::lanes::executor::tests::lane_builder_effective_clock_retains_original_payload_across_clock_rewind"],
      causes=(ExpectedFailure("lane builder must retain its original effective timestamp before publication",
          "crates/iroha_core/src/sumeragi/lanes/executor.rs"),)),

    m("HC264", "Routing lane builder: collapse future-only clock wait into an empty payload",
      ["sumeragi::lanes::executor::tests::future_only_lane_work_retries_without_an_empty_answer_or_new_traffic"],
      causes=(ExpectedFailure("future-only lane work must retry instead of reporting an empty payload",
          "crates/iroha_core/src/sumeragi/lanes/executor.rs"),)),

    m("HC260", "Proposer clock: publish original canonical payload before its clock boundary",
      ["sumeragi::executor::payload_owner::tests::proposer_clock_retains_final_input_and_canonical_output_until_due",
       "sumeragi::executor::payload_owner::tests::proposer_clock_retains_certified_lane_floor_and_completed_original"],
      causes=tuple(ExpectedFailure(message,
          "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
          worker_thread=worker,
          join_source=join_source,
          join_message=join_message) for message, worker, join_source, join_message in (
              ("canonical payload clock must wait after its signed input becomes due",
               "sumeragi-publication-test",
               "crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
               "publication worker fixture: Any { .. }"),
              ("canonical lane merge floor must wait without empty or unrelated work",
               "sumeragi-original-lane-merge-test",
               "crates/iroha_core/src/sumeragi/lanes/merge_tests.rs",
               "original lane fixture: Any { .. }")))),

    m("HC253", "Native parent journal retry: classify unavailable original path bindings as corrupt history",
      ["sumeragi::executor::payload_owner::tests::retained_partial_payload_refuses_missing_original_parent_and_resumes_same_paid_wire",
       "sumeragi::executor::payload_owner::tests::retained_partial_payload_refuses_substituted_original_parent_and_resumes_same_paid_wire"],
      causes=tuple(ExpectedFailure("original parent journal unavailability remains retryable",
          "crates/iroha_core/src/sumeragi/executor/payload_owner.rs",
          worker_thread="sumeragi-publication-test",
          join_source="crates/iroha_core/src/sumeragi/executor_publication_tests.rs",
          join_message="publication worker fixture: Any { .. }") for _ in range(2))),


    m("HC254", "Lane geometry completion: retire original physical owners without final authentication",
      ["state::tests::geometry_completion_tests::completed_publication_refuses_substituted_journal_namespace_and_retries_original_owner",
       "state::tests::geometry_completion_tests::prepublication_refuses_substituted_tiered_directory_and_retries_original_owner",
       "state::tests::geometry_completion_tests::completed_publication_refuses_substituted_tiered_directory_and_retries_original_owner"],
      causes=tuple(ExpectedFailure(cause, "crates/iroha_core/src/state/geometry_completion_tests.rs")
          for cause in ("completed publication refuses a substituted original journal namespace",
                        "publication refuses a substituted original tiered directory",
                        "publication refuses a substituted original tiered directory"))),

    m("HC255", "Lane geometry retry: reopen completed tiered progress before an identity refusal",
      ["state::tests::geometry_completion_tests::completed_retry_preserves_original_applied_progress_on_tiered_identity_refusal"],
      causes=(ExpectedFailure("completed tiered refusal preserves original forward progress",
          "crates/iroha_core/src/state/geometry_completion_tests.rs"),)),

    m("HC256", "Lane geometry completion: accept a different original configured baseline",
      ["state::tests::geometry_completion_tests::completed_publication_refuses_changed_baseline_and_retries_original_owner"],
      causes=(ExpectedFailure("completed publication refuses a changed original configured baseline",
          "crates/iroha_core/src/state/geometry_completion_tests.rs"),)),

]


# Model resource-custody rules execute only in the owning DataModel unit-test crate.
MODEL_MUTATIONS = [
    m("DM1", "AMX instruction custody: deep-copy the original funded instruction graph",
      ["isi::amx_owner::tests::original_amx_instruction_clone_retains_exact_graph_and_pool_through_last_reader"]),
    m("DM2", "AMX proof custody: omit the actual Begin participant allocation from admission",
      ["isi::amx_owner::tests::original_amx_instruction_admits_complete_actual_layouts_before_copy_and_retries_same_pool"]),
    m("DM3", "AMX instruction custody: retain the final additional ledger instead of refunding its exact credit",
      ["isi::amx_owner::tests::original_amx_instruction_last_owner_destroys_fields_and_refunds_exact_ledger"]),
    m("DM4", "AMX Begin source scan: skip the canonical participant field payload context",
      ["sumeragi_amx::allocation::tests::original_begin_record_scan_preserves_canonical_depth_refusal_and_exact_retry"]),
    m("DM5", "AMX transaction identity: reconstruct the canonical frame as heap scratch",
      ["amx_prepare_streaming_allocations::observer_counts_all_three_allocation_routes_and_resets_after_unwind",
       "amx_prepare_streaming_allocations::transaction_id_streaming_matches_canonical_frames_without_heap_allocations"]),
    m("DM6", "AMX Begin matching: reconstruct a heap-owning Begin instead of borrowing its original fields",
      ["amx_prepare_streaming_allocations::observer_counts_all_three_allocation_routes_and_resets_after_unwind",
       "amx_prepare_streaming_allocations::begin_matches_borrows_original_graph_without_heap_allocations"]),
    m("DM7", "Native AMX monetary effects: materialize the canonical leg frame as unfunded heap scratch",
      ["amx_prepare_streaming_allocations::observer_counts_all_three_allocation_routes_and_resets_after_unwind",
       "amx_prepare_streaming_allocations::native_transfer_effects_stream_exact_monetary_fields_without_heap_allocations"]),
    m("DM8", "AMX deadline custody: consume pending source before every decision record succeeds",
      ["sumeragi_amx::tests::sumeragi_amx_expiry_refusal_and_unwind_preserve_original_pending_graph"]),
    m("DM9", "AMX record encoding: erase the original physical allocation refusal",
      ["sumeragi_amx::tests::sumeragi_amx_encoding_keeps_exact_physical_allocator_refusal"]),
    m("DM10", "pinned genesis: repeat completed canonical authentication over the original body",
      ["sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_uses_one_original_decode_and_retains_metadata"]),
    m("DM11", "pinned genesis: erase original binary decoder refusal provenance",
      ["sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_preserves_original_binary_refusal"]),
    m("DM12", "pinned genesis: erase original signed JSON decoder refusal provenance",
      ["sumeragi_finality::genesis_dataspace::tests::pinned_signed_genesis_preserves_original_json_refusal_and_retry"]),
    m("DM13", "consensus fingerprint: reopen completed authenticated metadata",
      ["sumeragi_finality::tests::consensus_fingerprint_reuses_original_authenticated_metadata_under_one_pass_budget"]),
    m("DM14", "initial chain parameters: reopen constructor-authenticated metadata",
      ["sumeragi_finality::tests::initial_chain_parameters_reuses_constructor_authenticated_metadata_under_one_pass_budget"]),


    m("DM15", "original signed genesis policy: repeat completed exact instruction decoding",
      ["sumeragi_finality::genesis::original_policy::tests::original_completed_policy_survives_metadata_refusal_without_another_decode"]),

    m("DM16", "signed epoch validation: reconstruct a temporary owning generation roster",
      ["sumeragi::epoch::tests::epoch_validation_retains_original_signed_roster_without_generation_allocation"]),
    m("DM17", "NPoS validation: reconstruct fixed synthetic identity during original record transfer",
      ["parameter::system::npos_json::tests::admitted_npos_record_moves_exact_original_quantity_backing_and_funded_charge_ledger",
       "parameter::system::tests::sumeragi_npos_synthetic_identity_is_exact_and_validation_never_allocates",
       "nexus::committee::tests::frozen_policy_validation_borrows_fixed_synthetic_identity_without_allocation"]),

    m("DM18", "committee readiness: reconstruct a temporary owning generation roster",
      ["nexus::committee::tests::public_readiness_borrows_original_roster_with_only_canonical_transcript_work"]),
    m("DM19", "committee Activate validation: reconstruct a temporary owning generation roster",
      ["nexus::committee::tests::public_activation_borrows_original_generation_beyond_existing_readiness_work"]),
    m("DM20", "multisig contract recognition: turn original scoped JSON refusal into nonmatch",
      ["smart_contract::multisig_call::tests::canonical_recognition_preserves_original_scoped_refusal_and_same_envelope_retry"]),
    m("DM21", "canonical address decoder: erase original scoped and unscoped resource causes",
      ["account::address::tests::canonical_address_json_preserves_original_refusal_fields_scope_and_retry", "account::address::tests::account_address_value_and_map_key_json_decoders_are_borrowed_and_measured", "account::address::tests::address_resource_conversions_preserve_fields_and_anonymous_bounds_without_minting_scope"]),
    m("DM22", "canonical account parser: replace original address cause with a fieldless bound",
      ["account::json_tests::canonical_account_json_preserves_original_refusal_fields_scope_and_retry", "account::json_tests::account_id_json_roundtrips_large_multisig_as_canonical_i105", "account::json_tests::account_id_value_and_map_key_json_decoders_are_borrowed_and_measured", "account::json_tests::canonical_account_public_parser_preserves_original_address_cause_and_diagnostics"]),
    m("DM23", "numeric I105 resource refusal: continue later canonical candidates",
      ["account::address::tests::numeric_i105_resource_refusal_stops_at_original_candidate_without_later_allocations"]),
    m("DM24", "expected I105 prefix diagnostics: retry a terminal resource refusal",
      ["account::address::tests::expected_i105_prefix_diagnostics_do_not_retry_original_resource_refusal"]),

    m("DM25", "persisted AccountId storage keys: erase original typed refusal at canonical delegation",
      ["json_key_codec::tests::account_storage_keys_preserve_original_refusal_fields_scope_and_retry"]),
    m("DM26", "persisted role assignment keys: erase original account refusal at canonical delegation",
      ["role::native_assignment_tests::role_assignment_storage_keys_preserve_original_account_refusal_and_retry"]),
    m("DM27", "Kaigi participant metadata: erase original typed refusal at canonical map delegation",
      ["kaigi::tests::kaigi_participant_metadata_preserves_original_account_refusal_and_canonical_map"]),
    m("DM28", "instruction archive: retry after original borrowed-pair refusal",
      ["isi::instruction_decode_refusal_tests::archived_instruction_refusal_stops_without_allocating_an_owned_pair_retry"]),
    m("DM29", "instruction slice: erase original scoped resource refusal",
      ["isi::instruction_decode_refusal_tests::instruction_slice_retains_original_scoped_refusal_and_retry"]),
    m("DM30", "instruction JSON: stringify original nested binary refusal",
      ["isi::instruction_decode_refusal_tests::instruction_json_retains_original_scoped_refusal_and_retry"]),
    m("DM31", "instruction base64: omit cumulative scratch admission",
      ["isi::instruction_decode_refusal_tests::instruction_base64_scratch_is_admitted_before_decode_and_retries_original_input"]),
    m("DM32", "structured asset instructions: erase original canonical account refusal",
      ["isi::instruction_decode_refusal_tests::structured_asset_instructions_preserve_original_account_refusal_and_retry"]),
    m("DM33", "native AMX multisig semantic cause: allocate a String on original retained replay",
      ["sumeragi_amx::native::leg_decode::tests::invalid_native_multisig_threshold_replay_preserves_original_cause_without_diagnostic_allocations",
       "sumeragi_amx::native::leg_decode::tests::invalid_native_multisig_member_replay_preserves_original_cause_without_diagnostic_allocations"]),

    m("DM34", "epoch validation cache: reconstruct an owning canonical epoch snapshot",
      ["sumeragi_finality::epoch_graph::validation_tests::epoch_scope_retains_exact_context_without_a_hidden_heap_graph"],
      causes=(
          ExpectedFailure('epoch cache adds no heap graph beyond original context validation', 'crates/iroha_data_model/src/sumeragi_finality/epoch_graph/validation_tests.rs'),
      )),

    m("DM35", "AMX decisions: discard authenticated authority while Yes escrow remains unresolved",
      ["sumeragi_amx::tests::sumeragi_amx_delayed_decisions_survive_three_rotations_and_restart"]),

    m("DM36", "committed clock drift: omit the CT4 protocol bound",
      ["parameter::system::tests::clock_drift_bound_accepts_exact_limit_and_rejects_excess_without_overflow"]),
    m("DM37", "committed due-work policy: omit combined drift/cadence margin and overflow checks",
      ["parameter::system::tests::due_work_policy_checks_combined_margin_and_overflow_without_local_clock"]),
    m("DM38", "AMX debit approval: trust a permission cut under a foreign authenticated root",
      ["sumeragi_amx::approval_proof::tests::exact_debit_approval_rejects_substituted_roots_terms_relays_schema_and_permission_preimages"]),
    m("DM39", "last Yes ignores signed ledger-time expiry",
      ["sumeragi_amx::tests::time_tests::sumeragi_amx_time_boundary_is_exclusive_and_height_boundary_inclusive"], causes=(ExpectedFailure("late Yes must never decide Commit",
          "crates/iroha_data_model/src/sumeragi_amx/time_tests.rs"),)),
    m("DM40", "time expiry mutates a pending decision before its original writer accepts",
      ["sumeragi_amx::tests::time_tests::sumeragi_amx_time_expiry_preserves_all_pending_rows_on_writer_refusal"], causes=(ExpectedFailure("failed witness publication cannot prune time-expired obligations",
          "crates/iroha_data_model/src/sumeragi_amx/time_tests.rs"),)),

]


# Daemon integration rules execute only in the owning daemon unit-test crate.
DAEMON_MUTATIONS = [
    m("HC340", "AMX expiry recovery: treat decoded terminal journal state as fresh exact-carrier proof",
      ["amx_relay::ledger::expiry_recovery_tests::independently_decided_expiry_recovers_only_the_existing_exact_carrier_without_dispatch"],
      causes=(ExpectedFailure("read-only carrier recovery must preserve independently authenticated outcomes: unknown",
          "crates/irohad/src/amx_relay/expiry_recovery_tests.rs"),)),
    m("HC331", "AMX handoff recovery: omit independently applied original handoffs after epoch advancement",
      ["amx_relay::ledger::handoff_recovery_tests::fresh_relayer_recovers_independent_native_handoffs_after_two_epochs_and_restart"],
      causes=(ExpectedFailure("fresh relayer must recover the original independent successful handoff after its source epoch is no longer tracked",
          "crates/irohad/src/amx_relay/handoff_recovery_tests.rs"),)),
    m("HC332", "AMX source scan: continually move the frontier before retrying pending original handoffs",
      ["amx_relay::tests::growing_source_tip_cannot_starve_pending_original_handoff_retry"],
      causes=(ExpectedFailure("continuous source growth must not starve bounded retry of the original handoff",
          "crates/irohad/src/amx_relay.rs"),)),
    m("HC266", "AMX relay journal identity substitutes an unrelated authenticated successful carrier",
      ["amx_relay::ledger::proof_tests::relay_journal_identity_cannot_substitute_an_unrelated_successful_carrier"]),
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
    m("HC198", "DKG file publication: omit exact original creation mode initialization before public bytes",
      ["beacon_bootstrap::seat_export::tests::public_output_initializes_exact_original_creation_mode_before_publication_and_restore"]),
    m("HC200", "DKG aggregate restore: require adjacent live phase height while rebuilding complete original certified history",
      ["beacon_bootstrap::seat_attempt::finality::tests::aggregate_restart_replays_complete_original_history_before_next_phase_and_keeps_cutoff"]),
]


SDK_MUTATIONS = [
    m("SDK1", "Public Norito reads: accept missing or foreign response media",
      ["http::public::tests::public_norito_reads_refuse_missing_foreign_media_and_elapsed_requests",
       "http::public::tests::public_norito_reads_select_only_fixed_media_and_retain_original_public_policies"]),
]

DEPLOY_MUTATIONS = [
    m("DEP1", "Managed AMX sources: reconstruct a lost published capsule over HTTP",
      ["bootstrap::amx_sources::tests::managed_amx_sources_refuse_partial_removed_and_substituted_custody_without_http_repair",
       "bootstrap::amx_sources::tests::managed_amx_sources_keep_original_g1_h2_across_advanced_checkpoint_and_reopen",
       "bootstrap::amx_sources::tests::managed_amx_sources_refuse_incomplete_staging_without_refetch_or_new_deadline"]),
    m("DEP2", "Managed AMX sources: accept same bytes from a replaced original file inode",
      ["bootstrap::amx_sources::tests::managed_amx_sources_bind_original_file_identity_and_exact_capsule_inventory",
       "bootstrap::amx_sources::tests::managed_amx_sources_feed_real_private_staging_and_exact_retained_generation"]),
    m("DEP3", "Managed AMX sources: omit the live-release check after retained authentication",
      ["bootstrap::amx_sources::tests::managed_amx_sources_recheck_release_after_retained_authentication_without_refetch"]),
    m("DEP4", "Managed AMX sources: publish a new capsule after original acquisition expires",
      ["bootstrap::amx_sources::tests::managed_amx_sources_refuse_wrong_parent_height_and_expired_reads_before_publication"]),
    m("DEP5", "Managed AMX sources: reopen replaced G1/H2 from an unchanged local record",
      ["bootstrap::amx_sources::tests::managed_amx_sources_reopen_refuses_identical_g1_h2_replacement_without_http_repair",
       "bootstrap::amx_sources::tests::managed_amx_sources_reopen_preserves_original_native_pair_and_directory_without_new_reads"]),
    m("DEP6", "Administrative AMX registration: accept a substituted original child or signer",
      ["attachment::amx_registration::tests::original_amx_administrator_child_fees_time_and_checkpoint_survive_reopen_and_refuse_substitution"]),
    m("DEP7", "signed service profile: reconstruct completed original authenticated genesis metadata",
      ["localnet::private_root::tests::private_root_preparation_executes_signed_genesis_and_retains_owner_on_reopen"]),

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



TORII_MUTATIONS = [
    m("TOR1", "Pipeline cache: accept a block outcome without its exact canonical transaction binding",
      ["tests_runtime_handlers::pipeline_status_cached_applied_refuses_removed_original_membership",
       "tests_runtime_handlers::prepared_submit_outcome_cached_applied_refuses_removed_original_membership"]),
    m("TOR2", "Pipeline pending refresh: use execution capacity before original query admission and mutate the cache on refusal",
      ["tests_runtime_handlers::pipeline_status_pending_refresh_retains_original_query_refusal_and_pending_source"]),
    m("TOR3", "Finite finality HTTP stop control: retire original query credit before an unpolled worker error or deadline result",
      ["finality_interval::tests::failed_and_timed_out_workers_keep_original_credit_until_unpolled_stop_control_retires"]),
    m("TOR4", "Push replay: discard the original current carrier attempt on a late capacity refusal",
      ["push::tests::push_replay_late_capacity_retains_original_frame_and_waits_for_external_release",
       "push::tests::push_replay_verification_slot_capacity_preserves_original_wait_and_resumes"]),
    m("TOR5", "Push startup: read genesis execution before its genuine committed successor instead of waiting",
      ["push::tests::push_worker_genesis_bootstrap_waits_for_authenticated_successor_and_shutdown",
       "push::tests::push_worker_genesis_bootstrap_rejects_corrupt_history_and_nonzero_cursor"]),

]


NORITO_MUTATIONS = [
    m("NC1", "Direct canonical JSON: omit original active-counter family capture",
      ["core::decode_attempt::tests::direct_json_refusal_keeps_original_context_and_retry"]),
    m("NC2", "Decode provenance: accept a saved refusal without its observer root and boundary",
      ["core::decode_attempt::tests::direct_attempt_replay_under_same_counter_owner_is_invalid",
       "core::decode_attempt::tests::direct_attempt_cross_thread_replay_with_original_shared_context_is_invalid",
       "core::decode_attempt::tests::direct_nested_attempts_preserve_parent_origin_and_refuse_old_sibling",
       "core::decode_attempt::tests::already_active_direct_attempt_rejects_later_foreign_thread_root"]),
    m("NC3", "Decode provenance: wrap an exhausted observer identity sequence",
      ["core::decode_attempt::tests::observer_boundary_sequence_exhaustion_never_wraps"]),
    m("NC4", "JSON resource conversion: discard original unscoped decoder fields",
      ["json::tests::core_resource_errors_roundtrip_exact_fields_without_fresh_scope",
       "json::tests::direct_json_parser_retains_unscoped_fields_and_same_input_retry"]),
    m("NC5", "JSON resource conversion: turn malformed input into allocator refusal",
      ["json::tests::non_resource_core_errors_cannot_become_json_allocator_refusals"]),
]


def package_options(args):
    """Select the actual implementation owner without propagating a mutation to dependencies."""
    if getattr(args, "norito", False):
        return "norito", "mutation-testing", "SUMERAGI_NORITO_MUTATION"
    if getattr(args, "torii", False):
        return "iroha_torii", "mutation-testing", "SUMERAGI_TORII_MUTATION"
    if getattr(args, "sdk", False):
        return "iroha", "mutation-testing", "SUMERAGI_SDK_MUTATION"
    if getattr(args, "deploy", False):
        return "iroha_deploy", "mutation-testing", "SUMERAGI_DEPLOY_MUTATION"
    if getattr(args, "model", False):
        return "iroha_data_model", "mutation-testing", "SUMERAGI_MODEL_MUTATION"
    if getattr(args, "daemon", False):
        return "irohad_lib", "mutation-testing", "SUMERAGI_DAEMON_MUTATION"
    if getattr(args, "core", False):
        return "iroha_core", "mutation-testing,iroha-core-tests", "SUMERAGI_CORE_MUTATION"
    return CRATE, FEATURES, "SUMERAGI_MUTATION"

TEST_COMPLETION = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in \d+(?:\.\d+)?s$", re.M)
TEST_RUNNING = re.compile(r"^running (\d+) tests?$", re.M)
TEST_LIST = re.compile(r"^(\S+): test$", re.M)
TEST_LIST_COMPLETION = re.compile(r"^(\d+) tests?, (\d+) benchmarks?$", re.M)


def serial_test_terminals(output):
    """Bind each inline or logger-split status to its one serial libtest owner.

    The caller also checks discovery, process exit, counts and header/summary
    order. An orphan, duplicate or unfinished terminal never qualifies a result.
    """
    results = []
    pending = None
    valid = True
    offset = 0
    for line in output.splitlines(keepends=True):
        text = line.rstrip("\r\n")
        start = re.fullmatch(r"test (\S+)(?: - should panic)? \.\.\.(?: (.*))?", text)
        if start:
            if pending is not None:
                valid = False
            pending = (start.group(1), offset)
            status = start.group(2) or ""
        else:
            status = text
        if re.fullmatch(r"ok|FAILED|ignored(?:, .*?)?", status):
            if pending is None:
                valid = False
            else:
                name, begin = pending
                results.append((name, status, begin, offset + len(text)))
                pending = None
        if text.startswith("test result:") and pending is not None:
            valid = False
        offset += len(line)
    return results, valid and pending is None


def captured_test_panics(output):
    """Keep each panic inside its exact libtest captured-output owner."""
    headers = list(re.finditer(r"^---- (\S+) stdout ----$", output, re.M))
    boundaries = list(re.finditer(r"^(?:---- \S+ stdout ----|failures:|test result:.*)$", output, re.M))
    generic = re.compile(r"^thread '[^']+'(?: \(\d+\))? panicked at [^\n]+:\n", re.M)
    exact = re.compile(r"^thread '([^']+)'(?: \(\d+\))? panicked at (.+):[0-9]+:[0-9]+:\n([^\n]*)", re.M)
    result = {}
    accounted = 0
    valid = True
    for header in headers:
        name = header.group(1)
        end = next((boundary.start() for boundary in boundaries if boundary.start() > header.start()), len(output))
        body = output[header.end():end]
        panics = list(exact.finditer(body))
        valid = valid and name not in result and len(panics) == len(list(generic.finditer(body)))
        result[name] = [dict(thread=panic.group(1), source=panic.group(2), message=panic.group(3)) for panic in panics]
        accounted += len(panics)
    return result, valid and accounted == len(list(generic.finditer(output)))


def expected_test_failure(name, expected, panics):
    """An incidental message or fixture failure cannot kill a declared causal control."""
    if not panics or len(panics) != (2 if expected.worker_thread else 1):
        return False
    first = panics[0]
    if (first['thread'] != (expected.worker_thread or name) or first['source'] != expected.source
            or first['message'] not in (expected.cause,
                f"assertion `left == right` failed: {expected.cause}",
                f"assertion `left != right` failed: {expected.cause}")):
        return False
    return not expected.worker_thread or panics[1] == {
        'thread': name, 'source': expected.join_source, 'message': expected.join_message}


@dataclass
class Step:
    status: str  # pass | fail | build-error | execution-error | timeout | missing-test | skipped
    seconds: float = 0.0
    failed: list = field(default_factory=list)
    ran: list = field(default_factory=list)
    detail: list = field(default_factory=list)
    log: str = ""
    selected: list = field(default_factory=list)
    discovery_log: str = ""
    panics: dict = field(default_factory=dict)
    panic_owners_valid: bool = False


def cargo_test(args, target_dir, mutation, filters, seeds, timeout, log_path, no_run=False):
    """Run `cargo test` for the crate; returns (returncode or None on timeout, output)."""
    env = dict(os.environ)
    env.pop("SUMERAGI_MUTATION", None)
    env.pop("SUMERAGI_CORE_MUTATION", None)
    env.pop("SUMERAGI_DAEMON_MUTATION", None)
    env.pop("SUMERAGI_MODEL_MUTATION", None)
    env.pop("SUMERAGI_SDK_MUTATION", None)
    env.pop("SUMERAGI_DEPLOY_MUTATION", None)
    env.pop("SUMERAGI_TORII_MUTATION", None)
    env.pop("SUMERAGI_NORITO_MUTATION", None)
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
    profile = ("test" if any(getattr(args, owner, False) for owner in ("model", "sdk", "deploy", "torii", "norito")) else
               (getattr(args, "core_profile", None) or "test") if getattr(args, "core", False) else None)
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


def test_selector_matches(selector, name):
    """Resolve a full test path or every exact leaf, without a substring substitute."""
    return name == selector if "::" in selector else name.rsplit("::", 1)[-1] == selector


def required_test_failures(filters, failed):
    """Retain only failures of declared controls, separately from selected extras."""
    return sorted(name for name in failed
                  if any(test_selector_matches(selector, name) for selector in filters))


def run_step(args, target_dir, mutation, filters, seeds, timeout, log_path):
    """Account for the actual substring selection within one original deadline."""
    started = time.monotonic()
    discovery_log = log_path.with_name(log_path.stem + ".discovery" + log_path.suffix)
    discovery_code, listing, discovery_elapsed = cargo_test(
        args, target_dir, mutation, [*filters, "--list", "--format", "pretty", "--color", "never"],
        seeds, timeout, discovery_log)
    selected = TEST_LIST.findall(listing)
    declared = TEST_LIST_COMPLETION.findall(listing)
    elapsed = max(time.monotonic() - started, discovery_elapsed)
    step = Step(status="pass", seconds=round(elapsed, 1), selected=selected,
                log=str(log_path), discovery_log=str(discovery_log))
    if discovery_code is None or (timeout and elapsed >= timeout):
        step.status = "timeout"
        step.detail.append(f"discovery exhausted the original {timeout}s deadline")
        return step
    if discovery_code != 0 or declared != [(str(len(selected)), "0")] or len(selected) != len(set(selected)):
        step.status = "execution-error"
        step.detail.append("test discovery did not complete exactly one unique libtest inventory")
        return step
    missing = [selector for selector in filters
               if not any(test_selector_matches(selector, name) for name in selected)]
    if missing:
        step.status = "missing-test"
        step.detail.append(f"no discovered declared control: {missing}")
        return step
    required = {name for name in selected
                if any(test_selector_matches(selector, name) for selector in filters)}
    remaining = max(0.0, timeout - elapsed) if timeout else 0
    code, out, runtime_elapsed = cargo_test(
        args, target_dir, mutation,
        [*filters, "--test-threads=1", "--format", "pretty", "--color", "never"],
        seeds, remaining, log_path)
    elapsed = max(time.monotonic() - started, discovery_elapsed + runtime_elapsed)
    terminals, terminal_owners_valid = serial_test_terminals(out)
    results = [(name, verdict) for name, verdict, _, _ in terminals]
    ran = sorted({name for name, verdict in results if not verdict.startswith("ignored")})
    failed = sorted({name for name, verdict in results if verdict == "FAILED"})
    panics, panic_owners_valid = captured_test_panics(out)
    step = Step(status="pass", seconds=round(elapsed, 1), failed=failed, ran=ran,
                selected=selected, log=str(log_path), discovery_log=str(discovery_log),
                panics=panics, panic_owners_valid=panic_owners_valid)
    missing = sorted(required - set(ran))
    if code is None or (timeout and elapsed > timeout):
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
        step.detail.append(f"no executed declared control: {missing}")
        step.status = "missing-test"
    if step.status in ("pass", "fail"):
        expected = "FAILED" if step.status == "fail" else "ok"
        passed = sum(verdict == "ok" for _, verdict in results)
        summaries = TEST_COMPLETION.findall(out)
        summary_lines = re.findall(r"^test result:.*$", out, re.M)
        running = list(TEST_RUNNING.finditer(out))
        completions = list(TEST_COMPLETION.finditer(out))
        ordered = (len(running) == len(completions) == 1 and bool(terminals)
                   and running[0].end() < terminals[0][2]
                   and terminals[-1][3] < completions[0].start())
        exact = (len(summary_lines) == len(summaries) == 1
                 and [match.group(1) for match in running] == [str(len(selected))]
                 and ordered and terminal_owners_valid
                 and summaries[0][0] == expected
                 and tuple(map(int, summaries[0][1:5])) == (passed, len(failed), 0, 0)
                 and len(results) == len(selected) and len(ran) == len(results)
                 and set(ran) == set(selected))
        if not exact or code != (101 if failed else 0):
            step.status = "execution-error"
            step.detail.append("cargo did not complete every discovered test exactly once with a matching summary")
    return step


def build(args, target_dir, mutation, log_path):
    code, out, elapsed = cargo_test(args, target_dir, mutation, [], None, args.timeout_build,
                                    log_path, no_run=True)
    ok = code == 0
    detail = [] if ok else ([line for line in out.splitlines() if line.startswith("error")][:5]
                            or ["timeout" if code is None else f"cargo exited {code}"])
    return Step(status="pass" if ok else "build-error", seconds=round(elapsed, 1),
                detail=detail, log=str(log_path))


def has_switch(mid, *, core=False, daemon=False, model=False, sdk=False, deploy=False, torii=False, norito=False):
    if sum((core, daemon, model, sdk, deploy, torii, norito)) > 1:
        raise ValueError("a mutation has exactly one implementation owner")
    if norito:
        cfg, source = "sumeragi_norito_mutation", REPO / "crates" / "norito" / "src"
    elif torii:
        cfg, source = "sumeragi_torii_mutation", REPO / "crates" / "iroha_torii" / "src"
    elif sdk:
        cfg, source = "sumeragi_sdk_mutation", REPO / "crates" / "iroha" / "src"
    elif deploy:
        cfg, source = "sumeragi_deploy_mutation", REPO / "crates" / "iroha_deploy" / "src"
    elif model:
        cfg, source = "sumeragi_model_mutation", REPO / "crates" / "iroha_data_model" / "src"
    elif daemon:
        cfg, source = "sumeragi_daemon_mutation", REPO / "crates" / "irohad" / "src"
    else:
        cfg = "sumeragi_core_mutation" if core else "sumeragi_mutation"
        source = REPO / "crates" / "iroha_core" / "src" if core else CRATE_SRC
    needle = f'{cfg} = "{mid}"'
    return any(needle in p.read_text() for p in source.rglob("*.rs"))



def run_grouped_steps(args, target_dir, mutation, groups, seeds, timeout, logs, stem):
    """Retain every invocation and refuse an aggregate pass or kill on any step error."""
    steps = []
    for index, filters in enumerate(groups):
        log = logs / f"{stem}.{index:03d}.log"
        if not filters:
            step = Step(status="missing-test", detail=["no selectors for this invocation"], log=str(log))
        else:
            step = run_step(args, target_dir, mutation, filters, seeds, timeout, log)
        steps.append({"filters": list(filters), "deadline_seconds": timeout,
                      "seeds": seeds, **step.__dict__,
                      "required_failed": required_test_failures(filters, step.failed)})
    errors = [step["status"] for step in steps if step["status"] not in ("pass", "fail")]
    status = (errors[0] if errors else "fail" if any(step["status"] == "fail" for step in steps)
              else "pass" if steps else "missing-test")
    return {"status": status,
            "seconds": round(sum(step["seconds"] for step in steps), 1),
            "failed": sorted({name for step in steps for name in step["failed"]}),
            "required_failed": sorted({name for step in steps for name in step["required_failed"]}),
            "ran": sorted({name for step in steps for name in step["ran"]}),
            "selected": sorted({name for step in steps for name in step["selected"]}),
            "steps": steps}


def evaluate(args, target_dir, mu):
    logs = args.target_dir / "logs"
    result = {"id": mu.id, "site": mu.site, "named_tests": list(mu.tests),
              "scenarios": [SCENARIOS[s] for s in mu.scenarios]}
    if not mu.tests:
        result.update(verdict="error", reason="no named test selectors")
        return result
    started = time.monotonic()
    if getattr(args, "norito", False):
        present = has_switch(mu.id, norito=True)
    elif getattr(args, "torii", False):
        present = has_switch(mu.id, torii=True)
    elif getattr(args, "sdk", False):
        present = has_switch(mu.id, sdk=True)
    elif getattr(args, "deploy", False):
        present = has_switch(mu.id, deploy=True)
    elif getattr(args, "model", False):
        present = has_switch(mu.id, model=True)
    elif getattr(args, "daemon", False):
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
    named_failed = required_test_failures(mu.tests, named.failed)
    result["named"] = {**named.__dict__, "required_failed": named_failed}
    killed_by_test = named.status == "fail" and bool(named_failed)
    causal_failures = None
    if mu.causes and named.status == "fail":
        causal_failures = {
            name: (named.panic_owners_valid and name in named_failed
                   and expected_test_failure(name, expected, named.panics.get(name)))
            for name, expected in zip(mu.tests, mu.causes)
        }
        result["named"]["causal_failures"] = causal_failures
        killed_by_test = all(causal_failures.values())
    scen = None
    if mu.scenarios and not args.fast:
        groups = [(scenario,) for scenario in dict.fromkeys(SCENARIOS[s] for s in mu.scenarios)]
        scen = run_grouped_steps(args, target_dir, mu.id, groups, args.seeds,
                                 args.timeout_scenario, logs, f"{mu.id}.scenario")
        result["scenario"] = scen
    killed_by_scenario = scen is not None and scen["status"] == "fail" and bool(scen["required_failed"])
    if named.status not in ("pass", "fail"):
        result.update(verdict="error", reason=f"named tests: {named.status}")
    elif causal_failures is not None and not killed_by_test:
        result.update(verdict="error", reason="named tests: every declared causal control must fail at its exact owned assertion")
    elif named.status == "fail" and not killed_by_test:
        result.update(verdict="error", reason="named tests: only additional substring-selected tests failed")
    elif scen is not None and scen["status"] not in ("pass", "fail"):
        result.update(verdict="error", reason=f"scenarios: {scen['status']}")
    elif scen is not None and any(step["status"] == "fail" and not step["required_failed"]
                                  for step in scen["steps"]):
        result.update(verdict="error", reason="scenarios: only additional substring-selected tests failed")
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
    # Preserve each mutation's exact named-selector tuple as its original step.
    # The baseline de-duplicates tuples, rather than merging unrelated steps.
    groups = sorted({tuple(mu.tests) for mu in mutations})
    named = run_grouped_steps(args, target_dir, None, groups, None, args.timeout_test,
                             logs, "baseline.named")
    result["named"] = named
    ok = named["status"] == "pass"
    scenarios = sorted({SCENARIOS[s] for mu in mutations for s in mu.scenarios})
    if scenarios and not args.fast:
        scen = run_grouped_steps(args, target_dir, None, [(s,) for s in scenarios],
                                 args.seeds, args.timeout_scenario, logs, "baseline.scenario")
        result["scenario"] = scen
        ok = ok and scen["status"] == "pass"
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
    owner.add_argument("--model", action="store_true",
                       help="qualify registered DataModel resource-custody rules with Model unit tests in the test profile")
    owner.add_argument("--sdk", action="store_true",
                       help="qualify registered SDK public-read rules with owning unit tests in the test profile")
    owner.add_argument("--deploy", action="store_true",
                       help="qualify registered Deploy managed-bootstrap custody rules with owning unit tests in the test profile")
    owner.add_argument("--torii", action="store_true",
                       help="qualify registered Torii canonical-outcome custody rules with owning unit tests in the test profile")
    owner.add_argument("--norito", action="store_true",
                       help="qualify registered Norito decode-origin rules with owning unit tests in the test profile")
    parser.add_argument("--only", help="comma-separated mutation ids (default: all)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="parallel jobs, each with its own target sub-directory")
    parser.add_argument("--fast", action="store_true",
                        help="named deterministic tests only (skip the randomized scenarios)")
    parser.add_argument("--seeds", type=int, default=200,
                        help="SUMERAGI_SIM_SEEDS for the scenarios (default 200)")
    parser.add_argument("--target-dir", type=Path,
                        help="dedicated target root (default: target/sumeragi-mutants; --core: target/sumeragi-core-mutants; --daemon: target/sumeragi-daemon-mutants; --model: target/sumeragi-model-mutants; --sdk: target/sumeragi-sdk-mutants; --deploy: target/sumeragi-deploy-mutants; --torii: target/sumeragi-torii-mutants; --norito: target/sumeragi-norito-mutants)")
    parser.add_argument("--skip-baseline", action="store_true",
                        help="do not run the unmutated build")
    parser.add_argument("--strict", action="store_true",
                        help="also fail when a mutation is killed only by its scenario "
                             "(the literal §13.4 CI rule)")
    parser.add_argument("--core-profile", choices=("release", "test"),
                        help="Core-only build profile (default: test); identical for baseline and mutant")
    parser.add_argument("--timeout-build", type=int, default=1200,
                        help="seconds per build deadline (0 disables its deadline)")
    parser.add_argument("--timeout-test", type=int, default=900,
                        help="seconds per named-selector tuple deadline (0 disables its deadline)")
    parser.add_argument("--timeout-scenario", type=int, default=3600,
                        help="seconds per scenario deadline (0 disables its deadline)")
    parser.add_argument("--list", action="store_true", help="print the mutation table and exit")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if not 1 <= args.seeds <= (1 << 64) - 1:
        parser.error("--seeds must be a positive u64 count")
    if args.strict and args.skip_baseline:
        parser.error("--strict requires the unmutated baseline")
    if args.target_dir is None:
        name = ("sumeragi-norito-mutants" if args.norito else
                "sumeragi-torii-mutants" if args.torii else
                "sumeragi-sdk-mutants" if args.sdk else
                "sumeragi-deploy-mutants" if args.deploy else
                "sumeragi-model-mutants" if args.model else
                "sumeragi-daemon-mutants" if args.daemon else
                "sumeragi-core-mutants" if args.core else "sumeragi-mutants")
        args.target_dir = REPO / "target" / name
    args.target_dir = args.target_dir.resolve()
    if args.core_profile is not None and not args.core:
        parser.error("--core-profile requires --core; protocol and daemon qualification use release")
    table = (NORITO_MUTATIONS if args.norito else TORII_MUTATIONS if args.torii else SDK_MUTATIONS if args.sdk else DEPLOY_MUTATIONS if args.deploy else
             MODEL_MUTATIONS if args.model else DAEMON_MUTATIONS if args.daemon else
             CORE_MUTATIONS if args.core else MUTATIONS)
    by_id = index_mutations(table)
    if min(args.timeout_build, args.timeout_test, args.timeout_scenario) < 0:
        parser.error("timeouts must be nonnegative; 0 waits without terminating a command")

    if args.list:
        for mu in table:
            print(f"{mu.id:22} {', '.join(mu.tests):60} {' '.join(mu.scenarios) or '-':10} "
                  f"{mu.site}")
        return 0

    selected = table
    if args.only is not None:
        wanted = [x.strip() for x in args.only.split(",") if x.strip()]
        if not wanted:
            parser.error("--only must select at least one mutation id")
        if len(wanted) != len(set(wanted)):
            parser.error("--only contains duplicate mutation ids")
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
            try:
                if kind == "baseline":
                    res = evaluate_baseline(args, target_dir, selected)
                else:
                    res = evaluate(args, target_dir, mu)
            except Exception as error:
                # A local guard/build/reader failure is an error for this original
                # work item, never a test kill. Do not catch process interrupts.
                res = {"id": "baseline" if kind == "baseline" else mu.id,
                       "verdict": "error",
                       "reason": f"worker evaluation raised {type(error).__name__}: {error}"}
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
        "baseline": baseline["verdict"] if baseline else ("skipped" if args.skip_baseline else "error"),
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
        "profile": ("test" if args.model or args.sdk or args.deploy or args.torii or args.norito else
                    (args.core_profile or "test") if args.core else "release"),
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
