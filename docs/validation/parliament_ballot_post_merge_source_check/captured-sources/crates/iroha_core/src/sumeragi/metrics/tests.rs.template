//! Node-local recorder observations, bounded timing owners and per-instance lifecycle.

use super::*;
use iroha_crypto::{Algorithm, KeyPair, bls_normal_pop_prove};
use iroha_data_model::sumeragi_finality::{
    FinalityValidator, ScheduledSlot,
    test_fixtures::{NativeFinalityFixture, author_payload},
};
use iroha_sumeragi::{
    api::{Footprint, HaltReason},
    availability::{AvailabilitySource, AvailableBody},
    message::{BlockHeader, Qc, SyncRequest, TimeoutVote, VoteKind},
    preimage::payload_hash,
    types::{AggregateSignature, Bitmap, ControlWitness, EpochId, Hash32, PublicKey, Signature},
};
use iroha_telemetry::metrics::{
    Metrics,
    sumeragi::{HALT_REASONS, halt_reason_label},
};
use std::sync::Arc;

fn status() -> CoreStatus {
    CoreStatus {
        instance: Hash32([1; 32]),
        height: 10,
        view: 3,
        stage: 2,
        leader: None,
        proxy_tail: None,
        high_qc_view: None,
        level: 4,
        start_level: 1,
        t_retx: 250,
        committed_height: 9,
        applied_height: 8,
        awaiting: true,
        signer: Some(PublicKey::new(vec![1; 48]).unwrap()),
        unanchored: true,
        abstaining: true,
        halted: Some(HaltReason::SafetyViolation { height: 9 }),
        footprint: Footprint::default(),
    }
}

fn recorder(metrics: &Metrics) -> InstanceMetrics {
    InstanceMetrics::new(metrics.sumeragi_instance(GLOBAL_LANE))
}

// Timing observes custody already produced by the authoring port. This fixture uses genuine
// BLS/RS16 availability and the signed genesis schedule, but executes no World transition.
fn available_body() -> (AvailableBody, AvailabilitySource) {
    let fixture = NativeFinalityFixture::start("metrics-body-custody");
    let parent = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("fixture genesis has an authenticated successor");
    };
    let config = scheduled.height_config().unwrap();
    let mut keys: Vec<_> = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    let validators: Vec<_> = keys
        .iter()
        .map(|key| FinalityValidator {
            public_key: key.public_key().clone(),
            proof_of_possession: bls_normal_pop_prove(key.private_key()).unwrap(),
        })
        .collect();
    let crypto = crate::sumeragi::crypto::BlsCrypto::new();
    let payload = b"node-local timing fixture";
    let header = BlockHeader {
        instance: fixture.verifier().instance(),
        epoch: config.epoch.id,
        height: scheduled.height,
        origin_view: 0,
        parent_hash: parent.core_hash(),
        parent_result: parent.result(),
        payload_hash: payload_hash(&crypto, payload),
        payload_len: u32::try_from(payload.len()).unwrap(),
        availability_digest: Hash32::ZERO,
        proposer: 0,
        skipped_leaders: vec![],
        control_witness: ControlWitness::empty(),
    };
    let budget = iroha_allocation::AllocationBudget::new(128 * 1024 * 1024);
    let body = author_payload(header, payload, &config, &budget, &validators, &keys[0]).body;
    let source = AvailabilitySource::new(
        body.header().instance,
        body.header().height,
        body.hash(&crypto),
        config,
    )
    .unwrap();
    (body, source)
}

// These unsigned certificate fields are recorder input only: no crypto port or consensus core
// receives them, and they make no execution, finality or protocol-admission claim.
fn commit(body: &AvailableBody) -> Action {
    Action::CommitBlock {
        block: body.clone(),
        commit_qc: Qc {
            kind: VoteKind::Commit,
            instance: body.header().instance,
            epoch: body.header().epoch,
            height: body.header().height,
            view: body.header().origin_view,
            block_hash: Hash32::ZERO,
            result: Hash32::ZERO,
            signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
            agg_sig: AggregateSignature([0; 96]),
        },
    }
}

fn timeout(height: u64, view: u64, broadcast: bool) -> Action {
    let msg = WireMessage::Timeout(Box::new(TimeoutVote {
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 0,
            context: Hash32([2; 32]),
        },
        height,
        view,
        high_pqc: None,
        signer: 0,
        sig: Signature([0; 96]),
    }));
    if broadcast {
        Action::Broadcast { to: vec![], msg }
    } else {
        Action::Send {
            to: PublicKey::new(vec![1; 48]).unwrap(),
            msg,
        }
    }
}

#[test]
fn first_snapshot_sets_every_gauge_without_counting_restored_history() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    recorder.observe(
        &status(),
        &Backlog {
            ingress_dropped: 20,
            held_dropped: 30,
            serve_dropped: 40,
            ..Backlog::default()
        },
    );
    for (gauge, expected) in [
        (&metrics.sumeragi_round_height, 10),
        (&metrics.sumeragi_round_view, 3),
        (&metrics.sumeragi_round_stage, 2),
        (&metrics.sumeragi_pacemaker_level, 4),
        (&metrics.sumeragi_pacemaker_start_level, 1),
        (&metrics.sumeragi_retransmit_interval_ms, 250),
        (&metrics.sumeragi_committed_height, 9),
        (&metrics.sumeragi_applied_height, 8),
        (&metrics.sumeragi_awaiting_configuration, 1),
        (&metrics.sumeragi_signer_present, 1),
        (&metrics.sumeragi_abstaining, 1),
        (&metrics.sumeragi_unanchored, 1),
    ] {
        assert_eq!(gauge.with_label_values(&[GLOBAL_LANE]).get(), expected);
    }
    assert_eq!(metrics.view_changes.get(), 3);
    assert_eq!(
        metrics
            .sumeragi_commits_total
            .with_label_values(&[GLOBAL_LANE])
            .get(),
        0
    );
    assert_eq!(
        metrics
            .sumeragi_view_changes_total
            .with_label_values(&[GLOBAL_LANE])
            .get(),
        0
    );
    for queue in DropQueue::ALL {
        assert_eq!(
            metrics
                .sumeragi_dropped_total
                .with_label_values(&[GLOBAL_LANE, queue.label()])
                .get(),
            0
        );
    }
    assert_eq!(
        metrics
            .sumeragi_halted
            .with_label_values(&[GLOBAL_LANE, "safety_violation"])
            .get(),
        1
    );
}

#[test]
fn snapshots_count_only_positive_deltas_and_views_entered_at_new_heights() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    let mut status = status();
    let mut backlog = Backlog {
        ingress_dropped: 2,
        held_dropped: 3,
        serve_dropped: 4,
        ..Backlog::default()
    };
    recorder.observe(&status, &backlog);
    recorder.observe(&status, &backlog);
    status.view = 6;
    status.committed_height = 11;
    backlog.ingress_dropped = 5;
    backlog.held_dropped = 8;
    backlog.serve_dropped = 11;
    recorder.observe(&status, &backlog);
    status.height = 11;
    status.view = 2;
    status.committed_height = 12;
    recorder.observe(&status, &backlog);
    status.height = 9;
    status.view = 7;
    status.committed_height = 10;
    backlog.ingress_dropped = 1;
    backlog.held_dropped = 1;
    backlog.serve_dropped = 1;
    recorder.observe(&status, &backlog);
    recorder.observe(&status, &backlog);
    assert_eq!(
        metrics
            .sumeragi_commits_total
            .with_label_values(&[GLOBAL_LANE])
            .get(),
        3
    );
    assert_eq!(
        metrics
            .sumeragi_view_changes_total
            .with_label_values(&[GLOBAL_LANE])
            .get(),
        5
    );
    for (queue, expected) in DropQueue::ALL.into_iter().zip([3, 5, 7]) {
        assert_eq!(
            metrics
                .sumeragi_dropped_total
                .with_label_values(&[GLOBAL_LANE, queue.label()])
                .get(),
            expected
        );
    }
}

#[test]
fn halt_reasons_are_exclusive_clearable_and_report_worker_stop() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    let mut status = status();
    for reason in [Some(HaltReason::ApplyDiverged { height: 42 }), None] {
        status.halted = reason;
        recorder.observe(&status, &Backlog::default());
        for halt in HALT_REASONS {
            assert_eq!(
                metrics
                    .sumeragi_halted
                    .with_label_values(&[GLOBAL_LANE, halt_reason_label(halt)])
                    .get(),
                u64::from(reason.is_some() && matches!(halt, SumeragiHaltReason::ApplyDiverged(_)))
            );
        }
    }
    InstanceMetrics::stopped(recorder.series());
    for halt in HALT_REASONS {
        assert_eq!(
            metrics
                .sumeragi_halted
                .with_label_values(&[GLOBAL_LANE, halt_reason_label(halt)])
                .get(),
            u64::from(halt == SumeragiHaltReason::DriverAnomaly)
        );
    }
}

#[test]
fn timeout_votes_count_new_rounds_once_across_send_and_rebroadcast() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    for (height, view, broadcast) in [
        (2, 3, false),
        (2, 3, true),
        (2, 1, false),
        (1, 99, true),
        (2, 4, true),
        (3, 0, false),
    ] {
        recorder.action(100, &timeout(height, view, broadcast));
    }
    assert_eq!(
        metrics
            .sumeragi_timeout_votes_total
            .with_label_values(&[GLOBAL_LANE])
            .get(),
        3
    );
    recorder.action(100, &Action::Halt(HaltReason::DriverAnomaly));
    assert_eq!(
        metrics
            .sumeragi_halted
            .with_label_values(&[GLOBAL_LANE, "driver_anomaly"])
            .get(),
        0,
        "halt visibility belongs to status snapshots"
    );
}

#[test]
fn each_sync_and_body_fetch_action_uses_its_closed_kind() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    let (_, source) = available_body();
    for broadcast in [false, true] {
        let msg = WireMessage::SyncRequest(SyncRequest {
            instance: source.instance(),
            from_height: 2,
            max_count: 1,
            max_bytes: 4096,
        });
        let action = if broadcast {
            Action::Broadcast { to: vec![], msg }
        } else {
            Action::Send {
                to: PublicKey::new(vec![1; 48]).unwrap(),
                msg,
            }
        };
        recorder.action(100, &action);
        recorder.action(
            100,
            &Action::FetchPayload {
                source: source.clone(),
                peers: vec![],
            },
        );
    }
    for kind in FetchKind::ALL {
        assert_eq!(
            metrics
                .sumeragi_fetch_requests_total
                .with_label_values(&[GLOBAL_LANE, kind.label()])
                .get(),
            2
        );
    }
}

#[test]
fn latency_uses_first_execute_and_consumes_commit_and_apply_timestamps() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    let (body, _) = available_body();
    let execute = Action::Execute {
        block: body.clone(),
        req: 1,
        certified: false,
    };
    recorder.action(10, &execute);
    recorder.action(25, &execute);
    recorder.action(40, &commit(&body));
    recorder.applied(55, body.header().height);
    recorder.applied(70, body.header().height);
    let commit_latency = metrics
        .sumeragi_commit_latency_ms
        .with_label_values(&[GLOBAL_LANE]);
    let apply_latency = metrics
        .sumeragi_apply_latency_ms
        .with_label_values(&[GLOBAL_LANE]);
    assert_eq!(
        (
            commit_latency.get_sample_count(),
            commit_latency.get_sample_sum()
        ),
        (1, 30.0)
    );
    assert_eq!(
        (
            apply_latency.get_sample_count(),
            apply_latency.get_sample_sum()
        ),
        (1, 15.0)
    );
    assert!(recorder.executed.is_empty());
    assert!(recorder.committed.is_empty());
    // A commit without a locally observed Execute has no made-up proposal latency.
    recorder.action(100, &commit(&body));
    recorder.applied(110, body.header().height);
    assert_eq!(commit_latency.get_sample_count(), 1);
    assert_eq!(
        (
            apply_latency.get_sample_count(),
            apply_latency.get_sample_sum()
        ),
        (2, 25.0)
    );
    recorder.action(200, &execute);
    recorder.action(190, &commit(&body));
    recorder.applied(180, body.header().height);
    assert_eq!(
        (
            commit_latency.get_sample_count(),
            commit_latency.get_sample_sum()
        ),
        (2, 30.0)
    );
    assert_eq!(
        (
            apply_latency.get_sample_count(),
            apply_latency.get_sample_sum()
        ),
        (3, 25.0)
    );
}

#[test]
fn timing_owners_keep_only_newest_heights_and_prune_superseded_entries() {
    let metrics = Metrics::default();
    let mut recorder = recorder(&metrics);
    let (body, _) = available_body();
    let count = u64::try_from(MAX_TIMED_HEIGHTS).unwrap();
    for height in 1..=count + 10 {
        recorder.executed.insert(height, height);
        recorder.committed.insert(height, height);
    }
    bound(&mut recorder.executed);
    bound(&mut recorder.committed);
    for times in [&recorder.executed, &recorder.committed] {
        assert_eq!(times.len(), MAX_TIMED_HEIGHTS);
        assert_eq!(times.first_key_value().map(|(height, _)| *height), Some(11));
        assert_eq!(
            times.last_key_value().map(|(height, _)| *height),
            Some(count + 10)
        );
    }
    recorder.executed = [(1, 10), (2, 10), (3, 10)].into_iter().collect();
    recorder.committed = [(1, 10), (3, 10)].into_iter().collect();
    assert_eq!(body.header().height, 2);
    recorder.action(30, &commit(&body));
    assert_eq!(
        recorder.executed.keys().copied().collect::<Vec<_>>(),
        vec![3]
    );
    recorder.applied(40, 2);
    assert_eq!(
        recorder.committed.keys().copied().collect::<Vec<_>>(),
        vec![3]
    );
    recorder.applied(50, 1);
    assert_eq!(
        metrics
            .sumeragi_apply_latency_ms
            .with_label_values(&[GLOBAL_LANE])
            .get_sample_count(),
        1
    );
}

#[test]
fn instance_labels_switch_and_retirement_follow_the_node_registry() {
    let metrics = Arc::new(Metrics::default());
    let global = MetricsInstance::Global;
    let lane = MetricsInstance::Lane(LaneId::new(7));
    assert_eq!(global.label(), GLOBAL_LANE);
    assert_eq!(lane.label(), "7");
    let disabled = StateTelemetry::new(Arc::clone(&metrics), false);
    assert!(InstanceMetrics::for_node(&disabled, lane).is_none());
    #[cfg(feature = "telemetry")]
    {
        let enabled = StateTelemetry::new(Arc::clone(&metrics), true);
        let mut recorder = InstanceMetrics::for_node(&enabled, lane).unwrap();
        assert_eq!(recorder.series().lane(), "7");
        recorder.observe(&status(), &Backlog::default());
        assert_eq!(
            metrics.view_changes.get(),
            0,
            "lane snapshots do not overwrite global status"
        );
        let _global = InstanceMetrics::for_node(&enabled, global).unwrap();
        InstanceMetrics::retire(&enabled, lane);
        let exposition = metrics.try_to_string().unwrap();
        assert!(!exposition.contains("lane=\"7\""));
        assert!(exposition.contains("sumeragi_round_height{lane=\"global\"} 0"));
    }
}

/// The value of an exposition sample line of `family` (the family's own series, or the `_count`
/// of a histogram family), if `line` is one.
fn sample_value(line: &str, family: &str) -> Option<f64> {
    let rest = line.strip_prefix(family)?;
    let rest = rest.strip_prefix("_count").unwrap_or(rest);
    let value = match rest.strip_prefix('{') {
        Some(labelled) => labelled.split_once("} ")?.1,
        None => rest.strip_prefix(' ')?,
    };
    value.parse().ok()
}

/// Every `sumeragi_*` family the node exports is written by live node code: the per-instance
/// families by this recorder (the driver's only telemetry writer) and the transaction-queue
/// gauges by the queue's backpressure telemetry. The telemetry crate pins that its registered
/// `sumeragi_*` families are exactly these.
#[test]
fn live_writers_move_every_exported_sumeragi_family() {
    let metrics = Arc::new(Metrics::default());
    let mut recorder = recorder(&metrics);
    let (body, source) = available_body();
    let mut status = status();
    recorder.observe(&status, &Backlog::default());
    status.view += 1;
    status.committed_height += 1;
    recorder.observe(
        &status,
        &Backlog {
            ingress_dropped: 1,
            held_dropped: 1,
            serve_dropped: 1,
            ..Backlog::default()
        },
    );
    recorder.action(1, &timeout(status.height, status.view, true));
    recorder.action(
        1,
        &Action::FetchPayload {
            source,
            peers: vec![],
        },
    );
    recorder.action(
        2,
        &Action::Execute {
            block: body.clone(),
            req: 1,
            certified: false,
        },
    );
    recorder.action(5, &commit(&body));
    recorder.applied(9, body.header().height);
    let telemetry = StateTelemetry::new(Arc::clone(&metrics), true);
    crate::telemetry::record_state_tx_queue_backpressure(
        &telemetry, 3, 8, 64, 128, true, true, true, 700,
    );

    let exposition = metrics.try_to_string().unwrap();
    let families: std::collections::BTreeSet<&str> = exposition
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|line| line.split(' ').next())
        .filter(|family| family.starts_with("sumeragi_"))
        .collect();
    assert!(families.contains("sumeragi_commit_latency_ms"));
    assert!(families.contains("sumeragi_tx_queue_depth"));
    for family in families {
        assert!(
            exposition
                .lines()
                .filter_map(|line| sample_value(line, family))
                .any(|value| value != 0.0),
            "`{family}` is exported but no live writer sets it"
        );
    }
}
