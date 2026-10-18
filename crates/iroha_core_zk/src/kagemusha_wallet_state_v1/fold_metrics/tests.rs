//! Observation-only fold records: turn phases, outcome mapping, the bounded log and its line.

use super::*;

fn record(ordinal: u32, outcome: FoldOutcomeV1, prove: Duration) -> FoldSubProofV1 {
    let mut phases = [Duration::ZERO; FoldPhaseV1::COUNT];
    phases[FoldPhaseV1::Prove.index()] = prove;
    FoldSubProofV1 {
        sequence: 3,
        operation: Some(KagemushaWalletOperationKindV1::Receive),
        stage: Some(FoldStageV1::W),
        ordinal,
        outcome,
        phases,
        peak_rss_bytes: None,
        ingests: ordinal % 3,
    }
}

#[test]
fn only_a_selected_turn_reports_and_its_phases_stay_on_its_thread() {
    // An idle or caught-up wake reports nothing, selected or not.
    let turn = FoldTurnV1::start();
    enter(FoldPhaseV1::ReadFold);
    assert_eq!(turn.finish(Ok(FoldStatus::CaughtUp), None), None);
    let mut turn = FoldTurnV1::start();
    turn.select(4, 2);
    assert_eq!(turn.finish(Ok(FoldStatus::Idle), None), None);
    // Outside a turn nothing is kept, so it cannot leak into the next turn.
    enter(FoldPhaseV1::Prove);
    stage(FoldStageV1::W);
    let mut turn = FoldTurnV1::start();
    turn.select(4, 2);
    let quiet = turn
        .finish(
            Ok(FoldStatus::Checkpoint {
                sequence: 4,
                ordinal: 2,
            }),
            None,
        )
        .unwrap();
    assert_eq!(quiet.stage, None);
    assert_eq!(quiet.phase(FoldPhaseV1::Prove), Duration::ZERO);

    let mut turn = FoldTurnV1::start();
    turn.select(4, 2);
    turn.operation(KagemushaWalletOperationKindV1::Load);
    enter(FoldPhaseV1::ReadFold);
    enter(FoldPhaseV1::Prove);
    stage(FoldStageV1::A);
    // Another thread's phase changes never touch this turn.
    std::thread::spawn(|| {
        enter(FoldPhaseV1::Publish);
        stage(FoldStageV1::Omega);
    })
    .join()
    .unwrap();
    std::thread::sleep(Duration::from_millis(2));
    enter(FoldPhaseV1::Publish);
    let record = turn
        .finish(
            Ok(FoldStatus::Checkpoint {
                sequence: 4,
                ordinal: 2,
            }),
            None,
        )
        .unwrap();
    assert_eq!(
        (
            record.sequence,
            record.ordinal,
            record.operation,
            record.stage,
            record.outcome,
            record.peak_rss_bytes,
        ),
        (
            4,
            2,
            Some(KagemushaWalletOperationKindV1::Load),
            Some(FoldStageV1::A),
            FoldOutcomeV1::Checkpoint,
            None,
        )
    );
    assert!(record.phase(FoldPhaseV1::Prove) >= Duration::from_millis(2));
    for phase in [
        FoldPhaseV1::FoldSeed,
        FoldPhaseV1::OwnerReplay,
        FoldPhaseV1::Restore,
        FoldPhaseV1::KeyImport,
    ] {
        assert_eq!(record.phase(phase), Duration::ZERO);
    }
}

#[test]
fn a_dropped_turn_closes_its_thread_state() {
    let mut turn = FoldTurnV1::start();
    turn.select(1, 0);
    stage(FoldStageV1::Q);
    drop(turn);
    stage(FoldStageV1::A);
    let mut turn = FoldTurnV1::start();
    turn.select(1, 0);
    let record = turn.finish(Ok(FoldStatus::Folded(1)), None).unwrap();
    assert_eq!(record.stage, None);
}

#[test]
fn only_this_schedulers_signal_makes_a_cancellation() {
    let outcome = |result: Result<FoldStatus, Error>, adopted: bool, cause| {
        let mut turn = FoldTurnV1::start();
        turn.select(1, 0);
        if adopted {
            turn.adopting();
        }
        turn.finish(result.as_ref().copied(), cause)
            .map(|record| record.outcome)
    };
    let checkpoint = FoldStatus::Checkpoint {
        sequence: 1,
        ordinal: 0,
    };
    assert_eq!(
        outcome(Ok(checkpoint), false, None),
        Some(FoldOutcomeV1::Checkpoint)
    );
    assert_eq!(
        outcome(Ok(FoldStatus::Folded(1)), false, None),
        Some(FoldOutcomeV1::Folded)
    );
    for adopted in [Ok(checkpoint), Ok(FoldStatus::Folded(1))] {
        assert_eq!(outcome(adopted, true, None), Some(FoldOutcomeV1::Adopted));
    }
    for cause in [
        FoldCancelCauseV1::Payment,
        FoldCancelCauseV1::SetupIngest,
        FoldCancelCauseV1::StatusRead,
        FoldCancelCauseV1::Activity,
        FoldCancelCauseV1::Close,
    ] {
        assert_eq!(
            outcome(Err(Error::Cancelled), false, Some(cause)),
            Some(FoldOutcomeV1::Cancelled(cause))
        );
        // A signalled turn that failed otherwise is not a cancellation.
        assert_eq!(
            outcome(Err(Error::WitnessLost("test")), false, Some(cause)),
            Some(FoldOutcomeV1::Failed)
        );
    }
    assert_eq!(
        outcome(Err(Error::Cancelled), false, None),
        Some(FoldOutcomeV1::Failed)
    );
    // A proof discarded at its publication is neither a cancellation nor a failure; a
    // discarding turn that failed otherwise is a failure.
    let discarded = |result: Result<FoldStatus, Error>| {
        let mut turn = FoldTurnV1::start();
        turn.select(1, 0);
        turn.discarding();
        turn.finish(result.as_ref().copied(), None)
            .map(|record| record.outcome)
    };
    assert_eq!(
        discarded(Err(Error::Cancelled)),
        Some(FoldOutcomeV1::Discarded)
    );
    assert_eq!(
        discarded(Err(Error::WitnessLost("test"))),
        Some(FoldOutcomeV1::Failed)
    );
    assert_eq!(
        outcome(Err(Error::Proof("test")), false, None),
        Some(FoldOutcomeV1::Failed)
    );
    for class in [
        FoldCallClassV1::Payment,
        FoldCallClassV1::SetupIngest,
        FoldCallClassV1::StatusRead,
    ] {
        assert_eq!(
            class.cause().name(),
            match class {
                FoldCallClassV1::Payment => "payment",
                FoldCallClassV1::SetupIngest => "setup_ingest",
                FoldCallClassV1::StatusRead => "status_read",
            }
        );
    }
}

#[test]
fn the_log_keeps_the_last_records_and_counts_every_one() {
    let mut metrics = FoldMetricsV1::default();
    let causes = [
        FoldCancelCauseV1::Payment,
        FoldCancelCauseV1::SetupIngest,
        FoldCancelCauseV1::StatusRead,
        FoldCancelCauseV1::Activity,
        FoldCancelCauseV1::Close,
    ];
    let total = u32::try_from(FOLD_METRICS_RECORDS_V1).unwrap() + 6;
    for ordinal in 0..total {
        let outcome = match ordinal % 10 {
            0 => FoldOutcomeV1::Checkpoint,
            1 => FoldOutcomeV1::Folded,
            2 => FoldOutcomeV1::Adopted,
            3 => FoldOutcomeV1::Discarded,
            n => causes
                .get(usize::try_from(n - 4).unwrap())
                .copied()
                .map_or(FoldOutcomeV1::Failed, FoldOutcomeV1::Cancelled),
        };
        metrics.record(record(ordinal, outcome, Duration::from_micros(10)));
    }
    assert_eq!(metrics.records().len(), FOLD_METRICS_RECORDS_V1);
    assert_eq!(metrics.records().front().unwrap().ordinal, 6);
    assert_eq!(metrics.records().back().unwrap().ordinal, total - 1);
    // Ordinals 0..=69 cycle through the ten outcomes seven times each. Their ingests are
    // `ordinal % 3`: 23 full cycles of 0 + 1 + 2, then ordinal 69 adds 0.
    assert_eq!(
        metrics.counts(),
        FoldCountsV1 {
            sub_proofs: 70,
            checkpoints: 7,
            folded: 7,
            adopted: 7,
            failed: 7,
            discarded: 7,
            cancelled_by_payment: 7,
            cancelled_by_setup_ingest: 7,
            cancelled_by_status_read: 7,
            cancelled_by_activity: 7,
            cancelled_by_close: 7,
            discarded_prove: Duration::from_micros(10 * (7 + 5 * 7)),
            overlapped_ingests: 69,
        }
    );
}

#[test]
fn log_line_carries_only_fixed_names_whole_microseconds_counts_and_bytes() {
    let mut metrics = FoldMetricsV1::default();
    let mut phases = [Duration::ZERO; FoldPhaseV1::COUNT];
    for (micros, phase) in (1..).zip(FoldPhaseV1::ALL) {
        phases[phase.index()] = Duration::from_micros(micros);
    }
    phases[FoldPhaseV1::Prove.index()] += Duration::from_nanos(999);
    metrics.record(FoldSubProofV1 {
        sequence: 7,
        operation: Some(KagemushaWalletOperationKindV1::Load),
        stage: Some(FoldStageV1::Q),
        ordinal: 1,
        outcome: FoldOutcomeV1::Cancelled(FoldCancelCauseV1::SetupIngest),
        phases,
        peak_rss_bytes: Some(4096),
        ingests: 0,
    });
    metrics.record(FoldSubProofV1 {
        sequence: 7,
        operation: None,
        stage: None,
        ordinal: 2,
        outcome: FoldOutcomeV1::Failed,
        phases: [Duration::ZERO; FoldPhaseV1::COUNT],
        peak_rss_bytes: None,
        ingests: 0,
    });
    metrics.record(FoldSubProofV1 {
        sequence: 8,
        operation: Some(KagemushaWalletOperationKindV1::Bootstrap),
        stage: Some(FoldStageV1::Omega),
        ordinal: 5,
        outcome: FoldOutcomeV1::Discarded,
        phases: [Duration::from_micros(2); FoldPhaseV1::COUNT],
        peak_rss_bytes: Some(8192),
        ingests: 3,
    });
    assert_eq!(
        metrics.to_json(),
        concat!(
            r#"{"schema":"iroha.kagemusha.fold-metrics.v1","counts":{"subProofs":3,"#,
            r#""checkpoints":0,"folded":0,"adopted":0,"failed":1,"discarded":1,"#,
            r#""cancelledByPayment":0,"cancelledBySetupIngest":1,"cancelledByStatusRead":0,"#,
            r#""cancelledByActivity":0,"cancelledByClose":0,"discardedProveMicros":9,"#,
            r#""overlappedIngests":3},"records":["#,
            r#"{"sequence":7,"operation":"load","stage":"q","ordinal":1,"outcome":"cancelled","#,
            r#""cause":"setup_ingest","ingests":0,"peakRssBytes":4096,"micros":{"#,
            r#""sync_manifest":1,"read_fold":2,"fold_seed":3,"owner_replay":4,"restore":5,"#,
            r#""key_import":6,"prove":7,"publish":8}},"#,
            r#"{"sequence":7,"operation":null,"stage":null,"ordinal":2,"outcome":"failed","#,
            r#""cause":null,"ingests":0,"peakRssBytes":null,"micros":{"sync_manifest":0,"#,
            r#""read_fold":0,"fold_seed":0,"owner_replay":0,"restore":0,"key_import":0,"#,
            r#""prove":0,"publish":0}},"#,
            r#"{"sequence":8,"operation":"bootstrap","stage":"omega","ordinal":5,"#,
            r#""outcome":"discarded","cause":null,"ingests":3,"peakRssBytes":8192,"micros":{"#,
            r#""sync_manifest":2,"read_fold":2,"fold_seed":2,"owner_replay":2,"restore":2,"#,
            r#""key_import":2,"prove":2,"publish":2}}]}"#
        )
    );
    let value: norito::json::Value =
        norito::json::from_slice(metrics.to_json().as_bytes()).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(
        object.get("schema").and_then(norito::json::Value::as_str),
        Some(FOLD_METRICS_SCHEMA_V1)
    );
    assert_eq!(
        object
            .get("records")
            .and_then(norito::json::Value::as_array)
            .map(Vec::len),
        Some(3)
    );
}

#[test]
fn every_public_name_is_fixed_distinct_and_lowercase() {
    let mut names: Vec<&str> = FoldPhaseV1::ALL
        .into_iter()
        .map(FoldPhaseV1::name)
        .collect();
    names.extend(
        KagemushaWalletOperationKindV1::ALL
            .into_iter()
            .map(operation_name),
    );
    names.extend(
        [
            FoldStageV1::Q,
            FoldStageV1::A,
            FoldStageV1::W,
            FoldStageV1::Omega,
        ]
        .map(FoldStageV1::name),
    );
    names.extend(
        [
            FoldCancelCauseV1::Payment,
            FoldCancelCauseV1::SetupIngest,
            FoldCancelCauseV1::StatusRead,
            FoldCancelCauseV1::Activity,
            FoldCancelCauseV1::Close,
        ]
        .map(FoldCancelCauseV1::name),
    );
    let outcomes = [
        FoldOutcomeV1::Checkpoint,
        FoldOutcomeV1::Folded,
        FoldOutcomeV1::Adopted,
        FoldOutcomeV1::Cancelled(FoldCancelCauseV1::Payment),
        FoldOutcomeV1::Discarded,
        FoldOutcomeV1::Failed,
    ]
    .map(FoldOutcomeV1::name);
    names.extend(outcomes);
    for name in &names {
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{name}"
        );
    }
    let phases = &names[..FoldPhaseV1::COUNT];
    let operations = &names[FoldPhaseV1::COUNT..FoldPhaseV1::COUNT + 8];
    for group in [phases, operations, &outcomes[..]] {
        let mut sorted = group.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), group.len());
    }
}
