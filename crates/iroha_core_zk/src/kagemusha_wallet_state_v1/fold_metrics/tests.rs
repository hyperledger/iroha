//! Observation-only fold records: turn phases, outcome mapping, the bounded log and its line.

use super::*;

fn record(ordinal: u32, outcome: FoldOutcomeV1, prove: Duration) -> FoldSubProofV1 {
    let mut phases = [Duration::ZERO; FoldPhaseV1::COUNT];
    phases[FoldPhaseV1::Prove.index()] = prove;
    FoldSubProofV1 {
        started_native_micros: 0,
        ended_native_micros: 0,
        sequence: 3,
        operation: Some(KagemushaWalletOperationKindV1::Receive),
        stage: Some(FoldStageV1::W),
        ordinal,
        outcome,
        phases,
        verification: KagemushaWalletVerificationCountsV1::default(),
        work: iroha_plonk::work_metrics::WorkMetrics::default(),
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
        started_native_micros: 0,
        ended_native_micros: 0,
        sequence: 7,
        operation: Some(KagemushaWalletOperationKindV1::Load),
        stage: Some(FoldStageV1::Q),
        ordinal: 1,
        outcome: FoldOutcomeV1::Cancelled(FoldCancelCauseV1::SetupIngest),
        phases,
        verification: KagemushaWalletVerificationCountsV1::default(),
        work: iroha_plonk::work_metrics::WorkMetrics::default(),
        peak_rss_bytes: Some(4096),
        ingests: 0,
    });
    metrics.record(FoldSubProofV1 {
        started_native_micros: 0,
        ended_native_micros: 0,
        sequence: 7,
        operation: None,
        stage: None,
        ordinal: 2,
        outcome: FoldOutcomeV1::Failed,
        phases: [Duration::ZERO; FoldPhaseV1::COUNT],
        verification: KagemushaWalletVerificationCountsV1::default(),
        work: iroha_plonk::work_metrics::WorkMetrics::default(),
        peak_rss_bytes: None,
        ingests: 0,
    });
    metrics.record(FoldSubProofV1 {
        started_native_micros: 0,
        ended_native_micros: 0,
        sequence: 8,
        operation: Some(KagemushaWalletOperationKindV1::Bootstrap),
        stage: Some(FoldStageV1::Omega),
        ordinal: 5,
        outcome: FoldOutcomeV1::Discarded,
        phases: [Duration::from_micros(2); FoldPhaseV1::COUNT],
        verification: KagemushaWalletVerificationCountsV1::default(),
        work: iroha_plonk::work_metrics::WorkMetrics::default(),
        peak_rss_bytes: Some(8192),
        ingests: 3,
    });
    assert_eq!(
        {
            let mut json = metrics.to_json();
            // Process scratch is live, process-wide observation rather than a fixture value.
            let memory_start = json.find(",\"processScratch\":").unwrap();
            let memory_end = memory_start + json[memory_start..].find(",\"records\":").unwrap();
            json.replace_range(memory_start..memory_end, "");
            let value: norito::json::Value = norito::json::from_slice(json.as_bytes()).unwrap();
            let sampled = value.as_object().unwrap()["sampledNativeMicros"]
                .as_u64()
                .unwrap();
            json.replacen(
                &format!("\"sampledNativeMicros\":{sampled}"),
                "\"sampledNativeMicros\":0",
                1,
            )
        },
        concat!(
            r#"{"schema":"iroha.kagemusha.fold-metrics.v2","sampledNativeMicros":0,"counts":{"subProofs":3,"#,
            r#""checkpoints":0,"folded":0,"adopted":0,"failed":1,"discarded":1,"#,
            r#""cancelledByPayment":0,"cancelledBySetupIngest":1,"cancelledByStatusRead":0,"#,
            r#""cancelledByActivity":0,"cancelledByClose":0,"discardedProveMicros":9,"#,
            r#""overlappedIngests":3},"records":["#,
            r#"{"startedNativeMicros":0,"endedNativeMicros":0,"sequence":7,"operation":"load","stage":"q","ordinal":1,"outcome":"cancelled","#,
            r#""cause":"setup_ingest","ingests":0,"peakRssBytes":4096,"verification":{"lineage":0,"full":0,"decides":0,"batches":0,"generatorMsms":0,"generatorMsmBases":0,"reusedVerifications":0,"reusedGenerators":0},"engineMicros":{"key_import":0,"key_rebuild":0,"witness":0,"prove":0,"self_verify":0,"commit":0},"micros":{"#,
            r#""sync_manifest":1,"read_fold":2,"fold_seed":3,"owner_replay":4,"restore":5,"#,
            r#""key_import":6,"prove":7,"publish":8}},"#,
            r#"{"startedNativeMicros":0,"endedNativeMicros":0,"sequence":7,"operation":null,"stage":null,"ordinal":2,"outcome":"failed","#,
            r#""cause":null,"ingests":0,"peakRssBytes":null,"verification":{"lineage":0,"full":0,"decides":0,"batches":0,"generatorMsms":0,"generatorMsmBases":0,"reusedVerifications":0,"reusedGenerators":0},"engineMicros":{"key_import":0,"key_rebuild":0,"witness":0,"prove":0,"self_verify":0,"commit":0},"micros":{"sync_manifest":0,"#,
            r#""read_fold":0,"fold_seed":0,"owner_replay":0,"restore":0,"key_import":0,"#,
            r#""prove":0,"publish":0}},"#,
            r#"{"startedNativeMicros":0,"endedNativeMicros":0,"sequence":8,"operation":"bootstrap","stage":"omega","ordinal":5,"#,
            r#""outcome":"discarded","cause":null,"ingests":3,"peakRssBytes":8192,"verification":{"lineage":0,"full":0,"decides":0,"batches":0,"generatorMsms":0,"generatorMsmBases":0,"reusedVerifications":0,"reusedGenerators":0},"engineMicros":{"key_import":0,"key_rebuild":0,"witness":0,"prove":0,"self_verify":0,"commit":0},"micros":{"#,
            r#""sync_manifest":2,"read_fold":2,"fold_seed":2,"owner_replay":2,"restore":2,"#,
            r#""key_import":2,"prove":2,"publish":2}}],"nativeWorkCount":0,"nativeWork":[]}"#
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

#[test]
fn verification_deltas_exclude_other_threads_and_earlier_turns() {
    use iroha_plonk::verification_counters::{record_decide, record_generator_msm};

    record_decide();
    let mut turn = FoldTurnV1::start();
    turn.select(1, 0);
    record_decide();
    record_generator_msm(8);
    std::thread::spawn(|| {
        record_decide();
        record_generator_msm(16);
    })
    .join()
    .unwrap();
    let record = turn.finish(Ok(FoldStatus::Folded(1)), None).unwrap();
    assert_eq!(record.verification.verify_lineage, 0);
    assert_eq!(record.verification.proofs.decides, 1);
    assert_eq!(record.verification.proofs.generator_msms, 1);
    assert_eq!(record.verification.proofs.generator_msm_bases, 8);
    let mut next = FoldTurnV1::start();
    next.select(2, 0);
    assert_eq!(
        next.finish(Ok(FoldStatus::Folded(2)), None)
            .unwrap()
            .verification,
        KagemushaWalletVerificationCountsV1::default()
    );
}

#[test]
fn maximal_public_records_fit_the_mobile_diagnostic_bound() {
    let mut metrics = FoldMetricsV1::default();
    let mut maximum = record(
        u32::MAX,
        FoldOutcomeV1::Cancelled(FoldCancelCauseV1::SetupIngest),
        Duration::MAX,
    );
    maximum.started_native_micros = u64::MAX;
    maximum.ended_native_micros = u64::MAX;
    maximum.sequence = u128::MAX;
    maximum.peak_rss_bytes = Some(u64::MAX);
    maximum.ingests = u32::MAX;
    maximum.phases = [Duration::MAX; FoldPhaseV1::COUNT];
    maximum.verification = KagemushaWalletVerificationCountsV1 {
        verify_lineage: u64::MAX,
        proofs: iroha_plonk::VerificationCounts {
            verify_full: u64::MAX,
            decides: u64::MAX,
            batches: u64::MAX,
            generator_msms: u64::MAX,
            generator_msm_bases: u64::MAX,
            reused_verifications: u64::MAX,
            reused_generators: u64::MAX,
        },
    };
    maximum.operation = Some(KagemushaWalletOperationKindV1::RefreshPolicy);
    maximum.stage = Some(FoldStageV1::Omega);
    maximum.work = iroha_plonk::work_metrics::WorkMetrics {
        key_import: Duration::MAX,
        key_rebuild: Duration::MAX,
        witness: Duration::MAX,
        prove: Duration::MAX,
        self_verify: Duration::MAX,
        commit: Duration::MAX,
    };
    for _ in 0..FOLD_METRICS_RECORDS_V1 {
        metrics.record(maximum);
    }
    for _ in 0..NATIVE_WORK_RECORDS_V1 + 3 {
        metrics.record_native_work(NativeWorkRecordV1 {
            started_native_micros: u64::MAX,
            ended_native_micros: u64::MAX,
            kind: NativeWorkKindV1::Fold,
            returned: false,
            elapsed: Duration::MAX,
            fold_record_id: Some(u64::MAX),
            bridge: NativeBridgeMetricsV1 {
                scheduler_wait: Duration::MAX,
                wallet_lock_wait: Duration::MAX,
                custody_admission: Duration::MAX,
            },
            admissions: NativeAdmissionsV1 {
                count: u64::MAX,
                records: [Some(NativeAdmissionV1 {
                    phase: NativeAdmissionPhaseV1::BeforeCommit,
                    required:
                        crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1 {
                            storage_bytes: u64::MAX,
                            memory_bytes: u64::MAX,
                        },
                    available: Some(
                        crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1 {
                            storage_bytes: u64::MAX - 1,
                            memory_bytes: Some(u64::MAX),
                        },
                    ),
                    result: NativeAdmissionResultV1::StorageShortfall,
                }); NATIVE_ADMISSION_RECORDS_V1],
            },
            verification: maximum.verification,
            work: maximum.work,
        });
    }
    assert_eq!(
        metrics.native_work_count(),
        u64::try_from(NATIVE_WORK_RECORDS_V1 + 3).unwrap()
    );
    assert_eq!(metrics.native_work().len(), NATIVE_WORK_RECORDS_V1);
    metrics.native_work_count = u64::MAX;
    metrics.set_process_peak_rss_bytes(Some(u64::MAX));
    metrics.counts = FoldCountsV1 {
        sub_proofs: u64::MAX,
        checkpoints: u64::MAX,
        folded: u64::MAX,
        adopted: u64::MAX,
        failed: u64::MAX,
        discarded: u64::MAX,
        cancelled_by_payment: u64::MAX,
        cancelled_by_setup_ingest: u64::MAX,
        cancelled_by_status_read: u64::MAX,
        cancelled_by_activity: u64::MAX,
        cancelled_by_close: u64::MAX,
        discarded_prove: Duration::MAX,
        overlapped_ingests: u64::MAX,
    };
    let json = metrics.to_json();
    // Clock and process scratch widths can grow after this test; reserve their full u64 widths.
    let bound = json.len() + 4 * 20;
    println!("fold-metrics.v2 worst-case retained JSON bound: {bound} bytes");
    assert!(bound <= FOLD_METRICS_MAX_BYTES_V1, "{bound}");
    let value: norito::json::Value = norito::json::from_slice(json.as_bytes()).unwrap();
    let object = value.as_object().unwrap();
    let scratch = object["processScratch"].as_object().unwrap();
    assert!(scratch["inUseBytes"].as_u64().unwrap() <= scratch["peakBytes"].as_u64().unwrap());
    assert!(scratch["peakBytes"].as_u64().unwrap() <= scratch["limitBytes"].as_u64().unwrap());
    assert_eq!(object["processPeakRssBytes"].as_u64(), Some(u64::MAX));
    let work = object["nativeWork"].as_array().unwrap()[0]
        .as_object()
        .unwrap();
    assert_eq!(work["admissionCount"].as_u64(), Some(u64::MAX));
    assert_eq!(
        work["admissions"].as_array().unwrap().len(),
        NATIVE_ADMISSION_RECORDS_V1
    );
    let rows = object["records"].as_array().unwrap();
    assert_eq!(rows.len(), FOLD_METRICS_RECORDS_V1);
    let verification = rows[0].as_object().unwrap()["verification"]
        .as_object()
        .unwrap();
    for field in [
        "lineage",
        "full",
        "decides",
        "batches",
        "generatorMsms",
        "generatorMsmBases",
        "reusedVerifications",
        "reusedGenerators",
    ] {
        assert_eq!(verification[field].as_u64(), Some(u64::MAX));
    }
}

#[test]
fn native_work_records_are_observation_only_and_count_the_calling_thread() {
    use iroha_plonk::{
        verification_counters::record_decide,
        work_metrics::{WorkPhase, WorkTimer},
    };
    let turn = NativeWorkTurnV1::start(NativeWorkKindV1::ReviewedExecute);
    record_decide();
    {
        let _timer = WorkTimer::start(WorkPhase::Prove);
    }
    std::thread::spawn(record_decide).join().unwrap();
    let record = turn.finish(false);
    assert!(!record.returned);
    assert_eq!(record.kind, NativeWorkKindV1::ReviewedExecute);
    assert_eq!(record.verification.proofs.decides, 1);
    assert_eq!(record.work.commit, Duration::ZERO);
    let mut log = FoldMetricsV1::default();
    log.record_native_work(record);
    assert_eq!(log.counts().sub_proofs, 0);
    assert_eq!(log.native_work_count(), 1);
    assert_eq!(log.native_work().front(), Some(&record));
}

#[test]
fn native_and_fold_marks_share_the_observation_clock_and_precede_sampling() {
    let (_, before) = native_mark();
    let native = NativeWorkTurnV1::start(NativeWorkKindV1::Execute);
    let mut fold = FoldTurnV1::start();
    fold.select(1, 0);
    let fold = fold.finish(Err(&Error::Proof("test")), None).unwrap();
    let native = native.finish(false);
    assert!(before <= native.started_native_micros);
    assert!(native.started_native_micros <= fold.started_native_micros);
    assert!(fold.started_native_micros <= fold.ended_native_micros);
    assert!(fold.ended_native_micros <= native.ended_native_micros);
    let mut log = FoldMetricsV1::default();
    log.record(fold);
    log.record_native_work(native);
    let json: norito::json::Value = norito::json::from_slice(log.to_json().as_bytes()).unwrap();
    let object = json.as_object().unwrap();
    let sampled = object["sampledNativeMicros"].as_u64().unwrap();
    assert!(native.ended_native_micros <= sampled);
    let (_, after) = native_mark();
    assert!(sampled <= after);
    let fold_json = &object["records"].as_array().unwrap()[0];
    assert_eq!(
        fold_json.as_object().unwrap()["startedNativeMicros"].as_u64(),
        Some(fold.started_native_micros)
    );
    assert_eq!(
        fold_json.as_object().unwrap()["endedNativeMicros"].as_u64(),
        Some(fold.ended_native_micros)
    );
    let work_json = &object["nativeWork"].as_array().unwrap()[0];
    assert_eq!(
        work_json.as_object().unwrap()["startedNativeMicros"].as_u64(),
        Some(native.started_native_micros)
    );
    assert_eq!(
        work_json.as_object().unwrap()["endedNativeMicros"].as_u64(),
        Some(native.ended_native_micros)
    );
}

#[test]
fn ring_reservation_refusal_loses_only_diagnostics_and_preserves_a_contiguous_suffix() {
    let mut rows = VecDeque::from([1_u64, 2]);
    retain_observation_with(&mut rows, 3, 4, |_, _| Err(()));
    assert!(rows.is_empty());
    retain_observation(&mut rows, 4, 4);
    for next in 5..=8 {
        retain_observation(&mut rows, next, 4);
    }
    assert_eq!(rows.iter().copied().collect::<Vec<_>>(), vec![5, 6, 7, 8]);
    retain_observation_with(&mut rows, 9, 4, |_, _| {
        panic!("full bounded ring must not allocate")
    });
    assert_eq!(rows.iter().copied().collect::<Vec<_>>(), vec![6, 7, 8, 9]);
}
