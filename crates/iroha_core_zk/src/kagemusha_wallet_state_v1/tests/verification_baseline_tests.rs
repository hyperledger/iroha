//! Coordinator-boundary Omega verification counts per operation and fold turn.
//!
//! `TestProofs` stands in for native proving, so these count only the coordinator's own
//! `NativeProofs::verify_lineage` calls: recorded-Omega reads and the completion checks of
//! `fold_once`. The installed native owner's verification inside preparation and the fold
//! worker is counted by `kagemusha_wallet_proofs_v1::verification_counts`. The 2026-10-15
//! baseline allowed two coordinator verifications per completion turn; each new Omega is now
//! verified exactly once before anything is recorded, and only exact canonical bytes reuse it.

use super::*;

fn verifies(w: &Wallet) -> usize {
    w.proofs.verifies.load(Ordering::SeqCst)
}

/// Run fold turns until `sequence` is folded; return each turn's coordinator verifications.
fn fold_turns(w: &mut Wallet, sequence: u128) -> Vec<usize> {
    let mut turns = Vec::new();
    loop {
        let before = verifies(w);
        let status = w.fold_once().expect("fold turn");
        turns.push(verifies(w) - before);
        match status {
            FoldStatus::Folded(folded) if folded == sequence => return turns,
            FoldStatus::Checkpoint { sequence: at, .. } if at == sequence => {}
            other => panic!("unexpected fold status {other:?}"),
        }
    }
}

/// A wallet whose Bootstrap is committed and folded through three checkpoints.
fn folded_bootstrap() -> (Wallet, FrozenTransition, usize, Vec<usize>) {
    let mut w = wallet();
    w.proofs.checkpoint_stages = 3;
    let boot = bootstrap();
    let before = verifies(&w);
    w.commit(boot.clone()).expect("Bootstrap");
    let commit = verifies(&w) - before;
    w.scheduler().set_activity(true, false);
    let turns = fold_turns(&mut w, 0);
    (w, boot, commit, turns)
}

/// Coordinator verifications of one lineage-consuming operation (the Send dispatch path).
fn retire(w: &mut Wallet) -> usize {
    let before = verifies(w);
    let completion = w
        .execute(OperationRequestV1 {
            request_id: [71; 32],
            action: OperationActionV1::Retire,
        })
        .expect("Retire");
    assert!(matches!(completion, Completion::Complete(_)));
    verifies(w) - before
}

#[test]
fn coordinator_lineage_verifications_stay_within_the_baseline() {
    let (mut w, boot, bootstrap_commit, bootstrap_turns) = folded_bootstrap();
    let receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                .request
                .body
                .amount,
        },
    );
    let before = verifies(&w);
    w.commit(receive).expect("Receive");
    let receive_commit = verifies(&w) - before;
    let receive_turns = fold_turns(&mut w, 1);
    let before = verifies(&w);
    assert_eq!(w.fold_once().expect("caught up"), FoldStatus::CaughtUp);
    let caught_up = verifies(&w) - before;

    let lineage_operation_warm = retire(&mut folded_bootstrap().0);
    // Opening a coordinator verifies the recorded Omega once (initialize -> read_fold), so the
    // first operation after a restart reuses it.
    let (w, ..) = folded_bootstrap();
    let before = verifies(&w);
    let mut w = Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id)
        .expect("restart");
    let reopen = verifies(&w) - before;
    let lineage_operation_after_restart = retire(&mut w);

    eprintln!(
        "VERIFY_BASELINE_COORDINATOR bootstrap_commit={bootstrap_commit} \
         bootstrap_turns={bootstrap_turns:?} receive_commit={receive_commit} \
         receive_turns={receive_turns:?} caught_up={caught_up} \
         lineage_operation_warm={lineage_operation_warm} reopen={reopen} \
         lineage_operation_after_restart={lineage_operation_after_restart}"
    );
    assert_eq!(
        bootstrap_turns.len(),
        4,
        "three checkpoints and a completion"
    );
    assert_eq!(receive_turns.len(), 4, "three checkpoints and a completion");
    assert_eq!(bootstrap_commit, 0);
    assert!(bootstrap_turns[..3].iter().all(|count| *count == 0));
    assert_eq!(
        bootstrap_turns[3], 1,
        "one completion check; the recorded bytes reuse it"
    );
    assert_eq!(
        receive_commit, 0,
        "the just-folded predecessor Omega is reused"
    );
    assert!(receive_turns[..3].iter().all(|count| *count == 0));
    assert_eq!(
        receive_turns[3], 1,
        "one completion check; the recorded bytes reuse it"
    );
    assert_eq!(caught_up, 0);
    assert_eq!(lineage_operation_warm, 0, "the just-folded Omega is reused");
    assert_eq!(reopen, 1, "one recorded-Omega read when the owner opens");
    assert_eq!(
        lineage_operation_after_restart, 0,
        "the Omega verified at open is reused"
    );
}

#[test]
fn fold_completion_and_adoption_verify_each_new_omega_once() {
    let mut w = wallet();
    w.commit(bootstrap()).expect("Bootstrap");
    w.scheduler().set_activity(true, false);
    assert!(matches!(
        w.fold_once().expect("checkpoint"),
        FoldStatus::Checkpoint { .. }
    ));
    let unpublished = w.custody.checkpoint.clone();
    let before = verifies(&w);
    assert_eq!(w.fold_once().expect("fold"), FoldStatus::Folded(0));
    assert_eq!(
        verifies(&w) - before,
        1,
        "one verification before recording"
    );
    let recorded = w
        .archive
        .get(ArchiveKey::Fold(0), 20_000)
        .expect("get")
        .expect("recorded Omega");

    // Publication interrupted after the exact Omega bytes: adoption reuses the verification
    // of the same record bytes from this session.
    w.custody.checkpoint = unpublished.clone();
    let before = verifies(&w);
    assert_eq!(w.fold_once().expect("adopt"), FoldStatus::Folded(0));
    assert_eq!(verifies(&w) - before, 0);

    // Without that session entry, adoption verifies the record once; completion reuses it.
    w.custody.checkpoint = unpublished.clone();
    w.verified_folds.clear();
    let before = verifies(&w);
    assert_eq!(w.fold_once().expect("adopt"), FoldStatus::Folded(0));
    assert_eq!(verifies(&w) - before, 1);

    // Record bytes that changed after verification are verified again, never reused.
    w.custody.checkpoint = unpublished;
    let mut changed: RecordedFold = archive::decode(&recorded).expect("decode");
    changed.record.lineage.proof = vec![1, 2, 4];
    w.archive.records.lock().expect("records").insert(
        ArchiveKey::Fold(0),
        archive::encode(&changed).expect("encode"),
    );
    let before = verifies(&w);
    assert!(matches!(w.fold_once(), Err(Error::Proof(_))));
    assert_eq!(verifies(&w) - before, 1);
    assert_eq!(w.manifest().expect("source manifest").1.folded, None);
}

/// Prime the coordinator's verification caches, then present a recorded Ω whose record, head,
/// credential or custody binding changed: every binding is checked before any reuse, a changed
/// lineage is verified in full even when the original is cached and offered as just verified,
/// record bytes that differ from the manifest digest are refused before verification, and
/// nothing is recorded, published or advanced.
#[test]
fn warm_fold_caches_never_admit_changed_records_heads_or_custody() {
    let (mut w, ..) = folded_bootstrap();
    let step = w.released_steps().expect("steps").remove(0);
    let recorded = w
        .archive
        .get(ArchiveKey::Fold(0), 20_000)
        .expect("get")
        .expect("recorded Omega");
    let original: RecordedFold = archive::decode(&recorded).expect("decode");
    let lineage = original.record.lineage.bytes();
    assert!(w.read_fold(&step).expect("read").is_some());
    assert_eq!(w.verified_folds.get(&0), Some(&recorded));
    let signatures = w.custody.signatures;
    let folded = w.manifest().expect("manifest").1.folded;
    let before = verifies(&w);

    let mutations: [(&str, fn(&mut RecordedFold)); 11] = [
        ("first sequence", |f| f.record.first_sequence += 1),
        ("sequence", |f| f.record.sequence += 1),
        ("head", |f| f.record.head.value[0] ^= 1),
        ("capsule digest", |f| f.record.capsule_digest[0] ^= 1),
        ("scheme", |f| f.record.scheme_id[0] ^= 1),
        ("wallet", |f| f.record.wallet_id[0] ^= 1),
        ("credential", |f| {
            f.record.lineage.public.credential_digest[0] ^= 1;
        }),
        ("lifecycle", |f| {
            f.record.lineage.public.lifecycle = KagemushaWalletLifecycleV1::Retiring;
        }),
        ("policy epoch", |f| f.record.lineage.public.policy_epoch += 1),
        ("controls", |f| f.record.lineage.public.enabled_controls ^= 1),
        ("burn on a non-Receive head", |f| f.burned = true),
    ];
    for (label, mutate) in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        let bytes = archive::encode(&changed).expect("encode");
        assert!(
            matches!(
                w.verify_fold_bytes(&step, &bytes, Some(&lineage), None),
                Err(Error::WitnessLost(_) | Error::Invalid(_))
            ),
            "{label}"
        );
        assert_eq!(w.verified_folds.get(&0), Some(&recorded), "{label}");
    }
    assert_eq!(verifies(&w), before, "no binding failure reaches verification");

    // A changed lineage is verified in full and refused, whatever the caches hold.
    let mut changed = original.clone();
    changed.record.lineage.proof = vec![1, 2, 4];
    let changed = archive::encode(&changed).expect("encode");
    assert!(matches!(
        w.verify_fold_bytes(&step, &changed, Some(&lineage), None),
        Err(Error::Proof(_))
    ));
    assert_eq!(verifies(&w), before + 1);
    assert_eq!(w.verified_folds.get(&0), Some(&recorded));
    // The exact original record is reused from the session cache.
    assert!(w.verify_fold_bytes(&step, &recorded, None, None).is_ok());
    assert_eq!(verifies(&w), before + 1);

    // Custody: stored record bytes that differ from the manifest-bound digest are refused
    // before any verification, with the cache warm or cold.
    w.archive
        .records
        .lock()
        .expect("records")
        .insert(ArchiveKey::Fold(0), changed);
    for clear in [false, true] {
        if clear {
            w.verified_folds.clear();
        }
        assert!(matches!(
            w.read_fold(&step),
            Err(Error::WitnessLost("source-bound Ω identity"))
        ));
    }
    assert_eq!(verifies(&w), before + 1);
    assert!(w.verified_folds.is_empty());

    // Nothing was recorded, published or advanced.
    assert_eq!(w.custody.signatures, signatures);
    assert_eq!(w.manifest().expect("manifest").1.folded, folded);
}

/// A fold completion that fails or is cancelled at its single Ω verification records nothing;
/// the next attempt verifies again from nothing, and a restarted coordinator verifies the
/// recorded Ω once.
#[test]
fn failed_or_cancelled_completion_verification_records_nothing() {
    let mut w = wallet();
    w.commit(bootstrap()).expect("Bootstrap");
    let scheduler = w.scheduler();
    scheduler.set_activity(true, false);
    assert!(matches!(
        w.fold_once().expect("checkpoint"),
        FoldStatus::Checkpoint { .. }
    ));
    let checkpoint = w.custody.checkpoint.clone();
    let signatures = w.custody.signatures;

    // The single completion verification fails: nothing is recorded or published.
    w.proofs.reject = true;
    let before = verifies(&w);
    assert!(matches!(w.fold_once(), Err(Error::Proof(_))));
    assert_eq!(verifies(&w) - before, 1);
    assert_eq!(w.manifest().expect("manifest").1.folded, None);
    assert!(w.verified_folds.is_empty());
    assert!(
        w.archive
            .get(ArchiveKey::Fold(0), 20_000)
            .expect("get")
            .is_none()
    );
    assert_eq!(w.custody.checkpoint, checkpoint);

    // A cancelled turn has no verdict and records nothing.
    w.proofs.reject = false;
    let step = w.released_steps().expect("steps").remove(0);
    let running = scheduler.start().expect("background permit");
    scheduler.set_activity(false, false);
    assert!(matches!(
        w.read_fold_cancellable(&step, Some(&running.token)),
        Err(Error::Cancelled)
    ));
    drop(running);
    scheduler.set_activity(true, false);
    assert!(w.verified_folds.is_empty());
    assert_eq!(w.manifest().expect("manifest").1.folded, None);

    // The next attempt verifies once and records.
    let before = verifies(&w);
    assert_eq!(w.fold_once().expect("fold"), FoldStatus::Folded(0));
    assert_eq!(verifies(&w) - before, 1);
    assert_eq!(w.custody.signatures, signatures);

    // A restarted coordinator shares no cache: it verifies the recorded Ω once when it opens.
    let before = verifies(&w);
    let mut w = Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id)
        .expect("restart");
    assert_eq!(verifies(&w) - before, 1);
    assert_eq!(w.manifest().expect("manifest").1.folded, Some(0));
}
