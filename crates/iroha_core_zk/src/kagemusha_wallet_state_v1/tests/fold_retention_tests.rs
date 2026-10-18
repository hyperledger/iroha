//! D6b slot ownership through the production coordinator and scheduler, with mock proof work.
//!
//! The mock leaves a marker with every checkpoint and records the marker each locked prepare is
//! handed; the markers carry no proof state. A sub-proof's marker reaches the next prepare only
//! after that sub-proof's own checkpoint publication, and every completion, failure, discard,
//! abandoned or refused publication, priority call, overlap and restart leaves the next prepare
//! cold. The mock's durable output is deterministic, so warm and all-cold runs must leave
//! byte-identical durable records. The four overlap regressions of the C12 countersign are the
//! `f1_*` and `f2_*` tests. The mock never computes or compares a retention key: key and prefix
//! matching belong to the native worker, whose predicates its unit tests pin and whose same-call
//! cold path the release fold flows drive with a changed key.

use super::*;
use std::ops::ControlFlow;

fn bootstrapped(stages: u8) -> Wallet {
    let mut wallet = wallet();
    wallet.proofs.checkpoint_stages = stages;
    wallet.commit(bootstrap()).expect("Bootstrap");
    wallet.scheduler().set_activity(true, false);
    wallet
}

fn prepared(wallet: &mut Wallet) -> FoldJobV1 {
    match wallet.fold_prepare().unwrap() {
        ControlFlow::Continue(job) => job,
        ControlFlow::Break(ended) => panic!("no sub-proof prepared: {ended:?}"),
    }
}

const fn checkpoint(ordinal: u32) -> FoldStatus {
    FoldStatus::Checkpoint {
        sequence: 0,
        ordinal,
    }
}

fn holds(wallet: &Wallet) -> bool {
    wallet.scheduler().holds_retained_for_test()
}

/// The durable records a fold left: every archive record and the selected manifest.
fn durable(wallet: &Wallet) -> (BTreeMap<ArchiveKey, Vec<u8>>, Option<([u8; 32], Vec<u8>)>) {
    (
        wallet.archive.records.lock().unwrap().clone(),
        wallet.custody.checkpoint.clone(),
    )
}

/// Fold Bootstrap to its Ω with a payment before every turn: every prepare runs cold.
fn all_cold(stages: u8) -> Wallet {
    let mut wallet = bootstrapped(stages);
    loop {
        drop(wallet.scheduler().payment());
        let status = wallet.fold_once().unwrap();
        assert_eq!(wallet.proofs.last_handed(), None);
        if status == FoldStatus::Folded(0) {
            return wallet;
        }
    }
}

/// The checkpoint and Ω records a fold left, without the index nodes an ingest adds.
fn fold_records(wallet: &Wallet) -> Vec<(ArchiveKey, Vec<u8>)> {
    wallet
        .archive
        .records
        .lock()
        .unwrap()
        .iter()
        .filter(|(key, _)| matches!(key, ArchiveKey::Checkpoint { .. } | ArchiveKey::Fold(_)))
        .map(|(key, bytes)| (*key, bytes.clone()))
        .collect()
}

/// An index-only ingest, as the direct-time and epoch ingests write it: a new direct anchor, a
/// new finality-epoch entry and the finality epoch `epoch` on the selected manifest, then the
/// scheduler's ingest signal. No fold field changes.
fn index_ingest(wallet: &mut Wallet, epoch: u8) {
    let (selected, mut manifest) = wallet.sync_manifest().unwrap();
    manifest.direct_anchors = manifest
        .direct_anchors
        .set(&mut wallet.archive, [epoch; 32], &[epoch])
        .unwrap();
    manifest.finality_epochs = manifest
        .finality_epochs
        .set(&mut wallet.archive, [epoch ^ 0x80; 32], &[epoch])
        .unwrap();
    manifest.finality_epoch = Some(u64::from(epoch));
    wallet.publish_manifest(selected, &manifest).unwrap();
    wallet.scheduler().ingest();
}

/// Deploy-pipeline §7.4 test 1 at the coordinator: each sub-proof is handed the marker its
/// predecessor's checkpoint publication left; the first one runs cold and the Ω leaves nothing.
#[test]
fn a_warm_chain_hands_each_sub_proof_its_predecessors_marker() {
    let mut w = bootstrapped(4);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    assert_eq!(
        w.proofs.last_handed(),
        None,
        "a step's first sub-proof is cold"
    );
    for ordinal in 1..4 {
        let left = w.proofs.last_left();
        assert_eq!(
            (left.sequence, left.checkpoints),
            (0, usize::try_from(ordinal - 1).unwrap())
        );
        assert_eq!(w.fold_once().unwrap(), checkpoint(ordinal));
        assert_eq!(w.proofs.last_handed(), Some(left));
    }
    let left = w.proofs.last_left();
    assert!(holds(&w));
    assert_eq!(w.fold_once().unwrap(), FoldStatus::Folded(0));
    assert_eq!(w.proofs.last_handed(), Some(left));
    assert!(!holds(&w), "the Ω retains nothing");
    assert_eq!(w.fold_once().unwrap(), FoldStatus::CaughtUp);
    // The host turn hands over the same way.
    let mut w = bootstrapped(3);
    for ordinal in 0..3 {
        let left = (ordinal > 0).then(|| w.proofs.last_left());
        let proved = prepared(&mut w).prove().unwrap();
        assert_eq!(w.proofs.last_handed(), left);
        assert_eq!(w.fold_publish(proved).unwrap().status, checkpoint(ordinal));
    }
}

/// Synthesis condition 8 with the same mock entropy: warm and all-cold folds leave the same
/// durable records, byte for byte.
#[test]
fn warm_and_all_cold_folds_leave_identical_durable_records() {
    let mut warm = bootstrapped(4);
    while warm.fold_once().unwrap() != FoldStatus::Folded(0) {}
    assert_eq!(durable(&warm), durable(&all_cold(4)));
}

/// Deploy-pipeline §7.4 tests 6, 7 and 9, and reviews G6 and K10: a payment, inactivity,
/// cancellation or close between or during sub-proofs leaves the next prepare cold; an
/// ingest-class change of the selected manifest does not.
#[test]
fn priority_inactivity_cancellation_and_close_leave_the_next_prepare_cold() {
    let mut w = bootstrapped(6);
    let scheduler = w.scheduler();
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    // A payment between sub-proofs: the slot is empty when payment() returns, so payment
    // proving and its capacity check never run beside retained fold state.
    let payment = scheduler.payment();
    assert!(!holds(&w), "empty when payment() returns");
    drop(payment);
    assert_eq!(w.fold_once().unwrap(), checkpoint(1));
    assert_eq!(w.proofs.last_handed(), None);
    // An ingest-class change of the selected manifest keeps the slot.
    let left = w.proofs.last_left();
    let (selected, mut manifest) = w.sync_manifest().unwrap();
    manifest.finality_epoch = Some(7);
    w.publish_manifest(selected, &manifest).unwrap();
    scheduler.ingest();
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(w.proofs.last_handed(), Some(left));
    // Leaving both activity states.
    scheduler.set_activity(false, false);
    assert!(!holds(&w));
    scheduler.set_activity(true, false);
    assert_eq!(w.fold_once().unwrap(), checkpoint(3));
    assert_eq!(w.proofs.last_handed(), None);
    // Cancelling the proof itself drops what its prepare took.
    let job = prepared(&mut w);
    assert!(w.proofs.last_handed().is_some());
    scheduler.set_activity(false, false);
    assert!(matches!(job.prove(), Err(Error::Cancelled)));
    scheduler.set_activity(true, false);
    assert!(!holds(&w));
    assert_eq!(w.fold_once().unwrap(), checkpoint(4));
    assert_eq!(w.proofs.last_handed(), None);
    // Close.
    assert!(holds(&w));
    scheduler.close();
    assert!(!holds(&w));
    assert_eq!(w.fold_once().unwrap(), FoldStatus::Idle);
}

/// Deploy-pipeline §7.4 tests 2, 3 and 5: a tampered durable checkpoint is refused by the
/// chain check on a warm turn too; an adopted interrupted publication and a restarted owner
/// both resume cold from the durable list, and the step completes.
#[test]
fn tamper_adoption_and_restart_resume_cold_from_the_durable_list() {
    let mut w = bootstrapped(5);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    assert_eq!(w.fold_once().unwrap(), checkpoint(1));
    // Tampering is never accepted: every turn re-chains the durable list first.
    let key = ArchiveKey::Checkpoint {
        sequence: 0,
        ordinal: 0,
    };
    let original = w.archive.records.lock().unwrap()[&key].clone();
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    w.archive.records.lock().unwrap().insert(key, tampered);
    let selected = w.custody.checkpoint.clone();
    assert!(matches!(w.fold_once(), Err(Error::WitnessLost(_))));
    assert_eq!(w.custody.checkpoint, selected, "nothing published");
    w.archive.records.lock().unwrap().insert(key, original);
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(
        w.proofs.last_handed(),
        None,
        "a failed turn dropped the retained state"
    );
    // An interrupted publication is adopted byte for byte; the next sub-proof is cold.
    let interrupted = w.custody.checkpoint.clone();
    assert_eq!(w.fold_once().unwrap(), checkpoint(3));
    w.custody.checkpoint = interrupted;
    let folds = w.proofs.folds.load(Ordering::SeqCst);
    assert_eq!(w.fold_once().unwrap(), checkpoint(3));
    assert_eq!(
        w.proofs.folds.load(Ordering::SeqCst),
        folds,
        "adopted, not proved"
    );
    assert!(!holds(&w), "adoption drops the retained state");
    assert_eq!(w.fold_once().unwrap(), checkpoint(4));
    assert_eq!(w.proofs.last_handed(), None);
    // A restarted owner shares no scheduler: it resumes cold and completes.
    let (custody, archive, proofs, scheme, wallet_id) =
        (w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id);
    let mut w = Coordinator::new(custody, archive, proofs, scheme, wallet_id).unwrap();
    w.scheduler().set_activity(true, false);
    assert_eq!(w.fold_once().unwrap(), FoldStatus::Folded(0));
    assert_eq!(w.proofs.last_handed(), None);
}

/// C12 regression 1: F2 starts after F1 released, evicts F1's pending marker, runs cold and
/// publishes first. F1's discarded publication neither clears F2's marker nor revives its own.
#[test]
fn f2_publishes_before_f1_and_f1_cleanup_keeps_f2s_retention() {
    let mut w = bootstrapped(4);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    let f1 = prepared(&mut w).prove().unwrap();
    let stale_marker = w.proofs.last_left();
    assert!(holds(&w), "F1's marker is parked as its slot is released");
    assert_eq!(w.fold_once().unwrap(), checkpoint(1));
    assert_eq!(
        w.proofs.last_handed(),
        None,
        "a pending marker is evicted, never resumed"
    );
    let newer_marker = w.proofs.last_left();
    assert_ne!(newer_marker.mark, stale_marker.mark);
    assert!(matches!(w.fold_publish(f1), Err(Error::Cancelled)));
    assert!(holds(&w), "F1's cleanup kept F2's marker");
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(w.proofs.last_handed(), Some(newer_marker));
}

/// C12 regression 2 and review G6a/K10a: a payment begins and ends between F1's release and
/// its publication. F1 still publishes but retains nothing; the next sub-proof is cold, and
/// the durable records equal an all-cold run.
#[test]
fn f1_payment_between_release_and_publication_prevents_its_retention() {
    let mut w = bootstrapped(4);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    let f1 = prepared(&mut w).prove().unwrap();
    let payment = w.scheduler().payment();
    assert!(
        !holds(&w),
        "the payment took the parked marker before it returned"
    );
    drop(payment);
    assert_eq!(w.fold_publish(f1).unwrap().status, checkpoint(1));
    assert!(!holds(&w), "the overlapped turn is never resurrected");
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(w.proofs.last_handed(), None);
    while w.fold_once().unwrap() != FoldStatus::Folded(0) {}
    assert_eq!(durable(&w), durable(&all_cold(4)));
}

/// C12 regression 3: after that payment, F2 runs cold, retains and publishes before F1's
/// cleanup; F1's discarded publication keeps F2's marker.
#[test]
fn f2_retains_after_that_payment_before_f1_cleanup() {
    let mut w = bootstrapped(4);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    let f1 = prepared(&mut w).prove().unwrap();
    drop(w.scheduler().payment());
    assert_eq!(w.fold_once().unwrap(), checkpoint(1));
    assert_eq!(w.proofs.last_handed(), None);
    let newer_marker = w.proofs.last_left();
    assert!(matches!(w.fold_publish(f1), Err(Error::Cancelled)));
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(w.proofs.last_handed(), Some(newer_marker));
}

/// C12 regression 4: an abandoned F1 publication (the host drops the proved job after a
/// custody refusal or a closed owner) and a publication refused because custody left its
/// released head each drop only F1's own marker; a newer attempt's marker survives.
#[test]
fn f1_abandoned_or_custody_refused_publication_drops_only_its_own_retention() {
    let mut w = bootstrapped(8);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    // Abandoned.
    drop(prepared(&mut w).prove().unwrap());
    assert!(!holds(&w));
    assert_eq!(w.fold_once().unwrap(), checkpoint(1));
    assert_eq!(w.proofs.last_handed(), None);
    // Refused: custody left its released head before the publication.
    let f1 = prepared(&mut w).prove().unwrap();
    let released = w.custody.status.clone();
    let SlotStatus::Released(record) = released.clone() else {
        panic!("a released head");
    };
    let before = durable(&w);
    w.custody.status = SlotStatus::Pending(record);
    // Pending custody discards a completed sub-proof; the next prepare parks until
    // the selected payment finishes. No checkpoint or retained value is promoted.
    assert!(matches!(w.fold_publish(f1), Err(Error::Cancelled)));
    assert_eq!(durable(&w), before);
    w.custody.status = released;
    assert!(!holds(&w));
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(w.proofs.last_handed(), None);
    // Abandoned and refused after a newer attempt retained.
    for abandon in [true, false] {
        let f1 = prepared(&mut w).prove().unwrap();
        let ordinal = match w.fold_once().unwrap() {
            FoldStatus::Checkpoint { ordinal, .. } => ordinal,
            other => panic!("unexpected fold status {other:?}"),
        };
        assert_eq!(
            w.proofs.last_handed(),
            None,
            "F1's pending marker was evicted"
        );
        let newer_marker = w.proofs.last_left();
        let before = durable(&w);
        if abandon {
            drop(f1);
        } else {
            let released = w.custody.status.clone();
            let SlotStatus::Released(record) = released.clone() else {
                panic!("a released head");
            };
            w.custody.status = SlotStatus::Pending(record);
            assert!(matches!(w.fold_publish(f1), Err(Error::Cancelled)));
            w.custody.status = released;
        }
        assert_eq!(durable(&w), before);
        assert!(holds(&w), "the newer marker survives");
        assert_eq!(w.fold_once().unwrap(), checkpoint(ordinal + 1));
        assert_eq!(w.proofs.last_handed(), Some(newer_marker));
    }
}

/// Review T8 and K14 at the coordinator: a direct-anchor and a finality-epoch insertion
/// between two warm sub-proofs is an ingest that keeps the slot, and the native key leaves
/// those insert-once index roots out; an issued Request enters only through payment priority,
/// which drops it. The fold records equal an all-cold run.
#[test]
fn index_ingests_keep_retention_and_payment_priority_drops_it() {
    let mut w = bootstrapped(4);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    let left = w.proofs.last_left();
    index_ingest(&mut w, 1);
    assert_eq!(w.fold_once().unwrap(), checkpoint(1));
    assert_eq!(
        w.proofs.last_handed(),
        Some(left),
        "index ingests keep the warm path"
    );
    // An issued Request enters only through `request()`, under payment priority.
    drop(w.scheduler().payment());
    assert_eq!(w.fold_once().unwrap(), checkpoint(2));
    assert_eq!(w.proofs.last_handed(), None);
    while w.fold_once().unwrap() != FoldStatus::Folded(0) {}
    assert_eq!(fold_records(&w), fold_records(&all_cold(4)));
}

/// Review T8 and K14 under B20: the same index-only ingest while a warm sub-proof proves
/// without the wallet owner, and while its released value waits for the publication. Neither
/// cancels the proof or touches the slot; the publication rebases onto the ingest as a
/// checkpoint and promotes the value, the next sub-proof is handed exactly that job's marker,
/// and the fold records equal an all-cold run.
#[test]
fn index_ingests_during_the_unlocked_proof_keep_retention_and_the_publication_rebases() {
    let mut w = bootstrapped(4);
    assert_eq!(w.fold_once().unwrap(), checkpoint(0));
    for (ordinal, during_proof) in [(1, true), (3, false)] {
        let left = w.proofs.last_left();
        let job = prepared(&mut w);
        assert_eq!(w.proofs.last_handed(), Some(left), "a warm sub-proof");
        if during_proof {
            // The job holds the background slot and no wallet owner.
            index_ingest(&mut w, ordinal);
        }
        let proved = job.prove().expect("an ingest never cancels the proof");
        let marker = w.proofs.last_left();
        assert!(holds(&w), "parked as the background slot is released");
        if !during_proof {
            index_ingest(&mut w, ordinal);
        }
        assert_eq!(
            w.fold_publish(proved).unwrap().status,
            checkpoint(u32::from(ordinal))
        );
        let (_, manifest) = w.sync_manifest().unwrap();
        assert_eq!(
            (manifest.finality_epoch, manifest.checkpoint_count),
            (Some(u64::from(ordinal)), u32::from(ordinal) + 1),
            "the publication rebased onto the ingest"
        );
        assert!(holds(&w), "its checkpoint promoted the value");
        let next = w.fold_once().unwrap();
        assert_eq!(
            w.proofs.last_handed(),
            Some(marker),
            "exactly that job's marker"
        );
        if ordinal == 1 {
            assert_eq!(next, checkpoint(2));
        } else {
            assert_eq!(next, FoldStatus::Folded(0));
        }
    }
    assert_eq!(fold_records(&w), fold_records(&all_cold(4)));
}

/// Deploy-pipeline §7.4 test 10 at the coordinator: the warm terminal turn verifies its new Ω
/// exactly once, before any credit, pending-map, archive or manifest effect. When that single
/// verification fails, nothing at all was written; the failed turn also dropped the retained
/// state, so the retry runs cold and verifies once.
#[test]
fn the_warm_terminal_verifies_its_omega_once_before_any_effect() {
    let mut w = bootstrapped(3);
    for ordinal in 0..3 {
        assert_eq!(w.fold_once().unwrap(), checkpoint(ordinal));
    }
    let left = w.proofs.last_left();
    let records = w.archive.records.lock().unwrap().clone();
    let selected = w.custody.checkpoint.clone();
    let verifies = w.proofs.verifies.load(Ordering::SeqCst);
    w.proofs.reject = true;
    assert!(matches!(w.fold_once(), Err(Error::Proof(_))));
    assert_eq!(
        w.proofs.last_handed(),
        Some(left),
        "the terminal turn ran warm"
    );
    assert_eq!(w.proofs.verifies.load(Ordering::SeqCst), verifies + 1);
    assert_eq!(
        *w.archive.records.lock().unwrap(),
        records,
        "no credit, pending-map or archive effect"
    );
    assert_eq!(w.custody.checkpoint, selected, "no manifest effect");
    w.proofs.reject = false;
    let verifies = w.proofs.verifies.load(Ordering::SeqCst);
    assert_eq!(w.fold_once().unwrap(), FoldStatus::Folded(0));
    assert_eq!(w.proofs.last_handed(), None);
    assert_eq!(w.proofs.verifies.load(Ordering::SeqCst), verifies + 1);
}
