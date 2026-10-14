//! Coordinator-boundary Omega verification counts per operation and fold turn.
//!
//! `TestProofs` stands in for native proving, so these count only the coordinator's own
//! `NativeProofs::verify_lineage` calls: recorded-Omega reads and the completion checks of
//! `fold_once`. The installed native owner's verification inside preparation and the fold
//! worker is counted by `kagemusha_wallet_proofs_v1::verification_counts`. The values are the
//! 2026-10-15 baseline and act as ceilings: an optimization may lower them, never raise them.

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
    assert!(
        bootstrap_turns[3] <= 2,
        "completion check and recorded-Omega read"
    );
    assert_eq!(
        receive_commit, 0,
        "the just-folded predecessor Omega is reused"
    );
    assert!(receive_turns[..3].iter().all(|count| *count == 0));
    assert!(
        receive_turns[3] <= 2,
        "completion check and recorded-Omega read"
    );
    assert_eq!(caught_up, 0);
    assert_eq!(lineage_operation_warm, 0, "the just-folded Omega is reused");
    assert!(reopen <= 1, "one recorded-Omega read when the owner opens");
    assert_eq!(
        lineage_operation_after_restart, 0,
        "the Omega verified at open is reused"
    );
}
