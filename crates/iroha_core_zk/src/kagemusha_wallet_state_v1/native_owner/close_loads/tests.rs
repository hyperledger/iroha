//! Durable closure publication with explicit mock relation authority and real control signatures.
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{
    MemoryArchive, TestCustody, TestProofs, bootstrap, field, frozen, signer, wallet,
};
use p256::ecdsa::{Signature, signature::Signer as _};
type Wallet = Coordinator<TestCustody, MemoryArchive, TestProofs>;
// The explicit mock relation leaves all original/map commitments unchanged. Retain the
// same authenticated descriptor before committing; never weaken the production lookup.
fn commit_preserving_source(wallet: &mut Wallet, next: FrozenTransition) {
    let (_, manifest) = wallet.manifest().unwrap();
    let previous = wallet
        .indexed_step(&manifest, manifest.indexed.unwrap())
        .unwrap();
    let source = wallet.source_custody(&manifest, &previous).unwrap();
    source
        .require(&mut wallet.archive, &next.capsule.successor_state)
        .unwrap();
    wallet
        .retain_source_custody(next.capsule.capsule_digest().unwrap(), &source)
        .unwrap();
    wallet.commit(next).unwrap();
}
fn retiring() -> Wallet {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    w.scheduler().set_activity(true, false);
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let step = w.released_steps().unwrap().remove(0);
    let fold = w.read_fold(&step).unwrap().unwrap();
    let mut next = frozen(Some(&boot), KagemushaWalletEffectV1::Retiring);
    let c = &mut next.capsule;
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: fold.record.lineage.clone(),
    };
    c.statement.lineage_burned_total = fold.record.lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = fold.record.lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    next.validate().unwrap();
    commit_preserving_source(&mut w, next);
    w
}
fn output(plan: &Plan) -> Vec<u8> {
    let body = plan.body().unwrap();
    let raw: Signature = signer(&plan.credential).sign(&body.signing_message());
    let control = KagemushaWalletLedgerControlV1::sign(
        body,
        &plan.credential.body.payment_key,
        KagemushaWalletSignerOutputV1::Raw(raw.to_bytes().into()),
    )
    .unwrap();
    KagemushaWalletCloseLoadsV1 {
        version: 1,
        control,
        credential: plan.credential,
        package: plan.package.clone(),
        certificates: plan.certificates.clone(),
    }
    .to_canonical_bytes()
    .unwrap()
}
#[test]
fn closure_uses_released_retiring_source_and_rejects_active_or_rebound_originals() {
    let mut active = wallet();
    active.commit(bootstrap()).unwrap();
    assert!(active.close_loads_plan([1; 32]).is_err());
    let (_, manifest) = active.manifest().unwrap();
    assert!(
        manifest
            .close_loads
            .get(&mut active.archive, &[1; 32])
            .unwrap()
            .is_none()
    );
    let mut w = retiring();
    let plan = w.close_loads_plan([1; 32]).unwrap();
    let (_, manifest) = w.manifest().unwrap();
    assert_eq!(plan.capsule, manifest.capsule);
    assert_eq!(plan.package.statement.sequence, manifest.indexed.unwrap());
    let body = plan.body().unwrap();
    assert!(matches!(
        body.action,
        KagemushaWalletLedgerControlActionV1::CloseLoads { next_load: 0, .. }
    ));
    let bytes = output(&plan);
    plan.output(&bytes).unwrap();
    let mut altered = plan.clone();
    altered.nonce = [6; 32];
    assert!(altered.output(&bytes).is_err());
    altered = plan.clone();
    altered.capsule = field(7);
    assert!(altered.require(&w.scheme_id, &w.wallet_id).is_err());
    altered = plan.clone();
    altered.package.statement.next_load += 1;
    assert!(altered.output(&bytes).is_err());
    assert!(plan.require(&field(4), &w.wallet_id).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(w.finish_close_loads(&plan, &trailing).is_err());
}
#[test]
fn closure_uncertainty_restart_and_later_head_preserve_exact_selected_output() {
    for after in [false, true] {
        let mut w = retiring();
        let plan = w.close_loads_plan([1; 32]).unwrap();
        let bytes = output(&plan);
        w.custody.fail_publication = Some(after);
        assert!(w.finish_close_loads(&plan, &bytes).is_err());
        let mut w =
            Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id).unwrap();
        let selected = w.close_loads_plan([1; 32]).unwrap();
        assert_eq!(selected.nonce, plan.nonce);
        if !after {
            w.finish_close_loads(&selected, &bytes).unwrap();
        }
        let selected = w.close_loads_plan([1; 32]).unwrap();
        assert_eq!(
            w.retained_close_loads(&selected).unwrap(),
            Some(bytes.clone())
        );
        // Explicit mock relation permits a later test step; production lifecycle restrictions
        // remain in native preparation. The journal must never replace this older exact output.
        let (_, manifest) = w.manifest().unwrap();
        let pred = w.indexed_step(&manifest, 1).unwrap();
        w.commit(frozen(
            Some(&pred.frozen),
            KagemushaWalletEffectV1::Load {
                load_ordinal: 0,
                receipt_digest: field(31),
                amount: 1,
                online_charge: 0,
            },
        ))
        .unwrap();
        let later = w.close_loads_plan([1; 32]).unwrap();
        assert_eq!(later.capsule, plan.capsule);
        assert_eq!(later.nonce, plan.nonce);
        assert_eq!(w.retained_close_loads(&later).unwrap(), Some(bytes));
        assert!(w.finish_close_loads(&plan, &output(&plan)).is_err());
        w.archive
            .remove(ArchiveKey::Object(later.output.unwrap()))
            .unwrap();
        assert!(matches!(
            w.retained_close_loads(&later),
            Err(Error::WitnessLost(_))
        ));
    }
}

fn rebind(value: &mut FrozenTransition) {
    let c = &mut value.capsule;
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    value.validate().unwrap();
}
#[test]
fn preissued_load_then_complete_consumer_can_select_new_closure_and_replay_both_attempts() {
    let mut w = retiring();
    let first = w.close_loads_plan([1; 32]).unwrap();
    let first_bytes = output(&first);
    w.finish_close_loads(&first, &first_bytes).unwrap();
    // The first next_load=0 cannot close a ledger that has already issued ordinal0.
    assert!(matches!(
        first.body().unwrap().action,
        KagemushaWalletLedgerControlActionV1::CloseLoads { next_load: 0, .. }
    ));
    let (_, manifest) = w.manifest().unwrap();
    let previous = w.indexed_step(&manifest, 1).unwrap();
    let mut load = frozen(
        Some(&previous.frozen),
        KagemushaWalletEffectV1::Load {
            load_ordinal: 0,
            receipt_digest: field(31),
            amount: 1,
            online_charge: 0,
        },
    );
    load.capsule.statement.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    load.capsule.successor_state.core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    rebind(&mut load);
    commit_preserving_source(&mut w, load.clone());
    assert!(
        w.close_loads_plan([2; 32]).is_err(),
        "Load alone is not a complete lineage consumer"
    );
    while !matches!(w.fold_once().unwrap(), FoldStatus::CaughtUp) {}
    let (_, manifest) = w.manifest().unwrap();
    let loaded = w.indexed_step(&manifest, 2).unwrap();
    let fold = w.read_fold(&loaded).unwrap().unwrap();
    let mut unload = frozen(
        Some(&load),
        KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&w.scheme_id, &w.wallet_id, 0),
            redeem_ordinal: 0,
            amount: 1,
            online_charge: 0,
            charge_quote: [0; 32],
        },
    );
    let c = &mut unload.capsule;
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: fold.record.lineage.clone(),
    };
    c.statement.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    c.successor_state.core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
    c.statement.lineage_burned_total = fold.record.lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = fold.record.lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    rebind(&mut unload);
    commit_preserving_source(&mut w, unload);
    let second = w.close_loads_plan([2; 32]).unwrap();
    assert!(matches!(
        second.body().unwrap().action,
        KagemushaWalletLedgerControlActionV1::CloseLoads { next_load: 1, .. }
    ));
    assert_ne!(second.capsule, first.capsule);
    let second_bytes = output(&second);
    w.finish_close_loads(&second, &second_bytes).unwrap();
    let mut w = Coordinator::new(w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id).unwrap();
    let first = w.close_loads_plan([1; 32]).unwrap();
    let second = w.close_loads_plan([2; 32]).unwrap();
    assert_eq!(w.retained_close_loads(&first).unwrap(), Some(first_bytes));
    assert_eq!(w.retained_close_loads(&second).unwrap(), Some(second_bytes));
}
