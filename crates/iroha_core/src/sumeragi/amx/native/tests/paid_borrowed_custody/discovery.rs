//! Real retained-history discovery across ordinary blocks, pruning and final-tip restart.

use super::*;
use crate::query::native_receipts::amx_relays;
use iroha_data_model::isi::sumeragi_amx::{PrepareAmxV1, SettleAmxV1};

fn intent_path_at(chain: &CertifiedTestChain, height: u64) -> std::path::PathBuf {
    chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{height:020}-{}.ami",
            hex::encode(chain.committed(height).block().hash().as_ref())
        ))
}

#[test]
fn native_amx_discovery_advances_ordinary_global_height_then_delivers_both_final_tip_decisions() {
    let (roots, restored, tx, begin_height) = restarted_paid_decision();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let baseline = budget.reserved_bytes();
        let view = restored.state().view();
        assert!(
            !intent_path_at(&restored, 2).exists(),
            "ordinary certified H2 has no AMX coordinates"
        );
        assert!(
            amx_relays(&view, 2)
                .unwrap()
                .complete_next()
                .unwrap()
                .is_none()
        );
        let mut begin = amx_relays(&view, begin_height).unwrap();
        for participant in [FIRST, SECOND] {
            let intent = begin.complete_next().unwrap().unwrap();
            let prepare = intent
                .instruction()
                .as_any()
                .downcast_ref::<PrepareAmxV1>()
                .unwrap();
            assert_eq!(prepare.dataspace, participant);
            assert_eq!(prepare.transaction.id().unwrap(), tx);
            assert_eq!(intent.descriptor().source_height(), begin_height);
        }
        assert!(begin.complete_next().unwrap().is_none());
        drop(begin);
        let mut discovery = amx_relays(&view, restored.height()).unwrap();
        let first = discovery.complete_next().unwrap().unwrap();
        let second = discovery.complete_next().unwrap().unwrap();
        assert!(discovery.complete_next().unwrap().is_none());
        for (intent, participant) in [&first, &second].into_iter().zip(&roots.participants) {
            assert_eq!(intent.descriptor().source_height(), restored.height());
            assert_eq!(
                intent.descriptor().target_network(),
                participant.network_id()
            );
            assert_eq!(instruction_decision(intent.instruction()).record.tx(), tx);
            assert!(intent.instruction().amx_proof_admitted_to(&budget));
        }
        assert_ne!(
            first.descriptor().target_network(),
            second.descriptor().target_network()
        );
        drop(discovery);
        drop(first);
        drop(second);
        drop(view);
        assert_eq!(budget.reserved_bytes(), baseline);
    });
}

#[test]
fn native_amx_discovery_advances_ordinary_private_height_and_refuses_missing_required_frame() {
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0xB1);
    let tx = transaction.id().unwrap();
    let signed = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: transaction.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    let begin = crate::query::native_receipts::amx_record_proof(
        &roots.global.state().view(),
        roots.global.height(),
        AmxRecordKind::Begin,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let ordinary = roots.participants[0].sign(
        &payer(),
        [Transfer::asset_quantity(
            AssetId::with_scope(
                principal(),
                account(&payer()),
                AssetBalanceScope::Dataspace(FIRST),
            ),
            1_u32,
            account(&receiver()),
        )
        .into()],
        2_499,
    );
    assert_eq!(
        roots.participants[0].commit_at(2_500, vec![ordinary]),
        vec![true]
    );
    let prepared = roots.prepare(0, &transaction, &begin);
    let mut restored = CertifiedTestChain::start(private_config(&roots.global, FIRST)).unwrap();
    restored.replay_from(&roots.participants[0]).unwrap();
    let budget = restored.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let baseline = budget.reserved_bytes();
        let view = restored.state().view();
        assert_eq!(restored.height(), 3);
        assert!(!intent_path_at(&restored, 2).exists());
        assert!(
            amx_relays(&view, 2)
                .unwrap()
                .complete_next()
                .unwrap()
                .is_none()
        );
        let path = intent_path_at(&restored, 3);
        let hidden = path.with_extension("held");
        std::fs::rename(&path, &hidden).unwrap();
        let mut discovery = amx_relays(&view, 3).unwrap();
        let refused = discovery.complete_next();
        std::fs::rename(&hidden, &path).unwrap();
        assert!(
            refused.is_err(),
            "a positive certified count cannot turn missing .ami into no work"
        );
        let intent = discovery.complete_next().unwrap().unwrap();
        assert_eq!(
            instruction_relay(intent.instruction()),
            prepared.canonical()
        );
        assert_eq!(intent.descriptor().source_height(), 3);
        assert!(discovery.complete_next().unwrap().is_none());
        drop(discovery);
        drop(intent);
        drop(view);
        assert_eq!(budget.reserved_bytes(), baseline);
    });
}

#[test]
fn native_amx_discovery_retains_abort_begin_locator_after_global_pruning_and_restart() {
    let mut roots = paid_roots();
    let mut transaction = roots.transaction(100, 0xB2);
    transaction.deadline = roots.global.height() + 2;
    let tx = transaction.id().unwrap();
    let begin_height = roots.global.height() + 1;
    let signed = paid_global_sign(&roots.global, [BeginAmxV1 { transaction }.into()], 2_999);
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), vec![true]);
    // Real authorized fee funding transactions advance this pruning control. They are
    // test input, not an idle liveness mechanism or manufactured empty blocks.
    for timestamp in [4_000, 5_000] {
        let signed = paid_global_sign(
            &roots.global,
            [Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(
                    fee_asset(),
                    account(&global_config().genesis_key),
                    AssetBalanceScope::Global,
                ),
            )
            .into()],
            timestamp - 1,
        );
        assert_eq!(roots.global.commit_at(timestamp, vec![signed]), vec![true]);
    }
    let decision_height = roots.global.height();
    assert!(
        roots
            .global
            .state()
            .view()
            .world()
            .sumeragi_amx()
            .transaction(&tx)
            .is_none()
    );
    let mut restored = CertifiedTestChain::start(paid_global_config()).unwrap();
    restored.replay_from(&roots.global).unwrap();
    assert_eq!(restored.height(), decision_height);
    assert_eq!(
        std::fs::read(intent_path_at(&restored, decision_height)).unwrap(),
        std::fs::read(intent_path_at(&roots.global, decision_height)).unwrap()
    );
    let view = restored.state().view();
    assert!(view.world().sumeragi_amx().transaction(&tx).is_none());
    let mut discovery = amx_relays(&view, decision_height).unwrap();
    for id in [FIRST, SECOND] {
        let intent = discovery.complete_next().unwrap().unwrap();
        let instruction = intent
            .instruction()
            .as_any()
            .downcast_ref::<SettleAmxV1>()
            .unwrap();
        assert_eq!(instruction.dataspace, id);
        assert!(
            matches!(&instruction.decision.record, AmxRecordV1::Decision(decision)
            if decision.tx == tx && decision.outcome == AmxOutcomeV1::Abort)
        );
        assert_eq!(intent.descriptor().source_height(), decision_height);
        assert_eq!(begin_height, 4);
    }
    assert!(discovery.complete_next().unwrap().is_none());
    assert_eq!(
        restored.height(),
        decision_height,
        "no successor needed for final decision delivery"
    );
}
