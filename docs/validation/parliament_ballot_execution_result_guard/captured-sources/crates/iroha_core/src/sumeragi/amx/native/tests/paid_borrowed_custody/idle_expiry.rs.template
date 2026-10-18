//! Funded final-payment closure must remain discoverable without a successor block.
//!
//! It tests source work discovery, not a claim of end-to-end signed-time qualification.

use super::*;
use crate::query::native_receipts::{NativeAmxRelaySourceV1, amx_record_proof, amx_relays};
use iroha_data_model::sumeragi_amx::amx_record_witness_key;

#[test]
fn native_amx_final_pending_begin_discovers_funded_global_closure_after_idle_restart() {
    let mut roots = paid_roots();
    let mut transaction = roots.transaction(100, 0xD7);
    // Begin at b, one actual healthy Yes relay at d=b+1. The other participant is silent.
    transaction.deadline = roots.global.height() + 2;
    transaction.expires_at_ms = 6_000;
    roots.approve_all(&transaction);
    let silent_height = roots.participants[1].height();
    let tx = transaction.id().unwrap();
    let begin_height = roots.global.height() + 1;
    let begin_carrier = paid_global_sign(
        &roots.global,
        [BeginAmxV1 {
            transaction: transaction.clone(),
        }
        .into()],
        2_999,
    );
    assert_eq!(
        roots.global.commit_at(3_000, vec![begin_carrier]),
        vec![true]
    );
    let begin = amx_record_proof(
        &roots.global.state().view(),
        begin_height,
        AmxRecordKind::Begin,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let healthy_yes = roots.prepare(0, &transaction, &begin);
    let relay = healthy_yes
        .into_relay()
        .complete(&roots.participants[0].state().ivm_execution_budget())
        .unwrap();
    let relay_carrier = paid_global_sign(&roots.global, [relay], 4_999);
    assert_eq!(
        roots.global.commit_at(5_000, vec![relay_carrier]),
        vec![true]
    );
    assert_eq!(roots.global.height(), transaction.deadline);
    global_paid_images(&roots.global, 4);
    for height in [begin_height, roots.global.height()] {
        assert!(
            roots
                .global
                .committed(height)
                .block()
                .external_signed_transaction_at(1)
                .is_none(),
            "only the exact Begin/Yes carriers may advance the payment; no fixture clock input"
        );
    }
    assert_eq!(
        roots.participants[1].height(),
        silent_height,
        "silent participant commits no payment input after its independent authorization"
    );
    let held = native(&roots.participants[0]);
    assert_eq!(held.escrows.len(), 1);
    assert_eq!(held.escrows[0].tx, tx);
    assert_eq!(held.escrows[0].settled, None);
    assert_eq!(
        balance(
            &roots.participants[0],
            FIRST,
            principal(),
            account(&payer())
        ),
        900_u32.into()
    );
    assert_eq!(
        balance(&roots.participants[0], FIRST, principal(), held.custody),
        100_u32.into()
    );

    // Original signed history reconstructs the final pending obligation. There is no successor.
    let mut restarted = CertifiedTestChain::start(paid_global_config()).unwrap();
    restarted.replay_from(&roots.global).unwrap();
    let tip = restarted.height();
    let tip_hash = restarted.committed(tip).block().hash();
    let view = restarted.state().view();
    let pending = view.world().sumeragi_amx().transaction(&tx).unwrap();
    assert!(pending.decided.is_none());
    assert_eq!(pending.yes.len(), 1);
    assert!(
        amx_record_proof(&view, tip, AmxRecordKind::Decision, tx)
            .complete()
            .unwrap()
            .is_none(),
        "an idle clock is not Abort authority"
    );

    let mut discovery = amx_relays(&view, begin_height).unwrap();
    let mut closure = None;
    let mut participants = 0;
    while let Some(intent) = discovery.complete_next().unwrap() {
        let source = intent.descriptor();
        if source.source()
            != (NativeAmxRelaySourceV1::Record {
                key: amx_record_witness_key(AmxRecordKind::Begin, tx),
            })
        {
            continue;
        }
        if source.target_scope() == SumeragiRootScope::Global {
            assert_eq!(source.source_network(), restarted.network_id());
            assert_eq!(source.target_network(), restarted.network_id());
            assert_eq!(source.source_height(), begin_height);
            assert_eq!(
                source.source_carrier(),
                restarted.committed(begin_height).block().hash()
            );
            assert_eq!(source.target_instance(), restarted.instance().0);
            closure = Some(intent);
        } else {
            participants += 1;
        }
    }
    assert_eq!(
        participants, 2,
        "the existing Begin still offers both real participant preparations"
    );
    assert_eq!(restarted.height(), tip);
    assert_eq!(restarted.committed(tip).block().hash(), tip_hash);
    assert_eq!(native(&roots.participants[0]).escrows[0].settled, None);
    assert!(
        closure.is_some(),
        "the final unresolved Begin must provide an authenticated funded Global closure carrier without a successor or unrelated traffic"
    );
}
