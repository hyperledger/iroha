//! Paid signed-time expiry closes a final native Yes escrow through a certified Abort.

use super::*;
use crate::query::native_receipts::{amx_record_proof, expire_amx_relay};
use iroha_data_model::sumeragi_amx::AmxDecisionV1;

fn locked_principal(roots: &Roots, transaction: [u8; 32]) {
    let chain = &roots.participants[0];
    let state = native(chain);
    assert_eq!(state.escrows.len(), 1);
    assert_eq!(state.escrows[0].tx, transaction);
    assert_eq!(state.escrows[0].settled, None);
    assert_eq!(
        balance(chain, FIRST, principal(), account(&payer())),
        900_u32.into()
    );
    assert_eq!(
        balance(chain, FIRST, principal(), state.custody),
        100_u32.into()
    );
    assert_eq!(
        balance(chain, FIRST, principal(), account(&receiver())),
        Quantity::zero()
    );
}

#[test]
fn native_amx_signed_time_expiry_requires_due_global_abort_before_releasing_final_yes() {
    fn control(early_attempt: bool) {
        let mut roots = paid_roots();
        let mut transaction = roots.transaction(100, if early_attempt { 0xD9 } else { 0xDA });
        transaction.deadline = roots.global.height() + 20;
        transaction.expires_at_ms = 7_000;
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
        assert_eq!(roots.global.commit_at(3_000, vec![begin_carrier]), [true]);
        let begin = amx_record_proof(
            &roots.global.state().view(),
            begin_height,
            AmxRecordKind::Begin,
            tx,
        )
        .complete()
        .unwrap()
        .unwrap();
        let yes = roots.prepare(0, &transaction, &begin);
        let relay = yes
            .into_relay()
            .complete(&roots.participants[0].state().ivm_execution_budget())
            .unwrap();
        let carrier = paid_global_sign(&roots.global, [relay], 4_999);
        assert_eq!(roots.global.commit_at(5_000, vec![carrier]), [true]);
        global_paid_images(&roots.global, 4);
        locked_principal(&roots, tx);
        assert_eq!(roots.participants[1].height(), silent_height);

        // A restarted Global reader has only actual payment work, with the final Yes at its tip.
        let mut restarted = CertifiedTestChain::start(paid_global_config()).unwrap();
        restarted.replay_from(&roots.global).unwrap();
        let prepare_height = roots.participants[0].height();
        let final_pending = restarted.height();
        let pending_hash = restarted.committed(final_pending).block().hash();
        let expiry = |chain: &CertifiedTestChain| {
            let intent = expire_amx_relay(&chain.state().view(), begin_height, tx)
                .unwrap()
                .complete()
                .unwrap();
            assert_eq!(
                intent.descriptor().ready_at_ms(),
                Some(transaction.expires_at_ms)
            );
            assert_eq!(intent.descriptor().source_height(), begin_height);
            intent.into_parts().1
        };
        // Discovery is not a local-clock authorization to release participant custody.
        let _ready = expiry(&restarted);
        assert_eq!(restarted.height(), final_pending);
        assert_eq!(
            restarted.committed(final_pending).block().hash(),
            pending_hash
        );
        assert_eq!(roots.participants[0].height(), prepare_height);
        locked_principal(&roots, tx);
        let mut paid = 4;
        if early_attempt {
            let carrier = paid_global_sign(&restarted, [expiry(&restarted)], 6_998);
            assert_eq!(
                restarted.commit_at(6_999, vec![carrier]),
                [false],
                "a signed-time expiry carrier cannot decide Abort one millisecond early"
            );
            paid += 1;
            global_paid_images(&restarted, paid);
            let view = restarted.state().view();
            assert!(
                view.world()
                    .sumeragi_amx()
                    .transaction(&tx)
                    .unwrap()
                    .decided
                    .is_none()
            );
            assert!(
                amx_record_proof(&view, restarted.height(), AmxRecordKind::Decision, tx)
                    .complete()
                    .unwrap()
                    .is_none()
            );
            locked_principal(&roots, tx);
        }
        // The early-rejection branch respects the next canonical cadence; the other hits
        // the exact exclusive signed-time boundary with height expiry still far away.
        let timestamp_ms = if early_attempt { 7_500 } else { 7_000 };
        assert!(restarted.height() + 1 < transaction.deadline);
        let carrier = paid_global_sign(&restarted, [expiry(&restarted)], timestamp_ms - 1);
        assert_eq!(
            restarted.commit_at(timestamp_ms, vec![carrier]),
            [true],
            "signed time alone must authorize the funded Abort before the height deadline"
        );
        paid += 1;
        global_paid_images(&restarted, paid);
        let decided_height = restarted.height();
        let decided_hash = restarted.committed(decided_height).block().hash();
        assert!(decided_height < transaction.deadline);
        let abort = amx_record_proof(
            &restarted.state().view(),
            decided_height,
            AmxRecordKind::Decision,
            tx,
        )
        .complete()
        .unwrap()
        .unwrap();
        assert!(matches!(&abort.canonical().record,
            AmxRecordV1::Decision(AmxDecisionV1 { tx: actual, outcome: AmxOutcomeV1::Abort }) if *actual == tx));
        locked_principal(&roots, tx);

        let fee_before = balance(
            &roots.participants[0],
            FIRST,
            fee_asset(),
            account(&payer()),
        );
        let instruction = abort
            .into_settle(FIRST)
            .complete(&restarted.state().ivm_execution_budget())
            .unwrap();
        let signed = roots.participants[0].sign(&payer(), [instruction], timestamp_ms + 999);
        assert_eq!(
            roots.participants[0].commit_at(timestamp_ms + 1_000, vec![signed]),
            [true]
        );
        let chain = &roots.participants[0];
        let state = native(chain);
        assert_eq!(state.escrows[0].settled, Some(AmxOutcomeV1::Abort));
        assert_eq!(
            balance(chain, FIRST, principal(), account(&payer())),
            1_000_u32.into()
        );
        assert_eq!(
            balance(chain, FIRST, principal(), state.custody),
            Quantity::zero()
        );
        assert_eq!(
            balance(chain, FIRST, principal(), account(&receiver())),
            Quantity::zero()
        );
        assert!(
            balance(chain, FIRST, fee_asset(), account(&payer())) < fee_before,
            "actual participant Abort settlement pays its authenticated native fee"
        );
        assert_eq!(roots.participants[1].height(), silent_height);
        assert_eq!(restarted.height(), decided_height);
        assert_eq!(
            restarted.committed(decided_height).block().hash(),
            decided_hash,
            "the final Abort needs no successor or unrelated transaction to release escrow"
        );
        for height in begin_height..=decided_height {
            assert_eq!(
                restarted
                    .committed(height)
                    .block()
                    .network_entrypoints()
                    .len(),
                1,
                "each post-setup Global block contains only its real payment carrier"
            );
        }
        let mut restored = CertifiedTestChain::start(paid_global_config()).unwrap();
        restored.replay_from(&restarted).unwrap();
        assert_eq!(restored.height(), decided_height);
        assert!(
            amx_record_proof(
                &restored.state().view(),
                decided_height,
                AmxRecordKind::Decision,
                tx
            )
            .complete()
            .unwrap()
            .is_some()
        );
    }
    let thread = crate::sumeragi::threads::sumeragi_thread_builder("native-amx-signed-expiry")
        .spawn(|| {
            control(true);
            control(false);
        })
        .unwrap();
    if let Err(original) = thread.join() {
        std::panic::resume_unwind(original);
    }
}
