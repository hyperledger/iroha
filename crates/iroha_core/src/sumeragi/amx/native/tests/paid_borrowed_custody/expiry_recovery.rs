//! Exact Global Decision recovery at the final tip, across reader and node restart.

use super::*;
use crate::query::native_receipts::{
    NativeAmxExpiryDecisionCursorV1, NativeAmxExpiryDecisionPollV1,
    VerifiedNativeAmxExpiryDecisionV1, expire_amx_relay, expiry_amx_decision,
};

fn finish<V: StateReadOnly>(
    view: &V,
    intent: &crate::query::native_receipts::NativeAmxRelayIntentV1,
    cursor: &mut NativeAmxExpiryDecisionCursorV1,
) -> Option<VerifiedNativeAmxExpiryDecisionV1> {
    let mut read = expiry_amx_decision(view, intent, cursor).unwrap();
    for _ in 0..100_000 {
        match read.poll().unwrap() {
            NativeAmxExpiryDecisionPollV1::Pending => {}
            NativeAmxExpiryDecisionPollV1::Complete(value) => return value,
        }
    }
    panic!("bounded AMX fixture acquisition must terminate");
}

#[test]
fn native_amx_expiry_recovery_authenticates_final_decision_after_restart_and_rechecks_cached_positive()
 {
    let mut roots = paid_roots();
    let mut transaction = roots.transaction(100, 0xD8);
    transaction.deadline = roots.global.height() + 8;
    transaction.expires_at_ms = 6_000;
    roots.approve_all(&transaction);
    // Give the foreign private history the same height using real owner approval work
    // before the final Begin. The negative control must fail its source join, not merely
    // because that unrelated root has not reached the selected height yet.
    let revoke = roots.participants[0].sign(
        &payer(),
        [iroha_data_model::isi::Revoke::account_permission(
            roots.approval(0, &transaction).permission().unwrap(),
            account(&payer()),
        )
        .into()],
        2_599,
    );
    assert_eq!(roots.participants[0].commit_at(2_600, vec![revoke]), [true]);
    roots.approve(0, &transaction, account(&payer()), 2_700);
    let tx = transaction.id().unwrap();
    let begin_height = roots.global.height() + 1;
    let begin = paid_global_sign(&roots.global, [BeginAmxV1 { transaction }.into()], 2_999);
    assert_eq!(roots.global.commit_at(3_000, vec![begin]), [true]);
    let intent = expire_amx_relay(&roots.global.state().view(), begin_height, tx)
        .unwrap()
        .complete()
        .unwrap();
    let mut cursor = NativeAmxExpiryDecisionCursorV1::default();
    {
        let view = roots.global.state().view();
        assert!(
            finish(&view, &intent, &mut cursor).is_none(),
            "a final unresolved Begin is not a fabricated Abort or terminal absence"
        );
    }
    assert!(cursor.matches_intent(&intent));
    assert_eq!(cursor.positive_height(), None);
    assert!(roots.participants[0].height() >= begin_height);
    assert!(
        expiry_amx_decision(&roots.participants[0].state().view(), &intent, &mut cursor).is_err(),
        "a child root cannot authenticate the Global expiry decision"
    );
    let (_, expiry) = intent.into_parts();
    let carrier = paid_global_sign(&roots.global, [expiry], 5_999);
    assert_eq!(roots.global.commit_at(6_000, vec![carrier]), [true]);
    let final_height = roots.global.height();
    let final_hash = roots.global.committed(final_height).block().hash();
    assert_eq!(
        roots
            .global
            .committed(final_height)
            .block()
            .network_entrypoints()
            .len(),
        1,
        "only funded expiry business work follows the final Begin"
    );

    let mut restarted = CertifiedTestChain::start(paid_global_config()).unwrap();
    restarted.replay_from(&roots.global).unwrap();
    let budget = restarted.state().ivm_execution_budget();
    budget.with_deferred_refund_notifications(|_| {
        let view = restarted.state().view();
        let intent = expire_amx_relay(&view, begin_height, tx).unwrap().complete().unwrap();
        let decision = finish(&view, &intent, &mut cursor).expect(
            "certified final-tip Abort must suppress a replacement expiry after relay/node restart");
        assert_eq!(decision.transaction(), tx);
        assert_eq!(decision.outcome(), AmxOutcomeV1::Abort);
        assert_eq!(decision.height(), final_height);
        assert_eq!(decision.carrier(), final_hash);
        assert_eq!(decision.timestamp_ms(), 6_000);
        assert_eq!(decision.source(), intent.descriptor());
        assert_eq!(cursor.positive_height(), Some(final_height));
        let limit = budget.limit_bytes();
        budget.set_limit_bytes(0);
        {
            let mut read = expiry_amx_decision(&view, &intent, &mut cursor).unwrap();
            assert!(read.poll().is_err(),
                "cached positive height must reauthenticate original proof before suppressing a carrier");
        }
        budget.set_limit_bytes(limit);
        let again = finish(&view, &intent, &mut cursor).unwrap();
        assert_eq!(again.carrier(), final_hash);
        assert_eq!(restarted.height(), final_height);
    });
}
