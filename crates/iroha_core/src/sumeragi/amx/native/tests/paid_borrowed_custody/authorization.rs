//! An authenticated unrelated Global request cannot supply a bank's debit consent.
//!
//! This uses a relay custodian holding the bank debit key, so the
//! ordinary source-owner check passes; the missing independent approval is the only
//! expected rejection. No simulated execution output or supplied committee is used.

use super::*;
use crate::query::native_receipts::begin_amx_relay;

#[test]
fn native_amx_unrelated_begin_cannot_create_bank_debit_consent() {
    let mut roots = paid_roots();
    let transaction = roots.transaction(100, 0xD7);
    let tx = transaction.id().unwrap();
    let unrelated = KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519);
    assert_ne!(account(&unrelated), account(&payer()));
    assert_ne!(account(&unrelated), account(&receiver()));
    let mut request = TransactionBuilder::new(
        roots.global.network_id(),
        account(&unrelated),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset(),
                GLOBAL_FEE.into(),
            )],
            None,
        ),
    );
    request.set_creation_time(Duration::from_millis(2_999));
    let request = request
        .with_instructions([BeginAmxV1 { transaction }])
        .sign(unrelated.private_key());
    assert_eq!(roots.global.commit_at(3_000, vec![request]), vec![true]);
    let final_source_height = roots.global.height();
    let intent = {
        let view = roots.global.state().view();
        let mut read = begin_amx_relay(&view, final_source_height, tx, FIRST).unwrap();
        read.complete().unwrap()
    };
    assert_eq!(
        intent.descriptor().target_network(),
        roots.participants[0].network_id()
    );
    assert!(native(&roots.participants[0]).escrows.is_empty());
    assert_eq!(
        balance(
            &roots.participants[0],
            FIRST,
            principal(),
            account(&payer())
        ),
        Quantity::from(1_000_u32),
    );
    // This is precisely the service's current action: it signs the independently
    // authenticated Begin's arbitrary requested terms using its configured bank key.
    // There has been no local owner-issued, exact-intent permission transaction.
    let (_, instruction) = intent.into_parts();
    let relay = roots.participants[0].sign(&payer(), [instruction], 3_999);
    let outcomes = roots.participants[0].commit_at(4_000, vec![relay]);
    assert_eq!(
        outcomes,
        vec![false],
        "authenticated unrelated Begin must not manufacture the bank's exact-intent debit consent",
    );
    assert!(native(&roots.participants[0]).escrows.is_empty());
    assert_eq!(
        balance(
            &roots.participants[0],
            FIRST,
            principal(),
            account(&payer())
        ),
        Quantity::from(1_000_u32),
        "unapproved principal remains with the original bank payer",
    );
    assert_eq!(roots.global.height(), final_source_height);
}

#[test]
fn native_amx_exact_owner_grant_revocation_and_separate_relay_preserve_settlement() {
    use iroha_data_model::isi::Revoke;

    let mut roots = Roots::new();
    let transaction = roots.transaction(100, 0xD8);
    let tx = transaction.id().unwrap();
    let approval = roots.approval(0, &transaction);
    let permission = approval.permission().unwrap();
    let typed: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::amx::CanPrepareAmx {
            approval: approval.clone(),
        }
        .into();
    assert_eq!(
        typed, permission,
        "model and executor share the one permission layout"
    );
    assert_ne!(account(&payer()), account(&receiver()));

    let carrier = roots.participants[0].sign(
        &receiver(),
        [Grant::account_permission(permission.clone(), account(&receiver())).into()],
        1_999,
    );
    assert_eq!(
        roots.participants[0].commit_at(2_000, vec![carrier]),
        vec![false],
        "an unapproved relay cannot issue the debit owner's exact consent"
    );
    let mut foreign = approval.clone();
    foreign.participant_instance[0] ^= 1;
    let carrier = roots.participants[0].sign(
        &payer(),
        [Grant::account_permission(foreign.permission().unwrap(), account(&receiver())).into()],
        2_099,
    );
    assert_eq!(
        roots.participants[0].commit_at(2_100, vec![carrier]),
        vec![false],
        "even an owner grant must name the exact immutable local bank root"
    );
    roots.approve(0, &transaction, account(&receiver()), 2_200);
    roots.approve(1, &transaction, account(&payer()), 2_200);
    let carrier = roots.participants[0].sign(
        &receiver(),
        [Grant::account_permission(permission.clone(), account(&payer())).into()],
        2_299,
    );
    assert_eq!(
        roots.participants[0].commit_at(2_300, vec![carrier]),
        vec![false],
        "holding an exact AMX debit permission never permits redelegation"
    );
    let carrier = roots.participants[0].sign(
        &receiver(),
        [Revoke::account_permission(permission.clone(), account(&receiver())).into()],
        2_399,
    );
    assert_eq!(
        roots.participants[0].commit_at(2_400, vec![carrier]),
        vec![false],
        "only the original debit owner may revoke its approval"
    );

    let signed = roots.global.sign(
        &global_config().genesis_key,
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
    let prepare = |roots: &Roots| {
        begin
            .try_copy(&roots.global.state().ivm_execution_budget())
            .unwrap()
            .into_prepare(FIRST, &transaction)
            .complete(&roots.global.state().ivm_execution_budget())
            .unwrap()
    };
    let carrier = roots.participants[0].sign(
        &payer(),
        [Revoke::account_permission(permission.clone(), account(&receiver())).into()],
        3_199,
    );
    assert_eq!(
        roots.participants[0].commit_at(3_200, vec![carrier]),
        vec![true]
    );
    let carrier = roots.participants[0].sign(&receiver(), [prepare(&roots)], 3_499);
    assert_eq!(
        roots.participants[0].commit_at(3_500, vec![carrier]),
        vec![false],
        "revocation before Prepare must prevent escrow despite the same authenticated Begin"
    );
    assert!(native(&roots.participants[0]).escrows.is_empty());
    roots.approve(0, &transaction, account(&receiver()), 3_600);
    let carrier = roots.participants[0].sign(&receiver(), [prepare(&roots)], 3_999);
    assert_eq!(
        roots.participants[0].commit_at(4_000, vec![carrier]),
        vec![true],
        "an exact current owner grant lets a separate fee relay prepare the debit"
    );
    let first = crate::query::native_receipts::amx_record_proof(
        &roots.participants[0].state().view(),
        roots.participants[0].height(),
        AmxRecordKind::Prepared,
        tx,
    )
    .complete()
    .unwrap()
    .unwrap();
    let second = roots.prepare(1, &transaction, &begin);
    let decision = roots.decide([first, second], tx);
    let carrier = roots.participants[0].sign(
        &payer(),
        [Revoke::account_permission(permission, account(&receiver())).into()],
        5_499,
    );
    assert_eq!(
        roots.participants[0].commit_at(5_500, vec![carrier]),
        vec![true]
    );
    let carrier = roots.participants[0].sign(
        &receiver(),
        [decision
            .into_settle(FIRST)
            .complete(&roots.global.state().ivm_execution_budget())
            .unwrap()],
        5_999,
    );
    assert_eq!(
        roots.participants[0].commit_at(6_000, vec![carrier]),
        vec![true],
        "revocation after Yes must not strand the original committed escrow"
    );
    assert_eq!(
        balance(
            &roots.participants[0],
            FIRST,
            principal(),
            account(&receiver())
        ),
        Quantity::from(100_u32)
    );
}
