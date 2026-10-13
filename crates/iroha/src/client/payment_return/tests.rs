//! Exact linked full-return controls with independent native certificates.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    block::{BlockSignatures, builder::BlockBuilder},
    query::CommittedTransaction,
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
    transaction::{
        TransactionBuilder,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use std::time::Duration;

fn evidence(block: &iroha_data_model::block::SignedBlock) -> CommittedTransaction {
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[index as usize].clone();
    CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(index).unwrap(),
        output,
    }
}
fn original() -> (NativeFinalityFixture, VerifiedPaymentReceipt) {
    let (native, intent, transaction) =
        super::super::verified_payment::payment_operation_fixture_for_testing(false);
    let verified = native
        .verifier()
        .verify_retained_decision(native.latest())
        .unwrap();
    let receipt = VerifiedPaymentReceipt::verify(
        &verified,
        native.network_id(),
        transaction.hash(),
        &intent,
        evidence(verified.block()),
    )
    .unwrap();
    (native, receipt)
}
fn certified_reverse(
    native: &mut NativeFinalityFixture,
    intent: &SettleAtomic,
    rejected: bool,
) -> Result<VerifiedPaymentReceipt, super::super::PaymentReceiptVerificationError> {
    let key = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519);
    let header = native.next_header();
    let mut builder = TransactionBuilder::new(
        native.network_id(),
        intent.settlement_id.owner().clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::SettlementInstructionBox::Atomic(
        intent.clone(),
    )]);
    builder.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let transaction = builder.sign(key.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction.clone());
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(
        &mut block,
        vec![if rejected {
            Err(TransactionRejectionReason::LimitCheck(
                TransactionLimitError {
                    reason: "reverse rejected".into(),
                },
            ))
        } else {
            Ok(Vec::new())
        }],
    );
    let proof = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&proof).unwrap();
    VerifiedPaymentReceipt::verify(
        &verified,
        native.network_id(),
        transaction.hash(),
        intent,
        evidence(verified.block()),
    )
}
fn request(original: VerifiedPaymentReceipt) -> NativePaymentFullReturnRequest {
    NativePaymentFullReturnRequest::new(
        original,
        NonZeroU64::new(100).unwrap(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .unwrap()
}
#[test]
fn native_payment_full_return_identity_is_canonical_and_original_stays_successful() {
    let (mut native, original) = original();
    let original_receipt = original.settlement().clone();
    let first = request(original.clone());
    let independent = request(original.clone());
    let link_json = norito::json::to_json(first.link()).unwrap();
    assert_eq!(
        norito::json::from_str::<NativePaymentReturnLink>(&link_json).unwrap(),
        *first.link()
    );
    let wire: norito::json::Value = norito::json::from_json(&link_json).unwrap();
    let expected_network: norito::json::Value =
        norito::json::from_json(&norito::json::to_json(&original.network()).unwrap()).unwrap();
    assert_eq!(wire.get("original_network"), Some(&expected_network));
    assert!(wire.get("network").is_none());
    assert!(
        norito::json::from_str::<NativePaymentReturnLink>(
            &link_json.replace("\"original_network\":", "\"network\":")
        )
        .is_err(),
        "the signed metadata has one field name, with no Rust-name alias"
    );
    assert_eq!(first.settlement_id(), independent.settlement_id());
    assert_eq!(first.payment().intent(), independent.payment().intent());
    let original_move = match &original.settlement().details {
        SettlementDetails::Atomic(details) => &details.movements.as_slice()[0],
        _ => unreachable!(),
    };
    assert_eq!(
        first.settlement_id().owner(),
        original_move.destination.account()
    );
    let reverse = certified_reverse(&mut native, first.payment().intent(), false).unwrap();
    let linked = first.verify_return(reverse.clone()).unwrap();
    independent.verify_return(reverse).unwrap();
    assert_eq!(linked.original().settlement(), &original_receipt);
    assert_eq!(
        linked.original().transaction_hash(),
        original.transaction_hash()
    );
    assert_ne!(
        linked.reverse().transaction_hash(),
        original.transaction_hash()
    );
    assert!(linked.original().evidence().result().is_ok());
    assert!(linked.reverse().evidence().result().is_ok());
}
#[test]
fn native_payment_full_return_rejects_changed_link_amount_and_bucket() {
    for change in 0..3 {
        let (mut native, original) = original();
        let expected = request(original);
        let mut intent = expected.payment().intent().clone();
        if change == 0 {
            intent.metadata = Metadata::default();
        } else {
            let details = intent.movements.resolve().unwrap();
            let movement = &details.as_slice()[0];
            intent.movements =
                AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
                    source: movement.source.clone(),
                    recipient: if change == 2 {
                        iroha_data_model::account::AccountId::new(
                            KeyPair::from_seed(vec![49; 32], Algorithm::Ed25519)
                                .public_key()
                                .clone(),
                        )
                    } else {
                        movement.destination.account().clone()
                    },
                    quantity: if change == 1 {
                        1_u32.into()
                    } else {
                        movement.quantity.clone()
                    },
                }])
                .unwrap();
        }
        let reverse = certified_reverse(&mut native, &intent, false).unwrap();
        assert!(expected.verify_return(reverse).is_err());
    }
}
#[test]
fn native_payment_full_return_requires_independently_successful_reverse_execution() {
    let (mut native, original) = original();
    let expected = request(original);
    assert!(certified_reverse(&mut native, expected.payment().intent(), true).is_err());
    assert!(expected.verify_return(expected.original().clone()).is_err());
}
