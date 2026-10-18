//! Structural projection controls; these tests deliberately grant no finality authority.

use super::*;
use crate::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    isi::{
        AtomicSettlementEscrows, AtomicSettlementMovement, AtomicSettlementMovements, SettlementId,
    },
    transaction::{
        FeeChargeLimit, FeePaymentIntent, TransactionBuilder,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;
use std::num::NonZeroU64;

fn projection_fixture(pipeline_gas: bool) -> (SettleAtomic, BlockHeader, TransactionEntrypoint) {
    let signer = KeyPair::from_seed(vec![71; 32], Algorithm::Ed25519);
    let payer = AccountId::new(signer.public_key().clone());
    let recipient = AccountId::new(
        KeyPair::from_seed(vec![72; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let asset: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap();
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"projection only",
    )));
    let intent = SettleAtomic::new(
        network,
        SettlementId::new(payer.clone(), "projection_reference".parse().unwrap()),
        AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
            source: AssetId::with_scope(asset.clone(), payer.clone(), AssetBalanceScope::Global),
            recipient,
            quantity: Quantity::from(42_u32),
        }])
        .unwrap(),
        AtomicSettlementEscrows::empty(),
        NonZeroU64::new(200).unwrap(),
        Metadata::default(),
    );
    let limits = if pipeline_gas {
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset,
            Quantity::from(2_u32),
        )]
    } else {
        Vec::new()
    };
    let tx = TransactionBuilder::new(network, payer, FeePaymentIntent::authority(limits, None))
        .with_instructions([SettlementInstructionBox::Atomic(intent.clone())])
        .sign(signer.private_key());
    let header = BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(*network.as_genesis_hash()),
        None,
        1000,
        0,
    );
    (intent, header, TransactionEntrypoint::External(tx))
}

#[test]
fn atomic_payment_projection_preserves_exact_terms_but_grants_no_header_authenticity() {
    let (intent, mut header, entrypoint) = projection_fixture(false);
    let result = TransactionResult::new(Ok(Vec::new()));
    let receipt = project_atomic_payment_receipt_unverified(
        intent.network_id,
        &intent,
        &header,
        &entrypoint,
        &result,
    )
    .unwrap();
    assert_eq!(receipt.block_hash, header.hash());
    assert_eq!(receipt.block_height, 2);
    assert_eq!(receipt.executed_at_ms, 1000);
    let SettlementDetails::Atomic(details) = receipt.details else {
        panic!("atomic receipt")
    };
    assert_eq!(details.intent_hash, intent.intent_hash().unwrap());
    assert_eq!(details.movements, intent.movements.resolve().unwrap());
    assert!(result.nexus_fee_receipt().is_none());
    // The helper accepts unauthenticated DTOs by design; only its callers can authenticate this header.
    header.creation_time_ms += 1;
    let unverified = project_atomic_payment_receipt_unverified(
        intent.network_id,
        &intent,
        &header,
        &entrypoint,
        &result,
    )
    .unwrap();
    assert_eq!(unverified.executed_at_ms, 1001);
    assert_ne!(unverified.block_hash, receipt.block_hash);
}

#[test]
fn atomic_payment_projection_refuses_rejection_different_terms_network_and_unsupported_fees() {
    let (intent, header, entrypoint) = projection_fixture(false);
    let rejected = TransactionResult::new(Err(TransactionRejectionReason::LimitCheck(
        TransactionLimitError {
            reason: "rejected source".to_owned(),
        },
    )));
    assert!(matches!(
        project_atomic_payment_receipt_unverified(
            intent.network_id,
            &intent,
            &header,
            &entrypoint,
            &rejected
        ),
        Err(AtomicPaymentProjectionError::RejectedExecution)
    ));
    let result = TransactionResult::new(Ok(Vec::new()));
    let mut changed = intent.clone();
    changed.expires_at_height = NonZeroU64::new(201).unwrap();
    assert!(matches!(
        project_atomic_payment_receipt_unverified(
            intent.network_id,
            &changed,
            &header,
            &entrypoint,
            &result
        ),
        Err(AtomicPaymentProjectionError::IntentMismatch)
    ));
    changed = intent.clone();
    changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign network",
    )));
    assert!(matches!(
        project_atomic_payment_receipt_unverified(
            changed.network_id,
            &changed,
            &header,
            &entrypoint,
            &result
        ),
        Err(AtomicPaymentProjectionError::NetworkMismatch)
    ));
    let (intent, header, entrypoint) = projection_fixture(true);
    assert!(matches!(
        project_atomic_payment_receipt_unverified(
            intent.network_id,
            &intent,
            &header,
            &entrypoint,
            &result
        ),
        Err(AtomicPaymentProjectionError::UnsupportedFeeOutcome)
    ));
}
