//! SDK trust-boundary controls with genuine native QCs over synthetic execution outputs.
//! These fixtures verify receipt authentication, not World execution or network qualification.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    block::{
        BlockSignatures, SignedBlock,
        builder::BlockBuilder,
        consensus::{NexusFeeScheduleInputs, NexusFeeSettlementV1},
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        output_budget::ExecutionOutputLimits,
    },
    isi::{
        AtomicSettlementEscrows, AtomicSettlementMovement, AtomicSettlementMovements,
        InstructionBox, Log, SettlementInstructionBox,
    },
    level::Level,
    nexus::{AxtPolicySnapshot, FeeDebitSource},
    sumeragi_finality::{SumeragiFinalityVerifier, test_fixtures::NativeFinalityFixture},
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, TransactionBuilder, TransactionResult,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use iroha_model_base::{
    metadata::Metadata,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::{json::Json, numeric::Quantity};
use std::{num::NonZeroU64, time::Duration};

struct Fixture {
    native: NativeFinalityFixture,
    verified: VerifiedSumeragiBlock,
    intent: SettleAtomic,
    transaction: SignedTransaction,
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

#[derive(Clone, Copy)]
enum FixtureOutcome {
    Applied,
    Rejected,
}

fn fixture(outcome: FixtureOutcome, charged: bool, pipeline_gas: bool, composite: bool) -> Fixture {
    fixture_with_transaction_network(outcome, charged, pipeline_gas, composite, None)
}

fn fixture_with_transaction_network(
    outcome: FixtureOutcome,
    charged: bool,
    pipeline_gas: bool,
    composite: bool,
    transaction_network: Option<NetworkId>,
) -> Fixture {
    let mut native = NativeFinalityFixture::start("sdk-verified-native-payment");
    let mut authenticator = native.verifier();
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let authority = AccountId::new(signer.public_key().clone());
    let asset: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap();
    let mut metadata = Metadata::default();
    metadata.insert(
        "payment_reference".parse().unwrap(),
        Json::new("invoice-250000"),
    );
    let intent = SettleAtomic::new(
        native.network_id(),
        SettlementId::new(authority.clone(), "sdk_payment_250000".parse().unwrap()),
        AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
            source: AssetId::with_scope(
                asset.clone(),
                authority.clone(),
                AssetBalanceScope::Global,
            ),
            recipient: account(42),
            quantity: Quantity::from(250_000_u32),
        }])
        .unwrap(),
        AtomicSettlementEscrows::empty(),
        NonZeroU64::new(100).unwrap(),
        metadata,
    );
    let mut fee_limits = Vec::new();
    if charged {
        fee_limits.push(FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::from(10_u32),
        ));
    }
    if pipeline_gas {
        fee_limits.push(FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset.clone(),
            Quantity::from(10_u32),
        ));
    }
    let mut instructions = vec![InstructionBox::from(SettlementInstructionBox::Atomic(
        intent.clone(),
    ))];
    if composite {
        instructions.push(Log::new(Level::INFO, "extra instruction".into()).into());
    }
    let header = native.next_header();
    let mut builder = TransactionBuilder::new(
        transaction_network.unwrap_or_else(|| native.network_id()),
        authority.clone(),
        FeePaymentIntent::authority(fee_limits, None),
    )
    .with_instructions(instructions);
    builder.set_creation_time(Duration::from_millis(header.creation_time_ms - 1));
    let transaction = builder.sign(signer.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction.clone());
    let mut block = builder.build(BlockSignatures::default());
    let mut result = TransactionResult::new(if matches!(outcome, FixtureOutcome::Rejected) {
        Err(TransactionRejectionReason::LimitCheck(
            TransactionLimitError {
                reason: "rejected payment fixture".into(),
            },
        ))
    } else {
        Ok(Vec::new())
    });
    if charged {
        result.set_nexus_fee_receipt(Some(NexusFeeReceipt {
            version: NexusFeeReceipt::VERSION,
            source_id: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
            dataspace_id: DataSpaceId::new(0),
            lane_id: LaneId::new(0),
            block_height: header.height().get(),
            debit_source: FeeDebitSource::Account(authority),
            fee_asset_id: asset,
            program_revision: None,
            lease_id: None,
            fee_amount: Quantity::from(2_u32),
            settlement: NexusFeeSettlementV1::Burn,
            schedule: NexusFeeScheduleInputs {
                tx_bytes_len: norito::canonical_frame_len(transaction.payload()).unwrap() as u64,
                instruction_count: 1,
                gas_used: 0,
                base_fee: Quantity::from(2_u32),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: Quantity::zero(),
                per_gas_unit_fee: Quantity::zero(),
            },
        }));
    }
    block
        .set_execution_outputs(
            vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result,
                completions: Vec::new(),
            })],
            0,
            std::collections::BTreeMap::default(),
            Vec::new(),
            AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &ExecutionOutputLimits {
                max_outputs: 16,
                max_output_bytes: 16 * 1024 * 1024,
                max_total_output_bytes: 32 * 1024 * 1024,
                max_executed_wire_bytes: 32 * 1024 * 1024,
            },
        )
        .unwrap();
    let proof = native.certify(block);
    let verified = authenticator.verify(&proof).unwrap();
    Fixture {
        native,
        verified,
        intent,
        transaction,
    }
}

fn evidence(block: &SignedBlock) -> CommittedTransaction {
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (output_index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    }
}

fn verify(
    fixture: &Fixture,
    evidence: CommittedTransaction,
) -> Result<VerifiedPaymentReceipt, PaymentReceiptVerificationError> {
    VerifiedPaymentReceipt::verify(
        &fixture.verified,
        fixture.native.network_id(),
        fixture.transaction.hash(),
        &fixture.intent,
        evidence,
    )
}

pub(super) fn payment_receipt() -> VerifiedPaymentReceipt {
    let fixture = fixture(FixtureOutcome::Applied, true, false, false);
    verify(&fixture, evidence(fixture.verified.block())).unwrap()
}

#[test]
fn recovered_payment_authenticates_original_carrier_from_independent_terms() {
    let original = fixture(FixtureOutcome::Applied, true, false, false);
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new(
        original.native.network_id(),
        original.transaction.authority().clone(),
        original.transaction.fee_payment_intent().clone(),
    )
    .with_instructions([SettlementInstructionBox::Atomic(original.intent.clone())]);
    builder.set_creation_time(original.transaction.creation_time() + Duration::from_millis(1));
    let fresh_carrier = builder.sign(signer.private_key());
    assert_ne!(fresh_carrier.hash(), original.transaction.hash());
    assert!(matches!(
        VerifiedPaymentReceipt::verify(
            &original.verified,
            original.native.network_id(),
            fresh_carrier.hash(),
            &original.intent,
            evidence(original.verified.block()),
        ),
        Err(PaymentReceiptVerificationError::TransactionMismatch)
    ));
    let recovered = VerifiedPaymentReceipt::verify_recovered(
        &original.verified,
        original.native.network_id(),
        &original.intent,
        evidence(original.verified.block()),
    )
    .unwrap();
    assert_eq!(recovered.transaction_hash(), original.transaction.hash());
    assert_eq!(recovered.settlement_id(), original.intent.settlement_id());
    assert_eq!(
        recovered.nexus_fee_receipt().unwrap().fee_amount,
        Quantity::from(2_u32)
    );

    let mut conflicting = original.intent.clone();
    conflicting.metadata.insert(
        "payment_reference".parse().unwrap(),
        Json::new("changed invoice"),
    );
    assert!(matches!(
        VerifiedPaymentReceipt::verify_recovered(
            &original.verified,
            original.native.network_id(),
            &conflicting,
            evidence(original.verified.block()),
        ),
        Err(PaymentReceiptVerificationError::IntentMismatch)
    ));
    let other = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"recovery foreign genesis",
    )));
    assert!(matches!(
        VerifiedPaymentReceipt::verify_recovered(
            &original.verified,
            other,
            &original.intent,
            evidence(original.verified.block()),
        ),
        Err(PaymentReceiptVerificationError::NetworkMismatch)
    ));
    let rejected = fixture(FixtureOutcome::Rejected, false, false, false);
    assert!(matches!(
        VerifiedPaymentReceipt::verify_recovered(
            &rejected.verified,
            rejected.native.network_id(),
            &rejected.intent,
            evidence(rejected.verified.block()),
        ),
        Err(PaymentReceiptVerificationError::Finality(_))
    ));
}

#[test]
fn verified_payment_at_final_tip_binds_exact_movements_and_authenticated_fee() {
    for charged in [false, true] {
        let fixture = fixture(FixtureOutcome::Applied, charged, false, false);
        assert_eq!(
            fixture.native.latest().height(),
            2,
            "no later block was authored"
        );
        let receipt = verify(&fixture, evidence(fixture.verified.block())).unwrap();
        assert_eq!(receipt.network(), fixture.native.network_id());
        assert_eq!(receipt.transaction_hash(), fixture.transaction.hash());
        assert_eq!(receipt.settlement_id(), fixture.intent.settlement_id());
        assert_eq!(receipt.context_id(), fixture.verified.context_id());
        assert_eq!(
            receipt.settlement().authority,
            *fixture.transaction.authority()
        );
        assert_eq!(receipt.settlement().metadata, fixture.intent.metadata);
        assert_eq!(receipt.settlement().block_height, 2);
        assert_eq!(
            receipt.settlement().block_hash,
            fixture.verified.header().hash()
        );
        assert_eq!(
            receipt.settlement().executed_at_ms,
            fixture.verified.header().creation_time_ms
        );
        let movement = receipt.settlement().details.movements().next().unwrap();
        assert_eq!(
            movement.source,
            fixture.intent.movements.as_slice()[0].source
        );
        assert_eq!(
            movement.destination,
            fixture.intent.movements.as_slice()[0].destination()
        );
        assert_eq!(movement.quantity, Quantity::from(250_000_u32));
        assert_eq!(
            receipt.nexus_fee_receipt(),
            receipt.evidence().result().nexus_fee_receipt()
        );
        assert_eq!(receipt.nexus_fee_receipt().is_some(), charged);
        if let Some(fee) = receipt.nexus_fee_receipt() {
            assert_eq!(fee.fee_amount, Quantity::from(2_u32));
        }
        // Persisted evidence must be decoded as data and independently checked again.
        let wire = norito::encode_canonical(receipt.evidence()).unwrap();
        let retained = norito::decode_canonical::<CommittedTransaction>(&wire).unwrap();
        assert_eq!(
            verify(&fixture, retained).unwrap().settlement(),
            receipt.settlement()
        );
    }
}

#[test]
fn included_rejection_and_forged_success_never_construct_payment_receipts() {
    let fixture = fixture(FixtureOutcome::Rejected, false, false, false);
    let mut included = evidence(fixture.verified.block());
    assert!(included.verify_inclusion_in_block(fixture.verified.block()));
    assert!(matches!(
        verify(&fixture, included.clone()),
        Err(PaymentReceiptVerificationError::Finality(_))
    ));
    let ExecutionOutputV1::Network(output) = &mut included.output else {
        unreachable!()
    };
    output.result.0 = Ok(Vec::new());
    included.output_hash = HashOf::new(&included.output);
    assert!(matches!(
        verify(&fixture, included),
        Err(PaymentReceiptVerificationError::Finality(_))
    ));
}

#[test]
fn independently_retained_identity_and_every_payment_term_are_required() {
    let fixture = fixture(FixtureOutcome::Applied, true, false, false);
    let verify_intent = |intent: &SettleAtomic| {
        VerifiedPaymentReceipt::verify(
            &fixture.verified,
            fixture.native.network_id(),
            fixture.transaction.hash(),
            intent,
            evidence(fixture.verified.block()),
        )
    };
    for field in 0..8 {
        let mut expected = fixture.intent.clone();
        let mut movements = expected.movements.as_slice().to_vec();
        match field {
            0 => expected.settlement_id.reference = "different_payment".parse().unwrap(),
            1 => movements[0].quantity = Quantity::from(250_001_u32),
            2 => movements[0].recipient = account(43),
            3 => movements[0].source.account = account(44),
            4 => movements[0].source.scope = AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
            5 => {
                movements[0].source.definition = AssetDefinitionId::from_uuid_bytes([
                    2, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
                ])
                .unwrap()
            }
            6 => {
                expected.metadata.insert(
                    "payment_reference".parse().unwrap(),
                    Json::new("different invoice"),
                );
            }
            7 => expected.expires_at_height = NonZeroU64::new(101).unwrap(),
            _ => unreachable!(),
        }
        expected.movements = AtomicSettlementMovements::try_from(movements).unwrap();
        let result = verify_intent(&expected);
        if field == 3 {
            assert!(matches!(
                result,
                Err(PaymentReceiptVerificationError::InvalidIntent(_))
            ));
        } else {
            assert!(
                matches!(result, Err(PaymentReceiptVerificationError::IntentMismatch)),
                "field {field}"
            );
        }
    }
    let other = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different authenticated genesis",
    )));
    let mut expected = fixture.intent.clone();
    expected.network_id = other;
    assert!(matches!(
        verify_intent(&expected),
        Err(PaymentReceiptVerificationError::NetworkMismatch)
    ));
    assert!(matches!(
        VerifiedPaymentReceipt::verify(
            &fixture.verified,
            other,
            fixture.transaction.hash(),
            &expected,
            evidence(fixture.verified.block()),
        ),
        Err(PaymentReceiptVerificationError::NetworkMismatch)
    ));
    assert!(matches!(
        VerifiedPaymentReceipt::verify(
            &fixture.verified,
            fixture.native.network_id(),
            HashOf::from_untyped_unchecked(Hash::new(b"different signed carrier")),
            &fixture.intent,
            evidence(fixture.verified.block()),
        ),
        Err(PaymentReceiptVerificationError::TransactionMismatch)
    ));
}

#[test]
fn changed_or_removed_fee_outcomes_fail_output_authentication() {
    let fixture = fixture(FixtureOutcome::Applied, true, false, false);
    for change in 0..4 {
        let mut substituted = evidence(fixture.verified.block());
        let ExecutionOutputV1::Network(output) = &mut substituted.output else {
            unreachable!()
        };
        let mut fee = output.result.nexus_fee_receipt().unwrap().clone();
        match change {
            0 => fee.fee_amount = Quantity::from(3_u32),
            1 => fee.debit_source = FeeDebitSource::Account(account(45)),
            2 => fee.source_id = [0; 32],
            3 => {}
            _ => unreachable!(),
        }
        output
            .result
            .set_nexus_fee_receipt((change != 3).then_some(fee));
        substituted.output_hash = HashOf::new(&substituted.output);
        assert!(matches!(
            verify(&fixture, substituted),
            Err(PaymentReceiptVerificationError::Finality(_))
        ));
    }
}

#[test]
fn composite_and_pipeline_gas_carriers_are_explicitly_unsupported() {
    let composite = fixture(FixtureOutcome::Applied, false, false, true);
    assert!(matches!(
        verify(&composite, evidence(composite.verified.block())),
        Err(PaymentReceiptVerificationError::UnsupportedCarrier)
    ));
    let gas = fixture(FixtureOutcome::Applied, false, true, false);
    assert!(matches!(
        verify(&gas, evidence(gas.verified.block())),
        Err(PaymentReceiptVerificationError::UnsupportedFeeOutcome)
    ));
}

#[test]
fn structural_proof_and_private_root_do_not_authorize_global_payment_receipts() {
    let fixture = fixture(FixtureOutcome::Applied, false, false, false);
    // A fresh verifier cannot skip its independently authenticated genesis prefix.
    let mut unadvanced = SumeragiFinalityVerifier::new(
        fixture.native.genesis(),
        fixture.native.chain_id(),
        fixture.native.genesis_proof().committee.clone(),
    )
    .unwrap();
    assert!(unadvanced.verify(fixture.native.latest()).is_err());
    let mut private = NativeFinalityFixture::start_with_scope(
        "payment-private-root",
        SumeragiRootScope::Dataspace {
            parent_network_id: fixture.native.network_id(),
            dataspace_id: DataSpaceId::new(7),
        },
    );
    let mut authenticator = private.verifier();
    let block = private.block_with_submitted_work(private.next_header());
    let proof = private.certify(block);
    let verified = authenticator.verify(&proof).unwrap();
    let mut expected = fixture.intent.clone();
    expected.network_id = private.network_id();
    assert!(matches!(
        VerifiedPaymentReceipt::verify(
            &verified,
            private.network_id(),
            fixture.transaction.hash(),
            &expected,
            evidence(verified.block()),
        ),
        Err(PaymentReceiptVerificationError::WrongRootScope)
    ));
}

pub(super) fn payment_operation_fixture(
    rejected: bool,
) -> (NativeFinalityFixture, SettleAtomic, SignedTransaction) {
    let outcome = if rejected {
        FixtureOutcome::Rejected
    } else {
        FixtureOutcome::Applied
    };
    let fixture = fixture(outcome, true, false, false);
    (fixture.native, fixture.intent, fixture.transaction)
}

#[test]
fn payment_execution_authenticates_rejection_without_granting_success() {
    let fixture = fixture(FixtureOutcome::Rejected, true, false, false);
    let original = evidence(fixture.verified.block());
    fixture
        .verified
        .verify_transaction_execution(&fixture.native.network_id(), &original)
        .unwrap();
    assert!(
        fixture
            .verified
            .verify_committed_transaction(&fixture.native.network_id(), &original)
            .is_err()
    );
    let mut altered = original.clone();
    let iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output) =
        &mut altered.output
    else {
        panic!("network output");
    };
    output.result = TransactionResult::new(Err(TransactionRejectionReason::LimitCheck(
        TransactionLimitError {
            reason: "changed rejection".into(),
        },
    )));
    assert!(
        fixture
            .verified
            .verify_transaction_execution(&fixture.native.network_id(), &altered)
            .is_err()
    );
    let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different independently selected genesis",
    )));
    assert_ne!(foreign, fixture.native.network_id());
    assert!(
        fixture
            .verified
            .verify_transaction_execution(&foreign, &original)
            .is_err()
    );
}

#[test]
fn payment_execution_does_not_close_a_foreign_network_carrier() {
    let transaction_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"foreign signed transaction network"),
    ));
    let fixture = fixture_with_transaction_network(
        FixtureOutcome::Rejected,
        false,
        false,
        false,
        Some(transaction_network),
    );
    let original = evidence(fixture.verified.block());
    // The signature and rejected input/output are genuinely authenticated in this
    // block, but that chain cannot close the carrier on its intended network.
    assert_ne!(fixture.native.network_id(), transaction_network);
    assert_eq!(fixture.transaction.network_id(), Some(&transaction_network));
    fixture.transaction.verify_signature().unwrap();
    assert!(original.verify_inclusion_in_block(fixture.verified.block()));
    assert!(original.result().is_err());
    assert!(
        fixture
            .verified
            .verify_transaction_execution(&transaction_network, &original)
            .is_err()
    );
    assert!(
        fixture
            .verified
            .verify_transaction_execution(&fixture.native.network_id(), &original)
            .is_err()
    );
}
