//! Parameter precedence, source preservation, and authority checks during genesis construction.

use super::*;
use iroha_data_model::{
    executor::Executor,
    isi::Upgrade,
    parameter::{BlockParameter, CustomParameter},
    proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    transaction::{FeePaymentIntent, IvmBytecode, TransactionBuilder, signed::MultisigSignatures},
};
use std::{num::NonZeroU32, panic::AssertUnwindSafe};

fn key() -> KeyPair {
    crate::init_instruction_registry();
    KeyPair::from_seed(
        b"parameter-normalization".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    )
}

fn block_limit(value: u64) -> Parameter {
    Parameter::Block(BlockParameter::MaxTransactions(
        std::num::NonZeroU64::new(value).unwrap(),
    ))
}

fn handshake(value: &str) -> Parameter {
    Parameter::Custom(CustomParameter::new(
        consensus_metadata::handshake_meta_id(),
        Json::new(value),
    ))
}

fn marker(label: &str) -> InstructionBox {
    Register::domain(Domain::new(DomainId::try_new(label, "universal").unwrap())).into()
}

fn builder(key: &KeyPair, index: u32, instructions: Vec<InstructionBox>) -> TransactionBuilder {
    let mut metadata = Metadata::default();
    metadata.insert("fixture_source".parse().unwrap(), Json::new(index));
    let mut builder = TransactionBuilder::new_genesis(
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .with_metadata(metadata);
    builder.set_creation_time(Duration::from_millis(100 + u64::from(index)));
    builder.set_nonce(NonZeroU32::new(index + 1).unwrap());
    builder.set_ttl(Duration::from_secs(50));
    builder
}

fn sign(key: &KeyPair, index: u32, instructions: Vec<InstructionBox>) -> SignedTransaction {
    builder(key, index, instructions)
        .try_sign(key.private_key())
        .unwrap()
}

fn non_instruction_payload(transaction: &SignedTransaction) -> norito::json::Value {
    let norito::json::Value::Object(mut fields) =
        norito::json::to_value(transaction.payload()).unwrap()
    else {
        panic!("transaction payload is an object");
    };
    assert!(fields.remove("instructions").is_some());
    norito::json::Value::Object(fields)
}

fn parameters(transaction: &SignedTransaction) -> Vec<Parameter> {
    transaction
        .instructions()
        .explicit_instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .map(|set| set.inner().clone())
        })
        .collect()
}

#[test]
fn normalization_places_unique_effective_parameters_before_ordinary_sources() {
    for upgrade in [false, true] {
        let key = key();
        let mut source = Vec::new();
        if upgrade {
            source.push(sign(
                &key,
                0,
                vec![Upgrade::new(Executor::new(IvmBytecode::from_compiled(vec![1, 2, 3]))).into()],
            ));
        }
        let offset = source.len();
        source.extend([
            sign(&key, 1, vec![marker("first")]),
            sign(&key, 2, vec![marker("untouched")]),
            sign(
                &key,
                3,
                vec![
                    SetParameter::new(block_limit(7)).into(),
                    marker("later"),
                    SetParameter::new(handshake("old")).into(),
                ],
            ),
            sign(&key, 4, vec![SetParameter::new(block_limit(8)).into()]),
        ]);
        let npos = Parameter::Custom(
            iroha_data_model::parameter::system::SumeragiNposParameters {
                max_validators: 4,
                ..Default::default()
            }
            .into_custom_parameter(),
        );
        let chosen = handshake("chosen");
        let result = normalize_parameter_transactions(
            &source,
            [
                block_limit(9),
                npos.clone(),
                block_limit(10),
                handshake("stale override"),
            ],
            &chosen,
            &key,
        );
        assert_eq!(
            result.len(),
            source.len() - 1,
            "empty parameter-only source removed"
        );
        assert_eq!(
            parameters(&result[offset]),
            vec![block_limit(10), npos, chosen.clone()]
        );
        assert!(
            result
                .iter()
                .skip(offset + 1)
                .all(|transaction| parameters(transaction).is_empty())
        );
        for index in 0..3 {
            assert_eq!(
                non_instruction_payload(&result[offset + index]),
                non_instruction_payload(&source[offset + index])
            );
            result[offset + index].verify_signature().unwrap();
        }
        assert_eq!(
            norito::codec::encode_adaptive(&result[offset + 1]),
            norito::codec::encode_adaptive(&source[offset + 1])
        );
        if upgrade {
            assert_eq!(
                norito::codec::encode_adaptive(&result[0]),
                norito::codec::encode_adaptive(&source[0])
            );
        }
        let ordinary = |transactions: &[SignedTransaction]| {
            transactions
                .iter()
                .flat_map(|transaction| transaction.instructions().explicit_instructions())
                .filter(|instruction| !instruction.as_any().is::<SetParameter>())
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(ordinary(&result), ordinary(&source));
        let Executable::Instructions(carrier) = result[offset].instructions() else {
            unreachable!()
        };
        assert!(
            carrier
                .iter()
                .take(3)
                .all(|instruction| instruction.as_any().is::<SetParameter>())
        );
        assert_eq!(carrier.last(), Some(&marker("first")));
        assert_eq!(
            normalize_parameter_transactions(&result, [], &chosen, &key),
            result,
            "normalization is idempotent"
        );
    }
}

#[test]
fn normalization_rejects_removing_a_foreign_parameter_source() {
    let key = key();
    let foreign = KeyPair::from_seed(
        b"foreign-parameter-authority".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    );
    let source = [
        sign(&key, 0, vec![marker("carrier")]),
        sign(&foreign, 1, vec![SetParameter::new(block_limit(7)).into()]),
    ];
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        normalize_parameter_transactions(&source, [], &handshake("chosen"), &key)
    }))
    .expect_err("foreign parameter source must not be erased");
    let text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("rejection diagnostic");
    assert!(text.contains("another authority"), "{text}");
}

#[test]
fn normalization_rejects_removing_a_proof_attached_parameter_source() {
    let key = key();
    let attachment = ProofAttachment::new_ref(
        "halo2/ipa".into(),
        ProofBox::new("halo2/ipa".into(), vec![1]),
        VerifyingKeyId::new("halo2/ipa", "normalization"),
    );
    let attached = builder(&key, 1, vec![SetParameter::new(block_limit(7)).into()])
        .with_proof_attachments(vec![attachment])
        .expect("valid proof carriers")
        .try_sign(key.private_key())
        .unwrap();
    let source = [sign(&key, 0, vec![marker("carrier")]), attached];
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        normalize_parameter_transactions(&source, [], &handshake("chosen"), &key)
    }))
    .expect_err("proof-attached source must not be erased");
    let text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("rejection diagnostic");
    assert!(text.contains("proof-attached"), "{text}");
}

#[test]
fn normalization_rejects_removing_a_multisig_parameter_source() {
    let key = key();
    let mut multisig = sign(&key, 1, vec![SetParameter::new(block_limit(7)).into()]);
    multisig.set_multisig_signatures(MultisigSignatures::new(Vec::new()));
    let source = [sign(&key, 0, vec![marker("carrier")]), multisig];
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        normalize_parameter_transactions(&source, [], &handshake("chosen"), &key)
    }))
    .expect_err("multisig source must not be erased");
    let text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("rejection diagnostic");
    assert!(text.contains("multisig"), "{text}");
}

#[test]
fn normalization_rejects_repairing_an_invalid_original_signature() {
    let key = key();
    let foreign = KeyPair::from_seed(
        b"invalid-original-signature".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    );
    let invalid = sign(&foreign, 1, vec![SetParameter::new(block_limit(7)).into()])
        .with_authority(AccountId::new(key.public_key().clone()));
    assert!(invalid.verify_signature().is_err());
    let source = [sign(&key, 0, vec![marker("carrier")]), invalid];
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        normalize_parameter_transactions(&source, [], &handshake("chosen"), &key)
    }))
    .expect_err("an invalid signed parameter source must not be repaired or erased");
    let text = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("rejection diagnostic");
    assert!(
        text.contains("original genesis parameter source signature must verify"),
        "{text}"
    );
}

/// A signed four-validator source that does not execute its provisional policy.
fn envelope_fixture(key: &KeyPair, selected_handshake: &Parameter) -> GenesisBlock {
    use iroha_data_model::isi::register::RegisterPeerWithPop;

    let validators = (0x51..=0x54)
        .map(|seed| {
            let validator = KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap();
            RegisterPeerWithPop::new(
                PeerId::new(validator.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(validator.private_key()).unwrap(),
            )
            .into()
        })
        .collect::<Vec<InstructionBox>>();
    let transactions = vec![
        sign(
            key,
            0,
            vec![
                SetParameter::new(block_limit(10)).into(),
                SetParameter::new(selected_handshake.clone()).into(),
            ],
        ),
        sign(key, 1, validators),
        sign(key, 2, vec![marker("retained-source")]),
    ];
    GenesisBlock(
        iroha_data_model::block::SignedBlock::try_genesis_with_da_proof_policies(
            transactions,
            key.private_key(),
            None,
            None,
            None,
        )
        .unwrap(),
    )
}

fn reject_original_envelope(
    source: &GenesisBlock,
    key: &KeyPair,
    expected: iroha_core::block::InvalidGenesisError,
) {
    let original = source.0.encode_wire().unwrap();
    let authority = AccountId::new(key.public_key().clone());
    let checked = if source.0.has_results() {
        check_genesis_block(&source.0, &authority)
    } else {
        check_genesis_block_intents(&source.0, &authority)
    };
    assert_eq!(checked, Err(expected));
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        normalize_genesis_parameters(source, &[], &[], &handshake("chosen"), key, None, None)
    }))
    .expect_err("invalid original envelope must not be repaired by normalization");
    assert_eq!(source.0.encode_wire().unwrap(), original);
}

#[test]
fn normalization_rejects_foreign_or_stale_original_header_signature() {
    use iroha_core::block::InvalidGenesisError;
    use iroha_data_model::block::{BlockSignature, SignedBlock};

    let key = key();
    let original = envelope_fixture(&key, &handshake("old"));
    let foreign = KeyPair::from_seed(b"foreign-header".to_vec(), Algorithm::Ed25519);
    let foreign_signature = BlockSignature::new(
        0,
        iroha_crypto::SignatureOf::try_from_hash(foreign.private_key(), original.0.hash()).unwrap(),
    );
    let forged = GenesisBlock(SignedBlock::presigned_with_payload(
        foreign_signature,
        original.0.payload().clone(),
    ));
    reject_original_envelope(&forged, &key, InvalidGenesisError::InvalidSignature);

    let mut payload = original.0.payload().clone();
    payload.header.creation_time_ms += 1;
    let corrupt = GenesisBlock(SignedBlock::presigned_with_payload(
        original.0.signatures().next().unwrap().clone(),
        payload,
    ));
    reject_original_envelope(&corrupt, &key, InvalidGenesisError::InvalidSignature);
}

#[test]
fn normalization_requires_one_original_signature_at_index_zero() {
    use iroha_core::block::InvalidGenesisError;
    use iroha_data_model::block::{BlockSignature, SignedBlock};

    let key = key();
    let original = envelope_fixture(&key, &handshake("old"));
    let unsigned = GenesisBlock(SignedBlock::unsigned_with_payload(
        original.0.payload().clone(),
    ));
    reject_original_envelope(&unsigned, &key, InvalidGenesisError::InvalidSignature);
    let misplaced = GenesisBlock(SignedBlock::presigned_with_payload(
        BlockSignature::new(
            1,
            original.0.signatures().next().unwrap().signature().clone(),
        ),
        original.0.payload().clone(),
    ));
    reject_original_envelope(&misplaced, &key, InvalidGenesisError::InvalidSignature);
    let mut multiple = original.clone();
    multiple.0.try_sign(key.private_key(), 1).unwrap();
    reject_original_envelope(&multiple, &key, InvalidGenesisError::InvalidSignature);
}

#[test]
fn normalization_rejects_original_input_and_sidecar_commitment_mismatch() {
    use iroha_core::block::InvalidGenesisError;
    use iroha_data_model::block::{BlockSignature, SignedBlock};

    let key = key();
    let original = envelope_fixture(&key, &handshake("old"));
    let mut payload = original.0.payload().clone();
    payload
        .external_entrypoints
        .push(sign(&key, 3, vec![marker("unsigned-addition")]).into());
    let changed = GenesisBlock(SignedBlock::presigned_with_payload(
        original.0.signatures().next().unwrap().clone(),
        payload,
    ));
    reject_original_envelope(&changed, &key, InvalidGenesisError::MerkleRootMismatch);

    let mut payload = original.0.payload().clone();
    payload.header.execution_context_hash = Some(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"absent committed context"),
    ));
    let signature = BlockSignature::new(
        0,
        iroha_crypto::SignatureOf::try_from_hash(key.private_key(), payload.header.hash()).unwrap(),
    );
    let incomplete = GenesisBlock(SignedBlock::presigned_with_payload(signature, payload));
    reject_original_envelope(
        &incomplete,
        &key,
        InvalidGenesisError::ProposalCommitmentMismatch,
    );
}

#[test]
fn normalization_authenticates_unchanged_original_transaction_sources() {
    use iroha_core::block::InvalidGenesisError;
    use iroha_data_model::block::SignedBlock;

    let key = key();
    let original = envelope_fixture(&key, &handshake("old"));
    let foreign = KeyPair::from_seed(b"foreign-ordinary-source".to_vec(), Algorithm::Ed25519);
    let replacement = sign(&foreign, 2, vec![marker("retained-source")]);
    let mut inputs = original
        .0
        .external_transactions()
        .cloned()
        .collect::<Vec<_>>();
    inputs[2] = replacement.clone();
    let forged = GenesisBlock(
        SignedBlock::try_genesis_with_da_proof_policies(
            inputs.clone(),
            key.private_key(),
            None,
            None,
            None,
        )
        .unwrap(),
    );
    reject_original_envelope(&forged, &key, InvalidGenesisError::UnexpectedAuthority);
    inputs[2] = replacement.with_authority(AccountId::new(key.public_key().clone()));
    let corrupt = GenesisBlock(
        SignedBlock::try_genesis_with_da_proof_policies(
            inputs,
            key.private_key(),
            None,
            None,
            None,
        )
        .unwrap(),
    );
    reject_original_envelope(
        &corrupt,
        &key,
        InvalidGenesisError::InvalidTransactionSignature,
    );
}

#[test]
fn authenticated_canonical_parameter_source_keeps_its_exact_wire() {
    let key = key();
    let chosen = handshake("chosen");
    let original = envelope_fixture(&key, &chosen);
    let bytes = original.0.encode_wire().unwrap();
    assert!(!original.0.has_results());
    assert_eq!(
        check_genesis_block_intents(&original.0, &AccountId::new(key.public_key().clone())),
        Ok(())
    );
    let normalized = normalize_genesis_parameters(&original, &[], &[], &chosen, &key, None, None);
    assert_eq!(normalized.0.encode_wire().unwrap(), bytes);
    assert_eq!(original.0.encode_wire().unwrap(), bytes);
    let changed =
        normalize_genesis_parameters(&original, &[], &[], &handshake("rebound"), &key, None, None);
    assert_ne!(changed.0.hash(), original.0.hash());
    assert_eq!(
        check_genesis_block_intents(&changed.0, &AccountId::new(key.public_key().clone())),
        Ok(())
    );
    assert_eq!(original.0.encode_wire().unwrap(), bytes);
}

#[test]
fn normalization_rejects_rejected_outputs_in_a_supplied_complete_envelope() {
    use iroha_core::block::{GenesisOutputRejection, InvalidGenesisError};
    use iroha_data_model::{
        block::{
            execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
            output_budget::ExecutionOutputLimits,
        },
        transaction::{TransactionResult, error::TransactionRejectionReason},
    };

    let key = key();
    let chosen = handshake("chosen");
    let mut complete = envelope_fixture(&key, &chosen);
    let mut outputs = (0..complete.0.network_entrypoint_count())
        .map(|index| {
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: u32::try_from(index).unwrap(),
                result: TransactionResult::new(Ok(Vec::new())),
                completions: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    let fragments = u64::try_from(outputs.len()).unwrap();
    let limits = ExecutionOutputLimits {
        max_outputs: 16,
        max_output_bytes: 65_536,
        max_total_output_bytes: 262_144,
        max_executed_wire_bytes: 1_048_576,
    };
    complete
        .0
        .set_execution_outputs(
            outputs.clone(),
            fragments,
            Default::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            &limits,
        )
        .unwrap();
    let original = complete.0.encode_wire().unwrap();
    assert_eq!(
        check_genesis_block(&complete.0, &AccountId::new(key.public_key().clone())),
        Ok(())
    );
    let normalized = normalize_genesis_parameters(&complete, &[], &[], &chosen, &key, None, None);
    assert!(
        !normalized.0.has_results(),
        "normalized sources require fresh native execution"
    );
    assert_eq!(complete.0.encode_wire().unwrap(), original);

    let reason = TransactionRejectionReason::Validation(
        iroha_data_model::ValidationFail::NotPermitted("original rejected output".to_owned()),
    );
    let ExecutionOutputV1::Network(first) = &mut outputs[0] else {
        unreachable!()
    };
    first.result = TransactionResult::new(Err(reason.clone()));
    complete
        .0
        .set_execution_outputs(
            outputs,
            fragments,
            Default::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            &limits,
        )
        .unwrap();
    reject_original_envelope(
        &complete,
        &key,
        InvalidGenesisError::RejectedOutput(GenesisOutputRejection {
            output_index: 0,
            reason: Box::new(reason),
        }),
    );
}
