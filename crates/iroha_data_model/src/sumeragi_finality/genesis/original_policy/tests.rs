//! Genuine signed-body policy custody and canonical error-order regressions.

use super::*;
use crate::{
    block::SignedBlock,
    isi::{InstructionBox, SetParameter},
    parameter::Parameter,
    sumeragi_finality::{
        authenticated_genesis, signed_genesis_consensus_metadata,
        test_fixtures::NativeFinalityFixture,
    },
    transaction::{Executable, TransactionBuilder},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_primitives::json::Json;
use norito::core::DecodeBudgetContext;

fn fixture() -> NativeFinalityFixture {
    NativeFinalityFixture::start_with_mode(
        "original-policy-custody",
        crate::parameter::system::SumeragiConsensusMode::Npos,
    )
}
fn limits(bytes: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, bytes, 64)
}
fn parameter(genesis: &SignedBlock) -> &CustomParameter {
    genesis
        .external_transactions()
        .find_map(|transaction| {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                return None;
            };
            instructions.iter().find_map(|instruction| {
                let set = instruction.as_any().downcast_ref::<SetParameter>()?;
                let Parameter::Custom(custom) = set.inner() else {
                    return None;
                };
                (custom.id() == &SumeragiNposParameters::parameter_id()).then_some(custom)
            })
        })
        .expect("the original fixture signs explicit NPoS policy")
}
fn shared(genesis: SignedBlock, budget: &AllocationBudget) -> SharedSignedBlock {
    SharedSignedBlock::try_new(genesis, budget).unwrap()
}

#[test]
fn original_completed_policy_survives_metadata_refusal_without_another_decode() {
    let fixture = fixture();
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let genesis = shared(fixture.genesis().clone(), &budget);
    let expected = authenticated_genesis(&genesis).unwrap().into_parts();
    let baseline = budget.reserved_bytes();
    let reference = DecodeBudgetContext::new(limits(usize::MAX));
    reference
        .with(|| SumeragiNposParameters::from_custom_parameter(parameter(&genesis)))
        .unwrap()
        .unwrap();
    let completed_debit = reference.consumed_allocated_bytes();
    assert!(completed_debit > 0);
    let before = reference.consumed_allocated_bytes();
    assert!(matches!(
        reference.with(|| norito::with_decode_limits_scope(limits(0), || {
            signed_genesis_consensus_metadata(&genesis)
        })),
        Err(GenesisReadError::Json(norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        )))
    ));
    let metadata_debit = reference.consumed_allocated_bytes() - before;
    let decoder = DecodeBudgetContext::new(limits(48 * 1024 * 1024));
    let mut original = OriginalGenesisRead::new(genesis.clone(), &budget).unwrap();
    assert!(SharedSignedBlock::ptr_eq(original.genesis(), &genesis));
    let cause = decoder
        .with(|| {
            norito::with_decode_limits_scope(
                limits(usize::try_from(completed_debit).unwrap()),
                || original.authenticate(),
            )
        })
        .unwrap_err();
    assert!(
        matches!(
            cause,
            OriginalGenesisReadError::Validation(GenesisReadError::Json(
                norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                )
            ))
        ),
        "{cause:?}"
    );
    assert_eq!(
        decoder.consumed_allocated_bytes(),
        completed_debit + metadata_debit
    );
    let retained = budget.reserved_bytes();
    assert!(retained > baseline);
    let completed = original.policy.completed.as_ref().unwrap();
    let coordinate = completed.0;
    let pointer: *const SumeragiNposParameters = completed.1.get();
    assert!(completed.1.belongs_to(&budget));
    let before = decoder.consumed_allocated_bytes();
    let cause = decoder
        .with(|| norito::with_decode_limits_scope(limits(0), || original.authenticate()))
        .unwrap_err();
    assert!(
        matches!(
            cause,
            OriginalGenesisReadError::Validation(GenesisReadError::Json(
                norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                )
            ))
        ),
        "{cause:?}"
    );
    assert_eq!(
        decoder.consumed_allocated_bytes() - before,
        metadata_debit,
        "original completed policy must survive metadata refusal without another policy decode"
    );
    let completed = original.policy.completed.as_ref().unwrap();
    assert_eq!(completed.0, coordinate);
    assert!(std::ptr::eq(completed.1.get(), pointer));
    assert!(completed.1.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        decoder
            .with(|| original.authenticate())
            .unwrap()
            .into_parts(),
        expected
    );
    assert!(std::ptr::eq(
        original.policy.completed.as_ref().unwrap().1.get(),
        pointer
    ));
    budget.with_deferred_refund_notifications(|_| drop(original));
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(genesis);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_policy_refuses_foreign_pool_and_preserves_typed_capacity() {
    let fixture = fixture();
    let budget = AllocationBudget::new(SharedSignedBlock::allocation_layout().size());
    let genesis = shared(fixture.genesis().clone(), &budget);
    let other = AllocationBudget::new(32 * 1024 * 1024);
    assert!(matches!(
        OriginalGenesisRead::new(genesis.clone(), &other),
        Err(OriginalGenesisReadError::ForeignPool)
    ));
    assert_eq!(other.reserved_bytes(), 0);
    let mut original = OriginalGenesisRead::new(genesis.clone(), &budget).unwrap();
    for _ in 0..2 {
        let cause = original.authenticate().unwrap_err();
        assert!(
            matches!(
                cause,
                OriginalGenesisReadError::Allocation(ChargedBufferError::Admission(_))
            ),
            "{cause:?}"
        );
        assert!(original.policy.completed.is_none());
        assert_eq!(
            budget.reserved_bytes(),
            SharedSignedBlock::allocation_layout().size()
        );
        assert!(SharedSignedBlock::ptr_eq(original.genesis(), &genesis));
    }
    drop(original);
    drop(genesis);
    assert_eq!(budget.reserved_bytes(), 0);
}

fn append_policy(fixture: &NativeFinalityFixture, extra: CustomParameter) -> SignedBlock {
    let source = fixture.genesis().external_transactions().next().unwrap();
    let Executable::Instructions(instructions) = source.instructions() else {
        panic!("explicit fixture");
    };
    let mut instructions: Vec<InstructionBox> = instructions.to_vec();
    instructions.push(SetParameter::new(Parameter::Custom(extra)).into());
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new_genesis(
        source.authority().clone(),
        source.fee_payment_intent().clone(),
    );
    builder.set_creation_time(source.creation_time());
    let transaction = builder
        .with_instructions(instructions)
        .sign(signer.private_key());
    SignedBlock::try_genesis(vec![transaction], signer.private_key(), None, None).unwrap()
}

#[test]
fn later_policy_is_decoded_before_duplicate_authority_on_every_retry() {
    let fixture = fixture();
    for malformed in [false, true] {
        let second = if malformed {
            CustomParameter::new(
                SumeragiNposParameters::parameter_id(),
                Json::new("not-a-policy"),
            )
        } else {
            parameter(fixture.genesis()).clone()
        };
        let block = append_policy(&fixture, second);
        let expected = authenticated_genesis(&block).unwrap_err();
        if malformed {
            assert!(matches!(expected, GenesisReadError::Json(_)));
        } else {
            assert!(
                matches!(&expected, GenesisReadError::Invalid(message) if message == "genesis repeats its signed NPoS parameter authority")
            );
        }
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let genesis = shared(block, &budget);
        let mut original = OriginalGenesisRead::new(genesis.clone(), &budget).unwrap();
        for _ in 0..2 {
            let cause = original.authenticate().unwrap_err();
            let OriginalGenesisReadError::Validation(actual) = cause else {
                panic!("{cause:?}");
            };
            assert_eq!(actual.to_string(), expected.to_string());
            assert!(
                original
                    .policy
                    .completed
                    .as_ref()
                    .unwrap()
                    .1
                    .belongs_to(&budget)
            );
        }
        drop(original);
        drop(genesis);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

// Re-sign the actual fixture instructions, replacing only the two selected custom bodies.
fn signed_policy_metadata(
    fixture: &NativeFinalityFixture,
    policy: &CustomParameter,
    metadata: &Json,
) -> SignedBlock {
    use crate::parameter::system::consensus_metadata;
    let source = fixture.genesis().external_transactions().next().unwrap();
    let Executable::Instructions(instructions) = source.instructions() else {
        panic!("explicit fixture");
    };
    let mut replacements = (0, 0);
    let instructions: Vec<InstructionBox> = instructions
        .iter()
        .map(|instruction| {
            if let Some(set) = instruction.as_any().downcast_ref::<SetParameter>()
                && let Parameter::Custom(custom) = set.inner()
            {
                if custom.id() == &SumeragiNposParameters::parameter_id() {
                    replacements.0 += 1;
                    return SetParameter::new(Parameter::Custom(policy.clone())).into();
                }
                if custom.id() == &consensus_metadata::handshake_meta_id() {
                    replacements.1 += 1;
                    return SetParameter::new(Parameter::Custom(CustomParameter::new(
                        consensus_metadata::handshake_meta_id(),
                        metadata.clone(),
                    )))
                    .into();
                }
            }
            instruction.clone()
        })
        .collect();
    assert_eq!(replacements, (1, 1));
    let signer = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new_genesis(
        source.authority().clone(),
        source.fee_payment_intent().clone(),
    );
    builder.set_creation_time(source.creation_time());
    let transaction = builder
        .with_instructions(instructions)
        .sign(signer.private_key());
    SignedBlock::try_genesis(vec![transaction], signer.private_key(), None, None).unwrap()
}

fn same_genesis_cause(actual: &GenesisReadError, expected: &GenesisReadError) {
    match (actual, expected) {
        (GenesisReadError::Invalid(actual), GenesisReadError::Invalid(expected)) => {
            assert_eq!(actual, expected);
        }
        (GenesisReadError::Json(actual), GenesisReadError::Json(expected)) => {
            assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        }
        _ => panic!("changed original classification: {actual:?} != {expected:?}"),
    }
}

#[test]
fn borrowed_policy_preserves_signed_metadata_before_election_bounds() {
    use crate::nexus::ValidatorElectionPolicyV1;
    let fixture = fixture();
    let source_metadata = signed_genesis_consensus_metadata(fixture.genesis()).unwrap();
    let source_parameters =
        SumeragiNposParameters::from_custom_parameter(parameter(fixture.genesis()))
            .unwrap()
            .unwrap();
    for mutation in 0..3 {
        let mut parameters = source_parameters.clone();
        match mutation {
            0 => parameters.min_self_bond = "0.0000000001".parse().unwrap(),
            1 => {
                parameters.epoch_length_blocks = std::num::NonZeroU64::new(2).unwrap();
                parameters.evidence_horizon_blocks = 1;
                parameters.slashing_delay_blocks = 1;
            }
            _ => {
                parameters.xor_asset_definition_id =
                    crate::asset::AssetDefinitionId::derive_from_components(
                        iroha_model_base::domain::DomainId::parse_fully_qualified(
                            "nexus.universal",
                        )
                        .unwrap(),
                        "xor".parse().unwrap(),
                    );
            }
        }
        let custom = parameters.clone().into_custom_parameter();
        let policy_cause = SumeragiNposParameters::from_custom_parameter(&custom).err();
        if mutation == 2 {
            assert!(matches!(
                policy_cause.as_ref(),
                Some(norito::json::Error::InvalidField { .. })
            ));
        } else {
            assert!(
                policy_cause.is_none(),
                "scale/epoch must reach the later election guard"
            );
        }
        for malformed_metadata in [false, true] {
            let metadata = if malformed_metadata {
                Json::new("not-consensus-metadata")
            } else {
                Json::new(source_metadata)
            };
            let block = signed_policy_metadata(&fixture, &custom, &metadata);
            let expected = policy_cause.as_ref().map_or_else(
                || {
                    if malformed_metadata {
                        signed_genesis_consensus_metadata(&block).unwrap_err()
                    } else {
                        GenesisReadError::Invalid(
                            ValidatorElectionPolicyV1::from_npos_parameters(&parameters)
                                .unwrap_err(),
                        )
                    }
                },
                |error| GenesisReadError::Json(error.clone()),
            );
            same_genesis_cause(&authenticated_genesis(&block).unwrap_err(), &expected);
            let budget = AllocationBudget::new(32 * 1024 * 1024);
            let genesis = shared(block, &budget);
            let baseline = budget.reserved_bytes();
            let mut original = OriginalGenesisRead::new(genesis.clone(), &budget).unwrap();
            for _ in 0..2 {
                let cause = original.authenticate().unwrap_err();
                let OriginalGenesisReadError::Validation(actual) = cause else {
                    panic!("{cause:?}");
                };
                same_genesis_cause(&actual, &expected);
                assert!(SharedSignedBlock::ptr_eq(original.genesis(), &genesis));
                if policy_cause.is_none() {
                    assert!(
                        original
                            .policy
                            .completed
                            .as_ref()
                            .unwrap()
                            .1
                            .belongs_to(&budget)
                    );
                    assert!(budget.reserved_bytes() > baseline);
                }
            }
            budget.with_deferred_refund_notifications(|_| drop(original));
            assert_eq!(budget.reserved_bytes(), baseline);
            drop(genesis);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}
