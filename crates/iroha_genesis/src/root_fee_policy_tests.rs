//! Original signed-genesis monetary policy authentication controls.

use super::*;
use iroha_data_model::{
    block::{
        BlockSignature, BlockSignatures,
        consensus::{RootFeePolicy, SumeragiRootScope},
    },
    sumeragi_finality::authenticated_genesis,
};

fn signed(fees: &[RootFeePolicy], scope: SumeragiRootScope) -> SignedBlock {
    init_instruction_registry();
    let key = KeyPair::from_seed(vec![0x75; 32], Algorithm::Ed25519);
    let mut context = SumeragiGenesisContextParameters::recommended();
    context.root_scope = scope;
    // First obtain the same canonical metadata/topology instructions as normal authoring.
    let mut initial = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    initial.base_fee = 1_u32.into();
    initial.per_gas_unit_fee = 1_u32.into();
    let mut manifest = GenesisBuilder::new_without_executor(ChainId::from("signed-root-fees"), ".")
        .with_sumeragi_context_parameters(context)
        .append_parameter(Parameter::Custom(initial.into_custom_parameter().unwrap()))
        .build_raw()
        .unwrap();
    manifest.transactions.first_mut().unwrap().topology =
        deterministic_test_genesis_topology_entries();
    let manifest = manifest.with_consensus_meta().unwrap();
    let mut batches = manifest.parse().unwrap();
    for batch in &mut batches {
        batch.retain(|instruction| {
            !instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_some_and(|set| {
                    matches!(set.inner(), Parameter::Custom(custom)
                if custom.id() == &RootFeePolicy::parameter_id())
                })
        });
    }
    // These malformed test bodies are signed normally; refusal must inspect original slots.
    batches[0].extend(fees.iter().cloned().map(|fee| {
        InstructionBox::from(SetParameter::new(Parameter::Custom(
            fee.into_custom_parameter().unwrap(),
        )))
    }));
    let transactions = batches
        .into_iter()
        .enumerate()
        .map(|(index, instructions)| {
            let mut builder = TransactionBuilder::new_genesis(
                AccountId::new(key.public_key().clone()),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions(instructions)
            .with_metadata(genesis_transaction_metadata(index as u64).unwrap());
            builder.set_creation_time(Duration::from_millis(1000 + index as u64));
            builder.try_sign(key.private_key()).unwrap()
        })
        .collect();
    SignedBlock::try_genesis_with_da_proof_policies(
        transactions,
        key.private_key(),
        None,
        None,
        None,
    )
    .unwrap()
}

#[test]
fn authenticated_signed_policy_has_one_exact_original_owner() {
    let expected = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    let block = signed(std::slice::from_ref(&expected), SumeragiRootScope::Global);
    assert_eq!(signed_genesis_root_fee_policy(&block).unwrap(), expected);
    for policies in [vec![], vec![expected.clone(), expected.clone()]] {
        let malformed = signed(&policies, SumeragiRootScope::Global);
        authenticated_genesis(&malformed).expect("failure is the actual root fee slot cardinality");
        assert!(signed_genesis_root_fee_policy(&malformed).is_err());
    }
    let mut substituted = block.clone();
    let wrong = KeyPair::from_seed(vec![0x76; 32], Algorithm::Ed25519);
    let signature =
        iroha_crypto::SignatureOf::try_from_hash(wrong.private_key(), substituted.hash()).unwrap();
    substituted
        .replace_signatures(
            BlockSignatures::try_from_iter([BlockSignature::new(0, signature)]).unwrap(),
        )
        .unwrap();
    assert_eq!(substituted.hash(), block.hash());
    assert!(signed_genesis_root_fee_policy(&substituted).is_err());
}

#[test]
fn authenticated_policy_validates_the_original_dataspace_root() {
    let mut policy = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    policy.base_fee = 1_u32.into();
    policy.per_gas_unit_fee = 1_u32.into();
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"root-fee-parent",
        ))),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
    };
    let block = signed(std::slice::from_ref(&policy), scope);
    assert_eq!(signed_genesis_root_fee_policy(&block).unwrap(), policy);
    policy.base_fee = 0_u32.into();
    let invalid = signed(&[policy], scope);
    authenticated_genesis(&invalid).expect("zero rate does not invalidate original signatures");
    assert!(signed_genesis_root_fee_policy(&invalid).is_err());
}

#[test]
fn manifest_fee_policy_uses_declared_account_context_and_restores_caller() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    let _caller = ChainDiscriminantGuard::enter(753);
    let manifest = {
        let _author = ChainDiscriminantGuard::enter(369);
        GenesisBuilder::new_without_executor(ChainId::from("declared-root-fee-context"), ".")
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
            .build_raw()
            .expect("complete authored genesis")
    };
    assert_eq!(manifest.chain_discriminant(), 369);
    let parameters = manifest.effective_parameters().unwrap();
    assert!(RootFeePolicy::from_parameters(&parameters).is_err());
    let original = manifest.encode();
    manifest
        .validate_mode_specific_consensus_parameters()
        .unwrap();
    assert_eq!(manifest.encode(), original);
    assert_eq!(chain_discriminant(), 753);
    manifest
        .clone()
        .normalize()
        .expect("normalize using the declared fee context");
    assert_eq!(chain_discriminant(), 753);

    // Declaring the caller's network cannot reinterpret a different network's policy.
    let wrong_context = manifest.with_chain_discriminant(753);
    assert!(
        wrong_context
            .validate_mode_specific_consensus_parameters()
            .is_err()
    );
    assert_eq!(
        chain_discriminant(),
        753,
        "error paths restore the caller's account context"
    );
}
