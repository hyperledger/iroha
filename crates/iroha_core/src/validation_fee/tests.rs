//! Conversion provenance and protected runtime fixture tests.
#[path = "permission_guard_tests.rs"]
mod permission_guard_tests;
#[path = "registry_refusal_tests.rs"]
mod registry_refusal_tests;
#[path = "runtime_dlmm_tests.rs"]
mod runtime_dlmm_tests;
#[path = "runtime_wrapper_tests.rs"]
pub(crate) mod runtime_wrapper_tests;
#[path = "signed_original_fixtures.rs"]
mod signed_original_fixtures;
use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    block::BlockHeader,
    events::time::{ExecutionTime, Schedule, TimeEventFilter},
    transaction::{Executable, executable::ContractInvocation},
    trigger::{
        Trigger,
        action::{Action, Repeats},
    },
};
use iroha_model_base::{domain::DomainId, name::Name, topology::DataSpaceId};
use iroha_primitives::numeric::NumericSpec;
pub(crate) use signed_original_fixtures::{
    sign_paid_fixture, signed_payout_lifecycle_registry_fixture,
    signed_payout_lifecycle_registry_fixture_with_config,
    with_original_validation_fee_payout_state_at_height,
};
use std::str::FromStr as _;
const TEST_VALIDATION_FEE_ASSET_SCALE: u8 = 2;
fn encode_fixture_int_map_key(value: i128) -> Vec<u8> {
    use ivm_abi::state_value::{
        StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
        StateValueSchemaV1, state_value_schema_hash_v1,
    };
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
    };
    let envelope =
        ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(value))
            .unwrap();
    norito::encode_canonical(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&norito::encode_canonical(&schema).unwrap()),
        atoms: vec![StateValueAtomV1::Pointer(envelope)],
    })
    .unwrap()
}

fn key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key pair")
}

fn account(seed: u8) -> AccountId {
    let key_pair = key_pair(seed);
    AccountId::new(key_pair.public_key().clone())
}

fn asset_definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").expect("domain id"),
        Name::from_str(name).expect("asset name"),
    )
}

fn fee_asset() -> AssetDefinitionId {
    asset_definition("fee_token")
}

fn successor_fee_asset() -> AssetDefinitionId {
    asset_definition("successor_fee_token")
}

fn validation_fee_test_network_id() -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([7; 32]),
    ))
}

fn xor_asset() -> AssetDefinitionId {
    iroha_data_model::parameter::system::SumeragiNposParameters::default().xor_asset_definition_id
}

fn test_contract_address() -> iroha_data_model::smart_contract::ContractAddress {
    iroha_data_model::smart_contract::ContractAddress::derive(
        &validation_fee_test_network_id(),
        &account(9),
        42,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("test contract address")
}

pub(crate) fn treasury_payout_binding(
    contract_address: iroha_data_model::smart_contract::ContractAddress,
    code: &[u8],
) -> ValidationFeeTreasuryPayoutBindingV1 {
    let treasury = contract_address.subject_id();
    let pool_contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        &validation_fee_test_network_id(),
        &account(2),
        43,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("pool address");
    ValidationFeeTreasuryPayoutBindingV1 {
        contract_address,
        code_hash: <[u8; 32]>::from(ivm::contract_code_hash(code)),
        entrypoint: "autonomous_validation_fee_tick"
            .parse()
            .expect("payout entrypoint"),
        treasury_account_id: treasury,
        ds_asset_id: fee_asset(),
        xor_asset_id: xor_asset(),
        pool_vault_account_id: pool_contract_address.subject_id(),
        pool_contract_address,
        pool_code_hash: [2; 32],
        reward_pool_account_id: account(8),
        reference_feed_id: "xor_per_sbd".parse().expect("feed"),
        reference_feed_config_version: 1,
        reference_provider_accounts: (10..15).map(account).collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100_000,
        min_interval_ms: 60000,
        max_source_age_ms: 300_000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    }
}

fn minimal_bound_contract_artifact() -> (
    Vec<u8>,
    iroha_data_model::smart_contract::manifest::ContractManifest,
) {
    let metadata = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 4,
        abi_version: 1,
    };
    let wrapper_entrypoint = iroha_data_model::smart_contract::manifest::EntrypointDescriptor {
        name: "autonomous_validation_fee_tick".to_owned(),
        kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "Payout".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
    };
    let pool_entrypoint = iroha_data_model::smart_contract::manifest::EntrypointDescriptor {
        name: VALIDATION_FEE_POOL_SWAP_ENTRYPOINT.to_owned(),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "SwapQuotePublic".parse().unwrap(),
            ),
        ..wrapper_entrypoint.clone()
    };
    let entrypoints = [wrapper_entrypoint, pool_entrypoint];
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: ["Payout", "SwapQuotePublic"].into_iter().map(|name| iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 {
            name: name.parse().unwrap(), scope: iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance,
        }).collect(),
        callables: (0..entrypoints.len())
            .map(|index| crate::ivm_test_support::unit_callable(index as u64 * 16))
            .collect(),
        seiyaku_name: "ValidationFeePayout".to_owned(),
        compiler_fingerprint: "validation-fee-bound-contract-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: entrypoints
            .iter()
            .enumerate()
            .map(|(index, entrypoint)| ivm::EmbeddedEntrypointDescriptor {
                name: entrypoint.name.clone(),
                kind: entrypoint.kind,
                params: entrypoint.params.clone(),
                argument_schema: entrypoint.argument_schema.clone(),
                return_type: entrypoint.return_type.clone(),
                return_schema: entrypoint.return_schema.clone(),
                authorization: entrypoint.authorization.clone(),
                read_keys: entrypoint.read_keys.clone(),
                write_keys: entrypoint.write_keys.clone(),
                access_hints_complete: entrypoint.access_hints_complete,
                access_hints_skipped: entrypoint.access_hints_skipped.clone(),
                triggers: entrypoint.triggers.clone(),
                entry_pc: u64::try_from(index).expect("fixture entrypoint index fits u64") * 16,
            })
            .collect(),
        error_types: Vec::new(),
        error_messages: Vec::new(),
        states: Vec::new(),
    };
    let mut instructions = Vec::new();
    for _ in &entrypoints {
        instructions.extend_from_slice(&crate::ivm_test_support::unit_return());
    }
    let mut artifact = metadata.encode();
    artifact.extend_from_slice(&interface.encode_section());
    artifact.extend_from_slice(&instructions);
    let verified = ivm::verify_contract_artifact(&artifact).expect("valid bound contract artifact");
    (artifact, verified.manifest)
}

#[test]
fn payout_permissions_require_dedicated_instance_roles() {
    use iroha_data_model::smart_contract::manifest::{
        ContractPermissionScopeV1, EntrypointAuthorizationV1,
    };
    let (_, manifest) = minimal_bound_contract_artifact();
    let selector = "autonomous_validation_fee_tick";
    assert_eq!(
        dedicated_payout_permission(&manifest, selector),
        Some("Payout".parse().unwrap())
    );
    assert_eq!(
        dedicated_payout_permission(&manifest, VALIDATION_FEE_POOL_SWAP_ENTRYPOINT),
        Some("SwapQuotePublic".parse().unwrap())
    );
    assert_eq!(dedicated_payout_permission(&manifest, "missing"), None);
    for authorization in [
        EntrypointAuthorizationV1::Anyone,
        EntrypointAuthorizationV1::RuntimeLifecycle,
    ] {
        let mut changed = manifest.clone();
        changed.entrypoints.as_mut().unwrap()[0].authorization = authorization;
        assert_eq!(dedicated_payout_permission(&changed, selector), None);
    }
    let mut shared = manifest.clone();
    shared.permissions[0].scope = ContractPermissionScopeV1::Chain {
        permission_name: "Payout".parse().unwrap(),
    };
    assert_eq!(dedicated_payout_permission(&shared, selector), None);
    let mut grouped = manifest.clone();
    let roles = grouped.entrypoints.as_mut().unwrap();
    roles[1].authorization = roles[0].authorization.clone();
    assert_eq!(dedicated_payout_permission(&grouped, selector), None);
    let mut missing = manifest.clone();
    missing.permissions.clear();
    assert_eq!(dedicated_payout_permission(&missing, selector), None);
    let mut duplicate = manifest;
    duplicate.permissions.push(duplicate.permissions[0].clone());
    assert_eq!(dedicated_payout_permission(&duplicate, selector), None);
}

pub(crate) fn validation_fee_payout_world(deployer: &AccountId) -> crate::state::World {
    use iroha_data_model::prelude::{Account, AssetDefinition, Domain};
    let contract_domain =
        Domain::new(DomainId::try_new("contracts", "universal").expect("contract domain id"))
            .build(deployer);
    let fee_domain = Domain::new(DomainId::try_new("fees", "paynet").expect("fee-asset domain id"))
        .build(deployer);
    let mut accounts = vec![Account::new(deployer.clone()).build(deployer)];
    accounts.extend((2..=14).map(|seed| Account::new(account(seed)).build(deployer)));
    let fee_definition = AssetDefinition::new(
        fee_asset(),
        "fee_token".to_owned(),
        NumericSpec::fractional(u32::from(TEST_VALIDATION_FEE_ASSET_SCALE)),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(deployer);
    let xor_definition = AssetDefinition::new(
        xor_asset(),
        "xor".to_owned(),
        NumericSpec::fractional(9),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(deployer);
    let successor_fee_definition = AssetDefinition::new(
        successor_fee_asset(),
        "successor_fee_token".to_owned(),
        NumericSpec::fractional(u32::from(TEST_VALIDATION_FEE_ASSET_SCALE)),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(deployer);
    let world = crate::state::World::with(
        [contract_domain, fee_domain],
        accounts,
        [fee_definition, successor_fee_definition, xor_definition],
    );
    {
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::system::SumeragiNposParameters::default()
                    .into_custom_parameter(),
            ))
            .expect("valid fixture parameters");
        parameters.commit();
    }
    world
}

pub(crate) fn register_bound_payout_time_trigger(
    state_tx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    expected_code_hash: Hash,
    trigger_id: &str,
) -> iroha_data_model::trigger::TriggerId {
    let trigger_id: iroha_data_model::trigger::TriggerId =
        trigger_id.parse().expect("payout trigger id");
    let block_cadence = std::time::Duration::from_millis(
        state_tx
            .world
            .parameters
            .sumeragi()
            .block_cadence_ms()
            .get(),
    );
    let action = Action::new(
        Executable::ContractCall(ContractInvocation {
            contract_address: binding.contract_address.clone(),
            expected_code_hash,
            entrypoint: binding.entrypoint.to_string(),
            arguments: None,
        }),
        Repeats::Indefinitely,
        binding.treasury_account_id.clone(),
        TimeEventFilter::new(ExecutionTime::Schedule(
            Schedule::starting_at(std::time::Duration::from_millis(1)).with_period(block_cadence),
        )),
    )
    .expect("bound payout trigger action");
    let trigger = Trigger::new(trigger_id.clone(), action);
    crate::smartcontracts::isi::triggers::isi::register_trigger_internal(
        &binding.treasury_account_id,
        state_tx,
        trigger,
        None,
    )
    .expect("register exact bound payout trigger");
    trigger_id
}

pub(crate) fn with_validation_fee_payout_state_at_height(
    height: u64,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &[u8], Hash),
) {
    with_validation_fee_payout_state_at_time(height, 0, test)
}
pub(crate) fn with_validation_fee_payout_state_at_time(
    height: u64,
    timestamp_ms: u64,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &[u8], Hash),
) {
    with_validation_fee_payout_component_state(
        height,
        timestamp_ms,
        PayoutComponentSource::Unowned,
        test,
    );
}

/// Retain a finite invocation owner before opening a direct component fixture.
/// This does not authenticate a Network input or authorize publication.
pub(crate) fn with_validation_fee_payout_invocation_at_time(
    height: u64,
    timestamp_ms: u64,
    invocation: Hash,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &[u8], Hash),
) {
    with_validation_fee_payout_component_state(
        height,
        timestamp_ms,
        PayoutComponentSource::Invocation(invocation),
        test,
    );
}

/// Own only the finite mandatory-purpose component scope for an idle maintenance test.
/// This grants neither complete carrier inventory nor publication authority.
pub(crate) fn with_validation_fee_payout_protocol_at_time(
    height: u64,
    timestamp_ms: u64,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &[u8], Hash),
) {
    with_validation_fee_payout_component_state(
        height,
        timestamp_ms,
        PayoutComponentSource::Mandatory,
        test,
    );
}

pub(crate) fn with_validation_fee_payout_block_at_time(
    height: u64,
    timestamp_ms: u64,
    test: impl FnOnce(&mut crate::state::StateBlock<'_>, &AccountId, &[u8], Hash),
) {
    // Contract reads require immutable scope authenticated by the actual root.
    // The later header remains an isolated component fixture, not certified history.
    let (chain, deployer, code, code_hash) =
        signed_original_fixtures::signed_fee_registry_root_fixture();
    let state = chain.state();
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("test height is non-zero"),
        state.view().latest_block_hash(),
        None,
        timestamp_ms,
        0,
    );
    let mut block = state.block(header);
    test(&mut block, &deployer, &code, code_hash);
}

enum PayoutComponentSource {
    Unowned,
    Invocation(Hash),
    Mandatory,
}

fn with_validation_fee_payout_component_state(
    height: u64,
    timestamp_ms: u64,
    invocation: PayoutComponentSource,
    test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &[u8], Hash),
) {
    // Execute the original signed genesis; committed root metadata is never seeded by hand.
    // The requested height is only this component projection, not certified native history.
    let (chain, deployer, code, code_hash) =
        signed_original_fixtures::signed_fee_registry_root_fixture();
    let state = std::sync::Arc::clone(chain.state());
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("test height is non-zero"),
        state.view().latest_block_hash(),
        None,
        timestamp_ms,
        0,
    );
    let mut block = state.block(header);
    // Retain each component's explicit finite purpose before borrowing State.
    // This grants no Network admission or block publication authority.
    let mut state_tx = match invocation {
        PayoutComponentSource::Invocation(hash) => block.transaction_for_fastpq_testing(hash),
        PayoutComponentSource::Mandatory => block.transaction_for_fastpq_protocol_testing(),
        PayoutComponentSource::Unowned => block.transaction(),
    };
    let deployment_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    crate::smartcontracts::Execute::execute(
        iroha_data_model::isi::Grant::account_permission(deployment_permission, deployer.clone()),
        &deployer,
        &mut state_tx,
    )
    .expect("grant contract lifecycle authority");
    test(&mut state_tx, &deployer, &code, code_hash);
}

#[test]
fn payout_component_quantity_requires_exact_retained_invocation() {
    use crate::smartcontracts::Execute;
    let invocation = Hash::new(b"payout component quantity source");
    let check = |state_tx: &mut StateTransaction<'_, '_>, retained: bool| {
        assert_eq!(
            crate::sumeragi::lanes::routing::read_committed_root_scope(&state_tx.world).unwrap(),
            Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
        );
        let owner = account(2);
        let recipient = account(3);
        let source = AssetId::new(fee_asset(), owner.clone());
        let destination = AssetId::new(fee_asset(), recipient.clone());
        **state_tx
            .world
            .asset_or_insert_exact(&source, Quantity::zero())
            .unwrap() = Quantity::from(10_u32);
        let result =
            Transfer::asset_quantity(source.clone(), 1_u32, recipient).execute(&owner, state_tx);
        if retained {
            result.expect("the original finite component invocation owns its transfer");
            assert_eq!(state_tx.tx_call_hash, Some(invocation));
            assert_eq!(state_tx.retail_fee_transcripts_for_test().len(), 1);
            assert_eq!(
                state_tx.retail_fee_transcripts_for_test()[0].batch_hash,
                invocation
            );
            assert_eq!(
                state_tx.world.assets.get(&source).unwrap().as_ref(),
                &Quantity::from(9_u32)
            );
            assert_eq!(
                state_tx.world.assets.get(&destination).unwrap().as_ref(),
                &Quantity::one()
            );
        } else {
            let error = result.expect_err("a copied or substituted hash cannot grant custody");
            assert!(
                error
                    .to_string()
                    .contains("FASTPQ source has no retained producer invocation")
            );
            assert_eq!(
                state_tx.world.assets.get(&source).unwrap().as_ref(),
                &Quantity::from(10_u32)
            );
            assert!(state_tx.world.assets.get(&destination).is_none());
            assert!(state_tx.retail_fee_transcripts_for_test().is_empty());
        }
    };
    with_validation_fee_payout_state_at_time(2, 0, |state_tx, _, _, _| {
        state_tx.tx_call_hash = Some(invocation);
        check(state_tx, false);
    });
    with_validation_fee_payout_invocation_at_time(2, 0, invocation, |state_tx, _, _, _| {
        state_tx.tx_call_hash = Some(Hash::new(b"substituted component source"));
        check(state_tx, false);
    });
    with_validation_fee_payout_invocation_at_time(2, 0, invocation, |state_tx, _, _, _| {
        check(state_tx, true);
    });
}

pub(crate) fn activate_bound_payout_runtime(
    state_tx: &mut StateTransaction<'_, '_>,
    deployer: &AccountId,
    code: &[u8],
    code_hash: Hash,
    nonce: u64,
    ds_asset_id: AssetDefinitionId,
    trigger_id: &str,
) -> BoundPayoutRuntimeFixture {
    use iroha_data_model::smart_contract::ContractAddress;
    use iroha_model_base::topology::DataSpaceId;
    let contract_address = ContractAddress::derive(
        &state_tx.network_id,
        deployer,
        nonce,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive payout contract address");
    state_tx
        .world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), deployer.clone());
    crate::smartcontracts::code::activate_instance(
        deployer,
        contract_address.clone(),
        1,
        code_hash,
        state_tx,
    )
    .expect("activate payout contract instance");
    let mut binding = treasury_payout_binding(contract_address.clone(), code);
    binding.ds_asset_id = ds_asset_id;
    let trigger_id = register_bound_payout_time_trigger(state_tx, &binding, code_hash, trigger_id);
    let _ = trigger_id;
    let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
    feed.feed_id = binding.reference_feed_id.clone();
    feed.feed_config_version =
        iroha_data_model::oracle::FeedConfigVersion(binding.reference_feed_config_version);
    feed.providers = binding.reference_provider_accounts.clone();
    feed.min_signers = 3;
    feed.committee_size = 5;
    state_tx
        .world
        .oracle_feeds
        .insert(feed.feed_id.clone(), feed);
    BoundPayoutRuntimeFixture { binding }
}

fn transfer(
    from: &AccountId,
    asset_definition: &AssetDefinitionId,
    amount: Quantity,
    to: &AccountId,
) -> InstructionBox {
    Transfer::asset_quantity(
        AssetId::new(asset_definition.clone(), from.clone()),
        amount,
        to.clone(),
    )
    .into()
}

fn canonical_treasury_payout_plan(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    xor_out: Quantity,
) -> Vec<InstructionBox> {
    treasury_payout_plan(
        binding,
        quantity_from_minor_units_u128(u128::from(binding.max_sbd_per_attempt_minor), 2)
            .expect("batch"),
        xor_out,
    )
}

fn treasury_payout_plan(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    debit_ds: Quantity,
    xor_out: Quantity,
) -> Vec<InstructionBox> {
    let mut instructions = vec![
        transfer(
            &binding.treasury_account_id,
            &binding.ds_asset_id,
            debit_ds,
            &binding.pool_vault_account_id,
        ),
        transfer(
            &binding.pool_vault_account_id,
            &binding.xor_asset_id,
            xor_out.clone(),
            &binding.treasury_account_id,
        ),
    ];
    instructions.push(transfer(
        &binding.treasury_account_id,
        &binding.xor_asset_id,
        xor_out,
        &binding.reward_pool_account_id,
    ));
    instructions
}

fn ordered_treasury_payout_plan(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    instructions: &[InstructionBox],
) -> Vec<(AccountId, InstructionBox)> {
    instructions
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, instruction)| {
            let authority = if index < 2 {
                &binding.pool_vault_account_id
            } else {
                &binding.treasury_account_id
            };
            (authority.clone(), instruction)
        })
        .collect()
}

fn grouped_treasury_payout_plan(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    instructions: &[InstructionBox],
) -> std::collections::BTreeMap<AccountId, Vec<InstructionBox>> {
    let mut groups = std::collections::BTreeMap::new();
    for (authority, instruction) in ordered_treasury_payout_plan(binding, instructions) {
        groups
            .entry(authority)
            .or_insert_with(Vec::new)
            .push(instruction);
    }
    groups
}

fn assert_treasury_payout_plan_mismatch(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    groups: &std::collections::BTreeMap<AccountId, Vec<InstructionBox>>,
    ordered: &[(AccountId, InstructionBox)],
) {
    let terms = ValidationFeePayoutTerms {
        debit_ds: "10".parse().expect("SBD"),
        min_xor_out: "19.8".parse().expect("reference minimum"),
        xor_scale: 9,
    };
    assert!(matches!(
        validate_treasury_payout_effect_plan(groups, ordered, binding, &terms),
        Ok(false)
            | Err(
                ValidationFeeAdmissionError::TreasuryPayoutEffectPlanMismatch { .. }
                    | ValidationFeeAdmissionError::TreasuryPayoutArithmeticFailure
            )
    ));
}

pub(crate) struct BoundPayoutRuntimeFixture {
    pub(crate) binding: ValidationFeeTreasuryPayoutBindingV1,
}

#[test]
fn treasury_payout_runtime_uses_canonical_complete_artifact_hash() {
    use sha2::{Digest as _, Sha256};
    with_validation_fee_payout_state_at_height(10, |stx, deployer, code, registered_hash| {
        let mut binding = activate_bound_payout_runtime(
            stx,
            deployer,
            code,
            registered_hash,
            90,
            fee_asset(),
            "canonical_artifact_payout",
        )
        .binding;
        assert_eq!(binding.code_hash, <[u8; 32]>::from(registered_hash));
        stx.world.bind_inactive_contract_subject_for_testing(
            binding.pool_contract_address.clone(),
            deployer.clone(),
        );
        crate::smartcontracts::code::activate_instance(
            deployer,
            binding.pool_contract_address.clone(),
            1,
            registered_hash,
            stx,
        )
        .unwrap();
        binding.pool_code_hash = registered_hash.into();
        validate_treasury_payout_binding_contract_subject(&binding, 2, stx).unwrap();
        let context = crate::executor::ContractRuntimeExecutionContext {
            contract_address: binding.contract_address.clone(),
            contract_subject: binding.treasury_account_id.clone(),
            contract_alias: None,
            entrypoint: binding.entrypoint.to_string(),
        };
        let origin = OpaqueDeferredRuntimeOrigin::new(&context, code);
        assert!(
            runtime_origin_matches_payout_binding(&binding, stx, &origin)
                .expect("complete exact runtime binding read")
        );
        let plain_sha: [u8; 32] = Sha256::digest(code).into();
        assert_ne!(plain_sha, binding.code_hash);
        let mut wrong_wrapper = binding.clone();
        wrong_wrapper.code_hash = plain_sha;
        assert!(validate_treasury_payout_binding_contract_subject(&wrong_wrapper, 2, stx).is_err());
        assert!(
            !runtime_origin_matches_payout_binding(&wrong_wrapper, stx, &origin)
                .expect("complete mismatched runtime binding read")
        );
        let mut wrong_pool = binding;
        wrong_pool.pool_code_hash = plain_sha;
        assert!(validate_treasury_payout_binding_contract_subject(&wrong_pool, 2, stx).is_err());
    });
}

#[test]
fn treasury_payout_effect_plan_rejects_every_unbound_substitution() {
    let binding = treasury_payout_binding(test_contract_address(), b"bound-pool");
    let treasury = binding.treasury_account_id.clone();
    let canonical = canonical_treasury_payout_plan(&binding, Quantity::from(20_u64));
    let canonical_groups = grouped_treasury_payout_plan(&binding, &canonical);
    let canonical_ordered = ordered_treasury_payout_plan(&binding, &canonical);
    let terms = ValidationFeePayoutTerms {
        debit_ds: "10".parse().expect("SBD"),
        min_xor_out: "19.8".parse().expect("minimum"),
        xor_scale: 9,
    };
    assert!(
        validate_treasury_payout_effect_plan(
            &canonical_groups,
            &canonical_ordered,
            &binding,
            &terms,
        )
        .expect("the exact three-transfer plan is well formed")
    );
    let collapsed = std::collections::BTreeMap::from([(treasury.clone(), canonical.clone())]);
    let collapsed_ordered = canonical
        .iter()
        .cloned()
        .map(|instruction| (treasury.clone(), instruction))
        .collect::<Vec<_>>();
    assert_treasury_payout_plan_mismatch(&binding, &collapsed, &collapsed_ordered);
    let mut missing = canonical.clone();
    missing.pop();
    let missing_groups = grouped_treasury_payout_plan(&binding, &missing);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &missing_groups,
        &ordered_treasury_payout_plan(&binding, &missing),
    );
    let mut extra = canonical.clone();
    extra.push(canonical[2].clone());
    let extra_groups = grouped_treasury_payout_plan(&binding, &extra);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &extra_groups,
        &ordered_treasury_payout_plan(&binding, &extra),
    );
    let mut reordered = canonical_ordered.clone();
    reordered.swap(0, 1);
    assert_treasury_payout_plan_mismatch(&binding, &canonical_groups, &reordered);
    let mut wrong_batch = canonical.clone();
    wrong_batch[0] = transfer(
        &treasury,
        &binding.ds_asset_id,
        Quantity::from(2_u64),
        &binding.pool_vault_account_id,
    );
    let wrong_batch_groups = grouped_treasury_payout_plan(&binding, &wrong_batch);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &wrong_batch_groups,
        &ordered_treasury_payout_plan(&binding, &wrong_batch),
    );
    let mut wrong_ds_asset = canonical.clone();
    wrong_ds_asset[0] = transfer(
        &treasury,
        &binding.xor_asset_id,
        quantity_from_minor_units_u128(u128::from(binding.max_sbd_per_attempt_minor), 2)
            .expect("batch"),
        &binding.pool_vault_account_id,
    );
    let wrong_ds_asset_groups = grouped_treasury_payout_plan(&binding, &wrong_ds_asset);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &wrong_ds_asset_groups,
        &ordered_treasury_payout_plan(&binding, &wrong_ds_asset),
    );
    let mut wrong_vault = canonical.clone();
    wrong_vault[1] = transfer(
        &account(7),
        &binding.xor_asset_id,
        Quantity::from(20_u64),
        &treasury,
    );
    let wrong_vault_groups = grouped_treasury_payout_plan(&binding, &wrong_vault);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &wrong_vault_groups,
        &ordered_treasury_payout_plan(&binding, &wrong_vault),
    );
    for outside_bound in [0_u64, 19_u64] {
        let out_of_bounds = canonical_treasury_payout_plan(&binding, Quantity::from(outside_bound));
        let out_of_bounds_groups = grouped_treasury_payout_plan(&binding, &out_of_bounds);
        assert_treasury_payout_plan_mismatch(
            &binding,
            &out_of_bounds_groups,
            &ordered_treasury_payout_plan(&binding, &out_of_bounds),
        );
    }
    let mut wrong_validator = canonical.clone();
    wrong_validator[2] = transfer(
        &treasury,
        &binding.xor_asset_id,
        Quantity::from(5_u64),
        &account(7),
    );
    let wrong_validator_groups = grouped_treasury_payout_plan(&binding, &wrong_validator);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &wrong_validator_groups,
        &ordered_treasury_payout_plan(&binding, &wrong_validator),
    );
    let mut wrong_final_amount = canonical.clone();
    wrong_final_amount[2] = transfer(
        &treasury,
        &binding.xor_asset_id,
        Quantity::from(4_u64),
        &binding.reward_pool_account_id,
    );
    let wrong_final_groups = grouped_treasury_payout_plan(&binding, &wrong_final_amount);
    assert_treasury_payout_plan_mismatch(
        &binding,
        &wrong_final_groups,
        &ordered_treasury_payout_plan(&binding, &wrong_final_amount),
    );
    let mut changed_custody = binding.clone();
    changed_custody.reward_pool_account_id = account(7);
    assert_treasury_payout_plan_mismatch(&changed_custody, &canonical_groups, &canonical_ordered);
    let other_authority = account(7);
    let wrong_authority_groups =
        std::collections::BTreeMap::from([(other_authority.clone(), canonical.clone())]);
    let wrong_authority_ordered = canonical
        .iter()
        .cloned()
        .map(|instruction| (other_authority.clone(), instruction))
        .collect::<Vec<_>>();
    assert_treasury_payout_plan_mismatch(
        &binding,
        &wrong_authority_groups,
        &wrong_authority_ordered,
    );
    let mut split_groups =
        std::collections::BTreeMap::from([(treasury.clone(), canonical[..2].to_vec())]);
    split_groups.insert(other_authority.clone(), vec![canonical[2].clone()]);
    let mut split_ordered = canonical_ordered;
    split_ordered[2].0 = other_authority;
    assert_treasury_payout_plan_mismatch(&binding, &split_groups, &split_ordered);
}

#[test]
fn opaque_proved_axt_is_rejected_without_represented_payment_legs() {
    assert_eq!(reject_ivm_proved_completed_axt_effects(0), Ok(()));
    assert_eq!(
        reject_ivm_proved_completed_axt_effects(1),
        Err(ValidationFeeAdmissionError::OpaqueIvmProvedAxtEffects {
            completed_envelopes: 1
        })
    );
}

use iroha_data_model::governance::types::GovernanceCertificateId;
use iroha_data_model::validation_fee::{
    ValidationFeePayoutPolicyEntryV1, ValidationFeePayoutPolicyRegistryV1,
};

fn test_parliament_candidates() -> Vec<AccountId> {
    (220_u8..=243).map(account).collect()
}

pub(crate) fn test_authorization(
    proposal: &iroha_data_model::governance::types::ProposalKind,
    enacted_at_height: u64,
) -> ValidationFeeParliamentAuthorizationV1 {
    let attempt = crate::governance::parliament::enacted_parliament_attempt_for_testing(
        proposal,
        test_parliament_candidates(),
        &validation_fee_test_network_id(),
        enacted_at_height,
    );
    let governance_certificate = attempt
        .certificate()
        .cloned()
        .expect("test Parliament attempt retains its enacted certificate");
    let proposal_operator = match proposal {
        iroha_data_model::governance::types::ProposalKind::ValidationFeePolicy(proposal) => {
            proposal.proposal_operator.clone()
        }
        iroha_data_model::governance::types::ProposalKind::ValidationFeePayoutLifecycle(
            proposal,
        ) => proposal.proposal_operator.clone(),
        _ => panic!("validation-fee authorization fixture requires a validation-fee proposal"),
    };
    let governance_certificate_id = GovernanceCertificateId::derive_v1(&governance_certificate);
    ValidationFeeParliamentAuthorizationV1 {
        proposal_operator,
        proposal_fingerprint: proposal.fingerprint(),
        governance_certificate_id,
        governance_certificate,
        enacted_at_height,
    }
}

pub(crate) fn payout_registry_entry(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    revision: u64,
    enacted_at_height: u64,
) -> ValidationFeePayoutPolicyEntryV1 {
    let kind = ProposalKind::ValidationFeePayoutLifecycle(
        iroha_data_model::governance::types::ValidationFeePayoutLifecycleProposal {
            proposal_operator: account(250),
            payout_binding: binding.clone(),
        },
    );
    ValidationFeePayoutPolicyEntryV1 {
        revision,
        proposal_id: kind.fingerprint(),
        lifecycle_seal: binding
            .lifecycle_seal()
            .expect("canonical conversion binding"),
        payout_binding: binding.clone(),
        parliament_authorization: test_authorization(&kind, enacted_at_height),
    }
}

pub(crate) fn policy_registry(
    policies: &[ValidationFeePolicyV1],
    bindings: &[ValidationFeeTreasuryPayoutBindingV1],
) -> ValidationFeePolicyRegistryV1 {
    let registered_policies = policies
        .iter()
        .map(|policy| {
            let kind = ProposalKind::ValidationFeePolicy(
                iroha_data_model::governance::types::ValidationFeePolicyProposal {
                    proposal_operator: account(250),
                    policy: policy.clone(),
                },
            );
            ValidationFeePolicyRegistryEntryV1::from_enactment(
                policy.clone(),
                test_authorization(&kind, 20),
            )
            .expect("registry entry")
        })
        .collect();
    ValidationFeePolicyRegistryV1 {
        registered_policies,
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: bindings
                .iter()
                .enumerate()
                .map(|(index, binding)| {
                    payout_registry_entry(binding, index as u64 + 1, 20 + index as u64)
                })
                .collect(),
        },
    }
}

fn seed_authorized_proposal(
    kind: iroha_data_model::governance::types::ProposalKind,
    authorization: ValidationFeeParliamentAuthorizationV1,
    state_tx: &mut StateTransaction<'_, '_>,
) {
    let proposal_id = authorization.proposal_fingerprint;
    assert_eq!(kind.fingerprint(), proposal_id);
    assert_eq!(authorization.invariant_error(), None);
    let proposal_operator = authorization.proposal_operator.clone();
    let attempt = crate::governance::parliament::enacted_parliament_attempt_for_testing(
        &kind,
        test_parliament_candidates(),
        &validation_fee_test_network_id(),
        authorization.enacted_at_height,
    );
    assert_eq!(
        attempt.certificate(),
        Some(&authorization.governance_certificate),
        "authorization must retain the exact certificate produced by its Parliament attempt"
    );
    let attempt_id = attempt.attempt().id;
    state_tx
        .world
        .put_governance_proposal(
            proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: proposal_operator,
                kind,
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Enacted,
            },
        )
        .expect("validation-fee test proposal must satisfy first-release JSON bounds");
    state_tx
        .world
        .put_parliament_attempt_for_testing(attempt_id, attempt)
        .expect("persist exact enacted validation-fee Parliament attempt");
}

pub(crate) fn install_policy_registry_fixture(
    registry: &ValidationFeePolicyRegistryV1,
    state_tx: &mut StateTransaction<'_, '_>,
) {
    use iroha_data_model::governance::types::{
        ProposalKind, ValidationFeePayoutLifecycleProposal, ValidationFeePolicyProposal,
    };
    for entry in &registry.payout_policies.entries {
        seed_authorized_proposal(
            ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                proposal_operator: entry.parliament_authorization.proposal_operator.clone(),
                payout_binding: entry.payout_binding.clone(),
            }),
            entry.parliament_authorization.clone(),
            state_tx,
        );
    }
    for entry in &registry.registered_policies {
        seed_authorized_proposal(
            ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
                proposal_operator: entry.parliament_authorization.proposal_operator.clone(),
                policy: entry.policy.clone(),
            }),
            entry.parliament_authorization.clone(),
            state_tx,
        );
    }
    state_tx
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(registry.clone().into_custom_parameter()))
        .expect("valid fixture parameters");
}
