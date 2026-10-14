//! Shared certified-chain fixtures for the block execution benchmarks.
//!
//! Every benchmark block goes through [`CertifiedTestChain`]: a real signed genesis of the
//! fixed four-validator committee, proposals assembled by the leader's payload builder,
//! execution, application and publication by the node's `StateExecutor`, durable Kura frames
//! and a BLS-certified `CommitQC`. Fixture setup never publishes a block outside that path.

use iroha_core::{
    state::{StateReadOnly as _, World, WorldReadOnly as _},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::Account,
    asset::{AssetDefinition, AssetDefinitionId},
    domain::Domain,
    isi::InstructionBox,
    parameter::{
        CustomParameter, CustomParameterId, Parameter, SmartContractParameter,
        TransactionParameter, system::IVM_HEAP_MAX_BYTES,
    },
    prelude::*,
    transaction::IvmBytecode,
};
use iroha_executor_data_model::permission::{
    account::CanUnregisterAccount, asset_definition::CanUnregisterAssetDefinition,
};
use iroha_model_base::domain::DomainId;
use std::num::{NonZeroU16, NonZeroU64};

/// Creation time of the benchmark genesis, in milliseconds.
pub const GENESIS_TIME_MS: u64 = 1_000;

/// Per-block IVM gas allowance of the benchmark chains.
///
/// The larger fixture registers 1,000 accounts and asset definitions in one block. Metering
/// stays enabled with an explicit allowance for that measured workload.
pub const GAS_LIMIT_PER_BLOCK: u64 = 64_000_000;

/// Start a certified chain for the benchmark workload.
///
/// The initial World holds `owner`, the benchmark `domains` owned by `owner` (the State seeds
/// their SNS name leases), explicit authority for `owner` to unregister `accounts` (universal
/// accounts do not give their registrant ownership) and lifted transaction and executor
/// limits. The signed genesis raises the per-block gas allowance and installs the canonical
/// guest executor from `defaults/executor.to` when that artifact is present.
///
/// # Panics
///
/// The signed benchmark genesis does not apply, or the chain does not run with the benchmark
/// parameters.
pub fn start_chain(
    owner: &AccountId,
    domains: &[DomainId],
    accounts: &[AccountId],
) -> CertifiedTestChain {
    let mut world = World::with(
        domains
            .iter()
            .map(|domain_id| Domain::new(domain_id.clone()).build(owner)),
        [Account::new(owner.clone()).build(owner)],
        [],
    );
    world.account_permissions_mut_for_testing().insert(
        owner.clone(),
        accounts
            .iter()
            .map(|account| {
                Permission::from(CanUnregisterAccount {
                    account: account.clone(),
                })
            })
            .collect(),
    );
    {
        // The signed genesis parameter snapshot never carries transaction or executor
        // limits, so the initial World supplies them.
        let mut block = world.block();
        for parameter in world_parameters() {
            block
                .parameters
                .get_mut()
                .set_parameter(parameter)
                .expect("valid fixture parameters");
        }
        block.commit();
    }
    let mut config = TestChainConfig::new(world, GENESIS_TIME_MS);
    config.genesis_parameters.push(gas_limit_parameter());
    if let Some(executor) = canonical_executor() {
        config
            .genesis_instructions
            .push(Upgrade::new(executor).into());
    }
    let chain = CertifiedTestChain::start(config).expect("signed benchmark genesis applies");
    {
        let view = chain.state().view();
        let installed = view.world().parameters().parameters().collect::<Vec<_>>();
        for parameter in world_parameters()
            .into_iter()
            .chain([gas_limit_parameter()])
        {
            assert!(
                installed.contains(&parameter),
                "the benchmark chain runs with {parameter}"
            );
        }
    }
    chain
}

/// The per-block IVM gas allowance, signed by the benchmark genesis.
fn gas_limit_parameter() -> Parameter {
    Parameter::Custom(CustomParameter::new(
        CustomParameterId::new(
            "ivm_gas_limit_per_block"
                .parse()
                .expect("gas parameter name"),
        ),
        iroha_primitives::json::Json::new(GAS_LIMIT_PER_BLOCK),
    ))
}

/// Transaction and executor limits of the benchmark World, lifted as far as their types allow
/// (the executor heap stays within the ABI heap window).
fn world_parameters() -> [Parameter; 8] {
    [
        Parameter::Transaction(TransactionParameter::MaxSignatures(NonZeroU64::MAX)),
        Parameter::Transaction(TransactionParameter::MaxInstructions(NonZeroU64::MAX)),
        Parameter::Transaction(TransactionParameter::IvmBytecodeSize(NonZeroU64::MAX)),
        Parameter::Transaction(TransactionParameter::MaxTxBytes(NonZeroU64::MAX)),
        Parameter::Transaction(TransactionParameter::MaxDecompressedBytes(NonZeroU64::MAX)),
        Parameter::Transaction(TransactionParameter::MaxMetadataDepth(NonZeroU16::MAX)),
        Parameter::Executor(SmartContractParameter::Fuel(NonZeroU64::MAX)),
        Parameter::Executor(SmartContractParameter::Memory(
            NonZeroU64::new(IVM_HEAP_MAX_BYTES).expect("ABI heap window is non-zero"),
        )),
    ]
}

/// The canonical guest executor, when `defaults/executor.to` is present and non-empty.
fn canonical_executor() -> Option<Executor> {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../defaults/executor.to");
    let bytecode = std::fs::read(path)
        .ok()
        .filter(|bytecode| !bytecode.is_empty())?;
    Some(Executor::new(IvmBytecode::from_compiled(bytecode)))
}

/// Commit `instructions` as one transaction of `authority` in the chain's next certified block.
///
/// The transaction is created at the tip's block time, so the block follows the tip by the
/// chain's one-millisecond cadence and the workload is deterministic.
///
/// # Panics
///
/// The block does not execute, or its transaction does not execute successfully.
pub fn commit_instructions(
    chain: &mut CertifiedTestChain,
    authority: &KeyPair,
    instructions: impl IntoIterator<Item = InstructionBox>,
) {
    let height = chain.height();
    let created_ms = {
        let view = chain.state().view();
        let tip = view
            .latest_block()
            .expect("the chain tip can be read")
            .expect("the chain has an applied tip");
        u64::try_from(tip.header().creation_time().as_millis()).expect("block time fits u64")
    };
    let transaction = chain.sign(authority, instructions, created_ms);
    assert_eq!(
        chain.commit(vec![transaction]),
        [true],
        "benchmark transactions must execute successfully"
    );
    assert_eq!(chain.height(), height + 1);
}

fn domain_for_index(domains: &[DomainId], total_items: usize, index: usize) -> Option<&DomainId> {
    if domains.is_empty() || total_items == 0 {
        return None;
    }
    let domain_index = index.saturating_mul(domains.len()) / total_items;
    domains.get(domain_index.min(domains.len() - 1))
}

/// Return the semantic name assigned by [`generate_ids`] to an asset fixture.
///
/// # Panics
///
/// Panics when the fixture collection cannot be partitioned evenly by domain.
pub fn generated_asset_definition_name(
    domain_count: usize,
    total_assets: usize,
    index: usize,
) -> String {
    assert!(
        domain_count > 0,
        "benchmark fixture needs at least one domain"
    );
    assert!(
        total_assets > 0,
        "benchmark fixture needs at least one asset"
    );
    assert_eq!(
        total_assets % domain_count,
        0,
        "benchmark assets must be partitioned evenly by domain"
    );
    let assets_per_domain = total_assets / domain_count;
    format!(
        "non_inlinable_asset_definition_name_{}",
        index % assets_per_domain
    )
}

/// Register every account and asset definition and grant `owner_id` the authority to
/// unregister each asset definition.
pub fn populate_state(
    domains: &[DomainId],
    accounts: &[AccountId],
    asset_definitions: &[AssetDefinitionId],
    owner_id: &AccountId,
) -> Vec<InstructionBox> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for account_id in accounts {
        let account = Account::new(account_id.clone());
        instructions.push(Register::account(account).into());
    }
    for (index, asset_definition_id) in asset_definitions.iter().enumerate() {
        let asset_definition = AssetDefinition::numeric(
            asset_definition_id.clone(),
            generated_asset_definition_name(domains.len(), asset_definitions.len(), index),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(
                domain_for_index(domains, asset_definitions.len(), index)
                    .expect("benchmark asset has a declared owning domain")
                    .clone(),
            ),
        );
        instructions.push(Register::asset_definition(asset_definition).into());
        let can_unregister_asset_definition = Grant::account_permission(
            CanUnregisterAssetDefinition {
                asset_definition: asset_definition_id.clone(),
            },
            owner_id.clone(),
        );
        instructions.push(can_unregister_asset_definition.into());
    }
    instructions
}

/// Unregister every `nth` account and asset definition of each domain, and all children of
/// every `nth` domain.
pub fn delete_every_nth(
    domains: &[DomainId],
    accounts: &[AccountId],
    asset_definitions: &[AssetDefinitionId],
    nth: usize,
) -> Vec<InstructionBox> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for (i, domain_id) in domains.iter().enumerate() {
        // Runtime domain re-registration is intentionally unavailable; churn the
        // domain's children while retaining its genesis-created parent.
        let delete_all_children = i % nth == 0;
        for (j, account_id) in accounts
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                domain_for_index(domains, accounts.len(), *index).is_some_and(|d| d == domain_id)
            })
            .map(|(_, account_id)| account_id)
            .enumerate()
        {
            if delete_all_children || j % nth == 0 {
                instructions.push(Unregister::account(account_id.clone()).into());
            }
        }
        for (k, asset_definition_id) in asset_definitions
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                domain_for_index(domains, asset_definitions.len(), *index)
                    .is_some_and(|domain| domain == domain_id)
            })
            .map(|(_, asset_definition_id)| asset_definition_id)
            .enumerate()
        {
            if delete_all_children || k % nth == 0 {
                instructions.push(Unregister::asset_definition(asset_definition_id.clone()).into());
            }
        }
    }
    instructions
}

/// Register again everything [`delete_every_nth`] unregistered with the same `nth`.
pub fn restore_every_nth(
    domains: &[DomainId],
    accounts: &[AccountId],
    asset_definitions: &[AssetDefinitionId],
    nth: usize,
) -> Vec<InstructionBox> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for (i, domain_id) in domains.iter().enumerate() {
        // Domains remain present so this restore batch uses only ordinary
        // post-genesis instructions.
        for (j, account_id) in accounts
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                domain_for_index(domains, accounts.len(), *index).is_some_and(|d| d == domain_id)
            })
            .map(|(_, account_id)| account_id)
            .enumerate()
        {
            if j % nth == 0 || i % nth == 0 {
                let account = Account::new(account_id.clone());
                instructions.push(Register::account(account).into());
            }
        }
        for (k, (asset_index, asset_definition_id)) in asset_definitions
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                domain_for_index(domains, asset_definitions.len(), *index)
                    .is_some_and(|domain| domain == domain_id)
            })
            .enumerate()
        {
            if k % nth == 0 || i % nth == 0 {
                let asset_definition = AssetDefinition::numeric(
                    asset_definition_id.clone(),
                    generated_asset_definition_name(
                        domains.len(),
                        asset_definitions.len(),
                        asset_index,
                    ),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    Some(domain_id.clone()),
                );
                instructions.push(Register::asset_definition(asset_definition).into());
            }
        }
    }
    instructions
}

fn construct_domain_id(i: usize) -> DomainId {
    DomainId::try_new(format!("non_inlinable_domain_name_{i}"), "universal").unwrap()
}

fn generate_account_id(seed: u128) -> AccountId {
    let mut seed_material = b"iroha-core-block-bench-account".to_vec();
    seed_material.extend_from_slice(&seed.to_le_bytes());
    let keypair = KeyPair::try_from_seed(seed_material, Algorithm::Ed25519)
        .expect("derive block benchmark account key");
    AccountId::new(keypair.public_key().clone())
}

fn construct_asset_definition_id(i: usize, domain_id: DomainId) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        domain_id,
        format!("non_inlinable_asset_definition_name_{i}")
            .parse()
            .unwrap(),
    )
}

/// Deterministic benchmark domains, accounts and asset definitions, partitioned by domain.
pub fn generate_ids(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
) -> (Vec<DomainId>, Vec<AccountId>, Vec<AssetDefinitionId>) {
    let mut domain_ids = Vec::new();
    let mut account_ids = Vec::new();
    let mut asset_definition_ids = Vec::new();
    for i in 0..domains {
        let domain_id = construct_domain_id(i);
        domain_ids.push(domain_id.clone());
        for account_idx in 0..accounts_per_domain {
            let seed = (i as u128) * accounts_per_domain as u128 + account_idx as u128;
            let account_id = generate_account_id(seed);
            account_ids.push(account_id)
        }
        for k in 0..assets_per_domain {
            let asset_definition_id = construct_asset_definition_id(k, domain_id.clone());
            asset_definition_ids.push(asset_definition_id);
        }
    }
    (domain_ids, account_ids, asset_definition_ids)
}

#[cfg(test)]
mod tests {

    #[test]
    fn start_chain_applies_the_benchmark_genesis() {
        let (domain_ids, account_ids, _) = generate_ids(2, 2, 2);
        let chain = start_chain(&ALICE_ID, &domain_ids, &account_ids);
        assert_eq!(chain.height(), 1);
        let view = chain.state().view();
        assert_eq!(view.height(), 1);
        assert!(
            view.latest_block()
                .expect("the benchmark genesis can be read")
                .is_some()
        );
        for domain_id in &domain_ids {
            assert!(view.world().domains().get(domain_id).is_some());
        }
        let permissions = view
            .world()
            .account_permissions()
            .get(&*ALICE_ID)
            .expect("the owner holds explicit removal authority");
        for account_id in &account_ids {
            assert!(
                permissions.contains(&Permission::from(CanUnregisterAccount {
                    account: account_id.clone(),
                }))
            );
        }
    }

    #[test]
    fn benchmark_world_makes_generated_children_registrable() {
        let (domain_ids, account_ids, asset_definition_ids) = generate_ids(1, 1, 1);
        let mut chain = start_chain(&ALICE_ID, &domain_ids, &account_ids);
        commit_instructions(
            &mut chain,
            &ALICE_KEYPAIR,
            populate_state(&domain_ids, &account_ids, &asset_definition_ids, &ALICE_ID),
        );
        commit_instructions(
            &mut chain,
            &ALICE_KEYPAIR,
            delete_every_nth(&domain_ids, &account_ids, &asset_definition_ids, 1),
        );
        commit_instructions(
            &mut chain,
            &ALICE_KEYPAIR,
            restore_every_nth(&domain_ids, &account_ids, &asset_definition_ids, 1),
        );
        assert_eq!(chain.height(), 4);
    }
}
