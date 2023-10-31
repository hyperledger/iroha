use std::str::FromStr as _;

use iroha_core::{
    block::{BlockBuilder, CommittedBlock},
    prelude::*,
    query::store::LiveQueryStore,
    smartcontracts::{Execute, Registrable as _},
    sumeragi::network_topology::Topology,
    wsv::World,
};
use iroha_data_model::{
    account::Account,
    asset::{AssetDefinition, AssetDefinitionId},
    domain::Domain,
    isi::InstructionExpr,
    prelude::*,
    transaction::TransactionLimits,
};
use iroha_primitives::unique_vec::UniqueVec;
use serde_json::json;

/// Create block
pub fn create_block(
    wsv: &mut WorldStateView,
    instructions: Vec<InstructionExpr>,
    account_id: AccountId,
    key_pair: KeyPair,
) -> CommittedBlock {
    let transaction = TransactionBuilder::new(account_id)
        .with_instructions(instructions)
        .sign(key_pair.clone())
        .unwrap();
    let limits = wsv.transaction_executor().transaction_limits;

    let topology = Topology::new(UniqueVec::new());
    let block = BlockBuilder::new(
        vec![AcceptedTransaction::accept(transaction, &limits).unwrap()],
        topology.clone(),
        Vec::new(),
    )
    .chain(0, wsv)
    .sign(key_pair)
    .unwrap()
    .commit(&topology)
    .unwrap();

    // Verify that transactions are valid
    for tx in &block.payload().transactions {
        assert_eq!(tx.error, None);
    }

    block
}

pub fn populate_wsv(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    owner_id: &AccountId,
) -> Vec<InstructionExpr> {
    let mut instructions: Vec<InstructionExpr> = Vec::new();
    for i in 0..domains {
        let domain_id = construct_domain_id(i);
        let domain = Domain::new(domain_id.clone());
        instructions.push(RegisterExpr::new(domain).into());
        let can_unregister_domain = GrantExpr::new(
            PermissionToken::new(
                "CanUnregisterDomain".parse().unwrap(),
                &json!({ "domain_id": domain_id.clone() }),
            ),
            owner_id.clone(),
        );
        instructions.push(can_unregister_domain.into());
        for j in 0..accounts_per_domain {
            let account_id = construct_account_id(j, domain_id.clone());
            let account = Account::new(account_id.clone(), []);
            instructions.push(RegisterExpr::new(account).into());
            let can_unregister_account = GrantExpr::new(
                PermissionToken::new(
                    "CanUnregisterAccount".parse().unwrap(),
                    &json!({ "account_id": account_id.clone() }),
                ),
                owner_id.clone(),
            );
            instructions.push(can_unregister_account.into());
        }
        for k in 0..assets_per_domain {
            let asset_definition_id = construct_asset_definition_id(k, domain_id.clone());
            let asset_definition = AssetDefinition::new(
                asset_definition_id.clone(),
                iroha_data_model::asset::AssetValueType::Quantity,
            );
            instructions.push(RegisterExpr::new(asset_definition).into());
            let can_unregister_asset_definition = GrantExpr::new(
                PermissionToken::new(
                    "CanUnregisterAssetDefinition".parse().unwrap(),
                    &json!({ "asset_definition_id": asset_definition_id }),
                ),
                owner_id.clone(),
            );
            instructions.push(can_unregister_asset_definition.into());
        }
    }
    instructions
}

pub fn delete_every_nth(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    nth: usize,
) -> Vec<InstructionExpr> {
    let mut instructions: Vec<InstructionExpr> = Vec::new();
    for i in 0..domains {
        let domain_id = construct_domain_id(i);
        if i % nth == 0 {
            instructions.push(UnregisterExpr::new(domain_id.clone()).into());
        } else {
            for j in 0..accounts_per_domain {
                if j % nth == 0 {
                    let account_id = construct_account_id(j, domain_id.clone());
                    instructions.push(UnregisterExpr::new(account_id.clone()).into());
                }
            }
            for k in 0..assets_per_domain {
                if k % nth == 0 {
                    let asset_definition_id = construct_asset_definition_id(k, domain_id.clone());
                    instructions.push(UnregisterExpr::new(asset_definition_id).into());
                }
            }
        }
    }
    instructions
}

pub fn restore_every_nth(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    nth: usize,
) -> Vec<InstructionExpr> {
    let mut instructions: Vec<InstructionExpr> = Vec::new();
    for i in 0..domains {
        let domain_id = construct_domain_id(i);
        if i % nth == 0 {
            let domain = Domain::new(domain_id.clone());
            instructions.push(RegisterExpr::new(domain).into());
        }
        for j in 0..accounts_per_domain {
            if j % nth == 0 || i % nth == 0 {
                let account_id = construct_account_id(j, domain_id.clone());
                let account = Account::new(account_id.clone(), []);
                instructions.push(RegisterExpr::new(account).into());
            }
        }
        for k in 0..assets_per_domain {
            if k % nth == 0 || i % nth == 0 {
                let asset_definition_id = construct_asset_definition_id(k, domain_id.clone());
                let asset_definition = AssetDefinition::new(
                    asset_definition_id,
                    iroha_data_model::asset::AssetValueType::Quantity,
                );
                instructions.push(RegisterExpr::new(asset_definition).into());
            }
        }
    }
    instructions
}

pub fn build_wsv(account_id: &AccountId, key_pair: &KeyPair) -> WorldStateView {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::test().start();
    let mut domain = Domain::new(account_id.domain_id.clone()).build(account_id);
    domain.accounts.insert(
        account_id.clone(),
        Account::new(account_id.clone(), [key_pair.public_key().clone()]).build(account_id),
    );
    let mut wsv = WorldStateView::new(World::with([domain], UniqueVec::new()), kura, query_handle);
    wsv.config.transaction_limits = TransactionLimits::new(u64::MAX, u64::MAX);
    wsv.config.wasm_runtime_config.fuel_limit = u64::MAX;
    wsv.config.wasm_runtime_config.max_memory = u32::MAX;

    {
        let path_to_executor = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/peer/executor.wasm");
        let wasm = std::fs::read(&path_to_executor)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", path_to_executor.display()));
        let executor = Executor::new(WasmSmartContract::from_compiled(wasm));
        UpgradeExpr::new(executor)
            .execute(account_id, &mut wsv)
            .expect("Failed to load executor");
    }

    wsv
}

fn construct_domain_id(i: usize) -> DomainId {
    DomainId::from_str(&format!("non_inlinable_domain_name_{i}")).unwrap()
}

fn construct_account_id(i: usize, domain_id: DomainId) -> AccountId {
    AccountId::new(
        Name::from_str(&format!("non_inlinable_account_name_{i}")).unwrap(),
        domain_id,
    )
}

fn construct_asset_definition_id(i: usize, domain_id: DomainId) -> AssetDefinitionId {
    AssetDefinitionId::new(
        Name::from_str(&format!("non_inlinable_asset_definition_name_{i}")).unwrap(),
        domain_id,
    )
}
