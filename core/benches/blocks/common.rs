use std::str::FromStr as _;

use eyre::Result;
use iroha_core::{
    block::{BlockBuilder, CommittedBlock},
    prelude::*,
    smartcontracts::Execute,
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
) -> Result<Vec<InstructionExpr>> {
    let mut instructions: Vec<InstructionExpr> = Vec::new();
    for i in 0..domains {
        let domain_id = DomainId::from_str(&i.to_string())?;
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
            let account_id = AccountId::new(Name::from_str(&j.to_string())?, domain_id.clone());
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
            let asset_definition_id =
                AssetDefinitionId::new(Name::from_str(&k.to_string())?, domain_id.clone());
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
    Ok(instructions)
}

pub fn delete_every_nth(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    nth: usize,
) -> Result<Vec<InstructionExpr>> {
    let mut instructions: Vec<InstructionExpr> = Vec::new();
    for i in 0..domains {
        let domain_id = DomainId::from_str(&i.to_string())?;
        if i % nth == 0 {
            instructions.push(UnregisterExpr::new(domain_id.clone()).into());
        } else {
            for j in 0..accounts_per_domain {
                if j % nth == 0 {
                    let account_id =
                        AccountId::new(Name::from_str(&j.to_string())?, domain_id.clone());
                    instructions.push(UnregisterExpr::new(account_id.clone()).into());
                }
            }
            for k in 0..assets_per_domain {
                if k % nth == 0 {
                    let asset_definition_id =
                        AssetDefinitionId::new(Name::from_str(&k.to_string())?, domain_id.clone());
                    instructions.push(UnregisterExpr::new(asset_definition_id).into());
                }
            }
        }
    }
    Ok(instructions)
}

pub fn restore_every_nth(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    nth: usize,
) -> Result<Vec<InstructionExpr>> {
    let mut instructions: Vec<InstructionExpr> = Vec::new();
    for i in 0..domains {
        let domain_id = DomainId::from_str(&i.to_string())?;
        if i % nth == 0 {
            let domain = Domain::new(domain_id.clone());
            instructions.push(RegisterExpr::new(domain).into());
        }
        for j in 0..accounts_per_domain {
            if j % nth == 0 || i % nth == 0 {
                let account_id = AccountId::new(Name::from_str(&j.to_string())?, domain_id.clone());
                let account = Account::new(account_id.clone(), []);
                instructions.push(RegisterExpr::new(account).into());
            }
        }
        for k in 0..assets_per_domain {
            if k % nth == 0 || i % nth == 0 {
                let asset_definition_id =
                    AssetDefinitionId::new(Name::from_str(&k.to_string())?, domain_id.clone());
                let asset_definition = AssetDefinition::new(
                    asset_definition_id,
                    iroha_data_model::asset::AssetValueType::Quantity,
                );
                instructions.push(RegisterExpr::new(asset_definition).into());
            }
        }
    }
    Ok(instructions)
}

pub fn build_wsv(account_id: &AccountId, key_pair: &KeyPair) -> WorldStateView {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let mut wsv = WorldStateView::new(World::with([], UniqueVec::new()), kura);
    wsv.config.transaction_limits = TransactionLimits::new(u64::MAX, u64::MAX);
    wsv.config.wasm_runtime_config.fuel_limit = u64::MAX;
    wsv.config.wasm_runtime_config.max_memory = u32::MAX;

    {
        let domain = Domain::new(account_id.domain_id.clone());
        RegisterExpr::new(domain)
            .execute(account_id, &mut wsv)
            .expect("Failed to register domain");
        let account = Account::new(account_id.clone(), [key_pair.public_key().clone()]);
        RegisterExpr::new(account)
            .execute(account_id, &mut wsv)
            .expect("Failed to register account");
    }

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
