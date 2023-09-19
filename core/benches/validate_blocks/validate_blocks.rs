#![allow(missing_docs, clippy::restriction)]

use std::{collections::BTreeSet, str::FromStr as _};

use eyre::Result;
use iroha_core::{
    block::{BlockBuilder, CommittedBlock},
    prelude::*,
    smartcontracts::Execute,
    sumeragi::network_topology::Topology,
    wsv::World,
};
use iroha_data_model::{
    asset::{AssetDefinition, AssetDefinitionId},
    isi::InstructionBox,
    prelude::*,
    transaction::TransactionLimits,
};

/// Create block and validate it
fn create_block(
    instructions: Vec<InstructionBox>,
    account_id: AccountId,
    key_pair: KeyPair,
    wsv: &mut WorldStateView,
) -> Result<CommittedBlock> {
    let transaction = TransactionBuilder::new(account_id)
        .with_instructions(instructions)
        .sign(key_pair.clone())?;

    let transaction_limits = &wsv.transaction_validator().transaction_limits;
    let transaction = AcceptedTransaction::accept(transaction, transaction_limits)?;

    let topology = Topology::new(Vec::new());
    let pending_block = BlockBuilder::new(vec![transaction], topology.clone(), Vec::new())
        .chain_first(wsv)
        .sign(key_pair)
        .unwrap()
        .commit(&topology)
        .unwrap();

    Ok(pending_block)
}

fn populate_wsv(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
) -> Result<Vec<InstructionBox>> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for i in 0..domains {
        let domain_id = DomainId::from_str(&i.to_string())?;
        let domain = Domain::new(domain_id.clone());
        instructions.push(RegisterBox::new(domain).into());
        for j in 0..accounts_per_domain {
            let account_id = AccountId::new(Name::from_str(&j.to_string())?, domain_id.clone());
            let account = Account::new(account_id.clone(), []);
            instructions.push(RegisterBox::new(account).into());
        }
        for k in 0..assets_per_domain {
            let asset_definition_id =
                AssetDefinitionId::new(Name::from_str(&k.to_string())?, domain_id.clone());
            let asset_definition = AssetDefinition::new(
                asset_definition_id,
                iroha_data_model::asset::AssetValueType::Quantity,
            );
            instructions.push(RegisterBox::new(asset_definition).into());
        }
    }
    Ok(instructions)
}

fn delete_every_nth(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    nth: usize,
) -> Result<Vec<InstructionBox>> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for i in 0..domains {
        let domain_id = DomainId::from_str(&i.to_string())?;
        if i % nth == 0 {
            instructions.push(UnregisterBox::new(domain_id.clone()).into());
        } else {
            for j in 0..accounts_per_domain {
                if j % nth == 0 {
                    let account_id =
                        AccountId::new(Name::from_str(&j.to_string())?, domain_id.clone());
                    instructions.push(UnregisterBox::new(account_id.clone()).into());
                }
            }
            for k in 0..assets_per_domain {
                if k % nth == 0 {
                    let asset_definition_id =
                        AssetDefinitionId::new(Name::from_str(&k.to_string())?, domain_id.clone());
                    instructions.push(UnregisterBox::new(asset_definition_id).into());
                }
            }
        }
    }
    Ok(instructions)
}

fn restore_every_nth(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    nth: usize,
) -> Result<Vec<InstructionBox>> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for i in 0..domains {
        let domain_id = DomainId::from_str(&i.to_string())?;
        if i % nth == 0 {
            let domain = Domain::new(domain_id.clone());
            instructions.push(RegisterBox::new(domain).into());
        }
        for j in 0..accounts_per_domain {
            if j % nth == 0 || i % nth == 0 {
                let account_id = AccountId::new(Name::from_str(&j.to_string())?, domain_id.clone());
                let account = Account::new(account_id.clone(), []);
                instructions.push(RegisterBox::new(account).into());
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
                instructions.push(RegisterBox::new(asset_definition).into());
            }
        }
    }
    Ok(instructions)
}

fn build_wsv(account_id: &AccountId, key_pair: &KeyPair) -> WorldStateView {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let mut wsv = WorldStateView::new(World::with([], BTreeSet::new()), kura);
    wsv.config.transaction_limits = TransactionLimits::new(u64::MAX, u64::MAX);

    {
        let domain = Domain::new(account_id.domain_id.clone());
        RegisterBox::new(domain)
            .execute(account_id, &mut wsv)
            .expect("Failed to register domain");
        let account = Account::new(account_id.clone(), [key_pair.public_key().clone()]);
        RegisterBox::new(account)
            .execute(account_id, &mut wsv)
            .expect("Failed to register account");
    }

    {
        let path_to_validator = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../configs/peer/validator.wasm");
        let wasm = std::fs::read(&path_to_validator)
            .unwrap_or_else(|_| panic!("Failed to read file: {}", path_to_validator.display()));
        let validator = Validator::new(WasmSmartContract::from_compiled(wasm));
        UpgradeBox::new(validator)
            .execute(account_id, &mut wsv)
            .expect("Failed to load validator");
    }

    wsv
}

#[derive(Clone)]
pub struct WsvValidateBlocks {
    wsv: WorldStateView,
    instructions: Vec<Vec<InstructionBox>>,
    key_pair: KeyPair,
    account_id: AccountId,
}

impl WsvValidateBlocks {
    /// Create [`WorldStateView`] and blocks for benchmarking
    ///
    /// # Errors
    /// - Failed to parse [`AccountId`]
    /// - Failed to generate [`KeyPair`]
    /// - Failed to create instructions for block
    pub fn setup() -> Result<Self> {
        let domains = 100;
        let accounts_per_domain = 1000;
        let assets_per_domain = 1000;
        let genesis_id: AccountId = "genesis@genesis".parse()?;
        let key_pair = KeyPair::generate()?;
        let wsv = build_wsv(&genesis_id, &key_pair);

        let nth = 100;
        let instructions = [
            populate_wsv(domains, accounts_per_domain, assets_per_domain),
            delete_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
            restore_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            wsv,
            instructions,
            key_pair,
            account_id: genesis_id,
        })
    }

    /// Run benchmark body.
    ///
    /// # Errors
    /// - Not enough blocks
    /// - Failed to apply block
    ///
    /// # Panics
    /// If wsv isn't one block ahead of finalized wsv.
    pub fn measure(
        Self {
            wsv,
            instructions,
            key_pair,
            account_id,
        }: Self,
    ) -> Result<()> {
        let mut finalized_wsv = wsv;
        let mut wsv = finalized_wsv.clone();

        for instructions in instructions {
            finalized_wsv = wsv.clone();
            let block = create_block(instructions, account_id.clone(), key_pair.clone(), &mut wsv)?;
            wsv.apply_without_execution(&block)?;
            assert_eq!(wsv.height(), finalized_wsv.height() + 1);
        }

        Ok(())
    }
}
