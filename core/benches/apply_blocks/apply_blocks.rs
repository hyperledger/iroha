#![allow(missing_docs, clippy::restriction)]

use std::{collections::BTreeSet, str::FromStr as _};

use eyre::Result;
use iroha_core::{
    block::{BlockBuilder, CommittedBlock},
    prelude::*,
    sumeragi::network_topology::Topology,
    wsv::World,
};
use iroha_data_model::{
    asset::{AssetDefinition, AssetDefinitionId},
    isi::InstructionBox,
    prelude::*,
};
use iroha_genesis::GenesisTransaction;

/// Create block
fn create_block(
    wsv: &mut WorldStateView,
    instructions: Vec<InstructionBox>,
    account_id: AccountId,
    key_pair: KeyPair,
) -> CommittedBlock {
    let transaction = TransactionBuilder::new(account_id)
        .with_instructions(instructions)
        .sign(key_pair.clone())
        .unwrap();

    let topology = Topology::new(Vec::new());
    BlockBuilder::new(
        vec![AcceptedTransaction::accept_genesis(GenesisTransaction(
            transaction,
        ))],
        topology.clone(),
        Vec::new(),
    )
    .chain(0, wsv)
    .sign(key_pair)
    .unwrap()
    .commit(&topology)
    .unwrap()
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

fn build_wsv(
    domains: usize,
    accounts_per_domain: usize,
    assets_per_domain: usize,
    account_id: AccountId,
    key_pair: KeyPair,
) -> Result<WorldStateView> {
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let mut wsv = WorldStateView::new(World::with([], BTreeSet::new()), kura);

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

    let block = create_block(&mut wsv, instructions, account_id, key_pair);
    wsv.apply(&block)?;
    Ok(wsv)
}

pub struct WsvApplyBlocks {
    wsv: WorldStateView,
    blocks: Vec<CommittedBlock>,
}

impl WsvApplyBlocks {
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
        let mut wsv = build_wsv(
            domains,
            accounts_per_domain,
            assets_per_domain,
            genesis_id.clone(),
            key_pair.clone(),
        )?;

        let nth = 100;
        let instructions = [
            delete_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
            restore_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

        let blocks = instructions
            .into_iter()
            .map(|instructions| {
                create_block(&mut wsv, instructions, genesis_id.clone(), key_pair.clone())
            })
            .collect();

        Ok(Self { wsv, blocks })
    }

    /// Run benchmark body.
    ///
    /// # Errors
    /// - Not enough blocks
    /// - Failed to apply block
    ///
    /// # Panics
    /// If wsv isn't one block ahead of finalized wsv.
    pub fn measure(Self { wsv, blocks }: &Self) -> Result<()> {
        let mut finalized_wsv = wsv.clone();
        let mut wsv = finalized_wsv.clone();

        for block in blocks {
            finalized_wsv = wsv.clone();
            wsv.apply(block)?;
            assert_eq!(wsv.height(), finalized_wsv.height() + 1);
        }

        Ok(())
    }
}
