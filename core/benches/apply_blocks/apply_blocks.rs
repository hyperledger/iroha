#![allow(missing_docs, clippy::restriction)]

use std::{collections::BTreeSet, str::FromStr as _};

use eyre::Result;
use iroha_config::sumeragi::default::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_core::{block::PendingBlock, prelude::*, wsv::World};
use iroha_crypto::{HashOf, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{
    asset::{AssetDefinition, AssetDefinitionId},
    block::{BlockHeader, VersionedCommittedBlock},
    isi::InstructionBox,
    prelude::*,
};

/// Create block, bypassing validation
fn create_block(
    height: u64,
    previous_block_hash: Option<HashOf<VersionedCommittedBlock>>,
    instructions: Vec<InstructionBox>,
    account_id: AccountId,
    key_pair: KeyPair,
) -> Result<VersionedCommittedBlock> {
    let transaction = TransactionBuilder::new(account_id)
        .with_instructions(instructions)
        .sign(key_pair.clone())?;

    let transactions_hash = [&transaction]
        .iter()
        .map(|tx| tx.hash())
        .collect::<MerkleTree<_>>()
        .hash();
    let timestamp = current_time().as_millis();
    let header = BlockHeader {
        timestamp,
        consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
        height,
        view_change_index: 1,
        previous_block_hash,
        transactions_hash, // Single transaction is merkle root hash
        rejected_transactions_hash: None,
        committed_with_topology: Vec::new(),
    };

    let signature = SignatureOf::from_hash(key_pair, Hash::new(header.payload()).typed())?;
    let signatures = SignaturesOf::from(signature);

    let pending_block = PendingBlock {
        header,
        transactions: vec![TransactionValue {
            tx: transaction,
            error: None,
        }],
        event_recommendations: Vec::new(),
        signatures,
    };

    Ok(pending_block.commit_unchecked().into())
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

    let block = create_block(1, None, instructions, account_id, key_pair)?;

    wsv.apply(&block)?;

    Ok(wsv)
}

pub struct WsvApplyBlocks {
    wsv: WorldStateView,
    blocks: Vec<VersionedCommittedBlock>,
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
        let wsv = build_wsv(
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

        let mut previous_block_hash = wsv.latest_block_hash();
        let mut blocks = Vec::new();
        for (instructions, height) in instructions.into_iter().zip(wsv.height() + 1..) {
            let block = create_block(
                height,
                previous_block_hash,
                instructions,
                genesis_id.clone(),
                key_pair.clone(),
            )?;
            previous_block_hash = Some(block.hash());
            blocks.push(block);
        }

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
