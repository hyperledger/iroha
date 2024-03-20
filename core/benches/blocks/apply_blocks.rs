use eyre::Result;
use iroha_core::{block::CommittedBlock, prelude::*, state::State};
use iroha_data_model::prelude::*;

#[path = "./common.rs"]
mod common;

use common::*;

pub struct StateApplyBlocks {
    state: State,
    blocks: Vec<CommittedBlock>,
}

impl StateApplyBlocks {
    /// Create [`State`] and blocks for benchmarking
    ///
    /// # Errors
    /// - Failed to parse [`AccountId`]
    /// - Failed to generate [`KeyPair`]
    /// - Failed to create instructions for block
    pub fn setup(rt: &tokio::runtime::Handle) -> Result<Self> {
        let domains = 100;
        let accounts_per_domain = 1000;
        let assets_per_domain = 1000;
        let account_id: AccountId = "alice@wonderland".parse()?;
        let key_pair = KeyPair::random();
        let state = build_state(rt, &account_id, &key_pair);

        let nth = 100;
        let instructions = [
            populate_state(domains, accounts_per_domain, assets_per_domain, &account_id),
            delete_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
            restore_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
        ];

        let blocks = {
            // Create empty state because it will be changed during creation of block
            let state = build_state(rt, &account_id, &key_pair);
            instructions
                .into_iter()
                .map(|instructions| -> Result<_> {
                    let mut state_block = state.block();
                    let block = create_block(
                        &mut state_block,
                        instructions,
                        account_id.clone(),
                        &key_pair,
                    );
                    state_block.apply_without_execution(&block)?;
                    state_block.commit();
                    Ok(block)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Self { state, blocks })
    }

    /// Run benchmark body.
    ///
    /// # Errors
    /// - Not enough blocks
    /// - Failed to apply block
    ///
    /// # Panics
    /// If state height isn't updated after applying block
    pub fn measure(Self { state, blocks }: &Self) -> Result<()> {
        for (block, i) in blocks.iter().zip(1..) {
            let mut state_block = state.block();
            state_block.apply(block)?;
            assert_eq!(state_block.height(), i);
            state_block.commit();
        }

        Ok(())
    }
}
