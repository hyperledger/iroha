use eyre::Result;
use iroha_core::{block::CommittedBlock, prelude::*, state::State};
use test_samples::gen_account_in;

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
    pub fn setup(rt: &tokio::runtime::Handle) -> Self {
        let domains = 100;
        let accounts_per_domain = 1000;
        let assets_per_domain = 1000;
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let state = build_state(rt, &alice_id);

        let nth = 100;
        let instructions = [
            populate_state(domains, accounts_per_domain, assets_per_domain, &alice_id),
            delete_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
            restore_every_nth(domains, accounts_per_domain, assets_per_domain, nth),
        ];

        let blocks = {
            // Create empty state because it will be changed during creation of block
            let state = build_state(rt, &alice_id);
            instructions
                .into_iter()
                .map(|instructions| {
                    let mut state_block = state.block();
                    let block = create_block(
                        &mut state_block,
                        instructions,
                        alice_id.clone(),
                        &alice_keypair,
                    );
                    let _events = state_block.apply_without_execution(&block);
                    state_block.commit();
                    block
                })
                .collect::<Vec<_>>()
        };

        Self { state, blocks }
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
            let _events = state_block.apply(block)?;
            assert_eq!(state_block.height(), i);
            state_block.commit();
        }

        Ok(())
    }
}
