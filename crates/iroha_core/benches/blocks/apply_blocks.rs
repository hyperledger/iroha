use eyre::Result;
use iroha_core::{
    block::CommittedBlock, prelude::*, state::State, sumeragi::network_topology::Topology,
};
use iroha_data_model::peer::PeerId;
use iroha_test_samples::gen_account_in;

#[path = "./common.rs"]
mod common;

use common::*;

pub struct StateApplyBlocks {
    state: State,
    blocks: Vec<CommittedBlock>,
    topology: Topology,
}

impl StateApplyBlocks {
    /// Create [`State`] and blocks for benchmarking
    ///
    /// # Errors
    /// - Failed to parse [`AccountId`]
    /// - Failed to generate [`KeyPair`]
    /// - Failed to create instructions for block
    pub fn setup(rt: &tokio::runtime::Handle) -> Self {
        let domains = 10;
        let accounts_per_domain = 100;
        let assets_per_domain = 100;
        let (domain_ids, account_ids, asset_definition_ids) =
            generate_ids(domains, accounts_per_domain, assets_per_domain);
        let (peer_public_key, peer_private_key) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let state = build_state(rt, &alice_id);

        let nth = 10;
        let instructions = [
            populate_state(&domain_ids, &account_ids, &asset_definition_ids, &alice_id),
            delete_every_nth(&domain_ids, &account_ids, &asset_definition_ids, nth),
            restore_every_nth(&domain_ids, &account_ids, &asset_definition_ids, nth),
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
                        alice_keypair.private_key(),
                        &topology,
                        &peer_private_key,
                    );
                    let _events =
                        state_block.apply_without_execution(&block, topology.as_ref().to_owned());
                    state_block.commit();
                    block
                })
                .collect::<Vec<_>>()
        };

        Self {
            state,
            blocks,
            topology,
        }
    }

    /// Run benchmark body.
    ///
    /// # Errors
    /// - Not enough blocks
    /// - Failed to apply block
    ///
    /// # Panics
    /// If state height isn't updated after applying block
    pub fn measure(
        Self {
            state,
            blocks,
            topology,
        }: &Self,
    ) -> Result<()> {
        for (block, i) in blocks.iter().zip(1..) {
            let mut state_block = state.block();
            let _events = state_block.apply(block, topology.as_ref().to_owned())?;
            assert_eq!(state_block.height(), i);
            state_block.commit();
        }

        Ok(())
    }
}
