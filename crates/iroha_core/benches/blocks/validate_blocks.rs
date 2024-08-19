use iroha_core::{prelude::*, state::State, sumeragi::network_topology::Topology};
use iroha_data_model::{isi::InstructionBox, prelude::*};
use iroha_test_samples::gen_account_in;

#[path = "./common.rs"]
mod common;

use common::*;

pub struct StateValidateBlocks {
    state: State,
    instructions: Vec<Vec<InstructionBox>>,
    account_private_key: PrivateKey,
    account_id: AccountId,
    topology: Topology,
    peer_private_key: PrivateKey,
}

impl StateValidateBlocks {
    /// Create [`State`] and blocks for benchmarking
    ///
    /// # Panics
    ///
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
        ]
        .into_iter()
        .collect::<Vec<_>>();

        Self {
            state,
            instructions,
            account_private_key: alice_keypair.private_key().clone(),
            account_id: alice_id,
            topology,
            peer_private_key,
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
            instructions,
            account_private_key,
            account_id,
            topology,
            peer_private_key,
        }: Self,
    ) {
        for (instructions, i) in instructions.into_iter().zip(1..) {
            let mut state_block = state.block();
            let block = create_block(
                &mut state_block,
                instructions,
                account_id.clone(),
                &account_private_key,
                &topology,
                &peer_private_key,
            );
            let _events = state_block.apply_without_execution(&block, topology.as_ref().to_owned());
            assert_eq!(state_block.height(), i);
            state_block.commit();
        }
    }
}
