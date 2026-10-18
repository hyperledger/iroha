//! Benchmark fixture for reexecuting and applying certified blocks.
//!
//! A source chain executes and certifies the benchmark blocks once. Each measured replica
//! starts from the same signed genesis and applies that certified suffix the way a node
//! applies blocks Kura already holds: every certificate is verified, every block is stored,
//! re-executed to its certified result and published through the node's `StateExecutor`.

#[path = "./common.rs"]
pub mod common;
use common::*;
use iroha_core::sumeragi::test_chain::CertifiedTestChain;
use iroha_data_model::prelude::AccountId;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use std::rc::Rc;

/// Benchmark domains.
const DOMAINS: usize = 10;
/// Accounts registered per benchmark domain.
const ACCOUNTS_PER_DOMAIN: usize = 100;
/// Asset definitions registered per benchmark domain.
const ASSETS_PER_DOMAIN: usize = 100;
/// Every `nth` child is unregistered and registered again.
const DELETE_EVERY_NTH: usize = 10;
/// Certified blocks applied by every measurement: populate, delete and restore.
const BLOCKS: u64 = 3;

/// Certified benchmark blocks shared by every measured replica.
pub struct CertifiedBlocks {
    /// The chain that executed and certified the benchmark blocks.
    chain: CertifiedTestChain,
    /// Benchmark domains of the source genesis World.
    domain_ids: Vec<DomainId>,
    /// Benchmark accounts the source genesis authorizes the owner to unregister.
    account_ids: Vec<AccountId>,
}

impl CertifiedBlocks {
    /// Execute and certify the populate, delete and restore blocks on a source chain.
    ///
    /// # Panics
    ///
    /// The benchmark genesis or one of its blocks does not execute successfully.
    pub fn setup() -> Rc<Self> {
        let (domain_ids, account_ids, asset_definition_ids) =
            generate_ids(DOMAINS, ACCOUNTS_PER_DOMAIN, ASSETS_PER_DOMAIN);
        let mut chain = start_chain(&ALICE_ID, &domain_ids, &account_ids);
        let instructions = [
            populate_state(&domain_ids, &account_ids, &asset_definition_ids, &ALICE_ID),
            delete_every_nth(
                &domain_ids,
                &account_ids,
                &asset_definition_ids,
                DELETE_EVERY_NTH,
            ),
            restore_every_nth(
                &domain_ids,
                &account_ids,
                &asset_definition_ids,
                DELETE_EVERY_NTH,
            ),
        ];
        for instructions in instructions {
            commit_instructions(&mut chain, &ALICE_KEYPAIR, instructions);
        }
        Rc::new(Self {
            chain,
            domain_ids,
            account_ids,
        })
    }
}

/// A replica of the benchmark genesis that applies the shared certified blocks.
pub struct StateApplyBlocks {
    /// The certified blocks to apply.
    blocks: Rc<CertifiedBlocks>,
    /// A chain started from the same signed genesis, at the genesis height.
    replica: CertifiedTestChain,
}

impl StateApplyBlocks {
    /// Start a replica of the genesis that certified `blocks`.
    ///
    /// # Panics
    ///
    /// The benchmark genesis does not apply.
    pub fn setup(blocks: &Rc<CertifiedBlocks>) -> Self {
        let replica = start_chain(&ALICE_ID, &blocks.domain_ids, &blocks.account_ids);
        assert_eq!(
            replica.height() + BLOCKS,
            blocks.chain.height(),
            "the replica starts at the certified genesis"
        );
        Self {
            blocks: Rc::clone(blocks),
            replica,
        }
    }

    /// Run benchmark body: apply every certified block to the replica.
    ///
    /// Each fixture is measured once; the replica then holds the whole certified chain.
    ///
    /// # Panics
    ///
    /// A block does not re-execute to its certified result or cannot be applied, or the
    /// replica's height does not advance by every applied block.
    pub fn measure(&mut self) {
        let base_height = self.replica.height();
        self.replica
            .replay_from(&self.blocks.chain)
            .expect("reexecute and apply the certified benchmark blocks");
        assert_eq!(self.replica.height(), base_height + BLOCKS);
        assert_eq!(
            self.replica.state().view().height(),
            self.blocks.chain.state().view().height()
        );
    }
}
