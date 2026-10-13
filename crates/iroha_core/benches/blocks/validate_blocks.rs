//! Benchmark fixture for validating and publishing canonical block outputs.
//!
//! Each measured block is assembled by the leader's payload builder, executed by the node's
//! `StateExecutor`, certified by a BLS `CommitQC`, stored in Kura and published: the path every
//! certified block takes on the global chain.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#[path = "./common.rs"]
mod common;
use common::*;
use iroha_core::sumeragi::test_chain::CertifiedTestChain;
use iroha_data_model::isi::InstructionBox;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use std::sync::{Arc, OnceLock};
type InstructionBatch = Arc<[InstructionBox]>;
const BENCH_DOMAINS: usize = 4;
const BENCH_ACCOUNTS_PER_DOMAIN: usize = 25;
const BENCH_ASSETS_PER_DOMAIN: usize = 25;
const BENCH_DELETE_EVERY_NTH: usize = 5;
/// Lazily prepared instruction batches shared across benchmark iterations to
/// keep setup work bounded while still exercising meaningful block validation.
fn instruction_batches() -> &'static [InstructionBatch; 3] {
    static BATCHES: OnceLock<[InstructionBatch; 3]> = OnceLock::new();
    BATCHES.get_or_init(|| {
        let (domain_ids, account_ids, asset_definition_ids) = generate_ids(
            BENCH_DOMAINS,
            BENCH_ACCOUNTS_PER_DOMAIN,
            BENCH_ASSETS_PER_DOMAIN,
        );
        let owner_id = (*ALICE_ID).clone();
        [
            Arc::from(
                populate_state(&domain_ids, &account_ids, &asset_definition_ids, &owner_id)
                    .into_boxed_slice(),
            ),
            Arc::from(
                delete_every_nth(
                    &domain_ids,
                    &account_ids,
                    &asset_definition_ids,
                    BENCH_DELETE_EVERY_NTH,
                )
                .into_boxed_slice(),
            ),
            Arc::from(
                restore_every_nth(
                    &domain_ids,
                    &account_ids,
                    &asset_definition_ids,
                    BENCH_DELETE_EVERY_NTH,
                )
                .into_boxed_slice(),
            ),
        ]
    })
}
/// A certified chain at its benchmark genesis and the instruction batches to commit on it.
pub struct StateValidateBlocks {
    chain: CertifiedTestChain,
    instructions: Vec<InstructionBatch>,
}
impl StateValidateBlocks {
    /// Start the certified benchmark chain.
    ///
    /// # Panics
    ///
    /// The benchmark genesis does not apply.
    pub fn setup() -> Self {
        let (domain_ids, account_ids, _) = generate_ids(
            BENCH_DOMAINS,
            BENCH_ACCOUNTS_PER_DOMAIN,
            BENCH_ASSETS_PER_DOMAIN,
        );
        let chain = start_chain(&ALICE_ID, &domain_ids, &account_ids);
        let instructions = instruction_batches().to_vec();
        Self {
            chain,
            instructions,
        }
    }
    /// Run benchmark body: validate, certify and publish one block per instruction batch.
    ///
    /// Each fixture is measured once; its chain then holds every benchmark block.
    ///
    /// # Panics
    ///
    /// A block does not execute, a transaction fails, or the committed height does not
    /// advance by one per block.
    pub fn measure(&mut self) {
        let base_height = self.chain.state().view().height();
        for (instruction_batch, i) in self.instructions.iter().zip(1..) {
            commit_instructions(
                &mut self.chain,
                &ALICE_KEYPAIR,
                instruction_batch.iter().cloned(),
            );
            assert_eq!(self.chain.state().view().height(), base_height + i);
        }
    }
}
