//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_data_model::{
    block::BlockHeader,
    query::{
        block::FindBlockHeaderByHash,
        error::{FindError, QueryExecutionFail},
        predicate::{
            predicate_atoms::block::{BlockHeaderPredicateBox, SignedBlockPredicateBox},
            CompoundPredicate,
        },
    },
};
use iroha_telemetry::metrics;
use nonzero_ext::nonzero;

use super::*;
use crate::{smartcontracts::ValidQuery, state::StateReadOnly};

impl ValidQuery for FindBlocks {
    #[metrics(+"find_blocks")]
    fn execute(
        self,
        filter: CompoundPredicate<SignedBlockPredicateBox>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item>, QueryExecutionFail> {
        Ok(state_ro
            .all_blocks(nonzero!(1_usize))
            .rev()
            .filter(move |block| filter.applies(block))
            .map(|block| (*block).clone()))
    }
}

impl ValidQuery for FindBlockHeaders {
    #[metrics(+"find_block_headers")]
    fn execute(
        self,
        filter: CompoundPredicate<BlockHeaderPredicateBox>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item>, QueryExecutionFail> {
        Ok(state_ro
            .all_blocks(nonzero!(1_usize))
            .rev()
            .filter(move |block| filter.applies(block.header()))
            .map(|block| block.header().clone()))
    }
}

impl ValidSingularQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(&self, state_ro: &impl StateReadOnly) -> Result<BlockHeader, QueryExecutionFail> {
        let hash = self.hash;

        let block = state_ro
            .kura()
            .get_block_height_by_hash(hash)
            .and_then(|height| state_ro.kura().get_block_by_height(height))
            .ok_or_else(|| QueryExecutionFail::Find(FindError::Block(hash)))?;

        Ok(block.header().clone())
    }
}
