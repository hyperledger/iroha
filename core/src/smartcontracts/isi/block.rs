//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    query::{
        block::FindBlockHeaderByHash,
        error::{FindError, QueryExecutionFail},
    },
};
use iroha_telemetry::metrics;
use nonzero_ext::nonzero;

use super::*;
use crate::state::StateReadOnly;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute<'state>(
        &self,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<Box<dyn Iterator<Item = SignedBlock> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            state_ro
                .all_blocks(nonzero!(1_usize))
                .rev()
                .map(|block| (*block).clone()),
        ))
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute<'state>(
        &self,
        staete_snapshot: &'state impl StateReadOnly,
    ) -> Result<Box<dyn Iterator<Item = BlockHeader> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            staete_snapshot
                .all_blocks(nonzero!(1_usize))
                .rev()
                .map(|block| block.header().clone()),
        ))
    }
}

impl ValidQuery for FindBlockHeaderByHash {
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
