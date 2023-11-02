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

use super::*;
use crate::state::StateSnapshot;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute<'state>(
        &self,
        state_snapshot: &'state StateSnapshot<'state>,
    ) -> Result<Box<dyn Iterator<Item = SignedBlock> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            state_snapshot
                .all_blocks()
                .rev()
                .map(|block| (*block).clone()),
        ))
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute<'state>(
        &self,
        staete_snapshot: &'state StateSnapshot<'state>,
    ) -> Result<Box<dyn Iterator<Item = BlockHeader> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            staete_snapshot
                .all_blocks()
                .rev()
                .map(|block| block.header().clone()),
        ))
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(
        &self,
        state_snapshot: &StateSnapshot<'_>,
    ) -> Result<BlockHeader, QueryExecutionFail> {
        let hash = self.hash;

        let block = state_snapshot
            .all_blocks()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| QueryExecutionFail::Find(FindError::Block(hash)))?;

        Ok(block.header().clone())
    }
}
