//! This module contains trait implementations related to block queries
use eyre::{Result, WrapErr};
use iroha_data_model::{
    block::{BlockHeader, VersionedSignedBlock},
    evaluate::ExpressionEvaluator,
    query::{
        block::FindBlockHeaderByHash,
        error::{FindError, QueryExecutionFail},
    },
};
use iroha_telemetry::metrics;

use super::*;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<Box<dyn Iterator<Item = VersionedSignedBlock> + 'wsv>, QueryExecutionFail> {
        Ok(Box::new(
            wsv.all_blocks()
                .rev()
                .map(|block| VersionedSignedBlock::clone(&block)),
        ))
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<Box<dyn Iterator<Item = BlockHeader> + 'wsv>, QueryExecutionFail> {
        Ok(Box::new(
            wsv.all_blocks()
                .rev()
                .map(|block| block.payload().header.clone()),
        ))
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(&self, wsv: &WorldStateView) -> Result<BlockHeader, QueryExecutionFail> {
        let hash = wsv
            .evaluate(&self.hash)
            .wrap_err("Failed to evaluate hash")
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;

        let block = wsv
            .all_blocks()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| QueryExecutionFail::Find(FindError::Block(hash)))?;

        Ok(block.payload().header.clone())
    }
}
