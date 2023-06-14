//! This module contains trait implementations related to block queries
use eyre::{Result, WrapErr};
use iroha_crypto::HashOf;
use iroha_data_model::{
    block::VersionedCommittedBlock,
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
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFail> {
        let blocks = wsv
            .all_blocks()
            .map(|block| VersionedCommittedBlock::clone(&block))
            .rev()
            .collect();
        Ok(blocks)
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFail> {
        let block_headers = wsv
            .all_blocks()
            .rev()
            .map(|block| block.as_v1().header.clone())
            .collect();
        Ok(block_headers)
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFail> {
        let hash = wsv
            .evaluate(&self.hash)
            .wrap_err("Failed to evaluate hash")
            .map(HashOf::from_untyped_unchecked)
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;

        let block = wsv
            .all_blocks()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| QueryExecutionFail::Find(Box::new(FindError::Block(hash))))?;

        Ok(block.as_v1().header.clone())
    }
}
