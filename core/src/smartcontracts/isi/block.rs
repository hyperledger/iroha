//! This module contains trait implementations related to block queries
use eyre::{Result, WrapErr};
use iroha_data_model::{
    evaluate::ExpressionEvaluator,
    query::{
        block::FindBlockHeaderByHash,
        error::{FindError, QueryExecutionFailure},
    },
};
use iroha_telemetry::metrics;

use super::*;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFailure> {
        let blocks = wsv.all_blocks_by_value().rev().collect();
        Ok(blocks)
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFailure> {
        let block_headers = wsv
            .all_blocks_by_value()
            .rev()
            .map(|block| block.into_v1().header)
            .collect();
        Ok(block_headers)
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, QueryExecutionFailure> {
        let hash = wsv
            .evaluate(&self.hash)
            .wrap_err("Failed to evaluate hash")
            .map_err(|e| QueryExecutionFailure::Evaluate(e.to_string()))?
            .typed();

        let block = wsv
            .all_blocks_by_value()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| QueryExecutionFailure::Find(Box::new(FindError::Block(hash))))?;

        Ok(block.into_v1().header)
    }
}
