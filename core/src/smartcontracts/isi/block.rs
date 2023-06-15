//! This module contains trait implementations related to block queries
use eyre::{Result, WrapErr};
use iroha_data_model::{
    evaluate::ExpressionEvaluator,
    query::{
        block::FindBlockHeaderByHash,
        error::{FindError, QueryExecutionFail},
    },
};
use iroha_telemetry::metrics;

use super::*;
use crate::smartcontracts::query::Lazy;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail> {
        Ok(Box::new(
            wsv.all_blocks().rev().map(|block| Clone::clone(&*block)),
        ))
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail> {
        Ok(Box::new(
            wsv.all_blocks()
                .rev()
                .map(|block| block.as_v1().header.clone()),
        ))
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute<'wsv>(
        &self,
        wsv: &'wsv WorldStateView,
    ) -> Result<<Self::Output as Lazy>::Lazy<'wsv>, QueryExecutionFail> {
        let hash = wsv
            .evaluate(&self.hash)
            .wrap_err("Failed to evaluate hash")
            .map_err(|e| QueryExecutionFail::Evaluate(e.to_string()))?;

        let block = wsv
            .all_blocks()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| QueryExecutionFail::Find(FindError::Block(hash)))?;

        Ok(block.as_v1().header.clone())
    }
}
