//! This module contains trait implementations related to block queries
use eyre::{Result, WrapErr};
use iroha_data_model::query::{
    block::FindBlockHeaderByHash,
    error::{FindError, QueryExecutionFailure as Error},
};
use iroha_telemetry::metrics;

use super::*;
use crate::evaluate_with_error_msg;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
        let blocks = wsv.all_blocks_by_value().rev().collect();
        Ok(blocks)
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
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
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
        let hash = evaluate_with_error_msg!(self.hash, wsv, "Failed to evaluate hash").typed();

        let block = wsv
            .all_blocks_by_value()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| Error::Find(Box::new(FindError::Block(hash))))?;

        Ok(block.into_v1().header)
    }
}
