//! This module contains trait implementations related to block queries
use eyre::{Result, WrapErr};
use iroha_data_model::query::block::FindBlockHeaderByHash;
use iroha_telemetry::metrics;

use super::*;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, query::Error> {
        let blocks = wsv
            .blocks()
            .map(|block| block.clone())
            .map(VersionedCommittedBlock::into_value)
            .rev() // Sorted by height desc.
            .collect();
        Ok(blocks)
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, query::Error> {
        let block_headers = wsv
            .blocks()
            .map(|block| block.clone())
            .map(VersionedCommittedBlock::into_value)
            .map(|block_value| block_value.header)
            .rev() // Sorted by height desc.
            .collect();
        Ok(block_headers)
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, query::Error> {
        let hash = self
            .hash
            .evaluate(wsv, &Context::default())
            .wrap_err("Failed to evaluate hash")
            .map_err(|e| query::Error::Evaluate(e.to_string()))?
            .typed();

        let block = wsv
            .blocks()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| query::Error::Find(Box::new(FindError::Block(hash))))?;

        Ok(block.clone().into_value().header)
    }
}
