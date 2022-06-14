//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_data_model::block_value::BlockValue;
use iroha_telemetry::metrics;

use super::*;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, query::Error> {
        let mut blocks: Vec<BlockValue> = wsv
            .blocks()
            .map(|blk| blk.clone())
            .map(VersionedCommittedBlock::into_value)
            .collect();
        blocks.reverse();
        Ok(blocks)
    }
}
