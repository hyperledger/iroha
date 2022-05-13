//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_data_model::block_value::BlockValue;
use iroha_logger::prelude::*;
use iroha_telemetry::metrics;

use super::*;

impl<W: WorldTrait> ValidQuery<W> for FindAllBlocks {
    #[log]
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, query::Error> {
        let mut blocks: Vec<BlockValue> = wsv
            .blocks()
            .map(|blk| blk.clone())
            .map(VersionedCommittedBlock::into_value)
            .collect();
        blocks.reverse();
        Ok(blocks)
    }
}
