//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_data_model::block_value::BlockValue;
use iroha_telemetry::metrics;

use super::*;

impl<W: WorldTrait> ValidQuery<W> for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, query::Error> {
        let mut blocks: Vec<BlockValue> = wsv
            .lock_read_blocks()
            .all_blocks()
            .iter()
            .cloned()
            .map(VersionedCommittedBlock::into_value)
            .collect();
        blocks.reverse();
        Ok(blocks)
    }
}
