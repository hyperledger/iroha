//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_telemetry::metrics;

use super::*;

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, query::Error> {
        let mut blocks: Vec<Box<BlockValue>> = wsv
            .blocks()
            .map(|blk| blk.clone())
            .map(VersionedCommittedBlock::into_value)
            .map(Box::new)
            .collect();
        blocks.reverse();
        Ok(blocks)
    }
}
