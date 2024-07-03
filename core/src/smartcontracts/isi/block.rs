//! This module contains trait implementations related to block queries
use eyre::Result;
use iroha_data_model::{
    block::{BlockHeader, SignedBlock},
    query::{
        block::FindBlockHeaderByHash,
        error::{FindError, QueryExecutionFail},
        predicate::{
            predicate_atoms::block::{BlockHeaderPredicateBox, SignedBlockPredicateBox},
            CompoundPredicate,
        },
    },
};
use iroha_telemetry::metrics;

use super::*;
use crate::{smartcontracts::ValidIterableQuery, state::StateReadOnly};

impl ValidQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute<'state>(
        &self,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<Box<dyn Iterator<Item = SignedBlock> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            state_ro.all_blocks().rev().map(|block| (*block).clone()),
        ))
    }
}

impl ValidIterableQuery for FindAllBlocks {
    #[metrics(+"find_all_blocks")]
    fn execute<'state>(
        self,
        filter: CompoundPredicate<SignedBlockPredicateBox>,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item> + 'state, QueryExecutionFail> {
        Ok(state_ro
            .all_blocks()
            .rev()
            .filter(move |block| filter.applies(block))
            .map(|block| (*block).clone()))
    }
}

impl ValidQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute<'state>(
        &self,
        staete_snapshot: &'state impl StateReadOnly,
    ) -> Result<Box<dyn Iterator<Item = BlockHeader> + 'state>, QueryExecutionFail> {
        Ok(Box::new(
            staete_snapshot
                .all_blocks()
                .rev()
                .map(|block| block.header().clone()),
        ))
    }
}

impl ValidIterableQuery for FindAllBlockHeaders {
    #[metrics(+"find_all_block_headers")]
    fn execute<'state>(
        self,
        filter: CompoundPredicate<BlockHeaderPredicateBox>,
        state_ro: &'state impl StateReadOnly,
    ) -> Result<impl Iterator<Item = Self::Item> + 'state, QueryExecutionFail> {
        Ok(state_ro
            .all_blocks()
            .rev()
            .filter(move |block| filter.applies(block.header()))
            .map(|block| block.header().clone()))
    }
}

impl ValidQuery for FindBlockHeaderByHash {
    #[metrics(+"find_block_header")]
    fn execute(&self, state_ro: &impl StateReadOnly) -> Result<BlockHeader, QueryExecutionFail> {
        let hash = self.hash;

        let block = state_ro
            .all_blocks()
            .find(|block| block.hash() == hash)
            .ok_or_else(|| QueryExecutionFail::Find(FindError::Block(hash)))?;

        Ok(block.header().clone())
    }
}
