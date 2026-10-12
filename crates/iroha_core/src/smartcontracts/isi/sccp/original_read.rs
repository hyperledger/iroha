//! Borrowed SCCP consensus facts from one retained observation or exact pre-block image.
//!
//! Replacement execution reads its reverted MV baseline. It never reacquires the
//! still-published successor or copies retained committee and anchor payloads.

use super::{
    eligibility::{Current, EligibilityRead, TransactionParent},
    generation_record::RetainedSccpGeneration,
    store,
};
use crate::state::WorldReadOnly;
use iroha_data_model::sccp::generation::SccpAnchorV1;

/// Consensus and liability facts borrowed from the same original World cut.
/// Returned records borrow the retained source, not this lightweight adapter.
pub(crate) trait OriginalRead<'a>: EligibilityRead + Copy {
    /// Original selected generation.
    fn committee_current(self) -> u64;
    /// Original SCCP liability clock before S0 advances it.
    fn liability_clock(self) -> u64;
    /// Original consecutive degraded-finality count.
    fn degraded_run(self) -> u32;
    /// Exact retained generation, including its version-local lifecycle scalars.
    fn generation(self, number: &u64) -> Option<&'a RetainedSccpGeneration>;
    /// All original generations in canonical key order, without allocation.
    fn generations(self) -> impl Iterator<Item = (&'a u64, &'a RetainedSccpGeneration)>;
    /// Original open anchor chunk.
    fn anchor_open(self) -> &'a [SccpAnchorV1];
    /// Original closed anchor chunk commitment.
    fn anchor_chunk(self, number: &u64) -> Option<&'a [u8; 32]>;
}

impl<'a, W: WorldReadOnly + ?Sized> OriginalRead<'a> for Current<'a, W> {
    fn committee_current(self) -> u64 {
        *store::committee_current::get(self.0)
    }
    fn liability_clock(self) -> u64 {
        *store::liability_clock::get(self.0)
    }
    fn degraded_run(self) -> u32 {
        *store::degraded_run::get(self.0)
    }
    fn generation(self, number: &u64) -> Option<&'a RetainedSccpGeneration> {
        store::committee_generations::get(self.0, number)
    }
    fn generations(self) -> impl Iterator<Item = (&'a u64, &'a RetainedSccpGeneration)> {
        store::committee_generations::iter(self.0)
    }
    fn anchor_open(self) -> &'a [SccpAnchorV1] {
        store::anchor_open::get(self.0).as_slice()
    }
    fn anchor_chunk(self, number: &u64) -> Option<&'a [u8; 32]> {
        store::anchor_chunks::get(self.0, number)
    }
}

impl<'a> OriginalRead<'a> for TransactionParent<'a, '_, '_> {
    fn committee_current(self) -> u64 {
        *self.0.sccp_committee_current.get_before_block()
    }
    fn liability_clock(self) -> u64 {
        *self.0.sccp_liability_clock.get_before_block()
    }
    fn degraded_run(self) -> u32 {
        *self.0.sccp_degraded_run.get_before_block()
    }
    fn generation(self, number: &u64) -> Option<&'a RetainedSccpGeneration> {
        self.0.sccp_committee_generations.get_before_block(number)
    }
    fn generations(self) -> impl Iterator<Item = (&'a u64, &'a RetainedSccpGeneration)> {
        self.0.sccp_committee_generations.iter_before_block()
    }
    fn anchor_open(self) -> &'a [SccpAnchorV1] {
        self.0.sccp_anchor_open.get_before_block().as_slice()
    }
    fn anchor_chunk(self, number: &u64) -> Option<&'a [u8; 32]> {
        self.0.sccp_anchor_chunks.get_before_block(number)
    }
}

#[cfg(test)]
mod tests;
