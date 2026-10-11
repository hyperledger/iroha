//! Fixed staged-row owners admitting replacement overlap before growth.

use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer};

/// A staged canonical key and the two value commitments from one encoder pass.
pub(super) struct PairedDigestRow {
    pub(super) key: ChargedBuffer<u8>,
    pub(super) ordered_value_digest: Hash,
    pub(super) lookup_value_digest: Hash,
}

pub(super) fn encode_key<K: Encode + NoritoSchema>(
    table: &'static str,
    schema: Schema,
    key: &K,
    maximum: usize,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<u8>, LeafError> {
    typed_bare_payload(
        table,
        schema,
        key,
        maximum.min(MAX_NORITO_KEY_BYTES),
        |length| frame::FundedFrame::new(length, budget),
    )
    .map(frame::FundedFrame::into_buffer)
}

/// One staging owner retaining a clone of the caller's exact original pool.
pub(super) struct StagedRows {
    rows: ChargedBuffer<PairedDigestRow>,
    maximum: usize,
    budget: AllocationBudget,
}

impl StagedRows {
    pub(super) fn new(maximum: usize, budget: &AllocationBudget) -> Result<Self, LeafError> {
        Ok(Self {
            rows: ChargedBuffer::new(0, budget).map_err(frame::buffer_error)?,
            maximum,
            budget: budget.clone(),
        })
    }

    pub(super) fn len(&self) -> usize {
        self.rows.as_slice().len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.rows.as_slice().is_empty()
    }
    pub(super) fn as_slice(&self) -> &[PairedDigestRow] {
        self.rows.as_slice()
    }
    pub(super) fn as_mut_slice(&mut self) -> &mut [PairedDigestRow] {
        self.rows.as_mut_slice()
    }

    /// An allocation refusal leaves every previous row and charge with this owner.
    pub(super) fn push(&mut self, row: PairedDigestRow) -> Result<(), LeafError> {
        self.reserve_for(self.len().checked_add(1).ok_or(LeafError::RowLimit)?)?;
        self.push_reserved(row);
        Ok(())
    }

    /// Exact number of prior slots moved by the next growth, before allocation.
    pub(super) fn growth_rows(&self) -> usize {
        if self.len() == self.rows.capacity() {
            self.len()
        } else {
            0
        }
    }
    /// Admit backing before moving the caller's pending actual row.
    pub(super) fn reserve_for(&mut self, required: usize) -> Result<(), LeafError> {
        if required > self.maximum || required > self.len().saturating_add(1) {
            return Err(LeafError::RowLimit);
        }
        if required > self.rows.capacity() {
            let capacity = self
                .rows
                .capacity()
                .checked_mul(2)
                .unwrap_or(self.maximum)
                .max(1)
                .min(self.maximum);
            let mut grown =
                ChargedBuffer::new(capacity, &self.budget).map_err(frame::buffer_error)?;
            for old in self.rows.drain_all() {
                grown.push_reserved(old);
            }
            self.rows = grown;
        }
        Ok(())
    }
    /// Caller has already admitted the exact next slot.
    pub(super) fn push_reserved(&mut self, row: PairedDigestRow) {
        self.rows.push_reserved(row);
    }
    /// Retire every initialized key and its backing before the caller's scope.
    pub(super) fn retire(&mut self) -> Result<(), LeafError> {
        let empty = ChargedBuffer::new(0, &self.budget).map_err(frame::buffer_error)?;
        self.rows = empty;
        Ok(())
    }
    #[cfg(all(test, sumeragi_core_mutation = "HC176"))]
    pub(super) fn discard_for_mutation(&mut self) {
        for row in self.rows.drain_all() {
            drop(row);
        }
    }
}

#[cfg(test)]
#[path = "staging/tests.rs"]
mod tests;
