//! Consuming typed callback construction using the existing paired table codec.
//!
//! Each push consumes its builder: a refused row cannot leave a finishable prefix.
//! Row borrows end before push returns; only funded canonical key/digest staging
//! survives. Table-selection bits are inline; schema names and codec scratch
//! remain separate funding obligations. No membership or finalized-State authority is granted here.

use super::*;
use std::marker::PhantomData;

/// Additional work and ordered retention admitted across the caller's table group.
#[derive(Clone, Copy)]
pub(in crate::state) struct TypedPairedRowAllowance {
    /// Remaining bytes across both full-value encoder passes.
    pub streamed_bytes: u64,
    /// Remaining canonical key/digest framing and ordered Merkle-node bytes.
    pub ordered_bytes: usize,
}

/// Distinguish caller aggregate admission from the table's own canonical checks.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum TypedPairedRowError {
    /// Exact existing codec, table limit or original-pool failure.
    #[error(transparent)]
    Table(#[from] LeafError),
    /// The caller did not admit both value passes.
    #[error("aggregate full-value stream allowance exhausted")]
    StreamedAllowance,
    /// The caller did not admit the next row and complete ordered geometry.
    #[error("aggregate ordered retention allowance exhausted")]
    OrderedAllowance,
}

impl TypedPairedRowError {
    /// Single-table callers already supply at least their own complete bounds.
    pub(super) fn into_leaf(self) -> LeafError {
        match self {
            Self::Table(error) => error,
            Self::StreamedAllowance => LeafError::StreamedTableLimit,
            Self::OrderedAllowance => LeafError::OrderedRange(NoritoKeyRangeError::Capacity),
        }
    }
}

/// Typed staging shared by iterator and owner-callback table construction.
pub(in crate::state) struct TypedPairedTableBuilder<'budget, K, V> {
    table: &'static str,
    selection: CanonicalTableLeafSet,
    encoded: StagedRows,
    key_schema: Schema,
    value_schema: Schema,
    limits: LeafLimits,
    budget: &'budget iroha_allocation::AllocationBudget,
    retained_bytes: usize,
    streamed_bytes: u64,
    types: PhantomData<fn(&K, &V)>,
}

impl<'budget, K: Encode + NoritoSchema, V: Encode + NoritoSchema>
    TypedPairedTableBuilder<'budget, K, V>
{
    /// Select one declared table with the caller's original pool and bounds.
    pub(in crate::state) fn new(
        table: &str,
        limits: LeafLimits,
        budget: &'budget iroha_allocation::AllocationBudget,
    ) -> Result<Self, LeafError> {
        let selection = CanonicalTableLeafSet::new(&[table], limits, budget)?;
        let Some((table, (key_schema, value_schema))) = selection.selection.table(table) else {
            unreachable!("selected table remains registered")
        };
        let maximum = limits.max_rows.min(MAX_NORITO_TREE_ENTRIES as u64);
        Ok(Self {
            table,
            encoded: StagedRows::new(maximum as usize, budget)?,
            selection,
            key_schema,
            value_schema,
            limits,
            budget,
            retained_bytes: 0,
            streamed_bytes: 0,
            types: PhantomData,
        })
    }

    /// Encode this borrowed row immediately; refusal destroys the whole prefix.
    /// Admit the next geometry before key backing, and both bounded value passes
    /// before either starts. The original pool separately admits actual storage.
    pub(in crate::state) fn push(
        mut self,
        key: &K,
        value: &V,
        allowance: TypedPairedRowAllowance,
    ) -> Result<Self, TypedPairedRowError> {
        if self.encoded.len() as u64 >= self.limits.max_rows.min(MAX_NORITO_TREE_ENTRIES as u64) {
            return Err(LeafError::RowLimit.into());
        }
        let previous = ordered_retained_bytes(self.encoded.len(), self.retained_bytes)?;
        let next_without_key = self
            .retained_bytes
            .checked_add(3 * Hash::LENGTH)
            .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?;
        let next_without_key = ordered_retained_bytes(self.encoded.len() + 1, next_without_key)?;
        let table_key_bound = self
            .limits
            .max_ordered_table_bytes
            .min(MAX_NORITO_TREE_PAYLOAD_BYTES)
            .checked_sub(next_without_key)
            .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?
            / 2;
        let added_without_key = next_without_key
            .checked_sub(previous)
            .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?;
        let aggregate_key_bound = allowance
            .ordered_bytes
            .checked_sub(added_without_key)
            .ok_or(TypedPairedRowError::OrderedAllowance)?
            / 2;
        let payload_key_bound = self.limits.max_payload_bytes.min(MAX_NORITO_KEY_BYTES);
        let key_bound = payload_key_bound
            .min(table_key_bound)
            .min(aggregate_key_bound);
        let key = staging::encode_key(self.table, self.key_schema, key, key_bound, self.budget)
            .map_err(|error| {
                if error == LeafError::PayloadLimit && key_bound < payload_key_bound {
                    if table_key_bound <= aggregate_key_bound {
                        TypedPairedRowError::Table(LeafError::OrderedRange(
                            NoritoKeyRangeError::Capacity,
                        ))
                    } else {
                        TypedPairedRowError::OrderedAllowance
                    }
                } else {
                    TypedPairedRowError::Table(error)
                }
            })?;
        charge_digest_row(&mut self.retained_bytes, key.as_slice().len(), self.limits)?;
        let table_bound = value_stream_bound(self.limits, self.streamed_bytes)?;
        let aggregate_bound = usize::try_from(allowance.streamed_bytes / 2).unwrap_or(usize::MAX);
        let bound = table_bound.min(aggregate_bound);
        let (ordered_value_digest, lookup_value_digest, length) =
            typed_bare_payload_digests(self.table, self.value_schema, value, bound).map_err(
                |error| {
                    if error == LeafError::PayloadLimit && aggregate_bound < table_bound {
                        TypedPairedRowError::StreamedAllowance
                    } else {
                        TypedPairedRowError::Table(value_stream_error(error, bound, self.limits))
                    }
                },
            )?;
        charge_streamed_value(&mut self.streamed_bytes, length, self.limits)?;
        self.encoded.push(PairedDigestRow {
            key,
            ordered_value_digest,
            lookup_value_digest,
        })?;
        Ok(self)
    }

    /// Actual logical work/retention counters before final tree construction.
    pub(in crate::state) fn usage(&self) -> Result<(u64, u64, usize), LeafError> {
        Ok((
            self.encoded.len() as u64,
            self.streamed_bytes,
            ordered_retained_bytes(self.encoded.len(), self.retained_bytes)?,
        ))
    }

    /// Finish both existing indexes without accepting another inventory.
    pub(in crate::state) fn finish(self) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        CanonicalTableLeafSet::paired_table_from_digest_rows(
            self.table,
            self.limits,
            self.budget,
            self.selection,
            self.encoded,
            self.retained_bytes,
        )
    }
}

#[cfg(test)]
#[path = "typed_tests.rs"]
mod tests;
