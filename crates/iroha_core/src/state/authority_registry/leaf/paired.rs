//! Paired canonical table construction using the caller's original allocation pool.
//!
//! The ordered tree retains funded final key/digest backing, Merkle levels and
//! its private owner. Staging rows and canonical keys retain their own original
//! charges through sorting and final copies. Lookup nodes retain the same pool;
//! table-selection bits are inline; schema-name and serializer scratch funding remain open.
//! No finalized authority is claimed.

use super::*;
#[path = "paired/staging.rs"]
mod staging;
use staging::{PairedDigestRow, StagedRows};

#[path = "paired/typed.rs"]
mod typed;
pub(in crate::state) use typed::{
    TypedPairedRowAllowance, TypedPairedRowError, TypedPairedTableBuilder,
};

#[path = "paired/retained_semantic.rs"]
mod retained_semantic;
pub(in crate::state) use retained_semantic::{RetainedSemanticError, RetainedSemanticRows};

impl CanonicalTableLeafSet {
    /// Build both table indexes from one canonical streaming value per row.
    ///
    /// Both digests consume identical bytes in a common encoder pass. Only
    /// bounded keys and digests are retained, even for large code or histories.
    ///
    /// # Errors
    /// Refuses unresolved schemas, nominal-type mismatches, duplicate keys,
    /// fixed table/row/byte bounds, and local allocation failure.
    pub(crate) fn paired_table_from_rows<'a, K, V>(
        table: &str,
        limits: LeafLimits,
        budget: &iroha_allocation::AllocationBudget,
        rows: impl IntoIterator<Item = (&'a K, &'a V)>,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError>
    where
        K: Encode + NoritoSchema + 'a,
        V: Encode + NoritoSchema + 'a,
    {
        let mut builder = TypedPairedTableBuilder::new(table, limits, budget)?;
        for (key, value) in rows {
            builder = builder
                .push(
                    key,
                    value,
                    TypedPairedRowAllowance {
                        streamed_bytes: limits.max_streamed_value_bytes,
                        ordered_bytes: limits.max_ordered_table_bytes,
                    },
                )
                .map_err(TypedPairedRowError::into_leaf)?;
        }
        builder.finish()
    }

    /// Build one scoped pair from an owner-supplied semantic value projection.
    ///
    /// The caller must be the reviewed owner of the actual value and supply its
    /// declared borrowed V1 encoder. The exact semantic identity, canonical
    /// key type, row count, and bounded encoded bytes are checked here. This
    /// still cannot establish a complete State root or finality.
    ///
    /// # Errors
    /// Rejects an unresolved or mismatched schema, changed encodings, duplicate
    /// keys, row/byte limits, or local allocation failure before returning nodes.
    pub(crate) fn paired_semantic_table_from_rows<'a, K, V, S>(
        table: &str,
        semantic_identity: &'static str,
        limits: LeafLimits,
        budget: &iroha_allocation::AllocationBudget,
        rows: impl IntoIterator<Item = (&'a K, &'a V)>,
        project: impl Fn(&'a V) -> S,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError>
    where
        K: Encode + NoritoSchema + 'a,
        V: 'a,
        S: Encode,
    {
        let mut builder = retained_semantic::RetainedSemanticTable::once(
            table,
            semantic_identity,
            limits,
            budget,
        )?;
        let limit = builder.work_bound()?;
        for (key, value) in rows {
            builder
                .push(key, || project(value), limit)
                .map_err(|error| error.into_leaf())?;
        }
        builder.seal_rows();
        builder
            .advance_finalizer(limit)
            .map_err(|error| error.into_leaf())?;
        builder.take_once()
    }

    fn paired_table_from_digest_rows(
        table: &str,
        limits: LeafLimits,
        budget: &iroha_allocation::AllocationBudget,
        mut lookup: Self,
        mut encoded: StagedRows,
        retained_bytes: usize,
    ) -> Result<CanonicalTablePairedSnapshot, LeafError> {
        let Some((table, (key_schema, _))) = lookup.selection.table(table) else {
            unreachable!("selected table remains registered")
        };
        let maximum = limits
            .max_ordered_table_bytes
            .min(MAX_NORITO_TREE_PAYLOAD_BYTES);
        if !encoded.is_empty() && ordered_retained_bytes(encoded.len(), retained_bytes)? > maximum {
            return Err(LeafError::OrderedRange(NoritoKeyRangeError::Capacity));
        }
        encoded
            .as_mut_slice()
            .sort_unstable_by(|left, right| left.key.as_slice().cmp(right.key.as_slice()));
        let ordered = NoritoKeyDigestRangeTreeV1::from_sorted_digests(
            lookup.selection.schema,
            table.as_bytes(),
            encoded
                .as_slice()
                .iter()
                .map(|row| (row.key.as_slice(), row.ordered_value_digest)),
            limits.max_ordered_table_bytes,
            budget,
        )
        .map_err(LeafError::OrderedRange)?;
        let table_len = u64::try_from(table.len()).expect("static table identity fits u64");
        for row in encoded.as_slice() {
            let key_hash = bare_payload_hash(table, key_schema, row.key.as_slice(), KEY_PAYLOAD)?;
            let path = Hash::new_from_chunks(&[
                PATH,
                &table_len.to_le_bytes(),
                table.as_bytes(),
                key_hash.as_ref(),
            ]);
            lookup
                .leaves
                .replace(path, None, Some(row.lookup_value_digest))
                .map_err(|error| lookup_error(error, table))?;
        }
        let lookup_root = lookup.root();
        let ordered_root = ordered.root();
        let row_count = u64::try_from(ordered.len()).expect("bounded table row count fits u64");
        let root = paired_root(table, row_count, lookup_root, ordered_root);
        Ok(CanonicalTablePairedSnapshot {
            lookup,
            ordered,
            root,
        })
    }
}

#[cfg(test)]
#[path = "paired/funding_tests.rs"]
mod funding_tests;

/// Exact retained canonical row framing plus complete ordered Merkle levels.
fn ordered_retained_bytes(rows: usize, retained: usize) -> Result<usize, LeafError> {
    let nodes = if rows == 0 {
        0
    } else {
        rows.checked_next_power_of_two()
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| count.checked_sub(1))
            .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))?
    };
    nodes
        .checked_mul(Hash::LENGTH)
        .and_then(|bytes| retained.checked_add(bytes))
        .ok_or(LeafError::OrderedRange(NoritoKeyRangeError::Capacity))
}
