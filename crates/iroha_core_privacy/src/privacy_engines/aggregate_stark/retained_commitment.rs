//! Clearing Merkle cut custody and original-coordinate selected row replay.
//!
//! A cut is retained only inside the prover. No root, selected row or frontier
//! escapes a replay until both its original subtree and full root agree.

use super::*;

pub const CUT_LEVEL_V1: usize = 4;
const CUT_ROWS_V1: usize = 1 << CUT_LEVEL_V1;

/// Original level-four roots, without copying or debug-printing private custody.
pub struct RetainedMerkleCutV1 {
    rows: usize,
    roots: Vec<PrivacyOuterDigestV1>,
    root: PrivacyOuterDigestV1,
}

impl RetainedMerkleCutV1 {
    pub(super) fn new_v1(rows: usize) -> Result<Self, AggregateStarkErrorV1> {
        if rows < CUT_ROWS_V1 || !rows.is_power_of_two() {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let count = rows / CUT_ROWS_V1;
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(count)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        if roots.capacity() != count {
            return Err(AggregateStarkErrorV1::AllocationFailure);
        }
        Ok(Self {
            rows,
            roots,
            root: PrivacyOuterDigestV1::default(),
        })
    }

    /// Capture original global coordinates before reduction overwrites them.
    pub(super) fn capture_v1(
        &mut self,
        first: usize,
        nodes: &[PrivacyOuterDigestV1],
    ) -> Result<(), AggregateStarkErrorV1> {
        if first != self.roots.len()
            || first
                .checked_add(nodes.len())
                .is_none_or(|end| end > self.rows / CUT_ROWS_V1)
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        self.roots.extend_from_slice(nodes);
        Ok(())
    }

    pub(super) fn bind_root_v1(
        &mut self,
        root: PrivacyOuterDigestV1,
    ) -> Result<(), AggregateStarkErrorV1> {
        if self.roots.len() != self.rows / CUT_ROWS_V1 {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        self.root = root;
        Ok(())
    }

    /// Bind replay to the root already absorbed by the original transcript.
    pub(crate) fn check_root_v1(
        &self,
        rows: usize,
        expected: PrivacyOuterDigestV1,
    ) -> Result<(), AggregateStarkErrorV1> {
        if self.rows != rows || self.roots.len() != rows / CUT_ROWS_V1 || self.root != expected {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        Ok(())
    }

    /// Exact retained allocation and owner, charged across every phase lifetime.
    pub(crate) fn payload_bound_v1(rows: usize) -> Result<usize, AggregateStarkErrorV1> {
        if rows < CUT_ROWS_V1 || !rows.is_power_of_two() {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        (rows / CUT_ROWS_V1)
            .checked_mul(core::mem::size_of::<PrivacyOuterDigestV1>())
            .and_then(|n| n.checked_add(core::mem::size_of::<Self>()))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }
}

impl Drop for RetainedMerkleCutV1 {
    fn drop(&mut self) {
        for root in &mut self.roots {
            root.zeroize_v1();
        }
        self.root.zeroize_v1();
        #[cfg(test)]
        tests::observe_cut_clear_v1(&self.roots);
    }
}

/// Selected streams retain original global indices and complete-field checking.
pub struct SelectedRowCommitmentV1<'a> {
    inner: StreamingRowCommitmentV1,
    selected_rows: Vec<usize>,
    cut: &'a RetainedMerkleCutV1,
}

/// Conservative payload for selected streams, rows, index plans and frontier.
/// Both exact vector capacities and the existing tile/worker reserve are charged.
/// B-tree entries receive a conservative 1,024-byte allocation allowance each.
pub fn selected_payload_bound_v1(
    rows: usize,
    width: usize,
    queries: usize,
) -> Result<usize, AggregateStarkErrorV1> {
    if rows < CUT_ROWS_V1 || !rows.is_power_of_two() || width == 0 || queries == 0 || queries > rows
    {
        return Err(AggregateStarkErrorV1::InvalidLayout);
    }
    let selected = queries
        .checked_mul(CUT_ROWS_V1)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?
        .min(rows);
    let height = rows.ilog2() as usize;
    let field_row = width
        .checked_mul(core::mem::size_of::<F>())
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let row_owner = field_row
        .checked_add(core::mem::size_of::<Vec<F>>() + core::mem::size_of::<usize>() + 1024)
        .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
    let terms = [
        selected.checked_mul(
            core::mem::size_of::<PrivacyOuterLastFieldStreamV1>()
                + core::mem::size_of::<usize>()
                + MASKED_TRACE_LDE_COLUMN_BATCH_V1 * 8,
        ),
        queries.checked_mul(row_owner),
        queries.checked_mul(height).and_then(|n| {
            n.checked_mul(core::mem::size_of::<Option<PrivacyOuterDigestV1>>() + 1024)
        }),
        (height + 1).checked_mul(
            core::mem::size_of::<Option<PrivacyOuterDigestV1>>()
                + core::mem::size_of::<PrivacyOuterDomainPrefixV1>(),
        ),
        Some(
            core::mem::size_of::<SelectedRowCommitmentV1<'_>>()
                + core::mem::size_of::<StreamingMerkleAccumulatorV1>()
                + core::mem::size_of::<DigestCutTileV1>(),
        ),
        Some(streaming_commitment::payload_bound_v1()?),
    ];
    terms.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value.ok_or(AggregateStarkErrorV1::InvalidLayout)?)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    })
}

impl<'a> SelectedRowCommitmentV1<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_v1(
        context: TransparentStarkDigestContextV1,
        leaf_role: &[u8],
        node_role: &'static [u8],
        group: usize,
        rows: usize,
        width: usize,
        opening_indices: &[usize],
        cut: &'a RetainedMerkleCutV1,
    ) -> Result<Self, AggregateStarkErrorV1> {
        context.validate().map_err(map_transparent_error_v1)?;
        if cut.rows != rows
            || cut.roots.len() != rows / CUT_ROWS_V1
            || cut.roots.capacity() != cut.roots.len()
            || opening_indices.is_empty()
            || width == 0
            || leaf_role.is_empty()
            || node_role.is_empty()
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        validate_canonical_index_set_v1(rows, opening_indices)?;
        let mut count = 0usize;
        let mut previous = None;
        for &row in opening_indices {
            let block = row / CUT_ROWS_V1;
            if previous != Some(block) {
                count += 1;
                previous = Some(block);
            }
        }
        let selected_count = count
            .checked_mul(CUT_ROWS_V1)
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let mut selected_rows = Vec::new();
        selected_rows
            .try_reserve_exact(selected_count)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        if selected_rows.capacity() != selected_count {
            return Err(AggregateStarkErrorV1::AllocationFailure);
        }
        previous = None;
        for &row in opening_indices {
            let block = row / CUT_ROWS_V1;
            if previous != Some(block) {
                selected_rows.extend(block * CUT_ROWS_V1..(block + 1) * CUT_ROWS_V1);
                previous = Some(block);
            }
        }
        let group = u16::try_from(group)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let width_u16 = u16::try_from(width)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let value_bytes = width
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let mut digest_streams = Vec::new();
        digest_streams
            .try_reserve_exact(selected_count)
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        if digest_streams.capacity() != selected_count {
            return Err(AggregateStarkErrorV1::AllocationFailure);
        }
        let catalog = context.catalog_v1();
        let domain = context
            .domain_v1(&catalog, leaf_role, b"vector-row-leaf", 0, 0, 0)
            .map_err(map_transparent_error_v1)?;
        let prefix =
            PrivacyOuterDomainPrefixV1::new(domain).ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        for &row in &selected_rows {
            digest_streams.push(
                prefix
                    .last_field_stream_at_with_counter(
                        row as u64,
                        u64::from(u16::from_be_bytes(group)),
                        &[&group, &width_u16],
                        value_bytes,
                    )
                    .map_err(map_digest_stream_error_v1)
                    .map_err(map_transparent_error_v1)?,
            );
        }
        // This existing owner clears rows on every error and unwind path.
        let mut inner = StreamingRowCommitmentV1 {
            rows,
            width,
            received_columns: 0,
            failed: false,
            context,
            node_role,
            digest_streams,
            opening_indices: opening_indices.to_vec(),
            opened_rows: BTreeMap::new(),
        };
        for &index in opening_indices {
            let mut values = Vec::new();
            values
                .try_reserve_exact(width)
                .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
            if values.capacity() != width {
                return Err(AggregateStarkErrorV1::AllocationFailure);
            }
            inner.opened_rows.insert(index, values);
        }
        Ok(Self {
            inner,
            selected_rows,
            cut,
        })
    }

    /// Canonical global rows for the exact original cut subtrees.
    pub(crate) fn selected_rows_v1(&self) -> &[usize] {
        &self.selected_rows
    }

    pub(crate) fn absorb_selected_columns_v1<C: AsRef<[F]> + Sync>(
        &mut self,
        columns: &[C],
    ) -> Result<(), AggregateStarkErrorV1> {
        let inner = &mut self.inner;
        if inner.failed
            || columns.is_empty()
            || columns.len() > MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || inner
                .received_columns
                .checked_add(columns.len())
                .is_none_or(|end| end > inner.width)
            || columns
                .iter()
                .any(|column| column.as_ref().len() != self.selected_rows.len())
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        // Every supplied compact value is checked. The transform owner validates
        // all original coefficients and all device words before selecting rows.
        if columns.iter().any(|column| {
            column
                .as_ref()
                .iter()
                .any(|value| F::canonical(value.0).is_none())
        }) {
            return Err(AggregateStarkErrorV1::NonCanonicalField);
        }
        inner.failed = true;
        let failure = inner
            .digest_streams
            .par_iter_mut()
            .zip(&self.selected_rows)
            .enumerate()
            .map(|(selected, (stream, &row))| {
                let mut packed =
                    zeroize::Zeroizing::new([0u8; MASKED_TRACE_LDE_COLUMN_BATCH_V1 * 8]);
                for (index, column) in columns.iter().enumerate() {
                    packed[index * 8..(index + 1) * 8]
                        .copy_from_slice(&column.as_ref()[selected].0.to_be_bytes());
                }
                stream
                    .update(&packed[..columns.len() * 8])
                    .err()
                    .map(|error| (row, error))
            })
            .reduce(
                || None,
                |left, right| match (left, right) {
                    (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
                    (left, right) => left.or(right),
                },
            );
        if let Some((_, error)) = failure {
            return Err(map_transparent_error_v1(map_digest_stream_error_v1(error)));
        }
        for &index in &inner.opening_indices {
            let selected = self
                .selected_rows
                .binary_search(&index)
                .map_err(|_| AggregateStarkErrorV1::InternalInvariant)?;
            let row = inner
                .opened_rows
                .get_mut(&index)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
            for column in columns {
                row.push(column.as_ref()[selected]);
            }
        }
        inner.received_columns += columns.len();
        inner.failed = false;
        Ok(())
    }

    // Independent pre-optimization full-row oracle for retained-root tests.
    #[cfg(test)]
    pub(crate) fn absorb_columns_v1<C: AsRef<[F]> + Sync>(
        &mut self,
        columns: &[C],
    ) -> Result<(), AggregateStarkErrorV1> {
        let inner = &mut self.inner;
        if inner.failed
            || columns.is_empty()
            || columns.len() > MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || inner
                .received_columns
                .checked_add(columns.len())
                .is_none_or(|end| end > inner.width)
            || columns
                .iter()
                .any(|column| column.as_ref().len() != inner.rows)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        // Retain the complete original canonical-field scan, including unqueried rows.
        if columns.iter().any(|column| {
            column
                .as_ref()
                .iter()
                .any(|value| F::canonical(value.0).is_none())
        }) {
            return Err(AggregateStarkErrorV1::NonCanonicalField);
        }
        inner.failed = true;
        let failure = inner
            .digest_streams
            .par_iter_mut()
            .zip(&self.selected_rows)
            .map(|(stream, &row)| {
                let mut packed =
                    zeroize::Zeroizing::new([0u8; MASKED_TRACE_LDE_COLUMN_BATCH_V1 * 8]);
                for (index, column) in columns.iter().enumerate() {
                    packed[index * 8..(index + 1) * 8]
                        .copy_from_slice(&column.as_ref()[row].0.to_be_bytes());
                }
                stream
                    .update(&packed[..columns.len() * 8])
                    .err()
                    .map(|error| (row, error))
            })
            .reduce(
                || None,
                |left, right| match (left, right) {
                    (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
                    (left, right) => left.or(right),
                },
            );
        if let Some((_, error)) = failure {
            return Err(map_transparent_error_v1(map_digest_stream_error_v1(error)));
        }
        for &index in &inner.opening_indices {
            let row = inner
                .opened_rows
                .get_mut(&index)
                .ok_or(AggregateStarkErrorV1::InternalInvariant)?;
            for column in columns {
                row.push(column.as_ref()[index]);
            }
        }
        inner.received_columns += columns.len();
        inner.failed = false;
        Ok(())
    }

    pub(crate) fn finish_v1(
        mut self,
    ) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1> {
        let inner = &mut self.inner;
        if inner.failed
            || inner.received_columns != inner.width
            || inner.digest_streams.len() != self.selected_rows.len()
            || inner.digest_streams.capacity() != self.selected_rows.len()
            || inner
                .opened_rows
                .values()
                .any(|values| values.len() != inner.width)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        let mut acc = StreamingMerkleAccumulatorV1::new(
            inner.context,
            inner.node_role,
            inner.rows,
            &inner.opening_indices,
        )?;
        let mut offset = 0usize;
        let mut tile = DigestCutTileV1([PrivacyOuterDigestV1::default(); CUT_ROWS_V1]);
        for (block, &original) in self.cut.roots.iter().enumerate() {
            if self.selected_rows.get(offset).copied() == Some(block * CUT_ROWS_V1) {
                for (slot, stream) in tile
                    .0
                    .iter_mut()
                    .zip(&mut inner.digest_streams[offset..offset + CUT_ROWS_V1])
                {
                    *slot = stream
                        .finalize_in_place_v1()
                        .map_err(map_digest_stream_error_v1)
                        .map_err(map_transparent_error_v1)?;
                }
                // Reduction uses the accumulator's original leaf offset and levels.
                streaming_commitment::append_tile_v1(&mut acc, &mut tile.0)?;
                if tile.0[0] != original {
                    return Err(AggregateStarkErrorV1::InvalidProofShape);
                }
                for node in &mut tile.0 {
                    node.zeroize_v1();
                }
                offset += CUT_ROWS_V1;
            } else {
                acc.append_subtree_v1(CUT_LEVEL_V1, original)?;
            }
        }
        if offset != self.selected_rows.len()
            || acc.pending.last().copied().flatten() != Some(self.cut.root)
        {
            return Err(AggregateStarkErrorV1::InvalidProofShape);
        }
        // All root checks precede the first ownership transfer into public data.
        let commitment = acc.finish()?;
        Ok(StreamingRowCommitmentResultV1 {
            commitment,
            opened_rows: core::mem::take(&mut inner.opened_rows),
        })
    }
}

struct DigestCutTileV1([PrivacyOuterDigestV1; CUT_ROWS_V1]);
impl Drop for DigestCutTileV1 {
    fn drop(&mut self) {
        for node in &mut self.0 {
            node.zeroize_v1();
        }
    }
}

#[cfg(test)]
#[path = "retained_commitment_tests.rs"]
mod tests;
