//! Ordered common-domain commitments retaining each logical trace's native degree.
//!
//! MAIN binds this immutable joined layout before deriving auxiliary challenges;
//! its codec authenticates the same complete ordered row using one root per
//! phase while every logical polynomial retains its native degree.

use super::*;

/// Which independently committed transcript phase the joined row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinedTraceColumnKindV1 {
    /// Challenge-independent masked trace columns.
    Base,
    /// Masked product and other challenge-dependent columns.
    Aux,
}

/// Immutable ordered group slices for one common-domain vector commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinedTraceCommitmentPlanV1 {
    commitment_lde_log2: u8,
    kind: JoinedTraceColumnKindV1,
    groups: Vec<(u8, std::ops::Range<usize>)>,
    width: usize,
}

impl JoinedTraceCommitmentPlanV1 {
    /// Derive every native domain, width and slice from the verified layout.
    pub(crate) fn new_v1(
        parameters: AggregateStarkParametersV1,
        layout: &AggregateProofLayoutV1,
        kind: JoinedTraceColumnKindV1,
    ) -> Result<Self, AggregateStarkErrorV1> {
        layout.validate(parameters)?;
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(layout.trace_groups.len())
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        let mut width = 0_usize;
        for group in &layout.trace_groups {
            let start = width;
            width = width
                .checked_add(match kind {
                    JoinedTraceColumnKindV1::Base => group.base_width,
                    JoinedTraceColumnKindV1::Aux => group.aux_width,
                })
                .filter(|&total| total <= usize::from(u16::MAX))
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
            groups.push((group.native_trace_log2, start..width));
        }
        Ok(Self {
            commitment_lde_log2: layout.common_lde_log2,
            kind,
            groups,
            width,
        })
    }

    /// Exact public slice preserving a logical group's canonical column order.
    pub(crate) fn group_range_v1(
        &self,
        group: usize,
    ) -> Result<std::ops::Range<usize>, AggregateStarkErrorV1> {
        self.groups
            .get(group)
            .map(|(_, range)| range.clone())
            .ok_or(AggregateStarkErrorV1::InvalidLayout)
    }

    /// Exact summed vector width, without padding to the largest native trace.
    #[cfg(test)]
    pub(crate) const fn width_v1(&self) -> usize {
        self.width
    }

    fn roles_v1(&self, domains: &AggregateStarkDomainsV1) -> (&'static [u8], &'static [u8]) {
        match self.kind {
            JoinedTraceColumnKindV1::Base => (domains.base_leaf, domains.base_node),
            JoinedTraceColumnKindV1::Aux => (domains.aux_leaf, domains.aux_node),
        }
    }

    /// Commit or replay all ordered retained polynomials using one digest state
    /// per common-domain row and at most eight zeroizing evaluation columns.
    ///
    /// Every polynomial and index is checked before commitment allocation or
    /// FFT work. Native coefficient vectors stay in their original clearing
    /// owners. Column order and root bytes are independent of Rayon scheduling.
    #[cfg(test)]
    pub(crate) fn commit_v1(
        &self,
        domains: &AggregateStarkDomainsV1,
        polynomials: &[&MaskedTracePolynomialSetV1],
        opening_indices: &[usize],
    ) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1> {
        domains.validate()?;
        let rows = checked_domain_size_v1(self.commitment_lde_log2)?;
        if polynomials.len() != self.groups.len() {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        for (polynomials, (native, range)) in polynomials.iter().zip(&self.groups) {
            polynomials.validate_v1()?;
            if polynomials.native_trace_log2 != *native
                || polynomials.commitment_lde_log2 != self.commitment_lde_log2
                || polynomials.width() != range.len()
            {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
        }
        if !opening_indices.is_empty() {
            validate_canonical_index_set_v1(rows, opening_indices)?;
        }
        let (leaf, node) = self.roles_v1(domains);
        let mut commitment = StreamingRowCommitmentV1::new(
            domains.digest_context,
            leaf,
            node,
            JOINED_TRACE_GROUP_MARKER_V1,
            rows,
            self.width,
            opening_indices,
        )?;
        for polynomials in polynomials {
            for batch in polynomials.columns.chunks(MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
                // Validation above scans the complete retained set only once;
                // evaluating one column does not rescan every other column.
                let evaluations = batch
                    .par_iter()
                    .map(|coefficients| {
                        masked_trace_coefficients_on_coset_v1(
                            coefficients,
                            polynomials.native_trace_log2,
                            self.commitment_lde_log2,
                        )
                        .map(ZeroizingFieldColumnV1)
                        .map_err(map_transparent_error_v1)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                commitment.absorb_columns_v1(&evaluations)?;
            }
        }
        commitment.finish()
    }

    /// Replay immutable native sources with their original explicit masks.
    /// The callback transfers one clearing coefficient allocation at a time;
    /// at most eight transforms coexist and the leaf framing is unchanged.
    #[cfg(test)]
    pub(crate) fn commit_replayed_v1(
        &self,
        domains: &AggregateStarkDomainsV1,
        opening_indices: &[usize],
        mut coefficients: impl FnMut(usize, usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
        mut evaluate: impl FnMut(
            &[ZeroizingFieldColumnV1],
            u8,
            u8,
        ) -> Result<Vec<ZeroizingFieldColumnV1>, AggregateStarkErrorV1>,
    ) -> Result<StreamingRowCommitmentResultV1, AggregateStarkErrorV1> {
        domains.validate()?;
        let rows = checked_domain_size_v1(self.commitment_lde_log2)?;
        if !opening_indices.is_empty() {
            validate_canonical_index_set_v1(rows, opening_indices)?;
        }
        let (leaf, node) = self.roles_v1(domains);
        let mut commitment = StreamingRowCommitmentV1::new(
            domains.digest_context,
            leaf,
            node,
            JOINED_TRACE_GROUP_MARKER_V1,
            rows,
            self.width,
            opening_indices,
        )?;
        for (group, (native, range)) in self.groups.iter().enumerate() {
            for start in (0..range.len()).step_by(MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
                let end = (start + MASKED_TRACE_LDE_COLUMN_BATCH_V1).min(range.len());
                let mut batch = Vec::new();
                batch
                    .try_reserve_exact(end - start)
                    .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
                for column in start..end {
                    batch.push(ZeroizingFieldColumnV1(coefficients(group, column)?));
                }
                let evaluations = evaluate(&batch, *native, self.commitment_lde_log2)?;
                if evaluations.len() != batch.len()
                    || evaluations.iter().any(|column| column.len() != rows)
                {
                    return Err(AggregateStarkErrorV1::InvalidLayout);
                }
                commitment.absorb_columns_v1(&evaluations)?;
            }
        }
        commitment.finish()
    }

    /// Collect an original clearing cut, or replay only original queried subtrees.
    /// The initial commitment evaluates the full domain. A replay requests only
    /// canonical global rows of the original queried cuts, while the transform
    /// owner validates every original coefficient and preserves mask custody.
    pub(crate) fn commit_retained_replayed_v1(
        &self,
        domains: &AggregateStarkDomainsV1,
        opening_indices: &[usize],
        cut: Option<&retained_commitment::RetainedMerkleCutV1>,
        mut coefficients: impl FnMut(usize, usize) -> Result<Vec<F>, AggregateStarkErrorV1>,
        mut evaluate: impl FnMut(
            &[ZeroizingFieldColumnV1],
            u8,
            u8,
            Option<&[usize]>,
        ) -> Result<Vec<ZeroizingFieldColumnV1>, AggregateStarkErrorV1>,
    ) -> Result<
        (
            StreamingRowCommitmentResultV1,
            Option<retained_commitment::RetainedMerkleCutV1>,
        ),
        AggregateStarkErrorV1,
    > {
        domains.validate()?;
        let rows = checked_domain_size_v1(self.commitment_lde_log2)?;
        let (leaf, node) = self.roles_v1(domains);
        let mut builder = match cut {
            Some(cut) => RetainedReplayBuilderV1::Selected(
                retained_commitment::SelectedRowCommitmentV1::new_v1(
                    domains.digest_context,
                    leaf,
                    node,
                    JOINED_TRACE_GROUP_MARKER_V1,
                    rows,
                    self.width,
                    opening_indices,
                    cut,
                )?,
            ),
            None => {
                if !opening_indices.is_empty() {
                    return Err(AggregateStarkErrorV1::InvalidLayout);
                }
                RetainedReplayBuilderV1::Initial(StreamingRowCommitmentV1::new(
                    domains.digest_context,
                    leaf,
                    node,
                    JOINED_TRACE_GROUP_MARKER_V1,
                    rows,
                    self.width,
                    &[],
                )?)
            }
        };
        for (group, (native, range)) in self.groups.iter().enumerate() {
            for start in (0..range.len()).step_by(MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
                let end = (start + MASKED_TRACE_LDE_COLUMN_BATCH_V1).min(range.len());
                let mut batch = Vec::new();
                batch
                    .try_reserve_exact(end - start)
                    .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
                for column in start..end {
                    batch.push(ZeroizingFieldColumnV1(coefficients(group, column)?));
                }
                let selected = match &builder {
                    RetainedReplayBuilderV1::Initial(_) => None,
                    RetainedReplayBuilderV1::Selected(builder) => Some(builder.selected_rows_v1()),
                };
                let evaluated_rows = selected.map_or(rows, <[usize]>::len);
                let evaluations = evaluate(&batch, *native, self.commitment_lde_log2, selected)?;
                if evaluations.len() != batch.len()
                    || evaluations
                        .iter()
                        .any(|column| column.len() != evaluated_rows)
                {
                    return Err(AggregateStarkErrorV1::InvalidLayout);
                }
                match &mut builder {
                    RetainedReplayBuilderV1::Initial(builder) => {
                        builder.absorb_columns_v1(&evaluations)?
                    }
                    RetainedReplayBuilderV1::Selected(builder) => {
                        builder.absorb_selected_columns_v1(&evaluations)?
                    }
                }
            }
        }
        match builder {
            RetainedReplayBuilderV1::Initial(builder) => {
                let (result, cut) = builder.finish_retaining_cut_v1()?;
                Ok((result, Some(cut)))
            }
            RetainedReplayBuilderV1::Selected(builder) => Ok((builder.finish_v1()?, None)),
        }
    }

    /// Hash an opened common-domain row without copying its logical slices.
    /// No current/next row or relation is omitted by this primitive.
    #[cfg(test)]
    pub(crate) fn leaf_hash_v1(
        &self,
        domains: &AggregateStarkDomainsV1,
        row_index: usize,
        logical_rows: &[&[F]],
    ) -> Result<PrivacyOuterDigestV1, AggregateStarkErrorV1> {
        domains.validate()?;
        if row_index >= checked_domain_size_v1(self.commitment_lde_log2)?
            || logical_rows.len() != self.groups.len()
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        for (row, (_, range)) in logical_rows.iter().zip(&self.groups) {
            if row.len() != range.len() {
                return Err(AggregateStarkErrorV1::InvalidLayout);
            }
            if row.iter().any(|value| F::canonical(value.0).is_none()) {
                return Err(AggregateStarkErrorV1::NonCanonicalField);
            }
        }
        let group = u16::MAX.to_be_bytes();
        let width = u16::try_from(self.width)
            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)?
            .to_be_bytes();
        let (leaf, _) = self.roles_v1(domains);
        let mut stream = privacy_outer_last_field_stream_v1(
            domains.digest_context,
            leaf,
            b"vector-row-leaf",
            0,
            u64::try_from(row_index).map_err(|_| AggregateStarkErrorV1::InvalidLayout)?,
            u64::from(u16::MAX),
            &[&group, &width],
            self.width
                .checked_mul(core::mem::size_of::<u64>())
                .ok_or(AggregateStarkErrorV1::InvalidLayout)?,
        )
        .map_err(map_transparent_error_v1)?;
        for row in logical_rows {
            for value in *row {
                let packed = zeroize::Zeroizing::new(value.0.to_be_bytes());
                stream
                    .update(&packed[..])
                    .map_err(map_digest_stream_error_v1)
                    .map_err(map_transparent_error_v1)?;
            }
        }
        stream
            .finalize()
            .map_err(map_digest_stream_error_v1)
            .map_err(map_transparent_error_v1)
    }
}

/// The selected builder owns private output rows until original-root agreement.
enum RetainedReplayBuilderV1<'a> {
    Initial(StreamingRowCommitmentV1),
    Selected(retained_commitment::SelectedRowCommitmentV1<'a>),
}

#[cfg(test)]
#[path = "joined_trace_tests.rs"]
mod tests;
