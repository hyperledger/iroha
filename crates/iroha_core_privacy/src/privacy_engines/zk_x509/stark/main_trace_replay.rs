//! Original-mask replay from closed immutable MAIN witness owners.

use super::super::super::der_stark::{
    fill_zk_x509_der_stark_native_aux_columns_v1, fill_zk_x509_der_stark_native_base_columns_v1,
};
use super::super::super::private_table::{
    PrivateTableV1, zeroize_field_rows_v1, zeroize_fields_v1,
};
#[cfg(test)]
use super::super::super::prover_observation::{PhaseTimerV1, PhaseV1};
use super::main_bounded_transform::{MainBoundedTransformPolicyV1, check_completion_v1};
use super::*;
use crate::privacy_engines::transparent_stark::{ReplayableTraceMaskV1, sample_trace_mask_v1};
use fastpq_prover::goldilocks_transform::{
    GoldilocksTransformBackendV1 as Backend, GoldilocksTransformDirectionV1 as Direction,
    GoldilocksTransformErrorV1 as TransformError, goldilocks_transform_completion_uncertain_v1,
    transform_goldilocks_columns_v1,
};

#[cfg(test)]
use crate::privacy_engines::transparent_stark::masked_trace_coefficients_with_mask_v1;

/// The only long-lived per-column randomness; coefficients clear on drop.
pub(in super::super) struct MainTraceMaskGroupV1 {
    native_log: u8,
    common_log: u8,
    masks: Vec<ReplayableTraceMaskV1>,
}

impl MainTraceMaskGroupV1 {
    fn empty_v1(native_log: u8, common_log: u8, width: usize) -> Result<Self, ZkX509StarkErrorV1> {
        let native_rows = 1_usize
            .checked_shl(u32::from(native_log))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let common_rows = 1_usize
            .checked_shl(u32::from(common_log))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if native_log >= common_log
            || width == 0
            || width > usize::from(u16::MAX)
            || native_rows
                .checked_add(MASK_DEGREE)
                .is_none_or(|highest| highest >= common_rows)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut masks = Vec::new();
        masks
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if masks.capacity() != width {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        Ok(Self {
            native_log,
            common_log,
            masks,
        })
    }

    #[cfg(test)]
    pub(in super::super) fn sample_v1<R: TryRngCore>(
        native_log: u8,
        common_log: u8,
        width: usize,
        rng: &mut R,
        mut source: impl FnMut(usize) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let mut group = Self::empty_v1(native_log, common_log, width)?;
        let native_rows = 1_usize << native_log;
        for column in 0..width {
            // Preserve the original source-before-entropy order and reject bad
            // native columns before sampling their masks. No native column survives.
            #[cfg(test)]
            let source_timer = PhaseTimerV1::start_v1(PhaseV1::SampleSourceColumns);
            let native = source(column)?;
            #[cfg(test)]
            source_timer.complete_v1();
            if native.len() != native_rows
                || native.iter().any(|value| F::canonical(value.0).is_none())
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            #[cfg(test)]
            let mask_timer = PhaseTimerV1::start_v1(PhaseV1::SampleMaskDraws);
            group
                .masks
                .push(sample_trace_mask_v1(MASK_DEGREE, rng).map_err(map_transparent_error_v1)?);
            #[cfg(test)]
            mask_timer.complete_v1();
        }
        Ok(group)
    }

    /// Reuse bounded source batches while the original sampler preserves the
    /// exact per-column validation and entropy draw sequence when source
    /// construction succeeds. A failed batch construction can reject before
    /// the corresponding scalar source would have been reached; no proof is
    /// published in either case. The pending iterator owns at most eight
    /// clearing columns on error and unwind too.
    #[cfg(test)]
    pub(in super::super) fn sample_batched_v1<R: TryRngCore>(
        native_log: u8,
        common_log: u8,
        width: usize,
        rng: &mut R,
        mut source: impl FnMut(
            core::ops::Range<usize>,
        ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let mut pending = Vec::new().into_iter();
        let mut next_column = 0;
        Self::sample_v1(native_log, common_log, width, rng, |column| {
            if column != next_column {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            if pending.len() == 0 {
                let end = column
                    .checked_add(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                    .min(width);
                let batch = source(column..end)?;
                if batch.len() != end - column {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                pending = batch.into_iter();
            }
            next_column += 1;
            pending.next().ok_or(ZkX509StarkErrorV1::InternalInvariant)
        })
    }

    /// Retain only this batch through its original source-before-mask sequence.
    /// A failed transform returns immediately, so later columns consume no entropy.
    /// Successful calls preserve the sampler's exact RNG sequence. Failed calls
    /// deliberately do not promise the old all-masks-before-commit RNG position.
    #[allow(clippy::too_many_arguments)]
    fn sample_and_replay_batch_with_v1<R: TryRngCore>(
        &mut self,
        columns: core::ops::Range<usize>,
        policy: MainBoundedTransformPolicyV1,
        rng: &mut R,
        mut source: impl FnMut(usize) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1>,
        transform: impl FnMut(&mut [Vec<u64>], u64, Direction) -> Result<Backend, TransformError>,
        mut uncertain: impl FnMut() -> bool,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        check_completion_v1(uncertain())?;
        let width = columns
            .end
            .checked_sub(columns.start)
            .filter(|&width| width != 0 && width <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if columns.start != self.masks.len() || columns.end > self.masks.capacity() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let native_rows = 1_usize << self.native_log;
        let mut resident = Vec::new();
        resident
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if resident.capacity() != width {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for column in columns.clone() {
            check_completion_v1(uncertain())?;
            #[cfg(test)]
            let source_timer = PhaseTimerV1::start_v1(PhaseV1::SampleSourceColumns);
            let native = source(column)?;
            #[cfg(test)]
            source_timer.complete_v1();
            if native.len() != native_rows
                || native.iter().any(|value| F::canonical(value.0).is_none())
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            if native.0.capacity() != native_rows {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
            check_completion_v1(uncertain())?;
            #[cfg(test)]
            let mask_timer = PhaseTimerV1::start_v1(PhaseV1::SampleMaskDraws);
            self.masks
                .push(sample_trace_mask_v1(MASK_DEGREE, rng).map_err(map_transparent_error_v1)?);
            #[cfg(test)]
            mask_timer.complete_v1();
            resident.push(native);
        }
        // In the batched source case this drops an exhausted source allocation.
        // It must precede replay: only its replacement iterator header array is
        // charged by for_native_replay_v1, never two simultaneous source arrays.
        drop(source);
        let mut resident = resident.into_iter();
        self.replay_batch_with_v1(
            columns,
            policy,
            |_| resident.next().ok_or(ZkX509StarkErrorV1::InternalInvariant),
            transform,
            uncertain,
        )
    }

    #[cfg(test)]
    fn replay_v1(
        &self,
        column: usize,
        native: &[F],
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let mask = self
            .masks
            .get(column)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        masked_trace_coefficients_with_mask_v1(native, self.native_log, mask.coefficients())
            .map(ZeroizingMainTraceColumnV1)
            .map_err(map_transparent_error_v1)
    }

    /// Construct sources serially, interpolate only the bounded resident batch,
    /// then replace each native allocation with its original masked polynomial.
    fn replay_batch_v1(
        &self,
        columns: core::ops::Range<usize>,
        policy: MainBoundedTransformPolicyV1,
        source: impl FnMut(usize) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1>,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        self.replay_batch_with_v1(
            columns,
            policy,
            source,
            |words, root, direction| {
                transform_goldilocks_columns_v1(
                    words,
                    root,
                    direction,
                    fastpq_prover::ExecutionMode::Auto,
                )
            },
            goldilocks_transform_completion_uncertain_v1,
        )
    }

    fn replay_batch_with_v1(
        &self,
        columns: core::ops::Range<usize>,
        policy: MainBoundedTransformPolicyV1,
        mut source: impl FnMut(usize) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1>,
        mut transform: impl FnMut(&mut [Vec<u64>], u64, Direction) -> Result<Backend, TransformError>,
        mut uncertain: impl FnMut() -> bool,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        check_completion_v1(uncertain())?;
        let width = columns
            .end
            .checked_sub(columns.start)
            .filter(|&width| width != 0 && width <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let masks = self
            .masks
            .get(columns.clone())
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let native_rows = 1_usize
            .checked_shl(u32::from(self.native_log))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let root =
            goldilocks_primitive_root_v1(self.native_log).map_err(map_transparent_error_v1)?;
        if masks.iter().any(|mask| {
            mask.coefficients().len() != MASK_DEGREE + 1
                || mask
                    .coefficients()
                    .iter()
                    .any(|value| F::canonical(value.0).is_none())
        }) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let coefficient_count = native_rows
            .checked_add(MASK_DEGREE + 1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        // One matrix owner guards the original native allocations. This allows
        // the exact same shared word staging as private quotient forward FFTs.
        let mut batch = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1::<Vec<F>>);
        batch
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if batch.capacity() != width {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for column in columns {
            check_completion_v1(uncertain())?;
            let native = PrivateTableV1::new(source(column)?.into_vec_v1(), zeroize_fields_v1);
            if native.len() != native_rows
                || native.iter().any(|value| F::canonical(value.0).is_none())
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            if native.capacity() != native_rows {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
            batch.push(native.into_vec());
        }
        // The clearing word/device batch is gone before mask replacement starts.
        policy.inverse_with_v1(&mut batch, root, &mut transform, &mut uncertain)?;
        for (native, mask) in batch.iter_mut().zip(masks) {
            check_completion_v1(uncertain())?;
            let mut coefficients = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
            coefficients
                .try_reserve_exact(coefficient_count)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            if coefficients.capacity() != coefficient_count {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
            coefficients.extend_from_slice(native);
            coefficients.resize(coefficient_count, F::ZERO);
            // T(X) + r(X)(X^n - 1), including masks longer than native n.
            for (degree, &random) in mask.coefficients().iter().enumerate() {
                coefficients[degree] = coefficients[degree].sub(random);
                coefficients[native_rows + degree] = coefficients[native_rows + degree].add(random);
            }
            // Guard the outgoing allocation before the old native cells drop.
            let previous = PrivateTableV1::new(
                core::mem::replace(native, coefficients.into_vec()),
                zeroize_fields_v1,
            );
            drop(previous);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if output.capacity() != width {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for coefficients in batch.iter_mut() {
            output.push(ZeroizingMainTraceColumnV1(core::mem::take(coefficients)));
        }
        check_completion_v1(uncertain())?;
        Ok(output)
    }
}

/// Retained originals are created only by the first commitment. The test-only
/// oracle keeps original native replay available for independent comparison.
enum RetainedRfcV1 {
    Original(super::main_retained_rfc::MainRetainedRfcV1),
    #[cfg(test)]
    ReplayOracle,
}
/// Six exact groups retain original masks and the RFC masked coefficient owners.
/// Other columns replay their closed immutable sources; every final commitment
/// replay still checks its original root.
pub(in super::super) struct MainTracePolynomialSetV1 {
    proof_instance: ZkX509ProofInstanceV1,
    retained_rfc: RetainedRfcV1,
    groups: [MainTraceMaskGroupV1; FULL_PROFILE_TRACE_GROUPS_V1],
    cut: Option<aggregate::retained_commitment::RetainedMerkleCutV1>,
}

impl MainTracePolynomialSetV1 {
    pub(super) const fn proof_instance_v1(&self) -> ZkX509ProofInstanceV1 {
        self.proof_instance
    }
    #[cfg(test)]
    pub(in super::super) fn from_ordered_v1(
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        groups: Vec<MainTraceMaskGroupV1>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let set = Self {
            proof_instance: TEST_PROOF_INSTANCE_V1,
            retained_rfc: RetainedRfcV1::ReplayOracle,
            groups: groups
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?,
            cut: None,
        };
        set.validate_v1(layout, kind)?;
        Ok(set)
    }

    pub(super) fn validate_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        match &self.retained_rfc {
            RetainedRfcV1::Original(cache) => {
                cache.validate_v1(self.proof_instance, layout, kind)?
            }
            #[cfg(test)]
            RetainedRfcV1::ReplayOracle => (),
        }
        for (masks, group) in self.groups.iter().zip(&layout.trace_groups) {
            let width = match kind {
                MainTraceColumnKindV1::Base => group.base_width,
                MainTraceColumnKindV1::Aux => group.aux_width,
            };
            if masks.masks.len() != width
                || masks.native_log != group.native_trace_log2
                || masks.common_log != layout.common_lde_log2
                || masks
                    .masks
                    .iter()
                    .any(|mask| mask.coefficients().len() != MASK_DEGREE + 1)
            {
                return Err(ZkX509StarkErrorV1::TranscriptMismatch);
            }
        }
        Ok(())
    }

    pub(super) fn joined_plan_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
    ) -> Result<aggregate::joined_trace::JoinedTraceCommitmentPlanV1, ZkX509StarkErrorV1> {
        self.validate_v1(layout, kind)?;
        aggregate::joined_trace::JoinedTraceCommitmentPlanV1::new_v1(
            layout.parameters_v1(),
            &layout.as_shared()?,
            match kind {
                MainTraceColumnKindV1::Base => {
                    aggregate::joined_trace::JoinedTraceColumnKindV1::Base
                }
                MainTraceColumnKindV1::Aux => aggregate::joined_trace::JoinedTraceColumnKindV1::Aux,
            },
        )
        .map_err(map_aggregate_error_v1)
    }

    pub(super) fn retained_rfc_payload_v1(&self) -> usize {
        match &self.retained_rfc {
            RetainedRfcV1::Original(cache) => cache.allocated_payload_v1(),
            #[cfg(test)]
            RetainedRfcV1::ReplayOracle => 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn replay_columns_coefficients_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        group_index: usize,
        columns: core::ops::Range<usize>,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        policy: MainBoundedTransformPolicyV1,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        check_completion_v1(goldilocks_transform_completion_uncertain_v1())?;
        let width = columns
            .end
            .checked_sub(columns.start)
            .filter(|&n| n > 0 && n <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let masks = self
            .groups
            .get(group_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if columns.end > masks.masks.len() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let cache = match &self.retained_rfc {
            RetainedRfcV1::Original(cache) => cache,
            #[cfg(test)]
            RetainedRfcV1::ReplayOracle => {
                return self.replay_uncached_columns_v1(
                    layout,
                    kind,
                    group_index,
                    columns,
                    sources,
                    policy,
                );
            }
        };
        cache.validate_v1(self.proof_instance, layout, kind)?;
        let (first_end, first_cached) = cache.run_v1(group_index, columns.start, columns.end)?;
        if !first_cached && first_end == columns.end {
            return self.replay_uncached_columns_v1(
                layout,
                kind,
                group_index,
                columns,
                sources,
                policy,
            );
        }
        let policy = policy.reserve_additional_v1(
            super::main_retained_rfc::MainRetainedRfcV1::replay_metadata_v1(),
        )?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if output.capacity() != width {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        let mut first = columns.start;
        while first < columns.end {
            let (end, cached) = cache.run_v1(group_index, first, columns.end)?;
            let batch = if cached {
                cache.copy_columns_v1(group_index, first..end)?
            } else {
                self.replay_uncached_columns_v1(
                    layout,
                    kind,
                    group_index,
                    first..end,
                    sources,
                    policy,
                )?
            };
            if batch.len() != end - first || batch.capacity() != end - first {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
            output.extend(batch);
            first = end;
        }
        check_completion_v1(goldilocks_transform_completion_uncertain_v1())?;
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_uncached_columns_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        group_index: usize,
        columns: core::ops::Range<usize>,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        policy: MainBoundedTransformPolicyV1,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        let masks = self
            .groups
            .get(group_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let mut next_column = columns.start;
        let mut native = None;
        let policy = policy.for_native_replay_v1()?;
        masks.replay_batch_v1(columns.clone(), policy, |column| {
            if column != next_column {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            if native.is_none() {
                let batch =
                    sources.native_columns_v1(layout, kind, group_index, columns.clone())?;
                let actual_columns = batch.len();
                let requested_columns = columns.len();
                if actual_columns != requested_columns || batch.capacity() != columns.len() {
                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                }
                native = Some(batch.into_iter());
            }
            next_column += 1;
            native
                .as_mut()
                .and_then(Iterator::next)
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)
        })
    }

    pub(super) fn commit_joined_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        indices: &[usize],
        expected_root: PrivacyOuterDigestV1,
        assembly_payload: usize,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
    ) -> Result<aggregate::StreamingRowCommitmentResultV1, ZkX509StarkErrorV1> {
        let plan = self.joined_plan_v1(layout, kind)?;
        let native_policy =
            MainBoundedTransformPolicyV1::for_assembly_v1(layout, assembly_payload)?;
        let cut = self
            .cut
            .as_ref()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        cut.check_root_v1(layout.common_lde_size(), expected_root)
            .map_err(map_aggregate_error_v1)?;
        let (result, retained) = Self::commit_joined_batches_v1(
            self.proof_instance,
            layout,
            kind,
            indices,
            assembly_payload,
            plan,
            Some(cut),
            |group, columns| {
                self.replay_columns_coefficients_v1(
                    layout,
                    kind,
                    group,
                    columns,
                    sources,
                    native_policy,
                )
            },
        )?;
        if retained.is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(result)
    }

    /// First commitment consumes each native source once, retaining masks, RFC originals and its Merkle cut.
    /// All successful RNG draws, polynomials and commitment framing are unchanged.
    /// Errors are fail-fast: no later source/RNG activity and no partial root escapes.
    pub(super) fn sample_and_commit_joined_v1<R: TryRngCore>(
        proof_instance: ZkX509ProofInstanceV1,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        assembly_payload: usize,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        rng: &mut R,
    ) -> Result<(Self, aggregate::StreamingRowCommitmentResultV1), ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        check_completion_v1(goldilocks_transform_completion_uncertain_v1())?;
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(FULL_PROFILE_TRACE_GROUPS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for (index, group) in layout.trace_groups.iter().enumerate() {
            if MAIN_BASE_COMMITMENT_NATIVE_LOGS_V1.get(index).copied()
                != Some(group.native_trace_log2)
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let width = match kind {
                MainTraceColumnKindV1::Base => group.base_width,
                MainTraceColumnKindV1::Aux => group.aux_width,
            };
            groups.push(MainTraceMaskGroupV1::empty_v1(
                group.native_trace_log2,
                layout.common_lde_log2,
                width,
            )?);
        }
        let mut set = Self {
            proof_instance,
            retained_rfc: RetainedRfcV1::Original(
                super::main_retained_rfc::MainRetainedRfcV1::new_v1(proof_instance, layout, kind)?,
            ),
            groups: groups
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?,
            cut: None,
        };
        let plan = aggregate::joined_trace::JoinedTraceCommitmentPlanV1::new_v1(
            layout.parameters_v1(),
            &layout.as_shared()?,
            match kind {
                MainTraceColumnKindV1::Base => {
                    aggregate::joined_trace::JoinedTraceColumnKindV1::Base
                }
                MainTraceColumnKindV1::Aux => aggregate::joined_trace::JoinedTraceColumnKindV1::Aux,
            },
        )
        .map_err(map_aggregate_error_v1)?;
        let policy = MainBoundedTransformPolicyV1::for_assembly_v1(layout, assembly_payload)?
            .reserve_additional_v1(
                super::main_retained_rfc::MainRetainedRfcV1::replay_metadata_v1(),
            )?
            .for_native_replay_v1()?;
        let (commitment, cut) = Self::commit_joined_batches_v1(
            proof_instance,
            layout,
            kind,
            &[],
            assembly_payload,
            plan,
            None,
            |group, columns| {
                let mut pending = Vec::new().into_iter();
                let mut next_column = columns.start;
                let range = columns.clone();
                let retained_range = columns.clone();
                let mut batch = set
                    .groups
                    .get_mut(group)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                    .sample_and_replay_batch_with_v1(
                        columns,
                        policy,
                        rng,
                        move |column| {
                            if column != next_column {
                                return Err(ZkX509StarkErrorV1::InternalInvariant);
                            }
                            next_column += 1;
                            // Preserve the previous source/entropy interleaving: groups
                            // 0..4 construct one source per draw; log19 constructs eight.
                            if group != FULL_PROFILE_TRACE_GROUPS_V1 - 1 {
                                let (registration, local) =
                                    registered_main_group_column_v1(layout, group, kind, column)?;
                                return sources.native_column_v1(layout, kind, registration, local);
                            }
                            if column == range.start {
                                let batch = sources.native_columns_v1(
                                    layout,
                                    kind,
                                    group,
                                    range.clone(),
                                )?;
                                let actual_columns = batch.len();
                                let requested_columns = range.len();
                                if actual_columns != requested_columns
                                    || batch.capacity() != range.len()
                                {
                                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                                }
                                pending = batch.into_iter();
                            }
                            pending.next().ok_or(ZkX509StarkErrorV1::InternalInvariant)
                        },
                        |words, root, direction| {
                            transform_goldilocks_columns_v1(
                                words,
                                root,
                                direction,
                                fastpq_prover::ExecutionMode::Auto,
                            )
                        },
                        goldilocks_transform_completion_uncertain_v1,
                    )?;
                match &mut set.retained_rfc {
                    RetainedRfcV1::Original(cache) => {
                        cache.retain_batch_v1(group, retained_range, &mut batch)?
                    }
                    #[cfg(test)]
                    RetainedRfcV1::ReplayOracle => {
                        return Err(ZkX509StarkErrorV1::InternalInvariant);
                    }
                }
                Ok(batch)
            },
        )?;
        set.cut = Some(cut.ok_or(ZkX509StarkErrorV1::InternalInvariant)?);
        set.validate_v1(layout, kind)?;
        Ok((set, commitment))
    }

    /// One framing and evaluator path serves initial resident batches and replay.
    fn commit_joined_batches_v1(
        proof_instance: ZkX509ProofInstanceV1,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        indices: &[usize],
        assembly_payload: usize,
        plan: aggregate::joined_trace::JoinedTraceCommitmentPlanV1,
        cut: Option<&aggregate::retained_commitment::RetainedMerkleCutV1>,
        mut batch: impl FnMut(
            usize,
            core::ops::Range<usize>,
        ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1>,
    ) -> Result<
        (
            aggregate::StreamingRowCommitmentResultV1,
            Option<aggregate::retained_commitment::RetainedMerkleCutV1>,
        ),
        ZkX509StarkErrorV1,
    > {
        // The same joined plan creates the leaf framing for retained and replayed
        // columns. At most eight coefficient/evaluation columns coexist.
        let mut source_error = None;
        let mut pending = Vec::new().into_iter();
        let mut pending_next = None;
        let mut evaluator =
            main_transform::MainTraceCosetEvaluatorV1::new_v1(layout, assembly_payload)?;
        let result = plan.commit_retained_replayed_v1(
            main_domains_v1(proof_instance),
            indices,
            cut,
            |group, column| {
                let replay = (|| {
                    if pending.len() == 0 {
                        if column % aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 != 0 {
                            return Err(ZkX509StarkErrorV1::InternalInvariant);
                        }
                        let descriptor = layout
                            .trace_groups
                            .get(group)
                            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
                        let width = match kind {
                            MainTraceColumnKindV1::Base => descriptor.base_width,
                            MainTraceColumnKindV1::Aux => descriptor.aux_width,
                        };
                        let end = width.min(column + aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1);
                        #[cfg(test)]
                        let source_timer = PhaseTimerV1::start_v1(if cut.is_some() {
                            PhaseV1::QueryJoinedSourceBatch
                        } else {
                            PhaseV1::InitialJoinedSourceBatch
                        });
                        pending = batch(group, column..end)?.into_iter();
                        #[cfg(test)]
                        source_timer.complete_v1();
                        pending_next = Some((group, column));
                    }
                    if pending_next != Some((group, column)) {
                        return Err(ZkX509StarkErrorV1::InternalInvariant);
                    }
                    pending_next = Some((group, column + 1));
                    pending.next().ok_or(ZkX509StarkErrorV1::InternalInvariant)
                })();
                replay
                    .map(|coefficients| coefficients.into_vec_v1())
                    .map_err(|error| {
                        source_error = Some(error);
                        AggregateStarkErrorV1::InvalidLayout
                    })
            },
            |columns, native, common, selected| {
                #[cfg(test)]
                let transform_timer = PhaseTimerV1::start_v1(if cut.is_some() {
                    PhaseV1::QueryJoinedTransform
                } else {
                    PhaseV1::InitialJoinedTransform
                });
                let evaluated = match selected {
                    Some(indices) => {
                        evaluator.evaluate_selected_v1(columns, native, common, indices)?
                    }
                    None => evaluator.evaluate_v1(columns, native, common)?,
                };
                #[cfg(test)]
                transform_timer.complete_v1();
                Ok(evaluated)
            },
        );
        tracing::debug!(target: "zk_x509::transform", actual = ?evaluator.receipt_v1(),
            "completed MAIN joined commitment transform dispatches");
        if fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1() {
            return Err(ZkX509StarkErrorV1::AcceleratorCompletionUncertain);
        }
        match (result, source_error) {
            (Ok(result), None) => Ok(result),
            (Err(_), Some(error)) => Err(error),
            (Err(error), None) => Err(map_aggregate_error_v1(error)),
            (Ok(_), Some(_)) => Err(ZkX509StarkErrorV1::InternalInvariant),
        }
    }

    /// Borrow only the original masks owned by this exact validated trace set.
    pub(super) fn original_masks_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        group: usize,
        columns: core::ops::Range<usize>,
    ) -> Result<&[ReplayableTraceMaskV1], ZkX509StarkErrorV1> {
        self.validate_v1(layout, kind)?;
        if columns.is_empty() || columns.len() > aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        self.groups
            .get(group)
            .and_then(|group| group.masks.get(columns))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }

    pub(super) fn retained_group_width_v1(&self, group: usize) -> usize {
        match &self.retained_rfc {
            RetainedRfcV1::Original(cache) => cache.group_width_v1(group),
            #[cfg(test)]
            RetainedRfcV1::ReplayOracle => 0,
        }
    }

    /// Gather only original noncached sources; cached columns remain borrowed
    /// from the immutable first-commit owner. All original source errors occur
    /// before any opening checks. Each public batch still covers every index.
    pub(super) fn deep_batch_v1<'a>(
        &'a self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        group: usize,
        columns: core::ops::Range<usize>,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
    ) -> Result<main_deep_replay::MainDeepReplayBatchV1<'a>, ZkX509StarkErrorV1> {
        self.validate_v1(layout, kind)?;
        let _width = columns
            .end
            .checked_sub(columns.start)
            .filter(|&n| n > 0 && n <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let masks = self
            .groups
            .get(group)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if columns.end > masks.masks.len() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        main_deep_replay::MainDeepReplayBatchV1::gather_v1(
            columns,
            |first, end| match &self.retained_rfc {
                RetainedRfcV1::Original(cache) => cache.run_v1(group, first, end),
                #[cfg(test)]
                RetainedRfcV1::ReplayOracle => Ok((end, false)),
            },
            |range| sources.native_columns_v1(layout, kind, group, range),
            |column| match &self.retained_rfc {
                RetainedRfcV1::Original(cache) => cache.column_v1(group, column),
                #[cfg(test)]
                RetainedRfcV1::ReplayOracle => Err(ZkX509StarkErrorV1::InternalInvariant),
            },
        )
    }

    pub(super) fn deep_group_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        group: usize,
        point: E,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
    ) -> Result<(Vec<E>, Vec<E>), ZkX509StarkErrorV1> {
        self.validate_v1(layout, kind)?;
        let masks = self
            .groups
            .get(group)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let mut current_values = ZeroizingExtensionColumnV1(Vec::new());
        let mut next_values = ZeroizingExtensionColumnV1(Vec::new());
        current_values
            .0
            .try_reserve_exact(masks.masks.len())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        next_values
            .0
            .try_reserve_exact(masks.masks.len())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        let points = main_deep_replay::MainMixedDeepPointsV1::new_v1(
            masks.native_log,
            point,
            self.retained_group_width_v1(group) != 0,
            main_resources::MainProverBufferPlanV1::new_v1(layout)?.replay_batch,
        )?;
        for first in (0..masks.masks.len()).step_by(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1) {
            let end = masks
                .masks
                .len()
                .min(first + aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1);
            let batch = self.deep_batch_v1(layout, kind, group, first..end, sources)?;
            points.check_workspace_v1(&[], 0, &batch.native, batch.native.capacity())?;
            let original_masks = self.original_masks_v1(layout, kind, group, first..end)?;
            if batch.length != original_masks.len() {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            let mut values = main_deep_replay::MainDeepStackValuesV1::<
                { 2 * aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 },
            >::zero_v1();
            values.as_mut_slice_v1()[..2 * batch.length]
                .par_chunks_mut(2)
                .enumerate()
                .zip(original_masks.par_iter())
                .try_for_each(|((offset, values), mask)| {
                    values.copy_from_slice(
                        &points.evaluate_v1(batch.input_v1(offset, mask.coefficients())?)?,
                    );
                    Ok::<(), ZkX509StarkErrorV1>(())
                })?;
            for pair in values.as_slice_v1()[..2 * batch.length].chunks_exact(2) {
                current_values.0.push(pair[0]);
                next_values.0.push(pair[1]);
            }
        }
        Ok((
            core::mem::take(&mut current_values.0),
            core::mem::take(&mut next_values.0),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    fn native(log: u8, column: usize) -> ZeroizingMainTraceColumnV1 {
        ZeroizingMainTraceColumnV1(
            (0..1_usize << log)
                .map(|row| F((row * row + 17 * column + 3) as u64))
                .collect(),
        )
    }

    #[test]
    fn mask_only_replay_matches_retained_coefficients_entropy_and_independent_native_evaluation() {
        for native_log in [3, 8, 11] {
            let common_log = 13;
            let mut replay_rng = StdRng::from_seed([native_log; 32]);
            let mut retained_rng = StdRng::from_seed([native_log; 32]);
            let group = MainTraceMaskGroupV1::sample_v1(
                native_log,
                common_log,
                3,
                &mut replay_rng,
                |column| Ok(native(native_log, column)),
            )
            .unwrap();
            let retained = aggregate::MaskedTracePolynomialSetV1::sample_columns_v1(
                native_log,
                common_log,
                3,
                MASK_DEGREE,
                &mut retained_rng,
                |column| Ok(native(native_log, column).into_vec_v1()),
            )
            .unwrap();
            assert_eq!(replay_rng.next_u64(), retained_rng.next_u64());
            let root = goldilocks_primitive_root_v1(native_log).unwrap();
            for column in 0..3 {
                let values = native(native_log, column);
                let coefficients = group.replay_v1(column, &values).unwrap();
                assert_eq!(
                    &*coefficients,
                    retained.column_coefficients_v1(column).unwrap()
                );
                assert_eq!(&*group.replay_v1(column, &values).unwrap(), &*coefficients);
                // The mask vanishes at each independently selected native point,
                // including when its degree exceeds the smallest native subgroup.
                for row in [0, 1, (1_usize << native_log) - 1] {
                    let point = root.pow(row as u128);
                    let actual = coefficients
                        .iter()
                        .rev()
                        .fold(F::ZERO, |value, &coefficient| {
                            value.mul(point).add(coefficient)
                        });
                    assert_eq!(actual, values[row]);
                }
            }
        }
    }

    #[test]
    fn bounded_parallel_interpolation_preserves_original_masks_order_and_polynomials() {
        for native_log in [3, 11] {
            let mut rng = StdRng::from_seed([native_log + 91; 32]);
            let group = MainTraceMaskGroupV1::sample_v1(native_log, 13, 10, &mut rng, |column| {
                Ok(native(native_log, column))
            })
            .unwrap();
            for width in [1, 3, 8] {
                let range = 2..2 + width;
                let expected = range
                    .clone()
                    .map(|column| {
                        group
                            .replay_v1(column, &native(native_log, column))
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                for workers in [1, 4] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap();
                    let actual = pool.install(|| {
                        let caller = std::thread::current().id();
                        let mut order = Vec::new();
                        let result = group
                            .replay_batch_v1(
                                range.clone(),
                                MainBoundedTransformPolicyV1::cpu_v1(),
                                |column| {
                                    assert_eq!(std::thread::current().id(), caller);
                                    order.push(column);
                                    Ok(native(native_log, column))
                                },
                            )
                            .unwrap();
                        assert_eq!(order, range.clone().collect::<Vec<_>>());
                        result
                    });
                    assert_eq!(actual, expected);
                    let root = goldilocks_primitive_root_v1(native_log).unwrap();
                    for (offset, coefficients) in actual.iter().enumerate() {
                        let values = native(native_log, offset + 2);
                        for row in [0, 1, values.len() / 2, values.len() - 1] {
                            let point = root.pow(row as u128);
                            let value = coefficients
                                .iter()
                                .rev()
                                .fold(F::ZERO, |sum, &coefficient| sum.mul(point).add(coefficient));
                            assert_eq!(value, values[row]);
                        }
                        if native_log == 3 {
                            // Independent quadratic-time inverse DFT and exact
                            // coefficient convolution; no FFT helper is used.
                            let n = values.len();
                            let inverse_n = F(n as u64).inv().unwrap();
                            let inverse_root = root.inv().unwrap();
                            let mut reference = vec![F::ZERO; n + MASK_DEGREE + 1];
                            for (degree, target) in reference[..n].iter_mut().enumerate() {
                                *target = values
                                    .iter()
                                    .enumerate()
                                    .fold(F::ZERO, |sum, (row, &value)| {
                                        sum.add(value.mul(inverse_root.pow((degree * row) as u128)))
                                    })
                                    .mul(inverse_n);
                            }
                            for (degree, &mask) in
                                group.masks[offset + 2].coefficients().iter().enumerate()
                            {
                                reference[degree] = reference[degree].sub(mask);
                                reference[n + degree] = reference[n + degree].add(mask);
                            }
                            assert_eq!(&**coefficients, reference);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bounded_interpolation_clears_partial_sources_on_error_unwind_and_replacement() {
        use super::super::super::super::private_table::inspection;
        let mut rng = StdRng::from_seed([119; 32]);
        let group =
            MainTraceMaskGroupV1::sample_v1(3, 13, 8, &mut rng, |column| Ok(native(3, column)))
                .unwrap();
        for range in [0..0, 0..9, 9..10] {
            let mut calls = 0;
            assert!(
                group
                    .replay_batch_v1(range, MainBoundedTransformPolicyV1::cpu_v1(), |_| {
                        calls += 1;
                        Ok(native(3, 0))
                    })
                    .is_err()
            );
            assert_eq!(calls, 0);
        }
        let assert_cleared = |observations: Vec<inspection::ErasureObservationV1>, cells: usize| {
            assert_eq!(
                observations.iter().map(|value| value.cells).sum::<usize>(),
                cells
            );
            assert!(
                observations
                    .iter()
                    .map(|value| value.nonzero_before)
                    .sum::<usize>()
                    > 0
            );
            assert!(observations.iter().all(|value| value.nonzero_after == 0));
        };
        for unwind in [false, true] {
            let (result, observations) = inspection::observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    group.replay_batch_v1(0..8, MainBoundedTransformPolicyV1::cpu_v1(), |column| {
                        if column == 2 {
                            assert!(!unwind, "injected source unwind");
                            return Err(ZkX509StarkErrorV1::InternalInvariant);
                        }
                        Ok(native(3, column))
                    })
                }))
            });
            assert!(match result {
                Ok(result) => result.is_err(),
                Err(_) => unwind,
            });
            assert_cleared(observations, 16);
        }
        let (result, observations) = inspection::observe_v1(|| {
            group
                .replay_batch_v1(0..8, MainBoundedTransformPolicyV1::cpu_v1(), |column| {
                    Ok(native(3, column))
                })
                .unwrap()
        });
        assert_cleared(observations, 64);
        assert_eq!(result.len(), 8);
        let (result, observations) = inspection::observe_v1(|| {
            group.replay_batch_v1(0..8, MainBoundedTransformPolicyV1::cpu_v1(), |column| {
                if column == 7 {
                    Ok(ZeroizingMainTraceColumnV1(vec![F::ONE; 7]))
                } else {
                    Ok(native(3, column))
                }
            })
        });
        assert!(result.is_err());
        assert_cleared(observations, 63);
    }

    #[test]
    fn mask_replay_rejects_invalid_shapes_and_preserves_entropy_on_source_failure() {
        let mut rng = StdRng::from_seed([71; 32]);
        let mut unchanged = rng.clone();
        let mut calls = 0;
        assert!(
            MainTraceMaskGroupV1::sample_v1(3, 3, 1, &mut rng, |_| {
                calls += 1;
                Ok(native(3, 0))
            })
            .is_err()
        );
        assert_eq!(calls, 0);
        assert_eq!(rng.next_u64(), unchanged.next_u64());
        for invalid in [
            vec![F::ONE; 7],
            vec![F(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1); 8],
        ] {
            let mut rng = StdRng::from_seed([72; 32]);
            let mut unchanged = rng.clone();
            assert!(
                MainTraceMaskGroupV1::sample_v1(3, 11, 1, &mut rng, |_| Ok(
                    ZeroizingMainTraceColumnV1(invalid.clone())
                ))
                .is_err()
            );
            assert_eq!(rng.next_u64(), unchanged.next_u64());
        }
        let mut rng = StdRng::from_seed([73; 32]);
        let group =
            MainTraceMaskGroupV1::sample_v1(3, 11, 1, &mut rng, |_| Ok(native(3, 0))).unwrap();
        assert!(group.replay_v1(1, &native(3, 0)).is_err());
        assert!(group.replay_v1(0, &[F::ONE; 7]).is_err());
        let mut coefficients = group.replay_v1(0, &native(3, 0)).unwrap();
        coefficients.zeroize_private_v1();
        assert!(coefficients.is_empty());
        assert!(core::mem::needs_drop::<MainTraceMaskGroupV1>());
        assert!(core::mem::needs_drop::<ReplayableTraceMaskV1>());
    }
}

/// Immutable closed source roles for deterministic replay of original columns.
pub(super) enum MainTraceReplaySourcesV1<'phase, 'assembly> {
    Base {
        assembly: &'assembly ZkX509MainTraceAssemblyV1,
        sha: &'phase [ZkX509ShaBatchSegmentBaseSourceV1<'assembly>; ZK_X509_SHA_SEGMENT_COUNT_V1],
        p256: &'phase P256MainBaseSourceV1,
        projection: &'phase MainProjectionTraceGroupSourceV1<'assembly>,
        io: &'phase MainIoTraceGroupSourceV1<'assembly>,
    },
    Bound {
        log19: &'phase MainLog19BoundTraceGroupSourceV1<'assembly>,
        projection: &'phase MainProjectionTraceGroupSourceV1<'assembly>,
        io: &'phase MainIoTraceGroupSourceV1<'assembly>,
    },
}

impl MainTraceReplaySourcesV1<'_, '_> {
    /// Extract each DER, SHA and arithmetic/value base or bound auxiliary run once, preserving
    /// public group/registration order and the closed base/bound phase.
    pub(super) fn native_columns_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        group: usize,
        columns: core::ops::Range<usize>,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        let width = columns
            .end
            .checked_sub(columns.start)
            .filter(|&width| width > 0 && width <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches!(self, Self::Base { .. }) && matches!(kind, MainTraceColumnKindV1::Aux) {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        let mut first = columns.start;
        while first < columns.end {
            let (registration, local) =
                registered_main_group_column_v1(layout, group, kind, first)?;
            #[cfg(test)]
            let source_timer = PhaseTimerV1::start_v1(match (registration.segment.adapter, kind) {
                (SegmentAdapterIdV1::ByteMemory, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceByteMemoryBase
                }
                (SegmentAdapterIdV1::ByteMemory, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceByteMemoryAux
                }
                (SegmentAdapterIdV1::StrictDer, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceStrictDerBase
                }
                (SegmentAdapterIdV1::StrictDer, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceStrictDerAux
                }
                (SegmentAdapterIdV1::Rfc5280, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceRfc5280Base
                }
                (SegmentAdapterIdV1::Rfc5280, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceRfc5280Aux
                }
                (SegmentAdapterIdV1::Sha256CallBus, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceSha256CallBusBase
                }
                (SegmentAdapterIdV1::Sha256CallBus, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceSha256CallBusAux
                }
                (SegmentAdapterIdV1::CaAccumulator, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceCaAccumulatorBase
                }
                (SegmentAdapterIdV1::CaAccumulator, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceCaAccumulatorAux
                }
                (SegmentAdapterIdV1::Projection, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceProjectionBase
                }
                (SegmentAdapterIdV1::Projection, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceProjectionAux
                }
                (SegmentAdapterIdV1::P256Arithmetic, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceP256ArithmeticBase
                }
                (SegmentAdapterIdV1::P256Arithmetic, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceP256ArithmeticAux
                }
                (SegmentAdapterIdV1::P256Reduction, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceP256ReductionBase
                }
                (SegmentAdapterIdV1::P256Reduction, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceP256ReductionAux
                }
                (SegmentAdapterIdV1::P256LowS, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceP256LowSBase
                }
                (SegmentAdapterIdV1::P256LowS, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceP256LowSAux
                }
                (SegmentAdapterIdV1::P256Window, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceP256WindowBase
                }
                (SegmentAdapterIdV1::P256Window, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceP256WindowAux
                }
                (SegmentAdapterIdV1::P256ValueBus, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceP256ValueBusBase
                }
                (SegmentAdapterIdV1::P256ValueBus, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceP256ValueBusAux
                }
                (SegmentAdapterIdV1::P256ScalarBitBus, MainTraceColumnKindV1::Base) => {
                    PhaseV1::SourceP256ScalarBitBusBase
                }
                (SegmentAdapterIdV1::P256ScalarBitBus, MainTraceColumnKindV1::Aux) => {
                    PhaseV1::SourceP256ScalarBitBusAux
                }
            });
            if registration.segment.adapter == SegmentAdapterIdV1::StrictDer {
                let end = columns.end.min(match kind {
                    MainTraceColumnKindV1::Base => registration.base_end()?,
                    MainTraceColumnKindV1::Aux => registration.aux_end()?,
                });
                if end <= first {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let count = end - first;
                let rows = registration.segment.trace_size();
                if output.capacity() != width {
                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                }
                let mut batch = Vec::new();
                batch
                    .try_reserve_exact(count)
                    .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
                if batch.capacity() != count {
                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                }
                for _ in 0..count {
                    let column = zeroed_main_trace_column_v1(rows)?;
                    if column.0.capacity() != rows {
                        return Err(ZkX509StarkErrorV1::ProofTooLarge);
                    }
                    batch.push(column);
                }
                {
                    let mut targets: [&mut [F]; aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] =
                        core::array::from_fn(|_| -> &mut [F] { &mut [] });
                    for (target, column) in targets.iter_mut().zip(batch.iter_mut()) {
                        *target = &mut **column;
                    }
                    match self {
                        Self::Base {
                            assembly,
                            sha,
                            p256,
                            ..
                        } => {
                            let source = MainLog19BaseTraceGroupSourceV1::for_main_v1(
                                layout, assembly, sha, p256,
                            )?;
                            if source.registration_index_v1(registration)? != 0 {
                                return Err(ZkX509StarkErrorV1::ProfileMismatch);
                            }
                            fill_zk_x509_der_stark_native_base_columns_v1(
                                source.der,
                                local,
                                &mut targets[..count],
                            )?;
                        }
                        Self::Bound { log19, .. } => {
                            if log19.registration_index_v1(registration)? != 0 {
                                return Err(ZkX509StarkErrorV1::ProfileMismatch);
                            }
                            match kind {
                                MainTraceColumnKindV1::Base => {
                                    fill_zk_x509_der_stark_native_base_columns_v1(
                                        &log19.der.base,
                                        local,
                                        &mut targets[..count],
                                    )?;
                                }
                                MainTraceColumnKindV1::Aux => {
                                    fill_zk_x509_der_stark_native_aux_columns_v1(
                                        &log19.der,
                                        local,
                                        &mut targets[..count],
                                    )?;
                                }
                            }
                        }
                    }
                }
                output.extend(batch);
                first = end;
                #[cfg(test)]
                source_timer.complete_v1();
                continue;
            }
            if registration.segment.adapter == SegmentAdapterIdV1::Rfc5280
                && matches!(kind, MainTraceColumnKindV1::Base)
            {
                let end = columns.end.min(registration.base_end()?);
                if end <= first {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let mut batch = (first..end)
                    .map(|_| zeroed_main_trace_column_v1(registration.segment.trace_size()))
                    .collect::<Result<Vec<_>, _>>()?;
                {
                    let count = batch.len();
                    let mut targets: [&mut [F]; aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] =
                        core::array::from_fn(|_| -> &mut [F] { &mut [] });
                    for (target, column) in targets.iter_mut().zip(batch.iter_mut()) {
                        *target = &mut **column;
                    }
                    match self {
                        Self::Base {
                            assembly,
                            sha,
                            p256,
                            ..
                        } => {
                            let source = MainLog19BaseTraceGroupSourceV1::for_main_v1(
                                layout, assembly, sha, p256,
                            )?;
                            if source.registration_index_v1(registration)? != 1 {
                                return Err(ZkX509StarkErrorV1::ProfileMismatch);
                            }
                            source
                                .rfc
                                .fill_base_columns_v1(local, &mut targets[..count])
                                .map_err(map_main_rfc_source_error_v1)?;
                        }
                        Self::Bound { log19, .. } => {
                            if log19.registration_index_v1(registration)? != 1 {
                                return Err(ZkX509StarkErrorV1::ProfileMismatch);
                            }
                            log19
                                .rfc
                                .fill_base_columns_v1(local, &mut targets[..count])
                                .map_err(map_main_rfc_source_error_v1)?;
                        }
                    }
                }
                output.extend(batch);
                first = end;
                #[cfg(test)]
                source_timer.complete_v1();
                continue;
            }
            if registration.segment.adapter == SegmentAdapterIdV1::Rfc5280
                && matches!(kind, MainTraceColumnKindV1::Aux)
                && let Self::Bound { log19, .. } = self
            {
                let end = columns.end.min(registration.aux_end()?);
                if end <= first {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                if log19.registration_index_v1(registration)? != 1 {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let count = end - first;
                let rows = registration.segment.trace_size();
                if output.capacity() != width {
                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                }
                let mut batch = Vec::new();
                batch
                    .try_reserve_exact(count)
                    .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
                if batch.capacity() != count {
                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                }
                for _ in 0..count {
                    let column = zeroed_main_trace_column_v1(rows)?;
                    if column.0.capacity() != rows {
                        return Err(ZkX509StarkErrorV1::ProofTooLarge);
                    }
                    batch.push(column);
                }
                {
                    let count = batch.len();
                    let mut targets: [&mut [F]; aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] =
                        core::array::from_fn(|_| -> &mut [F] { &mut [] });
                    for (target, column) in targets.iter_mut().zip(batch.iter_mut()) {
                        *target = &mut **column;
                    }
                    log19
                        .rfc
                        .fill_aux_columns_v1(local, &mut targets[..count])
                        .map_err(map_main_rfc_source_error_v1)?;
                }
                output.extend(batch);
                first = end;
                #[cfg(test)]
                source_timer.complete_v1();
                continue;
            }
            let grouped_p256_aux = registration.segment.adapter
                == SegmentAdapterIdV1::P256Arithmetic
                || (registration.segment.adapter == SegmentAdapterIdV1::P256ValueBus
                    && p256_instance_parts_v1(registration.segment.instance)
                        .is_some_and(|(_, local)| local <= 1));
            if grouped_p256_aux && matches!(kind, MainTraceColumnKindV1::Base) {
                let end = columns.end.min(registration.base_end()?);
                if end <= first {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let mut batch = (first..end)
                    .map(|_| zeroed_main_trace_column_v1(registration.segment.trace_size()))
                    .collect::<Result<Vec<_>, _>>()?;
                {
                    let count = batch.len();
                    let mut targets: [&mut [F]; aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] =
                        core::array::from_fn(|_| -> &mut [F] { &mut [] });
                    for (target, column) in targets.iter_mut().zip(batch.iter_mut()) {
                        *target = &mut **column;
                    }
                    match self {
                        Self::Base {
                            assembly,
                            sha,
                            p256,
                            ..
                        } => {
                            let source = MainLog19BaseTraceGroupSourceV1::for_main_v1(
                                layout, assembly, sha, p256,
                            )?;
                            let binding = source.p256_binding_v1(registration)?;
                            p256.fill_base_columns_v1(binding.p256, local, &mut targets[..count])?;
                        }
                        Self::Bound { log19, .. } => {
                            let binding = log19.p256_binding_v1(registration)?;
                            log19.p256.fill_base_columns_v1(
                                binding.p256,
                                local,
                                &mut targets[..count],
                            )?;
                        }
                    }
                }
                output.extend(batch);
                first = end;
                #[cfg(test)]
                source_timer.complete_v1();
                continue;
            }
            if grouped_p256_aux
                && matches!(kind, MainTraceColumnKindV1::Aux)
                && let Self::Bound { log19, .. } = self
            {
                let end = columns.end.min(registration.aux_end()?);
                if end <= first {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let binding = log19.p256_binding_v1(registration)?;
                let mut batch = (first..end)
                    .map(|_| zeroed_main_trace_column_v1(registration.segment.trace_size()))
                    .collect::<Result<Vec<_>, _>>()?;
                {
                    let count = batch.len();
                    let mut targets: [&mut [F]; aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1] =
                        core::array::from_fn(|_| -> &mut [F] { &mut [] });
                    for (target, column) in targets.iter_mut().zip(batch.iter_mut()) {
                        *target = &mut **column;
                    }
                    if registration.segment.adapter == SegmentAdapterIdV1::P256Arithmetic {
                        log19.p256.fill_arithmetic_aux_columns_v1(
                            binding.p256,
                            local,
                            &mut targets[..count],
                        )?;
                    } else {
                        log19.p256.fill_value_aux_columns_v1(
                            binding.p256,
                            local,
                            &mut targets[..count],
                        )?;
                    }
                }
                output.extend(batch);
                first = end;
                #[cfg(test)]
                source_timer.complete_v1();
                continue;
            }
            if registration.segment.adapter != SegmentAdapterIdV1::Sha256CallBus {
                output.push(self.native_column_v1(layout, kind, registration, local)?);
                first += 1;
                #[cfg(test)]
                source_timer.complete_v1();
                continue;
            }
            let end = columns.end.min(match kind {
                MainTraceColumnKindV1::Base => registration.base_end()?,
                MainTraceColumnKindV1::Aux => registration.aux_end()?,
            });
            if end <= first {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let segment = usize::from(registration.segment.instance);
            let mut batch = (first..end)
                .map(|_| zeroed_main_trace_column_v1(registration.segment.trace_size()))
                .collect::<Result<Vec<_>, _>>()?;
            let mut targets = batch
                .iter_mut()
                .map(|column| &mut **column)
                .collect::<Vec<_>>();
            match self {
                Self::Base { sha, .. } => sha
                    .get(segment)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                    .fill_base_columns_v1(segment, local, &mut targets)
                    .map_err(map_main_sha_source_error_v1)?,
                Self::Bound { log19, .. } => {
                    let source = log19
                        .sha_aux
                        .get(segment)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
                    match kind {
                        MainTraceColumnKindV1::Base => source
                            .replay_base_columns_v1(segment, local, &mut targets)
                            .map_err(map_main_sha_source_error_v1)?,
                        MainTraceColumnKindV1::Aux => {
                            source
                                .fill_aux_columns_with_air_terminals_v1(
                                    segment,
                                    local,
                                    &mut targets,
                                )
                                .map_err(map_main_sha_source_error_v1)?;
                        }
                    }
                }
            }
            drop(targets);
            output.extend(batch);
            first = end;
            #[cfg(test)]
            source_timer.complete_v1();
        }
        if output.len() != width {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(output)
    }

    fn native_column_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
        registration: RegisteredSegmentLayoutV1,
        column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let get = |source: &dyn MainTraceGroupSourceV1| match kind {
            MainTraceColumnKindV1::Base => source.native_base_column_v1(registration, column),
            MainTraceColumnKindV1::Aux => source.native_aux_column_v1(registration, column),
        };
        match self {
            Self::Base {
                assembly,
                sha,
                p256,
                projection,
                io,
            } => {
                if matches!(kind, MainTraceColumnKindV1::Aux) {
                    return Err(ZkX509StarkErrorV1::TranscriptMismatch);
                }
                match registration.trace_group {
                    0 => get(&MainP256Log5TraceGroupSourceV1::for_base_v1(layout, p256)?),
                    1 => get(&MainP256ScalarTraceGroupSourceV1::for_base_v1(
                        layout, p256,
                    )?),
                    2 => get(*projection),
                    3 => get(&MainP256Log16TraceGroupSourceV1::for_base_v1(layout, p256)?),
                    4 => get(*io),
                    5 => get(&MainLog19BaseTraceGroupSourceV1::for_main_v1(
                        layout, assembly, sha, p256,
                    )?),
                    _ => Err(ZkX509StarkErrorV1::ProfileMismatch),
                }
            }
            Self::Bound {
                log19,
                projection,
                io,
            } => match registration.trace_group {
                0 => get(&MainP256Log5TraceGroupSourceV1::for_bound_v1(
                    layout,
                    &log19.p256,
                )?),
                1 => get(&MainP256ScalarTraceGroupSourceV1::for_bound_v1(
                    layout,
                    &log19.p256,
                )?),
                2 => get(*projection),
                3 => get(&MainP256Log16TraceGroupSourceV1::for_bound_v1(
                    layout,
                    &log19.p256,
                )?),
                4 => get(*io),
                5 => get(*log19),
                _ => Err(ZkX509StarkErrorV1::ProfileMismatch),
            },
        }
    }
}

#[cfg(test)]
#[path = "main_mask_sampling_tests.rs"]
mod mask_sampling_tests;

#[cfg(test)]
mod native_mask_borrow_tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    #[test]
    #[ignore = "complete registered original-mask ownership and RNG control; run optimized"]
    fn original_mask_borrows_bind_registered_kind_group_range_and_preserve_entropy() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let mut rng = StdRng::from_seed([191; 32]);
        let groups = layout
            .trace_groups
            .iter()
            .map(|group| MainTraceMaskGroupV1 {
                native_log: group.native_trace_log2,
                common_log: layout.common_lde_log2,
                masks: (0..group.base_width)
                    .map(|_| sample_trace_mask_v1(MASK_DEGREE, &mut rng).unwrap())
                    .collect(),
            })
            .collect::<Vec<_>>();
        let set =
            MainTracePolynomialSetV1::from_ordered_v1(&layout, MainTraceColumnKindV1::Base, groups)
                .unwrap();
        let mut unchanged_rng = rng.clone();
        for (index, group) in layout.trace_groups.iter().enumerate() {
            let end = group
                .base_width
                .min(aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1);
            let borrowed = set
                .original_masks_v1(&layout, MainTraceColumnKindV1::Base, index, 0..end)
                .unwrap();
            assert_eq!(borrowed.len(), end);
            for (column, mask) in borrowed.iter().enumerate() {
                assert!(core::ptr::eq(mask, &set.groups[index].masks[column]));
                assert_eq!(
                    mask.coefficients(),
                    set.groups[index].masks[column].coefficients()
                );
                assert_eq!(mask.coefficients().len(), MASK_DEGREE + 1);
            }
            for invalid in [
                0..0,
                0..aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 + 1,
                group.base_width..group.base_width + 1,
            ] {
                assert!(
                    set.original_masks_v1(&layout, MainTraceColumnKindV1::Base, index, invalid)
                        .is_err()
                );
            }
        }
        assert!(
            set.original_masks_v1(
                &layout,
                MainTraceColumnKindV1::Base,
                FULL_PROFILE_TRACE_GROUPS_V1,
                0..1
            )
            .is_err()
        );
        assert!(
            set.original_masks_v1(&layout, MainTraceColumnKindV1::Aux, 0, 0..1)
                .is_err()
        );
        let mut malformed_layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        malformed_layout.trace_groups[0].native_trace_log2 += 1;
        assert!(
            set.original_masks_v1(&malformed_layout, MainTraceColumnKindV1::Base, 0, 0..1)
                .is_err()
        );
        assert_eq!(rng.next_u64(), unchanged_rng.next_u64());
    }
}

#[cfg(test)]
#[path = "main_trace_replay_inverse_tests.rs"]
mod inverse_tests;

#[cfg(test)]
#[path = "main_sample_commit_tests.rs"]
mod sample_commit_tests;
