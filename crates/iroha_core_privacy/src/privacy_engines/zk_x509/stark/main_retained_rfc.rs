//! Single-owner RFC masked coefficients retained from the original first commitment.

use super::super::super::private_table::{ClearingVecV1, PrivateTableV1, zeroize_fields_v1};
use super::*;

/// Exact public registration slice; no witness-derived cache size or selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlanV1 {
    group: usize,
    start: usize,
    end: usize,
    coefficients: usize,
    base: bool,
}
impl PlanV1 {
    fn new_v1(
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::Rfc5280, 0)?;
        let base = matches!(kind, MainTraceColumnKindV1::Base);
        let (start, end) = if base {
            (registration.base_start, registration.base_end()?)
        } else {
            (registration.aux_start, registration.aux_end()?)
        };
        let coefficients = registration
            .segment
            .trace_size()
            .checked_add(MASK_DEGREE + 1)
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        Ok(Self {
            group: registration.trace_group,
            start,
            end,
            coefficients,
            base,
        })
    }
    fn width_v1(self) -> usize {
        self.end - self.start
    }
    fn payload_v1(self) -> Result<usize, ZkX509StarkErrorV1> {
        self.coefficients
            .checked_mul(core::mem::size_of::<F>())
            .and_then(|n| n.checked_add(core::mem::size_of::<PrivateTableV1<F>>()))
            .and_then(|n| n.checked_mul(self.width_v1()))
            .and_then(|n| n.checked_add(core::mem::size_of::<MainRetainedRfcV1>()))
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)
    }
    fn contains_v1(self, group: usize, column: usize) -> bool {
        group == self.group && (self.start..self.end).contains(&column)
    }
}

/// The original coefficient arrays move here; only bounded working copies leave.
/// All production insertion is private to the original first-commit constructor.
pub(super) struct MainRetainedRfcV1 {
    proof_instance: ZkX509ProofInstanceV1,
    plan: PlanV1,
    columns: ClearingVecV1<PrivateTableV1<F>>,
}
impl MainRetainedRfcV1 {
    /// Additional split receivers and copy/iterator metadata, beyond the original
    /// five-array native replay ledger. Values keep their existing bounded batch charge.
    pub(super) const fn replay_metadata_v1() -> usize {
        2 * aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            * core::mem::size_of::<ZeroizingMainTraceColumnV1>()
            + 2 * core::mem::size_of::<Vec<ZeroizingMainTraceColumnV1>>()
            + 2 * core::mem::size_of::<std::vec::IntoIter<ZeroizingMainTraceColumnV1>>()
            + 2 * core::mem::size_of::<PrivateTableV1<F>>()
            + 2 * core::mem::size_of::<ZeroizingMainTraceColumnV1>()
    }
    /// Small original-mask test geometry has no production constructor path.
    #[cfg(test)]
    pub(super) fn for_original_mask_test_v1(group: usize, width: usize, native_log: u8) -> Self {
        Self::from_plan_v1(
            TEST_PROOF_INSTANCE_V1,
            PlanV1 {
                group,
                start: 0,
                end: width,
                coefficients: (1usize << native_log) + MASK_DEGREE + 1,
                base: true,
            },
        )
        .unwrap()
    }
    pub(super) fn forecast_all_v1(
        layout: &AggregateProofLayoutV1,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        PlanV1::new_v1(layout, MainTraceColumnKindV1::Base)?
            .payload_v1()?
            .checked_add(PlanV1::new_v1(layout, MainTraceColumnKindV1::Aux)?.payload_v1()?)
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)
    }
    pub(super) fn new_v1(
        proof_instance: ZkX509ProofInstanceV1,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        Self::from_plan_v1(proof_instance, PlanV1::new_v1(layout, kind)?)
    }
    fn from_plan_v1(
        proof_instance: ZkX509ProofInstanceV1,
        plan: PlanV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        plan.payload_v1()?;
        let columns = ClearingVecV1::try_with_capacity_v1(plan.width_v1())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if columns.capacity_v1() != plan.width_v1() {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        Ok(Self {
            proof_instance,
            plan,
            columns,
        })
    }
    pub(super) fn validate_v1(
        &self,
        proof_instance: ZkX509ProofInstanceV1,
        layout: &AggregateProofLayoutV1,
        kind: MainTraceColumnKindV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if self.proof_instance != proof_instance || self.plan != PlanV1::new_v1(layout, kind)? {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        self.validate_complete_v1()
    }
    fn validate_complete_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        if self.columns.len() != self.plan.width_v1()
            || self.columns.capacity_v1() != self.plan.width_v1()
            || self.columns.iter().any(|column| {
                column.len() != self.plan.coefficients
                    || column.capacity() != self.plan.coefficients
            })
            || self.allocated_payload_v1() != self.plan.payload_v1()?
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    pub(super) fn allocated_payload_v1(&self) -> usize {
        self.columns.iter().fold(
            core::mem::size_of::<Self>().saturating_add(self.columns.allocated_bytes_v1()),
            |n, column| {
                n.saturating_add(column.capacity().saturating_mul(core::mem::size_of::<F>()))
            },
        )
    }
    /// Preserve the exact complete batch returned after original source/entropy work.
    pub(super) fn retain_batch_v1(
        &mut self,
        group: usize,
        range: core::ops::Range<usize>,
        batch: &mut [ZeroizingMainTraceColumnV1],
    ) -> Result<(), ZkX509StarkErrorV1> {
        if range.end.checked_sub(range.start) != Some(batch.len())
            || batch.is_empty()
            || batch.len() > aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        for (index, column) in range.zip(batch) {
            if !self.plan.contains_v1(group, index) {
                continue;
            }
            if index != self.plan.start + self.columns.len()
                || column.len() != self.plan.coefficients
                || column.0.capacity() != self.plan.coefficients
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            // Allocate under a clearing owner before copying private coefficients.
            // On failure the caller still owns the untouched original column.
            let working = copy_v1(column)?;
            let original = core::mem::replace(column, working);
            let original = PrivateTableV1::new(original.into_vec_v1(), zeroize_fields_v1);
            self.columns.try_push_v1(original).map_err(|rejected| {
                drop(rejected);
                ZkX509StarkErrorV1::ProofTooLarge
            })?;
        }
        Ok(())
    }
    /// Public maximal run beginning at `first`, bounded by the requested original batch.
    pub(super) fn run_v1(
        &self,
        group: usize,
        first: usize,
        end: usize,
    ) -> Result<(usize, bool), ZkX509StarkErrorV1> {
        if first >= end || end - first > aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        if group != self.plan.group || first >= self.plan.end {
            return Ok((end, false));
        }
        if first < self.plan.start {
            return Ok((end.min(self.plan.start), false));
        }
        Ok((end.min(self.plan.end), true))
    }
    /// Borrow one immutable original; public range classification has already
    /// selected the source. No coefficient copy or fresh source work occurs.
    pub(super) fn column_v1(
        &self,
        group: usize,
        column: usize,
    ) -> Result<&[F], ZkX509StarkErrorV1> {
        self.validate_complete_v1()?;
        if !self.plan.contains_v1(group, column) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(&self.columns[column - self.plan.start])
    }
    pub(super) fn group_width_v1(&self, group: usize) -> usize {
        if group == self.plan.group {
            self.plan.width_v1()
        } else {
            0
        }
    }
    pub(super) fn copy_columns_v1(
        &self,
        group: usize,
        range: core::ops::Range<usize>,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1> {
        self.validate_complete_v1()?;
        let width = range
            .end
            .checked_sub(range.start)
            .filter(|&n| n > 0 && n <= aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if !self.plan.contains_v1(group, range.start) || range.end > self.plan.end {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(width)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if output.capacity() != width {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for index in range {
            output.push(copy_v1(&self.columns[index - self.plan.start])?);
        }
        Ok(output)
    }
}
fn copy_v1(column: &[F]) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
    let mut copy = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
    copy.try_reserve_exact(column.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    if copy.capacity() != column.len() {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    copy.extend_from_slice(column);
    Ok(ZeroizingMainTraceColumnV1(copy.into_vec()))
}

#[cfg(test)]
mod tests {
    use super::super::main_bounded_transform::MainBoundedTransformPolicyV1;
    use super::*;
    fn fixture() -> MainRetainedRfcV1 {
        MainRetainedRfcV1::from_plan_v1(
            TEST_PROOF_INSTANCE_V1,
            PlanV1 {
                group: 5,
                start: 4,
                end: 7,
                coefficients: 32,
                base: true,
            },
        )
        .unwrap()
    }
    fn column(value: u64) -> ZeroizingMainTraceColumnV1 {
        ZeroizingMainTraceColumnV1(vec![F(value); 32])
    }
    #[test]
    fn original_transfer_and_copies_retain_all_coefficients_without_aliasing() {
        let mut retained = fixture();
        let mut batch = vec![column(3), column(5), column(7), column(11)];
        let pointers: Vec<_> = batch.iter().map(|x| x.as_ptr()).collect();
        retained.retain_batch_v1(5, 3..7, &mut batch).unwrap();
        retained.validate_complete_v1().unwrap();
        assert_eq!(batch[0].as_ptr(), pointers[0]);
        for i in 0..3 {
            assert_eq!(retained.columns[i].as_ptr(), pointers[i + 1]);
            assert_ne!(batch[i + 1].as_ptr(), pointers[i + 1]);
            assert_eq!(retained.columns[i].as_slice(), &*batch[i + 1]);
        }
        // Exercise the same pre-copy reservation primitive as the production
        // split receiver, at its exact limit and one byte below it.
        let rows = 256;
        let admitted = rows * core::mem::size_of::<u64>()
            + core::mem::size_of::<Vec<u64>>()
            + core::mem::size_of::<PrivateTableV1<Vec<u64>>>()
            + fastpq_prover::goldilocks_transform::metal_goldilocks_transform_extra_payload_v1(
                rows, 1,
            )
            .unwrap();
        let metadata = MainRetainedRfcV1::replay_metadata_v1();
        assert!(admitted >= metadata);
        for shortage in [0, 1] {
            let policy = MainBoundedTransformPolicyV1::for_test_v1(rows, 1)
                .reserve_additional_v1(admitted - metadata + shortage)
                .unwrap();
            let mut copied_after_reservation = false;
            let outcome = policy
                .reserve_additional_v1(metadata)
                .and_then(|remaining| {
                    assert!(remaining.reserve_additional_v1(1).is_err());
                    copied_after_reservation = true;
                    retained.copy_columns_v1(5, 4..7)
                });
            assert_eq!(outcome.is_ok(), shortage == 0);
            assert_eq!(copied_after_reservation, shortage == 0);
            if let Ok(columns) = outcome {
                assert_eq!(columns, batch[1..]);
            }
        }
        let copied = retained.copy_columns_v1(5, 4..7).unwrap();
        assert_eq!(copied, batch[1..]);
        batch[1][31] = F(99);
        assert_eq!(retained.columns[0][31], F(5));
        assert_eq!(copied[0][31], F(5));
        assert_eq!(
            retained.allocated_payload_v1(),
            retained.plan.payload_v1().unwrap()
        );
    }
    #[test]
    fn exact_public_registration_and_all_crossing_batches_preserve_column_order() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        for (kind, start, end) in [
            (MainTraceColumnKindV1::Base, 76, 361),
            (MainTraceColumnKindV1::Aux, 196, 476),
        ] {
            let cache = MainRetainedRfcV1::new_v1(TEST_PROOF_INSTANCE_V1, &layout, kind).unwrap();
            assert_eq!(
                (
                    cache.plan.group,
                    cache.plan.start,
                    cache.plan.end,
                    cache.plan.coefficients
                ),
                (5, start, end, 526_104)
            );
            let group = layout.trace_groups[5];
            let width = if matches!(kind, MainTraceColumnKindV1::Base) {
                group.base_width
            } else {
                group.aux_width
            };
            let mut seen = Vec::new();
            let mut cached = Vec::new();
            for first in (0..width).step_by(8) {
                let end_batch = (first + 8).min(width);
                let mut cursor = first;
                while cursor < end_batch {
                    let (next, hit) = cache.run_v1(5, cursor, end_batch).unwrap();
                    assert!(next > cursor);
                    for column in cursor..next {
                        seen.push(column);
                        if hit {
                            cached.push(column);
                        }
                    }
                    cursor = next;
                }
            }
            assert_eq!(seen, (0..width).collect::<Vec<_>>());
            assert_eq!(cached, (start..end).collect::<Vec<_>>());
            assert_eq!(
                cache.validate_v1(TEST_PROOF_INSTANCE_V1, &layout, kind),
                Err(ZkX509StarkErrorV1::ProfileMismatch)
            );
            let wrong_kind = if matches!(kind, MainTraceColumnKindV1::Base) {
                MainTraceColumnKindV1::Aux
            } else {
                MainTraceColumnKindV1::Base
            };
            assert_eq!(
                cache.validate_v1(TEST_PROOF_INSTANCE_V1, &layout, wrong_kind),
                Err(ZkX509StarkErrorV1::TranscriptMismatch)
            );
            assert_eq!(
                cache.validate_v1(ZkX509ProofInstanceV1::new_v1([0x6b; 32]), &layout, kind),
                Err(ZkX509StarkErrorV1::TranscriptMismatch)
            );
        }
    }
    #[test]
    fn partial_missing_reordered_oversized_and_duplicate_columns_are_refused() {
        let mut cache = fixture();
        assert!(cache.copy_columns_v1(5, 4..5).is_err());
        assert!(cache.retain_batch_v1(5, 5..6, &mut [column(1)]).is_err());
        let mut too_short = ZeroizingMainTraceColumnV1(vec![F::ONE; 31]);
        assert!(
            cache
                .retain_batch_v1(5, 4..5, core::slice::from_mut(&mut too_short))
                .is_err()
        );
        cache.retain_batch_v1(5, 4..5, &mut [column(2)]).unwrap();
        assert!(cache.validate_complete_v1().is_err());
        assert!(cache.retain_batch_v1(5, 4..5, &mut [column(2)]).is_err());
        cache
            .retain_batch_v1(5, 5..7, &mut [column(3), column(4)])
            .unwrap();
        cache.validate_complete_v1().unwrap();
        for range in [3..5, 6..8, 4..4, 4..13] {
            assert!(cache.copy_columns_v1(5, range).is_err());
        }
        assert!(cache.copy_columns_v1(4, 4..5).is_err());
        let mut overflow = cache.plan;
        overflow.coefficients = usize::MAX;
        assert!(overflow.payload_v1().is_err());
    }
    #[test]
    fn retained_and_working_allocations_clear_on_success_error_and_unwind() {
        use super::super::super::super::private_table::{allocation_inspection, inspection};
        for mode in 0..3 {
            let ((result, fields), allocations) = allocation_inspection::observe_v1(|| {
                inspection::observe_v1(|| {
                    std::panic::catch_unwind(|| {
                        let mut retained = fixture();
                        let mut batch = vec![column(3), column(5), column(7)];
                        if mode == 0 {
                            retained.retain_batch_v1(5, 4..7, &mut batch).unwrap();
                            retained.validate_complete_v1().unwrap();
                            Ok(())
                        } else {
                            retained.retain_batch_v1(5, 4..5, &mut batch[..1]).unwrap();
                            if mode == 2 {
                                panic!("injected retained owner unwind");
                            }
                            Err(())
                        }
                    })
                })
            });
            match mode {
                0 => assert!(result.unwrap().is_ok()),
                1 => assert!(result.unwrap().is_err()),
                _ => assert!(result.is_err()),
            }
            let expected = (if mode == 0 { 6 } else { 4 }) * 32;
            assert_eq!(
                fields.iter().map(|x| x.nonzero_before).sum::<usize>(),
                expected
            );
            assert!(fields.iter().all(|x| x.nonzero_after == 0));
            assert_eq!(allocations.len(), 1);
            assert_eq!(
                allocations[0].bytes,
                3 * core::mem::size_of::<PrivateTableV1<F>>()
            );
            assert_eq!(allocations[0].nonzero_after, 0);
        }
    }
}
