//! Bounded evaluation of the unchanged MAIN coset polynomials.
//!
//! Eight evaluation columns remain resident. The measured exact-root Metal
//! kernel is selected only when its complete staging allowance fits beyond all
//! admitted source, replay scratch and runtime reserves. CPU fallback preserves
//! the same polynomial and does not relax uncertain-completion admission.

use super::super::super::private_table::{PrivateTableV1, zeroize_fields_v1, zeroize_words_v1};
#[cfg(test)]
use super::super::super::prover_observation;
use super::*;
use crate::privacy_engines::transparent_stark::masked_trace_coefficients_on_coset_v1;
use fastpq_prover::goldilocks_transform::{
    GoldilocksTransformBackendV1 as Backend, GoldilocksTransformDirectionV1 as Direction,
    transform_goldilocks_columns_v1,
};

type Column = aggregate::ZeroizingFieldColumnV1;

#[path = "main_selected_coset.rs"]
mod selected_coset;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct MainTransformReceiptV1 {
    cpu_columns: usize,
    metal_columns: usize,
}

pub(super) struct MainTraceCosetEvaluatorV1 {
    evaluation_rows: usize,
    device_columns: usize,
    receipt: MainTransformReceiptV1,
}

impl MainTraceCosetEvaluatorV1 {
    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        assembly_payload: usize,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let admitted = main_resources::MainProverBufferPlanV1::new_v1(layout)?
            .check_before_sources_v1(assembly_payload)?;
        let ceiling =
            usize::try_from(super::super::super::profile::ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let available = ceiling
            .checked_sub(admitted)
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        // Native19/common22 full-output parity and bounded dispatch timing
        // qualify this kernel selection, not the complete MAIN time budget.
        // CUDA has no matching staging contract and remains on the CPU path.
        let device_columns = select_device_columns_v1(
            layout.common_lde_size(),
            available,
            fastpq_prover::goldilocks_transform::available_goldilocks_transform_backend_v1(),
        );
        #[cfg(test)]
        prover_observation::policy_v1(device_columns);
        Ok(Self {
            evaluation_rows: layout.common_lde_size(),
            device_columns,
            receipt: MainTransformReceiptV1::default(),
        })
    }

    pub(super) fn receipt_v1(&self) -> &MainTransformReceiptV1 {
        &self.receipt
    }

    pub(super) fn evaluate_v1(
        &mut self,
        columns: &[Column],
        native_log: u8,
        common_log: u8,
    ) -> Result<Vec<Column>, AggregateStarkErrorV1> {
        self.evaluate_rows_v1(columns, native_log, common_log, None)
    }

    /// Return only the exact canonical selected rows from the original coset.
    pub(super) fn evaluate_selected_v1(
        &mut self,
        columns: &[Column],
        native_log: u8,
        common_log: u8,
        selected: &[usize],
    ) -> Result<Vec<Column>, AggregateStarkErrorV1> {
        self.evaluate_rows_v1(columns, native_log, common_log, Some(selected))
    }

    fn evaluate_rows_v1(
        &mut self,
        columns: &[Column],
        native_log: u8,
        common_log: u8,
        selected: Option<&[usize]>,
    ) -> Result<Vec<Column>, AggregateStarkErrorV1> {
        // An already admitted CPU phase must also stop if another device call
        // has since left a live private allocation with uncertain completion.
        if fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1() {
            #[cfg(test)]
            prover_observation::failed_transform_v1();
            return Err(AggregateStarkErrorV1::InternalInvariant);
        }
        let result = self.evaluate_selected_with_v1(
            columns,
            native_log,
            common_log,
            selected,
            |values, root| {
                transform_goldilocks_columns_v1(
                    values,
                    root,
                    Direction::Forward,
                    fastpq_prover::ExecutionMode::Auto,
                )
                .map_err(|_| AggregateStarkErrorV1::InvalidLayout)
            },
        );
        #[cfg(test)]
        if result.is_err() {
            prover_observation::failed_transform_v1();
        }
        result
    }

    #[cfg(test)]
    fn evaluate_with_v1(
        &mut self,
        columns: &[Column],
        native_log: u8,
        common_log: u8,
        transform: impl FnMut(&mut [Vec<u64>], u64) -> Result<Backend, AggregateStarkErrorV1>,
    ) -> Result<Vec<Column>, AggregateStarkErrorV1> {
        self.evaluate_selected_with_v1(columns, native_log, common_log, None, transform)
    }

    fn evaluate_selected_with_v1(
        &mut self,
        columns: &[Column],
        native_log: u8,
        common_log: u8,
        selected: Option<&[usize]>,
        mut transform: impl FnMut(&mut [Vec<u64>], u64) -> Result<Backend, AggregateStarkErrorV1>,
    ) -> Result<Vec<Column>, AggregateStarkErrorV1> {
        let rows = 1_usize
            .checked_shl(u32::from(common_log))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let native_rows = 1_usize
            .checked_shl(u32::from(native_log))
            .ok_or(AggregateStarkErrorV1::InvalidLayout)?;
        let root = goldilocks_primitive_root_v1(common_log)
            .map_err(aggregate::map_transparent_error_v1)?;
        let shift = F(GOLDILOCKS_GENERATOR_V1);
        if rows != self.evaluation_rows
            || columns.is_empty()
            || columns.len() > aggregate::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || rows <= native_rows
            || shift.pow(rows as u128) == F::ONE
            || shift.pow(native_rows as u128) == F::ONE
            || columns
                .iter()
                .any(|column| column.is_empty() || column.len() > rows)
        {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        if selected.is_some_and(|indices| {
            indices.is_empty()
                || indices.last().is_none_or(|&row| row >= rows)
                || indices.windows(2).any(|pair| pair[0] >= pair[1])
        }) {
            return Err(AggregateStarkErrorV1::InvalidLayout);
        }
        if columns
            .iter()
            .flat_map(|column| column.iter())
            .any(|value| F::canonical(value.0).is_none())
        {
            return Err(AggregateStarkErrorV1::NonCanonicalField);
        }
        if self.device_columns == 0 {
            let result = columns
                .par_iter()
                .map(|column| match selected {
                    Some(indices) => {
                        selected_coset::evaluate_v1(column, native_log, common_log, indices)
                    }
                    None => masked_trace_coefficients_on_coset_v1(column, native_log, common_log)
                        .map(Column::from_vec_v1)
                        .map_err(aggregate::map_transparent_error_v1),
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.receipt.cpu_columns += columns.len();
            #[cfg(test)]
            prover_observation::completed_transform_v1(false, columns.len());
            return Ok(result);
        }
        // Guard both allocation levels before any private write. Each FFT
        // operates on at most the admitted batch, although eight outputs live.
        let mut words = PrivateTableV1::new(Vec::new(), erase_word_rows_v1);
        words
            .try_reserve_exact(columns.len())
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for coefficients in columns {
            let mut column = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
            column
                .try_reserve_exact(rows)
                .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
            column.resize(rows, 0);
            let mut power = F::ONE;
            for (output, coefficient) in column.iter_mut().zip(coefficients.iter()) {
                *output = coefficient.mul(power).0;
                power = power.mul(shift);
            }
            words.push(column.into_vec());
        }
        for batch in words.chunks_mut(self.device_columns) {
            match transform(batch, root.0)? {
                Backend::Cpu => {
                    self.receipt.cpu_columns += batch.len();
                    #[cfg(test)]
                    prover_observation::completed_transform_v1(false, batch.len());
                }
                Backend::Metal => {
                    self.receipt.metal_columns += batch.len();
                    #[cfg(test)]
                    prover_observation::completed_transform_v1(true, batch.len());
                }
                // Detection is process-immutable, and this evaluator is only
                // admitted for Metal. Never reinterpret another backend receipt.
                Backend::Cuda => return Err(AggregateStarkErrorV1::InvalidLayout),
            }
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(words.len())
            .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
        for words in words.iter_mut() {
            let mut column = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
            let output_rows = selected.map_or(rows, <[usize]>::len);
            column
                .try_reserve_exact(output_rows)
                .map_err(|_| AggregateStarkErrorV1::AllocationFailure)?;
            if column.capacity() != output_rows {
                return Err(AggregateStarkErrorV1::AllocationFailure);
            }
            // Preserve full device-output canonical checking, including
            // unselected rows; gather only after original completion succeeds.
            if words.iter().any(|&word| F::canonical(word).is_none()) {
                return Err(AggregateStarkErrorV1::NonCanonicalField);
            }
            match selected {
                Some(indices) => column.extend(indices.iter().map(|&row| F(words[row]))),
                None => column.extend(words.iter().copied().map(F)),
            }
            output.push(Column::from_vec_v1(column.into_vec()));
            // Only one field conversion column overlaps the word outputs.
            zeroize_words_v1(words);
            *words = Vec::new();
        }
        Ok(output)
    }
}

fn erase_word_rows_v1(rows: &mut [Vec<u64>]) {
    for row in rows {
        zeroize_words_v1(row);
    }
}

fn select_device_columns_v1(rows: usize, available: usize, backend: Option<Backend>) -> usize {
    if backend == Some(Backend::Metal) {
        select_metal_columns_v1(rows, available)
    } else {
        0
    }
}

fn select_metal_columns_v1(rows: usize, available: usize) -> usize {
    use fastpq_prover::goldilocks_transform::metal_goldilocks_transform_extra_payload_v1;
    // Conversion overlaps only one completed word column. Its allowance is
    // bounded by every admitted Metal dispatch allowance (which includes cache).
    [4, 2, 1]
        .into_iter()
        .find(|&columns| {
            metal_goldilocks_transform_extra_payload_v1(rows, columns)
                .is_ok_and(|required| required <= available)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::super::super::super::private_table::inspection;
    use super::*;
    use fastpq_prover::goldilocks_transform::metal_goldilocks_transform_extra_payload_v1;

    #[test]
    fn production_transform_selects_only_admitted_metal_backend() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let evaluator = MainTraceCosetEvaluatorV1::new_v1(&layout, 288_345_698).unwrap();
        assert_eq!(
            evaluator.device_columns,
            select_device_columns_v1(
                layout.common_lde_size(),
                596_974_144
                    - core::mem::size_of::<E>()
                    - 288_345_698
                    - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1,
                fastpq_prover::goldilocks_transform::available_goldilocks_transform_backend_v1(),
            )
        );
        for backend in [None, Some(Backend::Cpu), Some(Backend::Cuda)] {
            assert_eq!(
                select_device_columns_v1(layout.common_lde_size(), usize::MAX, backend),
                0
            );
        }
        assert_eq!(
            select_device_columns_v1(layout.common_lde_size(), 0, Some(Backend::Metal)),
            0
        );
        assert_eq!(
            select_device_columns_v1(
                layout.common_lde_size(),
                596_974_144
                    - core::mem::size_of::<E>()
                    - 288_345_698
                    - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1,
                Some(Backend::Metal),
            ),
            2
        );
        assert_eq!(evaluator.receipt_v1(), &MainTransformReceiptV1::default());
    }

    fn columns_v1(count: usize) -> Vec<Column> {
        (0..count)
            .map(|column| {
                Column::from_vec_v1(
                    (0..21)
                        .map(|degree| F((column * 19 + degree * 7 + 1) as u64))
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn device_allowance_preserves_cpu_admission_and_all_reserves() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let plan = main_resources::MainProverBufferPlanV1::new_v1(&layout).unwrap();
        let cap = super::super::super::super::profile::ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1 as usize;
        let baseline = plan.check_before_sources_v1(0).unwrap();
        let assembly_limit = cap - baseline;
        // The 12 GiB ceiling still reserves 6 GiB of native sources, 1 GiB
        // of source scratch and 1 GiB of runtime beyond the live transforms.
        assert_eq!(
            assembly_limit,
            (12_usize << 30)
                - (3_697_993_152 + core::mem::size_of::<E>())
                - (8 << 30)
                - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1
        );
        assert_eq!(
            assembly_limit,
            596_974_144
                - core::mem::size_of::<E>()
                - main_bounded_transform::SHARED_POWERS_ALLOWANCE_V1
        );
        assert_eq!(
            select_metal_columns_v1(layout.common_lde_size(), assembly_limit - 288_345_698),
            2
        );
        for count in [1, 2, 4] {
            let required =
                metal_goldilocks_transform_extra_payload_v1(layout.common_lde_size(), count)
                    .unwrap();
            assert_eq!(
                select_metal_columns_v1(layout.common_lde_size(), required),
                count
            );
            assert!(select_metal_columns_v1(layout.common_lde_size(), required - 1) < count);
        }
        assert_eq!(select_metal_columns_v1(layout.common_lde_size(), 0), 0);
        assert!(plan.check_before_sources_v1(assembly_limit).is_ok());
        assert!(plan.check_before_sources_v1(assembly_limit + 1).is_err());
    }

    #[test]
    fn bounded_packing_subdispatch_and_conversion_match_independent_coset_values() {
        for count in [1, 3, 8] {
            for device_columns in [1, 2, 4] {
                let columns = columns_v1(count);
                let mut evaluator = MainTraceCosetEvaluatorV1 {
                    evaluation_rows: 64,
                    device_columns,
                    receipt: MainTransformReceiptV1::default(),
                };
                let (output, erased) = inspection::observe_v1(|| {
                    evaluator
                        .evaluate_with_v1(&columns, 4, 6, |batch, root| {
                            assert!(batch.len() <= device_columns);
                            transform_goldilocks_columns_v1(
                                batch,
                                root,
                                Direction::Forward,
                                fastpq_prover::ExecutionMode::Cpu,
                            )
                            .map_err(|_| AggregateStarkErrorV1::InvalidLayout)
                        })
                        .unwrap()
                });
                let root = goldilocks_primitive_root_v1(6).unwrap();
                for (coefficients, values) in columns.iter().zip(output) {
                    for (index, value) in values.iter().enumerate() {
                        let point = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(index as u128));
                        let expected = coefficients
                            .iter()
                            .rev()
                            .fold(F::ZERO, |sum, value| sum.mul(point).add(*value));
                        assert_eq!(*value, expected);
                    }
                }
                assert_eq!(evaluator.receipt.cpu_columns, count);
                assert_eq!(evaluator.receipt.metal_columns, 0);
                assert_eq!(
                    erased.iter().map(|entry| entry.cells).sum::<usize>(),
                    count * 64
                );
                assert!(erased.iter().all(|entry| entry.nonzero_after == 0));
            }
        }
    }

    #[test]
    fn failed_and_unwinding_dispatch_erase_the_actual_word_allocations() {
        let columns = columns_v1(3);
        for unwind in [false, true] {
            let ((), observations) = inspection::observe_v1(|| {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut evaluator = MainTraceCosetEvaluatorV1 {
                        evaluation_rows: 64,
                        device_columns: 2,
                        receipt: MainTransformReceiptV1::default(),
                    };
                    evaluator.evaluate_with_v1(&columns, 4, 6, |batch, _| {
                        batch[0][0] = 999;
                        if unwind {
                            panic!("injected dispatch unwind");
                        }
                        Err(AggregateStarkErrorV1::AllocationFailure)
                    })
                }));
                assert!(if unwind {
                    outcome.is_err()
                } else {
                    outcome.unwrap().is_err()
                });
            });
            assert_eq!(
                observations.iter().map(|entry| entry.cells).sum::<usize>(),
                3 * 64
            );
            assert!(
                observations
                    .iter()
                    .map(|entry| entry.nonzero_before)
                    .sum::<usize>()
                    > 0
            );
            assert!(observations.iter().all(|entry| entry.nonzero_after == 0));
        }
    }
    #[test]
    fn malformed_inputs_and_device_outputs_fail_before_publication() {
        use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
        let mut evaluator = MainTraceCosetEvaluatorV1 {
            evaluation_rows: 64,
            device_columns: 2,
            receipt: MainTransformReceiptV1::default(),
        };
        let mut columns = columns_v1(3);
        let mut calls = 0;
        assert!(
            evaluator
                .evaluate_with_v1(&columns, 4, 7, |_, _| {
                    calls += 1;
                    unreachable!()
                })
                .is_err()
        );
        columns[2] = Column::from_vec_v1(vec![F(GOLDILOCKS_MODULUS_V1)]);
        assert!(
            evaluator
                .evaluate_with_v1(&columns, 4, 6, |_, _| {
                    calls += 1;
                    unreachable!()
                })
                .is_err()
        );
        assert_eq!(calls, 0);
        let columns = columns_v1(3);
        let (result, cleared) = inspection::observe_v1(|| {
            evaluator.evaluate_with_v1(&columns, 4, 6, |batch, _| {
                batch[0][1] = GOLDILOCKS_MODULUS_V1;
                Ok(Backend::Metal)
            })
        });
        assert!(matches!(
            result,
            Err(AggregateStarkErrorV1::NonCanonicalField)
        ));
        // All three raw output columns are cleared at their actual ownership
        // boundaries; canonical validation precedes field-value publication.
        assert!(cleared.iter().map(|entry| entry.cells).sum::<usize>() >= 3 * 64);
        assert!(cleared.iter().all(|entry| entry.nonzero_after == 0));
    }
    #[test]
    fn selected_cpu_and_device_adapter_keep_original_row_coordinates_and_fault_checks() {
        use crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1;
        for width in [1, 3, 8] {
            let columns = columns_v1(width);
            for selected in [vec![0], vec![63], vec![0, 7, 16, 63], (0..64).collect()] {
                let expected = columns
                    .iter()
                    .map(|column| masked_trace_coefficients_on_coset_v1(column, 4, 6).unwrap())
                    .collect::<Vec<_>>();
                for device_columns in [0, 1, 2, 4] {
                    let mut evaluator = MainTraceCosetEvaluatorV1 {
                        evaluation_rows: 64,
                        device_columns,
                        receipt: MainTransformReceiptV1::default(),
                    };
                    let actual = evaluator
                        .evaluate_selected_with_v1(
                            &columns,
                            4,
                            6,
                            Some(&selected),
                            |batch, root| {
                                transform_goldilocks_columns_v1(
                                    batch,
                                    root,
                                    Direction::Forward,
                                    fastpq_prover::ExecutionMode::Cpu,
                                )
                                .map_err(|_| AggregateStarkErrorV1::InvalidLayout)
                            },
                        )
                        .unwrap();
                    for (column, full) in actual.iter().zip(&expected) {
                        assert_eq!(column.len(), selected.len());
                        for (&row, &value) in selected.iter().zip(column.iter()) {
                            assert_eq!(value, full[row]);
                        }
                    }
                    assert_eq!(evaluator.receipt.cpu_columns, width);
                }
            }
        }
        let columns = columns_v1(1);
        let mut evaluator = MainTraceCosetEvaluatorV1 {
            evaluation_rows: 64,
            device_columns: 1,
            receipt: MainTransformReceiptV1::default(),
        };
        let result = evaluator.evaluate_selected_with_v1(&columns, 4, 6, Some(&[0]), |batch, _| {
            batch[0][63] = GOLDILOCKS_MODULUS_V1;
            Ok(Backend::Metal)
        });
        assert!(
            matches!(result, Err(AggregateStarkErrorV1::NonCanonicalField)),
            "unselected device corruption must remain visible"
        );
        for selected in [vec![], vec![64], vec![2, 1], vec![1, 1]] {
            assert!(
                evaluator
                    .evaluate_selected_with_v1(&columns, 4, 6, Some(&selected), |_, _| panic!(
                        "invalid selected geometry dispatched"
                    ))
                    .is_err()
            );
        }
    }

    #[test]
    #[ignore = "requires actual Metal common22 selected-row parity; component evidence only"]
    fn selected_required_metal_matches_pruned_cpu_and_original_full_coset() {
        use crate::privacy_engines::transparent_stark::masked_trace_coefficients_with_mask_v1;
        assert_eq!(
            fastpq_prover::goldilocks_transform::available_goldilocks_transform_backend_v1(),
            Some(Backend::Metal)
        );
        let common = 22;
        let rows = 1usize << common;
        let selected = (0..136)
            .flat_map(|query| {
                let block = (query * 1_729 + 17) % (rows / 16);
                block * 16..block * 16 + 16
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for native in [5, 19] {
            for width in [1, 8] {
                let columns = (0..width)
                    .map(|column| {
                        let values = (0..1usize << native)
                            .map(|row| F((row * 17 + column * 13 + 1) as u64))
                            .collect::<Vec<_>>();
                        let mask = (0..1816)
                            .map(|degree| F((degree * 29 + column * 7 + 3) as u64))
                            .collect::<Vec<_>>();
                        Column::from_vec_v1(
                            masked_trace_coefficients_with_mask_v1(&values, native, &mask).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
                let mut metal = MainTraceCosetEvaluatorV1::new_v1(&layout, 0).unwrap();
                assert!(metal.device_columns > 0);
                let actual = metal
                    .evaluate_selected_v1(&columns, native, common, &selected)
                    .unwrap();
                assert_eq!(metal.receipt.metal_columns, width);
                assert_eq!(metal.receipt.cpu_columns, 0);
                let mut cpu = MainTraceCosetEvaluatorV1 {
                    evaluation_rows: rows,
                    device_columns: 0,
                    receipt: MainTransformReceiptV1::default(),
                };
                let pruned = cpu
                    .evaluate_selected_v1(&columns, native, common, &selected)
                    .unwrap();
                for ((column, actual), pruned) in
                    columns.iter().zip(actual.iter()).zip(pruned.iter())
                {
                    let full = Column::from_vec_v1(
                        masked_trace_coefficients_on_coset_v1(column, native, common).unwrap(),
                    );
                    for ((&row, &actual), &pruned) in
                        selected.iter().zip(actual.iter()).zip(pruned.iter())
                    {
                        assert_eq!(actual, full[row]);
                        assert_eq!(pruned, full[row]);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "main_common22_coarse_diagnostic_tests.rs"]
mod common22_coarse_diagnostic_tests;
