//! Lossless, clearing retention of already validated native P-256 arithmetic rows.
//!
//! This changes storage only. It preserves the original row validator and compares
//! every regenerated cell before retaining the compact operation. MAIN ownership,
//! allocation-phase integration and full proof parity remain required before use.

use super::*;
use crate::privacy_engines::zk_x509::private_table::{ClearingVecV1, zeroize_words_v1};

/// One immutable native operation; its public kind/modulus remain attached.
struct CompactOperationV1 {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retain validated public operation identity with compact witness custody; fixed-row qualification consumes it"
        )
    )]
    topology: ZkX509P256ArithmeticTopologyV1,
    expanded: ExpandedOperationV1,
}

impl Drop for CompactOperationV1 {
    fn drop(&mut self) {
        let value = &mut self.expanded;
        for limbs in [
            &mut value.a,
            &mut value.b,
            &mut value.c,
            &mut value.q,
            &mut value.a_difference,
            &mut value.b_difference,
            &mut value.c_difference,
        ] {
            zeroize_words_v1(limbs);
        }
        for borrows in [
            &mut value.a_borrow,
            &mut value.b_borrow,
            &mut value.c_borrow,
        ] {
            zeroize_words_v1(borrows);
        }
        zeroize_words_v1(&mut value.carries);
    }
}

impl CompactOperationV1 {
    fn from_rows_v1(
        fixed: ZkX509P256ArithmeticFixedRowV1,
        rows: &[[F; P256_ARITHMETIC_BASE_WIDTH_V1]],
    ) -> Result<Self, ZkX509P256AirErrorV1> {
        if rows.len() != P256_ARITHMETIC_ROWS_PER_OPERATION_V1 || fixed.coefficient != 0 {
            return Err(ZkX509P256AirErrorV1::Topology);
        }
        // Establish clearing ownership before the first fallible private conversion.
        let mut result = Self {
            topology: ZkX509P256ArithmeticTopologyV1 {
                kind: fixed.kind,
                modulus: fixed.modulus,
            },
            expanded: ExpandedOperationV1 {
                a: [0; LIMBS],
                b: [0; LIMBS],
                c: [0; LIMBS],
                q: [0; LIMBS],
                a_difference: [0; LIMBS],
                b_difference: [0; LIMBS],
                c_difference: [0; LIMBS],
                a_borrow: [0; LIMBS + 1],
                b_borrow: [0; LIMBS + 1],
                c_borrow: [0; LIMBS + 1],
                carries: [0; P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + 1],
            },
        };
        let limb = |value: F| u16::try_from(value.0).map_err(|_| ZkX509P256AirErrorV1::Constraint);
        let bit = |value: F| {
            if value.0 <= 1 {
                Ok(value.0 as u8)
            } else {
                Err(ZkX509P256AirErrorV1::Constraint)
            }
        };
        for index in 0..LIMBS {
            result.expanded.a[index] = limb(rows[0][A_START + index])?;
            result.expanded.b[index] = limb(rows[0][B_START + index])?;
            result.expanded.c[index] = limb(rows[0][C_START + index])?;
            result.expanded.q[index] = limb(rows[0][Q_START + index])?;
            result.expanded.a_difference[index] = limb(rows[index][A_DIFFERENCE])?;
            result.expanded.b_difference[index] = limb(rows[index][B_DIFFERENCE])?;
            result.expanded.c_difference[index] = limb(rows[index][C_DIFFERENCE])?;
            result.expanded.a_borrow[index + 1] = bit(rows[index][A_BORROW_AFTER])?;
            result.expanded.b_borrow[index + 1] = bit(rows[index][B_BORROW_AFTER])?;
            result.expanded.c_borrow[index + 1] = bit(rows[index][C_BORROW_AFTER])?;
        }
        result.expanded.a_borrow[0] = bit(rows[0][A_BORROW_BEFORE])?;
        result.expanded.b_borrow[0] = bit(rows[0][B_BORROW_BEFORE])?;
        result.expanded.c_borrow[0] = bit(rows[0][C_BORROW_BEFORE])?;
        for (coefficient, row) in rows.iter().enumerate() {
            let encoded =
                i64::try_from(row[CARRY].0).map_err(|_| ZkX509P256AirErrorV1::CarryRange)?;
            result.expanded.carries[coefficient] = encoded
                .checked_sub(CARRY_BIAS)
                .ok_or(ZkX509P256AirErrorV1::CarryRange)?;
        }
        // The original last-row equation uses a fixed zero next carry. No 33rd
        // carry cell exists in the committed rows, and no new cell is introduced.
        for (coefficient, original) in rows.iter().enumerate() {
            let mut regenerated = result.expanded.base_row(ZkX509P256ArithmeticFixedRowV1 {
                coefficient: coefficient as u8,
                ..fixed
            })?;
            let matches = &regenerated == original;
            crate::privacy_engines::zk_x509::private_table::zeroize_fields_v1(&mut regenerated);
            if !matches {
                return Err(ZkX509P256AirErrorV1::Constraint);
            }
        }
        Ok(result)
    }

    /// Select one original cell using only public column/coefficient positions.
    fn cell_v1(&self, coefficient: usize, column: usize) -> F {
        let value = &self.expanded;
        let slot = coefficient % LIMBS;
        let canonicality = coefficient < LIMBS;
        let word = if column < B_START {
            u64::from(value.a[column - A_START])
        } else if column < C_START {
            u64::from(value.b[column - B_START])
        } else if column < Q_START {
            u64::from(value.c[column - C_START])
        } else if column < A_BITS {
            u64::from(value.q[column - Q_START])
        } else if column < B_BITS {
            u64::from((value.a[slot] >> (column - A_BITS)) & 1)
        } else if column < C_BITS {
            u64::from((value.b[slot] >> (column - B_BITS)) & 1)
        } else if column < Q_BITS {
            u64::from((value.c[slot] >> (column - C_BITS)) & 1)
        } else if column < A_DIFFERENCE {
            u64::from((value.q[slot] >> (column - Q_BITS)) & 1)
        } else if column < CARRY {
            if !canonicality {
                0
            } else if column == A_DIFFERENCE {
                u64::from(value.a_difference[slot])
            } else if column == B_DIFFERENCE {
                u64::from(value.b_difference[slot])
            } else if column == C_DIFFERENCE {
                u64::from(value.c_difference[slot])
            } else if column < B_DIFFERENCE_BITS {
                u64::from((value.a_difference[slot] >> (column - A_DIFFERENCE_BITS)) & 1)
            } else if column < C_DIFFERENCE_BITS {
                u64::from((value.b_difference[slot] >> (column - B_DIFFERENCE_BITS)) & 1)
            } else if column < A_BORROW_BEFORE {
                u64::from((value.c_difference[slot] >> (column - C_DIFFERENCE_BITS)) & 1)
            } else if column == A_BORROW_BEFORE {
                u64::from(value.a_borrow[slot])
            } else if column == B_BORROW_BEFORE {
                u64::from(value.b_borrow[slot])
            } else if column == C_BORROW_BEFORE {
                u64::from(value.c_borrow[slot])
            } else if column == A_BORROW_AFTER {
                u64::from(value.a_borrow[slot + 1])
            } else if column == B_BORROW_AFTER {
                u64::from(value.b_borrow[slot + 1])
            } else {
                u64::from(value.c_borrow[slot + 1])
            }
        } else {
            let encoded = (value.carries[coefficient] + CARRY_BIAS) as u64;
            if column == CARRY {
                encoded
            } else {
                (encoded >> (column - CARRY_BIT_START)) & 1
            }
        };
        F(word)
    }
}

/// Compact native storage with no mutable or cloning interface.
///
/// The caller retains the source trace until construction succeeds and must
/// account for both allocations during that overlap. Spare allocation is cleared.
pub(crate) struct P256CompactArithmeticTraceV1 {
    operations: ClearingVecV1<CompactOperationV1>,
}

impl core::fmt::Debug for P256CompactArithmeticTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256CompactArithmeticTraceV1")
            .field("private_material", &"<redacted>")
            .finish()
    }
}

impl P256CompactArithmeticTraceV1 {
    /// Validate and retain exact original rows within an explicit payload ceiling.
    #[cfg(test)]
    pub(crate) fn from_trace_v1(
        trace: &ZkX509P256ArithmeticTraceV1,
        payload_ceiling: usize,
    ) -> Result<Self, ZkX509P256AirErrorV1> {
        trace.validate()?;
        Self::retain_rows_v1(trace, payload_ceiling)
    }

    /// Consume only the adapter's immutable, constraint- and topology-checked capability.
    pub(crate) fn from_validated_v1(
        owner: &crate::privacy_engines::zk_x509::p256_aggregate_adapter::P256MainRawArithmeticV1,
        payload_ceiling: usize,
    ) -> Result<Self, ZkX509P256AirErrorV1> {
        Self::retain_rows_v1(owner.validated_trace_v1(), payload_ceiling)
    }

    /// Exact reserve request for a public operation count; actual capacity is checked separately.
    pub(crate) fn payload_forecast_v1(count: usize) -> Result<usize, ZkX509P256AirErrorV1> {
        count
            .checked_mul(core::mem::size_of::<CompactOperationV1>())
            .ok_or(ZkX509P256AirErrorV1::Allocation)
    }

    fn retain_rows_v1(
        trace: &ZkX509P256ArithmeticTraceV1,
        payload_ceiling: usize,
    ) -> Result<Self, ZkX509P256AirErrorV1> {
        let count = trace.rows() / P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        let required = count
            .checked_mul(core::mem::size_of::<CompactOperationV1>())
            .ok_or(ZkX509P256AirErrorV1::Allocation)?;
        if required > payload_ceiling {
            return Err(ZkX509P256AirErrorV1::Allocation);
        }
        let mut operations = ClearingVecV1::try_with_capacity_v1(count)
            .map_err(|_| ZkX509P256AirErrorV1::Allocation)?;
        if operations.allocated_bytes_v1() > payload_ceiling {
            return Err(ZkX509P256AirErrorV1::Allocation);
        }
        for (index, rows) in trace
            .base
            .chunks_exact(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .enumerate()
        {
            let operation = CompactOperationV1::from_rows_v1(
                trace.fixed[index * P256_ARITHMETIC_ROWS_PER_OPERATION_V1],
                rows,
            )?;
            if operations.try_push_v1(operation).is_err() {
                return Err(ZkX509P256AirErrorV1::Allocation);
            }
        }
        Ok(Self { operations })
    }

    /// Number of original logical rows, excluding aggregate padding.
    pub(crate) fn rows_v1(&self) -> usize {
        self.operations.len() * P256_ARITHMETIC_ROWS_PER_OPERATION_V1
    }

    /// Actual retained payload including unused operation capacity.
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        self.operations.allocated_bytes_v1()
    }

    /// Original operation metadata at one logical row.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<ZkX509P256ArithmeticFixedRowV1, ZkX509P256AirErrorV1> {
        let index = row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        let operation = self
            .operations
            .get(index)
            .ok_or(ZkX509P256AirErrorV1::Topology)?;
        Ok(ZkX509P256ArithmeticFixedRowV1 {
            operation: u32::try_from(index).map_err(|_| ZkX509P256AirErrorV1::Topology)?,
            coefficient: (row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1) as u8,
            kind: operation.topology.kind,
            modulus: operation.topology.modulus,
        })
    }

    /// Select the native scalar cells using only the public row position.
    pub(crate) fn scalar_sources_v1(&self, row: usize) -> Result<[F; 8], ZkX509P256AirErrorV1> {
        let mut values = [F::ZERO; 8];
        let high = usize::from(row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1 >= LIMBS) * 8;
        self.fill_cells_v1(row, C_BITS + high, &mut values)?;
        Ok(values)
    }

    /// Native coefficient selection equivalent to the original fixed-column projection.
    pub(crate) fn operand_sources_v1(&self, row: usize) -> Result<[F; 3], ZkX509P256AirErrorV1> {
        let operation = self
            .operations
            .get(row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .ok_or(ZkX509P256AirErrorV1::Topology)?;
        let coefficient = row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        let limb = coefficient % LIMBS;
        Ok([A_START, B_START, C_START].map(|first| operation.cell_v1(coefficient, first + limb)))
    }

    /// Write original contiguous cells without allocating or copying a full row.
    pub(crate) fn fill_cells_v1(
        &self,
        row: usize,
        first: usize,
        output: &mut [F],
    ) -> Result<(), ZkX509P256AirErrorV1> {
        if output.is_empty()
            || first
                .checked_add(output.len())
                .is_none_or(|end| end > P256_ARITHMETIC_BASE_WIDTH_V1)
        {
            return Err(ZkX509P256AirErrorV1::Topology);
        }
        let operation = self
            .operations
            .get(row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .ok_or(ZkX509P256AirErrorV1::Topology)?;
        let coefficient = row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        for (offset, destination) in output.iter_mut().enumerate() {
            *destination = operation.cell_v1(coefficient, first + offset);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(value: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[31] = value;
        bytes
    }

    fn predecessor(mut bytes: [u8; 32]) -> [u8; 32] {
        for byte in bytes.iter_mut().rev() {
            let (next, borrow) = byte.overflowing_sub(1);
            *byte = next;
            if !borrow {
                return bytes;
            }
        }
        panic!("fixture modulus is positive");
    }

    fn boundary_trace() -> ZkX509P256ArithmeticTraceV1 {
        let mut operations = Vec::new();
        for modulus in [
            ZkX509P256ModulusV1::BaseField,
            ZkX509P256ModulusV1::ScalarField,
        ] {
            let last = predecessor(modulus.bytes_be());
            for (kind, a, b, c) in [
                (ZkX509P256ArithmeticKindV1::Add, word(3), word(5), word(8)),
                (
                    ZkX509P256ArithmeticKindV1::Multiply,
                    word(3),
                    word(5),
                    word(15),
                ),
                (
                    ZkX509P256ArithmeticKindV1::Subtract,
                    word(5),
                    word(3),
                    word(2),
                ),
                (ZkX509P256ArithmeticKindV1::Add, last, word(1), word(0)),
                (ZkX509P256ArithmeticKindV1::Multiply, last, last, word(1)),
                (ZkX509P256ArithmeticKindV1::Subtract, word(0), word(1), last),
            ] {
                operations.push(ZkX509P256ArithmeticOperationV1 {
                    kind,
                    modulus,
                    a,
                    b,
                    c,
                });
            }
        }
        build_zk_x509_p256_arithmetic_trace_v1(&operations).unwrap()
    }

    #[test]
    fn compact_rows_preserve_every_native_cell_and_fixed_position() {
        let raw = boundary_trace();
        let compact = P256CompactArithmeticTraceV1::from_trace_v1(&raw, usize::MAX).unwrap();
        assert_eq!(compact.rows_v1(), raw.rows());
        let topology: Vec<_> = raw
            .fixed
            .iter()
            .step_by(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .map(|fixed| ZkX509P256ArithmeticTopologyV1 {
                kind: fixed.kind,
                modulus: fixed.modulus,
            })
            .collect();
        let fixed =
            P256ArithmeticStarkFixedProviderV1::new_v1(&topology, raw.rows().next_power_of_two())
                .unwrap();
        for row in 0..raw.rows() {
            let native_fixed = fixed.row_v1(row).unwrap();
            assert_eq!(
                compact.scalar_sources_v1(row).unwrap(),
                p256_arithmetic_opened_scalar_source_bits_v1(&raw.base[row], &native_fixed)
            );
            assert_eq!(
                compact.operand_sources_v1(row).unwrap(),
                p256_arithmetic_opened_operand_limbs_v1(&raw.base[row], &native_fixed)
            );
            assert_eq!(compact.fixed_row_v1(row).unwrap(), raw.fixed[row]);
            for width in [1, 8, P256_ARITHMETIC_BASE_WIDTH_V1] {
                for first in (0..P256_ARITHMETIC_BASE_WIDTH_V1).step_by(width) {
                    let count = width.min(P256_ARITHMETIC_BASE_WIDTH_V1 - first);
                    let mut output = vec![F(97); count];
                    compact.fill_cells_v1(row, first, &mut output).unwrap();
                    assert_eq!(output, raw.base[row][first..first + count]);
                }
            }
        }
        assert_eq!(compact.operations.len(), 12);
        assert!(
            compact.allocated_heap_bytes_v1() * 90
                < raw.base.len() * core::mem::size_of::<[F; P256_ARITHMETIC_BASE_WIDTH_V1]>()
        );
    }

    #[test]
    fn compact_storage_rejects_malformed_original_constraints_and_topology() {
        let original = boundary_trace();
        for (row, column) in [
            (0, A_START),
            (1, Q_START),
            (0, A_BITS),
            (0, A_DIFFERENCE),
            (15, A_BORROW_AFTER),
            (16, B_DIFFERENCE),
            (31, CARRY),
            (7, CARRY_BIT_START),
        ] {
            let mut raw = original.clone();
            raw.base[row][column] = raw.base[row][column].add(F::ONE);
            assert!(P256CompactArithmeticTraceV1::from_trace_v1(&raw, usize::MAX).is_err());
        }
        let mut raw = original.clone();
        raw.fixed[3].coefficient = 4;
        assert!(P256CompactArithmeticTraceV1::from_trace_v1(&raw, usize::MAX).is_err());
        let mut raw = original;
        raw.fixed[3].modulus = ZkX509P256ModulusV1::ScalarField;
        assert!(P256CompactArithmeticTraceV1::from_trace_v1(&raw, usize::MAX).is_err());
    }

    #[test]
    fn compact_partial_record_clears_on_bad_conversion_or_regeneration_mismatch() {
        use crate::privacy_engines::zk_x509::private_table::inspection;
        let raw = boundary_trace();
        for column in [B_START + 1, Q_BITS + 7, CARRY] {
            let mut rows = raw.base[..P256_ARITHMETIC_ROWS_PER_OPERATION_V1].to_vec();
            rows[0][column] = if column == B_START + 1 {
                F(1 << 16)
            } else if column == CARRY {
                F((CARRY_BIAS + CARRY_ABSOLUTE_BOUND) as u64)
            } else {
                rows[0][column].add(F::ONE)
            };
            let (result, observations) =
                inspection::observe_v1(|| CompactOperationV1::from_rows_v1(raw.fixed[0], &rows));
            assert!(result.is_err());
            assert!(observations.iter().any(|item| item.nonzero_before > 0));
            assert!(observations.iter().all(|item| item.nonzero_after == 0));
        }
    }

    #[test]
    fn compact_storage_checks_exact_payload_and_public_ranges_before_writing() {
        let raw = boundary_trace();
        let bytes = 12 * core::mem::size_of::<CompactOperationV1>();
        assert!(matches!(
            P256CompactArithmeticTraceV1::from_trace_v1(&raw, bytes - 1),
            Err(ZkX509P256AirErrorV1::Allocation)
        ));
        let compact = P256CompactArithmeticTraceV1::from_trace_v1(&raw, bytes).unwrap();
        assert_eq!(compact.allocated_heap_bytes_v1(), bytes);
        let mut output = [F(97); 8];
        for (row, first) in [
            (raw.rows(), 0),
            (0, P256_ARITHMETIC_BASE_WIDTH_V1 - 7),
            (0, usize::MAX),
        ] {
            assert!(compact.fill_cells_v1(row, first, &mut output).is_err());
            assert_eq!(output, [F(97); 8]);
        }
        assert!(compact.fill_cells_v1(0, 0, &mut []).is_err());
        assert!(compact.fixed_row_v1(raw.rows()).is_err());
    }

    #[test]
    fn compact_storage_clears_live_values_and_entire_capacity_on_drop_and_unwind() {
        use crate::privacy_engines::zk_x509::private_table::{allocation_inspection, inspection};
        let raw = boundary_trace();
        for unwind in [false, true] {
            let (_, live) = inspection::observe_v1(|| {
                let (_, allocations) = allocation_inspection::observe_v1(|| {
                    let constructed = core::cell::Cell::new(false);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let compact =
                            P256CompactArithmeticTraceV1::from_trace_v1(&raw, usize::MAX).unwrap();
                        assert_eq!(compact.rows_v1(), raw.rows());
                        constructed.set(true);
                        if unwind {
                            panic!("exercise compact allocation unwind");
                        }
                        drop(compact);
                    }));
                    assert!(
                        constructed.get(),
                        "constructor and row assertion must finish before deliberate unwind"
                    );
                    assert_eq!(result.is_err(), unwind);
                });
                assert!(
                    allocations
                        .iter()
                        .any(|item| item.bytes >= 12 * core::mem::size_of::<CompactOperationV1>())
                );
                assert!(allocations.iter().all(|item| item.nonzero_after == 0));
            });
            assert!(live.iter().any(|item| item.nonzero_before > 0));
            assert!(live.iter().all(|item| item.nonzero_after == 0));
        }
    }
}
