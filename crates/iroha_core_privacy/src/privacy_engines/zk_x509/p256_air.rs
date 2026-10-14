//! Exact nonnative P-256 integer arithmetic for the zk-X509 STARK.
//!
//! P-256 base- and scalar-field elements use sixteen little-endian 16-bit limbs. Every limb and
//! every signed carry is bit-decomposed. Multiplication proves all 32 schoolbook coefficients of `a
//! * b = c + q * modulus`; addition proves the analogous radix equation. The absolute value of
//! every integer residue is below `2^43`, so equality in Goldilocks is equality over the integers
//! rather than a field-wrap shortcut.
use crate::privacy_engines::transparent_stark::{GoldilocksFieldV1 as F, PolynomialAirFieldV1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use p256::elliptic_curve::bigint::{Encoding as _, NonZero, U256, U512};
use thiserror::Error;
/// P-256 coordinate-field modulus in canonical big-endian form.
pub(crate) const P256_BASE_MODULUS_BE_V1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// P-256 scalar-field order in canonical big-endian form.
pub(crate) const P256_SCALAR_MODULUS_BE_V1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const LIMBS: usize = 16;
/// Fixed schoolbook coefficient rows per arithmetic operation.
pub(crate) const P256_ARITHMETIC_ROWS_PER_OPERATION_V1: usize = 2 * LIMBS;
/// Base width before aggregate column sharding.
pub(crate) const P256_ARITHMETIC_BASE_WIDTH_V1: usize = 211;
/// Challenge-dependent aggregate width.
///
/// Arithmetic itself has no lookup product. The single column is committed
/// after the transcript challenges and constrained to zero so the aggregate
/// proof has one uniform base/aux commitment shape without an unbound cell.
pub(crate) const P256_ARITHMETIC_STARK_AUX_WIDTH_V1: usize = 1;
/// Verifier-preprocessed fixed width for the extension-domain evaluator.
pub(crate) const P256_ARITHMETIC_STARK_FIXED_WIDTH_V1: usize = 90;
/// Exact fixed-width constraint inventory for one opened arithmetic row.
pub(crate) const P256_ARITHMETIC_STARK_CONSTRAINT_COUNT_V1: usize = 368;
/// Maximum total degree in committed and verifier-preprocessed columns.
pub(crate) const P256_ARITHMETIC_STARK_CONSTRAINT_DEGREE_V1: u8 = 4;
const LIMB_BITS: usize = 16;
const CARRY_BITS: usize = 25;
const CARRY_BIAS: i64 = 1 << 24;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const CARRY_ABSOLUTE_BOUND: i64 = 1 << 22;
const RADIX: i64 = 1 << 16;
const A_START: usize = 0;
const B_START: usize = A_START + LIMBS;
const C_START: usize = B_START + LIMBS;
const Q_START: usize = C_START + LIMBS;
const A_BITS: usize = Q_START + LIMBS;
const B_BITS: usize = A_BITS + LIMB_BITS;
const C_BITS: usize = B_BITS + LIMB_BITS;
const Q_BITS: usize = C_BITS + LIMB_BITS;
const A_DIFFERENCE: usize = Q_BITS + LIMB_BITS;
const B_DIFFERENCE: usize = A_DIFFERENCE + 1;
const C_DIFFERENCE: usize = B_DIFFERENCE + 1;
const A_DIFFERENCE_BITS: usize = C_DIFFERENCE + 1;
const B_DIFFERENCE_BITS: usize = A_DIFFERENCE_BITS + LIMB_BITS;
const C_DIFFERENCE_BITS: usize = B_DIFFERENCE_BITS + LIMB_BITS;
const A_BORROW_BEFORE: usize = C_DIFFERENCE_BITS + LIMB_BITS;
const B_BORROW_BEFORE: usize = A_BORROW_BEFORE + 1;
const C_BORROW_BEFORE: usize = B_BORROW_BEFORE + 1;
const A_BORROW_AFTER: usize = C_BORROW_BEFORE + 1;
const B_BORROW_AFTER: usize = A_BORROW_AFTER + 1;
const C_BORROW_AFTER: usize = B_BORROW_AFTER + 1;
const CARRY: usize = C_BORROW_AFTER + 1;
const CARRY_BIT_START: usize = CARRY + 1;
const STARK_KIND_MULTIPLY: usize = 0;
const STARK_KIND_ADD: usize = STARK_KIND_MULTIPLY + 1;
const STARK_KIND_SUBTRACT: usize = STARK_KIND_ADD + 1;
const STARK_MODULUS_LIMBS_START: usize = STARK_KIND_SUBTRACT + 1;
const STARK_COEFFICIENT_START: usize = STARK_MODULUS_LIMBS_START + LIMBS;
const STARK_RANGE_SLOT_START: usize =
    STARK_COEFFICIENT_START + P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
const STARK_LOW_SLOT_START: usize = STARK_RANGE_SLOT_START + LIMBS;
const STARK_LOW_MODULUS_LIMB: usize = STARK_LOW_SLOT_START + LIMBS;
const STARK_CANONICALITY_ROW: usize = STARK_LOW_MODULUS_LIMB + 1;
const STARK_SLOT_FIRST: usize = STARK_CANONICALITY_ROW + 1;
const STARK_SLOT_LAST: usize = STARK_SLOT_FIRST + 1;
const STARK_OPERATION_FIRST: usize = STARK_SLOT_LAST + 1;
const STARK_OPERATION_LAST: usize = STARK_OPERATION_FIRST + 1;
const STARK_PADDING: usize = STARK_OPERATION_LAST + 1;
const _: () = assert!(STARK_PADDING + 1 == P256_ARITHMETIC_STARK_FIXED_WIDTH_V1);
/// Fixed P-256 modulus selected by one arithmetic instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ZkX509P256ModulusV1 {
    /// Coordinate-field prime.
    BaseField,
    /// Scalar-field order.
    ScalarField,
}
impl ZkX509P256ModulusV1 {
    fn bytes_be(self) -> [u8; 32] {
        match self {
            Self::BaseField => P256_BASE_MODULUS_BE_V1,
            Self::ScalarField => P256_SCALAR_MODULUS_BE_V1,
        }
    }
    fn limbs_le(self) -> [u16; LIMBS] {
        bytes_be_to_limbs_le_v1(self.bytes_be())
    }
}
/// Fixed arithmetic relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ZkX509P256ArithmeticKindV1 {
    /// `a * b = c + q * modulus`.
    Multiply,
    /// `a + b = c + q * modulus`, with `q` exactly zero or one.
    Add,
    /// `a - b = c (mod modulus)`, proved as `a - b - c + q*modulus = 0`
    /// with `q` exactly zero or one.
    Subtract,
}
/// Value-free verifier instruction used to compile arithmetic preprocessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509P256ArithmeticTopologyV1 {
    /// Fixed arithmetic relation.
    pub(crate) kind: ZkX509P256ArithmeticKindV1,
    /// Fixed arithmetic modulus.
    pub(crate) modulus: ZkX509P256ModulusV1,
}
/// One canonical arithmetic operation before row expansion.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509P256ArithmeticOperationV1 {
    /// Relation kind.
    pub(crate) kind: ZkX509P256ArithmeticKindV1,
    /// Selected modulus.
    pub(crate) modulus: ZkX509P256ModulusV1,
    /// First canonical operand, big-endian.
    pub(crate) a: [u8; 32],
    /// Second canonical operand, big-endian.
    pub(crate) b: [u8; 32],
    /// Canonical result, big-endian.
    pub(crate) c: [u8; 32],
}
/// Verifier-regenerated row location and selectors.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509P256ArithmeticFixedRowV1 {
    /// Sequential operation index.
    pub(crate) operation: u32,
    /// Product/addition coefficient, from zero through 31.
    pub(crate) coefficient: u8,
    /// Relation kind.
    pub(crate) kind: ZkX509P256ArithmeticKindV1,
    /// Selected modulus.
    pub(crate) modulus: ZkX509P256ModulusV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509P256ArithmeticFixedRowV1 {
    const fn is_first(self) -> bool {
        self.coefficient == 0
    }
    const fn is_last(self) -> bool {
        self.coefficient as usize + 1 == P256_ARITHMETIC_ROWS_PER_OPERATION_V1
    }
    const fn has_canonicality_row(self) -> bool {
        (self.coefficient as usize) < LIMBS
    }
    const fn range_slot(self) -> usize {
        self.coefficient as usize % LIMBS
    }
}
/// Complete exact arithmetic trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZkX509P256ArithmeticTraceV1 {
    /// Verifier-regenerated fixed topology.
    pub(crate) fixed: Vec<ZkX509P256ArithmeticFixedRowV1>,
    /// Committed base rows.
    pub(crate) base: Vec<[F; P256_ARITHMETIC_BASE_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509P256ArithmeticTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509P256ArithmeticTraceV1 { <private trace redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509P256ArithmeticTraceV1 {
    fn drop(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.base);
    }
}
/// Clear private operation words held by temporary operation batches.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn zeroize_p256_operations_v1(operations: &mut [ZkX509P256ArithmeticOperationV1]) {
    for operation in operations {
        super::private_table::zeroize_words_v1(&mut operation.a);
        super::private_table::zeroize_words_v1(&mut operation.b);
        super::private_table::zeroize_words_v1(&mut operation.c);
    }
}
/// Project the selected `c`-limb bit decomposition from one opened arithmetic base row.
///
/// The coefficient fixed columns determine which limb this row represents. This helper deliberately
/// performs no native row decoding: source-product evaluators consume these sixteen committed cells
/// directly on the extension domain.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn p256_arithmetic_opened_c_limb_bits_v1(
    base: &[F; P256_ARITHMETIC_BASE_WIDTH_V1],
) -> [F; LIMB_BITS] {
    core::array::from_fn(|bit| base[C_BITS + bit])
}
/// Select the eight `c`-limb bit cells assigned to one scalar-source row.
///
/// The first sixteen coefficients select bits 0 through 7 and the final sixteen select bits 8
/// through 15. Selection is a polynomial in verifier-preprocessed coefficient columns, so the
/// extension evaluator does not branch on a native coefficient index.
pub(crate) fn p256_arithmetic_opened_scalar_source_bits_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    fixed: &[A; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1],
) -> [A; 8] {
    let high = (LIMBS..P256_ARITHMETIC_ROWS_PER_OPERATION_V1).fold(A::ZERO, |sum, coefficient| {
        sum.add(fixed[STARK_COEFFICIENT_START + coefficient])
    });
    core::array::from_fn(|bit| {
        base[C_BITS + bit].add(high.mul(base[C_BITS + LIMBS / 2 + bit].sub(base[C_BITS + bit])))
    })
}
/// Select the `a`, `b`, and `c` limb cells addressed by this opened coefficient row.
///
/// The first sixteen verifier-preprocessed coefficient selectors form the limb selector. This
/// projection is therefore a polynomial in the opened arithmetic row and fixed preprocessing; it
/// never decodes a proof-supplied row index.
pub(crate) fn p256_arithmetic_opened_operand_limbs_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    fixed: &[A; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1],
) -> [A; 3] {
    [A_START, B_START, C_START].map(|start| {
        (0..LIMBS).fold(A::ZERO, |sum, limb| {
            sum.add(base[start + limb].mul(fixed[STARK_RANGE_SLOT_START + limb]))
        })
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509P256ArithmeticTraceV1 {
    /// Number of logical rows.
    pub(crate) fn rows(&self) -> usize {
        self.base.len()
    }
    /// Validate fixed topology and every exact arithmetic identity.
    pub(crate) fn validate(&self) -> Result<(), ZkX509P256AirErrorV1> {
        if self.fixed.len() != self.base.len()
            || self.base.is_empty()
            || !self
                .base
                .len()
                .is_multiple_of(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
        {
            return Err(ZkX509P256AirErrorV1::Topology);
        }
        for row in 0..self.base.len() {
            let fixed = self.fixed[row];
            if fixed.operation as usize != row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1
                || fixed.coefficient as usize != row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1
            {
                return Err(ZkX509P256AirErrorV1::Topology);
            }
            let first = self.fixed[row - row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1];
            if fixed.kind != first.kind || fixed.modulus != first.modulus {
                return Err(ZkX509P256AirErrorV1::Topology);
            }
            let residues = evaluate_p256_arithmetic_row_constraints_v1(
                fixed,
                &self.base[row],
                self.base.get(row + 1),
            )?;
            if residues.iter().any(|residue| *residue != F::ZERO) {
                return Err(ZkX509P256AirErrorV1::Constraint);
            }
        }
        Ok(())
    }
}
/// Constant-memory verifier-owned arithmetic preprocessing provider.
///
/// The complete logical topology is checked once at construction. Numeric
/// fixed rows, including the canonical suffix through `trace_size`, are then
/// regenerated on demand without retaining a wide fixed table.
#[derive(Clone, Debug)]
pub(crate) struct P256ArithmeticStarkFixedProviderV1 {
    operations: Vec<ZkX509P256ArithmeticTopologyV1>,
    active_rows: usize,
    trace_size: usize,
}
impl P256ArithmeticStarkFixedProviderV1 {
    /// Allocated compact verifier topology payload.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        super::allocation_payload::vector_v1(&self.operations)
    }
    /// Validate the deterministic topology and establish one padded native domain.
    pub(crate) fn new_v1(
        operations: &[ZkX509P256ArithmeticTopologyV1],
        trace_size: usize,
    ) -> Result<Self, ZkX509P256AirErrorV1> {
        let active_rows = operations
            .len()
            .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .ok_or(ZkX509P256AirErrorV1::Allocation)?;
        let no_operations = operations.is_empty();
        if no_operations || !trace_size.is_power_of_two() || active_rows > trace_size {
            return Err(ZkX509P256AirErrorV1::Topology);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(operations.len())
            .map_err(|_| ZkX509P256AirErrorV1::Allocation)?;
        owned.extend_from_slice(operations);
        Ok(Self {
            operations: owned,
            active_rows,
            trace_size,
        })
    }
    /// Regenerate one exact numeric row.
    pub(crate) fn row_v1(
        &self,
        index: usize,
    ) -> Result<[F; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1], ZkX509P256AirErrorV1> {
        if index >= self.trace_size {
            return Err(ZkX509P256AirErrorV1::Topology);
        }
        if index >= self.active_rows {
            let mut row = [F::ZERO; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1];
            row[STARK_PADDING] = F::ONE;
            return Ok(row);
        }
        let operation = index / P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        let fixed = self
            .operations
            .get(operation)
            .copied()
            .ok_or(ZkX509P256AirErrorV1::Topology)?;
        let coefficient = index % P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        let mut row = [F::ZERO; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1];
        row[match fixed.kind {
            ZkX509P256ArithmeticKindV1::Multiply => STARK_KIND_MULTIPLY,
            ZkX509P256ArithmeticKindV1::Add => STARK_KIND_ADD,
            ZkX509P256ArithmeticKindV1::Subtract => STARK_KIND_SUBTRACT,
        }] = F::ONE;
        for (target, limb) in row[STARK_MODULUS_LIMBS_START..STARK_MODULUS_LIMBS_START + LIMBS]
            .iter_mut()
            .zip(fixed.modulus.limbs_le())
        {
            *target = F(u64::from(limb));
        }
        row[STARK_COEFFICIENT_START + coefficient] = F::ONE;
        let slot = coefficient % LIMBS;
        row[STARK_RANGE_SLOT_START + slot] = F::ONE;
        if coefficient < LIMBS {
            row[STARK_LOW_SLOT_START + slot] = F::ONE;
            row[STARK_LOW_MODULUS_LIMB] = F(u64::from(fixed.modulus.limbs_le()[slot]));
            row[STARK_CANONICALITY_ROW] = F::ONE;
        }
        row[STARK_SLOT_FIRST] = F(u64::from(slot == 0));
        row[STARK_SLOT_LAST] = F(u64::from(slot + 1 == LIMBS));
        row[STARK_OPERATION_FIRST] = F(u64::from(coefficient == 0));
        row[STARK_OPERATION_LAST] = F(u64::from(
            coefficient + 1 == P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
        ));
        Ok(row)
    }
}
/// Exact P-256 arithmetic trace failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum ZkX509P256AirErrorV1 {
    /// No operation was supplied or fixed rows are inconsistent.
    #[error("zk-X509 P-256 arithmetic topology is invalid")]
    Topology,
    /// An operand or result is not below its selected modulus.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 integer is non-canonical")]
    NonCanonicalInteger,
    /// The claimed modular result is false.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 modular operation is invalid")]
    InvalidOperation,
    /// A carry escaped the proved fixed signed range.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 arithmetic carry is out of range")]
    CarryRange,
    /// A range, comparison, transition, or coefficient identity failed.
    #[error("zk-X509 P-256 arithmetic constraint failed")]
    Constraint,
    /// Bounded trace sizing or allocation failed.
    #[error("zk-X509 P-256 arithmetic allocation failed")]
    Allocation,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy)]
struct ExpandedOperationV1 {
    a: [u16; LIMBS],
    b: [u16; LIMBS],
    c: [u16; LIMBS],
    q: [u16; LIMBS],
    a_difference: [u16; LIMBS],
    b_difference: [u16; LIMBS],
    c_difference: [u16; LIMBS],
    a_borrow: [u8; LIMBS + 1],
    b_borrow: [u8; LIMBS + 1],
    c_borrow: [u8; LIMBS + 1],
    carries: [i64; P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + 1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ExpandedOperationV1 {
    fn base_row(
        &self,
        fixed: ZkX509P256ArithmeticFixedRowV1,
    ) -> Result<[F; P256_ARITHMETIC_BASE_WIDTH_V1], ZkX509P256AirErrorV1> {
        // Refuse invalid carries before any private output cells are populated.
        let carry = self.carries[usize::from(fixed.coefficient)];
        if carry.unsigned_abs() >= CARRY_ABSOLUTE_BOUND as u64 {
            return Err(ZkX509P256AirErrorV1::CarryRange);
        }
        let encoded = carry
            .checked_add(CARRY_BIAS)
            .ok_or(ZkX509P256AirErrorV1::CarryRange)?;
        if !(0..(1_i64 << CARRY_BITS)).contains(&encoded) {
            return Err(ZkX509P256AirErrorV1::CarryRange);
        }
        let mut row = [F::ZERO; P256_ARITHMETIC_BASE_WIDTH_V1];
        write_limbs_v1(&mut row[A_START..A_START + LIMBS], &self.a);
        write_limbs_v1(&mut row[B_START..B_START + LIMBS], &self.b);
        write_limbs_v1(&mut row[C_START..C_START + LIMBS], &self.c);
        write_limbs_v1(&mut row[Q_START..Q_START + LIMBS], &self.q);
        let slot = fixed.range_slot();
        write_bits_v1(&mut row[A_BITS..A_BITS + LIMB_BITS], self.a[slot]);
        write_bits_v1(&mut row[B_BITS..B_BITS + LIMB_BITS], self.b[slot]);
        write_bits_v1(&mut row[C_BITS..C_BITS + LIMB_BITS], self.c[slot]);
        write_bits_v1(&mut row[Q_BITS..Q_BITS + LIMB_BITS], self.q[slot]);
        if fixed.has_canonicality_row() {
            row[A_DIFFERENCE] = F(u64::from(self.a_difference[slot]));
            row[B_DIFFERENCE] = F(u64::from(self.b_difference[slot]));
            row[C_DIFFERENCE] = F(u64::from(self.c_difference[slot]));
            write_bits_v1(
                &mut row[A_DIFFERENCE_BITS..A_DIFFERENCE_BITS + LIMB_BITS],
                self.a_difference[slot],
            );
            write_bits_v1(
                &mut row[B_DIFFERENCE_BITS..B_DIFFERENCE_BITS + LIMB_BITS],
                self.b_difference[slot],
            );
            write_bits_v1(
                &mut row[C_DIFFERENCE_BITS..C_DIFFERENCE_BITS + LIMB_BITS],
                self.c_difference[slot],
            );
            row[A_BORROW_BEFORE] = F(u64::from(self.a_borrow[slot]));
            row[B_BORROW_BEFORE] = F(u64::from(self.b_borrow[slot]));
            row[C_BORROW_BEFORE] = F(u64::from(self.c_borrow[slot]));
            row[A_BORROW_AFTER] = F(u64::from(self.a_borrow[slot + 1]));
            row[B_BORROW_AFTER] = F(u64::from(self.b_borrow[slot + 1]));
            row[C_BORROW_AFTER] = F(u64::from(self.c_borrow[slot + 1]));
        }
        row[CARRY] = F(encoded as u64);
        for bit in 0..CARRY_BITS {
            row[CARRY_BIT_START + bit] = F(((encoded as u64) >> bit) & 1);
        }
        Ok(row)
    }
}
/// Expand a non-empty fixed operation batch into exact coefficient rows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_p256_arithmetic_trace_v1(
    operations: &[ZkX509P256ArithmeticOperationV1],
) -> Result<ZkX509P256ArithmeticTraceV1, ZkX509P256AirErrorV1> {
    if operations.is_empty() {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    let rows = operations
        .len()
        .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
        .ok_or(ZkX509P256AirErrorV1::Allocation)?;
    let mut fixed_rows = Vec::new();
    let mut base = super::private_table::PrivateTableV1::new(
        Vec::new(),
        super::private_table::zeroize_field_rows_v1,
    );
    fixed_rows
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509P256AirErrorV1::Allocation)?;
    base.try_reserve_exact(rows)
        .map_err(|_| ZkX509P256AirErrorV1::Allocation)?;
    for (operation_index, operation) in operations.iter().copied().enumerate() {
        let operation_number =
            u32::try_from(operation_index).map_err(|_| ZkX509P256AirErrorV1::Allocation)?;
        let expanded = expand_operation_v1(operation)?;
        for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
            let fixed = ZkX509P256ArithmeticFixedRowV1 {
                operation: operation_number,
                coefficient: coefficient as u8,
                kind: operation.kind,
                modulus: operation.modulus,
            };
            fixed_rows.push(fixed);
            base.push(expanded.base_row(fixed)?);
        }
    }
    let trace = ZkX509P256ArithmeticTraceV1 {
        fixed: fixed_rows,
        base: base.into_vec(),
    };
    trace.validate()?;
    Ok(trace)
}
/// Read the `a`, `b`, and `c` limbs constrained on one operation's corresponding coefficient row.
///
/// This is the narrow source-binding surface used by value-copy buses.  It
/// deliberately keeps the arithmetic column layout private.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn p256_arithmetic_operand_limbs_v1(
    trace: &ZkX509P256ArithmeticTraceV1,
    operation: usize,
    limb: usize,
) -> Result<[F; 3], ZkX509P256AirErrorV1> {
    if limb >= LIMBS {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    let row = operation
        .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
        .and_then(|row| row.checked_add(limb))
        .ok_or(ZkX509P256AirErrorV1::Allocation)?;
    let fixed = trace.fixed.get(row).ok_or(ZkX509P256AirErrorV1::Topology)?;
    let base = trace.base.get(row).ok_or(ZkX509P256AirErrorV1::Topology)?;
    if fixed.operation as usize != operation || fixed.coefficient as usize != limb {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    Ok([
        base[A_START + limb],
        base[B_START + limb],
        base[C_START + limb],
    ])
}
/// Read the committed little-endian Boolean decomposition of one `c` limb.
///
/// This is the narrow source-binding surface used by the scalar-bit copy bus. It deliberately
/// exposes the constrained bit cells without exposing their private column offsets.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn p256_arithmetic_c_limb_bits_v1(
    trace: &ZkX509P256ArithmeticTraceV1,
    operation: usize,
    limb: usize,
) -> Result<[F; LIMB_BITS], ZkX509P256AirErrorV1> {
    if limb >= LIMBS {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    let row = operation
        .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
        .and_then(|row| row.checked_add(limb))
        .ok_or(ZkX509P256AirErrorV1::Allocation)?;
    let fixed = trace.fixed.get(row).ok_or(ZkX509P256AirErrorV1::Topology)?;
    let base = trace.base.get(row).ok_or(ZkX509P256AirErrorV1::Topology)?;
    if fixed.operation as usize != operation || fixed.coefficient as usize != limb {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    Ok(core::array::from_fn(|bit| base[C_BITS + bit]))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn expand_operation_v1(
    operation: ZkX509P256ArithmeticOperationV1,
) -> Result<ExpandedOperationV1, ZkX509P256AirErrorV1> {
    let modulus_be = operation.modulus.bytes_be();
    for value in [operation.a, operation.b, operation.c] {
        if value >= modulus_be {
            return Err(ZkX509P256AirErrorV1::NonCanonicalInteger);
        }
    }
    let q_be = match operation.kind {
        ZkX509P256ArithmeticKindV1::Multiply => {
            exact_multiplication_quotient_v1(operation.a, operation.b, operation.c, modulus_be)?
        }
        ZkX509P256ArithmeticKindV1::Add => {
            exact_addition_quotient_v1(operation.a, operation.b, operation.c, modulus_be)?
        }
        ZkX509P256ArithmeticKindV1::Subtract => {
            exact_subtraction_quotient_v1(operation.a, operation.b, operation.c, modulus_be)?
        }
    };
    let a = bytes_be_to_limbs_le_v1(operation.a);
    let b = bytes_be_to_limbs_le_v1(operation.b);
    let c = bytes_be_to_limbs_le_v1(operation.c);
    let q = bytes_be_to_limbs_le_v1(q_be);
    let modulus = operation.modulus.limbs_le();
    let (a_difference, a_borrow) = less_than_witness_v1(a, modulus)?;
    let (b_difference, b_borrow) = less_than_witness_v1(b, modulus)?;
    let (c_difference, c_borrow) = less_than_witness_v1(c, modulus)?;
    let carries = arithmetic_carries_v1(operation.kind, a, b, c, q, modulus)?;
    Ok(ExpandedOperationV1 {
        a,
        b,
        c,
        q,
        a_difference,
        b_difference,
        c_difference,
        a_borrow,
        b_borrow,
        c_borrow,
        carries,
    })
}
/// Evaluate one exact coefficient row.
///
/// Every returned expression is degree at most two.  `next_base` is required
/// inside an operation and ignored on its final row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn evaluate_p256_arithmetic_row_constraints_v1(
    fixed: ZkX509P256ArithmeticFixedRowV1,
    base: &[F; P256_ARITHMETIC_BASE_WIDTH_V1],
    next_base: Option<&[F; P256_ARITHMETIC_BASE_WIDTH_V1]>,
) -> Result<Vec<F>, ZkX509P256AirErrorV1> {
    if fixed.coefficient as usize >= P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    if !fixed.is_last() && next_base.is_none() {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    let mut residues = Vec::with_capacity(180);
    let slot = fixed.range_slot();
    for (value, bits) in [
        (base[A_START + slot], A_BITS),
        (base[B_START + slot], B_BITS),
        (base[C_START + slot], C_BITS),
        (base[Q_START + slot], Q_BITS),
    ] {
        append_range_residues_v1(&mut residues, value, &base[bits..bits + LIMB_BITS]);
    }
    if fixed.has_canonicality_row() {
        for (value, difference, difference_bits, borrow_before, borrow_after) in [
            (
                base[A_START + slot],
                base[A_DIFFERENCE],
                A_DIFFERENCE_BITS,
                base[A_BORROW_BEFORE],
                base[A_BORROW_AFTER],
            ),
            (
                base[B_START + slot],
                base[B_DIFFERENCE],
                B_DIFFERENCE_BITS,
                base[B_BORROW_BEFORE],
                base[B_BORROW_AFTER],
            ),
            (
                base[C_START + slot],
                base[C_DIFFERENCE],
                C_DIFFERENCE_BITS,
                base[C_BORROW_BEFORE],
                base[C_BORROW_AFTER],
            ),
        ] {
            append_range_residues_v1(
                &mut residues,
                difference,
                &base[difference_bits..difference_bits + LIMB_BITS],
            );
            residues.push(boolean_residue_v1(borrow_before));
            residues.push(boolean_residue_v1(borrow_after));
            let modulus_limb = F(u64::from(fixed.modulus.limbs_le()[slot]));
            residues.push(
                value
                    .sub(modulus_limb)
                    .sub(borrow_before)
                    .sub(difference)
                    .add(F(RADIX as u64).mul(borrow_after)),
            );
            if slot == 0 {
                residues.push(borrow_before);
            }
            if slot + 1 == LIMBS {
                residues.push(borrow_after.sub(F::ONE));
            }
        }
        if slot + 1 < LIMBS {
            let next = next_base.ok_or(ZkX509P256AirErrorV1::Topology)?;
            residues.extend_from_slice(&[
                next[A_BORROW_BEFORE].sub(base[A_BORROW_AFTER]),
                next[B_BORROW_BEFORE].sub(base[B_BORROW_AFTER]),
                next[C_BORROW_BEFORE].sub(base[C_BORROW_AFTER]),
            ]);
        }
    } else {
        for value in &base[A_DIFFERENCE..=C_BORROW_AFTER] {
            residues.push(*value);
        }
    }
    append_range_residues_v1(
        &mut residues,
        base[CARRY],
        &base[CARRY_BIT_START..CARRY_BIT_START + CARRY_BITS],
    );
    let carry = base[CARRY].sub(F(CARRY_BIAS as u64));
    if fixed.is_first() {
        residues.push(carry);
    }
    let next_carry = if fixed.is_last() {
        F::ZERO
    } else {
        next_base.ok_or(ZkX509P256AirErrorV1::Topology)?[CARRY].sub(F(CARRY_BIAS as u64))
    };
    if !fixed.is_last() {
        let next = next_base.ok_or(ZkX509P256AirErrorV1::Topology)?;
        for column in A_START..Q_START + LIMBS {
            residues.push(next[column].sub(base[column]));
        }
    }
    if matches!(
        fixed.kind,
        ZkX509P256ArithmeticKindV1::Add | ZkX509P256ArithmeticKindV1::Subtract
    ) {
        residues.push(boolean_residue_v1(base[Q_START]));
        for quotient_limb in &base[Q_START + 1..Q_START + LIMBS] {
            residues.push(*quotient_limb);
        }
    }
    let coefficient = usize::from(fixed.coefficient);
    let modulus = fixed.modulus.limbs_le();
    let relation = match fixed.kind {
        ZkX509P256ArithmeticKindV1::Multiply => {
            let mut value = carry;
            for left in 0..LIMBS {
                let Some(right) = coefficient.checked_sub(left) else {
                    continue;
                };
                if right < LIMBS {
                    value = value.add(base[A_START + left].mul(base[B_START + right]));
                    value = value.sub(base[Q_START + left].mul(F(u64::from(modulus[right]))));
                }
            }
            if coefficient < LIMBS {
                value = value.sub(base[C_START + coefficient]);
            }
            value.sub(F(RADIX as u64).mul(next_carry))
        }
        ZkX509P256ArithmeticKindV1::Add => {
            let mut value = carry;
            if coefficient < LIMBS {
                value = value
                    .add(base[A_START + coefficient])
                    .add(base[B_START + coefficient])
                    .sub(base[C_START + coefficient])
                    .sub(base[Q_START].mul(F(u64::from(modulus[coefficient]))));
            }
            value.sub(F(RADIX as u64).mul(next_carry))
        }
        ZkX509P256ArithmeticKindV1::Subtract => {
            let mut value = carry;
            if coefficient < LIMBS {
                value = value
                    .add(base[A_START + coefficient])
                    .sub(base[B_START + coefficient])
                    .sub(base[C_START + coefficient])
                    .add(base[Q_START].mul(F(u64::from(modulus[coefficient]))));
            }
            value.sub(F(RADIX as u64).mul(next_carry))
        }
    };
    residues.push(relation);
    Ok(residues)
}
/// Compile the exact numeric preprocessing rows used by the aggregate STARK.
///
/// `operations` must come from the deterministic ECDSA topology compiler, not from proof bytes or a
/// witness trace. The suffix through `trace_size` is the sole canonical padding schedule.
#[cfg(test)]
pub(crate) fn compile_p256_arithmetic_stark_fixed_rows_v1(
    operations: &[ZkX509P256ArithmeticTopologyV1],
    trace_size: usize,
) -> Result<Vec<[F; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1]>, ZkX509P256AirErrorV1> {
    let provider = P256ArithmeticStarkFixedProviderV1::new_v1(operations, trace_size)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(trace_size)
        .map_err(|_| ZkX509P256AirErrorV1::Allocation)?;
    for index in 0..trace_size {
        rows.push(provider.row_v1(index)?);
    }
    Ok(rows)
}
fn stark_selected_limb_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    limb_start: usize,
    fixed: &[A; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1],
    selector_start: usize,
) -> A {
    (0..LIMBS).fold(A::ZERO, |sum, limb| {
        sum.add(base[limb_start + limb].mul(fixed[selector_start + limb]))
    })
}
fn push_stark_range_residues_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    selected: A,
    bits: &[A],
) -> Result<(), ZkX509P256AirErrorV1> {
    if bits.is_empty() || bits.len() >= u64::BITS as usize {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    let mut packed = A::ZERO;
    for (index, bit) in bits.iter().copied().enumerate() {
        residues.push(boolean_residue_v1(bit));
        packed = packed.add(bit.mul_base(F(1_u64 << index)));
    }
    residues.push(selected.sub(packed));
    Ok(())
}
/// Evaluate one P-256 arithmetic row as a fixed-width polynomial vector.
///
/// Unlike the native `evaluate_p256_arithmetic_row_constraints_v1` reference evaluator, this
/// function never branches on a native enum or row number. Kind, coefficient, modulus, range slot,
/// and boundary selectors are verifier-preprocessed polynomial openings. Consequently the same
/// degree-four expressions are valid on the aggregate extension domain.
#[cfg(test)]
pub(crate) fn evaluate_p256_arithmetic_stark_residues_v1(
    current: &[F; P256_ARITHMETIC_BASE_WIDTH_V1],
    next: &[F; P256_ARITHMETIC_BASE_WIDTH_V1],
    current_aux: &[F; P256_ARITHMETIC_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_ARITHMETIC_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<F>, ZkX509P256AirErrorV1> {
    evaluate_p256_arithmetic_stark_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
    )
}
/// Exact same integer-arithmetic polynomial relation over F or Fp4.
pub(crate) fn evaluate_p256_arithmetic_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    next: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    current_aux: &[A; P256_ARITHMETIC_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_ARITHMETIC_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<A>, ZkX509P256AirErrorV1> {
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509P256AirErrorV1::Constraint);
    }
    let mut residues = Vec::with_capacity(P256_ARITHMETIC_STARK_CONSTRAINT_COUNT_V1);
    for (limb_start, bits_start) in [
        (A_START, A_BITS),
        (B_START, B_BITS),
        (C_START, C_BITS),
        (Q_START, Q_BITS),
    ] {
        let selected = stark_selected_limb_v1(current, limb_start, fixed, STARK_RANGE_SLOT_START);
        push_stark_range_residues_v1(
            &mut residues,
            selected,
            &current[bits_start..bits_start + LIMB_BITS],
        )?;
    }
    let canonicality = fixed[STARK_CANONICALITY_ROW];
    let noncanonicality = A::ONE.sub(canonicality);
    let range_slot_first = fixed[STARK_SLOT_FIRST];
    let range_slot_last = fixed[STARK_SLOT_LAST];
    let modulus_limb = (0..LIMBS).fold(A::ZERO, |sum, limb| {
        sum.add(fixed[STARK_RANGE_SLOT_START + limb].mul(fixed[STARK_MODULUS_LIMBS_START + limb]))
    });
    for (
        limb_start,
        difference,
        difference_bits,
        borrow_before,
        borrow_after,
        next_borrow_before,
    ) in [
        (
            A_START,
            A_DIFFERENCE,
            A_DIFFERENCE_BITS,
            A_BORROW_BEFORE,
            A_BORROW_AFTER,
            A_BORROW_BEFORE,
        ),
        (
            B_START,
            B_DIFFERENCE,
            B_DIFFERENCE_BITS,
            B_BORROW_BEFORE,
            B_BORROW_AFTER,
            B_BORROW_BEFORE,
        ),
        (
            C_START,
            C_DIFFERENCE,
            C_DIFFERENCE_BITS,
            C_BORROW_BEFORE,
            C_BORROW_AFTER,
            C_BORROW_BEFORE,
        ),
    ] {
        push_stark_range_residues_v1(
            &mut residues,
            current[difference],
            &current[difference_bits..difference_bits + LIMB_BITS],
        )?;
        residues.push(boolean_residue_v1(current[borrow_before]));
        residues.push(boolean_residue_v1(current[borrow_after]));
        let value = stark_selected_limb_v1(current, limb_start, fixed, STARK_RANGE_SLOT_START);
        residues.push(
            canonicality.mul(
                value
                    .sub(modulus_limb)
                    .sub(current[borrow_before])
                    .sub(current[difference])
                    .add(A::from_base(F(RADIX as u64)).mul(current[borrow_after])),
            ),
        );
        residues.push(
            canonicality
                .mul(range_slot_first)
                .mul(current[borrow_before]),
        );
        residues.push(
            canonicality
                .mul(range_slot_last)
                .mul(current[borrow_after].sub(A::ONE)),
        );
        residues.push(
            canonicality
                .mul(A::ONE.sub(range_slot_last))
                .mul(next[next_borrow_before].sub(current[borrow_after])),
        );
    }
    for value in &current[A_DIFFERENCE..=C_BORROW_AFTER] {
        residues.push(noncanonicality.mul(*value));
    }
    push_stark_range_residues_v1(
        &mut residues,
        current[CARRY],
        &current[CARRY_BIT_START..CARRY_BIT_START + CARRY_BITS],
    )?;
    let carry = current[CARRY].sub(A::from_base(F(CARRY_BIAS as u64)));
    residues.push(fixed[STARK_OPERATION_FIRST].mul(carry));
    let multiply = fixed[STARK_KIND_MULTIPLY];
    let add = fixed[STARK_KIND_ADD];
    let subtract = fixed[STARK_KIND_SUBTRACT];
    let active = multiply.add(add).add(subtract);
    let operation_not_last = A::ONE.sub(fixed[STARK_OPERATION_LAST]);
    let active_not_last = active.mul(operation_not_last);
    for column in A_START..Q_START + LIMBS {
        residues.push(active_not_last.mul(next[column].sub(current[column])));
    }
    let add_or_subtract = add.add(subtract);
    residues.push(add_or_subtract.mul(current[Q_START].mul(current[Q_START].sub(A::ONE))));
    for quotient_limb in &current[Q_START + 1..Q_START + LIMBS] {
        residues.push(add_or_subtract.mul(*quotient_limb));
    }
    let next_carry = operation_not_last.mul(next[CARRY].sub(A::from_base(F(CARRY_BIAS as u64))));
    let mut multiplication_relation = carry.sub(A::from_base(F(RADIX as u64)).mul(next_carry));
    for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
        let selector = fixed[STARK_COEFFICIENT_START + coefficient];
        let mut coefficient_relation = A::ZERO;
        for left in 0..LIMBS {
            let Some(right) = coefficient.checked_sub(left) else {
                continue;
            };
            if right < LIMBS {
                coefficient_relation = coefficient_relation
                    .add(current[A_START + left].mul(current[B_START + right]))
                    .sub(current[Q_START + left].mul(fixed[STARK_MODULUS_LIMBS_START + right]));
            }
        }
        if coefficient < LIMBS {
            coefficient_relation = coefficient_relation.sub(current[C_START + coefficient]);
        }
        multiplication_relation = multiplication_relation.add(selector.mul(coefficient_relation));
    }
    let low_a = stark_selected_limb_v1(current, A_START, fixed, STARK_LOW_SLOT_START);
    let low_b = stark_selected_limb_v1(current, B_START, fixed, STARK_LOW_SLOT_START);
    let low_c = stark_selected_limb_v1(current, C_START, fixed, STARK_LOW_SLOT_START);
    let quotient_modulus = current[Q_START].mul(fixed[STARK_LOW_MODULUS_LIMB]);
    let addition_relation = carry
        .add(low_a)
        .add(low_b)
        .sub(low_c)
        .sub(quotient_modulus)
        .sub(A::from_base(F(RADIX as u64)).mul(next_carry));
    let subtraction_relation = carry
        .add(low_a)
        .sub(low_b)
        .sub(low_c)
        .add(quotient_modulus)
        .sub(A::from_base(F(RADIX as u64)).mul(next_carry));
    residues.push(
        multiply
            .mul(multiplication_relation)
            .add(add.mul(addition_relation))
            .add(subtract.mul(subtraction_relation)),
    );
    let padding = fixed[STARK_PADDING];
    for value in &current[A_START..Q_START + LIMBS] {
        residues.push(padding.mul(*value));
    }
    residues.push(padding.mul(current[CARRY]));
    residues.push(current_aux[0]);
    if residues.len() != P256_ARITHMETIC_STARK_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509P256AirErrorV1::Topology);
    }
    Ok(residues)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn append_range_residues_v1(residues: &mut Vec<F>, value: F, bits: &[F]) {
    let mut packed = F::ZERO;
    for (index, bit) in bits.iter().copied().enumerate() {
        residues.push(boolean_residue_v1(bit));
        packed = packed.add(bit.mul(F(1_u64 << index)));
    }
    residues.push(value.sub(packed));
}
fn boolean_residue_v1<A: PolynomialAirFieldV1>(value: A) -> A {
    value.mul(value.sub(A::ONE))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn arithmetic_carries_v1(
    kind: ZkX509P256ArithmeticKindV1,
    a: [u16; LIMBS],
    b: [u16; LIMBS],
    c: [u16; LIMBS],
    q: [u16; LIMBS],
    modulus: [u16; LIMBS],
) -> Result<[i64; P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + 1], ZkX509P256AirErrorV1> {
    let mut carries = [0_i64; P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + 1];
    for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
        let mut value = i128::from(carries[coefficient]);
        match kind {
            ZkX509P256ArithmeticKindV1::Multiply => {
                for left in 0..LIMBS {
                    let Some(right) = coefficient.checked_sub(left) else {
                        continue;
                    };
                    if right < LIMBS {
                        value += i128::from(a[left]) * i128::from(b[right]);
                        value -= i128::from(q[left]) * i128::from(modulus[right]);
                    }
                }
                if coefficient < LIMBS {
                    value -= i128::from(c[coefficient]);
                }
            }
            ZkX509P256ArithmeticKindV1::Add => {
                if coefficient < LIMBS {
                    value += i128::from(a[coefficient]) + i128::from(b[coefficient]);
                    value -= i128::from(c[coefficient]);
                    value -= i128::from(q[0]) * i128::from(modulus[coefficient]);
                }
            }
            ZkX509P256ArithmeticKindV1::Subtract => {
                if coefficient < LIMBS {
                    value += i128::from(a[coefficient]);
                    value -= i128::from(b[coefficient]) + i128::from(c[coefficient]);
                    value += i128::from(q[0]) * i128::from(modulus[coefficient]);
                }
            }
        }
        if value % i128::from(RADIX) != 0 {
            return Err(ZkX509P256AirErrorV1::InvalidOperation);
        }
        let next = value / i128::from(RADIX);
        let next = i64::try_from(next).map_err(|_| ZkX509P256AirErrorV1::CarryRange)?;
        if next.unsigned_abs() >= CARRY_ABSOLUTE_BOUND as u64 {
            return Err(ZkX509P256AirErrorV1::CarryRange);
        }
        carries[coefficient + 1] = next;
    }
    if carries[P256_ARITHMETIC_ROWS_PER_OPERATION_V1] != 0 {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    }
    Ok(carries)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn less_than_witness_v1(
    value: [u16; LIMBS],
    modulus: [u16; LIMBS],
) -> Result<([u16; LIMBS], [u8; LIMBS + 1]), ZkX509P256AirErrorV1> {
    let mut difference = [0_u16; LIMBS];
    let mut borrow = [0_u8; LIMBS + 1];
    for index in 0..LIMBS {
        let raw = i32::from(value[index]) - i32::from(modulus[index]) - i32::from(borrow[index]);
        if raw < 0 {
            difference[index] = (raw + RADIX as i32) as u16;
            borrow[index + 1] = 1;
        } else {
            difference[index] = raw as u16;
        }
    }
    if borrow[LIMBS] != 1 {
        return Err(ZkX509P256AirErrorV1::NonCanonicalInteger);
    }
    Ok((difference, borrow))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn exact_multiplication_quotient_v1(
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
    modulus: [u8; 32],
) -> Result<[u8; 32], ZkX509P256AirErrorV1> {
    let product: U512 = U256::from_be_slice(&a).mul(&U256::from_be_slice(&b));
    let wide_modulus = U256::ZERO.concat(&U256::from_be_slice(&modulus));
    let divisor = NonZero::new(wide_modulus).unwrap();
    let (quotient, remainder) = product.div_rem(&divisor);
    let quotient = quotient.to_be_bytes();
    let remainder = remainder.to_be_bytes();
    if remainder[..32].iter().any(|byte| *byte != 0)
        || remainder[32..] != c
        || quotient[..32].iter().any(|byte| *byte != 0)
    {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    }
    let mut result = [0_u8; 32];
    result.copy_from_slice(&quotient[32..]);
    Ok(result)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn exact_addition_quotient_v1(
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
    modulus: [u8; 32],
) -> Result<[u8; 32], ZkX509P256AirErrorV1> {
    let sum = add_be_v1(a, b);
    let c = widen_be_v1(c);
    let quotient = if sum == c {
        0
    } else if sum == add_wide_be_v1(c, widen_be_v1(modulus))? {
        1
    } else {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    };
    let mut result = [0_u8; 32];
    result[31] = quotient;
    Ok(result)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn exact_subtraction_quotient_v1(
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
    modulus: [u8; 32],
) -> Result<[u8; 32], ZkX509P256AirErrorV1> {
    let (difference, quotient) = if a >= b {
        (subtract_wide_be_v1(widen_be_v1(a), widen_be_v1(b))?, 0)
    } else {
        let lifted = add_wide_be_v1(widen_be_v1(a), widen_be_v1(modulus))?;
        (subtract_wide_be_v1(lifted, widen_be_v1(b))?, 1)
    };
    if difference[0] != 0 || difference[1..] != c {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    }
    let mut result = [0_u8; 32];
    result[31] = quotient;
    Ok(result)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn widen_be_v1(value: [u8; 32]) -> [u8; 33] {
    let mut wide = [0_u8; 33];
    wide[1..].copy_from_slice(&value);
    wide
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn add_be_v1(left: [u8; 32], right: [u8; 32]) -> [u8; 33] {
    let mut result = [0_u8; 33];
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let value = u16::from(left[index]) + u16::from(right[index]) + carry;
        result[index + 1] = value as u8;
        carry = value >> 8;
    }
    result[0] = carry as u8;
    result
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn add_wide_be_v1(left: [u8; 33], right: [u8; 33]) -> Result<[u8; 33], ZkX509P256AirErrorV1> {
    let mut result = [0_u8; 33];
    let mut carry = 0_u16;
    for index in (0..33).rev() {
        let value = u16::from(left[index]) + u16::from(right[index]) + carry;
        result[index] = value as u8;
        carry = value >> 8;
    }
    if carry != 0 {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    }
    Ok(result)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn subtract_wide_be_v1(left: [u8; 33], right: [u8; 33]) -> Result<[u8; 33], ZkX509P256AirErrorV1> {
    if left < right {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    }
    let mut result = [0_u8; 33];
    let mut borrow = 0_i16;
    for index in (0..33).rev() {
        let value = i16::from(left[index]) - i16::from(right[index]) - borrow;
        if value < 0 {
            result[index] = (value + 256) as u8;
            borrow = 1;
        } else {
            result[index] = value as u8;
            borrow = 0;
        }
    }
    if borrow != 0 {
        return Err(ZkX509P256AirErrorV1::InvalidOperation);
    }
    Ok(result)
}
fn bytes_be_to_limbs_le_v1(bytes: [u8; 32]) -> [u16; LIMBS] {
    core::array::from_fn(|index| {
        let low = 31 - 2 * index;
        u16::from_le_bytes([bytes[low], bytes[low - 1]])
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_limbs_v1(target: &mut [F], limbs: &[u16; LIMBS]) {
    for (target, limb) in target.iter_mut().zip(limbs.iter().copied()) {
        *target = F(u64::from(limb));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_bits_v1(target: &mut [F], value: u16) {
    for (bit, target) in target.iter_mut().enumerate() {
        *target = F(u64::from((value >> bit) & 1));
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_arithmetic_erasure_covers_success_partial_error_and_unwind() {
        use super::super::private_table::{PrivateTableV1, inspection::observe_v1};
        let mut operations = boundary_operations();
        let valid = operations[0];
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&[valid]).unwrap();
        assert_eq!(
            format!("{trace:?}"),
            "ZkX509P256ArithmeticTraceV1 { <private trace redacted> }"
        );
        let cells = trace.base.len() * P256_ARITHMETIC_BASE_WIDTH_V1;
        let (_, observed) = observe_v1(|| drop(trace));
        assert_eq!(observed.iter().map(|item| item.cells).sum::<usize>(), cells);
        assert!(observed.iter().any(|item| item.nonzero_before > 0));
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        let mut invalid = valid;
        invalid.a = [255; 32];
        let (result, observed) =
            observe_v1(|| build_zk_x509_p256_arithmetic_trace_v1(&[valid, invalid]));
        assert!(result.is_err());
        assert!(
            observed
                .iter()
                .any(|item| item.cells == cells && item.nonzero_before > 0)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        let (result, observed) = observe_v1(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _operations = PrivateTableV1::new(
                    core::mem::take(&mut operations),
                    zeroize_p256_operations_v1,
                );
                let _trace = build_zk_x509_p256_arithmetic_trace_v1(&[valid]).unwrap();
                panic!("exercise private P256 trace unwind");
            }))
        });
        assert!(result.is_err());
        assert!(
            observed
                .iter()
                .any(|item| item.cells == 32 && item.nonzero_before > 0)
        );
        assert!(
            observed
                .iter()
                .any(|item| item.cells == cells && item.nonzero_before > 0)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    use super::*;
    use p256::{Scalar, elliptic_curve::PrimeField as _};
    fn zero() -> [u8; 32] {
        [0; 32]
    }
    fn one() -> [u8; 32] {
        let mut value = [0; 32];
        value[31] = 1;
        value
    }
    fn small(value: u64) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
    fn minus_one(mut value: [u8; 32]) -> [u8; 32] {
        for byte in value.iter_mut().rev() {
            if *byte != 0 {
                *byte -= 1;
                return value;
            }
            *byte = 0xff;
        }
        panic!("non-zero modulus")
    }
    fn subtract_small(mut value: [u8; 32], amount: u64) -> [u8; 32] {
        let mut borrow = amount;
        for byte in value.iter_mut().rev() {
            let part = (borrow & 0xff) as u8;
            let (next, underflow) = byte.overflowing_sub(part);
            *byte = next;
            borrow = (borrow >> 8) + u64::from(underflow);
            if borrow == 0 {
                break;
            }
        }
        assert_eq!(borrow, 0);
        value
    }
    fn bigint_multiply_mod(left: [u8; 32], right: [u8; 32], modulus: [u8; 32]) -> [u8; 32] {
        let product: U512 = U256::from_be_slice(&left).mul(&U256::from_be_slice(&right));
        let divisor = NonZero::new(U256::ZERO.concat(&U256::from_be_slice(&modulus))).unwrap();
        let remainder = product.div_rem(&divisor).1.to_be_bytes();
        assert!(remainder[..32].iter().all(|byte| *byte == 0));
        let mut result = [0_u8; 32];
        result.copy_from_slice(&remainder[32..]);
        result
    }
    fn bigint_add_mod(left: [u8; 32], right: [u8; 32], modulus: [u8; 32]) -> [u8; 32] {
        let sum = add_be_v1(left, right);
        let modulus = widen_be_v1(modulus);
        let reduced = if sum >= modulus {
            let mut result = [0_u8; 33];
            let mut borrow = 0_i16;
            for index in (0..33).rev() {
                let value = i16::from(sum[index]) - i16::from(modulus[index]) - borrow;
                if value < 0 {
                    result[index] = (value + 256) as u8;
                    borrow = 1;
                } else {
                    result[index] = value as u8;
                    borrow = 0;
                }
            }
            assert_eq!(borrow, 0);
            result
        } else {
            sum
        };
        assert_eq!(reduced[0], 0);
        let mut result = [0_u8; 32];
        result.copy_from_slice(&reduced[1..]);
        result
    }
    fn bigint_subtract_mod(left: [u8; 32], right: [u8; 32], modulus: [u8; 32]) -> [u8; 32] {
        let lifted = if left >= right {
            widen_be_v1(left)
        } else {
            add_wide_be_v1(widen_be_v1(left), widen_be_v1(modulus)).expect("bounded lift")
        };
        let difference =
            subtract_wide_be_v1(lifted, widen_be_v1(right)).expect("nonnegative difference");
        assert_eq!(difference[0], 0);
        let mut result = [0_u8; 32];
        result.copy_from_slice(&difference[1..]);
        result
    }
    fn boundary_operations() -> Vec<ZkX509P256ArithmeticOperationV1> {
        [
            (ZkX509P256ModulusV1::BaseField, P256_BASE_MODULUS_BE_V1),
            (ZkX509P256ModulusV1::ScalarField, P256_SCALAR_MODULUS_BE_V1),
        ]
        .into_iter()
        .flat_map(|(modulus, bytes)| {
            [
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Multiply,
                    modulus,
                    a: minus_one(bytes),
                    b: minus_one(bytes),
                    c: one(),
                },
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Add,
                    modulus,
                    a: minus_one(bytes),
                    b: one(),
                    c: zero(),
                },
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Subtract,
                    modulus,
                    a: zero(),
                    b: one(),
                    c: minus_one(bytes),
                },
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Multiply,
                    modulus,
                    a: small(0xffff_ffff),
                    b: small(0x1_0000_0001),
                    c: small(0xffff_ffff_ffff_ffff),
                },
            ]
        })
        .collect()
    }
    fn arithmetic_topology(
        operations: &[ZkX509P256ArithmeticOperationV1],
    ) -> Vec<ZkX509P256ArithmeticTopologyV1> {
        operations
            .iter()
            .map(|operation| ZkX509P256ArithmeticTopologyV1 {
                kind: operation.kind,
                modulus: operation.modulus,
            })
            .collect()
    }
    #[test]
    fn exact_base_and_scalar_arithmetic_accepts_boundary_vectors() {
        assert_eq!(
            hex::encode(P256_BASE_MODULUS_BE_V1),
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        );
        assert_eq!(
            hex::encode(P256_SCALAR_MODULUS_BE_V1),
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
        );
        let operations = boundary_operations();
        let trace =
            build_zk_x509_p256_arithmetic_trace_v1(&operations).expect("canonical arithmetic");
        assert_eq!(
            trace.rows(),
            operations.len() * P256_ARITHMETIC_ROWS_PER_OPERATION_V1
        );
        trace.validate().expect("all exact coefficient identities");
    }
    #[test]
    fn operand_limb_accessor_is_exact_and_bounds_checked() {
        let operations = boundary_operations();
        let trace =
            build_zk_x509_p256_arithmetic_trace_v1(&operations).expect("canonical arithmetic");
        let expected_a = bytes_be_to_limbs_le_v1(operations[1].a);
        let expected_b = bytes_be_to_limbs_le_v1(operations[1].b);
        let expected_c = bytes_be_to_limbs_le_v1(operations[1].c);
        let fixed = P256ArithmeticStarkFixedProviderV1::new_v1(
            &arithmetic_topology(&operations),
            trace.rows().next_power_of_two(),
        )
        .expect("numeric fixed provider");
        for limb in 0..LIMBS {
            let expected = [
                F(u64::from(expected_a[limb])),
                F(u64::from(expected_b[limb])),
                F(u64::from(expected_c[limb])),
            ];
            assert_eq!(
                p256_arithmetic_operand_limbs_v1(&trace, 1, limb),
                Ok(expected)
            );
            let row = P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + limb;
            assert_eq!(
                p256_arithmetic_opened_operand_limbs_v1(
                    &trace.base[row],
                    &fixed.row_v1(row).expect("fixed row"),
                ),
                expected,
                "direct opened projection limb {limb}",
            );
        }
        assert_eq!(
            p256_arithmetic_operand_limbs_v1(&trace, operations.len(), 0),
            Err(ZkX509P256AirErrorV1::Topology)
        );
        assert_eq!(
            p256_arithmetic_operand_limbs_v1(&trace, 0, LIMBS),
            Err(ZkX509P256AirErrorV1::Topology)
        );
    }
    #[test]
    fn c_limb_bit_accessor_reads_constrained_cells_and_checks_topology() {
        let operations = boundary_operations();
        let trace =
            build_zk_x509_p256_arithmetic_trace_v1(&operations).expect("canonical arithmetic");
        let expected_c = bytes_be_to_limbs_le_v1(operations[3].c);
        for (limb, expected) in expected_c.iter().copied().enumerate() {
            assert_eq!(
                p256_arithmetic_c_limb_bits_v1(&trace, 3, limb),
                Ok(core::array::from_fn(|bit| {
                    F(u64::from((expected >> bit) & 1))
                }))
            );
        }
        assert_eq!(
            p256_arithmetic_c_limb_bits_v1(&trace, operations.len(), 0),
            Err(ZkX509P256AirErrorV1::Topology)
        );
        assert_eq!(
            p256_arithmetic_c_limb_bits_v1(&trace, 0, LIMBS),
            Err(ZkX509P256AirErrorV1::Topology)
        );
        let mut bad_fixed = trace.clone();
        bad_fixed.fixed[3 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1].coefficient = 1;
        assert_eq!(
            p256_arithmetic_c_limb_bits_v1(&bad_fixed, 3, 0),
            Err(ZkX509P256AirErrorV1::Topology)
        );
        let mut missing_base = trace;
        missing_base
            .base
            .truncate(3 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1);
        assert_eq!(
            p256_arithmetic_c_limb_bits_v1(&missing_base, 3, 0),
            Err(ZkX509P256AirErrorV1::Topology)
        );
    }
    #[test]
    fn arithmetic_is_differential_against_rustcrypto_p256() {
        let mut operations = Vec::new();
        for index in 1_u64..=48 {
            let first_small = small(
                index
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(index as u32 % 63),
            );
            let second_small = small(
                index
                    .wrapping_mul(0xd1b5_4a32_d192_ed03)
                    .rotate_right(index as u32 % 61),
            );
            let first_base = if index % 3 == 0 {
                subtract_small(P256_BASE_MODULUS_BE_V1, index)
            } else {
                first_small
            };
            let second_base = if index % 5 == 0 {
                subtract_small(P256_BASE_MODULUS_BE_V1, index + 97)
            } else {
                second_small
            };
            for (kind, result) in [
                (
                    ZkX509P256ArithmeticKindV1::Multiply,
                    bigint_multiply_mod(first_base, second_base, P256_BASE_MODULUS_BE_V1),
                ),
                (
                    ZkX509P256ArithmeticKindV1::Add,
                    bigint_add_mod(first_base, second_base, P256_BASE_MODULUS_BE_V1),
                ),
                (
                    ZkX509P256ArithmeticKindV1::Subtract,
                    bigint_subtract_mod(first_base, second_base, P256_BASE_MODULUS_BE_V1),
                ),
            ] {
                operations.push(ZkX509P256ArithmeticOperationV1 {
                    kind,
                    modulus: ZkX509P256ModulusV1::BaseField,
                    a: first_base,
                    b: second_base,
                    c: result,
                });
            }
            let first_scalar_bytes = if index % 4 == 0 {
                subtract_small(P256_SCALAR_MODULUS_BE_V1, index)
            } else {
                first_small
            };
            let second_scalar_bytes = if index % 7 == 0 {
                subtract_small(P256_SCALAR_MODULUS_BE_V1, index + 131)
            } else {
                second_small
            };
            let first_scalar = Option::<Scalar>::from(Scalar::from_repr(first_scalar_bytes.into()))
                .expect("canonical scalar operand");
            let second_scalar =
                Option::<Scalar>::from(Scalar::from_repr(second_scalar_bytes.into()))
                    .expect("canonical scalar operand");
            for (kind, result) in [
                (
                    ZkX509P256ArithmeticKindV1::Multiply,
                    (first_scalar * second_scalar).to_bytes().into(),
                ),
                (
                    ZkX509P256ArithmeticKindV1::Add,
                    (first_scalar + second_scalar).to_bytes().into(),
                ),
                (
                    ZkX509P256ArithmeticKindV1::Subtract,
                    (first_scalar - second_scalar).to_bytes().into(),
                ),
            ] {
                operations.push(ZkX509P256ArithmeticOperationV1 {
                    kind,
                    modulus: ZkX509P256ModulusV1::ScalarField,
                    a: first_scalar_bytes,
                    b: second_scalar_bytes,
                    c: result,
                });
            }
        }
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&operations)
            .expect("RustCrypto differential vectors");
        assert_eq!(operations.len(), 288);
        trace.validate().expect("differential trace");
    }
    #[test]
    fn modular_subtraction_covers_borrow_no_borrow_equal_and_false_claims() {
        for (modulus, modulus_bytes) in [
            (ZkX509P256ModulusV1::BaseField, P256_BASE_MODULUS_BE_V1),
            (ZkX509P256ModulusV1::ScalarField, P256_SCALAR_MODULUS_BE_V1),
        ] {
            let operations = [
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Subtract,
                    modulus,
                    a: zero(),
                    b: one(),
                    c: minus_one(modulus_bytes),
                },
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Subtract,
                    modulus,
                    a: minus_one(modulus_bytes),
                    b: subtract_small(modulus_bytes, 2),
                    c: one(),
                },
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Subtract,
                    modulus,
                    a: small(17),
                    b: small(17),
                    c: zero(),
                },
                ZkX509P256ArithmeticOperationV1 {
                    kind: ZkX509P256ArithmeticKindV1::Subtract,
                    modulus,
                    a: one(),
                    b: zero(),
                    c: one(),
                },
            ];
            build_zk_x509_p256_arithmetic_trace_v1(&operations)
                .expect("subtraction boundary trace")
                .validate()
                .expect("subtraction constraints");
            let mut false_claim = operations[0];
            false_claim.c = zero();
            assert_eq!(
                build_zk_x509_p256_arithmetic_trace_v1(&[false_claim]),
                Err(ZkX509P256AirErrorV1::InvalidOperation)
            );
        }
    }
    #[test]
    fn false_noncanonical_empty_and_overwide_operations_fail_closed() {
        assert_eq!(
            build_zk_x509_p256_arithmetic_trace_v1(&[]),
            Err(ZkX509P256AirErrorV1::Topology)
        );
        let invalid_result = ZkX509P256ArithmeticOperationV1 {
            kind: ZkX509P256ArithmeticKindV1::Multiply,
            modulus: ZkX509P256ModulusV1::BaseField,
            a: small(7),
            b: small(9),
            c: small(64),
        };
        assert_eq!(
            build_zk_x509_p256_arithmetic_trace_v1(&[invalid_result]),
            Err(ZkX509P256AirErrorV1::InvalidOperation)
        );
        for modulus in [
            ZkX509P256ModulusV1::BaseField,
            ZkX509P256ModulusV1::ScalarField,
        ] {
            let mut invalid = ZkX509P256ArithmeticOperationV1 {
                kind: ZkX509P256ArithmeticKindV1::Add,
                modulus,
                a: zero(),
                b: zero(),
                c: zero(),
            };
            invalid.a = modulus.bytes_be();
            assert_eq!(
                build_zk_x509_p256_arithmetic_trace_v1(&[invalid]),
                Err(ZkX509P256AirErrorV1::NonCanonicalInteger)
            );
            invalid.a = zero();
            invalid.c = modulus.bytes_be();
            assert_eq!(
                build_zk_x509_p256_arithmetic_trace_v1(&[invalid]),
                Err(ZkX509P256AirErrorV1::NonCanonicalInteger)
            );
        }
    }
    #[test]
    fn every_committed_base_cell_is_constraint_relevant() {
        let operations = boundary_operations();
        for operation in &operations[..3] {
            let trace = build_zk_x509_p256_arithmetic_trace_v1(&[*operation])
                .expect("canonical arithmetic");
            for row in 0..trace.base.len() {
                for column in 0..P256_ARITHMETIC_BASE_WIDTH_V1 {
                    let mut changed = trace.clone();
                    changed.base[row][column] = changed.base[row][column].add(F::ONE);
                    assert!(
                        changed.validate().is_err(),
                        "{:?} mutation survived at row {row}, column {column}",
                        operation.kind
                    );
                }
            }
        }
    }
    #[test]
    fn fixed_topology_kind_and_modulus_are_not_prover_selectable() {
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&[boundary_operations()[0]])
            .expect("canonical arithmetic");
        for row in 0..trace.fixed.len() {
            let mut changed = trace.clone();
            changed.fixed[row].coefficient ^= 1;
            assert!(changed.validate().is_err(), "coefficient row {row}");
            let mut changed = trace.clone();
            changed.fixed[row].operation ^= 1;
            assert!(changed.validate().is_err(), "operation row {row}");
            let mut changed = trace.clone();
            changed.fixed[row].kind = ZkX509P256ArithmeticKindV1::Add;
            assert!(changed.validate().is_err(), "kind row {row}");
            let mut changed = trace.clone();
            changed.fixed[row].modulus = ZkX509P256ModulusV1::ScalarField;
            assert!(changed.validate().is_err(), "modulus row {row}");
        }
    }
    #[test]
    fn coordinated_quotient_carry_and_comparison_attacks_fail() {
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&[boundary_operations()[0]])
            .expect("canonical arithmetic");
        let mut quotient = trace.clone();
        for row in &mut quotient.base {
            row[Q_START] = row[Q_START].add(F::ONE);
            let value = row[Q_START].value() as u16;
            write_bits_v1(&mut row[Q_BITS..Q_BITS + LIMB_BITS], value);
        }
        assert!(quotient.validate().is_err());
        let mut carry = trace.clone();
        for row in &mut carry.base {
            let encoded = (CARRY_BIAS + 1) as u64;
            row[CARRY] = F(encoded);
            for bit in 0..CARRY_BITS {
                row[CARRY_BIT_START + bit] = F((encoded >> bit) & 1);
            }
        }
        assert!(carry.validate().is_err());
        let mut comparison = trace;
        comparison.base[0][A_BORROW_AFTER] = comparison.base[0][A_BORROW_AFTER].sub(F::ONE);
        comparison.base[1][A_BORROW_BEFORE] = comparison.base[1][A_BORROW_BEFORE].sub(F::ONE);
        assert!(comparison.validate().is_err());
    }
    fn validate_numeric_stark_trace(
        trace: &ZkX509P256ArithmeticTraceV1,
        topology: &[ZkX509P256ArithmeticTopologyV1],
        trace_size: usize,
    ) -> Result<(), ZkX509P256AirErrorV1> {
        let fixed = compile_p256_arithmetic_stark_fixed_rows_v1(topology, trace_size)?;
        let mut base = trace.base.clone();
        base.resize(trace_size, [F::ZERO; P256_ARITHMETIC_BASE_WIDTH_V1]);
        let aux = vec![[F::ZERO; P256_ARITHMETIC_STARK_AUX_WIDTH_V1]; trace_size];
        for row in 0..trace_size {
            let next = (row + 1) % trace_size;
            let residues = evaluate_p256_arithmetic_stark_residues_v1(
                &base[row],
                &base[next],
                &aux[row],
                &aux[next],
                &fixed[row],
            )?;
            if residues.len() != P256_ARITHMETIC_STARK_CONSTRAINT_COUNT_V1
                || residues.iter().any(|residue| *residue != F::ZERO)
            {
                return Err(ZkX509P256AirErrorV1::Constraint);
            }
        }
        Ok(())
    }
    #[test]
    fn numeric_fixed_evaluator_matches_every_arithmetic_row_and_padding() {
        let operations = boundary_operations();
        let topology = arithmetic_topology(&operations);
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&operations)
            .expect("canonical boundary arithmetic");
        let trace_size = (trace.base.len() + 1).next_power_of_two();
        assert!(trace_size > trace.base.len());
        validate_numeric_stark_trace(&trace, &topology, trace_size)
            .expect("numeric fixed evaluator accepts the canonical trace");
    }
    #[test]
    fn numeric_fixed_compiler_rejects_topology_substitution_and_bad_padding_shape() {
        let operations = boundary_operations()[..3].to_vec();
        let trace =
            build_zk_x509_p256_arithmetic_trace_v1(&operations).expect("canonical arithmetic");
        let topology = arithmetic_topology(&operations);
        let trace_size = trace.base.len().next_power_of_two();
        assert!(compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size).is_ok());
        let mut omitted = topology.clone();
        omitted.pop();
        assert_ne!(
            compile_p256_arithmetic_stark_fixed_rows_v1(&omitted, trace_size)
                .expect("internally valid shorter topology"),
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size)
                .expect("canonical topology"),
        );
        let mut reordered = topology.clone();
        reordered.swap(0, 1);
        assert_ne!(
            compile_p256_arithmetic_stark_fixed_rows_v1(&reordered, trace_size)
                .expect("internally valid reordered topology"),
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size)
                .expect("canonical topology"),
        );
        let mut substituted = topology.clone();
        substituted[0].kind = ZkX509P256ArithmeticKindV1::Subtract;
        substituted[1].modulus = ZkX509P256ModulusV1::ScalarField;
        assert_ne!(
            compile_p256_arithmetic_stark_fixed_rows_v1(&substituted, trace_size)
                .expect("internally valid substituted topology"),
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size)
                .expect("canonical topology"),
        );
        assert_eq!(
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace.base.len() - 1),
            Err(ZkX509P256AirErrorV1::Topology)
        );
        assert_eq!(
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size + 1),
            Err(ZkX509P256AirErrorV1::Topology)
        );
    }
    #[test]
    fn numeric_fixed_compiler_is_independent_of_private_operand_bytes() {
        let operations = boundary_operations();
        let topology = arithmetic_topology(&operations);
        let mut different_private_values = operations.clone();
        for (index, operation) in different_private_values.iter_mut().enumerate() {
            operation.a = [index as u8; 32];
            operation.b = [index.wrapping_mul(17) as u8; 32];
            operation.c = [index.wrapping_mul(31) as u8; 32];
        }
        let changed_topology = arithmetic_topology(&different_private_values);
        assert_eq!(topology, changed_topology);
        let trace_size =
            (operations.len() * P256_ARITHMETIC_ROWS_PER_OPERATION_V1).next_power_of_two();
        assert_eq!(
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size),
            compile_p256_arithmetic_stark_fixed_rows_v1(&changed_topology, trace_size),
        );
    }
    #[test]
    fn numeric_evaluator_binds_every_active_and_padding_base_column() {
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&boundary_operations()[..3])
            .expect("multiply, add, and subtract trace");
        let trace_size = trace.base.len().next_power_of_two();
        let topology = arithmetic_topology(&boundary_operations()[..3]);
        let fixed =
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size).expect("fixed rows");
        let mut base = trace.base.clone();
        base.resize(trace_size, [F::ZERO; P256_ARITHMETIC_BASE_WIDTH_V1]);
        let aux = vec![[F::ZERO; P256_ARITHMETIC_STARK_AUX_WIDTH_V1]; trace_size];
        let rejects = |base: &[[F; P256_ARITHMETIC_BASE_WIDTH_V1]]| {
            (0..trace_size).any(|row| {
                let next = (row + 1) % trace_size;
                match evaluate_p256_arithmetic_stark_residues_v1(
                    &base[row],
                    &base[next],
                    &aux[row],
                    &aux[next],
                    &fixed[row],
                ) {
                    Ok(residues) => residues.iter().any(|residue| *residue != F::ZERO),
                    Err(_) => true,
                }
            })
        };
        for column in 0..P256_ARITHMETIC_BASE_WIDTH_V1 {
            let mut changed = base.clone();
            changed[7][column] = changed[7][column].add(F::ONE);
            assert!(rejects(&changed), "unbound active column {column}");
            let mut changed = base.clone();
            changed[trace.base.len()][column] = changed[trace.base.len()][column].add(F::ONE);
            assert!(rejects(&changed), "unbound padding column {column}");
        }
    }
    #[test]
    fn numeric_evaluator_rejects_auxiliary_and_noncanonical_fields() {
        let trace = build_zk_x509_p256_arithmetic_trace_v1(&boundary_operations()[..1])
            .expect("canonical arithmetic");
        let trace_size = trace.base.len().next_power_of_two();
        let topology = arithmetic_topology(&boundary_operations()[..1]);
        let fixed =
            compile_p256_arithmetic_stark_fixed_rows_v1(&topology, trace_size).expect("fixed rows");
        let mut base = trace.base.clone();
        base.resize(trace_size, [F::ZERO; P256_ARITHMETIC_BASE_WIDTH_V1]);
        let zero_aux = [F::ZERO; P256_ARITHMETIC_STARK_AUX_WIDTH_V1];
        let mut bad_aux = zero_aux;
        bad_aux[0] = F::ONE;
        let residues = evaluate_p256_arithmetic_stark_residues_v1(
            &base[0], &base[1], &bad_aux, &zero_aux, &fixed[0],
        )
        .expect("canonical nonzero auxiliary field");
        assert!(residues.iter().any(|residue| *residue != F::ZERO));
        let mut noncanonical = base[0];
        noncanonical[0] = F(u64::MAX);
        assert_eq!(
            evaluate_p256_arithmetic_stark_residues_v1(
                &noncanonical,
                &base[1],
                &zero_aux,
                &zero_aux,
                &fixed[0],
            ),
            Err(ZkX509P256AirErrorV1::Constraint)
        );
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "p256_compact_arithmetic.rs"]
pub(super) mod compact_arithmetic;
