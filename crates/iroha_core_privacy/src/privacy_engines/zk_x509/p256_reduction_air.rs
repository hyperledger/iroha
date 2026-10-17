//! Exact one-subtraction reduction from a 256-bit word into the P-256 scalar field.
//!
//! SHA-256 digests and affine P-256 x-coordinates are 256-bit integers, while
//! ECDSA arithmetic is modulo the slightly smaller P-256 group order. Since
//! every admitted word is below `2^256 < 2n`, canonical reduction needs
//! exactly one Boolean quotient:
//!
//! `word = reduced + q*n`, where `q ∈ {0,1}` and `0 <= reduced < n`.
//!
//! All word, result, comparison-difference, carry, borrow, and quotient cells
//! are range constrained. The production value/byte buses bind `word` and
//! `reduced` to SHA/P-256 inputs and scalar-arithmetic values respectively.
use super::p256_air::P256_SCALAR_MODULUS_BE_V1;
use crate::privacy_engines::transparent_stark::{GoldilocksFieldV1 as F, PolynomialAirFieldV1};
use thiserror::Error;
/// Stable descriptor for 256-bit-to-scalar canonical reduction.
#[cfg(test)]
pub const ZK_X509_P256_REDUCTION_AIR_DESCRIPTOR_V1: &[u8] = b"zk-x509-p256-reduction-air-v2-incompatible:input-u256:output-canonical-scalar:16xu16-little-endian:word=reduced+boolean-q-times-order:2pow256-less-than-2n:carry-and-borrow-boolean:all-word-result-difference-limbs-bit-ranged:wallet-low-s-strict-less-than-floor-order-half-plus1:fixed-16-row-topologies:reduction-numeric-fixed36-aux1-constraints122-degree4:low-s-numeric-fixed36-aux1-constraints77-degree3:verifier-preprocessed-one-hot-limb-selectors-and-all-limb-constants:fixed-schedule-derived-only-from-protocol-limb-count-and-native-domain:no-witness-fixed-input:first-last-boundaries:canonical-zero-padding:no-native-row-branch-on-lde:io-and-value-bus-binding=complete-via-p256-aggregate-adapter:standalone-activation=not-applicable";
/// Exact row count for one reduction.
pub const P256_REDUCTION_ROWS_V1: usize = 16;
/// Committed base width for one reduction row.
pub const P256_REDUCTION_BASE_WIDTH_V1: usize = 56;
/// Inclusive low-s ceiling `floor(n/2)`.
#[cfg(test)]
pub const P256_LOW_S_MAXIMUM_BE_V1: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];
/// Exclusive bound used to prove wallet-signature low-s canonicality.
pub const P256_LOW_S_EXCLUSIVE_BOUND_BE_V1: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa9,
];
/// Committed base width for one low-s comparison row.
pub const P256_LOW_S_BASE_WIDTH_V1: usize = 36;
/// Challenge-dependent aggregate width for one reduction trace.
///
/// Reduction has no lookup product. The sole column is committed after the
/// transcript challenges and constrained to zero so it cannot carry an
/// unbound witness while the aggregate proof retains a uniform aux shape.
pub const P256_REDUCTION_STARK_AUX_WIDTH_V1: usize = 1;
/// Verifier-preprocessed width for one reduction opening.
pub const P256_REDUCTION_STARK_FIXED_WIDTH_V1: usize = 36;
/// Exact residue count for one reduction opening.
pub const P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1: usize = 122;
/// Maximum total degree in committed and verifier-preprocessed reduction columns.
pub const P256_REDUCTION_STARK_CONSTRAINT_DEGREE_V1: u8 = 4;
/// Challenge-dependent aggregate width for one wallet low-S trace.
///
/// The sole column is constrained to zero for the same uniform aggregate
/// commitment shape used by reduction.
pub const P256_LOW_S_STARK_AUX_WIDTH_V1: usize = 1;
/// Verifier-preprocessed width for one wallet low-S opening.
pub const P256_LOW_S_STARK_FIXED_WIDTH_V1: usize = 36;
/// Exact residue count for one wallet low-S opening.
pub const P256_LOW_S_STARK_CONSTRAINT_COUNT_V1: usize = 77;
/// Maximum total degree in committed and verifier-preprocessed wallet low-S columns.
pub const P256_LOW_S_STARK_CONSTRAINT_DEGREE_V1: u8 = 3;
const LIMBS: usize = 16;
const LIMB_BITS: usize = 16;
const RADIX: u64 = 1 << LIMB_BITS;
const WORD: usize = 0;
const REDUCED: usize = 1;
const QUOTIENT: usize = 2;
const CARRY_BEFORE: usize = 3;
const CARRY_AFTER: usize = 4;
const WORD_BITS: usize = 5;
const REDUCED_BITS: usize = WORD_BITS + LIMB_BITS;
const DIFFERENCE: usize = REDUCED_BITS + LIMB_BITS;
const DIFFERENCE_BITS: usize = DIFFERENCE + 1;
const BORROW_BEFORE: usize = DIFFERENCE_BITS + LIMB_BITS;
const BORROW_AFTER: usize = BORROW_BEFORE + 1;
const LOW_S_VALUE: usize = 0;
const LOW_S_DIFFERENCE: usize = 1;
const LOW_S_VALUE_BITS: usize = 2;
const LOW_S_DIFFERENCE_BITS: usize = LOW_S_VALUE_BITS + LIMB_BITS;
const LOW_S_BORROW_BEFORE: usize = LOW_S_DIFFERENCE_BITS + LIMB_BITS;
const LOW_S_BORROW_AFTER: usize = LOW_S_BORROW_BEFORE + 1;
const STARK_LIMB_SELECTOR_START: usize = 0;
const STARK_LIMB_CONSTANT_START: usize = STARK_LIMB_SELECTOR_START + LIMBS;
const STARK_FIRST: usize = STARK_LIMB_CONSTANT_START + LIMBS;
const STARK_LAST: usize = STARK_FIRST + 1;
const STARK_ACTIVE: usize = STARK_LAST + 1;
const STARK_PADDING: usize = STARK_ACTIVE + 1;
const _: () = assert!(STARK_PADDING + 1 == P256_REDUCTION_STARK_FIXED_WIDTH_V1);
const _: () = assert!(P256_REDUCTION_STARK_FIXED_WIDTH_V1 == P256_LOW_S_STARK_FIXED_WIDTH_V1);
const _: () = assert!(P256_REDUCTION_STARK_CONSTRAINT_DEGREE_V1 <= 4);
const _: () = assert!(P256_LOW_S_STARK_CONSTRAINT_DEGREE_V1 <= 4);
/// Verifier-fixed limb row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ReductionFixedRowV1 {
    /// Little-endian 16-bit limb index.
    pub(crate) limb: u8,
}
/// Complete exact reduction trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256ReductionTraceV1 {
    /// Verifier-regenerated row topology.
    pub(crate) fixed: [P256ReductionFixedRowV1; P256_REDUCTION_ROWS_V1],
    /// Committed witness rows.
    pub(crate) base: [[F; P256_REDUCTION_BASE_WIDTH_V1]; P256_REDUCTION_ROWS_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ReductionTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256ReductionTraceV1 { <private trace redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ReductionTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ReductionTraceV1 {
    /// Overwrite every committed reduction row.
    pub(crate) fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.base);
    }
    /// Validate topology and every algebraic row identity.
    pub(crate) fn validate(&self) -> Result<(), P256ReductionAirErrorV1> {
        for row in 0..P256_REDUCTION_ROWS_V1 {
            if usize::from(self.fixed[row].limb) != row {
                return Err(P256ReductionAirErrorV1::Topology);
            }
            let residues = evaluate_p256_reduction_row_constraints_v1(
                self.fixed[row],
                &self.base[row],
                self.base.get(row + 1),
            )?;
            if residues.iter().any(|residue| *residue != F::ZERO) {
                return Err(P256ReductionAirErrorV1::Constraint);
            }
        }
        Ok(())
    }
    /// Canonical reduced scalar reconstructed from committed limbs.
    pub(crate) fn reduced_be_v1(&self) -> [u8; 32] {
        let limbs = core::array::from_fn(|limb| self.base[limb][REDUCED].value() as u16);
        limbs_le_to_bytes_be_v1(limbs)
    }
}
/// Read the exact input-word and reduced-result cells for one limb.
///
/// This is the narrow pointwise surface used by the aggregate value/byte
/// bindings; it does not expose or reinterpret the internal carry witness.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_reduction_limb_cells_v1(
    trace: &P256ReductionTraceV1,
    limb: usize,
) -> Result<[F; 2], P256ReductionAirErrorV1> {
    if limb >= P256_REDUCTION_ROWS_V1 || usize::from(trace.fixed[limb].limb) != limb {
        return Err(P256ReductionAirErrorV1::Topology);
    }
    Ok([trace.base[limb][WORD], trace.base[limb][REDUCED]])
}
/// Project the word and reduced-result cells from one opened LDE base row.
///
/// This is deliberately a pure column projection. Cross-source products are
/// appended to the aggregate auxiliary trace by the caller.
pub fn p256_reduction_opened_binding_cells_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_REDUCTION_BASE_WIDTH_V1],
) -> [A; 2] {
    [base[WORD], base[REDUCED]]
}
/// Reduction construction or constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum P256ReductionAirErrorV1 {
    /// Fixed rows are reordered or out of range.
    #[error("zk-X509 P-256 reduction topology is invalid")]
    Topology,
    /// A claimed reduction or canonical comparison is false.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 reduction witness is invalid")]
    InvalidWitness,
    /// A local or transition polynomial identity is nonzero.
    #[error("zk-X509 P-256 reduction constraint failed")]
    Constraint,
    /// A bounded aggregate-column allocation failed.
    #[cfg(test)]
    #[error("zk-X509 P-256 reduction aggregate allocation failed")]
    Allocation,
}
/// Exact fixed trace proving `s <= floor(n/2)`.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256LowSTraceV1 {
    /// Verifier-regenerated limb rows.
    pub(crate) fixed: [P256ReductionFixedRowV1; P256_REDUCTION_ROWS_V1],
    /// Committed low-s comparison rows.
    pub(crate) base: [[F; P256_LOW_S_BASE_WIDTH_V1]; P256_REDUCTION_ROWS_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256LowSTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256LowSTraceV1 { <private trace redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256LowSTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256LowSTraceV1 {
    /// Overwrite every committed low-s comparison row.
    pub(crate) fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.base);
    }
    /// Validate the strict comparison against `floor(n/2)+1`.
    pub(crate) fn validate(&self) -> Result<(), P256ReductionAirErrorV1> {
        for row in 0..LIMBS {
            if usize::from(self.fixed[row].limb) != row {
                return Err(P256ReductionAirErrorV1::Topology);
            }
            let residues = evaluate_p256_low_s_row_constraints_v1(
                self.fixed[row],
                &self.base[row],
                self.base.get(row + 1),
            )?;
            if residues.iter().any(|residue| *residue != F::ZERO) {
                return Err(P256ReductionAirErrorV1::Constraint);
            }
        }
        Ok(())
    }
}
/// Read the scalar cell constrained by one low-s comparison limb.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_low_s_limb_cell_v1(
    trace: &P256LowSTraceV1,
    limb: usize,
) -> Result<F, P256ReductionAirErrorV1> {
    if limb >= P256_REDUCTION_ROWS_V1 || usize::from(trace.fixed[limb].limb) != limb {
        return Err(P256ReductionAirErrorV1::Topology);
    }
    Ok(trace.base[limb][LOW_S_VALUE])
}
/// Project the wallet scalar cell from one opened low-S LDE base row.
///
/// No auxiliary or verifier-fixed opening is interpreted here.
pub fn p256_low_s_opened_binding_cell_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_LOW_S_BASE_WIDTH_V1],
) -> A {
    base[LOW_S_VALUE]
}
/// Build the exact wallet low-s comparison trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_p256_low_s_trace_v1(
    scalar_be: [u8; 32],
) -> Result<P256LowSTraceV1, P256ReductionAirErrorV1> {
    if scalar_be >= P256_LOW_S_EXCLUSIVE_BOUND_BE_V1 {
        return Err(P256ReductionAirErrorV1::InvalidWitness);
    }
    let scalar = bytes_be_to_limbs_le_v1(scalar_be);
    let bound = bytes_be_to_limbs_le_v1(P256_LOW_S_EXCLUSIVE_BOUND_BE_V1);
    let (difference, borrow) = less_than_witness_v1(scalar, bound)?;
    let fixed = core::array::from_fn(|limb| P256ReductionFixedRowV1 { limb: limb as u8 });
    let mut base = [[F::ZERO; P256_LOW_S_BASE_WIDTH_V1]; LIMBS];
    for limb in 0..LIMBS {
        base[limb][LOW_S_VALUE] = F(u64::from(scalar[limb]));
        base[limb][LOW_S_DIFFERENCE] = F(u64::from(difference[limb]));
        write_bits_v1(
            &mut base[limb][LOW_S_VALUE_BITS..LOW_S_VALUE_BITS + LIMB_BITS],
            scalar[limb],
        );
        write_bits_v1(
            &mut base[limb][LOW_S_DIFFERENCE_BITS..LOW_S_DIFFERENCE_BITS + LIMB_BITS],
            difference[limb],
        );
        base[limb][LOW_S_BORROW_BEFORE] = F(u64::from(borrow[limb]));
        base[limb][LOW_S_BORROW_AFTER] = F(u64::from(borrow[limb + 1]));
    }
    let trace = P256LowSTraceV1 { fixed, base };
    trace.validate()?;
    Ok(trace)
}
/// Evaluate one exact low-s comparison row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_p256_low_s_row_constraints_v1(
    fixed: P256ReductionFixedRowV1,
    base: &[F; P256_LOW_S_BASE_WIDTH_V1],
    next: Option<&[F; P256_LOW_S_BASE_WIDTH_V1]>,
) -> Result<Vec<F>, P256ReductionAirErrorV1> {
    let limb = usize::from(fixed.limb);
    if limb >= LIMBS || (limb + 1 < LIMBS && next.is_none()) {
        return Err(P256ReductionAirErrorV1::Topology);
    }
    let mut residues = Vec::with_capacity(40);
    append_range_residues_v1(
        &mut residues,
        base[LOW_S_VALUE],
        &base[LOW_S_VALUE_BITS..LOW_S_VALUE_BITS + LIMB_BITS],
    );
    append_range_residues_v1(
        &mut residues,
        base[LOW_S_DIFFERENCE],
        &base[LOW_S_DIFFERENCE_BITS..LOW_S_DIFFERENCE_BITS + LIMB_BITS],
    );
    residues.push(boolean_residue_v1(base[LOW_S_BORROW_BEFORE]));
    residues.push(boolean_residue_v1(base[LOW_S_BORROW_AFTER]));
    let bound_limb = F(u64::from(
        bytes_be_to_limbs_le_v1(P256_LOW_S_EXCLUSIVE_BOUND_BE_V1)[limb],
    ));
    residues.push(
        base[LOW_S_VALUE]
            .sub(bound_limb)
            .sub(base[LOW_S_BORROW_BEFORE])
            .sub(base[LOW_S_DIFFERENCE])
            .add(F(RADIX).mul(base[LOW_S_BORROW_AFTER])),
    );
    if limb == 0 {
        residues.push(base[LOW_S_BORROW_BEFORE]);
    }
    if limb + 1 == LIMBS {
        residues.push(base[LOW_S_BORROW_AFTER].sub(F::ONE));
    } else {
        residues.push(
            next.ok_or(P256ReductionAirErrorV1::Topology)?[LOW_S_BORROW_BEFORE]
                .sub(base[LOW_S_BORROW_AFTER]),
        );
    }
    Ok(residues)
}
/// Build the canonical fixed trace for one arbitrary 256-bit word.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_p256_reduction_trace_v1(
    word_be: [u8; 32],
) -> Result<P256ReductionTraceV1, P256ReductionAirErrorV1> {
    let (reduced_be, quotient) = if word_be >= P256_SCALAR_MODULUS_BE_V1 {
        (
            subtract_be_v1(word_be, P256_SCALAR_MODULUS_BE_V1)
                .ok_or(P256ReductionAirErrorV1::InvalidWitness)?,
            1_u8,
        )
    } else {
        (word_be, 0_u8)
    };
    let word = bytes_be_to_limbs_le_v1(word_be);
    let reduced = bytes_be_to_limbs_le_v1(reduced_be);
    let modulus = bytes_be_to_limbs_le_v1(P256_SCALAR_MODULUS_BE_V1);
    let (difference, borrows) = less_than_witness_v1(reduced, modulus)?;
    let mut carries = [0_u8; LIMBS + 1];
    for limb in 0..LIMBS {
        let sum = u64::from(reduced[limb])
            + u64::from(quotient) * u64::from(modulus[limb])
            + u64::from(carries[limb]);
        if sum % RADIX != u64::from(word[limb]) {
            return Err(P256ReductionAirErrorV1::InvalidWitness);
        }
        let next = sum / RADIX;
        if next > 1 {
            return Err(P256ReductionAirErrorV1::InvalidWitness);
        }
        carries[limb + 1] = next as u8;
    }
    if carries[LIMBS] != 0 {
        return Err(P256ReductionAirErrorV1::InvalidWitness);
    }
    let fixed = core::array::from_fn(|limb| P256ReductionFixedRowV1 { limb: limb as u8 });
    let mut base = [[F::ZERO; P256_REDUCTION_BASE_WIDTH_V1]; P256_REDUCTION_ROWS_V1];
    for limb in 0..LIMBS {
        base[limb][WORD] = F(u64::from(word[limb]));
        base[limb][REDUCED] = F(u64::from(reduced[limb]));
        base[limb][QUOTIENT] = F(u64::from(quotient));
        base[limb][CARRY_BEFORE] = F(u64::from(carries[limb]));
        base[limb][CARRY_AFTER] = F(u64::from(carries[limb + 1]));
        write_bits_v1(
            &mut base[limb][WORD_BITS..WORD_BITS + LIMB_BITS],
            word[limb],
        );
        write_bits_v1(
            &mut base[limb][REDUCED_BITS..REDUCED_BITS + LIMB_BITS],
            reduced[limb],
        );
        base[limb][DIFFERENCE] = F(u64::from(difference[limb]));
        write_bits_v1(
            &mut base[limb][DIFFERENCE_BITS..DIFFERENCE_BITS + LIMB_BITS],
            difference[limb],
        );
        base[limb][BORROW_BEFORE] = F(u64::from(borrows[limb]));
        base[limb][BORROW_AFTER] = F(u64::from(borrows[limb + 1]));
    }
    let trace = P256ReductionTraceV1 { fixed, base };
    trace.validate()?;
    if trace.reduced_be_v1() != reduced_be {
        return Err(P256ReductionAirErrorV1::InvalidWitness);
    }
    Ok(trace)
}
/// Evaluate one exact reduction row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_p256_reduction_row_constraints_v1(
    fixed: P256ReductionFixedRowV1,
    base: &[F; P256_REDUCTION_BASE_WIDTH_V1],
    next: Option<&[F; P256_REDUCTION_BASE_WIDTH_V1]>,
) -> Result<Vec<F>, P256ReductionAirErrorV1> {
    let limb = usize::from(fixed.limb);
    if limb >= LIMBS || (limb + 1 < LIMBS && next.is_none()) {
        return Err(P256ReductionAirErrorV1::Topology);
    }
    let mut residues = Vec::with_capacity(64);
    append_range_residues_v1(
        &mut residues,
        base[WORD],
        &base[WORD_BITS..WORD_BITS + LIMB_BITS],
    );
    append_range_residues_v1(
        &mut residues,
        base[REDUCED],
        &base[REDUCED_BITS..REDUCED_BITS + LIMB_BITS],
    );
    append_range_residues_v1(
        &mut residues,
        base[DIFFERENCE],
        &base[DIFFERENCE_BITS..DIFFERENCE_BITS + LIMB_BITS],
    );
    for value in [
        base[QUOTIENT],
        base[CARRY_BEFORE],
        base[CARRY_AFTER],
        base[BORROW_BEFORE],
        base[BORROW_AFTER],
    ] {
        residues.push(boolean_residue_v1(value));
    }
    let modulus_limb = F(u64::from(
        bytes_be_to_limbs_le_v1(P256_SCALAR_MODULUS_BE_V1)[limb],
    ));
    residues.push(
        base[REDUCED]
            .add(base[QUOTIENT].mul(modulus_limb))
            .add(base[CARRY_BEFORE])
            .sub(base[WORD])
            .sub(F(RADIX).mul(base[CARRY_AFTER])),
    );
    residues.push(
        base[REDUCED]
            .sub(modulus_limb)
            .sub(base[BORROW_BEFORE])
            .sub(base[DIFFERENCE])
            .add(F(RADIX).mul(base[BORROW_AFTER])),
    );
    if limb == 0 {
        residues.push(base[CARRY_BEFORE]);
        residues.push(base[BORROW_BEFORE]);
    }
    if limb + 1 == LIMBS {
        residues.push(base[CARRY_AFTER]);
        residues.push(base[BORROW_AFTER].sub(F::ONE));
    } else {
        let next = next.ok_or(P256ReductionAirErrorV1::Topology)?;
        residues.extend_from_slice(&[
            next[QUOTIENT].sub(base[QUOTIENT]),
            next[CARRY_BEFORE].sub(base[CARRY_AFTER]),
            next[BORROW_BEFORE].sub(base[BORROW_AFTER]),
        ]);
    }
    Ok(residues)
}
/// Compile verifier-owned numeric rows for the aggregate reduction STARK.
///
/// The schedule is derived solely from the protocol constant `LIMBS` and the verifier-selected
/// native domain. It is compiled into polynomial one-hot limb selectors, all scalar-modulus limbs,
/// boundary selectors, and the sole canonical padding suffix. No witness row or value from a proof
/// can select this topology.
#[cfg(test)]
pub fn compile_p256_reduction_stark_fixed_rows_v1(
    trace_size: usize,
) -> Result<Vec<[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1]>, P256ReductionAirErrorV1> {
    compile_p256_comparison_stark_fixed_rows_v1(
        bytes_be_to_limbs_le_v1(P256_SCALAR_MODULUS_BE_V1),
        trace_size,
    )
}
/// Compile verifier-owned numeric rows for the aggregate wallet low-S STARK.
///
/// This uses the same exact 16-row topology as reduction, but preprocesses the
/// exclusive low-S bound instead of the scalar modulus.
#[cfg(test)]
pub fn compile_p256_low_s_stark_fixed_rows_v1(
    trace_size: usize,
) -> Result<Vec<[F; P256_LOW_S_STARK_FIXED_WIDTH_V1]>, P256ReductionAirErrorV1> {
    compile_p256_comparison_stark_fixed_rows_v1(
        bytes_be_to_limbs_le_v1(P256_LOW_S_EXCLUSIVE_BOUND_BE_V1),
        trace_size,
    )
}
/// Constant-memory verifier preprocessing for one reduction or low-S comparison adapter.
///
/// The selected limb constants are constructor-owned, never proof metadata. All numeric rows and
/// the canonical padding suffix are regenerated on demand.
#[derive(Clone, Copy, Debug)]
pub struct P256ComparisonStarkFixedProviderV1 {
    limb_constants: [u16; LIMBS],
    trace_size: usize,
}
impl P256ComparisonStarkFixedProviderV1 {
    /// Construct the scalar-modulus reduction schedule.
    pub(crate) fn reduction_v1(trace_size: usize) -> Result<Self, P256ReductionAirErrorV1> {
        Self::new_v1(
            bytes_be_to_limbs_le_v1(P256_SCALAR_MODULUS_BE_V1),
            trace_size,
        )
    }
    /// Construct the strict wallet low-S comparison schedule.
    pub(crate) fn low_s_v1(trace_size: usize) -> Result<Self, P256ReductionAirErrorV1> {
        Self::new_v1(
            bytes_be_to_limbs_le_v1(P256_LOW_S_EXCLUSIVE_BOUND_BE_V1),
            trace_size,
        )
    }
    fn new_v1(
        limb_constants: [u16; LIMBS],
        trace_size: usize,
    ) -> Result<Self, P256ReductionAirErrorV1> {
        if !trace_size.is_power_of_two() || LIMBS > trace_size {
            return Err(P256ReductionAirErrorV1::Topology);
        }
        Ok(Self {
            limb_constants,
            trace_size,
        })
    }
    /// Regenerate one exact numeric fixed row.
    pub(crate) fn row_v1(
        self,
        index: usize,
    ) -> Result<[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1], P256ReductionAirErrorV1> {
        if index >= self.trace_size {
            return Err(P256ReductionAirErrorV1::Topology);
        }
        let mut row = [F::ZERO; P256_REDUCTION_STARK_FIXED_WIDTH_V1];
        if index >= LIMBS {
            row[STARK_PADDING] = F::ONE;
            return Ok(row);
        }
        row[STARK_LIMB_SELECTOR_START + index] = F::ONE;
        for (target, constant) in row[STARK_LIMB_CONSTANT_START..STARK_LIMB_CONSTANT_START + LIMBS]
            .iter_mut()
            .zip(self.limb_constants)
        {
            *target = F(u64::from(constant));
        }
        row[STARK_FIRST] = F(u64::from(index == 0));
        row[STARK_LAST] = F(u64::from(index + 1 == LIMBS));
        row[STARK_ACTIVE] = F::ONE;
        Ok(row)
    }
}
#[cfg(test)]
fn compile_p256_comparison_stark_fixed_rows_v1(
    limb_constants: [u16; LIMBS],
    trace_size: usize,
) -> Result<Vec<[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1]>, P256ReductionAirErrorV1> {
    let provider = P256ComparisonStarkFixedProviderV1::new_v1(limb_constants, trace_size)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(trace_size)
        .map_err(|_| P256ReductionAirErrorV1::Allocation)?;
    for index in 0..trace_size {
        rows.push(provider.row_v1(index)?);
    }
    Ok(rows)
}
fn stark_selected_limb_constant_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_REDUCTION_STARK_FIXED_WIDTH_V1],
) -> A {
    (0..LIMBS).fold(A::ZERO, |sum, limb| {
        sum.add(
            fixed[STARK_LIMB_SELECTOR_START + limb].mul(fixed[STARK_LIMB_CONSTANT_START + limb]),
        )
    })
}
fn stark_fields_are_canonical_v1<A: PolynomialAirFieldV1, const BASE: usize, const AUX: usize>(
    current: &[A; BASE],
    next: &[A; BASE],
    current_aux: &[A; AUX],
    next_aux: &[A; AUX],
    fixed: &[A; P256_REDUCTION_STARK_FIXED_WIDTH_V1],
) -> bool {
    current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .all(|value| value.is_canonical())
}
#[cfg(test)]
/// Evaluate one aggregate reduction opening as an exact polynomial vector.
///
/// Limb constants, first/last boundaries, activity, and padding are numeric
/// verifier-preprocessed openings. The evaluator therefore has no native
/// limb/row branch on the LDE and has maximum total degree four.
pub fn evaluate_p256_reduction_stark_residues_v1(
    current: &[F; P256_REDUCTION_BASE_WIDTH_V1],
    next: &[F; P256_REDUCTION_BASE_WIDTH_V1],
    current_aux: &[F; P256_REDUCTION_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_REDUCTION_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<F>, P256ReductionAirErrorV1> {
    evaluate_p256_reduction_stark_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
    )
}
/// The same complete comparison polynomial over base or extension arithmetic.
pub fn evaluate_p256_reduction_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_REDUCTION_BASE_WIDTH_V1],
    next: &[A; P256_REDUCTION_BASE_WIDTH_V1],
    current_aux: &[A; P256_REDUCTION_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_REDUCTION_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_REDUCTION_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<A>, P256ReductionAirErrorV1> {
    if !stark_fields_are_canonical_v1(current, next, current_aux, next_aux, fixed) {
        return Err(P256ReductionAirErrorV1::Constraint);
    }
    let mut residues = Vec::with_capacity(P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1);
    for (value, bits_start) in [
        (WORD, WORD_BITS),
        (REDUCED, REDUCED_BITS),
        (DIFFERENCE, DIFFERENCE_BITS),
    ] {
        append_range_residues_v1(
            &mut residues,
            current[value],
            &current[bits_start..bits_start + LIMB_BITS],
        );
    }
    for value in [
        current[QUOTIENT],
        current[CARRY_BEFORE],
        current[CARRY_AFTER],
        current[BORROW_BEFORE],
        current[BORROW_AFTER],
    ] {
        residues.push(boolean_residue_v1(value));
    }
    let active = fixed[STARK_ACTIVE];
    let constant = stark_selected_limb_constant_v1(fixed);
    residues.push(
        active.mul(
            current[REDUCED]
                .add(current[QUOTIENT].mul(constant))
                .add(current[CARRY_BEFORE])
                .sub(current[WORD])
                .sub(current[CARRY_AFTER].mul_base(F(RADIX))),
        ),
    );
    residues.push(
        active.mul(
            current[REDUCED]
                .sub(constant)
                .sub(current[BORROW_BEFORE])
                .sub(current[DIFFERENCE])
                .add(current[BORROW_AFTER].mul_base(F(RADIX))),
        ),
    );
    residues.push(active.mul(fixed[STARK_FIRST]).mul(current[CARRY_BEFORE]));
    residues.push(active.mul(fixed[STARK_FIRST]).mul(current[BORROW_BEFORE]));
    residues.push(active.mul(fixed[STARK_LAST]).mul(current[CARRY_AFTER]));
    residues.push(
        active
            .mul(fixed[STARK_LAST])
            .mul(current[BORROW_AFTER].sub(A::ONE)),
    );
    let active_not_last = active.mul(A::ONE.sub(fixed[STARK_LAST]));
    residues.push(active_not_last.mul(next[QUOTIENT].sub(current[QUOTIENT])));
    residues.push(active_not_last.mul(next[CARRY_BEFORE].sub(current[CARRY_AFTER])));
    residues.push(active_not_last.mul(next[BORROW_BEFORE].sub(current[BORROW_AFTER])));
    let padding = fixed[STARK_PADDING];
    for value in current {
        residues.push(padding.mul(*value));
    }
    residues.push(current_aux[0]);
    if residues.len() != P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1 {
        return Err(P256ReductionAirErrorV1::Topology);
    }
    Ok(residues)
}
#[cfg(test)]
/// Evaluate one aggregate wallet low-S opening as an exact polynomial vector.
///
/// The same numeric topology removes native row branching from the LDE. The
/// strict comparison has maximum total degree three.
pub fn evaluate_p256_low_s_stark_residues_v1(
    current: &[F; P256_LOW_S_BASE_WIDTH_V1],
    next: &[F; P256_LOW_S_BASE_WIDTH_V1],
    current_aux: &[F; P256_LOW_S_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_LOW_S_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_LOW_S_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<F>, P256ReductionAirErrorV1> {
    evaluate_p256_low_s_stark_residues_over_field_v1(current, next, current_aux, next_aux, fixed)
}
/// The same complete comparison polynomial over base or extension arithmetic.
pub fn evaluate_p256_low_s_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_LOW_S_BASE_WIDTH_V1],
    next: &[A; P256_LOW_S_BASE_WIDTH_V1],
    current_aux: &[A; P256_LOW_S_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_LOW_S_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_LOW_S_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<A>, P256ReductionAirErrorV1> {
    if !stark_fields_are_canonical_v1(current, next, current_aux, next_aux, fixed) {
        return Err(P256ReductionAirErrorV1::Constraint);
    }
    let mut residues = Vec::with_capacity(P256_LOW_S_STARK_CONSTRAINT_COUNT_V1);
    for (value, bits_start) in [
        (LOW_S_VALUE, LOW_S_VALUE_BITS),
        (LOW_S_DIFFERENCE, LOW_S_DIFFERENCE_BITS),
    ] {
        append_range_residues_v1(
            &mut residues,
            current[value],
            &current[bits_start..bits_start + LIMB_BITS],
        );
    }
    residues.push(boolean_residue_v1(current[LOW_S_BORROW_BEFORE]));
    residues.push(boolean_residue_v1(current[LOW_S_BORROW_AFTER]));
    let active = fixed[STARK_ACTIVE];
    let constant = stark_selected_limb_constant_v1(fixed);
    residues.push(
        active.mul(
            current[LOW_S_VALUE]
                .sub(constant)
                .sub(current[LOW_S_BORROW_BEFORE])
                .sub(current[LOW_S_DIFFERENCE])
                .add(current[LOW_S_BORROW_AFTER].mul_base(F(RADIX))),
        ),
    );
    residues.push(
        active
            .mul(fixed[STARK_FIRST])
            .mul(current[LOW_S_BORROW_BEFORE]),
    );
    residues.push(
        active
            .mul(fixed[STARK_LAST])
            .mul(current[LOW_S_BORROW_AFTER].sub(A::ONE)),
    );
    let active_not_last = active.mul(A::ONE.sub(fixed[STARK_LAST]));
    residues.push(active_not_last.mul(next[LOW_S_BORROW_BEFORE].sub(current[LOW_S_BORROW_AFTER])));
    let padding = fixed[STARK_PADDING];
    for value in current {
        residues.push(padding.mul(*value));
    }
    residues.push(current_aux[0]);
    if residues.len() != P256_LOW_S_STARK_CONSTRAINT_COUNT_V1 {
        return Err(P256ReductionAirErrorV1::Topology);
    }
    Ok(residues)
}
fn append_range_residues_v1<A: PolynomialAirFieldV1>(residues: &mut Vec<A>, value: A, bits: &[A]) {
    let mut packed = A::ZERO;
    for (bit, cell) in bits.iter().copied().enumerate() {
        residues.push(boolean_residue_v1(cell));
        packed = packed.add(cell.mul_base(F(1_u64 << bit)));
    }
    residues.push(value.sub(packed));
}
fn boolean_residue_v1<A: PolynomialAirFieldV1>(value: A) -> A {
    value.mul(value.sub(A::ONE))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn less_than_witness_v1(
    value: [u16; LIMBS],
    modulus: [u16; LIMBS],
) -> Result<([u16; LIMBS], [u8; LIMBS + 1]), P256ReductionAirErrorV1> {
    let mut difference = [0_u16; LIMBS];
    let mut borrow = [0_u8; LIMBS + 1];
    for limb in 0..LIMBS {
        let raw = i32::from(value[limb]) - i32::from(modulus[limb]) - i32::from(borrow[limb]);
        if raw < 0 {
            difference[limb] = (raw + RADIX as i32) as u16;
            borrow[limb + 1] = 1;
        } else {
            difference[limb] = raw as u16;
        }
    }
    if borrow[LIMBS] != 1 {
        return Err(P256ReductionAirErrorV1::InvalidWitness);
    }
    Ok((difference, borrow))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn subtract_be_v1(mut left: [u8; 32], right: [u8; 32]) -> Option<[u8; 32]> {
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let value = i16::from(left[index]) - i16::from(right[index]) - borrow;
        if value < 0 {
            left[index] = (value + 256) as u8;
            borrow = 1;
        } else {
            left[index] = value as u8;
            borrow = 0;
        }
    }
    (borrow == 0).then_some(left)
}
fn bytes_be_to_limbs_le_v1(bytes: [u8; 32]) -> [u16; LIMBS] {
    core::array::from_fn(|limb| {
        let low = 31 - 2 * limb;
        u16::from_le_bytes([bytes[low], bytes[low - 1]])
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn limbs_le_to_bytes_be_v1(limbs: [u16; LIMBS]) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (limb, value) in limbs.into_iter().enumerate() {
        let [low, high] = value.to_le_bytes();
        bytes[31 - 2 * limb] = low;
        bytes[30 - 2 * limb] = high;
    }
    bytes
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_bits_v1(target: &mut [F], value: u16) {
    for (bit, cell) in target.iter_mut().enumerate() {
        *cell = F(u64::from((value >> bit) & 1));
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_comparison_erasure_clears_live_rows_on_drop() {
        use super::super::private_table::inspection::observe_v1;
        let reduction = build_p256_reduction_trace_v1([127; 32]).unwrap();
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let low_s = build_p256_low_s_trace_v1(scalar).unwrap();
        assert_eq!(
            format!("{reduction:?}"),
            "P256ReductionTraceV1 { <private trace redacted> }"
        );
        assert_eq!(
            format!("{low_s:?}"),
            "P256LowSTraceV1 { <private trace redacted> }"
        );
        let expected = reduction.base.len() * P256_REDUCTION_BASE_WIDTH_V1
            + low_s.base.len() * P256_LOW_S_BASE_WIDTH_V1;
        let ((), observed) = observe_v1(|| {
            drop(reduction);
            drop(low_s);
        });
        assert_eq!(
            observed.iter().map(|item| item.cells).sum::<usize>(),
            expected
        );
        assert!(
            observed
                .iter()
                .all(|item| item.nonzero_before > 0 && item.nonzero_after == 0)
        );
    }

    use super::*;
    fn add_small_be(mut value: [u8; 32], amount: u64) -> [u8; 32] {
        let mut carry = amount;
        for byte in value.iter_mut().rev() {
            let sum = u64::from(*byte) + (carry & 0xff);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
            if carry == 0 {
                break;
            }
        }
        assert_eq!(carry, 0);
        value
    }
    fn subtract_small_be(mut value: [u8; 32], amount: u64) -> [u8; 32] {
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
    fn unchecked_subtraction_witness(
        value: [u16; LIMBS],
        bound: [u16; LIMBS],
    ) -> ([u16; LIMBS], [u8; LIMBS + 1]) {
        let mut difference = [0_u16; LIMBS];
        let mut borrow = [0_u8; LIMBS + 1];
        for limb in 0..LIMBS {
            let raw = i32::from(value[limb]) - i32::from(bound[limb]) - i32::from(borrow[limb]);
            if raw < 0 {
                difference[limb] = (raw + RADIX as i32) as u16;
                borrow[limb + 1] = 1;
            } else {
                difference[limb] = raw as u16;
            }
        }
        (difference, borrow)
    }
    fn reduction_numeric_trace_has_nonzero(
        base: &[[F; P256_REDUCTION_BASE_WIDTH_V1]],
        aux: &[[F; P256_REDUCTION_STARK_AUX_WIDTH_V1]],
        fixed: &[[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1]],
    ) -> bool {
        assert_eq!(base.len(), aux.len());
        assert_eq!(base.len(), fixed.len());
        (0..base.len()).any(|row| {
            let next = (row + 1) % base.len();
            match evaluate_p256_reduction_stark_residues_v1(
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
    }
    fn low_s_numeric_trace_has_nonzero(
        base: &[[F; P256_LOW_S_BASE_WIDTH_V1]],
        aux: &[[F; P256_LOW_S_STARK_AUX_WIDTH_V1]],
        fixed: &[[F; P256_LOW_S_STARK_FIXED_WIDTH_V1]],
    ) -> bool {
        assert_eq!(base.len(), aux.len());
        assert_eq!(base.len(), fixed.len());
        (0..base.len()).any(|row| {
            let next = (row + 1) % base.len();
            match evaluate_p256_low_s_stark_residues_v1(
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
    }
    fn reduction_numeric_nonzero_count(
        base: &[[F; P256_REDUCTION_BASE_WIDTH_V1]],
        fixed: &[[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1]],
    ) -> usize {
        let aux = vec![[F::ZERO; P256_REDUCTION_STARK_AUX_WIDTH_V1]; base.len()];
        (0..base.len())
            .map(|row| {
                let next = (row + 1) % base.len();
                evaluate_p256_reduction_stark_residues_v1(
                    &base[row],
                    &base[next],
                    &aux[row],
                    &aux[next],
                    &fixed[row],
                )
                .expect("canonical aggregate fields")
                .into_iter()
                .filter(|residue| *residue != F::ZERO)
                .count()
            })
            .sum()
    }
    fn low_s_numeric_nonzero_count(
        base: &[[F; P256_LOW_S_BASE_WIDTH_V1]],
        fixed: &[[F; P256_LOW_S_STARK_FIXED_WIDTH_V1]],
    ) -> usize {
        let aux = vec![[F::ZERO; P256_LOW_S_STARK_AUX_WIDTH_V1]; base.len()];
        (0..base.len())
            .map(|row| {
                let next = (row + 1) % base.len();
                evaluate_p256_low_s_stark_residues_v1(
                    &base[row],
                    &base[next],
                    &aux[row],
                    &aux[next],
                    &fixed[row],
                )
                .expect("canonical aggregate fields")
                .into_iter()
                .filter(|residue| *residue != F::ZERO)
                .count()
            })
            .sum()
    }
    #[test]
    fn reduction_accepts_all_boundaries_and_deterministic_differentials() {
        let maximum = [0xff_u8; 32];
        let boundaries = [
            [0_u8; 32],
            {
                let mut one = [0_u8; 32];
                one[31] = 1;
                one
            },
            subtract_small_be(P256_SCALAR_MODULUS_BE_V1, 1),
            P256_SCALAR_MODULUS_BE_V1,
            add_small_be(P256_SCALAR_MODULUS_BE_V1, 1),
            maximum,
        ];
        for word in boundaries {
            let trace = build_p256_reduction_trace_v1(word).expect("boundary reduction");
            trace.validate().expect("boundary constraints");
            let expected = if word >= P256_SCALAR_MODULUS_BE_V1 {
                subtract_be_v1(word, P256_SCALAR_MODULUS_BE_V1).expect("one subtraction")
            } else {
                word
            };
            assert_eq!(trace.reduced_be_v1(), expected);
        }
        for index in 0_u64..=511 {
            let mut word = [0_u8; 32];
            for chunk in 0..4 {
                let value = index
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15 ^ (chunk as u64 + 1))
                    .rotate_left(((index + chunk as u64 * 13) % 64) as u32);
                word[chunk * 8..chunk * 8 + 8].copy_from_slice(&value.to_be_bytes());
            }
            let trace = build_p256_reduction_trace_v1(word).expect("differential reduction");
            let expected = if word >= P256_SCALAR_MODULUS_BE_V1 {
                subtract_be_v1(word, P256_SCALAR_MODULUS_BE_V1).expect("one subtraction")
            } else {
                word
            };
            assert_eq!(trace.reduced_be_v1(), expected);
        }
    }
    #[test]
    fn wallet_low_s_accepts_exact_lower_half_and_rejects_high_half() {
        for scalar in [
            [0_u8; 32],
            {
                let mut one = [0_u8; 32];
                one[31] = 1;
                one
            },
            subtract_small_be(P256_LOW_S_MAXIMUM_BE_V1, 1),
            P256_LOW_S_MAXIMUM_BE_V1,
        ] {
            build_p256_low_s_trace_v1(scalar)
                .expect("admitted low-s")
                .validate()
                .expect("low-s constraints");
        }
        for scalar in [
            P256_LOW_S_EXCLUSIVE_BOUND_BE_V1,
            subtract_small_be(P256_SCALAR_MODULUS_BE_V1, 1),
            P256_SCALAR_MODULUS_BE_V1,
            [0xff_u8; 32],
        ] {
            assert_eq!(
                build_p256_low_s_trace_v1(scalar),
                Err(P256ReductionAirErrorV1::InvalidWitness)
            );
        }
    }
    #[test]
    fn every_low_s_cell_and_fixed_limb_is_constraint_relevant() {
        let trace = build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("maximum low-s");
        for row in 0..LIMBS {
            for column in 0..P256_LOW_S_BASE_WIDTH_V1 {
                let mut changed = trace.clone();
                changed.base[row][column] = changed.base[row][column].add(F::ONE);
                assert!(
                    changed.validate().is_err(),
                    "low-s mutation survived at row {row}, column {column}"
                );
            }
            let mut changed = trace.clone();
            changed.fixed[row].limb ^= 1;
            assert!(changed.validate().is_err());
        }
    }
    #[test]
    fn every_committed_cell_is_constraint_relevant_on_both_quotient_paths() {
        for word in [
            subtract_small_be(P256_SCALAR_MODULUS_BE_V1, 17),
            add_small_be(P256_SCALAR_MODULUS_BE_V1, 17),
        ] {
            let trace = build_p256_reduction_trace_v1(word).expect("valid reduction");
            for row in 0..P256_REDUCTION_ROWS_V1 {
                for column in 0..P256_REDUCTION_BASE_WIDTH_V1 {
                    let mut changed = trace.clone();
                    changed.base[row][column] = changed.base[row][column].add(F::ONE);
                    assert!(
                        changed.validate().is_err(),
                        "mutation survived at row {row}, column {column}"
                    );
                }
            }
        }
    }
    #[test]
    fn fixed_rows_and_coordinated_quotient_carry_borrow_attacks_fail() {
        let trace =
            build_p256_reduction_trace_v1(add_small_be(P256_SCALAR_MODULUS_BE_V1, 0x1_0001))
                .expect("valid lifted reduction");
        for row in 0..P256_REDUCTION_ROWS_V1 {
            let mut changed = trace.clone();
            changed.fixed[row].limb ^= 1;
            assert!(changed.validate().is_err());
        }
        let mut quotient = trace.clone();
        for row in &mut quotient.base {
            row[QUOTIENT] = F::ZERO;
        }
        assert!(quotient.validate().is_err());
        let mut carry = trace.clone();
        carry.base[0][CARRY_AFTER] = carry.base[0][CARRY_AFTER].add(F::ONE);
        carry.base[1][CARRY_BEFORE] = carry.base[1][CARRY_BEFORE].add(F::ONE);
        assert!(carry.validate().is_err());
        let mut borrow = trace;
        borrow.base[0][BORROW_AFTER] = borrow.base[0][BORROW_AFTER].sub(F::ONE);
        borrow.base[1][BORROW_BEFORE] = borrow.base[1][BORROW_BEFORE].sub(F::ONE);
        assert!(borrow.validate().is_err());
    }
    #[test]
    fn pointwise_binding_accessors_are_exact_and_bounds_checked() {
        let word = add_small_be(P256_SCALAR_MODULUS_BE_V1, 0x1234);
        let reduction = build_p256_reduction_trace_v1(word).expect("valid reduction");
        let word_limbs = bytes_be_to_limbs_le_v1(word);
        let reduced_limbs = bytes_be_to_limbs_le_v1(reduction.reduced_be_v1());
        for limb in 0..LIMBS {
            assert_eq!(
                p256_reduction_limb_cells_v1(&reduction, limb).unwrap(),
                [
                    F(u64::from(word_limbs[limb])),
                    F(u64::from(reduced_limbs[limb]))
                ]
            );
        }
        assert_eq!(
            p256_reduction_limb_cells_v1(&reduction, LIMBS),
            Err(P256ReductionAirErrorV1::Topology)
        );
        let low_s = build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("valid low-s");
        let low_s_limbs = bytes_be_to_limbs_le_v1(P256_LOW_S_MAXIMUM_BE_V1);
        for (limb, expected) in low_s_limbs.into_iter().enumerate() {
            assert_eq!(
                p256_low_s_limb_cell_v1(&low_s, limb).unwrap(),
                F(u64::from(expected))
            );
        }
        assert_eq!(
            p256_low_s_limb_cell_v1(&low_s, LIMBS),
            Err(P256ReductionAirErrorV1::Topology)
        );
    }
    #[test]
    fn opened_binding_projections_select_exact_committed_base_cells() {
        let reduction =
            build_p256_reduction_trace_v1(add_small_be(P256_SCALAR_MODULUS_BE_V1, 0x1234))
                .expect("valid reduction");
        for row in &reduction.base {
            let expected = [row[WORD], row[REDUCED]];
            assert_eq!(p256_reduction_opened_binding_cells_v1(row), expected);
            for (column, _) in row.iter().enumerate() {
                let mut changed = *row;
                changed[column] = changed[column].add(F::ONE);
                let mut changed_expected = expected;
                if column == WORD {
                    changed_expected[0] = changed_expected[0].add(F::ONE);
                }
                if column == REDUCED {
                    changed_expected[1] = changed_expected[1].add(F::ONE);
                }
                assert_eq!(
                    p256_reduction_opened_binding_cells_v1(&changed),
                    changed_expected,
                    "wrong reduction projection at column {column}"
                );
            }
        }
        let low_s = build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("valid low-S");
        for row in &low_s.base {
            let expected = row[LOW_S_VALUE];
            assert_eq!(p256_low_s_opened_binding_cell_v1(row), expected);
            for (column, _) in row.iter().enumerate() {
                let mut changed = *row;
                changed[column] = changed[column].add(F::ONE);
                let changed_expected = if column == LOW_S_VALUE {
                    expected.add(F::ONE)
                } else {
                    expected
                };
                assert_eq!(
                    p256_low_s_opened_binding_cell_v1(&changed),
                    changed_expected,
                    "wrong low-S projection at column {column}"
                );
            }
        }
    }
    #[test]
    fn numeric_profiles_have_exact_release_shapes_and_only_aggregate_activation() {
        assert_eq!(P256_REDUCTION_STARK_AUX_WIDTH_V1, 1);
        assert_eq!(P256_REDUCTION_STARK_FIXED_WIDTH_V1, 36);
        assert_eq!(P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1, 122);
        assert_eq!(P256_REDUCTION_STARK_CONSTRAINT_DEGREE_V1, 4);
        assert_eq!(P256_LOW_S_STARK_AUX_WIDTH_V1, 1);
        assert_eq!(P256_LOW_S_STARK_FIXED_WIDTH_V1, 36);
        assert_eq!(P256_LOW_S_STARK_CONSTRAINT_COUNT_V1, 77);
        assert_eq!(P256_LOW_S_STARK_CONSTRAINT_DEGREE_V1, 3);
        assert!(
            ZK_X509_P256_REDUCTION_AIR_DESCRIPTOR_V1
                .ends_with(b":standalone-activation=not-applicable")
        );
    }
    #[test]
    fn numeric_fixed_evaluators_accept_every_canonical_row_and_padding() {
        let trace_size = 32;
        let modulus = bytes_be_to_limbs_le_v1(P256_SCALAR_MODULUS_BE_V1);
        for word in [
            subtract_small_be(P256_SCALAR_MODULUS_BE_V1, 17),
            add_small_be(P256_SCALAR_MODULUS_BE_V1, 17),
        ] {
            let trace = build_p256_reduction_trace_v1(word).expect("canonical reduction");
            let fixed = compile_p256_reduction_stark_fixed_rows_v1(trace_size)
                .expect("verifier reduction preprocessing");
            let mut base = trace.base.to_vec();
            base.resize(trace_size, [F::ZERO; P256_REDUCTION_BASE_WIDTH_V1]);
            let aux = vec![[F::ZERO; P256_REDUCTION_STARK_AUX_WIDTH_V1]; trace_size];
            assert!(!reduction_numeric_trace_has_nonzero(&base, &aux, &fixed));
            for row in 0..LIMBS {
                for limb in 0..LIMBS {
                    assert_eq!(
                        fixed[row][STARK_LIMB_SELECTOR_START + limb],
                        F(u64::from(row == limb))
                    );
                    assert_eq!(
                        fixed[row][STARK_LIMB_CONSTANT_START + limb],
                        F(u64::from(modulus[limb]))
                    );
                }
                assert_eq!(fixed[row][STARK_FIRST], F(u64::from(row == 0)));
                assert_eq!(fixed[row][STARK_LAST], F(u64::from(row + 1 == LIMBS)));
                assert_eq!(fixed[row][STARK_ACTIVE], F::ONE);
                assert_eq!(fixed[row][STARK_PADDING], F::ZERO);
                let next = (row + 1) % trace_size;
                let residues = evaluate_p256_reduction_stark_residues_v1(
                    &base[row],
                    &base[next],
                    &aux[row],
                    &aux[next],
                    &fixed[row],
                )
                .expect("canonical reduction row");
                assert_eq!(residues.len(), P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1);
                assert!(residues.iter().all(|residue| *residue == F::ZERO));
            }
            for row in LIMBS..trace_size {
                let mut expected_fixed = [F::ZERO; P256_REDUCTION_STARK_FIXED_WIDTH_V1];
                expected_fixed[STARK_PADDING] = F::ONE;
                assert_eq!(fixed[row], expected_fixed);
                let next = (row + 1) % trace_size;
                let residues = evaluate_p256_reduction_stark_residues_v1(
                    &base[row],
                    &base[next],
                    &aux[row],
                    &aux[next],
                    &fixed[row],
                )
                .expect("canonical reduction padding");
                assert_eq!(residues.len(), P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1);
                assert!(residues.iter().all(|residue| *residue == F::ZERO));
            }
        }
        let trace = build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("canonical low-S");
        let bound = bytes_be_to_limbs_le_v1(P256_LOW_S_EXCLUSIVE_BOUND_BE_V1);
        let fixed = compile_p256_low_s_stark_fixed_rows_v1(trace_size)
            .expect("verifier low-S preprocessing");
        let mut base = trace.base.to_vec();
        base.resize(trace_size, [F::ZERO; P256_LOW_S_BASE_WIDTH_V1]);
        let aux = vec![[F::ZERO; P256_LOW_S_STARK_AUX_WIDTH_V1]; trace_size];
        assert!(!low_s_numeric_trace_has_nonzero(&base, &aux, &fixed));
        for row in 0..LIMBS {
            for limb in 0..LIMBS {
                assert_eq!(
                    fixed[row][STARK_LIMB_SELECTOR_START + limb],
                    F(u64::from(row == limb))
                );
                assert_eq!(
                    fixed[row][STARK_LIMB_CONSTANT_START + limb],
                    F(u64::from(bound[limb]))
                );
            }
            let next = (row + 1) % trace_size;
            let residues = evaluate_p256_low_s_stark_residues_v1(
                &base[row],
                &base[next],
                &aux[row],
                &aux[next],
                &fixed[row],
            )
            .expect("canonical low-S row");
            assert_eq!(residues.len(), P256_LOW_S_STARK_CONSTRAINT_COUNT_V1);
            assert!(residues.iter().all(|residue| *residue == F::ZERO));
        }
        for row in LIMBS..trace_size {
            let mut expected_fixed = [F::ZERO; P256_LOW_S_STARK_FIXED_WIDTH_V1];
            expected_fixed[STARK_PADDING] = F::ONE;
            assert_eq!(fixed[row], expected_fixed);
            let next = (row + 1) % trace_size;
            let residues = evaluate_p256_low_s_stark_residues_v1(
                &base[row],
                &base[next],
                &aux[row],
                &aux[next],
                &fixed[row],
            )
            .expect("canonical low-S padding");
            assert_eq!(residues.len(), P256_LOW_S_STARK_CONSTRAINT_COUNT_V1);
            assert!(residues.iter().all(|residue| *residue == F::ZERO));
        }
    }
    #[test]
    fn numeric_fixed_compilers_are_witness_independent_and_reject_bad_domains() {
        let trace =
            build_p256_reduction_trace_v1([0_u8; 32]).expect("canonical reduction topology");
        type Compiler =
            fn(
                usize,
            )
                -> Result<Vec<[F; P256_REDUCTION_STARK_FIXED_WIDTH_V1]>, P256ReductionAirErrorV1>;
        let reduction_compiler: Compiler = compile_p256_reduction_stark_fixed_rows_v1;
        let low_s_compiler: Compiler = compile_p256_low_s_stark_fixed_rows_v1;
        for compiler in [reduction_compiler, low_s_compiler] {
            let canonical = compiler(LIMBS).expect("protocol-owned exact schedule");
            for row in 0..LIMBS {
                let mut changed = trace.clone();
                changed.fixed[row].limb ^= 1;
                assert_eq!(
                    changed.validate(),
                    Err(P256ReductionAirErrorV1::Topology),
                    "mutated witness topology at row {row} was accepted"
                );
                assert_eq!(
                    compiler(LIMBS).expect("fixed schedule remains verifier-owned"),
                    canonical,
                    "witness topology influenced verifier preprocessing at row {row}"
                );
            }
            assert_eq!(compiler(LIMBS / 2), Err(P256ReductionAirErrorV1::Topology));
            assert_eq!(compiler(LIMBS + 1), Err(P256ReductionAirErrorV1::Topology));
            assert_eq!(compiler(0), Err(P256ReductionAirErrorV1::Topology));
        }
    }
    #[test]
    fn numeric_reduction_binds_every_active_padding_and_auxiliary_cell() {
        let trace =
            build_p256_reduction_trace_v1(add_small_be(P256_SCALAR_MODULUS_BE_V1, 0x1_0001))
                .expect("canonical lifted reduction");
        let trace_size = 32;
        let fixed = compile_p256_reduction_stark_fixed_rows_v1(trace_size)
            .expect("verifier reduction preprocessing");
        let mut base = trace.base.to_vec();
        base.resize(trace_size, [F::ZERO; P256_REDUCTION_BASE_WIDTH_V1]);
        let aux = vec![[F::ZERO; P256_REDUCTION_STARK_AUX_WIDTH_V1]; trace_size];
        for row in 0..LIMBS {
            for column in 0..P256_REDUCTION_BASE_WIDTH_V1 {
                let mut changed = base.clone();
                changed[row][column] = changed[row][column].add(F::ONE);
                assert!(
                    reduction_numeric_trace_has_nonzero(&changed, &aux, &fixed),
                    "unbound reduction active cell row {row}, column {column}"
                );
            }
        }
        for row in LIMBS..trace_size {
            for column in 0..P256_REDUCTION_BASE_WIDTH_V1 {
                let mut changed = base.clone();
                changed[row][column] = F::ONE;
                assert!(
                    reduction_numeric_trace_has_nonzero(&changed, &aux, &fixed),
                    "unbound reduction padding cell row {row}, column {column}"
                );
            }
        }
        for row in 0..trace_size {
            for column in 0..P256_REDUCTION_STARK_AUX_WIDTH_V1 {
                let mut changed = aux.clone();
                changed[row][column] = F::ONE;
                assert!(
                    reduction_numeric_trace_has_nonzero(&base, &changed, &fixed),
                    "unbound reduction auxiliary cell row {row}, column {column}"
                );
            }
        }
    }
    #[test]
    fn numeric_low_s_binds_every_active_padding_and_auxiliary_cell() {
        let trace = build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("canonical low-S");
        let trace_size = 32;
        let fixed = compile_p256_low_s_stark_fixed_rows_v1(trace_size)
            .expect("verifier low-S preprocessing");
        let mut base = trace.base.to_vec();
        base.resize(trace_size, [F::ZERO; P256_LOW_S_BASE_WIDTH_V1]);
        let aux = vec![[F::ZERO; P256_LOW_S_STARK_AUX_WIDTH_V1]; trace_size];
        for row in 0..LIMBS {
            for column in 0..P256_LOW_S_BASE_WIDTH_V1 {
                let mut changed = base.clone();
                changed[row][column] = changed[row][column].add(F::ONE);
                assert!(
                    low_s_numeric_trace_has_nonzero(&changed, &aux, &fixed),
                    "unbound low-S active cell row {row}, column {column}"
                );
            }
        }
        for row in LIMBS..trace_size {
            for column in 0..P256_LOW_S_BASE_WIDTH_V1 {
                let mut changed = base.clone();
                changed[row][column] = F::ONE;
                assert!(
                    low_s_numeric_trace_has_nonzero(&changed, &aux, &fixed),
                    "unbound low-S padding cell row {row}, column {column}"
                );
            }
        }
        for row in 0..trace_size {
            for column in 0..P256_LOW_S_STARK_AUX_WIDTH_V1 {
                let mut changed = aux.clone();
                changed[row][column] = F::ONE;
                assert!(
                    low_s_numeric_trace_has_nonzero(&base, &changed, &fixed),
                    "unbound low-S auxiliary cell row {row}, column {column}"
                );
            }
        }
    }
    #[test]
    fn numeric_coordinated_quotient_carry_borrow_and_high_s_attacks_fail() {
        let word = add_small_be(P256_SCALAR_MODULUS_BE_V1, 0x1_0001);
        let trace = build_p256_reduction_trace_v1(word).expect("canonical lifted reduction");
        let fixed = compile_p256_reduction_stark_fixed_rows_v1(LIMBS)
            .expect("verifier reduction preprocessing");
        let mut forged = trace.base.to_vec();
        let word_limbs = bytes_be_to_limbs_le_v1(word);
        let modulus = bytes_be_to_limbs_le_v1(P256_SCALAR_MODULUS_BE_V1);
        let (difference, borrow) = unchecked_subtraction_witness(word_limbs, modulus);
        assert_eq!(borrow[LIMBS], 0);
        for limb in 0..LIMBS {
            forged[limb][REDUCED] = F(u64::from(word_limbs[limb]));
            write_bits_v1(
                &mut forged[limb][REDUCED_BITS..REDUCED_BITS + LIMB_BITS],
                word_limbs[limb],
            );
            forged[limb][QUOTIENT] = F::ZERO;
            forged[limb][CARRY_BEFORE] = F::ZERO;
            forged[limb][CARRY_AFTER] = F::ZERO;
            forged[limb][DIFFERENCE] = F(u64::from(difference[limb]));
            write_bits_v1(
                &mut forged[limb][DIFFERENCE_BITS..DIFFERENCE_BITS + LIMB_BITS],
                difference[limb],
            );
            forged[limb][BORROW_BEFORE] = F(u64::from(borrow[limb]));
            forged[limb][BORROW_AFTER] = F(u64::from(borrow[limb + 1]));
        }
        assert_eq!(
            reduction_numeric_nonzero_count(&forged, &fixed),
            1,
            "coordinated q/carry/borrow forgery must reach only the final canonicality gate"
        );
        let _low_s_topology =
            build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("canonical low-S");
        let low_s_fixed =
            compile_p256_low_s_stark_fixed_rows_v1(LIMBS).expect("verifier low-S preprocessing");
        let bound = bytes_be_to_limbs_le_v1(P256_LOW_S_EXCLUSIVE_BOUND_BE_V1);
        for high_s in [
            P256_LOW_S_EXCLUSIVE_BOUND_BE_V1,
            subtract_small_be(P256_SCALAR_MODULUS_BE_V1, 1),
        ] {
            let value = bytes_be_to_limbs_le_v1(high_s);
            let (difference, borrow) = unchecked_subtraction_witness(value, bound);
            assert_eq!(borrow[LIMBS], 0);
            let mut forged = vec![[F::ZERO; P256_LOW_S_BASE_WIDTH_V1]; LIMBS];
            for limb in 0..LIMBS {
                forged[limb][LOW_S_VALUE] = F(u64::from(value[limb]));
                forged[limb][LOW_S_DIFFERENCE] = F(u64::from(difference[limb]));
                write_bits_v1(
                    &mut forged[limb][LOW_S_VALUE_BITS..LOW_S_VALUE_BITS + LIMB_BITS],
                    value[limb],
                );
                write_bits_v1(
                    &mut forged[limb][LOW_S_DIFFERENCE_BITS..LOW_S_DIFFERENCE_BITS + LIMB_BITS],
                    difference[limb],
                );
                forged[limb][LOW_S_BORROW_BEFORE] = F(u64::from(borrow[limb]));
                forged[limb][LOW_S_BORROW_AFTER] = F(u64::from(borrow[limb + 1]));
            }
            assert_eq!(
                low_s_numeric_nonzero_count(&forged, &low_s_fixed),
                1,
                "coordinated high-S comparison forgery must reach the final strictness gate"
            );
        }
    }
    #[test]
    fn numeric_evaluators_reject_noncanonical_fields_in_every_opening_group() {
        let trace =
            build_p256_reduction_trace_v1([0_u8; 32]).expect("canonical reduction topology");
        let reduction_fixed = compile_p256_reduction_stark_fixed_rows_v1(LIMBS)
            .expect("verifier reduction preprocessing");
        let reduction_aux = [F::ZERO; P256_REDUCTION_STARK_AUX_WIDTH_V1];
        for column in 0..P256_REDUCTION_BASE_WIDTH_V1 {
            let mut current = trace.base[0];
            current[column] = F(u64::MAX);
            assert_eq!(
                evaluate_p256_reduction_stark_residues_v1(
                    &current,
                    &trace.base[1],
                    &reduction_aux,
                    &reduction_aux,
                    &reduction_fixed[0],
                ),
                Err(P256ReductionAirErrorV1::Constraint)
            );
            let mut next = trace.base[1];
            next[column] = F(u64::MAX);
            assert_eq!(
                evaluate_p256_reduction_stark_residues_v1(
                    &trace.base[0],
                    &next,
                    &reduction_aux,
                    &reduction_aux,
                    &reduction_fixed[0],
                ),
                Err(P256ReductionAirErrorV1::Constraint)
            );
        }
        for column in 0..P256_REDUCTION_STARK_FIXED_WIDTH_V1 {
            let mut fixed = reduction_fixed[0];
            fixed[column] = F(u64::MAX);
            assert_eq!(
                evaluate_p256_reduction_stark_residues_v1(
                    &trace.base[0],
                    &trace.base[1],
                    &reduction_aux,
                    &reduction_aux,
                    &fixed,
                ),
                Err(P256ReductionAirErrorV1::Constraint)
            );
        }
        let mut bad_aux = reduction_aux;
        bad_aux[0] = F(u64::MAX);
        assert_eq!(
            evaluate_p256_reduction_stark_residues_v1(
                &trace.base[0],
                &trace.base[1],
                &bad_aux,
                &reduction_aux,
                &reduction_fixed[0],
            ),
            Err(P256ReductionAirErrorV1::Constraint)
        );
        assert_eq!(
            evaluate_p256_reduction_stark_residues_v1(
                &trace.base[0],
                &trace.base[1],
                &reduction_aux,
                &bad_aux,
                &reduction_fixed[0],
            ),
            Err(P256ReductionAirErrorV1::Constraint)
        );
        let low_s = build_p256_low_s_trace_v1(P256_LOW_S_MAXIMUM_BE_V1).expect("canonical low-S");
        let low_s_fixed =
            compile_p256_low_s_stark_fixed_rows_v1(LIMBS).expect("verifier low-S preprocessing");
        let low_s_aux = [F::ZERO; P256_LOW_S_STARK_AUX_WIDTH_V1];
        for column in 0..P256_LOW_S_BASE_WIDTH_V1 {
            let mut current = low_s.base[0];
            current[column] = F(u64::MAX);
            assert_eq!(
                evaluate_p256_low_s_stark_residues_v1(
                    &current,
                    &low_s.base[1],
                    &low_s_aux,
                    &low_s_aux,
                    &low_s_fixed[0],
                ),
                Err(P256ReductionAirErrorV1::Constraint)
            );
            let mut next = low_s.base[1];
            next[column] = F(u64::MAX);
            assert_eq!(
                evaluate_p256_low_s_stark_residues_v1(
                    &low_s.base[0],
                    &next,
                    &low_s_aux,
                    &low_s_aux,
                    &low_s_fixed[0],
                ),
                Err(P256ReductionAirErrorV1::Constraint)
            );
        }
        for column in 0..P256_LOW_S_STARK_FIXED_WIDTH_V1 {
            let mut fixed = low_s_fixed[0];
            fixed[column] = F(u64::MAX);
            assert_eq!(
                evaluate_p256_low_s_stark_residues_v1(
                    &low_s.base[0],
                    &low_s.base[1],
                    &low_s_aux,
                    &low_s_aux,
                    &fixed,
                ),
                Err(P256ReductionAirErrorV1::Constraint)
            );
        }
        let mut bad_aux = low_s_aux;
        bad_aux[0] = F(u64::MAX);
        assert_eq!(
            evaluate_p256_low_s_stark_residues_v1(
                &low_s.base[0],
                &low_s.base[1],
                &bad_aux,
                &low_s_aux,
                &low_s_fixed[0],
            ),
            Err(P256ReductionAirErrorV1::Constraint)
        );
        assert_eq!(
            evaluate_p256_low_s_stark_residues_v1(
                &low_s.base[0],
                &low_s.base[1],
                &low_s_aux,
                &bad_aux,
                &low_s_fixed[0],
            ),
            Err(P256ReductionAirErrorV1::Constraint)
        );
    }
}
