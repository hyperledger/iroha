//! Verifier-derived algebraic openings for zk-X509 fixed columns.
//!
//! Fixed columns are protocol constants, not prover witnesses.  This module
//! therefore commits their exact algebraic schedule in the compiled profile
//! and evaluates that schedule directly at transcript-derived verifier query
//! points.  It deliberately has no proof codec, artifact reader, cache,
//! Merkle tree, or prover-supplied fixed material.
//!
//! A schedule is an additive, canonically ordered collection of compact atoms:
//! contiguous affine ranges, affine values repeated at a fixed row stride, and
//! isolated sparse values.  Overlap has explicit field-addition semantics.
//! Canonical ordering and exact-duplicate rejection make one compiler output
//! deterministic, while the descriptor digest intentionally distinguishes
//! semantically equivalent alternate decompositions.  Evaluation groups
//! extension-domain query indices by their residue modulo the blowup.  One
//! native-domain Lagrange table and its two prefix sums serve every query in a
//! residue group.  Consequently the working set is
//! `O(native_size + query_count * width + atom_count)`, never a materialized
//! `native_size * width` matrix or an LDE table.
//!
//! The extension-point evaluator uses the same schedule and sum kernels with
//! quartic-field weights. It evaluates the actual fixed polynomials at `z`,
//! without treating an extension element as an LDE index or a selector bit.
use super::stark::ZK_X509_FIXED_DIGEST_CONTEXT_V1;
#[cfg(test)]
use crate::privacy_engines::transparent_stark::goldilocks_batch_invert_v1;
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_MODULUS_V1, GoldilocksFieldV1 as F, GoldilocksFp4V1 as E, PolynomialAirFieldV1,
    PrivacyOuterDigestV1, TransparentStarkErrorV1, goldilocks_primitive_root_v1,
    privacy_outer_digest_frame_v1,
};
use core::cmp::Ordering;
use std::vec::Vec;
use thiserror::Error;
#[cfg(test)]
#[path = "fixed_algebraic_oods_tests.rs"]
mod oods_tests;
/// Exact first-release semantics committed alongside every schedule digest.
pub const ZK_X509_FIXED_ALGEBRAIC_DESCRIPTOR_V1: &[u8] = b"zk-x509-fixed-algebraic-v1-incompatible:verifier-derived-only:no-proof-fixed-material:no-artifact:no-merkle:additive-canonical-atoms=affine-range+repeated-affine-stride+sparse:overlap=goldilocks-field-addition:exact-duplicate-atoms-rejected:semantically-equivalent-alternate-decompositions-have-distinct-descriptor-digests:goldilocks-modulus=0xffffffff00000001:native-root-domain:generator-shifted-lde-coset:coset-disjoint-from-lde-subgroup:query-index-derived-point:residue-grouped-barycentric-lagrange:batch-inverted-native-denominators:cyclic-prefix-affine-sums:repeated-sums=generic-gcd-cycles+reduced-stride-modular-inverse+cyclic-weight-and-ordinal-prefixes+per-stride-min-direct-occurrence-work-vs-native-prefix-work:one-column-native-streaming:no-native-times-width-or-lde-table:bounded-native20-lde25-blowup8-width472-atoms65536-queries272-output-fields128384-work2pow28:digest=sha3-384-opaque48:wire=X5K1+u16be-version1+u16be-header24+native-log2-u8+lde-log2-u8+width-u16be+atom-count-u32be+coset-shift-u64be+canonical-variable-atoms:first-release-no-legacy";
const ZK_X509_FIXED_ALGEBRAIC_MAGIC_V1: [u8; 4] = *b"X5K1";
const ZK_X509_FIXED_ALGEBRAIC_VERSION_V1: u16 = 1;
const ZK_X509_FIXED_ALGEBRAIC_HEADER_BYTES_V1: u16 = 24;
const ZK_X509_FIXED_ALGEBRAIC_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:fixed-algebraic:schedule:v1";
const ZK_X509_FIXED_ALGEBRAIC_AFFINE_TAG_V1: u8 = 1;
const ZK_X509_FIXED_ALGEBRAIC_REPEATED_TAG_V1: u8 = 2;
const ZK_X509_FIXED_ALGEBRAIC_SPARSE_TAG_V1: u8 = 3;
const ZK_X509_FIXED_ALGEBRAIC_AFFINE_BYTES_V1: usize = 35;
const ZK_X509_FIXED_ALGEBRAIC_REPEATED_BYTES_V1: usize = 43;
const ZK_X509_FIXED_ALGEBRAIC_SPARSE_BYTES_V1: usize = 19;
const ZK_X509_FIXED_ALGEBRAIC_BUILDER_GROWTH_V1: usize = 256;
/// Largest native domain accepted by the first-release kernel.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_NATIVE_LOG2_V1: u8 = 20;
/// Largest extension domain accepted by the first-release kernel.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_LDE_LOG2_V1: u8 = 25;
/// Largest supported LDE-to-native power-of-two ratio.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_BLOWUP_LOG2_V1: u8 = 8;
/// Largest fixed-column width accepted by one schedule.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1: u16 = 472;
/// Largest canonical atom collection accepted by one schedule.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1: usize = 65_536;
#[cfg(test)]
/// Largest canonical verifier query set accepted in one batch.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1: usize = 272;
#[cfg(test)]
/// Largest row-major result, measured in Goldilocks elements.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_OUTPUT_FIELDS_V1: usize = 272 * 472;
/// Deterministic cap on the evaluator's coarse field-operation work score.
pub const ZK_X509_FIXED_ALGEBRAIC_MAX_EVALUATION_WORK_V1: u64 = 1_u64 << 28;
/// Fail-closed error from construction, binding, or deterministic evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509FixedAlgebraicErrorV1 {
    /// Native or extension-domain geometry is outside the release profile.
    #[error("zk-X509 algebraic fixed domain is invalid")]
    InvalidDomain,
    /// Fixed-column width is zero or exceeds the release profile.
    #[error("zk-X509 algebraic fixed width is invalid")]
    InvalidWidth,
    /// An atom has an invalid shape or lies outside its schedule.
    #[error("zk-X509 algebraic fixed atom is invalid")]
    InvalidAtom,
    /// The atom collection has a redundant or otherwise non-canonical entry.
    #[error("zk-X509 algebraic fixed schedule is non-canonical")]
    NonCanonicalSchedule,
    /// A supplied Goldilocks value is not a canonical residue.
    #[error("zk-X509 algebraic fixed field is non-canonical")]
    NonCanonicalField,
    /// Query indices are empty, unordered, duplicated, or outside the LDE.
    #[error("zk-X509 algebraic fixed query set is invalid")]
    InvalidQuery,
    /// A first-release count or deterministic work cap was exceeded.
    #[error("zk-X509 algebraic fixed resource limit exceeded")]
    LimitExceeded,
    /// Checked integer arithmetic could not represent the requested shape.
    #[error("zk-X509 algebraic fixed integer arithmetic overflowed")]
    IntegerOverflow,
    /// A bounded allocation could not be satisfied.
    #[error("zk-X509 algebraic fixed bounded allocation failed")]
    AllocationFailure,
    /// A requested barycentric denominator has no inverse.
    #[error("zk-X509 algebraic fixed attempted to invert zero")]
    DivisionByZero,
    /// A compiled schedule does not match its expected descriptor digest.
    #[cfg(test)]
    #[error("zk-X509 algebraic fixed descriptor digest mismatch")]
    DescriptorMismatch,
    /// An invariant of an already checked schedule was violated.
    #[error("zk-X509 algebraic fixed internal invariant failed")]
    InternalInvariant,
}
fn map_transparent_error_v1(error: TransparentStarkErrorV1) -> ZkX509FixedAlgebraicErrorV1 {
    match error {
        TransparentStarkErrorV1::InvalidDomain | TransparentStarkErrorV1::DomainTooLarge => {
            ZkX509FixedAlgebraicErrorV1::InvalidDomain
        }
        TransparentStarkErrorV1::DivisionByZero => ZkX509FixedAlgebraicErrorV1::DivisionByZero,
        TransparentStarkErrorV1::NonCanonicalField => {
            ZkX509FixedAlgebraicErrorV1::NonCanonicalField
        }
        TransparentStarkErrorV1::AllocationFailure => {
            ZkX509FixedAlgebraicErrorV1::AllocationFailure
        }
        _ => ZkX509FixedAlgebraicErrorV1::InternalInvariant,
    }
}
fn canonical_field_v1(value: F) -> bool {
    value.value() < GOLDILOCKS_MODULUS_V1
}
/// Checked native and extension-domain geometry for one fixed schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509FixedAlgebraicDomainV1 {
    native_log2: u8,
    lde_log2: u8,
    coset_shift: F,
}
impl ZkX509FixedAlgebraicDomainV1 {
    /// Construct a release-bounded, subgroup-disjoint evaluation domain.
    pub(crate) fn new_v1(
        native_log2: u8,
        lde_log2: u8,
        coset_shift: F,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        if native_log2 == 0
            || native_log2 > ZK_X509_FIXED_ALGEBRAIC_MAX_NATIVE_LOG2_V1
            || lde_log2 <= native_log2
            || lde_log2 > ZK_X509_FIXED_ALGEBRAIC_MAX_LDE_LOG2_V1
            || lde_log2 - native_log2 > ZK_X509_FIXED_ALGEBRAIC_MAX_BLOWUP_LOG2_V1
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain);
        }
        if !canonical_field_v1(coset_shift) {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
        }
        if coset_shift == F::ZERO {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain);
        }
        let lde_size = 1_u64
            .checked_shl(u32::from(lde_log2))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if coset_shift.pow(u128::from(lde_size)) == F::ONE {
            // The shift is in the LDE subgroup, so its coset can intersect the
            // native interpolation domain and create a zero denominator.
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain);
        }
        let native_root =
            goldilocks_primitive_root_v1(native_log2).map_err(map_transparent_error_v1)?;
        let lde_root = goldilocks_primitive_root_v1(lde_log2).map_err(map_transparent_error_v1)?;
        let blowup = 1_u64
            .checked_shl(u32::from(lde_log2 - native_log2))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if lde_root.pow(u128::from(blowup)) != native_root {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(Self {
            native_log2,
            lde_log2,
            coset_shift,
        })
    }
    /// Native-domain base-two logarithm.
    #[cfg(test)]
    pub(crate) const fn native_log2_v1(self) -> u8 {
        self.native_log2
    }
    /// Extension-domain base-two logarithm.
    #[cfg(test)]
    pub(crate) const fn lde_log2_v1(self) -> u8 {
        self.lde_log2
    }
    /// Canonical multiplicative coset shift.
    #[cfg(test)]
    pub(crate) const fn coset_shift_v1(self) -> F {
        self.coset_shift
    }
    /// Exact native-domain size.
    pub(crate) fn native_size_v1(self) -> Result<u64, ZkX509FixedAlgebraicErrorV1> {
        1_u64
            .checked_shl(u32::from(self.native_log2))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
    }
    #[cfg(test)]
    /// Exact extension-domain size.
    pub(crate) fn lde_size_v1(self) -> Result<u64, ZkX509FixedAlgebraicErrorV1> {
        1_u64
            .checked_shl(u32::from(self.lde_log2))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
    }
    #[cfg(test)]
    /// Exact power-of-two LDE blowup.
    pub(crate) fn blowup_v1(self) -> Result<u64, ZkX509FixedAlgebraicErrorV1> {
        1_u64
            .checked_shl(u32::from(self.lde_log2 - self.native_log2))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
    }
    /// Map one canonical extension-domain index to its verifier point.
    #[cfg(test)]
    pub(crate) fn query_point_v1(self, query_index: u64) -> Result<F, ZkX509FixedAlgebraicErrorV1> {
        if query_index >= self.lde_size_v1()? {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        let root = goldilocks_primitive_root_v1(self.lde_log2).map_err(map_transparent_error_v1)?;
        let point = self.coset_shift.mul(root.pow(u128::from(query_index)));
        if point.pow(u128::from(self.native_size_v1()?)) == F::ONE {
            return Err(ZkX509FixedAlgebraicErrorV1::DivisionByZero);
        }
        Ok(point)
    }
}
/// One additive compact atom in a verifier-owned native fixed schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkX509FixedAlgebraicAtomV1 {
    /// `value(row) = start_value + step * (row - start)` for `start..end`.
    Affine {
        /// Fixed-column index.
        column: u16,
        /// Inclusive native row.
        start: u64,
        /// Exclusive native row.
        end: u64,
        /// Value at `start`.
        start_value: F,
        /// Per-row field increment.
        step: F,
    },
    /// At occurrence `k`, row `first + k * stride` receives
    /// `start_value + k * step`.
    Repeated {
        /// Fixed-column index.
        column: u16,
        /// First native row.
        first: u64,
        /// Number of occurrences.
        count: u64,
        /// Positive row stride.
        stride: u64,
        /// Value at occurrence zero.
        start_value: F,
        /// Per-occurrence field increment.
        step: F,
    },
    /// One isolated native row value.
    Sparse {
        /// Fixed-column index.
        column: u16,
        /// Native row.
        row: u64,
        /// Nonzero contribution.
        value: F,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AtomOrderKeyV1 {
    column: u16,
    first_row: u64,
    tag: u8,
    shape_a: u64,
    shape_b: u64,
    value_a: u64,
    value_b: u64,
}
impl ZkX509FixedAlgebraicAtomV1 {
    /// Construct one non-redundant contiguous affine range.
    pub(crate) fn affine_v1(
        column: u16,
        start: u64,
        end: u64,
        start_value: F,
        step: F,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        if end.checked_sub(start).is_none_or(|length| length < 2) {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom);
        }
        if !canonical_field_v1(start_value) || !canonical_field_v1(step) {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
        }
        if start_value == F::ZERO && step == F::ZERO {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule);
        }
        Ok(Self::Affine {
            column,
            start,
            end,
            start_value,
            step,
        })
    }
    /// Construct a constant contribution at an arithmetic progression of rows.
    pub(crate) fn repeated_v1(
        column: u16,
        first: u64,
        count: u64,
        stride: u64,
        value: F,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        Self::repeated_affine_v1(column, first, count, stride, value, F::ZERO)
    }
    /// Construct an affine value sequence at an arithmetic progression of rows.
    pub(crate) fn repeated_affine_v1(
        column: u16,
        first: u64,
        count: u64,
        stride: u64,
        start_value: F,
        step: F,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        if count < 2 || stride < 2 {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom);
        }
        count
            .checked_sub(1)
            .and_then(|last| last.checked_mul(stride))
            .and_then(|offset| first.checked_add(offset))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if !canonical_field_v1(start_value) || !canonical_field_v1(step) {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
        }
        if start_value == F::ZERO && step == F::ZERO {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule);
        }
        Ok(Self::Repeated {
            column,
            first,
            count,
            stride,
            start_value,
            step,
        })
    }
    /// Construct one nonzero isolated row contribution.
    pub(crate) fn sparse_v1(
        column: u16,
        row: u64,
        value: F,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        if !canonical_field_v1(value) {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
        }
        if value == F::ZERO {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule);
        }
        Ok(Self::Sparse { column, row, value })
    }
    fn column_v1(self) -> u16 {
        match self {
            Self::Affine { column, .. }
            | Self::Repeated { column, .. }
            | Self::Sparse { column, .. } => column,
        }
    }
    fn order_key_v1(self) -> AtomOrderKeyV1 {
        match self {
            Self::Affine {
                column,
                start,
                end,
                start_value,
                step,
            } => AtomOrderKeyV1 {
                column,
                first_row: start,
                tag: ZK_X509_FIXED_ALGEBRAIC_AFFINE_TAG_V1,
                shape_a: end,
                shape_b: 0,
                value_a: start_value.value(),
                value_b: step.value(),
            },
            Self::Repeated {
                column,
                first,
                count,
                stride,
                start_value,
                step,
            } => AtomOrderKeyV1 {
                column,
                first_row: first,
                tag: ZK_X509_FIXED_ALGEBRAIC_REPEATED_TAG_V1,
                shape_a: count,
                shape_b: stride,
                value_a: start_value.value(),
                value_b: step.value(),
            },
            Self::Sparse { column, row, value } => AtomOrderKeyV1 {
                column,
                first_row: row,
                tag: ZK_X509_FIXED_ALGEBRAIC_SPARSE_TAG_V1,
                shape_a: 0,
                shape_b: 0,
                value_a: value.value(),
                value_b: 0,
            },
        }
    }
    fn canonical_cmp_v1(self, other: Self) -> Ordering {
        self.order_key_v1().cmp(&other.order_key_v1())
    }
    fn encoded_len_v1(self) -> usize {
        match self {
            Self::Affine { .. } => ZK_X509_FIXED_ALGEBRAIC_AFFINE_BYTES_V1,
            Self::Repeated { .. } => ZK_X509_FIXED_ALGEBRAIC_REPEATED_BYTES_V1,
            Self::Sparse { .. } => ZK_X509_FIXED_ALGEBRAIC_SPARSE_BYTES_V1,
        }
    }
    fn validate_for_schedule_v1(
        self,
        native_size: u64,
        width: u16,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if self.column_v1() >= width {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom);
        }
        match self {
            Self::Affine {
                start,
                end,
                start_value,
                step,
                ..
            } => {
                if end.checked_sub(start).is_none_or(|length| length < 2)
                    || end > native_size
                    || !canonical_field_v1(start_value)
                    || !canonical_field_v1(step)
                    || (start_value == F::ZERO && step == F::ZERO)
                {
                    return Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom);
                }
            }
            Self::Repeated {
                first,
                count,
                stride,
                start_value,
                step,
                ..
            } => {
                let last = count
                    .checked_sub(1)
                    .filter(|_| count >= 2 && stride >= 2)
                    .and_then(|last| last.checked_mul(stride))
                    .and_then(|offset| first.checked_add(offset))
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InvalidAtom)?;
                if last >= native_size
                    || !canonical_field_v1(start_value)
                    || !canonical_field_v1(step)
                    || (start_value == F::ZERO && step == F::ZERO)
                {
                    return Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom);
                }
            }
            Self::Sparse { row, value, .. } => {
                if row >= native_size || !canonical_field_v1(value) || value == F::ZERO {
                    return Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom);
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn contribution_at_native_row_v1(
        self,
        row: u64,
    ) -> Result<Option<F>, ZkX509FixedAlgebraicErrorV1> {
        match self {
            Self::Affine {
                start,
                end,
                start_value,
                step,
                ..
            } => {
                if row < start || row >= end {
                    return Ok(None);
                }
                let offset = row
                    .checked_sub(start)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                Ok(Some(start_value.add(step.mul(F(offset)))))
            }
            Self::Repeated {
                first,
                count,
                stride,
                start_value,
                step,
                ..
            } => {
                let Some(delta) = row.checked_sub(first) else {
                    return Ok(None);
                };
                if delta % stride != 0 {
                    return Ok(None);
                }
                let occurrence = delta / stride;
                if occurrence >= count {
                    return Ok(None);
                }
                Ok(Some(start_value.add(step.mul(F(occurrence)))))
            }
            Self::Sparse {
                row: atom_row,
                value,
                ..
            } => Ok((row == atom_row).then_some(value)),
        }
    }
}
/// Incremental checked builder for one canonical fixed schedule.
pub struct ZkX509FixedAlgebraicScheduleBuilderV1 {
    domain: ZkX509FixedAlgebraicDomainV1,
    width: u16,
    atoms: Vec<ZkX509FixedAlgebraicAtomV1>,
}
impl ZkX509FixedAlgebraicScheduleBuilderV1 {
    /// Start a release-bounded schedule.
    pub(crate) fn new_v1(
        domain: ZkX509FixedAlgebraicDomainV1,
        width: u16,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        validate_width_v1(width)?;
        Ok(Self {
            domain,
            width,
            atoms: Vec::new(),
        })
    }
    /// Add one already checked atom.  Ordering is canonicalized by `finish_v1`.
    pub(crate) fn push_atom_v1(
        &mut self,
        atom: ZkX509FixedAlgebraicAtomV1,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if self.atoms.len() >= ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded);
        }
        atom.validate_for_schedule_v1(self.domain.native_size_v1()?, self.width)?;
        if self.atoms.len() == self.atoms.capacity() {
            let remaining = ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1
                .checked_sub(self.atoms.len())
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            self.atoms
                .try_reserve_exact(remaining.min(ZK_X509_FIXED_ALGEBRAIC_BUILDER_GROWTH_V1))
                .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        }
        self.atoms.push(atom);
        Ok(())
    }
    /// Add one contiguous affine range.
    pub(crate) fn push_affine_v1(
        &mut self,
        column: u16,
        start: u64,
        end: u64,
        start_value: F,
        step: F,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        self.push_atom_v1(ZkX509FixedAlgebraicAtomV1::affine_v1(
            column,
            start,
            end,
            start_value,
            step,
        )?)
    }
    /// Add an affine repeated contribution.
    pub(crate) fn push_repeated_affine_v1(
        &mut self,
        column: u16,
        first: u64,
        count: u64,
        stride: u64,
        start_value: F,
        step: F,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        self.push_atom_v1(ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(
            column,
            first,
            count,
            stride,
            start_value,
            step,
        )?)
    }
    /// Add one isolated value.
    pub(crate) fn push_sparse_v1(
        &mut self,
        column: u16,
        row: u64,
        value: F,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        self.push_atom_v1(ZkX509FixedAlgebraicAtomV1::sparse_v1(column, row, value)?)
    }
    /// Canonicalize, bind, and close the schedule.
    pub(crate) fn finish_v1(
        self,
    ) -> Result<ZkX509FixedAlgebraicScheduleV1, ZkX509FixedAlgebraicErrorV1> {
        ZkX509FixedAlgebraicScheduleV1::new_v1(self.domain, self.width, self.atoms)
    }
}
fn validate_width_v1(width: u16) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
    if width == 0 || width > ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1 {
        return Err(ZkX509FixedAlgebraicErrorV1::InvalidWidth);
    }
    Ok(())
}
/// Closed, immutable, canonically bound verifier-owned fixed schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509FixedAlgebraicScheduleV1 {
    domain: ZkX509FixedAlgebraicDomainV1,
    width: u16,
    atoms: Vec<ZkX509FixedAlgebraicAtomV1>,
    descriptor_digest: PrivacyOuterDigestV1,
}
impl ZkX509FixedAlgebraicScheduleV1 {
    /// Check, canonically order, and bind an additive atom collection.
    pub(crate) fn new_v1(
        domain: ZkX509FixedAlgebraicDomainV1,
        width: u16,
        mut atoms: Vec<ZkX509FixedAlgebraicAtomV1>,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        validate_width_v1(width)?;
        if atoms.is_empty() {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule);
        }
        if atoms.len() > ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded);
        }
        let native_size = domain.native_size_v1()?;
        for atom in atoms.iter().copied() {
            atom.validate_for_schedule_v1(native_size, width)?;
        }
        atoms.sort_unstable_by(|left, right| left.canonical_cmp_v1(*right));
        if atoms.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left == right)
        }) {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule);
        }
        let mut schedule = Self {
            domain,
            width,
            atoms,
            descriptor_digest: PrivacyOuterDigestV1::default(),
        };
        let descriptor = schedule.canonical_descriptor_v1()?;
        schedule.descriptor_digest = privacy_outer_digest_frame_v1(
            ZK_X509_FIXED_DIGEST_CONTEXT_V1,
            ZK_X509_FIXED_ALGEBRAIC_DIGEST_DOMAIN_V1,
            b"verifier-fixed-algebraic-schedule",
            0,
            0,
            0,
            &[ZK_X509_FIXED_ALGEBRAIC_DESCRIPTOR_V1, &descriptor],
        )
        .map_err(map_transparent_error_v1)?;
        Ok(schedule)
    }
    /// Checked domain geometry.
    pub(crate) const fn domain_v1(&self) -> ZkX509FixedAlgebraicDomainV1 {
        self.domain
    }
    /// Exact fixed-column width.
    pub(crate) const fn width_v1(&self) -> u16 {
        self.width
    }
    /// Canonical atom order committed by the schedule digest.
    pub(crate) fn atoms_v1(&self) -> &[ZkX509FixedAlgebraicAtomV1] {
        &self.atoms
    }
    /// Exact canonical big-endian descriptor bytes.
    pub(crate) fn canonical_descriptor_v1(&self) -> Result<Vec<u8>, ZkX509FixedAlgebraicErrorV1> {
        let mut encoded_len = usize::from(ZK_X509_FIXED_ALGEBRAIC_HEADER_BYTES_V1);
        for atom in self.atoms.iter().copied() {
            encoded_len = encoded_len
                .checked_add(atom.encoded_len_v1())
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        encoded.extend_from_slice(&ZK_X509_FIXED_ALGEBRAIC_MAGIC_V1);
        encoded.extend_from_slice(&ZK_X509_FIXED_ALGEBRAIC_VERSION_V1.to_be_bytes());
        encoded.extend_from_slice(&ZK_X509_FIXED_ALGEBRAIC_HEADER_BYTES_V1.to_be_bytes());
        encoded.push(self.domain.native_log2);
        encoded.push(self.domain.lde_log2);
        encoded.extend_from_slice(&self.width.to_be_bytes());
        encoded.extend_from_slice(
            &u32::try_from(self.atoms.len())
                .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&self.domain.coset_shift.value().to_be_bytes());
        for atom in self.atoms.iter().copied() {
            match atom {
                ZkX509FixedAlgebraicAtomV1::Affine {
                    column,
                    start,
                    end,
                    start_value,
                    step,
                } => {
                    encoded.push(ZK_X509_FIXED_ALGEBRAIC_AFFINE_TAG_V1);
                    encoded.extend_from_slice(&column.to_be_bytes());
                    encoded.extend_from_slice(&start.to_be_bytes());
                    encoded.extend_from_slice(&end.to_be_bytes());
                    encoded.extend_from_slice(&start_value.value().to_be_bytes());
                    encoded.extend_from_slice(&step.value().to_be_bytes());
                }
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column,
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                } => {
                    encoded.push(ZK_X509_FIXED_ALGEBRAIC_REPEATED_TAG_V1);
                    encoded.extend_from_slice(&column.to_be_bytes());
                    encoded.extend_from_slice(&first.to_be_bytes());
                    encoded.extend_from_slice(&count.to_be_bytes());
                    encoded.extend_from_slice(&stride.to_be_bytes());
                    encoded.extend_from_slice(&start_value.value().to_be_bytes());
                    encoded.extend_from_slice(&step.value().to_be_bytes());
                }
                ZkX509FixedAlgebraicAtomV1::Sparse { column, row, value } => {
                    encoded.push(ZK_X509_FIXED_ALGEBRAIC_SPARSE_TAG_V1);
                    encoded.extend_from_slice(&column.to_be_bytes());
                    encoded.extend_from_slice(&row.to_be_bytes());
                    encoded.extend_from_slice(&value.value().to_be_bytes());
                }
            }
        }
        if encoded.len() != encoded_len {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(encoded)
    }
    /// SHA3-384 digest of protocol semantics and exact canonical bytes.
    pub(crate) const fn descriptor_digest_v1(&self) -> PrivacyOuterDigestV1 {
        self.descriptor_digest
    }
    /// Fail closed unless the compiled profile pins this exact schedule.
    #[cfg(test)]
    pub(crate) fn verify_descriptor_digest_v1(
        &self,
        expected: &PrivacyOuterDigestV1,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if self.descriptor_digest != *expected {
            return Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch);
        }
        Ok(())
    }
    /// Evaluate one native row without constructing a native matrix.
    #[cfg(test)]
    pub(crate) fn native_row_v1(
        &self,
        row: u64,
        output: &mut [F],
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if row >= self.domain.native_size_v1()? || output.len() != usize::from(self.width) {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        output.fill(F::ZERO);
        for atom in self.atoms.iter().copied() {
            let Some(value) = atom.contribution_at_native_row_v1(row)? else {
                continue;
            };
            let target = output
                .get_mut(usize::from(atom.column_v1()))
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            *target = target.add(value);
        }
        Ok(())
    }
    /// Fill one complete native fixed column for a one-column-at-a-time IFFT.
    ///
    /// The caller owns exactly `native_size` fields.  The method clears that
    /// buffer and applies only atoms for `column`, so its working memory is
    /// `O(native_size)` and never `native_size * width`.
    #[cfg(test)]
    pub(crate) fn fill_native_column_v1(
        &self,
        column: u16,
        output: &mut [F],
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        let native_size = usize::try_from(self.domain.native_size_v1()?)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if column >= self.width || output.len() != native_size {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        output.fill(F::ZERO);
        for atom in self
            .atoms
            .iter()
            .copied()
            .filter(|atom| atom.column_v1() == column)
        {
            match atom {
                ZkX509FixedAlgebraicAtomV1::Affine {
                    start,
                    end,
                    start_value,
                    step,
                    ..
                } => {
                    let start = usize::try_from(start)
                        .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                    let end = usize::try_from(end)
                        .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                    let range = output
                        .get_mut(start..end)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                    let mut value = start_value;
                    for target in range {
                        *target = target.add(value);
                        value = value.add(step);
                    }
                }
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                    ..
                } => {
                    let mut row = first;
                    let mut value = start_value;
                    for occurrence in 0..count {
                        let target = output
                            .get_mut(
                                usize::try_from(row)
                                    .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
                            )
                            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                        *target = target.add(value);
                        if occurrence.checked_add(1).is_some_and(|next| next < count) {
                            row = row
                                .checked_add(stride)
                                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                            value = value.add(step);
                        }
                    }
                }
                ZkX509FixedAlgebraicAtomV1::Sparse { row, value, .. } => {
                    let target = output
                        .get_mut(
                            usize::try_from(row)
                                .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
                        )
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                    *target = target.add(value);
                }
            }
        }
        if output
            .iter()
            .copied()
            .any(|value| !canonical_field_v1(value))
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(())
    }
    #[cfg(test)]
    /// Evaluate every fixed column at sorted, unique verifier LDE indices.
    pub(crate) fn evaluate_query_indices_v1(
        &self,
        query_indices: &[u64],
    ) -> Result<ZkX509FixedAlgebraicOpeningsV1, ZkX509FixedAlgebraicErrorV1> {
        validate_query_indices_v1(self.domain, query_indices)?;
        let width = usize::from(self.width);
        let output_fields = query_indices
            .len()
            .checked_mul(width)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if output_fields > ZK_X509_FIXED_ALGEBRAIC_MAX_OUTPUT_FIELDS_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded);
        }
        let blowup = self.domain.blowup_v1()?;
        let native_size = self.domain.native_size_v1()?;
        let native_size_usize = usize::try_from(native_size)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let mut grouped = Vec::new();
        grouped
            .try_reserve_exact(query_indices.len())
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for (slot, index) in query_indices.iter().copied().enumerate() {
            grouped.push(GroupedQueryV1 {
                remainder: index % blowup,
                shift: index / blowup,
                slot,
            });
        }
        grouped.sort_unstable_by_key(|query| (query.remainder, query.shift, query.slot));
        let (repeated_references, repeated_runs) = repeated_stride_plan_v1(&self.atoms)?;
        self.validate_evaluation_work_v1(
            &grouped,
            &repeated_references,
            &repeated_runs,
            native_size,
        )?;
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(output_fields)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        fields.resize(output_fields, F::ZERO);
        let mut group_start = 0_usize;
        while group_start < grouped.len() {
            let first = grouped
                .get(group_start)
                .copied()
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            let mut group_end = group_start
                .checked_add(1)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            while grouped
                .get(group_end)
                .is_some_and(|query| query.remainder == first.remainder)
            {
                group_end = group_end
                    .checked_add(1)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            }
            let table = LagrangeTableV1::new_v1(self.domain, first.remainder)?;
            let group_queries = grouped
                .get(group_start..group_end)
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            for query in group_queries {
                let row_start = query
                    .slot
                    .checked_mul(width)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                let row_end = row_start
                    .checked_add(width)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                let row = fields
                    .get_mut(row_start..row_end)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                let shift = usize::try_from(query.shift)
                    .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                if shift >= native_size_usize {
                    return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
                }
                for atom in self
                    .atoms
                    .iter()
                    .copied()
                    .filter(|atom| !matches!(atom, ZkX509FixedAlgebraicAtomV1::Repeated { .. }))
                {
                    let contribution = table.non_repeated_atom_sum_v1(atom, shift)?;
                    let target = row
                        .get_mut(usize::from(atom.column_v1()))
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                    *target = target.add(contribution);
                }
            }
            for run in repeated_runs.iter().copied() {
                let references = repeated_references
                    .get(run.references_start..run.references_end)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                let use_table =
                    repeated_stride_uses_table_v1(run, group_queries.len(), native_size)?;
                let stride_table = use_table
                    .then(|| CyclicStrideTableV1::new_v1(&table.weights, run.stride))
                    .transpose()?;
                for query in group_queries {
                    let row_start = query
                        .slot
                        .checked_mul(width)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                    let row_end = row_start
                        .checked_add(width)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                    let row = fields
                        .get_mut(row_start..row_end)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                    let shift = usize::try_from(query.shift)
                        .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                    for reference in references {
                        let atom = self
                            .atoms
                            .get(reference.atom_index)
                            .copied()
                            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                        let contribution = if let Some(stride_table) = &stride_table {
                            stride_table.repeated_atom_sum_v1(atom, shift)?
                        } else {
                            table.repeated_atom_sum_naive_v1(atom, shift)?
                        };
                        let target = row
                            .get_mut(usize::from(atom.column_v1()))
                            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                        *target = target.add(contribution);
                    }
                }
            }
            group_start = group_end;
        }
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(query_indices.len())
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        indices.extend_from_slice(query_indices);
        Ok(ZkX509FixedAlgebraicOpeningsV1 {
            schedule_digest: self.descriptor_digest,
            query_indices: indices,
            width: self.width,
            fields,
        })
    }
    /// Evaluate the native fixed polynomials at a canonical quartic-field point.
    ///
    /// Only native subgroup points are rejected here: embedded base-field
    /// points outside that subgroup are useful for differential validation.
    /// The enclosing DEEP verifier must additionally enforce its challenge
    /// admissibility rules. No prover-supplied fixed values are accepted.
    ///
    /// MAIN uses this owner for its complete Fp4 constraint check while keeping
    /// the authenticated scalar relation queries in the current wire format.
    pub(crate) fn evaluate_extension_point_v1(
        &self,
        point: E,
    ) -> Result<Vec<E>, ZkX509FixedAlgebraicErrorV1> {
        if !point.is_canonical() {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
        }
        let native_size = self.domain.native_size_v1()?;
        let (references, runs) = repeated_stride_plan_v1(&self.atoms)?;
        // The same public schedule-work bound applies to one field point.
        // Here its units are extension operations, not base-field operations
        // or elapsed time. Shape and allocations are unchanged by the point.
        self.validate_evaluation_work_v1(
            &[GroupedQueryV1 {
                remainder: 0,
                shift: 0,
                slot: 0,
            }],
            &references,
            &runs,
            native_size,
        )?;
        let table = LagrangeTableV1::<E>::at_extension_point_v1(self.domain, point)?;
        let mut row = Vec::new();
        row.try_reserve_exact(usize::from(self.width))
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        row.resize(usize::from(self.width), E::ZERO);
        for atom in self
            .atoms
            .iter()
            .copied()
            .filter(|atom| !matches!(atom, ZkX509FixedAlgebraicAtomV1::Repeated { .. }))
        {
            let contribution = table.non_repeated_atom_sum_v1(atom, 0)?;
            let target = row
                .get_mut(usize::from(atom.column_v1()))
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            *target = target.add(contribution);
        }
        for run in runs {
            let stride_table = repeated_stride_uses_table_v1(run, 1, native_size)?
                .then(|| CyclicStrideTableV1::new_v1(&table.weights, run.stride))
                .transpose()?;
            for reference in references
                .get(run.references_start..run.references_end)
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?
            {
                let atom = self
                    .atoms
                    .get(reference.atom_index)
                    .copied()
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                let contribution = if let Some(stride_table) = &stride_table {
                    stride_table.repeated_atom_sum_v1(atom, 0)?
                } else {
                    table.repeated_atom_sum_naive_v1(atom, 0)?
                };
                let target = row
                    .get_mut(usize::from(atom.column_v1()))
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                *target = target.add(contribution);
            }
        }
        Ok(row)
    }
    fn validate_evaluation_work_v1(
        &self,
        grouped_queries: &[GroupedQueryV1],
        repeated_references: &[RepeatedAtomReferenceV1],
        repeated_runs: &[RepeatedStrideRunV1],
        native_size: u64,
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if grouped_queries.is_empty()
            || repeated_references.len()
                != repeated_runs.iter().try_fold(
                    0_usize,
                    |total, run| -> Result<usize, ZkX509FixedAlgebraicErrorV1> {
                        total
                            .checked_add(
                                run.references_end
                                    .checked_sub(run.references_start)
                                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?,
                            )
                            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
                    },
                )?
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let query_count = u64::try_from(grouped_queries.len())
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let non_repeated_atoms = self
            .atoms
            .len()
            .checked_sub(repeated_references.len())
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let mut total = u64::try_from(non_repeated_atoms)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
            .checked_mul(query_count)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let mut group_start = 0_usize;
        while group_start < grouped_queries.len() {
            let remainder = grouped_queries
                .get(group_start)
                .map(|query| query.remainder)
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            let mut group_end = group_start;
            while grouped_queries
                .get(group_end)
                .is_some_and(|query| query.remainder == remainder)
            {
                group_end = group_end
                    .checked_add(1)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            }
            let group_query_count = group_end
                .checked_sub(group_start)
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
            total = total
                .checked_add(native_size)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            for run in repeated_runs.iter().copied() {
                let group_query_count_u64 = u64::try_from(group_query_count)
                    .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                let direct = run
                    .total_occurrences
                    .checked_mul(group_query_count_u64)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                let atom_count = u64::try_from(
                    run.references_end
                        .checked_sub(run.references_start)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?,
                )
                .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                let table = native_size
                    .checked_add(
                        atom_count
                            .checked_mul(group_query_count_u64)
                            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
                    )
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                total = total
                    .checked_add(direct.min(table))
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            }
            group_start = group_end;
        }
        if total > ZK_X509_FIXED_ALGEBRAIC_MAX_EVALUATION_WORK_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded);
        }
        Ok(())
    }
}
#[cfg(test)]
fn validate_query_indices_v1(
    domain: ZkX509FixedAlgebraicDomainV1,
    query_indices: &[u64],
) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
    if query_indices.is_empty()
        || query_indices.len() > ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1
        || query_indices.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_none_or(|(left, right)| left >= right)
        })
    {
        return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
    }
    let lde_size = domain.lde_size_v1()?;
    if query_indices
        .last()
        .copied()
        .is_none_or(|last| last >= lde_size)
    {
        return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
    }
    Ok(())
}
#[derive(Clone, Copy)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "query-slot fields serve only the test and release-evidence opened-row evaluator"
    )
)]
struct GroupedQueryV1 {
    remainder: u64,
    shift: u64,
    slot: usize,
}
#[derive(Clone, Copy)]
struct RepeatedAtomReferenceV1 {
    stride: u64,
    atom_index: usize,
    count: u64,
}
#[derive(Clone, Copy)]
struct RepeatedStrideRunV1 {
    stride: u64,
    references_start: usize,
    references_end: usize,
    total_occurrences: u64,
}
fn repeated_stride_plan_v1(
    atoms: &[ZkX509FixedAlgebraicAtomV1],
) -> Result<(Vec<RepeatedAtomReferenceV1>, Vec<RepeatedStrideRunV1>), ZkX509FixedAlgebraicErrorV1> {
    let repeated_count = atoms
        .iter()
        .filter(|atom| matches!(atom, ZkX509FixedAlgebraicAtomV1::Repeated { .. }))
        .count();
    let mut references = Vec::new();
    references
        .try_reserve_exact(repeated_count)
        .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
    for (atom_index, atom) in atoms.iter().copied().enumerate() {
        if let ZkX509FixedAlgebraicAtomV1::Repeated { stride, count, .. } = atom {
            references.push(RepeatedAtomReferenceV1 {
                stride,
                atom_index,
                count,
            });
        }
    }
    references.sort_unstable_by_key(|reference| (reference.stride, reference.atom_index));
    let mut runs = Vec::new();
    runs.try_reserve_exact(references.len())
        .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
    let mut start = 0_usize;
    while start < references.len() {
        let stride = references
            .get(start)
            .map(|reference| reference.stride)
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let mut end = start;
        let mut total_occurrences = 0_u64;
        while references
            .get(end)
            .is_some_and(|reference| reference.stride == stride)
        {
            total_occurrences = total_occurrences
                .checked_add(
                    references
                        .get(end)
                        .map(|reference| reference.count)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?,
                )
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            end = end
                .checked_add(1)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        }
        runs.push(RepeatedStrideRunV1 {
            stride,
            references_start: start,
            references_end: end,
            total_occurrences,
        });
        start = end;
    }
    Ok((references, runs))
}
fn repeated_stride_uses_table_v1(
    run: RepeatedStrideRunV1,
    query_count: usize,
    native_size: u64,
) -> Result<bool, ZkX509FixedAlgebraicErrorV1> {
    let query_count =
        u64::try_from(query_count).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
    let atom_count = u64::try_from(
        run.references_end
            .checked_sub(run.references_start)
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?,
    )
    .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
    let direct = run
        .total_occurrences
        .checked_mul(query_count)
        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
    let table = native_size
        .checked_add(
            atom_count
                .checked_mul(query_count)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
        )
        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
    Ok(table < direct)
}
struct LagrangeTableV1<A = F> {
    native_size: usize,
    weights: Vec<A>,
    prefix: Vec<A>,
    linear_prefix: Vec<A>,
}
impl LagrangeTableV1<F> {
    #[cfg(test)]
    fn new_v1(
        domain: ZkX509FixedAlgebraicDomainV1,
        remainder: u64,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        let native_size_u64 = domain.native_size_v1()?;
        let native_size = usize::try_from(native_size_u64)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let blowup = domain.blowup_v1()?;
        if remainder >= blowup {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let native_root =
            goldilocks_primitive_root_v1(domain.native_log2).map_err(map_transparent_error_v1)?;
        let lde_root =
            goldilocks_primitive_root_v1(domain.lde_log2).map_err(map_transparent_error_v1)?;
        if lde_root.pow(u128::from(blowup)) != native_root {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let point = domain.coset_shift.mul(lde_root.pow(u128::from(remainder)));
        let numerator = point.pow(u128::from(native_size_u64)).sub(F::ONE);
        if numerator == F::ZERO {
            return Err(ZkX509FixedAlgebraicErrorV1::DivisionByZero);
        }
        let inverse_size = F(native_size_u64)
            .inv()
            .ok_or(ZkX509FixedAlgebraicErrorV1::DivisionByZero)?;
        let common = numerator.mul(inverse_size);
        let mut weights = Vec::new();
        weights
            .try_reserve_exact(native_size)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        let mut native_point = F::ONE;
        for _ in 0..native_size {
            weights.push(point.sub(native_point));
            native_point = native_point.mul(native_root);
        }
        if native_point != F::ONE {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        goldilocks_batch_invert_v1(&mut weights).map_err(map_transparent_error_v1)?;
        native_point = F::ONE;
        let mut weight_sum = F::ZERO;
        for weight in &mut weights {
            *weight = common.mul(native_point).mul(*weight);
            weight_sum = weight_sum.add(*weight);
            native_point = native_point.mul(native_root);
        }
        if native_point != F::ONE || weight_sum != F::ONE {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Self::from_weights_v1(weights)
    }
}
impl LagrangeTableV1<E> {
    fn at_extension_point_v1(
        domain: ZkX509FixedAlgebraicDomainV1,
        point: E,
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        if !point.is_canonical() {
            return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
        }
        let native_size_u64 = domain.native_size_v1()?;
        let native_size = usize::try_from(native_size_u64)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let root =
            goldilocks_primitive_root_v1(domain.native_log2).map_err(map_transparent_error_v1)?;
        let numerator = point.pow(u128::from(native_size_u64)).sub(E::ONE);
        if numerator == E::ZERO {
            return Err(ZkX509FixedAlgebraicErrorV1::DivisionByZero);
        }
        let common = numerator.mul_base(
            F(native_size_u64)
                .inv()
                .ok_or(ZkX509FixedAlgebraicErrorV1::DivisionByZero)?,
        );
        // L_j(z) = (z^N - 1) * g^j / (N * (z - g^j)). Batch inversion
        // uses one true Fp4 inverse. These are public fixed/challenge values.
        let mut weights = Vec::new();
        let mut products = Vec::new();
        weights
            .try_reserve_exact(native_size)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        products
            .try_reserve_exact(native_size)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        let mut native_point = F::ONE;
        let mut product = E::ONE;
        for _ in 0..native_size {
            let denominator = point.sub(E::from_base(native_point));
            products.push(product);
            product = product.mul(denominator);
            weights.push(denominator);
            native_point = native_point.mul(root);
        }
        if native_point != F::ONE {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let mut inverse = product
            .inv()
            .ok_or(ZkX509FixedAlgebraicErrorV1::DivisionByZero)?;
        for (weight, prefix) in weights.iter_mut().zip(&products).rev() {
            let denominator = *weight;
            *weight = inverse.mul(*prefix);
            inverse = inverse.mul(denominator);
        }
        drop(products);
        native_point = F::ONE;
        for weight in &mut weights {
            *weight = common.mul_base(native_point).mul(*weight);
            native_point = native_point.mul(root);
        }
        Self::from_weights_v1(weights)
    }
}
impl<A: PolynomialAirFieldV1 + PartialEq> LagrangeTableV1<A> {
    fn from_weights_v1(weights: Vec<A>) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        let native_size = weights.len();
        if native_size < 2
            || !native_size.is_power_of_two()
            || weights.iter().any(|weight| !weight.is_canonical())
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let prefix_len = native_size
            .checked_add(1)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let mut prefix = Vec::new();
        let mut linear_prefix = Vec::new();
        prefix
            .try_reserve_exact(prefix_len)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        linear_prefix
            .try_reserve_exact(prefix_len)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        prefix.push(A::ZERO);
        linear_prefix.push(A::ZERO);
        for (row, weight) in weights.iter().copied().enumerate() {
            let prefix_value = prefix
                .last()
                .copied()
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?
                .add(weight);
            let row_u64 =
                u64::try_from(row).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let linear_value = linear_prefix
                .last()
                .copied()
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?
                .add(weight.mul_base(F(row_u64)));
            prefix.push(prefix_value);
            linear_prefix.push(linear_value);
        }
        if prefix.last() != Some(&A::ONE) {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(Self {
            native_size,
            weights,
            prefix,
            linear_prefix,
        })
    }
    fn shifted_weight_v1(
        &self,
        row: usize,
        shift: usize,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        if row >= self.native_size || shift >= self.native_size {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let index = row
            .checked_add(self.native_size)
            .and_then(|value| value.checked_sub(shift))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
            % self.native_size;
        self.weights
            .get(index)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)
    }
    fn affine_prefix_sum_v1(
        &self,
        start: usize,
        end: usize,
        start_value: F,
        step: F,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        if start > end || end > self.native_size {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let prefix_start = self
            .prefix
            .get(start)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let prefix_end = self
            .prefix
            .get(end)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let linear_start = self
            .linear_prefix
            .get(start)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let linear_end = self
            .linear_prefix
            .get(end)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let weight_sum = prefix_end.sub(prefix_start);
        let start_u64 =
            u64::try_from(start).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let relative_linear_sum = linear_end
            .sub(linear_start)
            .sub(weight_sum.mul_base(F(start_u64)));
        Ok(weight_sum
            .mul_base(start_value)
            .add(relative_linear_sum.mul_base(step)))
    }
    fn shifted_affine_sum_v1(
        &self,
        start: u64,
        end: u64,
        start_value: F,
        step: F,
        shift: usize,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        if shift >= self.native_size {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let start =
            usize::try_from(start).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let end = usize::try_from(end).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if start >= end || end > self.native_size {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let mut result = A::ZERO;
        let before_end = end.min(shift);
        if start < before_end {
            let mapped_start = start
                .checked_add(
                    self.native_size
                        .checked_sub(shift)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
                )
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let mapped_end = mapped_start
                .checked_add(
                    before_end
                        .checked_sub(start)
                        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
                )
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            result = result.add(self.affine_prefix_sum_v1(
                mapped_start,
                mapped_end,
                start_value,
                step,
            )?);
        }
        let after_start = start.max(shift);
        if after_start < end {
            let offset = after_start
                .checked_sub(start)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let offset =
                u64::try_from(offset).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let value_at_after = start_value.add(step.mul(F(offset)));
            let mapped_start = after_start
                .checked_sub(shift)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let mapped_end = end
                .checked_sub(shift)
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            result = result.add(self.affine_prefix_sum_v1(
                mapped_start,
                mapped_end,
                value_at_after,
                step,
            )?);
        }
        Ok(result)
    }
    fn non_repeated_atom_sum_v1(
        &self,
        atom: ZkX509FixedAlgebraicAtomV1,
        shift: usize,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        match atom {
            ZkX509FixedAlgebraicAtomV1::Affine {
                start,
                end,
                start_value,
                step,
                ..
            } => self.shifted_affine_sum_v1(start, end, start_value, step, shift),
            ZkX509FixedAlgebraicAtomV1::Repeated { .. } => {
                Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant)
            }
            ZkX509FixedAlgebraicAtomV1::Sparse { row, value, .. } => {
                let row = usize::try_from(row)
                    .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
                Ok(self.shifted_weight_v1(row, shift)?.mul_base(value))
            }
        }
    }
    fn repeated_atom_sum_naive_v1(
        &self,
        atom: ZkX509FixedAlgebraicAtomV1,
        shift: usize,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        let ZkX509FixedAlgebraicAtomV1::Repeated {
            first,
            count,
            stride,
            start_value,
            step,
            ..
        } = atom
        else {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        };
        let mut result = A::ZERO;
        for occurrence in 0..count {
            let row = occurrence
                .checked_mul(stride)
                .and_then(|offset| first.checked_add(offset))
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let row =
                usize::try_from(row).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            let value = start_value.add(step.mul(F(occurrence)));
            result = result.add(self.shifted_weight_v1(row, shift)?.mul_base(value));
        }
        Ok(result)
    }
}
fn gcd_usize_v1(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
fn multiply_mod_usize_v1(
    left: usize,
    right: usize,
    modulus: usize,
) -> Result<usize, ZkX509FixedAlgebraicErrorV1> {
    if modulus == 0 {
        return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
    }
    let reduced = u128::try_from(left)
        .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
        .checked_mul(
            u128::try_from(right).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?,
        )
        .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
        % u128::try_from(modulus).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
    usize::try_from(reduced).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
}
fn modular_inverse_power_of_two_v1(
    value: usize,
    modulus: usize,
) -> Result<usize, ZkX509FixedAlgebraicErrorV1> {
    if modulus < 2 || !modulus.is_power_of_two() || value == 0 || value >= modulus || value % 2 == 0
    {
        return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
    }
    let mut exponent = modulus
        .checked_div(2)
        .and_then(|phi| phi.checked_sub(1))
        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
    let mut base = value;
    let mut inverse = 1_usize;
    while exponent != 0 {
        if exponent & 1 == 1 {
            inverse = multiply_mod_usize_v1(inverse, base, modulus)?;
        }
        base = multiply_mod_usize_v1(base, base, modulus)?;
        exponent >>= 1;
    }
    if multiply_mod_usize_v1(value, inverse, modulus)? != 1 {
        return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
    }
    Ok(inverse)
}
/// Prefix sums over every additive cycle generated by one native row stride.
///
/// For `g = gcd(stride, N)`, the stride partitions the native row indices into
/// `g` cycles of length `N/g`.  The reduced stride is odd and therefore
/// invertible modulo that power-of-two cycle length.  Two prefixes per cycle
/// recover both `sum(weight)` and `sum(k * weight)` for a cyclic interval.
struct CyclicStrideTableV1<A = F> {
    native_size: usize,
    stride: usize,
    gcd: usize,
    cycle_len: usize,
    reduced_stride_inverse: usize,
    prefix: Vec<A>,
    ordinal_prefix: Vec<A>,
}
impl<A: PolynomialAirFieldV1> CyclicStrideTableV1<A> {
    fn new_v1(weights: &[A], stride: u64) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        let native_size = weights.len();
        let stride =
            usize::try_from(stride).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if native_size < 2
            || !native_size.is_power_of_two()
            || stride == 0
            || stride >= native_size
            || weights.iter().copied().any(|weight| !weight.is_canonical())
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let gcd = gcd_usize_v1(stride, native_size);
        if gcd == 0 || !gcd.is_power_of_two() {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let cycle_len = native_size
            .checked_div(gcd)
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let reduced_stride = stride
            .checked_div(gcd)
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let reduced_stride_inverse = modular_inverse_power_of_two_v1(reduced_stride, cycle_len)?;
        let per_cycle = cycle_len
            .checked_add(1)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let table_len = gcd
            .checked_mul(per_cycle)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let mut prefix = Vec::new();
        let mut ordinal_prefix = Vec::new();
        prefix
            .try_reserve_exact(table_len)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        ordinal_prefix
            .try_reserve_exact(table_len)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for cycle in 0..gcd {
            prefix.push(A::ZERO);
            ordinal_prefix.push(A::ZERO);
            let mut index = cycle;
            for ordinal in 0..cycle_len {
                let weight = weights
                    .get(index)
                    .copied()
                    .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
                prefix.push(
                    prefix
                        .last()
                        .copied()
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?
                        .add(weight),
                );
                ordinal_prefix.push(
                    ordinal_prefix
                        .last()
                        .copied()
                        .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?
                        .add(
                            weight.mul_base(F(u64::try_from(ordinal)
                                .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?)),
                        ),
                );
                index = index
                    .checked_add(stride)
                    .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
                    % native_size;
            }
            if index != cycle {
                return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
            }
        }
        if prefix.len() != table_len || ordinal_prefix.len() != table_len {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(Self {
            native_size,
            stride,
            gcd,
            cycle_len,
            reduced_stride_inverse,
            prefix,
            ordinal_prefix,
        })
    }
    fn cycle_segment_v1(
        &self,
        cycle: usize,
        start: usize,
        end: usize,
    ) -> Result<(A, A), ZkX509FixedAlgebraicErrorV1> {
        if cycle >= self.gcd || start > end || end > self.cycle_len {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let per_cycle = self
            .cycle_len
            .checked_add(1)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let base = cycle
            .checked_mul(per_cycle)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let start = base
            .checked_add(start)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let end = base
            .checked_add(end)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let weight_start = self
            .prefix
            .get(start)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let weight_end = self
            .prefix
            .get(end)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let ordinal_start = self
            .ordinal_prefix
            .get(start)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let ordinal_end = self
            .ordinal_prefix
            .get(end)
            .copied()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        Ok((weight_end.sub(weight_start), ordinal_end.sub(ordinal_start)))
    }
    fn repeated_affine_sum_v1(
        &self,
        first: u64,
        count: u64,
        stride: u64,
        start_value: F,
        step: F,
        shift: usize,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        let first =
            usize::try_from(first).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let count =
            usize::try_from(count).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let stride =
            usize::try_from(stride).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if first >= self.native_size
            || count == 0
            || count > self.cycle_len
            || stride != self.stride
            || shift >= self.native_size
            || !canonical_field_v1(start_value)
            || !canonical_field_v1(step)
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let last = count
            .checked_sub(1)
            .and_then(|last| last.checked_mul(stride))
            .and_then(|offset| first.checked_add(offset))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if last >= self.native_size {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        let shifted_first = first
            .checked_add(self.native_size)
            .and_then(|value| value.checked_sub(shift))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
            % self.native_size;
        let cycle = shifted_first % self.gcd;
        let quotient = shifted_first
            .checked_sub(cycle)
            .and_then(|value| value.checked_div(self.gcd))
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        let position =
            multiply_mod_usize_v1(quotient, self.reduced_stride_inverse, self.cycle_len)?;
        let first_count = count.min(
            self.cycle_len
                .checked_sub(position)
                .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?,
        );
        let first_end = position
            .checked_add(first_count)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let (first_weights, first_ordinals) = self.cycle_segment_v1(cycle, position, first_end)?;
        let position_field = F(
            u64::try_from(position).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?
        );
        let mut weight_sum = first_weights;
        let mut relative_sum = first_ordinals.sub(first_weights.mul_base(position_field));
        let remaining = count
            .checked_sub(first_count)
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        if remaining != 0 {
            let (second_weights, second_ordinals) = self.cycle_segment_v1(cycle, 0, remaining)?;
            weight_sum = weight_sum.add(second_weights);
            relative_sum = relative_sum.add(
                second_ordinals.add(
                    second_weights.mul_base(F(u64::try_from(first_count)
                        .map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?)),
                ),
            );
        }
        Ok(weight_sum
            .mul_base(start_value)
            .add(relative_sum.mul_base(step)))
    }
    fn repeated_atom_sum_v1(
        &self,
        atom: ZkX509FixedAlgebraicAtomV1,
        shift: usize,
    ) -> Result<A, ZkX509FixedAlgebraicErrorV1> {
        let ZkX509FixedAlgebraicAtomV1::Repeated {
            first,
            count,
            stride,
            start_value,
            step,
            ..
        } = atom
        else {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        };
        self.repeated_affine_sum_v1(first, count, stride, start_value, step, shift)
    }
}
/// Canonical row-major verifier-derived fixed openings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509FixedAlgebraicOpeningsV1 {
    schedule_digest: PrivacyOuterDigestV1,
    query_indices: Vec<u64>,
    width: u16,
    fields: Vec<F>,
}
impl ZkX509FixedAlgebraicOpeningsV1 {
    #[cfg(test)]
    /// Concatenate independently capped child schedules in fixed column order.
    ///
    /// Every child must have been evaluated at the identical canonical query set. The caller
    /// supplies the typed composite digest that binds child identity and order; this helper only
    /// performs the checked row-major concatenation and cannot reorder or omit a child.
    pub(crate) fn concatenate_v1(
        schedule_digest: PrivacyOuterDigestV1,
        parts: &[Self],
    ) -> Result<Self, ZkX509FixedAlgebraicErrorV1> {
        if parts.len() < 2 {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        let first = parts
            .first()
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)?;
        if first.query_indices.is_empty()
            || first.query_indices.len() > ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1
            || first
                .query_indices
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        for part in parts {
            if part.query_indices != first.query_indices {
                return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
            }
            validate_width_v1(part.width)?;
            let expected_fields = part
                .query_indices
                .len()
                .checked_mul(usize::from(part.width))
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            if part.fields.len() != expected_fields {
                return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
            }
            if part
                .fields
                .iter()
                .copied()
                .any(|value| !canonical_field_v1(value))
            {
                return Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField);
            }
        }
        let width = parts.iter().try_fold(0_usize, |width, part| {
            width
                .checked_add(usize::from(part.width))
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
        })?;
        let width =
            u16::try_from(width).map_err(|_| ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        validate_width_v1(width)?;
        let field_count = first
            .query_indices
            .len()
            .checked_mul(usize::from(width))
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        if field_count > ZK_X509_FIXED_ALGEBRAIC_MAX_OUTPUT_FIELDS_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded);
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(field_count)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for row in 0..first.query_indices.len() {
            for part in parts {
                fields.extend_from_slice(part.row_v1(row)?);
            }
        }
        if fields.len() != field_count {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(Self {
            schedule_digest,
            query_indices: first.query_indices.clone(),
            width,
            fields,
        })
    }
    #[cfg(test)]
    /// Schedule binding shared by every returned row.
    pub(crate) const fn schedule_digest_v1(&self) -> PrivacyOuterDigestV1 {
        self.schedule_digest
    }
    #[cfg(test)]
    /// Canonical sorted verifier query indices.
    pub(crate) fn query_indices_v1(&self) -> &[u64] {
        &self.query_indices
    }
    #[cfg(test)]
    /// Exact fixed row width.
    pub(crate) const fn width_v1(&self) -> u16 {
        self.width
    }
    #[cfg(test)]
    /// Number of verifier-derived rows.
    pub(crate) fn len_v1(&self) -> usize {
        self.query_indices.len()
    }
    #[cfg(test)]
    /// Whether the checked opening set is empty.  Valid instances are not.
    pub(crate) fn is_empty_v1(&self) -> bool {
        self.query_indices.is_empty()
    }
    #[cfg(test)]
    /// Borrow one row by canonical slot.
    pub(crate) fn row_v1(&self, slot: usize) -> Result<&[F], ZkX509FixedAlgebraicErrorV1> {
        if slot >= self.query_indices.len() {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        let width = usize::from(self.width);
        let start = slot
            .checked_mul(width)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        let end = start
            .checked_add(width)
            .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
        self.fields
            .get(start..end)
            .ok_or(ZkX509FixedAlgebraicErrorV1::InternalInvariant)
    }
    #[cfg(test)]
    /// Borrow the row for one exact verifier query index.
    pub(crate) fn row_for_query_v1(
        &self,
        query_index: u64,
    ) -> Result<Option<&[F]>, ZkX509FixedAlgebraicErrorV1> {
        match self.query_indices.binary_search(&query_index) {
            Ok(slot) => self.row_v1(slot).map(Some),
            Err(_) => Ok(None),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::transparent_stark::{
        GOLDILOCKS_GENERATOR_V1, goldilocks_evaluate_coset_v1, goldilocks_ifft_v1,
    };
    fn release_shift_v1() -> F {
        F(GOLDILOCKS_GENERATOR_V1)
    }
    fn domain_v1(
        native_log2: u8,
        lde_log2: u8,
    ) -> Result<ZkX509FixedAlgebraicDomainV1, ZkX509FixedAlgebraicErrorV1> {
        ZkX509FixedAlgebraicDomainV1::new_v1(native_log2, lde_log2, release_shift_v1())
    }
    fn kat_schedule_v1() -> ZkX509FixedAlgebraicScheduleV1 {
        let domain = domain_v1(3, 5).expect("KAT domain");
        ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            3,
            vec![
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(2, 0, 3, 2, F(4), F(1))
                    .expect("KAT repeated atom"),
                ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 0, F(9)).expect("KAT sparse atom"),
                ZkX509FixedAlgebraicAtomV1::affine_v1(1, 1, 5, F(3), F(2))
                    .expect("KAT affine atom"),
            ],
        )
        .expect("KAT schedule")
    }
    fn mixed_schedule_v1(
        seed: u64,
    ) -> Result<ZkX509FixedAlgebraicScheduleV1, ZkX509FixedAlgebraicErrorV1> {
        let domain = domain_v1(4, 6)?;
        let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 4)?;
        builder.push_affine_v1(0, 0, 16, F(3 + seed), F(5))?;
        // Deliberate overlap: the schedule representation binds field-addition
        // semantics rather than depending on insertion order.
        builder.push_repeated_affine_v1(0, 0, 8, 2, F(7), F(1 + seed))?;
        builder.push_sparse_v1(0, 6, F(11))?;
        // Deliberately adjacent non-mergeable affine atoms.
        builder.push_affine_v1(1, 0, 5, F(13), F(2))?;
        builder.push_affine_v1(1, 5, 11, F(29), F(4))?;
        // Interleaved repeated supports with overlapping bounding intervals.
        builder.push_repeated_affine_v1(2, 0, 8, 2, F(17), F(3))?;
        builder.push_repeated_affine_v1(2, 1, 8, 2, F(19), F(6))?;
        builder.push_sparse_v1(3, seed % 16, F(23 + seed))?;
        builder.finish_v1()
    }
    fn materialized_fft_lde_v1(schedule: &ZkX509FixedAlgebraicScheduleV1) -> Vec<Vec<F>> {
        let domain = schedule.domain_v1();
        let native_size =
            usize::try_from(domain.native_size_v1().expect("native size")).expect("usize native");
        let lde_size = usize::try_from(domain.lde_size_v1().expect("LDE size")).expect("usize LDE");
        let native_root =
            goldilocks_primitive_root_v1(domain.native_log2_v1()).expect("native root");
        let lde_root = goldilocks_primitive_root_v1(domain.lde_log2_v1()).expect("LDE root");
        let width = usize::from(schedule.width_v1());
        let mut native_row = vec![F::ZERO; width];
        let mut lde_columns = Vec::with_capacity(width);
        for column in 0..width {
            let mut native_column = Vec::with_capacity(native_size);
            for row in 0..native_size {
                schedule
                    .native_row_v1(u64::try_from(row).expect("small row"), &mut native_row)
                    .expect("native row");
                native_column.push(native_row[column]);
            }
            goldilocks_ifft_v1(&mut native_column, native_root).expect("native IFFT");
            lde_columns.push(
                goldilocks_evaluate_coset_v1(
                    &native_column,
                    lde_size,
                    lde_root,
                    domain.coset_shift_v1(),
                )
                .expect("independent coset FFT"),
            );
        }
        lde_columns
    }
    fn assert_matches_fft_v1(schedule: &ZkX509FixedAlgebraicScheduleV1, query_indices: &[u64]) {
        let materialized = materialized_fft_lde_v1(schedule);
        let openings = schedule
            .evaluate_query_indices_v1(query_indices)
            .expect("algebraic openings");
        assert_eq!(openings.query_indices_v1(), query_indices);
        for (slot, query) in query_indices.iter().copied().enumerate() {
            let opened = openings.row_v1(slot).expect("opened row");
            for (column, values) in materialized.iter().enumerate() {
                let query = usize::try_from(query).expect("small query");
                assert_eq!(
                    opened.get(column),
                    values.get(query),
                    "query {query}, column {column}"
                );
            }
        }
    }
    fn naive_repeated_affine_sum_v1(
        table: &LagrangeTableV1,
        first: usize,
        count: usize,
        stride: usize,
        start_value: F,
        step: F,
        shift: usize,
    ) -> F {
        let mut result = F::ZERO;
        for occurrence in 0..count {
            let row = first + occurrence * stride;
            let value = start_value
                .add(step.mul(F(u64::try_from(occurrence).expect("small test occurrence"))));
            result = result.add(
                value.mul(
                    table
                        .shifted_weight_v1(row, shift)
                        .expect("valid shifted weight"),
                ),
            );
        }
        result
    }
    fn grouped_queries_v1(
        domain: ZkX509FixedAlgebraicDomainV1,
        query_indices: &[u64],
    ) -> Vec<GroupedQueryV1> {
        let blowup = domain.blowup_v1().expect("test blowup");
        let mut grouped: Vec<_> = query_indices
            .iter()
            .copied()
            .enumerate()
            .map(|(slot, index)| GroupedQueryV1 {
                remainder: index % blowup,
                shift: index / blowup,
                slot,
            })
            .collect();
        grouped.sort_unstable_by_key(|query| (query.remainder, query.shift, query.slot));
        grouped
    }
    #[test]
    fn domain_constructor_rejects_every_invalid_boundary_v1() {
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(0, 1, release_shift_v1()),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(21, 22, release_shift_v1()),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(4, 4, release_shift_v1()),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(4, 26, release_shift_v1()),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(16, 25, release_shift_v1()),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(4, 6, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(4, 6, F(GOLDILOCKS_MODULUS_V1)),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(4, 6, F::ONE),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        let lde_root = goldilocks_primitive_root_v1(6).expect("root");
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(4, 6, lde_root),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        let maximum = domain_v1(
            ZK_X509_FIXED_ALGEBRAIC_MAX_NATIVE_LOG2_V1,
            ZK_X509_FIXED_ALGEBRAIC_MAX_LDE_LOG2_V1,
        )
        .expect("maximum release domain");
        assert_eq!(maximum.native_size_v1(), Ok(1_u64 << 20));
        assert_eq!(maximum.lde_size_v1(), Ok(1_u64 << 25));
        assert_eq!(maximum.blowup_v1(), Ok(1_u64 << 5));
    }
    #[test]
    fn query_points_are_exact_coset_points_and_never_native_v1() {
        let domain = domain_v1(4, 6).expect("domain");
        let root = goldilocks_primitive_root_v1(6).expect("root");
        let mut expected = release_shift_v1();
        for index in 0..64 {
            let point = domain.query_point_v1(index).expect("query point");
            assert_eq!(point, expected);
            assert_ne!(point.pow(16), F::ONE);
            expected = expected.mul(root);
        }
        assert_eq!(
            domain.query_point_v1(64),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
    }
    #[test]
    fn atom_constructors_reject_zero_aliases_overflow_and_noncanonical_fields_v1() {
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::affine_v1(0, 2, 2, F::ONE, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::affine_v1(0, 2, 3, F::ONE, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::affine_v1(0, 0, 2, F::ZERO, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::affine_v1(0, 0, 2, F(GOLDILOCKS_MODULUS_V1), F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::repeated_v1(0, 0, 1, 2, F::ONE),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::repeated_v1(0, 0, 2, 1, F::ONE),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::repeated_v1(0, u64::MAX - 1, 2, 2, F::ONE),
            Err(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::repeated_v1(0, 0, 2, 2, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 0, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule)
        );
        assert_eq!(
            ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 0, F(GOLDILOCKS_MODULUS_V1)),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField)
        );
    }
    #[test]
    fn schedule_revalidates_public_atom_variants_fail_closed_v1() {
        let domain = domain_v1(3, 5).expect("domain");
        assert_eq!(
            ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 0).err(),
            Some(ZkX509FixedAlgebraicErrorV1::InvalidWidth)
        );
        assert_eq!(
            ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 473).err(),
            Some(ZkX509FixedAlgebraicErrorV1::InvalidWidth)
        );
        assert_eq!(
            ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 1, Vec::new()),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule)
        );
        let malformed = [
            ZkX509FixedAlgebraicAtomV1::Sparse {
                column: 1,
                row: 0,
                value: F::ONE,
            },
            ZkX509FixedAlgebraicAtomV1::Sparse {
                column: 0,
                row: 8,
                value: F::ONE,
            },
            ZkX509FixedAlgebraicAtomV1::Repeated {
                column: 0,
                first: 0,
                count: 5,
                stride: 2,
                start_value: F::ONE,
                step: F::ZERO,
            },
            ZkX509FixedAlgebraicAtomV1::Affine {
                column: 0,
                start: 0,
                end: 9,
                start_value: F::ONE,
                step: F::ZERO,
            },
            ZkX509FixedAlgebraicAtomV1::Sparse {
                column: 0,
                row: 0,
                value: F(GOLDILOCKS_MODULUS_V1),
            },
        ];
        for atom in malformed {
            assert!(matches!(
                ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 1, vec![atom]),
                Err(ZkX509FixedAlgebraicErrorV1::InvalidAtom
                    | ZkX509FixedAlgebraicErrorV1::NonCanonicalField)
            ));
        }
        let atom = ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 0, F::ONE).expect("valid sparse atom");
        assert_eq!(
            ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 1, vec![atom, atom]),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule)
        );
        assert_eq!(
            ZkX509FixedAlgebraicScheduleV1::new_v1(
                domain,
                1,
                vec![atom; ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1 + 1],
            ),
            Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded)
        );
    }
    #[test]
    fn builder_growth_is_chunked_and_stays_below_the_atom_cap_v1() {
        let domain = domain_v1(10, 12).expect("domain");
        let mut builder =
            ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 1).expect("builder");
        assert_eq!(builder.atoms.capacity(), 0);
        for row in 0..257 {
            builder
                .push_sparse_v1(0, row, F(row + 1))
                .expect("bounded sparse atom");
        }
        assert_eq!(builder.atoms.len(), 257);
        assert!(builder.atoms.capacity() >= 257);
        assert!(builder.atoms.capacity() <= 512);
        assert!(builder.atoms.capacity() <= ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1);
    }
    #[test]
    fn canonical_descriptor_and_digest_have_exact_kat_v1() {
        let schedule = kat_schedule_v1();
        let descriptor = schedule
            .canonical_descriptor_v1()
            .expect("canonical descriptor");
        assert_eq!(descriptor.len(), 121);
        assert_eq!(
            descriptor.get(..24),
            Some(
                &[
                    0x58, 0x35, 0x4b, 0x31, 0x00, 0x01, 0x00, 0x18, 0x03, 0x05, 0x00, 0x03, 0x00,
                    0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
                ][..]
            )
        );
        assert_eq!(
            descriptor.get(24),
            Some(&ZK_X509_FIXED_ALGEBRAIC_SPARSE_TAG_V1)
        );
        assert_eq!(
            descriptor.get(43),
            Some(&ZK_X509_FIXED_ALGEBRAIC_AFFINE_TAG_V1)
        );
        assert_eq!(
            descriptor.get(78),
            Some(&ZK_X509_FIXED_ALGEBRAIC_REPEATED_TAG_V1)
        );
        assert_ne!(
            schedule.descriptor_digest_v1(),
            PrivacyOuterDigestV1::default()
        );
        schedule
            .verify_descriptor_digest_v1(&schedule.descriptor_digest_v1())
            .expect("exact digest");
        let mut mutation = schedule.descriptor_digest_v1();
        let mut mutation_words = mutation.to_bytes();
        mutation_words[2] ^= 0x80;
        mutation = PrivacyOuterDigestV1::from_bytes(mutation_words);
        assert_eq!(
            schedule.verify_descriptor_digest_v1(&mutation),
            Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch)
        );
    }
    #[test]
    fn insertion_order_is_canonical_but_alternate_decomposition_is_bound_v1() {
        let schedule = kat_schedule_v1();
        let mut reversed = schedule.atoms_v1().to_vec();
        reversed.reverse();
        let reordered = ZkX509FixedAlgebraicScheduleV1::new_v1(
            schedule.domain_v1(),
            schedule.width_v1(),
            reversed,
        )
        .expect("reordered schedule");
        assert_eq!(
            reordered.canonical_descriptor_v1(),
            schedule.canonical_descriptor_v1()
        );
        assert_eq!(
            reordered.descriptor_digest_v1(),
            schedule.descriptor_digest_v1()
        );
        let domain = domain_v1(3, 5).expect("domain");
        let affine = ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            1,
            vec![ZkX509FixedAlgebraicAtomV1::affine_v1(0, 0, 2, F(5), F::ZERO).expect("affine")],
        )
        .expect("affine schedule");
        let sparse = ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            1,
            vec![
                ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 0, F(5)).expect("sparse zero"),
                ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 1, F(5)).expect("sparse one"),
            ],
        )
        .expect("sparse schedule");
        for row in 0..8 {
            let mut left = [F::ZERO; 1];
            let mut right = [F::ZERO; 1];
            affine.native_row_v1(row, &mut left).expect("left row");
            sparse.native_row_v1(row, &mut right).expect("right row");
            assert_eq!(left, right);
        }
        assert_ne!(
            affine.descriptor_digest_v1(),
            sparse.descriptor_digest_v1(),
            "the profile pins the compiler representation, not only its values"
        );
    }
    #[test]
    fn native_rows_apply_exact_additive_overlap_semantics_v1() {
        let schedule = mixed_schedule_v1(0).expect("mixed schedule");
        let mut row = [F::ZERO; 4];
        schedule.native_row_v1(0, &mut row).expect("row zero");
        assert_eq!(row, [F(10), F(13), F(17), F(23)]);
        schedule.native_row_v1(5, &mut row).expect("row five");
        assert_eq!(row, [F(28), F(29), F(31), F::ZERO]);
        schedule.native_row_v1(6, &mut row).expect("row six");
        assert_eq!(row, [F(54), F(33), F(26), F::ZERO]);
        assert_eq!(
            schedule.native_row_v1(16, &mut row),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        assert_eq!(
            schedule.native_row_v1(0, &mut row[..3]),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
    }
    #[test]
    fn native_column_stream_matches_native_rows_for_every_column_v1() {
        let schedule = mixed_schedule_v1(7).expect("mixed schedule");
        let native_size =
            usize::try_from(schedule.domain_v1().native_size_v1().expect("native size"))
                .expect("small native size");
        let width = usize::from(schedule.width_v1());
        let mut row = vec![F::ZERO; width];
        let mut column = vec![F(GOLDILOCKS_MODULUS_V1 - 1); native_size];
        for column_index in 0..width {
            schedule
                .fill_native_column_v1(
                    u16::try_from(column_index).expect("small column"),
                    &mut column,
                )
                .expect("native column");
            for (row_index, streamed) in column.iter().copied().enumerate() {
                schedule
                    .native_row_v1(u64::try_from(row_index).expect("small row"), &mut row)
                    .expect("native row");
                assert_eq!(
                    streamed, row[column_index],
                    "row {row_index}, column {column_index}"
                );
                assert!(canonical_field_v1(streamed));
            }
        }
    }
    #[test]
    fn native_column_stream_accepts_boundary_columns_and_fails_closed_v1() {
        let domain = domain_v1(7, 9).expect("boundary domain");
        let schedule = ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1,
            vec![
                ZkX509FixedAlgebraicAtomV1::affine_v1(0, 0, 128, F(3), F(2))
                    .expect("first-column affine"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(471, 1, 4, 32, F(5), F(7))
                    .expect("last-column repeated"),
                ZkX509FixedAlgebraicAtomV1::sparse_v1(471, 127, F(11)).expect("last-column sparse"),
            ],
        )
        .expect("boundary schedule");
        let mut first = vec![F::ZERO; 128];
        let mut last = vec![F::ZERO; 128];
        schedule
            .fill_native_column_v1(0, &mut first)
            .expect("first column");
        schedule
            .fill_native_column_v1(471, &mut last)
            .expect("last column");
        assert_eq!(first[0], F(3));
        assert_eq!(first[127], F(257));
        assert_eq!(last[1], F(5));
        assert_eq!(last[33], F(12));
        assert_eq!(last[65], F(19));
        assert_eq!(last[97], F(26));
        assert_eq!(last[127], F(11));
        assert!(first.iter().chain(&last).copied().all(canonical_field_v1));
        let mut unchanged = vec![F(99); 128];
        assert_eq!(
            schedule.fill_native_column_v1(472, &mut unchanged),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        assert_eq!(unchanged, vec![F(99); 128]);
        assert_eq!(
            schedule.fill_native_column_v1(0, &mut unchanged[..127]),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
    }
    #[test]
    fn generic_stride_tables_match_naive_sums_for_all_gcd_cycles_v1() {
        let domain = domain_v1(6, 8).expect("stride-test domain");
        let native_size =
            usize::try_from(domain.native_size_v1().expect("native size")).expect("small native");
        let strides = [1_usize, 2, 3, 6, 10, 24, 32, 40];
        let mut saw_wrap = false;
        let mut saw_non_wrap = false;
        for remainder in 0..4 {
            let lagrange = LagrangeTableV1::new_v1(domain, remainder).expect("Lagrange table");
            for stride in strides {
                let stride_u64 = u64::try_from(stride).expect("small stride");
                let cyclic = CyclicStrideTableV1::new_v1(&lagrange.weights, stride_u64)
                    .expect("generic stride table");
                assert_eq!(cyclic.gcd, gcd_usize_v1(stride, native_size));
                assert_eq!(cyclic.cycle_len, native_size / cyclic.gcd);
                assert_eq!(
                    multiply_mod_usize_v1(
                        stride / cyclic.gcd,
                        cyclic.reduced_stride_inverse,
                        cyclic.cycle_len,
                    ),
                    Ok(1)
                );
                for first in [0_usize, 1, 5] {
                    let maximum_count = (native_size - 1 - first) / stride + 1;
                    for count in [1_usize, maximum_count] {
                        for shift in 0..native_size {
                            let shifted_first = (first + native_size - shift) % native_size;
                            let cycle = shifted_first % cyclic.gcd;
                            let quotient = (shifted_first - cycle) / cyclic.gcd;
                            let position = multiply_mod_usize_v1(
                                quotient,
                                cyclic.reduced_stride_inverse,
                                cyclic.cycle_len,
                            )
                            .expect("cycle position");
                            if count > cyclic.cycle_len - position {
                                saw_wrap = true;
                            } else {
                                saw_non_wrap = true;
                            }
                            let expected = naive_repeated_affine_sum_v1(
                                &lagrange,
                                first,
                                count,
                                stride,
                                F(7),
                                F(5),
                                shift,
                            );
                            let actual = cyclic
                                .repeated_affine_sum_v1(
                                    u64::try_from(first).expect("small first row"),
                                    u64::try_from(count).expect("small occurrence count"),
                                    stride_u64,
                                    F(7),
                                    F(5),
                                    shift,
                                )
                                .expect("cyclic affine sum");
                            assert_eq!(
                                actual, expected,
                                "remainder {remainder}, stride {stride}, first {first}, \
                                 count {count}, shift {shift}"
                            );
                        }
                    }
                }
            }
        }
        assert!(saw_wrap, "at least one shifted cycle must wrap");
        assert!(saw_non_wrap, "at least one shifted cycle must not wrap");
    }
    #[test]
    fn generic_stride_table_rejects_malformed_shapes_v1() {
        let domain = domain_v1(6, 8).expect("stride-test domain");
        let lagrange = LagrangeTableV1::new_v1(domain, 0).expect("Lagrange table");
        assert!(CyclicStrideTableV1::new_v1(&lagrange.weights, 0).is_err());
        assert!(CyclicStrideTableV1::new_v1(&lagrange.weights, 64).is_err());
        assert!(CyclicStrideTableV1::new_v1(&lagrange.weights[..63], 3).is_err());
        let cyclic =
            CyclicStrideTableV1::new_v1(&lagrange.weights, 24).expect("generic stride table");
        for malformed in [
            cyclic.repeated_affine_sum_v1(0, 0, 24, F::ONE, F::ZERO, 0),
            cyclic.repeated_affine_sum_v1(0, 4, 24, F::ONE, F::ZERO, 0),
            cyclic.repeated_affine_sum_v1(0, 2, 23, F::ONE, F::ZERO, 0),
            cyclic.repeated_affine_sum_v1(64, 1, 24, F::ONE, F::ZERO, 0),
            cyclic.repeated_affine_sum_v1(0, 1, 24, F::ONE, F::ZERO, 64),
            cyclic.repeated_affine_sum_v1(0, 1, 24, F(GOLDILOCKS_MODULUS_V1), F::ZERO, 0),
        ] {
            assert_eq!(
                malformed,
                Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant)
            );
        }
    }
    #[test]
    fn repeated_stride_cost_choice_uses_direct_on_exact_ties_v1() {
        let tied = RepeatedStrideRunV1 {
            stride: 3,
            references_start: 0,
            references_end: 1,
            total_occurrences: 9,
        };
        assert_eq!(9 * 8, 64 + 1 * 8);
        assert_eq!(repeated_stride_uses_table_v1(tied, 8, 64), Ok(false));
        assert_eq!(
            repeated_stride_uses_table_v1(
                RepeatedStrideRunV1 {
                    total_occurrences: 10,
                    ..tied
                },
                8,
                64,
            ),
            Ok(true)
        );
        assert_eq!(
            repeated_stride_uses_table_v1(
                RepeatedStrideRunV1 {
                    total_occurrences: 8,
                    ..tied
                },
                8,
                64,
            ),
            Ok(false)
        );
    }
    #[test]
    fn mixed_atoms_match_independent_ifft_and_coset_fft_across_groups_v1() {
        let schedule = mixed_schedule_v1(0).expect("mixed schedule");
        // Blowup is four.  These indices cover every residue and multiple
        // native-root shifts, including the cyclic split used by affine sums.
        let queries = [0, 1, 2, 3, 4, 7, 8, 13, 19, 31, 47, 63];
        assert_matches_fft_v1(&schedule, &queries);
    }
    #[test]
    fn hybrid_repeated_table_and_direct_paths_match_independent_fft_v1() {
        let domain = domain_v1(6, 9).expect("hybrid domain");
        let schedule = ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            2,
            vec![
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(0, 0, 32, 2, F(3), F(5))
                    .expect("dense stride two"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(0, 0, 22, 3, F(7), F(11))
                    .expect("dense non-divisor stride three"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(1, 1, 11, 6, F(13), F(17))
                    .expect("dense non-divisor stride six"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(1, 0, 7, 10, F(19), F(23))
                    .expect("dense non-divisor stride ten"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(0, 0, 3, 24, F(29), F(31))
                    .expect("direct stride twenty-four"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(1, 0, 2, 32, F(37), F(41))
                    .expect("direct half-domain stride"),
                ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(1, 0, 2, 40, F(43), F(47))
                    .expect("direct non-divisor stride forty"),
            ],
        )
        .expect("hybrid schedule");
        let queries: Vec<u64> = (0..272).collect();
        assert_matches_fft_v1(&schedule, &queries);
    }
    #[test]
    fn deterministic_property_schedules_match_independent_fft_v1() {
        let queries = [0, 1, 3, 4, 9, 16, 27, 42, 55, 63];
        for seed in 0..48 {
            let schedule = mixed_schedule_v1(seed).expect("property schedule");
            assert_matches_fft_v1(&schedule, &queries);
        }
    }
    #[test]
    fn constant_full_domain_atom_opens_to_the_same_constant_v1() {
        let domain = domain_v1(4, 6).expect("domain");
        let schedule = ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            1,
            vec![
                ZkX509FixedAlgebraicAtomV1::affine_v1(0, 0, 16, F(91), F::ZERO)
                    .expect("constant atom"),
            ],
        )
        .expect("constant schedule");
        let queries = [0, 1, 2, 3, 8, 17, 31, 48, 63];
        let openings = schedule
            .evaluate_query_indices_v1(&queries)
            .expect("constant openings");
        for slot in 0..queries.len() {
            assert_eq!(openings.row_v1(slot).expect("row"), &[F(91)]);
        }
    }
    #[test]
    fn query_shape_and_opening_accessors_fail_closed_v1() {
        let schedule = kat_schedule_v1();
        for invalid in [Vec::new(), vec![1, 1], vec![2, 1], vec![32]] {
            assert_eq!(
                schedule.evaluate_query_indices_v1(&invalid),
                Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
            );
        }
        let too_many: Vec<u64> = (0..=u64::try_from(ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1)
            .expect("query cap"))
            .collect();
        assert_eq!(
            schedule.evaluate_query_indices_v1(&too_many),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let openings = schedule
            .evaluate_query_indices_v1(&[0, 3, 31])
            .expect("openings");
        assert_eq!(openings.len_v1(), 3);
        assert!(!openings.is_empty_v1());
        assert_eq!(openings.width_v1(), 3);
        assert_eq!(
            openings.schedule_digest_v1(),
            schedule.descriptor_digest_v1()
        );
        assert_eq!(openings.row_for_query_v1(3), openings.row_v1(1).map(Some));
        assert_eq!(openings.row_for_query_v1(2), Ok(None));
        assert_eq!(
            openings.row_v1(3),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
    }
    #[test]
    fn composite_opening_concatenation_is_row_major_and_fail_closed_v1() {
        let left = ZkX509FixedAlgebraicOpeningsV1 {
            schedule_digest: PrivacyOuterDigestV1::from_bytes([1; 48]),
            query_indices: vec![2, 9],
            width: 2,
            fields: vec![F(11), F(12), F(21), F(22)],
        };
        let right = ZkX509FixedAlgebraicOpeningsV1 {
            schedule_digest: PrivacyOuterDigestV1::from_bytes([2; 48]),
            query_indices: vec![2, 9],
            width: 1,
            fields: vec![F(13), F(23)],
        };
        let composite_digest = PrivacyOuterDigestV1::from_bytes([9; 48]);
        let combined = ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
            composite_digest,
            &[left.clone(), right.clone()],
        )
        .expect("canonical child openings");
        assert_eq!(combined.schedule_digest_v1(), composite_digest);
        assert_eq!(combined.query_indices_v1(), &[2, 9]);
        assert_eq!(combined.width_v1(), 3);
        assert_eq!(combined.row_v1(0), Ok(&[F(11), F(12), F(13)][..]));
        assert_eq!(combined.row_v1(1), Ok(&[F(21), F(22), F(23)][..]));
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(composite_digest, &[]),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
                composite_digest,
                core::slice::from_ref(&left),
            ),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let mut mismatched_queries = right.clone();
        mismatched_queries.query_indices[1] = 10;
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
                composite_digest,
                &[left.clone(), mismatched_queries],
            ),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let mut unordered_left = left.clone();
        unordered_left.query_indices.swap(0, 1);
        let mut unordered_right = right.clone();
        unordered_right.query_indices.swap(0, 1);
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
                composite_digest,
                &[unordered_left, unordered_right],
            ),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let mut malformed_fields = right.clone();
        malformed_fields.fields.pop();
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
                composite_digest,
                &[left.clone(), malformed_fields],
            ),
            Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant)
        );
        let mut noncanonical_fields = right.clone();
        noncanonical_fields.fields[0] = F(GOLDILOCKS_MODULUS_V1);
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
                composite_digest,
                &[left.clone(), noncanonical_fields],
            ),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalField)
        );
        let over_profile_width = [
            ZkX509FixedAlgebraicOpeningsV1 {
                schedule_digest: PrivacyOuterDigestV1::from_bytes([3; 48]),
                query_indices: vec![0],
                width: 300,
                fields: vec![F::ZERO; 300],
            },
            ZkX509FixedAlgebraicOpeningsV1 {
                schedule_digest: PrivacyOuterDigestV1::from_bytes([4; 48]),
                query_indices: vec![0],
                width: 173,
                fields: vec![F::ZERO; 173],
            },
        ];
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(composite_digest, &over_profile_width,),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidWidth)
        );
        let maximum_width_part = ZkX509FixedAlgebraicOpeningsV1 {
            schedule_digest: PrivacyOuterDigestV1::from_bytes([5; 48]),
            query_indices: vec![0],
            width: ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1,
            fields: vec![F::ZERO; usize::from(ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1)],
        };
        assert_eq!(
            ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(
                composite_digest,
                &vec![maximum_width_part; 140],
            ),
            Err(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)
        );
    }
    #[test]
    fn exact_release_272_by_472_result_boundary_is_accepted_v1() {
        assert_eq!(ZK_X509_FIXED_ALGEBRAIC_MAX_OUTPUT_FIELDS_V1, 128_384);
        let domain = domain_v1(7, 9).expect("boundary domain");
        let schedule = ZkX509FixedAlgebraicScheduleV1::new_v1(
            domain,
            ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1,
            vec![ZkX509FixedAlgebraicAtomV1::sparse_v1(471, 0, F::ONE).expect("boundary atom")],
        )
        .expect("boundary schedule");
        let queries: Vec<u64> = (0..u64::try_from(ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1)
            .expect("query cap"))
            .collect();
        let openings = schedule
            .evaluate_query_indices_v1(&queries)
            .expect("exact release boundary");
        assert_eq!(openings.len_v1(), 272);
        assert_eq!(openings.width_v1(), 472);
        assert_eq!(
            openings.row_v1(271).expect("last row").len(),
            usize::from(ZK_X509_FIXED_ALGEBRAIC_MAX_WIDTH_V1)
        );
        assert_eq!(
            ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 473).err(),
            Some(ZkX509FixedAlgebraicErrorV1::InvalidWidth)
        );
        let too_many_queries: Vec<u64> = (0..273).collect();
        assert_eq!(
            schedule.evaluate_query_indices_v1(&too_many_queries),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
    }
    #[test]
    fn release_p256_shaped_schedule_accepts_and_evaluates_272_queries_v1() {
        let domain = domain_v1(19, 25).expect("P-256-shaped domain");
        let mut atoms = Vec::with_capacity(192);
        for role in 0..2_u16 {
            for atom_index in 0..96_u64 {
                atoms.push(
                    ZkX509FixedAlgebraicAtomV1::repeated_affine_v1(
                        role,
                        0,
                        14_828,
                        32,
                        F(atom_index + 1),
                        F(atom_index + 3),
                    )
                    .expect("P-256-shaped repeated atom"),
                );
            }
        }
        let schedule = ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 2, atoms)
            .expect("P-256-shaped schedule");
        let spread_queries: Vec<u64> = (0..272).collect();
        let spread_grouped = grouped_queries_v1(domain, &spread_queries);
        let (references, runs) =
            repeated_stride_plan_v1(schedule.atoms_v1()).expect("repeated stride plan");
        schedule
            .validate_evaluation_work_v1(
                &spread_grouped,
                &references,
                &runs,
                domain.native_size_v1().expect("native size"),
            )
            .expect("full spread work must fit the release cap");
        // Keep the release-shape evaluator test practical while still opening
        // all 272 verifier rows: one remainder group exercises the same dense
        // stride table against every native-root shift.
        let same_remainder_queries: Vec<u64> = (0..272).map(|shift| shift * 64).collect();
        let openings = schedule
            .evaluate_query_indices_v1(&same_remainder_queries)
            .expect("272-query P-256-shaped evaluation");
        assert_eq!(openings.len_v1(), 272);
        assert_eq!(openings.width_v1(), 2);
        assert!(
            openings.fields.iter().copied().all(canonical_field_v1),
            "every verifier-derived opening must be canonical"
        );
        assert!(
            openings
                .fields
                .iter()
                .copied()
                .any(|value| value != F::ZERO),
            "the nonzero fixed schedule must not collapse to all-zero openings"
        );
    }
    #[test]
    fn adversarial_distinct_stride_work_is_rejected_before_evaluation_v1() {
        let domain = domain_v1(20, 21).expect("large native domain");
        let native_size = domain.native_size_v1().expect("native size");
        let mut atoms = Vec::with_capacity(1_024);
        for stride in 2..=1_025_u64 {
            let count = (native_size - 1) / stride + 1;
            atoms.push(
                ZkX509FixedAlgebraicAtomV1::repeated_v1(0, 0, count, stride, F::ONE)
                    .expect("distinct-stride repeated atom"),
            );
        }
        let schedule = ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 1, atoms)
            .expect("large-work schedule construction is still bounded");
        let same_remainder_queries: Vec<u64> = (0..272).map(|shift| shift * 2).collect();
        assert_eq!(
            schedule.evaluate_query_indices_v1(&same_remainder_queries),
            Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded)
        );
    }
}
