//! Fixed-topology four-bit selector for complete P-256 scalar multiplication.
//!
//! Every lookup scans all sixteen candidate points. Candidate and selected output coordinates are
//! exposed in value-id-contiguous order: the sixteen little-endian limbs of x, then y, then z.
//! Three consecutive limbs are packed into each physical row, so one candidate consumes sixteen
//! rows and one selected output consumes another sixteen rows.
//!
//! The selector is reconstructed from four Boolean scalar bits on every candidate row. Forty-eight
//! running accumulators select all three coordinates without a host-language branch. The
//! surrounding P-256 value bus must bind every external limb to its arithmetic SSA value, and the
//! scalar-bit copy bus must bind the four repeated bits to the scalar arithmetic trace. The
//! aggregate adapter supplies both bindings; this AIR has no standalone activation path.
use crate::privacy_engines::transparent_stark::{GoldilocksFieldV1 as F, PolynomialAirFieldV1};
use thiserror::Error;
/// Stable aggregate layout for all selectors in one ECDSA equation.
#[cfg(test)]
pub const ZK_X509_P256_WINDOW_BATCH_DESCRIPTOR_V1: &[u8] = b"zk-x509-p256-window-batch-v1-incompatible:one-signature:u1-window0-through63-then-u2-window0-through63:128-verifier-fixed-vertical-blocks:512-rows-per-block:65536-row-single-commitment:no-horizontal-instance-expansion:base61:aux1-zero-before-cross-products:fixed27:constraints232-degree4:cross-trace-address-binding=complete-via-p256-aggregate-adapter:standalone-activation=not-applicable";
/// Rows used by one 16-way point lookup.
pub const P256_WINDOW_ROWS_V1: usize = 16 * 16 + 16;
/// Sole padded native trace size for one window instance.
pub const P256_WINDOW_STARK_TRACE_SIZE_V1: usize = 512;
/// Verifier-positioned selectors in one complete two-scalar multiplication.
pub const P256_WINDOW_BATCH_INSTANCES_V1: usize = 2 * 64;
/// Sole vertically packed aggregate trace size for one ECDSA equation.
pub const P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1: usize =
    P256_WINDOW_BATCH_INSTANCES_V1 * P256_WINDOW_STARK_TRACE_SIZE_V1;
/// Committed base width for one selector row.
pub const P256_WINDOW_BASE_WIDTH_V1: usize = 61;
/// Aggregate auxiliary width, constrained to the sole canonical zero column.
pub const P256_WINDOW_STARK_AUX_WIDTH_V1: usize = 1;
/// Verifier-preprocessed fixed width for the extension-domain evaluator.
pub const P256_WINDOW_STARK_FIXED_WIDTH_V1: usize = 27;
/// Exact fixed-width constraint inventory per opened row.
pub const P256_WINDOW_STARK_CONSTRAINT_COUNT_V1: usize = 232;
/// Maximum total degree in committed and verifier-preprocessed columns.
pub const P256_WINDOW_STARK_CONSTRAINT_DEGREE_V1: u8 = 4;
/// External limbs packed into one physical row.
pub const P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1: usize = 3;
/// Coordinate limbs retained by the running selector.
pub const P256_WINDOW_COORDINATE_LIMBS_V1: usize = 16;
/// Projective coordinates in one point.
pub const P256_WINDOW_COORDINATES_V1: usize = 3;
/// Candidate points in one four-bit table.
pub const P256_WINDOW_CANDIDATES_V1: usize = 16;
/// Physical rows occupied by one point.
pub const P256_WINDOW_ROWS_PER_POINT_V1: usize = 16;
const ACCUMULATOR: usize = 0;
const EXTERNAL: usize = ACCUMULATOR + P256_WINDOW_COORDINATES_V1 * P256_WINDOW_COORDINATE_LIMBS_V1;
const BITS: usize = EXTERNAL + P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1;
const MATCH_PREFIX: usize = BITS + 4;
const SELECTOR: usize = MATCH_PREFIX + 4;
const SELECTED_COUNT: usize = SELECTOR + 1;
const _: () = assert!(SELECTED_COUNT + 1 == P256_WINDOW_BASE_WIDTH_V1);
const _: () = assert!(P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 == 65_536);
const _: () = assert!(P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1.is_power_of_two());
const STARK_CANDIDATE: usize = 0;
const STARK_OUTPUT: usize = STARK_CANDIDATE + 1;
const STARK_PADDING: usize = STARK_OUTPUT + 1;
const STARK_EXPECTED_BITS: usize = STARK_PADDING + 1;
const STARK_CHUNK_SELECTORS: usize = STARK_EXPECTED_BITS + 4;
const STARK_CHUNK_LAST: usize = STARK_CHUNK_SELECTORS + P256_WINDOW_ROWS_PER_POINT_V1;
const STARK_ACTIVE_FIRST: usize = STARK_CHUNK_LAST + 1;
const STARK_ACTIVE_FINAL: usize = STARK_ACTIVE_FIRST + 1;
const STARK_ACTIVE_CONTINUE: usize = STARK_ACTIVE_FINAL + 1;
const _: () = assert!(STARK_ACTIVE_CONTINUE + 1 == P256_WINDOW_STARK_FIXED_WIDTH_V1);
/// Which ECDSA scalar supplies this verifier-positioned nibble.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256WindowScalarV1 {
    /// `z * s^-1 mod n`.
    U1,
    /// `r * s^-1 mod n`.
    U2,
}
/// Projective coordinate selected or exposed by one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256WindowCoordinateV1 {
    /// Homogeneous x-coordinate.
    X,
    /// Homogeneous y-coordinate.
    Y,
    /// Homogeneous z-coordinate.
    Z,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256WindowCoordinateV1 {
    const fn index(self) -> usize {
        match self {
            Self::X => 0,
            Self::Y => 1,
            Self::Z => 2,
        }
    }
    const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::X),
            1 => Some(Self::Y),
            2 => Some(Self::Z),
            _ => None,
        }
    }
}
/// Exact projective point bytes used to build a selector witness.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256WindowPointV1 {
    /// Canonical x-coordinate.
    pub(crate) x_be: [u8; 32],
    /// Canonical y-coordinate.
    pub(crate) y_be: [u8; 32],
    /// Canonical z-coordinate.
    pub(crate) z_be: [u8; 32],
}
/// Verifier-fixed phase of one selector row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256WindowRowKindV1 {
    /// Three consecutive limbs of one candidate point.
    Candidate {
        /// Candidate table index.
        candidate: u8,
        /// Three-limb chunk within x, y, z in that order.
        chunk: u8,
    },
    /// Three consecutive limbs of the selected output point.
    Output {
        /// Three-limb chunk within x, y, z in that order.
        chunk: u8,
    },
}
/// Complete verifier-regenerated row identity.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256WindowFixedRowV1 {
    /// Scalar whose nibble is consumed.
    pub(crate) scalar: P256WindowScalarV1,
    /// Big-endian nibble index in that scalar, from 0 through 63.
    pub(crate) window: u8,
    /// Candidate or selected-output phase.
    pub(crate) kind: P256WindowRowKindV1,
}
/// Address of one pointwise value-bus read.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256WindowExternalAddressV1 {
    /// One coordinate limb of one table candidate.
    Candidate {
        /// Candidate table index.
        candidate: u8,
        /// Projective coordinate.
        coordinate: P256WindowCoordinateV1,
        /// Little-endian 16-bit limb index.
        limb: u8,
    },
    /// One coordinate limb of the selected output.
    Output {
        /// Projective coordinate.
        coordinate: P256WindowCoordinateV1,
        /// Little-endian 16-bit limb index.
        limb: u8,
    },
}
/// One complete 16-way point-selection trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256WindowTraceV1 {
    /// Verifier-regenerated topology.
    pub(crate) fixed: Vec<P256WindowFixedRowV1>,
    /// Committed witness rows.
    pub(crate) base: Vec<[F; P256_WINDOW_BASE_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256WindowTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256WindowTraceV1 { <private trace redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256WindowTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}

/// One aggregate commitment layout for all 128 verifier-positioned windows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256WindowBatchStarkTraceV1 {
    /// Vertically concatenated and per-window padded selector rows.
    pub(crate) base: Vec<[F; P256_WINDOW_BASE_WIDTH_V1]>,
    /// Sole zero auxiliary column before cross-trace products are appended.
    pub(crate) aux: Vec<[F; P256_WINDOW_STARK_AUX_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256WindowBatchStarkTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256WindowBatchStarkTraceV1 { <private trace redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256WindowBatchStarkTraceV1 {
    fn drop(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.base);
        super::private_table::zeroize_field_rows_v1(&mut self.aux);
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256WindowTraceV1 {
    /// Overwrite every witness-bearing selector row.
    pub(crate) fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.base);
        self.base.clear();
    }
    /// Validate the exact verifier-positioned lookup and all row identities.
    pub(crate) fn validate_for_v1(
        &self,
        scalar: P256WindowScalarV1,
        window: u8,
    ) -> Result<(), P256WindowAirErrorV1> {
        if window >= 64
            || self.fixed != fixed_rows_v1(scalar, window)
            || self.base.len() != P256_WINDOW_ROWS_V1
        {
            return Err(P256WindowAirErrorV1::Topology);
        }
        for row in 0..P256_WINDOW_ROWS_V1 {
            let residues = evaluate_p256_window_row_constraints_v1(
                self.fixed[row],
                &self.base[row],
                self.base.get(row + 1),
            )?;
            if residues.iter().any(|residue| *residue != F::ZERO) {
                return Err(P256WindowAirErrorV1::Constraint);
            }
        }
        Ok(())
    }
    /// Return one of the four algebraically repeated big-endian nibble bits.
    pub(crate) fn bit_v1(&self, bit: usize) -> Result<F, P256WindowAirErrorV1> {
        if bit >= 4 || self.base.len() != P256_WINDOW_ROWS_V1 {
            return Err(P256WindowAirErrorV1::Index);
        }
        Ok(self.base[0][BITS + bit])
    }
    /// Reconstruct the selected projective point from committed output rows.
    pub(crate) fn selected_point_v1(&self) -> Result<P256WindowPointV1, P256WindowAirErrorV1> {
        if self.base.len() != P256_WINDOW_ROWS_V1 {
            return Err(P256WindowAirErrorV1::Index);
        }
        let mut limbs = [[0_u16; P256_WINDOW_COORDINATE_LIMBS_V1]; P256_WINDOW_COORDINATES_V1];
        for chunk in 0..P256_WINDOW_ROWS_PER_POINT_V1 {
            let row = 16 * 16 + chunk;
            for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                let (coordinate, limb) = packed_limb_v1(chunk, slot)?;
                let value = self.base[row][EXTERNAL + slot].value();
                if value > u64::from(u16::MAX) {
                    return Err(P256WindowAirErrorV1::ExternalRange);
                }
                limbs[coordinate.index()][limb] = value as u16;
            }
        }
        Ok(P256WindowPointV1 {
            x_be: limbs_le_to_bytes_be_v1(limbs[0]),
            y_be: limbs_le_to_bytes_be_v1(limbs[1]),
            z_be: limbs_le_to_bytes_be_v1(limbs[2]),
        })
    }
}
/// Selector construction or constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum P256WindowAirErrorV1 {
    /// A scalar/window position or row order is invalid.
    #[error("zk-X509 P-256 window topology is invalid")]
    Topology,
    /// A bit, table, row, or slot index is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 window index is invalid")]
    Index,
    /// An external limb is not a canonical 16-bit value.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external window limb is out of range")]
    ExternalRange,
    /// A local or transition identity is nonzero.
    #[error("zk-X509 P-256 window constraint failed")]
    Constraint,
    /// A bounded fixed-trace allocation failed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 window allocation failed")]
    Allocation,
}
/// Build one fixed-topology selector witness.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_p256_window_trace_v1(
    scalar: P256WindowScalarV1,
    window: u8,
    table: [P256WindowPointV1; P256_WINDOW_CANDIDATES_V1],
    bits_be: [u8; 4],
) -> Result<P256WindowTraceV1, P256WindowAirErrorV1> {
    if window >= 64 || bits_be.iter().any(|bit| *bit > 1) {
        return Err(P256WindowAirErrorV1::Index);
    }
    let selected_index = bits_be
        .iter()
        .fold(0_usize, |value, bit| (value << 1) | usize::from(*bit));
    let table_limbs = table.map(point_limbs_v1);
    let selected_limbs = table_limbs[selected_index];
    let fixed = fixed_rows_v1(scalar, window);
    let mut base = super::private_table::PrivateTableV1::new(
        Vec::with_capacity(P256_WINDOW_ROWS_V1),
        super::private_table::zeroize_field_rows_v1,
    );
    let mut accumulator = [F::ZERO; P256_WINDOW_COORDINATES_V1 * P256_WINDOW_COORDINATE_LIMBS_V1];
    let mut selected_count = F::ZERO;
    for (candidate, candidate_limbs) in table_limbs.iter().enumerate() {
        let selector = if candidate == selected_index {
            F::ONE
        } else {
            F::ZERO
        };
        let prefixes = match_prefixes_v1(bits_be.map(|bit| F(u64::from(bit))), candidate as u8);
        for chunk in 0..P256_WINDOW_ROWS_PER_POINT_V1 {
            let mut row = [F::ZERO; P256_WINDOW_BASE_WIDTH_V1];
            row[ACCUMULATOR..ACCUMULATOR + accumulator.len()].copy_from_slice(&accumulator);
            for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                let (coordinate, limb) = packed_limb_v1(chunk, slot)?;
                let value = F(u64::from(candidate_limbs[coordinate.index()][limb]));
                row[EXTERNAL + slot] = value;
            }
            for bit in 0..4 {
                row[BITS + bit] = F(u64::from(bits_be[bit]));
                row[MATCH_PREFIX + bit] = prefixes[bit];
            }
            row[SELECTOR] = selector;
            row[SELECTED_COUNT] = selected_count;
            base.push(row);
            for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                let (coordinate, limb) = packed_limb_v1(chunk, slot)?;
                let index = coordinate.index() * P256_WINDOW_COORDINATE_LIMBS_V1 + limb;
                accumulator[index] = accumulator[index].add(selector.mul(row[EXTERNAL + slot]));
            }
            if chunk + 1 == P256_WINDOW_ROWS_PER_POINT_V1 {
                selected_count = selected_count.add(selector);
            }
        }
    }
    for chunk in 0..P256_WINDOW_ROWS_PER_POINT_V1 {
        let mut row = [F::ZERO; P256_WINDOW_BASE_WIDTH_V1];
        row[ACCUMULATOR..ACCUMULATOR + accumulator.len()].copy_from_slice(&accumulator);
        for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
            let (coordinate, limb) = packed_limb_v1(chunk, slot)?;
            row[EXTERNAL + slot] = F(u64::from(selected_limbs[coordinate.index()][limb]));
        }
        for bit in 0..4 {
            row[BITS + bit] = F(u64::from(bits_be[bit]));
        }
        row[SELECTED_COUNT] = selected_count;
        base.push(row);
    }
    let trace = P256WindowTraceV1 {
        fixed,
        base: base.into_vec(),
    };
    trace.validate_for_v1(scalar, window)?;
    Ok(trace)
}
/// Return the fixed pointwise value-bus address for one external row slot.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_window_external_address_v1(
    fixed: P256WindowFixedRowV1,
    slot: usize,
) -> Result<P256WindowExternalAddressV1, P256WindowAirErrorV1> {
    if slot >= P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
        return Err(P256WindowAirErrorV1::Index);
    }
    let (chunk, candidate) = match fixed.kind {
        P256WindowRowKindV1::Candidate { candidate, chunk } => {
            (usize::from(chunk), Some(candidate))
        }
        P256WindowRowKindV1::Output { chunk } => (usize::from(chunk), None),
    };
    let (coordinate, limb) = packed_limb_v1(chunk, slot)?;
    Ok(match candidate {
        Some(candidate) => P256WindowExternalAddressV1::Candidate {
            candidate,
            coordinate,
            limb: limb as u8,
        },
        None => P256WindowExternalAddressV1::Output {
            coordinate,
            limb: limb as u8,
        },
    })
}
/// Return one committed external limb for pointwise value-bus equality.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_window_external_limb_v1(
    trace: &P256WindowTraceV1,
    row: usize,
    slot: usize,
) -> Result<F, P256WindowAirErrorV1> {
    if row >= P256_WINDOW_ROWS_V1
        || slot >= P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1
        || trace.base.len() != P256_WINDOW_ROWS_V1
    {
        return Err(P256WindowAirErrorV1::Index);
    }
    Ok(trace.base[row][EXTERNAL + slot])
}
/// Project the three external cells directly from one committed base opening.
///
/// Unlike the native trace accessor, this projection also applies to an LDE
/// opening. The aggregate cross-trace product must consume these returned
/// fields directly rather than copying them into an unbound bridge trace.
pub const fn p256_window_opened_external_cells_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_WINDOW_BASE_WIDTH_V1],
) -> [A; P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1] {
    [base[EXTERNAL], base[EXTERNAL + 1], base[EXTERNAL + 2]]
}
/// Project the four committed selector bits from one opened window row.
///
/// Scalar source products select one of these cells with verifier-fixed
/// numeric columns; this projection itself never decodes a native row kind.
pub const fn p256_window_opened_scalar_bits_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_WINDOW_BASE_WIDTH_V1],
) -> [A; 4] {
    [base[BITS], base[BITS + 1], base[BITS + 2], base[BITS + 3]]
}
/// Evaluate one fixed selector row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_p256_window_row_constraints_v1(
    fixed: P256WindowFixedRowV1,
    base: &[F; P256_WINDOW_BASE_WIDTH_V1],
    next: Option<&[F; P256_WINDOW_BASE_WIDTH_V1]>,
) -> Result<Vec<F>, P256WindowAirErrorV1> {
    if fixed.window >= 64 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let mut residues = Vec::with_capacity(64);
    for bit in 0..4 {
        residues.push(boolean_residue_v1(base[BITS + bit]));
    }
    match fixed.kind {
        P256WindowRowKindV1::Candidate { candidate, chunk } => {
            if candidate >= 16 || chunk >= 16 || next.is_none() {
                return Err(P256WindowAirErrorV1::Topology);
            }
            let prefixes =
                match_prefixes_v1(core::array::from_fn(|bit| base[BITS + bit]), candidate);
            for bit in 0..4 {
                residues.push(base[MATCH_PREFIX + bit].sub(prefixes[bit]));
            }
            residues.push(base[SELECTOR].sub(base[MATCH_PREFIX + 3]));
            residues.push(boolean_residue_v1(base[SELECTOR]));
            if candidate == 0 && chunk == 0 {
                residues.extend(base[ACCUMULATOR..ACCUMULATOR + 48].iter().copied());
                residues.push(base[SELECTED_COUNT]);
            }
            let next = next.ok_or(P256WindowAirErrorV1::Topology)?;
            for index in 0..48 {
                let update = (0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1)
                    .find_map(|slot| {
                        let (coordinate, limb) = packed_limb_v1(usize::from(chunk), slot).ok()?;
                        let accumulator =
                            coordinate.index() * P256_WINDOW_COORDINATE_LIMBS_V1 + limb;
                        (accumulator == index).then_some(base[EXTERNAL + slot])
                    })
                    .unwrap_or(F::ZERO);
                residues.push(
                    next[ACCUMULATOR + index]
                        .sub(base[ACCUMULATOR + index])
                        .sub(base[SELECTOR].mul(update)),
                );
            }
            let increment = if chunk == 15 { base[SELECTOR] } else { F::ZERO };
            residues.push(
                next[SELECTED_COUNT]
                    .sub(base[SELECTED_COUNT])
                    .sub(increment),
            );
            append_bit_transition_residues_v1(&mut residues, base, next);
        }
        P256WindowRowKindV1::Output { chunk } => {
            if chunk >= 16 {
                return Err(P256WindowAirErrorV1::Topology);
            }
            for bit in 0..4 {
                residues.push(base[MATCH_PREFIX + bit]);
            }
            residues.push(base[SELECTOR]);
            for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                let (coordinate, limb) = packed_limb_v1(usize::from(chunk), slot)?;
                let accumulator = coordinate.index() * P256_WINDOW_COORDINATE_LIMBS_V1 + limb;
                residues.push(base[EXTERNAL + slot].sub(base[ACCUMULATOR + accumulator]));
            }
            match next {
                Some(next) => {
                    for index in 0..48 {
                        residues.push(next[ACCUMULATOR + index].sub(base[ACCUMULATOR + index]));
                    }
                    residues.push(next[SELECTED_COUNT].sub(base[SELECTED_COUNT]));
                    append_bit_transition_residues_v1(&mut residues, base, next);
                }
                None => {
                    if chunk != 15 {
                        return Err(P256WindowAirErrorV1::Topology);
                    }
                    residues.push(base[SELECTED_COUNT].sub(F::ONE));
                }
            }
        }
    }
    Ok(residues)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fixed_rows_v1(scalar: P256WindowScalarV1, window: u8) -> Vec<P256WindowFixedRowV1> {
    let mut fixed = Vec::with_capacity(P256_WINDOW_ROWS_V1);
    for candidate in 0..16 {
        for chunk in 0..16 {
            fixed.push(P256WindowFixedRowV1 {
                scalar,
                window,
                kind: P256WindowRowKindV1::Candidate { candidate, chunk },
            });
        }
    }
    for chunk in 0..16 {
        fixed.push(P256WindowFixedRowV1 {
            scalar,
            window,
            kind: P256WindowRowKindV1::Output { chunk },
        });
    }
    fixed
}
/// Compile the sole verifier-owned numeric window preprocessing trace.
///
/// Scalar role and window index are checked here and separately bound by the
/// scalar-bit/external-copy manifests. They do not become proof metadata.
#[cfg(test)]
pub fn compile_p256_window_stark_fixed_rows_v1(
    scalar: P256WindowScalarV1,
    window: u8,
) -> Result<Vec<[F; P256_WINDOW_STARK_FIXED_WIDTH_V1]>, P256WindowAirErrorV1> {
    if window >= 64 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let topology = fixed_rows_v1(scalar, window);
    if topology.len() != P256_WINDOW_ROWS_V1
        || P256_WINDOW_STARK_TRACE_SIZE_V1 < topology.len()
        || !P256_WINDOW_STARK_TRACE_SIZE_V1.is_power_of_two()
    {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(P256_WINDOW_STARK_TRACE_SIZE_V1)
        .map_err(|_| P256WindowAirErrorV1::Allocation)?;
    for (index, row) in topology.into_iter().enumerate() {
        let expected_index = match row.kind {
            P256WindowRowKindV1::Candidate { candidate, chunk } => {
                usize::from(candidate) * P256_WINDOW_ROWS_PER_POINT_V1 + usize::from(chunk)
            }
            P256WindowRowKindV1::Output { chunk } => {
                P256_WINDOW_CANDIDATES_V1 * P256_WINDOW_ROWS_PER_POINT_V1 + usize::from(chunk)
            }
        };
        if expected_index != index {
            return Err(P256WindowAirErrorV1::Topology);
        }
        rows.push(p256_window_stark_fixed_local_row_v1(index)?);
    }
    rows.resize_with(P256_WINDOW_STARK_TRACE_SIZE_V1, || {
        let mut fixed = [F::ZERO; P256_WINDOW_STARK_FIXED_WIDTH_V1];
        fixed[STARK_PADDING] = F::ONE;
        fixed
    });
    Ok(rows)
}
fn p256_window_stark_fixed_local_row_v1(
    local: usize,
) -> Result<[F; P256_WINDOW_STARK_FIXED_WIDTH_V1], P256WindowAirErrorV1> {
    if local >= P256_WINDOW_STARK_TRACE_SIZE_V1 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let mut fixed = [F::ZERO; P256_WINDOW_STARK_FIXED_WIDTH_V1];
    if local >= P256_WINDOW_ROWS_V1 {
        fixed[STARK_PADDING] = F::ONE;
        return Ok(fixed);
    }
    if local < P256_WINDOW_CANDIDATES_V1 * P256_WINDOW_ROWS_PER_POINT_V1 {
        let candidate = local / P256_WINDOW_ROWS_PER_POINT_V1;
        let chunk = local % P256_WINDOW_ROWS_PER_POINT_V1;
        fixed[STARK_CANDIDATE] = F::ONE;
        for bit in 0..4 {
            fixed[STARK_EXPECTED_BITS + bit] = F(((candidate >> (3 - bit)) & 1) as u64);
        }
        fixed[STARK_CHUNK_SELECTORS + chunk] = F::ONE;
        fixed[STARK_CHUNK_LAST] = F(u64::from(chunk + 1 == P256_WINDOW_ROWS_PER_POINT_V1));
        fixed[STARK_ACTIVE_FIRST] = F(u64::from(local == 0));
    } else {
        let chunk = local - P256_WINDOW_CANDIDATES_V1 * P256_WINDOW_ROWS_PER_POINT_V1;
        fixed[STARK_OUTPUT] = F::ONE;
        fixed[STARK_CHUNK_SELECTORS + chunk] = F::ONE;
        fixed[STARK_CHUNK_LAST] = F(u64::from(chunk + 1 == P256_WINDOW_ROWS_PER_POINT_V1));
        fixed[STARK_ACTIVE_FINAL] = F(u64::from(local + 1 == P256_WINDOW_ROWS_V1));
    }
    fixed[STARK_ACTIVE_CONTINUE] = F(u64::from(local + 1 < P256_WINDOW_ROWS_V1));
    Ok(fixed)
}
/// Constant-memory verifier preprocessing for the vertically packed window adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256WindowBatchStarkFixedProviderV1 {
    trace_size: usize,
}
impl P256WindowBatchStarkFixedProviderV1 {
    /// Establish one padded native domain.
    pub(crate) fn new_v1(trace_size: usize) -> Result<Self, P256WindowAirErrorV1> {
        if !trace_size.is_power_of_two() || trace_size < P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
            return Err(P256WindowAirErrorV1::Topology);
        }
        Ok(Self { trace_size })
    }
    /// Regenerate one exact numeric row without retaining 128 fixed blocks or their suffix.
    pub(crate) fn row_v1(
        self,
        index: usize,
    ) -> Result<[F; P256_WINDOW_STARK_FIXED_WIDTH_V1], P256WindowAirErrorV1> {
        if index >= self.trace_size {
            return Err(P256WindowAirErrorV1::Topology);
        }
        if index >= P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
            let mut fixed = [F::ZERO; P256_WINDOW_STARK_FIXED_WIDTH_V1];
            fixed[STARK_PADDING] = F::ONE;
            return Ok(fixed);
        }
        p256_window_stark_fixed_local_row_v1(index % P256_WINDOW_STARK_TRACE_SIZE_V1)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_window_batch_position_v1(
    index: usize,
) -> Result<(P256WindowScalarV1, u8), P256WindowAirErrorV1> {
    if index >= P256_WINDOW_BATCH_INSTANCES_V1 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let scalar = if index < 64 {
        P256WindowScalarV1::U1
    } else {
        P256WindowScalarV1::U2
    };
    let window = u8::try_from(index % 64).map_err(|_| P256WindowAirErrorV1::Allocation)?;
    Ok((scalar, window))
}
/// Compile all 128 selector schedules as vertical blocks of one commitment.
///
/// This is the sole aggregate layout: creating 128 horizontal commitment
/// instances would exceed both the instance ceiling and the proof-byte cap.
#[cfg(test)]
pub fn compile_p256_window_batch_stark_fixed_rows_v1()
-> Result<Vec<[F; P256_WINDOW_STARK_FIXED_WIDTH_V1]>, P256WindowAirErrorV1> {
    let provider =
        P256WindowBatchStarkFixedProviderV1::new_v1(P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1)
        .map_err(|_| P256WindowAirErrorV1::Allocation)?;
    for index in 0..P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
        rows.push(provider.row_v1(index)?);
    }
    if rows.len() != P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    Ok(rows)
}
/// Build the sole vertically packed aggregate witness for one ECDSA equation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_p256_window_batch_stark_trace_v1(
    windows: &[P256WindowTraceV1],
) -> Result<P256WindowBatchStarkTraceV1, P256WindowAirErrorV1> {
    if windows.len() != P256_WINDOW_BATCH_INSTANCES_V1 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let mut base = super::private_table::PrivateTableV1::new(
        Vec::new(),
        super::private_table::zeroize_field_rows_v1,
    );
    base.try_reserve_exact(P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1)
        .map_err(|_| P256WindowAirErrorV1::Allocation)?;
    for (index, trace) in windows.iter().enumerate() {
        let (scalar, window) = p256_window_batch_position_v1(index)?;
        trace.validate_for_v1(scalar, window)?;
        base.extend_from_slice(&trace.base);
        let block_end = (index + 1)
            .checked_mul(P256_WINDOW_STARK_TRACE_SIZE_V1)
            .ok_or(P256WindowAirErrorV1::Allocation)?;
        base.resize(block_end, [F::ZERO; P256_WINDOW_BASE_WIDTH_V1]);
    }
    if base.len() != P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    let aux =
        vec![[F::ZERO; P256_WINDOW_STARK_AUX_WIDTH_V1]; P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1];
    Ok(P256WindowBatchStarkTraceV1 {
        base: base.into_vec(),
        aux,
    })
}
fn stark_window_matching_bit_v1<A: PolynomialAirFieldV1>(bit: A, expected: A) -> A {
    expected
        .mul(bit)
        .add(A::ONE.sub(expected).mul(A::ONE.sub(bit)))
}
/// Evaluate one window row as a fixed-width extension-domain polynomial vector.
///
/// All row roles, candidate bits, chunk positions, and boundaries are numeric verifier
/// preprocessing. The evaluator never decodes a proof-controlled enum or index.
#[cfg(test)]
pub fn evaluate_p256_window_stark_residues_v1(
    current: &[F; P256_WINDOW_BASE_WIDTH_V1],
    next: &[F; P256_WINDOW_BASE_WIDTH_V1],
    current_aux: &[F; P256_WINDOW_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_WINDOW_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_WINDOW_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<F>, P256WindowAirErrorV1> {
    evaluate_p256_window_stark_residues_over_field_v1(current, next, current_aux, next_aux, fixed)
}
/// Shared numeric window polynomial over the base or extension field.
pub fn evaluate_p256_window_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_WINDOW_BASE_WIDTH_V1],
    next: &[A; P256_WINDOW_BASE_WIDTH_V1],
    current_aux: &[A; P256_WINDOW_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_WINDOW_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_WINDOW_STARK_FIXED_WIDTH_V1],
) -> Result<Vec<A>, P256WindowAirErrorV1> {
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(P256WindowAirErrorV1::Constraint);
    }
    let mut residues = Vec::with_capacity(P256_WINDOW_STARK_CONSTRAINT_COUNT_V1);
    for bit in 0..4 {
        residues.push(boolean_residue_v1(current[BITS + bit]));
    }
    residues.push(boolean_residue_v1(current[SELECTOR]));
    let candidate = fixed[STARK_CANDIDATE];
    for bit in 0..4 {
        let matching =
            stark_window_matching_bit_v1(current[BITS + bit], fixed[STARK_EXPECTED_BITS + bit]);
        let expected_prefix = if bit == 0 {
            matching
        } else {
            current[MATCH_PREFIX + bit - 1].mul(matching)
        };
        residues.push(candidate.mul(current[MATCH_PREFIX + bit].sub(expected_prefix)));
    }
    residues.push(candidate.mul(current[SELECTOR].sub(current[MATCH_PREFIX + 3])));
    let first = fixed[STARK_ACTIVE_FIRST];
    for accumulator in &current[ACCUMULATOR..ACCUMULATOR + 48] {
        residues.push(first.mul(*accumulator));
    }
    residues.push(first.mul(current[SELECTED_COUNT]));
    for accumulator in 0..48 {
        let chunk = accumulator / P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1;
        let slot = accumulator % P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1;
        let update = fixed[STARK_CHUNK_SELECTORS + chunk]
            .mul(current[SELECTOR])
            .mul(current[EXTERNAL + slot]);
        residues.push(
            candidate.mul(
                next[ACCUMULATOR + accumulator]
                    .sub(current[ACCUMULATOR + accumulator])
                    .sub(update),
            ),
        );
    }
    residues.push(
        candidate.mul(
            next[SELECTED_COUNT]
                .sub(current[SELECTED_COUNT])
                .sub(fixed[STARK_CHUNK_LAST].mul(current[SELECTOR])),
        ),
    );
    let output = fixed[STARK_OUTPUT];
    for prefix in &current[MATCH_PREFIX..MATCH_PREFIX + 4] {
        residues.push(output.mul(*prefix));
    }
    residues.push(output.mul(current[SELECTOR]));
    for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
        let selected =
            (0..P256_WINDOW_ROWS_PER_POINT_V1).fold(A::ZERO, |sum, chunk| {
                sum.add(fixed[STARK_CHUNK_SELECTORS + chunk].mul(
                    current[ACCUMULATOR + chunk * P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 + slot],
                ))
            });
        residues.push(output.mul(current[EXTERNAL + slot].sub(selected)));
    }
    let output_continue = output.mul(fixed[STARK_ACTIVE_CONTINUE]);
    for accumulator in 0..48 {
        residues.push(
            output_continue
                .mul(next[ACCUMULATOR + accumulator].sub(current[ACCUMULATOR + accumulator])),
        );
    }
    residues.push(output_continue.mul(next[SELECTED_COUNT].sub(current[SELECTED_COUNT])));
    residues.push(fixed[STARK_ACTIVE_FINAL].mul(current[SELECTED_COUNT].sub(A::ONE)));
    for bit in 0..4 {
        residues.push(fixed[STARK_ACTIVE_CONTINUE].mul(next[BITS + bit].sub(current[BITS + bit])));
    }
    let padding = fixed[STARK_PADDING];
    for value in current {
        residues.push(padding.mul(*value));
    }
    residues.push(current_aux[0]);
    if residues.len() != P256_WINDOW_STARK_CONSTRAINT_COUNT_V1 {
        return Err(P256WindowAirErrorV1::Topology);
    }
    Ok(residues)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn packed_limb_v1(
    chunk: usize,
    slot: usize,
) -> Result<(P256WindowCoordinateV1, usize), P256WindowAirErrorV1> {
    if chunk >= P256_WINDOW_ROWS_PER_POINT_V1 || slot >= P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
        return Err(P256WindowAirErrorV1::Index);
    }
    let packed = chunk * P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 + slot;
    let coordinate = P256WindowCoordinateV1::from_index(packed / P256_WINDOW_COORDINATE_LIMBS_V1)
        .ok_or(P256WindowAirErrorV1::Index)?;
    Ok((coordinate, packed % P256_WINDOW_COORDINATE_LIMBS_V1))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn match_prefixes_v1(bits: [F; 4], candidate: u8) -> [F; 4] {
    let mut prefix = F::ONE;
    core::array::from_fn(|bit| {
        let expected = (candidate >> (3 - bit)) & 1;
        let matching = if expected == 1 {
            bits[bit]
        } else {
            F::ONE.sub(bits[bit])
        };
        prefix = prefix.mul(matching);
        prefix
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn append_bit_transition_residues_v1(
    residues: &mut Vec<F>,
    base: &[F; P256_WINDOW_BASE_WIDTH_V1],
    next: &[F; P256_WINDOW_BASE_WIDTH_V1],
) {
    for bit in 0..4 {
        residues.push(next[BITS + bit].sub(base[BITS + bit]));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn point_limbs_v1(
    point: P256WindowPointV1,
) -> [[u16; P256_WINDOW_COORDINATE_LIMBS_V1]; P256_WINDOW_COORDINATES_V1] {
    [
        bytes_be_to_limbs_le_v1(point.x_be),
        bytes_be_to_limbs_le_v1(point.y_be),
        bytes_be_to_limbs_le_v1(point.z_be),
    ]
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn bytes_be_to_limbs_le_v1(bytes: [u8; 32]) -> [u16; P256_WINDOW_COORDINATE_LIMBS_V1] {
    core::array::from_fn(|limb| {
        let low = 31 - 2 * limb;
        u16::from_be_bytes([bytes[low - 1], bytes[low]])
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn limbs_le_to_bytes_be_v1(limbs: [u16; P256_WINDOW_COORDINATE_LIMBS_V1]) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (limb, value) in limbs.into_iter().enumerate() {
        let low = 31 - 2 * limb;
        let encoded = value.to_be_bytes();
        bytes[low - 1] = encoded[0];
        bytes[low] = encoded[1];
    }
    bytes
}
fn boolean_residue_v1<A: PolynomialAirFieldV1>(value: A) -> A {
    value.mul(value.sub(A::ONE))
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_window_erasure_covers_drop_and_partially_built_batch() {
        use super::super::private_table::inspection::observe_v1;
        let trace = build_p256_window_trace_v1(P256WindowScalarV1::U1, 0, table_v1(), [1, 0, 1, 0])
            .unwrap();
        assert_eq!(
            format!("{trace:?}"),
            "P256WindowTraceV1 { <private trace redacted> }"
        );
        let cells = trace.base.len() * P256_WINDOW_BASE_WIDTH_V1;
        let ((), observed) = observe_v1(|| drop(trace));
        assert_eq!(observed.iter().map(|item| item.cells).sum::<usize>(), cells);
        assert!(observed.iter().any(|item| item.nonzero_before > 0));
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        let mut windows = window_batch_v1();
        windows[1].fixed[0] = windows[0].fixed[0];
        let (result, observed) = observe_v1(|| build_p256_window_batch_stark_trace_v1(&windows));
        assert!(result.is_err());
        assert!(
            observed
                .iter()
                .any(|item| item.cells >= cells && item.nonzero_before > 0)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    use super::*;
    fn point_v1(tag: u8) -> P256WindowPointV1 {
        let mut x = [0_u8; 32];
        let mut y = [0_u8; 32];
        let mut z = [0_u8; 32];
        for index in 0..32 {
            x[index] = tag.wrapping_mul(17).wrapping_add(index as u8);
            y[index] = tag.wrapping_mul(29).wrapping_add((2 * index) as u8);
            z[index] = tag.wrapping_mul(43).wrapping_add((3 * index) as u8);
        }
        P256WindowPointV1 {
            x_be: x,
            y_be: y,
            z_be: z,
        }
    }
    fn table_v1() -> [P256WindowPointV1; 16] {
        core::array::from_fn(|candidate| point_v1(candidate as u8))
    }
    fn bits_v1(candidate: usize) -> [u8; 4] {
        core::array::from_fn(|bit| ((candidate >> (3 - bit)) & 1) as u8)
    }
    fn trace_v1(candidate: usize) -> P256WindowTraceV1 {
        build_p256_window_trace_v1(P256WindowScalarV1::U1, 37, table_v1(), bits_v1(candidate))
            .expect("valid selector")
    }
    #[test]
    fn all_sixteen_nibbles_select_exact_id_contiguous_points() {
        for selected in 0..16 {
            let trace = trace_v1(selected);
            assert_eq!(trace.selected_point_v1().unwrap(), table_v1()[selected]);
            assert_eq!(trace.fixed.len(), P256_WINDOW_ROWS_V1);
            assert_eq!(trace.base.len(), P256_WINDOW_ROWS_V1);
            for row in 0..P256_WINDOW_ROWS_V1 {
                assert_eq!(
                    p256_window_opened_external_cells_v1(&trace.base[row]),
                    core::array::from_fn(|slot| {
                        p256_window_external_limb_v1(&trace, row, slot)
                            .expect("in-range committed external cell")
                    }),
                );
                for slot in 0..3 {
                    let address = p256_window_external_address_v1(trace.fixed[row], slot).unwrap();
                    let expected_packed = (row % 16) * 3 + slot;
                    let expected_coordinate =
                        P256WindowCoordinateV1::from_index(expected_packed / 16).unwrap();
                    let expected_limb = (expected_packed % 16) as u8;
                    match address {
                        P256WindowExternalAddressV1::Candidate {
                            candidate,
                            coordinate,
                            limb,
                        } => {
                            assert_eq!(candidate as usize, row / 16);
                            assert_eq!(coordinate, expected_coordinate);
                            assert_eq!(limb, expected_limb);
                        }
                        P256WindowExternalAddressV1::Output { coordinate, limb } => {
                            assert!(row >= 256);
                            assert_eq!(coordinate, expected_coordinate);
                            assert_eq!(limb, expected_limb);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn wrong_bits_selector_prefix_accumulator_count_and_output_fail_closed() {
        let attacks = [
            (0, BITS, F(2)),
            (16 * 5, MATCH_PREFIX + 3, F::ZERO),
            (16 * 5, SELECTOR, F::ZERO),
            (0, ACCUMULATOR + 7, F::ONE),
            (16 * 5 + 15, SELECTED_COUNT, F::ONE),
            (256 + 9, EXTERNAL + 1, F(65_535)),
        ];
        for (row, column, replacement) in attacks {
            let mut trace = trace_v1(5);
            trace.base[row][column] = replacement;
            assert_eq!(
                trace.validate_for_v1(P256WindowScalarV1::U1, 37),
                Err(P256WindowAirErrorV1::Constraint),
                "row {row}, column {column}"
            );
        }
    }
    #[test]
    fn coordinated_wrong_candidate_and_bit_changes_fail() {
        let mut trace = trace_v1(9);
        // Try to turn candidate 8 into the selected row without changing the
        // verifier-positioned scalar bits throughout the full trace.
        for chunk in 0..16 {
            let row = 8 * 16 + chunk;
            trace.base[row][MATCH_PREFIX + 3] = F::ONE;
            trace.base[row][SELECTOR] = F::ONE;
        }
        assert_eq!(
            trace.validate_for_v1(P256WindowScalarV1::U1, 37),
            Err(P256WindowAirErrorV1::Constraint)
        );
        let mut trace = trace_v1(9);
        // Changing every repeated bit still cannot rebind the fixed scalar
        // position once the scalar-bit copy bus supplies the expected bits;
        // even locally, changing only one phase violates transitions.
        trace.base[80][BITS] = F::ONE.sub(trace.base[80][BITS]);
        assert_eq!(
            trace.validate_for_v1(P256WindowScalarV1::U1, 37),
            Err(P256WindowAirErrorV1::Constraint)
        );
    }
    #[test]
    fn selected_candidate_limb_mutations_and_output_aliases_fail() {
        for packed in 0..48 {
            let mut trace = trace_v1(11);
            let row = 11 * 16 + packed / 3;
            let slot = packed % 3;
            trace.base[row][EXTERNAL + slot] = trace.base[row][EXTERNAL + slot].add(F::ONE);
            assert_eq!(
                trace.validate_for_v1(P256WindowScalarV1::U1, 37),
                Err(P256WindowAirErrorV1::Constraint),
                "selected packed limb {packed}"
            );
        }
        for packed in 0..48 {
            let mut trace = trace_v1(11);
            let row = 256 + packed / 3;
            let slot = packed % 3;
            trace.base[row][EXTERNAL + slot] = trace.base[row][EXTERNAL + slot].add(F::ONE);
            assert_eq!(
                trace.validate_for_v1(P256WindowScalarV1::U1, 37),
                Err(P256WindowAirErrorV1::Constraint),
                "output packed limb {packed}"
            );
        }
    }
    #[test]
    fn every_accumulator_and_control_cell_is_constraint_relevant() {
        let baseline = trace_v1(13);
        for row in 0..P256_WINDOW_ROWS_V1 {
            for column in 0..P256_WINDOW_BASE_WIDTH_V1 {
                // Unselected external candidate limbs are intentionally
                // constrained only by the aggregate value bus.
                let unselected_external =
                    row < 256 && row / 16 != 13 && (EXTERNAL..EXTERNAL + 3).contains(&column);
                if unselected_external {
                    continue;
                }
                let mut attacked = baseline.clone();
                attacked.base[row][column] = attacked.base[row][column].add(F::ONE);
                assert_eq!(
                    attacked.validate_for_v1(P256WindowScalarV1::U1, 37),
                    Err(P256WindowAirErrorV1::Constraint),
                    "row {row}, column {column}"
                );
            }
        }
    }
    #[test]
    fn topology_positions_bits_and_indices_are_fail_closed() {
        let trace = trace_v1(3);
        assert_eq!(
            trace.validate_for_v1(P256WindowScalarV1::U2, 37),
            Err(P256WindowAirErrorV1::Topology)
        );
        assert_eq!(
            trace.validate_for_v1(P256WindowScalarV1::U1, 36),
            Err(P256WindowAirErrorV1::Topology)
        );
        assert_eq!(trace.bit_v1(4), Err(P256WindowAirErrorV1::Index));
        assert_eq!(
            p256_window_external_limb_v1(&trace, 272, 0),
            Err(P256WindowAirErrorV1::Index)
        );
        assert_eq!(
            p256_window_external_address_v1(trace.fixed[0], 3),
            Err(P256WindowAirErrorV1::Index)
        );
        assert_eq!(
            build_p256_window_trace_v1(P256WindowScalarV1::U1, 64, table_v1(), [0; 4],),
            Err(P256WindowAirErrorV1::Index)
        );
        assert_eq!(
            build_p256_window_trace_v1(P256WindowScalarV1::U1, 0, table_v1(), [0, 0, 0, 2],),
            Err(P256WindowAirErrorV1::Index)
        );
    }
    fn validate_numeric_window_v1(trace: &P256WindowTraceV1) -> Result<(), P256WindowAirErrorV1> {
        let fixed =
            compile_p256_window_stark_fixed_rows_v1(trace.fixed[0].scalar, trace.fixed[0].window)?;
        if trace.fixed != fixed_rows_v1(trace.fixed[0].scalar, trace.fixed[0].window) {
            return Err(P256WindowAirErrorV1::Topology);
        }
        let mut base = trace.base.clone();
        base.resize(
            P256_WINDOW_STARK_TRACE_SIZE_V1,
            [F::ZERO; P256_WINDOW_BASE_WIDTH_V1],
        );
        let aux = vec![[F::ZERO; P256_WINDOW_STARK_AUX_WIDTH_V1]; P256_WINDOW_STARK_TRACE_SIZE_V1];
        for row in 0..P256_WINDOW_STARK_TRACE_SIZE_V1 {
            let next = (row + 1) % P256_WINDOW_STARK_TRACE_SIZE_V1;
            let residues = evaluate_p256_window_stark_residues_v1(
                &base[row],
                &base[next],
                &aux[row],
                &aux[next],
                &fixed[row],
            )?;
            if residues.len() != P256_WINDOW_STARK_CONSTRAINT_COUNT_V1
                || residues.iter().any(|residue| *residue != F::ZERO)
            {
                return Err(P256WindowAirErrorV1::Constraint);
            }
        }
        Ok(())
    }
    fn window_batch_v1() -> Vec<P256WindowTraceV1> {
        let mut windows = Vec::with_capacity(P256_WINDOW_BATCH_INSTANCES_V1);
        for index in 0..P256_WINDOW_BATCH_INSTANCES_V1 {
            let (scalar, window) = p256_window_batch_position_v1(index).expect("batch position");
            windows.push(
                build_p256_window_trace_v1(
                    scalar,
                    window,
                    table_v1(),
                    bits_v1((index * 11 + 7) % P256_WINDOW_CANDIDATES_V1),
                )
                .expect("canonical batch window"),
            );
        }
        windows
    }
    #[test]
    fn aggregate_batch_is_one_exact_vertical_commitment_not_128_instances() {
        let windows = window_batch_v1();
        let trace =
            build_p256_window_batch_stark_trace_v1(&windows).expect("vertical window batch");
        let fixed = compile_p256_window_batch_stark_fixed_rows_v1().expect("batch preprocessing");
        assert_eq!(P256_WINDOW_BATCH_INSTANCES_V1, 128);
        assert_eq!(P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1, 65_536);
        assert_eq!(trace.base.len(), P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1);
        assert_eq!(trace.aux.len(), P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1);
        assert_eq!(fixed.len(), P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1);
        assert!(
            ZK_X509_P256_WINDOW_BATCH_DESCRIPTOR_V1
                .windows(b"no-horizontal-instance-expansion".len())
                .any(|window| window == b"no-horizontal-instance-expansion"),
        );
        for (row, fixed_row) in fixed.iter().enumerate() {
            let next = (row + 1) % P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1;
            let residues = evaluate_p256_window_stark_residues_v1(
                &trace.base[row],
                &trace.base[next],
                &trace.aux[row],
                &trace.aux[next],
                fixed_row,
            )
            .expect("canonical batch opening");
            assert_eq!(residues.len(), P256_WINDOW_STARK_CONSTRAINT_COUNT_V1);
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "batch row {row}",
            );
        }
        for block in 0..P256_WINDOW_BATCH_INSTANCES_V1 {
            let start = block * P256_WINDOW_STARK_TRACE_SIZE_V1;
            let padding = start + P256_WINDOW_ROWS_V1;
            assert_eq!(fixed[start][STARK_ACTIVE_FIRST], F::ONE);
            assert_eq!(fixed[padding][STARK_PADDING], F::ONE);
            assert!(
                trace.base[padding..start + P256_WINDOW_STARK_TRACE_SIZE_V1]
                    .iter()
                    .all(|row| row.iter().all(|value| *value == F::ZERO)),
            );
        }
    }
    #[test]
    fn aggregate_batch_rejects_missing_extra_and_reordered_typed_blocks() {
        let windows = window_batch_v1();
        let mut missing = windows.clone();
        missing.pop();
        assert_eq!(
            build_p256_window_batch_stark_trace_v1(&missing),
            Err(P256WindowAirErrorV1::Topology),
        );
        let mut extra = windows.clone();
        extra.push(windows[0].clone());
        assert_eq!(
            build_p256_window_batch_stark_trace_v1(&extra),
            Err(P256WindowAirErrorV1::Topology),
        );
        let mut reordered = windows;
        reordered.swap(0, 1);
        assert_eq!(
            build_p256_window_batch_stark_trace_v1(&reordered),
            Err(P256WindowAirErrorV1::Topology),
        );
        assert_eq!(
            p256_window_batch_position_v1(P256_WINDOW_BATCH_INSTANCES_V1),
            Err(P256WindowAirErrorV1::Topology),
        );
    }
    #[test]
    fn numeric_fixed_evaluator_matches_all_nibbles_and_canonical_padding() {
        for selected in 0..16 {
            validate_numeric_window_v1(&trace_v1(selected))
                .expect("numeric window evaluator accepts exact selection");
        }
        assert_eq!(
            compile_p256_window_stark_fixed_rows_v1(P256WindowScalarV1::U1, 64),
            Err(P256WindowAirErrorV1::Topology)
        );
    }
    #[test]
    fn numeric_evaluator_binds_every_selected_and_padding_base_column() {
        let trace = trace_v1(13);
        let fixed = compile_p256_window_stark_fixed_rows_v1(P256WindowScalarV1::U1, 37).unwrap();
        let mut base = trace.base.clone();
        base.resize(
            P256_WINDOW_STARK_TRACE_SIZE_V1,
            [F::ZERO; P256_WINDOW_BASE_WIDTH_V1],
        );
        let aux = vec![[F::ZERO; P256_WINDOW_STARK_AUX_WIDTH_V1]; P256_WINDOW_STARK_TRACE_SIZE_V1];
        let rejects = |base: &[[F; P256_WINDOW_BASE_WIDTH_V1]]| {
            (0..P256_WINDOW_STARK_TRACE_SIZE_V1).any(|row| {
                let next = (row + 1) % P256_WINDOW_STARK_TRACE_SIZE_V1;
                match evaluate_p256_window_stark_residues_v1(
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
        let selected_row = 13 * P256_WINDOW_ROWS_PER_POINT_V1 + 7;
        for column in 0..P256_WINDOW_BASE_WIDTH_V1 {
            let mut changed = base.clone();
            changed[selected_row][column] = changed[selected_row][column].add(F::ONE);
            assert!(rejects(&changed), "unbound selected-row column {column}");
            let mut changed = base.clone();
            changed[P256_WINDOW_ROWS_V1][column] = changed[P256_WINDOW_ROWS_V1][column].add(F::ONE);
            assert!(rejects(&changed), "unbound padding column {column}");
        }
    }
    #[test]
    fn numeric_evaluator_rejects_auxiliary_fixed_and_noncanonical_attacks() {
        let trace = trace_v1(6);
        let mut base = trace.base.clone();
        base.resize(
            P256_WINDOW_STARK_TRACE_SIZE_V1,
            [F::ZERO; P256_WINDOW_BASE_WIDTH_V1],
        );
        let fixed = compile_p256_window_stark_fixed_rows_v1(P256WindowScalarV1::U1, 37).unwrap();
        let zero_aux = [F::ZERO; P256_WINDOW_STARK_AUX_WIDTH_V1];
        let mut bad_aux = zero_aux;
        bad_aux[0] = F::ONE;
        let residues = evaluate_p256_window_stark_residues_v1(
            &base[0], &base[1], &bad_aux, &zero_aux, &fixed[0],
        )
        .expect("canonical nonzero auxiliary");
        assert!(residues.iter().any(|residue| *residue != F::ZERO));
        let row = 6 * P256_WINDOW_ROWS_PER_POINT_V1;
        let mut wrong_fixed = fixed[row];
        wrong_fixed[STARK_EXPECTED_BITS] = F::ONE.sub(wrong_fixed[STARK_EXPECTED_BITS]);
        let residues = evaluate_p256_window_stark_residues_v1(
            &base[row],
            &base[row + 1],
            &zero_aux,
            &zero_aux,
            &wrong_fixed,
        )
        .expect("canonical substituted fixed row");
        assert!(residues.iter().any(|residue| *residue != F::ZERO));
        let mut noncanonical = base[0];
        noncanonical[0] = F(u64::MAX);
        assert_eq!(
            evaluate_p256_window_stark_residues_v1(
                &noncanonical,
                &base[1],
                &zero_aux,
                &zero_aux,
                &fixed[0],
            ),
            Err(P256WindowAirErrorV1::Constraint)
        );
    }
}
