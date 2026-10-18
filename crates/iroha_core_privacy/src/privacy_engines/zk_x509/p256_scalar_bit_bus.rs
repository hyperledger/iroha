//! Pointwise scalar-bit copy bus for the complete P-256 window schedule.
//!
//! The P-256 arithmetic chip decomposes each scalar result into sixteen little-endian 16-bit limbs.
//! The window chip consumes 64 big-endian four-bit nibbles for each of `u1` and `u2`. This module
//! fixes the conversion between those layouts and binds every one of the 512 consumed bits directly
//! to the corresponding committed arithmetic `c` bit.
//!
//! Four independently challenged products audit the same fixed-address copy relation. Three
//! consecutive factors are packed into one physical row with explicit intermediate products, so
//! every product transition remains degree two. The 513th and final slot is canonical inactive
//! padding. Deterministic per-slot equality is also enforced; correctness therefore does not depend
//! on a probabilistic permutation argument.
//!
//! The aggregate zk-X509 proof commits the arithmetic trace and all 128 window traces before
//! sampling these challenges; this bus has no standalone activation path.
#[cfg(not(any(test, feature = "privacy-release-evidence")))]
use super::p256_window_air::P256WindowScalarV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    credential_pre_aux::ZkX509CredentialMainPostBaseChallengesV1,
    p256_air::{
        P256_ARITHMETIC_ROWS_PER_OPERATION_V1, ZkX509P256AirErrorV1, ZkX509P256ArithmeticTraceV1,
        ZkX509P256ModulusV1, p256_arithmetic_c_limb_bits_v1,
    },
    p256_window_air::{P256WindowAirErrorV1, P256WindowScalarV1, P256WindowTraceV1},
};
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, PolynomialAirFieldV1, TransparentStarkErrorV1, TransparentTranscriptV1,
};
use thiserror::Error;
/// Stable descriptor for the aggregate-only first-release scalar-bit copy bus.
#[cfg(test)]
pub const ZK_X509_P256_SCALAR_BIT_BUS_DESCRIPTOR_V1: &[u8] = b"zk-x509-p256-scalar-bit-bus-v2-incompatible:two-verifier-fixed-scalars-u1-then-u2:64-big-endian-four-bit-windows-per-scalar:pointwise-map-to-little-endian-c-limb-bits:scalar-field-c-operations-distinct:deterministic-bit-equality:four-post-arithmetic-and-window-commitment-products:scalar-window-bit-value-tuples:three-factors-per-physical-row:one-canonical-inactive-factor:256-row-canonical-padding:aggregate-base6:aux32:verifier-fixed16:constraints67-degree3:source-side-terminal-binding=complete-via-p256-aggregate-adapter:standalone-activation=not-applicable";
/// Independent tuple-product lanes.
pub const P256_SCALAR_BIT_BUS_LANES_V1: usize = 4;
/// `beta`, scalar, window, bit-within-window, and value.
pub const P256_SCALAR_BIT_BUS_TUPLE_TERMS_V1: usize = 5;
/// Consecutive low-degree factors packed into one physical row.
pub const P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1: usize = 3;
/// Fixed four-bit windows consumed by each scalar.
pub const P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1: usize = 64;
/// Scalars consumed by ECDSA verification: `u1` and `u2`.
pub const P256_SCALAR_BIT_BUS_SCALARS_V1: usize = 2;
/// Verifier-owned arithmetic operation supplying the `u1` scalar.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const P256_SCALAR_BIT_BUS_U1_C_OPERATION_V1: u32 = 13;
/// Verifier-owned arithmetic operation supplying the `u2` scalar.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const P256_SCALAR_BIT_BUS_U2_C_OPERATION_V1: u32 = 14;
/// Pointwise bit copies in the complete schedule.
pub const P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1: usize =
    P256_SCALAR_BIT_BUS_SCALARS_V1 * P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1 * 4;
/// Physical rows after packing three factors and adding canonical padding.
pub const P256_SCALAR_BIT_BUS_ROWS_V1: usize =
    P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1.div_ceil(P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1);
/// Total factor slots, including exactly one inactive slot.
pub const P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1: usize =
    P256_SCALAR_BIT_BUS_ROWS_V1 * P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1;
/// Sole padded aggregate trace size.
pub const P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1: usize = 256;
/// Committed arithmetic/window bit copies.
pub const P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1: usize = 6;
/// Two four-state, four-lane product families.
pub const P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1: usize = 32;
/// Verifier-preprocessed slot coordinates and row boundaries.
pub const P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1: usize = 16;
/// Exact fixed-width opened-row constraint inventory.
pub const P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1: usize = 67;
/// Maximum total polynomial degree.
pub const P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_DEGREE_V1: u8 = 3;
const P256_SCALAR_BITS_V1: usize = 256;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const P256_SCALAR_LIMBS_V1: usize = 16;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const P256_SCALAR_LIMB_BITS_V1: usize = 16;
const P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1: usize = P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 + 1;
const STARK_ARITHMETIC_BITS: usize = 0;
const STARK_WINDOW_BITS: usize = STARK_ARITHMETIC_BITS + P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1;
const STARK_ARITHMETIC_PRODUCTS: usize = 0;
const STARK_WINDOW_PRODUCTS: usize = STARK_ARITHMETIC_PRODUCTS
    + P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 * P256_SCALAR_BIT_BUS_LANES_V1;
const STARK_FIXED_SLOT_WIDTH: usize = 4;
const STARK_FIXED_SLOT_ACTIVE: usize = 0;
const STARK_FIXED_SLOT_SCALAR: usize = 1;
const STARK_FIXED_SLOT_WINDOW: usize = 2;
const STARK_FIXED_SLOT_BIT: usize = 3;
const STARK_FIXED_FIRST_ROW: usize =
    P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 * STARK_FIXED_SLOT_WIDTH;
const STARK_FIXED_LAST_ACTIVE_ROW: usize = STARK_FIXED_FIRST_ROW + 1;
const STARK_FIXED_ACTIVE_CONTINUE: usize = STARK_FIXED_LAST_ACTIVE_ROW + 1;
const STARK_FIXED_PADDING: usize = STARK_FIXED_ACTIVE_CONTINUE + 1;
const _: () = assert!(P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1 == 512);
const _: () = assert!(P256_SCALAR_BIT_BUS_ROWS_V1 == 171);
const _: () = assert!(P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1 == 513);
const _: () =
    assert!(P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1 - P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1 == 1);
#[cfg(any(test, feature = "privacy-release-evidence"))]
const _: () = assert!(P256_SCALAR_LIMBS_V1 * P256_SCALAR_LIMB_BITS_V1 == P256_SCALAR_BITS_V1);
const _: () = assert!(
    STARK_WINDOW_BITS + P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1
        == P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1
);
const _: () = assert!(
    STARK_WINDOW_PRODUCTS + P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 * P256_SCALAR_BIT_BUS_LANES_V1
        == P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1
);
const _: () = assert!(STARK_FIXED_PADDING + 1 == P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1);
/// One verifier-fixed scalar result supplying 64 window nibbles.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ScalarBitSourceV1 {
    /// `u1` or `u2`; sources must be supplied in that order.
    pub(crate) scalar: P256WindowScalarV1,
    /// Arithmetic operation whose committed scalar-field `c` is consumed.
    pub(crate) c_operation: u32,
}
/// Verifier-regenerated identity for one factor slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ScalarBitBusFixedAccessV1 {
    /// Canonical product-identity padding.
    Inactive,
    /// One big-endian bit in one verifier-positioned scalar nibble.
    Active {
        /// `u1` or `u2`.
        scalar: P256WindowScalarV1,
        /// Big-endian nibble index, from zero through 63.
        window: u8,
        /// Big-endian bit within the nibble, from zero through three.
        bit: u8,
    },
}
/// One tuple-compression lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ScalarBitBusLaneChallengesV1 {
    /// `beta` followed by coefficients for scalar, window, bit, and value.
    pub(crate) terms: [F; P256_SCALAR_BIT_BUS_TUPLE_TERMS_V1],
}
/// Four independently sampled tuple products.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ScalarBitBusChallengesV1 {
    /// Transcript-separated product lanes.
    pub(crate) lanes: [P256ScalarBitBusLaneChallengesV1; P256_SCALAR_BIT_BUS_LANES_V1],
}
impl P256ScalarBitBusChallengesV1 {
    /// Reject zero, non-canonical, or repeated challenge coordinates.
    pub(crate) fn validate_v1(self) -> Result<(), P256ScalarBitBusErrorV1> {
        let mut seen = [F::ZERO; P256_SCALAR_BIT_BUS_LANES_V1 * P256_SCALAR_BIT_BUS_TUPLE_TERMS_V1];
        let mut count = 0;
        for lane in self.lanes {
            for term in lane.terms {
                if F::canonical(term.0).is_none()
                    || term == F::ZERO
                    || seen[..count].contains(&term)
                {
                    return Err(P256ScalarBitBusErrorV1::Challenge);
                }
                seen[count] = term;
                count += 1;
            }
        }
        Ok(())
    }
}
/// One physical AIR row containing three pointwise copy factors.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ScalarBitBusRowV1 {
    /// Verifier-regenerated identities for all three slots.
    pub(crate) fixed: [P256ScalarBitBusFixedAccessV1; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
    /// Bits copied from committed arithmetic `c` decomposition cells.
    pub(crate) arithmetic_bits: [F; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
    /// Bits copied from committed window selector cells.
    pub(crate) window_bits: [F; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
    /// Arithmetic-endpoint products before, between, and after the factors.
    pub(crate) arithmetic_products:
        [[F; P256_SCALAR_BIT_BUS_LANES_V1]; P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1],
    /// Window-endpoint products before, between, and after the factors.
    pub(crate) window_products:
        [[F; P256_SCALAR_BIT_BUS_LANES_V1]; P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1],
}
/// Complete scalar-bit copy trace.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256ScalarBitBusTraceV1 {
    /// Exactly 171 packed rows: 512 active factors and one inactive factor.
    pub(crate) rows: Vec<P256ScalarBitBusRowV1>,
}
/// Scalar-bit topology, source, equality, or product failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum P256ScalarBitBusErrorV1 {
    /// Scalar sources, operation positions, windows, or packed rows are invalid.
    #[error("zk-X509 P-256 scalar-bit bus topology is invalid")]
    Topology,
    /// An arithmetic endpoint is not its committed scalar `c` bit.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 scalar-bit arithmetic source binding is invalid")]
    ArithmeticSource,
    /// A window endpoint is not its committed selector bit.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 scalar-bit window source binding is invalid")]
    WindowSource,
    /// A bit, padding value, or product encoding is non-canonical.
    #[error("zk-X509 P-256 scalar-bit bus range is invalid")]
    Range,
    /// Transcript challenges are zero, non-canonical, or repeated.
    #[error("zk-X509 P-256 scalar-bit bus challenges are invalid")]
    Challenge,
    /// A pointwise arithmetic/window bit equality is false.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 scalar-bit pointwise equality is invalid")]
    Equality,
    /// A product boundary, intermediate state, or transition is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 scalar-bit product constraint is invalid")]
    Constraint,
    /// Arithmetic and window terminal products differ.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 scalar-bit terminal products differ")]
    Terminal,
    /// A base or auxiliary operation was attempted in the wrong phase.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 scalar-bit bus phase is invalid")]
    Phase,
    /// Length or allocation arithmetic exceeded a fixed bound.
    #[error("zk-X509 P-256 scalar-bit bus resource bound is exceeded")]
    Resource,
}
/// Sample product challenges after the arithmetic base commitment and all 128
/// window base commitments have been absorbed in verifier-fixed order.
///
/// The aggregate prover and verifier own commitment absorption. This function only performs the
/// post-commitment squeezes and gives every lane/coordinate an independent domain label.
pub fn derive_zk_x509_p256_scalar_bit_bus_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<P256ScalarBitBusChallengesV1, TransparentStarkErrorV1> {
    let labels: [[&[u8]; P256_SCALAR_BIT_BUS_TUPLE_TERMS_V1]; P256_SCALAR_BIT_BUS_LANES_V1] = [
        [
            b"zk-x509-p256-scalar-bit-bus-lane0-beta-v1",
            b"zk-x509-p256-scalar-bit-bus-lane0-scalar-v1",
            b"zk-x509-p256-scalar-bit-bus-lane0-window-v1",
            b"zk-x509-p256-scalar-bit-bus-lane0-bit-v1",
            b"zk-x509-p256-scalar-bit-bus-lane0-value-v1",
        ],
        [
            b"zk-x509-p256-scalar-bit-bus-lane1-beta-v1",
            b"zk-x509-p256-scalar-bit-bus-lane1-scalar-v1",
            b"zk-x509-p256-scalar-bit-bus-lane1-window-v1",
            b"zk-x509-p256-scalar-bit-bus-lane1-bit-v1",
            b"zk-x509-p256-scalar-bit-bus-lane1-value-v1",
        ],
        [
            b"zk-x509-p256-scalar-bit-bus-lane2-beta-v1",
            b"zk-x509-p256-scalar-bit-bus-lane2-scalar-v1",
            b"zk-x509-p256-scalar-bit-bus-lane2-window-v1",
            b"zk-x509-p256-scalar-bit-bus-lane2-bit-v1",
            b"zk-x509-p256-scalar-bit-bus-lane2-value-v1",
        ],
        [
            b"zk-x509-p256-scalar-bit-bus-lane3-beta-v1",
            b"zk-x509-p256-scalar-bit-bus-lane3-scalar-v1",
            b"zk-x509-p256-scalar-bit-bus-lane3-window-v1",
            b"zk-x509-p256-scalar-bit-bus-lane3-bit-v1",
            b"zk-x509-p256-scalar-bit-bus-lane3-value-v1",
        ],
    ];
    let mut lanes = [P256ScalarBitBusLaneChallengesV1 {
        terms: [F::ZERO; P256_SCALAR_BIT_BUS_TUPLE_TERMS_V1],
    }; P256_SCALAR_BIT_BUS_LANES_V1];
    for (lane, lane_labels) in lanes.iter_mut().zip(labels) {
        for (term, label) in lane.terms.iter_mut().zip(lane_labels) {
            *term = transcript.challenge_field(label)?;
        }
    }
    Ok(P256ScalarBitBusChallengesV1 { lanes })
}
/// Convert one big-endian window bit to its arithmetic `c` limb and little-endian bit position.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_scalar_window_bit_to_c_position_v1(
    window: usize,
    bit: usize,
) -> Result<(usize, usize), P256ScalarBitBusErrorV1> {
    if window >= P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1 || bit >= 4 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let global_be = window
        .checked_mul(4)
        .and_then(|position| position.checked_add(bit))
        .ok_or(P256ScalarBitBusErrorV1::Resource)?;
    let bit_le = P256_SCALAR_BITS_V1
        .checked_sub(global_be + 1)
        .ok_or(P256ScalarBitBusErrorV1::Resource)?;
    Ok((
        bit_le / P256_SCALAR_LIMB_BITS_V1,
        bit_le % P256_SCALAR_LIMB_BITS_V1,
    ))
}
/// Build all 512 fixed-position copies and the one canonical padding slot.
#[cfg(test)]
pub fn build_zk_x509_p256_scalar_bit_bus_trace_v1(
    sources: &[P256ScalarBitSourceV1],
    windows: &[P256WindowTraceV1],
    arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<P256ScalarBitBusTraceV1, P256ScalarBitBusErrorV1> {
    challenges.validate_v1()?;
    let expected = expected_accesses_v1(sources, windows, arithmetic_trace)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(P256_SCALAR_BIT_BUS_ROWS_V1)
        .map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
    let mut arithmetic_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
    let mut window_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
    for chunk in expected.chunks_exact(P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1) {
        let mut fixed =
            [P256ScalarBitBusFixedAccessV1::Inactive; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1];
        let mut arithmetic_bits = [F::ZERO; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1];
        let mut window_bits = [F::ZERO; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1];
        let mut arithmetic_products =
            [[F::ONE; P256_SCALAR_BIT_BUS_LANES_V1]; P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1];
        let mut window_products =
            [[F::ONE; P256_SCALAR_BIT_BUS_LANES_V1]; P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1];
        arithmetic_products[0] = arithmetic_running;
        window_products[0] = window_running;
        for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
            let access = chunk[slot];
            fixed[slot] = access.fixed;
            arithmetic_bits[slot] = access.arithmetic_bit;
            window_bits[slot] = access.window_bit;
            for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
                arithmetic_running[lane] = arithmetic_running[lane].mul(compress_access_v1(
                    access.fixed,
                    access.arithmetic_bit,
                    challenges.lanes[lane],
                ));
                window_running[lane] = window_running[lane].mul(compress_access_v1(
                    access.fixed,
                    access.window_bit,
                    challenges.lanes[lane],
                ));
            }
            arithmetic_products[slot + 1] = arithmetic_running;
            window_products[slot + 1] = window_running;
        }
        rows.push(P256ScalarBitBusRowV1 {
            fixed,
            arithmetic_bits,
            window_bits,
            arithmetic_products,
            window_products,
        });
    }
    if rows.len() != P256_SCALAR_BIT_BUS_ROWS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let trace = P256ScalarBitBusTraceV1 { rows };
    trace.validate_v1(sources, windows, arithmetic_trace, challenges)?;
    Ok(trace)
}
#[cfg(test)]
impl P256ScalarBitBusTraceV1 {
    /// Validate fixed positions, both source bindings, pointwise equality,
    /// canonical padding, every intermediate product, and terminal equality.
    pub(crate) fn validate_v1(
        &self,
        sources: &[P256ScalarBitSourceV1],
        windows: &[P256WindowTraceV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
        challenges: P256ScalarBitBusChallengesV1,
    ) -> Result<(), P256ScalarBitBusErrorV1> {
        challenges.validate_v1()?;
        let expected = expected_accesses_v1(sources, windows, arithmetic_trace)?;
        if self.rows.len() != P256_SCALAR_BIT_BUS_ROWS_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        let mut arithmetic_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        let mut window_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        for (row_index, row) in self.rows.iter().enumerate() {
            let first = row_index
                .checked_mul(P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1)
                .ok_or(P256ScalarBitBusErrorV1::Resource)?;
            let expected_chunk = expected
                .get(first..first + P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1)
                .ok_or(P256ScalarBitBusErrorV1::Topology)?;
            let expected_fixed = core::array::from_fn(|slot| expected_chunk[slot].fixed);
            if row.fixed != expected_fixed {
                return Err(P256ScalarBitBusErrorV1::Topology);
            }
            validate_row_range_v1(row)?;
            for (slot, access) in expected_chunk.iter().copied().enumerate() {
                if row.arithmetic_bits[slot] != access.arithmetic_bit {
                    return Err(P256ScalarBitBusErrorV1::ArithmeticSource);
                }
                if row.window_bits[slot] != access.window_bit {
                    return Err(P256ScalarBitBusErrorV1::WindowSource);
                }
                if row.arithmetic_bits[slot] != row.window_bits[slot] {
                    return Err(P256ScalarBitBusErrorV1::Equality);
                }
            }
            let constraints = evaluate_zk_x509_p256_scalar_bit_bus_row_constraints_v1(
                expected_fixed,
                row,
                core::array::from_fn(|slot| expected_chunk[slot].arithmetic_bit),
                core::array::from_fn(|slot| expected_chunk[slot].window_bit),
                arithmetic_running,
                window_running,
                challenges,
            );
            if constraints.iter().any(|constraint| *constraint != F::ZERO) {
                return Err(P256ScalarBitBusErrorV1::Constraint);
            }
            arithmetic_running = row.arithmetic_products[P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1];
            window_running = row.window_products[P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1];
        }
        let terminal = evaluate_zk_x509_p256_scalar_bit_bus_terminal_constraints_v1(self)?;
        if terminal.iter().any(|constraint| *constraint != F::ZERO) {
            return Err(P256ScalarBitBusErrorV1::Terminal);
        }
        Ok(())
    }
}
/// Low-degree constraints for one packed three-factor row.
///
/// `fixed` is verifier-regenerated. Every slot constrains both bits to be equal to the supplied
/// cells from the already-committed arithmetic and window traces, Boolean, and equal to each other.
/// It then advances each of both endpoint-product families in every lane by one independently
/// compressed factor.
#[cfg(test)]
pub fn evaluate_zk_x509_p256_scalar_bit_bus_row_constraints_v1(
    fixed: [P256ScalarBitBusFixedAccessV1; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
    row: &P256ScalarBitBusRowV1,
    arithmetic_sources: [F; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
    window_sources: [F; P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
    expected_arithmetic_before: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    expected_window_before: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Vec<F> {
    let mut constraints = Vec::with_capacity(
        2 * P256_SCALAR_BIT_BUS_LANES_V1
            + P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 * (7 + 2 * P256_SCALAR_BIT_BUS_LANES_V1),
    );
    for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
        constraints.push(row.arithmetic_products[0][lane].sub(expected_arithmetic_before[lane]));
        constraints.push(row.window_products[0][lane].sub(expected_window_before[lane]));
    }
    for (slot, fixed) in fixed.into_iter().enumerate() {
        let arithmetic_bit = row.arithmetic_bits[slot];
        let window_bit = row.window_bits[slot];
        constraints.push(arithmetic_bit.sub(arithmetic_sources[slot]));
        constraints.push(window_bit.sub(window_sources[slot]));
        constraints.push(arithmetic_bit.mul(arithmetic_bit.sub(F::ONE)));
        constraints.push(window_bit.mul(window_bit.sub(F::ONE)));
        constraints.push(arithmetic_bit.sub(window_bit));
        if fixed == P256ScalarBitBusFixedAccessV1::Inactive {
            constraints.push(arithmetic_bit);
            constraints.push(window_bit);
        }
        for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
            let arithmetic_factor =
                compress_access_v1(fixed, arithmetic_bit, challenges.lanes[lane]);
            let window_factor = compress_access_v1(fixed, window_bit, challenges.lanes[lane]);
            constraints.push(
                row.arithmetic_products[slot + 1][lane]
                    .sub(row.arithmetic_products[slot][lane].mul(arithmetic_factor)),
            );
            constraints.push(
                row.window_products[slot + 1][lane]
                    .sub(row.window_products[slot][lane].mul(window_factor)),
            );
        }
    }
    constraints
}
/// Four aggregate boundary constraints equating endpoint products.
#[cfg(test)]
pub fn evaluate_zk_x509_p256_scalar_bit_bus_terminal_constraints_v1(
    trace: &P256ScalarBitBusTraceV1,
) -> Result<[F; P256_SCALAR_BIT_BUS_LANES_V1], P256ScalarBitBusErrorV1> {
    if trace.rows.len() != P256_SCALAR_BIT_BUS_ROWS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let last = trace.rows.last().ok_or(P256ScalarBitBusErrorV1::Topology)?;
    let arithmetic = last.arithmetic_products[P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1];
    let window = last.window_products[P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1];
    Ok(core::array::from_fn(|lane| {
        arithmetic[lane].sub(window[lane])
    }))
}
/// Rectangular aggregate representation of the packed scalar-bit bus.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256ScalarBitBusStarkTraceV1 {
    /// Six committed arithmetic/window bit-copy columns.
    pub(crate) base: Vec<[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1]>,
    /// Thirty-two challenge-dependent product-state columns.
    pub(crate) aux: Vec<[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1]>,
}
#[cfg(test)]
impl P256ScalarBitBusStarkTraceV1 {
    fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.base);
        super::private_table::zeroize_field_rows_v1(&mut self.aux);
        self.base.clear();
        self.aux.clear();
    }
}
#[cfg(test)]
impl Drop for P256ScalarBitBusStarkTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
fn expected_stark_fixed_access_v1(
    factor: usize,
) -> Result<P256ScalarBitBusFixedAccessV1, P256ScalarBitBusErrorV1> {
    if factor >= P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    if factor == P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1 {
        return Ok(P256ScalarBitBusFixedAccessV1::Inactive);
    }
    let bits_per_scalar = P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1
        .checked_mul(4)
        .ok_or(P256ScalarBitBusErrorV1::Resource)?;
    if bits_per_scalar != P256_SCALAR_BITS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let scalar_index = factor / P256_SCALAR_BITS_V1;
    let within_scalar = factor % P256_SCALAR_BITS_V1;
    Ok(P256ScalarBitBusFixedAccessV1::Active {
        scalar: expected_scalar_v1(scalar_index)?,
        window: u8::try_from(within_scalar / 4).map_err(|_| P256ScalarBitBusErrorV1::Resource)?,
        bit: u8::try_from(within_scalar % 4).map_err(|_| P256ScalarBitBusErrorV1::Resource)?,
    })
}
/// Compile the exact verifier-owned numeric preprocessing schedule.
#[cfg(test)]
pub fn compile_p256_scalar_bit_bus_stark_fixed_rows_v1()
-> Result<Vec<[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1]>, P256ScalarBitBusErrorV1> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)
        .map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
    for row_index in 0..P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 {
        rows.push(p256_scalar_bit_bus_stark_fixed_row_v1(
            row_index,
            P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1,
        )?);
    }
    Ok(rows)
}
/// Regenerate one verifier-owned scalar-bit bus fixed row on any shared
/// power-of-two domain containing the exact 171 logical rows.
///
/// This is the production constant-memory provider used by the native scalar-bit aggregate group.
pub fn p256_scalar_bit_bus_stark_fixed_row_v1(
    row_index: usize,
    trace_size: usize,
) -> Result<[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1], P256ScalarBitBusErrorV1> {
    if trace_size < P256_SCALAR_BIT_BUS_ROWS_V1
        || !trace_size.is_power_of_two()
        || row_index >= trace_size
    {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let mut fixed = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1];
    if row_index < P256_SCALAR_BIT_BUS_ROWS_V1 {
        for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
            let factor = row_index
                .checked_mul(P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1)
                .and_then(|first| first.checked_add(slot))
                .ok_or(P256ScalarBitBusErrorV1::Resource)?;
            if let P256ScalarBitBusFixedAccessV1::Active {
                scalar,
                window,
                bit,
            } = expected_stark_fixed_access_v1(factor)?
            {
                let start = slot * STARK_FIXED_SLOT_WIDTH;
                fixed[start + STARK_FIXED_SLOT_ACTIVE] = F::ONE;
                fixed[start + STARK_FIXED_SLOT_SCALAR] = F(match scalar {
                    P256WindowScalarV1::U1 => 1,
                    P256WindowScalarV1::U2 => 2,
                });
                fixed[start + STARK_FIXED_SLOT_WINDOW] = F(u64::from(window) + 1);
                fixed[start + STARK_FIXED_SLOT_BIT] = F(u64::from(bit) + 1);
            }
        }
        fixed[STARK_FIXED_FIRST_ROW] = F(u64::from(row_index == 0));
        fixed[STARK_FIXED_LAST_ACTIVE_ROW] =
            F(u64::from(row_index + 1 == P256_SCALAR_BIT_BUS_ROWS_V1));
        fixed[STARK_FIXED_ACTIVE_CONTINUE] =
            F(u64::from(row_index + 1 < P256_SCALAR_BIT_BUS_ROWS_V1));
    } else {
        fixed[STARK_FIXED_PADDING] = F::ONE;
    }
    Ok(fixed)
}
/// Project the verifier-preprocessed selector for the final active packed-bus
/// row at an arbitrary aggregate-domain opening.
#[cfg(test)]
pub const fn p256_scalar_bit_bus_stark_last_active_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
) -> A {
    fixed[STARK_FIXED_LAST_ACTIVE_ROW]
}
/// Convert the typed bus rows to the sole padded aggregate layout.
#[cfg(test)]
pub fn build_p256_scalar_bit_bus_stark_trace_v1(
    trace: &P256ScalarBitBusTraceV1,
) -> Result<P256ScalarBitBusStarkTraceV1, P256ScalarBitBusErrorV1> {
    if trace.rows.len() != P256_SCALAR_BIT_BUS_ROWS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let mut base = Vec::new();
    let mut aux = Vec::new();
    base.try_reserve_exact(P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)
        .map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
    aux.try_reserve_exact(P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)
        .map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
    for (row_index, row) in trace.rows.iter().enumerate() {
        for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
            let factor = row_index
                .checked_mul(P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1)
                .and_then(|first| first.checked_add(slot))
                .ok_or(P256ScalarBitBusErrorV1::Resource)?;
            if row.fixed[slot] != expected_stark_fixed_access_v1(factor)? {
                return Err(P256ScalarBitBusErrorV1::Topology);
            }
        }
        let mut base_row = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1];
        base_row
            [STARK_ARITHMETIC_BITS..STARK_ARITHMETIC_BITS + P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1]
            .copy_from_slice(&row.arithmetic_bits);
        base_row[STARK_WINDOW_BITS..STARK_WINDOW_BITS + P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1]
            .copy_from_slice(&row.window_bits);
        let mut aux_row = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1];
        for state in 0..P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 {
            for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
                aux_row[STARK_ARITHMETIC_PRODUCTS + state * P256_SCALAR_BIT_BUS_LANES_V1 + lane] =
                    row.arithmetic_products[state][lane];
                aux_row[STARK_WINDOW_PRODUCTS + state * P256_SCALAR_BIT_BUS_LANES_V1 + lane] =
                    row.window_products[state][lane];
            }
        }
        base.push(base_row);
        aux.push(aux_row);
    }
    base.resize(
        P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1,
        [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    );
    aux.resize(
        P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1,
        [F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    );
    Ok(P256ScalarBitBusStarkTraceV1 { base, aux })
}
/// Challenge-independent committed material for the scalar-bit copy bus.
///
/// Construction validates the arithmetic and window sources before retaining
/// only the six committed base columns. Challenge-dependent products are not
/// present in this type and cannot be obtained from it.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ScalarBitBusBaseMaterialV1 {
    rows: Vec<[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ScalarBitBusBaseMaterialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ScalarBitBusBaseMaterialV1")
            .field("private_rows", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ScalarBitBusBaseMaterialV1 {
    /// Validate both committed sources and build the canonical padded base
    /// domain without accepting any auxiliary challenge.
    pub(crate) fn new_v1(
        windows: &[P256WindowTraceV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        Self::from_sources_v1(
            &[
                P256ScalarBitSourceV1 {
                    scalar: P256WindowScalarV1::U1,
                    c_operation: P256_SCALAR_BIT_BUS_U1_C_OPERATION_V1,
                },
                P256ScalarBitSourceV1 {
                    scalar: P256WindowScalarV1::U2,
                    c_operation: P256_SCALAR_BIT_BUS_U2_C_OPERATION_V1,
                },
            ],
            windows,
            arithmetic_trace,
        )
    }
    fn from_sources_v1(
        sources: &[P256ScalarBitSourceV1],
        windows: &[P256WindowTraceV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        let expected = expected_accesses_v1(sources, windows, arithmetic_trace)?;
        if expected.len() != P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        let mut material = Self { rows: Vec::new() };
        material
            .rows
            .try_reserve_exact(P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)
            .map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
        for row_index in 0..P256_SCALAR_BIT_BUS_ROWS_V1 {
            let mut row = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1];
            for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
                let factor = row_index
                    .checked_mul(P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1)
                    .and_then(|first| first.checked_add(slot))
                    .ok_or(P256ScalarBitBusErrorV1::Resource)?;
                let access = expected
                    .get(factor)
                    .copied()
                    .ok_or(P256ScalarBitBusErrorV1::Topology)?;
                if access.fixed != expected_stark_fixed_access_v1(factor)? {
                    return Err(P256ScalarBitBusErrorV1::Topology);
                }
                if access.arithmetic_bit != access.window_bit {
                    return Err(P256ScalarBitBusErrorV1::Equality);
                }
                row[STARK_ARITHMETIC_BITS + slot] = access.arithmetic_bit;
                row[STARK_WINDOW_BITS + slot] = access.window_bit;
            }
            material.rows.push(row);
        }
        material.rows.resize(
            P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1,
            [F::ZERO; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
        );
        material.validate_integrity_v1()?;
        Ok(material)
    }
    #[cfg(test)]
    fn from_sources_for_test_v1(
        sources: &[P256ScalarBitSourceV1],
        windows: &[P256WindowTraceV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        Self::from_sources_v1(sources, windows, arithmetic_trace)
    }
    fn validate_integrity_v1(&self) -> Result<(), P256ScalarBitBusErrorV1> {
        if self.rows.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        for (row_index, row) in self.rows.iter().enumerate() {
            validate_scalar_bit_bus_base_row_v1(row_index, row)?;
        }
        Ok(())
    }
    fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1], P256ScalarBitBusErrorV1> {
        let value = self
            .rows
            .get(row)
            .copied()
            .ok_or(P256ScalarBitBusErrorV1::Topology)?;
        validate_scalar_bit_bus_base_row_v1(row, &value)?;
        Ok(value)
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.rows);
        self.rows.clear();
    }
    #[cfg(test)]
    fn row_mut_for_test_v1(
        &mut self,
        row: usize,
    ) -> Result<&mut [F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1], P256ScalarBitBusErrorV1> {
        self.rows
            .get_mut(row)
            .ok_or(P256ScalarBitBusErrorV1::Topology)
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.rows.is_empty()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ScalarBitBusBaseMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_scalar_bit_bus_base_row_v1(
    row_index: usize,
    row: &[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
) -> Result<(), P256ScalarBitBusErrorV1> {
    if row_index >= P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    if row.iter().any(|value| F::canonical(value.0).is_none()) {
        return Err(P256ScalarBitBusErrorV1::Range);
    }
    if row_index >= P256_SCALAR_BIT_BUS_ROWS_V1 {
        return if row.iter().all(|value| *value == F::ZERO) {
            Ok(())
        } else {
            Err(P256ScalarBitBusErrorV1::Range)
        };
    }
    let fixed =
        p256_scalar_bit_bus_stark_fixed_row_v1(row_index, P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)?;
    for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
        let arithmetic = row[STARK_ARITHMETIC_BITS + slot];
        let window = row[STARK_WINDOW_BITS + slot];
        if ![F::ZERO, F::ONE].contains(&arithmetic) || ![F::ZERO, F::ONE].contains(&window) {
            return Err(P256ScalarBitBusErrorV1::Range);
        }
        let active = fixed[slot * STARK_FIXED_SLOT_WIDTH + STARK_FIXED_SLOT_ACTIVE];
        if active == F::ZERO {
            if arithmetic != F::ZERO || window != F::ZERO {
                return Err(P256ScalarBitBusErrorV1::Range);
            }
        } else if active != F::ONE {
            return Err(P256ScalarBitBusErrorV1::Topology);
        } else if arithmetic != window {
            return Err(P256ScalarBitBusErrorV1::Equality);
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256ScalarBitBusColumnFillGuardV1<'a> {
    output: &'a mut [F],
    committed: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ScalarBitBusColumnFillGuardV1<'a> {
    fn new_v1(output: &'a mut [F]) -> Self {
        Self {
            output,
            committed: false,
        }
    }
    fn output_v1(&mut self) -> &mut [F] {
        self.output
    }
    fn commit_v1(mut self) {
        self.committed = true;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ScalarBitBusColumnFillGuardV1<'_> {
    fn drop(&mut self) {
        if !self.committed {
            super::private_table::zeroize_fields_v1(&mut self.output[..]);
        }
    }
}
/// Challenge-independent committed base-row replay.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug)]
pub struct P256ScalarBitBusStarkBaseRowProviderV1<'a> {
    material: &'a P256ScalarBitBusBaseMaterialV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ScalarBitBusStarkBaseRowProviderV1<'a> {
    fn new_v1(
        material: &'a P256ScalarBitBusBaseMaterialV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        if material.rows.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        Ok(Self { material })
    }
    /// One exact committed base row.
    pub(crate) fn base_row_v1(
        self,
        row: usize,
    ) -> Result<[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1], P256ScalarBitBusErrorV1> {
        self.material.base_row_v1(row)
    }
    /// One exact committed base cell.
    #[cfg(test)]
    pub(crate) fn base_cell_v1(
        self,
        row: usize,
        column: usize,
    ) -> Result<F, P256ScalarBitBusErrorV1> {
        if column >= P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        Ok(self.base_row_v1(row)?[column])
    }
    /// Replay one full committed base column transactionally.
    #[cfg(test)]
    pub(crate) fn fill_base_column_v1(
        self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256ScalarBitBusErrorV1> {
        if column >= P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1
            || output.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
        {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        let mut guard = P256ScalarBitBusColumnFillGuardV1::new_v1(output);
        for (row, value) in guard.output_v1().iter_mut().enumerate() {
            *value = self.base_cell_v1(row, column)?;
        }
        guard.commit_v1();
        Ok(())
    }
}
/// Verifier-owned fixed-row replay for the sole scalar-bit bus identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ScalarBitBusStarkFixedProviderV1 {
    trace_size: usize,
}
impl P256ScalarBitBusStarkFixedProviderV1 {
    /// Select the canonical native domain. No witness topology is accepted.
    pub(crate) fn new_v1(trace_size: usize) -> Result<Self, P256ScalarBitBusErrorV1> {
        if trace_size != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        Ok(Self { trace_size })
    }
    /// One verifier-regenerated fixed row.
    pub(crate) fn fixed_row_v1(
        self,
        row: usize,
    ) -> Result<[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1], P256ScalarBitBusErrorV1> {
        p256_scalar_bit_bus_stark_fixed_row_v1(row, self.trace_size)
    }
    /// One verifier-regenerated fixed cell.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn fixed_cell_v1(
        self,
        row: usize,
        column: usize,
    ) -> Result<F, P256ScalarBitBusErrorV1> {
        if column >= P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1 {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        Ok(self.fixed_row_v1(row)?[column])
    }
    /// Replay one full verifier-owned fixed column transactionally.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn fill_fixed_column_v1(
        self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256ScalarBitBusErrorV1> {
        if column >= P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1 || output.len() != self.trace_size {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        let mut guard = P256ScalarBitBusColumnFillGuardV1::new_v1(output);
        for (row, value) in guard.output_v1().iter_mut().enumerate() {
            *value = self.fixed_cell_v1(row, column)?;
        }
        guard.commit_v1();
        Ok(())
    }
}
/// Pre-X5B1 scalar-bit bus capability.
///
/// Binding is poison-on-attempt: the sole transition is consumed before any
/// fallible validation or product computation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ScalarBitBusBaseSourceV1 {
    material: Option<P256ScalarBitBusBaseMaterialV1>,
    bind_attempted: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ScalarBitBusBaseSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ScalarBitBusBaseSourceV1")
            .field("bind_attempted", &self.bind_attempted)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ScalarBitBusBaseSourceV1 {
    /// Allocated committed scalar rows, including unused capacity.
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        self.material.as_ref().map_or(0, |material| {
            super::allocation_payload::vector_v1(&material.rows)
        })
    }
    /// Validate source bindings and enter the challenge-independent phase.
    pub(crate) fn new_v1(
        windows: &[P256WindowTraceV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        Self::from_base_material_v1(P256ScalarBitBusBaseMaterialV1::new_v1(
            windows,
            arithmetic_trace,
        )?)
    }
    #[cfg(test)]
    fn from_sources_for_test_v1(
        sources: &[P256ScalarBitSourceV1],
        windows: &[P256WindowTraceV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        Self::from_base_material_v1(P256ScalarBitBusBaseMaterialV1::from_sources_for_test_v1(
            sources,
            windows,
            arithmetic_trace,
        )?)
    }
    /// Enter the base phase from already validated, challenge-independent material.
    pub(crate) fn from_base_material_v1(
        material: P256ScalarBitBusBaseMaterialV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        material.validate_integrity_v1()?;
        Ok(Self {
            material: Some(material),
            bind_attempted: false,
        })
    }
    fn ensure_base_phase_v1(&self) -> Result<(), P256ScalarBitBusErrorV1> {
        if self.bind_attempted || self.material.is_none() {
            Err(P256ScalarBitBusErrorV1::Phase)
        } else {
            Ok(())
        }
    }
    fn material_v1(&self) -> Result<&P256ScalarBitBusBaseMaterialV1, P256ScalarBitBusErrorV1> {
        self.ensure_base_phase_v1()?;
        self.material.as_ref().ok_or(P256ScalarBitBusErrorV1::Phase)
    }
    /// Committed base-row replay before X5B1.
    pub(crate) fn base_rows_v1(
        &self,
    ) -> Result<P256ScalarBitBusStarkBaseRowProviderV1<'_>, P256ScalarBitBusErrorV1> {
        P256ScalarBitBusStarkBaseRowProviderV1::new_v1(self.material_v1()?)
    }
    /// Verifier-owned fixed-row replay before X5B1.
    #[cfg(test)]
    pub(crate) fn fixed_rows_v1(
        &self,
    ) -> Result<P256ScalarBitBusStarkFixedProviderV1, P256ScalarBitBusErrorV1> {
        self.ensure_base_phase_v1()?;
        P256ScalarBitBusStarkFixedProviderV1::new_v1(P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)
    }
    /// Consume the sole phase transition using the opaque MAIN X5B1 token.
    pub(crate) fn bind_v1(
        &mut self,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<P256ScalarBitBusBoundSourceV1, P256ScalarBitBusErrorV1> {
        self.ensure_base_phase_v1()?;
        self.bind_attempted = true;
        let material = self
            .material
            .as_ref()
            .ok_or(P256ScalarBitBusErrorV1::Phase)?;
        material.validate_integrity_v1()?;
        let challenges = post_base.p256_scalar();
        challenges.validate_v1()?;
        let terminals = compute_scalar_bit_bus_terminals_v1(material, challenges)?;
        if terminals[0] != terminals[1] {
            return Err(P256ScalarBitBusErrorV1::Terminal);
        }
        Ok(P256ScalarBitBusBoundSourceV1 {
            material: self.material.take(),
            post_base: Some(post_base),
            terminals,
        })
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        if let Some(material) = self.material.as_mut() {
            material.zeroize_private_v1();
        }
        self.material = None;
        self.bind_attempted = true;
    }
    #[cfg(test)]
    fn material_mut_for_test_v1(
        &mut self,
    ) -> Result<&mut P256ScalarBitBusBaseMaterialV1, P256ScalarBitBusErrorV1> {
        self.ensure_base_phase_v1()?;
        self.material.as_mut().ok_or(P256ScalarBitBusErrorV1::Phase)
    }
    #[cfg(test)]
    const fn bind_attempted_for_test_v1(&self) -> bool {
        self.bind_attempted
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.material.is_none()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ScalarBitBusBaseSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Post-X5B1 scalar-bit bus capability.
///
/// Only this type can mint challenge-dependent product replay and expose the two terminal families.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ScalarBitBusBoundSourceV1 {
    material: Option<P256ScalarBitBusBaseMaterialV1>,
    post_base: Option<ZkX509CredentialMainPostBaseChallengesV1>,
    terminals: [[F; P256_SCALAR_BIT_BUS_LANES_V1]; 2],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ScalarBitBusBoundSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ScalarBitBusBoundSourceV1")
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ScalarBitBusBoundSourceV1 {
    /// Allocated committed scalar rows, including unused capacity.
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        self.material.as_ref().map_or(0, |material| {
            super::allocation_payload::vector_v1(&material.rows)
        })
    }
    fn material_v1(&self) -> Result<&P256ScalarBitBusBaseMaterialV1, P256ScalarBitBusErrorV1> {
        self.material.as_ref().ok_or(P256ScalarBitBusErrorV1::Phase)
    }
    /// Opaque post-base capability retained for sibling P-256 providers.
    pub(crate) fn post_base_v1(
        &self,
    ) -> Result<ZkX509CredentialMainPostBaseChallengesV1, P256ScalarBitBusErrorV1> {
        self.post_base.ok_or(P256ScalarBitBusErrorV1::Phase)
    }
    /// Committed base-row replay retained across the phase transition.
    pub(crate) fn base_rows_v1(
        &self,
    ) -> Result<P256ScalarBitBusStarkBaseRowProviderV1<'_>, P256ScalarBitBusErrorV1> {
        P256ScalarBitBusStarkBaseRowProviderV1::new_v1(self.material_v1()?)
    }
    /// Mint deterministic auxiliary replay under the bound X5B1 challenges.
    pub(crate) fn aux_source_v1(
        &self,
    ) -> Result<P256ScalarBitBusStarkAuxSourceV1<'_>, P256ScalarBitBusErrorV1> {
        let source = P256ScalarBitBusStarkAuxSourceV1::new_v1(
            self.material_v1()?,
            self.post_base_v1()?.p256_scalar(),
        )?;
        if source.terminals_v1() != self.terminals {
            return Err(P256ScalarBitBusErrorV1::Terminal);
        }
        Ok(source)
    }
    /// Arithmetic and window product terminals under X5B1.
    pub(crate) const fn terminals_v1(&self) -> [[F; P256_SCALAR_BIT_BUS_LANES_V1]; 2] {
        self.terminals
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.post_base = None;
        for terminal in &mut self.terminals {
            super::private_table::zeroize_fields_v1(&mut terminal[..]);
        }
        if let Some(material) = self.material.as_mut() {
            material.zeroize_private_v1();
        }
        self.material = None;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.post_base.is_none()
            && self.material.is_none()
            && self
                .terminals
                .iter()
                .flatten()
                .all(|value| *value == F::ZERO)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ScalarBitBusBoundSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Challenge-bound constant-memory auxiliary replay.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ScalarBitBusStarkAuxSourceV1<'a> {
    material: &'a P256ScalarBitBusBaseMaterialV1,
    challenges: P256ScalarBitBusChallengesV1,
    terminals: [[F; P256_SCALAR_BIT_BUS_LANES_V1]; 2],
    arithmetic_running: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    window_running: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    next_row: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ScalarBitBusStarkAuxSourceV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ScalarBitBusStarkAuxSourceV1")
            .field("next_row", &self.next_row)
            .field("private_state", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ScalarBitBusStarkAuxSourceV1<'a> {
    fn new_v1(
        material: &'a P256ScalarBitBusBaseMaterialV1,
        challenges: P256ScalarBitBusChallengesV1,
    ) -> Result<Self, P256ScalarBitBusErrorV1> {
        challenges.validate_v1()?;
        material.validate_integrity_v1()?;
        let terminals = compute_scalar_bit_bus_terminals_v1(material, challenges)?;
        if terminals[0] != terminals[1] {
            return Err(P256ScalarBitBusErrorV1::Terminal);
        }
        Ok(Self {
            material,
            challenges,
            terminals,
            arithmetic_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            window_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            next_row: 0,
        })
    }
    /// Emit the next exact challenge-dependent row, including canonical zero
    /// domain padding after the final logical row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1]>, P256ScalarBitBusErrorV1> {
        if self.next_row == P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 {
            return Ok(None);
        }
        if self.next_row >= P256_SCALAR_BIT_BUS_ROWS_V1 {
            self.next_row += 1;
            return Ok(Some([F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1]));
        }
        let mut arithmetic_running = self.arithmetic_running;
        let mut window_running = self.window_running;
        let row = scalar_bit_bus_aux_row_v1(
            self.material,
            self.next_row,
            self.challenges,
            &mut arithmetic_running,
            &mut window_running,
        )?;
        self.arithmetic_running = arithmetic_running;
        self.window_running = window_running;
        self.next_row += 1;
        if self.next_row == P256_SCALAR_BIT_BUS_ROWS_V1
            && [self.arithmetic_running, self.window_running] != self.terminals
        {
            return Err(P256ScalarBitBusErrorV1::Constraint);
        }
        Ok(Some(row))
    }
    /// Restart deterministic auxiliary replay.
    #[cfg(test)]
    pub(crate) fn replay_v1(&self) -> Self {
        Self {
            material: self.material,
            challenges: self.challenges,
            terminals: self.terminals,
            arithmetic_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            window_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            next_row: 0,
        }
    }
    /// Replay one complete auxiliary column transactionally.
    #[cfg(test)]
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256ScalarBitBusErrorV1> {
        if column >= P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1
            || output.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
        {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
        let mut replay = self.replay_v1();
        let mut guard = P256ScalarBitBusColumnFillGuardV1::new_v1(output);
        for value in guard.output_v1() {
            let row = replay
                .next_aux_row_v1()?
                .ok_or(P256ScalarBitBusErrorV1::Topology)?;
            *value = row[column];
        }
        guard.commit_v1();
        Ok(())
    }
    /// Bound arithmetic and window product terminals.
    pub(crate) const fn terminals_v1(&self) -> [[F; P256_SCALAR_BIT_BUS_LANES_V1]; 2] {
        self.terminals
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        for lane in &mut self.challenges.lanes {
            super::private_table::zeroize_fields_v1(&mut lane.terms[..]);
        }
        for terminal in &mut self.terminals {
            super::private_table::zeroize_fields_v1(&mut terminal[..]);
        }
        super::private_table::zeroize_fields_v1(&mut self.arithmetic_running[..]);
        super::private_table::zeroize_fields_v1(&mut self.window_running[..]);
        self.next_row = P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.challenges
            .lanes
            .iter()
            .flat_map(|lane| lane.terms)
            .chain(self.terminals.iter().flatten().copied())
            .chain(self.arithmetic_running)
            .chain(self.window_running)
            .all(|value| value == F::ZERO)
            && self.next_row == P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ScalarBitBusStarkAuxSourceV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn scalar_bit_bus_aux_row_v1(
    material: &P256ScalarBitBusBaseMaterialV1,
    row_index: usize,
    challenges: P256ScalarBitBusChallengesV1,
    arithmetic_running: &mut [F; P256_SCALAR_BIT_BUS_LANES_V1],
    window_running: &mut [F; P256_SCALAR_BIT_BUS_LANES_V1],
) -> Result<[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1], P256ScalarBitBusErrorV1> {
    if row_index >= P256_SCALAR_BIT_BUS_ROWS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let base = material.base_row_v1(row_index)?;
    let fixed =
        p256_scalar_bit_bus_stark_fixed_row_v1(row_index, P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1)?;
    let mut aux = [F::ZERO; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1];
    aux[STARK_ARITHMETIC_PRODUCTS..STARK_ARITHMETIC_PRODUCTS + P256_SCALAR_BIT_BUS_LANES_V1]
        .copy_from_slice(arithmetic_running);
    aux[STARK_WINDOW_PRODUCTS..STARK_WINDOW_PRODUCTS + P256_SCALAR_BIT_BUS_LANES_V1]
        .copy_from_slice(window_running);
    for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
        let fixed_start = slot * STARK_FIXED_SLOT_WIDTH;
        let fixed_slot = &fixed[fixed_start..fixed_start + STARK_FIXED_SLOT_WIDTH];
        for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
            let arithmetic_before = arithmetic_running[lane];
            let window_before = window_running[lane];
            arithmetic_running[lane] = arithmetic_before.mul(stark_scalar_bit_factor_v1(
                fixed_slot,
                base[STARK_ARITHMETIC_BITS + slot],
                challenges.lanes[lane],
            )?);
            window_running[lane] = window_before.mul(stark_scalar_bit_factor_v1(
                fixed_slot,
                base[STARK_WINDOW_BITS + slot],
                challenges.lanes[lane],
            )?);
        }
        let state = slot + 1;
        let arithmetic_offset = STARK_ARITHMETIC_PRODUCTS + state * P256_SCALAR_BIT_BUS_LANES_V1;
        let window_offset = STARK_WINDOW_PRODUCTS + state * P256_SCALAR_BIT_BUS_LANES_V1;
        aux[arithmetic_offset..arithmetic_offset + P256_SCALAR_BIT_BUS_LANES_V1]
            .copy_from_slice(arithmetic_running);
        aux[window_offset..window_offset + P256_SCALAR_BIT_BUS_LANES_V1]
            .copy_from_slice(window_running);
    }
    Ok(aux)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compute_scalar_bit_bus_terminals_v1(
    material: &P256ScalarBitBusBaseMaterialV1,
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<[[F; P256_SCALAR_BIT_BUS_LANES_V1]; 2], P256ScalarBitBusErrorV1> {
    challenges.validate_v1()?;
    material.validate_integrity_v1()?;
    let mut arithmetic = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
    let mut window = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
    for row in 0..P256_SCALAR_BIT_BUS_ROWS_V1 {
        scalar_bit_bus_aux_row_v1(material, row, challenges, &mut arithmetic, &mut window)?;
    }
    Ok([arithmetic, window])
}
fn stark_scalar_bit_factor_v1<A: PolynomialAirFieldV1>(
    fixed_slot: &[A],
    value: A,
    challenge: P256ScalarBitBusLaneChallengesV1,
) -> Result<A, P256ScalarBitBusErrorV1> {
    let fixed_slot: &[A; STARK_FIXED_SLOT_WIDTH] = fixed_slot
        .try_into()
        .map_err(|_| P256ScalarBitBusErrorV1::Topology)?;
    let active = fixed_slot[STARK_FIXED_SLOT_ACTIVE];
    let terms = challenge.terms.map(A::from_base);
    let compressed = terms[0]
        .add(terms[1].mul(fixed_slot[STARK_FIXED_SLOT_SCALAR]))
        .add(terms[2].mul(fixed_slot[STARK_FIXED_SLOT_WINDOW]))
        .add(terms[3].mul(fixed_slot[STARK_FIXED_SLOT_BIT]))
        .add(terms[4].mul(value));
    Ok(A::ONE.add(active.mul(compressed.sub(A::ONE))))
}
/// Canonical auxiliary terminal columns, in arithmetic then window order.
pub fn p256_scalar_bit_bus_terminal_columns_v1() -> [[usize; P256_SCALAR_BIT_BUS_LANES_V1]; 2] {
    let final_state = (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1) * P256_SCALAR_BIT_BUS_LANES_V1;
    [
        core::array::from_fn(|lane| STARK_ARITHMETIC_PRODUCTS + final_state + lane),
        core::array::from_fn(|lane| STARK_WINDOW_PRODUCTS + final_state + lane),
    ]
}
/// Arithmetic and window product terminals in one opened packed-bus auxiliary row.
///
/// The aggregate verifier opens this projection at the verifier-fixed final logical row; no
/// proof-supplied row index is accepted by the terminal registration.
#[cfg(test)]
pub fn p256_scalar_bit_bus_opened_terminals_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
) -> [[A; P256_SCALAR_BIT_BUS_LANES_V1]; 2] {
    let final_state = (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1) * P256_SCALAR_BIT_BUS_LANES_V1;
    [
        core::array::from_fn(|lane| aux[STARK_ARITHMETIC_PRODUCTS + final_state + lane]),
        core::array::from_fn(|lane| aux[STARK_WINDOW_PRODUCTS + final_state + lane]),
    ]
}
/// Evaluate the packed scalar-bit bus on the aggregate extension domain.
///
/// The terminal equality here binds the two bus copies. Source-side products over the arithmetic
/// and window commitments remain a separate required adapter and activation gate.
#[cfg(test)]
pub fn evaluate_p256_scalar_bit_bus_stark_residues_v1(
    current: &[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    next: &[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<F>, P256ScalarBitBusErrorV1> {
    evaluate_p256_scalar_bit_bus_stark_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
}
/// The same scalar-bit copy relation over F or Fp4, including verifier-fixed selectors.
pub fn evaluate_p256_scalar_bit_bus_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    next: &[A; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<A>, P256ScalarBitBusErrorV1> {
    challenges.validate_v1()?;
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(P256ScalarBitBusErrorV1::Range);
    }
    let mut residues = Vec::with_capacity(P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1);
    for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
        let arithmetic_bit = current[STARK_ARITHMETIC_BITS + slot];
        let window_bit = current[STARK_WINDOW_BITS + slot];
        let fixed_start = slot * STARK_FIXED_SLOT_WIDTH;
        let fixed_slot = &fixed[fixed_start..fixed_start + STARK_FIXED_SLOT_WIDTH];
        let inactive = A::ONE.sub(fixed_slot[STARK_FIXED_SLOT_ACTIVE]);
        residues.push(arithmetic_bit.mul(arithmetic_bit.sub(A::ONE)));
        residues.push(window_bit.mul(window_bit.sub(A::ONE)));
        residues.push(arithmetic_bit.sub(window_bit));
        residues.push(inactive.mul(arithmetic_bit));
        residues.push(inactive.mul(window_bit));
        for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
            let arithmetic_before =
                STARK_ARITHMETIC_PRODUCTS + slot * P256_SCALAR_BIT_BUS_LANES_V1 + lane;
            let arithmetic_after = arithmetic_before + P256_SCALAR_BIT_BUS_LANES_V1;
            let window_before = STARK_WINDOW_PRODUCTS + slot * P256_SCALAR_BIT_BUS_LANES_V1 + lane;
            let window_after = window_before + P256_SCALAR_BIT_BUS_LANES_V1;
            let arithmetic_factor =
                stark_scalar_bit_factor_v1(fixed_slot, arithmetic_bit, challenges.lanes[lane])?;
            let window_factor =
                stark_scalar_bit_factor_v1(fixed_slot, window_bit, challenges.lanes[lane])?;
            residues.push(
                current_aux[arithmetic_after]
                    .sub(current_aux[arithmetic_before].mul(arithmetic_factor)),
            );
            residues
                .push(current_aux[window_after].sub(current_aux[window_before].mul(window_factor)));
        }
    }
    for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
        residues.push(
            fixed[STARK_FIXED_FIRST_ROW]
                .mul(current_aux[STARK_ARITHMETIC_PRODUCTS + lane].sub(A::ONE)),
        );
        residues.push(
            fixed[STARK_FIXED_FIRST_ROW].mul(current_aux[STARK_WINDOW_PRODUCTS + lane].sub(A::ONE)),
        );
        residues.push(fixed[STARK_FIXED_ACTIVE_CONTINUE].mul(
            next_aux[STARK_ARITHMETIC_PRODUCTS + lane].sub(
                current_aux[STARK_ARITHMETIC_PRODUCTS
                    + (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1) * P256_SCALAR_BIT_BUS_LANES_V1
                    + lane],
            ),
        ));
        residues.push(fixed[STARK_FIXED_ACTIVE_CONTINUE].mul(
            next_aux[STARK_WINDOW_PRODUCTS + lane].sub(
                current_aux[STARK_WINDOW_PRODUCTS
                    + (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1) * P256_SCALAR_BIT_BUS_LANES_V1
                    + lane],
            ),
        ));
        residues.push(
            fixed[STARK_FIXED_LAST_ACTIVE_ROW].mul(
                current_aux[STARK_ARITHMETIC_PRODUCTS
                    + (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1) * P256_SCALAR_BIT_BUS_LANES_V1
                    + lane]
                    .sub(
                        current_aux[STARK_WINDOW_PRODUCTS
                            + (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1)
                                * P256_SCALAR_BIT_BUS_LANES_V1
                            + lane],
                    ),
            ),
        );
        residues
            .push(fixed[STARK_FIXED_PADDING].mul(current_aux[STARK_ARITHMETIC_PRODUCTS + lane]));
        residues.push(fixed[STARK_FIXED_PADDING].mul(current_aux[STARK_WINDOW_PRODUCTS + lane]));
    }
    if residues.len() != P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    Ok(residues)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedAccessV1 {
    fixed: P256ScalarBitBusFixedAccessV1,
    arithmetic_bit: F,
    window_bit: F,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ExpectedAccessV1 {
    const fn inactive() -> Self {
        Self {
            fixed: P256ScalarBitBusFixedAccessV1::Inactive,
            arithmetic_bit: F::ZERO,
            window_bit: F::ZERO,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn expected_accesses_v1(
    sources: &[P256ScalarBitSourceV1],
    windows: &[P256WindowTraceV1],
    arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
) -> Result<Vec<ExpectedAccessV1>, P256ScalarBitBusErrorV1> {
    validate_sources_v1(sources, arithmetic_trace)?;
    if windows.len() != P256_SCALAR_BIT_BUS_SCALARS_V1 * P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    let mut c_bits = [[[F::ZERO; P256_SCALAR_LIMB_BITS_V1]; P256_SCALAR_LIMBS_V1];
        P256_SCALAR_BIT_BUS_SCALARS_V1];
    for (scalar_index, source) in sources.iter().copied().enumerate() {
        let operation =
            usize::try_from(source.c_operation).map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
        for (limb, target) in c_bits[scalar_index].iter_mut().enumerate() {
            *target = p256_arithmetic_c_limb_bits_v1(arithmetic_trace, operation, limb)
                .map_err(map_arithmetic_error_v1)?;
        }
    }
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1)
        .map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
    for (scalar_index, scalar_c_bits) in c_bits.iter().enumerate() {
        let scalar = expected_scalar_v1(scalar_index)?;
        for window in 0..P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1 {
            let window_index = scalar_index
                .checked_mul(P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1)
                .and_then(|index| index.checked_add(window))
                .ok_or(P256ScalarBitBusErrorV1::Resource)?;
            let trace = windows
                .get(window_index)
                .ok_or(P256ScalarBitBusErrorV1::Topology)?;
            trace
                .validate_for_v1(
                    scalar,
                    u8::try_from(window).map_err(|_| P256ScalarBitBusErrorV1::Resource)?,
                )
                .map_err(map_window_error_v1)?;
            for bit in 0..4 {
                let (limb, limb_bit) = p256_scalar_window_bit_to_c_position_v1(window, bit)?;
                expected.push(ExpectedAccessV1 {
                    fixed: P256ScalarBitBusFixedAccessV1::Active {
                        scalar,
                        window: u8::try_from(window)
                            .map_err(|_| P256ScalarBitBusErrorV1::Resource)?,
                        bit: u8::try_from(bit).map_err(|_| P256ScalarBitBusErrorV1::Resource)?,
                    },
                    arithmetic_bit: scalar_c_bits[limb][limb_bit],
                    window_bit: trace.bit_v1(bit).map_err(map_window_error_v1)?,
                });
            }
        }
    }
    if expected.len() != P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1 {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    expected.push(ExpectedAccessV1::inactive());
    Ok(expected)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_sources_v1(
    sources: &[P256ScalarBitSourceV1],
    arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
) -> Result<(), P256ScalarBitBusErrorV1> {
    if sources.len() != P256_SCALAR_BIT_BUS_SCALARS_V1
        || sources[0].scalar != P256WindowScalarV1::U1
        || sources[1].scalar != P256WindowScalarV1::U2
        || sources[0].c_operation == sources[1].c_operation
    {
        return Err(P256ScalarBitBusErrorV1::Topology);
    }
    arithmetic_trace
        .validate()
        .map_err(map_arithmetic_error_v1)?;
    for source in sources {
        let operation =
            usize::try_from(source.c_operation).map_err(|_| P256ScalarBitBusErrorV1::Resource)?;
        let row = operation
            .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .ok_or(P256ScalarBitBusErrorV1::Resource)?;
        let fixed = arithmetic_trace
            .fixed
            .get(row)
            .ok_or(P256ScalarBitBusErrorV1::Topology)?;
        if fixed.operation != source.c_operation
            || fixed.coefficient != 0
            || fixed.modulus != ZkX509P256ModulusV1::ScalarField
        {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_row_range_v1(row: &P256ScalarBitBusRowV1) -> Result<(), P256ScalarBitBusErrorV1> {
    if row
        .arithmetic_bits
        .iter()
        .chain(row.window_bits.iter())
        .chain(row.arithmetic_products.iter().flatten())
        .chain(row.window_products.iter().flatten())
        .any(|value| F::canonical(value.0).is_none())
    {
        return Err(P256ScalarBitBusErrorV1::Range);
    }
    for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
        let arithmetic_bit = row.arithmetic_bits[slot];
        let window_bit = row.window_bits[slot];
        if ![F::ZERO, F::ONE].contains(&arithmetic_bit)
            || ![F::ZERO, F::ONE].contains(&window_bit)
            || (row.fixed[slot] == P256ScalarBitBusFixedAccessV1::Inactive
                && (arithmetic_bit != F::ZERO || window_bit != F::ZERO))
        {
            return Err(P256ScalarBitBusErrorV1::Range);
        }
        if let P256ScalarBitBusFixedAccessV1::Active { window, bit, .. } = row.fixed[slot]
            && (usize::from(window) >= P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1 || bit >= 4)
        {
            return Err(P256ScalarBitBusErrorV1::Topology);
        }
    }
    Ok(())
}
#[cfg(test)]
fn compress_access_v1(
    fixed: P256ScalarBitBusFixedAccessV1,
    value: F,
    challenges: P256ScalarBitBusLaneChallengesV1,
) -> F {
    let P256ScalarBitBusFixedAccessV1::Active {
        scalar,
        window,
        bit,
    } = fixed
    else {
        return F::ONE;
    };
    let terms = challenges.terms;
    terms[0]
        .add(terms[1].mul(F(match scalar {
            P256WindowScalarV1::U1 => 1,
            P256WindowScalarV1::U2 => 2,
        })))
        .add(terms[2].mul(F(u64::from(window) + 1)))
        .add(terms[3].mul(F(u64::from(bit) + 1)))
        .add(terms[4].mul(value))
}
const fn expected_scalar_v1(index: usize) -> Result<P256WindowScalarV1, P256ScalarBitBusErrorV1> {
    match index {
        0 => Ok(P256WindowScalarV1::U1),
        1 => Ok(P256WindowScalarV1::U2),
        _ => Err(P256ScalarBitBusErrorV1::Topology),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn map_arithmetic_error_v1(error: ZkX509P256AirErrorV1) -> P256ScalarBitBusErrorV1 {
    match error {
        ZkX509P256AirErrorV1::Topology => P256ScalarBitBusErrorV1::Topology,
        ZkX509P256AirErrorV1::Allocation => P256ScalarBitBusErrorV1::Resource,
        _ => P256ScalarBitBusErrorV1::ArithmeticSource,
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn map_window_error_v1(error: P256WindowAirErrorV1) -> P256ScalarBitBusErrorV1 {
    match error {
        P256WindowAirErrorV1::Topology | P256WindowAirErrorV1::Index => {
            P256ScalarBitBusErrorV1::Topology
        }
        P256WindowAirErrorV1::Allocation => P256ScalarBitBusErrorV1::Resource,
        P256WindowAirErrorV1::ExternalRange | P256WindowAirErrorV1::Constraint => {
            P256ScalarBitBusErrorV1::WindowSource
        }
    }
}
#[cfg(test)]
#[path = "p256_scalar_bit_bus_fp4_tests.rs"]
mod fp4_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
    use crate::privacy_engines::zk_x509::{
        credential_pre_aux::{
            ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, ZkX509CredentialMainPreAuxV1,
            derive_zk_x509_credential_pre_aux_binding_v1,
        },
        p256_air::{
            ZkX509P256ArithmeticKindV1, ZkX509P256ArithmeticOperationV1,
            build_zk_x509_p256_arithmetic_trace_v1,
        },
        p256_window_air::{
            P256_WINDOW_CANDIDATES_V1, P256WindowPointV1, build_p256_window_trace_v1,
        },
        stark::zk_x509_test_digest384_v1,
    };
    use std::sync::OnceLock;
    struct FixtureV1 {
        values: [[u8; 32]; P256_SCALAR_BIT_BUS_SCALARS_V1],
        operations: [ZkX509P256ArithmeticOperationV1; P256_SCALAR_BIT_BUS_SCALARS_V1],
        sources: [P256ScalarBitSourceV1; P256_SCALAR_BIT_BUS_SCALARS_V1],
        arithmetic: ZkX509P256ArithmeticTraceV1,
        windows: Vec<P256WindowTraceV1>,
        challenges: P256ScalarBitBusChallengesV1,
        trace: P256ScalarBitBusTraceV1,
    }
    fn fixture_v1() -> &'static FixtureV1 {
        static FIXTURE: OnceLock<FixtureV1> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let values = [
                core::array::from_fn(|index| if index % 2 == 0 { 0x55 } else { 0xc3 }),
                core::array::from_fn(|index| if index % 2 == 0 { 0xa5 } else { 0x3c }),
            ];
            let operations = core::array::from_fn(|index| ZkX509P256ArithmeticOperationV1 {
                kind: ZkX509P256ArithmeticKindV1::Add,
                modulus: ZkX509P256ModulusV1::ScalarField,
                a: values[index],
                b: [0; 32],
                c: values[index],
            });
            let arithmetic = build_zk_x509_p256_arithmetic_trace_v1(&operations)
                .expect("two canonical scalar results");
            let sources = [
                P256ScalarBitSourceV1 {
                    scalar: P256WindowScalarV1::U1,
                    c_operation: 0,
                },
                P256ScalarBitSourceV1 {
                    scalar: P256WindowScalarV1::U2,
                    c_operation: 1,
                },
            ];
            let mut windows = Vec::with_capacity(
                P256_SCALAR_BIT_BUS_SCALARS_V1 * P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1,
            );
            for (scalar_index, scalar) in [P256WindowScalarV1::U1, P256WindowScalarV1::U2]
                .into_iter()
                .enumerate()
            {
                for window in 0..P256_SCALAR_BIT_BUS_WINDOWS_PER_SCALAR_V1 {
                    windows.push(
                        build_p256_window_trace_v1(
                            scalar,
                            window as u8,
                            table_v1(),
                            bits_for_window_v1(values[scalar_index], window),
                        )
                        .expect("canonical window trace"),
                    );
                }
            }
            let challenges = challenges_v1();
            let trace = build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &sources,
                &windows,
                &arithmetic,
                challenges,
            )
            .expect("complete scalar-bit bus");
            FixtureV1 {
                values,
                operations,
                sources,
                arithmetic,
                windows,
                challenges,
                trace,
            }
        })
    }
    fn table_v1() -> [P256WindowPointV1; P256_WINDOW_CANDIDATES_V1] {
        core::array::from_fn(|candidate| P256WindowPointV1 {
            x_be: coordinate_v1(candidate as u8, 0x11),
            y_be: coordinate_v1(candidate as u8, 0x53),
            z_be: coordinate_v1(candidate as u8, 0x97),
        })
    }
    fn coordinate_v1(candidate: u8, domain: u8) -> [u8; 32] {
        core::array::from_fn(|index| {
            domain
                .wrapping_add(candidate.wrapping_mul(17))
                .wrapping_add((index as u8).wrapping_mul(29))
        })
    }
    fn bits_for_window_v1(value: [u8; 32], window: usize) -> [u8; 4] {
        let byte = value[window / 2];
        let nibble = if window.is_multiple_of(2) {
            byte >> 4
        } else {
            byte & 0x0f
        };
        core::array::from_fn(|bit| (nibble >> (3 - bit)) & 1)
    }
    fn challenges_v1() -> P256ScalarBitBusChallengesV1 {
        P256ScalarBitBusChallengesV1 {
            lanes: core::array::from_fn(|lane| P256ScalarBitBusLaneChallengesV1 {
                terms: core::array::from_fn(|term| {
                    F(17 + (lane * P256_SCALAR_BIT_BUS_TUPLE_TERMS_V1 + term) as u64)
                }),
            }),
        }
    }
    fn post_base_v1(seed: u8) -> ZkX509CredentialMainPostBaseChallengesV1 {
        let main = ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            core::array::from_fn::<_, ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, _>(|index| {
                zk_x509_test_digest384_v1(seed.wrapping_add(index as u8).wrapping_add(2))
            }),
        );
        derive_zk_x509_credential_pre_aux_binding_v1(
            main,
            zk_x509_test_digest384_v1(seed.wrapping_add(0x20)),
            zk_x509_test_digest384_v1(seed.wrapping_add(0x40)),
            zk_x509_test_digest384_v1(seed.wrapping_add(0x60)),
        )
        .expect("opaque X5B1 binding")
        .main_post_base()
    }
    fn base_source_v1() -> P256ScalarBitBusBaseSourceV1 {
        let fixture = fixture_v1();
        P256ScalarBitBusBaseSourceV1::from_sources_for_test_v1(
            &fixture.sources,
            &fixture.windows,
            &fixture.arithmetic,
        )
        .expect("challenge-independent scalar-bit bus")
    }
    fn slot_v1(trace: &P256ScalarBitBusTraceV1, ordinal: usize) -> (&P256ScalarBitBusRowV1, usize) {
        (
            &trace.rows[ordinal / P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1],
            ordinal % P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1,
        )
    }
    fn rebuild_products_v1(
        trace: &mut P256ScalarBitBusTraceV1,
        challenges: P256ScalarBitBusChallengesV1,
    ) {
        let mut arithmetic_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        let mut window_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        for row in &mut trace.rows {
            row.arithmetic_products[0] = arithmetic_running;
            row.window_products[0] = window_running;
            for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
                for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
                    arithmetic_running[lane] = arithmetic_running[lane].mul(compress_access_v1(
                        row.fixed[slot],
                        row.arithmetic_bits[slot],
                        challenges.lanes[lane],
                    ));
                    window_running[lane] = window_running[lane].mul(compress_access_v1(
                        row.fixed[slot],
                        row.window_bits[slot],
                        challenges.lanes[lane],
                    ));
                }
                row.arithmetic_products[slot + 1] = arithmetic_running;
                row.window_products[slot + 1] = window_running;
            }
        }
    }
    fn flip_bit_v1(bit: F) -> F {
        F::ONE.sub(bit)
    }
    fn post_commitment_transcript_v1(
        arithmetic_commitment: PrivacyOuterDigestV1,
        window_commitments: &[PrivacyOuterDigestV1; 128],
    ) -> TransparentTranscriptV1 {
        let mut transcript = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"p256-scalar-bit-bus-test",
            &PrivacyOuterDigestV1::from_bytes([0x31; 48]),
            &PrivacyOuterDigestV1::from_bytes([0x72; 48]),
        )
        .expect("test transcript");
        let arithmetic_commitment = arithmetic_commitment.to_bytes();
        transcript
            .absorb(
                b"zk-x509-p256-arithmetic-base-commitment-v1",
                &[&arithmetic_commitment],
            )
            .expect("arithmetic commitment");
        for (index, commitment) in window_commitments.iter().enumerate() {
            let commitment = commitment.to_bytes();
            transcript
                .absorb(
                    b"zk-x509-p256-window-base-commitment-v1",
                    &[&(index as u32).to_be_bytes(), &commitment],
                )
                .expect("window commitment");
        }
        transcript
    }
    fn numeric_rejects_v1(
        base: &[[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1]],
        aux: &[[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1]],
        fixed: &[[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1]],
        challenges: P256ScalarBitBusChallengesV1,
    ) -> bool {
        if base.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
            || aux.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
            || fixed.len() != P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
        {
            return true;
        }
        (0..P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1).any(|row| {
            let next = (row + 1) % P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1;
            match evaluate_p256_scalar_bit_bus_stark_residues_v1(
                &base[row],
                &base[next],
                &aux[row],
                &aux[next],
                &fixed[row],
                challenges,
            ) {
                Ok(residues) => {
                    residues.len() != P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1
                        || residues.iter().any(|residue| *residue != F::ZERO)
                }
                Err(_) => true,
            }
        })
    }
    #[test]
    fn phased_source_matches_legacy_base_aux_fixed_and_terminals() {
        let fixture = fixture_v1();
        let post_base = post_base_v1(0x21);
        let legacy_trace = build_zk_x509_p256_scalar_bit_bus_trace_v1(
            &fixture.sources,
            &fixture.windows,
            &fixture.arithmetic,
            post_base.p256_scalar(),
        )
        .expect("legacy differential trace");
        let legacy =
            build_p256_scalar_bit_bus_stark_trace_v1(&legacy_trace).expect("legacy STARK rows");
        let mut source = base_source_v1();
        {
            let base = source.base_rows_v1().expect("pre-X5B1 base rows");
            for column in 0..P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1 {
                let mut output = vec![F(99); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
                base.fill_base_column_v1(column, &mut output)
                    .expect("complete base column");
                assert_eq!(
                    output,
                    legacy
                        .base
                        .iter()
                        .map(|row| row[column])
                        .collect::<Vec<_>>(),
                    "base column {column}",
                );
            }
        }
        {
            let fixed = source.fixed_rows_v1().expect("pre-X5B1 fixed rows");
            let legacy_fixed =
                compile_p256_scalar_bit_bus_stark_fixed_rows_v1().expect("fixed schedule");
            for column in 0..P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1 {
                let mut output = vec![F(99); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
                fixed
                    .fill_fixed_column_v1(column, &mut output)
                    .expect("complete fixed column");
                assert_eq!(
                    output,
                    legacy_fixed
                        .iter()
                        .map(|row| row[column])
                        .collect::<Vec<_>>(),
                    "fixed column {column}",
                );
            }
        }
        let bound = source.bind_v1(post_base).expect("one-shot X5B1 bind");
        let aux = bound.aux_source_v1().expect("post-X5B1 auxiliary replay");
        for column in 0..P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1 {
            let mut output = vec![F(99); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            aux.fill_aux_column_v1(column, &mut output)
                .expect("complete auxiliary column");
            assert_eq!(
                output,
                legacy.aux.iter().map(|row| row[column]).collect::<Vec<_>>(),
                "auxiliary column {column}",
            );
        }
        assert_eq!(
            bound.terminals_v1(),
            p256_scalar_bit_bus_opened_terminals_v1(&legacy.aux[P256_SCALAR_BIT_BUS_ROWS_V1 - 1],),
        );
    }
    #[test]
    fn two_opaque_tokens_leave_base_and_fixed_invariant_but_change_aux() {
        let first_token = post_base_v1(0x31);
        let second_token = post_base_v1(0x71);
        assert_ne!(
            first_token.p256_scalar(),
            second_token.p256_scalar(),
            "test tokens must bind distinct scalar-bit challenges",
        );
        let mut first = base_source_v1();
        let mut second = base_source_v1();
        for column in 0..P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1 {
            let mut first_column = vec![F(17); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            let mut second_column = vec![F(29); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            first
                .base_rows_v1()
                .expect("first base rows")
                .fill_base_column_v1(column, &mut first_column)
                .expect("first base column");
            second
                .base_rows_v1()
                .expect("second base rows")
                .fill_base_column_v1(column, &mut second_column)
                .expect("second base column");
            assert_eq!(first_column, second_column, "base column {column}");
        }
        for column in 0..P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1 {
            let mut first_column = vec![F(17); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            let mut second_column = vec![F(29); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            first
                .fixed_rows_v1()
                .expect("first fixed rows")
                .fill_fixed_column_v1(column, &mut first_column)
                .expect("first fixed column");
            second
                .fixed_rows_v1()
                .expect("second fixed rows")
                .fill_fixed_column_v1(column, &mut second_column)
                .expect("second fixed column");
            assert_eq!(first_column, second_column, "fixed column {column}");
        }
        let first = first.bind_v1(first_token).expect("first opaque bind");
        let second = second.bind_v1(second_token).expect("second opaque bind");
        let mut changed = false;
        for column in 0..P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1 {
            let mut first_column = vec![F::ZERO; P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            let mut second_column = vec![F::ZERO; P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            first
                .aux_source_v1()
                .expect("first auxiliary source")
                .fill_aux_column_v1(column, &mut first_column)
                .expect("first auxiliary column");
            second
                .aux_source_v1()
                .expect("second auxiliary source")
                .fill_aux_column_v1(column, &mut second_column)
                .expect("second auxiliary column");
            changed |= first_column != second_column;
        }
        assert!(changed, "X5B1 challenges must affect auxiliary products");
        for column in 0..P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1 {
            let mut first_column = vec![F(17); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            let mut second_column = vec![F(29); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
            first
                .base_rows_v1()
                .expect("bound first base rows")
                .fill_base_column_v1(column, &mut first_column)
                .expect("bound first base column");
            second
                .base_rows_v1()
                .expect("bound second base rows")
                .fill_base_column_v1(column, &mut second_column)
                .expect("bound second base column");
            assert_eq!(first_column, second_column, "bound base column {column}");
        }
    }
    #[test]
    fn phased_source_rejects_bad_identity_width_and_length_without_mutation() {
        let fixture = fixture_v1();
        assert!(matches!(
            P256ScalarBitBusBaseSourceV1::new_v1(&fixture.windows, &fixture.arithmetic),
            Err(P256ScalarBitBusErrorV1::Topology),
        ));
        let mut swapped = fixture.sources;
        swapped.swap(0, 1);
        assert!(matches!(
            P256ScalarBitBusBaseSourceV1::from_sources_for_test_v1(
                &swapped,
                &fixture.windows,
                &fixture.arithmetic,
            ),
            Err(P256ScalarBitBusErrorV1::Topology),
        ));
        let zero = ZkX509P256ArithmeticOperationV1 {
            kind: ZkX509P256ArithmeticKindV1::Add,
            modulus: ZkX509P256ModulusV1::ScalarField,
            a: [0; 32],
            b: [0; 32],
            c: [0; 32],
        };
        let mut canonical_operations =
            vec![
                zero;
                usize::try_from(P256_SCALAR_BIT_BUS_U2_C_OPERATION_V1 + 1)
                    .expect("operation count")
            ];
        canonical_operations
            [usize::try_from(P256_SCALAR_BIT_BUS_U1_C_OPERATION_V1).expect("u1 operation")] =
            fixture.operations[0];
        canonical_operations
            [usize::try_from(P256_SCALAR_BIT_BUS_U2_C_OPERATION_V1).expect("u2 operation")] =
            fixture.operations[1];
        let canonical_arithmetic = build_zk_x509_p256_arithmetic_trace_v1(&canonical_operations)
            .expect("canonical scalar operation positions");
        P256ScalarBitBusBaseSourceV1::new_v1(&fixture.windows, &canonical_arithmetic)
            .expect("verifier-owned u1/u2 identities");
        let mut source = base_source_v1();
        let base = source.base_rows_v1().expect("base rows");
        let mut bad_width = vec![F(77); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
        let before = bad_width.clone();
        assert_eq!(
            base.fill_base_column_v1(P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1, &mut bad_width),
            Err(P256ScalarBitBusErrorV1::Topology),
        );
        assert_eq!(bad_width, before);
        let mut bad_length = vec![F(78); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 - 1];
        let before = bad_length.clone();
        assert_eq!(
            base.fill_base_column_v1(0, &mut bad_length),
            Err(P256ScalarBitBusErrorV1::Topology),
        );
        assert_eq!(bad_length, before);
        assert_eq!(
            P256ScalarBitBusStarkFixedProviderV1::new_v1(
                P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 / 2,
            ),
            Err(P256ScalarBitBusErrorV1::Topology),
        );
        let fixed = source.fixed_rows_v1().expect("fixed rows");
        let mut bad_width = vec![F(79); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
        let before = bad_width.clone();
        assert_eq!(
            fixed.fill_fixed_column_v1(P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1, &mut bad_width),
            Err(P256ScalarBitBusErrorV1::Topology),
        );
        assert_eq!(bad_width, before);
        let bound = source.bind_v1(post_base_v1(0x42)).expect("opaque bind");
        let aux = bound.aux_source_v1().expect("auxiliary source");
        let mut bad_width = vec![F(80); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
        let before = bad_width.clone();
        assert_eq!(
            aux.fill_aux_column_v1(P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1, &mut bad_width),
            Err(P256ScalarBitBusErrorV1::Topology),
        );
        assert_eq!(bad_width, before);
        let mut bad_length = vec![F(81); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1 + 1];
        let before = bad_length.clone();
        assert_eq!(
            aux.fill_aux_column_v1(0, &mut bad_length),
            Err(P256ScalarBitBusErrorV1::Topology),
        );
        assert_eq!(bad_length, before);
    }
    #[test]
    fn bind_is_one_shot_and_failed_attempt_is_permanently_poisoned() {
        let first_token = post_base_v1(0x51);
        let second_token = post_base_v1(0x52);
        let mut malformed = base_source_v1();
        let row = malformed
            .material_mut_for_test_v1()
            .expect("test material")
            .row_mut_for_test_v1(93)
            .expect("active row");
        row[STARK_ARITHMETIC_BITS] = F::ONE.sub(row[STARK_ARITHMETIC_BITS]);
        assert!(matches!(
            malformed.bind_v1(first_token),
            Err(P256ScalarBitBusErrorV1::Equality),
        ));
        assert!(malformed.bind_attempted_for_test_v1());
        assert!(matches!(
            malformed.bind_v1(second_token),
            Err(P256ScalarBitBusErrorV1::Phase),
        ));
        let mut valid = base_source_v1();
        let bound = valid.bind_v1(first_token).expect("first bind succeeds");
        assert!(matches!(
            valid.bind_v1(second_token),
            Err(P256ScalarBitBusErrorV1::Phase),
        ));
        assert!(bound.aux_source_v1().is_ok());
    }
    #[test]
    fn mid_column_failure_zeroizes_the_entire_destination() {
        let mut source = base_source_v1();
        source
            .material_mut_for_test_v1()
            .expect("test material")
            .row_mut_for_test_v1(113)
            .expect("active row")[STARK_ARITHMETIC_BITS] = F(u64::MAX);
        let provider = source.base_rows_v1().expect("shape-valid row provider");
        let mut output = vec![F(0xdead); P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1];
        assert_eq!(
            provider.fill_base_column_v1(STARK_ARITHMETIC_BITS, &mut output),
            Err(P256ScalarBitBusErrorV1::Range),
        );
        assert!(output.iter().all(|value| *value == F::ZERO));
    }
    #[test]
    fn phased_private_state_zeroizes_recursively() {
        let ((), observations) = super::super::private_table::inspection::observe_v1(
            phased_private_state_zeroizes_recursively_body_v1,
        );
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
    fn phased_private_state_zeroizes_recursively_body_v1() {
        let fixture = fixture_v1();
        let mut material = P256ScalarBitBusBaseMaterialV1::from_sources_for_test_v1(
            &fixture.sources,
            &fixture.windows,
            &fixture.arithmetic,
        )
        .expect("base material");
        material.zeroize_private_v1();
        assert!(material.private_is_zeroized_v1());
        let mut source = base_source_v1();
        source.zeroize_private_v1();
        assert!(source.private_is_zeroized_v1());
        let mut source = base_source_v1();
        let mut bound = source
            .bind_v1(post_base_v1(0x61))
            .expect("bound scalar-bit source");
        let mut aux = bound.aux_source_v1().expect("auxiliary source");
        aux.next_aux_row_v1()
            .expect("first auxiliary row")
            .expect("row exists");
        aux.zeroize_private_v1();
        assert!(aux.private_is_zeroized_v1());
        drop(aux);
        bound.zeroize_private_v1();
        assert!(bound.private_is_zeroized_v1());
        let mut legacy =
            build_p256_scalar_bit_bus_stark_trace_v1(&fixture.trace).expect("legacy trace");
        legacy.zeroize_private_v1();
        assert!(legacy.base.is_empty());
        assert!(legacy.aux.is_empty());
    }
    #[test]
    fn numeric_fixed_evaluator_matches_all_512_copies_and_canonical_padding() {
        let fixture = fixture_v1();
        let stark = build_p256_scalar_bit_bus_stark_trace_v1(&fixture.trace)
            .expect("rectangular scalar-bit bus");
        let fixed =
            compile_p256_scalar_bit_bus_stark_fixed_rows_v1().expect("canonical fixed schedule");
        assert_eq!(stark.base.len(), P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1);
        assert_eq!(stark.aux.len(), P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1);
        assert_eq!(fixed.len(), P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1);
        assert!(!numeric_rejects_v1(
            &stark.base,
            &stark.aux,
            &fixed,
            fixture.challenges,
        ));
        for factor in 0..P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1 {
            let row = factor / P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1;
            let slot = factor % P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1;
            let start = slot * STARK_FIXED_SLOT_WIDTH;
            match expected_stark_fixed_access_v1(factor).expect("in-range factor") {
                P256ScalarBitBusFixedAccessV1::Inactive => {
                    assert_eq!(
                        fixed[row][start..start + STARK_FIXED_SLOT_WIDTH],
                        [F::ZERO; STARK_FIXED_SLOT_WIDTH],
                    );
                }
                P256ScalarBitBusFixedAccessV1::Active {
                    scalar,
                    window,
                    bit,
                } => {
                    assert_eq!(fixed[row][start + STARK_FIXED_SLOT_ACTIVE], F::ONE);
                    assert_eq!(
                        fixed[row][start + STARK_FIXED_SLOT_SCALAR],
                        F(match scalar {
                            P256WindowScalarV1::U1 => 1,
                            P256WindowScalarV1::U2 => 2,
                        }),
                    );
                    assert_eq!(
                        fixed[row][start + STARK_FIXED_SLOT_WINDOW],
                        F(u64::from(window) + 1),
                    );
                    assert_eq!(
                        fixed[row][start + STARK_FIXED_SLOT_BIT],
                        F(u64::from(bit) + 1),
                    );
                }
            }
        }
        for row in fixed.iter().skip(P256_SCALAR_BIT_BUS_ROWS_V1) {
            assert_eq!(row[STARK_FIXED_PADDING], F::ONE);
            assert!(
                row[..STARK_FIXED_PADDING]
                    .iter()
                    .all(|value| *value == F::ZERO)
            );
        }
        assert_eq!(
            p256_scalar_bit_bus_stark_last_active_selector_v1(
                &fixed[P256_SCALAR_BIT_BUS_ROWS_V1 - 1],
            ),
            F::ONE
        );
        assert_eq!(
            p256_scalar_bit_bus_stark_last_active_selector_v1(&fixed[0]),
            F::ZERO
        );
        assert_eq!(
            p256_scalar_bit_bus_stark_last_active_selector_v1(&fixed[P256_SCALAR_BIT_BUS_ROWS_V1],),
            F::ZERO
        );
        assert_eq!(
            compile_p256_scalar_bit_bus_stark_fixed_rows_v1(),
            Ok(fixed),
            "verifier preprocessing must be deterministic",
        );
    }
    #[test]
    fn numeric_evaluator_binds_every_active_and_padding_witness_column() {
        let fixture = fixture_v1();
        let stark = build_p256_scalar_bit_bus_stark_trace_v1(&fixture.trace)
            .expect("rectangular scalar-bit bus");
        let fixed =
            compile_p256_scalar_bit_bus_stark_fixed_rows_v1().expect("canonical fixed schedule");
        let active_row = 73;
        let padding_row = P256_SCALAR_BIT_BUS_ROWS_V1 + 11;
        for column in 0..P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1 {
            let mut changed = stark.base.clone();
            changed[active_row][column] = changed[active_row][column].add(F::ONE);
            assert!(
                numeric_rejects_v1(&changed, &stark.aux, &fixed, fixture.challenges),
                "unbound active base column {column}",
            );
            let mut changed = stark.base.clone();
            changed[padding_row][column] = changed[padding_row][column].add(F::ONE);
            assert!(
                numeric_rejects_v1(&changed, &stark.aux, &fixed, fixture.challenges),
                "unbound padding base column {column}",
            );
        }
        for column in 0..P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1 {
            let mut changed = stark.aux.clone();
            changed[active_row][column] = changed[active_row][column].add(F::ONE);
            assert!(
                numeric_rejects_v1(&stark.base, &changed, &fixed, fixture.challenges),
                "unbound active auxiliary column {column}",
            );
            let mut changed = stark.aux.clone();
            changed[padding_row][column] = changed[padding_row][column].add(F::ONE);
            assert!(
                numeric_rejects_v1(&stark.base, &changed, &fixed, fixture.challenges),
                "unbound padding auxiliary column {column}",
            );
        }
    }
    #[test]
    fn numeric_evaluator_rejects_schedule_terminal_challenge_and_range_attacks() {
        let fixture = fixture_v1();
        let stark = build_p256_scalar_bit_bus_stark_trace_v1(&fixture.trace)
            .expect("rectangular scalar-bit bus");
        let fixed =
            compile_p256_scalar_bit_bus_stark_fixed_rows_v1().expect("canonical fixed schedule");
        let mut reordered = fixed.clone();
        reordered.swap(37, 38);
        assert!(numeric_rejects_v1(
            &stark.base,
            &stark.aux,
            &reordered,
            fixture.challenges,
        ));
        let mut substituted = fixed.clone();
        substituted[19][STARK_FIXED_SLOT_WINDOW] =
            substituted[19][STARK_FIXED_SLOT_WINDOW].add(F::ONE);
        assert!(numeric_rejects_v1(
            &stark.base,
            &stark.aux,
            &substituted,
            fixture.challenges,
        ));
        let mut terminal = stark.aux.clone();
        let last = P256_SCALAR_BIT_BUS_ROWS_V1 - 1;
        let terminal_column = STARK_WINDOW_PRODUCTS
            + (P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1) * P256_SCALAR_BIT_BUS_LANES_V1
            + 2;
        terminal[last][terminal_column] = terminal[last][terminal_column].add(F::ONE);
        assert!(numeric_rejects_v1(
            &stark.base,
            &terminal,
            &fixed,
            fixture.challenges,
        ));
        let mut bad_challenges = fixture.challenges;
        bad_challenges.lanes[0].terms[0] = F::ZERO;
        assert!(numeric_rejects_v1(
            &stark.base,
            &stark.aux,
            &fixed,
            bad_challenges,
        ));
        let current_row = 8;
        let next_row = current_row + 1;
        let noncanonical = F(u64::MAX);
        for opening in 0..5 {
            let mut current_base = stark.base[current_row];
            let mut next_base = stark.base[next_row];
            let mut current_aux = stark.aux[current_row];
            let mut next_aux = stark.aux[next_row];
            let mut fixed_row = fixed[current_row];
            match opening {
                0 => current_base[0] = noncanonical,
                1 => next_base[0] = noncanonical,
                2 => current_aux[0] = noncanonical,
                3 => next_aux[0] = noncanonical,
                4 => fixed_row[0] = noncanonical,
                _ => unreachable!(),
            }
            assert_eq!(
                evaluate_p256_scalar_bit_bus_stark_residues_v1(
                    &current_base,
                    &next_base,
                    &current_aux,
                    &next_aux,
                    &fixed_row,
                    fixture.challenges,
                ),
                Err(P256ScalarBitBusErrorV1::Range),
                "non-canonical opening group {opening}",
            );
        }
    }
    #[test]
    fn numeric_copy_bus_alone_cannot_replace_source_side_commitment_binding() {
        let fixture = fixture_v1();
        let mut coordinated = fixture.trace.clone();
        let row = 19;
        let slot = 1;
        let replacement = flip_bit_v1(coordinated.rows[row].arithmetic_bits[slot]);
        coordinated.rows[row].arithmetic_bits[slot] = replacement;
        coordinated.rows[row].window_bits[slot] = replacement;
        rebuild_products_v1(&mut coordinated, fixture.challenges);
        let stark = build_p256_scalar_bit_bus_stark_trace_v1(&coordinated)
            .expect("internally consistent coordinated copy");
        let fixed =
            compile_p256_scalar_bit_bus_stark_fixed_rows_v1().expect("canonical fixed schedule");
        assert!(
            !numeric_rejects_v1(&stark.base, &stark.aux, &fixed, fixture.challenges),
            "the copy bus only proves equality between its two committed copies",
        );
        assert_eq!(
            coordinated.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::ArithmeticSource),
            "activation must remain gated on algebraic source-side products",
        );
        assert!(
            ZK_X509_P256_SCALAR_BIT_BUS_DESCRIPTOR_V1
                .windows(b"source-side-terminal-binding=complete-via-p256-aggregate-adapter".len())
                .any(|window| {
                    window == b"source-side-terminal-binding=complete-via-p256-aggregate-adapter"
                }),
        );
    }
    #[test]
    fn complete_schedule_roundtrips_with_exact_mapping_and_one_padding_slot() {
        let fixture = fixture_v1();
        fixture
            .trace
            .validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            )
            .expect("complete pointwise copy");
        assert_eq!(P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1, 512);
        assert_eq!(P256_SCALAR_BIT_BUS_ROWS_V1, 171);
        assert_eq!(P256_SCALAR_BIT_BUS_FACTOR_SLOTS_V1, 513);
        assert_eq!(p256_scalar_window_bit_to_c_position_v1(0, 0), Ok((15, 15)));
        assert_eq!(p256_scalar_window_bit_to_c_position_v1(63, 3), Ok((0, 0)));
        assert_eq!(
            p256_scalar_window_bit_to_c_position_v1(64, 0),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        assert_eq!(
            p256_scalar_window_bit_to_c_position_v1(0, 4),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        for scalar in 0..P256_SCALAR_BIT_BUS_SCALARS_V1 {
            for global_be in 0..P256_SCALAR_BITS_V1 {
                let ordinal = scalar * P256_SCALAR_BITS_V1 + global_be;
                let (row, slot) = slot_v1(&fixture.trace, ordinal);
                let byte = fixture.values[scalar][global_be / 8];
                let expected = F(u64::from((byte >> (7 - global_be % 8)) & 1));
                assert_eq!(row.arithmetic_bits[slot], expected, "arithmetic {ordinal}");
                assert_eq!(row.window_bits[slot], expected, "window {ordinal}");
                let (limb, bit) =
                    p256_scalar_window_bit_to_c_position_v1(global_be / 4, global_be % 4)
                        .expect("in-range mapping");
                assert_eq!(limb * 16 + bit, 255 - global_be);
            }
        }
        let (last, padding_slot) = slot_v1(&fixture.trace, P256_SCALAR_BIT_BUS_ACTIVE_BITS_V1);
        assert_eq!(padding_slot, 2);
        assert_eq!(
            last.fixed[padding_slot],
            P256ScalarBitBusFixedAccessV1::Inactive
        );
        assert_eq!(last.arithmetic_bits[padding_slot], F::ZERO);
        assert_eq!(last.window_bits[padding_slot], F::ZERO);
        assert_eq!(
            last.arithmetic_products[padding_slot],
            last.arithmetic_products[padding_slot + 1]
        );
        assert_eq!(
            last.window_products[padding_slot],
            last.window_products[padding_slot + 1]
        );
        assert_eq!(
            evaluate_zk_x509_p256_scalar_bit_bus_terminal_constraints_v1(&fixture.trace),
            Ok([F::ZERO; P256_SCALAR_BIT_BUS_LANES_V1])
        );
    }
    #[test]
    fn missing_duplicate_extra_and_reordered_windows_fail_closed() {
        let fixture = fixture_v1();
        let mut windows = fixture.windows.clone();
        windows.pop();
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut windows = fixture.windows.clone();
        windows.push(fixture.windows[0].clone());
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut windows = fixture.windows.clone();
        windows[1] = windows[0].clone();
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut windows = fixture.windows.clone();
        windows.swap(31, 32);
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut windows = fixture.windows.clone();
        windows.swap(63, 64);
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
    }
    #[test]
    fn source_operations_are_exact_ordered_distinct_scalar_field_results() {
        let fixture = fixture_v1();
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources[..1],
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut sources = fixture.sources;
        sources.swap(0, 1);
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut sources = fixture.sources;
        sources[1].c_operation = sources[0].c_operation;
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let mut sources = fixture.sources;
        sources[1].c_operation = u32::MAX;
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
        let operations = [
            ZkX509P256ArithmeticOperationV1 {
                modulus: ZkX509P256ModulusV1::BaseField,
                ..fixture.operations[0]
            },
            fixture.operations[1],
        ];
        let arithmetic = build_zk_x509_p256_arithmetic_trace_v1(&operations)
            .expect("valid mixed-modulus arithmetic");
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &fixture.windows,
                &arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        ));
    }
    #[test]
    fn valid_but_inconsistent_window_bits_fail_deterministic_equality() {
        let fixture = fixture_v1();
        let mut windows = fixture.windows.clone();
        let mut bits = bits_for_window_v1(fixture.values[0], 0);
        bits[0] ^= 1;
        windows[0] = build_p256_window_trace_v1(P256WindowScalarV1::U1, 0, table_v1(), bits)
            .expect("internally valid but inconsistent window");
        assert!(matches!(
            build_zk_x509_p256_scalar_bit_bus_trace_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges
            ),
            Err(P256ScalarBitBusErrorV1::Equality)
        ));
    }
    #[test]
    fn either_endpoint_or_coordinated_endpoint_mutation_remains_source_bound() {
        let fixture = fixture_v1();
        let row_index = 19;
        let slot = 1;
        let mut attacked = fixture.trace.clone();
        attacked.rows[row_index].arithmetic_bits[slot] =
            flip_bit_v1(attacked.rows[row_index].arithmetic_bits[slot]);
        rebuild_products_v1(&mut attacked, fixture.challenges);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::ArithmeticSource)
        );
        let mut attacked = fixture.trace.clone();
        attacked.rows[row_index].window_bits[slot] =
            flip_bit_v1(attacked.rows[row_index].window_bits[slot]);
        rebuild_products_v1(&mut attacked, fixture.challenges);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::WindowSource)
        );
        let mut attacked = fixture.trace.clone();
        let flipped = flip_bit_v1(attacked.rows[row_index].arithmetic_bits[slot]);
        attacked.rows[row_index].arithmetic_bits[slot] = flipped;
        attacked.rows[row_index].window_bits[slot] = flipped;
        rebuild_products_v1(&mut attacked, fixture.challenges);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::ArithmeticSource)
        );
    }
    #[test]
    fn metadata_order_shape_padding_and_noncanonical_attacks_fail_closed() {
        let fixture = fixture_v1();
        let mut attacked = fixture.trace.clone();
        attacked.rows[0].fixed[0] = P256ScalarBitBusFixedAccessV1::Active {
            scalar: P256WindowScalarV1::U2,
            window: 0,
            bit: 0,
        };
        rebuild_products_v1(&mut attacked, fixture.challenges);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        let mut attacked = fixture.trace.clone();
        attacked.rows.swap(0, 1);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        let mut attacked = fixture.trace.clone();
        attacked.rows.pop();
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        let mut attacked = fixture.trace.clone();
        attacked.rows.push(fixture.trace.rows[0]);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        let last = P256_SCALAR_BIT_BUS_ROWS_V1 - 1;
        let padding = P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 - 1;
        let mut attacked = fixture.trace.clone();
        attacked.rows[last].arithmetic_bits[padding] = F::ONE;
        attacked.rows[last].window_bits[padding] = F::ONE;
        rebuild_products_v1(&mut attacked, fixture.challenges);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Range)
        );
        let mut attacked = fixture.trace.clone();
        attacked.rows[last].fixed[padding] = P256ScalarBitBusFixedAccessV1::Active {
            scalar: P256WindowScalarV1::U2,
            window: 63,
            bit: 3,
        };
        rebuild_products_v1(&mut attacked, fixture.challenges);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Topology)
        );
        let mut attacked = fixture.trace.clone();
        attacked.rows[7].arithmetic_products[2][1] = F(u64::MAX);
        assert_eq!(
            attacked.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::Range)
        );
    }
    #[test]
    fn every_endpoint_value_equality_and_intermediate_product_state_is_constrained() {
        let fixture = fixture_v1();
        for row_index in 0..P256_SCALAR_BIT_BUS_ROWS_V1 {
            let row = fixture.trace.rows[row_index];
            let arithmetic_before = if row_index == 0 {
                [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1]
            } else {
                fixture.trace.rows[row_index - 1].arithmetic_products
                    [P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1]
            };
            let window_before = if row_index == 0 {
                [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1]
            } else {
                fixture.trace.rows[row_index - 1].window_products
                    [P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1]
            };
            assert!(
                evaluate_zk_x509_p256_scalar_bit_bus_row_constraints_v1(
                    row.fixed,
                    &row,
                    row.arithmetic_bits,
                    row.window_bits,
                    arithmetic_before,
                    window_before,
                    fixture.challenges,
                )
                .iter()
                .all(|constraint| *constraint == F::ZERO),
                "honest row {row_index}"
            );
            for slot in 0..P256_SCALAR_BIT_BUS_FACTORS_PER_ROW_V1 {
                if row.fixed[slot] == P256ScalarBitBusFixedAccessV1::Inactive {
                    continue;
                }
                let mut changed = row;
                changed.arithmetic_bits[slot] = flip_bit_v1(changed.arithmetic_bits[slot]);
                assert!(
                    evaluate_zk_x509_p256_scalar_bit_bus_row_constraints_v1(
                        row.fixed,
                        &changed,
                        row.arithmetic_bits,
                        row.window_bits,
                        arithmetic_before,
                        window_before,
                        fixture.challenges,
                    )
                    .iter()
                    .any(|constraint| *constraint != F::ZERO),
                    "arithmetic value row {row_index} slot {slot}"
                );
                let mut changed = row;
                changed.window_bits[slot] = flip_bit_v1(changed.window_bits[slot]);
                assert!(
                    evaluate_zk_x509_p256_scalar_bit_bus_row_constraints_v1(
                        row.fixed,
                        &changed,
                        row.arithmetic_bits,
                        row.window_bits,
                        arithmetic_before,
                        window_before,
                        fixture.challenges,
                    )
                    .iter()
                    .any(|constraint| *constraint != F::ZERO),
                    "window value row {row_index} slot {slot}"
                );
            }
            for endpoint in 0..2 {
                for state in 0..P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 {
                    for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
                        let mut changed = row;
                        let products = if endpoint == 0 {
                            &mut changed.arithmetic_products
                        } else {
                            &mut changed.window_products
                        };
                        products[state][lane] = products[state][lane].add(F::ONE);
                        assert!(
                            evaluate_zk_x509_p256_scalar_bit_bus_row_constraints_v1(
                                row.fixed,
                                &changed,
                                row.arithmetic_bits,
                                row.window_bits,
                                arithmetic_before,
                                window_before,
                                fixture.challenges,
                            )
                            .iter()
                            .any(|constraint| *constraint != F::ZERO),
                            "endpoint {endpoint} row {row_index} state {state} lane {lane}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn terminal_and_source_trace_attacks_are_detected_independently() {
        let fixture = fixture_v1();
        let mut attacked = fixture.trace.clone();
        let last = attacked.rows.last_mut().expect("last row");
        last.window_products[P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1][2] =
            last.window_products[P256_SCALAR_BIT_BUS_PRODUCT_STATES_V1 - 1][2].add(F::ONE);
        let terminal = evaluate_zk_x509_p256_scalar_bit_bus_terminal_constraints_v1(&attacked)
            .expect("terminal shape");
        assert_ne!(terminal[2], F::ZERO);
        let mut arithmetic = fixture.arithmetic.clone();
        arithmetic.base[0][0] = arithmetic.base[0][0].add(F::ONE);
        assert_eq!(
            fixture.trace.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::ArithmeticSource)
        );
        let mut windows = fixture.windows.clone();
        windows[0].base[0][0] = windows[0].base[0][0].add(F::ONE);
        assert_eq!(
            fixture.trace.validate_v1(
                &fixture.sources,
                &windows,
                &fixture.arithmetic,
                fixture.challenges,
            ),
            Err(P256ScalarBitBusErrorV1::WindowSource)
        );
    }
    #[test]
    fn challenge_validation_and_post_commitment_transcript_separation_are_exact() {
        let fixture = fixture_v1();
        fixture.challenges.validate_v1().expect("test challenges");
        let mut bad = fixture.challenges;
        bad.lanes[0].terms[0] = F::ZERO;
        assert_eq!(bad.validate_v1(), Err(P256ScalarBitBusErrorV1::Challenge));
        let mut bad = fixture.challenges;
        bad.lanes[1].terms[3] = F(u64::MAX);
        assert_eq!(bad.validate_v1(), Err(P256ScalarBitBusErrorV1::Challenge));
        let mut bad = fixture.challenges;
        bad.lanes[2] = bad.lanes[0];
        assert_eq!(bad.validate_v1(), Err(P256ScalarBitBusErrorV1::Challenge));
        let mut bad = fixture.challenges;
        bad.lanes[0].terms[4] = bad.lanes[0].terms[3];
        assert_eq!(bad.validate_v1(), Err(P256ScalarBitBusErrorV1::Challenge));
        let mut wrong_but_well_formed = fixture.challenges;
        wrong_but_well_formed.lanes[1].terms[4] = F(1_001);
        wrong_but_well_formed
            .validate_v1()
            .expect("well-formed replacement challenge");
        assert_eq!(
            fixture.trace.validate_v1(
                &fixture.sources,
                &fixture.windows,
                &fixture.arithmetic,
                wrong_but_well_formed,
            ),
            Err(P256ScalarBitBusErrorV1::Constraint)
        );
        let arithmetic_commitment = PrivacyOuterDigestV1::from_bytes([0x81; 48]);
        let window_commitments: [PrivacyOuterDigestV1; 128] = core::array::from_fn(|index| {
            PrivacyOuterDigestV1::from_bytes(core::array::from_fn(|byte| (index + byte + 1) as u8))
        });
        let mut first = post_commitment_transcript_v1(arithmetic_commitment, &window_commitments);
        let first_challenges = derive_zk_x509_p256_scalar_bit_bus_challenges_v1(&mut first)
            .expect("post-commitment challenges");
        first_challenges
            .validate_v1()
            .expect("separated transcript challenges");
        let mut replay = post_commitment_transcript_v1(arithmetic_commitment, &window_commitments);
        assert_eq!(
            derive_zk_x509_p256_scalar_bit_bus_challenges_v1(&mut replay)
                .expect("deterministic replay"),
            first_challenges
        );
        let mut changed_windows = window_commitments;
        let mut changed_words = changed_windows[91].to_bytes();
        changed_words[0] ^= 1;
        changed_windows[91] = PrivacyOuterDigestV1::from_bytes(changed_words);
        let mut changed = post_commitment_transcript_v1(arithmetic_commitment, &changed_windows);
        assert_ne!(
            derive_zk_x509_p256_scalar_bit_bus_challenges_v1(&mut changed)
                .expect("changed commitment challenges"),
            first_challenges
        );
        let mut changed = post_commitment_transcript_v1(
            PrivacyOuterDigestV1::from_bytes([0x82; 48]),
            &window_commitments,
        );
        assert_ne!(
            derive_zk_x509_p256_scalar_bit_bus_challenges_v1(&mut changed)
                .expect("changed arithmetic commitment challenges"),
            first_challenges
        );
        let mut bare = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"p256-scalar-bit-bus-test",
            &PrivacyOuterDigestV1::from_bytes([0x31; 48]),
            &PrivacyOuterDigestV1::from_bytes([0x72; 48]),
        )
        .expect("bare transcript");
        assert_ne!(
            derive_zk_x509_p256_scalar_bit_bus_challenges_v1(&mut bare)
                .expect("premature challenges"),
            first_challenges
        );
    }
}
