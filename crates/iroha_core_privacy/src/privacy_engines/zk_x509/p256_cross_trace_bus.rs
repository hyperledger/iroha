//! Source-attached cross-trace product bus for the P-256 ECDSA relation.
//!
//! An aggregate STARK cannot bind an arbitrary value-bus writer to an arbitrary window or reduction
//! row by passing native arrays into a row evaluator. This module instead gives every source and
//! sink cell a verifier-fixed tagged factor and proves multiset equality with four independent
//! products.
//!
//! Writer source factors are attached to the committed value-bus execution rows. Repeated uses have
//! the exact first-release multiplicities `{1, 2, 64, 65, 129}` and are exponentiated with a fixed
//! eight-square addition chain, keeping the maximum constraint degree at three. The binder sink
//! consumes its committed writer/external copies directly. Window, reduction, and low-s source
//! products use the generic six-slot product evaluator below and must be appended to their
//! respective source commitments through:
//!
//! - `p256_window_opened_external_cells_v1(&[F; 61]) -> [F; 3]`;
//! - `p256_reduction_opened_binding_cells_v1(&[F; 56]) -> [F; 2]`;
//! - `p256_low_s_opened_binding_cell_v1(&[F; 36]) -> F`.
//!
//! Their exact additional auxiliary widths are 23, 18, and 13 columns. The
//! two-factor-packed value-writer source adds 86 columns (98 together with the
//! existing twelve value-bus products), and the binder sink adds 38. Segment terminal columns
//! are constant and chain value bus -> all windows -> both reductions ->
//! optional low-s. Each linked adapter uses its smallest supported native domain. The 128 window
//! instances are verifier-fixed vertical blocks in exactly `128 * 512 = 65,536` rows, so their
//! product continues through block boundaries. Cross-domain starts and terminals are explicit
//! transcript-bound claims, constrained at each source's own first/final row before verifier
//! equality checks. No standalone copied-source trace or unconstrained host terminal lift is sound.
//!
//! The tagged-product core is intentionally channel-generic. Its arithmetic and window-bit channel
//! tags can also bind the scalar-bit bus without a second permutation construction.
//!
//! The aggregate adapter registers these source-attached auxiliary columns and
//! terminal chain in the production verifier.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_external_binding_air::{
    P256ExternalBindingFixedAccessV1, P256ExternalBindingRowV1, P256ExternalBindingTraceV1,
    p256_input_selection_byte_v1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_value_bus::{
    P256ValueAccessKindV1, P256ValueBusBaseEndpointTraceV1, P256ValueBusErrorV1,
    P256ValueBusFixedAccessV1, p256_value_bus_base_execution_source_cell_v1,
};
use super::{
    p256_ecdsa_air::P256EcdsaRoleV1,
    p256_external_binding_air::{
        P256_EXTERNAL_BINDINGS_PER_ROW_V1, P256_INPUT_SELECTION_ROW_START_V1,
        P256_INPUT_SELECTION_SELECTOR_ROW_V1, P256ExternalBindingCrossExternalSourceV1,
        P256ExternalBindingCrossSourceV1, P256ExternalBindingErrorV1,
        compile_zk_x509_p256_external_cross_sources_v1, p256_external_binding_active_equalities_v1,
        p256_external_binding_dynamic_sources_v1, p256_external_binding_rows_v1,
        p256_selected_input_writer_id_v1,
    },
    p256_value_bus::{
        P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1, P256_VALUE_BUS_LIMBS_V1,
        P256_VALUE_BUS_SEGMENT_ROWS_V1,
    },
};
#[cfg(test)]
use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, PolynomialAirFieldV1, TransparentStarkErrorV1, TransparentTranscriptV1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use std::sync::Arc;
use thiserror::Error;
/// Independent tagged-product lanes.
pub const P256_CROSS_TRACE_LANES_V1: usize = 4;
/// `beta`, endpoint, address, and value coefficients.
pub const P256_CROSS_TRACE_CHALLENGE_TERMS_V1: usize = 4;
/// Unambiguous transcript labels for every lane and tuple coordinate.
pub const P256_CROSS_TRACE_CHALLENGE_LABELS_V1: [[&[u8]; P256_CROSS_TRACE_CHALLENGE_TERMS_V1];
    P256_CROSS_TRACE_LANES_V1] = [
    [
        b"zk-x509-p256-cross-trace-lane0-beta-v1",
        b"zk-x509-p256-cross-trace-lane0-endpoint-v1",
        b"zk-x509-p256-cross-trace-lane0-address-v1",
        b"zk-x509-p256-cross-trace-lane0-value-v1",
    ],
    [
        b"zk-x509-p256-cross-trace-lane1-beta-v1",
        b"zk-x509-p256-cross-trace-lane1-endpoint-v1",
        b"zk-x509-p256-cross-trace-lane1-address-v1",
        b"zk-x509-p256-cross-trace-lane1-value-v1",
    ],
    [
        b"zk-x509-p256-cross-trace-lane2-beta-v1",
        b"zk-x509-p256-cross-trace-lane2-endpoint-v1",
        b"zk-x509-p256-cross-trace-lane2-address-v1",
        b"zk-x509-p256-cross-trace-lane2-value-v1",
    ],
    [
        b"zk-x509-p256-cross-trace-lane3-beta-v1",
        b"zk-x509-p256-cross-trace-lane3-endpoint-v1",
        b"zk-x509-p256-cross-trace-lane3-address-v1",
        b"zk-x509-p256-cross-trace-lane3-value-v1",
    ],
];
/// Maximum ordinary source/sink events consumed by one physical row.
pub const P256_CROSS_TRACE_EVENT_SLOTS_V1: usize = 6;
/// Powers `L^(2^0)` through `L^(2^7)` used by writer multiplicities.
pub const P256_CROSS_TRACE_WRITER_POWERS_V1: usize = 8;
/// Cross-product auxiliary columns added to a value-bus execution trace.
pub const P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1: usize = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1
    * (1 + P256_CROSS_TRACE_LANES_V1 * (P256_CROSS_TRACE_WRITER_POWERS_V1 + 2))
    + P256_CROSS_TRACE_LANES_V1;
/// Cross-product auxiliary columns added to a binder sink trace.
pub const P256_CROSS_TRACE_SINK_AUX_WIDTH_V1: usize = P256_CROSS_TRACE_EVENT_SLOTS_V1
    + P256_CROSS_TRACE_LANES_V1 * (P256_CROSS_TRACE_EVENT_SLOTS_V1 + 2);
/// Required cross-product auxiliary columns for the vertically packed window adapter.
pub const P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1: usize = 3 + P256_CROSS_TRACE_LANES_V1 * 5;
/// Required cross-product auxiliary columns for each reduction instance.
pub const P256_CROSS_TRACE_REDUCTION_AUX_WIDTH_V1: usize = 2 + P256_CROSS_TRACE_LANES_V1 * 4;
/// Required cross-product auxiliary columns for the wallet low-s instance.
pub const P256_CROSS_TRACE_LOW_S_AUX_WIDTH_V1: usize = 1 + P256_CROSS_TRACE_LANES_V1 * 3;
/// Active vertically packed rows for all 128 window selectors.
pub const P256_CROSS_TRACE_WINDOW_ACTIVE_ROWS_V1: usize = 128 * 512;
/// Native size of the value-bus writer source.
pub const P256_CROSS_TRACE_WRITER_TRACE_SIZE_V1: usize = 1 << 19;
/// Native size of the vertically packed/padded window source adapter.
pub const P256_CROSS_TRACE_WINDOW_TRACE_SIZE_V1: usize = 1 << 16;
/// Native size of the three-binding sink adapter.
pub const P256_CROSS_TRACE_SINK_TRACE_SIZE_V1: usize = 1 << 16;
/// Native size of each reduction source adapter.
pub const P256_CROSS_TRACE_REDUCTION_TRACE_SIZE_V1: usize = 1 << 5;
/// Native size of the wallet low-s source adapter.
pub const P256_CROSS_TRACE_LOW_S_TRACE_SIZE_V1: usize = 1 << 5;
/// Maximum total degree of the writer multiplicity evaluator.
pub const P256_CROSS_TRACE_MAX_CONSTRAINT_DEGREE_V1: u8 = 3;
/// Exact residue count for one writer-source opening.
pub const P256_CROSS_TRACE_WRITER_CONSTRAINT_COUNT_V1: usize =
    P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1
        + P256_CROSS_TRACE_LANES_V1 * (10 * P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + 3);
/// Exact residue count for one six-event binder-sink opening.
pub const P256_CROSS_TRACE_SINK_CONSTRAINT_COUNT_V1: usize = P256_CROSS_TRACE_EVENT_SLOTS_V1
    + P256_CROSS_TRACE_LANES_V1 * (P256_CROSS_TRACE_EVENT_SLOTS_V1 + 4)
    + 4 * P256_EXTERNAL_BINDINGS_PER_ROW_V1;
const P256_CROSS_TRACE_INITIAL_VALUES_V1: usize = 850;
const P256_CROSS_TRACE_ARITHMETIC_OPERATIONS_V1: usize = 14_828;
const P256_CROSS_TRACE_EQUALITIES_V1: usize = 5;
const P256_CROSS_TRACE_VALUE_BUS_SEGMENTS_V1: usize =
    P256_CROSS_TRACE_ARITHMETIC_OPERATIONS_V1 + P256_CROSS_TRACE_EQUALITIES_V1;
const P256_CROSS_TRACE_VALUE_BUS_ACTIVE_ROWS_V1: usize =
    P256_CROSS_TRACE_VALUE_BUS_SEGMENTS_V1 * P256_VALUE_BUS_SEGMENT_ROWS_V1;
const P256_CROSS_TRACE_VALUE_BUS_PACKED_ACTIVE_ROWS_V1: usize =
    P256_CROSS_TRACE_VALUE_BUS_ACTIVE_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
/// Sole padded native size of the cross-bound value-bus execution trace.
pub const P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1: usize = P256_CROSS_TRACE_WRITER_TRACE_SIZE_V1;
const P256_CROSS_TRACE_VALUE_CELLS_V1: usize = (P256_CROSS_TRACE_INITIAL_VALUES_V1
    + P256_CROSS_TRACE_ARITHMETIC_OPERATIONS_V1)
    * P256_VALUE_BUS_LIMBS_V1;
const P256_CROSS_TRACE_CERTIFICATE_WRITER_SOURCE_CELLS_V1: usize = 14_240;
const P256_CROSS_TRACE_WALLET_WRITER_SOURCE_CELLS_V1: usize = 14_240;
#[cfg(test)]
const P256_CROSS_TRACE_CERTIFICATE_EVENTS_V1: usize = 216_384;
#[cfg(test)]
const P256_CROSS_TRACE_WALLET_EVENTS_V1: usize = 216_416;
const P256_CROSS_TRACE_MAX_WRITER_MULTIPLICITY_V1: u16 = 129;
const _: () = assert!(P256_CROSS_TRACE_VALUE_BUS_ACTIVE_ROWS_V1 == 949_312);
const _: () = assert!(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 == 2);
const _: () = assert!(P256_CROSS_TRACE_VALUE_BUS_PACKED_ACTIVE_ROWS_V1 == 474_656);
const _: () = assert!(
    P256_CROSS_TRACE_VALUE_BUS_PACKED_ACTIVE_ROWS_V1 < P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1
);
const _: () = assert!(P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1.is_power_of_two());
const _: () = assert!(P256_CROSS_TRACE_SINK_TRACE_SIZE_V1.is_power_of_two());
const _: () = assert!(P256_CROSS_TRACE_WINDOW_ACTIVE_ROWS_V1 == 65_536);
const _: () =
    assert!(P256_CROSS_TRACE_WINDOW_ACTIVE_ROWS_V1 == P256_CROSS_TRACE_WINDOW_TRACE_SIZE_V1);
const _: () = assert!(P256_CROSS_TRACE_REDUCTION_TRACE_SIZE_V1 >= 16);
const _: () = assert!(P256_CROSS_TRACE_LOW_S_TRACE_SIZE_V1 >= 16);
const _: () = assert!(P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1 == 86);
const _: () = assert!(P256_CROSS_TRACE_WRITER_CONSTRAINT_COUNT_V1 == 94);
const _: () = assert!(P256_CROSS_TRACE_SINK_AUX_WIDTH_V1 == 38);
const _: () = assert!(P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1 == 23);
const _: () = assert!(P256_CROSS_TRACE_REDUCTION_AUX_WIDTH_V1 == 18);
const _: () = assert!(P256_CROSS_TRACE_LOW_S_AUX_WIDTH_V1 == 13);
const _: () = assert!(P256_CROSS_TRACE_MAX_CONSTRAINT_DEGREE_V1 == 3);
/// Cross-trace endpoint domain included in every active factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256CrossTraceEndpointV1 {
    /// Canonical value-bus writer.
    Writer,
    /// Window, reduction, result-x, or low-s source cell.
    External,
    /// Unreduced digest input limb from the actual digest-reduction WORD column.
    DigestInput,
    /// Arithmetic `c`-bit endpoint reserved for scalar-bit source binding.
    #[cfg(test)]
    ScalarArithmetic,
    /// Canonical per-window bit endpoint reserved for scalar-bit source binding.
    #[cfg(test)]
    ScalarWindow,
}
impl P256CrossTraceEndpointV1 {
    const fn field(self) -> F {
        match self {
            Self::Writer => F(1),
            Self::External => F(2),
            Self::DigestInput => F(5),
            #[cfg(test)]
            Self::ScalarArithmetic => F(3),
            #[cfg(test)]
            Self::ScalarWindow => F(4),
        }
    }
}
/// One verifier-fixed tagged source identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceTagV1 {
    /// Writer or external endpoint domain.
    pub(crate) endpoint: P256CrossTraceEndpointV1,
    /// Injective address inside that endpoint domain.
    pub(crate) address: u32,
}
/// Numeric verifier preprocessing for one optional product factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceEventFixedV1<A = F> {
    /// One for an active event and zero for identity padding.
    pub(crate) active: A,
    /// Active-coded endpoint domain.
    pub(crate) endpoint: A,
    /// Active-coded canonical address.
    pub(crate) address: A,
}
impl P256CrossTraceEventFixedV1 {
    pub(crate) const fn inactive() -> Self {
        Self {
            active: F::ZERO,
            endpoint: F::ZERO,
            address: F::ZERO,
        }
    }
    pub(crate) fn active(tag: P256CrossTraceTagV1) -> Self {
        Self {
            active: F::ONE,
            endpoint: tag.endpoint.field(),
            address: F(u64::from(tag.address)),
        }
    }
}
/// Numeric first/last/continuation selectors for one native segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceBoundaryFixedV1<A = F> {
    /// One only on the first native row.
    pub(crate) first: A,
    /// One only on the final native row.
    pub(crate) last: A,
    /// One on every row except the final native row.
    pub(crate) continuation: A,
}
impl P256CrossTraceBoundaryFixedV1 {
    pub(crate) fn for_row(index: usize, rows: usize) -> Result<Self, P256CrossTraceBusErrorV1> {
        if rows == 0 || !rows.is_power_of_two() || index >= rows {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
        Ok(Self {
            first: F(u64::from(index == 0)),
            last: F(u64::from(index + 1 == rows)),
            continuation: F(u64::from(index + 1 < rows)),
        })
    }
}
/// One tuple-compression lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceLaneChallengesV1 {
    /// `beta`, endpoint, address, and value coefficients.
    pub(crate) terms: [F; P256_CROSS_TRACE_CHALLENGE_TERMS_V1],
}
/// Four independent post-base-commitment tuple products.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceChallengesV1 {
    /// Independently sampled lanes.
    pub(crate) lanes: [P256CrossTraceLaneChallengesV1; P256_CROSS_TRACE_LANES_V1],
}
impl P256CrossTraceChallengesV1 {
    /// Reject zero, noncanonical, or repeated challenge coordinates.
    pub(crate) fn validate(self) -> Result<(), P256CrossTraceBusErrorV1> {
        let mut seen = [F::ZERO; P256_CROSS_TRACE_LANES_V1 * P256_CROSS_TRACE_CHALLENGE_TERMS_V1];
        for (seen_len, term) in self
            .lanes
            .iter()
            .flat_map(|lane| lane.terms.iter())
            .enumerate()
        {
            if *term == F::ZERO || F::canonical(term.0).is_none() || seen[..seen_len].contains(term)
            {
                return Err(P256CrossTraceBusErrorV1::Challenge);
            }
            seen[seen_len] = *term;
        }
        Ok(())
    }
}
/// Derive all cross-trace challenges only after every source and sink base
/// commitment has entered the transcript.
pub fn derive_zk_x509_p256_cross_trace_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<P256CrossTraceChallengesV1, TransparentStarkErrorV1> {
    let mut lanes = [P256CrossTraceLaneChallengesV1 {
        terms: [F::ZERO; P256_CROSS_TRACE_CHALLENGE_TERMS_V1],
    }; P256_CROSS_TRACE_LANES_V1];
    for (lane, labels) in lanes.iter_mut().zip(P256_CROSS_TRACE_CHALLENGE_LABELS_V1) {
        for (term, label) in lane.terms.iter_mut().zip(labels) {
            *term = transcript.challenge_field(label)?;
        }
    }
    Ok(P256CrossTraceChallengesV1 { lanes })
}
/// Cross-source topology, challenge, product, or resource failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum P256CrossTraceBusErrorV1 {
    /// A fixed address, role, row order, count, or boundary is wrong.
    #[error("zk-X509 P-256 cross-trace topology is invalid")]
    Topology,
    /// A source row is not the verifier-selected committed cell.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 cross-trace source is invalid")]
    Source,
    /// A multiplicity is unsupported, missing, duplicated, or inconsistent.
    #[error("zk-X509 P-256 cross-trace multiplicity is invalid")]
    Multiplicity,
    /// Challenges are zero, noncanonical, or repeated across lanes.
    #[error("zk-X509 P-256 cross-trace challenges are invalid")]
    Challenge,
    /// A product, addition chain, boundary, or terminal constraint failed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 cross-trace constraint failed")]
    Constraint,
    /// A bounded allocation or checked index exceeded the release envelope.
    #[error("zk-X509 P-256 cross-trace resource bound is exceeded")]
    Resource,
}
impl From<P256ExternalBindingErrorV1> for P256CrossTraceBusErrorV1 {
    fn from(error: P256ExternalBindingErrorV1) -> Self {
        match error {
            P256ExternalBindingErrorV1::Resource => Self::Resource,
            _ => Self::Topology,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl From<P256ValueBusErrorV1> for P256CrossTraceBusErrorV1 {
    fn from(error: P256ValueBusErrorV1) -> Self {
        match error {
            P256ValueBusErrorV1::Resource => Self::Resource,
            _ => Self::Source,
        }
    }
}
/// Numeric fixed row for an ordinary segment with up to six active events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceRegularFixedRowV1 {
    /// Ordered factor identities; inactive entries contribute one.
    pub(crate) events: [P256CrossTraceEventFixedV1; P256_CROSS_TRACE_EVENT_SLOTS_V1],
    /// Exact native segment boundaries.
    pub(crate) boundary: P256CrossTraceBoundaryFixedV1,
}
/// Challenge-dependent row for an ordinary product segment.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceRegularAuxRowV1 {
    /// Active-gated copies of actual committed source cells.
    pub(crate) event_values: [F; P256_CROSS_TRACE_EVENT_SLOTS_V1],
    /// Product before the row followed by all six factor transitions.
    pub(crate) products: [[F; P256_CROSS_TRACE_EVENT_SLOTS_V1 + 1]; P256_CROSS_TRACE_LANES_V1],
    /// Segment terminal repeated as a degree-zero column.
    pub(crate) terminal: [F; P256_CROSS_TRACE_LANES_V1],
}
/// Test-only materialization of one ordinary source/sink product segment.
///
/// `source_values` must be the actual cells from the committed base rows that share this segment's
/// native layout. Inactive event slots are algebraically gated to zero and contribute the product
/// identity. Production adapters should call [`build_regular_row_v1`] while streaming directly into
/// their commitment/LDE pipeline instead of retaining a million-row `Vec`.
#[cfg(test)]
pub fn build_zk_x509_p256_cross_trace_regular_aux_v1(
    fixed: &[P256CrossTraceRegularFixedRowV1],
    source_values: &[[F; P256_CROSS_TRACE_EVENT_SLOTS_V1]],
    start: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<P256CrossTraceRegularAuxRowV1>, P256CrossTraceBusErrorV1> {
    challenges.validate()?;
    validate_regular_fixed_v1(fixed)?;
    if fixed.len() != source_values.len()
        || start.iter().any(|value| F::canonical(value.0).is_none())
    {
        return Err(P256CrossTraceBusErrorV1::Topology);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(fixed.len())
        .map_err(|_| P256CrossTraceBusErrorV1::Resource)?;
    let mut running = start;
    for (fixed, source_values) in fixed.iter().zip(source_values) {
        let row = build_regular_row_v1(*fixed, *source_values, running, challenges);
        running = core::array::from_fn(|lane| row.products[lane][P256_CROSS_TRACE_EVENT_SLOTS_V1]);
        rows.push(row);
    }
    for row in &mut rows {
        row.terminal = running;
    }
    validate_regular_aux_v1(fixed, source_values, &rows, start, challenges)?;
    Ok(rows)
}
/// Build one deterministic ordinary auxiliary row for a streaming consumer.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_regular_row_v1(
    fixed: P256CrossTraceRegularFixedRowV1,
    source_values: [F; P256_CROSS_TRACE_EVENT_SLOTS_V1],
    product_before: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
) -> P256CrossTraceRegularAuxRowV1 {
    let event_values =
        core::array::from_fn(|slot| fixed.events[slot].active.mul(source_values[slot]));
    let mut products = [[F::ZERO; P256_CROSS_TRACE_EVENT_SLOTS_V1 + 1]; P256_CROSS_TRACE_LANES_V1];
    if fixed.events.iter().all(|event| event.active == F::ZERO) {
        for lane in 0..P256_CROSS_TRACE_LANES_V1 {
            products[lane].fill(product_before[lane]);
        }
        return P256CrossTraceRegularAuxRowV1 {
            event_values,
            products,
            terminal: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
        };
    }
    for lane in 0..P256_CROSS_TRACE_LANES_V1 {
        products[lane][0] = product_before[lane];
        for slot in 0..P256_CROSS_TRACE_EVENT_SLOTS_V1 {
            products[lane][slot + 1] = products[lane][slot].mul(compress_event_v1(
                fixed.events[slot],
                event_values[slot],
                challenges.lanes[lane],
            ));
        }
    }
    P256CrossTraceRegularAuxRowV1 {
        event_values,
        products,
        terminal: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
    }
}
/// Pure degree-two residues for one ordinary product row.
#[cfg(test)]
pub fn evaluate_zk_x509_p256_cross_trace_regular_row_constraints_v1(
    fixed: P256CrossTraceRegularFixedRowV1,
    source_values: [F; P256_CROSS_TRACE_EVENT_SLOTS_V1],
    current: &P256CrossTraceRegularAuxRowV1,
    next: &P256CrossTraceRegularAuxRowV1,
    start: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Vec<F> {
    let mut residues = Vec::with_capacity(
        P256_CROSS_TRACE_EVENT_SLOTS_V1
            + P256_CROSS_TRACE_LANES_V1 * (P256_CROSS_TRACE_EVENT_SLOTS_V1 + 4),
    );
    for (slot, source_value) in source_values.into_iter().enumerate() {
        residues.push(current.event_values[slot].sub(fixed.events[slot].active.mul(source_value)));
    }
    for (lane, start) in start.into_iter().enumerate() {
        residues.push(
            fixed
                .boundary
                .first
                .mul(current.products[lane][0].sub(start)),
        );
        for slot in 0..P256_CROSS_TRACE_EVENT_SLOTS_V1 {
            let factor = compress_event_v1(
                fixed.events[slot],
                current.event_values[slot],
                challenges.lanes[lane],
            );
            residues.push(
                current.products[lane][slot + 1].sub(current.products[lane][slot].mul(factor)),
            );
        }
        let after = current.products[lane][P256_CROSS_TRACE_EVENT_SLOTS_V1];
        residues.push(
            fixed
                .boundary
                .continuation
                .mul(next.products[lane][0].sub(after)),
        );
        residues.push(fixed.boundary.last.mul(current.terminal[lane].sub(after)));
        residues.push(next.terminal[lane].sub(current.terminal[lane]));
    }
    residues
}
#[cfg(test)]
fn validate_regular_aux_v1(
    fixed: &[P256CrossTraceRegularFixedRowV1],
    source_values: &[[F; P256_CROSS_TRACE_EVENT_SLOTS_V1]],
    rows: &[P256CrossTraceRegularAuxRowV1],
    start: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<(), P256CrossTraceBusErrorV1> {
    if rows.len() != fixed.len() || source_values.len() != fixed.len() {
        return Err(P256CrossTraceBusErrorV1::Topology);
    }
    for index in 0..rows.len() {
        let next = (index + 1) % rows.len();
        let residues = evaluate_zk_x509_p256_cross_trace_regular_row_constraints_v1(
            fixed[index],
            source_values[index],
            &rows[index],
            &rows[next],
            start,
            challenges,
        );
        if residues.iter().any(|residue| *residue != F::ZERO) {
            return Err(P256CrossTraceBusErrorV1::Constraint);
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_regular_fixed_v1(
    fixed: &[P256CrossTraceRegularFixedRowV1],
) -> Result<(), P256CrossTraceBusErrorV1> {
    if fixed.is_empty() || !fixed.len().is_power_of_two() {
        return Err(P256CrossTraceBusErrorV1::Topology);
    }
    for (index, row) in fixed.iter().enumerate() {
        if row.boundary != P256CrossTraceBoundaryFixedV1::for_row(index, fixed.len())?
            || row.events.iter().any(|event| {
                !matches!(event.active, F::ZERO | F::ONE)
                    || (event.active == F::ZERO
                        && (event.endpoint != F::ZERO || event.address != F::ZERO))
                    || (event.active == F::ONE && !matches!(event.endpoint, F(1..=5)))
            })
        {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
    }
    Ok(())
}
/// Fixed local and product schedule for one three-binding sink row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceSinkFixedRowV1 {
    /// Active binding selectors.
    pub(crate) active: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    /// Direct-constant selectors.
    pub(crate) constant: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    /// Compiler-owned expected constant limbs.
    pub(crate) constant_value: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    /// Interleaved writer/external product events.
    pub(crate) product: P256CrossTraceRegularFixedRowV1,
}
/// Compact verifier-owned sink schedule.
///
/// Only logical binding rows are retained. Native-domain padding and boundary selectors are
/// regenerated on demand, avoiding a wide fixed-table allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256CrossTraceSinkFixedV1 {
    logical: Vec<[Option<P256ExternalBindingCrossSourceV1>; P256_EXTERNAL_BINDINGS_PER_ROW_V1]>,
}
impl P256CrossTraceSinkFixedV1 {
    /// Allocated compact verifier schedule payload.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        super::allocation_payload::vector_v1(&self.logical)
    }
    /// Compile the sole role-derived schedule without consulting a witness,
    /// proof, or prover-supplied metadata.
    pub(crate) fn compile_v1(role: P256EcdsaRoleV1) -> Result<Self, P256CrossTraceBusErrorV1> {
        let logical = compile_zk_x509_p256_external_cross_sources_v1(role)?;
        if logical.len() != p256_external_binding_rows_v1(role)
            || logical.len() >= P256_INPUT_SELECTION_ROW_START_V1
        {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
        let writer_events = logical
            .iter()
            .flatten()
            .filter(|source| source.is_some())
            .count();
        let external_events = logical
            .iter()
            .flatten()
            .filter_map(|source| source.as_ref())
            .filter(|source| {
                matches!(
                    source.external,
                    P256ExternalBindingCrossExternalSourceV1::Dynamic { .. }
                )
            })
            .count();
        if writer_events != p256_external_binding_active_equalities_v1(role)
            || external_events != p256_external_binding_dynamic_sources_v1(role)
        {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
        Ok(Self { logical })
    }
    /// Regenerate one exact fixed row, including canonical inactive padding.
    pub(crate) fn row_v1(
        &self,
        row: usize,
    ) -> Result<P256CrossTraceSinkFixedRowV1, P256CrossTraceBusErrorV1> {
        if row >= P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
        let slots = self
            .logical
            .get(row)
            .copied()
            .unwrap_or([None; P256_EXTERNAL_BINDINGS_PER_ROW_V1]);
        let mut active = [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1];
        let mut constant = [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1];
        let mut constant_value = [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1];
        let mut events = [P256CrossTraceEventFixedV1::inactive(); P256_CROSS_TRACE_EVENT_SLOTS_V1];
        for (slot, source) in slots.into_iter().enumerate() {
            let Some(source) = source else {
                continue;
            };
            active[slot] = F::ONE;
            let writer_address = writer_address_v1(source.writer_id.0, source.writer_limb)?;
            events[2 * slot] = P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                endpoint: P256CrossTraceEndpointV1::Writer,
                address: writer_address,
            });
            match source.external {
                P256ExternalBindingCrossExternalSourceV1::Dynamic { address } => {
                    events[2 * slot + 1] =
                        P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                            endpoint: P256CrossTraceEndpointV1::External,
                            address,
                        });
                }
                P256ExternalBindingCrossExternalSourceV1::Constant { value } => {
                    constant[slot] = F::ONE;
                    constant_value[slot] = value;
                }
            }
        }
        // Every old equality event is retained. The separate byte region reuses
        // event zero only where all three legacy writer/external pairs are zero.
        if (P256_INPUT_SELECTION_ROW_START_V1..P256_INPUT_SELECTION_SELECTOR_ROW_V1).contains(&row)
        {
            let byte = row - P256_INPUT_SELECTION_ROW_START_V1;
            if byte.is_multiple_of(2) {
                let limb = 15 - (byte % 32) / 2;
                let tag = match p256_selected_input_writer_id_v1(byte / 32)? {
                    Some(id) => P256CrossTraceTagV1 {
                        endpoint: P256CrossTraceEndpointV1::Writer,
                        address: writer_address_v1(id.0, limb as u8)?,
                    },
                    None => P256CrossTraceTagV1 {
                        endpoint: P256CrossTraceEndpointV1::DigestInput,
                        address: limb as u32,
                    },
                };
                events[0] = P256CrossTraceEventFixedV1::active(tag);
            }
        }
        Ok(P256CrossTraceSinkFixedRowV1 {
            active,
            constant,
            constant_value,
            product: P256CrossTraceRegularFixedRowV1 {
                events,
                boundary: P256CrossTraceBoundaryFixedV1::for_row(
                    row,
                    P256_CROSS_TRACE_SINK_TRACE_SIZE_V1,
                )?,
            },
        })
    }
    /// Logical non-padding row count.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn logical_rows_v1(&self) -> usize {
        self.logical.len()
    }
}
/// Compile the compact role-derived sink schedule.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn compile_zk_x509_p256_cross_trace_sink_fixed_v1(
    role: P256EcdsaRoleV1,
) -> Result<P256CrossTraceSinkFixedV1, P256CrossTraceBusErrorV1> {
    P256CrossTraceSinkFixedV1::compile_v1(role)
}
/// Constant-memory deterministic provider for the minimal padded sink domain.
///
/// Construction makes one compact logical-row pass to validate local equalities and compute the
/// terminal. Consumers then pull the exact padded row sequence in a second pass. No million-row
/// auxiliary or fixed `Vec` is retained.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256CrossTraceSinkStreamV1<'a> {
    binding: &'a P256ExternalBindingTraceV1,
    fixed: Arc<P256CrossTraceSinkFixedV1>,
    challenges: P256CrossTraceChallengesV1,
    terminal: [F; P256_CROSS_TRACE_LANES_V1],
    running: [F; P256_CROSS_TRACE_LANES_V1],
    next_row: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256CrossTraceSinkStreamV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256CrossTraceSinkStreamV1 { <private stream redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256CrossTraceSinkStreamV1<'_> {
    fn drop(&mut self) {
        super::private_table::zeroize_fields_v1(&mut self.running);
        super::private_table::zeroize_fields_v1(&mut self.terminal);
        for lane in &mut self.challenges.lanes {
            super::private_table::zeroize_fields_v1(&mut lane.terms);
        }
    }
}

/// Prepare the binder sink stream from the binder's committed base copies.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_p256_cross_trace_sink_v1(
    binding: &P256ExternalBindingTraceV1,
    challenges: P256CrossTraceChallengesV1,
) -> Result<P256CrossTraceSinkStreamV1<'_>, P256CrossTraceBusErrorV1> {
    challenges.validate()?;
    validate_binding_fixed_schedule_v1(binding)?;
    let fixed = Arc::new(compile_zk_x509_p256_cross_trace_sink_fixed_v1(
        binding.role,
    )?);
    let terminal = compute_sink_terminal_v1(&fixed, binding, challenges)?;
    Ok(P256CrossTraceSinkStreamV1 {
        binding,
        fixed,
        challenges,
        terminal,
        running: [F::ONE; P256_CROSS_TRACE_LANES_V1],
        next_row: 0,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compute_sink_terminal_v1(
    fixed: &P256CrossTraceSinkFixedV1,
    binding: &P256ExternalBindingTraceV1,
    challenges: P256CrossTraceChallengesV1,
) -> Result<[F; P256_CROSS_TRACE_LANES_V1], P256CrossTraceBusErrorV1> {
    let mut running = [F::ONE; P256_CROSS_TRACE_LANES_V1];
    for row in (0..fixed.logical_rows_v1())
        .chain(P256_INPUT_SELECTION_ROW_START_V1..P256_INPUT_SELECTION_SELECTOR_ROW_V1)
    {
        let fixed_row = fixed.row_v1(row)?;
        let binding_row = sink_binding_row_v1(binding, row);
        if evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(fixed_row, &binding_row)
            .into_iter()
            .any(|residue| residue != F::ZERO)
        {
            return Err(P256CrossTraceBusErrorV1::Constraint);
        }
        let aux_row = build_regular_row_v1(
            fixed_row.product,
            sink_stream_source_values_v1(binding, row)?,
            running,
            challenges,
        );
        running =
            core::array::from_fn(|lane| aux_row.products[lane][P256_CROSS_TRACE_EVENT_SLOTS_V1]);
    }
    Ok(running)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256CrossTraceSinkStreamV1<'a> {
    /// Restart deterministic row replay without recompiling the schedule or
    /// recomputing the terminal.
    pub(crate) fn replay_v1(&self) -> P256CrossTraceSinkStreamV1<'a> {
        P256CrossTraceSinkStreamV1 {
            binding: self.binding,
            fixed: Arc::clone(&self.fixed),
            challenges: self.challenges,
            terminal: self.terminal,
            running: [F::ONE; P256_CROSS_TRACE_LANES_V1],
            next_row: 0,
        }
    }
    /// Emit the next exact auxiliary row, including canonical padding.
    pub(crate) fn next_row_v1(
        &mut self,
    ) -> Result<Option<P256CrossTraceRegularAuxRowV1>, P256CrossTraceBusErrorV1> {
        if self.next_row == P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 {
            return Ok(None);
        }
        let fixed = self.fixed.row_v1(self.next_row)?;
        let mut row = build_regular_row_v1(
            fixed.product,
            sink_stream_source_values_v1(self.binding, self.next_row)?,
            self.running,
            self.challenges,
        );
        self.running =
            core::array::from_fn(|lane| row.products[lane][P256_CROSS_TRACE_EVENT_SLOTS_V1]);
        row.terminal = self.terminal;
        self.next_row += 1;
        if self.next_row == P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 && self.running != self.terminal {
            return Err(P256CrossTraceBusErrorV1::Constraint);
        }
        Ok(Some(row))
    }
    /// Exact fixed row corresponding to one streamed ordinal.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<P256CrossTraceSinkFixedRowV1, P256CrossTraceBusErrorV1> {
        self.fixed.row_v1(row)
    }
    /// Verifier-fixed role.
    #[cfg(test)]
    pub(crate) fn role_v1(&self) -> P256EcdsaRoleV1 {
        self.binding.role
    }
    /// Number of rows not yet emitted.
    #[cfg(test)]
    pub(crate) const fn remaining_rows_v1(&self) -> usize {
        P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 - self.next_row
    }
    /// Constant sink product terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.terminal
    }
}
/// Pure sink residues over actual committed binder base cells.
#[cfg(test)]
pub fn evaluate_zk_x509_p256_cross_trace_sink_row_constraints_v1(
    fixed: P256CrossTraceSinkFixedRowV1,
    binding: &P256ExternalBindingRowV1,
    current: &P256CrossTraceRegularAuxRowV1,
    next: &P256CrossTraceRegularAuxRowV1,
    challenges: P256CrossTraceChallengesV1,
) -> Vec<F> {
    let sources = sink_source_values_v1(binding);
    let mut residues = evaluate_zk_x509_p256_cross_trace_regular_row_constraints_v1(
        fixed.product,
        sources,
        current,
        next,
        [F::ONE; P256_CROSS_TRACE_LANES_V1],
        challenges,
    );
    residues.extend(evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(
        fixed, binding,
    ));
    residues
}
/// Pure pointwise sink residues over the three committed writer/external
/// equality pairs. Keeping these separate makes the local binding surface
/// independently testable without allocating the complete sink product.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(
    fixed: P256CrossTraceSinkFixedRowV1,
    binding: &P256ExternalBindingRowV1,
) -> [F; 4 * P256_EXTERNAL_BINDINGS_PER_ROW_V1] {
    let mut residues = [F::ZERO; 4 * P256_EXTERNAL_BINDINGS_PER_ROW_V1];
    for slot in 0..P256_EXTERNAL_BINDINGS_PER_ROW_V1 {
        let inactive = F::ONE.sub(fixed.active[slot]);
        let offset = 4 * slot;
        residues[offset] =
            fixed.active[slot].mul(binding.writer_cells[slot].sub(binding.external_cells[slot]));
        residues[offset + 1] = inactive.mul(binding.writer_cells[slot]);
        residues[offset + 2] = inactive.mul(binding.external_cells[slot]);
        residues[offset + 3] =
            fixed.constant[slot].mul(binding.external_cells[slot].sub(fixed.constant_value[slot]));
    }
    residues
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn sink_source_values_v1(
    binding: &P256ExternalBindingRowV1,
) -> [F; P256_CROSS_TRACE_EVENT_SLOTS_V1] {
    core::array::from_fn(|event| {
        let slot = event / 2;
        if event.is_multiple_of(2) {
            binding.writer_cells[slot]
        } else {
            binding.external_cells[slot]
        }
    })
}
/// Native replay of the same affine source used at F/Fp4 openings. Inactive
/// neighboring-byte values are zero; no witness-selected event or address exists.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn sink_stream_source_values_v1(
    binding: &P256ExternalBindingTraceV1,
    row: usize,
) -> Result<[F; P256_CROSS_TRACE_EVENT_SLOTS_V1], P256CrossTraceBusErrorV1> {
    let mut sources = sink_source_values_v1(&sink_binding_row_v1(binding, row));
    for (position, weight) in [(row, 256_u64), (row + 1, 1_u64)] {
        if (P256_INPUT_SELECTION_ROW_START_V1..P256_INPUT_SELECTION_SELECTOR_ROW_V1)
            .contains(&position)
        {
            let value = p256_input_selection_byte_v1(
                &binding.input_selection.selected,
                position - P256_INPUT_SELECTION_ROW_START_V1,
            )?;
            sources[0] = sources[0].add(F(weight * u64::from(value)));
        }
    }
    Ok(sources)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn sink_binding_row_v1(
    binding: &P256ExternalBindingTraceV1,
    row: usize,
) -> P256ExternalBindingRowV1 {
    binding
        .rows
        .get(row)
        .copied()
        .unwrap_or(P256ExternalBindingRowV1 {
            fixed: [P256ExternalBindingFixedAccessV1::Inactive; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
            writer_cells: [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
            external_cells: [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
        })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_binding_fixed_schedule_v1(
    binding: &P256ExternalBindingTraceV1,
) -> Result<(), P256CrossTraceBusErrorV1> {
    let expected = compile_zk_x509_p256_external_cross_sources_v1(binding.role)?;
    if binding.rows.len() != expected.len()
        || binding.rows.iter().zip(expected).any(|(row, expected)| {
            row.fixed
                != core::array::from_fn(|slot| {
                    expected[slot]
                        .map(|source| source.fixed)
                        .unwrap_or(P256ExternalBindingFixedAccessV1::Inactive)
                })
        })
    {
        return Err(P256CrossTraceBusErrorV1::Topology);
    }
    Ok(())
}
/// Verifier-fixed writer multiplicity selectors at one flattened value-bus source row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceWriterFixedRowV1<A = F> {
    /// Two writer factors, each independently identity-padded.
    pub(crate) events: [P256CrossTraceEventFixedV1<A>; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Small multiplicity code: zero, one, or two on native rows; polynomial at OOD points.
    pub(crate) multiplicity_small: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Multiplicity 64 selector.
    pub(crate) multiplicity_64: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Multiplicity 65 selector.
    pub(crate) multiplicity_65: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Multiplicity 129 selector.
    pub(crate) multiplicity_129: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Exact global value-bus boundaries.
    pub(crate) boundary: P256CrossTraceBoundaryFixedV1<A>,
}
/// Compact verifier-owned writer-source schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256CrossTraceWriterSourceFixedV1 {
    multiplicities: Vec<u16>,
}
/// One challenge-dependent writer-source row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256CrossTraceWriterAuxRowV1<A = F> {
    /// Active-gated copy of the actual value-bus writer cell.
    pub(crate) event_values: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// `L^(2^0)` through `L^(2^7)` in each lane.
    pub(crate) powers: [[[A; P256_CROSS_TRACE_WRITER_POWERS_V1]; P256_CROSS_TRACE_LANES_V1];
        P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Verifier-selected `L^m`.
    pub(crate) selected_power:
        [[A; P256_CROSS_TRACE_LANES_V1]; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Product entering each factor slot.
    pub(crate) product_before:
        [[A; P256_CROSS_TRACE_LANES_V1]; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    /// Source terminal repeated as a degree-zero column.
    pub(crate) terminal: [A; P256_CROSS_TRACE_LANES_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::Zeroize for P256CrossTraceWriterAuxRowV1 {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.event_values);
        zeroize::Zeroize::zeroize(&mut self.powers);
        zeroize::Zeroize::zeroize(&mut self.selected_power);
        zeroize::Zeroize::zeroize(&mut self.product_before);
        zeroize::Zeroize::zeroize(&mut self.terminal);
    }
}
/// Either an independently compiled oracle schedule or the exact retained
/// verifier schedule borrowed through the immutable MAIN bound capability.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone)]
enum P256CrossTraceWriterFixedReplayV1<'a> {
    Compiled(Arc<P256CrossTraceWriterSourceFixedV1>),
    Bound(&'a P256CrossTraceWriterSourceFixedV1),
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256CrossTraceWriterFixedReplayV1<'_> {
    fn source_v1(&self) -> &P256CrossTraceWriterSourceFixedV1 {
        match self {
            Self::Compiled(source) => source,
            Self::Bound(source) => source,
        }
    }
}
/// Constant-memory deterministic provider for the `2^19` writer-source auxiliary rows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256CrossTraceWriterSourceStreamV1<'a> {
    value_bus: &'a P256ValueBusBaseEndpointTraceV1,
    fixed: P256CrossTraceWriterFixedReplayV1<'a>,
    challenges: P256CrossTraceChallengesV1,
    terminal: [F; P256_CROSS_TRACE_LANES_V1],
    running: [F; P256_CROSS_TRACE_LANES_V1],
    next_row: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256CrossTraceWriterSourceStreamV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256CrossTraceWriterSourceStreamV1 { <private stream redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256CrossTraceWriterSourceStreamV1<'_> {
    fn drop(&mut self) {
        super::private_table::zeroize_fields_v1(&mut self.running);
        super::private_table::zeroize_fields_v1(&mut self.terminal);
        for lane in &mut self.challenges.lanes {
            super::private_table::zeroize_fields_v1(&mut lane.terms);
        }
    }
}

impl P256CrossTraceWriterSourceFixedV1 {
    /// Allocated compact verifier schedule payload.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        super::allocation_payload::vector_v1(&self.multiplicities)
    }
    /// Compile exact writer multiplicities from the verifier-only binding schedule.
    pub(crate) fn compile_v1(role: P256EcdsaRoleV1) -> Result<Self, P256CrossTraceBusErrorV1> {
        let rows = compile_zk_x509_p256_external_cross_sources_v1(role)?;
        let mut multiplicities = vec![0_u16; P256_CROSS_TRACE_VALUE_CELLS_V1];
        let mut uses = 0_usize;
        for source in rows.into_iter().flatten().flatten() {
            let address =
                usize::try_from(writer_address_v1(source.writer_id.0, source.writer_limb)?)
                    .map_err(|_| P256CrossTraceBusErrorV1::Resource)?;
            let multiplicity = multiplicities
                .get_mut(address)
                .ok_or(P256CrossTraceBusErrorV1::Topology)?;
            *multiplicity = multiplicity
                .checked_add(1)
                .ok_or(P256CrossTraceBusErrorV1::Multiplicity)?;
            uses = uses
                .checked_add(1)
                .ok_or(P256CrossTraceBusErrorV1::Resource)?;
        }
        for word in 0..4 {
            let id = p256_selected_input_writer_id_v1(word)?
                .ok_or(P256CrossTraceBusErrorV1::Topology)?;
            for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
                let address = writer_address_v1(id.0, limb as u8)? as usize;
                let multiplicity = multiplicities
                    .get_mut(address)
                    .ok_or(P256CrossTraceBusErrorV1::Topology)?;
                *multiplicity = multiplicity
                    .checked_add(1)
                    .ok_or(P256CrossTraceBusErrorV1::Multiplicity)?;
                uses = uses
                    .checked_add(1)
                    .ok_or(P256CrossTraceBusErrorV1::Resource)?;
            }
        }
        let active = multiplicities
            .iter()
            .filter(|multiplicity| **multiplicity != 0)
            .count();
        let expected_active = match role {
            P256EcdsaRoleV1::CertificateOrCrl => {
                P256_CROSS_TRACE_CERTIFICATE_WRITER_SOURCE_CELLS_V1
            }
            P256EcdsaRoleV1::WalletOwnership => P256_CROSS_TRACE_WALLET_WRITER_SOURCE_CELLS_V1,
        };
        if uses != p256_external_binding_active_equalities_v1(role) + 4 * P256_VALUE_BUS_LIMBS_V1
            || active != expected_active
            || multiplicities
                .iter()
                .any(|multiplicity| !matches!(*multiplicity, 0 | 1 | 2 | 64 | 65 | 129))
            || multiplicities.iter().copied().max()
                != Some(P256_CROSS_TRACE_MAX_WRITER_MULTIPLICITY_V1)
        {
            return Err(P256CrossTraceBusErrorV1::Multiplicity);
        }
        Ok(Self { multiplicities })
    }
    /// Verifier-preprocessed row at one two-factor-packed value-bus ordinal.
    pub(crate) fn row_v1(
        &self,
        packed_ordinal: usize,
    ) -> Result<P256CrossTraceWriterFixedRowV1, P256CrossTraceBusErrorV1> {
        if packed_ordinal >= P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1 {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
        let boundary = P256CrossTraceBoundaryFixedV1::for_row(
            packed_ordinal,
            P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1,
        )?;
        let mut events =
            [P256CrossTraceEventFixedV1::inactive(); P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
        let mut multiplicities = [0_u16; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
        for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let ordinal = packed_ordinal
                .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
                .and_then(|ordinal| ordinal.checked_add(slot))
                .ok_or(P256CrossTraceBusErrorV1::Resource)?;
            let writer = writer_cell_at_execution_ordinal_v1(ordinal)?;
            let (event, multiplicity) = if let Some((id, limb)) = writer {
                let address = writer_address_v1(id, limb)?;
                let multiplicity = *self
                    .multiplicities
                    .get(usize::try_from(address).map_err(|_| P256CrossTraceBusErrorV1::Resource)?)
                    .ok_or(P256CrossTraceBusErrorV1::Topology)?;
                if !matches!(multiplicity, 0 | 1 | 2 | 64 | 65 | 129) {
                    return Err(P256CrossTraceBusErrorV1::Multiplicity);
                }
                if multiplicity == 0 {
                    (P256CrossTraceEventFixedV1::inactive(), 0)
                } else {
                    (
                        P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                            endpoint: P256CrossTraceEndpointV1::Writer,
                            address,
                        }),
                        multiplicity,
                    )
                }
            } else {
                (P256CrossTraceEventFixedV1::inactive(), 0)
            };
            events[slot] = event;
            multiplicities[slot] = multiplicity;
        }
        Ok(P256CrossTraceWriterFixedRowV1 {
            events,
            multiplicity_small: multiplicities.map(|m| F(u64::from(if m <= 2 { m } else { 0 }))),
            multiplicity_64: multiplicities.map(|multiplicity| F(u64::from(multiplicity == 64))),
            multiplicity_65: multiplicities.map(|multiplicity| F(u64::from(multiplicity == 65))),
            multiplicity_129: multiplicities.map(|multiplicity| F(u64::from(multiplicity == 129))),
            boundary,
        })
    }
    /// Number of distinct writer cells consumed by the sink.
    #[cfg(test)]
    pub(crate) fn active_source_cells_v1(&self) -> usize {
        self.multiplicities
            .iter()
            .filter(|multiplicity| **multiplicity != 0)
            .count()
    }
    /// Writer-use count including exact multiplicities.
    #[cfg(test)]
    pub(crate) fn total_uses_v1(&self) -> usize {
        self.multiplicities
            .iter()
            .map(|multiplicity| usize::from(*multiplicity))
            .sum()
    }
}
/// Prepare a streamed value-writer source product directly from committed execution values.
///
/// A first pass validates every selected source and computes the terminal. The
/// returned provider then regenerates all `2^20` rows sequentially without
/// retaining the roughly 272 MiB row-major auxiliary trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_p256_cross_trace_writer_source_v1(
    value_bus: &P256ValueBusBaseEndpointTraceV1,
    role: P256EcdsaRoleV1,
    challenges: P256CrossTraceChallengesV1,
) -> Result<P256CrossTraceWriterSourceStreamV1<'_>, P256CrossTraceBusErrorV1> {
    challenges.validate()?;
    let segment_count = value_bus.segment_count_v1().map_err(|error| match error {
        P256ValueBusErrorV1::Resource => P256CrossTraceBusErrorV1::Resource,
        _ => P256CrossTraceBusErrorV1::Topology,
    })?;
    if segment_count != P256_CROSS_TRACE_VALUE_BUS_SEGMENTS_V1 {
        return Err(P256CrossTraceBusErrorV1::Topology);
    }
    let fixed = Arc::new(P256CrossTraceWriterSourceFixedV1::compile_v1(role)?);
    let terminal = compute_writer_terminal_v1(value_bus, &fixed, challenges)?;
    Ok(P256CrossTraceWriterSourceStreamV1 {
        value_bus,
        fixed: P256CrossTraceWriterFixedReplayV1::Compiled(fixed),
        challenges,
        terminal,
        running: [F::ONE; P256_CROSS_TRACE_LANES_V1],
        next_row: 0,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compute_writer_terminal_v1(
    value_bus: &P256ValueBusBaseEndpointTraceV1,
    fixed: &P256CrossTraceWriterSourceFixedV1,
    challenges: P256CrossTraceChallengesV1,
) -> Result<[F; P256_CROSS_TRACE_LANES_V1], P256CrossTraceBusErrorV1> {
    let mut running = [F::ONE; P256_CROSS_TRACE_LANES_V1];
    for packed_ordinal in 0..P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1 {
        let fixed_row = fixed.row_v1(packed_ordinal)?;
        let sources = projected_writer_source_values_v1(value_bus, packed_ordinal, fixed_row)?;
        let row = build_writer_row_v1(fixed_row, sources, running, challenges);
        let final_slot = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1;
        running = core::array::from_fn(|lane| {
            row.product_before[final_slot][lane].mul(row.selected_power[final_slot][lane])
        });
    }
    Ok(running)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256CrossTraceWriterSourceStreamV1<'a> {
    /// Borrow the exact schedule and terminal already checked during MAIN bind.
    /// The capability has no public/raw constructor and fixes the endpoint,
    /// signature role, opaque token and derived terminal to the same owner.
    pub(super) fn from_bound_main_v1(
        bound: super::p256_aggregate_adapter::P256MainBoundWriterReplayV1<'a>,
    ) -> Result<Self, P256CrossTraceBusErrorV1> {
        let value_bus = bound.endpoint_v1();
        let challenges = bound.challenges_v1();
        challenges.validate()?;
        let segment_count = value_bus.segment_count_v1().map_err(|error| match error {
            P256ValueBusErrorV1::Resource => P256CrossTraceBusErrorV1::Resource,
            _ => P256CrossTraceBusErrorV1::Topology,
        })?;
        if segment_count != P256_CROSS_TRACE_VALUE_BUS_SEGMENTS_V1 {
            return Err(P256CrossTraceBusErrorV1::Topology);
        }
        Ok(Self {
            value_bus,
            fixed: P256CrossTraceWriterFixedReplayV1::Bound(bound.fixed_v1()),
            challenges,
            terminal: bound.terminal_v1(),
            running: [F::ONE; P256_CROSS_TRACE_LANES_V1],
            next_row: 0,
        })
    }
    /// Restart deterministic row replay without recompiling multiplicities or
    /// recomputing the terminal.
    pub(crate) fn replay_v1(&self) -> P256CrossTraceWriterSourceStreamV1<'a> {
        P256CrossTraceWriterSourceStreamV1 {
            value_bus: self.value_bus,
            fixed: self.fixed.clone(),
            challenges: self.challenges,
            terminal: self.terminal,
            running: [F::ONE; P256_CROSS_TRACE_LANES_V1],
            next_row: 0,
        }
    }
    /// Emit the next exact source-product row, including canonical padding.
    pub(crate) fn next_row_v1(
        &mut self,
    ) -> Result<Option<P256CrossTraceWriterAuxRowV1>, P256CrossTraceBusErrorV1> {
        if self.next_row == P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1 {
            return Ok(None);
        }
        let fixed = self.fixed.source_v1().row_v1(self.next_row)?;
        let sources = projected_writer_source_values_v1(self.value_bus, self.next_row, fixed)?;
        let mut row = zeroize::Zeroizing::new(build_writer_row_v1(
            fixed,
            sources,
            self.running,
            self.challenges,
        ));
        let final_slot = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1;
        self.running = core::array::from_fn(|lane| {
            row.product_before[final_slot][lane].mul(row.selected_power[final_slot][lane])
        });
        row.terminal = self.terminal;
        self.next_row += 1;
        if self.next_row == P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1
            && self.running != self.terminal
        {
            return Err(P256CrossTraceBusErrorV1::Constraint);
        }
        Ok(Some(*row))
    }
    /// Constant writer-source product terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.terminal
    }
}
/// Pure degree-three writer-source residues over the actual committed value-bus source cell.
pub fn evaluate_zk_x509_p256_cross_trace_writer_row_constraints_v1<A: PolynomialAirFieldV1>(
    fixed: P256CrossTraceWriterFixedRowV1<A>,
    source_values: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    current: &P256CrossTraceWriterAuxRowV1<A>,
    next: &P256CrossTraceWriterAuxRowV1<A>,
    challenges: P256CrossTraceChallengesV1,
) -> Vec<A> {
    let mut residues = Vec::with_capacity(P256_CROSS_TRACE_WRITER_CONSTRAINT_COUNT_V1);
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        residues.push(
            current.event_values[slot].sub(fixed.events[slot].active.mul(source_values[slot])),
        );
    }
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        for lane in 0..P256_CROSS_TRACE_LANES_V1 {
            let factor = compress_event_v1(
                fixed.events[slot],
                current.event_values[slot],
                challenges.lanes[lane],
            );
            residues.push(current.powers[slot][lane][0].sub(factor));
            for power in 1..P256_CROSS_TRACE_WRITER_POWERS_V1 {
                residues.push(
                    current.powers[slot][lane][power].sub(
                        current.powers[slot][lane][power - 1]
                            .mul(current.powers[slot][lane][power - 1]),
                    ),
                );
            }
            let expected_selected = A::ONE
                .sub(fixed.events[slot].active)
                // This cubic expression is bound to a separate committed selected_power.
                // The running recurrence below multiplies that cell, never this expression.
                .add(
                    fixed.multiplicity_small[slot]
                        .mul(A::ONE.add(A::ONE).sub(fixed.multiplicity_small[slot]))
                        .mul(current.powers[slot][lane][0]),
                )
                .add(
                    fixed.multiplicity_small[slot]
                        .mul(fixed.multiplicity_small[slot].sub(A::ONE))
                        .mul_base(F(0x7fff_ffff_8000_0001))
                        .mul(current.powers[slot][lane][1]),
                )
                .add(fixed.multiplicity_64[slot].mul(current.powers[slot][lane][6]))
                .add(
                    fixed.multiplicity_65[slot]
                        .mul(current.powers[slot][lane][6])
                        .mul(current.powers[slot][lane][0]),
                )
                .add(
                    fixed.multiplicity_129[slot]
                        .mul(current.powers[slot][lane][7])
                        .mul(current.powers[slot][lane][0]),
                );
            residues.push(current.selected_power[slot][lane].sub(expected_selected));
        }
    }
    for lane in 0..P256_CROSS_TRACE_LANES_V1 {
        residues.push(
            fixed
                .boundary
                .first
                .mul(current.product_before[0][lane].sub(A::ONE)),
        );
        for slot in 1..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let previous_after =
                current.product_before[slot - 1][lane].mul(current.selected_power[slot - 1][lane]);
            residues.push(current.product_before[slot][lane].sub(previous_after));
        }
        let final_slot = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1;
        let after =
            current.product_before[final_slot][lane].mul(current.selected_power[final_slot][lane]);
        residues.push(
            fixed
                .boundary
                .continuation
                .mul(next.product_before[0][lane].sub(after)),
        );
        residues.push(fixed.boundary.last.mul(current.terminal[lane].sub(after)));
        residues.push(next.terminal[lane].sub(current.terminal[lane]));
    }
    residues
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_writer_row_v1(
    fixed: P256CrossTraceWriterFixedRowV1,
    source_values: [F; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    product_before: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
) -> P256CrossTraceWriterAuxRowV1 {
    let event_values =
        core::array::from_fn(|slot| fixed.events[slot].active.mul(source_values[slot]));
    let mut powers = [[[F::ONE; P256_CROSS_TRACE_WRITER_POWERS_V1]; P256_CROSS_TRACE_LANES_V1];
        P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
    let mut selected_power =
        [[F::ONE; P256_CROSS_TRACE_LANES_V1]; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
    let mut product_states =
        [[F::ONE; P256_CROSS_TRACE_LANES_V1]; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
    let mut running = product_before;
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        product_states[slot] = running;
        // The complete inactive tuple is verifier-owned public schedule data.
        // Its compression and all powers are one, so the product carries exactly.
        // Keep unusual fixed tuples on the direct path rather than assuming that
        // an inactive flag alone proves the remaining selectors are canonical.
        if fixed.events[slot] == P256CrossTraceEventFixedV1::inactive()
            && fixed.multiplicity_small[slot] == F::ZERO
            && fixed.multiplicity_64[slot] == F::ZERO
            && fixed.multiplicity_65[slot] == F::ZERO
            && fixed.multiplicity_129[slot] == F::ZERO
        {
            continue;
        }
        for lane in 0..P256_CROSS_TRACE_LANES_V1 {
            powers[slot][lane][0] = compress_event_v1(
                fixed.events[slot],
                event_values[slot],
                challenges.lanes[lane],
            );
            for power in 1..P256_CROSS_TRACE_WRITER_POWERS_V1 {
                powers[slot][lane][power] =
                    powers[slot][lane][power - 1].mul(powers[slot][lane][power - 1]);
            }
            selected_power[slot][lane] = F::ONE
                .sub(fixed.events[slot].active)
                // This cubic expression is bound to a separate committed selected_power.
                // The running recurrence below multiplies that cell, never this expression.
                .add(
                    fixed.multiplicity_small[slot]
                        .mul(F::ONE.add(F::ONE).sub(fixed.multiplicity_small[slot]))
                        .mul(powers[slot][lane][0]),
                )
                .add(
                    fixed.multiplicity_small[slot]
                        .mul(fixed.multiplicity_small[slot].sub(F::ONE))
                        .mul_base(F(0x7fff_ffff_8000_0001))
                        .mul(powers[slot][lane][1]),
                )
                .add(fixed.multiplicity_64[slot].mul(powers[slot][lane][6]))
                .add(
                    fixed.multiplicity_65[slot]
                        .mul(powers[slot][lane][6])
                        .mul(powers[slot][lane][0]),
                )
                .add(
                    fixed.multiplicity_129[slot]
                        .mul(powers[slot][lane][7])
                        .mul(powers[slot][lane][0]),
                );
            running[lane] = running[lane].mul(selected_power[slot][lane]);
        }
    }
    P256CrossTraceWriterAuxRowV1 {
        event_values,
        powers,
        selected_power,
        product_before: product_states,
        terminal: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
    }
}
/// Four final residues equating the fully chained source product to the independent sink product.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1(
    final_source: [F; P256_CROSS_TRACE_LANES_V1],
    sink: [F; P256_CROSS_TRACE_LANES_V1],
) -> [F; P256_CROSS_TRACE_LANES_V1] {
    core::array::from_fn(|lane| final_source[lane].sub(sink[lane]))
}
fn writer_cell_at_execution_ordinal_v1(
    ordinal: usize,
) -> Result<Option<(u32, u8)>, P256CrossTraceBusErrorV1> {
    if ordinal >= P256_CROSS_TRACE_VALUE_BUS_ACTIVE_ROWS_V1 {
        return Ok(None);
    }
    let segment = ordinal / P256_VALUE_BUS_SEGMENT_ROWS_V1;
    let local = ordinal % P256_VALUE_BUS_SEGMENT_ROWS_V1;
    if segment >= P256_CROSS_TRACE_ARITHMETIC_OPERATIONS_V1 {
        return Ok(None);
    }
    if local < 3 * P256_VALUE_BUS_LIMBS_V1 && local % 3 == 2 {
        let id = P256_CROSS_TRACE_INITIAL_VALUES_V1
            .checked_add(segment)
            .ok_or(P256CrossTraceBusErrorV1::Resource)?;
        return Ok(Some((
            u32::try_from(id).map_err(|_| P256CrossTraceBusErrorV1::Resource)?,
            u8::try_from(local / 3).map_err(|_| P256CrossTraceBusErrorV1::Resource)?,
        )));
    }
    if segment < P256_CROSS_TRACE_INITIAL_VALUES_V1
        && (3 * P256_VALUE_BUS_LIMBS_V1..3 * P256_VALUE_BUS_LIMBS_V1 + P256_VALUE_BUS_LIMBS_V1)
            .contains(&local)
    {
        return Ok(Some((
            u32::try_from(segment).map_err(|_| P256CrossTraceBusErrorV1::Resource)?,
            u8::try_from(local - 3 * P256_VALUE_BUS_LIMBS_V1)
                .map_err(|_| P256CrossTraceBusErrorV1::Resource)?,
        )));
    }
    Ok(None)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn projected_writer_source_values_v1(
    value_bus: &P256ValueBusBaseEndpointTraceV1,
    packed_ordinal: usize,
    fixed: P256CrossTraceWriterFixedRowV1,
) -> Result<[F; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1], P256CrossTraceBusErrorV1> {
    let mut values = [F::ZERO; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let ordinal = packed_ordinal
            .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
            .and_then(|ordinal| ordinal.checked_add(slot))
            .ok_or(P256CrossTraceBusErrorV1::Resource)?;
        if ordinal >= P256_CROSS_TRACE_VALUE_BUS_ACTIVE_ROWS_V1 {
            continue;
        }
        let (actual_fixed, value) =
            p256_value_bus_base_execution_source_cell_v1(value_bus, ordinal)?;
        if fixed.events[slot].active == F::ONE {
            let address = u32::try_from(fixed.events[slot].address.0)
                .map_err(|_| P256CrossTraceBusErrorV1::Resource)?;
            let expected_id = address / P256_VALUE_BUS_LIMBS_V1 as u32;
            let expected_limb = (address % P256_VALUE_BUS_LIMBS_V1 as u32) as u8;
            if !matches!(
                actual_fixed,
                P256ValueBusFixedAccessV1::Active {
                    id,
                    limb,
                    access: P256ValueAccessKindV1::Write,
                    ..
                } if id.0 == expected_id && limb == expected_limb
            ) {
                return Err(P256CrossTraceBusErrorV1::Source);
            }
        }
        values[slot] = value;
    }
    Ok(values)
}
fn writer_address_v1(id: u32, limb: u8) -> Result<u32, P256CrossTraceBusErrorV1> {
    if usize::from(limb) >= P256_VALUE_BUS_LIMBS_V1 {
        return Err(P256CrossTraceBusErrorV1::Topology);
    }
    id.checked_mul(P256_VALUE_BUS_LIMBS_V1 as u32)
        .and_then(|address| address.checked_add(u32::from(limb)))
        .ok_or(P256CrossTraceBusErrorV1::Resource)
}
fn compress_event_v1<A: PolynomialAirFieldV1>(
    fixed: P256CrossTraceEventFixedV1<A>,
    event_value: A,
    challenges: P256CrossTraceLaneChallengesV1,
) -> A {
    A::ONE
        .sub(fixed.active)
        .add(fixed.active.mul_base(challenges.terms[0]))
        .add(fixed.endpoint.mul_base(challenges.terms[1]))
        .add(fixed.address.mul_base(challenges.terms[2]))
        .add(event_value.mul_base(challenges.terms[3]))
}
/// Exact maximum tagged-event count used in the four-lane soundness bound.
#[cfg(test)]
pub const fn p256_cross_trace_events_v1(role: P256EcdsaRoleV1) -> usize {
    match role {
        P256EcdsaRoleV1::CertificateOrCrl => P256_CROSS_TRACE_CERTIFICATE_EVENTS_V1,
        P256EcdsaRoleV1::WalletOwnership => P256_CROSS_TRACE_WALLET_EVENTS_V1,
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_cross_stream_erasure_clears_live_products_and_redacts_debug() {
        use super::super::private_table::inspection::observe_v1;
        let fixture = wallet_sink_fixture_v1();
        let mut sink =
            build_zk_x509_p256_cross_trace_sink_v1(&fixture.binding, challenges_v1()).unwrap();
        sink.next_row_v1().unwrap().unwrap();
        let endpoint = P256ValueBusBaseEndpointTraceV1 {
            endpoint: super::super::p256_value_bus::P256ValueBusEndpointV1::Execution,
            rows: Vec::new(),
        };
        let writer = P256CrossTraceWriterSourceStreamV1 {
            value_bus: &endpoint,
            fixed: P256CrossTraceWriterFixedReplayV1::Compiled(Arc::new(
                P256CrossTraceWriterSourceFixedV1 {
                    multiplicities: Vec::new(),
                },
            )),
            challenges: challenges_v1(),
            terminal: [F(17); P256_CROSS_TRACE_LANES_V1],
            running: [F(19); P256_CROSS_TRACE_LANES_V1],
            next_row: 7,
        };
        assert_eq!(
            format!("{sink:?}"),
            "P256CrossTraceSinkStreamV1 { <private stream redacted> }"
        );
        assert_eq!(
            format!("{writer:?}"),
            "P256CrossTraceWriterSourceStreamV1 { <private stream redacted> }"
        );
        let ((), observed) = observe_v1(|| {
            drop(sink);
            drop(writer);
        });
        assert!(
            observed
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>()
                >= 4 * P256_CROSS_TRACE_LANES_V1
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    use super::*;
    use crate::privacy_engines::zk_x509::{
        p256_air::ZkX509P256ModulusV1,
        p256_ecdsa_air::P256EcdsaWitnessV1,
        p256_external_binding_air::{
            P256ExternalReductionV1, P256InverseAuxiliaryManifestV1,
            P256OptionalCertificateSelectionV1, P256UnresolvedByteIoEndpointV1,
            P256UnresolvedByteIoKindV1, P256UnresolvedByteIoManifestV1,
            P256UnresolvedByteIoSourceV1,
        },
        p256_value_bus::{
            P256ValueBusBaseCellV1, P256ValueBusBaseEndpointTraceV1, P256ValueBusEndpointV1,
            P256ValueBusFixedAccessV1, P256ValueIdV1,
        },
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::OnceLock,
    };
    fn challenges_v1() -> P256CrossTraceChallengesV1 {
        P256CrossTraceChallengesV1 {
            lanes: core::array::from_fn(|lane| P256CrossTraceLaneChallengesV1 {
                terms: core::array::from_fn(|term| F(101 + (lane * 31 + term * 7) as u64)),
            }),
        }
    }
    fn byte_io_manifest_v1() -> P256UnresolvedByteIoManifestV1 {
        P256UnresolvedByteIoManifestV1 {
            endpoints: [
                P256UnresolvedByteIoEndpointV1 {
                    kind: P256UnresolvedByteIoKindV1::PublicKeyX,
                    source: P256UnresolvedByteIoSourceV1::ValueWriter {
                        id: P256ValueIdV1(47),
                        modulus: ZkX509P256ModulusV1::BaseField,
                    },
                },
                P256UnresolvedByteIoEndpointV1 {
                    kind: P256UnresolvedByteIoKindV1::PublicKeyY,
                    source: P256UnresolvedByteIoSourceV1::ValueWriter {
                        id: P256ValueIdV1(48),
                        modulus: ZkX509P256ModulusV1::BaseField,
                    },
                },
                P256UnresolvedByteIoEndpointV1 {
                    kind: P256UnresolvedByteIoKindV1::SignatureR,
                    source: P256UnresolvedByteIoSourceV1::ValueWriter {
                        id: P256ValueIdV1(52),
                        modulus: ZkX509P256ModulusV1::ScalarField,
                    },
                },
                P256UnresolvedByteIoEndpointV1 {
                    kind: P256UnresolvedByteIoKindV1::SignatureS,
                    source: P256UnresolvedByteIoSourceV1::ValueWriter {
                        id: P256ValueIdV1(53),
                        modulus: ZkX509P256ModulusV1::ScalarField,
                    },
                },
                P256UnresolvedByteIoEndpointV1 {
                    kind: P256UnresolvedByteIoKindV1::DigestWord,
                    source: P256UnresolvedByteIoSourceV1::ReductionWord {
                        reduction: P256ExternalReductionV1::Digest,
                    },
                },
            ],
        }
    }
    fn synthetic_binding_v1(role: P256EcdsaRoleV1) -> P256ExternalBindingTraceV1 {
        let sources = compile_zk_x509_p256_external_cross_sources_v1(role).expect("fixed sources");
        let mut writer_values = BTreeMap::<u32, F>::new();
        for source in sources.iter().flatten().flatten() {
            if let P256ExternalBindingCrossExternalSourceV1::Constant { value } = source.external {
                let address =
                    writer_address_v1(source.writer_id.0, source.writer_limb).expect("writer");
                assert!(writer_values.insert(address, value).is_none());
            }
        }
        for source in sources.iter().flatten().flatten() {
            let address =
                writer_address_v1(source.writer_id.0, source.writer_limb).expect("writer");
            writer_values.entry(address).or_insert_with(|| {
                F((u64::from(address).wrapping_mul(73).wrapping_add(19)) & u64::from(u16::MAX))
            });
        }
        let selected_word = |id: u32| {
            let mut bytes = [0_u8; 32];
            for limb in 0..16 {
                let address = writer_address_v1(id, limb as u8).unwrap();
                let value = writer_values
                    .get(&address)
                    .copied()
                    .unwrap_or(F(
                        (u64::from(address).wrapping_mul(73).wrapping_add(19)) & 65535
                    ));
                bytes[30 - 2 * limb..32 - 2 * limb]
                    .copy_from_slice(&(value.0 as u16).to_be_bytes());
            }
            bytes
        };
        let selected = P256EcdsaWitnessV1 {
            public_key_x_be: selected_word(47),
            public_key_y_be: selected_word(48),
            r_be: selected_word(52),
            s_be: selected_word(53),
            digest_be: core::array::from_fn(|i| (i * 7 + 3) as u8),
        };
        let rows = sources
            .into_iter()
            .map(|sources| {
                let mut fixed =
                    [P256ExternalBindingFixedAccessV1::Inactive; P256_EXTERNAL_BINDINGS_PER_ROW_V1];
                let mut writer_cells = [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1];
                let mut external_cells = [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1];
                for (slot, source) in sources.into_iter().enumerate() {
                    let Some(source) = source else {
                        continue;
                    };
                    let address =
                        writer_address_v1(source.writer_id.0, source.writer_limb).expect("writer");
                    let value = writer_values[&address];
                    fixed[slot] = source.fixed;
                    writer_cells[slot] = value;
                    external_cells[slot] = value;
                }
                P256ExternalBindingRowV1 {
                    fixed,
                    writer_cells,
                    external_cells,
                }
            })
            .collect();
        P256ExternalBindingTraceV1 {
            role,
            rows,
            byte_io: byte_io_manifest_v1(),
            input_selection: P256OptionalCertificateSelectionV1 {
                active: F::ONE,
                real: selected,
                selected,
            },
            inverse_auxiliaries: P256InverseAuxiliaryManifestV1 {
                r_inverse: P256ValueIdV1(54),
                s_inverse: P256ValueIdV1(56),
                result_z_inverse: P256ValueIdV1(847),
            },
        }
    }
    fn direct_source_terminal_v1(
        binding: &P256ExternalBindingTraceV1,
        challenges: P256CrossTraceChallengesV1,
    ) -> [F; P256_CROSS_TRACE_LANES_V1] {
        let sources =
            compile_zk_x509_p256_external_cross_sources_v1(binding.role).expect("sources");
        let mut writers = BTreeMap::<u32, (F, usize)>::new();
        let mut externals = Vec::<(u32, F)>::new();
        for ((sources, row), row_index) in sources.iter().zip(&binding.rows).zip(0_usize..) {
            let _ = row_index;
            for (slot, source) in sources.iter().copied().enumerate() {
                let Some(source) = source else {
                    continue;
                };
                let address =
                    writer_address_v1(source.writer_id.0, source.writer_limb).expect("writer");
                let value = row.writer_cells[slot];
                match writers.entry(address) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert((value, 1));
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        assert_eq!(entry.get().0, value);
                        entry.get_mut().1 += 1;
                    }
                }
                if let P256ExternalBindingCrossExternalSourceV1::Dynamic { address } =
                    source.external
                {
                    externals.push((address, row.external_cells[slot]));
                }
            }
        }
        let mut digest = Vec::new();
        for word in 0..5 {
            for limb in 0..16 {
                let byte = word * 32 + 30 - 2 * limb;
                let value = F(256
                    * u64::from(
                        p256_input_selection_byte_v1(&binding.input_selection.selected, byte)
                            .unwrap(),
                    )
                    + u64::from(
                        p256_input_selection_byte_v1(&binding.input_selection.selected, byte + 1)
                            .unwrap(),
                    ));
                if let Some(id) = p256_selected_input_writer_id_v1(word).unwrap() {
                    let address = writer_address_v1(id.0, limb as u8).unwrap();
                    let entry = writers.entry(address).or_insert((value, 0));
                    assert_eq!(entry.0, value);
                    entry.1 += 1;
                } else {
                    digest.push((limb as u32, value));
                }
            }
        }
        let mut terminal = [F::ONE; P256_CROSS_TRACE_LANES_V1];
        for (lane, terminal) in terminal.iter_mut().enumerate() {
            for (address, (value, multiplicity)) in &writers {
                let factor = compress_event_v1(
                    P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                        endpoint: P256CrossTraceEndpointV1::Writer,
                        address: *address,
                    }),
                    *value,
                    challenges.lanes[lane],
                );
                for _ in 0..*multiplicity {
                    *terminal = terminal.mul(factor);
                }
            }
            for &(address, value) in &digest {
                *terminal = terminal.mul(compress_event_v1(
                    P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                        endpoint: P256CrossTraceEndpointV1::DigestInput,
                        address,
                    }),
                    value,
                    challenges.lanes[lane],
                ));
            }
            for (address, value) in &externals {
                *terminal = terminal.mul(compress_event_v1(
                    P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                        endpoint: P256CrossTraceEndpointV1::External,
                        address: *address,
                    }),
                    *value,
                    challenges.lanes[lane],
                ));
            }
        }
        assert_eq!(
            writers.values().map(|(_, count)| *count).sum::<usize>()
                + externals.len()
                + digest.len(),
            p256_cross_trace_events_v1(binding.role)
        );
        terminal
    }
    fn direct_sink_terminal_v1(
        binding: &P256ExternalBindingTraceV1,
        challenges: P256CrossTraceChallengesV1,
    ) -> [F; P256_CROSS_TRACE_LANES_V1] {
        validate_binding_fixed_schedule_v1(binding).expect("binding schedule");
        let schedule =
            compile_zk_x509_p256_cross_trace_sink_fixed_v1(binding.role).expect("sink schedule");
        let mut terminal = [F::ONE; P256_CROSS_TRACE_LANES_V1];
        let mut events = 0_usize;
        for row in (0..schedule.logical_rows_v1())
            .chain(P256_INPUT_SELECTION_ROW_START_V1..P256_INPUT_SELECTION_SELECTOR_ROW_V1)
        {
            let fixed = schedule.row_v1(row).expect("fixed row");
            let values = sink_stream_source_values_v1(binding, row).unwrap();
            for (slot, value) in values.into_iter().enumerate() {
                if fixed.product.events[slot].active == F::ZERO {
                    continue;
                }
                events += 1;
                for (lane, terminal) in terminal.iter_mut().enumerate() {
                    *terminal = terminal.mul(compress_event_v1(
                        fixed.product.events[slot],
                        value,
                        challenges.lanes[lane],
                    ));
                }
            }
        }
        assert_eq!(events, p256_cross_trace_events_v1(binding.role));
        terminal
    }
    struct SinkFixtureV1 {
        binding: P256ExternalBindingTraceV1,
        fixed: P256CrossTraceSinkFixedV1,
        source_terminal: [F; P256_CROSS_TRACE_LANES_V1],
        sink_terminal: [F; P256_CROSS_TRACE_LANES_V1],
    }
    fn wallet_sink_fixture_v1() -> &'static SinkFixtureV1 {
        static FIXTURE: OnceLock<SinkFixtureV1> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let binding = synthetic_binding_v1(P256EcdsaRoleV1::WalletOwnership);
            let fixed =
                compile_zk_x509_p256_cross_trace_sink_fixed_v1(binding.role).expect("sink fixed");
            let source_terminal = direct_source_terminal_v1(&binding, challenges_v1());
            let sink_terminal = direct_sink_terminal_v1(&binding, challenges_v1());
            assert_eq!(
                evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1(
                    source_terminal,
                    sink_terminal,
                ),
                [F::ZERO; P256_CROSS_TRACE_LANES_V1]
            );
            SinkFixtureV1 {
                binding,
                fixed,
                source_terminal,
                sink_terminal,
            }
        })
    }
    fn sink_row_context_v1(
        fixture: &SinkFixtureV1,
        row: usize,
    ) -> (
        P256CrossTraceSinkFixedRowV1,
        P256ExternalBindingRowV1,
        P256CrossTraceRegularAuxRowV1,
        P256CrossTraceRegularAuxRowV1,
    ) {
        assert!(row == 0 || row + 1 == P256_CROSS_TRACE_SINK_TRACE_SIZE_V1);
        let fixed = fixture.fixed.row_v1(row).expect("fixed row");
        let binding = sink_binding_row_v1(&fixture.binding, row);
        let product_before = if row == 0 {
            [F::ONE; P256_CROSS_TRACE_LANES_V1]
        } else {
            fixture.sink_terminal
        };
        let mut current = build_regular_row_v1(
            fixed.product,
            sink_source_values_v1(&binding),
            product_before,
            challenges_v1(),
        );
        current.terminal = fixture.sink_terminal;
        let next_row = (row + 1) % P256_CROSS_TRACE_SINK_TRACE_SIZE_V1;
        let next_fixed = fixture.fixed.row_v1(next_row).expect("next fixed row");
        let next_binding = sink_binding_row_v1(&fixture.binding, next_row);
        let next_before = if row == 0 {
            core::array::from_fn(|lane| current.products[lane][P256_CROSS_TRACE_EVENT_SLOTS_V1])
        } else {
            [F::ONE; P256_CROSS_TRACE_LANES_V1]
        };
        let mut next = build_regular_row_v1(
            next_fixed.product,
            sink_source_values_v1(&next_binding),
            next_before,
            challenges_v1(),
        );
        next.terminal = fixture.sink_terminal;
        (fixed, binding, current, next)
    }
    fn regular_fixture_v1() -> (
        Vec<P256CrossTraceRegularFixedRowV1>,
        Vec<[F; P256_CROSS_TRACE_EVENT_SLOTS_V1]>,
        [F; P256_CROSS_TRACE_LANES_V1],
        Vec<P256CrossTraceRegularAuxRowV1>,
    ) {
        let rows = 8;
        let fixed = (0..rows)
            .map(|row| {
                let events = core::array::from_fn(|slot| {
                    if (row + 2 * slot).is_multiple_of(3) {
                        P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                            endpoint: match (row + slot) % 4 {
                                0 => P256CrossTraceEndpointV1::Writer,
                                1 => P256CrossTraceEndpointV1::External,
                                2 => P256CrossTraceEndpointV1::ScalarArithmetic,
                                _ => P256CrossTraceEndpointV1::ScalarWindow,
                            },
                            address: (row * P256_CROSS_TRACE_EVENT_SLOTS_V1 + slot) as u32,
                        })
                    } else {
                        P256CrossTraceEventFixedV1::inactive()
                    }
                });
                P256CrossTraceRegularFixedRowV1 {
                    events,
                    boundary: P256CrossTraceBoundaryFixedV1::for_row(row, rows).expect("boundary"),
                }
            })
            .collect::<Vec<_>>();
        let source = (0..rows)
            .map(|row| core::array::from_fn(|slot| F((17 * row + 11 * slot + 3) as u64)))
            .collect::<Vec<_>>();
        let start = [F(7), F(11), F(13), F(17)];
        let aux =
            build_zk_x509_p256_cross_trace_regular_aux_v1(&fixed, &source, start, challenges_v1())
                .expect("regular product");
        (fixed, source, start, aux)
    }
    fn regular_has_nonzero_v1(
        fixed: &[P256CrossTraceRegularFixedRowV1],
        source: &[[F; P256_CROSS_TRACE_EVENT_SLOTS_V1]],
        start: [F; P256_CROSS_TRACE_LANES_V1],
        aux: &[P256CrossTraceRegularAuxRowV1],
    ) -> bool {
        (0..aux.len()).any(|row| {
            evaluate_zk_x509_p256_cross_trace_regular_row_constraints_v1(
                fixed[row],
                source[row],
                &aux[row],
                &aux[(row + 1) % aux.len()],
                start,
                challenges_v1(),
            )
            .into_iter()
            .any(|residue| residue != F::ZERO)
        })
    }
    fn small_writer_fixture_v1() -> (
        Vec<P256CrossTraceWriterFixedRowV1>,
        Vec<[F; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1]>,
        Vec<P256CrossTraceWriterAuxRowV1>,
    ) {
        let multiplicities = [1_u16, 64, 65, 129, 0, 2, 64, 0];
        let rows = multiplicities.len() / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let fixed = (0..rows)
            .map(|row| {
                let multiplicity = core::array::from_fn(|slot| {
                    multiplicities[row * P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + slot]
                });
                P256CrossTraceWriterFixedRowV1 {
                    events: core::array::from_fn(|slot| {
                        if multiplicity[slot] == 0 {
                            P256CrossTraceEventFixedV1::inactive()
                        } else {
                            P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
                                endpoint: P256CrossTraceEndpointV1::Writer,
                                address: (row * P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + slot)
                                    as u32,
                            })
                        }
                    }),
                    multiplicity_small: multiplicity
                        .map(|m| F(u64::from(if m <= 2 { m } else { 0 }))),
                    multiplicity_64: multiplicity
                        .map(|multiplicity| F(u64::from(multiplicity == 64))),
                    multiplicity_65: multiplicity
                        .map(|multiplicity| F(u64::from(multiplicity == 65))),
                    multiplicity_129: multiplicity
                        .map(|multiplicity| F(u64::from(multiplicity == 129))),
                    boundary: P256CrossTraceBoundaryFixedV1::for_row(row, rows).expect("boundary"),
                }
            })
            .collect::<Vec<_>>();
        let source = (0..rows)
            .map(|row| {
                core::array::from_fn(|slot| {
                    F(((row * P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + slot) * 23 + 5) as u64)
                })
            })
            .collect::<Vec<_>>();
        let mut running = [F::ONE; P256_CROSS_TRACE_LANES_V1];
        let mut aux = fixed
            .iter()
            .copied()
            .zip(source.iter().copied())
            .map(|(fixed, source)| {
                let row = build_writer_row_v1(fixed, source, running, challenges_v1());
                let final_slot = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1;
                running = core::array::from_fn(|lane| {
                    row.product_before[final_slot][lane].mul(row.selected_power[final_slot][lane])
                });
                row
            })
            .collect::<Vec<_>>();
        for row in &mut aux {
            row.terminal = running;
        }
        (fixed, source, aux)
    }
    fn writer_has_nonzero_v1(
        fixed: &[P256CrossTraceWriterFixedRowV1],
        source: &[[F; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1]],
        aux: &[P256CrossTraceWriterAuxRowV1],
    ) -> bool {
        (0..aux.len()).any(|row| {
            evaluate_zk_x509_p256_cross_trace_writer_row_constraints_v1(
                fixed[row],
                source[row],
                &aux[row],
                &aux[(row + 1) % aux.len()],
                challenges_v1(),
            )
            .into_iter()
            .any(|residue| residue != F::ZERO)
        })
    }
    #[test]
    fn exact_role_schedules_counts_vertical_shapes_and_multiplicities() {
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let sources = compile_zk_x509_p256_external_cross_sources_v1(role).expect("sources");
            assert_eq!(sources.len(), p256_external_binding_rows_v1(role));
            assert_eq!(
                sources
                    .iter()
                    .flatten()
                    .filter(|slot| slot.is_some())
                    .count(),
                p256_external_binding_active_equalities_v1(role)
            );
            let dynamic = sources
                .iter()
                .flatten()
                .filter_map(|slot| slot.as_ref())
                .filter_map(|source| match source.external {
                    P256ExternalBindingCrossExternalSourceV1::Dynamic { address } => Some(address),
                    P256ExternalBindingCrossExternalSourceV1::Constant { .. } => None,
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(
                dynamic.len(),
                p256_external_binding_dynamic_sources_v1(role)
            );
            assert_eq!(dynamic.first().copied(), Some(0));
            assert_eq!(
                dynamic.last().copied(),
                Some((p256_external_binding_dynamic_sources_v1(role) - 1) as u32)
            );
            let sink = compile_zk_x509_p256_cross_trace_sink_fixed_v1(role).expect("sink");
            assert_eq!(sink.logical_rows_v1(), p256_external_binding_rows_v1(role));
            assert_eq!(
                sink.row_v1(0).expect("first row").product.boundary.first,
                F::ONE
            );
            assert_eq!(
                sink.row_v1(P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 - 1)
                    .expect("last row")
                    .product
                    .boundary
                    .last,
                F::ONE
            );
            let first_padding = sink
                .row_v1(p256_external_binding_rows_v1(role))
                .expect("first padding row");
            assert_eq!(
                first_padding.active,
                [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1]
            );
            assert_eq!(
                first_padding.constant,
                [F::ZERO; P256_EXTERNAL_BINDINGS_PER_ROW_V1]
            );
            assert_eq!(
                first_padding.product.events,
                [P256CrossTraceEventFixedV1::inactive(); P256_CROSS_TRACE_EVENT_SLOTS_V1]
            );
            assert_eq!(
                sink.row_v1(P256_CROSS_TRACE_SINK_TRACE_SIZE_V1),
                Err(P256CrossTraceBusErrorV1::Topology)
            );
            let writers = P256CrossTraceWriterSourceFixedV1::compile_v1(role).expect("writers");
            assert_eq!(
                writers.active_source_cells_v1(),
                match role {
                    P256EcdsaRoleV1::CertificateOrCrl => 14_240,
                    P256EcdsaRoleV1::WalletOwnership => 14_240,
                }
            );
            assert_eq!(
                writers.total_uses_v1(),
                p256_external_binding_active_equalities_v1(role) + 64
            );
            assert!(
                writers
                    .multiplicities
                    .iter()
                    .all(|multiplicity| matches!(*multiplicity, 0 | 1 | 2 | 64 | 65 | 129))
            );
            assert_eq!(writers.multiplicities[0], 129);
            assert_eq!(writers.multiplicities[P256_VALUE_BUS_LIMBS_V1], 65);
            assert_eq!(writers.multiplicities[47 * P256_VALUE_BUS_LIMBS_V1], 65);
            assert_eq!(
                writers.multiplicities[53 * P256_VALUE_BUS_LIMBS_V1],
                1 + usize::from(role == P256EcdsaRoleV1::WalletOwnership) as u16
            );
            assert_eq!(
                p256_cross_trace_events_v1(role),
                p256_external_binding_active_equalities_v1(role)
                    + p256_external_binding_dynamic_sources_v1(role)
                    + 80
            );
        }
        assert_eq!(P256_CROSS_TRACE_WINDOW_ACTIVE_ROWS_V1, 65_536);
        assert_eq!(P256_CROSS_TRACE_WRITER_TRACE_SIZE_V1, 524_288);
        assert_eq!(P256_CROSS_TRACE_WINDOW_TRACE_SIZE_V1, 65_536);
        assert_eq!(P256_CROSS_TRACE_SINK_TRACE_SIZE_V1, 65_536);
        assert_eq!(P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1, 524_288);
        assert_eq!(P256_CROSS_TRACE_REDUCTION_TRACE_SIZE_V1, 32);
        assert_eq!(P256_CROSS_TRACE_LOW_S_TRACE_SIZE_V1, 32);
        assert_eq!(P256_CROSS_TRACE_MAX_CONSTRAINT_DEGREE_V1, 3);
        assert_eq!(P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1 + 12, 98);
        assert_eq!(P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1 + 1, 24);
        assert_eq!(P256_CROSS_TRACE_REDUCTION_AUX_WIDTH_V1 + 1, 19);
        assert_eq!(P256_CROSS_TRACE_LOW_S_AUX_WIDTH_V1 + 1, 14);
    }
    #[test]
    fn sink_stream_emits_exact_minimal_domain_without_retaining_aux_rows() {
        let fixture = wallet_sink_fixture_v1();
        let mut stream = build_zk_x509_p256_cross_trace_sink_v1(&fixture.binding, challenges_v1())
            .expect("sink stream");
        assert_eq!(stream.role_v1(), P256EcdsaRoleV1::WalletOwnership);
        assert_eq!(stream.terminal_v1(), fixture.sink_terminal);
        assert_eq!(
            stream.remaining_rows_v1(),
            P256_CROSS_TRACE_SINK_TRACE_SIZE_V1
        );
        assert_eq!(
            stream.fixed.logical.len(),
            p256_external_binding_rows_v1(P256EcdsaRoleV1::WalletOwnership)
        );
        let (_, _, expected_first, _) = sink_row_context_v1(fixture, 0);
        assert_eq!(
            stream.next_row_v1().expect("first row"),
            Some(expected_first)
        );
        let mut last = expected_first;
        for ordinal in 1..P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 {
            let row = stream
                .next_row_v1()
                .expect("stream row")
                .expect("remaining row");
            if ordinal == fixture.fixed.logical_rows_v1() {
                assert_eq!(
                    stream
                        .fixed_row_v1(ordinal)
                        .expect("first padding")
                        .product
                        .events,
                    [P256CrossTraceEventFixedV1::inactive(); P256_CROSS_TRACE_EVENT_SLOTS_V1]
                );
                assert_eq!(row.event_values, [F::ZERO; P256_CROSS_TRACE_EVENT_SLOTS_V1]);
                for (lane, products) in row.products.iter().enumerate() {
                    assert!(
                        products.iter().all(|product| *product
                            == last.products[lane][P256_CROSS_TRACE_EVENT_SLOTS_V1])
                    );
                }
            }
            last = row;
        }
        assert_eq!(stream.remaining_rows_v1(), 0);
        assert_eq!(stream.next_row_v1().expect("exhausted stream"), None);
        assert_eq!(last.terminal, fixture.sink_terminal);
        for (lane, products) in last.products.iter().enumerate() {
            assert!(
                products
                    .iter()
                    .all(|product| *product == fixture.sink_terminal[lane])
            );
        }
    }
    #[test]
    fn writer_stream_rejects_short_and_unshaped_execution_sources_before_emission() {
        let empty = P256ValueBusBaseEndpointTraceV1 {
            endpoint: P256ValueBusEndpointV1::Execution,
            rows: Vec::new(),
        };
        assert!(matches!(
            build_zk_x509_p256_cross_trace_writer_source_v1(
                &empty,
                P256EcdsaRoleV1::WalletOwnership,
                challenges_v1(),
            ),
            Err(P256CrossTraceBusErrorV1::Topology)
        ));
        let unshaped = P256ValueBusBaseEndpointTraceV1 {
            endpoint: P256ValueBusEndpointV1::Execution,
            rows: vec![
                P256ValueBusBaseCellV1 {
                    fixed: P256ValueBusFixedAccessV1::Inactive,
                    value: F::ZERO,
                };
                P256_CROSS_TRACE_VALUE_BUS_SEGMENTS_V1 * P256_VALUE_BUS_SEGMENT_ROWS_V1
            ],
        };
        assert!(matches!(
            build_zk_x509_p256_cross_trace_writer_source_v1(
                &unshaped,
                P256EcdsaRoleV1::WalletOwnership,
                challenges_v1(),
            ),
            Err(P256CrossTraceBusErrorV1::Source)
        ));
    }
    #[test]
    fn ordinary_product_constrains_every_aux_cell_source_tag_boundary_and_terminal() {
        let (fixed, source, start, aux) = regular_fixture_v1();
        assert!(!regular_has_nonzero_v1(&fixed, &source, start, &aux));
        for row in 0..aux.len() {
            for slot in 0..P256_CROSS_TRACE_EVENT_SLOTS_V1 {
                let mut changed = aux.clone();
                changed[row].event_values[slot] = changed[row].event_values[slot].add(F::ONE);
                assert!(regular_has_nonzero_v1(&fixed, &source, start, &changed));
            }
            for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                for state in 0..=P256_CROSS_TRACE_EVENT_SLOTS_V1 {
                    let mut changed = aux.clone();
                    changed[row].products[lane][state] =
                        changed[row].products[lane][state].add(F::ONE);
                    assert!(regular_has_nonzero_v1(&fixed, &source, start, &changed));
                }
                let mut changed = aux.clone();
                changed[row].terminal[lane] = changed[row].terminal[lane].add(F::ONE);
                assert!(regular_has_nonzero_v1(&fixed, &source, start, &changed));
            }
        }
        for row in 0..fixed.len() {
            for slot in 0..P256_CROSS_TRACE_EVENT_SLOTS_V1 {
                if fixed[row].events[slot].active == F::ONE {
                    let mut changed = source.clone();
                    changed[row][slot] = changed[row][slot].add(F::ONE);
                    assert!(regular_has_nonzero_v1(&fixed, &changed, start, &aux));
                    let mut changed = fixed.clone();
                    changed[row].events[slot].address =
                        changed[row].events[slot].address.add(F::ONE);
                    assert!(regular_has_nonzero_v1(&changed, &source, start, &aux));
                    let mut changed = fixed.clone();
                    changed[row].events[slot].active = F::ZERO;
                    changed[row].events[slot].endpoint = F::ZERO;
                    changed[row].events[slot].address = F::ZERO;
                    assert!(regular_has_nonzero_v1(&changed, &source, start, &aux));
                }
            }
        }
        let mut reordered_source = source.clone();
        reordered_source.swap(0, 3);
        assert!(regular_has_nonzero_v1(
            &fixed,
            &reordered_source,
            start,
            &aux
        ));
        let mut reordered_fixed = fixed.clone();
        reordered_fixed.swap(0, 1);
        assert_eq!(
            build_zk_x509_p256_cross_trace_regular_aux_v1(
                &reordered_fixed,
                &source,
                start,
                challenges_v1()
            ),
            Err(P256CrossTraceBusErrorV1::Topology)
        );
        assert_eq!(
            build_zk_x509_p256_cross_trace_regular_aux_v1(
                &fixed[..fixed.len() - 1],
                &source[..source.len() - 1],
                start,
                challenges_v1()
            ),
            Err(P256CrossTraceBusErrorV1::Topology)
        );
        let mut duplicated = fixed.clone();
        duplicated.extend_from_slice(&fixed);
        let mut duplicated_source = source.clone();
        duplicated_source.extend_from_slice(&source);
        assert_eq!(
            build_zk_x509_p256_cross_trace_regular_aux_v1(
                &duplicated,
                &duplicated_source,
                start,
                challenges_v1()
            ),
            Err(P256CrossTraceBusErrorV1::Topology)
        );
    }
    #[test]
    fn writer_addition_chain_constrains_every_cell_and_exact_multiplicity() {
        let (fixed, source, aux) = small_writer_fixture_v1();
        assert!(!writer_has_nonzero_v1(&fixed, &source, &aux));
        let multiplicities = [1_usize, 64, 65, 129, 0, 2, 64, 0];
        for row in 0..aux.len() {
            for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
                let logical = row * P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + slot;
                for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                    let factor = compress_event_v1(
                        fixed[row].events[slot],
                        aux[row].event_values[slot],
                        challenges_v1().lanes[lane],
                    );
                    let expected =
                        (0..multiplicities[logical]).fold(F::ONE, |value, _| value.mul(factor));
                    assert_eq!(aux[row].selected_power[slot][lane], expected);
                }
                let mut changed = aux.clone();
                changed[row].event_values[slot] = changed[row].event_values[slot].add(F::ONE);
                assert!(writer_has_nonzero_v1(&fixed, &source, &changed));
                for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                    for power in 0..P256_CROSS_TRACE_WRITER_POWERS_V1 {
                        let mut changed = aux.clone();
                        changed[row].powers[slot][lane][power] =
                            changed[row].powers[slot][lane][power].add(F::ONE);
                        assert!(writer_has_nonzero_v1(&fixed, &source, &changed));
                    }
                    let mut changed = aux.clone();
                    changed[row].selected_power[slot][lane] =
                        changed[row].selected_power[slot][lane].add(F::ONE);
                    assert!(writer_has_nonzero_v1(&fixed, &source, &changed));
                    let mut changed = aux.clone();
                    changed[row].product_before[slot][lane] =
                        changed[row].product_before[slot][lane].add(F::ONE);
                    assert!(writer_has_nonzero_v1(&fixed, &source, &changed));
                    let mut changed = aux.clone();
                    changed[row].terminal[lane] = changed[row].terminal[lane].add(F::ONE);
                    assert!(writer_has_nonzero_v1(&fixed, &source, &changed));
                }
            }
        }
        for row in 0..fixed.len() {
            for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
                if fixed[row].events[slot].active == F::ONE {
                    let mut changed = source.clone();
                    changed[row][slot] = changed[row][slot].add(F::ONE);
                    assert!(writer_has_nonzero_v1(&fixed, &changed, &aux));
                }
            }
        }
        let mut wrong_multiplicity = fixed.clone();
        wrong_multiplicity[0].multiplicity_64[1] = F::ZERO;
        wrong_multiplicity[0].multiplicity_65[1] = F::ONE;
        assert!(writer_has_nonzero_v1(&wrong_multiplicity, &source, &aux));
        let mut duplicate_multiplicity = fixed.clone();
        duplicate_multiplicity[1].multiplicity_64[0] = F::ONE;
        assert!(writer_has_nonzero_v1(
            &duplicate_multiplicity,
            &source,
            &aux
        ));
        let mut wrong_tag = fixed.clone();
        wrong_tag[0].events[0].address = wrong_tag[0].events[0].address.add(F::ONE);
        assert!(writer_has_nonzero_v1(&wrong_tag, &source, &aux));
        let mut reordered = aux.clone();
        reordered.swap(2, 3);
        assert!(writer_has_nonzero_v1(&fixed, &source, &reordered));
        let mut exact =
            P256CrossTraceWriterSourceFixedV1::compile_v1(P256EcdsaRoleV1::WalletOwnership)
                .expect("exact schedule");
        exact.multiplicities[0] = 3;
        assert_eq!(
            exact.row_v1(3 * P256_VALUE_BUS_LIMBS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1),
            Err(P256CrossTraceBusErrorV1::Multiplicity)
        );
    }
    #[test]
    fn writer_multiplicity_domain_accepts_two_and_rejects_unsupported_values() {
        let row = 3 * P256_VALUE_BUS_LIMBS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let mut fixed =
            P256CrossTraceWriterSourceFixedV1::compile_v1(P256EcdsaRoleV1::WalletOwnership)
                .unwrap();
        assert_eq!(fixed.row_v1(row).unwrap().multiplicity_129[0], F::ONE);
        for value in [0_u16, 1, 2, 64, 65, 129] {
            fixed.multiplicities[0] = value;
            let actual = fixed.row_v1(row).unwrap();
            assert_eq!(actual.events[0].active, F(u64::from(value != 0)));
            assert_eq!(actual.events[0].endpoint, F(u64::from(value != 0)));
            assert_eq!(actual.events[0].address, F::ZERO);
            assert_eq!(
                actual.multiplicity_small[0],
                F(u64::from(if value <= 2 { value } else { 0 }))
            );
            assert_eq!(actual.multiplicity_64[0], F(u64::from(value == 64)));
            assert_eq!(actual.multiplicity_65[0], F(u64::from(value == 65)));
            assert_eq!(actual.multiplicity_129[0], F(u64::from(value == 129)));
        }
        for value in [3_u16, 63, 66, 128, 130, u16::MAX] {
            fixed.multiplicities[0] = value;
            assert_eq!(
                fixed.row_v1(row),
                Err(P256CrossTraceBusErrorV1::Multiplicity)
            );
        }
        // Small multiplicity two is admissible, but substituting it for an
        // authenticated 65-use row still invalidates the unchanged witness.
        let (mut fixed, source, aux) = small_writer_fixture_v1();
        fixed[1].multiplicity_65[0] = F::ZERO;
        fixed[1].multiplicity_small[0] = F(2);
        assert!(writer_has_nonzero_v1(&fixed, &source, &aux));
    }
    #[test]
    fn sink_rejects_local_fixed_padding_and_coordinated_copy_attacks() {
        let fixture = wallet_sink_fixture_v1();
        let first_fixed = fixture.fixed.row_v1(0).expect("first fixed");
        assert!(
            evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(
                first_fixed,
                &fixture.binding.rows[0],
            )
            .into_iter()
            .all(|residue| residue == F::ZERO)
        );
        let mut writer_only = fixture.binding.clone();
        writer_only.rows[0].writer_cells[0] = writer_only.rows[0].writer_cells[0].add(F::ONE);
        assert!(
            evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(
                first_fixed,
                &writer_only.rows[0],
            )
            .into_iter()
            .any(|residue| residue != F::ZERO)
        );
        assert!(matches!(
            build_zk_x509_p256_cross_trace_sink_v1(&writer_only, challenges_v1()),
            Err(P256CrossTraceBusErrorV1::Constraint)
        ));
        let mut coordinated = fixture.binding.clone();
        coordinated.rows[0].writer_cells[0] = coordinated.rows[0].writer_cells[0].add(F::ONE);
        coordinated.rows[0].external_cells[0] = coordinated.rows[0].external_cells[0].add(F::ONE);
        assert!(
            evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(
                first_fixed,
                &coordinated.rows[0],
            )
            .into_iter()
            .all(|residue| residue == F::ZERO)
        );
        let changed_sink_terminal =
            build_zk_x509_p256_cross_trace_sink_v1(&coordinated, challenges_v1())
                .expect("locally consistent coordinated sink")
                .terminal_v1();
        assert!(
            evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1(
                fixture.source_terminal,
                changed_sink_terminal,
            )
            .into_iter()
            .any(|residue| residue != F::ZERO)
        );
        let constant = (0..fixture.fixed.logical_rows_v1())
            .find_map(|row| {
                let fixed = fixture.fixed.row_v1(row).expect("fixed");
                fixed
                    .constant
                    .iter()
                    .position(|constant| *constant == F::ONE)
                    .map(|slot| (row, slot))
            })
            .expect("constant slot");
        let mut changed_constant = fixture.binding.clone();
        changed_constant.rows[constant.0].writer_cells[constant.1] =
            changed_constant.rows[constant.0].writer_cells[constant.1].add(F::ONE);
        changed_constant.rows[constant.0].external_cells[constant.1] =
            changed_constant.rows[constant.0].external_cells[constant.1].add(F::ONE);
        assert!(
            evaluate_zk_x509_p256_cross_trace_sink_local_constraints_v1(
                fixture.fixed.row_v1(constant.0).expect("constant row"),
                &changed_constant.rows[constant.0],
            )
            .into_iter()
            .any(|residue| residue != F::ZERO)
        );
        assert!(matches!(
            build_zk_x509_p256_cross_trace_sink_v1(&changed_constant, challenges_v1()),
            Err(P256CrossTraceBusErrorV1::Constraint)
        ));
        let mut reordered = fixture.binding.clone();
        reordered.rows.swap(0, 1);
        assert_eq!(
            validate_binding_fixed_schedule_v1(&reordered),
            Err(P256CrossTraceBusErrorV1::Topology)
        );
        let mut omitted = fixture.binding.clone();
        omitted.rows.pop();
        assert_eq!(
            validate_binding_fixed_schedule_v1(&omitted),
            Err(P256CrossTraceBusErrorV1::Topology)
        );
        let mut duplicated = fixture.binding.clone();
        duplicated.rows.push(duplicated.rows[0]);
        assert_eq!(
            validate_binding_fixed_schedule_v1(&duplicated),
            Err(P256CrossTraceBusErrorV1::Topology)
        );
        let (canonical, binding, current, next) = sink_row_context_v1(fixture, 0);
        assert!(!sink_opened_row_has_nonzero_v1(
            canonical, &binding, &current, &next
        ));
        let mut wrong_tag = canonical;
        wrong_tag.product.events[0].address = wrong_tag.product.events[0].address.add(F::ONE);
        assert!(sink_opened_row_has_nonzero_v1(
            wrong_tag, &binding, &current, &next
        ));
        let mut rebound_terminal = current;
        rebound_terminal.terminal[0] = rebound_terminal.terminal[0].add(F::ONE);
        assert!(sink_opened_row_has_nonzero_v1(
            canonical,
            &binding,
            &rebound_terminal,
            &next,
        ));
        let (padding_fixed, padding_binding, mut padding, padding_next) =
            sink_row_context_v1(fixture, P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 - 1);
        padding.event_values[0] = F::ONE;
        assert!(sink_opened_row_has_nonzero_v1(
            padding_fixed,
            &padding_binding,
            &padding,
            &padding_next,
        ));
    }
    #[test]
    fn every_sink_aux_column_is_constraint_relevant_on_active_and_padding_rows() {
        let fixture = wallet_sink_fixture_v1();
        for row in [0, P256_CROSS_TRACE_SINK_TRACE_SIZE_V1 - 1] {
            let (fixed, binding, current, next) = sink_row_context_v1(fixture, row);
            for slot in 0..P256_CROSS_TRACE_EVENT_SLOTS_V1 {
                let mut changed = current;
                changed.event_values[slot] = changed.event_values[slot].add(F::ONE);
                assert!(sink_opened_row_has_nonzero_v1(
                    fixed, &binding, &changed, &next
                ));
            }
            for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                for state in 0..=P256_CROSS_TRACE_EVENT_SLOTS_V1 {
                    let mut changed = current;
                    changed.products[lane][state] = changed.products[lane][state].add(F::ONE);
                    assert!(sink_opened_row_has_nonzero_v1(
                        fixed, &binding, &changed, &next
                    ));
                }
                let mut changed = current;
                changed.terminal[lane] = changed.terminal[lane].add(F::ONE);
                assert!(sink_opened_row_has_nonzero_v1(
                    fixed, &binding, &changed, &next
                ));
            }
        }
    }
    fn sink_opened_row_has_nonzero_v1(
        fixed: P256CrossTraceSinkFixedRowV1,
        binding: &P256ExternalBindingRowV1,
        current: &P256CrossTraceRegularAuxRowV1,
        next: &P256CrossTraceRegularAuxRowV1,
    ) -> bool {
        let residues = evaluate_zk_x509_p256_cross_trace_sink_row_constraints_v1(
            fixed,
            binding,
            current,
            next,
            challenges_v1(),
        );
        assert_eq!(residues.len(), P256_CROSS_TRACE_SINK_CONSTRAINT_COUNT_V1);
        residues.into_iter().any(|residue| residue != F::ZERO)
    }
    #[test]
    fn challenges_terminal_and_soundness_domains_fail_closed() {
        challenges_v1().validate().expect("valid challenges");
        let unique_labels = P256_CROSS_TRACE_CHALLENGE_LABELS_V1
            .iter()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            unique_labels.len(),
            P256_CROSS_TRACE_LANES_V1 * P256_CROSS_TRACE_CHALLENGE_TERMS_V1
        );
        let mut transcript = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"p256-cross-trace-test",
            &PrivacyOuterDigestV1::from_bytes([0x43; 48]),
            &PrivacyOuterDigestV1::from_bytes([0xb8; 48]),
        )
        .expect("transcript");
        let transcript_challenges =
            derive_zk_x509_p256_cross_trace_challenges_v1(&mut transcript).expect("challenges");
        transcript_challenges
            .validate()
            .expect("lane-separated transcript challenges");
        let mut zero = challenges_v1();
        zero.lanes[0].terms[0] = F::ZERO;
        assert_eq!(zero.validate(), Err(P256CrossTraceBusErrorV1::Challenge));
        let mut noncanonical = challenges_v1();
        noncanonical.lanes[0].terms[0] = F(u64::MAX);
        assert_eq!(
            noncanonical.validate(),
            Err(P256CrossTraceBusErrorV1::Challenge)
        );
        let mut repeated_in_lane = challenges_v1();
        repeated_in_lane.lanes[0].terms[3] = repeated_in_lane.lanes[0].terms[1];
        assert_eq!(
            repeated_in_lane.validate(),
            Err(P256CrossTraceBusErrorV1::Challenge)
        );
        let mut repeated_across_lanes = challenges_v1();
        repeated_across_lanes.lanes[2].terms[1] = repeated_across_lanes.lanes[0].terms[3];
        assert_eq!(
            repeated_across_lanes.validate(),
            Err(P256CrossTraceBusErrorV1::Challenge)
        );
        assert_eq!(
            evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1(
                [F(3), F(5), F(7), F(11)],
                [F(3), F(5), F(7), F(11)]
            ),
            [F::ZERO; P256_CROSS_TRACE_LANES_V1]
        );
        assert!(
            evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1(
                [F(3), F(5), F(7), F(11)],
                [F(4), F(5), F(7), F(11)]
            )
            .into_iter()
            .any(|residue| residue != F::ZERO)
        );
        // Four independent lanes reduce the tagged-multiset collision bound
        // below 2^-176 for the exact maximum first-release event count.
        let field = (u128::from(u64::MAX) - u128::from(u32::MAX) + 1) as f64;
        let ratio = P256_CROSS_TRACE_WALLET_EVENTS_V1 as f64 / field;
        assert!(ratio.powi(4) < 2_f64.powi(-176));
    }
}

#[cfg(test)]
#[path = "p256_writer_inactive_tests.rs"]
mod writer_inactive_tests;
