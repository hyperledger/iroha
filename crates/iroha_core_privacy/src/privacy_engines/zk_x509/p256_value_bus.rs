//! Fixed-topology value-copy bus for exact P-256 arithmetic.
//!
//! Arithmetic operands are SSA values. Every input or constant value is written exactly once in the
//! spare coefficient rows of one arithmetic operation, and every derived value is written exactly
//! once by that operation's `c` operand. The first sixteen coefficient rows expose pointwise
//! `a`/`b` reads and `c` writes. A verifier-fixed sorted endpoint then proves, with four
//! independently challenged products, that every read sees the unique writer for the same `(value
//! id, limb, modulus, value kind)`.
//!
//! Ordinary equality assertions add two memory reads per limb and an explicit limb equality.
//! Boolean bridges do the same across the scalar/base modulus boundary, while additionally proving
//! that both represented integers are canonical bits. Neither assertion form creates a writer.
//!
//! Rows in this module are product-factor slots. The AIR embedding packs exactly two consecutive
//! slots into one physical row using one intermediate product; each individual transition remains
//! degree two. Keeping segment boundaries in factor-slot units also permits a later source-bound
//! external read stream to concatenate complete 16-limb values without per-value padding. No
//! unconstrained external-read API is exposed here.
use super::p256_air::ZkX509P256ModulusV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    credential_pre_aux::ZkX509CredentialMainPostBaseChallengesV1,
    p256_air::{
        P256_ARITHMETIC_ROWS_PER_OPERATION_V1, P256_BASE_MODULUS_BE_V1, P256_SCALAR_MODULUS_BE_V1,
        ZkX509P256AirErrorV1, ZkX509P256ArithmeticOperationV1, ZkX509P256ArithmeticTraceV1,
        build_zk_x509_p256_arithmetic_trace_v1, p256_arithmetic_operand_limbs_v1,
    },
    p256_ecdsa_air::P256EcdsaRoleV1,
    p256_trace::P256EcdsaTopologyV1,
    p256_trace::{P256EcdsaTraceMaterialV1, compile_p256_ecdsa_topology_v1},
};
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, PolynomialAirFieldV1, TransparentStarkErrorV1, TransparentTranscriptV1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use std::sync::Arc;
use thiserror::Error;
/// Number of independently sampled grand-product lanes.
pub const P256_VALUE_BUS_LANES_V1: usize = 4;
/// `beta`, id, limb, read/write, modulus, value kind, and value.
pub const P256_VALUE_BUS_TUPLE_TERMS_V1: usize = 7;
/// Little-endian 16-bit limbs in one P-256 field element.
pub const P256_VALUE_BUS_LIMBS_V1: usize = 16;
/// Consecutive product factors supported by one packed physical AIR row.
pub const P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1: usize = 2;
/// Fixed logical bus rows in every arithmetic or assertion segment.
pub const P256_VALUE_BUS_SEGMENT_ROWS_V1: usize = 64;
/// Canonical first-release native domain for either P-256 value-bus endpoint.
pub const P256_VALUE_BUS_STARK_TRACE_SIZE_V1: usize = 1 << 19;
/// Numeric aggregate base width: two limbs and their little-endian bits.
pub const P256_VALUE_BUS_STARK_BASE_WIDTH_V1: usize =
    P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * (1 + P256_VALUE_BUS_LIMBS_V1);
/// Four products before, between, and after the two factors.
pub const P256_VALUE_BUS_STARK_AUX_WIDTH_V1: usize =
    (P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + 1) * P256_VALUE_BUS_LANES_V1;
/// Numeric verifier preprocessing width.
pub const P256_VALUE_BUS_STARK_FIXED_WIDTH_V1: usize =
    P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * 10 + 2;
/// Exact residue inventory for one opened aggregate row.
pub const P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1: usize =
    P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * 41 + 2 * P256_VALUE_BUS_LANES_V1;
/// Maximum total degree of the numeric adapter.
pub const P256_VALUE_BUS_STARK_CONSTRAINT_DEGREE_V1: u8 = 2;
/// Unambiguous transcript labels for all 28 challenge coordinates.
pub const P256_VALUE_BUS_CHALLENGE_LABELS_V1: [[&[u8]; P256_VALUE_BUS_TUPLE_TERMS_V1];
    P256_VALUE_BUS_LANES_V1] = [
    [
        b"zk-x509-p256-value-bus-lane0-beta-v1",
        b"zk-x509-p256-value-bus-lane0-id-v1",
        b"zk-x509-p256-value-bus-lane0-limb-v1",
        b"zk-x509-p256-value-bus-lane0-read-write-v1",
        b"zk-x509-p256-value-bus-lane0-modulus-v1",
        b"zk-x509-p256-value-bus-lane0-value-kind-v1",
        b"zk-x509-p256-value-bus-lane0-value-v1",
    ],
    [
        b"zk-x509-p256-value-bus-lane1-beta-v1",
        b"zk-x509-p256-value-bus-lane1-id-v1",
        b"zk-x509-p256-value-bus-lane1-limb-v1",
        b"zk-x509-p256-value-bus-lane1-read-write-v1",
        b"zk-x509-p256-value-bus-lane1-modulus-v1",
        b"zk-x509-p256-value-bus-lane1-value-kind-v1",
        b"zk-x509-p256-value-bus-lane1-value-v1",
    ],
    [
        b"zk-x509-p256-value-bus-lane2-beta-v1",
        b"zk-x509-p256-value-bus-lane2-id-v1",
        b"zk-x509-p256-value-bus-lane2-limb-v1",
        b"zk-x509-p256-value-bus-lane2-read-write-v1",
        b"zk-x509-p256-value-bus-lane2-modulus-v1",
        b"zk-x509-p256-value-bus-lane2-value-kind-v1",
        b"zk-x509-p256-value-bus-lane2-value-v1",
    ],
    [
        b"zk-x509-p256-value-bus-lane3-beta-v1",
        b"zk-x509-p256-value-bus-lane3-id-v1",
        b"zk-x509-p256-value-bus-lane3-limb-v1",
        b"zk-x509-p256-value-bus-lane3-read-write-v1",
        b"zk-x509-p256-value-bus-lane3-modulus-v1",
        b"zk-x509-p256-value-bus-lane3-value-kind-v1",
        b"zk-x509-p256-value-bus-lane3-value-v1",
    ],
];
const _: () = assert!(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 == 2);
const _: () = assert!(P256_VALUE_BUS_STARK_BASE_WIDTH_V1 == 34);
const _: () = assert!(P256_VALUE_BUS_STARK_AUX_WIDTH_V1 == 12);
const _: () = assert!(P256_VALUE_BUS_STARK_FIXED_WIDTH_V1 == 22);
const _: () = assert!(P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1 == 90);
/// Verifier-assigned SSA value identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct P256ValueIdV1(pub(crate) u32);
/// Origin of an initial SSA value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256InitialValueKindV1 {
    /// Private or public circuit input supplied by the surrounding relation.
    Input,
    /// Verifier-fixed constant supplied by the surrounding relation.
    Constant,
}
/// One arithmetic operation linked to fixed SSA operand/result identifiers.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256LinkedOperationV1 {
    /// First operand read.
    pub(crate) a: P256ValueIdV1,
    /// Second operand read.
    pub(crate) b: P256ValueIdV1,
    /// Unique result writer.
    pub(crate) c: P256ValueIdV1,
    /// Exact arithmetic instruction and its committed operand cells.
    pub(crate) operation: ZkX509P256ArithmeticOperationV1,
}
/// One initial value written in an operation's sixteen spare coefficient rows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256InitialValueBindingV1 {
    /// Sequential verifier-assigned identifier.
    pub(crate) id: P256ValueIdV1,
    /// Field in which the integer is canonical.
    pub(crate) modulus: ZkX509P256ModulusV1,
    /// Canonical big-endian integer.
    pub(crate) value: [u8; 32],
    /// Input or verifier-fixed constant.
    pub(crate) kind: P256InitialValueKindV1,
}
/// Verifier-owned metadata for one initial SSA writer.
///
/// Witness bytes are deliberately absent. Fixed preprocessing accepts this
/// type instead of [`P256InitialValueBindingV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256InitialValueTopologyV1 {
    /// Sequential canonical value identifier.
    pub(crate) id: P256ValueIdV1,
    /// Coordinate or scalar modulus.
    pub(crate) modulus: ZkX509P256ModulusV1,
    /// Surrounding input or verifier-fixed constant.
    pub(crate) kind: P256InitialValueKindV1,
}
/// Verifier-owned metadata for one arithmetic SSA instruction.
///
/// Operand and result values are committed elsewhere and never enter this topology object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256LinkedOperationTopologyV1 {
    /// First existing operand.
    pub(crate) a: P256ValueIdV1,
    /// Second existing operand.
    pub(crate) b: P256ValueIdV1,
    /// Unique result writer.
    pub(crate) c: P256ValueIdV1,
    /// Fixed arithmetic relation.
    pub(crate) kind: super::p256_air::ZkX509P256ArithmeticKindV1,
    /// Fixed arithmetic modulus.
    pub(crate) modulus: ZkX509P256ModulusV1,
}
/// Explicit equality between two already-written values in the same modulus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256EqualityBindingV1 {
    /// First existing value.
    pub(crate) left: P256ValueIdV1,
    /// Second existing value.
    pub(crate) right: P256ValueIdV1,
}
/// Equality bridge for a canonical scalar-field bit and base-field bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256BooleanBridgeBindingV1 {
    /// Existing scalar-field value constrained to zero or one.
    pub(crate) scalar_bit: P256ValueIdV1,
    /// Existing base-field value constrained to the same zero or one.
    pub(crate) base_bit: P256ValueIdV1,
}
/// Value origin included in every active permutation tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ValueKindV1 {
    /// Surrounding-relation input.
    Input,
    /// Verifier-fixed constant.
    Constant,
    /// Unique result of one arithmetic operation.
    Derived,
}
/// Memory access direction included in every active permutation tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ValueAccessKindV1 {
    /// The unique writer for one value limb.
    Write,
    /// A use of an already-written value limb.
    Read,
}
/// Verifier-regenerated address for one logical bus row.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ValueBusFixedAccessV1 {
    /// Canonical product-identity padding.
    Inactive,
    /// One addressed 16-bit memory access.
    Active {
        /// SSA value identifier.
        id: P256ValueIdV1,
        /// Little-endian limb index.
        limb: u8,
        /// Read or unique write.
        access: P256ValueAccessKindV1,
        /// P-256 coordinate or scalar modulus.
        modulus: ZkX509P256ModulusV1,
        /// Input, constant, or derived value origin.
        value_kind: P256ValueKindV1,
    },
}
/// One challenged product row.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ValueBusRowV1 {
    /// Verifier-regenerated address or inactive selector.
    pub(crate) fixed: P256ValueBusFixedAccessV1,
    /// Addressed 16-bit limb.
    pub(crate) value: F,
    /// Little-endian Boolean decomposition of `value`.
    pub(crate) value_bits: [F; P256_VALUE_BUS_LIMBS_V1],
    /// Products before this access.
    pub(crate) product_before: [F; P256_VALUE_BUS_LANES_V1],
    /// Products after this access.
    pub(crate) product_after: [F; P256_VALUE_BUS_LANES_V1],
}
/// One fixed-size physical segment with explicit product boundaries.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256ValueBusSegmentV1 {
    /// Sequential verifier-fixed segment index.
    pub(crate) index: u32,
    /// Products entering this segment.
    pub(crate) product_before: [F; P256_VALUE_BUS_LANES_V1],
    /// Exactly 64 access or inactive rows.
    pub(crate) rows: Vec<P256ValueBusRowV1>,
    /// Products leaving this segment.
    pub(crate) product_after: [F; P256_VALUE_BUS_LANES_V1],
}
/// Product endpoint.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ValueBusEndpointV1 {
    /// Arithmetic and assertion accesses in fixed execution order.
    Execution,
    /// The same accesses verifier-sorted by id, limb, and writer-first.
    Sorted,
}
/// One endpoint's segmented product trace.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256ValueBusEndpointTraceV1 {
    /// Execution or sorted endpoint.
    pub(crate) endpoint: P256ValueBusEndpointV1,
    /// Arithmetic segments, equality segments, then Boolean-bridge segments.
    pub(crate) segments: Vec<P256ValueBusSegmentV1>,
}
/// Complete differential memory-bus trace.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256ValueBusTraceV1 {
    /// Source-bound execution accesses.
    pub(crate) execution: P256ValueBusEndpointTraceV1,
    /// Verifier-sorted accesses used for writer/read adjacency.
    pub(crate) sorted: P256ValueBusEndpointTraceV1,
}
/// One challenge-independent value-bus cell.
///
/// Product accumulators are deliberately absent. The 16-bit decomposition is regenerated when a
/// committed base row is requested, so the retained private material is the addressed field cell
/// and nothing challenge dependent can exist before X5B1.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ValueBusBaseCellV1 {
    /// Verifier-owned address and access direction.
    pub(crate) fixed: P256ValueBusFixedAccessV1,
    /// Addressed field cell. Active cells must be canonical 16-bit integers
    /// and inactive cells must be zero.
    pub(crate) value: F,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl AsMut<[F]> for P256ValueBusBaseCellV1 {
    fn as_mut(&mut self) -> &mut [F] {
        core::slice::from_mut(&mut self.value)
    }
}

/// One challenge-independent execution or writer-first endpoint.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256ValueBusBaseEndpointTraceV1 {
    /// Execution or sorted endpoint identity.
    pub(crate) endpoint: P256ValueBusEndpointV1,
    /// Exact logical factor rows, including canonical 64-row segment padding.
    pub(crate) rows: Vec<P256ValueBusBaseCellV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ValueBusBaseEndpointTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256ValueBusBaseEndpointTraceV1 { <private trace redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ValueBusBaseEndpointTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ValueBusBaseEndpointTraceV1 {
    /// Exact number of complete logical segments.
    pub(crate) fn segment_count_v1(&self) -> Result<usize, P256ValueBusErrorV1> {
        if self.rows.is_empty()
            || !self
                .rows
                .len()
                .is_multiple_of(P256_VALUE_BUS_SEGMENT_ROWS_V1)
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(self.rows.len() / P256_VALUE_BUS_SEGMENT_ROWS_V1)
    }
    /// Read one challenge-independent logical cell.
    pub(crate) fn source_cell_v1(
        &self,
        ordinal: usize,
    ) -> Result<(P256ValueBusFixedAccessV1, F), P256ValueBusErrorV1> {
        let row = self
            .rows
            .get(ordinal)
            .ok_or(P256ValueBusErrorV1::Topology)?;
        validate_base_cell_v1(*row)?;
        Ok((row.fixed, row.value))
    }
    fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_field_rows_v1(&mut self.rows);
        self.rows.clear();
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.rows.is_empty()
    }
}
/// Complete challenge-independent P-256 value-memory material.
///
/// This is the only production input to the value-bus base commitment. It is constructed from a
/// witness only after independently compiling and matching the verifier's role-specific SSA
/// topology. Fixed rows are never retained here; they are regenerated from [`P256EcdsaTopologyV1`].
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256ValueBusBaseMaterialV1 {
    role: P256EcdsaRoleV1,
    topology: P256EcdsaTopologyV1,
    execution: P256ValueBusBaseEndpointTraceV1,
    sorted: P256ValueBusBaseEndpointTraceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ValueBusBaseMaterialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ValueBusBaseMaterialV1")
            .field("role", &self.role)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ValueBusBaseMaterialV1 {
    /// Compile one canonical role-separated value bus without sampling or
    /// accepting any grand-product challenge.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn from_trace_material_v1(
        material: &P256EcdsaTraceMaterialV1,
    ) -> Result<Self, P256ValueBusErrorV1> {
        let expected = compile_p256_ecdsa_topology_v1(material.role)
            .map_err(|_| P256ValueBusErrorV1::Topology)?;
        validate_trace_material_topology_v1(material, &expected)?;
        let operations = material
            .linked_operations
            .iter()
            .map(|linked| linked.operation)
            .collect::<Vec<_>>();
        let operations = super::private_table::PrivateTableV1::new(
            operations,
            super::p256_air::zeroize_p256_operations_v1,
        );
        let arithmetic_trace =
            build_zk_x509_p256_arithmetic_trace_v1(&operations).map_err(map_arithmetic_error_v1)?;
        let execution_events = execution_events_v1(
            &material.initial_values,
            &material.linked_operations,
            &material.equalities,
            &material.boolean_bridges,
            &arithmetic_trace,
        )?;
        let sorted_events = sorted_events_v1(&execution_events)?;
        let value_bus = Self {
            role: material.role,
            topology: expected,
            execution: build_base_endpoint_v1(
                P256ValueBusEndpointV1::Execution,
                &execution_events,
            )?,
            sorted: build_base_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events)?,
        };
        value_bus.validate_integrity_v1()?;
        Ok(value_bus)
    }
    #[cfg(test)]
    fn fixture_v1(
        role: P256EcdsaRoleV1,
        topology: P256EcdsaTopologyV1,
        initial_values: &[P256InitialValueBindingV1],
        linked_operations: &[P256LinkedOperationV1],
        equalities: &[P256EqualityBindingV1],
        boolean_bridges: &[P256BooleanBridgeBindingV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256ValueBusErrorV1> {
        validate_value_bus_topology_components_v1(
            role,
            initial_values,
            linked_operations,
            equalities,
            boolean_bridges,
            &topology,
        )?;
        let execution_events = execution_events_v1(
            initial_values,
            linked_operations,
            equalities,
            boolean_bridges,
            arithmetic_trace,
        )?;
        let sorted_events = sorted_events_v1(&execution_events)?;
        let value_bus = Self {
            role,
            topology,
            execution: build_base_endpoint_v1(
                P256ValueBusEndpointV1::Execution,
                &execution_events,
            )?,
            sorted: build_base_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events)?,
        };
        value_bus.validate_integrity_v1()?;
        Ok(value_bus)
    }
    /// Role fixed by the verifier-owned topology compiler.
    const fn role_v1(&self) -> P256EcdsaRoleV1 {
        self.role
    }
    /// Challenge-independent execution endpoint.
    const fn execution_v1(&self) -> &P256ValueBusBaseEndpointTraceV1 {
        &self.execution
    }
    /// Challenge-independent writer-first endpoint.
    const fn sorted_v1(&self) -> &P256ValueBusBaseEndpointTraceV1 {
        &self.sorted
    }
    /// Verifier-owned canonical SSA topology.
    const fn topology_v1(&self) -> &P256EcdsaTopologyV1 {
        &self.topology
    }
    fn fixed_provider_v1(
        &self,
        endpoint: P256ValueBusStarkEndpointV1,
    ) -> Result<P256ValueBusStarkFixedProviderV1, P256ValueBusErrorV1> {
        P256ValueBusStarkFixedProviderV1::new_v1(
            endpoint,
            &self.topology.initial_values,
            &self.topology.linked_operations,
            &self.topology.equalities,
            &self.topology.boolean_bridges,
            P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        )
    }
    fn validate_integrity_v1(&self) -> Result<(), P256ValueBusErrorV1> {
        if self.topology.role != self.role
            || self.execution.endpoint != P256ValueBusEndpointV1::Execution
            || self.sorted.endpoint != P256ValueBusEndpointV1::Sorted
            || self.execution.rows.len() != self.sorted.rows.len()
            || self.execution.segment_count_v1()?
                != self
                    .topology
                    .linked_operations
                    .len()
                    .checked_add(self.topology.equalities.len())
                    .and_then(|segments| segments.checked_add(self.topology.boolean_bridges.len()))
                    .ok_or(P256ValueBusErrorV1::Resource)?
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let execution_fixed = self.fixed_provider_v1(P256ValueBusStarkEndpointV1::Execution)?;
        let sorted_fixed = self.fixed_provider_v1(P256ValueBusStarkEndpointV1::Sorted)?;
        validate_base_endpoint_against_fixed_v1(&self.execution, &execution_fixed)?;
        validate_base_endpoint_against_fixed_v1(&self.sorted, &sorted_fixed)?;
        let expected_sorted = sorted_base_cells_v1(&self.execution.rows)?;
        if self.sorted.rows.as_slice() != expected_sorted.as_slice() {
            return Err(P256ValueBusErrorV1::Adjacency);
        }
        validate_base_equality_segments_v1(
            &self.execution,
            self.topology.linked_operations.len(),
            &self.topology.equalities,
        )?;
        validate_base_boolean_bridge_segments_v1(
            &self.execution,
            self.topology.linked_operations.len(),
            self.topology.equalities.len(),
            &self.topology.boolean_bridges,
        )
    }
    fn zeroize_private_v1(&mut self) {
        self.execution.zeroize_private_v1();
        self.sorted.zeroize_private_v1();
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.execution.private_is_zeroized_v1() && self.sorted.private_is_zeroized_v1()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ValueBusBaseMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// One tuple-compression lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ValueBusLaneChallengesV1 {
    /// `beta` followed by six tuple coefficients.
    pub(crate) terms: [F; P256_VALUE_BUS_TUPLE_TERMS_V1],
}
/// Four independently sampled tuple products.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ValueBusChallengesV1 {
    /// Independent lanes.
    pub(crate) lanes: [P256ValueBusLaneChallengesV1; P256_VALUE_BUS_LANES_V1],
}
impl P256ValueBusChallengesV1 {
    pub(crate) fn validate(self) -> Result<(), P256ValueBusErrorV1> {
        let mut seen = [F::ZERO; P256_VALUE_BUS_LANES_V1 * P256_VALUE_BUS_TUPLE_TERMS_V1];
        let mut count = 0;
        for lane in self.lanes {
            for term in lane.terms {
                if F::canonical(term.0).is_none()
                    || term == F::ZERO
                    || seen[..count].contains(&term)
                {
                    return Err(P256ValueBusErrorV1::Challenge);
                }
                seen[count] = term;
                count += 1;
            }
        }
        Ok(())
    }
}
/// Value-bus topology, source, range, or algebraic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum P256ValueBusErrorV1 {
    /// A post-base operation was attempted before binding or a one-shot phase
    /// transition was reused.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 value-bus phase transition is invalid")]
    Phase,
    /// IDs, writers, access order, moduli, or segment shapes are invalid.
    #[error("zk-X509 P-256 value-bus topology is invalid")]
    Topology,
    /// An execution access is not the corresponding arithmetic/input limb.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 value-bus source binding is invalid")]
    Source,
    /// A limb, bit decomposition, or field encoding is not canonical.
    #[error("zk-X509 P-256 value-bus range is invalid")]
    Range,
    /// Transcript challenges are zero, non-canonical, or repeated by lane.
    #[error("zk-X509 P-256 value-bus challenges are invalid")]
    Challenge,
    /// A product transition or segment boundary is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 value-bus product constraint is invalid")]
    Constraint,
    /// A sorted read differs from its unique writer.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 value-bus sorted adjacency is invalid")]
    Adjacency,
    /// An explicit same-modulus equality is false.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 value equality is invalid")]
    Equality,
    /// A scalar/base Boolean bridge is non-Boolean or unequal.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 Boolean bridge is invalid")]
    BooleanBridge,
    /// Execution and sorted terminal products differ.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 value-bus terminal products differ")]
    Terminal,
    /// Length or allocation arithmetic exceeded a fixed bound.
    #[error("zk-X509 P-256 value-bus resource bound is exceeded")]
    Resource,
}
/// Derive bus challenges only after execution and sorted base traces commit.
pub fn derive_zk_x509_p256_value_bus_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<P256ValueBusChallengesV1, TransparentStarkErrorV1> {
    let mut lanes = [P256ValueBusLaneChallengesV1 {
        terms: [F::ZERO; P256_VALUE_BUS_TUPLE_TERMS_V1],
    }; P256_VALUE_BUS_LANES_V1];
    for (lane, labels) in lanes.iter_mut().zip(P256_VALUE_BUS_CHALLENGE_LABELS_V1) {
        for (term, label) in lane.terms.iter_mut().zip(labels) {
            *term = transcript.challenge_field(label)?;
        }
    }
    Ok(P256ValueBusChallengesV1 { lanes })
}
/// Build both endpoints and fail closed unless the completed bus validates.
#[cfg(test)]
pub fn build_zk_x509_p256_value_bus_trace_v1(
    initial_values: &[P256InitialValueBindingV1],
    linked_operations: &[P256LinkedOperationV1],
    equalities: &[P256EqualityBindingV1],
    boolean_bridges: &[P256BooleanBridgeBindingV1],
    arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
    challenges: P256ValueBusChallengesV1,
) -> Result<P256ValueBusTraceV1, P256ValueBusErrorV1> {
    challenges.validate()?;
    let execution_events = execution_events_v1(
        initial_values,
        linked_operations,
        equalities,
        boolean_bridges,
        arithmetic_trace,
    )?;
    let sorted_events = sorted_events_v1(&execution_events)?;
    let trace = P256ValueBusTraceV1 {
        execution: build_endpoint_v1(
            P256ValueBusEndpointV1::Execution,
            &execution_events,
            challenges,
        )?,
        sorted: build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events, challenges)?,
    };
    trace.validate(
        initial_values,
        linked_operations,
        equalities,
        boolean_bridges,
        arithmetic_trace,
        challenges,
    )?;
    Ok(trace)
}
/// Read one unique writer cell from the committed execution endpoint.
///
/// The caller supplies the verifier-owned initial-value count, modulus, and value kind. Initial
/// writers occupy rows 48 through 63 of the segment whose index is their value ID. Derived writers
/// occupy the `c` slot of their producing arithmetic operation. This accessor regenerates that
/// address and rejects any fixed-row, endpoint, segment, range, or provenance mismatch; it never
/// searches for a proof-supplied address.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_value_bus_writer_location_v1(
    initial_value_count: usize,
    id: P256ValueIdV1,
    limb: usize,
    modulus: ZkX509P256ModulusV1,
    value_kind: P256ValueKindV1,
) -> Result<(usize, usize, P256ValueBusFixedAccessV1), P256ValueBusErrorV1> {
    if initial_value_count == 0 || limb >= P256_VALUE_BUS_LIMBS_V1 {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let id_index = usize::try_from(id.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
    let (segment_index, local_row, expected_kind) = if id_index < initial_value_count {
        if value_kind == P256ValueKindV1::Derived {
            return Err(P256ValueBusErrorV1::Topology);
        }
        (id_index, 3 * P256_VALUE_BUS_LIMBS_V1 + limb, value_kind)
    } else {
        if value_kind != P256ValueKindV1::Derived {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let operation = id_index
            .checked_sub(initial_value_count)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let row = limb
            .checked_mul(3)
            .and_then(|row| row.checked_add(2))
            .ok_or(P256ValueBusErrorV1::Resource)?;
        (operation, row, P256ValueKindV1::Derived)
    };
    let expected_fixed = P256ValueBusFixedAccessV1::Active {
        id,
        limb: u8::try_from(limb).map_err(|_| P256ValueBusErrorV1::Resource)?,
        access: P256ValueAccessKindV1::Write,
        modulus,
        value_kind: expected_kind,
    };
    Ok((segment_index, local_row, expected_fixed))
}
/// Read one unique writer cell from the challenged execution endpoint.
///
/// This compatibility-free internal projection exists only for differential tests of the challenged
/// trace. Production cross-chip consumers must use [`p256_value_bus_base_writer_limb_cell_v1`] so
/// no challenge-dependent material is needed before the joint MAIN base roots are committed.
#[cfg(test)]
pub fn p256_value_bus_writer_limb_cell_v1(
    trace: &P256ValueBusTraceV1,
    initial_value_count: usize,
    id: P256ValueIdV1,
    limb: usize,
    modulus: ZkX509P256ModulusV1,
    value_kind: P256ValueKindV1,
) -> Result<F, P256ValueBusErrorV1> {
    if trace.execution.endpoint != P256ValueBusEndpointV1::Execution {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let (segment_index, local_row, expected_fixed) =
        p256_value_bus_writer_location_v1(initial_value_count, id, limb, modulus, value_kind)?;
    let segment = trace
        .execution
        .segments
        .get(segment_index)
        .ok_or(P256ValueBusErrorV1::Topology)?;
    if segment.index != u32::try_from(segment_index).map_err(|_| P256ValueBusErrorV1::Resource)?
        || segment.rows.len() != P256_VALUE_BUS_SEGMENT_ROWS_V1
    {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let row = segment
        .rows
        .get(local_row)
        .ok_or(P256ValueBusErrorV1::Topology)?;
    if row.fixed != expected_fixed {
        return Err(P256ValueBusErrorV1::Source);
    }
    if F::canonical(row.value.0).is_none() || row.value.0 > u64::from(u16::MAX) {
        return Err(P256ValueBusErrorV1::Range);
    }
    Ok(row.value)
}
/// Read one unique writer cell from a challenge-independent execution endpoint.
///
/// The address is regenerated from the verifier-owned SSA topology. The
/// endpoint is never searched and no challenged product column participates,
/// so external-binding base construction can finish before X5B1.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_value_bus_base_writer_limb_cell_v1(
    endpoint: &P256ValueBusBaseEndpointTraceV1,
    initial_value_count: usize,
    id: P256ValueIdV1,
    limb: usize,
    modulus: ZkX509P256ModulusV1,
    value_kind: P256ValueKindV1,
) -> Result<F, P256ValueBusErrorV1> {
    if endpoint.endpoint != P256ValueBusEndpointV1::Execution {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let (segment_index, local_row, expected_fixed) =
        p256_value_bus_writer_location_v1(initial_value_count, id, limb, modulus, value_kind)?;
    let segment_count = endpoint.segment_count_v1()?;
    if segment_index >= segment_count {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let ordinal = segment_index
        .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
        .and_then(|offset| offset.checked_add(local_row))
        .ok_or(P256ValueBusErrorV1::Resource)?;
    let row = endpoint
        .rows
        .get(ordinal)
        .ok_or(P256ValueBusErrorV1::Topology)?;
    // Regenerate and authenticate the verifier-owned address before parsing
    // its witness value. This matches the challenged accessor and prevents a
    // coordinated wrong-address/nonzero-value cell from being misclassified
    // as a mere range failure.
    if row.fixed != expected_fixed {
        return Err(P256ValueBusErrorV1::Source);
    }
    validate_base_cell_v1(*row)?;
    Ok(row.value)
}
/// Exact committed execution cell at one flattened factor-row ordinal.
///
/// This is the narrow source projection used while constructing auxiliary cross-trace products. It
/// checks the execution endpoint and canonical segment addressing before returning the
/// verifier-fixed access and its committed value. The cross-trace AIR consumes the corresponding
/// opened `value` column directly; this native locator is not a verification oracle.
#[cfg(test)]
pub fn p256_value_bus_execution_source_cell_v1(
    trace: &P256ValueBusTraceV1,
    ordinal: usize,
) -> Result<(P256ValueBusFixedAccessV1, F), P256ValueBusErrorV1> {
    if trace.execution.endpoint != P256ValueBusEndpointV1::Execution {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let segment_index = ordinal / P256_VALUE_BUS_SEGMENT_ROWS_V1;
    let local_row = ordinal % P256_VALUE_BUS_SEGMENT_ROWS_V1;
    let segment = trace
        .execution
        .segments
        .get(segment_index)
        .ok_or(P256ValueBusErrorV1::Topology)?;
    if segment.index != u32::try_from(segment_index).map_err(|_| P256ValueBusErrorV1::Resource)?
        || segment.rows.len() != P256_VALUE_BUS_SEGMENT_ROWS_V1
    {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let row = segment
        .rows
        .get(local_row)
        .ok_or(P256ValueBusErrorV1::Topology)?;
    if F::canonical(row.value.0).is_none() || row.value.0 > u64::from(u16::MAX) {
        return Err(P256ValueBusErrorV1::Range);
    }
    Ok((row.fixed, row.value))
}
/// Read one logical cell from a challenge-independent execution endpoint.
///
/// Cross-writer products consume this projection after X5B1; they never
/// depend on a value-bus trace that already contains challenged products.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_value_bus_base_execution_source_cell_v1(
    endpoint: &P256ValueBusBaseEndpointTraceV1,
    ordinal: usize,
) -> Result<(P256ValueBusFixedAccessV1, F), P256ValueBusErrorV1> {
    if endpoint.endpoint != P256ValueBusEndpointV1::Execution {
        return Err(P256ValueBusErrorV1::Topology);
    }
    endpoint.source_cell_v1(ordinal)
}
#[cfg(test)]
impl P256ValueBusTraceV1 {
    /// Validate fixed topology, source binding, range checks, adjacency,
    /// assertion constraints, all segment products, and terminal equality.
    pub(crate) fn validate(
        &self,
        initial_values: &[P256InitialValueBindingV1],
        linked_operations: &[P256LinkedOperationV1],
        equalities: &[P256EqualityBindingV1],
        boolean_bridges: &[P256BooleanBridgeBindingV1],
        arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
        challenges: P256ValueBusChallengesV1,
    ) -> Result<(), P256ValueBusErrorV1> {
        challenges.validate()?;
        let execution_events = execution_events_v1(
            initial_values,
            linked_operations,
            equalities,
            boolean_bridges,
            arithmetic_trace,
        )?;
        let sorted_events = sorted_events_v1(&execution_events)?;
        self.execution.validate(
            P256ValueBusEndpointV1::Execution,
            &execution_events,
            true,
            challenges,
        )?;
        self.sorted.validate(
            P256ValueBusEndpointV1::Sorted,
            &sorted_events,
            false,
            challenges,
        )?;
        validate_sorted_adjacency_v1(&self.sorted)?;
        validate_equality_segments_v1(&self.execution, linked_operations.len(), equalities.len())?;
        validate_boolean_bridge_segments_v1(
            &self.execution,
            linked_operations.len(),
            equalities.len(),
            boolean_bridges.len(),
        )?;
        let terminal =
            evaluate_zk_x509_p256_value_bus_terminal_constraints_v1(&self.execution, &self.sorted)?;
        if terminal.iter().any(|constraint| *constraint != F::ZERO) {
            return Err(P256ValueBusErrorV1::Terminal);
        }
        Ok(())
    }
}
#[cfg(test)]
impl P256ValueBusEndpointTraceV1 {
    fn validate(
        &self,
        endpoint: P256ValueBusEndpointV1,
        expected: &[ExpectedAccessV1],
        bind_sources: bool,
        challenges: P256ValueBusChallengesV1,
    ) -> Result<(), P256ValueBusErrorV1> {
        if self.endpoint != endpoint
            || expected.is_empty()
            || !expected
                .len()
                .is_multiple_of(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            || self.segments.len() != expected.len() / P256_VALUE_BUS_SEGMENT_ROWS_V1
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let mut running = [F::ONE; P256_VALUE_BUS_LANES_V1];
        for (segment_index, segment) in self.segments.iter().enumerate() {
            let expected_index =
                u32::try_from(segment_index).map_err(|_| P256ValueBusErrorV1::Resource)?;
            if segment.index != expected_index
                || segment.rows.len() != P256_VALUE_BUS_SEGMENT_ROWS_V1
                || segment.product_before != running
                || !canonical_products_v1(segment.product_before)
                || !canonical_products_v1(segment.product_after)
            {
                return Err(P256ValueBusErrorV1::Constraint);
            }
            for (local_row, row) in segment.rows.iter().enumerate() {
                let ordinal = segment_index
                    .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
                    .and_then(|value| value.checked_add(local_row))
                    .ok_or(P256ValueBusErrorV1::Resource)?;
                let expected_row = expected.get(ordinal).ok_or(P256ValueBusErrorV1::Topology)?;
                if row.fixed != expected_row.fixed {
                    return Err(P256ValueBusErrorV1::Topology);
                }
                validate_row_range_v1(row)?;
                if bind_sources && expected_row.source_bound && row.value != expected_row.value {
                    return Err(P256ValueBusErrorV1::Source);
                }
                let constraints = evaluate_zk_x509_p256_value_bus_row_constraints_v1(
                    row.fixed, row, running, challenges,
                );
                if constraints.iter().any(|constraint| *constraint != F::ZERO) {
                    return Err(P256ValueBusErrorV1::Constraint);
                }
                running = row.product_after;
            }
            if segment.product_after != running {
                return Err(P256ValueBusErrorV1::Constraint);
            }
        }
        Ok(())
    }
    fn row(&self, ordinal: usize) -> Result<&P256ValueBusRowV1, P256ValueBusErrorV1> {
        let segment = ordinal / P256_VALUE_BUS_SEGMENT_ROWS_V1;
        let local = ordinal % P256_VALUE_BUS_SEGMENT_ROWS_V1;
        self.segments
            .get(segment)
            .and_then(|segment| segment.rows.get(local))
            .ok_or(P256ValueBusErrorV1::Topology)
    }
    fn terminal(&self) -> Result<[F; P256_VALUE_BUS_LANES_V1], P256ValueBusErrorV1> {
        self.segments
            .last()
            .map(|segment| segment.product_after)
            .ok_or(P256ValueBusErrorV1::Topology)
    }
}
/// Low-degree constraints for one range-checked product transition.
#[cfg(test)]
pub fn evaluate_zk_x509_p256_value_bus_row_constraints_v1(
    fixed: P256ValueBusFixedAccessV1,
    row: &P256ValueBusRowV1,
    expected_before: [F; P256_VALUE_BUS_LANES_V1],
    challenges: P256ValueBusChallengesV1,
) -> Vec<F> {
    let mut constraints =
        Vec::with_capacity(2 * P256_VALUE_BUS_LIMBS_V1 + 2 * P256_VALUE_BUS_LANES_V1 + 1);
    let mut packed = F::ZERO;
    for (index, bit) in row.value_bits.iter().copied().enumerate() {
        constraints.push(bit.mul(bit.sub(F::ONE)));
        packed = packed.add(bit.mul(F(1_u64 << index)));
        if fixed == P256ValueBusFixedAccessV1::Inactive {
            constraints.push(bit);
        }
    }
    constraints.push(row.value.sub(packed));
    if fixed == P256ValueBusFixedAccessV1::Inactive {
        constraints.push(row.value);
    }
    for (lane, expected_before) in expected_before.iter().copied().enumerate() {
        constraints.push(row.product_before[lane].sub(expected_before));
        let factor = compress_access_v1(fixed, row.value, challenges.lanes[lane]);
        constraints.push(row.product_after[lane].sub(row.product_before[lane].mul(factor)));
    }
    constraints
}
/// Four terminal constraints equating execution and sorted products.
#[cfg(test)]
pub fn evaluate_zk_x509_p256_value_bus_terminal_constraints_v1(
    execution: &P256ValueBusEndpointTraceV1,
    sorted: &P256ValueBusEndpointTraceV1,
) -> Result<[F; P256_VALUE_BUS_LANES_V1], P256ValueBusErrorV1> {
    if execution.endpoint != P256ValueBusEndpointV1::Execution
        || sorted.endpoint != P256ValueBusEndpointV1::Sorted
        || execution.segments.len() != sorted.segments.len()
    {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let execution = execution.terminal()?;
    let sorted = sorted.terminal()?;
    Ok(core::array::from_fn(|lane| {
        execution[lane].sub(sorted[lane])
    }))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ValueMetadataV1 {
    modulus: ZkX509P256ModulusV1,
    value_kind: P256ValueKindV1,
    limbs: [u16; P256_VALUE_BUS_LIMBS_V1],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ExpectedAccessV1 {
    fixed: P256ValueBusFixedAccessV1,
    value: F,
    source_bound: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl AsMut<[F]> for ExpectedAccessV1 {
    fn as_mut(&mut self) -> &mut [F] {
        core::slice::from_mut(&mut self.value)
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ExpectedAccessV1 {
    const fn inactive() -> Self {
        Self {
            fixed: P256ValueBusFixedAccessV1::Inactive,
            value: F::ZERO,
            source_bound: false,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn execution_events_v1(
    initial_values: &[P256InitialValueBindingV1],
    linked_operations: &[P256LinkedOperationV1],
    equalities: &[P256EqualityBindingV1],
    boolean_bridges: &[P256BooleanBridgeBindingV1],
    arithmetic_trace: &ZkX509P256ArithmeticTraceV1,
) -> Result<super::private_table::PrivateTableV1<ExpectedAccessV1>, P256ValueBusErrorV1> {
    let metadata = validate_value_topology_v1(
        initial_values,
        linked_operations,
        equalities,
        boolean_bridges,
    )?;
    arithmetic_trace
        .validate()
        .map_err(map_arithmetic_error_v1)?;
    let expected_arithmetic_rows = linked_operations
        .len()
        .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
        .ok_or(P256ValueBusErrorV1::Resource)?;
    if arithmetic_trace.rows() != expected_arithmetic_rows {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let segments = linked_operations
        .len()
        .checked_add(equalities.len())
        .and_then(|value| value.checked_add(boolean_bridges.len()))
        .ok_or(P256ValueBusErrorV1::Resource)?;
    let rows = segments
        .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
        .ok_or(P256ValueBusErrorV1::Resource)?;
    let mut events = super::private_table::PrivateTableV1::new(
        Vec::new(),
        super::private_table::zeroize_field_rows_v1,
    );
    events
        .try_reserve_exact(rows)
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    for (operation_index, linked) in linked_operations.iter().copied().enumerate() {
        let first_row = operation_index
            .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let fixed = arithmetic_trace
            .fixed
            .get(first_row)
            .ok_or(P256ValueBusErrorV1::Topology)?;
        if fixed.operation as usize != operation_index
            || fixed.coefficient != 0
            || fixed.kind != linked.operation.kind
            || fixed.modulus != linked.operation.modulus
        {
            return Err(P256ValueBusErrorV1::Source);
        }
        let operation_limbs = [
            bytes_be_to_limbs_le_v1(linked.operation.a),
            bytes_be_to_limbs_le_v1(linked.operation.b),
            bytes_be_to_limbs_le_v1(linked.operation.c),
        ];
        let ids = [linked.a, linked.b, linked.c];
        let accesses = [
            P256ValueAccessKindV1::Read,
            P256ValueAccessKindV1::Read,
            P256ValueAccessKindV1::Write,
        ];
        let pointwise_operation_limbs: [[u16; 3]; P256_VALUE_BUS_LIMBS_V1] =
            core::array::from_fn(|limb| {
                [
                    operation_limbs[0][limb],
                    operation_limbs[1][limb],
                    operation_limbs[2][limb],
                ]
            });
        for (limb, expected_operands) in pointwise_operation_limbs.into_iter().enumerate() {
            let arithmetic_limbs =
                p256_arithmetic_operand_limbs_v1(arithmetic_trace, operation_index, limb)
                    .map_err(map_arithmetic_error_v1)?;
            for (((id, access), expected_operand), arithmetic_limb) in ids
                .into_iter()
                .zip(accesses)
                .zip(expected_operands)
                .zip(arithmetic_limbs)
            {
                let expected_value = F(u64::from(expected_operand));
                if arithmetic_limb != expected_value {
                    return Err(P256ValueBusErrorV1::Source);
                }
                let id_index = usize::try_from(id.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
                let value_metadata = metadata
                    .get(id_index)
                    .ok_or(P256ValueBusErrorV1::Topology)?;
                events.push(ExpectedAccessV1 {
                    fixed: P256ValueBusFixedAccessV1::Active {
                        id,
                        limb: limb as u8,
                        access,
                        modulus: linked.operation.modulus,
                        value_kind: value_metadata.value_kind,
                    },
                    value: arithmetic_limb,
                    source_bound: true,
                });
            }
        }
        if let Some(initial) = initial_values.get(operation_index).copied() {
            let value_metadata = metadata
                .get(operation_index)
                .ok_or(P256ValueBusErrorV1::Topology)?;
            for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
                events.push(ExpectedAccessV1 {
                    fixed: P256ValueBusFixedAccessV1::Active {
                        id: initial.id,
                        limb: limb as u8,
                        access: P256ValueAccessKindV1::Write,
                        modulus: initial.modulus,
                        value_kind: value_metadata.value_kind,
                    },
                    value: F(u64::from(value_metadata.limbs[limb])),
                    source_bound: true,
                });
            }
        } else {
            events.extend(core::iter::repeat_n(
                ExpectedAccessV1::inactive(),
                P256_VALUE_BUS_LIMBS_V1,
            ));
        }
    }
    for equality in equalities.iter().copied() {
        append_assertion_segment_v1(&mut events, &metadata, equality.left, equality.right)?;
    }
    for bridge in boolean_bridges.iter().copied() {
        append_assertion_segment_v1(&mut events, &metadata, bridge.scalar_bit, bridge.base_bit)?;
    }
    if events.len() != rows {
        return Err(P256ValueBusErrorV1::Topology);
    }
    validate_unique_writers_v1(&events, metadata.len())?;
    Ok(events)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_value_topology_v1(
    initial_values: &[P256InitialValueBindingV1],
    linked_operations: &[P256LinkedOperationV1],
    equalities: &[P256EqualityBindingV1],
    boolean_bridges: &[P256BooleanBridgeBindingV1],
) -> Result<super::private_table::PrivateTableV1<ValueMetadataV1>, P256ValueBusErrorV1> {
    if initial_values.is_empty()
        || linked_operations.is_empty()
        || initial_values.len() > linked_operations.len()
    {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let value_count = initial_values
        .len()
        .checked_add(linked_operations.len())
        .ok_or(P256ValueBusErrorV1::Resource)?;
    let _last_id = u32::try_from(value_count - 1).map_err(|_| P256ValueBusErrorV1::Resource)?;
    let mut metadata =
        super::private_table::PrivateTableV1::new(Vec::new(), |rows: &mut [ValueMetadataV1]| {
            for row in rows {
                super::private_table::zeroize_words_v1(&mut row.limbs);
            }
        });
    metadata
        .try_reserve_exact(value_count)
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    for (index, initial) in initial_values.iter().copied().enumerate() {
        let expected_id = u32::try_from(index).map_err(|_| P256ValueBusErrorV1::Resource)?;
        if initial.id != P256ValueIdV1(expected_id)
            || initial.value >= modulus_bytes_v1(initial.modulus)
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        metadata.push(ValueMetadataV1 {
            modulus: initial.modulus,
            value_kind: match initial.kind {
                P256InitialValueKindV1::Input => P256ValueKindV1::Input,
                P256InitialValueKindV1::Constant => P256ValueKindV1::Constant,
            },
            limbs: bytes_be_to_limbs_le_v1(initial.value),
        });
    }
    for (operation_index, linked) in linked_operations.iter().copied().enumerate() {
        let c_index = initial_values
            .len()
            .checked_add(operation_index)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let expected_c =
            P256ValueIdV1(u32::try_from(c_index).map_err(|_| P256ValueBusErrorV1::Resource)?);
        if linked.c != expected_c
            || linked.operation.a >= modulus_bytes_v1(linked.operation.modulus)
            || linked.operation.b >= modulus_bytes_v1(linked.operation.modulus)
            || linked.operation.c >= modulus_bytes_v1(linked.operation.modulus)
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        for id in [linked.a, linked.b] {
            let index = usize::try_from(id.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
            let operand = metadata.get(index).ok_or(P256ValueBusErrorV1::Topology)?;
            if operand.modulus != linked.operation.modulus {
                return Err(P256ValueBusErrorV1::Topology);
            }
        }
        metadata.push(ValueMetadataV1 {
            modulus: linked.operation.modulus,
            value_kind: P256ValueKindV1::Derived,
            limbs: bytes_be_to_limbs_le_v1(linked.operation.c),
        });
    }
    for equality in equalities.iter().copied() {
        if equality.left == equality.right {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let left = value_metadata_v1(&metadata, equality.left)?;
        let right = value_metadata_v1(&metadata, equality.right)?;
        if left.modulus != right.modulus {
            return Err(P256ValueBusErrorV1::Topology);
        }
    }
    for bridge in boolean_bridges.iter().copied() {
        if bridge.scalar_bit == bridge.base_bit
            || value_metadata_v1(&metadata, bridge.scalar_bit)?.modulus
                != ZkX509P256ModulusV1::ScalarField
            || value_metadata_v1(&metadata, bridge.base_bit)?.modulus
                != ZkX509P256ModulusV1::BaseField
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
    }
    Ok(metadata)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn value_metadata_v1(
    metadata: &[ValueMetadataV1],
    id: P256ValueIdV1,
) -> Result<ValueMetadataV1, P256ValueBusErrorV1> {
    let index = usize::try_from(id.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
    metadata
        .get(index)
        .copied()
        .ok_or(P256ValueBusErrorV1::Topology)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn append_assertion_segment_v1(
    events: &mut Vec<ExpectedAccessV1>,
    metadata: &[ValueMetadataV1],
    left_id: P256ValueIdV1,
    right_id: P256ValueIdV1,
) -> Result<(), P256ValueBusErrorV1> {
    let left = value_metadata_v1(metadata, left_id)?;
    let right = value_metadata_v1(metadata, right_id)?;
    for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
        for (id, value) in [(left_id, left), (right_id, right)] {
            events.push(ExpectedAccessV1 {
                fixed: P256ValueBusFixedAccessV1::Active {
                    id,
                    limb: limb as u8,
                    access: P256ValueAccessKindV1::Read,
                    modulus: value.modulus,
                    value_kind: value.value_kind,
                },
                value: F(u64::from(value.limbs[limb])),
                source_bound: false,
            });
        }
    }
    events.extend(core::iter::repeat_n(
        ExpectedAccessV1::inactive(),
        P256_VALUE_BUS_SEGMENT_ROWS_V1 - 2 * P256_VALUE_BUS_LIMBS_V1,
    ));
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_unique_writers_v1(
    events: &[ExpectedAccessV1],
    value_count: usize,
) -> Result<(), P256ValueBusErrorV1> {
    let cells = value_count
        .checked_mul(P256_VALUE_BUS_LIMBS_V1)
        .ok_or(P256ValueBusErrorV1::Resource)?;
    let mut writers = Vec::new();
    writers
        .try_reserve_exact(cells)
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    writers.resize(cells, 0_u8);
    for event in events {
        let P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            access: P256ValueAccessKindV1::Write,
            ..
        } = event.fixed
        else {
            continue;
        };
        let cell = usize::try_from(id.0)
            .ok()
            .and_then(|id| id.checked_mul(P256_VALUE_BUS_LIMBS_V1))
            .and_then(|cell| cell.checked_add(usize::from(limb)))
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let writer = writers.get_mut(cell).ok_or(P256ValueBusErrorV1::Topology)?;
        *writer = writer.checked_add(1).ok_or(P256ValueBusErrorV1::Topology)?;
    }
    if writers.iter().any(|writers| *writers != 1) {
        return Err(P256ValueBusErrorV1::Topology);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn sorted_events_v1(
    execution: &[ExpectedAccessV1],
) -> Result<super::private_table::PrivateTableV1<ExpectedAccessV1>, P256ValueBusErrorV1> {
    let mut active = super::private_table::PrivateTableV1::new(
        Vec::new(),
        super::private_table::zeroize_field_rows_v1,
    );
    active
        .try_reserve_exact(execution.len())
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    for event in execution.iter().copied() {
        if event.fixed != P256ValueBusFixedAccessV1::Inactive {
            active.push(event);
        }
    }
    // Equal addressed accesses have identical private values in a valid trace.
    // Sorting in place avoids an unowned private merge-sort allocation.
    active.sort_unstable_by_key(|event| fixed_sort_key_v1(event.fixed));
    let padding = execution.len() - active.len();
    active
        .try_reserve_exact(padding)
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    active.extend(core::iter::repeat_n(ExpectedAccessV1::inactive(), padding));
    Ok(active)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fixed_sort_key_v1(fixed: P256ValueBusFixedAccessV1) -> (u32, u8, u8) {
    match fixed {
        P256ValueBusFixedAccessV1::Inactive => (u32::MAX, u8::MAX, u8::MAX),
        P256ValueBusFixedAccessV1::Active {
            id, limb, access, ..
        } => (
            id.0,
            limb,
            match access {
                P256ValueAccessKindV1::Write => 0,
                P256ValueAccessKindV1::Read => 1,
            },
        ),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_trace_material_topology_v1(
    material: &P256EcdsaTraceMaterialV1,
    expected: &P256EcdsaTopologyV1,
) -> Result<(), P256ValueBusErrorV1> {
    validate_value_bus_topology_components_v1(
        material.role,
        &material.initial_values,
        &material.linked_operations,
        &material.equalities,
        &material.boolean_bridges,
        expected,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_value_bus_topology_components_v1(
    role: P256EcdsaRoleV1,
    initial_values: &[P256InitialValueBindingV1],
    linked_operations: &[P256LinkedOperationV1],
    equalities: &[P256EqualityBindingV1],
    boolean_bridges: &[P256BooleanBridgeBindingV1],
    expected: &P256EcdsaTopologyV1,
) -> Result<(), P256ValueBusErrorV1> {
    if expected.role != role
        || initial_values.len() != expected.initial_values.len()
        || linked_operations.len() != expected.linked_operations.len()
        || equalities != expected.equalities
        || boolean_bridges != expected.boolean_bridges
        || initial_values
            .iter()
            .zip(&expected.initial_values)
            .any(|(actual, expected)| {
                actual.id != expected.id
                    || actual.modulus != expected.modulus
                    || actual.kind != expected.kind
            })
        || linked_operations
            .iter()
            .zip(&expected.linked_operations)
            .any(|(actual, expected)| {
                actual.a != expected.a
                    || actual.b != expected.b
                    || actual.c != expected.c
                    || actual.operation.kind != expected.kind
                    || actual.operation.modulus != expected.modulus
            })
    {
        return Err(P256ValueBusErrorV1::Topology);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_base_endpoint_v1(
    endpoint: P256ValueBusEndpointV1,
    events: &[ExpectedAccessV1],
) -> Result<P256ValueBusBaseEndpointTraceV1, P256ValueBusErrorV1> {
    if events.is_empty() || !events.len().is_multiple_of(P256_VALUE_BUS_SEGMENT_ROWS_V1) {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let mut trace = P256ValueBusBaseEndpointTraceV1 {
        endpoint,
        rows: Vec::new(),
    };
    trace
        .rows
        .try_reserve_exact(events.len())
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    for event in events {
        let cell = P256ValueBusBaseCellV1 {
            fixed: event.fixed,
            value: event.value,
        };
        validate_base_cell_v1(cell)?;
        trace.rows.push(cell);
    }
    Ok(trace)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_base_cell_v1(cell: P256ValueBusBaseCellV1) -> Result<(), P256ValueBusErrorV1> {
    if F::canonical(cell.value.0).is_none()
        || cell.value.0 > u64::from(u16::MAX)
        || (cell.fixed == P256ValueBusFixedAccessV1::Inactive && cell.value != F::ZERO)
        || matches!(
            cell.fixed,
            P256ValueBusFixedAccessV1::Active { limb, .. }
                if usize::from(limb) >= P256_VALUE_BUS_LIMBS_V1
        )
    {
        return Err(P256ValueBusErrorV1::Range);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn sorted_base_cells_v1(
    execution: &[P256ValueBusBaseCellV1],
) -> Result<super::private_table::PrivateTableV1<P256ValueBusBaseCellV1>, P256ValueBusErrorV1> {
    let mut sorted = super::private_table::PrivateTableV1::new(
        Vec::new(),
        super::private_table::zeroize_field_rows_v1,
    );
    sorted
        .try_reserve_exact(execution.len())
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    sorted.extend(
        execution
            .iter()
            .copied()
            .filter(|row| row.fixed != P256ValueBusFixedAccessV1::Inactive),
    );
    sorted.sort_unstable_by_key(|row| fixed_sort_key_v1(row.fixed));
    let padding = execution.len() - sorted.len();
    sorted.extend(core::iter::repeat_n(
        P256ValueBusBaseCellV1 {
            fixed: P256ValueBusFixedAccessV1::Inactive,
            value: F::ZERO,
        },
        padding,
    ));
    Ok(sorted)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fixed_access_from_numeric_row_v1(
    fixed: &[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1],
    slot: usize,
) -> Result<P256ValueBusFixedAccessV1, P256ValueBusErrorV1> {
    if slot >= P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let offset = stark_fixed_offset_v1(slot);
    let active = fixed[offset + STARK_FIXED_ACTIVE];
    if active == F::ZERO {
        return Ok(P256ValueBusFixedAccessV1::Inactive);
    }
    if active != F::ONE {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let id = u32::try_from(fixed[offset + STARK_FIXED_ID].0)
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    let limb = u8::try_from(fixed[offset + STARK_FIXED_LIMB].0)
        .map_err(|_| P256ValueBusErrorV1::Topology)?;
    let access = match fixed[offset + STARK_FIXED_ACCESS].0 {
        1 => P256ValueAccessKindV1::Write,
        2 => P256ValueAccessKindV1::Read,
        _ => return Err(P256ValueBusErrorV1::Topology),
    };
    let modulus = match fixed[offset + STARK_FIXED_MODULUS].0 {
        1 => ZkX509P256ModulusV1::BaseField,
        2 => ZkX509P256ModulusV1::ScalarField,
        _ => return Err(P256ValueBusErrorV1::Topology),
    };
    let value_kind = match fixed[offset + STARK_FIXED_VALUE_KIND].0 {
        1 => P256ValueKindV1::Input,
        2 => P256ValueKindV1::Constant,
        3 => P256ValueKindV1::Derived,
        _ => return Err(P256ValueBusErrorV1::Topology),
    };
    Ok(P256ValueBusFixedAccessV1::Active {
        id: P256ValueIdV1(id),
        limb,
        access,
        modulus,
        value_kind,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_base_endpoint_against_fixed_v1(
    endpoint: &P256ValueBusBaseEndpointTraceV1,
    fixed: &P256ValueBusStarkFixedProviderV1,
) -> Result<(), P256ValueBusErrorV1> {
    if endpoint.rows.len() != fixed.logical_factor_rows_v1() {
        return Err(P256ValueBusErrorV1::Topology);
    }
    for (ordinal, row) in endpoint.rows.iter().copied().enumerate() {
        let packed = ordinal / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let slot = ordinal % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let expected = fixed_access_from_numeric_row_v1(&fixed.row_v1(packed)?, slot)?;
        if row.fixed != expected {
            return Err(P256ValueBusErrorV1::Topology);
        }
        // Classify an address/schedule substitution as topology even when the
        // substituted inactive selector also makes the retained value invalid
        // padding. Once the verifier-owned address agrees, value and padding
        // canonicality retain their precise `Range` classification.
        validate_base_cell_v1(row)?;
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_base_equality_segments_v1(
    execution: &P256ValueBusBaseEndpointTraceV1,
    arithmetic_segments: usize,
    equalities: &[P256EqualityBindingV1],
) -> Result<(), P256ValueBusErrorV1> {
    for (equality, binding) in equalities.iter().enumerate() {
        let first = arithmetic_segments
            .checked_add(equality)
            .and_then(|segment| segment.checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1))
            .ok_or(P256ValueBusErrorV1::Resource)?;
        for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
            let left = execution
                .rows
                .get(first + 2 * limb)
                .ok_or(P256ValueBusErrorV1::Topology)?;
            let right = execution
                .rows
                .get(first + 2 * limb + 1)
                .ok_or(P256ValueBusErrorV1::Topology)?;
            if left.value != right.value
                || !matches!(
                    left.fixed,
                    P256ValueBusFixedAccessV1::Active {
                        id,
                        limb: actual_limb,
                        access: P256ValueAccessKindV1::Read,
                        ..
                    } if id == binding.left && usize::from(actual_limb) == limb
                )
                || !matches!(
                    right.fixed,
                    P256ValueBusFixedAccessV1::Active {
                        id,
                        limb: actual_limb,
                        access: P256ValueAccessKindV1::Read,
                        ..
                    } if id == binding.right && usize::from(actual_limb) == limb
                )
            {
                return Err(P256ValueBusErrorV1::Equality);
            }
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_base_boolean_bridge_segments_v1(
    execution: &P256ValueBusBaseEndpointTraceV1,
    arithmetic_segments: usize,
    equality_segments: usize,
    bridges: &[P256BooleanBridgeBindingV1],
) -> Result<(), P256ValueBusErrorV1> {
    let first_bridge = arithmetic_segments
        .checked_add(equality_segments)
        .ok_or(P256ValueBusErrorV1::Resource)?;
    for (bridge, binding) in bridges.iter().enumerate() {
        let first = first_bridge
            .checked_add(bridge)
            .and_then(|segment| segment.checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1))
            .ok_or(P256ValueBusErrorV1::Resource)?;
        for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
            let scalar = execution
                .rows
                .get(first + 2 * limb)
                .ok_or(P256ValueBusErrorV1::Topology)?;
            let base = execution
                .rows
                .get(first + 2 * limb + 1)
                .ok_or(P256ValueBusErrorV1::Topology)?;
            let expected = if limb == 0 {
                scalar.value == base.value
                    && matches!(scalar.value, F::ZERO | F::ONE)
                    && matches!(base.value, F::ZERO | F::ONE)
            } else {
                scalar.value == F::ZERO && base.value == F::ZERO
            };
            if !expected
                || !matches!(
                    scalar.fixed,
                    P256ValueBusFixedAccessV1::Active {
                        id,
                        limb: actual_limb,
                        access: P256ValueAccessKindV1::Read,
                        modulus: ZkX509P256ModulusV1::ScalarField,
                        ..
                    } if id == binding.scalar_bit && usize::from(actual_limb) == limb
                )
                || !matches!(
                    base.fixed,
                    P256ValueBusFixedAccessV1::Active {
                        id,
                        limb: actual_limb,
                        access: P256ValueAccessKindV1::Read,
                        modulus: ZkX509P256ModulusV1::BaseField,
                        ..
                    } if id == binding.base_bit && usize::from(actual_limb) == limb
                )
            {
                return Err(P256ValueBusErrorV1::BooleanBridge);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
fn build_endpoint_v1(
    endpoint: P256ValueBusEndpointV1,
    events: &[ExpectedAccessV1],
    challenges: P256ValueBusChallengesV1,
) -> Result<P256ValueBusEndpointTraceV1, P256ValueBusErrorV1> {
    if events.is_empty() || !events.len().is_multiple_of(P256_VALUE_BUS_SEGMENT_ROWS_V1) {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let segment_count = events.len() / P256_VALUE_BUS_SEGMENT_ROWS_V1;
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(segment_count)
        .map_err(|_| P256ValueBusErrorV1::Resource)?;
    let mut running = [F::ONE; P256_VALUE_BUS_LANES_V1];
    for (segment_index, event_segment) in events
        .chunks_exact(P256_VALUE_BUS_SEGMENT_ROWS_V1)
        .enumerate()
    {
        let product_before = running;
        let mut rows = Vec::new();
        rows.try_reserve_exact(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            .map_err(|_| P256ValueBusErrorV1::Resource)?;
        for event in event_segment {
            let value_bits = if event.fixed == P256ValueBusFixedAccessV1::Inactive {
                [F::ZERO; P256_VALUE_BUS_LIMBS_V1]
            } else {
                core::array::from_fn(|bit| F((event.value.0 >> bit) & 1))
            };
            let product_after = core::array::from_fn(|lane| {
                running[lane].mul(compress_access_v1(
                    event.fixed,
                    event.value,
                    challenges.lanes[lane],
                ))
            });
            rows.push(P256ValueBusRowV1 {
                fixed: event.fixed,
                value: event.value,
                value_bits,
                product_before: running,
                product_after,
            });
            running = product_after;
        }
        segments.push(P256ValueBusSegmentV1 {
            index: u32::try_from(segment_index).map_err(|_| P256ValueBusErrorV1::Resource)?,
            product_before,
            rows,
            product_after: running,
        });
    }
    Ok(P256ValueBusEndpointTraceV1 { endpoint, segments })
}
#[cfg(test)]
fn validate_row_range_v1(row: &P256ValueBusRowV1) -> Result<(), P256ValueBusErrorV1> {
    if F::canonical(row.value.0).is_none()
        || row
            .value_bits
            .iter()
            .chain(row.product_before.iter())
            .chain(row.product_after.iter())
            .any(|value| F::canonical(value.0).is_none())
    {
        return Err(P256ValueBusErrorV1::Range);
    }
    let mut packed = F::ZERO;
    for (index, bit) in row.value_bits.iter().copied().enumerate() {
        if bit != F::ZERO && bit != F::ONE {
            return Err(P256ValueBusErrorV1::Range);
        }
        packed = packed.add(bit.mul(F(1_u64 << index)));
    }
    if row.value != packed
        || (row.fixed == P256ValueBusFixedAccessV1::Inactive
            && (row.value != F::ZERO || row.value_bits.iter().any(|bit| *bit != F::ZERO)))
    {
        return Err(P256ValueBusErrorV1::Range);
    }
    if let P256ValueBusFixedAccessV1::Active { limb, .. } = row.fixed
        && usize::from(limb) >= P256_VALUE_BUS_LIMBS_V1
    {
        return Err(P256ValueBusErrorV1::Topology);
    }
    Ok(())
}
#[cfg(test)]
fn validate_sorted_adjacency_v1(
    sorted: &P256ValueBusEndpointTraceV1,
) -> Result<(), P256ValueBusErrorV1> {
    let mut previous: Option<(P256ValueIdV1, u8, F)> = None;
    let rows = sorted
        .segments
        .len()
        .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
        .ok_or(P256ValueBusErrorV1::Resource)?;
    let mut inactive = false;
    for ordinal in 0..rows {
        let row = sorted.row(ordinal)?;
        let P256ValueBusFixedAccessV1::Active {
            id, limb, access, ..
        } = row.fixed
        else {
            inactive = true;
            continue;
        };
        if inactive {
            return Err(P256ValueBusErrorV1::Adjacency);
        }
        let group = (id, limb);
        match (previous, access) {
            (None, P256ValueAccessKindV1::Write) => {}
            (Some((previous_id, previous_limb, _)), P256ValueAccessKindV1::Write)
                if (previous_id, previous_limb) != group => {}
            (Some((previous_id, previous_limb, previous_value)), P256ValueAccessKindV1::Read)
                if (previous_id, previous_limb) == group && previous_value == row.value => {}
            _ => return Err(P256ValueBusErrorV1::Adjacency),
        }
        previous = Some((id, limb, row.value));
    }
    Ok(())
}
#[cfg(test)]
fn validate_equality_segments_v1(
    execution: &P256ValueBusEndpointTraceV1,
    arithmetic_segments: usize,
    equality_segments: usize,
) -> Result<(), P256ValueBusErrorV1> {
    for equality in 0..equality_segments {
        let segment = arithmetic_segments
            .checked_add(equality)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let first = segment
            .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
            let left = execution.row(
                first
                    .checked_add(2 * limb)
                    .ok_or(P256ValueBusErrorV1::Resource)?,
            )?;
            let right = execution.row(
                first
                    .checked_add(2 * limb + 1)
                    .ok_or(P256ValueBusErrorV1::Resource)?,
            )?;
            if left.value.sub(right.value) != F::ZERO {
                return Err(P256ValueBusErrorV1::Equality);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_boolean_bridge_segments_v1(
    execution: &P256ValueBusEndpointTraceV1,
    arithmetic_segments: usize,
    equality_segments: usize,
    bridge_segments: usize,
) -> Result<(), P256ValueBusErrorV1> {
    let first_bridge = arithmetic_segments
        .checked_add(equality_segments)
        .ok_or(P256ValueBusErrorV1::Resource)?;
    for bridge in 0..bridge_segments {
        let segment = first_bridge
            .checked_add(bridge)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let first = segment
            .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
            let scalar = execution.row(
                first
                    .checked_add(2 * limb)
                    .ok_or(P256ValueBusErrorV1::Resource)?,
            )?;
            let base = execution.row(
                first
                    .checked_add(2 * limb + 1)
                    .ok_or(P256ValueBusErrorV1::Resource)?,
            )?;
            let invalid = if limb == 0 {
                scalar.value.mul(scalar.value.sub(F::ONE)) != F::ZERO
                    || base.value.mul(base.value.sub(F::ONE)) != F::ZERO
                    || scalar.value != base.value
            } else {
                scalar.value != F::ZERO || base.value != F::ZERO
            };
            if invalid {
                return Err(P256ValueBusErrorV1::BooleanBridge);
            }
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compress_access_v1(
    fixed: P256ValueBusFixedAccessV1,
    value: F,
    challenges: P256ValueBusLaneChallengesV1,
) -> F {
    let P256ValueBusFixedAccessV1::Active {
        id,
        limb,
        access,
        modulus,
        value_kind,
    } = fixed
    else {
        return F::ONE;
    };
    let terms = challenges.terms;
    terms[0]
        .add(terms[1].mul(F(u64::from(id.0))))
        .add(terms[2].mul(F(u64::from(limb))))
        .add(terms[3].mul(F(match access {
            P256ValueAccessKindV1::Write => 1,
            P256ValueAccessKindV1::Read => 2,
        })))
        .add(terms[4].mul(F(match modulus {
            ZkX509P256ModulusV1::BaseField => 1,
            ZkX509P256ModulusV1::ScalarField => 2,
        })))
        .add(terms[5].mul(F(match value_kind {
            P256ValueKindV1::Input => 1,
            P256ValueKindV1::Constant => 2,
            P256ValueKindV1::Derived => 3,
        })))
        .add(terms[6].mul(value))
}
#[cfg(test)]
fn canonical_products_v1(products: [F; P256_VALUE_BUS_LANES_V1]) -> bool {
    products
        .iter()
        .all(|product| F::canonical(product.0).is_some())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn bytes_be_to_limbs_le_v1(bytes: [u8; 32]) -> [u16; P256_VALUE_BUS_LIMBS_V1] {
    core::array::from_fn(|index| {
        let low = 31 - 2 * index;
        u16::from_le_bytes([bytes[low], bytes[low - 1]])
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn modulus_bytes_v1(modulus: ZkX509P256ModulusV1) -> [u8; 32] {
    match modulus {
        ZkX509P256ModulusV1::BaseField => P256_BASE_MODULUS_BE_V1,
        ZkX509P256ModulusV1::ScalarField => P256_SCALAR_MODULUS_BE_V1,
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn map_arithmetic_error_v1(error: ZkX509P256AirErrorV1) -> P256ValueBusErrorV1 {
    match error {
        ZkX509P256AirErrorV1::Topology => P256ValueBusErrorV1::Topology,
        ZkX509P256AirErrorV1::Allocation => P256ValueBusErrorV1::Resource,
        _ => P256ValueBusErrorV1::Source,
    }
}
const STARK_BASE_SLOT_WIDTH: usize = 1 + P256_VALUE_BUS_LIMBS_V1;
const STARK_BASE_VALUE: usize = 0;
const STARK_BASE_BITS: usize = STARK_BASE_VALUE + 1;
const STARK_FIXED_SLOT_WIDTH: usize = 10;
const STARK_FIXED_ACTIVE: usize = 0;
const STARK_FIXED_ID: usize = STARK_FIXED_ACTIVE + 1;
const STARK_FIXED_LIMB: usize = STARK_FIXED_ID + 1;
const STARK_FIXED_ACCESS: usize = STARK_FIXED_LIMB + 1;
const STARK_FIXED_MODULUS: usize = STARK_FIXED_ACCESS + 1;
const STARK_FIXED_VALUE_KIND: usize = STARK_FIXED_MODULUS + 1;
const STARK_FIXED_PADDING: usize = STARK_FIXED_VALUE_KIND + 1;
const STARK_FIXED_EQUAL_NEXT: usize = STARK_FIXED_PADDING + 1;
const STARK_FIXED_BOOLEAN: usize = STARK_FIXED_EQUAL_NEXT + 1;
const STARK_FIXED_ZERO: usize = STARK_FIXED_BOOLEAN + 1;
const STARK_FIXED_FIRST: usize = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * STARK_FIXED_SLOT_WIDTH;
const STARK_FIXED_CONTINUATION: usize = STARK_FIXED_FIRST + 1;
const fn stark_base_offset_v1(slot: usize) -> usize {
    slot * STARK_BASE_SLOT_WIDTH
}
const fn stark_fixed_offset_v1(slot: usize) -> usize {
    slot * STARK_FIXED_SLOT_WIDTH
}
const fn stark_aux_product_offset_v1(state: usize) -> usize {
    state * P256_VALUE_BUS_LANES_V1
}
const _: () = assert!(
    P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * STARK_BASE_SLOT_WIDTH
        == P256_VALUE_BUS_STARK_BASE_WIDTH_V1
);
const _: () = assert!(
    (P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + 1) * P256_VALUE_BUS_LANES_V1
        == P256_VALUE_BUS_STARK_AUX_WIDTH_V1
);
const _: () = assert!(STARK_FIXED_ZERO + 1 == STARK_FIXED_SLOT_WIDTH);
const _: () = assert!(STARK_FIXED_CONTINUATION + 1 == P256_VALUE_BUS_STARK_FIXED_WIDTH_V1);
/// Numeric aggregate endpoint selected entirely by verifier registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ValueBusStarkEndpointV1 {
    /// Source-bound execution order.
    Execution,
    /// Writer-first address order.
    Sorted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ValueBusStarkMetadataV1 {
    modulus: ZkX509P256ModulusV1,
    value_kind: P256ValueKindV1,
    reads: usize,
}
/// Compact verifier-owned fixed-row provider for either value-bus endpoint.
///
/// Storage is proportional to the 15,678 SSA values and 14,828 operations,
/// not to the million-row native domain. Sorted rows are located through
/// per-value prefix counts; no sorted witness address table is retained.
#[derive(Clone, Debug)]
pub struct P256ValueBusStarkFixedProviderV1 {
    endpoint: P256ValueBusStarkEndpointV1,
    initial_values: Vec<P256InitialValueTopologyV1>,
    linked_operations: Vec<P256LinkedOperationTopologyV1>,
    equalities: Vec<P256EqualityBindingV1>,
    boolean_bridges: Vec<P256BooleanBridgeBindingV1>,
    metadata: Vec<P256ValueBusStarkMetadataV1>,
    sorted_prefix: Vec<usize>,
    logical_factor_rows: usize,
    sorted_active_factor_rows: usize,
    trace_size: usize,
}
impl P256ValueBusStarkFixedProviderV1 {
    /// Allocated verifier-owned SSA and sorted-index payload.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            vector_v1(&self.initial_values),
            vector_v1(&self.linked_operations),
            vector_v1(&self.equalities),
            vector_v1(&self.boolean_bridges),
            vector_v1(&self.metadata),
            vector_v1(&self.sorted_prefix),
        ])
    }
    /// Validate the complete SSA address topology and establish a padded native domain.
    pub(crate) fn new_v1(
        endpoint: P256ValueBusStarkEndpointV1,
        initial_values: &[P256InitialValueTopologyV1],
        linked_operations: &[P256LinkedOperationTopologyV1],
        equalities: &[P256EqualityBindingV1],
        boolean_bridges: &[P256BooleanBridgeBindingV1],
        trace_size: usize,
    ) -> Result<Self, P256ValueBusErrorV1> {
        if initial_values.is_empty()
            || linked_operations.is_empty()
            || initial_values.len() > linked_operations.len()
            || !trace_size.is_power_of_two()
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let value_count = initial_values
            .len()
            .checked_add(linked_operations.len())
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(value_count)
            .map_err(|_| P256ValueBusErrorV1::Resource)?;
        for (index, initial) in initial_values.iter().copied().enumerate() {
            if initial.id.0 != u32::try_from(index).map_err(|_| P256ValueBusErrorV1::Resource)? {
                return Err(P256ValueBusErrorV1::Topology);
            }
            metadata.push(P256ValueBusStarkMetadataV1 {
                modulus: initial.modulus,
                value_kind: match initial.kind {
                    P256InitialValueKindV1::Input => P256ValueKindV1::Input,
                    P256InitialValueKindV1::Constant => P256ValueKindV1::Constant,
                },
                reads: 0,
            });
        }
        for (operation, linked) in linked_operations.iter().copied().enumerate() {
            let expected_c = initial_values
                .len()
                .checked_add(operation)
                .ok_or(P256ValueBusErrorV1::Resource)?;
            if linked.c.0 != u32::try_from(expected_c).map_err(|_| P256ValueBusErrorV1::Resource)? {
                return Err(P256ValueBusErrorV1::Topology);
            }
            for id in [linked.a, linked.b] {
                let index = usize::try_from(id.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
                let operand = metadata
                    .get_mut(index)
                    .ok_or(P256ValueBusErrorV1::Topology)?;
                if operand.modulus != linked.modulus {
                    return Err(P256ValueBusErrorV1::Topology);
                }
                operand.reads = operand
                    .reads
                    .checked_add(1)
                    .ok_or(P256ValueBusErrorV1::Resource)?;
            }
            metadata.push(P256ValueBusStarkMetadataV1 {
                modulus: linked.modulus,
                value_kind: P256ValueKindV1::Derived,
                reads: 0,
            });
        }
        for equality in equalities.iter().copied() {
            if equality.left == equality.right {
                return Err(P256ValueBusErrorV1::Topology);
            }
            let left =
                usize::try_from(equality.left.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
            let right =
                usize::try_from(equality.right.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
            if metadata
                .get(left)
                .zip(metadata.get(right))
                .is_none_or(|(left, right)| left.modulus != right.modulus)
            {
                return Err(P256ValueBusErrorV1::Topology);
            }
            for index in [left, right] {
                metadata[index].reads = metadata[index]
                    .reads
                    .checked_add(1)
                    .ok_or(P256ValueBusErrorV1::Resource)?;
            }
        }
        for bridge in boolean_bridges.iter().copied() {
            if bridge.scalar_bit == bridge.base_bit {
                return Err(P256ValueBusErrorV1::Topology);
            }
            let scalar =
                usize::try_from(bridge.scalar_bit.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
            let base =
                usize::try_from(bridge.base_bit.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
            if metadata.get(scalar).map(|value| value.modulus)
                != Some(ZkX509P256ModulusV1::ScalarField)
                || metadata.get(base).map(|value| value.modulus)
                    != Some(ZkX509P256ModulusV1::BaseField)
            {
                return Err(P256ValueBusErrorV1::Topology);
            }
            for index in [scalar, base] {
                metadata[index].reads = metadata[index]
                    .reads
                    .checked_add(1)
                    .ok_or(P256ValueBusErrorV1::Resource)?;
            }
        }
        let segments = linked_operations
            .len()
            .checked_add(equalities.len())
            .and_then(|value| value.checked_add(boolean_bridges.len()))
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let logical_factor_rows = segments
            .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let packed_rows = logical_factor_rows
            .checked_add(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1)
            .ok_or(P256ValueBusErrorV1::Resource)?
            / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        if packed_rows > trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let mut sorted_prefix = Vec::new();
        sorted_prefix
            .try_reserve_exact(metadata.len() + 1)
            .map_err(|_| P256ValueBusErrorV1::Resource)?;
        sorted_prefix.push(0_usize);
        for value in &metadata {
            let rows = value
                .reads
                .checked_add(1)
                .and_then(|rows| rows.checked_mul(P256_VALUE_BUS_LIMBS_V1))
                .ok_or(P256ValueBusErrorV1::Resource)?;
            let next = sorted_prefix
                .last()
                .copied()
                .and_then(|prefix| prefix.checked_add(rows))
                .ok_or(P256ValueBusErrorV1::Resource)?;
            sorted_prefix.push(next);
        }
        let sorted_active_factor_rows =
            *sorted_prefix.last().ok_or(P256ValueBusErrorV1::Topology)?;
        if sorted_active_factor_rows > logical_factor_rows {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(Self {
            endpoint,
            initial_values: initial_values.to_vec(),
            linked_operations: linked_operations.to_vec(),
            equalities: equalities.to_vec(),
            boolean_bridges: boolean_bridges.to_vec(),
            metadata,
            sorted_prefix,
            logical_factor_rows,
            sorted_active_factor_rows,
            trace_size,
        })
    }
    /// Exact numeric fixed row, including all logical inactive slots and the
    /// canonical domain suffix.
    pub(crate) fn row_v1(
        &self,
        index: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1], P256ValueBusErrorV1> {
        if index >= self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let mut fixed = [F::ZERO; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1];
        fixed[STARK_FIXED_FIRST] = F(u64::from(index == 0));
        fixed[STARK_FIXED_CONTINUATION] = F(u64::from(index + 1 < self.trace_size));
        for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let ordinal = index
                .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
                .and_then(|ordinal| ordinal.checked_add(slot))
                .ok_or(P256ValueBusErrorV1::Resource)?;
            let offset = stark_fixed_offset_v1(slot);
            let slot_fixed = &mut fixed[offset..offset + STARK_FIXED_SLOT_WIDTH];
            let active = match self.endpoint {
                P256ValueBusStarkEndpointV1::Execution => {
                    self.execution_access_v1(ordinal, slot_fixed)?
                }
                P256ValueBusStarkEndpointV1::Sorted => {
                    self.sorted_access_v1(ordinal, slot_fixed)?
                }
            };
            slot_fixed[STARK_FIXED_PADDING] = F(u64::from(!active));
        }
        Ok(fixed)
    }
    /// One verifier-preprocessed cell without retaining a fixed-row matrix.
    #[cfg(test)]
    pub(crate) fn fixed_cell_v1(
        &self,
        index: usize,
        column: usize,
    ) -> Result<F, P256ValueBusErrorV1> {
        if column >= P256_VALUE_BUS_STARK_FIXED_WIDTH_V1 {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(self.row_v1(index)?[column])
    }
    /// Regenerate one complete verifier-preprocessed native column.
    #[cfg(test)]
    pub(crate) fn fill_fixed_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256ValueBusErrorV1> {
        if column >= P256_VALUE_BUS_STARK_FIXED_WIDTH_V1 || output.len() != self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        for (index, value) in output.iter_mut().enumerate() {
            *value = self.fixed_cell_v1(index, column)?;
        }
        Ok(())
    }
    fn execution_access_v1(
        &self,
        index: usize,
        fixed: &mut [F],
    ) -> Result<bool, P256ValueBusErrorV1> {
        if fixed.len() != STARK_FIXED_SLOT_WIDTH {
            return Err(P256ValueBusErrorV1::Topology);
        }
        if index >= self.logical_factor_rows {
            return Ok(false);
        }
        let segment = index / P256_VALUE_BUS_SEGMENT_ROWS_V1;
        let local = index % P256_VALUE_BUS_SEGMENT_ROWS_V1;
        if let Some(linked) = self.linked_operations.get(segment).copied() {
            if local < 3 * P256_VALUE_BUS_LIMBS_V1 {
                let limb = local / 3;
                let (id, access) = match local % 3 {
                    0 => (linked.a, P256ValueAccessKindV1::Read),
                    1 => (linked.b, P256ValueAccessKindV1::Read),
                    2 => (linked.c, P256ValueAccessKindV1::Write),
                    _ => return Err(P256ValueBusErrorV1::Topology),
                };
                self.fill_access_v1(fixed, id, limb, access)?;
                return Ok(true);
            }
            if local < 4 * P256_VALUE_BUS_LIMBS_V1 && segment < self.initial_values.len() {
                self.fill_access_v1(
                    fixed,
                    self.initial_values[segment].id,
                    local - 3 * P256_VALUE_BUS_LIMBS_V1,
                    P256ValueAccessKindV1::Write,
                )?;
                return Ok(true);
            }
            return Ok(false);
        }
        let assertion = segment
            .checked_sub(self.linked_operations.len())
            .ok_or(P256ValueBusErrorV1::Topology)?;
        if assertion < self.equalities.len() {
            if local >= 2 * P256_VALUE_BUS_LIMBS_V1 {
                return Ok(false);
            }
            let equality = self.equalities[assertion];
            let id = if local.is_multiple_of(2) {
                equality.left
            } else {
                equality.right
            };
            self.fill_access_v1(fixed, id, local / 2, P256ValueAccessKindV1::Read)?;
            fixed[STARK_FIXED_EQUAL_NEXT] = F(u64::from(local.is_multiple_of(2)));
            return Ok(true);
        }
        let bridge = assertion
            .checked_sub(self.equalities.len())
            .and_then(|index| self.boolean_bridges.get(index))
            .copied()
            .ok_or(P256ValueBusErrorV1::Topology)?;
        if local >= 2 * P256_VALUE_BUS_LIMBS_V1 {
            return Ok(false);
        }
        let id = if local.is_multiple_of(2) {
            bridge.scalar_bit
        } else {
            bridge.base_bit
        };
        self.fill_access_v1(fixed, id, local / 2, P256ValueAccessKindV1::Read)?;
        fixed[STARK_FIXED_EQUAL_NEXT] = F(u64::from(local.is_multiple_of(2)));
        fixed[STARK_FIXED_BOOLEAN] = F(u64::from(local < 2));
        fixed[STARK_FIXED_ZERO] = F(u64::from(local >= 2));
        Ok(true)
    }
    fn sorted_access_v1(&self, index: usize, fixed: &mut [F]) -> Result<bool, P256ValueBusErrorV1> {
        if fixed.len() != STARK_FIXED_SLOT_WIDTH {
            return Err(P256ValueBusErrorV1::Topology);
        }
        if index >= self.sorted_active_factor_rows {
            return Ok(false);
        }
        let id_index = self
            .sorted_prefix
            .partition_point(|prefix| *prefix <= index)
            .checked_sub(1)
            .ok_or(P256ValueBusErrorV1::Topology)?;
        let metadata = self
            .metadata
            .get(id_index)
            .ok_or(P256ValueBusErrorV1::Topology)?;
        let per_limb = metadata
            .reads
            .checked_add(1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let within = index
            .checked_sub(self.sorted_prefix[id_index])
            .ok_or(P256ValueBusErrorV1::Topology)?;
        let limb = within / per_limb;
        let position = within % per_limb;
        self.fill_access_v1(
            fixed,
            P256ValueIdV1(u32::try_from(id_index).map_err(|_| P256ValueBusErrorV1::Resource)?),
            limb,
            if position == 0 {
                P256ValueAccessKindV1::Write
            } else {
                P256ValueAccessKindV1::Read
            },
        )?;
        fixed[STARK_FIXED_EQUAL_NEXT] = F(u64::from(position + 1 < per_limb));
        Ok(true)
    }
    fn fill_access_v1(
        &self,
        fixed: &mut [F],
        id: P256ValueIdV1,
        limb: usize,
        access: P256ValueAccessKindV1,
    ) -> Result<(), P256ValueBusErrorV1> {
        if fixed.len() != STARK_FIXED_SLOT_WIDTH || limb >= P256_VALUE_BUS_LIMBS_V1 {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let id_index = usize::try_from(id.0).map_err(|_| P256ValueBusErrorV1::Resource)?;
        let metadata = self
            .metadata
            .get(id_index)
            .ok_or(P256ValueBusErrorV1::Topology)?;
        fixed[STARK_FIXED_ACTIVE] = F::ONE;
        fixed[STARK_FIXED_ID] = F(u64::from(id.0));
        fixed[STARK_FIXED_LIMB] =
            F(u64::try_from(limb).map_err(|_| P256ValueBusErrorV1::Resource)?);
        fixed[STARK_FIXED_ACCESS] = F(match access {
            P256ValueAccessKindV1::Write => 1,
            P256ValueAccessKindV1::Read => 2,
        });
        fixed[STARK_FIXED_MODULUS] = F(match metadata.modulus {
            ZkX509P256ModulusV1::BaseField => 1,
            ZkX509P256ModulusV1::ScalarField => 2,
        });
        fixed[STARK_FIXED_VALUE_KIND] = F(match metadata.value_kind {
            P256ValueKindV1::Input => 1,
            P256ValueKindV1::Constant => 2,
            P256ValueKindV1::Derived => 3,
        });
        Ok(())
    }
    /// Exact product-factor rows before two-factor packing.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) const fn logical_factor_rows_v1(&self) -> usize {
        self.logical_factor_rows
    }
}
/// Challenge-independent committed base-row provider.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug)]
pub struct P256ValueBusStarkBaseRowProviderV1<'a> {
    endpoint: &'a P256ValueBusBaseEndpointTraceV1,
    packed_rows: usize,
    trace_size: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ValueBusStarkBaseRowProviderV1<'a> {
    /// Validate one endpoint against its expected identity and native domain.
    pub(crate) fn new_v1(
        endpoint: &'a P256ValueBusBaseEndpointTraceV1,
        expected: P256ValueBusStarkEndpointV1,
        trace_size: usize,
    ) -> Result<Self, P256ValueBusErrorV1> {
        let typed_expected = match expected {
            P256ValueBusStarkEndpointV1::Execution => P256ValueBusEndpointV1::Execution,
            P256ValueBusStarkEndpointV1::Sorted => P256ValueBusEndpointV1::Sorted,
        };
        let logical_factor_rows = endpoint.rows.len();
        let packed_rows = logical_factor_rows
            .checked_add(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1)
            .ok_or(P256ValueBusErrorV1::Resource)?
            / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        if endpoint.endpoint != typed_expected
            || endpoint.segment_count_v1()? == 0
            || !trace_size.is_power_of_two()
            || packed_rows > trace_size
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(Self {
            endpoint,
            packed_rows,
            trace_size,
        })
    }
    /// Exact committed base row with canonical domain padding.
    pub(crate) fn base_row_v1(
        self,
        index: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1], P256ValueBusErrorV1> {
        if index >= self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let mut base = [F::ZERO; P256_VALUE_BUS_STARK_BASE_WIDTH_V1];
        if index >= self.packed_rows {
            return Ok(base);
        }
        for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let ordinal = index
                .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
                .and_then(|ordinal| ordinal.checked_add(slot))
                .ok_or(P256ValueBusErrorV1::Resource)?;
            let Some(cell) = self.endpoint.rows.get(ordinal).copied() else {
                continue;
            };
            validate_base_cell_v1(cell)?;
            let offset = stark_base_offset_v1(slot);
            base[offset + STARK_BASE_VALUE] = cell.value;
            let value = u16::try_from(cell.value.0).map_err(|_| P256ValueBusErrorV1::Range)?;
            for bit in 0..P256_VALUE_BUS_LIMBS_V1 {
                base[offset + STARK_BASE_BITS + bit] = F(u64::from((value >> bit) & 1));
            }
        }
        Ok(base)
    }
    /// Challenge-independent endpoint.
    #[cfg(test)]
    pub(crate) const fn endpoint_v1(self) -> &'a P256ValueBusBaseEndpointTraceV1 {
        self.endpoint
    }
}
/// Challenge-bound product replay for one endpoint.
///
/// Construction is private to [`P256ValueBusBoundSourceV1`], so raw challenges cannot create an
/// auxiliary stream before the X5B1 phase transition.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ValueBusStarkAuxSourceV1<'a> {
    endpoint: &'a P256ValueBusBaseEndpointTraceV1,
    challenges: P256ValueBusChallengesV1,
    terminal: [F; P256_VALUE_BUS_LANES_V1],
    running: [F; P256_VALUE_BUS_LANES_V1],
    next_row: usize,
    trace_size: usize,
}
#[cfg(test)]
impl<'a> P256ValueBusStarkAuxSourceV1<'a> {
    fn new_v1(
        endpoint: &'a P256ValueBusBaseEndpointTraceV1,
        expected: P256ValueBusStarkEndpointV1,
        trace_size: usize,
        challenges: P256ValueBusChallengesV1,
    ) -> Result<Self, P256ValueBusErrorV1> {
        challenges.validate()?;
        let base = P256ValueBusStarkBaseRowProviderV1::new_v1(endpoint, expected, trace_size)?;
        let terminal = compute_base_endpoint_terminal_v1(base.endpoint_v1(), challenges)?;
        Ok(Self {
            endpoint,
            challenges,
            terminal,
            running: [F::ONE; P256_VALUE_BUS_LANES_V1],
            next_row: 0,
            trace_size,
        })
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ValueBusStarkAuxSourceV1<'_> {
    /// Emit the next exact challenge-dependent auxiliary row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1]>, P256ValueBusErrorV1> {
        if self.next_row == self.trace_size {
            return Ok(None);
        }
        let mut aux = zeroize::Zeroizing::new([F::ZERO; P256_VALUE_BUS_STARK_AUX_WIDTH_V1]);
        aux[stark_aux_product_offset_v1(0)
            ..stark_aux_product_offset_v1(0) + P256_VALUE_BUS_LANES_V1]
            .copy_from_slice(&self.running);
        for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let ordinal = self
                .next_row
                .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
                .and_then(|ordinal| ordinal.checked_add(slot))
                .ok_or(P256ValueBusErrorV1::Resource)?;
            if let Some(cell) = self.endpoint.rows.get(ordinal).copied() {
                validate_base_cell_v1(cell)?;
                for lane in 0..P256_VALUE_BUS_LANES_V1 {
                    self.running[lane] = self.running[lane].mul(compress_access_v1(
                        cell.fixed,
                        cell.value,
                        self.challenges.lanes[lane],
                    ));
                }
            }
            let offset = stark_aux_product_offset_v1(slot + 1);
            aux[offset..offset + P256_VALUE_BUS_LANES_V1].copy_from_slice(&self.running);
        }
        self.next_row += 1;
        if self.next_row == self.trace_size && self.running != self.terminal {
            return Err(P256ValueBusErrorV1::Constraint);
        }
        Ok(Some(*aux))
    }
    /// Restart deterministic auxiliary replay.
    pub(crate) fn replay_v1(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            challenges: self.challenges,
            terminal: self.terminal,
            running: [F::ONE; P256_VALUE_BUS_LANES_V1],
            next_row: 0,
            trace_size: self.trace_size,
        }
    }
    /// Endpoint terminal under the bound X5B1 challenges.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_VALUE_BUS_LANES_V1] {
        self.terminal
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ValueBusStarkAuxSourceV1<'_> {
    fn drop(&mut self) {
        super::private_table::zeroize_fields_v1(&mut self.running[..]);
        super::private_table::zeroize_fields_v1(&mut self.terminal[..]);
        self.next_row = self.trace_size;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compute_base_endpoint_terminal_v1(
    endpoint: &P256ValueBusBaseEndpointTraceV1,
    challenges: P256ValueBusChallengesV1,
) -> Result<[F; P256_VALUE_BUS_LANES_V1], P256ValueBusErrorV1> {
    challenges.validate()?;
    let mut terminal = [F::ONE; P256_VALUE_BUS_LANES_V1];
    for cell in endpoint.rows.iter().copied() {
        validate_base_cell_v1(cell)?;
        for lane in 0..P256_VALUE_BUS_LANES_V1 {
            terminal[lane] = terminal[lane].mul(compress_access_v1(
                cell.fixed,
                cell.value,
                challenges.lanes[lane],
            ));
        }
    }
    Ok(terminal)
}
/// Conservative construction scratch for one serial value-source build.
/// Charges the temporary arithmetic matrix, copied operations, four full event
/// tables, four compact endpoint/sort tables, and compact topology overhead.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_value_source_scratch_forecast_v1(
    role: P256EcdsaRoleV1,
) -> Result<usize, P256ValueBusErrorV1> {
    use super::{
        allocation_payload::sum_v1,
        p256_air::{
            P256_ARITHMETIC_BASE_WIDTH_V1, ZkX509P256ArithmeticFixedRowV1,
            ZkX509P256ArithmeticOperationV1,
        },
    };
    use core::mem::size_of;
    let topology =
        compile_p256_ecdsa_topology_v1(role).map_err(|_| P256ValueBusErrorV1::Topology)?;
    let operations = topology.linked_operations.len();
    let factors = (operations + topology.equalities.len() + topology.boolean_bridges.len())
        * P256_VALUE_BUS_SEGMENT_ROWS_V1;
    if factors > P256_VALUE_BUS_STARK_TRACE_SIZE_V1 * P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        return Err(P256ValueBusErrorV1::Topology);
    }
    Ok(sum_v1([
        operations
            * P256_ARITHMETIC_ROWS_PER_OPERATION_V1
            * (size_of::<[F; P256_ARITHMETIC_BASE_WIDTH_V1]>()
                + size_of::<ZkX509P256ArithmeticFixedRowV1>()),
        operations * size_of::<ZkX509P256ArithmeticOperationV1>(),
        4 * factors * (size_of::<ExpectedAccessV1>() + size_of::<P256ValueBusBaseCellV1>()),
        32 << 20,
    ]))
}

/// Forecast the canonical retained value source before any private matrix is built.
/// Only the compact, value-free verifier topology and fixed providers are allocated.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_value_source_allocation_forecast_v1(
    role: P256EcdsaRoleV1,
) -> Result<usize, P256ValueBusErrorV1> {
    use super::allocation_payload::{p256_topology_v1, sum_v1};
    let topology =
        compile_p256_ecdsa_topology_v1(role).map_err(|_| P256ValueBusErrorV1::Topology)?;
    let provider = |endpoint| {
        P256ValueBusStarkFixedProviderV1::new_v1(
            endpoint,
            &topology.initial_values,
            &topology.linked_operations,
            &topology.equalities,
            &topology.boolean_bridges,
            P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        )
    };
    let execution = provider(P256ValueBusStarkEndpointV1::Execution)?;
    let sorted = provider(P256ValueBusStarkEndpointV1::Sorted)?;
    let rows = execution.logical_factor_rows;
    if rows != sorted.logical_factor_rows {
        return Err(P256ValueBusErrorV1::Topology);
    }
    let arc_header = 2 * core::mem::size_of::<usize>();
    Ok(sum_v1([
        arc_header,
        core::mem::size_of::<P256ValueBusBaseMaterialV1>(),
        p256_topology_v1(&topology),
        2 * rows * core::mem::size_of::<P256ValueBusBaseCellV1>(),
        2 * (arc_header + core::mem::size_of::<P256ValueBusStarkFixedProviderV1>()),
        execution.allocated_heap_bytes_v1(),
        sorted.allocated_heap_bytes_v1(),
    ]))
}
/// Pre-commitment value-bus capability.
///
/// Binding is poison-on-attempt: the sole transition is consumed before any fallible validation. A
/// malformed base source therefore cannot be retried with a different transcript token.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ValueBusBaseSourceV1 {
    material: Option<Arc<P256ValueBusBaseMaterialV1>>,
    execution_fixed: Option<Arc<P256ValueBusStarkFixedProviderV1>>,
    sorted_fixed: Option<Arc<P256ValueBusStarkFixedProviderV1>>,
    bind_attempted: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ValueBusBaseSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ValueBusBaseSourceV1")
            .field("bind_attempted", &self.bind_attempted)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ValueBusBaseSourceV1 {
    /// Reachable allocation payload; shared replay handles do not duplicate it.
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        use super::allocation_payload::{p256_topology_v1, sum_v1, vector_v1};
        let arc_header = 2 * core::mem::size_of::<usize>();
        sum_v1([
            self.material.as_deref().map_or(0, |material| {
                sum_v1([
                    arc_header,
                    core::mem::size_of_val(material),
                    p256_topology_v1(&material.topology),
                    vector_v1(&material.execution.rows),
                    vector_v1(&material.sorted.rows),
                ])
            }),
            self.execution_fixed.as_deref().map_or(0, |fixed| {
                sum_v1([
                    arc_header,
                    core::mem::size_of_val(fixed),
                    fixed.allocated_heap_bytes_v1(),
                ])
            }),
            self.sorted_fixed.as_deref().map_or(0, |fixed| {
                sum_v1([
                    arc_header,
                    core::mem::size_of_val(fixed),
                    fixed.allocated_heap_bytes_v1(),
                ])
            }),
        ])
    }
    /// Validate canonical witness material and enter the challenge-independent base phase.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn new_v1(material: &P256EcdsaTraceMaterialV1) -> Result<Self, P256ValueBusErrorV1> {
        Self::from_base_material_v1(P256ValueBusBaseMaterialV1::from_trace_material_v1(
            material,
        )?)
    }
    fn from_base_material_v1(
        material: P256ValueBusBaseMaterialV1,
    ) -> Result<Self, P256ValueBusErrorV1> {
        material.validate_integrity_v1()?;
        let execution_fixed = material.fixed_provider_v1(P256ValueBusStarkEndpointV1::Execution)?;
        let sorted_fixed = material.fixed_provider_v1(P256ValueBusStarkEndpointV1::Sorted)?;
        Ok(Self {
            material: Some(Arc::new(material)),
            execution_fixed: Some(Arc::new(execution_fixed)),
            sorted_fixed: Some(Arc::new(sorted_fixed)),
            bind_attempted: false,
        })
    }
    fn ensure_base_phase_v1(&self) -> Result<(), P256ValueBusErrorV1> {
        if self.bind_attempted
            || self.material.is_none()
            || self.execution_fixed.is_none()
            || self.sorted_fixed.is_none()
        {
            Err(P256ValueBusErrorV1::Phase)
        } else {
            Ok(())
        }
    }
    /// Verifier-selected role while the pre-commitment capability remains live.
    pub(crate) fn role_v1(&self) -> Result<P256EcdsaRoleV1, P256ValueBusErrorV1> {
        self.ensure_base_phase_v1()?;
        Ok(self
            .material
            .as_deref()
            .ok_or(P256ValueBusErrorV1::Phase)?
            .role_v1())
    }
    /// Challenge-independent execution endpoint while the pre-commitment capability remains live.
    pub(crate) fn execution_endpoint_v1(
        &self,
    ) -> Result<&P256ValueBusBaseEndpointTraceV1, P256ValueBusErrorV1> {
        self.ensure_base_phase_v1()?;
        Ok(self
            .material
            .as_deref()
            .ok_or(P256ValueBusErrorV1::Phase)?
            .execution_v1())
    }
    /// One challenge-independent committed base row.
    pub(crate) fn base_row_v1(
        &self,
        endpoint: P256ValueBusStarkEndpointV1,
        row: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1], P256ValueBusErrorV1> {
        self.ensure_base_phase_v1()?;
        let material = self.material.as_deref().ok_or(P256ValueBusErrorV1::Phase)?;
        let endpoint_trace = match endpoint {
            P256ValueBusStarkEndpointV1::Execution => material.execution_v1(),
            P256ValueBusStarkEndpointV1::Sorted => material.sorted_v1(),
        };
        P256ValueBusStarkBaseRowProviderV1::new_v1(
            endpoint_trace,
            endpoint,
            P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        )?
        .base_row_v1(row)
    }
    /// One verifier-owned fixed row. No witness value is accepted by this path.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        endpoint: P256ValueBusStarkEndpointV1,
        row: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1], P256ValueBusErrorV1> {
        self.ensure_base_phase_v1()?;
        match endpoint {
            P256ValueBusStarkEndpointV1::Execution => self
                .execution_fixed
                .as_deref()
                .ok_or(P256ValueBusErrorV1::Phase)?
                .row_v1(row),
            P256ValueBusStarkEndpointV1::Sorted => self
                .sorted_fixed
                .as_deref()
                .ok_or(P256ValueBusErrorV1::Phase)?
                .row_v1(row),
        }
    }
    /// Consume the sole phase transition using an opaque X5B1 token.
    pub(crate) fn bind_v1(
        &mut self,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<P256ValueBusBoundSourceV1, P256ValueBusErrorV1> {
        self.ensure_base_phase_v1()?;
        self.bind_attempted = true;
        let material = self.material.as_deref().ok_or(P256ValueBusErrorV1::Phase)?;
        material.validate_integrity_v1()?;
        let value_challenges = post_base.p256_value();
        value_challenges.validate()?;
        post_base
            .p256_cross()
            .validate()
            .map_err(|_| P256ValueBusErrorV1::Challenge)?;
        let execution_terminal =
            compute_base_endpoint_terminal_v1(material.execution_v1(), value_challenges)?;
        let sorted_terminal =
            compute_base_endpoint_terminal_v1(material.sorted_v1(), value_challenges)?;
        if execution_terminal != sorted_terminal {
            return Err(P256ValueBusErrorV1::Terminal);
        }
        Ok(P256ValueBusBoundSourceV1 {
            material: self.material.take(),
            execution_fixed: self.execution_fixed.take(),
            sorted_fixed: self.sorted_fixed.take(),
            post_base: Some(post_base),
            execution_terminal,
            sorted_terminal,
        })
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        if let Some(material) = self.material.as_mut()
            && let Some(material) = Arc::get_mut(material)
        {
            material.zeroize_private_v1();
        }
        self.material = None;
        self.execution_fixed = None;
        self.sorted_fixed = None;
        self.bind_attempted = true;
    }
    #[cfg(test)]
    fn material_mut_for_test_v1(
        &mut self,
    ) -> Result<&mut P256ValueBusBaseMaterialV1, P256ValueBusErrorV1> {
        self.ensure_base_phase_v1()?;
        Arc::get_mut(self.material.as_mut().ok_or(P256ValueBusErrorV1::Phase)?)
            .ok_or(P256ValueBusErrorV1::Phase)
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
impl Drop for P256ValueBusBaseSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Post-X5B1 value-bus capability.
///
/// It retains the base commitment material for constraint and cross-source projection, while
/// challenge-dependent products are exposed only through replay objects minted here.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ValueBusBoundSourceV1 {
    material: Option<Arc<P256ValueBusBaseMaterialV1>>,
    execution_fixed: Option<Arc<P256ValueBusStarkFixedProviderV1>>,
    sorted_fixed: Option<Arc<P256ValueBusStarkFixedProviderV1>>,
    post_base: Option<ZkX509CredentialMainPostBaseChallengesV1>,
    execution_terminal: [F; P256_VALUE_BUS_LANES_V1],
    sorted_terminal: [F; P256_VALUE_BUS_LANES_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ValueBusBoundSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ValueBusBoundSourceV1")
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ValueBusBoundSourceV1 {
    /// Reachable allocation payload; shared replay handles do not duplicate it.
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        use super::allocation_payload::{p256_topology_v1, sum_v1, vector_v1};
        let arc_header = 2 * core::mem::size_of::<usize>();
        sum_v1([
            self.material.as_deref().map_or(0, |material| {
                sum_v1([
                    arc_header,
                    core::mem::size_of_val(material),
                    p256_topology_v1(&material.topology),
                    vector_v1(&material.execution.rows),
                    vector_v1(&material.sorted.rows),
                ])
            }),
            self.execution_fixed.as_deref().map_or(0, |fixed| {
                sum_v1([
                    arc_header,
                    core::mem::size_of_val(fixed),
                    fixed.allocated_heap_bytes_v1(),
                ])
            }),
            self.sorted_fixed.as_deref().map_or(0, |fixed| {
                sum_v1([
                    arc_header,
                    core::mem::size_of_val(fixed),
                    fixed.allocated_heap_bytes_v1(),
                ])
            }),
        ])
    }
    fn material_v1(&self) -> Result<&P256ValueBusBaseMaterialV1, P256ValueBusErrorV1> {
        self.material.as_deref().ok_or(P256ValueBusErrorV1::Phase)
    }
    /// Role selected before base commitment.
    pub(crate) fn role_v1(&self) -> Result<P256EcdsaRoleV1, P256ValueBusErrorV1> {
        Ok(self.material_v1()?.role_v1())
    }
    /// Verifier-owned canonical topology.
    pub(crate) fn topology_v1(&self) -> Result<&P256EcdsaTopologyV1, P256ValueBusErrorV1> {
        Ok(self.material_v1()?.topology_v1())
    }
    /// Challenge-independent execution endpoint used by writer projection.
    pub(crate) fn execution_endpoint_v1(
        &self,
    ) -> Result<&P256ValueBusBaseEndpointTraceV1, P256ValueBusErrorV1> {
        Ok(self.material_v1()?.execution_v1())
    }
    /// Challenge-independent sorted endpoint.
    pub(crate) fn sorted_endpoint_v1(
        &self,
    ) -> Result<&P256ValueBusBaseEndpointTraceV1, P256ValueBusErrorV1> {
        Ok(self.material_v1()?.sorted_v1())
    }
    /// Opaque post-base phase token for sibling P-256 adapters.
    pub(crate) fn post_base_v1(
        &self,
    ) -> Result<ZkX509CredentialMainPostBaseChallengesV1, P256ValueBusErrorV1> {
        self.post_base.ok_or(P256ValueBusErrorV1::Phase)
    }
    /// Committed execution base rows.
    pub(crate) fn execution_base_rows_v1(
        &self,
    ) -> Result<P256ValueBusStarkBaseRowProviderV1<'_>, P256ValueBusErrorV1> {
        P256ValueBusStarkBaseRowProviderV1::new_v1(
            self.execution_endpoint_v1()?,
            P256ValueBusStarkEndpointV1::Execution,
            P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        )
    }
    /// Committed sorted base rows.
    pub(crate) fn sorted_base_rows_v1(
        &self,
    ) -> Result<P256ValueBusStarkBaseRowProviderV1<'_>, P256ValueBusErrorV1> {
        P256ValueBusStarkBaseRowProviderV1::new_v1(
            self.sorted_endpoint_v1()?,
            P256ValueBusStarkEndpointV1::Sorted,
            P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        )
    }
    /// Mint replay only from this exact immutable endpoint's checked bind result.
    /// No external terminal, endpoint, or challenge is accepted. The final replay
    /// row independently checks its accumulated product against the retained value.
    fn bound_aux_source_v1(
        &self,
        expected: P256ValueBusStarkEndpointV1,
    ) -> Result<P256ValueBusStarkAuxSourceV1<'_>, P256ValueBusErrorV1> {
        let challenges = self.post_base_v1()?.p256_value();
        challenges.validate()?;
        let (endpoint, terminal) = match expected {
            P256ValueBusStarkEndpointV1::Execution => {
                (self.execution_endpoint_v1()?, self.execution_terminal)
            }
            P256ValueBusStarkEndpointV1::Sorted => {
                (self.sorted_endpoint_v1()?, self.sorted_terminal)
            }
        };
        P256ValueBusStarkBaseRowProviderV1::new_v1(
            endpoint,
            expected,
            P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        )?;
        Ok(P256ValueBusStarkAuxSourceV1 {
            endpoint,
            challenges,
            terminal,
            running: [F::ONE; P256_VALUE_BUS_LANES_V1],
            next_row: 0,
            trace_size: P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        })
    }
    /// Challenge-bound execution product replay.
    pub(crate) fn execution_aux_source_v1(
        &self,
    ) -> Result<P256ValueBusStarkAuxSourceV1<'_>, P256ValueBusErrorV1> {
        self.bound_aux_source_v1(P256ValueBusStarkEndpointV1::Execution)
    }
    /// Challenge-bound sorted product replay.
    pub(crate) fn sorted_aux_source_v1(
        &self,
    ) -> Result<P256ValueBusStarkAuxSourceV1<'_>, P256ValueBusErrorV1> {
        self.bound_aux_source_v1(P256ValueBusStarkEndpointV1::Sorted)
    }
    /// Verifier-owned fixed execution row retained across the phase transition.
    #[cfg(test)]
    pub(crate) fn execution_fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1], P256ValueBusErrorV1> {
        self.execution_fixed
            .as_deref()
            .ok_or(P256ValueBusErrorV1::Phase)?
            .row_v1(row)
    }
    /// Recursively overwrite the retained bound value material and challenge-derived terminals.
    ///
    /// The bound capability uniquely owns its material in production. The
    /// `Arc::get_mut` check keeps this idempotent and prevents clearing through
    /// an aliased test-only owner before the final owner drops.
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.post_base = None;
        super::private_table::zeroize_fields_v1(&mut self.execution_terminal[..]);
        super::private_table::zeroize_fields_v1(&mut self.sorted_terminal[..]);
        if let Some(material) = self.material.as_mut()
            && let Some(material) = Arc::get_mut(material)
        {
            material.zeroize_private_v1();
        }
        self.material = None;
        self.execution_fixed = None;
        self.sorted_fixed = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ValueBusBoundSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Constant-memory committed base/aux row provider for one completed endpoint.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct P256ValueBusStarkRowProviderV1<'a> {
    endpoint: &'a P256ValueBusEndpointTraceV1,
    logical_factor_rows: usize,
    packed_rows: usize,
    terminal: [F; P256_VALUE_BUS_LANES_V1],
    trace_size: usize,
}
#[cfg(test)]
impl<'a> P256ValueBusStarkRowProviderV1<'a> {
    /// Validate endpoint identity and establish one padded domain.
    pub(crate) fn new_v1(
        endpoint: &'a P256ValueBusEndpointTraceV1,
        expected: P256ValueBusStarkEndpointV1,
        trace_size: usize,
    ) -> Result<Self, P256ValueBusErrorV1> {
        let typed_expected = match expected {
            P256ValueBusStarkEndpointV1::Execution => P256ValueBusEndpointV1::Execution,
            P256ValueBusStarkEndpointV1::Sorted => P256ValueBusEndpointV1::Sorted,
        };
        let logical_factor_rows = endpoint
            .segments
            .len()
            .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let packed_rows = logical_factor_rows
            .checked_add(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1)
            .ok_or(P256ValueBusErrorV1::Resource)?
            / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        if endpoint.endpoint != typed_expected
            || logical_factor_rows == 0
            || packed_rows > trace_size
            || !trace_size.is_power_of_two()
            || endpoint
                .segments
                .iter()
                .enumerate()
                .any(|(index, segment)| {
                    segment.index != u32::try_from(index).unwrap_or(u32::MAX)
                        || segment.rows.len() != P256_VALUE_BUS_SEGMENT_ROWS_V1
                })
        {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(Self {
            endpoint,
            logical_factor_rows,
            packed_rows,
            terminal: endpoint.terminal()?,
            trace_size,
        })
    }
    /// Direct committed base opening at one native ordinal.
    pub(crate) fn base_row_v1(
        self,
        index: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1], P256ValueBusErrorV1> {
        if index >= self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let mut base = [F::ZERO; P256_VALUE_BUS_STARK_BASE_WIDTH_V1];
        if index >= self.packed_rows {
            return Ok(base);
        }
        for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let ordinal = index
                .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
                .and_then(|ordinal| ordinal.checked_add(slot))
                .ok_or(P256ValueBusErrorV1::Resource)?;
            if ordinal >= self.logical_factor_rows {
                continue;
            }
            let row = self.endpoint.row(ordinal)?;
            let offset = stark_base_offset_v1(slot);
            base[offset + STARK_BASE_VALUE] = row.value;
            base[offset + STARK_BASE_BITS..offset + STARK_BASE_BITS + P256_VALUE_BUS_LIMBS_V1]
                .copy_from_slice(&row.value_bits);
        }
        Ok(base)
    }
    /// One directly committed base cell without copying a complete row.
    pub(crate) fn base_cell_v1(
        self,
        index: usize,
        column: usize,
    ) -> Result<F, P256ValueBusErrorV1> {
        if index >= self.trace_size || column >= P256_VALUE_BUS_STARK_BASE_WIDTH_V1 {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(self.base_row_v1(index)?[column])
    }
    /// Copy one complete committed base column into caller-owned storage.
    pub(crate) fn fill_base_column_v1(
        self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256ValueBusErrorV1> {
        if column >= P256_VALUE_BUS_STARK_BASE_WIDTH_V1 || output.len() != self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        for (index, value) in output.iter_mut().enumerate() {
            *value = self.base_cell_v1(index, column)?;
        }
        Ok(())
    }
    /// Existing four-lane value-bus products at one native ordinal.
    pub(crate) fn aux_row_v1(
        self,
        index: usize,
    ) -> Result<[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1], P256ValueBusErrorV1> {
        if index >= self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        let mut aux = [F::ZERO; P256_VALUE_BUS_STARK_AUX_WIDTH_V1];
        let first_ordinal = index
            .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
            .ok_or(P256ValueBusErrorV1::Resource)?;
        let mut running = if first_ordinal < self.logical_factor_rows {
            self.endpoint.row(first_ordinal)?.product_before
        } else {
            self.terminal
        };
        aux[stark_aux_product_offset_v1(0)
            ..stark_aux_product_offset_v1(0) + P256_VALUE_BUS_LANES_V1]
            .copy_from_slice(&running);
        for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            let ordinal = first_ordinal
                .checked_add(slot)
                .ok_or(P256ValueBusErrorV1::Resource)?;
            if ordinal < self.logical_factor_rows {
                let row = self.endpoint.row(ordinal)?;
                if row.product_before != running {
                    return Err(P256ValueBusErrorV1::Constraint);
                }
                running = row.product_after;
            }
            let offset = stark_aux_product_offset_v1(slot + 1);
            aux[offset..offset + P256_VALUE_BUS_LANES_V1].copy_from_slice(&running);
        }
        Ok(aux)
    }
    /// One challenge-dependent product cell without retaining an auxiliary row matrix.
    pub(crate) fn aux_cell_v1(self, index: usize, column: usize) -> Result<F, P256ValueBusErrorV1> {
        if index >= self.trace_size || column >= P256_VALUE_BUS_STARK_AUX_WIDTH_V1 {
            return Err(P256ValueBusErrorV1::Topology);
        }
        Ok(self.aux_row_v1(index)?[column])
    }
    /// Copy one complete challenge-dependent auxiliary column into caller-owned storage.
    pub(crate) fn fill_aux_column_v1(
        self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256ValueBusErrorV1> {
        if column >= P256_VALUE_BUS_STARK_AUX_WIDTH_V1 || output.len() != self.trace_size {
            return Err(P256ValueBusErrorV1::Topology);
        }
        for (index, value) in output.iter_mut().enumerate() {
            *value = self.aux_cell_v1(index, column)?;
        }
        Ok(())
    }
}
/// Project both committed limb cells used by packed writer/copy products.
pub fn p256_value_bus_opened_values_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
) -> [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1] {
    core::array::from_fn(|slot| base[stark_base_offset_v1(slot) + STARK_BASE_VALUE])
}
/// Evaluate one numeric value-bus row on the aggregate extension domain.
///
/// All topology, endpoint ordering, adjacency, assertion, and boundary selectors are numeric
/// verifier preprocessing. No proof cell is decoded as an enum or native row index.
#[cfg(test)]
pub fn evaluate_p256_value_bus_stark_residues_v1(
    current: &[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
    next: &[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ValueBusChallengesV1,
) -> Result<Vec<F>, P256ValueBusErrorV1> {
    evaluate_p256_value_bus_stark_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
}
/// Shared numeric value-bus polynomial over the base or extension field.
pub fn evaluate_p256_value_bus_stark_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
    next: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ValueBusChallengesV1,
) -> Result<Vec<A>, P256ValueBusErrorV1> {
    challenges.validate()?;
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(P256ValueBusErrorV1::Range);
    }
    let mut residues = Vec::with_capacity(P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1);
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let base_offset = stark_base_offset_v1(slot);
        let fixed_offset = stark_fixed_offset_v1(slot);
        let mut packed = A::ZERO;
        for bit in 0..P256_VALUE_BUS_LIMBS_V1 {
            let value = current[base_offset + STARK_BASE_BITS + bit];
            residues.push(value.mul(value.sub(A::ONE)));
            packed = packed.add(value.mul(A::from_base(F(1_u64 << bit))));
        }
        let value = current[base_offset + STARK_BASE_VALUE];
        residues.push(value.sub(packed));
        residues.push(fixed[fixed_offset + STARK_FIXED_PADDING].mul(value));
        for bit in 0..P256_VALUE_BUS_LIMBS_V1 {
            residues.push(
                fixed[fixed_offset + STARK_FIXED_PADDING]
                    .mul(current[base_offset + STARK_BASE_BITS + bit]),
            );
        }
        for lane in 0..P256_VALUE_BUS_LANES_V1 {
            let terms = challenges.lanes[lane].terms;
            let factor = A::ONE
                .sub(fixed[fixed_offset + STARK_FIXED_ACTIVE])
                .add(fixed[fixed_offset + STARK_FIXED_ACTIVE].mul_base(terms[0]))
                .add(fixed[fixed_offset + STARK_FIXED_ID].mul_base(terms[1]))
                .add(fixed[fixed_offset + STARK_FIXED_LIMB].mul_base(terms[2]))
                .add(fixed[fixed_offset + STARK_FIXED_ACCESS].mul_base(terms[3]))
                .add(fixed[fixed_offset + STARK_FIXED_MODULUS].mul_base(terms[4]))
                .add(fixed[fixed_offset + STARK_FIXED_VALUE_KIND].mul_base(terms[5]))
                .add(value.mul_base(terms[6]));
            residues.push(
                current_aux[stark_aux_product_offset_v1(slot + 1) + lane]
                    .sub(current_aux[stark_aux_product_offset_v1(slot) + lane].mul(factor)),
            );
        }
        let next_value = if slot + 1 < P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            current[stark_base_offset_v1(slot + 1) + STARK_BASE_VALUE]
        } else {
            next[STARK_BASE_VALUE]
        };
        residues.push(fixed[fixed_offset + STARK_FIXED_EQUAL_NEXT].mul(next_value.sub(value)));
        residues.push(
            fixed[fixed_offset + STARK_FIXED_BOOLEAN]
                .mul(value)
                .mul(value.sub(A::ONE)),
        );
        residues.push(fixed[fixed_offset + STARK_FIXED_ZERO].mul(value));
    }
    for lane in 0..P256_VALUE_BUS_LANES_V1 {
        residues.push(
            fixed[STARK_FIXED_FIRST]
                .mul(current_aux[stark_aux_product_offset_v1(0) + lane].sub(A::ONE)),
        );
        residues.push(fixed[STARK_FIXED_CONTINUATION].mul(
            next_aux[stark_aux_product_offset_v1(0) + lane].sub(
                current_aux
                    [stark_aux_product_offset_v1(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) + lane],
            ),
        ));
    }
    if residues.len() != P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1 {
        return Err(P256ValueBusErrorV1::Topology);
    }
    Ok(residues)
}
/// Canonical auxiliary columns carrying the value product after all row factors.
pub fn p256_value_bus_terminal_columns_v1() -> [usize; P256_VALUE_BUS_LANES_V1] {
    core::array::from_fn(|lane| {
        stark_aux_product_offset_v1(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) + lane
    })
}
/// Project the terminal product from one verifier-fixed native-row opening.
#[cfg(test)]
pub fn p256_value_bus_stark_opened_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
) -> [A; P256_VALUE_BUS_LANES_V1] {
    core::array::from_fn(|lane| {
        aux[stark_aux_product_offset_v1(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) + lane]
    })
}
/// Terminal equality over verifier-fixed final native-row openings.
#[cfg(test)]
pub fn evaluate_p256_value_bus_stark_terminal_openings_v1(
    execution: &[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
    sorted: &[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
) -> [F; P256_VALUE_BUS_LANES_V1] {
    let execution = p256_value_bus_stark_opened_terminal_v1(execution);
    let sorted = p256_value_bus_stark_opened_terminal_v1(sorted);
    core::array::from_fn(|lane| execution[lane].sub(sorted[lane]))
}
/// Verifier-preprocessed selector for the final shared native-domain row.
#[cfg(test)]
pub fn p256_value_bus_stark_last_domain_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1],
) -> A {
    A::ONE.sub(fixed[STARK_FIXED_CONTINUATION])
}
/// Gate execution/sorted terminal equality at the final shared-domain row.
///
/// This is the aggregate-quotient form; the ungated helper above is reserved
/// for an explicitly verifier-fixed final-row opening.
#[cfg(test)]
pub fn evaluate_p256_value_bus_stark_terminal_opened_rows_v1(
    last_domain_selector: F,
    execution: &[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
    sorted: &[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1],
) -> [F; P256_VALUE_BUS_LANES_V1] {
    evaluate_p256_value_bus_stark_terminal_openings_v1(execution, sorted)
        .map(|residue| last_domain_selector.mul(residue))
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_value_erasure_covers_partial_endpoint_and_in_place_sort_parity() {
        use super::super::private_table::inspection::observe_v1;
        let program = program(1);
        let execution = execution_events_v1(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
        )
        .unwrap();
        let mut reference = execution.to_vec();
        reference.sort_by_key(|event| fixed_sort_key_v1(event.fixed));
        let sorted = sorted_events_v1(&execution).unwrap();
        // Only fixed address and value are committed. `source_bound` is an
        // execution-only validation hint and need not order equal sorted reads.
        assert_eq!(
            sorted
                .iter()
                .map(|event| (event.fixed, event.value))
                .collect::<Vec<_>>(),
            reference
                .iter()
                .map(|event| (event.fixed, event.value))
                .collect::<Vec<_>>(),
        );
        let event = *execution
            .iter()
            .find(|event| event.value != F::ZERO)
            .unwrap();
        let mut invalid = vec![event; P256_VALUE_BUS_SEGMENT_ROWS_V1];
        invalid[1].value = F(u64::from(u16::MAX) + 1);
        let (result, observed) =
            observe_v1(|| build_base_endpoint_v1(P256ValueBusEndpointV1::Execution, &invalid));
        assert_eq!(result, Err(P256ValueBusErrorV1::Range));
        assert!(
            observed
                .iter()
                .any(|item| item.cells == 1 && item.nonzero_before == 1)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        let ((), observed) = observe_v1(|| {
            drop(execution);
            drop(sorted);
        });
        assert!(
            observed
                .iter()
                .any(|item| item.cells > 1 && item.nonzero_before > 0)
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    use super::super::p256_air::{
        ZkX509P256ArithmeticKindV1, build_zk_x509_p256_arithmetic_trace_v1,
    };
    use super::*;
    use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
    use crate::privacy_engines::zk_x509::credential_pre_aux::{
        ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, ZkX509CredentialMainPreAuxV1,
        derive_zk_x509_credential_pre_aux_binding_v1,
    };
    use crate::privacy_engines::zk_x509::stark::zk_x509_test_digest384_v1;
    #[derive(Clone)]
    struct ProgramV1 {
        initial: Vec<P256InitialValueBindingV1>,
        linked: Vec<P256LinkedOperationV1>,
        equalities: Vec<P256EqualityBindingV1>,
        bridges: Vec<P256BooleanBridgeBindingV1>,
        arithmetic: ZkX509P256ArithmeticTraceV1,
    }
    fn small(value: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
    fn operation(
        kind: ZkX509P256ArithmeticKindV1,
        modulus: ZkX509P256ModulusV1,
        a: u64,
        b: u64,
        c: u64,
    ) -> ZkX509P256ArithmeticOperationV1 {
        ZkX509P256ArithmeticOperationV1 {
            kind,
            modulus,
            a: small(a),
            b: small(b),
            c: small(c),
        }
    }
    fn program(bit: u64) -> ProgramV1 {
        let initial = vec![
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(0),
                modulus: ZkX509P256ModulusV1::BaseField,
                value: small(3),
                kind: P256InitialValueKindV1::Input,
            },
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(1),
                modulus: ZkX509P256ModulusV1::BaseField,
                value: small(5),
                kind: P256InitialValueKindV1::Constant,
            },
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(2),
                modulus: ZkX509P256ModulusV1::BaseField,
                value: small(0),
                kind: P256InitialValueKindV1::Constant,
            },
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(3),
                modulus: ZkX509P256ModulusV1::ScalarField,
                value: small(bit),
                kind: P256InitialValueKindV1::Input,
            },
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(4),
                modulus: ZkX509P256ModulusV1::BaseField,
                value: small(bit),
                kind: P256InitialValueKindV1::Input,
            },
        ];
        let operations = vec![
            operation(
                ZkX509P256ArithmeticKindV1::Multiply,
                ZkX509P256ModulusV1::BaseField,
                3,
                5,
                15,
            ),
            operation(
                ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ModulusV1::BaseField,
                15,
                3,
                18,
            ),
            operation(
                ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ModulusV1::BaseField,
                18,
                5,
                23,
            ),
            operation(
                ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ModulusV1::BaseField,
                23,
                bit,
                23 + bit,
            ),
            operation(
                ZkX509P256ArithmeticKindV1::Multiply,
                ZkX509P256ModulusV1::ScalarField,
                bit,
                bit,
                bit * bit,
            ),
            operation(
                ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ModulusV1::BaseField,
                23 + bit,
                0,
                23 + bit,
            ),
        ];
        let linked = vec![
            P256LinkedOperationV1 {
                a: P256ValueIdV1(0),
                b: P256ValueIdV1(1),
                c: P256ValueIdV1(5),
                operation: operations[0],
            },
            P256LinkedOperationV1 {
                a: P256ValueIdV1(5),
                b: P256ValueIdV1(0),
                c: P256ValueIdV1(6),
                operation: operations[1],
            },
            P256LinkedOperationV1 {
                a: P256ValueIdV1(6),
                b: P256ValueIdV1(1),
                c: P256ValueIdV1(7),
                operation: operations[2],
            },
            P256LinkedOperationV1 {
                a: P256ValueIdV1(7),
                b: P256ValueIdV1(4),
                c: P256ValueIdV1(8),
                operation: operations[3],
            },
            P256LinkedOperationV1 {
                a: P256ValueIdV1(3),
                b: P256ValueIdV1(3),
                c: P256ValueIdV1(9),
                operation: operations[4],
            },
            P256LinkedOperationV1 {
                a: P256ValueIdV1(8),
                b: P256ValueIdV1(2),
                c: P256ValueIdV1(10),
                operation: operations[5],
            },
        ];
        ProgramV1 {
            initial,
            linked,
            equalities: vec![P256EqualityBindingV1 {
                left: P256ValueIdV1(8),
                right: P256ValueIdV1(10),
            }],
            bridges: vec![P256BooleanBridgeBindingV1 {
                scalar_bit: P256ValueIdV1(3),
                base_bit: P256ValueIdV1(4),
            }],
            arithmetic: build_zk_x509_p256_arithmetic_trace_v1(&operations)
                .expect("valid arithmetic fixture"),
        }
    }
    fn fixed_topology_v1(
        program: &ProgramV1,
    ) -> (
        Vec<P256InitialValueTopologyV1>,
        Vec<P256LinkedOperationTopologyV1>,
    ) {
        let initial = program
            .initial
            .iter()
            .map(|value| P256InitialValueTopologyV1 {
                id: value.id,
                modulus: value.modulus,
                kind: value.kind,
            })
            .collect::<Vec<_>>();
        let linked = program
            .linked
            .iter()
            .map(|operation| P256LinkedOperationTopologyV1 {
                a: operation.a,
                b: operation.b,
                c: operation.c,
                kind: operation.operation.kind,
                modulus: operation.operation.modulus,
            })
            .collect::<Vec<_>>();
        (initial, linked)
    }
    fn fixed_provider_v1(
        program: &ProgramV1,
        endpoint: P256ValueBusStarkEndpointV1,
        trace_size: usize,
    ) -> Result<P256ValueBusStarkFixedProviderV1, P256ValueBusErrorV1> {
        let (initial, linked) = fixed_topology_v1(program);
        P256ValueBusStarkFixedProviderV1::new_v1(
            endpoint,
            &initial,
            &linked,
            &program.equalities,
            &program.bridges,
            trace_size,
        )
    }
    fn topology_v1(program: &ProgramV1, role: P256EcdsaRoleV1) -> P256EcdsaTopologyV1 {
        let mut topology = compile_p256_ecdsa_topology_v1(role).expect("canonical topology");
        let (initial_values, linked_operations) = fixed_topology_v1(program);
        topology.initial_values = initial_values;
        topology.linked_operations = linked_operations;
        topology.equalities = program.equalities.clone();
        topology.boolean_bridges = program.bridges.clone();
        topology
    }
    fn base_material_v1(program: &ProgramV1) -> P256ValueBusBaseMaterialV1 {
        P256ValueBusBaseMaterialV1::fixture_v1(
            P256EcdsaRoleV1::WalletOwnership,
            topology_v1(program, P256EcdsaRoleV1::WalletOwnership),
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
        )
        .expect("challenge-independent value bus")
    }
    fn base_source_v1(program: &ProgramV1) -> P256ValueBusBaseSourceV1 {
        P256ValueBusBaseSourceV1::from_base_material_v1(base_material_v1(program))
            .expect("base source")
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
    fn challenges() -> P256ValueBusChallengesV1 {
        P256ValueBusChallengesV1 {
            lanes: core::array::from_fn(|lane| P256ValueBusLaneChallengesV1 {
                terms: core::array::from_fn(|term| F((lane * 31 + term + 2) as u64)),
            }),
        }
    }
    fn build(program: &ProgramV1) -> Result<P256ValueBusTraceV1, P256ValueBusErrorV1> {
        build_zk_x509_p256_value_bus_trace_v1(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
            challenges(),
        )
    }
    fn validate(
        trace: &P256ValueBusTraceV1,
        program: &ProgramV1,
    ) -> Result<(), P256ValueBusErrorV1> {
        trace.validate(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
            challenges(),
        )
    }
    fn endpoint_events(endpoint: &P256ValueBusEndpointTraceV1) -> Vec<ExpectedAccessV1> {
        endpoint
            .segments
            .iter()
            .flat_map(|segment| {
                segment.rows.iter().map(|row| ExpectedAccessV1 {
                    fixed: row.fixed,
                    value: row.value,
                    source_bound: false,
                })
            })
            .collect()
    }
    fn rebuild_endpoint(endpoint: &P256ValueBusEndpointTraceV1) -> P256ValueBusEndpointTraceV1 {
        build_endpoint_v1(endpoint.endpoint, &endpoint_events(endpoint), challenges())
            .expect("rebuild endpoint products")
    }
    fn row_mut(
        endpoint: &mut P256ValueBusEndpointTraceV1,
        ordinal: usize,
    ) -> &mut P256ValueBusRowV1 {
        let segment = ordinal / P256_VALUE_BUS_SEGMENT_ROWS_V1;
        let local = ordinal % P256_VALUE_BUS_SEGMENT_ROWS_V1;
        &mut endpoint.segments[segment].rows[local]
    }
    fn set_row_value(row: &mut P256ValueBusRowV1, value: u16) {
        row.value = F(u64::from(value));
        row.value_bits = core::array::from_fn(|bit| F(u64::from((value >> bit) & 1)));
    }
    fn set_id_value(events: &mut [ExpectedAccessV1], id: P256ValueIdV1, value: u16) {
        for event in events {
            if matches!(
                event.fixed,
                P256ValueBusFixedAccessV1::Active { id: event_id, .. } if event_id == id
            ) {
                event.value = F(u64::from(value));
            }
        }
    }
    fn raw_trace(program: &ProgramV1) -> P256ValueBusTraceV1 {
        let execution = execution_events_v1(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
        )
        .expect("raw execution events");
        let sorted = sorted_events_v1(&execution).expect("raw sorted events");
        P256ValueBusTraceV1 {
            execution: build_endpoint_v1(
                P256ValueBusEndpointV1::Execution,
                &execution,
                challenges(),
            )
            .expect("raw execution"),
            sorted: build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted, challenges())
                .expect("raw sorted"),
        }
    }
    #[test]
    fn canonical_bus_has_exact_writers_sorted_adjacency_and_segment_boundaries() {
        let program = program(0);
        let trace = build(&program).expect("canonical value bus");
        validate(&trace, &program).expect("canonical validation");
        assert_eq!(trace.execution.segments.len(), 8);
        assert_eq!(trace.sorted.segments.len(), 8);
        let execution = execution_events_v1(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
        )
        .expect("execution schedule");
        assert_eq!(execution.len(), 8 * P256_VALUE_BUS_SEGMENT_ROWS_V1);
        assert_eq!(
            execution
                .iter()
                .filter(|event| event.fixed == P256ValueBusFixedAccessV1::Inactive)
                .count(),
            80
        );
        for (index, segment) in trace.execution.segments.iter().enumerate() {
            assert_eq!(segment.index as usize, index);
            assert_eq!(segment.rows.len(), P256_VALUE_BUS_SEGMENT_ROWS_V1);
            if index == 0 {
                assert_eq!(segment.product_before, [F::ONE; P256_VALUE_BUS_LANES_V1]);
            } else {
                assert_eq!(
                    segment.product_before,
                    trace.execution.segments[index - 1].product_after
                );
            }
        }
        assert!(
            evaluate_zk_x509_p256_value_bus_terminal_constraints_v1(
                &trace.execution,
                &trace.sorted,
            )
            .expect("terminal constraints")
            .iter()
            .all(|constraint| *constraint == F::ZERO)
        );
        let mut arithmetic_only = program;
        arithmetic_only.equalities.clear();
        arithmetic_only.bridges.clear();
        let trace = build(&arithmetic_only).expect("arithmetic-only bus");
        assert_eq!(trace.execution.segments.len(), arithmetic_only.linked.len());
        validate(&trace, &arithmetic_only).expect("arithmetic-only validation");
    }
    #[test]
    fn checked_writer_accessor_regenerates_exact_initial_and_derived_addresses() {
        let program = program(1);
        let trace = build(&program).expect("canonical value bus");
        let initial_count = program.initial.len();
        let base = P256ValueBusBaseEndpointTraceV1 {
            endpoint: trace.execution.endpoint,
            rows: trace
                .execution
                .segments
                .iter()
                .flat_map(|segment| {
                    segment.rows.iter().map(|row| P256ValueBusBaseCellV1 {
                        fixed: row.fixed,
                        value: row.value,
                    })
                })
                .collect(),
        };
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Ok(F(3))
        );
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(1),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Constant,
            ),
            Ok(F(5))
        );
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(5),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Derived,
            ),
            Ok(F(15))
        );
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(5),
                15,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Derived,
            ),
            Ok(F::ZERO)
        );
        for (id, limb, kind, expected) in [
            (0, 0, P256ValueKindV1::Input, F(3)),
            (1, 0, P256ValueKindV1::Constant, F(5)),
            (5, 0, P256ValueKindV1::Derived, F(15)),
            (5, 15, P256ValueKindV1::Derived, F::ZERO),
        ] {
            assert_eq!(
                p256_value_bus_base_writer_limb_cell_v1(
                    &base,
                    initial_count,
                    P256ValueIdV1(id),
                    limb,
                    ZkX509P256ModulusV1::BaseField,
                    kind,
                ),
                Ok(expected)
            );
        }
        for result in [
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(0),
                P256_VALUE_BUS_LIMBS_V1,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count + 1,
                P256ValueIdV1(5),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Derived,
            ),
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::ScalarField,
                P256ValueKindV1::Input,
            ),
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Derived,
            ),
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(5),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            p256_value_bus_writer_limb_cell_v1(
                &trace,
                initial_count,
                P256ValueIdV1(u32::MAX),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Derived,
            ),
        ] {
            assert!(result.is_err());
        }
        let mut wrong_endpoint = trace.clone();
        wrong_endpoint.execution.endpoint = P256ValueBusEndpointV1::Sorted;
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &wrong_endpoint,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut wrong_address = trace.clone();
        wrong_address.execution.segments[0].rows[48].fixed = P256ValueBusFixedAccessV1::Inactive;
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &wrong_address,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Source)
        );
        let mut non_limb = trace;
        non_limb.execution.segments[0].rows[48].value = F(u64::from(u16::MAX) + 1);
        assert_eq!(
            p256_value_bus_writer_limb_cell_v1(
                &non_limb,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Range)
        );
        let mut wrong_base_endpoint = base.clone();
        wrong_base_endpoint.endpoint = P256ValueBusEndpointV1::Sorted;
        assert_eq!(
            p256_value_bus_base_writer_limb_cell_v1(
                &wrong_base_endpoint,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut wrong_base_address = base.clone();
        wrong_base_address.rows[48].fixed = P256ValueBusFixedAccessV1::Inactive;
        assert_eq!(
            p256_value_bus_base_writer_limb_cell_v1(
                &wrong_base_address,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Source)
        );
        let mut coordinated_wrong_base_address = base.clone();
        coordinated_wrong_base_address.rows[48] = P256ValueBusBaseCellV1 {
            fixed: P256ValueBusFixedAccessV1::Inactive,
            value: F(u64::MAX),
        };
        assert_eq!(
            p256_value_bus_base_writer_limb_cell_v1(
                &coordinated_wrong_base_address,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Source)
        );
        let mut truncated_base = base.clone();
        let _ = truncated_base.rows.pop();
        assert_eq!(
            p256_value_bus_base_writer_limb_cell_v1(
                &truncated_base,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut extended_base = base.clone();
        extended_base.rows.push(P256ValueBusBaseCellV1 {
            fixed: P256ValueBusFixedAccessV1::Inactive,
            value: F::ZERO,
        });
        assert_eq!(
            p256_value_bus_base_writer_limb_cell_v1(
                &extended_base,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut non_limb_base = base;
        non_limb_base.rows[48].value = F(u64::from(u16::MAX) + 1);
        assert_eq!(
            p256_value_bus_base_writer_limb_cell_v1(
                &non_limb_base,
                initial_count,
                P256ValueIdV1(0),
                0,
                ZkX509P256ModulusV1::BaseField,
                P256ValueKindV1::Input,
            ),
            Err(P256ValueBusErrorV1::Range)
        );
    }
    #[test]
    fn execution_source_projection_is_exact_flattened_and_fail_closed() {
        let program = program(1);
        let trace = build(&program).expect("canonical value bus");
        let rows = trace.execution.segments.len() * P256_VALUE_BUS_SEGMENT_ROWS_V1;
        for ordinal in 0..rows {
            let segment = ordinal / P256_VALUE_BUS_SEGMENT_ROWS_V1;
            let local = ordinal % P256_VALUE_BUS_SEGMENT_ROWS_V1;
            assert_eq!(
                p256_value_bus_execution_source_cell_v1(&trace, ordinal),
                Ok((
                    trace.execution.segments[segment].rows[local].fixed,
                    trace.execution.segments[segment].rows[local].value,
                ))
            );
        }
        assert_eq!(
            p256_value_bus_execution_source_cell_v1(&trace, rows),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut wrong_endpoint = trace.clone();
        wrong_endpoint.execution.endpoint = P256ValueBusEndpointV1::Sorted;
        assert_eq!(
            p256_value_bus_execution_source_cell_v1(&wrong_endpoint, 0),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut wrong_segment = trace.clone();
        wrong_segment.execution.segments[0].index = 1;
        assert_eq!(
            p256_value_bus_execution_source_cell_v1(&wrong_segment, 0),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut short_segment = trace.clone();
        short_segment.execution.segments[0].rows.pop();
        assert_eq!(
            p256_value_bus_execution_source_cell_v1(&short_segment, 0),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut non_limb = trace;
        non_limb.execution.segments[0].rows[0].value = F(u64::from(u16::MAX) + 1);
        assert_eq!(
            p256_value_bus_execution_source_cell_v1(&non_limb, 0),
            Err(P256ValueBusErrorV1::Range)
        );
    }
    #[test]
    fn every_source_bound_execution_access_is_checked_pointwise() {
        let program = program(0);
        let trace = build(&program).expect("canonical value bus");
        let expected = execution_events_v1(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
        )
        .expect("execution schedule");
        let mut mutations = 0_usize;
        for (ordinal, event) in expected.iter().enumerate() {
            if !event.source_bound {
                continue;
            }
            let mut changed = trace.clone();
            let value = event.value.0 as u16 ^ 1;
            set_row_value(row_mut(&mut changed.execution, ordinal), value);
            assert_eq!(
                validate(&changed, &program),
                Err(P256ValueBusErrorV1::Source),
                "source access {ordinal}"
            );
            mutations += 1;
        }
        assert_eq!(mutations, 6 * 48 + 5 * 16);
    }
    #[test]
    fn all_tuple_fields_bits_products_and_inactive_padding_are_constrained() {
        let program = program(0);
        let trace = build(&program).expect("canonical value bus");
        let expected = execution_events_v1(
            &program.initial,
            &program.linked,
            &program.equalities,
            &program.bridges,
            &program.arithmetic,
        )
        .expect("execution schedule");
        for bit in 0..P256_VALUE_BUS_LIMBS_V1 {
            let mut row = trace.execution.segments[0].rows[0];
            row.value_bits[bit] = F(2);
            assert_eq!(
                validate_row_range_v1(&row),
                Err(P256ValueBusErrorV1::Range),
                "bit {bit}"
            );
        }
        let mut row = trace.execution.segments[0].rows[0];
        row.value = F(1 << 16);
        row.value_bits = [F::ZERO; P256_VALUE_BUS_LIMBS_V1];
        assert_eq!(validate_row_range_v1(&row), Err(P256ValueBusErrorV1::Range));
        row.value = F(u64::MAX);
        assert_eq!(validate_row_range_v1(&row), Err(P256ValueBusErrorV1::Range));
        for ordinal in 0..expected.len() {
            for lane in 0..P256_VALUE_BUS_LANES_V1 {
                let mut changed = trace.execution.clone();
                row_mut(&mut changed, ordinal).product_after[lane] =
                    row_mut(&mut changed, ordinal).product_after[lane].add(F::ONE);
                assert_eq!(
                    changed.validate(
                        P256ValueBusEndpointV1::Execution,
                        &expected,
                        true,
                        challenges(),
                    ),
                    Err(P256ValueBusErrorV1::Constraint),
                    "product row {ordinal}, lane {lane}"
                );
            }
        }
        let inactive = 5 * P256_VALUE_BUS_SEGMENT_ROWS_V1 + 48;
        assert_eq!(
            trace.execution.row(inactive).expect("inactive").fixed,
            P256ValueBusFixedAccessV1::Inactive
        );
        let mut changed = trace.clone();
        set_row_value(row_mut(&mut changed.execution, inactive), 1);
        assert_eq!(
            validate(&changed, &program),
            Err(P256ValueBusErrorV1::Range)
        );
        let mut changed = trace.clone();
        row_mut(&mut changed.execution, inactive).fixed = trace.execution.segments[0].rows[0].fixed;
        assert_eq!(
            validate(&changed, &program),
            Err(P256ValueBusErrorV1::Topology)
        );
        let sorted_inactive = expected.len() - 1;
        assert_eq!(
            trace
                .sorted
                .row(sorted_inactive)
                .expect("sorted inactive")
                .fixed,
            P256ValueBusFixedAccessV1::Inactive
        );
        let mut changed = trace;
        set_row_value(row_mut(&mut changed.sorted, sorted_inactive), 1);
        assert_eq!(
            validate(&changed, &program),
            Err(P256ValueBusErrorV1::Range)
        );
    }
    #[test]
    fn sequential_ids_unique_writers_moduli_and_operation_kinds_fail_closed() {
        let canonical = program(0);
        let mut empty = canonical.clone();
        empty.initial.clear();
        empty.linked.clear();
        empty.arithmetic.fixed.clear();
        empty.arithmetic.base.clear();
        assert_eq!(build(&empty), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.initial[1].id = P256ValueIdV1(0);
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.linked[0].c = P256ValueIdV1(6);
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.linked[0].a = P256ValueIdV1(10);
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.linked.truncate(changed.initial.len() - 1);
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.initial[0].modulus = ZkX509P256ModulusV1::ScalarField;
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.initial[0].value = P256_BASE_MODULUS_BE_V1;
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.linked[0].operation.kind = ZkX509P256ArithmeticKindV1::Add;
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Source));
        let mut changed = canonical.clone();
        changed.linked[0].operation.a = small(4);
        assert_eq!(build(&changed), Err(P256ValueBusErrorV1::Source));
        let trace = build(&canonical).expect("canonical value bus");
        let expected = execution_events_v1(
            &canonical.initial,
            &canonical.linked,
            &canonical.equalities,
            &canonical.bridges,
            &canonical.arithmetic,
        )
        .expect("canonical execution events");
        let mut duplicate_events = expected.clone();
        let P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            modulus,
            value_kind,
            ..
        } = duplicate_events[0].fixed
        else {
            panic!("active read")
        };
        duplicate_events[0].fixed = P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            access: P256ValueAccessKindV1::Write,
            modulus,
            value_kind,
        };
        assert_eq!(
            validate_unique_writers_v1(&duplicate_events, 11),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut missing_events = expected;
        let P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            modulus,
            value_kind,
            ..
        } = missing_events[2].fixed
        else {
            panic!("active writer")
        };
        missing_events[2].fixed = P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            access: P256ValueAccessKindV1::Read,
            modulus,
            value_kind,
        };
        assert_eq!(
            validate_unique_writers_v1(&missing_events, 11),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut changed_program = canonical.clone();
        changed_program.initial[0].kind = P256InitialValueKindV1::Constant;
        assert_eq!(
            validate(&trace, &changed_program),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut duplicate_writer = trace.clone();
        let read = duplicate_writer.execution.segments[0].rows[0].fixed;
        let P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            modulus,
            value_kind,
            ..
        } = read
        else {
            panic!("active read")
        };
        duplicate_writer.execution.segments[0].rows[0].fixed = P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            access: P256ValueAccessKindV1::Write,
            modulus,
            value_kind,
        };
        duplicate_writer.execution = rebuild_endpoint(&duplicate_writer.execution);
        assert_eq!(
            validate(&duplicate_writer, &canonical),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut missing_writer = trace;
        let writer = missing_writer.execution.segments[0].rows[2].fixed;
        let P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            modulus,
            value_kind,
            ..
        } = writer
        else {
            panic!("active writer")
        };
        missing_writer.execution.segments[0].rows[2].fixed = P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            access: P256ValueAccessKindV1::Read,
            modulus,
            value_kind,
        };
        missing_writer.execution = rebuild_endpoint(&missing_writer.execution);
        assert_eq!(
            validate(&missing_writer, &canonical),
            Err(P256ValueBusErrorV1::Topology)
        );
    }
    #[test]
    fn verifier_fixed_access_metadata_rejects_coordinated_endpoint_changes() {
        let program = program(0);
        let trace = build(&program).expect("canonical value bus");
        let original = trace.execution.segments[0].rows[0].fixed;
        let P256ValueBusFixedAccessV1::Active {
            id,
            limb,
            access,
            modulus,
            value_kind,
        } = original
        else {
            panic!("active fixed row")
        };
        let mutations = [
            P256ValueBusFixedAccessV1::Active {
                id: P256ValueIdV1(id.0 + 1),
                limb,
                access,
                modulus,
                value_kind,
            },
            P256ValueBusFixedAccessV1::Active {
                id,
                limb: limb + 1,
                access,
                modulus,
                value_kind,
            },
            P256ValueBusFixedAccessV1::Active {
                id,
                limb,
                access: P256ValueAccessKindV1::Write,
                modulus,
                value_kind,
            },
            P256ValueBusFixedAccessV1::Active {
                id,
                limb,
                access,
                modulus: ZkX509P256ModulusV1::ScalarField,
                value_kind,
            },
            P256ValueBusFixedAccessV1::Active {
                id,
                limb,
                access,
                modulus,
                value_kind: P256ValueKindV1::Constant,
            },
        ];
        for fixed in mutations {
            let mut changed = trace.clone();
            changed.execution.segments[0].rows[0].fixed = fixed;
            changed.execution = rebuild_endpoint(&changed.execution);
            assert_eq!(
                validate(&changed, &program),
                Err(P256ValueBusErrorV1::Topology)
            );
        }
    }
    #[test]
    fn sorted_adjacency_and_four_lane_permutation_resist_coordinated_values() {
        let program = program(0);
        let trace = build(&program).expect("canonical value bus");
        let mut sorted_events = endpoint_events(&trace.sorted);
        let read = sorted_events
            .iter_mut()
            .find(|event| {
                matches!(
                    event.fixed,
                    P256ValueBusFixedAccessV1::Active {
                        id: P256ValueIdV1(0),
                        limb: 0,
                        access: P256ValueAccessKindV1::Read,
                        ..
                    }
                )
            })
            .expect("sorted read");
        read.value = F(4);
        let mut changed = trace.clone();
        changed.sorted =
            build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events, challenges())
                .expect("changed sorted products");
        assert_eq!(
            validate(&changed, &program),
            Err(P256ValueBusErrorV1::Adjacency)
        );
        let mut sorted_events = endpoint_events(&trace.sorted);
        set_id_value(&mut sorted_events, P256ValueIdV1(0), 4);
        let mut changed = trace.clone();
        changed.sorted =
            build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events, challenges())
                .expect("changed sorted group");
        assert_eq!(
            validate(&changed, &program),
            Err(P256ValueBusErrorV1::Terminal)
        );
        let mut execution_events = endpoint_events(&trace.execution);
        let mut sorted_events = endpoint_events(&trace.sorted);
        set_id_value(&mut execution_events, P256ValueIdV1(0), 4);
        set_id_value(&mut sorted_events, P256ValueIdV1(0), 4);
        let coordinated = P256ValueBusTraceV1 {
            execution: build_endpoint_v1(
                P256ValueBusEndpointV1::Execution,
                &execution_events,
                challenges(),
            )
            .expect("coordinated execution"),
            sorted: build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events, challenges())
                .expect("coordinated sorted"),
        };
        assert_eq!(
            validate(&coordinated, &program),
            Err(P256ValueBusErrorV1::Source)
        );
        for lane in 0..P256_VALUE_BUS_LANES_V1 {
            let canonical = compress_access_v1(original_active(), F(3), challenges().lanes[lane]);
            for mutation in tuple_mutations() {
                assert_ne!(
                    canonical,
                    compress_access_v1(mutation, F(3), challenges().lanes[lane]),
                    "tuple lane {lane}"
                );
            }
            assert_ne!(
                canonical,
                compress_access_v1(original_active(), F(4), challenges().lanes[lane]),
                "value tuple lane {lane}"
            );
        }
    }
    fn original_active() -> P256ValueBusFixedAccessV1 {
        P256ValueBusFixedAccessV1::Active {
            id: P256ValueIdV1(7),
            limb: 3,
            access: P256ValueAccessKindV1::Read,
            modulus: ZkX509P256ModulusV1::BaseField,
            value_kind: P256ValueKindV1::Derived,
        }
    }
    fn tuple_mutations() -> [P256ValueBusFixedAccessV1; 5] {
        [
            P256ValueBusFixedAccessV1::Active {
                id: P256ValueIdV1(8),
                limb: 3,
                access: P256ValueAccessKindV1::Read,
                modulus: ZkX509P256ModulusV1::BaseField,
                value_kind: P256ValueKindV1::Derived,
            },
            P256ValueBusFixedAccessV1::Active {
                id: P256ValueIdV1(7),
                limb: 4,
                access: P256ValueAccessKindV1::Read,
                modulus: ZkX509P256ModulusV1::BaseField,
                value_kind: P256ValueKindV1::Derived,
            },
            P256ValueBusFixedAccessV1::Active {
                id: P256ValueIdV1(7),
                limb: 3,
                access: P256ValueAccessKindV1::Write,
                modulus: ZkX509P256ModulusV1::BaseField,
                value_kind: P256ValueKindV1::Derived,
            },
            P256ValueBusFixedAccessV1::Active {
                id: P256ValueIdV1(7),
                limb: 3,
                access: P256ValueAccessKindV1::Read,
                modulus: ZkX509P256ModulusV1::ScalarField,
                value_kind: P256ValueKindV1::Derived,
            },
            P256ValueBusFixedAccessV1::Active {
                id: P256ValueIdV1(7),
                limb: 3,
                access: P256ValueAccessKindV1::Read,
                modulus: ZkX509P256ModulusV1::BaseField,
                value_kind: P256ValueKindV1::Input,
            },
        ]
    }
    #[test]
    fn equality_rows_are_explicit_same_modulus_and_memory_bound() {
        let canonical = program(0);
        build(&canonical).expect("true equality");
        let mut false_equality = canonical.clone();
        false_equality.equalities[0] = P256EqualityBindingV1 {
            left: P256ValueIdV1(6),
            right: P256ValueIdV1(8),
        };
        assert_eq!(build(&false_equality), Err(P256ValueBusErrorV1::Equality));
        assert_eq!(
            validate(&raw_trace(&false_equality), &false_equality),
            Err(P256ValueBusErrorV1::Equality)
        );
        let mut different_modulus = canonical.clone();
        different_modulus.equalities[0] = P256EqualityBindingV1 {
            left: P256ValueIdV1(3),
            right: P256ValueIdV1(4),
        };
        assert_eq!(
            build(&different_modulus),
            Err(P256ValueBusErrorV1::Topology)
        );
        let mut self_equality = canonical.clone();
        self_equality.equalities[0].right = self_equality.equalities[0].left;
        assert_eq!(build(&self_equality), Err(P256ValueBusErrorV1::Topology));
        let mut unknown_id = canonical.clone();
        unknown_id.equalities[0].right = P256ValueIdV1(99);
        assert_eq!(build(&unknown_id), Err(P256ValueBusErrorV1::Topology));
        let false_trace = raw_trace(&false_equality);
        let mut execution_events = endpoint_events(&false_trace.execution);
        let mut sorted_events = endpoint_events(&false_trace.sorted);
        set_id_value(&mut execution_events, P256ValueIdV1(6), 23);
        set_id_value(&mut sorted_events, P256ValueIdV1(6), 23);
        let coordinated = P256ValueBusTraceV1 {
            execution: build_endpoint_v1(
                P256ValueBusEndpointV1::Execution,
                &execution_events,
                challenges(),
            )
            .expect("coordinated equality execution"),
            sorted: build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events, challenges())
                .expect("coordinated equality sorted"),
        };
        assert_eq!(
            validate(&coordinated, &false_equality),
            Err(P256ValueBusErrorV1::Source)
        );
    }
    #[test]
    fn boolean_bridge_accepts_zero_and_one_and_rejects_every_non_bit_shape() {
        build(&program(0)).expect("zero bridge");
        build(&program(1)).expect("one bridge");
        assert_eq!(build(&program(2)), Err(P256ValueBusErrorV1::BooleanBridge));
        assert_eq!(
            build(&program(1 << 16)),
            Err(P256ValueBusErrorV1::BooleanBridge)
        );
        let mut swapped = program(0);
        swapped.bridges[0] = P256BooleanBridgeBindingV1 {
            scalar_bit: P256ValueIdV1(4),
            base_bit: P256ValueIdV1(3),
        };
        assert_eq!(build(&swapped), Err(P256ValueBusErrorV1::Topology));
        let program = program(0);
        let trace = build(&program).expect("canonical bridge");
        let mut execution_events = endpoint_events(&trace.execution);
        let mut sorted_events = endpoint_events(&trace.sorted);
        for id in [P256ValueIdV1(3), P256ValueIdV1(4)] {
            set_id_value(&mut execution_events, id, 1);
            set_id_value(&mut sorted_events, id, 1);
        }
        let coordinated = P256ValueBusTraceV1 {
            execution: build_endpoint_v1(
                P256ValueBusEndpointV1::Execution,
                &execution_events,
                challenges(),
            )
            .expect("coordinated bridge execution"),
            sorted: build_endpoint_v1(P256ValueBusEndpointV1::Sorted, &sorted_events, challenges())
                .expect("coordinated bridge sorted"),
        };
        assert_eq!(
            validate(&coordinated, &program),
            Err(P256ValueBusErrorV1::Source)
        );
    }
    #[test]
    fn subtraction_operations_use_the_same_fixed_bus_without_special_cases() {
        let operations = vec![
            operation(
                ZkX509P256ArithmeticKindV1::Subtract,
                ZkX509P256ModulusV1::BaseField,
                9,
                4,
                5,
            ),
            operation(
                ZkX509P256ArithmeticKindV1::Add,
                ZkX509P256ModulusV1::BaseField,
                5,
                4,
                9,
            ),
        ];
        let program = ProgramV1 {
            initial: vec![
                P256InitialValueBindingV1 {
                    id: P256ValueIdV1(0),
                    modulus: ZkX509P256ModulusV1::BaseField,
                    value: small(9),
                    kind: P256InitialValueKindV1::Input,
                },
                P256InitialValueBindingV1 {
                    id: P256ValueIdV1(1),
                    modulus: ZkX509P256ModulusV1::BaseField,
                    value: small(4),
                    kind: P256InitialValueKindV1::Input,
                },
            ],
            linked: vec![
                P256LinkedOperationV1 {
                    a: P256ValueIdV1(0),
                    b: P256ValueIdV1(1),
                    c: P256ValueIdV1(2),
                    operation: operations[0],
                },
                P256LinkedOperationV1 {
                    a: P256ValueIdV1(2),
                    b: P256ValueIdV1(1),
                    c: P256ValueIdV1(3),
                    operation: operations[1],
                },
            ],
            equalities: vec![P256EqualityBindingV1 {
                left: P256ValueIdV1(0),
                right: P256ValueIdV1(3),
            }],
            bridges: Vec::new(),
            arithmetic: build_zk_x509_p256_arithmetic_trace_v1(&operations)
                .expect("subtraction arithmetic"),
        };
        let trace = build(&program).expect("subtraction value bus");
        validate(&trace, &program).expect("subtraction bus validation");
    }
    #[test]
    fn omitted_reordered_duplicated_and_reindexed_segments_fail() {
        let program = program(0);
        let trace = build(&program).expect("canonical value bus");
        let mut omitted = trace.clone();
        omitted.execution.segments.pop();
        assert!(validate(&omitted, &program).is_err());
        let mut duplicated = trace.clone();
        duplicated
            .sorted
            .segments
            .push(duplicated.sorted.segments[0].clone());
        assert!(validate(&duplicated, &program).is_err());
        let mut reordered = trace.clone();
        reordered.execution.segments.swap(0, 1);
        assert!(validate(&reordered, &program).is_err());
        let mut coordinated_reorder = trace.clone();
        coordinated_reorder.execution.segments.swap(0, 1);
        for (index, segment) in coordinated_reorder
            .execution
            .segments
            .iter_mut()
            .enumerate()
        {
            segment.index = index as u32;
        }
        assert!(validate(&coordinated_reorder, &program).is_err());
        let mut reindexed = trace.clone();
        reindexed.sorted.segments[2].index ^= 1;
        assert_eq!(
            validate(&reindexed, &program),
            Err(P256ValueBusErrorV1::Constraint)
        );
        let mut boundary = trace;
        boundary.execution.segments[1].product_before[2] =
            boundary.execution.segments[1].product_before[2].add(F::ONE);
        assert_eq!(
            validate(&boundary, &program),
            Err(P256ValueBusErrorV1::Constraint)
        );
    }
    type NumericEndpointRowsV1 = (
        Vec<[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1]>,
        Vec<[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1]>,
        Vec<[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1]>,
    );
    fn numeric_endpoint_rows(
        program: &ProgramV1,
        trace: &P256ValueBusTraceV1,
        endpoint: P256ValueBusStarkEndpointV1,
        trace_size: usize,
    ) -> NumericEndpointRowsV1 {
        let typed = match endpoint {
            P256ValueBusStarkEndpointV1::Execution => &trace.execution,
            P256ValueBusStarkEndpointV1::Sorted => &trace.sorted,
        };
        let rows = P256ValueBusStarkRowProviderV1::new_v1(typed, endpoint, trace_size)
            .expect("numeric row provider");
        let fixed =
            fixed_provider_v1(program, endpoint, trace_size).expect("numeric fixed provider");
        (
            (0..trace_size)
                .map(|row| rows.base_row_v1(row).expect("base row"))
                .collect(),
            (0..trace_size)
                .map(|row| rows.aux_row_v1(row).expect("aux row"))
                .collect(),
            (0..trace_size)
                .map(|row| fixed.row_v1(row).expect("fixed row"))
                .collect(),
        )
    }
    fn numeric_endpoint_residues(
        base: &[[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1]],
        aux: &[[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1]],
        fixed: &[[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1]],
    ) -> Vec<F> {
        let rows = base.len();
        assert_eq!(aux.len(), rows);
        assert_eq!(fixed.len(), rows);
        (0..rows)
            .flat_map(|row| {
                evaluate_p256_value_bus_stark_residues_v1(
                    &base[row],
                    &base[(row + 1) % rows],
                    &aux[row],
                    &aux[(row + 1) % rows],
                    &fixed[row],
                    challenges(),
                )
                .expect("numeric residues")
            })
            .collect()
    }
    #[test]
    fn numeric_fixed_and_row_providers_cover_active_logical_and_domain_padding() {
        let program = program(1);
        let trace = build(&program).expect("canonical value bus");
        let trace_size = 1 << 10;
        for endpoint in [
            P256ValueBusStarkEndpointV1::Execution,
            P256ValueBusStarkEndpointV1::Sorted,
        ] {
            let (base, aux, fixed) = numeric_endpoint_rows(&program, &trace, endpoint, trace_size);
            assert!(
                numeric_endpoint_residues(&base, &aux, &fixed)
                    .iter()
                    .all(|residue| *residue == F::ZERO)
            );
            let typed = match endpoint {
                P256ValueBusStarkEndpointV1::Execution => &trace.execution,
                P256ValueBusStarkEndpointV1::Sorted => &trace.sorted,
            };
            let rows = P256ValueBusStarkRowProviderV1::new_v1(typed, endpoint, trace_size)
                .expect("column row provider");
            let fixed_provider =
                fixed_provider_v1(&program, endpoint, trace_size).expect("column fixed provider");
            for column in 0..P256_VALUE_BUS_STARK_BASE_WIDTH_V1 {
                let mut output = vec![F::ZERO; trace_size];
                rows.fill_base_column_v1(column, &mut output)
                    .expect("base column");
                assert!(
                    output
                        .iter()
                        .zip(&base)
                        .all(|(value, row)| *value == row[column])
                );
            }
            for column in 0..P256_VALUE_BUS_STARK_AUX_WIDTH_V1 {
                let mut output = vec![F::ZERO; trace_size];
                rows.fill_aux_column_v1(column, &mut output)
                    .expect("aux column");
                assert!(
                    output
                        .iter()
                        .zip(&aux)
                        .all(|(value, row)| *value == row[column])
                );
            }
            for column in 0..P256_VALUE_BUS_STARK_FIXED_WIDTH_V1 {
                let mut output = vec![F::ZERO; trace_size];
                fixed_provider
                    .fill_fixed_column_v1(column, &mut output)
                    .expect("fixed column");
                assert!(
                    output
                        .iter()
                        .zip(&fixed)
                        .all(|(value, row)| *value == row[column])
                );
            }
            assert_eq!(fixed[0][STARK_FIXED_FIRST], F::ONE);
            assert_eq!(fixed[trace_size - 1][STARK_FIXED_CONTINUATION], F::ZERO);
            let packed_rows = trace.execution.segments.len() * P256_VALUE_BUS_SEGMENT_ROWS_V1
                / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
            for row in packed_rows..trace_size {
                assert_eq!(base[row], [F::ZERO; P256_VALUE_BUS_STARK_BASE_WIDTH_V1]);
                assert_eq!(fixed[row][STARK_FIXED_PADDING], F::ONE);
                assert_eq!(
                    fixed[row][stark_fixed_offset_v1(1) + STARK_FIXED_PADDING],
                    F::ONE
                );
            }
        }
        let (execution_base, execution_aux, execution_fixed) = numeric_endpoint_rows(
            &program,
            &trace,
            P256ValueBusStarkEndpointV1::Execution,
            trace_size,
        );
        let (sorted_base, sorted_aux, _) = numeric_endpoint_rows(
            &program,
            &trace,
            P256ValueBusStarkEndpointV1::Sorted,
            trace_size,
        );
        assert_ne!(execution_base, sorted_base);
        let terminal_offset = stark_aux_product_offset_v1(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1);
        let opened_execution_terminal: [F; P256_VALUE_BUS_LANES_V1] = execution_aux[trace_size - 1]
            [terminal_offset..terminal_offset + P256_VALUE_BUS_LANES_V1]
            .try_into()
            .expect("terminal width");
        assert_eq!(
            p256_value_bus_stark_opened_terminal_v1(&execution_aux[trace_size - 1]),
            opened_execution_terminal,
        );
        assert_eq!(
            p256_value_bus_stark_opened_terminal_v1(&execution_aux[trace_size - 1]),
            p256_value_bus_stark_opened_terminal_v1(&sorted_aux[trace_size - 1]),
        );
        assert!(
            evaluate_p256_value_bus_stark_terminal_openings_v1(
                &execution_aux[trace_size - 1],
                &sorted_aux[trace_size - 1],
            )
            .iter()
            .all(|residue| *residue == F::ZERO)
        );
        let last_selector =
            p256_value_bus_stark_last_domain_selector_v1(&execution_fixed[trace_size - 1]);
        assert_eq!(last_selector, F::ONE);
        assert!(
            evaluate_p256_value_bus_stark_terminal_opened_rows_v1(
                last_selector,
                &execution_aux[trace_size - 1],
                &sorted_aux[trace_size - 1],
            )
            .iter()
            .all(|residue| *residue == F::ZERO)
        );
        assert_eq!(
            p256_value_bus_stark_last_domain_selector_v1(&execution_fixed[0]),
            F::ZERO
        );
    }
    #[test]
    fn numeric_fixed_provider_is_independent_of_private_values() {
        let first = program(0);
        let second = program(1);
        let trace_size = 1 << 10;
        for endpoint in [
            P256ValueBusStarkEndpointV1::Execution,
            P256ValueBusStarkEndpointV1::Sorted,
        ] {
            let first =
                fixed_provider_v1(&first, endpoint, trace_size).expect("first fixed provider");
            let second =
                fixed_provider_v1(&second, endpoint, trace_size).expect("second fixed provider");
            for row in 0..trace_size {
                assert_eq!(
                    first.row_v1(row).expect("first fixed row"),
                    second.row_v1(row).expect("second fixed row"),
                    "private-value-dependent fixed row {row}",
                );
            }
        }
    }
    #[test]
    fn numeric_fixed_provider_rejects_adversarial_ssa_topologies() {
        let program = program(1);
        let (initial, linked) = fixed_topology_v1(&program);
        let trace_size = 1 << 10;
        let rejects = |initial: &[P256InitialValueTopologyV1],
                       linked: &[P256LinkedOperationTopologyV1],
                       equalities: &[P256EqualityBindingV1],
                       bridges: &[P256BooleanBridgeBindingV1]| {
            assert_eq!(
                P256ValueBusStarkFixedProviderV1::new_v1(
                    P256ValueBusStarkEndpointV1::Execution,
                    initial,
                    linked,
                    equalities,
                    bridges,
                    trace_size,
                )
                .map(|_| ()),
                Err(P256ValueBusErrorV1::Topology),
            );
        };
        let mut changed_initial = initial.clone();
        changed_initial[0].id.0 = 1;
        rejects(
            &changed_initial,
            &linked,
            &program.equalities,
            &program.bridges,
        );
        let mut changed_linked = linked.clone();
        changed_linked[0].a = changed_linked[0].c;
        rejects(
            &initial,
            &changed_linked,
            &program.equalities,
            &program.bridges,
        );
        changed_linked = linked.clone();
        changed_linked[0].c.0 += 1;
        rejects(
            &initial,
            &changed_linked,
            &program.equalities,
            &program.bridges,
        );
        changed_linked = linked.clone();
        changed_linked[0].modulus = ZkX509P256ModulusV1::ScalarField;
        rejects(
            &initial,
            &changed_linked,
            &program.equalities,
            &program.bridges,
        );
        let self_equality = [P256EqualityBindingV1 {
            left: P256ValueIdV1(0),
            right: P256ValueIdV1(0),
        }];
        rejects(&initial, &linked, &self_equality, &program.bridges);
        let reversed_bridge = [P256BooleanBridgeBindingV1 {
            scalar_bit: P256ValueIdV1(4),
            base_bit: P256ValueIdV1(3),
        }];
        rejects(&initial, &linked, &program.equalities, &reversed_bridge);
    }
    #[test]
    fn numeric_adapter_rejects_every_committed_column_mutation_and_terminal_forgery() {
        let program = program(1);
        let trace = build(&program).expect("canonical value bus");
        let trace_size = 1 << 10;
        let (base, aux, fixed) = numeric_endpoint_rows(
            &program,
            &trace,
            P256ValueBusStarkEndpointV1::Execution,
            trace_size,
        );
        assert!(
            numeric_endpoint_residues(&base, &aux, &fixed)
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
        for column in 0..P256_VALUE_BUS_STARK_BASE_WIDTH_V1 {
            let mut changed = base.clone();
            changed[0][column] = changed[0][column].add(F::ONE);
            assert!(
                numeric_endpoint_residues(&changed, &aux, &fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "active base column {column}"
            );
        }
        for column in 0..P256_VALUE_BUS_STARK_AUX_WIDTH_V1 {
            let mut changed = aux.clone();
            changed[0][column] = changed[0][column].add(F::ONE);
            assert!(
                numeric_endpoint_residues(&base, &changed, &fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "active aux column {column}"
            );
        }
        let padding = trace.execution.segments.len() * P256_VALUE_BUS_SEGMENT_ROWS_V1
            / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        for column in 0..P256_VALUE_BUS_STARK_BASE_WIDTH_V1 {
            let mut changed = base.clone();
            changed[padding][column] = F::ONE;
            assert!(
                numeric_endpoint_residues(&changed, &aux, &fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "padding base column {column}"
            );
        }
        for row in [padding, trace_size - 1] {
            for column in 0..P256_VALUE_BUS_STARK_AUX_WIDTH_V1 {
                let mut changed = aux.clone();
                changed[row][column] = changed[row][column].add(F::ONE);
                assert!(
                    numeric_endpoint_residues(&base, &changed, &fixed)
                        .iter()
                        .any(|residue| *residue != F::ZERO),
                    "boundary aux row {row} column {column}"
                );
            }
        }
        let (_, mut sorted_aux, _) = numeric_endpoint_rows(
            &program,
            &trace,
            P256ValueBusStarkEndpointV1::Sorted,
            trace_size,
        );
        let terminal_offset = stark_aux_product_offset_v1(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1);
        sorted_aux[trace_size - 1][terminal_offset] =
            sorted_aux[trace_size - 1][terminal_offset].add(F::ONE);
        assert!(
            evaluate_p256_value_bus_stark_terminal_openings_v1(
                &aux[trace_size - 1],
                &sorted_aux[trace_size - 1],
            )
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
        assert!(
            evaluate_p256_value_bus_stark_terminal_opened_rows_v1(
                F::ONE,
                &aux[trace_size - 1],
                &sorted_aux[trace_size - 1],
            )
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
        assert_eq!(
            evaluate_p256_value_bus_stark_terminal_opened_rows_v1(
                F::ZERO,
                &aux[trace_size - 1],
                &sorted_aux[trace_size - 1],
            ),
            [F::ZERO; P256_VALUE_BUS_LANES_V1]
        );
    }
    fn assert_numeric_base_attack_rejected_v1(
        base: &[[F; P256_VALUE_BUS_STARK_BASE_WIDTH_V1]],
        aux: &[[F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1]],
        fixed: &[[F; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1]],
    ) {
        assert!(
            numeric_endpoint_residues(base, aux, fixed)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
    }
    #[test]
    fn exact_two_factor_packing_rejects_swaps_drops_duplicates_splices_and_activation() {
        let program = program(1);
        let trace = build(&program).expect("canonical value bus");
        let trace_size = 1 << 10;
        let (base, aux, fixed) = numeric_endpoint_rows(
            &program,
            &trace,
            P256ValueBusStarkEndpointV1::Execution,
            trace_size,
        );
        assert!(
            numeric_endpoint_residues(&base, &aux, &fixed)
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
        let mut within_row_swap = base.clone();
        for column in 0..STARK_BASE_SLOT_WIDTH {
            within_row_swap[0].swap(column, STARK_BASE_SLOT_WIDTH + column);
        }
        assert_numeric_base_attack_rejected_v1(&within_row_swap, &aux, &fixed);
        let mut cross_row_swap = base.clone();
        cross_row_swap.swap(0, 1);
        assert_numeric_base_attack_rejected_v1(&cross_row_swap, &aux, &fixed);
        let mut dropped = base.clone();
        dropped[0][..STARK_BASE_SLOT_WIDTH].fill(F::ZERO);
        assert_numeric_base_attack_rejected_v1(&dropped, &aux, &fixed);
        let mut duplicated = base.clone();
        let first_slot: [F; STARK_BASE_SLOT_WIDTH] = duplicated[0][..STARK_BASE_SLOT_WIDTH]
            .try_into()
            .expect("slot");
        duplicated[0][STARK_BASE_SLOT_WIDTH..2 * STARK_BASE_SLOT_WIDTH]
            .copy_from_slice(&first_slot);
        assert_numeric_base_attack_rejected_v1(&duplicated, &aux, &fixed);
        let mut segment_boundary_splice = base.clone();
        segment_boundary_splice.swap(
            P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1,
            P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
        );
        assert_numeric_base_attack_rejected_v1(&segment_boundary_splice, &aux, &fixed);
        let packed_rows = trace.execution.segments.len() * P256_VALUE_BUS_SEGMENT_ROWS_V1
            / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let mut inactive_factor_activation = base;
        inactive_factor_activation[packed_rows][STARK_BASE_VALUE] = F::ONE;
        inactive_factor_activation[packed_rows][STARK_BASE_BITS] = F::ONE;
        assert_numeric_base_attack_rejected_v1(&inactive_factor_activation, &aux, &fixed);
    }
    #[test]
    fn odd_terminal_factor_is_canonical_identity_padding() {
        let mut current = [F::ZERO; P256_VALUE_BUS_STARK_BASE_WIDTH_V1];
        current[STARK_BASE_VALUE] = F(7);
        for bit in 0..P256_VALUE_BUS_LIMBS_V1 {
            current[STARK_BASE_BITS + bit] = F((7 >> bit) & 1);
        }
        let mut fixed = [F::ZERO; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1];
        fixed[STARK_FIXED_ACTIVE] = F::ONE;
        fixed[STARK_FIXED_ID] = F(9);
        fixed[STARK_FIXED_LIMB] = F(3);
        fixed[STARK_FIXED_ACCESS] = F::ONE;
        fixed[STARK_FIXED_MODULUS] = F::ONE;
        fixed[STARK_FIXED_VALUE_KIND] = F::ONE;
        fixed[stark_fixed_offset_v1(1) + STARK_FIXED_PADDING] = F::ONE;
        fixed[STARK_FIXED_FIRST] = F::ONE;
        let mut aux = [F::ZERO; P256_VALUE_BUS_STARK_AUX_WIDTH_V1];
        for lane in 0..P256_VALUE_BUS_LANES_V1 {
            aux[stark_aux_product_offset_v1(0) + lane] = F::ONE;
            let terms = challenges().lanes[lane].terms;
            let factor = terms[0]
                .add(F(9).mul(terms[1]))
                .add(F(3).mul(terms[2]))
                .add(terms[3])
                .add(terms[4])
                .add(terms[5])
                .add(F(7).mul(terms[6]));
            aux[stark_aux_product_offset_v1(1) + lane] = factor;
            aux[stark_aux_product_offset_v1(2) + lane] = factor;
        }
        let residues = evaluate_p256_value_bus_stark_residues_v1(
            &current,
            &current,
            &aux,
            &aux,
            &fixed,
            challenges(),
        )
        .expect("odd-factor residues");
        assert!(residues.iter().all(|residue| *residue == F::ZERO));
        let mut forged = aux;
        forged[stark_aux_product_offset_v1(2)] = forged[stark_aux_product_offset_v1(2)].add(F::ONE);
        assert!(
            evaluate_p256_value_bus_stark_residues_v1(
                &current,
                &current,
                &forged,
                &forged,
                &fixed,
                challenges(),
            )
            .expect("forged odd-factor residues")
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
    }
    #[test]
    fn challenge_validation_and_derivation_are_lane_separated() {
        let program = program(0);
        let mut bad = challenges();
        bad.lanes[1].terms[4] = F::ZERO;
        assert_eq!(
            build_zk_x509_p256_value_bus_trace_v1(
                &program.initial,
                &program.linked,
                &program.equalities,
                &program.bridges,
                &program.arithmetic,
                bad,
            ),
            Err(P256ValueBusErrorV1::Challenge)
        );
        let mut bad = challenges();
        bad.lanes[2] = bad.lanes[0];
        assert_eq!(
            build_zk_x509_p256_value_bus_trace_v1(
                &program.initial,
                &program.linked,
                &program.equalities,
                &program.bridges,
                &program.arithmetic,
                bad,
            ),
            Err(P256ValueBusErrorV1::Challenge)
        );
        let mut bad = challenges();
        bad.lanes[2].terms[6] = bad.lanes[0].terms[1];
        assert_eq!(
            build_zk_x509_p256_value_bus_trace_v1(
                &program.initial,
                &program.linked,
                &program.equalities,
                &program.bridges,
                &program.arithmetic,
                bad,
            ),
            Err(P256ValueBusErrorV1::Challenge)
        );
        let mut bad = challenges();
        bad.lanes[0].terms[0] = F(u64::MAX);
        assert_eq!(
            build_zk_x509_p256_value_bus_trace_v1(
                &program.initial,
                &program.linked,
                &program.equalities,
                &program.bridges,
                &program.arithmetic,
                bad,
            ),
            Err(P256ValueBusErrorV1::Challenge)
        );
        let mut transcript = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"p256-value-bus-test",
            &PrivacyOuterDigestV1::from_bytes([0x51; 48]),
            &PrivacyOuterDigestV1::from_bytes([0xa7; 48]),
        )
        .expect("test transcript");
        let derived = derive_zk_x509_p256_value_bus_challenges_v1(&mut transcript)
            .expect("derived challenges");
        derived.validate().expect("separated challenge lanes");
        let flat: Vec<_> = derived.lanes.iter().flat_map(|lane| lane.terms).collect();
        for (index, value) in flat.iter().enumerate() {
            assert!(!flat[..index].contains(value));
        }
    }
    #[test]
    fn bound_endpoint_replay_matches_direct_terminals_and_rejects_cached_mutation() {
        let program = program(1);
        for seed in [37, 41] {
            let mut base = base_source_v1(&program);
            let mut bound = base.bind_v1(post_base_v1(seed)).unwrap();
            for expected in [
                P256ValueBusStarkEndpointV1::Execution,
                P256ValueBusStarkEndpointV1::Sorted,
            ] {
                let endpoint = match expected {
                    P256ValueBusStarkEndpointV1::Execution => {
                        bound.execution_endpoint_v1().unwrap()
                    }
                    P256ValueBusStarkEndpointV1::Sorted => bound.sorted_endpoint_v1().unwrap(),
                };
                let mut direct = P256ValueBusStarkAuxSourceV1::new_v1(
                    endpoint,
                    expected,
                    P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
                    bound.post_base_v1().unwrap().p256_value(),
                )
                .unwrap();
                let mut replay = bound.bound_aux_source_v1(expected).unwrap();
                assert_eq!(direct.terminal_v1(), replay.terminal_v1());
                for _ in 0..P256_VALUE_BUS_STARK_TRACE_SIZE_V1 {
                    let wanted =
                        zeroize::Zeroizing::new(direct.next_aux_row_v1().unwrap().unwrap());
                    let actual =
                        zeroize::Zeroizing::new(replay.next_aux_row_v1().unwrap().unwrap());
                    assert_eq!(*actual, *wanted);
                }
                assert!(direct.next_aux_row_v1().unwrap().is_none());
                assert!(replay.next_aux_row_v1().unwrap().is_none());
                drop(direct);
                drop(replay);
                let terminal = match expected {
                    P256ValueBusStarkEndpointV1::Execution => &mut bound.execution_terminal,
                    P256ValueBusStarkEndpointV1::Sorted => &mut bound.sorted_terminal,
                };
                terminal[0] = terminal[0].add(F::ONE);
                let mut mutated = bound.bound_aux_source_v1(expected).unwrap();
                for _ in 0..P256_VALUE_BUS_STARK_TRACE_SIZE_V1 - 1 {
                    let _row = zeroize::Zeroizing::new(mutated.next_aux_row_v1().unwrap().unwrap());
                }
                assert_eq!(
                    mutated.next_aux_row_v1(),
                    Err(P256ValueBusErrorV1::Constraint)
                );
                drop(mutated);
                let terminal = match expected {
                    P256ValueBusStarkEndpointV1::Execution => &mut bound.execution_terminal,
                    P256ValueBusStarkEndpointV1::Sorted => &mut bound.sorted_terminal,
                };
                terminal[0] = terminal[0].sub(F::ONE);
            }
            bound.zeroize_private_v1();
            assert!(matches!(
                bound.execution_aux_source_v1(),
                Err(P256ValueBusErrorV1::Phase)
            ));
            assert!(matches!(
                bound.sorted_aux_source_v1(),
                Err(P256ValueBusErrorV1::Phase)
            ));
        }
    }
    #[test]
    fn phased_base_and_fixed_rows_ignore_x5b1_while_auxiliary_products_bind_it() {
        let program = program(1);
        let mut first = base_source_v1(&program);
        let mut second = base_source_v1(&program);
        let sampled_rows = 32;
        for endpoint in [
            P256ValueBusStarkEndpointV1::Execution,
            P256ValueBusStarkEndpointV1::Sorted,
        ] {
            for row in 0..sampled_rows {
                assert_eq!(
                    first.base_row_v1(endpoint, row),
                    second.base_row_v1(endpoint, row),
                    "base row depended on a future X5B1 token at {endpoint:?}/{row}",
                );
                assert_eq!(
                    first.fixed_row_v1(endpoint, row),
                    second.fixed_row_v1(endpoint, row),
                    "fixed row depended on a future X5B1 token at {endpoint:?}/{row}",
                );
            }
        }
        assert!(!first.bind_attempted_for_test_v1());
        assert!(!second.bind_attempted_for_test_v1());
        let first_base = (0..sampled_rows)
            .map(|row| {
                first
                    .base_row_v1(P256ValueBusStarkEndpointV1::Execution, row)
                    .expect("first base")
            })
            .collect::<Vec<_>>();
        let first_fixed = (0..sampled_rows)
            .map(|row| {
                first
                    .fixed_row_v1(P256ValueBusStarkEndpointV1::Execution, row)
                    .expect("first fixed")
            })
            .collect::<Vec<_>>();
        let first_bound = first.bind_v1(post_base_v1(0x11)).expect("first bind");
        let second_bound = second.bind_v1(post_base_v1(0x71)).expect("second bind");
        assert!(first.bind_attempted_for_test_v1());
        assert!(second.bind_attempted_for_test_v1());
        assert_eq!(
            first.bind_v1(post_base_v1(0x12)).map(|_| ()),
            Err(P256ValueBusErrorV1::Phase),
        );
        assert_eq!(
            first
                .base_row_v1(P256ValueBusStarkEndpointV1::Execution, 0)
                .map(|_| ()),
            Err(P256ValueBusErrorV1::Phase),
            "base-phase capability survived X5B1 binding",
        );
        let first_bound_base = first_bound
            .execution_base_rows_v1()
            .expect("bound base rows");
        for row in 0..sampled_rows {
            assert_eq!(
                first_bound_base.base_row_v1(row).expect("bound base"),
                first_base[row],
            );
            assert_eq!(
                first_bound
                    .execution_fixed_row_v1(row)
                    .expect("bound fixed"),
                first_fixed[row],
            );
        }
        let mut first_aux = first_bound
            .execution_aux_source_v1()
            .expect("first auxiliary replay");
        let mut second_aux = second_bound
            .execution_aux_source_v1()
            .expect("second auxiliary replay");
        let mut differs = false;
        for _ in 0..sampled_rows {
            let first_row = first_aux
                .next_aux_row_v1()
                .expect("first auxiliary row")
                .expect("first auxiliary row exists");
            let second_row = second_aux
                .next_aux_row_v1()
                .expect("second auxiliary row")
                .expect("second auxiliary row exists");
            differs |= first_row != second_row;
        }
        assert!(
            differs,
            "distinct X5B1 tokens produced identical auxiliaries"
        );
        assert_eq!(
            first_aux.terminal_v1(),
            first_bound
                .sorted_aux_source_v1()
                .expect("sorted auxiliary replay")
                .terminal_v1(),
        );
    }
    #[test]
    fn phased_source_matches_legacy_projection_base_and_auxiliary_rows() {
        let program = program(1);
        let challenge = challenges();
        let legacy = build(&program).expect("legacy test-only bus");
        let base = base_material_v1(&program);
        assert_eq!(
            base.execution.rows.len(),
            legacy.execution.segments.len() * 64
        );
        for ordinal in 0..base.execution.rows.len() {
            assert_eq!(
                p256_value_bus_base_execution_source_cell_v1(&base.execution, ordinal),
                p256_value_bus_execution_source_cell_v1(&legacy, ordinal),
                "writer projection diverged at logical row {ordinal}",
            );
        }
        let trace_size = 1 << 10;
        for (base_endpoint, legacy_endpoint, endpoint) in [
            (
                &base.execution,
                &legacy.execution,
                P256ValueBusStarkEndpointV1::Execution,
            ),
            (
                &base.sorted,
                &legacy.sorted,
                P256ValueBusStarkEndpointV1::Sorted,
            ),
        ] {
            let phased_base =
                P256ValueBusStarkBaseRowProviderV1::new_v1(base_endpoint, endpoint, trace_size)
                    .expect("phased base rows");
            let legacy_rows =
                P256ValueBusStarkRowProviderV1::new_v1(legacy_endpoint, endpoint, trace_size)
                    .expect("legacy rows");
            let mut phased_aux = P256ValueBusStarkAuxSourceV1::new_v1(
                base_endpoint,
                endpoint,
                trace_size,
                challenge,
            )
            .expect("phased auxiliary rows");
            for row in 0..trace_size {
                assert_eq!(
                    phased_base.base_row_v1(row).expect("phased base"),
                    legacy_rows.base_row_v1(row).expect("legacy base"),
                    "base projection diverged at {endpoint:?}/{row}",
                );
                assert_eq!(
                    phased_aux
                        .next_aux_row_v1()
                        .expect("phased auxiliary")
                        .expect("phased row"),
                    legacy_rows.aux_row_v1(row).expect("legacy auxiliary"),
                    "auxiliary replay diverged at {endpoint:?}/{row}",
                );
            }
            assert_eq!(phased_aux.next_aux_row_v1(), Ok(None));
        }
    }
    #[test]
    fn phased_source_rejects_ssa_value_padding_and_sorted_corruption() {
        let program = program(1);
        let mut changed = base_material_v1(&program);
        changed.execution.rows[0].fixed = P256ValueBusFixedAccessV1::Inactive;
        assert_eq!(
            changed.validate_integrity_v1(),
            Err(P256ValueBusErrorV1::Topology),
        );
        let mut changed = base_material_v1(&program);
        changed.execution.rows[0].value = changed.execution.rows[0].value.add(F::ONE);
        assert!(changed.validate_integrity_v1().is_err());
        let mut changed = base_material_v1(&program);
        let padding = changed
            .execution
            .rows
            .iter()
            .position(|row| row.fixed == P256ValueBusFixedAccessV1::Inactive)
            .expect("logical segment padding");
        changed.execution.rows[padding].value = F::ONE;
        assert_eq!(
            changed.validate_integrity_v1(),
            Err(P256ValueBusErrorV1::Range),
        );
        let mut changed = base_material_v1(&program);
        changed.sorted.rows.swap(0, 1);
        assert!(changed.validate_integrity_v1().is_err());
        let mut changed = base_material_v1(&program);
        changed.sorted.rows[0].value = changed.sorted.rows[0].value.add(F::ONE);
        assert_eq!(
            changed.validate_integrity_v1(),
            Err(P256ValueBusErrorV1::Adjacency),
        );
        let mut source = base_source_v1(&program);
        source
            .material_mut_for_test_v1()
            .expect("mutable pre-bind source")
            .sorted
            .rows[0]
            .value = F(0xffff);
        assert!(
            source.bind_v1(post_base_v1(0x31)).is_err(),
            "corrupted base source reached the auxiliary phase",
        );
        assert!(source.bind_attempted_for_test_v1());
        assert_eq!(
            source.bind_v1(post_base_v1(0x32)).map(|_| ()),
            Err(P256ValueBusErrorV1::Phase),
            "failed bind was retryable with another token",
        );
        assert_eq!(
            source
                .fixed_row_v1(P256ValueBusStarkEndpointV1::Execution, 0)
                .map(|_| ()),
            Err(P256ValueBusErrorV1::Phase),
        );
    }
    #[test]
    fn canonical_topology_validation_rejects_every_value_bus_family_mutation() {
        let program = program(1);
        let canonical = topology_v1(&program, P256EcdsaRoleV1::WalletOwnership);
        let validate = |expected: &P256EcdsaTopologyV1| {
            validate_value_bus_topology_components_v1(
                P256EcdsaRoleV1::WalletOwnership,
                &program.initial,
                &program.linked,
                &program.equalities,
                &program.bridges,
                expected,
            )
        };
        validate(&canonical).expect("canonical value-bus topology");
        let mut changed = canonical.clone();
        changed.role = P256EcdsaRoleV1::CertificateOrCrl;
        assert_eq!(validate(&changed), Err(P256ValueBusErrorV1::Topology));
        for mutate in 0..3 {
            let mut changed = canonical.clone();
            match mutate {
                0 => changed.initial_values[0].id.0 += 1,
                1 => changed.initial_values[0].modulus = ZkX509P256ModulusV1::ScalarField,
                2 => changed.initial_values[0].kind = P256InitialValueKindV1::Constant,
                _ => unreachable!(),
            }
            assert_eq!(validate(&changed), Err(P256ValueBusErrorV1::Topology));
        }
        for mutate in 0..5 {
            let mut changed = canonical.clone();
            match mutate {
                0 => changed.linked_operations[0].a.0 += 1,
                1 => changed.linked_operations[0].b.0 += 1,
                2 => changed.linked_operations[0].c.0 += 1,
                3 => {
                    changed.linked_operations[0].kind = ZkX509P256ArithmeticKindV1::Add;
                }
                4 => {
                    changed.linked_operations[0].modulus = ZkX509P256ModulusV1::ScalarField;
                }
                _ => unreachable!(),
            }
            assert_eq!(validate(&changed), Err(P256ValueBusErrorV1::Topology));
        }
        let mut changed = canonical.clone();
        changed.equalities.clear();
        assert_eq!(validate(&changed), Err(P256ValueBusErrorV1::Topology));
        let mut changed = canonical.clone();
        changed.boolean_bridges.clear();
        assert_eq!(validate(&changed), Err(P256ValueBusErrorV1::Topology));
    }
    #[test]
    fn phased_private_material_zeroizes_recursively() {
        let ((), observations) = super::super::private_table::inspection::observe_v1(
            phased_private_material_zeroizes_recursively_body_v1,
        );
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
    fn phased_private_material_zeroizes_recursively_body_v1() {
        let program = program(1);
        let mut material = base_material_v1(&program);
        material.zeroize_private_v1();
        assert!(material.private_is_zeroized_v1());
        let mut source = base_source_v1(&program);
        source.zeroize_private_v1();
        assert!(source.private_is_zeroized_v1());
        assert_eq!(
            source
                .base_row_v1(P256ValueBusStarkEndpointV1::Execution, 0)
                .map(|_| ()),
            Err(P256ValueBusErrorV1::Phase),
        );
    }
}
