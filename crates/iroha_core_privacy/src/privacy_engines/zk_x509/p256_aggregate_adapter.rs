//! Heterogeneous-domain numeric aggregate adapters for the exact P-256 relation.
//!
//! Every adapter uses its smallest protocol-supported power-of-two native domain. Cross-trace
//! products consume cells projected directly from that adapter's committed base row. Explicit
//! verifier-ordered terminal claims are transcript-bound after auxiliary commitments, constrained
//! at each source's own final native row, then equality-checked by the verifier. There is no copied
//! bridge trace or unconstrained host lift. Verifier preprocessing and challenge-dependent traces
//! can both be replayed one native column at a time.
//!
//! This is the first-release aggregate registration surface.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::main_assembly::ZkX509MainTraceAssemblyV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_cross_trace_bus::evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::ClearingVecV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    credential_pre_aux::ZkX509CredentialMainPostBaseChallengesV1,
    p256_air::{
        ZkX509P256ArithmeticTraceV1, compact_arithmetic::P256CompactArithmeticTraceV1,
        p256_arithmetic_opened_c_limb_bits_v1,
    },
    p256_cross_trace_bus::{
        P256CrossTraceRegularAuxRowV1, P256CrossTraceSinkStreamV1,
        P256CrossTraceWriterSourceStreamV1, build_zk_x509_p256_cross_trace_sink_v1,
        build_zk_x509_p256_cross_trace_writer_source_v1,
    },
    p256_external_binding_air::{
        P256ExternalBindingTraceV1, P256OptionalCertificateSelectionV1,
        build_zk_x509_p256_external_binding_trace_v1, p256_external_binding_rows_v1,
    },
    p256_reduction_air::{P256LowSTraceV1, P256ReductionTraceV1},
    p256_scalar_bit_bus::{P256ScalarBitBusBaseSourceV1, P256ScalarBitBusBoundSourceV1},
    p256_trace::P256EcdsaTraceMaterialV1,
    p256_value_bus::{
        P256ValueBusBaseSourceV1, P256ValueBusBoundSourceV1, P256ValueBusStarkAuxSourceV1,
        P256ValueBusStarkBaseRowProviderV1,
    },
    p256_window_air::{
        P256WindowBatchStarkTraceV1, P256WindowTraceV1, build_p256_window_batch_stark_trace_v1,
    },
    rfc5280_stark::{
        ZkX509P256CertificatePrivateProductsV1, ZkX509P256PrivateProductsV1,
        ZkX509P256WalletPrivateProductsV1,
    },
};
use super::{
    p256_air::{
        P256_ARITHMETIC_BASE_WIDTH_V1, P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
        P256_ARITHMETIC_STARK_AUX_WIDTH_V1, P256_ARITHMETIC_STARK_CONSTRAINT_COUNT_V1,
        P256_ARITHMETIC_STARK_FIXED_WIDTH_V1, P256ArithmeticStarkFixedProviderV1,
        ZkX509P256AirErrorV1, ZkX509P256ArithmeticTopologyV1,
        evaluate_p256_arithmetic_stark_residues_over_field_v1,
        p256_arithmetic_opened_operand_limbs_v1, p256_arithmetic_opened_scalar_source_bits_v1,
    },
    p256_cross_trace_bus::{
        P256_CROSS_TRACE_CHALLENGE_TERMS_V1, P256_CROSS_TRACE_LANES_V1,
        P256_CROSS_TRACE_LOW_S_AUX_WIDTH_V1, P256_CROSS_TRACE_LOW_S_TRACE_SIZE_V1,
        P256_CROSS_TRACE_REDUCTION_AUX_WIDTH_V1, P256_CROSS_TRACE_REDUCTION_TRACE_SIZE_V1,
        P256_CROSS_TRACE_SINK_AUX_WIDTH_V1, P256_CROSS_TRACE_SINK_CONSTRAINT_COUNT_V1,
        P256_CROSS_TRACE_SINK_TRACE_SIZE_V1, P256_CROSS_TRACE_VALUE_BUS_TRACE_SIZE_V1,
        P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1, P256_CROSS_TRACE_WINDOW_TRACE_SIZE_V1,
        P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1, P256_CROSS_TRACE_WRITER_CONSTRAINT_COUNT_V1,
        P256CrossTraceBoundaryFixedV1, P256CrossTraceBusErrorV1, P256CrossTraceChallengesV1,
        P256CrossTraceEndpointV1, P256CrossTraceEventFixedV1, P256CrossTraceSinkFixedV1,
        P256CrossTraceTagV1, P256CrossTraceWriterAuxRowV1, P256CrossTraceWriterSourceFixedV1,
        evaluate_zk_x509_p256_cross_trace_writer_row_constraints_v1,
    },
    p256_ecdsa_air::P256EcdsaRoleV1,
    p256_external_binding_air::{
        P256_EXTERNAL_BINDINGS_PER_ROW_V1, P256_INPUT_SELECTION_ROW_START_V1,
        P256_INPUT_SELECTION_SELECTOR_ROW_V1, ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
        ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1, p256_input_selection_byte_v1,
    },
    p256_reduction_air::{
        P256_LOW_S_BASE_WIDTH_V1, P256_LOW_S_STARK_AUX_WIDTH_V1,
        P256_LOW_S_STARK_CONSTRAINT_COUNT_V1, P256_LOW_S_STARK_FIXED_WIDTH_V1,
        P256_REDUCTION_BASE_WIDTH_V1, P256_REDUCTION_ROWS_V1, P256_REDUCTION_STARK_AUX_WIDTH_V1,
        P256_REDUCTION_STARK_CONSTRAINT_COUNT_V1, P256_REDUCTION_STARK_FIXED_WIDTH_V1,
        P256ComparisonStarkFixedProviderV1, P256ReductionAirErrorV1,
        evaluate_p256_low_s_stark_residues_over_field_v1,
        evaluate_p256_reduction_stark_residues_over_field_v1, p256_low_s_opened_binding_cell_v1,
        p256_reduction_opened_binding_cells_v1,
    },
    p256_scalar_bit_bus::{
        P256_SCALAR_BIT_BUS_LANES_V1, P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1,
        P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1, P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1,
        P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1, P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1,
        P256ScalarBitBusChallengesV1, P256ScalarBitBusErrorV1,
        evaluate_p256_scalar_bit_bus_stark_residues_over_field_v1,
    },
    p256_trace::{P256EcdsaTopologyV1, P256TraceCompilerErrorV1, compile_p256_ecdsa_topology_v1},
    p256_value_bus::{
        P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1, P256_VALUE_BUS_LANES_V1,
        P256_VALUE_BUS_SEGMENT_ROWS_V1, P256_VALUE_BUS_STARK_AUX_WIDTH_V1,
        P256_VALUE_BUS_STARK_BASE_WIDTH_V1, P256_VALUE_BUS_STARK_CONSTRAINT_COUNT_V1,
        P256_VALUE_BUS_STARK_FIXED_WIDTH_V1, P256_VALUE_BUS_STARK_TRACE_SIZE_V1,
        P256ValueBusChallengesV1, P256ValueBusErrorV1, P256ValueBusStarkEndpointV1,
        P256ValueBusStarkFixedProviderV1, evaluate_p256_value_bus_stark_residues_over_field_v1,
        p256_value_bus_opened_values_v1,
    },
    p256_window_air::{
        P256_WINDOW_BASE_WIDTH_V1, P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1,
        P256_WINDOW_STARK_AUX_WIDTH_V1, P256_WINDOW_STARK_CONSTRAINT_COUNT_V1,
        P256_WINDOW_STARK_FIXED_WIDTH_V1, P256_WINDOW_STARK_TRACE_SIZE_V1, P256WindowAirErrorV1,
        P256WindowBatchStarkFixedProviderV1, evaluate_p256_window_stark_residues_over_field_v1,
        p256_window_opened_external_cells_v1, p256_window_opened_scalar_bits_v1,
    },
};
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, PolynomialAirFieldV1, TransparentStarkErrorV1, TransparentTranscriptV1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use std::borrow::Cow;
use thiserror::Error;
/// Stable descriptor for the first-release heterogeneous-domain integration layer.
#[cfg(test)]
pub const ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_V1: &[u8] =
    b"zk-x509-p256-aggregate-adapter-v1:heterogeneous-minimal-native-domains:value-log19-exact2-factor-packing:arithmetic-log19:window-log16:reduction-log5:wallet-low-s-log5:sink-log16:scalar-bit-log8:four-independent-domain-separated-permutation-lanes:source-attached-products:direct-committed-base-cell-projections:no-copied-bridge:no-unconstrained-host-lift:terminal-claims-proof-encoded-role-ordered-and-transcript-bound-after-aux-roots-before-composition-fri-grinding-and-queries:each-terminal-claim-constrained-at-its-source-verifier-fixed-terminal-row:cross-start-claims-constrained-at-source-native-first-row:claim-equalities-checked-verifier-side:value-execution-base34-aux116-fixed46-local-constraints210-claim-constraints12-degree3:value-sorted-base34-aux12-fixed22-local-constraints90-claim-constraints4-degree2:arithmetic-base211-aux72-fixed134-local-constraints455-claim-constraints8-degree4:all14828x16x3-arithmetic-operand-result-cells-bound-to-value-bus-by-unique-address:window-vertical128-base61-aux37-fixed47-local-constraints284-claim-constraints8-degree4:reduction-base56-aux19-fixed45-local-constraints148-claim-constraints4-degree4:wallet-low-s-base36-aux14-fixed42-local-constraints98-claim-constraints4-degree3:sink-base25-aux38-fixed36-local-constraints99-claim-constraints4-degree3:scalar-bit-base6-aux32-fixed16-local-constraints67-claim-constraints8-degree3:p256-worst-multiset-cardinality-below2pow20-per-signature:four-lane-local-collision-below2pow176:p256-25-argument-horizontal-five-signature-union-below2pow171:provider-sized-base-fixed-and-aux-column-replay:first-release";
/// SHA-256 of [`ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_V1`].
#[cfg(test)]
pub const ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_SHA256_V1: [u8; 32] = [
    0x2e, 0x47, 0x2f, 0x1d, 0x09, 0x5b, 0x82, 0xeb, 0x9f, 0x46, 0x2d, 0x06, 0xac, 0xbf, 0x2f, 0x01,
    0x1c, 0xfb, 0x7e, 0x49, 0xa3, 0xf4, 0x47, 0x07, 0xcf, 0x89, 0x23, 0x0a, 0xc4, 0xd5, 0x20, 0x34,
];
include!("p256_aggregate_layout.rs");
#[cfg(test)]
#[path = "p256_bound_terminal_replay_tests.rs"]
mod bound_terminal_replay_tests;
#[cfg(test)]
#[path = "p256_fixed_replay_batch_tests.rs"]
mod fixed_replay_batch_tests;
#[cfg(test)]
#[path = "p256_native_boundary_sources.rs"]
mod native_boundary_sources;
/// Aggregate adapter construction or algebraic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum P256AggregateAdapterErrorV1 {
    /// A base-only or challenge-bound capability was used in the wrong phase.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 aggregate adapter phase is invalid")]
    Phase,
    /// A role, adapter order, row count, fixed schedule, or opening is wrong.
    #[error("zk-X509 P-256 aggregate adapter topology is invalid")]
    Topology,
    /// One committed source row is absent or has the wrong native shape.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 aggregate source row is invalid")]
    Source,
    /// A cross-trace or scalar-bit challenge is invalid.
    #[error("zk-X509 P-256 aggregate challenge is invalid")]
    Challenge,
    /// A row, boundary, product, or terminal residue is nonzero.
    #[error("zk-X509 P-256 aggregate constraint failed")]
    Constraint,
    /// Bounded allocation or checked index arithmetic failed.
    #[error("zk-X509 P-256 aggregate resource bound is exceeded")]
    Resource,
}
fn verifier_topology_v1(
    role: P256EcdsaRoleV1,
) -> Result<P256EcdsaTopologyV1, P256AggregateAdapterErrorV1> {
    compile_p256_ecdsa_topology_v1(role).map_err(|error| match error {
        P256TraceCompilerErrorV1::Resource => P256AggregateAdapterErrorV1::Resource,
        _ => P256AggregateAdapterErrorV1::Topology,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_arithmetic_trace_topology_v1(
    trace: &ZkX509P256ArithmeticTraceV1,
    topology: &P256EcdsaTopologyV1,
) -> Result<(), P256AggregateAdapterErrorV1> {
    let expected_rows = topology
        .linked_operations
        .len()
        .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
        .ok_or(P256AggregateAdapterErrorV1::Resource)?;
    if trace.rows() != expected_rows || trace.fixed.len() != expected_rows {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    for (operation, expected) in topology.linked_operations.iter().enumerate() {
        for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
            let row = operation
                .checked_mul(P256_ARITHMETIC_ROWS_PER_OPERATION_V1)
                .and_then(|row| row.checked_add(coefficient))
                .ok_or(P256AggregateAdapterErrorV1::Resource)?;
            let actual = trace
                .fixed
                .get(row)
                .ok_or(P256AggregateAdapterErrorV1::Topology)?;
            if actual.operation as usize != operation
                || actual.coefficient as usize != coefficient
                || actual.kind != expected.kind
                || actual.modulus != expected.modulus
            {
                return Err(P256AggregateAdapterErrorV1::Topology);
            }
        }
    }
    Ok(())
}
/// Independent lanes in the value-bus/arithmetic copy permutation.
pub const P256_ARITHMETIC_COPY_LANES_V1: usize = 4;
/// `beta`, unique cell address, and committed limb value.
pub const P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1: usize = 3;
/// Domain-separated labels for all twelve post-commitment coordinates.
pub const P256_ARITHMETIC_COPY_CHALLENGE_LABELS_V1: [[&[u8];
    P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1];
    P256_ARITHMETIC_COPY_LANES_V1] = [
    [
        b"zk-x509-p256-arithmetic-copy-lane0-beta-v1",
        b"zk-x509-p256-arithmetic-copy-lane0-address-v1",
        b"zk-x509-p256-arithmetic-copy-lane0-value-v1",
    ],
    [
        b"zk-x509-p256-arithmetic-copy-lane1-beta-v1",
        b"zk-x509-p256-arithmetic-copy-lane1-address-v1",
        b"zk-x509-p256-arithmetic-copy-lane1-value-v1",
    ],
    [
        b"zk-x509-p256-arithmetic-copy-lane2-beta-v1",
        b"zk-x509-p256-arithmetic-copy-lane2-address-v1",
        b"zk-x509-p256-arithmetic-copy-lane2-value-v1",
    ],
    [
        b"zk-x509-p256-arithmetic-copy-lane3-beta-v1",
        b"zk-x509-p256-arithmetic-copy-lane3-address-v1",
        b"zk-x509-p256-arithmetic-copy-lane3-value-v1",
    ],
];
/// One arithmetic-copy tuple-compression lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ArithmeticCopyLaneChallengesV1 {
    /// `beta`, address, and value coefficients.
    pub(crate) terms: [F; P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1],
}
/// Four independent post-base-commitment arithmetic-copy products.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ArithmeticCopyChallengesV1 {
    /// Independently sampled tuple-compression lanes.
    pub(crate) lanes: [P256ArithmeticCopyLaneChallengesV1; P256_ARITHMETIC_COPY_LANES_V1],
}
impl P256ArithmeticCopyChallengesV1 {
    /// Reject zero, noncanonical, or repeated coordinates.
    pub(crate) fn validate_v1(self) -> Result<(), P256AggregateAdapterErrorV1> {
        let mut seen =
            [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1 * P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1];
        for (seen_len, term) in self
            .lanes
            .iter()
            .flat_map(|lane| lane.terms.iter())
            .enumerate()
        {
            if *term == F::ZERO || F::canonical(term.0).is_none() || seen[..seen_len].contains(term)
            {
                return Err(P256AggregateAdapterErrorV1::Challenge);
            }
            seen[seen_len] = *term;
        }
        Ok(())
    }
}
/// Derive the arithmetic-copy challenges after both base commitments.
pub fn derive_p256_arithmetic_copy_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<P256ArithmeticCopyChallengesV1, TransparentStarkErrorV1> {
    let mut lanes = [P256ArithmeticCopyLaneChallengesV1 {
        terms: [F::ZERO; P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1],
    }; P256_ARITHMETIC_COPY_LANES_V1];
    for (lane, labels) in lanes
        .iter_mut()
        .zip(P256_ARITHMETIC_COPY_CHALLENGE_LABELS_V1)
    {
        for (term, label) in lane.terms.iter_mut().zip(labels) {
            *term = transcript.challenge_field(label)?;
        }
    }
    Ok(P256ArithmeticCopyChallengesV1 { lanes })
}
macro_rules! map_adapter_error {
    ($error:ty) => {
        impl From<$error> for P256AggregateAdapterErrorV1 {
            fn from(error: $error) -> Self {
                match error {
                    _ => Self::Constraint,
                }
            }
        }
    };
}
map_adapter_error!(ZkX509P256AirErrorV1);
map_adapter_error!(P256WindowAirErrorV1);
map_adapter_error!(P256ReductionAirErrorV1);
map_adapter_error!(P256ScalarBitBusErrorV1);
map_adapter_error!(P256ValueBusErrorV1);
map_adapter_error!(P256CrossTraceBusErrorV1);
map_adapter_error!(super::p256_external_binding_air::P256ExternalBindingErrorV1);
fn f_usize_v1(value: usize) -> Result<F, P256AggregateAdapterErrorV1> {
    Ok(F(
        u64::try_from(value).map_err(|_| P256AggregateAdapterErrorV1::Resource)?
    ))
}
/// Zero a caller-owned destination unless a complete column is committed.
///
/// Callers perform all shape and column-index checks before constructing this
/// guard. Those prevalidation errors therefore preserve the caller's buffer,
/// while every error or panic after the first possible write clears the whole
/// destination rather than exposing a private column prefix.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256AggregateColumnDestinationGuardV1<'a> {
    output: &'a mut [F],
    committed: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256AggregateColumnDestinationGuardV1<'a> {
    fn new_v1(output: &'a mut [F]) -> Self {
        Self {
            output,
            committed: false,
        }
    }
    fn commit_v1(mut self) {
        self.committed = true;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256AggregateColumnDestinationGuardV1<'_> {
    fn drop(&mut self) {
        if !self.committed {
            super::private_table::zeroize_fields_v1(&mut self.output[..]);
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_cross_challenges_v1(challenges: &mut P256CrossTraceChallengesV1) {
    for lane in &mut challenges.lanes {
        super::private_table::zeroize_fields_v1(&mut lane.terms[..]);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_scalar_challenges_v1(challenges: &mut P256ScalarBitBusChallengesV1) {
    for lane in &mut challenges.lanes {
        super::private_table::zeroize_fields_v1(&mut lane.terms[..]);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_arithmetic_copy_challenges_v1(challenges: &mut P256ArithmeticCopyChallengesV1) {
    for lane in &mut challenges.lanes {
        super::private_table::zeroize_fields_v1(&mut lane.terms[..]);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_aggregate_row_column_v1<const WIDTH: usize>(
    rows: usize,
    column: usize,
    output: &mut [F],
    mut row_v1: impl FnMut(usize) -> Result<[F; WIDTH], P256AggregateAdapterErrorV1>,
) -> Result<(), P256AggregateAdapterErrorV1> {
    if column >= WIDTH || output.len() != rows || !rows.is_power_of_two() {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let destination = P256AggregateColumnDestinationGuardV1::new_v1(output);
    for (row, value) in destination.output.iter_mut().enumerate() {
        *value = row_v1(row)?[column];
    }
    destination.commit_v1();
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_aggregate_aux_column_v1<const WIDTH: usize>(
    rows: usize,
    column: usize,
    output: &mut [F],
    mut next_row_v1: impl FnMut() -> Result<Option<[F; WIDTH]>, P256AggregateAdapterErrorV1>,
) -> Result<(), P256AggregateAdapterErrorV1> {
    if column >= WIDTH || output.len() != rows || !rows.is_power_of_two() {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let destination = P256AggregateColumnDestinationGuardV1::new_v1(output);
    for value in destination.output.iter_mut() {
        *value = next_row_v1()?.ok_or(P256AggregateAdapterErrorV1::Topology)?[column];
    }
    if next_row_v1()?.is_some() {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    destination.commit_v1();
    Ok(())
}
/// One commit decision covers every caller-owned destination in a bounded batch.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256AggregateColumnsDestinationGuardV1<'a, 'b> {
    outputs: &'a mut [&'b mut [F]],
    committed: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256AggregateColumnsDestinationGuardV1<'_, '_> {
    fn drop(&mut self) {
        if !self.committed {
            for output in self.outputs.iter_mut() {
                super::private_table::zeroize_fields_v1(output);
            }
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256AggregateAuxRowScratchV1<const WIDTH: usize>([F; WIDTH]);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<const WIDTH: usize> Drop for P256AggregateAuxRowScratchV1<WIDTH> {
    fn drop(&mut self) {
        super::private_table::zeroize_fields_v1(&mut self.0);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_aggregate_aux_columns_v1<const WIDTH: usize>(
    rows: usize,
    first: usize,
    outputs: &mut [&mut [F]],
    mut next_row_v1: impl FnMut() -> Result<Option<[F; WIDTH]>, P256AggregateAdapterErrorV1>,
) -> Result<(), P256AggregateAdapterErrorV1> {
    if outputs.is_empty()
        || outputs.len() > crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
        || first
            .checked_add(outputs.len())
            .is_none_or(|end| end > WIDTH)
        || !rows.is_power_of_two()
        || outputs.iter().any(|output| output.len() != rows)
    {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut destination = P256AggregateColumnsDestinationGuardV1 {
        outputs,
        committed: false,
    };
    for row in 0..rows {
        let values = P256AggregateAuxRowScratchV1(
            next_row_v1()?.ok_or(P256AggregateAdapterErrorV1::Topology)?,
        );
        for (offset, output) in destination.outputs.iter_mut().enumerate() {
            output[row] = values.0[first + offset];
        }
    }
    if let Some(extra) = next_row_v1()? {
        let _clear = P256AggregateAuxRowScratchV1(extra);
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    destination.committed = true;
    Ok(())
}
/// Replay a bounded set of challenge-independent columns through the same
/// transactional destination and clearing row owner as auxiliary replay.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_aggregate_base_columns_v1<const WIDTH: usize>(
    rows: usize,
    first: usize,
    outputs: &mut [&mut [F]],
    mut base_row: impl FnMut(usize) -> Result<[F; WIDTH], P256AggregateAdapterErrorV1>,
) -> Result<(), P256AggregateAdapterErrorV1> {
    let mut row = 0;
    fill_aggregate_aux_columns_v1::<WIDTH>(rows, first, outputs, || {
        if row == rows {
            return Ok(None);
        }
        let values = base_row(row)?;
        row += 1;
        Ok(Some(values))
    })
}
/// Conservative stack charge for either serial arithmetic or value base replay.
/// Native output columns already occupy the unchanged eight-column allowance.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_base_replay_scratch_v1() -> usize {
    core::mem::size_of::<P256ArithmeticAggregateRowsV1<'static>>()
        + core::mem::size_of::<super::p256_value_bus::P256ValueBusStarkBaseRowProviderV1<'static>>()
        + core::mem::size_of::<P256AggregateAuxRowScratchV1<P256_VALUE_BUS_STARK_BASE_WIDTH_V1>>()
        + core::mem::size_of::<P256AggregateColumnsDestinationGuardV1<'static, 'static>>()
        + crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            * core::mem::size_of::<&mut [F]>()
        + 2 * core::mem::size_of::<usize>()
        + 2 * core::mem::size_of::<&P256ValueBusBaseSourceV1>()
        + core::mem::size_of::<P256ValueBusStarkEndpointV1>()
}
/// Stack-owned replay state in addition to the already admitted native columns.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_arithmetic_aux_replay_scratch_v1() -> usize {
    core::mem::size_of::<P256ArithmeticAggregateAuxStreamV1<'static>>()
        + core::mem::size_of::<P256AggregateAuxRowScratchV1<P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1>>(
        )
        + core::mem::size_of::<P256AggregateColumnsDestinationGuardV1<'static, 'static>>()
        + crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            * core::mem::size_of::<&mut [F]>()
        + core::mem::size_of::<P256ArithmeticAuxSelectionV1>()
        + core::mem::size_of::<P256AggregateAuxRowScratchV1<P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1>>(
        )
        + core::mem::size_of::<P256AggregateAuxRowScratchV1<8>>()
        + core::mem::size_of::<[F; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1]>()
        + core::mem::size_of::<[P256ScalarSourceEventFixedV1; 8]>()
        + core::mem::size_of::<[P256ArithmeticCopyEventFixedV1; 3]>()
}
/// Peak stack payload for a serial value-bus batch, beyond existing stream heap scratch.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_value_aux_replay_scratch_v1() -> usize {
    let execution = core::mem::size_of::<P256MainBoundWriterReplayV1<'static>>()
        + core::mem::size_of::<P256ValueExecutionAggregateStreamV1<'static>>()
        + core::mem::size_of::<
            P256AggregateAuxRowScratchV1<P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1>,
        >();
    let sorted = core::mem::size_of::<P256ValueBusStarkAuxSourceV1<'static>>()
        + core::mem::size_of::<P256AggregateAuxRowScratchV1<P256_VALUE_BUS_STARK_AUX_WIDTH_V1>>();
    execution.max(sorted)
        + core::mem::size_of::<P256AggregateColumnsDestinationGuardV1<'static, 'static>>()
        + crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            * core::mem::size_of::<&mut [F]>()
}
fn encode_cross_event_v1(event: P256CrossTraceEventFixedV1, target: &mut [F]) {
    target[0] = event.active;
    target[1] = event.endpoint;
    target[2] = event.address;
}
fn decode_cross_event_v1<A: PolynomialAirFieldV1>(source: &[A]) -> P256CrossTraceEventFixedV1<A> {
    P256CrossTraceEventFixedV1 {
        active: source[0],
        endpoint: source[1],
        address: source[2],
    }
}
fn encode_boundary_v1(boundary: P256CrossTraceBoundaryFixedV1, target: &mut [F]) {
    target[0] = boundary.first;
    target[1] = boundary.last;
    target[2] = boundary.continuation;
}
fn decode_boundary_v1<A: PolynomialAirFieldV1>(source: &[A]) -> P256CrossTraceBoundaryFixedV1<A> {
    P256CrossTraceBoundaryFixedV1 {
        first: source[0],
        last: source[1],
        continuation: source[2],
    }
}
fn active_cross_event_v1(
    endpoint: P256CrossTraceEndpointV1,
    address: usize,
) -> Result<P256CrossTraceEventFixedV1, P256AggregateAdapterErrorV1> {
    Ok(P256CrossTraceEventFixedV1::active(P256CrossTraceTagV1 {
        endpoint,
        address: u32::try_from(address).map_err(|_| P256AggregateAdapterErrorV1::Resource)?,
    }))
}
fn compact_aux_width_v1(events: usize) -> usize {
    events + P256_CROSS_TRACE_LANES_V1 * (events + 1) + P256_CROSS_TRACE_LANES_V1
}
fn compact_products_start_v1(events: usize, lane: usize) -> usize {
    events + lane * (events + 1)
}
fn compact_terminal_start_v1(events: usize) -> usize {
    events + P256_CROSS_TRACE_LANES_V1 * (events + 1)
}
fn cross_factor_v1<A: PolynomialAirFieldV1>(
    fixed: P256CrossTraceEventFixedV1<A>,
    value: A,
    terms: [F; P256_CROSS_TRACE_CHALLENGE_TERMS_V1],
) -> A {
    A::ONE
        .sub(fixed.active)
        .add(fixed.active.mul_base(terms[0]))
        .add(fixed.endpoint.mul_base(terms[1]))
        .add(fixed.address.mul_base(terms[2]))
        .add(value.mul_base(terms[3]))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_compact_cross_aux_row_v1(
    events: &[P256CrossTraceEventFixedV1],
    sources: &[F],
    before: [F; P256_CROSS_TRACE_LANES_V1],
    terminal: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
    target: &mut [F],
) -> Result<[F; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    if events.len() != sources.len() || target.len() != compact_aux_width_v1(events.len()) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    for slot in 0..events.len() {
        target[slot] = events[slot].active.mul(sources[slot]);
    }
    let mut after = [F::ZERO; P256_CROSS_TRACE_LANES_V1];
    for lane in 0..P256_CROSS_TRACE_LANES_V1 {
        let start = compact_products_start_v1(events.len(), lane);
        target[start] = before[lane];
        for slot in 0..events.len() {
            target[start + slot + 1] = target[start + slot].mul(cross_factor_v1(
                events[slot],
                target[slot],
                challenges.lanes[lane].terms,
            ));
        }
        after[lane] = target[start + events.len()];
        target[compact_terminal_start_v1(events.len()) + lane] = terminal[lane];
    }
    Ok(after)
}
fn evaluate_compact_cross_local_residues_v1<A: PolynomialAirFieldV1>(
    events: &[P256CrossTraceEventFixedV1<A>],
    sources: &[A],
    boundary: P256CrossTraceBoundaryFixedV1<A>,
    current: &[A],
    next: &[A],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    challenges
        .validate()
        .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
    let width = compact_aux_width_v1(events.len());
    if events.len() != sources.len() || current.len() != width || next.len() != width {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if sources
        .iter()
        .chain(current)
        .chain(next)
        .any(|value| !value.is_canonical())
        || events.iter().any(|event| {
            !event.active.is_canonical()
                || !event.endpoint.is_canonical()
                || !event.address.is_canonical()
        })
        || [boundary.first, boundary.last, boundary.continuation]
            .into_iter()
            .any(|value| !value.is_canonical())
    {
        return Err(P256AggregateAdapterErrorV1::Constraint);
    }
    let mut residues =
        Vec::with_capacity(events.len() + P256_CROSS_TRACE_LANES_V1 * (events.len() + 3));
    for slot in 0..events.len() {
        residues.push(current[slot].sub(events[slot].active.mul(sources[slot])));
    }
    for lane in 0..P256_CROSS_TRACE_LANES_V1 {
        let product = compact_products_start_v1(events.len(), lane);
        for slot in 0..events.len() {
            let factor = cross_factor_v1(events[slot], current[slot], challenges.lanes[lane].terms);
            residues.push(current[product + slot + 1].sub(current[product + slot].mul(factor)));
        }
        let after = current[product + events.len()];
        residues.push(boundary.continuation.mul(next[product].sub(after)));
        let terminal = compact_terminal_start_v1(events.len()) + lane;
        residues.push(boundary.last.mul(current[terminal].sub(after)));
        residues.push(next[terminal].sub(current[terminal]));
    }
    Ok(residues)
}
fn evaluate_compact_cross_residues_v1<A: PolynomialAirFieldV1>(
    events: &[P256CrossTraceEventFixedV1<A>],
    sources: &[A],
    boundary: P256CrossTraceBoundaryFixedV1<A>,
    current: &[A],
    next: &[A],
    start_values: [F; P256_CROSS_TRACE_LANES_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    if start_values.iter().any(|value| !value.is_canonical()) {
        return Err(P256AggregateAdapterErrorV1::Constraint);
    }
    let mut residues = evaluate_compact_cross_local_residues_v1(
        events, sources, boundary, current, next, challenges,
    )?;
    for (lane, start) in start_values.into_iter().enumerate() {
        residues.push(
            boundary.first.mul(
                current[compact_products_start_v1(events.len(), lane)].sub(A::from_base(start)),
            ),
        );
    }
    Ok(residues)
}
#[cfg(test)]
fn compact_cross_terminal_v1<A: PolynomialAirFieldV1>(
    events: usize,
    aux: &[A],
) -> Result<[A; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    if aux.len() != compact_aux_width_v1(events) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(core::array::from_fn(|lane| {
        aux[compact_terminal_start_v1(events) + lane]
    }))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ArithmeticCopyEventFixedV1<A = F> {
    active: A,
    address: A,
}
impl P256ArithmeticCopyEventFixedV1 {
    const fn inactive_v1() -> Self {
        Self {
            active: F::ZERO,
            address: F::ZERO,
        }
    }
    fn active_v1(address: usize) -> Result<Self, P256AggregateAdapterErrorV1> {
        Ok(Self {
            active: F::ONE,
            address: f_usize_v1(address)?,
        })
    }
}
fn encode_arithmetic_copy_event_v1(event: P256ArithmeticCopyEventFixedV1, target: &mut [F]) {
    target[0] = event.active;
    target[1] = event.address;
}
fn decode_arithmetic_copy_event_v1<A: PolynomialAirFieldV1>(
    source: &[A],
) -> P256ArithmeticCopyEventFixedV1<A> {
    P256ArithmeticCopyEventFixedV1 {
        active: source[0],
        address: source[1],
    }
}
fn arithmetic_copy_factor_v1<A: PolynomialAirFieldV1>(
    fixed: P256ArithmeticCopyEventFixedV1<A>,
    value: A,
    terms: [F; P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1],
) -> A {
    A::ONE
        .sub(fixed.active)
        .add(fixed.active.mul_base(terms[0]))
        .add(fixed.address.mul_base(terms[1]))
        .add(value.mul_base(terms[2]))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_compact_arithmetic_copy_aux_row_v1(
    events: &[P256ArithmeticCopyEventFixedV1],
    sources: &[F],
    before: [F; P256_ARITHMETIC_COPY_LANES_V1],
    terminal: [F; P256_ARITHMETIC_COPY_LANES_V1],
    challenges: P256ArithmeticCopyChallengesV1,
    target: &mut [F],
) -> Result<[F; P256_ARITHMETIC_COPY_LANES_V1], P256AggregateAdapterErrorV1> {
    if events.len() != sources.len() || target.len() != compact_aux_width_v1(events.len()) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    for slot in 0..events.len() {
        target[slot] = events[slot].active.mul(sources[slot]);
    }
    let mut after = [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1];
    for lane in 0..P256_ARITHMETIC_COPY_LANES_V1 {
        let start = compact_products_start_v1(events.len(), lane);
        target[start] = before[lane];
        for slot in 0..events.len() {
            target[start + slot + 1] = target[start + slot].mul(arithmetic_copy_factor_v1(
                events[slot],
                target[slot],
                challenges.lanes[lane].terms,
            ));
        }
        after[lane] = target[start + events.len()];
        target[compact_terminal_start_v1(events.len()) + lane] = terminal[lane];
    }
    Ok(after)
}
fn evaluate_compact_arithmetic_copy_residues_v1<A: PolynomialAirFieldV1>(
    events: &[P256ArithmeticCopyEventFixedV1<A>],
    sources: &[A],
    boundary: P256CrossTraceBoundaryFixedV1<A>,
    current: &[A],
    next: &[A],
    challenges: P256ArithmeticCopyChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    challenges.validate_v1()?;
    let width = compact_aux_width_v1(events.len());
    if events.len() != sources.len() || current.len() != width || next.len() != width {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if sources
        .iter()
        .chain(current)
        .chain(next)
        .any(|value| !value.is_canonical())
        || events.iter().any(|event| {
            [event.active, event.address]
                .iter()
                .any(|value| !value.is_canonical())
        })
        || [boundary.first, boundary.continuation, boundary.last]
            .iter()
            .any(|value| !value.is_canonical())
    {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut residues =
        Vec::with_capacity(events.len() + P256_ARITHMETIC_COPY_LANES_V1 * (events.len() + 4));
    for slot in 0..events.len() {
        residues.push(current[slot].sub(events[slot].active.mul(sources[slot])));
    }
    for lane in 0..P256_ARITHMETIC_COPY_LANES_V1 {
        let product = compact_products_start_v1(events.len(), lane);
        residues.push(boundary.first.mul(current[product].sub(A::ONE)));
        for slot in 0..events.len() {
            let factor = arithmetic_copy_factor_v1(
                events[slot],
                current[slot],
                challenges.lanes[lane].terms,
            );
            residues.push(current[product + slot + 1].sub(current[product + slot].mul(factor)));
        }
        let after = current[product + events.len()];
        residues.push(boundary.continuation.mul(next[product].sub(after)));
        let terminal = compact_terminal_start_v1(events.len()) + lane;
        residues.push(boundary.last.mul(current[terminal].sub(after)));
        residues.push(next[terminal].sub(current[terminal]));
    }
    Ok(residues)
}
fn value_arithmetic_copy_events_v1(
    packed_row: usize,
    arithmetic_operations: usize,
) -> Result<
    [P256ArithmeticCopyEventFixedV1; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
    P256AggregateAdapterErrorV1,
> {
    if packed_row >= P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut events =
        [P256ArithmeticCopyEventFixedV1::inactive_v1(); P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1];
    for (slot, event) in events.iter_mut().enumerate() {
        let ordinal = packed_row
            .checked_mul(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
            .and_then(|ordinal| ordinal.checked_add(slot))
            .ok_or(P256AggregateAdapterErrorV1::Resource)?;
        let operation = ordinal / P256_VALUE_BUS_SEGMENT_ROWS_V1;
        let local = ordinal % P256_VALUE_BUS_SEGMENT_ROWS_V1;
        if operation >= arithmetic_operations || local >= 3 * 16 {
            continue;
        }
        let address = operation
            .checked_mul(3 * 16)
            .and_then(|address| address.checked_add(local))
            .ok_or(P256AggregateAdapterErrorV1::Resource)?;
        *event = P256ArithmeticCopyEventFixedV1::active_v1(address)?;
    }
    Ok(events)
}
fn arithmetic_value_copy_events_v1(
    row: usize,
    logical_rows: usize,
) -> Result<[P256ArithmeticCopyEventFixedV1; 3], P256AggregateAdapterErrorV1> {
    if row >= P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if row >= logical_rows {
        return Ok([P256ArithmeticCopyEventFixedV1::inactive_v1(); 3]);
    }
    let operation = row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
    let coefficient = row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
    if coefficient >= 16 {
        return Ok([P256ArithmeticCopyEventFixedV1::inactive_v1(); 3]);
    }
    let first = operation
        .checked_mul(3 * 16)
        .and_then(|address| address.checked_add(coefficient * 3))
        .ok_or(P256AggregateAdapterErrorV1::Resource)?;
    let mut events = [P256ArithmeticCopyEventFixedV1::inactive_v1(); 3];
    for (slot, event) in events.iter_mut().enumerate() {
        *event = P256ArithmeticCopyEventFixedV1::active_v1(
            first
                .checked_add(slot)
                .ok_or(P256AggregateAdapterErrorV1::Resource)?,
        )?;
    }
    Ok(events)
}
#[cfg(test)]
fn arithmetic_copy_terminal_v1<A: PolynomialAirFieldV1>(
    events: usize,
    aux: &[A],
) -> Result<[A; P256_ARITHMETIC_COPY_LANES_V1], P256AggregateAdapterErrorV1> {
    if aux.len() != compact_aux_width_v1(events) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(core::array::from_fn(|lane| {
        aux[compact_terminal_start_v1(events) + lane]
    }))
}
/// Verifier-owned role of one external cross-product source segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub enum P256CrossTraceTerminalRoleV1 {
    /// Value-bus writer multiplicities.
    ValueWriter,
    /// All 128 vertically packed windows.
    WindowBatch,
    /// Digest reduction output.
    DigestReduction,
    /// Result-X reduction input and output.
    ResultXReduction,
    /// Wallet-only low-S scalar.
    WalletLowS,
}
/// One explicit, transcript-bound source-segment terminal claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256CrossTraceTerminalClaimV1 {
    /// Registration-owned segment role.
    pub(crate) role: P256CrossTraceTerminalRoleV1,
    /// Claimed product entering this segment.
    pub(crate) start: [F; P256_CROSS_TRACE_LANES_V1],
    /// Claimed product leaving this segment.
    pub(crate) terminal: [F; P256_CROSS_TRACE_LANES_V1],
}
/// Explicit transcript-bound claims for the three non-cross product buses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256BusTerminalClaimsV1 {
    /// Value-bus execution permutation terminal.
    pub(crate) value_execution: [F; P256_VALUE_BUS_LANES_V1],
    /// Value-bus sorted permutation terminal.
    pub(crate) value_sorted: [F; P256_VALUE_BUS_LANES_V1],
    /// Value-side arithmetic-cell permutation terminal.
    pub(crate) value_arithmetic_copy: [F; P256_ARITHMETIC_COPY_LANES_V1],
    /// Arithmetic-side cell permutation terminal.
    pub(crate) arithmetic_value_copy: [F; P256_ARITHMETIC_COPY_LANES_V1],
    /// Arithmetic scalar-bit source terminal.
    pub(crate) arithmetic_scalar: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    /// Window scalar-bit source terminal.
    pub(crate) window_scalar: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    /// Arithmetic endpoint terminal in the packed scalar-bit bus.
    pub(crate) scalar_bus_arithmetic: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    /// Window endpoint terminal in the packed scalar-bit bus.
    pub(crate) scalar_bus_window: [F; P256_SCALAR_BIT_BUS_LANES_V1],
}
/// Stable transcript label for all verifier-ordered P-256 terminal claims.
#[cfg(test)]
pub const P256_TERMINAL_CLAIMS_TRANSCRIPT_LABEL_V1: &[u8] = b"zk-x509-p256-terminal-claims-v1";
/// Exact source role order for one ECDSA statement role.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn p256_cross_trace_terminal_roles_v1(
    role: P256EcdsaRoleV1,
) -> &'static [P256CrossTraceTerminalRoleV1] {
    const CERTIFICATE: [P256CrossTraceTerminalRoleV1; 4] = [
        P256CrossTraceTerminalRoleV1::ValueWriter,
        P256CrossTraceTerminalRoleV1::WindowBatch,
        P256CrossTraceTerminalRoleV1::DigestReduction,
        P256CrossTraceTerminalRoleV1::ResultXReduction,
    ];
    const WALLET: [P256CrossTraceTerminalRoleV1; 5] = [
        P256CrossTraceTerminalRoleV1::ValueWriter,
        P256CrossTraceTerminalRoleV1::WindowBatch,
        P256CrossTraceTerminalRoleV1::DigestReduction,
        P256CrossTraceTerminalRoleV1::ResultXReduction,
        P256CrossTraceTerminalRoleV1::WalletLowS,
    ];
    match role {
        P256EcdsaRoleV1::CertificateOrCrl => &CERTIFICATE,
        P256EcdsaRoleV1::WalletOwnership => &WALLET,
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_claim_fields_are_canonical_v1(fields: impl IntoIterator<Item = F>) -> bool {
    fields
        .into_iter()
        .all(|field| F::canonical(field.0).is_some())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_p256_cross_trace_terminal_claims_v1(
    role: P256EcdsaRoleV1,
    sources: &[P256CrossTraceTerminalClaimV1],
) -> Result<(), P256AggregateAdapterErrorV1> {
    let expected = p256_cross_trace_terminal_roles_v1(role);
    if sources.len() != expected.len()
        || sources
            .iter()
            .zip(expected)
            .any(|(source, expected)| source.role != *expected)
        || !p256_claim_fields_are_canonical_v1(
            sources
                .iter()
                .flat_map(|source| source.start.into_iter().chain(source.terminal)),
        )
    {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(())
}
/// Exact host-side terminal-claim equalities, ending at the independent binding sink.
///
/// Private product validation checks this chain before constructing a bound native source.
/// Registered private MAIN endpoint columns bind each product to its source trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_p256_cross_trace_terminal_claim_equalities_v1(
    role: P256EcdsaRoleV1,
    sources: &[P256CrossTraceTerminalClaimV1],
    sink: [F; P256_CROSS_TRACE_LANES_V1],
) -> Result<Vec<F>, P256AggregateAdapterErrorV1> {
    validate_p256_cross_trace_terminal_claims_v1(role, sources)?;
    if !p256_claim_fields_are_canonical_v1(sink) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut residues = Vec::with_capacity((sources.len() + 1) * P256_CROSS_TRACE_LANES_V1);
    for lane in 0..P256_CROSS_TRACE_LANES_V1 {
        residues.push(sources[0].start[lane].sub(F::ONE));
    }
    for pair in sources.windows(2) {
        for lane in 0..P256_CROSS_TRACE_LANES_V1 {
            residues.push(pair[1].start[lane].sub(pair[0].terminal[lane]));
        }
    }
    let final_source = sources
        .last()
        .ok_or(P256AggregateAdapterErrorV1::Topology)?;
    residues.extend(evaluate_zk_x509_p256_cross_trace_terminal_constraints_v1(
        final_source.terminal,
        sink,
    ));
    Ok(residues)
}
/// Host-side equality residues for value, arithmetic-copy, and scalar buses.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_p256_bus_terminal_claim_equalities_v1(
    claims: P256BusTerminalClaimsV1,
) -> Result<[F; 4 * P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    if !p256_claim_fields_are_canonical_v1(
        [
            claims.value_execution,
            claims.value_sorted,
            claims.value_arithmetic_copy,
            claims.arithmetic_value_copy,
            claims.arithmetic_scalar,
            claims.window_scalar,
            claims.scalar_bus_arithmetic,
            claims.scalar_bus_window,
        ]
        .into_iter()
        .flatten(),
    ) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut residues = [F::ZERO; 4 * P256_CROSS_TRACE_LANES_V1];
    for lane in 0..P256_CROSS_TRACE_LANES_V1 {
        residues[lane] = claims.value_execution[lane].sub(claims.value_sorted[lane]);
        residues[P256_CROSS_TRACE_LANES_V1 + lane] =
            claims.value_arithmetic_copy[lane].sub(claims.arithmetic_value_copy[lane]);
        residues[2 * P256_CROSS_TRACE_LANES_V1 + lane] =
            claims.arithmetic_scalar[lane].sub(claims.scalar_bus_arithmetic[lane]);
        residues[3 * P256_CROSS_TRACE_LANES_V1 + lane] =
            claims.window_scalar[lane].sub(claims.scalar_bus_window[lane]);
    }
    Ok(residues)
}
/// Bind an explicit terminal claim to a product carried by one source trace.
///
/// `last_selector` is verifier preprocessing for that source's own native final row, so this works
/// across heterogeneous trace sizes without a host lift.
#[cfg(test)]
pub fn evaluate_p256_terminal_claim_binding_v1<A: PolynomialAirFieldV1>(
    last_selector: A,
    opened_terminal: [A; P256_CROSS_TRACE_LANES_V1],
    claimed_terminal: [F; P256_CROSS_TRACE_LANES_V1],
) -> [A; P256_CROSS_TRACE_LANES_V1] {
    core::array::from_fn(|lane| {
        last_selector.mul(opened_terminal[lane].sub(A::from_base(claimed_terminal[lane])))
    })
}
/// Absorb all canonical terminal claims in the sole verifier-owned order.
///
/// Call this after auxiliary commitment roots and before any composition,
/// FRI, grinding, or query challenge.
#[cfg(test)]
pub fn absorb_p256_terminal_claims_v1(
    transcript: &mut TransparentTranscriptV1,
    role: P256EcdsaRoleV1,
    buses: P256BusTerminalClaimsV1,
    cross_sources: &[P256CrossTraceTerminalClaimV1],
    sink: [F; P256_CROSS_TRACE_LANES_V1],
) -> Result<(), P256AggregateAdapterErrorV1> {
    evaluate_p256_bus_terminal_claim_equalities_v1(buses)?;
    validate_p256_cross_trace_terminal_claims_v1(role, cross_sources)?;
    if !p256_claim_fields_are_canonical_v1(sink) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let field_count = (8 * P256_CROSS_TRACE_LANES_V1)
        .checked_add(
            cross_sources
                .len()
                .checked_mul(2 * P256_CROSS_TRACE_LANES_V1)
                .ok_or(P256AggregateAdapterErrorV1::Resource)?,
        )
        .and_then(|count| count.checked_add(P256_CROSS_TRACE_LANES_V1))
        .ok_or(P256AggregateAdapterErrorV1::Resource)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            field_count
                .checked_mul(8)
                .ok_or(P256AggregateAdapterErrorV1::Resource)?,
        )
        .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
    for field in [
        buses.value_execution,
        buses.value_sorted,
        buses.value_arithmetic_copy,
        buses.arithmetic_value_copy,
        buses.arithmetic_scalar,
        buses.window_scalar,
        buses.scalar_bus_arithmetic,
        buses.scalar_bus_window,
    ]
    .into_iter()
    .flatten()
    .chain(
        cross_sources
            .iter()
            .flat_map(|source| source.start.into_iter().chain(source.terminal)),
    )
    .chain(sink)
    {
        encoded.extend_from_slice(&field.0.to_be_bytes());
    }
    let role_byte = [match role {
        P256EcdsaRoleV1::CertificateOrCrl => 1,
        P256EcdsaRoleV1::WalletOwnership => 2,
    }];
    let source_count =
        [u8::try_from(cross_sources.len()).map_err(|_| P256AggregateAdapterErrorV1::Resource)?];
    transcript
        .absorb(
            P256_TERMINAL_CLAIMS_TRANSCRIPT_LABEL_V1,
            &[&role_byte, &source_count, &encoded],
        )
        .map_err(|_| P256AggregateAdapterErrorV1::Resource)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn flatten_writer_aux_v1(
    row: P256CrossTraceWriterAuxRowV1,
) -> [F; P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1] {
    let mut flat = [F::ZERO; P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1];
    flat[..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1].copy_from_slice(&row.event_values);
    let mut cursor = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
    for slot in row.powers {
        for lane in slot {
            for power in lane {
                flat[cursor] = power;
                cursor += 1;
            }
        }
    }
    for slots in [row.selected_power, row.product_before] {
        for values in slots {
            for value in values {
                flat[cursor] = value;
                cursor += 1;
            }
        }
    }
    for value in row.terminal {
        flat[cursor] = value;
        cursor += 1;
    }
    debug_assert_eq!(cursor, flat.len());
    flat
}
fn decode_writer_aux_v1<A: PolynomialAirFieldV1>(
    flat: &[A],
) -> Result<P256CrossTraceWriterAuxRowV1<A>, P256AggregateAdapterErrorV1> {
    if flat.len() != P256_CROSS_TRACE_WRITER_AUX_WIDTH_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let event_values: [A; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1] = flat
        [..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let mut cursor = P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
    let powers = core::array::from_fn(|_| {
        core::array::from_fn(|_| {
            core::array::from_fn(|_| {
                let value = flat[cursor];
                cursor += 1;
                value
            })
        })
    });
    let selected_power = core::array::from_fn(|_| {
        core::array::from_fn(|_| {
            let value = flat[cursor];
            cursor += 1;
            value
        })
    });
    let product_before = core::array::from_fn(|_| {
        core::array::from_fn(|_| {
            let value = flat[cursor];
            cursor += 1;
            value
        })
    });
    let terminal = core::array::from_fn(|_| {
        let value = flat[cursor];
        cursor += 1;
        value
    });
    if cursor != flat.len() {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(P256CrossTraceWriterAuxRowV1 {
        event_values,
        powers,
        selected_power,
        product_before,
        terminal,
    })
}
fn encode_writer_fixed_v1(
    row: super::p256_cross_trace_bus::P256CrossTraceWriterFixedRowV1,
) -> [F; VALUE_WRITER_FIXED_WIDTH] {
    let mut flat = [F::ZERO; VALUE_WRITER_FIXED_WIDTH];
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let event = VALUE_WRITER_EVENT + slot * CROSS_EVENT_FIXED_WIDTH;
        encode_cross_event_v1(
            row.events[slot],
            &mut flat[event..event + CROSS_EVENT_FIXED_WIDTH],
        );
        let multiplicity = VALUE_WRITER_MULTIPLICITIES + slot * 4;
        flat[multiplicity] = row.multiplicity_small[slot];
        flat[multiplicity + 1] = row.multiplicity_64[slot];
        flat[multiplicity + 2] = row.multiplicity_65[slot];
        flat[multiplicity + 3] = row.multiplicity_129[slot];
    }
    encode_boundary_v1(
        row.boundary,
        &mut flat[VALUE_WRITER_BOUNDARY..VALUE_WRITER_BOUNDARY + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    flat
}
fn decode_writer_fixed_v1<A: PolynomialAirFieldV1>(
    flat: &[A],
) -> Result<
    super::p256_cross_trace_bus::P256CrossTraceWriterFixedRowV1<A>,
    P256AggregateAdapterErrorV1,
> {
    if flat.len() != VALUE_WRITER_FIXED_WIDTH {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(
        super::p256_cross_trace_bus::P256CrossTraceWriterFixedRowV1 {
            events: core::array::from_fn(|slot| {
                let event = VALUE_WRITER_EVENT + slot * CROSS_EVENT_FIXED_WIDTH;
                decode_cross_event_v1(&flat[event..event + CROSS_EVENT_FIXED_WIDTH])
            }),
            multiplicity_small: core::array::from_fn(|slot| {
                flat[VALUE_WRITER_MULTIPLICITIES + slot * 4]
            }),
            multiplicity_64: core::array::from_fn(|slot| {
                flat[VALUE_WRITER_MULTIPLICITIES + slot * 4 + 1]
            }),
            multiplicity_65: core::array::from_fn(|slot| {
                flat[VALUE_WRITER_MULTIPLICITIES + slot * 4 + 2]
            }),
            multiplicity_129: core::array::from_fn(|slot| {
                flat[VALUE_WRITER_MULTIPLICITIES + slot * 4 + 3]
            }),
            boundary: decode_boundary_v1(
                &flat[VALUE_WRITER_BOUNDARY..VALUE_WRITER_BOUNDARY + CROSS_BOUNDARY_FIXED_WIDTH],
            ),
        },
    )
}
/// Constant-memory verifier preprocessing for the value execution adapter and
/// its attached writer source product.
#[derive(Clone, Debug)]
pub struct P256ValueExecutionAggregateFixedProviderV1 {
    value: P256ValueBusStarkFixedProviderV1,
    writer: P256CrossTraceWriterSourceFixedV1,
    arithmetic_operations: usize,
}
impl P256ValueExecutionAggregateFixedProviderV1 {
    /// Compile the exact execution and writer schedules.
    pub(crate) fn new_v1(role: P256EcdsaRoleV1) -> Result<Self, P256AggregateAdapterErrorV1> {
        let topology = verifier_topology_v1(role)?;
        let value = P256ValueBusStarkFixedProviderV1::new_v1(
            P256ValueBusStarkEndpointV1::Execution,
            &topology.initial_values,
            &topology.linked_operations,
            &topology.equalities,
            &topology.boolean_bridges,
            P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
        )?;
        let writer = P256CrossTraceWriterSourceFixedV1::compile_v1(role)?;
        if topology.linked_operations.len() != P256_ARITHMETIC_OPERATIONS_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self {
            value,
            writer,
            arithmetic_operations: topology.linked_operations.len(),
        })
    }
    /// Regenerate one exact flat fixed row.
    pub(crate) fn row_v1(
        &self,
        index: usize,
    ) -> Result<[F; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1>
    {
        let mut fixed = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1];
        fixed[VALUE_NATIVE_FIXED..VALUE_WRITER_FIXED].copy_from_slice(&self.value.row_v1(index)?);
        fixed[VALUE_WRITER_FIXED..VALUE_ARITHMETIC_COPY_FIXED]
            .copy_from_slice(&encode_writer_fixed_v1(self.writer.row_v1(index)?));
        for (slot, event) in value_arithmetic_copy_events_v1(index, self.arithmetic_operations)?
            .into_iter()
            .enumerate()
        {
            let offset = VALUE_ARITHMETIC_COPY_FIXED + slot * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
            encode_arithmetic_copy_event_v1(
                event,
                &mut fixed[offset..offset + ARITHMETIC_COPY_EVENT_FIXED_WIDTH],
            );
        }
        encode_boundary_v1(
            P256CrossTraceBoundaryFixedV1::for_row(index, P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1)?,
            &mut fixed[VALUE_ARITHMETIC_COPY_BOUNDARY_FIXED..],
        );
        Ok(fixed)
    }
    /// Regenerate one complete verifier-preprocessed native column.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn fill_fixed_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(
            P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            |row| self.row_v1(row),
        )
    }
}
/// Constant-memory integrated value-execution base/aux stream.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ValueExecutionAggregateStreamV1<'a> {
    base: P256ValueBusStarkBaseRowProviderV1<'a>,
    value_aux: Option<P256ValueBusStarkAuxSourceV1<'a>>,
    writer: Option<P256CrossTraceWriterSourceStreamV1<'a>>,
    writer_terminal: [F; P256_CROSS_TRACE_LANES_V1],
    arithmetic_operations: usize,
    arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
    arithmetic_copy_running: [F; P256_ARITHMETIC_COPY_LANES_V1],
    arithmetic_copy_terminal: [F; P256_ARITHMETIC_COPY_LANES_V1],
    next_row: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ValueExecutionAggregateStreamV1<'a> {
    /// Construct the execution aggregate only from an X5B1-bound value-bus source.
    pub(crate) fn new_v1(
        value_bus: &'a P256ValueBusBoundSourceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        let post_base = value_bus.post_base_v1()?;
        let role = value_bus.role_v1()?;
        let topology = value_bus.topology_v1()?;
        let linked_operations = &topology.linked_operations;
        let cross_challenges = post_base.p256_cross();
        let arithmetic_copy_challenges = post_base.p256_arithmetic_copy();
        arithmetic_copy_challenges.validate_v1()?;
        if linked_operations.len() != P256_ARITHMETIC_OPERATIONS_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let base = value_bus.execution_base_rows_v1()?;
        let value_aux = value_bus.execution_aux_source_v1()?;
        let mut arithmetic_copy_terminal = [F::ONE; P256_ARITHMETIC_COPY_LANES_V1];
        let packed_arithmetic_rows = linked_operations
            .len()
            .checked_mul(P256_VALUE_BUS_SEGMENT_ROWS_V1)
            .ok_or(P256AggregateAdapterErrorV1::Resource)?
            / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        for row in 0..packed_arithmetic_rows {
            let events = value_arithmetic_copy_events_v1(row, linked_operations.len())?;
            let sources = p256_value_bus_opened_values_v1(&base.base_row_v1(row)?);
            let mut aux = [F::ZERO; P256_VALUE_ARITHMETIC_COPY_AUX_WIDTH_V1];
            arithmetic_copy_terminal = build_compact_arithmetic_copy_aux_row_v1(
                &events,
                &sources,
                arithmetic_copy_terminal,
                [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1],
                arithmetic_copy_challenges,
                &mut aux,
            )?;
        }
        let writer = build_zk_x509_p256_cross_trace_writer_source_v1(
            value_bus.execution_endpoint_v1()?,
            role,
            cross_challenges,
        )?;
        let writer_terminal = writer.terminal_v1();
        Ok(Self {
            base,
            value_aux: Some(value_aux),
            writer: Some(writer),
            writer_terminal,
            arithmetic_operations: linked_operations.len(),
            arithmetic_copy_challenges,
            arithmetic_copy_running: [F::ONE; P256_ARITHMETIC_COPY_LANES_V1],
            arithmetic_copy_terminal,
            next_row: 0,
        })
    }
    /// Emit the next exact 116-column auxiliary row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1>
    {
        if self.next_row == P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 {
            return Ok(None);
        }
        let mut aux =
            zeroize::Zeroizing::new([F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1]);
        aux[VALUE_NATIVE_AUX..VALUE_WRITER_AUX].copy_from_slice(
            &self
                .value_aux
                .as_mut()
                .ok_or(P256AggregateAdapterErrorV1::Challenge)?
                .next_aux_row_v1()?
                .ok_or(P256AggregateAdapterErrorV1::Topology)?,
        );
        let writer = self
            .writer
            .as_mut()
            .ok_or(P256AggregateAdapterErrorV1::Challenge)?
            .next_row_v1()?
            .ok_or(P256AggregateAdapterErrorV1::Topology)?;
        aux[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX]
            .copy_from_slice(&flatten_writer_aux_v1(writer));
        let events = value_arithmetic_copy_events_v1(self.next_row, self.arithmetic_operations)?;
        let sources = p256_value_bus_opened_values_v1(&self.base.base_row_v1(self.next_row)?);
        self.arithmetic_copy_running = build_compact_arithmetic_copy_aux_row_v1(
            &events,
            &sources,
            self.arithmetic_copy_running,
            self.arithmetic_copy_terminal,
            self.arithmetic_copy_challenges,
            &mut aux[VALUE_ARITHMETIC_COPY_AUX..],
        )?;
        self.next_row += 1;
        if self.next_row == P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1
            && self.arithmetic_copy_running != self.arithmetic_copy_terminal
        {
            super::private_table::zeroize_fields_v1(&mut aux[..]);
            return Err(P256AggregateAdapterErrorV1::Constraint);
        }
        Ok(Some(*aux))
    }
    /// Replay this deterministic stream into one challenge-dependent native
    /// auxiliary column, then drop all row-local state.
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.arithmetic_copy_challenges.validate_v1()?;
        let mut replay = Self {
            base: self.base,
            value_aux: Some(
                self.value_aux
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Challenge)?
                    .replay_v1(),
            ),
            writer: Some(
                self.writer
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Challenge)?
                    .replay_v1(),
            ),
            writer_terminal: self.writer_terminal,
            arithmetic_operations: self.arithmetic_operations,
            arithmetic_copy_challenges: self.arithmetic_copy_challenges,
            arithmetic_copy_running: [F::ONE; P256_ARITHMETIC_COPY_LANES_V1],
            arithmetic_copy_terminal: self.arithmetic_copy_terminal,
            next_row: 0,
        };
        fill_aggregate_aux_column_v1(
            P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            || replay.next_aux_row_v1(),
        )
    }
    /// Writer product terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.writer_terminal
    }
    /// Value-memory execution terminal carried by the native value-bus substream.
    pub(crate) fn value_terminal_v1(
        &self,
    ) -> Result<[F; P256_VALUE_BUS_LANES_V1], P256AggregateAdapterErrorV1> {
        Ok(self
            .value_aux
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Challenge)?
            .terminal_v1())
    }
    /// Terminal of the direct value-bus arithmetic-cell copy product.
    pub(crate) const fn arithmetic_copy_terminal_v1(&self) -> [F; P256_ARITHMETIC_COPY_LANES_V1] {
        self.arithmetic_copy_terminal
    }
    /// Recursively release retained replay state and clear challenge-bound
    /// products while preserving the borrowed base provider.
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.value_aux = None;
        self.writer = None;
        super::private_table::zeroize_fields_v1(&mut self.writer_terminal[..]);
        zeroize_arithmetic_copy_challenges_v1(&mut self.arithmetic_copy_challenges);
        super::private_table::zeroize_fields_v1(&mut self.arithmetic_copy_running[..]);
        super::private_table::zeroize_fields_v1(&mut self.arithmetic_copy_terminal[..]);
        self.next_row = P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.value_aux.is_none()
            && self.writer.is_none()
            && self
                .arithmetic_copy_challenges
                .lanes
                .iter()
                .flat_map(|lane| lane.terms)
                .all(|value| value == F::ZERO)
            && self
                .writer_terminal
                .iter()
                .chain(&self.arithmetic_copy_running)
                .chain(&self.arithmetic_copy_terminal)
                .all(|value| *value == F::ZERO)
            && self.next_row == P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ValueExecutionAggregateStreamV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Post-commitment challenges consumed by the value-execution aggregate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ValueExecutionAggregateChallengesV1 {
    /// Internal execution/sorted value-bus permutation.
    pub(crate) value: P256ValueBusChallengesV1,
    /// Writer/external tagged-product chain.
    pub(crate) cross: P256CrossTraceChallengesV1,
    /// Direct value-bus/arithmetic cell-copy permutation.
    pub(crate) arithmetic_copy: P256ArithmeticCopyChallengesV1,
}
/// Complete value execution, writer multiplicity and arithmetic-copy polynomials.
pub fn evaluate_p256_value_execution_aggregate_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
    next: &[A; P256_VALUE_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[A; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1],
    next_aux: &[A; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1],
    fixed: &[A; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1],
    challenges: P256ValueExecutionAggregateChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    challenges
        .cross
        .validate()
        .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(P256AggregateAdapterErrorV1::Constraint);
    }
    let current_value_aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1] = current_aux
        [..P256_VALUE_BUS_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let next_value_aux: &[A; P256_VALUE_BUS_STARK_AUX_WIDTH_V1] = next_aux
        [..P256_VALUE_BUS_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let value_fixed: &[A; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1] = fixed
        [..P256_VALUE_BUS_STARK_FIXED_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let mut residues = evaluate_p256_value_bus_stark_residues_over_field_v1(
        current,
        next,
        current_value_aux,
        next_value_aux,
        value_fixed,
        challenges.value,
    )?;
    let current_writer =
        decode_writer_aux_v1(&current_aux[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX])?;
    let next_writer = decode_writer_aux_v1(&next_aux[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX])?;
    let writer_fixed =
        decode_writer_fixed_v1(&fixed[VALUE_WRITER_FIXED..VALUE_ARITHMETIC_COPY_FIXED])?;
    residues.extend(evaluate_zk_x509_p256_cross_trace_writer_row_constraints_v1(
        writer_fixed,
        p256_value_bus_opened_values_v1(current),
        &current_writer,
        &next_writer,
        challenges.cross,
    ));
    let events: [P256ArithmeticCopyEventFixedV1<A>; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1] =
        core::array::from_fn(|slot| {
            let offset = VALUE_ARITHMETIC_COPY_FIXED + slot * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
            decode_arithmetic_copy_event_v1(
                &fixed[offset..offset + ARITHMETIC_COPY_EVENT_FIXED_WIDTH],
            )
        });
    let boundary = decode_boundary_v1(&fixed[VALUE_ARITHMETIC_COPY_BOUNDARY_FIXED..]);
    residues.extend(evaluate_compact_arithmetic_copy_residues_v1(
        &events,
        &p256_value_bus_opened_values_v1(current),
        boundary,
        &current_aux[VALUE_ARITHMETIC_COPY_AUX..],
        &next_aux[VALUE_ARITHMETIC_COPY_AUX..],
        challenges.arithmetic_copy,
    )?);
    if residues.len() != P256_VALUE_EXECUTION_AGGREGATE_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Construct the explicit writer claim from native first/final rows.
#[cfg(test)]
pub fn p256_value_execution_cross_terminal_claim_v1(
    first_aux: &[F; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1],
    terminal_aux: &[F; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1],
) -> Result<P256CrossTraceTerminalClaimV1, P256AggregateAdapterErrorV1> {
    let first = decode_writer_aux_v1(&first_aux[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX])?;
    let terminal =
        decode_writer_aux_v1(&terminal_aux[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX])?;
    Ok(P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::ValueWriter,
        start: first.product_before[0],
        terminal: terminal.terminal,
    })
}
/// Direct value-bus side arithmetic-copy terminal projection.
#[cfg(test)]
pub fn p256_value_execution_arithmetic_copy_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_ARITHMETIC_COPY_LANES_V1], P256AggregateAdapterErrorV1> {
    arithmetic_copy_terminal_v1(
        P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
        &aux[VALUE_ARITHMETIC_COPY_AUX..],
    )
}
/// Writer terminal carried by one value-execution auxiliary opening.
#[cfg(test)]
pub fn p256_value_execution_cross_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    Ok(decode_writer_aux_v1(&aux[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX])?.terminal)
}
/// Final native-row selector in value-execution preprocessing.
#[cfg(test)]
pub fn p256_value_execution_last_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1],
) -> A {
    decode_boundary_v1(&fixed[VALUE_ARITHMETIC_COPY_BOUNDARY_FIXED..]).last
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ScalarSourceEventFixedV1<A = F> {
    active: A,
    scalar: A,
    window: A,
    bit: A,
}
impl P256ScalarSourceEventFixedV1 {
    const fn inactive_v1() -> Self {
        Self {
            active: F::ZERO,
            scalar: F::ZERO,
            window: F::ZERO,
            bit: F::ZERO,
        }
    }
}
fn encode_scalar_event_v1(event: P256ScalarSourceEventFixedV1, target: &mut [F]) {
    target[0] = event.active;
    target[1] = event.scalar;
    target[2] = event.window;
    target[3] = event.bit;
}
fn decode_scalar_event_v1<A: PolynomialAirFieldV1>(
    source: &[A],
) -> P256ScalarSourceEventFixedV1<A> {
    P256ScalarSourceEventFixedV1 {
        active: source[0],
        scalar: source[1],
        window: source[2],
        bit: source[3],
    }
}
fn scalar_factor_v1<A: PolynomialAirFieldV1>(
    fixed: P256ScalarSourceEventFixedV1<A>,
    value: A,
    terms: [F; 5],
) -> A {
    A::ONE
        .sub(fixed.active)
        .add(fixed.active.mul_base(terms[0]))
        .add(fixed.scalar.mul_base(terms[1]))
        .add(fixed.window.mul_base(terms[2]))
        .add(fixed.bit.mul_base(terms[3]))
        .add(value.mul_base(terms[4]))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_compact_scalar_aux_row_v1(
    events: &[P256ScalarSourceEventFixedV1],
    sources: &[F],
    before: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    terminal: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    challenges: P256ScalarBitBusChallengesV1,
    target: &mut [F],
) -> Result<[F; P256_SCALAR_BIT_BUS_LANES_V1], P256AggregateAdapterErrorV1> {
    if events.len() != sources.len() || target.len() != compact_aux_width_v1(events.len()) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    for slot in 0..events.len() {
        target[slot] = events[slot].active.mul(sources[slot]);
    }
    let mut after = [F::ZERO; P256_SCALAR_BIT_BUS_LANES_V1];
    for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
        let start = compact_products_start_v1(events.len(), lane);
        target[start] = before[lane];
        for slot in 0..events.len() {
            target[start + slot + 1] = target[start + slot].mul(scalar_factor_v1(
                events[slot],
                target[slot],
                challenges.lanes[lane].terms,
            ));
        }
        after[lane] = target[start + events.len()];
        target[compact_terminal_start_v1(events.len()) + lane] = terminal[lane];
    }
    Ok(after)
}
fn evaluate_compact_scalar_residues_v1<A: PolynomialAirFieldV1>(
    events: &[P256ScalarSourceEventFixedV1<A>],
    sources: &[A],
    boundary: P256CrossTraceBoundaryFixedV1<A>,
    current: &[A],
    next: &[A],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    challenges
        .validate_v1()
        .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
    let width = compact_aux_width_v1(events.len());
    if events.len() != sources.len() || current.len() != width || next.len() != width {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if sources
        .iter()
        .chain(current)
        .chain(next)
        .any(|value| !value.is_canonical())
        || events.iter().any(|event| {
            [event.active, event.scalar, event.window, event.bit]
                .iter()
                .any(|value| !value.is_canonical())
        })
        || [boundary.first, boundary.continuation, boundary.last]
            .iter()
            .any(|value| !value.is_canonical())
    {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut residues =
        Vec::with_capacity(events.len() + P256_SCALAR_BIT_BUS_LANES_V1 * (events.len() + 4));
    for slot in 0..events.len() {
        residues.push(current[slot].sub(events[slot].active.mul(sources[slot])));
    }
    for lane in 0..P256_SCALAR_BIT_BUS_LANES_V1 {
        let product = compact_products_start_v1(events.len(), lane);
        residues.push(boundary.first.mul(current[product].sub(A::ONE)));
        for slot in 0..events.len() {
            let factor =
                scalar_factor_v1(events[slot], current[slot], challenges.lanes[lane].terms);
            residues.push(current[product + slot + 1].sub(current[product + slot].mul(factor)));
        }
        let after = current[product + events.len()];
        residues.push(boundary.continuation.mul(next[product].sub(after)));
        let terminal = compact_terminal_start_v1(events.len()) + lane;
        residues.push(boundary.last.mul(current[terminal].sub(after)));
        residues.push(next[terminal].sub(current[terminal]));
    }
    Ok(residues)
}
fn arithmetic_scalar_events_v1(
    row: usize,
) -> Result<[P256ScalarSourceEventFixedV1; 8], P256AggregateAdapterErrorV1> {
    if row >= P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let operation = row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
    if !matches!(operation, 13 | 14) {
        return Ok([P256ScalarSourceEventFixedV1::inactive_v1(); 8]);
    }
    let coefficient = row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
    let limb = coefficient % 16;
    let bit_offset = if coefficient < 16 { 0 } else { 8 };
    let scalar = operation - 12;
    let mut events = [P256ScalarSourceEventFixedV1::inactive_v1(); 8];
    for (slot, event) in events.iter_mut().enumerate() {
        let little_endian = limb
            .checked_mul(16)
            .and_then(|value| value.checked_add(bit_offset + slot))
            .ok_or(P256AggregateAdapterErrorV1::Resource)?;
        let big_endian = 255_usize
            .checked_sub(little_endian)
            .ok_or(P256AggregateAdapterErrorV1::Topology)?;
        *event = P256ScalarSourceEventFixedV1 {
            active: F::ONE,
            scalar: f_usize_v1(scalar)?,
            window: f_usize_v1(big_endian / 4 + 1)?,
            bit: f_usize_v1(big_endian % 4 + 1)?,
        };
    }
    Ok(events)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn arithmetic_scalar_sources_v1(row: usize, base: &[F; P256_ARITHMETIC_BASE_WIDTH_V1]) -> [F; 8] {
    let coefficient = row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
    let offset = if coefficient < 16 { 0 } else { 8 };
    let bits = p256_arithmetic_opened_c_limb_bits_v1(base);
    core::array::from_fn(|slot| bits[offset + slot])
}
/// Borrow either the checked raw oracle or MAIN's lossless compact owner.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug)]
enum P256ArithmeticRowsStorageV1<'a> {
    Raw(&'a ZkX509P256ArithmeticTraceV1),
    Compact(&'a P256CompactArithmeticTraceV1),
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ArithmeticRowsStorageV1<'_> {
    fn rows_v1(&self) -> usize {
        match self {
            Self::Raw(trace) => trace.rows(),
            Self::Compact(trace) => trace.rows_v1(),
        }
    }
    fn fill_cells_v1(
        &self,
        row: usize,
        first: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        if first
            .checked_add(output.len())
            .is_none_or(|end| end > P256_ARITHMETIC_BASE_WIDTH_V1)
            || output.is_empty()
            || row >= P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        if row >= self.rows_v1() {
            output.fill(F::ZERO);
            return Ok(());
        }
        match self {
            Self::Raw(trace) => {
                output.copy_from_slice(&trace.base[row][first..first + output.len()])
            }
            Self::Compact(trace) => trace.fill_cells_v1(row, first, output)?,
        }
        Ok(())
    }
    fn scalar_sources_v1(&self, row: usize) -> Result<[F; 8], P256AggregateAdapterErrorV1> {
        if row >= self.rows_v1() {
            return Ok([F::ZERO; 8]);
        }
        Ok(match self {
            Self::Raw(trace) => arithmetic_scalar_sources_v1(row, &trace.base[row]),
            Self::Compact(trace) => trace.scalar_sources_v1(row)?,
        })
    }
    fn operand_sources_v1(
        &self,
        row: usize,
        fixed: &P256ArithmeticStarkFixedProviderV1,
    ) -> Result<[F; 3], P256AggregateAdapterErrorV1> {
        if row >= self.rows_v1() {
            return Ok([F::ZERO; 3]);
        }
        Ok(match self {
            Self::Raw(trace) => {
                p256_arithmetic_opened_operand_limbs_v1(&trace.base[row], &fixed.row_v1(row)?)
            }
            Self::Compact(trace) => trace.operand_sources_v1(row)?,
        })
    }
}
/// Constant-memory base/fixed provider for exact arithmetic plus its attached
/// scalar-source and value-copy products.
#[derive(Clone, Debug)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ArithmeticAggregateRowsV1<'a> {
    trace: P256ArithmeticRowsStorageV1<'a>,
    fixed: Cow<'a, P256ArithmeticStarkFixedProviderV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ArithmeticAggregateRowsV1<'a> {
    /// Validate the exact arithmetic trace and scalar source positions.
    pub(crate) fn new_v1(
        role: P256EcdsaRoleV1,
        trace: &'a ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        #[cfg(test)]
        validated_owner_tests::record_checked_constructor_v1();
        trace.validate()?;
        let topology = verifier_topology_v1(role)?;
        validate_arithmetic_trace_topology_v1(trace, &topology)?;
        let arithmetic_topology = topology
            .linked_operations
            .iter()
            .map(|operation| ZkX509P256ArithmeticTopologyV1 {
                kind: operation.kind,
                modulus: operation.modulus,
            })
            .collect::<Vec<_>>();
        if arithmetic_topology.len() != P256_ARITHMETIC_OPERATIONS_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self {
            trace: P256ArithmeticRowsStorageV1::Raw(trace),
            fixed: Cow::Owned(P256ArithmeticStarkFixedProviderV1::new_v1(
                &arithmetic_topology,
                P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            )?),
        })
    }
    /// Direct committed arithmetic row or canonical zero padding.
    #[cfg(test)]
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_ARITHMETIC_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        if row >= P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let mut output = [F::ZERO; P256_ARITHMETIC_BASE_WIDTH_V1];
        self.trace.fill_cells_v1(row, 0, &mut output)?;
        Ok(output)
    }

    /// Borrow contiguous cells from the immutable retained arithmetic rows
    /// into at most eight caller-owned columns. No full private row is copied
    /// to stack: the source remains under its clearing owner throughout.
    fn fill_base_columns_v1(
        &self,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        if outputs.is_empty()
            || outputs.len()
                > crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || first
                .checked_add(outputs.len())
                .is_none_or(|end| end > P256_ARITHMETIC_BASE_WIDTH_V1)
            || outputs
                .iter()
                .any(|output| output.len() != P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1)
            || self.trace.rows_v1() > P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let mut destination = P256AggregateColumnsDestinationGuardV1 {
            outputs,
            committed: false,
        };
        for row in 0..P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
            let mut cells = P256AggregateAuxRowScratchV1([F::ZERO; 8]);
            self.trace
                .fill_cells_v1(row, first, &mut cells.0[..destination.outputs.len()])?;
            for (offset, output) in destination.outputs.iter_mut().enumerate() {
                output[row] = cells.0[offset];
            }
        }
        destination.committed = true;
        Ok(())
    }
    /// Copy one complete committed arithmetic column into caller-owned
    /// storage without materializing an aggregate row matrix.
    pub(crate) fn fill_base_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.fill_base_columns_v1(column, &mut [output])
    }
}
/// A bounded column selection derived only from the public registration range.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ArithmeticAuxSelectionV1 {
    scalar: bool,
    value_copy: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ArithmeticAuxSelectionV1 {
    fn new_v1(first: usize, width: usize) -> Result<Self, P256AggregateAdapterErrorV1> {
        let end = first
            .checked_add(width)
            .filter(|&end| end <= P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1)
            .filter(|_| {
                width > 0
                    && width
                        <= crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            })
            .ok_or(P256AggregateAdapterErrorV1::Topology)?;
        Ok(Self {
            scalar: first < ARITHMETIC_VALUE_COPY_AUX && end > ARITHMETIC_SCALAR_AUX,
            value_copy: end > ARITHMETIC_VALUE_COPY_AUX,
        })
    }
}
/// Exact compact row when its verifier-fixed events are all inactive: every
/// source is zero, every prefix is the unchanged running product, and terminal
/// copies remain those of the same bound source. No private value is inspected.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_compact_identity_aux_row_v1(
    events: usize,
    running: &[F; P256_PERMUTATION_CHALLENGE_LANES_V1],
    terminal: &[F; P256_PERMUTATION_CHALLENGE_LANES_V1],
    target: &mut [F],
) -> Result<(), P256AggregateAdapterErrorV1> {
    if !matches!(events, 3 | 8) || target.len() != compact_aux_width_v1(events) {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    target[..events].fill(F::ZERO);
    for lane in 0..P256_PERMUTATION_CHALLENGE_LANES_V1 {
        let start = compact_products_start_v1(events, lane);
        target[start..start + events + 1].fill(running[lane]);
        target[compact_terminal_start_v1(events) + lane] = terminal[lane];
    }
    Ok(())
}
/// Constant-memory arithmetic auxiliary stream.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ArithmeticAggregateAuxStreamV1<'a> {
    rows: P256ArithmeticAggregateRowsV1<'a>,
    scalar_challenges: P256ScalarBitBusChallengesV1,
    scalar_running: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    scalar_terminal: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
    arithmetic_copy_running: [F; P256_ARITHMETIC_COPY_LANES_V1],
    arithmetic_copy_terminal: [F; P256_ARITHMETIC_COPY_LANES_V1],
    next_row: usize,
    _not_copy: core::cell::Cell<()>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ArithmeticAggregateAuxStreamV1<'a> {
    /// Compute the source terminal from the two exact scalar operations, then
    /// prepare a streaming second pass.
    #[cfg(test)]
    pub(crate) fn new_v1(
        role: P256EcdsaRoleV1,
        trace: &'a ZkX509P256ArithmeticTraceV1,
        scalar_challenges: P256ScalarBitBusChallengesV1,
        arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        scalar_challenges
            .validate_v1()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        arithmetic_copy_challenges.validate_v1()?;
        let rows = P256ArithmeticAggregateRowsV1::new_v1(role, trace)?;
        Self::from_rows_v1(rows, scalar_challenges, arithmetic_copy_challenges)
    }
    /// Reuse only a validated immutable owner; arbitrary borrowed traces still
    /// enter through the fully checked constructor above.
    fn from_validated_v1(
        role: P256EcdsaRoleV1,
        owner: &'a P256MainValidatedArithmeticV1,
        scalar_challenges: P256ScalarBitBusChallengesV1,
        arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        scalar_challenges
            .validate_v1()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        arithmetic_copy_challenges.validate_v1()?;
        let rows = owner.rows_v1(role)?;
        Self::from_rows_v1(rows, scalar_challenges, arithmetic_copy_challenges)
    }
    fn from_rows_v1(
        rows: P256ArithmeticAggregateRowsV1<'a>,
        scalar_challenges: P256ScalarBitBusChallengesV1,
        arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        #[cfg(test)]
        auxiliary_replay_tests::record_terminal_derivation_v1();
        let mut scalar_terminal = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        for operation in [13_usize, 14] {
            for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
                let row = operation * P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + coefficient;
                let events = arithmetic_scalar_events_v1(row)?;
                let sources = P256AggregateAuxRowScratchV1(rows.trace.scalar_sources_v1(row)?);
                let mut aux = [F::ZERO; P256_SCALAR_ARITHMETIC_SOURCE_AUX_WIDTH_V1];
                scalar_terminal = build_compact_scalar_aux_row_v1(
                    &events,
                    &sources.0,
                    scalar_terminal,
                    [F::ZERO; P256_SCALAR_BIT_BUS_LANES_V1],
                    scalar_challenges,
                    &mut aux,
                )?;
            }
        }
        let mut arithmetic_copy_terminal = [F::ONE; P256_ARITHMETIC_COPY_LANES_V1];
        for operation in 0..P256_ARITHMETIC_OPERATIONS_V1 {
            for coefficient in 0..16 {
                let row = operation * P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + coefficient;
                let events = arithmetic_value_copy_events_v1(row, rows.trace.rows_v1())?;
                let sources =
                    P256AggregateAuxRowScratchV1(rows.trace.operand_sources_v1(row, &rows.fixed)?);
                let mut aux = [F::ZERO; P256_ARITHMETIC_VALUE_COPY_AUX_WIDTH_V1];
                arithmetic_copy_terminal = build_compact_arithmetic_copy_aux_row_v1(
                    &events,
                    &sources.0,
                    arithmetic_copy_terminal,
                    [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1],
                    arithmetic_copy_challenges,
                    &mut aux,
                )?;
            }
        }
        Ok(Self {
            rows,
            scalar_challenges,
            scalar_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            scalar_terminal,
            arithmetic_copy_challenges,
            arithmetic_copy_running: [F::ONE; P256_ARITHMETIC_COPY_LANES_V1],
            arithmetic_copy_terminal,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        })
    }
    /// Emit the next exact integrated auxiliary row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1>
    {
        if self.next_row == P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
            return Ok(None);
        }
        #[cfg(test)]
        auxiliary_replay_tests::record_arithmetic_row_v1();
        let events = arithmetic_scalar_events_v1(self.next_row)?;
        let sources =
            P256AggregateAuxRowScratchV1(self.rows.trace.scalar_sources_v1(self.next_row)?);
        let mut aux = [F::ZERO; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1];
        self.scalar_running = build_compact_scalar_aux_row_v1(
            &events,
            &sources.0,
            self.scalar_running,
            self.scalar_terminal,
            self.scalar_challenges,
            &mut aux[ARITHMETIC_SCALAR_AUX..ARITHMETIC_VALUE_COPY_AUX],
        )?;
        let copy_events =
            arithmetic_value_copy_events_v1(self.next_row, self.rows.trace.rows_v1())?;
        let copy_sources = P256AggregateAuxRowScratchV1(
            self.rows
                .trace
                .operand_sources_v1(self.next_row, &self.rows.fixed)?,
        );
        self.arithmetic_copy_running = build_compact_arithmetic_copy_aux_row_v1(
            &copy_events,
            &copy_sources.0,
            self.arithmetic_copy_running,
            self.arithmetic_copy_terminal,
            self.arithmetic_copy_challenges,
            &mut aux[ARITHMETIC_VALUE_COPY_AUX..],
        )?;
        self.next_row += 1;
        Ok(Some(aux))
    }
    /// Project only requested public column families while preserving the
    /// native row order. Activity is the verifier-owned operation/coefficient
    /// schedule, never a witness selector. The dense stream above remains the
    /// independent native oracle and the terminal-derivation path.
    fn next_selected_aux_row_v1(
        &mut self,
        selection: P256ArithmeticAuxSelectionV1,
    ) -> Result<Option<[F; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1>
    {
        if self.next_row == P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
            return Ok(None);
        }
        if self.next_row > P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        #[cfg(test)]
        auxiliary_replay_tests::record_arithmetic_row_v1();
        let row = self.next_row;
        let mut aux =
            P256AggregateAuxRowScratchV1([F::ZERO; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1]);
        if selection.scalar {
            let target = &mut aux.0[ARITHMETIC_SCALAR_AUX..ARITHMETIC_VALUE_COPY_AUX];
            if matches!(row / P256_ARITHMETIC_ROWS_PER_OPERATION_V1, 13 | 14) {
                if row >= self.rows.trace.rows_v1() {
                    return Err(P256AggregateAdapterErrorV1::Source);
                }
                let events = arithmetic_scalar_events_v1(row)?;
                let sources = P256AggregateAuxRowScratchV1(self.rows.trace.scalar_sources_v1(row)?);
                self.scalar_running = build_compact_scalar_aux_row_v1(
                    &events,
                    &sources.0,
                    self.scalar_running,
                    self.scalar_terminal,
                    self.scalar_challenges,
                    target,
                )?;
            } else {
                fill_compact_identity_aux_row_v1(
                    8,
                    &self.scalar_running,
                    &self.scalar_terminal,
                    target,
                )?;
            }
        }
        if selection.value_copy {
            let target = &mut aux.0[ARITHMETIC_VALUE_COPY_AUX..];
            let logical_rows =
                P256_ARITHMETIC_OPERATIONS_V1 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
            if row < logical_rows && row % P256_ARITHMETIC_ROWS_PER_OPERATION_V1 < 16 {
                if row >= self.rows.trace.rows_v1() {
                    return Err(P256AggregateAdapterErrorV1::Source);
                }
                let events = arithmetic_value_copy_events_v1(row, logical_rows)?;
                let sources = P256AggregateAuxRowScratchV1(
                    self.rows.trace.operand_sources_v1(row, &self.rows.fixed)?,
                );
                self.arithmetic_copy_running = build_compact_arithmetic_copy_aux_row_v1(
                    &events,
                    &sources.0,
                    self.arithmetic_copy_running,
                    self.arithmetic_copy_terminal,
                    self.arithmetic_copy_challenges,
                    target,
                )?;
            } else {
                fill_compact_identity_aux_row_v1(
                    3,
                    &self.arithmetic_copy_running,
                    &self.arithmetic_copy_terminal,
                    target,
                )?;
            }
        }
        // Column zero and every unselected family remain zero. Only selected
        // columns are copied by the existing transactional destination guard.
        self.next_row += 1;
        Ok(Some(aux.0))
    }
    /// Replay this deterministic stream into one challenge-dependent arithmetic auxiliary column.
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.scalar_challenges
            .validate_v1()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        self.arithmetic_copy_challenges.validate_v1()?;
        let mut replay = Self {
            rows: self.rows.clone(),
            scalar_challenges: self.scalar_challenges,
            scalar_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            scalar_terminal: self.scalar_terminal,
            arithmetic_copy_challenges: self.arithmetic_copy_challenges,
            arithmetic_copy_running: [F::ONE; P256_ARITHMETIC_COPY_LANES_V1],
            arithmetic_copy_terminal: self.arithmetic_copy_terminal,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        };
        fill_aggregate_aux_column_v1(
            P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            || replay.next_aux_row_v1(),
        )
    }
    /// Arithmetic scalar-source terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_SCALAR_BIT_BUS_LANES_V1] {
        self.scalar_terminal
    }
    /// Terminal of all direct arithmetic `a`, `b`, and `c` limb copies.
    pub(crate) const fn arithmetic_copy_terminal_v1(&self) -> [F; P256_ARITHMETIC_COPY_LANES_V1] {
        self.arithmetic_copy_terminal
    }
    /// Clear every challenge and running/terminal product. The borrowed
    /// arithmetic rows and their verifier-owned fixed provider remain intact.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_scalar_challenges_v1(&mut self.scalar_challenges);
        super::private_table::zeroize_fields_v1(&mut self.scalar_running[..]);
        super::private_table::zeroize_fields_v1(&mut self.scalar_terminal[..]);
        zeroize_arithmetic_copy_challenges_v1(&mut self.arithmetic_copy_challenges);
        super::private_table::zeroize_fields_v1(&mut self.arithmetic_copy_running[..]);
        super::private_table::zeroize_fields_v1(&mut self.arithmetic_copy_terminal[..]);
        self.next_row = P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.scalar_challenges
            .lanes
            .iter()
            .flat_map(|lane| lane.terms)
            .all(|value| value == F::ZERO)
            && self
                .arithmetic_copy_challenges
                .lanes
                .iter()
                .flat_map(|lane| lane.terms)
                .all(|value| value == F::ZERO)
            && self
                .scalar_running
                .iter()
                .chain(&self.scalar_terminal)
                .chain(&self.arithmetic_copy_running)
                .chain(&self.arithmetic_copy_terminal)
                .all(|value| *value == F::ZERO)
            && self.next_row == P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ArithmeticAggregateAuxStreamV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Integrated arithmetic residues with eight direct `c`-bit source events.
#[cfg(test)]
pub fn evaluate_p256_arithmetic_aggregate_residues_v1(
    current: &[F; P256_ARITHMETIC_BASE_WIDTH_V1],
    next: &[F; P256_ARITHMETIC_BASE_WIDTH_V1],
    current_aux: &[F; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1],
    next_aux: &[F; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1],
    fixed: &[F; P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1],
    scalar_challenges: P256ScalarBitBusChallengesV1,
    arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
) -> Result<Vec<F>, P256AggregateAdapterErrorV1> {
    evaluate_p256_arithmetic_aggregate_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        scalar_challenges,
        arithmetic_copy_challenges,
    )
}
/// Integrated arithmetic, scalar-source and value-copy polynomials over F or Fp4.
pub fn evaluate_p256_arithmetic_aggregate_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    next: &[A; P256_ARITHMETIC_BASE_WIDTH_V1],
    current_aux: &[A; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1],
    next_aux: &[A; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1],
    fixed: &[A; P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1],
    scalar_challenges: P256ScalarBitBusChallengesV1,
    arithmetic_copy_challenges: P256ArithmeticCopyChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    let current_native: &[A; P256_ARITHMETIC_STARK_AUX_WIDTH_V1] = current_aux
        [..P256_ARITHMETIC_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let next_native: &[A; P256_ARITHMETIC_STARK_AUX_WIDTH_V1] = next_aux
        [..P256_ARITHMETIC_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let native_fixed: &[A; P256_ARITHMETIC_STARK_FIXED_WIDTH_V1] = fixed
        [..P256_ARITHMETIC_STARK_FIXED_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let mut residues = evaluate_p256_arithmetic_stark_residues_over_field_v1(
        current,
        next,
        current_native,
        next_native,
        native_fixed,
    )?;
    let events: [P256ScalarSourceEventFixedV1<A>; 8] = core::array::from_fn(|slot| {
        let start = ARITHMETIC_SCALAR_FIXED + slot * SCALAR_EVENT_FIXED_WIDTH;
        decode_scalar_event_v1(&fixed[start..start + SCALAR_EVENT_FIXED_WIDTH])
    });
    let boundary = decode_boundary_v1(
        &fixed[ARITHMETIC_BOUNDARY_FIXED..ARITHMETIC_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    let sources = p256_arithmetic_opened_scalar_source_bits_v1(current, native_fixed);
    residues.extend(evaluate_compact_scalar_residues_v1(
        &events,
        &sources,
        boundary,
        &current_aux[ARITHMETIC_SCALAR_AUX..ARITHMETIC_VALUE_COPY_AUX],
        &next_aux[ARITHMETIC_SCALAR_AUX..ARITHMETIC_VALUE_COPY_AUX],
        scalar_challenges,
    )?);
    let copy_events: [P256ArithmeticCopyEventFixedV1<A>; 3] = core::array::from_fn(|slot| {
        let start = ARITHMETIC_VALUE_COPY_FIXED + slot * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
        decode_arithmetic_copy_event_v1(&fixed[start..start + ARITHMETIC_COPY_EVENT_FIXED_WIDTH])
    });
    let copy_boundary = decode_boundary_v1(&fixed[ARITHMETIC_VALUE_COPY_BOUNDARY_FIXED..]);
    let copy_sources = p256_arithmetic_opened_operand_limbs_v1(current, native_fixed);
    residues.extend(evaluate_compact_arithmetic_copy_residues_v1(
        &copy_events,
        &copy_sources,
        copy_boundary,
        &current_aux[ARITHMETIC_VALUE_COPY_AUX..],
        &next_aux[ARITHMETIC_VALUE_COPY_AUX..],
        arithmetic_copy_challenges,
    )?);
    if residues.len() != P256_ARITHMETIC_AGGREGATE_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Arithmetic scalar-source terminal projection.
#[cfg(test)]
pub fn p256_arithmetic_scalar_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_SCALAR_BIT_BUS_LANES_V1], P256AggregateAdapterErrorV1> {
    compact_cross_terminal_v1(8, &aux[ARITHMETIC_SCALAR_AUX..ARITHMETIC_VALUE_COPY_AUX])
}
/// Direct arithmetic side value-copy terminal projection.
#[cfg(test)]
pub fn p256_arithmetic_value_copy_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_ARITHMETIC_COPY_LANES_V1], P256AggregateAdapterErrorV1> {
    arithmetic_copy_terminal_v1(3, &aux[ARITHMETIC_VALUE_COPY_AUX..])
}
/// Final native-row selector in arithmetic preprocessing.
#[cfg(test)]
pub fn p256_arithmetic_last_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1],
) -> A {
    decode_boundary_v1(&fixed[ARITHMETIC_VALUE_COPY_BOUNDARY_FIXED..]).last
}
/// Bind the complete value-bus arithmetic-access product to every directly
/// opened arithmetic `a`, `b`, and `c` limb.
#[cfg(test)]
pub fn evaluate_p256_arithmetic_copy_terminal_openings_v1(
    value_bus: [F; P256_ARITHMETIC_COPY_LANES_V1],
    arithmetic: [F; P256_ARITHMETIC_COPY_LANES_V1],
) -> [F; P256_ARITHMETIC_COPY_LANES_V1] {
    core::array::from_fn(|lane| value_bus[lane].sub(arithmetic[lane]))
}
fn window_cross_events_v1(
    row: usize,
) -> Result<[P256CrossTraceEventFixedV1; 3], P256AggregateAdapterErrorV1> {
    if row >= P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if row >= P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
        return Ok([P256CrossTraceEventFixedV1::inactive(); 3]);
    }
    let block = row / P256_WINDOW_STARK_TRACE_SIZE_V1;
    let local = row % P256_WINDOW_STARK_TRACE_SIZE_V1;
    if local >= 272 {
        return Ok([P256CrossTraceEventFixedV1::inactive(); 3]);
    }
    let mut events = [P256CrossTraceEventFixedV1::inactive(); 3];
    for (slot, event) in events.iter_mut().enumerate() {
        let address = if local < 256 {
            block * 16 * 3 * 16 + local * 3 + slot
        } else {
            WINDOW_CANDIDATE_EVENTS + block * 3 * 16 + (local - 256) * 3 + slot
        };
        *event = active_cross_event_v1(P256CrossTraceEndpointV1::External, address)?;
    }
    Ok(events)
}
fn window_scalar_event_v1(
    row: usize,
) -> Result<P256ScalarSourceEventFixedV1, P256AggregateAdapterErrorV1> {
    if row >= P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if row >= P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
        return Ok(P256ScalarSourceEventFixedV1::inactive_v1());
    }
    let block = row / P256_WINDOW_STARK_TRACE_SIZE_V1;
    let local = row % P256_WINDOW_STARK_TRACE_SIZE_V1;
    if local >= 4 {
        return Ok(P256ScalarSourceEventFixedV1::inactive_v1());
    }
    Ok(P256ScalarSourceEventFixedV1 {
        active: F::ONE,
        scalar: f_usize_v1(block / 64 + 1)?,
        window: f_usize_v1(block % 64 + 1)?,
        bit: f_usize_v1(local + 1)?,
    })
}
/// Constant-memory base/fixed provider for the vertically packed 128-window adapter.
#[derive(Clone, Copy, Debug)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256WindowAggregateRowsV1<'a> {
    trace: &'a P256WindowBatchStarkTraceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256WindowAggregateRowsV1<'a> {
    /// Validate the sole vertical commitment layout.
    pub(crate) fn new_v1(
        trace: &'a P256WindowBatchStarkTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        if trace.base.len() != P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1
            || trace.aux.len() != P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1
            || trace.aux.iter().flatten().any(|value| *value != F::ZERO)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self { trace })
    }
    /// Direct committed base row or canonical zero padding.
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_WINDOW_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        if row >= P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(self
            .trace
            .base
            .get(row)
            .copied()
            .unwrap_or([F::ZERO; P256_WINDOW_BASE_WIDTH_V1]))
    }
    /// Copy one complete committed window column into caller-owned storage.
    pub(crate) fn fill_base_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(P256_WINDOW_AGGREGATE_TRACE_SIZE_V1, column, output, |row| {
            self.base_row_v1(row)
        })
    }
    fn native_aux_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_WINDOW_STARK_AUX_WIDTH_V1], P256AggregateAdapterErrorV1> {
        if row >= P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(self
            .trace
            .aux
            .get(row)
            .copied()
            .unwrap_or([F::ZERO; P256_WINDOW_STARK_AUX_WIDTH_V1]))
    }
}
/// Constant-memory integrated window auxiliary stream.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256WindowAggregateAuxStreamV1<'a> {
    rows: P256WindowAggregateRowsV1<'a>,
    cross_challenges: P256CrossTraceChallengesV1,
    scalar_challenges: P256ScalarBitBusChallengesV1,
    cross_start: [F; P256_CROSS_TRACE_LANES_V1],
    cross_running: [F; P256_CROSS_TRACE_LANES_V1],
    cross_terminal: [F; P256_CROSS_TRACE_LANES_V1],
    scalar_running: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    scalar_terminal: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    next_row: usize,
    _not_copy: core::cell::Cell<()>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256WindowAggregateAuxStreamV1<'a> {
    /// Prepare both external and scalar source products.
    pub(crate) fn new_v1(
        trace: &'a P256WindowBatchStarkTraceV1,
        cross_start: [F; P256_CROSS_TRACE_LANES_V1],
        cross_challenges: P256CrossTraceChallengesV1,
        scalar_challenges: P256ScalarBitBusChallengesV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        cross_challenges
            .validate()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        scalar_challenges
            .validate_v1()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        let rows = P256WindowAggregateRowsV1::new_v1(trace)?;
        let mut cross_running = cross_start;
        let mut scalar_running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        for row in 0..P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 {
            let base = rows.base_row_v1(row)?;
            let cross_events = window_cross_events_v1(row)?;
            let cross_sources = p256_window_opened_external_cells_v1(&base);
            let mut cross_aux = [F::ZERO; P256_CROSS_TRACE_WINDOW_AUX_WIDTH_V1];
            cross_running = build_compact_cross_aux_row_v1(
                &cross_events,
                &cross_sources,
                cross_running,
                [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                cross_challenges,
                &mut cross_aux,
            )?;
            let scalar_event = [window_scalar_event_v1(row)?];
            let bits = p256_window_opened_scalar_bits_v1(&base);
            let scalar_source = [bits[row % P256_WINDOW_STARK_TRACE_SIZE_V1 % 4]];
            let mut scalar_aux = [F::ZERO; P256_SCALAR_WINDOW_SOURCE_AUX_WIDTH_V1];
            scalar_running = build_compact_scalar_aux_row_v1(
                &scalar_event,
                &scalar_source,
                scalar_running,
                [F::ZERO; P256_SCALAR_BIT_BUS_LANES_V1],
                scalar_challenges,
                &mut scalar_aux,
            )?;
        }
        Ok(Self {
            rows,
            cross_challenges,
            scalar_challenges,
            cross_start,
            cross_running: cross_start,
            cross_terminal: cross_running,
            scalar_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            scalar_terminal: scalar_running,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        })
    }
    /// Emit the next exact 37-column row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1> {
        if self.next_row == P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 {
            return Ok(None);
        }
        let row = self.next_row;
        let base = self.rows.base_row_v1(row)?;
        let mut aux = [F::ZERO; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1];
        aux[..P256_WINDOW_STARK_AUX_WIDTH_V1].copy_from_slice(&self.rows.native_aux_row_v1(row)?);
        let cross_events = window_cross_events_v1(row)?;
        self.cross_running = build_compact_cross_aux_row_v1(
            &cross_events,
            &p256_window_opened_external_cells_v1(&base),
            self.cross_running,
            self.cross_terminal,
            self.cross_challenges,
            &mut aux[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX],
        )?;
        let scalar_event = [window_scalar_event_v1(row)?];
        let bits = p256_window_opened_scalar_bits_v1(&base);
        let local = row % P256_WINDOW_STARK_TRACE_SIZE_V1;
        let source = [if local < 4 { bits[local] } else { F::ZERO }];
        self.scalar_running = build_compact_scalar_aux_row_v1(
            &scalar_event,
            &source,
            self.scalar_running,
            self.scalar_terminal,
            self.scalar_challenges,
            &mut aux[WINDOW_SCALAR_AUX..],
        )?;
        self.next_row += 1;
        Ok(Some(aux))
    }
    /// Replay this deterministic stream into one challenge-dependent window auxiliary column.
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.cross_challenges
            .validate()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        self.scalar_challenges
            .validate_v1()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        let mut replay = Self {
            rows: self.rows,
            cross_challenges: self.cross_challenges,
            scalar_challenges: self.scalar_challenges,
            cross_start: self.cross_start,
            cross_running: self.cross_start,
            cross_terminal: self.cross_terminal,
            scalar_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            scalar_terminal: self.scalar_terminal,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        };
        fill_aggregate_aux_column_v1(P256_WINDOW_AGGREGATE_TRACE_SIZE_V1, column, output, || {
            replay.next_aux_row_v1()
        })
    }
    /// External cross-product start.
    pub(crate) const fn cross_start_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.cross_start
    }
    /// External cross-product terminal.
    pub(crate) const fn cross_terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.cross_terminal
    }
    /// Window scalar-source terminal.
    pub(crate) const fn scalar_terminal_v1(&self) -> [F; P256_SCALAR_BIT_BUS_LANES_V1] {
        self.scalar_terminal
    }
    /// Clear all challenge-bound window products without altering the
    /// committed-row reference or verifier-owned fixed topology.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_cross_challenges_v1(&mut self.cross_challenges);
        zeroize_scalar_challenges_v1(&mut self.scalar_challenges);
        super::private_table::zeroize_fields_v1(&mut self.cross_start[..]);
        super::private_table::zeroize_fields_v1(&mut self.cross_running[..]);
        super::private_table::zeroize_fields_v1(&mut self.cross_terminal[..]);
        super::private_table::zeroize_fields_v1(&mut self.scalar_running[..]);
        super::private_table::zeroize_fields_v1(&mut self.scalar_terminal[..]);
        self.next_row = P256_WINDOW_AGGREGATE_TRACE_SIZE_V1;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.cross_challenges
            .lanes
            .iter()
            .flat_map(|lane| lane.terms)
            .all(|value| value == F::ZERO)
            && self
                .scalar_challenges
                .lanes
                .iter()
                .flat_map(|lane| lane.terms)
                .all(|value| value == F::ZERO)
            && self
                .cross_start
                .iter()
                .chain(&self.cross_running)
                .chain(&self.cross_terminal)
                .chain(&self.scalar_running)
                .chain(&self.scalar_terminal)
                .all(|value| *value == F::ZERO)
            && self.next_row == P256_WINDOW_AGGREGATE_TRACE_SIZE_V1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256WindowAggregateAuxStreamV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Complete vertical window AIR and attached cross/scalar products over one field.
pub fn evaluate_p256_window_aggregate_local_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_WINDOW_BASE_WIDTH_V1],
    next: &[A; P256_WINDOW_BASE_WIDTH_V1],
    current_aux: &[A; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1],
    next_aux: &[A; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1],
    fixed: &[A; P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1],
    cross: P256CrossTraceChallengesV1,
    scalar: P256ScalarBitBusChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    let current_native: &[A; P256_WINDOW_STARK_AUX_WIDTH_V1] = current_aux
        [..P256_WINDOW_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let next_native: &[A; P256_WINDOW_STARK_AUX_WIDTH_V1] = next_aux
        [..P256_WINDOW_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let native_fixed: &[A; P256_WINDOW_STARK_FIXED_WIDTH_V1] = fixed
        [..P256_WINDOW_STARK_FIXED_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let mut residues = evaluate_p256_window_stark_residues_over_field_v1(
        current,
        next,
        current_native,
        next_native,
        native_fixed,
    )?;
    let cross_events: [P256CrossTraceEventFixedV1<A>; 3] = core::array::from_fn(|slot| {
        let start = WINDOW_CROSS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
        decode_cross_event_v1(&fixed[start..start + CROSS_EVENT_FIXED_WIDTH])
    });
    let boundary = decode_boundary_v1(
        &fixed[WINDOW_BOUNDARY_FIXED..WINDOW_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    residues.extend(evaluate_compact_cross_local_residues_v1(
        &cross_events,
        &p256_window_opened_external_cells_v1(current),
        boundary,
        &current_aux[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX],
        &next_aux[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX],
        cross,
    )?);
    let scalar_event =
        decode_scalar_event_v1(&fixed[WINDOW_SCALAR_FIXED..WINDOW_SCALAR_BIT_SELECTORS_FIXED]);
    let bits = p256_window_opened_scalar_bits_v1(current);
    let selected = bits
        .into_iter()
        .enumerate()
        .fold(A::ZERO, |sum, (bit, value)| {
            sum.add(fixed[WINDOW_SCALAR_BIT_SELECTORS_FIXED + bit].mul(value))
        });
    residues.extend(evaluate_compact_scalar_residues_v1(
        &[scalar_event],
        &[selected],
        boundary,
        &current_aux[WINDOW_SCALAR_AUX..],
        &next_aux[WINDOW_SCALAR_AUX..],
        scalar,
    )?);
    if residues.len() != P256_WINDOW_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Construct the explicit window claim from native first/final rows.
#[cfg(test)]
pub fn p256_window_cross_terminal_claim_v1(
    first_aux: &[F; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1],
    terminal_aux: &[F; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1],
) -> Result<P256CrossTraceTerminalClaimV1, P256AggregateAdapterErrorV1> {
    let start = core::array::from_fn(|lane| {
        first_aux[WINDOW_CROSS_AUX + compact_products_start_v1(3, lane)]
    });
    Ok(P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::WindowBatch,
        start,
        terminal: compact_cross_terminal_v1(3, &terminal_aux[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX])?,
    })
}
/// Window scalar-source terminal projection.
#[cfg(test)]
pub fn p256_window_scalar_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_SCALAR_BIT_BUS_LANES_V1], P256AggregateAdapterErrorV1> {
    compact_cross_terminal_v1(1, &aux[WINDOW_SCALAR_AUX..])
}
/// Window external-chain terminal projection.
#[cfg(test)]
pub fn p256_window_cross_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    compact_cross_terminal_v1(3, &aux[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX])
}
/// Final native-row selector in window preprocessing.
#[cfg(test)]
pub fn p256_window_last_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1],
) -> A {
    decode_boundary_v1(
        &fixed[WINDOW_BOUNDARY_FIXED..WINDOW_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    )
    .last
}
/// Verifier-owned reduction instance in the terminal chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ReductionAggregateRoleV1 {
    /// Digest word to scalar reduction.
    Digest,
    /// Affine result-X to scalar reduction.
    ResultX,
}
fn reduction_cross_events_v1(
    role: P256ReductionAggregateRoleV1,
    row: usize,
) -> Result<[P256CrossTraceEventFixedV1; 2], P256AggregateAdapterErrorV1> {
    if row >= P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if row >= P256_REDUCTION_ROWS_V1 {
        return Ok([P256CrossTraceEventFixedV1::inactive(); 2]);
    }
    match role {
        P256ReductionAggregateRoleV1::Digest => Ok([
            active_cross_event_v1(P256CrossTraceEndpointV1::DigestInput, row)?,
            active_cross_event_v1(
                P256CrossTraceEndpointV1::External,
                DIGEST_REDUCTION_OUTPUT_ADDRESS + row,
            )?,
        ]),
        P256ReductionAggregateRoleV1::ResultX => Ok([
            active_cross_event_v1(
                P256CrossTraceEndpointV1::External,
                RESULT_X_REDUCTION_SOURCE_ADDRESS + row,
            )?,
            active_cross_event_v1(
                P256CrossTraceEndpointV1::External,
                RESULT_X_REDUCTION_OUTPUT_ADDRESS + row,
            )?,
        ]),
    }
}
/// Constant-memory base/fixed provider for one reduction instance.
#[derive(Clone, Copy, Debug)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ReductionAggregateRowsV1<'a> {
    role: P256ReductionAggregateRoleV1,
    trace: &'a P256ReductionTraceV1,
    #[cfg(test)]
    fixed: P256ComparisonStarkFixedProviderV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ReductionAggregateRowsV1<'a> {
    /// Validate the exact 16-row reduction topology.
    pub(crate) fn new_v1(
        role: P256ReductionAggregateRoleV1,
        trace: &'a P256ReductionTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        trace.validate()?;
        Ok(Self {
            role,
            trace,
            #[cfg(test)]
            fixed: P256ComparisonStarkFixedProviderV1::reduction_v1(
                P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
            )?,
        })
    }
    /// Direct committed reduction row or canonical zero padding.
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_REDUCTION_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        if row >= P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(self
            .trace
            .base
            .get(row)
            .copied()
            .unwrap_or([F::ZERO; P256_REDUCTION_BASE_WIDTH_V1]))
    }
    /// Copy one complete committed reduction column into caller-owned storage.
    pub(crate) fn fill_base_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(
            P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            |row| self.base_row_v1(row),
        )
    }
    /// Exact flat fixed row.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
        let mut fixed = [F::ZERO; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1];
        fixed[..P256_REDUCTION_STARK_FIXED_WIDTH_V1].copy_from_slice(&self.fixed.row_v1(row)?);
        for (slot, event) in reduction_cross_events_v1(self.role, row)?
            .into_iter()
            .enumerate()
        {
            let start = REDUCTION_CROSS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
            encode_cross_event_v1(event, &mut fixed[start..start + CROSS_EVENT_FIXED_WIDTH]);
        }
        encode_boundary_v1(
            P256CrossTraceBoundaryFixedV1::for_row(row, P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1)?,
            &mut fixed
                [REDUCTION_BOUNDARY_FIXED..REDUCTION_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
        );
        Ok(fixed)
    }
}
/// Constant-memory reduction auxiliary stream.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256ReductionAggregateAuxStreamV1<'a> {
    rows: P256ReductionAggregateRowsV1<'a>,
    challenges: P256CrossTraceChallengesV1,
    start: [F; P256_CROSS_TRACE_LANES_V1],
    running: [F; P256_CROSS_TRACE_LANES_V1],
    terminal: [F; P256_CROSS_TRACE_LANES_V1],
    next_row: usize,
    _not_copy: core::cell::Cell<()>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256ReductionAggregateAuxStreamV1<'a> {
    /// Prepare one exact reduction chain segment.
    pub(crate) fn new_v1(
        role: P256ReductionAggregateRoleV1,
        trace: &'a P256ReductionTraceV1,
        start: [F; P256_CROSS_TRACE_LANES_V1],
        challenges: P256CrossTraceChallengesV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        challenges
            .validate()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        let rows = P256ReductionAggregateRowsV1::new_v1(role, trace)?;
        let mut running = start;
        for row in 0..P256_REDUCTION_ROWS_V1 {
            let events = reduction_cross_events_v1(role, row)?;
            let sources = p256_reduction_opened_binding_cells_v1(&rows.base_row_v1(row)?);
            let mut aux = [F::ZERO; P256_CROSS_TRACE_REDUCTION_AUX_WIDTH_V1];
            running = build_compact_cross_aux_row_v1(
                &events,
                &sources,
                running,
                [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                challenges,
                &mut aux,
            )?;
        }
        Ok(Self {
            rows,
            challenges,
            start,
            running: start,
            terminal: running,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        })
    }
    /// Direct committed base row.
    #[cfg(test)]
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_REDUCTION_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        self.rows.base_row_v1(row)
    }
    /// Exact flat fixed row.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
        self.rows.fixed_row_v1(row)
    }
    /// Emit the next exact 19-column row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1>
    {
        if self.next_row == P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 {
            return Ok(None);
        }
        let row = self.next_row;
        let mut aux = [F::ZERO; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1];
        let events = reduction_cross_events_v1(self.rows.role, row)?;
        let sources = p256_reduction_opened_binding_cells_v1(&self.rows.base_row_v1(row)?);
        self.running = build_compact_cross_aux_row_v1(
            &events,
            &sources,
            self.running,
            self.terminal,
            self.challenges,
            &mut aux[REDUCTION_CROSS_AUX..],
        )?;
        self.next_row += 1;
        Ok(Some(aux))
    }
    /// Replay this deterministic stream into one challenge-dependent reduction auxiliary column.
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.challenges
            .validate()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        let mut replay = Self {
            rows: self.rows,
            challenges: self.challenges,
            start: self.start,
            running: self.start,
            terminal: self.terminal,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        };
        fill_aggregate_aux_column_v1(
            P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            || replay.next_aux_row_v1(),
        )
    }
    /// Segment start.
    pub(crate) const fn start_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.start
    }
    /// Segment terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.terminal
    }
    /// Clear reduction challenges and product endpoints while retaining the
    /// public role and fixed schedule in `rows`.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_cross_challenges_v1(&mut self.challenges);
        super::private_table::zeroize_fields_v1(&mut self.start[..]);
        super::private_table::zeroize_fields_v1(&mut self.running[..]);
        super::private_table::zeroize_fields_v1(&mut self.terminal[..]);
        self.next_row = P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.challenges
            .lanes
            .iter()
            .flat_map(|lane| lane.terms)
            .all(|value| value == F::ZERO)
            && self
                .start
                .iter()
                .chain(&self.running)
                .chain(&self.terminal)
                .all(|value| *value == F::ZERO)
            && self.next_row == P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ReductionAggregateAuxStreamV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// The same integrated comparison and cross-trace polynomials over either field.
pub fn evaluate_p256_reduction_aggregate_local_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_REDUCTION_BASE_WIDTH_V1],
    next: &[A; P256_REDUCTION_BASE_WIDTH_V1],
    current_aux: &[A; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1],
    next_aux: &[A; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1],
    fixed: &[A; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    let current_native: &[A; P256_REDUCTION_STARK_AUX_WIDTH_V1] = current_aux
        [..P256_REDUCTION_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let next_native: &[A; P256_REDUCTION_STARK_AUX_WIDTH_V1] = next_aux
        [..P256_REDUCTION_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let native_fixed: &[A; P256_REDUCTION_STARK_FIXED_WIDTH_V1] = fixed
        [..P256_REDUCTION_STARK_FIXED_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let mut residues = evaluate_p256_reduction_stark_residues_over_field_v1(
        current,
        next,
        current_native,
        next_native,
        native_fixed,
    )?;
    let events: [P256CrossTraceEventFixedV1<A>; 2] = core::array::from_fn(|slot| {
        let offset = REDUCTION_CROSS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
        decode_cross_event_v1(&fixed[offset..offset + CROSS_EVENT_FIXED_WIDTH])
    });
    let boundary = decode_boundary_v1(
        &fixed[REDUCTION_BOUNDARY_FIXED..REDUCTION_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    residues.extend(evaluate_compact_cross_local_residues_v1(
        &events,
        &p256_reduction_opened_binding_cells_v1(current),
        boundary,
        &current_aux[REDUCTION_CROSS_AUX..],
        &next_aux[REDUCTION_CROSS_AUX..],
        challenges,
    )?);
    if residues.len() != P256_REDUCTION_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Construct an explicit reduction claim from native first/final rows.
#[cfg(test)]
pub fn p256_reduction_cross_terminal_claim_v1(
    role: P256ReductionAggregateRoleV1,
    first_aux: &[F; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1],
    terminal_aux: &[F; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1],
) -> Result<P256CrossTraceTerminalClaimV1, P256AggregateAdapterErrorV1> {
    Ok(P256CrossTraceTerminalClaimV1 {
        role: match role {
            P256ReductionAggregateRoleV1::Digest => P256CrossTraceTerminalRoleV1::DigestReduction,
            P256ReductionAggregateRoleV1::ResultX => P256CrossTraceTerminalRoleV1::ResultXReduction,
        },
        start: core::array::from_fn(|lane| {
            first_aux[REDUCTION_CROSS_AUX + compact_products_start_v1(2, lane)]
        }),
        terminal: compact_cross_terminal_v1(2, &terminal_aux[REDUCTION_CROSS_AUX..])?,
    })
}
/// Reduction external-chain terminal projection.
#[cfg(test)]
pub fn p256_reduction_cross_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    compact_cross_terminal_v1(2, &aux[REDUCTION_CROSS_AUX..])
}
/// Final native-row selector in reduction preprocessing.
#[cfg(test)]
pub fn p256_reduction_last_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1],
) -> A {
    decode_boundary_v1(
        &fixed[REDUCTION_BOUNDARY_FIXED..REDUCTION_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    )
    .last
}
fn low_s_cross_event_v1(
    row: usize,
) -> Result<P256CrossTraceEventFixedV1, P256AggregateAdapterErrorV1> {
    if row >= P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    if row < P256_REDUCTION_ROWS_V1 {
        active_cross_event_v1(P256CrossTraceEndpointV1::External, LOW_S_ADDRESS + row)
    } else {
        Ok(P256CrossTraceEventFixedV1::inactive())
    }
}
/// Constant-memory wallet low-S base/fixed provider.
#[derive(Clone, Copy, Debug)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256LowSAggregateRowsV1<'a> {
    trace: &'a P256LowSTraceV1,
    #[cfg(test)]
    fixed: P256ComparisonStarkFixedProviderV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256LowSAggregateRowsV1<'a> {
    /// Construct only for the wallet role.
    pub(crate) fn new_v1(
        role: P256EcdsaRoleV1,
        trace: &'a P256LowSTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        if role != P256EcdsaRoleV1::WalletOwnership {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        trace.validate()?;
        Ok(Self {
            trace,
            #[cfg(test)]
            fixed: P256ComparisonStarkFixedProviderV1::low_s_v1(
                P256_LOW_S_AGGREGATE_TRACE_SIZE_V1,
            )?,
        })
    }
    /// Direct committed low-S row or canonical zero padding.
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_LOW_S_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        if row >= P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(self
            .trace
            .base
            .get(row)
            .copied()
            .unwrap_or([F::ZERO; P256_LOW_S_BASE_WIDTH_V1]))
    }
    /// Copy one complete committed low-S column into caller-owned storage.
    pub(crate) fn fill_base_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(P256_LOW_S_AGGREGATE_TRACE_SIZE_V1, column, output, |row| {
            self.base_row_v1(row)
        })
    }
    /// Exact flat fixed row.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
        let mut fixed = [F::ZERO; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1];
        fixed[..P256_LOW_S_STARK_FIXED_WIDTH_V1].copy_from_slice(&self.fixed.row_v1(row)?);
        encode_cross_event_v1(
            low_s_cross_event_v1(row)?,
            &mut fixed[LOW_S_CROSS_FIXED..LOW_S_BOUNDARY_FIXED],
        );
        encode_boundary_v1(
            P256CrossTraceBoundaryFixedV1::for_row(row, P256_LOW_S_AGGREGATE_TRACE_SIZE_V1)?,
            &mut fixed[LOW_S_BOUNDARY_FIXED..LOW_S_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
        );
        Ok(fixed)
    }
}
/// Constant-memory wallet low-S auxiliary stream.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256LowSAggregateAuxStreamV1<'a> {
    rows: P256LowSAggregateRowsV1<'a>,
    challenges: P256CrossTraceChallengesV1,
    start: [F; P256_CROSS_TRACE_LANES_V1],
    running: [F; P256_CROSS_TRACE_LANES_V1],
    terminal: [F; P256_CROSS_TRACE_LANES_V1],
    next_row: usize,
    _not_copy: core::cell::Cell<()>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256LowSAggregateAuxStreamV1<'a> {
    /// Prepare the wallet-only chain segment.
    pub(crate) fn new_v1(
        role: P256EcdsaRoleV1,
        trace: &'a P256LowSTraceV1,
        start: [F; P256_CROSS_TRACE_LANES_V1],
        challenges: P256CrossTraceChallengesV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        challenges
            .validate()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        let rows = P256LowSAggregateRowsV1::new_v1(role, trace)?;
        let mut running = start;
        for row in 0..P256_REDUCTION_ROWS_V1 {
            let event = [low_s_cross_event_v1(row)?];
            let source = [p256_low_s_opened_binding_cell_v1(&rows.base_row_v1(row)?)];
            let mut aux = [F::ZERO; P256_CROSS_TRACE_LOW_S_AUX_WIDTH_V1];
            running = build_compact_cross_aux_row_v1(
                &event,
                &source,
                running,
                [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                challenges,
                &mut aux,
            )?;
        }
        Ok(Self {
            rows,
            challenges,
            start,
            running: start,
            terminal: running,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        })
    }
    /// Direct committed base row.
    #[cfg(test)]
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_LOW_S_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        self.rows.base_row_v1(row)
    }
    /// Exact flat fixed row.
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
        self.rows.fixed_row_v1(row)
    }
    /// Emit the next exact 14-column row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1> {
        if self.next_row == P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 {
            return Ok(None);
        }
        let row = self.next_row;
        let mut aux = [F::ZERO; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1];
        let events = [low_s_cross_event_v1(row)?];
        let sources = [p256_low_s_opened_binding_cell_v1(
            &self.rows.base_row_v1(row)?,
        )];
        self.running = build_compact_cross_aux_row_v1(
            &events,
            &sources,
            self.running,
            self.terminal,
            self.challenges,
            &mut aux[LOW_S_CROSS_AUX..],
        )?;
        self.next_row += 1;
        Ok(Some(aux))
    }
    /// Replay this deterministic stream into one challenge-dependent low-S auxiliary column.
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.challenges
            .validate()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        let mut replay = Self {
            rows: self.rows,
            challenges: self.challenges,
            start: self.start,
            running: self.start,
            terminal: self.terminal,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        };
        fill_aggregate_aux_column_v1(P256_LOW_S_AGGREGATE_TRACE_SIZE_V1, column, output, || {
            replay.next_aux_row_v1()
        })
    }
    /// Segment start.
    pub(crate) const fn start_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.start
    }
    /// Segment terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.terminal
    }
    /// Clear wallet low-S challenges and products while retaining the public
    /// role/fixed topology in `rows`.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_cross_challenges_v1(&mut self.challenges);
        super::private_table::zeroize_fields_v1(&mut self.start[..]);
        super::private_table::zeroize_fields_v1(&mut self.running[..]);
        super::private_table::zeroize_fields_v1(&mut self.terminal[..]);
        self.next_row = P256_LOW_S_AGGREGATE_TRACE_SIZE_V1;
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.challenges
            .lanes
            .iter()
            .flat_map(|lane| lane.terms)
            .all(|value| value == F::ZERO)
            && self
                .start
                .iter()
                .chain(&self.running)
                .chain(&self.terminal)
                .all(|value| *value == F::ZERO)
            && self.next_row == P256_LOW_S_AGGREGATE_TRACE_SIZE_V1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256LowSAggregateAuxStreamV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// The same integrated comparison and cross-trace polynomials over either field.
pub fn evaluate_p256_low_s_aggregate_local_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_LOW_S_BASE_WIDTH_V1],
    next: &[A; P256_LOW_S_BASE_WIDTH_V1],
    current_aux: &[A; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1],
    next_aux: &[A; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1],
    fixed: &[A; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    let current_native: &[A; P256_LOW_S_STARK_AUX_WIDTH_V1] = current_aux
        [..P256_LOW_S_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let next_native: &[A; P256_LOW_S_STARK_AUX_WIDTH_V1] = next_aux
        [..P256_LOW_S_STARK_AUX_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let native_fixed: &[A; P256_LOW_S_STARK_FIXED_WIDTH_V1] = fixed
        [..P256_LOW_S_STARK_FIXED_WIDTH_V1]
        .try_into()
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let mut residues = evaluate_p256_low_s_stark_residues_over_field_v1(
        current,
        next,
        current_native,
        next_native,
        native_fixed,
    )?;
    let event = decode_cross_event_v1(&fixed[LOW_S_CROSS_FIXED..LOW_S_BOUNDARY_FIXED]);
    let boundary = decode_boundary_v1(
        &fixed[LOW_S_BOUNDARY_FIXED..LOW_S_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    residues.extend(evaluate_compact_cross_local_residues_v1(
        &[event],
        &[p256_low_s_opened_binding_cell_v1(current)],
        boundary,
        &current_aux[LOW_S_CROSS_AUX..],
        &next_aux[LOW_S_CROSS_AUX..],
        challenges,
    )?);
    if residues.len() != P256_LOW_S_AGGREGATE_LOCAL_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Construct the explicit wallet low-S claim from native first/final rows.
#[cfg(test)]
pub fn p256_low_s_cross_terminal_claim_v1(
    first_aux: &[F; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1],
    terminal_aux: &[F; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1],
) -> Result<P256CrossTraceTerminalClaimV1, P256AggregateAdapterErrorV1> {
    Ok(P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::WalletLowS,
        start: core::array::from_fn(|lane| {
            first_aux[LOW_S_CROSS_AUX + compact_products_start_v1(1, lane)]
        }),
        terminal: compact_cross_terminal_v1(1, &terminal_aux[LOW_S_CROSS_AUX..])?,
    })
}
/// Wallet low-S external-chain terminal projection.
#[cfg(test)]
pub fn p256_low_s_cross_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1],
) -> Result<[A; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    compact_cross_terminal_v1(1, &aux[LOW_S_CROSS_AUX..])
}
/// Final native-row selector in low-S preprocessing.
#[cfg(test)]
pub fn p256_low_s_last_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1],
) -> A {
    decode_boundary_v1(
        &fixed[LOW_S_BOUNDARY_FIXED..LOW_S_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    )
    .last
}
const SINK_ACTIVE_FIXED: usize = 0;
const SINK_CONSTANT_FIXED: usize = SINK_ACTIVE_FIXED + P256_EXTERNAL_BINDINGS_PER_ROW_V1;
const SINK_CONSTANT_VALUE_FIXED: usize = SINK_CONSTANT_FIXED + P256_EXTERNAL_BINDINGS_PER_ROW_V1;
const SINK_EVENTS_FIXED: usize = SINK_CONSTANT_VALUE_FIXED + P256_EXTERNAL_BINDINGS_PER_ROW_V1;
const SINK_BOUNDARY_FIXED: usize = SINK_EVENTS_FIXED + 6 * CROSS_EVENT_FIXED_WIDTH;
const SINK_SELECTION_BYTE_FIXED: usize = SINK_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH;
const SINK_SELECTION_SELECTOR_FIXED: usize = SINK_SELECTION_BYTE_FIXED + 1;
const SINK_SELECTION_REQUIRE_ACTIVE_FIXED: usize = SINK_SELECTION_SELECTOR_FIXED + 1;
const SINK_SELECTION_DUMMY_FIXED: usize = SINK_SELECTION_REQUIRE_ACTIVE_FIXED + 1;
const SINK_SELECTION_INACTIVE_REAL_FIXED: usize = SINK_SELECTION_DUMMY_FIXED + 1;
const SINK_SELECTION_CONTINUE_FIXED: usize = SINK_SELECTION_INACTIVE_REAL_FIXED + 1;
const SINK_SELECTION_REAL_BASE: usize = 2 * P256_EXTERNAL_BINDINGS_PER_ROW_V1;
const SINK_SELECTION_SELECTED_BASE: usize = SINK_SELECTION_REAL_BASE + 1;
const SINK_SELECTION_ACTIVE_BASE: usize = SINK_SELECTION_SELECTED_BASE + 1;
const SINK_SELECTION_REAL_BITS_BASE: usize = SINK_SELECTION_ACTIVE_BASE + 1;
const SINK_SELECTION_SELECTED_BITS_BASE: usize = SINK_SELECTION_REAL_BITS_BASE + 8;
const _: () = assert!(SINK_SELECTION_SELECTED_BITS_BASE + 8 == P256_BINDING_SINK_BASE_WIDTH_V1);
const _: () = assert!(SINK_SELECTION_CONTINUE_FIXED + 1 == P256_BINDING_SINK_FIXED_WIDTH_V1);
/// Verifier-owned real key bytes and private activity column in the committed sink.
/// Qx and Qy are the first 64 big-endian bytes, before optional-certificate selection.
pub const fn p256_real_key_input_columns_v1() -> (usize, usize, usize) {
    (
        SINK_SELECTION_REAL_BASE,
        SINK_SELECTION_ACTIVE_BASE,
        P256_INPUT_SELECTION_ROW_START_V1,
    )
}

/// Verifier-owned unreduced SHA digest bytes in the same real-input column.
/// The four preceding 32-byte words are Qx, Qy, r and s; no selected/dummy column is used.
pub const fn p256_real_digest_input_columns_v1() -> (usize, usize) {
    (
        SINK_SELECTION_REAL_BASE,
        P256_INPUT_SELECTION_ROW_START_V1 + 4 * 32,
    )
}

fn p256_inactive_real_byte_v1(byte: usize) -> Result<u8, P256AggregateAdapterErrorV1> {
    if byte < 4 * 32 {
        Ok(0)
    } else {
        ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1
            .get(byte - 4 * 32)
            .copied()
            .ok_or(P256AggregateAdapterErrorV1::Topology)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_byte_bits_v1(target: &mut [F], byte: u8) {
    for (bit, value) in target.iter_mut().enumerate() {
        *value = F(u64::from((byte >> bit) & 1));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn flatten_regular_aux_v1(
    row: P256CrossTraceRegularAuxRowV1,
) -> [F; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1] {
    let mut flat = [F::ZERO; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1];
    flat[..6].copy_from_slice(&row.event_values);
    let mut cursor = 6;
    for products in row.products {
        for product in products {
            flat[cursor] = product;
            cursor += 1;
        }
    }
    flat[cursor..cursor + P256_CROSS_TRACE_LANES_V1].copy_from_slice(&row.terminal);
    flat
}
/// Constant-memory verifier preprocessing for the external-binding sink.
#[derive(Clone, Debug)]
pub struct P256BindingSinkFixedProviderV1 {
    fixed: P256CrossTraceSinkFixedV1,
    optional_certificate: bool,
}
impl P256BindingSinkFixedProviderV1 {
    /// Compile the role-exact sink schedule.
    pub(crate) fn new_v1(role: P256EcdsaRoleV1) -> Result<Self, P256AggregateAdapterErrorV1> {
        Self::new_with_optional_certificate_v1(role, false)
    }
    /// Compile the role-exact schedule for the sole optional certificate instance. The Boolean is
    /// verifier-derived from global signature index two and is never accepted from proof metadata.
    pub(crate) fn new_with_optional_certificate_v1(
        role: P256EcdsaRoleV1,
        optional_certificate: bool,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        if optional_certificate && role != P256EcdsaRoleV1::CertificateOrCrl {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self {
            fixed: P256CrossTraceSinkFixedV1::compile_v1(role)?,
            optional_certificate,
        })
    }
    /// Regenerate one exact flat fixed row.
    pub(crate) fn row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_BINDING_SINK_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
        let source = self.fixed.row_v1(row)?;
        let mut fixed = [F::ZERO; P256_BINDING_SINK_FIXED_WIDTH_V1];
        fixed[SINK_ACTIVE_FIXED..SINK_CONSTANT_FIXED].copy_from_slice(&source.active);
        fixed[SINK_CONSTANT_FIXED..SINK_CONSTANT_VALUE_FIXED].copy_from_slice(&source.constant);
        fixed[SINK_CONSTANT_VALUE_FIXED..SINK_EVENTS_FIXED].copy_from_slice(&source.constant_value);
        for (slot, event) in source.product.events.into_iter().enumerate() {
            let offset = SINK_EVENTS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
            encode_cross_event_v1(event, &mut fixed[offset..offset + CROSS_EVENT_FIXED_WIDTH]);
        }
        encode_boundary_v1(
            source.product.boundary,
            &mut fixed[SINK_BOUNDARY_FIXED..SINK_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
        );
        if (P256_INPUT_SELECTION_ROW_START_V1..P256_INPUT_SELECTION_SELECTOR_ROW_V1).contains(&row)
        {
            let byte = row - P256_INPUT_SELECTION_ROW_START_V1;
            fixed[SINK_SELECTION_BYTE_FIXED] = F::ONE;
            fixed[SINK_SELECTION_DUMMY_FIXED] = F(u64::from(p256_input_selection_byte_v1(
                &ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1,
                byte,
            )?));
            fixed[SINK_SELECTION_INACTIVE_REAL_FIXED] =
                F(u64::from(p256_inactive_real_byte_v1(byte)?));
        } else if row == P256_INPUT_SELECTION_SELECTOR_ROW_V1 {
            fixed[SINK_SELECTION_SELECTOR_FIXED] = F::ONE;
            fixed[SINK_SELECTION_REQUIRE_ACTIVE_FIXED] = F(u64::from(!self.optional_certificate));
        }
        fixed[SINK_SELECTION_CONTINUE_FIXED] = F(u64::from(
            row + 1 < P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
        ));
        Ok(fixed)
    }
    /// Regenerate one complete verifier-preprocessed sink column.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn fill_fixed_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(
            P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            |row| self.row_v1(row),
        )
    }
}
/// Constant-memory committed sink base-row provider.
#[derive(Clone, Copy, Debug)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256BindingSinkRowsV1<'a> {
    trace: &'a P256ExternalBindingTraceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256BindingSinkRowsV1<'a> {
    /// Validate the exact role-dependent row count.
    pub(crate) fn new_v1(
        trace: &'a P256ExternalBindingTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        if trace.rows.len() != p256_external_binding_rows_v1(trace.role)
            || trace.rows.len() > P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self { trace })
    }
    /// Direct writer/external committed cells or canonical zero padding.
    pub(crate) fn base_row_v1(
        self,
        row: usize,
    ) -> Result<[F; P256_BINDING_SINK_BASE_WIDTH_V1], P256AggregateAdapterErrorV1> {
        if row >= P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let mut base = [F::ZERO; P256_BINDING_SINK_BASE_WIDTH_V1];
        if let Some(source) = self.trace.rows.get(row) {
            base[..P256_EXTERNAL_BINDINGS_PER_ROW_V1].copy_from_slice(&source.writer_cells);
            base[P256_EXTERNAL_BINDINGS_PER_ROW_V1..2 * P256_EXTERNAL_BINDINGS_PER_ROW_V1]
                .copy_from_slice(&source.external_cells);
        }
        base[SINK_SELECTION_ACTIVE_BASE] = self.trace.input_selection.active;
        if (P256_INPUT_SELECTION_ROW_START_V1..P256_INPUT_SELECTION_SELECTOR_ROW_V1).contains(&row)
        {
            let byte = row - P256_INPUT_SELECTION_ROW_START_V1;
            let real = p256_input_selection_byte_v1(&self.trace.input_selection.real, byte)?;
            let selected =
                p256_input_selection_byte_v1(&self.trace.input_selection.selected, byte)?;
            base[SINK_SELECTION_REAL_BASE] = F(u64::from(real));
            base[SINK_SELECTION_SELECTED_BASE] = F(u64::from(selected));
            write_byte_bits_v1(
                &mut base[SINK_SELECTION_REAL_BITS_BASE..SINK_SELECTION_REAL_BITS_BASE + 8],
                real,
            );
            write_byte_bits_v1(
                &mut base[SINK_SELECTION_SELECTED_BITS_BASE..SINK_SELECTION_SELECTED_BITS_BASE + 8],
                selected,
            );
        }
        Ok(base)
    }
    /// Copy one complete committed sink column into caller-owned storage.
    pub(crate) fn fill_base_column_v1(
        self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(
            P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            |row| self.base_row_v1(row),
        )
    }
}
/// Integrated binding-sink base/aux stream.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256BindingSinkAggregateStreamV1<'a> {
    rows: P256BindingSinkRowsV1<'a>,
    fixed: P256BindingSinkFixedProviderV1,
    sink: Option<P256CrossTraceSinkStreamV1<'a>>,
    terminal: [F; P256_CROSS_TRACE_LANES_V1],
    optional_certificate: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256BindingSinkAggregateStreamV1<'a> {
    /// Build the sole verifier-positioned optional certificate sink.
    pub(crate) fn new_with_optional_certificate_v1(
        trace: &'a P256ExternalBindingTraceV1,
        challenges: P256CrossTraceChallengesV1,
        optional_certificate: bool,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        if optional_certificate && trace.role != P256EcdsaRoleV1::CertificateOrCrl {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let sink = build_zk_x509_p256_cross_trace_sink_v1(trace, challenges)?;
        let terminal = sink.terminal_v1();
        Ok(Self {
            rows: P256BindingSinkRowsV1::new_v1(trace)?,
            fixed: P256BindingSinkFixedProviderV1::new_with_optional_certificate_v1(
                trace.role,
                optional_certificate,
            )?,
            sink: Some(sink),
            terminal,
            optional_certificate,
        })
    }
    /// Emit the next exact 38-column row.
    pub(crate) fn next_aux_row_v1(
        &mut self,
    ) -> Result<Option<[F; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1]>, P256AggregateAdapterErrorV1> {
        Ok(self
            .sink
            .as_mut()
            .ok_or(P256AggregateAdapterErrorV1::Challenge)?
            .next_row_v1()?
            .map(flatten_regular_aux_v1))
    }
    /// Replay this deterministic stream into one challenge-dependent sink auxiliary column.
    pub(crate) fn fill_aux_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let mut replay = Self {
            rows: self.rows,
            fixed: self.fixed.clone(),
            sink: Some(
                self.sink
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Challenge)?
                    .replay_v1(),
            ),
            terminal: self.terminal,
            optional_certificate: self.optional_certificate,
        };
        fill_aggregate_aux_column_v1(
            P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            || replay.next_aux_row_v1(),
        )
    }
    /// Independent sink terminal.
    pub(crate) const fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        self.terminal
    }
    /// Release the challenge-bound sink replay and terminal while preserving
    /// the independently compiled verifier-owned fixed topology.
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.sink = None;
        super::private_table::zeroize_fields_v1(&mut self.terminal[..]);
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.sink.is_none() && self.terminal.iter().all(|value| *value == F::ZERO)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256BindingSinkAggregateStreamV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
fn sink_sources_from_opened_base_v1<A: PolynomialAirFieldV1>(
    base: &[A; P256_BINDING_SINK_BASE_WIDTH_V1],
    next: &[A; P256_BINDING_SINK_BASE_WIDTH_V1],
) -> [A; 6] {
    let mut sources = core::array::from_fn(|event| {
        let slot = event / 2;
        if event.is_multiple_of(2) {
            base[slot]
        } else {
            base[P256_EXTERNAL_BINDINGS_PER_ROW_V1 + slot]
        }
    });
    // At legacy event rows both selected bytes are zero. At the disjoint
    // selected-input rows writer0 is zero. Keep the expression affine at OOD
    // points; the existing event selector gates the committed event value.
    sources[0] = sources[0]
        .add(base[SINK_SELECTION_SELECTED_BASE].mul_base(F(256)))
        .add(next[SINK_SELECTION_SELECTED_BASE]);
    sources
}
/// Pure numeric sink residues over directly opened writer/external cells.
#[cfg(test)]
pub fn evaluate_p256_binding_sink_aggregate_residues_v1(
    current: &[F; P256_BINDING_SINK_BASE_WIDTH_V1],
    next: &[F; P256_BINDING_SINK_BASE_WIDTH_V1],
    current_aux: &[F; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1],
    next_aux: &[F; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1],
    fixed: &[F; P256_BINDING_SINK_FIXED_WIDTH_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<F>, P256AggregateAdapterErrorV1> {
    evaluate_p256_binding_sink_aggregate_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
}
/// Complete binding-sink relation over F or Fp4, including optional input selection.
pub fn evaluate_p256_binding_sink_aggregate_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_BINDING_SINK_BASE_WIDTH_V1],
    next: &[A; P256_BINDING_SINK_BASE_WIDTH_V1],
    current_aux: &[A; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1],
    next_aux: &[A; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1],
    fixed: &[A; P256_BINDING_SINK_FIXED_WIDTH_V1],
    challenges: P256CrossTraceChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(P256AggregateAdapterErrorV1::Constraint);
    }
    let events: [P256CrossTraceEventFixedV1<A>; 6] = core::array::from_fn(|slot| {
        let offset = SINK_EVENTS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
        decode_cross_event_v1(&fixed[offset..offset + CROSS_EVENT_FIXED_WIDTH])
    });
    let boundary = decode_boundary_v1(
        &fixed[SINK_BOUNDARY_FIXED..SINK_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    let sources = sink_sources_from_opened_base_v1(current, next);
    let mut residues = evaluate_compact_cross_residues_v1(
        &events,
        &sources,
        boundary,
        current_aux,
        next_aux,
        [F::ONE; P256_CROSS_TRACE_LANES_V1],
        challenges,
    )?;
    for slot in 0..P256_EXTERNAL_BINDINGS_PER_ROW_V1 {
        let active = fixed[SINK_ACTIVE_FIXED + slot];
        let inactive = A::ONE.sub(active);
        let writer = current[slot];
        let external = current[P256_EXTERNAL_BINDINGS_PER_ROW_V1 + slot];
        residues.push(active.mul(writer.sub(external)));
        residues.push(inactive.mul(writer));
        residues.push(inactive.mul(external));
        residues.push(
            fixed[SINK_CONSTANT_FIXED + slot]
                .mul(external.sub(fixed[SINK_CONSTANT_VALUE_FIXED + slot])),
        );
    }
    let byte_gate = fixed[SINK_SELECTION_BYTE_FIXED];
    let selector_gate = fixed[SINK_SELECTION_SELECTOR_FIXED];
    let require_active = fixed[SINK_SELECTION_REQUIRE_ACTIVE_FIXED];
    let continue_gate = fixed[SINK_SELECTION_CONTINUE_FIXED];
    let real = current[SINK_SELECTION_REAL_BASE];
    let selected = current[SINK_SELECTION_SELECTED_BASE];
    let active = current[SINK_SELECTION_ACTIVE_BASE];
    let inactive = A::ONE.sub(active);
    residues.push(continue_gate.mul(next[SINK_SELECTION_ACTIVE_BASE].sub(active)));
    residues.push(selector_gate.mul(active).mul(active.sub(A::ONE)));
    residues.push(selector_gate.mul(require_active).mul(active.sub(A::ONE)));
    residues.push(
        byte_gate.mul(
            selected.sub(
                active
                    .mul(real)
                    .add(inactive.mul(fixed[SINK_SELECTION_DUMMY_FIXED])),
            ),
        ),
    );
    residues.push(byte_gate.mul(inactive.mul(real.sub(fixed[SINK_SELECTION_INACTIVE_REAL_FIXED]))));
    residues.push(A::ONE.sub(byte_gate).mul(real));
    residues.push(A::ONE.sub(byte_gate).mul(selected));
    let mut packed_real = A::ZERO;
    let mut packed_selected = A::ZERO;
    for bit in 0..8 {
        let coefficient = F(1_u64 << bit);
        let real_bit = current[SINK_SELECTION_REAL_BITS_BASE + bit];
        let selected_bit = current[SINK_SELECTION_SELECTED_BITS_BASE + bit];
        residues.push(real_bit.mul(real_bit.sub(A::ONE)));
        residues.push(selected_bit.mul(selected_bit.sub(A::ONE)));
        residues.push(A::ONE.sub(byte_gate).mul(real_bit));
        residues.push(A::ONE.sub(byte_gate).mul(selected_bit));
        packed_real = packed_real.add(real_bit.mul_base(coefficient));
        packed_selected = packed_selected.add(selected_bit.mul_base(coefficient));
    }
    residues.push(byte_gate.mul(real.sub(packed_real)));
    residues.push(byte_gate.mul(selected.sub(packed_selected)));
    if residues.len() != P256_BINDING_SINK_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Independent sink terminal projection.
#[cfg(test)]
pub fn p256_binding_sink_terminal_v1<A: PolynomialAirFieldV1>(
    aux: &[A; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1],
) -> Result<[A; P256_CROSS_TRACE_LANES_V1], P256AggregateAdapterErrorV1> {
    compact_cross_terminal_v1(6, aux)
}
/// Final native-row selector in binding-sink preprocessing.
#[cfg(test)]
pub fn p256_binding_sink_last_selector_v1<A: PolynomialAirFieldV1>(
    fixed: &[A; P256_BINDING_SINK_FIXED_WIDTH_V1],
) -> A {
    decode_boundary_v1(
        &fixed[SINK_BOUNDARY_FIXED..SINK_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    )
    .last
}
/// Native-domain scalar-bit bus residues.
#[cfg(test)]
pub fn evaluate_p256_scalar_bit_bus_aggregate_residues_v1(
    current: &[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    next: &[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    next_aux: &[F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    fixed: &[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<F>, P256AggregateAdapterErrorV1> {
    evaluate_p256_scalar_bit_bus_aggregate_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
}
/// Packed scalar-bit bus relation over the base or extension field.
pub fn evaluate_p256_scalar_bit_bus_aggregate_residues_over_field_v1<A: PolynomialAirFieldV1>(
    current: &[A; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    next: &[A; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1],
    current_aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    next_aux: &[A; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1],
    fixed: &[A; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    challenges: P256ScalarBitBusChallengesV1,
) -> Result<Vec<A>, P256AggregateAdapterErrorV1> {
    let residues = evaluate_p256_scalar_bit_bus_stark_residues_over_field_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )?;
    if residues.len() != P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(residues)
}
/// Bind both direct source terminals to the packed-bus terminal at the
/// verifier-preprocessed final active bus row.
#[cfg(test)]
pub fn evaluate_p256_scalar_source_terminal_openings_v1<A: PolynomialAirFieldV1>(
    bus_last_active_selector: A,
    arithmetic_source: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    window_source: [F; P256_SCALAR_BIT_BUS_LANES_V1],
    bus: [[A; P256_SCALAR_BIT_BUS_LANES_V1]; 2],
) -> [A; 2 * P256_SCALAR_BIT_BUS_LANES_V1] {
    core::array::from_fn(|index| {
        let lane = index % P256_SCALAR_BIT_BUS_LANES_V1;
        if index < P256_SCALAR_BIT_BUS_LANES_V1 {
            bus_last_active_selector.mul(A::from_base(arithmetic_source[lane]).sub(bus[0][lane]))
        } else {
            bus_last_active_selector.mul(A::from_base(window_source[lane]).sub(bus[1][lane]))
        }
    })
}
/// Verifier-owned P-256 adapter family within one signature instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256MainAdapterV1 {
    /// Value memory: local zero is execution and local one is sorted.
    ValueBus,
    /// Wide P-256 arithmetic.
    Arithmetic,
    /// Vertically packed 128-window batch.
    WindowBatch,
    /// Scalar reductions: local zero is digest and local one is result-X.
    Reduction,
    /// Wallet-only low-S comparison.
    WalletLowS,
    /// External writer/binding sink.
    BindingSink,
    /// Packed arithmetic/window scalar-bit copy bus.
    ScalarBitBus,
}
/// Closed auxiliary column families used by private MAIN endpoint equations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256PrivateLinkFamilyV1 {
    /// Value memory endpoint.
    Value,
    /// Value/arithmetic copy endpoint.
    Copy,
    /// Arithmetic scalar-bit endpoint.
    ArithmeticScalar,
    /// Window scalar-bit endpoint.
    WindowScalar,
    /// Product entering the external-cell chain segment.
    ChainStart,
    /// Constant-on-native-domain external-cell terminal.
    ChainTerminal,
}
/// Resolve column indices from the same layout constants used to encode the trace.
/// No witness, terminal value, native row or column index is accepted from a proof.
pub fn p256_private_link_columns_v1(
    registration: P256MainRegistrationV1,
    family: P256PrivateLinkFamilyV1,
) -> Result<[usize; 4], P256AggregateAdapterErrorV1> {
    use P256MainAdapterV1 as Adapter;
    use P256PrivateLinkFamilyV1 as Family;
    let offset = match (
        registration.adapter_v1(),
        registration.local_instance_v1(),
        family,
    ) {
        (Adapter::ValueBus, 0 | 1, Family::Value) => {
            return Ok(super::p256_value_bus::p256_value_bus_terminal_columns_v1());
        }
        (Adapter::ValueBus, 0, Family::Copy) => {
            VALUE_ARITHMETIC_COPY_AUX
                + compact_terminal_start_v1(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
        }
        (Adapter::Arithmetic, 0, Family::Copy) => {
            ARITHMETIC_VALUE_COPY_AUX + compact_terminal_start_v1(3)
        }
        (Adapter::Arithmetic, 0, Family::ArithmeticScalar) => {
            ARITHMETIC_SCALAR_AUX + compact_terminal_start_v1(8)
        }
        (Adapter::WindowBatch, 0, Family::WindowScalar) => {
            WINDOW_SCALAR_AUX + compact_terminal_start_v1(1)
        }
        (Adapter::ScalarBitBus, 0, Family::ArithmeticScalar) => {
            return Ok(super::p256_scalar_bit_bus::p256_scalar_bit_bus_terminal_columns_v1()[0]);
        }
        (Adapter::ScalarBitBus, 0, Family::WindowScalar) => {
            return Ok(super::p256_scalar_bit_bus::p256_scalar_bit_bus_terminal_columns_v1()[1]);
        }
        (Adapter::ValueBus, 0, Family::ChainStart) => {
            return Ok(core::array::from_fn(|lane| {
                VALUE_ARITHMETIC_COPY_AUX - 4 - P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 * 4 + lane
            }));
        }
        (Adapter::ValueBus, 0, Family::ChainTerminal) => VALUE_ARITHMETIC_COPY_AUX - 4,
        (Adapter::WindowBatch, 0, Family::ChainStart) => {
            return Ok(core::array::from_fn(|lane| {
                WINDOW_CROSS_AUX + compact_products_start_v1(3, lane)
            }));
        }
        (Adapter::WindowBatch, 0, Family::ChainTerminal) => {
            WINDOW_CROSS_AUX + compact_terminal_start_v1(3)
        }
        (Adapter::Reduction, 0 | 1, Family::ChainStart) => {
            return Ok(core::array::from_fn(|lane| {
                REDUCTION_CROSS_AUX + compact_products_start_v1(2, lane)
            }));
        }
        (Adapter::Reduction, 0 | 1, Family::ChainTerminal) => {
            REDUCTION_CROSS_AUX + compact_terminal_start_v1(2)
        }
        (Adapter::WalletLowS, 0, Family::ChainStart) => {
            return Ok(core::array::from_fn(|lane| {
                LOW_S_CROSS_AUX + compact_products_start_v1(1, lane)
            }));
        }
        (Adapter::WalletLowS, 0, Family::ChainTerminal) => {
            LOW_S_CROSS_AUX + compact_terminal_start_v1(1)
        }
        (Adapter::BindingSink, 0, Family::ChainTerminal) => compact_terminal_start_v1(6),
        _ => return Err(P256AggregateAdapterErrorV1::Topology),
    };
    Ok(core::array::from_fn(|lane| offset + lane))
}
/// Exact verifier-owned identity of one P-256 MAIN registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256MainRegistrationV1 {
    signature: u8,
    adapter: P256MainAdapterV1,
    local_instance: u8,
}
impl P256MainRegistrationV1 {
    /// Validate a verifier-positioned signature, adapter, and local instance.
    pub(crate) fn new_v1(
        signature: usize,
        adapter: P256MainAdapterV1,
        local_instance: usize,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        if signature >= P256_X5S1_SIGNATURES_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let valid_local = match adapter {
            P256MainAdapterV1::ValueBus | P256MainAdapterV1::Reduction => local_instance < 2,
            _ => local_instance == 0,
        };
        if !valid_local
            || (adapter == P256MainAdapterV1::WalletLowS
                && signature != P256_X5S1_SIGNATURES_V1 - 1)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self {
            signature: u8::try_from(signature)
                .map_err(|_| P256AggregateAdapterErrorV1::Resource)?,
            adapter,
            local_instance: u8::try_from(local_instance)
                .map_err(|_| P256AggregateAdapterErrorV1::Resource)?,
        })
    }
    /// Global signature index in the sole five-signature order.
    pub(crate) const fn signature_v1(self) -> usize {
        self.signature as usize
    }
    /// Registration-owned adapter family.
    pub(crate) const fn adapter_v1(self) -> P256MainAdapterV1 {
        self.adapter
    }
    /// Verifier-owned adapter-local instance.
    pub(crate) const fn local_instance_v1(self) -> usize {
        self.local_instance as usize
    }
    /// Role implied solely by the global signature index.
    pub(crate) const fn role_v1(self) -> P256EcdsaRoleV1 {
        if self.signature_v1() < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            P256EcdsaRoleV1::CertificateOrCrl
        } else {
            P256EcdsaRoleV1::WalletOwnership
        }
    }
    /// Native domain and committed/fixed widths for this exact registration.
    pub(crate) const fn shape_v1(
        self,
    ) -> Result<P256MainAdapterShapeV1, P256AggregateAdapterErrorV1> {
        let shape = match (self.adapter, self.local_instance) {
            (P256MainAdapterV1::ValueBus, 0) => P256MainAdapterShapeV1 {
                trace_size: P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
                aux_width: P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1,
                fixed_width: P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::ValueBus, 1) => P256MainAdapterShapeV1 {
                trace_size: P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
                aux_width: P256_VALUE_BUS_STARK_AUX_WIDTH_V1,
                fixed_width: P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::Arithmetic, 0) => P256MainAdapterShapeV1 {
                trace_size: P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_ARITHMETIC_BASE_WIDTH_V1,
                aux_width: P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1,
                fixed_width: P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::WindowBatch, 0) => P256MainAdapterShapeV1 {
                trace_size: P256_WINDOW_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_WINDOW_BASE_WIDTH_V1,
                aux_width: P256_WINDOW_AGGREGATE_AUX_WIDTH_V1,
                fixed_width: P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::Reduction, 0 | 1) => P256MainAdapterShapeV1 {
                trace_size: P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_REDUCTION_BASE_WIDTH_V1,
                aux_width: P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1,
                fixed_width: P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::WalletLowS, 0) => P256MainAdapterShapeV1 {
                trace_size: P256_LOW_S_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_LOW_S_BASE_WIDTH_V1,
                aux_width: P256_LOW_S_AGGREGATE_AUX_WIDTH_V1,
                fixed_width: P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::BindingSink, 0) => P256MainAdapterShapeV1 {
                trace_size: P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_BINDING_SINK_BASE_WIDTH_V1,
                aux_width: P256_CROSS_TRACE_SINK_AUX_WIDTH_V1,
                fixed_width: P256_BINDING_SINK_FIXED_WIDTH_V1,
            },
            (P256MainAdapterV1::ScalarBitBus, 0) => P256MainAdapterShapeV1 {
                trace_size: P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_SIZE_V1,
                base_width: P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1,
                aux_width: P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1,
                fixed_width: P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1,
            },
            _ => return Err(P256AggregateAdapterErrorV1::Topology),
        };
        Ok(shape)
    }
}
/// Exact native shape selected by a verifier-owned P-256 registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256MainAdapterShapeV1 {
    /// Native power-of-two row count.
    pub(crate) trace_size: usize,
    /// Challenge-independent committed width.
    pub(crate) base_width: usize,
    /// Post-X5B1 auxiliary width.
    pub(crate) aux_width: usize,
    /// Verifier-preprocessed width.
    pub(crate) fixed_width: usize,
}
fn canonical_p256_main_registrations_v1()
-> Result<Vec<P256MainRegistrationV1>, P256AggregateAdapterErrorV1> {
    let mut registrations = Vec::new();
    registrations
        .try_reserve_exact(
            P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 * 8 + P256_X5S1_WALLET_SIGNATURES_V1 * 9,
        )
        .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
    for signature in 0..P256_X5S1_SIGNATURES_V1 {
        for (adapter, local) in [
            (P256MainAdapterV1::ValueBus, 0),
            (P256MainAdapterV1::ValueBus, 1),
            (P256MainAdapterV1::Arithmetic, 0),
            (P256MainAdapterV1::WindowBatch, 0),
            (P256MainAdapterV1::Reduction, 0),
            (P256MainAdapterV1::Reduction, 1),
        ] {
            registrations.push(P256MainRegistrationV1::new_v1(signature, adapter, local)?);
        }
        if signature == P256_X5S1_SIGNATURES_V1 - 1 {
            registrations.push(P256MainRegistrationV1::new_v1(
                signature,
                P256MainAdapterV1::WalletLowS,
                0,
            )?);
        }
        registrations.push(P256MainRegistrationV1::new_v1(
            signature,
            P256MainAdapterV1::BindingSink,
            0,
        )?);
        registrations.push(P256MainRegistrationV1::new_v1(
            signature,
            P256MainAdapterV1::ScalarBitBus,
            0,
        )?);
    }
    Ok(registrations)
}
/// Reject any omitted, duplicated, or reordered P-256 MAIN registration.
pub fn validate_p256_main_registration_order_v1(
    registrations: &[P256MainRegistrationV1],
) -> Result<(), P256AggregateAdapterErrorV1> {
    if registrations != canonical_p256_main_registrations_v1()? {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    Ok(())
}
fn p256_main_owned_fixed_row_v1<const WIDTH: usize>(
    row: [F; WIDTH],
) -> Result<Vec<F>, P256AggregateAdapterErrorV1> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(WIDTH)
        .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
    owned.extend_from_slice(&row);
    Ok(owned)
}
#[derive(Clone, Debug)]
struct P256MainArithmeticFixedSourceV1 {
    fixed: P256ArithmeticStarkFixedProviderV1,
}
impl P256MainArithmeticFixedSourceV1 {
    fn new_v1(role: P256EcdsaRoleV1) -> Result<Self, P256AggregateAdapterErrorV1> {
        let topology = verifier_topology_v1(role)?;
        let arithmetic_topology = topology
            .linked_operations
            .iter()
            .map(|operation| ZkX509P256ArithmeticTopologyV1 {
                kind: operation.kind,
                modulus: operation.modulus,
            })
            .collect::<Vec<_>>();
        if arithmetic_topology.len() != P256_ARITHMETIC_OPERATIONS_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        Ok(Self {
            fixed: P256ArithmeticStarkFixedProviderV1::new_v1(
                &arithmetic_topology,
                P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            )?,
        })
    }
    fn row_v1(
        &self,
        row: usize,
    ) -> Result<[F; P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
        let mut fixed = [F::ZERO; P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1];
        fixed[..P256_ARITHMETIC_STARK_FIXED_WIDTH_V1].copy_from_slice(&self.fixed.row_v1(row)?);
        for (slot, event) in arithmetic_scalar_events_v1(row)?.into_iter().enumerate() {
            let start = ARITHMETIC_SCALAR_FIXED + slot * SCALAR_EVENT_FIXED_WIDTH;
            encode_scalar_event_v1(event, &mut fixed[start..start + SCALAR_EVENT_FIXED_WIDTH]);
        }
        encode_boundary_v1(
            P256CrossTraceBoundaryFixedV1::for_row(row, P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1)?,
            &mut fixed
                [ARITHMETIC_BOUNDARY_FIXED..ARITHMETIC_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
        );
        for (slot, event) in arithmetic_value_copy_events_v1(
            row,
            P256_ARITHMETIC_OPERATIONS_V1 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
        )?
        .into_iter()
        .enumerate()
        {
            let start = ARITHMETIC_VALUE_COPY_FIXED + slot * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
            encode_arithmetic_copy_event_v1(
                event,
                &mut fixed[start..start + ARITHMETIC_COPY_EVENT_FIXED_WIDTH],
            );
        }
        encode_boundary_v1(
            P256CrossTraceBoundaryFixedV1::for_row(row, P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1)?,
            &mut fixed[ARITHMETIC_VALUE_COPY_BOUNDARY_FIXED..],
        );
        Ok(fixed)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn fill_fixed_column_v1(
        &self,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        fill_aggregate_row_column_v1(
            P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            column,
            output,
            |row| self.row_v1(row),
        )
    }
}
fn p256_main_window_fixed_row_v1(
    provider: P256WindowBatchStarkFixedProviderV1,
    row: usize,
) -> Result<[F; P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
    let mut fixed = [F::ZERO; P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1];
    fixed[..P256_WINDOW_STARK_FIXED_WIDTH_V1].copy_from_slice(&provider.row_v1(row)?);
    for (slot, event) in window_cross_events_v1(row)?.into_iter().enumerate() {
        let start = WINDOW_CROSS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
        encode_cross_event_v1(event, &mut fixed[start..start + CROSS_EVENT_FIXED_WIDTH]);
    }
    encode_scalar_event_v1(
        window_scalar_event_v1(row)?,
        &mut fixed[WINDOW_SCALAR_FIXED..WINDOW_SCALAR_FIXED + SCALAR_EVENT_FIXED_WIDTH],
    );
    let local = row % P256_WINDOW_STARK_TRACE_SIZE_V1;
    if row < P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1 && local < 4 {
        fixed[WINDOW_SCALAR_BIT_SELECTORS_FIXED + local] = F::ONE;
    }
    encode_boundary_v1(
        P256CrossTraceBoundaryFixedV1::for_row(row, P256_WINDOW_AGGREGATE_TRACE_SIZE_V1)?,
        &mut fixed[WINDOW_BOUNDARY_FIXED..WINDOW_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    Ok(fixed)
}
fn p256_main_reduction_fixed_row_v1(
    provider: P256ComparisonStarkFixedProviderV1,
    role: P256ReductionAggregateRoleV1,
    row: usize,
) -> Result<[F; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
    let mut fixed = [F::ZERO; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1];
    fixed[..P256_REDUCTION_STARK_FIXED_WIDTH_V1].copy_from_slice(&provider.row_v1(row)?);
    for (slot, event) in reduction_cross_events_v1(role, row)?
        .into_iter()
        .enumerate()
    {
        let start = REDUCTION_CROSS_FIXED + slot * CROSS_EVENT_FIXED_WIDTH;
        encode_cross_event_v1(event, &mut fixed[start..start + CROSS_EVENT_FIXED_WIDTH]);
    }
    encode_boundary_v1(
        P256CrossTraceBoundaryFixedV1::for_row(row, P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1)?,
        &mut fixed[REDUCTION_BOUNDARY_FIXED..REDUCTION_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    Ok(fixed)
}
fn p256_main_low_s_fixed_row_v1(
    provider: P256ComparisonStarkFixedProviderV1,
    row: usize,
) -> Result<[F; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1], P256AggregateAdapterErrorV1> {
    let mut fixed = [F::ZERO; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1];
    fixed[..P256_LOW_S_STARK_FIXED_WIDTH_V1].copy_from_slice(&provider.row_v1(row)?);
    encode_cross_event_v1(
        low_s_cross_event_v1(row)?,
        &mut fixed[LOW_S_CROSS_FIXED..LOW_S_BOUNDARY_FIXED],
    );
    encode_boundary_v1(
        P256CrossTraceBoundaryFixedV1::for_row(row, P256_LOW_S_AGGREGATE_TRACE_SIZE_V1)?,
        &mut fixed[LOW_S_BOUNDARY_FIXED..LOW_S_BOUNDARY_FIXED + CROSS_BOUNDARY_FIXED_WIDTH],
    );
    Ok(fixed)
}
fn p256_main_value_fixed_source_v1(
    role: P256EcdsaRoleV1,
    endpoint: P256ValueBusStarkEndpointV1,
) -> Result<P256ValueBusStarkFixedProviderV1, P256AggregateAdapterErrorV1> {
    let topology = verifier_topology_v1(role)?;
    Ok(P256ValueBusStarkFixedProviderV1::new_v1(
        endpoint,
        &topology.initial_values,
        &topology.linked_operations,
        &topology.equalities,
        &topology.boolean_bridges,
        P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
    )?)
}
/// Borrow the admitted public matrix without allocating another field owner.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256PublicArithmeticFixedDestinationV1<'a> {
    columns: &'a mut [Vec<F>],
    committed: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256PublicArithmeticFixedDestinationV1<'_> {
    fn drop(&mut self) {
        if !self.committed {
            for column in &mut *self.columns {
                super::private_table::zeroize_fields_v1(column);
            }
        }
    }
}
/// Fill only a complete public arithmetic fixed matrix, with one row per call.
/// The private replay helpers retain their independent eight-column limit.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fill_public_arithmetic_fixed_matrix_with_v1(
    rows: usize,
    columns: &mut [Vec<F>],
    mut fixed_row: impl FnMut(
        usize,
    ) -> Result<
        [F; P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1],
        P256AggregateAdapterErrorV1,
    >,
) -> Result<(), P256AggregateAdapterErrorV1> {
    if !rows.is_power_of_two()
        || columns.len() != P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1
        || columns.iter().any(|column| column.len() != rows)
    {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut destination = P256PublicArithmeticFixedDestinationV1 {
        columns,
        committed: false,
    };
    for row in 0..rows {
        let values = P256AggregateAuxRowScratchV1(fixed_row(row)?);
        for (column, &value) in destination.columns.iter_mut().zip(&values.0) {
            column[row] = value;
        }
    }
    destination.committed = true;
    Ok(())
}
/// Closed verifier-only fixed preprocessing for every canonical P-256 MAIN registration.
///
/// Construction depends solely on native verifier topology. It accepts no witness rows, proof
/// metadata, roles, optional-selection flags, or challenges. The global signature position derives
/// both the role and the sole optional-certificate sink at signature two.
#[derive(Clone, Debug)]
pub struct P256MainVerifierFixedSourceV1 {
    certificate_execution: P256ValueExecutionAggregateFixedProviderV1,
    certificate_sorted: P256ValueBusStarkFixedProviderV1,
    certificate_arithmetic: P256MainArithmeticFixedSourceV1,
    wallet_execution: P256ValueExecutionAggregateFixedProviderV1,
    wallet_sorted: P256ValueBusStarkFixedProviderV1,
    wallet_arithmetic: P256MainArithmeticFixedSourceV1,
    window: P256WindowBatchStarkFixedProviderV1,
    reduction: P256ComparisonStarkFixedProviderV1,
    low_s: P256ComparisonStarkFixedProviderV1,
    certificate_sink: P256BindingSinkFixedProviderV1,
    optional_certificate_sink: P256BindingSinkFixedProviderV1,
    wallet_sink: P256BindingSinkFixedProviderV1,
    scalar: super::p256_scalar_bit_bus::P256ScalarBitBusStarkFixedProviderV1,
}
impl P256MainVerifierFixedSourceV1 {
    /// Allocated schedules shared by the five native signature sources.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn allocated_heap_bytes_v1(&self) -> usize {
        use super::allocation_payload::sum_v1;
        sum_v1([
            self.certificate_execution.value.allocated_heap_bytes_v1(),
            self.certificate_execution.writer.allocated_heap_bytes_v1(),
            self.certificate_sorted.allocated_heap_bytes_v1(),
            self.certificate_arithmetic.fixed.allocated_heap_bytes_v1(),
            self.wallet_execution.value.allocated_heap_bytes_v1(),
            self.wallet_execution.writer.allocated_heap_bytes_v1(),
            self.wallet_sorted.allocated_heap_bytes_v1(),
            self.wallet_arithmetic.fixed.allocated_heap_bytes_v1(),
            self.certificate_sink.fixed.allocated_heap_bytes_v1(),
            self.optional_certificate_sink
                .fixed
                .allocated_heap_bytes_v1(),
            self.wallet_sink.fixed.allocated_heap_bytes_v1(),
        ])
    }
    /// Compile all verifier-owned schedules once.
    pub(crate) fn new_v1() -> Result<Self, P256AggregateAdapterErrorV1> {
        Ok(Self {
            certificate_execution: P256ValueExecutionAggregateFixedProviderV1::new_v1(
                P256EcdsaRoleV1::CertificateOrCrl,
            )?,
            certificate_sorted: p256_main_value_fixed_source_v1(
                P256EcdsaRoleV1::CertificateOrCrl,
                P256ValueBusStarkEndpointV1::Sorted,
            )?,
            certificate_arithmetic: P256MainArithmeticFixedSourceV1::new_v1(
                P256EcdsaRoleV1::CertificateOrCrl,
            )?,
            wallet_execution: P256ValueExecutionAggregateFixedProviderV1::new_v1(
                P256EcdsaRoleV1::WalletOwnership,
            )?,
            wallet_sorted: p256_main_value_fixed_source_v1(
                P256EcdsaRoleV1::WalletOwnership,
                P256ValueBusStarkEndpointV1::Sorted,
            )?,
            wallet_arithmetic: P256MainArithmeticFixedSourceV1::new_v1(
                P256EcdsaRoleV1::WalletOwnership,
            )?,
            window: P256WindowBatchStarkFixedProviderV1::new_v1(
                P256_WINDOW_AGGREGATE_TRACE_SIZE_V1,
            )?,
            reduction: P256ComparisonStarkFixedProviderV1::reduction_v1(
                P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
            )?,
            low_s: P256ComparisonStarkFixedProviderV1::low_s_v1(
                P256_LOW_S_AGGREGATE_TRACE_SIZE_V1,
            )?,
            certificate_sink: P256BindingSinkFixedProviderV1::new_v1(
                P256EcdsaRoleV1::CertificateOrCrl,
            )?,
            optional_certificate_sink:
                P256BindingSinkFixedProviderV1::new_with_optional_certificate_v1(
                    P256EcdsaRoleV1::CertificateOrCrl,
                    true,
                )?,
            wallet_sink: P256BindingSinkFixedProviderV1::new_v1(P256EcdsaRoleV1::WalletOwnership)?,
            scalar: super::p256_scalar_bit_bus::P256ScalarBitBusStarkFixedProviderV1::new_v1(
                P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_SIZE_V1,
            )?,
        })
    }
    fn execution_v1(&self, role: P256EcdsaRoleV1) -> &P256ValueExecutionAggregateFixedProviderV1 {
        match role {
            P256EcdsaRoleV1::CertificateOrCrl => &self.certificate_execution,
            P256EcdsaRoleV1::WalletOwnership => &self.wallet_execution,
        }
    }
    fn sorted_v1(&self, role: P256EcdsaRoleV1) -> &P256ValueBusStarkFixedProviderV1 {
        match role {
            P256EcdsaRoleV1::CertificateOrCrl => &self.certificate_sorted,
            P256EcdsaRoleV1::WalletOwnership => &self.wallet_sorted,
        }
    }
    fn arithmetic_v1(&self, role: P256EcdsaRoleV1) -> &P256MainArithmeticFixedSourceV1 {
        match role {
            P256EcdsaRoleV1::CertificateOrCrl => &self.certificate_arithmetic,
            P256EcdsaRoleV1::WalletOwnership => &self.wallet_arithmetic,
        }
    }
    fn sink_v1(&self, registration: P256MainRegistrationV1) -> &P256BindingSinkFixedProviderV1 {
        if registration.signature_v1() == 2 {
            &self.optional_certificate_sink
        } else {
            match registration.role_v1() {
                P256EcdsaRoleV1::CertificateOrCrl => &self.certificate_sink,
                P256EcdsaRoleV1::WalletOwnership => &self.wallet_sink,
            }
        }
    }
    /// Regenerate one verifier-owned fixed row for a canonical registration.
    pub(crate) fn fixed_row_v1(
        &self,
        registration: P256MainRegistrationV1,
        row: usize,
    ) -> Result<Vec<F>, P256AggregateAdapterErrorV1> {
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::ValueBus, 0) => {
                p256_main_owned_fixed_row_v1(self.execution_v1(registration.role_v1()).row_v1(row)?)
            }
            (P256MainAdapterV1::ValueBus, 1) => {
                p256_main_owned_fixed_row_v1(self.sorted_v1(registration.role_v1()).row_v1(row)?)
            }
            (P256MainAdapterV1::Arithmetic, 0) => p256_main_owned_fixed_row_v1(
                self.arithmetic_v1(registration.role_v1()).row_v1(row)?,
            ),
            (P256MainAdapterV1::WindowBatch, 0) => {
                p256_main_owned_fixed_row_v1(p256_main_window_fixed_row_v1(self.window, row)?)
            }
            (P256MainAdapterV1::Reduction, local @ 0..=1) => {
                p256_main_owned_fixed_row_v1(p256_main_reduction_fixed_row_v1(
                    self.reduction,
                    if local == 0 {
                        P256ReductionAggregateRoleV1::Digest
                    } else {
                        P256ReductionAggregateRoleV1::ResultX
                    },
                    row,
                )?)
            }
            (P256MainAdapterV1::WalletLowS, 0) => {
                p256_main_owned_fixed_row_v1(p256_main_low_s_fixed_row_v1(self.low_s, row)?)
            }
            (P256MainAdapterV1::BindingSink, 0) => {
                p256_main_owned_fixed_row_v1(self.sink_v1(registration).row_v1(row)?)
            }
            (P256MainAdapterV1::ScalarBitBus, 0) => {
                p256_main_owned_fixed_row_v1(self.scalar.fixed_row_v1(row)?)
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Regenerate one verifier-owned fixed cell without any proof input.
    #[cfg(test)]
    pub(crate) fn fixed_cell_v1(
        &self,
        registration: P256MainRegistrationV1,
        row: usize,
        column: usize,
    ) -> Result<F, P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if row >= shape.trace_size || column >= shape.fixed_width {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        self.fixed_row_v1(registration, row)?
            .get(column)
            .copied()
            .ok_or(P256AggregateAdapterErrorV1::Topology)
    }
    /// Fill the already admitted public arithmetic matrix with one canonical
    /// row pass. The only scratch is one clearing stack row; the existing
    /// column allocations stay with the caller on success, error and unwind.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn fill_arithmetic_fixed_matrix_v1(
        &self,
        registration: P256MainRegistrationV1,
        columns: &mut [Vec<F>],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        if P256MainRegistrationV1::new_v1(
            registration.signature_v1(),
            P256MainAdapterV1::Arithmetic,
            0,
        )? != registration
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let fixed = self.arithmetic_v1(registration.role_v1());
        fill_public_arithmetic_fixed_matrix_with_v1(
            P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            columns,
            |row| fixed.row_v1(row),
        )
    }
    /// Independent eight-column replay oracle for the public matrix fill.
    #[cfg(test)]
    pub(crate) fn fill_arithmetic_fixed_columns_v1(
        &self,
        registration: P256MainRegistrationV1,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        if registration.adapter_v1() != P256MainAdapterV1::Arithmetic
            || registration.local_instance_v1() != 0
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let fixed = self.arithmetic_v1(registration.role_v1());
        let mut row = 0;
        fill_aggregate_aux_columns_v1::<P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1>(
            P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            first,
            outputs,
            || {
                if row == P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
                    return Ok(None);
                }
                let values = fixed.row_v1(row)?;
                row += 1;
                Ok(Some(values))
            },
        )
    }
    /// Replay one complete verifier-owned fixed column transactionally.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn fill_fixed_column_v1(
        &self,
        registration: P256MainRegistrationV1,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if column >= shape.fixed_width || output.len() != shape.trace_size {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::ValueBus, 0) => self
                .execution_v1(registration.role_v1())
                .fill_fixed_column_v1(column, output),
            (P256MainAdapterV1::ValueBus, 1) => {
                let fixed = self.sorted_v1(registration.role_v1());
                fill_aggregate_row_column_v1::<P256_VALUE_BUS_STARK_FIXED_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| Ok(fixed.row_v1(row)?),
                )
            }
            (P256MainAdapterV1::Arithmetic, 0) => self
                .arithmetic_v1(registration.role_v1())
                .fill_fixed_column_v1(column, output),
            (P256MainAdapterV1::WindowBatch, 0) => {
                fill_aggregate_row_column_v1::<P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| p256_main_window_fixed_row_v1(self.window, row),
                )
            }
            (P256MainAdapterV1::Reduction, local @ 0..=1) => {
                fill_aggregate_row_column_v1::<P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| {
                        p256_main_reduction_fixed_row_v1(
                            self.reduction,
                            if local == 0 {
                                P256ReductionAggregateRoleV1::Digest
                            } else {
                                P256ReductionAggregateRoleV1::ResultX
                            },
                            row,
                        )
                    },
                )
            }
            (P256MainAdapterV1::WalletLowS, 0) => {
                fill_aggregate_row_column_v1::<P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| p256_main_low_s_fixed_row_v1(self.low_s, row),
                )
            }
            (P256MainAdapterV1::BindingSink, 0) => self
                .sink_v1(registration)
                .fill_fixed_column_v1(column, output),
            (P256MainAdapterV1::ScalarBitBus, 0) => self
                .scalar
                .fill_fixed_column_v1(column, output)
                .map_err(P256AggregateAdapterErrorV1::from),
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_main_arithmetic_trace_v1(trace: &mut ZkX509P256ArithmeticTraceV1) {
    super::private_table::zeroize_field_rows_v1(&mut trace.base);
    trace.base.clear();
    trace.fixed.clear();
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_main_window_batch_v1(trace: &mut P256WindowBatchStarkTraceV1) {
    super::private_table::zeroize_field_rows_v1(&mut trace.base);
    super::private_table::zeroize_field_rows_v1(&mut trace.aux);
    trace.base.clear();
    trace.aux.clear();
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainWindowInputGuardV1(Vec<P256WindowTraceV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainWindowInputGuardV1 {
    fn drop(&mut self) {
        for trace in &mut self.0 {
            trace.zeroize_private_v1();
        }
        self.0.clear();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainArithmeticGuardV1(Option<ZkX509P256ArithmeticTraceV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainArithmeticGuardV1 {
    fn as_ref_v1(&self) -> Result<&ZkX509P256ArithmeticTraceV1, P256AggregateAdapterErrorV1> {
        self.0.as_ref().ok_or(P256AggregateAdapterErrorV1::Source)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainArithmeticGuardV1 {
    fn drop(&mut self) {
        if let Some(trace) = self.0.as_mut() {
            zeroize_main_arithmetic_trace_v1(trace);
        }
        self.0 = None;
    }
}
/// Immutable checked raw capability, consumed after scalar-source construction.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256MainRawArithmeticV1 {
    role: P256EcdsaRoleV1,
    trace: P256MainArithmeticGuardV1,
    fixed: P256ArithmeticStarkFixedProviderV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainRawArithmeticV1 {
    fn new_v1(
        role: P256EcdsaRoleV1,
        trace: ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        let trace = P256MainArithmeticGuardV1(Some(trace));
        let fixed = P256ArithmeticAggregateRowsV1::new_v1(role, trace.as_ref_v1()?)?
            .fixed
            .into_owned();
        Ok(Self { role, trace, fixed })
    }
    /// Borrow the trace whose immutable owner established full constraints and role topology.
    pub(crate) fn validated_trace_v1(&self) -> &ZkX509P256ArithmeticTraceV1 {
        self.trace
            .0
            .as_ref()
            .expect("checked raw owner retains its trace")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
enum P256MainArithmeticStorageV1 {
    Compact(P256CompactArithmeticTraceV1),
    // Deliberately malformed allocation fixtures never enter a replay path.
    #[cfg(test)]
    AllocationFixture(P256MainArithmeticGuardV1),
}
/// Immutable lossless arithmetic capability established at the owned trace boundary.
///
/// MAIN retains compact cells and its verifier-fixed schedule. The checked raw
/// trace clears before the next signature is constructed; no mutable or cloning
/// API can change the validated operation records.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainValidatedArithmeticV1 {
    role: P256EcdsaRoleV1,
    trace: P256MainArithmeticStorageV1,
    fixed: P256ArithmeticStarkFixedProviderV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainValidatedArithmeticV1 {
    #[cfg(test)]
    fn new_v1(
        role: P256EcdsaRoleV1,
        trace: ZkX509P256ArithmeticTraceV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        Self::from_raw_v1(P256MainRawArithmeticV1::new_v1(role, trace)?)
    }
    fn from_raw_v1(raw: P256MainRawArithmeticV1) -> Result<Self, P256AggregateAdapterErrorV1> {
        let compact = P256CompactArithmeticTraceV1::from_validated_v1(
            &raw,
            P256CompactArithmeticTraceV1::payload_forecast_v1(P256_ARITHMETIC_OPERATIONS_V1)?,
        )?;
        let P256MainRawArithmeticV1 { role, trace, fixed } = raw;
        drop(trace); // clear the one raw construction matrix before retaining another signature
        Ok(Self {
            role,
            trace: P256MainArithmeticStorageV1::Compact(compact),
            fixed,
        })
    }
    fn rows_v1(
        &self,
        role: P256EcdsaRoleV1,
    ) -> Result<P256ArithmeticAggregateRowsV1<'_>, P256AggregateAdapterErrorV1> {
        if self.role != role {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let trace = match &self.trace {
            P256MainArithmeticStorageV1::Compact(trace) => {
                P256ArithmeticRowsStorageV1::Compact(trace)
            }
            #[cfg(test)]
            P256MainArithmeticStorageV1::AllocationFixture(_) => {
                return Err(P256AggregateAdapterErrorV1::Source);
            }
        };
        Ok(P256ArithmeticAggregateRowsV1 {
            trace,
            fixed: Cow::Borrowed(&self.fixed),
        })
    }
    fn allocated_heap_bytes_v1(&self) -> usize {
        let trace = match &self.trace {
            P256MainArithmeticStorageV1::Compact(trace) => trace.allocated_heap_bytes_v1(),
            #[cfg(test)]
            P256MainArithmeticStorageV1::AllocationFixture(trace) => {
                let trace = trace
                    .as_ref_v1()
                    .expect("allocation fixture retains its trace");
                super::allocation_payload::sum_v1([
                    super::allocation_payload::vector_v1(&trace.fixed),
                    super::allocation_payload::vector_v1(&trace.base),
                ])
            }
        };
        super::allocation_payload::sum_v1([trace, self.fixed.allocated_heap_bytes_v1()])
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainWindowBatchGuardV1(Option<P256WindowBatchStarkTraceV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainWindowBatchGuardV1 {
    fn as_ref_v1(&self) -> Result<&P256WindowBatchStarkTraceV1, P256AggregateAdapterErrorV1> {
        self.0.as_ref().ok_or(P256AggregateAdapterErrorV1::Source)
    }
    fn take_v1(&mut self) -> Result<P256WindowBatchStarkTraceV1, P256AggregateAdapterErrorV1> {
        self.0.take().ok_or(P256AggregateAdapterErrorV1::Source)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainWindowBatchGuardV1 {
    fn drop(&mut self) {
        if let Some(trace) = self.0.as_mut() {
            zeroize_main_window_batch_v1(trace);
        }
        self.0 = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainReductionGuardV1(Option<P256ReductionTraceV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainReductionGuardV1 {
    fn as_ref_v1(&self) -> Result<&P256ReductionTraceV1, P256AggregateAdapterErrorV1> {
        self.0.as_ref().ok_or(P256AggregateAdapterErrorV1::Source)
    }
    fn take_v1(&mut self) -> Result<P256ReductionTraceV1, P256AggregateAdapterErrorV1> {
        self.0.take().ok_or(P256AggregateAdapterErrorV1::Source)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainReductionGuardV1 {
    fn drop(&mut self) {
        if let Some(trace) = self.0.as_mut() {
            trace.zeroize_private_v1();
        }
        self.0 = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainLowSGuardV1(Option<P256LowSTraceV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainLowSGuardV1 {
    fn as_ref_v1(&self) -> Option<&P256LowSTraceV1> {
        self.0.as_ref()
    }
    fn take_v1(&mut self) -> Option<P256LowSTraceV1> {
        self.0.take()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainLowSGuardV1 {
    fn drop(&mut self) {
        if let Some(trace) = self.0.as_mut() {
            trace.zeroize_private_v1();
        }
        self.0 = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainSignatureBaseV1 {
    role: P256EcdsaRoleV1,
    value: Option<P256ValueBusBaseSourceV1>,
    scalar: Option<P256ScalarBitBusBaseSourceV1>,
    arithmetic: Option<P256MainValidatedArithmeticV1>,
    window: Option<P256WindowBatchStarkTraceV1>,
    digest_reduction: Option<P256ReductionTraceV1>,
    result_x_reduction: Option<P256ReductionTraceV1>,
    low_s: Option<P256LowSTraceV1>,
    sink: Option<P256ExternalBindingTraceV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256MainSignatureBaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256MainSignatureBaseV1")
            .field("role", &self.role)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainSignatureBaseV1 {
    fn new_v1(
        signature: usize,
        material: &P256EcdsaTraceMaterialV1,
        optional_selection: P256OptionalCertificateSelectionV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        let expected_role = if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            P256EcdsaRoleV1::CertificateOrCrl
        } else if signature == P256_X5S1_SIGNATURES_V1 - 1 {
            P256EcdsaRoleV1::WalletOwnership
        } else {
            return Err(P256AggregateAdapterErrorV1::Topology);
        };
        if material.role != expected_role {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let topology = verifier_topology_v1(expected_role)?;
        material
            .validate_topology_v1(&topology)
            .map_err(|error| match error {
                P256TraceCompilerErrorV1::Resource => P256AggregateAdapterErrorV1::Resource,
                _ => P256AggregateAdapterErrorV1::Topology,
            })?;
        if material.reductions.len() != 2
            || (expected_role == P256EcdsaRoleV1::CertificateOrCrl && !material.low_s.is_empty())
            || (expected_role == P256EcdsaRoleV1::WalletOwnership && material.low_s.len() != 1)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let value = P256ValueBusBaseSourceV1::new_v1(material)
            .map_err(P256AggregateAdapterErrorV1::from)?;
        if value.role_v1().map_err(P256AggregateAdapterErrorV1::from)? != expected_role {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let mut sink = build_zk_x509_p256_external_binding_trace_v1(material, &value)
            .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
        if signature == 2 {
            sink.bind_optional_certificate_selection_v1(
                optional_selection,
                material,
                value
                    .execution_endpoint_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?,
            )
            .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
        }
        let arithmetic = P256MainRawArithmeticV1::new_v1(
            expected_role,
            material
                .build_arithmetic_trace_v1()
                .map_err(P256AggregateAdapterErrorV1::from)?,
        )?;
        let mut window_inputs = Vec::new();
        window_inputs
            .try_reserve_exact(material.windows.len())
            .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
        for window in &material.windows {
            window_inputs.push(window.trace.clone());
        }
        let window_inputs = P256MainWindowInputGuardV1(window_inputs);
        let scalar =
            P256ScalarBitBusBaseSourceV1::new_v1(&window_inputs.0, arithmetic.validated_trace_v1())
                .map_err(P256AggregateAdapterErrorV1::from)?;
        let arithmetic = P256MainValidatedArithmeticV1::from_raw_v1(arithmetic)?;
        let mut window = P256MainWindowBatchGuardV1(Some(
            build_p256_window_batch_stark_trace_v1(&window_inputs.0)
                .map_err(P256AggregateAdapterErrorV1::from)?,
        ));
        P256WindowAggregateRowsV1::new_v1(window.as_ref_v1()?)?;
        let mut digest_reduction =
            P256MainReductionGuardV1(Some(material.reductions[0].trace.clone()));
        let mut result_x_reduction =
            P256MainReductionGuardV1(Some(material.reductions[1].trace.clone()));
        P256ReductionAggregateRowsV1::new_v1(
            P256ReductionAggregateRoleV1::Digest,
            digest_reduction.as_ref_v1()?,
        )?;
        P256ReductionAggregateRowsV1::new_v1(
            P256ReductionAggregateRoleV1::ResultX,
            result_x_reduction.as_ref_v1()?,
        )?;
        let mut low_s =
            P256MainLowSGuardV1(material.low_s.first().map(|binding| binding.trace.clone()));
        if let Some(low_s) = low_s.as_ref_v1() {
            P256LowSAggregateRowsV1::new_v1(expected_role, low_s)?;
        }
        P256BindingSinkRowsV1::new_v1(&sink)?;
        let mut source = Self {
            role: expected_role,
            value: None,
            scalar: None,
            arithmetic: None,
            window: None,
            digest_reduction: None,
            result_x_reduction: None,
            low_s: None,
            sink: None,
        };
        source.value = Some(value);
        source.scalar = Some(scalar);
        source.sink = Some(sink);
        source.arithmetic = Some(arithmetic);
        source.window = Some(window.take_v1()?);
        source.digest_reduction = Some(digest_reduction.take_v1()?);
        source.result_x_reduction = Some(result_x_reduction.take_v1()?);
        source.low_s = low_s.take_v1();
        Ok(source)
    }
    fn zeroize_private_v1(&mut self) {
        if let Some(value) = self.value.as_mut() {
            value.zeroize_private_v1();
        }
        self.value = None;
        if let Some(scalar) = self.scalar.as_mut() {
            scalar.zeroize_private_v1();
        }
        self.scalar = None;
        // Dropping the immutable capability clears its owned private trace.
        self.arithmetic = None;
        if let Some(window) = self.window.as_mut() {
            zeroize_main_window_batch_v1(window);
        }
        self.window = None;
        if let Some(reduction) = self.digest_reduction.as_mut() {
            reduction.zeroize_private_v1();
        }
        self.digest_reduction = None;
        if let Some(reduction) = self.result_x_reduction.as_mut() {
            reduction.zeroize_private_v1();
        }
        self.result_x_reduction = None;
        if let Some(low_s) = self.low_s.as_mut() {
            low_s.zeroize_private_v1();
        }
        self.low_s = None;
        if let Some(sink) = self.sink.as_mut() {
            sink.zeroize_private_v1();
        }
        self.sink = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainSignatureBaseV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// Pre-X5B1 capability for the exact five-signature P-256 MAIN set.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256MainBaseSourceV1 {
    // Keep the reserved exact-five owner on the heap across phase transitions.
    // An inline array duplicates the embedded reduction traces in debug frames.
    signatures: Option<ClearingVecV1<P256MainSignatureBaseV1>>,
    fixed: Option<P256MainVerifierFixedSourceV1>,
    bind_attempted: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256MainBaseSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256MainBaseSourceV1")
            .field("bind_attempted", &self.bind_attempted)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainBaseSourceV1 {
    /// Forecast the largest serial native source construction before allocating it.
    pub(crate) fn replay_scratch_forecast_v1() -> Result<usize, P256AggregateAdapterErrorV1> {
        let certificate = super::p256_value_bus::p256_value_source_scratch_forecast_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
        )?;
        let wallet = super::p256_value_bus::p256_value_source_scratch_forecast_v1(
            P256EcdsaRoleV1::WalletOwnership,
        )?;
        use super::allocation_payload::{p256_topology_v1, sum_v1, vector_v1};
        let mut validation_scratch = 0;
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let topology = verifier_topology_v1(role)?;
            let operations = topology
                .linked_operations
                .iter()
                .map(|operation| ZkX509P256ArithmeticTopologyV1 {
                    kind: operation.kind,
                    modulus: operation.modulus,
                })
                .collect::<Vec<_>>();
            let fixed = P256ArithmeticStarkFixedProviderV1::new_v1(
                &operations,
                P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            )?;
            // Outer signature topology and checked-constructor topology coexist
            // with the collected operations and the newly retained provider.
            // Charging that provider here as well is conservative during transfer.
            validation_scratch = validation_scratch.max(sum_v1([
                2 * p256_topology_v1(&topology),
                vector_v1(&operations),
                fixed.allocated_heap_bytes_v1(),
            ]));
        }
        let value_replay = certificate
            .max(wallet)
            .checked_add(p256_value_aux_replay_scratch_v1())
            .ok_or(P256AggregateAdapterErrorV1::Resource)?;
        Ok(value_replay
            .max(validation_scratch)
            .max(p256_arithmetic_aux_replay_scratch_v1())
            .max(p256_base_replay_scratch_v1()))
    }
    /// Predict the complete canonical five-signature source before private allocations.
    ///
    /// The compact verifier schedules are measured using their actual capacities;
    /// private matrices use the exact reserve sizes in their canonical builders.
    pub(crate) fn allocation_forecast_v1() -> Result<usize, P256AggregateAdapterErrorV1> {
        use super::allocation_payload::sum_v1;
        use super::p256_value_bus::p256_value_source_allocation_forecast_v1;
        use core::mem::size_of;
        let fixed = P256MainVerifierFixedSourceV1::new_v1()?;
        let signatures = [P256EcdsaRoleV1::CertificateOrCrl; 4]
            .into_iter()
            .chain([P256EcdsaRoleV1::WalletOwnership]);
        let mut total = sum_v1([
            size_of::<Self>().max(size_of::<P256MainBoundSourceV1>()),
            // Both reserved owner vectors coexist until the single-use bind
            // has transferred or cleared every signature. Their child matrices
            // move between owners and are counted only once below.
            P256_X5S1_SIGNATURES_V1 * size_of::<P256MainSignatureBaseV1>(),
            P256_X5S1_SIGNATURES_V1 * size_of::<P256MainSignatureBoundV1>(),
            fixed.allocated_heap_bytes_v1(),
        ]);
        // All compact owners may coexist with the one current raw constructor.
        // Retain this conservative charge through later phases; it is not reusable credit.
        let raw_rows = P256_ARITHMETIC_OPERATIONS_V1 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        total = sum_v1([
            total,
            raw_rows
                * (size_of::<[F; P256_ARITHMETIC_BASE_WIDTH_V1]>()
                    + size_of::<super::p256_air::ZkX509P256ArithmeticFixedRowV1>()),
        ]);
        for role in signatures {
            let value = p256_value_source_allocation_forecast_v1(role)?;
            let arithmetic =
                P256CompactArithmeticTraceV1::payload_forecast_v1(P256_ARITHMETIC_OPERATIONS_V1)?;
            let window = P256_WINDOW_BATCH_STARK_TRACE_SIZE_V1
                * (size_of::<[F; P256_WINDOW_BASE_WIDTH_V1]>()
                    + size_of::<[F; P256_WINDOW_STARK_AUX_WIDTH_V1]>());
            let scalar = P256_SCALAR_BIT_BUS_STARK_TRACE_SIZE_V1
                * size_of::<[F; P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1]>();
            let sink = super::p256_external_binding_air::p256_external_binding_rows_v1(role)
                * size_of::<super::p256_external_binding_air::P256ExternalBindingRowV1>();
            total = sum_v1([
                total,
                value,
                arithmetic,
                window,
                scalar,
                sink,
                // One immutable validated schedule per signature, moved intact
                // between the coexisting base and bound owner allocations.
                fixed.arithmetic_v1(role).fixed.allocated_heap_bytes_v1(),
            ]);
        }
        Ok(total)
    }
    /// Reachable native source payload, excluding the separately borrowed assembly.
    pub(crate) fn allocated_payload_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            core::mem::size_of_val(self),
            self.fixed
                .as_ref()
                .map_or(0, P256MainVerifierFixedSourceV1::allocated_heap_bytes_v1),
            self.signatures
                .as_ref()
                .map_or(0, ClearingVecV1::allocated_bytes_v1),
            self.signatures.as_ref().map_or(0, |signatures| {
                sum_v1(signatures.iter().map(|signature| {
                    sum_v1([
                        signature
                            .value
                            .as_ref()
                            .map_or(0, |value| value.allocated_heap_bytes_v1()),
                        signature
                            .scalar
                            .as_ref()
                            .map_or(0, |scalar| scalar.allocated_heap_bytes_v1()),
                        signature
                            .arithmetic
                            .as_ref()
                            .map_or(0, P256MainValidatedArithmeticV1::allocated_heap_bytes_v1),
                        signature.window.as_ref().map_or(0, |trace| {
                            sum_v1([vector_v1(&trace.base), vector_v1(&trace.aux)])
                        }),
                        signature
                            .sink
                            .as_ref()
                            .map_or(0, |trace| vector_v1(&trace.rows)),
                    ])
                }))
            }),
        ])
    }
    /// Compile all five role-positioned signatures from the canonical MAIN
    /// assembly before any P-256 base commitment is exposed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn new_v1(
        assembly: &ZkX509MainTraceAssemblyV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        Self::from_materials_v1(
            &assembly.p256_materials,
            assembly.optional_certificate_selection,
        )
    }
    fn from_materials_v1(
        materials: &[P256EcdsaTraceMaterialV1; P256_X5S1_SIGNATURES_V1],
        optional_selection: P256OptionalCertificateSelectionV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        for (signature, material) in materials.iter().enumerate() {
            let expected = if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
                P256EcdsaRoleV1::CertificateOrCrl
            } else {
                P256EcdsaRoleV1::WalletOwnership
            };
            if material.role != expected {
                return Err(P256AggregateAdapterErrorV1::Topology);
            }
            material
                .validate_topology_v1(&verifier_topology_v1(expected)?)
                .map_err(|error| match error {
                    P256TraceCompilerErrorV1::Resource => P256AggregateAdapterErrorV1::Resource,
                    _ => P256AggregateAdapterErrorV1::Topology,
                })?;
        }
        let mut signatures = ClearingVecV1::try_with_capacity_v1(P256_X5S1_SIGNATURES_V1)
            .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
        for (signature, material) in materials.iter().enumerate() {
            signatures
                .try_push_v1(P256MainSignatureBaseV1::new_v1(
                    signature,
                    material,
                    optional_selection,
                )?)
                .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
        }
        Ok(Self {
            signatures: Some(signatures),
            fixed: Some(P256MainVerifierFixedSourceV1::new_v1()?),
            bind_attempted: false,
        })
    }
    #[cfg(test)]
    fn from_materials_for_test_v1(
        materials: &[P256EcdsaTraceMaterialV1; P256_X5S1_SIGNATURES_V1],
        optional_selection: P256OptionalCertificateSelectionV1,
    ) -> Result<Self, P256AggregateAdapterErrorV1> {
        Self::from_materials_v1(materials, optional_selection)
    }
    fn ensure_base_phase_v1(&self) -> Result<(), P256AggregateAdapterErrorV1> {
        if self.bind_attempted
            || self
                .signatures
                .as_ref()
                .is_none_or(|signatures| signatures.len() != P256_X5S1_SIGNATURES_V1)
            || self.fixed.is_none()
        {
            Err(P256AggregateAdapterErrorV1::Phase)
        } else {
            Ok(())
        }
    }
    fn signature_v1(
        &self,
        registration: P256MainRegistrationV1,
    ) -> Result<&P256MainSignatureBaseV1, P256AggregateAdapterErrorV1> {
        self.ensure_base_phase_v1()?;
        self.signatures
            .as_ref()
            .and_then(|signatures| signatures.get(registration.signature_v1()))
            .filter(|signature| signature.role == registration.role_v1())
            .ok_or(P256AggregateAdapterErrorV1::Topology)
    }
    /// Sole verifier-owned registration order for all five signatures.
    pub(crate) fn canonical_registrations_v1(
        &self,
    ) -> Result<Vec<P256MainRegistrationV1>, P256AggregateAdapterErrorV1> {
        self.ensure_base_phase_v1()?;
        canonical_p256_main_registrations_v1()
    }
    /// Replay up to eight adjacent arithmetic or execution/sorted value base
    /// columns. The immutable phase owner and exact registration remain the
    /// authority; all columns share one canonical row pass and clearing guard.
    pub(crate) fn fill_base_columns_v1(
        &self,
        registration: P256MainRegistrationV1,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if !matches!(
            (registration.adapter_v1(), registration.local_instance_v1()),
            (P256MainAdapterV1::Arithmetic, 0) | (P256MainAdapterV1::ValueBus, 0 | 1)
        ) || outputs.is_empty()
            || outputs.len()
                > crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || first
                .checked_add(outputs.len())
                .is_none_or(|end| end > shape.base_width)
            || outputs
                .iter()
                .any(|output| output.len() != shape.trace_size)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::Arithmetic, 0) => {
                let rows = signature
                    .arithmetic
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .rows_v1(signature.role)?;
                rows.fill_base_columns_v1(first, outputs)
            }
            (P256MainAdapterV1::ValueBus, local @ 0..=1) => {
                let value = signature
                    .value
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Source)?;
                let endpoint = if local == 0 {
                    P256ValueBusStarkEndpointV1::Execution
                } else {
                    P256ValueBusStarkEndpointV1::Sorted
                };
                fill_aggregate_base_columns_v1::<P256_VALUE_BUS_STARK_BASE_WIDTH_V1>(
                    shape.trace_size,
                    first,
                    outputs,
                    |row| Ok(value.base_row_v1(endpoint, row)?),
                )
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Replay one complete challenge-independent committed column.
    pub(crate) fn fill_base_column_v1(
        &self,
        registration: P256MainRegistrationV1,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if column >= shape.base_width || output.len() != shape.trace_size {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::ValueBus, local @ 0..=1) => {
                let endpoint = if local == 0 {
                    P256ValueBusStarkEndpointV1::Execution
                } else {
                    P256ValueBusStarkEndpointV1::Sorted
                };
                let value = signature
                    .value
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Source)?;
                fill_aggregate_row_column_v1::<P256_VALUE_BUS_STARK_BASE_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| Ok(value.base_row_v1(endpoint, row)?),
                )
            }
            (P256MainAdapterV1::Arithmetic, 0) => signature
                .arithmetic
                .as_ref()
                .ok_or(P256AggregateAdapterErrorV1::Source)?
                .rows_v1(signature.role)?
                .fill_base_column_v1(column, output),
            (P256MainAdapterV1::WindowBatch, 0) => P256WindowAggregateRowsV1::new_v1(
                signature
                    .window
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Source)?,
            )?
            .fill_base_column_v1(column, output),
            (P256MainAdapterV1::Reduction, local @ 0..=1) => {
                let trace = if local == 0 {
                    signature.digest_reduction.as_ref()
                } else {
                    signature.result_x_reduction.as_ref()
                }
                .ok_or(P256AggregateAdapterErrorV1::Source)?;
                P256ReductionAggregateRowsV1::new_v1(
                    if local == 0 {
                        P256ReductionAggregateRoleV1::Digest
                    } else {
                        P256ReductionAggregateRoleV1::ResultX
                    },
                    trace,
                )?
                .fill_base_column_v1(column, output)
            }
            (P256MainAdapterV1::WalletLowS, 0) => P256LowSAggregateRowsV1::new_v1(
                signature.role,
                signature
                    .low_s
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Source)?,
            )?
            .fill_base_column_v1(column, output),
            (P256MainAdapterV1::BindingSink, 0) => P256BindingSinkRowsV1::new_v1(
                signature
                    .sink
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Source)?,
            )?
            .fill_base_column_v1(column, output),
            (P256MainAdapterV1::ScalarBitBus, 0) => {
                let rows = signature
                    .scalar
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Source)?
                    .base_rows_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?;
                fill_aggregate_row_column_v1::<P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| Ok(rows.base_row_v1(row)?),
                )
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Replay one complete verifier-preprocessed column.
    #[cfg(test)]
    pub(crate) fn fill_fixed_column_v1(
        &self,
        registration: P256MainRegistrationV1,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if column >= shape.fixed_width || output.len() != shape.trace_size {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        self.ensure_base_phase_v1()?;
        self.fixed
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?
            .fill_fixed_column_v1(registration, column, output)
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        if let Some(signatures) = self.signatures.as_mut() {
            for signature in signatures.iter_mut() {
                signature.zeroize_private_v1();
            }
        }
        self.signatures = None;
        self.fixed = None;
        self.bind_attempted = true;
    }
    #[cfg(test)]
    fn poison_scalar_for_test_v1(
        &mut self,
        signature: usize,
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.ensure_base_phase_v1()?;
        self.signatures
            .as_mut()
            .and_then(|signatures| signatures.get_mut(signature))
            .and_then(|signature| signature.scalar.as_mut())
            .ok_or(P256AggregateAdapterErrorV1::Topology)?
            .zeroize_private_v1();
        Ok(())
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.signatures.is_none() && self.fixed.is_none() && self.bind_attempted
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainBaseSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainSignatureBoundV1 {
    role: P256EcdsaRoleV1,
    value: Option<P256ValueBusBoundSourceV1>,
    scalar: Option<P256ScalarBitBusBoundSourceV1>,
    arithmetic: Option<P256MainValidatedArithmeticV1>,
    window: Option<P256WindowBatchStarkTraceV1>,
    digest_reduction: Option<P256ReductionTraceV1>,
    result_x_reduction: Option<P256ReductionTraceV1>,
    low_s: Option<P256LowSTraceV1>,
    sink: Option<P256ExternalBindingTraceV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256MainSignatureBoundV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256MainSignatureBoundV1")
            .field("role", &self.role)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainSignatureBoundV1 {
    fn zeroize_private_v1(&mut self) {
        if let Some(value) = self.value.as_mut() {
            value.zeroize_private_v1();
        }
        self.value = None;
        if let Some(scalar) = self.scalar.as_mut() {
            scalar.zeroize_private_v1();
        }
        self.scalar = None;
        // Dropping the immutable capability clears its owned private trace.
        self.arithmetic = None;
        if let Some(window) = self.window.as_mut() {
            zeroize_main_window_batch_v1(window);
        }
        self.window = None;
        if let Some(reduction) = self.digest_reduction.as_mut() {
            reduction.zeroize_private_v1();
        }
        self.digest_reduction = None;
        if let Some(reduction) = self.result_x_reduction.as_mut() {
            reduction.zeroize_private_v1();
        }
        self.result_x_reduction = None;
        if let Some(low_s) = self.low_s.as_mut() {
            low_s.zeroize_private_v1();
        }
        self.low_s = None;
        if let Some(sink) = self.sink.as_mut() {
            sink.zeroize_private_v1();
        }
        self.sink = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainSignatureBoundV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainSignatureTerminalClaimsV1 {
    role: P256EcdsaRoleV1,
    buses: P256BusTerminalClaimsV1,
    cross_sources: Vec<P256CrossTraceTerminalClaimV1>,
    sink: [F; P256_CROSS_TRACE_LANES_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainSignatureTerminalClaimsV1 {
    fn drop(&mut self) {
        zeroize_p256_main_bus_claims_v1(&mut self.buses);
        for source in &mut self.cross_sources {
            super::private_table::zeroize_fields_v1(&mut source.start[..]);
            super::private_table::zeroize_fields_v1(&mut source.terminal[..]);
        }
        self.cross_sources.clear();
        super::private_table::zeroize_fields_v1(&mut self.sink[..]);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainCrossClaimsGuardV1(Vec<P256CrossTraceTerminalClaimV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainCrossClaimsGuardV1 {
    fn take_v1(&mut self) -> Vec<P256CrossTraceTerminalClaimV1> {
        core::mem::take(&mut self.0)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainCrossClaimsGuardV1 {
    fn drop(&mut self) {
        for source in &mut self.0 {
            super::private_table::zeroize_fields_v1(&mut source.start[..]);
            super::private_table::zeroize_fields_v1(&mut source.terminal[..]);
        }
        self.0.clear();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct P256MainTerminalAssemblyGuardV1 {
    certificate_or_crl:
        [ZkX509P256CertificatePrivateProductsV1; P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1],
    wallet: ZkX509P256WalletPrivateProductsV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainTerminalAssemblyGuardV1 {
    fn drop(&mut self) {
        for signature in &mut self.certificate_or_crl {
            zeroize_p256_main_bus_claims_v1(&mut signature.buses);
            for source in &mut signature.cross_sources {
                super::private_table::zeroize_fields_v1(&mut source.start[..]);
                super::private_table::zeroize_fields_v1(&mut source.terminal[..]);
            }
            super::private_table::zeroize_fields_v1(&mut signature.sink[..]);
        }
        zeroize_p256_main_bus_claims_v1(&mut self.wallet.buses);
        for source in &mut self.wallet.cross_sources {
            super::private_table::zeroize_fields_v1(&mut source.start[..]);
            super::private_table::zeroize_fields_v1(&mut source.terminal[..]);
        }
        super::private_table::zeroize_fields_v1(&mut self.wallet.sink[..]);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_main_signature_terminal_claims_v1(
    signature: &P256MainSignatureBoundV1,
    post_base: ZkX509CredentialMainPostBaseChallengesV1,
    optional_certificate: bool,
) -> Result<P256MainSignatureTerminalClaimsV1, P256AggregateAdapterErrorV1> {
    let value = signature
        .value
        .as_ref()
        .ok_or(P256AggregateAdapterErrorV1::Phase)?;
    if value
        .post_base_v1()
        .map_err(P256AggregateAdapterErrorV1::from)?
        != post_base
    {
        return Err(P256AggregateAdapterErrorV1::Challenge);
    }
    let scalar = signature
        .scalar
        .as_ref()
        .ok_or(P256AggregateAdapterErrorV1::Phase)?;
    if scalar
        .post_base_v1()
        .map_err(P256AggregateAdapterErrorV1::from)?
        != post_base
    {
        return Err(P256AggregateAdapterErrorV1::Challenge);
    }
    let execution = P256ValueExecutionAggregateStreamV1::new_v1(value)?;
    let sorted = value
        .sorted_aux_source_v1()
        .map_err(P256AggregateAdapterErrorV1::from)?;
    let arithmetic = P256ArithmeticAggregateAuxStreamV1::from_validated_v1(
        signature.role,
        signature
            .arithmetic
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?,
        post_base.p256_scalar(),
        post_base.p256_arithmetic_copy(),
    )?;
    let scalar_terminals = scalar.terminals_v1();
    let writer = P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::ValueWriter,
        start: [F::ONE; P256_CROSS_TRACE_LANES_V1],
        terminal: execution.terminal_v1(),
    };
    let window = P256WindowAggregateAuxStreamV1::new_v1(
        signature
            .window
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?,
        writer.terminal,
        post_base.p256_cross(),
        post_base.p256_scalar(),
    )?;
    let window_claim = P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::WindowBatch,
        start: window.cross_start_v1(),
        terminal: window.cross_terminal_v1(),
    };
    let digest = P256ReductionAggregateAuxStreamV1::new_v1(
        P256ReductionAggregateRoleV1::Digest,
        signature
            .digest_reduction
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?,
        window_claim.terminal,
        post_base.p256_cross(),
    )?;
    let digest_claim = P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::DigestReduction,
        start: digest.start_v1(),
        terminal: digest.terminal_v1(),
    };
    let result_x = P256ReductionAggregateAuxStreamV1::new_v1(
        P256ReductionAggregateRoleV1::ResultX,
        signature
            .result_x_reduction
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?,
        digest_claim.terminal,
        post_base.p256_cross(),
    )?;
    let result_x_claim = P256CrossTraceTerminalClaimV1 {
        role: P256CrossTraceTerminalRoleV1::ResultXReduction,
        start: result_x.start_v1(),
        terminal: result_x.terminal_v1(),
    };
    let mut cross_sources = P256MainCrossClaimsGuardV1(Vec::new());
    cross_sources
        .0
        .try_reserve_exact(p256_cross_trace_terminal_roles_v1(signature.role).len())
        .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
    cross_sources
        .0
        .extend([writer, window_claim, digest_claim, result_x_claim]);
    if signature.role == P256EcdsaRoleV1::WalletOwnership {
        let low_s = P256LowSAggregateAuxStreamV1::new_v1(
            signature.role,
            signature
                .low_s
                .as_ref()
                .ok_or(P256AggregateAdapterErrorV1::Phase)?,
            result_x_claim.terminal,
            post_base.p256_cross(),
        )?;
        cross_sources.0.push(P256CrossTraceTerminalClaimV1 {
            role: P256CrossTraceTerminalRoleV1::WalletLowS,
            start: low_s.start_v1(),
            terminal: low_s.terminal_v1(),
        });
    } else if signature.low_s.is_some() {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let buses = P256BusTerminalClaimsV1 {
        value_execution: execution.value_terminal_v1()?,
        value_sorted: sorted.terminal_v1(),
        value_arithmetic_copy: execution.arithmetic_copy_terminal_v1(),
        arithmetic_value_copy: arithmetic.arithmetic_copy_terminal_v1(),
        arithmetic_scalar: arithmetic.terminal_v1(),
        window_scalar: window.scalar_terminal_v1(),
        scalar_bus_arithmetic: scalar_terminals[0],
        scalar_bus_window: scalar_terminals[1],
    };
    let mut claims = P256MainSignatureTerminalClaimsV1 {
        role: signature.role,
        buses,
        cross_sources: cross_sources.take_v1(),
        sink: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
    };
    claims.sink = P256BindingSinkAggregateStreamV1::new_with_optional_certificate_v1(
        signature
            .sink
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?,
        post_base.p256_cross(),
        optional_certificate,
    )?
    .terminal_v1();
    if evaluate_p256_bus_terminal_claim_equalities_v1(claims.buses)?
        .iter()
        .any(|residue| *residue != F::ZERO)
        || evaluate_p256_cross_trace_terminal_claim_equalities_v1(
            claims.role,
            &claims.cross_sources,
            claims.sink,
        )?
        .iter()
        .any(|residue| *residue != F::ZERO)
    {
        return Err(P256AggregateAdapterErrorV1::Constraint);
    }
    Ok(claims)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_main_terminal_claims_v1(
    signatures: &[P256MainSignatureBoundV1; P256_X5S1_SIGNATURES_V1],
    post_base: ZkX509CredentialMainPostBaseChallengesV1,
) -> Result<ZkX509P256PrivateProductsV1, P256AggregateAdapterErrorV1> {
    let mut computed = Vec::new();
    computed
        .try_reserve_exact(P256_X5S1_SIGNATURES_V1)
        .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
    for (signature_index, signature) in signatures.iter().enumerate() {
        let expected_role = if signature_index < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            P256EcdsaRoleV1::CertificateOrCrl
        } else {
            P256EcdsaRoleV1::WalletOwnership
        };
        if signature.role != expected_role {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        computed.push(p256_main_signature_terminal_claims_v1(
            signature,
            post_base,
            signature_index == 2,
        )?);
    }
    if computed.len() != P256_X5S1_SIGNATURES_V1
        || computed
            .iter()
            .take(P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1)
            .any(|signature| {
                signature.role != P256EcdsaRoleV1::CertificateOrCrl
                    || signature.cross_sources.len() != 4
            })
    {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let certificate_or_crl = core::array::from_fn(|signature_index| {
        let signature = &computed[signature_index];
        let mut cross_sources = [signature.cross_sources[0]; 4];
        cross_sources.copy_from_slice(&signature.cross_sources);
        ZkX509P256CertificatePrivateProductsV1 {
            buses: signature.buses,
            cross_sources,
            sink: signature.sink,
        }
    });
    let wallet = computed
        .get(P256_X5S1_SIGNATURES_V1 - 1)
        .ok_or(P256AggregateAdapterErrorV1::Topology)?;
    if wallet.role != P256EcdsaRoleV1::WalletOwnership || wallet.cross_sources.len() != 5 {
        return Err(P256AggregateAdapterErrorV1::Topology);
    }
    let mut wallet_cross_sources = [wallet.cross_sources[0]; 5];
    wallet_cross_sources.copy_from_slice(&wallet.cross_sources);
    let assembled = P256MainTerminalAssemblyGuardV1 {
        certificate_or_crl,
        wallet: ZkX509P256WalletPrivateProductsV1 {
            buses: wallet.buses,
            cross_sources: wallet_cross_sources,
            sink: wallet.sink,
        },
    };
    ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(
        assembled.certificate_or_crl,
        assembled.wallet,
    )
    .map_err(|_| P256AggregateAdapterErrorV1::Constraint)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_p256_main_bus_claims_v1(claims: &mut P256BusTerminalClaimsV1) {
    super::private_table::zeroize_fields_v1(&mut claims.value_execution[..]);
    super::private_table::zeroize_fields_v1(&mut claims.value_sorted[..]);
    super::private_table::zeroize_fields_v1(&mut claims.value_arithmetic_copy[..]);
    super::private_table::zeroize_fields_v1(&mut claims.arithmetic_value_copy[..]);
    super::private_table::zeroize_fields_v1(&mut claims.arithmetic_scalar[..]);
    super::private_table::zeroize_fields_v1(&mut claims.window_scalar[..]);
    super::private_table::zeroize_fields_v1(&mut claims.scalar_bus_arithmetic[..]);
    super::private_table::zeroize_fields_v1(&mut claims.scalar_bus_window[..]);
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_p256_main_terminal_claims_v1(claims: &mut ZkX509P256PrivateProductsV1) {
    for signature in &mut claims.certificate_or_crl {
        zeroize_p256_main_bus_claims_v1(&mut signature.buses);
        for source in &mut signature.cross_sources {
            super::private_table::zeroize_fields_v1(&mut source.start[..]);
            super::private_table::zeroize_fields_v1(&mut source.terminal[..]);
        }
        super::private_table::zeroize_fields_v1(&mut signature.sink[..]);
    }
    zeroize_p256_main_bus_claims_v1(&mut claims.wallet.buses);
    for source in &mut claims.wallet.cross_sources {
        super::private_table::zeroize_fields_v1(&mut source.start[..]);
        super::private_table::zeroize_fields_v1(&mut source.terminal[..]);
    }
    super::private_table::zeroize_fields_v1(&mut claims.wallet.sink[..]);
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainBaseSourceV1 {
    /// Consume the exact five-signature base phase once under the opaque X5B1 token.
    ///
    /// The source is poisoned before any fallible validation or child bind.
    /// A failed transition recursively clears every retained private trace and
    /// can never be retried with another transcript.
    pub(crate) fn bind_v1(
        &mut self,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<P256MainBoundSourceV1, P256AggregateAdapterErrorV1> {
        self.ensure_base_phase_v1()?;
        self.bind_attempted = true;
        let result = (|| {
            let signatures = self
                .signatures
                .as_mut()
                .ok_or(P256AggregateAdapterErrorV1::Phase)?;
            for signature in signatures.iter() {
                if signature.value.is_none()
                    || signature.scalar.is_none()
                    || signature.arithmetic.is_none()
                    || signature.window.is_none()
                    || signature.digest_reduction.is_none()
                    || signature.result_x_reduction.is_none()
                    || signature.sink.is_none()
                    || (signature.role == P256EcdsaRoleV1::WalletOwnership)
                        != signature.low_s.is_some()
                {
                    return Err(P256AggregateAdapterErrorV1::Source);
                }
            }
            let mut bound = ClearingVecV1::try_with_capacity_v1(P256_X5S1_SIGNATURES_V1)
                .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
            for signature in signatures.iter_mut() {
                let value = signature
                    .value
                    .as_mut()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .bind_v1(post_base)
                    .map_err(P256AggregateAdapterErrorV1::from)?;
                if value
                    .post_base_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?
                    != post_base
                {
                    return Err(P256AggregateAdapterErrorV1::Challenge);
                }
                let scalar = signature
                    .scalar
                    .as_mut()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .bind_v1(post_base)
                    .map_err(P256AggregateAdapterErrorV1::from)?;
                if scalar
                    .post_base_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?
                    != post_base
                {
                    return Err(P256AggregateAdapterErrorV1::Challenge);
                }
                bound
                    .try_push_v1(P256MainSignatureBoundV1 {
                        role: signature.role,
                        value: Some(value),
                        scalar: Some(scalar),
                        arithmetic: signature.arithmetic.take(),
                        window: signature.window.take(),
                        digest_reduction: signature.digest_reduction.take(),
                        result_x_reduction: signature.result_x_reduction.take(),
                        low_s: signature.low_s.take(),
                        sink: signature.sink.take(),
                    })
                    .map_err(|_| P256AggregateAdapterErrorV1::Resource)?;
            }
            let mut source = P256MainBoundSourceV1 {
                signatures: Some(bound),
                fixed: self.fixed.take(),
                post_base: Some(post_base),
                terminal_claims: None,
            };
            source.terminal_claims = Some(p256_main_terminal_claims_v1(
                source
                    .signatures
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .as_slice_v1()
                    .try_into()
                    .map_err(|_| P256AggregateAdapterErrorV1::Topology)?,
                post_base,
            )?);
            source.ensure_bound_v1()?;
            Ok(source)
        })();
        self.signatures = None;
        if result.is_err() {
            self.zeroize_private_v1();
        }
        result
    }
}
/// Unforgeable borrow of one MAIN signature's bind-derived writer state.
/// Fields and construction stay private to this module; the cross-trace stream
/// may only read them. No proof claim, raw terminal or independent key/trace can
/// be supplied by a caller. The lifetime keeps the complete checked owner alive.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) struct P256MainBoundWriterReplayV1<'a> {
    endpoint: &'a super::p256_value_bus::P256ValueBusBaseEndpointTraceV1,
    fixed: &'a P256CrossTraceWriterSourceFixedV1,
    post_base: ZkX509CredentialMainPostBaseChallengesV1,
    terminal: &'a [F; P256_CROSS_TRACE_LANES_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> P256MainBoundWriterReplayV1<'a> {
    /// The immutable execution endpoint selected by MAIN registration.
    pub(super) fn endpoint_v1(&self) -> &'a super::p256_value_bus::P256ValueBusBaseEndpointTraceV1 {
        self.endpoint
    }
    /// The retained verifier-owned schedule for that signature role.
    pub(super) fn fixed_v1(&self) -> &'a P256CrossTraceWriterSourceFixedV1 {
        self.fixed
    }
    /// Challenges from the same opaque MAIN post-base token.
    pub(super) fn challenges_v1(&self) -> P256CrossTraceChallengesV1 {
        self.post_base.p256_cross()
    }
    /// The terminal computed from this same endpoint during its checked bind.
    pub(super) fn terminal_v1(&self) -> [F; P256_CROSS_TRACE_LANES_V1] {
        *self.terminal
    }
}
/// Post-X5B1 capability for the sole five-signature P-256 MAIN set.
///
/// It is the only production source of P-256 auxiliary replay. All challenge
/// families remain tied to the single retained opaque token; callers cannot
/// pass a second raw challenge set into column replay.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub struct P256MainBoundSourceV1 {
    // Cardinality is checked before replay; transferring this owner never
    // materializes the five large signatures as a stack array.
    signatures: Option<ClearingVecV1<P256MainSignatureBoundV1>>,
    fixed: Option<P256MainVerifierFixedSourceV1>,
    post_base: Option<ZkX509CredentialMainPostBaseChallengesV1>,
    terminal_claims: Option<ZkX509P256PrivateProductsV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256MainBoundSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256MainBoundSourceV1")
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256MainBoundSourceV1 {
    /// Reachable native source payload, excluding the separately borrowed assembly.
    pub(crate) fn allocated_payload_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            core::mem::size_of_val(self),
            self.fixed
                .as_ref()
                .map_or(0, P256MainVerifierFixedSourceV1::allocated_heap_bytes_v1),
            self.signatures
                .as_ref()
                .map_or(0, ClearingVecV1::allocated_bytes_v1),
            self.signatures.as_ref().map_or(0, |signatures| {
                sum_v1(signatures.iter().map(|signature| {
                    sum_v1([
                        signature
                            .value
                            .as_ref()
                            .map_or(0, |value| value.allocated_heap_bytes_v1()),
                        signature
                            .scalar
                            .as_ref()
                            .map_or(0, |scalar| scalar.allocated_heap_bytes_v1()),
                        signature
                            .arithmetic
                            .as_ref()
                            .map_or(0, P256MainValidatedArithmeticV1::allocated_heap_bytes_v1),
                        signature.window.as_ref().map_or(0, |trace| {
                            sum_v1([vector_v1(&trace.base), vector_v1(&trace.aux)])
                        }),
                        signature
                            .sink
                            .as_ref()
                            .map_or(0, |trace| vector_v1(&trace.rows)),
                    ])
                }))
            }),
        ])
    }
    fn ensure_bound_v1(&self) -> Result<(), P256AggregateAdapterErrorV1> {
        let post_base = self.post_base.ok_or(P256AggregateAdapterErrorV1::Phase)?;
        let claims = self
            .terminal_claims
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        if self.fixed.is_none() {
            return Err(P256AggregateAdapterErrorV1::Phase);
        }
        if ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(
            claims.certificate_or_crl,
            claims.wallet,
        )
        .map_err(|_| P256AggregateAdapterErrorV1::Constraint)?
            != claims
        {
            return Err(P256AggregateAdapterErrorV1::Constraint);
        }
        let signatures = self
            .signatures
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        if signatures.len() != P256_X5S1_SIGNATURES_V1 {
            return Err(P256AggregateAdapterErrorV1::Phase);
        }
        for (signature_index, signature) in signatures.iter().enumerate() {
            let expected_role = if signature_index < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
                P256EcdsaRoleV1::CertificateOrCrl
            } else {
                P256EcdsaRoleV1::WalletOwnership
            };
            if signature.role != expected_role
                || signature
                    .value
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .post_base_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?
                    != post_base
                || signature
                    .scalar
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .post_base_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?
                    != post_base
            {
                return Err(P256AggregateAdapterErrorV1::Challenge);
            }
        }
        Ok(())
    }
    fn signature_v1(
        &self,
        registration: P256MainRegistrationV1,
    ) -> Result<&P256MainSignatureBoundV1, P256AggregateAdapterErrorV1> {
        self.ensure_bound_v1()?;
        self.signatures
            .as_ref()
            .and_then(|signatures| signatures.get(registration.signature_v1()))
            .filter(|signature| signature.role == registration.role_v1())
            .ok_or(P256AggregateAdapterErrorV1::Topology)
    }
    fn cross_claim_v1(
        &self,
        registration: P256MainRegistrationV1,
        role: P256CrossTraceTerminalRoleV1,
    ) -> Result<P256CrossTraceTerminalClaimV1, P256AggregateAdapterErrorV1> {
        self.ensure_bound_v1()?;
        let claims = self
            .terminal_claims
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        let sources: &[P256CrossTraceTerminalClaimV1] =
            if registration.signature_v1() < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
                &claims.certificate_or_crl[registration.signature_v1()].cross_sources
            } else if registration.signature_v1() == P256_X5S1_SIGNATURES_V1 - 1 {
                &claims.wallet.cross_sources
            } else {
                return Err(P256AggregateAdapterErrorV1::Topology);
            };
        sources
            .iter()
            .copied()
            .find(|source| source.role == role)
            .ok_or(P256AggregateAdapterErrorV1::Topology)
    }
    /// The already-bound opaque MAIN token used by residue evaluators.
    ///
    /// Returning the capability does not permit caller-selected challenges:
    /// construction remains private to pre-aux transcript binding, and every
    /// replay first checks equality with both retained child capabilities.
    pub(crate) fn post_base_v1(
        &self,
    ) -> Result<ZkX509CredentialMainPostBaseChallengesV1, P256AggregateAdapterErrorV1> {
        self.ensure_bound_v1()?;
        self.post_base.ok_or(P256AggregateAdapterErrorV1::Phase)
    }
    /// Sole verifier-owned registration order retained after binding.
    pub(crate) fn canonical_registrations_v1(
        &self,
    ) -> Result<Vec<P256MainRegistrationV1>, P256AggregateAdapterErrorV1> {
        self.ensure_bound_v1()?;
        canonical_p256_main_registrations_v1()
    }
    /// Replay up to eight adjacent arithmetic or execution/sorted value base
    /// columns. The immutable phase owner and exact registration remain the
    /// authority; all columns share one canonical row pass and clearing guard.
    pub(crate) fn fill_base_columns_v1(
        &self,
        registration: P256MainRegistrationV1,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if !matches!(
            (registration.adapter_v1(), registration.local_instance_v1()),
            (P256MainAdapterV1::Arithmetic, 0) | (P256MainAdapterV1::ValueBus, 0 | 1)
        ) || outputs.is_empty()
            || outputs.len()
                > crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || first
                .checked_add(outputs.len())
                .is_none_or(|end| end > shape.base_width)
            || outputs
                .iter()
                .any(|output| output.len() != shape.trace_size)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::Arithmetic, 0) => {
                let rows = signature
                    .arithmetic
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .rows_v1(signature.role)?;
                rows.fill_base_columns_v1(first, outputs)
            }
            (P256MainAdapterV1::ValueBus, local @ 0..=1) => {
                let value = signature
                    .value
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?;
                let rows = if local == 0 {
                    value.execution_base_rows_v1()
                } else {
                    value.sorted_base_rows_v1()
                }
                .map_err(P256AggregateAdapterErrorV1::from)?;
                fill_aggregate_base_columns_v1::<P256_VALUE_BUS_STARK_BASE_WIDTH_V1>(
                    shape.trace_size,
                    first,
                    outputs,
                    |row| Ok(rows.base_row_v1(row)?),
                )
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Replay one complete challenge-independent committed column after binding.
    pub(crate) fn fill_base_column_v1(
        &self,
        registration: P256MainRegistrationV1,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if column >= shape.base_width || output.len() != shape.trace_size {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::ValueBus, local @ 0..=1) => {
                let value = signature
                    .value
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?;
                let rows = if local == 0 {
                    value.execution_base_rows_v1()
                } else {
                    value.sorted_base_rows_v1()
                }
                .map_err(P256AggregateAdapterErrorV1::from)?;
                fill_aggregate_row_column_v1::<P256_VALUE_BUS_STARK_BASE_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| Ok(rows.base_row_v1(row)?),
                )
            }
            (P256MainAdapterV1::Arithmetic, 0) => signature
                .arithmetic
                .as_ref()
                .ok_or(P256AggregateAdapterErrorV1::Phase)?
                .rows_v1(signature.role)?
                .fill_base_column_v1(column, output),
            (P256MainAdapterV1::WindowBatch, 0) => P256WindowAggregateRowsV1::new_v1(
                signature
                    .window
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?,
            )?
            .fill_base_column_v1(column, output),
            (P256MainAdapterV1::Reduction, local @ 0..=1) => {
                let trace = if local == 0 {
                    signature.digest_reduction.as_ref()
                } else {
                    signature.result_x_reduction.as_ref()
                }
                .ok_or(P256AggregateAdapterErrorV1::Phase)?;
                P256ReductionAggregateRowsV1::new_v1(
                    if local == 0 {
                        P256ReductionAggregateRoleV1::Digest
                    } else {
                        P256ReductionAggregateRoleV1::ResultX
                    },
                    trace,
                )?
                .fill_base_column_v1(column, output)
            }
            (P256MainAdapterV1::WalletLowS, 0) => P256LowSAggregateRowsV1::new_v1(
                signature.role,
                signature
                    .low_s
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?,
            )?
            .fill_base_column_v1(column, output),
            (P256MainAdapterV1::BindingSink, 0) => P256BindingSinkRowsV1::new_v1(
                signature
                    .sink
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?,
            )?
            .fill_base_column_v1(column, output),
            (P256MainAdapterV1::ScalarBitBus, 0) => {
                let rows = signature
                    .scalar
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .base_rows_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?;
                fill_aggregate_row_column_v1::<P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    |row| Ok(rows.base_row_v1(row)?),
                )
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Replay one complete witness-free verifier-preprocessed column after binding.
    pub(crate) fn fill_fixed_column_v1(
        &self,
        registration: P256MainRegistrationV1,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if column >= shape.fixed_width || output.len() != shape.trace_size {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        self.ensure_bound_v1()?;
        self.fixed
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?
            .fill_fixed_column_v1(registration, column, output)
    }
    /// Fill the admitted public matrix from this exact bound owner's verifier
    /// schedule; private trace replay keeps its separate eight-column limit.
    pub(crate) fn fill_arithmetic_fixed_matrix_v1(
        &self,
        registration: P256MainRegistrationV1,
        columns: &mut [Vec<F>],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        self.signature_v1(registration)?;
        self.fixed
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?
            .fill_arithmetic_fixed_matrix_v1(registration, columns)
    }
    /// Borrow execution replay from this exact checked MAIN owner. As with the
    /// arithmetic replay factory, all terminal copies come from the private
    /// result of binding this same immutable source, never from prover claims.
    fn value_execution_aux_stream_v1(
        &self,
        registration: P256MainRegistrationV1,
    ) -> Result<P256ValueExecutionAggregateStreamV1<'_>, P256AggregateAdapterErrorV1> {
        if registration.adapter_v1() != P256MainAdapterV1::ValueBus
            || registration.local_instance_v1() != 0
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        let post_base = self.post_base_v1()?;
        let value = signature
            .value
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        let topology = value.topology_v1()?;
        if topology.linked_operations.len() != P256_ARITHMETIC_OPERATIONS_V1 {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let claims = self
            .terminal_claims
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        let (buses, sources): (_, &[P256CrossTraceTerminalClaimV1]) =
            if registration.signature_v1() < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
                let claims = &claims.certificate_or_crl[registration.signature_v1()];
                (&claims.buses, &claims.cross_sources)
            } else if registration.signature_v1() == P256_X5S1_SIGNATURES_V1 - 1 {
                (&claims.wallet.buses, &claims.wallet.cross_sources)
            } else {
                return Err(P256AggregateAdapterErrorV1::Topology);
            };
        let writer_claim = sources
            .iter()
            .find(|claim| claim.role == P256CrossTraceTerminalRoleV1::ValueWriter)
            .ok_or(P256AggregateAdapterErrorV1::Topology)?;
        if writer_claim.start != [F::ONE; P256_CROSS_TRACE_LANES_V1] {
            return Err(P256AggregateAdapterErrorV1::Constraint);
        }
        let value_aux = value.execution_aux_source_v1()?;
        if value_aux.terminal_v1() != buses.value_execution {
            return Err(P256AggregateAdapterErrorV1::Constraint);
        }
        let fixed = self
            .fixed
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?
            .execution_v1(signature.role);
        let writer =
            P256CrossTraceWriterSourceStreamV1::from_bound_main_v1(P256MainBoundWriterReplayV1 {
                endpoint: value.execution_endpoint_v1()?,
                fixed: &fixed.writer,
                post_base,
                terminal: &writer_claim.terminal,
            })?;
        let arithmetic_copy_challenges = post_base.p256_arithmetic_copy();
        arithmetic_copy_challenges.validate_v1()?;
        Ok(P256ValueExecutionAggregateStreamV1 {
            base: value.execution_base_rows_v1()?,
            value_aux: Some(value_aux),
            writer: Some(writer),
            writer_terminal: writer_claim.terminal,
            arithmetic_operations: topology.linked_operations.len(),
            arithmetic_copy_challenges,
            arithmetic_copy_running: [F::ONE; P256_ARITHMETIC_COPY_LANES_V1],
            arithmetic_copy_terminal: buses.value_arithmetic_copy,
            next_row: 0,
        })
    }
    /// Borrow one arithmetic stream from this source's sole checked bind result.
    /// No caller can supply a trace, terminal, challenge, or different token.
    fn arithmetic_aux_stream_v1(
        &self,
        registration: P256MainRegistrationV1,
    ) -> Result<P256ArithmeticAggregateAuxStreamV1<'_>, P256AggregateAdapterErrorV1> {
        if registration.adapter_v1() != P256MainAdapterV1::Arithmetic
            || registration.local_instance_v1() != 0
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        let post_base = self.post_base_v1()?;
        let scalar_challenges = post_base.p256_scalar();
        let arithmetic_copy_challenges = post_base.p256_arithmetic_copy();
        scalar_challenges
            .validate_v1()
            .map_err(|_| P256AggregateAdapterErrorV1::Challenge)?;
        arithmetic_copy_challenges.validate_v1()?;
        let rows = signature
            .arithmetic
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?
            .rows_v1(signature.role)?;
        let claims = self
            .terminal_claims
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        let buses = if registration.signature_v1() < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            &claims.certificate_or_crl[registration.signature_v1()].buses
        } else if registration.signature_v1() == P256_X5S1_SIGNATURES_V1 - 1 {
            &claims.wallet.buses
        } else {
            return Err(P256AggregateAdapterErrorV1::Topology);
        };
        // These products were computed from this same immutable trace while
        // binding this source. Borrowing self prevents replacing that owner or
        // its claims until the returned stream is gone.
        Ok(P256ArithmeticAggregateAuxStreamV1 {
            rows,
            scalar_challenges,
            scalar_running: [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1],
            scalar_terminal: buses.arithmetic_scalar,
            arithmetic_copy_challenges,
            arithmetic_copy_running: [F::ONE; P256_ARITHMETIC_COPY_LANES_V1],
            arithmetic_copy_terminal: buses.arithmetic_value_copy,
            next_row: 0,
            _not_copy: core::cell::Cell::new(()),
        })
    }
    /// Replay at most eight adjacent arithmetic auxiliary columns together.
    /// Caller-owned columns occupy the existing native replay batch; no matrix
    /// or second column batch is allocated by this source.
    pub(crate) fn fill_arithmetic_aux_columns_v1(
        &self,
        registration: P256MainRegistrationV1,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if outputs.is_empty()
            || outputs.len()
                > crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || first
                .checked_add(outputs.len())
                .is_none_or(|end| end > shape.aux_width)
            || outputs
                .iter()
                .any(|output| output.len() != shape.trace_size)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let selection = P256ArithmeticAuxSelectionV1::new_v1(first, outputs.len())?;
        let mut stream = self.arithmetic_aux_stream_v1(registration)?;
        fill_aggregate_aux_columns_v1::<P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1>(
            shape.trace_size,
            first,
            outputs,
            || stream.next_selected_aux_row_v1(selection),
        )
    }
    /// Replay at most eight adjacent value auxiliary columns from one exact
    /// execution or sorted endpoint. Registration and token validation precede
    /// construction; the existing row/destination guards clear every batch on
    /// stream failure, extra rows or unwind. No retained source matrix is added.
    pub(crate) fn fill_value_aux_columns_v1(
        &self,
        registration: P256MainRegistrationV1,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if !matches!(
            (registration.adapter_v1(), registration.local_instance_v1()),
            (P256MainAdapterV1::ValueBus, 0 | 1)
        ) || outputs.is_empty()
            || outputs.len()
                > crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
            || first
                .checked_add(outputs.len())
                .is_none_or(|end| end > shape.aux_width)
            || outputs
                .iter()
                .any(|output| output.len() != shape.trace_size)
        {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        let value = signature
            .value
            .as_ref()
            .ok_or(P256AggregateAdapterErrorV1::Phase)?;
        match registration.local_instance_v1() {
            0 => {
                let mut stream = self.value_execution_aux_stream_v1(registration)?;
                fill_aggregate_aux_columns_v1::<P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1>(
                    shape.trace_size,
                    first,
                    outputs,
                    || stream.next_aux_row_v1(),
                )
            }
            1 => {
                let mut stream = value.sorted_aux_source_v1()?;
                fill_aggregate_aux_columns_v1::<P256_VALUE_BUS_STARK_AUX_WIDTH_V1>(
                    shape.trace_size,
                    first,
                    outputs,
                    || {
                        stream
                            .next_aux_row_v1()
                            .map_err(P256AggregateAdapterErrorV1::from)
                    },
                )
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Replay one complete challenge-dependent committed column from the
    /// single retained X5B1 token.
    pub(crate) fn fill_aux_column_v1(
        &self,
        registration: P256MainRegistrationV1,
        column: usize,
        output: &mut [F],
    ) -> Result<(), P256AggregateAdapterErrorV1> {
        let shape = registration.shape_v1()?;
        if column >= shape.aux_width || output.len() != shape.trace_size {
            return Err(P256AggregateAdapterErrorV1::Topology);
        }
        let signature = self.signature_v1(registration)?;
        let post_base = self.post_base_v1()?;
        match (registration.adapter_v1(), registration.local_instance_v1()) {
            (P256MainAdapterV1::ValueBus, 0) => self
                .value_execution_aux_stream_v1(registration)?
                .fill_aux_column_v1(column, output),
            (P256MainAdapterV1::ValueBus, 1) => {
                let mut source = signature
                    .value
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .sorted_aux_source_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?;
                fill_aggregate_aux_column_v1::<P256_VALUE_BUS_STARK_AUX_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    || {
                        source
                            .next_aux_row_v1()
                            .map_err(P256AggregateAdapterErrorV1::from)
                    },
                )
            }
            (P256MainAdapterV1::Arithmetic, 0) => self
                .arithmetic_aux_stream_v1(registration)?
                .fill_aux_column_v1(column, output),
            (P256MainAdapterV1::WindowBatch, 0) => {
                let start = self
                    .cross_claim_v1(registration, P256CrossTraceTerminalRoleV1::WindowBatch)?
                    .start;
                P256WindowAggregateAuxStreamV1::new_v1(
                    signature
                        .window
                        .as_ref()
                        .ok_or(P256AggregateAdapterErrorV1::Phase)?,
                    start,
                    post_base.p256_cross(),
                    post_base.p256_scalar(),
                )?
                .fill_aux_column_v1(column, output)
            }
            (P256MainAdapterV1::Reduction, local @ 0..=1) => {
                let (role, claim_role, trace) = if local == 0 {
                    (
                        P256ReductionAggregateRoleV1::Digest,
                        P256CrossTraceTerminalRoleV1::DigestReduction,
                        signature.digest_reduction.as_ref(),
                    )
                } else {
                    (
                        P256ReductionAggregateRoleV1::ResultX,
                        P256CrossTraceTerminalRoleV1::ResultXReduction,
                        signature.result_x_reduction.as_ref(),
                    )
                };
                let start = self.cross_claim_v1(registration, claim_role)?.start;
                P256ReductionAggregateAuxStreamV1::new_v1(
                    role,
                    trace.ok_or(P256AggregateAdapterErrorV1::Phase)?,
                    start,
                    post_base.p256_cross(),
                )?
                .fill_aux_column_v1(column, output)
            }
            (P256MainAdapterV1::WalletLowS, 0) => {
                let start = self
                    .cross_claim_v1(registration, P256CrossTraceTerminalRoleV1::WalletLowS)?
                    .start;
                P256LowSAggregateAuxStreamV1::new_v1(
                    signature.role,
                    signature
                        .low_s
                        .as_ref()
                        .ok_or(P256AggregateAdapterErrorV1::Phase)?,
                    start,
                    post_base.p256_cross(),
                )?
                .fill_aux_column_v1(column, output)
            }
            (P256MainAdapterV1::BindingSink, 0) => {
                P256BindingSinkAggregateStreamV1::new_with_optional_certificate_v1(
                    signature
                        .sink
                        .as_ref()
                        .ok_or(P256AggregateAdapterErrorV1::Phase)?,
                    post_base.p256_cross(),
                    registration.signature_v1() == 2,
                )?
                .fill_aux_column_v1(column, output)
            }
            (P256MainAdapterV1::ScalarBitBus, 0) => {
                let mut source = signature
                    .scalar
                    .as_ref()
                    .ok_or(P256AggregateAdapterErrorV1::Phase)?
                    .aux_source_v1()
                    .map_err(P256AggregateAdapterErrorV1::from)?;
                fill_aggregate_aux_column_v1::<P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1>(
                    shape.trace_size,
                    column,
                    output,
                    || {
                        source
                            .next_aux_row_v1()
                            .map_err(P256AggregateAdapterErrorV1::from)
                    },
                )
            }
            _ => Err(P256AggregateAdapterErrorV1::Topology),
        }
    }
    /// Private product owner for all five role-positioned signatures; no public scalar codec.
    #[cfg(test)]
    pub(crate) fn terminal_claims_v1(
        &self,
    ) -> Result<ZkX509P256PrivateProductsV1, P256AggregateAdapterErrorV1> {
        self.ensure_bound_v1()?;
        self.terminal_claims
            .ok_or(P256AggregateAdapterErrorV1::Phase)
    }
    pub(crate) fn zeroize_private_v1(&mut self) {
        self.post_base = None;
        if let Some(claims) = self.terminal_claims.as_mut() {
            zeroize_p256_main_terminal_claims_v1(claims);
        }
        self.terminal_claims = None;
        if let Some(signatures) = self.signatures.as_mut() {
            for signature in signatures.iter_mut() {
                signature.zeroize_private_v1();
            }
        }
        self.signatures = None;
        self.fixed = None;
    }
    #[cfg(test)]
    fn replace_post_base_for_test_v1(
        &mut self,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) {
        self.post_base = Some(post_base);
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.signatures.is_none()
            && self.fixed.is_none()
            && self.post_base.is_none()
            && self.terminal_claims.is_none()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256MainBoundSourceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(test)]
struct P256MainCanonicalTestMaterialsV1 {
    materials: [P256EcdsaTraceMaterialV1; P256_X5S1_SIGNATURES_V1],
    selection: P256OptionalCertificateSelectionV1,
}
#[cfg(test)]
impl Drop for P256MainCanonicalTestMaterialsV1 {
    fn drop(&mut self) {
        for material in &mut self.materials {
            material.zeroize_private_v1();
        }
        self.selection.real.zeroize_private_v1();
        self.selection.selected.zeroize_private_v1();
        super::private_table::zeroize_fields_v1(core::slice::from_mut(&mut self.selection.active));
    }
}
#[cfg(test)]
fn p256_main_signed_witness_for_test_v1(
    seed: u8,
) -> Result<super::p256_ecdsa_air::P256EcdsaWitnessV1, P256AggregateAdapterErrorV1> {
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
    let mut secret = [0_u8; 32];
    secret[31] = seed.max(1);
    let key = SigningKey::from_slice(&secret).map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    secret.fill(0);
    let digest = core::array::from_fn(|index| {
        seed.wrapping_mul(31)
            .wrapping_add((index as u8).wrapping_mul(17))
    });
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let signature = match signature.normalize_s() {
        Some(normalized) => normalized,
        None => signature,
    };
    let encoded = key.verifying_key().to_encoded_point(false);
    let mut public_key_x_be = [0_u8; 32];
    let mut public_key_y_be = [0_u8; 32];
    public_key_x_be.copy_from_slice(encoded.x().ok_or(P256AggregateAdapterErrorV1::Topology)?);
    public_key_y_be.copy_from_slice(encoded.y().ok_or(P256AggregateAdapterErrorV1::Topology)?);
    Ok(super::p256_ecdsa_air::P256EcdsaWitnessV1 {
        public_key_x_be,
        public_key_y_be,
        r_be: signature.r().to_bytes().into(),
        s_be: signature.s().to_bytes().into(),
        digest_be: digest,
    })
}
#[cfg(test)]
fn p256_main_canonical_materials_for_test_v1()
-> Result<P256MainCanonicalTestMaterialsV1, P256AggregateAdapterErrorV1> {
    let inactive_real = super::p256_ecdsa_air::P256EcdsaWitnessV1 {
        public_key_x_be: [0; 32],
        public_key_y_be: [0; 32],
        r_be: [0; 32],
        s_be: [0; 32],
        digest_be: ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
    };
    let selection =
        super::p256_external_binding_air::select_zk_x509_optional_certificate_p256_witness_v1(
            0,
            inactive_real,
        )
        .map_err(|_| P256AggregateAdapterErrorV1::Topology)?;
    let certificate = super::p256_trace::compile_p256_ecdsa_trace_material_v1(
        P256EcdsaRoleV1::CertificateOrCrl,
        selection.selected,
    )
    .map_err(|error| match error {
        P256TraceCompilerErrorV1::Resource => P256AggregateAdapterErrorV1::Resource,
        _ => P256AggregateAdapterErrorV1::Topology,
    })?;
    let wallet = super::p256_trace::compile_p256_ecdsa_trace_material_v1(
        P256EcdsaRoleV1::WalletOwnership,
        p256_main_signed_witness_for_test_v1(113)?,
    )
    .map_err(|error| match error {
        P256TraceCompilerErrorV1::Resource => P256AggregateAdapterErrorV1::Resource,
        _ => P256AggregateAdapterErrorV1::Topology,
    })?;
    Ok(P256MainCanonicalTestMaterialsV1 {
        materials: [
            certificate.clone(),
            certificate.clone(),
            certificate.clone(),
            certificate,
            wallet,
        ],
        selection,
    })
}
/// Canonical exact-five-signature central P-256 source for native-log tests.
///
/// This fixture bypasses only release-profile assembly setup; it still
/// compiles and validates the full production certificate/CRL and wallet
/// material through the ordinary native Rust trace compiler.
#[cfg(test)]
pub fn p256_main_base_source_fixture_for_test_v1()
-> Result<P256MainBaseSourceV1, P256AggregateAdapterErrorV1> {
    let fixture = p256_main_canonical_materials_for_test_v1()?;
    P256MainBaseSourceV1::from_materials_v1(&fixture.materials, fixture.selection)
}
#[cfg(test)]
#[path = "p256_arithmetic_fp4_tests.rs"]
mod arithmetic_fp4_tests;
#[cfg(test)]
#[path = "p256_auxiliary_replay_tests.rs"]
mod auxiliary_replay_tests;
#[cfg(test)]
#[path = "p256_binding_sink_fp4_tests.rs"]
mod sink_fp4_tests;
#[cfg(test)]
#[path = "p256_validated_owner_tests.rs"]
mod validated_owner_tests;
#[cfg(test)]
mod tests {
    /// Malformed allocation fixtures exercise clearing and capacity accounting
    /// only; they never enter a column or auxiliary replay path.
    fn arithmetic_allocation_fixture_v1(
        trace: ZkX509P256ArithmeticTraceV1,
    ) -> P256MainValidatedArithmeticV1 {
        P256MainValidatedArithmeticV1 {
            role: P256EcdsaRoleV1::CertificateOrCrl,
            trace: P256MainArithmeticStorageV1::AllocationFixture(P256MainArithmeticGuardV1(Some(
                trace,
            ))),
            fixed: P256MainArithmeticFixedSourceV1::new_v1(P256EcdsaRoleV1::CertificateOrCrl)
                .unwrap()
                .fixed,
        }
    }
    #[test]
    fn p256_main_signature_owners_bound_inline_size_and_reject_wrong_cardinality() {
        use core::mem::size_of;
        // The ordinary libtest thread must exercise the actual bind below;
        // these bounds also catch reintroducing a five-owner stack aggregate.
        assert!(size_of::<P256MainBaseSourceV1>() <= 16 * 1024);
        assert!(size_of::<P256MainBoundSourceV1>() <= 16 * 1024);
        assert!(size_of::<P256MainSignatureBaseV1>() <= 32 * 1024);
        assert!(size_of::<P256MainSignatureBoundV1>() <= 32 * 1024);
        eprintln!(
            "P256 owner inline bytes: base={} bound={} signature-base={} signature-bound={}",
            size_of::<P256MainBaseSourceV1>(),
            size_of::<P256MainBoundSourceV1>(),
            size_of::<P256MainSignatureBaseV1>(),
            size_of::<P256MainSignatureBoundV1>(),
        );
        for count in [0, 4, 6] {
            let source = P256MainBaseSourceV1 {
                signatures: Some(ClearingVecV1::from_vec_for_test_v1(
                    (0..count)
                        .map(|_| P256MainSignatureBaseV1 {
                            role: P256EcdsaRoleV1::CertificateOrCrl,
                            value: None,
                            scalar: None,
                            arithmetic: None,
                            window: None,
                            digest_reduction: None,
                            result_x_reduction: None,
                            low_s: None,
                            sink: None,
                        })
                        .collect(),
                )),
                fixed: Some(P256MainVerifierFixedSourceV1::new_v1().unwrap()),
                bind_attempted: false,
            };
            assert_eq!(
                source.ensure_base_phase_v1(),
                Err(P256AggregateAdapterErrorV1::Phase)
            );
        }
    }

    #[test]
    fn p256_main_signature_vector_clears_on_rejected_bind_and_unwind() {
        use super::super::private_table::inspection::observe_v1;
        for unwind in [false, true] {
            let mut signatures = ClearingVecV1::from_vec_for_test_v1(Vec::with_capacity(9));
            for _ in 0..P256_X5S1_SIGNATURES_V1 {
                signatures
                    .try_push_v1(P256MainSignatureBaseV1 {
                        role: P256EcdsaRoleV1::CertificateOrCrl,
                        value: None,
                        scalar: None,
                        arithmetic: Some(arithmetic_allocation_fixture_v1(
                            ZkX509P256ArithmeticTraceV1 {
                                fixed: Vec::new(),
                                base: vec![[F(79); P256_ARITHMETIC_BASE_WIDTH_V1]; 2],
                            },
                        )),
                        window: None,
                        digest_reduction: None,
                        result_x_reduction: None,
                        low_s: None,
                        sink: None,
                    })
                    .unwrap();
            }
            let mut source = P256MainBaseSourceV1 {
                signatures: Some(signatures),
                fixed: Some(P256MainVerifierFixedSourceV1::new_v1().unwrap()),
                bind_attempted: false,
            };
            let (((), observed), allocations) =
                super::super::private_table::allocation_inspection::observe_v1(|| {
                    observe_v1(|| {
                        if unwind {
                            assert!(
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                                    let _owner = source;
                                    panic!("exercise signature-vector cleanup");
                                }))
                                .is_err()
                            );
                        } else {
                            let binding = main_post_base_v1(29);
                            assert!(matches!(
                                source.bind_v1(binding),
                                Err(P256AggregateAdapterErrorV1::Source)
                            ));
                            assert!(source.private_is_zeroized_v1());
                            assert!(matches!(
                                source.bind_v1(binding),
                                Err(P256AggregateAdapterErrorV1::Phase)
                            ));
                        }
                    })
                });
            assert_eq!(
                observed
                    .iter()
                    .map(|item| item.nonzero_before)
                    .sum::<usize>(),
                P256_X5S1_SIGNATURES_V1 * 2 * P256_ARITHMETIC_BASE_WIDTH_V1
            );
            assert!(observed.iter().all(|item| item.nonzero_after == 0));
            assert_eq!(allocations.len(), 1);
            assert!(allocations[0].bytes >= 9 * core::mem::size_of::<P256MainSignatureBaseV1>());
            assert_eq!(allocations[0].nonzero_after, 0);
        }
    }

    #[test]
    fn p256_main_signature_allocation_clears_taken_slots_and_partial_bound_owners() {
        use super::super::private_table::{allocation_inspection, inspection};
        for failure in [0, 1, 2] {
            let (((), fields), allocations) = allocation_inspection::observe_v1(|| {
                inspection::observe_v1(|| {
                    let operation = || -> Result<(), ()> {
                        let mut base = ClearingVecV1::from_vec_for_test_v1(Vec::with_capacity(9));
                        let mut bound = ClearingVecV1::from_vec_for_test_v1(Vec::with_capacity(7));
                        for _ in 0..P256_X5S1_SIGNATURES_V1 {
                            let mut digest = build_p256_reduction_trace_v1([0; 32]).unwrap();
                            let mut result_x = build_p256_reduction_trace_v1([0; 32]).unwrap();
                            let mut low_s = build_p256_low_s_trace_v1([0; 32]).unwrap();
                            digest.base.iter_mut().for_each(|row| row.fill(F(83)));
                            result_x.base.iter_mut().for_each(|row| row.fill(F(89)));
                            low_s.base.iter_mut().for_each(|row| row.fill(F(97)));
                            base.try_push_v1(P256MainSignatureBaseV1 {
                                role: P256EcdsaRoleV1::WalletOwnership,
                                value: None,
                                scalar: None,
                                arithmetic: None,
                                window: None,
                                digest_reduction: Some(digest),
                                result_x_reduction: Some(result_x),
                                low_s: Some(low_s),
                                sink: None,
                            })
                            .unwrap();
                        }
                        // Exercise the production move operations, leaving inline
                        // private bytes behind None discriminants in the old owner.
                        for signature in base.iter_mut().take(2) {
                            bound
                                .try_push_v1(P256MainSignatureBoundV1 {
                                    role: signature.role,
                                    value: None,
                                    scalar: None,
                                    arithmetic: None,
                                    window: None,
                                    digest_reduction: signature.digest_reduction.take(),
                                    result_x_reduction: signature.result_x_reduction.take(),
                                    low_s: signature.low_s.take(),
                                    sink: None,
                                })
                                .unwrap();
                        }
                        assert!(base[0].digest_reduction.is_none());
                        match failure {
                            1 => return Err(()),
                            2 => panic!("exercise partial signature transfer unwind"),
                            _ => {}
                        }
                        drop(base);
                        // Clearing the old allocation must preserve transferred owners.
                        assert!(
                            bound[0]
                                .digest_reduction
                                .as_ref()
                                .unwrap()
                                .base
                                .iter()
                                .flatten()
                                .all(|value| *value == F(83))
                        );
                        drop(bound);
                        Ok(())
                    };
                    match failure {
                        0 => assert_eq!(operation(), Ok(())),
                        1 => assert_eq!(operation(), Err(())),
                        _ => assert!(std::panic::catch_unwind(operation).is_err()),
                    }
                })
            });
            assert_eq!(allocations.len(), 2);
            let expected_capacity = 9 * core::mem::size_of::<P256MainSignatureBaseV1>()
                + 7 * core::mem::size_of::<P256MainSignatureBoundV1>();
            assert!(allocations.iter().map(|item| item.bytes).sum::<usize>() >= expected_capacity);
            assert!(allocations.iter().all(|item| item.nonzero_after == 0));
            assert!(fields.iter().any(|item| item.nonzero_before > 0));
            assert!(fields.iter().all(|item| item.nonzero_after == 0));
        }
    }

    #[test]
    fn p256_main_bound_signature_owner_rejects_an_empty_valid_claim_set() {
        let buses = canonical_bus_terminal_claims();
        let certificate_or_crl = core::array::from_fn(|_| {
            let (cross_sources, sink) = canonical_terminal_chain(P256EcdsaRoleV1::CertificateOrCrl);
            ZkX509P256CertificatePrivateProductsV1 {
                buses,
                cross_sources: cross_sources.try_into().unwrap(),
                sink,
            }
        });
        let (cross_sources, sink) = canonical_terminal_chain(P256EcdsaRoleV1::WalletOwnership);
        let claims = ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(
            certificate_or_crl,
            ZkX509P256WalletPrivateProductsV1 {
                buses,
                cross_sources: cross_sources.try_into().unwrap(),
                sink,
            },
        )
        .unwrap();
        let source = P256MainBoundSourceV1 {
            signatures: Some(ClearingVecV1::from_vec_for_test_v1(Vec::new())),
            fixed: Some(P256MainVerifierFixedSourceV1::new_v1().unwrap()),
            post_base: Some(main_post_base_v1(29)),
            terminal_claims: Some(claims),
        };
        assert_eq!(
            source.ensure_bound_v1(),
            Err(P256AggregateAdapterErrorV1::Phase)
        );
    }

    #[test]
    fn owned_main_p256_erasure_observes_live_retained_source_allocations() {
        use super::super::private_table::inspection::observe_v1;
        let source = P256MainBaseSourceV1 {
            signatures: Some(ClearingVecV1::from_vec_for_test_v1(
                (0..P256_X5S1_SIGNATURES_V1)
                    .map(|_| P256MainSignatureBaseV1 {
                        role: P256EcdsaRoleV1::CertificateOrCrl,
                        value: None,
                        scalar: None,
                        arithmetic: Some(arithmetic_allocation_fixture_v1(
                            ZkX509P256ArithmeticTraceV1 {
                                fixed: Vec::new(),
                                base: vec![[F(37); P256_ARITHMETIC_BASE_WIDTH_V1]; 2],
                            },
                        )),
                        window: Some(P256WindowBatchStarkTraceV1 {
                            base: vec![[F(41); P256_WINDOW_BASE_WIDTH_V1]; 3],
                            aux: vec![[F(43); P256_WINDOW_STARK_AUX_WIDTH_V1]; 3],
                        }),
                        digest_reduction: None,
                        result_x_reduction: None,
                        low_s: None,
                        sink: None,
                    })
                    .collect(),
            )),
            fixed: None,
            bind_attempted: false,
        };
        let expected = 5
            * (2 * P256_ARITHMETIC_BASE_WIDTH_V1
                + 3 * P256_WINDOW_BASE_WIDTH_V1
                + 3 * P256_WINDOW_STARK_AUX_WIDTH_V1);
        let ((), observed) = observe_v1(|| drop(source));
        assert_eq!(
            observed
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            expected
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    #[test]
    fn p256_main_capacity_payload_counts_retained_matrices_and_schedule_clones() {
        use super::super::allocation_payload::vector_v1;
        let mut source = P256MainBaseSourceV1 {
            signatures: Some(ClearingVecV1::from_vec_for_test_v1(
                (0..P256_X5S1_SIGNATURES_V1)
                    .map(|_| P256MainSignatureBaseV1 {
                        role: P256EcdsaRoleV1::CertificateOrCrl,
                        value: None,
                        scalar: None,
                        arithmetic: Some(arithmetic_allocation_fixture_v1(
                            ZkX509P256ArithmeticTraceV1 {
                                fixed: Vec::with_capacity(5),
                                base: Vec::with_capacity(7),
                            },
                        )),
                        window: Some(P256WindowBatchStarkTraceV1 {
                            base: Vec::with_capacity(3),
                            aux: Vec::with_capacity(11),
                        }),
                        digest_reduction: None,
                        result_x_reduction: None,
                        low_s: None,
                        sink: None,
                    })
                    .collect(),
            )),
            fixed: None,
            bind_attempted: false,
        };
        let signatures = source.signatures.as_ref().unwrap();
        let signature_capacity = signatures.allocated_bytes_v1();
        let expected_matrices = signatures
            .iter()
            .map(|signature| {
                let arithmetic = signature.arithmetic.as_ref().unwrap();
                let window = signature.window.as_ref().unwrap();
                let P256MainArithmeticStorageV1::AllocationFixture(raw) = &arithmetic.trace else {
                    panic!("explicit allocation fixture");
                };
                let raw = raw.as_ref_v1().unwrap();
                vector_v1(&raw.fixed)
                    + vector_v1(&raw.base)
                    + arithmetic.fixed.allocated_heap_bytes_v1()
                    + vector_v1(&window.base)
                    + vector_v1(&window.aux)
            })
            .sum::<usize>();
        assert_eq!(
            source.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&source) + signature_capacity + expected_matrices
        );
        let forecast = P256MainBaseSourceV1::allocation_forecast_v1().unwrap();
        let scratch = P256MainBaseSourceV1::replay_scratch_forecast_v1().unwrap();
        assert!(scratch < super::super::allocation_payload::MAIN_SOURCE_SCRATCH_ALLOWANCE_BYTES_V1);
        eprintln!("canonical P256 source construction scratch forecast: {scratch}");
        let raw_arithmetic_overlap = 14_828 * 32 * 211 * 8;
        assert_eq!(raw_arithmetic_overlap, 800_949_248);
        let compact_arithmetic =
            5 * P256CompactArithmeticTraceV1::payload_forecast_v1(14_828).unwrap();
        assert_eq!(compact_arithmetic, 40_925_280);
        assert!(forecast > raw_arithmetic_overlap + compact_arithmetic);
        assert!(forecast < 5 * raw_arithmetic_overlap);
        assert!(forecast < super::super::allocation_payload::MAIN_NATIVE_SOURCE_ALLOWANCE_BYTES_V1);
        eprintln!("canonical P256 retained source allocation forecast: {forecast}");
        let fixed = P256MainVerifierFixedSourceV1::new_v1().unwrap();
        let fixed_payload = fixed.allocated_heap_bytes_v1();
        assert!(fixed_payload > 0);
        assert!(fixed.clone().allocated_heap_bytes_v1() <= fixed_payload);
        source.fixed = Some(fixed);
        assert_eq!(
            source.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&source)
                + signature_capacity
                + expected_matrices
                + fixed_payload
        );
        source.zeroize_private_v1();
        assert_eq!(
            source.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&source)
        );
        let bound = P256MainBoundSourceV1 {
            signatures: None,
            fixed: None,
            post_base: None,
            terminal_claims: None,
        };
        assert_eq!(
            bound.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&bound)
        );
        let mut bound = P256MainBoundSourceV1 {
            signatures: Some(ClearingVecV1::from_vec_for_test_v1(Vec::with_capacity(9))),
            fixed: None,
            post_base: None,
            terminal_claims: None,
        };
        assert_eq!(
            bound.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&bound)
                + bound.signatures.as_ref().unwrap().allocated_bytes_v1()
        );
        bound.zeroize_private_v1();
        assert_eq!(
            bound.allocated_payload_bytes_v1(),
            core::mem::size_of_val(&bound)
        );
    }

    use super::super::{
        credential_pre_aux::{
            ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, ZkX509CredentialMainPreAuxV1,
            derive_zk_x509_credential_pre_aux_binding_v1,
        },
        p256_air::{
            ZkX509P256ArithmeticKindV1, ZkX509P256ArithmeticOperationV1, ZkX509P256ModulusV1,
            build_zk_x509_p256_arithmetic_trace_v1, p256_arithmetic_operand_limbs_v1,
        },
        p256_cross_trace_bus::P256CrossTraceLaneChallengesV1,
        p256_reduction_air::{build_p256_low_s_trace_v1, build_p256_reduction_trace_v1},
        p256_scalar_bit_bus::P256ScalarBitBusLaneChallengesV1,
        p256_value_bus::{
            P256InitialValueBindingV1, P256InitialValueKindV1, P256LinkedOperationV1,
            P256ValueBusLaneChallengesV1, P256ValueBusStarkRowProviderV1, P256ValueIdV1,
            build_zk_x509_p256_value_bus_trace_v1,
        },
        stark::zk_x509_test_digest384_v1,
    };
    use super::*;
    use sha2::{Digest as _, Sha256};
    pub(super) fn main_post_base_v1(seed: u8) -> ZkX509CredentialMainPostBaseChallengesV1 {
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
    fn arithmetic_copy_challenges() -> P256ArithmeticCopyChallengesV1 {
        P256ArithmeticCopyChallengesV1 {
            lanes: core::array::from_fn(|lane| P256ArithmeticCopyLaneChallengesV1 {
                terms: core::array::from_fn(|term| F((lane * 17 + term + 2) as u64)),
            }),
        }
    }
    fn copy_sources(events: &[P256ArithmeticCopyEventFixedV1]) -> Vec<F> {
        events
            .iter()
            .map(|event| {
                if event.active == F::ONE {
                    event.address.add(F(101))
                } else {
                    F::ZERO
                }
            })
            .collect()
    }
    fn build_copy_endpoint(
        events: &[Vec<P256ArithmeticCopyEventFixedV1>],
        sources: &[Vec<F>],
        challenges: P256ArithmeticCopyChallengesV1,
    ) -> (Vec<Vec<F>>, [F; P256_ARITHMETIC_COPY_LANES_V1]) {
        assert_eq!(events.len(), sources.len());
        let mut terminal = [F::ONE; P256_ARITHMETIC_COPY_LANES_V1];
        for (row_events, row_sources) in events.iter().zip(sources) {
            let mut scratch = vec![F::ZERO; compact_aux_width_v1(row_events.len())];
            terminal = build_compact_arithmetic_copy_aux_row_v1(
                row_events,
                row_sources,
                terminal,
                [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1],
                challenges,
                &mut scratch,
            )
            .expect("first-pass copy product");
        }
        let mut running = [F::ONE; P256_ARITHMETIC_COPY_LANES_V1];
        let mut aux = Vec::with_capacity(events.len());
        for (row_events, row_sources) in events.iter().zip(sources) {
            let mut row = vec![F::ZERO; compact_aux_width_v1(row_events.len())];
            running = build_compact_arithmetic_copy_aux_row_v1(
                row_events,
                row_sources,
                running,
                terminal,
                challenges,
                &mut row,
            )
            .expect("second-pass copy product");
            aux.push(row);
        }
        assert_eq!(running, terminal);
        (aux, terminal)
    }
    fn copy_endpoint_residues(
        events: &[Vec<P256ArithmeticCopyEventFixedV1>],
        sources: &[Vec<F>],
        aux: &[Vec<F>],
        challenges: P256ArithmeticCopyChallengesV1,
    ) -> Vec<F> {
        let rows = events.len();
        assert_eq!(sources.len(), rows);
        assert_eq!(aux.len(), rows);
        (0..rows)
            .flat_map(|row| {
                evaluate_compact_arithmetic_copy_residues_v1(
                    &events[row],
                    &sources[row],
                    P256CrossTraceBoundaryFixedV1::for_row(row, rows).expect("copy boundary"),
                    &aux[row],
                    &aux[(row + 1) % rows],
                    challenges,
                )
                .expect("copy residues")
            })
            .collect()
    }
    fn one_event_fixture(
        rows: usize,
        active: usize,
    ) -> (Vec<Vec<P256ArithmeticCopyEventFixedV1>>, Vec<Vec<F>>) {
        let events: Vec<_> = (0..rows)
            .map(|row| {
                vec![if row < active {
                    P256ArithmeticCopyEventFixedV1::active_v1(row).expect("active copy event")
                } else {
                    P256ArithmeticCopyEventFixedV1::inactive_v1()
                }]
            })
            .collect();
        let sources = events.iter().map(|row| copy_sources(row)).collect();
        (events, sources)
    }
    fn three_event_fixture(
        rows: usize,
        active_rows: usize,
    ) -> (Vec<Vec<P256ArithmeticCopyEventFixedV1>>, Vec<Vec<F>>) {
        let events: Vec<Vec<P256ArithmeticCopyEventFixedV1>> = (0..rows)
            .map(|row| {
                (0..3)
                    .map(|slot| {
                        if row < active_rows {
                            P256ArithmeticCopyEventFixedV1::active_v1(row * 3 + slot)
                                .expect("active copy event")
                        } else {
                            P256ArithmeticCopyEventFixedV1::inactive_v1()
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let sources = events.iter().map(|row| copy_sources(row)).collect();
        (events, sources)
    }
    fn cross_challenges() -> P256CrossTraceChallengesV1 {
        P256CrossTraceChallengesV1 {
            lanes: core::array::from_fn(|lane| P256CrossTraceLaneChallengesV1 {
                terms: core::array::from_fn(|term| F((lane * 19 + term + 2) as u64)),
            }),
        }
    }
    fn scalar_challenges() -> P256ScalarBitBusChallengesV1 {
        P256ScalarBitBusChallengesV1 {
            lanes: core::array::from_fn(|lane| P256ScalarBitBusLaneChallengesV1 {
                terms: core::array::from_fn(|term| F((lane * 23 + term + 2) as u64)),
            }),
        }
    }
    fn selection_tail_residues_v1(
        current: &[F; P256_BINDING_SINK_BASE_WIDTH_V1],
        next: &[F; P256_BINDING_SINK_BASE_WIDTH_V1],
        fixed: &[F; P256_BINDING_SINK_FIXED_WIDTH_V1],
    ) -> Vec<F> {
        let aux = [F::ZERO; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1];
        let residues = evaluate_p256_binding_sink_aggregate_residues_v1(
            current,
            next,
            &aux,
            &aux,
            fixed,
            cross_challenges(),
        )
        .expect("selection residues");
        residues[P256_BINDING_SINK_CONSTRAINT_COUNT_V1 - 41..].to_vec()
    }
    fn selection_byte_row_v1(
        active: F,
        real: u8,
        selected: u8,
        dummy: u8,
        inactive_real: u8,
    ) -> (
        [F; P256_BINDING_SINK_BASE_WIDTH_V1],
        [F; P256_BINDING_SINK_FIXED_WIDTH_V1],
    ) {
        let mut base = [F::ZERO; P256_BINDING_SINK_BASE_WIDTH_V1];
        base[SINK_SELECTION_REAL_BASE] = F(u64::from(real));
        base[SINK_SELECTION_SELECTED_BASE] = F(u64::from(selected));
        base[SINK_SELECTION_ACTIVE_BASE] = active;
        write_byte_bits_v1(
            &mut base[SINK_SELECTION_REAL_BITS_BASE..SINK_SELECTION_REAL_BITS_BASE + 8],
            real,
        );
        write_byte_bits_v1(
            &mut base[SINK_SELECTION_SELECTED_BITS_BASE..SINK_SELECTION_SELECTED_BITS_BASE + 8],
            selected,
        );
        let mut fixed = [F::ZERO; P256_BINDING_SINK_FIXED_WIDTH_V1];
        fixed[SINK_SELECTION_BYTE_FIXED] = F::ONE;
        fixed[SINK_SELECTION_DUMMY_FIXED] = F(u64::from(dummy));
        fixed[SINK_SELECTION_INACTIVE_REAL_FIXED] = F(u64::from(inactive_real));
        (base, fixed)
    }
    #[test]
    fn real_input_projections_use_range_checked_unselected_key_and_digest_cells() {
        let (key_column, activity_column, key_start) = p256_real_key_input_columns_v1();
        let (digest_column, digest_start) = p256_real_digest_input_columns_v1();
        assert_ne!(key_column, SINK_SELECTION_SELECTED_BASE);
        assert_eq!(digest_column, key_column);
        assert_eq!(digest_start - key_start, 128);
        let fixed = P256BindingSinkFixedProviderV1::new_with_optional_certificate_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
            true,
        )
        .unwrap();
        for (start, count) in [(key_start, 64), (digest_start, 32)] {
            for row in start..start + count {
                let actual_fixed = fixed.row_v1(row).unwrap();
                assert_eq!(actual_fixed[SINK_SELECTION_BYTE_FIXED], F::ONE);
                let dummy = actual_fixed[SINK_SELECTION_DUMMY_FIXED].0 as u8;
                let inactive = actual_fixed[SINK_SELECTION_INACTIVE_REAL_FIXED].0 as u8;
                // Distinct real and selected cells are legal only while inactive:
                // the projection must retain the committed real source.
                let (base, _) = selection_byte_row_v1(F::ZERO, inactive, dummy, dummy, inactive);
                assert_eq!(base[key_column], F(u64::from(inactive)));
                assert_eq!(base[activity_column], F::ZERO);
                assert!(
                    selection_tail_residues_v1(&base, &base, &actual_fixed)
                        .iter()
                        .all(|residue| *residue == F::ZERO)
                );
                let mut changed = base;
                let changed_real = inactive ^ 1;
                changed[key_column] = F(u64::from(changed_real));
                write_byte_bits_v1(
                    &mut changed[SINK_SELECTION_REAL_BITS_BASE..SINK_SELECTION_REAL_BITS_BASE + 8],
                    changed_real,
                );
                assert!(
                    selection_tail_residues_v1(&changed, &changed, &actual_fixed)
                        .iter()
                        .any(|residue| *residue != F::ZERO)
                );
            }
        }
        assert_eq!(
            fixed.row_v1(digest_start + 32).unwrap()[SINK_SELECTION_SELECTOR_FIXED],
            F::ONE
        );
        assert_eq!(
            fixed.row_v1(key_start - 1).unwrap()[SINK_SELECTION_BYTE_FIXED],
            F::ZERO
        );
    }

    #[test]
    fn binding_sink_commits_all_321_optional_certificate_relations() {
        let mut caught = 0_usize;
        // One Boolean relation, committed on the verifier-fixed selector row.
        let mut selector = [F::ZERO; P256_BINDING_SINK_BASE_WIDTH_V1];
        selector[SINK_SELECTION_ACTIVE_BASE] = F::ONE;
        let mut selector_fixed = [F::ZERO; P256_BINDING_SINK_FIXED_WIDTH_V1];
        selector_fixed[SINK_SELECTION_SELECTOR_FIXED] = F::ONE;
        assert!(
            selection_tail_residues_v1(&selector, &selector, &selector_fixed)
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
        selector[SINK_SELECTION_ACTIVE_BASE] = F(2);
        assert!(
            selection_tail_residues_v1(&selector, &selector, &selector_fixed)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        caught += 1;
        for byte in 0..P256_INPUT_SELECTION_BYTES_V1 {
            let real = u8::try_from((byte * 73 + 19) % 251).expect("fixture byte");
            let dummy =
                p256_input_selection_byte_v1(&ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1, byte)
                    .expect("dummy byte");
            // All 160 selected-byte relations reject even a coordinated
            // selected-byte/range-bit substitution.
            let (active, active_fixed) = selection_byte_row_v1(F::ONE, real, real, dummy, 0);
            assert!(
                selection_tail_residues_v1(&active, &active, &active_fixed)
                    .iter()
                    .all(|residue| *residue == F::ZERO),
                "active byte {byte}",
            );
            let changed_selected = real ^ 1;
            let mut changed = active;
            changed[SINK_SELECTION_SELECTED_BASE] = F(u64::from(changed_selected));
            write_byte_bits_v1(
                &mut changed
                    [SINK_SELECTION_SELECTED_BITS_BASE..SINK_SELECTION_SELECTED_BITS_BASE + 8],
                changed_selected,
            );
            assert!(
                selection_tail_residues_v1(&changed, &changed, &active_fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "selected byte {byte}",
            );
            caught += 1;
            // All 160 inactive-source relations reject a coordinated
            // real-byte/range-bit substitution, including the digest word.
            let inactive_real = p256_inactive_real_byte_v1(byte).expect("inactive byte");
            let (inactive, inactive_fixed) =
                selection_byte_row_v1(F::ZERO, inactive_real, dummy, dummy, inactive_real);
            assert!(
                selection_tail_residues_v1(&inactive, &inactive, &inactive_fixed)
                    .iter()
                    .all(|residue| *residue == F::ZERO),
                "inactive byte {byte}",
            );
            let changed_real = inactive_real ^ 1;
            let mut changed = inactive;
            changed[SINK_SELECTION_REAL_BASE] = F(u64::from(changed_real));
            write_byte_bits_v1(
                &mut changed[SINK_SELECTION_REAL_BITS_BASE..SINK_SELECTION_REAL_BITS_BASE + 8],
                changed_real,
            );
            assert!(
                selection_tail_residues_v1(&changed, &changed, &inactive_fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "inactive real byte {byte}",
            );
            caught += 1;
        }
        assert_eq!(caught, 321);
    }
    #[test]
    fn binding_sink_selector_rejects_range_padding_transition_and_fixed_schedule_attacks() {
        let byte = 137;
        let dummy = p256_input_selection_byte_v1(&ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1, byte)
            .expect("dummy byte");
        let inactive_real = p256_inactive_real_byte_v1(byte).expect("inactive byte");
        let (base, fixed) =
            selection_byte_row_v1(F::ZERO, inactive_real, dummy, dummy, inactive_real);
        for column in SINK_SELECTION_REAL_BITS_BASE..SINK_SELECTION_SELECTED_BITS_BASE + 8 {
            let mut changed = base;
            changed[column] = F(2);
            assert!(
                selection_tail_residues_v1(&changed, &changed, &fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "range bit column {column}",
            );
        }
        let mut changed_fixed = fixed;
        changed_fixed[SINK_SELECTION_DUMMY_FIXED] =
            changed_fixed[SINK_SELECTION_DUMMY_FIXED].add(F::ONE);
        assert!(
            selection_tail_residues_v1(&base, &base, &changed_fixed)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut changed_fixed = fixed;
        changed_fixed[SINK_SELECTION_INACTIVE_REAL_FIXED] =
            changed_fixed[SINK_SELECTION_INACTIVE_REAL_FIXED].add(F::ONE);
        assert!(
            selection_tail_residues_v1(&base, &base, &changed_fixed)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut padding = [F::ZERO; P256_BINDING_SINK_BASE_WIDTH_V1];
        padding[SINK_SELECTION_ACTIVE_BASE] = F::ONE;
        let padding_fixed = [F::ZERO; P256_BINDING_SINK_FIXED_WIDTH_V1];
        for column in [
            SINK_SELECTION_REAL_BASE,
            SINK_SELECTION_SELECTED_BASE,
            SINK_SELECTION_REAL_BITS_BASE,
            SINK_SELECTION_SELECTED_BITS_BASE,
        ] {
            let mut changed = padding;
            changed[column] = F::ONE;
            assert!(
                selection_tail_residues_v1(&changed, &changed, &padding_fixed)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "padding column {column}",
            );
        }
        let mut transition_fixed = padding_fixed;
        transition_fixed[SINK_SELECTION_CONTINUE_FIXED] = F::ONE;
        let mut changed_next = padding;
        changed_next[SINK_SELECTION_ACTIVE_BASE] = F::ZERO;
        assert!(
            selection_tail_residues_v1(&padding, &changed_next, &transition_fixed)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
        let mut inactive_selector = [F::ZERO; P256_BINDING_SINK_BASE_WIDTH_V1];
        inactive_selector[SINK_SELECTION_ACTIVE_BASE] = F::ZERO;
        let mut mandatory_fixed = padding_fixed;
        mandatory_fixed[SINK_SELECTION_SELECTOR_FIXED] = F::ONE;
        mandatory_fixed[SINK_SELECTION_REQUIRE_ACTIVE_FIXED] = F::ONE;
        assert!(
            selection_tail_residues_v1(&inactive_selector, &inactive_selector, &mandatory_fixed,)
                .iter()
                .any(|residue| *residue != F::ZERO)
        );
    }
    #[test]
    fn only_certificate_sinks_can_use_the_verifier_positioned_optional_schedule() {
        assert!(
            P256BindingSinkFixedProviderV1::new_with_optional_certificate_v1(
                P256EcdsaRoleV1::CertificateOrCrl,
                true,
            )
            .is_ok()
        );
        assert_eq!(
            P256BindingSinkFixedProviderV1::new_with_optional_certificate_v1(
                P256EcdsaRoleV1::WalletOwnership,
                true,
            )
            .map(|_| ()),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
    }
    type CrossFixtureV1 = (
        Vec<Vec<P256CrossTraceEventFixedV1>>,
        Vec<Vec<F>>,
        Vec<Vec<F>>,
        [F; P256_CROSS_TRACE_LANES_V1],
        [F; P256_CROSS_TRACE_LANES_V1],
    );
    fn cross_fixture(event_slots: usize) -> CrossFixtureV1 {
        let rows = 8;
        let events: Vec<Vec<_>> = (0..rows)
            .map(|row| {
                (0..event_slots)
                    .map(|slot| {
                        if row < 2 {
                            active_cross_event_v1(
                                P256CrossTraceEndpointV1::External,
                                row * event_slots + slot,
                            )
                            .expect("cross event")
                        } else {
                            P256CrossTraceEventFixedV1::inactive()
                        }
                    })
                    .collect()
            })
            .collect();
        let sources: Vec<Vec<_>> = events
            .iter()
            .map(|events| {
                events
                    .iter()
                    .map(|event| {
                        if event.active == F::ONE {
                            event.address.add(F(211))
                        } else {
                            F::ZERO
                        }
                    })
                    .collect()
            })
            .collect();
        let start = [F(5), F(7), F(11), F(13)];
        let challenges = cross_challenges();
        let mut terminal = start;
        for (events, sources) in events.iter().zip(&sources) {
            let mut scratch = vec![F::ZERO; compact_aux_width_v1(event_slots)];
            terminal = build_compact_cross_aux_row_v1(
                events,
                sources,
                terminal,
                [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                challenges,
                &mut scratch,
            )
            .expect("cross first pass");
        }
        let mut running = start;
        let mut aux = Vec::with_capacity(rows);
        for (events, sources) in events.iter().zip(&sources) {
            let mut row = vec![F::ZERO; compact_aux_width_v1(event_slots)];
            running = build_compact_cross_aux_row_v1(
                events, sources, running, terminal, challenges, &mut row,
            )
            .expect("cross second pass");
            aux.push(row);
        }
        assert_eq!(running, terminal);
        (events, sources, aux, start, terminal)
    }
    fn cross_fixture_residues(
        events: &[Vec<P256CrossTraceEventFixedV1>],
        sources: &[Vec<F>],
        aux: &[Vec<F>],
        start: [F; P256_CROSS_TRACE_LANES_V1],
    ) -> Vec<F> {
        let rows = events.len();
        (0..rows)
            .flat_map(|row| {
                evaluate_compact_cross_residues_v1(
                    &events[row],
                    &sources[row],
                    P256CrossTraceBoundaryFixedV1::for_row(row, rows).expect("cross boundary"),
                    &aux[row],
                    &aux[(row + 1) % rows],
                    start,
                    cross_challenges(),
                )
                .expect("cross residues")
            })
            .collect()
    }
    fn assert_aux_column_transpose_v1<const WIDTH: usize>(rows: Vec<Vec<F>>) {
        let rows: Vec<[F; WIDTH]> = rows
            .into_iter()
            .map(|row| row.try_into().expect("fixture width"))
            .collect();
        assert_eq!(rows.len(), 8);
        for column in 0..WIDTH {
            let mut replay = rows.iter().copied();
            let mut output = [F::ZERO; 8];
            fill_aggregate_aux_column_v1(8, column, &mut output, || Ok(replay.next()))
                .expect("column replay");
            assert_eq!(
                output,
                core::array::from_fn(|row| rows[row][column]),
                "column {column}/{WIDTH}",
            );
        }
        let mut replay = rows.iter().copied();
        assert_eq!(
            fill_aggregate_aux_column_v1(8, WIDTH, &mut [F::ZERO; 8], || Ok(replay.next())),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        let mut replay = rows.iter().copied();
        assert_eq!(
            fill_aggregate_aux_column_v1(8, 0, &mut [F::ZERO; 7], || Ok(replay.next())),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        let mut short = rows[..7].iter().copied();
        assert_eq!(
            fill_aggregate_aux_column_v1(8, 0, &mut [F::ZERO; 8], || Ok(short.next())),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        let mut extra = rows.iter().copied().chain(core::iter::once(rows[0]));
        assert_eq!(
            fill_aggregate_aux_column_v1(8, 0, &mut [F::ZERO; 8], || Ok(extra.next())),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
    }
    #[test]
    fn aggregate_column_destinations_are_transactional_and_fail_closed() {
        let ((), observed) = super::super::private_table::inspection::observe_v1(
            aggregate_column_destinations_are_transactional_and_fail_closed_body_v1,
        );
        assert!(observed.iter().any(|item| item.nonzero_before > 0));
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }
    fn aggregate_column_destinations_are_transactional_and_fail_closed_body_v1() {
        const SENTINEL: F = F(0x5a5a);
        // Shape and column-index failures happen before the destination guard
        // exists, so caller-owned storage remains byte-for-byte untouched.
        let mut invalid_row_column = [SENTINEL; 8];
        assert_eq!(
            fill_aggregate_row_column_v1::<2>(8, 2, &mut invalid_row_column, |_| panic!(
                "prevalidation must not call the row source"
            ),),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(invalid_row_column, [SENTINEL; 8]);
        let mut invalid_row_length = [SENTINEL; 7];
        assert_eq!(
            fill_aggregate_row_column_v1::<2>(8, 0, &mut invalid_row_length, |_| panic!(
                "prevalidation must not call the row source"
            ),),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(invalid_row_length, [SENTINEL; 7]);
        let mut non_power_of_two = [SENTINEL; 6];
        assert_eq!(
            fill_aggregate_row_column_v1::<2>(6, 0, &mut non_power_of_two, |_| panic!(
                "prevalidation must not call the row source"
            ),),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(non_power_of_two, [SENTINEL; 6]);
        let mut invalid_aux_column = [SENTINEL; 8];
        assert_eq!(
            fill_aggregate_aux_column_v1::<2>(8, 2, &mut invalid_aux_column, || panic!(
                "prevalidation must not call the auxiliary source"
            ),),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(invalid_aux_column, [SENTINEL; 8]);
        let mut invalid_aux_length = [SENTINEL; 7];
        assert_eq!(
            fill_aggregate_aux_column_v1::<2>(8, 0, &mut invalid_aux_length, || panic!(
                "prevalidation must not call the auxiliary source"
            ),),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(invalid_aux_length, [SENTINEL; 7]);
        // Once a source has begun populating a column, every error path clears
        // the complete destination instead of retaining a successful prefix.
        let mut row_error = [SENTINEL; 8];
        assert_eq!(
            fill_aggregate_row_column_v1::<2>(8, 1, &mut row_error, |row| {
                if row == 3 {
                    Err(P256AggregateAdapterErrorV1::Source)
                } else {
                    Ok([F(row as u64), F((row + 17) as u64)])
                }
            }),
            Err(P256AggregateAdapterErrorV1::Source)
        );
        assert_eq!(row_error, [F::ZERO; 8]);
        let mut aux_call = 0_usize;
        let mut aux_error = [SENTINEL; 8];
        assert_eq!(
            fill_aggregate_aux_column_v1::<2>(8, 1, &mut aux_error, || {
                let call = aux_call;
                aux_call += 1;
                if call == 3 {
                    Err(P256AggregateAdapterErrorV1::Source)
                } else {
                    Ok(Some([F(call as u64), F((call + 29) as u64)]))
                }
            }),
            Err(P256AggregateAdapterErrorV1::Source)
        );
        assert_eq!(aux_error, [F::ZERO; 8]);
        let rows: [[F; 2]; 8] =
            core::array::from_fn(|row| [F((row + 1) as u64), F((row + 101) as u64)]);
        let mut short = rows[..7].iter().copied();
        let mut short_output = [SENTINEL; 8];
        assert_eq!(
            fill_aggregate_aux_column_v1(8, 0, &mut short_output, || Ok(short.next())),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(short_output, [F::ZERO; 8]);
        let mut extra = rows.iter().copied().chain(core::iter::once(rows[0]));
        let mut extra_output = [SENTINEL; 8];
        assert_eq!(
            fill_aggregate_aux_column_v1(8, 0, &mut extra_output, || Ok(extra.next())),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(extra_output, [F::ZERO; 8]);
        // A complete successful replay commits the exact transposed column.
        let mut row_success = [SENTINEL; 8];
        fill_aggregate_row_column_v1::<2>(8, 1, &mut row_success, |row| Ok(rows[row]))
            .expect("complete row column");
        assert_eq!(row_success, rows.map(|row| row[1]));
        let mut replay = rows.iter().copied();
        let mut aux_success = [SENTINEL; 8];
        fill_aggregate_aux_column_v1(8, 0, &mut aux_success, || Ok(replay.next()))
            .expect("complete auxiliary column");
        assert_eq!(aux_success, rows.map(|row| row[0]));
    }
    #[test]
    fn aggregate_private_zeroization_is_idempotent_and_preserves_fixed_topology() {
        let ((), observations) = super::super::private_table::inspection::observe_v1(
            aggregate_private_zeroization_is_idempotent_and_preserves_fixed_topology_body_v1,
        );
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
    fn aggregate_private_zeroization_is_idempotent_and_preserves_fixed_topology_body_v1() {
        const SENTINEL: F = F(0x6b6b);
        let reduction_trace =
            build_p256_reduction_trace_v1([0_u8; 32]).expect("canonical reduction");
        let mut reduction = P256ReductionAggregateAuxStreamV1::new_v1(
            P256ReductionAggregateRoleV1::Digest,
            &reduction_trace,
            [F(3), F(5), F(7), F(11)],
            cross_challenges(),
        )
        .expect("reduction stream");
        let reduction_fixed_first = reduction
            .fixed_row_v1(0)
            .expect("first reduction fixed row");
        let reduction_fixed_last = reduction
            .fixed_row_v1(P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 - 1)
            .expect("last reduction fixed row");
        let reduction_base = reduction.base_row_v1(0).expect("reduction base row");
        assert!(!reduction.private_is_zeroized_v1());
        reduction.zeroize_private_v1();
        reduction.zeroize_private_v1();
        assert!(reduction.private_is_zeroized_v1());
        assert_eq!(
            reduction.fixed_row_v1(0).expect("fixed after zeroize"),
            reduction_fixed_first
        );
        assert_eq!(
            reduction
                .fixed_row_v1(P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 - 1)
                .expect("padding fixed after zeroize"),
            reduction_fixed_last
        );
        assert_eq!(
            reduction.base_row_v1(0).expect("base after zeroize"),
            reduction_base
        );
        assert_eq!(reduction.next_aux_row_v1(), Ok(None));
        let mut reduction_output = [SENTINEL; P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1];
        assert_eq!(
            reduction.fill_aux_column_v1(0, &mut reduction_output),
            Err(P256AggregateAdapterErrorV1::Challenge)
        );
        assert_eq!(
            reduction_output,
            [SENTINEL; P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1]
        );
        let low_s_trace = build_p256_low_s_trace_v1([0_u8; 32]).expect("canonical low-S");
        let mut low_s = P256LowSAggregateAuxStreamV1::new_v1(
            P256EcdsaRoleV1::WalletOwnership,
            &low_s_trace,
            [F(13), F(17), F(19), F(23)],
            cross_challenges(),
        )
        .expect("low-S stream");
        let low_s_fixed_first = low_s.fixed_row_v1(0).expect("first low-S fixed row");
        let low_s_fixed_last = low_s
            .fixed_row_v1(P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 - 1)
            .expect("last low-S fixed row");
        let low_s_base = low_s.base_row_v1(0).expect("low-S base row");
        assert!(!low_s.private_is_zeroized_v1());
        low_s.zeroize_private_v1();
        low_s.zeroize_private_v1();
        assert!(low_s.private_is_zeroized_v1());
        assert_eq!(
            low_s.fixed_row_v1(0).expect("fixed after zeroize"),
            low_s_fixed_first
        );
        assert_eq!(
            low_s
                .fixed_row_v1(P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 - 1)
                .expect("padding fixed after zeroize"),
            low_s_fixed_last
        );
        assert_eq!(
            low_s.base_row_v1(0).expect("base after zeroize"),
            low_s_base
        );
        assert_eq!(low_s.next_aux_row_v1(), Ok(None));
        let mut low_s_output = [SENTINEL; P256_LOW_S_AGGREGATE_TRACE_SIZE_V1];
        assert_eq!(
            low_s.fill_aux_column_v1(0, &mut low_s_output),
            Err(P256AggregateAdapterErrorV1::Challenge)
        );
        assert_eq!(low_s_output, [SENTINEL; P256_LOW_S_AGGREGATE_TRACE_SIZE_V1]);
    }
    type ScalarFixtureV1 = (
        Vec<Vec<P256ScalarSourceEventFixedV1>>,
        Vec<Vec<F>>,
        Vec<Vec<F>>,
        [F; P256_SCALAR_BIT_BUS_LANES_V1],
    );
    fn scalar_fixture(event_slots: usize) -> ScalarFixtureV1 {
        let rows = 8;
        let events: Vec<Vec<_>> = (0..rows)
            .map(|row| {
                (0..event_slots)
                    .map(|slot| {
                        if row < 2 {
                            P256ScalarSourceEventFixedV1 {
                                active: F::ONE,
                                scalar: F(u64::try_from(row + 1).expect("scalar")),
                                window: F(u64::try_from(slot / 4 + 1).expect("window")),
                                bit: F(u64::try_from(slot % 4 + 1).expect("bit")),
                            }
                        } else {
                            P256ScalarSourceEventFixedV1::inactive_v1()
                        }
                    })
                    .collect()
            })
            .collect();
        let sources: Vec<Vec<_>> = events
            .iter()
            .map(|events| {
                events
                    .iter()
                    .map(|event| {
                        if event.active == F::ONE {
                            event
                                .scalar
                                .mul(F(17))
                                .add(event.window.mul(F(5)))
                                .add(event.bit)
                        } else {
                            F::ZERO
                        }
                    })
                    .collect()
            })
            .collect();
        let challenges = scalar_challenges();
        let mut terminal = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        for (events, sources) in events.iter().zip(&sources) {
            let mut scratch = vec![F::ZERO; compact_aux_width_v1(event_slots)];
            terminal = build_compact_scalar_aux_row_v1(
                events,
                sources,
                terminal,
                [F::ZERO; P256_SCALAR_BIT_BUS_LANES_V1],
                challenges,
                &mut scratch,
            )
            .expect("scalar first pass");
        }
        let mut running = [F::ONE; P256_SCALAR_BIT_BUS_LANES_V1];
        let mut aux = Vec::with_capacity(rows);
        for (events, sources) in events.iter().zip(&sources) {
            let mut row = vec![F::ZERO; compact_aux_width_v1(event_slots)];
            running = build_compact_scalar_aux_row_v1(
                events, sources, running, terminal, challenges, &mut row,
            )
            .expect("scalar second pass");
            aux.push(row);
        }
        assert_eq!(running, terminal);
        (events, sources, aux, terminal)
    }
    fn scalar_fixture_residues(
        events: &[Vec<P256ScalarSourceEventFixedV1>],
        sources: &[Vec<F>],
        aux: &[Vec<F>],
    ) -> Vec<F> {
        let rows = events.len();
        (0..rows)
            .flat_map(|row| {
                evaluate_compact_scalar_residues_v1(
                    &events[row],
                    &sources[row],
                    P256CrossTraceBoundaryFixedV1::for_row(row, rows).expect("scalar boundary"),
                    &aux[row],
                    &aux[(row + 1) % rows],
                    scalar_challenges(),
                )
                .expect("scalar residues")
            })
            .collect()
    }
    #[test]
    fn aggregate_shapes_descriptor_and_copy_challenges_are_exact() {
        assert_eq!(
            [
                P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
                P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
                P256_WINDOW_AGGREGATE_TRACE_SIZE_V1,
                P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
                P256_LOW_S_AGGREGATE_TRACE_SIZE_V1,
                P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
                P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_SIZE_V1,
            ],
            [1 << 19, 1 << 19, 1 << 16, 1 << 5, 1 << 5, 1 << 16, 1 << 8]
        );
        assert_eq!(P256_ARITHMETIC_COPY_CELLS_V1, 711_744);
        assert_eq!(P256_PERMUTATION_FACTOR_CARDINALITY_BOUND_V1, 1 << 20);
        assert_eq!(P256_PERMUTATION_ARGUMENTS_PER_SIGNATURE_V1, 5);
        assert_eq!(P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1, 4);
        assert_eq!(P256_X5S1_WALLET_SIGNATURES_V1, 1);
        assert_eq!(P256_X5S1_SIGNATURES_V1, 5);
        assert_eq!(P256_X5S1_PERMUTATION_ARGUMENTS_V1, 25);
        assert_eq!(P256_PERMUTATION_LOCAL_COLLISION_BITS_V1, 176);
        assert_eq!(P256_X5S1_PERMUTATION_UNION_COLLISION_BITS_V1, 171);
        assert_eq!(
            (
                P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
                P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1,
                P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
                P256_VALUE_EXECUTION_AGGREGATE_CONSTRAINT_COUNT_V1,
            ),
            (34, 116, 46, 210)
        );
        assert_eq!(
            (
                P256_ARITHMETIC_BASE_WIDTH_V1,
                P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1,
                P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
                P256_ARITHMETIC_AGGREGATE_CONSTRAINT_COUNT_V1,
            ),
            (211, 72, 134, 455)
        );
        assert!(ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_V1.ends_with(b"first-release"));
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_V1)),
            ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_SHA256_V1
        );
        let challenges = arithmetic_copy_challenges();
        challenges.validate_v1().expect("valid copy challenges");
        for lane in 0..P256_ARITHMETIC_COPY_LANES_V1 {
            for term in 0..P256_ARITHMETIC_COPY_CHALLENGE_TERMS_V1 {
                let mut zero = challenges;
                zero.lanes[lane].terms[term] = F::ZERO;
                assert_eq!(
                    zero.validate_v1(),
                    Err(P256AggregateAdapterErrorV1::Challenge)
                );
                let mut duplicate = challenges;
                duplicate.lanes[lane].terms[term] = challenges.lanes[0].terms[0];
                if lane != 0 || term != 0 {
                    assert_eq!(
                        duplicate.validate_v1(),
                        Err(P256AggregateAdapterErrorV1::Challenge)
                    );
                }
            }
        }
        let mut noncanonical = challenges;
        noncanonical.lanes[2].terms[2] = F(u64::MAX);
        assert_eq!(
            noncanonical.validate_v1(),
            Err(P256AggregateAdapterErrorV1::Challenge)
        );
        let labels: Vec<_> = P256_ARITHMETIC_COPY_CHALLENGE_LABELS_V1
            .iter()
            .flatten()
            .copied()
            .collect();
        for (index, label) in labels.iter().enumerate() {
            assert!(!labels[..index].contains(label));
        }
    }
    #[test]
    fn every_fixed_source_address_is_injective_complete_and_padded() {
        let mut value_seen = vec![false; P256_ARITHMETIC_COPY_CELLS_V1];
        let mut arithmetic_seen = vec![false; P256_ARITHMETIC_COPY_CELLS_V1];
        let mut window_seen = vec![false; WINDOW_EXTERNAL_EVENTS];
        let mut window_scalar_seen = [false; 512];
        let mut arithmetic_scalar_seen = [false; 512];
        for row in 0..P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 {
            for value_event in value_arithmetic_copy_events_v1(row, P256_ARITHMETIC_OPERATIONS_V1)
                .expect("value copy schedule")
            {
                if value_event.active == F::ONE {
                    let address = usize::try_from(value_event.address.0).expect("value address");
                    assert!(!value_seen[address], "duplicate value address {address}");
                    value_seen[address] = true;
                } else {
                    assert_eq!(value_event.address, F::ZERO);
                }
            }
        }
        for row in 0..P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
            for event in arithmetic_value_copy_events_v1(
                row,
                P256_ARITHMETIC_OPERATIONS_V1 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            )
            .expect("arithmetic copy schedule")
            {
                if event.active == F::ONE {
                    let address = usize::try_from(event.address.0).expect("arithmetic address");
                    assert!(
                        !arithmetic_seen[address],
                        "duplicate arithmetic address {address}"
                    );
                    arithmetic_seen[address] = true;
                } else {
                    assert_eq!(event.address, F::ZERO);
                }
            }
            for event in arithmetic_scalar_events_v1(row).expect("arithmetic scalar schedule") {
                if event.active == F::ONE {
                    let address = usize::try_from(
                        event
                            .scalar
                            .sub(F::ONE)
                            .mul(F(256))
                            .add(event.window.sub(F::ONE).mul(F(4)))
                            .add(event.bit.sub(F::ONE))
                            .0,
                    )
                    .expect("arithmetic scalar address");
                    assert!(!arithmetic_scalar_seen[address]);
                    arithmetic_scalar_seen[address] = true;
                }
            }
        }
        for row in 0..P256_WINDOW_AGGREGATE_TRACE_SIZE_V1 {
            for event in window_cross_events_v1(row).expect("window schedule") {
                if event.active == F::ONE {
                    assert_eq!(event.endpoint, F(2));
                    let address = usize::try_from(event.address.0).expect("window address");
                    assert!(!window_seen[address], "duplicate window address {address}");
                    window_seen[address] = true;
                } else {
                    assert_eq!(event.endpoint, F::ZERO);
                    assert_eq!(event.address, F::ZERO);
                }
            }
            let window_scalar = window_scalar_event_v1(row).expect("window scalar schedule");
            if window_scalar.active == F::ONE {
                let address = usize::try_from(
                    window_scalar
                        .scalar
                        .sub(F::ONE)
                        .mul(F(256))
                        .add(window_scalar.window.sub(F::ONE).mul(F(4)))
                        .add(window_scalar.bit.sub(F::ONE))
                        .0,
                )
                .expect("window scalar address");
                assert!(!window_scalar_seen[address]);
                window_scalar_seen[address] = true;
            }
        }
        assert!(value_seen.into_iter().all(core::convert::identity));
        assert!(arithmetic_seen.into_iter().all(core::convert::identity));
        assert!(window_seen.into_iter().all(core::convert::identity));
        assert_eq!(window_scalar_seen, [true; 512]);
        assert_eq!(arithmetic_scalar_seen, [true; 512]);
        for row in 0..P256_REDUCTION_ROWS_V1 {
            let digest = reduction_cross_events_v1(P256ReductionAggregateRoleV1::Digest, row)
                .expect("digest reduction schedule");
            assert_eq!(
                digest[0],
                active_cross_event_v1(P256CrossTraceEndpointV1::DigestInput, row).unwrap()
            );
            assert_eq!(
                digest[1].address,
                F(u64::try_from(DIGEST_REDUCTION_OUTPUT_ADDRESS + row).expect("digest address"))
            );
            let result = reduction_cross_events_v1(P256ReductionAggregateRoleV1::ResultX, row)
                .expect("result reduction schedule");
            assert_eq!(
                result[0].address,
                F(u64::try_from(RESULT_X_REDUCTION_SOURCE_ADDRESS + row)
                    .expect("result source address"))
            );
            assert_eq!(
                result[1].address,
                F(u64::try_from(RESULT_X_REDUCTION_OUTPUT_ADDRESS + row)
                    .expect("result output address"))
            );
            assert_eq!(
                low_s_cross_event_v1(row).expect("low-s schedule").address,
                F(u64::try_from(LOW_S_ADDRESS + row).expect("low-s address"))
            );
        }
        for row in [
            P256_REDUCTION_ROWS_V1,
            P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1 - 1,
        ] {
            assert_eq!(
                reduction_cross_events_v1(P256ReductionAggregateRoleV1::Digest, row)
                    .expect("digest padding"),
                [P256CrossTraceEventFixedV1::inactive(); 2]
            );
            assert_eq!(
                reduction_cross_events_v1(P256ReductionAggregateRoleV1::ResultX, row)
                    .expect("result padding"),
                [P256CrossTraceEventFixedV1::inactive(); 2]
            );
        }
        for row in [
            P256_REDUCTION_ROWS_V1,
            P256_LOW_S_AGGREGATE_TRACE_SIZE_V1 - 1,
        ] {
            assert_eq!(
                low_s_cross_event_v1(row).expect("low-s padding"),
                P256CrossTraceEventFixedV1::inactive()
            );
        }
        assert_eq!(
            P256CrossTraceBoundaryFixedV1::for_row(0, P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1)
                .expect("first boundary"),
            P256CrossTraceBoundaryFixedV1 {
                first: F::ONE,
                last: F::ZERO,
                continuation: F::ONE,
            }
        );
        assert_eq!(
            P256CrossTraceBoundaryFixedV1::for_row(
                P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 - 1,
                P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
            )
            .expect("last boundary"),
            P256CrossTraceBoundaryFixedV1 {
                first: F::ZERO,
                last: F::ONE,
                continuation: F::ZERO,
            }
        );
        assert!(
            value_arithmetic_copy_events_v1(P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1, 1).is_err()
        );
        assert!(
            arithmetic_value_copy_events_v1(P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1, 1).is_err()
        );
        assert!(window_cross_events_v1(P256_WINDOW_AGGREGATE_TRACE_SIZE_V1).is_err());
        assert!(window_scalar_event_v1(P256_WINDOW_AGGREGATE_TRACE_SIZE_V1).is_err());
        assert!(low_s_cross_event_v1(P256_LOW_S_AGGREGATE_TRACE_SIZE_V1).is_err());
    }
    #[test]
    fn arithmetic_copy_products_reject_all_source_aux_padding_and_opening_mutations() {
        let challenges = arithmetic_copy_challenges();
        let (value_events, value_sources) = one_event_fixture(8, 6);
        let (arithmetic_events, arithmetic_sources) = three_event_fixture(8, 2);
        let (value_aux, value_terminal) =
            build_copy_endpoint(&value_events, &value_sources, challenges);
        let (arithmetic_aux, arithmetic_terminal) =
            build_copy_endpoint(&arithmetic_events, &arithmetic_sources, challenges);
        assert_eq!(value_terminal, arithmetic_terminal);
        assert!(
            copy_endpoint_residues(&value_events, &value_sources, &value_aux, challenges)
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
        assert!(
            copy_endpoint_residues(
                &arithmetic_events,
                &arithmetic_sources,
                &arithmetic_aux,
                challenges,
            )
            .iter()
            .all(|residue| *residue == F::ZERO)
        );
        assert_eq!(
            evaluate_p256_arithmetic_copy_terminal_openings_v1(value_terminal, arithmetic_terminal,),
            [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1]
        );
        for (events, sources, aux, boundary_rows) in [
            (&value_events, &value_sources, &value_aux, [0_usize, 6, 7]),
            (
                &arithmetic_events,
                &arithmetic_sources,
                &arithmetic_aux,
                [0_usize, 2, 7],
            ),
        ] {
            for row in boundary_rows {
                for column in 0..aux[row].len() {
                    let mut changed = aux.clone();
                    changed[row][column] = changed[row][column].add(F::ONE);
                    assert!(
                        copy_endpoint_residues(events, sources, &changed, challenges)
                            .iter()
                            .any(|residue| *residue != F::ZERO),
                        "row {row}, aux column {column}"
                    );
                }
            }
            for row in 0..events.len() {
                for slot in 0..events[row].len() {
                    if events[row][slot].active != F::ONE {
                        continue;
                    }
                    let mut changed = sources.clone();
                    changed[row][slot] = changed[row][slot].add(F::ONE);
                    assert!(
                        copy_endpoint_residues(events, &changed, aux, challenges)
                            .iter()
                            .any(|residue| *residue != F::ZERO),
                        "row {row}, source slot {slot}"
                    );
                    for coordinate in 0..2 {
                        let mut changed_events = events.clone();
                        if coordinate == 0 {
                            changed_events[row][slot].active = F::ZERO;
                        } else {
                            changed_events[row][slot].address =
                                changed_events[row][slot].address.add(F::ONE);
                        }
                        assert!(
                            copy_endpoint_residues(&changed_events, sources, aux, challenges,)
                                .iter()
                                .any(|residue| *residue != F::ZERO),
                            "row {row}, fixed slot {slot}, coordinate {coordinate}"
                        );
                    }
                }
            }
        }
        let mut coordinated_sources = value_sources.clone();
        coordinated_sources[3][0] = coordinated_sources[3][0].add(F::ONE);
        let (coordinated_aux, coordinated_terminal) =
            build_copy_endpoint(&value_events, &coordinated_sources, challenges);
        assert!(
            copy_endpoint_residues(
                &value_events,
                &coordinated_sources,
                &coordinated_aux,
                challenges,
            )
            .iter()
            .all(|residue| *residue == F::ZERO)
        );
        assert!(
            evaluate_p256_arithmetic_copy_terminal_openings_v1(
                coordinated_terminal,
                arithmetic_terminal,
            )
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
        for lane in 0..P256_ARITHMETIC_COPY_LANES_V1 {
            let mut forged = arithmetic_terminal;
            forged[lane] = forged[lane].add(F::ONE);
            let residues =
                evaluate_p256_arithmetic_copy_terminal_openings_v1(value_terminal, forged);
            assert_ne!(residues[lane], F::ZERO);
        }
    }
    #[test]
    fn all_compact_cross_and_scalar_adapter_widths_reject_every_committed_mutation() {
        for event_slots in [1_usize, 2, 3, 6] {
            let (events, sources, aux, start, _) = cross_fixture(event_slots);
            assert!(
                cross_fixture_residues(&events, &sources, &aux, start)
                    .iter()
                    .all(|residue| *residue == F::ZERO)
            );
            for row in [0_usize, 2, 7] {
                for column in 0..aux[row].len() {
                    let mut changed = aux.clone();
                    changed[row][column] = changed[row][column].add(F::ONE);
                    assert!(
                        cross_fixture_residues(&events, &sources, &changed, start)
                            .iter()
                            .any(|residue| *residue != F::ZERO),
                        "cross N={event_slots}, row {row}, aux column {column}",
                    );
                }
            }
            for row in 0..2 {
                for slot in 0..event_slots {
                    let mut changed_sources = sources.clone();
                    changed_sources[row][slot] = changed_sources[row][slot].add(F::ONE);
                    assert!(
                        cross_fixture_residues(&events, &changed_sources, &aux, start)
                            .iter()
                            .any(|residue| *residue != F::ZERO),
                        "cross N={event_slots}, row {row}, source {slot}",
                    );
                    for coordinate in 0..3 {
                        let mut changed_events = events.clone();
                        match coordinate {
                            0 => changed_events[row][slot].active = F::ZERO,
                            1 => {
                                changed_events[row][slot].endpoint =
                                    changed_events[row][slot].endpoint.add(F::ONE);
                            }
                            2 => {
                                changed_events[row][slot].address =
                                    changed_events[row][slot].address.add(F::ONE);
                            }
                            _ => unreachable!(),
                        }
                        assert!(
                            cross_fixture_residues(&changed_events, &sources, &aux, start,)
                                .iter()
                                .any(|residue| *residue != F::ZERO),
                            "cross N={event_slots}, row {row}, fixed {slot}/{coordinate}",
                        );
                    }
                }
            }
            let mut inactive_events = events.clone();
            inactive_events[2][0].active = F::ONE;
            assert!(
                cross_fixture_residues(&inactive_events, &sources, &aux, start)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "cross N={event_slots}, inactive selector",
            );
        }
        for event_slots in [1_usize, 8] {
            let (events, sources, aux, _) = scalar_fixture(event_slots);
            assert!(
                scalar_fixture_residues(&events, &sources, &aux)
                    .iter()
                    .all(|residue| *residue == F::ZERO)
            );
            for row in [0_usize, 2, 7] {
                for column in 0..aux[row].len() {
                    let mut changed = aux.clone();
                    changed[row][column] = changed[row][column].add(F::ONE);
                    assert!(
                        scalar_fixture_residues(&events, &sources, &changed)
                            .iter()
                            .any(|residue| *residue != F::ZERO),
                        "scalar N={event_slots}, row {row}, aux column {column}",
                    );
                }
            }
            for row in 0..2 {
                for slot in 0..event_slots {
                    let mut changed_sources = sources.clone();
                    changed_sources[row][slot] = changed_sources[row][slot].add(F::ONE);
                    assert!(
                        scalar_fixture_residues(&events, &changed_sources, &aux)
                            .iter()
                            .any(|residue| *residue != F::ZERO),
                        "scalar N={event_slots}, row {row}, source {slot}",
                    );
                    for coordinate in 0..4 {
                        let mut changed_events = events.clone();
                        let event = &mut changed_events[row][slot];
                        match coordinate {
                            0 => event.active = F::ZERO,
                            1 => event.scalar = event.scalar.add(F::ONE),
                            2 => event.window = event.window.add(F::ONE),
                            3 => event.bit = event.bit.add(F::ONE),
                            _ => unreachable!(),
                        }
                        assert!(
                            scalar_fixture_residues(&changed_events, &sources, &aux)
                                .iter()
                                .any(|residue| *residue != F::ZERO),
                            "scalar N={event_slots}, row {row}, fixed {slot}/{coordinate}",
                        );
                    }
                }
            }
            let mut inactive_events = events.clone();
            inactive_events[2][0].active = F::ONE;
            assert!(
                scalar_fixture_residues(&inactive_events, &sources, &aux)
                    .iter()
                    .any(|residue| *residue != F::ZERO),
                "scalar N={event_slots}, inactive selector",
            );
        }
    }
    #[test]
    fn challenge_dependent_n1_n2_n3_n6_columns_equal_row_transposes() {
        assert_aux_column_transpose_v1::<13>(cross_fixture(1).2);
        assert_aux_column_transpose_v1::<18>(cross_fixture(2).2);
        assert_aux_column_transpose_v1::<23>(cross_fixture(3).2);
        assert_aux_column_transpose_v1::<38>(cross_fixture(6).2);
    }
    #[test]
    fn every_aggregate_terminal_projection_reads_the_registered_columns() {
        let (_, _, window_rows, window_start, window_terminal) = cross_fixture(3);
        let mut window_first = [F::ZERO; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1];
        let mut window_last = [F::ZERO; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1];
        window_first[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX].copy_from_slice(&window_rows[0]);
        window_last[WINDOW_CROSS_AUX..WINDOW_SCALAR_AUX].copy_from_slice(&window_rows[7]);
        assert_eq!(
            p256_window_cross_terminal_claim_v1(&window_first, &window_last),
            Ok(P256CrossTraceTerminalClaimV1 {
                role: P256CrossTraceTerminalRoleV1::WindowBatch,
                start: window_start,
                terminal: window_terminal,
            })
        );
        let mut window_fixed = [F::ZERO; P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1];
        window_fixed[WINDOW_BOUNDARY_FIXED + 1] = F::ONE;
        assert_eq!(p256_window_last_selector_v1(&window_fixed), F::ONE);
        assert_eq!(
            p256_window_cross_terminal_v1(&window_last),
            Ok(window_terminal)
        );
        let (_, _, reduction_rows, reduction_start, reduction_terminal) = cross_fixture(2);
        let mut reduction_first = [F::ZERO; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1];
        let mut reduction_last = [F::ZERO; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1];
        reduction_first[REDUCTION_CROSS_AUX..].copy_from_slice(&reduction_rows[0]);
        reduction_last[REDUCTION_CROSS_AUX..].copy_from_slice(&reduction_rows[7]);
        for (role, terminal_role) in [
            (
                P256ReductionAggregateRoleV1::Digest,
                P256CrossTraceTerminalRoleV1::DigestReduction,
            ),
            (
                P256ReductionAggregateRoleV1::ResultX,
                P256CrossTraceTerminalRoleV1::ResultXReduction,
            ),
        ] {
            assert_eq!(
                p256_reduction_cross_terminal_claim_v1(role, &reduction_first, &reduction_last,),
                Ok(P256CrossTraceTerminalClaimV1 {
                    role: terminal_role,
                    start: reduction_start,
                    terminal: reduction_terminal,
                })
            );
            let mut reduction_fixed = [F::ZERO; P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1];
            reduction_fixed[REDUCTION_BOUNDARY_FIXED + 1] = F::ONE;
            assert_eq!(p256_reduction_last_selector_v1(&reduction_fixed), F::ONE);
            assert_eq!(
                p256_reduction_cross_terminal_v1(&reduction_last),
                Ok(reduction_terminal)
            );
        }
        let (_, _, low_s_rows, low_s_start, low_s_terminal) = cross_fixture(1);
        let mut low_s_first = [F::ZERO; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1];
        let mut low_s_last = [F::ZERO; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1];
        low_s_first[LOW_S_CROSS_AUX..].copy_from_slice(&low_s_rows[0]);
        low_s_last[LOW_S_CROSS_AUX..].copy_from_slice(&low_s_rows[7]);
        assert_eq!(
            p256_low_s_cross_terminal_claim_v1(&low_s_first, &low_s_last),
            Ok(P256CrossTraceTerminalClaimV1 {
                role: P256CrossTraceTerminalRoleV1::WalletLowS,
                start: low_s_start,
                terminal: low_s_terminal,
            })
        );
        let mut low_s_fixed = [F::ZERO; P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1];
        low_s_fixed[LOW_S_BOUNDARY_FIXED + 1] = F::ONE;
        assert_eq!(p256_low_s_last_selector_v1(&low_s_fixed), F::ONE);
        assert_eq!(
            p256_low_s_cross_terminal_v1(&low_s_last),
            Ok(low_s_terminal)
        );
        let (_, _, sink_rows, _, sink_terminal) = cross_fixture(6);
        let sink_last: [F; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1] =
            sink_rows[7].clone().try_into().expect("sink aux width");
        assert_eq!(p256_binding_sink_terminal_v1(&sink_last), Ok(sink_terminal));
        let (_, _, window_scalar_rows, window_scalar_terminal) = scalar_fixture(1);
        let mut window_scalar_last = [F::ZERO; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1];
        window_scalar_last[WINDOW_SCALAR_AUX..].copy_from_slice(&window_scalar_rows[7]);
        assert_eq!(
            p256_window_scalar_terminal_v1(&window_scalar_last),
            Ok(window_scalar_terminal)
        );
        let (_, _, arithmetic_scalar_rows, arithmetic_scalar_terminal) = scalar_fixture(8);
        let mut arithmetic_scalar_last = [F::ZERO; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1];
        arithmetic_scalar_last[ARITHMETIC_SCALAR_AUX..ARITHMETIC_VALUE_COPY_AUX]
            .copy_from_slice(&arithmetic_scalar_rows[7]);
        assert_eq!(
            p256_arithmetic_scalar_terminal_v1(&arithmetic_scalar_last),
            Ok(arithmetic_scalar_terminal)
        );
        assert_eq!(
            evaluate_p256_scalar_source_terminal_openings_v1(
                F::ONE,
                arithmetic_scalar_terminal,
                window_scalar_terminal,
                [arithmetic_scalar_terminal, window_scalar_terminal],
            ),
            [F::ZERO; 2 * P256_SCALAR_BIT_BUS_LANES_V1]
        );
        let mut forged_bus = [arithmetic_scalar_terminal, window_scalar_terminal];
        forged_bus[1][2] = forged_bus[1][2].add(F::ONE);
        assert_ne!(
            evaluate_p256_scalar_source_terminal_openings_v1(
                F::ONE,
                arithmetic_scalar_terminal,
                window_scalar_terminal,
                forged_bus,
            )[P256_SCALAR_BIT_BUS_LANES_V1 + 2],
            F::ZERO
        );
        assert_eq!(
            evaluate_p256_scalar_source_terminal_openings_v1(
                F::ZERO,
                arithmetic_scalar_terminal,
                window_scalar_terminal,
                forged_bus,
            ),
            [F::ZERO; 2 * P256_SCALAR_BIT_BUS_LANES_V1]
        );
        let writer_start = [F(17), F(19), F(23), F(29)];
        let writer_terminal = [F(31), F(37), F(41), F(43)];
        let writer_first_row = P256CrossTraceWriterAuxRowV1 {
            event_values: [F::ZERO; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
            powers: [[[F::ZERO; 8]; P256_CROSS_TRACE_LANES_V1];
                P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
            selected_power: [[F::ZERO; P256_CROSS_TRACE_LANES_V1];
                P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
            product_before: [writer_start; P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1],
            terminal: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
        };
        let writer_last_row = P256CrossTraceWriterAuxRowV1 {
            terminal: writer_terminal,
            ..writer_first_row
        };
        assert_eq!(
            decode_writer_aux_v1(&flatten_writer_aux_v1(writer_first_row)),
            Ok(writer_first_row)
        );
        assert_eq!(
            decode_writer_aux_v1(&flatten_writer_aux_v1(writer_last_row)),
            Ok(writer_last_row)
        );
        let mut value_first = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1];
        let mut value_last = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1];
        value_first[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX]
            .copy_from_slice(&flatten_writer_aux_v1(writer_first_row));
        value_last[VALUE_WRITER_AUX..VALUE_ARITHMETIC_COPY_AUX]
            .copy_from_slice(&flatten_writer_aux_v1(writer_last_row));
        assert_eq!(
            p256_value_execution_cross_terminal_claim_v1(&value_first, &value_last),
            Ok(P256CrossTraceTerminalClaimV1 {
                role: P256CrossTraceTerminalRoleV1::ValueWriter,
                start: writer_start,
                terminal: writer_terminal,
            })
        );
        assert_eq!(
            p256_value_execution_cross_terminal_v1(&value_last),
            Ok(writer_terminal)
        );
        let writer_fixed =
            P256CrossTraceWriterSourceFixedV1::compile_v1(P256EcdsaRoleV1::WalletOwnership)
                .expect("writer fixed");
        let mut value_fixed = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1];
        value_fixed[VALUE_ARITHMETIC_COPY_BOUNDARY_FIXED + 1] = F::ONE;
        assert_eq!(p256_value_execution_last_selector_v1(&value_fixed), F::ONE);
        assert_eq!(
            evaluate_p256_terminal_claim_binding_v1(
                p256_value_execution_last_selector_v1(&value_fixed),
                writer_terminal,
                writer_terminal,
            ),
            [F::ZERO; P256_CROSS_TRACE_LANES_V1]
        );
        for row in [0, P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 - 1] {
            let typed = writer_fixed.row_v1(row).expect("writer fixed row");
            assert_eq!(
                decode_writer_fixed_v1(&encode_writer_fixed_v1(typed)),
                Ok(typed)
            );
        }
    }
    #[test]
    fn private_link_columns_match_independent_typed_terminal_projections() {
        use P256MainAdapterV1 as Adapter;
        use P256PrivateLinkFamilyV1 as Family;
        let check = |adapter, local, family, row: &[F], expected: [F; 4]| {
            let registration = P256MainRegistrationV1::new_v1(4, adapter, local).unwrap();
            let columns = p256_private_link_columns_v1(registration, family).unwrap();
            assert_eq!(columns.map(|column| row[column]), expected);
        };
        let value: [F; P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let arithmetic: [F; P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let window: [F; P256_WINDOW_AGGREGATE_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let reduction: [F; P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let low_s: [F; P256_LOW_S_AGGREGATE_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let sink: [F; P256_CROSS_TRACE_SINK_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let scalar: [F; P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        let native_value: [F; P256_VALUE_BUS_STARK_AUX_WIDTH_V1] =
            core::array::from_fn(|i| F(i as u64 + 1));
        for local in [0, 1] {
            check(
                Adapter::ValueBus,
                local,
                Family::Value,
                &native_value,
                super::super::p256_value_bus::p256_value_bus_stark_opened_terminal_v1(
                    &native_value,
                ),
            );
        }
        check(
            Adapter::ValueBus,
            0,
            Family::Copy,
            &value,
            p256_value_execution_arithmetic_copy_terminal_v1(&value).unwrap(),
        );
        check(
            Adapter::ValueBus,
            0,
            Family::ChainStart,
            &value,
            p256_value_execution_cross_terminal_claim_v1(&value, &value)
                .unwrap()
                .start,
        );
        check(
            Adapter::ValueBus,
            0,
            Family::ChainTerminal,
            &value,
            p256_value_execution_cross_terminal_v1(&value).unwrap(),
        );
        check(
            Adapter::Arithmetic,
            0,
            Family::Copy,
            &arithmetic,
            p256_arithmetic_value_copy_terminal_v1(&arithmetic).unwrap(),
        );
        check(
            Adapter::Arithmetic,
            0,
            Family::ArithmeticScalar,
            &arithmetic,
            p256_arithmetic_scalar_terminal_v1(&arithmetic).unwrap(),
        );
        check(
            Adapter::WindowBatch,
            0,
            Family::WindowScalar,
            &window,
            p256_window_scalar_terminal_v1(&window).unwrap(),
        );
        check(
            Adapter::WindowBatch,
            0,
            Family::ChainStart,
            &window,
            p256_window_cross_terminal_claim_v1(&window, &window)
                .unwrap()
                .start,
        );
        check(
            Adapter::WindowBatch,
            0,
            Family::ChainTerminal,
            &window,
            p256_window_cross_terminal_v1(&window).unwrap(),
        );
        for (local, role) in [
            (0, P256ReductionAggregateRoleV1::Digest),
            (1, P256ReductionAggregateRoleV1::ResultX),
        ] {
            check(
                Adapter::Reduction,
                local,
                Family::ChainStart,
                &reduction,
                p256_reduction_cross_terminal_claim_v1(role, &reduction, &reduction)
                    .unwrap()
                    .start,
            );
            check(
                Adapter::Reduction,
                local,
                Family::ChainTerminal,
                &reduction,
                p256_reduction_cross_terminal_v1(&reduction).unwrap(),
            );
        }
        check(
            Adapter::WalletLowS,
            0,
            Family::ChainStart,
            &low_s,
            p256_low_s_cross_terminal_claim_v1(&low_s, &low_s)
                .unwrap()
                .start,
        );
        check(
            Adapter::WalletLowS,
            0,
            Family::ChainTerminal,
            &low_s,
            p256_low_s_cross_terminal_v1(&low_s).unwrap(),
        );
        check(
            Adapter::BindingSink,
            0,
            Family::ChainTerminal,
            &sink,
            p256_binding_sink_terminal_v1(&sink).unwrap(),
        );
        let terminal =
            super::super::p256_scalar_bit_bus::p256_scalar_bit_bus_opened_terminals_v1(&scalar);
        check(
            Adapter::ScalarBitBus,
            0,
            Family::ArithmeticScalar,
            &scalar,
            terminal[0],
        );
        check(
            Adapter::ScalarBitBus,
            0,
            Family::WindowScalar,
            &scalar,
            terminal[1],
        );
        for (adapter, local, family) in [
            (Adapter::ValueBus, 1, Family::ChainStart),
            (Adapter::Arithmetic, 0, Family::ChainStart),
            (Adapter::ScalarBitBus, 0, Family::Copy),
            (Adapter::BindingSink, 0, Family::ChainStart),
        ] {
            assert!(
                p256_private_link_columns_v1(
                    P256MainRegistrationV1::new_v1(4, adapter, local).unwrap(),
                    family
                )
                .is_err()
            );
        }
    }

    fn small_be(value: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
    #[test]
    fn arithmetic_copy_known_answer_binds_real_value_bus_and_arithmetic_openings() {
        let operations = [
            ZkX509P256ArithmeticOperationV1 {
                kind: ZkX509P256ArithmeticKindV1::Add,
                modulus: ZkX509P256ModulusV1::BaseField,
                a: small_be(3),
                b: small_be(5),
                c: small_be(8),
            },
            ZkX509P256ArithmeticOperationV1 {
                kind: ZkX509P256ArithmeticKindV1::Multiply,
                modulus: ZkX509P256ModulusV1::BaseField,
                a: small_be(8),
                b: small_be(5),
                c: small_be(40),
            },
        ];
        let initial = [
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(0),
                modulus: ZkX509P256ModulusV1::BaseField,
                value: small_be(3),
                kind: P256InitialValueKindV1::Input,
            },
            P256InitialValueBindingV1 {
                id: P256ValueIdV1(1),
                modulus: ZkX509P256ModulusV1::BaseField,
                value: small_be(5),
                kind: P256InitialValueKindV1::Constant,
            },
        ];
        let linked = [
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
        ];
        let arithmetic =
            build_zk_x509_p256_arithmetic_trace_v1(&operations).expect("KAT arithmetic trace");
        let value_challenges = P256ValueBusChallengesV1 {
            lanes: core::array::from_fn(|lane| P256ValueBusLaneChallengesV1 {
                terms: core::array::from_fn(|term| F((lane * 31 + term + 2) as u64)),
            }),
        };
        let value_bus = build_zk_x509_p256_value_bus_trace_v1(
            &initial,
            &linked,
            &[],
            &[],
            &arithmetic,
            value_challenges,
        )
        .expect("KAT value bus");
        let trace_size = 128;
        let value_rows = P256ValueBusStarkRowProviderV1::new_v1(
            &value_bus.execution,
            P256ValueBusStarkEndpointV1::Execution,
            trace_size,
        )
        .expect("KAT value rows");
        let arithmetic_topology = operations.map(|operation| ZkX509P256ArithmeticTopologyV1 {
            kind: operation.kind,
            modulus: operation.modulus,
        });
        let arithmetic_fixed =
            P256ArithmeticStarkFixedProviderV1::new_v1(&arithmetic_topology, trace_size)
                .expect("KAT arithmetic fixed");
        let mut value_events = Vec::with_capacity(trace_size);
        let mut value_sources = Vec::with_capacity(trace_size);
        let mut arithmetic_events = Vec::with_capacity(trace_size);
        let mut arithmetic_sources = Vec::with_capacity(trace_size);
        for row in 0..trace_size {
            value_events.push(
                value_arithmetic_copy_events_v1(row, operations.len())
                    .expect("KAT value event")
                    .to_vec(),
            );
            value_sources.push(
                p256_value_bus_opened_values_v1(
                    &value_rows.base_row_v1(row).expect("KAT value base"),
                )
                .to_vec(),
            );
            let events = arithmetic_value_copy_events_v1(row, arithmetic.rows())
                .expect("KAT arithmetic events");
            arithmetic_events.push(events.to_vec());
            let base = arithmetic
                .base
                .get(row)
                .copied()
                .unwrap_or([F::ZERO; P256_ARITHMETIC_BASE_WIDTH_V1]);
            arithmetic_sources.push(
                p256_arithmetic_opened_operand_limbs_v1(
                    &base,
                    &arithmetic_fixed.row_v1(row).expect("KAT fixed row"),
                )
                .to_vec(),
            );
        }
        for operation in 0..operations.len() {
            for limb in 0..16 {
                let arithmetic_row = operation * P256_ARITHMETIC_ROWS_PER_OPERATION_V1 + limb;
                let expected = p256_arithmetic_operand_limbs_v1(&arithmetic, operation, limb)
                    .expect("typed operand limbs");
                assert_eq!(arithmetic_sources[arithmetic_row], expected);
                for (slot, expected) in expected.into_iter().enumerate() {
                    let factor = operation * P256_VALUE_BUS_SEGMENT_ROWS_V1 + limb * 3 + slot;
                    let value_row = factor / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
                    let value_slot = factor % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
                    assert_eq!(
                        value_sources[value_row][value_slot], expected,
                        "operation {operation}, limb {limb}, slot {slot}",
                    );
                }
            }
        }
        let copy_challenges = arithmetic_copy_challenges();
        let (value_aux, value_terminal) =
            build_copy_endpoint(&value_events, &value_sources, copy_challenges);
        let (arithmetic_aux, arithmetic_terminal) =
            build_copy_endpoint(&arithmetic_events, &arithmetic_sources, copy_challenges);
        let expected_terminal = [
            F(0x03f9_d4f7_e5b3_f1ee),
            F(0x9c0d_f529_3f08_95ed),
            F(0xd985_3169_6a04_d4ed),
            F(0xbd2f_25fc_8ba6_8e00),
        ];
        assert_eq!(value_terminal, expected_terminal);
        assert_eq!(arithmetic_terminal, expected_terminal);
        assert!(
            copy_endpoint_residues(&value_events, &value_sources, &value_aux, copy_challenges,)
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
        assert!(
            copy_endpoint_residues(
                &arithmetic_events,
                &arithmetic_sources,
                &arithmetic_aux,
                copy_challenges,
            )
            .iter()
            .all(|residue| *residue == F::ZERO)
        );
        assert_eq!(
            evaluate_p256_arithmetic_copy_terminal_openings_v1(value_terminal, arithmetic_terminal,),
            [F::ZERO; P256_ARITHMETIC_COPY_LANES_V1]
        );
    }
    fn canonical_terminal_chain(
        role: P256EcdsaRoleV1,
    ) -> (
        Vec<P256CrossTraceTerminalClaimV1>,
        [F; P256_CROSS_TRACE_LANES_V1],
    ) {
        let mut running = [F::ONE; P256_CROSS_TRACE_LANES_V1];
        let mut claims = Vec::new();
        for (index, source_role) in p256_cross_trace_terminal_roles_v1(role)
            .iter()
            .copied()
            .enumerate()
        {
            let terminal = core::array::from_fn(|lane| F((index * 13 + lane + 7) as u64));
            claims.push(P256CrossTraceTerminalClaimV1 {
                role: source_role,
                start: running,
                terminal,
            });
            running = terminal;
        }
        (claims, running)
    }
    fn bus_terminal_claims(groups: [[F; P256_CROSS_TRACE_LANES_V1]; 8]) -> P256BusTerminalClaimsV1 {
        P256BusTerminalClaimsV1 {
            value_execution: groups[0],
            value_sorted: groups[1],
            value_arithmetic_copy: groups[2],
            arithmetic_value_copy: groups[3],
            arithmetic_scalar: groups[4],
            window_scalar: groups[5],
            scalar_bus_arithmetic: groups[6],
            scalar_bus_window: groups[7],
        }
    }
    fn canonical_bus_terminal_claims() -> P256BusTerminalClaimsV1 {
        bus_terminal_claims([
            [F(11), F(12), F(13), F(14)],
            [F(11), F(12), F(13), F(14)],
            [F(21), F(22), F(23), F(24)],
            [F(21), F(22), F(23), F(24)],
            [F(31), F(32), F(33), F(34)],
            [F(41), F(42), F(43), F(44)],
            [F(31), F(32), F(33), F(34)],
            [F(41), F(42), F(43), F(44)],
        ])
    }
    fn terminal_claim_transcript() -> TransparentTranscriptV1 {
        TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"p256-claim-test",
            &zk_x509_test_digest384_v1(7),
            &zk_x509_test_digest384_v1(9),
        )
        .expect("claim transcript")
    }
    #[test]
    fn transcript_bound_terminal_claims_order_and_mutations_fail_closed() {
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let (canonical, sink) = canonical_terminal_chain(role);
            assert!(
                evaluate_p256_cross_trace_terminal_claim_equalities_v1(role, &canonical, sink)
                    .expect("canonical terminal claims")
                    .iter()
                    .all(|residue| *residue == F::ZERO)
            );
            let buses = canonical_bus_terminal_claims();
            assert_eq!(
                evaluate_p256_bus_terminal_claim_equalities_v1(buses),
                Ok([F::ZERO; 4 * P256_CROSS_TRACE_LANES_V1])
            );
            let mut canonical_transcript = terminal_claim_transcript();
            absorb_p256_terminal_claims_v1(
                &mut canonical_transcript,
                role,
                buses,
                &canonical,
                sink,
            )
            .expect("absorb canonical claims");
            let canonical_state = canonical_transcript.state();
            let mut missing = canonical.clone();
            missing.pop();
            assert_eq!(
                evaluate_p256_cross_trace_terminal_claim_equalities_v1(role, &missing, sink),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            assert_eq!(
                absorb_p256_terminal_claims_v1(
                    &mut terminal_claim_transcript(),
                    role,
                    buses,
                    &missing,
                    sink,
                ),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            let mut duplicate = canonical.clone();
            duplicate.push(canonical[0]);
            assert_eq!(
                evaluate_p256_cross_trace_terminal_claim_equalities_v1(role, &duplicate, sink),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            assert_eq!(
                absorb_p256_terminal_claims_v1(
                    &mut terminal_claim_transcript(),
                    role,
                    buses,
                    &duplicate,
                    sink,
                ),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            let mut reordered = canonical.clone();
            reordered.swap(0, 1);
            assert_eq!(
                evaluate_p256_cross_trace_terminal_claim_equalities_v1(role, &reordered, sink),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            assert_eq!(
                absorb_p256_terminal_claims_v1(
                    &mut terminal_claim_transcript(),
                    role,
                    buses,
                    &reordered,
                    sink,
                ),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            for index in 0..canonical.len() {
                for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                    let mut forged = canonical.clone();
                    forged[index].start[lane] = forged[index].start[lane].add(F::ONE);
                    assert!(
                        evaluate_p256_cross_trace_terminal_claim_equalities_v1(
                            role, &forged, sink,
                        )
                        .expect("start-claim residues")
                            .iter()
                            .any(|residue| *residue != F::ZERO)
                    );
                    let mut transcript = terminal_claim_transcript();
                    absorb_p256_terminal_claims_v1(&mut transcript, role, buses, &forged, sink)
                        .expect("absorb forged start");
                    assert_ne!(transcript.state(), canonical_state);
                    let mut forged = canonical.clone();
                    forged[index].terminal[lane] = forged[index].terminal[lane].add(F::ONE);
                    assert!(
                        evaluate_p256_cross_trace_terminal_claim_equalities_v1(
                            role, &forged, sink,
                        )
                            .expect("terminal residues")
                            .iter()
                            .any(|residue| *residue != F::ZERO)
                    );
                    assert_ne!(
                        evaluate_p256_terminal_claim_binding_v1(
                            F::ONE,
                            canonical[index].terminal,
                            forged[index].terminal,
                        )[lane],
                        F::ZERO
                    );
                    assert_eq!(
                        evaluate_p256_terminal_claim_binding_v1(
                            F::ZERO,
                            canonical[index].terminal,
                            forged[index].terminal,
                        ),
                        [F::ZERO; P256_CROSS_TRACE_LANES_V1]
                    );
                }
            }
            for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                let mut forged_sink = sink;
                forged_sink[lane] = forged_sink[lane].add(F::ONE);
                assert!(
                    evaluate_p256_cross_trace_terminal_claim_equalities_v1(
                        role,
                        &canonical,
                        forged_sink,
                    )
                    .expect("sink residues")
                    .iter()
                    .any(|residue| *residue != F::ZERO)
                );
            }
            let canonical_groups = [
                buses.value_execution,
                buses.value_sorted,
                buses.value_arithmetic_copy,
                buses.arithmetic_value_copy,
                buses.arithmetic_scalar,
                buses.window_scalar,
                buses.scalar_bus_arithmetic,
                buses.scalar_bus_window,
            ];
            for group in 0..canonical_groups.len() {
                for lane in 0..P256_CROSS_TRACE_LANES_V1 {
                    let mut groups = canonical_groups;
                    groups[group][lane] = groups[group][lane].add(F::ONE);
                    let forged = bus_terminal_claims(groups);
                    assert!(
                        evaluate_p256_bus_terminal_claim_equalities_v1(forged)
                            .expect("bus claim residues")
                            .iter()
                            .any(|residue| *residue != F::ZERO)
                    );
                    let mut transcript = terminal_claim_transcript();
                    absorb_p256_terminal_claims_v1(&mut transcript, role, forged, &canonical, sink)
                        .expect("absorb forged bus claim");
                    assert_ne!(transcript.state(), canonical_state);
                }
            }
            let mut noncanonical_cross = canonical.clone();
            noncanonical_cross[0].terminal[0] = F(u64::MAX);
            assert_eq!(
                absorb_p256_terminal_claims_v1(
                    &mut terminal_claim_transcript(),
                    role,
                    buses,
                    &noncanonical_cross,
                    sink,
                ),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            let mut noncanonical_groups = canonical_groups;
            noncanonical_groups[0][0] = F(u64::MAX);
            assert_eq!(
                absorb_p256_terminal_claims_v1(
                    &mut terminal_claim_transcript(),
                    role,
                    bus_terminal_claims(noncanonical_groups),
                    &canonical,
                    sink,
                ),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
            let mut noncanonical_sink = sink;
            noncanonical_sink[0] = F(u64::MAX);
            assert_eq!(
                absorb_p256_terminal_claims_v1(
                    &mut terminal_claim_transcript(),
                    role,
                    buses,
                    &canonical,
                    noncanonical_sink,
                ),
                Err(P256AggregateAdapterErrorV1::Topology)
            );
        }
        let (wallet, wallet_sink) = canonical_terminal_chain(P256EcdsaRoleV1::WalletOwnership);
        assert_eq!(
            evaluate_p256_cross_trace_terminal_claim_equalities_v1(
                P256EcdsaRoleV1::CertificateOrCrl,
                &wallet,
                wallet_sink,
            ),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
    }
    fn run_p256_main_test_on_explicit_stack_v1(name: &'static str, body: fn()) {
        std::thread::scope(|scope| {
            let thread = std::thread::Builder::new()
                .name(name.to_owned())
                .stack_size(32 * 1024 * 1024)
                .spawn_scoped(scope, body)
                .expect("spawn bounded-stack P-256 MAIN test");
            thread.join().expect("P-256 MAIN test thread");
        });
    }
    #[test]
    fn p256_main_ephemeral_stream_zeroization_is_recursive_and_idempotent() {
        run_p256_main_test_on_explicit_stack_v1(
            "p256-main-stream-zeroization",
            p256_main_ephemeral_stream_zeroization_body_v1,
        );
    }
    fn p256_main_ephemeral_stream_zeroization_body_v1() {
        let fixture =
            p256_main_canonical_materials_for_test_v1().expect("canonical P-256 MAIN materials");
        let mut source =
            P256MainBaseSourceV1::from_materials_for_test_v1(&fixture.materials, fixture.selection)
                .expect("canonical five-signature base source");
        let post_base = main_post_base_v1(71);
        let bound = source.bind_v1(post_base).expect("one exact X5B1 bind");
        let signature = &bound
            .signatures
            .as_ref()
            .expect("retained bound signatures")[2];
        let mut execution = P256ValueExecutionAggregateStreamV1::new_v1(
            signature.value.as_ref().expect("bound value source"),
        )
        .expect("execution stream");
        let mut arithmetic = P256ArithmeticAggregateAuxStreamV1::from_validated_v1(
            signature.role,
            signature
                .arithmetic
                .as_ref()
                .expect("bound arithmetic trace"),
            post_base.p256_scalar(),
            post_base.p256_arithmetic_copy(),
        )
        .expect("arithmetic stream");
        let mut window = P256WindowAggregateAuxStreamV1::new_v1(
            signature.window.as_ref().expect("bound window trace"),
            execution.terminal_v1(),
            post_base.p256_cross(),
            post_base.p256_scalar(),
        )
        .expect("window stream");
        let mut sink = P256BindingSinkAggregateStreamV1::new_with_optional_certificate_v1(
            signature.sink.as_ref().expect("bound sink trace"),
            post_base.p256_cross(),
            true,
        )
        .expect("optional-certificate sink stream");
        assert!(!execution.private_is_zeroized_v1());
        assert!(!arithmetic.private_is_zeroized_v1());
        assert!(!window.private_is_zeroized_v1());
        assert!(!sink.private_is_zeroized_v1());
        execution.zeroize_private_v1();
        arithmetic.zeroize_private_v1();
        window.zeroize_private_v1();
        sink.zeroize_private_v1();
        assert!(execution.private_is_zeroized_v1());
        assert!(arithmetic.private_is_zeroized_v1());
        assert!(window.private_is_zeroized_v1());
        assert!(sink.private_is_zeroized_v1());
        execution.zeroize_private_v1();
        arithmetic.zeroize_private_v1();
        window.zeroize_private_v1();
        sink.zeroize_private_v1();
        assert!(execution.private_is_zeroized_v1());
        assert!(arithmetic.private_is_zeroized_v1());
        assert!(window.private_is_zeroized_v1());
        assert!(sink.private_is_zeroized_v1());
    }
    #[test]
    fn p256_main_registration_and_verifier_fixed_source_are_closed_and_exact() {
        run_p256_main_test_on_explicit_stack_v1(
            "p256-main-registration",
            p256_main_registration_and_verifier_fixed_source_body_v1,
        );
    }
    #[test]
    fn p256_main_arithmetic_copy_selectors_use_true_logical_row_bound() {
        let logical_rows = P256_ARITHMETIC_OPERATIONS_V1 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let source =
                P256MainArithmeticFixedSourceV1::new_v1(role).expect("closed arithmetic source");
            for row in [
                P256_ARITHMETIC_OPERATIONS_V1,
                464 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
                logical_rows - 17,
                logical_rows - 16,
                logical_rows - 1,
                logical_rows,
            ] {
                let fixed = source.row_v1(row).expect("bounded MAIN fixed row");
                let expected = arithmetic_value_copy_events_v1(row, logical_rows)
                    .expect("canonical arithmetic-copy schedule");
                for (slot, event) in expected.into_iter().enumerate() {
                    let mut encoded = [F::ZERO; ARITHMETIC_COPY_EVENT_FIXED_WIDTH];
                    encode_arithmetic_copy_event_v1(event, &mut encoded);
                    let start =
                        ARITHMETIC_VALUE_COPY_FIXED + slot * ARITHMETIC_COPY_EVENT_FIXED_WIDTH;
                    assert_eq!(
                        fixed[start..start + ARITHMETIC_COPY_EVENT_FIXED_WIDTH],
                        encoded,
                        "role {role:?}, row {row}, slot {slot}"
                    );
                }
            }
        }
    }
    fn p256_main_registration_and_verifier_fixed_source_body_v1() {
        let registrations = canonical_p256_main_registrations_v1().expect("canonical MAIN order");
        assert_eq!(registrations.len(), 41);
        validate_p256_main_registration_order_v1(&registrations).expect("exact MAIN order");
        for (index, registration) in registrations.iter().copied().enumerate() {
            let signature = registration.signature_v1();
            assert!(signature < P256_X5S1_SIGNATURES_V1, "registration {index}");
            assert_eq!(
                registration.role_v1(),
                if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
                    P256EcdsaRoleV1::CertificateOrCrl
                } else {
                    P256EcdsaRoleV1::WalletOwnership
                }
            );
            let shape = registration.shape_v1().expect("validated MAIN shape");
            let expected = match (registration.adapter_v1(), registration.local_instance_v1()) {
                (P256MainAdapterV1::ValueBus, 0) => (
                    P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
                    P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
                    P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1,
                    P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::ValueBus, 1) => (
                    P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
                    P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
                    P256_VALUE_BUS_STARK_AUX_WIDTH_V1,
                    P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::Arithmetic, 0) => (
                    P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
                    P256_ARITHMETIC_BASE_WIDTH_V1,
                    P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1,
                    P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::WindowBatch, 0) => (
                    P256_WINDOW_AGGREGATE_TRACE_SIZE_V1,
                    P256_WINDOW_BASE_WIDTH_V1,
                    P256_WINDOW_AGGREGATE_AUX_WIDTH_V1,
                    P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::Reduction, 0 | 1) => (
                    P256_REDUCTION_AGGREGATE_TRACE_SIZE_V1,
                    P256_REDUCTION_BASE_WIDTH_V1,
                    P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1,
                    P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::WalletLowS, 0) => (
                    P256_LOW_S_AGGREGATE_TRACE_SIZE_V1,
                    P256_LOW_S_BASE_WIDTH_V1,
                    P256_LOW_S_AGGREGATE_AUX_WIDTH_V1,
                    P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::BindingSink, 0) => (
                    P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1,
                    P256_BINDING_SINK_BASE_WIDTH_V1,
                    P256_CROSS_TRACE_SINK_AUX_WIDTH_V1,
                    P256_BINDING_SINK_FIXED_WIDTH_V1,
                ),
                (P256MainAdapterV1::ScalarBitBus, 0) => (
                    P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_SIZE_V1,
                    P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1,
                    P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1,
                    P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1,
                ),
                _ => panic!("constructor admitted an invalid MAIN registration"),
            };
            assert_eq!(
                (
                    shape.trace_size,
                    shape.base_width,
                    shape.aux_width,
                    shape.fixed_width,
                ),
                expected,
                "registration {index}",
            );
        }
        for signature in 0..P256_X5S1_SIGNATURES_V1 {
            assert_eq!(
                registrations
                    .iter()
                    .filter(|registration| registration.signature_v1() == signature)
                    .count(),
                if signature + 1 == P256_X5S1_SIGNATURES_V1 {
                    9
                } else {
                    8
                }
            );
        }
        let mut omitted = registrations.clone();
        omitted.remove(7);
        assert_eq!(
            validate_p256_main_registration_order_v1(&omitted),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        let mut reordered = registrations.clone();
        reordered.swap(0, 1);
        assert_eq!(
            validate_p256_main_registration_order_v1(&reordered),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        let mut duplicated = registrations.clone();
        duplicated[1] = duplicated[0];
        assert_eq!(
            validate_p256_main_registration_order_v1(&duplicated),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert!(matches!(
            P256MainRegistrationV1::new_v1(P256_X5S1_SIGNATURES_V1, P256MainAdapterV1::ValueBus, 0,),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        assert!(matches!(
            P256MainRegistrationV1::new_v1(0, P256MainAdapterV1::ValueBus, 2),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        assert!(matches!(
            P256MainRegistrationV1::new_v1(0, P256MainAdapterV1::Reduction, 2),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        assert!(matches!(
            P256MainRegistrationV1::new_v1(0, P256MainAdapterV1::Arithmetic, 1),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        assert!(matches!(
            P256MainRegistrationV1::new_v1(0, P256MainAdapterV1::WalletLowS, 0),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        let forged = P256MainRegistrationV1 {
            signature: 0,
            adapter: P256MainAdapterV1::Arithmetic,
            local_instance: 1,
        };
        assert_eq!(
            forged.shape_v1(),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        let fixed = P256MainVerifierFixedSourceV1::new_v1().expect("closed fixed source");
        let sink_one =
            P256MainRegistrationV1::new_v1(1, P256MainAdapterV1::BindingSink, 0).expect("sink one");
        let sink_two =
            P256MainRegistrationV1::new_v1(2, P256MainAdapterV1::BindingSink, 0).expect("sink two");
        let sink_three = P256MainRegistrationV1::new_v1(3, P256MainAdapterV1::BindingSink, 0)
            .expect("sink three");
        let selector_row = P256_INPUT_SELECTION_SELECTOR_ROW_V1;
        assert_eq!(
            fixed
                .fixed_cell_v1(sink_one, selector_row, SINK_SELECTION_REQUIRE_ACTIVE_FIXED,)
                .expect("ordinary certificate selector"),
            F::ONE
        );
        assert_eq!(
            fixed
                .fixed_cell_v1(sink_two, selector_row, SINK_SELECTION_REQUIRE_ACTIVE_FIXED,)
                .expect("optional certificate selector"),
            F::ZERO
        );
        assert_eq!(
            fixed
                .fixed_cell_v1(
                    sink_three,
                    selector_row,
                    SINK_SELECTION_REQUIRE_ACTIVE_FIXED,
                )
                .expect("ordinary certificate selector"),
            F::ONE
        );
        assert_eq!(
            fixed
                .fixed_row_v1(sink_one, selector_row - 1)
                .expect("witness-free fixed row"),
            fixed
                .fixed_row_v1(sink_two, selector_row - 1)
                .expect("same witness-free fixed row"),
        );
        let mut invalid = [F(77); 8];
        assert_eq!(
            fixed.fill_fixed_column_v1(sink_two, 0, &mut invalid),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
        assert_eq!(invalid, [F(77); 8]);
        assert_eq!(
            fixed.fixed_cell_v1(sink_two, P256_BINDING_SINK_AGGREGATE_TRACE_SIZE_V1, 0,),
            Err(P256AggregateAdapterErrorV1::Topology)
        );
    }
    #[test]
    fn p256_main_exact_five_signature_pipeline_binds_once_and_replays_from_one_token() {
        run_p256_main_test_on_explicit_stack_v1(
            "p256-main-x5s1",
            p256_main_exact_five_signature_pipeline_body_v1,
        );
    }
    fn p256_main_exact_five_signature_pipeline_body_v1() {
        let mut fixture =
            p256_main_canonical_materials_for_test_v1().expect("canonical P-256 MAIN materials");
        let selection = fixture.selection;
        fixture.materials.swap(0, P256_X5S1_SIGNATURES_V1 - 1);
        assert!(matches!(
            P256MainBaseSourceV1::from_materials_for_test_v1(&fixture.materials, selection),
            Err(P256AggregateAdapterErrorV1::Topology)
        ));
        fixture.materials.swap(0, P256_X5S1_SIGNATURES_V1 - 1);
        let post_base = main_post_base_v1(41);
        let mut partially_poisoned =
            P256MainBaseSourceV1::from_materials_for_test_v1(&fixture.materials, selection)
                .expect("canonical source before injected child failure");
        partially_poisoned
            .poison_scalar_for_test_v1(0)
            .expect("inject scalar failure after value bind starts");
        assert!(partially_poisoned.bind_v1(post_base).is_err());
        assert!(partially_poisoned.private_is_zeroized_v1());
        assert!(matches!(
            partially_poisoned.bind_v1(post_base),
            Err(P256AggregateAdapterErrorV1::Phase)
        ));
        drop(partially_poisoned);
        let mut source =
            P256MainBaseSourceV1::from_materials_for_test_v1(&fixture.materials, selection)
                .expect("canonical five-signature base source");
        drop(fixture);
        assert_eq!(
            source
                .canonical_registrations_v1()
                .expect("base registrations")
                .len(),
            41
        );
        let scalar = P256MainRegistrationV1::new_v1(4, P256MainAdapterV1::ScalarBitBus, 0)
            .expect("wallet scalar registration");
        let reduction = P256MainRegistrationV1::new_v1(4, P256MainAdapterV1::Reduction, 0)
            .expect("wallet digest reduction");
        let scalar_shape = scalar.shape_v1().expect("scalar shape");
        let reduction_shape = reduction.shape_v1().expect("reduction shape");
        let mut scalar_base_before = vec![F::ZERO; scalar_shape.trace_size];
        let mut scalar_fixed_before = vec![F::ZERO; scalar_shape.trace_size];
        source
            .fill_base_column_v1(scalar, 0, &mut scalar_base_before)
            .expect("base-phase scalar column");
        source
            .fill_fixed_column_v1(scalar, 0, &mut scalar_fixed_before)
            .expect("base-phase scalar fixed column");
        let independent_fixed =
            P256MainVerifierFixedSourceV1::new_v1().expect("independent fixed source");
        let mut independently_replayed = vec![F::ZERO; scalar_shape.trace_size];
        independent_fixed
            .fill_fixed_column_v1(scalar, 0, &mut independently_replayed)
            .expect("independent fixed replay");
        assert_eq!(scalar_fixed_before, independently_replayed);
        let mut bound = source.bind_v1(post_base).expect("one exact X5B1 bind");
        assert!(source.private_is_zeroized_v1());
        assert_eq!(
            bound.post_base_v1().expect("retained opaque token"),
            post_base
        );
        assert_eq!(
            bound
                .canonical_registrations_v1()
                .expect("bound registrations")
                .len(),
            41
        );
        assert!(matches!(
            source.bind_v1(post_base),
            Err(P256AggregateAdapterErrorV1::Phase)
        ));
        let mut denied_after_bind = scalar_base_before.clone();
        assert_eq!(
            source.fill_base_column_v1(scalar, 0, &mut denied_after_bind),
            Err(P256AggregateAdapterErrorV1::Phase)
        );
        assert_eq!(denied_after_bind, scalar_base_before);
        let mut scalar_base_after = vec![F::ZERO; scalar_shape.trace_size];
        let mut scalar_fixed_after = vec![F::ZERO; scalar_shape.trace_size];
        bound
            .fill_base_column_v1(scalar, 0, &mut scalar_base_after)
            .expect("bound scalar base replay");
        bound
            .fill_fixed_column_v1(scalar, 0, &mut scalar_fixed_after)
            .expect("bound scalar fixed replay");
        assert_eq!(scalar_base_after, scalar_base_before);
        assert_eq!(scalar_fixed_after, scalar_fixed_before);
        let claims = bound.terminal_claims_v1().expect("exact private products");
        for certificate in claims.certificate_or_crl {
            assert!(
                evaluate_p256_bus_terminal_claim_equalities_v1(certificate.buses)
                    .expect("certificate bus equalities")
                    .iter()
                    .all(|residue| *residue == F::ZERO)
            );
            assert!(
                evaluate_p256_cross_trace_terminal_claim_equalities_v1(
                    P256EcdsaRoleV1::CertificateOrCrl,
                    &certificate.cross_sources,
                    certificate.sink,
                )
                .expect("certificate cross equalities")
                .iter()
                .all(|residue| *residue == F::ZERO)
            );
        }
        assert!(
            evaluate_p256_bus_terminal_claim_equalities_v1(claims.wallet.buses)
                .expect("wallet bus equalities")
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
        assert!(
            evaluate_p256_cross_trace_terminal_claim_equalities_v1(
                P256EcdsaRoleV1::WalletOwnership,
                &claims.wallet.cross_sources,
                claims.wallet.sink,
            )
            .expect("wallet cross equalities")
            .iter()
            .all(|residue| *residue == F::ZERO)
        );
        let mut scalar_aux = vec![F::ZERO; scalar_shape.trace_size];
        bound
            .fill_aux_column_v1(scalar, 0, &mut scalar_aux)
            .expect("scalar auxiliary replay");
        let mut reduction_aux = vec![F::ZERO; reduction_shape.trace_size];
        bound
            .fill_aux_column_v1(reduction, 0, &mut reduction_aux)
            .expect("digest reduction auxiliary replay");
        let other_post_base = main_post_base_v1(42);
        bound.replace_post_base_for_test_v1(other_post_base);
        let mut token_mismatch = vec![F(91); scalar_shape.trace_size];
        assert_eq!(
            bound.fill_aux_column_v1(scalar, 0, &mut token_mismatch),
            Err(P256AggregateAdapterErrorV1::Challenge)
        );
        assert!(token_mismatch.iter().all(|value| *value == F(91)));
        bound.replace_post_base_for_test_v1(post_base);
        bound
            .terminal_claims
            .as_mut()
            .expect("retained terminal claims")
            .wallet
            .cross_sources[4]
            .start[0] = claims.wallet.cross_sources[4].start[0].add(F::ONE);
        assert!(matches!(
            bound.terminal_claims_v1(),
            Err(P256AggregateAdapterErrorV1::Constraint)
        ));
        bound.terminal_claims = Some(claims);
        assert_eq!(
            bound.terminal_claims_v1().expect("restored terminals"),
            claims
        );
        bound.zeroize_private_v1();
        assert!(bound.private_is_zeroized_v1());
        assert!(matches!(
            bound.fill_aux_column_v1(scalar, 0, &mut scalar_aux),
            Err(P256AggregateAdapterErrorV1::Phase)
        ));
    }
    #[test]
    fn p256_main_failed_bind_is_permanently_poisoned_and_zeroized() {
        run_p256_main_test_on_explicit_stack_v1(
            "p256-main-failed-bind",
            p256_main_failed_bind_body_v1,
        );
    }
    fn p256_main_failed_bind_body_v1() {
        let signatures = ClearingVecV1::from_vec_for_test_v1(
            (0..P256_X5S1_SIGNATURES_V1)
                .map(|signature| P256MainSignatureBaseV1 {
                    role: if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
                        P256EcdsaRoleV1::CertificateOrCrl
                    } else {
                        P256EcdsaRoleV1::WalletOwnership
                    },
                    value: None,
                    scalar: None,
                    arithmetic: None,
                    window: None,
                    digest_reduction: None,
                    result_x_reduction: None,
                    low_s: None,
                    sink: None,
                })
                .collect(),
        );
        let mut source = P256MainBaseSourceV1 {
            signatures: Some(signatures),
            fixed: Some(P256MainVerifierFixedSourceV1::new_v1().expect("closed fixed source")),
            bind_attempted: false,
        };
        let post_base = main_post_base_v1(29);
        assert!(matches!(
            source.bind_v1(post_base),
            Err(P256AggregateAdapterErrorV1::Source)
        ));
        assert!(source.private_is_zeroized_v1());
        assert!(matches!(
            source.bind_v1(post_base),
            Err(P256AggregateAdapterErrorV1::Phase)
        ));
        let mut bound = P256MainBoundSourceV1 {
            signatures: None,
            fixed: Some(P256MainVerifierFixedSourceV1::new_v1().expect("closed fixed source")),
            post_base: Some(post_base),
            terminal_claims: Some(ZkX509P256PrivateProductsV1::canonical_zero_for_test_v1()),
        };
        bound.zeroize_private_v1();
        assert!(bound.private_is_zeroized_v1());
        assert!(matches!(
            bound.post_base_v1(),
            Err(P256AggregateAdapterErrorV1::Phase)
        ));
    }
    #[test]
    fn p256_main_x5v1_constructor_rejects_every_terminal_equality_tamper_class() {
        run_p256_main_test_on_explicit_stack_v1(
            "p256-main-x5v1-tamper",
            p256_main_x5v1_constructor_tamper_body_v1,
        );
    }
    fn p256_main_x5v1_constructor_tamper_body_v1() {
        let buses = canonical_bus_terminal_claims();
        let certificate_or_crl = core::array::from_fn(|_| {
            let (cross_sources, sink) = canonical_terminal_chain(P256EcdsaRoleV1::CertificateOrCrl);
            ZkX509P256CertificatePrivateProductsV1 {
                buses,
                cross_sources: cross_sources.try_into().expect("four certificate sources"),
                sink,
            }
        });
        let (wallet_sources, wallet_sink) =
            canonical_terminal_chain(P256EcdsaRoleV1::WalletOwnership);
        let wallet = ZkX509P256WalletPrivateProductsV1 {
            buses,
            cross_sources: wallet_sources.try_into().expect("five wallet sources"),
            sink: wallet_sink,
        };
        ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(certificate_or_crl, wallet)
            .expect("canonical private products");
        let mut changed = certificate_or_crl;
        changed[0].cross_sources[1].start[0] = changed[0].cross_sources[1].start[0].add(F::ONE);
        assert!(ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(changed, wallet).is_err());
        let mut changed = certificate_or_crl;
        changed[1].sink[1] = changed[1].sink[1].add(F::ONE);
        assert!(ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(changed, wallet).is_err());
        let mut changed = certificate_or_crl;
        changed[2].buses.value_sorted[2] = changed[2].buses.value_sorted[2].add(F::ONE);
        assert!(ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(changed, wallet).is_err());
        let mut changed_wallet = wallet;
        changed_wallet.cross_sources[4].start[3] =
            changed_wallet.cross_sources[4].start[3].add(F::ONE);
        assert!(
            ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(
                certificate_or_crl,
                changed_wallet,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
#[path = "p256_value_aux_batch_tests.rs"]
mod value_aux_batch_tests;

#[cfg(test)]
#[path = "p256_base_replay_batch_tests.rs"]
mod base_replay_batch_tests;

#[cfg(test)]
#[path = "p256_selected_input_binding_tests.rs"]
mod selected_input_binding_tests;
