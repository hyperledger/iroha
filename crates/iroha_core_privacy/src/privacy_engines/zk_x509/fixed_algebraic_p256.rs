//! Compact verifier-derived algebraic fixed schedules for zk-X509 P-256.
//!
//! The first-release P-256 log19 fixed surface has six unique schedules:
//! certificate and wallet arithmetic, value execution, and value-sorted
//! schedules.  Four certificate/CRL signature positions alias the certificate
//! schedule for each adapter and the wallet signature aliases the wallet
//! schedule, yielding exactly fifteen accepted registrations.
//!
//! Compilation consumes only the independently generated value-free P-256
//! topology.  It emits structural affine, repeated-affine, and sparse atoms;
//! it never constructs a `2^19 * 404` native matrix, an LDE, an artifact,
//! a Merkle tree, or proof-supplied fixed bytes.
#[cfg(test)]
use super::fixed_algebraic::ZkX509FixedAlgebraicAtomV1;
#[cfg(test)]
use super::fixed_algebraic::ZkX509FixedAlgebraicOpeningsV1;
#[cfg(test)]
use super::p256_aggregate_adapter::P256_X5S1_SIGNATURES_V1;
#[cfg(test)]
use super::p256_aggregate_adapter::P256AggregateAdapterErrorV1;
use super::{
    fixed_algebraic::{
        ZkX509FixedAlgebraicDomainV1, ZkX509FixedAlgebraicErrorV1,
        ZkX509FixedAlgebraicScheduleBuilderV1, ZkX509FixedAlgebraicScheduleV1,
    },
    p256_aggregate_adapter::{
        P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1, P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
        P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1, P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
        P256MainAdapterV1, P256MainRegistrationV1,
    },
    p256_air::{
        P256_ARITHMETIC_ROWS_PER_OPERATION_V1, P256_ARITHMETIC_STARK_FIXED_WIDTH_V1,
        P256_BASE_MODULUS_BE_V1, P256_SCALAR_MODULUS_BE_V1, ZkX509P256ArithmeticKindV1,
        ZkX509P256ModulusV1,
    },
    p256_ecdsa_air::P256EcdsaRoleV1,
    p256_external_binding_air::{
        P256ExternalBindingErrorV1, compile_zk_x509_p256_external_cross_sources_v1,
        p256_selected_input_writer_id_v1,
    },
    p256_trace::{P256EcdsaTopologyV1, P256TraceCompilerErrorV1, compile_p256_ecdsa_topology_v1},
    p256_value_bus::{
        P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1, P256_VALUE_BUS_LIMBS_V1,
        P256_VALUE_BUS_SEGMENT_ROWS_V1, P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
        P256BooleanBridgeBindingV1, P256EqualityBindingV1, P256InitialValueKindV1, P256ValueIdV1,
        P256ValueKindV1,
    },
    profile::{ZK_X509_MAIN_COMMON_LDE_LOG2_V1, ZK_X509_MAX_NATIVE_TRACE_LOG2_V1},
    stark::ZK_X509_FIXED_DIGEST_CONTEXT_V1,
};
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_GENERATOR_V1, GoldilocksFieldV1 as F, GoldilocksFp4V1 as E, PrivacyOuterDigestV1,
    privacy_outer_digest_frame_v1,
};
use std::{sync::OnceLock, vec::Vec};
use thiserror::Error;
/// Exact compact P-256 fixed-schedule semantics bound by the release profile.
pub const ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1: &[u8] =
    b"zk-x509-p256-fixed-algebraic-v1-incompatible:native-log19:generator-coset-lde-log22:width404:six-schedules=certificate-arithmetic134+wallet-arithmetic134+certificate-execution46+wallet-execution46+certificate-sorted22+wallet-sorted22:typed-composite-children=134,134,46,46,22,22:each-child-generic-cap65536:composite-digest=sha3-384-opaque48-binds-profile+ordered-widths+ordered-child-digests:row-major-child-opening-concatenation:aliases-exactly15=signatures0through4-times-arithmetic0+value-execution0+value-sorted1:signatures0through3-certificate-role:signature4-wallet-role:closed-value-free-topology-only:writer-source=external-sink-plus-selected-Qx-Qy-r-s64-limb-uses:multiplicity-small0through2+64+65+129:additive-affine+repeated-affine+sparse:operation-metadata-plan=min-exact-row-axis-vs-canonical-call-axis:row-axis-on-tie:call-segments=14x43+64x222+row-tail18:sorted-active-factors=725504-distinct-from-execution-logical-factors949312:sorted-equal-read-runs=min-exact-relative-factor-axis-vs-per-value-axis:relative-factor-axis-on-tie:sorted-whole-plan=min-exact-global-local-vs-phase-hybrid:global-local-on-tie:phase-hybrid=prefix893-local+min-local-vs13x43-phase+scalar-boundary222-local+min-local-vs63x222-phase+tail18-local:pinned-boundary-extents=1712,9984:pinned-repeated-extents=1888,10176:local-on-phase-tie:no-native-matrix:no-lde-table:no-artifact:no-merkle:no-proof-fixed-bytes:first-release";
#[cfg(test)]
const P256_COMPILER_DESCRIPTOR_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:p256-fixed-algebraic-compiler:v1";
const P256_COMPOSITE_DESCRIPTOR_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:p256-fixed-algebraic-composite:v1";
/// Exact number of unique verifier-owned schedules.
pub const ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1: usize = 6;
/// Exact number of accepted registration aliases.
#[cfg(test)]
pub const ZK_X509_P256_FIXED_ALGEBRAIC_ALIAS_COUNT_V1: usize = 15;
/// Exact combined fixed width.
pub const ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1: usize = 404;
const P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1: [usize; 6] = [
    P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
    P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
    P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
    P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
    P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
    P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
];
const P256_FIXED_ALGEBRAIC_CHILD_ATOM_COUNTS_V1: [usize; 6] =
    [11_563, 11_563, 28_689, 28_689, 59_556, 59_556];
// Bind the canonical ordered child descriptors, including the distinct selected
// input multiplicities of certificate and wallet execution. Both roles have
// the same width and atom count, so those shape checks cannot identify them.
const P256_FIXED_ALGEBRAIC_COMPOSITE_DIGEST_V1: [u8; 48] = [
    0xfb, 0x20, 0x17, 0x20, 0xf6, 0xda, 0xda, 0x59, 0xa0, 0xee, 0x68, 0x6e, 0x12, 0xc0, 0xa0, 0xc4,
    0x18, 0xc5, 0x37, 0x6c, 0xe4, 0x4e, 0xc1, 0xb3, 0xf2, 0x1a, 0xce, 0x01, 0x59, 0x49, 0x9f, 0x35,
    0x97, 0xd0, 0xa7, 0x5b, 0x05, 0x39, 0xcf, 0x49, 0x24, 0xd7, 0x27, 0xa8, 0xf3, 0x48, 0x5f, 0x19,
];
const CERTIFICATE_ARITHMETIC_START_V1: usize = 0;
const WALLET_ARITHMETIC_START_V1: usize =
    CERTIFICATE_ARITHMETIC_START_V1 + P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1;
const CERTIFICATE_EXECUTION_START_V1: usize =
    WALLET_ARITHMETIC_START_V1 + P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1;
const WALLET_EXECUTION_START_V1: usize =
    CERTIFICATE_EXECUTION_START_V1 + P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1;
const CERTIFICATE_SORTED_START_V1: usize =
    WALLET_EXECUTION_START_V1 + P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1;
const WALLET_SORTED_START_V1: usize =
    CERTIFICATE_SORTED_START_V1 + P256_VALUE_BUS_STARK_FIXED_WIDTH_V1;
const P256_ARITHMETIC_OPERATIONS_V1: usize = 14_828;
const P256_INITIAL_VALUES_V1: usize = 850;
const P256_VALUE_BUS_ASSERTIONS_V1: usize = 5;
const P256_VARIABLE_TABLE_CALLS_V1: usize = 14;
const P256_COMPLETE_ADD_OPERATIONS_V1: usize = 43;
const P256_SCALAR_ROUNDS_V1: usize = 64;
const P256_COMPLETE_DOUBLE_OPERATIONS_V1: usize = 34;
const P256_SCALAR_ROUND_OPERATIONS_V1: usize =
    4 * P256_COMPLETE_DOUBLE_OPERATIONS_V1 + 2 * P256_COMPLETE_ADD_OPERATIONS_V1;
const P256_VARIABLE_TABLE_OPERATIONS_V1: usize =
    P256_VARIABLE_TABLE_CALLS_V1 * P256_COMPLETE_ADD_OPERATIONS_V1;
const P256_FINAL_OPERATION_START_V1: usize =
    P256_VARIABLE_TABLE_OPERATIONS_V1 + P256_SCALAR_ROUNDS_V1 * P256_SCALAR_ROUND_OPERATIONS_V1;
const P256_FINAL_OPERATIONS_V1: usize =
    P256_ARITHMETIC_OPERATIONS_V1 - P256_FINAL_OPERATION_START_V1;
const P256_VARIABLE_VALUE_START_V1: usize = P256_INITIAL_VALUES_V1;
const P256_SCALAR_VALUE_START_V1: usize =
    P256_VARIABLE_VALUE_START_V1 + P256_VARIABLE_TABLE_OPERATIONS_V1;
const P256_FINAL_VALUE_START_V1: usize = P256_INITIAL_VALUES_V1 + P256_FINAL_OPERATION_START_V1;
const P256_VARIABLE_REPEATED_VALUE_START_V1: usize =
    P256_VARIABLE_VALUE_START_V1 + P256_COMPLETE_ADD_OPERATIONS_V1;
const P256_VARIABLE_REPEATED_CALLS_V1: usize = P256_VARIABLE_TABLE_CALLS_V1 - 1;
const P256_SCALAR_REPEATED_VALUE_START_V1: usize =
    P256_SCALAR_VALUE_START_V1 + P256_SCALAR_ROUND_OPERATIONS_V1;
const P256_SCALAR_REPEATED_ROUNDS_V1: usize = P256_SCALAR_ROUNDS_V1 - 1;
const P256_VARIABLE_BOUNDARY_FACTORS_V1: usize = 1_712;
const P256_VARIABLE_REPEATED_BLOCK_FACTORS_V1: usize = 1_888;
const P256_SCALAR_BOUNDARY_FACTORS_V1: usize = 9_984;
const P256_SCALAR_REPEATED_BLOCK_FACTORS_V1: usize = 10_176;
const P256_VALUE_BUS_LOGICAL_FACTORS_V1: usize =
    (P256_ARITHMETIC_OPERATIONS_V1 + P256_VALUE_BUS_ASSERTIONS_V1) * P256_VALUE_BUS_SEGMENT_ROWS_V1;
const P256_VALUE_BUS_LOGICAL_PACKED_ROWS_V1: usize =
    P256_VALUE_BUS_LOGICAL_FACTORS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
const P256_VALUE_BUS_SORTED_ACTIVE_FACTORS_V1: usize =
    P256_ARITHMETIC_OPERATIONS_V1 * 3 * P256_VALUE_BUS_LIMBS_V1
        + P256_INITIAL_VALUES_V1 * P256_VALUE_BUS_LIMBS_V1
        + P256_VALUE_BUS_ASSERTIONS_V1 * 2 * P256_VALUE_BUS_LIMBS_V1;
const P256_VALUE_BUS_SORTED_ACTIVE_PACKED_ROWS_V1: usize =
    P256_VALUE_BUS_SORTED_ACTIVE_FACTORS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
// Native arithmetic fixed layout.
const ARITH_KIND_MULTIPLY_V1: usize = 0;
const ARITH_KIND_ADD_V1: usize = 1;
const ARITH_KIND_SUBTRACT_V1: usize = 2;
const ARITH_MODULUS_START_V1: usize = 3;
const ARITH_COEFFICIENT_START_V1: usize = ARITH_MODULUS_START_V1 + 16;
const ARITH_RANGE_SLOT_START_V1: usize =
    ARITH_COEFFICIENT_START_V1 + P256_ARITHMETIC_ROWS_PER_OPERATION_V1;
const ARITH_LOW_SLOT_START_V1: usize = ARITH_RANGE_SLOT_START_V1 + 16;
const ARITH_LOW_MODULUS_LIMB_V1: usize = ARITH_LOW_SLOT_START_V1 + 16;
const ARITH_CANONICALITY_ROW_V1: usize = ARITH_LOW_MODULUS_LIMB_V1 + 1;
const ARITH_SLOT_FIRST_V1: usize = ARITH_CANONICALITY_ROW_V1 + 1;
const ARITH_SLOT_LAST_V1: usize = ARITH_SLOT_FIRST_V1 + 1;
const ARITH_OPERATION_FIRST_V1: usize = ARITH_SLOT_LAST_V1 + 1;
const ARITH_OPERATION_LAST_V1: usize = ARITH_OPERATION_FIRST_V1 + 1;
const ARITH_PADDING_V1: usize = ARITH_OPERATION_LAST_V1 + 1;
// Arithmetic aggregate suffix.
const ARITH_SCALAR_START_V1: usize = P256_ARITHMETIC_STARK_FIXED_WIDTH_V1;
const ARITH_BOUNDARY_START_V1: usize = ARITH_SCALAR_START_V1 + 8 * 4;
const ARITH_VALUE_COPY_START_V1: usize = ARITH_BOUNDARY_START_V1 + 3;
const ARITH_VALUE_COPY_BOUNDARY_START_V1: usize = ARITH_VALUE_COPY_START_V1 + 3 * 2;
// Packed value-bus layout.
const VALUE_SLOT_WIDTH_V1: usize = 10;
const VALUE_ACTIVE_V1: usize = 0;
const VALUE_ID_V1: usize = 1;
const VALUE_LIMB_V1: usize = 2;
const VALUE_ACCESS_V1: usize = 3;
const VALUE_MODULUS_V1: usize = 4;
const VALUE_KIND_V1: usize = 5;
const VALUE_PADDING_V1: usize = 6;
const VALUE_EQUAL_NEXT_V1: usize = 7;
const VALUE_BOOLEAN_V1: usize = 8;
const VALUE_ZERO_V1: usize = 9;
const VALUE_FIRST_V1: usize = 20;
const VALUE_CONTINUATION_V1: usize = 21;
// Value-execution aggregate suffix.
const EXECUTION_WRITER_START_V1: usize = P256_VALUE_BUS_STARK_FIXED_WIDTH_V1;
const EXECUTION_WRITER_EVENT_WIDTH_V1: usize = 2 * 3;
const EXECUTION_WRITER_MULTIPLICITY_START_V1: usize =
    EXECUTION_WRITER_START_V1 + EXECUTION_WRITER_EVENT_WIDTH_V1;
const EXECUTION_WRITER_BOUNDARY_START_V1: usize = EXECUTION_WRITER_MULTIPLICITY_START_V1 + 2 * 4;
const EXECUTION_VALUE_COPY_START_V1: usize = EXECUTION_WRITER_BOUNDARY_START_V1 + 3;
const EXECUTION_VALUE_COPY_BOUNDARY_START_V1: usize = EXECUTION_VALUE_COPY_START_V1 + 2 * 2;
const _: () = {
    assert!(
        P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1[0]
            + P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1[1]
            + P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1[2]
            + P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1[3]
            + P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1[4]
            + P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1[5]
            == ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1
    );
    assert!(P256_ARITHMETIC_ROWS_PER_OPERATION_V1 == 32);
    assert!(ARITH_PADDING_V1 + 1 == P256_ARITHMETIC_STARK_FIXED_WIDTH_V1);
    assert!(ARITH_VALUE_COPY_BOUNDARY_START_V1 + 3 == P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1);
    assert!(VALUE_CONTINUATION_V1 + 1 == P256_VALUE_BUS_STARK_FIXED_WIDTH_V1);
    assert!(
        EXECUTION_VALUE_COPY_BOUNDARY_START_V1 + 3 == P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1
    );
    assert!(P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 == 1 << 19);
    assert!(P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 == 1 << 19);
    assert!(P256_VARIABLE_TABLE_OPERATIONS_V1 == 602);
    assert!(P256_SCALAR_ROUND_OPERATIONS_V1 == 222);
    assert!(P256_FINAL_OPERATION_START_V1 == 14_810);
    assert!(P256_FINAL_OPERATIONS_V1 == 18);
    assert!(P256_VARIABLE_VALUE_START_V1 == 850);
    assert!(P256_SCALAR_VALUE_START_V1 == 1_452);
    assert!(P256_FINAL_VALUE_START_V1 == 15_660);
    assert!(P256_VARIABLE_REPEATED_VALUE_START_V1 == 893);
    assert!(P256_VARIABLE_REPEATED_CALLS_V1 == 13);
    assert!(P256_SCALAR_REPEATED_VALUE_START_V1 == 1_674);
    assert!(P256_SCALAR_REPEATED_ROUNDS_V1 == 63);
    assert!(P256_FINAL_VALUE_START_V1 + P256_FINAL_OPERATIONS_V1 == 15_678);
    assert!(P256_VALUE_BUS_LOGICAL_FACTORS_V1 == 949_312);
    assert!(P256_VALUE_BUS_LOGICAL_PACKED_ROWS_V1 == 474_656);
    assert!(P256_VALUE_BUS_SORTED_ACTIVE_FACTORS_V1 == 725_504);
    assert!(P256_VALUE_BUS_SORTED_ACTIVE_PACKED_ROWS_V1 == 362_752);
    assert!(P256_VALUE_BUS_SORTED_ACTIVE_FACTORS_V1 < P256_VALUE_BUS_LOGICAL_FACTORS_V1);
    assert!(WALLET_ARITHMETIC_START_V1 == 134);
    assert!(CERTIFICATE_EXECUTION_START_V1 == 268);
    assert!(WALLET_EXECUTION_START_V1 == 314);
    assert!(CERTIFICATE_SORTED_START_V1 == 360);
    assert!(WALLET_SORTED_START_V1 == 382);
    assert!(
        WALLET_SORTED_START_V1 + P256_VALUE_BUS_STARK_FIXED_WIDTH_V1
            == ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1
    );
};
/// P-256 algebraic fixed compilation or alias-selection failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509P256FixedAlgebraicErrorV1 {
    /// The independently compiled P-256 topology is not the release topology.
    #[error("zk-X509 P-256 algebraic fixed topology is invalid")]
    Topology,
    /// Checked arithmetic or a bounded allocation exceeded the release shape.
    #[error("zk-X509 P-256 algebraic fixed resource bound is exceeded")]
    Resource,
    /// The shared algebraic schedule kernel rejected the compiled schedule.
    #[error("zk-X509 P-256 algebraic fixed schedule is invalid: {0}")]
    Algebraic(ZkX509FixedAlgebraicErrorV1),
}
impl From<ZkX509FixedAlgebraicErrorV1> for ZkX509P256FixedAlgebraicErrorV1 {
    fn from(error: ZkX509FixedAlgebraicErrorV1) -> Self {
        Self::Algebraic(error)
    }
}
fn map_trace_error_v1(error: P256TraceCompilerErrorV1) -> ZkX509P256FixedAlgebraicErrorV1 {
    match error {
        P256TraceCompilerErrorV1::Resource => ZkX509P256FixedAlgebraicErrorV1::Resource,
        _ => ZkX509P256FixedAlgebraicErrorV1::Topology,
    }
}
fn map_external_error_v1(error: P256ExternalBindingErrorV1) -> ZkX509P256FixedAlgebraicErrorV1 {
    match error {
        P256ExternalBindingErrorV1::Resource => ZkX509P256FixedAlgebraicErrorV1::Resource,
        _ => ZkX509P256FixedAlgebraicErrorV1::Topology,
    }
}
#[cfg(test)]
fn map_adapter_error_v1(error: P256AggregateAdapterErrorV1) -> ZkX509P256FixedAlgebraicErrorV1 {
    match error {
        P256AggregateAdapterErrorV1::Resource => ZkX509P256FixedAlgebraicErrorV1::Resource,
        _ => ZkX509P256FixedAlgebraicErrorV1::Topology,
    }
}
/// One of the six unique P-256 fixed schedules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZkX509P256FixedAlgebraicScheduleKindV1 {
    /// Certificate/CRL arithmetic.
    CertificateArithmetic,
    /// Wallet-ownership arithmetic.
    WalletArithmetic,
    /// Certificate/CRL execution-order value bus plus attached sources.
    CertificateExecution,
    /// Wallet-ownership execution-order value bus plus attached sources.
    WalletExecution,
    /// Certificate/CRL writer-first sorted value bus.
    CertificateSorted,
    /// Wallet-ownership writer-first sorted value bus.
    WalletSorted,
}
impl ZkX509P256FixedAlgebraicScheduleKindV1 {
    /// Exact slice in the combined 404-column schedule.
    pub(crate) const fn start_width_v1(self) -> (usize, usize) {
        match self {
            Self::CertificateArithmetic => (
                CERTIFICATE_ARITHMETIC_START_V1,
                P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
            ),
            Self::WalletArithmetic => (
                WALLET_ARITHMETIC_START_V1,
                P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
            ),
            Self::CertificateExecution => (
                CERTIFICATE_EXECUTION_START_V1,
                P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
            ),
            Self::WalletExecution => (
                WALLET_EXECUTION_START_V1,
                P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
            ),
            Self::CertificateSorted => (
                CERTIFICATE_SORTED_START_V1,
                P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
            ),
            Self::WalletSorted => (WALLET_SORTED_START_V1, P256_VALUE_BUS_STARK_FIXED_WIDTH_V1),
        }
    }
    /// Representative canonical MAIN registration.
    #[cfg(test)]
    pub(crate) fn representative_registration_v1(
        self,
    ) -> Result<P256MainRegistrationV1, ZkX509P256FixedAlgebraicErrorV1> {
        let certificate = 0;
        let wallet = P256_X5S1_SIGNATURES_V1
            .checked_sub(1)
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
        let (signature, adapter, local) = match self {
            Self::CertificateArithmetic => (certificate, P256MainAdapterV1::Arithmetic, 0),
            Self::WalletArithmetic => (wallet, P256MainAdapterV1::Arithmetic, 0),
            Self::CertificateExecution => (certificate, P256MainAdapterV1::ValueBus, 0),
            Self::WalletExecution => (wallet, P256MainAdapterV1::ValueBus, 0),
            Self::CertificateSorted => (certificate, P256MainAdapterV1::ValueBus, 1),
            Self::WalletSorted => (wallet, P256MainAdapterV1::ValueBus, 1),
        };
        P256MainRegistrationV1::new_v1(signature, adapter, local).map_err(map_adapter_error_v1)
    }
}
/// Resolve one of the exact fifteen supported MAIN registrations.
pub fn zk_x509_p256_fixed_algebraic_schedule_for_registration_v1(
    registration: P256MainRegistrationV1,
) -> Result<ZkX509P256FixedAlgebraicScheduleKindV1, ZkX509P256FixedAlgebraicErrorV1> {
    let certificate = registration.role_v1() == P256EcdsaRoleV1::CertificateOrCrl;
    match (
        registration.adapter_v1(),
        registration.local_instance_v1(),
        certificate,
    ) {
        (P256MainAdapterV1::Arithmetic, 0, true) => {
            Ok(ZkX509P256FixedAlgebraicScheduleKindV1::CertificateArithmetic)
        }
        (P256MainAdapterV1::Arithmetic, 0, false) => {
            Ok(ZkX509P256FixedAlgebraicScheduleKindV1::WalletArithmetic)
        }
        (P256MainAdapterV1::ValueBus, 0, true) => {
            Ok(ZkX509P256FixedAlgebraicScheduleKindV1::CertificateExecution)
        }
        (P256MainAdapterV1::ValueBus, 0, false) => {
            Ok(ZkX509P256FixedAlgebraicScheduleKindV1::WalletExecution)
        }
        (P256MainAdapterV1::ValueBus, 1, true) => {
            Ok(ZkX509P256FixedAlgebraicScheduleKindV1::CertificateSorted)
        }
        (P256MainAdapterV1::ValueBus, 1, false) => {
            Ok(ZkX509P256FixedAlgebraicScheduleKindV1::WalletSorted)
        }
        _ => Err(ZkX509P256FixedAlgebraicErrorV1::Topology),
    }
}
#[cfg(test)]
/// Borrow one registration's fixed slice from a combined algebraic opening.
pub fn zk_x509_p256_fixed_algebraic_row_for_registration_v1<'a>(
    combined: &'a [F],
    registration: P256MainRegistrationV1,
) -> Result<&'a [F], ZkX509P256FixedAlgebraicErrorV1> {
    if combined.len() != ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let schedule = zk_x509_p256_fixed_algebraic_schedule_for_registration_v1(registration)?;
    let (start, width) = schedule.start_width_v1();
    let shape = registration.shape_v1().map_err(map_adapter_error_v1)?;
    if shape.trace_size != 1_usize << ZK_X509_MAX_NATIVE_TRACE_LOG2_V1 || shape.fixed_width != width
    {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    combined
        .get(start..start + width)
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256ValueMetadataV1 {
    modulus: ZkX509P256ModulusV1,
    kind: P256ValueKindV1,
    reads: usize,
}
fn checked_add_v1(left: usize, right: usize) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    left.checked_add(right)
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Resource)
}
fn checked_mul_v1(left: usize, right: usize) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    left.checked_mul(right)
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Resource)
}
fn u16_v1(value: usize) -> Result<u16, ZkX509P256FixedAlgebraicErrorV1> {
    u16::try_from(value).map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)
}
fn u64_v1(value: usize) -> Result<u64, ZkX509P256FixedAlgebraicErrorV1> {
    u64::try_from(value).map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)
}
fn id_index_v1(id: P256ValueIdV1) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    usize::try_from(id.0).map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)
}
fn f_usize_v1(value: usize) -> Result<F, ZkX509P256FixedAlgebraicErrorV1> {
    Ok(F(u64_v1(value)?))
}
fn negative_one_v1() -> F {
    F::ZERO.sub(F::ONE)
}
fn push_contiguous_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    start: usize,
    end: usize,
    start_value: F,
    step: F,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if start >= end {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    if start_value == F::ZERO && step == F::ZERO {
        return Ok(());
    }
    if end - start == 1 {
        if start_value != F::ZERO {
            builder.push_sparse_v1(u16_v1(column)?, u64_v1(start)?, start_value)?;
        }
        return Ok(());
    }
    builder.push_affine_v1(
        u16_v1(column)?,
        u64_v1(start)?,
        u64_v1(end)?,
        start_value,
        step,
    )?;
    Ok(())
}
fn push_sparse_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    row: usize,
    value: F,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if value != F::ZERO {
        builder.push_sparse_v1(u16_v1(column)?, u64_v1(row)?, value)?;
    }
    Ok(())
}
fn push_repeated_affine_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    first: usize,
    count: usize,
    stride: usize,
    start_value: F,
    step: F,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if count == 0 || stride == 0 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    if start_value == F::ZERO && step == F::ZERO {
        return Ok(());
    }
    if count == 1 {
        return push_sparse_v1(builder, column, first, start_value);
    }
    if stride == 1 {
        return push_contiguous_v1(
            builder,
            column,
            first,
            checked_add_v1(first, count)?,
            start_value,
            step,
        );
    }
    builder.push_repeated_affine_v1(
        u16_v1(column)?,
        u64_v1(first)?,
        u64_v1(count)?,
        u64_v1(stride)?,
        start_value,
        step,
    )?;
    Ok(())
}
fn push_repeated_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    first: usize,
    count: usize,
    stride: usize,
    value: F,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    push_repeated_affine_v1(builder, column, first, count, stride, value, F::ZERO)
}
fn push_strided_sequence_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    first: usize,
    stride: usize,
    values: &[F],
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if values.is_empty() || stride == 0 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut start = 0_usize;
    while start < values.len() {
        if start + 1 == values.len() {
            let row = checked_add_v1(first, checked_mul_v1(start, stride)?)?;
            push_sparse_v1(builder, column, row, values[start])?;
            break;
        }
        let step = values[start + 1].sub(values[start]);
        let mut end = start + 2;
        while end < values.len() && values[end].sub(values[end - 1]) == step {
            end += 1;
        }
        let row = checked_add_v1(first, checked_mul_v1(start, stride)?)?;
        push_repeated_affine_v1(
            builder,
            column,
            row,
            end - start,
            stride,
            values[start],
            step,
        )?;
        start = end;
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256OperationCallSegmentV1 {
    first_operation: usize,
    calls: usize,
    operations_per_call: usize,
}
const P256_OPERATION_CALL_SEGMENTS_V1: [P256OperationCallSegmentV1; 2] = [
    P256OperationCallSegmentV1 {
        first_operation: 0,
        calls: P256_VARIABLE_TABLE_CALLS_V1,
        operations_per_call: P256_COMPLETE_ADD_OPERATIONS_V1,
    },
    P256OperationCallSegmentV1 {
        first_operation: P256_VARIABLE_TABLE_OPERATIONS_V1,
        calls: P256_SCALAR_ROUNDS_V1,
        operations_per_call: P256_SCALAR_ROUND_OPERATIONS_V1,
    },
];
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum P256OperationSequenceAxisV1 {
    Row,
    Call,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256OperationSequenceRunV1 {
    first: usize,
    count: usize,
    stride: usize,
    start_value: F,
    step: F,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct P256OperationSequencePlanV1 {
    #[cfg(test)]
    axis: P256OperationSequenceAxisV1,
    runs: Vec<P256OperationSequenceRunV1>,
}
fn append_projected_sequence_runs_v1(
    runs: &mut Vec<P256OperationSequenceRunV1>,
    physical_first: usize,
    physical_stride: usize,
    values: &[F],
    value_first: usize,
    value_stride: usize,
    value_count: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if physical_stride == 0 || value_stride == 0 || value_count == 0 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let last_value = checked_add_v1(value_first, checked_mul_v1(value_count - 1, value_stride)?)?;
    if last_value >= values.len() {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let value_at = |index: usize| -> Result<F, ZkX509P256FixedAlgebraicErrorV1> {
        values
            .get(checked_add_v1(
                value_first,
                checked_mul_v1(index, value_stride)?,
            )?)
            .copied()
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)
    };
    let mut start = 0_usize;
    while start < value_count {
        let start_value = value_at(start)?;
        if start + 1 == value_count {
            if start_value != F::ZERO {
                runs.push(P256OperationSequenceRunV1 {
                    first: checked_add_v1(physical_first, checked_mul_v1(start, physical_stride)?)?,
                    count: 1,
                    stride: physical_stride,
                    start_value,
                    step: F::ZERO,
                });
            }
            break;
        }
        let step = value_at(start + 1)?.sub(start_value);
        let mut end = start + 2;
        while end < value_count && value_at(end)?.sub(value_at(end - 1)?) == step {
            end += 1;
        }
        if start_value != F::ZERO || step != F::ZERO {
            runs.push(P256OperationSequenceRunV1 {
                first: checked_add_v1(physical_first, checked_mul_v1(start, physical_stride)?)?,
                count: end - start,
                stride: physical_stride,
                start_value,
                step,
            });
        }
        start = end;
    }
    Ok(())
}
fn compile_p256_operation_sequence_plan_for_layout_v1(
    values: &[F],
    call_segments: &[P256OperationCallSegmentV1],
    row_tail_start: usize,
) -> Result<P256OperationSequencePlanV1, ZkX509P256FixedAlgebraicErrorV1> {
    if values.is_empty() || row_tail_start >= values.len() {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    // Every projected value belongs to exactly one run, so `values.len()` is
    // a strict allocation bound even for adversarial segment partitions.
    let maximum_runs = values.len();
    let mut row_runs = Vec::new();
    row_runs
        .try_reserve_exact(maximum_runs)
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    append_projected_sequence_runs_v1(
        &mut row_runs,
        0,
        P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
        values,
        0,
        1,
        values.len(),
    )?;
    let mut call_runs = Vec::new();
    call_runs
        .try_reserve_exact(maximum_runs)
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    let mut expected_first = 0_usize;
    for segment in call_segments.iter().copied() {
        if segment.first_operation != expected_first
            || segment.calls < 2
            || segment.operations_per_call == 0
        {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        let segment_operations = checked_mul_v1(segment.calls, segment.operations_per_call)?;
        let segment_end = checked_add_v1(segment.first_operation, segment_operations)?;
        if segment_end > row_tail_start {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        for operation_in_call in 0..segment.operations_per_call {
            let operation = checked_add_v1(segment.first_operation, operation_in_call)?;
            append_projected_sequence_runs_v1(
                &mut call_runs,
                checked_mul_v1(
                    operation,
                    P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
                )?,
                checked_mul_v1(
                    segment.operations_per_call,
                    P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
                )?,
                values,
                operation,
                segment.operations_per_call,
                segment.calls,
            )?;
        }
        expected_first = segment_end;
    }
    if expected_first != row_tail_start {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    append_projected_sequence_runs_v1(
        &mut call_runs,
        checked_mul_v1(
            row_tail_start,
            P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
        )?,
        P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
        values,
        row_tail_start,
        1,
        values.len() - row_tail_start,
    )?;
    if call_runs.len() < row_runs.len() {
        Ok(P256OperationSequencePlanV1 {
            #[cfg(test)]
            axis: P256OperationSequenceAxisV1::Call,
            runs: call_runs,
        })
    } else {
        Ok(P256OperationSequencePlanV1 {
            #[cfg(test)]
            axis: P256OperationSequenceAxisV1::Row,
            runs: row_runs,
        })
    }
}
fn compile_p256_operation_sequence_plan_v1(
    values: &[F],
) -> Result<P256OperationSequencePlanV1, ZkX509P256FixedAlgebraicErrorV1> {
    if values.len() != P256_ARITHMETIC_OPERATIONS_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    compile_p256_operation_sequence_plan_for_layout_v1(
        values,
        &P256_OPERATION_CALL_SEGMENTS_V1,
        P256_FINAL_OPERATION_START_V1,
    )
}
fn push_p256_operation_sequence_plan_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    first: usize,
    plan: &P256OperationSequencePlanV1,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    for run in plan.runs.iter().copied() {
        push_repeated_affine_v1(
            builder,
            column,
            checked_add_v1(first, run.first)?,
            run.count,
            run.stride,
            run.start_value,
            run.step,
        )?;
    }
    Ok(())
}
fn compile_value_metadata_v1(
    topology: &P256EcdsaTopologyV1,
) -> Result<Vec<P256ValueMetadataV1>, ZkX509P256FixedAlgebraicErrorV1> {
    if topology.initial_values.len() != P256_INITIAL_VALUES_V1
        || topology.linked_operations.len() != P256_ARITHMETIC_OPERATIONS_V1
        || topology.equalities.len() + topology.boolean_bridges.len()
            != P256_VALUE_BUS_ASSERTIONS_V1
    {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let value_count = checked_add_v1(
        topology.initial_values.len(),
        topology.linked_operations.len(),
    )?;
    let mut metadata = Vec::new();
    metadata
        .try_reserve_exact(value_count)
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    for (index, initial) in topology.initial_values.iter().copied().enumerate() {
        if id_index_v1(initial.id)? != index {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        metadata.push(P256ValueMetadataV1 {
            modulus: initial.modulus,
            kind: match initial.kind {
                P256InitialValueKindV1::Input => P256ValueKindV1::Input,
                P256InitialValueKindV1::Constant => P256ValueKindV1::Constant,
            },
            reads: 0,
        });
    }
    for (operation_index, operation) in topology.linked_operations.iter().copied().enumerate() {
        let expected_c = checked_add_v1(P256_INITIAL_VALUES_V1, operation_index)?;
        if id_index_v1(operation.c)? != expected_c {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        for id in [operation.a, operation.b] {
            let value = metadata
                .get_mut(id_index_v1(id)?)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
            if value.modulus != operation.modulus {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            value.reads = checked_add_v1(value.reads, 1)?;
        }
        metadata.push(P256ValueMetadataV1 {
            modulus: operation.modulus,
            kind: P256ValueKindV1::Derived,
            reads: 0,
        });
    }
    for P256EqualityBindingV1 { left, right } in topology.equalities.iter().copied() {
        if left == right {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        let left_index = id_index_v1(left)?;
        let right_index = id_index_v1(right)?;
        if metadata.get(left_index).map(|value| value.modulus)
            != metadata.get(right_index).map(|value| value.modulus)
        {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        for index in [left_index, right_index] {
            let value = metadata
                .get_mut(index)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
            value.reads = checked_add_v1(value.reads, 1)?;
        }
    }
    for P256BooleanBridgeBindingV1 {
        scalar_bit,
        base_bit,
    } in topology.boolean_bridges.iter().copied()
    {
        let scalar = id_index_v1(scalar_bit)?;
        let base = id_index_v1(base_bit)?;
        if metadata.get(scalar).map(|value| value.modulus) != Some(ZkX509P256ModulusV1::ScalarField)
            || metadata.get(base).map(|value| value.modulus) != Some(ZkX509P256ModulusV1::BaseField)
        {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        for index in [scalar, base] {
            let value = metadata
                .get_mut(index)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
            value.reads = checked_add_v1(value.reads, 1)?;
        }
    }
    if metadata.len() != value_count {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(metadata)
}
fn modulus_field_v1(modulus: ZkX509P256ModulusV1) -> F {
    match modulus {
        ZkX509P256ModulusV1::BaseField => F(1),
        ZkX509P256ModulusV1::ScalarField => F(2),
    }
}
fn value_kind_field_v1(kind: P256ValueKindV1) -> F {
    match kind {
        P256ValueKindV1::Input => F(1),
        P256ValueKindV1::Constant => F(2),
        P256ValueKindV1::Derived => F(3),
    }
}
fn modulus_limbs_v1(modulus: ZkX509P256ModulusV1) -> [u16; 16] {
    let bytes = match modulus {
        ZkX509P256ModulusV1::BaseField => P256_BASE_MODULUS_BE_V1,
        ZkX509P256ModulusV1::ScalarField => P256_SCALAR_MODULUS_BE_V1,
    };
    core::array::from_fn(|index| {
        let low = 31 - 2 * index;
        u16::from_le_bytes([bytes[low], bytes[low - 1]])
    })
}
fn value_slot_column_v1(slice_start: usize, slot: usize, field: usize) -> usize {
    slice_start + slot * VALUE_SLOT_WIDTH_V1 + field
}
fn arithmetic_kind_column_v1(kind: ZkX509P256ArithmeticKindV1) -> usize {
    match kind {
        ZkX509P256ArithmeticKindV1::Multiply => ARITH_KIND_MULTIPLY_V1,
        ZkX509P256ArithmeticKindV1::Add => ARITH_KIND_ADD_V1,
        ZkX509P256ArithmeticKindV1::Subtract => ARITH_KIND_SUBTRACT_V1,
    }
}
fn compile_arithmetic_fixed_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    topology: &P256EcdsaTopologyV1,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    let operations = &topology.linked_operations;
    if operations.len() != P256_ARITHMETIC_OPERATIONS_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let active_rows = checked_mul_v1(operations.len(), P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?;
    if active_rows > P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    // Each instruction kind is a maximal contiguous block selector.
    let mut run_start = 0_usize;
    while run_start < operations.len() {
        let kind = operations[run_start].kind;
        let mut run_end = run_start + 1;
        while run_end < operations.len() && operations[run_end].kind == kind {
            run_end += 1;
        }
        push_contiguous_v1(
            builder,
            slice_start + arithmetic_kind_column_v1(kind),
            checked_mul_v1(run_start, P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?,
            checked_mul_v1(run_end, P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?,
            F::ONE,
            F::ZERO,
        )?;
        run_start = run_end;
    }
    // Base-field modulus limbs are the common schedule. Scalar-field
    // instructions add the exact limb delta on their contiguous operation
    // runs, avoiding sixteen copies of the complete instruction topology.
    let base_limbs = modulus_limbs_v1(ZkX509P256ModulusV1::BaseField);
    let scalar_limbs = modulus_limbs_v1(ZkX509P256ModulusV1::ScalarField);
    for (limb, value) in base_limbs.into_iter().enumerate() {
        push_contiguous_v1(
            builder,
            slice_start + ARITH_MODULUS_START_V1 + limb,
            0,
            active_rows,
            F(u64::from(value)),
            F::ZERO,
        )?;
        push_repeated_v1(
            builder,
            slice_start + ARITH_LOW_MODULUS_LIMB_V1,
            limb,
            operations.len(),
            P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F(u64::from(value)),
        )?;
    }
    let mut scalar_run_start = 0_usize;
    while scalar_run_start < operations.len() {
        if operations[scalar_run_start].modulus != ZkX509P256ModulusV1::ScalarField {
            scalar_run_start += 1;
            continue;
        }
        let mut scalar_run_end = scalar_run_start + 1;
        while scalar_run_end < operations.len()
            && operations[scalar_run_end].modulus == ZkX509P256ModulusV1::ScalarField
        {
            scalar_run_end += 1;
        }
        for limb in 0..16 {
            let delta = F(u64::from(scalar_limbs[limb])).sub(F(u64::from(base_limbs[limb])));
            push_contiguous_v1(
                builder,
                slice_start + ARITH_MODULUS_START_V1 + limb,
                checked_mul_v1(scalar_run_start, P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?,
                checked_mul_v1(scalar_run_end, P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?,
                delta,
                F::ZERO,
            )?;
            push_repeated_v1(
                builder,
                slice_start + ARITH_LOW_MODULUS_LIMB_V1,
                checked_add_v1(
                    checked_mul_v1(scalar_run_start, P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?,
                    limb,
                )?,
                scalar_run_end - scalar_run_start,
                P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
                delta,
            )?;
        }
        scalar_run_start = scalar_run_end;
    }
    // Coefficient and range-slot schedules repeat identically for every
    // instruction.
    for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
        push_repeated_v1(
            builder,
            slice_start + ARITH_COEFFICIENT_START_V1 + coefficient,
            coefficient,
            operations.len(),
            P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F::ONE,
        )?;
    }
    for limb in 0..16 {
        for coefficient in [limb, limb + 16] {
            push_repeated_v1(
                builder,
                slice_start + ARITH_RANGE_SLOT_START_V1 + limb,
                coefficient,
                operations.len(),
                P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
                F::ONE,
            )?;
        }
        push_repeated_v1(
            builder,
            slice_start + ARITH_LOW_SLOT_START_V1 + limb,
            limb,
            operations.len(),
            P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F::ONE,
        )?;
        push_repeated_v1(
            builder,
            slice_start + ARITH_CANONICALITY_ROW_V1,
            limb,
            operations.len(),
            P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F::ONE,
        )?;
    }
    for (column, coefficient) in [
        (ARITH_SLOT_FIRST_V1, 0),
        (ARITH_SLOT_FIRST_V1, 16),
        (ARITH_SLOT_LAST_V1, 15),
        (ARITH_SLOT_LAST_V1, 31),
        (ARITH_OPERATION_FIRST_V1, 0),
        (ARITH_OPERATION_LAST_V1, 31),
    ] {
        push_repeated_v1(
            builder,
            slice_start + column,
            coefficient,
            operations.len(),
            P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F::ONE,
        )?;
    }
    push_contiguous_v1(
        builder,
        slice_start + ARITH_PADDING_V1,
        active_rows,
        P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
        F::ONE,
        F::ZERO,
    )?;
    // The scalar-bit source is confined to instruction positions 13 and 14.
    for slot in 0..8 {
        let scalar_column = slice_start + ARITH_SCALAR_START_V1 + slot * 4;
        push_contiguous_v1(
            builder,
            scalar_column,
            13 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            15 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F::ONE,
            F::ZERO,
        )?;
        push_contiguous_v1(
            builder,
            scalar_column + 1,
            13 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            14 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F::ONE,
            F::ZERO,
        )?;
        push_contiguous_v1(
            builder,
            scalar_column + 1,
            14 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            15 * P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
            F(2),
            F::ZERO,
        )?;
        for operation in 13..15 {
            for coefficient in 0..P256_ARITHMETIC_ROWS_PER_OPERATION_V1 {
                let limb = coefficient % 16;
                let bit_offset = if coefficient < 16 { 0 } else { 8 };
                let little_endian = checked_add_v1(checked_mul_v1(limb, 16)?, bit_offset + slot)?;
                let big_endian = 255_usize
                    .checked_sub(little_endian)
                    .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
                let row = checked_add_v1(
                    checked_mul_v1(operation, P256_ARITHMETIC_ROWS_PER_OPERATION_V1)?,
                    coefficient,
                )?;
                push_sparse_v1(
                    builder,
                    scalar_column + 2,
                    row,
                    f_usize_v1(big_endian / 4 + 1)?,
                )?;
                push_sparse_v1(
                    builder,
                    scalar_column + 3,
                    row,
                    f_usize_v1(big_endian % 4 + 1)?,
                )?;
            }
        }
    }
    push_boundary_v1(
        builder,
        slice_start + ARITH_BOUNDARY_START_V1,
        P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
    )?;
    // Three arithmetic-copy events occupy the first sixteen coefficient rows
    // of every operation.  Their addresses are affine both within and across
    // operations.
    for slot in 0..3 {
        let event = slice_start + ARITH_VALUE_COPY_START_V1 + slot * 2;
        for coefficient in 0..16 {
            push_repeated_v1(
                builder,
                event,
                coefficient,
                operations.len(),
                P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
                F::ONE,
            )?;
            push_repeated_affine_v1(
                builder,
                event + 1,
                coefficient,
                operations.len(),
                P256_ARITHMETIC_ROWS_PER_OPERATION_V1,
                f_usize_v1(checked_add_v1(checked_mul_v1(coefficient, 3)?, slot)?)?,
                F(48),
            )?;
        }
    }
    push_boundary_v1(
        builder,
        slice_start + ARITH_VALUE_COPY_BOUNDARY_START_V1,
        P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1,
    )
}
fn push_boundary_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column_start: usize,
    rows: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if rows < 2 || !rows.is_power_of_two() {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    push_sparse_v1(builder, column_start, 0, F::ONE)?;
    push_sparse_v1(builder, column_start + 1, rows - 1, F::ONE)?;
    push_contiguous_v1(builder, column_start + 2, 0, rows - 1, F::ONE, F::ZERO)
}
fn compile_execution_fixed_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    topology: &P256EcdsaTopologyV1,
    metadata: &[P256ValueMetadataV1],
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if topology.linked_operations.len() != P256_ARITHMETIC_OPERATIONS_V1
        || topology.initial_values.len() != P256_INITIAL_VALUES_V1
        || metadata.len() != P256_INITIAL_VALUES_V1 + P256_ARITHMETIC_OPERATIONS_V1
    {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let operations = &topology.linked_operations;
    // Every arithmetic segment exposes 48 execution factors, followed by an
    // initial writer only in the first 850 segments.
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let active = value_slot_column_v1(slice_start, slot, VALUE_ACTIVE_V1);
        for offset in 0..24 {
            push_repeated_v1(
                builder,
                active,
                offset,
                operations.len(),
                P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
                F::ONE,
            )?;
        }
        for offset in 24..32 {
            push_repeated_v1(
                builder,
                active,
                offset,
                P256_INITIAL_VALUES_V1,
                P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
                F::ONE,
            )?;
            push_repeated_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_PADDING_V1),
                checked_add_v1(checked_mul_v1(P256_INITIAL_VALUES_V1, 32)?, offset)?,
                operations.len() - P256_INITIAL_VALUES_V1,
                32,
                F::ONE,
            )?;
        }
    }
    // Operation operands use six parity-separated three-row progressions.
    // Compile each metadata vector once, compare its exact row-axis encoding
    // with the canonical formula-call transpose, and replay the smaller plan
    // at all sixteen limb-pair offsets. The deterministic row-on-tie rule is
    // part of the compiler descriptor.
    for operand in 0..3 {
        let mut ids = Vec::new();
        let mut moduli = Vec::new();
        let mut kinds = Vec::new();
        ids.try_reserve_exact(operations.len())
            .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
        moduli
            .try_reserve_exact(operations.len())
            .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
        kinds
            .try_reserve_exact(operations.len())
            .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
        for operation in operations.iter().copied() {
            let id = match operand {
                0 => operation.a,
                1 => operation.b,
                2 => operation.c,
                _ => return Err(ZkX509P256FixedAlgebraicErrorV1::Topology),
            };
            let meta = metadata
                .get(id_index_v1(id)?)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
            ids.push(F(u64::from(id.0)));
            moduli.push(modulus_field_v1(meta.modulus));
            kinds.push(value_kind_field_v1(meta.kind));
        }
        let id_plan = compile_p256_operation_sequence_plan_v1(&ids)?;
        let modulus_plan = compile_p256_operation_sequence_plan_v1(&moduli)?;
        let kind_plan = compile_p256_operation_sequence_plan_v1(&kinds)?;
        for parity in 0..2 {
            let local = checked_add_v1(checked_mul_v1(3, parity)?, operand)?;
            let slot = local % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
            let first_offset = local / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
            for limb_pair in 0..8 {
                let first = checked_add_v1(first_offset, checked_mul_v1(limb_pair, 3)?)?;
                push_p256_operation_sequence_plan_v1(
                    builder,
                    value_slot_column_v1(slice_start, slot, VALUE_ID_V1),
                    first,
                    &id_plan,
                )?;
                push_p256_operation_sequence_plan_v1(
                    builder,
                    value_slot_column_v1(slice_start, slot, VALUE_MODULUS_V1),
                    first,
                    &modulus_plan,
                )?;
                push_p256_operation_sequence_plan_v1(
                    builder,
                    value_slot_column_v1(slice_start, slot, VALUE_KIND_V1),
                    first,
                    &kind_plan,
                )?;
            }
        }
    }
    // Limb and access schedules are identical in every arithmetic segment.
    for local in 0..48 {
        let slot = local % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let row = local / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let operand = local % 3;
        push_repeated_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_LIMB_V1),
            row,
            operations.len(),
            32,
            f_usize_v1(local / 3)?,
        )?;
        push_repeated_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_ACCESS_V1),
            row,
            operations.len(),
            32,
            F(if operand == 2 { 1 } else { 2 }),
        )?;
    }
    // Initial writers are eight packed rows. Their identifiers, modulus, and
    // origin kind are affine sequences across the first 850 operation slots.
    let mut initial_ids = Vec::new();
    let mut initial_moduli = Vec::new();
    let mut initial_kinds = Vec::new();
    for values in [&mut initial_ids, &mut initial_moduli, &mut initial_kinds] {
        values
            .try_reserve_exact(topology.initial_values.len())
            .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    }
    for initial in topology.initial_values.iter().copied() {
        initial_ids.push(F(u64::from(initial.id.0)));
        initial_moduli.push(modulus_field_v1(initial.modulus));
        initial_kinds.push(match initial.kind {
            P256InitialValueKindV1::Input => value_kind_field_v1(P256ValueKindV1::Input),
            P256InitialValueKindV1::Constant => value_kind_field_v1(P256ValueKindV1::Constant),
        });
    }
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        for offset in 0..8 {
            let first = 24 + offset;
            push_strided_sequence_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_ID_V1),
                first,
                32,
                &initial_ids,
            )?;
            push_strided_sequence_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_MODULUS_V1),
                first,
                32,
                &initial_moduli,
            )?;
            push_strided_sequence_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_KIND_V1),
                first,
                32,
                &initial_kinds,
            )?;
            push_repeated_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_LIMB_V1),
                first,
                P256_INITIAL_VALUES_V1,
                32,
                f_usize_v1(offset * 2 + slot)?,
            )?;
            push_repeated_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_ACCESS_V1),
                first,
                P256_INITIAL_VALUES_V1,
                32,
                F::ONE,
            )?;
        }
    }
    let mut assertion_index = 0_usize;
    for equality in topology.equalities.iter().copied() {
        compile_execution_assertion_v1(
            builder,
            slice_start,
            metadata,
            assertion_index,
            equality.left,
            equality.right,
            false,
        )?;
        assertion_index += 1;
    }
    for bridge in topology.boolean_bridges.iter().copied() {
        compile_execution_assertion_v1(
            builder,
            slice_start,
            metadata,
            assertion_index,
            bridge.scalar_bit,
            bridge.base_bit,
            true,
        )?;
        assertion_index += 1;
    }
    if assertion_index != P256_VALUE_BUS_ASSERTIONS_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    // Canonical packed suffix.
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        push_contiguous_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_PADDING_V1),
            P256_VALUE_BUS_LOGICAL_PACKED_ROWS_V1,
            P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
            F::ONE,
            F::ZERO,
        )?;
    }
    push_value_bus_boundaries_v1(builder, slice_start)?;
    compile_writer_fixed_v1(builder, slice_start, topology.role, metadata.len())?;
    compile_value_copy_fixed_v1(builder, slice_start)
}
fn compile_execution_assertion_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    metadata: &[P256ValueMetadataV1],
    assertion_index: usize,
    left: P256ValueIdV1,
    right: P256ValueIdV1,
    boolean: bool,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if assertion_index >= P256_VALUE_BUS_ASSERTIONS_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let segment = checked_add_v1(P256_ARITHMETIC_OPERATIONS_V1, assertion_index)?;
    let start = checked_mul_v1(segment, 32)?;
    for (slot, id) in [left, right].into_iter().enumerate() {
        let meta = metadata
            .get(id_index_v1(id)?)
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
        for (field, value) in [
            (VALUE_ACTIVE_V1, F::ONE),
            (VALUE_ID_V1, F(u64::from(id.0))),
            (VALUE_ACCESS_V1, F(2)),
            (VALUE_MODULUS_V1, modulus_field_v1(meta.modulus)),
            (VALUE_KIND_V1, value_kind_field_v1(meta.kind)),
        ] {
            push_contiguous_v1(
                builder,
                value_slot_column_v1(slice_start, slot, field),
                start,
                start + 16,
                value,
                F::ZERO,
            )?;
        }
        push_contiguous_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_LIMB_V1),
            start,
            start + 16,
            F::ZERO,
            F::ONE,
        )?;
        push_contiguous_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_PADDING_V1),
            start + 16,
            start + 32,
            F::ONE,
            F::ZERO,
        )?;
        if boolean {
            push_sparse_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_BOOLEAN_V1),
                start,
                F::ONE,
            )?;
            push_contiguous_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_ZERO_V1),
                start + 1,
                start + 16,
                F::ONE,
                F::ZERO,
            )?;
        }
    }
    push_contiguous_v1(
        builder,
        value_slot_column_v1(slice_start, 0, VALUE_EQUAL_NEXT_V1),
        start,
        start + 16,
        F::ONE,
        F::ZERO,
    )
}
fn push_value_bus_boundaries_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    push_sparse_v1(builder, slice_start + VALUE_FIRST_V1, 0, F::ONE)?;
    push_contiguous_v1(
        builder,
        slice_start + VALUE_CONTINUATION_V1,
        0,
        P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1 - 1,
        F::ONE,
        F::ZERO,
    )
}
fn compile_writer_fixed_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    role: P256EcdsaRoleV1,
    value_count: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    let cells = checked_mul_v1(value_count, P256_VALUE_BUS_LIMBS_V1)?;
    let mut multiplicities = Vec::new();
    multiplicities
        .try_reserve_exact(cells)
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    multiplicities.resize(cells, 0_u16);
    let sources =
        compile_zk_x509_p256_external_cross_sources_v1(role).map_err(map_external_error_v1)?;
    for source in sources.into_iter().flatten().flatten() {
        let address = checked_add_v1(
            checked_mul_v1(id_index_v1(source.writer_id)?, P256_VALUE_BUS_LIMBS_V1)?,
            usize::from(source.writer_limb),
        )?;
        let multiplicity = multiplicities
            .get_mut(address)
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
        *multiplicity = multiplicity
            .checked_add(1)
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    }
    // The selected-input sink consumes each Qx/Qy/r/s writer limb once
    // in addition to the original external equality schedule. Derive those
    // public owners independently, exactly as the closed native provider does.
    for word in 0..4 {
        let id = p256_selected_input_writer_id_v1(word)
            .map_err(map_external_error_v1)?
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
        for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
            let address = checked_add_v1(
                checked_mul_v1(id_index_v1(id)?, P256_VALUE_BUS_LIMBS_V1)?,
                limb,
            )?;
            let multiplicity = multiplicities
                .get_mut(address)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
            *multiplicity = multiplicity
                .checked_add(1)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Resource)?;
        }
    }
    let mut active = [Vec::<(usize, F)>::new(), Vec::<(usize, F)>::new()];
    let mut addresses = [Vec::<(usize, F)>::new(), Vec::<(usize, F)>::new()];
    let mut selectors: [[Vec<(usize, F)>; 4]; 2] =
        core::array::from_fn(|_| core::array::from_fn(|_| Vec::new()));
    let active_count = multiplicities
        .iter()
        .filter(|multiplicity| **multiplicity != 0)
        .count();
    for points in active
        .iter_mut()
        .chain(addresses.iter_mut())
        .chain(selectors.iter_mut().flatten())
    {
        points
            .try_reserve_exact(active_count)
            .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    }
    for (address, multiplicity) in multiplicities.into_iter().enumerate() {
        if multiplicity == 0 {
            continue;
        }
        let id = address / P256_VALUE_BUS_LIMBS_V1;
        let limb = address % P256_VALUE_BUS_LIMBS_V1;
        let ordinal = if id < P256_INITIAL_VALUES_V1 {
            checked_add_v1(
                checked_mul_v1(id, P256_VALUE_BUS_SEGMENT_ROWS_V1)?,
                checked_add_v1(3 * P256_VALUE_BUS_LIMBS_V1, limb)?,
            )?
        } else {
            let operation = id
                .checked_sub(P256_INITIAL_VALUES_V1)
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
            if operation >= P256_ARITHMETIC_OPERATIONS_V1 {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            checked_add_v1(
                checked_mul_v1(operation, P256_VALUE_BUS_SEGMENT_ROWS_V1)?,
                checked_add_v1(checked_mul_v1(limb, 3)?, 2)?,
            )?
        };
        let slot = ordinal % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let row = ordinal / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        active[slot].push((row, F::ONE));
        // Algebraic point series contain only explicit nonzero cells. Writer
        // address zero is nevertheless a valid active source: it is the first
        // limb of verifier-owned constant value zero (`id = 0, limb = 0`).
        // Leave that address cell implicit while retaining its active/event
        // selectors above.
        if address != 0 {
            addresses[slot].push((row, f_usize_v1(address)?));
        }
        let (selector, value) = match multiplicity {
            1 | 2 => (0, F(u64::from(multiplicity))),
            64 => (1, F::ONE),
            65 => (2, F::ONE),
            129 => (3, F::ONE),
            _ => return Err(ZkX509P256FixedAlgebraicErrorV1::Topology),
        };
        selectors[slot][selector].push((row, value));
    }
    for slot in 0..2 {
        active[slot].sort_unstable_by_key(|(row, _)| *row);
        addresses[slot].sort_unstable_by_key(|(row, _)| *row);
        let event = slice_start + EXECUTION_WRITER_START_V1 + slot * 3;
        push_point_series_v1(builder, event, &active[slot])?;
        push_point_series_v1(builder, event + 1, &active[slot])?;
        push_point_series_v1(builder, event + 2, &addresses[slot])?;
        for selector in 0..4 {
            selectors[slot][selector].sort_unstable_by_key(|(row, _)| *row);
            push_point_series_v1(
                builder,
                slice_start + EXECUTION_WRITER_MULTIPLICITY_START_V1 + slot * 4 + selector,
                &selectors[slot][selector],
            )?;
        }
    }
    push_boundary_v1(
        builder,
        slice_start + EXECUTION_WRITER_BOUNDARY_START_V1,
        P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
    )
}
fn push_point_series_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    column: usize,
    points: &[(usize, F)],
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if points.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || points.iter().any(|(_, value)| *value == F::ZERO)
    {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut start = 0_usize;
    while start < points.len() {
        if start + 1 == points.len() {
            push_sparse_v1(builder, column, points[start].0, points[start].1)?;
            break;
        }
        let row_step = points[start + 1]
            .0
            .checked_sub(points[start].0)
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
        let value_step = points[start + 1].1.sub(points[start].1);
        let mut end = start + 2;
        while end < points.len()
            && points[end].0.checked_sub(points[end - 1].0) == Some(row_step)
            && points[end].1.sub(points[end - 1].1) == value_step
        {
            end += 1;
        }
        push_repeated_affine_v1(
            builder,
            column,
            points[start].0,
            end - start,
            row_step,
            points[start].1,
            value_step,
        )?;
        start = end;
    }
    Ok(())
}
fn compile_value_copy_fixed_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    for slot in 0..2 {
        let event = slice_start + EXECUTION_VALUE_COPY_START_V1 + slot * 2;
        for offset in 0..24 {
            push_repeated_v1(
                builder,
                event,
                offset,
                P256_ARITHMETIC_OPERATIONS_V1,
                32,
                F::ONE,
            )?;
            push_repeated_affine_v1(
                builder,
                event + 1,
                offset,
                P256_ARITHMETIC_OPERATIONS_V1,
                32,
                f_usize_v1(checked_add_v1(checked_mul_v1(offset, 2)?, slot)?)?,
                F(48),
            )?;
        }
    }
    push_boundary_v1(
        builder,
        slice_start + EXECUTION_VALUE_COPY_BOUNDARY_START_V1,
        P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum P256SortedRunAxisV1 {
    RelativeFactor,
    PerValue,
}
fn sorted_relative_factor_axis_atom_count_v1(
    run_start: usize,
    run_count: usize,
    per_limb: usize,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    if run_count == 0 || per_limb == 0 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    checked_add_v1(run_start, run_count)?;
    let block_factors = checked_mul_v1(P256_VALUE_BUS_LIMBS_V1, per_limb)?;
    let id_atoms = if run_start == 0 && run_count == 1 {
        0
    } else {
        block_factors
    };
    let nonzero_limb_atoms = checked_mul_v1(P256_VALUE_BUS_LIMBS_V1 - 1, per_limb)?;
    checked_add_v1(
        checked_add_v1(id_atoms, nonzero_limb_atoms)?,
        2 * P256_VALUE_BUS_LIMBS_V1,
    )
}
fn sorted_per_value_axis_atom_count_v1(
    run_start: usize,
    run_count: usize,
    per_limb: usize,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    if run_count == 0 || per_limb == 0 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    checked_add_v1(run_start, run_count)?;
    let limb_atoms_per_value = checked_mul_v1(
        P256_VALUE_BUS_LIMBS_V1 - 1,
        if per_limb == 1 { 1 } else { 2 },
    )?;
    let correction_atoms_per_value = if per_limb.is_multiple_of(2) { 2 } else { 4 };
    let atoms_per_nonzero_value = checked_add_v1(
        checked_add_v1(2, limb_atoms_per_value)?,
        correction_atoms_per_value,
    )?;
    let mut atoms = checked_mul_v1(run_count, atoms_per_nonzero_value)?;
    if run_start == 0 {
        atoms = atoms
            .checked_sub(2)
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
    }
    Ok(atoms)
}
fn sorted_run_axis_v1(
    run_start: usize,
    run_count: usize,
    per_limb: usize,
) -> Result<P256SortedRunAxisV1, ZkX509P256FixedAlgebraicErrorV1> {
    let relative = sorted_relative_factor_axis_atom_count_v1(run_start, run_count, per_limb)?;
    let per_value = sorted_per_value_axis_atom_count_v1(run_start, run_count, per_limb)?;
    if per_value < relative {
        Ok(P256SortedRunAxisV1::PerValue)
    } else {
        Ok(P256SortedRunAxisV1::RelativeFactor)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum P256SortedRepeatedPhaseAxisV1 {
    Local,
    Phase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256SortedRepeatedPhasePlanV1 {
    value_start: usize,
    repeats: usize,
    values_per_repeat: usize,
    block_factors: usize,
    local_atoms: usize,
    phase_atoms: usize,
    axis: P256SortedRepeatedPhaseAxisV1,
}
impl P256SortedRepeatedPhasePlanV1 {
    fn value_end_v1(self) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
        checked_add_v1(
            self.value_start,
            checked_mul_v1(self.repeats, self.values_per_repeat)?,
        )
    }
    const fn selected_atoms_v1(self) -> usize {
        match self.axis {
            P256SortedRepeatedPhaseAxisV1::Local => self.local_atoms,
            P256SortedRepeatedPhaseAxisV1::Phase => self.phase_atoms,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum P256SortedWholeAxisV1 {
    GlobalLocal,
    PhaseHybrid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256SortedRunPlanV1 {
    global_local_atoms: usize,
    hybrid_atoms: usize,
    prefix_local_atoms: usize,
    variable_repeated: P256SortedRepeatedPhasePlanV1,
    scalar_boundary_local_atoms: usize,
    scalar_repeated: P256SortedRepeatedPhasePlanV1,
    tail_local_atoms: usize,
    axis: P256SortedWholeAxisV1,
}
impl P256SortedRunPlanV1 {
    const fn selected_atoms_v1(self) -> usize {
        match self.axis {
            P256SortedWholeAxisV1::GlobalLocal => self.global_local_atoms,
            P256SortedWholeAxisV1::PhaseHybrid => self.hybrid_atoms,
        }
    }
}
fn sorted_local_range_atom_count_v1(
    metadata: &[P256ValueMetadataV1],
    value_start: usize,
    value_end: usize,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    if value_start >= value_end || value_end > metadata.len() {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut atoms = 0_usize;
    let mut run_start = value_start;
    while run_start < value_end {
        let per_limb = checked_add_v1(metadata[run_start].reads, 1)?;
        let mut run_end = run_start + 1;
        while run_end < value_end && checked_add_v1(metadata[run_end].reads, 1)? == per_limb {
            run_end += 1;
        }
        let relative =
            sorted_relative_factor_axis_atom_count_v1(run_start, run_end - run_start, per_limb)?;
        let per_value =
            sorted_per_value_axis_atom_count_v1(run_start, run_end - run_start, per_limb)?;
        atoms = checked_add_v1(atoms, core::cmp::min(relative, per_value))?;
        run_start = run_end;
    }
    Ok(atoms)
}
fn compile_sorted_repeated_phase_plan_v1(
    metadata: &[P256ValueMetadataV1],
    prefix: &[usize],
    value_start: usize,
    repeats: usize,
    values_per_repeat: usize,
) -> Result<P256SortedRepeatedPhasePlanV1, ZkX509P256FixedAlgebraicErrorV1> {
    if prefix.len() != metadata.len() + 1 || repeats < 2 || values_per_repeat == 0 {
        #[cfg(test)]
        eprintln!(
            "P256_PHASE_DIAGNOSTIC invariant=shape value_start={value_start} repeats={repeats} \
             values_per_repeat={values_per_repeat} metadata_len={} prefix_len={}",
            metadata.len(),
            prefix.len(),
        );
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let phase_values = checked_mul_v1(repeats, values_per_repeat)?;
    let value_end = checked_add_v1(value_start, phase_values)?;
    let first_block_end = checked_add_v1(value_start, values_per_repeat)?;
    if value_end > metadata.len() || first_block_end > value_end {
        #[cfg(test)]
        eprintln!(
            "P256_PHASE_DIAGNOSTIC invariant=bounds value_start={value_start} \
             first_block_end={first_block_end} value_end={value_end} metadata_len={}",
            metadata.len(),
        );
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let block_factors = prefix[first_block_end]
        .checked_sub(prefix[value_start])
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
    if block_factors == 0
        || !block_factors.is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
        || !prefix[value_start].is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
    {
        #[cfg(test)]
        eprintln!(
            "P256_PHASE_DIAGNOSTIC invariant=block-alignment value_start={value_start} \
             block_factors={block_factors} logical_start={}",
            prefix[value_start],
        );
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    for repetition in 0..repeats {
        let repeat_start =
            checked_add_v1(value_start, checked_mul_v1(repetition, values_per_repeat)?)?;
        let repeat_end = checked_add_v1(repeat_start, values_per_repeat)?;
        let expected_logical_start = checked_add_v1(
            prefix[value_start],
            checked_mul_v1(repetition, block_factors)?,
        )?;
        if prefix[repeat_start] != expected_logical_start
            || prefix[repeat_end]
                .checked_sub(prefix[repeat_start])
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?
                != block_factors
        {
            #[cfg(test)]
            eprintln!(
                "P256_PHASE_DIAGNOSTIC invariant=block-extent value_start={value_start} \
                 repetition={repetition} repeat_start={repeat_start} repeat_end={repeat_end} \
                 expected_logical_start={expected_logical_start} actual_logical_start={} \
                 expected_block_factors={block_factors} actual_block_factors={:?}",
                prefix[repeat_start],
                prefix[repeat_end].checked_sub(prefix[repeat_start]),
            );
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        for template_offset in 0..values_per_repeat {
            if metadata[repeat_start + template_offset] != metadata[value_start + template_offset] {
                #[cfg(test)]
                eprintln!(
                    "P256_PHASE_DIAGNOSTIC invariant=metadata-template value_start={value_start} \
                     repetition={repetition} template_offset={template_offset} actual_index={} \
                     expected={:?} actual={:?}",
                    repeat_start + template_offset,
                    metadata[value_start + template_offset],
                    metadata[repeat_start + template_offset],
                );
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
        }
    }
    let expected_logical_end =
        checked_add_v1(prefix[value_start], checked_mul_v1(repeats, block_factors)?)?;
    if prefix[value_end] != expected_logical_end {
        #[cfg(test)]
        eprintln!(
            "P256_PHASE_DIAGNOSTIC invariant=phase-end value_start={value_start} \
             value_end={value_end} expected_logical_end={expected_logical_end} \
             actual_logical_end={}",
            prefix[value_end],
        );
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let local_atoms = sorted_local_range_atom_count_v1(metadata, value_start, value_end)?;
    let mut phase_atoms = 0_usize;
    for template_offset in 0..values_per_repeat {
        let id = checked_add_v1(value_start, template_offset)?;
        let per_limb = checked_add_v1(metadata[id].reads, 1)?;
        phase_atoms = checked_add_v1(
            phase_atoms,
            sorted_relative_factor_axis_atom_count_v1(id, repeats, per_limb)?,
        )?;
    }
    let axis = if phase_atoms < local_atoms {
        P256SortedRepeatedPhaseAxisV1::Phase
    } else {
        P256SortedRepeatedPhaseAxisV1::Local
    };
    Ok(P256SortedRepeatedPhasePlanV1 {
        value_start,
        repeats,
        values_per_repeat,
        block_factors,
        local_atoms,
        phase_atoms,
        axis,
    })
}
fn compile_sorted_run_plan_v1(
    metadata: &[P256ValueMetadataV1],
    prefix: &[usize],
) -> Result<P256SortedRunPlanV1, ZkX509P256FixedAlgebraicErrorV1> {
    if metadata.len() != P256_FINAL_VALUE_START_V1 + P256_FINAL_OPERATIONS_V1
        || prefix.len() != metadata.len() + 1
    {
        #[cfg(test)]
        eprintln!(
            "P256_PHASE_DIAGNOSTIC invariant=release-shape metadata_len={} prefix_len={} \
             expected_metadata_len={}",
            metadata.len(),
            prefix.len(),
            P256_FINAL_VALUE_START_V1 + P256_FINAL_OPERATIONS_V1,
        );
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let variable_repeated = compile_sorted_repeated_phase_plan_v1(
        metadata,
        prefix,
        P256_VARIABLE_REPEATED_VALUE_START_V1,
        P256_VARIABLE_REPEATED_CALLS_V1,
        P256_COMPLETE_ADD_OPERATIONS_V1,
    )?;
    let scalar_repeated = compile_sorted_repeated_phase_plan_v1(
        metadata,
        prefix,
        P256_SCALAR_REPEATED_VALUE_START_V1,
        P256_SCALAR_REPEATED_ROUNDS_V1,
        P256_SCALAR_ROUND_OPERATIONS_V1,
    )?;
    let variable_boundary_factors = prefix[P256_VARIABLE_REPEATED_VALUE_START_V1]
        .checked_sub(prefix[P256_VARIABLE_VALUE_START_V1])
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
    let scalar_boundary_factors = prefix[P256_SCALAR_REPEATED_VALUE_START_V1]
        .checked_sub(prefix[P256_SCALAR_VALUE_START_V1])
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
    if variable_boundary_factors != P256_VARIABLE_BOUNDARY_FACTORS_V1
        || variable_repeated.block_factors != P256_VARIABLE_REPEATED_BLOCK_FACTORS_V1
        || scalar_boundary_factors != P256_SCALAR_BOUNDARY_FACTORS_V1
        || scalar_repeated.block_factors != P256_SCALAR_REPEATED_BLOCK_FACTORS_V1
        || variable_repeated.value_end_v1()? != P256_SCALAR_VALUE_START_V1
        || scalar_repeated.value_end_v1()? != P256_FINAL_VALUE_START_V1
    {
        #[cfg(test)]
        eprintln!(
            "P256_PHASE_DIAGNOSTIC invariant=release-phase-groups \
             variable_boundary_factors={variable_boundary_factors} \
             expected_variable_boundary_factors={P256_VARIABLE_BOUNDARY_FACTORS_V1} \
             variable_repeated_factors={} \
             expected_variable_repeated_factors={P256_VARIABLE_REPEATED_BLOCK_FACTORS_V1} \
             scalar_boundary_factors={scalar_boundary_factors} \
             expected_scalar_boundary_factors={P256_SCALAR_BOUNDARY_FACTORS_V1} \
             scalar_repeated_factors={} \
             expected_scalar_repeated_factors={P256_SCALAR_REPEATED_BLOCK_FACTORS_V1} \
             variable_end={:?} expected_variable_end={P256_SCALAR_VALUE_START_V1} \
             scalar_end={:?} expected_scalar_end={P256_FINAL_VALUE_START_V1}",
            variable_repeated.block_factors,
            scalar_repeated.block_factors,
            variable_repeated.value_end_v1(),
            scalar_repeated.value_end_v1(),
        );
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let prefix_local_atoms =
        sorted_local_range_atom_count_v1(metadata, 0, P256_VARIABLE_REPEATED_VALUE_START_V1)?;
    let scalar_boundary_local_atoms = sorted_local_range_atom_count_v1(
        metadata,
        P256_SCALAR_VALUE_START_V1,
        P256_SCALAR_REPEATED_VALUE_START_V1,
    )?;
    let tail_local_atoms =
        sorted_local_range_atom_count_v1(metadata, P256_FINAL_VALUE_START_V1, metadata.len())?;
    let hybrid_atoms = checked_add_v1(
        checked_add_v1(
            checked_add_v1(
                checked_add_v1(prefix_local_atoms, variable_repeated.selected_atoms_v1())?,
                scalar_boundary_local_atoms,
            )?,
            scalar_repeated.selected_atoms_v1(),
        )?,
        tail_local_atoms,
    )?;
    let global_local_atoms = sorted_local_range_atom_count_v1(metadata, 0, metadata.len())?;
    let axis = if hybrid_atoms < global_local_atoms {
        P256SortedWholeAxisV1::PhaseHybrid
    } else {
        P256SortedWholeAxisV1::GlobalLocal
    };
    Ok(P256SortedRunPlanV1 {
        global_local_atoms,
        hybrid_atoms,
        prefix_local_atoms,
        variable_repeated,
        scalar_boundary_local_atoms,
        scalar_repeated,
        tail_local_atoms,
        axis,
    })
}
fn emit_sorted_relative_factor_axis_run_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    logical_start: usize,
    run_start: usize,
    run_count: usize,
    per_limb: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    let expected_atoms = sorted_relative_factor_axis_atom_count_v1(run_start, run_count, per_limb)?;
    if !logical_start.is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let block_factors = checked_mul_v1(P256_VALUE_BUS_LIMBS_V1, per_limb)?;
    if !block_factors.is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let block_rows = block_factors / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
    let mut emitted = 0_usize;
    for relative in 0..block_factors {
        let logical = checked_add_v1(logical_start, relative)?;
        let slot = logical % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let row = logical / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        push_repeated_affine_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_ID_V1),
            row,
            run_count,
            block_rows,
            f_usize_v1(run_start)?,
            F::ONE,
        )?;
        if run_count > 1 || run_start != 0 {
            emitted = checked_add_v1(emitted, 1)?;
        }
        let limb = relative / per_limb;
        push_repeated_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_LIMB_V1),
            row,
            run_count,
            block_rows,
            f_usize_v1(limb)?,
        )?;
        if limb != 0 {
            emitted = checked_add_v1(emitted, 1)?;
        }
        if relative.is_multiple_of(per_limb) {
            push_repeated_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_ACCESS_V1),
                row,
                run_count,
                block_rows,
                negative_one_v1(),
            )?;
            emitted = checked_add_v1(emitted, 1)?;
        }
        if (relative + 1).is_multiple_of(per_limb) {
            push_repeated_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_EQUAL_NEXT_V1),
                row,
                run_count,
                block_rows,
                negative_one_v1(),
            )?;
            emitted = checked_add_v1(emitted, 1)?;
        }
    }
    if emitted != expected_atoms {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(())
}
fn push_sorted_logical_stride_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    field: usize,
    logical_first: usize,
    count: usize,
    logical_stride: usize,
    value: F,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    if count < 2 || logical_stride == 0 || value == F::ZERO {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    // Validate the complete logical progression before mutating the builder,
    // including the second packed-slot series used by odd strides.
    checked_add_v1(logical_first, checked_mul_v1(count - 1, logical_stride)?)?;
    if logical_stride.is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) {
        let slot = logical_first % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        push_repeated_v1(
            builder,
            value_slot_column_v1(slice_start, slot, field),
            logical_first / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
            count,
            logical_stride / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
            value,
        )?;
        return Ok(1);
    }
    let mut atoms = 0_usize;
    for occurrence_offset in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let occurrence_count =
            (count + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - 1 - occurrence_offset)
                / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        if occurrence_count == 0 {
            continue;
        }
        let first = checked_add_v1(
            logical_first,
            checked_mul_v1(occurrence_offset, logical_stride)?,
        )?;
        let slot = first % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        push_repeated_v1(
            builder,
            value_slot_column_v1(slice_start, slot, field),
            first / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1,
            occurrence_count,
            logical_stride,
            value,
        )?;
        atoms = checked_add_v1(atoms, 1)?;
    }
    Ok(atoms)
}
fn emit_sorted_per_value_axis_run_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    logical_start: usize,
    logical_end: usize,
    run_start: usize,
    run_count: usize,
    per_limb: usize,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    let expected_atoms = sorted_per_value_axis_atom_count_v1(run_start, run_count, per_limb)?;
    if !logical_start.is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1) {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let block_factors = checked_mul_v1(P256_VALUE_BUS_LIMBS_V1, per_limb)?;
    let expected_end = checked_add_v1(logical_start, checked_mul_v1(run_count, block_factors)?)?;
    if logical_end != expected_end {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut emitted = 0_usize;
    for value_offset in 0..run_count {
        let id = checked_add_v1(run_start, value_offset)?;
        let block_start =
            checked_add_v1(logical_start, checked_mul_v1(value_offset, block_factors)?)?;
        if id != 0 {
            emitted = checked_add_v1(
                emitted,
                push_logical_constant_range_v1(
                    builder,
                    slice_start,
                    VALUE_ID_V1,
                    block_start,
                    checked_add_v1(block_start, block_factors)?,
                    f_usize_v1(id)?,
                )?,
            )?;
        }
        for limb in 1..P256_VALUE_BUS_LIMBS_V1 {
            let limb_start = checked_add_v1(block_start, checked_mul_v1(limb, per_limb)?)?;
            emitted = checked_add_v1(
                emitted,
                push_logical_constant_range_v1(
                    builder,
                    slice_start,
                    VALUE_LIMB_V1,
                    limb_start,
                    checked_add_v1(limb_start, per_limb)?,
                    f_usize_v1(limb)?,
                )?,
            )?;
        }
        emitted = checked_add_v1(
            emitted,
            push_sorted_logical_stride_v1(
                builder,
                slice_start,
                VALUE_ACCESS_V1,
                block_start,
                P256_VALUE_BUS_LIMBS_V1,
                per_limb,
                negative_one_v1(),
            )?,
        )?;
        emitted = checked_add_v1(
            emitted,
            push_sorted_logical_stride_v1(
                builder,
                slice_start,
                VALUE_EQUAL_NEXT_V1,
                checked_add_v1(block_start, per_limb - 1)?,
                P256_VALUE_BUS_LIMBS_V1,
                per_limb,
                negative_one_v1(),
            )?,
        )?;
    }
    if emitted != expected_atoms {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(())
}
fn emit_sorted_local_range_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    metadata: &[P256ValueMetadataV1],
    prefix: &[usize],
    value_start: usize,
    value_end: usize,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    if prefix.len() != metadata.len() + 1 || value_start >= value_end || value_end > metadata.len()
    {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let expected_atoms = sorted_local_range_atom_count_v1(metadata, value_start, value_end)?;
    let mut emitted = 0_usize;
    let mut run_start = value_start;
    while run_start < value_end {
        let per_limb = checked_add_v1(metadata[run_start].reads, 1)?;
        let mut run_end = run_start + 1;
        while run_end < value_end && checked_add_v1(metadata[run_end].reads, 1)? == per_limb {
            run_end += 1;
        }
        let run_count = run_end - run_start;
        let run_atoms = match sorted_run_axis_v1(run_start, run_count, per_limb)? {
            P256SortedRunAxisV1::RelativeFactor => {
                emit_sorted_relative_factor_axis_run_v1(
                    builder,
                    slice_start,
                    prefix[run_start],
                    run_start,
                    run_count,
                    per_limb,
                )?;
                sorted_relative_factor_axis_atom_count_v1(run_start, run_count, per_limb)?
            }
            P256SortedRunAxisV1::PerValue => {
                emit_sorted_per_value_axis_run_v1(
                    builder,
                    slice_start,
                    prefix[run_start],
                    prefix[run_end],
                    run_start,
                    run_count,
                    per_limb,
                )?;
                sorted_per_value_axis_atom_count_v1(run_start, run_count, per_limb)?
            }
        };
        emitted = checked_add_v1(emitted, run_atoms)?;
        run_start = run_end;
    }
    if emitted != expected_atoms {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(emitted)
}
fn emit_sorted_repeated_phase_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    metadata: &[P256ValueMetadataV1],
    prefix: &[usize],
    plan: P256SortedRepeatedPhasePlanV1,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    let validated = compile_sorted_repeated_phase_plan_v1(
        metadata,
        prefix,
        plan.value_start,
        plan.repeats,
        plan.values_per_repeat,
    )?;
    if validated != plan || plan.axis != P256SortedRepeatedPhaseAxisV1::Phase {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let block_rows = plan.block_factors / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
    if block_rows == 0 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut emitted = 0_usize;
    for template_offset in 0..plan.values_per_repeat {
        let id = checked_add_v1(plan.value_start, template_offset)?;
        let per_limb = checked_add_v1(metadata[id].reads, 1)?;
        let block_factors = checked_mul_v1(P256_VALUE_BUS_LIMBS_V1, per_limb)?;
        for relative in 0..block_factors {
            let logical = checked_add_v1(prefix[id], relative)?;
            let slot = logical % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
            let row = logical / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
            push_repeated_affine_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_ID_V1),
                row,
                plan.repeats,
                block_rows,
                f_usize_v1(id)?,
                f_usize_v1(plan.values_per_repeat)?,
            )?;
            emitted = checked_add_v1(emitted, 1)?;
            let limb = relative / per_limb;
            push_repeated_v1(
                builder,
                value_slot_column_v1(slice_start, slot, VALUE_LIMB_V1),
                row,
                plan.repeats,
                block_rows,
                f_usize_v1(limb)?,
            )?;
            if limb != 0 {
                emitted = checked_add_v1(emitted, 1)?;
            }
            if relative.is_multiple_of(per_limb) {
                push_repeated_v1(
                    builder,
                    value_slot_column_v1(slice_start, slot, VALUE_ACCESS_V1),
                    row,
                    plan.repeats,
                    block_rows,
                    negative_one_v1(),
                )?;
                emitted = checked_add_v1(emitted, 1)?;
            }
            if (relative + 1).is_multiple_of(per_limb) {
                push_repeated_v1(
                    builder,
                    value_slot_column_v1(slice_start, slot, VALUE_EQUAL_NEXT_V1),
                    row,
                    plan.repeats,
                    block_rows,
                    negative_one_v1(),
                )?;
                emitted = checked_add_v1(emitted, 1)?;
            }
        }
    }
    if emitted != plan.phase_atoms {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(emitted)
}
fn emit_sorted_run_plan_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    metadata: &[P256ValueMetadataV1],
    prefix: &[usize],
    plan: P256SortedRunPlanV1,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if compile_sorted_run_plan_v1(metadata, prefix)? != plan {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let emitted = match plan.axis {
        P256SortedWholeAxisV1::GlobalLocal => {
            emit_sorted_local_range_v1(builder, slice_start, metadata, prefix, 0, metadata.len())?
        }
        P256SortedWholeAxisV1::PhaseHybrid => {
            let prefix_atoms = emit_sorted_local_range_v1(
                builder,
                slice_start,
                metadata,
                prefix,
                0,
                P256_VARIABLE_REPEATED_VALUE_START_V1,
            )?;
            if prefix_atoms != plan.prefix_local_atoms {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            let mut emitted = prefix_atoms;
            let variable_phase = plan.variable_repeated;
            let variable_atoms = match variable_phase.axis {
                P256SortedRepeatedPhaseAxisV1::Local => emit_sorted_local_range_v1(
                    builder,
                    slice_start,
                    metadata,
                    prefix,
                    variable_phase.value_start,
                    variable_phase.value_end_v1()?,
                )?,
                P256SortedRepeatedPhaseAxisV1::Phase => emit_sorted_repeated_phase_v1(
                    builder,
                    slice_start,
                    metadata,
                    prefix,
                    variable_phase,
                )?,
            };
            if variable_atoms != variable_phase.selected_atoms_v1() {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            emitted = checked_add_v1(emitted, variable_atoms)?;
            let scalar_boundary_atoms = emit_sorted_local_range_v1(
                builder,
                slice_start,
                metadata,
                prefix,
                P256_SCALAR_VALUE_START_V1,
                P256_SCALAR_REPEATED_VALUE_START_V1,
            )?;
            if scalar_boundary_atoms != plan.scalar_boundary_local_atoms {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            emitted = checked_add_v1(emitted, scalar_boundary_atoms)?;
            let scalar_phase = plan.scalar_repeated;
            let scalar_atoms = match scalar_phase.axis {
                P256SortedRepeatedPhaseAxisV1::Local => emit_sorted_local_range_v1(
                    builder,
                    slice_start,
                    metadata,
                    prefix,
                    scalar_phase.value_start,
                    scalar_phase.value_end_v1()?,
                )?,
                P256SortedRepeatedPhaseAxisV1::Phase => emit_sorted_repeated_phase_v1(
                    builder,
                    slice_start,
                    metadata,
                    prefix,
                    scalar_phase,
                )?,
            };
            if scalar_atoms != scalar_phase.selected_atoms_v1() {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            emitted = checked_add_v1(emitted, scalar_atoms)?;
            let tail_atoms = emit_sorted_local_range_v1(
                builder,
                slice_start,
                metadata,
                prefix,
                P256_FINAL_VALUE_START_V1,
                metadata.len(),
            )?;
            if tail_atoms != plan.tail_local_atoms {
                return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
            }
            emitted = checked_add_v1(emitted, tail_atoms)?;
            emitted
        }
    };
    if emitted != plan.selected_atoms_v1() {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(())
}
fn compile_sorted_fixed_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    metadata: &[P256ValueMetadataV1],
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if metadata.len() != P256_INITIAL_VALUES_V1 + P256_ARITHMETIC_OPERATIONS_V1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(metadata.len() + 1)
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    prefix.push(0_usize);
    for value in metadata {
        let per_limb = checked_add_v1(value.reads, 1)?;
        let factors = checked_mul_v1(P256_VALUE_BUS_LIMBS_V1, per_limb)?;
        prefix.push(checked_add_v1(
            *prefix
                .last()
                .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?,
            factors,
        )?);
    }
    let active_factors = *prefix
        .last()
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?;
    if active_factors != P256_VALUE_BUS_SORTED_ACTIVE_FACTORS_V1
        || !active_factors.is_multiple_of(P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1)
    {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let active_rows = active_factors / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
    // Validate the complete repeated phase geometry and select the exact
    // whole-plan minimum before the first builder mutation.
    let run_plan = compile_sorted_run_plan_v1(metadata, &prefix)?;
    // Every sorted active factor is a read by default. The unique writer and
    // per-limb terminal positions add -1 corrections to access and
    // equal-next respectively.
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        for (field, value) in [
            (VALUE_ACTIVE_V1, F::ONE),
            (VALUE_ACCESS_V1, F(2)),
            (VALUE_EQUAL_NEXT_V1, F::ONE),
        ] {
            push_contiguous_v1(
                builder,
                value_slot_column_v1(slice_start, slot, field),
                0,
                active_rows,
                value,
                F::ZERO,
            )?;
        }
        push_contiguous_v1(
            builder,
            value_slot_column_v1(slice_start, slot, VALUE_PADDING_V1),
            active_rows,
            P256_VALUE_BUS_AGGREGATE_TRACE_SIZE_V1,
            F::ONE,
            F::ZERO,
        )?;
    }
    // The release topology contains two repeated metadata phases. Compare the
    // established global-local plan against a phase-hybrid transpose that
    // keeps the initial and final regions local. The established whole plan
    // wins ties.
    emit_sorted_run_plan_v1(builder, slice_start, metadata, &prefix, run_plan)?;
    compile_sorted_metadata_field_v1(
        builder,
        slice_start,
        metadata,
        &prefix,
        VALUE_MODULUS_V1,
        |value| modulus_field_v1(value.modulus),
    )?;
    compile_sorted_metadata_field_v1(
        builder,
        slice_start,
        metadata,
        &prefix,
        VALUE_KIND_V1,
        |value| value_kind_field_v1(value.kind),
    )?;
    push_value_bus_boundaries_v1(builder, slice_start)
}
fn compile_sorted_metadata_field_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    metadata: &[P256ValueMetadataV1],
    prefix: &[usize],
    field: usize,
    value_v1: impl Fn(P256ValueMetadataV1) -> F,
) -> Result<(), ZkX509P256FixedAlgebraicErrorV1> {
    if prefix.len() != metadata.len() + 1 {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    let mut start = 0_usize;
    while start < metadata.len() {
        let value = value_v1(metadata[start]);
        let mut end = start + 1;
        while end < metadata.len() && value_v1(metadata[end]) == value {
            end += 1;
        }
        let _ = push_logical_constant_range_v1(
            builder,
            slice_start,
            field,
            prefix[start],
            prefix[end],
            value,
        )?;
        start = end;
    }
    Ok(())
}
fn push_logical_constant_range_v1(
    builder: &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    slice_start: usize,
    field: usize,
    logical_start: usize,
    logical_end: usize,
    value: F,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    let expected_atoms = logical_constant_range_atom_count_v1(logical_start, logical_end, value)?;
    if expected_atoms == 0 {
        return Ok(0);
    }
    let mut atoms = 0_usize;
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let parity = logical_start % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let adjustment = (slot + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - parity)
            % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let first = checked_add_v1(logical_start, adjustment)?;
        if first >= logical_end {
            continue;
        }
        let count = (logical_end - 1 - first) / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 + 1;
        let row = first / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        push_contiguous_v1(
            builder,
            value_slot_column_v1(slice_start, slot, field),
            row,
            checked_add_v1(row, count)?,
            value,
            F::ZERO,
        )?;
        atoms = checked_add_v1(atoms, 1)?;
    }
    if atoms != expected_atoms {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    Ok(atoms)
}
fn logical_constant_range_atom_count_v1(
    logical_start: usize,
    logical_end: usize,
    value: F,
) -> Result<usize, ZkX509P256FixedAlgebraicErrorV1> {
    if logical_start >= logical_end {
        return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
    }
    if value == F::ZERO {
        return Ok(0);
    }
    let mut atoms = 0_usize;
    for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
        let parity = logical_start % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let adjustment = (slot + P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 - parity)
            % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let first = checked_add_v1(logical_start, adjustment)?;
        if first >= logical_end {
            continue;
        }
        atoms = checked_add_v1(atoms, 1)?;
    }
    Ok(atoms)
}
/// Digest of the stable P-256 structural compiler descriptor.
#[cfg(test)]
pub fn zk_x509_p256_fixed_algebraic_compiler_descriptor_digest_v1()
-> Result<PrivacyOuterDigestV1, ZkX509P256FixedAlgebraicErrorV1> {
    privacy_outer_digest_frame_v1(
        ZK_X509_FIXED_DIGEST_CONTEXT_V1,
        P256_COMPILER_DESCRIPTOR_DIGEST_DOMAIN_V1,
        b"p256-fixed-algebraic-compiler",
        0,
        0,
        0,
        &[ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1],
    )
    .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Topology)
}
/// Typed composition of the six independently capped P-256 registrations.
///
/// Child order is the canonical MAIN registration order: certificate arithmetic, wallet arithmetic,
/// certificate execution, wallet execution, certificate sorted memory, and wallet sorted memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509P256FixedAlgebraicScheduleV1 {
    children: [ZkX509FixedAlgebraicScheduleV1; ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1],
    descriptor_digest: PrivacyOuterDigestV1,
}
impl ZkX509P256FixedAlgebraicScheduleV1 {
    fn new_v1(
        children: [ZkX509FixedAlgebraicScheduleV1; ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1],
    ) -> Result<Self, ZkX509P256FixedAlgebraicErrorV1> {
        let domain = children
            .first()
            .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)?
            .domain_v1();
        if children
            .iter()
            .zip(P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1)
            .zip(P256_FIXED_ALGEBRAIC_CHILD_ATOM_COUNTS_V1)
            .any(|((child, width), atom_count)| {
                child.domain_v1() != domain
                    || usize::from(child.width_v1()) != width
                    || child.atoms_v1().len() != atom_count
            })
        {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        let mut encoded_widths = [0_u8; 2 * ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1];
        let mut child_digests = [0_u8; 48 * ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1];
        for (index, child) in children.iter().enumerate() {
            let width = child.width_v1().to_be_bytes();
            encoded_widths[index * 2..index * 2 + 2].copy_from_slice(&width);
            child_digests[index * 48..index * 48 + 48]
                .copy_from_slice(&child.descriptor_digest_v1().to_bytes());
        }
        let descriptor_digest = privacy_outer_digest_frame_v1(
            ZK_X509_FIXED_DIGEST_CONTEXT_V1,
            P256_COMPOSITE_DESCRIPTOR_DIGEST_DOMAIN_V1,
            b"p256-fixed-algebraic-composite",
            0,
            0,
            0,
            &[
                ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1,
                &encoded_widths,
                &child_digests,
            ],
        )
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Topology)?;
        if descriptor_digest.to_bytes() != P256_FIXED_ALGEBRAIC_COMPOSITE_DIGEST_V1 {
            return Err(ZkX509P256FixedAlgebraicErrorV1::Topology);
        }
        Ok(Self {
            children,
            descriptor_digest,
        })
    }
    /// Exact combined fixed width in canonical child order.
    #[cfg(test)]
    pub(crate) const fn width_v1(&self) -> u16 {
        ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 as u16
    }
    /// Digest binding compiler semantics and every ordered child descriptor.
    pub(crate) const fn descriptor_digest_v1(&self) -> PrivacyOuterDigestV1 {
        self.descriptor_digest
    }
    /// Fail closed unless the compiled profile pins this exact composite.
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
    /// Common child domain shared by all six registrations.
    #[cfg(test)]
    pub(crate) fn domain_v1(&self) -> ZkX509FixedAlgebraicDomainV1 {
        self.children[0].domain_v1()
    }
    /// Exact total across the six independently bounded atom collections.
    #[cfg(test)]
    pub(crate) fn atom_count_v1(&self) -> usize {
        self.children
            .iter()
            .map(|child| child.atoms_v1().len())
            .sum()
    }
    /// Borrow the six independently capped schedules in registration order.
    #[cfg(test)]
    pub(crate) fn children_v1(
        &self,
    ) -> &[ZkX509FixedAlgebraicScheduleV1; ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1] {
        &self.children
    }
    /// Evaluate one combined native row without constructing a native matrix.
    #[cfg(test)]
    pub(crate) fn native_row_v1(
        &self,
        row: u64,
        output: &mut [F],
    ) -> Result<(), ZkX509FixedAlgebraicErrorV1> {
        if output.len() != ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery);
        }
        let mut start = 0_usize;
        for child in &self.children {
            let end = start
                .checked_add(usize::from(child.width_v1()))
                .ok_or(ZkX509FixedAlgebraicErrorV1::IntegerOverflow)?;
            child.native_row_v1(row, &mut output[start..end])?;
            start = end;
        }
        if start != output.len() {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(())
    }
    /// Evaluate the same ordered child fixed polynomials at the DEEP point.
    /// Each child enforces its public work bound; only one child table is live.
    pub(crate) fn evaluate_extension_point_v1(
        &self,
        point: E,
    ) -> Result<Vec<E>, ZkX509FixedAlgebraicErrorV1> {
        let mut combined = Vec::new();
        combined
            .try_reserve_exact(ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1)
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for child in &self.children {
            let row = child.evaluate_extension_point_v1(point)?;
            if row.len() != usize::from(child.width_v1()) {
                return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
            }
            combined.extend(row);
        }
        if combined.len() != ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 {
            return Err(ZkX509FixedAlgebraicErrorV1::InternalInvariant);
        }
        Ok(combined)
    }
    #[cfg(test)]
    /// Evaluate and concatenate all six child openings in canonical order.
    pub(crate) fn evaluate_query_indices_v1(
        &self,
        query_indices: &[u64],
    ) -> Result<ZkX509FixedAlgebraicOpeningsV1, ZkX509FixedAlgebraicErrorV1> {
        let mut parts = Vec::new();
        parts
            .try_reserve_exact(self.children.len())
            .map_err(|_| ZkX509FixedAlgebraicErrorV1::AllocationFailure)?;
        for child in &self.children {
            parts.push(child.evaluate_query_indices_v1(query_indices)?);
        }
        ZkX509FixedAlgebraicOpeningsV1::concatenate_v1(self.descriptor_digest, &parts)
    }
    #[cfg(test)]
    fn atoms_v1(&self) -> Vec<ZkX509FixedAlgebraicAtomV1> {
        let mut atoms = Vec::with_capacity(self.atom_count_v1());
        let mut column_offset = 0_u16;
        for child in &self.children {
            atoms.extend(child.atoms_v1().iter().copied().map(|atom| match atom {
                ZkX509FixedAlgebraicAtomV1::Affine {
                    column,
                    start,
                    end,
                    start_value,
                    step,
                } => ZkX509FixedAlgebraicAtomV1::Affine {
                    column: column_offset + column,
                    start,
                    end,
                    start_value,
                    step,
                },
                ZkX509FixedAlgebraicAtomV1::Repeated {
                    column,
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                } => ZkX509FixedAlgebraicAtomV1::Repeated {
                    column: column_offset + column,
                    first,
                    count,
                    stride,
                    start_value,
                    step,
                },
                ZkX509FixedAlgebraicAtomV1::Sparse { column, row, value } => {
                    ZkX509FixedAlgebraicAtomV1::Sparse {
                        column: column_offset + column,
                        row,
                        value,
                    }
                }
            }));
            column_offset += child.width_v1();
        }
        atoms
    }
}
fn compile_p256_fixed_child_v1(
    domain: ZkX509FixedAlgebraicDomainV1,
    width: usize,
    compile: impl FnOnce(
        &mut ZkX509FixedAlgebraicScheduleBuilderV1,
    ) -> Result<(), ZkX509P256FixedAlgebraicErrorV1>,
) -> Result<ZkX509FixedAlgebraicScheduleV1, ZkX509P256FixedAlgebraicErrorV1> {
    let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, u16_v1(width)?)?;
    compile(&mut builder)?;
    builder.finish_v1().map_err(Into::into)
}
/// Compile the exact six-schedule, 404-column verifier-owned P-256 schedule.
pub fn compile_zk_x509_p256_fixed_algebraic_schedule_v1()
-> Result<ZkX509P256FixedAlgebraicScheduleV1, ZkX509P256FixedAlgebraicErrorV1> {
    let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
        ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
        ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
        F(GOLDILOCKS_GENERATOR_V1),
    )?;
    let certificate = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::CertificateOrCrl)
        .map_err(map_trace_error_v1)?;
    let wallet = compile_p256_ecdsa_topology_v1(P256EcdsaRoleV1::WalletOwnership)
        .map_err(map_trace_error_v1)?;
    let certificate_metadata = compile_value_metadata_v1(&certificate)?;
    let wallet_metadata = compile_value_metadata_v1(&wallet)?;
    let mut children = Vec::new();
    children
        .try_reserve_exact(ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1)
        .map_err(|_| ZkX509P256FixedAlgebraicErrorV1::Resource)?;
    children.push(compile_p256_fixed_child_v1(
        domain,
        P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
        |builder| compile_arithmetic_fixed_v1(builder, 0, &certificate),
    )?);
    children.push(compile_p256_fixed_child_v1(
        domain,
        P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
        |builder| compile_arithmetic_fixed_v1(builder, 0, &wallet),
    )?);
    children.push(compile_p256_fixed_child_v1(
        domain,
        P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
        |builder| compile_execution_fixed_v1(builder, 0, &certificate, &certificate_metadata),
    )?);
    children.push(compile_p256_fixed_child_v1(
        domain,
        P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
        |builder| compile_execution_fixed_v1(builder, 0, &wallet, &wallet_metadata),
    )?);
    children.push(compile_p256_fixed_child_v1(
        domain,
        P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
        |builder| compile_sorted_fixed_v1(builder, 0, &certificate_metadata),
    )?);
    children.push(compile_p256_fixed_child_v1(
        domain,
        P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
        |builder| compile_sorted_fixed_v1(builder, 0, &wallet_metadata),
    )?);
    let children = children
        .try_into()
        .map_err(|_: Vec<ZkX509FixedAlgebraicScheduleV1>| {
            ZkX509P256FixedAlgebraicErrorV1::Topology
        })?;
    ZkX509P256FixedAlgebraicScheduleV1::new_v1(children)
}
static ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_V1: OnceLock<ZkX509P256FixedAlgebraicScheduleV1> =
    OnceLock::new();
/// Borrow the canonical verifier-derived P-256 schedule.
///
/// Only a successful compilation is cached. A transient allocation failure or any fail-closed
/// topology error therefore cannot poison the process-wide cell, while the raw compiler remains
/// available for independent KAT reproduction.
pub fn zk_x509_p256_fixed_algebraic_schedule_v1()
-> Result<&'static ZkX509P256FixedAlgebraicScheduleV1, ZkX509P256FixedAlgebraicErrorV1> {
    if let Some(schedule) = ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_V1.get() {
        return Ok(schedule);
    }
    let schedule = compile_zk_x509_p256_fixed_algebraic_schedule_v1()?;
    let _ = ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_V1.set(schedule);
    ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_V1
        .get()
        .ok_or(ZkX509P256FixedAlgebraicErrorV1::Topology)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::{
        transparent_stark::{
            goldilocks_evaluate_coset_v1, goldilocks_ifft_v1, goldilocks_primitive_root_v1,
        },
        zk_x509::{
            fixed_algebraic::{
                ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1, ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1,
            },
            p256_aggregate_adapter::P256MainVerifierFixedSourceV1,
        },
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt::Write as _,
    };
    // Filled from the first successful structural compilation and deliberately
    // pinned thereafter. A topology or atom-decomposition change must update
    // the profile and this KAT together.
    const P256_FIXED_ALGEBRAIC_ATOM_COUNT_KAT_V1: usize = 199_616;
    const P256_FIXED_ALGEBRAIC_ATOM_PROFILE_KAT_V1: (usize, usize, usize, u64, u64) =
        (41_872, 149_102, 8_642, 21_813_752, 14_828);
    const P256_FIXED_ALGEBRAIC_UNIQUE_REPEAT_STRIDES_KAT_V1: &[u64] =
        &[2, 3, 5, 7, 8, 16, 24, 25, 32, 944, 1_376, 5_088, 7_104];
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct P256DiagnosticStageCountV1 {
        stage: &'static str,
        atoms: usize,
    }
    fn exact_maximum_272_query_work_score_v1(schedule: &ZkX509FixedAlgebraicScheduleV1) -> u64 {
        let domain = schedule.domain_v1();
        let native_size = domain.native_size_v1().expect("bounded native size");
        let blowup = domain.blowup_v1().expect("bounded LDE blowup");
        let query_count =
            u64::try_from(ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1).expect("small query cap");
        let mut group_counts = BTreeMap::<u64, u64>::new();
        for query in 0..query_count {
            let count = group_counts.entry(query % blowup).or_default();
            *count = count.checked_add(1).expect("bounded group query count");
        }
        assert_eq!(
            u64::try_from(group_counts.len()).expect("bounded groups"),
            blowup
        );
        assert_eq!(group_counts.values().sum::<u64>(), query_count);
        assert!(group_counts.values().all(|count| {
            *count == query_count / blowup || *count == query_count.div_ceil(blowup)
        }));
        let mut non_repeated = 0_u64;
        let mut repeated_runs = BTreeMap::<u64, (u64, u64)>::new();
        for atom in schedule.atoms_v1().iter().copied() {
            if let ZkX509FixedAlgebraicAtomV1::Repeated { count, stride, .. } = atom {
                let (atom_count, occurrences) = repeated_runs.entry(stride).or_default();
                *atom_count = atom_count
                    .checked_add(1)
                    .expect("bounded repeated atom count");
                *occurrences = occurrences
                    .checked_add(count)
                    .expect("bounded repeated occurrence count");
            } else {
                non_repeated = non_repeated
                    .checked_add(1)
                    .expect("bounded non-repeated atom count");
            }
        }
        let mut total = non_repeated
            .checked_mul(query_count)
            .expect("bounded non-repeated query work");
        for group_query_count in group_counts.values().copied() {
            total = total
                .checked_add(native_size)
                .expect("bounded Lagrange-table work");
            for (atom_count, occurrences) in repeated_runs.values().copied() {
                let direct = occurrences
                    .checked_mul(group_query_count)
                    .expect("bounded direct repeated work");
                let table = native_size
                    .checked_add(
                        atom_count
                            .checked_mul(group_query_count)
                            .expect("bounded table reference work"),
                    )
                    .expect("bounded stride-table work");
                total = total
                    .checked_add(direct.min(table))
                    .expect("bounded total evaluation work");
            }
        }
        total
    }
    fn digest_hex_v1(digest: PrivacyOuterDigestV1) -> String {
        let mut encoded = String::with_capacity(96);
        for byte in digest.to_bytes() {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String is infallible");
        }
        encoded
    }
    #[test]
    fn collect_exact_release_kats_or_report_stage_v1() {
        let schedule = compile_zk_x509_p256_fixed_algebraic_schedule_v1()
            .expect("six independently capped canonical child schedules");
        let stages: Vec<P256DiagnosticStageCountV1> = [
            "certificate-arithmetic",
            "wallet-arithmetic",
            "certificate-execution",
            "wallet-execution",
            "certificate-sorted",
            "wallet-sorted",
        ]
        .into_iter()
        .zip(schedule.children_v1())
        .map(|(stage, child)| P256DiagnosticStageCountV1 {
            stage,
            atoms: child.atoms_v1().len(),
        })
        .collect();
        let child_digests: Vec<String> = schedule
            .children_v1()
            .iter()
            .map(|child| digest_hex_v1(child.descriptor_digest_v1()))
            .collect();
        let mut affine = 0_usize;
        let mut repeated = 0_usize;
        let mut sparse = 0_usize;
        let mut repeated_terms = 0_u64;
        let mut maximum_repetition = 0_u64;
        let mut strides = BTreeSet::new();
        for atom in schedule.atoms_v1().iter().copied() {
            match atom {
                ZkX509FixedAlgebraicAtomV1::Affine { .. } => affine += 1,
                ZkX509FixedAlgebraicAtomV1::Repeated { count, stride, .. } => {
                    repeated += 1;
                    repeated_terms = repeated_terms
                        .checked_add(count)
                        .expect("bounded canonical repetition count");
                    maximum_repetition = maximum_repetition.max(count);
                    strides.insert(stride);
                }
                ZkX509FixedAlgebraicAtomV1::Sparse { .. } => sparse += 1,
            }
        }
        println!(
            "P256_KATS stages={:?} child_digests={child_digests:?} atom_count={} \
             schedule_digest={} compiler_digest={} \
             atom_profile=({affine},{repeated},{sparse},{repeated_terms},{maximum_repetition}) \
             unique_repeat_strides={:?} maximum_272_query_work={}",
            stages,
            schedule.atom_count_v1(),
            digest_hex_v1(schedule.descriptor_digest_v1()),
            digest_hex_v1(
                zk_x509_p256_fixed_algebraic_compiler_descriptor_digest_v1()
                    .expect("stable compiler descriptor"),
            ),
            strides,
            schedule
                .children_v1()
                .iter()
                .map(exact_maximum_272_query_work_score_v1)
                .sum::<u64>(),
        );
    }
    fn reconstruct_operation_sequence_plan_v1(plan: &P256OperationSequencePlanV1) -> Vec<F> {
        let packed_rows = P256_VALUE_BUS_SEGMENT_ROWS_V1 / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
        let mut values = vec![F::ZERO; P256_ARITHMETIC_OPERATIONS_V1];
        for run in plan.runs.iter().copied() {
            for occurrence in 0..run.count {
                let row = run.first + occurrence * run.stride;
                assert_eq!(row % packed_rows, 0);
                let operation = row / packed_rows;
                let target = values
                    .get_mut(operation)
                    .expect("plan run is inside the operation topology");
                *target = target.add(run.start_value.add(run.step.mul(F(occurrence as u64))));
            }
        }
        values
    }
    #[test]
    fn operation_sequence_row_and_call_axis_plans_are_exact_v1() {
        let zero_values = vec![F::ZERO; P256_ARITHMETIC_OPERATIONS_V1];
        let tied_plan =
            compile_p256_operation_sequence_plan_v1(&zero_values).expect("zero topology");
        assert_eq!(tied_plan.axis, P256OperationSequenceAxisV1::Row);
        assert!(tied_plan.runs.is_empty());
        assert_eq!(
            reconstruct_operation_sequence_plan_v1(&tied_plan),
            zero_values
        );
        let row_values: Vec<F> = (0..P256_ARITHMETIC_OPERATIONS_V1)
            .map(|index| F(index as u64 + 1))
            .collect();
        let row_plan =
            compile_p256_operation_sequence_plan_v1(&row_values).expect("row-affine topology");
        assert_eq!(row_plan.axis, P256OperationSequenceAxisV1::Row);
        assert_eq!(row_plan.runs.len(), 1);
        assert_eq!(
            reconstruct_operation_sequence_plan_v1(&row_plan),
            row_values
        );
        let mut call_values = vec![F::ZERO; P256_ARITHMETIC_OPERATIONS_V1];
        for (segment_index, segment) in P256_OPERATION_CALL_SEGMENTS_V1.iter().copied().enumerate()
        {
            for call in 0..segment.calls {
                for operation_in_call in 0..segment.operations_per_call {
                    let operation = segment.first_operation
                        + call * segment.operations_per_call
                        + operation_in_call;
                    let relative = operation_in_call as u64;
                    let base =
                        1 + segment_index as u64 * 1_000_000 + relative * relative * 3 + relative;
                    let step = 17 + 2 * relative;
                    call_values[operation] = F(base + call as u64 * step);
                }
            }
        }
        for operation in P256_FINAL_OPERATION_START_V1..P256_ARITHMETIC_OPERATIONS_V1 {
            let relative = (operation - P256_FINAL_OPERATION_START_V1) as u64;
            call_values[operation] = F(9_000_001 + relative * relative);
        }
        let call_plan =
            compile_p256_operation_sequence_plan_v1(&call_values).expect("call-affine topology");
        assert_eq!(call_plan.axis, P256OperationSequenceAxisV1::Call);
        assert_eq!(
            call_plan.runs.len(),
            P256_COMPLETE_ADD_OPERATIONS_V1 + P256_SCALAR_ROUND_OPERATIONS_V1 + 9
        );
        assert_eq!(
            reconstruct_operation_sequence_plan_v1(&call_plan),
            call_values
        );
    }
    #[test]
    fn operation_sequence_plan_rejects_malformed_segment_boundaries_v1() {
        let values = vec![F::ONE; P256_ARITHMETIC_OPERATIONS_V1];
        assert_eq!(
            compile_p256_operation_sequence_plan_v1(&values[..values.len() - 1]),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        let [first, second] = P256_OPERATION_CALL_SEGMENTS_V1;
        for malformed in [
            [
                first,
                P256OperationCallSegmentV1 {
                    first_operation: second.first_operation + 1,
                    ..second
                },
            ],
            [
                first,
                P256OperationCallSegmentV1 {
                    first_operation: second.first_operation - 1,
                    ..second
                },
            ],
            [P256OperationCallSegmentV1 { calls: 1, ..first }, second],
            [
                first,
                P256OperationCallSegmentV1 {
                    operations_per_call: 0,
                    ..second
                },
            ],
        ] {
            assert_eq!(
                compile_p256_operation_sequence_plan_for_layout_v1(
                    &values,
                    &malformed,
                    P256_FINAL_OPERATION_START_V1,
                ),
                Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
            );
        }
        for malformed_tail in [
            P256_FINAL_OPERATION_START_V1 - 1,
            P256_FINAL_OPERATION_START_V1 + 1,
            values.len(),
        ] {
            assert_eq!(
                compile_p256_operation_sequence_plan_for_layout_v1(
                    &values,
                    &P256_OPERATION_CALL_SEGMENTS_V1,
                    malformed_tail,
                ),
                Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
            );
        }
        assert_eq!(
            compile_p256_operation_sequence_plan_for_layout_v1(
                &values,
                &[P256OperationCallSegmentV1 {
                    first_operation: 0,
                    calls: usize::MAX,
                    operations_per_call: 2,
                }],
                P256_FINAL_OPERATION_START_V1,
            ),
            Err(ZkX509P256FixedAlgebraicErrorV1::Resource)
        );
    }
    fn isolated_sorted_run_schedule_v1(
        axis: P256SortedRunAxisV1,
        run_start: usize,
        run_count: usize,
        per_limb: usize,
    ) -> ZkX509FixedAlgebraicScheduleV1 {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release algebraic domain");
        let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
            domain,
            u16_v1(P256_VALUE_BUS_STARK_FIXED_WIDTH_V1).expect("bounded sorted width"),
        )
        .expect("bounded sorted-run builder");
        let block_factors = P256_VALUE_BUS_LIMBS_V1 * per_limb;
        let logical_end = run_count * block_factors;
        match axis {
            P256SortedRunAxisV1::RelativeFactor => emit_sorted_relative_factor_axis_run_v1(
                &mut builder,
                0,
                0,
                run_start,
                run_count,
                per_limb,
            )
            .expect("valid relative-factor run"),
            P256SortedRunAxisV1::PerValue => emit_sorted_per_value_axis_run_v1(
                &mut builder,
                0,
                0,
                logical_end,
                run_start,
                run_count,
                per_limb,
            )
            .expect("valid per-value run"),
        }
        builder.finish_v1().expect("canonical isolated run")
    }
    #[test]
    fn sorted_run_axis_uses_exact_costs_and_preserves_relative_ties_v1() {
        assert_eq!(sorted_relative_factor_axis_atom_count_v1(7, 3, 1), Ok(63));
        assert_eq!(sorted_per_value_axis_atom_count_v1(7, 3, 1), Ok(63));
        assert_eq!(
            sorted_run_axis_v1(7, 3, 1),
            Ok(P256SortedRunAxisV1::RelativeFactor),
            "the established axis must win exact ties"
        );
        assert_eq!(
            sorted_run_axis_v1(7, 1, 1),
            Ok(P256SortedRunAxisV1::PerValue)
        );
        assert_eq!(
            sorted_run_axis_v1(7, 4, 1),
            Ok(P256SortedRunAxisV1::RelativeFactor)
        );
        assert_eq!(sorted_relative_factor_axis_atom_count_v1(7, 2, 5), Ok(187));
        assert_eq!(sorted_per_value_axis_atom_count_v1(7, 2, 5), Ok(72));
        assert_eq!(
            sorted_run_axis_v1(7, 2, 5),
            Ok(P256SortedRunAxisV1::PerValue)
        );
        for malformed in [(0, 0, 1), (0, 1, 0)] {
            assert_eq!(
                sorted_run_axis_v1(malformed.0, malformed.1, malformed.2),
                Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
            );
        }
        assert_eq!(
            sorted_run_axis_v1(usize::MAX, 1, 1),
            Err(ZkX509P256FixedAlgebraicErrorV1::Resource)
        );
        assert_eq!(
            sorted_run_axis_v1(0, 1, usize::MAX),
            Err(ZkX509P256FixedAlgebraicErrorV1::Resource)
        );
    }
    #[test]
    fn sorted_run_axes_are_native_row_equivalent_with_exact_savings_v1() {
        let run_start = 7;
        let run_count = 2;
        let per_limb = 5;
        let relative = isolated_sorted_run_schedule_v1(
            P256SortedRunAxisV1::RelativeFactor,
            run_start,
            run_count,
            per_limb,
        );
        let per_value = isolated_sorted_run_schedule_v1(
            P256SortedRunAxisV1::PerValue,
            run_start,
            run_count,
            per_limb,
        );
        assert_eq!(relative.atoms_v1().len(), 187);
        assert_eq!(per_value.atoms_v1().len(), 72);
        let logical_end = run_count * P256_VALUE_BUS_LIMBS_V1 * per_limb;
        let mut relative_row = [F::ZERO; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1];
        let mut per_value_row = [F::ZERO; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1];
        for row in 0..=logical_end / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            relative
                .native_row_v1(row as u64, &mut relative_row)
                .expect("relative-factor native row");
            per_value
                .native_row_v1(row as u64, &mut per_value_row)
                .expect("per-value native row");
            assert_eq!(per_value_row, relative_row, "packed sorted row {row}");
        }
    }
    #[test]
    fn malformed_sorted_runs_fail_before_mutating_the_builder_v1() {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release algebraic domain");
        let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
            domain,
            u16_v1(P256_VALUE_BUS_STARK_FIXED_WIDTH_V1).expect("bounded sorted width"),
        )
        .expect("bounded adversarial builder");
        builder
            .push_sparse_v1(21, 1_000, F(123))
            .expect("sentinel atom");
        assert_eq!(
            emit_sorted_relative_factor_axis_run_v1(&mut builder, 0, 1, 7, 2, 5),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            emit_sorted_relative_factor_axis_run_v1(&mut builder, 0, 0, 7, 0, 5),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            emit_sorted_per_value_axis_run_v1(&mut builder, 0, 0, 159, 7, 2, 5),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            emit_sorted_per_value_axis_run_v1(&mut builder, 0, 0, 0, 7, 2, 0),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        for malformed in [
            push_sorted_logical_stride_v1(&mut builder, 0, VALUE_ACCESS_V1, 0, 1, 1, F::ONE),
            push_sorted_logical_stride_v1(&mut builder, 0, VALUE_ACCESS_V1, 0, 2, 0, F::ONE),
            push_sorted_logical_stride_v1(&mut builder, 0, VALUE_ACCESS_V1, 0, 2, 1, F::ZERO),
        ] {
            assert_eq!(malformed, Err(ZkX509P256FixedAlgebraicErrorV1::Topology));
        }
        assert_eq!(
            push_sorted_logical_stride_v1(
                &mut builder,
                0,
                VALUE_ACCESS_V1,
                usize::MAX - 1,
                2,
                2,
                F::ONE,
            ),
            Err(ZkX509P256FixedAlgebraicErrorV1::Resource)
        );
        let schedule = builder.finish_v1().expect("sentinel-only schedule");
        assert_eq!(schedule.atoms_v1().len(), 1);
    }
    fn synthetic_phase_metadata_v1() -> (Vec<P256ValueMetadataV1>, Vec<usize>) {
        let leading = P256ValueMetadataV1 {
            modulus: ZkX509P256ModulusV1::BaseField,
            kind: P256ValueKindV1::Input,
            reads: 0,
        };
        let template = [
            P256ValueMetadataV1 {
                modulus: ZkX509P256ModulusV1::BaseField,
                kind: P256ValueKindV1::Derived,
                reads: 0,
            },
            P256ValueMetadataV1 {
                modulus: ZkX509P256ModulusV1::ScalarField,
                kind: P256ValueKindV1::Derived,
                reads: 1,
            },
        ];
        let mut metadata = vec![leading];
        for _ in 0..3 {
            metadata.extend_from_slice(&template);
        }
        let mut prefix = vec![0_usize];
        for value in &metadata {
            prefix.push(
                prefix.last().copied().expect("prefix origin")
                    + P256_VALUE_BUS_LIMBS_V1 * (value.reads + 1),
            );
        }
        (metadata, prefix)
    }
    fn isolated_synthetic_phase_schedule_v1(
        metadata: &[P256ValueMetadataV1],
        prefix: &[usize],
        plan: P256SortedRepeatedPhasePlanV1,
        axis: P256SortedRepeatedPhaseAxisV1,
    ) -> ZkX509FixedAlgebraicScheduleV1 {
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release algebraic domain");
        let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
            domain,
            u16_v1(P256_VALUE_BUS_STARK_FIXED_WIDTH_V1).expect("bounded sorted width"),
        )
        .expect("bounded phase builder");
        match axis {
            P256SortedRepeatedPhaseAxisV1::Local => {
                emit_sorted_local_range_v1(
                    &mut builder,
                    0,
                    metadata,
                    prefix,
                    plan.value_start,
                    plan.value_end_v1().expect("bounded phase end"),
                )
                .expect("valid local phase");
            }
            P256SortedRepeatedPhaseAxisV1::Phase => {
                emit_sorted_repeated_phase_v1(&mut builder, 0, metadata, prefix, plan)
                    .expect("valid repeated phase");
            }
        }
        builder.finish_v1().expect("canonical isolated phase")
    }
    #[test]
    fn repeated_phase_axis_is_exact_and_native_row_equivalent_v1() {
        let (metadata, prefix) = synthetic_phase_metadata_v1();
        let plan = compile_sorted_repeated_phase_plan_v1(&metadata, &prefix, 1, 3, 2)
            .expect("identical repeated template");
        assert_eq!(plan.block_factors, 48);
        assert_eq!(plan.local_atoms, 165);
        assert_eq!(plan.phase_atoms, 157);
        assert_eq!(plan.axis, P256SortedRepeatedPhaseAxisV1::Phase);
        let local = isolated_synthetic_phase_schedule_v1(
            &metadata,
            &prefix,
            plan,
            P256SortedRepeatedPhaseAxisV1::Local,
        );
        let phase = isolated_synthetic_phase_schedule_v1(
            &metadata,
            &prefix,
            plan,
            P256SortedRepeatedPhaseAxisV1::Phase,
        );
        assert_eq!(local.atoms_v1().len(), plan.local_atoms);
        assert_eq!(phase.atoms_v1().len(), plan.phase_atoms);
        let mut local_row = [F::ZERO; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1];
        let mut phase_row = [F::ZERO; P256_VALUE_BUS_STARK_FIXED_WIDTH_V1];
        for row in 0..=prefix[metadata.len()] / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
            local
                .native_row_v1(row as u64, &mut local_row)
                .expect("local native row");
            phase
                .native_row_v1(row as u64, &mut phase_row)
                .expect("phase native row");
            assert_eq!(phase_row, local_row, "synthetic phase row {row}");
        }
    }
    #[test]
    fn repeated_phase_template_drift_and_overflow_fail_before_mutation_v1() {
        let (metadata, prefix) = synthetic_phase_metadata_v1();
        let plan = compile_sorted_repeated_phase_plan_v1(&metadata, &prefix, 1, 3, 2)
            .expect("identical repeated template");
        for field in 0..3 {
            let mut drifted = metadata.clone();
            match field {
                0 => drifted[3].reads += 1,
                1 => drifted[3].modulus = ZkX509P256ModulusV1::ScalarField,
                2 => drifted[3].kind = P256ValueKindV1::Constant,
                _ => unreachable!("three metadata fields"),
            }
            assert_eq!(
                compile_sorted_repeated_phase_plan_v1(&drifted, &prefix, 1, 3, 2),
                Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
            );
        }
        let mut drifted_prefix = prefix.clone();
        drifted_prefix[3] += 2;
        assert_eq!(
            compile_sorted_repeated_phase_plan_v1(&metadata, &drifted_prefix, 1, 3, 2),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            compile_sorted_repeated_phase_plan_v1(&metadata, &prefix, 1, usize::MAX, 2),
            Err(ZkX509P256FixedAlgebraicErrorV1::Resource)
        );
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release algebraic domain");
        let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
            domain,
            u16_v1(P256_VALUE_BUS_STARK_FIXED_WIDTH_V1).expect("bounded sorted width"),
        )
        .expect("bounded adversarial phase builder");
        builder
            .push_sparse_v1(21, 1_000, F(123))
            .expect("sentinel atom");
        let mut drifted = metadata;
        drifted[3].reads += 1;
        assert_eq!(
            emit_sorted_repeated_phase_v1(&mut builder, 0, &drifted, &prefix, plan),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            builder
                .finish_v1()
                .expect("sentinel-only schedule")
                .atoms_v1()
                .len(),
            1
        );
    }
    #[test]
    fn active_zero_writer_address_is_encoded_as_implicit_zero_v1() {
        let sources =
            compile_zk_x509_p256_external_cross_sources_v1(P256EcdsaRoleV1::CertificateOrCrl)
                .expect("verifier-owned certificate sources");
        assert!(
            sources
                .iter()
                .flatten()
                .flatten()
                .any(|source| source.writer_id == P256ValueIdV1(0) && source.writer_limb == 0),
            "the release topology binds the first limb of constant value zero"
        );
        let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
            ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("release algebraic domain");
        let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
            domain,
            u16_v1(P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1).expect("bounded execution width"),
        )
        .expect("bounded writer schedule");
        compile_writer_fixed_v1(
            &mut builder,
            0,
            P256EcdsaRoleV1::CertificateOrCrl,
            P256_INITIAL_VALUES_V1 + P256_ARITHMETIC_OPERATIONS_V1,
        )
        .expect("zero is a canonical active writer address");
        let schedule = builder.finish_v1().expect("canonical writer schedule");
        // Initial value zero, limb zero occupies logical ordinal 48, hence
        // packed row 24 and slot zero.
        let mut row = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1];
        schedule
            .native_row_v1(24, &mut row)
            .expect("writer row is in the native domain");
        assert_eq!(row[EXECUTION_WRITER_START_V1], F::ONE);
        assert_eq!(row[EXECUTION_WRITER_START_V1 + 1], F::ONE);
        assert_eq!(row[EXECUTION_WRITER_START_V1 + 2], F::ZERO);
    }
    #[test]
    fn selected_input_writers_match_closed_native_fixed_rows_in_both_roles() {
        use super::super::p256_cross_trace_bus::P256CrossTraceWriterSourceFixedV1;
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let domain = ZkX509FixedAlgebraicDomainV1::new_v1(
                ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
                ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .expect("release domain");
            let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
                domain,
                u16_v1(P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1).unwrap(),
            )
            .unwrap();
            compile_writer_fixed_v1(
                &mut builder,
                0,
                role,
                P256_INITIAL_VALUES_V1 + P256_ARITHMETIC_OPERATIONS_V1,
            )
            .unwrap();
            let schedule = builder.finish_v1().unwrap();
            let native = P256CrossTraceWriterSourceFixedV1::compile_v1(role).unwrap();
            let mut rows = BTreeSet::new();
            for (word, id) in [47_usize, 48, 52, 53].into_iter().enumerate() {
                assert_eq!(
                    p256_selected_input_writer_id_v1(word).unwrap(),
                    Some(P256ValueIdV1(id as u32))
                );
                for limb in 0..P256_VALUE_BUS_LIMBS_V1 {
                    let ordinal =
                        id * P256_VALUE_BUS_SEGMENT_ROWS_V1 + 3 * P256_VALUE_BUS_LIMBS_V1 + limb;
                    let row = ordinal / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
                    let slot = ordinal % P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1;
                    let mut actual = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1];
                    schedule.native_row_v1(row as u64, &mut actual).unwrap();
                    let event = EXECUTION_WRITER_START_V1 + slot * 3;
                    assert_eq!(
                        &actual[event..event + 3],
                        &[
                            F::ONE,
                            F::ONE,
                            F((id * P256_VALUE_BUS_LIMBS_V1 + limb) as u64)
                        ]
                    );
                    let multiplicity = EXECUTION_WRITER_MULTIPLICITY_START_V1 + slot * 4;
                    let expected =
                        if word < 2 {
                            [F::ZERO, F::ZERO, F::ONE, F::ZERO]
                        } else {
                            [
                                F(1 + u64::from(
                                    word == 3 && role == P256EcdsaRoleV1::WalletOwnership,
                                )),
                                F::ZERO,
                                F::ZERO,
                                F::ZERO,
                            ]
                        };
                    assert_eq!(&actual[multiplicity..multiplicity + 4], &expected);
                    rows.extend([row - 1, row, row + 1]);
                }
            }
            for row in rows {
                let mut actual = [F::ZERO; P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1];
                schedule.native_row_v1(row as u64, &mut actual).unwrap();
                let expected = native.row_v1(row).unwrap();
                for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
                    let event = EXECUTION_WRITER_START_V1 + slot * 3;
                    assert_eq!(
                        &actual[event..event + 3],
                        &[
                            expected.events[slot].active,
                            expected.events[slot].endpoint,
                            expected.events[slot].address
                        ]
                    );
                    let multiplicity = EXECUTION_WRITER_MULTIPLICITY_START_V1 + slot * 4;
                    assert_eq!(
                        &actual[multiplicity..multiplicity + 4],
                        &[
                            expected.multiplicity_small[slot],
                            expected.multiplicity_64[slot],
                            expected.multiplicity_65[slot],
                            expected.multiplicity_129[slot]
                        ]
                    );
                }
            }
        }
    }
    fn schedule_v1() -> &'static ZkX509P256FixedAlgebraicScheduleV1 {
        zk_x509_p256_fixed_algebraic_schedule_v1()
            .expect("canonical cached structural P-256 algebraic schedule")
    }
    fn native_source_v1() -> &'static P256MainVerifierFixedSourceV1 {
        static SOURCE: OnceLock<P256MainVerifierFixedSourceV1> = OnceLock::new();
        SOURCE.get_or_init(|| {
            P256MainVerifierFixedSourceV1::new_v1()
                .expect("closed verifier-owned P-256 fixed source")
        })
    }
    const SCHEDULE_KINDS_V1: [ZkX509P256FixedAlgebraicScheduleKindV1;
        ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1] = [
        ZkX509P256FixedAlgebraicScheduleKindV1::CertificateArithmetic,
        ZkX509P256FixedAlgebraicScheduleKindV1::WalletArithmetic,
        ZkX509P256FixedAlgebraicScheduleKindV1::CertificateExecution,
        ZkX509P256FixedAlgebraicScheduleKindV1::WalletExecution,
        ZkX509P256FixedAlgebraicScheduleKindV1::CertificateSorted,
        ZkX509P256FixedAlgebraicScheduleKindV1::WalletSorted,
    ];
    fn expected_combined_native_row_v1(row: usize) -> [F; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1] {
        let mut combined = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1];
        for kind in SCHEDULE_KINDS_V1 {
            let registration = kind
                .representative_registration_v1()
                .expect("representative registration");
            let expected = native_source_v1()
                .fixed_row_v1(registration, row)
                .expect("closed native fixed row");
            let (start, width) = kind.start_width_v1();
            assert_eq!(expected.len(), width);
            combined[start..start + width].copy_from_slice(&expected);
        }
        combined
    }
    fn kind_for_global_column_v1(column: usize) -> (ZkX509P256FixedAlgebraicScheduleKindV1, usize) {
        for kind in SCHEDULE_KINDS_V1 {
            let (start, width) = kind.start_width_v1();
            if (start..start + width).contains(&column) {
                return (kind, column - start);
            }
        }
        panic!("test global column must be in the exact width");
    }
    #[test]
    fn exact_six_schedules_fifteen_aliases_and_widths() {
        assert_eq!(SCHEDULE_KINDS_V1.len(), 6);
        assert_eq!(schedule_v1().width_v1(), 404);
        assert_eq!(
            SCHEDULE_KINDS_V1.map(ZkX509P256FixedAlgebraicScheduleKindV1::start_width_v1),
            [
                (0, 134),
                (134, 134),
                (268, 46),
                (314, 46),
                (360, 22),
                (382, 22),
            ]
        );
        let mut aliases = 0_usize;
        for signature in 0..P256_X5S1_SIGNATURES_V1 {
            for (adapter, local) in [
                (P256MainAdapterV1::Arithmetic, 0),
                (P256MainAdapterV1::ValueBus, 0),
                (P256MainAdapterV1::ValueBus, 1),
            ] {
                let registration = P256MainRegistrationV1::new_v1(signature, adapter, local)
                    .expect("canonical alias");
                let kind = zk_x509_p256_fixed_algebraic_schedule_for_registration_v1(registration)
                    .expect("accepted exact alias");
                assert_eq!(
                    kind,
                    match (adapter, local, signature < 4) {
                        (P256MainAdapterV1::Arithmetic, 0, true) =>
                            ZkX509P256FixedAlgebraicScheduleKindV1::CertificateArithmetic,
                        (P256MainAdapterV1::Arithmetic, 0, false) =>
                            ZkX509P256FixedAlgebraicScheduleKindV1::WalletArithmetic,
                        (P256MainAdapterV1::ValueBus, 0, true) =>
                            ZkX509P256FixedAlgebraicScheduleKindV1::CertificateExecution,
                        (P256MainAdapterV1::ValueBus, 0, false) =>
                            ZkX509P256FixedAlgebraicScheduleKindV1::WalletExecution,
                        (P256MainAdapterV1::ValueBus, 1, true) =>
                            ZkX509P256FixedAlgebraicScheduleKindV1::CertificateSorted,
                        (P256MainAdapterV1::ValueBus, 1, false) =>
                            ZkX509P256FixedAlgebraicScheduleKindV1::WalletSorted,
                        _ => unreachable!("test enumerates the exact three adapters"),
                    }
                );
                aliases += 1;
            }
        }
        assert_eq!(aliases, ZK_X509_P256_FIXED_ALGEBRAIC_ALIAS_COUNT_V1);
    }
    #[test]
    fn atom_count_and_descriptor_digest_are_exact_and_deterministic() {
        let first = schedule_v1();
        assert!(
            core::ptr::eq(first, schedule_v1())
                && core::ptr::eq(
                    first,
                    zk_x509_p256_fixed_algebraic_schedule_v1()
                        .expect("successful process-wide schedule cache"),
                ),
            "successful compilation is cached at one stable address"
        );
        assert_ne!(
            zk_x509_p256_fixed_algebraic_compiler_descriptor_digest_v1()
                .expect("compiler descriptor digest"),
            PrivacyOuterDigestV1::default()
        );
        assert_eq!(
            first.atoms_v1().len(),
            P256_FIXED_ALGEBRAIC_ATOM_COUNT_KAT_V1
        );
        assert_ne!(
            first.descriptor_digest_v1(),
            PrivacyOuterDigestV1::default()
        );
        let independently_compiled = compile_zk_x509_p256_fixed_algebraic_schedule_v1()
            .expect("independent deterministic compilation");
        assert_eq!(
            independently_compiled.atoms_v1(),
            first.atoms_v1(),
            "the canonical atom decomposition is deterministic"
        );
        assert_eq!(
            independently_compiled.descriptor_digest_v1(),
            first.descriptor_digest_v1()
        );
    }
    #[test]
    fn composite_children_are_exact_and_reject_order_width_and_substitution_attacks() {
        let schedule = schedule_v1();
        assert_eq!(
            core::array::from_fn(|index| schedule.children_v1()[index].atoms_v1().len()),
            P256_FIXED_ALGEBRAIC_CHILD_ATOM_COUNTS_V1,
        );
        assert!(
            schedule
                .children_v1()
                .iter()
                .all(|child| child.descriptor_digest_v1() != PrivacyOuterDigestV1::default())
        );
        let mut reordered = schedule.children.clone();
        reordered.swap(2, 3);
        // Equal widths and atom counts do not authorize reordered or replaced
        // children. The constructor now enforces the original ordered pin.
        // Independently frame each candidate digest to retain the original
        // descriptor-mismatch assertions as well as constructor rejection.
        let candidate_digest =
            |children: &[ZkX509FixedAlgebraicScheduleV1;
                  ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1]| {
                let mut widths = [0_u8; 2 * ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1];
                let mut digests = [0_u8; 48 * ZK_X509_P256_FIXED_ALGEBRAIC_SCHEDULE_COUNT_V1];
                for (index, child) in children.iter().enumerate() {
                    widths[index * 2..index * 2 + 2]
                        .copy_from_slice(&child.width_v1().to_be_bytes());
                    digests[index * 48..index * 48 + 48]
                        .copy_from_slice(&child.descriptor_digest_v1().to_bytes());
                }
                privacy_outer_digest_frame_v1(
                    ZK_X509_FIXED_DIGEST_CONTEXT_V1,
                    P256_COMPOSITE_DESCRIPTOR_DIGEST_DOMAIN_V1,
                    b"p256-fixed-algebraic-composite",
                    0,
                    0,
                    0,
                    &[
                        ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1,
                        &widths,
                        &digests,
                    ],
                )
                .unwrap()
            };
        assert_eq!(
            candidate_digest(&schedule.children),
            schedule.descriptor_digest_v1()
        );
        let reordered_digest = candidate_digest(&reordered);
        assert_eq!(
            ZkX509P256FixedAlgebraicScheduleV1::new_v1(reordered),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            schedule.verify_descriptor_digest_v1(&reordered_digest),
            Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch)
        );
        let mut substituted = schedule.children.clone();
        substituted[2] = substituted[3].clone();
        let substituted_digest = candidate_digest(&substituted);
        assert_eq!(
            ZkX509P256FixedAlgebraicScheduleV1::new_v1(substituted),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        assert_eq!(
            schedule.verify_descriptor_digest_v1(&substituted_digest),
            Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch)
        );
        let mut wrong_order = schedule.children.clone();
        wrong_order.swap(1, 2);
        assert_eq!(
            ZkX509P256FixedAlgebraicScheduleV1::new_v1(wrong_order),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        let domain = schedule.domain_v1();
        let mut wrong_width =
            ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(domain, 45).expect("bounded child");
        wrong_width
            .push_sparse_v1(0, 0, F::ONE)
            .expect("canonical sparse child");
        let mut malformed_width = schedule.children.clone();
        malformed_width[2] = wrong_width
            .finish_v1()
            .expect("canonical wrong-width child");
        assert_eq!(
            ZkX509P256FixedAlgebraicScheduleV1::new_v1(malformed_width),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
    }
    #[test]
    fn composite_pin_rejects_same_shape_algebraic_child_mutation() {
        let schedule = schedule_v1();
        assert_eq!(
            schedule.descriptor_digest_v1().to_bytes(),
            P256_FIXED_ALGEBRAIC_COMPOSITE_DIGEST_V1,
        );
        let original = &schedule.children[0];
        let mut atoms = original.atoms_v1().to_vec();
        let ZkX509FixedAlgebraicAtomV1::Affine { start_value, .. } = &mut atoms[0] else {
            panic!("the canonical arithmetic child starts with its active-row selector");
        };
        *start_value = start_value.add(F::ONE);
        let changed = ZkX509FixedAlgebraicScheduleV1::new_v1(
            original.domain_v1(),
            original.width_v1(),
            atoms,
        )
        .expect("the altered child retains canonical algebraic shape");
        assert_eq!(changed.width_v1(), original.width_v1());
        assert_eq!(changed.atoms_v1().len(), original.atoms_v1().len());
        assert_ne!(
            changed.descriptor_digest_v1(),
            original.descriptor_digest_v1()
        );
        let mut substituted = schedule.children.clone();
        substituted[0] = changed;
        assert_eq!(
            ZkX509P256FixedAlgebraicScheduleV1::new_v1(substituted).err(),
            Some(ZkX509P256FixedAlgebraicErrorV1::Topology),
        );
    }
    #[test]
    fn sorted_active_extent_is_distinct_from_execution_logical_extent_v1() {
        assert_eq!(P256_VALUE_BUS_SORTED_ACTIVE_PACKED_ROWS_V1, 362_752);
        assert_eq!(P256_VALUE_BUS_LOGICAL_PACKED_ROWS_V1, 474_656);
        const {
            assert!(
                P256_VALUE_BUS_SORTED_ACTIVE_PACKED_ROWS_V1 < P256_VALUE_BUS_LOGICAL_PACKED_ROWS_V1
            )
        };
        let mut last_active = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1];
        schedule_v1()
            .native_row_v1(
                (P256_VALUE_BUS_SORTED_ACTIVE_PACKED_ROWS_V1 - 1) as u64,
                &mut last_active,
            )
            .expect("last sorted active row");
        let mut first_padding = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1];
        schedule_v1()
            .native_row_v1(
                P256_VALUE_BUS_SORTED_ACTIVE_PACKED_ROWS_V1 as u64,
                &mut first_padding,
            )
            .expect("first sorted padding row");
        for slice_start in [CERTIFICATE_SORTED_START_V1, WALLET_SORTED_START_V1] {
            for slot in 0..P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1 {
                assert_eq!(
                    last_active[value_slot_column_v1(slice_start, slot, VALUE_ACTIVE_V1)],
                    F::ONE
                );
                assert_eq!(
                    last_active[value_slot_column_v1(slice_start, slot, VALUE_PADDING_V1)],
                    F::ZERO
                );
                assert_eq!(
                    first_padding[value_slot_column_v1(slice_start, slot, VALUE_ACTIVE_V1)],
                    F::ZERO
                );
                assert_eq!(
                    first_padding[value_slot_column_v1(slice_start, slot, VALUE_PADDING_V1)],
                    F::ONE
                );
            }
        }
    }
    #[test]
    fn atom_profile_and_unique_repetition_strides_are_exact() {
        let atoms = schedule_v1().atoms_v1();
        let mut affine = 0_usize;
        let mut repeated = 0_usize;
        let mut sparse = 0_usize;
        let mut repeated_terms = 0_u64;
        let mut maximum_repetition = 0_u64;
        let mut strides = BTreeSet::new();
        for atom in atoms.iter().copied() {
            match atom {
                ZkX509FixedAlgebraicAtomV1::Affine { .. } => affine += 1,
                ZkX509FixedAlgebraicAtomV1::Repeated { count, stride, .. } => {
                    repeated += 1;
                    repeated_terms = repeated_terms
                        .checked_add(count)
                        .expect("bounded canonical repetition count");
                    maximum_repetition = maximum_repetition.max(count);
                    strides.insert(stride);
                }
                ZkX509FixedAlgebraicAtomV1::Sparse { .. } => sparse += 1,
            }
        }
        let observed = (
            atoms.len(),
            (affine, repeated, sparse, repeated_terms, maximum_repetition),
            strides.into_iter().collect::<Vec<_>>(),
        );
        let expected = (
            P256_FIXED_ALGEBRAIC_ATOM_COUNT_KAT_V1,
            P256_FIXED_ALGEBRAIC_ATOM_PROFILE_KAT_V1,
            P256_FIXED_ALGEBRAIC_UNIQUE_REPEAT_STRIDES_KAT_V1.to_vec(),
        );
        assert_eq!(observed, expected);
    }
    #[test]
    fn native_rows_match_closed_provider_at_transitions_and_deterministic_samples() {
        let mut rows = BTreeSet::new();
        let mut insert_boundary = |row: usize| {
            if row < P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
                rows.insert(row);
            }
            if row > 0 {
                rows.insert(row - 1);
            }
            if row + 1 < P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 {
                rows.insert(row + 1);
            }
        };
        for boundary in [
            0,
            13 * 32,
            14 * 32,
            15 * 32,
            P256_INITIAL_VALUES_V1 * 32,
            P256_ARITHMETIC_OPERATIONS_V1 * 32,
            P256_VALUE_BUS_LOGICAL_PACKED_ROWS_V1,
            P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 - 1,
        ] {
            insert_boundary(boundary);
        }
        for assertion in 0..=P256_VALUE_BUS_ASSERTIONS_V1 {
            let start = (P256_ARITHMETIC_OPERATIONS_V1 + assertion) * 32;
            insert_boundary(start);
            insert_boundary(start + 16);
        }
        for role in [
            P256EcdsaRoleV1::CertificateOrCrl,
            P256EcdsaRoleV1::WalletOwnership,
        ] {
            let topology = compile_p256_ecdsa_topology_v1(role).expect("closed topology");
            for operation in 1..topology.linked_operations.len() {
                let previous = topology.linked_operations[operation - 1];
                let current = topology.linked_operations[operation];
                if previous.kind != current.kind || previous.modulus != current.modulus {
                    insert_boundary(operation * P256_ARITHMETIC_ROWS_PER_OPERATION_V1);
                }
            }
            let metadata = compile_value_metadata_v1(&topology).expect("closed metadata");
            let mut logical = 0_usize;
            let mut previous_reads = None;
            for value in metadata {
                let per_limb = value.reads + 1;
                if previous_reads != Some(per_limb) {
                    insert_boundary(logical / P256_VALUE_BUS_FACTORS_PER_PACKED_ROW_V1);
                    previous_reads = Some(per_limb);
                }
                logical += P256_VALUE_BUS_LIMBS_V1 * per_limb;
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..256 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            rows.insert((state as usize) & (P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1 - 1));
        }
        let mut actual = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1];
        for row in rows {
            schedule_v1()
                .native_row_v1(row as u64, &mut actual)
                .expect("algebraic native row");
            assert_eq!(
                actual,
                expected_combined_native_row_v1(row),
                "native row {row}"
            );
        }
    }
    #[test]
    fn aliases_select_the_exact_native_schedule_slice() {
        for row in [0, 1, 415, 447, 448, 479, 474_655, 474_656, 524_287] {
            let combined = expected_combined_native_row_v1(row);
            for signature in 0..P256_X5S1_SIGNATURES_V1 {
                for (adapter, local) in [
                    (P256MainAdapterV1::Arithmetic, 0),
                    (P256MainAdapterV1::ValueBus, 0),
                    (P256MainAdapterV1::ValueBus, 1),
                ] {
                    let registration = P256MainRegistrationV1::new_v1(signature, adapter, local)
                        .expect("canonical alias");
                    let expected = native_source_v1()
                        .fixed_row_v1(registration, row)
                        .expect("native alias row");
                    assert_eq!(
                        zk_x509_p256_fixed_algebraic_row_for_registration_v1(
                            &combined,
                            registration,
                        )
                        .expect("exact alias slice"),
                        expected.as_slice()
                    );
                }
            }
        }
    }
    fn combined_reference_coefficients_v1() -> Vec<F> {
        let selected = [
            (0_usize, F(3)),
            (133, F(5)),
            (268, F(7)),
            (313, F(11)),
            (360, F(13)),
            (403, F(17)),
        ];
        let rows = P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1;
        let mut combined = vec![F::ZERO; rows];
        let mut scratch = vec![F::ZERO; rows];
        for (global, coefficient) in selected {
            let (kind, local) = kind_for_global_column_v1(global);
            native_source_v1()
                .fill_fixed_column_v1(
                    kind.representative_registration_v1()
                        .expect("representative registration"),
                    local,
                    &mut scratch,
                )
                .expect("closed native fixed column");
            for (target, value) in combined.iter_mut().zip(&scratch) {
                *target = target.add(value.mul(coefficient));
            }
        }
        let root =
            goldilocks_primitive_root_v1(ZK_X509_MAX_NATIVE_TRACE_LOG2_V1).expect("native root");
        goldilocks_ifft_v1(&mut combined, root).expect("independent native IFFT");
        combined
    }
    fn evaluate_coefficients_v1(coefficients: &[F], point: F) -> F {
        coefficients
            .iter()
            .rev()
            .fold(F::ZERO, |accumulator, coefficient| {
                accumulator.mul(point).add(*coefficient)
            })
    }
    fn selected_opening_linear_combination_v1(row: &[F]) -> F {
        [
            (0_usize, F(3)),
            (133, F(5)),
            (268, F(7)),
            (313, F(11)),
            (360, F(13)),
            (403, F(17)),
        ]
        .into_iter()
        .fold(F::ZERO, |accumulator, (column, coefficient)| {
            accumulator.add(row[column].mul(coefficient))
        })
    }
    #[test]
    fn ifft_coset_query_openings_match_independent_polynomial_evaluation() {
        let queries = [
            0_u64,
            1,
            63,
            64,
            (1_u64 << ZK_X509_MAIN_COMMON_LDE_LOG2_V1) - 1,
        ];
        let openings = schedule_v1()
            .evaluate_query_indices_v1(&queries)
            .expect("bounded algebraic queries");
        let coefficients = combined_reference_coefficients_v1();
        for (slot, query) in queries.into_iter().enumerate() {
            let point = schedule_v1()
                .domain_v1()
                .query_point_v1(query)
                .expect("generator-coset point");
            assert_eq!(
                selected_opening_linear_combination_v1(openings.row_v1(slot).expect("opening row")),
                evaluate_coefficients_v1(&coefficients, point),
                "query {query}"
            );
        }
    }
    #[test]
    #[ignore = "release diagnostic materializes one 2^22 scalar coset LDE, never a width-404 matrix"]
    fn independent_coset_fft_matches_every_selected_query() {
        let coefficients = combined_reference_coefficients_v1();
        let lde_size = 1_usize << ZK_X509_MAIN_COMMON_LDE_LOG2_V1;
        let lde_root =
            goldilocks_primitive_root_v1(ZK_X509_MAIN_COMMON_LDE_LOG2_V1).expect("LDE root");
        let lde = goldilocks_evaluate_coset_v1(
            &coefficients,
            lde_size,
            lde_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .expect("independent generator-coset FFT");
        let queries = [
            0_u64,
            1,
            63,
            64,
            1_048_573,
            (1_u64 << ZK_X509_MAIN_COMMON_LDE_LOG2_V1) - 1,
        ];
        let openings = schedule_v1()
            .evaluate_query_indices_v1(&queries)
            .expect("bounded algebraic queries");
        for (slot, query) in queries.into_iter().enumerate() {
            assert_eq!(
                selected_opening_linear_combination_v1(openings.row_v1(slot).expect("opening row")),
                lde[query as usize],
                "coset FFT query {query}"
            );
        }
    }
    #[test]
    fn malformed_domains_descriptors_queries_and_registrations_fail_closed() {
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(0, 25, F(7)),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        assert_eq!(
            ZkX509FixedAlgebraicDomainV1::new_v1(19, 25, F::ZERO),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidDomain)
        );
        let mut changed_digest = schedule_v1().descriptor_digest_v1();
        let mut changed_words = changed_digest.to_bytes();
        changed_words[0] ^= 1;
        changed_digest = PrivacyOuterDigestV1::from_bytes(changed_words);
        assert_eq!(
            schedule_v1().verify_descriptor_digest_v1(&changed_digest),
            Err(ZkX509FixedAlgebraicErrorV1::DescriptorMismatch)
        );
        assert_eq!(
            schedule_v1().evaluate_query_indices_v1(&[7, 7]),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        assert_eq!(
            schedule_v1().evaluate_query_indices_v1(&[1_u64 << ZK_X509_MAIN_COMMON_LDE_LOG2_V1]),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let mut short_native = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 - 1];
        assert_eq!(
            schedule_v1().native_row_v1(0, &mut short_native),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let mut native = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1];
        assert_eq!(
            schedule_v1().native_row_v1(1_u64 << 19, &mut native),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let unsupported = P256MainRegistrationV1::new_v1(0, P256MainAdapterV1::WindowBatch, 0)
            .expect("valid non-log19 registration");
        assert_eq!(
            zk_x509_p256_fixed_algebraic_schedule_for_registration_v1(unsupported),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        let short = [F::ZERO; ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 - 1];
        assert_eq!(
            zk_x509_p256_fixed_algebraic_row_for_registration_v1(&short, unsupported),
            Err(ZkX509P256FixedAlgebraicErrorV1::Topology)
        );
        for signature in 0..P256_X5S1_SIGNATURES_V1 {
            for (adapter, locals) in [
                (P256MainAdapterV1::ValueBus, 2),
                (P256MainAdapterV1::Arithmetic, 1),
                (P256MainAdapterV1::WindowBatch, 1),
                (P256MainAdapterV1::Reduction, 2),
                (P256MainAdapterV1::WalletLowS, 1),
                (P256MainAdapterV1::BindingSink, 1),
                (P256MainAdapterV1::ScalarBitBus, 1),
            ] {
                for local in 0..locals {
                    let Ok(registration) =
                        P256MainRegistrationV1::new_v1(signature, adapter, local)
                    else {
                        continue;
                    };
                    let accepted = matches!(
                        (adapter, local),
                        (P256MainAdapterV1::ValueBus, 0 | 1) | (P256MainAdapterV1::Arithmetic, 0)
                    );
                    assert_eq!(
                        zk_x509_p256_fixed_algebraic_schedule_for_registration_v1(registration)
                            .is_ok(),
                        accepted,
                        "signature {signature}, adapter {adapter:?}, local {local}"
                    );
                }
            }
        }
    }
    #[test]
    fn kernel_resource_and_canonicality_limits_fail_closed() {
        assert!(
            schedule_v1()
                .children_v1()
                .iter()
                .all(|child| child.atoms_v1().len() <= ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1)
        );
        let too_many_queries: Vec<u64> =
            (0..=ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1 as u64).collect();
        assert_eq!(
            schedule_v1().evaluate_query_indices_v1(&too_many_queries),
            Err(ZkX509FixedAlgebraicErrorV1::InvalidQuery)
        );
        let domain = schedule_v1().domain_v1();
        let duplicate = ZkX509FixedAlgebraicAtomV1::sparse_v1(0, 0, F::ONE).expect("valid atom");
        assert_eq!(
            ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 1, vec![duplicate, duplicate]),
            Err(ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule)
        );
        let over_limit = vec![duplicate; ZK_X509_FIXED_ALGEBRAIC_MAX_ATOMS_V1 + 1];
        assert_eq!(
            ZkX509FixedAlgebraicScheduleV1::new_v1(domain, 1, over_limit),
            Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded)
        );
        let stress_domain =
            ZkX509FixedAlgebraicDomainV1::new_v1(20, 21, F(GOLDILOCKS_GENERATOR_V1))
                .expect("bounded stress domain");
        let native_size = 1_u64 << 20;
        let mut high_work = Vec::new();
        high_work
            .try_reserve_exact(1_024)
            .expect("small test allocation");
        for stride in 2..=1_025_u64 {
            high_work.push(
                ZkX509FixedAlgebraicAtomV1::repeated_v1(
                    0,
                    0,
                    (native_size - 1) / stride + 1,
                    stride,
                    F(stride),
                )
                .expect("bounded adversarial repeated atom"),
            );
        }
        let high_work = ZkX509FixedAlgebraicScheduleV1::new_v1(stress_domain, 1, high_work)
            .expect("canonical adversarial schedule");
        let maximum_queries: Vec<u64> =
            (0..ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1 as u64).collect();
        assert_eq!(
            high_work.evaluate_query_indices_v1(&maximum_queries),
            Err(ZkX509FixedAlgebraicErrorV1::LimitExceeded)
        );
    }
    #[test]
    #[ignore = "release diagnostic: exhaustive full-domain differential, one column at a time"]
    fn every_native_cell_matches_without_materializing_a_width_404_matrix() {
        let rows = P256_ARITHMETIC_AGGREGATE_TRACE_SIZE_V1;
        for global_column in 0..ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1 {
            let (kind, local_column) = kind_for_global_column_v1(global_column);
            let registration = kind
                .representative_registration_v1()
                .expect("representative registration");
            let mut expected = vec![F::ZERO; rows];
            native_source_v1()
                .fill_fixed_column_v1(registration, local_column, &mut expected)
                .expect("closed native column");
            let mut actual = vec![F::ZERO; rows];
            for atom in schedule_v1().atoms_v1().iter().copied() {
                match atom {
                    ZkX509FixedAlgebraicAtomV1::Affine {
                        column,
                        start,
                        end,
                        start_value,
                        step,
                    } if usize::from(column) == global_column => {
                        for row in start..end {
                            actual[row as usize] =
                                actual[row as usize].add(start_value.add(step.mul(F(row - start))));
                        }
                    }
                    ZkX509FixedAlgebraicAtomV1::Repeated {
                        column,
                        first,
                        count,
                        stride,
                        start_value,
                        step,
                    } if usize::from(column) == global_column => {
                        for occurrence in 0..count {
                            let row = first + occurrence * stride;
                            actual[row as usize] =
                                actual[row as usize].add(start_value.add(step.mul(F(occurrence))));
                        }
                    }
                    ZkX509FixedAlgebraicAtomV1::Sparse { column, row, value }
                        if usize::from(column) == global_column =>
                    {
                        actual[row as usize] = actual[row as usize].add(value);
                    }
                    _ => {}
                }
            }
            assert_eq!(actual, expected, "global fixed column {global_column}");
        }
    }
}

#[cfg(test)]
mod extension_wrapper_tests {
    use super::*;
    use crate::privacy_engines::transparent_stark::{
        goldilocks_ifft_v1, goldilocks_primitive_root_v1,
    };

    #[test]
    fn extension_wrapper_preserves_all_child_columns_and_rejects_native_points() {
        // A small arithmetic fixture exercises the private forwarding owner;
        // the production constructor still accepts only its closed full schedule.
        let widths = P256_FIXED_ALGEBRAIC_CHILD_WIDTHS_V1;
        let domain =
            ZkX509FixedAlgebraicDomainV1::new_v1(3, 6, F(GOLDILOCKS_GENERATOR_V1)).unwrap();
        let children = core::array::from_fn(|child| {
            let mut builder = ZkX509FixedAlgebraicScheduleBuilderV1::new_v1(
                domain,
                u16::try_from(widths[child]).unwrap(),
            )
            .unwrap();
            builder
                .push_atom_v1(ZkX509FixedAlgebraicAtomV1::Sparse {
                    column: 0,
                    row: child as u64,
                    value: F(7 + child as u64),
                })
                .unwrap();
            builder
                .push_atom_v1(ZkX509FixedAlgebraicAtomV1::Sparse {
                    column: u16::try_from(widths[child] - 1).unwrap(),
                    row: 7,
                    value: F(19 + child as u64),
                })
                .unwrap();
            builder.finish_v1().unwrap()
        });
        let schedule = ZkX509P256FixedAlgebraicScheduleV1 {
            children,
            descriptor_digest: PrivacyOuterDigestV1::default(),
        };
        let point = E::canonical([2, 3, 5, 7]).unwrap();
        let actual = schedule.evaluate_extension_point_v1(point).unwrap();
        assert_eq!(actual.len(), ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1);
        let root = goldilocks_primitive_root_v1(3).unwrap();
        let mut offset = 0;
        for (child, &width) in widths.iter().enumerate() {
            for column in 0..width {
                let mut coefficients = vec![F::ZERO; 8];
                if column == 0 {
                    coefficients[child] = F(7 + child as u64);
                }
                if column + 1 == width {
                    coefficients[7] = F(19 + child as u64);
                }
                goldilocks_ifft_v1(&mut coefficients, root).unwrap();
                let expected = coefficients.iter().rev().fold(E::ZERO, |sum, &value| {
                    sum.mul(point).add(E::from_base(value))
                });
                assert_eq!(actual[offset + column], expected);
            }
            offset += width;
        }
        assert_eq!(offset, actual.len());
        assert!(schedule.evaluate_extension_point_v1(E::ONE).is_err());
    }
}
