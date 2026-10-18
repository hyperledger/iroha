//! Deterministic pointwise bindings for the complete P-256 ECDSA witness.
//!
//! The window, reduction, low-s, and value-bus chips commit the same 16-bit values in different
//! traces. This module fixes every cross-chip address and constrains the two committed cells to be
//! equal. Three consecutive equalities are packed into one physical row; the final row is completed
//! by verifier-fixed zero padding.
//!
//! The first-release compiler topology is intentionally exact. All 850 initial value IDs, 457
//! verifier-owned constants, 393 input owners, 14,828 arithmetic result IDs, window table IDs, and
//! inverse relations are regenerated here. Constants are derived from protocol constants and the
//! fixed generator table, never from proof-supplied metadata. Typed public-key, signature, and
//! digest endpoints name the remaining external byte-source obligation exposed through
//! [`P256UnresolvedByteIoManifestV1`].
//! TODO: join the real input tuple to the certificate/RFC/SHA/IO byte owners in the
//! verifier relation; selected-to-arithmetic binding alone does not discharge that obligation.
//!
//! The aggregate zk-X509 STARK commits every source trace before evaluating
//! these equalities; this AIR has no standalone activation path.
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_trace::{P256EcdsaTraceMaterialV1, P256ReductionSourceV1};
use super::{
    p256_air::ZkX509P256ModulusV1,
    p256_ecdsa_air::{P256EcdsaRoleV1, P256EcdsaWitnessV1},
    p256_group_air::{P256_CURVE_B_BE_V1, P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1},
    p256_reduction_air::P256_REDUCTION_ROWS_V1,
    p256_value_bus::{P256_VALUE_BUS_LIMBS_V1, P256ValueIdV1},
    p256_window_air::{
        P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1, P256WindowCoordinateV1, P256WindowScalarV1,
    },
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    p256_air::{P256_BASE_MODULUS_BE_V1, P256_SCALAR_MODULUS_BE_V1, ZkX509P256ArithmeticKindV1},
    p256_reduction_air::{p256_low_s_limb_cell_v1, p256_reduction_limb_cells_v1},
    p256_value_bus::{
        P256EqualityBindingV1, P256InitialValueKindV1, P256ValueBusBaseEndpointTraceV1,
        P256ValueBusBaseSourceV1, P256ValueBusErrorV1, P256ValueKindV1,
        p256_value_bus_base_writer_limb_cell_v1,
    },
    p256_window_air::{
        P256_WINDOW_ROWS_V1, P256WindowExternalAddressV1, p256_window_external_address_v1,
        p256_window_external_limb_v1,
    },
};
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use p256::{ProjectivePoint, Scalar, elliptic_curve::sec1::ToEncodedPoint as _};
use thiserror::Error;
/// Pointwise equalities packed into one physical row.
pub const P256_EXTERNAL_BINDINGS_PER_ROW_V1: usize = 3;
/// Canonical initial values emitted by the one-signature compiler.
pub const P256_EXTERNAL_INITIAL_VALUES_V1: usize = 850;
/// Verifier-owned constant initial values.
pub const P256_EXTERNAL_CONSTANT_INITIAL_VALUES_V1: usize = 457;
/// Input initial values with an explicit external or auxiliary owner.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const P256_EXTERNAL_INPUT_INITIAL_VALUES_V1: usize = 393;
/// Window candidate limbs bound across all 128 selectors.
pub const P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1: usize =
    128 * 16 * 3 * P256_VALUE_BUS_LIMBS_V1;
/// Selected-output limbs bound across all 128 selectors.
pub const P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1: usize = 128 * 3 * P256_VALUE_BUS_LIMBS_V1;
/// Both reduced scalar outputs.
pub const P256_EXTERNAL_REDUCTION_OUTPUT_BINDINGS_V1: usize = 2 * P256_REDUCTION_ROWS_V1;
/// Base-coordinate source of the result-x reduction.
pub const P256_EXTERNAL_RESULT_X_SOURCE_BINDINGS_V1: usize = P256_REDUCTION_ROWS_V1;
/// Wallet-only low-s scalar bindings.
pub const P256_EXTERNAL_LOW_S_BINDINGS_V1: usize = P256_REDUCTION_ROWS_V1;
/// All fixed constant writer limbs.
pub const P256_EXTERNAL_CONSTANT_BINDINGS_V1: usize =
    P256_EXTERNAL_CONSTANT_INITIAL_VALUES_V1 * P256_VALUE_BUS_LIMBS_V1;
const P256_EXTERNAL_BASE_BINDINGS_V1: usize = P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1
    + P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1
    + P256_EXTERNAL_REDUCTION_OUTPUT_BINDINGS_V1
    + P256_EXTERNAL_RESULT_X_SOURCE_BINDINGS_V1
    + P256_EXTERNAL_CONSTANT_BINDINGS_V1;
const P256_EXTERNAL_CERTIFICATE_BINDINGS_V1: usize = P256_EXTERNAL_BASE_BINDINGS_V1;
const P256_EXTERNAL_WALLET_BINDINGS_V1: usize =
    P256_EXTERNAL_BASE_BINDINGS_V1 + P256_EXTERNAL_LOW_S_BINDINGS_V1;
const P256_EXTERNAL_CERTIFICATE_DYNAMIC_SOURCES_V1: usize =
    P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1
        + P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1
        + P256_EXTERNAL_REDUCTION_OUTPUT_BINDINGS_V1
        + P256_EXTERNAL_RESULT_X_SOURCE_BINDINGS_V1;
const P256_EXTERNAL_WALLET_DYNAMIC_SOURCES_V1: usize =
    P256_EXTERNAL_CERTIFICATE_DYNAMIC_SOURCES_V1 + P256_EXTERNAL_LOW_S_BINDINGS_V1;
const P256_EXTERNAL_CERTIFICATE_ROWS_V1: usize =
    P256_EXTERNAL_CERTIFICATE_BINDINGS_V1.div_ceil(P256_EXTERNAL_BINDINGS_PER_ROW_V1);
const P256_EXTERNAL_WALLET_ROWS_V1: usize =
    P256_EXTERNAL_WALLET_BINDINGS_V1.div_ceil(P256_EXTERNAL_BINDINGS_PER_ROW_V1);
const P256_EXTERNAL_ARITHMETIC_OPERATIONS_V1: usize = P256_TWO_SCALAR_ARITHMETIC_OPERATIONS_V1 + 18;
/// Bytes in the canonical `(Qx,Qy,r,s,digest)` tuple.
pub const P256_INPUT_SELECTION_BYTES_V1: usize = 5 * 32;
/// Verifier-fixed byte region, disjoint from all existing external equality rows.
pub const P256_INPUT_SELECTION_ROW_START_V1: usize = 40_960;
/// One row after the byte region: the private activity selector is constrained here.
pub const P256_INPUT_SELECTION_SELECTOR_ROW_V1: usize =
    P256_INPUT_SELECTION_ROW_START_V1 + P256_INPUT_SELECTION_BYTES_V1;
const _: () = assert!(P256_EXTERNAL_WALLET_ROWS_V1 < P256_INPUT_SELECTION_ROW_START_V1);
const _: () = assert!(P256_INPUT_SELECTION_SELECTOR_ROW_V1 < 1 << 16);

/// Compiler-owned value writer for each selected coordinate; digest uses the reduction WORD.
pub fn p256_selected_input_writer_id_v1(
    word: usize,
) -> Result<Option<P256ValueIdV1>, P256ExternalBindingErrorV1> {
    match word {
        0 => Ok(Some(P256ValueIdV1(PUBLIC_KEY_X_ID_V1))),
        1 => Ok(Some(P256ValueIdV1(PUBLIC_KEY_Y_ID_V1))),
        2 => Ok(Some(P256ValueIdV1(SIGNATURE_R_ID_V1))),
        3 => Ok(Some(P256ValueIdV1(SIGNATURE_S_ID_V1))),
        4 => Ok(None),
        _ => Err(P256ExternalBindingErrorV1::Topology),
    }
}

/// Canonical big-endian byte coordinate used by both native providers and fixed preprocessing.
pub fn p256_input_selection_byte_v1(
    witness: &P256EcdsaWitnessV1,
    byte: usize,
) -> Result<u8, P256ExternalBindingErrorV1> {
    let word = byte / 32;
    let offset = byte % 32;
    match word {
        0 => Ok(witness.public_key_x_be[offset]),
        1 => Ok(witness.public_key_y_be[offset]),
        2 => Ok(witness.r_be[offset]),
        3 => Ok(witness.s_be[offset]),
        4 => Ok(witness.digest_be[offset]),
        _ => Err(P256ExternalBindingErrorV1::Topology),
    }
}

const VARIABLE_TABLE_OPERATION_START_V1: usize = 15;
const COMPLETE_ADD_OPERATIONS_V1: usize = 43;
const COMPLETE_ADD_OUTPUT_OFFSETS_V1: [usize; 3] = [36, 39, 42];
const VARIABLE_TABLE_ADDITIONS_V1: usize = 14;
const VARIABLE_TABLE_OPERATIONS_V1: usize =
    VARIABLE_TABLE_ADDITIONS_V1 * COMPLETE_ADD_OPERATIONS_V1;
const SCALAR_ROUND_OPERATION_START_V1: usize =
    VARIABLE_TABLE_OPERATION_START_V1 + VARIABLE_TABLE_OPERATIONS_V1;
const SCALAR_ROUND_OPERATIONS_V1: usize = 4 * 34 + 2 * COMPLETE_ADD_OPERATIONS_V1;
const NORMALIZATION_OPERATION_START_V1: usize =
    SCALAR_ROUND_OPERATION_START_V1 + 64 * SCALAR_ROUND_OPERATIONS_V1;
const GENERATOR_CONSTANTS_END_V1: usize = 47;
const PUBLIC_KEY_X_ID_V1: u32 = 47;
const PUBLIC_KEY_Y_ID_V1: u32 = 48;
const PUBLIC_KEY_Z_ID_V1: u32 = 49;
const SIGNATURE_R_ID_V1: u32 = 52;
const SIGNATURE_S_ID_V1: u32 = 53;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const R_INVERSE_ID_V1: u32 = 54;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const R_INVERSE_ONE_ID_V1: u32 = 55;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const S_INVERSE_ID_V1: u32 = 56;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const S_INVERSE_ONE_ID_V1: u32 = 57;
const DIGEST_REDUCTION_OUTPUT_ID_V1: u32 = 58;
const VARIABLE_IDENTITY_X_ID_V1: u32 = 59;
const VARIABLE_IDENTITY_Y_ID_V1: u32 = 60;
const VARIABLE_IDENTITY_Z_ID_V1: u32 = 61;
const WINDOW_INITIAL_START_V1: usize = 79;
const WINDOW_INITIAL_STRIDE_V1: usize = 12;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const RESULT_Z_INVERSE_ID_V1: u32 = 847;
#[cfg(any(test, feature = "privacy-release-evidence"))]
const RESULT_Z_INVERSE_ONE_ID_V1: u32 = 848;
const RESULT_X_REDUCTION_OUTPUT_ID_V1: u32 = 849;
const ZERO_BE_V1: [u8; 32] = [0; 32];
const ONE_BE_V1: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const THREE_BE_V1: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
];
/// Domain pinning the public dummy used by the optional third certificate.
///
/// The tuple itself is deliberately independent of private witness material: it uses the standard
/// P-256 generator as the public key and the valid `(d, k) = (1, 1)` signature of SHA-256(empty).
/// It is selected only when the RFC adapter's certificate-slot selector is zero.
#[cfg(test)]
pub const ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DOMAIN_V1: &[u8] =
    b"iroha.zk-x509.p256.optional-certificate-dummy.v1";
/// SHA-256(empty), which is also the canonical inactive SHA-call digest.
pub const ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];
/// Verifier-owned valid P-256 tuple used by the inactive optional slot.
pub const ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1: P256EcdsaWitnessV1 = P256EcdsaWitnessV1 {
    // Standard P-256 generator.
    public_key_x_be: [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ],
    public_key_y_be: [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ],
    // r = x(G), because the public nonce is k = 1.
    r_be: [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ],
    // s = SHA256(empty) + r mod n for the public key d = 1.
    s_be: [
        0x4e, 0xc8, 0x96, 0x36, 0x7a, 0x28, 0x5e, 0x5b, 0x93, 0xb8, 0xdb, 0xad, 0xfd, 0x13, 0xfa,
        0x16, 0xe1, 0xca, 0xc4, 0xb7, 0xeb, 0x6f, 0x28, 0x68, 0xa5, 0x7d, 0x07, 0x9e, 0x54, 0x88,
        0x55, 0x9a,
    ],
    digest_be: ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
};
const _: () = assert!(P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1 == 98_304);
const _: () = assert!(P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1 == 6_144);
const _: () = assert!(P256_EXTERNAL_CERTIFICATE_BINDINGS_V1 == 111_808);
const _: () = assert!(P256_EXTERNAL_WALLET_BINDINGS_V1 == 111_824);
const _: () = assert!(P256_EXTERNAL_CERTIFICATE_DYNAMIC_SOURCES_V1 == 104_496);
const _: () = assert!(P256_EXTERNAL_WALLET_DYNAMIC_SOURCES_V1 == 104_512);
const _: () = assert!(P256_EXTERNAL_CERTIFICATE_ROWS_V1 == 37_270);
const _: () = assert!(P256_EXTERNAL_WALLET_ROWS_V1 == 37_275);
const _: () = assert!(
    P256_EXTERNAL_CERTIFICATE_ROWS_V1 * P256_EXTERNAL_BINDINGS_PER_ROW_V1
        - P256_EXTERNAL_CERTIFICATE_BINDINGS_V1
        == 2
);
const _: () = assert!(
    P256_EXTERNAL_WALLET_ROWS_V1 * P256_EXTERNAL_BINDINGS_PER_ROW_V1
        - P256_EXTERNAL_WALLET_BINDINGS_V1
        == 1
);
const _: () = assert!(NORMALIZATION_OPERATION_START_V1 + 3 == 14_828);
const _: () = assert!(P256_EXTERNAL_ARITHMETIC_OPERATIONS_V1 == 14_828);
/// Which one-subtraction reduction owns an external binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ExternalReductionV1 {
    /// SHA-256 digest reduced modulo the scalar order.
    Digest,
    /// Normalized result x-coordinate reduced modulo the scalar order.
    ResultX,
}
/// Typed byte word that remains for the cross-chip byte-I/O adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256UnresolvedByteIoKindV1 {
    /// Affine public-key x-coordinate.
    PublicKeyX,
    /// Affine public-key y-coordinate.
    PublicKeyY,
    /// Strict-DER signature scalar r.
    SignatureR,
    /// Strict-DER signature scalar s.
    SignatureS,
    /// Exact SHA-256/prehash word before scalar reduction.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    DigestWord,
}
/// Committed source of one unresolved byte word.
///
/// Keeping the larger writer payload inline preserves a `Copy`, allocation- free sum type and
/// excludes the invalid field combinations that a flattened struct would admit.
#[allow(
    variant_size_differences,
    reason = "boxing a tiny verifier manifest would add allocation and lose Copy semantics"
)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256UnresolvedByteIoSourceV1 {
    /// One canonical value-bus writer.
    ValueWriter {
        /// Fixed SSA value ID.
        id: P256ValueIdV1,
        /// Base or scalar modulus of the encoded word.
        modulus: ZkX509P256ModulusV1,
    },
    /// Input-word cells of one fixed reduction trace.
    ReductionWord {
        /// Digest or result-x reduction.
        reduction: P256ExternalReductionV1,
    },
}
/// One typed byte-I/O endpoint that is intentionally unresolved here.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256UnresolvedByteIoEndpointV1 {
    /// Semantic byte word.
    pub(crate) kind: P256UnresolvedByteIoKindV1,
    /// Already-committed source that a byte adapter must consume.
    pub(crate) source: P256UnresolvedByteIoSourceV1,
}
/// Exact Qx, Qy, r, s, and digest manifest in verifier-fixed order.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256UnresolvedByteIoManifestV1 {
    /// Five unresolved endpoints in the order documented above.
    pub(crate) endpoints: [P256UnresolvedByteIoEndpointV1; 5],
}
/// The only three input writers that are internal inverse witnesses.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256InverseAuxiliaryManifestV1 {
    /// Inverse used to prove r is nonzero.
    pub(crate) r_inverse: P256ValueIdV1,
    /// Inverse used to prove s is nonzero.
    pub(crate) s_inverse: P256ValueIdV1,
    /// Inverse used to normalize the nonidentity result point.
    pub(crate) result_z_inverse: P256ValueIdV1,
}
/// Verifier-regenerated identity for one packed equality slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ExternalBindingFixedAccessV1 {
    /// Canonical zero padding.
    Inactive,
    /// One table-candidate coordinate limb.
    WindowCandidate {
        /// U1 or U2 selector family.
        scalar: P256WindowScalarV1,
        /// Big-endian nibble index.
        window: u8,
        /// Candidate table index.
        candidate: u8,
        /// Projective coordinate.
        coordinate: P256WindowCoordinateV1,
        /// Little-endian 16-bit limb.
        limb: u8,
    },
    /// One selected-output coordinate limb.
    WindowOutput {
        /// U1 or U2 selector family.
        scalar: P256WindowScalarV1,
        /// Big-endian nibble index.
        window: u8,
        /// Projective coordinate.
        coordinate: P256WindowCoordinateV1,
        /// Little-endian 16-bit limb.
        limb: u8,
    },
    /// One reduced scalar output limb.
    ReductionOutput {
        /// Digest or result-x reduction.
        reduction: P256ExternalReductionV1,
        /// Little-endian 16-bit limb.
        limb: u8,
    },
    /// One unreduced result-x source limb.
    ResultXReductionSource {
        /// Little-endian 16-bit limb.
        limb: u8,
    },
    /// One wallet-only low-s scalar limb.
    LowS {
        /// Little-endian 16-bit limb.
        limb: u8,
    },
    /// One verifier-owned constant writer limb.
    Constant {
        /// Fixed initial value ID.
        id: P256ValueIdV1,
        /// Little-endian 16-bit limb.
        limb: u8,
    },
}
/// Verifier-owned external endpoint paired with one binding slot.
///
/// Dynamic endpoints must participate in the cross-trace product. Constant endpoints are instead
/// constrained directly in the sink AIR against the compiler-owned value carried here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256ExternalBindingCrossExternalSourceV1 {
    /// One unique window, reduction, result-x, or low-s source cell.
    Dynamic {
        /// Contiguous verifier-owned address in the role-specific dynamic external-source schedule.
        address: u32,
    },
    /// One compiler-owned constant limb.
    Constant {
        /// Exact expected 16-bit limb, never copied from proof metadata.
        value: F,
    },
}
/// Exact writer and external source identities for one active binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ExternalBindingCrossSourceV1 {
    /// Verifier-regenerated logical binding address.
    pub(crate) fixed: P256ExternalBindingFixedAccessV1,
    /// Canonical SSA writer ID.
    pub(crate) writer_id: P256ValueIdV1,
    /// Little-endian writer limb.
    pub(crate) writer_limb: u8,
    /// Dynamic cross-trace endpoint or direct fixed constant.
    pub(crate) external: P256ExternalBindingCrossExternalSourceV1,
}
/// Three deterministic pointwise equalities.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ExternalBindingRowV1 {
    /// Verifier-regenerated addresses.
    pub(crate) fixed: [P256ExternalBindingFixedAccessV1; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    /// Copies of unique value-bus writer cells.
    pub(crate) writer_cells: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    /// Copies of window/reduction/low-s/fixed-constant cells.
    pub(crate) external_cells: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
}
/// Complete deterministic binding trace and its two ownership manifests.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub struct P256ExternalBindingTraceV1 {
    /// Verifier-fixed ECDSA role.
    pub(crate) role: P256EcdsaRoleV1,
    /// Exactly 37,275 wallet rows or 37,270 certificate rows.
    pub(crate) rows: Vec<P256ExternalBindingRowV1>,
    /// Qx, Qy, r, s, and digest endpoints bound by the MAIN byte-I/O adapter.
    pub(crate) byte_io: P256UnresolvedByteIoManifestV1,
    /// Complete committed byte selection feeding the fixed P-256 instance.
    pub(crate) input_selection: P256OptionalCertificateSelectionV1,
    /// Exactly the r, s, and result-z inverse inputs.
    pub(crate) inverse_auxiliaries: P256InverseAuxiliaryManifestV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256ExternalBindingTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256ExternalBindingTraceV1")
            .field("role", &self.role)
            .field("private_material", &"<redacted>")
            .finish()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_external_binding_rows_v1(rows: &mut [P256ExternalBindingRowV1]) {
    for row in rows {
        super::private_table::zeroize_fields_v1(&mut row.writer_cells);
        super::private_table::zeroize_fields_v1(&mut row.external_cells);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ExternalBindingTraceV1 {
    /// Recursively overwrite every private source and copied witness cell.
    ///
    /// Fixed addresses and ownership manifests are public topology, but the row allocation is
    /// cleared as well so no stale cells remain reachable after an error path or ordinary drop.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_external_binding_rows_v1(&mut self.rows);
        self.rows.clear();
        super::private_table::zeroize_fields_v1(core::slice::from_mut(
            &mut self.input_selection.active,
        ));
        self.input_selection.real.zeroize_private_v1();
        self.input_selection.selected.zeroize_private_v1();
    }
    #[cfg(test)]
    fn private_is_zeroized_v1(&self) -> bool {
        self.rows.is_empty()
            && self.input_selection.active == F::ZERO
            && self.input_selection.real.private_is_zeroized_v1()
            && self.input_selection.selected.private_is_zeroized_v1()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for P256ExternalBindingTraceV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
/// External-binding topology, ownership, source, or equality failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum P256ExternalBindingErrorV1 {
    /// Fixed IDs, roles, windows, reductions, or row ordering differ.
    #[error("zk-X509 P-256 external-binding topology is invalid")]
    Topology,
    /// Initial inputs are missing, duplicated, aliased, or unowned.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding ownership is invalid")]
    Ownership,
    /// A verifier-owned constant or its fixed writer is wrong.
    #[error("zk-X509 P-256 external-binding constant is invalid")]
    Constant,
    /// A value-bus execution writer address or copied cell is wrong.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding writer source is invalid")]
    WriterSource,
    /// A window, reduction, low-s, or copied external cell is wrong.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding external source is invalid")]
    ExternalSource,
    /// Two pointwise source cells are unequal.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding equality is invalid")]
    Equality,
    /// A field or limb encoding is noncanonical.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding range is invalid")]
    Range,
    /// Inactive slots or the final padding count are noncanonical.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding padding is invalid")]
    Padding,
    /// A low-degree row residue is nonzero.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 external-binding row constraint failed")]
    Constraint,
    /// The optional-certificate selector or canonical inactive source is invalid.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 P-256 optional-certificate selection is invalid")]
    OptionalCertificateSelection,
    /// Length or index arithmetic exceeded the fixed envelope.
    #[error("zk-X509 P-256 external-binding resource bound is exceeded")]
    Resource,
}
/// Algebraic input selection for the privately optional certificate slot.
///
/// `real` is always the exact RFC/SHA source tuple.  For an inactive slot its
/// Qx, Qy, r, and s words must be zero while its digest is SHA-256(empty).
/// `selected` is the tuple compiled by the ordinary, ungated P-256 chip.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P256OptionalCertificateSelectionV1 {
    /// RFC-derived Boolean selector: zero for depth two, one for depth three.
    pub(crate) active: F,
    /// Exact tuple emitted by RFC/SHA byte I/O before dummy selection.
    pub(crate) real: P256EcdsaWitnessV1,
    /// Exact tuple consumed by the fixed P-256 certificate instance.
    pub(crate) selected: P256EcdsaWitnessV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for P256OptionalCertificateSelectionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("P256OptionalCertificateSelectionV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256OptionalCertificateSelectionV1 {
    /// Evaluate the complete low-degree selector relation.
    ///
    /// The first residue constrains `active` to Boolean.  The following 160
    /// residues constrain every selected byte.  The final 160 residues pin
    /// the complete inactive real source to `(0, 0, 0, 0, SHA256(empty))`.
    pub(crate) fn constraint_residues_v1(self) -> [F; 321] {
        let active = self.active;
        let inactive = F::ONE.sub(active);
        let real_words = [
            self.real.public_key_x_be,
            self.real.public_key_y_be,
            self.real.r_be,
            self.real.s_be,
            self.real.digest_be,
        ];
        let selected_words = [
            self.selected.public_key_x_be,
            self.selected.public_key_y_be,
            self.selected.r_be,
            self.selected.s_be,
            self.selected.digest_be,
        ];
        let dummy_words = [
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1.public_key_x_be,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1.public_key_y_be,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1.r_be,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1.s_be,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1.digest_be,
        ];
        let mut residues = [F::ZERO; 321];
        residues[0] = active.mul(active.sub(F::ONE));
        for word in 0..5 {
            for byte in 0..32 {
                let index = word * 32 + byte;
                let real = F(u64::from(real_words[word][byte]));
                let selected = F(u64::from(selected_words[word][byte]));
                let dummy = F(u64::from(dummy_words[word][byte]));
                residues[1 + index] = selected.sub(active.mul(real).add(inactive.mul(dummy)));
                let inactive_real = if word == 4 { real.sub(dummy) } else { real };
                residues[161 + index] = inactive.mul(inactive_real);
            }
        }
        residues
    }
    /// Re-evaluate all selector constraints.
    pub(crate) fn validate_v1(self) -> Result<(), P256ExternalBindingErrorV1> {
        if self
            .constraint_residues_v1()
            .into_iter()
            .any(|residue| residue != F::ZERO)
        {
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        } else {
            Ok(())
        }
    }
}
/// Select the exact tuple consumed by the fixed optional P-256 instance.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn select_zk_x509_optional_certificate_p256_witness_v1(
    active: u8,
    real: P256EcdsaWitnessV1,
) -> Result<P256OptionalCertificateSelectionV1, P256ExternalBindingErrorV1> {
    let selected = match active {
        0 => ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1,
        1 => real,
        _ => return Err(P256ExternalBindingErrorV1::OptionalCertificateSelection),
    };
    let selection = P256OptionalCertificateSelectionV1 {
        active: F(u64::from(active)),
        real,
        selected,
    };
    selection.validate_v1()?;
    Ok(selection)
}
/// Number of active equalities for one verifier-fixed role.
pub const fn p256_external_binding_active_equalities_v1(role: P256EcdsaRoleV1) -> usize {
    match role {
        P256EcdsaRoleV1::CertificateOrCrl => P256_EXTERNAL_CERTIFICATE_BINDINGS_V1,
        P256EcdsaRoleV1::WalletOwnership => P256_EXTERNAL_WALLET_BINDINGS_V1,
    }
}
/// Number of three-equality physical rows for one verifier-fixed role.
pub const fn p256_external_binding_rows_v1(role: P256EcdsaRoleV1) -> usize {
    match role {
        P256EcdsaRoleV1::CertificateOrCrl => P256_EXTERNAL_CERTIFICATE_ROWS_V1,
        P256EcdsaRoleV1::WalletOwnership => P256_EXTERNAL_WALLET_ROWS_V1,
    }
}
/// Number of nonconstant external cells that enter the cross-trace product.
pub const fn p256_external_binding_dynamic_sources_v1(role: P256EcdsaRoleV1) -> usize {
    match role {
        P256EcdsaRoleV1::CertificateOrCrl => P256_EXTERNAL_CERTIFICATE_DYNAMIC_SOURCES_V1,
        P256EcdsaRoleV1::WalletOwnership => P256_EXTERNAL_WALLET_DYNAMIC_SOURCES_V1,
    }
}
/// Compile the sole verifier-owned cross-source schedule for one role.
///
/// The result has exactly three slots per physical binding row, including canonical `None` padding.
/// It depends only on the first-release topology and fixed P-256 constants; no witness, value-bus
/// row, or proof metadata is consulted.
pub fn compile_zk_x509_p256_external_cross_sources_v1(
    role: P256EcdsaRoleV1,
) -> Result<
    Vec<[Option<P256ExternalBindingCrossSourceV1>; P256_EXTERNAL_BINDINGS_PER_ROW_V1]>,
    P256ExternalBindingErrorV1,
> {
    let active = p256_external_binding_active_equalities_v1(role);
    let total = p256_external_binding_rows_v1(role)
        .checked_mul(P256_EXTERNAL_BINDINGS_PER_ROW_V1)
        .ok_or(P256ExternalBindingErrorV1::Resource)?;
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(total)
        .map_err(|_| P256ExternalBindingErrorV1::Resource)?;
    for (scalar_index, scalar) in [P256WindowScalarV1::U1, P256WindowScalarV1::U2]
        .into_iter()
        .enumerate()
    {
        for window in 0..64 {
            for candidate in 0..16 {
                for chunk in 0..P256_VALUE_BUS_LIMBS_V1 {
                    for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                        let packed = chunk
                            .checked_mul(P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1)
                            .and_then(|value| value.checked_add(slot))
                            .ok_or(P256ExternalBindingErrorV1::Resource)?;
                        let coordinate_index = packed / P256_VALUE_BUS_LIMBS_V1;
                        let limb = packed % P256_VALUE_BUS_LIMBS_V1;
                        let coordinate = coordinate_from_index_v1(coordinate_index)?;
                        let fixed = P256ExternalBindingFixedAccessV1::WindowCandidate {
                            scalar,
                            window: u8::try_from(window)
                                .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                            candidate: u8::try_from(candidate)
                                .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                            coordinate,
                            limb: u8::try_from(limb)
                                .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                        };
                        let address = scalar_index
                            .checked_mul(64 * 16 * 3 * P256_VALUE_BUS_LIMBS_V1)
                            .and_then(|value| {
                                value.checked_add(window * 16 * 3 * P256_VALUE_BUS_LIMBS_V1)
                            })
                            .and_then(|value| {
                                value.checked_add(candidate * 3 * P256_VALUE_BUS_LIMBS_V1)
                            })
                            .and_then(|value| {
                                value.checked_add(coordinate_index * P256_VALUE_BUS_LIMBS_V1 + limb)
                            })
                            .ok_or(P256ExternalBindingErrorV1::Resource)?;
                        sources.push(P256ExternalBindingCrossSourceV1 {
                            fixed,
                            writer_id: expected_window_candidate_id_v1(
                                scalar,
                                candidate,
                                coordinate_index,
                            )?,
                            writer_limb: u8::try_from(limb)
                                .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                            external: P256ExternalBindingCrossExternalSourceV1::Dynamic {
                                address: u32::try_from(address)
                                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                            },
                        });
                    }
                }
            }
            for chunk in 0..P256_VALUE_BUS_LIMBS_V1 {
                for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                    let packed = chunk
                        .checked_mul(P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1)
                        .and_then(|value| value.checked_add(slot))
                        .ok_or(P256ExternalBindingErrorV1::Resource)?;
                    let coordinate_index = packed / P256_VALUE_BUS_LIMBS_V1;
                    let limb = packed % P256_VALUE_BUS_LIMBS_V1;
                    let coordinate = coordinate_from_index_v1(coordinate_index)?;
                    let fixed = P256ExternalBindingFixedAccessV1::WindowOutput {
                        scalar,
                        window: u8::try_from(window)
                            .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                        coordinate,
                        limb: u8::try_from(limb)
                            .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                    };
                    let address = P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1
                        .checked_add(
                            scalar_index
                                .checked_mul(64 * 3 * P256_VALUE_BUS_LIMBS_V1)
                                .ok_or(P256ExternalBindingErrorV1::Resource)?,
                        )
                        .and_then(|value| value.checked_add(window * 3 * P256_VALUE_BUS_LIMBS_V1))
                        .and_then(|value| {
                            value.checked_add(coordinate_index * P256_VALUE_BUS_LIMBS_V1 + limb)
                        })
                        .ok_or(P256ExternalBindingErrorV1::Resource)?;
                    sources.push(P256ExternalBindingCrossSourceV1 {
                        fixed,
                        writer_id: expected_window_output_id_v1(scalar, window, coordinate_index)?,
                        writer_limb: u8::try_from(limb)
                            .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                        external: P256ExternalBindingCrossExternalSourceV1::Dynamic {
                            address: u32::try_from(address)
                                .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                        },
                    });
                }
            }
        }
    }
    let reduction_start =
        P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1 + P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1;
    for (reduction_index, (reduction, writer_id)) in [
        (
            P256ExternalReductionV1::Digest,
            P256ValueIdV1(DIGEST_REDUCTION_OUTPUT_ID_V1),
        ),
        (
            P256ExternalReductionV1::ResultX,
            P256ValueIdV1(RESULT_X_REDUCTION_OUTPUT_ID_V1),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        for limb in 0..P256_REDUCTION_ROWS_V1 {
            let address = reduction_start
                .checked_add(reduction_index * P256_REDUCTION_ROWS_V1 + limb)
                .ok_or(P256ExternalBindingErrorV1::Resource)?;
            sources.push(P256ExternalBindingCrossSourceV1 {
                fixed: P256ExternalBindingFixedAccessV1::ReductionOutput {
                    reduction,
                    limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
                writer_id,
                writer_limb: u8::try_from(limb)
                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                external: P256ExternalBindingCrossExternalSourceV1::Dynamic {
                    address: u32::try_from(address)
                        .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
            });
        }
    }
    let result_x_start = reduction_start + P256_EXTERNAL_REDUCTION_OUTPUT_BINDINGS_V1;
    for limb in 0..P256_REDUCTION_ROWS_V1 {
        let address = result_x_start
            .checked_add(limb)
            .ok_or(P256ExternalBindingErrorV1::Resource)?;
        sources.push(P256ExternalBindingCrossSourceV1 {
            fixed: P256ExternalBindingFixedAccessV1::ResultXReductionSource {
                limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
            },
            writer_id: derived_id_v1(NORMALIZATION_OPERATION_START_V1 + 1)?,
            writer_limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
            external: P256ExternalBindingCrossExternalSourceV1::Dynamic {
                address: u32::try_from(address)
                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
            },
        });
    }
    if role == P256EcdsaRoleV1::WalletOwnership {
        let low_s_start = result_x_start + P256_EXTERNAL_RESULT_X_SOURCE_BINDINGS_V1;
        for limb in 0..P256_REDUCTION_ROWS_V1 {
            let address = low_s_start
                .checked_add(limb)
                .ok_or(P256ExternalBindingErrorV1::Resource)?;
            sources.push(P256ExternalBindingCrossSourceV1 {
                fixed: P256ExternalBindingFixedAccessV1::LowS {
                    limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
                writer_id: P256ValueIdV1(SIGNATURE_S_ID_V1),
                writer_limb: u8::try_from(limb)
                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                external: P256ExternalBindingCrossExternalSourceV1::Dynamic {
                    address: u32::try_from(address)
                        .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
            });
        }
    }
    let topology = expected_initial_topology_v1()?;
    let mut constants = 0_usize;
    for (index, initial) in topology.into_iter().enumerate() {
        let Some(value_be) = initial.constant else {
            continue;
        };
        constants = constants
            .checked_add(1)
            .ok_or(P256ExternalBindingErrorV1::Resource)?;
        let id =
            P256ValueIdV1(u32::try_from(index).map_err(|_| P256ExternalBindingErrorV1::Resource)?);
        for (limb, value) in bytes_be_to_limbs_le_v1(value_be).into_iter().enumerate() {
            sources.push(P256ExternalBindingCrossSourceV1 {
                fixed: P256ExternalBindingFixedAccessV1::Constant {
                    id,
                    limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
                writer_id: id,
                writer_limb: u8::try_from(limb)
                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                external: P256ExternalBindingCrossExternalSourceV1::Constant {
                    value: F(u64::from(value)),
                },
            });
        }
    }
    if constants != P256_EXTERNAL_CONSTANT_INITIAL_VALUES_V1 || sources.len() != active {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    let dynamic = p256_external_binding_dynamic_sources_v1(role);
    let mut seen = vec![false; dynamic];
    let mut dynamic_count = 0_usize;
    for source in &sources {
        if let P256ExternalBindingCrossExternalSourceV1::Dynamic { address } = source.external {
            let address =
                usize::try_from(address).map_err(|_| P256ExternalBindingErrorV1::Resource)?;
            let slot = seen
                .get_mut(address)
                .ok_or(P256ExternalBindingErrorV1::Topology)?;
            if *slot {
                return Err(P256ExternalBindingErrorV1::Topology);
            }
            *slot = true;
            dynamic_count = dynamic_count
                .checked_add(1)
                .ok_or(P256ExternalBindingErrorV1::Resource)?;
        }
    }
    if dynamic_count != dynamic || seen.iter().any(|seen| !*seen) {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    sources.resize_with(total, || P256ExternalBindingCrossSourceV1 {
        fixed: P256ExternalBindingFixedAccessV1::Inactive,
        writer_id: P256ValueIdV1(0),
        writer_limb: 0,
        external: P256ExternalBindingCrossExternalSourceV1::Constant { value: F::ZERO },
    });
    let mut rows = Vec::new();
    rows.try_reserve_exact(p256_external_binding_rows_v1(role))
        .map_err(|_| P256ExternalBindingErrorV1::Resource)?;
    for chunk in sources.chunks_exact(P256_EXTERNAL_BINDINGS_PER_ROW_V1) {
        rows.push(core::array::from_fn(|slot| {
            (chunk[slot].fixed != P256ExternalBindingFixedAccessV1::Inactive).then_some(chunk[slot])
        }));
    }
    Ok(rows)
}
/// Build the complete binding trace from one already validated, challenged-free execution endpoint.
///
/// This narrow constructor remains private so production callers cannot
/// substitute an arbitrary endpoint for the role-bound base material.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_external_binding_from_execution_endpoint_v1(
    material: &P256EcdsaTraceMaterialV1,
    value_bus: &P256ValueBusBaseEndpointTraceV1,
) -> Result<P256ExternalBindingTraceV1, P256ExternalBindingErrorV1> {
    let expected = expected_slots_v1(material, value_bus)?;
    let row_count = p256_external_binding_rows_v1(material.role);
    if expected.len()
        != row_count
            .checked_mul(P256_EXTERNAL_BINDINGS_PER_ROW_V1)
            .ok_or(P256ExternalBindingErrorV1::Resource)?
    {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    let mut rows =
        super::private_table::PrivateTableV1::new(Vec::new(), zeroize_external_binding_rows_v1);
    rows.try_reserve_exact(row_count)
        .map_err(|_| P256ExternalBindingErrorV1::Resource)?;
    for chunk in expected.chunks_exact(P256_EXTERNAL_BINDINGS_PER_ROW_V1) {
        rows.push(P256ExternalBindingRowV1 {
            fixed: core::array::from_fn(|slot| chunk[slot].fixed),
            writer_cells: core::array::from_fn(|slot| chunk[slot].writer),
            external_cells: core::array::from_fn(|slot| chunk[slot].external),
        });
    }
    let topology = validate_material_topology_v1(material)?;
    let selected = p256_byte_io_witness_v1(material, topology.byte_io)?;
    let trace = P256ExternalBindingTraceV1 {
        role: material.role,
        rows: rows.into_vec(),
        byte_io: topology.byte_io,
        input_selection: P256OptionalCertificateSelectionV1 {
            active: F::ONE,
            real: selected,
            selected,
        },
        inverse_auxiliaries: topology.inverse_auxiliaries,
    };
    trace.validate_v1(material, value_bus)?;
    Ok(trace)
}
/// Build the complete external binding from the sole validated value-bus pre-commitment capability.
///
/// The role check happens before projecting the execution endpoint. This is
/// the production constructor used by MAIN; it does not rebuild the value bus
/// and cannot depend on any post-X5B1 product accumulator.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn build_zk_x509_p256_external_binding_trace_v1(
    material: &P256EcdsaTraceMaterialV1,
    value_bus: &P256ValueBusBaseSourceV1,
) -> Result<P256ExternalBindingTraceV1, P256ExternalBindingErrorV1> {
    if value_bus.role_v1().map_err(map_writer_error_v1)? != material.role {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    build_external_binding_from_execution_endpoint_v1(
        material,
        value_bus
            .execution_endpoint_v1()
            .map_err(map_writer_error_v1)?,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl P256ExternalBindingTraceV1 {
    /// Validate exact coverage, ownership, source copies, equality, and padding.
    pub(crate) fn validate_v1(
        &self,
        material: &P256EcdsaTraceMaterialV1,
        value_bus: &P256ValueBusBaseEndpointTraceV1,
    ) -> Result<(), P256ExternalBindingErrorV1> {
        let topology = validate_material_topology_v1(material)?;
        if self.role != material.role
            || self.byte_io != topology.byte_io
            || self.inverse_auxiliaries != topology.inverse_auxiliaries
            || self.rows.len() != p256_external_binding_rows_v1(material.role)
        {
            return Err(P256ExternalBindingErrorV1::Topology);
        }
        let selected = p256_byte_io_witness_v1(material, topology.byte_io)?;
        if self.input_selection.selected != selected
            || self
                .input_selection
                .constraint_residues_v1()
                .iter()
                .any(|residue| *residue != F::ZERO)
        {
            return Err(P256ExternalBindingErrorV1::OptionalCertificateSelection);
        }
        let expected = expected_slots_with_topology_v1(material, value_bus, &topology)?;
        for (row_index, row) in self.rows.iter().enumerate() {
            let first = row_index
                .checked_mul(P256_EXTERNAL_BINDINGS_PER_ROW_V1)
                .ok_or(P256ExternalBindingErrorV1::Resource)?;
            let chunk = expected
                .get(first..first + P256_EXTERNAL_BINDINGS_PER_ROW_V1)
                .ok_or(P256ExternalBindingErrorV1::Topology)?;
            let expected_fixed = core::array::from_fn(|slot| chunk[slot].fixed);
            let writer_sources = core::array::from_fn(|slot| chunk[slot].writer);
            let external_sources = core::array::from_fn(|slot| chunk[slot].external);
            if row.fixed != expected_fixed {
                return Err(P256ExternalBindingErrorV1::Topology);
            }
            for slot in 0..P256_EXTERNAL_BINDINGS_PER_ROW_V1 {
                let inactive = row.fixed[slot] == P256ExternalBindingFixedAccessV1::Inactive;
                if F::canonical(row.writer_cells[slot].0).is_none()
                    || F::canonical(row.external_cells[slot].0).is_none()
                    || row.writer_cells[slot].0 > u64::from(u16::MAX)
                    || row.external_cells[slot].0 > u64::from(u16::MAX)
                {
                    return Err(P256ExternalBindingErrorV1::Range);
                }
                if inactive
                    && (row.writer_cells[slot] != F::ZERO || row.external_cells[slot] != F::ZERO)
                {
                    return Err(P256ExternalBindingErrorV1::Padding);
                }
                if row.writer_cells[slot] != writer_sources[slot] {
                    return Err(P256ExternalBindingErrorV1::WriterSource);
                }
                if row.external_cells[slot] != external_sources[slot] {
                    return Err(P256ExternalBindingErrorV1::ExternalSource);
                }
                if !inactive && row.writer_cells[slot] != row.external_cells[slot] {
                    return Err(P256ExternalBindingErrorV1::Equality);
                }
            }
            let residues = evaluate_zk_x509_p256_external_binding_row_constraints_v1(
                expected_fixed,
                row,
                writer_sources,
                external_sources,
            );
            if residues.iter().any(|residue| *residue != F::ZERO) {
                return Err(P256ExternalBindingErrorV1::Constraint);
            }
        }
        Ok(())
    }
    /// Replace the ordinary active identity selection with the sole optional certificate relation.
    /// The selected tuple must already be the exact input compiled into this P-256 instance.
    pub(crate) fn bind_optional_certificate_selection_v1(
        &mut self,
        selection: P256OptionalCertificateSelectionV1,
        material: &P256EcdsaTraceMaterialV1,
        value_bus: &P256ValueBusBaseEndpointTraceV1,
    ) -> Result<(), P256ExternalBindingErrorV1> {
        let previous = self.input_selection;
        self.input_selection = selection;
        if let Err(error) = self.validate_v1(material, value_bus) {
            self.input_selection = previous;
            return Err(error);
        }
        Ok(())
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn p256_byte_io_witness_v1(
    material: &P256EcdsaTraceMaterialV1,
    manifest: P256UnresolvedByteIoManifestV1,
) -> Result<P256EcdsaWitnessV1, P256ExternalBindingErrorV1> {
    let mut witness = P256EcdsaWitnessV1 {
        public_key_x_be: [0; 32],
        public_key_y_be: [0; 32],
        r_be: [0; 32],
        s_be: [0; 32],
        digest_be: [0; 32],
    };
    for endpoint in manifest.endpoints {
        let word = match endpoint.source {
            P256UnresolvedByteIoSourceV1::ValueWriter { id, modulus } => {
                let value = material
                    .initial_values
                    .iter()
                    .find(|value| value.id == id)
                    .ok_or(P256ExternalBindingErrorV1::Ownership)?;
                if value.modulus != modulus || value.kind != P256InitialValueKindV1::Input {
                    return Err(P256ExternalBindingErrorV1::Ownership);
                }
                value.value
            }
            P256UnresolvedByteIoSourceV1::ReductionWord {
                reduction: P256ExternalReductionV1::Digest,
            } => {
                let reduction = material
                    .reductions
                    .iter()
                    .find(|reduction| {
                        matches!(reduction.source, P256ReductionSourceV1::Digest { .. })
                    })
                    .ok_or(P256ExternalBindingErrorV1::Ownership)?;
                match reduction.source {
                    P256ReductionSourceV1::Digest { word_be } => word_be,
                    P256ReductionSourceV1::BaseCoordinate { .. } => {
                        return Err(P256ExternalBindingErrorV1::Ownership);
                    }
                }
            }
            P256UnresolvedByteIoSourceV1::ReductionWord {
                reduction: P256ExternalReductionV1::ResultX,
            } => return Err(P256ExternalBindingErrorV1::Ownership),
        };
        match endpoint.kind {
            P256UnresolvedByteIoKindV1::PublicKeyX => witness.public_key_x_be = word,
            P256UnresolvedByteIoKindV1::PublicKeyY => witness.public_key_y_be = word,
            P256UnresolvedByteIoKindV1::SignatureR => witness.r_be = word,
            P256UnresolvedByteIoKindV1::SignatureS => witness.s_be = word,
            P256UnresolvedByteIoKindV1::DigestWord => witness.digest_be = word,
        }
    }
    Ok(witness)
}
/// Pure low-degree residues for one packed row.
///
/// `fixed`, `writer_sources`, and `external_sources` are supplied from
/// verifier-regenerated addresses and openings of the already-committed source
/// traces.  Every active slot copies both sources and constrains equality.
/// Inactive slots additionally constrain both committed copies to zero.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn evaluate_zk_x509_p256_external_binding_row_constraints_v1(
    fixed: [P256ExternalBindingFixedAccessV1; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    row: &P256ExternalBindingRowV1,
    writer_sources: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
    external_sources: [F; P256_EXTERNAL_BINDINGS_PER_ROW_V1],
) -> Vec<F> {
    let mut residues = Vec::with_capacity(15);
    for slot in 0..P256_EXTERNAL_BINDINGS_PER_ROW_V1 {
        residues.push(row.writer_cells[slot].sub(writer_sources[slot]));
        residues.push(row.external_cells[slot].sub(external_sources[slot]));
        residues.push(row.writer_cells[slot].sub(row.external_cells[slot]));
        if fixed[slot] == P256ExternalBindingFixedAccessV1::Inactive {
            residues.push(row.writer_cells[slot]);
            residues.push(row.external_cells[slot]);
        }
    }
    residues
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedInitialOwnerV1 {
    Constant,
    ByteIo(P256UnresolvedByteIoKindV1),
    InverseR,
    InverseS,
    InverseResultZ,
    WindowOutput {
        scalar: P256WindowScalarV1,
        window: u8,
        coordinate: P256WindowCoordinateV1,
    },
    ReductionOutput(P256ExternalReductionV1),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedInitialV1 {
    modulus: ZkX509P256ModulusV1,
    owner: ExpectedInitialOwnerV1,
    constant: Option<[u8; 32]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug)]
struct ExpectedTopologyV1 {
    initial: Vec<ExpectedInitialV1>,
    byte_io: P256UnresolvedByteIoManifestV1,
    inverse_auxiliaries: P256InverseAuxiliaryManifestV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedBindingV1 {
    fixed: P256ExternalBindingFixedAccessV1,
    writer: F,
    external: F,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ExpectedBindingV1 {
    const fn inactive() -> Self {
        Self {
            fixed: P256ExternalBindingFixedAccessV1::Inactive,
            writer: F::ZERO,
            external: F::ZERO,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_expected_bindings_v1(bindings: &mut [ExpectedBindingV1]) {
    for binding in bindings {
        super::private_table::zeroize_fields_v1(core::slice::from_mut(&mut binding.writer));
        super::private_table::zeroize_fields_v1(core::slice::from_mut(&mut binding.external));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn expected_slots_v1(
    material: &P256EcdsaTraceMaterialV1,
    value_bus: &P256ValueBusBaseEndpointTraceV1,
) -> Result<super::private_table::PrivateTableV1<ExpectedBindingV1>, P256ExternalBindingErrorV1> {
    let topology = validate_material_topology_v1(material)?;
    expected_slots_with_topology_v1(material, value_bus, &topology)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn expected_slots_with_topology_v1(
    material: &P256EcdsaTraceMaterialV1,
    value_bus: &P256ValueBusBaseEndpointTraceV1,
    topology: &ExpectedTopologyV1,
) -> Result<super::private_table::PrivateTableV1<ExpectedBindingV1>, P256ExternalBindingErrorV1> {
    let active = p256_external_binding_active_equalities_v1(material.role);
    let slots = p256_external_binding_rows_v1(material.role)
        .checked_mul(P256_EXTERNAL_BINDINGS_PER_ROW_V1)
        .ok_or(P256ExternalBindingErrorV1::Resource)?;
    let mut expected =
        super::private_table::PrivateTableV1::new(Vec::new(), zeroize_expected_bindings_v1);
    expected
        .try_reserve_exact(slots)
        .map_err(|_| P256ExternalBindingErrorV1::Resource)?;
    let mut candidate_count = 0_usize;
    let mut output_count = 0_usize;
    for (ordinal, window) in material.windows.iter().enumerate() {
        let scalar = if ordinal < 64 {
            P256WindowScalarV1::U1
        } else {
            P256WindowScalarV1::U2
        };
        let window_index = ordinal % 64;
        for row in 0..P256_WINDOW_ROWS_V1 {
            let fixed_row = *window
                .trace
                .fixed
                .get(row)
                .ok_or(P256ExternalBindingErrorV1::Topology)?;
            for slot in 0..P256_WINDOW_EXTERNAL_LIMBS_PER_ROW_V1 {
                let address = p256_window_external_address_v1(fixed_row, slot)
                    .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
                let external = p256_window_external_limb_v1(&window.trace, row, slot)
                    .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
                let (id, coordinate, limb, fixed) = match address {
                    P256WindowExternalAddressV1::Candidate {
                        candidate,
                        coordinate,
                        limb,
                    } => {
                        candidate_count = candidate_count
                            .checked_add(1)
                            .ok_or(P256ExternalBindingErrorV1::Resource)?;
                        let id = window.candidates[usize::from(candidate)]
                            [coordinate_index_v1(coordinate)];
                        (
                            id,
                            coordinate,
                            limb,
                            P256ExternalBindingFixedAccessV1::WindowCandidate {
                                scalar,
                                window: u8::try_from(window_index)
                                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                                candidate,
                                coordinate,
                                limb,
                            },
                        )
                    }
                    P256WindowExternalAddressV1::Output { coordinate, limb } => {
                        output_count = output_count
                            .checked_add(1)
                            .ok_or(P256ExternalBindingErrorV1::Resource)?;
                        let id = window.output[coordinate_index_v1(coordinate)];
                        (
                            id,
                            coordinate,
                            limb,
                            P256ExternalBindingFixedAccessV1::WindowOutput {
                                scalar,
                                window: u8::try_from(window_index)
                                    .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                                coordinate,
                                limb,
                            },
                        )
                    }
                };
                let _ = coordinate;
                let writer = writer_cell_v1(
                    value_bus,
                    topology,
                    id,
                    usize::from(limb),
                    ZkX509P256ModulusV1::BaseField,
                )?;
                expected.push(ExpectedBindingV1 {
                    fixed,
                    writer,
                    external,
                });
            }
        }
    }
    if candidate_count != P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1
        || output_count != P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1
    {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    for (index, reduction) in material.reductions.iter().enumerate() {
        let reduction_kind = match index {
            0 => P256ExternalReductionV1::Digest,
            1 => P256ExternalReductionV1::ResultX,
            _ => return Err(P256ExternalBindingErrorV1::Topology),
        };
        for limb in 0..P256_REDUCTION_ROWS_V1 {
            let cells = p256_reduction_limb_cells_v1(&reduction.trace, limb)
                .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
            expected.push(ExpectedBindingV1 {
                fixed: P256ExternalBindingFixedAccessV1::ReductionOutput {
                    reduction: reduction_kind,
                    limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
                writer: writer_cell_v1(
                    value_bus,
                    topology,
                    reduction.output,
                    limb,
                    ZkX509P256ModulusV1::ScalarField,
                )?,
                external: cells[1],
            });
        }
    }
    let result_x_reduction = material
        .reductions
        .get(1)
        .ok_or(P256ExternalBindingErrorV1::Topology)?;
    for limb in 0..P256_REDUCTION_ROWS_V1 {
        let cells = p256_reduction_limb_cells_v1(&result_x_reduction.trace, limb)
            .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
        expected.push(ExpectedBindingV1 {
            fixed: P256ExternalBindingFixedAccessV1::ResultXReductionSource {
                limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
            },
            writer: writer_cell_v1(
                value_bus,
                topology,
                material.assigned.result_x,
                limb,
                ZkX509P256ModulusV1::BaseField,
            )?,
            external: cells[0],
        });
    }
    if material.role == P256EcdsaRoleV1::WalletOwnership {
        let low_s = material
            .low_s
            .first()
            .ok_or(P256ExternalBindingErrorV1::Topology)?;
        for limb in 0..P256_REDUCTION_ROWS_V1 {
            expected.push(ExpectedBindingV1 {
                fixed: P256ExternalBindingFixedAccessV1::LowS {
                    limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
                writer: writer_cell_v1(
                    value_bus,
                    topology,
                    material.assigned.s,
                    limb,
                    ZkX509P256ModulusV1::ScalarField,
                )?,
                external: p256_low_s_limb_cell_v1(&low_s.trace, limb)
                    .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?,
            });
        }
    }
    let mut constants = 0_usize;
    for (index, initial) in topology.initial.iter().copied().enumerate() {
        let Some(value_be) = initial.constant else {
            continue;
        };
        constants = constants
            .checked_add(1)
            .ok_or(P256ExternalBindingErrorV1::Resource)?;
        let id =
            P256ValueIdV1(u32::try_from(index).map_err(|_| P256ExternalBindingErrorV1::Resource)?);
        let limbs = bytes_be_to_limbs_le_v1(value_be);
        for (limb, expected_limb) in limbs.into_iter().enumerate() {
            expected.push(ExpectedBindingV1 {
                fixed: P256ExternalBindingFixedAccessV1::Constant {
                    id,
                    limb: u8::try_from(limb).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                },
                writer: writer_cell_v1(value_bus, topology, id, limb, initial.modulus)?,
                external: F(u64::from(expected_limb)),
            });
        }
    }
    if constants != P256_EXTERNAL_CONSTANT_INITIAL_VALUES_V1 || expected.len() != active {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    expected.resize(slots, ExpectedBindingV1::inactive());
    if expected[active..]
        .iter()
        .any(|binding| *binding != ExpectedBindingV1::inactive())
    {
        return Err(P256ExternalBindingErrorV1::Padding);
    }
    Ok(expected)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_material_topology_v1(
    material: &P256EcdsaTraceMaterialV1,
) -> Result<ExpectedTopologyV1, P256ExternalBindingErrorV1> {
    let initial = expected_initial_topology_v1()?;
    if material.initial_values.len() != P256_EXTERNAL_INITIAL_VALUES_V1
        || material.linked_operations.len() != P256_EXTERNAL_ARITHMETIC_OPERATIONS_V1
        || material.windows.len() != 128
        || material.reductions.len() != 2
        || !material.boolean_bridges.is_empty()
    {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    for (index, (actual, expected)) in material
        .initial_values
        .iter()
        .zip(initial.iter())
        .enumerate()
    {
        let expected_id =
            P256ValueIdV1(u32::try_from(index).map_err(|_| P256ExternalBindingErrorV1::Resource)?);
        let expected_kind = if expected.constant.is_some() {
            P256InitialValueKindV1::Constant
        } else {
            P256InitialValueKindV1::Input
        };
        if actual.id != expected_id
            || actual.modulus != expected.modulus
            || actual.kind != expected_kind
            || actual.value >= modulus_bytes_v1(expected.modulus)
        {
            return Err(P256ExternalBindingErrorV1::Topology);
        }
        if let Some(constant) = expected.constant
            && actual.value != constant
        {
            return Err(P256ExternalBindingErrorV1::Constant);
        }
    }
    let expected_assigned = [
        (material.assigned.public_key.x, PUBLIC_KEY_X_ID_V1),
        (material.assigned.public_key.y, PUBLIC_KEY_Y_ID_V1),
        (material.assigned.public_key.z, PUBLIC_KEY_Z_ID_V1),
        (material.assigned.r, SIGNATURE_R_ID_V1),
        (material.assigned.s, SIGNATURE_S_ID_V1),
        (material.assigned.z, DIGEST_REDUCTION_OUTPUT_ID_V1),
        (material.assigned.u1, derived_id_v1(13)?.0),
        (material.assigned.u2, derived_id_v1(14)?.0),
        (
            material.assigned.result.x,
            derived_id_v1(final_result_operation_v1(0)?)?.0,
        ),
        (
            material.assigned.result.y,
            derived_id_v1(final_result_operation_v1(1)?)?.0,
        ),
        (
            material.assigned.result.z,
            derived_id_v1(final_result_operation_v1(2)?)?.0,
        ),
        (
            material.assigned.result_x,
            derived_id_v1(NORMALIZATION_OPERATION_START_V1 + 1)?.0,
        ),
        (material.assigned.reduced_x, RESULT_X_REDUCTION_OUTPUT_ID_V1),
    ];
    if expected_assigned
        .iter()
        .any(|(actual, expected)| actual.0 != *expected)
    {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    let expected_equalities = [
        P256EqualityBindingV1 {
            left: derived_id_v1(1)?,
            right: derived_id_v1(10)?,
        },
        P256EqualityBindingV1 {
            left: derived_id_v1(11)?,
            right: P256ValueIdV1(R_INVERSE_ONE_ID_V1),
        },
        P256EqualityBindingV1 {
            left: derived_id_v1(12)?,
            right: P256ValueIdV1(S_INVERSE_ONE_ID_V1),
        },
        P256EqualityBindingV1 {
            left: derived_id_v1(NORMALIZATION_OPERATION_START_V1)?,
            right: P256ValueIdV1(RESULT_Z_INVERSE_ONE_ID_V1),
        },
        P256EqualityBindingV1 {
            left: P256ValueIdV1(RESULT_X_REDUCTION_OUTPUT_ID_V1),
            right: P256ValueIdV1(SIGNATURE_R_ID_V1),
        },
    ];
    if material.equalities.as_slice() != expected_equalities.as_slice() {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    for (ordinal, window) in material.windows.iter().enumerate() {
        let scalar = if ordinal < 64 {
            P256WindowScalarV1::U1
        } else {
            P256WindowScalarV1::U2
        };
        let window_index = ordinal % 64;
        window
            .trace
            .validate_for_v1(
                scalar,
                u8::try_from(window_index).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
            )
            .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
        let expected_source = if scalar == P256WindowScalarV1::U1 {
            13
        } else {
            14
        };
        if window.scalar_source_operation != expected_source {
            return Err(P256ExternalBindingErrorV1::Topology);
        }
        for candidate in 0..16 {
            for coordinate in 0..3 {
                if window.candidates[candidate][coordinate]
                    != expected_window_candidate_id_v1(scalar, candidate, coordinate)?
                {
                    return Err(P256ExternalBindingErrorV1::Ownership);
                }
            }
        }
        for coordinate in 0..3 {
            if window.output[coordinate]
                != expected_window_output_id_v1(scalar, window_index, coordinate)?
            {
                return Err(P256ExternalBindingErrorV1::Ownership);
            }
        }
    }
    let digest = &material.reductions[0];
    let P256ReductionSourceV1::Digest { word_be: digest_be } = digest.source else {
        return Err(P256ExternalBindingErrorV1::Topology);
    };
    if digest.output != P256ValueIdV1(DIGEST_REDUCTION_OUTPUT_ID_V1) {
        return Err(P256ExternalBindingErrorV1::Ownership);
    }
    validate_reduction_word_v1(&digest.trace, digest_be)?;
    let result_x = &material.reductions[1];
    let P256ReductionSourceV1::BaseCoordinate { id, word_be } = result_x.source else {
        return Err(P256ExternalBindingErrorV1::Topology);
    };
    if id != material.assigned.result_x
        || result_x.output != P256ValueIdV1(RESULT_X_REDUCTION_OUTPUT_ID_V1)
    {
        return Err(P256ExternalBindingErrorV1::Ownership);
    }
    validate_reduction_word_v1(&result_x.trace, word_be)?;
    match material.role {
        P256EcdsaRoleV1::WalletOwnership => {
            let [low_s] = material.low_s.as_slice() else {
                return Err(P256ExternalBindingErrorV1::Topology);
            };
            if low_s.scalar != material.assigned.s {
                return Err(P256ExternalBindingErrorV1::Ownership);
            }
            low_s
                .trace
                .validate()
                .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
        }
        P256EcdsaRoleV1::CertificateOrCrl if !material.low_s.is_empty() => {
            return Err(P256ExternalBindingErrorV1::Topology);
        }
        P256EcdsaRoleV1::CertificateOrCrl => {}
    }
    validate_inverse_relation_v1(
        material,
        11,
        P256ValueIdV1(SIGNATURE_R_ID_V1),
        P256ValueIdV1(R_INVERSE_ID_V1),
        P256ValueIdV1(R_INVERSE_ONE_ID_V1),
        ZkX509P256ModulusV1::ScalarField,
    )?;
    validate_inverse_relation_v1(
        material,
        12,
        P256ValueIdV1(SIGNATURE_S_ID_V1),
        P256ValueIdV1(S_INVERSE_ID_V1),
        P256ValueIdV1(S_INVERSE_ONE_ID_V1),
        ZkX509P256ModulusV1::ScalarField,
    )?;
    validate_inverse_relation_v1(
        material,
        NORMALIZATION_OPERATION_START_V1,
        material.assigned.result.z,
        P256ValueIdV1(RESULT_Z_INVERSE_ID_V1),
        P256ValueIdV1(RESULT_Z_INVERSE_ONE_ID_V1),
        ZkX509P256ModulusV1::BaseField,
    )?;
    let byte_io = expected_byte_io_manifest_v1();
    let inverse_auxiliaries = P256InverseAuxiliaryManifestV1 {
        r_inverse: P256ValueIdV1(R_INVERSE_ID_V1),
        s_inverse: P256ValueIdV1(S_INVERSE_ID_V1),
        result_z_inverse: P256ValueIdV1(RESULT_Z_INVERSE_ID_V1),
    };
    validate_input_ownership_v1(material, &initial, byte_io, inverse_auxiliaries)?;
    Ok(ExpectedTopologyV1 {
        initial,
        byte_io,
        inverse_auxiliaries,
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_input_ownership_v1(
    material: &P256EcdsaTraceMaterialV1,
    expected: &[ExpectedInitialV1],
    byte_io: P256UnresolvedByteIoManifestV1,
    inverses: P256InverseAuxiliaryManifestV1,
) -> Result<(), P256ExternalBindingErrorV1> {
    let mut owned = vec![false; P256_EXTERNAL_INITIAL_VALUES_V1];
    {
        let mut mark = |id: P256ValueIdV1| -> Result<(), P256ExternalBindingErrorV1> {
            let index = usize::try_from(id.0).map_err(|_| P256ExternalBindingErrorV1::Resource)?;
            let slot = owned
                .get_mut(index)
                .ok_or(P256ExternalBindingErrorV1::Ownership)?;
            if *slot {
                return Err(P256ExternalBindingErrorV1::Ownership);
            }
            *slot = true;
            Ok(())
        };
        for endpoint in byte_io.endpoints {
            if let P256UnresolvedByteIoSourceV1::ValueWriter { id, .. } = endpoint.source {
                mark(id)?;
            }
        }
        for id in [
            inverses.r_inverse,
            inverses.s_inverse,
            inverses.result_z_inverse,
        ] {
            mark(id)?;
        }
        for window in &material.windows {
            for id in window.output {
                mark(id)?;
            }
        }
        for reduction in &material.reductions {
            mark(reduction.output)?;
        }
    }
    let mut inputs = 0_usize;
    let mut constants = 0_usize;
    let mut inverse_count = 0_usize;
    for (index, (actual, expected)) in material
        .initial_values
        .iter()
        .zip(expected.iter())
        .enumerate()
    {
        match actual.kind {
            P256InitialValueKindV1::Input => {
                inputs += 1;
                if !owned[index] || expected.constant.is_some() {
                    return Err(P256ExternalBindingErrorV1::Ownership);
                }
                if matches!(
                    expected.owner,
                    ExpectedInitialOwnerV1::InverseR
                        | ExpectedInitialOwnerV1::InverseS
                        | ExpectedInitialOwnerV1::InverseResultZ
                ) {
                    inverse_count += 1;
                }
            }
            P256InitialValueKindV1::Constant => {
                constants += 1;
                if owned[index]
                    || expected.owner != ExpectedInitialOwnerV1::Constant
                    || expected.constant.is_none()
                {
                    return Err(P256ExternalBindingErrorV1::Ownership);
                }
            }
        }
    }
    if inputs != P256_EXTERNAL_INPUT_INITIAL_VALUES_V1
        || constants != P256_EXTERNAL_CONSTANT_INITIAL_VALUES_V1
        || inverse_count != 3
        || owned
            .iter()
            .zip(material.initial_values.iter())
            .any(|(owned, initial)| *owned != (initial.kind == P256InitialValueKindV1::Input))
    {
        return Err(P256ExternalBindingErrorV1::Ownership);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_inverse_relation_v1(
    material: &P256EcdsaTraceMaterialV1,
    operation_index: usize,
    value: P256ValueIdV1,
    inverse: P256ValueIdV1,
    one: P256ValueIdV1,
    modulus: ZkX509P256ModulusV1,
) -> Result<(), P256ExternalBindingErrorV1> {
    let operation = material
        .linked_operations
        .get(operation_index)
        .ok_or(P256ExternalBindingErrorV1::Topology)?;
    let product = derived_id_v1(operation_index)?;
    if operation.a != value
        || operation.b != inverse
        || operation.c != product
        || operation.operation.kind != ZkX509P256ArithmeticKindV1::Multiply
        || operation.operation.modulus != modulus
    {
        return Err(P256ExternalBindingErrorV1::Ownership);
    }
    let matching_equalities = material
        .equalities
        .iter()
        .filter(|equality| {
            (equality.left == product && equality.right == one)
                || (equality.left == one && equality.right == product)
        })
        .count();
    if matching_equalities != 1 {
        return Err(P256ExternalBindingErrorV1::Ownership);
    }
    Ok(())
}
fn expected_initial_topology_v1() -> Result<Vec<ExpectedInitialV1>, P256ExternalBindingErrorV1> {
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(P256_EXTERNAL_INITIAL_VALUES_V1)
        .map_err(|_| P256ExternalBindingErrorV1::Resource)?;
    {
        let mut push_constant = |modulus, value| {
            expected.push(ExpectedInitialV1 {
                modulus,
                owner: ExpectedInitialOwnerV1::Constant,
                constant: Some(value),
            });
        };
        push_constant(ZkX509P256ModulusV1::BaseField, ZERO_BE_V1);
        push_constant(ZkX509P256ModulusV1::BaseField, ONE_BE_V1);
        for multiple in 1..16 {
            let [x, y, z] = fixed_generator_point_v1(multiple)?;
            for coordinate in [x, y, z] {
                push_constant(ZkX509P256ModulusV1::BaseField, coordinate);
            }
        }
    }
    if expected.len() != GENERATOR_CONSTANTS_END_V1 {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::BaseField,
        ExpectedInitialOwnerV1::ByteIo(P256UnresolvedByteIoKindV1::PublicKeyX),
    );
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::BaseField,
        ExpectedInitialOwnerV1::ByteIo(P256UnresolvedByteIoKindV1::PublicKeyY),
    );
    push_constant_v1(&mut expected, ZkX509P256ModulusV1::BaseField, ONE_BE_V1);
    push_constant_v1(
        &mut expected,
        ZkX509P256ModulusV1::BaseField,
        P256_CURVE_B_BE_V1,
    );
    push_constant_v1(&mut expected, ZkX509P256ModulusV1::BaseField, THREE_BE_V1);
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::ScalarField,
        ExpectedInitialOwnerV1::ByteIo(P256UnresolvedByteIoKindV1::SignatureR),
    );
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::ScalarField,
        ExpectedInitialOwnerV1::ByteIo(P256UnresolvedByteIoKindV1::SignatureS),
    );
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::ScalarField,
        ExpectedInitialOwnerV1::InverseR,
    );
    push_constant_v1(&mut expected, ZkX509P256ModulusV1::ScalarField, ONE_BE_V1);
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::ScalarField,
        ExpectedInitialOwnerV1::InverseS,
    );
    push_constant_v1(&mut expected, ZkX509P256ModulusV1::ScalarField, ONE_BE_V1);
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::ScalarField,
        ExpectedInitialOwnerV1::ReductionOutput(P256ExternalReductionV1::Digest),
    );
    for value in [ZERO_BE_V1, ONE_BE_V1, ZERO_BE_V1] {
        push_constant_v1(&mut expected, ZkX509P256ModulusV1::BaseField, value);
    }
    for _ in 0..VARIABLE_TABLE_ADDITIONS_V1 {
        push_constant_v1(
            &mut expected,
            ZkX509P256ModulusV1::BaseField,
            P256_CURVE_B_BE_V1,
        );
    }
    for value in [ZERO_BE_V1, ONE_BE_V1, ZERO_BE_V1] {
        push_constant_v1(&mut expected, ZkX509P256ModulusV1::BaseField, value);
    }
    if expected.len() != WINDOW_INITIAL_START_V1 {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    for window in 0..64 {
        for _ in 0..4 {
            push_constant_v1(
                &mut expected,
                ZkX509P256ModulusV1::BaseField,
                P256_CURVE_B_BE_V1,
            );
        }
        for scalar in [P256WindowScalarV1::U1, P256WindowScalarV1::U2] {
            for coordinate in [
                P256WindowCoordinateV1::X,
                P256WindowCoordinateV1::Y,
                P256WindowCoordinateV1::Z,
            ] {
                push_input_v1(
                    &mut expected,
                    ZkX509P256ModulusV1::BaseField,
                    ExpectedInitialOwnerV1::WindowOutput {
                        scalar,
                        window: u8::try_from(window)
                            .map_err(|_| P256ExternalBindingErrorV1::Resource)?,
                        coordinate,
                    },
                );
            }
        }
        for _ in 0..2 {
            push_constant_v1(
                &mut expected,
                ZkX509P256ModulusV1::BaseField,
                P256_CURVE_B_BE_V1,
            );
        }
    }
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::BaseField,
        ExpectedInitialOwnerV1::InverseResultZ,
    );
    push_constant_v1(&mut expected, ZkX509P256ModulusV1::BaseField, ONE_BE_V1);
    push_input_v1(
        &mut expected,
        ZkX509P256ModulusV1::ScalarField,
        ExpectedInitialOwnerV1::ReductionOutput(P256ExternalReductionV1::ResultX),
    );
    if expected.len() != P256_EXTERNAL_INITIAL_VALUES_V1 {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    Ok(expected)
}
fn push_constant_v1(
    expected: &mut Vec<ExpectedInitialV1>,
    modulus: ZkX509P256ModulusV1,
    value: [u8; 32],
) {
    expected.push(ExpectedInitialV1 {
        modulus,
        owner: ExpectedInitialOwnerV1::Constant,
        constant: Some(value),
    });
}
fn push_input_v1(
    expected: &mut Vec<ExpectedInitialV1>,
    modulus: ZkX509P256ModulusV1,
    owner: ExpectedInitialOwnerV1,
) {
    expected.push(ExpectedInitialV1 {
        modulus,
        owner,
        constant: None,
    });
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn expected_byte_io_manifest_v1() -> P256UnresolvedByteIoManifestV1 {
    P256UnresolvedByteIoManifestV1 {
        endpoints: [
            P256UnresolvedByteIoEndpointV1 {
                kind: P256UnresolvedByteIoKindV1::PublicKeyX,
                source: P256UnresolvedByteIoSourceV1::ValueWriter {
                    id: P256ValueIdV1(PUBLIC_KEY_X_ID_V1),
                    modulus: ZkX509P256ModulusV1::BaseField,
                },
            },
            P256UnresolvedByteIoEndpointV1 {
                kind: P256UnresolvedByteIoKindV1::PublicKeyY,
                source: P256UnresolvedByteIoSourceV1::ValueWriter {
                    id: P256ValueIdV1(PUBLIC_KEY_Y_ID_V1),
                    modulus: ZkX509P256ModulusV1::BaseField,
                },
            },
            P256UnresolvedByteIoEndpointV1 {
                kind: P256UnresolvedByteIoKindV1::SignatureR,
                source: P256UnresolvedByteIoSourceV1::ValueWriter {
                    id: P256ValueIdV1(SIGNATURE_R_ID_V1),
                    modulus: ZkX509P256ModulusV1::ScalarField,
                },
            },
            P256UnresolvedByteIoEndpointV1 {
                kind: P256UnresolvedByteIoKindV1::SignatureS,
                source: P256UnresolvedByteIoSourceV1::ValueWriter {
                    id: P256ValueIdV1(SIGNATURE_S_ID_V1),
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
fn fixed_generator_point_v1(multiple: usize) -> Result<[[u8; 32]; 3], P256ExternalBindingErrorV1> {
    if !(1..16).contains(&multiple) {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    let point = ProjectivePoint::GENERATOR
        * Scalar::from(u64::try_from(multiple).map_err(|_| P256ExternalBindingErrorV1::Resource)?);
    let encoded = point.to_affine().to_encoded_point(false);
    let mut x = [0_u8; 32];
    let mut y = [0_u8; 32];
    x.copy_from_slice(encoded.x().ok_or(P256ExternalBindingErrorV1::Constant)?);
    y.copy_from_slice(encoded.y().ok_or(P256ExternalBindingErrorV1::Constant)?);
    Ok([x, y, ONE_BE_V1])
}
fn expected_window_candidate_id_v1(
    scalar: P256WindowScalarV1,
    candidate: usize,
    coordinate: usize,
) -> Result<P256ValueIdV1, P256ExternalBindingErrorV1> {
    if candidate >= 16 || coordinate >= 3 {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    let id = match scalar {
        P256WindowScalarV1::U1 if candidate == 0 => [0_u32, 1, 0][coordinate],
        P256WindowScalarV1::U1 => {
            let offset = (candidate - 1)
                .checked_mul(3)
                .and_then(|value| value.checked_add(coordinate))
                .and_then(|value| value.checked_add(2))
                .ok_or(P256ExternalBindingErrorV1::Resource)?;
            u32::try_from(offset).map_err(|_| P256ExternalBindingErrorV1::Resource)?
        }
        P256WindowScalarV1::U2 if candidate == 0 => [
            VARIABLE_IDENTITY_X_ID_V1,
            VARIABLE_IDENTITY_Y_ID_V1,
            VARIABLE_IDENTITY_Z_ID_V1,
        ][coordinate],
        P256WindowScalarV1::U2 if candidate == 1 => {
            [PUBLIC_KEY_X_ID_V1, PUBLIC_KEY_Y_ID_V1, PUBLIC_KEY_Z_ID_V1][coordinate]
        }
        P256WindowScalarV1::U2 => {
            let operation = VARIABLE_TABLE_OPERATION_START_V1
                .checked_add(
                    (candidate - 2)
                        .checked_mul(COMPLETE_ADD_OPERATIONS_V1)
                        .ok_or(P256ExternalBindingErrorV1::Resource)?,
                )
                .and_then(|value| value.checked_add(COMPLETE_ADD_OUTPUT_OFFSETS_V1[coordinate]))
                .ok_or(P256ExternalBindingErrorV1::Resource)?;
            return derived_id_v1(operation);
        }
    };
    Ok(P256ValueIdV1(id))
}
fn expected_window_output_id_v1(
    scalar: P256WindowScalarV1,
    window: usize,
    coordinate: usize,
) -> Result<P256ValueIdV1, P256ExternalBindingErrorV1> {
    if window >= 64 || coordinate >= 3 {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    let scalar_offset = match scalar {
        P256WindowScalarV1::U1 => 4,
        P256WindowScalarV1::U2 => 7,
    };
    let index = WINDOW_INITIAL_START_V1
        .checked_add(
            window
                .checked_mul(WINDOW_INITIAL_STRIDE_V1)
                .ok_or(P256ExternalBindingErrorV1::Resource)?,
        )
        .and_then(|value| value.checked_add(scalar_offset + coordinate))
        .ok_or(P256ExternalBindingErrorV1::Resource)?;
    Ok(P256ValueIdV1(
        u32::try_from(index).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
    ))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn final_result_operation_v1(coordinate: usize) -> Result<usize, P256ExternalBindingErrorV1> {
    if coordinate >= 3 {
        return Err(P256ExternalBindingErrorV1::Topology);
    }
    SCALAR_ROUND_OPERATION_START_V1
        .checked_add(
            63_usize
                .checked_mul(SCALAR_ROUND_OPERATIONS_V1)
                .ok_or(P256ExternalBindingErrorV1::Resource)?,
        )
        .and_then(|value| value.checked_add(4 * 34 + COMPLETE_ADD_OPERATIONS_V1))
        .and_then(|value| value.checked_add(COMPLETE_ADD_OUTPUT_OFFSETS_V1[coordinate]))
        .ok_or(P256ExternalBindingErrorV1::Resource)
}
fn derived_id_v1(operation: usize) -> Result<P256ValueIdV1, P256ExternalBindingErrorV1> {
    let id = P256_EXTERNAL_INITIAL_VALUES_V1
        .checked_add(operation)
        .ok_or(P256ExternalBindingErrorV1::Resource)?;
    Ok(P256ValueIdV1(
        u32::try_from(id).map_err(|_| P256ExternalBindingErrorV1::Resource)?,
    ))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn writer_cell_v1(
    value_bus: &P256ValueBusBaseEndpointTraceV1,
    topology: &ExpectedTopologyV1,
    id: P256ValueIdV1,
    limb: usize,
    modulus: ZkX509P256ModulusV1,
) -> Result<F, P256ExternalBindingErrorV1> {
    let id_index = usize::try_from(id.0).map_err(|_| P256ExternalBindingErrorV1::Resource)?;
    let kind = if id_index < P256_EXTERNAL_INITIAL_VALUES_V1 {
        let initial = topology
            .initial
            .get(id_index)
            .ok_or(P256ExternalBindingErrorV1::Ownership)?;
        if initial.modulus != modulus {
            return Err(P256ExternalBindingErrorV1::Ownership);
        }
        if initial.constant.is_some() {
            P256ValueKindV1::Constant
        } else {
            P256ValueKindV1::Input
        }
    } else {
        P256ValueKindV1::Derived
    };
    p256_value_bus_base_writer_limb_cell_v1(
        value_bus,
        P256_EXTERNAL_INITIAL_VALUES_V1,
        id,
        limb,
        modulus,
        kind,
    )
    .map_err(map_writer_error_v1)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_reduction_word_v1(
    trace: &super::p256_reduction_air::P256ReductionTraceV1,
    word_be: [u8; 32],
) -> Result<(), P256ExternalBindingErrorV1> {
    trace
        .validate()
        .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
    let limbs = bytes_be_to_limbs_le_v1(word_be);
    for (limb, expected) in limbs.into_iter().enumerate() {
        let cells = p256_reduction_limb_cells_v1(trace, limb)
            .map_err(|_| P256ExternalBindingErrorV1::ExternalSource)?;
        if cells[0] != F(u64::from(expected)) {
            return Err(P256ExternalBindingErrorV1::ExternalSource);
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn coordinate_index_v1(coordinate: P256WindowCoordinateV1) -> usize {
    match coordinate {
        P256WindowCoordinateV1::X => 0,
        P256WindowCoordinateV1::Y => 1,
        P256WindowCoordinateV1::Z => 2,
    }
}
fn coordinate_from_index_v1(
    coordinate: usize,
) -> Result<P256WindowCoordinateV1, P256ExternalBindingErrorV1> {
    match coordinate {
        0 => Ok(P256WindowCoordinateV1::X),
        1 => Ok(P256WindowCoordinateV1::Y),
        2 => Ok(P256WindowCoordinateV1::Z),
        _ => Err(P256ExternalBindingErrorV1::Topology),
    }
}
fn bytes_be_to_limbs_le_v1(bytes: [u8; 32]) -> [u16; P256_VALUE_BUS_LIMBS_V1] {
    core::array::from_fn(|limb| {
        let offset = 32 - 2 * (limb + 1);
        u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
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
fn map_writer_error_v1(error: P256ValueBusErrorV1) -> P256ExternalBindingErrorV1 {
    match error {
        P256ValueBusErrorV1::Resource => P256ExternalBindingErrorV1::Resource,
        P256ValueBusErrorV1::Range => P256ExternalBindingErrorV1::Range,
        P256ValueBusErrorV1::Phase | P256ValueBusErrorV1::Topology => {
            P256ExternalBindingErrorV1::Topology
        }
        _ => P256ExternalBindingErrorV1::WriterSource,
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn owned_expected_binding_erasure_clears_live_private_projection_cells() {
        use super::super::private_table::{PrivateTableV1, inspection::observe_v1};
        let rows = PrivateTableV1::new(
            vec![ExpectedBindingV1 {
                fixed: P256ExternalBindingFixedAccessV1::Inactive,
                writer: F(17),
                external: F(19),
            }],
            zeroize_expected_bindings_v1,
        );
        let ((), observed) = observe_v1(|| drop(rows));
        assert_eq!(
            observed
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            2
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
    }

    use super::*;
    use crate::privacy_engines::zk_x509::{
        credential_pre_aux::{
            ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, ZkX509CredentialMainPostBaseChallengesV1,
            ZkX509CredentialMainPreAuxV1, derive_zk_x509_credential_pre_aux_binding_v1,
        },
        p256_ecdsa_air::P256EcdsaWitnessV1,
        p256_trace::compile_p256_ecdsa_trace_material_v1,
        p256_value_bus::{
            P256_VALUE_BUS_SEGMENT_ROWS_V1, P256ValueAccessKindV1, P256ValueBusBaseCellV1,
            P256ValueBusBaseEndpointTraceV1, P256ValueBusEndpointV1, P256ValueBusFixedAccessV1,
        },
        stark::zk_x509_test_digest384_v1,
    };
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _};
    use std::sync::OnceLock;
    struct FixtureV1 {
        material: P256EcdsaTraceMaterialV1,
        value_bus: P256ValueBusBaseEndpointTraceV1,
        trace: P256ExternalBindingTraceV1,
    }
    fn wallet_fixture_v1() -> &'static FixtureV1 {
        static FIXTURE: OnceLock<FixtureV1> = OnceLock::new();
        FIXTURE.get_or_init(|| fixture_v1(P256EcdsaRoleV1::WalletOwnership, 97))
    }
    fn fixture_v1(role: P256EcdsaRoleV1, seed: u8) -> FixtureV1 {
        let material = material_v1(role, seed);
        let value_bus = synthetic_writer_endpoint_v1(&material);
        let trace = build_external_binding_from_execution_endpoint_v1(&material, &value_bus)
            .expect("complete external bindings");
        FixtureV1 {
            material,
            value_bus,
            trace,
        }
    }
    fn material_v1(role: P256EcdsaRoleV1, seed: u8) -> P256EcdsaTraceMaterialV1 {
        compile_p256_ecdsa_trace_material_v1(role, signed_witness_v1(seed))
            .expect("valid compiler material")
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
    fn signed_witness_v1(seed: u8) -> P256EcdsaWitnessV1 {
        let mut secret = [0_u8; 32];
        secret[31] = seed.max(1);
        let key = SigningKey::from_slice(&secret).expect("valid key");
        let digest = core::array::from_fn(|index| {
            seed.wrapping_mul(31)
                .wrapping_add((index as u8).wrapping_mul(17))
        });
        let signature: Signature = key.sign_prehash(&digest).expect("signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let encoded = key.verifying_key().to_encoded_point(false);
        let mut public_key_x_be = [0_u8; 32];
        let mut public_key_y_be = [0_u8; 32];
        public_key_x_be.copy_from_slice(encoded.x().expect("x"));
        public_key_y_be.copy_from_slice(encoded.y().expect("y"));
        P256EcdsaWitnessV1 {
            public_key_x_be,
            public_key_y_be,
            r_be: signature.r().to_bytes().into(),
            s_be: signature.s().to_bytes().into(),
            digest_be: digest,
        }
    }
    fn blank_bus_row_v1() -> P256ValueBusBaseCellV1 {
        P256ValueBusBaseCellV1 {
            fixed: P256ValueBusFixedAccessV1::Inactive,
            value: F::ZERO,
        }
    }
    fn synthetic_writer_endpoint_v1(
        material: &P256EcdsaTraceMaterialV1,
    ) -> P256ValueBusBaseEndpointTraceV1 {
        let result_x_operation = usize::try_from(material.assigned.result_x.0)
            .expect("result x id")
            - material.initial_values.len();
        let mut rows = vec![
            blank_bus_row_v1();
            material.linked_operations.len() * P256_VALUE_BUS_SEGMENT_ROWS_V1
        ];
        for initial in &material.initial_values {
            let segment = usize::try_from(initial.id.0).expect("initial id");
            let limbs = bytes_be_to_limbs_le_v1(initial.value);
            for (limb, value) in limbs.into_iter().enumerate() {
                let row =
                    segment * P256_VALUE_BUS_SEGMENT_ROWS_V1 + 3 * P256_VALUE_BUS_LIMBS_V1 + limb;
                rows[row] = P256ValueBusBaseCellV1 {
                    fixed: P256ValueBusFixedAccessV1::Active {
                        id: initial.id,
                        limb: limb as u8,
                        access: P256ValueAccessKindV1::Write,
                        modulus: initial.modulus,
                        value_kind: match initial.kind {
                            P256InitialValueKindV1::Input => P256ValueKindV1::Input,
                            P256InitialValueKindV1::Constant => P256ValueKindV1::Constant,
                        },
                    },
                    value: F(u64::from(value)),
                };
            }
        }
        for (operation, linked) in material.linked_operations.iter().enumerate() {
            if operation >= material.initial_values.len() && operation != result_x_operation {
                continue;
            }
            let limbs = bytes_be_to_limbs_le_v1(linked.operation.c);
            for (limb, value) in limbs.into_iter().enumerate() {
                let row = operation * P256_VALUE_BUS_SEGMENT_ROWS_V1 + 3 * limb + 2;
                rows[row] = P256ValueBusBaseCellV1 {
                    fixed: P256ValueBusFixedAccessV1::Active {
                        id: linked.c,
                        limb: limb as u8,
                        access: P256ValueAccessKindV1::Write,
                        modulus: linked.operation.modulus,
                        value_kind: P256ValueKindV1::Derived,
                    },
                    value: F(u64::from(value)),
                };
            }
        }
        P256ValueBusBaseEndpointTraceV1 {
            endpoint: P256ValueBusEndpointV1::Execution,
            rows,
        }
    }
    #[test]
    fn wallet_and_certificate_have_exact_coverage_ownership_and_padding() {
        let wallet = wallet_fixture_v1();
        wallet
            .trace
            .validate_v1(&wallet.material, &wallet.value_bus)
            .expect("wallet bindings");
        assert_eq!(
            wallet.trace.rows.len(),
            p256_external_binding_rows_v1(P256EcdsaRoleV1::WalletOwnership)
        );
        assert_eq!(
            wallet.trace.inverse_auxiliaries,
            P256InverseAuxiliaryManifestV1 {
                r_inverse: P256ValueIdV1(R_INVERSE_ID_V1),
                s_inverse: P256ValueIdV1(S_INVERSE_ID_V1),
                result_z_inverse: P256ValueIdV1(RESULT_Z_INVERSE_ID_V1),
            }
        );
        assert_eq!(wallet.trace.byte_io, expected_byte_io_manifest_v1());
        let wallet_inactive = wallet
            .trace
            .rows
            .iter()
            .flat_map(|row| row.fixed)
            .filter(|fixed| *fixed == P256ExternalBindingFixedAccessV1::Inactive)
            .count();
        assert_eq!(wallet_inactive, 1);
        let mut window_candidates = 0_usize;
        let mut window_outputs = 0_usize;
        let mut reduction_outputs = 0_usize;
        let mut result_x_sources = 0_usize;
        let mut low_s = 0_usize;
        let mut constants = 0_usize;
        let mut constant_cells =
            vec![false; P256_EXTERNAL_INITIAL_VALUES_V1 * P256_VALUE_BUS_LIMBS_V1];
        for fixed in wallet.trace.rows.iter().flat_map(|row| row.fixed) {
            match fixed {
                P256ExternalBindingFixedAccessV1::WindowCandidate { .. } => {
                    window_candidates += 1;
                }
                P256ExternalBindingFixedAccessV1::WindowOutput { .. } => {
                    window_outputs += 1;
                }
                P256ExternalBindingFixedAccessV1::ReductionOutput { .. } => {
                    reduction_outputs += 1;
                }
                P256ExternalBindingFixedAccessV1::ResultXReductionSource { .. } => {
                    result_x_sources += 1;
                }
                P256ExternalBindingFixedAccessV1::LowS { .. } => {
                    low_s += 1;
                }
                P256ExternalBindingFixedAccessV1::Constant { id, limb } => {
                    constants += 1;
                    let cell = usize::try_from(id.0).expect("constant id")
                        * P256_VALUE_BUS_LIMBS_V1
                        + usize::from(limb);
                    assert!(!constant_cells[cell], "duplicate constant writer cell");
                    constant_cells[cell] = true;
                }
                P256ExternalBindingFixedAccessV1::Inactive => {}
            }
        }
        assert_eq!(
            window_candidates,
            P256_EXTERNAL_WINDOW_CANDIDATE_BINDINGS_V1
        );
        assert_eq!(window_outputs, P256_EXTERNAL_WINDOW_OUTPUT_BINDINGS_V1);
        assert_eq!(
            reduction_outputs,
            P256_EXTERNAL_REDUCTION_OUTPUT_BINDINGS_V1
        );
        assert_eq!(result_x_sources, P256_EXTERNAL_RESULT_X_SOURCE_BINDINGS_V1);
        assert_eq!(low_s, P256_EXTERNAL_LOW_S_BINDINGS_V1);
        assert_eq!(constants, P256_EXTERNAL_CONSTANT_BINDINGS_V1);
        let certificate = fixture_v1(P256EcdsaRoleV1::CertificateOrCrl, 101);
        certificate
            .trace
            .validate_v1(&certificate.material, &certificate.value_bus)
            .expect("certificate bindings");
        assert_eq!(
            certificate.trace.rows.len(),
            p256_external_binding_rows_v1(P256EcdsaRoleV1::CertificateOrCrl)
        );
        let certificate_inactive = certificate
            .trace
            .rows
            .iter()
            .flat_map(|row| row.fixed)
            .filter(|fixed| *fixed == P256ExternalBindingFixedAccessV1::Inactive)
            .count();
        assert_eq!(certificate_inactive, 2);
        assert!(certificate.material.low_s.is_empty());
    }
    #[test]
    fn every_packed_copy_cell_and_low_degree_residue_is_constrained() {
        let fixture = wallet_fixture_v1();
        for row in &fixture.trace.rows {
            let writer_sources = row.writer_cells;
            let external_sources = row.external_cells;
            assert!(
                evaluate_zk_x509_p256_external_binding_row_constraints_v1(
                    row.fixed,
                    row,
                    writer_sources,
                    external_sources,
                )
                .iter()
                .all(|residue| *residue == F::ZERO)
            );
            for slot in 0..P256_EXTERNAL_BINDINGS_PER_ROW_V1 {
                let mut changed = *row;
                changed.writer_cells[slot] = changed.writer_cells[slot].add(F::ONE);
                assert!(
                    evaluate_zk_x509_p256_external_binding_row_constraints_v1(
                        row.fixed,
                        &changed,
                        writer_sources,
                        external_sources,
                    )
                    .iter()
                    .any(|residue| *residue != F::ZERO)
                );
                let mut changed = *row;
                changed.external_cells[slot] = changed.external_cells[slot].add(F::ONE);
                assert!(
                    evaluate_zk_x509_p256_external_binding_row_constraints_v1(
                        row.fixed,
                        &changed,
                        writer_sources,
                        external_sources,
                    )
                    .iter()
                    .any(|residue| *residue != F::ZERO)
                );
            }
        }
    }
    #[test]
    fn material_ids_constants_inverse_owners_and_fixed_order_fail_closed() {
        let fixture = wallet_fixture_v1();
        let mut missing_initial = fixture.material.clone();
        missing_initial.initial_values.pop();
        assert_eq!(
            validate_material_topology_v1(&missing_initial).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut wrong_constant = fixture.material.clone();
        wrong_constant.initial_values[0].value[31] = 1;
        assert_eq!(
            validate_material_topology_v1(&wrong_constant).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Constant)
        );
        let mut proof_owned_constant = fixture.material.clone();
        proof_owned_constant.initial_values[0].kind = P256InitialValueKindV1::Input;
        assert_eq!(
            validate_material_topology_v1(&proof_owned_constant).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut aliased_output = fixture.material.clone();
        aliased_output.windows[0].output[0] = aliased_output.windows[0].output[1];
        assert_eq!(
            validate_material_topology_v1(&aliased_output).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Ownership)
        );
        let mut aliased_candidate = fixture.material.clone();
        aliased_candidate.windows[64].candidates[2][0] =
            aliased_candidate.windows[64].candidates[1][0];
        assert_eq!(
            validate_material_topology_v1(&aliased_candidate).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Ownership)
        );
        let mut wrong_window_order = fixture.material.clone();
        wrong_window_order.windows.swap(0, 1);
        assert!(validate_material_topology_v1(&wrong_window_order).is_err());
        let mut swapped_reductions = fixture.material.clone();
        swapped_reductions.reductions.swap(0, 1);
        assert_eq!(
            validate_material_topology_v1(&swapped_reductions).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut rebound_reduction = fixture.material.clone();
        let word_be = match rebound_reduction.reductions[1].source {
            P256ReductionSourceV1::BaseCoordinate { word_be, .. } => word_be,
            P256ReductionSourceV1::Digest { .. } => panic!("result-x source"),
        };
        rebound_reduction.reductions[1].source = P256ReductionSourceV1::BaseCoordinate {
            id: P256ValueIdV1(0),
            word_be,
        };
        assert_eq!(
            validate_material_topology_v1(&rebound_reduction).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Ownership)
        );
        let mut rebound_low_s = fixture.material.clone();
        rebound_low_s.low_s[0].scalar = rebound_low_s.assigned.r;
        assert_eq!(
            validate_material_topology_v1(&rebound_low_s).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Ownership)
        );
        let mut rebound_inverse = fixture.material.clone();
        rebound_inverse.linked_operations[11].b = P256ValueIdV1(S_INVERSE_ID_V1);
        assert_eq!(
            validate_material_topology_v1(&rebound_inverse).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Ownership)
        );
        let inverse_product = derived_id_v1(11).expect("inverse product");
        let mut missing_inverse_equality = fixture.material.clone();
        missing_inverse_equality.equalities.retain(|equality| {
            !((equality.left == inverse_product
                && equality.right == P256ValueIdV1(R_INVERSE_ONE_ID_V1))
                || (equality.right == inverse_product
                    && equality.left == P256ValueIdV1(R_INVERSE_ONE_ID_V1)))
        });
        assert_eq!(
            validate_material_topology_v1(&missing_inverse_equality).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let inverse_equality = fixture
            .material
            .equalities
            .iter()
            .copied()
            .find(|equality| {
                (equality.left == inverse_product
                    && equality.right == P256ValueIdV1(R_INVERSE_ONE_ID_V1))
                    || (equality.right == inverse_product
                        && equality.left == P256ValueIdV1(R_INVERSE_ONE_ID_V1))
            })
            .expect("r inverse equality");
        let mut duplicate_inverse_equality = fixture.material.clone();
        duplicate_inverse_equality.equalities.push(inverse_equality);
        assert_eq!(
            validate_material_topology_v1(&duplicate_inverse_equality).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut reordered_equalities = fixture.material.clone();
        reordered_equalities.equalities.swap(0, 1);
        assert_eq!(
            validate_material_topology_v1(&reordered_equalities).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut reversed_equality = fixture.material.clone();
        let equality = &mut reversed_equality.equalities[0];
        core::mem::swap(&mut equality.left, &mut equality.right);
        assert_eq!(
            validate_material_topology_v1(&reversed_equality).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut aliased_public_input = fixture.material.clone();
        aliased_public_input.assigned.public_key.x = aliased_public_input.assigned.public_key.y;
        assert_eq!(
            validate_material_topology_v1(&aliased_public_input).map(|_| ()),
            Err(P256ExternalBindingErrorV1::Topology)
        );
    }
    #[test]
    fn row_manifest_coverage_padding_and_coordinated_copy_attacks_fail() {
        let fixture = wallet_fixture_v1();
        let mut changed = fixture.trace.clone();
        changed.rows[0].fixed[0] = P256ExternalBindingFixedAccessV1::Inactive;
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut changed = fixture.trace.clone();
        changed.rows[0].writer_cells[0] = changed.rows[0].writer_cells[0].add(F::ONE);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::WriterSource)
        );
        let mut changed = fixture.trace.clone();
        changed.rows[0].external_cells[0] = changed.rows[0].external_cells[0].add(F::ONE);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::ExternalSource)
        );
        let mut changed = fixture.trace.clone();
        changed.rows[0].writer_cells[0] = changed.rows[0].writer_cells[0].add(F::ONE);
        changed.rows[0].external_cells[0] = changed.rows[0].external_cells[0].add(F::ONE);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::WriterSource),
            "coordinated copies cannot detach from actual source cells"
        );
        let mut changed = fixture.trace.clone();
        changed.rows.swap(0, 1);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut changed = fixture.trace.clone();
        changed.rows.pop();
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut changed = fixture.trace.clone();
        changed.rows.push(changed.rows[0]);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let last = fixture.trace.rows.len() - 1;
        let padding_slot = P256_EXTERNAL_BINDINGS_PER_ROW_V1 - 1;
        assert_eq!(
            fixture.trace.rows[last].fixed[padding_slot],
            P256ExternalBindingFixedAccessV1::Inactive
        );
        let mut changed = fixture.trace.clone();
        changed.rows[last].writer_cells[padding_slot] = F::ONE;
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Padding)
        );
        let mut changed = fixture.trace.clone();
        changed.rows[last].fixed[padding_slot] = P256ExternalBindingFixedAccessV1::Constant {
            id: P256ValueIdV1(0),
            limb: 0,
        };
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut changed = fixture.trace.clone();
        changed.rows[0].writer_cells[0] = F(u64::from(u16::MAX) + 1);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Range)
        );
        let mut changed = fixture.trace.clone();
        changed.byte_io.endpoints.swap(0, 1);
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut changed = fixture.trace.clone();
        changed.inverse_auxiliaries.r_inverse = changed.inverse_auxiliaries.s_inverse;
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let mut changed = fixture.trace.clone();
        changed.role = P256EcdsaRoleV1::CertificateOrCrl;
        assert_eq!(
            changed.validate_v1(&fixture.material, &fixture.value_bus),
            Err(P256ExternalBindingErrorV1::Topology)
        );
    }
    #[test]
    fn production_base_source_path_matches_projection_binds_once_and_zeroizes_recursively() {
        let ((), observations) = super::super::private_table::inspection::observe_v1(production_base_source_path_matches_projection_binds_once_and_zeroizes_recursively_body_v1);
        assert!(observations.iter().any(|item| item.nonzero_before > 0));
        assert!(observations.iter().all(|item| item.nonzero_after == 0));
    }
    fn production_base_source_path_matches_projection_binds_once_and_zeroizes_recursively_body_v1()
    {
        let fixture = wallet_fixture_v1();
        let mut base = P256ValueBusBaseSourceV1::new_v1(&fixture.material)
            .expect("validated challenge-independent value-bus source");
        let mut production = build_zk_x509_p256_external_binding_trace_v1(&fixture.material, &base)
            .expect("production external binding");
        assert_eq!(production, fixture.trace);
        let mut wrong_role = fixture.material.clone();
        wrong_role.role = P256EcdsaRoleV1::CertificateOrCrl;
        assert_eq!(
            build_zk_x509_p256_external_binding_trace_v1(&wrong_role, &base),
            Err(P256ExternalBindingErrorV1::Topology)
        );
        let bound = base
            .bind_v1(post_base_v1(0x41))
            .expect("source remains bindable after external base construction");
        bound
            .execution_aux_source_v1()
            .expect("bound source mints auxiliary replay");
        assert_eq!(
            build_zk_x509_p256_external_binding_trace_v1(&fixture.material, &base),
            Err(P256ExternalBindingErrorV1::Topology),
            "consumed base capability was reusable after X5B1",
        );
        production.zeroize_private_v1();
        assert!(production.private_is_zeroized_v1());
        production.zeroize_private_v1();
        assert!(production.private_is_zeroized_v1());
    }
    #[test]
    fn writer_window_and_coordinated_constant_source_mutations_fail() {
        let fixture = wallet_fixture_v1();
        let mut wrong_address = fixture.value_bus.clone();
        wrong_address.rows[48].fixed = P256ValueBusFixedAccessV1::Inactive;
        assert_eq!(
            build_external_binding_from_execution_endpoint_v1(&fixture.material, &wrong_address,),
            Err(P256ExternalBindingErrorV1::WriterSource)
        );
        let mut wrong_writer = fixture.value_bus.clone();
        wrong_writer.rows[48].value = F::ONE;
        assert_eq!(
            build_external_binding_from_execution_endpoint_v1(&fixture.material, &wrong_writer,),
            Err(P256ExternalBindingErrorV1::Equality)
        );
        let selected = (0..4).fold(0_usize, |value, bit| {
            let bit = fixture.material.windows[0]
                .trace
                .bit_v1(bit)
                .expect("window bit");
            (value << 1) | usize::try_from(bit.0).expect("Boolean bit")
        });
        let candidate = (selected + 1) % 16;
        let row = candidate * 16;
        let external_column = 3 * 16;
        let candidate_id = fixture.material.windows[0].candidates[candidate][0];
        let mut wrong_window = fixture.material.clone();
        wrong_window.windows[0].trace.base[row][external_column] =
            wrong_window.windows[0].trace.base[row][external_column].add(F::ONE);
        wrong_window.windows[0]
            .trace
            .validate_for_v1(P256WindowScalarV1::U1, 0)
            .expect("unselected candidate is constrained only by the binding");
        assert_eq!(
            build_external_binding_from_execution_endpoint_v1(&wrong_window, &fixture.value_bus,),
            Err(P256ExternalBindingErrorV1::Equality)
        );
        let mut coordinated_window = fixture.material.clone();
        coordinated_window.windows[0].trace.base[row][external_column] =
            coordinated_window.windows[0].trace.base[row][external_column].add(F::ONE);
        let mut coordinated_bus = fixture.value_bus.clone();
        let candidate_segment = usize::try_from(candidate_id.0).expect("initial constant id");
        let candidate_row =
            candidate_segment * P256_VALUE_BUS_SEGMENT_ROWS_V1 + 3 * P256_VALUE_BUS_LIMBS_V1;
        coordinated_bus.rows[candidate_row].value =
            coordinated_bus.rows[candidate_row].value.add(F::ONE);
        assert_eq!(
            build_external_binding_from_execution_endpoint_v1(
                &coordinated_window,
                &coordinated_bus,
            ),
            Err(P256ExternalBindingErrorV1::Equality),
            "the independent fixed-constant binding defeats a coordinated table/writer mutation"
        );
    }
    #[test]
    fn optional_certificate_selector_uses_only_the_pinned_public_dummy() {
        assert_eq!(
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DOMAIN_V1,
            b"iroha.zk-x509.p256.optional-certificate-dummy.v1"
        );
        assert_eq!(
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1.digest_be,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1
        );
        compile_p256_ecdsa_trace_material_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1,
        )
        .expect("the verifier-owned dummy is a valid public P-256 equation");
        let inactive_real = P256EcdsaWitnessV1 {
            public_key_x_be: [0; 32],
            public_key_y_be: [0; 32],
            r_be: [0; 32],
            s_be: [0; 32],
            digest_be: ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
        };
        let inactive = select_zk_x509_optional_certificate_p256_witness_v1(0, inactive_real)
            .expect("canonical inactive source");
        assert_eq!(
            inactive.selected,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1
        );
        assert!(
            inactive
                .constraint_residues_v1()
                .into_iter()
                .all(|residue| residue == F::ZERO)
        );
        let active_real = signed_witness_v1(113);
        let active = select_zk_x509_optional_certificate_p256_witness_v1(1, active_real)
            .expect("canonical active source");
        assert_eq!(active.selected, active_real);
        assert_ne!(active.selected, inactive.selected);
        assert!(
            active
                .constraint_residues_v1()
                .into_iter()
                .all(|residue| residue == F::ZERO)
        );
    }
    #[test]
    fn optional_certificate_selector_rejects_non_boolean_and_noncanonical_sources() {
        let inactive_real = P256EcdsaWitnessV1 {
            public_key_x_be: [0; 32],
            public_key_y_be: [0; 32],
            r_be: [0; 32],
            s_be: [0; 32],
            digest_be: ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
        };
        assert_eq!(
            select_zk_x509_optional_certificate_p256_witness_v1(2, inactive_real),
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        );
        for word in 0..5 {
            let mut changed = inactive_real;
            match word {
                0 => changed.public_key_x_be[31] = 1,
                1 => changed.public_key_y_be[31] = 1,
                2 => changed.r_be[31] = 1,
                3 => changed.s_be[31] = 1,
                4 => changed.digest_be[31] ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(
                select_zk_x509_optional_certificate_p256_witness_v1(0, changed),
                Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
            );
        }
        let mut changed = select_zk_x509_optional_certificate_p256_witness_v1(0, inactive_real)
            .expect("canonical inactive selection");
        changed.active = F(2);
        assert_eq!(
            changed.validate_v1(),
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        );
        let mut changed = select_zk_x509_optional_certificate_p256_witness_v1(0, inactive_real)
            .expect("canonical inactive selection");
        changed.selected.public_key_x_be[0] ^= 1;
        assert_eq!(
            changed.validate_v1(),
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        );
    }
    #[test]
    fn optional_certificate_selector_rejects_cross_slot_substitution() {
        let inactive_real = P256EcdsaWitnessV1 {
            public_key_x_be: [0; 32],
            public_key_y_be: [0; 32],
            r_be: [0; 32],
            s_be: [0; 32],
            digest_be: ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
        };
        let inactive = select_zk_x509_optional_certificate_p256_witness_v1(0, inactive_real)
            .expect("inactive selection");
        let active = select_zk_x509_optional_certificate_p256_witness_v1(1, signed_witness_v1(127))
            .expect("active selection");
        let mut active_replaced = active;
        active_replaced.selected = inactive.selected;
        assert_eq!(
            active_replaced.validate_v1(),
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        );
        let mut inactive_replaced = inactive;
        inactive_replaced.selected = active.selected;
        assert_eq!(
            inactive_replaced.validate_v1(),
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        );
    }
    #[test]
    fn external_binding_accepts_canonical_inactive_selection_and_rolls_back_failure() {
        let material = compile_p256_ecdsa_trace_material_v1(
            P256EcdsaRoleV1::CertificateOrCrl,
            ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_V1,
        )
        .expect("dummy material");
        let value_bus = synthetic_writer_endpoint_v1(&material);
        let mut trace = build_external_binding_from_execution_endpoint_v1(&material, &value_bus)
            .expect("dummy external binding");
        let inactive_real = P256EcdsaWitnessV1 {
            public_key_x_be: [0; 32],
            public_key_y_be: [0; 32],
            r_be: [0; 32],
            s_be: [0; 32],
            digest_be: ZK_X509_P256_OPTIONAL_CERTIFICATE_DUMMY_DIGEST_V1,
        };
        let inactive = select_zk_x509_optional_certificate_p256_witness_v1(0, inactive_real)
            .expect("canonical inactive selection");
        trace
            .bind_optional_certificate_selection_v1(inactive, &material, &value_bus)
            .expect("bind inactive selection");
        trace
            .validate_v1(&material, &value_bus)
            .expect("inactive trace remains valid");
        let retained = trace.input_selection;
        let mut forged = retained;
        forged.selected.public_key_x_be[0] ^= 1;
        assert_eq!(
            trace.bind_optional_certificate_selection_v1(forged, &material, &value_bus),
            Err(P256ExternalBindingErrorV1::OptionalCertificateSelection)
        );
        assert_eq!(trace.input_selection, retained);
        trace
            .validate_v1(&material, &value_bus)
            .expect("failed replacement is atomic");
    }
}
