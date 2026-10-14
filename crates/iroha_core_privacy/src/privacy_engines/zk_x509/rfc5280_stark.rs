//! Native numeric RFC 5280 adapter for the closed first-release X5S1 profile.
//!
//! The owner trace in [`super::der_air`] parses values for witness construction, but none of its
//! host Boolean decisions are proof inputs. This adapter consumes exact strict-DER byte and node
//! events, derives semantic roles from a fixed parent/child/tag grammar, and recomputes the
//! admitted path, validity, extension, serial, and complete-CRL predicates from committed operands.
//! Fixed family ranges are reconstructed from one constant public registration; a witness cannot
//! select a row family.
//!
//! Four independently sampled Goldilocks lanes are used for every compressed
//! relation.  Composition/FRI challenge counts are deliberately outside this
//! module and remain three.  Aggregate registration and consensus activation
//! remain false until every terminal below is wired to its numeric consumer.
#[cfg(test)]
#[path = "rfc5280_ca_binding_tests.rs"]
mod ca_binding_tests;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::{
    PrivateTableV1, zeroize_field_rows_v1, zeroize_fields_v1, zeroize_words_v1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "rfc5280_private.rs"]
mod private;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "rfc5280_source_rows.rs"]
mod source_rows;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use private::{
    private_bytes_v1, reserve_private_semantic_v1, zeroize_equal_bytes_v1, zeroize_fixed_bytes_v1,
    zeroize_node_multiplicities_v1, zeroize_numeric_relations_v1, zeroize_source_cells_v1,
    zeroize_source_multiplicities_v1,
};

#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::der_air::rfc5280_io_witnesses_v1;
#[cfg(test)]
use super::p256_aggregate_adapter::P256CrossTraceTerminalRoleV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_aggregate_adapter::{
    P256BusTerminalClaimsV1, P256CrossTraceTerminalClaimV1,
    evaluate_p256_bus_terminal_claim_equalities_v1,
    evaluate_p256_cross_trace_terminal_claim_equalities_v1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_ecdsa_air::P256EcdsaRoleV1;
#[cfg(test)]
use super::stark::ZK_X509_DIGEST_CONTEXT_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    credential_pre_aux::ZkX509CredentialPreAuxBindingV1,
    der_air::{
        ZkX509DerAirErrorV1, ZkX509DerDocumentTraceV1, ZkX509Rfc5280DocumentKindV1,
        ZkX509Rfc5280DocumentProvenanceV1, ZkX509Rfc5280NodeProvenanceV1, ZkX509Rfc5280TraceV1,
    },
    io_air::ZkX509IoEndpointV1,
    sha_call_bus_stark::{ZkX509ShaBatchSegmentAuxSourceV1, ZkX509ShaCallBoundaryTerminalV1},
};
use super::{
    der_air::{
        ZK_X509_DER_AIR_MAX_DOCUMENTS_V1, ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1,
        ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1, ZkX509DerEkuV1,
        ZkX509Rfc5280GrammarRoleV1, ZkX509Rfc5280StatementV1,
    },
    der_stark::{
        ZK_X509_DER_STARK_BUS_LANES_V1, ZkX509DerStarkChallengesV1, ZkX509DerStarkErrorV1,
        ZkX509DerStarkNodeEventV1, zk_x509_der_stark_input_byte_factor_v1,
        zk_x509_der_stark_node_factor_v1,
    },
    io_air::ZkX509IoSegmentRoleV1,
    p256_aggregate_adapter::{P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1, P256_X5S1_SIGNATURES_V1},
    p256_cross_trace_bus::P256_CROSS_TRACE_LANES_V1,
    profile::{
        ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1, ZK_X509_MAX_CRL_ENTRIES_V1,
        ZK_X509_MAX_SERIAL_BYTES_V1, ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
    },
};
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_MODULUS_V1, GoldilocksFieldV1 as F, PolynomialAirFieldV1, TransparentStarkErrorV1,
    TransparentTranscriptV1,
};
#[cfg(test)]
use crate::privacy_engines::transparent_stark::{
    PrivacyOuterDigestV1, privacy_outer_digest_frame_v1,
};
use iroha_data_model::privacy::PrivacyZkX509PresentationWindowV1;
use thiserror::Error;
#[path = "rfc5280_binding_glue.rs"]
mod binding;
#[path = "rfc5280_calendar.rs"]
mod calendar;
#[path = "rfc5280_copy_census.rs"]
mod copy_census;
#[path = "rfc5280_name_policy.rs"]
mod name_policy;
#[path = "rfc5280_name_values.rs"]
mod name_values;
#[path = "rfc5280_numeric.rs"]
mod numeric;
#[path = "rfc5280_path_len.rs"]
mod path_len;
#[path = "rfc5280_profile_identity.rs"]
mod profile_identity;
#[path = "rfc5280_projection_disclosure.rs"]
mod projection_disclosure;
#[path = "rfc5280_projection_serial.rs"]
mod projection_serial;
#[path = "rfc5280_temporal.rs"]
mod temporal;
#[path = "rfc5280_variable_output.rs"]
mod variable_output;
use binding::numeric_lookup_event_v1;
/// Stable identity of the native RFC adapter integrated only through MAIN.
#[cfg(test)]
pub(crate) const ZK_X509_RFC5280_STARK_DESCRIPTOR_V1: &[u8] = b"zk-x509-rfc5280-stark-v1-incompatible:native-log19:base285:aux280:fixed147:constraints2145:degree4:source-node-root-kind-active-gated-helper-fixed-eight-equality-and-fifteen-embedded-endpoint-slots-complete-nonempty-original-node-spans-live-prefix-count-typed-copy-domains103-104-optional-slot-canonical-zero-exact-extension-oid-ordinal-ku-document-and-critical-cardinality-eku-canonical-profile-uuid-oids:output-metadata-six-verifier-fixed-equations:five-key-and-five-complete-spki-outputs-der-node-byte-lookups-key-length66-offset1-spki-content89-total91-offset0-nine-variable-tbs-crl-signature-byte-and-canonical-u16-in-eight-byte-big-endian-length-pairs-live-prefix-count-node-continuity-source-start-helper:projection-leaf-serial-magnitude-sign-octet-nonzero-first-byte-big-endian-length-selected-original-subject-oid-value-provenance-with-complete-name-oid-census-three-original-classes-disjoint-document-stride12-keys1through48-six-bit-positive-gaps-uniqueness-nonempty-bounded-rdns-and-complete-original-value-census-country-printable-utf8-dfa:max-private-active-rows246673:fixed-public-nonpadding-rows292206:four-copy-lanes:zero-sized-public-shape:constant-registration-transcript:no-private-depth-length-count-or-family-boundary-disclosure:committed-family-active-prefixes-except-verifier-fixed-temporal-basic-constraints-and-complete-copy-slot-census:inactive-rows-canonical-zero:four-fixed-top-document-slots:top-document-max4096:optional-certificate-slot2-boolean-provenance-bound:depth2-slot2-zero-byte-zero-node-dummy:certificate-slot-active-output-channel:source-byte-and-node-private-joined-der-endpoints:canonical-parent-child-tag-ordinal-grammar:closed-leaf-five-ca-four-extension-cardinality-and-ordinal-bound-critical-positions:no-host-role-labels:extension-embedded-exact-copy:algorithm-and-profile-fixed-byte-rows:decimal-calendar-to-unix-arithmetic:gregorian-euclidean-year-quotients-and-exact-leap-bit:utc1970-2049-generalized2050-9999-actual-der-tag-and-raw-year-bound:fixed72-authenticated-document-role-instance-time-slots:complete-der-time-node-census:fixed15-decimal-byte-rows-including-z-and-zero-utc-padding:fixed73-two-phase-relations-with-verifier-public-operands-and-only-next-update-strict:entry-count-equals64-boolean-entry-census:38-bit-nonwrapping-timestamp-and-slack:range-byte-before-after-transition-bound:four-lane-affine-one-plus-tuple-logarithmic-lookup-domains100-101:singular-inverse-zero-and-exact-singular-count:bounded-public-presentation-window:private-certificate-validity-covers-window:private-crl-interval-covers-window:basic-constraints-fixed-three-slots-twelve-rows-original-signed-extension-ordinal3-complete-bytes-eight-canonical-u32-integer-variants-32bit-pathlen-and-nonwrapping-slack-at-least-subordinate-count:ku-eku-bc:serial-positive-max20:complete-crl-max64:fixed-two-phase-serial-comparator-layout:fixed-seven-phase-calendar-copy-layout:max-serial-comparisons127:max-serial-comparator-logical-rows2667:max-serial-comparator-physical-rows5334:max-serial-source-rows5334:leaf-vs-every-entry-nonmembership:adjacent-revoked-serial-strict-increasing-unsigned-magnitude:length-then-byte-lexicographic:active-prefix-count-and-zero-padding:first-magnitude-byte-nonzero:first-difference-range-checked:der-integer-optional-sign-octet-bound:serial-source-node-and-byte-zero-safe-log-lookups-with-singular-count-equality:serial-decimal-relation-to-comparator-calendar-range-four-lane-grand-product:one-compressed-factor-per-physical-row:zero-product-factors-total-no-prover-abort:full-input-affine-degree-audit:issuer-name-and-aki-ski-byte-equality:fixed-five-document-sha-call-sources:fixed-three-certificate-signature-key-slots:depth2-third-tbs-signature-key-canonical-dummy:full-signed-crl-commitment-and-tbs-p256-message-distinct:producer-and-consumer-terminals-enumerated:thirty-nine-relation-four-lane-union-bound-at-least170-bits:canonical-base-fixed-aux-column-provider:eighteen-verifier-fixed-output-role-endpoint-selectors:nine-independent-normalized-producer-and-nine-actual-consumer-four-lane-products:governed-root-spki-and-certificate-slot-active-products-air-bound:four-private-governed-root-consumer-to-original-CA-polynomial-links:private-normalized-producer-to-consumer36-final-equalities:16-native-constant-private-sha-bridge-columns:16-sha-quartic-endpoint-plus4-rfc-quartic-union-main-joins:endpoint-map6,2,2,2,3,3,2,4,3:direction0:instance0:typed-family-role-endpoint-lane-addresses:no-der-public-claim-slots:der-rfc8-private-linear-quotients:verifier-original-polynomial-private-link-replay:no-public-terminal-products:sha-terminal-ca-call-family-lane-addresses-fixed:compact-ca-call-role-and-order-fixed:verifier-committed-sha-terminal-replay:five-p256-witnesses-native-rust-fixed-certificate-crl-wallet-order:p256348-private-products-no-public-codec:p256184-private-linear-links:four-certificate-or-crl-then-wallet-role-order:p256-bus-cross-start-terminal-and-sink-addresses-fixed:canonical-goldilocks-big-endian:verifier-authenticated-p256-private-oods-link-equations:compact-ca-subproof-dedicated-x5c1-x5c2-complete:ca-claim-free-frame10bytes-main-frame1002-joint132-Fp4-openings4224:ca-single-log12-trace4096-base695-aux128-fixed80-constraints1363-degree3-4chunks:ca-local-lde-log16-mask2100-deep52800-fri136-rounds6-terminal1024-degree143-grinding20:shared-x5b1-single-joined-main-base-root-plus-ca-base-root-challenge-schedule:ca-public-profile-and-root-bound:ca-prover-self-verifies-independent-verifier-and-resource-gates:integration=complete-via-main-aggregate:standalone-activation=not-applicable";
/// SHA-256 of [`ZK_X509_RFC5280_STARK_DESCRIPTOR_V1`].
#[cfg(test)]
pub(crate) const ZK_X509_RFC5280_STARK_DESCRIPTOR_SHA256_V1: [u8; 32] = [
    0x34, 0x1c, 0x8f, 0x9f, 0x2a, 0xb8, 0x46, 0xc1, 0x81, 0x68, 0x73, 0x90, 0x8c, 0x39, 0x68, 0x41,
    0x3a, 0x76, 0x1e, 0x55, 0x82, 0x38, 0x1a, 0xd3, 0x2e, 0xd7, 0x21, 0x5b, 0x6e, 0x86, 0x75, 0x60,
];
/// Native trace logarithm after the 4 KiB X.509 admission cap.
pub(crate) const ZK_X509_RFC5280_STARK_TRACE_LOG2_V1: u8 = 19;
/// Native trace size.
pub(crate) const ZK_X509_RFC5280_STARK_TRACE_SIZE_V1: usize =
    1 << ZK_X509_RFC5280_STARK_TRACE_LOG2_V1;
/// Base columns, including committed private row-activity and chain-depth selectors.
pub(crate) const ZK_X509_RFC5280_STARK_BASE_WIDTH_V1: usize = 285;
/// Six shared-bus product pairs, eighteen independent output-role products, one serial-copy product
/// pair, and two zero-safe DER-backed byte/node lookups in four lanes,
/// shared by serial, semantic and fixed public-key output queries.
pub(crate) const ZK_X509_RFC5280_STARK_AUX_WIDTH_V1: usize = 280;
/// Verifier-preprocessed family, boundary, address, and output-role columns.
pub(crate) const ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1: usize = 147;
/// Exact opened-row residue inventory.
pub(crate) const ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1: usize = {
    let mut total = 51;
    let mut index = 0;
    while index < RFC5280_RESIDUE_SECTIONS_V1.len() {
        total += RFC5280_RESIDUE_SECTIONS_V1[index].1;
        index += 1;
    }
    total
};
/// Auditable evaluator-section inventory. The ordering follows the shared
/// RFC relation evaluator, including the reference terminal equations.
const RFC5280_RESIDUE_SECTIONS_V1: [(&str, usize); 20] = [
    ("common", 13),
    ("degree-normalization-helpers", 19),
    ("source-families", 4 + copy_census::RESIDUES),
    ("source-node-grammar", 74),
    ("grammar-ordinal-local", 34),
    (
        "fixed-equal-decimal-and-name-uniqueness",
        56 + name_policy::RESIDUES + name_values::RESIDUES + profile_identity::RESIDUES,
    ),
    (
        "calendar",
        11 + calendar::RESIDUES_V1 + binding::RESIDUES_V1,
    ),
    ("relation-basic-constraints", 3 + path_len::RESIDUES),
    ("serial-source", 29),
    ("serial-compare", 82),
    ("range-profile", 12),
    (
        "output-metadata-and-private-geometry",
        11 + OUTPUT_SOURCE_RESIDUES_V1
            + variable_output::RESIDUES
            + projection_serial::RESIDUES
            + projection_disclosure::RESIDUES
            + ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
    ),
    ("der-products-and-private-sha-bridge-constancy", 40),
    (
        "private-output-equalities-and-external-consumers",
        RFC5280_TERMINAL_RESIDUES_V1,
    ),
    ("output-role-products", 144),
    ("shared-copy-products", 28),
    ("grammar-ordinal-products", 28),
    ("profile-lookups", 96),
    ("serial-lookups", 144),
    ("grammar-lookups", 144),
];
/// Maximum committed-column degree.
pub(crate) const ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1: u8 = 4;
/// Copy/call bus challenge lanes. This must remain equal to strict DER.
pub(crate) const ZK_X509_RFC5280_STARK_BUS_LANES_V1: usize = 4;
/// Maximum compressed events in any one relation.
pub(crate) const ZK_X509_RFC5280_STARK_RELATION_EVENT_BOUND_V1: usize =
    ZK_X509_RFC5280_STARK_TRACE_SIZE_V1;
/// Conservatively union-bounded compressed relations, including the
/// DER-byte/DER-node serial/key-source lookups, serial copy bus, and the unified
/// authenticated temporal/numeric lookup, plus nine normalized output role equalities.
pub(crate) const ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1: usize = 39;
/// Conservative remaining collision-security bits.
///
/// For Goldilocks `p = 2^64 - 2^32 + 1`, `p - 1 > 2^63`.  Each lane's
/// collision polynomial has degree at most `N = 2^19`; four independent lanes
/// therefore fail with probability `< (2^19 / 2^63)^4 = 2^-176`.  A union
/// over at most thirty-nine relations is `< 39 * 2^-176 < 2^-170`.
pub(crate) const ZK_X509_RFC5280_STARK_COPY_SOUNDNESS_BITS_V1: u16 = 170;
const RFC_TUPLE_CHALLENGE_LABELS_V1: [&[u8]; 12] = [
    b"zk-x509-rfc5280-bus-tuple-slot-00-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-01-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-02-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-03-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-04-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-05-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-06-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-07-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-08-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-09-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-10-v1",
    b"zk-x509-rfc5280-bus-tuple-slot-11-v1",
];
const MAX_TOP_LEVEL_SOURCE_BYTES_V1: usize =
    ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 * ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1;
// Embedded extension payloads are disjoint slices of the admitted top-level
// documents, so their combined byte count cannot exceed the same 16 KiB.
const MAX_EMBEDDED_SOURCE_BYTES_V1: usize = MAX_TOP_LEVEL_SOURCE_BYTES_V1;
const MAX_SOURCE_BYTES_V1: usize = MAX_TOP_LEVEL_SOURCE_BYTES_V1 + MAX_EMBEDDED_SOURCE_BYTES_V1;
const MAX_SOURCE_NODES_V1: usize =
    (ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 + ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1) * 2_048;
const MAX_SOURCE_DOCUMENTS_V1: usize =
    ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 + ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1;
const SERIAL_COMPARISON_WIDTH_V1: usize = 1 + ZK_X509_MAX_SERIAL_BYTES_V1;
const MAX_SERIAL_COMPARISONS_V1: usize = 2 * ZK_X509_MAX_CRL_ENTRIES_V1 - 1;
const MAX_SERIAL_COMPARISON_ROWS_V1: usize = MAX_SERIAL_COMPARISONS_V1 * SERIAL_COMPARISON_WIDTH_V1;
const SERIAL_COMPARISON_PHASES_V1: usize = 2;
const MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1: usize =
    MAX_SERIAL_COMPARISON_ROWS_V1 * SERIAL_COMPARISON_PHASES_V1;
const MAX_SERIAL_SOURCE_ROWS_V1: usize = 2 * MAX_SERIAL_COMPARISON_ROWS_V1;
const CALENDAR_COPY_PHASES_V1: usize = numeric::CALENDAR_PHASES_V1;
const MAX_SEMANTIC_ROWS_V1: usize = 55_360;
// Exact worst-case endpoint bytes after the 4 KiB cap, including both the
// producer and fixed consumer side and the distinct complete-signed-CRL
// padded message/length pair.
const MAX_OUTPUT_EVENT_ROWS_V1: usize = 45_410;
const MAX_ACTIVE_ROWS_V1: usize = name_values::ROWS
    + MAX_SOURCE_BYTES_V1
    + MAX_SOURCE_NODES_V1
    + MAX_EMBEDDED_SOURCE_BYTES_V1
    + ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1
    + (MAX_SOURCE_NODES_V1 - MAX_SOURCE_DOCUMENTS_V1)
    + MAX_SERIAL_SOURCE_ROWS_V1
    + MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1
    + MAX_SEMANTIC_ROWS_V1
    + MAX_OUTPUT_EVENT_ROWS_V1;
// Fixed public registration geometry.  These capacities are independent of
// every private length/count and still fit the native log19 domain.
const FIXED_SOURCE_BYTE_ROWS_V1: usize = MAX_SOURCE_BYTES_V1;
const FIXED_SOURCE_NODE_ROWS_V1: usize = MAX_SOURCE_NODES_V1;
const FIXED_EMBEDDED_COPY_ROWS_V1: usize = MAX_EMBEDDED_SOURCE_BYTES_V1;
const FIXED_GRAMMAR_ROWS_V1: usize = ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1 + MAX_SOURCE_NODES_V1;
const FIXED_FIXED_BYTE_ROWS_V1: usize = 16_384;
const FIXED_EQUAL_BYTE_ROWS_V1: usize = 16_384;
const FIXED_DECIMAL_ROWS_V1: usize = numeric::TEMPORAL_SLOTS_V1 * numeric::DECIMAL_ROWS_PER_TIME_V1;
const FIXED_CALENDAR_ROWS_V1: usize = numeric::TEMPORAL_SLOTS_V1 * CALENDAR_COPY_PHASES_V1;
const FIXED_RELATION_ROWS_V1: usize = numeric::RELATION_SLOTS_V1 * numeric::RELATION_PHASES_V1;
const FIXED_BASIC_CONSTRAINTS_ROWS_V1: usize = 256;
const FIXED_RANGE_ROWS_V1: usize =
    numeric::RELATION_SLOTS_V1 * numeric::RANGE_BYTES_PER_RELATION_V1;
const FIXED_SEMANTIC_SOURCE_ROWS_V1: usize = 32_768;
const FIXED_SEMANTIC_CONSUMER_ROWS_V1: usize = 32_768;
const FIXED_OUTPUT_ROWS_PER_SIDE_V1: usize = MAX_OUTPUT_EVENT_ROWS_V1 / 2;
const FIXED_NON_PADDING_ROWS_V1: usize = FIXED_SOURCE_BYTE_ROWS_V1
    + FIXED_SOURCE_NODE_ROWS_V1
    + FIXED_EMBEDDED_COPY_ROWS_V1
    + FIXED_GRAMMAR_ROWS_V1
    + name_values::ROWS
    + FIXED_FIXED_BYTE_ROWS_V1
    + FIXED_EQUAL_BYTE_ROWS_V1
    + FIXED_DECIMAL_ROWS_V1
    + FIXED_CALENDAR_ROWS_V1
    + FIXED_RELATION_ROWS_V1
    + FIXED_BASIC_CONSTRAINTS_ROWS_V1
    + MAX_SERIAL_SOURCE_ROWS_V1
    + MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1
    + FIXED_RANGE_ROWS_V1
    + FIXED_SEMANTIC_SOURCE_ROWS_V1
    + FIXED_SEMANTIC_CONSUMER_ROWS_V1
    + FIXED_OUTPUT_ROWS_PER_SIDE_V1
    + FIXED_OUTPUT_ROWS_PER_SIDE_V1;
const FIXED_PADDING_ROWS_V1: usize =
    ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - FIXED_NON_PADDING_ROWS_V1;
const _: () = assert!(ZK_X509_RFC5280_STARK_BUS_LANES_V1 == ZK_X509_DER_STARK_BUS_LANES_V1);
const _: () = assert!(MAX_ACTIVE_ROWS_V1 <= ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
const _: () = assert!(MAX_OUTPUT_EVENT_ROWS_V1 % 2 == 0);
const _: () = assert!(FIXED_NON_PADDING_ROWS_V1 < ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
const _: () = assert!(ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1 <= u16::MAX as usize);
const _: () = {
    let mut section = 0;
    let mut total = 0;
    while section < RFC5280_RESIDUE_SECTIONS_V1.len() {
        total += RFC5280_RESIDUE_SECTIONS_V1[section].1;
        section += 1;
    }
    assert!(total + 51 == ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1);
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
const fn serial_comparison_count_v1(crl_entries: usize) -> usize {
    if crl_entries == 0 {
        0
    } else {
        2 * crl_entries - 1
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
const fn serial_comparison_rows_v1(crl_entries: usize) -> usize {
    serial_comparison_count_v1(crl_entries) * SERIAL_COMPARISON_WIDTH_V1
}
fn serial_comparison_descriptor_v1(
    comparison: usize,
) -> Result<(ZkX509Rfc5280SerialComparisonKindV1, u16, u16), ZkX509Rfc5280StarkErrorV1> {
    if comparison >= MAX_SERIAL_COMPARISONS_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    if comparison == 0 || comparison % 2 == 1 {
        let entry = if comparison == 0 {
            0
        } else {
            (comparison + 1) / 2
        };
        return Ok((
            ZkX509Rfc5280SerialComparisonKindV1::LeafNonMembership,
            0,
            u16::try_from(entry + 1).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        ));
    }
    let adjacent = comparison / 2 - 1;
    Ok((
        ZkX509Rfc5280SerialComparisonKindV1::AdjacentStrictOrder,
        u16::try_from(adjacent + 1).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        u16::try_from(adjacent + 2).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
    ))
}
fn serial_source_descriptor_v1(
    ordinal: usize,
) -> Result<(u16, u16, ZkX509Rfc5280GrammarRoleV1, u16), ZkX509Rfc5280StarkErrorV1> {
    let source_group = ordinal / SERIAL_COMPARISON_WIDTH_V1;
    let comparison = source_group / 2;
    let right_side = source_group % 2 == 1;
    let offset = ordinal % SERIAL_COMPARISON_WIDTH_V1;
    let (_, left_instance, right_instance) = serial_comparison_descriptor_v1(comparison)?;
    let logical_id = if right_side {
        right_instance
    } else {
        left_instance
    };
    let (role, role_instance) = if logical_id == 0 {
        (ZkX509Rfc5280GrammarRoleV1::CertificateSerial, 0)
    } else {
        (ZkX509Rfc5280GrammarRoleV1::CrlEntrySerial, logical_id - 1)
    };
    Ok((
        logical_id,
        u16::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        role,
        role_instance,
    ))
}
/// Fixed row families in canonical schedule order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ZkX509Rfc5280StarkFamilyV1 {
    SourceByte = 0,
    SourceNode = 1,
    EmbeddedCopy = 2,
    Grammar = 3,
    FixedByte = 4,
    EqualByte = 5,
    Decimal = 6,
    Calendar = 7,
    Relation = 8,
    BasicConstraints = 9,
    SerialSource = 10,
    SerialCompare = 11,
    RangeByte = 12,
    SemanticSource = 13,
    SemanticConsumer = 14,
    OutputProducer = 15,
    OutputConsumer = 16,
    NameValue = 17,
    Padding = 18,
}
const FAMILY_COUNT_V1: usize = ZkX509Rfc5280StarkFamilyV1::Padding as usize + 1;
/// Topology-neutral purpose of a producer/consumer output event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum ZkX509Rfc5280OutputRoleV1 {
    Projection = 1,
    CertificateTbsSha = 2,
    CrlTbsP256Message = 3,
    CrlCommitment = 4,
    P256Signature = 5,
    P256PublicKey = 6,
    IssuerSpkiSha = 7,
    GovernedTrustAnchor = 8,
    /// Private optional-certificate selector copied to the P-256 aggregate.
    CertificateSlotActive = 9,
}
const OUTPUT_ROLE_COUNT_V1: usize = ZkX509Rfc5280OutputRoleV1::CertificateSlotActive as usize;
#[cfg(test)]
const OUTPUT_ROLES_V1: [ZkX509Rfc5280OutputRoleV1; OUTPUT_ROLE_COUNT_V1] = [
    ZkX509Rfc5280OutputRoleV1::Projection,
    ZkX509Rfc5280OutputRoleV1::CertificateTbsSha,
    ZkX509Rfc5280OutputRoleV1::CrlTbsP256Message,
    ZkX509Rfc5280OutputRoleV1::CrlCommitment,
    ZkX509Rfc5280OutputRoleV1::P256Signature,
    ZkX509Rfc5280OutputRoleV1::P256PublicKey,
    ZkX509Rfc5280OutputRoleV1::IssuerSpkiSha,
    ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor,
    ZkX509Rfc5280OutputRoleV1::CertificateSlotActive,
];
#[cfg(test)]
fn output_role_from_index_v1(index: usize) -> Option<ZkX509Rfc5280OutputRoleV1> {
    OUTPUT_ROLES_V1.get(index).copied()
}
/// Private witness geometry.  None of these values is transcript material.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280StarkPrivateShapeV1 {
    pub(crate) chain_depth: u8,
    /// Committed selector copied to fixed certificate slot two.
    pub(crate) certificate_slot_2_active: F,
    pub(crate) top_document_count: u8,
    pub(crate) top_document_lengths: [u16; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1],
    pub(crate) top_node_counts: [u16; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1],
    pub(crate) embedded_document_count: u8,
    pub(crate) embedded_document_lengths: [u16; ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1],
    pub(crate) embedded_node_counts: [u16; ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1],
    pub(crate) crl_entries: u8,
    pub(crate) disclosed_attributes: u8,
    pub(crate) embedded_copy_rows: u32,
    pub(crate) grammar_rows: u32,
    pub(crate) fixed_byte_rows: u32,
    pub(crate) name_value_rows: u32,
    pub(crate) equality_rows: u32,
    pub(crate) decimal_rows: u32,
    pub(crate) calendar_rows: u32,
    pub(crate) relation_rows: u32,
    pub(crate) basic_constraints_rows: u32,
    pub(crate) serial_source_rows: u32,
    pub(crate) serial_rows: u32,
    pub(crate) range_rows: u32,
    pub(crate) semantic_source_rows: u32,
    pub(crate) semantic_consumer_rows: u32,
    pub(crate) output_producer_rows: u32,
    pub(crate) output_consumer_rows: u32,
    pub(crate) io_channels: u16,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280StarkPrivateShapeV1 {
    fn checked_sum(
        values: impl IntoIterator<Item = usize>,
    ) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
        values
            .into_iter()
            .try_fold(0_usize, |sum, value| sum.checked_add(value))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)
    }
    pub(crate) fn source_bytes(&self) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
        let top = self.top_document_lengths[..usize::from(self.top_document_count)]
            .iter()
            .map(|value| usize::from(*value));
        let embedded = self.embedded_document_lengths[..usize::from(self.embedded_document_count)]
            .iter()
            .map(|value| usize::from(*value));
        Self::checked_sum(top.chain(embedded))
    }
    pub(crate) fn source_nodes(&self) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
        let top = self.top_node_counts[..usize::from(self.top_document_count)]
            .iter()
            .map(|value| usize::from(*value));
        let embedded = self.embedded_node_counts[..usize::from(self.embedded_document_count)]
            .iter()
            .map(|value| usize::from(*value));
        Self::checked_sum(top.chain(embedded))
    }
    pub(crate) fn family_counts(
        &self,
    ) -> Result<[usize; FAMILY_COUNT_V1], ZkX509Rfc5280StarkErrorV1> {
        let mut counts = [0_usize; FAMILY_COUNT_V1];
        counts[ZkX509Rfc5280StarkFamilyV1::SourceByte as usize] = self.source_bytes()?;
        counts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize] = self.source_nodes()?;
        counts[ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy as usize] =
            usize::try_from(self.embedded_copy_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::Grammar as usize] =
            usize::try_from(self.grammar_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::FixedByte as usize] =
            usize::try_from(self.fixed_byte_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::NameValue as usize] =
            usize::try_from(self.name_value_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::EqualByte as usize] =
            usize::try_from(self.equality_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::Decimal as usize] =
            usize::try_from(self.decimal_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::Calendar as usize] =
            usize::try_from(self.calendar_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::Relation as usize] =
            usize::try_from(self.relation_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize] =
            usize::try_from(self.basic_constraints_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::SerialSource as usize] =
            usize::try_from(self.serial_source_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize] =
            usize::try_from(self.serial_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::RangeByte as usize] =
            usize::try_from(self.range_rows).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::SemanticSource as usize] =
            usize::try_from(self.semantic_source_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::SemanticConsumer as usize] =
            usize::try_from(self.semantic_consumer_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] =
            usize::try_from(self.output_producer_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        counts[ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize] =
            usize::try_from(self.output_consumer_rows)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        let active = Self::checked_sum(
            counts[..ZkX509Rfc5280StarkFamilyV1::Padding as usize]
                .iter()
                .copied(),
        )?;
        counts[ZkX509Rfc5280StarkFamilyV1::Padding as usize] = ZK_X509_RFC5280_STARK_TRACE_SIZE_V1
            .checked_sub(active)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        Ok(counts)
    }
    pub(crate) fn active_rows(&self) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
        let counts = self.family_counts()?;
        Self::checked_sum(
            counts[..ZkX509Rfc5280StarkFamilyV1::Padding as usize]
                .iter()
                .copied(),
        )
    }
    pub(crate) fn validate(&self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        let top_count = usize::from(self.top_document_count);
        let embedded_count = usize::from(self.embedded_document_count);
        if !(2..=3).contains(&usize::from(self.chain_depth))
            || self
                .certificate_slot_2_active
                .mul(self.certificate_slot_2_active.sub(F::ONE))
                != F::ZERO
            || self.certificate_slot_2_active != F(u64::from(usize::from(self.chain_depth) == 3))
            || top_count != usize::from(self.chain_depth) + 1
            || top_count > ZK_X509_DER_AIR_MAX_DOCUMENTS_V1
            || embedded_count > ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1
            || embedded_count != 4 * usize::from(self.chain_depth) + 3
            || usize::from(self.crl_entries) > ZK_X509_MAX_CRL_ENTRIES_V1
            || self.disclosed_attributes > 4
            || self
                .top_document_lengths
                .iter()
                .enumerate()
                .any(|(slot, length)| {
                    let required = slot < top_count;
                    if required {
                        *length == 0
                            || usize::from(*length)
                                > ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
                    } else {
                        *length != 0
                    }
                })
            || self
                .top_node_counts
                .iter()
                .enumerate()
                .any(|(slot, count)| {
                    let required = slot < top_count;
                    if required {
                        *count == 0 || *count > 2_048
                    } else {
                        *count != 0
                    }
                })
            || self.embedded_document_lengths[..embedded_count]
                .iter()
                .any(|length| *length == 0)
            || self.embedded_document_lengths[embedded_count..]
                .iter()
                .any(|length| *length != 0)
            || self.embedded_node_counts[..embedded_count]
                .iter()
                .any(|count| *count == 0 || *count > 2_048)
            || self.embedded_node_counts[embedded_count..]
                .iter()
                .any(|count| *count != 0)
            || self.embedded_copy_rows as usize
                != copy_census::active_rows(
                    ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
                    self.chain_depth == 3,
                )
            || self.equality_rows as usize
                != copy_census::active_rows(
                    ZkX509Rfc5280StarkFamilyV1::EqualByte,
                    self.chain_depth == 3,
                )
            || self.semantic_consumer_rows as usize
                != copy_census::active_rows(
                    ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
                    self.chain_depth == 3,
                )
            || self.grammar_rows as usize
                != self
                    .source_nodes()?
                    .checked_sub(top_count.saturating_add(embedded_count))
                    .and_then(|rows| rows.checked_add(ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1))
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?
            || self.calendar_rows as usize
                != usize::from(self.chain_depth)
                    .saturating_mul(2)
                    .saturating_add(2)
                    .saturating_add(usize::from(self.crl_entries))
                    .saturating_mul(CALENDAR_COPY_PHASES_V1)
            || self.serial_source_rows as usize
                != serial_comparison_rows_v1(usize::from(self.crl_entries)).saturating_mul(2)
            || self.serial_rows as usize
                != serial_comparison_rows_v1(usize::from(self.crl_entries))
                    .saturating_mul(SERIAL_COMPARISON_PHASES_V1)
            || self.output_producer_rows != self.output_consumer_rows
            || self.embedded_copy_rows as usize > FIXED_EMBEDDED_COPY_ROWS_V1
            || self.grammar_rows as usize > FIXED_GRAMMAR_ROWS_V1
            || self.name_value_rows as usize > name_values::ROWS
            || self.fixed_byte_rows as usize > FIXED_FIXED_BYTE_ROWS_V1
            || self.equality_rows as usize > FIXED_EQUAL_BYTE_ROWS_V1
            || self.decimal_rows as usize > FIXED_DECIMAL_ROWS_V1
            || self.calendar_rows as usize > FIXED_CALENDAR_ROWS_V1
            || self.relation_rows as usize > FIXED_RELATION_ROWS_V1
            || self.basic_constraints_rows as usize > FIXED_BASIC_CONSTRAINTS_ROWS_V1
            || self.serial_source_rows as usize > MAX_SERIAL_SOURCE_ROWS_V1
            || self.serial_rows as usize > MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1
            || self.range_rows as usize > FIXED_RANGE_ROWS_V1
            || self.semantic_source_rows as usize > FIXED_SEMANTIC_SOURCE_ROWS_V1
            || self.semantic_consumer_rows as usize > FIXED_SEMANTIC_CONSUMER_ROWS_V1
            || self.output_producer_rows as usize > FIXED_OUTPUT_ROWS_PER_SIDE_V1
            || self.output_consumer_rows as usize > FIXED_OUTPUT_ROWS_PER_SIDE_V1
            || (self.fixed_byte_rows as usize)
                .saturating_add(self.equality_rows as usize)
                .saturating_add(self.decimal_rows as usize)
                .saturating_add(self.calendar_rows as usize)
                .saturating_add(self.relation_rows as usize)
                .saturating_add(self.basic_constraints_rows as usize)
                .saturating_add(self.range_rows as usize)
                .saturating_add(self.semantic_source_rows as usize)
                .saturating_add(self.semantic_consumer_rows as usize)
                > MAX_SEMANTIC_ROWS_V1
            || self.output_producer_rows as usize > MAX_OUTPUT_EVENT_ROWS_V1 / 2
            || self.active_rows()? > MAX_ACTIVE_ROWS_V1
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        let embedded_bytes: usize = self.embedded_document_lengths[..embedded_count]
            .iter()
            .map(|length| usize::from(*length))
            .sum();
        let top_bytes: usize = self.top_document_lengths[..top_count]
            .iter()
            .map(|length| usize::from(*length))
            .sum();
        if embedded_bytes > top_bytes
            || self.source_bytes()? > MAX_SOURCE_BYTES_V1
            || self.source_nodes()? > MAX_SOURCE_NODES_V1
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        Ok(())
    }
}
/// Fixed-size verifier projection of the public RFC 5280 statement.
///
/// Private chain depth, document geometry, certificate validity intervals,
/// CRL-entry count, and all DER bytes remain absent.  The values retained
/// here are exactly those needed to regenerate public fixed columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280StarkShapeV1 {
    presentation_not_before_unix_seconds: u64,
    presentation_not_after_unix_seconds: u64,
    leaf_key_usage: u16,
    leaf_extended_key_usage_count: u8,
    leaf_extended_key_usages: [u8; 3],
    crl_number: u64,
    disclosed_attribute_count: u8,
    disclosed_attribute_indices: [u8; 4],
}
impl Default for ZkX509Rfc5280StarkShapeV1 {
    fn default() -> Self {
        Self {
            presentation_not_before_unix_seconds: 1,
            presentation_not_after_unix_seconds: 2,
            leaf_key_usage: 1,
            leaf_extended_key_usage_count: 1,
            leaf_extended_key_usages: [1, 0, 0],
            crl_number: 1,
            disclosed_attribute_count: 0,
            disclosed_attribute_indices: [0; 4],
        }
    }
}
impl ZkX509Rfc5280StarkShapeV1 {
    pub(crate) fn from_statement(
        statement: &ZkX509Rfc5280StatementV1,
    ) -> Result<Self, ZkX509Rfc5280StarkErrorV1> {
        let mut leaf_extended_key_usages = [0_u8; 3];
        if statement.leaf_extended_key_usages.len() > leaf_extended_key_usages.len() {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        for (output, usage) in leaf_extended_key_usages
            .iter_mut()
            .zip(statement.leaf_extended_key_usages.iter().copied())
        {
            *output = eku_code_v1(usage);
        }
        let mut disclosed_attribute_indices = [0_u8; 4];
        if statement.disclosed_attribute_indices.len() > disclosed_attribute_indices.len() {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        disclosed_attribute_indices[..statement.disclosed_attribute_indices.len()]
            .copy_from_slice(&statement.disclosed_attribute_indices);
        let shape = Self {
            presentation_not_before_unix_seconds: statement.presentation_not_before_unix_seconds,
            presentation_not_after_unix_seconds: statement.presentation_not_after_unix_seconds,
            leaf_key_usage: statement.leaf_key_usage,
            leaf_extended_key_usage_count: u8::try_from(statement.leaf_extended_key_usages.len())
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            leaf_extended_key_usages,
            crl_number: statement.crl_number,
            disclosed_attribute_count: u8::try_from(statement.disclosed_attribute_indices.len())
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            disclosed_attribute_indices,
        };
        shape.validate()?;
        Ok(shape)
    }
    /// Original disclosure count retained by the validated public statement shape.
    pub(super) const fn disclosed_attribute_count(&self) -> u8 {
        self.disclosed_attribute_count
    }
    pub(crate) const fn family_counts(&self) -> [usize; FAMILY_COUNT_V1] {
        [
            FIXED_SOURCE_BYTE_ROWS_V1,
            FIXED_SOURCE_NODE_ROWS_V1,
            FIXED_EMBEDDED_COPY_ROWS_V1,
            FIXED_GRAMMAR_ROWS_V1,
            FIXED_FIXED_BYTE_ROWS_V1,
            FIXED_EQUAL_BYTE_ROWS_V1,
            FIXED_DECIMAL_ROWS_V1,
            FIXED_CALENDAR_ROWS_V1,
            FIXED_RELATION_ROWS_V1,
            FIXED_BASIC_CONSTRAINTS_ROWS_V1,
            MAX_SERIAL_SOURCE_ROWS_V1,
            MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1,
            FIXED_RANGE_ROWS_V1,
            FIXED_SEMANTIC_SOURCE_ROWS_V1,
            FIXED_SEMANTIC_CONSUMER_ROWS_V1,
            FIXED_OUTPUT_ROWS_PER_SIDE_V1,
            FIXED_OUTPUT_ROWS_PER_SIDE_V1,
            name_values::ROWS,
            FIXED_PADDING_ROWS_V1,
        ]
    }
    pub(crate) fn validate(&self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        let eku_count = usize::from(self.leaf_extended_key_usage_count);
        let disclosed_count = usize::from(self.disclosed_attribute_count);
        if PrivacyZkX509PresentationWindowV1::new(
            self.presentation_not_before_unix_seconds,
            self.presentation_not_after_unix_seconds,
        )
        .validate()
        .is_err()
            || self.leaf_key_usage == 0
            || eku_count == 0
            || eku_count > self.leaf_extended_key_usages.len()
            || self.leaf_extended_key_usages[..eku_count]
                .iter()
                .any(|usage| !(1..=3).contains(usage))
            || self.leaf_extended_key_usages[..eku_count]
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.leaf_extended_key_usages[eku_count..]
                .iter()
                .any(|usage| *usage != 0)
            || disclosed_count > self.disclosed_attribute_indices.len()
            || self.disclosed_attribute_indices[..disclosed_count]
                .iter()
                .any(|index| *index >= 4)
            || self.disclosed_attribute_indices[..disclosed_count]
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.disclosed_attribute_indices[disclosed_count..]
                .iter()
                .any(|index| *index != 0)
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        let usages = self.leaf_extended_key_usages()?;
        encode_key_usage_v1(self.leaf_key_usage)?;
        encode_eku_v1(&usages)?;
        Ok(())
    }
    fn leaf_extended_key_usages(&self) -> Result<Vec<ZkX509DerEkuV1>, ZkX509Rfc5280StarkErrorV1> {
        self.leaf_extended_key_usages[..usize::from(self.leaf_extended_key_usage_count)]
            .iter()
            .copied()
            .map(eku_from_code_v1)
            .collect()
    }
    /// Canonical public transcript frame; it contains no private geometry.
    #[cfg(test)]
    pub(crate) fn transcript_bytes(&self) -> Result<Vec<u8>, ZkX509Rfc5280StarkErrorV1> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(8 + 8 + 2 + 1 + 3 + 8 + 1 + 4);
        bytes.extend_from_slice(&self.presentation_not_before_unix_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.presentation_not_after_unix_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.leaf_key_usage.to_be_bytes());
        bytes.push(self.leaf_extended_key_usage_count);
        bytes.extend_from_slice(&self.leaf_extended_key_usages);
        bytes.extend_from_slice(&self.crl_number.to_be_bytes());
        bytes.push(self.disclosed_attribute_count);
        bytes.extend_from_slice(&self.disclosed_attribute_indices);
        Ok(bytes)
    }
    #[cfg(test)]
    pub(crate) fn schedule_digest(
        &self,
    ) -> Result<PrivacyOuterDigestV1, ZkX509Rfc5280StarkErrorV1> {
        privacy_outer_digest_frame_v1(
            ZK_X509_DIGEST_CONTEXT_V1,
            b"iroha:privacy:zk-x509:rfc5280-stark-schedule:v1",
            b"rfc5280-public-schedule",
            0,
            0,
            0,
            &[&self.transcript_bytes()?],
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)
    }
}
/// Four post-base tuple-compression lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280StarkChallengesV1 {
    pub(crate) tuple: [[F; 12]; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
}
impl ZkX509Rfc5280StarkChallengesV1 {
    pub(crate) fn validate(self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
            for (index, value) in self.tuple[lane].iter().copied().enumerate() {
                if value == F::ZERO
                    || value.0 >= GOLDILOCKS_MODULUS_V1
                    || F::canonical(value.0).is_none()
                    || self.tuple[lane][..index].contains(&value)
                    || self.tuple[..lane]
                        .iter()
                        .flat_map(|previous| previous.iter())
                        .any(|previous| *previous == value)
                {
                    return Err(ZkX509Rfc5280StarkErrorV1::Challenge);
                }
            }
        }
        Ok(())
    }
}
pub(crate) fn derive_zk_x509_rfc5280_stark_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509Rfc5280StarkChallengesV1, TransparentStarkErrorV1> {
    let mut challenges = ZkX509Rfc5280StarkChallengesV1 {
        tuple: [[F::ZERO; 12]; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
    };
    for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
        for (value, label) in challenges.tuple[lane]
            .iter_mut()
            .zip(RFC_TUPLE_CHALLENGE_LABELS_V1)
        {
            *value = transcript.challenge_field(label)?;
        }
    }
    Ok(challenges)
}
/// Adapter construction or numeric-constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509Rfc5280StarkErrorV1 {
    #[error("zk-X509 RFC 5280 STARK public shape is invalid")]
    Shape,
    #[error("zk-X509 RFC 5280 STARK fixed grammar is invalid")]
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    Grammar,
    #[error("zk-X509 RFC 5280 STARK semantic relation is invalid")]
    Semantic,
    #[error("zk-X509 RFC 5280 STARK source address or multiplicity is invalid")]
    Source,
    #[error("zk-X509 RFC 5280 STARK output topology is invalid")]
    Output,
    #[error("zk-X509 RFC 5280 STARK transcript challenge is invalid")]
    Challenge,
    #[error("zk-X509 RFC/SHA/P-256 STARK terminal-claim encoding is invalid")]
    TerminalClaim,
    #[error("zk-X509 RFC 5280 STARK resource envelope is exceeded")]
    Resource,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl From<ZkX509DerAirErrorV1> for ZkX509Rfc5280StarkErrorV1 {
    fn from(_: ZkX509DerAirErrorV1) -> Self {
        Self::Semantic
    }
}
impl From<ZkX509DerStarkErrorV1> for ZkX509Rfc5280StarkErrorV1 {
    fn from(error: ZkX509DerStarkErrorV1) -> Self {
        match error {
            ZkX509DerStarkErrorV1::Challenge => Self::Challenge,
            #[cfg(any(test, feature = "privacy-release-evidence"))]
            ZkX509DerStarkErrorV1::Resource => Self::Resource,
            _ => Self::Source,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn source_documents_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> impl Iterator<Item = &ZkX509DerDocumentTraceV1> {
    trace.documents.iter().chain(&trace.embedded_documents)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn role_tag_is_admitted_v1(row: ZkX509Rfc5280NodeProvenanceV1) -> bool {
    use ZkX509Rfc5280GrammarRoleV1 as R;
    let tag = (row.tag_class, row.constructed, row.tag_number);
    match row.role {
        R::Certificate
        | R::CertificateTbs
        | R::CertificateOuterAlgorithm
        | R::CertificateTbsAlgorithm
        | R::CertificateValidity
        | R::CertificateSubject
        | R::CertificateIssuer
        | R::CertificateSpki
        | R::CertificateSpkiAlgorithm
        | R::CertificateExtensions
        | R::CertificateExtension
        | R::Crl
        | R::CrlTbs
        | R::CrlOuterAlgorithm
        | R::CrlTbsAlgorithm
        | R::CrlIssuer
        | R::CrlEntries
        | R::CrlEntry
        | R::CrlExtensions
        | R::CrlExtension
        | R::NameAttribute
        | R::EmbeddedAki
        | R::EmbeddedBasicConstraints
        | R::EmbeddedEku => tag == (0, true, 16),
        R::NameRdn => tag == (0, true, 17),
        R::CertificateVersion => tag == (2, true, 0),
        R::CertificateExtensionsWrapper => tag == (2, true, 3),
        R::CrlExtensionsWrapper => tag == (2, true, 0),
        R::CertificateVersionInteger
        | R::CertificateSerial
        | R::CrlVersion
        | R::CrlEntrySerial
        | R::EmbeddedBasicConstraintsPathLen
        | R::EmbeddedCrlNumber => tag == (0, false, 2),
        R::CertificateSignatureValue
        | R::CertificatePublicKey
        | R::CrlSignatureValue
        | R::EmbeddedKeyUsage => tag == (0, false, 3),
        R::CertificateExtensionOid
        | R::CrlExtensionOid
        | R::NameAttributeOid
        | R::AlgorithmOid
        | R::EmbeddedEkuOid => tag == (0, false, 6),
        R::CertificateExtensionCritical
        | R::CrlExtensionCritical
        | R::EmbeddedBasicConstraintsCa => tag == (0, false, 1),
        R::CertificateExtensionValue | R::CrlExtensionValue | R::EmbeddedSki => {
            tag == (0, false, 4)
        }
        R::EmbeddedAkiIdentifier => tag == (2, false, 0),
        R::CertificateNotBefore
        | R::CertificateNotAfter
        | R::CrlThisUpdate
        | R::CrlNextUpdate
        | R::CrlEntryTime => {
            row.tag_class == 0 && !row.constructed && matches!(row.tag_number, 23 | 24)
        }
        R::NameAttributeValue => {
            row.tag_class == 0 && !row.constructed && matches!(row.tag_number, 12 | 19)
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn root_role_v1(kind: ZkX509Rfc5280DocumentKindV1) -> ZkX509Rfc5280GrammarRoleV1 {
    use ZkX509Rfc5280DocumentKindV1 as D;
    use ZkX509Rfc5280GrammarRoleV1 as R;
    match kind {
        D::Certificate => R::Certificate,
        D::Crl => R::Crl,
        D::AuthorityKeyIdentifier => R::EmbeddedAki,
        D::SubjectKeyIdentifier => R::EmbeddedSki,
        D::KeyUsage => R::EmbeddedKeyUsage,
        D::BasicConstraints => R::EmbeddedBasicConstraints,
        D::ExtendedKeyUsage => R::EmbeddedEku,
        D::CrlNumber => R::EmbeddedCrlNumber,
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn expected_child_role_v1(
    document: &ZkX509Rfc5280DocumentProvenanceV1,
    parent: ZkX509Rfc5280NodeProvenanceV1,
    child: ZkX509Rfc5280NodeProvenanceV1,
    child_count: usize,
) -> Result<(ZkX509Rfc5280GrammarRoleV1, u16), ZkX509Rfc5280StarkErrorV1> {
    use ZkX509Rfc5280GrammarRoleV1 as R;
    let ordinal = usize::from(child.child_ordinal);
    let inherited = parent.role_instance;
    let result = match parent.role {
        R::Certificate => match ordinal {
            0 => (R::CertificateTbs, inherited),
            1 => (R::CertificateOuterAlgorithm, 0),
            2 => (R::CertificateSignatureValue, inherited),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CertificateTbs => match ordinal {
            0 => (R::CertificateVersion, inherited),
            1 => (R::CertificateSerial, inherited),
            2 => (R::CertificateTbsAlgorithm, 1),
            3 => (R::CertificateIssuer, 0),
            4 => (R::CertificateValidity, inherited),
            5 => (R::CertificateSubject, 1),
            6 => (R::CertificateSpki, inherited),
            7 => (R::CertificateExtensionsWrapper, 0),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CertificateVersion if ordinal == 0 => (R::CertificateVersionInteger, inherited),
        R::CertificateOuterAlgorithm
        | R::CertificateTbsAlgorithm
        | R::CertificateSpkiAlgorithm
        | R::CrlOuterAlgorithm
        | R::CrlTbsAlgorithm => (
            R::AlgorithmOid,
            inherited
                .checked_mul(4)
                .and_then(|instance| instance.checked_add(child.child_ordinal))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        ),
        R::CertificateIssuer | R::CertificateSubject | R::CrlIssuer => (
            R::NameRdn,
            inherited
                .checked_mul(256)
                .and_then(|instance| instance.checked_add(child.child_ordinal))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        ),
        R::NameRdn => {
            let name = inherited / 256;
            let rdn = inherited % 256;
            (
                R::NameAttribute,
                name.checked_mul(1024)
                    .and_then(|instance| instance.checked_add(rdn.checked_mul(16)?))
                    .and_then(|instance| instance.checked_add(child.child_ordinal))
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
            )
        }
        R::NameAttribute => match ordinal {
            0 => (R::NameAttributeOid, inherited),
            1 => (R::NameAttributeValue, inherited),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CertificateValidity => match ordinal {
            0 => (R::CertificateNotBefore, inherited),
            1 => (R::CertificateNotAfter, inherited),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CertificateSpki => match ordinal {
            0 => (R::CertificateSpkiAlgorithm, 2),
            1 => (R::CertificatePublicKey, inherited),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CertificateExtensionsWrapper if ordinal == 0 => (R::CertificateExtensions, 0),
        R::CertificateExtensions => (R::CertificateExtension, child.child_ordinal),
        R::CertificateExtension => {
            let role = if ordinal == 0 {
                R::CertificateExtensionOid
            } else if child_count == 3 && ordinal == 1 {
                R::CertificateExtensionCritical
            } else if ordinal + 1 == child_count {
                R::CertificateExtensionValue
            } else {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            };
            (role, inherited)
        }
        R::Crl => match ordinal {
            0 => (R::CrlTbs, 0),
            1 => (R::CrlOuterAlgorithm, 3),
            2 => (R::CrlSignatureValue, 0),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CrlTbs => {
            let has_entries = child_count == 7;
            match ordinal {
                0 => (R::CrlVersion, 0),
                1 => (R::CrlTbsAlgorithm, 4),
                2 => (R::CrlIssuer, 2),
                3 => (R::CrlThisUpdate, 0),
                4 => (R::CrlNextUpdate, 0),
                5 if has_entries => (R::CrlEntries, 0),
                5 | 6 => (R::CrlExtensionsWrapper, 0),
                _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
            }
        }
        R::CrlEntries => (R::CrlEntry, child.child_ordinal),
        R::CrlEntry => match ordinal {
            0 => (R::CrlEntrySerial, inherited),
            1 => (R::CrlEntryTime, inherited),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::CrlExtensionsWrapper if ordinal == 0 => (R::CrlExtensions, 0),
        R::CrlExtensions => (R::CrlExtension, child.child_ordinal),
        R::CrlExtension => {
            let role = if ordinal == 0 {
                R::CrlExtensionOid
            } else if child_count == 3 && ordinal == 1 {
                R::CrlExtensionCritical
            } else if ordinal + 1 == child_count {
                R::CrlExtensionValue
            } else {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            };
            (role, inherited)
        }
        R::EmbeddedAki if ordinal == 0 => (R::EmbeddedAkiIdentifier, 0),
        R::EmbeddedBasicConstraints => match ordinal {
            0 => (R::EmbeddedBasicConstraintsCa, 0),
            1 => (R::EmbeddedBasicConstraintsPathLen, 0),
            _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
        },
        R::EmbeddedEku => (R::EmbeddedEkuOid, child.child_ordinal),
        _ => return Err(ZkX509Rfc5280StarkErrorV1::Grammar),
    };
    if document.kind == ZkX509Rfc5280DocumentKindV1::Certificate
        && matches!(result.0, R::CrlTbs | R::CrlEntry | R::CrlExtension)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    Ok(result)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZkX509Rfc5280GrammarRuleV1 {
    parent_role: u16,
    child_role: u16,
    tag_class: u8,
    constructed: bool,
    tag_number: u32,
    ordinal_exact: bool,
    ordinal_last: bool,
    ordinal_parameter: u16,
    count_exact: bool,
    count_parameter: u16,
    quotient_scale: u16,
    remainder_scale: u16,
    ordinal_scale: u16,
    constant: u16,
    /// Zero for non-roots, then certificate, CRL, or embedded root.
    root_kind: u8,
}
// The closed grammar is serialized as fixed-width little-endian records. The
// specialized const decoder preserves the exact typed table without runtime work.
const ZK_X509_RFC5280_GRAMMAR_RULE_RECORD_BYTES_V1: usize = 26;
const ZK_X509_RFC5280_GRAMMAR_RULE_BYTES_V1: &[u8; 2_236] =
    include_bytes!("assets/rfc5280_grammar_rules_v1.bin");
const fn decode_rfc5280_grammar_rules_v1(bytes: &[u8; 2_236]) -> [ZkX509Rfc5280GrammarRuleV1; 86] {
    let zero = ZkX509Rfc5280GrammarRuleV1 {
        parent_role: 0,
        child_role: 0,
        tag_class: 0,
        constructed: false,
        tag_number: 0,
        ordinal_exact: false,
        ordinal_last: false,
        ordinal_parameter: 0,
        count_exact: false,
        count_parameter: 0,
        quotient_scale: 0,
        remainder_scale: 0,
        ordinal_scale: 0,
        constant: 0,
        root_kind: 0,
    };
    let mut rules = [zero; 86];
    let mut index = 0;
    while index < rules.len() {
        let offset = index * ZK_X509_RFC5280_GRAMMAR_RULE_RECORD_BYTES_V1;
        rules[index] = ZkX509Rfc5280GrammarRuleV1 {
            parent_role: u16::from_le_bytes([bytes[offset], bytes[offset + 1]]),
            child_role: u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]),
            tag_class: bytes[offset + 4],
            constructed: bytes[offset + 5] != 0,
            tag_number: u32::from_le_bytes([
                bytes[offset + 6],
                bytes[offset + 7],
                bytes[offset + 8],
                bytes[offset + 9],
            ]),
            ordinal_exact: bytes[offset + 10] != 0,
            ordinal_last: bytes[offset + 11] != 0,
            ordinal_parameter: u16::from_le_bytes([bytes[offset + 12], bytes[offset + 13]]),
            count_exact: bytes[offset + 14] != 0,
            count_parameter: u16::from_le_bytes([bytes[offset + 15], bytes[offset + 16]]),
            quotient_scale: u16::from_le_bytes([bytes[offset + 17], bytes[offset + 18]]),
            remainder_scale: u16::from_le_bytes([bytes[offset + 19], bytes[offset + 20]]),
            ordinal_scale: u16::from_le_bytes([bytes[offset + 21], bytes[offset + 22]]),
            constant: u16::from_le_bytes([bytes[offset + 23], bytes[offset + 24]]),
            root_kind: bytes[offset + 25],
        };
        index += 1;
    }
    rules
}
const ZK_X509_RFC5280_GRAMMAR_RULE_ARRAY_V1: [ZkX509Rfc5280GrammarRuleV1; 86] =
    decode_rfc5280_grammar_rules_v1(ZK_X509_RFC5280_GRAMMAR_RULE_BYTES_V1);
const ZK_X509_RFC5280_GRAMMAR_RULES_V1: &[ZkX509Rfc5280GrammarRuleV1] =
    &ZK_X509_RFC5280_GRAMMAR_RULE_ARRAY_V1;
const ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1: usize = ZK_X509_RFC5280_GRAMMAR_RULES_V1.len();
const _: () = assert!(ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1 == 86);
fn grammar_tag_pack_v1<A: PolynomialAirFieldV1>(tag_class: A, constructed: A, tag_number: A) -> A {
    tag_class
        .add(constructed.mul(A::from_base(F(4))))
        .add(tag_number.mul(A::from_base(F(8))))
}
fn grammar_ordinal_pack_v1<A: PolynomialAirFieldV1>(exact: A, last: A, parameter: A) -> A {
    exact
        .add(last.mul(A::from_base(F(2))))
        .add(parameter.mul(A::from_base(F(4))))
}
fn grammar_count_pack_v1<A: PolynomialAirFieldV1>(exact: A, parameter: A) -> A {
    exact.add(parameter.mul(A::from_base(F(2))))
}
fn grammar_rule_expected_cells_v1(rule: ZkX509Rfc5280GrammarRuleV1) -> [F; 10] {
    [
        F(u64::from(rule.parent_role)),
        F(u64::from(rule.child_role)),
        grammar_tag_pack_v1(
            F(u64::from(rule.tag_class)),
            F(u64::from(rule.constructed)),
            F(u64::from(rule.tag_number)),
        ),
        grammar_ordinal_pack_v1(
            F(u64::from(rule.ordinal_exact)),
            F(u64::from(rule.ordinal_last)),
            F(u64::from(rule.ordinal_parameter)),
        ),
        grammar_count_pack_v1(
            F(u64::from(rule.count_exact)),
            F(u64::from(rule.count_parameter)),
        ),
        F(u64::from(rule.quotient_scale)),
        F(u64::from(rule.remainder_scale)),
        F(u64::from(rule.ordinal_scale)),
        F(u64::from(rule.constant)),
        F(u64::from(rule.root_kind)),
    ]
}
const fn profile_role_required_v1(role: u16) -> bool {
    role == ZkX509Rfc5280GrammarRoleV1::CertificateOuterAlgorithm as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificateTbsAlgorithm as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CrlOuterAlgorithm as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CrlTbsAlgorithm as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificateSpkiAlgorithm as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificateVersion as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificateSignatureValue as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CrlSignatureValue as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificateExtensionOid as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CrlExtensionOid as u16
        || role == ZkX509Rfc5280GrammarRoleV1::CertificateExtensionCritical as u16
        || role == ZkX509Rfc5280GrammarRoleV1::NameAttributeOid as u16
        || role == ZkX509Rfc5280GrammarRoleV1::NameAttributeValue as u16
        || role == ZkX509Rfc5280GrammarRoleV1::EmbeddedKeyUsage as u16
        || role == ZkX509Rfc5280GrammarRoleV1::EmbeddedEku as u16
        || role == ZkX509Rfc5280GrammarRoleV1::EmbeddedCrlNumber as u16
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn grammar_rule_matches_node_v1(
    rule: ZkX509Rfc5280GrammarRuleV1,
    node: ZkX509Rfc5280NodeProvenanceV1,
    parent_role: u16,
    parent_instance: u16,
    child_count: u16,
) -> bool {
    let root = node.node == 0;
    let ordinal = if root {
        u16::from(node.document)
    } else {
        node.child_ordinal
    };
    if rule.parent_role != parent_role
        || rule.child_role != node.role as u16
        || rule.tag_class != node.tag_class
        || rule.constructed != node.constructed
        || rule.tag_number != node.tag_number
        || (rule.root_kind == 0) != !root
        || (rule.ordinal_exact && ordinal != rule.ordinal_parameter)
        || (rule.ordinal_last && ordinal.checked_add(1) != Some(child_count))
        || (rule.count_exact && child_count != rule.count_parameter)
    {
        return false;
    }
    let quotient = parent_instance / 256;
    let remainder = parent_instance % 256;
    u32::from(quotient)
        .checked_mul(u32::from(rule.quotient_scale))
        .and_then(|value| value.checked_add(u32::from(remainder) * u32::from(rule.remainder_scale)))
        .and_then(|value| value.checked_add(u32::from(ordinal) * u32::from(rule.ordinal_scale)))
        .and_then(|value| value.checked_add(u32::from(rule.constant)))
        == Some(u32::from(node.role_instance))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn grammar_rule_index_for_node_v1(
    node: ZkX509Rfc5280NodeProvenanceV1,
    parent_role: u16,
    parent_instance: u16,
    child_count: u16,
) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
    let mut matches = ZK_X509_RFC5280_GRAMMAR_RULES_V1
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, rule)| {
            grammar_rule_matches_node_v1(*rule, node, parent_role, parent_instance, child_count)
        });
    let (index, _) = matches.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
    if matches.next().is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    Ok(index)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn direct_parent_from_spans_v1(
    rows: &[ZkX509Rfc5280NodeProvenanceV1],
    index: usize,
) -> Option<usize> {
    let row = rows[index];
    if row.depth == 0 {
        return None;
    }
    rows[..index]
        .iter()
        .enumerate()
        .rev()
        .find_map(|(parent, candidate)| {
            (candidate.depth + 1 == row.depth
                && candidate.content_start <= row.start
                && candidate.content_end >= row.content_end)
                .then_some(parent)
        })
}
/// Independently validate exact owner provenance and the fixed grammar.
///
/// This deliberately does not trust a role merely because it was copied from
/// the DER builder. Parent links and child ordinals are recomputed from spans,
/// and the role/instance pair is then derived by the closed transition table.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn validate_zk_x509_rfc5280_provenance_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let source_documents = source_documents_v1(trace).collect::<Vec<_>>();
    if source_documents.len() != trace.semantic_provenance.len() {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    for (document_index, (document, provenance)) in source_documents
        .into_iter()
        .zip(&trace.semantic_provenance)
        .enumerate()
    {
        if usize::from(provenance.document) != document_index
            || provenance.nodes.len() != document.nodes.len()
            || provenance.nodes.is_empty()
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
        }
        if document_index < trace.documents.len() {
            if provenance.parent_document != u8::MAX || provenance.parent_node != u16::MAX {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            }
        } else {
            let parent_document = usize::from(provenance.parent_document);
            let parent_node = usize::from(provenance.parent_node);
            let parent = trace
                .semantic_provenance
                .get(parent_document)
                .and_then(|document| document.nodes.get(parent_node))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
            if !matches!(
                parent.role,
                ZkX509Rfc5280GrammarRoleV1::CertificateExtensionValue
                    | ZkX509Rfc5280GrammarRoleV1::CrlExtensionValue
            ) {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            }
        }
        for (node_index, (row, owner)) in provenance.nodes.iter().zip(&document.nodes).enumerate() {
            if usize::from(row.document) != document_index
                || usize::from(row.node) != node_index
                || row.start
                    != u16::try_from(owner.start.value.0)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                || row.content_start
                    != u16::try_from(owner.content_start.value.0)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                || row.content_end
                    != u16::try_from(owner.end.value.0)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                || row.depth
                    != u8::try_from(owner.depth.value.0)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                || row.tag_class
                    != u8::try_from(owner.tag_class.value.0)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                || row.constructed != (owner.constructed == F::ONE)
                || row.tag_number
                    != u32::try_from(owner.tag_number.value.0)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                || !role_tag_is_admitted_v1(*row)
            {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            }
            let parent = direct_parent_from_spans_v1(&provenance.nodes, node_index);
            if node_index == 0 {
                let expected_instance =
                    if provenance.kind == ZkX509Rfc5280DocumentKindV1::Certificate {
                        u16::try_from(document_index)
                            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
                    } else {
                        0
                    };
                if row.parent_node != u16::MAX
                    || row.child_ordinal != 0
                    || row.role != root_role_v1(provenance.kind)
                    || row.role_instance != expected_instance
                {
                    return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
                }
                continue;
            }
            let parent_index = parent.ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
            if usize::from(row.parent_node) != parent_index {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            }
            let derived_ordinal = provenance.nodes[..node_index]
                .iter()
                .filter(|candidate| usize::from(candidate.parent_node) == parent_index)
                .count();
            if usize::from(row.child_ordinal) != derived_ordinal {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            }
            let child_count = provenance
                .nodes
                .iter()
                .filter(|candidate| usize::from(candidate.parent_node) == parent_index)
                .count();
            let expected = expected_child_role_v1(
                provenance,
                provenance.nodes[parent_index],
                *row,
                child_count,
            )?;
            if (row.role, row.role_instance) != expected {
                return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
            }
        }
    }
    Ok(())
}
fn compress_tuple_v1<A: PolynomialAirFieldV1>(values: [A; 12], challenge: [F; 12]) -> A {
    values
        .into_iter()
        .zip(challenge)
        .fold(A::ZERO, |sum, (value, coefficient)| {
            sum.add(value.mul_base(coefficient))
        })
}
/// Exact strict-DER source terminals consumed by this adapter.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280DerSourceTerminalsV1 {
    pub(crate) input_byte: [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
    pub(crate) node: [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
}
#[cfg(test)]
pub(crate) fn zk_x509_rfc5280_der_source_terminals_v1(
    trace: &ZkX509Rfc5280TraceV1,
    challenges: ZkX509DerStarkChallengesV1,
) -> Result<ZkX509Rfc5280DerSourceTerminalsV1, ZkX509Rfc5280StarkErrorV1> {
    validate_zk_x509_rfc5280_provenance_v1(trace)?;
    let mut input_byte = [F::ONE; ZK_X509_RFC5280_STARK_BUS_LANES_V1];
    let mut node = [F::ONE; ZK_X509_RFC5280_STARK_BUS_LANES_V1];
    for (document_index, document) in source_documents_v1(trace).enumerate() {
        for (address, byte) in document.bytes.iter().enumerate() {
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                input_byte[lane] = input_byte[lane].mul(zk_x509_der_stark_input_byte_factor_v1(
                    F(u64::try_from(document_index)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?),
                    F(u64::try_from(address).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?),
                    byte.value.value,
                    lane,
                    challenges,
                )?);
            }
        }
        let provenance = trace
            .semantic_provenance
            .get(document_index)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
        for row in &provenance.nodes {
            let content_len = row
                .content_end
                .checked_sub(row.content_start)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
            let parent_frame = if row.parent_node == u16::MAX {
                0
            } else {
                row.parent_node
            };
            let event = ZkX509DerStarkNodeEventV1 {
                document: F(u64::from(row.document)),
                ordinal: F(u64::from(row.node)),
                parent_frame: F(u64::from(parent_frame)),
                tag_class: F(u64::from(row.tag_class)),
                tag_number: F(u64::from(row.tag_number)),
                constructed: F(u64::from(row.constructed)),
                start: F(u64::from(row.start)),
                content_start: F(u64::from(row.content_start)),
                content_end: F(u64::from(row.content_end)),
                depth: F(u64::from(row.depth)),
                content_len: F(u64::from(content_len)),
            };
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                node[lane] =
                    node[lane].mul(zk_x509_der_stark_node_factor_v1(event, lane, challenges)?);
            }
        }
    }
    Ok(ZkX509Rfc5280DerSourceTerminalsV1 { input_byte, node })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn find_role_node_v1(
    trace: &ZkX509Rfc5280TraceV1,
    document: usize,
    role: ZkX509Rfc5280GrammarRoleV1,
) -> Result<ZkX509Rfc5280NodeProvenanceV1, ZkX509Rfc5280StarkErrorV1> {
    let mut rows = trace
        .semantic_provenance
        .get(document)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?
        .nodes
        .iter()
        .copied()
        .filter(|row| row.role == role);
    let row = rows.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
    if rows.next().is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    Ok(row)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn find_role_instance_node_v1(
    trace: &ZkX509Rfc5280TraceV1,
    document: usize,
    role: ZkX509Rfc5280GrammarRoleV1,
    role_instance: u16,
) -> Result<ZkX509Rfc5280NodeProvenanceV1, ZkX509Rfc5280StarkErrorV1> {
    let mut rows = trace
        .semantic_provenance
        .get(document)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?
        .nodes
        .iter()
        .copied()
        .filter(|row| row.role == role && row.role_instance == role_instance);
    let row = rows.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
    if rows.next().is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    Ok(row)
}
fn endpoint_role_code_v1(role: ZkX509IoSegmentRoleV1) -> Result<u64, ZkX509Rfc5280StarkErrorV1> {
    match role {
        ZkX509IoSegmentRoleV1::StrictDer => Ok(1),
        ZkX509IoSegmentRoleV1::Sha256 => Ok(2),
        ZkX509IoSegmentRoleV1::P256 => Ok(3),
        ZkX509IoSegmentRoleV1::CaAccumulator => Ok(4),
        ZkX509IoSegmentRoleV1::Projection => Ok(6),
        ZkX509IoSegmentRoleV1::PublicInput => Ok(7),
        #[cfg(test)]
        ZkX509IoSegmentRoleV1::CrlCommitment => Err(ZkX509Rfc5280StarkErrorV1::Output),
    }
}
fn output_role_index_v1(role: ZkX509Rfc5280OutputRoleV1) -> usize {
    role as usize - 1
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn output_roles_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<Vec<ZkX509Rfc5280OutputRoleV1>, ZkX509Rfc5280StarkErrorV1> {
    let mut roles = Vec::new();
    roles.extend(core::iter::repeat_n(
        ZkX509Rfc5280OutputRoleV1::Projection,
        3 + 2 + 2 * trace.statement.disclosed_attribute_indices.len(),
    ));
    // Three fixed padded/length TBS channel pairs.
    roles.extend(core::iter::repeat_n(
        ZkX509Rfc5280OutputRoleV1::CertificateTbsSha,
        6,
    ));
    roles.push(ZkX509Rfc5280OutputRoleV1::CertificateSlotActive);
    for _ in 0..3 {
        roles.extend([
            ZkX509Rfc5280OutputRoleV1::P256Signature,
            ZkX509Rfc5280OutputRoleV1::P256Signature,
            ZkX509Rfc5280OutputRoleV1::P256PublicKey,
        ]);
    }
    roles.extend([
        ZkX509Rfc5280OutputRoleV1::CrlTbsP256Message,
        ZkX509Rfc5280OutputRoleV1::CrlTbsP256Message,
        ZkX509Rfc5280OutputRoleV1::CrlCommitment,
        ZkX509Rfc5280OutputRoleV1::CrlCommitment,
        ZkX509Rfc5280OutputRoleV1::P256Signature,
        ZkX509Rfc5280OutputRoleV1::P256Signature,
        ZkX509Rfc5280OutputRoleV1::P256PublicKey,
        ZkX509Rfc5280OutputRoleV1::P256PublicKey,
        ZkX509Rfc5280OutputRoleV1::IssuerSpkiSha,
        ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor,
    ]);
    Ok(roles)
}
#[cfg(test)]
fn output_factor_v1(
    role: ZkX509Rfc5280OutputRoleV1,
    channel: u32,
    endpoint: ZkX509IoEndpointV1,
    offset: usize,
    value: u8,
    is_write: bool,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<F, ZkX509Rfc5280StarkErrorV1> {
    zk_x509_rfc5280_opened_output_factor_v1(
        role,
        F(u64::from(channel)),
        endpoint,
        F(u64::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?),
        F(u64::from(value)),
        F(u64::from(is_write)),
        lane,
        challenges,
    )
}
/// Compress one downstream output event directly from constrained field cells.
///
/// Downstream numeric adapters use this exact expression for their consumer products. Byte range,
/// offset, and direction constraints remain owned by the calling adapter; this helper solely
/// guarantees an identical typed tuple and challenge domain on both sides of the RFC relation.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn zk_x509_rfc5280_opened_output_factor_v1(
    role: ZkX509Rfc5280OutputRoleV1,
    channel: F,
    endpoint: ZkX509IoEndpointV1,
    offset: F,
    value: F,
    is_write: F,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<F, ZkX509Rfc5280StarkErrorV1> {
    zk_x509_rfc5280_opened_output_factor_fields_v1(
        F(role as u64),
        channel,
        F(endpoint_role_code_v1(endpoint.role)?),
        F(u64::from(endpoint.instance)),
        offset,
        value,
        is_write,
        lane,
        challenges,
    )
}
/// Field-native form of the RFC output tuple compression.
///
/// This is used at STARK query points where verifier-fixed role/channel cells
/// are polynomial openings rather than host enums.  Native-row callers should
/// prefer [`zk_x509_rfc5280_opened_output_factor_v1`].
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn zk_x509_rfc5280_opened_output_factor_fields_v1(
    role: F,
    channel: F,
    endpoint_role: F,
    endpoint_instance: F,
    offset: F,
    value: F,
    is_write: F,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<F, ZkX509Rfc5280StarkErrorV1> {
    challenges.validate()?;
    zk_x509_rfc5280_opened_output_factor_fields_after_challenge_validation_v1(
        role,
        channel,
        endpoint_role,
        endpoint_instance,
        offset,
        value,
        is_write,
        lane,
        challenges,
    )
}
/// Field-native tuple compression after the owning adapter has validated the
/// challenge family once at its public boundary.
///
/// This avoids repeating the full 48-scalar validation on every row and lane
/// of a multi-million-row adapter. The lane bound remains checked here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zk_x509_rfc5280_opened_output_factor_fields_after_challenge_validation_v1<
    A: PolynomialAirFieldV1,
>(
    role: A,
    channel: A,
    endpoint_role: A,
    endpoint_instance: A,
    offset: A,
    value: A,
    is_write: A,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<A, ZkX509Rfc5280StarkErrorV1> {
    let challenge = challenges
        .tuple
        .get(lane)
        .copied()
        .ok_or(ZkX509Rfc5280StarkErrorV1::Challenge)?;
    Ok(compress_tuple_v1(
        [
            A::from_base(F(80)),
            role,
            channel,
            endpoint_role,
            endpoint_instance,
            offset,
            value,
            is_write,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenge,
    ))
}
/// Exact per-purpose producer and fixed-consumer terminal products.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280OutputTerminalsV1 {
    pub(crate) producer: [[F; ZK_X509_RFC5280_STARK_BUS_LANES_V1]; OUTPUT_ROLE_COUNT_V1],
    pub(crate) consumer: [[F; ZK_X509_RFC5280_STARK_BUS_LANES_V1]; OUTPUT_ROLE_COUNT_V1],
    pub(crate) producer_events: [u32; OUTPUT_ROLE_COUNT_V1],
    pub(crate) consumer_events: [u32; OUTPUT_ROLE_COUNT_V1],
}
/// Enumerate and compress both sides of every exact downstream I/O channel.
///
/// Producer and consumer factors intentionally include endpoint and write
/// direction, so they are not equated to one another inside this adapter.
/// Each downstream numeric adapter must expose the matching role terminal.
#[cfg(test)]
pub(crate) fn zk_x509_rfc5280_output_terminals_v1(
    trace: &ZkX509Rfc5280TraceV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<ZkX509Rfc5280OutputTerminalsV1, ZkX509Rfc5280StarkErrorV1> {
    challenges.validate()?;
    let witnesses = rfc5280_io_witnesses_v1(trace, 0)?;
    let roles = output_roles_v1(trace)?;
    if roles.len() != witnesses.len() {
        return Err(ZkX509Rfc5280StarkErrorV1::Output);
    }
    let mut terminals = ZkX509Rfc5280OutputTerminalsV1 {
        producer: [[F::ONE; ZK_X509_RFC5280_STARK_BUS_LANES_V1]; OUTPUT_ROLE_COUNT_V1],
        consumer: [[F::ONE; ZK_X509_RFC5280_STARK_BUS_LANES_V1]; OUTPUT_ROLE_COUNT_V1],
        producer_events: [0; OUTPUT_ROLE_COUNT_V1],
        consumer_events: [0; OUTPUT_ROLE_COUNT_V1],
    };
    for (role, witness) in roles.into_iter().zip(witnesses) {
        if witness.producer_value.len()
            != usize::try_from(witness.declaration.byte_len)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?
            || witness.consumer_values.len() != witness.declaration.consumers.len()
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Output);
        }
        let role_index = output_role_index_v1(role);
        for (offset, value) in witness.producer_value.iter().copied().enumerate() {
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                terminals.producer[role_index][lane] =
                    terminals.producer[role_index][lane].mul(output_factor_v1(
                        role,
                        witness.declaration.channel,
                        witness.declaration.producer,
                        offset,
                        value,
                        true,
                        lane,
                        challenges,
                    )?);
            }
            terminals.producer_events[role_index] = terminals.producer_events[role_index]
                .checked_add(1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        }
        for (consumer, values) in witness
            .declaration
            .consumers
            .iter()
            .copied()
            .zip(&witness.consumer_values)
        {
            if values.len() != witness.producer_value.len() {
                return Err(ZkX509Rfc5280StarkErrorV1::Output);
            }
            for (offset, value) in values.iter().copied().enumerate() {
                for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                    terminals.consumer[role_index][lane] = terminals.consumer[role_index][lane]
                        .mul(output_factor_v1(
                            role,
                            witness.declaration.channel,
                            consumer,
                            offset,
                            value,
                            false,
                            lane,
                            challenges,
                        )?);
                }
                terminals.consumer_events[role_index] = terminals.consumer_events[role_index]
                    .checked_add(1)
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
            }
        }
    }
    if terminals.producer_events != terminals.consumer_events
        || terminals
            .producer_events
            .iter()
            .map(|events| usize::try_from(*events).unwrap_or(usize::MAX))
            .sum::<usize>()
            > MAX_OUTPUT_EVENT_ROWS_V1 / 2
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Output);
    }
    Ok(terminals)
}
const ECDSA_SHA256_ALGORITHM_V1: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];
const P256_ALGORITHM_V1: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];
const CERTIFICATE_EXTENSION_OIDS_V1: [&[u8]; 5] = [
    &[0x55, 0x1d, 0x23],
    &[0x55, 0x1d, 0x0e],
    &[0x55, 0x1d, 0x0f],
    &[0x55, 0x1d, 0x13],
    &[0x55, 0x1d, 0x25],
];
const CRL_EXTENSION_OIDS_V1: [&[u8]; 2] = [&[0x55, 0x1d, 0x23], &[0x55, 0x1d, 0x14]];
const NAME_OIDS_V1: [&[u8]; 4] = [
    &[0x55, 0x04, 0x06],
    &[0x55, 0x04, 0x0a],
    &[0x55, 0x04, 0x0b],
    &[0x55, 0x04, 0x03],
];
const EKU_OIDS_V1: [&[u8]; 3] = [
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02],
    super::profile::ZK_X509_DOCUMENT_SIGNING_EKU_DER_VALUE_V1,
    super::profile::ZK_X509_WALLET_IDENTITY_EKU_DER_VALUE_V1,
];
const KEY_USAGE_KEY_CERT_SIGN_V1: u16 = 1 << 5;
const KEY_USAGE_CRL_SIGN_V1: u16 = 1 << 6;
/// One exact byte address read by a semantic predicate.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ZkX509Rfc5280SourceCellV1 {
    pub(crate) document: u8,
    pub(crate) address: u16,
    pub(crate) value: u8,
}
/// One fixed-profile byte equality.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280FixedByteV1 {
    pub(crate) source: ZkX509Rfc5280SourceCellV1,
    pub(crate) source_node: ZkX509Rfc5280NodeProvenanceV1,
    pub(crate) expected: u8,
    pub(crate) purpose: u16,
    pub(crate) instance: u16,
    pub(crate) variant: u16,
    pub(crate) offset: u16,
    pub(crate) length: u16,
}
/// One two-source equality byte.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280EqualByteV1 {
    pub(crate) left: ZkX509Rfc5280SourceCellV1,
    pub(crate) right: ZkX509Rfc5280SourceCellV1,
    pub(crate) purpose: u16,
    pub(crate) instance: u16,
    pub(crate) offset: u16,
}
/// Explicit numeric operands for one admitted scalar predicate.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280NumericRelationV1 {
    /// Stable relation code fixed by schedule order.
    pub(crate) relation: u16,
    pub(crate) instance: u16,
    /// `left = right + slack`.
    pub(crate) left: u64,
    pub(crate) right: u64,
    pub(crate) slack: u64,
    /// If true, the slack must be nonzero.
    pub(crate) strict: bool,
}
/// Verifier-fixed purpose of one serial comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ZkX509Rfc5280SerialComparisonKindV1 {
    /// The leaf magnitude must differ from one active revoked magnitude.
    LeafNonMembership = 0,
    /// Two adjacent revoked magnitudes must be strictly increasing.
    AdjacentStrictOrder = 1,
}
/// One fixed-width serial comparison, including length and padded octets.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280SerialComparisonV1 {
    pub(crate) kind: ZkX509Rfc5280SerialComparisonKindV1,
    pub(crate) left_instance: u16,
    pub(crate) right_instance: u16,
    pub(crate) left: [u8; SERIAL_COMPARISON_WIDTH_V1],
    pub(crate) right: [u8; SERIAL_COMPARISON_WIDTH_V1],
}
/// One canonical DER-backed producer frame for a comparator endpoint.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280SerialSourceV1 {
    pub(crate) logical_id: u16,
    pub(crate) node: ZkX509Rfc5280NodeProvenanceV1,
    pub(crate) frame: [u8; SERIAL_COMPARISON_WIDTH_V1],
    /// Exact DER INTEGER contents, including an optional sign octet.
    pub(crate) encoded_contents: Vec<ZkX509Rfc5280SourceCellV1>,
}
/// Complete prover-side semantic operands. Each vector is committed as a
/// fixed-family range; none is reduced to a host Boolean digest.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280SemanticWitnessV1 {
    pub(crate) fixed_bytes: Vec<ZkX509Rfc5280FixedByteV1>,
    pub(crate) equal_bytes: Vec<ZkX509Rfc5280EqualByteV1>,
    pub(crate) decimal_cells: Vec<ZkX509Rfc5280SourceCellV1>,
    pub(crate) calendar_values: Vec<u64>,
    pub(crate) numeric_relations: Vec<ZkX509Rfc5280NumericRelationV1>,
    pub(crate) serial_sources: Vec<ZkX509Rfc5280SerialSourceV1>,
    pub(crate) serial_comparisons: Vec<ZkX509Rfc5280SerialComparisonV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn document_bytes_v1(
    trace: &ZkX509Rfc5280TraceV1,
    document: usize,
) -> Result<PrivateTableV1<u8>, ZkX509Rfc5280StarkErrorV1> {
    let rows = &source_documents_v1(trace)
        .nth(document)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?
        .bytes;
    let mut bytes = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
    bytes
        .try_reserve_exact(rows.len())
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for row in rows {
        bytes.push(u8::try_from(row.value.value.0).map_err(|_| ZkX509Rfc5280StarkErrorV1::Source)?);
    }
    Ok(bytes)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn source_slice_v1(
    trace: &ZkX509Rfc5280TraceV1,
    row: ZkX509Rfc5280NodeProvenanceV1,
    contents_only: bool,
) -> Result<PrivateTableV1<ZkX509Rfc5280SourceCellV1>, ZkX509Rfc5280StarkErrorV1> {
    let bytes = document_bytes_v1(trace, usize::from(row.document))?;
    let start = if contents_only {
        row.content_start
    } else {
        row.start
    };
    let end = row.content_end;
    if start > end || usize::from(end) > bytes.len() {
        return Err(ZkX509Rfc5280StarkErrorV1::Source);
    }
    let mut cells = PrivateTableV1::new(Vec::new(), zeroize_source_cells_v1);
    cells
        .try_reserve_exact(usize::from(end - start))
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for address in start..end {
        cells.push(ZkX509Rfc5280SourceCellV1 {
            document: row.document,
            address,
            value: bytes[usize::from(address)],
        });
    }
    Ok(cells)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_fixed_slice_v1(
    output: &mut Vec<ZkX509Rfc5280FixedByteV1>,
    source_node: ZkX509Rfc5280NodeProvenanceV1,
    source: &[ZkX509Rfc5280SourceCellV1],
    expected: &[u8],
    purpose: u16,
    instance: u16,
    variant: u16,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    if source.len() != expected.len() {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    reserve_private_semantic_v1(output, source.len(), zeroize_fixed_bytes_v1)?;
    let length = u16::try_from(expected.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for (offset, (source, expected)) in source
        .iter()
        .copied()
        .zip(expected.iter().copied())
        .enumerate()
    {
        output.push(ZkX509Rfc5280FixedByteV1 {
            source,
            source_node,
            expected,
            purpose,
            instance,
            variant,
            offset: u16::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            length,
        });
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_equal_slices_v1(
    output: &mut Vec<ZkX509Rfc5280EqualByteV1>,
    left: &[ZkX509Rfc5280SourceCellV1],
    right: &[ZkX509Rfc5280SourceCellV1],
    purpose: u16,
    instance: u16,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    if left.len() != right.len() {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    reserve_private_semantic_v1(output, left.len(), zeroize_equal_bytes_v1)?;
    for (offset, (left, right)) in left.iter().copied().zip(right.iter().copied()).enumerate() {
        output.push(ZkX509Rfc5280EqualByteV1 {
            left,
            right,
            purpose,
            instance,
            offset: u16::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        });
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn role_nodes_v1(
    trace: &ZkX509Rfc5280TraceV1,
    role: ZkX509Rfc5280GrammarRoleV1,
) -> impl Iterator<Item = ZkX509Rfc5280NodeProvenanceV1> + '_ {
    trace
        .semantic_provenance
        .iter()
        .flat_map(|document| document.nodes.iter())
        .copied()
        .filter(move |row| row.role == role)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn embedded_role_node_v1(
    trace: &ZkX509Rfc5280TraceV1,
    parent_document: usize,
    kind: ZkX509Rfc5280DocumentKindV1,
) -> Result<ZkX509Rfc5280NodeProvenanceV1, ZkX509Rfc5280StarkErrorV1> {
    let mut matches = trace.semantic_provenance.iter().filter(|document| {
        document.kind == kind && usize::from(document.parent_document) == parent_document
    });
    let document = matches.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
    if matches.next().is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    document
        .nodes
        .first()
        .copied()
        .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn serial_frame_v1(
    serial: &[u8],
) -> Result<[u8; SERIAL_COMPARISON_WIDTH_V1], ZkX509Rfc5280StarkErrorV1> {
    if serial.is_empty() || serial.len() > ZK_X509_MAX_SERIAL_BYTES_V1 || serial.first() == Some(&0)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    let mut frame = [0_u8; SERIAL_COMPARISON_WIDTH_V1];
    frame[0] = u8::try_from(serial.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    frame[1..1 + serial.len()].copy_from_slice(serial);
    Ok(frame)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_serial_frame_v1(
    frame: &[u8; SERIAL_COMPARISON_WIDTH_V1],
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let length = usize::from(frame[0]);
    if !(1..=ZK_X509_MAX_SERIAL_BYTES_V1).contains(&length)
        || frame[1] == 0
        || frame[1 + length..].iter().any(|byte| *byte != 0)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_serial_comparison_v1(
    comparison: &ZkX509Rfc5280SerialComparisonV1,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    validate_serial_frame_v1(&comparison.left)?;
    validate_serial_frame_v1(&comparison.right)?;
    match comparison.kind {
        ZkX509Rfc5280SerialComparisonKindV1::LeafNonMembership => {
            if comparison.left == comparison.right {
                return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
            }
        }
        ZkX509Rfc5280SerialComparisonKindV1::AdjacentStrictOrder => {
            if comparison.left >= comparison.right {
                return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
            }
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_serial_comparisons_v1(
    leaf: &[u8],
    revoked_serials: &[Vec<u8>],
) -> Result<Vec<ZkX509Rfc5280SerialComparisonV1>, ZkX509Rfc5280StarkErrorV1> {
    if revoked_serials.len() > ZK_X509_MAX_CRL_ENTRIES_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    let leaf = serial_frame_v1(leaf)?;
    let mut revoked = PrivateTableV1::new(Vec::new(), zeroize_words_v1);
    revoked
        .try_reserve_exact(revoked_serials.len())
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for serial in revoked_serials {
        revoked.push(serial_frame_v1(serial)?);
    }
    let mut comparisons = Vec::new();
    comparisons
        .try_reserve_exact(serial_comparison_count_v1(revoked.len()))
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for (index, right) in revoked.iter().copied().enumerate() {
        let leaf_comparison = ZkX509Rfc5280SerialComparisonV1 {
            kind: ZkX509Rfc5280SerialComparisonKindV1::LeafNonMembership,
            left_instance: 0,
            right_instance: u16::try_from(index + 1)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            left: leaf,
            right,
        };
        validate_serial_comparison_v1(&leaf_comparison)?;
        comparisons.push(leaf_comparison);
        if index != 0 {
            let adjacent_comparison = ZkX509Rfc5280SerialComparisonV1 {
                kind: ZkX509Rfc5280SerialComparisonKindV1::AdjacentStrictOrder,
                left_instance: u16::try_from(index)
                    .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                right_instance: u16::try_from(index + 1)
                    .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                left: revoked[index - 1],
                right,
            };
            validate_serial_comparison_v1(&adjacent_comparison)?;
            comparisons.push(adjacent_comparison);
        }
    }
    if comparisons.len() != serial_comparison_count_v1(revoked.len()) {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(comparisons)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_serial_comparison_manifest_v1(
    leaf: &[u8],
    revoked_serials: &[Vec<u8>],
    comparisons: &[ZkX509Rfc5280SerialComparisonV1],
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let expected = canonical_serial_comparisons_v1(leaf, revoked_serials)?;
    if comparisons != expected {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_serial_source_v1(
    trace: &ZkX509Rfc5280TraceV1,
    logical_id: u16,
) -> Result<ZkX509Rfc5280SerialSourceV1, ZkX509Rfc5280StarkErrorV1> {
    let crl_document = trace.certificates.len();
    let (document, role, role_instance, serial) = if logical_id == 0 {
        (
            0,
            ZkX509Rfc5280GrammarRoleV1::CertificateSerial,
            0,
            trace
                .certificates
                .first()
                .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?
                .serial
                .as_slice(),
        )
    } else {
        let entry = usize::from(logical_id - 1);
        (
            crl_document,
            ZkX509Rfc5280GrammarRoleV1::CrlEntrySerial,
            logical_id - 1,
            trace
                .crl
                .revoked_serials
                .get(entry)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?
                .as_slice(),
        )
    };
    let node = find_role_instance_node_v1(trace, document, role, role_instance)?;
    let frame = serial_frame_v1(serial)?;
    let encoded_contents = source_slice_v1(trace, node, true)?;
    let encoded = private_bytes_v1(encoded_contents.iter().map(|cell| cell.value))?;
    let sign_padding = encoded.len() == serial.len() + 1
        && encoded.first() == Some(&0)
        && encoded.get(1..) == Some(serial);
    if encoded.as_slice() != serial && !sign_padding || sign_padding != (serial[0] & 0x80 != 0) {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(ZkX509Rfc5280SerialSourceV1 {
        logical_id,
        node,
        frame,
        encoded_contents: encoded_contents.into_vec(),
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_serial_sources_v1(
    trace: &ZkX509Rfc5280TraceV1,
    comparisons: &[ZkX509Rfc5280SerialComparisonV1],
) -> Result<Vec<ZkX509Rfc5280SerialSourceV1>, ZkX509Rfc5280StarkErrorV1> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(
            comparisons
                .len()
                .checked_mul(2)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for comparison in comparisons {
        for logical_id in [comparison.left_instance, comparison.right_instance] {
            sources.push(canonical_serial_source_v1(trace, logical_id)?);
        }
    }
    Ok(sources)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_serial_source_manifest_v1(
    trace: &ZkX509Rfc5280TraceV1,
    comparisons: &[ZkX509Rfc5280SerialComparisonV1],
    sources: &[ZkX509Rfc5280SerialSourceV1],
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let expected = canonical_serial_sources_v1(trace, comparisons)?;
    if sources != expected {
        return Err(ZkX509Rfc5280StarkErrorV1::Source);
    }
    Ok(())
}
/// Exact DER-table multiplicity for one serial-source node lookup key.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ZkX509Rfc5280SerialNodeMultiplicityV1 {
    pub(crate) document: u8,
    pub(crate) node: u16,
    pub(crate) required_multiplicity: u16,
}
/// Compile the pre-challenge byte/node table multiplicities consumed by the
/// serial-source lookup arguments.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn zk_x509_rfc5280_serial_lookup_multiplicities_v1(
    sources: &[ZkX509Rfc5280SerialSourceV1],
) -> Result<
    (
        PrivateTableV1<ZkX509Rfc5280SourceMultiplicityV1>,
        PrivateTableV1<ZkX509Rfc5280SerialNodeMultiplicityV1>,
    ),
    ZkX509Rfc5280StarkErrorV1,
> {
    let byte_count = sources
        .iter()
        .try_fold(0usize, |count, source| {
            count.checked_add(source.encoded_contents.len())
        })
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut bytes = PrivateTableV1::new(Vec::new(), zeroize_source_cells_v1);
    bytes
        .try_reserve_exact(byte_count)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut nodes = PrivateTableV1::new(Vec::new(), |nodes: &mut [(u8, u16)]| {
        for (document, node) in nodes {
            zeroize_words_v1(core::slice::from_mut(document));
            zeroize_words_v1(core::slice::from_mut(node));
        }
    });
    nodes
        .try_reserve_exact(sources.len())
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for source in sources {
        build_zk_x509_rfc5280_serial_source_rows_v1(source)?;
        bytes.extend(source.encoded_contents.iter().copied());
        nodes.push((source.node.document, source.node.node));
    }
    bytes.sort_unstable();
    nodes.sort_unstable();
    let mut byte_multiplicities = PrivateTableV1::new(Vec::new(), zeroize_source_multiplicities_v1);
    byte_multiplicities
        .try_reserve_exact(bytes.len())
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for source in bytes.iter().copied() {
        if let Some(last) = byte_multiplicities.last_mut()
            && last.source == source
        {
            last.required_multiplicity = last
                .required_multiplicity
                .checked_add(1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        } else {
            byte_multiplicities.push(ZkX509Rfc5280SourceMultiplicityV1 {
                source,
                required_multiplicity: 1,
            });
        }
    }
    let mut node_multiplicities = PrivateTableV1::new(Vec::new(), zeroize_node_multiplicities_v1);
    node_multiplicities
        .try_reserve_exact(nodes.len())
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for (document, node) in nodes.iter().copied() {
        if let Some(last) = node_multiplicities.last_mut()
            && last.document == document
            && last.node == node
        {
            last.required_multiplicity = last
                .required_multiplicity
                .checked_add(
                    u16::try_from(SERIAL_COMPARISON_WIDTH_V1)
                        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                )
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        } else {
            node_multiplicities.push(ZkX509Rfc5280SerialNodeMultiplicityV1 {
                document,
                node,
                required_multiplicity: u16::try_from(SERIAL_COMPARISON_WIDTH_V1)
                    .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            });
        }
    }
    Ok((byte_multiplicities, node_multiplicities))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_relation_v1(
    output: &mut Vec<ZkX509Rfc5280NumericRelationV1>,
    relation: u16,
    instance: usize,
    left: u64,
    right: u64,
    strict: bool,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let slack = left
        .checked_sub(right)
        .filter(|slack| !strict || *slack != 0)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
    reserve_private_semantic_v1(output, 1, zeroize_numeric_relations_v1)?;
    output.push(ZkX509Rfc5280NumericRelationV1 {
        relation,
        instance: u16::try_from(instance).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        left,
        right,
        slack,
        strict,
    });
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_decimal_v1(bytes: &[u8]) -> Result<u16, ZkX509Rfc5280StarkErrorV1> {
    bytes.iter().try_fold(0_u16, |value, byte| {
        if !byte.is_ascii_digit() {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u16::from(*byte - b'0')))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn parse_time_cells_v1(
    cells: &[ZkX509Rfc5280SourceCellV1],
    tag: u32,
) -> Result<(u64, PrivateTableV1<ZkX509Rfc5280SourceCellV1>), ZkX509Rfc5280StarkErrorV1> {
    use time::{Date, Month, PrimitiveDateTime, Time};
    let bytes = private_bytes_v1(cells.iter().map(|cell| cell.value))?;
    let (year, offset, z_offset) = if tag == 23 {
        if bytes.len() != 13 || bytes[12] != b'Z' {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        let short = parse_decimal_v1(&bytes[..2])?;
        let year = if short >= 50 {
            1900 + i32::from(short)
        } else {
            2000 + i32::from(short)
        };
        if !(1970..=2049).contains(&year) {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        (year, 2, 12)
    } else if tag == 24 {
        if bytes.len() != 15 || bytes[14] != b'Z' {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        let year = i32::from(parse_decimal_v1(&bytes[..4])?);
        if !(2050..=9999).contains(&year) {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        (year, 4, 14)
    } else {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    };
    let month = Month::try_from(
        u8::try_from(parse_decimal_v1(&bytes[offset..offset + 2])?)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?,
    )
    .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?;
    let day = u8::try_from(parse_decimal_v1(&bytes[offset + 2..offset + 4])?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?;
    let hour = u8::try_from(parse_decimal_v1(&bytes[offset + 4..offset + 6])?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?;
    let minute = u8::try_from(parse_decimal_v1(&bytes[offset + 6..offset + 8])?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?;
    let second = u8::try_from(parse_decimal_v1(&bytes[offset + 8..offset + 10])?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?;
    let timestamp = PrimitiveDateTime::new(
        Date::from_calendar_date(year, month, day)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?,
        Time::from_hms(hour, minute, second).map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?,
    )
    .assume_utc()
    .unix_timestamp();
    let mut decimal = PrivateTableV1::new(Vec::new(), zeroize_source_cells_v1);
    decimal
        .try_reserve_exact(z_offset)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    decimal.extend_from_slice(&cells[..z_offset]);
    Ok((
        u64::try_from(timestamp).map_err(|_| ZkX509Rfc5280StarkErrorV1::Semantic)?,
        decimal,
    ))
}
fn encode_unsigned_integer_v1(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let magnitude = &bytes[first..];
    let mut encoded = Vec::with_capacity(magnitude.len() + 3);
    encoded.push(0x02);
    encoded.push(
        u8::try_from(magnitude.len() + usize::from(magnitude[0] & 0x80 != 0))
            .expect("u64 INTEGER length fits u8"),
    );
    if magnitude[0] & 0x80 != 0 {
        encoded.push(0);
    }
    encoded.extend_from_slice(magnitude);
    encoded
}
fn encode_key_usage_v1(flags: u16) -> Result<Vec<u8>, ZkX509Rfc5280StarkErrorV1> {
    let highest = (0..16)
        .rev()
        .find(|bit| flags & (1_u16 << bit) != 0)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
    let value_len = highest / 8 + 1;
    let unused = 7 - highest % 8;
    let mut value = vec![0_u8; value_len];
    for bit in 0..16 {
        if flags & (1_u16 << bit) != 0 {
            value[bit / 8] |= 0x80 >> (bit % 8);
        }
    }
    let mut encoded = vec![
        0x03,
        u8::try_from(value.len() + 1).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        u8::try_from(unused).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
    ];
    encoded.extend_from_slice(&value);
    Ok(encoded)
}
#[cfg(test)]
fn encode_basic_constraints_v1(
    ca: bool,
    path_len: Option<u32>,
) -> Result<Vec<u8>, ZkX509Rfc5280StarkErrorV1> {
    let mut body = Vec::new();
    if ca {
        body.extend_from_slice(&[0x01, 0x01, 0xff]);
    } else if path_len.is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    if let Some(path_len) = path_len {
        body.extend_from_slice(&encode_unsigned_integer_v1(u64::from(path_len)));
    }
    if body.len() >= 128 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    let mut encoded = vec![
        0x30,
        u8::try_from(body.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
    ];
    encoded.extend_from_slice(&body);
    Ok(encoded)
}
fn eku_oid_v1(eku: ZkX509DerEkuV1) -> &'static [u8] {
    match eku {
        ZkX509DerEkuV1::ClientAuthentication => EKU_OIDS_V1[0],
        ZkX509DerEkuV1::DocumentSigning => EKU_OIDS_V1[1],
        ZkX509DerEkuV1::WalletIdentity => EKU_OIDS_V1[2],
    }
}
const fn eku_code_v1(eku: ZkX509DerEkuV1) -> u8 {
    match eku {
        ZkX509DerEkuV1::ClientAuthentication => 1,
        ZkX509DerEkuV1::DocumentSigning => 2,
        ZkX509DerEkuV1::WalletIdentity => 3,
    }
}
fn eku_from_code_v1(code: u8) -> Result<ZkX509DerEkuV1, ZkX509Rfc5280StarkErrorV1> {
    match code {
        1 => Ok(ZkX509DerEkuV1::ClientAuthentication),
        2 => Ok(ZkX509DerEkuV1::DocumentSigning),
        3 => Ok(ZkX509DerEkuV1::WalletIdentity),
        _ => Err(ZkX509Rfc5280StarkErrorV1::Shape),
    }
}
fn encode_eku_v1(usages: &[ZkX509DerEkuV1]) -> Result<Vec<u8>, ZkX509Rfc5280StarkErrorV1> {
    if usages.is_empty() {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    let mut body = Vec::new();
    for usage in usages {
        let oid = eku_oid_v1(*usage);
        body.push(0x06);
        body.push(u8::try_from(oid.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
        body.extend_from_slice(oid);
    }
    if body.len() >= 128 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    let mut encoded = vec![
        0x30,
        u8::try_from(body.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
    ];
    encoded.extend_from_slice(&body);
    Ok(encoded)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn find_embedded_inner_role_v1(
    trace: &ZkX509Rfc5280TraceV1,
    parent_document: usize,
    kind: ZkX509Rfc5280DocumentKindV1,
    role: ZkX509Rfc5280GrammarRoleV1,
) -> Result<ZkX509Rfc5280NodeProvenanceV1, ZkX509Rfc5280StarkErrorV1> {
    let document = trace
        .semantic_provenance
        .iter()
        .find(|document| {
            document.kind == kind && usize::from(document.parent_document) == parent_document
        })
        .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
    let mut nodes = document
        .nodes
        .iter()
        .copied()
        .filter(|node| node.role == role);
    let node = nodes.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
    if nodes.next().is_some() {
        return Err(ZkX509Rfc5280StarkErrorV1::Grammar);
    }
    Ok(node)
}
/// Build every semantic operand and reject malformed or inconsistent paths.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_rfc5280_semantic_witness_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<ZkX509Rfc5280SemanticWitnessV1, ZkX509Rfc5280StarkErrorV1> {
    validate_zk_x509_rfc5280_provenance_v1(trace)?;
    let depth = trace.certificates.len();
    if !(2..=3).contains(&depth)
        || trace.crl.revoked_serials.len() > ZK_X509_MAX_CRL_ENTRIES_V1
        || trace
            .statement
            .disclosed_attribute_indices
            .iter()
            .any(|index| *index >= 4)
        || trace
            .statement
            .disclosed_attribute_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || trace
            .statement
            .disclosed_attribute_indices
            .iter()
            .any(|index| trace.certificates[0].subject.attributes[usize::from(*index)].is_none())
        || trace.certificates[1].extensions.key_usage & KEY_USAGE_CRL_SIGN_V1 == 0
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    let mut witness = ZkX509Rfc5280SemanticWitnessV1 {
        fixed_bytes: Vec::new(),
        equal_bytes: Vec::new(),
        decimal_cells: Vec::new(),
        calendar_values: Vec::new(),
        numeric_relations: Vec::new(),
        serial_sources: Vec::new(),
        serial_comparisons: Vec::new(),
    };
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateOuterAlgorithm)
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CertificateTbsAlgorithm,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlOuterAlgorithm,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlTbsAlgorithm,
        ))
    {
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &source_slice_v1(trace, row, false)?,
            ECDSA_SHA256_ALGORITHM_V1,
            1,
            row.role_instance,
            0,
        )?;
    }
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateSpkiAlgorithm) {
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &source_slice_v1(trace, row, false)?,
            P256_ALGORITHM_V1,
            2,
            row.document.into(),
            0,
        )?;
    }
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateVersion) {
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &source_slice_v1(trace, row, true)?,
            &[0x02, 0x01, 0x02],
            3,
            row.document.into(),
            0,
        )?;
    }
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateSignatureValue).chain(
        role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CrlSignatureValue),
    ) {
        let first = source_slice_v1(trace, row, true)?
            .iter()
            .copied()
            .next()
            .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &[first],
            &[0],
            4,
            row.document.into(),
            0,
        )?;
    }
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey) {
        let contents = source_slice_v1(trace, row, true)?;
        if contents.len() != 66 {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &contents[..2],
            &[0, 0x04],
            5,
            row.document.into(),
            0,
        )?;
    }
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateExtensionOid) {
        let expected = CERTIFICATE_EXTENSION_OIDS_V1
            .get(usize::from(row.role_instance))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &source_slice_v1(trace, row, true)?,
            expected,
            6,
            row.role_instance,
            row.role_instance,
        )?;
    }
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CrlExtensionOid) {
        let expected = CRL_EXTENSION_OIDS_V1
            .get(usize::from(row.role_instance))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &source_slice_v1(trace, row, true)?,
            expected,
            7,
            row.role_instance,
            row.role_instance,
        )?;
    }
    for row in role_nodes_v1(
        trace,
        ZkX509Rfc5280GrammarRoleV1::CertificateExtensionCritical,
    ) {
        if !matches!(row.role_instance, 2..=4) {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            row,
            &source_slice_v1(trace, row, true)?,
            &[0xff],
            8,
            row.role_instance,
            0,
        )?;
    }
    if role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CrlExtensionCritical)
        .next()
        .is_some()
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    // A fixed public document/Name/OID traversal emits the complete original
    // census, including CRL issuer class 2, in disjoint document/class/OID key
    // order without a witness-dependent sorting algorithm or an
    // additional secret-bearing allocation. Matching and original source
    // traversal still require a separate whole-prover side-channel review.
    for document in 0..ZK_X509_DER_AIR_MAX_DOCUMENTS_V1 {
        for name in 0..3 {
            for (variant, expected) in NAME_OIDS_V1.into_iter().enumerate() {
                for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::NameAttributeOid) {
                    if usize::from(row.document) != document || row.role_instance / 1024 != name {
                        continue;
                    }
                    let source = source_slice_v1(trace, row, true)?;
                    let actual = private_bytes_v1(source.iter().map(|cell| cell.value))?;
                    if !NAME_OIDS_V1.contains(&actual.as_slice()) {
                        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
                    }
                    if actual.as_slice() != expected {
                        continue;
                    }
                    push_fixed_slice_v1(
                        &mut witness.fixed_bytes,
                        row,
                        &source,
                        expected,
                        9,
                        row.role_instance,
                        u16::try_from(variant).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                    )?;
                }
            }
        }
    }
    for (index, certificate) in trace.certificates.iter().enumerate() {
        let key_usage_root =
            embedded_role_node_v1(trace, index, ZkX509Rfc5280DocumentKindV1::KeyUsage)?;
        push_fixed_slice_v1(
            &mut witness.fixed_bytes,
            key_usage_root,
            &source_slice_v1(trace, key_usage_root, false)?,
            &encode_key_usage_v1(certificate.extensions.key_usage)?,
            10,
            u16::try_from(index).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            u16::from(index != 0),
        )?;
        if let Some(ekus) = certificate.extensions.extended_key_usages.as_deref() {
            let eku_root =
                embedded_role_node_v1(trace, index, ZkX509Rfc5280DocumentKindV1::ExtendedKeyUsage)?;
            push_fixed_slice_v1(
                &mut witness.fixed_bytes,
                eku_root,
                &source_slice_v1(trace, eku_root, false)?,
                &encode_eku_v1(ekus)?,
                12,
                u16::try_from(index).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                0,
            )?;
        }
    }
    for (index, certificate) in trace.certificates.iter().enumerate() {
        let parent_index = if index + 1 < depth { index + 1 } else { index };
        let issuer =
            find_role_node_v1(trace, index, ZkX509Rfc5280GrammarRoleV1::CertificateIssuer)?;
        let subject = find_role_node_v1(
            trace,
            parent_index,
            ZkX509Rfc5280GrammarRoleV1::CertificateSubject,
        )?;
        push_equal_slices_v1(
            &mut witness.equal_bytes,
            &source_slice_v1(trace, issuer, false)?,
            &source_slice_v1(trace, subject, false)?,
            1,
            u16::try_from(index).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        )?;
        let aki = find_embedded_inner_role_v1(
            trace,
            index,
            ZkX509Rfc5280DocumentKindV1::AuthorityKeyIdentifier,
            ZkX509Rfc5280GrammarRoleV1::EmbeddedAkiIdentifier,
        )?;
        let ski = find_embedded_inner_role_v1(
            trace,
            parent_index,
            ZkX509Rfc5280DocumentKindV1::SubjectKeyIdentifier,
            ZkX509Rfc5280GrammarRoleV1::EmbeddedSki,
        )?;
        push_equal_slices_v1(
            &mut witness.equal_bytes,
            &source_slice_v1(trace, aki, true)?,
            &source_slice_v1(trace, ski, true)?,
            2,
            u16::try_from(index).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        )?;
        if certificate.not_before > trace.statement.presentation_not_before_unix_seconds
            || certificate.not_after < trace.statement.presentation_not_after_unix_seconds
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
        }
        push_relation_v1(
            &mut witness.numeric_relations,
            1,
            index,
            trace.statement.presentation_not_before_unix_seconds,
            certificate.not_before,
            false,
        )?;
        push_relation_v1(
            &mut witness.numeric_relations,
            2,
            index,
            certificate.not_after,
            trace.statement.presentation_not_after_unix_seconds,
            false,
        )?;
        if index == 0 {
            if certificate.extensions.basic_constraints_path_len.is_some()
                || certificate.extensions.extended_key_usages.as_deref()
                    != Some(trace.statement.leaf_extended_key_usages.as_slice())
            {
                return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
            }
        } else {
            let subordinate =
                u32::try_from(index - 1).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
            let path_len = certificate
                .extensions
                .basic_constraints_path_len
                .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
            if path_len < subordinate {
                return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
            }
            if certificate.extensions.extended_key_usages.is_some() {
                return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
            }
        }
    }
    let crl_document = depth;
    let crl_issuer = find_role_node_v1(trace, crl_document, ZkX509Rfc5280GrammarRoleV1::CrlIssuer)?;
    let issuer_subject =
        find_role_node_v1(trace, 1, ZkX509Rfc5280GrammarRoleV1::CertificateSubject)?;
    push_equal_slices_v1(
        &mut witness.equal_bytes,
        &source_slice_v1(trace, crl_issuer, false)?,
        &source_slice_v1(trace, issuer_subject, false)?,
        3,
        0,
    )?;
    let crl_aki = find_embedded_inner_role_v1(
        trace,
        crl_document,
        ZkX509Rfc5280DocumentKindV1::AuthorityKeyIdentifier,
        ZkX509Rfc5280GrammarRoleV1::EmbeddedAkiIdentifier,
    )?;
    let issuer_ski = find_embedded_inner_role_v1(
        trace,
        1,
        ZkX509Rfc5280DocumentKindV1::SubjectKeyIdentifier,
        ZkX509Rfc5280GrammarRoleV1::EmbeddedSki,
    )?;
    push_equal_slices_v1(
        &mut witness.equal_bytes,
        &source_slice_v1(trace, crl_aki, true)?,
        &source_slice_v1(trace, issuer_ski, true)?,
        4,
        0,
    )?;
    let crl_number_root =
        embedded_role_node_v1(trace, crl_document, ZkX509Rfc5280DocumentKindV1::CrlNumber)?;
    push_fixed_slice_v1(
        &mut witness.fixed_bytes,
        crl_number_root,
        &source_slice_v1(trace, crl_number_root, false)?,
        &encode_unsigned_integer_v1(trace.statement.crl_number),
        13,
        0,
        0,
    )?;
    push_relation_v1(
        &mut witness.numeric_relations,
        4,
        0,
        trace.statement.presentation_not_before_unix_seconds,
        trace.crl.this_update,
        false,
    )?;
    push_relation_v1(
        &mut witness.numeric_relations,
        5,
        0,
        trace.crl.next_update,
        trace.statement.presentation_not_after_unix_seconds,
        true,
    )?;
    let stale_limit = trace
        .crl
        .this_update
        .checked_add(u64::from(numeric::CRL_AGE_SECONDS_V1))
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    push_relation_v1(
        &mut witness.numeric_relations,
        6,
        0,
        stale_limit,
        trace.statement.presentation_not_after_unix_seconds,
        false,
    )?;
    witness.serial_comparisons =
        canonical_serial_comparisons_v1(&trace.certificates[0].serial, &trace.crl.revoked_serials)?;
    validate_serial_comparison_manifest_v1(
        &trace.certificates[0].serial,
        &trace.crl.revoked_serials,
        &witness.serial_comparisons,
    )?;
    witness.serial_sources = canonical_serial_sources_v1(trace, &witness.serial_comparisons)?;
    validate_serial_source_manifest_v1(
        trace,
        &witness.serial_comparisons,
        &witness.serial_sources,
    )?;
    zk_x509_rfc5280_serial_lookup_multiplicities_v1(&witness.serial_sources)?;
    for row in role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateNotBefore)
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CertificateNotAfter,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlThisUpdate,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlNextUpdate,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlEntryTime,
        ))
    {
        let decimal = source_slice_v1(trace, row, true)?;
        let (calendar, _) = parse_time_cells_v1(&decimal, row.tag_number)?;
        reserve_private_semantic_v1(&mut witness.calendar_values, 1, zeroize_words_v1)?;
        reserve_private_semantic_v1(
            &mut witness.decimal_cells,
            decimal.len(),
            zeroize_source_cells_v1,
        )?;
        witness.calendar_values.push(calendar);
        witness.decimal_cells.extend_from_slice(&decimal);
        if row.role == ZkX509Rfc5280GrammarRoleV1::CrlEntryTime {
            push_relation_v1(
                &mut witness.numeric_relations,
                7,
                usize::from(row.role_instance),
                trace.crl.this_update,
                calendar,
                false,
            )?;
        }
    }
    let expected_calendars = PrivateTableV1::new(
        trace
            .certificates
            .iter()
            .map(|certificate| certificate.not_before)
            .chain(
                trace
                    .certificates
                    .iter()
                    .map(|certificate| certificate.not_after),
            )
            .chain([trace.crl.this_update, trace.crl.next_update])
            .collect::<Vec<_>>(),
        zeroize_words_v1,
    );
    if witness.calendar_values[..expected_calendars.len()] != *expected_calendars.as_slice() {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    if witness
        .fixed_bytes
        .iter()
        .any(|row| row.source.value != row.expected)
        || witness
            .equal_bytes
            .iter()
            .any(|row| row.left.value != row.right.value)
        || witness.numeric_relations.iter().any(|row| {
            row.left != row.right.saturating_add(row.slack) || (row.strict && row.slack == 0)
        })
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(witness)
}
/// Unique source address and the exact number of semantic consumers.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280SourceMultiplicityV1 {
    pub(crate) source: ZkX509Rfc5280SourceCellV1,
    pub(crate) required_multiplicity: u16,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn zk_x509_rfc5280_semantic_source_multiplicities_v1(
    witness: &ZkX509Rfc5280SemanticWitnessV1,
) -> Result<PrivateTableV1<ZkX509Rfc5280SourceMultiplicityV1>, ZkX509Rfc5280StarkErrorV1> {
    let mut cells = PrivateTableV1::new(Vec::new(), zeroize_source_cells_v1);
    cells
        .try_reserve(
            witness
                .fixed_bytes
                .len()
                .saturating_add(witness.equal_bytes.len().saturating_mul(2))
                .saturating_add(witness.decimal_cells.len()),
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    cells.extend(witness.fixed_bytes.iter().map(|row| row.source));
    cells.extend(
        witness
            .equal_bytes
            .iter()
            .flat_map(|row| [row.left, row.right]),
    );
    cells.extend(witness.decimal_cells.iter().copied());
    cells.sort_unstable();
    let mut unique = PrivateTableV1::new(Vec::new(), zeroize_source_multiplicities_v1);
    unique
        .try_reserve_exact(cells.len())
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for source in cells.iter().copied() {
        if let Some(last) = unique.last_mut()
            && last.source == source
        {
            last.required_multiplicity = last
                .required_multiplicity
                .checked_add(1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        } else {
            unique.push(ZkX509Rfc5280SourceMultiplicityV1 {
                source,
                required_multiplicity: 1,
            });
        }
    }
    if unique
        .windows(2)
        .any(|pair| pair[0].source >= pair[1].source)
        || unique.iter().any(|entry| entry.required_multiplicity == 0)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Source);
    }
    Ok(unique)
}
/// Compile and validate all private geometry from an owner trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_rfc5280_stark_private_shape_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<ZkX509Rfc5280StarkPrivateShapeV1, ZkX509Rfc5280StarkErrorV1> {
    let semantic = build_zk_x509_rfc5280_semantic_witness_v1(trace)?;
    let public_shape = ZkX509Rfc5280StarkShapeV1::from_statement(&trace.statement)?;
    let profile_byte_table = compile_profile_byte_table_v1(public_shape)?;
    let io = rfc5280_io_witnesses_v1(trace, 0)?;
    let output_rows = io.iter().try_fold(0_usize, |sum, witness| {
        let consumers = witness.declaration.consumers.len();
        if consumers != 1 {
            return Err(ZkX509Rfc5280StarkErrorV1::Output);
        }
        sum.checked_add(
            usize::try_from(witness.declaration.byte_len)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)
    })?;
    let mut shape = ZkX509Rfc5280StarkPrivateShapeV1 {
        chain_depth: u8::try_from(trace.certificates.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        certificate_slot_2_active: F(u64::from(trace.certificates.len() == 3)),
        top_document_count: u8::try_from(trace.documents.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        top_document_lengths: [0; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1],
        top_node_counts: [0; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1],
        embedded_document_count: u8::try_from(trace.embedded_documents.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        embedded_document_lengths: [0; ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1],
        embedded_node_counts: [0; ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1],
        crl_entries: u8::try_from(trace.crl.revoked_serials.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        disclosed_attributes: u8::try_from(trace.statement.disclosed_attribute_indices.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        embedded_copy_rows: u32::try_from(copy_census::active_rows(
            ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
            trace.certificates.len() == 3,
        ))
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        // One verifier-owned rule row plus one canonical ordinal row for
        // every non-root DER node.
        grammar_rows: u32::try_from(
            trace
                .semantic_provenance
                .iter()
                .try_fold(0_usize, |rows, document| {
                    rows.checked_add(document.nodes.len().saturating_sub(1))
                })
                .and_then(|rows| rows.checked_add(ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        name_value_rows: u32::try_from(name_values::private_count(trace)?)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        fixed_byte_rows: u32::try_from(semantic.fixed_bytes.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        equality_rows: u32::try_from(copy_census::active_rows(
            ZkX509Rfc5280StarkFamilyV1::EqualByte,
            trace.certificates.len() == 3,
        ))
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        decimal_rows: u32::try_from(
            semantic.calendar_values.len() * numeric::DECIMAL_ROWS_PER_TIME_V1,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        calendar_rows: u32::try_from(
            semantic
                .calendar_values
                .len()
                .checked_mul(CALENDAR_COPY_PHASES_V1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        relation_rows: u32::try_from(
            semantic.numeric_relations.len() * numeric::RELATION_PHASES_V1,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        basic_constraints_rows: u32::try_from(trace.certificates.len() * path_len::ROWS_PER_SLOT)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        serial_source_rows: u32::try_from(
            semantic
                .serial_sources
                .len()
                .checked_mul(SERIAL_COMPARISON_WIDTH_V1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        serial_rows: u32::try_from(
            semantic
                .serial_comparisons
                .len()
                .checked_mul(SERIAL_COMPARISON_WIDTH_V1)
                .and_then(|rows| rows.checked_mul(SERIAL_COMPARISON_PHASES_V1))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        range_rows: u32::try_from(
            semantic
                .numeric_relations
                .len()
                .checked_mul(8)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        semantic_source_rows: u32::try_from(profile_byte_table.len())
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        semantic_consumer_rows: u32::try_from(copy_census::active_rows(
            ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
            trace.certificates.len() == 3,
        ))
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        output_producer_rows: u32::try_from(output_rows)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        output_consumer_rows: u32::try_from(output_rows)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
        io_channels: u16::try_from(io.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
    };
    for (index, document) in trace.documents.iter().enumerate() {
        shape.top_document_lengths[index] =
            u16::try_from(document.bytes.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        shape.top_node_counts[index] =
            u16::try_from(document.nodes.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    }
    for (index, document) in trace.embedded_documents.iter().enumerate() {
        shape.embedded_document_lengths[index] =
            u16::try_from(document.bytes.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        shape.embedded_node_counts[index] =
            u16::try_from(document.nodes.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    }
    shape.validate()?;
    Ok(shape)
}
/// Return the constant public registration shape after validating the private
/// witness geometry.  No private count is copied into the transcript.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_rfc5280_stark_shape_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<ZkX509Rfc5280StarkShapeV1, ZkX509Rfc5280StarkErrorV1> {
    build_zk_x509_rfc5280_stark_private_shape_v1(trace)?;
    ZkX509Rfc5280StarkShapeV1::from_statement(&trace.statement)
}
pub(crate) type ZkX509Rfc5280StarkBaseRowV1<A = F> = [A; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
pub(crate) type ZkX509Rfc5280StarkAuxRowV1<A = F> = [A; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
pub(crate) type ZkX509Rfc5280StarkFixedRowV1<A = F> = [A; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
/// One byte in the verifier-owned closed-profile pattern table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZkX509Rfc5280ProfileByteEntryV1 {
    purpose: u16,
    variant: u16,
    source_role: u16,
    offset: u16,
    length: u16,
    expected: u8,
    contents_only: bool,
    exact_end: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZkX509Rfc5280OutputTopologyEntryV1 {
    role: ZkX509Rfc5280OutputRoleV1,
    channel: u32,
    producer_endpoint_role: u8,
    consumer_endpoint_role: u8,
    endpoint_instance: u16,
    offset: u32,
}
fn append_profile_pattern_v1(
    entries: &mut Vec<ZkX509Rfc5280ProfileByteEntryV1>,
    purpose: u16,
    variant: u16,
    source_role: ZkX509Rfc5280GrammarRoleV1,
    bytes: &[u8],
    contents_only: bool,
    exact_end: bool,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let length = u16::try_from(bytes.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for (offset, expected) in bytes.iter().copied().enumerate() {
        entries.push(ZkX509Rfc5280ProfileByteEntryV1 {
            purpose,
            variant,
            source_role: source_role as u16,
            offset: u16::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            length,
            expected,
            contents_only,
            exact_end,
        });
    }
    Ok(())
}
fn compile_profile_byte_table_v1(
    shape: ZkX509Rfc5280StarkShapeV1,
) -> Result<Vec<ZkX509Rfc5280ProfileByteEntryV1>, ZkX509Rfc5280StarkErrorV1> {
    shape.validate()?;
    let mut entries = Vec::new();
    for role in [
        ZkX509Rfc5280GrammarRoleV1::CertificateOuterAlgorithm,
        ZkX509Rfc5280GrammarRoleV1::CertificateTbsAlgorithm,
        ZkX509Rfc5280GrammarRoleV1::CrlOuterAlgorithm,
        ZkX509Rfc5280GrammarRoleV1::CrlTbsAlgorithm,
    ] {
        append_profile_pattern_v1(
            &mut entries,
            1,
            0,
            role,
            ECDSA_SHA256_ALGORITHM_V1,
            false,
            true,
        )?;
    }
    append_profile_pattern_v1(
        &mut entries,
        2,
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateSpkiAlgorithm,
        P256_ALGORITHM_V1,
        false,
        true,
    )?;
    append_profile_pattern_v1(
        &mut entries,
        3,
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateVersion,
        &[0x02, 0x01, 0x02],
        true,
        true,
    )?;
    for role in [
        ZkX509Rfc5280GrammarRoleV1::CertificateSignatureValue,
        ZkX509Rfc5280GrammarRoleV1::CrlSignatureValue,
    ] {
        append_profile_pattern_v1(&mut entries, 4, 0, role, &[0], true, false)?;
    }
    append_profile_pattern_v1(
        &mut entries,
        5,
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey,
        &[0, 0x04],
        true,
        false,
    )?;
    for (variant, oid) in CERTIFICATE_EXTENSION_OIDS_V1.into_iter().enumerate() {
        append_profile_pattern_v1(
            &mut entries,
            6,
            u16::try_from(variant).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            ZkX509Rfc5280GrammarRoleV1::CertificateExtensionOid,
            oid,
            true,
            true,
        )?;
    }
    for (variant, oid) in CRL_EXTENSION_OIDS_V1.into_iter().enumerate() {
        append_profile_pattern_v1(
            &mut entries,
            7,
            u16::try_from(variant).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            ZkX509Rfc5280GrammarRoleV1::CrlExtensionOid,
            oid,
            true,
            true,
        )?;
    }
    append_profile_pattern_v1(
        &mut entries,
        8,
        0,
        ZkX509Rfc5280GrammarRoleV1::CertificateExtensionCritical,
        &[0xff],
        true,
        true,
    )?;
    for (variant, oid) in NAME_OIDS_V1.into_iter().enumerate() {
        append_profile_pattern_v1(
            &mut entries,
            9,
            u16::try_from(variant).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            ZkX509Rfc5280GrammarRoleV1::NameAttributeOid,
            oid,
            true,
            true,
        )?;
    }
    append_profile_pattern_v1(
        &mut entries,
        10,
        0,
        ZkX509Rfc5280GrammarRoleV1::EmbeddedKeyUsage,
        &encode_key_usage_v1(shape.leaf_key_usage)?,
        false,
        true,
    )?;
    append_profile_pattern_v1(
        &mut entries,
        10,
        1,
        ZkX509Rfc5280GrammarRoleV1::EmbeddedKeyUsage,
        &encode_key_usage_v1(KEY_USAGE_KEY_CERT_SIGN_V1 | KEY_USAGE_CRL_SIGN_V1)?,
        false,
        true,
    )?;
    append_profile_pattern_v1(
        &mut entries,
        12,
        0,
        ZkX509Rfc5280GrammarRoleV1::EmbeddedEku,
        &encode_eku_v1(&shape.leaf_extended_key_usages()?)?,
        false,
        true,
    )?;
    append_profile_pattern_v1(
        &mut entries,
        13,
        0,
        ZkX509Rfc5280GrammarRoleV1::EmbeddedCrlNumber,
        &encode_unsigned_integer_v1(shape.crl_number),
        false,
        true,
    )?;
    name_values::append_table(&mut entries);
    if entries.len() > FIXED_SEMANTIC_SOURCE_ROWS_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    Ok(entries)
}
/// Index of a key channel in the fixed certificate, CRL, wallet order.
/// Disclosure channels precede these positions and have verifier-owned count.
fn key_output_slot_v1(shape: ZkX509Rfc5280StarkShapeV1, channel: u32) -> Option<usize> {
    let shift = u32::from(shape.disclosed_attribute_count) * 2;
    [14_u32, 17, 20, 27, 28]
        .into_iter()
        .position(|base| channel == base + shift)
}
/// (optional, source-document base, source-document certificate-slot coefficient).
/// The second certificate uses document 1 at depth two and document 2 at depth three.
const KEY_OUTPUT_SOURCES_V1: [(u64, u64, u64); 5] =
    [(0, 1, 0), (0, 1, 1), (1, 2, 0), (0, 1, 0), (0, 0, 0)];
const KEY_OUTPUT_CONTENT_BYTES_V1: u64 = 1 + ZK_X509_UNCOMPRESSED_P256_BYTES_V1 as u64;
const SPKI_OUTPUT_BYTES_V1: usize = 91;
const SPKI_OUTPUT_CONTENT_BYTES_V1: u64 = 89;
// Projection leaf/issuer/optional-root, issuer hash, and governed trust anchor.
const SPKI_OUTPUT_SOURCES_V1: [(u64, u64, u64); 5] =
    [(0, 0, 0), (0, 1, 0), (1, 2, 0), (0, 1, 0), (0, 1, 1)];
fn spki_output_slot_v1(shape: ZkX509Rfc5280StarkShapeV1, channel: u32) -> Option<usize> {
    let shift = u32::from(shape.disclosed_attribute_count) * 2;
    [0, 1, 2, 29 + shift, 30 + shift]
        .into_iter()
        .position(|candidate| candidate == channel)
}

const OUTPUT_SOURCE_PROVENANCE_COLUMNS_V1: [usize; 12] = [
    BASE_A,
    BASE_G,
    BASE_H,
    BASE_DOCUMENT,
    BASE_ADDRESS,
    BASE_NODE,
    BASE_START,
    BASE_CONTENT_START,
    BASE_CONTENT_END,
    BASE_TAG_CLASS,
    BASE_CONSTRUCTED,
    BASE_TAG_NUMBER,
];
const OUTPUT_SOURCE_RESIDUES_V1: usize = 24;
// Existing serial-node queries plus every new fixed key query fit the u16
// multiplicity owner; the byte table's usize total remains far below N.
const _: () = assert!(
    MAX_SERIAL_SOURCE_ROWS_V1 + 5 * ZK_X509_UNCOMPRESSED_P256_BYTES_V1 + 5 * SPKI_OUTPUT_BYTES_V1
        < u16::MAX as usize
);

fn compile_output_topology_v1(
    shape: ZkX509Rfc5280StarkShapeV1,
) -> Result<Vec<ZkX509Rfc5280OutputTopologyEntryV1>, ZkX509Rfc5280StarkErrorV1> {
    const SPKI_DER_BYTES: usize = 91;
    const SIGNATURE_DER_BYTES: usize = 72;
    let strict_der = u8::try_from(endpoint_role_code_v1(ZkX509IoSegmentRoleV1::StrictDer)?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Output)?;
    let mut channels = Vec::new();
    let mut push_channel = |role: ZkX509Rfc5280OutputRoleV1,
                            consumer: ZkX509IoSegmentRoleV1,
                            byte_len: usize|
     -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        let channel =
            u32::try_from(channels.len()).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        let consumer_endpoint_role = u8::try_from(endpoint_role_code_v1(consumer)?)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Output)?;
        channels.push((role, channel, consumer_endpoint_role, byte_len));
        Ok(())
    };
    for _ in 0..3 {
        push_channel(
            ZkX509Rfc5280OutputRoleV1::Projection,
            ZkX509IoSegmentRoleV1::Projection,
            SPKI_DER_BYTES,
        )?;
    }
    for byte_len in [8, ZK_X509_MAX_SERIAL_BYTES_V1] {
        push_channel(
            ZkX509Rfc5280OutputRoleV1::Projection,
            ZkX509IoSegmentRoleV1::Projection,
            byte_len,
        )?;
    }
    for _ in 0..shape.disclosed_attribute_count {
        for byte_len in [8, ZK_X509_MAX_ATTRIBUTE_VALUE_BYTES_V1] {
            push_channel(
                ZkX509Rfc5280OutputRoleV1::Projection,
                ZkX509IoSegmentRoleV1::Projection,
                byte_len,
            )?;
        }
    }
    for _ in 0..3 {
        for byte_len in [ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1, 8] {
            push_channel(
                ZkX509Rfc5280OutputRoleV1::CertificateTbsSha,
                ZkX509IoSegmentRoleV1::Sha256,
                byte_len,
            )?;
        }
    }
    push_channel(
        ZkX509Rfc5280OutputRoleV1::CertificateSlotActive,
        ZkX509IoSegmentRoleV1::P256,
        1,
    )?;
    for _ in 0..3 {
        for byte_len in [SIGNATURE_DER_BYTES, 8] {
            push_channel(
                ZkX509Rfc5280OutputRoleV1::P256Signature,
                ZkX509IoSegmentRoleV1::P256,
                byte_len,
            )?;
        }
        push_channel(
            ZkX509Rfc5280OutputRoleV1::P256PublicKey,
            ZkX509IoSegmentRoleV1::P256,
            ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
        )?;
    }
    for byte_len in [ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1, 8] {
        push_channel(
            ZkX509Rfc5280OutputRoleV1::CrlTbsP256Message,
            ZkX509IoSegmentRoleV1::Sha256,
            byte_len,
        )?;
    }
    for byte_len in [ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1, 8] {
        push_channel(
            ZkX509Rfc5280OutputRoleV1::CrlCommitment,
            ZkX509IoSegmentRoleV1::Sha256,
            byte_len,
        )?;
    }
    for byte_len in [SIGNATURE_DER_BYTES, 8] {
        push_channel(
            ZkX509Rfc5280OutputRoleV1::P256Signature,
            ZkX509IoSegmentRoleV1::P256,
            byte_len,
        )?;
    }
    for _ in 0..2 {
        push_channel(
            ZkX509Rfc5280OutputRoleV1::P256PublicKey,
            ZkX509IoSegmentRoleV1::P256,
            ZK_X509_UNCOMPRESSED_P256_BYTES_V1,
        )?;
    }
    push_channel(
        ZkX509Rfc5280OutputRoleV1::IssuerSpkiSha,
        ZkX509IoSegmentRoleV1::Sha256,
        SPKI_DER_BYTES,
    )?;
    push_channel(
        ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor,
        ZkX509IoSegmentRoleV1::CaAccumulator,
        SPKI_DER_BYTES,
    )?;
    let total_rows = channels.iter().try_fold(0_usize, |sum, channel| {
        sum.checked_add(channel.3)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)
    })?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(total_rows)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for (role, channel, consumer_endpoint_role, byte_len) in channels {
        for offset in 0..byte_len {
            entries.push(ZkX509Rfc5280OutputTopologyEntryV1 {
                role,
                channel,
                producer_endpoint_role: strict_der,
                consumer_endpoint_role,
                endpoint_instance: 0,
                offset: u32::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            });
        }
    }
    if entries.len() > FIXED_OUTPUT_ROWS_PER_SIDE_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    Ok(entries)
}
/// Exact producer rows for the five keys and the optional-certificate selector.
/// Only the public statement shape and existing fixed output topology are consumed.
/// Every key block is the original 65-byte SEC1 source, before P-256 dummy selection.
pub(crate) fn zk_x509_rfc_key_join_rows_v1(
    shape: ZkX509Rfc5280StarkShapeV1,
) -> Result<([usize; 6], [u32; 6], usize, usize), ZkX509Rfc5280StarkErrorV1> {
    shape.validate()?;
    let shift = u32::from(shape.disclosed_attribute_count) * 2;
    let channels = [14_u32, 17, 20, 27, 28, 11].map(|channel| channel + shift);
    let topology = compile_output_topology_v1(shape)?;
    if topology.capacity() != topology.len()
        || topology.len() > FIXED_OUTPUT_ROWS_PER_SIDE_V1
        || core::mem::size_of::<ZkX509Rfc5280OutputTopologyEntryV1>() > 32
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    let strict_der = u8::try_from(endpoint_role_code_v1(ZkX509IoSegmentRoleV1::StrictDer)?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    let p256 = u8::try_from(endpoint_role_code_v1(ZkX509IoSegmentRoleV1::P256)?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    let producer_start = shape.family_counts()
        [..ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
        .iter()
        .try_fold(0_usize, |sum, count| sum.checked_add(*count))
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut rows = [0_usize; 6];
    for (index, channel) in channels.into_iter().enumerate() {
        let role = if index < 5 {
            ZkX509Rfc5280OutputRoleV1::P256PublicKey
        } else {
            ZkX509Rfc5280OutputRoleV1::CertificateSlotActive
        };
        let length = if index < 5 {
            ZK_X509_UNCOMPRESSED_P256_BYTES_V1
        } else {
            1
        };
        let start = topology
            .iter()
            .position(|entry| entry.channel == channel)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Output)?;
        let end = start
            .checked_add(length)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        let block = topology
            .get(start..end)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Output)?;
        if block.iter().enumerate().any(|(offset, entry)| {
            entry.channel != channel
                || entry.role != role
                || entry.offset as usize != offset
                || entry.producer_endpoint_role != strict_der
                || entry.consumer_endpoint_role != p256
                || entry.endpoint_instance != 0
        }) || topology
            .get(end)
            .is_some_and(|entry| entry.channel == channel)
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Output);
        }
        rows[index] = producer_start
            .checked_add(start)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    }
    Ok((rows, channels, BASE_VALUE, BASE_CERT2_ACTIVE))
}

/// Verifier-owned family ranges. It stores only O(1) boundaries, never `2^18` fixed rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280StarkFixedScheduleV1 {
    pub(crate) shape: ZkX509Rfc5280StarkShapeV1,
    counts: [usize; FAMILY_COUNT_V1],
    starts: [usize; FAMILY_COUNT_V1],
    profile_byte_table: Vec<ZkX509Rfc5280ProfileByteEntryV1>,
    output_topology: Vec<ZkX509Rfc5280OutputTopologyEntryV1>,
}
pub(crate) fn compile_zk_x509_rfc5280_stark_fixed_schedule_v1(
    shape: ZkX509Rfc5280StarkShapeV1,
) -> Result<ZkX509Rfc5280StarkFixedScheduleV1, ZkX509Rfc5280StarkErrorV1> {
    shape.validate()?;
    numeric::validate_window_v1(
        shape.presentation_not_before_unix_seconds,
        shape.presentation_not_after_unix_seconds,
    )?;
    let counts = shape.family_counts();
    let mut starts = [0_usize; FAMILY_COUNT_V1];
    let mut cursor = 0_usize;
    for family in 0..FAMILY_COUNT_V1 {
        starts[family] = cursor;
        cursor = cursor
            .checked_add(counts[family])
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    }
    if cursor != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let profile_byte_table = compile_profile_byte_table_v1(shape)?;
    let output_topology = compile_output_topology_v1(shape)?;
    Ok(ZkX509Rfc5280StarkFixedScheduleV1 {
        shape,
        counts,
        starts,
        profile_byte_table,
        output_topology,
    })
}
impl ZkX509Rfc5280StarkFixedScheduleV1 {
    pub(crate) fn family_and_ordinal(
        &self,
        row: usize,
    ) -> Result<(ZkX509Rfc5280StarkFamilyV1, usize), ZkX509Rfc5280StarkErrorV1> {
        if row >= ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        const FAMILIES: [ZkX509Rfc5280StarkFamilyV1; FAMILY_COUNT_V1] = [
            ZkX509Rfc5280StarkFamilyV1::SourceByte,
            ZkX509Rfc5280StarkFamilyV1::SourceNode,
            ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
            ZkX509Rfc5280StarkFamilyV1::Grammar,
            ZkX509Rfc5280StarkFamilyV1::FixedByte,
            ZkX509Rfc5280StarkFamilyV1::EqualByte,
            ZkX509Rfc5280StarkFamilyV1::Decimal,
            ZkX509Rfc5280StarkFamilyV1::Calendar,
            ZkX509Rfc5280StarkFamilyV1::Relation,
            ZkX509Rfc5280StarkFamilyV1::BasicConstraints,
            ZkX509Rfc5280StarkFamilyV1::SerialSource,
            ZkX509Rfc5280StarkFamilyV1::SerialCompare,
            ZkX509Rfc5280StarkFamilyV1::RangeByte,
            ZkX509Rfc5280StarkFamilyV1::SemanticSource,
            ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
            ZkX509Rfc5280StarkFamilyV1::OutputProducer,
            ZkX509Rfc5280StarkFamilyV1::OutputConsumer,
            ZkX509Rfc5280StarkFamilyV1::NameValue,
            ZkX509Rfc5280StarkFamilyV1::Padding,
        ];
        for (index, family) in FAMILIES.into_iter().enumerate() {
            let start = self.starts[index];
            let end = start
                .checked_add(self.counts[index])
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
            if (start..end).contains(&row) {
                return Ok((family, row - start));
            }
        }
        Err(ZkX509Rfc5280StarkErrorV1::Shape)
    }
    /// Reconstruct every selector and expected cell from the row ordinal and public statement
    /// projection. No committed witness value is accepted as an input.
    pub(crate) fn fixed_row(
        &self,
        row: usize,
    ) -> Result<ZkX509Rfc5280StarkFixedRowV1, ZkX509Rfc5280StarkErrorV1> {
        let (family, ordinal) = self.family_and_ordinal(row)?;
        let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        fixed[family as usize] = F::ONE;
        fixed[FIX_GLOBAL_FIRST] = F(u64::from(row == 0));
        fixed[FIX_GLOBAL_LAST] = F(u64::from(row + 1 == ZK_X509_RFC5280_STARK_TRACE_SIZE_V1));
        fixed[FIX_CONTINUE] = F::ONE.sub(fixed[FIX_GLOBAL_LAST]);
        let (local_first, local_last) = match family {
            ZkX509Rfc5280StarkFamilyV1::SerialSource => {
                let group_size = SERIAL_COMPARISON_WIDTH_V1;
                (
                    ordinal % group_size == 0,
                    ordinal % group_size + 1 == group_size,
                )
            }
            ZkX509Rfc5280StarkFamilyV1::SerialCompare => {
                let phase = ordinal % SERIAL_COMPARISON_PHASES_V1;
                let logical_ordinal = ordinal / SERIAL_COMPARISON_PHASES_V1;
                let logical_offset = logical_ordinal % SERIAL_COMPARISON_WIDTH_V1;
                (
                    phase + 1 == SERIAL_COMPARISON_PHASES_V1 && logical_offset == 0,
                    phase + 1 == SERIAL_COMPARISON_PHASES_V1
                        && logical_offset + 1 == SERIAL_COMPARISON_WIDTH_V1,
                )
            }
            ZkX509Rfc5280StarkFamilyV1::RangeByte => (ordinal % 8 == 0, ordinal % 8 + 1 == 8),
            ZkX509Rfc5280StarkFamilyV1::NameValue => {
                (ordinal == 0, ordinal + 1 == self.counts[family as usize])
            }
            _ => (true, true),
        };
        fixed[FIX_LOCAL_FIRST] = F(u64::from(local_first));
        fixed[FIX_LOCAL_LAST] = F(u64::from(local_last));
        fixed[FIX_ACTIVATION_CONTINUE] = F(u64::from(match family {
            ZkX509Rfc5280StarkFamilyV1::SourceByte if ordinal < MAX_TOP_LEVEL_SOURCE_BYTES_V1 => {
                ordinal % ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1 + 1
                    != ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1
            }
            ZkX509Rfc5280StarkFamilyV1::SourceNode => ordinal % 2_048 + 1 != 2_048,
            _ => ordinal + 1 != self.counts[family as usize],
        }));
        if family == ZkX509Rfc5280StarkFamilyV1::SourceByte
            && ordinal < MAX_TOP_LEVEL_SOURCE_BYTES_V1
        {
            let document = ordinal / ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1;
            let address = ordinal % ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1;
            fixed[FIX_EXPECTED] =
                F(u64::try_from(document).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
            fixed[FIX_EXPECTED + 1] =
                F(u64::try_from(address).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
            fixed[FIX_ADDRESS_FIXED] = F::ONE;
            fixed[FIX_DOCUMENT_FIXED] = F::ONE;
            fixed[FIX_REQUIRED_ACTIVE] =
                F(u64::from(address == 0 && matches!(document, 0 | 1 | 2)));
            // With contiguous strict-DER document identifiers, slot three is
            // present exactly for a depth-three chain (it carries the CRL).
            // A depth-two chain has only documents 0, 1, and 2.
            fixed[FIX_CERT2_SLOT_FIRST] = F(u64::from(document == 3 && address == 0));
        }
        copy_census::populate_fixed(&mut fixed, family, ordinal);
        if family == ZkX509Rfc5280StarkFamilyV1::BasicConstraints {
            path_len::populate_fixed(&mut fixed, ordinal);
        }
        if family == ZkX509Rfc5280StarkFamilyV1::FixedByte {
            fixed[FIX_EXPECTED] = F(u64::from(ordinal == 0));
        }
        if family == ZkX509Rfc5280StarkFamilyV1::SourceNode {
            let document = ordinal / 2_048;
            let node = ordinal % 2_048;
            fixed[FIX_EXPECTED] =
                F(u64::try_from(document).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
            fixed[FIX_EXPECTED + 1] =
                F(u64::try_from(node).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
            fixed[FIX_ADDRESS_FIXED] = F::ONE;
            fixed[FIX_DOCUMENT_FIXED] = F::ONE;
            fixed[FIX_REQUIRED_ACTIVE] = F(u64::from(node == 0 && matches!(document, 0 | 1 | 2)));
            fixed[FIX_EXPECTED + 2] = F(u64::from(node == 0));
            fixed[FIX_EXPECTED + 3] = F(u64::from(node == 0 && matches!(document, 0 | 1)));
            fixed[FIX_EXPECTED + 4] = F(u64::from(node == 0 && document == 2));
            fixed[FIX_EXPECTED + 5] = F(u64::from(node == 0 && document == 3));
            fixed[FIX_EXPECTED + 6] = F(u64::from(node == 0 && document >= 4));
        }
        if family == ZkX509Rfc5280StarkFamilyV1::Grammar {
            if let Some(rule) = ZK_X509_RFC5280_GRAMMAR_RULES_V1.get(ordinal).copied() {
                fixed[FIX_EXPECTED..FIX_EXPECTED + 10]
                    .copy_from_slice(&grammar_rule_expected_cells_v1(rule));
                fixed[FIX_REQUIRED_ACTIVE] = F::ONE;
                fixed[FIX_GRAMMAR_RULE] = F::ONE;
                fixed[FIX_GRAMMAR_ORDINAL_FIRST] =
                    F(u64::from(profile_role_required_v1(rule.child_role)));
            } else if ordinal == ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1 {
                fixed[FIX_REQUIRED_ACTIVE] = F::ONE;
                fixed[FIX_GRAMMAR_ORDINAL_FIRST] = F::ONE;
            }
        }
        if family == ZkX509Rfc5280StarkFamilyV1::SerialSource {
            let (logical_id, offset, role, role_instance) = serial_source_descriptor_v1(ordinal)?;
            fixed[FIX_EXPECTED] = F(u64::from(logical_id));
            fixed[FIX_EXPECTED + 1] = F(u64::from(offset));
            fixed[FIX_EXPECTED + 2] = F(role as u64);
            fixed[FIX_EXPECTED + 3] = F(u64::from(role_instance));
            fixed[FIX_EXPECTED + 4] = F(u64::from(usize::from(offset) == 1));
        }
        if family == ZkX509Rfc5280StarkFamilyV1::SerialCompare {
            let logical_ordinal = ordinal / SERIAL_COMPARISON_PHASES_V1;
            let comparison = logical_ordinal / SERIAL_COMPARISON_WIDTH_V1;
            let offset = logical_ordinal % SERIAL_COMPARISON_WIDTH_V1;
            let (kind, left_instance, right_instance) =
                serial_comparison_descriptor_v1(comparison)?;
            // These cells are derived solely from the fixed maximum layout
            // and row ordinal. Private activity flags select an exact prefix.
            fixed[FIX_EXPECTED] = F(kind as u64);
            fixed[FIX_EXPECTED + 1] = F(u64::from(left_instance));
            fixed[FIX_EXPECTED + 2] = F(u64::from(right_instance));
            fixed[FIX_EXPECTED + 3] =
                F(u64::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
            fixed[FIX_EXPECTED + 4] = F(u64::from(offset == 1));
        }
        if family == ZkX509Rfc5280StarkFamilyV1::SemanticSource
            && let Some(entry) = self.profile_byte_table.get(ordinal).copied()
        {
            fixed[FIX_EXPECTED] = F(u64::from(entry.purpose));
            fixed[FIX_EXPECTED + 1] = F(u64::from(entry.variant));
            fixed[FIX_EXPECTED + 2] = F(u64::from(entry.source_role));
            fixed[FIX_EXPECTED + 3] = F(u64::from(entry.offset));
            fixed[FIX_EXPECTED + 4] = F(u64::from(entry.length));
            fixed[FIX_EXPECTED + 5] = F(u64::from(entry.expected));
            fixed[FIX_EXPECTED + 6] = F(u64::from(entry.contents_only));
            fixed[FIX_EXPECTED + 7] = F(u64::from(entry.exact_end));
            fixed[FIX_EXPECTED + 8] = F::ONE;
            fixed[FIX_EXPECTED + 9] = F::ONE;
            fixed[FIX_REQUIRED_ACTIVE] = F::ONE;
        }
        if matches!(
            family,
            ZkX509Rfc5280StarkFamilyV1::OutputProducer | ZkX509Rfc5280StarkFamilyV1::OutputConsumer
        ) && let Some(entry) = self.output_topology.get(ordinal).copied()
        {
            let consumer = family == ZkX509Rfc5280StarkFamilyV1::OutputConsumer;
            fixed[FIX_EXPECTED] = F(entry.role as u64);
            fixed[FIX_EXPECTED + 1] = F(u64::from(entry.channel));
            fixed[FIX_EXPECTED + 2] = F(u64::from(if consumer {
                entry.consumer_endpoint_role
            } else {
                entry.producer_endpoint_role
            }));
            fixed[FIX_EXPECTED + 3] = F(u64::from(entry.endpoint_instance));
            fixed[FIX_EXPECTED + 4] = F(u64::from(entry.offset));
            fixed[FIX_EXPECTED + 5] = F(u64::from(!consumer));
            if !consumer && let Some(slot) = key_output_slot_v1(self.shape, entry.channel) {
                let (optional, document, coefficient) = KEY_OUTPUT_SOURCES_V1[slot];
                fixed[FIX_EXPECTED + 6] = F::ONE;
                fixed[FIX_EXPECTED + 7] = F(optional);
                fixed[FIX_EXPECTED + 8] = F(document);
                fixed[FIX_EXPECTED + 9] = F(coefficient);
            } else if !consumer && let Some(slot) = spki_output_slot_v1(self.shape, entry.channel) {
                let (optional, document, coefficient) = SPKI_OUTPUT_SOURCES_V1[slot];
                fixed[FIX_EXPECTED + 6] = F::ONE;
                fixed[FIX_EXPECTED + 7] = F(optional);
                fixed[FIX_EXPECTED + 8] = F(document);
                fixed[FIX_EXPECTED + 9] = F(coefficient);
                fixed[FIX_OUTPUT_SOURCE_SPKI] = F::ONE;
            }
            variable_output::populate_fixed(
                &mut fixed,
                self.shape,
                entry.channel,
                entry.offset as usize,
                consumer,
            );
            projection_serial::populate_fixed(
                &mut fixed,
                entry.channel,
                entry.offset as usize,
                consumer,
            );
            projection_disclosure::populate_fixed(
                &mut fixed,
                self.shape,
                entry.channel,
                entry.offset as usize,
                consumer,
            );
            fixed[FIX_REQUIRED_ACTIVE] = F::ONE;
            fixed[output_role_fixed_selector_column_v1(
                output_role_index_v1(entry.role),
                consumer,
            )] = F::ONE;
        }
        let active_family = |candidate| F(u64::from(family == candidate));
        fixed[FIX_GRAMMAR_RULE_TABLE] =
            active_family(ZkX509Rfc5280StarkFamilyV1::Grammar).mul(fixed[FIX_GRAMMAR_RULE]);
        fixed[FIX_GRAMMAR_ORDINAL_TABLE] = active_family(ZkX509Rfc5280StarkFamilyV1::Grammar)
            .mul(F::ONE.sub(fixed[FIX_GRAMMAR_RULE]));
        fixed[FIX_SOURCE_NODE_NON_ROOT] = active_family(ZkX509Rfc5280StarkFamilyV1::SourceNode)
            .mul(F::ONE.sub(fixed[FIX_EXPECTED + 2]));
        fixed[FIX_PROFILE_TABLE] =
            active_family(ZkX509Rfc5280StarkFamilyV1::SemanticSource).mul(fixed[FIX_EXPECTED + 9]);
        fixed[FIX_SERIAL_SOURCE_FIRST] =
            active_family(ZkX509Rfc5280StarkFamilyV1::SerialSource).mul(fixed[FIX_LOCAL_FIRST]);
        fixed[FIX_SERIAL_SOURCE_INTERIOR] = active_family(ZkX509Rfc5280StarkFamilyV1::SerialSource)
            .mul(F::ONE.sub(fixed[FIX_LOCAL_FIRST]))
            .mul(F::ONE.sub(fixed[FIX_LOCAL_LAST]));
        fixed[FIX_SERIAL_SOURCE_NOT_FIRST] =
            active_family(ZkX509Rfc5280StarkFamilyV1::SerialSource)
                .mul(F::ONE.sub(fixed[FIX_LOCAL_FIRST]));
        fixed[FIX_SERIAL_SOURCE_FIRST_PAYLOAD] =
            active_family(ZkX509Rfc5280StarkFamilyV1::SerialSource).mul(fixed[FIX_EXPECTED + 4]);
        if family == ZkX509Rfc5280StarkFamilyV1::SerialCompare {
            let phase = ordinal % SERIAL_COMPARISON_PHASES_V1;
            fixed[FIX_SERIAL_COMPARE_PHASE_LEFT] = F(u64::from(phase == 0));
            fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT] =
                F(u64::from(phase + 1 == SERIAL_COMPARISON_PHASES_V1));
            fixed[FIX_SERIAL_COMPARE_FIRST] =
                fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT].mul(fixed[FIX_LOCAL_FIRST]);
            fixed[FIX_SERIAL_COMPARE_LAST] =
                fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT].mul(fixed[FIX_LOCAL_LAST]);
            fixed[FIX_SERIAL_COMPARE_INTERIOR] = fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT]
                .mul(F::ONE.sub(fixed[FIX_LOCAL_FIRST]))
                .mul(F::ONE.sub(fixed[FIX_LOCAL_LAST]));
            fixed[FIX_SERIAL_COMPARE_NOT_FIRST] =
                fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT].mul(F::ONE.sub(fixed[FIX_LOCAL_FIRST]));
            fixed[FIX_SERIAL_COMPARE_FIRST_PAYLOAD] =
                fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT].mul(fixed[FIX_EXPECTED + 4]);
        }
        if family == ZkX509Rfc5280StarkFamilyV1::Calendar {
            fixed[FIX_CALENDAR_PHASES + ordinal % CALENDAR_COPY_PHASES_V1] = F::ONE;
        }
        fixed[FIX_RANGE_TERMINAL] =
            active_family(ZkX509Rfc5280StarkFamilyV1::RangeByte).mul(fixed[FIX_LOCAL_LAST]);
        binding::populate_fixed_v1(&mut fixed, family, ordinal, self.shape)?;
        Ok(fixed)
    }
}
/// Generic one-column replay helper for base and auxiliary providers.
///
/// At log19 this allocates about 4 MiB per field column and never constructs
/// the full base+aux+fixed matrix.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_rfc5280_stark_column_v1(
    width: usize,
    column: usize,
    mut cell: impl FnMut(usize, usize) -> Result<F, ZkX509Rfc5280StarkErrorV1>,
) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
    if column >= width {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let mut values = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
    values
        .try_reserve_exact(ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for row in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
        values.push(cell(row, column)?);
    }
    Ok(values.into_vec())
}
const BASE_VALUE: usize = 0;
const BASE_BYTE_BITS: usize = 1;
const BASE_A: usize = 9;
const BASE_B: usize = 10;
const BASE_C: usize = 11;
const BASE_D: usize = 12;
const BASE_E: usize = 13;
const BASE_F: usize = 14;
const BASE_G: usize = 15;
const BASE_H: usize = 16;
const BASE_DOCUMENT: usize = 17;
const BASE_ADDRESS: usize = 18;
const BASE_NODE: usize = 19;
const BASE_PARENT: usize = 20;
const BASE_CHILD: usize = 21;
const BASE_START: usize = 22;
const BASE_CONTENT_START: usize = 23;
const BASE_CONTENT_END: usize = 24;
const BASE_DEPTH: usize = 25;
const BASE_TAG_CLASS: usize = 26;
const BASE_CONSTRUCTED: usize = 27;
const BASE_TAG_NUMBER: usize = 28;
const BASE_ROLE: usize = 29;
const BASE_INSTANCE: usize = 30;
const BASE_OFFSET: usize = 31;
const BASE_ENDPOINT_ROLE: usize = 32;
const BASE_ENDPOINT_INSTANCE: usize = 33;
const BASE_IS_WRITE: usize = 34;
const BASE_STRICT: usize = 35;
const BASE_EQUAL: usize = 36;
const BASE_INVERSE: usize = 37;
const BASE_STATE_BEFORE: usize = 38;
const BASE_STATE_AFTER: usize = 39;
const BASE_SMALL_BITS: usize = 40;
const BASE_ACTIVE: usize = 64;
const BASE_CERT2_ACTIVE: usize = 65;
const GRAMMAR_CHILD_ORDINAL_BITS: usize = 66;
const GRAMMAR_CHILD_COUNT_BITS: usize = 82;
const BASE_GRAMMAR_ORDINAL: usize = 98;
const BASE_EXPECTED_ROOT_KIND: usize = 99;
const BASE_ORDINAL_NEXT_ACTIVE: usize = 100;
const BASE_ORDINAL_EQUAL_CONTINUE: usize = 101;
const BASE_PROFILE_TABLE_ACTIVE: usize = 102;
const BASE_PROFILE_TABLE_MULTIPLICITY: usize = 103;
const BASE_PROFILE_TOPOLOGY_QUERY_ACTIVE: usize = 104;
const BASE_SERIAL_BYTE_QUERY_ACTIVE: usize = 105;
const BASE_SERIAL_BYTE_QUERY_VALUE: usize = 106;
const BASE_COPY_SOURCE_ACTIVE: usize = 107;
const BASE_COPY_CONSUMER_ACTIVE: usize = 108;
const BASE_COPY_DOMAIN: usize = 109;
const BASE_COPY_KEY_1: usize = 110;
const BASE_COPY_KEY_2: usize = 111;
const BASE_COPY_VALUE: usize = 112;
const _: () = assert!(GRAMMAR_CHILD_COUNT_BITS + 16 == BASE_GRAMMAR_ORDINAL);
const CALENDAR_COLUMNS: usize = BASE_COPY_VALUE + 1;
const CALENDAR_END: usize = CALENDAR_COLUMNS + calendar::WIDTH_V1;
const BASE_COPY_START: usize = CALENDAR_END;
const BASE_COPY_GENERALIZED: usize = BASE_COPY_START + 1;
const BASE_DECIMAL_DIGIT_ACTIVE: usize = BASE_COPY_GENERALIZED + 1;
const BASE_NUMERIC_SOURCE: usize = BASE_DECIMAL_DIGIT_ACTIVE + 1;
const BASE_NUMERIC_QUERY: usize = BASE_NUMERIC_SOURCE + 1;
const BASE_NUMERIC_MULTIPLICITY: usize = BASE_NUMERIC_QUERY + 1;
const BASE_ENTRY_COUNT: usize = BASE_NUMERIC_MULTIPLICITY + 1;
const BASE_ENTRY_CENSUS: usize = BASE_ENTRY_COUNT + 1;
const _: () = assert!(BASE_ENTRY_CENSUS + 1 == ZK_X509_RFC5280_STARK_BASE_WIDTH_V1);
const SERIAL_LESS: usize = BASE_D;
const SERIAL_ORDER_BEFORE: usize = BASE_E;
const SERIAL_ORDER_AFTER: usize = BASE_F;
const SERIAL_LEFT_LENGTH: usize = BASE_G;
const SERIAL_RIGHT_LENGTH: usize = BASE_H;
const SERIAL_LEFT_ACTIVE: usize = BASE_DOCUMENT;
const SERIAL_RIGHT_ACTIVE: usize = BASE_ADDRESS;
const SERIAL_LEFT_COUNT_BEFORE: usize = BASE_NODE;
const SERIAL_LEFT_COUNT_AFTER: usize = BASE_PARENT;
const SERIAL_RIGHT_COUNT_BEFORE: usize = BASE_CHILD;
const SERIAL_RIGHT_COUNT_AFTER: usize = BASE_START;
const SERIAL_LEFT_FIRST_INVERSE: usize = BASE_CONTENT_START;
const SERIAL_RIGHT_FIRST_INVERSE: usize = BASE_CONTENT_END;
const SERIAL_LEFT_BITS: usize = BASE_SMALL_BITS;
const SERIAL_RIGHT_BITS: usize = SERIAL_LEFT_BITS + 8;
const SERIAL_SLACK_BITS: usize = SERIAL_RIGHT_BITS + 8;
const SERIAL_SOURCE_LOGICAL_ID: usize = BASE_ENDPOINT_INSTANCE;
const SERIAL_SOURCE_LENGTH: usize = BASE_B;
const SERIAL_SOURCE_QUERY_VALUE: usize = BASE_C;
const SERIAL_SOURCE_COUNT_BEFORE: usize = BASE_D;
const SERIAL_SOURCE_COUNT_AFTER: usize = BASE_E;
const SERIAL_SOURCE_FIRST_INVERSE: usize = BASE_F;
const SERIAL_BYTE_TABLE_MULTIPLICITY: usize = BASE_C;
const SERIAL_NODE_TABLE_MULTIPLICITY: usize = BASE_F;
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_u8_bits_v1(row: &mut ZkX509Rfc5280StarkBaseRowV1, start: usize, value: u8) {
    for bit in 0..8 {
        row[start + bit] = F(u64::from((value >> bit) & 1));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn write_u16_bits_v1(row: &mut ZkX509Rfc5280StarkBaseRowV1, start: usize, value: u16) {
    for bit in 0..16 {
        row[start + bit] = F(u64::from((value >> bit) & 1));
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn build_zk_x509_rfc5280_serial_comparison_rows_v1(
    comparison: &ZkX509Rfc5280SerialComparisonV1,
) -> Result<PrivateTableV1<ZkX509Rfc5280StarkBaseRowV1>, ZkX509Rfc5280StarkErrorV1> {
    validate_serial_comparison_v1(comparison)?;
    let strict = comparison.kind == ZkX509Rfc5280SerialComparisonKindV1::AdjacentStrictOrder;
    let mut prefix_equal = true;
    let mut order_satisfied = false;
    let left_length = comparison.left[0];
    let right_length = comparison.right[0];
    let mut left_count = 0_u8;
    let mut right_count = 0_u8;
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    rows.try_reserve_exact(SERIAL_COMPARISON_WIDTH_V1)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for offset in 0..SERIAL_COMPARISON_WIDTH_V1 {
        let left = comparison.left[offset];
        let right = comparison.right[offset];
        let equal = left == right;
        let less = strict && prefix_equal && !equal && left < right;
        let slack = if less {
            right
                .checked_sub(left)
                .and_then(|difference| difference.checked_sub(1))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?
        } else {
            0
        };
        let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        row[BASE_ACTIVE] = F::ONE;
        row[BASE_A] = F(u64::from(left));
        row[BASE_B] = F(u64::from(right));
        row[BASE_C] = F(u64::from(slack));
        row[BASE_ROLE] = F(u64::from(comparison.left_instance));
        row[BASE_INSTANCE] = F(u64::from(comparison.right_instance));
        row[BASE_OFFSET] =
            F(u64::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
        row[BASE_STRICT] = F(u64::from(strict));
        row[BASE_EQUAL] = F(u64::from(equal));
        row[BASE_INVERSE] = F(u64::from(left))
            .sub(F(u64::from(right)))
            .inverse_or_zero_canonical_v1();
        row[BASE_STATE_BEFORE] = F(u64::from(prefix_equal));
        row[BASE_STATE_AFTER] = F(u64::from(prefix_equal && equal));
        row[SERIAL_LESS] = F(u64::from(less));
        row[SERIAL_ORDER_BEFORE] = F(u64::from(order_satisfied));
        order_satisfied |= less;
        row[SERIAL_ORDER_AFTER] = F(u64::from(order_satisfied));
        let left_active = offset != 0 && offset <= usize::from(left_length);
        let right_active = offset != 0 && offset <= usize::from(right_length);
        row[SERIAL_LEFT_LENGTH] = F(u64::from(left_length));
        row[SERIAL_RIGHT_LENGTH] = F(u64::from(right_length));
        row[SERIAL_LEFT_ACTIVE] = F(u64::from(left_active));
        row[SERIAL_RIGHT_ACTIVE] = F(u64::from(right_active));
        row[SERIAL_LEFT_COUNT_BEFORE] = F(u64::from(left_count));
        row[SERIAL_RIGHT_COUNT_BEFORE] = F(u64::from(right_count));
        left_count = left_count
            .checked_add(u8::from(left_active))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        right_count = right_count
            .checked_add(u8::from(right_active))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        row[SERIAL_LEFT_COUNT_AFTER] = F(u64::from(left_count));
        row[SERIAL_RIGHT_COUNT_AFTER] = F(u64::from(right_count));
        if offset == 1 {
            row[SERIAL_LEFT_FIRST_INVERSE] = F(u64::from(left))
                .inv()
                .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
            row[SERIAL_RIGHT_FIRST_INVERSE] = F(u64::from(right))
                .inv()
                .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        }
        write_u8_bits_v1(&mut row, SERIAL_LEFT_BITS, left);
        write_u8_bits_v1(&mut row, SERIAL_RIGHT_BITS, right);
        write_u8_bits_v1(&mut row, SERIAL_SLACK_BITS, slack);
        rows.push(row);
        prefix_equal &= equal;
    }
    if (!strict && prefix_equal) || (strict && !order_satisfied) {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    if left_count != left_length || right_count != right_length {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(rows)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn build_zk_x509_rfc5280_serial_source_rows_v1(
    source: &ZkX509Rfc5280SerialSourceV1,
) -> Result<PrivateTableV1<ZkX509Rfc5280StarkBaseRowV1>, ZkX509Rfc5280StarkErrorV1> {
    validate_serial_frame_v1(&source.frame)?;
    let length = source.frame[0];
    let encoded = private_bytes_v1(source.encoded_contents.iter().map(|cell| cell.value))?;
    let magnitude = &source.frame[1..1 + usize::from(length)];
    let sign_padding = encoded.len() == magnitude.len() + 1
        && encoded.first() == Some(&0)
        && encoded.get(1..) == Some(magnitude);
    if (encoded.as_slice() != magnitude && !sign_padding)
        || sign_padding != (magnitude[0] & 0x80 != 0)
        || usize::from(source.node.content_start)
            .checked_add(encoded.len())
            .filter(|end| *end == usize::from(source.node.content_end))
            .is_none()
        || source
            .encoded_contents
            .iter()
            .enumerate()
            .any(|(offset, cell)| {
                cell.document != source.node.document
                    || usize::from(cell.address) != usize::from(source.node.content_start) + offset
            })
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Source);
    }
    let content_len = source
        .node
        .content_end
        .checked_sub(source.node.content_start)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?;
    let mut count = 0_u8;
    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    rows.try_reserve_exact(SERIAL_COMPARISON_WIDTH_V1)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for offset in 0..SERIAL_COMPARISON_WIDTH_V1 {
        let value = source.frame[offset];
        let active = offset != 0 && offset <= usize::from(length);
        let query_padding = offset == 0 && sign_padding;
        let query_active = query_padding || active;
        let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        row[BASE_ACTIVE] = F::ONE;
        row[BASE_VALUE] = F(u64::from(value));
        write_u8_bits_v1(&mut row, BASE_BYTE_BITS, value);
        row[BASE_A] = F(u64::from(content_len));
        row[SERIAL_SOURCE_LENGTH] = F(u64::from(length));
        row[BASE_DOCUMENT] = F(u64::from(source.node.document));
        row[BASE_NODE] = F(u64::from(source.node.node));
        row[BASE_PARENT] = F(u64::from(source.node.parent_node));
        row[BASE_CHILD] = F(u64::from(source.node.child_ordinal));
        row[BASE_START] = F(u64::from(source.node.start));
        row[BASE_CONTENT_START] = F(u64::from(source.node.content_start));
        row[BASE_CONTENT_END] = F(u64::from(source.node.content_end));
        row[BASE_DEPTH] = F(u64::from(source.node.depth));
        row[BASE_TAG_CLASS] = F(u64::from(source.node.tag_class));
        row[BASE_CONSTRUCTED] = F(u64::from(source.node.constructed));
        row[BASE_TAG_NUMBER] = F(u64::from(source.node.tag_number));
        row[BASE_ROLE] = F(source.node.role as u64);
        row[BASE_INSTANCE] = F(u64::from(source.node.role_instance));
        row[BASE_OFFSET] =
            F(u64::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
        row[SERIAL_SOURCE_LOGICAL_ID] = F(u64::from(source.logical_id));
        row[BASE_STRICT] = F(u64::from(sign_padding));
        row[BASE_EQUAL] = F(u64::from(active));
        row[BASE_IS_WRITE] = F(u64::from(query_active));
        row[SERIAL_SOURCE_COUNT_BEFORE] = F(u64::from(count));
        count = count
            .checked_add(u8::from(active))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        row[SERIAL_SOURCE_COUNT_AFTER] = F(u64::from(count));
        if offset == 1 {
            row[SERIAL_SOURCE_FIRST_INVERSE] = F(u64::from(value))
                .inv()
                .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        }
        if query_padding {
            row[BASE_ADDRESS] = F(u64::from(source.node.content_start));
        } else if active {
            let address = usize::from(source.node.content_end)
                .checked_sub(usize::from(length))
                .and_then(|address| address.checked_add(offset - 1))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?;
            row[BASE_ADDRESS] =
                F(u64::try_from(address).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
            row[SERIAL_SOURCE_QUERY_VALUE] = F(u64::from(value));
        }
        rows.push(row);
    }
    if count != length {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(rows)
}
const FIX_GLOBAL_FIRST: usize = FAMILY_COUNT_V1;
const FIX_GLOBAL_LAST: usize = FIX_GLOBAL_FIRST + 1;
const FIX_CONTINUE: usize = FIX_GLOBAL_LAST + 1;
const FIX_LOCAL_FIRST: usize = FIX_CONTINUE + 1;
const FIX_LOCAL_LAST: usize = FIX_LOCAL_FIRST + 1;
const FIX_EXPECTED: usize = FIX_LOCAL_LAST + 1;
const FIX_ACTIVATION_CONTINUE: usize = FIX_EXPECTED + 10;
const FIX_REQUIRED_ACTIVE: usize = FIX_ACTIVATION_CONTINUE + 1;
const FIX_ADDRESS_FIXED: usize = FIX_REQUIRED_ACTIVE + 1;
const FIX_CERT2_OUTPUT: usize = FIX_ADDRESS_FIXED + 1;
const FIX_CERT2_SLOT_FIRST: usize = FIX_CERT2_OUTPUT + 1;
const FIX_DOCUMENT_FIXED: usize = FIX_CERT2_SLOT_FIRST + 1;
const FIX_GRAMMAR_RULE: usize = FIX_DOCUMENT_FIXED + 1;
const FIX_GRAMMAR_ORDINAL_FIRST: usize = FIX_GRAMMAR_RULE + 1;
// Products of verifier-owned selectors are materialized before interpolation.
// Referring to these columns, rather than multiplying their separate LDEs in
// the AIR, keeps the registered polynomial degree truthful.
const FIX_GRAMMAR_RULE_TABLE: usize = FIX_GRAMMAR_ORDINAL_FIRST + 1;
const FIX_GRAMMAR_ORDINAL_TABLE: usize = FIX_GRAMMAR_RULE_TABLE + 1;
const FIX_SOURCE_NODE_NON_ROOT: usize = FIX_GRAMMAR_ORDINAL_TABLE + 1;
const FIX_PROFILE_TABLE: usize = FIX_SOURCE_NODE_NON_ROOT + 1;
const FIX_SERIAL_SOURCE_FIRST: usize = FIX_PROFILE_TABLE + 1;
const FIX_SERIAL_SOURCE_INTERIOR: usize = FIX_SERIAL_SOURCE_FIRST + 1;
const FIX_SERIAL_SOURCE_NOT_FIRST: usize = FIX_SERIAL_SOURCE_INTERIOR + 1;
const FIX_SERIAL_SOURCE_FIRST_PAYLOAD: usize = FIX_SERIAL_SOURCE_NOT_FIRST + 1;
const FIX_SERIAL_COMPARE_PHASE_LEFT: usize = FIX_SERIAL_SOURCE_FIRST_PAYLOAD + 1;
const FIX_SERIAL_COMPARE_PHASE_RIGHT: usize = FIX_SERIAL_COMPARE_PHASE_LEFT + 1;
const FIX_SERIAL_COMPARE_FIRST: usize = FIX_SERIAL_COMPARE_PHASE_RIGHT + 1;
const FIX_SERIAL_COMPARE_LAST: usize = FIX_SERIAL_COMPARE_FIRST + 1;
const FIX_SERIAL_COMPARE_INTERIOR: usize = FIX_SERIAL_COMPARE_LAST + 1;
const FIX_SERIAL_COMPARE_NOT_FIRST: usize = FIX_SERIAL_COMPARE_INTERIOR + 1;
const FIX_SERIAL_COMPARE_FIRST_PAYLOAD: usize = FIX_SERIAL_COMPARE_NOT_FIRST + 1;
const FIX_CALENDAR_PHASES: usize = FIX_SERIAL_COMPARE_FIRST_PAYLOAD + 1;
const FIX_RANGE_TERMINAL: usize = FIX_CALENDAR_PHASES + CALENDAR_COPY_PHASES_V1;
const FIX_OUTPUT_ROLE_PRODUCTS: usize = FIX_RANGE_TERMINAL + 1;
const OUTPUT_ENDPOINT_COUNT_V1: usize = 2;
const FIX_TEMPORAL_FAMILY: usize =
    FIX_OUTPUT_ROLE_PRODUCTS + OUTPUT_ROLE_COUNT_V1 * OUTPUT_ENDPOINT_COUNT_V1;
const FIX_TEMPORAL_DOCUMENT: usize = FIX_TEMPORAL_FAMILY + 1;
const FIX_TEMPORAL_CRL_DOCUMENT: usize = FIX_TEMPORAL_DOCUMENT + 1;
const FIX_TEMPORAL_ROLE: usize = FIX_TEMPORAL_CRL_DOCUMENT + 1;
const FIX_TEMPORAL_INSTANCE: usize = FIX_TEMPORAL_ROLE + 1;
const FIX_TEMPORAL_SLOT: usize = FIX_TEMPORAL_INSTANCE + 1;
const FIX_NUMERIC_REQUIRED: usize = FIX_TEMPORAL_SLOT + 1;
const FIX_NUMERIC_CERT2: usize = FIX_NUMERIC_REQUIRED + 1;
const FIX_TIME_IDENTITY: usize = FIX_NUMERIC_CERT2 + 1;
const FIX_TIME_VALUE: usize = FIX_TIME_IDENTITY + 1;
const FIX_TIME_THIS_UPDATE: usize = FIX_TIME_VALUE + 1;
const FIX_NUMERIC_QUERY: usize = FIX_TIME_THIS_UPDATE + 1;
const FIX_NUMERIC_LEFT: usize = FIX_NUMERIC_QUERY + 1;
const FIX_NUMERIC_RIGHT: usize = FIX_NUMERIC_LEFT + 1;
const FIX_NUMERIC_ENTRY_COUNT: usize = FIX_NUMERIC_RIGHT + 1;
const FIX_TEMPORAL_CONTINUE: usize = FIX_NUMERIC_ENTRY_COUNT + 1;
const FIX_RELATION_CONTINUE: usize = FIX_TEMPORAL_CONTINUE + 1;
const FIX_RANGE_CONTINUE: usize = FIX_RELATION_CONTINUE + 1;
const FIX_RANGE_LEADING_ZERO: usize = FIX_RANGE_CONTINUE + 1;
const FIX_RANGE_HIGH_BITS_ZERO: usize = FIX_RANGE_LEADING_ZERO + 1;
const FIX_OUTPUT_SOURCE_SPKI: usize = FIX_RANGE_HIGH_BITS_ZERO + 1;
const _: () = assert!(projection_disclosure::FIX_END == ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1);
const AUX_NUMERIC_INVERSE: usize = 264;
const AUX_NUMERIC_ZERO: usize = 268;
const AUX_NUMERIC_SUM: usize = 272;
const AUX_NUMERIC_ZERO_SUM: usize = 276;
const AUX_DER_BYTE_BEFORE: usize = 0;
const AUX_DER_BYTE_AFTER: usize = 4;
const AUX_DER_NODE_BEFORE: usize = 8;
const AUX_DER_NODE_AFTER: usize = 12;
const AUX_PROFILE_LOOKUP_ACCUMULATOR: usize = 16;
const AUX_PROFILE_TABLE_INVERSE: usize = 20;
const AUX_PROFILE_QUERY_INVERSE: usize = 24;
const AUX_PROFILE_ZERO_ACCUMULATOR: usize = 28;
const AUX_SHA_UNION_CENTERS: usize = 32;
const AUX_SERIAL_SOURCE_BEFORE: usize = 48;
const AUX_SERIAL_SOURCE_AFTER: usize = 52;
const AUX_SERIAL_CONSUMER_BEFORE: usize = 56;
const AUX_SERIAL_CONSUMER_AFTER: usize = 60;
const AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR: usize = 64;
const AUX_SERIAL_BYTE_TABLE_INVERSE: usize = 68;
const AUX_SERIAL_BYTE_QUERY_INVERSE: usize = 72;
const AUX_SERIAL_BYTE_ZERO_ACCUMULATOR: usize = 76;
const AUX_SERIAL_BYTE_TABLE_ZERO: usize = 80;
const AUX_SERIAL_BYTE_QUERY_ZERO: usize = 84;
const AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR: usize = 88;
const AUX_SERIAL_NODE_TABLE_INVERSE: usize = 92;
const AUX_SERIAL_NODE_QUERY_INVERSE: usize = 96;
const AUX_SERIAL_NODE_ZERO_ACCUMULATOR: usize = 100;
const AUX_SERIAL_NODE_TABLE_ZERO: usize = 104;
const AUX_SERIAL_NODE_QUERY_ZERO: usize = 108;
const AUX_PROFILE_TABLE_ZERO: usize = 112;
const AUX_PROFILE_QUERY_ZERO: usize = 116;
const AUX_PROFILE_TOPOLOGY_QUERY_INVERSE: usize = 120;
const AUX_PROFILE_TOPOLOGY_QUERY_ZERO: usize = 124;
const AUX_GRAMMAR_RULE_LOOKUP_ACCUMULATOR: usize = 128;
const AUX_GRAMMAR_RULE_TABLE_INVERSE: usize = 132;
const AUX_GRAMMAR_RULE_QUERY_INVERSE: usize = 136;
const AUX_GRAMMAR_RULE_ZERO_ACCUMULATOR: usize = 140;
const AUX_GRAMMAR_RULE_TABLE_ZERO: usize = 144;
const AUX_GRAMMAR_RULE_QUERY_ZERO: usize = 148;
const AUX_GRAMMAR_PARENT_LOOKUP_ACCUMULATOR: usize = 152;
const AUX_GRAMMAR_PARENT_TABLE_INVERSE: usize = 156;
const AUX_GRAMMAR_PARENT_QUERY_INVERSE: usize = 160;
const AUX_GRAMMAR_PARENT_ZERO_ACCUMULATOR: usize = 164;
const AUX_GRAMMAR_PARENT_TABLE_ZERO: usize = 168;
const AUX_GRAMMAR_PARENT_QUERY_ZERO: usize = 172;
const AUX_GRAMMAR_ORDINAL_SOURCE_BEFORE: usize = 176;
const AUX_GRAMMAR_ORDINAL_SOURCE_AFTER: usize = 180;
const AUX_GRAMMAR_ORDINAL_TABLE_BEFORE: usize = 184;
const AUX_GRAMMAR_ORDINAL_TABLE_AFTER: usize = 188;
const AUX_OUTPUT_ROLE_PRODUCTS: usize = 192;
/// Only consumers used outside the RFC adapter have public scalar claims.
const PUBLIC_OUTPUT_ROLES_V1: [ZkX509Rfc5280OutputRoleV1; 1] =
    [ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor];
const RFC5280_PRIVATE_OUTPUT_EQUALITIES_V1: usize =
    OUTPUT_ROLE_COUNT_V1 * ZK_X509_RFC5280_STARK_BUS_LANES_V1;
const RFC5280_TERMINAL_RESIDUES_V1: usize =
    RFC5280_PRIVATE_OUTPUT_EQUALITIES_V1 + RFC5280_TERMINAL_CLAIM_RECORDS_V1;
const RFC5280_TERMINAL_CLAIM_RECORDS_V1: usize =
    PUBLIC_OUTPUT_ROLES_V1.len() * ZK_X509_RFC5280_STARK_BUS_LANES_V1;
const _: () = assert!(
    AUX_OUTPUT_ROLE_PRODUCTS
        + OUTPUT_ROLE_COUNT_V1 * OUTPUT_ENDPOINT_COUNT_V1 * ZK_X509_RFC5280_STARK_BUS_LANES_V1
        == AUX_NUMERIC_INVERSE
);
const _: () = assert!(AUX_NUMERIC_ZERO_SUM + 4 == ZK_X509_RFC5280_STARK_AUX_WIDTH_V1);
const _: () = assert!(RFC5280_TERMINAL_CLAIM_RECORDS_V1 == 4);
const fn output_endpoint_index_v1(consumer: bool) -> usize {
    if consumer { 1 } else { 0 }
}
const fn output_role_fixed_selector_column_v1(role_index: usize, consumer: bool) -> usize {
    FIX_OUTPUT_ROLE_PRODUCTS
        + role_index * OUTPUT_ENDPOINT_COUNT_V1
        + output_endpoint_index_v1(consumer)
}
const fn output_role_aux_column_v1(role_index: usize, consumer: bool, lane: usize) -> usize {
    AUX_OUTPUT_ROLE_PRODUCTS
        + (role_index * OUTPUT_ENDPOINT_COUNT_V1 + output_endpoint_index_v1(consumer))
            * ZK_X509_RFC5280_STARK_BUS_LANES_V1
        + lane
}
/// Actual normalized governed-root consumer columns, in compression-lane order.
pub(crate) fn zk_x509_rfc_governed_root_columns_v1() -> [usize; 4] {
    core::array::from_fn(|lane| {
        output_role_aux_column_v1(
            ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor as usize - 1,
            true,
            lane,
        )
    })
}
/// Closed local columns for the private SHA union bridge. The first matrix
/// owns one constant column per physical SHA segment and compression lane;
/// the second selects the four actual RFC consumer roles joined to SHA.
pub(crate) fn zk_x509_rfc_sha_union_columns_v1() -> ([[usize; 4]; 4], [[usize; 4]; 4]) {
    let bridge = core::array::from_fn(|segment| {
        core::array::from_fn(|lane| AUX_SHA_UNION_CENTERS + segment * 4 + lane)
    });
    let roles = [
        ZkX509Rfc5280OutputRoleV1::CertificateTbsSha,
        ZkX509Rfc5280OutputRoleV1::CrlTbsP256Message,
        ZkX509Rfc5280OutputRoleV1::CrlCommitment,
        ZkX509Rfc5280OutputRoleV1::IssuerSpkiSha,
    ];
    let consumer = core::array::from_fn(|index| {
        core::array::from_fn(|lane| {
            output_role_aux_column_v1(roles[index] as usize - 1, true, lane)
        })
    });
    (bridge, consumer)
}

/// One canonical external consumer product; private producers have no wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280OutputRoleTerminalClaimsV1 {
    pub(crate) role: ZkX509Rfc5280OutputRoleV1,
    pub(crate) consumer_products: [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
}
/// Full local RFC relation with only the four public root-SPKI claims removed.
/// The36 private producer/consumer equalities remain in the local relation.
pub(crate) const ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1: usize =
    ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1 - 4;

/// The four-lane governed-root consumer product. DER handoffs and all normalized
/// producer/consumer equalities are proved using committed private endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280StarkTerminalClaimsV1 {
    output_roles: [ZkX509Rfc5280OutputRoleTerminalClaimsV1; PUBLIC_OUTPUT_ROLES_V1.len()],
}
impl ZkX509Rfc5280StarkTerminalClaimsV1 {
    #[cfg(test)]
    fn canonical_identity_v1() -> Self {
        Self {
            output_roles: core::array::from_fn(|index| ZkX509Rfc5280OutputRoleTerminalClaimsV1 {
                role: PUBLIC_OUTPUT_ROLES_V1[index],
                consumer_products: [F::ONE; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
            }),
        }
    }
    #[cfg(test)]
    pub(crate) fn output_role_products_v1(
        &self,
        role: ZkX509Rfc5280OutputRoleV1,
    ) -> Option<ZkX509Rfc5280OutputRoleTerminalClaimsV1> {
        PUBLIC_OUTPUT_ROLES_V1
            .iter()
            .position(|expected| *expected == role)
            .map(|index| self.output_roles[index])
    }
    #[cfg(test)]
    pub(crate) fn governed_trust_anchor_products_v1(
        &self,
    ) -> ZkX509Rfc5280OutputRoleTerminalClaimsV1 {
        self.output_roles[0]
    }
    fn claim_value_v1(&self, claim_index: usize) -> Option<F> {
        self.output_roles
            .get(claim_index / ZK_X509_RFC5280_STARK_BUS_LANES_V1)
            .map(|role| role.consumer_products[claim_index % ZK_X509_RFC5280_STARK_BUS_LANES_V1])
    }
    fn validate_v1(&self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        if self
            .output_roles
            .iter()
            .zip(PUBLIC_OUTPUT_ROLES_V1)
            .any(|(actual, expected)| {
                actual.role != expected
                    || actual
                        .consumer_products
                        .iter()
                        .any(|value| F::canonical(value.0).is_none())
            })
        {
            return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
        }
        Ok(())
    }
}
const P256_TERMINAL_BUS_FAMILIES_V1: usize = 8;
const P256_TERMINAL_CERTIFICATE_CROSS_SOURCES_V1: usize = 4;
const P256_TERMINAL_WALLET_CROSS_SOURCES_V1: usize = 5;
#[cfg(test)]
const P256_TERMINAL_CROSS_START_V1: usize = 1;
#[cfg(test)]
const P256_TERMINAL_CROSS_TERMINAL_V1: usize = 2;
#[cfg(test)]
const P256_TERMINAL_FIRST_CROSS_FAMILY_V1: usize = P256_TERMINAL_BUS_FAMILIES_V1;
#[cfg(test)]
const P256_TERMINAL_SINK_FAMILY_V1: usize =
    P256_TERMINAL_FIRST_CROSS_FAMILY_V1 + P256_TERMINAL_WALLET_CROSS_SOURCES_V1;
const P256_TERMINAL_CERTIFICATE_RECORDS_V1: usize = P256_TERMINAL_BUS_FAMILIES_V1
    * P256_CROSS_TRACE_LANES_V1
    + P256_TERMINAL_CERTIFICATE_CROSS_SOURCES_V1 * 2 * P256_CROSS_TRACE_LANES_V1
    + P256_CROSS_TRACE_LANES_V1;
const P256_TERMINAL_WALLET_RECORDS_V1: usize = P256_TERMINAL_BUS_FAMILIES_V1
    * P256_CROSS_TRACE_LANES_V1
    + P256_TERMINAL_WALLET_CROSS_SOURCES_V1 * 2 * P256_CROSS_TRACE_LANES_V1
    + P256_CROSS_TRACE_LANES_V1;
const P256_TERMINAL_CLAIM_RECORDS_V1: usize = P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1
    * P256_TERMINAL_CERTIFICATE_RECORDS_V1
    + P256_TERMINAL_WALLET_RECORDS_V1;
#[cfg(test)]
const P256_CERTIFICATE_CROSS_ROLES_V1: [P256CrossTraceTerminalRoleV1;
    P256_TERMINAL_CERTIFICATE_CROSS_SOURCES_V1] = [
    P256CrossTraceTerminalRoleV1::ValueWriter,
    P256CrossTraceTerminalRoleV1::WindowBatch,
    P256CrossTraceTerminalRoleV1::DigestReduction,
    P256CrossTraceTerminalRoleV1::ResultXReduction,
];
#[cfg(test)]
const P256_WALLET_CROSS_ROLES_V1: [P256CrossTraceTerminalRoleV1;
    P256_TERMINAL_WALLET_CROSS_SOURCES_V1] = [
    P256CrossTraceTerminalRoleV1::ValueWriter,
    P256CrossTraceTerminalRoleV1::WindowBatch,
    P256CrossTraceTerminalRoleV1::DigestReduction,
    P256CrossTraceTerminalRoleV1::ResultXReduction,
    P256CrossTraceTerminalRoleV1::WalletLowS,
];
const _: () = assert!(P256_CROSS_TRACE_LANES_V1 == 4);
const _: () = assert!(P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 == 4);
const _: () = assert!(P256_X5S1_SIGNATURES_V1 == 5);
const _: () = assert!(P256_TERMINAL_CERTIFICATE_RECORDS_V1 == 68);
const _: () = assert!(P256_TERMINAL_WALLET_RECORDS_V1 == 76);
const _: () = assert!(P256_TERMINAL_CLAIM_RECORDS_V1 == 348);
/// Private prover products for one certificate-or-CRL P-256 equation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) struct ZkX509P256CertificatePrivateProductsV1 {
    /// Eight role-ordered four-lane bus terminals.
    pub(crate) buses: P256BusTerminalClaimsV1,
    /// Four verifier-owned cross-source roles, each with start and terminal.
    pub(crate) cross_sources:
        [P256CrossTraceTerminalClaimV1; P256_TERMINAL_CERTIFICATE_CROSS_SOURCES_V1],
    /// Independent four-lane binding sink.
    pub(crate) sink: [F; P256_CROSS_TRACE_LANES_V1],
}
/// Private prover products for the wallet-ownership P-256 equation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) struct ZkX509P256WalletPrivateProductsV1 {
    /// Eight role-ordered four-lane bus terminals.
    pub(crate) buses: P256BusTerminalClaimsV1,
    /// Five verifier-owned cross-source roles, including wallet low-S.
    pub(crate) cross_sources:
        [P256CrossTraceTerminalClaimV1; P256_TERMINAL_WALLET_CROSS_SOURCES_V1],
    /// Independent four-lane binding sink.
    pub(crate) sink: [F; P256_CROSS_TRACE_LANES_V1],
}
/// Private products retained only by the wiping bound P-256 witness owner.
/// These values have no wire codec and never enter MAIN's public statement or transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) struct ZkX509P256PrivateProductsV1 {
    /// Certificate slots zero through two followed by the signed CRL.
    pub(crate) certificate_or_crl:
        [ZkX509P256CertificatePrivateProductsV1; P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1],
    /// Final wallet-ownership signature.
    pub(crate) wallet: ZkX509P256WalletPrivateProductsV1,
}
#[cfg(test)]
fn empty_p256_bus_terminal_claims_v1() -> P256BusTerminalClaimsV1 {
    let zero = [F::ZERO; P256_CROSS_TRACE_LANES_V1];
    P256BusTerminalClaimsV1 {
        value_execution: zero,
        value_sorted: zero,
        value_arithmetic_copy: zero,
        arithmetic_value_copy: zero,
        arithmetic_scalar: zero,
        window_scalar: zero,
        scalar_bus_arithmetic: zero,
        scalar_bus_window: zero,
    }
}
#[cfg(test)]
fn p256_bus_terminal_claim_value_v1(
    buses: P256BusTerminalClaimsV1,
    family: usize,
    lane: usize,
) -> Option<F> {
    match family {
        0 => buses.value_execution.get(lane).copied(),
        1 => buses.value_sorted.get(lane).copied(),
        2 => buses.value_arithmetic_copy.get(lane).copied(),
        3 => buses.arithmetic_value_copy.get(lane).copied(),
        4 => buses.arithmetic_scalar.get(lane).copied(),
        5 => buses.window_scalar.get(lane).copied(),
        6 => buses.scalar_bus_arithmetic.get(lane).copied(),
        7 => buses.scalar_bus_window.get(lane).copied(),
        _ => None,
    }
}
#[cfg(test)]
fn set_p256_bus_terminal_claim_value_v1(
    buses: &mut P256BusTerminalClaimsV1,
    family: usize,
    lane: usize,
    value: F,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let target = match family {
        0 => buses.value_execution.get_mut(lane),
        1 => buses.value_sorted.get_mut(lane),
        2 => buses.value_arithmetic_copy.get_mut(lane),
        3 => buses.arithmetic_value_copy.get_mut(lane),
        4 => buses.arithmetic_scalar.get_mut(lane),
        5 => buses.window_scalar.get_mut(lane),
        6 => buses.scalar_bus_arithmetic.get_mut(lane),
        7 => buses.scalar_bus_window.get_mut(lane),
        _ => None,
    }
    .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
    *target = value;
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509P256PrivateProductsV1 {
    #[cfg(test)]
    pub(crate) fn canonical_zero_for_test_v1() -> Self {
        Self::empty_v1()
    }
    /// Construct private products from all five native P-256 AIR instances.
    /// Every bus, cross-source chain and sink must already agree; proof verification
    /// independently enforces those equalities through masked polynomial links.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) fn from_p256_air_terminals_v1(
        certificate_or_crl: [ZkX509P256CertificatePrivateProductsV1;
            P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1],
        wallet: ZkX509P256WalletPrivateProductsV1,
    ) -> Result<Self, ZkX509Rfc5280StarkErrorV1> {
        let claims = Self {
            certificate_or_crl,
            wallet,
        };
        claims.validate_air_terminals_v1()?;
        Ok(claims)
    }
    #[cfg(test)]
    fn empty_v1() -> Self {
        Self {
            certificate_or_crl: core::array::from_fn(|_| ZkX509P256CertificatePrivateProductsV1 {
                buses: empty_p256_bus_terminal_claims_v1(),
                cross_sources: core::array::from_fn(|role| P256CrossTraceTerminalClaimV1 {
                    role: P256_CERTIFICATE_CROSS_ROLES_V1[role],
                    start: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                    terminal: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                }),
                sink: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
            }),
            wallet: ZkX509P256WalletPrivateProductsV1 {
                buses: empty_p256_bus_terminal_claims_v1(),
                cross_sources: core::array::from_fn(|role| P256CrossTraceTerminalClaimV1 {
                    role: P256_WALLET_CROSS_ROLES_V1[role],
                    start: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                    terminal: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
                }),
                sink: [F::ZERO; P256_CROSS_TRACE_LANES_V1],
            },
        }
    }
    fn signature_role_v1(signature: usize) -> Option<P256EcdsaRoleV1> {
        if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            Some(P256EcdsaRoleV1::CertificateOrCrl)
        } else if signature == P256_X5S1_SIGNATURES_V1 - 1 {
            Some(P256EcdsaRoleV1::WalletOwnership)
        } else {
            None
        }
    }
    fn signature_parts_v1(
        &self,
        signature: usize,
    ) -> Option<(
        P256BusTerminalClaimsV1,
        &[P256CrossTraceTerminalClaimV1],
        [F; P256_CROSS_TRACE_LANES_V1],
    )> {
        if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            let terminals = self.certificate_or_crl.get(signature)?;
            Some((terminals.buses, &terminals.cross_sources, terminals.sink))
        } else if signature == P256_X5S1_SIGNATURES_V1 - 1 {
            Some((
                self.wallet.buses,
                &self.wallet.cross_sources,
                self.wallet.sink,
            ))
        } else {
            None
        }
    }
    #[cfg(test)]
    fn signature_parts_mut_v1(
        &mut self,
        signature: usize,
    ) -> Option<(
        &mut P256BusTerminalClaimsV1,
        &mut [P256CrossTraceTerminalClaimV1],
        &mut [F; P256_CROSS_TRACE_LANES_V1],
    )> {
        if signature < P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 {
            let terminals = self.certificate_or_crl.get_mut(signature)?;
            Some((
                &mut terminals.buses,
                &mut terminals.cross_sources,
                &mut terminals.sink,
            ))
        } else if signature == P256_X5S1_SIGNATURES_V1 - 1 {
            Some((
                &mut self.wallet.buses,
                &mut self.wallet.cross_sources,
                &mut self.wallet.sink,
            ))
        } else {
            None
        }
    }
    #[cfg(test)]
    fn claim_address_v1(claim_index: usize) -> Option<(usize, usize, usize, usize)> {
        if claim_index >= P256_TERMINAL_CLAIM_RECORDS_V1 {
            return None;
        }
        let certificate_records =
            P256_X5S1_CERTIFICATE_OR_CRL_SIGNATURES_V1 * P256_TERMINAL_CERTIFICATE_RECORDS_V1;
        let (signature, local, cross_sources) = if claim_index < certificate_records {
            (
                claim_index / P256_TERMINAL_CERTIFICATE_RECORDS_V1,
                claim_index % P256_TERMINAL_CERTIFICATE_RECORDS_V1,
                P256_TERMINAL_CERTIFICATE_CROSS_SOURCES_V1,
            )
        } else {
            (
                P256_X5S1_SIGNATURES_V1 - 1,
                claim_index - certificate_records,
                P256_TERMINAL_WALLET_CROSS_SOURCES_V1,
            )
        };
        let bus_records = P256_TERMINAL_BUS_FAMILIES_V1 * P256_CROSS_TRACE_LANES_V1;
        if local < bus_records {
            return Some((
                signature,
                local / P256_CROSS_TRACE_LANES_V1,
                local % P256_CROSS_TRACE_LANES_V1,
                0,
            ));
        }
        let cross_local = local - bus_records;
        let cross_records = cross_sources * 2 * P256_CROSS_TRACE_LANES_V1;
        if cross_local < cross_records {
            let role = cross_local / (2 * P256_CROSS_TRACE_LANES_V1);
            let role_local = cross_local % (2 * P256_CROSS_TRACE_LANES_V1);
            return Some((
                signature,
                P256_TERMINAL_FIRST_CROSS_FAMILY_V1 + role,
                role_local % P256_CROSS_TRACE_LANES_V1,
                P256_TERMINAL_CROSS_START_V1 + role_local / P256_CROSS_TRACE_LANES_V1,
            ));
        }
        let sink_lane = cross_local - cross_records;
        (sink_lane < P256_CROSS_TRACE_LANES_V1).then_some((
            signature,
            P256_TERMINAL_SINK_FAMILY_V1,
            sink_lane,
            0,
        ))
    }
    #[cfg(test)]
    fn claim_value_v1(&self, claim_index: usize) -> Option<F> {
        let (signature, family, lane, endpoint) = Self::claim_address_v1(claim_index)?;
        let (buses, cross_sources, sink) = self.signature_parts_v1(signature)?;
        if family < P256_TERMINAL_BUS_FAMILIES_V1 && endpoint == 0 {
            return p256_bus_terminal_claim_value_v1(buses, family, lane);
        }
        if (P256_TERMINAL_FIRST_CROSS_FAMILY_V1..P256_TERMINAL_SINK_FAMILY_V1).contains(&family) {
            let source = cross_sources.get(family - P256_TERMINAL_FIRST_CROSS_FAMILY_V1)?;
            return match endpoint {
                P256_TERMINAL_CROSS_START_V1 => source.start.get(lane).copied(),
                P256_TERMINAL_CROSS_TERMINAL_V1 => source.terminal.get(lane).copied(),
                _ => None,
            };
        }
        if family == P256_TERMINAL_SINK_FAMILY_V1 && endpoint == 0 {
            return sink.get(lane).copied();
        }
        None
    }
    #[cfg(test)]
    fn set_claim_value_v1(
        &mut self,
        claim_index: usize,
        value: F,
    ) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        let (signature, family, lane, endpoint) =
            Self::claim_address_v1(claim_index).ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
        let (buses, cross_sources, sink) = self
            .signature_parts_mut_v1(signature)
            .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
        if family < P256_TERMINAL_BUS_FAMILIES_V1 && endpoint == 0 {
            return set_p256_bus_terminal_claim_value_v1(buses, family, lane, value);
        }
        if (P256_TERMINAL_FIRST_CROSS_FAMILY_V1..P256_TERMINAL_SINK_FAMILY_V1).contains(&family) {
            let source = cross_sources
                .get_mut(family - P256_TERMINAL_FIRST_CROSS_FAMILY_V1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            let target = match endpoint {
                P256_TERMINAL_CROSS_START_V1 => source.start.get_mut(lane),
                P256_TERMINAL_CROSS_TERMINAL_V1 => source.terminal.get_mut(lane),
                _ => None,
            }
            .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            *target = value;
            return Ok(());
        }
        if family == P256_TERMINAL_SINK_FAMILY_V1 && endpoint == 0 {
            *sink
                .get_mut(lane)
                .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)? = value;
            return Ok(());
        }
        Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
    }
    fn validate_topology_v1(&self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        for signature in 0..P256_X5S1_SIGNATURES_V1 {
            let role = Self::signature_role_v1(signature)
                .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            let (buses, cross_sources, sink) = self
                .signature_parts_v1(signature)
                .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            evaluate_p256_bus_terminal_claim_equalities_v1(buses)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            evaluate_p256_cross_trace_terminal_claim_equalities_v1(role, cross_sources, sink)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
        }
        Ok(())
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn validate_air_terminals_v1(&self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        self.validate_topology_v1()?;
        for signature in 0..P256_X5S1_SIGNATURES_V1 {
            let role = Self::signature_role_v1(signature)
                .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            let (buses, cross_sources, sink) = self
                .signature_parts_v1(signature)
                .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            let bus_residues = evaluate_p256_bus_terminal_claim_equalities_v1(buses)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            let cross_residues =
                evaluate_p256_cross_trace_terminal_claim_equalities_v1(role, cross_sources, sink)
                    .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            if bus_residues
                .iter()
                .chain(&cross_residues)
                .any(|residue| *residue != F::ZERO)
            {
                return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
            }
        }
        Ok(())
    }
}
/// Compare two private synthetic product fixtures without a serialized claim path.
/// The first fixture must satisfy the complete bus and source-chain equalities.
#[cfg(test)]
pub(crate) fn evaluate_zk_x509_p256_terminal_claim_residues_v1(
    committed: ZkX509P256PrivateProductsV1,
    claims: ZkX509P256PrivateProductsV1,
) -> Result<[F; P256_TERMINAL_CLAIM_RECORDS_V1], ZkX509Rfc5280StarkErrorV1> {
    committed.validate_air_terminals_v1()?;
    claims.validate_topology_v1()?;
    Ok(core::array::from_fn(|claim_index| {
        let expected = committed
            .claim_value_v1(claim_index)
            .expect("bounded committed P-256 terminal");
        let claimed = claims
            .claim_value_v1(claim_index)
            .expect("bounded proof P-256 terminal");
        expected.sub(claimed)
    }))
}
fn pack_bits_v1<A: PolynomialAirFieldV1>(bits: &[A]) -> A {
    bits.iter()
        .copied()
        .enumerate()
        .fold(A::ZERO, |sum, (bit, value)| {
            sum.add(value.mul(A::from_base(F(1_u64 << bit))))
        })
}
fn push_boolean_v1<A: PolynomialAirFieldV1>(residues: &mut Vec<A>, gate: A, value: A) {
    residues.push(gate.mul(value).mul(value.sub(A::ONE)));
}
fn push_gated_zero_safe_inverse_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    denominator: A,
    zero: A,
    inverse: A,
) {
    residues.push(zero.mul(zero.sub(A::ONE)));
    residues.push(A::ONE.sub(gate).mul(zero));
    residues.push(A::ONE.sub(gate).mul(inverse));
    residues.push(denominator.mul(zero));
    residues.push(denominator.mul(inverse).sub(gate.mul(A::ONE.sub(zero))));
    residues.push(zero.mul(inverse));
}
fn push_reused_gated_zero_safe_inverse_v1<A: PolynomialAirFieldV1>(
    residues: &mut Vec<A>,
    gate: A,
    denominator: A,
    zero: A,
    inverse: A,
) {
    // These helper cells are shared by several mutually exclusive row
    // families. Canonicalize the zero flag and inverse only while this family
    // is active; another family may legitimately assign both cells.
    residues.push(gate.mul(zero).mul(zero.sub(A::ONE)));
    residues.push(gate.mul(denominator).mul(zero));
    residues.push(gate.mul(denominator.mul(inverse).sub(A::ONE.sub(zero))));
    residues.push(gate.mul(zero).mul(inverse));
}
#[inline]
fn assert_residue_section_v1(
    residues_len: usize,
    section_start: &mut usize,
    section: (&'static str, usize),
) {
    debug_assert_eq!(
        residues_len - *section_start,
        section.1,
        "RFC 5280 residue section `{}` drifted",
        section.0
    );
    *section_start = residues_len;
}
/// Bind both output families to their verifier-owned channel schedule.
///
/// This authenticates event metadata. The five key and five SPKI producers and
/// nine variable TBS/CRL/signature byte-and-length pairs are separately bound to
/// DER below, as are the canonical leaf serial magnitude and selected original
/// Subject/OID/value bytes. The NamePolicy and NameValue families separately bind
/// the complete original OID/value census, OID uniqueness and closed string policy.
/// TODO: finish end-to-end adversarial qualification of full parser equivalence.
/// The family selectors and activity remain field-valued at OOD points, so the
/// full expression has degree three including fixed-column polynomials.
fn output_metadata_residues_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> [A; 6] {
    let output = family_gate_v1(fixed, ZkX509Rfc5280StarkFamilyV1::OutputProducer)
        .add(family_gate_v1(
            fixed,
            ZkX509Rfc5280StarkFamilyV1::OutputConsumer,
        ))
        .mul(current[BASE_ACTIVE]);
    let columns = [
        BASE_ROLE,
        BASE_INSTANCE,
        BASE_ENDPOINT_ROLE,
        BASE_ENDPOINT_INSTANCE,
        BASE_OFFSET,
        BASE_IS_WRITE,
    ];
    core::array::from_fn(|index| {
        output.mul(current[columns[index]].sub(fixed[FIX_EXPECTED + index]))
    })
}
/// Authenticate fixed key and complete SPKI outputs to DER byte/node queries.
/// The verifier-fixed source kind selects a 65-byte key or exact 91-byte DER SPKI.
/// BASE_D is committed before challenges; optional selection does not increase
/// the lookup recurrence degree. All selectors remain polynomials.
fn output_source_residues_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> [A; OUTPUT_SOURCE_RESIDUES_V1] {
    let producer = family_gate_v1(fixed, ZkX509Rfc5280StarkFamilyV1::OutputProducer)
        .sub(fixed[variable_output::FIX_VARIABLE])
        .sub(fixed[projection_serial::FIX_SERIAL])
        .sub(fixed[projection_disclosure::FIX_DISCLOSURE]);
    let key = fixed[FIX_EXPECTED + 6];
    let optional = fixed[FIX_EXPECTED + 7];
    let spki = fixed[FIX_OUTPUT_SOURCE_SPKI];
    let live = current[BASE_D];
    let query = producer.mul(live);
    let mut residues = [A::ZERO; OUTPUT_SOURCE_RESIDUES_V1];
    residues[0] = producer.mul(
        live.sub(
            key.mul(
                A::ONE
                    .sub(optional)
                    .add(optional.mul(current[BASE_CERT2_ACTIVE])),
            ),
        ),
    );
    for (index, difference) in [
        current[BASE_DOCUMENT].sub(
            fixed[FIX_EXPECTED + 8].add(fixed[FIX_EXPECTED + 9].mul(current[BASE_CERT2_ACTIVE])),
        ),
        current[BASE_G].sub(
            A::from_base(F(ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey as u64))
                .sub(spki.mul(A::from_base(F(2)))),
        ),
        current[BASE_H].sub(current[BASE_DOCUMENT]),
        current[BASE_TAG_CLASS],
        current[BASE_CONSTRUCTED].sub(spki),
        current[BASE_TAG_NUMBER].sub(A::from_base(F(3)).add(spki.mul(A::from_base(F(13))))),
        current[BASE_A].sub(A::from_base(F(KEY_OUTPUT_CONTENT_BYTES_V1)).add(spki.mul(
            A::from_base(F(SPKI_OUTPUT_CONTENT_BYTES_V1 - KEY_OUTPUT_CONTENT_BYTES_V1)),
        ))),
        current[BASE_CONTENT_END]
            .sub(current[BASE_CONTENT_START])
            .sub(current[BASE_A]),
        current[BASE_ADDRESS]
            .sub(
                A::ONE
                    .sub(spki)
                    .mul(current[BASE_CONTENT_START].add(A::ONE)),
            )
            .sub(spki.mul(current[BASE_START]))
            .sub(fixed[FIX_EXPECTED + 4]),
    ]
    .into_iter()
    .enumerate()
    {
        residues[1 + index] = query.mul(difference);
    }
    // Absent optional sources and other producer families have no source claim.
    for (index, column) in OUTPUT_SOURCE_PROVENANCE_COLUMNS_V1.into_iter().enumerate() {
        residues[10 + index] = producer.mul(A::ONE.sub(live)).mul(current[column]);
    }
    residues[22] = producer.mul(key.sub(live)).mul(current[BASE_VALUE]);
    residues[23] = query.mul(spki).mul(
        current[BASE_CONTENT_END]
            .sub(current[BASE_START])
            .sub(A::from_base(F(SPKI_OUTPUT_BYTES_V1 as u64))),
    );
    residues
}
fn output_source_query_gate_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> A {
    family_gate_v1(fixed, ZkX509Rfc5280StarkFamilyV1::OutputProducer).mul(current[BASE_D])
}

fn output_source_node_query_gate_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> A {
    output_source_query_gate_v1(current, fixed)
        .add(fixed[projection_serial::FIX_LENGTH_LAST])
        .add(fixed[projection_disclosure::FIX_LENGTH_FIRST])
        .add(fixed[projection_disclosure::FIX_VALUE_FIRST])
}

fn private_geometry_residues_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    next: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> Vec<A> {
    let mut residues = Vec::with_capacity(5 + ZK_X509_RFC5280_STARK_BASE_WIDTH_V1);
    let active = current[BASE_ACTIVE];
    let cert2_active = current[BASE_CERT2_ACTIVE];
    push_boolean_v1(&mut residues, A::ONE, active);
    push_boolean_v1(&mut residues, A::ONE, cert2_active);
    residues.push(
        fixed[FIX_CERT2_OUTPUT]
            .mul(active)
            .mul(current[BASE_VALUE].sub(cert2_active)),
    );
    residues.push(
        fixed[FIX_ACTIVATION_CONTINUE]
            .mul(next[BASE_ACTIVE])
            .mul(A::ONE.sub(active)),
    );
    residues.push(fixed[FIX_REQUIRED_ACTIVE].mul(active.sub(A::ONE)));
    residues.push(fixed[FIX_CERT2_SLOT_FIRST].mul(active.sub(cert2_active)));
    let fixed_grouped = [
        ZkX509Rfc5280StarkFamilyV1::SerialSource,
        ZkX509Rfc5280StarkFamilyV1::SerialCompare,
        ZkX509Rfc5280StarkFamilyV1::RangeByte,
        ZkX509Rfc5280StarkFamilyV1::Decimal,
        ZkX509Rfc5280StarkFamilyV1::Calendar,
        ZkX509Rfc5280StarkFamilyV1::Relation,
    ]
    .into_iter()
    .fold(A::ZERO, |sum, family| {
        sum.add(family_gate_v1(fixed, family))
    });
    residues.push(
        fixed_grouped
            .mul(active)
            .mul(A::ONE.sub(next[BASE_ACTIVE]))
            .mul(A::ONE.sub(fixed[FIX_LOCAL_LAST])),
    );
    let padding = family_gate_v1(fixed, ZkX509Rfc5280StarkFamilyV1::Padding);
    residues.push(padding.mul(active));
    for (column, value) in current.iter().copied().enumerate() {
        if !matches!(
            column,
            BASE_ACTIVE | BASE_CERT2_ACTIVE | BASE_ENTRY_COUNT | BASE_ENTRY_CENSUS
        ) {
            residues.push(A::ONE.sub(active).mul(value));
        }
    }
    residues.push(fixed[FIX_CONTINUE].mul(next[BASE_CERT2_ACTIVE].sub(cert2_active)));
    debug_assert_eq!(residues.len(), 5 + ZK_X509_RFC5280_STARK_BASE_WIDTH_V1);
    residues
}
fn family_gate_v1<A: PolynomialAirFieldV1>(
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    family: ZkX509Rfc5280StarkFamilyV1,
) -> A {
    fixed[family as usize]
}
fn active_family_gate_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    family: ZkX509Rfc5280StarkFamilyV1,
) -> A {
    current[BASE_ACTIVE].mul(family_gate_v1(fixed, family))
}
fn output_row_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(80)),
            current[BASE_ROLE],
            current[BASE_INSTANCE],
            current[BASE_ENDPOINT_ROLE],
            current[BASE_ENDPOINT_INSTANCE],
            current[BASE_OFFSET],
            current[BASE_VALUE],
            current[BASE_IS_WRITE],
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
/// The one receiver of each verifier-owned output role. Instance is zero in
/// every output topology entry; channel and offset identify the exact byte.
const OUTPUT_CONSUMER_ENDPOINTS_V1: [u64; OUTPUT_ROLE_COUNT_V1] = [6, 2, 2, 2, 3, 3, 2, 4, 3];
/// Compress a producer byte with its fixed receiver's tags. Consumer products
/// retain their actual metadata, already bound by output_metadata_residues_v1.
/// Reusing existing producer auxiliary owners adds neither openings nor columns.
fn output_role_product_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    role_index: usize,
    consumer: bool,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    if consumer {
        return output_row_factor_v1(current, lane, challenges);
    }
    compress_tuple_v1(
        [
            A::from_base(F(80)),
            current[BASE_ROLE],
            current[BASE_INSTANCE],
            A::from_base(F(OUTPUT_CONSUMER_ENDPOINTS_V1[role_index])),
            A::ZERO,
            current[BASE_OFFSET],
            current[BASE_VALUE],
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
#[cfg(test)]
fn serial_copy_factor_v1(
    logical_id: F,
    offset: F,
    value: F,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> F {
    compress_tuple_v1(
        [
            F(90),
            logical_id,
            offset,
            value,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn normalized_copy_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            current[BASE_COPY_DOMAIN],
            current[BASE_COPY_KEY_1],
            current[BASE_COPY_KEY_2],
            current[BASE_COPY_VALUE],
            current[BASE_COPY_START],
            current[BASE_COPY_GENERALIZED],
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn serial_byte_lookup_factor_v1<A: PolynomialAirFieldV1>(
    document: A,
    address: A,
    value: A,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(91)),
            document,
            address,
            value,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn profile_byte_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(96)),
            current[BASE_ROLE],
            current[BASE_ENDPOINT_ROLE],
            current[BASE_PARENT],
            current[BASE_OFFSET],
            current[BASE_B],
            current[BASE_VALUE],
            current[BASE_ENDPOINT_INSTANCE],
            current[BASE_CHILD],
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn profile_topology_source_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(97)),
            current[BASE_ROLE],
            current[BASE_DOCUMENT],
            current[BASE_NODE],
            current[BASE_START],
            current[BASE_CONTENT_START],
            current[BASE_CONTENT_END],
            current[BASE_INSTANCE],
            current[BASE_TAG_NUMBER],
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn profile_topology_query_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(97)),
            current[BASE_PARENT],
            current[BASE_DOCUMENT],
            current[BASE_NODE],
            current[BASE_CONTENT_START],
            current[BASE_DEPTH],
            current[BASE_TAG_NUMBER],
            current[BASE_H],
            current[BASE_TAG_CLASS],
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn serial_node_lookup_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(92)),
            current[BASE_DOCUMENT],
            current[BASE_NODE],
            current[BASE_START],
            current[BASE_CONTENT_START],
            current[BASE_CONTENT_END],
            current[BASE_TAG_CLASS],
            current[BASE_CONSTRUCTED],
            current[BASE_TAG_NUMBER],
            current[BASE_ROLE],
            current[BASE_INSTANCE],
            current[BASE_A],
        ],
        challenges.tuple[lane],
    )
}
/// Remap only the two output-owned metadata slots. The table identity stays
/// byte-for-byte unchanged; output queries use their separate grammar aliases.
fn node_query_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    serial_node_lookup_factor_v1(current, lane, challenges).add(
        family_gate_v1(fixed, ZkX509Rfc5280StarkFamilyV1::OutputProducer).mul(
            current[BASE_G]
                .sub(current[BASE_ROLE])
                .mul_base(challenges.tuple[lane][9])
                .add(
                    current[BASE_H]
                        .sub(current[BASE_INSTANCE])
                        .mul_base(challenges.tuple[lane][10]),
                ),
        ),
    )
}

fn grammar_rule_table_factor_v1<A: PolynomialAirFieldV1>(
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(93)),
            fixed[FIX_EXPECTED],
            fixed[FIX_EXPECTED + 1],
            fixed[FIX_EXPECTED + 2],
            fixed[FIX_EXPECTED + 3],
            fixed[FIX_EXPECTED + 4],
            fixed[FIX_EXPECTED + 5],
            fixed[FIX_EXPECTED + 6],
            fixed[FIX_EXPECTED + 7],
            fixed[FIX_EXPECTED + 8],
            fixed[FIX_EXPECTED + 9],
            fixed[FIX_GRAMMAR_ORDINAL_FIRST],
        ],
        challenges.tuple[lane],
    )
}
fn grammar_rule_query_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(93)),
            current[BASE_B],
            current[BASE_ROLE],
            grammar_tag_pack_v1(
                current[BASE_TAG_CLASS],
                current[BASE_CONSTRUCTED],
                current[BASE_TAG_NUMBER],
            ),
            grammar_ordinal_pack_v1(
                current[BASE_IS_WRITE],
                current[BASE_STRICT],
                current[BASE_STATE_BEFORE],
            ),
            grammar_count_pack_v1(current[BASE_EQUAL], current[BASE_STATE_AFTER]),
            current[BASE_OFFSET],
            current[BASE_ENDPOINT_ROLE],
            current[BASE_ENDPOINT_INSTANCE],
            current[BASE_H],
            current[BASE_E],
            current[BASE_INVERSE],
        ],
        challenges.tuple[lane],
    )
}
fn grammar_parent_table_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(94)),
            current[BASE_DOCUMENT],
            current[BASE_NODE],
            current[BASE_ROLE],
            current[BASE_INSTANCE],
            current[BASE_D],
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn grammar_parent_query_factor_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(94)),
            current[BASE_DOCUMENT],
            current[BASE_PARENT],
            current[BASE_B],
            current[BASE_C],
            current[BASE_G],
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
fn grammar_ordinal_factor_v1<A: PolynomialAirFieldV1>(
    document: A,
    parent: A,
    child: A,
    child_count: A,
    lane: usize,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> A {
    compress_tuple_v1(
        [
            A::from_base(F(95)),
            document,
            parent,
            child,
            child_count,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
            A::ZERO,
        ],
        challenges.tuple[lane],
    )
}
/// Challenge-independent canonical RFC 5280 trace material.
///
/// Rows retain the prefix selected by their public family and ordinal. Omitted
/// nonzero fields reject during construction; replay restores the exact full
/// 285-column row. Sparse fixed-capacity gaps replay as the unique inactive zero
/// row before carried selectors and deterministic helpers are populated. The
/// owner never allocates the full `2^19 × 285` matrix.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ZkX509Rfc5280StarkBaseMaterialV1 {
    pub(crate) private_shape: ZkX509Rfc5280StarkPrivateShapeV1,
    pub(crate) schedule: ZkX509Rfc5280StarkFixedScheduleV1,
    family_rows: [source_rows::FamilyRowsV1; FAMILY_COUNT_V1],
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509Rfc5280StarkBaseMaterialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509Rfc5280StarkBaseMaterialV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509Rfc5280StarkBaseMaterialV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280StarkBaseMaterialV1 {
    /// Allocated sparse row payload; providers only borrow these rows.
    pub(crate) fn allocated_heap_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            sum_v1(
                self.family_rows
                    .iter()
                    .map(source_rows::FamilyRowsV1::allocated_heap_bytes_v1),
            ),
            vector_v1(&self.schedule.profile_byte_table),
            vector_v1(&self.schedule.output_topology),
        ])
    }
    /// Recursively overwrite every private shape cell and committed field row.
    pub(crate) fn zeroize_private_v1(&mut self) {
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.chain_depth));
        zeroize_fields_v1(core::slice::from_mut(
            &mut self.private_shape.certificate_slot_2_active,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.top_document_count,
        ));
        zeroize_words_v1(&mut self.private_shape.top_document_lengths);
        zeroize_words_v1(&mut self.private_shape.top_node_counts);
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.embedded_document_count,
        ));
        zeroize_words_v1(&mut self.private_shape.embedded_document_lengths);
        zeroize_words_v1(&mut self.private_shape.embedded_node_counts);
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.crl_entries));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.disclosed_attributes,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.embedded_copy_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.grammar_rows));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.fixed_byte_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.name_value_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.equality_rows));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.decimal_rows));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.calendar_rows));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.relation_rows));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.basic_constraints_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.serial_source_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.serial_rows));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.range_rows));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.semantic_source_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.semantic_consumer_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.output_producer_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(
            &mut self.private_shape.output_consumer_rows,
        ));
        zeroize_words_v1(core::slice::from_mut(&mut self.private_shape.io_channels));
        for family in &mut self.family_rows {
            family.clear();
        }
    }
    #[cfg(test)]
    pub(crate) fn private_is_zeroized_v1(&self) -> bool {
        let shape = &self.private_shape;
        shape.chain_depth == 0
            && shape.certificate_slot_2_active == F::ZERO
            && shape.top_document_count == 0
            && shape.top_document_lengths.iter().all(|value| *value == 0)
            && shape.top_node_counts.iter().all(|value| *value == 0)
            && shape.embedded_document_count == 0
            && shape
                .embedded_document_lengths
                .iter()
                .all(|value| *value == 0)
            && shape.embedded_node_counts.iter().all(|value| *value == 0)
            && shape.crl_entries == 0
            && shape.disclosed_attributes == 0
            && shape.embedded_copy_rows == 0
            && shape.grammar_rows == 0
            && shape.fixed_byte_rows == 0
            && shape.name_value_rows == 0
            && shape.equality_rows == 0
            && shape.decimal_rows == 0
            && shape.calendar_rows == 0
            && shape.relation_rows == 0
            && shape.basic_constraints_rows == 0
            && shape.serial_source_rows == 0
            && shape.serial_rows == 0
            && shape.range_rows == 0
            && shape.semantic_source_rows == 0
            && shape.semantic_consumer_rows == 0
            && shape.output_producer_rows == 0
            && shape.output_consumer_rows == 0
            && shape.io_channels == 0
            && self
                .family_rows
                .iter()
                .all(source_rows::FamilyRowsV1::is_empty)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn active_zero_row_v1() -> ZkX509Rfc5280StarkBaseRowV1 {
    let mut row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
    row[BASE_ACTIVE] = F::ONE;
    row
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn byte_row_v1(document: u64, address: u64, value: u8) -> ZkX509Rfc5280StarkBaseRowV1 {
    let mut row = active_zero_row_v1();
    row[BASE_VALUE] = F(u64::from(value));
    write_u8_bits_v1(&mut row, BASE_BYTE_BITS, value);
    row[BASE_DOCUMENT] = F(document);
    row[BASE_ADDRESS] = F(address);
    row
}
/// Grow by copying into a clearing owner, then erase the displaced allocation.
/// Ordinary Vec reallocation could free an initialized private row allocation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn reserve_private_family_rows_v1(
    rows: &mut Vec<ZkX509Rfc5280StarkBaseRowV1>,
    length: usize,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    if length > ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    if length <= rows.capacity() {
        return Ok(());
    }
    let capacity = length
        .checked_next_power_of_two()
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut replacement = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
    replacement
        .try_reserve_exact(capacity)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    replacement.extend_from_slice(rows);
    zeroize_field_rows_v1(rows);
    *rows = replacement.into_vec();
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn ensure_family_slot_v1(
    rows: &mut Vec<ZkX509Rfc5280StarkBaseRowV1>,
    ordinal: usize,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let length = ordinal
        .checked_add(1)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    if rows.len() < length {
        reserve_private_family_rows_v1(rows, length)?;
        rows.resize(length, [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_family_row_v1(
    rows: &mut Vec<ZkX509Rfc5280StarkBaseRowV1>,
    row: ZkX509Rfc5280StarkBaseRowV1,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let length = rows
        .len()
        .checked_add(1)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    reserve_private_family_rows_v1(rows, length)?;
    rows.push(row);
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_time_nodes_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> impl Iterator<Item = ZkX509Rfc5280NodeProvenanceV1> + '_ {
    role_nodes_v1(trace, ZkX509Rfc5280GrammarRoleV1::CertificateNotBefore)
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CertificateNotAfter,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlThisUpdate,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlNextUpdate,
        ))
        .chain(role_nodes_v1(
            trace,
            ZkX509Rfc5280GrammarRoleV1::CrlEntryTime,
        ))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CalendarOperandsV1 {
    generalized: bool,
    timestamp: u64,
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn calendar_operands_v1(
    cells: &[ZkX509Rfc5280SourceCellV1],
    tag: u32,
) -> Result<CalendarOperandsV1, ZkX509Rfc5280StarkErrorV1> {
    let (timestamp, decimal) = parse_time_cells_v1(cells, tag)?;
    let bytes = private_bytes_v1(decimal.iter().map(|cell| cell.value))?;
    let (year, offset) = match tag {
        23 => {
            let short = u64::from(parse_decimal_v1(&bytes[..2])?);
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                2,
            )
        }
        24 => (u64::from(parse_decimal_v1(&bytes[..4])?), 4),
        _ => return Err(ZkX509Rfc5280StarkErrorV1::Semantic),
    };
    Ok(CalendarOperandsV1 {
        generalized: tag == 24,
        timestamp,
        year,
        month: u64::from(parse_decimal_v1(&bytes[offset..offset + 2])?),
        day: u64::from(parse_decimal_v1(&bytes[offset + 2..offset + 4])?),
        hour: u64::from(parse_decimal_v1(&bytes[offset + 4..offset + 6])?),
        minute: u64::from(parse_decimal_v1(&bytes[offset + 6..offset + 8])?),
        second: u64::from(parse_decimal_v1(&bytes[offset + 8..offset + 10])?),
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn calendar_row_v1(
    operands: CalendarOperandsV1,
) -> Result<ZkX509Rfc5280StarkBaseRowV1, ZkX509Rfc5280StarkErrorV1> {
    let mut row = active_zero_row_v1();
    row[BASE_A] = F(operands.year);
    row[BASE_B] = F(operands.month);
    row[BASE_C] = F(operands.day);
    row[BASE_D] = F(operands.hour);
    row[BASE_E] = F(operands.minute);
    row[BASE_F] = F(operands.second);
    row[BASE_G] = F(operands.timestamp);
    row[BASE_H] = F(calendar::populate_v1(
        operands,
        &mut row[CALENDAR_COLUMNS..CALENDAR_END],
    )?);
    Ok(row)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn output_base_row_v1(
    role: ZkX509Rfc5280OutputRoleV1,
    channel: u32,
    endpoint: ZkX509IoEndpointV1,
    offset: usize,
    value: u8,
    is_write: bool,
) -> Result<ZkX509Rfc5280StarkBaseRowV1, ZkX509Rfc5280StarkErrorV1> {
    let mut row = active_zero_row_v1();
    row[BASE_VALUE] = F(u64::from(value));
    write_u8_bits_v1(&mut row, BASE_BYTE_BITS, value);
    row[BASE_ROLE] = F(role as u64);
    row[BASE_INSTANCE] = F(u64::from(channel));
    row[BASE_OFFSET] = F(u64::try_from(offset).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
    row[BASE_ENDPOINT_ROLE] = F(endpoint_role_code_v1(endpoint.role)?);
    row[BASE_ENDPOINT_INSTANCE] = F(u64::from(endpoint.instance));
    row[BASE_IS_WRITE] = F(u64::from(is_write));
    Ok(row)
}
/// Borrow all five exact whole-SPKI source nodes without copying private bytes.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn spki_output_nodes_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<[Option<&ZkX509Rfc5280NodeProvenanceV1>; 5], ZkX509Rfc5280StarkErrorV1> {
    if !(2..=3).contains(&trace.certificates.len()) {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let cert2 = u64::from(trace.certificates.len() == 3);
    let mut result = [None; 5];
    for (slot, (optional, document, coefficient)) in SPKI_OUTPUT_SOURCES_V1.into_iter().enumerate()
    {
        if optional == 1 && cert2 == 0 {
            continue;
        }
        let document = usize::try_from(document + coefficient * cert2)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        let provenance = trace
            .semantic_provenance
            .get(document)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
        let mut nodes = provenance.nodes.iter().filter(|node| {
            node.role == ZkX509Rfc5280GrammarRoleV1::CertificateSpki
                && usize::from(node.role_instance) == document
        });
        let node = nodes.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
        if nodes.next().is_some()
            || usize::from(node.document) != document
            || node.content_end.checked_sub(node.start) != Some(SPKI_OUTPUT_BYTES_V1 as u16)
            || node.content_end.checked_sub(node.content_start)
                != Some(SPKI_OUTPUT_CONTENT_BYTES_V1 as u16)
            || node.tag_class != 0
            || !node.constructed
            || node.tag_number != 16
            || usize::from(node.content_end)
                > trace
                    .documents
                    .get(document)
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?
                    .bytes
                    .len()
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Source);
        }
        result[slot] = Some(node);
    }
    Ok(result)
}
/// Borrow the unique exact key nodes; no copied byte/node allocation is added.
/// These are construction operands only. The opened-row constraints independently
/// authenticate the same node identity, length and byte address.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn key_output_nodes_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<[Option<&ZkX509Rfc5280NodeProvenanceV1>; 5], ZkX509Rfc5280StarkErrorV1> {
    if !(2..=3).contains(&trace.certificates.len()) {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let cert2 = u64::from(trace.certificates.len() == 3);
    let mut result = [None; 5];
    for (slot, (optional, document, coefficient)) in KEY_OUTPUT_SOURCES_V1.into_iter().enumerate() {
        if optional == 1 && cert2 == 0 {
            continue;
        }
        let document = usize::try_from(document + coefficient * cert2)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        let provenance = trace
            .semantic_provenance
            .get(document)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
        let mut nodes = provenance.nodes.iter().filter(|node| {
            node.role == ZkX509Rfc5280GrammarRoleV1::CertificatePublicKey
                && usize::from(node.role_instance) == document
        });
        let node = nodes.next().ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
        if nodes.next().is_some()
            || usize::from(node.document) != document
            || node.content_end.checked_sub(node.content_start)
                != Some(KEY_OUTPUT_CONTENT_BYTES_V1 as u16)
            || node.tag_class != 0
            || node.constructed
            || node.tag_number != 3
            || usize::from(node.content_end)
                > trace
                    .documents
                    .get(document)
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?
                    .bytes
                    .len()
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Source);
        }
        result[slot] = Some(node);
    }
    Ok(result)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn populate_der_output_row_v1(
    row: &mut ZkX509Rfc5280StarkBaseRowV1,
    trace: &ZkX509Rfc5280TraceV1,
    node: Option<&ZkX509Rfc5280NodeProvenanceV1>,
    offset: usize,
    whole_spki: bool,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    let width = if whole_spki {
        SPKI_OUTPUT_BYTES_V1
    } else {
        ZK_X509_UNCOMPRESSED_P256_BYTES_V1
    };
    if offset >= width {
        return Err(ZkX509Rfc5280StarkErrorV1::Output);
    }
    let Some(node) = node else {
        return if row[BASE_VALUE] == F::ZERO {
            Ok(())
        } else {
            Err(ZkX509Rfc5280StarkErrorV1::Output)
        };
    };
    let start = if whole_spki {
        usize::from(node.start)
    } else {
        usize::from(node.content_start) + 1
    };
    let address = start
        .checked_add(offset)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    let byte = trace
        .documents
        .get(usize::from(node.document))
        .and_then(|document| document.bytes.get(address))
        .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?;
    if address >= usize::from(node.content_end) || row[BASE_VALUE] != byte.value.value {
        return Err(ZkX509Rfc5280StarkErrorV1::Output);
    }
    row[BASE_D] = F::ONE;
    row[BASE_A] = F(if whole_spki {
        SPKI_OUTPUT_CONTENT_BYTES_V1
    } else {
        KEY_OUTPUT_CONTENT_BYTES_V1
    });
    row[BASE_G] = F(node.role as u64);
    row[BASE_H] = F(u64::from(node.role_instance));
    row[BASE_DOCUMENT] = F(u64::from(node.document));
    row[BASE_ADDRESS] = F(address as u64);
    row[BASE_NODE] = F(u64::from(node.node));
    row[BASE_START] = F(u64::from(node.start));
    row[BASE_CONTENT_START] = F(u64::from(node.content_start));
    row[BASE_CONTENT_END] = F(u64::from(node.content_end));
    row[BASE_TAG_CLASS] = F(u64::from(node.tag_class));
    row[BASE_CONSTRUCTED] = F(u64::from(node.constructed));
    row[BASE_TAG_NUMBER] = F(u64::from(node.tag_number));
    Ok(())
}

// The sole caller supplies a fresh active_zero_row_v1 with untouched gap
// cells. Explicit zero inverse/gap/bit writes therefore preserve its zero
// difference case. Keep malformed-input writes in the original order.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn populate_ordinal_gap_v1(
    row: &mut ZkX509Rfc5280StarkBaseRowV1,
    difference: u64,
) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    row[BASE_B] = F(difference);
    row[BASE_EQUAL] = F(u64::from(difference == 0));
    row[BASE_INVERSE] = F::canonical(difference)
        .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?
        .inverse_or_zero_canonical_v1();
    let gap = difference.saturating_sub(1);
    row[BASE_C] = F(gap);
    write_u16_bits_v1(
        row,
        GRAMMAR_CHILD_ORDINAL_BITS,
        u16::try_from(gap).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
    );
    Ok(())
}

/// Compile every canonical base family from the strict-DER owner trace.
#[allow(clippy::too_many_lines)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_rfc5280_stark_base_material_v1(
    trace: &ZkX509Rfc5280TraceV1,
) -> Result<ZkX509Rfc5280StarkBaseMaterialV1, ZkX509Rfc5280StarkErrorV1> {
    validate_zk_x509_rfc5280_provenance_v1(trace)?;
    let semantic = build_zk_x509_rfc5280_semantic_witness_v1(trace)?;
    let private_shape = build_zk_x509_rfc5280_stark_private_shape_v1(trace)?;
    let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(
        build_zk_x509_rfc5280_stark_shape_v1(trace)?,
    )?;
    let mut family_rows: [PrivateTableV1<ZkX509Rfc5280StarkBaseRowV1>; FAMILY_COUNT_V1] =
        core::array::from_fn(|_| PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1));
    let (serial_byte_multiplicities, serial_node_multiplicities) =
        zk_x509_rfc5280_serial_lookup_multiplicities_v1(&semantic.serial_sources)?;
    let semantic_multiplicities = zk_x509_rfc5280_semantic_source_multiplicities_v1(&semantic)?;
    let key_nodes = key_output_nodes_v1(trace)?;
    let spki_nodes = spki_output_nodes_v1(trace)?;
    let variable_nodes = variable_output::nodes(trace)?;
    let projection_serial_source = projection_serial::source(trace)?;
    let basic_constraints_sources = path_len::sources(trace)?;
    let copy_sources = copy_census::Sources::new(trace)?;
    let projection_disclosure_sources = projection_disclosure::sources(trace)?;
    let byte_lookup_count = serial_byte_multiplicities
        .iter()
        .chain(semantic_multiplicities.iter())
        .try_fold(0usize, |count, entry| {
            count.checked_add(usize::from(entry.required_multiplicity))
        })
        .and_then(|count| {
            trace
                .embedded_byte_rows
                .len()
                .checked_mul(2)
                .and_then(|embedded| count.checked_add(embedded))
        })
        .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
    let mut byte_lookup_cells = PrivateTableV1::new(Vec::new(), zeroize_source_cells_v1);
    byte_lookup_cells
        .try_reserve_exact(byte_lookup_count)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for entry in serial_byte_multiplicities.iter() {
        byte_lookup_cells.extend(core::iter::repeat_n(
            entry.source,
            usize::from(entry.required_multiplicity),
        ));
    }
    for entry in semantic_multiplicities.iter() {
        byte_lookup_cells.extend(core::iter::repeat_n(
            entry.source,
            usize::from(entry.required_multiplicity),
        ));
    }
    for embedded in &trace.embedded_byte_rows {
        let value =
            u8::try_from(embedded.value.value.0).map_err(|_| ZkX509Rfc5280StarkErrorV1::Source)?;
        byte_lookup_cells.push(ZkX509Rfc5280SourceCellV1 {
            document: u8::try_from(embedded.parent_document.value.0)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            address: u16::try_from(embedded.parent_offset.value.0)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            value,
        });
        byte_lookup_cells.push(ZkX509Rfc5280SourceCellV1 {
            document: u8::try_from(
                trace
                    .documents
                    .len()
                    .checked_add(
                        usize::try_from(embedded.embedded_document.value.0)
                            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                    )
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?,
            )
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            address: u16::try_from(embedded.embedded_offset.value.0)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            value,
        });
    }
    byte_lookup_cells.sort_unstable();
    let serial_byte_multiplicity = |document: usize, address: usize, value: u8| {
        u64::try_from(
            byte_lookup_cells
                .iter()
                .filter(|entry| {
                    usize::from(entry.document) == document
                        && usize::from(entry.address) == address
                        && entry.value == value
                })
                .count()
                + name_values::byte_multiplicity(trace, document, address)
                + path_len::byte_multiplicity(&basic_constraints_sources, document, address)
                + key_nodes
                    .iter()
                    .flatten()
                    .filter(|node| {
                        usize::from(node.document) == document
                            && address > usize::from(node.content_start)
                            && address < usize::from(node.content_end)
                    })
                    .count()
                + spki_nodes
                    .iter()
                    .flatten()
                    .filter(|node| {
                        usize::from(node.document) == document
                            && address >= usize::from(node.start)
                            && address < usize::from(node.content_end)
                    })
                    .count()
                + variable_output::byte_multiplicity(&variable_nodes, document, address)
                + projection_serial::byte_multiplicity(
                    &projection_serial_source,
                    document,
                    address,
                )
                + projection_disclosure::byte_multiplicity(
                    &projection_disclosure_sources,
                    document,
                    address,
                ),
        )
        .expect("bounded RFC lookup multiplicity fits u64")
    };
    let serial_node_multiplicity = |document: usize, node: usize| {
        let multiplicity = serial_node_multiplicities
            .iter()
            .find(|entry| {
                usize::from(entry.document) == document && usize::from(entry.node) == node
            })
            .map_or(0, |entry| entry.required_multiplicity)
            + (key_nodes
                .iter()
                .flatten()
                .filter(|entry| {
                    usize::from(entry.document) == document && usize::from(entry.node) == node
                })
                .count()
                * ZK_X509_UNCOMPRESSED_P256_BYTES_V1) as u16
            + (spki_nodes
                .iter()
                .flatten()
                .filter(|entry| {
                    usize::from(entry.document) == document && usize::from(entry.node) == node
                })
                .count()
                * SPKI_OUTPUT_BYTES_V1) as u16
            + variable_output::node_multiplicity(&variable_nodes, document, node)
            + projection_serial::node_multiplicity(&projection_serial_source, document, node)
            + projection_disclosure::node_multiplicity(
                &projection_disclosure_sources,
                document,
                node,
            );
        multiplicity
            .checked_add(path_len::node_multiplicity(
                &basic_constraints_sources,
                document,
                node,
            ))
            .and_then(|value| value.checked_add(copy_sources.node_multiplicity(document, node)))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)
    };
    let source_byte_family = ZkX509Rfc5280StarkFamilyV1::SourceByte as usize;
    for (document, source) in trace.documents.iter().enumerate() {
        for (address, byte) in source.bytes.iter().enumerate() {
            let ordinal = document
                .checked_mul(ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1)
                .and_then(|start| start.checked_add(address))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
            ensure_family_slot_v1(&mut family_rows[source_byte_family], ordinal)?;
            let value =
                u8::try_from(byte.value.value.0).map_err(|_| ZkX509Rfc5280StarkErrorV1::Source)?;
            let mut row = byte_row_v1(
                u64::try_from(document).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                u64::try_from(address).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                value,
            );
            row[SERIAL_BYTE_TABLE_MULTIPLICITY] = F(u64::from(serial_byte_multiplicity(
                document, address, value,
            )));
            family_rows[source_byte_family][ordinal] = row;
        }
    }
    let mut embedded_byte_ordinal = MAX_TOP_LEVEL_SOURCE_BYTES_V1;
    for (embedded, source) in trace.embedded_documents.iter().enumerate() {
        let document = trace
            .documents
            .len()
            .checked_add(embedded)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        for (address, byte) in source.bytes.iter().enumerate() {
            ensure_family_slot_v1(&mut family_rows[source_byte_family], embedded_byte_ordinal)?;
            let value =
                u8::try_from(byte.value.value.0).map_err(|_| ZkX509Rfc5280StarkErrorV1::Source)?;
            let mut row = byte_row_v1(
                u64::try_from(document).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                u64::try_from(address).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
                value,
            );
            row[SERIAL_BYTE_TABLE_MULTIPLICITY] = F(u64::from(serial_byte_multiplicity(
                document, address, value,
            )));
            family_rows[source_byte_family][embedded_byte_ordinal] = row;
            embedded_byte_ordinal = embedded_byte_ordinal
                .checked_add(1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        }
    }
    let source_node_family = ZkX509Rfc5280StarkFamilyV1::SourceNode as usize;
    let mut grammar_rule_multiplicities = [0_u32; ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1];
    for provenance in &trace.semantic_provenance {
        let document = usize::from(provenance.document);
        for node in &provenance.nodes {
            let node_index = usize::from(node.node);
            let child_count = u16::try_from(
                provenance
                    .nodes
                    .iter()
                    .filter(|candidate| usize::from(candidate.parent_node) == node_index)
                    .count(),
            )
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
            let (parent_role, parent_instance, parent_child_count) = if node_index == 0 {
                (0_u16, 0_u16, child_count)
            } else {
                let parent = provenance
                    .nodes
                    .get(usize::from(node.parent_node))
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
                let parent_child_count = u16::try_from(
                    provenance
                        .nodes
                        .iter()
                        .filter(|candidate| candidate.parent_node == parent.node)
                        .count(),
                )
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
                (parent.role as u16, parent.role_instance, parent_child_count)
            };
            let rule_index = grammar_rule_index_for_node_v1(
                *node,
                parent_role,
                parent_instance,
                parent_child_count,
            )?;
            grammar_rule_multiplicities[rule_index] = grammar_rule_multiplicities[rule_index]
                .checked_add(1)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
            let rule = ZK_X509_RFC5280_GRAMMAR_RULES_V1[rule_index];
            let ordinal = document
                .checked_mul(2_048)
                .and_then(|start| start.checked_add(node_index))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
            ensure_family_slot_v1(&mut family_rows[source_node_family], ordinal)?;
            let mut row = active_zero_row_v1();
            row[BASE_A] = F(u64::from(
                node.content_end
                    .checked_sub(node.content_start)
                    .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?,
            ));
            let quotient = u8::try_from(parent_instance / 256)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
            let remainder = u8::try_from(parent_instance % 256)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
            row[BASE_VALUE] = F(u64::from(quotient));
            write_u8_bits_v1(&mut row, BASE_BYTE_BITS, quotient);
            row[BASE_B] = F(u64::from(parent_role));
            row[BASE_C] = F(u64::from(parent_instance));
            row[BASE_D] = F(u64::from(child_count));
            row[BASE_E] = F(u64::from(rule.root_kind));
            row[SERIAL_NODE_TABLE_MULTIPLICITY] =
                F(u64::from(serial_node_multiplicity(document, node_index)?));
            row[BASE_G] = F(u64::from(parent_child_count));
            row[BASE_H] = F(u64::from(rule.constant));
            row[BASE_DOCUMENT] = F(u64::from(node.document));
            row[BASE_ADDRESS] = F(u64::from(remainder));
            row[BASE_NODE] = F(u64::from(node.node));
            row[BASE_PARENT] = F(if node.parent_node == u16::MAX {
                0
            } else {
                u64::from(node.parent_node)
            });
            row[BASE_CHILD] = F(u64::from(node.child_ordinal));
            row[BASE_START] = F(u64::from(node.start));
            row[BASE_CONTENT_START] = F(u64::from(node.content_start));
            row[BASE_CONTENT_END] = F(u64::from(node.content_end));
            row[BASE_DEPTH] = F(u64::from(node.depth));
            row[BASE_TAG_CLASS] = F(u64::from(node.tag_class));
            row[BASE_CONSTRUCTED] = F(u64::from(node.constructed));
            row[BASE_TAG_NUMBER] = F(u64::from(node.tag_number));
            row[BASE_ROLE] = F(node.role as u64);
            row[BASE_INSTANCE] = F(u64::from(node.role_instance));
            row[BASE_OFFSET] = F(u64::from(rule.quotient_scale));
            row[BASE_ENDPOINT_ROLE] = F(u64::from(rule.remainder_scale));
            row[BASE_ENDPOINT_INSTANCE] = F(u64::from(rule.ordinal_scale));
            row[BASE_IS_WRITE] = F(u64::from(rule.ordinal_exact));
            row[BASE_STRICT] = F(u64::from(rule.ordinal_last));
            row[BASE_EQUAL] = F(u64::from(rule.count_exact));
            row[BASE_INVERSE] = F(u64::from(profile_role_required_v1(node.role as u16)));
            row[BASE_STATE_BEFORE] = F(u64::from(rule.ordinal_parameter));
            row[BASE_STATE_AFTER] = F(u64::from(rule.count_parameter));
            write_u8_bits_v1(&mut row, BASE_SMALL_BITS, remainder);
            write_u8_bits_v1(
                &mut row,
                BASE_SMALL_BITS + 8,
                u8::try_from(rule.ordinal_parameter)
                    .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            );
            write_u8_bits_v1(
                &mut row,
                BASE_SMALL_BITS + 16,
                u8::try_from(rule.count_parameter)
                    .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?,
            );
            write_u16_bits_v1(&mut row, GRAMMAR_CHILD_ORDINAL_BITS, node.child_ordinal);
            write_u16_bits_v1(&mut row, GRAMMAR_CHILD_COUNT_BITS, child_count);
            binding::populate_node_classification_v1(&mut row);
            name_policy::populate_source_node(&mut row)?;
            profile_identity::populate_source_node(&mut row);
            family_rows[source_node_family][ordinal] = row;
        }
    }
    let grammar_family = ZkX509Rfc5280StarkFamilyV1::Grammar as usize;
    for multiplicity in grammar_rule_multiplicities {
        let mut row = active_zero_row_v1();
        row[BASE_A] = F(u64::from(multiplicity));
        push_family_row_v1(&mut family_rows[grammar_family], row)?;
    }
    let mut ordinal_entries = PrivateTableV1::new(Vec::new(), |rows| {
        for (document, parent, child, count) in rows {
            zeroize_words_v1(core::slice::from_mut(document));
            zeroize_words_v1(core::slice::from_mut(parent));
            zeroize_words_v1(core::slice::from_mut(child));
            zeroize_words_v1(core::slice::from_mut(count));
        }
    });
    ordinal_entries
        .try_reserve(private_shape.source_nodes()?)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    for provenance in &trace.semantic_provenance {
        for node in provenance.nodes.iter().skip(1) {
            let parent = provenance
                .nodes
                .get(usize::from(node.parent_node))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
            let parent_child_count = u16::try_from(
                provenance
                    .nodes
                    .iter()
                    .filter(|candidate| candidate.parent_node == parent.node)
                    .count(),
            )
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
            ordinal_entries.push((
                node.document,
                node.parent_node,
                node.child_ordinal,
                parent_child_count,
            ));
        }
    }
    ordinal_entries.sort_unstable();
    for (index, (document, parent, child, child_count)) in
        ordinal_entries.iter().copied().enumerate()
    {
        let key = u64::from(document)
            .checked_mul(2_048)
            .and_then(|value| value.checked_add(u64::from(parent)))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
        let mut row = active_zero_row_v1();
        row[BASE_A] = F(key);
        row[BASE_D] = F(u64::from(child_count));
        row[BASE_DOCUMENT] = F(u64::from(document));
        row[BASE_PARENT] = F(u64::from(parent));
        row[BASE_CHILD] = F(u64::from(child));
        if let Some((next_document, next_parent, _, _)) = ordinal_entries.get(index + 1).copied() {
            let next_key = u64::from(next_document)
                .checked_mul(2_048)
                .and_then(|value| value.checked_add(u64::from(next_parent)))
                .ok_or(ZkX509Rfc5280StarkErrorV1::Resource)?;
            let difference = next_key
                .checked_sub(key)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Grammar)?;
            populate_ordinal_gap_v1(&mut row, difference)?;
        }
        row[BASE_ORDINAL_NEXT_ACTIVE] = F(u64::from(index + 1 < ordinal_entries.len()));
        row[BASE_ORDINAL_EQUAL_CONTINUE] = row[BASE_ORDINAL_NEXT_ACTIVE].mul(row[BASE_EQUAL]);
        push_family_row_v1(&mut family_rows[grammar_family], row)?;
    }
    for family in [
        ZkX509Rfc5280StarkFamilyV1::EqualByte,
        ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
        ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
    ] {
        copy_census::populate_rows(
            trace,
            &copy_sources,
            family,
            &mut family_rows[family as usize],
        )?;
    }
    let fixed_family = ZkX509Rfc5280StarkFamilyV1::FixedByte as usize;
    let mut previous_name_key = 0;
    for source in &semantic.fixed_bytes {
        let mut row = byte_row_v1(
            u64::from(source.source.document),
            u64::from(source.source.address),
            source.source.value,
        );
        row[BASE_A] = F(u64::from(source.expected));
        row[BASE_B] = F(u64::from(source.length));
        row[BASE_H] = F(u64::from(source.source_node.role_instance));
        row[BASE_TAG_CLASS] = F(u64::from(source.source_node.tag_number));
        row[BASE_NODE] = F(u64::from(source.source_node.node));
        row[BASE_PARENT] = F(source.source_node.role as u64);
        row[BASE_CHILD] = F(u64::from(matches!(
            source.purpose,
            1 | 2 | 3 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13
        )));
        row[BASE_START] = F(u64::from(
            source
                .source
                .address
                .checked_sub(source.offset)
                .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?,
        ));
        row[BASE_CONTENT_START] = F(u64::from(source.source_node.start));
        row[BASE_CONTENT_END] = row[BASE_START].add(F(u64::from(source.length)));
        row[BASE_DEPTH] = F(u64::from(source.source_node.content_start));
        row[BASE_TAG_NUMBER] = F(u64::from(source.source_node.content_end));
        row[BASE_ROLE] = F(u64::from(source.purpose));
        row[BASE_INSTANCE] = F(u64::from(source.instance));
        row[BASE_OFFSET] = F(u64::from(source.offset));
        row[BASE_ENDPOINT_ROLE] = F(u64::from(source.variant));
        row[BASE_ENDPOINT_INSTANCE] = F(u64::from(matches!(source.purpose, 3..=9)));
        row[BASE_IS_WRITE] = F(u64::from(source.offset == 0));
        row[BASE_STRICT] = F(u64::from(source.offset + 1 == source.length));
        // Original offsets are u16, so the fixed inverse-or-zero chain has
        // the same value as the old checked inverse with its zero special case.
        row[BASE_INVERSE] = F(u64::from(source.offset)).inverse_or_zero_canonical_v1();
        let remaining = source
            .length
            .checked_sub(source.offset)
            .and_then(|remaining| remaining.checked_sub(1))
            .ok_or(ZkX509Rfc5280StarkErrorV1::Semantic)?;
        // Keep the original checked length/offset arithmetic above; every
        // admitted remaining count is also a canonical u16 field value.
        row[BASE_G] = F(u64::from(remaining)).inverse_or_zero_canonical_v1();
        name_policy::populate_fixed_byte(&mut row, &mut previous_name_key)?;
        profile_identity::populate_fixed_byte(&mut row, private_shape.certificate_slot_2_active);
        push_family_row_v1(&mut family_rows[fixed_family], row)?;
    }
    binding::append_temporal_rows_v1(trace, &mut family_rows)?;
    binding::append_relation_rows_v1(trace, &semantic, &mut family_rows)?;
    path_len::append_rows(
        trace,
        &basic_constraints_sources,
        &mut family_rows[ZkX509Rfc5280StarkFamilyV1::BasicConstraints as usize],
    )?;
    let serial_source_family = ZkX509Rfc5280StarkFamilyV1::SerialSource as usize;
    for source in &semantic.serial_sources {
        for row in build_zk_x509_rfc5280_serial_source_rows_v1(source)?
            .iter()
            .copied()
        {
            push_family_row_v1(&mut family_rows[serial_source_family], row)?;
        }
    }
    let serial_family = ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize;
    for comparison in &semantic.serial_comparisons {
        for row in build_zk_x509_rfc5280_serial_comparison_rows_v1(comparison)?
            .iter()
            .copied()
        {
            for _ in 0..SERIAL_COMPARISON_PHASES_V1 {
                push_family_row_v1(&mut family_rows[serial_family], row)?;
            }
        }
    }
    let name_value_family = ZkX509Rfc5280StarkFamilyV1::NameValue as usize;
    name_values::populate_rows(trace, &mut family_rows[name_value_family])?;
    let semantic_source_family = ZkX509Rfc5280StarkFamilyV1::SemanticSource as usize;
    for entry in &schedule.profile_byte_table {
        let multiplicity = semantic
            .fixed_bytes
            .iter()
            .filter(|query| {
                query.purpose == entry.purpose
                    && query.variant == entry.variant
                    && query.source_node.role as u16 == entry.source_role
                    && query.offset == entry.offset
                    && query.length == entry.length
                    && query.expected == entry.expected
            })
            .count()
            + name_values::profile_multiplicity(&family_rows[name_value_family], *entry);
        let mut row = active_zero_row_v1();
        row[BASE_A] = F::ONE;
        row[BASE_VALUE] = F(u64::from(entry.expected));
        write_u8_bits_v1(&mut row, BASE_BYTE_BITS, entry.expected);
        row[BASE_B] = F(u64::from(entry.length));
        row[BASE_D] =
            F(u64::try_from(multiplicity).map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?);
        row[BASE_PARENT] = F(u64::from(entry.source_role));
        row[BASE_CHILD] = F(u64::from(entry.exact_end));
        row[BASE_ROLE] = F(u64::from(entry.purpose));
        row[BASE_OFFSET] = F(u64::from(entry.offset));
        row[BASE_ENDPOINT_ROLE] = F(u64::from(entry.variant));
        row[BASE_ENDPOINT_INSTANCE] = F(u64::from(entry.contents_only));
        push_family_row_v1(&mut family_rows[semantic_source_family], row)?;
    }
    let output_producer_family = ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize;
    let output_consumer_family = ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize;
    let io = rfc5280_io_witnesses_v1(trace, 0)?;
    let roles = output_roles_v1(trace)?;
    if io.len() != roles.len() {
        return Err(ZkX509Rfc5280StarkErrorV1::Output);
    }
    for (role, witness) in roles.into_iter().zip(io) {
        if witness.consumer_values.len() != witness.declaration.consumers.len() {
            return Err(ZkX509Rfc5280StarkErrorV1::Output);
        }
        let key_slot = key_output_slot_v1(schedule.shape, witness.declaration.channel);
        if (role == ZkX509Rfc5280OutputRoleV1::P256PublicKey) != key_slot.is_some() {
            return Err(ZkX509Rfc5280StarkErrorV1::Output);
        }
        for (offset, value) in witness.producer_value.iter().copied().enumerate() {
            let mut row = output_base_row_v1(
                role,
                witness.declaration.channel,
                witness.declaration.producer,
                offset,
                value,
                true,
            )?;
            if let Some(length) = projection_serial::slot(witness.declaration.channel) {
                projection_serial::populate_row(
                    &mut row,
                    &projection_serial_source,
                    length,
                    offset,
                )?;
            } else if let Some((slot, length)) =
                projection_disclosure::slot(schedule.shape, witness.declaration.channel)
            {
                projection_disclosure::populate_row(
                    &mut row,
                    projection_disclosure_sources[slot]
                        .as_ref()
                        .ok_or(ZkX509Rfc5280StarkErrorV1::Source)?,
                    length,
                    offset,
                )?;
            } else if let Some(slot) = key_slot {
                populate_der_output_row_v1(&mut row, trace, key_nodes[slot], offset, false)?;
            } else if let Some(slot) =
                spki_output_slot_v1(schedule.shape, witness.declaration.channel)
            {
                populate_der_output_row_v1(&mut row, trace, spki_nodes[slot], offset, true)?;
            } else if let Some((slot, length)) =
                variable_output::slot(schedule.shape, witness.declaration.channel)
            {
                variable_output::populate_row(
                    &mut row,
                    trace,
                    variable_nodes[slot],
                    slot,
                    length,
                    offset,
                )?;
            }
            push_family_row_v1(&mut family_rows[output_producer_family], row)?;
        }
        for (endpoint, values) in witness
            .declaration
            .consumers
            .iter()
            .copied()
            .zip(&witness.consumer_values)
        {
            for (offset, value) in values.iter().copied().enumerate() {
                let row = output_base_row_v1(
                    role,
                    witness.declaration.channel,
                    endpoint,
                    offset,
                    value,
                    false,
                )?;
                push_family_row_v1(&mut family_rows[output_consumer_family], row)?;
            }
        }
    }
    let private_counts = private_shape.family_counts()?;
    for family in 0..FAMILY_COUNT_V1 {
        let active = family_rows[family]
            .iter()
            .filter(|row| row[BASE_ACTIVE] == F::ONE)
            .count();
        if family != ZkX509Rfc5280StarkFamilyV1::Padding as usize
            && active != private_counts[family]
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        if family_rows[family].len() > schedule.counts[family] {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
    }
    // These construction-only owners must release before old and compact
    // family allocations overlap. The schedule remains in the final material
    // and is charged alongside that overlap; the input trace is borrowed.
    drop((
        semantic,
        serial_byte_multiplicities,
        serial_node_multiplicities,
        semantic_multiplicities,
        byte_lookup_cells,
        ordinal_entries,
    ));
    let schedule_payload = super::allocation_payload::sum_v1([
        super::allocation_payload::vector_v1(&schedule.profile_byte_table),
        super::allocation_payload::vector_v1(&schedule.output_topology),
    ]);
    let family_rows = source_rows::compact_families_v1(family_rows, schedule_payload)?;
    Ok(ZkX509Rfc5280StarkBaseMaterialV1 {
        private_shape,
        schedule,
        family_rows,
    })
}
fn populate_degree_normalization_helpers_v1<A: PolynomialAirFieldV1>(
    row: &mut ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) {
    let family = |candidate: ZkX509Rfc5280StarkFamilyV1| fixed[candidate as usize];
    let active = row[BASE_ACTIVE];
    let source_node = family(ZkX509Rfc5280StarkFamilyV1::SourceNode);
    let root = fixed[FIX_EXPECTED + 2];
    row[BASE_GRAMMAR_ORDINAL] = source_node.mul(
        root.mul(row[BASE_DOCUMENT])
            .add(A::ONE.sub(root).mul(row[BASE_CHILD])),
    );
    row[BASE_EXPECTED_ROOT_KIND] = source_node.mul(active).mul(
        fixed[FIX_EXPECTED + 3]
            .add(
                fixed[FIX_EXPECTED + 4].mul(
                    row[BASE_CERT2_ACTIVE]
                        .add(A::ONE.sub(row[BASE_CERT2_ACTIVE]).mul(A::from_base(F(2)))),
                ),
            )
            .add(
                fixed[FIX_EXPECTED + 5].mul(
                    row[BASE_CERT2_ACTIVE]
                        .mul(A::from_base(F(2)))
                        .add(A::ONE.sub(row[BASE_CERT2_ACTIVE]).mul(A::from_base(F(3)))),
                ),
            )
            .add(fixed[FIX_EXPECTED + 6].mul(A::from_base(F(3)))),
    );
    let profile = fixed[FIX_PROFILE_TABLE].mul(active);
    let topology = source_node.mul(active).mul(row[BASE_INVERSE]);
    row[BASE_PROFILE_TABLE_ACTIVE] = profile.add(topology);
    row[BASE_PROFILE_TABLE_MULTIPLICITY] = profile.mul(row[BASE_D]).add(topology);
    row[BASE_PROFILE_TOPOLOGY_QUERY_ACTIVE] = family(ZkX509Rfc5280StarkFamilyV1::FixedByte)
        .add(family(ZkX509Rfc5280StarkFamilyV1::NameValue))
        .mul(active)
        .mul(row[BASE_IS_WRITE]);
    let serial_query = family(ZkX509Rfc5280StarkFamilyV1::SerialSource)
        .mul(active)
        .mul(row[BASE_IS_WRITE]);
    let direct_query = family(ZkX509Rfc5280StarkFamilyV1::FixedByte)
        .add(family(ZkX509Rfc5280StarkFamilyV1::NameValue))
        .mul(active);
    let key_query = output_source_query_gate_v1(row, fixed);
    let basic_constraints_query = path_len::byte_query_gate(row, fixed);
    row[BASE_SERIAL_BYTE_QUERY_ACTIVE] = key_query
        .add(basic_constraints_query)
        .add(serial_query)
        .add(direct_query)
        .add(
            family(ZkX509Rfc5280StarkFamilyV1::Decimal)
                .mul(active)
                .mul(row[BASE_EQUAL]),
        );
    row[BASE_SERIAL_BYTE_QUERY_VALUE] = key_query
        .add(basic_constraints_query)
        .mul(row[BASE_VALUE])
        .add(fixed[projection_disclosure::FIX_OID_VALUE])
        .sub(fixed[projection_disclosure::FIX_OID_QUERY].mul(row[BASE_VALUE]))
        .add(serial_query.mul(row[SERIAL_SOURCE_QUERY_VALUE]))
        .add(
            family(ZkX509Rfc5280StarkFamilyV1::FixedByte)
                .add(family(ZkX509Rfc5280StarkFamilyV1::NameValue))
                .add(family(ZkX509Rfc5280StarkFamilyV1::Decimal))
                .mul(active)
                .mul(row[BASE_VALUE]),
        );
    let serial_source = family(ZkX509Rfc5280StarkFamilyV1::SerialSource).mul(active);
    let decimal_source = family(ZkX509Rfc5280StarkFamilyV1::Decimal)
        .mul(active)
        .mul(row[BASE_STRICT]);
    let relation_source = fixed[FIX_NUMERIC_RIGHT].mul(active);
    let serial_left = fixed[FIX_SERIAL_COMPARE_PHASE_LEFT].mul(active);
    let serial_right = fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT].mul(active);
    let calendar_phases = fixed
        [FIX_CALENDAR_PHASES + 1..FIX_CALENDAR_PHASES + CALENDAR_COPY_PHASES_V1]
        .iter()
        .copied()
        .fold(A::ZERO, A::add);
    let calendar_consumer = calendar_phases.mul(active);
    let range_consumer = fixed[FIX_RANGE_TERMINAL].mul(active);
    let name_oid_source = family(ZkX509Rfc5280StarkFamilyV1::FixedByte).mul(row[BASE_E]);
    let name_value_consumer = family(ZkX509Rfc5280StarkFamilyV1::NameValue)
        .mul(active)
        .mul(row[BASE_IS_WRITE]);
    let name_copy = name_oid_source.add(name_value_consumer);
    row[BASE_COPY_SOURCE_ACTIVE] = serial_source
        .add(decimal_source)
        .add(relation_source)
        .add(name_oid_source);
    row[BASE_COPY_CONSUMER_ACTIVE] = serial_left
        .add(serial_right)
        .add(calendar_consumer)
        .add(range_consumer)
        .add(name_value_consumer);
    row[BASE_COPY_DOMAIN] = serial_source
        .add(serial_left)
        .add(serial_right)
        .mul(A::from_base(F(90)))
        .add(
            decimal_source
                .add(calendar_consumer)
                .mul(A::from_base(F(98))),
        )
        .add(relation_source.add(range_consumer).mul(A::from_base(F(99))))
        .add(name_copy.mul_base(F(name_values::COPY_DOMAIN)));
    row[BASE_COPY_KEY_1] = serial_source
        .mul(row[SERIAL_SOURCE_LOGICAL_ID])
        .add(decimal_source.mul(row[BASE_INSTANCE]))
        .add(relation_source.mul(row[BASE_ROLE]))
        .add(serial_left.mul(row[BASE_ROLE]))
        .add(serial_right.mul(row[BASE_INSTANCE]))
        .add(calendar_consumer.mul(row[BASE_INSTANCE]))
        .add(range_consumer.mul(row[BASE_ROLE]))
        .add(name_copy.mul(row[BASE_DOCUMENT]));
    row[BASE_COPY_KEY_2] = serial_source
        .mul(row[BASE_OFFSET])
        .add(decimal_source.mul(row[BASE_ROLE]))
        .add(relation_source.mul(row[BASE_INSTANCE]))
        .add(serial_left.add(serial_right).mul(row[BASE_OFFSET]))
        .add(
            fixed[FIX_CALENDAR_PHASES + 1..FIX_CALENDAR_PHASES + CALENDAR_COPY_PHASES_V1]
                .iter()
                .copied()
                .enumerate()
                .fold(A::ZERO, |sum, (component, selector)| {
                    sum.add(selector.mul(active).mul(A::from_base(F(
                        u64::try_from(component).expect("six calendar components fit u64"),
                    ))))
                }),
        )
        .add(range_consumer.mul(row[BASE_INSTANCE]))
        .add(name_copy.mul(row[BASE_H]));
    row[BASE_COPY_VALUE] = serial_source
        .mul(row[BASE_VALUE])
        .add(decimal_source.mul(row[BASE_STATE_AFTER]))
        .add(relation_source.mul(row[BASE_C]))
        .add(serial_left.mul(row[BASE_A]))
        .add(serial_right.mul(row[BASE_B]))
        .add(
            fixed[FIX_CALENDAR_PHASES + 1..FIX_CALENDAR_PHASES + CALENDAR_COPY_PHASES_V1]
                .iter()
                .copied()
                .zip([
                    row[CALENDAR_COLUMNS + calendar::RAW_YEAR],
                    row[BASE_B],
                    row[BASE_C],
                    row[BASE_D],
                    row[BASE_E],
                    row[BASE_F],
                ])
                .fold(A::ZERO, |sum, (selector, value)| {
                    sum.add(selector.mul(active).mul(value))
                }),
        )
        .add(range_consumer.mul(row[BASE_STATE_AFTER]))
        .add(name_oid_source.mul(row[BASE_ENDPOINT_ROLE]))
        .add(name_value_consumer.mul(row[BASE_G]));
    binding::normalize_v1(row, fixed);
    copy_census::normalize(row, fixed);
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509Rfc5280StarkBaseMaterialV1 {
    pub(crate) fn base_row(
        &self,
        row: usize,
    ) -> Result<ZkX509Rfc5280StarkBaseRowV1, ZkX509Rfc5280StarkErrorV1> {
        let (family, ordinal) = self.schedule.family_and_ordinal(row)?;
        let mut value = self.family_rows[family as usize]
            .get(ordinal)
            .unwrap_or([F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]);
        value[BASE_CERT2_ACTIVE] = self.private_shape.certificate_slot_2_active;
        value[BASE_ENTRY_COUNT] = F(u64::from(self.private_shape.crl_entries));
        let entry_start = self.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Relation as usize]
            + 9 * numeric::RELATION_PHASES_V1;
        let before_entries = row.saturating_sub(entry_start) / numeric::RELATION_PHASES_V1;
        value[BASE_ENTRY_CENSUS] =
            F(before_entries.min(usize::from(self.private_shape.crl_entries)) as u64);
        let fixed = self.schedule.fixed_row(row)?;
        populate_degree_normalization_helpers_v1(&mut value, &fixed);
        Ok(value)
    }
    pub(crate) fn fixed_row(
        &self,
        row: usize,
    ) -> Result<ZkX509Rfc5280StarkFixedRowV1, ZkX509Rfc5280StarkErrorV1> {
        self.schedule.fixed_row(row)
    }
    /// Fill caller-owned native columns, reconstructing each exact row once.
    /// The caller owns the column allocation/clearing charge; this method only
    /// uses one transient row, which is cleared after its selected cells copy.
    /// All destination geometry is checked before any output is written.
    pub(crate) fn fill_base_columns_v1(
        &self,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        let end = first
            .checked_add(outputs.len())
            .filter(|&end| end <= ZK_X509_RFC5280_STARK_BASE_WIDTH_V1)
            .ok_or(ZkX509Rfc5280StarkErrorV1::Shape)?;
        if outputs.is_empty()
            || outputs
                .iter()
                .any(|column| column.len() != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
        {
            return Err(ZkX509Rfc5280StarkErrorV1::Shape);
        }
        for index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let mut row = self.base_row(index)?;
            for (column, output) in (first..end).zip(outputs.iter_mut()) {
                output[index] = row[column];
            }
            zeroize_fields_v1(&mut row);
        }
        Ok(())
    }
    pub(crate) fn build_base_column(
        &self,
        column: usize,
    ) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
        build_zk_x509_rfc5280_stark_column_v1(
            ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
            column,
            |row, column| Ok(self.base_row(row)?[column]),
        )
    }
    pub(crate) fn build_fixed_column(
        &self,
        column: usize,
    ) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
        build_zk_x509_rfc5280_stark_column_v1(
            ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1,
            column,
            |row, column| Ok(self.fixed_row(row)?[column]),
        )
    }
}
#[cfg(test)]
fn row_family_gate_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
    row: usize,
    family: ZkX509Rfc5280StarkFamilyV1,
) -> Result<F, ZkX509Rfc5280StarkErrorV1> {
    let (actual, _) = material.schedule.family_and_ordinal(row)?;
    Ok(F(u64::from(
        actual == family && material.base_row(row)?[BASE_ACTIVE] == F::ONE,
    )))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn product_relation_factor_v1(
    relation: usize,
    row: &ZkX509Rfc5280StarkBaseRowV1,
    lane: usize,
    der_challenges: ZkX509DerStarkChallengesV1,
) -> Result<F, ZkX509Rfc5280StarkErrorV1> {
    match relation {
        0 => Ok(zk_x509_der_stark_input_byte_factor_v1(
            row[BASE_DOCUMENT],
            row[BASE_ADDRESS],
            row[BASE_VALUE],
            lane,
            der_challenges,
        )?),
        1 => Ok(zk_x509_der_stark_node_factor_v1(
            ZkX509DerStarkNodeEventV1 {
                document: row[BASE_DOCUMENT],
                ordinal: row[BASE_NODE],
                parent_frame: row[BASE_PARENT],
                tag_class: row[BASE_TAG_CLASS],
                tag_number: row[BASE_TAG_NUMBER],
                constructed: row[BASE_CONSTRUCTED],
                start: row[BASE_START],
                content_start: row[BASE_CONTENT_START],
                content_end: row[BASE_CONTENT_END],
                depth: row[BASE_DEPTH],
                content_len: row[BASE_A],
            },
            lane,
            der_challenges,
        )?),
        _ => Err(ZkX509Rfc5280StarkErrorV1::Shape),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn product_relation_family_v1(
    relation: usize,
) -> Result<ZkX509Rfc5280StarkFamilyV1, ZkX509Rfc5280StarkErrorV1> {
    match relation {
        0 => Ok(ZkX509Rfc5280StarkFamilyV1::SourceByte),
        1 => Ok(ZkX509Rfc5280StarkFamilyV1::SourceNode),
        _ => Err(ZkX509Rfc5280StarkErrorV1::Shape),
    }
}
// Original private source-admissibility preflight, independent of the public
// claim inventory. Fixed selectors are reconstructed from the same material's
// actual canonical schedule; no supplied selector or role grants proof authority.
#[cfg(test)]
fn selected_output_role_preflight_v1(
    row: &ZkX509Rfc5280StarkBaseRowV1,
    fixed: &ZkX509Rfc5280StarkFixedRowV1,
    consumer: bool,
) -> Result<usize, ZkX509Rfc5280StarkErrorV1> {
    let mut selected_role = None;
    for role_index in 0..OUTPUT_ROLE_COUNT_V1 {
        let selector = fixed[output_role_fixed_selector_column_v1(role_index, consumer)];
        if selector == F::ONE && selected_role.is_none() {
            selected_role = Some(role_index);
        } else if selector != F::ZERO {
            return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
        }
    }
    let role_index = selected_role.ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
    if row[BASE_ROLE]
        != F(output_role_from_index_v1(role_index)
            .ok_or(ZkX509Rfc5280StarkErrorV1::TerminalClaim)? as u64)
    {
        return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
    }
    Ok(role_index)
}
/// Compile only the governed-root consumer products; all other products stay private.
#[cfg(test)]
pub(crate) fn compile_zk_x509_rfc5280_stark_terminal_claims_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<ZkX509Rfc5280StarkTerminalClaimsV1, ZkX509Rfc5280StarkErrorV1> {
    der_challenges.validate()?;
    challenges.validate()?;
    let mut claims = ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1();
    let governed_role = output_role_index_v1(ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor);
    for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
        let row = material.base_row(row_index)?;
        let fixed = material.fixed_row(row_index)?;
        let (family, _) = material.schedule.family_and_ordinal(row_index)?;
        if row[BASE_ACTIVE] != F::ONE {
            continue;
        }
        if matches!(
            family,
            ZkX509Rfc5280StarkFamilyV1::OutputProducer | ZkX509Rfc5280StarkFamilyV1::OutputConsumer
        ) {
            let consumer = family == ZkX509Rfc5280StarkFamilyV1::OutputConsumer;
            let role_index = selected_output_role_preflight_v1(&row, &fixed, consumer)?;
            if consumer && role_index == governed_role {
                for lane in 0..4 {
                    claims.output_roles[0].consumer_products[lane] = claims.output_roles[0]
                        .consumer_products[lane]
                        .mul(output_row_factor_v1(&row, lane, challenges));
                }
            }
        }
    }
    claims.validate_v1()?;
    Ok(claims)
}
/// Exact RFC auxiliary columns linked privately to the strict-DER final row.
pub(crate) const fn zk_x509_rfc_der_terminal_columns_v1() -> [usize; 8] {
    [
        AUX_DER_BYTE_AFTER,
        AUX_DER_BYTE_AFTER + 1,
        AUX_DER_BYTE_AFTER + 2,
        AUX_DER_BYTE_AFTER + 3,
        AUX_DER_NODE_AFTER,
        AUX_DER_NODE_AFTER + 1,
        AUX_DER_NODE_AFTER + 2,
        AUX_DER_NODE_AFTER + 3,
    ]
}
/// Prove each role's normalized producer equals its consumer at the private
/// final auxiliary row, then bind the five consumers needed by other adapters.
/// No endpoint ratio or inverse is used: zero factors retain normal semantics.
pub(crate) fn evaluate_zk_x509_rfc5280_terminal_claim_residues_v1<A: PolynomialAirFieldV1>(
    last_aggregate: A,
    aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    claims: ZkX509Rfc5280StarkTerminalClaimsV1,
) -> Result<[A; RFC5280_TERMINAL_RESIDUES_V1], ZkX509Rfc5280StarkErrorV1> {
    claims.validate_v1()?;
    Ok(core::array::from_fn(|index| {
        let lane = index % ZK_X509_RFC5280_STARK_BUS_LANES_V1;
        if index < RFC5280_PRIVATE_OUTPUT_EQUALITIES_V1 {
            let role = index / ZK_X509_RFC5280_STARK_BUS_LANES_V1;
            last_aggregate.mul(
                aux[output_role_aux_column_v1(role, false, lane)]
                    .sub(aux[output_role_aux_column_v1(role, true, lane)]),
            )
        } else {
            let claim = index - RFC5280_PRIVATE_OUTPUT_EQUALITIES_V1;
            let role = output_role_index_v1(
                PUBLIC_OUTPUT_ROLES_V1[claim / ZK_X509_RFC5280_STARK_BUS_LANES_V1],
            );
            last_aggregate.mul(
                aux[output_role_aux_column_v1(role, true, lane)].sub(A::from_base(
                    claims
                        .claim_value_v1(claim)
                        .expect("bounded public consumer"),
                )),
            )
        }
    }))
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zero_safe_inverse_v1(gate: F, denominator: F) -> (F, F) {
    // Admitted factors are canonical tuple compressions. Preserve the prior
    // active malformed-input panic and inactive malformed-input tolerance.
    let active = u64::from(gate != F::ZERO);
    let zero = F(active & u64::from(denominator == F::ZERO));
    // Mask before validation: the canonicality check has the same successful
    // outcome for all admitted inputs, including inactive malformed words.
    // Checking a gate OR canonicality expression first can compile to a private
    // gate branch even when the source uses non-short-circuit Boolean operators.
    let selected = F(denominator.0 & 0_u64.wrapping_sub(active));
    assert!(
        selected.0 < crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1,
        "nonzero canonical Goldilocks value is invertible"
    );
    (zero, selected.inverse_or_zero_canonical_v1())
}

#[cfg(test)]
#[path = "rfc5280_zero_safe_inverse_tests.rs"]
mod zero_safe_inverse_tests;

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn product_aux_column_descriptor_v1(column: usize) -> Option<(usize, usize, bool)> {
    let starts = [
        (0, AUX_DER_BYTE_BEFORE, AUX_DER_BYTE_AFTER),
        (1, AUX_DER_NODE_BEFORE, AUX_DER_NODE_AFTER),
    ];
    for (relation, before, after) in starts {
        if (before..before + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((relation, column - before, false));
        }
        if (after..after + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((relation, column - after, true));
        }
    }
    None
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn output_role_aux_column_descriptor_v1(column: usize) -> Option<(usize, bool, usize)> {
    let local = column.checked_sub(AUX_OUTPUT_ROLE_PRODUCTS)?;
    if local >= OUTPUT_ROLE_COUNT_V1 * OUTPUT_ENDPOINT_COUNT_V1 * ZK_X509_RFC5280_STARK_BUS_LANES_V1
    {
        return None;
    }
    let role_index = local / (OUTPUT_ENDPOINT_COUNT_V1 * ZK_X509_RFC5280_STARK_BUS_LANES_V1);
    let endpoint_lane = local % (OUTPUT_ENDPOINT_COUNT_V1 * ZK_X509_RFC5280_STARK_BUS_LANES_V1);
    let consumer =
        endpoint_lane / ZK_X509_RFC5280_STARK_BUS_LANES_V1 == output_endpoint_index_v1(true);
    let lane = endpoint_lane % ZK_X509_RFC5280_STARK_BUS_LANES_V1;
    Some((role_index, consumer, lane))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn serial_product_aux_column_descriptor_v1(column: usize) -> Option<(bool, usize, bool)> {
    for (consumer, before, after) in [
        (false, AUX_SERIAL_SOURCE_BEFORE, AUX_SERIAL_SOURCE_AFTER),
        (true, AUX_SERIAL_CONSUMER_BEFORE, AUX_SERIAL_CONSUMER_AFTER),
    ] {
        if (before..before + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((consumer, column - before, false));
        }
        if (after..after + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((consumer, column - after, true));
        }
    }
    None
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn grammar_ordinal_product_aux_column_descriptor_v1(column: usize) -> Option<(bool, usize, bool)> {
    for (table, before, after) in [
        (
            false,
            AUX_GRAMMAR_ORDINAL_SOURCE_BEFORE,
            AUX_GRAMMAR_ORDINAL_SOURCE_AFTER,
        ),
        (
            true,
            AUX_GRAMMAR_ORDINAL_TABLE_BEFORE,
            AUX_GRAMMAR_ORDINAL_TABLE_AFTER,
        ),
    ] {
        if (before..before + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((table, column - before, false));
        }
        if (after..after + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((table, column - after, true));
        }
    }
    None
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy)]
struct LookupAuxDescriptorV1 {
    node: bool,
    lane: usize,
    kind: u8,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn lookup_aux_column_descriptor_v1(column: usize) -> Option<LookupAuxDescriptorV1> {
    for (node, starts) in [
        (
            false,
            [
                AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR,
                AUX_SERIAL_BYTE_TABLE_INVERSE,
                AUX_SERIAL_BYTE_QUERY_INVERSE,
                AUX_SERIAL_BYTE_ZERO_ACCUMULATOR,
                AUX_SERIAL_BYTE_TABLE_ZERO,
                AUX_SERIAL_BYTE_QUERY_ZERO,
            ],
        ),
        (
            true,
            [
                AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR,
                AUX_SERIAL_NODE_TABLE_INVERSE,
                AUX_SERIAL_NODE_QUERY_INVERSE,
                AUX_SERIAL_NODE_ZERO_ACCUMULATOR,
                AUX_SERIAL_NODE_TABLE_ZERO,
                AUX_SERIAL_NODE_QUERY_ZERO,
            ],
        ),
    ] {
        for (kind, start) in starts.into_iter().enumerate() {
            if (start..start + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
                return Some(LookupAuxDescriptorV1 {
                    node,
                    lane: column - start,
                    kind: u8::try_from(kind).expect("six lookup column kinds"),
                });
            }
        }
    }
    None
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn profile_lookup_aux_column_descriptor_v1(column: usize) -> Option<(usize, usize)> {
    for (kind, start) in [
        AUX_PROFILE_LOOKUP_ACCUMULATOR,
        AUX_PROFILE_TABLE_INVERSE,
        AUX_PROFILE_QUERY_INVERSE,
        AUX_PROFILE_ZERO_ACCUMULATOR,
        AUX_PROFILE_TABLE_ZERO,
        AUX_PROFILE_QUERY_ZERO,
        AUX_PROFILE_TOPOLOGY_QUERY_INVERSE,
        AUX_PROFILE_TOPOLOGY_QUERY_ZERO,
    ]
    .into_iter()
    .enumerate()
    {
        if (start..start + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
            return Some((kind, column - start));
        }
    }
    None
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy)]
struct GrammarLookupAuxDescriptorV1 {
    parent: bool,
    lane: usize,
    kind: u8,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn grammar_lookup_aux_column_descriptor_v1(column: usize) -> Option<GrammarLookupAuxDescriptorV1> {
    for (parent, starts) in [
        (
            false,
            [
                AUX_GRAMMAR_RULE_LOOKUP_ACCUMULATOR,
                AUX_GRAMMAR_RULE_TABLE_INVERSE,
                AUX_GRAMMAR_RULE_QUERY_INVERSE,
                AUX_GRAMMAR_RULE_ZERO_ACCUMULATOR,
                AUX_GRAMMAR_RULE_TABLE_ZERO,
                AUX_GRAMMAR_RULE_QUERY_ZERO,
            ],
        ),
        (
            true,
            [
                AUX_GRAMMAR_PARENT_LOOKUP_ACCUMULATOR,
                AUX_GRAMMAR_PARENT_TABLE_INVERSE,
                AUX_GRAMMAR_PARENT_QUERY_INVERSE,
                AUX_GRAMMAR_PARENT_ZERO_ACCUMULATOR,
                AUX_GRAMMAR_PARENT_TABLE_ZERO,
                AUX_GRAMMAR_PARENT_QUERY_ZERO,
            ],
        ),
    ] {
        for (kind, start) in starts.into_iter().enumerate() {
            if (start..start + ZK_X509_RFC5280_STARK_BUS_LANES_V1).contains(&column) {
                return Some(GrammarLookupAuxDescriptorV1 {
                    parent,
                    lane: column - start,
                    kind: u8::try_from(kind).expect("six grammar lookup column kinds"),
                });
            }
        }
    }
    None
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "rfc5280_aux_replay.rs"]
mod aux_replay;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "rfc5280_numeric_replay.rs"]
mod numeric_replay;

/// Named scratch for the bounded RFC auxiliary batch; destinations are caller-owned.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) const fn zk_x509_rfc_aux_replay_scratch_bytes_v1() -> usize {
    aux_replay::scratch_payload_bytes_v1()
}

/// Replay one challenge-dependent auxiliary column with bounded memory.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn build_zk_x509_rfc5280_stark_aux_column_v1(
    material: &ZkX509Rfc5280StarkBaseMaterialV1,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
    column: usize,
    sha_union: &ZkX509ShaUnionCentersV1,
) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
    der_challenges.validate()?;
    challenges.validate()?;
    sha_union.validate_v1()?;
    if column >= ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Shape);
    }
    let mut values = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
    values
        .try_reserve_exact(ZK_X509_RFC5280_STARK_TRACE_SIZE_V1)
        .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
    if values.capacity() != ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
        return Err(ZkX509Rfc5280StarkErrorV1::Resource);
    }
    values.resize(ZK_X509_RFC5280_STARK_TRACE_SIZE_V1, F::ZERO);
    aux_replay::fill_columns_v1(
        material,
        der_challenges,
        challenges,
        column,
        &mut [&mut values],
        sha_union,
    )?;
    Ok(values.into_vec())
}
/// Private native SHA centers. Only the actual four bound SHA sources can
/// construct a production owner; no wire codec, Copy or raw-array factory exists.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) struct ZkX509ShaUnionCentersV1 {
    products: [[F; 4]; 4],
    present: u8,
    binding: Option<ZkX509CredentialPreAuxBindingV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkX509ShaUnionCentersV1 {
    fn empty_v1() -> Self {
        Self {
            products: [[F::ZERO; 4]; 4],
            present: 0,
            binding: None,
        }
    }
    fn install_segment_v1(
        &mut self,
        segment: usize,
        streams: &[[F; 4]; 4],
    ) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        if segment >= 4
            || self.present & (1 << segment) != 0
            || streams
                .iter()
                .flatten()
                .any(|x| F::canonical(x.0).is_none())
        {
            return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
        }
        for lane in 0..4 {
            self.products[segment][lane] = streams.iter().fold(F::ONE, |p, s| p.mul(s[lane]));
        }
        self.present |= 1 << segment;
        Ok(())
    }
    fn validate_v1(&self) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        if self.present != 15
            || self
                .products
                .iter()
                .flatten()
                .any(|x| F::canonical(x.0).is_none())
        {
            return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
        }
        Ok(())
    }
    fn products_v1(&self) -> &[[F; 4]; 4] {
        &self.products
    }
    /// Replay genuine original SHA sources under the exact shared capability.
    /// Segment and compact-CA coverage/order are checked before returning an owner.
    pub(crate) fn from_bound_sources_v1(
        sources: &[ZkX509ShaBatchSegmentAuxSourceV1<'_>; 4],
        binding: ZkX509CredentialPreAuxBindingV1,
    ) -> Result<(Self, [ZkX509ShaCallBoundaryTerminalV1; 13]), ZkX509Rfc5280StarkErrorV1> {
        let mut owner = Self::empty_v1();
        let mut boundaries = zeroize::Zeroizing::new(Vec::new());
        boundaries
            .try_reserve_exact(13)
            .map_err(|_| ZkX509Rfc5280StarkErrorV1::Resource)?;
        for (index, source) in sources.iter().enumerate() {
            let terminal = source
                .rfc_union_air_terminals_v1(binding, index)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
            if usize::from(terminal.segment.segment) != index {
                return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
            }
            owner.install_segment_v1(index, &terminal.segment.rfc_stream_products)?;
            boundaries.extend_from_slice(&terminal.ca_call_boundaries);
        }
        // Keep the fixed-size copy under the same clearing discipline while
        // identity validation can still return early or unwind.
        let calls = zeroize::Zeroizing::new(
            <[ZkX509ShaCallBoundaryTerminalV1; 13]>::try_from(boundaries.as_slice())
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?,
        );
        for (index, terminal) in calls.iter().enumerate() {
            terminal
                .validate_identity_v1(index)
                .map_err(|_| ZkX509Rfc5280StarkErrorV1::TerminalClaim)?;
        }
        owner.validate_v1()?;
        owner.binding = Some(binding);
        Ok((owner, *calls))
    }
    #[cfg(test)]
    fn identity_fixture_v1() -> Self {
        Self {
            products: [[F::ONE; 4]; 4],
            present: 15,
            binding: None,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509ShaUnionCentersV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ZkX509ShaUnionCentersV1 { <private products redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZkX509ShaUnionCentersV1 {
    fn drop(&mut self) {
        zeroize_field_rows_v1(&mut self.products);
        self.present = 0;
    }
}
/// Sole production column provider for the RFC 5280 registration.
///
/// Challenge-independent base/fixed rows and challenge-dependent auxiliary
/// products are replayed from the same canonical material. Terminal claims
/// remain in the original masked polynomials and their private join relations.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) struct ZkX509Rfc5280StarkColumnProviderV1<'a> {
    material: &'a ZkX509Rfc5280StarkBaseMaterialV1,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
    sha_union: ZkX509ShaUnionCentersV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkX509Rfc5280StarkColumnProviderV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509Rfc5280StarkColumnProviderV1 { <private material redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> ZkX509Rfc5280StarkColumnProviderV1<'a> {
    /// Consume the private union owner from the same original X5B1 phase.
    pub(crate) fn new_v1(
        material: &'a ZkX509Rfc5280StarkBaseMaterialV1,
        binding: ZkX509CredentialPreAuxBindingV1,
        sha_union: ZkX509ShaUnionCentersV1,
    ) -> Result<Self, ZkX509Rfc5280StarkErrorV1> {
        if sha_union.binding != Some(binding) {
            return Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim);
        }
        Self::with_centers_v1(
            material,
            binding.main_post_base().der(),
            binding.rfc5280(),
            sha_union,
        )
    }
    fn with_centers_v1(
        material: &'a ZkX509Rfc5280StarkBaseMaterialV1,
        der_challenges: ZkX509DerStarkChallengesV1,
        challenges: ZkX509Rfc5280StarkChallengesV1,
        sha_union: ZkX509ShaUnionCentersV1,
    ) -> Result<Self, ZkX509Rfc5280StarkErrorV1> {
        der_challenges.validate()?;
        challenges.validate()?;
        sha_union.validate_v1()?;
        Ok(Self {
            material,
            der_challenges,
            challenges,
            sha_union,
        })
    }
    #[cfg(test)]
    /// Local test fixture for RFC recurrences; grants no production union owner.
    pub(crate) fn fixture_v1(
        material: &'a ZkX509Rfc5280StarkBaseMaterialV1,
        der_challenges: ZkX509DerStarkChallengesV1,
        challenges: ZkX509Rfc5280StarkChallengesV1,
    ) -> Result<Self, ZkX509Rfc5280StarkErrorV1> {
        Self::with_centers_v1(
            material,
            der_challenges,
            challenges,
            ZkX509ShaUnionCentersV1::identity_fixture_v1(),
        )
    }
    /// Borrow the same owned, binding-checked centers for the parent MAIN proof builder.
    pub(super) fn sha_union_centers_v1(&self) -> &[[F; 4]; 4] {
        self.sha_union.products_v1()
    }
    #[cfg(test)]
    pub(crate) fn base_row_v1(
        &self,
        row: usize,
    ) -> Result<ZkX509Rfc5280StarkBaseRowV1, ZkX509Rfc5280StarkErrorV1> {
        self.material.base_row(row)
    }
    #[cfg(test)]
    pub(crate) fn fixed_row_v1(
        &self,
        row: usize,
    ) -> Result<ZkX509Rfc5280StarkFixedRowV1, ZkX509Rfc5280StarkErrorV1> {
        self.material.fixed_row(row)
    }
    /// Replay caller-owned base columns without changing the bound phase.
    pub(crate) fn fill_base_columns_v1(
        &self,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        self.material.fill_base_columns_v1(first, outputs)
    }
    pub(crate) fn build_base_column_v1(
        &self,
        column: usize,
    ) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
        self.material.build_base_column(column)
    }
    pub(crate) fn build_fixed_column_v1(
        &self,
        column: usize,
    ) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
        self.material.build_fixed_column(column)
    }
    /// Fill the existing bounded native replay batch with one row reconstruction per index.
    pub(crate) fn fill_aux_columns_v1(
        &self,
        first: usize,
        outputs: &mut [&mut [F]],
    ) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
        aux_replay::fill_columns_v1(
            self.material,
            self.der_challenges,
            self.challenges,
            first,
            outputs,
            &self.sha_union,
        )
    }
    pub(crate) fn build_aux_column_v1(
        &self,
        column: usize,
    ) -> Result<Vec<F>, ZkX509Rfc5280StarkErrorV1> {
        build_zk_x509_rfc5280_stark_aux_column_v1(
            self.material,
            self.der_challenges,
            self.challenges,
            column,
            &self.sha_union,
        )
    }
    #[cfg(test)]
    pub(crate) fn terminal_claims_v1(
        &self,
    ) -> Result<ZkX509Rfc5280StarkTerminalClaimsV1, ZkX509Rfc5280StarkErrorV1> {
        compile_zk_x509_rfc5280_stark_terminal_claims_v1(
            self.material,
            self.der_challenges,
            self.challenges,
        )
    }
}
/// Evaluate the complete opened RFC row as an algebraic test oracle.
///
/// Fixed family selectors are verifier-preprocessed. Every family contributes the same residue
/// inventory on every row, so neither witness values nor roles can alter the composition shape.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn evaluate_zk_x509_rfc5280_stark_residues_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    next: &ZkX509Rfc5280StarkBaseRowV1<A>,
    current_aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    next_aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
    terminal_claims: ZkX509Rfc5280StarkTerminalClaimsV1,
) -> Result<Vec<A>, ZkX509Rfc5280StarkErrorV1> {
    evaluate_rfc5280_relation_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        der_challenges,
        challenges,
        Some(terminal_claims),
    )
}

/// Complete local RFC relation, retaining all36 private output equalities.
/// Only the four governed-root consumers require the joint original CA links.
pub(crate) fn evaluate_zk_x509_rfc5280_local_residues_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    next: &ZkX509Rfc5280StarkBaseRowV1<A>,
    current_aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    next_aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
) -> Result<Vec<A>, ZkX509Rfc5280StarkErrorV1> {
    evaluate_rfc5280_relation_v1(
        current,
        next,
        current_aux,
        next_aux,
        fixed,
        der_challenges,
        challenges,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_rfc5280_relation_v1<A: PolynomialAirFieldV1>(
    current: &ZkX509Rfc5280StarkBaseRowV1<A>,
    next: &ZkX509Rfc5280StarkBaseRowV1<A>,
    current_aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    next_aux: &ZkX509Rfc5280StarkAuxRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
    der_challenges: ZkX509DerStarkChallengesV1,
    challenges: ZkX509Rfc5280StarkChallengesV1,
    terminal_claims: Option<ZkX509Rfc5280StarkTerminalClaimsV1>,
) -> Result<Vec<A>, ZkX509Rfc5280StarkErrorV1> {
    der_challenges.validate()?;
    challenges.validate()?;
    if let Some(claims) = terminal_claims {
        claims.validate_v1()?;
    }
    if current
        .iter()
        .chain(next)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    let expected_count = if terminal_claims.is_some() {
        ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1
    } else {
        ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1
    };
    let mut residues = Vec::with_capacity(expected_count);
    let mut residue_section_start = 0;
    for bit in &current[BASE_BYTE_BITS..BASE_BYTE_BITS + 8] {
        push_boolean_v1(&mut residues, A::ONE, *bit);
    }
    residues
        .push(current[BASE_VALUE].sub(pack_bits_v1(&current[BASE_BYTE_BITS..BASE_BYTE_BITS + 8])));
    for value in [
        current[BASE_CONSTRUCTED],
        current[BASE_IS_WRITE],
        current[BASE_STRICT],
        current[BASE_EQUAL],
    ] {
        push_boolean_v1(&mut residues, A::ONE, value);
    }
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[0],
    );
    let mut normalized_helpers = *current;
    populate_degree_normalization_helpers_v1(&mut normalized_helpers, fixed);
    for column in [
        BASE_GRAMMAR_ORDINAL,
        BASE_EXPECTED_ROOT_KIND,
        BASE_PROFILE_TABLE_ACTIVE,
        BASE_PROFILE_TABLE_MULTIPLICITY,
        BASE_PROFILE_TOPOLOGY_QUERY_ACTIVE,
        BASE_SERIAL_BYTE_QUERY_ACTIVE,
        BASE_SERIAL_BYTE_QUERY_VALUE,
        BASE_COPY_SOURCE_ACTIVE,
        BASE_COPY_CONSUMER_ACTIVE,
        BASE_COPY_DOMAIN,
        BASE_COPY_KEY_1,
        BASE_COPY_KEY_2,
        BASE_COPY_VALUE,
        BASE_COPY_START,
        BASE_COPY_GENERALIZED,
        BASE_DECIMAL_DIGIT_ACTIVE,
        BASE_NUMERIC_SOURCE,
        BASE_NUMERIC_QUERY,
        BASE_NUMERIC_MULTIPLICITY,
    ] {
        residues.push(current[column].sub(normalized_helpers[column]));
    }
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[1],
    );
    let source_byte = active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::SourceByte);
    residues.push(
        source_byte
            .mul(fixed[FIX_DOCUMENT_FIXED])
            .mul(current[BASE_DOCUMENT].sub(fixed[FIX_EXPECTED])),
    );
    residues.push(
        source_byte
            .mul(fixed[FIX_ADDRESS_FIXED])
            .mul(current[BASE_ADDRESS].sub(fixed[FIX_EXPECTED + 1])),
    );
    let source_node = active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::SourceNode);
    residues.push(
        source_node
            .mul(fixed[FIX_DOCUMENT_FIXED])
            .mul(current[BASE_DOCUMENT].sub(fixed[FIX_EXPECTED])),
    );
    residues.push(
        source_node
            .mul(fixed[FIX_ADDRESS_FIXED])
            .mul(current[BASE_NODE].sub(fixed[FIX_EXPECTED + 1])),
    );
    residues.extend(copy_census::residues(current, next, fixed));
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[2],
    );
    let grammar_rule_table = current[BASE_ACTIVE].mul(fixed[FIX_GRAMMAR_RULE_TABLE]);
    let grammar_ordinal_table = current[BASE_ACTIVE].mul(fixed[FIX_GRAMMAR_ORDINAL_TABLE]);
    let root_node = fixed[FIX_EXPECTED + 2];
    let non_root_node = A::ONE.sub(root_node);
    for bit in &current[BASE_SMALL_BITS..BASE_SMALL_BITS + 24] {
        push_boolean_v1(&mut residues, source_node, *bit);
    }
    for bit in &current[GRAMMAR_CHILD_ORDINAL_BITS..GRAMMAR_CHILD_ORDINAL_BITS + 16] {
        push_boolean_v1(&mut residues, source_node, *bit);
    }
    for bit in &current[GRAMMAR_CHILD_COUNT_BITS..GRAMMAR_CHILD_COUNT_BITS + 16] {
        push_boolean_v1(&mut residues, source_node, *bit);
    }
    residues.push(source_node.mul(
        current[BASE_ADDRESS].sub(pack_bits_v1(&current[BASE_SMALL_BITS..BASE_SMALL_BITS + 8])),
    ));
    residues.push(source_node.mul(current[BASE_STATE_BEFORE].sub(pack_bits_v1(
        &current[BASE_SMALL_BITS + 8..BASE_SMALL_BITS + 16],
    ))));
    residues.push(source_node.mul(current[BASE_STATE_AFTER].sub(pack_bits_v1(
        &current[BASE_SMALL_BITS + 16..BASE_SMALL_BITS + 24],
    ))));
    residues.push(source_node.mul(current[BASE_CHILD].sub(pack_bits_v1(
        &current[GRAMMAR_CHILD_ORDINAL_BITS..GRAMMAR_CHILD_ORDINAL_BITS + 16],
    ))));
    residues.push(source_node.mul(current[BASE_D].sub(pack_bits_v1(
        &current[GRAMMAR_CHILD_COUNT_BITS..GRAMMAR_CHILD_COUNT_BITS + 16],
    ))));
    residues.push(
        source_node.mul(
            current[BASE_C]
                .sub(current[BASE_VALUE].mul(A::from_base(F(256))))
                .sub(current[BASE_ADDRESS]),
        ),
    );
    let grammar_ordinal = current[BASE_GRAMMAR_ORDINAL];
    residues.push(
        source_node.mul(
            current[BASE_INSTANCE].sub(
                current[BASE_VALUE]
                    .mul(current[BASE_OFFSET])
                    .add(current[BASE_ADDRESS].mul(current[BASE_ENDPOINT_ROLE]))
                    .add(grammar_ordinal.mul(current[BASE_ENDPOINT_INSTANCE]))
                    .add(current[BASE_H]),
            ),
        ),
    );
    residues.push(
        source_node
            .mul(current[BASE_IS_WRITE])
            .mul(grammar_ordinal.sub(current[BASE_STATE_BEFORE])),
    );
    residues.push(
        source_node
            .mul(current[BASE_STRICT])
            .mul(grammar_ordinal.add(A::ONE).sub(current[BASE_G])),
    );
    residues.push(
        source_node
            .mul(current[BASE_EQUAL])
            .mul(current[BASE_G].sub(current[BASE_STATE_AFTER])),
    );
    residues.push(
        source_node
            .mul(current[BASE_IS_WRITE])
            .mul(current[BASE_STRICT]),
    );
    residues.push(source_node.mul(root_node).mul(current[BASE_PARENT]));
    residues.push(source_node.mul(root_node).mul(current[BASE_CHILD]));
    residues.push(source_node.mul(root_node).mul(current[BASE_B]));
    residues.push(source_node.mul(root_node).mul(current[BASE_C]));
    residues.push(
        source_node
            .mul(root_node)
            .mul(current[BASE_G].sub(current[BASE_D])),
    );
    residues.push(source_node.mul(non_root_node).mul(current[BASE_E]));
    residues.push(
        source_node
            .mul(root_node)
            .mul(current[BASE_E].sub(current[BASE_EXPECTED_ROOT_KIND])),
    );
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[3],
    );
    let ordinal_next_active = current[BASE_ORDINAL_NEXT_ACTIVE];
    residues.push(
        ordinal_next_active.sub(
            fixed[FIX_GRAMMAR_ORDINAL_TABLE]
                .mul(fixed[FIX_ACTIVATION_CONTINUE])
                .mul(next[BASE_ACTIVE]),
        ),
    );
    residues.push(
        current[BASE_ORDINAL_EQUAL_CONTINUE].sub(ordinal_next_active.mul(current[BASE_EQUAL])),
    );
    for bit in &current[GRAMMAR_CHILD_ORDINAL_BITS..GRAMMAR_CHILD_ORDINAL_BITS + 16] {
        push_boolean_v1(&mut residues, grammar_ordinal_table, *bit);
    }
    residues.push(
        grammar_ordinal_table.mul(
            current[BASE_A]
                .sub(current[BASE_DOCUMENT].mul(A::from_base(F(2_048))))
                .sub(current[BASE_PARENT]),
        ),
    );
    residues.push(grammar_ordinal_table.mul(current[BASE_C].sub(pack_bits_v1(
        &current[GRAMMAR_CHILD_ORDINAL_BITS..GRAMMAR_CHILD_ORDINAL_BITS + 16],
    ))));
    residues.push(
        grammar_ordinal_table
            .mul(fixed[FIX_GRAMMAR_ORDINAL_FIRST])
            .mul(current[BASE_CHILD]),
    );
    residues.push(
        grammar_ordinal_table
            .mul(ordinal_next_active)
            .mul(current[BASE_B].sub(next[BASE_A].sub(current[BASE_A]))),
    );
    push_reused_gated_zero_safe_inverse_v1(
        &mut residues,
        // `ordinal_next_active` is itself constrained above to the exact
        // grammar-table/continuation/next-active conjunction. Reusing that
        // committed normalization helper here avoids multiplying the
        // zero-safe inverse identities by the same selectors a second time,
        // which would raise all four identities from degree four to five.
        ordinal_next_active,
        current[BASE_B],
        current[BASE_EQUAL],
        current[BASE_INVERSE],
    );
    residues.push(
        grammar_ordinal_table
            .mul(current[BASE_ORDINAL_EQUAL_CONTINUE])
            .mul(next[BASE_CHILD].sub(current[BASE_CHILD].add(A::ONE))),
    );
    residues.push(
        grammar_ordinal_table
            .mul(current[BASE_ORDINAL_EQUAL_CONTINUE])
            .mul(next[BASE_D].sub(current[BASE_D])),
    );
    residues.push(
        grammar_ordinal_table
            .mul(ordinal_next_active.sub(current[BASE_ORDINAL_EQUAL_CONTINUE]))
            .mul(next[BASE_CHILD]),
    );
    residues.push(
        grammar_ordinal_table
            .mul(ordinal_next_active.sub(current[BASE_ORDINAL_EQUAL_CONTINUE]))
            .mul(current[BASE_CHILD].add(A::ONE).sub(current[BASE_D])),
    );
    residues.push(
        grammar_ordinal_table
            .mul(ordinal_next_active.sub(current[BASE_ORDINAL_EQUAL_CONTINUE]))
            .mul(current[BASE_B].sub(A::ONE).sub(current[BASE_C])),
    );
    residues.push(
        grammar_ordinal_table
            .mul(A::ONE.sub(ordinal_next_active))
            .mul(current[BASE_CHILD].add(A::ONE).sub(current[BASE_D])),
    );
    residues.push(
        grammar_ordinal_table
            .mul(A::ONE.sub(ordinal_next_active))
            .mul(current[BASE_B]),
    );
    residues.push(
        grammar_ordinal_table
            .mul(A::ONE.sub(ordinal_next_active))
            .mul(current[BASE_C]),
    );
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[4],
    );
    let fixed_byte = active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::FixedByte);
    residues.push(fixed_byte.mul(current[BASE_VALUE].sub(current[BASE_A])));
    push_boolean_v1(&mut residues, fixed_byte, current[BASE_IS_WRITE]);
    push_boolean_v1(&mut residues, fixed_byte, current[BASE_STRICT]);
    push_boolean_v1(&mut residues, fixed_byte, current[BASE_ENDPOINT_INSTANCE]);
    push_boolean_v1(&mut residues, fixed_byte, current[BASE_CHILD]);
    push_reused_gated_zero_safe_inverse_v1(
        &mut residues,
        fixed_byte,
        current[BASE_OFFSET],
        current[BASE_IS_WRITE],
        current[BASE_INVERSE],
    );
    let fixed_byte_remaining = current[BASE_B].sub(current[BASE_OFFSET]).sub(A::ONE);
    push_reused_gated_zero_safe_inverse_v1(
        &mut residues,
        fixed_byte,
        fixed_byte_remaining,
        current[BASE_STRICT],
        current[BASE_G],
    );
    let fixed_byte_selected_start = current[BASE_CONTENT_START].add(
        current[BASE_ENDPOINT_INSTANCE].mul(current[BASE_DEPTH].sub(current[BASE_CONTENT_START])),
    );
    residues.push(fixed_byte.mul(current[BASE_START].sub(fixed_byte_selected_start)));
    residues.push(
        fixed_byte.mul(
            current[BASE_CONTENT_END]
                .sub(current[BASE_START])
                .sub(current[BASE_B]),
        ),
    );
    residues.push(
        fixed_byte
            .mul(current[BASE_CHILD])
            .mul(current[BASE_CONTENT_END].sub(current[BASE_TAG_NUMBER])),
    );
    let fixed_byte_continue = fixed_byte.mul(A::ONE.sub(current[BASE_STRICT]));
    residues.push(fixed_byte_continue.mul(next[BASE_ACTIVE].sub(A::ONE)));
    for (current_value, next_value) in [
        (current[BASE_ROLE], next[BASE_ROLE]),
        (current[BASE_INSTANCE], next[BASE_INSTANCE]),
        (current[BASE_ENDPOINT_ROLE], next[BASE_ENDPOINT_ROLE]),
        (current[BASE_PARENT], next[BASE_PARENT]),
        (current[BASE_DOCUMENT], next[BASE_DOCUMENT]),
        (current[BASE_NODE], next[BASE_NODE]),
        (current[BASE_B], next[BASE_B]),
        (current[BASE_START], next[BASE_START]),
        (current[BASE_CONTENT_START], next[BASE_CONTENT_START]),
        (current[BASE_DEPTH], next[BASE_DEPTH]),
        (current[BASE_TAG_NUMBER], next[BASE_TAG_NUMBER]),
        (
            current[BASE_ENDPOINT_INSTANCE],
            next[BASE_ENDPOINT_INSTANCE],
        ),
        (current[BASE_CHILD], next[BASE_CHILD]),
    ] {
        residues.push(fixed_byte_continue.mul(next_value.sub(current_value)));
    }
    residues.push(fixed_byte_continue.mul(next[BASE_OFFSET].sub(current[BASE_OFFSET]).sub(A::ONE)));
    residues
        .push(fixed_byte_continue.mul(next[BASE_ADDRESS].sub(current[BASE_ADDRESS]).sub(A::ONE)));
    residues.extend(name_policy::residues(current, next, fixed));
    residues.extend(name_values::residues(current, next, fixed));
    residues.extend(profile_identity::residues(current, fixed));
    let decimal = current[BASE_DECIMAL_DIGIT_ACTIVE];
    for bit in &current[BASE_SMALL_BITS..BASE_SMALL_BITS + 4] {
        push_boolean_v1(&mut residues, decimal, *bit);
    }
    residues
        .push(decimal.mul(
            current[BASE_A].sub(pack_bits_v1(&current[BASE_SMALL_BITS..BASE_SMALL_BITS + 4])),
        ));
    residues.push(decimal.mul(current[BASE_VALUE].sub(A::from_base(F(48)).add(current[BASE_A]))));
    residues.push(
        decimal.mul(
            current[BASE_STATE_AFTER].sub(
                current[BASE_STATE_BEFORE]
                    .mul(A::from_base(F(10)))
                    .add(current[BASE_A]),
            ),
        ),
    );
    push_reused_gated_zero_safe_inverse_v1(
        &mut residues,
        decimal,
        current[BASE_OFFSET],
        current[BASE_IS_WRITE],
        current[BASE_INVERSE],
    );
    push_reused_gated_zero_safe_inverse_v1(
        &mut residues,
        decimal,
        current[BASE_B].sub(current[BASE_OFFSET]).sub(A::ONE),
        current[BASE_STRICT],
        current[BASE_G],
    );
    residues.push(
        decimal
            .mul(current[BASE_IS_WRITE])
            .mul(current[BASE_STATE_BEFORE]),
    );
    residues.push(
        decimal
            .mul(current[BASE_SMALL_BITS + 3])
            .mul(current[BASE_SMALL_BITS + 1]),
    );
    residues.push(
        decimal
            .mul(current[BASE_SMALL_BITS + 3])
            .mul(current[BASE_SMALL_BITS + 2]),
    );
    let decimal_continue = decimal.mul(A::ONE.sub(current[BASE_STRICT]));
    residues.push(decimal_continue.mul(next[BASE_ACTIVE].sub(A::ONE)));
    residues.push(decimal_continue.mul(next[BASE_ROLE].sub(current[BASE_ROLE])));
    residues.push(decimal_continue.mul(next[BASE_INSTANCE].sub(current[BASE_INSTANCE])));
    residues.push(decimal_continue.mul(next[BASE_B].sub(current[BASE_B])));
    residues.push(decimal_continue.mul(next[BASE_OFFSET].sub(current[BASE_OFFSET]).sub(A::ONE)));
    residues.push(decimal_continue.mul(next[BASE_STATE_BEFORE].sub(current[BASE_STATE_AFTER])));
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[5],
    );
    let calendar =
        current[BASE_ACTIVE].mul(fixed[FIX_CALENDAR_PHASES + CALENDAR_COPY_PHASES_V1 - 1]);
    let calendar_phase_transition = fixed
        [FIX_CALENDAR_PHASES..FIX_CALENDAR_PHASES + CALENDAR_COPY_PHASES_V1 - 1]
        .iter()
        .copied()
        .fold(A::ZERO, A::add);
    for column in [
        BASE_ACTIVE,
        BASE_A,
        BASE_B,
        BASE_C,
        BASE_D,
        BASE_E,
        BASE_F,
        BASE_INSTANCE,
        BASE_G,
        CALENDAR_COLUMNS + calendar::RAW_YEAR,
        CALENDAR_COLUMNS + calendar::GENERALIZED,
    ] {
        residues.push(calendar_phase_transition.mul(next[column].sub(current[column])));
    }
    calendar::append_residues_v1(
        [
            current[BASE_A],
            current[BASE_B],
            current[BASE_C],
            current[BASE_D],
            current[BASE_E],
            current[BASE_F],
            current[BASE_G],
            current[BASE_H],
        ],
        &current[CALENDAR_COLUMNS..CALENDAR_END],
        calendar,
        &mut residues,
    );
    binding::append_residues_v1(current, next, fixed, &mut residues);
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[6],
    );
    let relation = active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::Relation);
    residues.push(relation.mul(current[BASE_A].sub(current[BASE_B].add(current[BASE_C]))));
    residues.push(
        relation.mul(
            current[BASE_C]
                .mul(current[BASE_INVERSE])
                .sub(current[BASE_STRICT]),
        ),
    );
    residues.push(
        relation
            .mul(A::ONE.sub(current[BASE_STRICT]))
            .mul(current[BASE_INVERSE]),
    );
    path_len::append_residues(current, next, fixed, &mut residues);
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[7],
    );
    let serial_source =
        active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::SerialSource);
    let serial_source_first = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_SOURCE_FIRST]);
    let serial_source_interior = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_SOURCE_INTERIOR]);
    let serial_source_not_first = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_SOURCE_NOT_FIRST]);
    let serial_source_first_payload =
        current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_SOURCE_FIRST_PAYLOAD]);
    for (actual, expected) in [
        (current[SERIAL_SOURCE_LOGICAL_ID], fixed[FIX_EXPECTED]),
        (current[BASE_OFFSET], fixed[FIX_EXPECTED + 1]),
        (current[BASE_ROLE], fixed[FIX_EXPECTED + 2]),
        (current[BASE_INSTANCE], fixed[FIX_EXPECTED + 3]),
    ] {
        residues.push(serial_source.mul(actual.sub(expected)));
    }
    residues.push(serial_source.mul(current[BASE_TAG_CLASS]));
    residues.push(serial_source.mul(current[BASE_CONSTRUCTED]));
    residues.push(serial_source.mul(current[BASE_TAG_NUMBER].sub(A::from_base(F(2)))));
    residues.push(
        serial_source.mul(
            current[BASE_CONTENT_END]
                .sub(current[BASE_CONTENT_START])
                .sub(current[BASE_A]),
        ),
    );
    residues.push(
        serial_source.mul(
            current[BASE_A]
                .sub(current[SERIAL_SOURCE_LENGTH])
                .sub(current[BASE_STRICT]),
        ),
    );
    residues.push(serial_source_first.mul(current[BASE_VALUE].sub(current[SERIAL_SOURCE_LENGTH])));
    residues.push(
        serial_source
            .mul(A::ONE.sub(fixed[FIX_LOCAL_LAST]))
            .mul(next[SERIAL_SOURCE_LENGTH].sub(current[SERIAL_SOURCE_LENGTH])),
    );
    residues.push(
        serial_source.mul(
            current[SERIAL_SOURCE_COUNT_AFTER]
                .sub(current[SERIAL_SOURCE_COUNT_BEFORE])
                .sub(current[BASE_EQUAL]),
        ),
    );
    residues.push(serial_source_first.mul(current[SERIAL_SOURCE_COUNT_BEFORE]));
    residues.push(serial_source_first.mul(current[BASE_EQUAL]));
    residues.push(
        serial_source
            .mul(A::ONE.sub(fixed[FIX_LOCAL_LAST]))
            .mul(next[SERIAL_SOURCE_COUNT_BEFORE].sub(current[SERIAL_SOURCE_COUNT_AFTER])),
    );
    residues.push(serial_source_first.mul(next[BASE_EQUAL].sub(A::ONE)));
    residues.push(
        serial_source_interior
            .mul(next[BASE_EQUAL])
            .mul(A::ONE.sub(current[BASE_EQUAL])),
    );
    residues.push(
        serial_source_not_first
            .mul(A::ONE.sub(current[BASE_EQUAL]))
            .mul(current[BASE_VALUE]),
    );
    residues.push(
        serial_source
            .mul(fixed[FIX_LOCAL_LAST])
            .mul(current[SERIAL_SOURCE_COUNT_AFTER].sub(current[SERIAL_SOURCE_LENGTH])),
    );
    residues.push(
        serial_source_first_payload.mul(
            current[BASE_VALUE]
                .mul(current[SERIAL_SOURCE_FIRST_INVERSE])
                .sub(A::ONE),
        ),
    );
    residues.push(
        serial_source
            .mul(A::ONE.sub(fixed[FIX_EXPECTED + 4]))
            .mul(current[SERIAL_SOURCE_FIRST_INVERSE]),
    );
    residues.push(
        serial_source_first_payload.mul(current[BASE_BYTE_BITS + 7].sub(current[BASE_STRICT])),
    );
    residues.push(
        serial_source.mul(
            current[BASE_IS_WRITE]
                .sub(current[BASE_EQUAL].add(fixed[FIX_LOCAL_FIRST].mul(current[BASE_STRICT]))),
        ),
    );
    residues.push(
        serial_source
            .mul(current[BASE_EQUAL])
            .mul(current[SERIAL_SOURCE_QUERY_VALUE].sub(current[BASE_VALUE])),
    );
    residues.push(
        serial_source_first
            .mul(current[BASE_STRICT])
            .mul(current[SERIAL_SOURCE_QUERY_VALUE]),
    );
    residues.push(
        serial_source
            .mul(A::ONE.sub(current[BASE_IS_WRITE]))
            .mul(current[SERIAL_SOURCE_QUERY_VALUE]),
    );
    residues.push(
        serial_source.mul(current[BASE_EQUAL]).mul(
            current[BASE_ADDRESS]
                .add(current[SERIAL_SOURCE_LENGTH])
                .add(A::ONE)
                .sub(current[BASE_CONTENT_END])
                .sub(current[BASE_OFFSET]),
        ),
    );
    residues.push(
        serial_source_first
            .mul(current[BASE_STRICT])
            .mul(current[BASE_ADDRESS].sub(current[BASE_CONTENT_START])),
    );
    residues.push(
        serial_source
            .mul(A::ONE.sub(current[BASE_IS_WRITE]))
            .mul(current[BASE_ADDRESS]),
    );
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[8],
    );
    let serial = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_COMPARE_PHASE_RIGHT]);
    let serial_first = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_COMPARE_FIRST]);
    let serial_last = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_COMPARE_LAST]);
    let serial_not_last = serial.sub(serial_last);
    let serial_interior = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_COMPARE_INTERIOR]);
    let serial_not_first = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_COMPARE_NOT_FIRST]);
    let serial_first_payload = current[BASE_ACTIVE].mul(fixed[FIX_SERIAL_COMPARE_FIRST_PAYLOAD]);
    for column in [
        BASE_ACTIVE,
        BASE_ROLE,
        BASE_INSTANCE,
        BASE_OFFSET,
        BASE_A,
        BASE_B,
    ] {
        residues.push(fixed[FIX_SERIAL_COMPARE_PHASE_LEFT].mul(next[column].sub(current[column])));
    }
    for (actual, expected) in [
        (current[BASE_STRICT], fixed[FIX_EXPECTED]),
        (current[BASE_ROLE], fixed[FIX_EXPECTED + 1]),
        (current[BASE_INSTANCE], fixed[FIX_EXPECTED + 2]),
        (current[BASE_OFFSET], fixed[FIX_EXPECTED + 3]),
    ] {
        residues.push(serial.mul(actual.sub(expected)));
    }
    for bit in &current[SERIAL_LEFT_BITS..SERIAL_SLACK_BITS + 8] {
        push_boolean_v1(&mut residues, serial, *bit);
    }
    residues.push(serial.mul(current[BASE_A].sub(pack_bits_v1(
        &current[SERIAL_LEFT_BITS..SERIAL_LEFT_BITS + 8],
    ))));
    residues.push(serial.mul(current[BASE_B].sub(pack_bits_v1(
        &current[SERIAL_RIGHT_BITS..SERIAL_RIGHT_BITS + 8],
    ))));
    residues.push(serial.mul(current[BASE_C].sub(pack_bits_v1(
        &current[SERIAL_SLACK_BITS..SERIAL_SLACK_BITS + 8],
    ))));
    for value in [
        current[SERIAL_LESS],
        current[SERIAL_ORDER_BEFORE],
        current[SERIAL_ORDER_AFTER],
    ] {
        push_boolean_v1(&mut residues, serial, value);
    }
    for active in [current[SERIAL_LEFT_ACTIVE], current[SERIAL_RIGHT_ACTIVE]] {
        push_boolean_v1(&mut residues, serial, active);
    }
    for (before, after, active) in [
        (
            current[SERIAL_LEFT_COUNT_BEFORE],
            current[SERIAL_LEFT_COUNT_AFTER],
            current[SERIAL_LEFT_ACTIVE],
        ),
        (
            current[SERIAL_RIGHT_COUNT_BEFORE],
            current[SERIAL_RIGHT_COUNT_AFTER],
            current[SERIAL_RIGHT_ACTIVE],
        ),
    ] {
        residues.push(serial.mul(after.sub(before.add(active))));
        residues.push(serial_first.mul(before));
        residues.push(serial_first.mul(active));
    }
    residues.push(serial_first.mul(current[SERIAL_LEFT_LENGTH].sub(current[BASE_A])));
    residues.push(serial_first.mul(current[SERIAL_RIGHT_LENGTH].sub(current[BASE_B])));
    for (length, next_length, count_after, next_count_before, active, next_active, value) in [
        (
            current[SERIAL_LEFT_LENGTH],
            next[SERIAL_LEFT_LENGTH],
            current[SERIAL_LEFT_COUNT_AFTER],
            next[SERIAL_LEFT_COUNT_BEFORE],
            current[SERIAL_LEFT_ACTIVE],
            next[SERIAL_LEFT_ACTIVE],
            current[BASE_A],
        ),
        (
            current[SERIAL_RIGHT_LENGTH],
            next[SERIAL_RIGHT_LENGTH],
            current[SERIAL_RIGHT_COUNT_AFTER],
            next[SERIAL_RIGHT_COUNT_BEFORE],
            current[SERIAL_RIGHT_ACTIVE],
            next[SERIAL_RIGHT_ACTIVE],
            current[BASE_B],
        ),
    ] {
        residues.push(serial_not_last.mul(next_length.sub(length)));
        residues.push(serial_not_last.mul(next_count_before.sub(count_after)));
        residues.push(serial_first.mul(next_active.sub(A::ONE)));
        residues.push(serial_interior.mul(next_active).mul(A::ONE.sub(active)));
        residues.push(serial_not_first.mul(A::ONE.sub(active)).mul(value));
        residues.push(serial_last.mul(count_after.sub(length)));
    }
    for (value, inverse) in [
        (current[BASE_A], current[SERIAL_LEFT_FIRST_INVERSE]),
        (current[BASE_B], current[SERIAL_RIGHT_FIRST_INVERSE]),
    ] {
        residues.push(serial_first_payload.mul(value.mul(inverse).sub(A::ONE)));
        residues.push(serial.mul(A::ONE.sub(fixed[FIX_EXPECTED + 4])).mul(inverse));
    }
    let difference = current[BASE_A].sub(current[BASE_B]);
    residues.push(
        serial.mul(
            difference
                .mul(current[BASE_INVERSE])
                .sub(A::ONE.sub(current[BASE_EQUAL])),
        ),
    );
    residues.push(serial.mul(current[BASE_EQUAL]).mul(difference));
    residues.push(serial.mul(current[BASE_EQUAL]).mul(current[BASE_INVERSE]));
    residues.push(
        serial.mul(
            current[BASE_STATE_AFTER].sub(current[BASE_STATE_BEFORE].mul(current[BASE_EQUAL])),
        ),
    );
    residues.push(serial_first.mul(current[BASE_STATE_BEFORE].sub(A::ONE)));
    residues.push(serial_not_last.mul(next[BASE_STATE_BEFORE].sub(current[BASE_STATE_AFTER])));
    residues.push(
        serial_last
            .mul(A::ONE.sub(current[BASE_STRICT]))
            .mul(current[BASE_STATE_AFTER]),
    );
    residues.push(
        serial
            .mul(current[SERIAL_LESS])
            .mul(A::ONE.sub(current[BASE_STRICT])),
    );
    residues.push(serial.mul(current[SERIAL_LESS]).mul(current[BASE_EQUAL]));
    residues.push(
        serial
            .mul(current[SERIAL_LESS])
            .mul(A::ONE.sub(current[BASE_STATE_BEFORE])),
    );
    residues.push(
        serial
            .mul(current[BASE_C])
            .mul(A::ONE.sub(current[SERIAL_LESS])),
    );
    residues.push(
        serial.mul(current[SERIAL_LESS]).mul(
            current[BASE_B]
                .sub(current[BASE_A])
                .sub(A::ONE)
                .sub(current[BASE_C]),
        ),
    );
    residues.push(serial.mul(current[SERIAL_ORDER_AFTER].sub(
        current[SERIAL_ORDER_BEFORE].add(current[BASE_STATE_BEFORE].mul(current[SERIAL_LESS])),
    )));
    residues.push(serial_first.mul(current[SERIAL_ORDER_BEFORE]));
    residues.push(serial_not_last.mul(next[SERIAL_ORDER_BEFORE].sub(current[SERIAL_ORDER_AFTER])));
    residues.push(
        serial_last
            .mul(current[BASE_STRICT])
            .mul(current[SERIAL_ORDER_AFTER].sub(A::ONE)),
    );
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[9],
    );
    let range = active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::RangeByte);
    residues.push(
        range.mul(
            current[BASE_STATE_AFTER].sub(
                current[BASE_STATE_BEFORE]
                    .mul(A::from_base(F(256)))
                    .add(current[BASE_VALUE]),
            ),
        ),
    );
    residues.push(
        range
            .mul(fixed[FIX_LOCAL_FIRST])
            .mul(current[BASE_STATE_BEFORE]),
    );
    residues.push(
        range
            .mul(A::ONE.sub(fixed[FIX_LOCAL_LAST]))
            .mul(next[BASE_ROLE].sub(current[BASE_ROLE])),
    );
    residues.push(
        range
            .mul(A::ONE.sub(fixed[FIX_LOCAL_LAST]))
            .mul(next[BASE_INSTANCE].sub(current[BASE_INSTANCE])),
    );
    let profile_table =
        active_family_gate_v1(current, fixed, ZkX509Rfc5280StarkFamilyV1::SemanticSource);
    for (actual, expected) in [
        (current[BASE_ROLE], fixed[FIX_EXPECTED]),
        (current[BASE_ENDPOINT_ROLE], fixed[FIX_EXPECTED + 1]),
        (current[BASE_PARENT], fixed[FIX_EXPECTED + 2]),
        (current[BASE_OFFSET], fixed[FIX_EXPECTED + 3]),
        (current[BASE_B], fixed[FIX_EXPECTED + 4]),
        (current[BASE_VALUE], fixed[FIX_EXPECTED + 5]),
        (current[BASE_ENDPOINT_INSTANCE], fixed[FIX_EXPECTED + 6]),
        (current[BASE_CHILD], fixed[FIX_EXPECTED + 7]),
    ] {
        residues.push(profile_table.mul(actual.sub(expected)));
    }
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[10],
    );
    residues.extend(output_metadata_residues_v1(current, fixed));
    residues.extend(output_source_residues_v1(current, fixed));
    residues.extend(variable_output::residues(current, next, fixed));
    residues.extend(projection_serial::residues(current, next, fixed));
    residues.extend(projection_disclosure::residues(current, next, fixed));
    // Every private family is a canonical active prefix of its fixed
    // registration segment. Top-level byte/node slots reset the prefix at
    // their fixed 4 KiB/2,048-node boundaries.
    residues.extend(private_geometry_residues_v1(current, next, fixed));
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[11],
    );
    let first = fixed[FIX_GLOBAL_FIRST];
    let last = fixed[FIX_GLOBAL_LAST];
    let continue_gate = fixed[FIX_CONTINUE];
    for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
        let der_byte_factor = zk_x509_der_stark_input_byte_factor_v1(
            current[BASE_DOCUMENT],
            current[BASE_ADDRESS],
            current[BASE_VALUE],
            lane,
            der_challenges,
        )?;
        let der_node_factor = zk_x509_der_stark_node_factor_v1(
            ZkX509DerStarkNodeEventV1 {
                document: current[BASE_DOCUMENT],
                ordinal: current[BASE_NODE],
                parent_frame: current[BASE_PARENT],
                tag_class: current[BASE_TAG_CLASS],
                tag_number: current[BASE_TAG_NUMBER],
                constructed: current[BASE_CONSTRUCTED],
                start: current[BASE_START],
                content_start: current[BASE_CONTENT_START],
                content_end: current[BASE_CONTENT_END],
                depth: current[BASE_DEPTH],
                content_len: current[BASE_A],
            },
            lane,
            der_challenges,
        )?;
        for (before, after, gate, factor) in [
            (
                AUX_DER_BYTE_BEFORE + lane,
                AUX_DER_BYTE_AFTER + lane,
                source_byte,
                der_byte_factor,
            ),
            (
                AUX_DER_NODE_BEFORE + lane,
                AUX_DER_NODE_AFTER + lane,
                source_node,
                der_node_factor,
            ),
        ] {
            residues.push(
                current_aux[after]
                    .sub(current_aux[before].mul(A::ONE.add(gate.mul(factor.sub(A::ONE))))),
            );
            residues.push(first.mul(current_aux[before].sub(A::ONE)));
            residues.push(continue_gate.mul(next_aux[before].sub(current_aux[after])));
        }
    }
    // The bridge is constant on every native row, without an initial-one
    // condition. It connects each SHA endpoint to the RFC final endpoint.
    for column in AUX_SHA_UNION_CENTERS..AUX_SERIAL_SOURCE_BEFORE {
        residues.push(continue_gate.mul(next_aux[column].sub(current_aux[column])));
    }
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[12],
    );
    if let Some(claims) = terminal_claims {
        residues.extend(evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(
            last,
            current_aux,
            claims,
        )?);
    } else {
        for role in 0..OUTPUT_ROLE_COUNT_V1 {
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                residues.push(
                    last.mul(
                        current_aux[output_role_aux_column_v1(role, false, lane)]
                            .sub(current_aux[output_role_aux_column_v1(role, true, lane)]),
                    ),
                );
            }
        }
    }
    let terminal_section = RFC5280_RESIDUE_SECTIONS_V1[13];
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        (
            terminal_section.0,
            terminal_section.1 - if terminal_claims.is_some() { 0 } else { 4 },
        ),
    );
    for role_index in 0..OUTPUT_ROLE_COUNT_V1 {
        for consumer in [false, true] {
            let selector = fixed[output_role_fixed_selector_column_v1(role_index, consumer)];
            let gate = current[BASE_ACTIVE].mul(selector);
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                let product = current_aux[output_role_aux_column_v1(role_index, consumer, lane)];
                residues.push(
                    continue_gate
                        .mul(
                            next_aux[output_role_aux_column_v1(role_index, consumer, lane)]
                                .sub(product),
                        )
                        .sub(
                            gate.mul(product).mul(
                                output_role_product_factor_v1(
                                    current, role_index, consumer, lane, challenges,
                                )
                                .sub(A::ONE),
                            ),
                        ),
                );
                residues.push(first.mul(product.sub(A::ONE)));
            }
        }
    }
    assert_residue_section_v1(
        residues.len(),
        &mut residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[14],
    );
    for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
        let mut lane_section_start = residues.len();
        let copy_factor = normalized_copy_factor_v1(current, lane, challenges);
        residues.push(
            current_aux[AUX_SERIAL_SOURCE_AFTER + lane]
                .sub(current_aux[AUX_SERIAL_SOURCE_BEFORE + lane].mul(
                    A::ONE.add(current[BASE_COPY_SOURCE_ACTIVE].mul(copy_factor.sub(A::ONE))),
                )),
        );
        residues.push(
            current_aux[AUX_SERIAL_CONSUMER_AFTER + lane].sub(
                current_aux[AUX_SERIAL_CONSUMER_BEFORE + lane].mul(
                    A::ONE.add(current[BASE_COPY_CONSUMER_ACTIVE].mul(copy_factor.sub(A::ONE))),
                ),
            ),
        );
        residues.push(first.mul(current_aux[AUX_SERIAL_SOURCE_BEFORE + lane].sub(A::ONE)));
        residues.push(first.mul(current_aux[AUX_SERIAL_CONSUMER_BEFORE + lane].sub(A::ONE)));
        residues.push(
            continue_gate.mul(
                next_aux[AUX_SERIAL_SOURCE_BEFORE + lane]
                    .sub(current_aux[AUX_SERIAL_SOURCE_AFTER + lane]),
            ),
        );
        residues.push(
            continue_gate.mul(
                next_aux[AUX_SERIAL_CONSUMER_BEFORE + lane]
                    .sub(current_aux[AUX_SERIAL_CONSUMER_AFTER + lane]),
            ),
        );
        residues.push(
            last.mul(
                current_aux[AUX_SERIAL_SOURCE_AFTER + lane]
                    .sub(current_aux[AUX_SERIAL_CONSUMER_AFTER + lane]),
            ),
        );
        assert_residue_section_v1(
            residues.len(),
            &mut lane_section_start,
            (
                RFC5280_RESIDUE_SECTIONS_V1[15].0,
                RFC5280_RESIDUE_SECTIONS_V1[15].1 / ZK_X509_RFC5280_STARK_BUS_LANES_V1,
            ),
        );
        let grammar_ordinal_source_factor = grammar_ordinal_factor_v1(
            current[BASE_DOCUMENT],
            current[BASE_PARENT],
            current[BASE_CHILD],
            current[BASE_G],
            lane,
            challenges,
        );
        let grammar_ordinal_table_factor = grammar_ordinal_factor_v1(
            current[BASE_DOCUMENT],
            current[BASE_PARENT],
            current[BASE_CHILD],
            current[BASE_D],
            lane,
            challenges,
        );
        for (before, after, gate, factor) in [
            (
                AUX_GRAMMAR_ORDINAL_SOURCE_BEFORE + lane,
                AUX_GRAMMAR_ORDINAL_SOURCE_AFTER + lane,
                current[BASE_ACTIVE].mul(fixed[FIX_SOURCE_NODE_NON_ROOT]),
                grammar_ordinal_source_factor,
            ),
            (
                AUX_GRAMMAR_ORDINAL_TABLE_BEFORE + lane,
                AUX_GRAMMAR_ORDINAL_TABLE_AFTER + lane,
                grammar_ordinal_table,
                grammar_ordinal_table_factor,
            ),
        ] {
            residues.push(
                current_aux[after]
                    .sub(current_aux[before].mul(A::ONE.add(gate.mul(factor.sub(A::ONE))))),
            );
            residues.push(first.mul(current_aux[before].sub(A::ONE)));
            residues.push(continue_gate.mul(next_aux[before].sub(current_aux[after])));
        }
        residues.push(
            last.mul(
                current_aux[AUX_GRAMMAR_ORDINAL_SOURCE_AFTER + lane]
                    .sub(current_aux[AUX_GRAMMAR_ORDINAL_TABLE_AFTER + lane]),
            ),
        );
        assert_residue_section_v1(
            residues.len(),
            &mut lane_section_start,
            (
                RFC5280_RESIDUE_SECTIONS_V1[16].0,
                RFC5280_RESIDUE_SECTIONS_V1[16].1 / ZK_X509_RFC5280_STARK_BUS_LANES_V1,
            ),
        );
        let profile_query_gate = fixed_byte.add(active_family_gate_v1(
            current,
            fixed,
            ZkX509Rfc5280StarkFamilyV1::NameValue,
        ));
        let profile_table_gate = current[BASE_PROFILE_TABLE_ACTIVE];
        let profile_table_factor = fixed[FIX_PROFILE_TABLE]
            .mul(profile_byte_factor_v1(current, lane, challenges))
            .add(
                fixed[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize]
                    .mul(profile_topology_source_factor_v1(current, lane, challenges)),
            );
        let profile_table_multiplicity = current[BASE_PROFILE_TABLE_MULTIPLICITY];
        let profile_query_factor = profile_byte_factor_v1(current, lane, challenges);
        let profile_topology_query = current[BASE_PROFILE_TOPOLOGY_QUERY_ACTIVE];
        let profile_topology_query_factor =
            profile_topology_query_factor_v1(current, lane, challenges);
        push_gated_zero_safe_inverse_v1(
            &mut residues,
            profile_table_gate,
            profile_table_factor,
            current_aux[AUX_PROFILE_TABLE_ZERO + lane],
            current_aux[AUX_PROFILE_TABLE_INVERSE + lane],
        );
        push_gated_zero_safe_inverse_v1(
            &mut residues,
            profile_query_gate,
            profile_query_factor,
            current_aux[AUX_PROFILE_QUERY_ZERO + lane],
            current_aux[AUX_PROFILE_QUERY_INVERSE + lane],
        );
        push_gated_zero_safe_inverse_v1(
            &mut residues,
            profile_topology_query,
            profile_topology_query_factor,
            current_aux[AUX_PROFILE_TOPOLOGY_QUERY_ZERO + lane],
            current_aux[AUX_PROFILE_TOPOLOGY_QUERY_INVERSE + lane],
        );
        residues.push(
            continue_gate
                .mul(
                    next_aux[AUX_PROFILE_LOOKUP_ACCUMULATOR + lane]
                        .sub(current_aux[AUX_PROFILE_LOOKUP_ACCUMULATOR + lane]),
                )
                .sub(
                    profile_table_gate
                        .mul(profile_table_multiplicity)
                        .mul(current_aux[AUX_PROFILE_TABLE_INVERSE + lane]),
                )
                .add(profile_query_gate.mul(current_aux[AUX_PROFILE_QUERY_INVERSE + lane]))
                .add(
                    profile_topology_query
                        .mul(current_aux[AUX_PROFILE_TOPOLOGY_QUERY_INVERSE + lane]),
                ),
        );
        residues.push(
            continue_gate
                .mul(
                    next_aux[AUX_PROFILE_ZERO_ACCUMULATOR + lane]
                        .sub(current_aux[AUX_PROFILE_ZERO_ACCUMULATOR + lane]),
                )
                .sub(
                    profile_table_gate
                        .mul(profile_table_multiplicity)
                        .mul(current_aux[AUX_PROFILE_TABLE_ZERO + lane]),
                )
                .add(profile_query_gate.mul(current_aux[AUX_PROFILE_QUERY_ZERO + lane]))
                .add(
                    profile_topology_query.mul(current_aux[AUX_PROFILE_TOPOLOGY_QUERY_ZERO + lane]),
                ),
        );
        for accumulator in [
            AUX_PROFILE_LOOKUP_ACCUMULATOR + lane,
            AUX_PROFILE_ZERO_ACCUMULATOR + lane,
        ] {
            residues.push(first.mul(current_aux[accumulator]));
            residues.push(last.mul(current_aux[accumulator]));
        }
        assert_residue_section_v1(
            residues.len(),
            &mut lane_section_start,
            (
                RFC5280_RESIDUE_SECTIONS_V1[17].0,
                RFC5280_RESIDUE_SECTIONS_V1[17].1 / ZK_X509_RFC5280_STARK_BUS_LANES_V1,
            ),
        );
        for (
            accumulator,
            zero_accumulator,
            table_inverse,
            query_inverse,
            table_zero,
            query_zero,
            table_gate,
            query_gate,
            table_factor,
            query_factor,
            multiplicity,
        ) in [
            (
                AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane,
                AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane,
                AUX_SERIAL_BYTE_TABLE_INVERSE + lane,
                AUX_SERIAL_BYTE_QUERY_INVERSE + lane,
                AUX_SERIAL_BYTE_TABLE_ZERO + lane,
                AUX_SERIAL_BYTE_QUERY_ZERO + lane,
                source_byte,
                current[BASE_SERIAL_BYTE_QUERY_ACTIVE],
                serial_byte_lookup_factor_v1(
                    current[BASE_DOCUMENT],
                    current[BASE_ADDRESS],
                    current[BASE_VALUE],
                    lane,
                    challenges,
                ),
                serial_byte_lookup_factor_v1(
                    current[BASE_DOCUMENT],
                    current[BASE_ADDRESS],
                    current[BASE_SERIAL_BYTE_QUERY_VALUE],
                    lane,
                    challenges,
                ),
                current[SERIAL_BYTE_TABLE_MULTIPLICITY],
            ),
            (
                AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR + lane,
                AUX_SERIAL_NODE_ZERO_ACCUMULATOR + lane,
                AUX_SERIAL_NODE_TABLE_INVERSE + lane,
                AUX_SERIAL_NODE_QUERY_INVERSE + lane,
                AUX_SERIAL_NODE_TABLE_ZERO + lane,
                AUX_SERIAL_NODE_QUERY_ZERO + lane,
                source_node,
                serial_source
                    .add(output_source_node_query_gate_v1(current, fixed))
                    .add(path_len::node_query_gate(current, fixed))
                    .add(copy_census::node_query_gate(current, fixed)),
                serial_node_lookup_factor_v1(current, lane, challenges),
                node_query_factor_v1(current, fixed, lane, challenges),
                current[SERIAL_NODE_TABLE_MULTIPLICITY],
            ),
        ] {
            push_gated_zero_safe_inverse_v1(
                &mut residues,
                table_gate,
                table_factor,
                current_aux[table_zero],
                current_aux[table_inverse],
            );
            push_gated_zero_safe_inverse_v1(
                &mut residues,
                query_gate,
                query_factor,
                current_aux[query_zero],
                current_aux[query_inverse],
            );
            residues.push(
                continue_gate
                    .mul(next_aux[accumulator].sub(current_aux[accumulator]))
                    .sub(table_gate.mul(multiplicity).mul(current_aux[table_inverse]))
                    .add(query_gate.mul(current_aux[query_inverse])),
            );
            residues.push(
                continue_gate
                    .mul(next_aux[zero_accumulator].sub(current_aux[zero_accumulator]))
                    .sub(table_gate.mul(multiplicity).mul(current_aux[table_zero]))
                    .add(query_gate.mul(current_aux[query_zero])),
            );
            residues.push(first.mul(current_aux[accumulator]));
            residues.push(first.mul(current_aux[zero_accumulator]));
            residues.push(last.mul(current_aux[accumulator]));
            residues.push(last.mul(current_aux[zero_accumulator]));
        }
        assert_residue_section_v1(
            residues.len(),
            &mut lane_section_start,
            (
                RFC5280_RESIDUE_SECTIONS_V1[18].0,
                RFC5280_RESIDUE_SECTIONS_V1[18].1 / ZK_X509_RFC5280_STARK_BUS_LANES_V1,
            ),
        );
        for (
            accumulator,
            zero_accumulator,
            table_inverse,
            query_inverse,
            table_zero,
            query_zero,
            table_gate,
            query_gate,
            table_factor,
            query_factor,
            multiplicity,
        ) in [
            (
                AUX_GRAMMAR_RULE_LOOKUP_ACCUMULATOR + lane,
                AUX_GRAMMAR_RULE_ZERO_ACCUMULATOR + lane,
                AUX_GRAMMAR_RULE_TABLE_INVERSE + lane,
                AUX_GRAMMAR_RULE_QUERY_INVERSE + lane,
                AUX_GRAMMAR_RULE_TABLE_ZERO + lane,
                AUX_GRAMMAR_RULE_QUERY_ZERO + lane,
                grammar_rule_table,
                source_node,
                grammar_rule_table_factor_v1(fixed, lane, challenges),
                grammar_rule_query_factor_v1(current, lane, challenges),
                current[BASE_A],
            ),
            (
                AUX_GRAMMAR_PARENT_LOOKUP_ACCUMULATOR + lane,
                AUX_GRAMMAR_PARENT_ZERO_ACCUMULATOR + lane,
                AUX_GRAMMAR_PARENT_TABLE_INVERSE + lane,
                AUX_GRAMMAR_PARENT_QUERY_INVERSE + lane,
                AUX_GRAMMAR_PARENT_TABLE_ZERO + lane,
                AUX_GRAMMAR_PARENT_QUERY_ZERO + lane,
                source_node,
                current[BASE_ACTIVE].mul(fixed[FIX_SOURCE_NODE_NON_ROOT]),
                grammar_parent_table_factor_v1(current, lane, challenges),
                grammar_parent_query_factor_v1(current, lane, challenges),
                current[BASE_D],
            ),
        ] {
            push_gated_zero_safe_inverse_v1(
                &mut residues,
                table_gate,
                table_factor,
                current_aux[table_zero],
                current_aux[table_inverse],
            );
            push_gated_zero_safe_inverse_v1(
                &mut residues,
                query_gate,
                query_factor,
                current_aux[query_zero],
                current_aux[query_inverse],
            );
            residues.push(
                continue_gate
                    .mul(next_aux[accumulator].sub(current_aux[accumulator]))
                    .sub(table_gate.mul(multiplicity).mul(current_aux[table_inverse]))
                    .add(query_gate.mul(current_aux[query_inverse])),
            );
            residues.push(
                continue_gate
                    .mul(next_aux[zero_accumulator].sub(current_aux[zero_accumulator]))
                    .sub(table_gate.mul(multiplicity).mul(current_aux[table_zero]))
                    .add(query_gate.mul(current_aux[query_zero])),
            );
            residues.push(first.mul(current_aux[accumulator]));
            residues.push(first.mul(current_aux[zero_accumulator]));
            residues.push(last.mul(current_aux[accumulator]));
            residues.push(last.mul(current_aux[zero_accumulator]));
        }
        assert_residue_section_v1(
            residues.len(),
            &mut lane_section_start,
            (
                RFC5280_RESIDUE_SECTIONS_V1[19].0,
                RFC5280_RESIDUE_SECTIONS_V1[19].1 / ZK_X509_RFC5280_STARK_BUS_LANES_V1,
            ),
        );
    }
    debug_assert_eq!(
        residues.len() - residue_section_start,
        RFC5280_RESIDUE_SECTIONS_V1[15..]
            .iter()
            .map(|section| section.1)
            .sum::<usize>(),
        "RFC 5280 four-lane residue sections drifted"
    );
    let numeric_start = residues.len();
    let numeric_row = |aux: &ZkX509Rfc5280StarkAuxRowV1<A>| numeric::NumericLookupRowV1 {
        inverse: core::array::from_fn(|lane| aux[AUX_NUMERIC_INVERSE + lane]),
        zero: core::array::from_fn(|lane| aux[AUX_NUMERIC_ZERO + lane]),
        sum: core::array::from_fn(|lane| aux[AUX_NUMERIC_SUM + lane]),
        zero_sum: core::array::from_fn(|lane| aux[AUX_NUMERIC_ZERO_SUM + lane]),
    };
    residues.extend(numeric::lookup_residues_v1(
        &numeric_lookup_event_v1(current, fixed),
        &numeric_row(current_aux),
        &numeric_row(next_aux),
        first,
        continue_gate,
        last,
        challenges.tuple,
    ));
    debug_assert_eq!(residues.len() - numeric_start, numeric::LOOKUP_RESIDUES_V1);
    if residues.len() != expected_count {
        return Err(ZkX509Rfc5280StarkErrorV1::Semantic);
    }
    Ok(residues)
}
#[cfg(test)]
#[path = "rfc5280_stark_fp4_tests.rs"]
mod fp4_tests;
#[cfg(test)]
mod tests {
    #[test]
    fn local_rfc_relation_removes_only_four_public_claims_and_preserves_private_equalities() {
        fn compare<A: PolynomialAirFieldV1 + core::fmt::Debug + PartialEq>(
            embed: impl Fn(usize) -> A,
        ) {
            for seed in 0..8 {
                let current = core::array::from_fn(|i| embed(seed + i));
                let next = core::array::from_fn(|i| embed(seed + 13 + i));
                let current_aux = core::array::from_fn(|i| embed(seed + 17 + i));
                let next_aux = core::array::from_fn(|i| embed(seed + 23 + i));
                let fixed = core::array::from_fn(|i| embed(seed + 29 + i));
                let full = evaluate_zk_x509_rfc5280_stark_residues_v1(
                    &current,
                    &next,
                    &current_aux,
                    &next_aux,
                    &fixed,
                    der_challenges_v1(),
                    challenges_v1(),
                    terminal_claims_v1(),
                )
                .unwrap();
                let local = evaluate_zk_x509_rfc5280_local_residues_v1(
                    &current,
                    &next,
                    &current_aux,
                    &next_aux,
                    &fixed,
                    der_challenges_v1(),
                    challenges_v1(),
                )
                .unwrap();
                let begin = RFC5280_RESIDUE_SECTIONS_V1[..13]
                    .iter()
                    .map(|section| section.1)
                    .sum::<usize>()
                    + RFC5280_PRIVATE_OUTPUT_EQUALITIES_V1;
                let expected = full[..begin]
                    .iter()
                    .chain(&full[begin + 4..])
                    .copied()
                    .collect::<Vec<_>>();
                assert_eq!(local.len(), ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1);
                assert_eq!(local, expected);
                assert_eq!(RFC5280_PRIVATE_OUTPUT_EQUALITIES_V1, 36);
            }
        }
        compare(|i| F((i % 17) as u64));
        compare(|i| {
            crate::privacy_engines::transparent_stark::GoldilocksFp4V1::canonical([
                (i % 17) as u64,
                (i % 11) as u64,
                (i % 7) as u64,
                (i % 5) as u64,
            ])
            .unwrap()
        });
    }
    use super::*;
    use crate::privacy_engines::zk_x509::{
        der_air::build_zk_x509_rfc5280_trace_v1, relation::tests::fixture,
    };
    use sha2::{Digest as _, Sha256};
    include!("rfc5280_stark_preflight_tests.rs");
    include!("rfc5280_presentation_interval_tests.rs");
    include!("rfc5280_key_output_tests.rs");
    include!("rfc5280_spki_output_tests.rs");
    include!("rfc5280_variable_output_tests.rs");
    include!("rfc5280_projection_serial_tests.rs");
    include!("rfc5280_projection_disclosure_tests.rs");
    include!("rfc5280_name_policy_tests.rs");
    include!("rfc5280_name_values_tests.rs");
    include!("rfc5280_private_output_tests.rs");
    fn challenges_v1() -> ZkX509Rfc5280StarkChallengesV1 {
        ZkX509Rfc5280StarkChallengesV1 {
            tuple: core::array::from_fn(|lane| {
                core::array::from_fn(|slot| {
                    F(u64::try_from(10_000 + lane * 100 + slot).expect("challenge fits"))
                })
            }),
        }
    }
    fn der_challenges_v1() -> ZkX509DerStarkChallengesV1 {
        ZkX509DerStarkChallengesV1 {
            tuple: core::array::from_fn(|lane| {
                core::array::from_fn(|slot| {
                    F(u64::try_from(20_000 + lane * 100 + slot).expect("challenge fits"))
                })
            }),
            byte_lookup: core::array::from_fn(|lane| {
                F(u64::try_from(30_000 + lane).expect("challenge fits"))
            }),
        }
    }
    fn terminal_claims_v1() -> ZkX509Rfc5280StarkTerminalClaimsV1 {
        ZkX509Rfc5280StarkTerminalClaimsV1::canonical_identity_v1()
    }
    fn nontrivial_terminal_claims_v1() -> ZkX509Rfc5280StarkTerminalClaimsV1 {
        let mut claims = terminal_claims_v1();
        for (index, role) in claims.output_roles.iter_mut().enumerate() {
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                role.consumer_products[lane] = F(2_000 + (index * 100 + lane) as u64);
            }
        }
        claims
    }
    fn terminal_aux_v1(claims: ZkX509Rfc5280StarkTerminalClaimsV1) -> ZkX509Rfc5280StarkAuxRowV1 {
        let mut aux = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
        for (role_index, role) in OUTPUT_ROLES_V1.into_iter().enumerate() {
            let products = claims
                .output_role_products_v1(role)
                .map(|claim| claim.consumer_products)
                .unwrap_or(core::array::from_fn(|lane| {
                    F(4_000 + (role_index * 100 + lane) as u64)
                }));
            for consumer in [false, true] {
                for (lane, product) in products.into_iter().enumerate() {
                    aux[output_role_aux_column_v1(role_index, consumer, lane)] = product;
                }
            }
        }
        aux
    }
    fn p256_bus_terminal_claims_v1(signature: usize) -> P256BusTerminalClaimsV1 {
        let family = |family: usize| -> [F; P256_CROSS_TRACE_LANES_V1] {
            core::array::from_fn(|lane| {
                F(10_000
                    + u64::try_from(signature * 1_000 + family * 10 + lane)
                        .expect("fixture P-256 bus value fits u64"))
            })
        };
        let value = family(0);
        let arithmetic_copy = family(1);
        let arithmetic_scalar = family(2);
        let window_scalar = family(3);
        P256BusTerminalClaimsV1 {
            value_execution: value,
            value_sorted: value,
            value_arithmetic_copy: arithmetic_copy,
            arithmetic_value_copy: arithmetic_copy,
            arithmetic_scalar,
            window_scalar,
            scalar_bus_arithmetic: arithmetic_scalar,
            scalar_bus_window: window_scalar,
        }
    }
    fn p256_certificate_terminal_claims_v1(
        signature: usize,
    ) -> ZkX509P256CertificatePrivateProductsV1 {
        let mut running = [F::ONE; P256_CROSS_TRACE_LANES_V1];
        let cross_sources = core::array::from_fn(|role| {
            let terminal = core::array::from_fn(|lane| {
                F(100_000
                    + u64::try_from(signature * 1_000 + role * 10 + lane)
                        .expect("fixture P-256 cross value fits u64"))
            });
            let claim = P256CrossTraceTerminalClaimV1 {
                role: P256_CERTIFICATE_CROSS_ROLES_V1[role],
                start: running,
                terminal,
            };
            running = terminal;
            claim
        });
        ZkX509P256CertificatePrivateProductsV1 {
            buses: p256_bus_terminal_claims_v1(signature),
            cross_sources,
            sink: running,
        }
    }
    fn p256_wallet_terminal_claims_v1() -> ZkX509P256WalletPrivateProductsV1 {
        let signature = P256_X5S1_SIGNATURES_V1 - 1;
        let mut running = [F::ONE; P256_CROSS_TRACE_LANES_V1];
        let cross_sources = core::array::from_fn(|role| {
            let terminal = core::array::from_fn(|lane| {
                F(100_000
                    + u64::try_from(signature * 1_000 + role * 10 + lane)
                        .expect("fixture P-256 cross value fits u64"))
            });
            let claim = P256CrossTraceTerminalClaimV1 {
                role: P256_WALLET_CROSS_ROLES_V1[role],
                start: running,
                terminal,
            };
            running = terminal;
            claim
        });
        ZkX509P256WalletPrivateProductsV1 {
            buses: p256_bus_terminal_claims_v1(signature),
            cross_sources,
            sink: running,
        }
    }
    fn p256_terminal_claims_v1() -> ZkX509P256PrivateProductsV1 {
        ZkX509P256PrivateProductsV1::from_p256_air_terminals_v1(
            core::array::from_fn(p256_certificate_terminal_claims_v1),
            p256_wallet_terminal_claims_v1(),
        )
        .expect("canonical five-signature P-256 AIR terminals")
    }
    #[test]
    fn key_join_rows_match_all_fixed_producer_bytes_and_selector_for_every_disclosure_count() {
        for count in 0..=4 {
            let mut shape = ZkX509Rfc5280StarkShapeV1::default();
            shape.disclosed_attribute_count = count;
            shape.disclosed_attribute_indices = core::array::from_fn(|index| {
                if index < usize::from(count) {
                    index as u8
                } else {
                    0
                }
            });
            let (rows, channels, value, activity) = zk_x509_rfc_key_join_rows_v1(shape).unwrap();
            assert_eq!(value, BASE_VALUE);
            assert_eq!(activity, BASE_CERT2_ACTIVE);
            let fixed = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
            for index in 0..6 {
                let length = if index < 5 { 65 } else { 1 };
                for offset in 0..length {
                    let row = fixed.fixed_row(rows[index] + offset).unwrap();
                    assert_eq!(
                        row[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize],
                        F::ONE
                    );
                    assert_eq!(row[FIX_EXPECTED + 1], F(u64::from(channels[index])));
                    assert_eq!(row[FIX_EXPECTED + 4], F(offset as u64));
                    assert_eq!(row[FIX_EXPECTED + 5], F::ONE);
                    assert_eq!(row[FIX_REQUIRED_ACTIVE], F::ONE);
                }
                assert_ne!(
                    fixed.fixed_row(rows[index] + length).unwrap()[FIX_EXPECTED + 1],
                    F(u64::from(channels[index]))
                );
            }
        }
        let mut invalid = ZkX509Rfc5280StarkShapeV1::default();
        invalid.disclosed_attribute_count = 5;
        assert!(matches!(
            zk_x509_rfc_key_join_rows_v1(invalid),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        ));
    }

    pub(super) fn canonical_trace_v1() -> ZkX509Rfc5280TraceV1 {
        let fixture = fixture();
        build_zk_x509_rfc5280_trace_v1(
            &fixture.witness.certificate_chain_der,
            &fixture.witness.crl_der,
            ZkX509Rfc5280StatementV1 {
                presentation_not_before_unix_seconds: fixture
                    .statement
                    .presentation_not_before_unix_seconds,
                presentation_not_after_unix_seconds: fixture
                    .statement
                    .presentation_not_after_unix_seconds,
                leaf_key_usage: 1,
                leaf_extended_key_usages: vec![ZkX509DerEkuV1::ClientAuthentication],
                crl_number: fixture.crl.crl_number,
                disclosed_attribute_indices: fixture
                    .statement
                    .disclosed_attributes
                    .iter()
                    .map(|attribute| attribute.index)
                    .collect(),
            },
        )
        .expect("canonical RFC trace")
    }
    #[test]
    fn owned_rfc_numeric_sources_clear_success_error_unwind_and_displaced_rows() {
        use super::super::private_table::inspection;
        let trace = canonical_trace_v1();
        let original = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let expected_fields = original
            .family_rows
            .iter()
            .map(source_rows::FamilyRowsV1::initialized_cells_v1)
            .sum::<usize>();
        assert!(expected_fields > 0);
        for mode in 0..3 {
            let material = original.clone();
            let (result, observed) = inspection::observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut material = material;
                    if mode == 0 {
                        material.zeroize_private_v1();
                        assert!(material.private_is_zeroized_v1());
                        assert_eq!(material.schedule, original.schedule);
                        Ok(())
                    } else if mode == 1 {
                        Err(())
                    } else {
                        panic!("injected RFC numeric source unwind")
                    }
                }))
            });
            assert_eq!(result.is_err(), mode == 2);
            assert!(observed.iter().map(|item| item.cells).sum::<usize>() >= expected_fields);
            assert!(observed.iter().any(|item| item.nonzero_before > 0));
            assert!(observed.iter().all(|item| item.nonzero_after == 0));
        }
        let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
        rows.try_reserve_exact(1).unwrap();
        rows.push([F(29); ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]);
        let first = rows.as_ptr();
        let ((), observed) = inspection::observe_v1(|| {
            push_family_row_v1(&mut rows, [F(31); ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]).unwrap();
            assert_ne!(rows.as_ptr(), first);
            assert_eq!(rows[0], [F(29); ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]);
            assert_eq!(rows[1], [F(31); ZK_X509_RFC5280_STARK_BASE_WIDTH_V1]);
        });
        assert_eq!(
            observed
                .iter()
                .map(|item| item.nonzero_before)
                .sum::<usize>(),
            ZK_X509_RFC5280_STARK_BASE_WIDTH_V1
        );
        assert!(observed.iter().all(|item| item.nonzero_after == 0));
        let retained = rows.clone();
        assert!(ensure_family_slot_v1(&mut rows, usize::MAX).is_err());
        assert_eq!(&**rows, &retained);
        // Ordinary error and unwinding after partial family writes still drop
        // the same guarded allocation used by the production compiler.
        for unwind in [false, true] {
            let (result, observed) = inspection::observe_v1(|| {
                std::panic::catch_unwind(|| {
                    let mut rows = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1);
                    push_family_row_v1(&mut rows, [F(37); ZK_X509_RFC5280_STARK_BASE_WIDTH_V1])
                        .unwrap();
                    if unwind {
                        panic!("injected RFC partial-family unwind");
                    }
                    ensure_family_slot_v1(&mut rows, usize::MAX)
                })
            });
            assert_eq!(result.is_err(), unwind);
            if !unwind {
                assert!(result.unwrap().is_err());
            }
            assert_eq!(
                observed
                    .iter()
                    .map(|item| item.nonzero_before)
                    .sum::<usize>(),
                ZK_X509_RFC5280_STARK_BASE_WIDTH_V1
            );
            assert!(observed.iter().all(|item| item.nonzero_after == 0));
        }
    }
    fn neutral_aux_v1() -> ZkX509Rfc5280StarkAuxRowV1 {
        let mut aux = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
        aux[AUX_DER_BYTE_BEFORE..AUX_PROFILE_LOOKUP_ACCUMULATOR].fill(F::ONE);
        aux[AUX_SHA_UNION_CENTERS..AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR].fill(F::ONE);
        aux[AUX_GRAMMAR_ORDINAL_SOURCE_BEFORE..AUX_NUMERIC_INVERSE].fill(F::ONE);
        aux
    }
    fn normalized_row_v1(
        mut row: ZkX509Rfc5280StarkBaseRowV1,
        fixed: &ZkX509Rfc5280StarkFixedRowV1,
    ) -> ZkX509Rfc5280StarkBaseRowV1 {
        populate_degree_normalization_helpers_v1(&mut row, fixed);
        row
    }
    fn serial_comparator_aux_v1(
        current: &ZkX509Rfc5280StarkBaseRowV1,
    ) -> (ZkX509Rfc5280StarkAuxRowV1, ZkX509Rfc5280StarkAuxRowV1) {
        let challenges = challenges_v1();
        let mut current_aux = neutral_aux_v1();
        let mut next_aux = neutral_aux_v1();
        for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
            let factor = normalized_copy_factor_v1(current, lane, challenges);
            let after = F::ONE.add(current[BASE_COPY_CONSUMER_ACTIVE].mul(factor.sub(F::ONE)));
            current_aux[AUX_SERIAL_CONSUMER_AFTER + lane] = after;
            next_aux[AUX_SERIAL_CONSUMER_BEFORE + lane] = after;
        }
        (current_aux, next_aux)
    }
    fn serial_source_aux_v1(
        current: &ZkX509Rfc5280StarkBaseRowV1,
        challenges: ZkX509Rfc5280StarkChallengesV1,
    ) -> (ZkX509Rfc5280StarkAuxRowV1, ZkX509Rfc5280StarkAuxRowV1) {
        let mut current_aux = neutral_aux_v1();
        let mut next_aux = neutral_aux_v1();
        for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
            let factor = normalized_copy_factor_v1(current, lane, challenges);
            let source = F::ONE.add(current[BASE_COPY_SOURCE_ACTIVE].mul(factor.sub(F::ONE)));
            current_aux[AUX_SERIAL_SOURCE_AFTER + lane] = source;
            next_aux[AUX_SERIAL_SOURCE_BEFORE + lane] = source;
            if current[BASE_IS_WRITE] == F::ONE {
                let factor = serial_byte_lookup_factor_v1(
                    current[BASE_DOCUMENT],
                    current[BASE_ADDRESS],
                    current[SERIAL_SOURCE_QUERY_VALUE],
                    lane,
                    challenges,
                );
                if factor == F::ZERO {
                    current_aux[AUX_SERIAL_BYTE_QUERY_ZERO + lane] = F::ONE;
                    next_aux[AUX_SERIAL_BYTE_ZERO_ACCUMULATOR + lane] = F::ZERO.sub(F::ONE);
                } else {
                    let inverse = factor.inv().expect("nonzero byte lookup factor");
                    current_aux[AUX_SERIAL_BYTE_QUERY_INVERSE + lane] = inverse;
                    next_aux[AUX_SERIAL_BYTE_LOOKUP_ACCUMULATOR + lane] = F::ZERO.sub(inverse);
                }
            }
            let node_factor = serial_node_lookup_factor_v1(current, lane, challenges);
            if node_factor == F::ZERO {
                current_aux[AUX_SERIAL_NODE_QUERY_ZERO + lane] = F::ONE;
                next_aux[AUX_SERIAL_NODE_ZERO_ACCUMULATOR + lane] = F::ZERO.sub(F::ONE);
            } else {
                let node_inverse = node_factor.inv().expect("nonzero node lookup factor");
                current_aux[AUX_SERIAL_NODE_QUERY_INVERSE + lane] = node_inverse;
                next_aux[AUX_SERIAL_NODE_LOOKUP_ACCUMULATOR + lane] = F::ZERO.sub(node_inverse);
            }
        }
        (current_aux, next_aux)
    }
    pub(super) fn serial_source_fixture_v1(
        logical_id: u16,
        magnitude: &[u8],
    ) -> ZkX509Rfc5280SerialSourceV1 {
        let sign_padding = magnitude[0] & 0x80 != 0;
        let mut encoded = Vec::new();
        if sign_padding {
            encoded.push(0);
        }
        encoded.extend_from_slice(magnitude);
        let content_start = 100_u16;
        let content_end = content_start + u16::try_from(encoded.len()).expect("fixture length");
        let (document, role, role_instance) = if logical_id == 0 {
            (0, ZkX509Rfc5280GrammarRoleV1::CertificateSerial, 0)
        } else {
            (
                2,
                ZkX509Rfc5280GrammarRoleV1::CrlEntrySerial,
                logical_id - 1,
            )
        };
        ZkX509Rfc5280SerialSourceV1 {
            logical_id,
            node: ZkX509Rfc5280NodeProvenanceV1 {
                document,
                node: 7 + logical_id,
                parent_node: 2,
                child_ordinal: 1,
                start: 98,
                content_start,
                content_end,
                depth: 2,
                tag_class: 0,
                constructed: false,
                tag_number: 2,
                role,
                role_instance,
            },
            frame: serial_frame_v1(magnitude).expect("fixture frame"),
            encoded_contents: encoded
                .into_iter()
                .enumerate()
                .map(|(offset, value)| ZkX509Rfc5280SourceCellV1 {
                    document,
                    address: content_start + u16::try_from(offset).expect("fixture offset"),
                    value,
                })
                .collect(),
        }
    }
    fn maximum_private_shape_v1() -> ZkX509Rfc5280StarkPrivateShapeV1 {
        let mut embedded_lengths = [0_u16; ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1];
        embedded_lengths[..14].fill(1_092);
        embedded_lengths[14] = 1_096;
        ZkX509Rfc5280StarkPrivateShapeV1 {
            chain_depth: 3,
            certificate_slot_2_active: F::ONE,
            top_document_count: 4,
            top_document_lengths: [4_096; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1],
            top_node_counts: [2_048; ZK_X509_DER_AIR_MAX_DOCUMENTS_V1],
            embedded_document_count: 15,
            embedded_document_lengths: embedded_lengths,
            embedded_node_counts: [2_048; ZK_X509_DER_AIR_MAX_EMBEDDED_DOCUMENTS_V1],
            crl_entries: 64,
            disclosed_attributes: 4,
            embedded_copy_rows: copy_census::EMBEDDED_ROWS as u32,
            grammar_rows: u32::try_from(
                ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1 + MAX_SOURCE_NODES_V1
                    - MAX_SOURCE_DOCUMENTS_V1,
            )
            .expect("grammar row bound fits u32"),
            name_value_rows: name_values::ROWS as u32,
            fixed_byte_rows: 16_384,
            equality_rows: copy_census::EQUALITY_ROWS as u32,
            decimal_rows: FIXED_DECIMAL_ROWS_V1 as u32,
            calendar_rows: 72 * CALENDAR_COPY_PHASES_V1 as u32,
            relation_rows: FIXED_RELATION_ROWS_V1 as u32,
            basic_constraints_rows: 256,
            serial_source_rows: u32::try_from(MAX_SERIAL_SOURCE_ROWS_V1)
                .expect("serial source bound fits u32"),
            serial_rows: u32::try_from(MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1)
                .expect("serial bound fits u32"),
            range_rows: FIXED_RANGE_ROWS_V1 as u32,
            semantic_source_rows: 18_203,
            semantic_consumer_rows: copy_census::CONSUMER_ROWS as u32,
            output_producer_rows: 22_705,
            output_consumer_rows: 22_705,
            io_channels: 1,
        }
    }
    fn refresh_private_shape_derived_rows_v1(shape: &mut ZkX509Rfc5280StarkPrivateShapeV1) {
        let top_count = usize::from(shape.top_document_count);
        let embedded_count = usize::from(shape.embedded_document_count);
        shape.embedded_copy_rows = copy_census::active_rows(
            ZkX509Rfc5280StarkFamilyV1::EmbeddedCopy,
            shape.chain_depth == 3,
        ) as u32;
        shape.equality_rows = copy_census::active_rows(
            ZkX509Rfc5280StarkFamilyV1::EqualByte,
            shape.chain_depth == 3,
        ) as u32;
        shape.semantic_consumer_rows = copy_census::active_rows(
            ZkX509Rfc5280StarkFamilyV1::SemanticConsumer,
            shape.chain_depth == 3,
        ) as u32;
        shape.grammar_rows = u32::try_from(
            shape
                .source_nodes()
                .expect("fixture source-node count")
                .checked_sub(top_count + embedded_count)
                .and_then(|rows| rows.checked_add(ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1))
                .expect("fixture grammar rows"),
        )
        .expect("fixture grammar rows fit");
        shape.calendar_rows = u32::try_from(
            (2 * usize::from(shape.chain_depth) + 2 + usize::from(shape.crl_entries))
                * CALENDAR_COPY_PHASES_V1,
        )
        .expect("fixture calendar rows fit");
        let serial_rows = serial_comparison_rows_v1(usize::from(shape.crl_entries));
        shape.serial_source_rows =
            u32::try_from(serial_rows * 2).expect("fixture serial-source rows fit");
        shape.serial_rows = u32::try_from(serial_rows * SERIAL_COMPARISON_PHASES_V1)
            .expect("fixture serial rows fit");
    }
    #[test]
    fn exact_private_maximum_and_fixed_public_geometry_fit_log19() {
        let descriptor: [u8; 32] = Sha256::digest(ZK_X509_RFC5280_STARK_DESCRIPTOR_V1).into();
        assert_eq!(descriptor, ZK_X509_RFC5280_STARK_DESCRIPTOR_SHA256_V1);
        assert!(
            ZK_X509_RFC5280_STARK_DESCRIPTOR_V1.ends_with(b":standalone-activation=not-applicable")
        );
        let shape = maximum_private_shape_v1();
        shape.validate().expect("exact conservative maximum");
        assert_eq!(MAX_OUTPUT_EVENT_ROWS_V1, 45_410);
        assert_eq!(MAX_ACTIVE_ROWS_V1, 246_673);
        assert_eq!(FIXED_NON_PADDING_ROWS_V1, 292_206);
        assert_eq!(
            shape.active_rows().expect("active rows")
                + (FIXED_EMBEDDED_COPY_ROWS_V1 - copy_census::EMBEDDED_ROWS)
                + (18_203 - copy_census::CONSUMER_ROWS - copy_census::EQUALITY_ROWS),
            MAX_ACTIVE_ROWS_V1
        );
        assert!(MAX_ACTIVE_ROWS_V1 < ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("schedule");
        assert_eq!(
            schedule.counts.iter().sum::<usize>(),
            ZK_X509_RFC5280_STARK_TRACE_SIZE_V1
        );
        let mut overflow = shape;
        overflow.output_producer_rows = 22_706;
        assert_eq!(
            usize::try_from(overflow.output_producer_rows).expect("fits")
                + usize::try_from(overflow.output_consumer_rows).expect("fits"),
            45_411
        );
        assert!(overflow.validate().is_err());
    }
    #[test]
    fn grammar_asset_preserves_every_rule_and_index() {
        assert_eq!(ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1, 86);
        assert_eq!(ZK_X509_RFC5280_GRAMMAR_RULE_BYTES_V1.len(), 2_236);
        assert_eq!(ZK_X509_RFC5280_GRAMMAR_RULES_V1.len(), 86);
        let mut encoded = Vec::with_capacity(ZK_X509_RFC5280_GRAMMAR_RULE_BYTES_V1.len());
        for rule in ZK_X509_RFC5280_GRAMMAR_RULES_V1 {
            encoded.extend_from_slice(&rule.parent_role.to_le_bytes());
            encoded.extend_from_slice(&rule.child_role.to_le_bytes());
            encoded.push(rule.tag_class);
            encoded.push(u8::from(rule.constructed));
            encoded.extend_from_slice(&rule.tag_number.to_le_bytes());
            encoded.push(u8::from(rule.ordinal_exact));
            encoded.push(u8::from(rule.ordinal_last));
            encoded.extend_from_slice(&rule.ordinal_parameter.to_le_bytes());
            encoded.push(u8::from(rule.count_exact));
            encoded.extend_from_slice(&rule.count_parameter.to_le_bytes());
            encoded.extend_from_slice(&rule.quotient_scale.to_le_bytes());
            encoded.extend_from_slice(&rule.remainder_scale.to_le_bytes());
            encoded.extend_from_slice(&rule.ordinal_scale.to_le_bytes());
            encoded.extend_from_slice(&rule.constant.to_le_bytes());
            encoded.push(rule.root_kind);
        }
        assert_eq!(encoded.as_slice(), ZK_X509_RFC5280_GRAMMAR_RULE_BYTES_V1);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&encoded)),
            [
                0x2c, 0xf3, 0xcc, 0xbd, 0x80, 0x83, 0x38, 0x42, 0x86, 0xfe, 0x74, 0x27, 0x42, 0x7a,
                0xc0, 0x39, 0x00, 0x31, 0x0b, 0x68, 0xe5, 0x51, 0xa0, 0xb0, 0x34, 0x57, 0x20, 0xf4,
                0xe1, 0x47, 0xe1, 0xe6,
            ]
        );
    }
    #[test]
    fn certificate_extension_grammar_accepts_only_closed_profile_cardinalities() {
        let extension = ZkX509Rfc5280NodeProvenanceV1 {
            document: 0,
            node: 1,
            parent_node: 0,
            child_ordinal: 0,
            start: 0,
            content_start: 2,
            content_end: 4,
            depth: 1,
            tag_class: 0,
            constructed: true,
            tag_number: 16,
            role: ZkX509Rfc5280GrammarRoleV1::CertificateExtension,
            role_instance: 0,
        };
        let parent_role = ZkX509Rfc5280GrammarRoleV1::CertificateExtensions as u16;
        let four = grammar_rule_index_for_node_v1(extension, parent_role, 0, 4)
            .expect("CA certificate has four mandatory extensions");
        let five = grammar_rule_index_for_node_v1(extension, parent_role, 0, 5)
            .expect("leaf certificate adds the required EKU extension");
        assert_ne!(four, five);
        for unsupported_count in [0, 1, 2, 3, 6, u16::MAX] {
            assert_eq!(
                grammar_rule_index_for_node_v1(extension, parent_role, 0, unsupported_count),
                Err(ZkX509Rfc5280StarkErrorV1::Grammar),
                "extension count {unsupported_count} is outside the closed profile"
            );
        }
    }

    #[test]
    fn private_output_role_preflight_preserves_every_original_source_admission_fence() {
        let mut material =
            build_zk_x509_rfc5280_stark_base_material_v1(&canonical_trace_v1()).unwrap();
        let mut seen = [[false; 9]; 2];
        for row_index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
            let (family, _) = material.schedule.family_and_ordinal(row_index).unwrap();
            if !matches!(
                family,
                ZkX509Rfc5280StarkFamilyV1::OutputProducer
                    | ZkX509Rfc5280StarkFamilyV1::OutputConsumer
            ) {
                continue;
            }
            let row = material.base_row(row_index).unwrap();
            if row[BASE_ACTIVE] != F::ONE {
                continue;
            }
            let fixed = material.fixed_row(row_index).unwrap();
            let consumer = family == ZkX509Rfc5280StarkFamilyV1::OutputConsumer;
            let role = selected_output_role_preflight_v1(&row, &fixed, consumer).unwrap();
            let endpoint = output_endpoint_index_v1(consumer);
            if seen[endpoint][role] {
                continue;
            }
            seen[endpoint][role] = true;
            let mut wrong = row;
            wrong[BASE_ROLE] = F(((role + 1) % 9 + 1) as u64);
            assert_eq!(
                selected_output_role_preflight_v1(&wrong, &fixed, consumer),
                Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
            );
            for malformed in [F::ZERO, F(2), F(GOLDILOCKS_MODULUS_V1)] {
                let mut changed = fixed;
                changed[output_role_fixed_selector_column_v1(role, consumer)] = malformed;
                assert_eq!(
                    selected_output_role_preflight_v1(&row, &changed, consumer),
                    Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
                );
            }
            let mut duplicate = fixed;
            duplicate[output_role_fixed_selector_column_v1((role + 1) % 9, consumer)] = F::ONE;
            assert_eq!(
                selected_output_role_preflight_v1(&row, &duplicate, consumer),
                Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
            );
        }
        assert!(seen.iter().flatten().all(|value| *value));
        // A malformed active private producer cannot be ignored merely because
        // it contributes no public governed-root record. The real compiler must
        // preserve its original fail-fast source rejection before encoding.
        let family = ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize;
        let row = material.family_rows[family].iter_mut().next().unwrap();
        assert_eq!(row[BASE_ACTIVE], F::ONE);
        row[BASE_ROLE] = F::ZERO;
        assert_eq!(
            compile_zk_x509_rfc5280_stark_terminal_claims_v1(
                &material,
                der_challenges_v1(),
                challenges_v1()
            ),
            Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
        );
    }
    #[test]
    fn rfc_role_air_bindings_reject_one_sided_coordinated_and_compensating_mutations() {
        let claims = nontrivial_terminal_claims_v1();
        let final_aux = terminal_aux_v1(claims);
        let evaluate = |aux: &ZkX509Rfc5280StarkAuxRowV1, claims| {
            evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, aux, claims).unwrap()
        };
        for role in 0..OUTPUT_ROLE_COUNT_V1 {
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                let mut changed = final_aux;
                changed[output_role_aux_column_v1(role, false, lane)] =
                    changed[output_role_aux_column_v1(role, false, lane)].add(F::ONE);
                assert_ne!(evaluate(&changed, claims)[role * 4 + lane], F::ZERO);
            }
        }
        let multiplier = F(7);
        let inverse = multiplier.inv().unwrap();
        // Two private SHA-consumer changes preserve their aggregate and the
        // four-role SHA union. Each still violates its normalized producer join.
        let mut changed = final_aux;
        let roles = [
            ZkX509Rfc5280OutputRoleV1::CertificateTbsSha,
            ZkX509Rfc5280OutputRoleV1::CrlTbsP256Message,
        ];
        let columns =
            roles.map(|role| output_role_aux_column_v1(output_role_index_v1(role), true, 2));
        for (column, factor) in columns.into_iter().zip([multiplier, inverse]) {
            changed[column] = changed[column].mul(factor);
        }
        assert_eq!(
            final_aux[columns[0]].mul(final_aux[columns[1]]),
            changed[columns[0]].mul(changed[columns[1]])
        );
        assert_eq!(
            evaluate(&changed, claims)
                .iter()
                .filter(|value| **value != F::ZERO)
                .count(),
            2
        );
        let mut wrong_role = claims;
        wrong_role.output_roles[0].role = ZkX509Rfc5280OutputRoleV1::CertificateSlotActive;
        assert_eq!(
            wrong_role.validate_v1(),
            Err(ZkX509Rfc5280StarkErrorV1::TerminalClaim)
        );
        // Optional-slot products have no public slot. Swapping a private
        // consumer with another role is still rejected by the private joins.
        let mut wrong_slot = final_aux;
        for lane in 0..4 {
            wrong_slot.swap(
                output_role_aux_column_v1(0, true, lane),
                output_role_aux_column_v1(8, true, lane),
            );
        }
        assert_eq!(
            evaluate(&wrong_slot, claims)
                .iter()
                .filter(|value| **value != F::ZERO)
                .count(),
            8
        );
        // A coordinated change to both endpoints requires changing the trace
        // recurrence. It cannot be rejected by an endpoint equality alone.
        let mut coordinated = final_aux;
        for endpoint in [false, true] {
            coordinated[output_role_aux_column_v1(0, endpoint, 0)] = F(42);
        }
        assert!(
            evaluate(&coordinated, claims)
                .iter()
                .all(|value| *value == F::ZERO)
        );
        // At the actual preceding native row, paired endpoint substitutions
        // cannot jump both products past their independent recurrences.
        // Include private Projection and CertificateSlotActive, which have
        // no public claim, and also update public claims for exported roles.
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .unwrap();
        let fixed = schedule
            .fixed_row(ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 2)
            .unwrap();
        assert_eq!(fixed[FIX_CONTINUE], F::ONE);
        let row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        let start = RFC5280_RESIDUE_SECTIONS_V1[..14]
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>();
        let end = start + RFC5280_RESIDUE_SECTIONS_V1[14].1;
        let recurrence = |next_aux: &ZkX509Rfc5280StarkAuxRowV1, changed_claims| {
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &row,
                &row,
                &final_aux,
                next_aux,
                &fixed,
                der_challenges_v1(),
                challenges_v1(),
                changed_claims,
            )
            .unwrap()[start..end]
                .to_vec()
        };
        assert!(
            recurrence(&final_aux, claims)
                .iter()
                .all(|value| *value == F::ZERO)
        );
        for role in 0..OUTPUT_ROLE_COUNT_V1 {
            for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                let mut next_aux = final_aux;
                for endpoint in [false, true] {
                    let column = output_role_aux_column_v1(role, endpoint, lane);
                    next_aux[column] = next_aux[column].add(F::ONE);
                }
                let mut changed_claims = claims;
                if let Some(index) = PUBLIC_OUTPUT_ROLES_V1
                    .iter()
                    .position(|value| output_role_index_v1(*value) == role)
                {
                    changed_claims.output_roles[index].consumer_products[lane] =
                        changed_claims.output_roles[index].consumer_products[lane].add(F::ONE);
                }
                assert!(
                    evaluate(&next_aux, changed_claims)
                        .iter()
                        .all(|value| *value == F::ZERO)
                );
                let residues = recurrence(&next_aux, changed_claims);
                assert_eq!(
                    residues.iter().filter(|value| **value != F::ZERO).count(),
                    2
                );
                for endpoint in [false, true] {
                    let index = ((role * OUTPUT_ENDPOINT_COUNT_V1
                        + output_endpoint_index_v1(endpoint))
                        * ZK_X509_RFC5280_STARK_BUS_LANES_V1
                        + lane)
                        * 2;
                    assert_eq!(
                        residues[index],
                        F::ONE,
                        "role {role}, endpoint {endpoint}, lane {lane}"
                    );
                    assert_eq!(residues[index + 1], F::ZERO);
                }
            }
        }
    }
    #[test]
    fn private_der_rfc_native_endpoints_preserve_handoff_and_local_binding() {
        use crate::privacy_engines::zk_x509::der_stark::{
            build_zk_x509_der_stark_base_v1, build_zk_x509_der_stark_trace_v1,
            zk_x509_der_stark_terminal_claims_v1,
        };
        let trace = canonical_trace_v1();
        let documents = source_documents_v1(&trace)
            .map(|document| {
                document
                    .bytes
                    .iter()
                    .map(|byte| {
                        u8::try_from(byte.value.value.0).expect("canonical native DER byte")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let documents_ref = documents.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let der_trace = build_zk_x509_der_stark_trace_v1(
            build_zk_x509_der_stark_base_v1(&documents_ref)
                .expect("same complete DER document order"),
            der_challenges_v1(),
        )
        .expect("independent strict-DER native owner");
        let der = zk_x509_der_stark_terminal_claims_v1(&der_trace).unwrap();
        let der_fields = [der.input_byte, der.node].concat();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let provider = ZkX509Rfc5280StarkColumnProviderV1::with_centers_v1(
            &material,
            der_challenges_v1(),
            challenges_v1(),
            ZkX509ShaUnionCentersV1::identity_fixture_v1(),
        )
        .unwrap();
        let claims = provider.terminal_claims_v1().unwrap();
        let columns = zk_x509_rfc_der_terminal_columns_v1();
        assert_eq!(columns.len(), 8);
        assert_eq!(
            columns
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8
        );
        let last = ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 1;
        let mut final_aux = terminal_aux_v1(claims);
        for (slot, after) in columns.into_iter().enumerate() {
            let values = PrivateTableV1::new(
                provider.build_aux_column_v1(after).unwrap(),
                zeroize_fields_v1,
            );
            let before = PrivateTableV1::new(
                provider.build_aux_column_v1(after - 4).unwrap(),
                zeroize_fields_v1,
            );
            assert_eq!(values.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
            assert!(values.iter().all(|value| F::canonical(value.0).is_some()));
            assert_eq!(values[last], der_fields[slot]);
            final_aux[after] = values[last];
            final_aux[after - 4] = before[last];
        }
        let native_fields = columns.map(|column| final_aux[column]);
        assert_eq!(native_fields.as_slice(), der_fields.as_slice());
        let local_start = RFC5280_RESIDUE_SECTIONS_V1[..12]
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>();
        let local_end = local_start + 24;
        let local = |aux: &ZkX509Rfc5280StarkAuxRowV1| {
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &material.base_row(last).unwrap(),
                &material.base_row(0).unwrap(),
                aux,
                &neutral_aux_v1(),
                &material.fixed_row(last).unwrap(),
                der_challenges_v1(),
                challenges_v1(),
                claims,
            )
            .unwrap()[local_start..local_end]
                .to_vec()
        };
        assert!(local(&final_aux).iter().all(|residue| *residue == F::ZERO));
        for (slot, column) in columns.into_iter().enumerate() {
            let mut wrong_der = der_fields.clone();
            wrong_der[slot] = wrong_der[slot].add(F::ONE);
            assert_ne!(native_fields.as_slice(), wrong_der.as_slice());
            let mut wrong_rfc = final_aux;
            wrong_rfc[column] = wrong_rfc[column].add(F::ONE);
            assert_ne!(
                columns.map(|column| wrong_rfc[column]).as_slice(),
                der_fields.as_slice()
            );
            assert!(
                local(&wrong_rfc).iter().any(|residue| *residue != F::ZERO),
                "private endpoint {slot} stays bound to the native before/after recurrence"
            );
            assert!(
                evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, &wrong_rfc, claims)
                    .unwrap()
                    .iter()
                    .all(|residue| *residue == F::ZERO),
                "the public output frame does not expose a private DER endpoint"
            );
            // A coordinated equality alone passes. The local recurrence still
            // rejects it; the real cross-registration relation is tested by MAIN.
            assert_eq!(
                columns.map(|column| wrong_rfc[column]).as_slice(),
                wrong_der.as_slice()
            );
            assert!(local(&wrong_rfc).iter().any(|residue| *residue != F::ZERO));
            zeroize_fields_v1(&mut wrong_rfc);
            zeroize_fields_v1(&mut wrong_der);
        }
        assert!(F::canonical(GOLDILOCKS_MODULUS_V1).is_none());
        zeroize_fields_v1(&mut final_aux);
    }

    #[test]
    fn private_p256_product_owner_preserves_all_fields_roles_and_zero_factors() {
        let products = p256_terminal_claims_v1();
        products.validate_air_terminals_v1().unwrap();
        assert_eq!(P256_TERMINAL_CLAIM_RECORDS_V1, 348);
        for index in 0..P256_TERMINAL_CLAIM_RECORDS_V1 {
            let original = products.claim_value_v1(index).unwrap();
            let mut changed = products;
            changed
                .set_claim_value_v1(index, original.add(F::ONE))
                .unwrap();
            let differences =
                evaluate_zk_x509_p256_terminal_claim_residues_v1(products, changed).unwrap();
            assert_eq!(
                differences
                    .iter()
                    .filter(|value| **value != F::ZERO)
                    .count(),
                1
            );
            assert_eq!(differences[index], F::ZERO.sub(F::ONE));
            let mut noncanonical = products;
            noncanonical.set_claim_value_v1(index, F(u64::MAX)).unwrap();
            assert!(noncanonical.validate_topology_v1().is_err());
        }
        for signature in 0..P256_X5S1_SIGNATURES_V1 {
            let (_, sources, _) = products.signature_parts_v1(signature).unwrap();
            for role_index in 0..sources.len() {
                let mut changed = products;
                let (_, mutable, _) = changed.signature_parts_mut_v1(signature).unwrap();
                mutable[role_index].role =
                    if mutable[role_index].role == P256CrossTraceTerminalRoleV1::WalletLowS {
                        P256CrossTraceTerminalRoleV1::ValueWriter
                    } else {
                        P256CrossTraceTerminalRoleV1::WalletLowS
                    };
                assert!(changed.validate_topology_v1().is_err());
            }
            let mut zero = products;
            let (buses, sources, sink) = zero.signature_parts_mut_v1(signature).unwrap();
            *buses = empty_p256_bus_terminal_claims_v1();
            for (index, source) in sources.iter_mut().enumerate() {
                source.start = if index == 0 {
                    [F::ONE; 4]
                } else {
                    [F::ZERO; 4]
                };
                source.terminal = [F::ZERO; 4];
            }
            *sink = [F::ZERO; 4];
            zero.validate_air_terminals_v1()
                .expect("zero product endpoints do not require division or abort");
        }
        assert_eq!(
            products.claim_value_v1(P256_TERMINAL_CLAIM_RECORDS_V1),
            None
        );
        let mut out_of_range = products;
        assert!(
            out_of_range
                .set_claim_value_v1(P256_TERMINAL_CLAIM_RECORDS_V1, F::ZERO)
                .is_err()
        );
        // MAIN's new private-link tests replace coordinated public-frame tampering:
        // there is no P-256 public frame or decoder left to mutate.
    }
    #[test]
    fn every_auxiliary_column_has_one_canonical_replay_descriptor() {
        for column in 0..ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 {
            let descriptors = [
                product_aux_column_descriptor_v1(column).is_some(),
                (AUX_SHA_UNION_CENTERS..AUX_SHA_UNION_CENTERS + 16).contains(&column),
                output_role_aux_column_descriptor_v1(column).is_some(),
                serial_product_aux_column_descriptor_v1(column).is_some(),
                grammar_ordinal_product_aux_column_descriptor_v1(column).is_some(),
                lookup_aux_column_descriptor_v1(column).is_some(),
                profile_lookup_aux_column_descriptor_v1(column).is_some(),
                grammar_lookup_aux_column_descriptor_v1(column).is_some(),
                (AUX_NUMERIC_INVERSE..ZK_X509_RFC5280_STARK_AUX_WIDTH_V1).contains(&column),
            ];
            assert_eq!(
                descriptors.into_iter().filter(|matched| *matched).count(),
                1,
                "auxiliary column {column} must have one replay equation"
            );
        }
        for column in [
            ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
            ZK_X509_RFC5280_STARK_AUX_WIDTH_V1 + 1,
            usize::MAX,
        ] {
            assert!(product_aux_column_descriptor_v1(column).is_none());
            assert!(output_role_aux_column_descriptor_v1(column).is_none());
            assert!(serial_product_aux_column_descriptor_v1(column).is_none());
            assert!(grammar_ordinal_product_aux_column_descriptor_v1(column).is_none());
            assert!(lookup_aux_column_descriptor_v1(column).is_none());
            assert!(profile_lookup_aux_column_descriptor_v1(column).is_none());
            assert!(grammar_lookup_aux_column_descriptor_v1(column).is_none());
        }
    }
    #[test]
    fn batched_native_base_replay_matches_every_row_and_bound_provider() {
        let trace = canonical_trace_v1();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let provider = ZkX509Rfc5280StarkColumnProviderV1::with_centers_v1(
            &material,
            der_challenges_v1(),
            challenges_v1(),
            ZkX509ShaUnionCentersV1::identity_fixture_v1(),
        )
        .unwrap();
        for first in [0, ZK_X509_RFC5280_STARK_BASE_WIDTH_V1 - 8] {
            let mut columns = (0..8)
                .map(|_| {
                    PrivateTableV1::new(
                        vec![F(97); ZK_X509_RFC5280_STARK_TRACE_SIZE_V1],
                        zeroize_fields_v1,
                    )
                })
                .collect::<Vec<_>>();
            {
                let mut targets = columns
                    .iter_mut()
                    .map(|column| column.as_mut_slice())
                    .collect::<Vec<_>>();
                material.fill_base_columns_v1(first, &mut targets).unwrap();
            }
            // The unchanged scalar path is an independent replay of one whole
            // selected column; all eight columns additionally match every row.
            let scalar = PrivateTableV1::new(
                material.build_base_column(first).unwrap(),
                zeroize_fields_v1,
            );
            assert_eq!(&*columns[0], &*scalar);
            for index in 0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 {
                let mut expected = material.base_row(index).unwrap();
                for (offset, column) in columns.iter().enumerate() {
                    assert_eq!(
                        column[index],
                        expected[first + offset],
                        "row {index}, column {}",
                        first + offset
                    );
                }
                zeroize_fields_v1(&mut expected);
            }
            // Bound replay has the same base values even after transcript
            // challenges exist; it must not accidentally return auxiliaries.
            let mut bound = PrivateTableV1::new(
                vec![F(98); ZK_X509_RFC5280_STARK_TRACE_SIZE_V1],
                zeroize_fields_v1,
            );
            provider
                .fill_base_columns_v1(first + 7, &mut [&mut bound])
                .unwrap();
            assert_eq!(&*bound, &*columns[7]);
        }
    }

    #[test]
    fn batched_native_base_replay_rejects_geometry_before_writing() {
        let trace = canonical_trace_v1();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace).unwrap();
        let mut valid = PrivateTableV1::new(
            vec![F(71); ZK_X509_RFC5280_STARK_TRACE_SIZE_V1],
            zeroize_fields_v1,
        );
        let mut short = [F(72); 3];
        assert_eq!(
            material.fill_base_columns_v1(0, &mut []),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        for first in [ZK_X509_RFC5280_STARK_BASE_WIDTH_V1, usize::MAX] {
            assert_eq!(
                material.fill_base_columns_v1(first, &mut [&mut valid]),
                Err(ZkX509Rfc5280StarkErrorV1::Shape)
            );
        }
        for first in [0, ZK_X509_RFC5280_STARK_BASE_WIDTH_V1 - 1] {
            assert_eq!(
                material.fill_base_columns_v1(first, &mut [&mut valid, &mut short]),
                Err(ZkX509Rfc5280StarkErrorV1::Shape)
            );
        }
        assert!(valid.iter().all(|value| *value == F(71)));
        assert_eq!(short, [F(72); 3]);
    }

    #[test]
    fn canonical_column_provider_replays_base_aux_and_private_products() {
        let trace = canonical_trace_v1();
        let material =
            build_zk_x509_rfc5280_stark_base_material_v1(&trace).expect("canonical base material");
        let der_challenges = der_challenges_v1();
        let challenges = challenges_v1();
        let provider = ZkX509Rfc5280StarkColumnProviderV1::with_centers_v1(
            &material,
            der_challenges,
            challenges,
            ZkX509ShaUnionCentersV1::identity_fixture_v1(),
        )
        .expect("canonical RFC column provider");
        let base_active = provider
            .build_base_column_v1(BASE_ACTIVE)
            .expect("base active column");
        let fixed_first = provider
            .build_fixed_column_v1(FIX_GLOBAL_FIRST)
            .expect("fixed first column");
        assert_eq!(base_active.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
        assert_eq!(fixed_first.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
        for row in [
            0,
            material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize],
            material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Grammar as usize],
            material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Padding as usize],
            ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 1,
        ] {
            assert_eq!(
                base_active[row],
                provider.base_row_v1(row).expect("base row")[BASE_ACTIVE]
            );
            assert_eq!(
                fixed_first[row],
                provider.fixed_row_v1(row).expect("fixed row")[FIX_GLOBAL_FIRST]
            );
        }
        assert_eq!(fixed_first[0], F::ONE);
        assert!(fixed_first[1..].iter().all(|value| *value == F::ZERO));
        assert_eq!(
            provider.build_base_column_v1(ZK_X509_RFC5280_STARK_BASE_WIDTH_V1),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        assert_eq!(
            provider.build_fixed_column_v1(ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        assert_eq!(
            provider.build_aux_column_v1(ZK_X509_RFC5280_STARK_AUX_WIDTH_V1),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        let claims = provider.terminal_claims_v1().unwrap();
        let current = provider.base_row_v1(0).expect("first base row");
        let next = provider.base_row_v1(1).expect("next base row");
        let fixed = provider.fixed_row_v1(0).expect("first fixed row");
        let current_aux = neutral_aux_v1();
        let next_aux = neutral_aux_v1();
        let canonical_residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges,
            challenges,
            claims,
        )
        .expect("canonical opened-row evaluation");
        assert_eq!(canonical_residues[8], F::ZERO);
        assert_eq!(canonical_residues[25], F::ZERO);
        let mut changed_value = current;
        changed_value[BASE_VALUE] = changed_value[BASE_VALUE].add(F::ONE);
        assert_ne!(
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &changed_value,
                &next,
                &current_aux,
                &next_aux,
                &fixed,
                der_challenges,
                challenges,
                claims,
            )
            .expect("mutated opened-row evaluation")[8],
            F::ZERO,
            "the provider byte value is constrained to its committed bits"
        );
        let mut changed_helper = current;
        changed_helper[BASE_COPY_VALUE] = changed_helper[BASE_COPY_VALUE].add(F::ONE);
        assert_ne!(
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &changed_helper,
                &next,
                &current_aux,
                &next_aux,
                &fixed,
                der_challenges,
                challenges,
                claims,
            )
            .expect("mutated helper evaluation")[25],
            F::ZERO,
            "the highest provider base column is algebraically replayed"
        );
        let der_source = zk_x509_rfc5280_der_source_terminals_v1(&trace, der_challenges)
            .expect("independent DER source terminals");
        let private_der_fields = [der_source.input_byte, der_source.node].concat();
        for (slot, column) in zk_x509_rfc_der_terminal_columns_v1()
            .into_iter()
            .enumerate()
        {
            let values = PrivateTableV1::new(
                provider.build_aux_column_v1(column).unwrap(),
                zeroize_fields_v1,
            );
            assert_eq!(*values.last().unwrap(), private_der_fields[slot]);
        }
        let output = zk_x509_rfc5280_output_terminals_v1(&trace, challenges)
            .expect("independent output terminals");
        for (role_index, role) in OUTPUT_ROLES_V1.into_iter().enumerate() {
            if let Some(public) = claims.output_role_products_v1(role) {
                assert_eq!(public.consumer_products, output.consumer[role_index]);
            } else {
                assert!(!PUBLIC_OUTPUT_ROLES_V1.contains(&role));
            }
        }
        assert_eq!(
            claims.governed_trust_anchor_products_v1().consumer_products,
            output.consumer[output_role_index_v1(ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor)]
        );
        assert_eq!(
            claims.output_roles.len(),
            1,
            "no internal endpoint or aggregate public slots"
        );
        let root_role_index = output_role_index_v1(ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor);
        let root_selector = output_role_fixed_selector_column_v1(root_role_index, true);
        let root_row = (0..ZK_X509_RFC5280_STARK_TRACE_SIZE_V1 - 1)
            .find(|row| {
                provider.fixed_row_v1(*row).expect("canonical fixed row")[root_selector] == F::ONE
            })
            .expect("governed root-SPKI consumer row");
        let root_aux_column = output_role_aux_column_v1(root_role_index, true, 0);
        let root_column = provider
            .build_aux_column_v1(root_aux_column)
            .expect("root-SPKI prefix product");
        let root_current = provider
            .base_row_v1(root_row)
            .expect("root-SPKI current base row");
        let root_next = provider
            .base_row_v1(root_row + 1)
            .expect("root-SPKI next base row");
        let root_fixed = provider
            .fixed_row_v1(root_row)
            .expect("root-SPKI fixed row");
        let mut root_current_aux = neutral_aux_v1();
        let mut root_next_aux = neutral_aux_v1();
        root_current_aux[root_aux_column] = root_column[root_row];
        root_next_aux[root_aux_column] = root_column[root_row + 1];
        let role_residue_offset: usize = RFC5280_RESIDUE_SECTIONS_V1[..14]
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>()
            + (root_role_index * OUTPUT_ENDPOINT_COUNT_V1 + output_endpoint_index_v1(true))
                * ZK_X509_RFC5280_STARK_BUS_LANES_V1
                * 2;
        let root_residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &root_current,
            &root_next,
            &root_current_aux,
            &root_next_aux,
            &root_fixed,
            der_challenges,
            challenges,
            claims,
        )
        .expect("canonical per-role root-SPKI recurrence");
        assert_eq!(root_residues[role_residue_offset], F::ZERO);
        let mut wrong_root_next_aux = root_next_aux;
        wrong_root_next_aux[root_aux_column] = wrong_root_next_aux[root_aux_column].add(F::ONE);
        assert_ne!(
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &root_current,
                &root_next,
                &root_current_aux,
                &wrong_root_next_aux,
                &root_fixed,
                der_challenges,
                challenges,
                claims,
            )
            .expect("mutated per-role root-SPKI recurrence")[role_residue_offset],
            F::ZERO,
            "the governed root-SPKI product cannot skip or alter its selected factor"
        );
        let mut wrong_root_fixed = root_fixed;
        wrong_root_fixed[root_selector] = F::ZERO;
        assert_ne!(
            evaluate_zk_x509_rfc5280_stark_residues_v1(
                &root_current,
                &root_next,
                &root_current_aux,
                &root_next_aux,
                &wrong_root_fixed,
                der_challenges,
                challenges,
                claims,
            )
            .expect("mutated verifier-fixed root selector")[role_residue_offset],
            F::ZERO,
            "the role product is gated only by the authenticated verifier selector"
        );
        let mut final_aux = [F::ZERO; ZK_X509_RFC5280_STARK_AUX_WIDTH_V1];
        // Reused aggregate columns now hold the sixteen private SHA bridges.
        // Every native value, including both endpoints, equals the owned center.
        for segment in 0..4 {
            for lane in 0..4 {
                let column = provider
                    .build_aux_column_v1(AUX_SHA_UNION_CENTERS + 4 * segment + lane)
                    .unwrap();
                assert_eq!(column.len(), ZK_X509_RFC5280_STARK_TRACE_SIZE_V1);
                assert!(
                    column
                        .iter()
                        .all(|value| *value == provider.sha_union_centers_v1()[segment][lane])
                );
            }
        }
        for role_index in 0..OUTPUT_ROLE_COUNT_V1 {
            for consumer in [false, true] {
                // Producer role products use the exact receiver tuple.
                let expected = output.consumer[role_index];
                for (lane, expected) in expected.into_iter().enumerate() {
                    let auxiliary_column = output_role_aux_column_v1(role_index, consumer, lane);
                    let column = provider
                        .build_aux_column_v1(auxiliary_column)
                        .expect("output-role terminal auxiliary column");
                    final_aux[auxiliary_column] = *column.last().expect("nonempty native column");
                    assert_eq!(final_aux[auxiliary_column], expected);
                }
            }
        }
        assert!(
            evaluate_zk_x509_rfc5280_terminal_claim_residues_v1(F::ONE, &final_aux, claims)
                .expect("verifier replay")
                .iter()
                .all(|residue| *residue == F::ZERO)
        );
    }
    #[test]
    fn private_geometry_mutations_do_not_change_public_schedule_digest() {
        let public = ZkX509Rfc5280StarkShapeV1::default();
        let digest = public.schedule_digest().expect("digest");
        let shape = maximum_private_shape_v1();
        let mut mutations = Vec::new();
        let mut changed = shape.clone();
        changed.crl_entries -= 1;
        refresh_private_shape_derived_rows_v1(&mut changed);
        mutations.push(changed);
        changed = shape.clone();
        changed.disclosed_attributes -= 1;
        refresh_private_shape_derived_rows_v1(&mut changed);
        mutations.push(changed);
        changed = shape.clone();
        changed.top_node_counts[0] -= 1;
        refresh_private_shape_derived_rows_v1(&mut changed);
        mutations.push(changed);
        changed = shape.clone();
        changed.io_channels += 1;
        refresh_private_shape_derived_rows_v1(&mut changed);
        mutations.push(changed);
        for mutation in mutations {
            mutation.validate().expect("valid private mutation");
            assert_eq!(
                ZkX509Rfc5280StarkShapeV1::default()
                    .schedule_digest()
                    .expect("constant public digest"),
                digest,
                "private counts and lengths never enter the public transcript"
            );
        }
    }
    #[test]
    fn output_grand_product_is_total_at_a_forced_zero_factor() {
        let endpoint = ZkX509IoEndpointV1 {
            role: ZkX509IoSegmentRoleV1::StrictDer,
            instance: 0,
        };
        let mut challenges = challenges_v1();
        let values = [
            F(80),
            F(ZkX509Rfc5280OutputRoleV1::Projection as u64),
            F(7),
            F(endpoint_role_code_v1(endpoint.role).expect("endpoint role")),
            F(u64::from(endpoint.instance)),
            F(2),
            F(3),
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ];
        let non_domain_sum = values[1..]
            .iter()
            .zip(&challenges.tuple[0][1..])
            .fold(F::ZERO, |sum, (value, coefficient)| {
                sum.add(value.mul(*coefficient))
            });
        challenges.tuple[0][0] =
            F::ZERO.sub(non_domain_sum.mul(F(80).inv().expect("nonzero output domain separator")));
        challenges.validate().expect("forced-zero challenges");
        assert_eq!(
            output_factor_v1(
                ZkX509Rfc5280OutputRoleV1::Projection,
                7,
                endpoint,
                2,
                3,
                true,
                0,
                challenges,
            )
            .expect("zero product factor is not a completeness error"),
            F::ZERO
        );
    }
    #[test]
    fn private_depth_selector_and_optional_slot_dummy_are_canonical() {
        let mut depth_two = maximum_private_shape_v1();
        depth_two.chain_depth = 2;
        depth_two.certificate_slot_2_active = F::ZERO;
        depth_two.top_document_count = 3;
        depth_two.top_document_lengths[3] = 0;
        depth_two.top_node_counts[3] = 0;
        // Embedded documents are byte ranges copied from the active
        // top-level documents. Removing the fourth 4 KiB document therefore
        // also requires a physically possible embedded-byte geometry instead
        // of retaining the depth-three 16 KiB maximum.
        depth_two.embedded_document_count = 11;
        depth_two.embedded_document_lengths[11..].fill(0);
        depth_two.embedded_node_counts[11..].fill(0);
        refresh_private_shape_derived_rows_v1(&mut depth_two);
        depth_two.validate().expect("canonical depth-two geometry");
        let mut flipped = depth_two.clone();
        flipped.certificate_slot_2_active = F::ONE;
        assert_eq!(
            flipped.validate(),
            Err(ZkX509Rfc5280StarkErrorV1::Shape),
            "the private selector is exactly depth == 3"
        );
        let mut noncanonical_dummy_bytes = depth_two.clone();
        noncanonical_dummy_bytes.top_document_lengths[3] = 1;
        assert_eq!(
            noncanonical_dummy_bytes.validate(),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        let mut noncanonical_dummy_nodes = depth_two.clone();
        noncanonical_dummy_nodes.top_node_counts[3] = 1;
        assert_eq!(
            noncanonical_dummy_nodes.validate(),
            Err(ZkX509Rfc5280StarkErrorV1::Shape)
        );
        let mut noncanonical_calendar_phase_count = depth_two.clone();
        noncanonical_calendar_phase_count.calendar_rows += 1;
        assert_eq!(
            noncanonical_calendar_phase_count.validate(),
            Err(ZkX509Rfc5280StarkErrorV1::Shape),
            "calendar rows are exactly seven physical phases per semantic timestamp"
        );
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("fixed schedule");
        let cert2_first = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SourceByte as usize]
            + 3 * ZK_X509_RFC5280_MAX_TOP_LEVEL_DOCUMENT_BYTES_V1;
        let fixed = schedule
            .fixed_row(cert2_first)
            .expect("optional-slot fixed row");
        let depth_two_row = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        assert!(
            private_geometry_residues_v1(&depth_two_row, &depth_two_row, &fixed)
                .iter()
                .all(|residue| *residue == F::ZERO),
            "depth two uses the unique inactive all-zero slot"
        );
        let mut depth_two_active = depth_two_row;
        depth_two_active[BASE_ACTIVE] = F::ONE;
        assert!(
            private_geometry_residues_v1(&depth_two_active, &depth_two_active, &fixed)
                .iter()
                .any(|residue| *residue != F::ZERO),
            "depth two cannot activate certificate slot two"
        );
        let mut nonzero_dummy = depth_two_row;
        nonzero_dummy[BASE_VALUE] = F::ONE;
        assert!(
            private_geometry_residues_v1(&nonzero_dummy, &depth_two_row, &fixed)
                .iter()
                .any(|residue| *residue != F::ZERO),
            "inactive dummy byte rows are all-zero outside carried selectors"
        );
        let mut depth_three_row = depth_two_row;
        depth_three_row[BASE_ACTIVE] = F::ONE;
        depth_three_row[BASE_CERT2_ACTIVE] = F::ONE;
        assert!(
            private_geometry_residues_v1(&depth_three_row, &depth_three_row, &fixed)
                .iter()
                .all(|residue| *residue == F::ZERO),
            "depth three activates the optional slot"
        );
        let mut depth_three_inactive = depth_two_row;
        depth_three_inactive[BASE_CERT2_ACTIVE] = F::ONE;
        assert!(
            private_geometry_residues_v1(&depth_three_inactive, &depth_three_inactive, &fixed)
                .iter()
                .any(|residue| *residue != F::ZERO),
            "depth three cannot suppress certificate slot two"
        );
    }
    #[test]
    fn four_lanes_are_distinct_and_global_copy_bound_is_at_least_170_bits() {
        let challenges = challenges_v1();
        challenges.validate().expect("four independent lanes");
        let mut duplicate = challenges;
        duplicate.tuple[3][11] = duplicate.tuple[0][0];
        assert_eq!(
            duplicate.validate(),
            Err(ZkX509Rfc5280StarkErrorV1::Challenge)
        );
        assert_eq!(ZK_X509_RFC5280_STARK_BUS_LANES_V1, 4);
        assert_eq!(ZK_X509_RFC5280_STARK_RELATION_EVENT_BOUND_V1, 1 << 19);
        assert_eq!(ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1, 39);
        let profile =
            core::str::from_utf8(super::super::profile::ZK_X509_STARK_PROFILE_DESCRIPTOR_V1)
                .unwrap();
        let temporal_air = profile
            .split('|')
            .find(|field| field.starts_with("rfc5280-temporal-air="))
            .unwrap();
        let declared_relations = temporal_air
            .strip_suffix("-relations")
            .unwrap()
            .rsplit('-')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(
            declared_relations,
            ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1
        );
        assert!(temporal_air.contains(&format!(
            "-constraints{}-",
            ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1
        )));
        assert_eq!(ZK_X509_RFC5280_STARK_COPY_SOUNDNESS_BITS_V1, 170);
    }
    #[test]
    fn evaluator_inventory_is_exact_and_padding_mutation_is_detected() {
        let current = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        let next = current;
        let current_aux = neutral_aux_v1();
        let next_aux = current_aux;
        let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        fixed[ZkX509Rfc5280StarkFamilyV1::Padding as usize] = F::ONE;
        let claims = terminal_claims_v1();
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges_v1(),
            claims,
        )
        .expect("total evaluator");
        assert_eq!(residues.len(), ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1);
        assert!(residues.iter().all(|residue| *residue == F::ZERO));
        let mut changed = current;
        changed[BASE_A] = F::ONE;
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &changed,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges_v1(),
            claims,
        )
        .expect("mutated evaluator");
        assert!(residues.iter().any(|residue| *residue != F::ZERO));
        let mut changed_high_column = current;
        changed_high_column[SERIAL_SLACK_BITS + 7] = F::ONE;
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &changed_high_column,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges_v1(),
            claims,
        )
        .expect("high-column padding mutation evaluator");
        assert!(
            residues.iter().any(|residue| *residue != F::ZERO),
            "inactive serial bit columns must be zero on padding rows"
        );
        assert!(ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1 <= usize::from(u16::MAX));
    }
    fn affine_value_v1(seed: u64, domain: u64, column: usize, point: u64) -> F {
        let column = u64::try_from(column).expect("test column fits u64");
        let intercept = F(seed
            .checked_mul(1_009)
            .and_then(|value| value.checked_add(domain * 131))
            .and_then(|value| value.checked_add(column * 17))
            .and_then(|value| value.checked_add(1))
            .expect("small affine intercept"));
        let slope = F(seed
            .checked_mul(313)
            .and_then(|value| value.checked_add(domain * 29))
            .and_then(|value| value.checked_add(column * 43))
            .and_then(|value| value.checked_add(7))
            .expect("small nonzero affine slope"));
        intercept.add(slope.mul(F(point)))
    }
    fn finite_difference_degree_v1(mut samples: Vec<F>) -> usize {
        let mut maximum_nonzero_order = 0;
        for order in 0..samples.len() {
            if samples.iter().any(|value| *value != F::ZERO) {
                maximum_nonzero_order = order;
            }
            if samples.len() == 1 {
                break;
            }
            samples = samples
                .windows(2)
                .map(|window| window[1].sub(window[0]))
                .collect();
        }
        maximum_nonzero_order
    }
    #[test]
    fn full_opened_input_affine_degree_inventory_is_exactly_four() {
        const SAMPLE_POINTS: u64 = 9;
        let mut maximum_degrees = vec![0_usize; ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1];
        for seed in [3_u64, 5, 11] {
            let sample_points = usize::try_from(SAMPLE_POINTS).expect("sample count fits usize");
            let mut samples = (0..ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1)
                .map(|_| Vec::with_capacity(sample_points))
                .collect::<Vec<_>>();
            for point in 0..SAMPLE_POINTS {
                let current =
                    core::array::from_fn(|column| affine_value_v1(seed, 1, column, point));
                let next = core::array::from_fn(|column| affine_value_v1(seed, 2, column, point));
                let current_aux =
                    core::array::from_fn(|column| affine_value_v1(seed, 3, column, point));
                let next_aux =
                    core::array::from_fn(|column| affine_value_v1(seed, 4, column, point));
                let fixed = core::array::from_fn(|column| affine_value_v1(seed, 5, column, point));
                let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                    &current,
                    &next,
                    &current_aux,
                    &next_aux,
                    &fixed,
                    der_challenges_v1(),
                    challenges_v1(),
                    terminal_claims_v1(),
                )
                .expect("affine degree evaluator is total");
                for (residue_samples, residue) in samples.iter_mut().zip(residues) {
                    residue_samples.push(residue);
                }
            }
            for (maximum, residue_samples) in maximum_degrees.iter_mut().zip(samples) {
                *maximum = (*maximum).max(finite_difference_degree_v1(residue_samples));
            }
        }
        let offenders = maximum_degrees
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, degree)| *degree > usize::from(ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1))
            .collect::<Vec<_>>();
        assert!(offenders.is_empty(), "degree-four offenders: {offenders:?}");
        assert!(
            maximum_degrees
                .iter()
                .any(|degree| *degree == usize::from(ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1)),
            "the registered degree must be attained, not only upper-bounded"
        );
        let inventory = core::array::from_fn::<_, 5, _>(|degree| {
            maximum_degrees
                .iter()
                .filter(|actual| **actual == degree)
                .count()
        });
        // Native finite differences vary every opened base, auxiliary and fixed
        // input at nine points for each of the three seeds above. The expected
        // inventory includes BasicConstraints126 plus copy40 and identity43,
        // replacing five old cubic equations. Native execution must confirm it.
        const EXPECTED_AFFINE_DEGREE_INVENTORY_V1: [usize; 5] = [0, 1, 916, 577, 655];
        assert_eq!(
            inventory, EXPECTED_AFFINE_DEGREE_INVENTORY_V1,
            "the full-input interpolation is a proof-shape pin, independent of evaluator sections"
        );
        assert_eq!(inventory.iter().sum::<usize>(), maximum_degrees.len());
    }
    #[test]
    fn every_committed_degree_normalization_helper_is_constrained() {
        let current = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        let next = current;
        let current_aux = neutral_aux_v1();
        let next_aux = current_aux;
        let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        fixed[ZkX509Rfc5280StarkFamilyV1::Padding as usize] = F::ONE;
        let direct_helpers = [
            BASE_GRAMMAR_ORDINAL,
            BASE_EXPECTED_ROOT_KIND,
            BASE_PROFILE_TABLE_ACTIVE,
            BASE_PROFILE_TABLE_MULTIPLICITY,
            BASE_PROFILE_TOPOLOGY_QUERY_ACTIVE,
            BASE_SERIAL_BYTE_QUERY_ACTIVE,
            BASE_SERIAL_BYTE_QUERY_VALUE,
            BASE_COPY_SOURCE_ACTIVE,
            BASE_COPY_CONSUMER_ACTIVE,
            BASE_COPY_DOMAIN,
            BASE_COPY_KEY_1,
            BASE_COPY_KEY_2,
            BASE_COPY_VALUE,
        ];
        // Thirteen elementary constraints precede this exact helper block:
        // eight byte-bit booleans, byte packing, and four global booleans.
        const HELPER_RESIDUE_START: usize = 13;
        for (helper_index, column) in direct_helpers.into_iter().enumerate() {
            let mut mutated = current;
            mutated[column] = F::ONE;
            let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                &mutated,
                &next,
                &current_aux,
                &next_aux,
                &fixed,
                der_challenges_v1(),
                challenges_v1(),
                terminal_claims_v1(),
            )
            .expect("helper mutation evaluator");
            assert_ne!(
                residues[HELPER_RESIDUE_START + helper_index],
                F::ZERO,
                "helper column {column} must have its own defining constraint"
            );
        }
        for column in [BASE_ORDINAL_NEXT_ACTIVE, BASE_ORDINAL_EQUAL_CONTINUE] {
            let mut mutated = current;
            mutated[column] = F::ONE;
            let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                &mutated,
                &next,
                &current_aux,
                &next_aux,
                &fixed,
                der_challenges_v1(),
                challenges_v1(),
                terminal_claims_v1(),
            )
            .expect("ordinal helper mutation evaluator");
            assert!(
                residues.iter().any(|residue| *residue != F::ZERO),
                "ordinal helper column {column} must be constrained"
            );
        }
    }
    #[test]
    fn physical_copy_phase_mutations_are_rejected() {
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("fixed schedule");
        let comparison = canonical_serial_comparisons_v1(&[7], &[vec![8]])
            .expect("canonical comparison")
            .remove(0);
        let serial_row =
            build_zk_x509_rfc5280_serial_comparison_rows_v1(&comparison).expect("serial rows")[0];
        let serial_start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize];
        let serial_fixed = schedule
            .fixed_row(serial_start)
            .expect("serial left-copy phase");
        let serial_current = normalized_row_v1(serial_row, &serial_fixed);
        let (current_aux, next_aux) = serial_comparator_aux_v1(&serial_current);
        let canonical = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &serial_current,
            &serial_row,
            &current_aux,
            &next_aux,
            &serial_fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("serial left phase evaluator");
        assert!(canonical.iter().all(|residue| *residue == F::ZERO));
        let mut changed_serial_right_phase = serial_row;
        changed_serial_right_phase[BASE_A] = changed_serial_right_phase[BASE_A].add(F::ONE);
        let rejected = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &serial_current,
            &changed_serial_right_phase,
            &current_aux,
            &next_aux,
            &serial_fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("serial phase mutation evaluator");
        assert!(
            rejected.iter().any(|residue| *residue != F::ZERO),
            "left and right physical serial phases cannot carry different copy tuples"
        );
        let trace = canonical_trace_v1();
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&trace)
            .expect("canonical calendar source");
        // Identity phase zero now authenticates the DER node. Exercise the
        // original inter-component copy property between real phases one/two,
        // where no additional numeric lookup event is emitted.
        let calendar_start =
            material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Calendar as usize] + 1;
        let calendar_fixed = material
            .fixed_row(calendar_start)
            .expect("first calendar component phase");
        let calendar_current = material
            .base_row(calendar_start)
            .expect("first calendar component row");
        let calendar_row = material
            .base_row(calendar_start + 1)
            .expect("second calendar component row");
        let (current_aux, next_aux) = serial_comparator_aux_v1(&calendar_current);
        let canonical = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &calendar_current,
            &calendar_row,
            &current_aux,
            &next_aux,
            &calendar_fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("calendar phase evaluator");
        assert!(canonical.iter().all(|residue| *residue == F::ZERO));
        let mut changed_calendar_phase = calendar_row;
        changed_calendar_phase[BASE_C] = changed_calendar_phase[BASE_C].add(F::ONE);
        let rejected = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &calendar_current,
            &changed_calendar_phase,
            &current_aux,
            &next_aux,
            &calendar_fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("calendar phase mutation evaluator");
        assert!(
            rejected.iter().any(|residue| *residue != F::ZERO),
            "seven physical calendar phases must copy one common semantic row"
        );
    }
    #[test]
    fn normalized_copy_product_is_total_at_a_forced_zero_factor() {
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("fixed schedule");
        let comparison = canonical_serial_comparisons_v1(&[7], &[vec![8]])
            .expect("canonical comparison")
            .remove(0);
        let row =
            build_zk_x509_rfc5280_serial_comparison_rows_v1(&comparison).expect("serial rows")[0];
        let serial_start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize];
        let fixed = schedule
            .fixed_row(serial_start)
            .expect("serial left-copy phase");
        let current = normalized_row_v1(row, &fixed);
        let mut challenges = challenges_v1();
        let tuple = [
            current[BASE_COPY_DOMAIN],
            current[BASE_COPY_KEY_1],
            current[BASE_COPY_KEY_2],
            current[BASE_COPY_VALUE],
        ];
        let non_domain_sum = tuple[1..]
            .iter()
            .zip(&challenges.tuple[0][1..4])
            .fold(F::ZERO, |sum, (value, coefficient)| {
                sum.add(value.mul(*coefficient))
            });
        challenges.tuple[0][0] = F::ZERO
            .sub(non_domain_sum.mul(tuple[0].inv().expect("copy domain separator is nonzero")));
        challenges.validate().expect("forced-zero copy challenges");
        assert_eq!(normalized_copy_factor_v1(&current, 0, challenges), F::ZERO);
        let mut current_aux = neutral_aux_v1();
        let mut next_aux = neutral_aux_v1();
        for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
            let factor = normalized_copy_factor_v1(&current, lane, challenges);
            let after = F::ONE.add(current[BASE_COPY_CONSUMER_ACTIVE].mul(factor.sub(F::ONE)));
            current_aux[AUX_SERIAL_CONSUMER_AFTER + lane] = after;
            next_aux[AUX_SERIAL_CONSUMER_BEFORE + lane] = after;
        }
        assert_eq!(current_aux[AUX_SERIAL_CONSUMER_AFTER], F::ZERO);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &row,
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges,
            terminal_claims_v1(),
        )
        .expect("zero copy factor never invokes an inverse");
        assert!(residues.iter().all(|residue| *residue == F::ZERO));
    }
    #[test]
    fn semantic_source_table_is_unique_and_multiplicity_exact() {
        let cell_a = ZkX509Rfc5280SourceCellV1 {
            document: 0,
            address: 7,
            value: 11,
        };
        let cell_b = ZkX509Rfc5280SourceCellV1 {
            document: 1,
            address: 3,
            value: 13,
        };
        let source_node = ZkX509Rfc5280NodeProvenanceV1 {
            document: 0,
            node: 0,
            parent_node: u16::MAX,
            child_ordinal: 0,
            start: 7,
            content_start: 7,
            content_end: 8,
            depth: 0,
            tag_class: 0,
            constructed: false,
            tag_number: 4,
            role: ZkX509Rfc5280GrammarRoleV1::CertificateOuterAlgorithm,
            role_instance: 0,
        };
        let witness = ZkX509Rfc5280SemanticWitnessV1 {
            fixed_bytes: vec![
                ZkX509Rfc5280FixedByteV1 {
                    source: cell_a,
                    source_node,
                    expected: 11,
                    purpose: 1,
                    instance: 0,
                    variant: 0,
                    offset: 0,
                    length: 1,
                },
                ZkX509Rfc5280FixedByteV1 {
                    source: cell_a,
                    source_node,
                    expected: 11,
                    purpose: 2,
                    instance: 0,
                    variant: 0,
                    offset: 0,
                    length: 1,
                },
            ],
            equal_bytes: vec![ZkX509Rfc5280EqualByteV1 {
                left: cell_a,
                right: cell_b,
                purpose: 3,
                instance: 0,
                offset: 0,
            }],
            decimal_cells: vec![cell_b],
            calendar_values: Vec::new(),
            numeric_relations: Vec::new(),
            serial_sources: Vec::new(),
            serial_comparisons: Vec::new(),
        };
        let table =
            zk_x509_rfc5280_semantic_source_multiplicities_v1(&witness).expect("source table");
        assert_eq!(
            table.as_slice(),
            &[
                ZkX509Rfc5280SourceMultiplicityV1 {
                    source: cell_a,
                    required_multiplicity: 3,
                },
                ZkX509Rfc5280SourceMultiplicityV1 {
                    source: cell_b,
                    required_multiplicity: 2,
                },
            ]
        );
        let mut duplicated = table;
        let first = duplicated[0];
        duplicated.push(first);
        duplicated.sort_unstable_by_key(|entry| entry.source);
        assert!(
            duplicated
                .windows(2)
                .any(|pair| pair[0].source == pair[1].source),
            "a duplicated unique source address is mechanically detectable"
        );
    }
    #[test]
    fn serial_private_difference_inverses_preserve_equal_prefixes_and_rejections() {
        for byte in 0_u8..=u8::MAX {
            for (left, right) in [([1, byte, 1], [1, 0, 2]), ([1, 0, 2], [1, byte, 1])] {
                let comparison = ZkX509Rfc5280SerialComparisonV1 {
                    kind: ZkX509Rfc5280SerialComparisonKindV1::LeafNonMembership,
                    left_instance: 0,
                    right_instance: 1,
                    left: serial_frame_v1(&left).expect("left frame"),
                    right: serial_frame_v1(&right).expect("right frame"),
                };
                let rows = build_zk_x509_rfc5280_serial_comparison_rows_v1(&comparison)
                    .expect("distinct serials");
                assert_eq!(rows.len(), SERIAL_COMPARISON_WIDTH_V1);
                for (offset, row) in rows.iter().enumerate() {
                    let difference = F(u64::from(comparison.left[offset]))
                        .sub(F(u64::from(comparison.right[offset])));
                    assert_eq!(row[BASE_EQUAL], F(u64::from(difference == F::ZERO)));
                    assert_eq!(row[BASE_INVERSE], difference.inv().unwrap_or(F::ZERO));
                }
            }
        }
        let valid = canonical_serial_comparisons_v1(&[7], &[vec![8], vec![9]]).expect("manifest");
        for attack in 0..5 {
            let mut changed = valid[2].clone();
            match attack {
                0 => changed.right = changed.left,
                1 => changed.left[1] = 0,
                2 => changed.right[SERIAL_COMPARISON_WIDTH_V1 - 1] = 1,
                3 => changed.right[0] = 0,
                _ => core::mem::swap(&mut changed.left, &mut changed.right),
            }
            assert!(matches!(
                build_zk_x509_rfc5280_serial_comparison_rows_v1(&changed),
                Err(ZkX509Rfc5280StarkErrorV1::Semantic)
            ));
        }
    }

    #[test]
    fn ordinal_gap_constructor_preserves_zero_bounds_and_error_write_order() {
        for difference in [
            0,
            1,
            2,
            65_535,
            65_536,
            65_537,
            GOLDILOCKS_MODULUS_V1 - 1,
            GOLDILOCKS_MODULUS_V1,
            u64::MAX,
        ] {
            let mut row = active_zero_row_v1();
            row[BASE_H] = F(37);
            let mut expected = row;
            expected[BASE_B] = F(difference);
            expected[BASE_EQUAL] = F(u64::from(difference == 0));
            let expected_result = if difference == 0 {
                Ok(())
            } else if let Some(inverse) = F(difference).inv() {
                expected[BASE_INVERSE] = inverse;
                let gap = difference - 1;
                expected[BASE_C] = F(gap);
                if let Ok(gap) = u16::try_from(gap) {
                    for bit in 0..16 {
                        expected[GRAMMAR_CHILD_ORDINAL_BITS + bit] = F(u64::from((gap >> bit) & 1));
                    }
                    Ok(())
                } else {
                    Err(ZkX509Rfc5280StarkErrorV1::Resource)
                }
            } else {
                Err(ZkX509Rfc5280StarkErrorV1::Grammar)
            };
            assert_eq!(
                populate_ordinal_gap_v1(&mut row, difference),
                expected_result
            );
            assert_eq!(row, expected, "difference {difference}");
        }
    }

    #[test]
    fn canonical_ordinal_rows_preserve_private_groups_and_inverse_constraints() {
        let material = build_zk_x509_rfc5280_stark_base_material_v1(&canonical_trace_v1())
            .expect("original DER trace");
        let rows = material.family_rows[ZkX509Rfc5280StarkFamilyV1::Grammar as usize]
            .iter()
            .skip(ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1)
            .collect::<Vec<_>>();
        let mut examples = [None, None];
        for (index, pair) in rows.windows(2).enumerate() {
            let difference = pair[1][BASE_A]
                .0
                .checked_sub(pair[0][BASE_A].0)
                .expect("sorted original keys");
            assert_eq!(pair[0][BASE_B], F(difference));
            assert_eq!(pair[0][BASE_EQUAL], F(u64::from(difference == 0)));
            assert_eq!(
                pair[0][BASE_INVERSE],
                F(difference).inv().unwrap_or(F::ZERO)
            );
            assert_eq!(pair[0][BASE_C], F(difference.saturating_sub(1)));
            assert_eq!(
                pack_bits_v1(&pair[0][GRAMMAR_CHILD_ORDINAL_BITS..GRAMMAR_CHILD_ORDINAL_BITS + 16]),
                pair[0][BASE_C]
            );
            examples[usize::from(difference != 0)].get_or_insert(index);
        }
        let last = rows.last().expect("original ordinal rows");
        for column in [BASE_B, BASE_EQUAL, BASE_INVERSE, BASE_C] {
            assert_eq!(last[column], F::ZERO);
        }
        for index in
            examples.map(|index| index.expect("both same-parent and different-parent groups"))
        {
            let physical = material.schedule.starts[ZkX509Rfc5280StarkFamilyV1::Grammar as usize]
                + ZK_X509_RFC5280_GRAMMAR_RULE_COUNT_V1
                + index;
            let mut current = material.base_row(physical).expect("original row");
            let next = material.base_row(physical + 1).expect("next row");
            let fixed = material.fixed_row(physical).expect("fixed row");
            let evaluate = |row: &ZkX509Rfc5280StarkBaseRowV1| {
                evaluate_zk_x509_rfc5280_stark_residues_v1(
                    row,
                    &next,
                    &neutral_aux_v1(),
                    &neutral_aux_v1(),
                    &fixed,
                    der_challenges_v1(),
                    challenges_v1(),
                    terminal_claims_v1(),
                )
                .expect("original evaluator")
            };
            let base_end: usize = RFC5280_RESIDUE_SECTIONS_V1[..12]
                .iter()
                .map(|(_, count)| count)
                .sum();
            assert!(
                evaluate(&current)[..base_end]
                    .iter()
                    .all(|value| *value == F::ZERO)
            );
            current[BASE_INVERSE] = current[BASE_INVERSE].add(F::ONE);
            assert!(
                evaluate(&current)[..base_end]
                    .iter()
                    .any(|value| *value != F::ZERO)
            );
        }
    }

    #[test]
    fn serial_comparison_rows_cover_leaf_and_exact_active_adjacencies() {
        let entries = ZK_X509_MAX_CRL_ENTRIES_V1;
        let comparisons = entries + entries - 1;
        assert_eq!(comparisons, MAX_SERIAL_COMPARISONS_V1);
        assert_eq!(
            comparisons * SERIAL_COMPARISON_WIDTH_V1,
            MAX_SERIAL_COMPARISON_ROWS_V1
        );
        assert_eq!(MAX_SERIAL_COMPARISON_ROWS_V1, 2_667);
        assert_eq!(serial_comparison_count_v1(0), 0);
        assert_eq!(serial_comparison_rows_v1(0), 0);
        let mut empty = maximum_private_shape_v1();
        empty.crl_entries = 0;
        refresh_private_shape_derived_rows_v1(&mut empty);
        empty.validate().expect("empty private CRL census");
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("fixed public schedule");
        assert_eq!(
            schedule.counts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize],
            MAX_SERIAL_COMPARISON_PHYSICAL_ROWS_V1,
            "the public comparator capacity is independent of the private CRL census"
        );
        empty.serial_rows = u32::try_from(SERIAL_COMPARISON_WIDTH_V1).expect("fits");
        assert_eq!(empty.validate(), Err(ZkX509Rfc5280StarkErrorV1::Shape));
    }
    #[test]
    fn der_backed_serial_source_proves_sign_octet_content_and_zero_padding() {
        let source = serial_source_fixture_v1(0, &[0xff]);
        let rows =
            build_zk_x509_rfc5280_serial_source_rows_v1(&source).expect("serial source rows");
        assert_eq!(rows.len(), SERIAL_COMPARISON_WIDTH_V1);
        assert_eq!(rows[0][BASE_IS_WRITE], F::ONE);
        assert_eq!(rows[0][BASE_ADDRESS], F(100));
        assert_eq!(rows[0][SERIAL_SOURCE_QUERY_VALUE], F::ZERO);
        assert_eq!(rows[1][BASE_ADDRESS], F(101));
        assert_eq!(rows[1][SERIAL_SOURCE_QUERY_VALUE], F(0xff));
        assert!(
            rows[2..].iter().all(|row| {
                row[BASE_EQUAL] == F::ZERO
                    && row[BASE_VALUE] == F::ZERO
                    && row[BASE_IS_WRITE] == F::ZERO
            }),
            "inactive magnitude slots are algebraically canonical padding"
        );
        let (byte_multiplicities, node_multiplicities) =
            zk_x509_rfc5280_serial_lookup_multiplicities_v1(core::slice::from_ref(&source))
                .expect("lookup multiplicities");
        assert_eq!(
            byte_multiplicities
                .iter()
                .map(|entry| (
                    entry.source.address,
                    entry.source.value,
                    entry.required_multiplicity
                ))
                .collect::<Vec<_>>(),
            vec![(100, 0, 1), (101, 0xff, 1)]
        );
        assert_eq!(
            node_multiplicities.as_slice(),
            &[ZkX509Rfc5280SerialNodeMultiplicityV1 {
                document: 0,
                node: 7,
                required_multiplicity: 21,
            }]
        );
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("source schedule");
        let start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialSource as usize];
        for (offset, source_row) in rows.iter().enumerate() {
            let next = rows.get(offset + 1).unwrap_or(source_row);
            let fixed = schedule
                .fixed_row(start + offset)
                .expect("source fixed row");
            let current = normalized_row_v1(*source_row, &fixed);
            let (current_aux, next_aux) = serial_source_aux_v1(&current, challenges_v1());
            let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                &current,
                next,
                &current_aux,
                &next_aux,
                &fixed,
                der_challenges_v1(),
                challenges_v1(),
                terminal_claims_v1(),
            )
            .expect("source evaluator");
            assert!(
                residues.iter().all(|residue| *residue == F::ZERO),
                "DER-backed source offset {offset} must satisfy every local residue"
            );
        }
    }
    #[test]
    fn der_backed_serial_lookup_is_complete_at_a_forced_zero_factor() {
        let source = serial_source_fixture_v1(0, &[0xff]);
        let rows =
            build_zk_x509_rfc5280_serial_source_rows_v1(&source).expect("serial source rows");
        let current = rows[1];
        let next = rows[2];
        let mut challenges = challenges_v1();
        let non_domain_sum = current[BASE_DOCUMENT]
            .mul(challenges.tuple[0][1])
            .add(current[BASE_ADDRESS].mul(challenges.tuple[0][2]))
            .add(current[SERIAL_SOURCE_QUERY_VALUE].mul(challenges.tuple[0][3]));
        challenges.tuple[0][0] = F::ZERO
            .sub(non_domain_sum.mul(F(91).inv().expect("nonzero serial-byte domain separator")));
        challenges.validate().expect("forced-collision challenges");
        assert_eq!(
            serial_byte_lookup_factor_v1(
                current[BASE_DOCUMENT],
                current[BASE_ADDRESS],
                current[SERIAL_SOURCE_QUERY_VALUE],
                0,
                challenges,
            ),
            F::ZERO
        );
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("source schedule");
        let index = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialSource as usize] + 1;
        let fixed = schedule.fixed_row(index).expect("source fixed row");
        let current = normalized_row_v1(current, &fixed);
        let (current_aux, next_aux) = serial_source_aux_v1(&current, challenges);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &next,
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges,
            terminal_claims_v1(),
        )
        .expect("zero-safe source evaluator");
        assert!(residues.iter().all(|residue| *residue == F::ZERO));
        let mut corrupted_aux = current_aux;
        corrupted_aux[AUX_SERIAL_BYTE_QUERY_ZERO] = F::ZERO;
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &next,
            &corrupted_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges,
            terminal_claims_v1(),
        )
        .expect("corrupted zero-safe source evaluator");
        assert!(residues.iter().any(|residue| *residue != F::ZERO));
    }
    fn serial_copy_products_v1(
        sources: &[ZkX509Rfc5280SerialSourceV1],
        comparisons: &[ZkX509Rfc5280SerialComparisonV1],
    ) -> (
        [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
        [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
    ) {
        let challenges = challenges_v1();
        let mut producer = [F::ONE; ZK_X509_RFC5280_STARK_BUS_LANES_V1];
        let mut consumer = producer;
        for source in sources {
            for (offset, value) in source.frame.iter().copied().enumerate() {
                for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                    producer[lane] = producer[lane].mul(serial_copy_factor_v1(
                        F(u64::from(source.logical_id)),
                        F(u64::try_from(offset).expect("offset fits")),
                        F(u64::from(value)),
                        lane,
                        challenges,
                    ));
                }
            }
        }
        for comparison in comparisons {
            for (logical_id, frame) in [
                (comparison.left_instance, &comparison.left),
                (comparison.right_instance, &comparison.right),
            ] {
                for (offset, value) in frame.iter().copied().enumerate() {
                    for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
                        consumer[lane] = consumer[lane].mul(serial_copy_factor_v1(
                            F(u64::from(logical_id)),
                            F(u64::try_from(offset).expect("offset fits")),
                            F(u64::from(value)),
                            lane,
                            challenges,
                        ));
                    }
                }
            }
        }
        (producer, consumer)
    }
    #[test]
    fn locally_valid_comparator_shadow_values_fail_serial_copy_and_der_lookup() {
        let canonical =
            canonical_serial_comparisons_v1(&[7], &[vec![8]]).expect("canonical comparison");
        let canonical_sources = vec![
            serial_source_fixture_v1(0, &[7]),
            serial_source_fixture_v1(1, &[8]),
        ];
        let (producer, consumer) = serial_copy_products_v1(&canonical_sources, &canonical);
        assert_eq!(producer, consumer);
        let mut changed_comparison = canonical.clone();
        changed_comparison[0].left = serial_frame_v1(&[6]).expect("alternate valid magnitude");
        validate_serial_comparison_v1(&changed_comparison[0])
            .expect("local leaf inequality still holds");
        let (producer, changed_consumer) =
            serial_copy_products_v1(&canonical_sources, &changed_comparison);
        assert_ne!(
            producer, changed_consumer,
            "four-lane serial copy terminals bind comparator values to sources"
        );
        let mut shadow_sources = canonical_sources.clone();
        shadow_sources[0].frame = serial_frame_v1(&[6]).expect("alternate source frame");
        let (shadow_producer, shadow_consumer) =
            serial_copy_products_v1(&shadow_sources, &changed_comparison);
        assert_eq!(
            shadow_producer, shadow_consumer,
            "the copy bus alone intentionally sees a self-consistent shadow"
        );
        let canonical_row = build_zk_x509_rfc5280_serial_source_rows_v1(&canonical_sources[0])
            .expect("canonical source rows");
        let mut shadow_row = canonical_row[1];
        shadow_row[BASE_VALUE] = F(6);
        shadow_row[SERIAL_SOURCE_QUERY_VALUE] = F(6);
        write_u8_bits_v1(&mut shadow_row, BASE_BYTE_BITS, 6);
        shadow_row[SERIAL_SOURCE_FIRST_INVERSE] = F(6).inv().expect("nonzero");
        let table_factor = serial_byte_lookup_factor_v1(
            canonical_row[1][BASE_DOCUMENT],
            canonical_row[1][BASE_ADDRESS],
            canonical_row[1][SERIAL_SOURCE_QUERY_VALUE],
            0,
            challenges_v1(),
        );
        let shadow_query_factor = serial_byte_lookup_factor_v1(
            shadow_row[BASE_DOCUMENT],
            shadow_row[BASE_ADDRESS],
            shadow_row[SERIAL_SOURCE_QUERY_VALUE],
            0,
            challenges_v1(),
        );
        assert_ne!(
            table_factor, shadow_query_factor,
            "DER-byte lookup rejects a value-mutated self-consistent shadow"
        );
    }
    #[test]
    fn source_address_and_node_span_mutations_break_der_lookup_keys() {
        let source = serial_source_fixture_v1(0, &[0xff]);
        let rows =
            build_zk_x509_rfc5280_serial_source_rows_v1(&source).expect("canonical source rows");
        let canonical = rows[1];
        let mut moved = canonical;
        moved[BASE_START] = moved[BASE_START].add(F::ONE);
        moved[BASE_CONTENT_START] = moved[BASE_CONTENT_START].add(F::ONE);
        moved[BASE_CONTENT_END] = moved[BASE_CONTENT_END].add(F::ONE);
        moved[BASE_ADDRESS] = moved[BASE_ADDRESS].add(F::ONE);
        assert_ne!(
            serial_node_lookup_factor_v1(&canonical, 0, challenges_v1()),
            serial_node_lookup_factor_v1(&moved, 0, challenges_v1()),
            "a self-consistently moved source span no longer matches the DER node table"
        );
        assert_ne!(
            serial_byte_lookup_factor_v1(
                canonical[BASE_DOCUMENT],
                canonical[BASE_ADDRESS],
                canonical[SERIAL_SOURCE_QUERY_VALUE],
                0,
                challenges_v1(),
            ),
            serial_byte_lookup_factor_v1(
                moved[BASE_DOCUMENT],
                moved[BASE_ADDRESS],
                moved[SERIAL_SOURCE_QUERY_VALUE],
                0,
                challenges_v1(),
            ),
            "a moved content address no longer matches the DER byte table"
        );
    }
    fn assert_serial_group_satisfied_v1(
        comparison: &ZkX509Rfc5280SerialComparisonV1,
        _crl_entries: usize,
        group: usize,
    ) {
        let rows = build_zk_x509_rfc5280_serial_comparison_rows_v1(comparison)
            .expect("canonical serial rows");
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("serial schedule");
        let start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize]
            + group * SERIAL_COMPARISON_WIDTH_V1 * SERIAL_COMPARISON_PHASES_V1;
        for (offset, row) in rows.iter().copied().enumerate() {
            for phase in 0..SERIAL_COMPARISON_PHASES_V1 {
                let physical_offset = offset * SERIAL_COMPARISON_PHASES_V1 + phase;
                let fixed = schedule
                    .fixed_row(start + physical_offset)
                    .expect("verifier-fixed serial row");
                let current = normalized_row_v1(row, &fixed);
                let next = if phase + 1 == SERIAL_COMPARISON_PHASES_V1 {
                    rows.get(offset + 1).copied().unwrap_or(row)
                } else {
                    row
                };
                let (current_aux, next_aux) = serial_comparator_aux_v1(&current);
                let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                    &current,
                    &next,
                    &current_aux,
                    &next_aux,
                    &fixed,
                    der_challenges_v1(),
                    challenges_v1(),
                    terminal_claims_v1(),
                )
                .expect("serial evaluator");
                assert!(
                    residues.iter().all(|residue| *residue == F::ZERO),
                    "serial group {group} logical offset {offset} phase {phase} \
                     must satisfy every residue"
                );
            }
        }
    }
    #[test]
    fn adjacent_order_handles_length_boundary_and_equal_prefix() {
        let boundary = canonical_serial_comparisons_v1(&[0x7f], &[vec![0xff], vec![0x01, 0x00]])
            .expect("0xff is less than 0x0100 by unsigned magnitude");
        assert_eq!(boundary.len(), 3);
        assert_eq!(
            boundary[2].kind,
            ZkX509Rfc5280SerialComparisonKindV1::AdjacentStrictOrder
        );
        assert_serial_group_satisfied_v1(&boundary[2], 2, 2);
        let equal_prefix =
            canonical_serial_comparisons_v1(&[0x02], &[vec![0x01, 0xfe], vec![0x01, 0xff]])
                .expect("equal-prefix magnitudes are ordered by first differing byte");
        assert_serial_group_satisfied_v1(&equal_prefix[2], 2, 2);
    }
    #[test]
    fn duplicate_descending_and_noncanonical_padding_reject() {
        assert_eq!(
            canonical_serial_comparisons_v1(&[7], &[vec![8], vec![8]]),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic)
        );
        assert_eq!(
            canonical_serial_comparisons_v1(&[7], &[vec![9], vec![8]]),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic)
        );
        let mut comparison = canonical_serial_comparisons_v1(&[7], &[vec![8], vec![9]])
            .expect("canonical manifest")
            .pop()
            .expect("adjacent comparison");
        comparison.right[ZK_X509_MAX_SERIAL_BYTES_V1] = 1;
        assert_eq!(
            validate_serial_comparison_v1(&comparison),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic),
            "inactive padded bytes are canonical zeros"
        );
        assert_eq!(
            serial_frame_v1(&[0, 1]),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic),
            "magnitude frames cannot carry a leading zero"
        );
    }
    #[test]
    fn dropped_and_reordered_comparators_fail_exact_manifest_and_fixed_schedule() {
        let revoked = vec![vec![8], vec![9], vec![10]];
        let manifest = canonical_serial_comparisons_v1(&[7], &revoked).expect("canonical manifest");
        assert_eq!(manifest.len(), 5);
        let mut dropped = manifest.clone();
        dropped.remove(1);
        assert_eq!(
            validate_serial_comparison_manifest_v1(&[7], &revoked, &dropped),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic)
        );
        let mut reordered = manifest.clone();
        reordered.swap(0, 1);
        assert_eq!(
            validate_serial_comparison_manifest_v1(&[7], &revoked, &reordered),
            Err(ZkX509Rfc5280StarkErrorV1::Semantic)
        );
        let mut shape = maximum_private_shape_v1();
        shape.crl_entries = 3;
        refresh_private_shape_derived_rows_v1(&mut shape);
        shape.serial_rows -= 1;
        assert_eq!(shape.validate(), Err(ZkX509Rfc5280StarkErrorV1::Shape));
        let comparison = &manifest[2];
        let rows = build_zk_x509_rfc5280_serial_comparison_rows_v1(comparison)
            .expect("adjacent serial rows");
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("serial schedule");
        let serial_start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize];
        let wrong_fixed = schedule
            .fixed_row(serial_start + SERIAL_COMPARISON_PHASES_V1 - 1)
            .expect("first leaf comparator fixed row");
        let current = normalized_row_v1(rows[0], &wrong_fixed);
        let (current_aux, next_aux) = serial_comparator_aux_v1(&current);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &rows[1],
            &current_aux,
            &next_aux,
            &wrong_fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("reordered comparator evaluator");
        assert!(
            residues.iter().any(|residue| *residue != F::ZERO),
            "an adjacent-order row cannot occupy a leaf-comparison slot"
        );
    }
    #[test]
    fn first_difference_and_state_transition_mutations_are_detected() {
        let manifest = canonical_serial_comparisons_v1(&[7], &[vec![0xff], vec![0x01, 0x00]])
            .expect("canonical boundary manifest");
        let comparison = &manifest[2];
        let mut rows = build_zk_x509_rfc5280_serial_comparison_rows_v1(comparison)
            .expect("canonical comparator rows");
        assert_eq!(rows[0][SERIAL_LESS], F::ONE);
        rows[0][SERIAL_LESS] = F::ZERO;
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("serial schedule");
        let start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize]
            + 2 * SERIAL_COMPARISON_WIDTH_V1 * SERIAL_COMPARISON_PHASES_V1;
        let fixed = schedule
            .fixed_row(start + SERIAL_COMPARISON_PHASES_V1 - 1)
            .expect("adjacent comparator fixed row");
        let current = normalized_row_v1(rows[0], &fixed);
        let (current_aux, next_aux) = serial_comparator_aux_v1(&current);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &rows[1],
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("mutated comparator evaluator");
        assert!(
            residues.iter().any(|residue| *residue != F::ZERO),
            "the first-difference success bit is algebraically linked"
        );
        // Use an equal-length pair with an equal first payload byte so the
        // canonical prefix state entering the second payload row is one.
        // The former boundary fixture had already transitioned to zero on its
        // length row, making a write of zero a no-op rather than a mutation.
        let state_manifest =
            canonical_serial_comparisons_v1(&[7], &[vec![0x01, 0x02], vec![0x01, 0x03]])
                .expect("canonical equal-prefix manifest");
        let mut rows = build_zk_x509_rfc5280_serial_comparison_rows_v1(&state_manifest[2])
            .expect("canonical equal-prefix comparator rows");
        assert_eq!(rows[0][BASE_STATE_AFTER], F::ONE);
        assert_eq!(rows[1][BASE_STATE_BEFORE], F::ONE);
        rows[1][BASE_STATE_BEFORE] = F::ZERO;
        let current = normalized_row_v1(rows[0], &fixed);
        let (current_aux, next_aux) = serial_comparator_aux_v1(&current);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &rows[1],
            &current_aux,
            &next_aux,
            &fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .expect("mutated transition evaluator");
        assert!(
            residues.iter().any(|residue| *residue != F::ZERO),
            "prefix state cannot be reset between comparator rows"
        );
    }
    #[test]
    fn proof_rows_reject_zero_oversized_alias_leading_zero_and_inactive_bytes() {
        let mut comparisons =
            canonical_serial_comparisons_v1(&[7], &[vec![8]]).expect("canonical comparison");
        let comparison = comparisons.remove(0);
        let canonical =
            build_zk_x509_rfc5280_serial_comparison_rows_v1(&comparison).expect("canonical rows");
        let schedule =
            compile_zk_x509_rfc5280_stark_fixed_schedule_v1(ZkX509Rfc5280StarkShapeV1::default())
                .expect("serial schedule");
        let start = schedule.starts[ZkX509Rfc5280StarkFamilyV1::SerialCompare as usize];
        let rejects = |rows: &[ZkX509Rfc5280StarkBaseRowV1], offset: usize, label: &str| {
            let fixed = schedule
                .fixed_row(
                    start + offset * SERIAL_COMPARISON_PHASES_V1 + SERIAL_COMPARISON_PHASES_V1 - 1,
                )
                .expect("fixed comparator row");
            let next = rows.get(offset + 1).unwrap_or(&rows[offset]);
            let current = normalized_row_v1(rows[offset], &fixed);
            let (current_aux, next_aux) = serial_comparator_aux_v1(&current);
            let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                &current,
                next,
                &current_aux,
                &next_aux,
                &fixed,
                der_challenges_v1(),
                challenges_v1(),
                terminal_claims_v1(),
            )
            .expect("mutated comparator evaluator");
            assert!(
                residues.iter().any(|residue| *residue != F::ZERO),
                "{label} must violate an algebraic comparator constraint"
            );
        };
        let mut zero_length = canonical.clone();
        zero_length[0][BASE_A] = F::ZERO;
        zero_length[0][SERIAL_LEFT_LENGTH] = F::ZERO;
        write_u8_bits_v1(&mut zero_length[0], SERIAL_LEFT_BITS, 0);
        rejects(&zero_length, 0, "zero length");
        let mut oversized_length = canonical.clone();
        oversized_length[0][BASE_A] = F(21);
        oversized_length[0][SERIAL_LEFT_LENGTH] = F(21);
        write_u8_bits_v1(&mut oversized_length[0], SERIAL_LEFT_BITS, 21);
        rejects(&oversized_length, 0, "length 21");
        let mut leading_zero = canonical.clone();
        leading_zero[1][BASE_A] = F::ZERO;
        leading_zero[1][BASE_INVERSE] = F::ZERO;
        write_u8_bits_v1(&mut leading_zero[1], SERIAL_LEFT_BITS, 0);
        rejects(&leading_zero, 1, "leading zero");
        let mut inactive_nonzero = canonical.clone();
        let last = SERIAL_COMPARISON_WIDTH_V1 - 1;
        inactive_nonzero[last][BASE_A] = F::ONE;
        inactive_nonzero[last][BASE_B] = F::ONE;
        write_u8_bits_v1(&mut inactive_nonzero[last], SERIAL_LEFT_BITS, 1);
        write_u8_bits_v1(&mut inactive_nonzero[last], SERIAL_RIGHT_BITS, 1);
        rejects(&inactive_nonzero, last, "nonzero inactive padding");
        let mut length_alias = canonical;
        length_alias[last][SERIAL_LEFT_LENGTH] = F(2);
        rejects(&length_alias, last, "value-preserving length/padding alias");
    }
    fn metadata_columns_v1() -> [usize; 6] {
        [
            BASE_ROLE,
            BASE_INSTANCE,
            BASE_ENDPOINT_ROLE,
            BASE_ENDPOINT_INSTANCE,
            BASE_OFFSET,
            BASE_IS_WRITE,
        ]
    }
    #[test]
    fn output_metadata_matches_every_verifier_owned_output_position() {
        for count in 0..=4_u8 {
            let mut shape = ZkX509Rfc5280StarkShapeV1::default();
            shape.disclosed_attribute_count = count;
            assert_eq!(shape.disclosed_attribute_count(), count);
            for index in 0..usize::from(count) {
                shape.disclosed_attribute_indices[index] = index as u8;
            }
            let schedule = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(shape).unwrap();
            for consumer in [false, true] {
                let family = if consumer {
                    ZkX509Rfc5280StarkFamilyV1::OutputConsumer
                } else {
                    ZkX509Rfc5280StarkFamilyV1::OutputProducer
                };
                for (ordinal, entry) in schedule.output_topology.iter().enumerate() {
                    let fixed = schedule
                        .fixed_row(schedule.starts[family as usize] + ordinal)
                        .unwrap();
                    let expected = [
                        F(entry.role as u64),
                        F(u64::from(entry.channel)),
                        F(u64::from(if consumer {
                            entry.consumer_endpoint_role
                        } else {
                            entry.producer_endpoint_role
                        })),
                        F(u64::from(entry.endpoint_instance)),
                        F(u64::from(entry.offset)),
                        F(u64::from(!consumer)),
                    ];
                    assert_eq!(&fixed[FIX_EXPECTED..FIX_EXPECTED + 6], &expected);
                    let mut current = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
                    current[BASE_ACTIVE] = F::ONE;
                    for (column, value) in metadata_columns_v1().into_iter().zip(expected) {
                        current[column] = value;
                    }
                    assert_eq!(output_metadata_residues_v1(&current, &fixed), [F::ZERO; 6]);
                }
            }
        }
    }
    #[test]
    fn output_metadata_rejects_each_coherently_changed_current_and_next_field() {
        for consumer in [false, true] {
            let family = if consumer {
                ZkX509Rfc5280StarkFamilyV1::OutputConsumer
            } else {
                ZkX509Rfc5280StarkFamilyV1::OutputProducer
            };
            let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
            fixed[family as usize] = F::ONE;
            fixed[FIX_EXPECTED..FIX_EXPECTED + 6].copy_from_slice(&[
                F(2),
                F(11),
                F(3),
                F(0),
                F(7),
                F(u64::from(!consumer)),
            ]);
            let mut current = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
            current[BASE_ACTIVE] = F::ONE;
            for (i, column) in metadata_columns_v1().into_iter().enumerate() {
                current[column] = fixed[FIX_EXPECTED + i];
            }
            let offset = RFC5280_RESIDUE_SECTIONS_V1[..11]
                .iter()
                .map(|section| section.1)
                .sum::<usize>();
            for (index, column) in metadata_columns_v1().into_iter().enumerate() {
                let mut changed = current;
                changed[column] = changed[column].add(F::ONE);
                let direct = output_metadata_residues_v1(&changed, &fixed);
                for (i, residue) in direct.iter().enumerate() {
                    assert_eq!(*residue, F(u64::from(i == index)));
                }
                // Changing next identically cannot repair the verifier-fixed current label.
                let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
                    &changed,
                    &changed,
                    &neutral_aux_v1(),
                    &neutral_aux_v1(),
                    &fixed,
                    der_challenges_v1(),
                    challenges_v1(),
                    terminal_claims_v1(),
                )
                .unwrap();
                assert_eq!(&residues[offset..offset + 6], &direct);
            }
            // Value extraction is deliberately outside this metadata-only relation.
            current[BASE_VALUE] = F(251);
            assert_eq!(output_metadata_residues_v1(&current, &fixed), [F::ZERO; 6]);
        }
    }
    #[test]
    fn output_metadata_preserves_padding_and_required_activity_guards() {
        let current = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
        let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
        fixed[ZkX509Rfc5280StarkFamilyV1::Padding as usize] = F::ONE;
        assert_eq!(output_metadata_residues_v1(&current, &fixed), [F::ZERO; 6]);
        assert!(
            private_geometry_residues_v1(&current, &current, &fixed)
                .iter()
                .all(|v| *v == F::ZERO)
        );
        for column in metadata_columns_v1() {
            let mut changed = current;
            changed[column] = F::ONE;
            assert!(
                private_geometry_residues_v1(&changed, &changed, &fixed)
                    .iter()
                    .any(|v| *v != F::ZERO)
            );
        }
        for family in [
            ZkX509Rfc5280StarkFamilyV1::OutputProducer,
            ZkX509Rfc5280StarkFamilyV1::OutputConsumer,
        ] {
            fixed.fill(F::ZERO);
            fixed[family as usize] = F::ONE;
            fixed[FIX_REQUIRED_ACTIVE] = F::ONE;
            assert!(
                private_geometry_residues_v1(&current, &current, &fixed)
                    .iter()
                    .any(|v| *v != F::ZERO)
            );
        }
    }
    #[test]
    fn output_metadata_fp4_uses_nonboolean_opened_selectors_and_full_evaluator() {
        use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
        let current = core::array::from_fn(|i| E::canonical([i as u64 + 1, 3, 5, 7]).unwrap());
        let fixed = core::array::from_fn(|i| E::canonical([i as u64 + 11, 13, 17, 19]).unwrap());
        let gate = fixed[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize]
            .add(fixed[ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize])
            .mul(current[BASE_ACTIVE]);
        let expected = metadata_columns_v1().map(|column| current[column]);
        let expected =
            core::array::from_fn::<_, 6, _>(|i| gate.mul(expected[i].sub(fixed[FIX_EXPECTED + i])));
        assert_eq!(output_metadata_residues_v1(&current, &fixed), expected);
        let aux = neutral_aux_v1().map(E::from_base);
        let residues = evaluate_zk_x509_rfc5280_stark_residues_v1(
            &current,
            &current,
            &aux,
            &aux,
            &fixed,
            der_challenges_v1(),
            challenges_v1(),
            terminal_claims_v1(),
        )
        .unwrap();
        let offset = RFC5280_RESIDUE_SECTIONS_V1[..11]
            .iter()
            .map(|section| section.1)
            .sum::<usize>();
        assert_eq!(&residues[offset..offset + 6], &expected);
        assert!(expected.iter().any(|v| *v != E::ZERO));
        for consumer in [false, true] {
            let mut base = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
            let mut fixed_base = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
            base[BASE_ACTIVE] = F::ONE;
            fixed_base[if consumer {
                ZkX509Rfc5280StarkFamilyV1::OutputConsumer
            } else {
                ZkX509Rfc5280StarkFamilyV1::OutputProducer
            } as usize] = F::ONE;
            for column in metadata_columns_v1() {
                base[column] = F(31);
            }
            assert_eq!(
                output_metadata_residues_v1(&base, &fixed_base).map(E::from_base),
                output_metadata_residues_v1(&base.map(E::from_base), &fixed_base.map(E::from_base))
            );
        }
    }
    #[test]
    fn output_metadata_each_residue_has_total_affine_degree_three() {
        let samples = (0..7)
            .map(|point| {
                let current = core::array::from_fn(|column| affine_value_v1(7, 1, column, point));
                let fixed = core::array::from_fn(|column| affine_value_v1(7, 5, column, point));
                output_metadata_residues_v1(&current, &fixed)
            })
            .collect::<Vec<_>>();
        for index in 0..6 {
            assert_eq!(
                finite_difference_degree_v1(samples.iter().map(|row| row[index]).collect()),
                3
            );
        }
        assert_eq!(ZK_X509_RFC5280_STARK_CONSTRAINT_COUNT_V1, 2_149);
        assert_eq!(
            (
                ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
                ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
                ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1,
                ZK_X509_RFC5280_STARK_TRACE_LOG2_V1,
                ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1
            ),
            (285, 280, 147, 19, 4)
        );
    }
    #[test]
    fn output_metadata_suppresses_other_families_and_preserves_optional_selector() {
        use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
        let current = core::array::from_fn(|i| E::canonical([i as u64 + 1, 2, 3, 4]).unwrap());
        let mut fixed = core::array::from_fn(|i| E::canonical([i as u64 + 7, 11, 13, 17]).unwrap());
        fixed[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] = E::ZERO;
        fixed[ZkX509Rfc5280StarkFamilyV1::OutputConsumer as usize] = E::ZERO;
        assert_eq!(output_metadata_residues_v1(&current, &fixed), [E::ZERO; 6]);
        for active in [F::ZERO, F::ONE] {
            let mut current = [F::ZERO; ZK_X509_RFC5280_STARK_BASE_WIDTH_V1];
            let mut fixed = [F::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
            current[BASE_ACTIVE] = F::ONE;
            current[BASE_CERT2_ACTIVE] = active;
            current[BASE_VALUE] = active;
            fixed[ZkX509Rfc5280StarkFamilyV1::OutputProducer as usize] = F::ONE;
            fixed[FIX_CERT2_OUTPUT] = F::ONE;
            fixed[FIX_REQUIRED_ACTIVE] = F::ONE;
            assert_eq!(output_metadata_residues_v1(&current, &fixed), [F::ZERO; 6]);
            assert!(
                private_geometry_residues_v1(&current, &current, &fixed)
                    .iter()
                    .all(|v| *v == F::ZERO)
            );
            current[BASE_VALUE] = F::ONE.sub(active);
            assert!(
                private_geometry_residues_v1(&current, &current, &fixed)
                    .iter()
                    .any(|v| *v != F::ZERO)
            );
        }
    }
    include!("rfc5280_nonkey_provenance_tests.rs");
    include!("rfc5280_sha_union_tests.rs");
    include!("rfc5280_aux_batch_tests.rs");
}
