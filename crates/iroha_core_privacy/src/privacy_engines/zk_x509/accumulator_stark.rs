//! Proof-facing adapter for compact trust-anchor membership.
//!
//! The adapter registers one log-twelve trace. Thirteen rows own the exact shared SHA calls for one
//! occupied leaf and twelve internal nodes, and 91 rows serialize the root SPKI with one reusable
//! byte decomposition. Four independently challenged running products bind those bytes
//! simultaneously to the leaf SHA input and strict-DER output consumer. Two SHA factors are
//! advanced per hash row, keeping the maximum committed-column degree at three.
#[cfg(test)]
use super::accumulator_air::ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::accumulator_air::ZkX509CaAccumulatorTraceV1;
#[cfg(test)]
use super::proof_instance::TEST_PROOF_INSTANCE_V1;
use super::proof_instance::ZkX509ProofInstanceV1;
use super::{
    accumulator_air::{
        CA_CURRENT_START, CA_DIGEST_BYTE_BITS_START, CA_DIGEST_START, CA_DIRECTION,
        CA_INDEX_BITS_START, CA_IO_BYTE, CA_IO_BYTE_BITS_START, CA_IO_WORD_ACC, CA_LEFT_START,
        CA_RIGHT_START, CA_SIBLING_BYTE_BITS_START, CA_SIBLING_START,
        ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1, ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1,
        ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1, ZK_X509_CA_ACCUMULATOR_IO_ROWS_V1,
        ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1, ZK_X509_CA_LEAF_SPKI_MESSAGE_OFFSET_V1,
        ZK_X509_CA_LEAF_SPKI_PREFIX_BYTE_V1, ZkX509AccumulatorAirErrorV1,
        ZkX509CaAccumulatorRowKindV1, ca_accumulator_fixed_row_v1,
    },
    credential_pre_aux::{
        ZkX509CredentialMainPreAuxV1, ZkX509CredentialPreAuxErrorV1,
        absorb_zk_x509_credential_pre_aux_binding_v1, derive_zk_x509_credential_pre_aux_binding_v1,
    },
    merkle::{
        ZK_X509_CA_COMPACT_TREE_DEPTH_V1, ZK_X509_CA_SPKI_DER_BYTES_V1, ZkX509MerkleErrorV1,
        ca_leaf_preimage_v1, ca_node_preimage_v1,
    },
    profile::{
        ZK_X509_CA_COMPOSITION_DEGREE_CHUNKS_V1, ZK_X509_CA_FRI_LDE_LOG2_V1,
        ZK_X509_CA_FRI_ROUNDS_V1, ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1,
        ZK_X509_CA_FRI_TERMINAL_LOG2_V1, ZK_X509_CA_PRE_DEEP_MAXIMUM_BYTES_V1,
        ZK_X509_CA_TRACE_MASK_DEGREE_V1, ZK_X509_FRI_QUERY_COUNT_V1, ZK_X509_GRINDING_BITS_V1,
        ZK_X509_MAX_PROOF_BYTES_V1, ZK_X509_PROOF_VERSION_V1, ZK_X509_SUITE_V1,
    },
    rfc5280_stark::{
        ZK_X509_RFC5280_STARK_BUS_LANES_V1, ZkX509Rfc5280OutputRoleV1,
        ZkX509Rfc5280StarkChallengesV1,
    },
    sha_call_bus_stark::{
        ZK_X509_SHA_BUS_LANES_V1, ZK_X509_SHA_CA_LEAF_CALL_V1, ZK_X509_SHA_CA_NODE_CALL_START_V1,
        ZkX509ShaCallActivationV1, ZkX509ShaCallBusChallengesV1, ZkX509ShaCallRoleV1,
        ZkX509ShaCallScheduleV1, ZkX509ShaCallWordKindV1, compress_sha_call_fields_v1,
    },
    stark::ZK_X509_FIXED_DIGEST_CONTEXT_V1,
};
#[cfg(test)]
use crate::privacy_engines::prover_randomness::{
    HealthCheckedTryCryptoRngV1, TryCryptoProverRandomnessErrorV1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_engines::transparent_stark::{
    GOLDILOCKS_GENERATOR_V1, goldilocks_evaluate_coset_v1, grind_nonce_v1,
};
use crate::privacy_engines::{
    aggregate_stark::{self as aggregate, AggregateStarkErrorV1},
    prover_randomness::TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1,
    transparent_stark::{
        GoldilocksFieldV1 as F, GoldilocksFp4V1 as E, PolynomialAirFieldV1, PrivacyOuterDigestV1,
        TransparentStarkErrorV1, TransparentTranscriptV1, append_u16_v1, append_u32_v1,
        append_u64_v1, goldilocks_ifft_v1, goldilocks_primitive_root_v1,
        privacy_outer_digest_frame_v1, transparent_stark_zk_mask_geometry_v1,
        verify_grinding_nonce_v1,
    },
};
use thiserror::Error;
#[path = "accumulator_joint_verifier.rs"]
pub mod joint_verifier;
#[cfg(test)]
#[path = "accumulator_stark_oods_tests.rs"]
mod oods_tests;
#[path = "accumulator_private_links.rs"]
pub mod private_links;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "accumulator_retained_columns.rs"]
mod retained_columns;
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[path = "accumulator_stages.rs"]
pub mod stages;
/// Native trace logarithm for 104 non-padding rows.
pub const ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1: u8 = 12;
/// SHA call products plus serialized SHA-source and RFC-output products.
pub const ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1: usize = 128;
/// Verifier-preprocessed row selectors, source constants, and I/O schedule.
pub const ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1: usize = 80;
/// SHA within-row identities plus serialized product initialization,
/// transition, and canonical-zero identities.
pub const ZK_X509_CA_ACCUMULATOR_AUX_CONSTRAINT_COUNT_V1: usize = 144;
/// Complete local base/auxiliary relation before cross-proof endpoint binding.
/// This is not a standalone relation: the mandatory joint MAIN composition
/// binds the omitted endpoints through 108 original-polynomial quotients.
pub const ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1: usize =
    ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1
        + ZK_X509_CA_ACCUMULATOR_AUX_CONSTRAINT_COUNT_V1;
/// Exact opened-row residue count.
pub const ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1: usize =
    ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1
        + ZK_X509_CA_ACCUMULATOR_AUX_CONSTRAINT_COUNT_V1
        + ZK_X509_CA_ACCUMULATOR_TERMINAL_CONSTRAINT_COUNT_V1;
/// Two SHA families, the completed leaf source, and root-SPKI I/O terminal.
pub const ZK_X509_CA_ACCUMULATOR_TERMINAL_CONSTRAINT_COUNT_V1: usize = 4 * ZK_X509_SHA_BUS_LANES_V1;
/// Maximum committed-column degree in any residue.
pub const ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1: u8 = 3;
/// Haböck--Al Kindi reduced AIR degree `d = d_AIR - 1`.
pub const ZK_X509_CA_ACCUMULATOR_REDUCED_AIR_DEGREE_V1: usize =
    ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1 as usize - 1;
/// Physical 64-column base chunks.
pub const ZK_X509_CA_ACCUMULATOR_BASE_CHUNKS_V1: usize =
    ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1.div_ceil(64);
/// Physical 64-column auxiliary chunks.
pub const ZK_X509_CA_ACCUMULATOR_AUX_CHUNKS_V1: usize =
    ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1.div_ceil(64);
/// Total physical commitment chunks.
pub const ZK_X509_CA_ACCUMULATOR_CHUNKS_V1: usize =
    ZK_X509_CA_ACCUMULATOR_BASE_CHUNKS_V1 + ZK_X509_CA_ACCUMULATOR_AUX_CHUNKS_V1;
/// Numerator of the exact FRI degree-cap-to-LDE-size ratio.
pub const ZK_X509_CA_ACCUMULATOR_FRI_RATE_NUMERATOR_V1: usize = 9;
/// Denominator of the exact FRI degree-cap-to-LDE-size ratio.
pub const ZK_X509_CA_ACCUMULATOR_FRI_RATE_DENOMINATOR_V1: usize = 64;
/// Authenticated scratch rows per independently decrypted block.
///
/// A fixed 128-row block bounds a simultaneous current/next base, aux,
/// and fixed working set below two MiB.  A prover must not silently substitute
/// the common full-profile domain or a larger scratch block.
pub const ZK_X509_CA_ACCUMULATOR_SCRATCH_CHUNK_ROWS_V1: usize = 128;
/// The first release uses one Fp4 composition lane.
pub const ZK_X509_CA_ACCUMULATOR_COMPOSITION_EXTENSION_LANES_V1: usize = 1;
/// Number of base-field components in the release Fp4 lane.
pub const ZK_X509_CA_ACCUMULATOR_EXTENSION_COMPONENTS_V1: usize = 4;
const FIELD_BYTES_V1: usize = core::mem::size_of::<F>();
const COMPOSITION_DEGREE_CHUNKS_V1: usize = ZK_X509_CA_COMPOSITION_DEGREE_CHUNKS_V1 as usize;
const SCRATCH_TAG_BYTES_V1: usize = 16;
/// Governed ceiling for challenge-independent native material.
pub const ZK_X509_CA_ACCUMULATOR_MAX_NATIVE_MATERIAL_BYTES_V1: usize = 64 << 20;
/// Governed ceiling for all local base, aux, and fixed LDE field payloads.
pub const ZK_X509_CA_ACCUMULATOR_MAX_LOCAL_LDE_BYTES_V1: usize = 512 << 20;
/// Governed ceiling for authenticated local trace scratch.
pub const ZK_X509_CA_ACCUMULATOR_MAX_LOCAL_SCRATCH_BYTES_V1: usize = 512 << 20;
/// Governed ceiling for the CA adapter's peak resident field payload.
///
/// The first-release producer materializes the complete local LDE.  This
/// ceiling therefore includes that LDE instead of claiming the lower resident
/// bound of a future streaming implementation.  It excludes only the generic
/// Merkle/FRI engine, whose independent ceiling is enforced by the local subproof prover.
pub const ZK_X509_CA_ACCUMULATOR_MAX_ADAPTER_RESIDENT_BYTES_V1: usize = 640 << 20;
/// Governed ceiling for native-to-local-LDE radix-2 butterflies.
pub const ZK_X509_CA_ACCUMULATOR_MAX_LDE_BUTTERFLIES_V1: usize = 600_000_000;
/// Governed ceiling for base-field component constraint evaluations.
pub const ZK_X509_CA_ACCUMULATOR_MAX_COMPOSITION_COMPONENT_EVALUATIONS_V1: usize = 400_000_000;
const SOURCE_WORDS_V1: usize = 48;
const DIGEST_WORDS_V1: usize = 8;
const SOURCE_PAIR_STEPS_V1: usize = SOURCE_WORDS_V1 / 2;
const DIGEST_PAIR_STEPS_V1: usize = DIGEST_WORDS_V1 / 2;
const SOURCE_STATES_V1: usize = SOURCE_PAIR_STEPS_V1 + 1;
const DIGEST_STATES_V1: usize = DIGEST_PAIR_STEPS_V1 + 1;
const SOURCE_AUX_START: usize = 0;
const DIGEST_AUX_START: usize = SOURCE_STATES_V1 * ZK_X509_SHA_BUS_LANES_V1;
const SERIALIZED_SHA_PRODUCT_START: usize =
    DIGEST_AUX_START + DIGEST_STATES_V1 * ZK_X509_SHA_BUS_LANES_V1;
const ROOT_SPKI_IO_PRODUCT_START: usize = SERIALIZED_SHA_PRODUCT_START + ZK_X509_SHA_BUS_LANES_V1;
/// Canonical root-SPKI channel before two channels per public disclosure.
pub const ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_BASE_CHANNEL_V1: u32 = 30;
/// Exact number of root-SPKI consumer events.
#[cfg(test)]
pub const ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_IO_EVENTS_V1: u16 = ZK_X509_CA_SPKI_DER_BYTES_V1 as u16;
const FIX_ACTIVE: usize = 0;
const FIX_LEAF: usize = 1;
const FIX_NODE: usize = 2;
const FIX_PADDING: usize = 3;
const FIX_TRANSITION: usize = 4;
const FIX_LAST: usize = 5;
const FIX_LEVEL: usize = 6;
const FIX_CALL: usize = 7;
const FIX_ROLE: usize = 8;
const FIX_SLOT: usize = 9;
const FIX_INDEX_SELECTORS_START: usize = 10;
const FIX_SOURCE_CONSTANTS_START: usize =
    FIX_INDEX_SELECTORS_START + ZK_X509_CA_COMPACT_TREE_DEPTH_V1;
const FIX_IO_ACTIVE: usize = FIX_SOURCE_CONSTANTS_START + SOURCE_WORDS_V1;
const FIX_IO_FIRST: usize = FIX_IO_ACTIVE + 1;
const FIX_IO_LAST: usize = FIX_IO_FIRST + 1;
const FIX_IO_TRANSITION: usize = FIX_IO_LAST + 1;
const FIX_IO_SAME_WORD_TO_NEXT: usize = FIX_IO_TRANSITION + 1;
const FIX_IO_WORD_END: usize = FIX_IO_SAME_WORD_TO_NEXT + 1;
const FIX_IO_OFFSET: usize = FIX_IO_WORD_END + 1;
const FIX_IO_WORD_INDEX: usize = FIX_IO_OFFSET + 1;
const FIX_IO_NEXT_WORD_END: usize = FIX_IO_WORD_INDEX + 1;
const FIX_IO_NEXT_WORD_INDEX: usize = FIX_IO_NEXT_WORD_END + 1;
const LEAF_DYNAMIC_OFFSET_V1: usize = ZK_X509_CA_LEAF_SPKI_MESSAGE_OFFSET_V1;
const NODE_LEFT_DYNAMIC_OFFSET_V1: usize = 75;
const NODE_RIGHT_DYNAMIC_OFFSET_V1: usize = 115;
const LEAF_DYNAMIC_WORD_START_V1: usize = LEAF_DYNAMIC_OFFSET_V1 / 4;
const LEAF_DYNAMIC_WORD_END_V1: usize =
    (LEAF_DYNAMIC_OFFSET_V1 + ZK_X509_CA_SPKI_DER_BYTES_V1 - 1) / 4;
const _: () = {
    assert!(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 == 1 << ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1);
    assert!(ZK_X509_SHA_BUS_LANES_V1 == ZK_X509_RFC5280_STARK_BUS_LANES_V1);
    assert!(
        ROOT_SPKI_IO_PRODUCT_START + ZK_X509_RFC5280_STARK_BUS_LANES_V1
            == ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
    );
    assert!(ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1 == 128);
    assert!(ZK_X509_CA_ACCUMULATOR_AUX_CONSTRAINT_COUNT_V1 == 144);
    assert!(FIX_IO_NEXT_WORD_INDEX + 1 == ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1);
    assert!(ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1 == 1_379);
    assert!(ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1 == 3);
    assert!(ZK_X509_CA_ACCUMULATOR_REDUCED_AIR_DEGREE_V1 == 2);
    assert!(COMPOSITION_DEGREE_CHUNKS_V1 == 4);
    assert!(ZK_X509_CA_ACCUMULATOR_BASE_CHUNKS_V1 == 11);
    assert!(ZK_X509_CA_ACCUMULATOR_AUX_CHUNKS_V1 == 2);
    assert!(ZK_X509_CA_ACCUMULATOR_CHUNKS_V1 == 13);
    assert!(FIELD_BYTES_V1 == 8);
    assert!(ZK_X509_CA_ACCUMULATOR_SCRATCH_CHUNK_ROWS_V1 == 128);
    assert!(LEAF_DYNAMIC_WORD_START_V1 == 16);
    assert!(LEAF_DYNAMIC_WORD_END_V1 == 38);
};
/// Stable proof-facing compact accumulator identity.
pub const ZK_X509_ACCUMULATOR_STARK_DESCRIPTOR_V1: &[u8] = b"zk-x509-ca-accumulator-stark-v1:dedicated-local-subproof-only:wire-envelope-X5C1+inner-X5C2:strict-version-length-and-no-trailing-bytes:claim-free-frame10bytes:inner-predeep-max1446016:inner-deep52800:subproof-max1498826:single-log12-trace4096:dedicated-lde-log16:compiled-max-air-degree3:haboeck-al-kindi-reduced-air-degree2:protocol3-trace-mask:haboeck-al-kindi-h-min=2*2*(4*n-deep+n-fri)+n-fri:trace-mask2100-coefficients-with108-translated-original-openings:max-fri-rate9over64:fri136-distinct-post-grinding20:fri-ordered-low-high-pair-leaves:binary-fri6-rounds-terminal1024-degree143:independent-fp4-fri-mask-root-before-deep-batching:one-MAIN-and-CA-joint-deep-point-current+next-plus108-translated-original-aux:both-local-checkpoints-and-both-original-composition-and-FRI-mask-roots-before-point:both-local-DEEP-plus-MAIN31-key-and-orderedMAIN24-CA108-before-independent-mixes:complete-fp4-local-air1363-and-verifier-fixed-polynomials-at-deep:current-only-queries-after-complete-oods-no-scalar-query-callback:fp4-composition-lanes1:fixed-selector-aware-maximum-quotient-degree22679:composition-degree-chunks4:canonical-chunk-stride9079:independent-adjacent-fp4-masks137-before-commitment:scratch-chunk-rows128:common-domain-lifting-forbidden:first-release-materializes-complete-local-lde:checked-native-lde-scratch-resident-and-work-ceilings:hash-rows13:serialized-root-spki-rows91:nonpadding104:zero-padding3992:base695-11chunks:aux128-2chunks:fixed80:constraints1363:degree3:private-index12-and-siblings12:leaf-call16:nodes-calls17through28:source48words+digest8words:four-independent-sha-call-lanes:two-affine-factors-per-hash-row:leaf-dynamic-source-words16through38-serialized:reusable-eight-bit-byte-range:big-endian-word-accumulator:root-spki-channel=30+2*public-disclosures:endpoint-role-ca-accumulator4:governed-trust-anchor-role8:rfc-output-tuple-tag80:four-independent-rfc-output-lanes:dual-running-products-sha-source-and-rfc-consumer:all-four-terminal-families-algebraically-bound:joint-original-polynomial-MAIN108-links=ordered-sha13-source-and-digest-plus-rfc91-root-consumer:no-public-terminal-products:shared-X5S1-pre-aux-after-one-joined-main-plus-one-ca-base-roots:public-governed-root-and-root-spki-channel:rand0.9-trycrypto-fixed64-reservoir-health-check-zeroize-poison-error-or-unwind:deterministic-preflight-before-entropy:producer-self-verifies:no-crl-accumulator";
const CA_PROOF_MAGIC_V1: [u8; 4] = *b"X5C1";
const CA_INNER_PROOF_MAGIC_V1: [u8; 4] = *b"X5C2";
const CA_ADAPTER_ID_V1: u16 = 5;
const CA_SECURITY_LANES_V1: usize = 1;
const CA_QUERY_COUNT_V1: usize = ZK_X509_FRI_QUERY_COUNT_V1 as usize;
const CA_BLOWUP_LOG2_V1: u8 = ZK_X509_CA_FRI_LDE_LOG2_V1 - ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1;
const CA_TERMINAL_LOG2_V1: u8 = ZK_X509_CA_FRI_TERMINAL_LOG2_V1;
const CA_TERMINAL_DEGREE_BOUND_V1: usize = ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1 as usize;
const CA_COMPOSITION_DEGREE_CHUNKS_V1: usize = ZK_X509_CA_COMPOSITION_DEGREE_CHUNKS_V1 as usize;
const CA_MASK_DEGREE_V1: usize = ZK_X509_CA_TRACE_MASK_DEGREE_V1 as usize;
const CA_DEEP_FIELD_COUNT_V1: usize = 2
    * (ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1 + ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1)
    + CA_COMPOSITION_DEGREE_CHUNKS_V1;
const CA_DEEP_BYTES_V1: usize = CA_DEEP_FIELD_COUNT_V1 * core::mem::size_of::<[u64; 4]>();
const CA_INNER_MAXIMUM_PROOF_BYTES_V1: usize =
    ZK_X509_CA_PRE_DEEP_MAXIMUM_BYTES_V1 as usize + CA_DEEP_BYTES_V1;
const CA_PROOF_LENGTH_OFFSET_V1: usize = 4 + 2;
const CA_PROOF_ENVELOPE_BYTES_V1: usize = CA_PROOF_LENGTH_OFFSET_V1 + 4;
/// Exact typed-claim envelope bytes, excluding the inner aggregate proof.
#[cfg(test)]
pub const ZK_X509_CA_ACCUMULATOR_FRAME_BYTES_V1: usize = CA_PROOF_ENVELOPE_BYTES_V1;
/// Exact dedicated compact-CA DEEP payload bytes.
#[cfg(test)]
pub const ZK_X509_CA_ACCUMULATOR_DEEP_OPENING_BYTES_V1: usize = CA_DEEP_BYTES_V1;
/// Exact maximum inner X5C2 bytes including its DEEP payload.
#[cfg(test)]
pub const ZK_X509_CA_ACCUMULATOR_INNER_MAX_PROOF_BYTES_V1: usize = CA_INNER_MAXIMUM_PROOF_BYTES_V1;
/// Exact hard ceiling for the dedicated compact-CA proof envelope.
pub const ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1: usize =
    CA_PROOF_ENVELOPE_BYTES_V1 + CA_INNER_MAXIMUM_PROOF_BYTES_V1;
const CA_BASE_LEAF_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:base-leaf:v1";
const CA_BASE_NODE_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:base-node:v1";
const CA_AUX_LEAF_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:aux-leaf:v1";
const CA_AUX_NODE_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:aux-node:v1";
const CA_COMPOSITION_LEAF_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:composition-leaf:v1";
const CA_COMPOSITION_NODE_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:composition-node:v1";
const CA_FRI_LEAF_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:fri-leaf:v1";
const CA_FRI_NODE_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:fri-node:v1";
const CA_LAYOUT_LABEL_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:aggregate-layout:v1";
const CA_BASE_ROOT_LABEL_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:base-root:v1";
const CA_AUX_ROOT_LABEL_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:aux-root:v1";
const CA_COMPOSITION_ROOT_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:composition-root:v1";
const CA_FRI_ROOT_LABEL_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:fri-root:v1";
const CA_FRI_BETA_LABEL_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:fri-beta:v1";
const CA_QUERY_SEED_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:query-seed:v1";
const CA_RELATION_LAYOUT_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:relation-layout:v1";
const CA_PROFILE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:profile-digest:v1";
const CA_PUBLIC_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:public-digest:v1";
const CA_SCHEDULE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:schedule-digest:v1";
const CA_REGISTRATION_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:ca-accumulator:registration:v1";
const CA_CONSTRAINT_ALPHA_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:constraint-alpha:v1";
const CA_DEEP_BASE_CURRENT_MIX_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:deep-base-current-mix:v1";
const CA_DEEP_BASE_NEXT_MIX_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:deep-base-next-mix:v1";
const CA_DEEP_AUX_CURRENT_MIX_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:deep-aux-current-mix:v1";
const CA_DEEP_AUX_NEXT_MIX_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:deep-aux-next-mix:v1";
const CA_DEEP_COMPOSITION_MIX_LABEL_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:deep-composition-mix:v1";
const CA_GRINDING_NONCE_DOMAIN_V1: &[u8] =
    b"iroha:privacy:zk-x509:ca-accumulator:grinding-nonce:v1";
pub(super) const CA_AGGREGATE_PARAMETERS_V1: aggregate::AggregateStarkParametersV1 =
    aggregate::AggregateStarkParametersV1 {
        proof_magic: CA_INNER_PROOF_MAGIC_V1,
        proof_version: ZK_X509_PROOF_VERSION_V1,
        fri_commitment_layout: aggregate::AggregateFriCommitmentLayoutV1::Paired,
        security_lanes: CA_SECURITY_LANES_V1,
        query_count: CA_QUERY_COUNT_V1,
        blowup_log2: CA_BLOWUP_LOG2_V1,
        terminal_log2: CA_TERMINAL_LOG2_V1,
        terminal_degree_bound: CA_TERMINAL_DEGREE_BOUND_V1,
        composition_degree_chunks: CA_COMPOSITION_DEGREE_CHUNKS_V1,
        minimum_trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
        maximum_trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
        maximum_trace_groups: 1,
        maximum_segment_instances: ZK_X509_CA_ACCUMULATOR_CHUNKS_V1,
        maximum_base_columns_per_instance: 64,
        maximum_aux_columns_per_instance: 64,
        maximum_proof_bytes: CA_INNER_MAXIMUM_PROOF_BYTES_V1,
    };
const fn ca_domains_v1(
    proof_instance: ZkX509ProofInstanceV1,
) -> aggregate::AggregateStarkDomainsV1 {
    aggregate::AggregateStarkDomainsV1 {
        digest_context: proof_instance.ca_context_v1(),
        base_leaf: CA_BASE_LEAF_DOMAIN_V1,
        base_node: CA_BASE_NODE_DOMAIN_V1,
        aux_leaf: CA_AUX_LEAF_DOMAIN_V1,
        aux_node: CA_AUX_NODE_DOMAIN_V1,
        composition_leaf: CA_COMPOSITION_LEAF_DOMAIN_V1,
        composition_node: CA_COMPOSITION_NODE_DOMAIN_V1,
        fri_leaf: CA_FRI_LEAF_DOMAIN_V1,
        fri_node: CA_FRI_NODE_DOMAIN_V1,
        layout_label: CA_LAYOUT_LABEL_V1,
        base_root_label: CA_BASE_ROOT_LABEL_V1,
        aux_root_label: CA_AUX_ROOT_LABEL_V1,
        composition_root_label: CA_COMPOSITION_ROOT_LABEL_V1,
        fri_root_label: CA_FRI_ROOT_LABEL_V1,
        fri_beta_label: CA_FRI_BETA_LABEL_V1,
        query_seed: CA_QUERY_SEED_DOMAIN_V1,
    }
}
const _: () = {
    assert!(CA_QUERY_COUNT_V1 == 136);
    assert!(CA_BLOWUP_LOG2_V1 == 4);
    assert!(CA_TERMINAL_LOG2_V1 == 10);
    assert!(ZK_X509_CA_FRI_ROUNDS_V1 == ZK_X509_CA_FRI_LDE_LOG2_V1 - CA_TERMINAL_LOG2_V1);
    assert!(CA_COMPOSITION_DEGREE_CHUNKS_V1 == 4);
    assert!(CA_MASK_DEGREE_V1 == 2099);
    assert!(CA_DEEP_BYTES_V1 == 52_800);
    assert!(CA_PROOF_ENVELOPE_BYTES_V1 == 10);
    assert!(CA_INNER_MAXIMUM_PROOF_BYTES_V1 == 1_498_816);
    assert!(ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 == 1_498_826);
    assert!(ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 < ZK_X509_MAX_PROOF_BYTES_V1 as usize);
};
/// Exact caller-supplied resource shape admitted by the first release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorResourceRequestV1 {
    /// Native trace logarithm.
    pub(crate) trace_log2: u8,
    /// Dedicated local LDE logarithm.
    pub(crate) lde_log2: u8,
    /// Haböck--Al Kindi reduced AIR degree `d = d_AIR - 1`.
    pub(crate) reduced_air_degree: usize,
    /// Number of DEEP samples selected by the outer proof.
    pub(crate) deep_query_count: usize,
    /// Number of FRI queries selected by the outer proof.
    pub(crate) fri_query_count: usize,
    /// Degree of the trace zero-knowledge mask.
    pub(crate) mask_degree: usize,
    /// Numerator of the exact FRI degree-cap-to-LDE-size ratio.
    pub(crate) fri_rate_numerator: usize,
    /// Denominator of the exact FRI degree-cap-to-LDE-size ratio.
    pub(crate) fri_rate_denominator: usize,
    /// Exact base width.
    pub(crate) base_width: usize,
    /// Exact auxiliary width.
    pub(crate) aux_width: usize,
    /// Exact verifier-preprocessed width.
    pub(crate) fixed_width: usize,
    /// Exact authenticated scratch block height.
    pub(crate) scratch_chunk_rows: usize,
    /// Exact number of Fp4 composition lanes.
    pub(crate) composition_extension_lanes: usize,
}
/// Checked exact resource census for one compact-CA local subproof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorResourceEnvelopeV1 {
    /// Exact zero-knowledge mask coefficient count.
    pub(crate) mask_coefficients: usize,
    /// Maximum degree of one masked trace column.
    pub(crate) maximum_masked_trace_degree: usize,
    /// FRI degree cap implied by the local domain and governed rate.
    pub(crate) fri_degree_cap: usize,
    /// Maximum fixed-selector-aware cubic quotient before coefficient chunking.
    pub(crate) maximum_quotient_degree: usize,
    /// Minimum safe local LDE rows before power-of-two rounding.
    pub(crate) minimum_safe_lde_rows: usize,
    /// Native base, aux, and fixed field cells retained by the adapter.
    pub(crate) native_material_field_cells: usize,
    /// Exact native field payload bytes.
    pub(crate) native_material_bytes: usize,
    /// Base and aux local-LDE field evaluations.
    pub(crate) committed_lde_field_evaluations: usize,
    /// Fixed local-LDE field evaluations.
    pub(crate) fixed_lde_field_evaluations: usize,
    /// Exact base, aux, and fixed local-LDE payload bytes.
    pub(crate) total_local_lde_bytes: usize,
    /// Exact encrypted scratch bytes including one tag per matrix record.
    pub(crate) encrypted_scratch_bytes: usize,
    /// Maximum current/next base, aux, and fixed decrypted block payload.
    pub(crate) current_next_block_bytes: usize,
    /// Maximum native plus local-LDE column payload during streaming.
    pub(crate) streamed_column_bytes: usize,
    /// Exact retained trace-mask payload.
    pub(crate) trace_mask_bytes: usize,
    /// Exact base-field residue evaluations in one Fp4 composition lane.
    pub(crate) composition_residue_evaluations: usize,
    /// Exact base-field component evaluations across the Fp4 lane.
    pub(crate) composition_component_evaluations: usize,
    /// Exact radix-2 butterflies for all base, aux, and fixed local LDEs.
    pub(crate) lde_butterflies: usize,
    /// Conservative exact CA-adapter resident field-payload census.
    pub(crate) adapter_resident_payload_bytes: usize,
}
/// Verifier-bound compact accumulator terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorStarkPublicV1 {
    /// Governed compact-tree root as exact byte fields.
    pub(crate) governed_root: [F; 32],
    /// Verifier-derived final DER I/O channel carrying the exact root SPKI.
    pub(crate) root_spki_channel: F,
}
/// Reference per-call products retained by material and algebraic test controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub struct ZkX509CaAccumulatorCallTerminalV1 {
    /// Canonical global SHA call.
    pub(crate) call: u8,
    /// Leaf or node role.
    pub(crate) role: ZkX509ShaCallRoleV1,
    /// Product over 48 padded source words.
    pub(crate) source_products: [F; ZK_X509_SHA_BUS_LANES_V1],
    /// Product over eight digest words.
    pub(crate) digest_products: [F; ZK_X509_SHA_BUS_LANES_V1],
}
/// Exact DER-output consumer terminal for the private root SPKI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub struct ZkX509CaAccumulatorIoTerminalV1 {
    /// Verifier-derived canonical channel.
    pub(crate) channel: u32,
    /// Exactly 91 byte-consumer events.
    pub(crate) event_count: u16,
    /// Product over `(role, channel, endpoint, offset, byte, read)` tuples.
    pub(crate) consumer_products: [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
}
/// Reference terminal claims used to compare the full and private local relations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub struct ZkX509CaAccumulatorStarkTerminalClaimsV1 {
    /// One source terminal per leaf/node SHA call.
    pub(crate) source_products:
        [[F; ZK_X509_SHA_BUS_LANES_V1]; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
    /// One digest terminal per leaf/node SHA call.
    pub(crate) digest_products:
        [[F; ZK_X509_SHA_BUS_LANES_V1]; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
    /// Exact root-SPKI consumer terminal.
    pub(crate) root_spki_consumer_products: [F; ZK_X509_RFC5280_STARK_BUS_LANES_V1],
}
/// Column-major material consumed by aggregate commitments.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509CaAccumulatorStarkMaterialV1 {
    /// Challenge-independent witness columns.
    pub(crate) base_columns: Vec<Vec<F>>,
    /// Four-lane per-call product columns.
    pub(crate) aux_columns: Vec<Vec<F>>,
    /// Verifier-preprocessed selectors and frame constants.
    pub(crate) fixed_columns: Vec<Vec<F>>,
    /// Exact thirteen call terminals.
    pub(crate) terminals:
        [ZkX509CaAccumulatorCallTerminalV1; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
    /// Exact 91-byte root-SPKI I/O consumer terminal.
    pub(crate) root_spki_terminal: ZkX509CaAccumulatorIoTerminalV1,
}
/// Reference terminal binding for algebraic and hostile-shape test controls.
///
/// Current X5S1 carries original-polynomial openings instead of public terminal
/// products. This test fixture retains exact omission, excess, substitution,
/// reordering and cross-root assertions against the reference terminal relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub struct ZkX509CaAccumulatorSubproofBindingV1 {
    /// Verifier-bound governed root and derived root-SPKI channel.
    pub(crate) public: ZkX509CaAccumulatorStarkPublicV1,
    /// Exact ordered leaf call followed by node levels zero through eleven.
    pub(crate) sha_terminals:
        [ZkX509CaAccumulatorCallTerminalV1; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
    /// Exact 91-event strict-DER consumer terminal.
    pub(crate) root_spki_terminal: ZkX509CaAccumulatorIoTerminalV1,
}
/// Numeric adapter construction or evaluation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkX509AccumulatorStarkErrorV1 {
    /// The compact native witness is invalid.
    #[error("zk-X509 compact CA STARK witness is invalid")]
    Witness,
    /// The verifier-owned SHA schedule or challenge family is invalid.
    #[error("zk-X509 compact CA STARK SHA call bus is invalid")]
    CallBus,
    /// The verifier-owned DER root-SPKI I/O bus is invalid.
    #[error("zk-X509 compact CA STARK root-SPKI I/O bus is invalid")]
    IoBus,
    /// An opened row has the wrong exact width.
    #[error("zk-X509 compact CA STARK row shape is invalid")]
    Shape,
    /// Checked allocation or conversion exceeded the fixed envelope.
    #[error("zk-X509 compact CA STARK resource envelope is exceeded")]
    Resource,
}
/// Dedicated compact-CA proof construction, wire, or verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509CaAccumulatorProofErrorV1 {
    /// The public root, verifier-owned schedule, or native witness is invalid.
    #[error("zk-X509 compact CA proof statement or witness is invalid")]
    InvalidStatementOrWitness,
    /// The exact proof envelope or inner proof is malformed.
    #[error("zk-X509 compact CA proof wire is malformed")]
    MalformedProof,
    /// The proof exceeds the sole release ceiling.
    #[error("zk-X509 compact CA proof exceeds its byte ceiling")]
    ProofTooLarge,
    /// A field was not a canonical Goldilocks residue.
    #[error("zk-X509 compact CA proof contains a non-canonical field")]
    NonCanonicalField,
    /// A committed trace or Merkle frontier is invalid.
    #[error("zk-X509 compact CA proof trace opening is invalid")]
    TraceOpening,
    /// An AIR, terminal-claim, composition, or DEEP identity is invalid.
    #[error("zk-X509 compact CA proof constraint opening is invalid")]
    ConstraintOpening,
    /// A FRI commitment, opening, fold, or terminal degree is invalid.
    #[error("zk-X509 compact CA proof FRI opening is invalid")]
    FriOpening,
    /// Fiat-Shamir replay, grinding, or query derivation failed.
    #[error("zk-X509 compact CA proof transcript is invalid")]
    TranscriptMismatch,
    /// Prover entropy was unavailable.
    #[error("zk-X509 compact CA prover randomness is unavailable")]
    RandomnessUnavailable,
    /// Prover entropy failed the release health policy.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact CA prover randomness failed its health check")]
    RandomnessUnhealthy,
    /// Checked arithmetic or allocation exceeded the fixed local envelope.
    #[error("zk-X509 compact CA proof resource envelope is exceeded")]
    Resource,
    /// The producer-generated proof failed independent verification.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 compact CA prover self-check failed")]
    ProverSelfCheckFailed,
}
impl From<ZkX509AccumulatorAirErrorV1> for ZkX509AccumulatorStarkErrorV1 {
    fn from(error: ZkX509AccumulatorAirErrorV1) -> Self {
        match error {
            ZkX509AccumulatorAirErrorV1::Resource => Self::Resource,
            _ => Self::Witness,
        }
    }
}
impl From<ZkX509MerkleErrorV1> for ZkX509AccumulatorStarkErrorV1 {
    fn from(_: ZkX509MerkleErrorV1) -> Self {
        Self::Witness
    }
}
impl From<ZkX509AccumulatorStarkErrorV1> for ZkX509CaAccumulatorProofErrorV1 {
    fn from(error: ZkX509AccumulatorStarkErrorV1) -> Self {
        match error {
            ZkX509AccumulatorStarkErrorV1::Resource => Self::Resource,
            ZkX509AccumulatorStarkErrorV1::Witness
            | ZkX509AccumulatorStarkErrorV1::CallBus
            | ZkX509AccumulatorStarkErrorV1::IoBus
            | ZkX509AccumulatorStarkErrorV1::Shape => Self::InvalidStatementOrWitness,
        }
    }
}
fn map_aggregate_proof_error_v1(error: AggregateStarkErrorV1) -> ZkX509CaAccumulatorProofErrorV1 {
    match error {
        AggregateStarkErrorV1::InvalidLayout
        | AggregateStarkErrorV1::InvalidProofShape
        | AggregateStarkErrorV1::AllocationFailure
        | AggregateStarkErrorV1::InternalInvariant => ZkX509CaAccumulatorProofErrorV1::Resource,
        AggregateStarkErrorV1::MalformedProof => ZkX509CaAccumulatorProofErrorV1::MalformedProof,
        AggregateStarkErrorV1::ProofTooLarge => ZkX509CaAccumulatorProofErrorV1::ProofTooLarge,
        AggregateStarkErrorV1::NonCanonicalField => {
            ZkX509CaAccumulatorProofErrorV1::NonCanonicalField
        }
        AggregateStarkErrorV1::TraceOpening => ZkX509CaAccumulatorProofErrorV1::TraceOpening,
        AggregateStarkErrorV1::ConstraintOpening | AggregateStarkErrorV1::DeepOpening => {
            ZkX509CaAccumulatorProofErrorV1::ConstraintOpening
        }
        AggregateStarkErrorV1::FriOpening | AggregateStarkErrorV1::FriDegree => {
            ZkX509CaAccumulatorProofErrorV1::FriOpening
        }
        AggregateStarkErrorV1::TranscriptMismatch => {
            ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch
        }
        AggregateStarkErrorV1::RandomnessUnavailable => {
            ZkX509CaAccumulatorProofErrorV1::RandomnessUnavailable
        }
    }
}
fn map_credential_pre_aux_error_v1(
    error: ZkX509CredentialPreAuxErrorV1,
) -> ZkX509CaAccumulatorProofErrorV1 {
    match error {
        ZkX509CredentialPreAuxErrorV1::Resource => ZkX509CaAccumulatorProofErrorV1::Resource,
        ZkX509CredentialPreAuxErrorV1::Transcript | ZkX509CredentialPreAuxErrorV1::Challenge => {
            ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch
        }
    }
}
fn map_transparent_proof_error_v1(
    error: TransparentStarkErrorV1,
) -> ZkX509CaAccumulatorProofErrorV1 {
    match error {
        TransparentStarkErrorV1::RandomnessUnavailable => {
            ZkX509CaAccumulatorProofErrorV1::RandomnessUnavailable
        }
        TransparentStarkErrorV1::AllocationFailure => ZkX509CaAccumulatorProofErrorV1::Resource,
        TransparentStarkErrorV1::NonCanonicalField => {
            ZkX509CaAccumulatorProofErrorV1::NonCanonicalField
        }
        TransparentStarkErrorV1::InvalidMerkleShape => {
            ZkX509CaAccumulatorProofErrorV1::TraceOpening
        }
        TransparentStarkErrorV1::FriDegree => ZkX509CaAccumulatorProofErrorV1::FriOpening,
        TransparentStarkErrorV1::MalformedProof => ZkX509CaAccumulatorProofErrorV1::MalformedProof,
        TransparentStarkErrorV1::InvalidGrinding
        | TransparentStarkErrorV1::ChallengeSamplingExhausted
        | TransparentStarkErrorV1::QuerySamplingExhausted => {
            ZkX509CaAccumulatorProofErrorV1::TranscriptMismatch
        }
        _ => ZkX509CaAccumulatorProofErrorV1::ConstraintOpening,
    }
}
/// Complete per-column primitive-coordinate closure for the CA-to-MAIN links.
/// Thirteen translated MAIN query/DEEP points join the two local points.
/// Frobenius closure counts at most four base coordinates per extension point.
fn ca_private_query_closure_coefficients_v1(
    deep_points: usize,
    queries: usize,
) -> Result<usize, ZkX509AccumulatorStarkErrorV1> {
    if queries == 0 {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    deep_points
        .checked_mul(4)
        .and_then(|deep| queries.checked_add(deep))
        .and_then(|points| points.checked_mul(2 + ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)
}
/// Derive the minimum safe local request for the compiled cubic AIR and exact
/// outer DEEP/FRI parameters.
pub fn ca_accumulator_resource_request_v1(
    reduced_air_degree: usize,
    deep_query_count: usize,
    fri_query_count: usize,
) -> Result<ZkX509CaAccumulatorResourceRequestV1, ZkX509AccumulatorStarkErrorV1> {
    if reduced_air_degree != ZK_X509_CA_ACCUMULATOR_REDUCED_AIR_DEGREE_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    let geometry = transparent_stark_zk_mask_geometry_v1(
        reduced_air_degree,
        ZK_X509_CA_ACCUMULATOR_EXTENSION_COMPONENTS_V1,
        deep_query_count,
        fri_query_count,
    )
    .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    let mask_coefficients =
        ca_private_query_closure_coefficients_v1(deep_query_count, fri_query_count)?;
    if mask_coefficients < geometry.minimum_mask_coefficients {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    let mask_degree = mask_coefficients - 1;
    let maximum_masked_trace_degree = ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
        .checked_add(mask_degree)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let minimum_safe_lde_rows = maximum_masked_trace_degree
        .checked_add(1)
        .and_then(|coefficients| {
            coefficients.checked_mul(ZK_X509_CA_ACCUMULATOR_FRI_RATE_DENOMINATOR_V1)
        })
        .map(|scaled| scaled.div_ceil(ZK_X509_CA_ACCUMULATOR_FRI_RATE_NUMERATOR_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let lde_rows = minimum_safe_lde_rows
        .checked_next_power_of_two()
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let lde_log2 =
        u8::try_from(lde_rows.ilog2()).map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    Ok(ZkX509CaAccumulatorResourceRequestV1 {
        trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
        lde_log2,
        reduced_air_degree,
        deep_query_count,
        fri_query_count,
        mask_degree,
        fri_rate_numerator: ZK_X509_CA_ACCUMULATOR_FRI_RATE_NUMERATOR_V1,
        fri_rate_denominator: ZK_X509_CA_ACCUMULATOR_FRI_RATE_DENOMINATOR_V1,
        base_width: ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
        aux_width: ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
        fixed_width: ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1,
        scratch_chunk_rows: ZK_X509_CA_ACCUMULATOR_SCRATCH_CHUNK_ROWS_V1,
        composition_extension_lanes: ZK_X509_CA_ACCUMULATOR_COMPOSITION_EXTENSION_LANES_V1,
    })
}
/// Validate a parameterized local resource shape and return its checked census.
///
/// The outer profile binds the compiled `d_AIR = 3`, exact DEEP count, FRI
/// query count, and mask degree. Passing a quadratic substitution, a weaker
/// mask, a lower-rate domain, the full profile's common LDE, or a noncanonical
/// scratch block fails before allocation.
pub fn checked_ca_accumulator_resource_envelope_v1(
    request: ZkX509CaAccumulatorResourceRequestV1,
) -> Result<ZkX509CaAccumulatorResourceEnvelopeV1, ZkX509AccumulatorStarkErrorV1> {
    if request.trace_log2 != ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1
        || request.base_width != ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
        || request.aux_width != ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
        || request.fixed_width != ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1
        || request.scratch_chunk_rows != ZK_X509_CA_ACCUMULATOR_SCRATCH_CHUNK_ROWS_V1
        || request.composition_extension_lanes
            != ZK_X509_CA_ACCUMULATOR_COMPOSITION_EXTENSION_LANES_V1
        || request.fri_rate_numerator != ZK_X509_CA_ACCUMULATOR_FRI_RATE_NUMERATOR_V1
        || request.fri_rate_denominator != ZK_X509_CA_ACCUMULATOR_FRI_RATE_DENOMINATOR_V1
        || request.reduced_air_degree != ZK_X509_CA_ACCUMULATOR_REDUCED_AIR_DEGREE_V1
        || request.scratch_chunk_rows == 0
        || !request.scratch_chunk_rows.is_power_of_two()
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    let mask_coefficients = request
        .mask_degree
        .checked_add(1)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let geometry = transparent_stark_zk_mask_geometry_v1(
        request.reduced_air_degree,
        ZK_X509_CA_ACCUMULATOR_EXTENSION_COMPONENTS_V1,
        request.deep_query_count,
        request.fri_query_count,
    )
    .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    if mask_coefficients
        != ca_private_query_closure_coefficients_v1(
            request.deep_query_count,
            request.fri_query_count,
        )?
        || mask_coefficients < geometry.minimum_mask_coefficients
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    let trace_rows = 1_usize
        .checked_shl(u32::from(request.trace_log2))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let lde_rows = 1_usize
        .checked_shl(u32::from(request.lde_log2))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let maximum_masked_trace_degree = trace_rows
        .checked_add(request.mask_degree)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let minimum_safe_lde_rows = maximum_masked_trace_degree
        .checked_add(1)
        .and_then(|coefficients| coefficients.checked_mul(request.fri_rate_denominator))
        .map(|scaled| scaled.div_ceil(request.fri_rate_numerator))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let exact_safe_lde_rows = minimum_safe_lde_rows
        .checked_next_power_of_two()
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let fri_degree_cap = lde_rows
        .checked_mul(request.fri_rate_numerator)
        .and_then(|scaled| scaled.checked_div(request.fri_rate_denominator))
        .and_then(|capacity| capacity.checked_sub(1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    // The two dynamic SHA source factors are affine in masked trace values,
    // but each is selected by one verifier-fixed polynomial of degree at most
    // `trace_rows - 1`. Account for both selectors explicitly: treating fixed
    // columns as degree-zero symbols is valid for the symbolic AIR inventory,
    // not for the actual univariate quotient committed by FRI.
    let fixed_selector_degree = trace_rows
        .checked_sub(1)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let maximum_quotient_degree = usize::from(ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1)
        .checked_mul(maximum_masked_trace_degree)
        .and_then(|degree| {
            fixed_selector_degree
                .checked_mul(2)
                .and_then(|selectors| degree.checked_add(selectors))
        })
        .and_then(|degree| degree.checked_sub(trace_rows))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let quotient_chunk_capacity = fri_degree_cap
        .checked_add(1)
        .and_then(|coefficients| coefficients.checked_sub(request.fri_query_count.checked_add(1)?))
        .and_then(|coefficients| coefficients.checked_mul(COMPOSITION_DEGREE_CHUNKS_V1))
        .and_then(|coefficients| coefficients.checked_sub(1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    if trace_rows != ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
        || lde_rows != exact_safe_lde_rows
        || maximum_masked_trace_degree > fri_degree_cap
        || maximum_quotient_degree > quotient_chunk_capacity
        || request.scratch_chunk_rows > lde_rows
        || lde_rows % request.scratch_chunk_rows != 0
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    let committed_width = request
        .base_width
        .checked_add(request.aux_width)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let total_width = committed_width
        .checked_add(request.fixed_width)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let native_material_field_cells = total_width
        .checked_mul(trace_rows)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let native_material_bytes = native_material_field_cells
        .checked_mul(FIELD_BYTES_V1)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let committed_lde_field_evaluations = committed_width
        .checked_mul(lde_rows)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let fixed_lde_field_evaluations = request
        .fixed_width
        .checked_mul(lde_rows)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let total_local_lde_bytes = committed_lde_field_evaluations
        .checked_add(fixed_lde_field_evaluations)
        .and_then(|cells| cells.checked_mul(FIELD_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let chunks_per_column = lde_rows / request.scratch_chunk_rows;
    let scratch_record_bytes = request
        .scratch_chunk_rows
        .checked_mul(FIELD_BYTES_V1)
        .and_then(|bytes| bytes.checked_add(SCRATCH_TAG_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let encrypted_scratch_bytes = total_width
        .checked_mul(chunks_per_column)
        .and_then(|records| records.checked_mul(scratch_record_bytes))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let current_next_block_bytes = total_width
        .checked_mul(request.scratch_chunk_rows)
        .and_then(|cells| cells.checked_mul(2))
        .and_then(|cells| cells.checked_mul(FIELD_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let streamed_column_bytes = trace_rows
        .checked_add(lde_rows)
        .and_then(|cells| cells.checked_mul(FIELD_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let trace_mask_bytes = committed_width
        .checked_mul(mask_coefficients)
        .and_then(|cells| cells.checked_mul(FIELD_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let composition_residue_evaluations = ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1
        .checked_mul(lde_rows)
        .and_then(|work| work.checked_mul(request.composition_extension_lanes))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let composition_component_evaluations = composition_residue_evaluations
        .checked_mul(ZK_X509_CA_ACCUMULATOR_EXTENSION_COMPONENTS_V1)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let per_column_butterflies = trace_rows
        .checked_div(2)
        .and_then(|half| half.checked_mul(usize::from(request.trace_log2)))
        .and_then(|native| {
            lde_rows
                .checked_div(2)
                .and_then(|half| half.checked_mul(usize::from(request.lde_log2)))
                .and_then(|lde| native.checked_add(lde))
        })
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let lde_butterflies = total_width
        .checked_mul(per_column_butterflies)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let residue_vector_bytes = ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1
        .checked_mul(FIELD_BYTES_V1)
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let composition_chunk_bytes = request
        .composition_extension_lanes
        .checked_mul(COMPOSITION_DEGREE_CHUNKS_V1)
        .and_then(|cells| cells.checked_mul(lde_rows))
        .and_then(|cells| cells.checked_mul(ZK_X509_CA_ACCUMULATOR_EXTENSION_COMPONENTS_V1))
        .and_then(|cells| cells.checked_mul(FIELD_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    // The blinder retains D coefficients per chunk beside the output codewords.
    // Its in-place inverse transform consumes the original quotient allocation
    // and drops that allocation before producing the first output codeword.
    let composition_blinding_bytes = fri_degree_cap
        .checked_add(1)
        .and_then(|coefficients| coefficients.checked_mul(COMPOSITION_DEGREE_CHUNKS_V1))
        .and_then(|coefficients| coefficients.checked_mul(request.composition_extension_lanes))
        .and_then(|coefficients| coefficients.checked_mul(core::mem::size_of::<E>()))
        .and_then(|bytes| {
            bytes.checked_add(
                super::composition_masking::QuotientChunkGeometryV1::mask_scratch_bytes_v1(),
            )
        })
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let adapter_resident_payload_bytes = native_material_bytes
        .checked_add(total_local_lde_bytes)
        .and_then(|bytes| bytes.checked_add(current_next_block_bytes))
        .and_then(|bytes| bytes.checked_add(streamed_column_bytes))
        .and_then(|bytes| bytes.checked_add(trace_mask_bytes))
        .and_then(|bytes| bytes.checked_add(residue_vector_bytes))
        .and_then(|bytes| bytes.checked_add(composition_chunk_bytes))
        .and_then(|bytes| bytes.checked_add(composition_blinding_bytes))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    let envelope = ZkX509CaAccumulatorResourceEnvelopeV1 {
        mask_coefficients,
        maximum_masked_trace_degree,
        fri_degree_cap,
        maximum_quotient_degree,
        minimum_safe_lde_rows,
        native_material_field_cells,
        native_material_bytes,
        committed_lde_field_evaluations,
        fixed_lde_field_evaluations,
        total_local_lde_bytes,
        encrypted_scratch_bytes,
        current_next_block_bytes,
        streamed_column_bytes,
        trace_mask_bytes,
        composition_residue_evaluations,
        composition_component_evaluations,
        lde_butterflies,
        adapter_resident_payload_bytes,
    };
    if envelope.native_material_bytes > ZK_X509_CA_ACCUMULATOR_MAX_NATIVE_MATERIAL_BYTES_V1
        || envelope.total_local_lde_bytes > ZK_X509_CA_ACCUMULATOR_MAX_LOCAL_LDE_BYTES_V1
        || envelope.encrypted_scratch_bytes > ZK_X509_CA_ACCUMULATOR_MAX_LOCAL_SCRATCH_BYTES_V1
        || envelope.adapter_resident_payload_bytes
            > ZK_X509_CA_ACCUMULATOR_MAX_ADAPTER_RESIDENT_BYTES_V1
        || envelope.lde_butterflies > ZK_X509_CA_ACCUMULATOR_MAX_LDE_BUTTERFLIES_V1
        || envelope.composition_component_evaluations
            > ZK_X509_CA_ACCUMULATOR_MAX_COMPOSITION_COMPONENT_EVALUATIONS_V1
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    Ok(envelope)
}
/// Derive the canonical root-SPKI I/O channel from public disclosure shape.
pub fn ca_accumulator_root_spki_channel_v1(
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<u32, ZkX509AccumulatorStarkErrorV1> {
    let disclosures = u32::try_from(schedule.shape().disclosed_attributes)
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_BASE_CHANNEL_V1
        .checked_add(
            disclosures
                .checked_mul(2)
                .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?,
        )
        .filter(|_| schedule.shape().disclosed_attributes <= 4)
        .ok_or(ZkX509AccumulatorStarkErrorV1::CallBus)
}
/// Derive verifier terminals from a validated trace and public schedule.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn ca_accumulator_stark_public_v1(
    trace: &ZkX509CaAccumulatorTraceV1,
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<ZkX509CaAccumulatorStarkPublicV1, ZkX509AccumulatorStarkErrorV1> {
    Ok(ZkX509CaAccumulatorStarkPublicV1 {
        governed_root: trace.statement.governed_root.map(|byte| F(u64::from(byte))),
        root_spki_channel: F(u64::from(ca_accumulator_root_spki_channel_v1(schedule)?)),
    })
}
/// Compile one verifier-preprocessed fixed row.
pub fn compile_ca_accumulator_fixed_row_v1(
    index: usize,
) -> Result<[F; ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1], ZkX509AccumulatorStarkErrorV1> {
    let location = ca_accumulator_fixed_row_v1(index)?;
    let mut fixed = [F::ZERO; ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1];
    fixed[FIX_ACTIVE] = F(u64::from(location.sha_active()));
    fixed[FIX_LEAF] = F(u64::from(matches!(
        location.kind,
        ZkX509CaAccumulatorRowKindV1::Leaf
    )));
    fixed[FIX_NODE] = F(u64::from(matches!(
        location.kind,
        ZkX509CaAccumulatorRowKindV1::Node(_)
    )));
    fixed[FIX_PADDING] = F(u64::from(matches!(
        location.kind,
        ZkX509CaAccumulatorRowKindV1::Padding
    )));
    fixed[FIX_TRANSITION] = F(u64::from(location.sha_transition()));
    fixed[FIX_LAST] = F(u64::from(matches!(
        location.kind,
        ZkX509CaAccumulatorRowKindV1::Node(level)
            if usize::from(level) + 1 == ZK_X509_CA_COMPACT_TREE_DEPTH_V1
    )));
    let source_constants = match location.kind {
        ZkX509CaAccumulatorRowKindV1::Leaf => {
            fixed[FIX_CALL] = F(ZK_X509_SHA_CA_LEAF_CALL_V1 as u64);
            fixed[FIX_ROLE] = F(u64::from(ZkX509ShaCallRoleV1::CaLeaf.role_code()));
            fixed[FIX_SLOT] = F::ZERO;
            padded_source_words_v1(&ca_leaf_preimage_v1(&[0_u8; ZK_X509_CA_SPKI_DER_BYTES_V1])?)?
        }
        ZkX509CaAccumulatorRowKindV1::Node(level) => {
            fixed[FIX_LEVEL] = F(u64::from(level));
            fixed[FIX_CALL] = F(u64::try_from(
                ZK_X509_SHA_CA_NODE_CALL_START_V1 + usize::from(level),
            )
            .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?);
            let role = ZkX509ShaCallRoleV1::CaNode(level);
            fixed[FIX_ROLE] = F(u64::from(role.role_code()));
            fixed[FIX_SLOT] = F(u64::from(level));
            fixed[FIX_INDEX_SELECTORS_START + usize::from(level)] = F::ONE;
            padded_source_words_v1(&ca_node_preimage_v1(
                usize::from(level),
                &[0; 32],
                &[0; 32],
            )?)?
        }
        ZkX509CaAccumulatorRowKindV1::RootSpkiByte(offset) => {
            let offset = usize::from(offset);
            let message_offset = LEAF_DYNAMIC_OFFSET_V1
                .checked_add(offset)
                .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
            let word_index = message_offset / 4;
            fixed[FIX_IO_ACTIVE] = F::ONE;
            fixed[FIX_IO_FIRST] = F(u64::from(offset == 0));
            fixed[FIX_IO_LAST] = F(u64::from(offset + 1 == ZK_X509_CA_ACCUMULATOR_IO_ROWS_V1));
            fixed[FIX_IO_TRANSITION] = F(u64::from(location.io_transition()));
            fixed[FIX_IO_SAME_WORD_TO_NEXT] = F(u64::from(
                location.io_transition() && (message_offset + 1) % 4 != 0,
            ));
            fixed[FIX_IO_WORD_END] = F(u64::from(message_offset % 4 == 3));
            fixed[FIX_IO_OFFSET] =
                F(u64::try_from(offset).map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?);
            fixed[FIX_IO_WORD_INDEX] =
                F(u64::try_from(word_index)
                    .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?);
            if location.io_transition() {
                let next_message_offset = message_offset
                    .checked_add(1)
                    .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
                fixed[FIX_IO_NEXT_WORD_END] = F(u64::from(next_message_offset % 4 == 3));
                fixed[FIX_IO_NEXT_WORD_INDEX] = F(u64::try_from(next_message_offset / 4)
                    .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?);
            }
            [0_u32; SOURCE_WORDS_V1]
        }
        ZkX509CaAccumulatorRowKindV1::Padding => [0_u32; SOURCE_WORDS_V1],
    };
    for (target, word) in fixed
        [FIX_SOURCE_CONSTANTS_START..FIX_SOURCE_CONSTANTS_START + SOURCE_WORDS_V1]
        .iter_mut()
        .zip(source_constants)
    {
        *target = F(u64::from(word));
    }
    Ok(fixed)
}
/// Compile all verifier-preprocessed fixed columns.
pub fn compile_ca_accumulator_fixed_columns_v1()
-> Result<Vec<Vec<F>>, ZkX509AccumulatorStarkErrorV1> {
    let mut columns = allocate_columns_v1(
        ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
    )?;
    for index in 0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
        append_array_row_v1(&mut columns, &compile_ca_accumulator_fixed_row_v1(index)?)?;
    }
    Ok(columns)
}
/// Build exact base, auxiliary, fixed, and terminal material.
#[cfg(test)]
pub fn build_ca_accumulator_stark_material_v1(
    trace: &ZkX509CaAccumulatorTraceV1,
    schedule: &ZkX509ShaCallScheduleV1,
    sha_challenges: ZkX509ShaCallBusChallengesV1,
    io_challenges: &ZkX509Rfc5280StarkChallengesV1,
) -> Result<ZkX509CaAccumulatorStarkMaterialV1, ZkX509AccumulatorStarkErrorV1> {
    let native_material_bytes = ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
        .checked_add(ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1)
        .and_then(|width| width.checked_add(ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1))
        .and_then(|width| width.checked_mul(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1))
        .and_then(|cells| cells.checked_mul(FIELD_BYTES_V1))
        .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
    if native_material_bytes > ZK_X509_CA_ACCUMULATOR_MAX_NATIVE_MATERIAL_BYTES_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::Resource);
    }
    trace.validate()?;
    sha_challenges
        .validate()
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::CallBus)?;
    io_challenges
        .validate()
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::IoBus)?;
    let public = ca_accumulator_stark_public_v1(trace, schedule)?;
    let mut base_columns = allocate_columns_v1(
        ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
    )?;
    let mut aux_columns = allocate_columns_v1(
        ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
    )?;
    let fixed_columns = compile_ca_accumulator_fixed_columns_v1()?;
    let mut terminals = Vec::new();
    terminals
        .try_reserve_exact(ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1)
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    let mut previous_aux = None;
    for index in 0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
        let base = trace.base_row(index)?;
        let fixed = compile_ca_accumulator_fixed_row_v1(index)?;
        let aux = build_aux_row_v1(
            public,
            &base,
            &fixed,
            previous_aux.as_ref(),
            sha_challenges,
            io_challenges,
        )?;
        append_array_row_v1(&mut base_columns, &base)?;
        append_array_row_v1(&mut aux_columns, &aux)?;
        if index < ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 {
            let call = usize::try_from(fixed[FIX_CALL].0)
                .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
            let manifest = schedule
                .call(call)
                .map_err(|_| ZkX509AccumulatorStarkErrorV1::CallBus)?;
            let expected_role = trace.hash_witnesses[index].role;
            if manifest.call as usize != call
                || manifest.role != expected_role
                || manifest.activation != ZkX509ShaCallActivationV1::Required
                || manifest.maximum_blocks != 3
            {
                return Err(ZkX509AccumulatorStarkErrorV1::CallBus);
            }
            terminals.push(ZkX509CaAccumulatorCallTerminalV1 {
                call: manifest.call,
                role: manifest.role,
                source_products: core::array::from_fn(|lane| {
                    aux[source_aux_cell_v1(SOURCE_STATES_V1 - 1, lane)]
                }),
                digest_products: core::array::from_fn(|lane| {
                    aux[digest_aux_cell_v1(DIGEST_STATES_V1 - 1, lane)]
                }),
            });
        }
        previous_aux = Some(aux);
    }
    let root_spki_last_row = ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1;
    for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
        terminals[0].source_products[lane] = terminals[0].source_products[lane]
            .mul(aux_columns[serialized_sha_product_cell_v1(lane)][root_spki_last_row]);
    }
    let root_spki_terminal = ZkX509CaAccumulatorIoTerminalV1 {
        channel: ca_accumulator_root_spki_channel_v1(schedule)?,
        event_count: ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_IO_EVENTS_V1,
        consumer_products: core::array::from_fn(|lane| {
            aux_columns[root_spki_io_product_cell_v1(lane)][root_spki_last_row]
        }),
    };
    validate_ca_accumulator_io_terminal_v1(public, root_spki_terminal)?;
    Ok(ZkX509CaAccumulatorStarkMaterialV1 {
        base_columns,
        aux_columns,
        fixed_columns,
        terminals: terminals
            .try_into()
            .map_err(|_: Vec<ZkX509CaAccumulatorCallTerminalV1>| {
                ZkX509AccumulatorStarkErrorV1::Shape
            })?,
        root_spki_terminal,
    })
}
/// Extract the exact proof terminal claims from committed material.
#[cfg(test)]
pub fn ca_accumulator_stark_terminal_claims_v1(
    material: &ZkX509CaAccumulatorStarkMaterialV1,
) -> ZkX509CaAccumulatorStarkTerminalClaimsV1 {
    ZkX509CaAccumulatorStarkTerminalClaimsV1 {
        source_products: core::array::from_fn(|row| material.terminals[row].source_products),
        digest_products: core::array::from_fn(|row| material.terminals[row].digest_products),
        root_spki_consumer_products: material.root_spki_terminal.consumer_products,
    }
}
/// Compile the typed reference binding used by algebraic and hostile-shape tests.
#[cfg(test)]
pub fn ca_accumulator_subproof_binding_v1(
    trace: &ZkX509CaAccumulatorTraceV1,
    schedule: &ZkX509ShaCallScheduleV1,
    material: &ZkX509CaAccumulatorStarkMaterialV1,
) -> Result<ZkX509CaAccumulatorSubproofBindingV1, ZkX509AccumulatorStarkErrorV1> {
    let binding = ZkX509CaAccumulatorSubproofBindingV1 {
        public: ca_accumulator_stark_public_v1(trace, schedule)?,
        sha_terminals: material.terminals,
        root_spki_terminal: material.root_spki_terminal,
    };
    validate_ca_accumulator_subproof_binding_v1(binding.public, schedule, binding)?;
    Ok(binding)
}
/// Extract the algebra claims from a validated typed subproof binding.
#[cfg(test)]
pub fn ca_accumulator_subproof_terminal_claims_v1(
    binding: ZkX509CaAccumulatorSubproofBindingV1,
) -> ZkX509CaAccumulatorStarkTerminalClaimsV1 {
    ZkX509CaAccumulatorStarkTerminalClaimsV1 {
        source_products: binding
            .sha_terminals
            .map(|terminal| terminal.source_products),
        digest_products: binding
            .sha_terminals
            .map(|terminal| terminal.digest_products),
        root_spki_consumer_products: binding.root_spki_terminal.consumer_products,
    }
}
/// Validate variable-length reference terminal fixtures before fixed-size conversion.
///
/// These algebraic controls reject omission, insertion, substitution and reordering;
/// they are not an X5S1 decoder or an independent credential acceptance path.
#[cfg(test)]
pub fn validate_ca_accumulator_subproof_terminal_sequence_v1(
    public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: &ZkX509ShaCallScheduleV1,
    sha_terminals: &[ZkX509CaAccumulatorCallTerminalV1],
    root_spki_terminal: ZkX509CaAccumulatorIoTerminalV1,
) -> Result<(), ZkX509AccumulatorStarkErrorV1> {
    if sha_terminals.len() != ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::CallBus);
    }
    validate_ca_accumulator_stark_public_v1(public, schedule)?;
    for (index, terminal) in sha_terminals.iter().copied().enumerate() {
        let expected_call = ZK_X509_SHA_CA_LEAF_CALL_V1
            .checked_add(index)
            .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?;
        let expected_role = if index == 0 {
            ZkX509ShaCallRoleV1::CaLeaf
        } else {
            ZkX509ShaCallRoleV1::CaNode(
                u8::try_from(index - 1).map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?,
            )
        };
        let manifest = schedule
            .call(expected_call)
            .map_err(|_| ZkX509AccumulatorStarkErrorV1::CallBus)?;
        if usize::from(terminal.call) != expected_call
            || terminal.role != expected_role
            || usize::from(manifest.call) != expected_call
            || manifest.role != expected_role
            || manifest.activation != ZkX509ShaCallActivationV1::Required
            || manifest.maximum_blocks != 3
            || terminal
                .source_products
                .iter()
                .chain(&terminal.digest_products)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509AccumulatorStarkErrorV1::CallBus);
        }
    }
    validate_ca_accumulator_io_terminal_v1(public, root_spki_terminal)
}
/// Validate one typed reference binding against the verifier-derived statement.
#[cfg(test)]
pub fn validate_ca_accumulator_subproof_binding_v1(
    expected_public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: &ZkX509ShaCallScheduleV1,
    binding: ZkX509CaAccumulatorSubproofBindingV1,
) -> Result<(), ZkX509AccumulatorStarkErrorV1> {
    validate_ca_accumulator_stark_public_v1(expected_public, schedule)?;
    if binding.public != expected_public {
        return Err(ZkX509AccumulatorStarkErrorV1::Witness);
    }
    validate_ca_accumulator_subproof_terminal_sequence_v1(
        binding.public,
        schedule,
        &binding.sha_terminals,
        binding.root_spki_terminal,
    )
}
fn validate_ca_accumulator_stark_public_v1(
    public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<(), ZkX509AccumulatorStarkErrorV1> {
    let expected_channel = F(u64::from(ca_accumulator_root_spki_channel_v1(schedule)?));
    if public.root_spki_channel != expected_channel
        || public
            .governed_root
            .iter()
            .any(|value| F::canonical(value.0).is_none() || value.0 > u64::from(u8::MAX))
    {
        return Err(ZkX509AccumulatorStarkErrorV1::IoBus);
    }
    Ok(())
}
/// Validate the fixed metadata and canonical products of the root-SPKI claim.
#[cfg(test)]
pub fn validate_ca_accumulator_io_terminal_v1(
    public: ZkX509CaAccumulatorStarkPublicV1,
    terminal: ZkX509CaAccumulatorIoTerminalV1,
) -> Result<(), ZkX509AccumulatorStarkErrorV1> {
    if terminal.channel
        != u32::try_from(public.root_spki_channel.0)
            .map_err(|_| ZkX509AccumulatorStarkErrorV1::IoBus)?
        || terminal.event_count != ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_IO_EVENTS_V1
        || terminal
            .consumer_products
            .iter()
            .any(|value| F::canonical(value.0).is_none())
    {
        return Err(ZkX509AccumulatorStarkErrorV1::IoBus);
    }
    Ok(())
}
/// Evaluate every local CA identity without exposing any endpoint product.
/// The consuming joint proof must additionally enforce all108 original-column
/// links; this function alone does not establish SHA/RFC witness consistency.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn evaluate_ca_accumulator_local_residues_v1<A: PolynomialAirFieldV1>(
    public: ZkX509CaAccumulatorStarkPublicV1,
    base: &[A],
    next_base: &[A],
    aux: &[A],
    next_aux: &[A],
    fixed: &[A],
    sha_challenges: ZkX509ShaCallBusChallengesV1,
    io_challenges: &ZkX509Rfc5280StarkChallengesV1,
) -> Result<Vec<A>, ZkX509AccumulatorStarkErrorV1> {
    if base.len() != ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
        || next_base.len() != ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
        || aux.len() != ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
        || next_aux.len() != ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
        || fixed.len() != ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    sha_challenges
        .validate()
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::CallBus)?;
    io_challenges
        .validate()
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::IoBus)?;
    if public.root_spki_channel.0 > u64::from(u32::MAX)
        || F::canonical(public.root_spki_channel.0).is_none()
        || public
            .governed_root
            .iter()
            .any(|value| F::canonical(value.0).is_none())
        || base
            .iter()
            .chain(next_base)
            .chain(aux)
            .chain(next_aux)
            .chain(fixed)
            .any(|value| !value.is_canonical())
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    let active = fixed[FIX_ACTIVE];
    let leaf = fixed[FIX_LEAF];
    let node = fixed[FIX_NODE];
    let io = fixed[FIX_IO_ACTIVE];
    let padding = fixed[FIX_PADDING];
    let transition = fixed[FIX_TRANSITION];
    let io_transition = fixed[FIX_IO_TRANSITION];
    let last = fixed[FIX_LAST];
    // Keep the current public wrapper's exact allocation until its endpoint
    // envelope is removed together with the completed joint proof.
    let mut residues = Vec::with_capacity(ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1);
    let digest_bits = &base[CA_DIGEST_BYTE_BITS_START..CA_DIGEST_BYTE_BITS_START + 32 * 8];
    let sibling_bits = &base[CA_SIBLING_BYTE_BITS_START..CA_SIBLING_BYTE_BITS_START + 32 * 8];
    let io_byte_bits = &base[CA_IO_BYTE_BITS_START..CA_IO_BYTE_BITS_START + 8];
    residues.extend(
        digest_bits
            .iter()
            .chain(sibling_bits.iter())
            .chain(io_byte_bits.iter())
            .map(|bit| bit.mul(bit.sub(A::ONE))),
    );
    for byte in 0..32 {
        residues.push(
            pack_little_bits_v1(&digest_bits[byte * 8..byte * 8 + 8])
                .sub(base[CA_DIGEST_START + byte]),
        );
        residues.push(
            pack_little_bits_v1(&sibling_bits[byte * 8..byte * 8 + 8])
                .sub(base[CA_SIBLING_START + byte]),
        );
    }
    residues.push(pack_little_bits_v1(io_byte_bits).sub(base[CA_IO_BYTE]));
    let index_bits =
        &base[CA_INDEX_BITS_START..CA_INDEX_BITS_START + ZK_X509_CA_COMPACT_TREE_DEPTH_V1];
    residues.extend(
        index_bits
            .iter()
            .map(|bit| active.mul(bit.mul(bit.sub(A::ONE)))),
    );
    let selected_direction = (0..ZK_X509_CA_COMPACT_TREE_DEPTH_V1).fold(A::ZERO, |sum, bit| {
        sum.add(fixed[FIX_INDEX_SELECTORS_START + bit].mul(index_bits[bit]))
    });
    residues.push(active.mul(base[CA_DIRECTION].sub(selected_direction)));
    for bit in 0..ZK_X509_CA_COMPACT_TREE_DEPTH_V1 {
        residues.push(transition.mul(next_base[CA_INDEX_BITS_START + bit].sub(index_bits[bit])));
    }
    for byte in 0..32 {
        residues.push(
            transition.mul(next_base[CA_CURRENT_START + byte].sub(base[CA_DIGEST_START + byte])),
        );
        residues.push(leaf.mul(base[CA_CURRENT_START + byte].sub(base[CA_DIGEST_START + byte])));
    }
    for column in [CA_SIBLING_START, CA_LEFT_START, CA_RIGHT_START] {
        residues.extend(
            base[column..column + 32]
                .iter()
                .map(|value| leaf.mul(*value)),
        );
    }
    residues.push(leaf.mul(base[CA_DIRECTION]));
    let direction = base[CA_DIRECTION];
    for byte in 0..32 {
        let current = base[CA_CURRENT_START + byte];
        let sibling = base[CA_SIBLING_START + byte];
        let left = current.add(direction.mul(sibling.sub(current)));
        let right = sibling.add(direction.mul(current.sub(sibling)));
        residues.push(node.mul(base[CA_LEFT_START + byte].sub(left)));
        residues.push(node.mul(base[CA_RIGHT_START + byte].sub(right)));
    }
    for byte in 0..32 {
        residues.push(
            last.mul(base[CA_DIGEST_START + byte].sub(A::from_base(public.governed_root[byte]))),
        );
    }
    residues.extend(
        base[..CA_DIGEST_BYTE_BITS_START]
            .iter()
            .map(|value| io.mul(*value)),
    );
    residues.push(active.mul(base[CA_IO_BYTE]));
    residues.push(active.mul(base[CA_IO_WORD_ACC]));
    residues.push(
        fixed[FIX_IO_FIRST].mul(
            base[CA_IO_WORD_ACC].sub(
                A::from_base(F(u64::from(ZK_X509_CA_LEAF_SPKI_PREFIX_BYTE_V1)))
                    .mul_base(F(256))
                    .add(base[CA_IO_BYTE]),
            ),
        ),
    );
    residues.push(
        io_transition.mul(
            next_base[CA_IO_WORD_ACC].sub(
                fixed[FIX_IO_SAME_WORD_TO_NEXT]
                    .mul(base[CA_IO_WORD_ACC])
                    .mul_base(F(256))
                    .add(next_base[CA_IO_BYTE]),
            ),
        ),
    );
    residues.extend(
        base[..CA_DIGEST_BYTE_BITS_START]
            .iter()
            .map(|value| padding.mul(*value)),
    );
    residues.push(padding.mul(base[CA_IO_BYTE]));
    residues.push(padding.mul(base[CA_IO_WORD_ACC]));
    if residues.len() != ZK_X509_CA_ACCUMULATOR_BASE_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
        residues.push(aux[source_aux_cell_v1(0, lane)].sub(active));
    }
    // State zero is already constrained to `active`. Ungated recurrences
    // therefore force every later state to zero on inactive rows while
    // avoiding a redundant selector factor in the committed quotient.
    for step in 0..SOURCE_PAIR_STEPS_V1 {
        for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
            let first = source_factor_v1(base, fixed, 2 * step, lane, sha_challenges)?;
            let second = source_factor_v1(base, fixed, 2 * step + 1, lane, sha_challenges)?;
            residues.push(
                aux[source_aux_cell_v1(step + 1, lane)]
                    .sub(aux[source_aux_cell_v1(step, lane)].mul(first).mul(second)),
            );
        }
    }
    for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
        residues.push(aux[digest_aux_cell_v1(0, lane)].sub(active));
    }
    for step in 0..DIGEST_PAIR_STEPS_V1 {
        for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
            let first = digest_factor_v1(base, fixed, 2 * step, lane, sha_challenges)?;
            let second = digest_factor_v1(base, fixed, 2 * step + 1, lane, sha_challenges)?;
            residues.push(
                aux[digest_aux_cell_v1(step + 1, lane)]
                    .sub(aux[digest_aux_cell_v1(step, lane)].mul(first).mul(second)),
            );
        }
    }
    let non_io = A::ONE.sub(io);
    for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
        let serialized_sha = aux[serialized_sha_product_cell_v1(lane)];
        let root_spki_io = aux[root_spki_io_product_cell_v1(lane)];
        let current_sha_factor = serialized_sha_factor_v1(
            fixed[FIX_IO_WORD_END],
            fixed[FIX_IO_WORD_INDEX],
            base[CA_IO_WORD_ACC],
            lane,
            sha_challenges,
        )?;
        let current_io_factor = root_spki_io_factor_v1(
            public,
            base[CA_IO_BYTE],
            fixed[FIX_IO_OFFSET],
            lane,
            io_challenges,
        )?;
        residues.push(fixed[FIX_IO_FIRST].mul(serialized_sha.sub(current_sha_factor)));
        residues.push(fixed[FIX_IO_FIRST].mul(root_spki_io.sub(current_io_factor)));
        let next_sha_factor = serialized_sha_factor_v1(
            fixed[FIX_IO_NEXT_WORD_END],
            fixed[FIX_IO_NEXT_WORD_INDEX],
            next_base[CA_IO_WORD_ACC],
            lane,
            sha_challenges,
        )?;
        let next_io_factor = root_spki_io_factor_v1(
            public,
            next_base[CA_IO_BYTE],
            fixed[FIX_IO_OFFSET].add(A::ONE),
            lane,
            io_challenges,
        )?;
        residues.push(io_transition.mul(
            next_aux[serialized_sha_product_cell_v1(lane)].sub(serialized_sha.mul(next_sha_factor)),
        ));
        residues.push(io_transition.mul(
            next_aux[root_spki_io_product_cell_v1(lane)].sub(root_spki_io.mul(next_io_factor)),
        ));
        residues.push(non_io.mul(serialized_sha));
        residues.push(non_io.mul(root_spki_io));
    }
    if residues.len() != ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    Ok(residues)
}

/// Full algebraic test oracle, including reference terminal product bindings.
/// It shares the shipping local prefix and adds terminal equations for parity and
/// mutation controls; it is not an independent proof acceptance path.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn evaluate_ca_accumulator_stark_residues_v1<A: PolynomialAirFieldV1>(
    public: ZkX509CaAccumulatorStarkPublicV1,
    base: &[A],
    next_base: &[A],
    aux: &[A],
    next_aux: &[A],
    fixed: &[A],
    sha_challenges: ZkX509ShaCallBusChallengesV1,
    io_challenges: &ZkX509Rfc5280StarkChallengesV1,
    terminal_claims: ZkX509CaAccumulatorStarkTerminalClaimsV1,
) -> Result<Vec<A>, ZkX509AccumulatorStarkErrorV1> {
    if terminal_claims
        .source_products
        .iter()
        .flatten()
        .chain(terminal_claims.digest_products.iter().flatten())
        .chain(terminal_claims.root_spki_consumer_products.iter())
        .any(|value| F::canonical(value.0).is_none())
    {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    let mut residues = evaluate_ca_accumulator_local_residues_v1(
        public,
        base,
        next_base,
        aux,
        next_aux,
        fixed,
        sha_challenges,
        io_challenges,
    )?;
    let leaf = fixed[FIX_LEAF];
    for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
        let leaf_constant_source = leaf_constant_source_product_v1(lane, sha_challenges)?;
        let selected_source = leaf
            .mul_base(leaf_constant_source)
            .add(selected_node_terminal_v1(
                fixed,
                terminal_claims.source_products,
                lane,
            ));
        let selected_digest =
            selected_call_terminal_v1(fixed, terminal_claims.digest_products, lane);
        residues.push(aux[source_aux_cell_v1(SOURCE_STATES_V1 - 1, lane)].sub(selected_source));
        residues.push(aux[digest_aux_cell_v1(DIGEST_STATES_V1 - 1, lane)].sub(selected_digest));
        residues.push(
            fixed[FIX_IO_LAST].mul(
                aux[serialized_sha_product_cell_v1(lane)]
                    .mul_base(leaf_constant_source)
                    .sub(A::from_base(terminal_claims.source_products[0][lane])),
            ),
        );
        residues.push(
            fixed[FIX_IO_LAST].mul(aux[root_spki_io_product_cell_v1(lane)].sub(A::from_base(
                terminal_claims.root_spki_consumer_products[lane],
            ))),
        );
    }
    if residues.len() != ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    Ok(residues)
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_aux_row_v1(
    public: ZkX509CaAccumulatorStarkPublicV1,
    base: &[F; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1],
    fixed: &[F; ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1],
    previous_aux: Option<&[F; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1]>,
    sha_challenges: ZkX509ShaCallBusChallengesV1,
    io_challenges: &ZkX509Rfc5280StarkChallengesV1,
) -> Result<[F; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1], ZkX509AccumulatorStarkErrorV1> {
    let mut aux = [F::ZERO; ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1];
    if fixed[FIX_ACTIVE] == F::ONE {
        for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
            aux[source_aux_cell_v1(0, lane)] = F::ONE;
            for step in 0..SOURCE_PAIR_STEPS_V1 {
                aux[source_aux_cell_v1(step + 1, lane)] = aux[source_aux_cell_v1(step, lane)]
                    .mul(source_factor_v1(
                        base,
                        fixed,
                        2 * step,
                        lane,
                        sha_challenges,
                    )?)
                    .mul(source_factor_v1(
                        base,
                        fixed,
                        2 * step + 1,
                        lane,
                        sha_challenges,
                    )?);
            }
            aux[digest_aux_cell_v1(0, lane)] = F::ONE;
            for step in 0..DIGEST_PAIR_STEPS_V1 {
                aux[digest_aux_cell_v1(step + 1, lane)] = aux[digest_aux_cell_v1(step, lane)]
                    .mul(digest_factor_v1(
                        base,
                        fixed,
                        2 * step,
                        lane,
                        sha_challenges,
                    )?)
                    .mul(digest_factor_v1(
                        base,
                        fixed,
                        2 * step + 1,
                        lane,
                        sha_challenges,
                    )?);
            }
        }
    }
    if fixed[FIX_IO_ACTIVE] == F::ONE {
        for lane in 0..ZK_X509_RFC5280_STARK_BUS_LANES_V1 {
            let previous_sha = if fixed[FIX_IO_FIRST] == F::ONE {
                F::ONE
            } else {
                previous_aux.ok_or(ZkX509AccumulatorStarkErrorV1::Shape)?
                    [serialized_sha_product_cell_v1(lane)]
            };
            let previous_io = if fixed[FIX_IO_FIRST] == F::ONE {
                F::ONE
            } else {
                previous_aux.ok_or(ZkX509AccumulatorStarkErrorV1::Shape)?
                    [root_spki_io_product_cell_v1(lane)]
            };
            aux[serialized_sha_product_cell_v1(lane)] = previous_sha.mul(serialized_sha_factor_v1(
                fixed[FIX_IO_WORD_END],
                fixed[FIX_IO_WORD_INDEX],
                base[CA_IO_WORD_ACC],
                lane,
                sha_challenges,
            )?);
            aux[root_spki_io_product_cell_v1(lane)] = previous_io.mul(root_spki_io_factor_v1(
                public,
                base[CA_IO_BYTE],
                fixed[FIX_IO_OFFSET],
                lane,
                io_challenges,
            )?);
        }
    }
    Ok(aux)
}
#[cfg(test)]
fn selected_node_terminal_v1<A: PolynomialAirFieldV1>(
    fixed: &[A],
    claims: [[F; ZK_X509_SHA_BUS_LANES_V1]; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
    lane: usize,
) -> A {
    (0..ZK_X509_CA_COMPACT_TREE_DEPTH_V1).fold(A::ZERO, |selected, level| {
        selected.add(fixed[FIX_INDEX_SELECTORS_START + level].mul_base(claims[level + 1][lane]))
    })
}
fn serialized_sha_factor_v1<A: PolynomialAirFieldV1>(
    word_end: A,
    word_index: A,
    word_value: A,
    lane: usize,
    challenges: ZkX509ShaCallBusChallengesV1,
) -> Result<A, ZkX509AccumulatorStarkErrorV1> {
    let lane_challenge = challenges
        .lanes
        .get(lane)
        .copied()
        .ok_or(ZkX509AccumulatorStarkErrorV1::CallBus)?;
    let factor = compress_sha_call_fields_v1(
        A::from_base(F(ZK_X509_SHA_CA_LEAF_CALL_V1 as u64)),
        A::from_base(F(u64::from(ZkX509ShaCallRoleV1::CaLeaf.role_code()))),
        A::ZERO,
        A::from_base(F(u64::from(ZkX509ShaCallWordKindV1::Input.code()))),
        word_index,
        word_value,
        lane_challenge,
    );
    Ok(A::ONE.add(word_end.mul(factor.sub(A::ONE))))
}
fn leaf_constant_source_product_v1(
    lane: usize,
    challenges: ZkX509ShaCallBusChallengesV1,
) -> Result<F, ZkX509AccumulatorStarkErrorV1> {
    let fixed = compile_ca_accumulator_fixed_row_v1(0)?;
    let base = [F::ZERO; ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1];
    (0..SOURCE_WORDS_V1).try_fold(F::ONE, |product, word| {
        if (LEAF_DYNAMIC_WORD_START_V1..=LEAF_DYNAMIC_WORD_END_V1).contains(&word) {
            Ok(product)
        } else {
            Ok(product.mul(source_factor_v1(&base, &fixed, word, lane, challenges)?))
        }
    })
}
fn root_spki_io_factor_v1<A: PolynomialAirFieldV1>(
    public: ZkX509CaAccumulatorStarkPublicV1,
    value: A,
    offset: A,
    lane: usize,
    challenges: &ZkX509Rfc5280StarkChallengesV1,
) -> Result<A, ZkX509AccumulatorStarkErrorV1> {
    let challenge = challenges
        .tuple
        .get(lane)
        .copied()
        .ok_or(ZkX509AccumulatorStarkErrorV1::IoBus)?;
    let values = [
        A::from_base(F(80)),
        A::from_base(F(ZkX509Rfc5280OutputRoleV1::GovernedTrustAnchor as u64)),
        A::from_base(public.root_spki_channel),
        A::from_base(F(4)),
        A::ZERO,
        offset,
        value,
        A::ZERO,
        A::ZERO,
        A::ZERO,
        A::ZERO,
        A::ZERO,
    ];
    Ok(values
        .into_iter()
        .zip(challenge)
        .fold(A::ZERO, |sum, (term, coefficient)| {
            sum.add(term.mul_base(coefficient))
        }))
}
#[cfg(test)]
fn selected_call_terminal_v1<A: PolynomialAirFieldV1>(
    fixed: &[A],
    claims: [[F; ZK_X509_SHA_BUS_LANES_V1]; ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1],
    lane: usize,
) -> A {
    let mut selected = fixed[FIX_LEAF].mul_base(claims[0][lane]);
    for level in 0..ZK_X509_CA_COMPACT_TREE_DEPTH_V1 {
        selected = selected
            .add(fixed[FIX_INDEX_SELECTORS_START + level].mul_base(claims[level + 1][lane]));
    }
    selected
}
fn source_factor_v1<A: PolynomialAirFieldV1>(
    base: &[A],
    fixed: &[A],
    word: usize,
    lane: usize,
    challenges: ZkX509ShaCallBusChallengesV1,
) -> Result<A, ZkX509AccumulatorStarkErrorV1> {
    let factor = compress_sha_call_fields_v1(
        fixed[FIX_CALL],
        fixed[FIX_ROLE],
        fixed[FIX_SLOT],
        A::from_base(F(u64::from(ZkX509ShaCallWordKindV1::Input.code()))),
        A::from_base(F(
            u64::try_from(word).map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?
        )),
        source_word_v1(base, fixed, word)?,
        challenges.lanes[lane],
    );
    if (LEAF_DYNAMIC_WORD_START_V1..=LEAF_DYNAMIC_WORD_END_V1).contains(&word) {
        Ok(fixed[FIX_LEAF].add(fixed[FIX_NODE].mul(factor)))
    } else {
        Ok(factor)
    }
}
fn digest_factor_v1<A: PolynomialAirFieldV1>(
    base: &[A],
    fixed: &[A],
    word: usize,
    lane: usize,
    challenges: ZkX509ShaCallBusChallengesV1,
) -> Result<A, ZkX509AccumulatorStarkErrorV1> {
    Ok(compress_sha_call_fields_v1(
        fixed[FIX_CALL],
        fixed[FIX_ROLE],
        fixed[FIX_SLOT],
        A::from_base(F(u64::from(ZkX509ShaCallWordKindV1::Digest.code()))),
        A::from_base(F(
            u64::try_from(word).map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?
        )),
        pack_be_bytes_v1(&base[CA_DIGEST_START + word * 4..CA_DIGEST_START + word * 4 + 4]),
        challenges.lanes[lane],
    ))
}
fn source_word_v1<A: PolynomialAirFieldV1>(
    base: &[A],
    fixed: &[A],
    word: usize,
) -> Result<A, ZkX509AccumulatorStarkErrorV1> {
    if word >= SOURCE_WORDS_V1 {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    let mut value = fixed[FIX_SOURCE_CONSTANTS_START + word];
    for byte in 0..32 {
        // `source_factor_v1` already selects this complete word with
        // `FIX_NODE`. Multiplying every dynamic byte by the same selector here
        // would rely on `node^2 = node` only on the native domain and raise
        // the actual univariate quotient above the three-chunk FRI capacity.
        // The unselected leaf/I/O/padding value is immaterial because the
        // outer selector and zero-initialized product recurrence reject it.
        value = value.add(dynamic_byte_contribution_v1(
            word,
            NODE_LEFT_DYNAMIC_OFFSET_V1 + byte,
            base[CA_LEFT_START + byte],
        ));
        value = value.add(dynamic_byte_contribution_v1(
            word,
            NODE_RIGHT_DYNAMIC_OFFSET_V1 + byte,
            base[CA_RIGHT_START + byte],
        ));
    }
    Ok(value)
}
fn dynamic_byte_contribution_v1<A: PolynomialAirFieldV1>(
    word: usize,
    offset: usize,
    value: A,
) -> A {
    if offset / 4 != word {
        return A::ZERO;
    }
    value.mul_base(F(1_u64 << (8 * (3 - offset % 4))))
}
fn padded_source_words_v1(
    message: &[u8],
) -> Result<[u32; SOURCE_WORDS_V1], ZkX509AccumulatorStarkErrorV1> {
    if message.is_empty() || message.len() > 183 {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    let mut padded = Vec::new();
    padded
        .try_reserve_exact(SOURCE_WORDS_V1 * 4)
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    padded.extend_from_slice(message);
    padded.push(0x80);
    padded.resize(SOURCE_WORDS_V1 * 4 - 8, 0);
    padded.extend_from_slice(
        &u64::try_from(message.len())
            .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?
            .checked_mul(8)
            .ok_or(ZkX509AccumulatorStarkErrorV1::Resource)?
            .to_be_bytes(),
    );
    if padded.len() != SOURCE_WORDS_V1 * 4 {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    padded
        .chunks_exact(4)
        .map(|word| u32::from_be_bytes(word.try_into().expect("four bytes")))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_: Vec<u32>| ZkX509AccumulatorStarkErrorV1::Shape)
}
const fn source_aux_cell_v1(state: usize, lane: usize) -> usize {
    SOURCE_AUX_START + state * ZK_X509_SHA_BUS_LANES_V1 + lane
}
const fn digest_aux_cell_v1(state: usize, lane: usize) -> usize {
    DIGEST_AUX_START + state * ZK_X509_SHA_BUS_LANES_V1 + lane
}
const fn serialized_sha_product_cell_v1(lane: usize) -> usize {
    SERIALIZED_SHA_PRODUCT_START + lane
}
const fn root_spki_io_product_cell_v1(lane: usize) -> usize {
    ROOT_SPKI_IO_PRODUCT_START + lane
}
fn pack_little_bits_v1<A: PolynomialAirFieldV1>(bits: &[A]) -> A {
    bits.iter().enumerate().fold(A::ZERO, |value, (bit, cell)| {
        value.add(cell.mul_base(F(1_u64 << bit)))
    })
}
fn pack_be_bytes_v1<A: PolynomialAirFieldV1>(bytes: &[A]) -> A {
    bytes
        .iter()
        .fold(A::ZERO, |value, byte| value.mul_base(F(256)).add(*byte))
}
fn allocate_columns_v1(
    width: usize,
    rows: usize,
) -> Result<Vec<Vec<F>>, ZkX509AccumulatorStarkErrorV1> {
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(width)
        .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
    for _ in 0..width {
        let mut column = Vec::new();
        column
            .try_reserve_exact(rows)
            .map_err(|_| ZkX509AccumulatorStarkErrorV1::Resource)?;
        columns.push(column);
    }
    Ok(columns)
}
fn append_array_row_v1<const WIDTH: usize>(
    columns: &mut [Vec<F>],
    row: &[F; WIDTH],
) -> Result<(), ZkX509AccumulatorStarkErrorV1> {
    if columns.len() != WIDTH {
        return Err(ZkX509AccumulatorStarkErrorV1::Shape);
    }
    for (column, value) in columns.iter_mut().zip(row.iter().copied()) {
        column.push(value);
    }
    Ok(())
}
fn ca_aggregate_layout_v1()
-> Result<aggregate::AggregateProofLayoutV1, ZkX509CaAccumulatorProofErrorV1> {
    let layout = aggregate::AggregateProofLayoutV1::new_with_trace_layout_v1(
        CA_AGGREGATE_PARAMETERS_V1,
        vec![aggregate::AggregateTraceGroupLayoutV1 {
            native_trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            segment_instances: ZK_X509_CA_ACCUMULATOR_CHUNKS_V1,
            base_width: ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
            aux_width: ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
        }],
        aggregate::AggregateTraceLayoutV1::GroupedCurrent,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    if layout.common_lde_log2() != ZK_X509_CA_FRI_LDE_LOG2_V1
        || layout
            .fri_rounds(CA_AGGREGATE_PARAMETERS_V1)
            .map_err(map_aggregate_proof_error_v1)?
            != usize::from(ZK_X509_CA_FRI_ROUNDS_V1)
        || aggregate::maximum_encoded_proof_with_deep_bytes_v1(CA_AGGREGATE_PARAMETERS_V1, &layout)
            .map_err(map_aggregate_proof_error_v1)?
            > CA_INNER_MAXIMUM_PROOF_BYTES_V1
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    Ok(layout)
}
/// Validate the FRI certificate against the same closed CA parameters and layout
/// used by the actual prover and verifier. A one-column surrogate cannot admit
/// this profile's dedicated native12-to-LDE16 padding geometry.
pub(super) fn validate_ca_fri_theorem_certificate_v1(
    certificate: aggregate::AggregateFriTheorem2CertificateV1,
) -> Result<aggregate::AggregateFriTheorem2BoundV1, ZkX509CaAccumulatorProofErrorV1> {
    aggregate::validate_affine_batched_fri_theorem2_v1(
        CA_AGGREGATE_PARAMETERS_V1,
        &ca_aggregate_layout_v1()?,
        certificate,
    )
    .map_err(map_aggregate_proof_error_v1)
}
fn canonical_ca_manifest_role_v1(
    call: usize,
) -> Result<ZkX509ShaCallRoleV1, ZkX509CaAccumulatorProofErrorV1> {
    if call == ZK_X509_SHA_CA_LEAF_CALL_V1 {
        return Ok(ZkX509ShaCallRoleV1::CaLeaf);
    }
    call.checked_sub(ZK_X509_SHA_CA_NODE_CALL_START_V1)
        .filter(|level| *level < ZK_X509_CA_COMPACT_TREE_DEPTH_V1)
        .and_then(|level| u8::try_from(level).ok())
        .map(ZkX509ShaCallRoleV1::CaNode)
        .ok_or(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)
}
fn validate_ca_proof_schedule_v1(
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
    if schedule.shape().disclosed_attributes > 4 {
        return Err(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness);
    }
    for call in ZK_X509_SHA_CA_LEAF_CALL_V1
        ..ZK_X509_SHA_CA_LEAF_CALL_V1 + ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1
    {
        let manifest = schedule
            .call(call)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
        if usize::from(manifest.call) != call
            || manifest.role != canonical_ca_manifest_role_v1(call)?
            || manifest.activation != ZkX509ShaCallActivationV1::Required
            || manifest.maximum_message_bytes == 0
            || manifest.maximum_blocks != 3
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness);
        }
    }
    Ok(())
}
fn ca_schedule_digest_v1(
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<PrivacyOuterDigestV1, ZkX509CaAccumulatorProofErrorV1> {
    validate_ca_proof_schedule_v1(schedule)?;
    let mut encoding = Vec::new();
    encoding
        .try_reserve_exact(4 + schedule.calls().len() * 35)
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
    append_u32_v1(
        &mut encoding,
        u32::try_from(schedule.shape().disclosed_attributes)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?,
    );
    for manifest in schedule.calls() {
        encoding.push(manifest.call);
        encoding.push(manifest.role.role_code());
        encoding.push(match manifest.activation {
            ZkX509ShaCallActivationV1::Required => 0,
            ZkX509ShaCallActivationV1::OptionalPrivate => 1,
            ZkX509ShaCallActivationV1::Inactive => 2,
        });
        append_u64_v1(
            &mut encoding,
            u64::try_from(manifest.maximum_message_bytes)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
        );
        append_u64_v1(
            &mut encoding,
            u64::try_from(manifest.maximum_blocks)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
        );
        append_u64_v1(
            &mut encoding,
            u64::try_from(manifest.first_event)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
        );
        append_u64_v1(
            &mut encoding,
            u64::try_from(manifest.first_logical_row)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
        );
    }
    privacy_outer_digest_frame_v1(
        ZK_X509_FIXED_DIGEST_CONTEXT_V1,
        CA_SCHEDULE_DIGEST_DOMAIN_V1,
        b"ca-sha-call-schedule",
        0,
        0,
        0,
        &[&encoding],
    )
    .map_err(map_transparent_proof_error_v1)
}
pub fn ca_profile_digest_v1() -> Result<PrivacyOuterDigestV1, ZkX509CaAccumulatorProofErrorV1> {
    let mut parameters = Vec::new();
    parameters.extend_from_slice(&CA_INNER_PROOF_MAGIC_V1);
    append_u16_v1(&mut parameters, ZK_X509_PROOF_VERSION_V1);
    parameters.push(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1);
    parameters.push(ZK_X509_CA_FRI_LDE_LOG2_V1);
    parameters.push(CA_TERMINAL_LOG2_V1);
    append_u16_v1(
        &mut parameters,
        u16::try_from(CA_TERMINAL_DEGREE_BOUND_V1)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
    );
    append_u16_v1(
        &mut parameters,
        u16::try_from(CA_QUERY_COUNT_V1).map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
    );
    append_u16_v1(
        &mut parameters,
        u16::try_from(CA_MASK_DEGREE_V1).map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
    );
    append_u16_v1(
        &mut parameters,
        u16::try_from(CA_COMPOSITION_DEGREE_CHUNKS_V1)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
    );
    parameters.push(ZK_X509_GRINDING_BITS_V1);
    append_u32_v1(
        &mut parameters,
        u32::try_from(CA_INNER_MAXIMUM_PROOF_BYTES_V1)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
    );
    privacy_outer_digest_frame_v1(
        ZK_X509_FIXED_DIGEST_CONTEXT_V1,
        CA_PROFILE_DIGEST_DOMAIN_V1,
        b"ca-proof-profile",
        0,
        0,
        0,
        &[
            ZK_X509_ACCUMULATOR_STARK_DESCRIPTOR_V1,
            TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1,
            &parameters,
            CA_BASE_LEAF_DOMAIN_V1,
            CA_BASE_NODE_DOMAIN_V1,
            CA_AUX_LEAF_DOMAIN_V1,
            CA_AUX_NODE_DOMAIN_V1,
            CA_COMPOSITION_LEAF_DOMAIN_V1,
            CA_COMPOSITION_NODE_DOMAIN_V1,
            CA_FRI_LEAF_DOMAIN_V1,
            CA_FRI_NODE_DOMAIN_V1,
        ],
    )
    .map_err(map_transparent_proof_error_v1)
}
fn validate_ca_proof_public_v1(
    public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
    validate_ca_proof_schedule_v1(schedule)?;
    validate_ca_accumulator_stark_public_v1(public, schedule)
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)
}
pub fn ca_public_digest_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: &ZkX509ShaCallScheduleV1,
) -> Result<PrivacyOuterDigestV1, ZkX509CaAccumulatorProofErrorV1> {
    validate_ca_proof_public_v1(public, schedule)?;
    let root = public
        .governed_root
        .map(|value| u8::try_from(value.0))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
    let channel = u32::try_from(public.root_spki_channel.0)
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?
        .to_be_bytes();
    let schedule_digest = ca_schedule_digest_v1(schedule)?;
    let schedule_digest = schedule_digest.to_bytes();
    privacy_outer_digest_frame_v1(
        proof_instance.ca_context_v1(),
        CA_PUBLIC_DIGEST_DOMAIN_V1,
        b"ca-public-statement",
        0,
        0,
        0,
        &[&root, &channel, &schedule_digest],
    )
    .map_err(map_transparent_proof_error_v1)
}
fn new_ca_transcript_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public: ZkX509CaAccumulatorStarkPublicV1,
    schedule: &ZkX509ShaCallScheduleV1,
    layout: &aggregate::AggregateProofLayoutV1,
) -> Result<TransparentTranscriptV1, ZkX509CaAccumulatorProofErrorV1> {
    let profile_digest = ca_profile_digest_v1()?;
    let public_digest = ca_public_digest_v1(proof_instance, public, schedule)?;
    let mut transcript = TransparentTranscriptV1::new(
        proof_instance.ca_context_v1(),
        ZK_X509_SUITE_V1,
        &profile_digest,
        &public_digest,
    )
    .map_err(map_transparent_proof_error_v1)?;
    transcript
        .absorb(
            b"zk-x509-ca-accumulator-proof-profile-v1",
            &[
                ZK_X509_ACCUMULATOR_STARK_DESCRIPTOR_V1,
                TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1,
            ],
        )
        .map_err(map_transparent_proof_error_v1)?;
    aggregate::absorb_layout_v1(
        &mut transcript,
        CA_AGGREGATE_PARAMETERS_V1,
        &ca_domains_v1(proof_instance),
        CA_RELATION_LAYOUT_DOMAIN_V1,
        layout,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    let schedule_digest = ca_schedule_digest_v1(schedule)?;
    let mut registration = Vec::new();
    registration.extend_from_slice(b"X5A1");
    append_u16_v1(&mut registration, CA_ADAPTER_ID_V1);
    append_u16_v1(&mut registration, 0);
    append_u32_v1(
        &mut registration,
        u32::try_from(schedule.shape().disclosed_attributes)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?,
    );
    for value in public.governed_root {
        append_u64_v1(&mut registration, value.0);
    }
    append_u64_v1(&mut registration, public.root_spki_channel.0);
    registration.extend_from_slice(&schedule_digest.to_bytes());
    transcript
        .absorb(CA_REGISTRATION_DOMAIN_V1, &[&registration])
        .map_err(map_transparent_proof_error_v1)?;
    Ok(transcript)
}
/// Encode the sole claim-free CA component frame. Acceptance requires both
/// members of the paired original-oracle credential verifier.
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn encode_ca_proof_envelope_v1(inner: &[u8]) -> Result<Vec<u8>, ZkX509CaAccumulatorProofErrorV1> {
    if inner.len() < 4
        || inner[..4] != CA_INNER_PROOF_MAGIC_V1
        || inner.len() > CA_INNER_MAXIMUM_PROOF_BYTES_V1
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::MalformedProof);
    }
    let exact = CA_PROOF_ENVELOPE_BYTES_V1
        .checked_add(inner.len())
        .ok_or(ZkX509CaAccumulatorProofErrorV1::ProofTooLarge)?;
    if exact > ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 {
        return Err(ZkX509CaAccumulatorProofErrorV1::ProofTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(exact)
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
    encoded.extend_from_slice(&CA_PROOF_MAGIC_V1);
    append_u16_v1(&mut encoded, ZK_X509_PROOF_VERSION_V1);
    append_u32_v1(
        &mut encoded,
        u32::try_from(inner.len()).map_err(|_| ZkX509CaAccumulatorProofErrorV1::ProofTooLarge)?,
    );
    encoded.extend_from_slice(inner);
    Ok(encoded)
}
fn decode_ca_proof_envelope_v1(encoded: &[u8]) -> Result<&[u8], ZkX509CaAccumulatorProofErrorV1> {
    if encoded.len() > ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 {
        return Err(ZkX509CaAccumulatorProofErrorV1::ProofTooLarge);
    }
    if encoded.len() < CA_PROOF_ENVELOPE_BYTES_V1 + 4
        || encoded[..4] != CA_PROOF_MAGIC_V1
        || u16::from_be_bytes(
            encoded[4..6]
                .try_into()
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::MalformedProof)?,
        ) != ZK_X509_PROOF_VERSION_V1
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::MalformedProof);
    }
    let len = usize::try_from(u32::from_be_bytes(
        encoded[CA_PROOF_LENGTH_OFFSET_V1..CA_PROOF_ENVELOPE_BYTES_V1]
            .try_into()
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::MalformedProof)?,
    ))
    .map_err(|_| ZkX509CaAccumulatorProofErrorV1::MalformedProof)?;
    if len < 4
        || len > CA_INNER_MAXIMUM_PROOF_BYTES_V1
        || CA_PROOF_ENVELOPE_BYTES_V1.checked_add(len) != Some(encoded.len())
        || encoded[CA_PROOF_ENVELOPE_BYTES_V1..CA_PROOF_ENVELOPE_BYTES_V1 + 4]
            != CA_INNER_PROOF_MAGIC_V1
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::MalformedProof);
    }
    Ok(&encoded[CA_PROOF_ENVELOPE_BYTES_V1..])
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn ca_fixed_lde_columns_v1(
    native_columns: &[Vec<F>],
) -> Result<Vec<Vec<F>>, ZkX509CaAccumulatorProofErrorV1> {
    if native_columns.len() != ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1
        || native_columns
            .iter()
            .any(|column| column.len() != ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness);
    }
    let native_root = goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1)
        .map_err(map_transparent_proof_error_v1)?;
    let lde_root = goldilocks_primitive_root_v1(ZK_X509_CA_FRI_LDE_LOG2_V1)
        .map_err(map_transparent_proof_error_v1)?;
    let lde_rows = 1_usize
        .checked_shl(u32::from(ZK_X509_CA_FRI_LDE_LOG2_V1))
        .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?;
    native_columns
        .iter()
        .map(|native| {
            let mut coefficients = native.clone();
            goldilocks_ifft_v1(&mut coefficients, native_root)
                .map_err(map_transparent_proof_error_v1)?;
            coefficients.resize(lde_rows, F::ZERO);
            goldilocks_evaluate_coset_v1(
                &coefficients,
                lde_rows,
                lde_root,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_proof_error_v1)
        })
        .collect()
}
/// Evaluate the verifier's native fixed polynomials at a true Fp4 point.
/// Only one native coefficient column is duplicated at a time.
fn ca_fixed_columns_at_deep_v1(
    native_columns: &[Vec<F>],
    point: E,
) -> Result<Vec<E>, ZkX509CaAccumulatorProofErrorV1> {
    if !point.is_canonical()
        || native_columns.len() != ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1
        || native_columns.iter().any(|column| {
            column.len() != ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
                || column.iter().any(|value| !value.is_canonical())
        })
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness);
    }
    let root = goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1)
        .map_err(map_transparent_proof_error_v1)?;
    native_columns
        .iter()
        .map(|column| {
            let mut coefficients = column.clone();
            goldilocks_ifft_v1(&mut coefficients, root).map_err(map_transparent_proof_error_v1)?;
            Ok(coefficients
                .iter()
                .rev()
                .fold(E::ZERO, |value, coefficient| {
                    value.mul(point).add(E::from_base(*coefficient))
                }))
        })
        .collect()
}

/// Check every compact-CA AIR identity at the transcript's Fp4 DEEP point.
///
/// This relation check must succeed before the current-only query rows bind
/// every current/next DEEP opening to the committed low-degree polynomials.
#[allow(clippy::too_many_arguments)]
fn verify_ca_deep_constraints_v1(
    public: ZkX509CaAccumulatorStarkPublicV1,
    deep: &aggregate::AggregateDeepProofV1,
    point: E,
    layout: &aggregate::AggregateProofLayoutV1,
    native_fixed: &[Vec<F>],
    sha_challenges: ZkX509ShaCallBusChallengesV1,
    io_challenges: &ZkX509Rfc5280StarkChallengesV1,
    alphas: &[E],
) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
    if !aggregate::deep_point_is_admissible_v1(point, CA_AGGREGATE_PARAMETERS_V1, layout)
        .map_err(map_aggregate_proof_error_v1)?
        || CA_SECURITY_LANES_V1 != 1
        || alphas.len() != ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1
        || alphas.iter().any(|value| !value.is_canonical())
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
    }
    let groups =
        aggregate::canonical_deep_trace_groups_v1(deep, CA_AGGREGATE_PARAMETERS_V1, layout)
            .map_err(map_aggregate_proof_error_v1)?;
    let [group] = groups.as_slice() else {
        return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
    };
    let fixed = ca_fixed_columns_at_deep_v1(native_fixed, point)?;
    let residues = evaluate_ca_accumulator_local_residues_v1(
        public,
        &group.base_current,
        &group.base_next,
        &group.aux_current,
        &group.aux_next,
        &fixed,
        sha_challenges,
        io_challenges,
    )
    .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
    let inverse_vanishing = point
        .pow(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 as u128)
        .sub(E::ONE)
        .inv()
        .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
    let chunk_power = point.pow(
        super::composition_masking::QuotientChunkGeometryV1::new_v1(
            layout,
            CA_AGGREGATE_PARAMETERS_V1,
        )
        .map_err(map_aggregate_proof_error_v1)?
        .stride_v1() as u128,
    );
    let expected = residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |value, (residue, coefficient)| {
            value.add(residue.mul(*coefficient))
        })
        .mul(inverse_vanishing);
    let chunks = aggregate::canonical_fp4_fields_v1(
        &deep.composition_values[0],
        CA_COMPOSITION_DEGREE_CHUNKS_V1,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    let actual = chunks
        .iter()
        .rev()
        .fold(E::ZERO, |value, chunk| value.mul(chunk_power).add(*chunk));
    if expected != actual {
        return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
    }
    Ok(())
}
#[cfg(test)]
fn ca_lde_row_v1(
    columns: &[Vec<F>],
    index: usize,
    expected_width: usize,
    expected_rows: usize,
) -> Result<Vec<F>, ZkX509CaAccumulatorProofErrorV1> {
    if columns.len() != expected_width
        || index >= expected_rows
        || columns.iter().any(|column| column.len() != expected_rows)
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    Ok(columns.iter().map(|column| column[index]).collect())
}
fn derive_ca_constraint_alphas_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<Vec<E>, ZkX509CaAccumulatorProofErrorV1> {
    (0..ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1)
        .map(|_| {
            transcript
                .challenge_fp4(CA_CONSTRAINT_ALPHA_LABEL_V1)
                .map_err(map_transparent_proof_error_v1)
        })
        .collect()
}
/// Clearing owner retained through every commitment, transcript and FRI operation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
type CaCompositionLanesV1 = super::private_table::PrivateTableV1<Vec<Vec<E>>>;

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn erase_ca_composition_chunks_v1(chunks: &mut [Vec<E>]) {
    for chunk in chunks {
        super::private_table::zeroize_words_v1(chunk);
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn own_ca_composition_lane_v1(
    chunks: Vec<Vec<E>>,
) -> Result<CaCompositionLanesV1, ZkX509CaAccumulatorProofErrorV1> {
    // Adopt the returned codewords before the only fallible outer reservation.
    let chunks = super::private_table::PrivateTableV1::new(chunks, erase_ca_composition_chunks_v1);
    let mut lanes = CaCompositionLanesV1::new(Vec::new(), |lanes| {
        for lane in lanes {
            erase_ca_composition_chunks_v1(lane);
        }
    });
    lanes
        .try_reserve_exact(1)
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
    lanes.push(chunks.into_vec());
    Ok(lanes)
}

fn ca_challenge_vector_v1(
    transcript: &mut TransparentTranscriptV1,
    label: &[u8],
    count: usize,
) -> Result<Vec<E>, ZkX509CaAccumulatorProofErrorV1> {
    (0..count)
        .map(|_| {
            transcript
                .challenge_fp4(label)
                .map_err(map_transparent_proof_error_v1)
        })
        .collect()
}
fn derive_ca_deep_mixes_v1(
    transcript: &mut TransparentTranscriptV1,
    layout: &aggregate::AggregateProofLayoutV1,
) -> Result<Vec<aggregate::AggregateDeepLaneMixV1>, ZkX509CaAccumulatorProofErrorV1> {
    let mix = aggregate::AggregateDeepLaneMixV1 {
        trace_groups: vec![aggregate::AggregateDeepTraceGroupMixV1 {
            base_current: ca_challenge_vector_v1(
                transcript,
                CA_DEEP_BASE_CURRENT_MIX_LABEL_V1,
                ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
            )?,
            base_next: ca_challenge_vector_v1(
                transcript,
                CA_DEEP_BASE_NEXT_MIX_LABEL_V1,
                ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
            )?,
            aux_current: ca_challenge_vector_v1(
                transcript,
                CA_DEEP_AUX_CURRENT_MIX_LABEL_V1,
                ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
            )?,
            aux_next: ca_challenge_vector_v1(
                transcript,
                CA_DEEP_AUX_NEXT_MIX_LABEL_V1,
                ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
            )?,
        }],
        composition: ca_challenge_vector_v1(
            transcript,
            CA_DEEP_COMPOSITION_MIX_LABEL_V1,
            CA_COMPOSITION_DEGREE_CHUNKS_V1,
        )?,
    };
    let mixes = vec![mix];
    aggregate::validate_deep_lane_mixes_v1(&mixes, CA_AGGREGATE_PARAMETERS_V1, layout)
        .map_err(map_aggregate_proof_error_v1)?;
    Ok(mixes)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn ca_fri_base_v1(
    trace_material: &aggregate::AggregateTraceGroupMaterialV1,
    composition: &[Vec<E>],
    deep: &aggregate::AggregateDeepProofV1,
    deep_point: E,
    mix: &aggregate::AggregateDeepLaneMixV1,
    layout: &aggregate::AggregateProofLayoutV1,
) -> Result<Vec<E>, ZkX509CaAccumulatorProofErrorV1> {
    let deep_trace =
        aggregate::canonical_deep_trace_groups_v1(deep, CA_AGGREGATE_PARAMETERS_V1, layout)
            .map_err(map_aggregate_proof_error_v1)?
            .into_iter()
            .next()
            .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
    let deep_composition = aggregate::canonical_fp4_fields_v1(
        deep.composition_values
            .first()
            .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?,
        CA_COMPOSITION_DEGREE_CHUNKS_V1,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    let coefficients = mix
        .trace_groups
        .first()
        .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
    let rows = layout.common_lde_size();
    if trace_material.base_lde.len() != coefficients.base_current.len()
        || trace_material.base_lde.len() != coefficients.base_next.len()
        || trace_material.aux_lde.len() != coefficients.aux_current.len()
        || trace_material.aux_lde.len() != coefficients.aux_next.len()
        || composition.len() != mix.composition.len()
        || deep_trace.base_current.len() != trace_material.base_lde.len()
        || deep_trace.base_next.len() != trace_material.base_lde.len()
        || deep_trace.aux_current.len() != trace_material.aux_lde.len()
        || deep_trace.aux_next.len() != trace_material.aux_lde.len()
        || deep_composition.len() != composition.len()
        || composition.iter().any(|chunk| chunk.len() != rows)
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
    }
    let native_root = goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1)
        .map_err(map_transparent_proof_error_v1)?;
    let deep_next = deep_point.mul_base(native_root);
    let lde_root = goldilocks_primitive_root_v1(layout.common_lde_log2())
        .map_err(map_transparent_proof_error_v1)?;
    let mut denominators = Vec::new();
    denominators
        .try_reserve_exact(
            rows.checked_mul(2)
                .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?,
        )
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
    let mut x = F(GOLDILOCKS_GENERATOR_V1);
    for _ in 0..rows {
        let point = E::from_base(x);
        denominators.push(point.sub(deep_point));
        denominators.push(point.sub(deep_next));
        x = x.mul(lde_root);
    }
    aggregate::batch_invert_fp4_nonzero_v1(&mut denominators)
        .map_err(map_aggregate_proof_error_v1)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
    for index in 0..rows {
        let current_inverse = denominators[2 * index];
        let next_inverse = denominators[2 * index + 1];
        let mut quotient = E::ZERO;
        for (column, ((deep_current, deep_next), (mix_current, mix_next))) in
            trace_material.base_lde.iter().zip(
                deep_trace
                    .base_current
                    .iter()
                    .zip(&deep_trace.base_next)
                    .zip(
                        coefficients
                            .base_current
                            .iter()
                            .zip(&coefficients.base_next),
                    ),
            )
        {
            let value = E::from_base(column[index]);
            quotient = quotient
                .add(
                    value
                        .sub(*deep_current)
                        .mul(current_inverse)
                        .mul(*mix_current),
                )
                .add(value.sub(*deep_next).mul(next_inverse).mul(*mix_next));
        }
        for (column, ((deep_current, deep_next), (mix_current, mix_next))) in
            trace_material.aux_lde.iter().zip(
                deep_trace
                    .aux_current
                    .iter()
                    .zip(&deep_trace.aux_next)
                    .zip(coefficients.aux_current.iter().zip(&coefficients.aux_next)),
            )
        {
            let value = E::from_base(column[index]);
            quotient = quotient
                .add(
                    value
                        .sub(*deep_current)
                        .mul(current_inverse)
                        .mul(*mix_current),
                )
                .add(value.sub(*deep_next).mul(next_inverse).mul(*mix_next));
        }
        for (chunk, (deep_value, coefficient)) in composition
            .iter()
            .zip(deep_composition.iter().zip(&mix.composition))
        {
            quotient = quotient.add(
                chunk[index]
                    .sub(*deep_value)
                    .mul(current_inverse)
                    .mul(*coefficient),
            );
        }
        result.push(quotient);
    }
    Ok(result)
}
fn absorb_ca_grinding_nonce_v1(
    transcript: &mut TransparentTranscriptV1,
    nonce: u64,
) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
    transcript
        .absorb(CA_GRINDING_NONCE_DOMAIN_V1, &[&nonce.to_be_bytes()])
        .map_err(map_transparent_proof_error_v1)
}
/// Decode the sole compact-CA base root needed by the joint X5S1 schedule.
///
/// Decoding establishes canonical shape and bounds but is not proof verification. An outer verifier
/// may use this root to construct the shared pre-auxiliary schedule only if it subsequently accepts
/// both joint CA and MAIN verifier finishes for the same exact proof bytes.
pub fn ca_accumulator_base_root_from_proof_v1(
    proof_bytes: &[u8],
) -> Result<PrivacyOuterDigestV1, ZkX509CaAccumulatorProofErrorV1> {
    let layout = ca_aggregate_layout_v1()?;
    let inner = decode_ca_proof_envelope_v1(proof_bytes)?;
    let (proof, _) =
        aggregate::decode_proof_with_deep_v1(inner, CA_AGGREGATE_PARAMETERS_V1, &layout)
            .map_err(map_aggregate_proof_error_v1)?;
    proof
        .trace_groups
        .first()
        .filter(|_| proof.trace_groups.len() == 1)
        .map(|group| group.base_root)
        .ok_or(ZkX509CaAccumulatorProofErrorV1::MalformedProof)
}
// Independent full-reference composition oracle for local-relation differential tests.
#[cfg(test)]
fn ca_quotient_value_v1(
    x: F,
    residues: &[F],
    alphas: &[E],
) -> Result<E, ZkX509CaAccumulatorProofErrorV1> {
    if residues.len() != ZK_X509_CA_ACCUMULATOR_CONSTRAINT_COUNT_V1
        || residues.len() != alphas.len()
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
    }
    let inverse_vanishing = x
        .pow(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 as u128)
        .sub(F::ONE)
        .inv()
        .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
    Ok(residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |sum, (residue, alpha)| {
            sum.add(alpha.mul_base(*residue))
        })
        .mul_base(inverse_vanishing))
}

#[cfg(test)]
fn ca_composition_lanes_v1<R: rand::TryRngCore>(
    public: ZkX509CaAccumulatorStarkPublicV1,
    base_lde: &[Vec<F>],
    aux_lde: &[Vec<F>],
    fixed_lde: &[Vec<F>],
    sha_challenges: ZkX509ShaCallBusChallengesV1,
    io_challenges: &ZkX509Rfc5280StarkChallengesV1,
    claims: ZkX509CaAccumulatorStarkTerminalClaimsV1,
    alphas: &[E],
    layout: &aggregate::AggregateProofLayoutV1,
    rng: &mut R,
) -> Result<CaCompositionLanesV1, ZkX509CaAccumulatorProofErrorV1> {
    let rows = layout.common_lde_size();
    let group = layout
        .trace_groups()
        .first()
        .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?;
    let stride = group
        .next_stride(layout.common_lde_log2())
        .map_err(map_aggregate_proof_error_v1)?;
    if rows != 1_usize << ZK_X509_CA_FRI_LDE_LOG2_V1
        || group.base_width != ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
        || group.aux_width != ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
    {
        return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
    }
    let lde_root = goldilocks_primitive_root_v1(layout.common_lde_log2())
        .map_err(map_transparent_proof_error_v1)?;
    let mut evaluations =
        super::private_table::PrivateTableV1::new(Vec::new(), |values: &mut [E]| {
            super::private_table::zeroize_words_v1(values);
        });
    evaluations
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
    let mut x = F(GOLDILOCKS_GENERATOR_V1);
    for index in 0..rows {
        let next = (index + stride) % rows;
        let base = ca_lde_row_v1(base_lde, index, ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1, rows)?;
        let next_base = ca_lde_row_v1(base_lde, next, ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1, rows)?;
        let aux = ca_lde_row_v1(aux_lde, index, ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1, rows)?;
        let next_aux = ca_lde_row_v1(aux_lde, next, ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1, rows)?;
        let fixed = ca_lde_row_v1(
            fixed_lde,
            index,
            ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1,
            rows,
        )?;
        let residues = evaluate_ca_accumulator_stark_residues_v1(
            public,
            &base,
            &next_base,
            &aux,
            &next_aux,
            &fixed,
            sha_challenges,
            io_challenges,
            claims,
        )
        .map_err(ZkX509CaAccumulatorProofErrorV1::from)?;
        evaluations.push(ca_quotient_value_v1(x, &residues, alphas)?);
        x = x.mul(lde_root);
    }
    let geometry = super::composition_masking::QuotientChunkGeometryV1::new_v1(
        layout,
        CA_AGGREGATE_PARAMETERS_V1,
    )
    .map_err(map_aggregate_proof_error_v1)?;
    let chunks = geometry
        .split_evaluations_v1(evaluations.into_vec(), layout.common_lde_log2(), rng)
        .map_err(map_aggregate_proof_error_v1)?;
    own_ca_composition_lane_v1(chunks)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        accumulator_air::{
            ZK_X509_CA_ACCUMULATOR_IO_START_V1, ZkX509CaAccumulatorStatementV1,
            ZkX509CaAccumulatorWitnessV1, build_ca_accumulator_trace_v1,
        },
        merkle::{
            ZK_X509_CA_SPKI_DER_BYTES_V1, ca_membership_path_from_complete_spkis_v1,
            ca_root_from_complete_spkis_v1,
        },
        sha_call_bus_stark::{ZkX509ShaCallBusLaneChallengesV1, ZkX509ShaCallPublicShapeV1},
        stark::zk_x509_test_digest384_v1,
    };
    use rand::{TryCryptoRng, TryRngCore};
    fn spki(index: u16) -> [u8; ZK_X509_CA_SPKI_DER_BYTES_V1] {
        let mut spki = [0x42; ZK_X509_CA_SPKI_DER_BYTES_V1];
        spki[..2].copy_from_slice(&index.to_be_bytes());
        spki
    }
    fn challenges() -> ZkX509ShaCallBusChallengesV1 {
        let mut next = 11_u64;
        ZkX509ShaCallBusChallengesV1 {
            lanes: core::array::from_fn(|_| ZkX509ShaCallBusLaneChallengesV1 {
                terms: core::array::from_fn(|_| {
                    let value = F(next);
                    next += 2;
                    value
                }),
            }),
        }
    }
    fn io_challenges() -> ZkX509Rfc5280StarkChallengesV1 {
        let mut next = 1_001_u64;
        ZkX509Rfc5280StarkChallengesV1 {
            tuple: core::array::from_fn(|_| {
                core::array::from_fn(|_| {
                    let value = F(next);
                    next += 2;
                    value
                })
            }),
        }
    }
    pub(super) fn fixture() -> (
        ZkX509CaAccumulatorTraceV1,
        ZkX509ShaCallScheduleV1,
        ZkX509ShaCallBusChallengesV1,
        ZkX509Rfc5280StarkChallengesV1,
    ) {
        let members = [spki(7), spki(1), spki(9), spki(3)];
        let refs = members
            .iter()
            .map(|member: &[u8; ZK_X509_CA_SPKI_DER_BYTES_V1]| member.as_slice())
            .collect::<Vec<_>>();
        let root = ca_root_from_complete_spkis_v1(&refs).expect("root");
        let path = ca_membership_path_from_complete_spkis_v1(&refs, &members[0]).expect("path");
        let trace = build_ca_accumulator_trace_v1(
            ZkX509CaAccumulatorStatementV1 {
                governed_root: root,
            },
            ZkX509CaAccumulatorWitnessV1 {
                root_spki_der: members[0],
                path,
            },
        )
        .expect("trace");
        let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 4,
        })
        .expect("schedule");
        (trace, schedule, challenges(), io_challenges())
    }
    pub(super) fn credential_main_pre_aux_v1() -> ZkX509CredentialMainPreAuxV1 {
        ZkX509CredentialMainPreAuxV1::fixture_for_test_v1(
            [0x91; 32],
            [0x92; 32],
            core::array::from_fn(|index| {
                zk_x509_test_digest384_v1(u8::try_from(0xa0 + index).expect("fixture root byte"))
            }),
        )
    }
    fn row(columns: &[Vec<F>], index: usize) -> Vec<F> {
        columns.iter().map(|column| column[index]).collect()
    }
    #[derive(Debug)]
    struct InjectedEntropyError;
    impl core::fmt::Display for InjectedEntropyError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected compact-CA prover entropy failure")
        }
    }
    #[derive(Clone, Copy)]
    enum EntropyMode {
        Period(usize),
        PartialFailure,
        Panic,
    }
    struct AdversarialEntropy(EntropyMode);
    impl TryRngCore for AdversarialEntropy {
        type Error = InjectedEntropyError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(InjectedEntropyError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(InjectedEntropyError)
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            match self.0 {
                EntropyMode::Period(period) => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = ((index % period) as u8).wrapping_mul(73).wrapping_add(11);
                    }
                    Ok(())
                }
                EntropyMode::PartialFailure => {
                    for (index, byte) in destination.iter_mut().take(17).enumerate() {
                        *byte = index as u8;
                    }
                    Err(InjectedEntropyError)
                }
                EntropyMode::Panic => panic!("entropy touched before deterministic preflight"),
            }
        }
    }
    impl TryCryptoRng for AdversarialEntropy {}
    fn canonical_proof_fixture() -> &'static (
        ZkX509CaAccumulatorStarkPublicV1,
        ZkX509ShaCallScheduleV1,
        Vec<u8>,
    ) {
        &stages::joint::tests::fixture_v1().evidence
    }
    fn verify_ca_component_v1(
        public: ZkX509CaAccumulatorStarkPublicV1,
        schedule: &ZkX509ShaCallScheduleV1,
        pre_aux: ZkX509CredentialMainPreAuxV1,
        encoded: &[u8],
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        let fixture = stages::joint::tests::fixture_v1();
        fixture.verify_v1(public, schedule, pre_aux, encoded, fixture.openings)
    }
    fn begin_ca_component_v1<R: TryCryptoRng + ?Sized>(
        trace: &ZkX509CaAccumulatorTraceV1,
        schedule: &ZkX509ShaCallScheduleV1,
        pre_aux: ZkX509CredentialMainPreAuxV1,
        rng: &mut R,
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        trace
            .validate()
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
        validate_ca_proof_schedule_v1(schedule)?;
        let mut rng = HealthCheckedTryCryptoRngV1::new(rng).map_err(|error| match error {
            TryCryptoProverRandomnessErrorV1::Unavailable => {
                ZkX509CaAccumulatorProofErrorV1::RandomnessUnavailable
            }
            TryCryptoProverRandomnessErrorV1::Unhealthy => {
                ZkX509CaAccumulatorProofErrorV1::RandomnessUnhealthy
            }
        })?;
        stages::commit_ca_through_auxiliary_v1(trace, schedule, pre_aux, &mut rng).map(|_| ())
    }
    #[test]
    fn dimensions_calls_and_terminals_are_exact() {
        let (trace, schedule, sha_challenges, io_challenges) = fixture();
        let material = build_ca_accumulator_stark_material_v1(
            &trace,
            &schedule,
            sha_challenges,
            &io_challenges,
        )
        .expect("material");
        assert_eq!(material.base_columns.len(), 695);
        assert_eq!(material.aux_columns.len(), 128);
        assert_eq!(material.fixed_columns.len(), 80);
        assert!(
            material
                .base_columns
                .iter()
                .chain(&material.aux_columns)
                .chain(&material.fixed_columns)
                .all(|column| column.len() == ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1)
        );
        assert_eq!(material.terminals.len(), 13);
        assert_eq!(material.terminals[0].call, 16);
        assert_eq!(material.terminals[0].role, ZkX509ShaCallRoleV1::CaLeaf);
        assert_eq!(material.terminals[12].call, 28);
        assert_eq!(material.terminals[12].role, ZkX509ShaCallRoleV1::CaNode(11));
        assert_eq!(material.root_spki_terminal.channel, 38);
        assert_eq!(
            material.root_spki_terminal.event_count,
            ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_IO_EVENTS_V1
        );
        let leaf_words =
            padded_source_words_v1(&trace.hash_witnesses[0].message).expect("leaf words");
        for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
            let expected_source =
                leaf_words
                    .iter()
                    .copied()
                    .enumerate()
                    .fold(F::ONE, |product, (word, value)| {
                        product.mul(compress_sha_call_fields_v1(
                            F(ZK_X509_SHA_CA_LEAF_CALL_V1 as u64),
                            F(u64::from(ZkX509ShaCallRoleV1::CaLeaf.role_code())),
                            F::ZERO,
                            F(u64::from(ZkX509ShaCallWordKindV1::Input.code())),
                            F(u64::try_from(word).expect("word")),
                            F(u64::from(value)),
                            sha_challenges.lanes[lane],
                        ))
                    });
            assert_eq!(material.terminals[0].source_products[lane], expected_source);
            let expected_io = trace
                .witness
                .root_spki_der
                .iter()
                .copied()
                .enumerate()
                .try_fold(F::ONE, |product, (offset, value)| {
                    Ok::<_, ZkX509AccumulatorStarkErrorV1>(product.mul(root_spki_io_factor_v1(
                        ca_accumulator_stark_public_v1(&trace, &schedule)?,
                        F(u64::from(value)),
                        F(u64::try_from(offset).expect("offset")),
                        lane,
                        &io_challenges,
                    )?))
                })
                .expect("I/O product");
            assert_eq!(
                material.root_spki_terminal.consumer_products[lane],
                expected_io
            );
        }
        assert_eq!(ZK_X509_CA_ACCUMULATOR_CHUNKS_V1, 13);
    }
    #[test]
    fn halkindi_parameterized_resource_envelope_is_exact_and_common_lifting_fails() {
        for (reduced_air_degree, deep_queries, fri_queries, expected_mask_coefficients) in
            [(2, 0, 60, 900), (2, 1, 60, 960), (2, 2, 60, 1020)]
        {
            let request =
                ca_accumulator_resource_request_v1(reduced_air_degree, deep_queries, fri_queries)
                    .expect("bounded cubic-AIR resource request");
            let envelope =
                checked_ca_accumulator_resource_envelope_v1(request).expect("safe local envelope");
            let lde_rows = 1_usize << request.lde_log2;
            let expected_masked_degree =
                ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 + expected_mask_coefficients - 1;
            assert_eq!(request.mask_degree + 1, expected_mask_coefficients);
            assert_eq!(envelope.mask_coefficients, expected_mask_coefficients);
            assert_eq!(envelope.maximum_masked_trace_degree, expected_masked_degree);
            assert_eq!(
                envelope.minimum_safe_lde_rows,
                ((expected_masked_degree + 1) * ZK_X509_CA_ACCUMULATOR_FRI_RATE_DENOMINATOR_V1)
                    .div_ceil(ZK_X509_CA_ACCUMULATOR_FRI_RATE_NUMERATOR_V1)
            );
            assert_eq!(
                envelope.fri_degree_cap,
                lde_rows * ZK_X509_CA_ACCUMULATOR_FRI_RATE_NUMERATOR_V1
                    / ZK_X509_CA_ACCUMULATOR_FRI_RATE_DENOMINATOR_V1
                    - 1
            );
            assert_eq!(
                envelope.maximum_quotient_degree,
                usize::from(ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1) * expected_masked_degree
                    + 2 * (ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 - 1)
                    - ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
            );
            assert!(
                envelope.maximum_quotient_degree
                    < (envelope.fri_degree_cap + 1 - request.fri_query_count - 1)
                        * COMPOSITION_DEGREE_CHUNKS_V1
            );
            assert_eq!(envelope.native_material_field_cells, 3_698_688);
            assert_eq!(envelope.native_material_bytes, 29_589_504);
            assert_eq!(
                envelope.committed_lde_field_evaluations,
                (ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1 + ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1)
                    * lde_rows
            );
            assert_eq!(
                envelope.fixed_lde_field_evaluations,
                ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1 * lde_rows
            );
            assert_eq!(
                envelope.trace_mask_bytes,
                (ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1 + ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1)
                    * expected_mask_coefficients
                    * FIELD_BYTES_V1
            );
        }
        let oversized_query_request =
            ca_accumulator_resource_request_v1(2, 1, 1700).expect("arithmetic high-query request");
        assert_eq!(oversized_query_request.mask_degree + 1, 25_560);
        assert_eq!(oversized_query_request.lde_log2, 18);
        assert_eq!(
            checked_ca_accumulator_resource_envelope_v1(oversized_query_request),
            Err(ZkX509AccumulatorStarkErrorV1::Resource),
            "the materialized log18 LDE must not bypass the 512 MiB local LDE cap"
        );
        // The compiled AIR is cubic, hence Haböck--Al Kindi uses d=d_AIR-1=2.
        // The outer theorem still chooses the exact DEEP and FRI counts.
        let request = ca_accumulator_resource_request_v1(2, 1, CA_QUERY_COUNT_V1)
            .expect("release resource census");
        assert_eq!(request.lde_log2, 16);
        let envelope =
            checked_ca_accumulator_resource_envelope_v1(request).expect("release resource census");
        assert_eq!(request.reduced_air_degree, 2);
        assert_eq!(request.fri_query_count, CA_QUERY_COUNT_V1);
        assert_eq!(envelope.mask_coefficients, 2100);
        assert_eq!(envelope.maximum_masked_trace_degree, 6_195);
        assert_eq!(envelope.fri_degree_cap, 9_215);
        assert_eq!(envelope.maximum_quotient_degree, 22_679);
        assert_eq!(envelope.minimum_safe_lde_rows, 44_061);
        assert_eq!(envelope.total_local_lde_bytes, 473_432_064);
        assert_eq!(envelope.encrypted_scratch_bytes, 480_829_440);
        assert_eq!(envelope.current_next_block_bytes, 1_849_344);
        assert_eq!(envelope.streamed_column_bytes, 557_056);
        assert_eq!(envelope.trace_mask_bytes, 13_826_400);
        assert_eq!(envelope.composition_residue_evaluations, 90_374_144);
        assert_eq!(envelope.composition_component_evaluations, 361_496_576);
        assert_eq!(envelope.lde_butterflies, 495_624_192);
        assert_eq!(envelope.adapter_resident_payload_bytes, 528_833_688);
        assert!(
            envelope.adapter_resident_payload_bytes >= envelope.total_local_lde_bytes,
            "the materialized first-release LDE must be counted as resident"
        );
        assert_eq!(
            ZK_X509_CA_ACCUMULATOR_MAX_ADAPTER_RESIDENT_BYTES_V1,
            640 << 20
        );
        assert_eq!(
            ca_accumulator_resource_request_v1(0, 0, 60),
            Err(ZkX509AccumulatorStarkErrorV1::Resource)
        );
        assert_eq!(
            ca_accumulator_resource_request_v1(2, 0, 0),
            Err(ZkX509AccumulatorStarkErrorV1::Resource)
        );
        assert_eq!(
            ca_accumulator_resource_request_v1(1, 1, 60),
            Err(ZkX509AccumulatorStarkErrorV1::Resource),
            "a quadratic-AIR substitution must fail for the compiled cubic AIR"
        );
        assert_eq!(
            ca_accumulator_resource_request_v1(2, usize::MAX, usize::MAX),
            Err(ZkX509AccumulatorStarkErrorV1::Resource)
        );
        let excessive =
            ca_accumulator_resource_request_v1(2, 1, 1_000).expect("arithmetic request");
        assert_eq!(
            checked_ca_accumulator_resource_envelope_v1(excessive),
            Err(ZkX509AccumulatorStarkErrorV1::Resource)
        );
        let quadratic_geometry =
            transparent_stark_zk_mask_geometry_v1(1, 4, 1, 60).expect("quadratic census only");
        let quadratic_substitution = ZkX509CaAccumulatorResourceRequestV1 {
            reduced_air_degree: 1,
            mask_degree: quadratic_geometry.minimum_mask_degree,
            ..request
        };
        assert_eq!(
            checked_ca_accumulator_resource_envelope_v1(quadratic_substitution),
            Err(ZkX509AccumulatorStarkErrorV1::Resource),
            "matching a quadratic mask must not downgrade the actual cubic AIR"
        );
        for hostile in [
            ZkX509CaAccumulatorResourceRequestV1 {
                lde_log2: 22,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                base_width: ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1 + 1,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                scratch_chunk_rows: 1 << 15,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                composition_extension_lanes: 3,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                mask_degree: request.mask_degree - 1,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                fri_rate_numerator: 8,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                fri_rate_denominator: 16,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                deep_query_count: 0,
                ..request
            },
            ZkX509CaAccumulatorResourceRequestV1 {
                fri_query_count: 61,
                ..request
            },
        ] {
            assert_eq!(
                checked_ca_accumulator_resource_envelope_v1(hostile),
                Err(ZkX509AccumulatorStarkErrorV1::Resource)
            );
        }
    }
    #[test]
    fn typed_outer_binding_rejects_omission_substitution_reorder_and_cross_root() {
        let (trace, schedule, sha_challenges, io_challenges) = fixture();
        let material = build_ca_accumulator_stark_material_v1(
            &trace,
            &schedule,
            sha_challenges,
            &io_challenges,
        )
        .expect("material");
        let binding =
            ca_accumulator_subproof_binding_v1(&trace, &schedule, &material).expect("binding");
        validate_ca_accumulator_subproof_binding_v1(binding.public, &schedule, binding)
            .expect("canonical binding");
        assert_eq!(
            ca_accumulator_subproof_terminal_claims_v1(binding),
            ca_accumulator_stark_terminal_claims_v1(&material)
        );
        assert_eq!(
            validate_ca_accumulator_subproof_terminal_sequence_v1(
                binding.public,
                &schedule,
                &binding.sha_terminals[..binding.sha_terminals.len() - 1],
                binding.root_spki_terminal,
            ),
            Err(ZkX509AccumulatorStarkErrorV1::CallBus)
        );
        let mut extra = binding.sha_terminals.to_vec();
        extra.push(binding.sha_terminals[0]);
        assert_eq!(
            validate_ca_accumulator_subproof_terminal_sequence_v1(
                binding.public,
                &schedule,
                &extra,
                binding.root_spki_terminal,
            ),
            Err(ZkX509AccumulatorStarkErrorV1::CallBus)
        );
        let mut reordered = binding;
        reordered.sha_terminals.swap(1, 2);
        assert_eq!(
            validate_ca_accumulator_subproof_binding_v1(binding.public, &schedule, reordered),
            Err(ZkX509AccumulatorStarkErrorV1::CallBus)
        );
        let mut substituted = binding;
        substituted.sha_terminals[0].source_products[0] =
            substituted.sha_terminals[0].source_products[0].add(F::ONE);
        assert_eq!(
            validate_ca_accumulator_subproof_binding_v1(binding.public, &schedule, substituted),
            Ok(())
        );
        // Metadata validation alone admits canonical challenge products.  The
        // local quotient and the outer shared-SHA equality reject substitution.
        let claims = ca_accumulator_subproof_terminal_claims_v1(substituted);
        let row_index = ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1;
        assert!(
            evaluate_ca_accumulator_stark_residues_v1(
                binding.public,
                &row(&material.base_columns, row_index),
                &row(&material.base_columns, row_index + 1),
                &row(&material.aux_columns, row_index),
                &row(&material.aux_columns, row_index + 1),
                &row(&material.fixed_columns, row_index),
                sha_challenges,
                &io_challenges,
                claims,
            )
            .expect("residues")
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
        let mut cross_root = binding.public;
        cross_root.governed_root[0] = if cross_root.governed_root[0] == F::ZERO {
            F::ONE
        } else {
            F::ZERO
        };
        assert_eq!(
            validate_ca_accumulator_subproof_binding_v1(cross_root, &schedule, binding),
            Err(ZkX509AccumulatorStarkErrorV1::Witness)
        );
        let mut wrong_channel = binding;
        wrong_channel.public.root_spki_channel = wrong_channel.public.root_spki_channel.add(F::ONE);
        assert_eq!(
            validate_ca_accumulator_subproof_binding_v1(binding.public, &schedule, wrong_channel,),
            Err(ZkX509AccumulatorStarkErrorV1::Witness)
        );
        let mut wrong_rfc = binding;
        wrong_rfc.root_spki_terminal.event_count -= 1;
        assert_eq!(
            validate_ca_accumulator_subproof_binding_v1(binding.public, &schedule, wrong_rfc),
            Err(ZkX509AccumulatorStarkErrorV1::IoBus)
        );
    }
    #[test]
    fn every_canonical_opened_row_has_exactly_1379_zero_residues() {
        let (trace, schedule, sha_challenges, io_challenges) = fixture();
        let public = ca_accumulator_stark_public_v1(&trace, &schedule).expect("public");
        let material = build_ca_accumulator_stark_material_v1(
            &trace,
            &schedule,
            sha_challenges,
            &io_challenges,
        )
        .expect("material");
        let terminal_claims = ca_accumulator_stark_terminal_claims_v1(&material);
        for index in 0..ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 {
            let next_index = (index + 1) % ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1;
            let residues = evaluate_ca_accumulator_stark_residues_v1(
                public,
                &row(&material.base_columns, index),
                &row(&material.base_columns, next_index),
                &row(&material.aux_columns, index),
                &row(&material.aux_columns, next_index),
                &row(&material.fixed_columns, index),
                sha_challenges,
                &io_challenges,
                terminal_claims,
            )
            .expect("residues");
            assert_eq!(residues.len(), 1_379);
            assert!(residues.iter().all(|residue| *residue == F::ZERO));
            let local = evaluate_ca_accumulator_local_residues_v1(
                public,
                &row(&material.base_columns, index),
                &row(&material.base_columns, next_index),
                &row(&material.aux_columns, index),
                &row(&material.aux_columns, next_index),
                &row(&material.fixed_columns, index),
                sha_challenges,
                &io_challenges,
            )
            .unwrap();
            assert_eq!(local.len(), 1363);
            assert_eq!(local, residues[..1363]);
        }
    }
    #[test]
    fn private_local_relation_binds_all_call_products_and_last_serialized_rows() {
        let (trace, schedule, sha, io) = fixture();
        let public = ca_accumulator_stark_public_v1(&trace, &schedule).unwrap();
        let material = build_ca_accumulator_stark_material_v1(&trace, &schedule, sha, &io).unwrap();
        let evaluate = |index: usize, aux: &[F], next_aux: &[F]| {
            let next = (index + 1) % ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1;
            evaluate_ca_accumulator_local_residues_v1(
                public,
                &row(&material.base_columns, index),
                &row(&material.base_columns, next),
                aux,
                next_aux,
                &row(&material.fixed_columns, index),
                sha,
                &io,
            )
            .unwrap()
        };
        // Each of13 source and digest endpoint rows is fixed by its own local
        // recurrence. No now-private endpoint is accepted merely because some
        // other endpoint has been altered to compensate its aggregate product.
        for index in 0..ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 {
            let honest = row(&material.aux_columns, index);
            let next = row(&material.aux_columns, index + 1);
            for lane in 0..4 {
                for column in [
                    source_aux_cell_v1(SOURCE_STATES_V1 - 1, lane),
                    digest_aux_cell_v1(DIGEST_STATES_V1 - 1, lane),
                ] {
                    let mut changed = honest.clone();
                    changed[column] = changed[column].add(F::ONE);
                    assert!(
                        evaluate(index, &changed, &next)
                            .iter()
                            .any(|r| *r != F::ZERO)
                    );
                }
            }
        }
        // The serialized source and RFC products have after-row semantics.
        // The preceding row binds a changed next product with coefficient one,
        // including at the final active row and when a multiplicative factor
        // vanishes. Padding is never substituted for that original endpoint.
        for index in
            ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1..ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1
        {
            let honest = row(&material.aux_columns, index);
            for lane in 0..4 {
                for column in [
                    serialized_sha_product_cell_v1(lane),
                    root_spki_io_product_cell_v1(lane),
                ] {
                    let mut changed = honest.clone();
                    changed[column] = changed[column].add(F::ONE);
                    let residues = if index == ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 {
                        evaluate(index, &changed, &row(&material.aux_columns, index + 1))
                    } else {
                        evaluate(index - 1, &row(&material.aux_columns, index - 1), &changed)
                    };
                    assert!(residues.iter().any(|r| *r != F::ZERO));
                }
            }
        }
    }

    #[test]
    fn base_aux_fixed_and_public_mutations_fail_closed() {
        let (trace, schedule, sha_challenges, io_challenges) = fixture();
        let public = ca_accumulator_stark_public_v1(&trace, &schedule).expect("public");
        let material = build_ca_accumulator_stark_material_v1(
            &trace,
            &schedule,
            sha_challenges,
            &io_challenges,
        )
        .expect("material");
        let terminal_claims = ca_accumulator_stark_terminal_claims_v1(&material);
        let index = 5;
        let base = row(&material.base_columns, index);
        let next = row(&material.base_columns, index + 1);
        let aux = row(&material.aux_columns, index);
        let next_aux = row(&material.aux_columns, index + 1);
        let fixed = row(&material.fixed_columns, index);
        let rejects = |base: &[F], next: &[F], aux: &[F], next_aux: &[F], fixed: &[F], public| {
            evaluate_ca_accumulator_stark_residues_v1(
                public,
                base,
                next,
                aux,
                next_aux,
                fixed,
                sha_challenges,
                &io_challenges,
                terminal_claims,
            )
            .expect("shape")
            .iter()
            .any(|residue| *residue != F::ZERO)
        };
        let mut changed = base.clone();
        changed[CA_SIBLING_START + 3] = changed[CA_SIBLING_START + 3].add(F::ONE);
        assert!(rejects(&changed, &next, &aux, &next_aux, &fixed, public));
        let mut changed = aux.clone();
        changed[77] = changed[77].add(F::ONE);
        assert!(rejects(&base, &next, &changed, &next_aux, &fixed, public));
        let mut changed = fixed.clone();
        changed[FIX_CALL] = changed[FIX_CALL].add(F::ONE);
        assert!(rejects(&base, &next, &aux, &next_aux, &changed, public));
        let padding_index = ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1;
        let padding_base = row(&material.base_columns, padding_index);
        let padding_next = row(&material.base_columns, padding_index + 1);
        let mut padding_aux = row(&material.aux_columns, padding_index);
        let padding_next_aux = row(&material.aux_columns, padding_index + 1);
        let padding_fixed = row(&material.fixed_columns, padding_index);
        padding_aux[source_aux_cell_v1(1, 0)] = F::ONE;
        assert!(
            evaluate_ca_accumulator_stark_residues_v1(
                public,
                &padding_base,
                &padding_next,
                &padding_aux,
                &padding_next_aux,
                &padding_fixed,
                sha_challenges,
                &io_challenges,
                terminal_claims,
            )
            .expect("padding mutation residues")
            .iter()
            .any(|residue| *residue != F::ZERO),
            "ungated product recurrences must still force every inactive state to zero"
        );
        let mut changed = public;
        changed.governed_root[0] = changed.governed_root[0].add(F::ONE);
        let last = 12;
        assert!(rejects(
            &row(&material.base_columns, last),
            &row(&material.base_columns, last + 1),
            &row(&material.aux_columns, last),
            &row(&material.aux_columns, last + 1),
            &row(&material.fixed_columns, last),
            changed,
        ));
    }
    #[test]
    fn root_spki_io_byte_range_order_channel_and_challenge_mutations_fail_closed() {
        let (trace, schedule, sha_challenges, io_challenges) = fixture();
        let public = ca_accumulator_stark_public_v1(&trace, &schedule).expect("public");
        let material = build_ca_accumulator_stark_material_v1(
            &trace,
            &schedule,
            sha_challenges,
            &io_challenges,
        )
        .expect("material");
        let terminal_claims = ca_accumulator_stark_terminal_claims_v1(&material);
        let row_index = ZK_X509_CA_ACCUMULATOR_IO_START_V1 + 17;
        let base = row(&material.base_columns, row_index);
        let next = row(&material.base_columns, row_index + 1);
        let aux = row(&material.aux_columns, row_index);
        let next_aux = row(&material.aux_columns, row_index + 1);
        let fixed = row(&material.fixed_columns, row_index);
        let rejects = |base: &[F],
                       public: ZkX509CaAccumulatorStarkPublicV1,
                       io_challenges: &ZkX509Rfc5280StarkChallengesV1| {
            evaluate_ca_accumulator_stark_residues_v1(
                public,
                base,
                &next,
                &aux,
                &next_aux,
                &fixed,
                sha_challenges,
                io_challenges,
                terminal_claims,
            )
            .expect("shape")
            .iter()
            .any(|residue| *residue != F::ZERO)
        };
        let mut changed = base.clone();
        changed[CA_IO_BYTE] = changed[CA_IO_BYTE].add(F::ONE);
        assert!(rejects(&changed, public, &io_challenges));
        let mut changed = base.clone();
        changed[CA_IO_WORD_ACC] = changed[CA_IO_WORD_ACC].add(F::ONE);
        assert!(rejects(&changed, public, &io_challenges));
        let mut out_of_range = base.clone();
        out_of_range[CA_IO_BYTE] = F(256);
        assert!(rejects(&out_of_range, public, &io_challenges));
        let reordered = row(&material.base_columns, row_index + 1);
        assert!(rejects(&reordered, public, &io_challenges));
        let mut wrong_channel = public;
        wrong_channel.root_spki_channel = wrong_channel.root_spki_channel.add(F::ONE);
        assert!(rejects(&base, wrong_channel, &io_challenges));
        let mut wrong_challenges = io_challenges;
        wrong_challenges.tuple[0][6] = wrong_challenges.tuple[0][6].add(F(10_000));
        assert!(rejects(&base, public, &wrong_challenges));
        let mut changed_next_aux = next_aux.clone();
        changed_next_aux[serialized_sha_product_cell_v1(0)] =
            changed_next_aux[serialized_sha_product_cell_v1(0)].add(F::ONE);
        assert!(
            evaluate_ca_accumulator_stark_residues_v1(
                public,
                &base,
                &next,
                &aux,
                &changed_next_aux,
                &fixed,
                sha_challenges,
                &io_challenges,
                terminal_claims,
            )
            .expect("shape")
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
        let mut changed_next_aux = next_aux;
        changed_next_aux[root_spki_io_product_cell_v1(3)] =
            changed_next_aux[root_spki_io_product_cell_v1(3)].add(F::ONE);
        assert!(
            evaluate_ca_accumulator_stark_residues_v1(
                public,
                &base,
                &next,
                &aux,
                &changed_next_aux,
                &fixed,
                sha_challenges,
                &io_challenges,
                terminal_claims,
            )
            .expect("shape")
            .iter()
            .any(|residue| *residue != F::ZERO)
        );
    }
    #[test]
    fn sha_and_root_spki_terminal_claim_mutations_and_reordering_fail_closed() {
        let (trace, schedule, sha_challenges, io_challenges) = fixture();
        let public = ca_accumulator_stark_public_v1(&trace, &schedule).expect("public");
        let material = build_ca_accumulator_stark_material_v1(
            &trace,
            &schedule,
            sha_challenges,
            &io_challenges,
        )
        .expect("material");
        let claims = ca_accumulator_stark_terminal_claims_v1(&material);
        let rejects = |row_index: usize, claims: ZkX509CaAccumulatorStarkTerminalClaimsV1| {
            let next_index = (row_index + 1) % ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1;
            evaluate_ca_accumulator_stark_residues_v1(
                public,
                &row(&material.base_columns, row_index),
                &row(&material.base_columns, next_index),
                &row(&material.aux_columns, row_index),
                &row(&material.aux_columns, next_index),
                &row(&material.fixed_columns, row_index),
                sha_challenges,
                &io_challenges,
                claims,
            )
            .expect("shape")
            .iter()
            .any(|residue| *residue != F::ZERO)
        };
        let mut changed = claims;
        changed.source_products[0][0] = changed.source_products[0][0].add(F::ONE);
        assert!(rejects(
            ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1,
            changed
        ));
        let mut changed = claims;
        changed.digest_products[0][1] = changed.digest_products[0][1].add(F::ONE);
        assert!(rejects(0, changed));
        let mut changed = claims;
        changed.root_spki_consumer_products[2] = changed.root_spki_consumer_products[2].add(F::ONE);
        assert!(rejects(
            ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1,
            changed
        ));
        let mut reordered = claims;
        reordered.source_products.swap(1, 2);
        reordered.digest_products.swap(1, 2);
        assert!(rejects(1, reordered));
        let mut invalid_metadata = material.root_spki_terminal;
        invalid_metadata.channel = invalid_metadata.channel.checked_add(1).expect("channel");
        assert_eq!(
            validate_ca_accumulator_io_terminal_v1(public, invalid_metadata),
            Err(ZkX509AccumulatorStarkErrorV1::IoBus)
        );
        invalid_metadata = material.root_spki_terminal;
        invalid_metadata.event_count -= 1;
        assert_eq!(
            validate_ca_accumulator_io_terminal_v1(public, invalid_metadata),
            Err(ZkX509AccumulatorStarkErrorV1::IoBus)
        );
    }
    #[test]
    fn root_spki_channel_is_derived_only_from_public_disclosure_shape() {
        for disclosures in 0..=4 {
            let schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
                disclosed_attributes: disclosures,
            })
            .expect("schedule");
            assert_eq!(
                ca_accumulator_root_spki_channel_v1(&schedule).expect("channel"),
                ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_BASE_CHANNEL_V1
                    + u32::try_from(disclosures * 2).expect("bounded disclosures")
            );
        }
    }
    #[test]
    fn fixed_frame_offsets_and_padding_are_pinned() {
        let leaf = compile_ca_accumulator_fixed_row_v1(0).expect("leaf");
        let node = compile_ca_accumulator_fixed_row_v1(1).expect("node");
        let first_io = compile_ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_IO_START_V1)
            .expect("first IO");
        let last_io =
            compile_ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1)
                .expect("last IO");
        let padding = compile_ca_accumulator_fixed_row_v1(ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1 - 1)
            .expect("padding");
        assert_eq!(leaf[FIX_CALL], F(16));
        assert_eq!(node[FIX_CALL], F(17));
        assert_eq!(node[FIX_LEVEL], F::ZERO);
        assert_eq!(first_io[FIX_IO_ACTIVE], F::ONE);
        assert_eq!(first_io[FIX_IO_FIRST], F::ONE);
        assert_eq!(first_io[FIX_IO_OFFSET], F::ZERO);
        assert_eq!(last_io[FIX_IO_LAST], F::ONE);
        assert_eq!(last_io[FIX_IO_OFFSET], F(90));
        assert_eq!(padding[FIX_PADDING], F::ONE);
        assert!(
            padding
                .iter()
                .enumerate()
                .all(|(column, value)| column == FIX_PADDING || *value == F::ZERO),
            "the sole padding selector must remain one while every other fixed cell is zero"
        );
        assert_eq!(LEAF_DYNAMIC_OFFSET_V1, 65);
        assert_eq!(NODE_LEFT_DYNAMIC_OFFSET_V1, 75);
        assert_eq!(NODE_RIGHT_DYNAMIC_OFFSET_V1, 115);
    }
    #[test]
    fn dedicated_proof_parameters_and_resource_gate_are_exact() {
        let layout = ca_aggregate_layout_v1().expect("dedicated layout");
        assert_eq!(layout.common_lde_log2(), 16);
        assert_eq!(
            layout
                .fri_rounds(CA_AGGREGATE_PARAMETERS_V1)
                .expect("FRI rounds"),
            6
        );
        assert_eq!(
            layout
                .fri_degree_cap(CA_AGGREGATE_PARAMETERS_V1)
                .expect("FRI degree cap"),
            9_216
        );
        assert_eq!(CA_MASK_DEGREE_V1 + 1, 2100);
        assert_eq!(CA_QUERY_COUNT_V1, 136);
        assert_eq!(CA_DEEP_BYTES_V1, 52_800);
        assert_eq!(
            aggregate::maximum_encoded_proof_with_deep_bytes_v1(
                CA_AGGREGATE_PARAMETERS_V1,
                &layout
            )
            .expect("maximum proof"),
            CA_INNER_MAXIMUM_PROOF_BYTES_V1,
        );
        let request =
            ca_accumulator_resource_request_v1(2, 1, CA_QUERY_COUNT_V1).expect("exact request");
        assert_eq!(request.lde_log2, 16);
        assert_eq!(request.mask_degree, 2099);
        assert_eq!(
            checked_ca_accumulator_resource_envelope_v1(request)
                .expect("exact envelope")
                .mask_coefficients,
            2100
        );
    }
    #[test]
    fn claim_free_ca_frame_rejects_retired_products_bad_lengths_and_suffix() {
        let inner = b"X5C2component-shape-fixture";
        let encoded = encode_ca_proof_envelope_v1(inner).unwrap();
        assert_eq!(encoded.len(), 10 + inner.len());
        assert_eq!(decode_ca_proof_envelope_v1(&encoded).unwrap(), inner);
        for length in 0..encoded.len() {
            assert!(decode_ca_proof_envelope_v1(&encoded[..length]).is_err());
        }
        for offset in 0..10 {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(decode_ca_proof_envelope_v1(&changed).is_err());
        }
        for extra in [1, 2, 4, 1296, 1300] {
            let mut retired = encoded.clone();
            retired.splice(6..6, vec![0; extra]);
            assert!(decode_ca_proof_envelope_v1(&retired).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_ca_proof_envelope_v1(&trailing).is_err());
        assert!(encode_ca_proof_envelope_v1(b"X5C1wrong-inner").is_err());
        assert!(matches!(
            decode_ca_proof_envelope_v1(&vec![0; ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 + 1]),
            Err(ZkX509CaAccumulatorProofErrorV1::ProofTooLarge)
        ));
    }
    #[test]
    fn prover_preflight_precedes_entropy_and_rng_health_fails_closed() {
        let (trace, schedule, _, _) = fixture();
        for period in [1, 2, 4, 8, 16, 32] {
            assert_eq!(
                begin_ca_component_v1(
                    &trace,
                    &schedule,
                    credential_main_pre_aux_v1(),
                    &mut AdversarialEntropy(EntropyMode::Period(period)),
                ),
                Err(ZkX509CaAccumulatorProofErrorV1::RandomnessUnhealthy),
                "period {period} must fail"
            );
        }
        assert_eq!(
            begin_ca_component_v1(
                &trace,
                &schedule,
                credential_main_pre_aux_v1(),
                &mut AdversarialEntropy(EntropyMode::PartialFailure),
            ),
            Err(ZkX509CaAccumulatorProofErrorV1::RandomnessUnavailable)
        );
        let mut invalid = trace;
        invalid.statement.governed_root[0] ^= 1;
        assert_eq!(
            begin_ca_component_v1(
                &invalid,
                &schedule,
                credential_main_pre_aux_v1(),
                &mut AdversarialEntropy(EntropyMode::Panic),
            ),
            Err(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)
        );
    }
    #[test]
    fn canonical_joint_ca_component_roundtrips_and_binds_originals() {
        let (public, schedule, proof) = canonical_proof_fixture();
        assert!(proof.len() <= ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1);
        verify_ca_component_v1(*public, schedule, credential_main_pre_aux_v1(), proof)
            .expect("canonical proof verifies");
        let inner = decode_ca_proof_envelope_v1(proof).expect("outer decode");
        let layout = ca_aggregate_layout_v1().expect("layout");
        let (decoded, deep) =
            aggregate::decode_proof_with_deep_v1(inner, CA_AGGREGATE_PARAMETERS_V1, &layout)
                .expect("inner decode");
        assert!(decoded.queries.iter().all(|query| {
            query
                .trace_groups
                .iter()
                .all(|group| group.base_next.is_empty() && group.aux_next.is_empty())
        }));
        assert_eq!(
            deep.trace_groups[0].base_next.len(),
            ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
        );
        assert_eq!(
            deep.trace_groups[0].aux_next.len(),
            ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
        );
        let mut retired_rows = decoded.clone();
        retired_rows.queries[0].trace_groups[0].base_next =
            retired_rows.queries[0].trace_groups[0].base_current.clone();
        assert!(
            aggregate::encode_proof_with_deep_v1(
                &retired_rows,
                &deep,
                CA_AGGREGATE_PARAMETERS_V1,
                &layout
            )
            .is_err()
        );
        assert_eq!(
            aggregate::encode_proof_with_deep_v1(
                &decoded,
                &deep,
                CA_AGGREGATE_PARAMETERS_V1,
                &layout,
            )
            .expect("canonical re-encode"),
            inner
        );
        assert_eq!(
            ca_accumulator_base_root_from_proof_v1(proof).expect("decoded CA base root"),
            decoded.trace_groups[0].base_root
        );
    }
    #[test]
    fn credential_pre_aux_context_mutations_reject_the_same_ca_proof() {
        let (public, schedule, proof) = canonical_proof_fixture();
        let canonical = credential_main_pre_aux_v1();
        let mut wrong_consensus = canonical;
        wrong_consensus.consensus_context_digest_mut_for_test_v1()[0] ^= 1;
        assert!(verify_ca_component_v1(*public, schedule, wrong_consensus, proof,).is_err());
        let mut wrong_profile = canonical;
        wrong_profile.main_profile_digest_mut_for_test_v1()[31] ^= 1;
        assert!(verify_ca_component_v1(*public, schedule, wrong_profile, proof,).is_err());
        let mut wrong_roots = canonical;
        let root = &mut wrong_roots.main_base_roots_mut_for_test_v1()[0];
        let mut bytes = root.to_bytes();
        bytes[0] ^= 1;
        *root = PrivacyOuterDigestV1::from_bytes(bytes);
        assert!(verify_ca_component_v1(*public, schedule, wrong_roots, proof,).is_err());
        let mut changed_proof = proof.clone();
        changed_proof[CA_PROOF_ENVELOPE_BYTES_V1 + 8] ^= 1;
        assert!(
            ca_accumulator_base_root_from_proof_v1(&changed_proof).is_ok_and(|root| root
                != ca_accumulator_base_root_from_proof_v1(proof).expect("canonical CA base root"))
        );
        assert!(verify_ca_component_v1(*public, schedule, canonical, &changed_proof,).is_err());
    }
    #[test]
    fn joint_ca_component_rejects_frame_root_deep_fri_query_and_frontier_mutations() {
        let (public, schedule, proof) = canonical_proof_fixture();
        let inner_start = CA_PROOF_ENVELOPE_BYTES_V1;
        let root_bytes = crate::privacy_engines::privacy_outer_hash::PRIVACY_OUTER_DIGEST_BYTES_V1;
        let deep_start = inner_start + 8 + 4 * root_bytes;
        let fri_start = deep_start + CA_DEEP_BYTES_V1;
        let hostile_offsets = [
            6,
            inner_start,
            inner_start + 8,
            inner_start + 8 + root_bytes,
            inner_start + 8 + 2 * root_bytes,
            inner_start + 8 + 3 * root_bytes,
            deep_start,
            fri_start,
            proof.len() / 2,
            proof.len() - 1,
        ];
        for offset in hostile_offsets {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            assert!(
                verify_ca_component_v1(*public, schedule, credential_main_pre_aux_v1(), &changed,)
                    .is_err(),
                "mutation at {offset} must fail"
            );
        }
        let query_bytes_v1 = 4
            + (ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1 + ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1)
                * core::mem::size_of::<u64>()
            + (CA_COMPOSITION_DEGREE_CHUNKS_V1 + 1 + 2 * usize::from(ZK_X509_CA_FRI_ROUNDS_V1))
                * core::mem::size_of::<[u64; 4]>();
        let query_start = fri_start
            + (usize::from(ZK_X509_CA_FRI_ROUNDS_V1) + 1) * root_bytes
            + (1 << CA_TERMINAL_LOG2_V1) * core::mem::size_of::<[u64; 4]>()
            + core::mem::size_of::<u64>();
        assert_eq!(query_bytes_v1, 7_132);
        let inner = decode_ca_proof_envelope_v1(proof).expect("canonical CA envelope");
        let layout = ca_aggregate_layout_v1().expect("canonical CA layout");
        let (decoded, _) =
            aggregate::decode_proof_with_deep_v1(inner, CA_AGGREGATE_PARAMETERS_V1, &layout)
                .expect("canonical CA inner proof");
        for (position, query) in decoded.queries.iter().enumerate() {
            let offset = query_start + position * query_bytes_v1;
            assert_eq!(&proof[offset..offset + 4], query.index.to_be_bytes());
        }
        let mut duplicate_query = proof.clone();
        let first_index = duplicate_query[query_start..query_start + 4].to_vec();
        duplicate_query[query_start + query_bytes_v1..query_start + query_bytes_v1 + 4]
            .copy_from_slice(&first_index);
        assert!(
            verify_ca_component_v1(
                *public,
                schedule,
                credential_main_pre_aux_v1(),
                &duplicate_query,
            )
            .is_err(),
            "duplicate transcript query must fail"
        );
        let mut grinding_mutation = proof.clone();
        grinding_mutation[query_start - 1] ^= 1;
        assert!(
            verify_ca_component_v1(
                *public,
                schedule,
                credential_main_pre_aux_v1(),
                &grinding_mutation,
            )
            .is_err(),
            "grinding nonce mutation must fail"
        );
        for truncated in [
            0,
            1,
            CA_PROOF_ENVELOPE_BYTES_V1 - 1,
            proof.len() / 3,
            proof.len() - 1,
        ] {
            assert!(
                verify_ca_component_v1(
                    *public,
                    schedule,
                    credential_main_pre_aux_v1(),
                    &proof[..truncated],
                )
                .is_err()
            );
        }
        let mut trailing = proof.clone();
        trailing.extend_from_slice(&[0, 1, 2, 3]);
        assert!(
            verify_ca_component_v1(*public, schedule, credential_main_pre_aux_v1(), &trailing,)
                .is_err()
        );
        let mut wrong_public = *public;
        wrong_public.governed_root[0] = wrong_public.governed_root[0].add(F::ONE);
        assert!(
            verify_ca_component_v1(wrong_public, schedule, credential_main_pre_aux_v1(), proof,)
                .is_err()
        );
        let other_schedule = ZkX509ShaCallScheduleV1::new(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: 3,
        })
        .expect("alternate public schedule");
        assert!(
            verify_ca_component_v1(
                *public,
                &other_schedule,
                credential_main_pre_aux_v1(),
                proof,
            )
            .is_err()
        );
    }

    #[test]
    fn ca_composition_codewords_clear_on_success_downstream_error_and_unwind() {
        use super::super::private_table::inspection;
        for outcome in 0..3 {
            let (result, erased) = inspection::observe_v1(|| {
                std::panic::catch_unwind(|| {
                    let chunks = vec![vec![E::canonical([3, 5, 7, 11]).unwrap(); 7]; 4];
                    let pointers = chunks.iter().map(Vec::as_ptr).collect::<Vec<_>>();
                    let owner = own_ca_composition_lane_v1(chunks)?;
                    assert_eq!(owner.len(), 1);
                    assert_eq!(
                        owner[0].iter().map(Vec::as_ptr).collect::<Vec<_>>(),
                        pointers
                    );
                    // All later fallible consumers borrow this exact owner.
                    match outcome {
                        0 => Ok(()),
                        1 => Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening),
                        _ => panic!("injected downstream composition consumer unwind"),
                    }
                })
            });
            match outcome {
                0 => assert!(result.unwrap().is_ok()),
                1 => assert!(result.unwrap().is_err()),
                _ => assert!(result.is_err()),
            }
            assert_eq!(erased.iter().map(|row| row.cells).sum::<usize>(), 28);
            assert_eq!(
                erased.iter().map(|row| row.nonzero_before).sum::<usize>(),
                28
            );
            assert!(erased.iter().all(|row| row.nonzero_after == 0));
        }
    }
}
