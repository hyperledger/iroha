//! Canonical bounded segmented transparent proof container for zk-X509 AIRs.
//!
//! This module is deliberately below the governed engine boundary. It implements the complete
//! commitment, quotient, Merkle-opening, binary-FRI, grinding, and exact-codec machinery for the
//! verifier-fixed cross-segment byte-memory table and the numeric output-projection AIR.
//!
//! The protocol order is fixed:
//!
//! 1. bind the exact public channel declarations;
//! 2. commit every masked base column;
//! 3. derive every independent relation-specific copy challenge;
//! 4. construct and commit every masked auxiliary product column;
//! 5. derive composition coefficients and commit quotient lanes;
//! 6. derive one shared DEEP point and bind current/next Fp4 openings;
//! 7. derive mixes over every DEEP quotient;
//! 8. commit each FRI layer before deriving its fold challenge;
//! 9. grind the completed commitment transcript;
//! 10. derive 136 unique query positions from the post-grinding transcript.
//!
//! Proof dimensions are reconstructed from the verifier statement. The wire contains no
//! caller-selected parameter and the strict reader rejects every truncation and trailing suffix.
mod main_aggregate;
#[cfg(test)]
use super::der_stark::{
    ZK_X509_DER_STARK_BUS_LANES_V1, ZkX509DerStarkChallengesV1, ZkX509DerStarkTerminalClaimsV1,
    evaluate_zk_x509_der_stark_residues_v1, zk_x509_der_stark_terminal_claims_v1,
};
#[cfg(test)]
use super::fixed_algebraic::ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::main_assembly::{ZkX509MainIoBaseMaterialV1, ZkX509MainTraceAssemblyV1};
#[cfg(test)]
use super::p256_aggregate_adapter::{
    P256BusTerminalClaimsV1, P256CrossTraceTerminalClaimV1, P256CrossTraceTerminalRoleV1,
    ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_SHA256_V1,
    ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_V1, absorb_p256_terminal_claims_v1,
    evaluate_p256_bus_terminal_claim_equalities_v1,
    evaluate_p256_cross_trace_terminal_claim_equalities_v1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::p256_aggregate_adapter::{P256MainBaseSourceV1, P256MainBoundSourceV1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::private_table::{PrivateTableV1, zeroize_field_rows_v1};
#[cfg(test)]
use super::proof_instance::TEST_PROOF_INSTANCE_V1;
use super::proof_instance::ZkX509ProofInstanceV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::sha_call_bus_stark::evaluate_zk_x509_sha_batch_local_residues_over_field_v1;
use super::{
    accumulator_air::{
        ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1, ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
    },
    accumulator_stark::{
        CA_AGGREGATE_PARAMETERS_V1, ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
        ZK_X509_CA_ACCUMULATOR_CHUNKS_V1, ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
        ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1, ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1,
        ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1, ZkX509AccumulatorStarkErrorV1,
    },
    credential_pre_aux::{
        ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1, ZkX509CredentialMainPostBaseChallengesV1,
        ZkX509CredentialMainPreAuxV1, ZkX509CredentialPreAuxBindingV1,
        absorb_zk_x509_credential_pre_aux_binding_v1,
    },
    credential_stark::{
        ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1, ZkX509CredentialPublicBindingV1,
    },
    der_air::ZkX509Rfc5280StatementV1,
    der_stark::{
        FIX_ACTIVE as DER_FIX_ACTIVE, FIX_COMPARATOR, FIX_FINAL_DOCUMENT, FIX_FIRST_ACTIVE,
        FIX_FIRST_AGGREGATE, FIX_FIRST_COMPARATOR, FIX_FIRST_PARSER,
        FIX_LAST_ACTIVE as DER_FIX_LAST_ACTIVE, FIX_LAST_AGGREGATE, FIX_LAST_COMPARATOR,
        FIX_LAST_PARSER, FIX_PADDING, FIX_PARSER, FIX_PARSER_CONTINUE,
        ZK_X509_DER_STARK_AUX_WIDTH_V1, ZK_X509_DER_STARK_BASE_WIDTH_V1,
        ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1, ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1, ZK_X509_DER_STARK_FIXED_WIDTH_V1,
        ZK_X509_DER_STARK_MAXIMUM_QUOTIENT_DEGREE_V1, ZK_X509_DER_STARK_TRACE_LOG2_V1,
        ZK_X509_DER_STARK_TRACE_SIZE_V1, ZkX509DerStarkErrorV1, ZkX509DerStarkPublicTerminalsV1,
        ZkX509DerStarkShapeV1, derive_zk_x509_der_stark_public_terminals_v1,
    },
    engine::construct_zk_x509_compiled_profile_v1,
    fixed_algebraic::{ZkX509FixedAlgebraicErrorV1, ZkX509FixedAlgebraicOpeningsV1},
    fixed_algebraic_p256::{
        ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1, ZkX509P256FixedAlgebraicErrorV1,
        zk_x509_p256_fixed_algebraic_schedule_v1,
    },
    fixed_algebraic_sha::{
        ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1, ZkX509ShaFixedAlgebraicErrorV1,
        zk_x509_sha_fixed_algebraic_schedule_v1,
    },
    io_air::{
        IO_PERMUTATION_LANES_V1, ZK_X509_IO_FIXED_CAPACITY_ROWS_V1, ZkX509IoAirErrorV1,
        ZkX509IoChallengesV1, ZkX509IoChannelDeclarationV1, ZkX509IoEndpointV1,
        ZkX509IoSegmentRoleV1, byte_memory_capacity_v1, validate_declarations_v1,
    },
    main_io::compile_zk_x509_main_io_declarations_v1,
    p256_aggregate_adapter::{
        P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1, P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
        P256_ARITHMETIC_AGGREGATE_TRACE_LOG2_V1, P256_ARITHMETIC_REGISTERED_CONSTRAINT_COUNT_V1,
        P256_BINDING_SINK_AGGREGATE_TRACE_LOG2_V1, P256_BINDING_SINK_BASE_WIDTH_V1,
        P256_BINDING_SINK_CONSTRAINT_DEGREE_V1, P256_BINDING_SINK_FIXED_WIDTH_V1,
        P256_BINDING_SINK_REGISTERED_CONSTRAINT_COUNT_V1, P256_LOW_S_AGGREGATE_AUX_WIDTH_V1,
        P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1, P256_LOW_S_AGGREGATE_TRACE_LOG2_V1,
        P256_LOW_S_REGISTERED_CONSTRAINT_COUNT_V1, P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1,
        P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1, P256_REDUCTION_AGGREGATE_TRACE_LOG2_V1,
        P256_REDUCTION_REGISTERED_CONSTRAINT_COUNT_V1, P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1,
        P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1, P256_VALUE_BUS_AGGREGATE_TRACE_LOG2_V1,
        P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1, P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
        P256_VALUE_EXECUTION_REGISTERED_CONSTRAINT_COUNT_V1,
        P256_VALUE_SORTED_REGISTERED_CONSTRAINT_COUNT_V1, P256_WINDOW_AGGREGATE_AUX_WIDTH_V1,
        P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1, P256_WINDOW_AGGREGATE_TRACE_LOG2_V1,
        P256_WINDOW_REGISTERED_CONSTRAINT_COUNT_V1, P256AggregateAdapterErrorV1,
        P256ArithmeticCopyChallengesV1, P256MainAdapterV1, P256MainRegistrationV1,
        P256MainVerifierFixedSourceV1, P256ValueExecutionAggregateChallengesV1,
        validate_p256_main_registration_order_v1,
    },
    p256_air::{P256_ARITHMETIC_BASE_WIDTH_V1, P256_ARITHMETIC_STARK_CONSTRAINT_DEGREE_V1},
    p256_cross_trace_bus::P256CrossTraceChallengesV1,
    p256_ecdsa_air::P256EcdsaRoleV1,
    p256_reduction_air::{P256_LOW_S_BASE_WIDTH_V1, P256_REDUCTION_BASE_WIDTH_V1},
    p256_scalar_bit_bus::{
        P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1, P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1,
        P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1,
        P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_DEGREE_V1, P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1,
        P256ScalarBitBusChallengesV1,
    },
    p256_value_bus::{
        P256_VALUE_BUS_STARK_AUX_WIDTH_V1, P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
        P256_VALUE_BUS_STARK_CONSTRAINT_DEGREE_V1, P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
        P256ValueBusChallengesV1,
    },
    p256_window_air::{P256_WINDOW_BASE_WIDTH_V1, P256_WINDOW_STARK_CONSTRAINT_DEGREE_V1},
    profile::{
        ZK_X509_CA_COMPOSITION_DEGREE_CHUNKS_V1, ZK_X509_CA_FRI_LDE_LOG2_V1,
        ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1, ZK_X509_CA_FRI_TERMINAL_LOG2_V1,
        ZK_X509_CA_TRACE_MASK_DEGREE_V1, ZK_X509_COMPOSITION_DEGREE_CHUNKS_V1,
        ZK_X509_COMPOSITION_LANES_V1, ZK_X509_FRI_BLOWUP_FACTOR_V1, ZK_X509_FRI_QUERY_COUNT_V1,
        ZK_X509_FRI_TERMINAL_DEGREE_BOUND_V1, ZK_X509_GRINDING_BITS_V1,
        ZK_X509_LOGICAL_REGISTRATIONS_V1, ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
        ZK_X509_MAIN_FRAME_BYTES_V1, ZK_X509_MAX_CONSTRAINT_DEGREE_V1,
        ZK_X509_MAX_NATIVE_TRACE_LOG2_V1, ZK_X509_MAX_PROOF_BYTES_V1,
        ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1, ZK_X509_PHYSICAL_COMMITMENT_CHUNKS_V1,
        ZK_X509_PROOF_VERSION_V1, ZK_X509_SUITE_V1, ZK_X509_TRACE_GROUPS_V1,
        ZK_X509_TRACE_MASK_DEGREE_V1,
    },
    projection_air::{
        ZK_X509_PROJECTION_AUX_WIDTH_V1, ZK_X509_PROJECTION_BASE_WIDTH_V1,
        ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1,
        ZK_X509_PROJECTION_STARK_CONSTRAINT_DEGREE_V1, ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1,
        ZK_X509_PROJECTION_TRACE_SIZE_V1, ZkX509ProjectionAirErrorV1, ZkX509ProjectionChallengesV1,
        compile_zk_x509_projection_stark_fixed_rows_v1,
        evaluate_zk_x509_projection_stark_residues_v1,
    },
    rfc5280_stark::{
        ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1, ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
        ZK_X509_RFC5280_STARK_BASE_WIDTH_V1, ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1,
        ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1, ZK_X509_RFC5280_STARK_TRACE_LOG2_V1,
        ZK_X509_RFC5280_STARK_TRACE_SIZE_V1, ZkX509Rfc5280StarkFixedRowV1,
        ZkX509Rfc5280StarkFixedScheduleV1, ZkX509Rfc5280StarkShapeV1,
        compile_zk_x509_rfc5280_stark_fixed_schedule_v1,
        evaluate_zk_x509_rfc5280_local_residues_v1,
    },
    sha_call_bus_stark::{
        ZK_X509_SHA_BATCH_AUX_WIDTH_V1, ZK_X509_SHA_BATCH_BASE_CHUNKS_PER_SEGMENT_V1,
        ZK_X509_SHA_BATCH_BASE_WIDTH_V1, ZK_X509_SHA_BATCH_CONSTRAINT_DEGREE_V1,
        ZK_X509_SHA_BATCH_FIXED_WIDTH_V1, ZK_X509_SHA_BATCH_LOCAL_CONSTRAINT_COUNT_V1,
        ZK_X509_SHA_FIXED_RFC_LENGTH_PAIR_V1, ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1,
        ZK_X509_SHA_SEGMENT_COUNT_V1, ZkX509ShaBatchFixedProviderV1, ZkX509ShaBatchRowV1,
        ZkX509ShaCallPublicShapeV1,
    },
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    accumulator_stark::ca_accumulator_stark_public_v1,
    der_stark::{
        ZkX509DerStarkBaseV1, ZkX509DerStarkFixedScheduleV1, ZkX509DerStarkTraceV1,
        build_zk_x509_der_stark_native_aux_column_v1,
        build_zk_x509_der_stark_native_base_column_v1,
        build_zk_x509_der_stark_native_fixed_column_v1, build_zk_x509_der_stark_trace_v1,
        compile_zk_x509_der_stark_fixed_schedule_v1,
    },
    io_air::{
        IoAccessV1, ZkX509IoChannelWitnessV1, build_zk_x509_io_base_tables_v1,
        build_zk_x509_io_trace_v1,
    },
    projection_air::{
        ZkX509ProjectionAuxTraceV1, ZkX509ProjectionTraceV1, build_zk_x509_projection_aux_trace_v1,
        compile_zk_x509_projection_fixed_trace_v1,
    },
    rfc5280_stark::{
        ZkX509Rfc5280StarkBaseMaterialV1, ZkX509Rfc5280StarkColumnProviderV1,
        ZkX509ShaUnionCentersV1,
    },
    sha_call_bus_stark::{
        ZkX509ShaBatchSegmentAuxSourceV1, ZkX509ShaBatchSegmentBaseSourceV1,
        ZkX509ShaCallScheduleV1, ZkX509ShaCallWitnessV1,
    },
};
#[cfg(test)]
use super::{
    credential_pre_aux::derive_zk_x509_credential_pre_aux_binding_v1,
    der_stark::{
        ZK_X509_DER_STARK_AIR_DESCRIPTOR_V1, build_zk_x509_der_stark_base_v1,
        derive_zk_x509_der_stark_challenges_v1, evaluate_zk_x509_der_stark_residues_into_v1,
        evaluate_zk_x509_der_stark_terminal_claim_residues_v1,
    },
    engine::recompute_zk_x509_compiled_profile_digest_v1,
    io_air::derive_zk_x509_io_challenges_v1,
    p256_aggregate_adapter::{
        derive_p256_arithmetic_copy_challenges_v1, p256_cross_trace_terminal_roles_v1,
    },
    p256_cross_trace_bus::{
        P256_CROSS_TRACE_LANES_V1, derive_zk_x509_p256_cross_trace_challenges_v1,
    },
    p256_scalar_bit_bus::derive_zk_x509_p256_scalar_bit_bus_challenges_v1,
    p256_value_bus::derive_zk_x509_p256_value_bus_challenges_v1,
    profile::{
        ZK_X509_FRI_FINAL_POLYNOMIAL_LENGTH_V1, ZK_X509_MAIN_PRE_DEEP_MAXIMUM_BYTES_V1,
        ZK_X509_PROVER_TARGET_SECONDS_V1,
    },
    projection_air::{
        ZK_X509_PROJECTION_AIR_DESCRIPTOR_V1, ZK_X509_PROJECTION_CHALLENGE_LABELS_V1,
        ZK_X509_PROJECTION_COPY_LANES_V1, ZkX509ProjectionCompactionChallengesV1,
        ZkX509ProjectionCopyChallengesV1, ZkX509ProjectionWitnessV1,
        build_zk_x509_projection_trace_v1,
    },
    rfc5280_stark::{
        ZkX509P256CertificatePrivateProductsV1, ZkX509P256PrivateProductsV1,
        ZkX509P256WalletPrivateProductsV1,
    },
    sha_call_bus_stark::ZK_X509_SHA_MAX_ENCODED_PROOF_BYTES_V1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_engines::transparent_stark::GOLDILOCKS_GENERATOR_V1;
#[cfg(test)]
use crate::privacy_engines::transparent_stark::goldilocks_batch_invert_v1;
#[cfg(test)]
use crate::privacy_engines::transparent_stark::goldilocks_evaluate_coset_v1;
#[cfg(test)]
use crate::privacy_engines::transparent_stark::{
    PrivacyOuterMerkleTreeV1, append_u64_v1, masked_trace_lde_column_v1,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_engines::transparent_stark::{
    goldilocks_fp4_evaluate_coset_v1, goldilocks_fp4_ifft_v1, goldilocks_ifft_v1, grind_nonce_v1,
};
use crate::privacy_engines::{
    aggregate_stark::{self as aggregate, AggregateStarkErrorV1},
    transparent_stark::{
        GoldilocksFieldV1 as F, GoldilocksFp4V1 as E, PolynomialAirFieldV1, PrivacyOuterDigestV1,
        TransparentStarkDigestContextV1, TransparentStarkErrorV1, TransparentTranscriptV1,
        append_u16_v1, append_u32_v1, goldilocks_primitive_root_v1, privacy_outer_digest_frame_v1,
        verify_grinding_nonce_v1,
    },
};
#[cfg(test)]
use iroha_data_model::privacy::PrivacyStatementV1;
use iroha_data_model::privacy::{IrohaZkX509StarkP256StatementV1, PrivacyProtocolIdV1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub use main_aggregate::commit_zk_x509_main_base_phase_v1_with_rng;
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub use main_aggregate::main_joint::finish_joint_main_ca_v1;
pub use main_aggregate::main_joint::{
    MainJointVerifierOraclesV1, main_joint_auxiliary_from_proofs_v1,
};
pub use main_aggregate::zk_x509_main_pre_aux_from_proof_v1;
#[cfg(test)]
use main_aggregate::{
    MainOpenedProviderSetV1, MainOpenedRowEvaluatorV1, MainTraceColumnKindV1,
    MainTracePolynomialSetV1, MainTraceProviderSetV1, P256OpenedRowEvaluatorV1,
    ProjectionOpenedRowEvaluatorV1, add_main_composition_coefficient_chunks_v1,
    main_opened_composition_value_v1, validate_main_fri_mixes_v1,
};
#[cfg(test)]
pub use main_aggregate::{ZkX509MainAwaitingCredentialBindingV1, ZkX509MainCompositionPhaseV1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use main_aggregate::{p256_opened_residues_v1, p256_scalar_opened_residues_v1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use rand::TryRngCore;
use std::collections::BTreeMap;
use thiserror::Error;
/// Complete proof-system descriptor for the implemented aggregate adapters.
///
/// The descriptor is transcript-bound and records the first-release geometry.
pub const ZK_X509_SEGMENTED_STARK_DESCRIPTOR_V1: &[u8] = b"zk-x509-aggregate-stark-v1-incompatible:wire=outer-X5S1-containing-exactly-one-X5M1-main-and-one-X5C1-ca:X5M1-claim-free-key-openings-plus-length-delimited-aggregate-no-fixed-sidecar-no-legacy:exact-statement-derived-shape:goldilocks-fp4-w4=7:main-common-lde-log22:compact-ca-local-lde-log16:ordered-native-stride-logical-trace-groups-main-joined-base-and-aux-roots:verifier-owned-logical-adapter-registration:exact-column-ranges-widths-constraint-counts-and-degrees-transcript-bound:64-column-physical-budget-chunks:main-49-registrations-6-groups-logs5,8,15,16,18,19-80-chunks:compact-ca-dedicated-log12-13-chunks:sha3-384-opaque48-vector-row-merkle:p256-binding-sink-degree3-including-fixed-selectors:sha-capacity-and-call-degree6-including-fixed-selectors:sha-digest-address-polynomial-select:sha-fixed-algebraic-width472-verifier-derived-no-proof-bytes:p256-fixed-algebraic-width404-verifier-derived-no-proof-bytes:fixed-polynomials-verifier-derived-at-deep-point-and-native-translates:x5b1-shared-challenge-pre-aux=single-joined-main-base-root-then-ca-base-root+main-profile+ca-profile+main-public+ca-public+sample-exact272-goldilocks-post-base-challenges-in-11-family-order=sha-call28,rfc48,projection28,io20,der52,sha-word-memory16,sha-word-base-fold4,p256-value28,p256-cross16,p256-scalar20,p256-arithmetic-copy12+opaque-main-post-base-session:main-io=statement-compiled-40+5d-declarations-logical55922+4736d-active-rows-padded-to262144:rfc5280-output-role-products=9-normalized-producer+9-actual-consumer-four-lane-aux-accumulators+36-private-equalities+4-private-CA-governed-root-consumer-links+16-private-sha-bridges+20-quartic-joins:main-key-byte-joins=12-blocks647-equalities-root-powers2,8:main-sha-digest-joins=5-blocks40-u32-equalities-root-power32:main-sha-rfc-private-union=16-constant-native-bridges+16-segment-quartic-links+4-role-quartic-links-original-masks-no-extra-openings:rfc5280-calendar-and-numeric=base285-aux280-fixed147-constraints2145-degree4-basic-constraints-fixed3x12-signed-parent-complete-canonical-u32-and-32bit-nonwrapping-slack-source-node-root-kind-active-gated-helper-fixed-eight-equality-and-fifteen-embedded-endpoint-slots-complete-nonempty-original-node-spans-live-prefix-count-typed-copy-domains103-104-optional-slot-canonical-zero-exact-extension-oid-ordinal-ku-document-and-critical-cardinality-five-key-and-five-complete-spki-outputs-der-node-byte-lookups-key-length66-offset1-spki-content89-total91-offset0-nine-variable-tbs-crl-signature-byte-and-canonical-u16-in-eight-byte-length-pairs-live-prefix-count-node-continuity-source-start-helper-projection-leaf-serial-magnitude-sign-octet-nonzero-first-byte-big-endian-length-selected-original-subject-oid-value-provenance-with-complete-name-oid-census-three-original-classes-disjoint-document-stride12-keys1through48-six-bit-positive-gaps-uniqueness-nonempty-bounded-rdns-and-complete-original-value-census-country-printable-utf8-dfa-output-metadata-six-verifier-fixed-equations-authenticated72-time-census-73-relations-38bit-slack-affine-loglookup-39relation-bound:local-component-history:both-original-aux-roots-before-active-fp4-local-constraint-alphas:then192-private-endpoint-link-descriptors-and-fp4-link-alphas:then17-key-and-digest-join-descriptors-and-fp4-alphas:then20-private-sha-union-descriptors-and-fp4-alphas:then108-CA-private-link-descriptors-and-fp4-alphas:private-links-linear-and-quartic-quotients-original-masks-before-composition-commitment:one-fp4-composition-lane:main-six-composition-chunks:ca-four-composition-chunks:canonical-quotient-stride=fri-cap-minus137:independent-fp4-adjacent-chunk-masks137-before-composition-root:fri-rate9over64:binary-fri:ordered-low-high-pair-leaves:affine-batching-m3-binary-fold-arity2:136-uniform-distinct-queries-without-replacement:main-terminal1024-degree143:ca-terminal1024-degree143:main-mask1816-coefficients:ca-mask2100-coefficients:one-shared-transcript-derived-deep-point-current+next+MAIN24-CA108-original-openings-both-local-records-bound-before-mixes:MAIN31-derived-key-and-digest-openings-power2,8,32-admissibility-and-DEEP-authentication:ca-complete-fp4-local-air1363-plus-MAIN108-original-cross-equations-at-deep-current-only-queried-trace-rows:main-complete-fp4-air49-native-vanishing-and-six-chunk-recomposition-at-deep-current-only-queried-trace-rows:grinding20:p256-four-independent-base-field-bus-lanes-per-family:all-roots-transcript-ordered:subproof-machinery-complete:X5M1-codec-and-accounting-complete:full-main-production-provider-verifier=complete:activation=unavailable-independent-qualification";
const PROOF_MAGIC_V1: [u8; 4] = *b"X5S1";
const SECURITY_LANES: usize = ZK_X509_COMPOSITION_LANES_V1 as usize;
const QUERY_COUNT: usize = ZK_X509_FRI_QUERY_COUNT_V1 as usize;
#[cfg(test)]
const BLOWUP: usize = ZK_X509_FRI_BLOWUP_FACTOR_V1 as usize;
const BLOWUP_LOG2: u8 = ZK_X509_FRI_BLOWUP_FACTOR_V1.ilog2() as u8;
#[cfg(test)]
const TERMINAL_SIZE: usize = ZK_X509_FRI_FINAL_POLYNOMIAL_LENGTH_V1 as usize;
const TERMINAL_LOG2: u8 = 10;
const TERMINAL_DEGREE_BOUND: usize = ZK_X509_FRI_TERMINAL_DEGREE_BOUND_V1 as usize;
const COMPOSITION_DEGREE_CHUNKS: usize = ZK_X509_COMPOSITION_DEGREE_CHUNKS_V1 as usize;
/// Inclusive degree of the trace mask multiplier.
///
/// Retain the existing 1816-coefficient trace masks. Canonical quotient chunks now use
/// independent adjacent-chunk masks; the earlier FFT-decomposition Equation (3) citation
/// alone does not qualify this mixed-native-domain construction. Full hiding review remains open.
const MASK_DEGREE: usize = ZK_X509_TRACE_MASK_DEGREE_V1 as usize;
const _: () = assert!(MASK_DEGREE == 1_815);
const DER_QUOTIENT_COSET_LOG2_V1: u8 = 22;
const DER_QUOTIENT_COSET_SIZE_V1: usize = 1 << DER_QUOTIENT_COSET_LOG2_V1;
const DER_MAXIMUM_QUOTIENT_DEGREE_V1: usize = ZK_X509_DER_STARK_MAXIMUM_QUOTIENT_DEGREE_V1;
const _: () = assert!(DER_MAXIMUM_QUOTIENT_DEGREE_V1 == 3_158_433);
const _: () = assert!(
    DER_MAXIMUM_QUOTIENT_DEGREE_V1 < DER_QUOTIENT_COSET_SIZE_V1
        && DER_QUOTIENT_COSET_SIZE_V1 / ZK_X509_DER_STARK_TRACE_SIZE_V1 == 8
);
const IO_LANES: usize = IO_PERMUTATION_LANES_V1;
const IO_BASE_WIDTH: usize = 28;
const IO_AUX_WIDTH: usize = 39;
const IO_FIXED_WIDTH: usize = 17;
const IO_CONSTRAINT_COUNT: usize = 91;
const IO_CONSTRAINT_DEGREE: u8 = 4;
const MIN_TRACE_LOG2: u8 = 4;
/// Smallest byte-memory trace whose shared FRI domain carries the release mask.
/// At log thirteen the 1/8 native-row masking margin is only 1,024 coefficients;
/// log fourteen provides 2,048 and carries all six composition chunks.
const IO_MIN_SECURE_TRACE_LOG2_V1: u8 = 14;
const _: () = assert!((1_usize << 13) / 8 <= MASK_DEGREE);
const _: () = assert!((1_usize << IO_MIN_SECURE_TRACE_LOG2_V1) / 8 > MASK_DEGREE);
const _: () = assert!(
    IO_CONSTRAINT_DEGREE as usize * ((1_usize << IO_MIN_SECURE_TRACE_LOG2_V1) + MASK_DEGREE)
        - (1_usize << IO_MIN_SECURE_TRACE_LOG2_V1)
        < COMPOSITION_DEGREE_CHUNKS * (1_usize << IO_MIN_SECURE_TRACE_LOG2_V1) * 9 / 8
);
#[cfg(test)]
const ACCUMULATOR_REGISTRATION_COUNT_V1: usize = 1;
#[cfg(test)]
const VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1: usize = QUERY_COUNT * 2;
const P256_CERTIFICATE_REGISTRATION_COUNT_V1: usize = 8;
const P256_WALLET_REGISTRATION_COUNT_V1: usize = 9;
const P256_SIGNATURE_COUNT_V1: usize = 5;
const P256_SIGNATURE_INSTANCE_STRIDE_V1: u16 = 3;
const _: () = assert!(
    P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1
        == P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_COUNT_V1
);
const CALCULATED_FULL_PROFILE_LOGICAL_REGISTRATIONS_V1: usize = 1
    + 1
    + 1
    + ZK_X509_SHA_SEGMENT_COUNT_V1
    + 1
    + 4 * P256_CERTIFICATE_REGISTRATION_COUNT_V1
    + P256_WALLET_REGISTRATION_COUNT_V1;
const FULL_PROFILE_LOGICAL_REGISTRATIONS_V1: usize = ZK_X509_LOGICAL_REGISTRATIONS_V1;
const FULL_PROFILE_TRACE_GROUPS_V1: usize = ZK_X509_TRACE_GROUPS_V1;
const FULL_PROFILE_PHYSICAL_CHUNKS_V1: usize = ZK_X509_PHYSICAL_COMMITMENT_CHUNKS_V1;
const MAIN_BASE_COMMITMENT_NATIVE_LOGS_V1: [u8; FULL_PROFILE_TRACE_GROUPS_V1] =
    [5, 8, 15, 16, 18, 19];
const _: () = assert!(
    CALCULATED_FULL_PROFILE_LOGICAL_REGISTRATIONS_V1 == FULL_PROFILE_LOGICAL_REGISTRATIONS_V1
);
// The complete ordered six-group row has one joined commitment. Logical
// registration counts are validated independently by the exact layout.
const _: () = assert!(ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 == 1);
const AGGREGATE_PARAMETERS_V1: aggregate::AggregateStarkParametersV1 =
    aggregate::AggregateStarkParametersV1 {
        proof_magic: PROOF_MAGIC_V1,
        proof_version: ZK_X509_PROOF_VERSION_V1,
        fri_commitment_layout: aggregate::AggregateFriCommitmentLayoutV1::Paired,
        security_lanes: SECURITY_LANES,
        query_count: QUERY_COUNT,
        blowup_log2: BLOWUP_LOG2,
        terminal_log2: TERMINAL_LOG2,
        terminal_degree_bound: TERMINAL_DEGREE_BOUND,
        composition_degree_chunks: COMPOSITION_DEGREE_CHUNKS,
        minimum_trace_log2: MIN_TRACE_LOG2,
        maximum_trace_log2: 19,
        maximum_trace_groups: FULL_PROFILE_TRACE_GROUPS_V1,
        maximum_segment_instances: FULL_PROFILE_PHYSICAL_CHUNKS_V1,
        maximum_base_columns_per_instance: ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1 as usize,
        maximum_aux_columns_per_instance: ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1 as usize,
        maximum_proof_bytes: ZK_X509_MAX_PROOF_BYTES_V1 as usize,
    };
#[cfg(test)]
#[path = "stark/io_fp4_air_tests.rs"]
mod io_fp4_air_tests;
#[cfg(test)]
#[path = "stark/proof_size_redesign_tests.rs"]
mod proof_size_redesign_tests;
const CA_BLOWUP_LOG2_V1: u8 = ZK_X509_CA_FRI_LDE_LOG2_V1 - ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1;
const CA_TERMINAL_SIZE_V1: usize = 1 << ZK_X509_CA_FRI_TERMINAL_LOG2_V1;
const CA_MASK_DEGREE_V1: usize = ZK_X509_CA_TRACE_MASK_DEGREE_V1 as usize;
const CA_COMPOSITION_DEGREE_CHUNKS_V1: usize = ZK_X509_CA_COMPOSITION_DEGREE_CHUNKS_V1 as usize;
const _: () = assert!(CA_BLOWUP_LOG2_V1 == 4);
const _: () = assert!(CA_TERMINAL_SIZE_V1 == 1024);
const _: () = assert!(CA_MASK_DEGREE_V1 == 2_099);
const _: () = assert!(CA_COMPOSITION_DEGREE_CHUNKS_V1 == 4);
const EXEC_CHANNEL: usize = 0;
const EXEC_OFFSET: usize = 1;
const EXEC_VALUE: usize = 2;
const EXEC_WRITE: usize = 3;
const EXEC_ROLE: usize = 4;
const EXEC_INSTANCE: usize = 5;
const EXEC_BITS: usize = 6;
const SORT_CHANNEL: usize = 14;
const SORT_OFFSET: usize = 15;
const SORT_VALUE: usize = 16;
const SORT_WRITE: usize = 17;
const SORT_ROLE: usize = 18;
const SORT_INSTANCE: usize = 19;
const SORT_BITS: usize = 20;
const AUX_EXEC_BEFORE: usize = 0;
const AUX_SORT_BEFORE: usize = AUX_EXEC_BEFORE + IO_LANES;
const AUX_EXEC_AFTER: usize = AUX_SORT_BEFORE + IO_LANES;
const AUX_SORT_AFTER: usize = AUX_EXEC_AFTER + IO_LANES;
const AUX_CONT_SEGMENT_INDEX: usize = AUX_SORT_AFTER + IO_LANES;
const AUX_CONT_GLOBAL_START: usize = AUX_CONT_SEGMENT_INDEX + 1;
const AUX_CONT_GLOBAL_END: usize = AUX_CONT_GLOBAL_START + 1;
const AUX_CONT_LOCAL_START: usize = AUX_CONT_GLOBAL_END + 1;
const AUX_CONT_LOCAL_END: usize = AUX_CONT_LOCAL_START + 1;
const AUX_CONT_MEMORY_START: usize = AUX_CONT_LOCAL_END + 1;
const AUX_CONT_MEMORY_END: usize = AUX_CONT_MEMORY_START + 1;
const AUX_CONT_EXEC_START: usize = AUX_CONT_MEMORY_END + 1;
const AUX_CONT_EXEC_END: usize = AUX_CONT_EXEC_START + IO_LANES;
const AUX_CONT_SORT_START: usize = AUX_CONT_EXEC_END + IO_LANES;
const AUX_CONT_SORT_END: usize = AUX_CONT_SORT_START + IO_LANES;
const _: () = assert!(IO_LANES == 4);
const _: () = assert!(AUX_CONT_SORT_END + IO_LANES == IO_AUX_WIDTH);
const FIX_EXEC_CHANNEL: usize = 0;
const FIX_EXEC_OFFSET: usize = 1;
const FIX_EXEC_WRITE: usize = 2;
const FIX_EXEC_ROLE: usize = 3;
const FIX_EXEC_INSTANCE: usize = 4;
const FIX_SORT_CHANNEL: usize = 5;
const FIX_SORT_OFFSET: usize = 6;
const FIX_SORT_WRITE: usize = 7;
const FIX_SORT_ROLE: usize = 8;
const FIX_SORT_INSTANCE: usize = 9;
const FIX_PUBLIC_SELECTOR: usize = 10;
const FIX_PUBLIC_VALUE: usize = 11;
const FIX_SORT_SAME_ADDRESS_NEXT: usize = 12;
const FIX_ACTIVE: usize = 13;
const FIX_FIRST: usize = 14;
const FIX_LAST_ACTIVE: usize = 15;
const FIX_TRANSITION: usize = 16;
const BASE_LEAF_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:base-leaf:v1";
const BASE_NODE_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:base-node:v1";
const AUX_LEAF_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:aux-leaf:v1";
const AUX_NODE_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:aux-node:v1";
const COMPOSITION_LEAF_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:composition-leaf:v1";
const COMPOSITION_NODE_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:composition-node:v1";
const FRI_LEAF_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:fri-leaf:v1";
const FRI_NODE_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:fri-node:v1";
#[cfg(test)]
const PUBLIC_DIGEST_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:io-public:v1";
const QUERY_SEED_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:query-seed:v1";
pub const ZK_X509_FIXED_DIGEST_CONTEXT_V1: TransparentStarkDigestContextV1 =
    TransparentStarkDigestContextV1::new(
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        b"iroha-zk-x509-stark-p256-release-profile-v1",
    );
#[cfg(test)]
pub const ZK_X509_DIGEST_CONTEXT_V1: TransparentStarkDigestContextV1 =
    TEST_PROOF_INSTANCE_V1.main_context_v1();
#[cfg(test)]
/// Construct one opaque 48-byte outer digest for cross-module zk-X509 tests.
pub fn zk_x509_test_digest384_v1(seed: u8) -> PrivacyOuterDigestV1 {
    PrivacyOuterDigestV1::from_bytes([seed; 48])
}
#[cfg(test)]
const DER_TERMINAL_CLAIMS_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:der-terminal-claims:v1";
#[cfg(test)]
const DER_PUBLIC_DIGEST_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:der-public:v1";
#[cfg(test)]
const PROJECTION_PUBLIC_DIGEST_DOMAIN: &[u8] = b"iroha:privacy:zk-x509:stark:projection-public:v1";
const MAIN_LAYOUT_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:stark:main-aggregate-layout:v1";
#[cfg(test)]
const P256_LAYOUT_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:stark:p256-aggregate-layout:v1";
#[cfg(test)]
const P256_REGISTRATION_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:stark:p256-registration:v1";
#[cfg(test)]
const DER_PROOF_MAGIC_V1: [u8; 4] = *b"X5P1";
#[cfg(test)]
const DER_PROOF_CLAIM_COUNT_V1: usize = 2 * ZK_X509_DER_STARK_BUS_LANES_V1;
#[cfg(test)]
const DER_PROOF_CLAIM_RECORD_BYTES_V1: usize = 2 + 2 + 8;
#[cfg(test)]
const DER_PROOF_LENGTH_OFFSET_V1: usize =
    4 + 2 + 2 + 2 + 2 + DER_PROOF_CLAIM_COUNT_V1 * DER_PROOF_CLAIM_RECORD_BYTES_V1;
#[cfg(test)]
const DER_PROOF_ENVELOPE_BYTES_V1: usize = DER_PROOF_LENGTH_OFFSET_V1 + 4;
#[cfg(test)]
const DER_SEGMENTED_PROOF_DESCRIPTOR_V1: &[u8] = b"zk-x509-der-segmented-proof-v1:wire=X5P1:version1:strict-der-adapter0:claim-count8:typed-lane-records=input-byte-type1-lanes0-3-then-node-type2-lanes0-3:no-duplicate-or-reordered-claims:canonical-goldilocks-u64be:exact-u32-length-prefixed-X5S1-payload:statement-frame=X5H1-document-count-u16-document-lengths-u16-parser-rows-u32-comparator-rows-u32:terminal-claim-transcript-frame=X5C1:query-only-verifier-fixed-columns:first-release";
const MAIN_PROOF_MAGIC_V1: [u8; 4] = *b"X5M1";
const MAIN_PROOF_KEY_OPENINGS_OFFSET_V1: usize = 4 + 2;
const MAIN_KEY_OPENING_COUNT_V1: usize = 31;
const MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1: usize =
    MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * MAIN_KEY_OPENING_COUNT_V1;
/// Exact canonical framing and original key openings around the inner X5S1.
pub const ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1: usize =
    MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1 + 4;
pub const ZK_X509_MAIN_PROOF_DESCRIPTOR_V1: &[u8] = b"zk-x509-main-proof-v1-incompatible:wire=X5M1+version1+exact31-canonical-Fp4-key-and-digest-join-openings992+u32be-inner-X5S1-length+exact-X5S1:no-fixed-sidecar:no-omitted-reordered-duplicated-or-trailing-records:private-der-rfc8-and-p256184-linear-endpoint-quotients+rfc-normalized-private-producer-consumer36-equalities-and-four-private-CA-governed-root-consumer-links+16-private-native-constant-bridges+20-quartic-original-masked-column-sha-rfc-endpoint-joins-no-extra-openings:main-key-byte-joins=12-blocks647-equalities-root-powers2,8:main-sha-digest-joins=5-blocks40-u32-equalities-root-power32:main-sha-rfc-private-union=16-constant-native-bridges+16-segment-quartic-links+4-role-quartic-links-original-masks-no-extra-openings:fixed-openings-derived-by-verifier-only-after-main-transcript-grinding:no-proof-supplied-fixed-values:x5b1-shared-main-ca-pre-aux-challenges:local-component-history:both-original-aux-roots-then-active-local-constraint-alphas-then-192-ordered-private-link-descriptors-and-link-alphas-then-17-key-and-digest-join-descriptors-and-alphas-then-20-private-sha-union-descriptors-and-alphas-then-108-ordered-CA-private-link-descriptors-and-alphas:additional31-derived-openings-plus-ordered132-MAIN24-CA108-openings-and-both-local-DEEP-records-before-independent-key-DEEP-and-FRI-mixes:first-release-no-legacy";
const _: () = assert!(ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1 == 1_002);
const _: () =
    assert!(ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1 == ZK_X509_MAIN_FRAME_BYTES_V1 as usize);
const fn main_domains_v1(
    proof_instance: ZkX509ProofInstanceV1,
) -> aggregate::AggregateStarkDomainsV1 {
    aggregate::AggregateStarkDomainsV1 {
        digest_context: proof_instance.main_context_v1(),
        base_leaf: BASE_LEAF_DOMAIN,
        base_node: BASE_NODE_DOMAIN,
        aux_leaf: AUX_LEAF_DOMAIN,
        aux_node: AUX_NODE_DOMAIN,
        composition_leaf: COMPOSITION_LEAF_DOMAIN,
        composition_node: COMPOSITION_NODE_DOMAIN,
        fri_leaf: FRI_LEAF_DOMAIN,
        fri_node: FRI_NODE_DOMAIN,
        layout_label: b"aggregate-stark-layout-v1",
        base_root_label: b"aggregate-stark-base-root-v1",
        aux_root_label: b"aggregate-stark-aux-root-v1",
        composition_root_label: b"aggregate-stark-composition-root-v1",
        fri_root_label: b"aggregate-stark-fri-layer-root-v1",
        fri_beta_label: b"zk-x509-fri-fold-beta-v1",
        query_seed: QUERY_SEED_DOMAIN,
    }
}
#[cfg(test)]
const AGGREGATE_DOMAINS_V1: aggregate::AggregateStarkDomainsV1 =
    main_domains_v1(TEST_PROOF_INSTANCE_V1);
/// Verifier-fixed byte-channel statement for the implemented STARK segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509IoStarkStatementV1 {
    declarations: Vec<ZkX509IoChannelDeclarationV1>,
}
impl ZkX509IoStarkStatementV1 {
    /// Construct the sole canonical statement topology.
    pub(crate) fn new(
        declarations: Vec<ZkX509IoChannelDeclarationV1>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_declarations_v1(&declarations)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        let rows = io_active_rows_v1(&declarations)?;
        if rows > byte_memory_capacity_v1().map_err(|_| ZkX509StarkErrorV1::InvalidStatement)? {
            return Err(ZkX509StarkErrorV1::InvalidStatement);
        }
        let layout = SegmentLayoutV1::for_io(rows)?;
        layout.validate()?;
        Ok(Self { declarations })
    }
    /// Borrow the verifier-fixed channel declarations.
    pub(crate) fn declarations(&self) -> &[ZkX509IoChannelDeclarationV1] {
        &self.declarations
    }
}
/// Failure in the bounded zk-X509 segmented proof implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509StarkErrorV1 {
    /// Verifier-fixed topology or public bytes are invalid.
    #[error("zk-X509 STARK public statement is invalid")]
    InvalidStatement,
    /// Witness declarations do not exactly equal the verifier statement.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 STARK witness topology does not match the statement")]
    WitnessStatementMismatch,
    /// Native byte-memory witness construction or validation failed.
    #[error("zk-X509 STARK byte-memory witness is invalid")]
    IoWitness,
    /// Native strict-DER witness construction or validation failed.
    #[error("zk-X509 STARK strict-DER witness is invalid")]
    DerWitness,
    /// Projection witness construction or algebraic compilation failed.
    #[error("zk-X509 STARK projection witness is invalid")]
    ProjectionWitness,
    /// Sparse-accumulator witness, SHA schedule, or numeric material is invalid.
    #[error("zk-X509 STARK accumulator witness is invalid")]
    AccumulatorWitness,
    /// P-256 aggregate witness, fixed topology, or terminal material is invalid.
    #[error("zk-X509 STARK P-256 aggregate witness is invalid")]
    P256Witness,
    /// A compiled segment/domain/column bound was exceeded.
    #[error("zk-X509 STARK segment profile is invalid")]
    ProfileMismatch,
    /// Proof bytes are empty, truncated, trailing, or otherwise malformed.
    #[error("zk-X509 STARK proof wire is malformed")]
    MalformedProof,
    /// Proof bytes exceed the consensus ceiling.
    #[error("zk-X509 STARK proof exceeds the byte ceiling")]
    ProofTooLarge,
    /// One proof field is not a canonical Goldilocks residue.
    #[error("zk-X509 STARK proof contains a non-canonical field")]
    NonCanonicalField,
    /// Masking entropy is unavailable.
    #[error("zk-X509 STARK masking entropy is unavailable")]
    RandomnessUnavailable,
    /// A committed base or auxiliary row opening is invalid.
    #[error("zk-X509 STARK trace opening is invalid")]
    TraceOpening,
    /// A quotient opening or algebraic constraint is invalid.
    #[error("zk-X509 STARK composition opening is invalid")]
    ConstraintOpening,
    /// A FRI opening/fold is invalid.
    #[error("zk-X509 STARK FRI opening is invalid")]
    FriOpening,
    /// The terminal FRI polynomial violates the degree bound.
    #[error("zk-X509 STARK FRI degree bound is invalid")]
    FriDegree,
    /// Transcript order, grinding, or query uniqueness is invalid.
    #[error("zk-X509 STARK transcript is invalid")]
    TranscriptMismatch,
    /// A bounded allocation failed.
    #[error("zk-X509 STARK bounded allocation failed")]
    AllocationFailure,
    /// Device work has uncertain completion and still owns private staging.
    /// A new proof cannot hide that retained payload by switching to CPU.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 prover device completion is uncertain; restart before proving again")]
    AcceleratorCompletionUncertain,
    /// An invariant in the compiled prover implementation failed.
    #[error("zk-X509 STARK internal invariant failed")]
    InternalInvariant,
}
impl From<ZkX509IoAirErrorV1> for ZkX509StarkErrorV1 {
    fn from(_: ZkX509IoAirErrorV1) -> Self {
        Self::IoWitness
    }
}
impl From<ZkX509ProjectionAirErrorV1> for ZkX509StarkErrorV1 {
    fn from(_: ZkX509ProjectionAirErrorV1) -> Self {
        Self::ProjectionWitness
    }
}
impl From<ZkX509DerStarkErrorV1> for ZkX509StarkErrorV1 {
    fn from(_: ZkX509DerStarkErrorV1) -> Self {
        Self::DerWitness
    }
}
impl From<ZkX509AccumulatorStarkErrorV1> for ZkX509StarkErrorV1 {
    fn from(error: ZkX509AccumulatorStarkErrorV1) -> Self {
        match error {
            ZkX509AccumulatorStarkErrorV1::Resource => Self::AllocationFailure,
            ZkX509AccumulatorStarkErrorV1::Witness
            | ZkX509AccumulatorStarkErrorV1::CallBus
            | ZkX509AccumulatorStarkErrorV1::IoBus
            | ZkX509AccumulatorStarkErrorV1::Shape => Self::AccumulatorWitness,
        }
    }
}
impl From<P256AggregateAdapterErrorV1> for ZkX509StarkErrorV1 {
    fn from(error: P256AggregateAdapterErrorV1) -> Self {
        match error {
            P256AggregateAdapterErrorV1::Resource => Self::AllocationFailure,
            #[cfg(any(test, feature = "privacy-release-evidence"))]
            P256AggregateAdapterErrorV1::Phase => Self::TranscriptMismatch,
            #[cfg(any(test, feature = "privacy-release-evidence"))]
            P256AggregateAdapterErrorV1::Source => Self::P256Witness,
            P256AggregateAdapterErrorV1::Topology
            | P256AggregateAdapterErrorV1::Challenge
            | P256AggregateAdapterErrorV1::Constraint => Self::P256Witness,
        }
    }
}
/// Decoded canonical MAIN frame borrowing its sole variable proof record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509MainProofEnvelopeV1<'a> {
    /// Exact ordered original-column evaluations at derived key-join DEEP points.
    pub(crate) key_openings: [E; MAIN_KEY_OPENING_COUNT_V1],
    /// Inner 49-registration aggregate X5S1 proof.
    pub(crate) aggregate_proof: &'a [u8],
}
/// Compute one MAIN frame length without allocation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const fn zk_x509_main_proof_envelope_encoded_len_v1(aggregate_bytes: usize) -> Option<usize> {
    ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1.checked_add(aggregate_bytes)
}
/// Encode the sole canonical MAIN frame.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub fn encode_zk_x509_main_proof_envelope_v1(
    key_openings: &[E; MAIN_KEY_OPENING_COUNT_V1],
    aggregate_proof: &[u8],
) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
    if aggregate_proof.len() < PROOF_MAGIC_V1.len()
        || aggregate_proof[..4] != PROOF_MAGIC_V1
        || aggregate_proof.len() > u32::MAX as usize
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }

    let encoded_len = zk_x509_main_proof_envelope_encoded_len_v1(aggregate_proof.len())
        .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
    if encoded_len > ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    encoded.extend_from_slice(&MAIN_PROOF_MAGIC_V1);
    append_u16_v1(&mut encoded, ZK_X509_PROOF_VERSION_V1);
    for value in key_openings {
        if !value.is_canonical() {
            return Err(ZkX509StarkErrorV1::NonCanonicalField);
        }
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    append_u32_v1(
        &mut encoded,
        u32::try_from(aggregate_proof.len()).map_err(|_| ZkX509StarkErrorV1::ProofTooLarge)?,
    );
    encoded.extend_from_slice(aggregate_proof);
    if encoded.len() != encoded_len {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(encoded)
}
fn main_envelope_u32_v1(encoded: &[u8], offset: usize) -> Result<usize, ZkX509StarkErrorV1> {
    let end = offset
        .checked_add(4)
        .ok_or(ZkX509StarkErrorV1::MalformedProof)?;
    usize::try_from(u32::from_be_bytes(
        encoded
            .get(offset..end)
            .ok_or(ZkX509StarkErrorV1::MalformedProof)?
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
    ))
    .map_err(|_| ZkX509StarkErrorV1::MalformedProof)
}
/// Decode exactly one MAIN frame, rejecting aliases, omissions, reordering,
/// noncanonical fields, length mismatches, and suffixes.
pub fn decode_zk_x509_main_proof_envelope_v1<'a>(
    encoded: &'a [u8],
) -> Result<ZkX509MainProofEnvelopeV1<'a>, ZkX509StarkErrorV1> {
    if encoded.len() > ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    if encoded.len() < ZK_X509_MAIN_PROOF_ENVELOPE_FIXED_BYTES_V1 + PROOF_MAGIC_V1.len()
        || encoded[..4] != MAIN_PROOF_MAGIC_V1
        || u16::from_be_bytes(
            encoded[4..6]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        ) != ZK_X509_PROOF_VERSION_V1
    {
        return Err(ZkX509StarkErrorV1::MalformedProof);
    }
    let mut key_openings = [E::ZERO; MAIN_KEY_OPENING_COUNT_V1];
    for (i, value) in key_openings.iter_mut().enumerate() {
        let mut words = [0_u64; 4];
        for (j, word) in words.iter_mut().enumerate() {
            let start = MAIN_PROOF_KEY_OPENINGS_OFFSET_V1 + 32 * i + 8 * j;
            *word = u64::from_be_bytes(
                encoded
                    .get(start..start + 8)
                    .ok_or(ZkX509StarkErrorV1::MalformedProof)?
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
            );
        }
        *value = E::canonical(words).ok_or(ZkX509StarkErrorV1::NonCanonicalField)?;
    }
    let aggregate_len = main_envelope_u32_v1(encoded, MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1)?;
    let aggregate_start = MAIN_PROOF_AGGREGATE_LENGTH_OFFSET_V1
        .checked_add(4)
        .ok_or(ZkX509StarkErrorV1::MalformedProof)?;
    let aggregate_end = aggregate_start
        .checked_add(aggregate_len)
        .ok_or(ZkX509StarkErrorV1::MalformedProof)?;
    let aggregate_proof = encoded
        .get(aggregate_start..aggregate_end)
        .ok_or(ZkX509StarkErrorV1::MalformedProof)?;
    if aggregate_end != encoded.len()
        || aggregate_proof.len() < PROOF_MAGIC_V1.len()
        || aggregate_proof[..4] != PROOF_MAGIC_V1
    {
        return Err(ZkX509StarkErrorV1::MalformedProof);
    }
    Ok(ZkX509MainProofEnvelopeV1 {
        key_openings,
        aggregate_proof,
    })
}
fn map_aggregate_error_v1(error: AggregateStarkErrorV1) -> ZkX509StarkErrorV1 {
    match error {
        AggregateStarkErrorV1::InvalidLayout | AggregateStarkErrorV1::InvalidProofShape => {
            ZkX509StarkErrorV1::ProfileMismatch
        }
        AggregateStarkErrorV1::MalformedProof => ZkX509StarkErrorV1::MalformedProof,
        AggregateStarkErrorV1::ProofTooLarge => ZkX509StarkErrorV1::ProofTooLarge,
        AggregateStarkErrorV1::NonCanonicalField => ZkX509StarkErrorV1::NonCanonicalField,
        AggregateStarkErrorV1::TraceOpening => ZkX509StarkErrorV1::TraceOpening,
        AggregateStarkErrorV1::ConstraintOpening => ZkX509StarkErrorV1::ConstraintOpening,
        AggregateStarkErrorV1::DeepOpening => ZkX509StarkErrorV1::ConstraintOpening,
        AggregateStarkErrorV1::FriOpening => ZkX509StarkErrorV1::FriOpening,
        AggregateStarkErrorV1::FriDegree => ZkX509StarkErrorV1::FriDegree,
        AggregateStarkErrorV1::TranscriptMismatch => ZkX509StarkErrorV1::TranscriptMismatch,
        AggregateStarkErrorV1::AllocationFailure => ZkX509StarkErrorV1::AllocationFailure,
        AggregateStarkErrorV1::RandomnessUnavailable => ZkX509StarkErrorV1::RandomnessUnavailable,
        AggregateStarkErrorV1::InternalInvariant => ZkX509StarkErrorV1::InternalInvariant,
    }
}
fn map_fixed_algebraic_error_v1(error: ZkX509FixedAlgebraicErrorV1) -> ZkX509StarkErrorV1 {
    match error {
        ZkX509FixedAlgebraicErrorV1::InvalidQuery => ZkX509StarkErrorV1::TraceOpening,
        ZkX509FixedAlgebraicErrorV1::AllocationFailure => ZkX509StarkErrorV1::AllocationFailure,
        ZkX509FixedAlgebraicErrorV1::InvalidDomain
        | ZkX509FixedAlgebraicErrorV1::InvalidWidth
        | ZkX509FixedAlgebraicErrorV1::InvalidAtom
        | ZkX509FixedAlgebraicErrorV1::NonCanonicalSchedule
        | ZkX509FixedAlgebraicErrorV1::NonCanonicalField
        | ZkX509FixedAlgebraicErrorV1::LimitExceeded
        | ZkX509FixedAlgebraicErrorV1::IntegerOverflow
        | ZkX509FixedAlgebraicErrorV1::DivisionByZero
        | ZkX509FixedAlgebraicErrorV1::InternalInvariant => ZkX509StarkErrorV1::ProfileMismatch,
        #[cfg(test)]
        ZkX509FixedAlgebraicErrorV1::DescriptorMismatch => ZkX509StarkErrorV1::ProfileMismatch,
    }
}
fn map_sha_fixed_algebraic_error_v1(error: ZkX509ShaFixedAlgebraicErrorV1) -> ZkX509StarkErrorV1 {
    match error {
        ZkX509ShaFixedAlgebraicErrorV1::Resource => ZkX509StarkErrorV1::AllocationFailure,
        ZkX509ShaFixedAlgebraicErrorV1::Topology | ZkX509ShaFixedAlgebraicErrorV1::Algebraic => {
            ZkX509StarkErrorV1::ProfileMismatch
        }
    }
}
fn map_p256_fixed_algebraic_error_v1(error: ZkX509P256FixedAlgebraicErrorV1) -> ZkX509StarkErrorV1 {
    match error {
        ZkX509P256FixedAlgebraicErrorV1::Resource => ZkX509StarkErrorV1::AllocationFailure,
        ZkX509P256FixedAlgebraicErrorV1::Topology => ZkX509StarkErrorV1::ProfileMismatch,
        ZkX509P256FixedAlgebraicErrorV1::Algebraic(error) => map_fixed_algebraic_error_v1(error),
    }
}
/// Stable identity of one physical opened-row evaluator.
///
/// Every identity is part of the sole first-release registration. Numeric
/// material must exist before the full proof API is enabled; an identity or
/// descriptor alone never satisfies registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
enum SegmentAdapterIdV1 {
    ByteMemory = 1,
    StrictDer = 2,
    Rfc5280 = 3,
    Sha256CallBus = 4,
    CaAccumulator = 5,
    Projection = 6,
    P256Arithmetic = 7,
    P256Reduction = 8,
    P256LowS = 9,
    P256Window = 10,
    P256ValueBus = 11,
    P256ScalarBitBus = 12,
}
impl SegmentAdapterIdV1 {
    const fn wire(self) -> u16 {
        self as u16
    }
}
fn p256_instance_v1(signature: usize, local: u16) -> Result<u16, ZkX509StarkErrorV1> {
    if signature >= P256_SIGNATURE_COUNT_V1 || local >= P256_SIGNATURE_INSTANCE_STRIDE_V1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    u16::try_from(signature)
        .ok()
        .and_then(|signature| signature.checked_mul(P256_SIGNATURE_INSTANCE_STRIDE_V1))
        .and_then(|base| base.checked_add(local))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
}
fn p256_instance_parts_v1(instance: u16) -> Option<(usize, u16)> {
    let signature = usize::from(instance / P256_SIGNATURE_INSTANCE_STRIDE_V1);
    (signature < P256_SIGNATURE_COUNT_V1)
        .then_some((signature, instance % P256_SIGNATURE_INSTANCE_STRIDE_V1))
}
/// Translate one verifier-owned MAIN slice into the sole central P-256
/// registration identity and revalidate every shared native dimension.
///
/// The MAIN layout represents the binding sink as value-bus local instance two, while the central
/// source gives it its own adapter identity at local instance zero. All other mappings are exact.
fn p256_main_registration_from_main_layout_v1(
    registration: RegisteredSegmentLayoutV1,
) -> Result<P256MainRegistrationV1, ZkX509StarkErrorV1> {
    registration.segment.validate()?;
    let (signature, local) = p256_instance_parts_v1(registration.segment.instance)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let (adapter, central_local) = match (registration.segment.adapter, local) {
        (SegmentAdapterIdV1::P256ValueBus, 0 | 1) => {
            (P256MainAdapterV1::ValueBus, usize::from(local))
        }
        (SegmentAdapterIdV1::P256ValueBus, 2) => (P256MainAdapterV1::BindingSink, 0),
        (SegmentAdapterIdV1::P256Arithmetic, 0) => (P256MainAdapterV1::Arithmetic, 0),
        (SegmentAdapterIdV1::P256Window, 0) => (P256MainAdapterV1::WindowBatch, 0),
        (SegmentAdapterIdV1::P256Reduction, 0 | 1) => {
            (P256MainAdapterV1::Reduction, usize::from(local))
        }
        (SegmentAdapterIdV1::P256LowS, 0) => (P256MainAdapterV1::WalletLowS, 0),
        (SegmentAdapterIdV1::P256ScalarBitBus, 0) => (P256MainAdapterV1::ScalarBitBus, 0),
        _ => return Err(ZkX509StarkErrorV1::ProfileMismatch),
    };
    let central = P256MainRegistrationV1::new_v1(signature, adapter, central_local)
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let shape = central
        .shape_v1()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    if shape.trace_size != registration.segment.trace_size()
        || shape.base_width != registration.segment.base_width
        || shape.aux_width != registration.segment.aux_width
        || shape.fixed_width != registration.segment.fixed_width
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(central)
}
const REQUIRED_FULL_PROFILE_ADAPTERS_V1: [SegmentAdapterIdV1; 11] = [
    SegmentAdapterIdV1::ByteMemory,
    SegmentAdapterIdV1::StrictDer,
    SegmentAdapterIdV1::Rfc5280,
    SegmentAdapterIdV1::Sha256CallBus,
    SegmentAdapterIdV1::Projection,
    SegmentAdapterIdV1::P256Arithmetic,
    SegmentAdapterIdV1::P256Reduction,
    SegmentAdapterIdV1::P256LowS,
    SegmentAdapterIdV1::P256Window,
    SegmentAdapterIdV1::P256ValueBus,
    SegmentAdapterIdV1::P256ScalarBitBus,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SegmentLayoutV1 {
    adapter: SegmentAdapterIdV1,
    instance: u16,
    active_rows: usize,
    trace_log2: u8,
    lde_log2: u8,
    base_width: usize,
    aux_width: usize,
    fixed_width: usize,
    constraint_count: usize,
    constraint_degree: u8,
    /// Exact number of 64-column streaming commitment slices allocated by
    /// the release plan. This is explicit because the compact-CA adapter
    /// streams its thirteen base and two auxiliary slices independently.
    physical_chunks: usize,
}
#[derive(Clone, Copy)]
struct SegmentDegreeCapacityProfileV1 {
    mask_degree: usize,
    fixed_selector_degree_terms: usize,
    minimum_trace_log2: u8,
    maximum_trace_log2: u8,
    minimum_blowup_log2: u8,
    maximum_lde_log2: u8,
    terminal_log2: u8,
    terminal_degree_bound: usize,
    composition_degree_chunks: usize,
}
const MAIN_DEGREE_CAPACITY_PROFILE_V1: SegmentDegreeCapacityProfileV1 =
    SegmentDegreeCapacityProfileV1 {
        mask_degree: MASK_DEGREE,
        fixed_selector_degree_terms: 0,
        minimum_trace_log2: MIN_TRACE_LOG2,
        maximum_trace_log2: ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
        minimum_blowup_log2: BLOWUP_LOG2,
        maximum_lde_log2: ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
        terminal_log2: TERMINAL_LOG2,
        terminal_degree_bound: TERMINAL_DEGREE_BOUND,
        composition_degree_chunks: COMPOSITION_DEGREE_CHUNKS,
    };
const CA_DEGREE_CAPACITY_PROFILE_V1: SegmentDegreeCapacityProfileV1 =
    SegmentDegreeCapacityProfileV1 {
        mask_degree: CA_MASK_DEGREE_V1,
        fixed_selector_degree_terms: 2,
        minimum_trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
        maximum_trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
        minimum_blowup_log2: CA_BLOWUP_LOG2_V1,
        maximum_lde_log2: ZK_X509_CA_FRI_LDE_LOG2_V1,
        terminal_log2: ZK_X509_CA_FRI_TERMINAL_LOG2_V1,
        terminal_degree_bound: ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1 as usize,
        composition_degree_chunks: CA_COMPOSITION_DEGREE_CHUNKS_V1,
    };
fn checked_segment_degree_capacity_for_profile_v1(
    trace_log2: u8,
    lde_log2: u8,
    constraint_degree: u8,
    profile: SegmentDegreeCapacityProfileV1,
) -> Result<(usize, usize), ZkX509StarkErrorV1> {
    let minimum_lde_log2 = trace_log2
        .checked_add(profile.minimum_blowup_log2)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if !(profile.minimum_trace_log2..=profile.maximum_trace_log2).contains(&trace_log2)
        || !(2..=ZK_X509_MAX_CONSTRAINT_DEGREE_V1).contains(&constraint_degree)
        || !(minimum_lde_log2..=profile.maximum_lde_log2).contains(&lde_log2)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let fri_rounds = lde_log2
        .checked_sub(profile.terminal_log2)
        .filter(|rounds| *rounds != 0)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let trace_size = 1_usize
        .checked_shl(u32::from(trace_log2))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let maximum_masked_trace_degree = trace_size
        .checked_add(profile.mask_degree)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let maximum_quotient_degree = usize::from(constraint_degree)
        .checked_mul(maximum_masked_trace_degree)
        .and_then(|degree| {
            profile
                .fixed_selector_degree_terms
                .checked_mul(trace_size - 1)
                .and_then(|selectors| degree.checked_add(selectors))
        })
        .and_then(|degree| degree.checked_sub(trace_size))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let fold_factor = 1_usize
        .checked_shl(u32::from(fri_rounds))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let maximum_fri_input_degree = profile
        .terminal_degree_bound
        .checked_add(1)
        .and_then(|terminal_coefficients| terminal_coefficients.checked_mul(fold_factor))
        .and_then(|coefficient_capacity| coefficient_capacity.checked_sub(1))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let maximum_composition_degree = maximum_fri_input_degree
        .checked_add(1)
        .and_then(|chunk_size| chunk_size.checked_sub(QUERY_COUNT + 1))
        .and_then(|stride| stride.checked_mul(profile.composition_degree_chunks))
        .and_then(|coefficient_capacity| coefficient_capacity.checked_sub(1))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if maximum_masked_trace_degree > maximum_fri_input_degree
        || maximum_quotient_degree > maximum_composition_degree
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok((maximum_quotient_degree, maximum_fri_input_degree))
}
fn checked_segment_degree_capacity_v1(
    trace_log2: u8,
    lde_log2: u8,
    constraint_degree: u8,
) -> Result<(usize, usize), ZkX509StarkErrorV1> {
    checked_segment_degree_capacity_for_profile_v1(
        trace_log2,
        lde_log2,
        constraint_degree,
        MAIN_DEGREE_CAPACITY_PROFILE_V1,
    )
}
fn checked_compact_ca_degree_capacity_v1(
    trace_log2: u8,
    lde_log2: u8,
    constraint_degree: u8,
) -> Result<(usize, usize), ZkX509StarkErrorV1> {
    checked_segment_degree_capacity_for_profile_v1(
        trace_log2,
        lde_log2,
        constraint_degree,
        CA_DEGREE_CAPACITY_PROFILE_V1,
    )
}
impl SegmentLayoutV1 {
    fn main_capacity_lde_log2_v1(self) -> u8 {
        if matches!(
            self.adapter,
            SegmentAdapterIdV1::P256Arithmetic
                | SegmentAdapterIdV1::P256Reduction
                | SegmentAdapterIdV1::P256LowS
                | SegmentAdapterIdV1::P256Window
                | SegmentAdapterIdV1::P256ValueBus
                | SegmentAdapterIdV1::P256ScalarBitBus
        ) {
            // Every canonical P-256 registration contains its log19 value and
            // arithmetic groups, so all smaller component polynomials are
            // committed on the verifier-fixed MAIN log22 domain. The
            // aggregate layout validates that actual common domain again.
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1
        } else {
            self.lde_log2
        }
    }
    fn with_checked_main_degree_capacity_v1(self) -> Result<Self, ZkX509StarkErrorV1> {
        checked_segment_degree_capacity_v1(
            self.trace_log2,
            self.main_capacity_lde_log2_v1(),
            self.constraint_degree,
        )?;
        Ok(self)
    }
    #[cfg(test)]
    fn with_checked_compact_ca_degree_capacity_v1(self) -> Result<Self, ZkX509StarkErrorV1> {
        checked_compact_ca_degree_capacity_v1(
            self.trace_log2,
            self.lde_log2,
            self.constraint_degree,
        )?;
        Ok(self)
    }
    fn for_io(active_rows: usize) -> Result<Self, ZkX509StarkErrorV1> {
        let padded = active_rows
            .max(1_usize << IO_MIN_SECURE_TRACE_LOG2_V1)
            .checked_next_power_of_two()
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let trace_log2 =
            u8::try_from(padded.ilog2()).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let lde_log2 = trace_log2
            .checked_add(BLOWUP_LOG2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Self {
            adapter: SegmentAdapterIdV1::ByteMemory,
            instance: 0,
            active_rows,
            trace_log2,
            lde_log2,
            base_width: IO_BASE_WIDTH,
            aux_width: IO_AUX_WIDTH,
            fixed_width: IO_FIXED_WIDTH,
            constraint_count: IO_CONSTRAINT_COUNT,
            constraint_degree: IO_CONSTRAINT_DEGREE,
            physical_chunks: 1,
        }
        .with_checked_main_degree_capacity_v1()
    }
    fn for_full_io() -> Result<Self, ZkX509StarkErrorV1> {
        // In the full MAIN registration `active_rows` is the transcript-bound
        // fixed table extent, not the statement-dependent logical prefix.
        // `IoTraceMaterialV1::logical_active_rows` separately controls the
        // active/last-active selectors and continuation endpoints.
        let active_rows = ZK_X509_IO_FIXED_CAPACITY_ROWS_V1;
        let mut layout = Self::for_io(active_rows)?;
        layout.trace_log2 = 18;
        layout.lde_log2 = 18 + BLOWUP_LOG2;
        layout.with_checked_main_degree_capacity_v1()
    }
    fn for_der(active_rows: usize) -> Result<Self, ZkX509StarkErrorV1> {
        let lde_log2 = ZK_X509_DER_STARK_TRACE_LOG2_V1
            .checked_add(BLOWUP_LOG2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Self {
            adapter: SegmentAdapterIdV1::StrictDer,
            instance: 0,
            active_rows,
            trace_log2: ZK_X509_DER_STARK_TRACE_LOG2_V1,
            lde_log2,
            base_width: ZK_X509_DER_STARK_BASE_WIDTH_V1,
            aux_width: ZK_X509_DER_STARK_AUX_WIDTH_V1,
            fixed_width: ZK_X509_DER_STARK_FIXED_WIDTH_V1,
            constraint_count: ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1,
            constraint_degree: ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1,
            physical_chunks: ZK_X509_DER_STARK_BASE_WIDTH_V1
                .max(ZK_X509_DER_STARK_AUX_WIDTH_V1)
                .div_ceil(usize::from(ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1)),
        }
        .with_checked_main_degree_capacity_v1()
    }
    fn for_der_main_v1(active_rows: usize) -> Result<Self, ZkX509StarkErrorV1> {
        let mut layout = Self::for_der(active_rows)?;
        layout.constraint_count = super::der_stark::ZK_X509_DER_STARK_LOCAL_CONSTRAINT_COUNT_V1;
        Ok(layout)
    }
    fn for_rfc5280(active_rows: usize) -> Result<Self, ZkX509StarkErrorV1> {
        let lde_log2 = ZK_X509_RFC5280_STARK_TRACE_LOG2_V1
            .checked_add(BLOWUP_LOG2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Self {
            adapter: SegmentAdapterIdV1::Rfc5280,
            instance: 0,
            active_rows,
            trace_log2: ZK_X509_RFC5280_STARK_TRACE_LOG2_V1,
            lde_log2,
            base_width: ZK_X509_RFC5280_STARK_BASE_WIDTH_V1,
            aux_width: ZK_X509_RFC5280_STARK_AUX_WIDTH_V1,
            fixed_width: ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1,
            constraint_count: ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1,
            constraint_degree: ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1,
            physical_chunks: ZK_X509_RFC5280_STARK_BASE_WIDTH_V1
                .max(ZK_X509_RFC5280_STARK_AUX_WIDTH_V1)
                .div_ceil(usize::from(ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1)),
        }
        .with_checked_main_degree_capacity_v1()
    }
    fn for_projection() -> Result<Self, ZkX509StarkErrorV1> {
        let trace_log2 = u8::try_from(ZK_X509_PROJECTION_TRACE_SIZE_V1.ilog2())
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let lde_log2 = trace_log2
            .checked_add(BLOWUP_LOG2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Self {
            adapter: SegmentAdapterIdV1::Projection,
            instance: 0,
            active_rows: ZK_X509_PROJECTION_TRACE_SIZE_V1,
            trace_log2,
            lde_log2,
            base_width: ZK_X509_PROJECTION_BASE_WIDTH_V1,
            aux_width: ZK_X509_PROJECTION_AUX_WIDTH_V1,
            fixed_width: ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1,
            constraint_count: ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1,
            constraint_degree: ZK_X509_PROJECTION_STARK_CONSTRAINT_DEGREE_V1,
            physical_chunks: 1,
        }
        .with_checked_main_degree_capacity_v1()
    }
    fn for_sha_segment(instance: u16, active_rows: usize) -> Result<Self, ZkX509StarkErrorV1> {
        let lde_log2 = ZK_X509_MAX_NATIVE_TRACE_LOG2_V1
            .checked_add(BLOWUP_LOG2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Self {
            adapter: SegmentAdapterIdV1::Sha256CallBus,
            instance,
            active_rows,
            trace_log2: ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
            lde_log2,
            base_width: ZK_X509_SHA_BATCH_BASE_WIDTH_V1,
            aux_width: ZK_X509_SHA_BATCH_AUX_WIDTH_V1,
            fixed_width: ZK_X509_SHA_BATCH_FIXED_WIDTH_V1,
            constraint_count: ZK_X509_SHA_BATCH_LOCAL_CONSTRAINT_COUNT_V1,
            constraint_degree: ZK_X509_SHA_BATCH_CONSTRAINT_DEGREE_V1,
            physical_chunks: ZK_X509_SHA_BATCH_BASE_CHUNKS_PER_SEGMENT_V1,
        }
        .with_checked_main_degree_capacity_v1()
    }
    #[cfg(test)]
    fn for_ca_accumulator() -> Result<Self, ZkX509StarkErrorV1> {
        Self {
            adapter: SegmentAdapterIdV1::CaAccumulator,
            instance: 0,
            active_rows: ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1,
            trace_log2: ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1,
            lde_log2: ZK_X509_CA_FRI_LDE_LOG2_V1,
            base_width: ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1,
            aux_width: ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1,
            fixed_width: ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1,
            constraint_count: ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1,
            constraint_degree: ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1,
            physical_chunks: ZK_X509_CA_ACCUMULATOR_CHUNKS_V1,
        }
        .with_checked_compact_ca_degree_capacity_v1()
    }
    fn for_p256_component(
        adapter: SegmentAdapterIdV1,
        instance: u16,
        trace_log2: u8,
        base_width: usize,
        aux_width: usize,
        fixed_width: usize,
        constraint_count: usize,
        constraint_degree: u8,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let active_rows = 1_usize
            .checked_shl(u32::from(trace_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let lde_log2 = trace_log2
            .checked_add(BLOWUP_LOG2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Self {
            adapter,
            instance,
            active_rows,
            trace_log2,
            lde_log2,
            base_width,
            aux_width,
            fixed_width,
            constraint_count,
            constraint_degree,
            physical_chunks: base_width
                .max(aux_width)
                .div_ceil(usize::from(ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1)),
        }
        .with_checked_main_degree_capacity_v1()
    }
    fn trace_size(self) -> usize {
        1_usize << self.trace_log2
    }
    fn lde_size(self) -> usize {
        1_usize << self.lde_log2
    }
    fn column_chunks(self) -> Result<usize, ZkX509StarkErrorV1> {
        let minimum = self
            .base_width
            .max(self.aux_width)
            .div_ceil(usize::from(ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1));
        (self.physical_chunks >= minimum && self.physical_chunks != 0)
            .then_some(self.physical_chunks)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    fn validate(self) -> Result<(), ZkX509StarkErrorV1> {
        let capacity_profile = if self.adapter == SegmentAdapterIdV1::CaAccumulator {
            checked_compact_ca_degree_capacity_v1(
                self.trace_log2,
                self.lde_log2,
                self.constraint_degree,
            )?;
            CA_DEGREE_CAPACITY_PROFILE_V1
        } else {
            checked_segment_degree_capacity_v1(
                self.trace_log2,
                self.main_capacity_lde_log2_v1(),
                self.constraint_degree,
            )?;
            MAIN_DEGREE_CAPACITY_PROFILE_V1
        };
        let expected_lde_log2 = self
            .trace_log2
            .checked_add(capacity_profile.minimum_blowup_log2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let evaluation_lde_log2 = if self.adapter == SegmentAdapterIdV1::CaAccumulator {
            self.lde_log2
        } else {
            self.main_capacity_lde_log2_v1()
        };
        let evaluation_lde_size = 1_usize << evaluation_lde_log2;
        let fri_rounds = evaluation_lde_log2
            .checked_sub(capacity_profile.terminal_log2)
            .filter(|rounds| *rounds != 0)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let terminal_size = 1_usize
            .checked_shl(u32::from(capacity_profile.terminal_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let paired_chunks = self
            .base_width
            .max(self.aux_width)
            .div_ceil(usize::from(ZK_X509_PHYSICAL_COMMITMENT_CHUNK_COLUMNS_V1));
        if self.active_rows == 0
            || self.active_rows > self.trace_size()
            || self.lde_log2 != expected_lde_log2
            || self.lde_size() < QUERY_COUNT
            || self.base_width == 0
            || self.aux_width == 0
            || self.base_width > usize::from(u16::MAX)
            || self.aux_width > usize::from(u16::MAX)
            || self.fixed_width == 0
            || self.constraint_count == 0
            || self.constraint_count > usize::from(u16::MAX)
            || (evaluation_lde_size >> fri_rounds) != terminal_size
            || self.column_chunks()? > FULL_PROFILE_PHYSICAL_CHUNKS_V1
            || (self.adapter != SegmentAdapterIdV1::CaAccumulator
                && self.physical_chunks != paired_chunks)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        match self.adapter {
            SegmentAdapterIdV1::ByteMemory
                if self.instance == 0
                    && self.base_width == IO_BASE_WIDTH
                    && self.aux_width == IO_AUX_WIDTH
                    && self.fixed_width == IO_FIXED_WIDTH
                    && self.constraint_count == IO_CONSTRAINT_COUNT
                    && self.constraint_degree == IO_CONSTRAINT_DEGREE => {}
            SegmentAdapterIdV1::StrictDer
                if self.instance == 0
                    && self.trace_log2 == ZK_X509_DER_STARK_TRACE_LOG2_V1
                    && self.active_rows <= ZK_X509_DER_STARK_TRACE_SIZE_V1
                    && self.base_width == ZK_X509_DER_STARK_BASE_WIDTH_V1
                    && self.aux_width == ZK_X509_DER_STARK_AUX_WIDTH_V1
                    && self.fixed_width == ZK_X509_DER_STARK_FIXED_WIDTH_V1
                    && matches!(
                        self.constraint_count,
                        ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1
                            | super::der_stark::ZK_X509_DER_STARK_LOCAL_CONSTRAINT_COUNT_V1
                    )
                    && self.constraint_degree == ZK_X509_DER_STARK_CONSTRAINT_DEGREE_V1 => {}
            SegmentAdapterIdV1::Rfc5280
                if self.instance == 0
                    && self.trace_log2 == ZK_X509_RFC5280_STARK_TRACE_LOG2_V1
                    && self.active_rows <= ZK_X509_RFC5280_STARK_TRACE_SIZE_V1
                    && self.base_width == ZK_X509_RFC5280_STARK_BASE_WIDTH_V1
                    && self.aux_width == ZK_X509_RFC5280_STARK_AUX_WIDTH_V1
                    && self.fixed_width == ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1
                    && self.constraint_count == ZK_X509_RFC5280_LOCAL_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == ZK_X509_RFC5280_STARK_CONSTRAINT_DEGREE_V1 => {}
            SegmentAdapterIdV1::Projection
                if self.instance == 0
                    && self.active_rows == ZK_X509_PROJECTION_TRACE_SIZE_V1
                    && self.base_width == ZK_X509_PROJECTION_BASE_WIDTH_V1
                    && self.aux_width == ZK_X509_PROJECTION_AUX_WIDTH_V1
                    && self.fixed_width == ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1
                    && self.constraint_count == ZK_X509_PROJECTION_STARK_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == ZK_X509_PROJECTION_STARK_CONSTRAINT_DEGREE_V1 => {}
            SegmentAdapterIdV1::Sha256CallBus
                if usize::from(self.instance) < ZK_X509_SHA_SEGMENT_COUNT_V1
                    && self.trace_log2 == ZK_X509_MAX_NATIVE_TRACE_LOG2_V1
                    && self.active_rows
                        == ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1[usize::from(self.instance)]
                    && self.base_width == ZK_X509_SHA_BATCH_BASE_WIDTH_V1
                    && self.aux_width == ZK_X509_SHA_BATCH_AUX_WIDTH_V1
                    && self.fixed_width == ZK_X509_SHA_BATCH_FIXED_WIDTH_V1
                    && self.constraint_count == ZK_X509_SHA_BATCH_LOCAL_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == ZK_X509_SHA_BATCH_CONSTRAINT_DEGREE_V1 => {}
            SegmentAdapterIdV1::CaAccumulator
                if self.instance == 0
                    && self.active_rows == ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1
                    && self.trace_log2 == ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1
                    && self.base_width == ZK_X509_CA_ACCUMULATOR_BASE_WIDTH_V1
                    && self.aux_width == ZK_X509_CA_ACCUMULATOR_AUX_WIDTH_V1
                    && self.fixed_width == ZK_X509_CA_ACCUMULATOR_FIXED_WIDTH_V1
                    && self.constraint_count
                        == ZK_X509_CA_ACCUMULATOR_LOCAL_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1
                    && self.physical_chunks == ZK_X509_CA_ACCUMULATOR_CHUNKS_V1 => {}
            SegmentAdapterIdV1::P256Arithmetic
                if p256_instance_parts_v1(self.instance).is_some_and(|(_, local)| local == 0)
                    && self.trace_log2 == P256_ARITHMETIC_AGGREGATE_TRACE_LOG2_V1
                    && self.active_rows == self.trace_size()
                    && self.base_width == P256_ARITHMETIC_BASE_WIDTH_V1
                    && self.aux_width == P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1
                    && self.fixed_width == P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1
                    && self.constraint_count == P256_ARITHMETIC_REGISTERED_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == P256_ARITHMETIC_STARK_CONSTRAINT_DEGREE_V1 => {}
            SegmentAdapterIdV1::P256Reduction
                if p256_instance_parts_v1(self.instance).is_some_and(|(_, local)| local < 2)
                    && self.trace_log2 == P256_REDUCTION_AGGREGATE_TRACE_LOG2_V1
                    && self.active_rows == self.trace_size()
                    && self.base_width == P256_REDUCTION_BASE_WIDTH_V1
                    && self.aux_width == P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1
                    && self.fixed_width == P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1
                    && self.constraint_count == P256_REDUCTION_REGISTERED_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == 4 => {}
            SegmentAdapterIdV1::P256LowS
                if p256_instance_parts_v1(self.instance)
                    .is_some_and(|(signature, local)| signature == 4 && local == 0)
                    && self.trace_log2 == P256_LOW_S_AGGREGATE_TRACE_LOG2_V1
                    && self.active_rows == self.trace_size()
                    && self.base_width == P256_LOW_S_BASE_WIDTH_V1
                    && self.aux_width == P256_LOW_S_AGGREGATE_AUX_WIDTH_V1
                    && self.fixed_width == P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1
                    && self.constraint_count == P256_LOW_S_REGISTERED_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == 3 => {}
            SegmentAdapterIdV1::P256Window
                if p256_instance_parts_v1(self.instance).is_some_and(|(_, local)| local == 0)
                    && self.trace_log2 == P256_WINDOW_AGGREGATE_TRACE_LOG2_V1
                    && self.active_rows == self.trace_size()
                    && self.base_width == P256_WINDOW_BASE_WIDTH_V1
                    && self.aux_width == P256_WINDOW_AGGREGATE_AUX_WIDTH_V1
                    && self.fixed_width == P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1
                    && self.constraint_count == P256_WINDOW_REGISTERED_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == P256_WINDOW_STARK_CONSTRAINT_DEGREE_V1 => {}
            SegmentAdapterIdV1::P256ValueBus
                if (p256_instance_parts_v1(self.instance).is_some_and(|(_, local)| local == 0)
                    && self.trace_log2 == P256_VALUE_BUS_AGGREGATE_TRACE_LOG2_V1
                    && self.active_rows == self.trace_size()
                    && self.base_width == P256_VALUE_BUS_STARK_BASE_WIDTH_V1
                    && self.aux_width == P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1
                    && self.fixed_width == P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1
                    && self.constraint_count
                        == P256_VALUE_EXECUTION_REGISTERED_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == 3)
                    || (p256_instance_parts_v1(self.instance)
                        .is_some_and(|(_, local)| local == 1)
                        && self.trace_log2 == P256_VALUE_BUS_AGGREGATE_TRACE_LOG2_V1
                        && self.active_rows == self.trace_size()
                        && self.base_width == P256_VALUE_BUS_STARK_BASE_WIDTH_V1
                        && self.aux_width == P256_VALUE_BUS_STARK_AUX_WIDTH_V1
                        && self.fixed_width == P256_VALUE_BUS_STARK_FIXED_WIDTH_V1
                        && self.constraint_count
                            == P256_VALUE_SORTED_REGISTERED_CONSTRAINT_COUNT_V1
                        && self.constraint_degree == P256_VALUE_BUS_STARK_CONSTRAINT_DEGREE_V1)
                    || (p256_instance_parts_v1(self.instance)
                        .is_some_and(|(_, local)| local == 2)
                        && self.trace_log2 == P256_BINDING_SINK_AGGREGATE_TRACE_LOG2_V1
                        && self.active_rows == self.trace_size()
                        && self.base_width == P256_BINDING_SINK_BASE_WIDTH_V1
                        && self.aux_width
                            == super::p256_cross_trace_bus::P256_CROSS_TRACE_SINK_AUX_WIDTH_V1
                        && self.fixed_width == P256_BINDING_SINK_FIXED_WIDTH_V1
                        && self.constraint_count
                            == P256_BINDING_SINK_REGISTERED_CONSTRAINT_COUNT_V1
                        && self.constraint_degree == P256_BINDING_SINK_CONSTRAINT_DEGREE_V1) => {}
            SegmentAdapterIdV1::P256ScalarBitBus
                if p256_instance_parts_v1(self.instance).is_some_and(|(_, local)| local == 0)
                    && self.trace_log2 == P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1
                    && self.active_rows == self.trace_size()
                    && self.base_width == P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1
                    && self.aux_width == P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1
                    && self.fixed_width == P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1
                    && self.constraint_count
                        == P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1
                    && self.constraint_degree == P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_DEGREE_V1 => {
            }
            _ => return Err(ZkX509StarkErrorV1::ProfileMismatch),
        }
        Ok(())
    }
}
#[cfg(test)]
fn canonical_accumulator_segment_layouts_v1()
-> Result<[SegmentLayoutV1; ACCUMULATOR_REGISTRATION_COUNT_V1], ZkX509StarkErrorV1> {
    Ok([SegmentLayoutV1::for_ca_accumulator()?])
}
fn canonical_p256_segment_layouts_for_signature_v1(
    role: P256EcdsaRoleV1,
    signature: usize,
) -> Result<Vec<SegmentLayoutV1>, ZkX509StarkErrorV1> {
    let expected_role = if signature == P256_SIGNATURE_COUNT_V1 - 1 {
        P256EcdsaRoleV1::WalletOwnership
    } else {
        P256EcdsaRoleV1::CertificateOrCrl
    };
    if role != expected_role {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let expected_count = match role {
        P256EcdsaRoleV1::CertificateOrCrl => P256_CERTIFICATE_REGISTRATION_COUNT_V1,
        P256EcdsaRoleV1::WalletOwnership => P256_WALLET_REGISTRATION_COUNT_V1,
    };
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(expected_count)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for instance in 0..2 {
        segments.push(SegmentLayoutV1::for_p256_component(
            SegmentAdapterIdV1::P256Reduction,
            p256_instance_v1(signature, instance)?,
            P256_REDUCTION_AGGREGATE_TRACE_LOG2_V1,
            P256_REDUCTION_BASE_WIDTH_V1,
            P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1,
            P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1,
            P256_REDUCTION_REGISTERED_CONSTRAINT_COUNT_V1,
            4,
        )?);
    }
    if role == P256EcdsaRoleV1::WalletOwnership {
        segments.push(SegmentLayoutV1::for_p256_component(
            SegmentAdapterIdV1::P256LowS,
            p256_instance_v1(signature, 0)?,
            P256_LOW_S_AGGREGATE_TRACE_LOG2_V1,
            P256_LOW_S_BASE_WIDTH_V1,
            P256_LOW_S_AGGREGATE_AUX_WIDTH_V1,
            P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1,
            P256_LOW_S_REGISTERED_CONSTRAINT_COUNT_V1,
            3,
        )?);
    }
    segments.push(SegmentLayoutV1::for_p256_component(
        SegmentAdapterIdV1::P256ScalarBitBus,
        p256_instance_v1(signature, 0)?,
        P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1,
        P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1,
        P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1,
        P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1,
        P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1,
        P256_SCALAR_BIT_BUS_STARK_CONSTRAINT_DEGREE_V1,
    )?);
    segments.push(SegmentLayoutV1::for_p256_component(
        SegmentAdapterIdV1::P256Window,
        p256_instance_v1(signature, 0)?,
        P256_WINDOW_AGGREGATE_TRACE_LOG2_V1,
        P256_WINDOW_BASE_WIDTH_V1,
        P256_WINDOW_AGGREGATE_AUX_WIDTH_V1,
        P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1,
        P256_WINDOW_REGISTERED_CONSTRAINT_COUNT_V1,
        P256_WINDOW_STARK_CONSTRAINT_DEGREE_V1,
    )?);
    segments.push(SegmentLayoutV1::for_p256_component(
        SegmentAdapterIdV1::P256ValueBus,
        p256_instance_v1(signature, 2)?,
        P256_BINDING_SINK_AGGREGATE_TRACE_LOG2_V1,
        P256_BINDING_SINK_BASE_WIDTH_V1,
        super::p256_cross_trace_bus::P256_CROSS_TRACE_SINK_AUX_WIDTH_V1,
        P256_BINDING_SINK_FIXED_WIDTH_V1,
        P256_BINDING_SINK_REGISTERED_CONSTRAINT_COUNT_V1,
        P256_BINDING_SINK_CONSTRAINT_DEGREE_V1,
    )?);
    segments.push(SegmentLayoutV1::for_p256_component(
        SegmentAdapterIdV1::P256Arithmetic,
        p256_instance_v1(signature, 0)?,
        P256_ARITHMETIC_AGGREGATE_TRACE_LOG2_V1,
        P256_ARITHMETIC_BASE_WIDTH_V1,
        P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1,
        P256_ARITHMETIC_AGGREGATE_FIXED_WIDTH_V1,
        P256_ARITHMETIC_REGISTERED_CONSTRAINT_COUNT_V1,
        P256_ARITHMETIC_STARK_CONSTRAINT_DEGREE_V1,
    )?);
    for (instance, aux_width, fixed_width, constraint_count, degree) in [
        (
            0,
            P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1,
            P256_VALUE_EXECUTION_AGGREGATE_FIXED_WIDTH_V1,
            P256_VALUE_EXECUTION_REGISTERED_CONSTRAINT_COUNT_V1,
            3,
        ),
        (
            1,
            P256_VALUE_BUS_STARK_AUX_WIDTH_V1,
            P256_VALUE_BUS_STARK_FIXED_WIDTH_V1,
            P256_VALUE_SORTED_REGISTERED_CONSTRAINT_COUNT_V1,
            P256_VALUE_BUS_STARK_CONSTRAINT_DEGREE_V1,
        ),
    ] {
        segments.push(SegmentLayoutV1::for_p256_component(
            SegmentAdapterIdV1::P256ValueBus,
            p256_instance_v1(signature, instance)?,
            P256_VALUE_BUS_AGGREGATE_TRACE_LOG2_V1,
            P256_VALUE_BUS_STARK_BASE_WIDTH_V1,
            aux_width,
            fixed_width,
            constraint_count,
            degree,
        )?);
    }
    if segments.len() != expected_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(segments)
}
#[cfg(test)]
fn canonical_p256_segment_layouts_v1(
    role: P256EcdsaRoleV1,
) -> Result<Vec<SegmentLayoutV1>, ZkX509StarkErrorV1> {
    let signature = match role {
        P256EcdsaRoleV1::CertificateOrCrl => 0,
        P256EcdsaRoleV1::WalletOwnership => P256_SIGNATURE_COUNT_V1 - 1,
    };
    canonical_p256_segment_layouts_for_signature_v1(role, signature)
}
fn canonical_sha_segment_layouts_v1() -> Result<Vec<SegmentLayoutV1>, ZkX509StarkErrorV1> {
    ZK_X509_SHA_SEGMENT_ACTIVE_ROWS_V1
        .iter()
        .copied()
        .enumerate()
        .map(|(instance, active_rows)| {
            SegmentLayoutV1::for_sha_segment(
                u16::try_from(instance).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                active_rows,
            )
        })
        .collect()
}
/// Reconstruct the sole complete fixed-capacity X5S1 registration.
///
/// Private witness code never supplies an adapter, instance, width, active count, family boundary,
/// order, or padding boundary. Public values affect verifier-fixed input bindings inside these
/// registrations, never the proof container geometry.
fn canonical_full_profile_segment_layouts_v1() -> Result<Vec<SegmentLayoutV1>, ZkX509StarkErrorV1> {
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(FULL_PROFILE_LOGICAL_REGISTRATIONS_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        let role = if signature + 1 == P256_SIGNATURE_COUNT_V1 {
            P256EcdsaRoleV1::WalletOwnership
        } else {
            P256EcdsaRoleV1::CertificateOrCrl
        };
        segments.extend(canonical_p256_segment_layouts_for_signature_v1(
            role, signature,
        )?);
    }
    segments.push(SegmentLayoutV1::for_projection()?);
    segments.push(SegmentLayoutV1::for_full_io()?);
    segments.push(SegmentLayoutV1::for_rfc5280(
        ZK_X509_RFC5280_STARK_TRACE_SIZE_V1,
    )?);
    segments.push(SegmentLayoutV1::for_der_main_v1(
        ZK_X509_DER_STARK_TRACE_SIZE_V1,
    )?);
    segments.extend(canonical_sha_segment_layouts_v1()?);
    segments
        .sort_unstable_by_key(|segment| (segment.trace_log2, segment.adapter, segment.instance));
    if segments.len() != FULL_PROFILE_LOGICAL_REGISTRATIONS_V1
        || segments.windows(2).any(|pair| {
            (pair[0].trace_log2, pair[0].adapter, pair[0].instance)
                >= (pair[1].trace_log2, pair[1].adapter, pair[1].instance)
        })
        || segments.iter().try_fold(0_usize, |chunks, segment| {
            chunks
                .checked_add(segment.column_chunks()?)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
        })? != FULL_PROFILE_PHYSICAL_CHUNKS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(segments)
}
/// One canonical trace-commitment group in the aggregate proof.
///
/// Segments with the same native trace size share one vector-row Merkle
/// commitment. Every group is evaluated on the proof's common LDE domain;
/// `next_stride` is therefore derived, never supplied by the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TraceGroupLayoutV1 {
    native_trace_log2: u8,
    /// Number of 64-column commitment-budget chunks, not logical adapters.
    column_chunks: usize,
    base_width: usize,
    aux_width: usize,
}
impl TraceGroupLayoutV1 {
    fn as_shared(self) -> aggregate::AggregateTraceGroupLayoutV1 {
        aggregate::AggregateTraceGroupLayoutV1 {
            native_trace_log2: self.native_trace_log2,
            segment_instances: self.column_chunks,
            base_width: self.base_width,
            aux_width: self.aux_width,
        }
    }
    #[cfg(test)]
    fn next_stride(self, common_lde_log2: u8) -> Result<usize, ZkX509StarkErrorV1> {
        self.as_shared()
            .next_stride(common_lde_log2)
            .map_err(map_aggregate_error_v1)
    }
}
/// One logical adapter's verifier-derived slices inside a trace-group row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegisteredSegmentLayoutV1 {
    segment: SegmentLayoutV1,
    trace_group: usize,
    base_start: usize,
    aux_start: usize,
    column_chunks: usize,
}
impl RegisteredSegmentLayoutV1 {
    fn base_end(self) -> Result<usize, ZkX509StarkErrorV1> {
        self.base_start
            .checked_add(self.segment.base_width)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    fn aux_end(self) -> Result<usize, ZkX509StarkErrorV1> {
        self.aux_start
            .checked_add(self.segment.aux_width)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
}
/// Verifier-derived aggregate commitment and FRI layout.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AggregateProofLayoutV1 {
    common_lde_log2: u8,
    trace_groups: Vec<TraceGroupLayoutV1>,
    registered_segments: Vec<RegisteredSegmentLayoutV1>,
}
impl AggregateProofLayoutV1 {
    #[cfg(test)]
    fn for_segments(layouts: &[SegmentLayoutV1]) -> Result<Self, ZkX509StarkErrorV1> {
        Self::for_segments_with_equal_log_bucketing_v1(layouts, false)
    }
    fn for_equal_log_buckets_v1(layouts: &[SegmentLayoutV1]) -> Result<Self, ZkX509StarkErrorV1> {
        Self::for_segments_with_equal_log_bucketing_v1(layouts, true)
    }
    fn for_segments_with_equal_log_bucketing_v1(
        layouts: &[SegmentLayoutV1],
        bucket_equal_logs: bool,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        if layouts.is_empty() || layouts.len() > FULL_PROFILE_LOGICAL_REGISTRATIONS_V1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut previous_key = None;
        for layout in layouts {
            layout.validate()?;
            let key = (layout.trace_log2, layout.adapter, layout.instance);
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            previous_key = Some(key);
        }
        // Most focused single-adapter proofs retain independent groups. A
        // role-local composite such as one P-256 signature deterministically
        // buckets equal native logarithms so a single vector-row commitment
        // owns disjoint verifier-fixed slices for every logical adapter.
        let mut trace_groups = Vec::with_capacity(layouts.len());
        let mut registered_segments = Vec::with_capacity(layouts.len());
        for segment in layouts.iter().copied() {
            let column_chunks = segment.column_chunks()?;
            let trace_group = if bucket_equal_logs
                && trace_groups
                    .last()
                    .is_some_and(|group: &TraceGroupLayoutV1| {
                        group.native_trace_log2 == segment.trace_log2
                    }) {
                trace_groups.len() - 1
            } else {
                trace_groups.push(TraceGroupLayoutV1 {
                    native_trace_log2: segment.trace_log2,
                    column_chunks: 0,
                    base_width: 0,
                    aux_width: 0,
                });
                trace_groups.len() - 1
            };
            let group = trace_groups
                .get_mut(trace_group)
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
            let base_start = group.base_width;
            let aux_start = group.aux_width;
            group.base_width = group
                .base_width
                .checked_add(segment.base_width)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            group.aux_width = group
                .aux_width
                .checked_add(segment.aux_width)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            group.column_chunks = group
                .column_chunks
                .checked_add(column_chunks)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            registered_segments.push(RegisteredSegmentLayoutV1 {
                segment,
                trace_group,
                base_start,
                aux_start,
                column_chunks,
            });
        }
        let maximum_native_log2 = trace_groups
            .last()
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .native_trace_log2;
        let compact_ca =
            layouts.len() == 1 && layouts[0].adapter == SegmentAdapterIdV1::CaAccumulator;
        let common_lde_log2 = if compact_ca {
            layouts[0].lde_log2
        } else {
            maximum_native_log2
                .checked_add(BLOWUP_LOG2)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
        };
        let layout = Self {
            common_lde_log2,
            trace_groups,
            registered_segments,
        };
        layout.validate()?;
        Ok(layout)
    }
    #[cfg(test)]
    fn for_accumulators_v1() -> Result<Self, ZkX509StarkErrorV1> {
        let layout = Self::for_segments(&canonical_accumulator_segment_layouts_v1()?)?;
        layout.validate_accumulator_registration_v1()?;
        Ok(layout)
    }
    #[cfg(test)]
    fn for_p256_v1(role: P256EcdsaRoleV1) -> Result<Self, ZkX509StarkErrorV1> {
        let layout = Self::for_equal_log_buckets_v1(&canonical_p256_segment_layouts_v1(role)?)?;
        layout.validate_p256_registration_v1(role)?;
        Ok(layout)
    }
    fn for_full_profile_v1() -> Result<Self, ZkX509StarkErrorV1> {
        let segments = canonical_full_profile_segment_layouts_v1()?;
        let layout = Self::for_equal_log_buckets_v1(&segments)?;
        layout.validate_exact_full_profile_registration_v1()?;
        Ok(layout)
    }
    fn registered_segment(
        &self,
        adapter: SegmentAdapterIdV1,
        instance: u16,
    ) -> Result<RegisteredSegmentLayoutV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .registered_segments
            .iter()
            .copied()
            .filter(|registration| {
                registration.segment.adapter == adapter && registration.segment.instance == instance
            });
        let registration = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(registration)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn common_lde_size(&self) -> usize {
        1_usize << self.common_lde_log2
    }
    #[cfg(test)]
    fn fri_rounds(&self) -> usize {
        usize::from(self.common_lde_log2 - self.parameters_v1().terminal_log2)
    }
    fn parameters_v1(&self) -> aggregate::AggregateStarkParametersV1 {
        if self.registered_segments.len() == 1
            && self.registered_segments[0].segment.adapter == SegmentAdapterIdV1::CaAccumulator
        {
            CA_AGGREGATE_PARAMETERS_V1
        } else {
            AGGREGATE_PARAMETERS_V1
        }
    }
    fn as_shared(&self) -> Result<aggregate::AggregateProofLayoutV1, ZkX509StarkErrorV1> {
        let parameters = self.parameters_v1();
        let trace_layout = if self.registered_segments.len() == 49
            && self.trace_groups.len() == FULL_PROFILE_TRACE_GROUPS_V1
        {
            aggregate::AggregateTraceLayoutV1::JoinedCurrent
        } else if self.registered_segments.len() == 1
            && matches!(
                self.registered_segments[0].segment.adapter,
                SegmentAdapterIdV1::CaAccumulator | SegmentAdapterIdV1::StrictDer
            )
        {
            // Both relations check every constraint at the authenticated DEEP point.
            aggregate::AggregateTraceLayoutV1::GroupedCurrent
        } else {
            // Other isolated AIR fixtures retain the ordinary full-row layout.
            aggregate::AggregateTraceLayoutV1::GroupedCurrentNext
        };
        let shared = aggregate::AggregateProofLayoutV1::new_with_trace_layout_v1(
            parameters,
            self.trace_groups
                .iter()
                .copied()
                .map(TraceGroupLayoutV1::as_shared)
                .collect(),
            trace_layout,
        )
        .map_err(map_aggregate_error_v1)?;
        if shared.common_lde_log2() != self.common_lde_log2 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(shared)
    }
    fn validate(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.as_shared()?;
        if self.registered_segments.is_empty() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut previous_key = None;
        let mut next_base = vec![0_usize; self.trace_groups.len()];
        let mut next_aux = vec![0_usize; self.trace_groups.len()];
        let mut chunks = vec![0_usize; self.trace_groups.len()];
        for registration in &self.registered_segments {
            registration.segment.validate()?;
            if registration.segment.adapter == SegmentAdapterIdV1::CaAccumulator {
                checked_compact_ca_degree_capacity_v1(
                    registration.segment.trace_log2,
                    self.common_lde_log2,
                    registration.segment.constraint_degree,
                )?;
            } else {
                checked_segment_degree_capacity_v1(
                    registration.segment.trace_log2,
                    self.common_lde_log2,
                    registration.segment.constraint_degree,
                )?;
            }
            let key = (
                registration.segment.trace_log2,
                registration.segment.adapter,
                registration.segment.instance,
            );
            if previous_key.is_some_and(|previous| previous >= key)
                || registration.trace_group >= self.trace_groups.len()
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let group = self.trace_groups[registration.trace_group];
            if group.native_trace_log2 != registration.segment.trace_log2
                || registration.base_start != next_base[registration.trace_group]
                || registration.aux_start != next_aux[registration.trace_group]
                || registration.column_chunks != registration.segment.column_chunks()?
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            next_base[registration.trace_group] = registration.base_end()?;
            next_aux[registration.trace_group] = registration.aux_end()?;
            chunks[registration.trace_group] = chunks[registration.trace_group]
                .checked_add(registration.column_chunks)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            previous_key = Some(key);
        }
        if self
            .trace_groups
            .iter()
            .zip(next_base)
            .zip(next_aux)
            .zip(chunks)
            .any(|(((group, base), aux), chunks)| {
                group.base_width != base || group.aux_width != aux || group.column_chunks != chunks
            })
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    fn validate_full_profile_registration(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.validate()?;
        if REQUIRED_FULL_PROFILE_ADAPTERS_V1.iter().any(|required| {
            !self
                .registered_segments
                .iter()
                .any(|registration| registration.segment.adapter == *required)
        }) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        if self.registered_segments.len() != FULL_PROFILE_LOGICAL_REGISTRATIONS_V1
            || self.trace_groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || self
                .trace_groups
                .iter()
                .try_fold(0_usize, |chunks, group| {
                    chunks
                        .checked_add(group.column_chunks)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
                })?
                != FULL_PROFILE_PHYSICAL_CHUNKS_V1
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    fn validate_exact_full_profile_registration_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.validate_full_profile_registration()?;
        let expected =
            Self::for_equal_log_buckets_v1(&canonical_full_profile_segment_layouts_v1()?)?;
        if self != &expected {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    fn validate_accumulator_instance_set_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.validate()?;
        let expected_segments = canonical_accumulator_segment_layouts_v1()?;
        let mut accumulator_registrations = [None; ACCUMULATOR_REGISTRATION_COUNT_V1];
        let mut count = 0_usize;
        for registration in self
            .registered_segments
            .iter()
            .copied()
            .filter(|registration| {
                registration.segment.adapter == SegmentAdapterIdV1::CaAccumulator
            })
        {
            let slot = accumulator_registrations
                .get_mut(count)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            *slot = Some(registration);
            count += 1;
        }
        if count != ACCUMULATOR_REGISTRATION_COUNT_V1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut previous_group = None;
        for (registration, expected) in accumulator_registrations.into_iter().zip(expected_segments)
        {
            let registration = registration.ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            let group = self.trace_groups.get(registration.trace_group);
            if previous_group.is_some_and(|previous| previous >= registration.trace_group)
                || registration.segment != expected
                || registration.base_start != 0
                || registration.aux_start != 0
                || group.is_none_or(|group| {
                    let native_trace_log2 = group.native_trace_log2;
                    native_trace_log2 != expected.trace_log2
                        || group.base_width != expected.base_width
                        || group.aux_width != expected.aux_width
                        || group.column_chunks != registration.column_chunks
                })
                || self
                    .registered_segments
                    .iter()
                    .filter(|candidate| candidate.trace_group == registration.trace_group)
                    .count()
                    != 1
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            previous_group = Some(registration.trace_group);
        }
        Ok(())
    }
    #[cfg(test)]
    fn validate_accumulator_registration_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.validate_accumulator_instance_set_v1()?;
        let expected = Self::for_segments(&canonical_accumulator_segment_layouts_v1()?)?;
        if self != &expected {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    fn validate_p256_instance_set_v1(
        &self,
        role: P256EcdsaRoleV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        self.validate()?;
        let expected_segments = canonical_p256_segment_layouts_v1(role)?;
        let registrations = self
            .registered_segments
            .iter()
            .copied()
            .filter(|registration| {
                matches!(
                    registration.segment.adapter,
                    SegmentAdapterIdV1::P256Arithmetic
                        | SegmentAdapterIdV1::P256Reduction
                        | SegmentAdapterIdV1::P256LowS
                        | SegmentAdapterIdV1::P256Window
                        | SegmentAdapterIdV1::P256ValueBus
                        | SegmentAdapterIdV1::P256ScalarBitBus
                )
            })
            .collect::<Vec<_>>();
        if registrations.len() != expected_segments.len() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        for (registration, expected) in registrations.into_iter().zip(expected_segments) {
            if registration.segment != expected {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn validate_p256_registration_v1(
        &self,
        role: P256EcdsaRoleV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        self.validate_p256_instance_set_v1(role)?;
        let expected = Self::for_equal_log_buckets_v1(&canonical_p256_segment_layouts_v1(role)?)?;
        if self != &expected {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
}
/// Publicly inspectable census of the sole first-release MAIN registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509MainRegistrationShapeV1 {
    /// Exact logical adapter registrations.
    pub(crate) logical_registrations: usize,
    /// Exact equal-native-log trace groups.
    pub(crate) trace_groups: usize,
    /// Exact 64-column commitment chunks.
    pub(crate) physical_chunks: usize,
}
/// Reconstruct and validate the exact 49-registration MAIN topology.
///
/// This is intentionally verifier-owned and accepts no witness-dependent dimensions. MAIN assembly
/// calls it before handing material to the aggregate prover.
pub fn validate_zk_x509_main_registration_shape_v1()
-> Result<ZkX509MainRegistrationShapeV1, ZkX509StarkErrorV1> {
    let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
    let physical_chunks = layout.trace_groups.iter().try_fold(0_usize, |sum, group| {
        sum.checked_add(group.column_chunks)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    })?;
    let shape = ZkX509MainRegistrationShapeV1 {
        logical_registrations: layout.registered_segments.len(),
        trace_groups: layout.trace_groups.len(),
        physical_chunks,
    };
    if shape.logical_registrations != FULL_PROFILE_LOGICAL_REGISTRATIONS_V1
        || shape.trace_groups != FULL_PROFILE_TRACE_GROUPS_V1
        || shape.physical_chunks != FULL_PROFILE_PHYSICAL_CHUNKS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(shape)
}
/// Expected successful MAIN common-domain FFT column count for diagnostic coverage.
#[cfg(test)]
pub(super) fn main_diagnostic_transform_columns_v1() -> Result<usize, ZkX509StarkErrorV1> {
    let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
    Ok(2 * layout
        .trace_groups
        .iter()
        .map(|group| group.base_width + group.aux_width)
        .sum::<usize>())
}
/// Complete verifier-owned first-release MAIN profile.
///
/// The registration census and sole 29-field compiled-profile digest are
/// constructed together. Fixed rows are evaluated from the manifest-bound
/// algebraic schedules and never selected by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509MainVerifierProfileV1 {
    /// Exact 49-registration topology.
    pub(crate) registration: ZkX509MainRegistrationShapeV1,
    /// Digest of the complete 29-field algebraic release manifest.
    pub(crate) compiled_profile_digest: [u8; 32],
}
/// Construct the sole MAIN verifier profile from independently pinned release material.
pub fn construct_zk_x509_main_verifier_profile_v1()
-> Result<ZkX509MainVerifierProfileV1, ZkX509StarkErrorV1> {
    let registration = validate_zk_x509_main_registration_shape_v1()?;
    let compiled =
        construct_zk_x509_compiled_profile_v1().map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    Ok(ZkX509MainVerifierProfileV1 {
        registration,
        compiled_profile_digest: compiled.digest(),
    })
}
/// Reject any supplied MAIN profile that differs from the verifier-owned release pins.
pub fn validate_zk_x509_main_verifier_profile_v1(
    supplied: ZkX509MainVerifierProfileV1,
) -> Result<(), ZkX509StarkErrorV1> {
    let expected = construct_zk_x509_main_verifier_profile_v1()?;
    if supplied.registration != expected.registration
        || supplied.compiled_profile_digest != expected.compiled_profile_digest
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Reject a full MAIN proof whose fixed opening schedule exceeds its X5S1 budget.
///
/// Registration and fixed-polynomial diagnostics remain independently usable.
/// Proof construction must pass this bounded geometry check before any entropy
/// is consumed or a commitment is emitted.
pub fn validate_zk_x509_main_proof_budget_v1() -> Result<(), ZkX509StarkErrorV1> {
    let layout = AggregateProofLayoutV1::for_full_profile_v1()?;
    let inner_bytes = aggregate::maximum_encoded_proof_with_deep_bytes_v1(
        AGGREGATE_PARAMETERS_V1,
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)?;
    let encoded_bytes = inner_bytes
        .checked_add(super::profile::ZK_X509_MAIN_FRAME_BYTES_V1 as usize)
        .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
    if encoded_bytes > super::credential_stark::ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    Ok(())
}
#[cfg(test)]
/// Verifier-derived fixed rows are evaluated only after MAIN grinding and
/// query derivation. Construction is private so a caller cannot substitute a
/// query set, schedule digest, or fixed row.
const MAIN_LOG19_QUERY_SCHEDULE_DOMAIN_V1: &[u8] = b"iroha.zk-x509.main.log19-query-schedule.v1";
/// Transcript-order current/next pairs for MAIN's native-log19 group.
///
/// The canonical sorted-unique union is used by both algebraic evaluators,
/// while the ordered pairs retain transcript order and current/next pairing.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct MainLog19VerifierQueryScheduleV1 {
    pairs: [(usize, usize); QUERY_COUNT],
    indices: Vec<u64>,
    order_digest: PrivacyOuterDigestV1,
}
#[cfg(test)]
fn main_log19_query_schedule_digest_v1(
    pairs: &[(usize, usize); QUERY_COUNT],
) -> Result<PrivacyOuterDigestV1, ZkX509StarkErrorV1> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(QUERY_COUNT * 2 * core::mem::size_of::<u64>())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for (current, next) in pairs {
        encoded.extend_from_slice(
            &u64::try_from(*current)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(
            &u64::try_from(*next)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?
                .to_be_bytes(),
        );
    }
    privacy_outer_digest_frame_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        MAIN_LOG19_QUERY_SCHEDULE_DOMAIN_V1,
        b"ordered-current-next-query-schedule",
        0,
        0,
        0,
        &[&encoded],
    )
    .map_err(map_transparent_error_v1)
}
#[cfg(test)]
impl MainLog19VerifierQueryScheduleV1 {
    fn from_query_coordinates_v1(query_coordinates: &[usize]) -> Result<Self, ZkX509StarkErrorV1> {
        let query_coordinates: [usize; QUERY_COUNT] = query_coordinates
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::TraceOpening)?;
        let common_lde_size = 1_usize
            .checked_shl(u32::from(ZK_X509_MAIN_COMMON_LDE_LOG2_V1))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let mut sorted_current = query_coordinates;
        sorted_current.sort_unstable();
        if sorted_current
            .windows(2)
            .any(|pair| pair.first() == pair.get(1))
        {
            return Err(ZkX509StarkErrorV1::TraceOpening);
        }
        let mut pairs = [(0_usize, 0_usize); QUERY_COUNT];
        let mut indices = Vec::new();
        indices
            .try_reserve_exact(VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for (target, current) in pairs.iter_mut().zip(query_coordinates) {
            if current >= common_lde_size {
                return Err(ZkX509StarkErrorV1::TraceOpening);
            }
            let next = current
                .checked_add(P256_MAIN_LOG19_NEXT_STRIDE_V1)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
                % common_lde_size;
            *target = (current, next);
            indices.push(u64::try_from(current).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?);
            indices.push(u64::try_from(next).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?);
        }
        indices.sort_unstable();
        indices.dedup();
        if indices.is_empty()
            || indices.len() > VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1
            || indices.len() > ZK_X509_FIXED_ALGEBRAIC_MAX_QUERIES_V1
        {
            return Err(ZkX509StarkErrorV1::TraceOpening);
        }
        let order_digest = main_log19_query_schedule_digest_v1(&pairs)?;
        Ok(Self {
            pairs,
            indices,
            order_digest,
        })
    }
    fn validate_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        let query_coordinates = self.pairs.map(|(current, _)| current);
        let expected = Self::from_query_coordinates_v1(&query_coordinates)?;
        if self != &expected {
            return Err(ZkX509StarkErrorV1::TraceOpening);
        }
        Ok(())
    }
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ZkX509MainVerifierDerivedFixedOpeningsV1 {
    query_schedule: MainLog19VerifierQueryScheduleV1,
    sha: ZkX509FixedAlgebraicOpeningsV1,
    p256_log19: ZkX509FixedAlgebraicOpeningsV1,
}
#[cfg(test)]
fn derive_zk_x509_main_fixed_openings_after_profile_validation_v1(
    sha_shape: ZkX509ShaCallPublicShapeV1,
    query_coordinates: &[usize],
) -> Result<ZkX509MainVerifierDerivedFixedOpeningsV1, ZkX509StarkErrorV1> {
    let query_schedule =
        MainLog19VerifierQueryScheduleV1::from_query_coordinates_v1(query_coordinates)?;
    let sha_schedule = zk_x509_sha_fixed_algebraic_schedule_v1(sha_shape)
        .map_err(map_sha_fixed_algebraic_error_v1)?;
    let p256_schedule =
        zk_x509_p256_fixed_algebraic_schedule_v1().map_err(map_p256_fixed_algebraic_error_v1)?;
    let sha = sha_schedule
        .evaluate_query_indices_v1(&query_schedule.indices)
        .map_err(map_fixed_algebraic_error_v1)?;
    let p256_log19 = p256_schedule
        .evaluate_query_indices_v1(&query_schedule.indices)
        .map_err(map_fixed_algebraic_error_v1)?;
    if sha.query_indices_v1() != query_schedule.indices.as_slice()
        || p256_log19.query_indices_v1() != query_schedule.indices.as_slice()
        || sha.schedule_digest_v1() != sha_schedule.descriptor_digest_v1()
        || p256_log19.schedule_digest_v1() != p256_schedule.descriptor_digest_v1()
        || usize::from(sha.width_v1()) != ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1
        || usize::from(p256_log19.width_v1()) != ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(ZkX509MainVerifierDerivedFixedOpeningsV1 {
        query_schedule,
        sha,
        p256_log19,
    })
}
/// A single joined root binds every column of the six native MAIN groups
/// before the joint credential transcript can issue auxiliary challenges.
struct ZkX509MainBaseCommitmentSessionV1 {
    proof_instance: ZkX509ProofInstanceV1,
    layout: AggregateProofLayoutV1,
    consensus_context_digest: [u8; 32],
    main_profile_digest: [u8; 32],
    root: Option<PrivacyOuterDigestV1>,
}
/// Type-level proof that the complete ordered MAIN base row was committed.
pub(super) struct ZkX509CompletedMainBaseCommitmentSessionV1 {
    proof_instance: ZkX509ProofInstanceV1,
    consensus_context_digest: [u8; 32],
    main_profile_digest: [u8; 32],
    root: PrivacyOuterDigestV1,
}
impl ZkX509CompletedMainBaseCommitmentSessionV1 {
    pub(super) fn into_pre_aux_parts_v1(
        self,
    ) -> (
        ZkX509ProofInstanceV1,
        [u8; 32],
        [u8; 32],
        [PrivacyOuterDigestV1; ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1],
    ) {
        (
            self.proof_instance,
            self.consensus_context_digest,
            self.main_profile_digest,
            [self.root],
        )
    }
}
impl ZkX509MainBaseCommitmentSessionV1 {
    fn new_v1(
        proof_instance: ZkX509ProofInstanceV1,
        layout: &AggregateProofLayoutV1,
        consensus_context_digest: [u8; 32],
        verifier_profile: ZkX509MainVerifierProfileV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_zk_x509_main_verifier_profile_v1(verifier_profile)?;
        Self::new_after_profile_validation_v1(
            proof_instance,
            layout,
            consensus_context_digest,
            verifier_profile.compiled_profile_digest,
        )
    }
    /// Private chronology initialization after release-profile validation.
    fn new_after_profile_validation_v1(
        proof_instance: ZkX509ProofInstanceV1,
        layout: &AggregateProofLayoutV1,
        consensus_context_digest: [u8; 32],
        main_profile_digest: [u8; 32],
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let session = Self {
            proof_instance,
            layout: layout.clone(),
            consensus_context_digest,
            main_profile_digest,
            root: None,
        };
        session.validate_state_v1()?;
        Ok(session)
    }
    fn validate_state_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.layout.validate_exact_full_profile_registration_v1()?;
        if self.layout.trace_groups.len() != FULL_PROFILE_TRACE_GROUPS_V1
            || self
                .layout
                .trace_groups
                .iter()
                .map(|group| group.native_trace_log2)
                .ne(MAIN_BASE_COMMITMENT_NATIVE_LOGS_V1)
            || self.layout.as_shared()?.trace_commitment_count_v1()
                != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1
            || self.consensus_context_digest == [0; 32]
            || self.main_profile_digest == [0; 32]
            || self.root == Some(PrivacyOuterDigestV1::default())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
    fn accept_joined_base_root_v1(
        &mut self,
        root: PrivacyOuterDigestV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        self.validate_state_v1()?;
        if self.root.is_some() || root == PrivacyOuterDigestV1::default() {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        self.root = Some(root);
        Ok(())
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn accept_streaming_base_commitment_v1(
        &mut self,
        commitment: &aggregate::StreamingRowCommitmentResultV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        self.accept_joined_base_root_v1(commitment.commitment.root)
    }
    fn accept_decoded_base_groups_v1(
        &mut self,
        groups: &[TraceGroupProofV1],
    ) -> Result<(), ZkX509StarkErrorV1> {
        self.validate_state_v1()?;
        if groups.len() != ZK_X509_CREDENTIAL_MAIN_BASE_ROOT_COUNT_V1 {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        self.accept_joined_base_root_v1(groups[0].base_root)
    }
    fn complete_v1(self) -> Result<ZkX509CompletedMainBaseCommitmentSessionV1, ZkX509StarkErrorV1> {
        self.validate_state_v1()?;
        let root = self.root.ok_or(ZkX509StarkErrorV1::TranscriptMismatch)?;
        Ok(ZkX509CompletedMainBaseCommitmentSessionV1 {
            proof_instance: self.proof_instance,
            consensus_context_digest: self.consensus_context_digest,
            main_profile_digest: self.main_profile_digest,
            root,
        })
    }
    fn finish_pre_aux_v1(self) -> Result<ZkX509CredentialMainPreAuxV1, ZkX509StarkErrorV1> {
        Ok(ZkX509CredentialMainPreAuxV1::from_completed_main_base_session_v1(self.complete_v1()?))
    }
}
#[cfg(test)]
#[derive(Clone)]
struct IoTraceMaterialV1 {
    layout: SegmentLayoutV1,
    /// Statement-compiled non-padding prefix; independent of the fixed MAIN
    /// registration extent carried by `layout.active_rows`.
    logical_active_rows: usize,
    base_columns: Vec<Vec<F>>,
    aux_columns: Vec<Vec<F>>,
    fixed_columns: Vec<Vec<F>>,
}
#[cfg(test)]
impl Drop for IoTraceMaterialV1 {
    fn drop(&mut self) {
        zeroize_field_rows_v1(&mut self.base_columns);
        zeroize_field_rows_v1(&mut self.aux_columns);
    }
}
#[cfg(test)]
#[derive(Clone)]
struct ProjectionTraceMaterialV1 {
    layout: SegmentLayoutV1,
    base_columns: Vec<Vec<F>>,
    aux_columns: Vec<Vec<F>>,
    fixed_columns: Vec<Vec<F>>,
}
/// Verifier-derived registration for one complete, one-signature P-256 AIR.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
struct P256TraceRegistrationV1 {
    role: P256EcdsaRoleV1,
    layout: AggregateProofLayoutV1,
}
#[cfg(test)]
impl P256TraceRegistrationV1 {
    fn new_v1(role: P256EcdsaRoleV1) -> Result<Self, ZkX509StarkErrorV1> {
        let registration = Self {
            role,
            layout: AggregateProofLayoutV1::for_p256_v1(role)?,
        };
        registration.validate()?;
        Ok(registration)
    }
    fn validate(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.layout.validate_p256_registration_v1(self.role)
    }
}
/// Four independent post-base-commitment P-256 challenge families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P256AggregateChallengesV1 {
    value: P256ValueBusChallengesV1,
    cross: P256CrossTraceChallengesV1,
    scalar: P256ScalarBitBusChallengesV1,
    arithmetic_copy: P256ArithmeticCopyChallengesV1,
}
impl P256AggregateChallengesV1 {
    fn validate(self) -> Result<(), ZkX509StarkErrorV1> {
        self.value
            .validate()
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        self.cross
            .validate()
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        self.scalar
            .validate_v1()
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        self.arithmetic_copy
            .validate_v1()
            .map_err(ZkX509StarkErrorV1::from)
    }
}
#[cfg(test)]
fn derive_p256_aggregate_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<P256AggregateChallengesV1, ZkX509StarkErrorV1> {
    let challenges = P256AggregateChallengesV1 {
        value: derive_zk_x509_p256_value_bus_challenges_v1(transcript)
            .map_err(map_transparent_error_v1)?,
        cross: derive_zk_x509_p256_cross_trace_challenges_v1(transcript)
            .map_err(map_transparent_error_v1)?,
        scalar: derive_zk_x509_p256_scalar_bit_bus_challenges_v1(transcript)
            .map_err(map_transparent_error_v1)?,
        arithmetic_copy: derive_p256_arithmetic_copy_challenges_v1(transcript)
            .map_err(map_transparent_error_v1)?,
    };
    challenges.validate()?;
    Ok(challenges)
}
/// Proof-encoded P-256 product terminals in their sole legal role order.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct P256TerminalRegistrationV1 {
    buses: P256BusTerminalClaimsV1,
    cross_sources: Vec<P256CrossTraceTerminalClaimV1>,
    sink: [F; P256_CROSS_TRACE_LANES_V1],
}
#[cfg(test)]
impl P256TerminalRegistrationV1 {
    fn validate(&self, role: P256EcdsaRoleV1) -> Result<(), ZkX509StarkErrorV1> {
        let bus_residues = evaluate_p256_bus_terminal_claim_equalities_v1(self.buses)
            .map_err(ZkX509StarkErrorV1::from)?;
        let cross_residues = evaluate_p256_cross_trace_terminal_claim_equalities_v1(
            role,
            &self.cross_sources,
            self.sink,
        )
        .map_err(ZkX509StarkErrorV1::from)?;
        if bus_residues
            .iter()
            .chain(&cross_residues)
            .any(|residue| *residue != F::ZERO)
        {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(())
    }
}
#[cfg(test)]
impl Drop for P256TerminalRegistrationV1 {
    fn drop(&mut self) {
        zeroize_p256_terminal_registration_v1(self);
    }
}
/// Verifier-side P-256 fixed openings paired with the proof terminal envelope.
///
/// Native base and auxiliary columns are streamed by the providers in
/// `p256_aggregate_adapter`; retaining only these sampled verifier-derived
/// rows keeps verification bounded independently of the million-row value bus.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
struct P256OpenedMaterialV1 {
    registration: P256TraceRegistrationV1,
    terminals: P256TerminalRegistrationV1,
    fixed_openings: Vec<BTreeMap<usize, Vec<F>>>,
}
#[cfg(test)]
impl P256OpenedMaterialV1 {
    fn validate(&self) -> Result<(), ZkX509StarkErrorV1> {
        self.registration.validate()?;
        self.terminals.validate(self.registration.role)?;
        if self.fixed_openings.len() != self.registration.layout.registered_segments.len()
            || self
                .fixed_openings
                .iter()
                .zip(&self.registration.layout.registered_segments)
                .any(|(openings, registration)| {
                    openings.is_empty()
                        || openings
                            .values()
                            .any(|row| row.len() != registration.segment.fixed_width)
                })
        {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ZkX509SegmentedStarkProofV1 {
    aggregate: aggregate::AggregateStarkProofV1,
    deep: aggregate::AggregateDeepProofV1,
}
impl core::ops::Deref for ZkX509SegmentedStarkProofV1 {
    type Target = aggregate::AggregateStarkProofV1;
    fn deref(&self) -> &Self::Target {
        &self.aggregate
    }
}
impl core::ops::DerefMut for ZkX509SegmentedStarkProofV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.aggregate
    }
}
type TraceGroupProofV1 = aggregate::AggregateTraceGroupProofV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
type FriLaneProofV1 = aggregate::AggregateFriLaneProofV1;
#[cfg(test)]
type FriLaneMaterialV1 = aggregate::AggregateFriLaneMaterialV1;
fn role_field_v1(role: ZkX509IoSegmentRoleV1) -> F {
    F(match role {
        ZkX509IoSegmentRoleV1::StrictDer => 1,
        ZkX509IoSegmentRoleV1::Sha256 => 2,
        ZkX509IoSegmentRoleV1::P256 => 3,
        ZkX509IoSegmentRoleV1::CaAccumulator => 4,
        #[cfg(test)]
        ZkX509IoSegmentRoleV1::CrlCommitment => 5,
        ZkX509IoSegmentRoleV1::Projection => 6,
        ZkX509IoSegmentRoleV1::PublicInput => 7,
    })
}
fn io_active_rows_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
) -> Result<usize, ZkX509StarkErrorV1> {
    declarations.iter().try_fold(0_usize, |rows, declaration| {
        let endpoints = declaration
            .consumers
            .len()
            .checked_add(1)
            .ok_or(ZkX509StarkErrorV1::InvalidStatement)?;
        let bytes = usize::try_from(declaration.byte_len)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        rows.checked_add(
            endpoints
                .checked_mul(bytes)
                .ok_or(ZkX509StarkErrorV1::InvalidStatement)?,
        )
        .ok_or(ZkX509StarkErrorV1::InvalidStatement)
    })
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn access_base_fields_v1(access: IoAccessV1, row: &mut [F], offset: usize, bits: usize) {
    row[offset] = access.channel;
    row[offset + 1] = access.offset;
    row[offset + 2] = access.value;
    row[offset + 3] = access.is_write;
    row[offset + 4] = role_field_v1(access.endpoint.role);
    row[offset + 5] = F(u64::from(access.endpoint.instance));
    for bit in 0..8 {
        row[bits + bit] = F((access.value.0 >> bit) & 1);
    }
}
#[cfg(test)]
fn access_fixed_fields_v1(access: IoAccessV1, row: &mut [F], offset: usize) {
    row[offset] = access.channel;
    row[offset + 1] = access.offset;
    row[offset + 2] = access.is_write;
    row[offset + 3] = role_field_v1(access.endpoint.role);
    row[offset + 4] = F(u64::from(access.endpoint.instance));
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MainIoAccessTopologyV1 {
    channel: F,
    offset: F,
    is_write: F,
    role: F,
    instance: F,
}
impl MainIoAccessTopologyV1 {
    fn new_v1(
        channel: u32,
        offset: usize,
        is_write: bool,
        endpoint: ZkX509IoEndpointV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        Ok(Self {
            channel: F(u64::from(channel)),
            offset: F(u64::try_from(offset).map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?),
            is_write: if is_write { F::ONE } else { F::ZERO },
            role: role_field_v1(endpoint.role),
            instance: F(u64::from(endpoint.instance)),
        })
    }
    fn write_fixed_fields_v1(self, row: &mut [F], offset: usize) {
        row[offset] = self.channel;
        row[offset + 1] = self.offset;
        row[offset + 2] = self.is_write;
        row[offset + 3] = self.role;
        row[offset + 4] = self.instance;
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn matches_access_v1(self, access: IoAccessV1) -> bool {
        self.channel == access.channel
            && self.offset == access.offset
            && self.is_write == access.is_write
            && self.role == role_field_v1(access.endpoint.role)
            && self.instance == F(u64::from(access.endpoint.instance))
    }
    fn same_address_v1(self, other: Self) -> bool {
        self.channel == other.channel && self.offset == other.offset
    }
}
/// Verifier-owned MAIN I/O fixed schedule compiled only from public channel declarations.
///
/// The schedule deliberately stores no byte value from an execution or sorted witness.
/// Execution-order and address-order topology are compiled directly from declarations, and public
/// bytes are retained only for the dedicated public-input selector.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MainIoFixedScheduleV1 {
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    execution: Vec<MainIoAccessTopologyV1>,
    sorted: Vec<MainIoAccessTopologyV1>,
    execution_public_values: Vec<Option<F>>,
}
impl MainIoFixedScheduleV1 {
    fn compile_v1(
        layout: SegmentLayoutV1,
        statement: &ZkX509IoStarkStatementV1,
        logical_active_rows: usize,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_io_logical_geometry_v1(layout, logical_active_rows)?;
        validate_declarations_v1(statement.declarations())
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        if io_active_rows_v1(statement.declarations())? != logical_active_rows {
            return Err(ZkX509StarkErrorV1::InvalidStatement);
        }
        let mut execution = Vec::new();
        let mut sorted = Vec::new();
        let mut execution_public_values = Vec::new();
        execution
            .try_reserve_exact(logical_active_rows)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        sorted
            .try_reserve_exact(logical_active_rows)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        execution_public_values
            .try_reserve_exact(logical_active_rows)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for declaration in statement.declarations() {
            let byte_len = usize::try_from(declaration.byte_len)
                .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
            for offset in 0..byte_len {
                execution.push(MainIoAccessTopologyV1::new_v1(
                    declaration.channel,
                    offset,
                    true,
                    declaration.producer,
                )?);
                execution_public_values.push(None);
            }
            for endpoint in declaration.consumers.iter().copied() {
                for offset in 0..byte_len {
                    execution.push(MainIoAccessTopologyV1::new_v1(
                        declaration.channel,
                        offset,
                        false,
                        endpoint,
                    )?);
                    let public_value = if endpoint.role == ZkX509IoSegmentRoleV1::PublicInput {
                        Some(F(u64::from(
                            declaration
                                .public_value
                                .as_ref()
                                .and_then(|value| value.get(offset))
                                .copied()
                                .ok_or(ZkX509StarkErrorV1::InvalidStatement)?,
                        )))
                    } else {
                        None
                    };
                    execution_public_values.push(public_value);
                }
            }
            // This is exactly the stable `(channel, offset, write/read)` order
            // used by the native I/O table builder: one write followed by the
            // declaration-canonical consumer order for each address.
            for offset in 0..byte_len {
                sorted.push(MainIoAccessTopologyV1::new_v1(
                    declaration.channel,
                    offset,
                    true,
                    declaration.producer,
                )?);
                for endpoint in declaration.consumers.iter().copied() {
                    sorted.push(MainIoAccessTopologyV1::new_v1(
                        declaration.channel,
                        offset,
                        false,
                        endpoint,
                    )?);
                }
            }
        }
        if execution.len() != logical_active_rows
            || sorted.len() != logical_active_rows
            || execution_public_values.len() != logical_active_rows
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(Self {
            layout,
            logical_active_rows,
            execution,
            sorted,
            execution_public_values,
        })
    }
    fn fixed_row_v1(&self, index: usize) -> Result<[F; IO_FIXED_WIDTH], ZkX509StarkErrorV1> {
        if index >= self.layout.trace_size() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut fixed = [F::ZERO; IO_FIXED_WIDTH];
        if index < self.logical_active_rows {
            self.execution[index].write_fixed_fields_v1(&mut fixed, FIX_EXEC_CHANNEL);
            self.sorted[index].write_fixed_fields_v1(&mut fixed, FIX_SORT_CHANNEL);
            if let Some(value) = self.execution_public_values[index] {
                fixed[FIX_PUBLIC_SELECTOR] = F::ONE;
                fixed[FIX_PUBLIC_VALUE] = value;
            }
            if index + 1 < self.logical_active_rows
                && self.sorted[index].same_address_v1(self.sorted[index + 1])
            {
                fixed[FIX_SORT_SAME_ADDRESS_NEXT] = F::ONE;
            }
        }
        let [active, first, last_active, transition] =
            io_fixed_selector_fields_v1(index, self.logical_active_rows, self.layout.trace_size())?;
        fixed[FIX_ACTIVE] = active;
        fixed[FIX_FIRST] = first;
        fixed[FIX_LAST_ACTIVE] = last_active;
        fixed[FIX_TRANSITION] = transition;
        Ok(fixed)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn fixed_columns_v1(&self) -> Result<Vec<Vec<F>>, ZkX509StarkErrorV1> {
        let mut fixed_columns =
            allocate_column_matrix_v1(IO_FIXED_WIDTH, self.layout.trace_size())?;
        for index in 0..self.layout.trace_size() {
            push_row_to_columns_v1(&mut fixed_columns, &self.fixed_row_v1(index)?)?;
        }
        Ok(fixed_columns)
    }
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    fn validate_witness_topology_v1(
        &self,
        execution: &[IoAccessV1],
        sorted: &[IoAccessV1],
    ) -> Result<(), ZkX509StarkErrorV1> {
        if execution.len() != self.logical_active_rows
            || sorted.len() != self.logical_active_rows
            || execution
                .iter()
                .copied()
                .zip(self.execution.iter().copied())
                .any(|(actual, expected)| !expected.matches_access_v1(actual))
            || sorted
                .iter()
                .copied()
                .zip(self.sorted.iter().copied())
                .any(|(actual, expected)| !expected.matches_access_v1(actual))
        {
            return Err(ZkX509StarkErrorV1::WitnessStatementMismatch);
        }
        Ok(())
    }
}
#[cfg(test)]
fn transpose_array_rows_v1<const WIDTH: usize>(
    rows: &[[F; WIDTH]],
) -> Result<Vec<Vec<F>>, ZkX509StarkErrorV1> {
    if rows.is_empty() {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let mut columns = (0..WIDTH)
        .map(|_| Vec::with_capacity(rows.len()))
        .collect::<Vec<_>>();
    for row in rows {
        for (column, value) in columns.iter_mut().zip(row.iter().copied()) {
            column.push(value);
        }
    }
    Ok(columns)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn allocate_column_matrix_v1(width: usize, rows: usize) -> Result<Vec<Vec<F>>, ZkX509StarkErrorV1> {
    let mut columns = Vec::new();
    columns
        .try_reserve_exact(width)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for _ in 0..width {
        let mut column = Vec::new();
        column
            .try_reserve_exact(rows)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        columns.push(column);
    }
    Ok(columns)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn push_row_to_columns_v1(columns: &mut [Vec<F>], row: &[F]) -> Result<(), ZkX509StarkErrorV1> {
    if columns.len() != row.len() {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    for (column, value) in columns.iter_mut().zip(row.iter().copied()) {
        column.push(value);
    }
    Ok(())
}
#[cfg(test)]
fn row_at_v1(columns: &[Vec<F>], index: usize) -> Result<Vec<F>, ZkX509StarkErrorV1> {
    columns
        .iter()
        .map(|column| {
            column
                .get(index)
                .copied()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)
        })
        .collect()
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn copy_row_at_v1(
    columns: &[Vec<F>],
    index: usize,
    row: &mut [F],
) -> Result<(), ZkX509StarkErrorV1> {
    if columns.len() != row.len() {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    for (value, column) in row.iter_mut().zip(columns) {
        *value = column
            .get(index)
            .copied()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    }
    Ok(())
}
#[cfg(test)]
fn topology_witnesses_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
) -> Result<Vec<ZkX509IoChannelWitnessV1>, ZkX509StarkErrorV1> {
    declarations
        .iter()
        .map(|declaration| {
            let byte_len = usize::try_from(declaration.byte_len)
                .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
            let common_value = declaration
                .public_value
                .clone()
                .unwrap_or_else(|| vec![0_u8; byte_len]);
            let consumer_values = declaration
                .consumers
                .iter()
                .map(|endpoint| {
                    if endpoint.role == ZkX509IoSegmentRoleV1::PublicInput {
                        declaration
                            .public_value
                            .clone()
                            .ok_or(ZkX509StarkErrorV1::InvalidStatement)
                    } else {
                        Ok(common_value.clone())
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ZkX509IoChannelWitnessV1 {
                declaration: declaration.clone(),
                producer_value: common_value,
                consumer_values,
            })
        })
        .collect()
}
#[cfg(test)]
fn public_value_for_access_v1(
    declarations: &[ZkX509IoChannelDeclarationV1],
    access: IoAccessV1,
) -> Result<Option<u8>, ZkX509StarkErrorV1> {
    if access.endpoint.role != ZkX509IoSegmentRoleV1::PublicInput {
        return Ok(None);
    }
    let declaration = declarations
        .get(usize::try_from(access.channel.0).map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?)
        .ok_or(ZkX509StarkErrorV1::InvalidStatement)?;
    declaration
        .public_value
        .as_ref()
        .and_then(|value| value.get(access.offset.0 as usize))
        .copied()
        .map(Some)
        .ok_or(ZkX509StarkErrorV1::InvalidStatement)
}
fn validate_io_logical_geometry_v1(
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
) -> Result<(), ZkX509StarkErrorV1> {
    layout.validate()?;
    if logical_active_rows == 0
        || logical_active_rows > layout.trace_size()
        || logical_active_rows > ZK_X509_IO_FIXED_CAPACITY_ROWS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let focused = SegmentLayoutV1::for_io(logical_active_rows)?;
    let full = SegmentLayoutV1::for_full_io()?;
    if layout != focused && layout != full {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(())
}
fn io_fixed_selector_fields_v1(
    index: usize,
    logical_active_rows: usize,
    trace_size: usize,
) -> Result<[F; 4], ZkX509StarkErrorV1> {
    if logical_active_rows == 0 || logical_active_rows > trace_size || index >= trace_size {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok([
        F(u64::from(index < logical_active_rows)),
        F(u64::from(index == 0)),
        F(u64::from(index + 1 == logical_active_rows)),
        F(u64::from(index + 1 < trace_size)),
    ])
}
#[cfg(test)]
fn build_io_base_and_fixed_columns_for_layout_v1(
    statement: &ZkX509IoStarkStatementV1,
    witnesses: &[ZkX509IoChannelWitnessV1],
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
) -> Result<
    (
        PrivateTableV1<Vec<F>>,
        Vec<Vec<F>>,
        PrivateTableV1<IoAccessV1>,
        PrivateTableV1<IoAccessV1>,
    ),
    ZkX509StarkErrorV1,
> {
    let fixed_schedule = MainIoFixedScheduleV1::compile_v1(layout, statement, logical_active_rows)?;
    build_io_base_and_fixed_columns_from_schedule_v1(statement, witnesses, &fixed_schedule)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_io_base_and_fixed_columns_from_schedule_v1(
    statement: &ZkX509IoStarkStatementV1,
    witnesses: &[ZkX509IoChannelWitnessV1],
    fixed_schedule: &MainIoFixedScheduleV1,
) -> Result<
    (
        PrivateTableV1<Vec<F>>,
        Vec<Vec<F>>,
        PrivateTableV1<IoAccessV1>,
        PrivateTableV1<IoAccessV1>,
    ),
    ZkX509StarkErrorV1,
> {
    let layout = fixed_schedule.layout;
    let logical_active_rows = fixed_schedule.logical_active_rows;
    if witnesses.len() != statement.declarations.len()
        || witnesses
            .iter()
            .zip(&statement.declarations)
            .any(|(witness, declaration)| witness.declaration != *declaration)
    {
        return Err(ZkX509StarkErrorV1::WitnessStatementMismatch);
    }
    let (declarations, execution, sorted) = build_zk_x509_io_base_tables_v1(witnesses)?;
    if declarations != statement.declarations {
        return Err(ZkX509StarkErrorV1::WitnessStatementMismatch);
    }
    if execution.len() != logical_active_rows || sorted.len() != logical_active_rows {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    fixed_schedule.validate_witness_topology_v1(&execution, &sorted)?;
    let mut base_columns = PrivateTableV1::new(
        allocate_column_matrix_v1(IO_BASE_WIDTH, layout.trace_size())?,
        zeroize_field_rows_v1,
    );
    for index in 0..layout.trace_size() {
        let mut base = [F::ZERO; IO_BASE_WIDTH];
        if index < logical_active_rows {
            let execution_access = execution[index];
            let sorted_access = sorted[index];
            access_base_fields_v1(execution_access, &mut base, EXEC_CHANNEL, EXEC_BITS);
            access_base_fields_v1(sorted_access, &mut base, SORT_CHANNEL, SORT_BITS);
        }
        push_row_to_columns_v1(&mut base_columns, &base)?;
    }
    let fixed_columns = fixed_schedule.fixed_columns_v1()?;
    Ok((base_columns, fixed_columns, execution, sorted))
}
#[cfg(test)]
fn build_io_base_and_fixed_columns_v1(
    statement: &ZkX509IoStarkStatementV1,
    witnesses: &[ZkX509IoChannelWitnessV1],
) -> Result<
    (
        SegmentLayoutV1,
        PrivateTableV1<Vec<F>>,
        Vec<Vec<F>>,
        PrivateTableV1<IoAccessV1>,
        PrivateTableV1<IoAccessV1>,
    ),
    ZkX509StarkErrorV1,
> {
    let logical_active_rows = io_active_rows_v1(&statement.declarations)?;
    let layout = SegmentLayoutV1::for_io(logical_active_rows)?;
    let (base_columns, fixed_columns, execution, sorted) =
        build_io_base_and_fixed_columns_for_layout_v1(
            statement,
            witnesses,
            layout,
            logical_active_rows,
        )?;
    Ok((layout, base_columns, fixed_columns, execution, sorted))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn build_io_aux_columns_v1(
    statement: &ZkX509IoStarkStatementV1,
    witnesses: &[ZkX509IoChannelWitnessV1],
    challenges: ZkX509IoChallengesV1,
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    expected_execution: &[IoAccessV1],
    expected_sorted: &[IoAccessV1],
) -> Result<PrivateTableV1<Vec<F>>, ZkX509StarkErrorV1> {
    validate_io_logical_geometry_v1(layout, logical_active_rows)?;
    let trace = build_zk_x509_io_trace_v1(witnesses, challenges)?;
    if trace.declarations != statement.declarations
        || trace.execution != expected_execution
        || trace.sorted != expected_sorted
        || trace.permutation_rows.len() != logical_active_rows
        || expected_execution.len() != logical_active_rows
        || expected_sorted.len() != logical_active_rows
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let final_row = trace
        .permutation_rows
        .last()
        .ok_or(ZkX509StarkErrorV1::IoWitness)?;
    let mut aux_columns = PrivateTableV1::new(
        allocate_column_matrix_v1(IO_AUX_WIDTH, layout.trace_size())?,
        zeroize_field_rows_v1,
    );
    let logical_active_rows_field =
        F(u64::try_from(logical_active_rows).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?);
    for index in 0..layout.trace_size() {
        let mut row = [F::ZERO; IO_AUX_WIDTH];
        if let Some(source) = trace.permutation_rows.get(index) {
            row[AUX_EXEC_BEFORE..AUX_EXEC_BEFORE + IO_LANES]
                .copy_from_slice(&source.execution_product_before);
            row[AUX_SORT_BEFORE..AUX_SORT_BEFORE + IO_LANES]
                .copy_from_slice(&source.sorted_product_before);
            row[AUX_EXEC_AFTER..AUX_EXEC_AFTER + IO_LANES]
                .copy_from_slice(&source.execution_product_after);
            row[AUX_SORT_AFTER..AUX_SORT_AFTER + IO_LANES]
                .copy_from_slice(&source.sorted_product_after);
        } else {
            row[AUX_EXEC_BEFORE..AUX_EXEC_BEFORE + IO_LANES]
                .copy_from_slice(&final_row.execution_product_after);
            row[AUX_SORT_BEFORE..AUX_SORT_BEFORE + IO_LANES]
                .copy_from_slice(&final_row.sorted_product_after);
            row[AUX_EXEC_AFTER..AUX_EXEC_AFTER + IO_LANES]
                .copy_from_slice(&final_row.execution_product_after);
            row[AUX_SORT_AFTER..AUX_SORT_AFTER + IO_LANES]
                .copy_from_slice(&final_row.sorted_product_after);
        }
        row[AUX_CONT_SEGMENT_INDEX] = F::ZERO;
        row[AUX_CONT_GLOBAL_START] = F::ZERO;
        row[AUX_CONT_GLOBAL_END] = logical_active_rows_field;
        row[AUX_CONT_LOCAL_START] = F::ZERO;
        row[AUX_CONT_LOCAL_END] = F::ZERO;
        row[AUX_CONT_MEMORY_START] = F::ZERO;
        row[AUX_CONT_MEMORY_END] = logical_active_rows_field;
        row[AUX_CONT_EXEC_START..AUX_CONT_EXEC_START + IO_LANES].fill(F::ONE);
        row[AUX_CONT_EXEC_END..AUX_CONT_EXEC_END + IO_LANES]
            .copy_from_slice(&final_row.execution_product_after);
        row[AUX_CONT_SORT_START..AUX_CONT_SORT_START + IO_LANES].fill(F::ONE);
        row[AUX_CONT_SORT_END..AUX_CONT_SORT_END + IO_LANES]
            .copy_from_slice(&final_row.sorted_product_after);
        push_row_to_columns_v1(&mut aux_columns, &row)?;
    }
    Ok(aux_columns)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_io_base_phase_shape_v1(
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    base_columns: &[Vec<F>],
    fixed_columns: &[Vec<F>],
) -> Result<(), ZkX509StarkErrorV1> {
    validate_io_logical_geometry_v1(layout, logical_active_rows)?;
    let trace_size = layout.trace_size();
    if base_columns.len() != IO_BASE_WIDTH
        || fixed_columns.len() != IO_FIXED_WIDTH
        || base_columns
            .iter()
            .chain(fixed_columns)
            .any(|column| column.len() != trace_size)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    if base_columns
        .iter()
        .chain(fixed_columns)
        .flatten()
        .any(|value| F::canonical(value.0).is_none())
    {
        return Err(ZkX509StarkErrorV1::IoWitness);
    }
    for index in 0..trace_size {
        let [active, first, last_active, transition] =
            io_fixed_selector_fields_v1(index, logical_active_rows, trace_size)?;
        if fixed_columns[FIX_ACTIVE][index] != active
            || fixed_columns[FIX_FIRST][index] != first
            || fixed_columns[FIX_LAST_ACTIVE][index] != last_active
            || fixed_columns[FIX_TRANSITION][index] != transition
        {
            return Err(ZkX509StarkErrorV1::IoWitness);
        }
        if index >= logical_active_rows
            && (base_columns.iter().any(|column| column[index] != F::ZERO)
                || fixed_columns
                    .iter()
                    .enumerate()
                    .any(|(column, values)| column != FIX_TRANSITION && values[index] != F::ZERO))
        {
            return Err(ZkX509StarkErrorV1::IoWitness);
        }
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_io_bound_material_shape_v1(
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    base_columns: &[Vec<F>],
    aux_columns: &[Vec<F>],
    fixed_columns: &[Vec<F>],
) -> Result<(), ZkX509StarkErrorV1> {
    validate_io_base_phase_shape_v1(layout, logical_active_rows, base_columns, fixed_columns)?;
    let trace_size = layout.trace_size();
    if aux_columns.len() != IO_AUX_WIDTH
        || aux_columns.iter().any(|column| column.len() != trace_size)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    if aux_columns
        .iter()
        .flatten()
        .any(|value| F::canonical(value.0).is_none())
    {
        return Err(ZkX509StarkErrorV1::IoWitness);
    }
    let logical_active_rows_field =
        F(u64::try_from(logical_active_rows).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?);
    for index in 0..trace_size {
        for (column, expected) in [
            (AUX_CONT_SEGMENT_INDEX, F::ZERO),
            (AUX_CONT_GLOBAL_START, F::ZERO),
            (AUX_CONT_GLOBAL_END, logical_active_rows_field),
            (AUX_CONT_LOCAL_START, F::ZERO),
            (AUX_CONT_LOCAL_END, F::ZERO),
            (AUX_CONT_MEMORY_START, F::ZERO),
            (AUX_CONT_MEMORY_END, logical_active_rows_field),
        ] {
            if aux_columns[column][index] != expected {
                return Err(ZkX509StarkErrorV1::IoWitness);
            }
        }
        for start in [AUX_CONT_EXEC_START, AUX_CONT_SORT_START] {
            if (0..IO_LANES).any(|lane| aux_columns[start + lane][index] != F::ONE) {
                return Err(ZkX509StarkErrorV1::IoWitness);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_io_trace_material_shape_v1(
    material: &IoTraceMaterialV1,
) -> Result<(), ZkX509StarkErrorV1> {
    validate_io_bound_material_shape_v1(
        material.layout,
        material.logical_active_rows,
        &material.base_columns,
        &material.aux_columns,
        &material.fixed_columns,
    )
}
#[cfg(test)]
fn build_projection_base_material_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    witness: &ZkX509ProjectionWitnessV1,
) -> Result<
    (
        SegmentLayoutV1,
        ZkX509ProjectionTraceV1,
        Vec<Vec<F>>,
        Vec<Vec<F>>,
    ),
    ZkX509StarkErrorV1,
> {
    let layout = SegmentLayoutV1::for_projection()?;
    layout.validate()?;
    let trace = build_zk_x509_projection_trace_v1(statement, witness)?;
    let fixed_rows = compile_zk_x509_projection_stark_fixed_rows_v1(statement)?;
    if trace.base.rows.len() != layout.trace_size()
        || trace.fixed.rows.len() != layout.trace_size()
        || fixed_rows.len() != layout.trace_size()
    {
        return Err(ZkX509StarkErrorV1::ProjectionWitness);
    }
    let base_columns = transpose_array_rows_v1(&trace.base.rows)?;
    let fixed_columns = transpose_array_rows_v1(&fixed_rows)?;
    Ok((layout, trace, base_columns, fixed_columns))
}
#[cfg(test)]
fn derive_projection_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509ProjectionChallengesV1, ZkX509StarkErrorV1> {
    let mut sampled = [F::ZERO; ZK_X509_PROJECTION_COPY_LANES_V1 * 7];
    for (index, challenge) in sampled.iter_mut().enumerate() {
        let label = ZK_X509_PROJECTION_CHALLENGE_LABELS_V1[index / 7][index % 7];
        *challenge = transcript
            .challenge_field(label)
            .map_err(map_transparent_error_v1)?;
    }
    Ok(ZkX509ProjectionChallengesV1 {
        copy: core::array::from_fn(|lane| ZkX509ProjectionCopyChallengesV1 {
            beta: sampled[lane * 7],
            gamma: sampled[lane * 7 + 1],
        }),
        compaction: core::array::from_fn(|lane| ZkX509ProjectionCompactionChallengesV1 {
            active: sampled[lane * 7 + 2],
            invocation: sampled[lane * 7 + 3],
            position: sampled[lane * 7 + 4],
            value: sampled[lane * 7 + 5],
            gamma: sampled[lane * 7 + 6],
        }),
    })
}
#[cfg(test)]
fn derive_der_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509DerStarkChallengesV1, ZkX509StarkErrorV1> {
    let challenges =
        derive_zk_x509_der_stark_challenges_v1(transcript).map_err(map_transparent_error_v1)?;
    challenges
        .validate()
        .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    Ok(challenges)
}
#[cfg(test)]
fn build_projection_trace_material_v1(
    layout: SegmentLayoutV1,
    trace: ZkX509ProjectionTraceV1,
    base_columns: Vec<Vec<F>>,
    fixed_columns: Vec<Vec<F>>,
    challenges: ZkX509ProjectionChallengesV1,
) -> Result<ProjectionTraceMaterialV1, ZkX509StarkErrorV1> {
    let aux = build_zk_x509_projection_aux_trace_v1(&trace.base, &trace.fixed, challenges)?;
    if aux.rows.len() != layout.trace_size() {
        return Err(ZkX509StarkErrorV1::ProjectionWitness);
    }
    Ok(ProjectionTraceMaterialV1 {
        layout,
        base_columns,
        aux_columns: transpose_array_rows_v1(&aux.rows)?,
        fixed_columns,
    })
}
#[cfg(test)]
fn io_public_digest_v1(
    statement: &ZkX509IoStarkStatementV1,
) -> Result<PrivacyOuterDigestV1, ZkX509StarkErrorV1> {
    let mut encoding = Vec::new();
    append_u16_v1(
        &mut encoding,
        u16::try_from(statement.declarations.len())
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?,
    );
    for declaration in &statement.declarations {
        append_u32_v1(&mut encoding, declaration.channel);
        encoding.push(role_field_v1(declaration.producer.role).0 as u8);
        append_u16_v1(&mut encoding, declaration.producer.instance);
        append_u16_v1(
            &mut encoding,
            u16::try_from(declaration.consumers.len())
                .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?,
        );
        for consumer in &declaration.consumers {
            encoding.push(role_field_v1(consumer.role).0 as u8);
            append_u16_v1(&mut encoding, consumer.instance);
        }
        append_u32_v1(&mut encoding, declaration.byte_len);
        match &declaration.public_value {
            Some(value) => {
                encoding.push(1);
                append_u32_v1(
                    &mut encoding,
                    u32::try_from(value.len()).map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?,
                );
                encoding.extend_from_slice(value);
            }
            None => encoding.push(0),
        }
    }
    privacy_outer_digest_frame_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        PUBLIC_DIGEST_DOMAIN,
        b"io-public-statement",
        0,
        0,
        0,
        &[&encoding],
    )
    .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)
}
#[cfg(test)]
fn der_public_digest_v1(
    shape: &ZkX509DerStarkShapeV1,
) -> Result<PrivacyOuterDigestV1, ZkX509StarkErrorV1> {
    shape
        .validate()
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    privacy_outer_digest_frame_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        DER_PUBLIC_DIGEST_DOMAIN,
        b"der-public-statement",
        0,
        0,
        0,
        &[
            DER_SEGMENTED_PROOF_DESCRIPTOR_V1,
            ZK_X509_DER_STARK_AIR_DESCRIPTOR_V1,
            shape.transcript_bytes(),
        ],
    )
    .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)
}
#[cfg(test)]
fn projection_public_digest_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<PrivacyOuterDigestV1, ZkX509StarkErrorV1> {
    let statement_digest = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone())
        .digest()
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    privacy_outer_digest_frame_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        PROJECTION_PUBLIC_DIGEST_DOMAIN,
        b"projection-public-statement",
        0,
        0,
        0,
        &[
            statement_digest.as_bytes(),
            ZK_X509_PROJECTION_AIR_DESCRIPTOR_V1,
        ],
    )
    .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)
}
fn io_compress_access_v1<A: crate::privacy_engines::transparent_stark::PolynomialAirFieldV1>(
    row: &[A],
    offset: usize,
    challenge: super::io_air::ZkX509IoLaneChallengesV1,
) -> A {
    A::from_base(challenge.beta)
        .add(A::from_base(challenge.channel).mul(row[offset]))
        .add(A::from_base(challenge.offset).mul(row[offset + 1]))
        .add(A::from_base(challenge.value).mul(row[offset + 2]))
        .add(A::from_base(challenge.is_write).mul(row[offset + 3]))
}
fn io_constraint_residues_v1<A: crate::privacy_engines::transparent_stark::PolynomialAirFieldV1>(
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    current_base: &[A],
    next_base: &[A],
    current_aux: &[A],
    next_aux: &[A],
    fixed: &[A],
    challenges: ZkX509IoChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    if current_base.len() != IO_BASE_WIDTH
        || next_base.len() != IO_BASE_WIDTH
        || current_aux.len() != IO_AUX_WIDTH
        || next_aux.len() != IO_AUX_WIDTH
        || fixed.len() != IO_FIXED_WIDTH
        || logical_active_rows == 0
        || logical_active_rows > layout.trace_size()
        || logical_active_rows > ZK_X509_IO_FIXED_CAPACITY_ROWS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    challenges.validate()?;
    if current_base
        .iter()
        .chain(next_base)
        .chain(current_aux)
        .chain(next_aux)
        .chain(fixed)
        .any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut residues = Vec::with_capacity(IO_CONSTRAINT_COUNT);
    for (trace, expected) in [
        (EXEC_CHANNEL, FIX_EXEC_CHANNEL),
        (EXEC_OFFSET, FIX_EXEC_OFFSET),
        (EXEC_WRITE, FIX_EXEC_WRITE),
        (EXEC_ROLE, FIX_EXEC_ROLE),
        (EXEC_INSTANCE, FIX_EXEC_INSTANCE),
        (SORT_CHANNEL, FIX_SORT_CHANNEL),
        (SORT_OFFSET, FIX_SORT_OFFSET),
        (SORT_WRITE, FIX_SORT_WRITE),
        (SORT_ROLE, FIX_SORT_ROLE),
        (SORT_INSTANCE, FIX_SORT_INSTANCE),
    ] {
        residues.push(current_base[trace].sub(fixed[expected]));
    }
    for bit in 0..8 {
        for offset in [EXEC_BITS, SORT_BITS] {
            let value = current_base[offset + bit];
            residues.push(value.mul(value.sub(A::ONE)));
        }
    }
    for (value_offset, bits_offset) in [(EXEC_VALUE, EXEC_BITS), (SORT_VALUE, SORT_BITS)] {
        let packed = (0..8).fold(A::ZERO, |sum, bit| {
            sum.add(current_base[bits_offset + bit].mul(A::from_base(F(1_u64 << bit))))
        });
        residues.push(current_base[value_offset].sub(packed));
    }
    let inactive = A::ONE.sub(fixed[FIX_ACTIVE]);
    residues.push(inactive.mul(current_base[EXEC_VALUE]));
    residues.push(inactive.mul(current_base[SORT_VALUE]));
    residues.push(
        fixed[FIX_PUBLIC_SELECTOR].mul(current_base[EXEC_VALUE].sub(fixed[FIX_PUBLIC_VALUE])),
    );
    residues.push(
        fixed[FIX_SORT_SAME_ADDRESS_NEXT].mul(next_base[SORT_VALUE].sub(current_base[SORT_VALUE])),
    );
    for lane in 0..IO_LANES {
        let challenge = challenges.lanes[lane];
        residues.push(fixed[FIX_FIRST].mul(current_aux[AUX_EXEC_BEFORE + lane].sub(A::ONE)));
        residues.push(fixed[FIX_FIRST].mul(current_aux[AUX_SORT_BEFORE + lane].sub(A::ONE)));
        let active_exec = io_compress_access_v1(current_base, EXEC_CHANNEL, challenge);
        let active_sort = io_compress_access_v1(current_base, SORT_CHANNEL, challenge);
        let exec_factor = fixed[FIX_ACTIVE]
            .mul(active_exec)
            .add(A::ONE.sub(fixed[FIX_ACTIVE]));
        let sort_factor = fixed[FIX_ACTIVE]
            .mul(active_sort)
            .add(A::ONE.sub(fixed[FIX_ACTIVE]));
        residues.push(
            current_aux[AUX_EXEC_AFTER + lane]
                .sub(current_aux[AUX_EXEC_BEFORE + lane].mul(exec_factor)),
        );
        residues.push(
            current_aux[AUX_SORT_AFTER + lane]
                .sub(current_aux[AUX_SORT_BEFORE + lane].mul(sort_factor)),
        );
        residues.push(
            fixed[FIX_TRANSITION]
                .mul(next_aux[AUX_EXEC_BEFORE + lane].sub(current_aux[AUX_EXEC_AFTER + lane])),
        );
        residues.push(
            fixed[FIX_TRANSITION]
                .mul(next_aux[AUX_SORT_BEFORE + lane].sub(current_aux[AUX_SORT_AFTER + lane])),
        );
        residues.push(
            fixed[FIX_LAST_ACTIVE]
                .mul(current_aux[AUX_EXEC_AFTER + lane].sub(current_aux[AUX_SORT_AFTER + lane])),
        );
    }
    let logical_active_rows = A::from_base(F(
        u64::try_from(logical_active_rows).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?
    ));
    for (column, expected) in [
        (AUX_CONT_SEGMENT_INDEX, A::ZERO),
        (AUX_CONT_GLOBAL_START, A::ZERO),
        (AUX_CONT_GLOBAL_END, logical_active_rows),
        (AUX_CONT_LOCAL_START, A::ZERO),
        (AUX_CONT_LOCAL_END, A::ZERO),
        (AUX_CONT_MEMORY_START, A::ZERO),
        (AUX_CONT_MEMORY_END, logical_active_rows),
    ] {
        residues.push(current_aux[column].sub(expected));
    }
    for start in [AUX_CONT_EXEC_START, AUX_CONT_SORT_START] {
        for lane in 0..IO_LANES {
            residues.push(current_aux[start + lane].sub(A::ONE));
        }
    }
    for (end, product_after) in [
        (AUX_CONT_EXEC_END, AUX_EXEC_AFTER),
        (AUX_CONT_SORT_END, AUX_SORT_AFTER),
    ] {
        for lane in 0..IO_LANES {
            residues
                .push(fixed[FIX_TRANSITION].mul(next_aux[end + lane].sub(current_aux[end + lane])));
            residues.push(
                fixed[FIX_LAST_ACTIVE]
                    .mul(current_aux[end + lane].sub(current_aux[product_after + lane])),
            );
        }
    }
    if residues.len() != IO_CONSTRAINT_COUNT {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(residues)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_io_bound_constraints_v1(
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    base_columns: &[Vec<F>],
    aux_columns: &[Vec<F>],
    fixed_columns: &[Vec<F>],
    challenges: ZkX509IoChallengesV1,
) -> Result<(), ZkX509StarkErrorV1> {
    validate_io_bound_material_shape_v1(
        layout,
        logical_active_rows,
        base_columns,
        aux_columns,
        fixed_columns,
    )?;
    let mut current_base = [F::ZERO; IO_BASE_WIDTH];
    let mut next_base = [F::ZERO; IO_BASE_WIDTH];
    let mut current_aux = [F::ZERO; IO_AUX_WIDTH];
    let mut next_aux = [F::ZERO; IO_AUX_WIDTH];
    let mut fixed = [F::ZERO; IO_FIXED_WIDTH];
    for index in 0..layout.trace_size() {
        let next = (index + 1) % layout.trace_size();
        copy_row_at_v1(base_columns, index, &mut current_base)?;
        copy_row_at_v1(base_columns, next, &mut next_base)?;
        copy_row_at_v1(aux_columns, index, &mut current_aux)?;
        copy_row_at_v1(aux_columns, next, &mut next_aux)?;
        copy_row_at_v1(fixed_columns, index, &mut fixed)?;
        let residues = io_constraint_residues_v1(
            layout,
            logical_active_rows,
            &current_base,
            &next_base,
            &current_aux,
            &next_aux,
            &fixed,
            challenges,
        )?;
        if residues.iter().any(|value| *value != F::ZERO) {
            return Err(ZkX509StarkErrorV1::IoWitness);
        }
    }
    Ok(())
}
#[cfg(test)]
fn validate_io_base_constraints_v1(
    material: &IoTraceMaterialV1,
    challenges: ZkX509IoChallengesV1,
) -> Result<(), ZkX509StarkErrorV1> {
    validate_io_bound_constraints_v1(
        material.layout,
        material.logical_active_rows,
        &material.base_columns,
        &material.aux_columns,
        &material.fixed_columns,
        challenges,
    )
}
fn map_transparent_error_v1(error: TransparentStarkErrorV1) -> ZkX509StarkErrorV1 {
    match error {
        TransparentStarkErrorV1::RandomnessUnavailable => ZkX509StarkErrorV1::RandomnessUnavailable,
        TransparentStarkErrorV1::AllocationFailure => ZkX509StarkErrorV1::AllocationFailure,
        TransparentStarkErrorV1::NonCanonicalField => ZkX509StarkErrorV1::NonCanonicalField,
        TransparentStarkErrorV1::FriDegree => ZkX509StarkErrorV1::FriDegree,
        TransparentStarkErrorV1::MalformedProof => ZkX509StarkErrorV1::MalformedProof,
        TransparentStarkErrorV1::InvalidGrinding
        | TransparentStarkErrorV1::ChallengeSamplingExhausted
        | TransparentStarkErrorV1::QuerySamplingExhausted => ZkX509StarkErrorV1::TranscriptMismatch,
        TransparentStarkErrorV1::InvalidMerkleShape => ZkX509StarkErrorV1::TraceOpening,
        _ => ZkX509StarkErrorV1::InternalInvariant,
    }
}
#[cfg(test)]
fn masked_lde_columns_v1<R: TryRngCore>(
    columns: &[Vec<F>],
    layout: SegmentLayoutV1,
    rng: &mut R,
) -> Result<Vec<Vec<F>>, ZkX509StarkErrorV1> {
    columns
        .iter()
        .map(|column| {
            masked_trace_lde_column_v1(column, layout.trace_log2, layout.lde_log2, MASK_DEGREE, rng)
                .map_err(map_transparent_error_v1)
        })
        .collect()
}
#[cfg(test)]
fn fixed_lde_columns_v1(
    columns: &[Vec<F>],
    layout: SegmentLayoutV1,
) -> Result<Vec<Vec<F>>, ZkX509StarkErrorV1> {
    let trace_root =
        goldilocks_primitive_root_v1(layout.trace_log2).map_err(map_transparent_error_v1)?;
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    columns
        .iter()
        .map(|column| {
            if column.len() != layout.trace_size() {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            let mut coefficients = column.clone();
            goldilocks_ifft_v1(&mut coefficients, trace_root).map_err(map_transparent_error_v1)?;
            goldilocks_evaluate_coset_v1(
                &coefficients,
                layout.lde_size(),
                lde_root,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_error_v1)
        })
        .collect()
}
#[cfg(test)]
fn sampled_verifier_generated_fixed_openings_v1<const WIDTH: usize>(
    segment: SegmentLayoutV1,
    common_lde_log2: u8,
    opening_indices: &[usize],
    mut fixed_row: impl FnMut(usize) -> Result<[F; WIDTH], ZkX509StarkErrorV1>,
) -> Result<BTreeMap<usize, Vec<F>>, ZkX509StarkErrorV1> {
    segment.validate()?;
    let common_lde_size = 1_usize
        .checked_shl(u32::from(common_lde_log2))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if WIDTH != segment.fixed_width
        || common_lde_log2 < segment.lde_log2
        || opening_indices.is_empty()
        || opening_indices.len() > VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1
        || opening_indices
            .iter()
            .any(|index| *index >= common_lde_size)
        || opening_indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let trace_root =
        goldilocks_primitive_root_v1(segment.trace_log2).map_err(map_transparent_error_v1)?;
    let common_lde_root =
        goldilocks_primitive_root_v1(common_lde_log2).map_err(map_transparent_error_v1)?;
    let inverse_trace_size =
        F(u64::try_from(segment.trace_size()).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?)
            .inv()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    let mut openings = BTreeMap::new();
    for index in opening_indices.iter().copied() {
        let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_lde_root.pow(index as u128));
        let common = x
            .pow(segment.trace_size() as u128)
            .sub(F::ONE)
            .mul(inverse_trace_size);
        let mut inverse_denominators = Vec::new();
        inverse_denominators
            .try_reserve_exact(segment.trace_size())
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        let mut trace_point = F::ONE;
        for _ in 0..segment.trace_size() {
            inverse_denominators.push(x.sub(trace_point));
            trace_point = trace_point.mul(trace_root);
        }
        goldilocks_batch_invert_v1(&mut inverse_denominators).map_err(map_transparent_error_v1)?;
        let mut opened = [F::ZERO; WIDTH];
        trace_point = F::ONE;
        for (row_index, inverse_denominator) in inverse_denominators.iter().copied().enumerate() {
            let weight = common.mul(trace_point).mul(inverse_denominator);
            for (value, fixed) in opened.iter_mut().zip(fixed_row(row_index)?) {
                *value = value.add(fixed.mul(weight));
            }
            trace_point = trace_point.mul(trace_root);
        }
        if openings.insert(index, opened.to_vec()).is_some() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
    }
    Ok(openings)
}
#[cfg(test)]
static DER_FIXED_OPENING_EVALUATIONS_V1: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
const DER_FIXED_MAX_SAMPLED_OPENINGS_V1: usize = QUERY_COUNT * 2;
#[cfg(test)]
fn checked_der_fixed_sampled_work_v1(
    active_rows: usize,
    trace_size: usize,
    opening_count: usize,
) -> Result<usize, ZkX509StarkErrorV1> {
    if active_rows == 0
        || active_rows > trace_size
        || opening_count == 0
        || opening_count > DER_FIXED_MAX_SAMPLED_OPENINGS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let sampled_roots = active_rows
        .checked_add(usize::from(active_rows < trace_size))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let sampled_work = sampled_roots
        .checked_mul(opening_count)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let maximum_work = trace_size
        .checked_add(1)
        .and_then(|roots| roots.checked_mul(DER_FIXED_MAX_SAMPLED_OPENINGS_V1))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if sampled_work > maximum_work {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(sampled_work)
}
#[cfg(test)]
fn der_fixed_row_at_point_for_shape_v1(
    document_count: usize,
    parser_rows: usize,
    active_rows: usize,
    trace_log2: u8,
    x: F,
) -> Result<[F; ZK_X509_DER_STARK_FIXED_WIDTH_V1], ZkX509StarkErrorV1> {
    let trace_size = 1_usize
        .checked_shl(u32::from(trace_log2))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if document_count == 0
        || parser_rows == 0
        || parser_rows > active_rows
        || active_rows > trace_size
        || x.pow(trace_size as u128) == F::ONE
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let trace_root = goldilocks_primitive_root_v1(trace_log2).map_err(map_transparent_error_v1)?;
    let mut inverse_denominators = Vec::new();
    inverse_denominators
        .try_reserve_exact(active_rows + usize::from(active_rows < trace_size))
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    let mut trace_point = F::ONE;
    for _ in 0..active_rows {
        inverse_denominators.push(x.sub(trace_point));
        trace_point = trace_point.mul(trace_root);
    }
    let last_trace_point = trace_root
        .inv()
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    if active_rows < trace_size {
        inverse_denominators.push(x.sub(last_trace_point));
    }
    goldilocks_batch_invert_v1(&mut inverse_denominators).map_err(map_transparent_error_v1)?;
    let inverse_trace_size =
        F(u64::try_from(trace_size).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?)
            .inv()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    let common = x
        .pow(trace_size as u128)
        .sub(F::ONE)
        .mul(inverse_trace_size);
    let parser_continue_end = parser_rows - 1;
    let mut prefix = F::ZERO;
    let mut parser_continue = F::ZERO;
    let mut parser = F::ZERO;
    let mut active = F::ZERO;
    let mut first = F::ZERO;
    let mut last_parser = F::ZERO;
    let mut first_comparator = F::ZERO;
    let mut last_active = F::ZERO;
    let mut last_aggregate = F::ZERO;
    trace_point = F::ONE;
    for (index, inverse_denominator) in inverse_denominators
        .iter()
        .copied()
        .take(active_rows)
        .enumerate()
    {
        let weight = common.mul(trace_point).mul(inverse_denominator);
        if index == 0 {
            first = weight;
        }
        if index + 1 == parser_rows {
            last_parser = weight;
        }
        if index == parser_rows && parser_rows < active_rows {
            first_comparator = weight;
        }
        if index + 1 == active_rows {
            last_active = weight;
        }
        if index + 1 == trace_size {
            last_aggregate = weight;
        }
        prefix = prefix.add(weight);
        if index + 1 == parser_continue_end {
            parser_continue = prefix;
        }
        if index + 1 == parser_rows {
            parser = prefix;
        }
        if index + 1 == active_rows {
            active = prefix;
        }
        trace_point = trace_point.mul(trace_root);
    }
    if active_rows == trace_size {
        if prefix != F::ONE {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
    } else {
        last_aggregate = common
            .mul(last_trace_point)
            .mul(inverse_denominators[active_rows]);
    }
    let comparator_present = parser_rows < active_rows;
    let mut row = [F::ZERO; ZK_X509_DER_STARK_FIXED_WIDTH_V1];
    row[DER_FIX_ACTIVE] = active;
    row[FIX_FIRST_ACTIVE] = first;
    row[DER_FIX_LAST_ACTIVE] = last_active;
    row[FIX_PARSER] = parser;
    row[FIX_FIRST_PARSER] = first;
    row[FIX_LAST_PARSER] = last_parser;
    row[FIX_COMPARATOR] = active.sub(parser);
    row[FIX_FIRST_COMPARATOR] = first_comparator;
    row[FIX_LAST_COMPARATOR] = if comparator_present {
        last_active
    } else {
        F::ZERO
    };
    row[FIX_PADDING] = F::ONE.sub(active);
    row[FIX_FIRST_AGGREGATE] = first;
    row[FIX_LAST_AGGREGATE] = last_aggregate;
    row[FIX_FINAL_DOCUMENT] =
        F(u64::try_from(document_count - 1).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?);
    row[FIX_PARSER_CONTINUE] = parser_continue;
    Ok(row)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegisteredRetainedProverPlanV1 {
    quotient_coset_log2: u8,
    quotient_coset_rows: usize,
    quotient_next_stride: usize,
    maximum_quotient_degree: usize,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn registered_retained_prover_plan_v1(
    segment: SegmentLayoutV1,
    common_lde_log2: u8,
) -> Result<RegisteredRetainedProverPlanV1, ZkX509StarkErrorV1> {
    segment.validate()?;
    if common_lde_log2 < segment.lde_log2 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let (maximum_quotient_degree, _) = checked_segment_degree_capacity_v1(
        segment.trace_log2,
        common_lde_log2,
        segment.constraint_degree,
    )?;
    let quotient_coset_rows = maximum_quotient_degree
        .checked_add(1)
        .and_then(|rows| rows.checked_next_power_of_two())
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let quotient_coset_log2 = u8::try_from(quotient_coset_rows.ilog2())
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let quotient_next_stride = quotient_coset_rows
        .checked_div(segment.trace_size())
        .filter(|stride| *stride != 0 && quotient_coset_rows % segment.trace_size() == 0)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if quotient_coset_log2 > common_lde_log2 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(RegisteredRetainedProverPlanV1 {
        quotient_coset_log2,
        quotient_coset_rows,
        quotient_next_stride,
        maximum_quotient_degree,
    })
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DerRetainedProverAllocationPlanV1 {
    quotient_coset_log2: u8,
    quotient_coset_rows: usize,
    quotient_next_stride: usize,
    maximum_quotient_degree: usize,
    retained_masked_coefficient_bytes: usize,
    quotient_trace_matrix_bytes: usize,
    encrypted_trace_scratch_bytes: usize,
    common_domain_trace_matrix_bytes: usize,
}
#[cfg(test)]
fn der_retained_prover_allocation_plan_v1(
    layout: SegmentLayoutV1,
) -> Result<DerRetainedProverAllocationPlanV1, ZkX509StarkErrorV1> {
    layout.validate()?;
    if layout.adapter != SegmentAdapterIdV1::StrictDer {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let retained = registered_retained_prover_plan_v1(layout, layout.lde_log2)?;
    let masked_coefficient_count = layout
        .trace_size()
        .checked_add(MASK_DEGREE)
        .and_then(|highest_degree| highest_degree.checked_add(1))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let retained_masked_coefficient_bytes = layout
        .base_width
        .checked_add(layout.aux_width)
        .and_then(|width| width.checked_mul(masked_coefficient_count))
        .and_then(|fields| fields.checked_mul(core::mem::size_of::<F>()))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let quotient_trace_matrix_bytes = layout
        .base_width
        .checked_add(layout.aux_width)
        .and_then(|width| width.checked_add(layout.fixed_width))
        .and_then(|width| width.checked_mul(retained.quotient_coset_rows))
        .and_then(|fields| fields.checked_mul(core::mem::size_of::<F>()))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let plan = DerRetainedProverAllocationPlanV1 {
        quotient_coset_log2: retained.quotient_coset_log2,
        quotient_coset_rows: retained.quotient_coset_rows,
        quotient_next_stride: retained.quotient_next_stride,
        maximum_quotient_degree: retained.maximum_quotient_degree,
        retained_masked_coefficient_bytes,
        quotient_trace_matrix_bytes,
        encrypted_trace_scratch_bytes: 0,
        common_domain_trace_matrix_bytes: 0,
    };
    if plan.quotient_coset_log2 != DER_QUOTIENT_COSET_LOG2_V1
        || plan.quotient_coset_rows != DER_QUOTIENT_COSET_SIZE_V1
        || plan.quotient_next_stride != 8
        || plan.maximum_quotient_degree != DER_MAXIMUM_QUOTIENT_DEGREE_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(plan)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ZeroizingBaseColumnsV1(Vec<Vec<F>>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::ops::Deref for ZeroizingBaseColumnsV1 {
    type Target = [Vec<F>];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZeroizingBaseColumnsV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::Zeroize for ZeroizingBaseColumnsV1 {
    fn zeroize(&mut self) {
        for column in &mut self.0 {
            for value in column {
                value.zeroize_v1();
            }
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ZeroizingExtensionColumnV1(Vec<E>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::ops::Deref for ZeroizingExtensionColumnV1 {
    type Target = [E];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZeroizingExtensionColumnV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::Zeroize for ZeroizingExtensionColumnV1 {
    fn zeroize(&mut self) {
        super::private_table::zeroize_words_v1(&mut self.0);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
type ZeroizingExtensionChunksV1 = super::private_table::PrivateTableV1<Vec<E>>;
#[cfg(any(test, feature = "privacy-release-evidence"))]
type ZeroizingExtensionLanesV1 = super::private_table::PrivateTableV1<Vec<Vec<E>>>;
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_extension_chunks_v1(columns: &mut [Vec<E>]) {
    for column in columns {
        super::private_table::zeroize_words_v1(column);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_extension_lanes_v1(lanes: &mut [Vec<Vec<E>>]) {
    for lane in lanes {
        zeroize_extension_chunks_v1(lane);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct RetainedCompositionMaterialV1 {
    evaluations: Vec<Vec<Vec<E>>>,
    coefficient_chunks: Vec<Vec<Vec<E>>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for RetainedCompositionMaterialV1 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl zeroize::Zeroize for RetainedCompositionMaterialV1 {
    fn zeroize(&mut self) {
        for lane in &mut self.evaluations {
            for chunk in lane {
                for value in chunk {
                    value.zeroize_v1();
                }
            }
        }
        for lane in &mut self.coefficient_chunks {
            for chunk in lane {
                for value in chunk {
                    value.zeroize_v1();
                }
            }
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fp4_coset_coefficients_v1(
    evaluations: &[E],
    coset_log2: u8,
) -> Result<ZeroizingExtensionColumnV1, ZkX509StarkErrorV1> {
    let expected = 1_usize
        .checked_shl(u32::from(coset_log2))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if evaluations.len() != expected || evaluations.iter().any(|value| !value.is_canonical()) {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let root = goldilocks_primitive_root_v1(coset_log2).map_err(map_transparent_error_v1)?;
    let inverse_shift = F(GOLDILOCKS_GENERATOR_V1)
        .inv()
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    let mut coefficients = ZeroizingExtensionColumnV1(Vec::new());
    coefficients
        .0
        .try_reserve_exact(expected)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    coefficients.0.extend_from_slice(evaluations);
    goldilocks_fp4_ifft_v1(&mut coefficients.0, root).map_err(map_transparent_error_v1)?;
    let mut inverse_shift_power = F::ONE;
    for coefficient in &mut coefficients.0 {
        *coefficient = coefficient.mul_base(inverse_shift_power);
        inverse_shift_power = inverse_shift_power.mul(inverse_shift);
    }
    Ok(coefficients)
}
#[cfg(test)]
fn der_fixed_columns_on_coset_v1(
    schedule: &ZkX509DerStarkFixedScheduleV1,
    layout: SegmentLayoutV1,
    evaluation_log2: u8,
) -> Result<ZeroizingBaseColumnsV1, ZkX509StarkErrorV1> {
    if layout.adapter != SegmentAdapterIdV1::StrictDer
        || layout.fixed_width != ZK_X509_DER_STARK_FIXED_WIDTH_V1
        || evaluation_log2 <= layout.trace_log2
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let evaluation_size = 1_usize
        .checked_shl(u32::from(evaluation_log2))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let trace_root =
        goldilocks_primitive_root_v1(layout.trace_log2).map_err(map_transparent_error_v1)?;
    let evaluation_root =
        goldilocks_primitive_root_v1(evaluation_log2).map_err(map_transparent_error_v1)?;
    let mut columns = ZeroizingBaseColumnsV1(Vec::new());
    columns
        .0
        .try_reserve_exact(ZK_X509_DER_STARK_FIXED_WIDTH_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for column in 0..ZK_X509_DER_STARK_FIXED_WIDTH_V1 {
        let mut coefficients = build_zk_x509_der_stark_native_fixed_column_v1(schedule, column)
            .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
        if coefficients.len() != layout.trace_size() {
            coefficients.fill(F::ZERO);
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        goldilocks_ifft_v1(&mut coefficients, trace_root).map_err(map_transparent_error_v1)?;
        let evaluations = goldilocks_evaluate_coset_v1(
            &coefficients,
            evaluation_size,
            evaluation_root,
            F(GOLDILOCKS_GENERATOR_V1),
        )
        .map_err(map_transparent_error_v1)?;
        coefficients.fill(F::ZERO);
        columns.0.push(evaluations);
    }
    Ok(columns)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn composition_coefficient_chunks_v1(
    quotient_coefficients: &[E],
    maximum_quotient_degree: usize,
    shared_layout: &aggregate::AggregateProofLayoutV1,
) -> Result<Vec<Vec<E>>, ZkX509StarkErrorV1> {
    let first_forbidden = maximum_quotient_degree
        .checked_add(1)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if quotient_coefficients
        .get(first_forbidden..)
        .is_some_and(|tail| tail.iter().any(|coefficient| *coefficient != E::ZERO))
    {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    let geometry = super::composition_masking::QuotientChunkGeometryV1::new_v1(
        shared_layout,
        AGGREGATE_PARAMETERS_V1,
    )
    .map_err(map_aggregate_error_v1)?;
    if maximum_quotient_degree
        >= geometry
            .stride_v1()
            .checked_mul(COMPOSITION_DEGREE_CHUNKS)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    geometry
        .split_v1(quotient_coefficients)
        .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn der_composition_material_from_polynomials_v1(
    layout: SegmentLayoutV1,
    schedule: &ZkX509DerStarkFixedScheduleV1,
    base_polynomials: &aggregate::MaskedTracePolynomialSetV1,
    aux_polynomials: &aggregate::MaskedTracePolynomialSetV1,
    challenges: ZkX509DerStarkChallengesV1,
    public: ZkX509DerStarkPublicTerminalsV1,
    claims: ZkX509DerStarkTerminalClaimsV1,
    alphas: &[Vec<E>],
) -> Result<RetainedCompositionMaterialV1, ZkX509StarkErrorV1> {
    let plan = der_retained_prover_allocation_plan_v1(layout)?;
    if base_polynomials.width() != ZK_X509_DER_STARK_BASE_WIDTH_V1
        || aux_polynomials.width() != ZK_X509_DER_STARK_AUX_WIDTH_V1
        || base_polynomials.native_trace_log2() != layout.trace_log2
        || aux_polynomials.native_trace_log2() != layout.trace_log2
        || base_polynomials.commitment_lde_log2() != layout.lde_log2
        || aux_polynomials.commitment_lde_log2() != layout.lde_log2
        || alphas.len() != SECURITY_LANES
        || alphas
            .iter()
            .any(|lane| lane.len() != ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let base_coset = base_polynomials
        .evaluate_columns_on_coset_v1(plan.quotient_coset_log2)
        .map_err(map_aggregate_error_v1)?;
    let aux_coset = aux_polynomials
        .evaluate_columns_on_coset_v1(plan.quotient_coset_log2)
        .map_err(map_aggregate_error_v1)?;
    let fixed_coset = der_fixed_columns_on_coset_v1(schedule, layout, plan.quotient_coset_log2)?;
    if base_coset
        .iter()
        .chain(&aux_coset)
        .any(|column| column.len() != plan.quotient_coset_rows)
        || fixed_coset
            .iter()
            .any(|column| column.len() != plan.quotient_coset_rows)
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let mut numerators = (0..SECURITY_LANES)
        .map(|_| {
            let mut numerator = ZeroizingExtensionColumnV1(Vec::new());
            numerator
                .0
                .try_reserve_exact(plan.quotient_coset_rows)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            Ok::<_, ZkX509StarkErrorV1>(numerator)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut residues = Vec::new();
    residues
        .try_reserve_exact(ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for index in 0..plan.quotient_coset_rows {
        let next = (index + plan.quotient_next_stride) % plan.quotient_coset_rows;
        let current_base: [F; ZK_X509_DER_STARK_BASE_WIDTH_V1] =
            core::array::from_fn(|column| base_coset[column][index]);
        let next_base: [F; ZK_X509_DER_STARK_BASE_WIDTH_V1] =
            core::array::from_fn(|column| base_coset[column][next]);
        let current_aux: [F; ZK_X509_DER_STARK_AUX_WIDTH_V1] =
            core::array::from_fn(|column| aux_coset[column][index]);
        let next_aux: [F; ZK_X509_DER_STARK_AUX_WIDTH_V1] =
            core::array::from_fn(|column| aux_coset[column][next]);
        let current_fixed: [F; ZK_X509_DER_STARK_FIXED_WIDTH_V1] =
            core::array::from_fn(|column| fixed_coset[column][index]);
        let next_fixed: [F; ZK_X509_DER_STARK_FIXED_WIDTH_V1] =
            core::array::from_fn(|column| fixed_coset[column][next]);
        evaluate_zk_x509_der_stark_residues_into_v1(
            &current_base,
            &next_base,
            &current_aux,
            &next_aux,
            &current_fixed,
            &next_fixed,
            challenges,
            public,
            claims,
            &mut residues,
        )
        .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
        if residues.len() != ZK_X509_DER_STARK_CONSTRAINT_COUNT_V1 {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        for lane in 0..SECURITY_LANES {
            numerators[lane].0.push(
                residues
                    .iter()
                    .zip(&alphas[lane])
                    .fold(E::ZERO, |sum, (residue, alpha)| {
                        sum.add(alpha.mul_base(*residue))
                    }),
            );
        }
    }
    drop(base_coset);
    drop(aux_coset);
    drop(fixed_coset);
    let shared_layout = AggregateProofLayoutV1::for_segments(&[layout])?.as_shared()?;
    let mut evaluations = Vec::new();
    let mut coefficient_chunks = Vec::new();
    evaluations
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    coefficient_chunks
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for numerator in &numerators {
        let quotient = ZeroizingExtensionColumnV1(
            aggregate::quotient_evaluations_from_constraint_coset_v1(
                numerator,
                layout.trace_log2,
                plan.quotient_coset_log2,
            )
            .map_err(map_aggregate_error_v1)?,
        );
        let chunks = aggregate::composition_chunks_from_quotient_coset_v1(
            &quotient,
            plan.quotient_coset_log2,
            plan.maximum_quotient_degree,
            AGGREGATE_PARAMETERS_V1,
            &shared_layout,
        )
        .map_err(map_aggregate_error_v1)?;
        // This standalone cfg(test) producer exercises the generic aggregate
        // relation, whose decomposition uses the full FRI cap. Derive its
        // coefficient view from those exact codewords; production MAIN uses
        // the independently blinded decomposition and matching OODS stride.
        let mut lane_coefficients =
            ZeroizingExtensionChunksV1::new(Vec::new(), zeroize_extension_chunks_v1);
        for chunk in &chunks {
            let coefficients = fp4_coset_coefficients_v1(chunk, layout.lde_log2)?;
            let cap = shared_layout
                .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
                .map_err(map_aggregate_error_v1)?;
            if coefficients.0[cap..].iter().any(|value| *value != E::ZERO) {
                return Err(ZkX509StarkErrorV1::ConstraintOpening);
            }
            let mut retained = ZeroizingExtensionColumnV1(Vec::new());
            retained
                .0
                .try_reserve_exact(cap)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            retained.0.extend_from_slice(&coefficients[..cap]);
            lane_coefficients.push(core::mem::take(&mut retained.0));
        }
        coefficient_chunks.push(lane_coefficients.into_vec());
        evaluations.push(chunks);
    }
    Ok(RetainedCompositionMaterialV1 {
        evaluations,
        coefficient_chunks,
    })
}
#[cfg(test)]
fn accumulate_base_deep_quotient_v1(
    coefficients: &[F],
    point: E,
    expected_value: E,
    scale: E,
    accumulator: &mut [E],
) -> Result<(), ZkX509StarkErrorV1> {
    let Some((&constant, higher)) = coefficients.split_first() else {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    };
    if higher.len() > accumulator.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let Some((&leading, middle)) = higher.split_last() else {
        if E::from_base(constant) != expected_value {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        return Ok(());
    };
    let mut quotient_coefficient = E::from_base(leading);
    accumulator[middle.len()] = accumulator[middle.len()].add(quotient_coefficient.mul(scale));
    for (degree, coefficient) in middle.iter().copied().enumerate().rev() {
        quotient_coefficient = E::from_base(coefficient).add(point.mul(quotient_coefficient));
        accumulator[degree] = accumulator[degree].add(quotient_coefficient.mul(scale));
    }
    if E::from_base(constant).add(point.mul(quotient_coefficient)) != expected_value {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn accumulate_extension_deep_quotient_v1(
    coefficients: &[E],
    point: E,
    expected_value: E,
    scale: E,
    accumulator: &mut [E],
) -> Result<(), ZkX509StarkErrorV1> {
    let Some((&constant, higher)) = coefficients.split_first() else {
        if expected_value != E::ZERO {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        return Ok(());
    };
    if higher.len() > accumulator.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let Some((&leading, middle)) = higher.split_last() else {
        if constant != expected_value {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        return Ok(());
    };
    let mut quotient_coefficient = leading;
    accumulator[middle.len()] = accumulator[middle.len()].add(quotient_coefficient.mul(scale));
    for (degree, coefficient) in middle.iter().copied().enumerate().rev() {
        quotient_coefficient = coefficient.add(point.mul(quotient_coefficient));
        accumulator[degree] = accumulator[degree].add(quotient_coefficient.mul(scale));
    }
    if constant.add(point.mul(quotient_coefficient)) != expected_value {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn evaluate_retained_composition_coefficients_at_deep_v1(
    coefficient_chunks: &[Vec<Vec<E>>],
    point: E,
) -> Result<Vec<Vec<E>>, ZkX509StarkErrorV1> {
    if !point.is_canonical()
        || coefficient_chunks.len() != SECURITY_LANES
        || coefficient_chunks
            .iter()
            .any(|lane| lane.len() != COMPOSITION_DEGREE_CHUNKS)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let coefficient_cap = 1_usize
        .checked_shl(u32::from(
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1
                .checked_sub(TERMINAL_LOG2)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
        ))
        .and_then(|fold_factor| (TERMINAL_DEGREE_BOUND + 1).checked_mul(fold_factor))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if coefficient_chunks.iter().flatten().any(|coefficients| {
        coefficients.len() > coefficient_cap
            || coefficients
                .iter()
                .any(|coefficient| !coefficient.is_canonical())
    }) {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(coefficient_chunks
        .iter()
        .map(|lane| {
            lane.iter()
                .map(|coefficients| {
                    coefficients
                        .iter()
                        .rev()
                        .copied()
                        .fold(E::ZERO, |value, coefficient| {
                            value.mul(point).add(coefficient)
                        })
                })
                .collect()
        })
        .collect())
}
#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn der_fri_bases_from_polynomials_v1(
    layout: SegmentLayoutV1,
    base_polynomials: &aggregate::MaskedTracePolynomialSetV1,
    aux_polynomials: &aggregate::MaskedTracePolynomialSetV1,
    composition_coefficients: &[Vec<Vec<E>>],
    mixes: &[FriMixV1],
    deep_point: E,
    deep_trace: &aggregate::AggregateOpenedDeepTraceGroupV1,
    deep_compositions: &[Vec<E>],
) -> Result<Vec<Vec<E>>, ZkX509StarkErrorV1> {
    let _plan = der_retained_prover_allocation_plan_v1(layout)?;
    if base_polynomials.width() != ZK_X509_DER_STARK_BASE_WIDTH_V1
        || aux_polynomials.width() != ZK_X509_DER_STARK_AUX_WIDTH_V1
        || base_polynomials.native_trace_log2() != layout.trace_log2
        || aux_polynomials.native_trace_log2() != layout.trace_log2
        || base_polynomials.commitment_lde_log2() != layout.lde_log2
        || aux_polynomials.commitment_lde_log2() != layout.lde_log2
        || composition_coefficients.len() != SECURITY_LANES
        || composition_coefficients
            .iter()
            .any(|lane| lane.len() != COMPOSITION_DEGREE_CHUNKS)
        || mixes.len() != SECURITY_LANES
        || mixes.iter().any(|mix| {
            mix.base.len() != ZK_X509_DER_STARK_BASE_WIDTH_V1
                || mix.base_next.len() != ZK_X509_DER_STARK_BASE_WIDTH_V1
                || mix.aux.len() != ZK_X509_DER_STARK_AUX_WIDTH_V1
                || mix.aux_next.len() != ZK_X509_DER_STARK_AUX_WIDTH_V1
                || mix.composition.len() != COMPOSITION_DEGREE_CHUNKS
        })
        || deep_trace.base_current.len() != ZK_X509_DER_STARK_BASE_WIDTH_V1
        || deep_trace.base_next.len() != ZK_X509_DER_STARK_BASE_WIDTH_V1
        || deep_trace.aux_current.len() != ZK_X509_DER_STARK_AUX_WIDTH_V1
        || deep_trace.aux_next.len() != ZK_X509_DER_STARK_AUX_WIDTH_V1
        || deep_compositions.len() != SECURITY_LANES
        || deep_compositions
            .iter()
            .any(|values| values.len() != COMPOSITION_DEGREE_CHUNKS)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let shared_layout = AggregateProofLayoutV1::for_segments(&[layout])?.as_shared()?;
    let coefficient_cap = shared_layout
        .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
        .map_err(map_aggregate_error_v1)?;
    let native_root =
        goldilocks_primitive_root_v1(layout.trace_log2).map_err(map_transparent_error_v1)?;
    let deep_next_point = deep_point.mul_base(native_root);
    let mut accumulators = (0..SECURITY_LANES)
        .map(|_| {
            let mut accumulator = ZeroizingExtensionColumnV1(Vec::new());
            accumulator
                .0
                .try_reserve_exact(coefficient_cap)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            accumulator.0.resize(coefficient_cap, E::ZERO);
            Ok::<_, ZkX509StarkErrorV1>(accumulator)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for column in 0..base_polynomials.width() {
        let coefficients = base_polynomials
            .column_coefficients_v1(column)
            .map_err(map_aggregate_error_v1)?;
        for lane in 0..SECURITY_LANES {
            accumulate_base_deep_quotient_v1(
                coefficients,
                deep_point,
                deep_trace.base_current[column],
                mixes[lane].base[column],
                &mut accumulators[lane].0,
            )?;
            accumulate_base_deep_quotient_v1(
                coefficients,
                deep_next_point,
                deep_trace.base_next[column],
                mixes[lane].base_next[column],
                &mut accumulators[lane].0,
            )?;
        }
    }
    for column in 0..aux_polynomials.width() {
        let coefficients = aux_polynomials
            .column_coefficients_v1(column)
            .map_err(map_aggregate_error_v1)?;
        for lane in 0..SECURITY_LANES {
            accumulate_base_deep_quotient_v1(
                coefficients,
                deep_point,
                deep_trace.aux_current[column],
                mixes[lane].aux[column],
                &mut accumulators[lane].0,
            )?;
            accumulate_base_deep_quotient_v1(
                coefficients,
                deep_next_point,
                deep_trace.aux_next[column],
                mixes[lane].aux_next[column],
                &mut accumulators[lane].0,
            )?;
        }
    }
    for lane in 0..SECURITY_LANES {
        for chunk in 0..COMPOSITION_DEGREE_CHUNKS {
            accumulate_extension_deep_quotient_v1(
                &composition_coefficients[lane][chunk],
                deep_point,
                deep_compositions[lane][chunk],
                mixes[lane].composition[chunk],
                &mut accumulators[lane].0,
            )?;
        }
    }
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    accumulators
        .iter()
        .map(|coefficients| {
            goldilocks_fp4_evaluate_coset_v1(
                coefficients,
                layout.lde_size(),
                lde_root,
                F(GOLDILOCKS_GENERATOR_V1),
            )
            .map_err(map_transparent_error_v1)
        })
        .collect()
}
#[cfg(test)]
fn row_tree_v1(
    domain: &[u8],
    node_domain: &'static [u8],
    segment: usize,
    columns: &[Vec<F>],
    rows: usize,
) -> Result<PrivacyOuterMerkleTreeV1, ZkX509StarkErrorV1> {
    aggregate::row_tree_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        domain,
        node_domain,
        segment,
        columns,
        rows,
    )
    .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn composition_tree_v1(
    lane: usize,
    chunks: &[Vec<E>],
) -> Result<PrivacyOuterMerkleTreeV1, ZkX509StarkErrorV1> {
    aggregate::composition_tree_v1(&AGGREGATE_DOMAINS_V1, lane, chunks)
        .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn fri_tree_v1(
    lane: usize,
    round: usize,
    values: &[E],
) -> Result<PrivacyOuterMerkleTreeV1, ZkX509StarkErrorV1> {
    aggregate::fri_tree_v1(
        &AGGREGATE_DOMAINS_V1,
        AGGREGATE_PARAMETERS_V1.fri_commitment_layout,
        lane,
        round,
        values,
    )
    .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn new_transcript_v1(
    public_digest: &PrivacyOuterDigestV1,
) -> Result<TransparentTranscriptV1, ZkX509StarkErrorV1> {
    let compiled_profile_digest = recompute_zk_x509_compiled_profile_digest_v1()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let compiled_profile_digest = privacy_outer_digest_frame_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        b"iroha:privacy:zk-x509:stark:compiled-profile:v1",
        b"compiled-profile",
        0,
        0,
        0,
        &[&compiled_profile_digest],
    )
    .map_err(map_transparent_error_v1)?;
    let mut transcript = TransparentTranscriptV1::new(
        ZK_X509_DIGEST_CONTEXT_V1,
        ZK_X509_SUITE_V1,
        &compiled_profile_digest,
        public_digest,
    )
    .map_err(map_transparent_error_v1)?;
    transcript
        .absorb(
            b"zk-x509-segmented-stark-profile-v1",
            &[ZK_X509_SEGMENTED_STARK_DESCRIPTOR_V1],
        )
        .map_err(map_transparent_error_v1)?;
    Ok(transcript)
}
/// Construct the release-only MAIN transcript from the sole compiled profile.
fn new_main_transcript_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public_digest: &[u8; 32],
    verifier_profile: ZkX509MainVerifierProfileV1,
) -> Result<TransparentTranscriptV1, ZkX509StarkErrorV1> {
    validate_zk_x509_main_verifier_profile_v1(verifier_profile)?;
    new_main_transcript_after_profile_validation_v1(
        proof_instance,
        public_digest,
        verifier_profile.compiled_profile_digest,
    )
}
/// Initialize MAIN after the independent release-profile validation step.
///
/// This split mirrors the MAIN base-commitment session: production reaches it
/// only through `new_main_transcript_v1`, while tests can exercise transcript
/// separation before the sole compiled-manifest pin is installed.
fn new_main_transcript_after_profile_validation_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public_digest: &[u8; 32],
    release_profile_digest: [u8; 32],
) -> Result<TransparentTranscriptV1, ZkX509StarkErrorV1> {
    if release_profile_digest == [0_u8; 32] {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let transcript_profile_digest = privacy_outer_digest_frame_v1(
        proof_instance.main_context_v1(),
        b"iroha:privacy:zk-x509:stark:release-profile:v1",
        b"release-profile",
        0,
        0,
        0,
        &[&release_profile_digest],
    )
    .map_err(map_transparent_error_v1)?;
    let transcript_public_digest = privacy_outer_digest_frame_v1(
        proof_instance.main_context_v1(),
        b"iroha:privacy:zk-x509:stark:main-public:v1",
        b"consensus-context",
        0,
        0,
        0,
        &[public_digest],
    )
    .map_err(map_transparent_error_v1)?;
    let mut transcript = TransparentTranscriptV1::new(
        proof_instance.main_context_v1(),
        ZK_X509_SUITE_V1,
        &transcript_profile_digest,
        &transcript_public_digest,
    )
    .map_err(map_transparent_error_v1)?;
    transcript
        .absorb(
            b"zk-x509-segmented-stark-profile-v1",
            &[ZK_X509_SEGMENTED_STARK_DESCRIPTOR_V1],
        )
        .map_err(map_transparent_error_v1)?;
    transcript
        .absorb(
            b"zk-x509-main-release-profile-v1",
            &[&release_profile_digest],
        )
        .map_err(map_transparent_error_v1)?;
    Ok(transcript)
}
fn absorb_aggregate_layout_v1(
    proof_instance: ZkX509ProofInstanceV1,
    transcript: &mut TransparentTranscriptV1,
    layout_domain: &[u8],
    layout: &AggregateProofLayoutV1,
) -> Result<(), ZkX509StarkErrorV1> {
    if transcript.context() != proof_instance.main_context_v1() {
        return Err(ZkX509StarkErrorV1::TranscriptMismatch);
    }
    layout.validate()?;
    let registration_count = u16::try_from(layout.registered_segments.len())
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let mut registration = Vec::new();
    registration
        .try_reserve_exact(
            6_usize
                .checked_add(
                    layout
                        .registered_segments
                        .len()
                        .checked_mul(33)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                )
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
        )
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    registration.extend_from_slice(b"X5R1");
    append_u16_v1(&mut registration, registration_count);
    for registered in &layout.registered_segments {
        append_u16_v1(&mut registration, registered.segment.adapter.wire());
        append_u16_v1(&mut registration, registered.segment.instance);
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.trace_group)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        append_u32_v1(
            &mut registration,
            u32::try_from(registered.segment.active_rows)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        registration.push(registered.segment.trace_log2);
        registration.push(registered.segment.lde_log2);
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.base_start)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.segment.base_width)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.aux_start).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.segment.aux_width)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.segment.fixed_width)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.segment.constraint_count)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
        registration.push(registered.segment.constraint_degree);
        append_u16_v1(
            &mut registration,
            u16::try_from(registered.column_chunks)
                .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
        );
    }
    transcript
        .absorb(
            b"zk-x509-registered-segment-layout-v1",
            &[layout_domain, &registration],
        )
        .map_err(map_transparent_error_v1)?;
    aggregate::absorb_layout_v1(
        transcript,
        layout.parameters_v1(),
        &main_domains_v1(proof_instance),
        layout_domain,
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)
}
/// Bind one exact role-specific P-256 registration before base commitments.
#[cfg(test)]
fn absorb_p256_registration_v1(
    transcript: &mut TransparentTranscriptV1,
    registration: &P256TraceRegistrationV1,
) -> Result<(), ZkX509StarkErrorV1> {
    registration.validate()?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        transcript,
        P256_LAYOUT_DOMAIN_V1,
        &registration.layout,
    )?;
    let role = [match registration.role {
        P256EcdsaRoleV1::CertificateOrCrl => 1,
        P256EcdsaRoleV1::WalletOwnership => 2,
    }];
    let segment_count = u16::try_from(registration.layout.registered_segments.len())
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?
        .to_be_bytes();
    transcript
        .absorb(
            b"zk-x509-p256-aggregate-adapter-profile-v1",
            &[
                ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_V1,
                &ZK_X509_P256_AGGREGATE_ADAPTER_DESCRIPTOR_SHA256_V1,
            ],
        )
        .map_err(map_transparent_error_v1)?;
    transcript
        .absorb(
            P256_REGISTRATION_DOMAIN_V1,
            &[b"X5E1", &role, &segment_count],
        )
        .map_err(map_transparent_error_v1)
}
/// Bind all proof-carried P-256 terminals after auxiliary roots.
#[cfg(test)]
fn absorb_p256_terminal_registration_v1(
    transcript: &mut TransparentTranscriptV1,
    role: P256EcdsaRoleV1,
    terminals: &P256TerminalRegistrationV1,
) -> Result<(), ZkX509StarkErrorV1> {
    terminals.validate(role)?;
    absorb_p256_terminal_claims_v1(
        transcript,
        role,
        terminals.buses,
        &terminals.cross_sources,
        terminals.sink,
    )
    .map_err(ZkX509StarkErrorV1::from)
}
/// Absorb DER terminal claims in the sole legal cross-adapter role order:
/// input bytes first, parsed-node events second, and lane order within role.
///
/// Provers and verifiers call this only after all auxiliary roots and before
/// deriving constraint alphas, FRI mixes, or queries.
#[cfg(test)]
fn absorb_der_terminal_claims_v1(
    transcript: &mut TransparentTranscriptV1,
    claims: ZkX509DerStarkTerminalClaimsV1,
) -> Result<(), ZkX509StarkErrorV1> {
    if claims
        .input_byte
        .iter()
        .chain(&claims.node)
        .any(|value| F::canonical(value.0).is_none())
    {
        return Err(ZkX509StarkErrorV1::InvalidStatement);
    }
    let mut encoding = Vec::new();
    encoding
        .try_reserve_exact(4 + 2 + 2 + 2 + 2 * (2 + 2 + 3 * 8))
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    encoding.extend_from_slice(b"X5C1");
    append_u16_v1(&mut encoding, SegmentAdapterIdV1::StrictDer.wire());
    append_u16_v1(&mut encoding, 0);
    append_u16_v1(&mut encoding, 2);
    for (role, lanes) in [(1_u16, claims.input_byte), (2_u16, claims.node)] {
        append_u16_v1(&mut encoding, role);
        append_u16_v1(
            &mut encoding,
            u16::try_from(lanes.len()).expect("DER lane count fits u16"),
        );
        for value in lanes {
            append_u64_v1(&mut encoding, value.0);
        }
    }
    transcript
        .absorb(DER_TERMINAL_CLAIMS_DOMAIN, &[&encoding])
        .map_err(map_transparent_error_v1)
}
#[cfg(test)]
fn encode_der_segmented_proof_envelope_v1(
    claims: ZkX509DerStarkTerminalClaimsV1,
    aggregate_proof: &[u8],
) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
    if aggregate_proof.is_empty()
        || aggregate_proof.len() > u32::MAX as usize
        || claims
            .input_byte
            .iter()
            .chain(&claims.node)
            .any(|value| F::canonical(value.0).is_none())
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let encoded_len = DER_PROOF_ENVELOPE_BYTES_V1
        .checked_add(aggregate_proof.len())
        .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
    if encoded_len > ZK_X509_MAX_PROOF_BYTES_V1 as usize {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    encoded.extend_from_slice(&DER_PROOF_MAGIC_V1);
    append_u16_v1(&mut encoded, ZK_X509_PROOF_VERSION_V1);
    append_u16_v1(&mut encoded, SegmentAdapterIdV1::StrictDer.wire());
    append_u16_v1(&mut encoded, 0);
    append_u16_v1(
        &mut encoded,
        u16::try_from(DER_PROOF_CLAIM_COUNT_V1).expect("DER claim count fits u16"),
    );
    for (claim_type, values) in [(1_u16, claims.input_byte), (2_u16, claims.node)] {
        for (lane, value) in values.into_iter().enumerate() {
            append_u16_v1(&mut encoded, claim_type);
            append_u16_v1(
                &mut encoded,
                u16::try_from(lane).expect("DER lane fits u16"),
            );
            append_u64_v1(&mut encoded, value.0);
        }
    }
    append_u32_v1(
        &mut encoded,
        u32::try_from(aggregate_proof.len()).map_err(|_| ZkX509StarkErrorV1::ProofTooLarge)?,
    );
    encoded.extend_from_slice(aggregate_proof);
    if encoded.len() != encoded_len {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(encoded)
}
#[cfg(test)]
fn decode_der_segmented_proof_envelope_v1(
    encoded: &[u8],
) -> Result<(ZkX509DerStarkTerminalClaimsV1, &[u8]), ZkX509StarkErrorV1> {
    if encoded.len() > ZK_X509_MAX_PROOF_BYTES_V1 as usize {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    if encoded.len() < DER_PROOF_ENVELOPE_BYTES_V1
        || encoded[..4] != DER_PROOF_MAGIC_V1
        || u16::from_be_bytes(
            encoded[4..6]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        ) != ZK_X509_PROOF_VERSION_V1
        || u16::from_be_bytes(
            encoded[6..8]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        ) != SegmentAdapterIdV1::StrictDer.wire()
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        ) != 0
        || usize::from(u16::from_be_bytes(
            encoded[10..12]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        )) != DER_PROOF_CLAIM_COUNT_V1
    {
        return Err(ZkX509StarkErrorV1::MalformedProof);
    }
    let mut fields = [F::ZERO; DER_PROOF_CLAIM_COUNT_V1];
    for (claim_index, slot) in fields.iter_mut().enumerate() {
        let start = 12_usize
            .checked_add(
                claim_index
                    .checked_mul(DER_PROOF_CLAIM_RECORD_BYTES_V1)
                    .ok_or(ZkX509StarkErrorV1::MalformedProof)?,
            )
            .ok_or(ZkX509StarkErrorV1::MalformedProof)?;
        let expected_type = if claim_index < ZK_X509_DER_STARK_BUS_LANES_V1 {
            1
        } else {
            2
        };
        let expected_lane = u16::try_from(claim_index % ZK_X509_DER_STARK_BUS_LANES_V1)
            .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?;
        let actual_type = u16::from_be_bytes(
            encoded[start..start + 2]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        );
        let actual_lane = u16::from_be_bytes(
            encoded[start + 2..start + 4]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        );
        if actual_type != expected_type || actual_lane != expected_lane {
            return Err(ZkX509StarkErrorV1::MalformedProof);
        }
        let raw = u64::from_be_bytes(
            encoded[start + 4..start + DER_PROOF_CLAIM_RECORD_BYTES_V1]
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
        );
        *slot = F::canonical(raw).ok_or(ZkX509StarkErrorV1::NonCanonicalField)?;
    }
    let aggregate_len = usize::try_from(u32::from_be_bytes(
        encoded[DER_PROOF_LENGTH_OFFSET_V1..DER_PROOF_ENVELOPE_BYTES_V1]
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?,
    ))
    .map_err(|_| ZkX509StarkErrorV1::MalformedProof)?;
    let expected_len = DER_PROOF_ENVELOPE_BYTES_V1
        .checked_add(aggregate_len)
        .ok_or(ZkX509StarkErrorV1::MalformedProof)?;
    if aggregate_len == 0 || encoded.len() != expected_len {
        return Err(ZkX509StarkErrorV1::MalformedProof);
    }
    let claims = ZkX509DerStarkTerminalClaimsV1 {
        input_byte: fields[..ZK_X509_DER_STARK_BUS_LANES_V1]
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
        node: fields[ZK_X509_DER_STARK_BUS_LANES_V1..]
            .try_into()
            .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
    };
    Ok((claims, &encoded[DER_PROOF_ENVELOPE_BYTES_V1..]))
}
#[cfg(test)]
fn evaluate_der_terminal_claim_opening_v1(
    last_aggregate: F,
    aux: &[F],
    claims: ZkX509DerStarkTerminalClaimsV1,
) -> Result<[F; 2 * ZK_X509_DER_STARK_BUS_LANES_V1], ZkX509StarkErrorV1> {
    let aux: &[F; ZK_X509_DER_STARK_AUX_WIDTH_V1] = aux
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    Ok(evaluate_zk_x509_der_stark_terminal_claim_residues_v1(
        last_aggregate,
        aux,
        claims,
    ))
}
fn challenge_vector_v1(
    transcript: &mut TransparentTranscriptV1,
    label: &[u8],
    count: usize,
) -> Result<Vec<E>, ZkX509StarkErrorV1> {
    (0..count)
        .map(|_| {
            transcript
                .challenge_fp4(label)
                .map_err(map_transparent_error_v1)
        })
        .collect()
}
#[derive(Clone)]
struct FriMixV1 {
    base: Vec<E>,
    base_next: Vec<E>,
    aux: Vec<E>,
    aux_next: Vec<E>,
    composition: Vec<E>,
}
fn derive_constraint_alphas_v1(
    transcript: &mut TransparentTranscriptV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<Vec<Vec<E>>>, ZkX509StarkErrorV1> {
    layout
        .registered_segments
        .iter()
        .map(|registration| {
            (0..SECURITY_LANES)
                .map(|_| {
                    challenge_vector_v1(
                        transcript,
                        b"zk-x509-constraint-alpha-v1",
                        registration.segment.constraint_count,
                    )
                })
                .collect()
        })
        .collect()
}
fn derive_fri_mixes_v1(
    transcript: &mut TransparentTranscriptV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<Vec<FriMixV1>>, ZkX509StarkErrorV1> {
    let composition_chunks = layout.parameters_v1().composition_degree_chunks;
    let composition = (0..SECURITY_LANES)
        .map(|_| {
            challenge_vector_v1(
                transcript,
                b"zk-x509-fri-composition-mix-v1",
                composition_chunks,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    layout
        .trace_groups
        .iter()
        .map(|group| {
            (0..SECURITY_LANES)
                .map(|lane| {
                    Ok(FriMixV1 {
                        base: challenge_vector_v1(
                            transcript,
                            b"zk-x509-deep-base-current-mix-v1",
                            group.base_width,
                        )?,
                        base_next: challenge_vector_v1(
                            transcript,
                            b"zk-x509-deep-base-next-mix-v1",
                            group.base_width,
                        )?,
                        aux: challenge_vector_v1(
                            transcript,
                            b"zk-x509-deep-aux-current-mix-v1",
                            group.aux_width,
                        )?,
                        aux_next: challenge_vector_v1(
                            transcript,
                            b"zk-x509-deep-aux-next-mix-v1",
                            group.aux_width,
                        )?,
                        composition: composition[lane].clone(),
                    })
                })
                .collect()
        })
        .collect()
}
fn aggregate_deep_lane_mixes_v1(
    mixes: &[Vec<FriMixV1>],
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<aggregate::AggregateDeepLaneMixV1>, ZkX509StarkErrorV1> {
    if mixes.len() != layout.trace_groups.len()
        || mixes.iter().any(|lanes| lanes.len() != SECURITY_LANES)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut lane_mixes = Vec::with_capacity(SECURITY_LANES);
    for lane in 0..SECURITY_LANES {
        let trace_groups = mixes
            .iter()
            .map(|lanes| {
                let mix = lanes.get(lane).ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
                Ok(aggregate::AggregateDeepTraceGroupMixV1 {
                    base_current: mix.base.clone(),
                    base_next: mix.base_next.clone(),
                    aux_current: mix.aux.clone(),
                    aux_next: mix.aux_next.clone(),
                })
            })
            .collect::<Result<Vec<_>, ZkX509StarkErrorV1>>()?;
        let composition = mixes
            .first()
            .and_then(|lanes| lanes.get(lane))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .composition
            .clone();
        if mixes
            .iter()
            .any(|lanes| lanes.get(lane).map(|mix| &mix.composition) != Some(&composition))
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        lane_mixes.push(aggregate::AggregateDeepLaneMixV1 {
            trace_groups,
            composition,
        });
    }
    aggregate::validate_deep_lane_mixes_v1(
        &lane_mixes,
        layout.parameters_v1(),
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)?;
    Ok(lane_mixes)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn canonical_deep_values_v1(
    deep: &aggregate::AggregateDeepProofV1,
    layout: &AggregateProofLayoutV1,
) -> Result<(Vec<aggregate::AggregateOpenedDeepTraceGroupV1>, Vec<Vec<E>>), ZkX509StarkErrorV1> {
    let shared_layout = layout.as_shared()?;
    let parameters = layout.parameters_v1();
    let trace_groups = aggregate::canonical_deep_trace_groups_v1(deep, parameters, &shared_layout)
        .map_err(map_aggregate_error_v1)?;
    let composition_values = deep
        .composition_values
        .iter()
        .map(|values| {
            aggregate::canonical_fp4_fields_v1(values, parameters.composition_degree_chunks)
                .map_err(map_aggregate_error_v1)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((trace_groups, composition_values))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn fp4_values_to_wire_v1(values: Vec<E>) -> Vec<[u64; 4]> {
    values
        .into_iter()
        .map(|value| value.coefficients().map(F::value))
        .collect()
}
#[cfg(test)]
fn composition_lanes_v1(
    material: &IoTraceMaterialV1,
    base_lde: &[Vec<F>],
    aux_lde: &[Vec<F>],
    fixed_lde: &[Vec<F>],
    challenges: ZkX509IoChallengesV1,
    alphas: &[Vec<E>],
) -> Result<Vec<Vec<Vec<E>>>, ZkX509StarkErrorV1> {
    if alphas.len() != SECURITY_LANES
        || alphas
            .iter()
            .any(|lane| lane.len() != material.layout.constraint_count)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let layout = material.layout;
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    let mut x = F(GOLDILOCKS_GENERATOR_V1);
    let mut lanes = (0..SECURITY_LANES)
        .map(|_| Vec::with_capacity(layout.lde_size()))
        .collect::<Vec<_>>();
    for index in 0..layout.lde_size() {
        let next = (index + BLOWUP) % layout.lde_size();
        let residues = io_constraint_residues_v1(
            layout,
            material.logical_active_rows,
            &row_at_v1(base_lde, index)?,
            &row_at_v1(base_lde, next)?,
            &row_at_v1(aux_lde, index)?,
            &row_at_v1(aux_lde, next)?,
            &row_at_v1(fixed_lde, index)?,
            challenges,
        )?;
        let inverse_vanishing = x
            .pow(layout.trace_size() as u128)
            .sub(F::ONE)
            .inv()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        for lane in 0..SECURITY_LANES {
            let value = residues
                .iter()
                .zip(&alphas[lane])
                .fold(E::ZERO, |sum, (residue, alpha)| {
                    sum.add(alpha.mul_base(*residue))
                })
                .mul_base(inverse_vanishing);
            lanes[lane].push(value);
        }
        x = x.mul(lde_root);
    }
    let shared_layout = AggregateProofLayoutV1::for_segments(&[layout])?.as_shared()?;
    lanes
        .iter()
        .map(|lane| {
            aggregate::split_composition_evaluations_v1(
                lane,
                AGGREGATE_PARAMETERS_V1,
                &shared_layout,
            )
            .map_err(map_aggregate_error_v1)
        })
        .collect()
}
#[cfg(test)]
fn quotient_value_v1(
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    x: F,
    current_base: &[F],
    next_base: &[F],
    current_aux: &[F],
    next_aux: &[F],
    fixed: &[F],
    challenges: ZkX509IoChallengesV1,
    alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    let residues = io_constraint_residues_v1(
        layout,
        logical_active_rows,
        current_base,
        next_base,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )?;
    if residues.len() != alphas.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let inverse_vanishing = x
        .pow(layout.trace_size() as u128)
        .sub(F::ONE)
        .inv()
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    Ok(residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |sum, (residue, alpha)| {
            sum.add(alpha.mul_base(*residue))
        })
        .mul_base(inverse_vanishing))
}
#[cfg(test)]
fn accumulator_quotient_value_v1(
    layout: SegmentLayoutV1,
    x: F,
    residues: &[F],
    alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    if residues.len() != layout.constraint_count || alphas.len() != layout.constraint_count {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let inverse_vanishing = x
        .pow(layout.trace_size() as u128)
        .sub(F::ONE)
        .inv()
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    Ok(residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |sum, (residue, alpha)| {
            sum.add(alpha.mul_base(*residue))
        })
        .mul_base(inverse_vanishing))
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn der_quotient_value_v1(
    layout: SegmentLayoutV1,
    x: F,
    current_base: &[F],
    next_base: &[F],
    current_aux: &[F],
    next_aux: &[F],
    fixed: &[F],
    next_fixed: &[F],
    challenges: ZkX509DerStarkChallengesV1,
    public: ZkX509DerStarkPublicTerminalsV1,
    claims: ZkX509DerStarkTerminalClaimsV1,
    alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    let current_base: &[F; ZK_X509_DER_STARK_BASE_WIDTH_V1] = current_base
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_base: &[F; ZK_X509_DER_STARK_BASE_WIDTH_V1] = next_base
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let current_aux: &[F; ZK_X509_DER_STARK_AUX_WIDTH_V1] = current_aux
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_aux: &[F; ZK_X509_DER_STARK_AUX_WIDTH_V1] = next_aux
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let fixed: &[F; ZK_X509_DER_STARK_FIXED_WIDTH_V1] = fixed
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_fixed: &[F; ZK_X509_DER_STARK_FIXED_WIDTH_V1] = next_fixed
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let residues = evaluate_zk_x509_der_stark_residues_v1(
        current_base,
        next_base,
        current_aux,
        next_aux,
        fixed,
        next_fixed,
        challenges,
        public,
        claims,
    )
    .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?;
    if residues.len() != layout.constraint_count || residues.len() != alphas.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let inverse_vanishing = x
        .pow(layout.trace_size() as u128)
        .sub(F::ONE)
        .inv()
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    Ok(residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |sum, (residue, alpha)| {
            sum.add(alpha.mul_base(*residue))
        })
        .mul_base(inverse_vanishing))
}
fn projection_constraint_residues_v1<
    A: crate::privacy_engines::transparent_stark::PolynomialAirFieldV1,
>(
    current_base: &[A],
    next_base: &[A],
    current_aux: &[A],
    next_aux: &[A],
    fixed: &[A],
    challenges: ZkX509ProjectionChallengesV1,
) -> Result<Vec<A>, ZkX509StarkErrorV1> {
    let current_base: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1] = current_base
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_base: &[A; ZK_X509_PROJECTION_BASE_WIDTH_V1] = next_base
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let current_aux: &[A; ZK_X509_PROJECTION_AUX_WIDTH_V1] = current_aux
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let next_aux: &[A; ZK_X509_PROJECTION_AUX_WIDTH_V1] = next_aux
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    let fixed: &[A; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1] = fixed
        .try_into()
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    evaluate_zk_x509_projection_stark_residues_v1(
        current_base,
        next_base,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )
    .map_err(Into::into)
}
#[cfg(test)]
fn projection_composition_lanes_v1(
    material: &ProjectionTraceMaterialV1,
    base_lde: &[Vec<F>],
    aux_lde: &[Vec<F>],
    fixed_lde: &[Vec<F>],
    challenges: ZkX509ProjectionChallengesV1,
    alphas: &[Vec<E>],
) -> Result<Vec<Vec<Vec<E>>>, ZkX509StarkErrorV1> {
    if alphas.len() != SECURITY_LANES
        || alphas
            .iter()
            .any(|lane| lane.len() != material.layout.constraint_count)
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let layout = material.layout;
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    let mut x = F(GOLDILOCKS_GENERATOR_V1);
    let mut lanes = (0..SECURITY_LANES)
        .map(|_| Vec::with_capacity(layout.lde_size()))
        .collect::<Vec<_>>();
    for index in 0..layout.lde_size() {
        let next = (index + BLOWUP) % layout.lde_size();
        let residues = projection_constraint_residues_v1(
            &row_at_v1(base_lde, index)?,
            &row_at_v1(base_lde, next)?,
            &row_at_v1(aux_lde, index)?,
            &row_at_v1(aux_lde, next)?,
            &row_at_v1(fixed_lde, index)?,
            challenges,
        )?;
        if residues.len() != layout.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let inverse_vanishing = x
            .pow(layout.trace_size() as u128)
            .sub(F::ONE)
            .inv()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        for lane in 0..SECURITY_LANES {
            lanes[lane].push(
                residues
                    .iter()
                    .zip(&alphas[lane])
                    .fold(E::ZERO, |sum, (residue, alpha)| {
                        sum.add(alpha.mul_base(*residue))
                    })
                    .mul_base(inverse_vanishing),
            );
        }
        x = x.mul(lde_root);
    }
    let shared_layout = AggregateProofLayoutV1::for_segments(&[layout])?.as_shared()?;
    lanes
        .iter()
        .map(|lane| {
            aggregate::split_composition_evaluations_v1(
                lane,
                AGGREGATE_PARAMETERS_V1,
                &shared_layout,
            )
            .map_err(map_aggregate_error_v1)
        })
        .collect()
}
#[cfg(test)]
fn validate_projection_base_constraints_v1(
    material: &ProjectionTraceMaterialV1,
    challenges: ZkX509ProjectionChallengesV1,
) -> Result<(), ZkX509StarkErrorV1> {
    let rows = material.layout.trace_size();
    for index in 0..rows {
        let next = (index + 1) % rows;
        let residues = projection_constraint_residues_v1(
            &row_at_v1(&material.base_columns, index)?,
            &row_at_v1(&material.base_columns, next)?,
            &row_at_v1(&material.aux_columns, index)?,
            &row_at_v1(&material.aux_columns, next)?,
            &row_at_v1(&material.fixed_columns, index)?,
            challenges,
        )?;
        if residues.len() != material.layout.constraint_count
            || residues.iter().any(|residue| *residue != F::ZERO)
        {
            return Err(ZkX509StarkErrorV1::ProjectionWitness);
        }
    }
    Ok(())
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn projection_quotient_value_v1(
    layout: SegmentLayoutV1,
    x: F,
    current_base: &[F],
    next_base: &[F],
    current_aux: &[F],
    next_aux: &[F],
    fixed: &[F],
    challenges: ZkX509ProjectionChallengesV1,
    alphas: &[E],
) -> Result<E, ZkX509StarkErrorV1> {
    let residues = projection_constraint_residues_v1(
        current_base,
        next_base,
        current_aux,
        next_aux,
        fixed,
        challenges,
    )?;
    if residues.len() != layout.constraint_count || residues.len() != alphas.len() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let inverse_vanishing = x
        .pow(layout.trace_size() as u128)
        .sub(F::ONE)
        .inv()
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    Ok(residues
        .iter()
        .zip(alphas)
        .fold(E::ZERO, |sum, (residue, alpha)| {
            sum.add(alpha.mul_base(*residue))
        })
        .mul_base(inverse_vanishing))
}
#[cfg(test)]
fn mix_fri_base_v1(
    layout: SegmentLayoutV1,
    base_lde: &[Vec<F>],
    aux_lde: &[Vec<F>],
    composition: &[Vec<E>],
    mix: &FriMixV1,
    deep_point: E,
    deep_trace: &aggregate::AggregateOpenedDeepTraceGroupV1,
    deep_composition: &[E],
) -> Result<Vec<E>, ZkX509StarkErrorV1> {
    let rows = composition
        .first()
        .map(Vec::len)
        .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    if base_lde.len() != mix.base.len()
        || base_lde.len() != mix.base_next.len()
        || aux_lde.len() != mix.aux.len()
        || aux_lde.len() != mix.aux_next.len()
        || composition.len() != mix.composition.len()
        || deep_trace.base_current.len() != base_lde.len()
        || deep_trace.base_next.len() != base_lde.len()
        || deep_trace.aux_current.len() != aux_lde.len()
        || deep_trace.aux_next.len() != aux_lde.len()
        || deep_composition.len() != composition.len()
        || rows != layout.lde_size()
        || composition.iter().any(|chunk| chunk.len() != rows)
        || base_lde
            .iter()
            .chain(aux_lde)
            .any(|column| column.len() != rows)
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    let native_root =
        goldilocks_primitive_root_v1(layout.trace_log2).map_err(map_transparent_error_v1)?;
    let deep_next_point = deep_point.mul_base(native_root);
    let mut result = Vec::new();
    result
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for start in (0..rows).step_by(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1) {
        let end = start
            .checked_add(aggregate::DEEP_FRI_BASE_BATCH_ROWS_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .min(rows);
        let mut inverse_denominators = Vec::new();
        inverse_denominators
            .try_reserve_exact(
                end.checked_sub(start)
                    .and_then(|length| length.checked_mul(2))
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
            )
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        let mut x_base = F(GOLDILOCKS_GENERATOR_V1).mul(
            lde_root.pow(u128::try_from(start).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?),
        );
        for _ in start..end {
            let query_point = E::from_base(x_base);
            inverse_denominators.push(query_point.sub(deep_point));
            inverse_denominators.push(query_point.sub(deep_next_point));
            x_base = x_base.mul(lde_root);
        }
        aggregate::batch_invert_fp4_nonzero_v1(&mut inverse_denominators)
            .map_err(map_aggregate_error_v1)?;
        for index in start..end {
            let local_index = index - start;
            let current_inverse = inverse_denominators[2 * local_index];
            let next_inverse = inverse_denominators[2 * local_index + 1];
            let mut quotient = E::ZERO;
            for (column_index, column) in base_lde.iter().enumerate() {
                let value = E::from_base(column[index]);
                quotient = quotient.add(
                    value
                        .sub(deep_trace.base_current[column_index])
                        .mul(current_inverse)
                        .mul(mix.base[column_index]),
                );
                quotient = quotient.add(
                    value
                        .sub(deep_trace.base_next[column_index])
                        .mul(next_inverse)
                        .mul(mix.base_next[column_index]),
                );
            }
            for (column_index, column) in aux_lde.iter().enumerate() {
                let value = E::from_base(column[index]);
                quotient = quotient.add(
                    value
                        .sub(deep_trace.aux_current[column_index])
                        .mul(current_inverse)
                        .mul(mix.aux[column_index]),
                );
                quotient = quotient.add(
                    value
                        .sub(deep_trace.aux_next[column_index])
                        .mul(next_inverse)
                        .mul(mix.aux_next[column_index]),
                );
            }
            for (chunk_index, (chunk, coefficient)) in
                composition.iter().zip(&mix.composition).enumerate()
            {
                quotient = quotient.add(
                    chunk[index]
                        .sub(deep_composition[chunk_index])
                        .mul(current_inverse)
                        .mul(*coefficient),
                );
            }
            result.push(quotient);
        }
    }
    Ok(result)
}
#[cfg(test)]
fn mix_opened_composition_chunks_v1(
    chunks: &[E],
    mix: &FriMixV1,
) -> Result<E, AggregateStarkErrorV1> {
    if chunks.is_empty() || chunks.len() != mix.composition.len() {
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    Ok(chunks
        .iter()
        .zip(&mix.composition)
        .fold(E::ZERO, |sum, (value, coefficient)| {
            sum.add(value.mul(*coefficient))
        }))
}
#[cfg(test)]
fn build_fri_lane_v1(
    lane: usize,
    layout: SegmentLayoutV1,
    base_values: Vec<E>,
    transcript: &mut TransparentTranscriptV1,
) -> Result<FriLaneMaterialV1, ZkX509StarkErrorV1> {
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&[layout])?;
    let parameters = aggregate_layout.parameters_v1();
    aggregate::build_fri_lane_v1(
        parameters,
        &AGGREGATE_DOMAINS_V1,
        &aggregate_layout.as_shared()?,
        lane,
        base_values,
        transcript,
    )
    .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn maximum_encoded_aggregate_proof_bytes_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<usize, ZkX509StarkErrorV1> {
    aggregate::maximum_encoded_proof_with_deep_bytes_v1(
        layout.parameters_v1(),
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn exact_encoded_aggregate_proof_bytes_v1(
    proof: &ZkX509SegmentedStarkProofV1,
    layout: &AggregateProofLayoutV1,
) -> Result<usize, ZkX509StarkErrorV1> {
    aggregate::exact_encoded_proof_with_deep_bytes_v1(
        &proof.aggregate,
        &proof.deep,
        layout.parameters_v1(),
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn canonical_multiproof_frontier_v1(
    tree: &PrivacyOuterMerkleTreeV1,
    leaf_count: usize,
    indices: &[usize],
) -> Result<Vec<PrivacyOuterDigestV1>, ZkX509StarkErrorV1> {
    aggregate::canonical_multiproof_frontier_v1(tree, leaf_count, indices)
        .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
fn verify_canonical_multiproof_v1(
    node_domain: &[u8],
    root: &PrivacyOuterDigestV1,
    leaf_count: usize,
    leaves: &BTreeMap<usize, PrivacyOuterDigestV1>,
    frontier: &[PrivacyOuterDigestV1],
) -> Result<(), ()> {
    aggregate::verify_canonical_multiproof_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        node_domain,
        root,
        leaf_count,
        leaves,
        frontier,
    )
    .map_err(|_| ())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn encode_zk_x509_segmented_stark_proof_v1(
    proof: &ZkX509SegmentedStarkProofV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
    aggregate::encode_proof_with_deep_v1(
        &proof.aggregate,
        &proof.deep,
        layout.parameters_v1(),
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)
}
fn decode_zk_x509_segmented_stark_proof_v1(
    bytes: &[u8],
    layout: &AggregateProofLayoutV1,
) -> Result<ZkX509SegmentedStarkProofV1, ZkX509StarkErrorV1> {
    let (aggregate, deep) =
        aggregate::decode_proof_with_deep_v1(bytes, layout.parameters_v1(), &layout.as_shared()?)
            .map_err(map_aggregate_error_v1)?;
    Ok(ZkX509SegmentedStarkProofV1 { aggregate, deep })
}
fn query_indices_v1(
    proof_instance: ZkX509ProofInstanceV1,
    transcript: &TransparentTranscriptV1,
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<usize>, ZkX509StarkErrorV1> {
    if transcript.context() != proof_instance.main_context_v1() {
        return Err(ZkX509StarkErrorV1::TranscriptMismatch);
    }
    aggregate::query_indices_v1(
        transcript,
        layout.parameters_v1(),
        &main_domains_v1(proof_instance),
        &layout.as_shared()?,
    )
    .map_err(map_aggregate_error_v1)
}
fn absorb_grinding_nonce_v1(
    transcript: &mut TransparentTranscriptV1,
    nonce: u64,
) -> Result<(), ZkX509StarkErrorV1> {
    transcript
        .absorb(b"zk-x509-grinding-nonce-v1", &[&nonce.to_be_bytes()])
        .map_err(map_transparent_error_v1)
}
/// Construct the canonical byte-memory segmented proof with an injected RNG.
///
/// The injected fallible RNG is used by deterministic KATs and entropy-failure
/// tests. Production callers of this currently internal API use `OsRng`.
#[cfg(test)]
pub fn prove_zk_x509_io_segmented_stark_v1_with_rng<R: TryRngCore>(
    statement: &ZkX509IoStarkStatementV1,
    witnesses: &[ZkX509IoChannelWitnessV1],
    rng: &mut R,
) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
    validate_declarations_v1(&statement.declarations)
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let public_digest = io_public_digest_v1(statement)?;
    let (layout, base_columns, fixed_columns, execution, sorted) =
        build_io_base_and_fixed_columns_v1(statement, witnesses)?;
    let layouts = [layout];
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&layouts)?;
    let shared_layout = aggregate_layout.as_shared()?;
    let base_lde = masked_lde_columns_v1(&base_columns, layout, rng)?;
    let base_tree = row_tree_v1(
        BASE_LEAF_DOMAIN,
        BASE_NODE_DOMAIN,
        0,
        &base_lde,
        layout.lde_size(),
    )?;
    let mut transcript = new_transcript_v1(&public_digest)?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        &mut transcript,
        b"iroha:privacy:zk-x509:io-aggregate-layout:v1",
        &aggregate_layout,
    )?;
    let mut trace_group_proofs = vec![TraceGroupProofV1 {
        base_root: base_tree.root(),
        aux_root: PrivacyOuterDigestV1::default(),
        base_frontier: Vec::new(),
        aux_frontier: Vec::new(),
    }];
    aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &trace_group_proofs)
        .map_err(map_aggregate_error_v1)?;
    let io_challenges =
        derive_zk_x509_io_challenges_v1(&mut transcript).map_err(map_transparent_error_v1)?;
    let logical_active_rows = io_active_rows_v1(&statement.declarations)?;
    let aux_columns = build_io_aux_columns_v1(
        statement,
        witnesses,
        io_challenges,
        layout,
        logical_active_rows,
        &execution,
        &sorted,
    )?;
    let trace_material = IoTraceMaterialV1 {
        layout,
        logical_active_rows,
        base_columns: base_columns.into_vec(),
        aux_columns: aux_columns.into_vec(),
        fixed_columns,
    };
    validate_io_base_constraints_v1(&trace_material, io_challenges)?;
    let aux_lde = masked_lde_columns_v1(&trace_material.aux_columns, layout, rng)?;
    let aux_tree = row_tree_v1(
        AUX_LEAF_DOMAIN,
        AUX_NODE_DOMAIN,
        0,
        &aux_lde,
        layout.lde_size(),
    )?;
    trace_group_proofs[0].aux_root = aux_tree.root();
    aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &trace_group_proofs)
        .map_err(map_aggregate_error_v1)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, &aggregate_layout)?;
    let fixed_lde = fixed_lde_columns_v1(&trace_material.fixed_columns, layout)?;
    let compositions = composition_lanes_v1(
        &trace_material,
        &base_lde,
        &aux_lde,
        &fixed_lde,
        io_challenges,
        &alphas[0],
    )?;
    let mut composition_trees = Vec::with_capacity(SECURITY_LANES);
    let mut composition_roots = Vec::with_capacity(SECURITY_LANES);
    for lane in 0..SECURITY_LANES {
        let tree = composition_tree_v1(lane, &compositions[lane])?;
        composition_roots.push(tree.root());
        composition_trees.push(tree);
    }
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let fri_masks = aggregate::build_fri_mask_oracles_v1(
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        rng,
    )
    .map_err(map_aggregate_error_v1)?;
    let fri_mask_roots = fri_masks
        .iter()
        .map(|mask| mask.tree.root())
        .collect::<Vec<_>>();
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let trace_materials = vec![aggregate::AggregateTraceGroupMaterialV1 {
        base_lde,
        aux_lde,
        base_tree,
        aux_tree,
    }];
    let deep_point =
        aggregate::derive_deep_point_v1(&mut transcript, AGGREGATE_PARAMETERS_V1, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    let deep = aggregate::build_materialized_deep_proof_v1(
        &trace_materials,
        &compositions,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
        deep_point,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &deep,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let (deep_trace_groups, deep_compositions) =
        canonical_deep_values_v1(&deep, &aggregate_layout)?;
    let mixes = derive_fri_mixes_v1(&mut transcript, &aggregate_layout)?;
    let mut fri_lanes = Vec::with_capacity(SECURITY_LANES);
    for lane in 0..SECURITY_LANES {
        let mut base = mix_fri_base_v1(
            layout,
            &trace_materials[0].base_lde,
            &trace_materials[0].aux_lde,
            &compositions[lane],
            &mixes[0][lane],
            deep_point,
            &deep_trace_groups[0],
            &deep_compositions[lane],
        )?;
        aggregate::add_fri_mask_oracle_v1(&mut base, &fri_masks[lane])
            .map_err(map_aggregate_error_v1)?;
        fri_lanes.push(build_fri_lane_v1(lane, layout, base, &mut transcript)?);
    }
    let grinding_state = transcript.state();
    let grinding_nonce = grind_nonce_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        &grinding_state,
        ZK_X509_GRINDING_BITS_V1,
    )
    .map_err(map_transparent_error_v1)?;
    absorb_grinding_nonce_v1(&mut transcript, grinding_nonce)?;
    let queries = query_indices_v1(TEST_PROOF_INSTANCE_V1, &transcript, &aggregate_layout)?
        .into_iter()
        .map(|index| {
            aggregate::build_query_v1(
                AGGREGATE_PARAMETERS_V1,
                &shared_layout,
                index,
                &trace_materials,
                &compositions,
                &fri_masks,
                &fri_lanes,
            )
            .map_err(map_aggregate_error_v1)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (trace_frontiers, composition_frontiers, fri_mask_frontiers, fri_round_frontiers) =
        aggregate::build_all_frontiers_v1(
            AGGREGATE_PARAMETERS_V1,
            &shared_layout,
            &queries,
            &trace_materials,
            &composition_trees,
            &fri_masks,
            &fri_lanes,
        )
        .map_err(map_aggregate_error_v1)?;
    for (group, (base_frontier, aux_frontier)) in trace_group_proofs.iter_mut().zip(trace_frontiers)
    {
        group.base_frontier = base_frontier;
        group.aux_frontier = aux_frontier;
    }
    let proof = ZkX509SegmentedStarkProofV1 {
        aggregate: aggregate::AggregateStarkProofV1 {
            version: ZK_X509_PROOF_VERSION_V1,
            trace_groups: trace_group_proofs,
            composition_roots,
            composition_frontiers,
            fri_mask_roots,
            fri_mask_frontiers,
            fri_lanes: fri_lanes
                .into_iter()
                .zip(fri_round_frontiers)
                .map(|(lane, round_frontiers)| FriLaneProofV1 {
                    roots: lane.roots,
                    terminal_values: lane
                        .terminal_values
                        .into_iter()
                        .map(|value| value.coefficients().map(F::value))
                        .collect(),
                    round_frontiers,
                })
                .collect(),
            queries,
            grinding_nonce,
        },
        deep,
    };
    let encoded = encode_zk_x509_segmented_stark_proof_v1(&proof, &aggregate_layout)?;
    verify_zk_x509_io_segmented_stark_v1(statement, &encoded)?;
    Ok(encoded)
}
/// Prove the registered projection AIR with injected masking entropy.
///
/// This bounded proof constrains the projection trace itself. Its SHA and DER byte channels remain
/// deliberately outside this proof until the aggregate cross-segment I/O registration is complete.
#[cfg(test)]
pub fn prove_zk_x509_projection_segmented_stark_v1_with_rng<R: TryRngCore>(
    statement: &IrohaZkX509StarkP256StatementV1,
    witness: &ZkX509ProjectionWitnessV1,
    rng: &mut R,
) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
    let public_digest = projection_public_digest_v1(statement)?;
    let (layout, trace, base_columns, fixed_columns) =
        build_projection_base_material_v1(statement, witness)?;
    let layouts = [layout];
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&layouts)?;
    let shared_layout = aggregate_layout.as_shared()?;
    let base_lde = masked_lde_columns_v1(&base_columns, layout, rng)?;
    let base_tree = row_tree_v1(
        BASE_LEAF_DOMAIN,
        BASE_NODE_DOMAIN,
        0,
        &base_lde,
        layout.lde_size(),
    )?;
    let mut transcript = new_transcript_v1(&public_digest)?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        &mut transcript,
        b"iroha:privacy:zk-x509:projection-aggregate-layout:v1",
        &aggregate_layout,
    )?;
    let mut trace_group_proofs = vec![TraceGroupProofV1 {
        base_root: base_tree.root(),
        aux_root: PrivacyOuterDigestV1::default(),
        base_frontier: Vec::new(),
        aux_frontier: Vec::new(),
    }];
    aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &trace_group_proofs)
        .map_err(map_aggregate_error_v1)?;
    let projection_challenges = derive_projection_challenges_v1(&mut transcript)?;
    let material = build_projection_trace_material_v1(
        layout,
        trace,
        base_columns,
        fixed_columns,
        projection_challenges,
    )?;
    validate_projection_base_constraints_v1(&material, projection_challenges)?;
    let aux_lde = masked_lde_columns_v1(&material.aux_columns, layout, rng)?;
    let aux_tree = row_tree_v1(
        AUX_LEAF_DOMAIN,
        AUX_NODE_DOMAIN,
        0,
        &aux_lde,
        layout.lde_size(),
    )?;
    trace_group_proofs[0].aux_root = aux_tree.root();
    aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &trace_group_proofs)
        .map_err(map_aggregate_error_v1)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, &aggregate_layout)?;
    let fixed_lde = fixed_lde_columns_v1(&material.fixed_columns, layout)?;
    let compositions = projection_composition_lanes_v1(
        &material,
        &base_lde,
        &aux_lde,
        &fixed_lde,
        projection_challenges,
        &alphas[0],
    )?;
    let mut composition_trees = Vec::with_capacity(SECURITY_LANES);
    let mut composition_roots = Vec::with_capacity(SECURITY_LANES);
    for lane in 0..SECURITY_LANES {
        let tree = composition_tree_v1(lane, &compositions[lane])?;
        composition_roots.push(tree.root());
        composition_trees.push(tree);
    }
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let fri_masks = aggregate::build_fri_mask_oracles_v1(
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        rng,
    )
    .map_err(map_aggregate_error_v1)?;
    let fri_mask_roots = fri_masks
        .iter()
        .map(|mask| mask.tree.root())
        .collect::<Vec<_>>();
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let trace_materials = vec![aggregate::AggregateTraceGroupMaterialV1 {
        base_lde,
        aux_lde,
        base_tree,
        aux_tree,
    }];
    let deep_point =
        aggregate::derive_deep_point_v1(&mut transcript, AGGREGATE_PARAMETERS_V1, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    let deep = aggregate::build_materialized_deep_proof_v1(
        &trace_materials,
        &compositions,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
        deep_point,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &deep,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let (deep_trace_groups, deep_compositions) =
        canonical_deep_values_v1(&deep, &aggregate_layout)?;
    let mixes = derive_fri_mixes_v1(&mut transcript, &aggregate_layout)?;
    let mut fri_lanes = Vec::with_capacity(SECURITY_LANES);
    for lane in 0..SECURITY_LANES {
        let mut base = mix_fri_base_v1(
            layout,
            &trace_materials[0].base_lde,
            &trace_materials[0].aux_lde,
            &compositions[lane],
            &mixes[0][lane],
            deep_point,
            &deep_trace_groups[0],
            &deep_compositions[lane],
        )?;
        aggregate::add_fri_mask_oracle_v1(&mut base, &fri_masks[lane])
            .map_err(map_aggregate_error_v1)?;
        fri_lanes.push(build_fri_lane_v1(lane, layout, base, &mut transcript)?);
    }
    let grinding_state = transcript.state();
    let grinding_nonce = grind_nonce_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        &grinding_state,
        ZK_X509_GRINDING_BITS_V1,
    )
    .map_err(map_transparent_error_v1)?;
    absorb_grinding_nonce_v1(&mut transcript, grinding_nonce)?;
    let queries = query_indices_v1(TEST_PROOF_INSTANCE_V1, &transcript, &aggregate_layout)?
        .into_iter()
        .map(|index| {
            aggregate::build_query_v1(
                AGGREGATE_PARAMETERS_V1,
                &shared_layout,
                index,
                &trace_materials,
                &compositions,
                &fri_masks,
                &fri_lanes,
            )
            .map_err(map_aggregate_error_v1)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (trace_frontiers, composition_frontiers, fri_mask_frontiers, fri_round_frontiers) =
        aggregate::build_all_frontiers_v1(
            AGGREGATE_PARAMETERS_V1,
            &shared_layout,
            &queries,
            &trace_materials,
            &composition_trees,
            &fri_masks,
            &fri_lanes,
        )
        .map_err(map_aggregate_error_v1)?;
    for (group, (base_frontier, aux_frontier)) in trace_group_proofs.iter_mut().zip(trace_frontiers)
    {
        group.base_frontier = base_frontier;
        group.aux_frontier = aux_frontier;
    }
    let proof = ZkX509SegmentedStarkProofV1 {
        aggregate: aggregate::AggregateStarkProofV1 {
            version: ZK_X509_PROOF_VERSION_V1,
            trace_groups: trace_group_proofs,
            composition_roots,
            composition_frontiers,
            fri_mask_roots,
            fri_mask_frontiers,
            fri_lanes: fri_lanes
                .into_iter()
                .zip(fri_round_frontiers)
                .map(|(lane, round_frontiers)| FriLaneProofV1 {
                    roots: lane.roots,
                    terminal_values: lane
                        .terminal_values
                        .into_iter()
                        .map(|value| value.coefficients().map(F::value))
                        .collect(),
                    round_frontiers,
                })
                .collect(),
            queries,
            grinding_nonce,
        },
        deep,
    };
    let encoded = encode_zk_x509_segmented_stark_proof_v1(&proof, &aggregate_layout)?;
    verify_zk_x509_projection_segmented_stark_v1(statement, &encoded)?;
    Ok(encoded)
}
#[cfg(test)]
#[allow(clippy::too_many_lines)]
fn build_zk_x509_der_segmented_stark_proof_v1_with_rng<R: TryRngCore>(
    shape: &ZkX509DerStarkShapeV1,
    documents: &[&[u8]],
    rng: &mut R,
) -> Result<Vec<u8>, ZkX509StarkErrorV1> {
    shape
        .validate()
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let base =
        build_zk_x509_der_stark_base_v1(documents).map_err(|_| ZkX509StarkErrorV1::DerWitness)?;
    let schedule = compile_zk_x509_der_stark_fixed_schedule_v1(shape.clone())
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let layout = SegmentLayoutV1::for_der(schedule.active_rows())?;
    layout.validate()?;
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&[layout])?;
    let shared_layout = aggregate_layout.as_shared()?;
    let public_digest = der_public_digest_v1(shape)?;
    let mut transcript = new_transcript_v1(&public_digest)?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        &mut transcript,
        b"iroha:privacy:zk-x509:der-aggregate-layout:v1",
        &aggregate_layout,
    )?;
    let (base_commitment, base_polynomials) = aggregate::commit_masked_trace_polynomial_columns_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        BASE_LEAF_DOMAIN,
        BASE_NODE_DOMAIN,
        0,
        layout.trace_log2,
        layout.lde_log2,
        ZK_X509_DER_STARK_BASE_WIDTH_V1,
        MASK_DEGREE,
        &[],
        rng,
        |column| {
            build_zk_x509_der_stark_native_base_column_v1(&base, column)
                .map_err(|_| AggregateStarkErrorV1::InternalInvariant)
        },
    )
    .map_err(map_aggregate_error_v1)?;
    let mut trace_group_proofs = vec![TraceGroupProofV1 {
        base_root: base_commitment.commitment.root,
        aux_root: PrivacyOuterDigestV1::default(),
        base_frontier: Vec::new(),
        aux_frontier: Vec::new(),
    }];
    aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &trace_group_proofs)
        .map_err(map_aggregate_error_v1)?;
    let challenges = derive_der_challenges_v1(&mut transcript)?;
    let public = derive_zk_x509_der_stark_public_terminals_v1(shape, challenges)
        .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    let trace = build_zk_x509_der_stark_trace_v1(base, challenges)
        .map_err(|_| ZkX509StarkErrorV1::DerWitness)?;
    let claims =
        zk_x509_der_stark_terminal_claims_v1(&trace).map_err(|_| ZkX509StarkErrorV1::DerWitness)?;
    let (aux_commitment, aux_polynomials) = aggregate::commit_masked_trace_polynomial_columns_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        AUX_LEAF_DOMAIN,
        AUX_NODE_DOMAIN,
        0,
        layout.trace_log2,
        layout.lde_log2,
        ZK_X509_DER_STARK_AUX_WIDTH_V1,
        MASK_DEGREE,
        &[],
        rng,
        |column| {
            build_zk_x509_der_stark_native_aux_column_v1(&trace, column)
                .map_err(|_| AggregateStarkErrorV1::InternalInvariant)
        },
    )
    .map_err(map_aggregate_error_v1)?;
    // The retained masked polynomials are the sole post-commitment source.
    // Release the native 76+196-column trace before allocating the larger
    // degree-seven quotient coset.
    drop(trace);
    trace_group_proofs[0].aux_root = aux_commitment.commitment.root;
    aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &trace_group_proofs)
        .map_err(map_aggregate_error_v1)?;
    absorb_der_terminal_claims_v1(&mut transcript, claims)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, &aggregate_layout)?;
    let composition_material = der_composition_material_from_polynomials_v1(
        layout,
        &schedule,
        &base_polynomials,
        &aux_polynomials,
        challenges,
        public,
        claims,
        &alphas[0],
    )?;
    let compositions = &composition_material.evaluations;
    let mut composition_roots = Vec::new();
    composition_roots
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for (lane, composition) in compositions.iter().enumerate() {
        composition_roots.push(
            aggregate::streaming_composition_commitment_v1(
                &AGGREGATE_DOMAINS_V1,
                lane,
                composition,
                &[],
            )
            .map_err(map_aggregate_error_v1)?
            .root,
        );
    }
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let fri_masks = aggregate::build_fri_mask_oracles_v1(
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        rng,
    )
    .map_err(map_aggregate_error_v1)?;
    let fri_mask_roots = fri_masks
        .iter()
        .map(|mask| mask.tree.root())
        .collect::<Vec<_>>();
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let deep_point =
        aggregate::derive_deep_point_v1(&mut transcript, AGGREGATE_PARAMETERS_V1, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    let (base_current, base_next) = aggregate::evaluate_masked_trace_polynomial_columns_at_deep_v1(
        &base_polynomials,
        deep_point,
    )
    .map_err(map_aggregate_error_v1)?;
    let (aux_current, aux_next) = aggregate::evaluate_masked_trace_polynomial_columns_at_deep_v1(
        &aux_polynomials,
        deep_point,
    )
    .map_err(map_aggregate_error_v1)?;
    let deep_composition_values = evaluate_retained_composition_coefficients_at_deep_v1(
        &composition_material.coefficient_chunks,
        deep_point,
    )?;
    let deep = aggregate::AggregateDeepProofV1 {
        trace_groups: vec![aggregate::AggregateDeepTraceGroupOpeningV1 {
            base_current: fp4_values_to_wire_v1(base_current),
            base_next: fp4_values_to_wire_v1(base_next),
            aux_current: fp4_values_to_wire_v1(aux_current),
            aux_next: fp4_values_to_wire_v1(aux_next),
        }],
        composition_values: deep_composition_values
            .into_iter()
            .map(fp4_values_to_wire_v1)
            .collect(),
    };
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &deep,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let (deep_trace_groups, deep_compositions) =
        canonical_deep_values_v1(&deep, &aggregate_layout)?;
    let mixes = derive_fri_mixes_v1(&mut transcript, &aggregate_layout)?;
    let mut fri_bases = der_fri_bases_from_polynomials_v1(
        layout,
        &base_polynomials,
        &aux_polynomials,
        &composition_material.coefficient_chunks,
        &mixes[0],
        deep_point,
        &deep_trace_groups[0],
        &deep_compositions,
    )?;
    for (base, mask) in fri_bases.iter_mut().zip(&fri_masks) {
        aggregate::add_fri_mask_oracle_v1(base, mask).map_err(map_aggregate_error_v1)?;
    }
    let mut fri_materials = Vec::new();
    fri_materials
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for lane in 0..SECURITY_LANES {
        let base_values = core::mem::take(
            fri_bases
                .get_mut(lane)
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?,
        );
        fri_materials.push(
            aggregate::build_streaming_fri_lane_v1(
                AGGREGATE_PARAMETERS_V1,
                &AGGREGATE_DOMAINS_V1,
                &shared_layout,
                lane,
                base_values,
                &mut transcript,
            )
            .map_err(map_aggregate_error_v1)?,
        );
    }
    fri_bases = der_fri_bases_from_polynomials_v1(
        layout,
        &base_polynomials,
        &aux_polynomials,
        &composition_material.coefficient_chunks,
        &mixes[0],
        deep_point,
        &deep_trace_groups[0],
        &deep_compositions,
    )?;
    for (base, mask) in fri_bases.iter_mut().zip(&fri_masks) {
        aggregate::add_fri_mask_oracle_v1(base, mask).map_err(map_aggregate_error_v1)?;
    }
    let grinding_state = transcript.state();
    let grinding_nonce = grind_nonce_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        &grinding_state,
        ZK_X509_GRINDING_BITS_V1,
    )
    .map_err(map_transparent_error_v1)?;
    absorb_grinding_nonce_v1(&mut transcript, grinding_nonce)?;
    let query_indices = query_indices_v1(TEST_PROOF_INSTANCE_V1, &transcript, &aggregate_layout)?;
    let query_skeleton = query_indices
        .iter()
        .map(|index| {
            Ok(aggregate::AggregateQueryProofV1 {
                index: u32::try_from(*index).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
                trace_groups: Vec::new(),
                composition_values: Vec::new(),
                fri_mask_values: Vec::new(),
                fri_lanes: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, ZkX509StarkErrorV1>>()?;
    let trace_opening_indices =
        aggregate::trace_group_opening_indices_v1(&query_skeleton, &shared_layout, 0)
            .map_err(map_aggregate_error_v1)?;
    let base_openings = aggregate::replay_masked_trace_polynomial_columns_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        BASE_LEAF_DOMAIN,
        BASE_NODE_DOMAIN,
        0,
        &base_polynomials,
        &trace_opening_indices,
    )
    .map_err(map_aggregate_error_v1)?;
    let aux_openings = aggregate::replay_masked_trace_polynomial_columns_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        AUX_LEAF_DOMAIN,
        AUX_NODE_DOMAIN,
        0,
        &aux_polynomials,
        &trace_opening_indices,
    )
    .map_err(map_aggregate_error_v1)?;
    if base_openings.commitment.root != trace_group_proofs[0].base_root
        || aux_openings.commitment.root != trace_group_proofs[0].aux_root
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    trace_group_proofs[0].base_frontier = base_openings.commitment.frontier;
    trace_group_proofs[0].aux_frontier = aux_openings.commitment.frontier;
    drop(base_polynomials);
    drop(aux_polynomials);
    let composition_opening_indices =
        aggregate::composition_opening_indices_v1(&query_skeleton, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    let mut composition_frontiers = Vec::new();
    composition_frontiers
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for (lane, composition) in compositions.iter().enumerate() {
        let commitment = aggregate::streaming_composition_commitment_v1(
            &AGGREGATE_DOMAINS_V1,
            lane,
            composition,
            &composition_opening_indices,
        )
        .map_err(map_aggregate_error_v1)?;
        if commitment.root != composition_roots[lane] {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        composition_frontiers.push(commitment.frontier);
    }
    let fri_mask_frontiers = fri_masks
        .iter()
        .map(|mask| {
            aggregate::canonical_multiproof_frontier_v1(
                &mask.tree,
                aggregate_layout.common_lde_size(),
                &composition_opening_indices,
            )
            .map_err(map_aggregate_error_v1)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut fri_openings = Vec::new();
    fri_openings
        .try_reserve_exact(SECURITY_LANES)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for (lane, (base_values, material)) in fri_bases.into_iter().zip(&fri_materials).enumerate() {
        fri_openings.push(
            aggregate::open_streaming_fri_lane_v1(
                AGGREGATE_PARAMETERS_V1,
                &AGGREGATE_DOMAINS_V1,
                &shared_layout,
                lane,
                base_values,
                material,
                &query_indices,
            )
            .map_err(map_aggregate_error_v1)?,
        );
    }
    let mut queries = Vec::new();
    queries
        .try_reserve_exact(query_indices.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for (query_position, index) in query_indices.iter().copied().enumerate() {
        let base_current = base_openings
            .opened_rows
            .get(&index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
            .iter()
            .map(|value| value.0)
            .collect();

        let aux_current = aux_openings
            .opened_rows
            .get(&index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
            .iter()
            .map(|value| value.0)
            .collect();

        queries.push(aggregate::AggregateQueryProofV1 {
            index: u32::try_from(index).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            trace_groups: vec![aggregate::AggregateTraceGroupQueryV1 {
                base_current,
                base_next: Vec::new(),
                aux_current,
                aux_next: Vec::new(),
            }],
            composition_values: compositions
                .iter()
                .map(|lane| {
                    lane.iter()
                        .map(|chunk| chunk[index].coefficients().map(F::value))
                        .collect()
                })
                .collect(),
            fri_mask_values: fri_masks
                .iter()
                .map(|mask| mask.evaluations[index].coefficients().map(F::value))
                .collect(),
            fri_lanes: fri_openings
                .iter()
                .map(|lane| {
                    lane.queries
                        .get(query_position)
                        .cloned()
                        .ok_or(ZkX509StarkErrorV1::InternalInvariant)
                })
                .collect::<Result<Vec<_>, _>>()?,
        });
    }
    let fri_lanes = fri_materials
        .into_iter()
        .zip(fri_openings)
        .map(|(material, openings)| FriLaneProofV1 {
            roots: material.roots,
            terminal_values: material
                .terminal_values
                .into_iter()
                .map(|value| value.coefficients().map(F::value))
                .collect(),
            round_frontiers: openings.round_frontiers,
        })
        .collect();
    let aggregate_proof = ZkX509SegmentedStarkProofV1 {
        aggregate: aggregate::AggregateStarkProofV1 {
            version: ZK_X509_PROOF_VERSION_V1,
            trace_groups: trace_group_proofs,
            composition_roots,
            composition_frontiers,
            fri_mask_roots,
            fri_mask_frontiers,
            fri_lanes,
            queries,
            grinding_nonce,
        },
        deep,
    };
    let aggregate_bytes =
        encode_zk_x509_segmented_stark_proof_v1(&aggregate_proof, &aggregate_layout)?;
    encode_der_segmented_proof_envelope_v1(claims, &aggregate_bytes)
}
#[cfg(test)]
struct IoOpenedRowEvaluatorV1<'a> {
    aggregate_layout: &'a AggregateProofLayoutV1,
    layout: SegmentLayoutV1,
    logical_active_rows: usize,
    fixed_lde: &'a [Vec<F>],
    io_challenges: ZkX509IoChallengesV1,
    alphas: &'a [Vec<E>],
    mixes: &'a [FriMixV1],
    lde_root: F,
}
#[cfg(test)]
struct DerOpenedRowEvaluatorV1<'a> {
    aggregate_layout: &'a AggregateProofLayoutV1,
    layout: SegmentLayoutV1,
    fixed_openings: &'a BTreeMap<usize, [F; ZK_X509_DER_STARK_FIXED_WIDTH_V1]>,
    challenges: ZkX509DerStarkChallengesV1,
    public: ZkX509DerStarkPublicTerminalsV1,
    claims: ZkX509DerStarkTerminalClaimsV1,
    alphas: &'a [Vec<E>],
    mixes: &'a [FriMixV1],
    lde_root: F,
}
#[derive(Clone, Copy)]
struct RegisteredOpenedRowsV1<'a, A = F> {
    base_current: &'a [A],
    base_next: &'a [A],
    aux_current: &'a [A],
    aux_next: &'a [A],
}
#[cfg(test)]
fn registered_opened_rows_v1<'a>(
    aggregate_layout: &AggregateProofLayoutV1,
    registration: RegisteredSegmentLayoutV1,
    trace_groups: &'a [aggregate::AggregateOpenedTraceGroupV1],
) -> Result<RegisteredOpenedRowsV1<'a>, AggregateStarkErrorV1> {
    if trace_groups.len() != aggregate_layout.trace_groups.len() {
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    let group = trace_groups
        .get(registration.trace_group)
        .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
    let expected = aggregate_layout
        .trace_groups
        .get(registration.trace_group)
        .ok_or(AggregateStarkErrorV1::ConstraintOpening)?;
    if group.base_current.len() != expected.base_width
        || group.base_next.len() != expected.base_width
        || group.aux_current.len() != expected.aux_width
        || group.aux_next.len() != expected.aux_width
    {
        return Err(AggregateStarkErrorV1::ConstraintOpening);
    }
    let base_end = registration
        .base_end()
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
    let aux_end = registration
        .aux_end()
        .map_err(|_| AggregateStarkErrorV1::ConstraintOpening)?;
    Ok(RegisteredOpenedRowsV1 {
        base_current: group
            .base_current
            .get(registration.base_start..base_end)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?,
        base_next: group
            .base_next
            .get(registration.base_start..base_end)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?,
        aux_current: group
            .aux_current
            .get(registration.aux_start..aux_end)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?,
        aux_next: group
            .aux_next
            .get(registration.aux_start..aux_end)
            .ok_or(AggregateStarkErrorV1::ConstraintOpening)?,
    })
}
/// One native trace-column implementation behind the unified MAIN boundary.
///
/// The verifier-owned registration is passed into every operation. Providers never supply adapter
/// identities, instances, ranges, widths, or native logarithms themselves.
#[cfg(any(test, feature = "privacy-release-evidence"))]
trait MainTraceGroupSourceV1 {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1>;
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1>;
}
/// A copied witness column which is overwritten before its allocation is released.
#[derive(Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ZeroizingMainTraceColumnV1(Vec<F>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZeroizingMainTraceColumnV1 {
    fn into_vec_v1(mut self) -> Vec<F> {
        core::mem::take(&mut self.0)
    }
    fn zeroize_private_v1(&mut self) {
        super::private_table::zeroize_fields_v1(&mut self.0);
        self.0.clear();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::ops::Deref for ZeroizingMainTraceColumnV1 {
    type Target = [F];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::ops::DerefMut for ZeroizingMainTraceColumnV1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl PartialEq<Vec<F>> for ZeroizingMainTraceColumnV1 {
    fn eq(&self, other: &Vec<F>) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZeroizingMainTraceColumnV1 {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MainP256RegistrationBindingV1 {
    main: RegisteredSegmentLayoutV1,
    p256: P256MainRegistrationV1,
}
fn canonical_p256_main_layout_bindings_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<MainP256RegistrationBindingV1>, ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(
            P256_CERTIFICATE_REGISTRATION_COUNT_V1 * (P256_SIGNATURE_COUNT_V1 - 1)
                + P256_WALLET_REGISTRATION_COUNT_V1,
        )
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for main in layout
        .registered_segments
        .iter()
        .copied()
        .filter(|registration| {
            matches!(
                registration.segment.adapter,
                SegmentAdapterIdV1::P256Arithmetic
                    | SegmentAdapterIdV1::P256Reduction
                    | SegmentAdapterIdV1::P256LowS
                    | SegmentAdapterIdV1::P256Window
                    | SegmentAdapterIdV1::P256ValueBus
                    | SegmentAdapterIdV1::P256ScalarBitBus
            )
        })
    {
        bindings.push(MainP256RegistrationBindingV1 {
            main,
            p256: p256_main_registration_from_main_layout_v1(main)?,
        });
    }
    // Validate the complete central order independently of MAIN's
    // equal-native-log order, then prove a one-to-one association with all
    // MAIN P-256 slices.
    let mut central_order = Vec::new();
    central_order
        .try_reserve_exact(bindings.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        for (adapter, local) in [
            (P256MainAdapterV1::ValueBus, 0),
            (P256MainAdapterV1::ValueBus, 1),
            (P256MainAdapterV1::Arithmetic, 0),
            (P256MainAdapterV1::WindowBatch, 0),
            (P256MainAdapterV1::Reduction, 0),
            (P256MainAdapterV1::Reduction, 1),
        ] {
            central_order.push(
                P256MainRegistrationV1::new_v1(signature, adapter, local)
                    .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            );
        }
        if signature == P256_SIGNATURE_COUNT_V1 - 1 {
            central_order.push(
                P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::WalletLowS, 0)
                    .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            );
        }
        for adapter in [
            P256MainAdapterV1::BindingSink,
            P256MainAdapterV1::ScalarBitBus,
        ] {
            central_order.push(
                P256MainRegistrationV1::new_v1(signature, adapter, 0)
                    .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            );
        }
    }
    validate_p256_main_registration_order_v1(&central_order)
        .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
    if bindings.len() != central_order.len()
        || central_order.iter().any(|expected| {
            bindings
                .iter()
                .filter(|binding| binding.p256 == *expected)
                .count()
                != 1
        })
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(bindings)
}
const P256_MAIN_LOG5_REGISTRATION_COUNT_V1: usize = 11;
const P256_MAIN_LOG5_BASE_WIDTH_V1: usize =
    10 * P256_REDUCTION_BASE_WIDTH_V1 + P256_LOW_S_BASE_WIDTH_V1;
const P256_MAIN_LOG5_AUX_WIDTH_V1: usize =
    10 * P256_REDUCTION_AGGREGATE_AUX_WIDTH_V1 + P256_LOW_S_AGGREGATE_AUX_WIDTH_V1;
const _: () = assert!(P256_MAIN_LOG5_BASE_WIDTH_V1 == 596);
const _: () = assert!(P256_MAIN_LOG5_AUX_WIDTH_V1 == 204);
fn canonical_p256_main_log5_bindings_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<MainP256RegistrationBindingV1>, ZkX509StarkErrorV1> {
    let bindings = canonical_p256_main_layout_bindings_v1(layout)?;
    let log5 = bindings
        .into_iter()
        .filter(|binding| binding.main.segment.trace_log2 == 5)
        .collect::<Vec<_>>();
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(P256_MAIN_LOG5_REGISTRATION_COUNT_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        for local in 0..2 {
            expected.push(
                P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::Reduction, local)
                    .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            );
        }
    }
    expected.push(
        P256MainRegistrationV1::new_v1(
            P256_SIGNATURE_COUNT_V1 - 1,
            P256MainAdapterV1::WalletLowS,
            0,
        )
        .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
    );
    let group = log5
        .first()
        .map(|binding| binding.main.trace_group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let group_layout = layout
        .trace_groups
        .get(group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if log5.len() != P256_MAIN_LOG5_REGISTRATION_COUNT_V1
        || log5
            .iter()
            .map(|binding| binding.p256)
            .ne(expected.iter().copied())
        || log5.iter().any(|binding| binding.main.trace_group != group)
        || group_layout.native_trace_log2 != 5
        || group_layout.base_width != P256_MAIN_LOG5_BASE_WIDTH_V1
        || group_layout.aux_width != P256_MAIN_LOG5_AUX_WIDTH_V1
        || group_layout.column_chunks != P256_MAIN_LOG5_REGISTRATION_COUNT_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(log5)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
const P256_MAIN_LOG16_REGISTRATION_COUNT_V1: usize = 10;
const P256_MAIN_LOG16_BASE_WIDTH_V1: usize =
    P256_SIGNATURE_COUNT_V1 * (P256_WINDOW_BASE_WIDTH_V1 + P256_BINDING_SINK_BASE_WIDTH_V1);
const P256_MAIN_LOG16_AUX_WIDTH_V1: usize = P256_SIGNATURE_COUNT_V1
    * (P256_WINDOW_AGGREGATE_AUX_WIDTH_V1
        + super::p256_cross_trace_bus::P256_CROSS_TRACE_SINK_AUX_WIDTH_V1);
const P256_MAIN_LOG16_PHYSICAL_CHUNKS_V1: usize = 10;
const P256_MAIN_LOG16_NEXT_STRIDE_V1: usize =
    1 << (ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - P256_WINDOW_AGGREGATE_TRACE_LOG2_V1);
const _: () = assert!(P256_MAIN_LOG16_BASE_WIDTH_V1 == 430);
const _: () = assert!(P256_MAIN_LOG16_AUX_WIDTH_V1 == 375);
const _: () = assert!(P256_MAIN_LOG16_PHYSICAL_CHUNKS_V1 == 10);
const _: () = assert!(
    P256_MAIN_LOG16_NEXT_STRIDE_V1
        == 1 << (ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - P256_WINDOW_AGGREGATE_TRACE_LOG2_V1)
);
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// The sole native-log-sixteen P-256 registration order: all five vertical
/// window batches followed by all five external-binding sinks.
///
/// MAIN sorts equal-log registrations by adapter identity and global instance.
/// Reconstructing the expected central identities here prevents either a
/// caller-selected topology or an accidental interleaving of the two AIRs.
fn canonical_p256_main_log16_bindings_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<MainP256RegistrationBindingV1>, ZkX509StarkErrorV1> {
    let bindings = canonical_p256_main_layout_bindings_v1(layout)?;
    let log16 = bindings
        .into_iter()
        .filter(|binding| binding.main.segment.trace_log2 == 16)
        .collect::<Vec<_>>();
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(P256_MAIN_LOG16_REGISTRATION_COUNT_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        expected.push(
            P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::WindowBatch, 0)
                .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
        );
    }
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        expected.push(
            P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::BindingSink, 0)
                .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
        );
    }
    let group = log16
        .first()
        .map(|binding| binding.main.trace_group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let group_layout = layout
        .trace_groups
        .get(group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if log16.len() != P256_MAIN_LOG16_REGISTRATION_COUNT_V1
        || log16
            .iter()
            .map(|binding| binding.p256)
            .ne(expected.iter().copied())
        || log16
            .iter()
            .any(|binding| binding.main.trace_group != group)
        || log16.iter().any(|binding| {
            !matches!(
                (
                    binding.main.segment.adapter,
                    p256_instance_parts_v1(binding.main.segment.instance),
                    binding.p256.adapter_v1(),
                    binding.p256.local_instance_v1(),
                ),
                (
                    SegmentAdapterIdV1::P256Window,
                    Some((_, 0)),
                    P256MainAdapterV1::WindowBatch,
                    0,
                ) | (
                    SegmentAdapterIdV1::P256ValueBus,
                    Some((_, 2)),
                    P256MainAdapterV1::BindingSink,
                    0,
                )
            )
        })
        || group_layout.native_trace_log2 != P256_WINDOW_AGGREGATE_TRACE_LOG2_V1
        || P256_WINDOW_AGGREGATE_TRACE_LOG2_V1 != P256_BINDING_SINK_AGGREGATE_TRACE_LOG2_V1
        || group_layout.base_width != P256_MAIN_LOG16_BASE_WIDTH_V1
        || group_layout.aux_width != P256_MAIN_LOG16_AUX_WIDTH_V1
        || group_layout.column_chunks != P256_MAIN_LOG16_PHYSICAL_CHUNKS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(log16)
}
const P256_MAIN_LOG19_REGISTRATION_COUNT_V1: usize = 15;
const MAIN_LOG19_NON_P256_REGISTRATION_COUNT_V1: usize = 6;
const MAIN_LOG19_REGISTRATION_COUNT_V1: usize = 21;
const MAIN_LOG19_BASE_WIDTH_V1: usize = 2_112;
const MAIN_LOG19_AUX_WIDTH_V1: usize = 1_788;
const MAIN_LOG19_PHYSICAL_CHUNKS_V1: usize = 52;
const P256_MAIN_LOG19_BASE_START_V1: usize = 717;
const P256_MAIN_LOG19_AUX_START_V1: usize = 788;
const P256_MAIN_LOG19_BASE_WIDTH_V1: usize = P256_SIGNATURE_COUNT_V1
    * (P256_ARITHMETIC_BASE_WIDTH_V1 + 2 * P256_VALUE_BUS_STARK_BASE_WIDTH_V1);
const P256_MAIN_LOG19_AUX_WIDTH_V1: usize = P256_SIGNATURE_COUNT_V1
    * (P256_ARITHMETIC_AGGREGATE_AUX_WIDTH_V1
        + P256_VALUE_EXECUTION_AGGREGATE_AUX_WIDTH_V1
        + P256_VALUE_BUS_STARK_AUX_WIDTH_V1);
const P256_MAIN_LOG19_PHYSICAL_CHUNKS_V1: usize = 35;
const P256_MAIN_LOG19_NEXT_STRIDE_V1: usize =
    1 << (ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - ZK_X509_MAX_NATIVE_TRACE_LOG2_V1);
const P256_MAIN_LOG19_BASE_STARTS_V1: [usize; P256_MAIN_LOG19_REGISTRATION_COUNT_V1] = [
    717, 928, 1_139, 1_350, 1_561, 1_772, 1_806, 1_840, 1_874, 1_908, 1_942, 1_976, 2_010, 2_044,
    2_078,
];
const P256_MAIN_LOG19_AUX_STARTS_V1: [usize; P256_MAIN_LOG19_REGISTRATION_COUNT_V1] = [
    788, 860, 932, 1_004, 1_076, 1_148, 1_264, 1_276, 1_392, 1_404, 1_520, 1_532, 1_648, 1_660,
    1_776,
];
const MAIN_LOG19_BASE_STARTS_V1: [usize; MAIN_LOG19_REGISTRATION_COUNT_V1] = [
    0, 76, 361, 450, 539, 628, 717, 928, 1_139, 1_350, 1_561, 1_772, 1_806, 1_840, 1_874, 1_908,
    1_942, 1_976, 2_010, 2_044, 2_078,
];
const MAIN_LOG19_AUX_STARTS_V1: [usize; MAIN_LOG19_REGISTRATION_COUNT_V1] = [
    0, 196, 476, 554, 632, 710, 788, 860, 932, 1_004, 1_076, 1_148, 1_264, 1_276, 1_392, 1_404,
    1_520, 1_532, 1_648, 1_660, 1_776,
];
const MAIN_LOG19_NON_P256_KEYS_V1: [(SegmentAdapterIdV1, u16);
    MAIN_LOG19_NON_P256_REGISTRATION_COUNT_V1] = [
    (SegmentAdapterIdV1::StrictDer, 0),
    (SegmentAdapterIdV1::Rfc5280, 0),
    (SegmentAdapterIdV1::Sha256CallBus, 0),
    (SegmentAdapterIdV1::Sha256CallBus, 1),
    (SegmentAdapterIdV1::Sha256CallBus, 2),
    (SegmentAdapterIdV1::Sha256CallBus, 3),
];
const _: () = assert!(P256_MAIN_LOG19_BASE_WIDTH_V1 == 1_395);
const _: () = assert!(P256_MAIN_LOG19_AUX_WIDTH_V1 == 1_000);
const _: () = assert!(
    MAIN_LOG19_NON_P256_REGISTRATION_COUNT_V1 + P256_MAIN_LOG19_REGISTRATION_COUNT_V1
        == MAIN_LOG19_REGISTRATION_COUNT_V1
);
const _: () = assert!(P256_MAIN_LOG19_BASE_START_V1 + P256_MAIN_LOG19_BASE_WIDTH_V1 == 2_112);
const _: () = assert!(P256_MAIN_LOG19_AUX_START_V1 + P256_MAIN_LOG19_AUX_WIDTH_V1 == 1_788);
const _: () = assert!(
    P256_MAIN_LOG19_NEXT_STRIDE_V1
        == 1 << (ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
);
/// Exact mixed log19 registration, including the six non-P-256 owners.
///
/// This validation is deliberately stronger than selecting every segment whose logarithm happens to
/// be 19. It fixes the registration identities, offsets, group geometry, and physical chunk count
/// before a production verifier source can exist.
fn canonical_main_log19_registrations_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<RegisteredSegmentLayoutV1>, ZkX509StarkErrorV1> {
    layout.validate_exact_full_profile_registration_v1()?;
    let registrations = layout
        .registered_segments
        .iter()
        .copied()
        .filter(|registration| registration.segment.trace_log2 == ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
        .collect::<Vec<_>>();
    let group = registrations
        .first()
        .map(|registration| registration.trace_group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let group_layout = layout
        .trace_groups
        .get(group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let non_p256_chunks = registrations
        .iter()
        .take(MAIN_LOG19_NON_P256_REGISTRATION_COUNT_V1)
        .try_fold(0_usize, |sum, registration| {
            sum.checked_add(registration.column_chunks)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
        })?;
    if registrations.len() != MAIN_LOG19_REGISTRATION_COUNT_V1
        || registrations
            .iter()
            .any(|registration| registration.trace_group != group)
        || registrations
            .iter()
            .map(|registration| registration.base_start)
            .ne(MAIN_LOG19_BASE_STARTS_V1)
        || registrations
            .iter()
            .map(|registration| registration.aux_start)
            .ne(MAIN_LOG19_AUX_STARTS_V1)
        || registrations
            .iter()
            .take(MAIN_LOG19_NON_P256_REGISTRATION_COUNT_V1)
            .map(|registration| (registration.segment.adapter, registration.segment.instance))
            .ne(MAIN_LOG19_NON_P256_KEYS_V1)
        || non_p256_chunks != MAIN_LOG19_PHYSICAL_CHUNKS_V1 - P256_MAIN_LOG19_PHYSICAL_CHUNKS_V1
        || group_layout.native_trace_log2 != ZK_X509_MAX_NATIVE_TRACE_LOG2_V1
        || group_layout.base_width != MAIN_LOG19_BASE_WIDTH_V1
        || group_layout.aux_width != MAIN_LOG19_AUX_WIDTH_V1
        || group_layout.column_chunks != MAIN_LOG19_PHYSICAL_CHUNKS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    canonical_p256_main_log19_bindings_v1(layout)?;
    Ok(registrations)
}
/// Exact P-256 subset of MAIN's mixed native-log19 group.
///
/// The six DER/RFC/SHA registrations occupy the fixed prefix. P-256 then appears as all five
/// arithmetic registrations followed by execution/sorted value-bus pairs in global signature order.
fn canonical_p256_main_log19_bindings_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<Vec<MainP256RegistrationBindingV1>, ZkX509StarkErrorV1> {
    let bindings = canonical_p256_main_layout_bindings_v1(layout)?;
    let log19 = bindings
        .into_iter()
        .filter(|binding| binding.main.segment.trace_log2 == ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
        .collect::<Vec<_>>();
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(P256_MAIN_LOG19_REGISTRATION_COUNT_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        expected.push(
            P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::Arithmetic, 0)
                .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
        );
    }
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        for local in 0..2 {
            expected.push(
                P256MainRegistrationV1::new_v1(signature, P256MainAdapterV1::ValueBus, local)
                    .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            );
        }
    }
    let group = log19
        .first()
        .map(|binding| binding.main.trace_group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let group_layout = layout
        .trace_groups
        .get(group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let group_registration_count = layout
        .registered_segments
        .iter()
        .filter(|registration| registration.trace_group == group)
        .count();
    let p256_chunks = log19.iter().try_fold(0_usize, |sum, binding| {
        sum.checked_add(binding.main.column_chunks)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    })?;
    if log19.len() != P256_MAIN_LOG19_REGISTRATION_COUNT_V1
        || log19
            .iter()
            .map(|binding| binding.p256)
            .ne(expected.iter().copied())
        || log19
            .iter()
            .any(|binding| binding.main.trace_group != group)
        || log19
            .iter()
            .map(|binding| binding.main.base_start)
            .ne(P256_MAIN_LOG19_BASE_STARTS_V1)
        || log19
            .iter()
            .map(|binding| binding.main.aux_start)
            .ne(P256_MAIN_LOG19_AUX_STARTS_V1)
        || group_registration_count != MAIN_LOG19_REGISTRATION_COUNT_V1
        || group_layout.native_trace_log2 != ZK_X509_MAX_NATIVE_TRACE_LOG2_V1
        || group_layout.base_width != MAIN_LOG19_BASE_WIDTH_V1
        || group_layout.aux_width != MAIN_LOG19_AUX_WIDTH_V1
        || group_layout.column_chunks != MAIN_LOG19_PHYSICAL_CHUNKS_V1
        || p256_chunks != P256_MAIN_LOG19_PHYSICAL_CHUNKS_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(log19)
}
fn p256_aggregate_challenges_from_post_base_v1(
    post_base: ZkX509CredentialMainPostBaseChallengesV1,
) -> Result<P256AggregateChallengesV1, ZkX509StarkErrorV1> {
    let challenges = P256AggregateChallengesV1 {
        value: post_base.p256_value(),
        cross: post_base.p256_cross(),
        scalar: post_base.p256_scalar(),
        arithmetic_copy: post_base.p256_arithmetic_copy(),
    };
    challenges.validate()?;
    Ok(challenges)
}
#[derive(Clone, Copy)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
enum MainP256Log5TracePhaseV1<'a> {
    Base(&'a P256MainBaseSourceV1),
    Bound(&'a P256MainBoundSourceV1),
}
/// Borrowed trace replay for the ten reductions and wallet low-S adapter.
///
/// The central five-signature source remains uniquely owned by the caller and
/// can therefore be reused by the other native-log P-256 views without
/// recompiling or duplicating any private trace material.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainP256Log5TraceGroupSourceV1<'a> {
    bindings: Vec<MainP256RegistrationBindingV1>,
    phase: MainP256Log5TracePhaseV1<'a>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainP256Log5TraceGroupSourceV1<'a> {
    fn for_base_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBaseSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_p256_main_registration_order_v1(&source.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        Ok(Self {
            bindings: canonical_p256_main_log5_bindings_v1(layout)?,
            phase: MainP256Log5TracePhaseV1::Base(source),
        })
    }
    fn for_bound_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBoundSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_p256_main_registration_order_v1(&source.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        source.post_base_v1()?;
        Ok(Self {
            bindings: canonical_p256_main_log5_bindings_v1(layout)?,
            phase: MainP256Log5TracePhaseV1::Bound(source),
        })
    }
    fn binding_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .bindings
            .iter()
            .copied()
            .filter(|binding| binding.main == registration);
        let binding = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(binding)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainP256Log5TraceGroupSourceV1<'_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let binding = self.binding_v1(registration)?;
        if local_column >= registration.segment.base_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut output = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
        match self.phase {
            MainP256Log5TracePhaseV1::Base(source) => {
                source.fill_base_column_v1(binding.p256, local_column, &mut output)?
            }
            MainP256Log5TracePhaseV1::Bound(source) => {
                source.fill_base_column_v1(binding.p256, local_column, &mut output)?
            }
        }
        if output.iter().any(|value| F::canonical(value.0).is_none()) {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(output)
    }
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let binding = self.binding_v1(registration)?;
        if local_column >= registration.segment.aux_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let source = match self.phase {
            MainP256Log5TracePhaseV1::Base(_) => {
                return Err(ZkX509StarkErrorV1::TranscriptMismatch);
            }
            MainP256Log5TracePhaseV1::Bound(source) => source,
        };
        let mut output = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
        source.fill_aux_column_v1(binding.p256, local_column, &mut output)?;
        if output.iter().any(|value| F::canonical(value.0).is_none()) {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(output)
    }
}
#[cfg(test)]
fn zeroize_p256_terminal_registration_v1(registration: &mut P256TerminalRegistrationV1) {
    registration.buses.value_execution.fill(F::ZERO);
    registration.buses.value_sorted.fill(F::ZERO);
    registration.buses.value_arithmetic_copy.fill(F::ZERO);
    registration.buses.arithmetic_value_copy.fill(F::ZERO);
    registration.buses.arithmetic_scalar.fill(F::ZERO);
    registration.buses.window_scalar.fill(F::ZERO);
    registration.buses.scalar_bus_arithmetic.fill(F::ZERO);
    registration.buses.scalar_bus_window.fill(F::ZERO);
    for claim in &mut registration.cross_sources {
        claim.start.fill(F::ZERO);
        claim.terminal.fill(F::ZERO);
    }
    registration.cross_sources.clear();
    registration.sink.fill(F::ZERO);
}
/// Fixed-polynomial streaming and composition evaluation for the log-five
/// prover, borrowing the one already-bound central P-256 capability.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainP256Log5ProverConstraintSourceV1<'a> {
    source: &'a P256MainBoundSourceV1,
    bindings: Vec<MainP256RegistrationBindingV1>,
    challenges: P256AggregateChallengesV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainP256Log5ProverConstraintSourceV1<'a> {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBoundSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_p256_main_registration_order_v1(&source.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        Ok(Self {
            source,
            bindings: canonical_p256_main_log5_bindings_v1(layout)?,
            challenges: p256_aggregate_challenges_from_post_base_v1(source.post_base_v1()?)?,
        })
    }
    fn binding_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .bindings
            .iter()
            .copied()
            .filter(|binding| binding.main == registration);
        let binding = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(binding)
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(
            RegisteredSegmentLayoutV1,
            usize,
            &[F],
        ) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        for binding in self.bindings.iter().copied() {
            let trace_root = goldilocks_primitive_root_v1(binding.main.segment.trace_log2)
                .map_err(map_transparent_error_v1)?;
            for local_column in 0..binding.main.segment.fixed_width {
                let mut coefficients =
                    zeroed_main_trace_column_v1(binding.main.segment.trace_size())?;
                self.source
                    .fill_fixed_column_v1(binding.p256, local_column, &mut coefficients)?;
                goldilocks_ifft_v1(&mut coefficients, trace_root)
                    .map_err(map_transparent_error_v1)?;
                consume(binding.main, local_column, &coefficients)?;
            }
        }
        Ok(())
    }
    fn constraint_residues_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F],
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let _binding = self.binding_v1(registration)?;
        if fixed.len() != registration.segment.fixed_width
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .chain(fixed)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        p256_opened_residues_v1(registration, opening, fixed, self.challenges)
    }
    #[cfg(test)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if F::canonical(x.0).is_none() || alphas.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues = self.constraint_residues_v1(registration, opening, fixed)?;
        accumulator_quotient_value_v1(registration.segment, x, &residues, alphas)
    }
}
/// Witness-free fixed preprocessing and opened-row evaluation for the eleven
/// reductions in MAIN's native log-five group.
///
/// One central verifier-fixed source is shared across all P-256 groups. This
/// view owns only its bounded, registration-local opening caches.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "opened-row fields serve only the test and release-evidence prover checks"
    )
)]
struct MainP256Log5VerifierConstraintSourceV1<'a> {
    bindings: Vec<MainP256RegistrationBindingV1>,
    common_lde_log2: u8,
    challenges: P256AggregateChallengesV1,
    fixed: &'a P256MainVerifierFixedSourceV1,
    fixed_openings: Vec<BTreeMap<usize, Vec<F>>>,
}
impl<'a> MainP256Log5VerifierConstraintSourceV1<'a> {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        fixed: &'a P256MainVerifierFixedSourceV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let bindings = canonical_p256_main_log5_bindings_v1(layout)?;
        if bindings
            .iter()
            .any(|binding| layout.common_lde_log2 < binding.main.segment.lde_log2)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut fixed_openings = Vec::new();
        fixed_openings
            .try_reserve_exact(P256_MAIN_LOG5_REGISTRATION_COUNT_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        fixed_openings.resize_with(P256_MAIN_LOG5_REGISTRATION_COUNT_V1, BTreeMap::new);
        Ok(Self {
            bindings,
            common_lde_log2: layout.common_lde_log2,
            challenges: p256_aggregate_challenges_from_post_base_v1(post_base)?,

            fixed,
            fixed_openings,
        })
    }
    #[cfg(test)]
    fn common_lde_size_v1(&self) -> Result<usize, ZkX509StarkErrorV1> {
        1_usize
            .checked_shl(u32::from(self.common_lde_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    #[cfg(test)]
    fn binding_index_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let mut matches = self
            .bindings
            .iter()
            .enumerate()
            .filter(|(_, binding)| binding.main == registration)
            .map(|(index, _)| index);
        let index = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(index)
    }
    #[cfg(test)]
    fn next_query_index_v1(
        &self,
        registration_index: usize,
        query_index: usize,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let registration = self
            .bindings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .main;
        let stride_log2 = self
            .common_lde_log2
            .checked_sub(registration.segment.trace_log2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let stride = 1_usize
            .checked_shl(u32::from(stride_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Ok(query_index
            .checked_add(stride)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            % self.common_lde_size_v1()?)
    }
    #[cfg(test)]
    fn ensure_fixed_openings_v1(
        &mut self,
        registration_index: usize,
        indices: [usize; 2],
    ) -> Result<(), ZkX509StarkErrorV1> {
        let binding = *self
            .bindings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let cache = self
            .fixed_openings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let mut missing = indices
            .into_iter()
            .filter(|index| !cache.contains_key(index))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        if cache
            .len()
            .checked_add(missing.len())
            .filter(|count| *count <= VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
            .is_none()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        // Sample into a temporary map. No rejected schedule or resource
        // request can partially consume the bounded cache.
        let sampled = match binding.p256.adapter_v1() {
            P256MainAdapterV1::Reduction => sampled_verifier_generated_fixed_openings_v1::<
                P256_REDUCTION_AGGREGATE_FIXED_WIDTH_V1,
            >(
                binding.main.segment,
                self.common_lde_log2,
                &missing,
                |row| {
                    self.fixed
                        .fixed_row_v1(binding.p256, row)?
                        .try_into()
                        .map_err(|_: Vec<F>| ZkX509StarkErrorV1::InternalInvariant)
                },
            )?,
            P256MainAdapterV1::WalletLowS => {
                sampled_verifier_generated_fixed_openings_v1::<P256_LOW_S_AGGREGATE_FIXED_WIDTH_V1>(
                    binding.main.segment,
                    self.common_lde_log2,
                    &missing,
                    |row| {
                        self.fixed
                            .fixed_row_v1(binding.p256, row)?
                            .try_into()
                            .map_err(|_: Vec<F>| ZkX509StarkErrorV1::InternalInvariant)
                    },
                )?
            }
            _ => return Err(ZkX509StarkErrorV1::InternalInvariant),
        };
        let cache = self
            .fixed_openings
            .get_mut(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if sampled.keys().any(|index| cache.contains_key(index)) {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        cache.extend(sampled);
        Ok(())
    }
    #[cfg(test)]
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let registration_index = self.binding_index_v1(registration)?;
        let _binding = *self
            .bindings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let common_lde_size = self.common_lde_size_v1()?;
        if query_index >= common_lde_size
            || next_query_index >= common_lde_size
            || next_query_index != self.next_query_index_v1(registration_index, query_index)?
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || F::canonical(x.0).is_none()
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let root =
            goldilocks_primitive_root_v1(self.common_lde_log2).map_err(map_transparent_error_v1)?;
        let expected_x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        if x != expected_x {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        self.ensure_fixed_openings_v1(registration_index, [query_index, next_query_index])?;
        let cache = self
            .fixed_openings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let current = cache
            .get(&query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let next = cache
            .get(&next_query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if current.len() != registration.segment.fixed_width
            || next.len() != registration.segment.fixed_width
            || current
                .iter()
                .chain(next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }

        p256_opened_residues_v1(registration, opening, current, self.challenges)
    }
    #[cfg(test)]
    fn cached_openings_v1(&self, registration_index: usize) -> Option<usize> {
        self.fixed_openings
            .get(registration_index)
            .map(BTreeMap::len)
    }
}
#[derive(Clone, Copy)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
enum MainP256Log16TracePhaseV1<'a> {
    Base(&'a P256MainBaseSourceV1),
    Bound(&'a P256MainBoundSourceV1),
}
/// Borrowed trace replay for MAIN's five window batches and five binding
/// sinks. The central P-256 source remains the sole owner of private rows.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainP256Log16TraceGroupSourceV1<'a> {
    bindings: Vec<MainP256RegistrationBindingV1>,
    phase: MainP256Log16TracePhaseV1<'a>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainP256Log16TraceGroupSourceV1<'a> {
    fn for_base_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBaseSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_p256_main_registration_order_v1(&source.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        Ok(Self {
            bindings: canonical_p256_main_log16_bindings_v1(layout)?,
            phase: MainP256Log16TracePhaseV1::Base(source),
        })
    }
    fn for_bound_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBoundSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_p256_main_registration_order_v1(&source.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        source.post_base_v1()?;
        Ok(Self {
            bindings: canonical_p256_main_log16_bindings_v1(layout)?,
            phase: MainP256Log16TracePhaseV1::Bound(source),
        })
    }
    fn binding_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .bindings
            .iter()
            .copied()
            .filter(|binding| binding.main == registration);
        let binding = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(binding)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainP256Log16TraceGroupSourceV1<'_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let binding = self.binding_v1(registration)?;
        if local_column >= registration.segment.base_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut output = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
        match self.phase {
            MainP256Log16TracePhaseV1::Base(source) => {
                source.fill_base_column_v1(binding.p256, local_column, &mut output)?
            }
            MainP256Log16TracePhaseV1::Bound(source) => {
                source.fill_base_column_v1(binding.p256, local_column, &mut output)?
            }
        }
        if output.iter().any(|value| F::canonical(value.0).is_none()) {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(output)
    }
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let binding = self.binding_v1(registration)?;
        if local_column >= registration.segment.aux_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let MainP256Log16TracePhaseV1::Bound(source) = self.phase else {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        };
        let mut output = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
        source.fill_aux_column_v1(binding.p256, local_column, &mut output)?;
        if output.iter().any(|value| F::canonical(value.0).is_none()) {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(output)
    }
}
/// Fixed-polynomial streaming and opened-row composition for the bound log-sixteen prover.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainP256Log16ProverConstraintSourceV1<'a> {
    source: &'a P256MainBoundSourceV1,
    bindings: Vec<MainP256RegistrationBindingV1>,
    challenges: P256AggregateChallengesV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainP256Log16ProverConstraintSourceV1<'a> {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBoundSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_p256_main_registration_order_v1(&source.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        Ok(Self {
            source,
            bindings: canonical_p256_main_log16_bindings_v1(layout)?,
            challenges: p256_aggregate_challenges_from_post_base_v1(source.post_base_v1()?)?,
        })
    }
    fn binding_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .bindings
            .iter()
            .copied()
            .filter(|binding| binding.main == registration);
        let binding = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(binding)
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(
            RegisteredSegmentLayoutV1,
            usize,
            &[F],
        ) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        for binding in self.bindings.iter().copied() {
            let trace_root = goldilocks_primitive_root_v1(binding.main.segment.trace_log2)
                .map_err(map_transparent_error_v1)?;
            for local_column in 0..binding.main.segment.fixed_width {
                let mut coefficients =
                    zeroed_main_trace_column_v1(binding.main.segment.trace_size())?;
                self.source
                    .fill_fixed_column_v1(binding.p256, local_column, &mut coefficients)?;
                goldilocks_ifft_v1(&mut coefficients, trace_root)
                    .map_err(map_transparent_error_v1)?;
                consume(binding.main, local_column, &coefficients)?;
            }
        }
        Ok(())
    }
    fn constraint_residues_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F],
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let _binding = self.binding_v1(registration)?;
        if fixed.len() != registration.segment.fixed_width
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .chain(fixed)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        p256_opened_residues_v1(registration, opening, fixed, self.challenges)
    }
    #[cfg(test)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if F::canonical(x.0).is_none() || alphas.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues = self.constraint_residues_v1(registration, opening, fixed)?;
        accumulator_quotient_value_v1(registration.segment, x, &residues, alphas)
    }
}
#[cfg(test)]
/// Witness-free fixed sampler and opened-row evaluator for all ten canonical
/// log-sixteen registrations.
///
/// Each registration owns an independent bounded cache. Missing rows are sampled into a temporary
/// map and committed only after every generated opening succeeds.
struct MainP256Log16VerifierConstraintSourceV1<'a> {
    bindings: Vec<MainP256RegistrationBindingV1>,
    common_lde_log2: u8,
    fixed: &'a P256MainVerifierFixedSourceV1,
    challenges: P256AggregateChallengesV1,
    fixed_openings: Vec<BTreeMap<usize, Vec<F>>>,
}
#[cfg(test)]
impl<'a> MainP256Log16VerifierConstraintSourceV1<'a> {
    #[cfg(test)]
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        fixed: &'a P256MainVerifierFixedSourceV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let bindings = canonical_p256_main_log16_bindings_v1(layout)?;
        if bindings.iter().any(|binding| {
            layout.common_lde_log2 < binding.main.segment.lde_log2
                || binding.main.segment.trace_log2 != P256_WINDOW_AGGREGATE_TRACE_LOG2_V1
        }) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut fixed_openings = Vec::new();
        fixed_openings
            .try_reserve_exact(P256_MAIN_LOG16_REGISTRATION_COUNT_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        fixed_openings.resize_with(P256_MAIN_LOG16_REGISTRATION_COUNT_V1, BTreeMap::new);
        Ok(Self {
            bindings,
            common_lde_log2: layout.common_lde_log2,
            fixed,
            challenges: p256_aggregate_challenges_from_post_base_v1(post_base)?,

            fixed_openings,
        })
    }
    #[cfg(test)]
    fn common_lde_size_v1(&self) -> Result<usize, ZkX509StarkErrorV1> {
        1_usize
            .checked_shl(u32::from(self.common_lde_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    #[cfg(test)]
    fn binding_index_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let mut matches = self
            .bindings
            .iter()
            .enumerate()
            .filter(|(_, binding)| binding.main == registration)
            .map(|(index, _)| index);
        let index = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(index)
    }
    #[cfg(test)]
    fn next_query_index_v1(
        &self,
        registration_index: usize,
        query_index: usize,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let registration = self
            .bindings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            .main;
        let stride_log2 = self
            .common_lde_log2
            .checked_sub(registration.segment.trace_log2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let stride = 1_usize
            .checked_shl(u32::from(stride_log2))
            .filter(|stride| *stride == P256_MAIN_LOG16_NEXT_STRIDE_V1)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Ok(query_index
            .checked_add(stride)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            % self.common_lde_size_v1()?)
    }
    #[cfg(test)]
    fn ensure_fixed_openings_v1(
        &mut self,
        registration_index: usize,
        indices: [usize; 2],
    ) -> Result<(), ZkX509StarkErrorV1> {
        let binding = *self
            .bindings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let cache = self
            .fixed_openings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let mut missing = indices
            .into_iter()
            .filter(|index| !cache.contains_key(index))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        if cache
            .len()
            .checked_add(missing.len())
            .filter(|count| *count <= VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
            .is_none()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let sampled = match binding.p256.adapter_v1() {
            P256MainAdapterV1::WindowBatch => {
                sampled_verifier_generated_fixed_openings_v1::<P256_WINDOW_AGGREGATE_FIXED_WIDTH_V1>(
                    binding.main.segment,
                    self.common_lde_log2,
                    &missing,
                    |row| {
                        self.fixed
                            .fixed_row_v1(binding.p256, row)?
                            .try_into()
                            .map_err(|_: Vec<F>| ZkX509StarkErrorV1::InternalInvariant)
                    },
                )?
            }
            P256MainAdapterV1::BindingSink => {
                sampled_verifier_generated_fixed_openings_v1::<P256_BINDING_SINK_FIXED_WIDTH_V1>(
                    binding.main.segment,
                    self.common_lde_log2,
                    &missing,
                    |row| {
                        self.fixed
                            .fixed_row_v1(binding.p256, row)?
                            .try_into()
                            .map_err(|_: Vec<F>| ZkX509StarkErrorV1::InternalInvariant)
                    },
                )?
            }
            _ => return Err(ZkX509StarkErrorV1::InternalInvariant),
        };
        let cache = self
            .fixed_openings
            .get_mut(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if sampled.keys().any(|index| cache.contains_key(index)) {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        cache.extend(sampled);
        Ok(())
    }
    #[cfg(test)]
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let registration_index = self.binding_index_v1(registration)?;
        let _binding = *self
            .bindings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let common_lde_size = self.common_lde_size_v1()?;
        if query_index >= common_lde_size
            || next_query_index >= common_lde_size
            || next_query_index != self.next_query_index_v1(registration_index, query_index)?
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || F::canonical(x.0).is_none()
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let root =
            goldilocks_primitive_root_v1(self.common_lde_log2).map_err(map_transparent_error_v1)?;
        let expected_x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        if x != expected_x {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        self.ensure_fixed_openings_v1(registration_index, [query_index, next_query_index])?;
        let cache = self
            .fixed_openings
            .get(registration_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let current = cache
            .get(&query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let next = cache
            .get(&next_query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if current.len() != registration.segment.fixed_width
            || next.len() != registration.segment.fixed_width
            || current
                .iter()
                .chain(next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        p256_opened_residues_v1(registration, opening, current, self.challenges)
    }
    #[cfg(test)]
    fn cached_openings_v1(&self, registration_index: usize) -> Option<usize> {
        self.fixed_openings
            .get(registration_index)
            .map(BTreeMap::len)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn map_main_sha_source_error_v1(
    error: super::sha_call_bus_stark::ZkX509ShaCallBusStarkErrorV1,
) -> ZkX509StarkErrorV1 {
    use super::sha_call_bus_stark::ZkX509ShaCallBusStarkErrorV1 as Error;
    match error {
        Error::Resource => ZkX509StarkErrorV1::AllocationFailure,
        Error::Phase => ZkX509StarkErrorV1::TranscriptMismatch,
        Error::Challenge => ZkX509StarkErrorV1::TranscriptMismatch,
        Error::Topology
        | Error::LengthOrPadding
        | Error::InactiveCall
        | Error::Digest
        | Error::Terminal => ZkX509StarkErrorV1::AccumulatorWitness,
        #[cfg(test)]
        Error::Event => ZkX509StarkErrorV1::AccumulatorWitness,
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn map_main_rfc_source_error_v1(
    error: super::rfc5280_stark::ZkX509Rfc5280StarkErrorV1,
) -> ZkX509StarkErrorV1 {
    use super::rfc5280_stark::ZkX509Rfc5280StarkErrorV1 as Error;
    match error {
        Error::Resource => ZkX509StarkErrorV1::AllocationFailure,
        Error::Challenge => ZkX509StarkErrorV1::TranscriptMismatch,
        Error::Shape
        | Error::Grammar
        | Error::Semantic
        | Error::Source
        | Error::Output
        | Error::TerminalClaim => ZkX509StarkErrorV1::DerWitness,
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_log19_sha_base_sources_v1<'a>(
    schedule: &'a ZkX509ShaCallScheduleV1,
    witnesses: &'a [ZkX509ShaCallWitnessV1; super::sha_call_bus_stark::ZK_X509_SHA_CALL_COUNT_V1],
) -> Result<[ZkX509ShaBatchSegmentBaseSourceV1<'a>; ZK_X509_SHA_SEGMENT_COUNT_V1], ZkX509StarkErrorV1>
{
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(ZK_X509_SHA_SEGMENT_COUNT_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for segment in 0..ZK_X509_SHA_SEGMENT_COUNT_V1 {
        sources.push(
            ZkX509ShaBatchSegmentBaseSourceV1::new_v1(schedule, witnesses, segment)
                .map_err(map_main_sha_source_error_v1)?,
        );
    }
    sources
        .try_into()
        .map_err(|_: Vec<ZkX509ShaBatchSegmentBaseSourceV1<'a>>| {
            ZkX509StarkErrorV1::InternalInvariant
        })
}
/// Challenge-independent owner of the complete mixed native-log19 MAIN group.
///
/// Strict DER, RFC 5280, the four SHA registrations, and all fifteen P-256
/// registrations are routed from the verifier-owned registration.  The type
/// deliberately has no auxiliary-column implementation: a successful X5B1
/// transition consumes it and returns [`MainLog19BoundTraceGroupSourceV1`].
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainLog19BaseTraceGroupSourceV1<'assembly, 'source> {
    registrations: Vec<RegisteredSegmentLayoutV1>,
    p256_bindings: Vec<MainP256RegistrationBindingV1>,
    der: &'assembly ZkX509DerStarkBaseV1,
    rfc: &'assembly ZkX509Rfc5280StarkBaseMaterialV1,
    sha: &'source [ZkX509ShaBatchSegmentBaseSourceV1<'assembly>; ZK_X509_SHA_SEGMENT_COUNT_V1],
    p256: &'source P256MainBaseSourceV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'assembly, 'source> MainLog19BaseTraceGroupSourceV1<'assembly, 'source> {
    /// This wrapper owns registration metadata; all native trace sources are borrowed.
    fn allocated_payload_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            core::mem::size_of_val(self),
            vector_v1(&self.registrations),
            vector_v1(&self.p256_bindings),
        ])
    }
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        assembly: &'assembly ZkX509MainTraceAssemblyV1,
        sha: &'source [ZkX509ShaBatchSegmentBaseSourceV1<'assembly>; ZK_X509_SHA_SEGMENT_COUNT_V1],
        p256: &'source P256MainBaseSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_zk_x509_main_verifier_profile_v1(assembly.verifier_profile)?;
        validate_p256_main_registration_order_v1(&p256.canonical_registrations_v1()?)
            .map_err(|_| ZkX509StarkErrorV1::P256Witness)?;
        Ok(Self {
            registrations: canonical_main_log19_registrations_v1(layout)?,
            p256_bindings: canonical_p256_main_log19_bindings_v1(layout)?,
            der: &assembly.der_base,
            rfc: &assembly.rfc_base,
            sha,
            p256,
        })
    }
    fn registration_index_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let mut matches = self
            .registrations
            .iter()
            .enumerate()
            .filter(|(_, candidate)| **candidate == registration)
            .map(|(index, _)| index);
        let index = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(index)
    }
    fn p256_binding_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .p256_bindings
            .iter()
            .copied()
            .filter(|binding| binding.main == registration);
        let binding = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(binding)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainLog19BaseTraceGroupSourceV1<'_, '_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let registration_index = self.registration_index_v1(registration)?;
        if local_column >= registration.segment.base_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let column = match registration_index {
            0 => build_zk_x509_der_stark_native_base_column_v1(self.der, local_column)
                .map_err(ZkX509StarkErrorV1::from)?,
            1 => self
                .rfc
                .build_base_column(local_column)
                .map_err(map_main_rfc_source_error_v1)?,
            2..=5 => {
                let segment = registration_index - 2;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.sha[segment]
                    .fill_base_column_v1(segment, local_column, &mut column)
                    .map_err(map_main_sha_source_error_v1)?;
                return Ok(column);
            }
            _ => {
                let binding = self.p256_binding_v1(registration)?;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.p256
                    .fill_base_column_v1(binding.p256, local_column, &mut column)?;
                return Ok(column);
            }
        };
        Ok(ZeroizingMainTraceColumnV1(column))
    }
    fn native_aux_column_v1(
        &self,
        _registration: RegisteredSegmentLayoutV1,
        _local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        Err(ZkX509StarkErrorV1::TranscriptMismatch)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_main_der_trace_cells_v1(trace: &mut ZkX509DerStarkTraceV1) {
    trace.base.zeroize_private_cells_v1();
    for value in trace.aux_rows.iter_mut().flatten() {
        value.zeroize_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroize_main_der_trace_v1(trace: &mut ZkX509DerStarkTraceV1) {
    zeroize_main_der_trace_cells_v1(trace);
    trace.base.private_shape.document_lengths.clear();
    trace.base.rows.clear();
    trace.aux_rows.clear();
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct ZeroizingMainDerTraceGuardV1(Option<ZkX509DerStarkTraceV1>);
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZeroizingMainDerTraceGuardV1 {
    fn new_v1(trace: ZkX509DerStarkTraceV1) -> Self {
        Self(Some(trace))
    }
    fn take_v1(&mut self) -> Result<ZkX509DerStarkTraceV1, ZkX509StarkErrorV1> {
        self.0.take().ok_or(ZkX509StarkErrorV1::InternalInvariant)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for ZeroizingMainDerTraceGuardV1 {
    fn drop(&mut self) {
        if let Some(trace) = self.0.as_mut() {
            zeroize_main_der_trace_v1(trace);
        }
        self.0 = None;
    }
}
/// Challenge-bound owner of the complete mixed native-log19 MAIN group.
///
/// Construction consumes the pre-X5B1 owner and requires both the outer
/// credential binding and the P-256 capability bound by that same token.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainLog19BoundTraceGroupSourceV1<'a> {
    registrations: Vec<RegisteredSegmentLayoutV1>,
    p256_bindings: Vec<MainP256RegistrationBindingV1>,
    der: ZkX509DerStarkTraceV1,
    der_fixed: ZkX509DerStarkFixedScheduleV1,
    rfc: ZkX509Rfc5280StarkColumnProviderV1<'a>,
    sha_aux: [ZkX509ShaBatchSegmentAuxSourceV1<'a>; ZK_X509_SHA_SEGMENT_COUNT_V1],
    sha_fixed: ZkX509ShaBatchFixedProviderV1,
    p256: P256MainBoundSourceV1,
    post_base: ZkX509CredentialMainPostBaseChallengesV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainLog19BoundTraceGroupSourceV1<'a> {
    /// Capacity of the bound DER/P-256 owners plus independently retained fixed schedules.
    /// The borrowed assembly and RFC/SHA witness storage are charged by their owner.
    fn allocated_payload_bytes_v1(&self) -> usize {
        use super::allocation_payload::{sum_v1, vector_v1};
        sum_v1([
            core::mem::size_of_val(self) - core::mem::size_of_val(&self.p256),
            self.p256.allocated_payload_bytes_v1(),
            vector_v1(&self.registrations),
            vector_v1(&self.p256_bindings),
            vector_v1(&self.der.base.private_shape.document_lengths),
            vector_v1(&self.der.base.rows),
            vector_v1(&self.der.aux_rows),
            self.sha_fixed.allocated_heap_bytes_v1(),
            sum_v1(
                self.sha_aux
                    .iter()
                    .map(ZkX509ShaBatchSegmentAuxSourceV1::retained_aux_heap_bytes_v1),
            ),
        ])
    }
    /// Consume every challenge-independent log19 child exactly once under the
    /// credential-derived X5B1 binding.
    ///
    /// This is deliberately the only transition into the bound mixed group. In particular, callers
    /// cannot provide a separately bound P-256 source: P-256 and all four SHA segments are
    /// transitioned here from the same opaque credential capability.
    fn bind_from_phase_v1(
        layout: &AggregateProofLayoutV1,
        assembly: &'a ZkX509MainTraceAssemblyV1,
        mut sha: [ZkX509ShaBatchSegmentBaseSourceV1<'a>; ZK_X509_SHA_SEGMENT_COUNT_V1],
        mut p256: P256MainBaseSourceV1,
        binding: ZkX509CredentialPreAuxBindingV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        validate_zk_x509_main_verifier_profile_v1(assembly.verifier_profile)?;
        let registrations = canonical_main_log19_registrations_v1(layout)?;
        let p256_bindings = canonical_p256_main_log19_bindings_v1(layout)?;
        let post_base = binding.main_post_base();
        let p256 = p256.bind_v1(post_base)?;
        if p256.post_base_v1()? != post_base {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let mut sha_aux = Vec::new();
        sha_aux
            .try_reserve_exact(ZK_X509_SHA_SEGMENT_COUNT_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        for source in &mut sha {
            sha_aux.push(
                source
                    .bind_v1(binding)
                    .map_err(map_main_sha_source_error_v1)?,
            );
        }
        let mut sha_aux: [ZkX509ShaBatchSegmentAuxSourceV1<'a>; ZK_X509_SHA_SEGMENT_COUNT_V1] =
            sha_aux
                .try_into()
                .map_err(|_: Vec<ZkX509ShaBatchSegmentAuxSourceV1<'a>>| {
                    ZkX509StarkErrorV1::InternalInvariant
                })?;
        // The complete public cache forecast was admitted before constructing
        // sources. Build after the temporary owner vector has been consumed so
        // private cached endpoints never remain in that retired allocation.
        for source in &mut sha_aux {
            source
                .retain_native_aux_v1()
                .map_err(map_main_sha_source_error_v1)?;
        }
        #[cfg(test)]
        let der_timer = super::prover_observation::PhaseTimerV1::start_v1(
            super::prover_observation::PhaseV1::DerBinding,
        );
        let mut der = ZeroizingMainDerTraceGuardV1::new_v1(
            build_zk_x509_der_stark_trace_v1(assembly.der_base.clone(), post_base.der())
                .map_err(ZkX509StarkErrorV1::from)?,
        );
        #[cfg(test)]
        der_timer.complete_v1();
        #[cfg(test)]
        let rfc_timer = super::prover_observation::PhaseTimerV1::start_v1(
            super::prover_observation::PhaseV1::RfcBinding,
        );
        // Only this original binding and the four already-bound physical SHA sources can
        // produce the private union owner. It retains the sixteen private centers and checks
        // each physical segment through actual SHA replay; only compact-CA boundaries escape.
        let (sha_union, ca_calls) =
            ZkX509ShaUnionCentersV1::from_bound_sources_v1(&sha_aux, binding)
                .map_err(map_main_rfc_source_error_v1)?;
        let _private_ca_calls = zeroize::Zeroizing::new(ca_calls);
        let rfc =
            ZkX509Rfc5280StarkColumnProviderV1::new_v1(&assembly.rfc_base, binding, sha_union)
                .map_err(map_main_rfc_source_error_v1)?;
        #[cfg(test)]
        rfc_timer.complete_v1();
        let der_fixed = compile_zk_x509_der_stark_fixed_schedule_v1(ZkX509DerStarkShapeV1)
            .map_err(ZkX509StarkErrorV1::from)?;
        let sha_fixed = ZkX509ShaBatchFixedProviderV1::new_v1(assembly.sha_schedule.shape())
            .map_err(map_main_sha_source_error_v1)?;
        let der = der.take_v1()?;
        Ok(Self {
            registrations,
            p256_bindings,
            der,
            der_fixed,
            rfc,
            sha_aux,
            sha_fixed,
            p256,
            post_base,
        })
    }
    fn registration_index_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let mut matches = self
            .registrations
            .iter()
            .enumerate()
            .filter(|(_, candidate)| **candidate == registration)
            .map(|(index, _)| index);
        let index = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(index)
    }
    fn p256_binding_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
        let mut matches = self
            .p256_bindings
            .iter()
            .copied()
            .filter(|binding| binding.main == registration);
        let binding = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        if matches.next().is_some() {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(binding)
    }
    fn zeroize_private_v1(&mut self) {
        zeroize_main_der_trace_v1(&mut self.der);
    }
    fn native_fixed_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let registration_index = self.registration_index_v1(registration)?;
        if local_column >= registration.segment.fixed_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let column = match registration_index {
            0 => build_zk_x509_der_stark_native_fixed_column_v1(&self.der_fixed, local_column)
                .map_err(ZkX509StarkErrorV1::from)?,
            1 => self
                .rfc
                .build_fixed_column_v1(local_column)
                .map_err(map_main_rfc_source_error_v1)?,
            2..=5 => {
                let segment = registration_index - 2;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                for (row, value) in column.iter_mut().enumerate() {
                    *value = self
                        .sha_fixed
                        .fixed_row_v1(segment, row)
                        .map_err(map_main_sha_source_error_v1)?[local_column];
                }
                return Ok(column);
            }
            _ => {
                let binding = self.p256_binding_v1(registration)?;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.p256
                    .fill_fixed_column_v1(binding.p256, local_column, &mut column)?;
                return Ok(column);
            }
        };
        Ok(ZeroizingMainTraceColumnV1(column))
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for MainLog19BoundTraceGroupSourceV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainLog19BoundTraceGroupSourceV1<'_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let registration_index = self.registration_index_v1(registration)?;
        if local_column >= registration.segment.base_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let column = match registration_index {
            0 => build_zk_x509_der_stark_native_base_column_v1(&self.der.base, local_column)
                .map_err(ZkX509StarkErrorV1::from)?,
            1 => self
                .rfc
                .build_base_column_v1(local_column)
                .map_err(map_main_rfc_source_error_v1)?,
            2..=5 => {
                let segment = registration_index - 2;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.sha_aux[segment]
                    .replay_base_column_v1(segment, local_column, &mut column)
                    .map_err(map_main_sha_source_error_v1)?;
                return Ok(column);
            }
            _ => {
                let binding = self.p256_binding_v1(registration)?;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.p256
                    .fill_base_column_v1(binding.p256, local_column, &mut column)?;
                return Ok(column);
            }
        };
        Ok(ZeroizingMainTraceColumnV1(column))
    }
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let registration_index = self.registration_index_v1(registration)?;
        if local_column >= registration.segment.aux_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let column = match registration_index {
            0 => build_zk_x509_der_stark_native_aux_column_v1(&self.der, local_column)
                .map_err(ZkX509StarkErrorV1::from)?,
            1 => self
                .rfc
                .build_aux_column_v1(local_column)
                .map_err(map_main_rfc_source_error_v1)?,
            2..=5 => {
                let segment = registration_index - 2;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.sha_aux[segment]
                    .fill_aux_column_v1(segment, local_column, &mut column)
                    .map_err(map_main_sha_source_error_v1)?;
                return Ok(column);
            }
            _ => {
                let binding = self.p256_binding_v1(registration)?;
                let mut column = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
                self.p256
                    .fill_aux_column_v1(binding.p256, local_column, &mut column)?;
                return Ok(column);
            }
        };
        Ok(ZeroizingMainTraceColumnV1(column))
    }
}
/// Native fixed-polynomial and quotient owner for the complete mixed log19 prover group.
///
/// The source borrows the already-bound trace owner, so it is impossible to
/// evaluate a challenge-dependent residue against a pre-X5B1 trace.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainLog19ProverConstraintSourceV1<'a, 'source> {
    source: &'source MainLog19BoundTraceGroupSourceV1<'a>,
    der_public: ZkX509DerStarkPublicTerminalsV1,
    p256_challenges: P256AggregateChallengesV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a, 'source> MainLog19ProverConstraintSourceV1<'a, 'source> {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        source: &'source MainLog19BoundTraceGroupSourceV1<'a>,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        if canonical_main_log19_registrations_v1(layout)? != source.registrations
            || source.p256.post_base_v1()? != source.post_base
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        Ok(Self {
            source,
            der_public: derive_zk_x509_der_stark_public_terminals_v1(
                &ZkX509DerStarkShapeV1,
                source.post_base.der(),
            )
            .map_err(ZkX509StarkErrorV1::from)?,
            p256_challenges: p256_aggregate_challenges_from_post_base_v1(source.post_base)?,
        })
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(
            RegisteredSegmentLayoutV1,
            usize,
            &[F],
        ) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        for registration in self.source.registrations.iter().copied() {
            let trace_root = goldilocks_primitive_root_v1(registration.segment.trace_log2)
                .map_err(map_transparent_error_v1)?;
            for local_column in 0..registration.segment.fixed_width {
                let mut coefficients = self
                    .source
                    .native_fixed_column_v1(registration, local_column)?;
                goldilocks_ifft_v1(&mut coefficients, trace_root)
                    .map_err(map_transparent_error_v1)?;
                consume(registration, local_column, &coefficients)?;
            }
        }
        Ok(())
    }
    fn constraint_residues_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed_current: &[F],
        fixed_next: &[F],
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let registration_index = self.source.registration_index_v1(registration)?;
        if fixed_current.len() != registration.segment.fixed_width
            || fixed_next.len() != registration.segment.fixed_width
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .chain(fixed_current)
                .chain(fixed_next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues = match registration_index {
            0 => super::der_stark::evaluate_zk_x509_der_stark_local_residues_v1(
                opening
                    .base_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                opening
                    .base_next
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                opening
                    .aux_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                opening
                    .aux_next
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                fixed_next
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                self.source.post_base.der(),
                self.der_public,
            )
            .map_err(ZkX509StarkErrorV1::from)?,
            1 => evaluate_zk_x509_rfc5280_local_residues_v1(
                opening
                    .base_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                opening
                    .base_next
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                opening
                    .aux_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                opening
                    .aux_next
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                fixed_current
                    .try_into()
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                self.source.post_base.der(),
                self.source.post_base.rfc5280(),
            )
            .map_err(map_main_rfc_source_error_v1)?,
            2..=5 => {
                let segment = registration_index - 2;
                let current = ZkX509ShaBatchRowV1 {
                    base: *<&[F; ZK_X509_SHA_BATCH_BASE_WIDTH_V1]>::try_from(opening.base_current)
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    aux: *<&[F; ZK_X509_SHA_BATCH_AUX_WIDTH_V1]>::try_from(opening.aux_current)
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    fixed: *<&[F; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]>::try_from(fixed_current)
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                };
                let next = ZkX509ShaBatchRowV1 {
                    base: *<&[F; ZK_X509_SHA_BATCH_BASE_WIDTH_V1]>::try_from(opening.base_next)
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    aux: *<&[F; ZK_X509_SHA_BATCH_AUX_WIDTH_V1]>::try_from(opening.aux_next)
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                    fixed: *<&[F; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]>::try_from(fixed_next)
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                };
                evaluate_zk_x509_sha_batch_local_residues_over_field_v1(
                    &current,
                    &next,
                    self.source.post_base.sha_word(),
                    self.source.post_base.sha(),
                    self.source.post_base.rfc5280(),
                    u8::try_from(segment).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?,
                )
                .map_err(map_main_sha_source_error_v1)?
            }
            _ => {
                let _binding = self.source.p256_binding_v1(registration)?;
                p256_opened_residues_v1(registration, opening, fixed_current, self.p256_challenges)?
            }
        };
        if residues.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(residues)
    }
    #[cfg(test)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed_current: &[F],
        fixed_next: &[F],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if F::canonical(x.0).is_none() || alphas.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        accumulator_quotient_value_v1(
            registration.segment,
            x,
            &self.constraint_residues_v1(registration, opening, fixed_current, fixed_next)?,
            alphas,
        )
    }
}
/// Verifier-side fixed-opening owner for the fifteen P-256 registrations in
/// MAIN's mixed native-log19 group.
///
/// Construction validates the manifest-bound log19 bindings, the post-base
/// P-256 challenges and the terminal claims; the complete OODS evaluation then
/// consumes the group through [`MainLog19VerifierConstraintSourceV1`].
struct MainP256Log19VerifierConstraintSourceV1 {
    fixed_openings: Option<ZkX509FixedAlgebraicOpeningsV1>,
}
impl MainP256Log19VerifierConstraintSourceV1 {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let bindings = canonical_p256_main_log19_bindings_v1(layout)?;
        if layout.common_lde_log2 != ZK_X509_MAIN_COMMON_LDE_LOG2_V1
            || bindings
                .iter()
                .any(|binding| binding.main.segment.trace_log2 != ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        p256_aggregate_challenges_from_post_base_v1(post_base)?;

        Ok(Self {
            fixed_openings: None,
        })
    }
    #[cfg(test)]
    fn install_verifier_derived_fixed_openings_v1(
        &mut self,
        openings: ZkX509FixedAlgebraicOpeningsV1,
        expected_indices: &[u64],
    ) -> Result<(), ZkX509StarkErrorV1> {
        if self.fixed_openings.is_some() {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        validate_verifier_derived_p256_log19_fixed_openings_v1(&openings, expected_indices)?;
        self.fixed_openings = Some(openings);
        Ok(())
    }
    #[cfg(test)]
    fn cached_openings_v1(&self) -> usize {
        self.fixed_openings
            .as_ref()
            .map_or(0, ZkX509FixedAlgebraicOpeningsV1::len_v1)
    }
}
#[cfg(test)]
fn validate_verifier_derived_p256_log19_fixed_openings_v1(
    openings: &ZkX509FixedAlgebraicOpeningsV1,
    expected_indices: &[u64],
) -> Result<(), ZkX509StarkErrorV1> {
    let schedule =
        zk_x509_p256_fixed_algebraic_schedule_v1().map_err(map_p256_fixed_algebraic_error_v1)?;
    if openings.is_empty_v1()
        || openings.len_v1() > VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1
        || openings.query_indices_v1() != expected_indices
        || usize::from(openings.width_v1()) != ZK_X509_P256_FIXED_ALGEBRAIC_WIDTH_V1
        || openings.schedule_digest_v1() != schedule.descriptor_digest_v1()
    {
        return Err(ZkX509StarkErrorV1::TraceOpening);
    }
    Ok(())
}
const MAIN_LOG19_SHA_PUBLIC_FIXED_START_V1: usize = ZK_X509_SHA_FIXED_RFC_LENGTH_PAIR_V1;
const MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1: usize =
    ZK_X509_SHA_BATCH_FIXED_WIDTH_V1 - MAIN_LOG19_SHA_PUBLIC_FIXED_START_V1;
const MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1: usize = ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1
    + ZK_X509_SHA_SEGMENT_COUNT_V1 * MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1;
const MAIN_LOG19_AFFINE_SEGMENT_GROWTH_V1: usize = 4_096;
const _: () = assert!(MAIN_LOG19_SHA_PUBLIC_FIXED_START_V1 == 91);
const _: () = assert!(MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1 == 27);
const _: () = assert!(MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1 == 255);
const _: () = assert!(MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1 <= u8::MAX as usize);
const _: () = assert!(
    P256_MAIN_LOG19_NEXT_STRIDE_V1
        == 1_usize << (ZK_X509_MAIN_COMMON_LDE_LOG2_V1 - ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
);
/// One maximal affine range in a verifier-owned fixed column.
///
/// `value(row) = start_value + step * (row - start)` for `start..end`.
/// Zero ranges are implicit and never retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MainLog19PublicFixedAffineSegmentV1 {
    column: u8,
    start: u32,
    end: u32,
    start_value: F,
    step: F,
}
#[derive(Clone, Copy)]
struct MainLog19AffineTrackerV1 {
    initialized: bool,
    start: u32,
    start_value: F,
    previous: F,
    step: Option<F>,
}
impl MainLog19AffineTrackerV1 {
    const EMPTY: Self = Self {
        initialized: false,
        start: 0,
        start_value: F::ZERO,
        previous: F::ZERO,
        step: None,
    };
    fn observe_v1(&mut self, row: u32, value: F) -> Option<(u32, u32, F, F)> {
        if !self.initialized {
            self.initialized = true;
            self.start = row;
            self.start_value = value;
            self.previous = value;
            self.step = None;
            return None;
        }
        let candidate_step = value.sub(self.previous);
        match self.step {
            None => {
                self.step = Some(candidate_step);
                self.previous = value;
                None
            }
            Some(step) if step == candidate_step => {
                self.previous = value;
                None
            }
            Some(step) => {
                let completed = (self.start, row, self.start_value, step);
                self.start = row;
                self.start_value = value;
                self.previous = value;
                self.step = None;
                Some(completed)
            }
        }
    }
    fn finish_v1(self, end: u32) -> Option<(u32, u32, F, F)> {
        self.initialized.then_some((
            self.start,
            end,
            self.start_value,
            self.step.unwrap_or(F::ZERO),
        ))
    }
}
/// Canonical piecewise-affine representation of all verifier-generated public
/// fixed columns in MAIN's native-log19 group.
///
/// Long selector runs, counters, offsets, and statement-derived event ranges
/// are retained structurally instead of materializing 3.5 million nonzero
/// cells. All transcript queries are evaluated as one batch over this schedule.
struct MainLog19PublicFixedAffineScheduleV1 {
    segments: Vec<MainLog19PublicFixedAffineSegmentV1>,
}
fn main_log19_public_fixed_row_v1(
    rfc: &ZkX509Rfc5280StarkFixedScheduleV1,
    sha: &ZkX509ShaBatchFixedProviderV1,
    row: usize,
) -> Result<[F; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1], ZkX509StarkErrorV1> {
    let mut combined = [F::ZERO; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1];
    let rfc_row = rfc
        .fixed_row(row)
        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
    combined[..ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1].copy_from_slice(&rfc_row);
    for segment in 0..ZK_X509_SHA_SEGMENT_COUNT_V1 {
        let sha_row = sha
            .fixed_row_v1(segment, row)
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let start =
            ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1 + segment * MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1;
        combined[start..start + MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1]
            .copy_from_slice(&sha_row[MAIN_LOG19_SHA_PUBLIC_FIXED_START_V1..]);
    }
    if combined.iter().any(|value| F::canonical(value.0).is_none()) {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(combined)
}
impl MainLog19PublicFixedAffineScheduleV1 {
    fn push_v1(
        &mut self,
        column: usize,
        start: u32,
        end: u32,
        start_value: F,
        step: F,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if start_value == F::ZERO && step == F::ZERO {
            return Ok(());
        }
        if column >= MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1
            || start >= end
            || usize::try_from(end).map_or(true, |end| end > ZK_X509_DER_STARK_TRACE_SIZE_V1)
            || F::canonical(start_value.0).is_none()
            || F::canonical(step.0).is_none()
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        if self.segments.len() == self.segments.capacity() {
            self.segments
                .try_reserve(MAIN_LOG19_AFFINE_SEGMENT_GROWTH_V1)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        }
        self.segments.push(MainLog19PublicFixedAffineSegmentV1 {
            column: u8::try_from(column).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?,
            start,
            end,
            start_value,
            step,
        });
        Ok(())
    }
    fn compile_v1(
        rfc: &ZkX509Rfc5280StarkFixedScheduleV1,
        sha: &ZkX509ShaBatchFixedProviderV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let mut schedule = Self {
            segments: Vec::new(),
        };
        let mut trackers = [MainLog19AffineTrackerV1::EMPTY; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1];
        for row in 0..ZK_X509_DER_STARK_TRACE_SIZE_V1 {
            let row_u32 = u32::try_from(row).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
            let combined = main_log19_public_fixed_row_v1(rfc, sha, row)?;
            for (column, (tracker, value)) in trackers.iter_mut().zip(combined).enumerate() {
                if let Some((start, end, start_value, step)) = tracker.observe_v1(row_u32, value) {
                    schedule.push_v1(column, start, end, start_value, step)?;
                }
            }
        }
        let end = u32::try_from(ZK_X509_DER_STARK_TRACE_SIZE_V1)
            .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
        for (column, tracker) in trackers.into_iter().enumerate() {
            if let Some((start, end, start_value, step)) = tracker.finish_v1(end) {
                schedule.push_v1(column, start, end, start_value, step)?;
            }
        }
        schedule
            .segments
            .sort_unstable_by_key(|segment| (segment.column, segment.start));
        schedule.validate_v1()?;
        Ok(schedule)
    }
    fn validate_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        if self.segments.is_empty()
            || self
                .segments
                .windows(2)
                .any(|pair| (pair[0].column, pair[0].start) >= (pair[1].column, pair[1].start))
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        let mut previous: [Option<MainLog19PublicFixedAffineSegmentV1>;
            MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1] = [None; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1];
        for segment in &self.segments {
            let column = usize::from(segment.column);
            if column >= MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1
                || segment.start >= segment.end
                || usize::try_from(segment.end)
                    .map_or(true, |end| end > ZK_X509_DER_STARK_TRACE_SIZE_V1)
                || (segment.start_value == F::ZERO && segment.step == F::ZERO)
                || F::canonical(segment.start_value.0).is_none()
                || F::canonical(segment.step.0).is_none()
                || previous[column].is_some_and(|prior| prior.end > segment.start)
            {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            previous[column] = Some(*segment);
        }
        Ok(())
    }
    #[cfg(test)]
    fn opened_all_v1(
        &self,
        query_schedule: &MainLog19VerifierQueryScheduleV1,
    ) -> Result<BTreeMap<usize, MainLog19VerifierGeneratedFixedOpeningV1>, ZkX509StarkErrorV1> {
        self.validate_v1()?;
        query_schedule.validate_v1()?;
        let common_lde_size = 1_usize
            .checked_shl(u32::from(ZK_X509_MAIN_COMMON_LDE_LOG2_V1))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let mut groups = BTreeMap::<usize, Vec<(usize, usize)>>::new();
        for index in query_schedule.indices.iter().copied() {
            let index = usize::try_from(index).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            if index >= common_lde_size {
                return Err(ZkX509StarkErrorV1::TraceOpening);
            }
            groups
                .entry(index % P256_MAIN_LOG19_NEXT_STRIDE_V1)
                .or_default()
                .push((index, index / P256_MAIN_LOG19_NEXT_STRIDE_V1));
        }
        let mut generated = BTreeMap::new();
        for (remainder, indices_and_shifts) in groups {
            let weights = main_log19_lagrange_weights_v1(remainder)?;
            let (prefix, linear_prefix) = main_log19_weight_prefixes_v1(&weights)?;
            let mut combined = Vec::new();
            combined
                .try_reserve_exact(indices_and_shifts.len())
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            combined.resize(
                indices_and_shifts.len(),
                [F::ZERO; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1],
            );
            for segment in &self.segments {
                for ((_, shift), opening) in indices_and_shifts.iter().zip(&mut combined) {
                    let contribution = main_log19_shifted_affine_segment_sum_v1(
                        &prefix,
                        &linear_prefix,
                        *shift,
                        *segment,
                    )?;
                    let column = usize::from(segment.column);
                    opening[column] = opening[column].add(contribution);
                }
            }
            for ((index, shift), combined) in indices_and_shifts.into_iter().zip(combined) {
                let der = main_log19_der_fixed_opening_from_prefix_v1(&weights, &prefix, shift)?;
                if generated
                    .insert(index, main_log19_generated_fixed_opening_v1(der, combined))
                    .is_some()
                {
                    return Err(ZkX509StarkErrorV1::InternalInvariant);
                }
            }
        }
        if generated.len() != query_schedule.indices.len()
            || generated
                .keys()
                .copied()
                .zip(query_schedule.indices.iter().copied())
                .any(|(actual, expected)| u64::try_from(actual).ok() != Some(expected))
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        Ok(generated)
    }
}
fn main_log19_weight_prefixes_v1<A: PolynomialAirFieldV1 + PartialEq>(
    weights: &[A],
) -> Result<(Vec<A>, Vec<A>), ZkX509StarkErrorV1> {
    if weights.len() != ZK_X509_DER_STARK_TRACE_SIZE_V1
        || weights.iter().any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut prefix = Vec::new();
    let mut linear_prefix = Vec::new();
    prefix
        .try_reserve_exact(ZK_X509_DER_STARK_TRACE_SIZE_V1 + 1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    linear_prefix
        .try_reserve_exact(ZK_X509_DER_STARK_TRACE_SIZE_V1 + 1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    prefix.push(A::ZERO);
    linear_prefix.push(A::ZERO);
    for (row, weight) in weights.iter().copied().enumerate() {
        prefix.push(
            prefix
                .last()
                .copied()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
                .add(weight),
        );
        linear_prefix.push(
            linear_prefix
                .last()
                .copied()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
                .add(
                    A::from_base(F(
                        u64::try_from(row).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?
                    ))
                    .mul(weight),
                ),
        );
    }
    if prefix.last() != Some(&A::ONE) {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok((prefix, linear_prefix))
}
fn main_log19_affine_prefix_sum_v1<A: PolynomialAirFieldV1 + PartialEq>(
    prefix: &[A],
    linear_prefix: &[A],
    start: usize,
    end: usize,
    start_value: F,
    step: F,
) -> Result<A, ZkX509StarkErrorV1> {
    if start > end
        || end > ZK_X509_DER_STARK_TRACE_SIZE_V1
        || prefix.len() != ZK_X509_DER_STARK_TRACE_SIZE_V1 + 1
        || linear_prefix.len() != prefix.len()
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let weight_sum = prefix[end].sub(prefix[start]);
    let relative_linear_sum = linear_prefix[end].sub(linear_prefix[start]).sub(
        A::from_base(F(
            u64::try_from(start).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?
        ))
        .mul(weight_sum),
    );
    Ok(weight_sum
        .mul_base(start_value)
        .add(relative_linear_sum.mul_base(step)))
}
fn main_log19_shifted_affine_segment_sum_v1<A: PolynomialAirFieldV1 + PartialEq>(
    prefix: &[A],
    linear_prefix: &[A],
    shift: usize,
    segment: MainLog19PublicFixedAffineSegmentV1,
) -> Result<A, ZkX509StarkErrorV1> {
    let rows = ZK_X509_DER_STARK_TRACE_SIZE_V1;
    if shift >= rows {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let start =
        usize::try_from(segment.start).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
    let end = usize::try_from(segment.end).map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
    let mut result = A::ZERO;
    let before_end = end.min(shift);
    if start < before_end {
        let mapped_start = start
            .checked_add(rows - shift)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        result = result.add(main_log19_affine_prefix_sum_v1(
            prefix,
            linear_prefix,
            mapped_start,
            mapped_start + before_end - start,
            segment.start_value,
            segment.step,
        )?);
    }
    let after_start = start.max(shift);
    if after_start < end {
        let value_at_after = segment.start_value.add(
            segment.step.mul(F(u64::try_from(after_start - start)
                .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?)),
        );
        result = result.add(main_log19_affine_prefix_sum_v1(
            prefix,
            linear_prefix,
            after_start - shift,
            end - shift,
            value_at_after,
            segment.step,
        )?);
    }
    Ok(result)
}
fn main_log19_shifted_weight_v1<A: PolynomialAirFieldV1 + PartialEq>(
    weights: &[A],
    row: usize,
    shift: usize,
) -> Result<A, ZkX509StarkErrorV1> {
    let rows = ZK_X509_DER_STARK_TRACE_SIZE_V1;
    if weights.len() != rows || row >= rows || shift >= rows {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(weights[(row + rows - shift) % rows])
}
fn main_log19_shifted_weight_sum_v1<A: PolynomialAirFieldV1 + PartialEq>(
    prefix: &[A],
    start: usize,
    end: usize,
    shift: usize,
) -> Result<A, ZkX509StarkErrorV1> {
    let rows = ZK_X509_DER_STARK_TRACE_SIZE_V1;
    if prefix.len() != rows + 1 || start > end || end > rows || shift >= rows {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let mut result = A::ZERO;
    let before_end = end.min(shift);
    if start < before_end {
        let mapped_start = start + rows - shift;
        result = result.add(prefix[mapped_start + before_end - start].sub(prefix[mapped_start]));
    }
    let after_start = start.max(shift);
    if after_start < end {
        result = result.add(prefix[end - shift].sub(prefix[after_start - shift]));
    }
    Ok(result)
}
fn main_log19_der_fixed_opening_from_prefix_v1<A: PolynomialAirFieldV1 + PartialEq>(
    weights: &[A],
    prefix: &[A],
    shift: usize,
) -> Result<[A; ZK_X509_DER_STARK_FIXED_WIDTH_V1], ZkX509StarkErrorV1> {
    let mut fixed = [A::ZERO; ZK_X509_DER_STARK_FIXED_WIDTH_V1];
    fixed[FIX_FIRST_AGGREGATE] = main_log19_shifted_weight_v1(weights, 0, shift)?;
    fixed[FIX_LAST_AGGREGATE] =
        main_log19_shifted_weight_v1(weights, ZK_X509_DER_STARK_TRACE_SIZE_V1 - 1, shift)?;
    fixed[FIX_FIRST_ACTIVE] = fixed[FIX_FIRST_AGGREGATE];
    fixed[DER_FIX_LAST_ACTIVE] = main_log19_shifted_weight_v1(
        weights,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1 - 1,
        shift,
    )?;
    fixed[FIX_FIRST_PARSER] = fixed[FIX_FIRST_AGGREGATE];
    fixed[FIX_LAST_PARSER] = main_log19_shifted_weight_v1(
        weights,
        super::der_stark::ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 - 1,
        shift,
    )?;
    fixed[FIX_FIRST_COMPARATOR] = main_log19_shifted_weight_v1(
        weights,
        super::der_stark::ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1,
        shift,
    )?;
    fixed[FIX_LAST_COMPARATOR] = fixed[DER_FIX_LAST_ACTIVE];
    fixed[DER_FIX_ACTIVE] = main_log19_shifted_weight_sum_v1(
        prefix,
        0,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        shift,
    )?;
    fixed[FIX_PARSER] = main_log19_shifted_weight_sum_v1(
        prefix,
        0,
        super::der_stark::ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1,
        shift,
    )?;
    fixed[FIX_PARSER_CONTINUE] = main_log19_shifted_weight_sum_v1(
        prefix,
        0,
        super::der_stark::ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1 - 1,
        shift,
    )?;
    fixed[FIX_COMPARATOR] = main_log19_shifted_weight_sum_v1(
        prefix,
        super::der_stark::ZK_X509_DER_STARK_MAX_PARSER_ROWS_V1,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        shift,
    )?;
    fixed[FIX_PADDING] = main_log19_shifted_weight_sum_v1(
        prefix,
        ZK_X509_DER_STARK_FIXED_NON_PADDING_ROWS_V1,
        ZK_X509_DER_STARK_TRACE_SIZE_V1,
        shift,
    )?;
    if fixed[DER_FIX_ACTIVE].add(fixed[FIX_PADDING]) != A::ONE
        || fixed[FIX_PARSER].add(fixed[FIX_COMPARATOR]) != fixed[DER_FIX_ACTIVE]
        || fixed[FIX_PARSER_CONTINUE].add(fixed[FIX_LAST_PARSER]) != fixed[FIX_PARSER]
        || fixed[FIX_FINAL_DOCUMENT] != A::ZERO
    {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(fixed)
}
#[cfg(test)]
fn main_log19_lagrange_weights_v1(query_index: usize) -> Result<Vec<F>, ZkX509StarkErrorV1> {
    let common_lde_size = 1_usize
        .checked_shl(u32::from(ZK_X509_MAIN_COMMON_LDE_LOG2_V1))
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if query_index >= common_lde_size {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let trace_root = goldilocks_primitive_root_v1(ZK_X509_MAX_NATIVE_TRACE_LOG2_V1)
        .map_err(map_transparent_error_v1)?;
    let common_root = goldilocks_primitive_root_v1(ZK_X509_MAIN_COMMON_LDE_LOG2_V1)
        .map_err(map_transparent_error_v1)?;
    if common_root.pow(P256_MAIN_LOG19_NEXT_STRIDE_V1 as u128) != trace_root {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    let x = F(GOLDILOCKS_GENERATOR_V1).mul(common_root.pow(query_index as u128));
    let numerator = x.pow(ZK_X509_DER_STARK_TRACE_SIZE_V1 as u128).sub(F::ONE);
    if numerator == F::ZERO {
        return Err(ZkX509StarkErrorV1::TranscriptMismatch);
    }
    let inverse_trace_size = F(u64::try_from(ZK_X509_DER_STARK_TRACE_SIZE_V1)
        .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?)
    .inv()
    .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
    let common = numerator.mul(inverse_trace_size);
    let mut denominators = Vec::new();
    denominators
        .try_reserve_exact(ZK_X509_DER_STARK_TRACE_SIZE_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    let mut trace_point = F::ONE;
    for _ in 0..ZK_X509_DER_STARK_TRACE_SIZE_V1 {
        denominators.push(x.sub(trace_point));
        trace_point = trace_point.mul(trace_root);
    }
    goldilocks_batch_invert_v1(&mut denominators).map_err(map_transparent_error_v1)?;
    trace_point = F::ONE;
    let mut sum = F::ZERO;
    for inverse in &mut denominators {
        *inverse = common.mul(trace_point).mul(*inverse);
        sum = sum.add(*inverse);
        trace_point = trace_point.mul(trace_root);
    }
    if trace_point != F::ONE || sum != F::ONE {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(denominators)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct MainLog19VerifierGeneratedFixedOpeningV1<A = F> {
    der: [A; ZK_X509_DER_STARK_FIXED_WIDTH_V1],
    rfc: ZkX509Rfc5280StarkFixedRowV1<A>,
    sha_public: [[A; MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1]; ZK_X509_SHA_SEGMENT_COUNT_V1],
}
fn main_log19_generated_fixed_opening_v1<A: PolynomialAirFieldV1 + PartialEq>(
    der: [A; ZK_X509_DER_STARK_FIXED_WIDTH_V1],
    combined: [A; MAIN_LOG19_PUBLIC_FIXED_WIDTH_V1],
) -> MainLog19VerifierGeneratedFixedOpeningV1<A> {
    let mut rfc = [A::ZERO; ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1];
    rfc.copy_from_slice(&combined[..ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1]);
    let mut sha_public =
        [[A::ZERO; MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1]; ZK_X509_SHA_SEGMENT_COUNT_V1];
    for (segment, target) in sha_public.iter_mut().enumerate() {
        let start =
            ZK_X509_RFC5280_STARK_FIXED_WIDTH_V1 + segment * MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1;
        target.copy_from_slice(&combined[start..start + MAIN_LOG19_SHA_PUBLIC_FIXED_WIDTH_V1]);
    }
    MainLog19VerifierGeneratedFixedOpeningV1 {
        der,
        rfc,
        sha_public,
    }
}
#[cfg(test)]
fn validate_verifier_derived_sha_fixed_openings_v1(
    openings: &ZkX509FixedAlgebraicOpeningsV1,
    expected_indices: &[u64],
    shape: ZkX509ShaCallPublicShapeV1,
) -> Result<(), ZkX509StarkErrorV1> {
    let schedule =
        zk_x509_sha_fixed_algebraic_schedule_v1(shape).map_err(map_sha_fixed_algebraic_error_v1)?;
    if openings.is_empty_v1()
        || openings.len_v1() > VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1
        || openings.query_indices_v1() != expected_indices
        || usize::from(openings.width_v1()) != ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1
        || openings.schedule_digest_v1() != schedule.descriptor_digest_v1()
    {
        return Err(ZkX509StarkErrorV1::TraceOpening);
    }
    Ok(())
}
fn expand_main_log19_sha_fixed_opening_v1<A: PolynomialAirFieldV1 + PartialEq>(
    combined: &[A],
    public: &MainLog19VerifierGeneratedFixedOpeningV1<A>,
) -> Result<[[A; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]; ZK_X509_SHA_SEGMENT_COUNT_V1], ZkX509StarkErrorV1>
{
    if combined.len() != ZK_X509_SHA_FIXED_ALGEBRAIC_WIDTH_V1
        || combined.iter().any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::TraceOpening);
    }
    let mut rows = [[A::ZERO; ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]; ZK_X509_SHA_SEGMENT_COUNT_V1];
    for (segment, row) in rows.iter_mut().enumerate() {
        let start = segment * ZK_X509_SHA_BATCH_FIXED_WIDTH_V1;
        row.copy_from_slice(&combined[start..start + ZK_X509_SHA_BATCH_FIXED_WIDTH_V1]);
        if row[MAIN_LOG19_SHA_PUBLIC_FIXED_START_V1..] != public.sha_public[segment] {
            return Err(ZkX509StarkErrorV1::TraceOpening);
        }
    }
    Ok(rows)
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "installed only by the test-only verifier-derived opening path"
    )
)]
struct MainLog19InstalledFixedOpeningsV1 {
    generated: BTreeMap<usize, MainLog19VerifierGeneratedFixedOpeningV1>,
}
/// Closed verifier owner for MAIN's complete mixed native-log19 group.
///
/// This is the only production route that can evaluate DER, RFC 5280, all
/// four SHA registrations, and the fifteen P-256 registrations. It owns the
/// exact 21-registration layout and compiles the statement-bound fixed schedule
/// for complete DEEP constraint evaluation. Scalar reference checks additionally
/// install the verifier-derived opening token bound to all 136 transcript-order queries.
struct MainLog19VerifierConstraintSourceV1 {
    post_base: ZkX509CredentialMainPostBaseChallengesV1,
    der_public: ZkX509DerStarkPublicTerminalsV1,
    rfc_fixed: ZkX509Rfc5280StarkFixedScheduleV1,
    sha_shape: ZkX509ShaCallPublicShapeV1,
    sha_fixed: ZkX509ShaBatchFixedProviderV1,
    public_fixed: Option<MainLog19PublicFixedAffineScheduleV1>,
    p256: MainP256Log19VerifierConstraintSourceV1,
    fixed_openings: Option<MainLog19InstalledFixedOpeningsV1>,
}
impl MainLog19VerifierConstraintSourceV1 {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        rfc_statement: &ZkX509Rfc5280StatementV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        canonical_main_log19_registrations_v1(layout)?;

        let der_public =
            derive_zk_x509_der_stark_public_terminals_v1(&ZkX509DerStarkShapeV1, post_base.der())?;
        let rfc_shape = ZkX509Rfc5280StarkShapeV1::from_statement(rfc_statement)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        let rfc_fixed = compile_zk_x509_rfc5280_stark_fixed_schedule_v1(rfc_shape)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        let sha_shape = ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes: rfc_statement.disclosed_attribute_indices.len(),
        };
        let sha_fixed = ZkX509ShaBatchFixedProviderV1::new_v1(sha_shape)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        let p256 = MainP256Log19VerifierConstraintSourceV1::for_main_v1(layout, post_base)?;
        Ok(Self {
            post_base,
            der_public,
            rfc_fixed,
            sha_shape,
            sha_fixed,
            public_fixed: None,
            p256,
            fixed_openings: None,
        })
    }
    fn prepare_complete_oods_fixed_v1(&mut self) -> Result<(), ZkX509StarkErrorV1> {
        if self.public_fixed.is_some()
            || self.fixed_openings.is_some()
            || self.p256.fixed_openings.is_some()
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let fixed =
            MainLog19PublicFixedAffineScheduleV1::compile_v1(&self.rfc_fixed, &self.sha_fixed)?;
        self.public_fixed = Some(fixed);
        Ok(())
    }
    #[cfg(test)]
    fn install_verifier_derived_fixed_openings_v1(
        &mut self,
        derived: ZkX509MainVerifierDerivedFixedOpeningsV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if self.public_fixed.is_some()
            || self.fixed_openings.is_some()
            || self.p256.fixed_openings.is_some()
        {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        let ZkX509MainVerifierDerivedFixedOpeningsV1 {
            query_schedule,
            sha,
            p256_log19,
        } = derived;
        query_schedule.validate_v1()?;
        validate_verifier_derived_sha_fixed_openings_v1(
            &sha,
            &query_schedule.indices,
            self.sha_shape,
        )?;
        validate_verifier_derived_p256_log19_fixed_openings_v1(
            &p256_log19,
            &query_schedule.indices,
        )?;
        // Compile and open the verifier-owned public schedule exactly once for
        // the complete transcript query set. Every allocation, interpolation,
        // and algebraic-SHA consistency check completes in temporary storage before
        // any cache becomes observable.
        let public_fixed =
            MainLog19PublicFixedAffineScheduleV1::compile_v1(&self.rfc_fixed, &self.sha_fixed)?;
        let generated = public_fixed.opened_all_v1(&query_schedule)?;
        let mut expanded_sha = BTreeMap::new();
        for index in query_schedule.indices.iter().copied() {
            let combined = sha
                .row_for_query_v1(index)
                .map_err(map_fixed_algebraic_error_v1)?
                .ok_or(ZkX509StarkErrorV1::TraceOpening)?;
            let index = usize::try_from(index).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let public = generated
                .get(&index)
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
            if expanded_sha
                .insert(
                    index,
                    expand_main_log19_sha_fixed_opening_v1(combined, public)?,
                )
                .is_some()
            {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
        }
        if generated.keys().copied().ne(expanded_sha.keys().copied())
            || expanded_sha.len() != query_schedule.indices.len()
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        // The P-256 opening was fully validated above. Its installation is the
        // only fallible mutation point; the remaining moves are infallible.
        self.p256
            .install_verifier_derived_fixed_openings_v1(p256_log19, &query_schedule.indices)?;
        let installed = MainLog19InstalledFixedOpeningsV1 { generated };
        self.public_fixed = Some(public_fixed);
        self.fixed_openings = Some(installed);
        Ok(())
    }
    #[cfg(test)]
    fn cached_openings_v1(&self) -> usize {
        self.fixed_openings
            .as_ref()
            .map_or(0, |fixed| fixed.generated.len())
    }
}
/// Test-only opened-row adversary interface.
///
/// Production MAIN verification never accepts a dynamic implementation.
/// Concrete verifier variants below are the only production constructors.
#[cfg(test)]
trait MainOpenedConstraintTestSourceV1 {
    fn fixed_opened_rows_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
    ) -> Result<MainFixedOpenedRowsV1, ZkX509StarkErrorV1>;
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &MainFixedOpenedRowsV1,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1>;
}
/// Test-only fixed rows used to exercise malformed-provider rejection.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct MainFixedOpenedRowsV1 {
    current: Vec<F>,
    next: Vec<F>,
}
fn validate_main_projection_registration_v1(
    registration: RegisteredSegmentLayoutV1,
) -> Result<(), ZkX509StarkErrorV1> {
    if registration.segment != SegmentLayoutV1::for_projection()? {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn copied_array_column_v1<const WIDTH: usize>(
    rows: &[[F; WIDTH]],
    local_column: usize,
) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
    if local_column >= WIDTH {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut column = Vec::new();
    column
        .try_reserve_exact(rows.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    column.extend(rows.iter().map(|row| row[local_column]));
    Ok(ZeroizingMainTraceColumnV1(column))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn copied_matrix_column_v1(
    columns: &[Vec<F>],
    expected_width: usize,
    expected_rows: usize,
    local_column: usize,
) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
    if columns.len() != expected_width || local_column >= expected_width {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let source = columns
        .get(local_column)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if source.len() != expected_rows || source.iter().any(|value| F::canonical(value.0).is_none()) {
        return Err(ZkX509StarkErrorV1::IoWitness);
    }
    let mut column = Vec::new();
    column
        .try_reserve_exact(source.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    column.extend_from_slice(source);
    Ok(ZeroizingMainTraceColumnV1(column))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_p256_scalar_registrations_v1(
    layout: &AggregateProofLayoutV1,
) -> Result<[MainP256RegistrationBindingV1; P256_SIGNATURE_COUNT_V1], ZkX509StarkErrorV1> {
    let registrations = canonical_p256_main_layout_bindings_v1(layout)?
        .into_iter()
        .filter(|binding| {
            binding.main.segment.trace_log2 == P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1
                && binding.main.segment.adapter == SegmentAdapterIdV1::P256ScalarBitBus
                && binding.p256.adapter_v1() == P256MainAdapterV1::ScalarBitBus
        })
        .collect::<Vec<_>>();
    let group = registrations
        .first()
        .map(|binding| binding.main.trace_group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let group_layout = layout
        .trace_groups
        .get(group)
        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if registrations.len() != P256_SIGNATURE_COUNT_V1
        || registrations
            .iter()
            .enumerate()
            .any(|(signature, binding)| {
                binding.p256.signature_v1() != signature
                    || binding.p256.local_instance_v1() != 0
                    || p256_instance_parts_v1(binding.main.segment.instance) != Some((signature, 0))
                    || binding.main.segment.constraint_count
                        != P256_SCALAR_BIT_BUS_REGISTERED_CONSTRAINT_COUNT_V1
            })
        || registrations
            .iter()
            .any(|binding| binding.main.trace_group != group)
        || group_layout.native_trace_log2 != P256_SCALAR_BIT_BUS_AGGREGATE_TRACE_LOG2_V1
        || group_layout.base_width
            != P256_SIGNATURE_COUNT_V1 * P256_SCALAR_BIT_BUS_STARK_BASE_WIDTH_V1
        || group_layout.aux_width
            != P256_SIGNATURE_COUNT_V1 * P256_SCALAR_BIT_BUS_STARK_AUX_WIDTH_V1
        || group_layout.column_chunks != P256_SIGNATURE_COUNT_V1
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    registrations
        .try_into()
        .map_err(|_: Vec<MainP256RegistrationBindingV1>| ZkX509StarkErrorV1::InternalInvariant)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn main_p256_scalar_registration_v1(
    registrations: &[MainP256RegistrationBindingV1; P256_SIGNATURE_COUNT_V1],
    registration: RegisteredSegmentLayoutV1,
) -> Result<MainP256RegistrationBindingV1, ZkX509StarkErrorV1> {
    let mut matches = registrations
        .iter()
        .copied()
        .filter(|candidate| candidate.main == registration);
    let matched = matches.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    if matches.next().is_some() {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok(matched)
}
#[cfg(test)]
fn main_p256_terminal_registration_v1(
    claims: &ZkX509P256PrivateProductsV1,
    signature: usize,
) -> Result<P256TerminalRegistrationV1, ZkX509StarkErrorV1> {
    let (buses, cross_sources, sink, role) =
        if let Some(claims) = claims.certificate_or_crl.get(signature) {
            (
                claims.buses,
                claims.cross_sources.as_slice(),
                claims.sink,
                P256EcdsaRoleV1::CertificateOrCrl,
            )
        } else if signature == P256_SIGNATURE_COUNT_V1 - 1 {
            (
                claims.wallet.buses,
                claims.wallet.cross_sources.as_slice(),
                claims.wallet.sink,
                P256EcdsaRoleV1::WalletOwnership,
            )
        } else {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        };
    let mut owned_cross_sources = Vec::new();
    owned_cross_sources
        .try_reserve_exact(cross_sources.len())
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    owned_cross_sources.extend_from_slice(cross_sources);
    let terminals = P256TerminalRegistrationV1 {
        buses,
        cross_sources: owned_cross_sources,
        sink,
    };
    terminals.validate(role)?;
    Ok(terminals)
}
#[cfg(test)]
fn main_p256_terminal_registrations_v1(
    claims: &ZkX509P256PrivateProductsV1,
) -> Result<[P256TerminalRegistrationV1; P256_SIGNATURE_COUNT_V1], ZkX509StarkErrorV1> {
    let mut registrations = Vec::new();
    registrations
        .try_reserve_exact(P256_SIGNATURE_COUNT_V1)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    for signature in 0..P256_SIGNATURE_COUNT_V1 {
        registrations.push(main_p256_terminal_registration_v1(claims, signature)?);
    }
    registrations
        .try_into()
        .map_err(|_: Vec<P256TerminalRegistrationV1>| ZkX509StarkErrorV1::InternalInvariant)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zeroed_main_trace_column_v1(
    rows: usize,
) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(rows)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    values.resize(rows, F::ZERO);
    Ok(ZeroizingMainTraceColumnV1(values))
}
/// Exact five-signature scalar-bit trace source for the canonical MAIN log-8 group.
///
/// This is a non-owning projection of the one central P-256 provider. The base
/// view is constructed before X5B1 and cannot expose auxiliary columns. After
/// the central provider consumes the opaque post-base token, callers drop that
/// view and construct a bound view over the resulting capability.
#[derive(Clone, Copy)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
enum MainP256ScalarTraceViewV1<'a> {
    Base(&'a P256MainBaseSourceV1),
    Bound(&'a P256MainBoundSourceV1),
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainP256ScalarTraceGroupSourceV1<'a> {
    registrations: [MainP256RegistrationBindingV1; P256_SIGNATURE_COUNT_V1],
    view: MainP256ScalarTraceViewV1<'a>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainP256ScalarTraceGroupSourceV1<'a> {
    fn for_base_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBaseSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let registrations = main_p256_scalar_registrations_v1(layout)?;
        let canonical = source.canonical_registrations_v1()?;
        validate_p256_main_registration_order_v1(&canonical)?;
        if registrations.iter().any(|registration| {
            !canonical
                .iter()
                .any(|candidate| *candidate == registration.p256)
        }) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(Self {
            registrations,
            view: MainP256ScalarTraceViewV1::Base(source),
        })
    }
    fn for_bound_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBoundSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let registrations = main_p256_scalar_registrations_v1(layout)?;
        let canonical = source.canonical_registrations_v1()?;
        validate_p256_main_registration_order_v1(&canonical)?;
        if registrations.iter().any(|registration| {
            !canonical
                .iter()
                .any(|candidate| *candidate == registration.p256)
        }) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(Self {
            registrations,
            view: MainP256ScalarTraceViewV1::Bound(source),
        })
    }
    fn p256_registration_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
    ) -> Result<P256MainRegistrationV1, ZkX509StarkErrorV1> {
        Ok(main_p256_scalar_registration_v1(&self.registrations, registration)?.p256)
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainP256ScalarTraceGroupSourceV1<'_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let p256 = self.p256_registration_v1(registration)?;
        if local_column >= registration.segment.base_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut output = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
        match self.view {
            MainP256ScalarTraceViewV1::Base(source) => {
                source.fill_base_column_v1(p256, local_column, &mut output.0)?;
            }
            MainP256ScalarTraceViewV1::Bound(source) => {
                source.fill_base_column_v1(p256, local_column, &mut output.0)?;
            }
        }
        if output.iter().any(|value| F::canonical(value.0).is_none()) {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(output)
    }
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let p256 = self.p256_registration_v1(registration)?;
        if local_column >= registration.segment.aux_width {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut output = zeroed_main_trace_column_v1(registration.segment.trace_size())?;
        let MainP256ScalarTraceViewV1::Bound(source) = self.view else {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        };
        source.fill_aux_column_v1(p256, local_column, &mut output.0)?;
        if output.iter().any(|value| F::canonical(value.0).is_none()) {
            return Err(ZkX509StarkErrorV1::P256Witness);
        }
        Ok(output)
    }
}
/// Fixed-polynomial and opened-row source for the five log-8 scalar buses on the prover side.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainP256ScalarProverConstraintSourceV1<'a> {
    registrations: [MainP256RegistrationBindingV1; P256_SIGNATURE_COUNT_V1],
    source: &'a P256MainBoundSourceV1,
    challenges: P256ScalarBitBusChallengesV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainP256ScalarProverConstraintSourceV1<'a> {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        source: &'a P256MainBoundSourceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let registrations = main_p256_scalar_registrations_v1(layout)?;
        let canonical = source.canonical_registrations_v1()?;
        validate_p256_main_registration_order_v1(&canonical)?;
        let challenges = source.post_base_v1()?.p256_scalar();
        challenges
            .validate_v1()
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;

        Ok(Self {
            registrations,
            source,
            challenges,
        })
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(
            RegisteredSegmentLayoutV1,
            usize,
            &[F],
        ) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        for matched in self.registrations.iter().copied() {
            let trace_root = goldilocks_primitive_root_v1(matched.main.segment.trace_log2)
                .map_err(map_transparent_error_v1)?;
            for local_column in 0..matched.main.segment.fixed_width {
                let mut column = zeroed_main_trace_column_v1(matched.main.segment.trace_size())?;
                self.source
                    .fill_fixed_column_v1(matched.p256, local_column, &mut column.0)?;
                goldilocks_ifft_v1(&mut column, trace_root).map_err(map_transparent_error_v1)?;
                consume(matched.main, local_column, &column)?;
            }
        }
        Ok(())
    }
    fn constraint_residues_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let _matched = main_p256_scalar_registration_v1(&self.registrations, registration)?;
        p256_scalar_opened_residues_v1(registration, opening, fixed, self.challenges)
    }
    #[cfg(test)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if F::canonical(x.0).is_none() || alphas.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues = self.constraint_residues_v1(registration, opening, fixed)?;
        accumulator_quotient_value_v1(registration.segment, x, &residues, alphas)
    }
}
#[cfg(test)]
/// Witness-free fixed sampler and opened-row evaluator for all five scalar
/// buses in the production MAIN verifier.
struct MainP256ScalarVerifierConstraintSourceV1<'a> {
    registrations: [MainP256RegistrationBindingV1; P256_SIGNATURE_COUNT_V1],
    common_lde_log2: u8,
    fixed: &'a P256MainVerifierFixedSourceV1,
    challenges: P256ScalarBitBusChallengesV1,
    fixed_openings:
        [BTreeMap<usize, [F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1]>; P256_SIGNATURE_COUNT_V1],
}
#[cfg(test)]
impl<'a> MainP256ScalarVerifierConstraintSourceV1<'a> {
    #[cfg(test)]
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        fixed: &'a P256MainVerifierFixedSourceV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let registrations = main_p256_scalar_registrations_v1(layout)?;
        if registrations
            .iter()
            .any(|registration| layout.common_lde_log2 < registration.main.segment.lde_log2)
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let challenges = post_base.p256_scalar();
        challenges
            .validate_v1()
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
        Ok(Self {
            registrations,
            common_lde_log2: layout.common_lde_log2,
            fixed,
            challenges,

            fixed_openings: core::array::from_fn(|_| BTreeMap::new()),
        })
    }
    #[cfg(test)]
    fn common_lde_size_v1(&self) -> Result<usize, ZkX509StarkErrorV1> {
        1_usize
            .checked_shl(u32::from(self.common_lde_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    #[cfg(test)]
    fn next_query_index_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let stride_log2 = self
            .common_lde_log2
            .checked_sub(registration.segment.trace_log2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let stride = 1_usize
            .checked_shl(u32::from(stride_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Ok(query_index
            .checked_add(stride)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            % self.common_lde_size_v1()?)
    }
    #[cfg(test)]
    fn ensure_fixed_openings_v1(
        &mut self,
        matched: MainP256RegistrationBindingV1,
        indices: [usize; 2],
    ) -> Result<(), ZkX509StarkErrorV1> {
        let signature = matched.p256.signature_v1();
        let cache = self
            .fixed_openings
            .get(signature)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let mut missing = indices
            .into_iter()
            .filter(|index| !cache.contains_key(index))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        if cache
            .len()
            .checked_add(missing.len())
            .filter(|count| *count <= VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
            .is_none()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let sampled = sampled_verifier_generated_fixed_openings_v1::<
            P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1,
        >(
            matched.main.segment,
            self.common_lde_log2,
            &missing,
            |row| {
                let fixed_row: [F; P256_SCALAR_BIT_BUS_STARK_FIXED_WIDTH_V1] = self
                    .fixed
                    .fixed_row_v1(matched.p256, row)?
                    .try_into()
                    .map_err(|_: Vec<F>| ZkX509StarkErrorV1::InternalInvariant)?;
                Ok(fixed_row)
            },
        )?;
        let cache = self
            .fixed_openings
            .get_mut(signature)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let mut converted = BTreeMap::new();
        for (index, row) in sampled {
            converted.insert(
                index,
                row.try_into()
                    .map_err(|_: Vec<F>| ZkX509StarkErrorV1::InternalInvariant)?,
            );
        }
        if converted.keys().any(|index| cache.contains_key(index)) {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        cache.extend(converted);
        Ok(())
    }
    #[cfg(test)]
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        let matched = main_p256_scalar_registration_v1(&self.registrations, registration)?;
        if query_index >= self.common_lde_size_v1()?
            || next_query_index >= self.common_lde_size_v1()?
            || next_query_index != self.next_query_index_v1(registration, query_index)?
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let root =
            goldilocks_primitive_root_v1(self.common_lde_log2).map_err(map_transparent_error_v1)?;
        let expected_x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        if x != expected_x {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        // Validate every caller-controlled coordinate and opening before the
        // bounded verifier-owned cache is allowed to change.
        self.ensure_fixed_openings_v1(matched, [query_index, next_query_index])?;
        let cache = self
            .fixed_openings
            .get(matched.p256.signature_v1())
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let fixed = cache
            .get(&query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let next_fixed = cache
            .get(&next_query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if fixed
            .iter()
            .chain(next_fixed)
            .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::InternalInvariant);
        }
        p256_scalar_opened_residues_v1(registration, opening, fixed, self.challenges)
    }
}
fn validate_main_io_registration_v1(
    registration: RegisteredSegmentLayoutV1,
) -> Result<(), ZkX509StarkErrorV1> {
    if registration.segment != SegmentLayoutV1::for_full_io()? {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    Ok(())
}
fn compile_main_io_public_statement_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(ZkX509IoStarkStatementV1, usize), ZkX509StarkErrorV1> {
    let plan = compile_zk_x509_main_io_declarations_v1(statement)
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let logical_active_rows = plan.logical_active_rows;
    let io_statement = ZkX509IoStarkStatementV1::new(plan.declarations)?;
    if io_active_rows_v1(io_statement.declarations())? != logical_active_rows {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    Ok((io_statement, logical_active_rows))
}
/// Compile the canonical log-18 MAIN I/O fixed schedule exclusively from the
/// verifier's typed public statement.
fn compile_main_io_fixed_schedule_v1(
    layout: SegmentLayoutV1,
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<(ZkX509IoStarkStatementV1, MainIoFixedScheduleV1), ZkX509StarkErrorV1> {
    if layout != SegmentLayoutV1::for_full_io()? {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let (io_statement, logical_active_rows) = compile_main_io_public_statement_v1(statement)?;
    let fixed_schedule =
        MainIoFixedScheduleV1::compile_v1(layout, &io_statement, logical_active_rows)?;
    Ok((io_statement, fixed_schedule))
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn compile_main_io_statement_from_source_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    source: &ZkX509MainIoBaseMaterialV1,
    layout: SegmentLayoutV1,
) -> Result<(ZkX509IoStarkStatementV1, MainIoFixedScheduleV1), ZkX509StarkErrorV1> {
    let (io_statement, fixed_schedule) = compile_main_io_fixed_schedule_v1(layout, statement)?;
    if source.declarations.as_slice() != io_statement.declarations()
        || source.logical_active_rows != fixed_schedule.logical_active_rows
        || source.execution.len() != fixed_schedule.logical_active_rows
        || source.sorted.len() != fixed_schedule.logical_active_rows
        || source.witnesses.len() != io_statement.declarations.len()
        || source
            .witnesses
            .iter()
            .zip(io_statement.declarations())
            .any(|(witness, declaration)| witness.declaration != *declaration)
    {
        return Err(ZkX509StarkErrorV1::WitnessStatementMismatch);
    }
    let (declarations, execution, sorted) = build_zk_x509_io_base_tables_v1(&source.witnesses)?;
    if declarations != source.declarations
        || execution.as_slice() != source.execution.as_slice()
        || sorted.as_slice() != source.sorted.as_slice()
    {
        return Err(ZkX509StarkErrorV1::IoWitness);
    }
    fixed_schedule.validate_witness_topology_v1(&execution, &sorted)?;
    Ok((io_statement, fixed_schedule))
}
/// Phased byte-memory source for the canonical MAIN log-18 group.
///
/// Construction validates and materializes only challenge-independent columns.
/// Auxiliary columns remain unavailable until the opaque joint post-base token
/// is bound. No API accepts raw I/O challenges.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainIoTraceGroupSourceV1<'a> {
    registration: RegisteredSegmentLayoutV1,
    statement: ZkX509IoStarkStatementV1,
    source: &'a ZkX509MainIoBaseMaterialV1,
    base_columns: Vec<Vec<F>>,
    fixed_columns: Vec<Vec<F>>,
    aux_columns: Option<Vec<Vec<F>>>,
    post_base: Option<ZkX509CredentialMainPostBaseChallengesV1>,
    bind_attempted: bool,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainIoTraceGroupSourceV1<'a> {
    /// Capacity of retained native columns and cloned declaration topology.
    fn allocated_payload_bytes_v1(&self) -> usize {
        use super::allocation_payload::{declaration_v1, sum_v1, vector_v1};
        let columns = |values: &Vec<Vec<F>>| {
            sum_v1([vector_v1(values), sum_v1(values.iter().map(vector_v1))])
        };
        sum_v1([
            core::mem::size_of_val(self),
            vector_v1(&self.statement.declarations),
            sum_v1(self.statement.declarations.iter().map(declaration_v1)),
            columns(&self.base_columns),
            columns(&self.fixed_columns),
            self.aux_columns.as_ref().map_or(0, columns),
        ])
    }
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        source: &'a ZkX509MainIoBaseMaterialV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::ByteMemory, 0)?;
        validate_main_io_registration_v1(registration)?;
        let (io_statement, fixed_schedule) =
            compile_main_io_statement_from_source_v1(statement, source, registration.segment)?;
        let (base_columns, fixed_columns, execution, sorted) =
            build_io_base_and_fixed_columns_from_schedule_v1(
                &io_statement,
                &source.witnesses,
                &fixed_schedule,
            )?;
        if execution.as_slice() != source.execution.as_slice()
            || sorted.as_slice() != source.sorted.as_slice()
        {
            return Err(ZkX509StarkErrorV1::IoWitness);
        }
        validate_io_base_phase_shape_v1(
            registration.segment,
            source.logical_active_rows,
            &base_columns,
            &fixed_columns,
        )?;
        Ok(Self {
            registration,
            statement: io_statement,
            source,
            base_columns: base_columns.into_vec(),
            fixed_columns,
            aux_columns: None,
            post_base: None,
            bind_attempted: false,
        })
    }
    fn bind_challenges_v1(
        &mut self,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if self.bind_attempted || self.aux_columns.is_some() || self.post_base.is_some() {
            return Err(ZkX509StarkErrorV1::TranscriptMismatch);
        }
        // Consume the sole phase transition before any fallible work. A failed
        // attempt cannot be retried with another token.
        self.bind_attempted = true;
        self.validate_base_phase_v1()?;
        let challenges = post_base.io();
        let aux_columns = build_io_aux_columns_v1(
            &self.statement,
            &self.source.witnesses,
            challenges,
            self.registration.segment,
            self.source.logical_active_rows,
            &self.source.execution,
            &self.source.sorted,
        )?;
        validate_io_bound_constraints_v1(
            self.registration.segment,
            self.source.logical_active_rows,
            &self.base_columns,
            &aux_columns,
            &self.fixed_columns,
            challenges,
        )?;
        self.aux_columns = Some(aux_columns.into_vec());
        self.post_base = Some(post_base);
        Ok(())
    }
    fn validate_base_phase_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        validate_io_base_phase_shape_v1(
            self.registration.segment,
            self.source.logical_active_rows,
            &self.base_columns,
            &self.fixed_columns,
        )
    }
    fn validate_bound_phase_v1(&self) -> Result<(), ZkX509StarkErrorV1> {
        let aux_columns = self
            .aux_columns
            .as_ref()
            .ok_or(ZkX509StarkErrorV1::TranscriptMismatch)?;
        let post_base = self
            .post_base
            .ok_or(ZkX509StarkErrorV1::TranscriptMismatch)?;
        validate_io_bound_constraints_v1(
            self.registration.segment,
            self.source.logical_active_rows,
            &self.base_columns,
            aux_columns,
            &self.fixed_columns,
            post_base.io(),
        )
    }
    fn zeroize_private_buffers_v1(&mut self) {
        for column in &mut self.base_columns {
            super::private_table::zeroize_fields_v1(column);
            column.clear();
        }
        self.base_columns.clear();
        if let Some(aux_columns) = &mut self.aux_columns {
            for column in aux_columns.iter_mut() {
                super::private_table::zeroize_fields_v1(column);
                column.clear();
            }
            aux_columns.clear();
        }
        self.aux_columns = None;
        for column in &mut self.fixed_columns {
            column.clear();
        }
        self.fixed_columns.clear();
        self.post_base = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for MainIoTraceGroupSourceV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_buffers_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainIoTraceGroupSourceV1<'_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if registration != self.registration {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        copied_matrix_column_v1(
            &self.base_columns,
            IO_BASE_WIDTH,
            self.registration.segment.trace_size(),
            local_column,
        )
    }
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if registration != self.registration {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let aux_columns = self
            .aux_columns
            .as_ref()
            .ok_or(ZkX509StarkErrorV1::TranscriptMismatch)?;
        copied_matrix_column_v1(
            aux_columns,
            IO_AUX_WIDTH,
            self.registration.segment.trace_size(),
            local_column,
        )
    }
}
/// MAIN I/O fixed-polynomial and composition source for the log-18 prover.
///
/// It uses the same statement-only fixed compiler as the verifier and independently revalidates the
/// prover's witness topology against that schedule. `MainIoTraceGroupSourceV1` performs the same
/// check before any base column can enter the MAIN commitment session.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainIoProverConstraintSourceV1 {
    registration: RegisteredSegmentLayoutV1,
    challenges: ZkX509IoChallengesV1,
    fixed_schedule: MainIoFixedScheduleV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainIoProverConstraintSourceV1 {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        source: &ZkX509MainIoBaseMaterialV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::ByteMemory, 0)?;
        validate_main_io_registration_v1(registration)?;
        let (_, fixed_schedule) =
            compile_main_io_statement_from_source_v1(statement, source, registration.segment)?;
        let challenges = post_base.io();
        challenges
            .validate()
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
        Ok(Self {
            registration,
            challenges,
            fixed_schedule,
        })
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(usize, &[F]) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        let trace_root = goldilocks_primitive_root_v1(self.registration.segment.trace_log2)
            .map_err(map_transparent_error_v1)?;
        for local_column in 0..IO_FIXED_WIDTH {
            let mut column = Vec::new();
            column
                .try_reserve_exact(self.registration.segment.trace_size())
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            for row in 0..self.registration.segment.trace_size() {
                column.push(self.fixed_schedule.fixed_row_v1(row)?[local_column]);
            }
            let mut coefficients = ZeroizingMainTraceColumnV1(column);
            goldilocks_ifft_v1(&mut coefficients, trace_root).map_err(map_transparent_error_v1)?;
            consume(local_column, &coefficients)?;
        }
        Ok(())
    }
    fn constraint_residues_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F; IO_FIXED_WIDTH],
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        if registration != self.registration
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .chain(fixed)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        io_constraint_residues_v1(
            registration.segment,
            self.fixed_schedule.logical_active_rows,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            self.challenges,
        )
    }
    #[cfg(test)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F; IO_FIXED_WIDTH],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if F::canonical(x.0).is_none() || alphas.len() != registration.segment.constraint_count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let residues = self.constraint_residues_v1(registration, opening, fixed)?;
        accumulator_quotient_value_v1(registration.segment, x, &residues, alphas)
    }
}
/// Verifier-generated MAIN I/O fixed openings and opened-row evaluator.
///
/// Fixed rows come only from the typed public statement. The cache is bounded to the two
/// coordinates needed for each canonical query, and all caller-controlled coordinates and opened
/// values are checked before that cache can change.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "opened-row fields serve only the test and release-evidence prover checks"
    )
)]
struct MainIoVerifierConstraintSourceV1 {
    registration: RegisteredSegmentLayoutV1,
    common_lde_log2: u8,
    challenges: ZkX509IoChallengesV1,
    fixed_schedule: MainIoFixedScheduleV1,
    fixed_openings: BTreeMap<usize, [F; IO_FIXED_WIDTH]>,
}
impl MainIoVerifierConstraintSourceV1 {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::ByteMemory, 0)?;
        validate_main_io_registration_v1(registration)?;
        if layout.common_lde_log2 < registration.segment.lde_log2 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let (_, fixed_schedule) =
            compile_main_io_fixed_schedule_v1(registration.segment, statement)?;
        let challenges = post_base.io();
        challenges
            .validate()
            .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
        Ok(Self {
            registration,
            common_lde_log2: layout.common_lde_log2,
            challenges,
            fixed_schedule,
            fixed_openings: BTreeMap::new(),
        })
    }
    #[cfg(test)]
    fn common_lde_size_v1(&self) -> Result<usize, ZkX509StarkErrorV1> {
        1_usize
            .checked_shl(u32::from(self.common_lde_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    #[cfg(test)]
    fn next_query_index_v1(&self, query_index: usize) -> Result<usize, ZkX509StarkErrorV1> {
        let stride_log2 = self
            .common_lde_log2
            .checked_sub(self.registration.segment.trace_log2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let stride = 1_usize
            .checked_shl(u32::from(stride_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Ok(query_index
            .checked_add(stride)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?
            % self.common_lde_size_v1()?)
    }
    #[cfg(test)]
    fn ensure_fixed_openings_v1(&mut self, indices: [usize; 2]) -> Result<(), ZkX509StarkErrorV1> {
        let mut missing = indices
            .into_iter()
            .filter(|index| !self.fixed_openings.contains_key(index))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        if self
            .fixed_openings
            .len()
            .checked_add(missing.len())
            .filter(|count| *count <= VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
            .is_none()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let sampled = sampled_verifier_generated_fixed_openings_v1(
            self.registration.segment,
            self.common_lde_log2,
            &missing,
            |row| self.fixed_schedule.fixed_row_v1(row),
        )?;
        for (index, row) in sampled {
            let row: [F; IO_FIXED_WIDTH] = row
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
            if self.fixed_openings.insert(index, row).is_some() {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        if registration != self.registration
            || query_index >= self.common_lde_size_v1()?
            || next_query_index >= self.common_lde_size_v1()?
            || next_query_index != self.next_query_index_v1(query_index)?
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || F::canonical(x.0).is_none()
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let root =
            goldilocks_primitive_root_v1(self.common_lde_log2).map_err(map_transparent_error_v1)?;
        let expected_x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        if x != expected_x {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        self.ensure_fixed_openings_v1([query_index, next_query_index])?;
        let current = self
            .fixed_openings
            .get(&query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let next = self
            .fixed_openings
            .get(&next_query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if current
            .iter()
            .chain(next)
            .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        io_constraint_residues_v1(
            registration.segment,
            self.fixed_schedule.logical_active_rows,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            current,
            self.challenges,
        )
    }
}
/// Challenge-independent and challenge-bound native projection columns for
/// the canonical MAIN log-15 group.
///
/// Base columns are available immediately. Auxiliary columns remain
/// inaccessible until the transcript-derived challenges are bound.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainProjectionTraceGroupSourceV1<'a> {
    registration: RegisteredSegmentLayoutV1,
    trace: &'a ZkX509ProjectionTraceV1,
    aux: Option<ZkX509ProjectionAuxTraceV1>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl<'a> MainProjectionTraceGroupSourceV1<'a> {
    /// Capacity of the owned auxiliary trace; base/fixed rows belong to the assembly.
    fn allocated_payload_bytes_v1(&self) -> usize {
        super::allocation_payload::sum_v1([
            core::mem::size_of_val(self),
            self.aux
                .as_ref()
                .map_or(0, |aux| super::allocation_payload::vector_v1(&aux.rows)),
        ])
    }
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        trace: &'a ZkX509ProjectionTraceV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::Projection, 0)?;
        validate_main_projection_registration_v1(registration)?;
        let fixed = compile_zk_x509_projection_fixed_trace_v1(statement)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        if trace.base.rows.len() != registration.segment.trace_size()
            || trace.fixed != fixed
            || trace
                .base
                .rows
                .iter()
                .flatten()
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProjectionWitness);
        }
        Ok(Self {
            registration,
            trace,
            aux: None,
        })
    }
    fn bind_challenges_v1(
        &mut self,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if self.aux.is_some() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let aux = build_zk_x509_projection_aux_trace_v1(
            &self.trace.base,
            &self.trace.fixed,
            post_base.projection(),
        )?;
        if aux.rows.len() != self.registration.segment.trace_size() {
            return Err(ZkX509StarkErrorV1::ProjectionWitness);
        }
        self.aux = Some(aux);
        Ok(())
    }
    fn zeroize_private_buffers_v1(&mut self) {
        if let Some(aux) = &mut self.aux {
            for row in &mut aux.rows {
                row.fill(F::ZERO);
            }
            aux.rows.clear();
        }
        self.aux = None;
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl Drop for MainProjectionTraceGroupSourceV1<'_> {
    fn drop(&mut self) {
        self.zeroize_private_buffers_v1();
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainTraceGroupSourceV1 for MainProjectionTraceGroupSourceV1<'_> {
    fn native_base_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if registration != self.registration {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        copied_array_column_v1(&self.trace.base.rows, local_column)
    }
    fn native_aux_column_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        local_column: usize,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if registration != self.registration {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let aux = self
            .aux
            .as_ref()
            .ok_or(ZkX509StarkErrorV1::TranscriptMismatch)?;
        copied_array_column_v1(&aux.rows, local_column)
    }
}
/// Projection fixed-polynomial and composition source for the MAIN prover.
///
/// Fixed columns are interpolated one at a time and handed to the caller through a scoped zeroizing
/// buffer. This is deliberately separate from the bounded sampled-opening verifier below: a full
/// prover traversal cannot consume, or exhaust, the verifier's 272-opening cache.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct MainProjectionProverConstraintSourceV1 {
    registration: RegisteredSegmentLayoutV1,
    challenges: ZkX509ProjectionChallengesV1,
    fixed_rows: Vec<[F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1]>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainProjectionProverConstraintSourceV1 {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::Projection, 0)?;
        validate_main_projection_registration_v1(registration)?;
        let fixed_rows = compile_zk_x509_projection_stark_fixed_rows_v1(statement)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        if fixed_rows.len() != registration.segment.trace_size() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(Self {
            registration,
            challenges: post_base.projection(),
            fixed_rows,
        })
    }
    fn stream_fixed_polynomials_v1(
        &self,
        mut consume: impl FnMut(usize, &[F]) -> Result<(), ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        let trace_root = goldilocks_primitive_root_v1(self.registration.segment.trace_log2)
            .map_err(map_transparent_error_v1)?;
        for local_column in 0..ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1 {
            let mut coefficients = copied_array_column_v1(&self.fixed_rows, local_column)?;
            goldilocks_ifft_v1(&mut coefficients, trace_root).map_err(map_transparent_error_v1)?;
            consume(local_column, &coefficients)?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn composition_value_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &[F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1],
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if registration != self.registration
            || alphas.len() != registration.segment.constraint_count
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        projection_quotient_value_v1(
            registration.segment,
            x,
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            fixed,
            self.challenges,
            alphas,
        )
    }
}
/// Test-only verifier-minted projection fixed opening.
///
/// The registration and both query coordinates travel with the sampled rows. Constraint evaluation
/// revalidates all four fields against the source cache, allowing tests to prove that
/// caller-provided rows cannot be substituted for verifier reconstruction. Production evaluation
/// never manufactures or exports this capability.
#[cfg(test)]
#[derive(Debug)]
struct MainProjectionVerifierFixedOpeningV1 {
    registration: RegisteredSegmentLayoutV1,
    query_index: usize,
    next_query_index: usize,
    current: [F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1],
    next: [F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1],
}
/// Verifier-generated projection fixed rows and opened constraint evaluator.
///
/// The fixed trace is compiled exclusively from the public statement and sampled directly on MAIN's
/// common coset. It never reads prover-native projection material. This source is verifier-only and
/// bounded to the exact number of fixed openings required by the canonical query schedule.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "opened-row fields serve only the test and release-evidence prover checks"
    )
)]
struct MainProjectionVerifierConstraintSourceV1 {
    registration: RegisteredSegmentLayoutV1,
    common_lde_log2: u8,
    challenges: ZkX509ProjectionChallengesV1,
    fixed_rows: Vec<[F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1]>,
    fixed_openings: BTreeMap<usize, [F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1]>,
}
impl MainProjectionVerifierConstraintSourceV1 {
    fn for_main_v1(
        layout: &AggregateProofLayoutV1,
        statement: &IrohaZkX509StarkP256StatementV1,
        post_base: ZkX509CredentialMainPostBaseChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let registration = layout.registered_segment(SegmentAdapterIdV1::Projection, 0)?;
        validate_main_projection_registration_v1(registration)?;
        let fixed_rows = compile_zk_x509_projection_stark_fixed_rows_v1(statement)
            .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
        if fixed_rows.len() != registration.segment.trace_size()
            || layout.common_lde_log2 < registration.segment.lde_log2
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(Self {
            registration,
            common_lde_log2: layout.common_lde_log2,
            challenges: post_base.projection(),
            fixed_rows,
            fixed_openings: BTreeMap::new(),
        })
    }
    #[cfg(test)]
    fn common_lde_size_v1(&self) -> Result<usize, ZkX509StarkErrorV1> {
        1_usize
            .checked_shl(u32::from(self.common_lde_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)
    }
    #[cfg(test)]
    fn next_query_index_v1(&self, query_index: usize) -> Result<usize, ZkX509StarkErrorV1> {
        let stride_log2 = self
            .common_lde_log2
            .checked_sub(self.registration.segment.trace_log2)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let stride = 1_usize
            .checked_shl(u32::from(stride_log2))
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let next = query_index
            .checked_add(stride)
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        Ok(next % self.common_lde_size_v1()?)
    }
    #[cfg(test)]
    fn ensure_fixed_openings_v1(&mut self, indices: [usize; 2]) -> Result<(), ZkX509StarkErrorV1> {
        let mut missing = indices
            .into_iter()
            .filter(|index| !self.fixed_openings.contains_key(index))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        if self
            .fixed_openings
            .len()
            .checked_add(missing.len())
            .filter(|count| *count <= VERIFIER_GENERATED_FIXED_MAX_SAMPLED_OPENINGS_V1)
            .is_none()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let sampled = sampled_verifier_generated_fixed_openings_v1(
            self.registration.segment,
            self.common_lde_log2,
            &missing,
            |row| {
                self.fixed_rows
                    .get(row)
                    .copied()
                    .ok_or(ZkX509StarkErrorV1::InternalInvariant)
            },
        )?;
        for (index, row) in sampled {
            let row: [F; ZK_X509_PROJECTION_STARK_FIXED_WIDTH_V1] = row
                .try_into()
                .map_err(|_| ZkX509StarkErrorV1::InternalInvariant)?;
            if self.fixed_openings.insert(index, row).is_some() {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn verifier_fixed_opening_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
    ) -> Result<MainProjectionVerifierFixedOpeningV1, ZkX509StarkErrorV1> {
        if registration != self.registration
            || query_index >= self.common_lde_size_v1()?
            || next_query_index >= self.common_lde_size_v1()?
            || next_query_index != self.next_query_index_v1(query_index)?
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        self.ensure_fixed_openings_v1([query_index, next_query_index])?;
        Ok(MainProjectionVerifierFixedOpeningV1 {
            registration,
            query_index,
            next_query_index,
            current: self
                .fixed_openings
                .get(&query_index)
                .copied()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?,
            next: self
                .fixed_openings
                .get(&next_query_index)
                .copied()
                .ok_or(ZkX509StarkErrorV1::InternalInvariant)?,
        })
    }
    #[cfg(test)]
    fn constraint_residues_from_fixed_opening_v1(
        &self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
        fixed: &MainProjectionVerifierFixedOpeningV1,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        if registration != self.registration
            || query_index >= self.common_lde_size_v1()?
            || next_query_index != self.next_query_index_v1(query_index)?
            || fixed.registration != registration
            || fixed.query_index != query_index
            || fixed.next_query_index != next_query_index
            || self.fixed_openings.get(&query_index) != Some(&fixed.current)
            || self.fixed_openings.get(&next_query_index) != Some(&fixed.next)
            || fixed
                .current
                .iter()
                .chain(&fixed.next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let root =
            goldilocks_primitive_root_v1(self.common_lde_log2).map_err(map_transparent_error_v1)?;
        let expected_x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        if x != expected_x {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        projection_constraint_residues_v1(
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            &fixed.current,
            self.challenges,
        )
    }
    #[cfg(test)]
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        if registration != self.registration
            || query_index >= self.common_lde_size_v1()?
            || next_query_index >= self.common_lde_size_v1()?
            || next_query_index != self.next_query_index_v1(query_index)?
            || opening.base_current.len() != registration.segment.base_width
            || opening.base_next.len() != registration.segment.base_width
            || opening.aux_current.len() != registration.segment.aux_width
            || opening.aux_next.len() != registration.segment.aux_width
            || opening
                .base_current
                .iter()
                .chain(opening.base_next)
                .chain(opening.aux_current)
                .chain(opening.aux_next)
                .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let root =
            goldilocks_primitive_root_v1(self.common_lde_log2).map_err(map_transparent_error_v1)?;
        let expected_x = F(GOLDILOCKS_GENERATOR_V1).mul(root.pow(query_index as u128));
        if x != expected_x {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        // Only the concrete verifier source can populate or read this cache.
        // All caller-controlled coordinates have already been validated, so a
        // rejected query cannot consume one of the bounded sampled openings.
        self.ensure_fixed_openings_v1([query_index, next_query_index])?;
        let current = self
            .fixed_openings
            .get(&query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        let next = self
            .fixed_openings
            .get(&next_query_index)
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if current
            .iter()
            .chain(next)
            .any(|value| F::canonical(value.0).is_none())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        projection_constraint_residues_v1(
            opening.base_current,
            opening.base_next,
            opening.aux_current,
            opening.aux_next,
            current,
            self.challenges,
        )
    }
}
/// Closed association between one implementation and one canonical MAIN
/// native-log group. No proof or caller-provided integer selects a group.
#[cfg(test)]
enum MainTraceGroupProviderV1<'a> {
    Log5(&'a mut MainP256Log5TraceGroupSourceV1<'a>),
    P256Scalar(&'a mut MainP256ScalarTraceGroupSourceV1<'a>),
    Log15(&'a mut dyn MainTraceGroupSourceV1),
    Log16(&'a mut MainP256Log16TraceGroupSourceV1<'a>),
    Log18(&'a mut dyn MainTraceGroupSourceV1),
    Log19(&'a mut dyn MainTraceGroupSourceV1),
    #[cfg(test)]
    TestLog5(&'a mut dyn MainTraceGroupSourceV1),
    #[cfg(test)]
    TestLog8(&'a mut dyn MainTraceGroupSourceV1),
    #[cfg(test)]
    TestLog16(&'a mut dyn MainTraceGroupSourceV1),
}
#[cfg(test)]
impl MainTraceGroupProviderV1<'_> {
    fn native_trace_log2_v1(&self) -> u8 {
        match self {
            Self::Log5(_) => 5,
            Self::P256Scalar(_) => 8,
            Self::Log15(_) => 15,
            Self::Log16(_) => 16,
            Self::Log18(_) => 18,
            Self::Log19(_) => 19,
            #[cfg(test)]
            Self::TestLog5(_) => 5,
            #[cfg(test)]
            Self::TestLog8(_) => 8,
            #[cfg(test)]
            Self::TestLog16(_) => 16,
        }
    }
    fn source_mut_v1(&mut self) -> &mut dyn MainTraceGroupSourceV1 {
        match self {
            Self::Log5(source) => *source,
            Self::P256Scalar(source) => *source,
            Self::Log16(source) => *source,
            Self::Log15(source) | Self::Log18(source) | Self::Log19(source) => *source,
            #[cfg(test)]
            Self::TestLog5(source) => *source,
            #[cfg(test)]
            Self::TestLog8(source) => *source,
            #[cfg(test)]
            Self::TestLog16(source) => *source,
        }
    }
}
#[cfg(test)]
/// Closed association between one verifier-safe opened-row implementation and
/// one canonical MAIN native-log group.
///
/// Production variants always name a concrete verifier implementation. The dynamic variants only
/// exist in unit tests so malformed-provider behavior remains testable without creating a
/// production extension point capable of fabricating fixed openings.
enum MainOpenedGroupProviderV1<'a> {
    Log5(&'a mut MainP256Log5VerifierConstraintSourceV1<'a>),
    Log16(&'a mut MainP256Log16VerifierConstraintSourceV1<'a>),
    Io(&'a mut MainIoVerifierConstraintSourceV1),
    Projection(&'a mut MainProjectionVerifierConstraintSourceV1),
    P256Scalar(&'a mut MainP256ScalarVerifierConstraintSourceV1<'a>),
    #[cfg(test)]
    TestLog5(&'a mut dyn MainOpenedConstraintTestSourceV1),
    #[cfg(test)]
    TestLog8(&'a mut dyn MainOpenedConstraintTestSourceV1),
    #[cfg(test)]
    TestLog15(&'a mut dyn MainOpenedConstraintTestSourceV1),
    #[cfg(test)]
    TestLog16(&'a mut dyn MainOpenedConstraintTestSourceV1),
    #[cfg(test)]
    TestLog18(&'a mut dyn MainOpenedConstraintTestSourceV1),
    #[cfg(test)]
    TestLog19(&'a mut dyn MainOpenedConstraintTestSourceV1),
}
#[cfg(test)]
impl MainOpenedGroupProviderV1<'_> {
    #[cfg(test)]
    fn native_trace_log2_v1(&self) -> u8 {
        match self {
            Self::Log5(_) => 5,
            Self::Log16(_) => 16,
            Self::Io(_) => 18,
            Self::Projection(_) => 15,
            Self::P256Scalar(_) => 8,
            #[cfg(test)]
            Self::TestLog5(_) => 5,
            #[cfg(test)]
            Self::TestLog8(_) => 8,
            #[cfg(test)]
            Self::TestLog15(_) => 15,
            #[cfg(test)]
            Self::TestLog16(_) => 16,
            #[cfg(test)]
            Self::TestLog18(_) => 18,
            #[cfg(test)]
            Self::TestLog19(_) => 19,
        }
    }
    #[cfg(test)]
    fn constraint_residues_v1(
        &mut self,
        registration: RegisteredSegmentLayoutV1,
        query_index: usize,
        next_query_index: usize,
        x: F,
        opening: RegisteredOpenedRowsV1<'_>,
    ) -> Result<Vec<F>, ZkX509StarkErrorV1> {
        match self {
            Self::Log5(source) => source.constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                opening,
            ),
            Self::Log16(source) => source.constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                opening,
            ),
            Self::Io(source) => source.constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                opening,
            ),
            Self::Projection(source) => source.constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                opening,
            ),
            Self::P256Scalar(source) => source.constraint_residues_v1(
                registration,
                query_index,
                next_query_index,
                x,
                opening,
            ),
            #[cfg(test)]
            Self::TestLog5(source)
            | Self::TestLog8(source)
            | Self::TestLog15(source)
            | Self::TestLog16(source)
            | Self::TestLog18(source)
            | Self::TestLog19(source) => {
                let fixed =
                    source.fixed_opened_rows_v1(registration, query_index, next_query_index)?;
                if fixed.current.len() != registration.segment.fixed_width
                    || fixed.next.len() != registration.segment.fixed_width
                    || fixed
                        .current
                        .iter()
                        .chain(&fixed.next)
                        .any(|value| F::canonical(value.0).is_none())
                {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                source.constraint_residues_v1(registration, query_index, x, opening, &fixed)
            }
        }
    }
}
/// Verify the exact canonical byte-memory segmented proof.
#[cfg(test)]
pub fn verify_zk_x509_io_segmented_stark_v1(
    statement: &ZkX509IoStarkStatementV1,
    proof_bytes: &[u8],
) -> Result<(), ZkX509StarkErrorV1> {
    validate_declarations_v1(&statement.declarations)
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let active_rows = io_active_rows_v1(&statement.declarations)?;
    if active_rows > byte_memory_capacity_v1().map_err(|_| ZkX509StarkErrorV1::InvalidStatement)? {
        return Err(ZkX509StarkErrorV1::InvalidStatement);
    }
    let layout = SegmentLayoutV1::for_io(active_rows)?;
    layout.validate()?;
    let layouts = [layout];
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&layouts)?;
    let proof = decode_zk_x509_segmented_stark_proof_v1(proof_bytes, &aggregate_layout)?;
    if proof.trace_groups.is_empty() {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let public_digest = io_public_digest_v1(statement)?;
    let mut transcript = new_transcript_v1(&public_digest)?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        &mut transcript,
        b"iroha:privacy:zk-x509:io-aggregate-layout:v1",
        &aggregate_layout,
    )?;
    aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &proof.trace_groups)
        .map_err(map_aggregate_error_v1)?;
    let io_challenges =
        derive_zk_x509_io_challenges_v1(&mut transcript).map_err(map_transparent_error_v1)?;
    aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &proof.trace_groups)
        .map_err(map_aggregate_error_v1)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, &aggregate_layout)?;
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &proof.composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &proof.fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let shared_layout = aggregate_layout.as_shared()?;
    let deep_point =
        aggregate::derive_deep_point_v1(&mut transcript, AGGREGATE_PARAMETERS_V1, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &proof.deep,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let mixes = derive_fri_mixes_v1(&mut transcript, &aggregate_layout)?;
    let deep_mixes = aggregate_deep_lane_mixes_v1(&mixes, &aggregate_layout)?;
    let (fri_betas, terminal_fields) = aggregate::verify_fri_commitments_v1(
        &proof,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        &mut transcript,
    )
    .map_err(map_aggregate_error_v1)?;
    let grinding_state = transcript.state();
    verify_grinding_nonce_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        &grinding_state,
        ZK_X509_GRINDING_BITS_V1,
        proof.grinding_nonce,
    )
    .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    absorb_grinding_nonce_v1(&mut transcript, proof.grinding_nonce)?;
    let expected_indices =
        query_indices_v1(TEST_PROOF_INSTANCE_V1, &transcript, &aggregate_layout)?;
    aggregate::verify_all_merkle_openings_v1(
        &proof,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        &expected_indices,
    )
    .map_err(map_aggregate_error_v1)?;
    let fixed_schedule = MainIoFixedScheduleV1::compile_v1(layout, statement, active_rows)?;
    let fixed_columns = fixed_schedule.fixed_columns_v1()?;
    let fixed_lde = fixed_lde_columns_v1(&fixed_columns, layout)?;
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    let mut evaluator = IoOpenedRowEvaluatorV1 {
        aggregate_layout: &aggregate_layout,
        layout,
        logical_active_rows: active_rows,
        fixed_lde: &fixed_lde,
        io_challenges,
        alphas: &alphas[0],
        mixes: &mixes[0],
        lde_root,
    };
    aggregate::verify_opened_query_relations_with_deep_v1(
        &proof.aggregate,
        &proof.deep,
        deep_point,
        &deep_mixes,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
        &expected_indices,
        &fri_betas,
        &terminal_fields,
        &mut evaluator,
    )
    .map_err(map_aggregate_error_v1)
}
/// Verify the exact canonical registered strict-DER proof.
#[cfg(test)]
pub fn verify_zk_x509_der_segmented_stark_v1(
    shape: &ZkX509DerStarkShapeV1,
    proof_bytes: &[u8],
) -> Result<(), ZkX509StarkErrorV1> {
    shape
        .validate()
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let schedule = compile_zk_x509_der_stark_fixed_schedule_v1(shape.clone())
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    let layout = SegmentLayoutV1::for_der(schedule.active_rows())?;
    layout.validate()?;
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&[layout])?;
    let (claims, aggregate_proof_bytes) = decode_der_segmented_proof_envelope_v1(proof_bytes)?;
    let proof = decode_zk_x509_segmented_stark_proof_v1(aggregate_proof_bytes, &aggregate_layout)?;
    if proof.trace_groups.len() != 1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let public_digest = der_public_digest_v1(shape)?;
    let mut transcript = new_transcript_v1(&public_digest)?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        &mut transcript,
        b"iroha:privacy:zk-x509:der-aggregate-layout:v1",
        &aggregate_layout,
    )?;
    aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &proof.trace_groups)
        .map_err(map_aggregate_error_v1)?;
    let challenges = derive_der_challenges_v1(&mut transcript)?;
    let public = derive_zk_x509_der_stark_public_terminals_v1(shape, challenges)
        .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &proof.trace_groups)
        .map_err(map_aggregate_error_v1)?;
    absorb_der_terminal_claims_v1(&mut transcript, claims)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, &aggregate_layout)?;
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &proof.composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &proof.fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let shared_layout = aggregate_layout.as_shared()?;
    let deep_point =
        aggregate::derive_deep_point_v1(&mut transcript, AGGREGATE_PARAMETERS_V1, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &proof.deep,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let mixes = derive_fri_mixes_v1(&mut transcript, &aggregate_layout)?;
    let deep_mixes = aggregate_deep_lane_mixes_v1(&mixes, &aggregate_layout)?;
    let (fri_betas, terminal_fields) = aggregate::verify_fri_commitments_v1(
        &proof,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        &mut transcript,
    )
    .map_err(map_aggregate_error_v1)?;
    let grinding_state = transcript.state();
    verify_grinding_nonce_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        &grinding_state,
        ZK_X509_GRINDING_BITS_V1,
        proof.grinding_nonce,
    )
    .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    absorb_grinding_nonce_v1(&mut transcript, proof.grinding_nonce)?;
    let expected_indices =
        query_indices_v1(TEST_PROOF_INSTANCE_V1, &transcript, &aggregate_layout)?;
    aggregate::verify_all_merkle_openings_v1(
        &proof,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        &expected_indices,
    )
    .map_err(map_aggregate_error_v1)?;
    main_aggregate::verify_standalone_der_oods_v1(
        &aggregate_layout,
        &proof.deep,
        deep_point,
        challenges,
        public,
        claims,
        &alphas[0],
    )?;
    aggregate::verify_opened_query_relations_after_complete_oods_v1(
        &proof.aggregate,
        &proof.deep,
        deep_point,
        &deep_mixes,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
        &expected_indices,
        &fri_betas,
        &terminal_fields,
        &[],
    )
    .map_err(map_aggregate_error_v1)
}
/// Verify the exact canonical registered projection proof.
#[cfg(test)]
pub fn verify_zk_x509_projection_segmented_stark_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    proof_bytes: &[u8],
) -> Result<(), ZkX509StarkErrorV1> {
    let layout = SegmentLayoutV1::for_projection()?;
    layout.validate()?;
    let fixed_rows = compile_zk_x509_projection_stark_fixed_rows_v1(statement)
        .map_err(|_| ZkX509StarkErrorV1::InvalidStatement)?;
    if fixed_rows.len() != layout.trace_size() {
        return Err(ZkX509StarkErrorV1::InvalidStatement);
    }
    let aggregate_layout = AggregateProofLayoutV1::for_segments(&[layout])?;
    let proof = decode_zk_x509_segmented_stark_proof_v1(proof_bytes, &aggregate_layout)?;
    if proof.trace_groups.len() != 1 {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let public_digest = projection_public_digest_v1(statement)?;
    let mut transcript = new_transcript_v1(&public_digest)?;
    absorb_aggregate_layout_v1(
        TEST_PROOF_INSTANCE_V1,
        &mut transcript,
        b"iroha:privacy:zk-x509:projection-aggregate-layout:v1",
        &aggregate_layout,
    )?;
    aggregate::absorb_base_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &proof.trace_groups)
        .map_err(map_aggregate_error_v1)?;
    let projection_challenges = derive_projection_challenges_v1(&mut transcript)?;
    aggregate::absorb_aux_roots_v1(&mut transcript, &AGGREGATE_DOMAINS_V1, &proof.trace_groups)
        .map_err(map_aggregate_error_v1)?;
    let alphas = derive_constraint_alphas_v1(&mut transcript, &aggregate_layout)?;
    aggregate::absorb_composition_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &proof.composition_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_fri_mask_roots_v1(
        &mut transcript,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &proof.fri_mask_roots,
    )
    .map_err(map_aggregate_error_v1)?;
    let shared_layout = aggregate_layout.as_shared()?;
    let deep_point =
        aggregate::derive_deep_point_v1(&mut transcript, AGGREGATE_PARAMETERS_V1, &shared_layout)
            .map_err(map_aggregate_error_v1)?;
    aggregate::absorb_deep_openings_v1(
        &mut transcript,
        &proof.deep,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
    )
    .map_err(map_aggregate_error_v1)?;
    let mixes = derive_fri_mixes_v1(&mut transcript, &aggregate_layout)?;
    let deep_mixes = aggregate_deep_lane_mixes_v1(&mixes, &aggregate_layout)?;
    let (fri_betas, terminal_fields) = aggregate::verify_fri_commitments_v1(
        &proof,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        &mut transcript,
    )
    .map_err(map_aggregate_error_v1)?;
    let grinding_state = transcript.state();
    verify_grinding_nonce_v1(
        ZK_X509_DIGEST_CONTEXT_V1,
        &grinding_state,
        ZK_X509_GRINDING_BITS_V1,
        proof.grinding_nonce,
    )
    .map_err(|_| ZkX509StarkErrorV1::TranscriptMismatch)?;
    absorb_grinding_nonce_v1(&mut transcript, proof.grinding_nonce)?;
    let expected_indices =
        query_indices_v1(TEST_PROOF_INSTANCE_V1, &transcript, &aggregate_layout)?;
    aggregate::verify_all_merkle_openings_v1(
        &proof,
        AGGREGATE_PARAMETERS_V1,
        &AGGREGATE_DOMAINS_V1,
        &shared_layout,
        &expected_indices,
    )
    .map_err(map_aggregate_error_v1)?;
    let fixed_columns = transpose_array_rows_v1(&fixed_rows)?;
    let fixed_lde = fixed_lde_columns_v1(&fixed_columns, layout)?;
    let lde_root =
        goldilocks_primitive_root_v1(layout.lde_log2).map_err(map_transparent_error_v1)?;
    let mut evaluator = ProjectionOpenedRowEvaluatorV1 {
        aggregate_layout: &aggregate_layout,
        layout,
        fixed_lde: &fixed_lde,
        challenges: projection_challenges,
        alphas: &alphas[0],
        mixes: &mixes[0],
        lde_root,
    };
    aggregate::verify_opened_query_relations_with_deep_v1(
        &proof.aggregate,
        &proof.deep,
        deep_point,
        &deep_mixes,
        AGGREGATE_PARAMETERS_V1,
        &shared_layout,
        &expected_indices,
        &fri_betas,
        &terminal_fields,
        &mut evaluator,
    )
    .map_err(map_aggregate_error_v1)
}
#[cfg(test)]
mod tests {
    include!("stark/support_and_io_tests.rs");
    include!("stark/main_p256_tests.rs");
    include!("stark/der_and_native_proof_tests.rs");
    include!("stark/native_registration_tests.rs");
    include!("stark/registration_phase_tests.rs");
}
