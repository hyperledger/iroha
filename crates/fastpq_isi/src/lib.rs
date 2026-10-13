//! FASTPQ Instruction Set - canonical STARK parameter descriptors.
//!
//! This crate publishes the canonical FASTPQ lane prover/verifier parameter
//! set. The constants exported here are used by the prover implementation and
//! kept in a dedicated crate so workspace members share one source of truth.
//!
//! The parameter descriptor mirrors the implementation-coupled specification.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
pub mod compact_challenge;
pub mod keccak256;
pub mod params;
pub mod poseidon;
pub mod poseidon_digest384;
mod poseidon_digest384_prefix;
pub mod resource_limits;
pub mod semantic_profile;
pub use params::{
    CANONICAL_PARAMETER_SETS, ExactDyadicBoundV1, FASTPQ_AGGREGATE_TARGETS_V1, FASTPQ_CATALOG_V1,
    FASTPQ_COMPOSITION_DEGREE_EXPANSION_V1, FASTPQ_DIGEST_LANE_BITS_V1, FASTPQ_DIGEST_LANES_V1,
    FASTPQ_FINAL_V1, FASTPQ_FINAL_V1_ID, FASTPQ_FRI_TERMINAL_DOMAIN_SIZE_V1,
    FASTPQ_MAX_QUERY_COUNT_V1, FASTPQ_MIN_QUERY_COUNT_V1, FASTPQ_QROM_BOUND_INPUTS_V1,
    FASTPQ_QUANTUM_ORACLE_QUERY_LOG2_BOUND_V1, FASTPQ_QUERY_COUNT_GRANULARITY_V1,
    FASTPQ_QUERY_COUNT_V1, FASTPQ_REQUIRED_SECURITY_BITS_V1,
    FastpqProductionQualificationBlockerV1, FastpqProductionQualificationV1,
    FastpqQromBoundInputsV1, FastpqQromBoundReportV1, FieldDescriptor, FriParameters,
    GOLDILOCKS_FP4_V1, HashDescriptor, POSEIDON_X7_GOLDILOCKS_DIGEST384_V1, StarkParameterSet,
    calculate_fastpq_qrom_bound_v1, find_by_name, select_fastpq_query_count_v1,
};
pub use poseidon_digest384::{
    GOLDILOCKS_DIGEST384_BYTES_V1, GOLDILOCKS_DIGEST384_LANES_V1,
    GOLDILOCKS_DIGEST384_PARAMETER_SHA3_256_V1, GOLDILOCKS_DIGEST384_ROUNDS_V1,
    GoldilocksDigest384FrameV1, GoldilocksDigest384LanePrefixV1,
    GoldilocksDigest384LastFieldStreamErrorV1, GoldilocksDigest384LastFieldStreamV1,
    GoldilocksDigest384V1, GoldilocksDigestDomainV1, goldilocks_digest384_lane_initial_state_v1,
    goldilocks_digest384_lane_round_constants_v1, hash_bytes_384_v1,
};
pub use poseidon_digest384_prefix::{
    GoldilocksDigest384DomainPrefixV1, GoldilocksDigest384OwnedDomainPrefixV1,
    GoldilocksDigest384OwnedDomainV1,
};
