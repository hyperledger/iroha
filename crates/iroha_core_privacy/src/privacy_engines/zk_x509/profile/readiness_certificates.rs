//! Typed, digest-pinned activation certificates for the X.509 release profile.
use super::*;
use crate::privacy_engines::{
    aggregate_stark::{
        AggregateFriTheorem2BoundV1, AggregateFriTheorem2CertificateV1, AggregateProofLayoutV1,
        AggregateTraceGroupLayoutV1, validate_affine_batched_fri_theorem2_v1,
    },
    transparent_stark::checked_transparent_stark_work_security_v1,
    zk_x509::{
        p256_aggregate_adapter::{
            P256_PERMUTATION_CHALLENGE_LANES_V1, P256_PERMUTATION_FACTOR_CARDINALITY_BOUND_V1,
            P256_PERMUTATION_LOCAL_COLLISION_BITS_V1, P256_X5S1_PERMUTATION_ARGUMENTS_V1,
            P256_X5S1_PERMUTATION_UNION_COLLISION_BITS_V1,
        },
        rfc5280_stark::{
            ZK_X509_RFC5280_STARK_BUS_LANES_V1, ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1,
            ZK_X509_RFC5280_STARK_COPY_SOUNDNESS_BITS_V1,
            ZK_X509_RFC5280_STARK_RELATION_EVENT_BOUND_V1,
        },
        sha_call_bus_stark::{
            ZK_X509_SHA_BASE_FOLD_COLLISION_LANES_V1, ZK_X509_SHA_BASE_FOLD_COLLISION_NUMERATOR_V1,
            ZK_X509_SHA_CALL_BUS_COLLISION_NUMERATOR_V1, ZK_X509_SHA_COLLISION_LANES_V1,
            ZK_X509_SHA_WORD_MEMORY_COLLISION_NUMERATOR_V1,
        },
    },
};
use iroha_data_model::privacy::ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1;
use sha2::{Digest as _, Sha256};
const SOUNDNESS_CERTIFICATE_SCHEMA_VERSION_V1: u16 = 1;
const SOUNDNESS_CERTIFICATE_DOMAIN_V1: &[u8] = b"iroha.zk-x509.soundness-certificate.payload.v1";
const SOUNDNESS_CERTIFICATE_FIELD_COUNT_V1: u16 = 61;
const SOUNDNESS_ROUND_BY_ROUND_BITS_V1: u16 = 157;
const SOUNDNESS_RANDOM_ORACLE_BITS_V1: u16 = 256;
const SOUNDNESS_MAX_RANDOM_ORACLE_QUERY_LOG2_V1: u16 = 64;
const SOUNDNESS_ROUND_BY_ROUND_UNION_TERMS_V1: u8 = 7;
const SHA_MEMORY_EQUALITIES_V1: u8 = 2;
const SHA_CALL_EQUALITIES_V1: u8 = 1;
const SHA_BASE_FOLD_EQUALITIES_V1: u8 = 1;
/// Independent SHA-256 pin for an accepted soundness-certificate payload.
///
/// No certificate is installed while the joint relation, transcript security
/// and correlated-opening hiding analysis await independent qualification.
/// TODO: review the complete joint protocol before installing a certificate.
pub const ZK_X509_SOUNDNESS_CERTIFICATE_SHA256_V1: [u8; 32] = [0; 32];
/// Schema version of the canonical native-resource certificate payload.
pub const ZK_X509_RESOURCE_CERTIFICATE_SCHEMA_VERSION_V1: u16 = 1;
const RESOURCE_CERTIFICATE_DOMAIN_V1: &[u8] =
    b"iroha.zk-x509.native-resource-certificate.payload.v1";
const RESOURCE_CERTIFICATE_FIELD_COUNT_V1: u16 = 60;
pub const ZK_X509_RESOURCE_OPERATING_SYSTEM_V1: &str = "linux";
pub const ZK_X509_RESOURCE_ARCHITECTURE_V1: &str = "aarch64";
pub const ZK_X509_RESOURCE_ENDIANNESS_V1: &str = "little";
pub const ZK_X509_RESOURCE_KERNEL_MINIMUM_MAJOR_V1: u16 = 6;
pub const ZK_X509_RESOURCE_KERNEL_MINIMUM_MINOR_V1: u16 = 3;
pub const ZK_X509_RESOURCE_RUSTC_RELEASE_V1: &str = "1.93.1";
pub const ZK_X509_RESOURCE_RUSTC_HOST_V1: &str = "aarch64-unknown-linux-gnu";
pub const ZK_X509_RESOURCE_RUSTC_COMMIT_HASH_V1: &str = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
pub const ZK_X509_RESOURCE_RUSTC_COMMIT_DATE_V1: &str = "2026-02-11";
pub const ZK_X509_RESOURCE_INSTANCE_TYPE_V1: &str = "c7g.4xlarge";
pub const ZK_X509_RESOURCE_CPU_MODEL_V1: &str = "Neoverse-V1";
pub const ZK_X509_RESOURCE_LOGICAL_CPU_COUNT_V1: u16 = 16;
pub const ZK_X509_RESOURCE_ONLINE_CPU_COUNT_V1: u16 = 16;
pub const ZK_X509_RESOURCE_AFFINITY_CPU_COUNT_V1: u16 = 16;
const RESOURCE_MAIN_THREAD_STACK_BYTES_V1: u64 = 8 * 1024 * 1024;
const RESOURCE_RAYON_WORKER_STACK_BYTES_V1: u64 = 8 * 1024 * 1024;
const RESOURCE_WATCHDOG_THREAD_STACK_BYTES_V1: u64 = 8 * 1024 * 1024;
const RESOURCE_RAYON_WORKER_COUNT_V1: u16 = 4;
const RESOURCE_MAX_STAGE_TASKS_V1: u16 = 6;
const RESOURCE_MAX_STAGE_OPEN_FILES_V1: u16 = 4;
const RESOURCE_CORE_DUMP_BYTES_V1: u64 = 0;
const RESOURCE_LANDLOCK_ABI_MINIMUM_V1: u16 = 3;
const RESOURCE_MINIMUM_EFFECTIVE_MEMORY_BYTES_V1: u64 = 12 * 1024 * 1024 * 1024;
/// Independently reviewed elapsed time observed for the positive stage.
pub const ZK_X509_RESOURCE_POSITIVE_ELAPSED_MILLIS_V1: u64 = 0;
/// Independently reviewed peak RSS observed for the positive stage.
pub const ZK_X509_RESOURCE_POSITIVE_PEAK_RSS_BYTES_V1: u64 = 0;
/// Independently reviewed peak address space observed for the positive stage.
pub const ZK_X509_RESOURCE_POSITIVE_PEAK_ADDRESS_SPACE_BYTES_V1: u64 = 0;
/// Independently reviewed elapsed time observed for the maximum-shape stage.
pub const ZK_X509_RESOURCE_MAXIMUM_ELAPSED_MILLIS_V1: u64 = 0;
/// Independently reviewed peak RSS observed for the maximum-shape stage.
pub const ZK_X509_RESOURCE_MAXIMUM_PEAK_RSS_BYTES_V1: u64 = 0;
/// Independently reviewed peak address space observed for the maximum-shape stage.
pub const ZK_X509_RESOURCE_MAXIMUM_PEAK_ADDRESS_SPACE_BYTES_V1: u64 = 0;
/// Independent SHA-256 pin for the typed native-resource payload.
///
/// This bootstrap pin remains zero until native Linux capture has populated
/// and reviewers have accepted every observation. It is not hashed into the
/// payload it authenticates.
pub const ZK_X509_RESOURCE_CERTIFICATE_SHA256_V1: [u8; 32] = [0; 32];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZkX509SoundnessCertificateV1 {
    schema_version: u16,
    compiled_profile_digest: [u8; 32],
    target_bits: u16,
    round_by_round_bits: u16,
    random_oracle_bits: u16,
    max_random_oracle_query_log2: u16,
    main_fri: AggregateFriTheorem2CertificateV1,
    ca_fri: AggregateFriTheorem2CertificateV1,
    goldilocks_modulus: u64,
    rfc_event_bound: u64,
    rfc_relation_count: u16,
    rfc_challenge_lanes: u8,
    p256_factor_bound: u64,
    p256_argument_count: u16,
    p256_challenge_lanes: u8,
    sha_memory_numerator: u64,
    sha_memory_equalities: u8,
    sha_memory_challenge_lanes: u8,
    sha_call_numerator: u64,
    sha_call_equalities: u8,
    sha_call_challenge_lanes: u8,
    sha_base_fold_numerator: u64,
    sha_base_fold_equalities: u8,
    sha_base_fold_challenge_lanes: u8,
    round_by_round_union_terms: u8,
}
/// Exact release-machine identity bound by the resource certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ResourceEnvironmentV1<'a> {
    /// Exact operating-system family.
    pub operating_system: &'a str,
    /// Exact target architecture.
    pub architecture: &'a str,
    /// Exact target byte order.
    pub endianness: &'a str,
    /// Minimum Linux kernel major version required by the isolation contract.
    pub kernel_minimum_major: u16,
    /// Minimum Linux kernel minor version required by the isolation contract.
    pub kernel_minimum_minor: u16,
    /// Exact `rustc -Vv` release.
    pub rustc_release: &'a str,
    /// Exact `rustc -Vv` host triple.
    pub rustc_host: &'a str,
    /// Exact `rustc -Vv` commit hash.
    pub rustc_commit_hash: &'a str,
    /// Exact `rustc -Vv` commit date.
    pub rustc_commit_date: &'a str,
    /// Exact native instance type.
    pub instance_type: &'a str,
    /// Exact native CPU model.
    pub cpu_model: &'a str,
    /// Exact logical processor count.
    pub logical_cpu_count: u16,
    /// Exact online processor count.
    pub online_cpu_count: u16,
    /// Exact processor-affinity count.
    pub affinity_cpu_count: u16,
}
/// Reviewed isolation and process ceilings, distinct from observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ResourceProcessLimitsV1 {
    /// Reviewed wall-clock ceiling, in milliseconds.
    pub elapsed_ceiling_millis: u64,
    /// Reviewed peak resident-set ceiling, in bytes.
    pub peak_rss_ceiling_bytes: u64,
    /// Reviewed virtual-address-space ceiling, in bytes.
    pub address_space_ceiling_bytes: u64,
    /// Exact main-thread stack limit, in bytes.
    pub main_thread_stack_bytes: u64,
    /// Exact Rayon-worker stack limit, in bytes.
    pub rayon_worker_stack_bytes: u64,
    /// Exact watchdog-thread stack limit, in bytes.
    pub watchdog_thread_stack_bytes: u64,
    /// Exact Rayon worker count.
    pub rayon_worker_count: u16,
    /// Exact process-task ceiling.
    pub max_stage_tasks: u16,
    /// Exact open-file ceiling after isolation.
    pub max_stage_open_files: u16,
    /// Exact core-dump byte ceiling.
    pub core_dump_bytes: u64,
    /// Minimum accepted Landlock ABI.
    pub landlock_abi_minimum: u16,
    /// Minimum effective cgroup memory headroom, in bytes.
    pub minimum_effective_memory_bytes: u64,
    /// Whether a cgroup-v2 hierarchy was established.
    pub cgroup_v2: bool,
    /// Whether the cgroup CPU quota was unlimited.
    pub cpu_quota_unlimited: bool,
    /// Whether Landlock `restrict_self` completed.
    pub landlock_restrict_self: bool,
    /// Whether file access used an anchored `openat2` walk.
    pub anchored_openat2: bool,
    /// Whether the anonymous runner used `MFD_EXEC`.
    pub memfd_exec: bool,
    /// Whether the anonymous runner required `F_SEAL_EXEC`.
    pub memfd_seal_exec: bool,
    /// Whether the measured runner was a fully static ELF.
    pub static_elf_only: bool,
    /// Whether seccomp was installed with thread synchronization.
    pub seccomp_tsync: bool,
}
/// One exact positive or maximum-shape native observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ResourceObservationV1 {
    /// Closed resource case tag: zero for positive, three for maximum shape.
    pub case_kind: u8,
    /// Observed elapsed time, in milliseconds.
    pub elapsed_millis: u64,
    /// Observed peak resident set, in bytes.
    pub peak_rss_bytes: u64,
    /// Observed peak virtual address space, in bytes.
    pub peak_address_space_bytes: u64,
    /// Actual primary relation units.
    pub primary_units: u64,
    /// Reviewed primary relation ceiling.
    pub primary_ceiling: u64,
    /// Actual secondary relation units.
    pub secondary_units: u64,
    /// Reviewed secondary relation ceiling.
    pub secondary_ceiling: u64,
    /// Actual relation depth.
    pub relation_depth: u64,
    /// Reviewed relation-depth ceiling.
    pub relation_depth_ceiling: u64,
}
/// Complete typed payload authenticated by the native-resource pin.
///
/// Constructing or validating this untrusted capture payload confers no activation authority.
/// Acceptance also requires exact source bindings and the independently installed nonzero pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509ResourceCertificateV1<'a> {
    /// Canonical certificate schema version.
    pub schema_version: u16,
    /// Digest of the exact compiled X.509 profile.
    pub compiled_profile_digest: [u8; 32],
    /// Exact native environment identity.
    pub environment: ZkX509ResourceEnvironmentV1<'a>,
    /// SHA-256 of the authoritative expectations Norito bytes.
    pub expectations_norito_sha256: [u8; 32],
    /// SHA-256 of the typed-equal expectations JSON bytes.
    pub expectations_json_sha256: [u8; 32],
    /// Exact encoded byte length of the deterministic X5S1 KAT.
    pub kat_proof_bytes: u32,
    /// SHA-256 of the deterministic X5S1 KAT.
    pub kat_proof_sha256: [u8; 32],
    /// Reviewed process ceilings and isolation requirements.
    pub process_limits: ZkX509ResourceProcessLimitsV1,
    /// Exact positive-stage native observation.
    pub positive: ZkX509ResourceObservationV1,
    /// Exact maximum-shape native observation.
    pub maximum: ZkX509ResourceObservationV1,
}
struct CertificateFrameV1(Sha256);
impl CertificateFrameV1 {
    fn new(domain: &[u8], field_count: u16) -> Self {
        let mut hash = Sha256::new();
        hash.update(ZK_X509_HASH_FRAME_DOMAIN_V1);
        hash.update(
            u16::try_from(domain.len())
                .expect("fixed readiness-certificate domain length fits u16")
                .to_be_bytes(),
        );
        hash.update(domain);
        hash.update(field_count.to_be_bytes());
        Self(hash)
    }
    fn field(&mut self, bytes: &[u8]) {
        self.0.update(
            u64::try_from(bytes.len())
                .expect("readiness-certificate field length fits u64")
                .to_be_bytes(),
        );
        self.0.update(bytes);
    }
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
fn append_fri_certificate_v1(
    frame: &mut CertificateFrameV1,
    certificate: AggregateFriTheorem2CertificateV1,
) {
    frame.field(&[certificate.affine_coefficient_numerator]);
    frame.field(&[certificate.affine_coefficient_denominator]);
    frame.field(&[certificate.batching_parameter_m]);
    frame.field(&[certificate.rho_numerator]);
    frame.field(&[certificate.rho_denominator]);
    frame.field(&[certificate.binary_fold_arity]);
    frame.field(&[certificate.domain_log2]);
    frame.field(&certificate.extension_field_lower_bound_bits.to_be_bytes());
    frame.field(&[certificate.base_field_two_adicity]);
    frame.field(&[u8::from(certificate.trace_domains_are_smooth_subgroups)]);
    frame.field(&[u8::from(
        certificate.evaluation_domain_is_smooth_generator_coset,
    )]);
    frame.field(&[u8::from(
        certificate.evaluation_domain_is_disjoint_from_trace_domains,
    )]);
    frame.field(&[certificate.fold_count]);
    frame.field(&[certificate.terminal_log2]);
    frame.field(&certificate.terminal_degree_bound.to_be_bytes());
    frame.field(&[certificate.query_count]);
    frame.field(&[u8::from(certificate.distinct_queries_without_replacement)]);
    frame.field(&[u8::from(certificate.uniform_rejection_sampling)]);
    frame.field(&certificate.claimed_query_error_bits.to_be_bytes());
}
fn canonical_soundness_certificate_v1(
    compiled_profile_digest: [u8; 32],
) -> ZkX509SoundnessCertificateV1 {
    ZkX509SoundnessCertificateV1 {
        schema_version: SOUNDNESS_CERTIFICATE_SCHEMA_VERSION_V1,
        compiled_profile_digest,
        target_bits: ZK_X509_TARGET_SOUNDNESS_BITS_V1,
        round_by_round_bits: SOUNDNESS_ROUND_BY_ROUND_BITS_V1,
        random_oracle_bits: SOUNDNESS_RANDOM_ORACLE_BITS_V1,
        max_random_oracle_query_log2: SOUNDNESS_MAX_RANDOM_ORACLE_QUERY_LOG2_V1,
        main_fri: fri_theorem_certificate_v1(
            ZK_X509_MAIN_COMMON_LDE_LOG2_V1,
            ZK_X509_FRI_ROUNDS_V1,
            ZK_X509_FRI_FINAL_POLYNOMIAL_LENGTH_V1.ilog2() as u8,
            ZK_X509_FRI_TERMINAL_DEGREE_BOUND_V1,
        ),
        ca_fri: fri_theorem_certificate_v1(
            ZK_X509_CA_FRI_LDE_LOG2_V1,
            ZK_X509_CA_FRI_ROUNDS_V1,
            ZK_X509_CA_FRI_TERMINAL_LOG2_V1,
            ZK_X509_CA_FRI_TERMINAL_DEGREE_BOUND_V1,
        ),
        goldilocks_modulus: ZK_X509_GOLDILOCKS_MODULUS_V1,
        rfc_event_bound: ZK_X509_RFC5280_STARK_RELATION_EVENT_BOUND_V1 as u64,
        rfc_relation_count: ZK_X509_RFC5280_STARK_COMPRESSED_RELATIONS_V1 as u16,
        rfc_challenge_lanes: ZK_X509_RFC5280_STARK_BUS_LANES_V1 as u8,
        p256_factor_bound: P256_PERMUTATION_FACTOR_CARDINALITY_BOUND_V1 as u64,
        p256_argument_count: P256_X5S1_PERMUTATION_ARGUMENTS_V1 as u16,
        p256_challenge_lanes: P256_PERMUTATION_CHALLENGE_LANES_V1 as u8,
        sha_memory_numerator: ZK_X509_SHA_WORD_MEMORY_COLLISION_NUMERATOR_V1,
        sha_memory_equalities: SHA_MEMORY_EQUALITIES_V1,
        sha_memory_challenge_lanes: ZK_X509_SHA_COLLISION_LANES_V1,
        sha_call_numerator: ZK_X509_SHA_CALL_BUS_COLLISION_NUMERATOR_V1,
        sha_call_equalities: SHA_CALL_EQUALITIES_V1,
        sha_call_challenge_lanes: ZK_X509_SHA_COLLISION_LANES_V1,
        sha_base_fold_numerator: ZK_X509_SHA_BASE_FOLD_COLLISION_NUMERATOR_V1,
        sha_base_fold_equalities: SHA_BASE_FOLD_EQUALITIES_V1,
        sha_base_fold_challenge_lanes: ZK_X509_SHA_BASE_FOLD_COLLISION_LANES_V1,
        round_by_round_union_terms: SOUNDNESS_ROUND_BY_ROUND_UNION_TERMS_V1,
    }
}
fn soundness_certificate_digest_v1(certificate: ZkX509SoundnessCertificateV1) -> [u8; 32] {
    let mut frame = CertificateFrameV1::new(
        SOUNDNESS_CERTIFICATE_DOMAIN_V1,
        SOUNDNESS_CERTIFICATE_FIELD_COUNT_V1,
    );
    frame.field(&certificate.schema_version.to_be_bytes());
    frame.field(&certificate.compiled_profile_digest);
    frame.field(&certificate.target_bits.to_be_bytes());
    frame.field(&certificate.round_by_round_bits.to_be_bytes());
    frame.field(&certificate.random_oracle_bits.to_be_bytes());
    frame.field(&certificate.max_random_oracle_query_log2.to_be_bytes());
    append_fri_certificate_v1(&mut frame, certificate.main_fri);
    append_fri_certificate_v1(&mut frame, certificate.ca_fri);
    frame.field(&certificate.goldilocks_modulus.to_be_bytes());
    frame.field(&certificate.rfc_event_bound.to_be_bytes());
    frame.field(&certificate.rfc_relation_count.to_be_bytes());
    frame.field(&[certificate.rfc_challenge_lanes]);
    frame.field(&certificate.p256_factor_bound.to_be_bytes());
    frame.field(&certificate.p256_argument_count.to_be_bytes());
    frame.field(&[certificate.p256_challenge_lanes]);
    frame.field(&certificate.sha_memory_numerator.to_be_bytes());
    frame.field(&[certificate.sha_memory_equalities]);
    frame.field(&[certificate.sha_memory_challenge_lanes]);
    frame.field(&certificate.sha_call_numerator.to_be_bytes());
    frame.field(&[certificate.sha_call_equalities]);
    frame.field(&[certificate.sha_call_challenge_lanes]);
    frame.field(&certificate.sha_base_fold_numerator.to_be_bytes());
    frame.field(&[certificate.sha_base_fold_equalities]);
    frame.field(&[certificate.sha_base_fold_challenge_lanes]);
    frame.field(&[certificate.round_by_round_union_terms]);
    frame.finish()
}
fn validate_fri_certificate_v1(
    certificate: AggregateFriTheorem2CertificateV1,
    native_trace_log2: u8,
    blowup_log2: u8,
    terminal_log2: u8,
    terminal_degree_bound: u16,
    composition_degree_chunks: u8,
) -> Option<AggregateFriTheorem2BoundV1> {
    let parameters = fri_parameters_v1(
        native_trace_log2,
        blowup_log2,
        terminal_log2,
        usize::from(terminal_degree_bound),
        usize::from(composition_degree_chunks),
    );
    let layout = AggregateProofLayoutV1::new(
        parameters,
        vec![AggregateTraceGroupLayoutV1 {
            native_trace_log2,
            segment_instances: 1,
            base_width: 1,
            aux_width: 1,
        }],
    )
    .ok()?;
    validate_affine_batched_fri_theorem2_v1(parameters, &layout, certificate).ok()
}
fn ceil_log2_v1(value: u16) -> Option<u16> {
    if value == 0 {
        return None;
    }
    Some(if value == 1 {
        0
    } else {
        u16::try_from(u16::BITS - (value - 1).leading_zeros()).ok()?
    })
}
fn weighted_exponent_union_security_bits_v1(terms: &[(u16, u16)]) -> Option<u16> {
    let scale = terms.iter().map(|(bits, _)| *bits).max()?;
    let mut numerator = 0_u128;
    for &(bits, multiplicity) in terms {
        if multiplicity == 0 {
            return None;
        }
        let weight = 1_u128
            .checked_shl(u32::from(scale - bits))?
            .checked_mul(u128::from(multiplicity))?;
        numerator = numerator.checked_add(weight)?;
    }
    let ceiling_log =
        u16::try_from(u128::BITS - (numerator.checked_sub(1)?).leading_zeros()).ok()?;
    scale.checked_sub(ceiling_log)
}
fn collision_union_security_bits_v1(denominator: u64, terms: &[(u64, u8, u16)]) -> Option<u16> {
    let mut exponents = Vec::with_capacity(terms.len());
    for &(numerator, lanes, multiplicity) in terms {
        if numerator == 0 || numerator >= denominator || lanes == 0 || multiplicity == 0 {
            return None;
        }
        let ratio = denominator / numerator;
        let ratio_floor_log2 = u16::try_from(u64::BITS - 1 - ratio.leading_zeros()).ok()?;
        exponents.push((
            ratio_floor_log2.checked_mul(u16::from(lanes))?,
            multiplicity,
        ));
    }
    weighted_exponent_union_security_bits_v1(&exponents)
}
fn exponent_union_security_bits_v1(terms: &[u16]) -> Option<u16> {
    let terms = terms.iter().map(|bits| (*bits, 1)).collect::<Vec<_>>();
    weighted_exponent_union_security_bits_v1(&terms)
}
/// Conservative paired-configuration factor for the conditional interactive argument.
/// Each local configuration has agreement > 7/16 and degree/domain <= 9/64.
/// The elementary incidence bound gives L < 6; eight per domain leaves slack.
const JOINT_CONFIGURATION_BOUND_V1: u16 = 8;
const JOINT_PAIRED_CONFIGURATION_BOUND_V1: u16 =
    JOINT_CONFIGURATION_BOUND_V1 * JOINT_CONFIGURATION_BOUND_V1;
/// Check the algebraic error ledger only. This is not a Fiat-Shamir, qROM,
/// transcript-simulation, or release-qualification certificate by itself.
/// The mixed-domain argument and term census are in the joint-relation spec.
fn joint_relation_error_bits_v1(certificate: ZkX509SoundnessCertificateV1) -> Option<u16> {
    let main = certificate.main_fri;
    let ca = certificate.ca_fri;
    let degree = |fri: AggregateFriTheorem2CertificateV1| {
        u64::from(fri.terminal_degree_bound)
            .checked_add(1)?
            .checked_shl(u32::from(fri.fold_count))
    };
    let main_degree = degree(main)?;
    let ca_degree = degree(ca)?;
    if main_degree != 589_824
        || ca_degree != 9_216
        || main.domain_log2 != 22
        || ca.domain_log2 != 16
        || main.extension_field_lower_bound_bits != 252
        || ca.extension_field_lower_bound_bits != 252
        || u64::from(ZK_X509_FRI_EXCLUSIVE_DEGREE_CAP_V1) != main_degree
        || u64::from(ZK_X509_COMPOSITION_DEGREE_CHUNKS_V1) != 6
        || ZK_X509_MAX_NATIVE_TRACE_LOG2_V1 != 19
        || ZK_X509_MAX_CONSTRAINT_DEGREE_V1 != 7
        || ZK_X509_CA_COMPOSITION_DEGREE_CHUNKS_V1 != 4
        || super::super::accumulator_stark::ZK_X509_CA_ACCUMULATOR_CONSTRAINT_DEGREE_V1 != 3
        || super::super::accumulator_stark::ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1 != 12
        || JOINT_CONFIGURATION_BOUND_V1 * (49 - 36) <= 112 - 36
    {
        return None;
    }
    // Only the linear digest joins substitute X^32. Other products are local
    // degree<=7, unpowered quartics, or MAIN(gamma X)*CA(eta X).
    // All MAIN divisors divide X^(2^19)-1; all CA divisors divide X^(2^12)-1.
    let main_numerator = 32_u64.checked_mul(main_degree)?.checked_add(1 << 19)?;
    let ca_numerator = 4_u64.checked_mul(ca_degree)?.checked_add(1 << 12)?;
    // Original point + six power2 + five power8 + twenty power32 maps.
    // The 24 MAIN translations preserve H19 and the common generator coset.
    let exclusions = 1_u64
        .checked_add((1 + 6 * 2 + 5 * 8 + 20 * 32) * ((1 << 19) + (1 << 22)))?
        .checked_add((2 + 108) * ((1 << 12) + (1 << 16)))?;
    let point_numerator = u64::from(JOINT_PAIRED_CONFIGURATION_BOUND_V1)
        .checked_mul(main_numerator.checked_add(ca_numerator)?)?;
    if exclusions != 3_277_643_777 || point_numerator >= 1 << 31 {
        return None;
    }
    // |F|>2^252 and exclusions<2^64 imply admitted support>2^251.
    // The paired point event is <2^-220; the paired independent-alpha event
    // is <64/2^252=2^-246. Their sum is strictly below 2^-219.
    Some(219)
}
fn validate_soundness_certificate_payload_v1(
    certificate: ZkX509SoundnessCertificateV1,
) -> Option<[u8; 32]> {
    if !digest_is_nonzero_v1(certificate.compiled_profile_digest)
        || usize::from(ZK_X509_LDE_COLUMN_BATCH_V1)
            != crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
        || certificate != canonical_soundness_certificate_v1(certificate.compiled_profile_digest)
    {
        return None;
    }
    let main = validate_fri_certificate_v1(
        certificate.main_fri,
        ZK_X509_MAX_NATIVE_TRACE_LOG2_V1,
        ZK_X509_FRI_BLOWUP_FACTOR_V1.ilog2() as u8,
        ZK_X509_FRI_FINAL_POLYNOMIAL_LENGTH_V1.ilog2() as u8,
        ZK_X509_FRI_TERMINAL_DEGREE_BOUND_V1,
        ZK_X509_COMPOSITION_DEGREE_CHUNKS_V1,
    )?;
    let ca =
        super::super::accumulator_stark::validate_ca_fri_theorem_certificate_v1(certificate.ca_fri)
            .ok()?;
    let denominator = certificate.goldilocks_modulus.checked_sub(1)?;
    let rfc_bits = collision_union_security_bits_v1(
        denominator,
        &[(
            certificate.rfc_event_bound,
            certificate.rfc_challenge_lanes,
            certificate.rfc_relation_count,
        )],
    )?;
    let p256_local_bits = collision_union_security_bits_v1(
        denominator,
        &[(
            certificate.p256_factor_bound.checked_sub(1)?,
            certificate.p256_challenge_lanes,
            1,
        )],
    )?;
    let p256_bits = collision_union_security_bits_v1(
        denominator,
        &[(
            certificate.p256_factor_bound.checked_sub(1)?,
            certificate.p256_challenge_lanes,
            certificate.p256_argument_count,
        )],
    )?;
    let sha_bits = collision_union_security_bits_v1(
        denominator,
        &[
            (
                certificate.sha_memory_numerator,
                certificate.sha_memory_challenge_lanes,
                u16::from(certificate.sha_memory_equalities),
            ),
            (
                certificate.sha_call_numerator,
                certificate.sha_call_challenge_lanes,
                u16::from(certificate.sha_call_equalities),
            ),
            (
                certificate.sha_base_fold_numerator,
                certificate.sha_base_fold_challenge_lanes,
                u16::from(certificate.sha_base_fold_equalities),
            ),
        ],
    )?;
    if rfc_bits != ZK_X509_RFC5280_STARK_COPY_SOUNDNESS_BITS_V1
        || p256_local_bits != P256_PERMUTATION_LOCAL_COLLISION_BITS_V1
        || p256_bits != P256_X5S1_PERMUTATION_UNION_COLLISION_BITS_V1
    {
        return None;
    }
    let joint_bits = joint_relation_error_bits_v1(certificate)?;
    // The explicit joint algebraic term fits inside the existing rounded MAIN
    // allowance: FRI terms <2^-188 and <2^-220, plus joint term <2^-219.
    let main_first_bits = certificate
        .main_fri
        .extension_field_lower_bound_bits
        .checked_sub(2 * u16::from(certificate.main_fri.domain_log2))?
        .checked_sub(20)?;
    let main_second_bits = certificate
        .main_fri
        .extension_field_lower_bound_bits
        .checked_sub(u16::from(certificate.main_fri.domain_log2))?
        .checked_sub(10)?;
    let main_algebraic_bits =
        exponent_union_security_bits_v1(&[main_first_bits, main_second_bits, joint_bits])?;
    if main_algebraic_bits != main.commitment_error_bits {
        return None;
    }
    // Base commitments precede bus challenges. Account for every possible
    // paired base configuration, rather than assuming the later extraction
    // selects a witness independently of those challenges.
    let configuration_bits = ceil_log2_v1(JOINT_PAIRED_CONFIGURATION_BOUND_V1)?;
    let round_by_round_bits = exponent_union_security_bits_v1(&[
        main.query_error_bits,
        main_algebraic_bits,
        ca.query_error_bits,
        ca.commitment_error_bits,
        rfc_bits.checked_sub(configuration_bits)?,
        p256_bits.checked_sub(configuration_bits)?,
        sha_bits.checked_sub(configuration_bits)?,
    ])?;
    if certificate.round_by_round_union_terms != SOUNDNESS_ROUND_BY_ROUND_UNION_TERMS_V1
        || round_by_round_bits != certificate.round_by_round_bits
    {
        return None;
    }
    // TODO: supply the concrete joint round-by-round/Fiat-Shamir reduction.
    // The interactive 157-bit ledger above is only the proposed RBR target.
    // This work-security arithmetic is conditional on that separate proof;
    // numerical success does not establish it. The activation pin stays zero.
    checked_transparent_stark_work_security_v1(
        certificate.target_bits,
        round_by_round_bits,
        certificate.random_oracle_bits,
        certificate.max_random_oracle_query_log2,
    )
    .ok()?;
    Some(soundness_certificate_digest_v1(certificate))
}
pub(super) fn soundness_certificate_is_pinned_v1(compiled_profile_digest: [u8; 32]) -> bool {
    let certificate = canonical_soundness_certificate_v1(compiled_profile_digest);
    soundness_certificate_matches_pin_v1(certificate, ZK_X509_SOUNDNESS_CERTIFICATE_SHA256_V1)
}
fn soundness_certificate_matches_pin_v1(
    certificate: ZkX509SoundnessCertificateV1,
    expected_certificate_sha256: [u8; 32],
) -> bool {
    digest_is_nonzero_v1(expected_certificate_sha256)
        && validate_soundness_certificate_payload_v1(certificate)
            .is_some_and(|digest| digest == expected_certificate_sha256)
}
/// Return the exact reviewed process limits included in every resource payload.
pub const fn canonical_resource_process_limits_v1() -> ZkX509ResourceProcessLimitsV1 {
    ZkX509ResourceProcessLimitsV1 {
        elapsed_ceiling_millis: ZK_X509_PROVER_TARGET_SECONDS_V1 * 1_000,
        peak_rss_ceiling_bytes: ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1,
        address_space_ceiling_bytes: ZK_X509_PROVER_ADDRESS_SPACE_CEILING_BYTES_V1,
        main_thread_stack_bytes: RESOURCE_MAIN_THREAD_STACK_BYTES_V1,
        rayon_worker_stack_bytes: RESOURCE_RAYON_WORKER_STACK_BYTES_V1,
        watchdog_thread_stack_bytes: RESOURCE_WATCHDOG_THREAD_STACK_BYTES_V1,
        rayon_worker_count: RESOURCE_RAYON_WORKER_COUNT_V1,
        max_stage_tasks: RESOURCE_MAX_STAGE_TASKS_V1,
        max_stage_open_files: RESOURCE_MAX_STAGE_OPEN_FILES_V1,
        core_dump_bytes: RESOURCE_CORE_DUMP_BYTES_V1,
        landlock_abi_minimum: RESOURCE_LANDLOCK_ABI_MINIMUM_V1,
        minimum_effective_memory_bytes: RESOURCE_MINIMUM_EFFECTIVE_MEMORY_BYTES_V1,
        cgroup_v2: true,
        cpu_quota_unlimited: true,
        landlock_restrict_self: true,
        anchored_openat2: true,
        memfd_exec: true,
        memfd_seal_exec: true,
        static_elf_only: true,
        seccomp_tsync: true,
    }
}
/// Return the exact release environment included in every resource payload.
pub const fn canonical_resource_environment_v1() -> ZkX509ResourceEnvironmentV1<'static> {
    ZkX509ResourceEnvironmentV1 {
        operating_system: ZK_X509_RESOURCE_OPERATING_SYSTEM_V1,
        architecture: ZK_X509_RESOURCE_ARCHITECTURE_V1,
        endianness: ZK_X509_RESOURCE_ENDIANNESS_V1,
        kernel_minimum_major: ZK_X509_RESOURCE_KERNEL_MINIMUM_MAJOR_V1,
        kernel_minimum_minor: ZK_X509_RESOURCE_KERNEL_MINIMUM_MINOR_V1,
        rustc_release: ZK_X509_RESOURCE_RUSTC_RELEASE_V1,
        rustc_host: ZK_X509_RESOURCE_RUSTC_HOST_V1,
        rustc_commit_hash: ZK_X509_RESOURCE_RUSTC_COMMIT_HASH_V1,
        rustc_commit_date: ZK_X509_RESOURCE_RUSTC_COMMIT_DATE_V1,
        instance_type: ZK_X509_RESOURCE_INSTANCE_TYPE_V1,
        cpu_model: ZK_X509_RESOURCE_CPU_MODEL_V1,
        logical_cpu_count: ZK_X509_RESOURCE_LOGICAL_CPU_COUNT_V1,
        online_cpu_count: ZK_X509_RESOURCE_ONLINE_CPU_COUNT_V1,
        affinity_cpu_count: ZK_X509_RESOURCE_AFFINITY_CPU_COUNT_V1,
    }
}
const fn canonical_positive_observation_v1(
    elapsed_millis: u64,
    peak_rss_bytes: u64,
    peak_address_space_bytes: u64,
) -> ZkX509ResourceObservationV1 {
    ZkX509ResourceObservationV1 {
        case_kind: 0,
        elapsed_millis,
        peak_rss_bytes,
        peak_address_space_bytes,
        primary_units: 2,
        primary_ceiling: ZK_X509_MAX_CHAIN_DEPTH_V1 as u64,
        secondary_units: 1,
        secondary_ceiling: ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 as u64,
        relation_depth: 0,
        relation_depth_ceiling: ZK_X509_MAX_CRL_ENTRIES_V1 as u64,
    }
}
const fn canonical_maximum_observation_v1(
    elapsed_millis: u64,
    peak_rss_bytes: u64,
    peak_address_space_bytes: u64,
) -> ZkX509ResourceObservationV1 {
    ZkX509ResourceObservationV1 {
        case_kind: 3,
        elapsed_millis,
        peak_rss_bytes,
        peak_address_space_bytes,
        primary_units: ZK_X509_MAX_CHAIN_DEPTH_V1 as u64,
        primary_ceiling: ZK_X509_MAX_CHAIN_DEPTH_V1 as u64,
        secondary_units: ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 as u64,
        secondary_ceiling: ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1 as u64,
        relation_depth: ZK_X509_MAX_CRL_ENTRIES_V1 as u64,
        relation_depth_ceiling: ZK_X509_MAX_CRL_ENTRIES_V1 as u64,
    }
}
fn source_resource_certificate_v1(
    compiled_profile_digest: [u8; 32],
) -> ZkX509ResourceCertificateV1<'static> {
    ZkX509ResourceCertificateV1 {
        schema_version: ZK_X509_RESOURCE_CERTIFICATE_SCHEMA_VERSION_V1,
        compiled_profile_digest,
        environment: canonical_resource_environment_v1(),
        expectations_norito_sha256: ZK_X509_NATIVE_RELEASE_EXPECTATIONS_NORITO_SHA256_V1,
        expectations_json_sha256: ZK_X509_NATIVE_RELEASE_EXPECTATIONS_JSON_SHA256_V1,
        kat_proof_bytes: ZK_X509_RELEASE_KAT_EXPECTED_PROOF_BYTES_V1,
        kat_proof_sha256: ZK_X509_RELEASE_KAT_EXPECTED_PROOF_SHA256_V1,
        process_limits: canonical_resource_process_limits_v1(),
        positive: canonical_positive_observation_v1(
            ZK_X509_RESOURCE_POSITIVE_ELAPSED_MILLIS_V1,
            ZK_X509_RESOURCE_POSITIVE_PEAK_RSS_BYTES_V1,
            ZK_X509_RESOURCE_POSITIVE_PEAK_ADDRESS_SPACE_BYTES_V1,
        ),
        maximum: canonical_maximum_observation_v1(
            ZK_X509_RESOURCE_MAXIMUM_ELAPSED_MILLIS_V1,
            ZK_X509_RESOURCE_MAXIMUM_PEAK_RSS_BYTES_V1,
            ZK_X509_RESOURCE_MAXIMUM_PEAK_ADDRESS_SPACE_BYTES_V1,
        ),
    }
}
fn append_observation_v1(frame: &mut CertificateFrameV1, observation: ZkX509ResourceObservationV1) {
    frame.field(&[observation.case_kind]);
    frame.field(&observation.elapsed_millis.to_be_bytes());
    frame.field(&observation.peak_rss_bytes.to_be_bytes());
    frame.field(&observation.peak_address_space_bytes.to_be_bytes());
    frame.field(&observation.primary_units.to_be_bytes());
    frame.field(&observation.primary_ceiling.to_be_bytes());
    frame.field(&observation.secondary_units.to_be_bytes());
    frame.field(&observation.secondary_ceiling.to_be_bytes());
    frame.field(&observation.relation_depth.to_be_bytes());
    frame.field(&observation.relation_depth_ceiling.to_be_bytes());
}
fn resource_certificate_digest_v1(certificate: ZkX509ResourceCertificateV1<'_>) -> [u8; 32] {
    let mut frame = CertificateFrameV1::new(
        RESOURCE_CERTIFICATE_DOMAIN_V1,
        RESOURCE_CERTIFICATE_FIELD_COUNT_V1,
    );
    frame.field(&certificate.schema_version.to_be_bytes());
    frame.field(&certificate.compiled_profile_digest);
    frame.field(certificate.environment.operating_system.as_bytes());
    frame.field(certificate.environment.architecture.as_bytes());
    frame.field(certificate.environment.endianness.as_bytes());
    frame.field(&certificate.environment.kernel_minimum_major.to_be_bytes());
    frame.field(&certificate.environment.kernel_minimum_minor.to_be_bytes());
    frame.field(certificate.environment.rustc_release.as_bytes());
    frame.field(certificate.environment.rustc_host.as_bytes());
    frame.field(certificate.environment.rustc_commit_hash.as_bytes());
    frame.field(certificate.environment.rustc_commit_date.as_bytes());
    frame.field(certificate.environment.instance_type.as_bytes());
    frame.field(certificate.environment.cpu_model.as_bytes());
    frame.field(&certificate.environment.logical_cpu_count.to_be_bytes());
    frame.field(&certificate.environment.online_cpu_count.to_be_bytes());
    frame.field(&certificate.environment.affinity_cpu_count.to_be_bytes());
    frame.field(&certificate.expectations_norito_sha256);
    frame.field(&certificate.expectations_json_sha256);
    frame.field(&certificate.kat_proof_bytes.to_be_bytes());
    frame.field(&certificate.kat_proof_sha256);
    frame.field(
        &certificate
            .process_limits
            .elapsed_ceiling_millis
            .to_be_bytes(),
    );
    frame.field(
        &certificate
            .process_limits
            .peak_rss_ceiling_bytes
            .to_be_bytes(),
    );
    frame.field(
        &certificate
            .process_limits
            .address_space_ceiling_bytes
            .to_be_bytes(),
    );
    frame.field(
        &certificate
            .process_limits
            .main_thread_stack_bytes
            .to_be_bytes(),
    );
    frame.field(
        &certificate
            .process_limits
            .rayon_worker_stack_bytes
            .to_be_bytes(),
    );
    frame.field(
        &certificate
            .process_limits
            .watchdog_thread_stack_bytes
            .to_be_bytes(),
    );
    frame.field(&certificate.process_limits.rayon_worker_count.to_be_bytes());
    frame.field(&certificate.process_limits.max_stage_tasks.to_be_bytes());
    frame.field(
        &certificate
            .process_limits
            .max_stage_open_files
            .to_be_bytes(),
    );
    frame.field(&certificate.process_limits.core_dump_bytes.to_be_bytes());
    frame.field(
        &certificate
            .process_limits
            .landlock_abi_minimum
            .to_be_bytes(),
    );
    frame.field(
        &certificate
            .process_limits
            .minimum_effective_memory_bytes
            .to_be_bytes(),
    );
    frame.field(&[u8::from(certificate.process_limits.cgroup_v2)]);
    frame.field(&[u8::from(certificate.process_limits.cpu_quota_unlimited)]);
    frame.field(&[u8::from(certificate.process_limits.landlock_restrict_self)]);
    frame.field(&[u8::from(certificate.process_limits.anchored_openat2)]);
    frame.field(&[u8::from(certificate.process_limits.memfd_exec)]);
    frame.field(&[u8::from(certificate.process_limits.memfd_seal_exec)]);
    frame.field(&[u8::from(certificate.process_limits.static_elf_only)]);
    frame.field(&[u8::from(certificate.process_limits.seccomp_tsync)]);
    append_observation_v1(&mut frame, certificate.positive);
    append_observation_v1(&mut frame, certificate.maximum);
    frame.finish()
}
fn observation_is_valid_v1(
    actual: ZkX509ResourceObservationV1,
    expected_shape: ZkX509ResourceObservationV1,
    limits: ZkX509ResourceProcessLimitsV1,
) -> bool {
    actual.case_kind == expected_shape.case_kind
        && actual.primary_units == expected_shape.primary_units
        && actual.primary_ceiling == expected_shape.primary_ceiling
        && actual.secondary_units == expected_shape.secondary_units
        && actual.secondary_ceiling == expected_shape.secondary_ceiling
        && actual.relation_depth == expected_shape.relation_depth
        && actual.relation_depth_ceiling == expected_shape.relation_depth_ceiling
        && actual.elapsed_millis > 0
        && actual.elapsed_millis <= limits.elapsed_ceiling_millis
        && actual.peak_rss_bytes > 0
        && actual.peak_rss_bytes <= limits.peak_rss_ceiling_bytes
        && actual.peak_address_space_bytes > 0
        && actual.peak_address_space_bytes <= limits.address_space_ceiling_bytes
}
/// Validate and digest a capture payload without consulting the bootstrap pin.
///
/// Capture uses this before the independent source pin exists. Final evidence
/// validation additionally calls [`resource_certificate_matches_source_v1`].
pub fn validate_resource_certificate_payload_v1(
    certificate: ZkX509ResourceCertificateV1<'_>,
) -> Option<[u8; 32]> {
    if certificate.schema_version != ZK_X509_RESOURCE_CERTIFICATE_SCHEMA_VERSION_V1
        || !digest_is_nonzero_v1(certificate.compiled_profile_digest)
        || usize::from(ZK_X509_LDE_COLUMN_BATCH_V1)
            != crate::privacy_engines::aggregate_stark::MASKED_TRACE_LDE_COLUMN_BATCH_V1
        || certificate.environment != canonical_resource_environment_v1()
        || certificate.process_limits != canonical_resource_process_limits_v1()
        || !release_evidence_pins_are_complete_v1(
            certificate.kat_proof_bytes,
            certificate.kat_proof_sha256,
            certificate.expectations_norito_sha256,
            certificate.expectations_json_sha256,
        )
        || !observation_is_valid_v1(
            certificate.positive,
            canonical_positive_observation_v1(0, 0, 0),
            certificate.process_limits,
        )
        || !observation_is_valid_v1(
            certificate.maximum,
            canonical_maximum_observation_v1(0, 0, 0),
            certificate.process_limits,
        )
    {
        return None;
    }
    Some(resource_certificate_digest_v1(certificate))
}
/// Require a validated capture payload to equal every installed source field
/// and the distinct compiled certificate pin.
pub fn resource_certificate_matches_source_v1(
    certificate: ZkX509ResourceCertificateV1<'_>,
    claimed_certificate_sha256: [u8; 32],
) -> bool {
    let source = source_resource_certificate_v1(certificate.compiled_profile_digest);
    resource_certificate_matches_expected_v1(
        certificate,
        source,
        claimed_certificate_sha256,
        ZK_X509_RESOURCE_CERTIFICATE_SHA256_V1,
    )
}
pub(super) fn resource_certificate_is_pinned_v1(compiled_profile_digest: [u8; 32]) -> bool {
    let certificate = source_resource_certificate_v1(compiled_profile_digest);
    resource_certificate_matches_source_v1(certificate, ZK_X509_RESOURCE_CERTIFICATE_SHA256_V1)
}
fn resource_certificate_matches_expected_v1(
    certificate: ZkX509ResourceCertificateV1<'_>,
    expected_source: ZkX509ResourceCertificateV1<'_>,
    claimed_certificate_sha256: [u8; 32],
    expected_certificate_sha256: [u8; 32],
) -> bool {
    certificate == expected_source
        && digest_is_nonzero_v1(expected_certificate_sha256)
        && validate_resource_certificate_payload_v1(certificate).is_some_and(|digest| {
            digest == claimed_certificate_sha256 && digest == expected_certificate_sha256
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    const TEST_PROFILE_DIGEST: [u8; 32] = [0x51; 32];
    fn independently_append_fri_fields_v1(
        fields: &mut Vec<Vec<u8>>,
        certificate: AggregateFriTheorem2CertificateV1,
    ) {
        fields.push(vec![certificate.affine_coefficient_numerator]);
        fields.push(vec![certificate.affine_coefficient_denominator]);
        fields.push(vec![certificate.batching_parameter_m]);
        fields.push(vec![certificate.rho_numerator]);
        fields.push(vec![certificate.rho_denominator]);
        fields.push(vec![certificate.binary_fold_arity]);
        fields.push(vec![certificate.domain_log2]);
        fields.push(
            certificate
                .extension_field_lower_bound_bits
                .to_be_bytes()
                .to_vec(),
        );
        fields.push(vec![certificate.base_field_two_adicity]);
        fields.push(vec![u8::from(
            certificate.trace_domains_are_smooth_subgroups,
        )]);
        fields.push(vec![u8::from(
            certificate.evaluation_domain_is_smooth_generator_coset,
        )]);
        fields.push(vec![u8::from(
            certificate.evaluation_domain_is_disjoint_from_trace_domains,
        )]);
        fields.push(vec![certificate.fold_count]);
        fields.push(vec![certificate.terminal_log2]);
        fields.push(certificate.terminal_degree_bound.to_be_bytes().to_vec());
        fields.push(vec![certificate.query_count]);
        fields.push(vec![u8::from(
            certificate.distinct_queries_without_replacement,
        )]);
        fields.push(vec![u8::from(certificate.uniform_rejection_sampling)]);
        fields.push(certificate.claimed_query_error_bits.to_be_bytes().to_vec());
    }
    fn independently_digest_soundness_certificate_v1(
        certificate: ZkX509SoundnessCertificateV1,
    ) -> ([u8; 32], usize) {
        let mut fields = vec![
            certificate.schema_version.to_be_bytes().to_vec(),
            certificate.compiled_profile_digest.to_vec(),
            certificate.target_bits.to_be_bytes().to_vec(),
            certificate.round_by_round_bits.to_be_bytes().to_vec(),
            certificate.random_oracle_bits.to_be_bytes().to_vec(),
            certificate
                .max_random_oracle_query_log2
                .to_be_bytes()
                .to_vec(),
        ];
        independently_append_fri_fields_v1(&mut fields, certificate.main_fri);
        independently_append_fri_fields_v1(&mut fields, certificate.ca_fri);
        fields.extend([
            certificate.goldilocks_modulus.to_be_bytes().to_vec(),
            certificate.rfc_event_bound.to_be_bytes().to_vec(),
            certificate.rfc_relation_count.to_be_bytes().to_vec(),
            vec![certificate.rfc_challenge_lanes],
            certificate.p256_factor_bound.to_be_bytes().to_vec(),
            certificate.p256_argument_count.to_be_bytes().to_vec(),
            vec![certificate.p256_challenge_lanes],
            certificate.sha_memory_numerator.to_be_bytes().to_vec(),
            vec![certificate.sha_memory_equalities],
            vec![certificate.sha_memory_challenge_lanes],
            certificate.sha_call_numerator.to_be_bytes().to_vec(),
            vec![certificate.sha_call_equalities],
            vec![certificate.sha_call_challenge_lanes],
            certificate.sha_base_fold_numerator.to_be_bytes().to_vec(),
            vec![certificate.sha_base_fold_equalities],
            vec![certificate.sha_base_fold_challenge_lanes],
            vec![certificate.round_by_round_union_terms],
        ]);
        assert_eq!(
            fields.len(),
            usize::from(SOUNDNESS_CERTIFICATE_FIELD_COUNT_V1)
        );
        let mut hash = Sha256::new();
        hash.update(ZK_X509_HASH_FRAME_DOMAIN_V1);
        hash.update(
            u16::try_from(SOUNDNESS_CERTIFICATE_DOMAIN_V1.len())
                .expect("soundness domain length fits u16")
                .to_be_bytes(),
        );
        hash.update(SOUNDNESS_CERTIFICATE_DOMAIN_V1);
        hash.update(SOUNDNESS_CERTIFICATE_FIELD_COUNT_V1.to_be_bytes());
        let mut payload_bytes =
            ZK_X509_HASH_FRAME_DOMAIN_V1.len() + 2 + SOUNDNESS_CERTIFICATE_DOMAIN_V1.len() + 2;
        for field in fields {
            let length = u64::try_from(field.len()).expect("soundness field length fits u64");
            hash.update(length.to_be_bytes());
            hash.update(&field);
            payload_bytes += 8 + field.len();
        }
        (hash.finalize().into(), payload_bytes)
    }
    macro_rules! reject_fri_mutations {
        ($certificate:ident, $digest:ident, $field:ident) => {{
            macro_rules! reject {
                ($mutate:expr) => {{
                    let mut mutation = $certificate;
                    ($mutate)(&mut mutation.$field);
                    assert_ne!(soundness_certificate_digest_v1(mutation), $digest);
                    assert!(!soundness_certificate_matches_pin_v1(mutation, $digest));
                }};
            }
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .affine_coefficient_numerator +=
                1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .affine_coefficient_denominator +=
                1);
            reject!(
                |value: &mut AggregateFriTheorem2CertificateV1| value.batching_parameter_m += 1
            );
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.rho_numerator += 1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.rho_denominator += 1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.binary_fold_arity += 1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.domain_log2 += 1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .extension_field_lower_bound_bits +=
                1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .base_field_two_adicity +=
                1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .trace_domains_are_smooth_subgroups ^=
                true);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .evaluation_domain_is_smooth_generator_coset ^=
                true);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .evaluation_domain_is_disjoint_from_trace_domains ^=
                true);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.fold_count += 1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.terminal_log2 += 1);
            reject!(
                |value: &mut AggregateFriTheorem2CertificateV1| value.terminal_degree_bound += 1
            );
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value.query_count += 1);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .distinct_queries_without_replacement ^=
                true);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .uniform_rejection_sampling ^=
                true);
            reject!(|value: &mut AggregateFriTheorem2CertificateV1| value
                .claimed_query_error_bits +=
                1);
        }};
    }
    macro_rules! reject_process_limit_mutations {
        ($certificate:ident, $digest:ident) => {{
            macro_rules! reject {
                ($mutate:expr) => {{
                    let mut mutation = $certificate;
                    ($mutate)(&mut mutation.process_limits);
                    assert_ne!(resource_certificate_digest_v1(mutation), $digest);
                    assert!(!resource_certificate_matches_expected_v1(
                        mutation,
                        $certificate,
                        resource_certificate_digest_v1(mutation),
                        $digest,
                    ));
                }};
            }
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.elapsed_ceiling_millis += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.peak_rss_ceiling_bytes += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value
                .address_space_ceiling_bytes +=
                1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.main_thread_stack_bytes += 1);
            reject!(
                |value: &mut ZkX509ResourceProcessLimitsV1| value.rayon_worker_stack_bytes += 1
            );
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value
                .watchdog_thread_stack_bytes +=
                1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.rayon_worker_count += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.max_stage_tasks += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.max_stage_open_files += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.core_dump_bytes += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.landlock_abi_minimum += 1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value
                .minimum_effective_memory_bytes +=
                1);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.cgroup_v2 ^= true);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.cpu_quota_unlimited ^= true);
            reject!(
                |value: &mut ZkX509ResourceProcessLimitsV1| value.landlock_restrict_self ^= true
            );
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.anchored_openat2 ^= true);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.memfd_exec ^= true);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.memfd_seal_exec ^= true);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.static_elf_only ^= true);
            reject!(|value: &mut ZkX509ResourceProcessLimitsV1| value.seccomp_tsync ^= true);
        }};
    }
    macro_rules! reject_observation_mutations {
        ($certificate:ident, $digest:ident, $field:ident) => {{
            macro_rules! reject {
                ($mutate:expr) => {{
                    let mut mutation = $certificate;
                    ($mutate)(&mut mutation.$field);
                    assert_ne!(resource_certificate_digest_v1(mutation), $digest);
                    assert!(!resource_certificate_matches_expected_v1(
                        mutation,
                        $certificate,
                        resource_certificate_digest_v1(mutation),
                        $digest,
                    ));
                }};
            }
            reject!(|value: &mut ZkX509ResourceObservationV1| value.case_kind ^= 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.elapsed_millis += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.peak_rss_bytes += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.peak_address_space_bytes += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.primary_units += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.primary_ceiling += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.secondary_units += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.secondary_ceiling += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.relation_depth += 1);
            reject!(|value: &mut ZkX509ResourceObservationV1| value.relation_depth_ceiling += 1);
        }};
    }
    fn test_resource_certificate_v1() -> ZkX509ResourceCertificateV1<'static> {
        ZkX509ResourceCertificateV1 {
            schema_version: ZK_X509_RESOURCE_CERTIFICATE_SCHEMA_VERSION_V1,
            compiled_profile_digest: TEST_PROFILE_DIGEST,
            environment: canonical_resource_environment_v1(),
            expectations_norito_sha256: [0x61; 32],
            expectations_json_sha256: [0x62; 32],
            kat_proof_bytes: 1,
            kat_proof_sha256: [0x63; 32],
            process_limits: canonical_resource_process_limits_v1(),
            positive: canonical_positive_observation_v1(1_000, 1024 * 1024, 64 * 1024 * 1024),
            maximum: canonical_maximum_observation_v1(2_000, 2 * 1024 * 1024, 128 * 1024 * 1024),
        }
    }
    #[test]
    fn exact_dyadic_union_retains_distinct_error_weights_and_rejects_overflow() {
        assert_eq!(
            weighted_exponent_union_security_bits_v1(&[(172, 2), (200, 1), (165, 1)]),
            Some(164)
        );
        assert_eq!(
            exponent_union_security_bits_v1(&[160, 187, 160, 199, 164, 165, 158]),
            Some(157)
        );
        assert_eq!(exponent_union_security_bits_v1(&[188, 220, 219]), Some(187));
        assert_eq!(weighted_exponent_union_security_bits_v1(&[(8, 1)]), Some(8));
        assert_eq!(weighted_exponent_union_security_bits_v1(&[(8, 0)]), None);
        assert_eq!(
            weighted_exponent_union_security_bits_v1(&[(0, 1), (128, 1)]),
            None
        );
        assert_eq!(
            weighted_exponent_union_security_bits_v1(&[(0, 3), (127, 1)]),
            None
        );
        assert_eq!(weighted_exponent_union_security_bits_v1(&[]), None);
    }

    #[test]
    fn joint_algebraic_ledger_binds_actual_restored_degrees_and_remains_unpinned() {
        let certificate = canonical_soundness_certificate_v1(TEST_PROFILE_DIGEST);
        assert_eq!(joint_relation_error_bits_v1(certificate), Some(219));
        assert_eq!(JOINT_PAIRED_CONFIGURATION_BOUND_V1, 64);
        let mut wrong = certificate;
        wrong.main_fri.fold_count -= 1;
        assert_eq!(joint_relation_error_bits_v1(wrong), None);
        wrong = certificate;
        wrong.ca_fri.terminal_degree_bound -= 1;
        assert_eq!(joint_relation_error_bits_v1(wrong), None);
        assert_eq!(ZK_X509_SOUNDNESS_CERTIFICATE_SHA256_V1, [0; 32]);
    }

    #[test]
    fn soundness_certificate_recomputes_the_complete_bound_without_installing_a_pin() {
        let certificate = canonical_soundness_certificate_v1(TEST_PROFILE_DIGEST);
        let digest = soundness_certificate_digest_v1(certificate);
        assert_ne!(digest, [0; 32]);
        assert_eq!(
            validate_soundness_certificate_payload_v1(certificate),
            Some(soundness_certificate_digest_v1(certificate))
        );
        assert!(soundness_certificate_matches_pin_v1(certificate, digest));
        assert!(!soundness_certificate_matches_pin_v1(certificate, [0; 32]));
        let mut wrong_pin = digest;
        wrong_pin[0] ^= 0x80;
        assert!(!soundness_certificate_matches_pin_v1(
            certificate,
            wrong_pin
        ));
    }
    #[test]
    fn unavailable_soundness_payload_has_an_independent_exact_hash() {
        let compiled_profile_digest =
            crate::privacy_engines::zk_x509::engine::construct_zk_x509_compiled_profile_v1()
                .expect("compiled X.509 profile")
                .digest();
        let certificate = canonical_soundness_certificate_v1(compiled_profile_digest);
        assert_eq!(
            validate_soundness_certificate_payload_v1(certificate),
            Some(soundness_certificate_digest_v1(certificate))
        );
        let (independent, payload_bytes) =
            independently_digest_soundness_certificate_v1(certificate);
        assert_eq!(SOUNDNESS_CERTIFICATE_FIELD_COUNT_V1, 61);
        assert_eq!(payload_bytes, 714);
        eprintln!(
            "zk-X509 soundness certificate v1 operator derivation: fields={} payload_bytes={} sha256={}",
            SOUNDNESS_CERTIFICATE_FIELD_COUNT_V1,
            payload_bytes,
            hex::encode(independent),
        );
        assert_eq!(soundness_certificate_digest_v1(certificate), independent);
        assert_eq!(ZK_X509_SOUNDNESS_CERTIFICATE_SHA256_V1, [0; 32]);
        assert!(!soundness_certificate_is_pinned_v1(compiled_profile_digest));
    }
    #[test]
    fn every_soundness_certificate_field_is_hashed_and_pinned() {
        let certificate = canonical_soundness_certificate_v1(TEST_PROFILE_DIGEST);
        let digest = soundness_certificate_digest_v1(certificate);
        assert_eq!(
            validate_soundness_certificate_payload_v1(certificate),
            Some(soundness_certificate_digest_v1(certificate))
        );
        macro_rules! reject_mutation {
            ($mutate:expr) => {{
                let mut mutation = certificate;
                ($mutate)(&mut mutation);
                assert_ne!(
                    soundness_certificate_digest_v1(mutation),
                    digest,
                    "mutated soundness field must change the payload digest"
                );
                assert!(
                    !soundness_certificate_matches_pin_v1(mutation, digest),
                    "mutated soundness field must fail the canonical pin"
                );
            }};
        }
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.schema_version += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .compiled_profile_digest[0] ^=
            1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.target_bits += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.round_by_round_bits += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.random_oracle_bits += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .max_random_oracle_query_log2 +=
            1);
        reject_fri_mutations!(certificate, digest, main_fri);
        reject_fri_mutations!(certificate, digest, ca_fri);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.goldilocks_modulus -= 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.rfc_event_bound += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.rfc_relation_count += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.rfc_challenge_lanes += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.p256_factor_bound += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.p256_argument_count += 1);
        reject_mutation!(
            |value: &mut ZkX509SoundnessCertificateV1| value.p256_challenge_lanes += 1
        );
        reject_mutation!(
            |value: &mut ZkX509SoundnessCertificateV1| value.sha_memory_numerator += 1
        );
        reject_mutation!(
            |value: &mut ZkX509SoundnessCertificateV1| value.sha_memory_equalities += 1
        );
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .sha_memory_challenge_lanes +=
            1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.sha_call_numerator += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value.sha_call_equalities += 1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .sha_call_challenge_lanes +=
            1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .sha_base_fold_numerator +=
            1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .sha_base_fold_equalities +=
            1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .sha_base_fold_challenge_lanes +=
            1);
        reject_mutation!(|value: &mut ZkX509SoundnessCertificateV1| value
            .round_by_round_union_terms +=
            1);
    }
    #[test]
    fn resource_certificate_accepts_only_distinct_nonzero_measurements_and_pin() {
        let certificate = test_resource_certificate_v1();
        let digest = validate_resource_certificate_payload_v1(certificate)
            .expect("canonical capture certificate");
        assert_ne!(digest, [0; 32]);
        assert!(resource_certificate_matches_expected_v1(
            certificate,
            certificate,
            digest,
            digest,
        ));
        assert!(!resource_certificate_matches_expected_v1(
            certificate,
            certificate,
            [0; 32],
            digest,
        ));
        assert!(!resource_certificate_matches_expected_v1(
            certificate,
            certificate,
            digest,
            [0; 32],
        ));
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0x80;
        assert!(!resource_certificate_matches_expected_v1(
            certificate,
            certificate,
            wrong_digest,
            digest,
        ));
        for mutation in [
            ZkX509ResourceCertificateV1 {
                positive: ZkX509ResourceObservationV1 {
                    elapsed_millis: 0,
                    ..certificate.positive
                },
                ..certificate
            },
            ZkX509ResourceCertificateV1 {
                positive: ZkX509ResourceObservationV1 {
                    peak_rss_bytes: certificate.process_limits.peak_rss_ceiling_bytes + 1,
                    ..certificate.positive
                },
                ..certificate
            },
            ZkX509ResourceCertificateV1 {
                maximum: ZkX509ResourceObservationV1 {
                    peak_address_space_bytes: certificate
                        .process_limits
                        .address_space_ceiling_bytes
                        + 1,
                    ..certificate.maximum
                },
                ..certificate
            },
            ZkX509ResourceCertificateV1 {
                expectations_json_sha256: certificate.expectations_norito_sha256,
                ..certificate
            },
        ] {
            assert!(validate_resource_certificate_payload_v1(mutation).is_none());
        }
    }
    #[test]
    fn every_resource_certificate_field_is_hashed_and_source_bound() {
        let certificate = test_resource_certificate_v1();
        let digest = validate_resource_certificate_payload_v1(certificate)
            .expect("canonical capture certificate");
        macro_rules! reject_mutation {
            ($mutate:expr) => {{
                let mut mutation = certificate;
                ($mutate)(&mut mutation);
                assert_ne!(
                    resource_certificate_digest_v1(mutation),
                    digest,
                    "mutated resource field must change the payload digest"
                );
                assert!(
                    !resource_certificate_matches_expected_v1(
                        mutation,
                        certificate,
                        resource_certificate_digest_v1(mutation),
                        digest,
                    ),
                    "mutated resource field must fail the installed source and pin"
                );
            }};
        }
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value.schema_version += 1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .compiled_profile_digest[0] ^=
            1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .operating_system =
            "not-linux");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .architecture =
            "x86_64");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .endianness = "big");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .kernel_minimum_major +=
            1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .kernel_minimum_minor +=
            1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .rustc_release =
            "different");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .rustc_host =
            "different");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .rustc_commit_hash =
            "different");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .rustc_commit_date =
            "different");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .instance_type =
            "different");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .cpu_model =
            "different");
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .logical_cpu_count += 1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .online_cpu_count += 1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .environment
            .affinity_cpu_count +=
            1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .expectations_norito_sha256[0] ^=
            1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value
            .expectations_json_sha256[0] ^=
            1);
        reject_mutation!(|value: &mut ZkX509ResourceCertificateV1<'_>| value.kat_proof_bytes += 1);
        reject_mutation!(
            |value: &mut ZkX509ResourceCertificateV1<'_>| value.kat_proof_sha256[0] ^= 1
        );
        reject_process_limit_mutations!(certificate, digest);
        reject_observation_mutations!(certificate, digest, positive);
        reject_observation_mutations!(certificate, digest, maximum);
    }
}
