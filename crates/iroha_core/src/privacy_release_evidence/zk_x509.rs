//! Release stage and authoritative-state verification for zk-X.509.
// This is a private continuation of the parent release-evidence module.
use super::*;
use crate::privacy_engines::zk_x509::{
    engine::construct_zk_x509_compiled_profile_v1,
    profile::{
        ZK_X509_RESOURCE_CERTIFICATE_SCHEMA_VERSION_V1, ZkX509ResourceCertificateV1,
        ZkX509ResourceEnvironmentV1, ZkX509ResourceObservationV1, ZkX509ResourceProcessLimitsV1,
        canonical_resource_environment_v1, canonical_resource_process_limits_v1,
        resource_certificate_matches_source_v1, validate_resource_certificate_payload_v1,
        zk_x509_native_release_expectation_capture_open_v1,
        zk_x509_native_release_expectation_digests_match_v1,
    },
    relation::release_fixture::{
        ZkX509ReleaseFixtureV1, build_zk_x509_network_release_fixture_v1,
        build_zk_x509_network_release_successor_fixture_v1,
    },
};
use iroha_crypto::PrivateKey;
use iroha_data_model::{
    isi::InstructionBox,
    privacy::{
        PrivacyZkX509CertificatePolicyRecordV1, PrivacyZkX509CrlRecordV1,
        PrivacyZkX509TrustAnchorRecordV1,
    },
    transaction::SignedTransaction,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
const ZK_X509_RELEASE_GENESIS_HASH_V1: [u8; 32] = [0x95; 32];
const ZK_X509_RELEASE_ACTION_INDEX_V1: u32 = 0;
/// Canonical native Linux environment bound into the X.509 resource capture.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_release_evidence::zk_x509::PrivacyReleaseZkX509ResourceEnvironmentV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PrivacyReleaseZkX509ResourceEnvironmentV1 {
    /// Exact operating-system family.
    pub operating_system: String,
    /// Exact target architecture.
    pub architecture: String,
    /// Exact target byte order.
    pub endianness: String,
    /// Minimum Linux kernel major version required by the isolation contract.
    pub kernel_minimum_major: u16,
    /// Minimum Linux kernel minor version required by the isolation contract.
    pub kernel_minimum_minor: u16,
    /// Exact `rustc -Vv` release.
    pub rustc_release: String,
    /// Exact `rustc -Vv` host triple.
    pub rustc_host: String,
    /// Exact `rustc -Vv` commit hash.
    pub rustc_commit_hash: String,
    /// Exact `rustc -Vv` commit date.
    pub rustc_commit_date: String,
    /// Exact native instance type.
    pub instance_type: String,
    /// Exact native CPU model.
    pub cpu_model: String,
    /// Exact logical processor count.
    pub logical_cpu_count: u16,
    /// Exact online processor count.
    pub online_cpu_count: u16,
    /// Exact processor-affinity count.
    pub affinity_cpu_count: u16,
}
/// Reviewed native process ceilings and isolation capabilities.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_release_evidence::zk_x509::PrivacyReleaseZkX509ResourceProcessLimitsV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PrivacyReleaseZkX509ResourceProcessLimitsV1 {
    /// Reviewed wall-clock ceiling, in milliseconds.
    pub elapsed_ceiling_millis: u64,
    /// Reviewed peak resident-set ceiling, in bytes.
    pub peak_rss_ceiling_bytes: u64,
    /// Reviewed virtual-address-space ceiling, in bytes.
    pub address_space_ceiling_bytes: u64,
    /// Exact main-thread stack limit.
    pub main_thread_stack_bytes: u64,
    /// Exact Rayon-worker stack limit.
    pub rayon_worker_stack_bytes: u64,
    /// Exact watchdog-thread stack limit.
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
    /// Minimum effective cgroup memory headroom.
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
/// One exact native measurement, distinct from reviewed process ceilings.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_release_evidence::zk_x509::PrivacyReleaseZkX509ResourceObservationV1"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PrivacyReleaseZkX509ResourceObservationV1 {
    /// Exact release case measured by this observation.
    pub case_kind: PrivacyReleaseCaseKindV1,
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
/// Typed, canonical capture artifact for the X.509 native-resource certificate.
///
/// The certificate digest authenticates this payload but is not itself hashed,
/// avoiding a self-reference. Source, executable, command-manifest, and final
/// receipt digests are deliberately absent.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_release_evidence::zk_x509::PrivacyReleaseZkX509ResourceCertificateV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct PrivacyReleaseZkX509ResourceCertificateV1 {
    /// Certificate schema version.
    pub schema_version: u16,
    /// Closed protocol identity.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Digest of the exact compiled X.509 profile.
    pub compiled_profile_digest: [u8; 32],
    /// Exact native environment identity.
    pub environment: PrivacyReleaseZkX509ResourceEnvironmentV1,
    /// SHA-256 of the authoritative expectations Norito bytes.
    pub expectations_norito_sha256: [u8; 32],
    /// SHA-256 of the typed-equal expectations JSON bytes.
    pub expectations_json_sha256: [u8; 32],
    /// Exact encoded byte length of the deterministic X5S1 KAT.
    pub kat_proof_bytes: u32,
    /// SHA-256 of the deterministic X5S1 KAT.
    pub kat_proof_sha256: [u8; 32],
    /// Reviewed process ceilings and isolation requirements.
    pub process_limits: PrivacyReleaseZkX509ResourceProcessLimitsV1,
    /// Exact positive-stage native observation.
    pub positive: PrivacyReleaseZkX509ResourceObservationV1,
    /// Exact maximum-shape native observation.
    pub maximum: PrivacyReleaseZkX509ResourceObservationV1,
    /// SHA-256 of the domain-separated typed payload above.
    pub certificate_sha256: [u8; 32],
}
/// One genuine native X.509 action and a separately signed malformed proof.
///
/// This non-shipping release-gate value exposes only ordinary production transactions and their
/// public governance inputs. Certificate, CRL, ownership-signature, and disclosure-opening witness
/// bytes remain inside `iroha_core`.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseZkX509NetworkActionsV1 {
    /// Ordinary production transaction carrying a valid native X5S1 proof.
    pub canonical_transaction: SignedTransaction,
    /// Independently signed transaction whose proof magic is corrupted.
    pub malformed_transaction: SignedTransaction,
    /// Exact trust-anchor origin required by the canonical statement.
    pub trust_anchor: PrivacyZkX509TrustAnchorRecordV1,
    /// Exact certificate-policy origin required by the canonical statement.
    pub certificate_policy: PrivacyZkX509CertificatePolicyRecordV1,
    /// Exact signed-CRL origin required by the canonical statement.
    pub crl: PrivacyZkX509CrlRecordV1,
    /// Exact public statement carried by the canonical and malformed transactions.
    pub statement: IrohaZkX509StarkP256StatementV1,
}
/// One independently proved post-restart action and its signed CRL successor.
///
/// This remains ordinary non-shipping release-gate material. It carries no
/// timing, memory, readiness, or operational-authority claim.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseZkX509SemanticReplayV1 {
    /// Ordinary production transaction carrying the fresh native X5S1 proof.
    pub transaction: SignedTransaction,
    /// Exact active CRL successor selected by the fresh statement.
    pub crl_successor: PrivacyZkX509CrlRecordV1,
    /// Exact public statement carried by `transaction`.
    pub statement: IrohaZkX509StarkP256StatementV1,
}
fn public_resource_environment_v1(
    environment: ZkX509ResourceEnvironmentV1<'_>,
) -> PrivacyReleaseZkX509ResourceEnvironmentV1 {
    PrivacyReleaseZkX509ResourceEnvironmentV1 {
        operating_system: environment.operating_system.to_owned(),
        architecture: environment.architecture.to_owned(),
        endianness: environment.endianness.to_owned(),
        kernel_minimum_major: environment.kernel_minimum_major,
        kernel_minimum_minor: environment.kernel_minimum_minor,
        rustc_release: environment.rustc_release.to_owned(),
        rustc_host: environment.rustc_host.to_owned(),
        rustc_commit_hash: environment.rustc_commit_hash.to_owned(),
        rustc_commit_date: environment.rustc_commit_date.to_owned(),
        instance_type: environment.instance_type.to_owned(),
        cpu_model: environment.cpu_model.to_owned(),
        logical_cpu_count: environment.logical_cpu_count,
        online_cpu_count: environment.online_cpu_count,
        affinity_cpu_count: environment.affinity_cpu_count,
    }
}
fn public_resource_process_limits_v1(
    limits: ZkX509ResourceProcessLimitsV1,
) -> PrivacyReleaseZkX509ResourceProcessLimitsV1 {
    PrivacyReleaseZkX509ResourceProcessLimitsV1 {
        elapsed_ceiling_millis: limits.elapsed_ceiling_millis,
        peak_rss_ceiling_bytes: limits.peak_rss_ceiling_bytes,
        address_space_ceiling_bytes: limits.address_space_ceiling_bytes,
        main_thread_stack_bytes: limits.main_thread_stack_bytes,
        rayon_worker_stack_bytes: limits.rayon_worker_stack_bytes,
        watchdog_thread_stack_bytes: limits.watchdog_thread_stack_bytes,
        rayon_worker_count: limits.rayon_worker_count,
        max_stage_tasks: limits.max_stage_tasks,
        max_stage_open_files: limits.max_stage_open_files,
        core_dump_bytes: limits.core_dump_bytes,
        landlock_abi_minimum: limits.landlock_abi_minimum,
        minimum_effective_memory_bytes: limits.minimum_effective_memory_bytes,
        cgroup_v2: limits.cgroup_v2,
        cpu_quota_unlimited: limits.cpu_quota_unlimited,
        landlock_restrict_self: limits.landlock_restrict_self,
        anchored_openat2: limits.anchored_openat2,
        memfd_exec: limits.memfd_exec,
        memfd_seal_exec: limits.memfd_seal_exec,
        static_elf_only: limits.static_elf_only,
        seccomp_tsync: limits.seccomp_tsync,
    }
}
fn private_resource_certificate_v1(
    certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
) -> Option<ZkX509ResourceCertificateV1<'_>> {
    let case_kind = |case: PrivacyReleaseCaseKindV1| match case {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd => Some(0),
        PrivacyReleaseCaseKindV1::MaximumShapeResource => Some(3),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation
        | PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => None,
    };
    let observation = |value: PrivacyReleaseZkX509ResourceObservationV1| {
        Some(ZkX509ResourceObservationV1 {
            case_kind: case_kind(value.case_kind)?,
            elapsed_millis: value.elapsed_millis,
            peak_rss_bytes: value.peak_rss_bytes,
            peak_address_space_bytes: value.peak_address_space_bytes,
            primary_units: value.primary_units,
            primary_ceiling: value.primary_ceiling,
            secondary_units: value.secondary_units,
            secondary_ceiling: value.secondary_ceiling,
            relation_depth: value.relation_depth,
            relation_depth_ceiling: value.relation_depth_ceiling,
        })
    };
    Some(ZkX509ResourceCertificateV1 {
        schema_version: certificate.schema_version,
        compiled_profile_digest: certificate.compiled_profile_digest,
        environment: ZkX509ResourceEnvironmentV1 {
            operating_system: &certificate.environment.operating_system,
            architecture: &certificate.environment.architecture,
            endianness: &certificate.environment.endianness,
            kernel_minimum_major: certificate.environment.kernel_minimum_major,
            kernel_minimum_minor: certificate.environment.kernel_minimum_minor,
            rustc_release: &certificate.environment.rustc_release,
            rustc_host: &certificate.environment.rustc_host,
            rustc_commit_hash: &certificate.environment.rustc_commit_hash,
            rustc_commit_date: &certificate.environment.rustc_commit_date,
            instance_type: &certificate.environment.instance_type,
            cpu_model: &certificate.environment.cpu_model,
            logical_cpu_count: certificate.environment.logical_cpu_count,
            online_cpu_count: certificate.environment.online_cpu_count,
            affinity_cpu_count: certificate.environment.affinity_cpu_count,
        },
        expectations_norito_sha256: certificate.expectations_norito_sha256,
        expectations_json_sha256: certificate.expectations_json_sha256,
        kat_proof_bytes: certificate.kat_proof_bytes,
        kat_proof_sha256: certificate.kat_proof_sha256,
        process_limits: ZkX509ResourceProcessLimitsV1 {
            elapsed_ceiling_millis: certificate.process_limits.elapsed_ceiling_millis,
            peak_rss_ceiling_bytes: certificate.process_limits.peak_rss_ceiling_bytes,
            address_space_ceiling_bytes: certificate.process_limits.address_space_ceiling_bytes,
            main_thread_stack_bytes: certificate.process_limits.main_thread_stack_bytes,
            rayon_worker_stack_bytes: certificate.process_limits.rayon_worker_stack_bytes,
            watchdog_thread_stack_bytes: certificate.process_limits.watchdog_thread_stack_bytes,
            rayon_worker_count: certificate.process_limits.rayon_worker_count,
            max_stage_tasks: certificate.process_limits.max_stage_tasks,
            max_stage_open_files: certificate.process_limits.max_stage_open_files,
            core_dump_bytes: certificate.process_limits.core_dump_bytes,
            landlock_abi_minimum: certificate.process_limits.landlock_abi_minimum,
            minimum_effective_memory_bytes: certificate
                .process_limits
                .minimum_effective_memory_bytes,
            cgroup_v2: certificate.process_limits.cgroup_v2,
            cpu_quota_unlimited: certificate.process_limits.cpu_quota_unlimited,
            landlock_restrict_self: certificate.process_limits.landlock_restrict_self,
            anchored_openat2: certificate.process_limits.anchored_openat2,
            memfd_exec: certificate.process_limits.memfd_exec,
            memfd_seal_exec: certificate.process_limits.memfd_seal_exec,
            static_elf_only: certificate.process_limits.static_elf_only,
            seccomp_tsync: certificate.process_limits.seccomp_tsync,
        },
        positive: observation(certificate.positive)?,
        maximum: observation(certificate.maximum)?,
    })
}
/// Build and digest a structurally valid native capture before source pinning.
///
/// # Errors
///
/// Returns an error if the compiled profile is unavailable or the supplied observations and
/// authenticated pins do not form a valid resource-certificate payload.
pub fn build_privacy_release_zk_x509_resource_certificate_v1(
    environment: PrivacyReleaseZkX509ResourceEnvironmentV1,
    expectations_norito_sha256: [u8; 32],
    expectations_json_sha256: [u8; 32],
    kat_proof_bytes: u32,
    kat_proof_sha256: [u8; 32],
    positive: PrivacyReleaseZkX509ResourceObservationV1,
    maximum: PrivacyReleaseZkX509ResourceObservationV1,
) -> Result<PrivacyReleaseZkX509ResourceCertificateV1, PrivacyReleaseEvidenceErrorClassV1> {
    let compiled_profile_digest = construct_zk_x509_compiled_profile_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable)?
        .digest();
    let mut certificate = PrivacyReleaseZkX509ResourceCertificateV1 {
        schema_version: ZK_X509_RESOURCE_CERTIFICATE_SCHEMA_VERSION_V1,
        protocol_id: PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        compiled_profile_digest,
        environment,
        expectations_norito_sha256,
        expectations_json_sha256,
        kat_proof_bytes,
        kat_proof_sha256,
        process_limits: public_resource_process_limits_v1(canonical_resource_process_limits_v1()),
        positive,
        maximum,
        certificate_sha256: [0; 32],
    };
    let payload = private_resource_certificate_v1(&certificate)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    certificate.certificate_sha256 = validate_resource_certificate_payload_v1(payload)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    Ok(certificate)
}
/// Return the exact canonical environment expected by the capture API.
#[must_use]
pub fn privacy_release_zk_x509_resource_environment_v1() -> PrivacyReleaseZkX509ResourceEnvironmentV1
{
    public_resource_environment_v1(canonical_resource_environment_v1())
}
/// Validate a typed capture against the current profile and KAT source pins.
#[must_use]
pub fn validate_privacy_release_zk_x509_resource_capture_v1(
    certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
) -> bool {
    if certificate.protocol_id != PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 {
        return false;
    }
    let Ok(compiled_profile) = construct_zk_x509_compiled_profile_v1() else {
        return false;
    };
    if certificate.compiled_profile_digest != compiled_profile.digest() {
        return false;
    }
    private_resource_certificate_v1(certificate)
        .and_then(validate_resource_certificate_payload_v1)
        .is_some_and(|digest| digest == certificate.certificate_sha256)
}
/// Validate a typed capture against every installed source field and pin.
#[must_use]
pub fn privacy_release_zk_x509_resource_certificate_matches_source_v1(
    certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
) -> bool {
    validate_privacy_release_zk_x509_resource_capture_v1(certificate)
        && private_resource_certificate_v1(certificate).is_some_and(|payload| {
            resource_certificate_matches_source_v1(payload, certificate.certificate_sha256)
        })
}
/// Whether the one-time native release capture corridor remains open.
///
/// Any populated KAT, expectation, resource-certificate, or observation pin
/// closes capture permanently. A partial source write therefore fails closed
/// rather than allowing a second capture.
pub const fn privacy_release_expectation_capture_open_v1() -> bool {
    zk_x509_native_release_expectation_capture_open_v1()
}
/// Whether a loaded native expectation pair matches both compiled pins.
pub const fn privacy_release_expectation_fixture_matches_v1(
    norito_sha256: [u8; 32],
    json_sha256: [u8; 32],
) -> bool {
    zk_x509_native_release_expectation_digests_match_v1(norito_sha256, json_sha256)
}
/// Return the canonical fixed process profile for `protocol_id`, when present.
///
/// `None` means that the protocol uses the release runner's generic reviewed stage limits. A
/// returned profile is exact rather than merely an upper bound: every case for that protocol must
/// carry the same wall-time, peak-RSS, and address-space values.
pub const fn privacy_release_process_profile_v1(
    protocol_id: PrivacyProtocolIdV1,
) -> Option<PrivacyReleaseProcessProfileV1> {
    match protocol_id {
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1 => {
            let elapsed_ceiling_millis = match ZK_X509_PROVER_TARGET_SECONDS_V1.checked_mul(1_000) {
                Some(value) => value,
                None => panic!("zk-X509 release target milliseconds overflow u64"),
            };
            Some(PrivacyReleaseProcessProfileV1 {
                protocol_id,
                elapsed_ceiling_millis,
                peak_rss_ceiling_bytes: ZK_X509_PROVER_PEAK_MEMORY_BYTES_V1,
                address_space_ceiling_bytes: ZK_X509_PROVER_ADDRESS_SPACE_CEILING_BYTES_V1,
            })
        }
        _ => None,
    }
}
fn zk_x509_network_transaction_payload_v1(
    context: &PrivacyReleaseTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, PrivacyReleaseEvidenceErrorClassV1> {
    if context.network_id.as_bytes() != &context.genesis_hash {
        return Err(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed);
    }
    let instructions = vec![InstructionBox::from(SubmitPrivacyProofV1::new(envelope))];
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_instructions(instructions)
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(time_to_live) = context.time_to_live {
        builder.set_ttl(time_to_live);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
}
fn zk_x509_network_envelope_v1(
    profile: CompiledPrivacyProfileV1,
    statement: &IrohaZkX509StarkP256StatementV1,
    proof: Vec<u8>,
) -> Result<PrivacyProofEnvelopeV1, PrivacyReleaseEvidenceErrorClassV1> {
    let typed_statement = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone());
    let envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(proof)),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if !profile.matches_envelope_v1(&envelope) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    Ok(envelope)
}
fn sign_zk_x509_network_payload_v1(
    payload: TransactionPayload,
    expected_intent: PrivacyTransactionIntentDigestV1,
    private_key: &PrivateKey,
) -> Result<SignedTransaction, PrivacyReleaseEvidenceErrorClassV1> {
    if payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
        != expected_intent
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let transaction = TransactionBuilder::from_payload(payload)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?
        .try_sign(private_key)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    transaction
        .verify_signature()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    Ok(transaction)
}
/// Authenticate and return the reviewed wall-clock ceiling for one native proof.
///
/// The network path runs one genuine positive-shape proof. It does not infer a
/// second-proof, process-RSS, or address-space measurement from the installed
/// positive observation; those remain properties of the authenticated native
/// resource capture rather than measurements made by this in-process builder.
fn zk_x509_network_proof_ceiling_v1(
    certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
    admission_reserve: Duration,
) -> Result<Duration, PrivacyReleaseEvidenceErrorClassV1> {
    if !privacy_release_zk_x509_resource_certificate_matches_source_v1(certificate) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable);
    }
    let ceiling_millis = certificate.process_limits.elapsed_ceiling_millis;
    let admission_reserve_millis = u64::try_from(admission_reserve.as_millis())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?;
    let Some(proof_ceiling_millis) = ceiling_millis.checked_sub(admission_reserve_millis) else {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded);
    };
    if admission_reserve_millis == 0
        || proof_ceiling_millis == 0
        || certificate.positive.elapsed_millis == 0
        || certificate.positive.elapsed_millis > proof_ceiling_millis
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded);
    }
    Ok(Duration::from_millis(proof_ceiling_millis))
}
fn zk_x509_network_window_has_reserve_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    trusted_block_timestamp_ms: u64,
    build_elapsed: Duration,
    admission_reserve: Duration,
) -> Result<bool, PrivacyReleaseEvidenceErrorClassV1> {
    let build_elapsed_millis = u64::try_from(build_elapsed.as_millis())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?;
    let admission_reserve_millis = u64::try_from(admission_reserve.as_millis())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?;
    if admission_reserve_millis == 0 {
        return Ok(false);
    }
    // TODO(X.6): take this deadline from the canonical interval definition
    // (`statement.presentation_window().last_admissible_block_timestamp_ms()`
    // plus one). It is the same value on every input; the lines below are
    // pinned as a `deferred` site in
    // specs/zk_x509_presentation_interval_sites.json and compared with the
    // definition by `deferred_sites_equal_the_canonical_definition_on_a_boundary_grid`.
    let deadline_exclusive_millis = statement
        .presentation_not_after_unix_seconds
        .checked_add(1)
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let estimated_finish_with_reserve = trusted_block_timestamp_ms
        .checked_add(build_elapsed_millis)
        .and_then(|millis| millis.checked_add(admission_reserve_millis))
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?;
    let actual_wall_millis = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?
            .as_millis(),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?;
    let actual_finish_with_reserve = actual_wall_millis
        .checked_add(admission_reserve_millis)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded)?;
    Ok(estimated_finish_with_reserve <= deadline_exclusive_millis
        && actual_finish_with_reserve <= deadline_exclusive_millis)
}
fn prove_zk_x509_network_fixture_v1(
    profile: CompiledPrivacyProfileV1,
    fixture: &ZkX509ReleaseFixtureV1,
    trusted_block_timestamp_ms: u64,
    genesis_hash: [u8; 32],
    expected_action_index: u32,
    proof_seed: [u8; 32],
) -> Result<Vec<u8>, PrivacyReleaseEvidenceErrorClassV1> {
    let encoded_witness = fixture
        .witness
        .encode_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let mut proof_rng = StdRng::from_seed(proof_seed);
    let proof = std::thread::scope(|scope| {
        let proof_thread = std::thread::Builder::new()
            .name(format!(
                "zk-x509-release-network-action-{expected_action_index}"
            ))
            .stack_size(PRIVACY_RELEASE_STAGE_STACK_BYTES_V1)
            .spawn_scoped(scope, || {
                prove_zk_x509_credential_proof_v1_with_rng(
                    &fixture.statement,
                    &fixture.authoritative_state,
                    trusted_block_timestamp_ms,
                    &limits,
                    genesis_hash,
                    &encoded_witness,
                    &mut proof_rng,
                )
            })
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
        proof_thread
            .join()
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)
    })?;
    verify_zk_x509_credential_proof_v1(
        &fixture.statement,
        &fixture.authoritative_state,
        genesis_hash,
        &proof,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    verify_zk_x509_release_production_envelope_v1(
        &profile,
        &fixture.statement,
        Some(&fixture.authoritative_state),
        false,
        &proof,
        &fixture.statement.context.network_id,
        genesis_hash,
        expected_action_index,
        trusted_block_timestamp_ms,
    )?;
    Ok(proof)
}
fn zk_x509_network_statement_context_v1(
    profile: CompiledPrivacyProfileV1,
    network_id: NetworkId,
    action_index: u32,
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
) -> PrivacyStatementContextV1 {
    PrivacyStatementContextV1 {
        network_id,
        action_index,
        transaction_intent_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    }
}
fn zk_x509_network_draft_envelope_v1(
    profile: CompiledPrivacyProfileV1,
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<PrivacyProofEnvelopeV1, PrivacyReleaseEvidenceErrorClassV1> {
    let envelope = PrivacyProofEnvelopeV1::bind_v1(
        PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone()),
        PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(Vec::new())),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if !profile.matches_envelope_v1(&envelope) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(envelope)
}
/// Build one genuine canonical X.509 action and a corruption control.
///
/// The production compiled-profile accessor is deliberately the first gate.
/// Until every authenticated expectation and resource pin is installed this
/// function returns [`PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable`]
/// and cannot expose unqualified profile material as a network action.
///
/// `resource_certificate` must be the canonical installed certificate and must match every
/// authenticated source pin. The authenticated process ceiling is reduced by `admission_reserve`,
/// which must be nonzero and must fit after the authenticated positive observation. The resulting
/// proof ceiling and the live statement deadline are enforced against this call's actual elapsed
/// time. This builder does not invent or record RSS, address-space, or second-proof measurements.
///
/// The caller must pass an actual committed block timestamp and submit the
/// returned action within the closed five-minute presentation window.
///
/// # Errors
///
/// Returns an error if the compiled profile or resource certificate is unavailable or invalid,
/// context validation, proving, verification, or signing fails, the time budget is exceeded,
/// or the verifier accepts the deliberately corrupted proof.
pub fn build_privacy_release_zk_x509_network_actions_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    trusted_block_timestamp_ms: u64,
    proof_seed: [u8; 32],
    resource_certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
    admission_reserve: Duration,
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseZkX509NetworkActionsV1, PrivacyReleaseEvidenceErrorClassV1> {
    let build_started = Instant::now();
    let PreparedZkX509NetworkActionV1 {
        profile,
        fixture,
        proof,
        intent,
        transaction: canonical_transaction,
    } = prepare_zk_x509_network_action_v1(
        &transaction_context,
        trusted_block_timestamp_ms,
        proof_seed,
        resource_certificate,
        admission_reserve,
        private_key,
        &ZkX509NetworkCrlLineageV1::Origin,
        &build_started,
    )?;
    let mut malformed_proof = proof;
    let magic = malformed_proof
        .first_mut()
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    *magic ^= 0x80;
    if verify_zk_x509_credential_proof_v1(
        &fixture.statement,
        &fixture.authoritative_state,
        transaction_context.genesis_hash,
        &malformed_proof,
    )
    .is_ok()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
    }
    let malformed_payload = zk_x509_network_transaction_payload_v1(
        &transaction_context,
        zk_x509_network_envelope_v1(profile, &fixture.statement, malformed_proof)?,
    )?;
    let malformed_transaction =
        sign_zk_x509_network_payload_v1(malformed_payload, intent, private_key)?;
    if malformed_transaction.hash() == canonical_transaction.hash() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    if !zk_x509_network_window_has_reserve_v1(
        &fixture.statement,
        trusted_block_timestamp_ms,
        build_started.elapsed(),
        admission_reserve,
    )? {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded);
    }
    Ok(PrivacyReleaseZkX509NetworkActionsV1 {
        canonical_transaction,
        malformed_transaction,
        trust_anchor: fixture.authoritative_state.trust_anchor(),
        certificate_policy: fixture.authoritative_state.certificate_policy().clone(),
        crl: fixture.authoritative_state.crl_record(),
        statement: fixture.statement,
    })
}
/// Build one fresh semantic replay against a newly signed active CRL successor.
///
/// This invokes exactly one independent native prover run with its own authenticated proof ceiling
/// and `admission_reserve`. The supplied current CRL is used only to derive and validate the exact
/// epoch, CRLNumber, and predecessor-digest transition. No pair-time or process-memory observation
/// is produced.
///
/// # Errors
///
/// Returns an error if the compiled profile, resource certificate, context, or CRL successor is
/// invalid, proving, verification, or signing fails, or the proof and admission time budget is exceeded.
#[allow(clippy::too_many_arguments)]
pub fn build_privacy_release_zk_x509_semantic_replay_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    trusted_block_timestamp_ms: u64,
    current_crl: PrivacyZkX509CrlRecordV1,
    proof_seed: [u8; 32],
    resource_certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
    admission_reserve: Duration,
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseZkX509SemanticReplayV1, PrivacyReleaseEvidenceErrorClassV1> {
    let build_started = Instant::now();
    let prepared = prepare_zk_x509_network_action_v1(
        &transaction_context,
        trusted_block_timestamp_ms,
        proof_seed,
        resource_certificate,
        admission_reserve,
        private_key,
        &ZkX509NetworkCrlLineageV1::Successor(current_crl),
        &build_started,
    )?;
    Ok(PrivacyReleaseZkX509SemanticReplayV1 {
        transaction: prepared.transaction,
        crl_successor: prepared.fixture.authoritative_state.crl_record(),
        statement: prepared.fixture.statement,
    })
}
#[derive(Clone)]
enum ZkX509NetworkCrlLineageV1 {
    Origin,
    Successor(PrivacyZkX509CrlRecordV1),
}
struct PreparedZkX509NetworkActionV1 {
    profile: CompiledPrivacyProfileV1,
    fixture: ZkX509ReleaseFixtureV1,
    proof: Vec<u8>,
    intent: PrivacyTransactionIntentDigestV1,
    transaction: SignedTransaction,
}
#[allow(clippy::too_many_arguments)]
fn prepare_zk_x509_network_action_v1(
    transaction_context: &PrivacyReleaseTransactionContextV1,
    trusted_block_timestamp_ms: u64,
    proof_seed: [u8; 32],
    resource_certificate: &PrivacyReleaseZkX509ResourceCertificateV1,
    admission_reserve: Duration,
    private_key: &PrivateKey,
    crl_lineage: &ZkX509NetworkCrlLineageV1,
    build_started: &Instant,
) -> Result<PreparedZkX509NetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
    let profile = compiled_privacy_profile_v1(protocol_id)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable)?;
    if transaction_context.network_id.as_bytes() != &transaction_context.genesis_hash
        || transaction_context.nonce.is_none()
        || proof_seed.iter().all(|byte| *byte == 0)
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed);
    }
    let draft_context = zk_x509_network_statement_context_v1(
        profile,
        transaction_context.network_id,
        ZK_X509_RELEASE_ACTION_INDEX_V1,
        PrivacyTransactionIntentDigestV1::new([0; 32]),
    );
    let draft_fixture = build_zk_x509_network_fixture_for_lineage_v1(
        draft_context,
        trusted_block_timestamp_ms,
        transaction_context.authority.clone(),
        crl_lineage,
    )?;
    if draft_fixture.statement.wallet_account != transaction_context.authority {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let intent = zk_x509_network_transaction_payload_v1(
        transaction_context,
        zk_x509_network_draft_envelope_v1(profile, &draft_fixture.statement)?,
    )?
    .privacy_transaction_intent_digest_v1()
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if intent.is_zero() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut final_context = draft_context;
    final_context.transaction_intent_digest = intent;
    let fixture = build_zk_x509_network_fixture_for_lineage_v1(
        final_context,
        trusted_block_timestamp_ms,
        transaction_context.authority.clone(),
        crl_lineage,
    )?;
    if fixture.statement.wallet_account != transaction_context.authority
        || fixture.authoritative_state.crl_record()
            != draft_fixture.authoritative_state.crl_record()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let proof_ceiling = zk_x509_network_proof_ceiling_v1(resource_certificate, admission_reserve)?;
    let proof_started = Instant::now();
    let proof = prove_zk_x509_network_fixture_v1(
        profile,
        &fixture,
        trusted_block_timestamp_ms,
        transaction_context.genesis_hash,
        ZK_X509_RELEASE_ACTION_INDEX_V1,
        proof_seed,
    )?;
    if proof_started.elapsed() > proof_ceiling {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded);
    }
    let canonical_payload = zk_x509_network_transaction_payload_v1(
        transaction_context,
        zk_x509_network_envelope_v1(profile, &fixture.statement, proof.clone())?,
    )?;
    let transaction = sign_zk_x509_network_payload_v1(canonical_payload, intent, private_key)?;
    if !zk_x509_network_window_has_reserve_v1(
        &fixture.statement,
        trusted_block_timestamp_ms,
        build_started.elapsed(),
        admission_reserve,
    )? {
        return Err(PrivacyReleaseEvidenceErrorClassV1::ResourceCeilingExceeded);
    }
    Ok(PreparedZkX509NetworkActionV1 {
        profile,
        fixture,
        proof,
        intent,
        transaction,
    })
}
fn build_zk_x509_network_fixture_for_lineage_v1(
    context: PrivacyStatementContextV1,
    trusted_block_timestamp_ms: u64,
    wallet_account: AccountId,
    crl_lineage: &ZkX509NetworkCrlLineageV1,
) -> Result<ZkX509ReleaseFixtureV1, PrivacyReleaseEvidenceErrorClassV1> {
    match crl_lineage {
        ZkX509NetworkCrlLineageV1::Origin => build_zk_x509_network_release_fixture_v1(
            context,
            trusted_block_timestamp_ms,
            wallet_account,
        ),
        ZkX509NetworkCrlLineageV1::Successor(current_crl) => {
            build_zk_x509_network_release_successor_fixture_v1(
                context,
                trusted_block_timestamp_ms,
                wallet_account,
                (*current_crl).clone(),
            )
        }
    }
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)
}
struct PreparedZkX509StageV1 {
    profile: CompiledPrivacyProfileV1,
    fixture: crate::privacy_engines::zk_x509::relation::release_fixture::ZkX509ReleaseFixtureV1,
    trusted_block_timestamp_ms: u64,
    proof: Vec<u8>,
}
fn prepare_zk_x509_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<PreparedZkX509StageV1, PrivacyReleaseEvidenceErrorClassV1> {
    let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
    let profile = compiled_privacy_profile_v1(protocol_id).map_err(|error| match error {
        crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
            protocol_id: unavailable,
        } if unavailable == protocol_id => PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
        _ => PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed,
    })?;
    let context =
        PrivacyStatementContextV1 {
            network_id: release_network_id_from_genesis_hash(ZK_X509_RELEASE_GENESIS_HASH_V1),
            action_index: ZK_X509_RELEASE_ACTION_INDEX_V1,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(
                stage_purpose_seed_v1(protocol_id, case_kind, b"transaction-intent")?,
            ),
            parameter_id: profile.parameter_id,
            parameter_digest: profile.parameter_digest,
            verifier_digest: profile.verifier_digest,
            statement_schema_digest: profile.statement_schema_digest,
            engine_manifest_digest: profile.engine_manifest_digest,
        };
    let maximum = case_kind == PrivacyReleaseCaseKindV1::MaximumShapeResource;
    let fixture = build_zk_x509_release_fixture_v1(context, maximum)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let encoded_witness = fixture
        .witness
        .encode_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let trusted_block_timestamp_ms = fixture
        .statement
        .presentation_not_before_unix_seconds
        .checked_mul(1_000)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let mut proof_rng = StdRng::from_seed(stage_purpose_seed_v1(
        protocol_id,
        case_kind,
        b"canonical-x5s1-proof",
    )?);
    let proof = prove_zk_x509_credential_proof_v1_with_rng(
        &fixture.statement,
        &fixture.authoritative_state,
        trusted_block_timestamp_ms,
        &limits,
        ZK_X509_RELEASE_GENESIS_HASH_V1,
        &encoded_witness,
        &mut proof_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    verify_zk_x509_credential_proof_v1(
        &fixture.statement,
        &fixture.authoritative_state,
        ZK_X509_RELEASE_GENESIS_HASH_V1,
        &proof,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    verify_zk_x509_release_production_envelope_v1(
        &profile,
        &fixture.statement,
        Some(&fixture.authoritative_state),
        false,
        &proof,
        &release_network_id_from_genesis_hash(ZK_X509_RELEASE_GENESIS_HASH_V1),
        ZK_X509_RELEASE_GENESIS_HASH_V1,
        ZK_X509_RELEASE_ACTION_INDEX_V1,
        trusted_block_timestamp_ms,
    )?;
    Ok(PreparedZkX509StageV1 {
        profile,
        fixture,
        trusted_block_timestamp_ms,
        proof,
    })
}
pub(super) fn run_zk_x509_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let PreparedZkX509StageV1 {
        profile,
        fixture,
        trusted_block_timestamp_ms,
        proof,
    } = prepare_zk_x509_stage_v1(case_kind)?;
    let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
    let resources = PrivacyReleaseResourceFactsV1 {
        primary_units: u64::try_from(fixture.witness.certificate_chain_len_v1())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        primary_ceiling: u64::try_from(ZK_X509_MAX_CHAIN_DEPTH_V1)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        secondary_units: u64::try_from(fixture.statement.disclosed_attributes.len())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        secondary_ceiling: u64::try_from(ZK_X509_MAX_DISCLOSED_ATTRIBUTES_V1)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        relation_depth: u64::try_from(fixture.crl_entry_count)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
        relation_depth_ceiling: u64::try_from(ZK_X509_MAX_CRL_ENTRIES_V1)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
    };
    if Some(resources) != privacy_release_resource_facts_v1(protocol_id, case_kind) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let typed_statement = PrivacyStatementV1::IrohaZkX509StarkP256V1(fixture.statement.clone());
    let original_material = norito::encode_canonical(&typed_statement)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let authoritative_network_id =
        release_network_id_from_genesis_hash(ZK_X509_RELEASE_GENESIS_HASH_V1);
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            original_material,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut wrong_intent = fixture.statement.clone();
            wrong_intent.context.transaction_intent_digest.0[0] ^= 0x80;
            let mut wrong_parameter_id = fixture.statement.clone();
            wrong_parameter_id.context.parameter_id.0[0] ^= 0x80;
            let mut wrong_parameter_digest = fixture.statement.clone();
            wrong_parameter_digest.context.parameter_digest.0[0] ^= 0x80;
            let mut wrong_verifier_digest = fixture.statement.clone();
            wrong_verifier_digest.context.verifier_digest.0[0] ^= 0x80;
            let mut wrong_schema_digest = fixture.statement.clone();
            wrong_schema_digest.context.statement_schema_digest.0[0] ^= 0x80;
            let mut wrong_manifest_digest = fixture.statement.clone();
            wrong_manifest_digest.context.engine_manifest_digest.0[0] ^= 0x80;
            let mut wrong_record = fixture.statement.clone();
            wrong_record.trust_anchor_record_digest.0[0] ^= 0x80;
            let mut wrong_root = fixture.statement.clone();
            wrong_root.ca_membership_root.0[0] ^= 0x80;
            let mut wrong_disclosure = fixture.statement.clone();
            wrong_disclosure.disclosed_attributes[0].attribute_digest.0[0] ^= 0x80;
            let mut wrong_challenge = fixture.statement.clone();
            wrong_challenge.wallet_challenge.0[0] ^= 0x80;
            let mut wrong_network = fixture.statement.clone();
            wrong_network.context.network_id = release_network_id_from_genesis_hash([0x96; 32]);
            let mut wrong_action = fixture.statement.clone();
            wrong_action.context.action_index = wrong_action
                .context
                .action_index
                .checked_add(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let mutations = [
                &wrong_intent,
                &wrong_parameter_id,
                &wrong_parameter_digest,
                &wrong_verifier_digest,
                &wrong_schema_digest,
                &wrong_manifest_digest,
                &wrong_record,
                &wrong_root,
                &wrong_disclosure,
                &wrong_challenge,
                &wrong_network,
                &wrong_action,
            ];
            for mutation in mutations {
                if verify_zk_x509_credential_proof_v1(
                    mutation,
                    &fixture.authoritative_state,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    &proof,
                )
                .is_ok()
                    || verify_zk_x509_release_production_envelope_v1(
                        &profile,
                        mutation,
                        Some(&fixture.authoritative_state),
                        false,
                        &proof,
                        &authoritative_network_id,
                        ZK_X509_RELEASE_GENESIS_HASH_V1,
                        ZK_X509_RELEASE_ACTION_INDEX_V1,
                        trusted_block_timestamp_ms,
                    )
                    .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            let envelope_mutations: [fn(&mut PrivacyProofEnvelopeV1); 9] = [
                |envelope| {
                    envelope.protocol_id = PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1;
                },
                |envelope| {
                    envelope.proof_system_id = PrivacyProofSystemIdV1::JindoPolynomialCommitment;
                },
                |envelope| {
                    envelope.engine_id = PrivacyEngineIdV1::NativeJindo;
                },
                |envelope| envelope.parameter_id.0[0] ^= 0x80,
                |envelope| envelope.parameter_digest.0[0] ^= 0x80,
                |envelope| envelope.verifier_digest.0[0] ^= 0x80,
                |envelope| envelope.statement_schema_digest.0[0] ^= 0x80,
                |envelope| envelope.engine_manifest_digest.0[0] ^= 0x80,
                |envelope| envelope.statement_digest.0[0] ^= 0x80,
            ];
            for mutate_envelope in envelope_mutations {
                if verify_zk_x509_release_production_envelope_with_mutations_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    &proof,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                    |_| {},
                    mutate_envelope,
                )
                .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            let activation_mutations: [fn(&mut PrivacyProtocolActivationRecordV1); 9] = [
                |activation| {
                    activation.protocol_id = PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1;
                },
                |activation| {
                    activation.proof_system_id = PrivacyProofSystemIdV1::JindoPolynomialCommitment;
                },
                |activation| {
                    activation.engine_id = PrivacyEngineIdV1::NativeJindo;
                },
                |activation| activation.parameter_id.0[0] ^= 0x80,
                |activation| activation.parameter_digest.0[0] ^= 0x80,
                |activation| activation.verifier_digest.0[0] ^= 0x80,
                |activation| activation.statement_schema_digest.0[0] ^= 0x80,
                |activation| activation.engine_manifest_digest.0[0] ^= 0x80,
                |activation| {
                    activation.protocol_limits =
                        PrivacyProtocolActivationLimitsV1::ZkAcePqAuthorizationV1;
                },
            ];
            for mutate_activation in activation_mutations {
                if verify_zk_x509_release_production_envelope_with_mutations_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    &proof,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                    mutate_activation,
                    |_| {},
                )
                .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            let mut wrong_genesis = ZK_X509_RELEASE_GENESIS_HASH_V1;
            wrong_genesis[0] ^= 0x80;
            let wrong_authoritative_network_id = release_network_id_from_genesis_hash([0x96; 32]);
            let wrong_authoritative_action_index =
                ZK_X509_RELEASE_ACTION_INDEX_V1
                    .checked_add(1)
                    .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_zk_x509_credential_proof_v1(
                &fixture.statement,
                &fixture.authoritative_state,
                wrong_genesis,
                &proof,
            )
            .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    &proof,
                    &authoritative_network_id,
                    wrong_genesis,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                )
                .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    &proof,
                    &wrong_authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                )
                .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    &proof,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    wrong_authoritative_action_index,
                    trusted_block_timestamp_ms,
                )
                .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    None,
                    false,
                    &proof,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                )
                .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    true,
                    &proof,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                )
                .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    &proof,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    0,
                )
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted);
            }
            (
                norito::encode_canonical(&PrivacyStatementV1::IrohaZkX509StarkP256V1(wrong_intent))
                    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt_header = proof.clone();
            let header = corrupt_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *header ^= 0x80;
            let mut corrupt_interior = proof.clone();
            let interior_index = corrupt_interior.len() / 2;
            let interior = corrupt_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            let mut suffix_extended = proof.clone();
            suffix_extended.push(0);
            for corrupt in [
                corrupt_header.as_slice(),
                corrupt_interior.as_slice(),
                suffix_extended.as_slice(),
                &[],
            ] {
                if verify_zk_x509_credential_proof_v1(
                    &fixture.statement,
                    &fixture.authoritative_state,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    corrupt,
                )
                .is_ok()
                    || verify_zk_x509_release_production_envelope_v1(
                        &profile,
                        &fixture.statement,
                        Some(&fixture.authoritative_state),
                        false,
                        corrupt,
                        &authoritative_network_id,
                        ZK_X509_RELEASE_GENESIS_HASH_V1,
                        ZK_X509_RELEASE_ACTION_INDEX_V1,
                        trusted_block_timestamp_ms,
                    )
                    .is_ok()
                {
                    return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
                }
            }
            let truncated_length = proof
                .len()
                .checked_sub(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            let truncated = &proof[..truncated_length];
            if verify_zk_x509_credential_proof_v1(
                &fixture.statement,
                &fixture.authoritative_state,
                ZK_X509_RELEASE_GENESIS_HASH_V1,
                truncated,
            )
            .is_ok()
                || verify_zk_x509_release_production_envelope_v1(
                    &profile,
                    &fixture.statement,
                    Some(&fixture.authoritative_state),
                    false,
                    truncated,
                    &authoritative_network_id,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    ZK_X509_RELEASE_ACTION_INDEX_V1,
                    trusted_block_timestamp_ms,
                )
                .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            (
                original_material,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    let public_statement_material = zk_x509_release_public_statement_material_v1(
        public_statement_material,
        fixture.resource_shape,
    )?;
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(
            proof,
            u64::from(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1),
        ),
        failure_class,
        resources,
    })
}
pub(super) const ZK_X509_RELEASE_PUBLIC_MATERIAL_DOMAIN_V1: &[u8] =
    b"iroha.privacy.release.zk-x509-public-statement-and-resource-shape.v1";
pub(super) fn zk_x509_release_public_statement_material_v1(
    statement_material: Vec<u8>,
    resource_shape: ZkX509ReleaseResourceShapeV1,
) -> Result<Vec<u8>, PrivacyReleaseEvidenceErrorClassV1> {
    resource_shape
        .validate_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let statement_len = u64::try_from(statement_material.len())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let mut material = Vec::with_capacity(
        ZK_X509_RELEASE_PUBLIC_MATERIAL_DOMAIN_V1.len()
            + size_of::<u64>()
            + statement_material.len()
            + size_of::<u8>()
            + resource_shape.certificate_der_lengths.len() * size_of::<u32>()
            + size_of::<u32>()
            + size_of::<u8>()
            + resource_shape.disclosed_value_lengths.len() * size_of::<u16>()
            + size_of::<u16>()
            + size_of::<u16>()
            + size_of::<u8>(),
    );
    material.extend_from_slice(ZK_X509_RELEASE_PUBLIC_MATERIAL_DOMAIN_V1);
    material.extend_from_slice(&statement_len.to_be_bytes());
    material.extend_from_slice(&statement_material);
    material.push(resource_shape.certificate_chain_depth);
    for certificate_der_length in resource_shape.certificate_der_lengths {
        material.extend_from_slice(&certificate_der_length.to_be_bytes());
    }
    material.extend_from_slice(&resource_shape.crl_der_length.to_be_bytes());
    material.push(resource_shape.maximum_serial_bytes);
    for disclosed_value_length in resource_shape.disclosed_value_lengths {
        material.extend_from_slice(&disclosed_value_length.to_be_bytes());
    }
    material.extend_from_slice(&resource_shape.maximum_disclosed_value_bytes.to_be_bytes());
    material.extend_from_slice(&resource_shape.ca_membership_index.to_be_bytes());
    material.push(u8::from(
        resource_shape.ca_membership_path_has_nonzero_sibling,
    ));
    Ok(material)
}
#[allow(clippy::too_many_arguments)]
fn verify_zk_x509_release_production_envelope_v1(
    profile: &CompiledPrivacyProfileV1,
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: Option<&PrivacyZkX509AuthoritativeStateV1>,
    certificate_nullifier_consumed: bool,
    proof: &[u8],
    authoritative_network_id: &NetworkId,
    genesis_hash: [u8; 32],
    authoritative_action_index: u32,
    block_timestamp_ms: u64,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    verify_zk_x509_release_production_envelope_with_mutations_v1(
        profile,
        statement,
        authoritative_state,
        certificate_nullifier_consumed,
        proof,
        authoritative_network_id,
        genesis_hash,
        authoritative_action_index,
        block_timestamp_ms,
        |_| {},
        |_| {},
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_zk_x509_release_production_envelope_with_mutations_v1<
    A: FnOnce(&mut PrivacyProtocolActivationRecordV1),
    E: FnOnce(&mut PrivacyProofEnvelopeV1),
>(
    profile: &CompiledPrivacyProfileV1,
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: Option<&PrivacyZkX509AuthoritativeStateV1>,
    certificate_nullifier_consumed: bool,
    proof: &[u8],
    authoritative_network_id: &NetworkId,
    genesis_hash: [u8; 32],
    authoritative_action_index: u32,
    block_timestamp_ms: u64,
    mutate_activation: A,
    mutate_envelope: E,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    let mut activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height: 1,
            activated_at_height: 2,
            state_since_height: 2,
        },
    ));
    mutate_activation(&mut activation);
    let typed_statement = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let mut envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(proof.to_vec())),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected)?;
    mutate_envelope(&mut envelope);
    let expected_encoded_action_bytes = norito::canonical_frame_len(&envelope)
        .ok()
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let effects = verify_privacy_envelope_v1(
        &envelope,
        PrivacyVerificationContextV1 {
            activation: &activation,
            consensus_limits: &limits,
            network_id: authoritative_network_id,
            genesis_hash,
            current_height: 2,
            expected_action_index: authoritative_action_index,
            block_timestamp_ms,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: None,
            zk_x509_state: authoritative_state.map(|authoritative_state| {
                PrivacyZkX509VerificationStateV1 {
                    authoritative_state,
                    certificate_nullifier_consumed,
                }
            }),
            bootle_lantern_policy: None,
            vega_issuer_record: None,
        },
    )
    .map_err(|source| match source {
        PrivacyVerificationErrorV1::NativeZkX509(_) => {
            PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected
        }
        _ => PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected,
    })?;
    if effects.protocol_id() != PrivacyProtocolIdV1::IrohaZkX509StarkP256V1
        || effects.statement_digest() != statement_digest
        || effects.action_index() != authoritative_action_index
        || effects.encoded_action_bytes() != expected_encoded_action_bytes
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let authoritative_state =
        authoritative_state.ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let trust_anchor = authoritative_state.trust_anchor();
    let certificate_policy = authoritative_state.certificate_policy();
    let crl = authoritative_state.crl_record();
    if statement.trust_anchor_record_digest != trust_anchor.record_digest
        || statement.trust_anchor_record_epoch != trust_anchor.record_epoch
        || statement.certificate_policy_record_digest != certificate_policy.record_digest
        || statement.certificate_policy_record_epoch != certificate_policy.record_epoch
        || statement.crl_record_digest != crl.record_digest
        || statement.crl_record_epoch != crl.record_epoch
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    match effects.into_ledger() {
        VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(actual)
            if actual.namespace == authoritative_state.namespace()
                && actual.certificate_nullifier == statement.certificate_nullifier
                && actual.trust_anchor_record_digest == trust_anchor.record_digest
                && actual.trust_anchor_record_epoch == trust_anchor.record_epoch
                && actual.certificate_policy_record_digest == certificate_policy.record_digest
                && actual.certificate_policy_record_epoch == certificate_policy.record_epoch
                && actual.crl_record_digest == crl.record_digest
                && actual.crl_record_epoch == crl.record_epoch =>
        {
            Ok(())
        }
        _ => Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    }
}
#[cfg(test)]
mod release_kat_tests {
    use super::*;
    use crate::privacy_engines::zk_x509::{
        credential_stark::{
            decode_zk_x509_credential_envelope_v1, encode_zk_x509_credential_envelope_v1,
        },
        profile::{
            ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1, ZK_X509_RELEASE_KAT_EXPECTED_PROOF_BYTES_V1,
            ZK_X509_RELEASE_KAT_EXPECTED_PROOF_SHA256_V1,
        },
    };
    const SECOND_PROOF_PURPOSE_V1: &[u8] = b"cross-subproof-splice-control";
    fn verify_qualification_proof_v1(
        fixture: &crate::privacy_engines::zk_x509::relation::release_fixture::ZkX509ReleaseFixtureV1,
        genesis_hash: [u8; 32],
        encoded: &[u8],
    ) -> Result<(), crate::privacy_engines::zk_x509::engine::ZkX509EngineErrorV1> {
        verify_zk_x509_credential_proof_v1(
            &fixture.statement,
            &fixture.authoritative_state,
            genesis_hash,
            encoded,
        )
    }
    #[test]
    #[ignore = "explicit canonical positive release-evidence KAT adversarial corpus"]
    fn positive_release_stage_is_the_sole_kat_producer() {
        let case_kind = PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd;
        let started = std::time::Instant::now();
        let PreparedZkX509StageV1 {
            profile: _,
            fixture,
            trusted_block_timestamp_ms,
            proof: encoded,
        } = prepare_zk_x509_stage_v1(case_kind).expect("canonical positive release stage");
        let elapsed = started.elapsed();
        let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
        let proof_bytes = u32::try_from(encoded.len()).expect("KAT proof length fits u32");
        let proof_sha256 = sha256_v1(&encoded);
        let proof_sha256_hex = hex::encode(proof_sha256);
        eprintln!(
            "zk-x509-release-stage-kat bytes={proof_bytes} sha256={proof_sha256_hex} elapsed_ms={}",
            elapsed.as_millis()
        );
        assert_eq!(
            ZK_X509_RELEASE_KAT_EXPECTED_PROOF_BYTES_V1 == 0,
            ZK_X509_RELEASE_KAT_EXPECTED_PROOF_SHA256_V1 == [0; 32],
            "source KAT pins must be either both open or both populated"
        );
        if ZK_X509_RELEASE_KAT_EXPECTED_PROOF_BYTES_V1 == 0 {
            assert!(
                privacy_release_expectation_capture_open_v1(),
                "all bootstrap release pins must leave the single runner capture corridor open"
            );
        } else {
            assert_eq!(
                proof_bytes, ZK_X509_RELEASE_KAT_EXPECTED_PROOF_BYTES_V1,
                "source KAT length must come from the positive release stage"
            );
            assert_eq!(
                proof_sha256, ZK_X509_RELEASE_KAT_EXPECTED_PROOF_SHA256_V1,
                "source KAT digest must come from the positive release stage"
            );
        }
        assert!(proof_bytes <= ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1);
        verify_qualification_proof_v1(&fixture, ZK_X509_RELEASE_GENESIS_HASH_V1, &encoded)
            .expect("canonical release-stage KAT independently verifies");
        let envelope =
            decode_zk_x509_credential_envelope_v1(&encoded).expect("canonical KAT envelope");
        let base = encoded.as_ptr() as usize;
        let main_start = (envelope.main_aggregate.as_ptr() as usize)
            .checked_sub(base)
            .expect("MAIN lies inside X5S1");
        let ca_start = (envelope.ca_subproof.as_ptr() as usize)
            .checked_sub(base)
            .expect("CA lies inside X5S1");
        let mut mutation_offsets = vec![0, 1, 4, 6, 40, 72, 104];
        mutation_offsets.extend(8..40); // Every required public nonce byte.
        for proof_start in [main_start, ca_start] {
            let header_start = proof_start
                .checked_sub(8)
                .expect("subproof follows its exact eight-byte header");
            mutation_offsets.extend(header_start..proof_start);
        }
        for (start, length) in [
            (main_start, envelope.main_aggregate.len()),
            (ca_start, envelope.ca_subproof.len()),
        ] {
            for local in [
                0,
                1,
                length / 4,
                length / 2,
                length.saturating_mul(3) / 4,
                length.saturating_sub(1),
            ] {
                if local < length {
                    mutation_offsets.push(start + local);
                }
            }
        }
        mutation_offsets.sort_unstable();
        mutation_offsets.dedup();
        for offset in mutation_offsets {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                verify_qualification_proof_v1(&fixture, ZK_X509_RELEASE_GENESIS_HASH_V1, &changed)
                    .is_err(),
                "mutated X5S1 byte {offset} was accepted"
            );
        }
        let canonical_seed = stage_purpose_seed_v1(protocol_id, case_kind, b"canonical-x5s1-proof")
            .expect("canonical proof seed");
        let second_seed = stage_purpose_seed_v1(protocol_id, case_kind, SECOND_PROOF_PURPOSE_V1)
            .expect("purpose-separated splice-control seed");
        assert_ne!(second_seed, canonical_seed);
        let encoded_witness = fixture.witness.encode_v1().expect("canonical KAT witness");
        let mut second_rng = StdRng::from_seed(second_seed);
        let second_encoded = prove_zk_x509_credential_proof_v1_with_rng(
            &fixture.statement,
            &fixture.authoritative_state,
            trusted_block_timestamp_ms,
            &PrivacyConsensusLimitsV1::taira_default(),
            ZK_X509_RELEASE_GENESIS_HASH_V1,
            &encoded_witness,
            &mut second_rng,
        )
        .expect("same-context purpose-separated control proof");
        verify_qualification_proof_v1(&fixture, ZK_X509_RELEASE_GENESIS_HASH_V1, &second_encoded)
            .expect("control proof independently verifies");
        let second_envelope = decode_zk_x509_credential_envelope_v1(&second_encoded)
            .expect("canonical control envelope");
        assert_eq!(envelope.public, second_envelope.public);
        assert_ne!(envelope.proof_instance, second_envelope.proof_instance);
        let second_main_start =
            second_envelope.main_aggregate.as_ptr() as usize - second_encoded.as_ptr() as usize;
        // Preserve genuine mandatory132-opening bytes from each decoded proof.
        let first_openings = &encoded[main_start - 8 - 132 * 32..main_start - 8];
        let second_openings =
            &second_encoded[second_main_start - 8 - 132 * 32..second_main_start - 8];
        assert_ne!(envelope.main_aggregate, second_envelope.main_aggregate);
        assert_ne!(envelope.ca_subproof, second_envelope.ca_subproof);
        for (label, main_aggregate, ca_subproof) in [
            (
                "proof-A MAIN with proof-B CA",
                envelope.main_aggregate,
                second_envelope.ca_subproof,
            ),
            (
                "proof-B MAIN with proof-A CA",
                second_envelope.main_aggregate,
                envelope.ca_subproof,
            ),
        ] {
            for instance in [envelope.proof_instance, second_envelope.proof_instance] {
                for openings in [first_openings, second_openings] {
                    let spliced = encode_zk_x509_credential_envelope_v1(
                        instance,
                        envelope.public,
                        main_aggregate,
                        ca_subproof,
                        openings,
                    )
                    .expect("mixed valid subproofs remain canonically framed");
                    assert!(
                        verify_qualification_proof_v1(
                            &fixture,
                            ZK_X509_RELEASE_GENESIS_HASH_V1,
                            &spliced
                        )
                        .is_err(),
                        "{label} was accepted with {instance:?}"
                    );
                }
            }
        }
        let mut truncations = vec![
            0,
            1,
            4,
            8,
            main_start,
            main_start.saturating_add(4),
            ca_start,
            ca_start.saturating_add(4),
            encoded.len().saturating_sub(1),
        ];
        truncations.sort_unstable();
        truncations.dedup();
        for length in truncations {
            assert!(
                verify_qualification_proof_v1(
                    &fixture,
                    ZK_X509_RELEASE_GENESIS_HASH_V1,
                    &encoded[..length],
                )
                .is_err(),
                "truncated X5S1 length {length} was accepted"
            );
        }
        let mut wrong_intent = fixture.statement.clone();
        wrong_intent.context.transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new([0xD1; 32]);
        assert!(
            verify_zk_x509_credential_proof_v1(
                &wrong_intent,
                &fixture.authoritative_state,
                ZK_X509_RELEASE_GENESIS_HASH_V1,
                &encoded,
            )
            .is_err()
        );
        let mut wrong_genesis = ZK_X509_RELEASE_GENESIS_HASH_V1;
        wrong_genesis[0] ^= 1;
        assert!(verify_qualification_proof_v1(&fixture, wrong_genesis, &encoded).is_err());
    }
}
#[cfg(test)]
mod resource_certificate_tests {
    use super::*;
    fn observation_v1(
        case_kind: PrivacyReleaseCaseKindV1,
        elapsed_millis: u64,
        peak_rss_bytes: u64,
        peak_address_space_bytes: u64,
    ) -> PrivacyReleaseZkX509ResourceObservationV1 {
        let resources = privacy_release_resource_facts_v1(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            case_kind,
        )
        .expect("X.509 release resource shape");
        PrivacyReleaseZkX509ResourceObservationV1 {
            case_kind,
            elapsed_millis,
            peak_rss_bytes,
            peak_address_space_bytes,
            primary_units: resources.primary_units,
            primary_ceiling: resources.primary_ceiling,
            secondary_units: resources.secondary_units,
            secondary_ceiling: resources.secondary_ceiling,
            relation_depth: resources.relation_depth,
            relation_depth_ceiling: resources.relation_depth_ceiling,
        }
    }
    fn capture_v1() -> PrivacyReleaseZkX509ResourceCertificateV1 {
        build_privacy_release_zk_x509_resource_certificate_v1(
            privacy_release_zk_x509_resource_environment_v1(),
            [0x31; 32],
            [0x32; 32],
            1,
            [0x33; 32],
            observation_v1(
                PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd,
                1,
                1024 * 1024,
                64 * 1024 * 1024,
            ),
            observation_v1(
                PrivacyReleaseCaseKindV1::MaximumShapeResource,
                2,
                2 * 1024 * 1024,
                128 * 1024 * 1024,
            ),
        )
        .expect("structurally valid pre-pin resource capture")
    }
    #[test]
    fn public_resource_capture_binds_every_top_level_field_and_digest() {
        let capture = capture_v1();
        assert!(validate_privacy_release_zk_x509_resource_capture_v1(
            &capture
        ));
        macro_rules! reject_mutation {
            ($mutate:expr) => {{
                let mut mutation = capture.clone();
                ($mutate)(&mut mutation);
                assert!(
                    !validate_privacy_release_zk_x509_resource_capture_v1(&mutation),
                    "mutated public capture field must reject"
                );
            }};
        }
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value.schema_version += 1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value.protocol_id =
                PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value
                .compiled_profile_digest[0] ^=
                1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value
                .environment
                .cpu_model
                .push('x')
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value
                .expectations_norito_sha256[0] ^=
                1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value
                .expectations_json_sha256[0] ^=
                1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value.kat_proof_bytes += 1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value.kat_proof_sha256[0] ^= 1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value
                .process_limits
                .main_thread_stack_bytes +=
                1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value
                .positive
                .elapsed_millis += 1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value.maximum.peak_rss_bytes +=
                1
        );
        reject_mutation!(
            |value: &mut PrivacyReleaseZkX509ResourceCertificateV1| value.certificate_sha256[0] ^=
                1
        );
    }
    #[test]
    fn public_resource_capture_rejects_wrong_case_and_zero_measurements() {
        let capture = capture_v1();
        for mutation in [
            PrivacyReleaseZkX509ResourceCertificateV1 {
                positive: PrivacyReleaseZkX509ResourceObservationV1 {
                    case_kind: PrivacyReleaseCaseKindV1::PublicStatementBindingMutation,
                    ..capture.positive
                },
                ..capture.clone()
            },
            PrivacyReleaseZkX509ResourceCertificateV1 {
                maximum: PrivacyReleaseZkX509ResourceObservationV1 {
                    elapsed_millis: 0,
                    ..capture.maximum
                },
                ..capture
            },
        ] {
            assert!(!validate_privacy_release_zk_x509_resource_capture_v1(
                &mutation
            ));
        }
    }
}
