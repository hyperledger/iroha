//! Authenticated service and HTTPS transport for the private Musubi publication control plane.
//!
//! The public Torii `SoraFS` upload route is deliberately not used here. Every request
//! targets one fixed publication-specific route, carries a bounded canonical Norito
//! authorization approved by the configured Iroha account controller, and rejects redirects.
//! The same crate owns explicit native seed, replay-journal and clock provisioning. Local seed
//! custody validates exact bytes; the daemon separately authenticates finalized registration.
use base64::Engine as _;
use iroha::client::Client;
use iroha_crypto::{KeyPair, PublicKey, SignatureOf};
use iroha_data_model::{
    NetworkId,
    account::{AccountController, AccountId, MultisigPolicy},
    musubi::{
        ArchiveId, MUSUBI_MAX_ARCHIVE_LOCATIONS_V1, MUSUBI_MAX_BUNDLE_PAYLOAD_BYTES_V1,
        MUSUBI_MAX_CAR_BYTES_V1, MUSUBI_MAX_CHUNKS_V1, MUSUBI_MAX_FILES_V1,
        MUSUBI_MAX_LOCATION_PROVIDERS_V1, MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1,
        MUSUBI_MAX_SEED_INGRESS_RECEIPT_LIFETIME_MS_V1, MUSUBI_MIN_HEALTHY_REPLICAS_V1,
        MusubiArchiveCommitmentV1, MusubiArchiveLocationIdV1, MusubiArchiveLocationStateV1,
        MusubiArchiveLocationV1, MusubiArchiveRecordV1, MusubiArchiveRegistrationProjectionV1,
        MusubiContentDigestV1, MusubiRegistrySnapshotV1, MusubiSeedIngressReceiptApprovalV1,
        MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptPayloadV1,
        MusubiSeedIngressReceiptV1, MusubiSemanticReleaseDigestV1, MusubiVerificationLockDigestV1,
        validate_musubi_account_id_v1, validate_musubi_portable_path_set_v1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{ManifestDigest, ReplicationOrderId},
    },
};
use iroha_telemetry::metrics::{
    global as global_metrics,
    musubi::{MusubiIngestDeadletterReasonV1, MusubiIntegritySurfaceV1},
};
use norito::DecodeLimits;
use reqwest::{
    StatusCode, blocking::Client as HttpClient, header::HeaderValue,
    redirect::Policy as RedirectPolicy,
};
/// Canonical original publication transport intent; this does not grant native service authority.
pub use sorafs_car::gateway::GeneratedLocalPublicationTransportV1;
use sorafs_car::{
    CarBuildPlan, CarChunk, FilePlan,
    gateway::GeneratedLocalPublicationHttpClientV1,
    musubi::{
        MusubiBundleIntegritySurfaceV1, MusubiBundleVerifierV1,
        plan::{
            MusubiPlanValidationContextV1, resolve_chunk_profile_v1, validate_plan_commitment_v1,
        },
    },
};
#[cfg(test)]
use sorafs_car::{
    DEFAULT_CHUNK_STORE_MAX_ESTIMATED_HEAP_BYTES, compute_chunk_plan_digest_sha3,
    musubi::{
        MUSUBI_BUNDLE_ARTIFACT_DESCRIPTOR_PATH_V1, MUSUBI_BUNDLE_SEMANTIC_RELEASE_PATH_V1,
        MUSUBI_BUNDLE_VERIFICATION_LOCK_PATH_V1,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
mod native_pin_session;
pub use native_pin_session::NativeMusubiPinSessionV1;
pub mod publication_client_journal;
mod publication_clock;
mod publication_journal;
mod seed_staging;
pub use seed_staging::{MusubiSeedStagingBackendV1, MusubiSeedStagingErrorV1};
#[cfg(any(test, feature = "test-fixtures"))]
pub mod seed_test_support;
pub use publication_clock::{
    DurableMusubiPublicationServiceClockOpenErrorV1, DurableMusubiPublicationServiceClockV1,
};
pub use publication_journal::{
    DurableMusubiPublicationServiceJournalLimitsV1,
    DurableMusubiPublicationServiceJournalOpenErrorV1, DurableMusubiPublicationServiceJournalV1,
};
const AUTH_DOMAIN_V1: [u8; 32] = *b"musubi-pub-runtime-auth-v1\0\0\0\0\0\0";
/// Exact security-sensitive authorization header accepted by the private service.
pub const MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1: &str =
    "x-iroha-musubi-publication-authorization";
/// Exact seed metadata header accepted only by the framed plan-and-CAR route.
pub const MUSUBI_PUBLICATION_SEED_METADATA_HEADER_V1: &str = "x-iroha-musubi-seed-ingress-metadata";
/// Canonical Norito media type used by control requests and every response.
pub const MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1: &str = "application/x-norito";
/// Canonical framed plan-and-CAR media type used only by seed ingress.
pub const MUSUBI_PUBLICATION_SEED_ENVELOPE_MEDIA_TYPE_V1: &str =
    "application/vnd.iroha.musubi-seed-ingress-v1";
/// Maximum canonical Norito bytes in one Musubi seed-ingress plan witness.
pub const MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1: usize = 24 * 1024 * 1024;
const MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_U64_V1: u64 = 24 * 1024 * 1024;
const AUTHORIZATION_HEADER: &str = MUSUBI_PUBLICATION_AUTHORIZATION_HEADER_V1;
const SEED_INGRESS_METADATA_HEADER: &str = MUSUBI_PUBLICATION_SEED_METADATA_HEADER_V1;
const APPLICATION_NORITO: &str = MUSUBI_PUBLICATION_NORITO_MEDIA_TYPE_V1;
const APPLICATION_MUSUBI_SEED_ENVELOPE: &str = MUSUBI_PUBLICATION_SEED_ENVELOPE_MEDIA_TYPE_V1;
const SEED_INGRESS_ROUTE: &str = "v1/musubi/publication/seed-ingress";
const STORAGE_COORDINATION_ROUTE: &str = "v1/musubi/publication/storage-coordinate";
const PROVIDER_READBACK_ROUTE: &str = "v1/musubi/publication/provider-readback";
const MAX_AUTHORIZATION_LIFETIME_MS: u64 = 60_000;
const DEFAULT_AUTHORIZATION_LIFETIME_MS: u64 = 30_000;
const MAX_AUTHORIZATION_BYTES: usize = 64 * 1024;
const MAX_SEED_INGRESS_METADATA_BYTES: usize = 64 * 1024;
const MAX_CONTROL_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTROL_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONTROL_RESPONSE_BYTES_U64: u64 = 16 * 1024 * 1024;
const RESPONSE_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    4_096,
    MAX_CONTROL_RESPONSE_BYTES,
    32_768,
    32 * 1024 * 1024,
    64,
);
const PROVIDER_READBACK_TARGET_DOMAIN_V1: &[u8] = b"iroha.musubi.v1.provider-readback-target";
const SEED_INGRESS_PLAN_DIGEST_DOMAIN_V1: &[u8] = b"iroha.musubi.v1.seed-ingress-plan";
const SEED_INGRESS_ENVELOPE_MAGIC_V1: [u8; 16] = *b"MUSUBI-SEED-V1\0\0";
const SEED_INGRESS_ENVELOPE_VERSION_V1: u8 = 1;
const SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1: usize = 40;
#[cfg(test)]
const BUNDLE_RELEASE_PATH_V1: &str = MUSUBI_BUNDLE_SEMANTIC_RELEASE_PATH_V1;
#[cfg(test)]
const BUNDLE_DESCRIPTOR_PATH_V1: &str = MUSUBI_BUNDLE_ARTIFACT_DESCRIPTOR_PATH_V1;
#[cfg(test)]
const BUNDLE_VERIFICATION_LOCK_PATH_V1: &str = MUSUBI_BUNDLE_VERIFICATION_LOCK_PATH_V1;
#[cfg(test)]
const SOURCE_TREE_DOMAIN_V1: &[u8] = b"musubi-source-tree-v1\0";
#[cfg(test)]
const ARTIFACT_DESCRIPTOR_DOMAIN_V1: &[u8] = b"musubi-artifact-descriptor-v1\0";
#[cfg(test)]
const BUNDLE_DOMAIN_V1: &[u8] = b"musubi-bundle-v1\0";
// TODO: Deployments must inject and qualify their private HTTPS listener, durable replay journal,
// broker signer, and authoritative SoraFS backends around the transport-independent server
// below. Before declaring a deployment production-qualified, bind each configured hostname to
// deployment-signed provider-advert IPs and add DNS-rebinding tests; disabling proxies and
// redirects alone is not DNS pinning. Do not adapt the daemon-private provider broker or restore
// `/v1/sorafs/upload`; this protocol intentionally exposes neither interface.
/// Fixed private publication-control operation covered by account authorization.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationRuntimeOperationV1")]
pub enum MusubiPublicationRuntimeOperationV1 {
    /// Stage one exact CAR through authenticated seed ingress.
    #[codec(index = 0)]
    SeedIngress,
    /// Register/reuse the permanent pin and replication order.
    #[codec(index = 1)]
    StorageCoordination,
    /// Read and verify the complete archive through one exact provider.
    #[codec(index = 2)]
    ProviderReadback,
}
/// Domain-separated short-lived authorization for one exact publication request.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationRuntimeAuthorizationPayloadV1")]
pub struct MusubiPublicationRuntimeAuthorizationPayloadV1 {
    /// Fixed domain marker preventing cross-protocol signature reuse.
    pub domain: [u8; 32],
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Exact private control-plane operation.
    pub operation: MusubiPublicationRuntimeOperationV1,
    /// Stable idempotency key derived from the immutable publication request.
    pub operation_id: [u8; 32],
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Account authorizing this request.
    pub publisher: AccountId,
    /// Domain-separated digest of the exact typed request metadata.
    pub request_digest: [u8; 32],
    /// Authorization issuance time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Inclusive authorization expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}
impl MusubiPublicationRuntimeAuthorizationPayloadV1 {
    fn validate(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        let lifetime = self.expires_at_ms.checked_sub(self.issued_at_ms);
        if self.domain != AUTH_DOMAIN_V1
            || self.version != 1
            || self.operation_id.iter().all(|byte| *byte == 0)
            || self.network_id.as_bytes()[31] & 1 != 1
            || validate_musubi_account_id_v1(&self.publisher).is_err()
            || self.request_digest.iter().all(|byte| *byte == 0)
            || self.issued_at_ms == 0
            || !matches!(lifetime, Some(1..=MAX_AUTHORIZATION_LIFETIME_MS))
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_INVALID",
            ));
        }
        Ok(())
    }
}
/// One controller approval for a bounded private publication request.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationRuntimeAuthorizationApprovalV1")]
pub struct MusubiPublicationRuntimeAuthorizationApprovalV1 {
    /// Publisher-controller key that produced this approval.
    pub public_key: PublicKey,
    /// Signature over the exact service authorization payload.
    pub signature: SignatureOf<MusubiPublicationRuntimeAuthorizationPayloadV1>,
}
/// Bounded publisher-controller authorization for one private publication request.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationRuntimeAuthorizationV1")]
pub struct MusubiPublicationRuntimeAuthorizationV1 {
    /// Exact statement covered by the signature.
    pub payload: MusubiPublicationRuntimeAuthorizationPayloadV1,
    /// Canonically ordered, distinct publisher-controller approvals.
    pub approvals: Vec<MusubiPublicationRuntimeAuthorizationApprovalV1>,
}
impl MusubiPublicationRuntimeAuthorizationV1 {
    /// Verify the exact operation, request digest, validity window, and account controller.
    ///
    /// # Errors
    ///
    /// Returns a redacted permanent error when any request, clock, controller, approval, or
    /// signature binding is invalid.
    pub fn verify(
        &self,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        request_digest: [u8; 32],
        current_time_ms: u64,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.verify_with_clock_skew(operation, operation_id, request_digest, current_time_ms, 0)
    }
    /// Verify an exact request while tolerating only a bounded future clock skew.
    ///
    /// Expiry remains strict: skew can accommodate a publisher clock that is slightly
    /// ahead of the service, but never extends an authorization beyond `expires_at_ms`.
    ///
    /// # Errors
    ///
    /// Returns a redacted permanent error when any request, clock, controller, or signature
    /// binding differs.
    pub fn verify_with_clock_skew(
        &self,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        request_digest: [u8; 32],
        current_time_ms: u64,
        max_future_clock_skew_ms: u64,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.payload.validate()?;
        if current_time_ms == 0
            || max_future_clock_skew_ms > MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_CLOCK_INVALID",
            ));
        }
        let latest_accepted_issue_time = current_time_ms
            .checked_add(max_future_clock_skew_ms)
            .ok_or_else(|| {
                MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_CLOCK_INVALID")
            })?;
        if self.payload.operation != operation
            || self.payload.operation_id != operation_id
            || self.payload.request_digest != request_digest
            || self.payload.issued_at_ms > latest_accepted_issue_time
            || current_time_ms > self.payload.expires_at_ms
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_MISMATCH",
            ));
        }
        if self.approvals.is_empty()
            || self.approvals.len() > MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1
            || self
                .approvals
                .windows(2)
                .any(|pair| pair[0].public_key >= pair[1].public_key)
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_APPROVALS_INVALID",
            ));
        }
        if !controller_fits_publication_approval_bound(&self.payload.publisher) {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_CONTROLLER_UNSUPPORTED",
            ));
        }
        let signing_hash = iroha_crypto::HashOf::new(&self.payload);
        match self.payload.publisher.controller() {
            AccountController::Single(expected_key) => {
                let [approval] = self.approvals.as_slice() else {
                    return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_RUNTIME_AUTHORIZATION_APPROVALS_INVALID",
                    ));
                };
                if expected_key != &approval.public_key {
                    return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_RUNTIME_AUTHORIZATION_KEY_MISMATCH",
                    ));
                }
                approval
                    .signature
                    .verify_hash(&approval.public_key, signing_hash)
                    .map_err(|_| {
                        MusubiPublicationRuntimeTransportErrorV1::permanent(
                            "MUSUBI_RUNTIME_AUTHORIZATION_SIGNATURE_INVALID",
                        )
                    })
            }
            AccountController::Multisig(policy) => {
                let mut approved_weight = 0_u32;
                for approval in &self.approvals {
                    let Some(member) = policy
                        .members()
                        .iter()
                        .find(|member| member.public_key() == &approval.public_key)
                    else {
                        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                            "MUSUBI_RUNTIME_AUTHORIZATION_KEY_MISMATCH",
                        ));
                    };
                    approval
                        .signature
                        .verify_hash(&approval.public_key, signing_hash)
                        .map_err(|_| {
                            MusubiPublicationRuntimeTransportErrorV1::permanent(
                                "MUSUBI_RUNTIME_AUTHORIZATION_SIGNATURE_INVALID",
                            )
                        })?;
                    approved_weight = approved_weight
                        .checked_add(u32::from(member.weight()))
                        .ok_or_else(|| {
                            MusubiPublicationRuntimeTransportErrorV1::permanent(
                                "MUSUBI_RUNTIME_AUTHORIZATION_APPROVALS_INVALID",
                            )
                        })?;
                }
                if approved_weight < u32::from(policy.threshold()) {
                    return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_RUNTIME_AUTHORIZATION_THRESHOLD_UNMET",
                    ));
                }
                Ok(())
            }
        }
    }
}
/// One bounded chunk in the canonical Musubi seed-ingress plan witness.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiSeedIngressCarChunkV1")]
pub struct MusubiSeedIngressCarChunkV1 {
    /// Absolute byte offset in the concatenated bundle payload.
    pub offset: u64,
    /// Positive chunk byte length.
    pub length: u32,
    /// BLAKE3-256 digest of the exact chunk bytes.
    pub digest: [u8; 32],
}
/// One portable file entry in the canonical Musubi seed-ingress plan witness.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiSeedIngressCarFileV1")]
pub struct MusubiSeedIngressCarFileV1 {
    /// Portable UTF-8 path components in canonical byte order.
    pub path: Vec<String>,
    /// First chunk belonging to this file.
    pub first_chunk: u32,
    /// Number of consecutive chunks belonging to this file.
    pub chunk_count: u32,
    /// Exact file byte length.
    pub size: u64,
}
/// Canonical bounded Norito witness for one exact multi-file `SoraFS` CAR build plan.
///
/// The chunk profile is deliberately absent. Conversion resolves the complete, canonical profile
/// identity from the accompanying immutable archive commitment, preventing a witness from
/// negotiating or aliasing a different chunker.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiSeedIngressCarPlanV1")]
pub struct MusubiSeedIngressCarPlanV1 {
    /// Closed witness schema version; must equal one.
    pub version: u8,
    /// BLAKE3-256 digest of the concatenated raw bundle payload.
    pub payload_digest: [u8; 32],
    /// Exact concatenated payload byte length.
    pub content_length: u64,
    /// Canonically ordered complete chunk inventory.
    pub chunks: Vec<MusubiSeedIngressCarChunkV1>,
    /// Canonically ordered complete file inventory.
    pub files: Vec<MusubiSeedIngressCarFileV1>,
}
impl MusubiSeedIngressCarPlanV1 {
    /// Convert a validated `SoraFS` plan into its canonical V1 wire witness.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error unless the plan uses the commitment's exact registered
    /// chunker and satisfies every Musubi V1 source, file, chunk, path, and heap bound.
    pub fn from_car_build_plan(
        plan: &CarBuildPlan,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> Result<Self, MusubiPublicationRuntimeTransportErrorV1> {
        validate_plan_commitment_v1(plan, commitment, MusubiPlanValidationContextV1::SeedIngress)
            .map_err(|_| seed_ingress_plan_invalid())?;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(plan.chunks.len())
            .map_err(|_| seed_ingress_plan_invalid())?;
        chunks.extend(plan.chunks.iter().map(|chunk| MusubiSeedIngressCarChunkV1 {
            offset: chunk.offset,
            length: chunk.length,
            digest: chunk.digest,
        }));
        let mut files = Vec::new();
        files
            .try_reserve_exact(plan.files.len())
            .map_err(|_| seed_ingress_plan_invalid())?;
        for file in &plan.files {
            files.push(MusubiSeedIngressCarFileV1 {
                path: clone_seed_ingress_path(&file.path)?,
                first_chunk: u32::try_from(file.first_chunk)
                    .map_err(|_| seed_ingress_plan_invalid())?,
                chunk_count: u32::try_from(file.chunk_count)
                    .map_err(|_| seed_ingress_plan_invalid())?,
                size: file.size,
            });
        }
        Ok(Self {
            version: 1,
            payload_digest: *plan.payload_digest.as_bytes(),
            content_length: plan.content_length,
            chunks,
            files,
        })
    }
    /// Reconstruct the exact validated `SoraFS` plan selected by an immutable commitment.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error for a non-V1 witness, unknown or noncanonical chunker,
    /// invalid plan geometry, nonportable path, missing bundle entry, or commitment mismatch.
    pub fn to_car_build_plan(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> Result<CarBuildPlan, MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_shape()?;
        let profile =
            resolve_chunk_profile_v1(commitment).map_err(|_| seed_ingress_plan_invalid())?;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(self.chunks.len())
            .map_err(|_| seed_ingress_plan_invalid())?;
        chunks.extend(self.chunks.iter().map(|chunk| CarChunk {
            offset: chunk.offset,
            length: chunk.length,
            digest: chunk.digest,
        }));
        let mut files = Vec::new();
        files
            .try_reserve_exact(self.files.len())
            .map_err(|_| seed_ingress_plan_invalid())?;
        for file in &self.files {
            files.push(FilePlan {
                path: clone_seed_ingress_path(&file.path)?,
                first_chunk: usize::try_from(file.first_chunk)
                    .map_err(|_| seed_ingress_plan_invalid())?,
                chunk_count: usize::try_from(file.chunk_count)
                    .map_err(|_| seed_ingress_plan_invalid())?,
                size: file.size,
            });
        }
        let plan = CarBuildPlan {
            chunk_profile: profile,
            payload_digest: blake3::Hash::from_bytes(self.payload_digest),
            content_length: self.content_length,
            chunks,
            files,
        };
        validate_plan_commitment_v1(
            &plan,
            commitment,
            MusubiPlanValidationContextV1::SeedIngress,
        )
        .map_err(|_| seed_ingress_plan_invalid())?;
        Ok(plan)
    }
    /// Validate this witness against one exact immutable archive commitment.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error for any malformed geometry, profile, or commitment binding.
    pub fn validate(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.to_car_build_plan(commitment).map(|_| ())
    }
    /// Encode this witness as bounded canonical Norito bytes.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when its closed V1 shape is invalid or encoding exceeds
    /// the fixed seed-ingress plan bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_shape()?;
        let bytes = norito::encode_canonical(self).map_err(|_| seed_ingress_plan_invalid())?;
        if bytes.is_empty() || bytes.len() > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1 {
            return Err(seed_ingress_plan_invalid());
        }
        Ok(bytes)
    }
    /// Compute the domain-separated digest of the exact canonical witness bytes.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when the witness cannot be encoded canonically within the
    /// V1 bound.
    pub fn canonical_digest(
        &self,
    ) -> Result<MusubiContentDigestV1, MusubiPublicationRuntimeTransportErrorV1> {
        self.canonical_bytes()
            .and_then(|bytes| seed_ingress_plan_digest(&bytes))
    }
    /// Return the exact canonical witness byte length.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when the witness cannot be encoded canonically within the
    /// V1 bound.
    pub fn canonical_len(&self) -> Result<u64, MusubiPublicationRuntimeTransportErrorV1> {
        u64::try_from(self.canonical_bytes()?.len()).map_err(|_| seed_ingress_plan_invalid())
    }
    fn validate_shape(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_non_path_shape()?;
        self.validate_portable_paths()
    }
    fn validate_non_path_shape(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        let maximum_files = usize::try_from(MUSUBI_MAX_FILES_V1)
            .unwrap_or(usize::MAX)
            .saturating_add(3);
        if self.version != 1
            || self.content_length == 0
            || self.content_length > MUSUBI_MAX_BUNDLE_PAYLOAD_BYTES_V1
            || self.chunks.is_empty()
            || self.chunks.len() > usize::try_from(MUSUBI_MAX_CHUNKS_V1).unwrap_or(usize::MAX)
            || self.files.len() < 4
            || self.files.len() > maximum_files
        {
            return Err(seed_ingress_plan_invalid());
        }
        Ok(())
    }
    fn validate_portable_paths(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        validate_musubi_portable_path_set_v1(self.files.iter().map(|file| file.path.as_slice()))
            .map_err(|_| seed_ingress_plan_invalid())?;
        Ok(())
    }
}
fn clone_seed_ingress_path(
    path: &[String],
) -> Result<Vec<String>, MusubiPublicationRuntimeTransportErrorV1> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(path.len())
        .map_err(|_| seed_ingress_plan_invalid())?;
    for component in path {
        let mut cloned_component = String::new();
        cloned_component
            .try_reserve_exact(component.len())
            .map_err(|_| seed_ingress_plan_invalid())?;
        cloned_component.push_str(component);
        cloned.push(cloned_component);
    }
    Ok(cloned)
}
/// Authenticated metadata accompanying one framed canonical plan-and-CAR seed body.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiSeedIngressStageRequestV1")]
pub struct MusubiSeedIngressStageRequestV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Stable idempotency key for the immutable publication request.
    pub operation_id: [u8; 32],
    /// Exact chain, actor, broker, provider, archive, and CAR binding.
    pub binding: MusubiSeedIngressReceiptBindingV1,
    /// Complete immutable archive commitment verified before staging.
    pub commitment: MusubiArchiveCommitmentV1,
    /// Domain-separated digest of the canonical Norito plan witness in the body envelope.
    pub plan_digest: MusubiContentDigestV1,
    /// Exact canonical Norito plan-witness byte length in the body envelope.
    pub plan_length: u64,
}
impl MusubiSeedIngressStageRequestV1 {
    /// Validate the closed request and its exact receipt binding.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when the receipt binding, version, or operation identity
    /// is invalid.
    pub fn validate(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.binding.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_REQUEST_INVALID",
            )
        })?;
        self.commitment.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_REQUEST_INVALID",
            )
        })?;
        if self.version != 1
            || self.operation_id.iter().all(|byte| *byte == 0)
            || self.plan_digest.is_zero()
            || self.plan_length == 0
            || self.plan_length > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_U64_V1
            || self.binding.archive_id != self.commitment.archive_id()
            || self.binding.car_body_digest != self.commitment.car_digest
            || self.binding.car_body_length != self.commitment.car_size
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_REQUEST_INVALID",
            ));
        }
        Ok(())
    }
}
fn seed_ingress_plan_invalid() -> MusubiPublicationRuntimeTransportErrorV1 {
    MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_PLAN_INVALID")
}
fn seed_ingress_plan_digest(
    canonical_plan: &[u8],
) -> Result<MusubiContentDigestV1, MusubiPublicationRuntimeTransportErrorV1> {
    if canonical_plan.is_empty() || canonical_plan.len() > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1 {
        return Err(seed_ingress_plan_invalid());
    }
    let length = u64::try_from(canonical_plan.len()).map_err(|_| seed_ingress_plan_invalid())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEED_INGRESS_PLAN_DIGEST_DOMAIN_V1);
    hasher.update(&length.to_be_bytes());
    hasher.update(canonical_plan);
    Ok(MusubiContentDigestV1::new(*hasher.finalize().as_bytes()))
}
/// Finalized immutable archive-registration evidence sent to the storage coordinator.
///
/// The named registry snapshot proves when the immutable registration became observable. A backend
/// may reproduce `registration` from any later finalized archive read because Core permits only the
/// omitted location directory to change after registration.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiFinalizedArchiveRegistrationEvidenceV1")]
pub struct MusubiFinalizedArchiveRegistrationEvidenceV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Exact finalized transaction identity that registered the archive.
    pub transaction_hash: [u8; 32],
    /// Finalized registry snapshot at or after registration.
    pub snapshot: MusubiRegistrySnapshotV1,
    /// Immutable projection reproduced from the authoritative archive record.
    pub registration: MusubiArchiveRegistrationProjectionV1,
}
impl MusubiFinalizedArchiveRegistrationEvidenceV1 {
    /// Validate deployment, finality, and immutable archive-registration bindings.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when the finalized snapshot or immutable registration
    /// evidence is malformed or internally inconsistent.
    pub fn validate(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.snapshot.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_ARCHIVE_REGISTRATION_EVIDENCE_INVALID",
            )
        })?;
        self.registration.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_ARCHIVE_REGISTRATION_EVIDENCE_INVALID",
            )
        })?;
        let binding = &self.registration.staging_receipt.payload.binding;
        if self.version != 1
            || self.network_id.as_bytes()[31] & 1 != 1
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || binding.network_id != self.network_id
            || self.registration.registered_at_height > self.snapshot.finalized_height
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_ARCHIVE_REGISTRATION_EVIDENCE_INVALID",
            ));
        }
        Ok(())
    }
}
/// Exact archive and receipt inputs sent to the private storage coordinator.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiStorageCoordinationRequestV1")]
pub struct MusubiStorageCoordinationRequestV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Stable idempotency key for the immutable publication request.
    pub operation_id: [u8; 32],
    /// One-based append-only archive-location transaction generation.
    pub generation: u8,
    /// Sorted identities used by every earlier generation; none may be returned again.
    pub prior_location_ids: Vec<MusubiArchiveLocationIdV1>,
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Account that registered the archive.
    pub publisher: AccountId,
    /// Complete immutable archive commitment.
    pub commitment: MusubiArchiveCommitmentV1,
    /// Verification-lock digest every provider must parse from the exact bundle.
    pub verification_lock_digest: MusubiVerificationLockDigestV1,
    /// Authenticated receipt for the exact staged CAR body.
    pub staging_receipt: MusubiSeedIngressReceiptV1,
    /// Registry admission revision used by archive registration.
    pub expected_policy_revision: u64,
    /// Finalized immutable registration evidence recovered before storage coordination.
    pub finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1,
}
impl MusubiStorageCoordinationRequestV1 {
    /// Digest the exact canonical request using the storage-authorization domain.
    /// # Errors
    /// Refuses invalid or over-limit request encoding.
    pub fn canonical_request_digest(
        &self,
    ) -> Result<[u8; 32], MusubiPublicationRuntimeTransportErrorV1> {
        let _canonical_flags =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        self.validate()?;
        let invalid = || {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_REQUEST_INVALID",
            )
        };
        let length = norito::canonical_frame_len(self).map_err(|_| invalid())?;
        if length > MAX_CONTROL_REQUEST_BYTES {
            return Err(invalid());
        }
        let bytes = norito::core::to_bytes_bounded(self, length).map_err(|_| invalid())?;
        request_digest(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            &bytes,
        )
    }

    /// Validate every immutable storage-coordination input.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when any request, receipt, commitment, generation, or
    /// finalized-registration binding is invalid.
    pub fn validate(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        self.commitment.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_REQUEST_INVALID",
            )
        })?;
        self.staging_receipt.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_REQUEST_INVALID",
            )
        })?;
        self.finalized_registration.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_REQUEST_INVALID",
            )
        })?;
        let binding = &self.staging_receipt.payload.binding;
        if self.version != 1
            || self.operation_id.iter().all(|byte| *byte == 0)
            || self.generation == 0
            || usize::from(self.generation) > MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1
            || self.prior_location_ids.len() + 1 != usize::from(self.generation)
            || self
                .prior_location_ids
                .iter()
                .any(MusubiArchiveLocationIdV1::is_zero)
            || self
                .prior_location_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.network_id.as_bytes()[31] & 1 != 1
            || self.expected_policy_revision == 0
            || self.verification_lock_digest.is_zero()
            || binding.network_id != self.network_id
            || binding.publisher != self.publisher
            || binding.archive_id != self.commitment.archive_id()
            || binding.car_body_digest != self.commitment.car_digest
            || binding.car_body_length != self.commitment.car_size
            || self.finalized_registration.network_id != self.network_id
            || self.finalized_registration.registration.archive_id != self.commitment.archive_id()
            || self.finalized_registration.registration.commitment != self.commitment
            || self.finalized_registration.registration.staging_receipt != self.staging_receipt
            || self.finalized_registration.registration.registered_by != self.publisher
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_REQUEST_INVALID",
            ));
        }
        Ok(())
    }
}
/// Whether the publisher must add the returned location or may reuse finalized state.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiStorageLocationDispositionV1")]
pub enum MusubiStorageLocationDispositionV1 {
    /// Coordinator observed the required finalized provider completions for this pin/order.
    #[codec(index = 0)]
    NeedsRegistration {
        /// Sorted distinct completed provider identities. The publisher acquires their originals.
        completed_providers: Vec<ProviderId>,
        /// Exact current archive location-set revision for compare-and-set.
        expected_location_revision: u64,
    },
    /// Identical retry found the exact finalized location already registered.
    #[codec(index = 1)]
    Registered(MusubiArchiveLocationV1),
}
/// Idempotent private storage-coordinator result.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiStorageCoordinationResponseV1")]
pub struct MusubiStorageCoordinationResponseV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Exact domain-separated digest of the complete authenticated coordination request.
    pub request_digest: [u8; 32],
    /// Current finalized authoritative archive record observed by the coordinator.
    pub archive: MusubiArchiveRecordV1,
    /// Stable location identity reserved for this archive.
    pub location_id: MusubiArchiveLocationIdV1,
    /// Permanent registry-grade `SoraFS` pin manifest.
    pub pin_manifest: ManifestDigest,
    /// Replication order assigned to the location.
    pub replication_order: ReplicationOrderId,
    /// Earliest renewal epoch selected for the location.
    pub renew_after_epoch: u64,
    /// Expiry epoch selected for the renewable location.
    pub expires_at_epoch: u64,
    /// Finalized retry disposition.
    pub disposition: MusubiStorageLocationDispositionV1,
}
impl MusubiStorageCoordinationResponseV1 {
    /// Validate the response against the exact authenticated request.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when the request is invalid or any archive, location,
    /// completed-provider, pin, replication, or expiry binding differs.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed storage response validator keeps all cross-field protocol invariants adjacent"
    )]
    pub fn validate_for(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        request.validate()?;
        self.archive.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
            )
        })?;
        let registered_binding = &self.archive.staging_receipt.payload.binding;
        self.archive
            .staging_receipt
            .verify(
                registered_binding,
                self.archive.staging_receipt.payload.issued_at_ms,
            )
            .map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::permanent(
                    "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
                )
            })?;
        if self.version != 1
            || self.request_digest != request.canonical_request_digest()?
            || self.archive.registration_projection()
                != request.finalized_registration.registration.clone()
            || self.location_id.is_zero()
            || self.pin_manifest.as_bytes().iter().all(|byte| *byte == 0)
            || self
                .replication_order
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.renew_after_epoch >= self.expires_at_epoch
            || request
                .prior_location_ids
                .binary_search(&self.location_id)
                .is_ok()
            || request
                .prior_location_ids
                .iter()
                .any(|location_id| self.archive.location_ids.binary_search(location_id).is_ok())
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
            ));
        }
        match &self.disposition {
            MusubiStorageLocationDispositionV1::NeedsRegistration {
                completed_providers,
                expected_location_revision,
            } => {
                if *expected_location_revision == 0
                    || *expected_location_revision != self.archive.location_revision
                    || self
                        .archive
                        .location_ids
                        .binary_search(&self.location_id)
                        .is_ok()
                    || completed_providers.len() < usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1)
                    || completed_providers.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1
                {
                    return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
                    ));
                }
                if completed_providers
                    .iter()
                    .any(|provider| provider.as_bytes() == &[0; 32])
                    || completed_providers
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                {
                    return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
                    ));
                }
            }
            MusubiStorageLocationDispositionV1::Registered(location) => {
                location.validate().map_err(|_| {
                    MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
                    )
                })?;
                if location.location_id != self.location_id
                    || location.archive_id != request.commitment.archive_id()
                    || location.state == MusubiArchiveLocationStateV1::Retired
                    || self
                        .archive
                        .location_ids
                        .binary_search(&self.location_id)
                        .is_err()
                    || location.pin_manifest != self.pin_manifest
                    || location.replication_order != self.replication_order
                    || location.renew_after_epoch != self.renew_after_epoch
                    || location.expires_at_epoch != self.expires_at_epoch
                {
                    return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_STORAGE_COORDINATION_RESPONSE_INVALID",
                    ));
                }
            }
        }
        Ok(())
    }
}
/// Exact provider-specific full-archive readback request.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiProviderReadbackRequestV1")]
pub struct MusubiProviderReadbackRequestV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Stable idempotency key for the immutable publication request.
    pub operation_id: [u8; 32],
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Account publishing the release.
    pub publisher: AccountId,
    /// Registry-policy revision of the exact successful native archive registration.
    pub expected_policy_revision: u64,
    /// Finalized immutable registration to authenticate before selecting a provider target.
    pub finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1,
    /// Exact finalized location and provider selected for readback.
    pub location: MusubiArchiveLocationV1,
    /// Provider whose endpoint must serve the complete archive.
    pub provider: ProviderId,
    /// Commitment that must be reproduced from the returned CAR.
    pub commitment: MusubiArchiveCommitmentV1,
    /// Semantic release digest that must be parsed from the returned bundle.
    pub semantic_release_digest: MusubiSemanticReleaseDigestV1,
    /// Verification-lock digest that must be parsed from the returned bundle.
    pub verification_lock_digest: MusubiVerificationLockDigestV1,
}
impl MusubiProviderReadbackRequestV1 {
    /// Validate exact location, provider, archive, and bundle bindings.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when the publisher, location, provider, commitment, or
    /// expected bundle digests are invalid.
    pub fn validate(&self) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        validate_musubi_account_id_v1(&self.publisher).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_REQUEST_INVALID",
            )
        })?;
        self.location.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_REQUEST_INVALID",
            )
        })?;
        self.commitment.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_REQUEST_INVALID",
            )
        })?;
        self.finalized_registration.validate().map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_REQUEST_INVALID",
            )
        })?;
        if self.version != 1
            || self.operation_id.iter().all(|byte| *byte == 0)
            || self.network_id.as_bytes()[31] & 1 != 1
            || self.expected_policy_revision == 0
            || self.finalized_registration.network_id != self.network_id
            || self.finalized_registration.registration.archive_id != self.commitment.archive_id()
            || self.finalized_registration.registration.commitment != self.commitment
            || self.finalized_registration.registration.registered_by != self.publisher
            || self.location.archive_id != self.commitment.archive_id()
            || self.location.finalized_height
                < self
                    .finalized_registration
                    .registration
                    .registered_at_height
            || self.location.state == MusubiArchiveLocationStateV1::Retired
            || self
                .location
                .providers
                .binary_search(&self.provider)
                .is_err()
            || self.semantic_release_digest
                != self
                    .finalized_registration
                    .registration
                    .staging_receipt
                    .payload
                    .binding
                    .semantic_release_manifest_digest
            || self.verification_lock_digest.is_zero()
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_REQUEST_INVALID",
            ));
        }
        // The finalized compact location commits the complete provider-attestation set by
        // digest. Core already exact-read and verified every immutable proof before it admitted
        // that location. Readback deliberately does not duplicate up to 64 full proofs in this
        // request; the provider must reproduce and parse the independently supplied archive
        // commitment and bundle digests instead.
        Ok(())
    }
}
/// Exact commitment evidence returned by one provider-specific readback service.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiProviderReadbackResponseV1")]
pub struct MusubiProviderReadbackResponseV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Provider through which the full CAR was read.
    pub provider: ProviderId,
    /// Finalized location used for the readback.
    pub location_id: MusubiArchiveLocationIdV1,
    /// Replication order whose completion authorized this provider.
    pub replication_order: ReplicationOrderId,
    /// Commitment reproduced by parsing and validating the complete CAR.
    pub commitment: MusubiArchiveCommitmentV1,
    /// Semantic release digest parsed from the canonical bundle.
    pub semantic_release_digest: MusubiSemanticReleaseDigestV1,
    /// Verification-lock digest parsed from the canonical bundle.
    pub verification_lock_digest: MusubiVerificationLockDigestV1,
}
impl MusubiProviderReadbackResponseV1 {
    /// Validate the response against one exact provider request.
    ///
    /// # Errors
    ///
    /// Returns a stable permanent error when any provider, location, replication, archive, or
    /// bundle-digest binding differs from the request.
    pub fn validate_for(
        &self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        if self.version != 1
            || self.provider != request.provider
            || self.location_id != request.location.location_id
            || self.replication_order != request.location.replication_order
            || self.commitment != request.commitment
            || self.semantic_release_digest != request.semantic_release_digest
            || self.verification_lock_digest != request.verification_lock_digest
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_RESPONSE_INVALID",
            ));
        }
        Ok(())
    }
}
/// Stable transport failure class without remote diagnostics or credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiPublicationRuntimeTransportFailureClassV1 {
    /// An identical idempotent request may succeed later.
    Retryable,
    /// Configuration, authorization, or response content must change.
    Permanent,
}
/// Redacted failure returned by the authenticated publication HTTPS client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MusubiPublicationRuntimeTransportErrorV1 {
    class: MusubiPublicationRuntimeTransportFailureClassV1,
    code: &'static str,
}
impl MusubiPublicationRuntimeTransportErrorV1 {
    const fn retryable(code: &'static str) -> Self {
        Self {
            class: MusubiPublicationRuntimeTransportFailureClassV1::Retryable,
            code,
        }
    }
    const fn permanent(code: &'static str) -> Self {
        Self {
            class: MusubiPublicationRuntimeTransportFailureClassV1::Permanent,
            code,
        }
    }
    /// Return whether an identical idempotent call may be retried.
    #[must_use]
    pub const fn class(&self) -> MusubiPublicationRuntimeTransportFailureClassV1 {
        self.class
    }
    /// Return the stable payload-free failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
impl fmt::Display for MusubiPublicationRuntimeTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}
impl std::error::Error for MusubiPublicationRuntimeTransportErrorV1 {}
/// Maximum future clock skew accepted by the private publication service.
pub const MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1: u64 = 30_000;
/// Maximum number of append-only location transaction generations in one publication operation.
pub const MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1: usize = 8;
fn storage_generation_target(generation: u8) -> [u8; 32] {
    let mut target = [0_u8; 32];
    target[0] = generation;
    target
}
fn valid_storage_generation_target(target: [u8; 32]) -> bool {
    target[0] > 0
        && usize::from(target[0]) <= MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1
        && target[1..].iter().all(|byte| *byte == 0)
}
fn provider_readback_target(location: &MusubiArchiveLocationV1, provider: ProviderId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVIDER_READBACK_TARGET_DOMAIN_V1);
    hasher.update(location.location_id.as_bytes());
    hasher.update(&location.revision.to_le_bytes());
    hasher.update(provider.as_bytes());
    *hasher.finalize().as_bytes()
}
fn maximum_historical_readbacks_per_operation() -> usize {
    let bound = MUSUBI_MAX_ARCHIVE_LOCATIONS_V1
        .checked_mul(MUSUBI_MAX_LOCATION_PROVIDERS_V1)
        .expect("Musubi readback history bound is a fixed small constant");
    debug_assert!(
        bound
            >= MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1
                .checked_mul(2)
                .expect("publication readback minimum is fixed")
    );
    bound
}
/// Exact private path for authenticated seed ingress.
pub const MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1: &str = "/v1/musubi/publication/seed-ingress";
/// Exact private path for permanent-pin and replication coordination.
pub const MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1: &str =
    "/v1/musubi/publication/storage-coordinate";
/// Exact private path for provider-specific full-archive readback.
pub const MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1: &str =
    "/v1/musubi/publication/provider-readback";
/// One of the three closed private publication routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MusubiPublicationPrivateRouteV1 {
    /// Authenticate, verify, and stage one framed canonical plan and exact CAR.
    SeedIngress,
    /// Coordinate a permanent pin and finalized replication order.
    StorageCoordination,
    /// Verify a complete archive through one exact provider.
    ProviderReadback,
}
impl MusubiPublicationPrivateRouteV1 {
    /// Parse an exact private route path without prefix or suffix matching.
    #[must_use]
    pub fn parse(path: &str) -> Option<Self> {
        match path {
            MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1 => Some(Self::SeedIngress),
            MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1 => Some(Self::StorageCoordination),
            MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1 => Some(Self::ProviderReadback),
            _ => None,
        }
    }
    /// Return the exact private route path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::SeedIngress => MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
            Self::StorageCoordination => MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
            Self::ProviderReadback => MUSUBI_PUBLICATION_PROVIDER_READBACK_PATH_V1,
        }
    }
}
/// Secret-free wire error returned by the private publication service.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationServiceErrorCodeV1")]
pub enum MusubiPublicationServiceErrorCodeV1 {
    /// The request did not select one exact fixed route.
    #[codec(index = 0)]
    RouteNotFound,
    /// The route's fixed request media type was not used.
    #[codec(index = 1)]
    MediaTypeInvalid,
    /// The authorization header was absent, malformed, noncanonical, or too large.
    #[codec(index = 2)]
    AuthorizationInvalid,
    /// The authorization is expired or outside the bounded clock-skew window.
    #[codec(index = 3)]
    AuthorizationExpired,
    /// The exact authorization was replayed before an idempotent result existed.
    #[codec(index = 4)]
    AuthorizationReplay,
    /// The request body or seed metadata was malformed, noncanonical, or too large.
    #[codec(index = 5)]
    RequestInvalid,
    /// The network, publisher, broker, provider, or operation binding differs.
    #[codec(index = 6)]
    IdentityMismatch,
    /// The framed plan or exact CAR differs from the authenticated binding.
    #[codec(index = 7)]
    CarBodyMismatch,
    /// An operation id was reused with different immutable request material.
    #[codec(index = 8)]
    OperationConflict,
    /// An identical operation is already being processed.
    #[codec(index = 9)]
    OperationBusy,
    /// The durable replay/idempotency journal is unavailable or full.
    #[codec(index = 10)]
    JournalUnavailable,
    /// The admitted seed-ingress backend could not stage the exact CAR.
    #[codec(index = 11)]
    SeedIngressUnavailable,
    /// The permanent-pin or replication coordinator could not complete.
    #[codec(index = 12)]
    StorageCoordinationUnavailable,
    /// The selected provider could not produce verified full-archive readback.
    #[codec(index = 13)]
    ProviderReadbackUnavailable,
    /// The injected broker signer could not issue the exact receipt.
    #[codec(index = 14)]
    ReceiptSigningUnavailable,
    /// An injected backend returned evidence that did not match its request.
    #[codec(index = 15)]
    BackendResponseInvalid,
    /// The service could not canonically encode its bounded response.
    #[codec(index = 16)]
    ResponseEncodingFailed,
    /// A method other than exact uppercase `POST` selected a private route.
    #[codec(index = 17)]
    MethodInvalid,
    /// The trusted service clock failed or regressed.
    #[codec(index = 18)]
    TrustedClockUnavailable,
}
impl MusubiPublicationServiceErrorCodeV1 {
    /// Return a stable payload-free diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RouteNotFound => "MUSUBI_PUBLICATION_ROUTE_NOT_FOUND",
            Self::MediaTypeInvalid => "MUSUBI_PUBLICATION_MEDIA_TYPE_INVALID",
            Self::AuthorizationInvalid => "MUSUBI_PUBLICATION_AUTHORIZATION_INVALID",
            Self::AuthorizationExpired => "MUSUBI_PUBLICATION_AUTHORIZATION_EXPIRED",
            Self::AuthorizationReplay => "MUSUBI_PUBLICATION_AUTHORIZATION_REPLAY",
            Self::RequestInvalid => "MUSUBI_PUBLICATION_REQUEST_INVALID",
            Self::IdentityMismatch => "MUSUBI_PUBLICATION_IDENTITY_MISMATCH",
            Self::CarBodyMismatch => "MUSUBI_PUBLICATION_CAR_BODY_MISMATCH",
            Self::OperationConflict => "MUSUBI_PUBLICATION_OPERATION_CONFLICT",
            Self::OperationBusy => "MUSUBI_PUBLICATION_OPERATION_BUSY",
            Self::JournalUnavailable => "MUSUBI_PUBLICATION_JOURNAL_UNAVAILABLE",
            Self::SeedIngressUnavailable => "MUSUBI_PUBLICATION_SEED_INGRESS_UNAVAILABLE",
            Self::StorageCoordinationUnavailable => {
                "MUSUBI_PUBLICATION_STORAGE_COORDINATION_UNAVAILABLE"
            }
            Self::ProviderReadbackUnavailable => "MUSUBI_PUBLICATION_PROVIDER_READBACK_UNAVAILABLE",
            Self::ReceiptSigningUnavailable => "MUSUBI_PUBLICATION_RECEIPT_SIGNING_UNAVAILABLE",
            Self::BackendResponseInvalid => "MUSUBI_PUBLICATION_BACKEND_RESPONSE_INVALID",
            Self::ResponseEncodingFailed => "MUSUBI_PUBLICATION_RESPONSE_ENCODING_FAILED",
            Self::MethodInvalid => "MUSUBI_PUBLICATION_METHOD_INVALID",
            Self::TrustedClockUnavailable => "MUSUBI_PUBLICATION_TRUSTED_CLOCK_UNAVAILABLE",
        }
    }
}
/// Canonical bounded error response for every private publication route.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationServiceErrorResponseV1")]
pub struct MusubiPublicationServiceErrorResponseV1 {
    /// Closed response schema version; always one.
    pub version: u8,
    /// Typed stable error code with no remote or credential material.
    pub code: MusubiPublicationServiceErrorCodeV1,
    /// Whether a newly authorized identical request may succeed later.
    pub retryable: bool,
}
/// Transport-neutral private HTTP request passed by a deployment-owned HTTPS ingress.
#[derive(Clone, Copy)]
pub struct MusubiPublicationPrivateHttpRequestV1<'a> {
    /// Exact uppercase HTTP method; V1 accepts only `POST`.
    pub method: &'a str,
    /// Exact one of the three `/v1/musubi/publication/...` paths, without a mount prefix.
    pub path: &'a str,
    /// Exact `Content-Type` header value.
    pub content_type: &'a str,
    /// URL-safe, unpadded base64 canonical authorization header.
    pub authorization: Option<&'a str>,
    /// URL-safe, unpadded base64 canonical seed metadata header.
    pub seed_ingress_metadata: Option<&'a str>,
    /// Exact bounded request body.
    pub body: &'a [u8],
}
impl fmt::Debug for MusubiPublicationPrivateHttpRequestV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiPublicationPrivateHttpRequestV1")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("content_type", &self.content_type)
            .field("authorization_present", &self.authorization.is_some())
            .field(
                "seed_ingress_metadata_length",
                &self.seed_ingress_metadata.map(str::len),
            )
            .field("body_length", &self.body.len())
            .finish()
    }
}
/// Transport-neutral private HTTP response emitted by the service core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MusubiPublicationPrivateHttpResponseV1 {
    /// HTTP status code selected without exposing backend details.
    pub status: u16,
    /// Fixed response media type.
    pub content_type: &'static str,
    /// Canonical bounded Norito success or error body.
    pub body: Vec<u8>,
}
/// Public, non-secret identity constraints for one private publication service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MusubiPublicationServiceConfigurationV1 {
    /// Exact deployment identity accepted by every request.
    pub network_id: NetworkId,
    /// Account whose controller signs seed-ingress receipts.
    pub ingress_broker: AccountId,
    /// Exact admitted provider served by seed ingress.
    pub seed_provider: ProviderId,
    /// Maximum publisher-clock lead accepted by authorization verification.
    pub max_future_clock_skew_ms: u64,
    /// Positive lifetime assigned to broker-signed staging receipts.
    pub receipt_lifetime_ms: u64,
}
impl MusubiPublicationServiceConfigurationV1 {
    fn validate(&self) -> Result<(), MusubiPublicationServiceErrorCodeV1> {
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.seed_provider.as_bytes().iter().all(|byte| *byte == 0)
            || self.max_future_clock_skew_ms > MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1
            || self.receipt_lifetime_ms == 0
            || self.receipt_lifetime_ms > MUSUBI_MAX_SEED_INGRESS_RECEIPT_LIFETIME_MS_V1
            || !controller_fits_publication_approval_bound(&self.ingress_broker)
        {
            return Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch);
        }
        Ok(())
    }
}
/// Stable deployment identity durably bound by a publication-service journal.
///
/// Timing policy is intentionally excluded so operators can adjust authorization skew or receipt
/// lifetime without discarding immutable replay/idempotency history.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationServiceJournalBindingV1")]
pub struct MusubiPublicationServiceJournalBindingV1 {
    /// Exact deployment identity accepted by every retained operation.
    pub network_id: NetworkId,
    /// Account whose controller signs retained seed-ingress receipts.
    pub ingress_broker: AccountId,
    /// Exact admitted seed provider for this private service.
    pub seed_provider: ProviderId,
}
impl MusubiPublicationServiceJournalBindingV1 {
    /// Derive the durable identity boundary from one service configuration.
    #[must_use]
    pub fn from_configuration(configuration: &MusubiPublicationServiceConfigurationV1) -> Self {
        Self {
            network_id: configuration.network_id,
            ingress_broker: configuration.ingress_broker.clone(),
            seed_provider: configuration.seed_provider,
        }
    }
    fn validate(&self) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.seed_provider.as_bytes().iter().all(|byte| *byte == 0)
            || !controller_fits_publication_approval_bound(&self.ingress_broker)
            || norito::encode_canonical(self)
                .ok()
                .is_none_or(|encoded| encoded.len() > MAX_SEED_INGRESS_METADATA_BYTES)
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Invalid);
        }
        Ok(())
    }
}
fn controller_fits_publication_approval_bound(account: &AccountId) -> bool {
    if validate_musubi_account_id_v1(account).is_err() {
        return false;
    }
    let AccountController::Multisig(policy) = account.controller() else {
        return true;
    };
    // `AccountId`'s generic Norito decode reconstructs its controller directly. Re-run the
    // policy constructor here so a canonical but structurally invalid wire policy cannot turn a
    // zero/duplicate/unsupported controller into publication authority.
    if MultisigPolicy::from_serialized(
        policy.version(),
        policy.threshold(),
        policy.members().to_vec(),
    )
    .is_err()
    {
        return false;
    }
    // Keep only the largest weights that could fit in one bounded publication approval set. This
    // is fixed-memory even if a deployment supplies a policy with an unusually large member set.
    let mut largest_weights = [0_u16; MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1];
    for member in policy.members() {
        let weight = member.weight();
        let Some(insert_at) = largest_weights
            .iter()
            .position(|existing| weight > *existing)
        else {
            continue;
        };
        for index in (insert_at + 1..largest_weights.len()).rev() {
            largest_weights[index] = largest_weights[index - 1];
        }
        largest_weights[insert_at] = weight;
    }
    largest_weights.into_iter().map(u32::from).sum::<u32>() >= u32::from(policy.threshold())
}
/// Backend failure class deliberately carrying no provider diagnostics or secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiPublicationServiceBackendErrorV1 {
    /// A newly authorized identical request may succeed later.
    Retryable,
    /// Deployment configuration or immutable backend state must change.
    Permanent,
}
impl fmt::Display for MusubiPublicationServiceBackendErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Retryable => "Musubi publication backend is temporarily unavailable",
            Self::Permanent => "Musubi publication backend requires configuration or state changes",
        })
    }
}
impl std::error::Error for MusubiPublicationServiceBackendErrorV1 {}

/// Admitted backend that durably stages an already verified exact CAR.
pub trait MusubiSeedIngressBackendV1: Send {
    /// Return the exact admitted provider served by this backend instance.
    ///
    /// The service constructor compares this identity with its public configuration before
    /// accepting traffic, so an injected backend cannot silently stage for another provider.
    fn provider_id(&self) -> ProviderId;
    /// Stage or idempotently reuse one exact operation and receipt binding.
    ///
    /// # Errors
    ///
    /// Returns a closed retryable or permanent backend failure when the exact CAR cannot be
    /// durably staged or reused.
    fn stage_exact_car(
        &mut self,
        operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1>;
    /// Re-read the retained exact CAR before replaying a completed journal receipt.
    ///
    /// This check must not recreate a missing record: a completed receipt only remains usable
    /// while its original durable seed custody is still intact.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if the retained operation, binding, plan, or CAR is absent,
    /// substituted, or temporarily unreadable.
    fn verify_staged_car(
        &self,
        operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1>;
}
mod storage_authorization;
pub use storage_authorization::VerifiedStorageCoordinationRequestV1;

/// Backend coordinating permanent pins, replication, and finalized provider completions.
pub trait MusubiStorageCoordinationBackendV1: Send {
    /// Recheck current finalized registration before replaying a cached response.
    ///
    /// This read-only check must neither pin nor submit a replication order. A response
    /// retained in the journal is not evidence that its registration remains in the
    /// daemon's current finalized State and Kura history.
    ///
    /// # Errors
    /// Refuses absent, substituted, or locally unavailable finalized registration.
    fn verify_current_registration(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1>;
    /// Coordinate or idempotently return evidence for one exact immutable request.
    ///
    /// The backend must independently retrieve the exact transaction, prove that its sole
    /// instruction is the matching archive registration finalized by the named snapshot, then
    /// match the immutable registration projection against a finalized archive read at that or a
    /// later snapshot. The authenticated publisher request binds those bytes but is not itself a
    /// finality proof. Mutable location fields are returned from the backend's current read and
    /// are deliberately excluded from the historical registration evidence.
    /// The verified request carries this call's original UTC and monotonic bounds. Retain the
    /// first accepted operation's finite lifetime and configured spending limits before paid
    /// work; retries cannot replace them. Recheck the original limits before every effect.
    ///
    /// # Errors
    ///
    /// Returns a closed retryable or permanent backend failure when pinning, replication, or
    /// finalized evidence retrieval cannot complete.
    fn coordinate_storage(
        &mut self,
        request: &VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1>;
}
/// Backend performing complete provider-specific archive and bundle verification.
pub trait MusubiProviderReadbackBackendV1: Send {
    /// Recheck the current finalized location, provider authority, and admitted endpoint before
    /// replaying an earlier complete readback from the journal.
    ///
    /// This read-only check must not fetch a CAR or mutate provider state. A historical readback
    /// response alone cannot establish that its target remains currently admitted.
    ///
    /// # Errors
    /// Returns a closed retryable or permanent failure when the current target cannot be proven.
    fn verify_current_target(
        &self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1>;
    /// Read, parse, and verify one exact committed CAR through the selected provider.
    ///
    /// # Errors
    ///
    /// Returns a closed retryable or permanent backend failure when the selected provider cannot
    /// reproduce and verify the complete archive.
    fn readback_provider(
        &mut self,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1>;
}
/// Immutable operation-wide binding enforced across all three private routes.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationOperationBindingV1")]
pub struct MusubiPublicationOperationBindingV1 {
    /// Stable publisher-selected operation id.
    pub operation_id: [u8; 32],
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Exact publisher identity.
    pub publisher: AccountId,
    /// Derived immutable archive identity.
    pub archive_id: ArchiveId,
    /// Digest of the exact canonical CAR.
    pub car_body_digest: MusubiContentDigestV1,
    /// Length of the exact canonical CAR.
    pub car_body_length: u64,
}
impl MusubiPublicationOperationBindingV1 {
    fn validate(&self) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        if self.operation_id.iter().all(|byte| *byte == 0)
            || self.network_id.as_bytes()[31] & 1 != 1
            || validate_musubi_account_id_v1(&self.publisher).is_err()
            || self.archive_id.is_zero()
            || self.car_body_digest.is_zero()
            || self.car_body_length == 0
            || self.car_body_length > MUSUBI_MAX_CAR_BYTES_V1
            || norito::encode_canonical(self)
                .ok()
                .is_none_or(|encoded| encoded.len() > MAX_SEED_INGRESS_METADATA_BYTES)
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Invalid);
        }
        Ok(())
    }
}
/// Canonical key for one idempotent route result within a publication operation.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha::musubi_runtime::MusubiPublicationIdempotencyKeyV1")]
pub struct MusubiPublicationIdempotencyKeyV1 {
    /// Exact private operation.
    pub operation: MusubiPublicationRuntimeOperationV1,
    /// Stable publisher-selected operation id.
    pub operation_id: [u8; 32],
    /// Route-specific target: zero for ingress, one-based location generation for storage
    /// coordination, or the exact location-ID/revision/provider digest for readback.
    pub target: [u8; 32],
}
/// Atomic journal attempt binding authorization replay to immutable operation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MusubiPublicationJournalAttemptV1 {
    /// Exact idempotent route key.
    pub key: MusubiPublicationIdempotencyKeyV1,
    /// Operation-wide immutable commitment.
    pub binding: MusubiPublicationOperationBindingV1,
    /// Domain-separated digest of the exact canonical typed request.
    pub request_digest: [u8; 32],
    /// Digest of the complete canonical signed authorization.
    pub authorization_digest: [u8; 32],
    /// Inclusive expiry used to bound replay retention.
    pub authorization_expires_at_ms: u64,
}
/// Result of atomically beginning one journaled service attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MusubiPublicationJournalBeginV1 {
    /// This caller owns the new in-flight attempt and may invoke a backend.
    Execute,
    /// The exact request already completed; return these canonical response bytes.
    Cached(Vec<u8>),
}
/// Stable journal failure with no filesystem, database, or credential details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiPublicationServiceJournalErrorV1 {
    /// The request binding or digest is structurally invalid.
    Invalid,
    /// An operation or route key was reused with substituted immutable material.
    Conflict,
    /// The exact authorization was already consumed by an unfinished attempt.
    Replay,
    /// Another caller owns the exact in-flight attempt.
    Busy,
    /// The bounded journal has no safe capacity for a new operation.
    Capacity,
    /// Durable journal state could not be read or committed.
    Unavailable,
}
/// Durable atomic replay and idempotency boundary required by production services.
///
/// A crash-safe implementation must recover an interrupted fresh attempt as an aborted
/// request-digest tombstone and an interrupted seed-receipt refresh as its retained prior
/// completed response before accepting traffic. Authorization digests already consumed by either
/// attempt remain consumed through their expiry.
pub trait MusubiPublicationServiceJournalV1: Send {
    /// Return the exact deployment identity bound by every retained record.
    fn deployment_binding(&self) -> &MusubiPublicationServiceJournalBindingV1;
    /// Atomically validate the operation binding and detect a cached result before reserving a
    /// new attempt and consuming its authorization digest. Cached seed receipts must remain
    /// available to [`Self::refresh_expired_seed_receipt`] with that same fresh authorization.
    ///
    /// # Errors
    ///
    /// Returns a stable journal error for invalid or conflicting bindings, replay, contention,
    /// exhausted capacity, or unavailable durable state.
    fn begin(
        &mut self,
        attempt: &MusubiPublicationJournalAttemptV1,
        current_time_ms: u64,
    ) -> Result<MusubiPublicationJournalBeginV1, MusubiPublicationServiceJournalErrorV1>;
    /// Atomically reopen an exact completed seed-ingress result after its receipt expired.
    ///
    /// The implementation must compare `expected_response`, consume the fresh authorization,
    /// and retain the prior completed response so [`Self::abort`] can restore it on failure.
    ///
    /// # Errors
    ///
    /// Returns a stable journal error when the completed response cannot be reopened atomically or
    /// the new authorization cannot be consumed.
    fn refresh_expired_seed_receipt(
        &mut self,
        attempt: &MusubiPublicationJournalAttemptV1,
        expected_response: &[u8],
        current_time_ms: u64,
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1>;
    /// Atomically persist the canonical successful response for the reserved attempt.
    ///
    /// # Errors
    ///
    /// Returns a stable journal error when the reservation conflicts, the response is invalid, or
    /// durable state cannot be committed.
    fn commit(
        &mut self,
        key: MusubiPublicationIdempotencyKeyV1,
        request_digest: [u8; 32],
        response: &[u8],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1>;
    /// Release an unfinished reservation while retaining its request-digest tombstone and
    /// consumed-authorization replay state.
    ///
    /// # Errors
    ///
    /// Returns a stable journal error when the reservation conflicts or durable state cannot be
    /// committed.
    fn abort(
        &mut self,
        key: MusubiPublicationIdempotencyKeyV1,
        request_digest: [u8; 32],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum InMemoryPublicationResultV1 {
    Pending([u8; 32]),
    Aborted([u8; 32]),
    Refreshing {
        request_digest: [u8; 32],
        previous_response: Vec<u8>,
    },
    Complete {
        request_digest: [u8; 32],
        response: Vec<u8>,
    },
}
/// Bounded process-local journal intended for tests and ephemeral development services.
///
/// Production deployments must inject a crash-safe implementation of
/// [`MusubiPublicationServiceJournalV1`]; this type deliberately makes no durability claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InMemoryMusubiPublicationServiceJournalV1 {
    binding: MusubiPublicationServiceJournalBindingV1,
    max_operations: usize,
    max_results: usize,
    max_authorizations: usize,
    operation_bindings: BTreeMap<[u8; 32], MusubiPublicationOperationBindingV1>,
    results: BTreeMap<MusubiPublicationIdempotencyKeyV1, InMemoryPublicationResultV1>,
    authorization_expiry: BTreeMap<[u8; 32], u64>,
    expiry_index: BTreeSet<(u64, [u8; 32])>,
}
impl InMemoryMusubiPublicationServiceJournalV1 {
    /// Construct a bounded ephemeral journal.
    ///
    /// # Errors
    ///
    /// Returns [`MusubiPublicationServiceJournalErrorV1::Invalid`] when the deployment binding is
    /// invalid, either bound is zero, or the protocol-derived result capacity overflows the
    /// platform size.
    pub fn new(
        binding: MusubiPublicationServiceJournalBindingV1,
        max_operations: usize,
        max_authorizations: usize,
    ) -> Result<Self, MusubiPublicationServiceJournalErrorV1> {
        binding.validate()?;
        if max_operations == 0 || max_authorizations == 0 {
            return Err(MusubiPublicationServiceJournalErrorV1::Invalid);
        }
        let max_results = max_operations
            .checked_mul(
                maximum_historical_readbacks_per_operation()
                    .saturating_add(1)
                    .saturating_add(MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1),
            )
            .ok_or(MusubiPublicationServiceJournalErrorV1::Invalid)?;
        Ok(Self {
            binding,
            max_operations,
            max_results,
            max_authorizations,
            operation_bindings: BTreeMap::new(),
            results: BTreeMap::new(),
            authorization_expiry: BTreeMap::new(),
            expiry_index: BTreeSet::new(),
        })
    }
    fn prune_authorizations(&mut self, current_time_ms: u64) {
        let expired = self
            .expiry_index
            .range(..(current_time_ms, [0_u8; 32]))
            .copied()
            .collect::<Vec<_>>();
        for entry @ (_, digest) in expired {
            self.expiry_index.remove(&entry);
            self.authorization_expiry.remove(&digest);
        }
    }
    fn validate_attempt(
        &self,
        attempt: &MusubiPublicationJournalAttemptV1,
        current_time_ms: u64,
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        attempt.binding.validate()?;
        if current_time_ms == 0
            || attempt.binding.network_id != self.binding.network_id
            || attempt.key.operation_id != attempt.binding.operation_id
            || match attempt.key.operation {
                MusubiPublicationRuntimeOperationV1::ProviderReadback => {
                    attempt.key.target.iter().all(|byte| *byte == 0)
                }
                MusubiPublicationRuntimeOperationV1::SeedIngress => {
                    attempt.key.target.iter().any(|byte| *byte != 0)
                }
                MusubiPublicationRuntimeOperationV1::StorageCoordination => {
                    !valid_storage_generation_target(attempt.key.target)
                }
            }
            || attempt.request_digest.iter().all(|byte| *byte == 0)
            || attempt.authorization_digest.iter().all(|byte| *byte == 0)
            || attempt.authorization_expires_at_ms == 0
            || attempt.authorization_expires_at_ms < current_time_ms
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Invalid);
        }
        Ok(())
    }
    fn consume_authorization(
        &mut self,
        attempt: &MusubiPublicationJournalAttemptV1,
        current_time_ms: u64,
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        self.prune_authorizations(current_time_ms);
        if self
            .authorization_expiry
            .contains_key(&attempt.authorization_digest)
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Replay);
        }
        if self.authorization_expiry.len() >= self.max_authorizations {
            return Err(MusubiPublicationServiceJournalErrorV1::Capacity);
        }
        self.authorization_expiry.insert(
            attempt.authorization_digest,
            attempt.authorization_expires_at_ms,
        );
        self.expiry_index.insert((
            attempt.authorization_expires_at_ms,
            attempt.authorization_digest,
        ));
        Ok(())
    }
}
impl MusubiPublicationServiceJournalV1 for InMemoryMusubiPublicationServiceJournalV1 {
    fn deployment_binding(&self) -> &MusubiPublicationServiceJournalBindingV1 {
        &self.binding
    }
    fn begin(
        &mut self,
        attempt: &MusubiPublicationJournalAttemptV1,
        current_time_ms: u64,
    ) -> Result<MusubiPublicationJournalBeginV1, MusubiPublicationServiceJournalErrorV1> {
        self.validate_attempt(attempt, current_time_ms)?;
        if let Some(existing) = self.operation_bindings.get(&attempt.binding.operation_id) {
            if existing != &attempt.binding {
                return Err(MusubiPublicationServiceJournalErrorV1::Conflict);
            }
        } else if self.operation_bindings.len() >= self.max_operations {
            return Err(MusubiPublicationServiceJournalErrorV1::Capacity);
        }
        let retrying_aborted = if let Some(existing) = self.results.get(&attempt.key) {
            match existing {
                InMemoryPublicationResultV1::Pending(request_digest)
                | InMemoryPublicationResultV1::Refreshing { request_digest, .. } => {
                    if request_digest == &attempt.request_digest {
                        return Err(MusubiPublicationServiceJournalErrorV1::Busy);
                    }
                    return Err(MusubiPublicationServiceJournalErrorV1::Conflict);
                }
                InMemoryPublicationResultV1::Aborted(request_digest) => {
                    if request_digest != &attempt.request_digest {
                        return Err(MusubiPublicationServiceJournalErrorV1::Conflict);
                    }
                    true
                }
                InMemoryPublicationResultV1::Complete {
                    request_digest,
                    response,
                } => {
                    if request_digest == &attempt.request_digest {
                        return Ok(MusubiPublicationJournalBeginV1::Cached(response.clone()));
                    }
                    return Err(MusubiPublicationServiceJournalErrorV1::Conflict);
                }
            }
        } else {
            false
        };
        if !retrying_aborted && self.results.len() >= self.max_results {
            return Err(MusubiPublicationServiceJournalErrorV1::Capacity);
        }
        if !retrying_aborted
            && attempt.key.operation == MusubiPublicationRuntimeOperationV1::ProviderReadback
            && self
                .results
                .keys()
                .filter(|key| {
                    key.operation_id == attempt.key.operation_id
                        && key.operation == MusubiPublicationRuntimeOperationV1::ProviderReadback
                })
                .count()
                >= maximum_historical_readbacks_per_operation()
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Capacity);
        }
        if !retrying_aborted
            && attempt.key.operation == MusubiPublicationRuntimeOperationV1::StorageCoordination
            && self
                .results
                .keys()
                .filter(|key| {
                    key.operation_id == attempt.key.operation_id
                        && key.operation == MusubiPublicationRuntimeOperationV1::StorageCoordination
                })
                .count()
                >= MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Capacity);
        }
        self.consume_authorization(attempt, current_time_ms)?;
        self.operation_bindings
            .entry(attempt.binding.operation_id)
            .or_insert_with(|| attempt.binding.clone());
        self.results.insert(
            attempt.key,
            InMemoryPublicationResultV1::Pending(attempt.request_digest),
        );
        Ok(MusubiPublicationJournalBeginV1::Execute)
    }
    fn refresh_expired_seed_receipt(
        &mut self,
        attempt: &MusubiPublicationJournalAttemptV1,
        expected_response: &[u8],
        current_time_ms: u64,
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        self.validate_attempt(attempt, current_time_ms)?;
        if attempt.key.operation != MusubiPublicationRuntimeOperationV1::SeedIngress
            || expected_response.is_empty()
            || expected_response.len() > MAX_CONTROL_RESPONSE_BYTES
        {
            return Err(MusubiPublicationServiceJournalErrorV1::Invalid);
        }
        if self.operation_bindings.get(&attempt.binding.operation_id) != Some(&attempt.binding) {
            return Err(MusubiPublicationServiceJournalErrorV1::Conflict);
        }
        let previous_response = match self.results.get(&attempt.key) {
            Some(InMemoryPublicationResultV1::Complete {
                request_digest,
                response,
            }) if *request_digest == attempt.request_digest && response == expected_response => {
                response.clone()
            }
            Some(InMemoryPublicationResultV1::Complete { request_digest, .. })
                if *request_digest != attempt.request_digest =>
            {
                return Err(MusubiPublicationServiceJournalErrorV1::Conflict);
            }
            Some(
                InMemoryPublicationResultV1::Complete { .. }
                | InMemoryPublicationResultV1::Pending(_)
                | InMemoryPublicationResultV1::Aborted(_)
                | InMemoryPublicationResultV1::Refreshing { .. },
            ) => {
                return Err(MusubiPublicationServiceJournalErrorV1::Busy);
            }
            None => return Err(MusubiPublicationServiceJournalErrorV1::Conflict),
        };
        self.consume_authorization(attempt, current_time_ms)?;
        self.results.insert(
            attempt.key,
            InMemoryPublicationResultV1::Refreshing {
                request_digest: attempt.request_digest,
                previous_response,
            },
        );
        Ok(())
    }
    fn commit(
        &mut self,
        key: MusubiPublicationIdempotencyKeyV1,
        request_digest: [u8; 32],
        response: &[u8],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        if response.is_empty() || response.len() > MAX_CONTROL_RESPONSE_BYTES {
            return Err(MusubiPublicationServiceJournalErrorV1::Invalid);
        }
        let Some(existing) = self.results.get_mut(&key) else {
            return Err(MusubiPublicationServiceJournalErrorV1::Unavailable);
        };
        match existing {
            InMemoryPublicationResultV1::Pending(existing_digest)
                if *existing_digest == request_digest =>
            {
                *existing = InMemoryPublicationResultV1::Complete {
                    request_digest,
                    response: response.to_vec(),
                };
                Ok(())
            }
            InMemoryPublicationResultV1::Refreshing {
                request_digest: existing_digest,
                ..
            } if *existing_digest == request_digest => {
                *existing = InMemoryPublicationResultV1::Complete {
                    request_digest,
                    response: response.to_vec(),
                };
                Ok(())
            }
            InMemoryPublicationResultV1::Complete {
                request_digest: existing_digest,
                response: existing_response,
            } if *existing_digest == request_digest && existing_response == response => Ok(()),
            _ => Err(MusubiPublicationServiceJournalErrorV1::Conflict),
        }
    }
    fn abort(
        &mut self,
        key: MusubiPublicationIdempotencyKeyV1,
        request_digest: [u8; 32],
    ) -> Result<(), MusubiPublicationServiceJournalErrorV1> {
        match self.results.get(&key) {
            Some(InMemoryPublicationResultV1::Pending(existing)) if *existing == request_digest => {
                self.results
                    .insert(key, InMemoryPublicationResultV1::Aborted(request_digest));
                Ok(())
            }
            Some(InMemoryPublicationResultV1::Aborted(existing)) if *existing == request_digest => {
                Ok(())
            }
            Some(InMemoryPublicationResultV1::Complete {
                request_digest: existing,
                ..
            }) if *existing == request_digest => Ok(()),
            Some(InMemoryPublicationResultV1::Refreshing {
                request_digest: existing,
                previous_response,
            }) if *existing == request_digest => {
                let previous_response = previous_response.clone();
                self.results.insert(
                    key,
                    InMemoryPublicationResultV1::Complete {
                        request_digest,
                        response: previous_response,
                    },
                );
                Ok(())
            }
            Some(
                InMemoryPublicationResultV1::Pending(_)
                | InMemoryPublicationResultV1::Aborted(_)
                | InMemoryPublicationResultV1::Refreshing { .. }
                | InMemoryPublicationResultV1::Complete { .. },
            ) => Err(MusubiPublicationServiceJournalErrorV1::Conflict),
            None => Ok(()),
        }
    }
}
/// Deployment-owned signing boundary for one exact seed-ingress receipt payload.
///
/// Implementations may call a deployment-owned signing or threshold collection service. They
/// return only controller approvals: the publication service constructs the payload and lifetime,
/// then verifies the assembled receipt before committing it to the replay journal. This prevents a
/// signer implementation from substituting any chain, publisher, archive, body, nonce, or expiry
/// field.
pub trait MusubiSeedIngressReceiptSigningProviderV1: Send {
    /// Exact broker account controlled by this signing provider.
    fn broker(&self) -> &AccountId;
    /// Sign the exact service-constructed payload with the broker controller.
    ///
    /// # Errors
    ///
    /// Returns a redacted retryable failure for a transient signer outage or a permanent failure
    /// when deployment policy cannot sign the payload. Returned approvals are independently
    /// verified by the service. Remote adapters should use `payload.expires_at_ms` as the signing
    /// call deadline so work that cannot produce a live receipt is cancelled promptly.
    fn sign_approvals(
        &mut self,
        payload: &MusubiSeedIngressReceiptPayloadV1,
    ) -> Result<Vec<MusubiSeedIngressReceiptApprovalV1>, MusubiPublicationServiceBackendErrorV1>;
}
/// Trusted wall-clock boundary used for authorization and receipt freshness.
///
/// Production implementations must persist or otherwise enforce a non-regressing time floor
/// across service restarts. The service additionally rejects regressions observed during one
/// process lifetime.
pub trait MusubiPublicationServiceClockV1: Send {
    /// Return current Unix time in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend failure when the trusted clock cannot be sampled.
    fn current_time_ms(&mut self) -> Result<u64, MusubiPublicationServiceBackendErrorV1>;
}
/// Raw system wall clock for qualified private-publication service runners.
///
/// This adapter does not itself persist a high-water mark. A production platform may use it only
/// when its clock is rollback-resistant across process restarts; otherwise it must inject a clock
/// backed by a durable time floor.
#[derive(Clone, Copy, Debug, Default)]
pub struct MusubiPublicationSystemClockV1;
impl MusubiPublicationServiceClockV1 for MusubiPublicationSystemClockV1 {
    fn current_time_ms(&mut self) -> Result<u64, MusubiPublicationServiceBackendErrorV1> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MusubiPublicationServiceBackendErrorV1::Retryable)
            .and_then(|elapsed| {
                u64::try_from(elapsed.as_millis())
                    .map_err(|_| MusubiPublicationServiceBackendErrorV1::Permanent)
            })
    }
}
/// Runtime-only software signing adapter for a single-controller ingress broker.
///
/// Production deployments should inject an authenticated implementation of
/// [`MusubiSeedIngressReceiptSigningProviderV1`] whose custody boundary meets
/// their policy. This adapter exists for focused tests and explicitly
/// controlled development deployments.
pub struct SoftwareMusubiSeedIngressReceiptSignerV1 {
    broker: AccountId,
    key_pair: KeyPair,
}
impl fmt::Debug for SoftwareMusubiSeedIngressReceiptSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareMusubiSeedIngressReceiptSignerV1")
            .field("broker", &self.broker)
            .finish_non_exhaustive()
    }
}
impl SoftwareMusubiSeedIngressReceiptSignerV1 {
    /// Construct from deployment-owned key material that exactly controls the broker account.
    ///
    /// # Errors
    ///
    /// Returns an identity error when the account is multisig or the key does not control it.
    pub fn new(
        broker: AccountId,
        key_pair: KeyPair,
    ) -> Result<Self, MusubiPublicationServiceErrorCodeV1> {
        let AccountController::Single(expected_key) = broker.controller() else {
            return Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch);
        };
        if expected_key != key_pair.public_key() {
            return Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch);
        }
        Ok(Self { broker, key_pair })
    }
}
impl MusubiSeedIngressReceiptSigningProviderV1 for SoftwareMusubiSeedIngressReceiptSignerV1 {
    fn broker(&self) -> &AccountId {
        &self.broker
    }
    fn sign_approvals(
        &mut self,
        payload: &MusubiSeedIngressReceiptPayloadV1,
    ) -> Result<Vec<MusubiSeedIngressReceiptApprovalV1>, MusubiPublicationServiceBackendErrorV1>
    {
        if payload.binding.ingress_broker != self.broker {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        let signature =
            SignatureOf::try_from_hash(self.key_pair.private_key(), payload.signing_hash())
                .map_err(|_| MusubiPublicationServiceBackendErrorV1::Permanent)?;
        Ok(vec![MusubiSeedIngressReceiptApprovalV1 {
            public_key: self.key_pair.public_key().clone(),
            signature,
        }])
    }
}
/// Complete transport-independent server counterpart for private Musubi publication routes.
///
/// The service owns no listener, TLS key, platform credential loader, or `SoraFS` implementation.
/// A deployment injects those boundaries together with a crash-safe journal. Requests are
/// handled serially by `&mut self`; an ingress may place the service behind one mutex when it
/// needs concurrency.
pub struct MusubiPublicationPrivateServiceV1 {
    config: MusubiPublicationServiceConfigurationV1,
    clock: Box<dyn MusubiPublicationServiceClockV1>,
    last_clock_ms: Option<u64>,
    receipt_signer: Box<dyn MusubiSeedIngressReceiptSigningProviderV1>,
    journal: Box<dyn MusubiPublicationServiceJournalV1>,
    seed_ingress: Box<dyn MusubiSeedIngressBackendV1>,
    storage: Box<dyn MusubiStorageCoordinationBackendV1>,
    readback: Box<dyn MusubiProviderReadbackBackendV1>,
}
impl fmt::Debug for MusubiPublicationPrivateServiceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MusubiPublicationPrivateServiceV1")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationPrivateServiceV1 {
    /// Construct a fail-closed service from deployment-owned runtime dependencies.
    ///
    /// # Errors
    ///
    /// Returns an identity error when public configuration is invalid, differs from the injected
    /// signing provider's broker, differs from the seed backend's admitted provider, or differs
    /// from the journal's immutable deployment binding. Production clock and journal adapters
    /// must reject rollback across service restarts.
    pub fn new(
        config: MusubiPublicationServiceConfigurationV1,
        clock: Box<dyn MusubiPublicationServiceClockV1>,
        receipt_signer: Box<dyn MusubiSeedIngressReceiptSigningProviderV1>,
        journal: Box<dyn MusubiPublicationServiceJournalV1>,
        seed_ingress: Box<dyn MusubiSeedIngressBackendV1>,
        storage: Box<dyn MusubiStorageCoordinationBackendV1>,
        readback: Box<dyn MusubiProviderReadbackBackendV1>,
    ) -> Result<Self, MusubiPublicationServiceErrorCodeV1> {
        config.validate()?;
        let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
        journal_binding
            .validate()
            .map_err(|_| MusubiPublicationServiceErrorCodeV1::IdentityMismatch)?;
        if &config.ingress_broker != receipt_signer.broker()
            || config.seed_provider != seed_ingress.provider_id()
            || journal.deployment_binding() != &journal_binding
        {
            return Err(MusubiPublicationServiceErrorCodeV1::IdentityMismatch);
        }
        Ok(Self {
            config,
            clock,
            last_clock_ms: None,
            receipt_signer,
            journal,
            seed_ingress,
            storage,
            readback,
        })
    }
    /// Handle one exact private HTTP request and always return a bounded typed response.
    #[must_use]
    pub fn handle(
        &mut self,
        request: MusubiPublicationPrivateHttpRequestV1<'_>,
    ) -> MusubiPublicationPrivateHttpResponseV1 {
        match self.try_handle(request) {
            Ok(body) => MusubiPublicationPrivateHttpResponseV1 {
                status: 200,
                content_type: APPLICATION_NORITO,
                body,
            },
            Err(error) => error.into_response(),
        }
    }
    fn try_handle(
        &mut self,
        request: MusubiPublicationPrivateHttpRequestV1<'_>,
    ) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1> {
        if request.method != "POST" {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::MethodInvalid,
            ));
        }
        let route = MusubiPublicationPrivateRouteV1::parse(request.path).ok_or_else(|| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RouteNotFound,
            )
        })?;
        match route {
            MusubiPublicationPrivateRouteV1::SeedIngress => {
                if request.content_type != APPLICATION_MUSUBI_SEED_ENVELOPE {
                    return Err(MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::MediaTypeInvalid,
                    ));
                }
                let current_time_ms = self.sample_time()?;
                self.handle_seed_ingress(request, current_time_ms)
            }
            MusubiPublicationPrivateRouteV1::StorageCoordination => {
                if request.content_type != APPLICATION_NORITO
                    || request.seed_ingress_metadata.is_some()
                {
                    return Err(MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::MediaTypeInvalid,
                    ));
                }
                let observation_started = std::time::Instant::now();
                let current_time_ms = self.sample_time()?;
                self.handle_storage_coordination(request, current_time_ms, observation_started)
            }
            MusubiPublicationPrivateRouteV1::ProviderReadback => {
                if request.content_type != APPLICATION_NORITO
                    || request.seed_ingress_metadata.is_some()
                {
                    return Err(MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::MediaTypeInvalid,
                    ));
                }
                let current_time_ms = self.sample_time()?;
                self.handle_provider_readback(request, current_time_ms)
            }
        }
    }
    #[allow(
        clippy::too_many_lines,
        reason = "the seed-ingress handler keeps one security-sensitive route's validation and journal transition contiguous"
    )]
    fn handle_seed_ingress(
        &mut self,
        http: MusubiPublicationPrivateHttpRequestV1<'_>,
        current_time_ms: u64,
    ) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1> {
        let metadata = decode_canonical_base64::<MusubiSeedIngressStageRequestV1>(
            http.seed_ingress_metadata.ok_or_else(|| {
                MusubiPublicationServiceErrorV1::permanent(
                    MusubiPublicationServiceErrorCodeV1::RequestInvalid,
                )
            })?,
            MAX_SEED_INGRESS_METADATA_BYTES,
            REQUEST_METADATA_DECODE_LIMITS,
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        )?;
        metadata.value.validate().map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
        })?;
        self.validate_seed_identity(&metadata.value)?;
        let maximum_body = SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1
            .checked_add(MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1)
            .and_then(|length| {
                usize::try_from(MUSUBI_MAX_CAR_BYTES_V1)
                    .ok()
                    .and_then(|car| length.checked_add(car))
            })
            .ok_or_else(|| {
                MusubiPublicationServiceErrorV1::permanent(
                    MusubiPublicationServiceErrorCodeV1::RequestInvalid,
                )
            })?;
        if http.body.len() <= SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1
            || http.body.len() > maximum_body
        {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::CarBodyMismatch,
            ));
        }
        let digest = request_digest(
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            &metadata.canonical,
        )
        .map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
        })?;
        let authorization = self.decode_and_verify_authorization(
            &http,
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            metadata.value.operation_id,
            digest,
            &metadata.value.binding.network_id,
            &metadata.value.binding.publisher,
            current_time_ms,
        )?;
        let verified_body = verify_seed_ingress_body(&metadata.value, http.body)?;
        let attempt = journal_attempt(
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            metadata.value.operation_id,
            [0_u8; 32],
            &metadata.value.binding.network_id,
            &metadata.value.binding.publisher,
            metadata.value.binding.archive_id,
            metadata.value.binding.car_body_digest,
            metadata.value.binding.car_body_length,
            digest,
            &authorization,
        );
        match self
            .journal
            .begin(&attempt, current_time_ms)
            .map_err(seed_ingress_journal_error)?
        {
            MusubiPublicationJournalBeginV1::Cached(response) => {
                self.seed_ingress
                    .verify_staged_car(
                        metadata.value.operation_id,
                        &metadata.value.binding,
                        &metadata.value.commitment,
                        &verified_body.plan,
                        verified_body.car,
                    )
                    .map_err(seed_ingress_backend_error)?;
                let receipt: MusubiSeedIngressReceiptV1 = decode_cached_response(&response)
                    .map_err(|error| {
                        error.ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid)
                    })?
                    .value;
                if receipt
                    .verify(&metadata.value.binding, current_time_ms)
                    .is_ok()
                {
                    return Ok(response);
                }
                receipt
                    .verify(&metadata.value.binding, receipt.payload.issued_at_ms)
                    .map_err(|_| {
                        MusubiPublicationServiceErrorV1::permanent(
                            MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
                        )
                        .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid)
                    })?;
                if current_time_ms <= receipt.payload.expires_at_ms {
                    return Err(MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
                    )
                    .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid));
                }
                self.journal
                    .refresh_expired_seed_receipt(&attempt, &response, current_time_ms)
                    .map_err(seed_ingress_journal_error)?;
            }
            MusubiPublicationJournalBeginV1::Execute => {}
        }
        let result = self
            .seed_ingress
            .stage_exact_car(
                metadata.value.operation_id,
                &metadata.value.binding,
                &metadata.value.commitment,
                &verified_body.plan,
                verified_body.car,
            )
            .map_err(seed_ingress_backend_error)
            .and_then(|()| self.issue_seed_ingress_receipt(metadata.value.binding))
            .and_then(|response| encode_service_response(&response));
        self.finish_attempt(attempt.key, digest, result)
    }
    fn issue_seed_ingress_receipt(
        &mut self,
        binding: MusubiSeedIngressReceiptBindingV1,
    ) -> Result<MusubiSeedIngressReceiptV1, MusubiPublicationServiceErrorV1> {
        if binding.ingress_broker != self.config.ingress_broker {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::IdentityMismatch,
            ));
        }
        let issued_at_ms = self.sample_time()?;
        let expires_at_ms = issued_at_ms
            .checked_add(self.config.receipt_lifetime_ms)
            .ok_or_else(|| {
                MusubiPublicationServiceErrorV1::permanent(
                    MusubiPublicationServiceErrorCodeV1::TrustedClockUnavailable,
                )
            })?;
        let payload = MusubiSeedIngressReceiptPayloadV1 {
            version: 1,
            binding,
            issued_at_ms,
            expires_at_ms,
        };
        payload.validate().map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable,
            )
            .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid)
        })?;
        let approvals = self
            .receipt_signer
            .sign_approvals(&payload)
            .map_err(|error| {
                service_backend_error(
                    MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable,
                    error,
                )
            })?;
        let receipt = MusubiSeedIngressReceiptV1 { payload, approvals };
        let verification_time_ms = self.sample_time()?;
        if verification_time_ms >= receipt.payload.expires_at_ms {
            return Err(MusubiPublicationServiceErrorV1::retryable(
                MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable,
            ));
        }
        receipt
            .verify(&receipt.payload.binding, verification_time_ms)
            .map_err(|_| {
                MusubiPublicationServiceErrorV1::permanent(
                    MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable,
                )
                .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid)
            })?;
        Ok(receipt)
    }
    #[allow(
        clippy::too_many_lines,
        reason = "the storage handler keeps one security-sensitive route's validation and journal transition contiguous"
    )]
    fn handle_storage_coordination(
        &mut self,
        http: MusubiPublicationPrivateHttpRequestV1<'_>,
        current_time_ms: u64,
        observation_started: std::time::Instant,
    ) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1> {
        let decoded = decode_canonical_body::<MusubiStorageCoordinationRequestV1>(
            http.body,
            MAX_CONTROL_REQUEST_BYTES,
            CONTROL_REQUEST_DECODE_LIMITS,
        )?;
        self.validate_control_identity(&decoded.value.network_id, &decoded.value.publisher)?;
        let digest = request_digest(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            &decoded.canonical,
        )
        .map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
        })?;
        let authorization = self.decode_and_verify_authorization(
            &http,
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            decoded.value.operation_id,
            digest,
            &decoded.value.network_id,
            &decoded.value.publisher,
            current_time_ms,
        )?;
        // Authentication above binds the exact canonical request before receipt telemetry is
        // possible. Validate the receipt's bounded shape (including its approval-count ceiling)
        // before any controller signature work, then check aggregate request bindings below.
        decoded.value.staging_receipt.validate().map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
            .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid)
        })?;
        let receipt_binding = &decoded.value.staging_receipt.payload.binding;
        if receipt_binding.ingress_broker != self.config.ingress_broker
            || receipt_binding.seed_provider != self.config.seed_provider
        {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::IdentityMismatch,
            ));
        }
        decoded
            .value
            .staging_receipt
            .verify(
                receipt_binding,
                decoded.value.staging_receipt.payload.issued_at_ms,
            )
            .map_err(|_| {
                MusubiPublicationServiceErrorV1::permanent(
                    MusubiPublicationServiceErrorCodeV1::RequestInvalid,
                )
                .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid)
            })?;
        // Registration admission already consumed receipt freshness. Storage coordination is
        // authorized by the finalized immutable registration projection and transaction identity,
        // so a crash after registration remains recoverable after the embedded receipt expires.
        if decoded.value.staging_receipt.payload.issued_at_ms
            > current_time_ms.saturating_add(self.config.max_future_clock_skew_ms)
        {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
            .ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptInvalid));
        }
        decoded.value.validate().map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
        })?;
        let attempt = journal_attempt(
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            decoded.value.operation_id,
            storage_generation_target(decoded.value.generation),
            &decoded.value.network_id,
            &decoded.value.publisher,
            decoded.value.commitment.archive_id(),
            decoded.value.commitment.car_digest,
            decoded.value.commitment.car_size,
            digest,
            &authorization,
        );
        match self.begin_attempt(&attempt, current_time_ms)? {
            MusubiPublicationJournalBeginV1::Cached(response) => {
                let cached: MusubiStorageCoordinationResponseV1 = decode_cached_response(&response)
                    .map_err(|error| error.integrity_failure(MusubiIntegritySurfaceV1::Other))?
                    .value;
                cached.validate_for(&decoded.value).map_err(|_| {
                    MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
                    )
                    .integrity_failure(MusubiIntegritySurfaceV1::Other)
                })?;
                self.storage
                    .verify_current_registration(&decoded.value)
                    .map_err(|error| {
                        service_backend_error(
                            MusubiPublicationServiceErrorCodeV1::StorageCoordinationUnavailable,
                            error,
                        )
                    })?;
                return Ok(response);
            }
            MusubiPublicationJournalBeginV1::Execute => {}
        }
        let result = VerifiedStorageCoordinationRequestV1::from_verified(
            &decoded.value,
            digest,
            &authorization.value,
            current_time_ms,
            observation_started,
        )
        .and_then(|verified| {
            self.storage.coordinate_storage(&verified).map_err(|error| {
                service_backend_error(
                    MusubiPublicationServiceErrorCodeV1::StorageCoordinationUnavailable,
                    error,
                )
            })
        })
        .and_then(|response| {
            response.validate_for(&decoded.value).map_err(|_| {
                MusubiPublicationServiceErrorV1::permanent(
                    MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
                )
                .integrity_failure(MusubiIntegritySurfaceV1::Other)
            })?;
            encode_service_response(&response)
        });
        self.finish_attempt(attempt.key, digest, result)
    }
    fn handle_provider_readback(
        &mut self,
        http: MusubiPublicationPrivateHttpRequestV1<'_>,
        current_time_ms: u64,
    ) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1> {
        let decoded = decode_canonical_body::<MusubiProviderReadbackRequestV1>(
            http.body,
            MAX_CONTROL_REQUEST_BYTES,
            CONTROL_REQUEST_DECODE_LIMITS,
        )?;
        self.validate_control_identity(&decoded.value.network_id, &decoded.value.publisher)?;
        let digest = request_digest(
            MusubiPublicationRuntimeOperationV1::ProviderReadback,
            &decoded.canonical,
        )
        .map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
        })?;
        let authorization = self.decode_and_verify_authorization(
            &http,
            MusubiPublicationRuntimeOperationV1::ProviderReadback,
            decoded.value.operation_id,
            digest,
            &decoded.value.network_id,
            &decoded.value.publisher,
            current_time_ms,
        )?;
        decoded.value.validate().map_err(|_| {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::RequestInvalid,
            )
        })?;
        let attempt = journal_attempt(
            MusubiPublicationRuntimeOperationV1::ProviderReadback,
            decoded.value.operation_id,
            provider_readback_target(&decoded.value.location, decoded.value.provider),
            &decoded.value.network_id,
            &decoded.value.publisher,
            decoded.value.commitment.archive_id(),
            decoded.value.commitment.car_digest,
            decoded.value.commitment.car_size,
            digest,
            &authorization,
        );
        match self.begin_attempt(&attempt, current_time_ms)? {
            MusubiPublicationJournalBeginV1::Cached(response) => {
                let cached: MusubiProviderReadbackResponseV1 = decode_cached_response(&response)
                    .map_err(|error| {
                        error.integrity_failure(MusubiIntegritySurfaceV1::ProviderReadback)
                    })?
                    .value;
                cached.validate_for(&decoded.value).map_err(|_| {
                    MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
                    )
                    .integrity_failure(MusubiIntegritySurfaceV1::ProviderReadback)
                })?;
                self.readback
                    .verify_current_target(&decoded.value)
                    .map_err(|error| {
                        service_backend_error(
                            MusubiPublicationServiceErrorCodeV1::ProviderReadbackUnavailable,
                            error,
                        )
                    })?;
                return Ok(response);
            }
            MusubiPublicationJournalBeginV1::Execute => {}
        }
        let result = self
            .readback
            .readback_provider(&decoded.value)
            .map_err(|error| {
                service_backend_error(
                    MusubiPublicationServiceErrorCodeV1::ProviderReadbackUnavailable,
                    error,
                )
            })
            .and_then(|response| {
                response.validate_for(&decoded.value).map_err(|_| {
                    MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
                    )
                    .integrity_failure(MusubiIntegritySurfaceV1::ProviderReadback)
                })?;
                encode_service_response(&response)
            });
        self.finish_attempt(attempt.key, digest, result)
    }
    fn validate_seed_identity(
        &self,
        request: &MusubiSeedIngressStageRequestV1,
    ) -> Result<(), MusubiPublicationServiceErrorV1> {
        let binding = &request.binding;
        self.validate_control_identity(&binding.network_id, &binding.publisher)?;
        if binding.ingress_broker != self.config.ingress_broker
            || binding.seed_provider != self.config.seed_provider
        {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::IdentityMismatch,
            ));
        }
        Ok(())
    }
    fn validate_control_identity(
        &self,
        network_id: &NetworkId,
        _publisher: &AccountId,
    ) -> Result<(), MusubiPublicationServiceErrorV1> {
        if network_id != &self.config.network_id {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::IdentityMismatch,
            ));
        }
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "the fixed authorization protocol binds every route, identity, digest, and clock field explicitly"
    )]
    fn decode_and_verify_authorization(
        &self,
        http: &MusubiPublicationPrivateHttpRequestV1<'_>,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        digest: [u8; 32],
        network_id: &NetworkId,
        publisher: &AccountId,
        current_time_ms: u64,
    ) -> Result<
        CanonicalDecodedV1<MusubiPublicationRuntimeAuthorizationV1>,
        MusubiPublicationServiceErrorV1,
    > {
        let authorization: CanonicalDecodedV1<MusubiPublicationRuntimeAuthorizationV1> =
            decode_canonical_base64(
                http.authorization.ok_or_else(|| {
                    MusubiPublicationServiceErrorV1::permanent(
                        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid,
                    )
                })?,
                MAX_AUTHORIZATION_BYTES,
                AUTHORIZATION_DECODE_LIMITS,
                MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid,
            )?;
        if &authorization.value.payload.network_id != network_id
            || &authorization.value.payload.publisher != publisher
            || network_id != &self.config.network_id
        {
            return Err(MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::IdentityMismatch,
            ));
        }
        authorization
            .value
            .verify_with_clock_skew(
                operation,
                operation_id,
                digest,
                current_time_ms,
                self.config.max_future_clock_skew_ms,
            )
            .map_err(|_| {
                let code = if current_time_ms > authorization.value.payload.expires_at_ms
                    || authorization.value.payload.issued_at_ms
                        > current_time_ms.saturating_add(self.config.max_future_clock_skew_ms)
                {
                    MusubiPublicationServiceErrorCodeV1::AuthorizationExpired
                } else {
                    MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
                };
                if code == MusubiPublicationServiceErrorCodeV1::AuthorizationExpired {
                    MusubiPublicationServiceErrorV1::retryable(code)
                } else {
                    MusubiPublicationServiceErrorV1::permanent(code)
                }
            })?;
        Ok(authorization)
    }
    fn begin_attempt(
        &mut self,
        attempt: &MusubiPublicationJournalAttemptV1,
        current_time_ms: u64,
    ) -> Result<MusubiPublicationJournalBeginV1, MusubiPublicationServiceErrorV1> {
        self.journal
            .begin(attempt, current_time_ms)
            .map_err(service_journal_error)
    }
    fn sample_time(&mut self) -> Result<u64, MusubiPublicationServiceErrorV1> {
        let current_time_ms = self.clock.current_time_ms().map_err(|error| {
            service_backend_error(
                MusubiPublicationServiceErrorCodeV1::TrustedClockUnavailable,
                error,
            )
        })?;
        if current_time_ms == 0
            || self
                .last_clock_ms
                .is_some_and(|previous| current_time_ms < previous)
        {
            return Err(MusubiPublicationServiceErrorV1::retryable(
                MusubiPublicationServiceErrorCodeV1::TrustedClockUnavailable,
            ));
        }
        self.last_clock_ms = Some(current_time_ms);
        Ok(current_time_ms)
    }
    fn finish_attempt(
        &mut self,
        key: MusubiPublicationIdempotencyKeyV1,
        request_digest: [u8; 32],
        result: Result<Vec<u8>, MusubiPublicationServiceErrorV1>,
    ) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1> {
        let operation = key.operation;
        match result {
            Ok(response) => {
                if let Err(commit_error) = self.journal.commit(key, request_digest, &response) {
                    let error = self
                        .journal
                        .abort(key, request_digest)
                        .err()
                        .unwrap_or(commit_error);
                    return Err(publication_journal_error(operation, error));
                }
                Ok(response)
            }
            Err(error) => {
                if let Err(journal_error) = self.journal.abort(key, request_digest) {
                    // The original verification/deadletter observation must not disappear merely
                    // because the durable journal then failed to release its reservation.
                    record_publication_service_telemetry(error.telemetry);
                    return Err(if error.telemetry.is_some() {
                        service_journal_error(journal_error)
                    } else {
                        publication_journal_error(operation, journal_error)
                    });
                }
                Err(error)
            }
        }
    }
}
const AUTHORIZATION_DECODE_LIMITS: DecodeLimits =
    DecodeLimits::new(128, MAX_AUTHORIZATION_BYTES, 512, 256 * 1024, 16);
const REQUEST_METADATA_DECODE_LIMITS: DecodeLimits =
    DecodeLimits::new(256, MAX_SEED_INGRESS_METADATA_BYTES, 2_048, 512 * 1024, 32);
const SEED_INGRESS_PLAN_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    16_384,
    MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1,
    300_000,
    32 * 1024 * 1024,
    128,
);
const CONTROL_REQUEST_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    4_096,
    MAX_CONTROL_REQUEST_BYTES,
    32_768,
    32 * 1024 * 1024,
    64,
);
struct VerifiedSeedIngressBodyV1<'a> {
    plan: CarBuildPlan,
    car: &'a [u8],
}
fn verify_seed_ingress_body<'a>(
    request: &MusubiSeedIngressStageRequestV1,
    body: &'a [u8],
) -> Result<VerifiedSeedIngressBodyV1<'a>, MusubiPublicationServiceErrorV1> {
    let mismatch = || seed_ingress_integrity_failure(MusubiIntegritySurfaceV1::ArchiveCommitment);
    let header = body
        .get(..SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1)
        .ok_or_else(mismatch)?;
    if header.get(..SEED_INGRESS_ENVELOPE_MAGIC_V1.len())
        != Some(SEED_INGRESS_ENVELOPE_MAGIC_V1.as_slice())
        || header.get(16).copied() != Some(SEED_INGRESS_ENVELOPE_VERSION_V1)
        || header
            .get(17..24)
            .is_none_or(|reserved| reserved != [0_u8; 7])
    {
        return Err(mismatch());
    }
    let plan_length = u64::from_be_bytes(
        header[24..32]
            .try_into()
            .expect("fixed seed-ingress header contains the plan length"),
    );
    let car_length = u64::from_be_bytes(
        header[32..40]
            .try_into()
            .expect("fixed seed-ingress header contains the CAR length"),
    );
    let plan_length_usize = usize::try_from(plan_length).map_err(|_| mismatch())?;
    let car_length_usize = usize::try_from(car_length).map_err(|_| mismatch())?;
    if plan_length == 0
        || plan_length_usize > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1
        || car_length == 0
        || car_length > MUSUBI_MAX_CAR_BYTES_V1
        || plan_length != request.plan_length
        || car_length != request.binding.car_body_length
        || car_length != request.commitment.car_size
    {
        return Err(mismatch());
    }
    let plan_end = SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1
        .checked_add(plan_length_usize)
        .ok_or_else(mismatch)?;
    let body_end = plan_end
        .checked_add(car_length_usize)
        .ok_or_else(mismatch)?;
    if body_end != body.len() {
        return Err(mismatch());
    }
    let canonical_plan = body
        .get(SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1..plan_end)
        .ok_or_else(mismatch)?;
    let car = body.get(plan_end..body_end).ok_or_else(mismatch)?;
    if seed_ingress_plan_digest(canonical_plan).map_err(|_| mismatch())? != request.plan_digest
        || blake3::hash(car).as_bytes() != request.commitment.car_digest.as_bytes()
        || blake3::hash(car).as_bytes() != request.binding.car_body_digest.as_bytes()
    {
        return Err(mismatch());
    }
    let witness = decode_seed_ingress_plan_witness(canonical_plan)?;
    let plan = witness
        .to_car_build_plan(&request.commitment)
        .map_err(|_| mismatch())?;
    let evidence = MusubiBundleVerifierV1::verify(&plan, car, &request.commitment)
        .map_err(|error| seed_ingress_bundle_integrity_failure(error.surface()))?;
    if evidence.semantic_release().semantic_digest()
        != request.binding.semantic_release_manifest_digest
    {
        return Err(seed_ingress_integrity_failure(
            MusubiIntegritySurfaceV1::Bundle,
        ));
    }
    Ok(VerifiedSeedIngressBodyV1 { plan, car })
}
fn decode_seed_ingress_plan_witness(
    canonical_plan: &[u8],
) -> Result<MusubiSeedIngressCarPlanV1, MusubiPublicationServiceErrorV1> {
    let mismatch = || seed_ingress_integrity_failure(MusubiIntegritySurfaceV1::ArchiveCommitment);
    let witness: MusubiSeedIngressCarPlanV1 =
        norito::decode_canonical_with_limits(canonical_plan, SEED_INGRESS_PLAN_DECODE_LIMITS)
            .map_err(|_| mismatch())?;
    witness.validate_non_path_shape().map_err(|_| mismatch())?;
    witness
        .validate_portable_paths()
        .map_err(|_| seed_ingress_integrity_failure(MusubiIntegritySurfaceV1::SourceTree))?;
    if norito::encode_canonical(&witness).map_err(|_| mismatch())? != canonical_plan {
        return Err(mismatch());
    }
    Ok(witness)
}
#[cfg(test)]
fn seed_ingress_source_material(
    mut entries: Vec<(String, u64, [u8; 32])>,
    expected_length: usize,
) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1> {
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(seed_ingress_integrity_failure(
            MusubiIntegritySurfaceV1::SourceTree,
        ));
    }
    let count = u32::try_from(entries.len())
        .map_err(|_| seed_ingress_integrity_failure(MusubiIntegritySurfaceV1::SourceTree))?;
    let mut material = Vec::new();
    material
        .try_reserve_exact(expected_length)
        .map_err(|_| seed_ingress_integrity_failure(MusubiIntegritySurfaceV1::SourceTree))?;
    seed_ingress_append_frame(&mut material, SOURCE_TREE_DOMAIN_V1)?;
    material.extend_from_slice(&count.to_be_bytes());
    for (path, size, digest) in entries {
        seed_ingress_append_frame(&mut material, path.as_bytes())?;
        material.extend_from_slice(&size.to_be_bytes());
        material.extend_from_slice(&digest);
    }
    if material.len() != expected_length {
        return Err(seed_ingress_integrity_failure(
            MusubiIntegritySurfaceV1::SourceTree,
        ));
    }
    Ok(material)
}
fn seed_ingress_integrity_failure(
    surface: MusubiIntegritySurfaceV1,
) -> MusubiPublicationServiceErrorV1 {
    MusubiPublicationServiceErrorV1::permanent(MusubiPublicationServiceErrorCodeV1::CarBodyMismatch)
        .integrity_failure(surface)
}
fn seed_ingress_bundle_integrity_failure(
    surface: MusubiBundleIntegritySurfaceV1,
) -> MusubiPublicationServiceErrorV1 {
    let surface = match surface {
        MusubiBundleIntegritySurfaceV1::ArchiveCommitment => {
            MusubiIntegritySurfaceV1::ArchiveCommitment
        }
        MusubiBundleIntegritySurfaceV1::Bundle => MusubiIntegritySurfaceV1::Bundle,
        MusubiBundleIntegritySurfaceV1::Descriptor => MusubiIntegritySurfaceV1::Descriptor,
        MusubiBundleIntegritySurfaceV1::SourceTree => MusubiIntegritySurfaceV1::SourceTree,
        MusubiBundleIntegritySurfaceV1::VerificationLock => {
            MusubiIntegritySurfaceV1::VerificationLock
        }
    };
    seed_ingress_integrity_failure(surface)
}
#[cfg(test)]
fn seed_ingress_append_frame(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), MusubiPublicationServiceErrorV1> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        MusubiPublicationServiceErrorV1::permanent(
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch,
        )
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}
#[cfg(test)]
fn seed_ingress_domain_digest(
    domain: &[u8],
    material: &[u8],
) -> Result<MusubiContentDigestV1, MusubiPublicationServiceErrorV1> {
    let length = u64::try_from(material.len()).map_err(|_| {
        MusubiPublicationServiceErrorV1::permanent(
            MusubiPublicationServiceErrorCodeV1::CarBodyMismatch,
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&length.to_be_bytes());
    hasher.update(material);
    Ok(MusubiContentDigestV1::new(*hasher.finalize().as_bytes()))
}
fn encode_seed_ingress_body(
    canonical_plan: &[u8],
    car: &[u8],
) -> Result<Vec<u8>, MusubiPublicationRuntimeTransportErrorV1> {
    let plan_length = u64::try_from(canonical_plan.len()).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_BODY_INVALID")
    })?;
    let car_length = u64::try_from(car.len()).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_BODY_INVALID")
    })?;
    if canonical_plan.is_empty()
        || canonical_plan.len() > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1
        || car.is_empty()
        || car_length > MUSUBI_MAX_CAR_BYTES_V1
    {
        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_SEED_INGRESS_BODY_INVALID",
        ));
    }
    let capacity = SEED_INGRESS_ENVELOPE_HEADER_BYTES_V1
        .checked_add(canonical_plan.len())
        .and_then(|length| length.checked_add(car.len()))
        .ok_or_else(|| {
            MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_BODY_INVALID")
        })?;
    let mut body = Vec::new();
    body.try_reserve_exact(capacity).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_BODY_INVALID")
    })?;
    body.extend_from_slice(&SEED_INGRESS_ENVELOPE_MAGIC_V1);
    body.push(SEED_INGRESS_ENVELOPE_VERSION_V1);
    body.extend_from_slice(&[0_u8; 7]);
    body.extend_from_slice(&plan_length.to_be_bytes());
    body.extend_from_slice(&car_length.to_be_bytes());
    body.extend_from_slice(canonical_plan);
    body.extend_from_slice(car);
    if body.len() != capacity {
        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_SEED_INGRESS_BODY_INVALID",
        ));
    }
    Ok(body)
}
struct CanonicalDecodedV1<T> {
    value: T,
    canonical: Vec<u8>,
}
fn decode_canonical_base64<T>(
    encoded: &str,
    max_decoded_bytes: usize,
    limits: DecodeLimits,
    code: MusubiPublicationServiceErrorCodeV1,
) -> Result<CanonicalDecodedV1<T>, MusubiPublicationServiceErrorV1>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    let max_encoded_bytes = max_decoded_bytes
        .checked_mul(4)
        .and_then(|value| value.checked_add(2))
        .map(|value| value / 3)
        .ok_or_else(|| MusubiPublicationServiceErrorV1::permanent(code))?;
    if encoded.is_empty() || encoded.len() > max_encoded_bytes || !encoded.is_ascii() {
        return Err(MusubiPublicationServiceErrorV1::permanent(code));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| MusubiPublicationServiceErrorV1::permanent(code))?;
    if bytes.is_empty()
        || bytes.len() > max_decoded_bytes
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != encoded
    {
        return Err(MusubiPublicationServiceErrorV1::permanent(code));
    }
    decode_canonical_bytes(&bytes, limits, code)
}
fn decode_canonical_body<T>(
    bytes: &[u8],
    max_bytes: usize,
    limits: DecodeLimits,
) -> Result<CanonicalDecodedV1<T>, MusubiPublicationServiceErrorV1>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(MusubiPublicationServiceErrorV1::permanent(
            MusubiPublicationServiceErrorCodeV1::RequestInvalid,
        ));
    }
    decode_canonical_bytes(
        bytes,
        limits,
        MusubiPublicationServiceErrorCodeV1::RequestInvalid,
    )
}
fn decode_cached_response<T>(
    bytes: &[u8],
) -> Result<CanonicalDecodedV1<T>, MusubiPublicationServiceErrorV1>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_RESPONSE_BYTES {
        return Err(MusubiPublicationServiceErrorV1::permanent(
            MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
        ));
    }
    decode_canonical_bytes(
        bytes,
        RESPONSE_DECODE_LIMITS,
        MusubiPublicationServiceErrorCodeV1::BackendResponseInvalid,
    )
}
fn decode_canonical_bytes<T>(
    bytes: &[u8],
    limits: DecodeLimits,
    code: MusubiPublicationServiceErrorCodeV1,
) -> Result<CanonicalDecodedV1<T>, MusubiPublicationServiceErrorV1>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    let value = norito::decode_canonical_with_limits(bytes, limits)
        .map_err(|_| MusubiPublicationServiceErrorV1::permanent(code))?;
    let canonical = norito::encode_canonical(&value)
        .map_err(|_| MusubiPublicationServiceErrorV1::permanent(code))?;
    if canonical != bytes {
        return Err(MusubiPublicationServiceErrorV1::permanent(code));
    }
    Ok(CanonicalDecodedV1 { value, canonical })
}
#[allow(
    clippy::too_many_arguments,
    reason = "the fixed journal record binds every immutable publication protocol field explicitly"
)]
fn journal_attempt(
    operation: MusubiPublicationRuntimeOperationV1,
    operation_id: [u8; 32],
    target: [u8; 32],
    network_id: &NetworkId,
    publisher: &AccountId,
    archive_id: ArchiveId,
    car_body_digest: MusubiContentDigestV1,
    car_body_length: u64,
    request_digest: [u8; 32],
    authorization: &CanonicalDecodedV1<MusubiPublicationRuntimeAuthorizationV1>,
) -> MusubiPublicationJournalAttemptV1 {
    MusubiPublicationJournalAttemptV1 {
        key: MusubiPublicationIdempotencyKeyV1 {
            operation,
            operation_id,
            target,
        },
        binding: MusubiPublicationOperationBindingV1 {
            operation_id,
            network_id: *network_id,
            publisher: publisher.clone(),
            archive_id,
            car_body_digest,
            car_body_length,
        },
        request_digest,
        authorization_digest: *blake3::hash(&authorization.canonical).as_bytes(),
        authorization_expires_at_ms: authorization.value.payload.expires_at_ms,
    }
}
fn encode_service_response<T>(value: &T) -> Result<Vec<u8>, MusubiPublicationServiceErrorV1>
where
    T: norito::core::NoritoSerialize,
{
    let bytes = norito::encode_canonical(value).map_err(|_| {
        MusubiPublicationServiceErrorV1::permanent(
            MusubiPublicationServiceErrorCodeV1::ResponseEncodingFailed,
        )
    })?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_RESPONSE_BYTES {
        return Err(MusubiPublicationServiceErrorV1::permanent(
            MusubiPublicationServiceErrorCodeV1::ResponseEncodingFailed,
        ));
    }
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MusubiPublicationServiceTelemetryEventV1 {
    IngestDeadletter(MusubiIngestDeadletterReasonV1),
    IntegrityFailure(MusubiIntegritySurfaceV1),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MusubiPublicationServiceErrorV1 {
    code: MusubiPublicationServiceErrorCodeV1,
    retryable: bool,
    telemetry: Option<MusubiPublicationServiceTelemetryEventV1>,
}
impl MusubiPublicationServiceErrorV1 {
    const fn permanent(code: MusubiPublicationServiceErrorCodeV1) -> Self {
        Self {
            code,
            retryable: false,
            telemetry: None,
        }
    }
    const fn retryable(code: MusubiPublicationServiceErrorCodeV1) -> Self {
        Self {
            code,
            retryable: true,
            telemetry: None,
        }
    }
    const fn ingest_deadletter(mut self, reason: MusubiIngestDeadletterReasonV1) -> Self {
        debug_assert!(!self.retryable);
        self.telemetry = Some(MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(
            reason,
        ));
        self
    }
    const fn integrity_failure(mut self, surface: MusubiIntegritySurfaceV1) -> Self {
        self.telemetry = Some(MusubiPublicationServiceTelemetryEventV1::IntegrityFailure(
            surface,
        ));
        self
    }
    fn into_response(self) -> MusubiPublicationPrivateHttpResponseV1 {
        record_publication_service_telemetry(self.telemetry);
        let status = match self.code {
            MusubiPublicationServiceErrorCodeV1::RouteNotFound => 404,
            MusubiPublicationServiceErrorCodeV1::MethodInvalid => 405,
            MusubiPublicationServiceErrorCodeV1::MediaTypeInvalid => 415,
            MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
            | MusubiPublicationServiceErrorCodeV1::AuthorizationExpired
            | MusubiPublicationServiceErrorCodeV1::AuthorizationReplay => 401,
            MusubiPublicationServiceErrorCodeV1::OperationBusy => 425,
            MusubiPublicationServiceErrorCodeV1::TrustedClockUnavailable => 503,
            MusubiPublicationServiceErrorCodeV1::JournalUnavailable
            | MusubiPublicationServiceErrorCodeV1::SeedIngressUnavailable
            | MusubiPublicationServiceErrorCodeV1::StorageCoordinationUnavailable
            | MusubiPublicationServiceErrorCodeV1::ProviderReadbackUnavailable
            | MusubiPublicationServiceErrorCodeV1::ReceiptSigningUnavailable
                if self.retryable =>
            {
                503
            }
            _ => 422,
        };
        let error = MusubiPublicationServiceErrorResponseV1 {
            version: 1,
            code: self.code,
            retryable: self.retryable,
        };
        let body = norito::encode_canonical(&error)
            .expect("fixed bounded Musubi publication error response must encode");
        MusubiPublicationPrivateHttpResponseV1 {
            status,
            content_type: APPLICATION_NORITO,
            body,
        }
    }
}
fn record_publication_service_telemetry(event: Option<MusubiPublicationServiceTelemetryEventV1>) {
    let (Some(metrics), Some(event)) = (global_metrics(), event) else {
        return;
    };
    match event {
        MusubiPublicationServiceTelemetryEventV1::IngestDeadletter(reason) => {
            metrics.musubi.inc_ingest_deadletter(reason);
        }
        MusubiPublicationServiceTelemetryEventV1::IntegrityFailure(surface) => {
            metrics.musubi.inc_integrity_failure(surface);
        }
    }
}
fn service_backend_error(
    code: MusubiPublicationServiceErrorCodeV1,
    error: MusubiPublicationServiceBackendErrorV1,
) -> MusubiPublicationServiceErrorV1 {
    match error {
        MusubiPublicationServiceBackendErrorV1::Retryable => {
            MusubiPublicationServiceErrorV1::retryable(code)
        }
        MusubiPublicationServiceBackendErrorV1::Permanent => {
            MusubiPublicationServiceErrorV1::permanent(code)
        }
    }
}
fn seed_ingress_backend_error(
    error: MusubiPublicationServiceBackendErrorV1,
) -> MusubiPublicationServiceErrorV1 {
    let service_error = service_backend_error(
        MusubiPublicationServiceErrorCodeV1::SeedIngressUnavailable,
        error,
    );
    if error == MusubiPublicationServiceBackendErrorV1::Permanent {
        service_error.ingest_deadletter(MusubiIngestDeadletterReasonV1::StorageRejected)
    } else {
        service_error
    }
}
fn service_journal_error(
    error: MusubiPublicationServiceJournalErrorV1,
) -> MusubiPublicationServiceErrorV1 {
    match error {
        MusubiPublicationServiceJournalErrorV1::Invalid
        | MusubiPublicationServiceJournalErrorV1::Conflict => {
            MusubiPublicationServiceErrorV1::permanent(
                MusubiPublicationServiceErrorCodeV1::OperationConflict,
            )
        }
        MusubiPublicationServiceJournalErrorV1::Replay => {
            MusubiPublicationServiceErrorV1::retryable(
                MusubiPublicationServiceErrorCodeV1::AuthorizationReplay,
            )
        }
        MusubiPublicationServiceJournalErrorV1::Busy => MusubiPublicationServiceErrorV1::retryable(
            MusubiPublicationServiceErrorCodeV1::OperationBusy,
        ),
        MusubiPublicationServiceJournalErrorV1::Capacity
        | MusubiPublicationServiceJournalErrorV1::Unavailable => {
            MusubiPublicationServiceErrorV1::retryable(
                MusubiPublicationServiceErrorCodeV1::JournalUnavailable,
            )
        }
    }
}
fn seed_ingress_journal_error(
    error: MusubiPublicationServiceJournalErrorV1,
) -> MusubiPublicationServiceErrorV1 {
    publication_journal_error(MusubiPublicationRuntimeOperationV1::SeedIngress, error)
}
fn publication_journal_error(
    operation: MusubiPublicationRuntimeOperationV1,
    error: MusubiPublicationServiceJournalErrorV1,
) -> MusubiPublicationServiceErrorV1 {
    let service_error = service_journal_error(error);
    if operation == MusubiPublicationRuntimeOperationV1::SeedIngress
        && error == MusubiPublicationServiceJournalErrorV1::Conflict
    {
        service_error.ingest_deadletter(MusubiIngestDeadletterReasonV1::ReceiptReplay)
    } else {
        service_error
    }
}
/// Closed failure returned by a deployment-owned publisher authorization signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiPublicationRuntimeAuthorizationSigningErrorV1 {
    /// The same exact payload may be signed after a transient provider outage.
    Retryable,
    /// Deployment policy or key state cannot authorize the exact payload.
    Permanent,
}
/// Deployment-owned controller signing boundary for private publication requests.
///
/// Implementations may collect approvals from a deployment-owned signing or threshold service. The
/// client constructs every payload field and accepts only approvals, then independently verifies
/// the assembled authorization before any network request is built.
pub trait MusubiPublicationRuntimeAuthorizationSigningProviderV1: Send + Sync {
    /// Exact publisher account controlled by this provider.
    fn publisher(&self) -> &AccountId;
    /// Sign one exact client-constructed authorization payload.
    ///
    /// # Errors
    /// Returns a closed retryable or permanent failure without provider diagnostics or secrets.
    fn sign_approvals(
        &self,
        payload: &MusubiPublicationRuntimeAuthorizationPayloadV1,
    ) -> Result<
        Vec<MusubiPublicationRuntimeAuthorizationApprovalV1>,
        MusubiPublicationRuntimeAuthorizationSigningErrorV1,
    >;
}
/// Runtime-only single-key authorization signer used by the platform Iroha client.
///
/// Multisig publishers use a deployment-owned threshold implementation of
/// [`MusubiPublicationRuntimeAuthorizationSigningProviderV1`] instead.
#[derive(Clone)]
pub struct SoftwareMusubiPublicationRuntimeAuthorizationSignerV1 {
    publisher: AccountId,
    key_pair: KeyPair,
}
impl fmt::Debug for SoftwareMusubiPublicationRuntimeAuthorizationSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareMusubiPublicationRuntimeAuthorizationSignerV1")
            .field("publisher", &self.publisher)
            .finish_non_exhaustive()
    }
}
impl SoftwareMusubiPublicationRuntimeAuthorizationSignerV1 {
    /// Bind one software key to the exact single-controller publisher.
    ///
    /// # Errors
    /// Returns a stable identity error for multisig accounts or mismatched keys.
    pub fn new(
        publisher: AccountId,
        key_pair: KeyPair,
    ) -> Result<Self, MusubiPublicationRuntimeTransportErrorV1> {
        let AccountController::Single(expected_key) = publisher.controller() else {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_MULTISIG_AUTH_PROVIDER_REQUIRED",
            ));
        };
        if expected_key != key_pair.public_key() {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_SIGNER_MISMATCH",
            ));
        }
        Ok(Self {
            publisher,
            key_pair,
        })
    }
}
impl MusubiPublicationRuntimeAuthorizationSigningProviderV1
    for SoftwareMusubiPublicationRuntimeAuthorizationSignerV1
{
    fn publisher(&self) -> &AccountId {
        &self.publisher
    }
    fn sign_approvals(
        &self,
        payload: &MusubiPublicationRuntimeAuthorizationPayloadV1,
    ) -> Result<
        Vec<MusubiPublicationRuntimeAuthorizationApprovalV1>,
        MusubiPublicationRuntimeAuthorizationSigningErrorV1,
    > {
        if payload.publisher != self.publisher {
            return Err(MusubiPublicationRuntimeAuthorizationSigningErrorV1::Permanent);
        }
        let signature = SignatureOf::try_new(self.key_pair.private_key(), payload)
            .map_err(|_| MusubiPublicationRuntimeAuthorizationSigningErrorV1::Permanent)?;
        Ok(vec![MusubiPublicationRuntimeAuthorizationApprovalV1 {
            public_key: self.key_pair.public_key().clone(),
            signature,
        }])
    }
}
/// Memory-only, fully authenticated request for one exact seed-ingress operation.
///
/// The value owns a short-lived signed authorization together with canonical metadata and the
/// framed plan-and-CAR body. It contains no signing key, but the authorization is replay-sensitive
/// until it expires and is consumed by the service journal. Callers must not persist, serialize,
/// or log this value or any of its headers.
pub struct MusubiPreparedSeedIngressRequestV1 {
    authorization_header: String,
    metadata_header: String,
    body: Vec<u8>,
    binding: MusubiSeedIngressReceiptBindingV1,
    authorization_issued_at_ms: u64,
    authorization_expires_at_ms: u64,
}
impl MusubiPreparedSeedIngressRequestV1 {
    /// Borrow the short-lived authorization header.
    ///
    /// This value is replay-sensitive. Keep it in memory and never persist or log it.
    #[must_use]
    pub fn authorization_header(&self) -> &str {
        &self.authorization_header
    }
    /// Borrow the URL-safe canonical seed metadata header.
    ///
    /// The metadata is inseparable from the signed authorization. Keep the complete prepared
    /// request in memory and never persist or log its headers.
    #[must_use]
    pub fn seed_ingress_metadata_header(&self) -> &str {
        &self.metadata_header
    }
    /// Borrow the exact fixed-magic plan-and-CAR body.
    ///
    /// The body is authenticated by the adjacent memory-only headers and must be submitted
    /// without modification.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Borrow the exact receipt binding expected from the service response.
    #[must_use]
    pub const fn binding(&self) -> &MusubiSeedIngressReceiptBindingV1 {
        &self.binding
    }
    /// Return when the short-lived authorization was issued, as Unix milliseconds.
    #[must_use]
    pub const fn authorization_issued_at_ms(&self) -> u64 {
        self.authorization_issued_at_ms
    }
    /// Return when the short-lived authorization expires, as Unix milliseconds.
    #[must_use]
    pub const fn authorization_expires_at_ms(&self) -> u64 {
        self.authorization_expires_at_ms
    }
    /// Borrow this value as the exact transport-neutral request accepted by the private service.
    ///
    /// The returned request borrows replay-sensitive authorization material. Keep it in memory,
    /// submit it only to the intended private service, and never persist or log its headers.
    #[must_use]
    pub fn as_private_http_request(&self) -> MusubiPublicationPrivateHttpRequestV1<'_> {
        MusubiPublicationPrivateHttpRequestV1 {
            method: "POST",
            path: MUSUBI_PUBLICATION_SEED_INGRESS_PATH_V1,
            content_type: MUSUBI_PUBLICATION_SEED_ENVELOPE_MEDIA_TYPE_V1,
            authorization: Some(self.authorization_header()),
            seed_ingress_metadata: Some(self.seed_ingress_metadata_header()),
            body: self.body(),
        }
    }
}
/// Account-authenticated client for the fixed private publication route inventory.
///
/// The client owns authorization issuance time, enforces a process-lifetime non-regressing
/// clock floor shared by its clones, and resamples after external signing. Callers cannot supply
/// timestamps for signed requests.
#[derive(Clone)]
pub struct AuthenticatedMusubiPublicationRuntimeClientV1 {
    network_id: NetworkId,
    publisher: AccountId,
    authorization_signer: Arc<dyn MusubiPublicationRuntimeAuthorizationSigningProviderV1>,
    publication_clock_floor_ms: Arc<AtomicU64>,
    http: PublicationHttpTransport,
}
#[derive(Clone)]
enum PublicationHttpTransport {
    Remote(HttpClient),
    Generated(GeneratedLocalPublicationHttpClientV1),
}
impl fmt::Debug for AuthenticatedMusubiPublicationRuntimeClientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMusubiPublicationRuntimeClientV1")
            .field("network_id", &self.network_id)
            .field("publisher", &self.publisher)
            .finish_non_exhaustive()
    }
}
impl AuthenticatedMusubiPublicationRuntimeClientV1 {
    /// Construct from an already validated platform Iroha client configuration.
    ///
    /// Torii headers and Basic Auth are deliberately not copied to the private service.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the client account and key do not form a supported publisher,
    /// the timeout is invalid, or the hardened HTTP client cannot be constructed.
    pub fn from_iroha_client(
        client: &Client,
        timeout: Duration,
    ) -> Result<Self, MusubiPublicationRuntimeTransportErrorV1> {
        let signer = SoftwareMusubiPublicationRuntimeAuthorizationSignerV1::new(
            client.account().clone(),
            client.key_pair().clone(),
        )?;
        Self::from_authorization_signer(
            *client.network_id(),
            client.account().clone(),
            Arc::new(signer),
            timeout,
        )
    }
    /// Construct with a deployment-owned signing or threshold authorization provider.
    ///
    /// # Errors
    /// Returns a stable error when the provider identity or timeout is invalid.
    pub fn from_authorization_signer(
        network_id: NetworkId,
        publisher: AccountId,
        authorization_signer: Arc<dyn MusubiPublicationRuntimeAuthorizationSigningProviderV1>,
        timeout: Duration,
    ) -> Result<Self, MusubiPublicationRuntimeTransportErrorV1> {
        Self::validate_configuration(&publisher, &authorization_signer, timeout)?;
        let http = HttpClient::builder()
            .https_only(true)
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::permanent(
                    "MUSUBI_RUNTIME_HTTP_CLIENT_INVALID",
                )
            })?;
        Ok(Self {
            network_id,
            publisher,
            authorization_signer,
            publication_clock_floor_ms: Arc::new(AtomicU64::new(0)),
            http: PublicationHttpTransport::Remote(http),
        })
    }
    /// Construct a generated private-publication client from a platform account signer.
    ///
    /// The supplied opaque selection binds only transport intent. Native service admission and
    /// authorization remain unchanged; Torii headers and Basic Auth are never copied.
    /// # Errors
    /// Refuses a different original network/chain, signer, timeout or TLS selection.
    pub fn from_generated_local_iroha_client(
        client: &Client,
        selection: GeneratedLocalPublicationTransportV1,
        timeout: Duration,
    ) -> Result<Self, MusubiPublicationRuntimeTransportErrorV1> {
        if client.chain().to_string() != selection.chain_id() {
            return Err(Self::generated_transport_invalid());
        }
        let signer = SoftwareMusubiPublicationRuntimeAuthorizationSignerV1::new(
            client.account().clone(),
            client.key_pair().clone(),
        )?;
        Self::from_generated_local_authorization_signer(
            *client.network_id(),
            client.account().clone(),
            Arc::new(signer),
            selection,
            timeout,
        )
    }
    /// Construct with an original generated listener and a deployment-owned account signer.
    ///
    /// No arbitrary HTTP client, certificate bypass or account-read capability is accepted.
    /// The publisher may differ from the original provider owner supplying the TLS identity.
    /// # Errors
    /// Refuses a different original network, invalid signer/timeout or TLS construction failure.
    pub fn from_generated_local_authorization_signer(
        network_id: NetworkId,
        publisher: AccountId,
        authorization_signer: Arc<dyn MusubiPublicationRuntimeAuthorizationSigningProviderV1>,
        selection: GeneratedLocalPublicationTransportV1,
        timeout: Duration,
    ) -> Result<Self, MusubiPublicationRuntimeTransportErrorV1> {
        Self::validate_configuration(&publisher, &authorization_signer, timeout)?;
        if network_id != selection.network_id() {
            return Err(Self::generated_transport_invalid());
        }
        let http = selection
            .blocking_client(timeout)
            .map_err(|_| Self::generated_transport_invalid())?;
        Ok(Self {
            network_id,
            publisher,
            authorization_signer,
            publication_clock_floor_ms: Arc::new(AtomicU64::new(0)),
            http: PublicationHttpTransport::Generated(http),
        })
    }
    /// Exact generated publication root, when this client has an original local selection.
    #[must_use]
    pub fn generated_local_base_url(&self) -> Option<&Url> {
        match &self.http {
            PublicationHttpTransport::Remote(_) => None,
            PublicationHttpTransport::Generated(http) => Some(http.selection().base_url()),
        }
    }
    fn validate_configuration(
        publisher: &AccountId,
        authorization_signer: &Arc<dyn MusubiPublicationRuntimeAuthorizationSigningProviderV1>,
        timeout: Duration,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        if timeout == Duration::ZERO || timeout > Duration::from_secs(60) {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_TIMEOUT_INVALID",
            ));
        }
        if authorization_signer.publisher() != publisher {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_SIGNER_MISMATCH",
            ));
        }
        if !controller_fits_publication_approval_bound(publisher) {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_CONTROLLER_UNSUPPORTED",
            ));
        }
        Ok(())
    }
    fn generated_transport_invalid() -> MusubiPublicationRuntimeTransportErrorV1 {
        MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_RUNTIME_GENERATED_TRANSPORT_INVALID",
        )
    }
    fn validate_base_url(
        &self,
        base: &Url,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        validate_publication_service_base_url(base)?;
        if let PublicationHttpTransport::Generated(http) = &self.http {
            http.selection()
                .validate_base_url(base)
                .map_err(|_| Self::generated_transport_invalid())?;
        }
        Ok(())
    }
    fn validate_endpoint(
        &self,
        endpoint: &Url,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        if let PublicationHttpTransport::Generated(http) = &self.http {
            http.selection()
                .validate_endpoint(endpoint)
                .map_err(|_| Self::generated_transport_invalid())?;
            if ![
                SEED_INGRESS_ROUTE,
                STORAGE_COORDINATION_ROUTE,
                PROVIDER_READBACK_ROUTE,
            ]
            .iter()
            .any(|route| endpoint.path().strip_prefix('/') == Some(*route))
            {
                return Err(Self::generated_transport_invalid());
            }
        }
        Ok(())
    }
    /// Return the exact configured deployment identity.
    #[must_use]
    pub const fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    /// Return the exact configured publisher identity.
    #[must_use]
    pub const fn publisher(&self) -> &AccountId {
        &self.publisher
    }
    /// Prepare one bounded, authenticated seed-ingress request entirely in memory.
    ///
    /// The returned value owns a short-lived signed authorization and must be submitted promptly
    /// to the supplied private service root, checked before signing. It contains no key material, but callers must not persist,
    /// serialize, or log it or its headers.
    ///
    /// # Errors
    ///
    /// Returns a stable error when request identity, plan, CAR, metadata, authorization signing,
    /// clock sampling, or bounded envelope construction fails.
    pub fn prepare_seed_ingress_request(
        &self,
        base_url: &Url,
        request: &MusubiSeedIngressStageRequestV1,
        plan: &CarBuildPlan,
        car: &mut dyn Read,
    ) -> Result<MusubiPreparedSeedIngressRequestV1, MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_base_url(base_url)?;
        request.validate()?;
        self.ensure_request_identity(&request.binding.network_id, &request.binding.publisher)?;
        let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(plan, &request.commitment)?;
        let canonical_plan = witness.canonical_bytes()?;
        let canonical_plan_digest = seed_ingress_plan_digest(&canonical_plan)?;
        let canonical_plan_length =
            u64::try_from(canonical_plan.len()).map_err(|_| seed_ingress_plan_invalid())?;
        if canonical_plan_digest != request.plan_digest
            || canonical_plan_length != request.plan_length
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_PLAN_INVALID",
            ));
        }
        let car_length = usize::try_from(request.binding.car_body_length).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_BODY_INVALID")
        })?;
        if car_length == 0 || request.binding.car_body_length > MUSUBI_MAX_CAR_BYTES_V1 {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_BODY_INVALID",
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(car_length).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_SEED_INGRESS_BODY_INVALID")
        })?;
        car.take(request.binding.car_body_length.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::retryable(
                    "MUSUBI_SEED_INGRESS_BODY_READ_FAILED",
                )
            })?;
        if bytes.len() != car_length
            || blake3::hash(&bytes).as_bytes() != request.binding.car_body_digest.as_bytes()
            || blake3::hash(&bytes).as_bytes() != request.commitment.car_digest.as_bytes()
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_BODY_INVALID",
            ));
        }
        let request_bytes = norito::encode_canonical(request).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_REQUEST_INVALID",
            )
        })?;
        if request_bytes.is_empty() || request_bytes.len() > MAX_SEED_INGRESS_METADATA_BYTES {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_METADATA_TOO_LARGE",
            ));
        }
        let authorization = self.authorization(
            MusubiPublicationRuntimeOperationV1::SeedIngress,
            request.operation_id,
            request_digest(
                MusubiPublicationRuntimeOperationV1::SeedIngress,
                &request_bytes,
            )?,
        )?;
        let authorization_header = encode_authorization_header(&authorization)?;
        let metadata_header = encode_seed_ingress_metadata_header(&request_bytes)?;
        let body = encode_seed_ingress_body(&canonical_plan, &bytes)?;
        Ok(MusubiPreparedSeedIngressRequestV1 {
            authorization_header,
            metadata_header,
            body,
            binding: request.binding.clone(),
            authorization_issued_at_ms: authorization.payload.issued_at_ms,
            authorization_expires_at_ms: authorization.payload.expires_at_ms,
        })
    }
    /// Send one bounded canonical plan-and-CAR envelope through seed ingress.
    ///
    /// # Errors
    ///
    /// Returns a stable error when request identity, URL, body, authorization, transport, decoding,
    /// or receipt verification fails.
    pub fn stage_seed_ingress(
        &self,
        base_url: &Url,
        request: &MusubiSeedIngressStageRequestV1,
        plan: &CarBuildPlan,
        car: &mut dyn Read,
    ) -> Result<MusubiSeedIngressReceiptV1, MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_base_url(base_url)?;
        let endpoint = publication_route(base_url, SEED_INGRESS_ROUTE)?;
        let prepared = self.prepare_seed_ingress_request(base_url, request, plan, car)?;
        let expected_binding = prepared.binding().clone();
        let response = self.send_prepared_seed_ingress(endpoint, prepared)?;
        let receipt: MusubiSeedIngressReceiptV1 = decode_response(&response)?;
        let mut clock = system_time_ms;
        let verification_time_ms = self.sample_publication_time(&mut clock)?;
        verify_seed_ingress_receipt(&receipt, &expected_binding, verification_time_ms)?;
        Ok(receipt)
    }
    /// Request an idempotent permanent pin/order coordination result.
    ///
    /// # Errors
    ///
    /// Returns a stable error when request identity or encoding, authorization, transport,
    /// decoding, or response validation fails.
    pub fn coordinate_storage(
        &self,
        base_url: &Url,
        request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationRuntimeTransportErrorV1> {
        request.validate()?;
        self.ensure_request_identity(&request.network_id, &request.publisher)?;
        let request_bytes = norito::encode_canonical(request).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_STORAGE_COORDINATION_REQUEST_INVALID",
            )
        })?;
        let response = self.post_control(
            base_url,
            STORAGE_COORDINATION_ROUTE,
            MusubiPublicationRuntimeOperationV1::StorageCoordination,
            request.operation_id,
            &request_bytes,
        )?;
        let response: MusubiStorageCoordinationResponseV1 = decode_response(&response)?;
        response.validate_for(request)?;
        Ok(response)
    }
    /// Read back one complete archive from one exact provider-specific HTTPS origin.
    ///
    /// # Errors
    ///
    /// Returns a stable error when request identity or encoding, authorization, transport,
    /// decoding, or provider-response validation fails.
    pub fn readback_provider(
        &self,
        base_url: &Url,
        request: &MusubiProviderReadbackRequestV1,
    ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationRuntimeTransportErrorV1> {
        request.validate()?;
        self.ensure_request_identity(&request.network_id, &request.publisher)?;
        let request_bytes = norito::encode_canonical(request).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_PROVIDER_READBACK_REQUEST_INVALID",
            )
        })?;
        let response = self.post_control(
            base_url,
            PROVIDER_READBACK_ROUTE,
            MusubiPublicationRuntimeOperationV1::ProviderReadback,
            request.operation_id,
            &request_bytes,
        )?;
        let response: MusubiProviderReadbackResponseV1 = decode_response(&response)?;
        response.validate_for(request)?;
        Ok(response)
    }
    fn post_control(
        &self,
        base_url: &Url,
        route: &str,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_base_url(base_url)?;
        if body.is_empty() || body.len() > MAX_CONTROL_REQUEST_BYTES {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_REQUEST_TOO_LARGE",
            ));
        }
        let endpoint = publication_route(base_url, route)?;
        self.validate_endpoint(&endpoint)?;
        let authorization =
            self.authorization(operation, operation_id, request_digest(operation, body)?)?;
        self.send(
            endpoint,
            APPLICATION_NORITO,
            &authorization,
            None,
            body.to_vec(),
        )
    }
    fn authorization(
        &self,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        digest: [u8; 32],
    ) -> Result<MusubiPublicationRuntimeAuthorizationV1, MusubiPublicationRuntimeTransportErrorV1>
    {
        self.authorization_with_clock(operation, operation_id, digest, system_time_ms)
    }
    fn authorization_with_clock<F>(
        &self,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        digest: [u8; 32],
        mut clock: F,
    ) -> Result<MusubiPublicationRuntimeAuthorizationV1, MusubiPublicationRuntimeTransportErrorV1>
    where
        F: FnMut() -> Result<u64, MusubiPublicationRuntimeTransportErrorV1>,
    {
        let issued_at_ms = self.sample_publication_time(&mut clock)?;
        let authorization = self.authorization_at(operation, operation_id, digest, issued_at_ms)?;
        let verification_time_ms = self.sample_publication_time(&mut clock)?;
        if verification_time_ms > authorization.payload.expires_at_ms {
            return Err(MusubiPublicationRuntimeTransportErrorV1::retryable(
                "MUSUBI_RUNTIME_AUTHORIZATION_SIGNER_UNAVAILABLE",
            ));
        }
        authorization.verify(operation, operation_id, digest, verification_time_ms)?;
        Ok(authorization)
    }
    fn authorization_at(
        &self,
        operation: MusubiPublicationRuntimeOperationV1,
        operation_id: [u8; 32],
        digest: [u8; 32],
        current_time_ms: u64,
    ) -> Result<MusubiPublicationRuntimeAuthorizationV1, MusubiPublicationRuntimeTransportErrorV1>
    {
        let payload = MusubiPublicationRuntimeAuthorizationPayloadV1 {
            domain: AUTH_DOMAIN_V1,
            version: 1,
            operation,
            operation_id,
            network_id: self.network_id,
            publisher: self.publisher.clone(),
            request_digest: digest,
            issued_at_ms: current_time_ms,
            expires_at_ms: current_time_ms
                .checked_add(DEFAULT_AUTHORIZATION_LIFETIME_MS)
                .ok_or_else(|| {
                    MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_RUNTIME_CLOCK_INVALID",
                    )
                })?,
        };
        payload.validate()?;
        let approvals = self
            .authorization_signer
            .sign_approvals(&payload)
            .map_err(|error| match error {
                MusubiPublicationRuntimeAuthorizationSigningErrorV1::Retryable => {
                    MusubiPublicationRuntimeTransportErrorV1::retryable(
                        "MUSUBI_RUNTIME_AUTHORIZATION_SIGNER_UNAVAILABLE",
                    )
                }
                MusubiPublicationRuntimeAuthorizationSigningErrorV1::Permanent => {
                    MusubiPublicationRuntimeTransportErrorV1::permanent(
                        "MUSUBI_RUNTIME_AUTHORIZATION_SIGNING_FAILED",
                    )
                }
            })?;
        let authorization = MusubiPublicationRuntimeAuthorizationV1 { payload, approvals };
        authorization.verify(operation, operation_id, digest, current_time_ms)?;
        Ok(authorization)
    }
    fn sample_publication_time<F>(
        &self,
        clock: &mut F,
    ) -> Result<u64, MusubiPublicationRuntimeTransportErrorV1>
    where
        F: FnMut() -> Result<u64, MusubiPublicationRuntimeTransportErrorV1>,
    {
        let current_time_ms = clock()?;
        if current_time_ms == 0
            || self
                .publication_clock_floor_ms
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |previous| {
                    (current_time_ms >= previous).then_some(current_time_ms)
                })
                .is_err()
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::retryable(
                "MUSUBI_RUNTIME_AUTHORIZATION_CLOCK_UNAVAILABLE",
            ));
        }
        Ok(current_time_ms)
    }
    fn ensure_request_identity(
        &self,
        network_id: &NetworkId,
        publisher: &AccountId,
    ) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
        if network_id != &self.network_id || publisher != &self.publisher {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_REQUEST_IDENTITY_MISMATCH",
            ));
        }
        Ok(())
    }
    fn send(
        &self,
        endpoint: Url,
        content_type: &'static str,
        authorization: &MusubiPublicationRuntimeAuthorizationV1,
        seed_ingress_metadata: Option<&[u8]>,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, MusubiPublicationRuntimeTransportErrorV1> {
        let request = self.prepare_request(
            endpoint,
            content_type,
            authorization,
            seed_ingress_metadata,
            body,
        )?;
        self.execute_request(request)
    }
    fn send_prepared_seed_ingress(
        &self,
        endpoint: Url,
        prepared: MusubiPreparedSeedIngressRequestV1,
    ) -> Result<Vec<u8>, MusubiPublicationRuntimeTransportErrorV1> {
        let MusubiPreparedSeedIngressRequestV1 {
            authorization_header,
            metadata_header,
            body,
            ..
        } = prepared;
        let mut authorization = HeaderValue::try_from(authorization_header).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_INVALID",
            )
        })?;
        authorization.set_sensitive(true);
        let mut metadata = HeaderValue::try_from(metadata_header).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_METADATA_TOO_LARGE",
            )
        })?;
        metadata.set_sensitive(true);
        self.validate_endpoint(&endpoint)?;
        let mut request = reqwest::blocking::Request::new(reqwest::Method::POST, endpoint);
        let headers = request.headers_mut();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_MUSUBI_SEED_ENVELOPE),
        );
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static(APPLICATION_NORITO),
        );
        headers.insert(AUTHORIZATION_HEADER, authorization);
        headers.insert(SEED_INGRESS_METADATA_HEADER, metadata);
        *request.body_mut() = Some(body.into());
        self.execute_request(request)
    }
    fn execute_request(
        &self,
        request: reqwest::blocking::Request,
    ) -> Result<Vec<u8>, MusubiPublicationRuntimeTransportErrorV1> {
        self.validate_endpoint(request.url())?;
        let mut response = match &self.http {
            PublicationHttpTransport::Remote(http) => http.execute(request).map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::retryable(
                    "MUSUBI_RUNTIME_TRANSPORT_FAILED",
                )
            })?,
            PublicationHttpTransport::Generated(http) => http.execute(request).map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::retryable(
                    "MUSUBI_RUNTIME_TRANSPORT_FAILED",
                )
            })?,
        };
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CONTROL_RESPONSE_BYTES_U64)
        {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_RESPONSE_TOO_LARGE",
            ));
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(MAX_CONTROL_RESPONSE_BYTES_U64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::retryable(
                    "MUSUBI_RUNTIME_RESPONSE_READ_FAILED",
                )
            })?;
        if bytes.len() > MAX_CONTROL_RESPONSE_BYTES {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_RESPONSE_TOO_LARGE",
            ));
        }
        if !status.is_success() {
            return Err(remote_transport_error(status, &bytes));
        }
        if bytes.is_empty() {
            return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_RESPONSE_TOO_LARGE",
            ));
        }
        Ok(bytes)
    }
    fn prepare_request(
        &self,
        endpoint: Url,
        content_type: &'static str,
        authorization: &MusubiPublicationRuntimeAuthorizationV1,
        seed_ingress_metadata: Option<&[u8]>,
        body: Vec<u8>,
    ) -> Result<reqwest::blocking::Request, MusubiPublicationRuntimeTransportErrorV1> {
        let authorization = encode_authorization_header(authorization)?;
        let mut authorization = HeaderValue::try_from(authorization).map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_RUNTIME_AUTHORIZATION_INVALID",
            )
        })?;
        authorization.set_sensitive(true);
        self.validate_endpoint(&endpoint)?;
        let mut request = reqwest::blocking::Request::new(reqwest::Method::POST, endpoint);
        let headers = request.headers_mut();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        );
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static(APPLICATION_NORITO),
        );
        headers.insert(AUTHORIZATION_HEADER, authorization);
        if let Some(metadata) = seed_ingress_metadata {
            if metadata.is_empty() || metadata.len() > MAX_SEED_INGRESS_METADATA_BYTES {
                return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
                    "MUSUBI_SEED_INGRESS_METADATA_TOO_LARGE",
                ));
            }
            let metadata = encode_seed_ingress_metadata_header(metadata)?;
            let mut metadata = HeaderValue::try_from(metadata).map_err(|_| {
                MusubiPublicationRuntimeTransportErrorV1::permanent(
                    "MUSUBI_SEED_INGRESS_METADATA_TOO_LARGE",
                )
            })?;
            metadata.set_sensitive(true);
            request
                .headers_mut()
                .insert(SEED_INGRESS_METADATA_HEADER, metadata);
        }
        *request.body_mut() = Some(body.into());
        Ok(request)
    }
}
/// Validate a credential-free HTTPS base used only by the private publication routes.
///
/// # Errors
///
/// Returns a stable permanent error unless the URL is an absolute credential-free HTTPS base with
/// a host, usable port, trailing slash, and no query, fragment, or public upload route.
pub fn validate_publication_service_base_url(
    url: &Url,
) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.port() == Some(0)
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
        || url.path().contains("/v1/sorafs/upload")
    {
        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_RUNTIME_SERVICE_URL_INVALID",
        ));
    }
    Ok(())
}
/// Return the scheme/host/port identity used to enforce distinct provider origins.
#[must_use]
pub fn publication_service_origin(url: &Url) -> Option<(String, String, u16)> {
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((url.scheme().to_owned(), host, port))
}
fn publication_route(
    base_url: &Url,
    route: &str,
) -> Result<Url, MusubiPublicationRuntimeTransportErrorV1> {
    base_url.join(route).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_SERVICE_URL_INVALID")
    })
}
fn system_time_ms() -> Result<u64, MusubiPublicationRuntimeTransportErrorV1> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_CLOCK_INVALID")
    })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_CLOCK_INVALID")
    })
}
fn verify_seed_ingress_receipt(
    receipt: &MusubiSeedIngressReceiptV1,
    expected_binding: &MusubiSeedIngressReceiptBindingV1,
    current_time_ms: u64,
) -> Result<(), MusubiPublicationRuntimeTransportErrorV1> {
    let latest_accepted_issue_time = current_time_ms
        .checked_add(MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1)
        .ok_or_else(|| {
            MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_CLOCK_INVALID")
        })?;
    if current_time_ms == 0 || receipt.payload.issued_at_ms > latest_accepted_issue_time {
        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_SEED_INGRESS_RECEIPT_INVALID",
        ));
    }
    receipt
        .verify(
            expected_binding,
            current_time_ms.max(receipt.payload.issued_at_ms),
        )
        .map_err(|_| {
            MusubiPublicationRuntimeTransportErrorV1::permanent(
                "MUSUBI_SEED_INGRESS_RECEIPT_INVALID",
            )
        })
}
fn request_digest(
    operation: MusubiPublicationRuntimeOperationV1,
    body: &[u8],
) -> Result<[u8; 32], MusubiPublicationRuntimeTransportErrorV1> {
    let body_length = u64::try_from(body.len()).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_REQUEST_TOO_LARGE")
    })?;
    let operation = norito::encode_canonical(&operation).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_REQUEST_INVALID")
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroha-musubi-publication-runtime-request-v1\0");
    hasher.update(&operation);
    hasher.update(&body_length.to_be_bytes());
    hasher.update(body);
    Ok(*hasher.finalize().as_bytes())
}
fn encode_authorization_header(
    authorization: &MusubiPublicationRuntimeAuthorizationV1,
) -> Result<String, MusubiPublicationRuntimeTransportErrorV1> {
    let authorization = norito::encode_canonical(authorization).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_AUTHORIZATION_INVALID")
    })?;
    if authorization.is_empty() || authorization.len() > MAX_AUTHORIZATION_BYTES {
        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_RUNTIME_AUTHORIZATION_TOO_LARGE",
        ));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(authorization))
}
fn encode_seed_ingress_metadata_header(
    metadata: &[u8],
) -> Result<String, MusubiPublicationRuntimeTransportErrorV1> {
    if metadata.is_empty() || metadata.len() > MAX_SEED_INGRESS_METADATA_BYTES {
        return Err(MusubiPublicationRuntimeTransportErrorV1::permanent(
            "MUSUBI_SEED_INGRESS_METADATA_TOO_LARGE",
        ));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(metadata))
}
fn decode_response<T>(bytes: &[u8]) -> Result<T, MusubiPublicationRuntimeTransportErrorV1>
where
    T: norito::core::NoritoSerialize,
    for<'de> T: norito::core::NoritoDeserialize<'de>,
{
    norito::decode_canonical_with_limits(bytes, RESPONSE_DECODE_LIMITS).map_err(|_| {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_RESPONSE_INVALID")
    })
}
fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}
fn remote_transport_error(
    status: StatusCode,
    body: &[u8],
) -> MusubiPublicationRuntimeTransportErrorV1 {
    if let Ok(error) = decode_response::<MusubiPublicationServiceErrorResponseV1>(body)
        && error.version == 1
    {
        return if error.retryable {
            MusubiPublicationRuntimeTransportErrorV1::retryable(error.code.as_str())
        } else {
            MusubiPublicationRuntimeTransportErrorV1::permanent(error.code.as_str())
        };
    }
    if retryable_status(status) {
        MusubiPublicationRuntimeTransportErrorV1::retryable("MUSUBI_RUNTIME_REMOTE_RETRYABLE")
    } else {
        MusubiPublicationRuntimeTransportErrorV1::permanent("MUSUBI_RUNTIME_REMOTE_REJECTED")
    }
}
#[cfg(test)]
mod tests {
    include!("tests/service_journal.rs");
    include!("tests/private_service.rs");
    mod storage_authorization {
        include!("tests/storage_authorization.rs");
    }
    mod generated_transport;
    pub mod wire_fixtures;
}
