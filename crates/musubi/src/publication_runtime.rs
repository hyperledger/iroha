//! Production-configured services for the resumable Musubi publication state machine.
//!
//! Endpoints and public deployment bindings are loaded only from the selected platform
//! `client.toml`. Account authentication reuses that file's Iroha signer through a fixed,
//! domain-separated request protocol; no token, credential, or provider URL enters a project,
//! command line, lockfile, or publication journal.
//! Storage coordination is deliberately downstream of journaled finalized registration evidence;
//! this service never registers an archive and never refreshes or replaces the receipt embedded
//! in the exact registration transaction. An exact active location replay is accepted by Core
//! before the location-set CAS check; any changed location request remains revision-gated.
use crate::{
    atomic_io::{AtomicWriteError, AtomicWriteErrorCode, AtomicWriteRoot},
    local_file::read_bounded_single_link_regular_file_v1,
    publish::{
        MUSUBI_MAX_PROVIDER_REGISTRATION_ATTEMPTS_V1, PublicationArchiveLocationAdvanceV1,
        PublicationArchiveLocationIntentV1, PublicationArchiveLocationTerminalReasonV1,
        PublicationArchiveLocationTerminalV1, PublicationArchiveRegistrationV1,
        PublicationBackendError, PublicationOperationIdV1,
        PublicationProviderRegistrationCheckpointAdvanceV1,
        PublicationProviderRegistrationCheckpointV1,
        PublicationProviderRegistrationTransactionCheckpointV1, PublicationReadbackEvidenceV1,
        PublicationRegisteredArchiveV1, PublicationRequestV1, PublicationValidationEvidenceV1,
        validate_archive_location_page,
    },
    registry::{
        PlatformConfigProvenanceV1, PublicationRuntimeServicesV1, RegistryFailureClassV1,
        RegistryReadClientV1, RegistrySigningClientV1, RegistryTerminalTransactionStateV1,
        RegistryTransactionStateV1, selected_client_config_path_v1,
    },
};
use iroha_data_model::{
    isi::{
        InstructionBox,
        musubi::{AddMusubiArchiveLocationV1, RegisterMusubiProviderBundleAttestationV1},
    },
    musubi::{
        ArchiveId, MUSUBI_MAX_LOCATION_PROVIDERS_V1, MUSUBI_MAX_PAGE_SIZE_V1,
        MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1, MusubiArchiveCommitmentV1,
        MusubiArchiveLocationPageV1, MusubiArchiveLocationQueryV1, MusubiArchiveLocationStateV1,
        MusubiNamespaceDelegationV1, MusubiPageRequestV1, MusubiProviderBundleAttestationDigestV1,
        MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRecordV1,
        MusubiProviderBundleAttestationRefV1, MusubiProviderBundleAttestationSetDigestV1,
        MusubiProviderBundleVerificationAttestationV1, MusubiSeedIngressReceiptBindingV1,
        MusubiSeedIngressReceiptV1, musubi_provider_bundle_attestation_set_digest_v1,
    },
    sorafs::capacity::ProviderId,
    sorafs::pin_registry::ReplicationOrderId,
    transaction::{Executable, SignedTransaction},
};
use iroha_musubi_service::{
    AuthenticatedMusubiPublicationRuntimeClientV1, MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1,
    MusubiFinalizedArchiveRegistrationEvidenceV1, MusubiProviderReadbackRequestV1,
    MusubiPublicationRuntimeTransportErrorV1, MusubiPublicationRuntimeTransportFailureClassV1,
    MusubiSeedIngressCarPlanV1, MusubiSeedIngressStageRequestV1,
    MusubiStorageCoordinationRequestV1, MusubiStorageCoordinationResponseV1,
    MusubiStorageLocationDispositionV1, publication_service_origin,
    validate_publication_service_base_url,
};
use norito::{Decode, DecodeLimits, Encode};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;
mod generated_local;
pub(crate) mod provider_inventory;
pub(crate) use generated_local::load_bound_generated_publication_runtime_v1;
pub use generated_local::{GeneratedPublicationContextV1, GeneratedPublicationNamespaceIntentV1};

const MAX_CLIENT_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_DELEGATION_BYTES: u64 = 256 * 1024;
const MAX_DELEGATION_BYTES_USIZE: usize = 256 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;
const PROVIDER_ATTESTATION_SET_CHECKPOINT_SCHEMA: &str =
    "musubi-provider-attestation-set-checkpoint";
const PROVIDER_ATTESTATION_CHECKPOINT_SCHEMA: &str = "musubi-provider-attestation-checkpoint";
const PROVIDER_ATTESTATION_CHECKPOINT_VERSION: u8 = 1;
const PROVIDER_ATTESTATION_SIDECAR_HASH_DOMAIN: &[u8] =
    b"iroha.musubi.provider-attestation-sidecar.v1";
const MAX_PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS: u8 =
    MUSUBI_MAX_PROVIDER_REGISTRATION_ATTEMPTS_V1;
const MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES: usize =
    MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1 * 2;
const DELEGATION_DECODE_LIMITS: DecodeLimits =
    DecodeLimits::new(64, MAX_DELEGATION_BYTES_USIZE, 256, 512 * 1024, 16);
const PROVIDER_ATTESTATION_CHECKPOINT_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES,
    MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES,
    MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES * 2,
    MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES * 4,
    64,
);
// The set checkpoint deliberately excludes the archive CAS revision. A finalized concurrent
// location transition may require rebasing still-missing registration transactions, but it must
// never permit the coordinator to substitute the archive/order/provider proof set for this
// publication generation.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "musubi::publication_runtime::PublicationProviderAttestationSetCheckpointV1"
)]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct PublicationProviderAttestationSetCheckpointV1 {
    schema: String,
    version: u8,
    operation_id: PublicationOperationIdV1,
    generation: u8,
    archive_id: ArchiveId,
    replication_order: ReplicationOrderId,
    attestations: Vec<MusubiProviderBundleVerificationAttestationV1>,
    set_digest: MusubiProviderBundleAttestationSetDigestV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publication_runtime::PublicationProviderAttestationCheckpointV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct PublicationProviderAttestationCheckpointV1 {
    schema: String,
    version: u8,
    operation_id: PublicationOperationIdV1,
    generation: u8,
    attempt: u8,
    expected_location_revision: u64,
    key: MusubiProviderBundleAttestationKeyV1,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
    signed_transaction: SignedTransaction,
    transaction_hash: [u8; 32],
}
impl PublicationProviderAttestationSetCheckpointV1 {
    fn new(
        operation_id: PublicationOperationIdV1,
        generation: u8,
        archive_id: ArchiveId,
        replication_order: ReplicationOrderId,
        attestations: Vec<MusubiProviderBundleVerificationAttestationV1>,
    ) -> Result<Self, PublicationBackendError> {
        if !(usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
            ..=MUSUBI_MAX_LOCATION_PROVIDERS_V1)
            .contains(&attestations.len())
        {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID",
            ));
        }
        let set_digest =
            retained_attestation_set_digest(archive_id, replication_order, &attestations)?;
        let selected = Self {
            schema: PROVIDER_ATTESTATION_SET_CHECKPOINT_SCHEMA.to_owned(),
            version: PROVIDER_ATTESTATION_CHECKPOINT_VERSION,
            operation_id,
            generation,
            archive_id,
            replication_order,
            attestations,
            set_digest,
        };
        selected.validate()?;
        Ok(selected)
    }
    fn validate(&self) -> Result<(), PublicationBackendError> {
        let invalid =
            || PublicationBackendError::permanent("PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID");
        if self.schema != PROVIDER_ATTESTATION_SET_CHECKPOINT_SCHEMA
            || self.version != PROVIDER_ATTESTATION_CHECKPOINT_VERSION
            || self.operation_id.as_bytes() == &[0; 32]
            || self.generation == 0
            || self.attestations.len()
                < usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
            || self.attestations.len() > MUSUBI_MAX_LOCATION_PROVIDERS_V1
        {
            return Err(invalid());
        }
        for attestation in &self.attestations {
            attestation
                .verify(&attestation.payload.binding)
                .map_err(|_| invalid())?;
            if attestation.key().archive_id != self.archive_id
                || attestation.key().replication_order != self.replication_order
            {
                return Err(invalid());
            }
        }
        let expected = retained_attestation_set_digest(
            self.archive_id,
            self.replication_order,
            &self.attestations,
        )?;
        if self.set_digest != expected {
            return Err(invalid());
        }
        Ok(())
    }
}
// Compact references are bounded stack scratch; neither an enclosing decoder's allocation
// allowance nor a full attestation graph is copied while recomputing the canonical set digest.
fn retained_attestation_set_digest(
    archive_id: ArchiveId,
    replication_order: ReplicationOrderId,
    attestations: &[MusubiProviderBundleVerificationAttestationV1],
) -> Result<MusubiProviderBundleAttestationSetDigestV1, PublicationBackendError> {
    let invalid =
        || PublicationBackendError::permanent("PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID");
    if !(usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
        ..=MUSUBI_MAX_LOCATION_PROVIDERS_V1)
        .contains(&attestations.len())
    {
        return Err(invalid());
    }
    let mut references = [MusubiProviderBundleAttestationRefV1 {
        provider_id: ProviderId::new([0; 32]),
        digest: MusubiProviderBundleAttestationDigestV1::new([0; 32]),
    }; MUSUBI_MAX_LOCATION_PROVIDERS_V1];
    for (reference, original) in references.iter_mut().zip(attestations) {
        *reference = original.reference();
    }
    musubi_provider_bundle_attestation_set_digest_v1(
        archive_id,
        replication_order,
        &references[..attestations.len()],
    )
    .map_err(|_| invalid())
}
impl PublicationProviderAttestationCheckpointV1 {
    fn new(
        operation_id: PublicationOperationIdV1,
        generation: u8,
        attempt: u8,
        expected_location_revision: u64,
        attestation: &MusubiProviderBundleVerificationAttestationV1,
        signed_transaction: SignedTransaction,
    ) -> Self {
        let transaction_hash = *signed_transaction.hash().as_ref();
        Self {
            schema: PROVIDER_ATTESTATION_CHECKPOINT_SCHEMA.to_owned(),
            version: PROVIDER_ATTESTATION_CHECKPOINT_VERSION,
            operation_id,
            generation,
            attempt,
            expected_location_revision,
            key: attestation.key(),
            attestation_digest: attestation.digest(),
            signed_transaction,
            transaction_hash,
        }
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        generation: u8,
        attempt: u8,
        request: &PublicationRequestV1,
        expected_location_revision: u64,
        attestation: &MusubiProviderBundleVerificationAttestationV1,
    ) -> Result<(), PublicationBackendError> {
        let instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision,
        );
        attestation
            .verify(&attestation.payload.binding)
            .map_err(|_| {
                PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
            })?;
        instruction.validate().map_err(|_| {
            PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
        })?;
        let expected_instruction: InstructionBox = instruction.into();
        let exact_instruction = matches!(
            self.signed_transaction.instructions(),
            Executable::Instructions(instructions)
                if instructions.len() == 1
                    && instructions.iter().next() == Some(&expected_instruction)
        );
        if self.schema != PROVIDER_ATTESTATION_CHECKPOINT_SCHEMA
            || self.version != PROVIDER_ATTESTATION_CHECKPOINT_VERSION
            || self.operation_id != operation_id
            || self.generation != generation
            || self.attempt != attempt
            || attempt == 0
            || attempt > MAX_PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS
            || self.expected_location_revision != expected_location_revision
            || self.key != attestation.key()
            || self.attestation_digest != attestation.digest()
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || self.transaction_hash != *self.signed_transaction.hash().as_ref()
            || self.signed_transaction.network_id().copied() != Some(request.network_id())
            || self.signed_transaction.authority() != &request.publisher
            || self.signed_transaction.verify_signature().is_err()
            || !exact_instruction
        {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_CHECKPOINT_INVALID",
            ));
        }
        Ok(())
    }
}
/// Public request bindings selected by the production platform configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPublicationBindingsV1 {
    /// Authenticated seed-ingress broker whose controller signs staging receipts.
    pub ingress_broker: iroha_data_model::account::AccountId,
    /// Seed provider selected for initial admitted ingress.
    pub seed_provider: ProviderId,
    /// Exact current registry admission-policy revision.
    pub expected_policy_revision: u64,
    /// Optional public generation-bound delegation for a delegated first package claim.
    pub namespace_delegation: Option<MusubiNamespaceDelegationV1>,
}
/// Stable, secret-redacted platform publication configuration failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionPublicationConfigurationErrorV1 {
    code: &'static str,
}
impl ProductionPublicationConfigurationErrorV1 {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
    /// Return the stable payload-free failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
impl fmt::Display for ProductionPublicationConfigurationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}
impl std::error::Error for ProductionPublicationConfigurationErrorV1 {}
/// Clean-package compiler validation injected by the packaging command.
pub trait PublicationCleanPackageValidatorV1 {
    /// Validate the exact packaged CAR and return secret-free evidence.
    ///
    /// # Errors
    ///
    /// Returns [`PublicationBackendError`] when the package cannot be validated or its evidence
    /// cannot be produced.
    fn validate_clean_package(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError>;
}
impl<F> PublicationCleanPackageValidatorV1 for F
where
    F: FnMut(
        PublicationOperationIdV1,
        &PublicationRequestV1,
        &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError>,
{
    fn validate_clean_package(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError> {
        self(operation_id, request, car)
    }
}
/// Fail-closed validator for callers that have not wired clean packaged-tree compilation.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePublicationCleanPackageValidatorV1;
impl PublicationCleanPackageValidatorV1 for UnavailablePublicationCleanPackageValidatorV1 {
    fn validate_clean_package(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError> {
        // Configuration-only callers may select this explicit sentinel. Executable publish and
        // resume commands inject their clean packaged-tree validator instead.
        Err(PublicationBackendError::permanent(
            "PACKAGE_VALIDATOR_NOT_CONFIGURED",
        ))
    }
}
#[derive(Clone)]
struct ProviderPublicationEndpointsV1 {
    readback: Url,
    attestation: Url,
}
#[derive(Clone)]
struct ParsedProductionPublicationConfigV1 {
    seed_ingress_url: Url,
    storage_coordinator_url: Url,
    provider_gateways: BTreeMap<ProviderId, ProviderPublicationEndpointsV1>,
    request_timeout: Duration,
    bindings: ProductionPublicationBindingsV1,
}
impl fmt::Debug for ParsedProductionPublicationConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedProductionPublicationConfigV1")
            .field("bindings", &self.bindings)
            .field("provider_gateway_count", &self.provider_gateways.len())
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}
/// Production implementation of the runtime-only publication service boundary.
pub struct ProductionPublicationRuntimeV1<V> {
    read: RegistryReadClientV1,
    signing: RegistrySigningClientV1,
    http: AuthenticatedMusubiPublicationRuntimeClientV1,
    validator: V,
    seed_ingress_url: Url,
    storage_coordinator_url: Url,
    provider_gateways: BTreeMap<ProviderId, ProviderPublicationEndpointsV1>,
    bindings: ProductionPublicationBindingsV1,
    checkpoint_root: Option<AtomicWriteRoot>,
    verified_provider_checkpoint: Option<PublicationProviderRegistrationCheckpointV1>,
    request_timeout: Duration,
}
impl<V> fmt::Debug for ProductionPublicationRuntimeV1<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionPublicationRuntimeV1")
            .field("publisher", self.signing.authority())
            .field("bindings", &self.bindings)
            .field("provider_gateway_count", &self.provider_gateways.len())
            .finish_non_exhaustive()
    }
}
impl<V> ProductionPublicationRuntimeV1<V> {
    /// Return the public request bindings while keeping runtime endpoints encapsulated.
    #[must_use]
    pub const fn bindings(&self) -> &ProductionPublicationBindingsV1 {
        &self.bindings
    }
    /// Bind immutable provider-attestation transaction checkpoints to the publication state root.
    ///
    /// The journal store must already have created its private `publication-v1` directory. An
    /// identical root may be rebound idempotently; switching roots after a runtime was loaded is
    /// rejected so an operation can never split its replay evidence across directories.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionPublicationConfigurationErrorV1`] when the root is unsafe or conflicts
    /// with a root already bound to this runtime.
    pub fn bind_publication_state_root(
        &mut self,
        user_state_root: &Path,
    ) -> Result<(), ProductionPublicationConfigurationErrorV1> {
        let root = AtomicWriteRoot::new(user_state_root).map_err(|_| {
            ProductionPublicationConfigurationErrorV1::new(
                "MUSUBI_PUBLICATION_CHECKPOINT_ROOT_INVALID",
            )
        })?;
        if self
            .checkpoint_root
            .as_ref()
            .is_some_and(|existing| existing.path() != root.path())
        {
            return Err(ProductionPublicationConfigurationErrorV1::new(
                "MUSUBI_PUBLICATION_CHECKPOINT_ROOT_CONFLICT",
            ));
        }
        self.checkpoint_root = Some(root);
        Ok(())
    }
    fn validate_request(
        &self,
        request: &PublicationRequestV1,
    ) -> Result<(), PublicationBackendError> {
        if request.network_id() != *self.http.network_id()
            || &request.publisher != self.http.publisher()
            || request.ingress_broker != self.bindings.ingress_broker
            || request.seed_provider != self.bindings.seed_provider
            || request.expected_policy_revision != self.bindings.expected_policy_revision
            || request.namespace_delegation != self.bindings.namespace_delegation
        {
            return Err(PublicationBackendError::permanent(
                "PUBLICATION_PLATFORM_BINDING_MISMATCH",
            ));
        }
        Ok(())
    }
    fn checkpoint_root(&self) -> Result<&AtomicWriteRoot, PublicationBackendError> {
        self.checkpoint_root.as_ref().ok_or_else(|| {
            PublicationBackendError::permanent("PUBLICATION_CHECKPOINT_STORE_NOT_BOUND")
        })
    }
    fn persist_attestation_set_checkpoint(
        &self,
        checkpoint: &PublicationProviderAttestationSetCheckpointV1,
    ) -> Result<[u8; 32], PublicationBackendError> {
        checkpoint.validate()?;
        let encoded = encode_attestation_set_checkpoint(checkpoint)?;
        let sidecar_hash = provider_attestation_sidecar_hash(&encoded);
        self.checkpoint_root()?
            .install_immutable(
                &provider_attestation_set_checkpoint_relative_path(
                    checkpoint.operation_id,
                    checkpoint.generation,
                ),
                &encoded,
            )
            .map_err(map_provider_checkpoint_io)?;
        Ok(sidecar_hash)
    }
    fn validate_anchored_attestation_set_checkpoint(
        &self,
        checkpoint: &PublicationProviderAttestationSetCheckpointV1,
        expected_sidecar_hash: [u8; 32],
    ) -> Result<(), PublicationBackendError> {
        checkpoint.validate()?;
        let expected_bytes = encode_attestation_set_checkpoint(checkpoint)?;
        if expected_sidecar_hash.iter().all(|byte| *byte == 0)
            || provider_attestation_sidecar_hash(&expected_bytes) != expected_sidecar_hash
        {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID",
            ));
        }
        let relative = provider_attestation_set_checkpoint_relative_path(
            checkpoint.operation_id,
            checkpoint.generation,
        );
        let observed = self
            .checkpoint_root()?
            .load_immutable(&relative, MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES)
            .map_err(map_provider_checkpoint_io)?
            .ok_or_else(|| {
                PublicationBackendError::permanent("PROVIDER_ATTESTATION_SET_CHECKPOINT_MISSING")
            })?;
        if observed != expected_bytes
            || provider_attestation_sidecar_hash(&observed) != expected_sidecar_hash
        {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID",
            ));
        }
        Ok(())
    }
    fn load_or_prepare_provider_checkpoint(
        &self,
        operation_id: PublicationOperationIdV1,
        generation: u8,
        attempt: u8,
        request: &PublicationRequestV1,
        expected_location_revision: u64,
        attestation: &MusubiProviderBundleVerificationAttestationV1,
    ) -> Result<PublicationProviderAttestationCheckpointV1, PublicationBackendError> {
        let relative = provider_attestation_checkpoint_relative_path(
            operation_id,
            generation,
            attempt,
            expected_location_revision,
            attestation.key().provider_id,
            attestation.digest(),
        );
        if let Some(encoded) = self
            .checkpoint_root()?
            .load_immutable(&relative, MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES)
            .map_err(map_provider_checkpoint_io)?
        {
            let checkpoint: PublicationProviderAttestationCheckpointV1 =
                norito::decode_canonical_with_limits(
                    &encoded,
                    PROVIDER_ATTESTATION_CHECKPOINT_DECODE_LIMITS,
                )
                .map_err(|_| {
                    PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
                })?;
            checkpoint.validate_for(
                operation_id,
                generation,
                attempt,
                request,
                expected_location_revision,
                attestation,
            )?;
            return Ok(checkpoint);
        }
        let instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision,
        );
        instruction.validate().map_err(|_| {
            PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
        })?;
        let payload = self
            .signing
            .prebuild_v1(instruction)
            .map_err(map_registry_error)?;
        let signed_transaction = self
            .signing
            .quote_and_sign_v1(payload)
            .map_err(map_registry_error)?;
        let checkpoint = PublicationProviderAttestationCheckpointV1::new(
            operation_id,
            generation,
            attempt,
            expected_location_revision,
            attestation,
            signed_transaction,
        );
        checkpoint.validate_for(
            operation_id,
            generation,
            attempt,
            request,
            expected_location_revision,
            attestation,
        )?;
        let encoded = encode_provider_attestation_checkpoint(&checkpoint)?;
        self.checkpoint_root()?
            .install_immutable(&relative, &encoded)
            .map_err(map_provider_checkpoint_io)?;
        let installed = self
            .checkpoint_root()?
            .load_immutable(&relative, MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES)
            .map_err(map_provider_checkpoint_io)?
            .ok_or_else(|| {
                PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_MISSING")
            })?;
        let installed: PublicationProviderAttestationCheckpointV1 =
            norito::decode_canonical_with_limits(
                &installed,
                PROVIDER_ATTESTATION_CHECKPOINT_DECODE_LIMITS,
            )
            .map_err(|_| {
                PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
            })?;
        installed.validate_for(
            operation_id,
            generation,
            attempt,
            request,
            expected_location_revision,
            attestation,
        )?;
        Ok(installed)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "checkpoint loading binds every immutable publication and attestation coordinate explicitly"
    )]
    fn load_anchored_provider_checkpoint(
        &self,
        operation_id: PublicationOperationIdV1,
        generation: u8,
        attempt: u8,
        request: &PublicationRequestV1,
        expected_location_revision: u64,
        attestation: &MusubiProviderBundleVerificationAttestationV1,
        expected_sidecar_hash: [u8; 32],
    ) -> Result<PublicationProviderAttestationCheckpointV1, PublicationBackendError> {
        if expected_sidecar_hash.iter().all(|byte| *byte == 0) {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_CHECKPOINT_INVALID",
            ));
        }
        let relative = provider_attestation_checkpoint_relative_path(
            operation_id,
            generation,
            attempt,
            expected_location_revision,
            attestation.key().provider_id,
            attestation.digest(),
        );
        let encoded = self
            .checkpoint_root()?
            .load_immutable(&relative, MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES)
            .map_err(map_provider_checkpoint_io)?
            .ok_or_else(|| {
                PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_MISSING")
            })?;
        if provider_attestation_sidecar_hash(&encoded) != expected_sidecar_hash {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_CHECKPOINT_INVALID",
            ));
        }
        let checkpoint: PublicationProviderAttestationCheckpointV1 =
            norito::decode_canonical_with_limits(
                &encoded,
                PROVIDER_ATTESTATION_CHECKPOINT_DECODE_LIMITS,
            )
            .map_err(|_| {
                PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
            })?;
        checkpoint.validate_for(
            operation_id,
            generation,
            attempt,
            request,
            expected_location_revision,
            attestation,
        )?;
        let expected_bytes = encode_provider_attestation_checkpoint(&checkpoint)?;
        if encoded != expected_bytes {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_CHECKPOINT_INVALID",
            ));
        }
        Ok(checkpoint)
    }
    fn exact_provider_attestation_registered(
        &self,
        registered: &PublicationRegisteredArchiveV1,
        attestation: &MusubiProviderBundleVerificationAttestationV1,
    ) -> Result<bool, PublicationBackendError> {
        let key = attestation.key();
        let Some(record) = self
            .read
            .provider_bundle_attestation(key)
            .map_err(map_registry_error)?
        else {
            return Ok(false);
        };
        validate_exact_provider_attestation_record(registered, attestation, &record)?;
        Ok(true)
    }
    fn coordinate_absent_archive_location(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[iroha_data_model::musubi::MusubiArchiveLocationIdV1],
        checkpoint: Option<&PublicationProviderRegistrationCheckpointV1>,
    ) -> Result<
        (
            MusubiStorageCoordinationResponseV1,
            MusubiArchiveLocationPageV1,
            PublicationProviderAttestationSetCheckpointV1,
        ),
        PublicationBackendError,
    > {
        if generation == 0
            || usize::from(generation) > MUSUBI_MAX_PUBLICATION_LOCATION_ATTEMPTS_V1
            || prior_location_ids.len() + 1 != usize::from(generation)
            || prior_location_ids
                .iter()
                .any(iroha_data_model::musubi::MusubiArchiveLocationIdV1::is_zero)
        {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_GENERATION_INVALID",
            ));
        }
        let mut sorted_prior_location_ids = prior_location_ids.to_vec();
        sorted_prior_location_ids.sort();
        if sorted_prior_location_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_GENERATION_INVALID",
            ));
        }
        let coordination_request = MusubiStorageCoordinationRequestV1 {
            version: 1,
            operation_id: *operation_id.as_bytes(),
            generation,
            prior_location_ids: sorted_prior_location_ids,
            network_id: request.network_id(),
            publisher: request.publisher.clone(),
            commitment: request.archive_commitment.clone(),
            verification_lock_digest: request.publication.manifest.verification_lock_digest,
            staging_receipt: registered.archive.staging_receipt.clone(),
            expected_policy_revision: request.expected_policy_revision,
            finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1 {
                version: 1,
                network_id: request.network_id(),
                transaction_hash: registered.finalized_transaction_hash,
                snapshot: registered.snapshot,
                registration: registered.archive.registration_projection(),
            },
        };
        let response = self
            .http
            .coordinate_storage(&self.storage_coordinator_url, &coordination_request)
            .map_err(map_transport_error)?;
        if response.archive.registration_projection()
            != registered.archive.registration_projection()
        {
            return Err(PublicationBackendError::permanent(
                "STORAGE_COORDINATOR_ARCHIVE_CONFLICT",
            ));
        }
        let attestation_set = self.acquire_provider_attestation_set(
            operation_id,
            generation,
            request,
            &response,
            checkpoint,
        )?;
        let FinalizedLocationStateV1::Absent { page } = self.finalized_location_state(
            request,
            registered,
            &response,
            attestation_set.set_digest,
        )?
        else {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_UNJOURNALED_FINALITY",
            ));
        };
        let MusubiStorageLocationDispositionV1::NeedsRegistration {
            expected_location_revision,
            ..
        } = &response.disposition
        else {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_UNJOURNALED_FINALITY",
            ));
        };
        if *expected_location_revision != page.archive.location_revision {
            return Err(PublicationBackendError::retryable(
                "STORAGE_COORDINATOR_LOCATION_REVISION_STALE",
            ));
        }
        Ok((response, page, attestation_set))
    }
    fn validate_provider_registration_checkpoint(
        &self,
        operation_id: PublicationOperationIdV1,
        generation: u8,
        request: &PublicationRequestV1,
        attestation_set: &PublicationProviderAttestationSetCheckpointV1,
        provider_attestations: &[MusubiProviderBundleVerificationAttestationV1],
        checkpoint: &PublicationProviderRegistrationCheckpointV1,
    ) -> Result<(), PublicationBackendError> {
        checkpoint.validate_for(request, generation).map_err(|_| {
            PublicationBackendError::permanent("PROVIDER_REGISTRATION_CHECKPOINT_INVALID")
        })?;
        if checkpoint.generation != generation
            || checkpoint.archive_id != attestation_set.archive_id
            || checkpoint.replication_order != attestation_set.replication_order
            || checkpoint.provider_attestation_set_digest != attestation_set.set_digest
        {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_REGISTRATION_CHECKPOINT_INVALID",
            ));
        }
        self.validate_anchored_attestation_set_checkpoint(
            attestation_set,
            checkpoint.set_sidecar_hash,
        )?;
        for transaction in &checkpoint.transactions {
            let attestation = provider_attestations
                .iter()
                .find(|attestation| {
                    attestation.key() == transaction.key
                        && attestation.digest() == transaction.attestation_digest
                })
                .ok_or_else(|| {
                    PublicationBackendError::permanent("PROVIDER_REGISTRATION_CHECKPOINT_INVALID")
                })?;
            let loaded = self.load_anchored_provider_checkpoint(
                operation_id,
                generation,
                transaction.attempt,
                request,
                transaction.expected_location_revision,
                attestation,
                transaction.sidecar_hash,
            )?;
            if loaded.transaction_hash != transaction.transaction_hash {
                return Err(PublicationBackendError::permanent(
                    "PROVIDER_REGISTRATION_CHECKPOINT_INVALID",
                ));
            }
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "the append operation records every signed provider-registration coordinate explicitly"
    )]
    fn append_provider_registration_transaction_checkpoint(
        &self,
        operation_id: PublicationOperationIdV1,
        generation: u8,
        request: &PublicationRequestV1,
        checkpoint: &PublicationProviderRegistrationCheckpointV1,
        attempt: u8,
        expected_location_revision: u64,
        attestation: &MusubiProviderBundleVerificationAttestationV1,
    ) -> Result<PublicationProviderRegistrationCheckpointAdvanceV1, PublicationBackendError> {
        let sidecar = self.load_or_prepare_provider_checkpoint(
            operation_id,
            generation,
            attempt,
            request,
            expected_location_revision,
            attestation,
        )?;
        let encoded = encode_provider_attestation_checkpoint(&sidecar)?;
        let mut updated = checkpoint.clone();
        updated
            .transactions
            .push(PublicationProviderRegistrationTransactionCheckpointV1 {
                attempt,
                expected_location_revision,
                key: attestation.key(),
                attestation_digest: attestation.digest(),
                transaction_hash: sidecar.transaction_hash,
                sidecar_hash: provider_attestation_sidecar_hash(&encoded),
            });
        updated.validate_for(request, generation).map_err(|_| {
            PublicationBackendError::permanent("PROVIDER_REGISTRATION_CHECKPOINT_INVALID")
        })?;
        Ok(PublicationProviderRegistrationCheckpointAdvanceV1::Updated(
            updated,
        ))
    }
    fn provider_attestation_rejection_rebase_revision(
        &self,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        signed_expected_location_revision: u64,
        rejection_height: Option<u64>,
    ) -> Result<u64, PublicationBackendError> {
        let Some(rejection_height) = rejection_height else {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_TRANSACTION_STATUS_INVALID",
            ));
        };
        if rejection_height <= registered.snapshot.finalized_height {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_TRANSACTION_STATUS_INVALID",
            ));
        }
        let page = self.finalized_archive_page(request, registered)?;
        if page.snapshot.finalized_height < rejection_height {
            return Err(PublicationBackendError::retryable(
                "PROVIDER_ATTESTATION_FINALIZED_QUERY_PENDING",
            ));
        }
        if page.archive.location_revision <= signed_expected_location_revision {
            return Err(PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_REGISTRATION_TERMINAL",
            ));
        }
        Ok(page.archive.location_revision)
    }
    fn finalized_archive_page(
        &self,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
    ) -> Result<MusubiArchiveLocationPageV1, PublicationBackendError> {
        let page = self
            .read
            .archive_locations(&MusubiArchiveLocationQueryV1 {
                archive_id: request.archive_commitment.archive_id(),
                page: MusubiPageRequestV1 {
                    limit: u32::try_from(MUSUBI_MAX_PAGE_SIZE_V1)
                        .expect("the fixed Musubi V1 page bound fits u32"),
                    cursor: None,
                },
            })
            .map_err(map_registry_error)?
            .ok_or_else(|| {
                PublicationBackendError::retryable("ARCHIVE_LOCATION_FINALIZED_QUERY_PENDING")
            })?;
        validate_finalized_archive_page(request, registered, &page)?;
        if page.next_cursor.is_some()
            || page.items.len() != page.archive.location_ids.len()
            || page
                .items
                .iter()
                .zip(&page.archive.location_ids)
                .any(|(location, location_id)| location.location_id != *location_id)
        {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_FINALIZED_PAGE_INCOMPLETE",
            ));
        }
        Ok(page)
    }
    fn finalized_location_state(
        &self,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        response: &MusubiStorageCoordinationResponseV1,
        provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
    ) -> Result<FinalizedLocationStateV1, PublicationBackendError> {
        let page = self.finalized_archive_page(request, registered)?;
        if page.archive.location_revision < response.archive.location_revision {
            return Err(PublicationBackendError::retryable(
                "ARCHIVE_LOCATION_FINALIZED_SNAPSHOT_STALE",
            ));
        }
        let Ok(index) = page
            .items
            .binary_search_by_key(&response.location_id, |location| location.location_id)
        else {
            // A location present in the coordinator's finalized current archive but absent from
            // the current non-retired directory was retired. Stable location identities are
            // never reusable, so do not loop on a mutation Core must permanently reject.
            if response
                .archive
                .location_ids
                .binary_search(&response.location_id)
                .is_ok()
            {
                return Err(PublicationBackendError::permanent(
                    "ARCHIVE_LOCATION_ID_CONFLICT",
                ));
            }
            if page.archive.location_revision == u64::MAX {
                return Err(PublicationBackendError::permanent(
                    "ARCHIVE_LOCATION_REVISION_EXHAUSTED",
                ));
            }
            return Ok(FinalizedLocationStateV1::Absent { page });
        };
        let location = &page.items[index];
        if location.state == MusubiArchiveLocationStateV1::Retired {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_ID_CONFLICT",
            ));
        }
        if !location_matches_coordination_response(
            location,
            response,
            provider_attestation_set_digest,
        ) {
            return Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_ID_CONFLICT",
            ));
        }
        Ok(FinalizedLocationStateV1::Exact { page })
    }
    fn location_transaction_advance(
        &self,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        intent: &PublicationArchiveLocationIntentV1,
        state: RegistryTransactionStateV1,
    ) -> Result<PublicationArchiveLocationAdvanceV1, PublicationBackendError> {
        if state == RegistryTransactionStateV1::Pending
            || state == RegistryTransactionStateV1::Absent
        {
            return Ok(PublicationArchiveLocationAdvanceV1::Pending);
        }
        let page = self.finalized_archive_page(request, registered)?;
        validate_archive_location_page(request, registered, &page).map_err(|_| {
            PublicationBackendError::permanent("ARCHIVE_LOCATION_FINALIZED_PAGE_INVALID")
        })?;
        let location_present = page
            .items
            .binary_search_by_key(&intent.location_id, |location| location.location_id)
            .is_ok();
        match state {
            RegistryTransactionStateV1::Applied { block_height } => {
                if block_height <= intent.prepared_page.snapshot.finalized_height {
                    return Err(PublicationBackendError::permanent(
                        "ARCHIVE_LOCATION_TRANSACTION_STATUS_INVALID",
                    ));
                }
                if page.snapshot.finalized_height < block_height {
                    return Ok(PublicationArchiveLocationAdvanceV1::Pending);
                }
                if location_present {
                    return Ok(PublicationArchiveLocationAdvanceV1::Registered(
                        PublicationArchiveRegistrationV1 {
                            intent: intent.clone(),
                            applied_height: block_height,
                            finalized_page: page,
                        },
                    ));
                }
                if page.archive.location_revision
                    > intent.expected_location_revision.saturating_add(1)
                {
                    return Ok(PublicationArchiveLocationAdvanceV1::Terminal(
                        PublicationArchiveLocationTerminalV1 {
                            transaction_hash: intent.transaction_hash,
                            reason:
                                PublicationArchiveLocationTerminalReasonV1::AppliedThenRetired {
                                    applied_height: block_height,
                                },
                            finalized_page: page,
                        },
                    ));
                }
                Err(PublicationBackendError::permanent(
                    "ARCHIVE_LOCATION_APPLIED_STATE_MISSING",
                ))
            }
            RegistryTransactionStateV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Rejected,
                block_height: Some(block_height),
            } => {
                if block_height <= intent.prepared_page.snapshot.finalized_height {
                    return Err(PublicationBackendError::permanent(
                        "ARCHIVE_LOCATION_TRANSACTION_STATUS_INVALID",
                    ));
                }
                if page.snapshot.finalized_height < block_height {
                    return Ok(PublicationArchiveLocationAdvanceV1::Pending);
                }
                if location_present {
                    return Err(PublicationBackendError::permanent(
                        "ARCHIVE_LOCATION_REJECTED_ID_PRESENT",
                    ));
                }
                if page.archive.location_revision <= intent.expected_location_revision {
                    return Err(PublicationBackendError::permanent(
                        "ARCHIVE_LOCATION_REGISTRATION_REJECTED",
                    ));
                }
                Ok(PublicationArchiveLocationAdvanceV1::Terminal(
                    PublicationArchiveLocationTerminalV1 {
                        transaction_hash: intent.transaction_hash,
                        reason: PublicationArchiveLocationTerminalReasonV1::RejectedRebase {
                            block_height,
                        },
                        finalized_page: page,
                    },
                ))
            }
            RegistryTransactionStateV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Rejected,
                block_height: None,
            } => Err(PublicationBackendError::permanent(
                "ARCHIVE_LOCATION_TRANSACTION_STATUS_INVALID",
            )),
            RegistryTransactionStateV1::Terminal {
                kind: RegistryTerminalTransactionStateV1::Expired,
                block_height,
            } => {
                if block_height
                    .is_some_and(|height| height <= intent.prepared_page.snapshot.finalized_height)
                {
                    return Err(PublicationBackendError::permanent(
                        "ARCHIVE_LOCATION_TRANSACTION_STATUS_INVALID",
                    ));
                }
                if block_height.is_some_and(|height| page.snapshot.finalized_height < height) {
                    return Ok(PublicationArchiveLocationAdvanceV1::Pending);
                }
                if location_present {
                    return Err(PublicationBackendError::permanent(
                        "ARCHIVE_LOCATION_EXPIRED_ID_PRESENT",
                    ));
                }
                Ok(PublicationArchiveLocationAdvanceV1::Terminal(
                    PublicationArchiveLocationTerminalV1 {
                        transaction_hash: intent.transaction_hash,
                        reason: PublicationArchiveLocationTerminalReasonV1::RegistryExpired {
                            block_height,
                        },
                        finalized_page: page,
                    },
                ))
            }
            RegistryTransactionStateV1::Pending | RegistryTransactionStateV1::Absent => {
                Ok(PublicationArchiveLocationAdvanceV1::Pending)
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum FinalizedLocationStateV1 {
    Exact { page: MusubiArchiveLocationPageV1 },
    Absent { page: MusubiArchiveLocationPageV1 },
}
fn validate_exact_provider_attestation_record(
    registered: &PublicationRegisteredArchiveV1,
    expected: &MusubiProviderBundleVerificationAttestationV1,
    record: &MusubiProviderBundleAttestationRecordV1,
) -> Result<(), PublicationBackendError> {
    record.validate().map_err(|_| {
        PublicationBackendError::permanent("PROVIDER_ATTESTATION_FINALIZED_RECORD_INVALID")
    })?;
    record
        .attestation
        .verify(&record.attestation.payload.binding)
        .map_err(|_| {
            PublicationBackendError::permanent("PROVIDER_ATTESTATION_FINALIZED_RECORD_INVALID")
        })?;
    if record.key != expected.key()
        || record.attestation_digest != expected.digest()
        || record.attestation != *expected
        || record.registered_at_height <= registered.archive.registered_at_height
    {
        return Err(PublicationBackendError::permanent(
            "PROVIDER_ATTESTATION_FINALIZED_RECORD_CONFLICT",
        ));
    }
    Ok(())
}
fn validate_finalized_archive_page(
    request: &PublicationRequestV1,
    registered: &PublicationRegisteredArchiveV1,
    page: &MusubiArchiveLocationPageV1,
) -> Result<(), PublicationBackendError> {
    page.validate().map_err(|_| {
        PublicationBackendError::permanent("ARCHIVE_LOCATION_FINALIZED_PAGE_INVALID")
    })?;
    let expected = &registered.archive;
    let observed = &page.archive;
    if page.snapshot.finalized_height < registered.snapshot.finalized_height
        || page.snapshot.index_revision < registered.snapshot.index_revision
    {
        return Err(PublicationBackendError::retryable(
            "ARCHIVE_LOCATION_FINALIZED_SNAPSHOT_STALE",
        ));
    }
    if page.snapshot.finalized_height == registered.snapshot.finalized_height
        && page.snapshot != registered.snapshot
    {
        return Err(PublicationBackendError::permanent(
            "ARCHIVE_LOCATION_FINALIZED_SNAPSHOT_CONFLICT",
        ));
    }
    if observed.location_revision < expected.location_revision {
        return Err(PublicationBackendError::retryable(
            "ARCHIVE_LOCATION_FINALIZED_SNAPSHOT_STALE",
        ));
    }
    if page.snapshot == registered.snapshot && observed != expected {
        return Err(PublicationBackendError::permanent(
            "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT",
        ));
    }
    if registered.network_id != request.network_id
        || expected.archive_id != request.archive_commitment.archive_id()
        || expected.commitment != request.archive_commitment
        || expected.registered_by != request.publisher
        || page.network_id != request.network_id()
        || observed.archive_id != expected.archive_id
        || observed.commitment != expected.commitment
        || observed.staging_receipt != expected.staging_receipt
        || observed.registered_by != expected.registered_by
        || observed.registered_at_height != expected.registered_at_height
    {
        return Err(PublicationBackendError::permanent(
            "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT",
        ));
    }
    Ok(())
}
fn location_matches_coordination_response(
    location: &iroha_data_model::musubi::MusubiArchiveLocationV1,
    response: &MusubiStorageCoordinationResponseV1,
    provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
) -> bool {
    location.location_id == response.location_id
        && location.archive_id == response.archive.archive_id
        && location.pin_manifest == response.pin_manifest
        && location.replication_order == response.replication_order
        && location.provider_attestation_set_digest == provider_attestation_set_digest
        && location.renew_after_epoch == response.renew_after_epoch
        && location.expires_at_epoch == response.expires_at_epoch
}
fn location_add_instruction(
    response: &MusubiStorageCoordinationResponseV1,
    expected_location_revision: u64,
    provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
) -> Result<AddMusubiArchiveLocationV1, PublicationBackendError> {
    Ok(AddMusubiArchiveLocationV1 {
        archive_id: response.archive.archive_id,
        location_id: response.location_id,
        pin_manifest: response.pin_manifest,
        replication_order: response.replication_order,
        provider_attestation_set_digest,
        renew_after_epoch: response.renew_after_epoch,
        expires_at_epoch: response.expires_at_epoch,
        expected_location_revision,
    })
}
fn provider_attestation_set_checkpoint_relative_path(
    operation_id: PublicationOperationIdV1,
    generation: u8,
) -> PathBuf {
    Path::new(iroha_musubi_service::publication_client_journal::DIRECTORY_NAME).join(format!(
        "{operation_id}.location-{generation:02}.provider-set.norito"
    ))
}
fn encode_attestation_set_checkpoint(
    checkpoint: &PublicationProviderAttestationSetCheckpointV1,
) -> Result<Vec<u8>, PublicationBackendError> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let invalid =
        || PublicationBackendError::permanent("PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID");
    checkpoint.validate()?;
    let length = norito::canonical_frame_len(checkpoint).map_err(|_| invalid())?;
    if length == 0 || length > MAX_PROVIDER_ATTESTATION_SET_CHECKPOINT_BYTES {
        return Err(PublicationBackendError::permanent(
            "PROVIDER_ATTESTATION_SET_CHECKPOINT_INVALID",
        ));
    }
    norito::core::to_bytes_bounded(checkpoint, length).map_err(|_| invalid())
}
fn encode_provider_attestation_checkpoint(
    checkpoint: &PublicationProviderAttestationCheckpointV1,
) -> Result<Vec<u8>, PublicationBackendError> {
    let encoded = norito::encode_canonical(checkpoint).map_err(|_| {
        PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_INVALID")
    })?;
    if encoded.is_empty() || encoded.len() > MAX_PROVIDER_ATTESTATION_CHECKPOINT_BYTES {
        return Err(PublicationBackendError::permanent(
            "PROVIDER_ATTESTATION_CHECKPOINT_INVALID",
        ));
    }
    Ok(encoded)
}
fn provider_attestation_sidecar_hash(encoded: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(
        &u64::try_from(PROVIDER_ATTESTATION_SIDECAR_HASH_DOMAIN.len())
            .expect("provider checkpoint hash domain length fits u64")
            .to_le_bytes(),
    );
    hasher.update(PROVIDER_ATTESTATION_SIDECAR_HASH_DOMAIN);
    hasher.update(
        &u64::try_from(encoded.len())
            .expect("bounded provider checkpoint length fits u64")
            .to_le_bytes(),
    );
    hasher.update(encoded);
    *hasher.finalize().as_bytes()
}
fn provider_attestation_checkpoint_relative_path(
    operation_id: PublicationOperationIdV1,
    generation: u8,
    attempt: u8,
    expected_location_revision: u64,
    provider_id: ProviderId,
    attestation_digest: MusubiProviderBundleAttestationDigestV1,
) -> PathBuf {
    // Unlike the stable set anchor, an exact registration instruction includes the current CAS
    // revision. Keep revision-specific signed transactions disjoint so a safe rebase cannot
    // collide with an immutable checkpoint prepared against an older finalized revision.
    Path::new(iroha_musubi_service::publication_client_journal::DIRECTORY_NAME).join(format!(
        "{operation_id}.l{generation:02}.t{attempt:02}.r{expected_location_revision:016x}.p{}.a{}.norito",
        hex::encode(provider_id.as_bytes()),
        hex::encode(attestation_digest.as_bytes())
    ))
}
fn next_provider_attestation_registration_attempt(
    attempt: u8,
) -> Result<u8, PublicationBackendError> {
    attempt
        .checked_add(1)
        .filter(|next| *next <= MAX_PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS)
        .ok_or_else(|| {
            PublicationBackendError::permanent(
                "PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS_EXHAUSTED",
            )
        })
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "this adapter is passed directly to Result::map_err and consumes its owned error value"
)]
fn map_provider_checkpoint_io(error: AtomicWriteError) -> PublicationBackendError {
    match error.code() {
        AtomicWriteErrorCode::ImmutableConflict => {
            PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_CONFLICT")
        }
        _ => PublicationBackendError::permanent("PROVIDER_ATTESTATION_CHECKPOINT_IO"),
    }
}
impl<V: PublicationCleanPackageValidatorV1> PublicationRuntimeServicesV1
    for ProductionPublicationRuntimeV1<V>
{
    fn validate_clean_package(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError> {
        self.validate_request(request)?;
        self.validator
            .validate_clean_package(operation_id, request, car)
    }
    fn stage_authenticated_seed_ingress(
        &mut self,
        operation_id: PublicationOperationIdV1,
        expected: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &MusubiSeedIngressCarPlanV1,
        car: &mut dyn Read,
    ) -> Result<MusubiSeedIngressReceiptV1, PublicationBackendError> {
        if expected.network_id != *self.http.network_id()
            || expected.publisher != *self.http.publisher()
            || expected.ingress_broker != self.bindings.ingress_broker
            || expected.seed_provider != self.bindings.seed_provider
        {
            return Err(PublicationBackendError::permanent(
                "PUBLICATION_PLATFORM_BINDING_MISMATCH",
            ));
        }
        let car_plan = plan
            .to_car_build_plan(commitment)
            .map_err(map_transport_error)?;
        let request = MusubiSeedIngressStageRequestV1 {
            version: 1,
            operation_id: *operation_id.as_bytes(),
            binding: expected.clone(),
            commitment: commitment.clone(),
            plan_digest: plan.canonical_digest().map_err(map_transport_error)?,
            plan_length: plan.canonical_len().map_err(map_transport_error)?,
        };
        self.http
            .stage_seed_ingress(&self.seed_ingress_url, &request, &car_plan, car)
            .map_err(map_transport_error)
    }
    fn checkpoint_archive_location_provider_registrations(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[iroha_data_model::musubi::MusubiArchiveLocationIdV1],
        checkpoint: Option<&PublicationProviderRegistrationCheckpointV1>,
    ) -> Result<PublicationProviderRegistrationCheckpointAdvanceV1, PublicationBackendError> {
        self.verified_provider_checkpoint = None;
        self.validate_request(request)?;
        let (_response, page, attestation_set) = self.coordinate_absent_archive_location(
            operation_id,
            request,
            registered,
            generation,
            prior_location_ids,
            checkpoint,
        )?;
        let provider_attestations = &attestation_set.attestations;
        let Some(checkpoint) = checkpoint else {
            let set_sidecar_hash = self.persist_attestation_set_checkpoint(&attestation_set)?;
            let checkpoint = PublicationProviderRegistrationCheckpointV1 {
                generation,
                archive_id: attestation_set.archive_id,
                replication_order: attestation_set.replication_order,
                provider_attestation_set_digest: attestation_set.set_digest,
                set_sidecar_hash,
                transactions: Vec::new(),
            };
            checkpoint.validate_for(request, generation).map_err(|_| {
                PublicationBackendError::permanent("PROVIDER_REGISTRATION_CHECKPOINT_INVALID")
            })?;
            return Ok(PublicationProviderRegistrationCheckpointAdvanceV1::Updated(
                checkpoint,
            ));
        };
        self.validate_provider_registration_checkpoint(
            operation_id,
            generation,
            request,
            &attestation_set,
            provider_attestations,
            checkpoint,
        )?;
        for attestation in provider_attestations {
            if self.exact_provider_attestation_registered(registered, attestation)? {
                continue;
            }
            let Some(transaction) = checkpoint.transactions.iter().rev().find(|transaction| {
                transaction.key == attestation.key()
                    && transaction.attestation_digest == attestation.digest()
            }) else {
                return self.append_provider_registration_transaction_checkpoint(
                    operation_id,
                    generation,
                    request,
                    checkpoint,
                    1,
                    page.archive.location_revision,
                    attestation,
                );
            };
            let sidecar = self.load_anchored_provider_checkpoint(
                operation_id,
                generation,
                transaction.attempt,
                request,
                transaction.expected_location_revision,
                attestation,
                transaction.sidecar_hash,
            )?;
            if sidecar.transaction_hash != transaction.transaction_hash {
                return Err(PublicationBackendError::permanent(
                    "PROVIDER_REGISTRATION_CHECKPOINT_INVALID",
                ));
            }
            let mut state = self
                .signing
                .transaction_application_state_v1(&sidecar.signed_transaction)
                .map_err(map_registry_error)?;
            let mut submission = None;
            if state == RegistryTransactionStateV1::Absent {
                submission = Some(self.signing.submit_signed_v1(&sidecar.signed_transaction));
                if let Some(Ok(transaction_hash)) = submission.as_ref()
                    && *transaction_hash != sidecar.transaction_hash
                {
                    return Err(PublicationBackendError::permanent(
                        "PROVIDER_ATTESTATION_TRANSACTION_HASH_MISMATCH",
                    ));
                }
                if self.exact_provider_attestation_registered(registered, attestation)? {
                    continue;
                }
                state = self
                    .signing
                    .transaction_application_state_v1(&sidecar.signed_transaction)
                    .map_err(map_registry_error)?;
            }
            match state {
                RegistryTransactionStateV1::Absent => {
                    return match submission.expect("absent state is submitted exactly once") {
                        Ok(_) => Err(PublicationBackendError::retryable(
                            "PROVIDER_ATTESTATION_REGISTRATION_PENDING",
                        )),
                        Err(error) => Err(map_registry_error(error)),
                    };
                }
                RegistryTransactionStateV1::Pending
                | RegistryTransactionStateV1::Applied { .. } => {
                    return Err(PublicationBackendError::retryable(
                        "PROVIDER_ATTESTATION_FINALIZED_QUERY_PENDING",
                    ));
                }
                RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Expired,
                    ..
                } => {
                    let attempt =
                        next_provider_attestation_registration_attempt(transaction.attempt)?;
                    return self.append_provider_registration_transaction_checkpoint(
                        operation_id,
                        generation,
                        request,
                        checkpoint,
                        attempt,
                        transaction.expected_location_revision,
                        attestation,
                    );
                }
                RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Rejected,
                    block_height,
                } => {
                    let expected_location_revision = self
                        .provider_attestation_rejection_rebase_revision(
                            request,
                            registered,
                            transaction.expected_location_revision,
                            block_height,
                        )?;
                    let attempt =
                        next_provider_attestation_registration_attempt(transaction.attempt)?;
                    return self.append_provider_registration_transaction_checkpoint(
                        operation_id,
                        generation,
                        request,
                        checkpoint,
                        attempt,
                        expected_location_revision,
                        attestation,
                    );
                }
            }
        }
        self.verified_provider_checkpoint = Some(checkpoint.clone());
        Ok(PublicationProviderRegistrationCheckpointAdvanceV1::Ready)
    }
    fn prepare_archive_location_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[iroha_data_model::musubi::MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationIntentV1, PublicationBackendError> {
        let checkpoint = self.verified_provider_checkpoint.take().ok_or_else(|| {
            PublicationBackendError::permanent("PROVIDER_REGISTRATION_CHECKPOINT_NOT_VERIFIED")
        })?;
        self.validate_request(request)?;
        let (response, page, attestation_set) = self.coordinate_absent_archive_location(
            operation_id,
            request,
            registered,
            generation,
            prior_location_ids,
            Some(&checkpoint),
        )?;
        let provider_attestations = &attestation_set.attestations;
        self.validate_provider_registration_checkpoint(
            operation_id,
            generation,
            request,
            &attestation_set,
            provider_attestations,
            &checkpoint,
        )?;
        for attestation in provider_attestations {
            if !self.exact_provider_attestation_registered(registered, attestation)? {
                return Err(PublicationBackendError::retryable(
                    "PROVIDER_ATTESTATION_FINALIZED_QUERY_PENDING",
                ));
            }
        }
        let instruction = location_add_instruction(
            &response,
            page.archive.location_revision,
            attestation_set.set_digest,
        )?;
        let payload = self
            .signing
            .prebuild_v1(instruction.clone())
            .map_err(map_registry_error)?;
        let signed_transaction = self
            .signing
            .quote_and_sign_v1(payload)
            .map_err(map_registry_error)?;
        Ok(PublicationArchiveLocationIntentV1::new(
            operation_id,
            generation,
            page,
            instruction,
            signed_transaction,
        ))
    }
    fn submit_or_recover_archive_location(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        intent: &PublicationArchiveLocationIntentV1,
        prior_location_ids: &[iroha_data_model::musubi::MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationAdvanceV1, PublicationBackendError> {
        self.validate_request(request)?;
        intent
            .validate_for(operation_id, request, registered, prior_location_ids)
            .map_err(|_| PublicationBackendError::permanent("ARCHIVE_LOCATION_INTENT_INVALID"))?;
        let initial_state = self
            .signing
            .transaction_application_state_v1(&intent.signed_transaction)
            .map_err(map_registry_error)?;
        if initial_state == RegistryTransactionStateV1::Absent {
            let submission = self.signing.submit_signed_v1(&intent.signed_transaction);
            if let Ok(transaction_hash) = submission
                && transaction_hash != intent.transaction_hash
            {
                return Err(PublicationBackendError::permanent(
                    "ARCHIVE_LOCATION_TRANSACTION_HASH_MISMATCH",
                ));
            }
            let observed = self
                .signing
                .transaction_application_state_v1(&intent.signed_transaction)
                .map_err(map_registry_error)?;
            if observed == RegistryTransactionStateV1::Absent {
                return match submission {
                    Ok(_) => Ok(PublicationArchiveLocationAdvanceV1::Pending),
                    Err(error) => Err(map_registry_error(error)),
                };
            }
            return self.location_transaction_advance(request, registered, intent, observed);
        }
        self.location_transaction_advance(request, registered, intent, initial_state)
    }
    fn readback_provider(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        location: &iroha_data_model::musubi::MusubiArchiveLocationV1,
        provider: ProviderId,
    ) -> Result<PublicationReadbackEvidenceV1, PublicationBackendError> {
        self.validate_request(request)?;
        let gateway = self.provider_gateways.get(&provider).ok_or_else(|| {
            PublicationBackendError::permanent("PROVIDER_READBACK_ENDPOINT_NOT_CONFIGURED")
        })?;
        let readback_request = MusubiProviderReadbackRequestV1 {
            version: 1,
            operation_id: *operation_id.as_bytes(),
            network_id: request.network_id(),
            publisher: request.publisher.clone(),
            expected_policy_revision: request.expected_policy_revision,
            finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1 {
                version: 1,
                network_id: request.network_id(),
                transaction_hash: registered.finalized_transaction_hash,
                snapshot: registered.snapshot,
                registration: registered.archive.registration_projection(),
            },
            location: location.clone(),
            provider,
            commitment: request.archive_commitment.clone(),
            semantic_release_digest: request.publication.manifest.semantic_digest(),
            verification_lock_digest: request.publication.manifest.verification_lock_digest,
        };
        let response = self
            .http
            .readback_provider(&gateway.readback, &readback_request)
            .map_err(map_transport_error)?;
        Ok(PublicationReadbackEvidenceV1 {
            provider: response.provider,
            location_id: response.location_id,
            replication_order: response.replication_order,
            commitment: response.commitment,
            semantic_release_digest: response.semantic_release_digest,
            verification_lock_digest: response.verification_lock_digest,
        })
    }
}
/// Loaded signer, runtime services, and public request bindings for one platform config.
pub struct LoadedProductionPublicationRuntimeV1<V> {
    signing: RegistrySigningClientV1,
    services: ProductionPublicationRuntimeV1<V>,
    bindings: ProductionPublicationBindingsV1,
}
impl<V> fmt::Debug for LoadedProductionPublicationRuntimeV1<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedProductionPublicationRuntimeV1")
            .field("publisher", self.signing.authority())
            .field("bindings", &self.bindings)
            .finish_non_exhaustive()
    }
}
impl<V> LoadedProductionPublicationRuntimeV1<V> {
    /// Return the public values needed to construct the immutable publication request.
    #[must_use]
    pub const fn bindings(&self) -> &ProductionPublicationBindingsV1 {
        &self.bindings
    }
    /// Clone the authenticated reader built from the same image as this runtime and signer.
    pub(crate) fn registry_reader(&self) -> RegistryReadClientV1 {
        self.services.read.clone()
    }
    /// Split the loaded boundary into signer, runtime services, and public bindings.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RegistrySigningClientV1,
        ProductionPublicationRuntimeV1<V>,
        ProductionPublicationBindingsV1,
    ) {
        (self.signing, self.services, self.bindings)
    }
}
/// Load the production runtime from an explicit native config or the default wallet's client file.
///
/// Wallet custody supplies the signer. Publication storage routing and provider policy remain
/// explicit native publication configuration and are never inferred from a wallet or endpoint.
///
/// # Errors
///
/// Returns [`ProductionPublicationConfigurationErrorV1`] when configuration, signer, endpoint,
/// gateway, or platform-binding validation fails.
pub fn load_production_publication_runtime_v1<V>(
    config: Option<&Path>,
    validator: V,
) -> Result<LoadedProductionPublicationRuntimeV1<V>, ProductionPublicationConfigurationErrorV1>
where
    V: PublicationCleanPackageValidatorV1,
{
    let config_path = selected_client_config_path_v1(config)
        .map_err(|error| ProductionPublicationConfigurationErrorV1::new(error.code()))?;
    let config_bytes = read_bounded_platform_config_v1(&config_path).map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_CONFIG_INVALID")
    })?;
    load_production_publication_runtime_from_bytes_v1(&config_path, &config_bytes, None, validator)
}
/// Load a production runtime only when the selected platform configuration still matches the
/// exact image used by the preceding authenticated resolution phase.
///
/// The bounded file is read before any signer or runtime configuration is parsed. Its anchored
/// path and domain-separated digest are process-local provenance and are never returned in an
/// error or persisted.
///
/// # Errors
///
/// Returns [`ProductionPublicationConfigurationErrorV1`] when the configuration cannot be read,
/// no longer matches `provenance`, or fails normal production-runtime validation.
pub(crate) fn load_bound_production_publication_runtime_v1<V>(
    provenance: &PlatformConfigProvenanceV1,
    validator: V,
) -> Result<LoadedProductionPublicationRuntimeV1<V>, ProductionPublicationConfigurationErrorV1>
where
    V: PublicationCleanPackageValidatorV1,
{
    let config_path = provenance.path();
    let config_bytes = read_bounded_platform_config_v1(config_path).map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_CONFIG_INVALID")
    })?;
    if !provenance.matches(&config_bytes) {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_CONFIG_CHANGED",
        ));
    }
    load_production_publication_runtime_from_bytes_v1(config_path, &config_bytes, None, validator)
}
fn load_production_publication_runtime_from_bytes_v1<V>(
    config_path: &Path,
    config_bytes: &[u8],
    generated: Option<iroha_musubi_service::GeneratedLocalPublicationTransportV1>,
    validator: V,
) -> Result<LoadedProductionPublicationRuntimeV1<V>, ProductionPublicationConfigurationErrorV1>
where
    V: PublicationCleanPackageValidatorV1,
{
    let (signing, publication) =
        RegistrySigningClientV1::load_with_publication_config_bytes(config_path, config_bytes)
            .map_err(|_| {
                ProductionPublicationConfigurationErrorV1::new(
                    "MUSUBI_PUBLICATION_SIGNER_CONFIG_INVALID",
                )
            })?;
    let read = signing.authenticated_reader().map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_PUBLIC_CONFIG_INVALID")
    })?;
    if read.account_chain_discriminant() != signing.account_chain_discriminant() {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_REGISTRY_PROFILE_MISMATCH",
        ));
    }
    let parsed = parse_publication_config(config_path, &signing, &publication)?;
    let http = match generated {
        Some(selection) => {
            generated_local::validate_routes(&parsed, &selection)?;
            signing.generated_publication_runtime_client(selection, parsed.request_timeout)
        }
        None => signing.publication_runtime_client(parsed.request_timeout),
    }
    .map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_RUNTIME_AUTH_INVALID")
    })?;
    let bindings = parsed.bindings.clone();
    let services = ProductionPublicationRuntimeV1 {
        read,
        signing: signing.clone(),
        http,
        validator,
        seed_ingress_url: parsed.seed_ingress_url,
        storage_coordinator_url: parsed.storage_coordinator_url,
        provider_gateways: parsed.provider_gateways,
        bindings: bindings.clone(),
        checkpoint_root: None,
        verified_provider_checkpoint: None,
        request_timeout: parsed.request_timeout,
    };
    Ok(LoadedProductionPublicationRuntimeV1 {
        signing,
        services,
        bindings,
    })
}
fn parse_publication_config(
    path: &Path,
    signing: &RegistrySigningClientV1,
    publication: &iroha::config::MusubiPublicationConfig,
) -> Result<ParsedProductionPublicationConfigV1, ProductionPublicationConfigurationErrorV1> {
    if publication.seed_ingress_url.is_none()
        && publication.storage_coordinator_url.is_none()
        && publication.ingress_broker.is_none()
        && publication.seed_provider.is_none()
        && publication.expected_policy_revision.is_none()
        && publication.request_timeout_ms.is_none()
        && publication.provider_gateways.is_empty()
        && publication.namespace_delegation_file.is_none()
    {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_CONFIG_MISSING",
        ));
    }
    let seed_ingress_url = parse_service_url(required_config_string(
        publication.seed_ingress_url.as_deref(),
    )?)?;
    let storage_coordinator_url = parse_service_url(required_config_string(
        publication.storage_coordinator_url.as_deref(),
    )?)?;
    let ingress_broker = signing
        .parse_account_id(required_config_string(
            publication.ingress_broker.as_deref(),
        )?)
        .map_err(|_| {
            ProductionPublicationConfigurationErrorV1::new(
                "MUSUBI_PUBLICATION_INGRESS_BROKER_INVALID",
            )
        })?;
    let seed_provider = parse_provider_id(required_config_string(
        publication.seed_provider.as_deref(),
    )?)?;
    let expected_policy_revision = publication
        .expected_policy_revision
        .filter(|revision| *revision > 0)
        .ok_or_else(invalid_publication_config)?;
    let request_timeout_ms = publication
        .request_timeout_ms
        .map(|timeout| {
            if timeout == 0 {
                Err(invalid_publication_config())
            } else {
                Ok(timeout)
            }
        })
        .transpose()?
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
    if request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_TIMEOUT_INVALID",
        ));
    }
    let provider_gateways = parse_provider_gateways(&publication.provider_gateways)?;
    let namespace_delegation = publication
        .namespace_delegation_file
        .as_deref()
        .map(|raw| load_namespace_delegation(path, raw, signing))
        .transpose()?;
    Ok(ParsedProductionPublicationConfigV1 {
        seed_ingress_url,
        storage_coordinator_url,
        provider_gateways,
        request_timeout: Duration::from_millis(request_timeout_ms),
        bindings: ProductionPublicationBindingsV1 {
            ingress_broker,
            seed_provider,
            expected_policy_revision,
            namespace_delegation,
        },
    })
}
fn parse_provider_gateways(
    gateways: &[iroha::config::MusubiPublicationProviderGatewayConfig],
) -> Result<
    BTreeMap<ProviderId, ProviderPublicationEndpointsV1>,
    ProductionPublicationConfigurationErrorV1,
> {
    if !(usize::from(iroha_data_model::musubi::MUSUBI_MIN_HEALTHY_REPLICAS_V1)
        ..=MUSUBI_MAX_LOCATION_PROVIDERS_V1)
        .contains(&gateways.len())
    {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_PROVIDER_GATEWAYS_INVALID",
        ));
    }
    let mut result = BTreeMap::new();
    let mut origins = BTreeSet::new();
    for value in gateways {
        let provider = parse_provider_id(required_config_string(Some(&value.provider_id))?)?;
        let url = parse_service_url(required_config_string(Some(&value.url))?)?;
        let attestation = provider_inventory::parse_attestation_origin(&value.attestation_url)?;
        let origin = publication_service_origin(&attestation).ok_or_else(|| {
            ProductionPublicationConfigurationErrorV1::new(
                "MUSUBI_PUBLICATION_PROVIDER_GATEWAYS_INVALID",
            )
        })?;
        if result
            .insert(
                provider,
                ProviderPublicationEndpointsV1 {
                    readback: url,
                    attestation,
                },
            )
            .is_some()
            || !origins.insert(origin)
        {
            return Err(ProductionPublicationConfigurationErrorV1::new(
                "MUSUBI_PUBLICATION_PROVIDER_GATEWAYS_INVALID",
            ));
        }
    }
    Ok(result)
}
fn load_namespace_delegation(
    config_path: &Path,
    configured_path: &str,
    signing: &RegistrySigningClientV1,
) -> Result<MusubiNamespaceDelegationV1, ProductionPublicationConfigurationErrorV1> {
    if configured_path.is_empty() || configured_path.trim() != configured_path {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_DELEGATION_INVALID",
        ));
    }
    let path = Path::new(configured_path);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    };
    let bytes = read_bounded_nonempty_regular(&resolved, MAX_DELEGATION_BYTES).map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_DELEGATION_INVALID")
    })?;
    let delegation: MusubiNamespaceDelegationV1 =
        norito::decode_canonical_with_limits(&bytes, DELEGATION_DECODE_LIMITS).map_err(|_| {
            ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_DELEGATION_INVALID")
        })?;
    delegation.validate().map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_DELEGATION_INVALID")
    })?;
    if &delegation.payload.delegate != signing.authority() {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_DELEGATION_DELEGATE_MISMATCH",
        ));
    }
    Ok(delegation)
}
fn parse_service_url(raw: &str) -> Result<Url, ProductionPublicationConfigurationErrorV1> {
    let url = raw.parse::<Url>().map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_SERVICE_URL_INVALID")
    })?;
    validate_publication_service_base_url(&url).map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_SERVICE_URL_INVALID")
    })?;
    Ok(url)
}
fn parse_provider_id(raw: &str) -> Result<ProviderId, ProductionPublicationConfigurationErrorV1> {
    if raw.len() != 64
        || raw
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_PROVIDER_ID_INVALID",
        ));
    }
    let decoded = hex::decode(raw).map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_PROVIDER_ID_INVALID")
    })?;
    let bytes = <[u8; 32]>::try_from(decoded).map_err(|_| {
        ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_PROVIDER_ID_INVALID")
    })?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ProductionPublicationConfigurationErrorV1::new(
            "MUSUBI_PUBLICATION_PROVIDER_ID_INVALID",
        ));
    }
    Ok(ProviderId::new(bytes))
}
fn required_config_string(
    value: Option<&str>,
) -> Result<&str, ProductionPublicationConfigurationErrorV1> {
    value
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .ok_or_else(invalid_publication_config)
}
const fn invalid_publication_config() -> ProductionPublicationConfigurationErrorV1 {
    ProductionPublicationConfigurationErrorV1::new("MUSUBI_PUBLICATION_CONFIG_INVALID")
}
/// Read one exact bounded platform `client.toml` through a no-follow stable descriptor.
///
/// This is shared by publication, authenticated registry reads, and prepared archive fetching so
/// all consumers preserve the same single-link and before/after identity checks. The reader is
/// implemented with no-follow final-component descriptors on Unix and retained `iroha_fs` handles
/// on Windows. Other targets return [`io::ErrorKind::Unsupported`] before inspecting the path.
pub(crate) fn read_bounded_platform_config_v1(path: &Path) -> std::io::Result<Vec<u8>> {
    read_bounded_nonempty_regular(path, MAX_CLIENT_CONFIG_BYTES)
}
fn read_bounded_nonempty_regular(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let bytes = read_bounded_single_link_regular_file_v1(path, maximum)?;
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "publication input must not be empty",
        ));
    }
    Ok(bytes)
}
fn map_transport_error(error: MusubiPublicationRuntimeTransportErrorV1) -> PublicationBackendError {
    match error.class() {
        MusubiPublicationRuntimeTransportFailureClassV1::Retryable => {
            PublicationBackendError::retryable(error.code())
        }
        MusubiPublicationRuntimeTransportFailureClassV1::Permanent => {
            PublicationBackendError::permanent(error.code())
        }
    }
}
fn map_registry_error(error: crate::registry::RegistryErrorV1) -> PublicationBackendError {
    match error.class() {
        RegistryFailureClassV1::Retryable | RegistryFailureClassV1::StaleCursor => {
            PublicationBackendError::retryable("MUSUBI_PUBLICATION_REGISTRY_RETRYABLE")
        }
        RegistryFailureClassV1::Permanent | RegistryFailureClassV1::NotFound => {
            PublicationBackendError::permanent("MUSUBI_PUBLICATION_REGISTRY_REJECTED")
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::PublicationBackendFailureClass;
    use iroha::crypto::{
        Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair, Signature, SignatureOf,
    };
    #[cfg(unix)]
    use iroha_data_model::musubi::{
        MusubiNamespaceBindingDigestV1, MusubiNamespaceDelegationApprovalV1,
        MusubiNamespaceDelegationPayloadV1,
    };
    use iroha_data_model::{
        NetworkId,
        account::{MultisigMember, MultisigPolicy, address::ChainDiscriminantGuard},
        block::BlockHeader,
        musubi::{
            MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1, MUSUBI_MIN_HEALTHY_REPLICAS_V1,
            MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiArchiveCommitmentV1,
            MusubiArchiveLocationIdV1, MusubiArchiveLocationV1, MusubiArchiveRecordV1,
            MusubiContentDigestV1, MusubiKotodamaEditionV1, MusubiNamespaceV1, MusubiPackageIdV1,
            MusubiPackageScopeV1, MusubiProviderBundleVerificationApprovalV1,
            MusubiProviderBundleVerificationAttestationV1,
            MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
            MusubiPublicationV1, MusubiRegistrySnapshotV1, MusubiReleaseIdV1,
            MusubiReleaseManifestV1, MusubiReleaseMetadataV1, MusubiResolutionProofV1,
            MusubiSeedIngressReceiptApprovalV1, MusubiSeedIngressReceiptPayloadV1,
            MusubiVerificationLockV1, MusubiVersionV1,
        },
        sorafs::pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ManifestRootCid,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::topology::DataSpaceId;
    use std::{
        fs,
        io::{self, Write as _},
        net::TcpListener,
        thread,
    };
    use tempfile::tempdir;
    pub(super) fn test_network_id(byte: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([byte; Hash::LENGTH]),
        ))
    }
    /// Build a reader for an independently selected simulated network before any query.
    fn fixture_registry_reader(torii_url: &Url, network_id: NetworkId) -> RegistryReadClientV1 {
        let signer = KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519)
            .expect("fixture reader signer");
        let config = format!(
            r#"
chain = "musubi-publication-runtime-test"
network_id = "{network_id}"
torii_url = "{torii_url}"
torii_request_timeout_ms = 2000

[account]
profile = "taira"
public_key = "{}"
private_key = "{}"
"#,
            signer.public_key(),
            ExposedPrivateKey(signer.private_key().clone()),
        );
        RegistryReadClientV1::load_from_config_bytes(
            Path::new("publication-runtime-reader-test.toml"),
            config.as_bytes(),
        )
        .expect("reader with explicit fixture network")
    }
    fn write_client_config(
        path: &Path,
        extra: &str,
    ) -> (
        RegistrySigningClientV1,
        iroha::config::MusubiPublicationConfig,
    ) {
        let key_pair =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("derive fixture key");
        let private_key = ExposedPrivateKey(key_pair.private_key().clone()).to_string();
        let network_id = test_network_id(0x7b);
        fs::write(
            path,
            format!(
                r#"
                    chain = "musubi-publication-runtime-test"
                    network_id = "{network_id}"
                    torii_url = "https://torii.example/"
                    torii_request_timeout_ms = 2000
                    [account]
                    profile = "taira"
                    public_key = "{}"
                    private_key = "{}"

                    [musubi.publication]
                    seed_ingress_url = "https://seed.example/private/"
                    storage_coordinator_url = "https://storage.example/private/"
                    ingress_broker = "{}"
                    seed_provider = "{}"
                    expected_policy_revision = 7
                    request_timeout_ms = 5000
                    provider_gateways = [
                      {{ provider_id = "{}", url = "https://provider-a.example/", attestation_url = "https://inventory-a.example/" }},
                      {{ provider_id = "{}", url = "https://provider-b.example/", attestation_url = "https://inventory-b.example/" }},
                      {{ provider_id = "{}", url = "https://provider-c.example/", attestation_url = "https://inventory-c.example/" }},
                    ]
                    {extra}
                "#,
                key_pair.public_key(),
                private_key,
                {
                    let account =
                        iroha_data_model::account::AccountId::new(key_pair.public_key().clone());
                    let _guard =
                        iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
                    account.canonical_i105().expect("Taira account")
                },
                hex::encode([0x11; 32]),
                hex::encode([0x21; 32]),
                hex::encode([0x22; 32]),
                hex::encode([0x23; 32]),
            ),
        )
        .expect("write config");
        RegistrySigningClientV1::load_with_publication_config(Some(path))
            .expect("load signer with typed publication config")
    }
    fn serve_archive_page_once(
        page: &MusubiArchiveLocationPageV1,
    ) -> (Url, thread::JoinHandle<Vec<u8>>) {
        let response = {
            let _guard = ChainDiscriminantGuard::enter(369);
            norito::json::to_vec(page).expect("encode archive page")
        };
        serve_json_once("200 OK", response)
    }
    pub(super) fn serve_json_once(
        status: &'static str,
        response: Vec<u8>,
    ) -> (Url, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().expect("loopback address");
        let server = thread::spawn(move || {
            let end = std::time::Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < end =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("one finalized query: {error}"),
                }
            };
            // Accepted sockets can inherit the listener's nonblocking mode on supported hosts.
            // The fixture's finite read/write timeouts require an explicitly blocking stream.
            stream
                .set_nonblocking(false)
                .expect("blocking query stream");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("query read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2_048];
            let (header_end, content_length) = loop {
                let read = stream.read(&mut buffer).expect("read query request");
                assert_ne!(read, 0, "query ended before its headers");
                assert!(
                    request.len().saturating_add(read) <= 16 * 1024,
                    "bounded headers"
                );
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..header_end]).expect("HTTP headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                assert!(content_length <= 128 * 1024, "bounded body");
                break (header_end + 4, content_length);
            };
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).expect("read query body");
                assert_ne!(read, 0, "query ended before its body");
                request.extend_from_slice(&buffer[..read]);
            }
            let request_body = request[header_end..header_end + content_length].to_vec();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
            request_body
        });
        (
            format!("http://{address}/").parse().expect("loopback URL"),
            server,
        )
    }
    fn rebase_commitment() -> MusubiArchiveCommitmentV1 {
        MusubiArchiveCommitmentV1 {
            root_cid: ManifestRootCid::from_blake3_digest([0x71; 32]).expect("root CID"),
            chunker: ChunkerProfileHandle {
                profile_id: 1,
                namespace: "sorafs".to_owned(),
                name: "sf1".to_owned(),
                semver: "1.0.0".to_owned(),
                multihash_code: 0x1f,
            },
            chunk_plan_digest: MusubiContentDigestV1::new([0x72; 32]),
            por_root: MusubiContentDigestV1::new([0x73; 32]),
            content_length: 1_024,
            car_digest: MusubiContentDigestV1::new([0x74; 32]),
            car_size: 2_048,
            bundle_digest: MusubiContentDigestV1::new([0x75; 32]),
            source_tree_digest: MusubiContentDigestV1::new([0x76; 32]),
            descriptor_digest: MusubiContentDigestV1::new([0x77; 32]),
            file_count: 2,
            chunk_count: 4,
        }
    }
    struct RebaseFixture {
        runtime: ProductionPublicationRuntimeV1<UnavailablePublicationCleanPackageValidatorV1>,
        request: PublicationRequestV1,
        registered: PublicationRegisteredArchiveV1,
        response: MusubiStorageCoordinationResponseV1,
        attestations: Vec<MusubiProviderBundleVerificationAttestationV1>,
        page: MusubiArchiveLocationPageV1,
    }
    pub(super) fn original_request_fixture() -> PublicationRequestV1 {
        rebase_fixture().request
    }
    fn rebase_fixture() -> RebaseFixture {
        let torii_url = "http://127.0.0.1:9/".parse().expect("dummy URL");
        let temporary = tempdir().expect("temporary directory");
        let config_path = temporary.path().join("client.toml");
        let (signing, publication_config) = write_client_config(&config_path, "");
        let parsed = parse_publication_config(&config_path, &signing, &publication_config)
            .expect("parse runtime config");
        let publisher = signing.authority().clone();
        let broker_key =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("broker key");
        let commitment = rebase_commitment();
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "rebase-fixture".parse().expect("package name"),
        );
        let release = MusubiReleaseIdV1::new(
            package,
            "1.0.0".parse::<MusubiVersionV1>().expect("version"),
        );
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let manifest = MusubiReleaseManifestV1 {
            release,
            edition: MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([0x78; 32]).expect("ABI"),
            dependencies: Vec::new(),
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([0x79; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            archive_id: commitment.archive_id(),
            verification_lock_digest: lock.digest(),
        };
        let resolution_snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 40,
            finalized_block_hash: [0x7a; 32],
            index_revision: 2,
        };
        let request = PublicationRequestV1 {
            network_id: test_network_id(0x7b),
            publisher: publisher.clone(),
            ingress_broker: publisher.clone(),
            seed_provider: ProviderId::new([0x11; 32]),
            namespace: MusubiNamespaceV1::new("rebase").expect("namespace"),
            publication: MusubiPublicationV1 {
                manifest,
                resolution: MusubiResolutionProofV1 {
                    snapshot: resolution_snapshot,
                    lock,
                },
            },
            archive_commitment: commitment.clone(),
            namespace_delegation: None,
            expected_policy_revision: 7,
            expected_governance_revision: None,
            nonce: [0x7c; 32],
        };
        request.validate().expect("publication request");
        let receipt_payload = MusubiSeedIngressReceiptPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            binding: MusubiSeedIngressReceiptBindingV1 {
                network_id: request.network_id(),
                publisher: request.publisher.clone(),
                ingress_broker: request.ingress_broker.clone(),
                seed_provider: request.seed_provider,
                semantic_release_manifest_digest: request.publication.manifest.semantic_digest(),
                archive_id: request.archive_commitment.archive_id(),
                car_body_digest: request.archive_commitment.car_digest,
                car_body_length: request.archive_commitment.car_size,
                nonce: request.nonce,
            },
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
        };
        let receipt = MusubiSeedIngressReceiptV1 {
            approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                public_key: broker_key.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    broker_key.private_key(),
                    receipt_payload.signing_hash(),
                )
                .expect("receipt signature"),
            }],
            payload: receipt_payload,
        };
        let archive = MusubiArchiveRecordV1 {
            archive_id: commitment.archive_id(),
            commitment: commitment.clone(),
            staging_receipt: receipt,
            registered_by: publisher.clone(),
            registered_at_height: 50,
            location_revision: 1,
            location_ids: Vec::new(),
        };
        let registered_snapshot = MusubiRegistrySnapshotV1 {
            finalized_height: 60,
            finalized_block_hash: [0x7d; 32],
            index_revision: 4,
        };
        let registered = PublicationRegisteredArchiveV1 {
            finalized_transaction_hash: [0x7e; 32],
            network_id: request.network_id,
            snapshot: registered_snapshot,
            archive: archive.clone(),
        };
        let replication_order = ReplicationOrderId::new([0x01; 32]);
        let provider_attestations = (0_u16..MUSUBI_MIN_HEALTHY_REPLICAS_V1)
            .map(|index| {
                let index = u8::try_from(index).expect("replica bound fits u8");
                let provider_key =
                    KeyPair::try_from_seed(vec![0x88 + index; 32], Algorithm::Ed25519)
                        .expect("provider key");
                let owner_key = KeyPair::try_from_seed(vec![0xb8 + index; 32], Algorithm::Ed25519)
                    .expect("distinct provider owner key");
                let provider_owner =
                    iroha_data_model::account::AccountId::new(owner_key.public_key().clone());
                let completion_signer =
                    iroha_data_model::account::AccountId::new(provider_key.public_key().clone());
                assert_ne!(provider_owner, completion_signer);
                let provider_binding = MusubiProviderBundleVerificationBindingV1 {
                    network_id: request.network_id(),
                    provider_id: ProviderId::new([0x90 + index; 32]),
                    completed_by: completion_signer.clone(),
                    completion_authority: ProviderIngestCompletionAuthorityV1::new(
                        provider_owner,
                        completion_signer,
                        ProviderIngestCompletionSignerPolicyV1 {
                            policy_id: [0x98 + index; 32],
                            revision: 1,
                            predecessor_digest: None,
                            policy_digest: [0xa0 + index; 32],
                        },
                    ),
                    replication_order,
                    assignment_revision: 1,
                    completion_epoch: 12,
                    finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                        height: 61,
                        block_hash: [0xa8 + index; 32],
                    },
                    archive_id: commitment.archive_id(),
                    bundle_digest: commitment.bundle_digest,
                    descriptor_digest: commitment.descriptor_digest,
                    semantic_release_manifest_digest: request
                        .publication
                        .manifest
                        .semantic_digest(),
                    verification_lock_digest: request.publication.manifest.verification_lock_digest,
                    source_tree_digest: commitment.source_tree_digest,
                };
                let provider_payload = MusubiProviderBundleVerificationPayloadV1 {
                    version: MUSUBI_REGISTRY_VERSION_V1,
                    binding: provider_binding,
                };
                MusubiProviderBundleVerificationAttestationV1 {
                    approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                        public_key: provider_key.public_key().clone(),
                        signature: SignatureOf::try_from_hash(
                            provider_key.private_key(),
                            provider_payload.signing_hash(),
                        )
                        .expect("provider signature"),
                    }],
                    payload: provider_payload,
                }
            })
            .collect::<Vec<_>>();
        let coordination_request = MusubiStorageCoordinationRequestV1 {
            version: 1,
            operation_id: *request.operation_id().as_bytes(),
            generation: 1,
            prior_location_ids: Vec::new(),
            network_id: request.network_id(),
            publisher: request.publisher.clone(),
            commitment: request.archive_commitment.clone(),
            verification_lock_digest: request.publication.manifest.verification_lock_digest,
            staging_receipt: registered.archive.staging_receipt.clone(),
            expected_policy_revision: request.expected_policy_revision,
            finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1 {
                version: 1,
                network_id: registered.network_id,
                transaction_hash: registered.finalized_transaction_hash,
                snapshot: registered.snapshot,
                registration: registered.archive.registration_projection(),
            },
        };
        let response = MusubiStorageCoordinationResponseV1 {
            version: 1,
            request_digest: coordination_request.canonical_request_digest().unwrap(),
            archive: archive.clone(),
            location_id: MusubiArchiveLocationIdV1::new([0x85; 32]),
            pin_manifest: ManifestDigest::new([0x86; 32]),
            replication_order,
            renew_after_epoch: 10,
            expires_at_epoch: 20,
            disposition: MusubiStorageLocationDispositionV1::NeedsRegistration {
                completed_providers: provider_attestations
                    .iter()
                    .map(|a| a.key().provider_id)
                    .collect(),
                expected_location_revision: archive.location_revision,
            },
        };
        let page = MusubiArchiveLocationPageV1 {
            network_id: request.network_id(),
            archive,
            items: Vec::new(),
            next_cursor: None,
            snapshot: registered_snapshot,
        };
        let read = fixture_registry_reader(&torii_url, request.network_id());
        let http = signing
            .publication_runtime_client(parsed.request_timeout)
            .expect("authenticated runtime client");
        let runtime = ProductionPublicationRuntimeV1 {
            read,
            signing,
            http,
            validator: UnavailablePublicationCleanPackageValidatorV1,
            seed_ingress_url: parsed.seed_ingress_url,
            storage_coordinator_url: parsed.storage_coordinator_url,
            provider_gateways: parsed.provider_gateways,
            bindings: parsed.bindings,
            checkpoint_root: None,
            verified_provider_checkpoint: None,
            request_timeout: parsed.request_timeout,
        };
        RebaseFixture {
            runtime,
            request,
            registered,
            response,
            attestations: provider_attestations,
            page,
        }
    }
    fn coordinator_location(fixture: &RebaseFixture) -> MusubiArchiveLocationV1 {
        let provider_attestations = coordinator_provider_attestations(fixture);
        MusubiArchiveLocationV1 {
            location_id: fixture.response.location_id,
            archive_id: fixture.response.archive.archive_id,
            pin_manifest: fixture.response.pin_manifest,
            replication_order: fixture.response.replication_order,
            providers: provider_attestations
                .iter()
                .map(|attestation| attestation.payload.binding.provider_id)
                .collect(),
            provider_attestation_set_digest: fixture_attestation_set_digest(fixture),
            renew_after_epoch: fixture.response.renew_after_epoch,
            expires_at_epoch: fixture.response.expires_at_epoch,
            finalized_height: 61,
            revision: 1,
            state: MusubiArchiveLocationStateV1::Healthy,
        }
    }
    fn coordinator_provider_attestations(
        fixture: &RebaseFixture,
    ) -> &[MusubiProviderBundleVerificationAttestationV1] {
        &fixture.attestations
    }
    fn fixture_attestation_set_digest(
        fixture: &RebaseFixture,
    ) -> MusubiProviderBundleAttestationSetDigestV1 {
        PublicationProviderAttestationSetCheckpointV1::new(
            fixture.request.operation_id(),
            1,
            fixture.response.archive.archive_id,
            fixture.response.replication_order,
            fixture.attestations.clone(),
        )
        .unwrap()
        .set_digest
    }

    fn serve_rebase_fixture_page(fixture: &mut RebaseFixture) -> thread::JoinHandle<Vec<u8>> {
        fixture
            .page
            .validate()
            .expect("valid finalized archive page");
        let (url, server) = serve_archive_page_once(&fixture.page);
        fixture.runtime.read = fixture_registry_reader(&url, fixture.request.network_id());
        server
    }
    fn advance_rebase_page(fixture: &mut RebaseFixture, location_revision: u64) {
        fixture.page.snapshot.finalized_height += 1;
        fixture.page.snapshot.finalized_block_hash = [0x87; 32];
        fixture.page.snapshot.index_revision += 1;
        fixture.page.archive.location_revision = location_revision;
    }
    fn rebase_location_intent(fixture: &RebaseFixture) -> PublicationArchiveLocationIntentV1 {
        let instruction = location_add_instruction(
            &fixture.response,
            fixture.page.archive.location_revision,
            fixture_attestation_set_digest(&fixture),
        )
        .expect("compact location instruction");
        let publisher_key =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("publisher key");
        let mut builder = TransactionBuilder::new(
            fixture.request.network_id(),
            fixture.request.publisher.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction.clone()]);
        builder.set_creation_time(Duration::from_millis(1_000));
        PublicationArchiveLocationIntentV1::new(
            fixture.request.operation_id(),
            1,
            fixture.page.clone(),
            instruction,
            builder.sign(publisher_key.private_key()),
        )
    }
    fn signed_provider_attestation_transaction(
        request: &PublicationRequestV1,
        instruction: RegisterMusubiProviderBundleAttestationV1,
        signer_seed: u8,
    ) -> SignedTransaction {
        let signer = KeyPair::try_from_seed(vec![signer_seed; 32], Algorithm::Ed25519)
            .expect("provider checkpoint signer");
        let mut builder = TransactionBuilder::new(
            request.network_id(),
            request.publisher.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction]);
        builder.set_creation_time(Duration::from_millis(1_000));
        let signature = Signature::try_new(signer.private_key(), &builder.payload_hash_bytes())
            .expect("sign provider checkpoint transaction payload");
        builder.build_with_signature(signature)
    }
    #[test]
    fn provider_attestation_checkpoint_decode_limits_admit_maximum_approval_set() {
        let fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let expected_location_revision = fixture.page.archive.location_revision;
        let mut attestation = coordinator_provider_attestations(&fixture)[0].clone();
        let mut signers = (0..MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1)
            .map(|index| {
                let seed = u8::try_from(index)
                    .expect("approval index fits u8")
                    .checked_add(0x80)
                    .expect("approval seed remains in range");
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .expect("maximum approval-set signer")
            })
            .collect::<Vec<_>>();
        signers.sort_by(|left, right| left.public_key().cmp(right.public_key()));
        let members = signers
            .iter()
            .map(|signer| {
                MultisigMember::new(signer.public_key().clone(), 1)
                    .expect("maximum approval-set member")
            })
            .collect::<Vec<_>>();
        let threshold = u16::try_from(MUSUBI_MAX_PUBLICATION_ATTESTATION_APPROVALS_V1)
            .expect("approval maximum fits u16");
        let completion_signer = iroha_data_model::account::AccountId::new_multisig(
            MultisigPolicy::new(threshold, members).expect("maximum approval-set policy"),
        );
        attestation.payload.binding.completed_by = completion_signer.clone();
        attestation
            .payload
            .binding
            .completion_authority
            .completion_signer = completion_signer;
        let signing_hash = attestation.payload.signing_hash();
        attestation.approvals = signers
            .iter()
            .map(|signer| MusubiProviderBundleVerificationApprovalV1 {
                public_key: signer.public_key().clone(),
                signature: SignatureOf::try_from_hash(signer.private_key(), signing_hash)
                    .expect("maximum approval-set signature"),
            })
            .collect();
        attestation
            .verify(&attestation.payload.binding)
            .expect("maximum approval-set attestation");
        let instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision,
        );
        let signed_transaction =
            signed_provider_attestation_transaction(&fixture.request, instruction, 0x51);
        let checkpoint = PublicationProviderAttestationCheckpointV1::new(
            operation_id,
            1,
            1,
            expected_location_revision,
            &attestation,
            signed_transaction,
        );
        let encoded =
            encode_provider_attestation_checkpoint(&checkpoint).expect("encode maximum checkpoint");
        assert!(
            encoded.len() > 256,
            "the maximum checkpoint must exercise a framed sequence beyond the old decode limit"
        );
        let decoded: PublicationProviderAttestationCheckpointV1 =
            norito::decode_canonical_with_limits(
                &encoded,
                PROVIDER_ATTESTATION_CHECKPOINT_DECODE_LIMITS,
            )
            .expect("decode maximum checkpoint within its production budget");
        assert_eq!(decoded, checkpoint);
        decoded
            .validate_for(
                operation_id,
                1,
                1,
                &fixture.request,
                expected_location_revision,
                &attestation,
            )
            .expect("decoded maximum checkpoint remains valid");
    }
    #[test]
    fn provider_attestation_set_checkpoint_is_deterministic_and_rejects_substitution() {
        let fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let attestations = coordinator_provider_attestations(&fixture);
        let checkpoint = PublicationProviderAttestationSetCheckpointV1::new(
            operation_id,
            1,
            fixture.response.archive.archive_id,
            fixture.response.replication_order,
            attestations.to_vec(),
        )
        .expect("canonical provider set checkpoint");
        let repeated = PublicationProviderAttestationSetCheckpointV1::new(
            operation_id,
            1,
            fixture.response.archive.archive_id,
            fixture.response.replication_order,
            attestations.to_vec(),
        )
        .expect("repeated provider set checkpoint");
        checkpoint.validate().expect("checkpoint validates");
        assert!(
            retained_attestation_set_digest(
                checkpoint.archive_id,
                checkpoint.replication_order,
                &attestations[..2]
            )
            .is_err()
        );
        assert_eq!(
            retained_attestation_set_digest(
                checkpoint.archive_id,
                checkpoint.replication_order,
                attestations
            )
            .unwrap(),
            checkpoint.set_digest
        );
        assert_eq!(checkpoint, repeated);
        let canonical = norito::encode_canonical(&checkpoint).unwrap();
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN,
            );
            assert_eq!(
                encode_attestation_set_checkpoint(&checkpoint).unwrap(),
                canonical
            );
        }
        assert_eq!(
            norito::encode_canonical(&checkpoint).expect("encode checkpoint"),
            norito::encode_canonical(&repeated).expect("encode repeated checkpoint")
        );
        let mut substituted_reference = checkpoint.clone();
        substituted_reference.attestations[0]
            .payload
            .binding
            .bundle_digest = MusubiContentDigestV1::new([0xee; 32]);
        assert!(
            substituted_reference.validate().is_err(),
            "the aggregate digest must reject a substituted provider reference"
        );
        let mut reordered_references = checkpoint.clone();
        reordered_references.attestations.reverse();
        assert!(
            reordered_references.validate().is_err(),
            "the aggregate digest must reject a reordered provider set"
        );
        let mut substituted_order = checkpoint;
        substituted_order.replication_order = ReplicationOrderId::new([0x6f; 32]);
        assert!(
            substituted_order.validate().is_err(),
            "the aggregate digest must bind the exact replication order"
        );
    }
    #[test]
    fn provider_attestation_transaction_checkpoint_binds_exact_instruction_and_signature() {
        let fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let expected_location_revision = fixture.page.archive.location_revision;
        let attestation = coordinator_provider_attestations(&fixture)[0].clone();
        let exact_instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision,
        );
        let exact_transaction = signed_provider_attestation_transaction(
            &fixture.request,
            exact_instruction.clone(),
            0x51,
        );
        let checkpoint = PublicationProviderAttestationCheckpointV1::new(
            operation_id,
            1,
            1,
            expected_location_revision,
            &attestation,
            exact_transaction,
        );
        checkpoint
            .validate_for(
                operation_id,
                1,
                1,
                &fixture.request,
                expected_location_revision,
                &attestation,
            )
            .expect("exact signed provider checkpoint");
        let mut invalid_provider_attestation = attestation.clone();
        let unrelated_provider_key =
            KeyPair::try_from_seed(vec![0x61; 32], Algorithm::Ed25519).expect("unrelated provider");
        invalid_provider_attestation.approvals[0].signature = SignatureOf::try_from_hash(
            unrelated_provider_key.private_key(),
            invalid_provider_attestation.payload.signing_hash(),
        )
        .expect("structurally valid unrelated provider signature");
        let invalid_provider_instruction = RegisterMusubiProviderBundleAttestationV1::new(
            invalid_provider_attestation.clone(),
            expected_location_revision,
        );
        let invalid_provider_transaction = signed_provider_attestation_transaction(
            &fixture.request,
            invalid_provider_instruction,
            0x51,
        );
        let invalid_provider_checkpoint = PublicationProviderAttestationCheckpointV1::new(
            operation_id,
            1,
            1,
            expected_location_revision,
            &invalid_provider_attestation,
            invalid_provider_transaction,
        );
        assert!(
            invalid_provider_checkpoint
                .validate_for(
                    operation_id,
                    1,
                    1,
                    &fixture.request,
                    expected_location_revision,
                    &invalid_provider_attestation,
                )
                .is_err(),
            "a checkpoint must verify the provider-owner attestation signature"
        );
        let substituted_instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision + 1,
        );
        let mut instruction_substitution = checkpoint.clone();
        instruction_substitution.signed_transaction = signed_provider_attestation_transaction(
            &fixture.request,
            substituted_instruction,
            0x51,
        );
        instruction_substitution.transaction_hash =
            *instruction_substitution.signed_transaction.hash().as_ref();
        assert!(
            instruction_substitution
                .validate_for(
                    operation_id,
                    1,
                    1,
                    &fixture.request,
                    expected_location_revision,
                    &attestation,
                )
                .is_err(),
            "a validly signed transaction for another instruction must be rejected"
        );
        let mut signature_substitution = checkpoint;
        signature_substitution.signed_transaction =
            signed_provider_attestation_transaction(&fixture.request, exact_instruction, 0x52);
        signature_substitution.transaction_hash =
            *signature_substitution.signed_transaction.hash().as_ref();
        assert!(
            signature_substitution
                .validate_for(
                    operation_id,
                    1,
                    1,
                    &fixture.request,
                    expected_location_revision,
                    &attestation,
                )
                .is_err(),
            "a signature outside the publication authority must be rejected"
        );
    }
    #[test]
    fn exact_provider_attestation_accepts_another_managers_original_audit_actor() {
        let fixture = rebase_fixture();
        let attestation = coordinator_provider_attestations(&fixture)[0].clone();
        let other_manager = KeyPair::try_from_seed(vec![0x62; 32], Algorithm::Ed25519)
            .expect("other archive manager");
        let record = MusubiProviderBundleAttestationRecordV1 {
            key: attestation.key(),
            attestation_digest: attestation.digest(),
            attestation: attestation.clone(),
            registered_by: iroha_data_model::account::AccountId::new(
                other_manager.public_key().clone(),
            ),
            registered_at_height: fixture.registered.archive.registered_at_height + 1,
        };
        validate_exact_provider_attestation_record(&fixture.registered, &attestation, &record)
            .expect("registered_by is immutable audit provenance, not proof identity");
        let mut preexisting = record;
        preexisting.registered_at_height = fixture.registered.archive.registered_at_height;
        let error = validate_exact_provider_attestation_record(
            &fixture.registered,
            &attestation,
            &preexisting,
        )
        .expect_err("a proof cannot predate the publication archive registration");
        assert_eq!(
            error.code(),
            "PROVIDER_ATTESTATION_FINALIZED_RECORD_CONFLICT"
        );
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
    }
    #[test]
    fn provider_attestation_checkpoint_restart_loads_exact_attempt_and_rejects_substitution() {
        let mut fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let expected_location_revision = fixture.page.archive.location_revision;
        let attestation = coordinator_provider_attestations(&fixture)[0].clone();
        let instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision,
        );
        let signed_transaction =
            signed_provider_attestation_transaction(&fixture.request, instruction, 0x51);
        let checkpoint = PublicationProviderAttestationCheckpointV1::new(
            operation_id,
            1,
            1,
            expected_location_revision,
            &attestation,
            signed_transaction,
        );
        let state = tempdir().expect("checkpoint state root");
        fs::create_dir(state.path().join("publication-v1"))
            .expect("private publication checkpoint directory");
        let writer = AtomicWriteRoot::new(state.path()).expect("bind checkpoint state root");
        let attempt_one_path = provider_attestation_checkpoint_relative_path(
            operation_id,
            1,
            1,
            expected_location_revision,
            attestation.key().provider_id,
            attestation.digest(),
        );
        writer
            .install_immutable(
                &attempt_one_path,
                &norito::encode_canonical(&checkpoint).expect("encode exact checkpoint"),
            )
            .expect("install exact checkpoint");
        fixture
            .runtime
            .bind_publication_state_root(state.path())
            .expect("bind runtime checkpoint root");
        assert_eq!(
            fixture
                .runtime
                .load_or_prepare_provider_checkpoint(
                    operation_id,
                    1,
                    1,
                    &fixture.request,
                    expected_location_revision,
                    &attestation,
                )
                .expect("restart loads exact immutable checkpoint"),
            checkpoint
        );
        let substituted_attempt_path = provider_attestation_checkpoint_relative_path(
            operation_id,
            1,
            2,
            expected_location_revision,
            attestation.key().provider_id,
            attestation.digest(),
        );
        writer
            .install_immutable(
                &substituted_attempt_path,
                &norito::encode_canonical(&checkpoint).expect("encode substituted checkpoint"),
            )
            .expect("install substituted checkpoint fixture");
        let error = fixture
            .runtime
            .load_or_prepare_provider_checkpoint(
                operation_id,
                1,
                2,
                &fixture.request,
                expected_location_revision,
                &attestation,
            )
            .expect_err("an attempt-one checkpoint cannot occupy the attempt-two path");
        assert_eq!(error.code(), "PROVIDER_ATTESTATION_CHECKPOINT_INVALID");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
    }
    #[test]
    fn anchored_provider_set_sidecar_deletion_is_permanent_on_reopen() {
        let mut fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let checkpoint = PublicationProviderAttestationSetCheckpointV1::new(
            operation_id,
            1,
            fixture.response.archive.archive_id,
            fixture.response.replication_order,
            coordinator_provider_attestations(&fixture).to_vec(),
        )
        .expect("provider set checkpoint");
        let state = tempdir().expect("checkpoint state root");
        fs::create_dir(state.path().join("publication-v1"))
            .expect("private publication checkpoint directory");
        fixture
            .runtime
            .bind_publication_state_root(state.path())
            .expect("bind checkpoint state root");
        let sidecar_hash = fixture
            .runtime
            .persist_attestation_set_checkpoint(&checkpoint)
            .expect("install provider set sidecar");
        let mut reopened = rebase_fixture();
        reopened
            .runtime
            .bind_publication_state_root(state.path())
            .expect("reopen checkpoint state root");
        reopened
            .runtime
            .validate_anchored_attestation_set_checkpoint(&checkpoint, sidecar_hash)
            .expect("reopened runtime validates the exact anchored set sidecar");
        let relative = provider_attestation_set_checkpoint_relative_path(operation_id, 1);
        fs::remove_file(state.path().join(relative)).expect("delete anchored set sidecar fixture");
        let mut deleted_reopen = rebase_fixture();
        deleted_reopen
            .runtime
            .bind_publication_state_root(state.path())
            .expect("reopen checkpoint root after set-sidecar deletion");
        let error = deleted_reopen
            .runtime
            .validate_anchored_attestation_set_checkpoint(&checkpoint, sidecar_hash)
            .expect_err("an anchored set sidecar must never be recreated after deletion");
        assert_eq!(error.code(), "PROVIDER_ATTESTATION_SET_CHECKPOINT_MISSING");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
    }
    #[test]
    fn anchored_provider_transaction_sidecar_deletion_is_permanent_on_reopen() {
        let fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let expected_location_revision = fixture.page.archive.location_revision;
        let attestation = coordinator_provider_attestations(&fixture)[0].clone();
        let instruction = RegisterMusubiProviderBundleAttestationV1::new(
            attestation.clone(),
            expected_location_revision,
        );
        let signed_transaction =
            signed_provider_attestation_transaction(&fixture.request, instruction, 0x51);
        let checkpoint = PublicationProviderAttestationCheckpointV1::new(
            operation_id,
            1,
            1,
            expected_location_revision,
            &attestation,
            signed_transaction,
        );
        let encoded =
            encode_provider_attestation_checkpoint(&checkpoint).expect("encode provider sidecar");
        let sidecar_hash = provider_attestation_sidecar_hash(&encoded);
        let relative = provider_attestation_checkpoint_relative_path(
            operation_id,
            1,
            1,
            expected_location_revision,
            attestation.key().provider_id,
            attestation.digest(),
        );
        let state = tempdir().expect("checkpoint state root");
        fs::create_dir(state.path().join("publication-v1"))
            .expect("private publication checkpoint directory");
        AtomicWriteRoot::new(state.path())
            .expect("bind checkpoint writer")
            .install_immutable(&relative, &encoded)
            .expect("install provider transaction sidecar");
        let mut reopened = rebase_fixture();
        reopened
            .runtime
            .bind_publication_state_root(state.path())
            .expect("reopen checkpoint state root");
        assert_eq!(
            reopened
                .runtime
                .load_anchored_provider_checkpoint(
                    operation_id,
                    1,
                    1,
                    &fixture.request,
                    expected_location_revision,
                    &attestation,
                    sidecar_hash,
                )
                .expect("reopened runtime validates the exact anchored transaction sidecar"),
            checkpoint
        );
        fs::remove_file(state.path().join(&relative))
            .expect("delete anchored transaction sidecar fixture");
        let mut deleted_reopen = rebase_fixture();
        deleted_reopen
            .runtime
            .bind_publication_state_root(state.path())
            .expect("reopen checkpoint root after transaction-sidecar deletion");
        let error = deleted_reopen
            .runtime
            .load_anchored_provider_checkpoint(
                operation_id,
                1,
                1,
                &fixture.request,
                expected_location_revision,
                &attestation,
                sidecar_hash,
            )
            .expect_err("an anchored transaction sidecar must never be recreated after deletion");
        assert_eq!(error.code(), "PROVIDER_ATTESTATION_CHECKPOINT_MISSING");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
    }
    #[test]
    fn provider_attestation_checkpoint_attempt_chain_is_bounded() {
        for attempt in 1..MAX_PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS {
            assert_eq!(
                next_provider_attestation_registration_attempt(attempt)
                    .expect("a bounded successor attempt"),
                attempt + 1
            );
        }
        let error = next_provider_attestation_registration_attempt(
            MAX_PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS,
        )
        .expect_err("the immutable attempt chain must be bounded");
        assert_eq!(
            error.code(),
            "PROVIDER_ATTESTATION_REGISTRATION_ATTEMPTS_EXHAUSTED"
        );
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
    }
    #[test]
    fn provider_attestation_rejection_rebases_only_from_a_covering_advanced_snapshot() {
        let mut lagging = rebase_fixture();
        let rejection_height = lagging.page.snapshot.finalized_height + 1;
        let server = serve_rebase_fixture_page(&mut lagging);
        let error = lagging
            .runtime
            .provider_attestation_rejection_rebase_revision(
                &lagging.request,
                &lagging.registered,
                lagging.page.archive.location_revision,
                Some(rejection_height),
            )
            .expect_err("a page below the rejection height cannot authorize a rebase");
        assert_eq!(error.code(), "PROVIDER_ATTESTATION_FINALIZED_QUERY_PENDING");
        assert_eq!(error.class(), PublicationBackendFailureClass::Retryable);
        server.join().expect("lagging finalized query server");
        let mut unchanged = rebase_fixture();
        let signed_revision = unchanged.page.archive.location_revision;
        advance_rebase_page(&mut unchanged, signed_revision);
        let rejection_height = unchanged.page.snapshot.finalized_height;
        let server = serve_rebase_fixture_page(&mut unchanged);
        let error = unchanged
            .runtime
            .provider_attestation_rejection_rebase_revision(
                &unchanged.request,
                &unchanged.registered,
                signed_revision,
                Some(rejection_height),
            )
            .expect_err("an unchanged CAS revision makes the rejection permanent");
        assert_eq!(error.code(), "PROVIDER_ATTESTATION_REGISTRATION_TERMINAL");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("unchanged finalized query server");
        let mut advanced = rebase_fixture();
        let signed_revision = advanced.page.archive.location_revision;
        advance_rebase_page(&mut advanced, signed_revision + 1);
        let rejection_height = advanced.page.snapshot.finalized_height;
        let server = serve_rebase_fixture_page(&mut advanced);
        assert_eq!(
            advanced
                .runtime
                .provider_attestation_rejection_rebase_revision(
                    &advanced.request,
                    &advanced.registered,
                    signed_revision,
                    Some(rejection_height),
                )
                .expect("a covering advanced snapshot authorizes a revision-specific retry"),
            signed_revision + 1
        );
        server.join().expect("advanced finalized query server");
        let missing_height = rebase_fixture();
        let error = missing_height
            .runtime
            .provider_attestation_rejection_rebase_revision(
                &missing_height.request,
                &missing_height.registered,
                missing_height.page.archive.location_revision,
                None,
            )
            .expect_err("a rejection without a finalized height cannot authorize a retry");
        assert_eq!(
            error.code(),
            "PROVIDER_ATTESTATION_TRANSACTION_STATUS_INVALID"
        );
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
    }
    #[test]
    fn provider_attestation_sidecar_paths_are_deterministic_and_disjoint() {
        let fixture = rebase_fixture();
        let operation_id = fixture.request.operation_id();
        let attestation = &coordinator_provider_attestations(&fixture)[0];
        let provider_id = attestation.key().provider_id;
        let attestation_digest = attestation.digest();
        let set_path = provider_attestation_set_checkpoint_relative_path(operation_id, 3);
        assert_eq!(
            set_path,
            PathBuf::from(format!(
                "publication-v1/{operation_id}.location-03.provider-set.norito"
            ))
        );
        assert_eq!(
            set_path,
            provider_attestation_set_checkpoint_relative_path(operation_id, 3)
        );
        let provider_path = provider_attestation_checkpoint_relative_path(
            operation_id,
            3,
            1,
            17,
            provider_id,
            attestation_digest,
        );
        assert_eq!(
            provider_path,
            PathBuf::from(format!(
                "publication-v1/{operation_id}.l03.t01.r0000000000000011.p{}.a{}.norito",
                hex::encode(provider_id.as_bytes()),
                hex::encode(attestation_digest.as_bytes())
            ))
        );
        assert_ne!(provider_path, set_path);
        assert_ne!(
            provider_path,
            provider_attestation_checkpoint_relative_path(
                operation_id,
                3,
                2,
                17,
                provider_id,
                attestation_digest,
            )
        );
        assert_ne!(
            provider_path,
            provider_attestation_checkpoint_relative_path(
                operation_id,
                4,
                1,
                17,
                provider_id,
                attestation_digest,
            )
        );
        assert_ne!(
            provider_path,
            provider_attestation_checkpoint_relative_path(
                operation_id,
                3,
                1,
                18,
                provider_id,
                attestation_digest,
            )
        );
        assert_ne!(
            provider_path,
            provider_attestation_checkpoint_relative_path(
                operation_id,
                3,
                1,
                17,
                provider_id,
                MusubiProviderBundleAttestationDigestV1::new([0xed; 32]),
            )
        );
        assert!(
            provider_path
                .file_name()
                .expect("provider checkpoint file name")
                .as_encoded_bytes()
                .len()
                <= 255,
            "one checkpoint component must remain within the portable filename ceiling"
        );
        assert!(set_path.is_relative());
        assert!(provider_path.is_relative());
        assert!(set_path.components().all(|component| !matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )));
        assert!(provider_path.components().all(|component| !matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )));
    }
    #[test]
    fn finalized_rebase_recovers_preexisting_exact_location_without_submission() {
        let mut fixture = rebase_fixture();
        let location = coordinator_location(&fixture);
        advance_rebase_page(&mut fixture, 2);
        fixture.page.archive.location_ids = vec![location.location_id];
        fixture.page.items = vec![location];
        let server = serve_rebase_fixture_page(&mut fixture);
        assert!(matches!(
            fixture
                .runtime
                .finalized_location_state(
                    &fixture.request,
                    &fixture.registered,
                    &fixture.response,
                    fixture_attestation_set_digest(&fixture)
                )
                .expect("exact committed location"),
            FinalizedLocationStateV1::Exact { .. }
        ));
        let request_body = server.join().expect("finalized query server");
        let query: MusubiArchiveLocationQueryV1 =
            norito::json::from_slice(&request_body).expect("archive-location query");
        assert_eq!(query.archive_id, fixture.response.archive.archive_id);
        assert_eq!(
            query.page.limit,
            u32::try_from(MUSUBI_MAX_PAGE_SIZE_V1).expect("page maximum fits u32")
        );
        assert!(query.page.cursor.is_none());
    }
    #[test]
    fn archive_location_page_rejects_future_height_and_revision_items() {
        let fixture = rebase_fixture();
        let mut page = fixture.page.clone();
        let mut location = coordinator_location(&fixture);
        page.archive.location_revision = 2;
        page.archive.location_ids = vec![location.location_id];
        location.finalized_height = page.snapshot.finalized_height + 1;
        location.revision = 2;
        page.items = vec![location.clone()];
        assert!(
            page.validate().is_err(),
            "a finalized page cannot contain a future location transition"
        );
        location.finalized_height = page.snapshot.finalized_height;
        location.revision = page.archive.location_revision + 1;
        page.items = vec![location];
        assert!(
            page.validate().is_err(),
            "a location revision cannot exceed its archive CAS revision"
        );
    }
    #[test]
    fn preparation_rejects_a_same_id_location_changed_after_coordination() {
        let mut fixture = rebase_fixture();
        let mut location = coordinator_location(&fixture);
        location.pin_manifest = ManifestDigest::new([0x88; 32]);
        location.renew_after_epoch = 20;
        location.expires_at_epoch = 40;
        location.revision = 2;
        advance_rebase_page(&mut fixture, 2);
        fixture.page.archive.location_ids = vec![location.location_id];
        fixture.page.items = vec![location];
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("preparation cannot adopt a changed unjournaled location");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_ID_CONFLICT");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_rejects_same_id_with_another_attestation_set() {
        let mut fixture = rebase_fixture();
        let mut location = coordinator_location(&fixture);
        location.provider_attestation_set_digest =
            MusubiProviderBundleAttestationSetDigestV1::new([0xee; 32]);
        advance_rebase_page(&mut fixture, 2);
        fixture.page.archive.location_ids = vec![location.location_id];
        fixture.page.items = vec![location];
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("same-id location with another proof set must conflict");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_ID_CONFLICT");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_rejects_a_coordinator_location_retired_since_its_checkpoint() {
        let mut fixture = rebase_fixture();
        let historical_location = coordinator_location(&fixture);
        fixture.registered.archive.location_revision = 2;
        fixture.registered.archive.location_ids = vec![historical_location.location_id];
        fixture.response.archive = fixture.registered.archive.clone();
        fixture.response.disposition =
            MusubiStorageLocationDispositionV1::Registered(historical_location);
        advance_rebase_page(&mut fixture, 3);
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("retired stable location identity must not be reused");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_ID_CONFLICT");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_uses_current_revision_instead_of_coordinator_cache() {
        let mut fixture = rebase_fixture();
        advance_rebase_page(&mut fixture, 7);
        let server = serve_rebase_fixture_page(&mut fixture);
        let state = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect("absent location can be rebased");
        let FinalizedLocationStateV1::Absent { page } = state else {
            panic!("expected absent finalized location state");
        };
        assert_eq!(page.archive.location_revision, 7);
        assert_eq!(
            page.snapshot.finalized_height,
            fixture.page.snapshot.finalized_height
        );
        let instruction = location_add_instruction(
            &fixture.response,
            page.archive.location_revision,
            fixture_attestation_set_digest(&fixture),
        )
        .expect("rebased compact location instruction");
        assert_eq!(instruction.expected_location_revision, 7);
        assert_ne!(
            instruction.expected_location_revision,
            match &fixture.response.disposition {
                MusubiStorageLocationDispositionV1::NeedsRegistration {
                    expected_location_revision,
                    ..
                } => *expected_location_revision,
                MusubiStorageLocationDispositionV1::Registered(_) => {
                    unreachable!("fixture requires registration")
                }
            }
        );
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_rejects_immutable_archive_conflict() {
        let mut fixture = rebase_fixture();
        advance_rebase_page(&mut fixture, 2);
        fixture.page.archive.registered_at_height += 1;
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("immutable registration height substitution must fail");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_rejects_every_immutable_archive_projection_substitution() {
        enum ProjectionMutation {
            Network,
            Commitment,
            Receipt,
            Registrant,
        }
        for mutation in [
            ProjectionMutation::Network,
            ProjectionMutation::Commitment,
            ProjectionMutation::Receipt,
            ProjectionMutation::Registrant,
        ] {
            let mut fixture = rebase_fixture();
            advance_rebase_page(&mut fixture, 2);
            match mutation {
                ProjectionMutation::Network => {
                    fixture.page.network_id = test_network_id(0x91);
                    fixture
                        .page
                        .archive
                        .staging_receipt
                        .payload
                        .binding
                        .network_id = fixture.page.network_id;
                }
                ProjectionMutation::Commitment => {
                    fixture.page.archive.commitment.root_cid =
                        ManifestRootCid::from_blake3_digest([0x92; 32])
                            .expect("replacement root CID");
                    let replacement_archive_id = fixture.page.archive.commitment.archive_id();
                    fixture.page.archive.archive_id = replacement_archive_id;
                    fixture
                        .page
                        .archive
                        .staging_receipt
                        .payload
                        .binding
                        .archive_id = replacement_archive_id;
                }
                ProjectionMutation::Receipt => {
                    fixture.page.archive.staging_receipt.payload.issued_at_ms += 1;
                    fixture.page.archive.staging_receipt.payload.expires_at_ms += 1;
                }
                ProjectionMutation::Registrant => {
                    let replacement_key =
                        KeyPair::try_from_seed(vec![0x93; 32], Algorithm::Ed25519)
                            .expect("replacement registrant key");
                    let replacement = iroha_data_model::account::AccountId::new(
                        replacement_key.public_key().clone(),
                    );
                    fixture.page.archive.registered_by = replacement.clone();
                    fixture
                        .page
                        .archive
                        .staging_receipt
                        .payload
                        .binding
                        .publisher = replacement;
                }
            }
            fixture
                .page
                .validate()
                .expect("substituted projection remains structurally valid");
            let server = serve_rebase_fixture_page(&mut fixture);
            let runtime_error = fixture
                .runtime
                .finalized_location_state(
                    &fixture.request,
                    &fixture.registered,
                    &fixture.response,
                    fixture_attestation_set_digest(&fixture),
                )
                .expect_err("a later snapshot must reproduce the immutable projection exactly");
            // Exact network/archive substitutions are rejected by the typed SDK before the
            // publication projection gate. Other immutable mutations still reach that gate.
            let expected_runtime_code = match mutation {
                ProjectionMutation::Network | ProjectionMutation::Commitment => {
                    "MUSUBI_PUBLICATION_REGISTRY_REJECTED"
                }
                ProjectionMutation::Receipt | ProjectionMutation::Registrant => {
                    "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT"
                }
            };
            assert_eq!(runtime_error.code(), expected_runtime_code);
            assert_eq!(
                runtime_error.class(),
                PublicationBackendFailureClass::Permanent
            );
            let error = validate_finalized_archive_page(
                &fixture.request,
                &fixture.registered,
                &fixture.page,
            )
            .expect_err("every immutable substitution must also fail the projection gate");
            assert_eq!(error.code(), "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT");
            assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
            server.join().expect("finalized query server");
        }
    }
    #[test]
    fn finalized_rebase_retries_a_snapshot_older_than_registration_evidence() {
        let mut fixture = rebase_fixture();
        fixture.page.snapshot.finalized_height -= 1;
        fixture.page.snapshot.finalized_block_hash = [0x89; 32];
        fixture.page.snapshot.index_revision -= 1;
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("lagging finalized endpoint must not supply a CAS revision");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_FINALIZED_SNAPSHOT_STALE");
        assert_eq!(error.class(), PublicationBackendFailureClass::Retryable);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_rejects_mutable_change_at_the_same_snapshot() {
        let mut fixture = rebase_fixture();
        fixture.page.archive.location_revision += 1;
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("one finalized snapshot cannot carry two archive records");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_FINALIZED_ARCHIVE_CONFLICT");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_retries_a_regressed_location_revision() {
        let mut fixture = rebase_fixture();
        fixture.registered.archive.location_revision = 3;
        fixture.response.archive.location_revision = 3;
        if let MusubiStorageLocationDispositionV1::NeedsRegistration {
            expected_location_revision,
            ..
        } = &mut fixture.response.disposition
        {
            *expected_location_revision = 3;
        }
        advance_rebase_page(&mut fixture, 2);
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("a later snapshot cannot regress the archive CAS revision");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_FINALIZED_SNAPSHOT_STALE");
        assert_eq!(error.class(), PublicationBackendFailureClass::Retryable);
        server.join().expect("finalized query server");
    }
    #[test]
    fn finalized_rebase_rejects_exhausted_location_revision() {
        let mut fixture = rebase_fixture();
        advance_rebase_page(&mut fixture, u64::MAX);
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .finalized_location_state(
                &fixture.request,
                &fixture.registered,
                &fixture.response,
                fixture_attestation_set_digest(&fixture),
            )
            .expect_err("location revision cannot be incremented");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_REVISION_EXHAUSTED");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn location_transaction_waits_for_its_finalized_anchor_and_fails_closed_without_rebase() {
        let mut fixture = rebase_fixture();
        let intent = rebase_location_intent(&fixture);
        advance_rebase_page(&mut fixture, intent.expected_location_revision);
        let server = serve_rebase_fixture_page(&mut fixture);
        assert_eq!(
            fixture
                .runtime
                .location_transaction_advance(
                    &fixture.request,
                    &fixture.registered,
                    &intent,
                    RegistryTransactionStateV1::Terminal {
                        kind: RegistryTerminalTransactionStateV1::Rejected,
                        block_height: Some(fixture.page.snapshot.finalized_height + 1),
                    },
                )
                .expect("a lagging page remains pending"),
            PublicationArchiveLocationAdvanceV1::Pending
        );
        server.join().expect("finalized query server");
        let server = serve_rebase_fixture_page(&mut fixture);
        let error = fixture
            .runtime
            .location_transaction_advance(
                &fixture.request,
                &fixture.registered,
                &intent,
                RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Rejected,
                    block_height: Some(fixture.page.snapshot.finalized_height),
                },
            )
            .expect_err("a rejection at the unchanged CAS revision is permanent");
        assert_eq!(error.code(), "ARCHIVE_LOCATION_REGISTRATION_REJECTED");
        assert_eq!(error.class(), PublicationBackendFailureClass::Permanent);
        server.join().expect("finalized query server");
    }
    #[test]
    fn location_transaction_records_rebase_expiry_application_and_later_retirement() {
        let mut rejected = rebase_fixture();
        let rejected_intent = rebase_location_intent(&rejected);
        advance_rebase_page(
            &mut rejected,
            rejected_intent.expected_location_revision + 1,
        );
        let rejected_height = rejected.page.snapshot.finalized_height;
        let server = serve_rebase_fixture_page(&mut rejected);
        let rejected_advance = rejected
            .runtime
            .location_transaction_advance(
                &rejected.request,
                &rejected.registered,
                &rejected_intent,
                RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Rejected,
                    block_height: Some(rejected_height),
                },
            )
            .expect("finalized CAS rebase is a terminal generation");
        assert!(matches!(
            rejected_advance,
            PublicationArchiveLocationAdvanceV1::Terminal(
                PublicationArchiveLocationTerminalV1 {
                    reason: PublicationArchiveLocationTerminalReasonV1::RejectedRebase {
                        block_height
                    },
                    ..
                }
            ) if block_height == rejected_height
        ));
        server.join().expect("finalized query server");
        let mut expired = rebase_fixture();
        let expired_intent = rebase_location_intent(&expired);
        advance_rebase_page(&mut expired, expired_intent.expected_location_revision);
        let server = serve_rebase_fixture_page(&mut expired);
        let expired_advance = expired
            .runtime
            .location_transaction_advance(
                &expired.request,
                &expired.registered,
                &expired_intent,
                RegistryTransactionStateV1::Terminal {
                    kind: RegistryTerminalTransactionStateV1::Expired,
                    block_height: None,
                },
            )
            .expect("expired absent transaction is a terminal generation");
        assert!(matches!(
            expired_advance,
            PublicationArchiveLocationAdvanceV1::Terminal(PublicationArchiveLocationTerminalV1 {
                reason: PublicationArchiveLocationTerminalReasonV1::RegistryExpired {
                    block_height: None
                },
                ..
            })
        ));
        server.join().expect("finalized query server");
        let mut applied = rebase_fixture();
        let applied_intent = rebase_location_intent(&applied);
        let location = coordinator_location(&applied);
        advance_rebase_page(&mut applied, applied_intent.expected_location_revision + 1);
        applied.page.archive.location_ids = vec![location.location_id];
        applied.page.items = vec![location];
        let applied_height = applied.page.snapshot.finalized_height;
        let server = serve_rebase_fixture_page(&mut applied);
        let applied_advance = applied
            .runtime
            .location_transaction_advance(
                &applied.request,
                &applied.registered,
                &applied_intent,
                RegistryTransactionStateV1::Applied {
                    block_height: applied_height,
                },
            )
            .expect("applied exact transaction recovers its finalized location");
        assert!(matches!(
            applied_advance,
            PublicationArchiveLocationAdvanceV1::Registered(
                PublicationArchiveRegistrationV1 {
                    applied_height: observed,
                    ..
                }
            ) if observed == applied_height
        ));
        server.join().expect("finalized query server");
        let mut retired = rebase_fixture();
        let retired_intent = rebase_location_intent(&retired);
        advance_rebase_page(&mut retired, retired_intent.expected_location_revision + 2);
        let applied_height = retired.page.snapshot.finalized_height;
        let server = serve_rebase_fixture_page(&mut retired);
        let retired_advance = retired
            .runtime
            .location_transaction_advance(
                &retired.request,
                &retired.registered,
                &retired_intent,
                RegistryTransactionStateV1::Applied {
                    block_height: applied_height,
                },
            )
            .expect("applied then retired transaction is terminal");
        assert!(matches!(
            retired_advance,
            PublicationArchiveLocationAdvanceV1::Terminal(
                PublicationArchiveLocationTerminalV1 {
                    reason: PublicationArchiveLocationTerminalReasonV1::AppliedThenRetired {
                        applied_height: observed
                    },
                    ..
                }
            ) if observed == applied_height
        ));
        server.join().expect("finalized query server");
    }
    #[test]
    fn platform_config_returns_only_public_request_bindings() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let (signing, publication) = write_client_config(&path, "");
        let parsed = parse_publication_config(&path, &signing, &publication)
            .expect("parse publication config");
        assert_eq!(parsed.bindings.seed_provider, ProviderId::new([0x11; 32]));
        assert_eq!(parsed.bindings.expected_policy_revision, 7);
        assert_eq!(parsed.provider_gateways.len(), 3);
        assert!(parsed.bindings.namespace_delegation.is_none());
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("seed.example"));
        assert!(!debug.contains("storage.example"));
        let platform_debug = format!("{signing:?} {publication:?}");
        assert!(!platform_debug.contains("seed.example"));
        assert!(!platform_debug.contains("storage.example"));
        assert!(!platform_debug.contains("provider-a.example"));
        let fixture_key =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("fixture key");
        let fixture_private = ExposedPrivateKey(fixture_key.private_key().clone()).to_string();
        assert!(!platform_debug.contains(&fixture_private));
    }
    #[cfg(unix)]
    #[test]
    fn provenance_bound_loader_accepts_the_unchanged_image_and_reuses_its_reader() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let (_signing, _publication) = write_client_config(&path, "");
        let (initial_reader, image) = RegistryReadClientV1::load_with_config_image(Some(&path))
            .expect("load authenticated configuration image");
        let provenance = image.provenance();
        drop(image);
        let loaded = load_bound_production_publication_runtime_v1(
            &provenance,
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect("unchanged configuration image");
        let runtime_reader = loaded.registry_reader();
        assert_eq!(runtime_reader.torii_url(), initial_reader.torii_url());
        assert_eq!(
            runtime_reader.account_chain_discriminant(),
            initial_reader.account_chain_discriminant()
        );
    }
    #[cfg(unix)]
    #[test]
    fn provenance_bound_loader_rejects_changed_bytes_before_signer_parsing() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let (_signing, _publication) = write_client_config(&path, "");
        let (_, image) = RegistryReadClientV1::load_with_config_image(Some(&path))
            .expect("load authenticated configuration image");
        let provenance = image.provenance();
        drop(image);
        let fixture_key =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("fixture key");
        let fixture_private = ExposedPrivateKey(fixture_key.private_key().clone()).to_string();
        let original = fs::read_to_string(&path).expect("read original configuration");
        let poisoned = original.replace(&fixture_private, "deliberately-not-a-private-key");
        assert_ne!(poisoned, original);
        fs::write(&path, poisoned).expect("replace configuration image");
        let error = load_bound_production_publication_runtime_v1(
            &provenance,
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect_err("changed configuration must fail before signer parsing");
        assert_eq!(error.code(), "MUSUBI_PUBLICATION_CONFIG_CHANGED");
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains(path.to_string_lossy().as_ref()));
        assert!(!error_debug.contains("deliberately-not-a-private-key"));
        let unbound_error = load_production_publication_runtime_v1(
            Some(&path),
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect_err("the replacement contains an invalid signer");
        assert_eq!(
            unbound_error.code(),
            "MUSUBI_PUBLICATION_SIGNER_CONFIG_INVALID"
        );
    }
    #[cfg(unix)]
    #[test]
    fn provenance_bound_loader_rejects_a_different_valid_image() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let (_signing, _publication) = write_client_config(&path, "");
        let (_, image) = RegistryReadClientV1::load_with_config_image(Some(&path))
            .expect("load authenticated configuration image");
        let provenance = image.provenance();
        drop(image);
        let mut alternate = fs::read_to_string(&path).expect("read original configuration");
        alternate.push_str("\n# valid alternate configuration image\n");
        fs::write(&path, alternate).expect("replace configuration with valid alternate bytes");
        load_production_publication_runtime_v1(
            Some(&path),
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect("the alternate image is independently valid");
        let error = load_bound_production_publication_runtime_v1(
            &provenance,
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect_err("a different valid image must not cross the resolution boundary");
        assert_eq!(error.code(), "MUSUBI_PUBLICATION_CONFIG_CHANGED");
    }
    #[cfg(unix)]
    #[test]
    fn production_loader_rejects_linked_configuration_inputs() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().expect("temporary directory");
        let target = temporary.path().join("target.toml");
        let (_signing, _publication) = write_client_config(&target, "");
        let symbolic = temporary.path().join("symbolic.toml");
        symlink(&target, &symbolic).expect("create symbolic link");
        let symbolic_error = load_production_publication_runtime_v1(
            Some(&symbolic),
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect_err("symbolic configuration must fail closed");
        assert_eq!(symbolic_error.code(), "MUSUBI_PUBLICATION_CONFIG_INVALID");
        let hard = temporary.path().join("hard.toml");
        fs::hard_link(&target, &hard).expect("create hard link");
        let hard_error = load_production_publication_runtime_v1(
            Some(&hard),
            UnavailablePublicationCleanPackageValidatorV1,
        )
        .expect_err("hard-linked configuration must fail closed");
        assert_eq!(hard_error.code(), "MUSUBI_PUBLICATION_CONFIG_INVALID");
    }
    #[test]
    fn bounded_platform_config_preserves_the_nonempty_contract() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        fs::write(&path, b"").expect("write empty configuration");
        assert_eq!(
            read_bounded_platform_config_v1(&path)
                .expect_err("empty platform configuration must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[cfg(not(any(unix, windows)))]
    #[test]
    fn bounded_platform_config_is_unsupported_before_path_io() {
        let parent = tempdir().expect("temporary parent");
        let path = parent.path().join("must-remain-absent/client.toml");
        let error = read_bounded_platform_config_v1(&path)
            .expect_err("non-Unix platform configuration must be unsupported");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!path.parent().expect("requested path has a parent").exists());
    }
    #[test]
    fn provider_gateways_must_have_distinct_provider_ids_and_origins() {
        let gateways = vec![
            iroha::config::MusubiPublicationProviderGatewayConfig {
                provider_id: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
                url: "https://same.example/".to_owned(),
                attestation_url: "https://inventory.example/".to_owned(),
            },
            iroha::config::MusubiPublicationProviderGatewayConfig {
                provider_id: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_owned(),
                url: "https://same.example/other/".to_owned(),
                attestation_url: "https://inventory.example/".to_owned(),
            },
        ];
        assert!(parse_provider_gateways(&gateways).is_err());
    }
    #[test]
    fn unknown_fields_and_retired_upload_routes_fail_closed() {
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("client.toml");
        let (_signing, _publication) = write_client_config(&path, "");
        let valid = fs::read_to_string(&path).expect("read valid client config");
        fs::write(&path, format!("{valid}\nunexpected = true\n"))
            .expect("write unknown publication field");
        assert!(
            RegistrySigningClientV1::load(Some(&path)).is_err(),
            "platform client config must reject unknown Musubi publication fields"
        );
        assert!(parse_service_url("https://seed.example/v1/sorafs/upload/").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn public_namespace_delegation_file_is_bounded_and_delegate_bound() {
        let temporary = tempdir().expect("temporary directory");
        let config_path = temporary.path().join("client.toml");
        let delegation_path = temporary.path().join("delegation.to");
        let (signing, publication) = write_client_config(
            &config_path,
            r#"namespace_delegation_file = "delegation.to""#,
        );
        let owner_key_pair =
            KeyPair::try_from_seed(vec![0x61; 32], Algorithm::Ed25519).expect("owner key");
        let payload = MusubiNamespaceDelegationPayloadV1 {
            version: 1,
            namespace_binding: MusubiNamespaceBindingDigestV1::new([0x62; 32]),
            owner_generation: 4,
            owner: iroha_data_model::account::AccountId::new(owner_key_pair.public_key().clone()),
            delegate: signing.authority().clone(),
            expires_at_height: 10_000,
        };
        let delegation = MusubiNamespaceDelegationV1 {
            approvals: vec![MusubiNamespaceDelegationApprovalV1 {
                public_key: owner_key_pair.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    owner_key_pair.private_key(),
                    payload.signing_hash(),
                )
                .expect("sign delegation"),
            }],
            payload,
        };
        fs::write(
            &delegation_path,
            norito::encode_canonical(&delegation).expect("encode delegation"),
        )
        .expect("write delegation");
        let parsed = parse_publication_config(&config_path, &signing, &publication)
            .expect("load public namespace delegation");
        assert_eq!(
            parsed.bindings.namespace_delegation.as_ref(),
            Some(&delegation)
        );
        let mut mismatched = delegation;
        mismatched.payload.delegate = mismatched.payload.owner.clone();
        fs::write(
            &delegation_path,
            norito::encode_canonical(&mismatched).expect("encode mismatched delegation"),
        )
        .expect("rewrite delegation");
        let error = parse_publication_config(&config_path, &signing, &publication)
            .expect_err("delegation for a different actor must fail");
        assert_eq!(
            error.code(),
            "MUSUBI_PUBLICATION_DELEGATION_DELEGATE_MISMATCH"
        );
    }
    #[test]
    fn attestation_set_checkpoint_encoder_charges_one_exact_frame_without_renewal() {
        let fixture = rebase_fixture();
        let checkpoint = PublicationProviderAttestationSetCheckpointV1::new(
            fixture.request.operation_id(),
            1,
            fixture.response.archive.archive_id,
            fixture.response.replication_order,
            coordinator_provider_attestations(&fixture).to_vec(),
        )
        .unwrap();
        let expected = norito::encode_canonical(&checkpoint).unwrap();
        let limits =
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, expected.len(), 128);
        norito::with_decode_limits_scope(limits, || {
            assert_eq!(
                encode_attestation_set_checkpoint(&checkpoint).unwrap(),
                expected
            );
            assert!(
                encode_attestation_set_checkpoint(&checkpoint).is_err(),
                "a second frame cannot renew the original cumulative allowance"
            );
        });
    }

    include!("publication_runtime/provider_inventory_tests.rs");
}

#[cfg(test)]
#[path = "publication_runtime/frame_identity_tests.rs"]
mod frame_identity_tests;
