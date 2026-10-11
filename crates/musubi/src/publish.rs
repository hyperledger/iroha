//! Resumable, evidence-checked Musubi V1 publication workflow.
//!
//! The workflow deliberately keeps network authentication and signing outside
//! the persisted state.  Its journal contains only public request material,
//! signed public evidence, finalized records, and idempotency identifiers.  A
//! backend is therefore supplied at runtime and cannot smuggle provider URLs, bearer credentials,
//! private keys, or a retired public upload route into a project or operation journal.
//!
//! Archive registration has three durable checkpoints inside the public `ArchiveRegistration`
//! phase: a bounded append-only sequence of exact fee-quoted signed transaction attempts, the
//! finalized authoritative archive record recovered from the registry, and only then permanent
//! pin/order coordination. An attempt is never replaced while its application state is absent,
//! unknown, or pending. A new receipt and transaction generation are permitted only after durable
//! terminal and finalized-absence evidence for the preceding attempt. Archive locations have an
//! independent bounded append-only generation history: each exact signed CAS is persisted before
//! submission, every later generation requires authoritative terminal finalized state, and retired
//! stable location identities are never reused. Release submission follows the same Phase-B
//! boundary: clean readbacks and one fee-quoted signature are persisted atomically before any send,
//! every retry first queries the exact transaction hash, and an absent transaction is submitted
//! only while the selected finalized location is byte-identical to the signed floor.
//!
//! Journal and staged-CAR access uses shared native filesystem custody on Unix and Windows.
//! Retained ancestors, owner-private files, bounded reads and exact object identities protect
//! recovery; native Windows execution remains part of the separate release qualification.
use crate::atomic_io::{AtomicWriteError, AtomicWriteRoot};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::{
        InstructionBox,
        musubi::{AddMusubiArchiveLocationV1, PublishMusubiReleaseV1, RegisterMusubiArchiveV1},
    },
    musubi::{
        ArchiveId, MUSUBI_MAX_CAR_BYTES_V1, MUSUBI_MAX_LOCATION_PROVIDERS_V1,
        MUSUBI_MIN_HEALTHY_REPLICAS_V1, MusubiArchiveCommitmentV1, MusubiArchiveLocationIdV1,
        MusubiArchiveLocationPageV1, MusubiArchiveLocationStateV1, MusubiArchiveLocationV1,
        MusubiArchiveRecordV1, MusubiArchiveRetentionDecisionV1,
        MusubiArchiveRetentionDispositionV1, MusubiArchiveRetentionPageV1,
        MusubiArchiveRetentionQueryV1, MusubiContentDigestV1, MusubiExactReleaseSnapshotV1,
        MusubiNamespaceDelegationV1, MusubiNamespaceV1, MusubiPackageScopeV1,
        MusubiProviderBundleAttestationDigestV1, MusubiProviderBundleAttestationKeyV1,
        MusubiProviderBundleAttestationSetDigestV1, MusubiPublicationV1, MusubiRegistrySnapshotV1,
        MusubiReleaseDigestV1, MusubiReleaseIdV1, MusubiReleaseRecordV1, MusubiResolverIndexPageV1,
        MusubiResolverReleaseRowV1, MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptV1,
        MusubiSemanticReleaseDigestV1, MusubiVerificationLockDigestV1, MusubiVersionReqV1,
    },
    sorafs::{
        capacity::ProviderId,
        pin_registry::{ManifestDigest, ReplicationOrderId},
    },
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload,
        TransactionSignature, signed::MultisigSignatures,
    },
};
use iroha_fs::{FileIdentity, FileSnapshot, PrivateDirectory, PublishMode, RetainedFile};
use iroha_model_base::metadata::Metadata;
use iroha_musubi_service::{
    MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1, MUSUBI_PUBLICATION_SERVICE_MAX_CLOCK_SKEW_MS_V1,
    MusubiSeedIngressCarPlanV1, publication_client_journal,
};
use norito::{
    DecodeLimits,
    codec::{Decode, Encode},
};
use sorafs_car::{CarBuildPlan, CarVerifier, ChunkStore};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    fs::File,
    io::{self, Read},
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    str::FromStr,
};
const JOURNAL_SCHEMA: &str = "musubi-publication-journal";
const JOURNAL_VERSION: u8 = 1;
const JOURNAL_EXTENSION: &str = "norito";
const JOURNAL_LOCK_EXTENSION: &str = "lock";
const STAGED_CAR_EXTENSION: &str = "car";
const STAGED_PLAN_EXTENSION: &str = "plan.norito";
const STAGED_PLAN_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    16_384,
    MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1,
    2_097_152,
    128 * 1024 * 1024,
    128,
);
const STAGED_CAR_PLAN_HEAP_LIMIT_BYTES_V1: usize =
    sorafs_car::DEFAULT_CHUNK_STORE_MAX_ESTIMATED_HEAP_BYTES;
#[cfg(all(test, unix))]
std::thread_local! {
    static TEST_PUBLICATION_READ_FIFO_SUBSTITUTIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
/// Maximum number of exact archive-registration transaction generations in one V1 operation.
pub const MUSUBI_MAX_ARCHIVE_REGISTRATION_ATTEMPTS_V1: usize = 8;
/// Maximum number of append-only archive-location transaction generations in one V1 operation.
pub const MUSUBI_MAX_ARCHIVE_LOCATION_ATTEMPTS_V1: usize = 8;
/// Maximum immutable signed registration attempts retained for one provider proof.
pub const MUSUBI_MAX_PROVIDER_REGISTRATION_ATTEMPTS_V1: u8 = 8;
/// Maximum number of exact release-submission transaction generations in one V1 operation.
pub const MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1: usize = 8;
/// Maximum authorization signatures retained by one compact release transaction envelope.
pub const MUSUBI_MAX_RELEASE_SIGNATURES_V1: usize = 16;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JOURNAL_BYTES_USIZE: usize = 16 * 1024 * 1024;
// The persisted frame reserves half of its payload budget for immutable request/archive evidence
// and half for eight release attempts plus compact completion state. Standalone canonical
// component frames overcount their nested representation, while the remaining 1/64 covers outer
// framing and terminal fields.
const JOURNAL_CANONICAL_OVERHEAD_RESERVE_BYTES: usize = MAX_JOURNAL_BYTES_USIZE / 64;
const JOURNAL_COMPONENT_BUDGET_BYTES: usize =
    MAX_JOURNAL_BYTES_USIZE - JOURNAL_CANONICAL_OVERHEAD_RESERVE_BYTES;
const JOURNAL_NON_RELEASE_BUDGET_BYTES: usize = JOURNAL_COMPONENT_BUDGET_BYTES / 2;
const JOURNAL_RELEASE_HISTORY_BUDGET_BYTES: usize =
    JOURNAL_COMPONENT_BUDGET_BYTES - JOURNAL_NON_RELEASE_BUDGET_BYTES;
const MAX_RELEASE_SUBMISSION_CANONICAL_BYTES: usize = JOURNAL_CANONICAL_OVERHEAD_RESERVE_BYTES / 4;
const MAX_RELEASE_FINAL_CHECKPOINT_CANONICAL_BYTES: usize =
    JOURNAL_CANONICAL_OVERHEAD_RESERVE_BYTES / 4;
const JOURNAL_RELEASE_FINAL_STATE_BUDGET_BYTES: usize =
    MAX_RELEASE_SUBMISSION_CANONICAL_BYTES + MAX_RELEASE_FINAL_CHECKPOINT_CANONICAL_BYTES;
const JOURNAL_RELEASE_ATTEMPTS_BUDGET_BYTES: usize =
    JOURNAL_RELEASE_HISTORY_BUDGET_BYTES - JOURNAL_RELEASE_FINAL_STATE_BUDGET_BYTES;
// The exact paired query is bounded independently from the compact journal checkpoint. It may
// include consensus-legal post-publication controller projections that must not inflate the
// durable operation frame.
const MAX_RELEASE_FINAL_QUERY_EVIDENCE_CANONICAL_BYTES: usize = MAX_JOURNAL_BYTES_USIZE;
const MAX_RELEASE_ATTEMPT_CANONICAL_BYTES: usize =
    JOURNAL_RELEASE_ATTEMPTS_BUDGET_BYTES / MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1;
// Every retained attempt receives equal canonical budgets for its persist-before-send intent and
// its later applied/terminal outcome. Their standalone frames overcount the nested attempt bytes.
const MAX_RELEASE_INTENT_CANONICAL_BYTES: usize = MAX_RELEASE_ATTEMPT_CANONICAL_BYTES / 2;
const MAX_RELEASE_OUTCOME_CANONICAL_BYTES: usize =
    MAX_RELEASE_ATTEMPT_CANONICAL_BYTES - MAX_RELEASE_INTENT_CANONICAL_BYTES;
// TODO: Replace complete journaled location pages with digest-addressed, durably verified
// sidecars before admitting the full consensus-legal 4 locations x 64 providers x 64 approvals
// shape (especially ML-DSA approvals). Until then the derived canonical budgets reject it
// fail-closed rather than allowing a publication that cannot append its terminal evidence.
const JOURNAL_DECODE_LIMITS: DecodeLimits = DecodeLimits::new(
    1_048_576,
    MAX_JOURNAL_BYTES_USIZE,
    2_097_152,
    64 * 1024 * 1024,
    128,
);
const OPERATION_ID_DOMAIN: &[u8] = b"iroha.musubi.publication-operation.v1";
const ARCHIVE_REGISTRATION_INSTRUCTION_DOMAIN: &[u8] =
    b"iroha.musubi.archive-registration-instruction.v1";
const ARCHIVE_LOCATION_INSTRUCTION_DOMAIN: &[u8] = b"iroha.musubi.archive-location-instruction.v1";
const PUBLISH_INSTRUCTION_DOMAIN: &[u8] = b"iroha.musubi.publish-instruction.v1";
const RELEASE_SIGNED_TRANSACTION_DOMAIN: &[u8] = b"iroha.musubi.release-signed-transaction.v1";
const FINAL_HOME_RELEASE_DOMAIN: &[u8] = b"iroha.musubi.final-home-release.v1";
const FINAL_UNIVERSAL_RELEASE_DOMAIN: &[u8] = b"iroha.musubi.final-universal-release.v1";
const FINAL_CHECKPOINT_DOMAIN: &[u8] = b"iroha.musubi.final-checkpoint.v1";
/// Stable identifier used to make every remote publication transition idempotent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct PublicationOperationIdV1([u8; 32]);
impl PublicationOperationIdV1 {
    /// Return the exact operation-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    fn from_request(request: &PublicationRequestV1) -> Self {
        Self(domain_hash(OPERATION_ID_DOMAIN, &request.encode()))
    }
    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}
impl fmt::Display for PublicationOperationIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}
/// Error returned when a detached publication operation id is not canonical hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationOperationIdParseError;
impl fmt::Display for PublicationOperationIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("publication operation id must be 64 non-zero lowercase hex digits")
    }
}
impl Error for PublicationOperationIdParseError {}
impl FromStr for PublicationOperationIdV1 {
    type Err = PublicationOperationIdParseError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.len() != 64
            || raw
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(PublicationOperationIdParseError);
        }
        let decoded = hex::decode(raw).map_err(|_| PublicationOperationIdParseError)?;
        let bytes = <[u8; 32]>::try_from(decoded).map_err(|_| PublicationOperationIdParseError)?;
        let operation_id = Self(bytes);
        if operation_id.is_zero() {
            return Err(PublicationOperationIdParseError);
        }
        Ok(operation_id)
    }
}
/// Public inputs that remain stable across every retry of one publication.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationRequestV1 {
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Account that will publish the release through Native AMX.
    pub publisher: AccountId,
    /// Authenticated seed-ingress broker expected to sign the staging receipt.
    pub ingress_broker: AccountId,
    /// Seed provider selected for the authenticated ingress request.
    pub seed_provider: ProviderId,
    /// Exact canonical namespace whose immutable binding authorizes the package claim.
    pub namespace: MusubiNamespaceV1,
    /// Immutable release and exact verification graph.
    pub publication: MusubiPublicationV1,
    /// Exact canonical CAR and parsed-bundle commitment.
    pub archive_commitment: MusubiArchiveCommitmentV1,
    /// Optional generation-bound authorization for the first package claim.
    pub namespace_delegation: Option<MusubiNamespaceDelegationV1>,
    /// Registry-policy revision used by archive and release admission.
    pub expected_policy_revision: u64,
    /// Existing package-governance revision, absent only for a first claim.
    pub expected_governance_revision: Option<u64>,
    /// Unpredictable public anti-replay nonce for this operation.
    pub nonce: [u8; 32],
}
impl PublicationRequestV1 {
    /// Return the exact genesis-derived network identity.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Validate all immutable publication, archive, deployment, and revision bindings.
    ///
    /// # Errors
    ///
    /// Returns an invalid-evidence error when any request field, namespace binding, archive
    /// commitment, or policy revision is malformed or inconsistent.
    pub fn validate(&self) -> Result<(), PublicationError> {
        self.publication
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        self.archive_commitment
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        self.namespace
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        if let Some(delegation) = &self.namespace_delegation {
            delegation
                .validate()
                .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
            if delegation.payload.delegate != self.publisher {
                return Err(PublicationError::InvalidEvidence {
                    phase: PublicationPhaseV1::Validation,
                    reason: "namespace delegation does not authorize the publisher".to_owned(),
                });
            }
        }
        if self.network_id.as_bytes()[31] & 1 != 1
            || self.seed_provider.as_bytes().iter().all(|byte| *byte == 0)
            || self.nonce.iter().all(|byte| *byte == 0)
            || self.expected_policy_revision == 0
            || self.expected_governance_revision == Some(0)
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Validation,
                reason: "publication deployment, nonce, or revision binding is inert".to_owned(),
            });
        }
        let namespace_scope_matches = match (
            &self.publication.manifest.release.package.scope,
            self.namespace.domain_segment(),
        ) {
            (MusubiPackageScopeV1::DataspaceRoot, None) => true,
            (MusubiPackageScopeV1::Domain(domain), Some(segment)) => domain.as_ref() == segment,
            _ => false,
        };
        if !namespace_scope_matches {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Validation,
                reason: "canonical namespace does not match the structural package scope"
                    .to_owned(),
            });
        }
        if self.publication.manifest.archive_id != self.archive_commitment.archive_id() {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Validation,
                reason: "release manifest does not bind the supplied archive commitment".to_owned(),
            });
        }
        Ok(())
    }
    /// Derive the stable idempotency identifier for this exact request.
    #[must_use]
    pub fn operation_id(&self) -> PublicationOperationIdV1 {
        PublicationOperationIdV1::from_request(self)
    }
    fn receipt_binding(&self) -> MusubiSeedIngressReceiptBindingV1 {
        MusubiSeedIngressReceiptBindingV1 {
            network_id: self.network_id(),
            publisher: self.publisher.clone(),
            ingress_broker: self.ingress_broker.clone(),
            seed_provider: self.seed_provider,
            semantic_release_manifest_digest: self.publication.manifest.semantic_digest(),
            archive_id: self.archive_commitment.archive_id(),
            car_body_digest: self.archive_commitment.car_digest,
            car_body_length: self.archive_commitment.car_size,
            nonce: self.nonce,
        }
    }
    pub(crate) fn publish_instruction(&self) -> PublishMusubiReleaseV1 {
        PublishMusubiReleaseV1::new(
            self.namespace.clone(),
            self.publication.clone(),
            self.namespace_delegation.clone(),
            self.expected_policy_revision,
            self.expected_governance_revision,
        )
    }
    /// Construct the one canonical archive-registration instruction for this operation receipt.
    pub(crate) fn archive_registration_instruction(
        &self,
        staging_receipt: &MusubiSeedIngressReceiptV1,
    ) -> RegisterMusubiArchiveV1 {
        RegisterMusubiArchiveV1::new(
            self.archive_commitment.clone(),
            staging_receipt.clone(),
            self.expected_policy_revision,
        )
    }
}
/// The seven production phases of Musubi V1 publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum PublicationPhaseV1 {
    /// Validate and compiler-check the clean package and exact proof.
    Validation,
    /// Stage the exact CAR through authenticated `SoraFS` seed ingress.
    SeedIngress,
    /// Persist exact registration intent and finality before creating its permanent pin/order.
    ArchiveRegistration,
    /// Wait for finalized, provider-verified replication quorum.
    Replication,
    /// Verify full readback through two distinct finalized providers.
    Readback,
    /// Submit the final package claim and release through Native AMX.
    ReleaseSubmission,
    /// Verify the exact finalized home record and universal resolver row.
    FinalVerification,
}
/// Secret-free proof that the clean package and exact verification graph were checked.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationValidationEvidenceV1 {
    /// Archive whose exact CAR bytes were checked.
    pub archive_id: ArchiveId,
    /// Semantic manifest digest embedded in the checked bundle.
    pub semantic_release_digest: MusubiSemanticReleaseDigestV1,
    /// Full registry release digest, including the archive identity.
    pub release_digest: MusubiReleaseDigestV1,
    /// Source-tree digest reproduced from the clean packaged tree.
    pub source_tree_digest: MusubiContentDigestV1,
    /// Typed artifact-descriptor digest reproduced from the bundle.
    pub descriptor_digest: MusubiContentDigestV1,
    /// Exact normalized verification-lock digest checked by the resolver.
    pub verification_lock_digest: MusubiVerificationLockDigestV1,
    /// Exact CAR digest read by the compiler-validation path.
    pub car_digest: MusubiContentDigestV1,
    /// Exact CAR length read by the compiler-validation path.
    pub car_size: u64,
    /// Deterministic digest of the successful compiler result.
    pub compiler_output_digest: MusubiContentDigestV1,
    /// Finalized registry snapshot against which the exact graph was checked.
    pub resolution_snapshot: MusubiRegistrySnapshotV1,
}
impl PublicationValidationEvidenceV1 {
    fn validate_for(&self, request: &PublicationRequestV1) -> Result<(), PublicationError> {
        let manifest = &request.publication.manifest;
        if self.archive_id != request.archive_commitment.archive_id()
            || self.semantic_release_digest != manifest.semantic_digest()
            || self.release_digest != manifest.release_digest()
            || self.source_tree_digest != request.archive_commitment.source_tree_digest
            || self.descriptor_digest != request.archive_commitment.descriptor_digest
            || self.verification_lock_digest != manifest.verification_lock_digest
            || self.car_digest != request.archive_commitment.car_digest
            || self.car_size != request.archive_commitment.car_size
            || self.compiler_output_digest.is_zero()
            || self.resolution_snapshot != request.publication.resolution.snapshot
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Validation,
                reason: "clean-package validation evidence was substituted or incomplete"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
/// Durable exact transaction intent for immutable archive registration.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveRegistrationIntentV1 {
    /// Operation whose immutable request produced this intent.
    pub operation_id: PublicationOperationIdV1,
    /// Exact archive identity registered by the instruction.
    pub archive_id: ArchiveId,
    /// Exact seed-ingress receipt embedded in the registration instruction.
    pub staging_receipt: MusubiSeedIngressReceiptV1,
    /// Domain-separated digest of the canonical [`RegisterMusubiArchiveV1`] instruction.
    pub instruction_digest: [u8; 32],
    /// Exact fee-quoted and signed transaction to submit or recover.
    pub signed_transaction: SignedTransaction,
    /// Canonical transaction hash derived from `signed_transaction`.
    pub transaction_hash: [u8; 32],
}
impl PublicationArchiveRegistrationIntentV1 {
    /// Bind an exact prebuilt transaction to the immutable operation and registration instruction.
    #[must_use]
    pub fn new(
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        staging_receipt: MusubiSeedIngressReceiptV1,
        signed_transaction: SignedTransaction,
    ) -> Self {
        let instruction = request.archive_registration_instruction(&staging_receipt);
        let transaction_hash = *signed_transaction.hash().as_ref();
        Self {
            operation_id,
            archive_id: request.archive_commitment.archive_id(),
            staging_receipt,
            instruction_digest: archive_registration_instruction_digest(&instruction),
            signed_transaction,
            transaction_hash,
        }
    }
    pub(crate) fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        staging_receipt: &MusubiSeedIngressReceiptV1,
    ) -> Result<(), PublicationError> {
        let instruction = request.archive_registration_instruction(staging_receipt);
        let expected_instruction: InstructionBox = instruction.clone().into();
        let exact_instruction = matches!(
            self.signed_transaction.instructions(),
            Executable::Instructions(instructions)
                if instructions.len() == 1
                    && instructions.iter().next() == Some(&expected_instruction)
        );
        let signature_is_valid = self.signed_transaction.verify_signature().is_ok();
        let receipt_is_valid = staging_receipt
            .verify(
                &request.receipt_binding(),
                staging_receipt.payload.issued_at_ms,
            )
            .is_ok();
        if self.operation_id != operation_id
            || self.archive_id != request.archive_commitment.archive_id()
            || &self.staging_receipt != staging_receipt
            || self.instruction_digest != archive_registration_instruction_digest(&instruction)
            || self.transaction_hash != *self.signed_transaction.hash().as_ref()
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || self.signed_transaction.network_id().copied() != Some(request.network_id())
            || self.signed_transaction.authority() != &request.publisher
            || archive_registration_intent_valid_until_ms(self).is_none()
            || !exact_instruction
            || !signature_is_valid
            || !receipt_is_valid
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ArchiveRegistration,
                reason: "archive registration intent or exact signed transaction was substituted"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
/// Return the earliest consensus validity deadline shared by the signed transaction and receipt.
pub(crate) fn archive_registration_intent_valid_until_ms(
    intent: &PublicationArchiveRegistrationIntentV1,
) -> Option<u64> {
    let created_at_ms =
        u64::try_from(intent.signed_transaction.creation_time().as_millis()).ok()?;
    if created_at_ms < intent.staging_receipt.payload.issued_at_ms
        || created_at_ms > intent.staging_receipt.payload.expires_at_ms
    {
        return None;
    }
    let ttl_ms = u64::try_from(intent.signed_transaction.time_to_live()?.as_millis()).ok()?;
    let transaction_expires_at_ms = created_at_ms.checked_add(ttl_ms)?;
    Some(transaction_expires_at_ms.min(intent.staging_receipt.payload.expires_at_ms))
}
/// Exact finalized registry evidence that an archive identity remained absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveAbsenceEvidenceV1 {
    /// Exact genesis-derived network identity returned by the finalized query.
    pub network_id: NetworkId,
    /// Finalized universal registry snapshot at which the archive was absent.
    pub snapshot: MusubiRegistrySnapshotV1,
    /// Consensus-committed creation time of the finalized block named by `snapshot`.
    pub finalized_time_ms: u64,
    /// Exact retention decision proving that the registry did not know the archive.
    pub decision: MusubiArchiveRetentionDecisionV1,
}
impl PublicationArchiveAbsenceEvidenceV1 {
    /// Validate that this evidence names the request's exact deployment and absent archive.
    pub(crate) fn validate_for(
        &self,
        request: &PublicationRequestV1,
    ) -> Result<(), PublicationError> {
        self.snapshot
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ArchiveRegistration, error))?;
        self.decision
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ArchiveRegistration, error))?;
        if self.network_id != request.network_id
            || self.decision.archive_id != request.archive_commitment.archive_id()
            || self.decision.disposition != MusubiArchiveRetentionDispositionV1::RetainUnknown
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ArchiveRegistration,
                reason: "archive-registration absence evidence was substituted".to_owned(),
            });
        }
        Ok(())
    }
}
/// Provable terminal state of one exact archive-registration transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PublicationArchiveRegistrationTerminalReasonV1 {
    /// Finalized transaction status expired the exact transaction.
    #[codec(index = 0)]
    RegistryExpired {
        /// Finalized block when supplied by the authoritative status record.
        block_height: Option<u64>,
    },
    /// A finalized block time passed the exact transaction/receipt validity window.
    #[codec(index = 1)]
    FinalizedValidityWindowElapsed {
        /// Consensus-committed time proving no later block may accept the intent.
        finalized_time_ms: u64,
    },
}
/// Durable terminal and finalized-absence evidence for one exact registration attempt.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveRegistrationTerminalV1 {
    /// Exact transaction whose generation may no longer be submitted or retried.
    pub transaction_hash: [u8; 32],
    /// Why the exact transaction is provably terminal.
    pub reason: PublicationArchiveRegistrationTerminalReasonV1,
    /// Finalized exact-identity query proving that no conflicting archive was present.
    pub absence: PublicationArchiveAbsenceEvidenceV1,
}
impl PublicationArchiveRegistrationTerminalV1 {
    /// Construct terminal evidence for a finalized registry expiration.
    #[must_use]
    pub fn registry_expired(
        intent: &PublicationArchiveRegistrationIntentV1,
        block_height: Option<u64>,
        absence: PublicationArchiveAbsenceEvidenceV1,
    ) -> Self {
        Self {
            transaction_hash: intent.transaction_hash,
            reason: PublicationArchiveRegistrationTerminalReasonV1::RegistryExpired {
                block_height,
            },
            absence,
        }
    }
    /// Construct terminal evidence from finalized chain time and exact archive absence.
    #[must_use]
    pub fn finalized_validity_window_elapsed(
        intent: &PublicationArchiveRegistrationIntentV1,
        absence: PublicationArchiveAbsenceEvidenceV1,
    ) -> Self {
        Self {
            transaction_hash: intent.transaction_hash,
            reason:
                PublicationArchiveRegistrationTerminalReasonV1::FinalizedValidityWindowElapsed {
                    finalized_time_ms: absence.finalized_time_ms,
                },
            absence,
        }
    }
    /// Validate this terminal proof against the exact persisted registration intent.
    pub(crate) fn validate_for(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
    ) -> Result<(), PublicationError> {
        self.absence.validate_for(request)?;
        let reason_is_valid = match self.reason {
            PublicationArchiveRegistrationTerminalReasonV1::RegistryExpired { block_height } => {
                block_height.is_none_or(|height| {
                    height > 0 && self.absence.snapshot.finalized_height >= height
                })
            }
            PublicationArchiveRegistrationTerminalReasonV1::FinalizedValidityWindowElapsed {
                finalized_time_ms,
            } => {
                finalized_time_ms == self.absence.finalized_time_ms
                    && archive_registration_intent_valid_until_ms(intent)
                        .is_some_and(|valid_until_ms| finalized_time_ms > valid_until_ms)
            }
        };
        if self.transaction_hash != intent.transaction_hash
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || !reason_is_valid
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ArchiveRegistration,
                reason: "archive-registration terminal evidence was substituted".to_owned(),
            });
        }
        Ok(())
    }
}
/// One immutable exact transaction generation and its optional terminal evidence.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveRegistrationAttemptV1 {
    /// One-based contiguous generation number within this operation journal.
    pub generation: u8,
    /// Exact fee-quoted signed transaction intent for this generation.
    pub intent: PublicationArchiveRegistrationIntentV1,
    /// Terminal and finalized-absence evidence, appended before a later generation is allowed.
    pub terminal: Option<PublicationArchiveRegistrationTerminalV1>,
}
impl PublicationArchiveRegistrationAttemptV1 {
    fn new(generation: u8, intent: PublicationArchiveRegistrationIntentV1) -> Self {
        Self {
            generation,
            intent,
            terminal: None,
        }
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
    ) -> Result<(), PublicationError> {
        self.intent
            .validate_for(operation_id, request, &self.intent.staging_receipt)?;
        if let Some(terminal) = &self.terminal {
            terminal.validate_for(request, &self.intent)?;
        }
        Ok(())
    }
}
/// Result of inspecting or submitting one exact archive-registration generation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed advance protocol returns complete finalized evidence without heap-indirecting its stable API"
)]
pub enum PublicationArchiveRegistrationAdvanceV1 {
    /// The exact transaction remains absent/unknown or pending and must not be replaced.
    Pending,
    /// The exact authoritative archive was recovered from finalized registry state.
    Registered(PublicationRegisteredArchiveV1),
    /// The exact transaction is terminal and the archive is finalized absent/conflict-free.
    TerminalAbsent(PublicationArchiveRegistrationTerminalV1),
}
/// Finalized authoritative archive record recovered for one exact registration transaction.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationRegisteredArchiveV1 {
    /// Exact transaction identity whose finalized effect was recovered.
    pub finalized_transaction_hash: [u8; 32],
    /// Exact genesis-derived network identity returned by the finalized query.
    pub network_id: NetworkId,
    /// Finalized registry snapshot that contains the authoritative archive record.
    pub snapshot: MusubiRegistrySnapshotV1,
    /// Authoritative archive record embedded in the finalized archive-location query page.
    pub archive: MusubiArchiveRecordV1,
}
impl PublicationRegisteredArchiveV1 {
    pub(crate) fn validate_for(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
    ) -> Result<(), PublicationError> {
        self.archive
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ArchiveRegistration, error))?;
        self.snapshot
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ArchiveRegistration, error))?;
        let observed_finalized_transaction_hash = self.finalized_transaction_hash;
        let expected_intent_transaction_hash = intent.transaction_hash;
        if observed_finalized_transaction_hash != expected_intent_transaction_hash
            || self.network_id != request.network_id
            || self.archive.registered_at_height > self.snapshot.finalized_height
            || self.archive.archive_id != intent.archive_id
            || self.archive.archive_id != request.archive_commitment.archive_id()
            || self.archive.commitment != request.archive_commitment
            || self.archive.staging_receipt != intent.staging_receipt
            || self.archive.registered_by != request.publisher
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ArchiveRegistration,
                reason: "finalized authoritative archive record conflicts with registration intent"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
/// Main-journal identity of one immutable provider-registration transaction sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationProviderRegistrationTransactionCheckpointV1 {
    /// One-based, provider-local immutable signing attempt.
    pub attempt: u8,
    /// Exact archive location revision carried by the signed registration instruction.
    pub expected_location_revision: u64,
    /// Immutable archive/order/provider identity of the registered proof.
    pub key: MusubiProviderBundleAttestationKeyV1,
    /// Digest of the complete provider attestation carried by the instruction.
    pub attestation_digest: MusubiProviderBundleAttestationDigestV1,
    /// Canonical Iroha hash of the exact signed transaction.
    pub transaction_hash: [u8; 32],
    /// Domain-separated hash of the complete immutable sidecar bytes.
    pub sidecar_hash: [u8; 32],
}
/// Compact main-journal anchor for one location generation's immutable provider sidecars.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationProviderRegistrationCheckpointV1 {
    /// One-based archive-location generation owning these proof registrations.
    pub generation: u8,
    /// Exact archive named by every provider proof.
    pub archive_id: ArchiveId,
    /// Exact replication order named by every provider proof.
    pub replication_order: ReplicationOrderId,
    /// Digest of the immutable sorted provider-proof set.
    pub provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
    /// Domain-separated hash of the complete immutable provider-set sidecar.
    pub set_sidecar_hash: [u8; 32],
    /// Append-only identities and hashes of every expected signed-transaction sidecar.
    pub transactions: Vec<PublicationProviderRegistrationTransactionCheckpointV1>,
}
impl PublicationProviderRegistrationCheckpointV1 {
    pub(crate) fn validate_for(
        &self,
        request: &PublicationRequestV1,
        expected_generation: u8,
    ) -> Result<(), PublicationError> {
        let maximum_transactions = MUSUBI_MAX_LOCATION_PROVIDERS_V1
            .checked_mul(usize::from(MUSUBI_MAX_PROVIDER_REGISTRATION_ATTEMPTS_V1))
            .expect("fixed provider checkpoint bounds fit usize");
        if self.generation != expected_generation
            || self.generation == 0
            || usize::from(self.generation) > MUSUBI_MAX_ARCHIVE_LOCATION_ATTEMPTS_V1
            || self.archive_id != request.archive_commitment.archive_id()
            || self
                .replication_order
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.provider_attestation_set_digest.is_zero()
            || self.set_sidecar_hash.iter().all(|byte| *byte == 0)
            || self.transactions.len() > maximum_transactions
        {
            return Err(PublicationError::InvalidJournal(
                "provider-registration checkpoint identity or bound is invalid".to_owned(),
            ));
        }
        let mut provider_attempts = BTreeMap::<ProviderId, (u8, u64)>::new();
        for transaction in &self.transactions {
            if transaction.key.validate().is_err()
                || transaction.key.archive_id != self.archive_id
                || transaction.key.replication_order != self.replication_order
                || transaction.attestation_digest.is_zero()
                || transaction.attempt == 0
                || transaction.attempt > MUSUBI_MAX_PROVIDER_REGISTRATION_ATTEMPTS_V1
                || transaction.transaction_hash.iter().all(|byte| *byte == 0)
                || transaction.sidecar_hash.iter().all(|byte| *byte == 0)
            {
                return Err(PublicationError::InvalidJournal(
                    "provider-registration transaction checkpoint is invalid".to_owned(),
                ));
            }
            match provider_attempts.get(&transaction.key.provider_id) {
                None if transaction.attempt == 1 => {}
                Some((prior_attempt, prior_revision))
                    if transaction.attempt == prior_attempt.saturating_add(1)
                        && transaction.expected_location_revision >= *prior_revision => {}
                _ => {
                    return Err(PublicationError::InvalidJournal(
                        "provider-registration attempts are not contiguous and monotonic"
                            .to_owned(),
                    ));
                }
            }
            provider_attempts.insert(
                transaction.key.provider_id,
                (transaction.attempt, transaction.expected_location_revision),
            );
        }
        Ok(())
    }
}
/// Result of checking provider registrations before a location transaction may be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationProviderRegistrationCheckpointAdvanceV1 {
    /// Every exact provider proof is finalized and all expected sidecars were revalidated.
    Ready,
    /// Persist this append-only compact anchor before any referenced transaction is submitted.
    Updated(PublicationProviderRegistrationCheckpointV1),
}
/// Exact signed compare-and-set transaction prepared for one archive-location generation.
///
/// This value is persisted before submission. A crash can therefore replay or inspect the exact
/// transaction instead of rebuilding a new mutation across an unjournaled phase cut.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveLocationIntentV1 {
    /// Stable publication operation that owns the location generation.
    pub operation_id: PublicationOperationIdV1,
    /// One-based contiguous generation number.
    pub generation: u8,
    /// Finalized complete archive/location page used to choose the CAS revision.
    pub prepared_page: MusubiArchiveLocationPageV1,
    /// Never-before-used stable location identity returned by the coordinator.
    pub location_id: MusubiArchiveLocationIdV1,
    /// Registry-grade pin manifest bound by the exact transaction.
    pub pin_manifest: ManifestDigest,
    /// Replication order bound by the exact transaction and provider-attestation set.
    pub replication_order: ReplicationOrderId,
    /// Digest of the sorted immutable provider-attestation records supplied to Core.
    pub provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1,
    /// Earliest renewal epoch selected by the coordinator.
    pub renew_after_epoch: u64,
    /// Expiry epoch selected by the coordinator.
    pub expires_at_epoch: u64,
    /// Exact archive location-set revision compared by Core.
    pub expected_location_revision: u64,
    /// Domain-separated digest of the canonical location instruction.
    pub instruction_digest: [u8; 32],
    /// Exact fee-quoted signed transaction, durably recorded before submission.
    pub signed_transaction: SignedTransaction,
    /// Canonical hash of `signed_transaction`.
    pub transaction_hash: [u8; 32],
}
impl PublicationArchiveLocationIntentV1 {
    /// Bind one exact signed transaction to its finalized preparation snapshot.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the fixed intent constructor consumes the prepared instruction and signed transaction as one immutable protocol step"
    )]
    pub fn new(
        operation_id: PublicationOperationIdV1,
        generation: u8,
        prepared_page: MusubiArchiveLocationPageV1,
        instruction: AddMusubiArchiveLocationV1,
        signed_transaction: SignedTransaction,
    ) -> Self {
        let transaction_hash = *signed_transaction.hash().as_ref();
        let instruction_digest = archive_location_instruction_digest(&instruction);
        Self {
            operation_id,
            generation,
            prepared_page,
            location_id: instruction.location_id,
            pin_manifest: instruction.pin_manifest,
            replication_order: instruction.replication_order,
            provider_attestation_set_digest: instruction.provider_attestation_set_digest,
            renew_after_epoch: instruction.renew_after_epoch,
            expires_at_epoch: instruction.expires_at_epoch,
            expected_location_revision: instruction.expected_location_revision,
            instruction_digest,
            signed_transaction,
            transaction_hash,
        }
    }
    /// Reconstruct the sole canonical instruction carried by this generation.
    #[must_use]
    pub fn instruction(&self) -> AddMusubiArchiveLocationV1 {
        AddMusubiArchiveLocationV1 {
            archive_id: self.prepared_page.archive.archive_id,
            location_id: self.location_id,
            pin_manifest: self.pin_manifest,
            replication_order: self.replication_order,
            provider_attestation_set_digest: self.provider_attestation_set_digest,
            renew_after_epoch: self.renew_after_epoch,
            expires_at_epoch: self.expires_at_epoch,
            expected_location_revision: self.expected_location_revision,
        }
    }
    pub(crate) fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<(), PublicationError> {
        validate_archive_location_page(request, registered, &self.prepared_page)?;
        let instruction = self.instruction();
        instruction
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ArchiveRegistration, error))?;
        let expected_instruction: InstructionBox = instruction.into();
        let exact_instruction = matches!(
            self.signed_transaction.instructions(),
            Executable::Instructions(instructions)
                if instructions.len() == 1
                    && instructions.iter().next() == Some(&expected_instruction)
        );
        let expected_generation = u8::try_from(prior_location_ids.len() + 1).ok();
        if self.operation_id != operation_id
            || Some(self.generation) != expected_generation
            || usize::from(self.generation) > MUSUBI_MAX_ARCHIVE_LOCATION_ATTEMPTS_V1
            || self.location_id.is_zero()
            || prior_location_ids.contains(&self.location_id)
            || prior_location_ids.iter().any(|location_id| {
                self.prepared_page
                    .archive
                    .location_ids
                    .binary_search(location_id)
                    .is_ok()
                    || self
                        .prepared_page
                        .items
                        .binary_search_by_key(location_id, |location| location.location_id)
                        .is_ok()
            })
            || self
                .prepared_page
                .archive
                .location_ids
                .binary_search(&self.location_id)
                .is_ok()
            || self.expected_location_revision != self.prepared_page.archive.location_revision
            || self.expected_location_revision == u64::MAX
            || self.instruction_digest != archive_location_instruction_digest(&self.instruction())
            || self.pin_manifest.as_bytes().iter().all(|byte| *byte == 0)
            || self
                .replication_order
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.renew_after_epoch >= self.expires_at_epoch
            || self.transaction_hash != *self.signed_transaction.hash().as_ref()
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || self.signed_transaction.network_id().copied() != Some(request.network_id())
            || self.signed_transaction.authority() != &request.publisher
            || self.signed_transaction.verify_signature().is_err()
            || !exact_instruction
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ArchiveRegistration,
                reason:
                    "archive-location intent, CAS revision, or signed transaction was substituted"
                        .to_owned(),
            });
        }
        Ok(())
    }
}
/// Finalized application evidence for one exact archive-location transaction.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveRegistrationV1 {
    /// Exact signed transaction that was journaled before submission.
    pub intent: PublicationArchiveLocationIntentV1,
    /// Authoritative block height at which that exact transaction was applied.
    pub applied_height: u64,
    /// Complete finalized current archive/location page at or after application.
    pub finalized_page: MusubiArchiveLocationPageV1,
}
impl PublicationArchiveRegistrationV1 {
    /// Return the stable location identity for this generation.
    #[must_use]
    pub const fn location_id(&self) -> MusubiArchiveLocationIdV1 {
        self.intent.location_id
    }
    /// Return the exact location from the finalized page.
    pub(crate) fn location(&self) -> Result<&MusubiArchiveLocationV1, PublicationError> {
        self.finalized_page
            .items
            .binary_search_by_key(&self.intent.location_id, |location| location.location_id)
            .ok()
            .map(|index| &self.finalized_page.items[index])
            .ok_or_else(|| {
                PublicationError::InvalidJournal(
                    "finalized archive-location generation is missing its location".to_owned(),
                )
            })
    }
    pub(crate) fn validate_polled_page(
        &self,
        request: &PublicationRequestV1,
        page: &MusubiArchiveLocationPageV1,
    ) -> Result<(), PublicationError> {
        page.validate()
            .map_err(|error| invalid(PublicationPhaseV1::Replication, error))?;
        let registered_location = self.location()?;
        let observed_location = page
            .items
            .binary_search_by_key(&self.intent.location_id, |location| location.location_id)
            .ok()
            .map(|index| &page.items[index]);
        let location_regressed = observed_location.is_some_and(|location| {
            !matches!(
                location_progress(registered_location, location),
                Ok(PublicationLocationProgressV1::Current)
            )
        });
        if page.network_id != request.network_id()
            || page.archive.registration_projection()
                != self.finalized_page.archive.registration_projection()
            || page.snapshot.finalized_height < self.finalized_page.snapshot.finalized_height
            || page.snapshot.index_revision < self.finalized_page.snapshot.index_revision
            || (page.snapshot.finalized_height == self.finalized_page.snapshot.finalized_height
                && page.snapshot != self.finalized_page.snapshot)
            || page.archive.location_revision < self.finalized_page.archive.location_revision
            || (page.snapshot == self.finalized_page.snapshot
                && (page.archive != self.finalized_page.archive
                    || page.items != self.finalized_page.items))
            || (page.archive.location_revision == self.finalized_page.archive.location_revision
                && (page.archive != self.finalized_page.archive
                    || page.items != self.finalized_page.items))
            || page.next_cursor.is_some()
            || page.items.len() != page.archive.location_ids.len()
            || page
                .items
                .iter()
                .zip(&page.archive.location_ids)
                .any(|(location, location_id)| {
                    location.location_id != *location_id
                        || location.archive_id != page.archive.archive_id
                        || location.finalized_height > page.snapshot.finalized_height
                        || location.state == MusubiArchiveLocationStateV1::Retired
                        || location.validate().is_err()
                })
            || location_regressed
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Replication,
                reason: "polled finalized archive-location page was incomplete or substituted"
                    .to_owned(),
            });
        }
        Ok(())
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<(), PublicationError> {
        self.intent
            .validate_for(operation_id, request, registered, prior_location_ids)?;
        validate_archive_location_page(request, registered, &self.finalized_page)?;
        let location = self.location()?;
        if self.applied_height <= self.intent.prepared_page.snapshot.finalized_height
            || self.applied_height > self.finalized_page.snapshot.finalized_height
            || self.finalized_page.snapshot.finalized_height
                < self.intent.prepared_page.snapshot.finalized_height
            || self.finalized_page.snapshot.index_revision
                < self.intent.prepared_page.snapshot.index_revision
            || (self.finalized_page.snapshot.finalized_height
                == self.intent.prepared_page.snapshot.finalized_height
                && self.finalized_page.snapshot != self.intent.prepared_page.snapshot)
            || self.finalized_page.archive.location_revision
                <= self.intent.expected_location_revision
            || location.revision <= self.intent.expected_location_revision
            || (location.revision == self.intent.expected_location_revision + 1
                && (location.finalized_height != self.applied_height
                    || location.state != MusubiArchiveLocationStateV1::Healthy
                    || location.pin_manifest != self.intent.pin_manifest
                    || location.replication_order != self.intent.replication_order
                    || location.provider_attestation_set_digest
                        != self.intent.provider_attestation_set_digest
                    || location.renew_after_epoch != self.intent.renew_after_epoch
                    || location.expires_at_epoch != self.intent.expires_at_epoch))
            || location.location_id != self.intent.location_id
            || location.archive_id != request.archive_commitment.archive_id()
            || location.finalized_height < self.applied_height
            || location.state == MusubiArchiveLocationStateV1::Retired
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ArchiveRegistration,
                reason: "archive-location application or finalized state was substituted"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
/// Why one exact archive-location generation can never become the active generation again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PublicationArchiveLocationTerminalReasonV1 {
    /// The exact CAS transaction was finalized rejected after another location mutation rebased it.
    #[codec(index = 0)]
    RejectedRebase {
        /// Finalized rejection height.
        block_height: u64,
    },
    /// The exact signed transaction expired without application.
    #[codec(index = 1)]
    RegistryExpired {
        /// Finalized height when one was supplied by the authoritative status record.
        block_height: Option<u64>,
    },
    /// The exact transaction applied, then the stable identity was retired before recovery.
    #[codec(index = 2)]
    AppliedThenRetired {
        /// Authoritative application height for the exact signed transaction.
        applied_height: u64,
    },
    /// A previously finalized active generation was later retired.
    #[codec(index = 3)]
    Retired,
}
/// Durable finalized floor against which one archive-location terminal was accepted.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[allow(
    clippy::large_enum_variant,
    reason = "the stable journal enum retains exact finalized replication evidence inline for deterministic recovery"
)]
pub enum PublicationArchiveLocationTerminalFloorV1 {
    /// The transaction never acquired finalized application evidence; use its prepared page.
    #[codec(index = 0)]
    Prepared,
    /// No healthy replication checkpoint existed; use the finalized application page.
    #[codec(index = 1)]
    Registered,
    /// A later healthy full-directory checkpoint existed and is retained exactly.
    #[codec(index = 2)]
    Replication(PublicationReplicationCheckpointV1),
}
/// Finalized full-directory evidence terminating one archive-location generation.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveLocationTerminalV1 {
    /// Exact signed transaction identity owned by the generation.
    pub transaction_hash: [u8; 32],
    /// Authoritative reason this generation cannot be retried.
    pub reason: PublicationArchiveLocationTerminalReasonV1,
    /// Complete finalized directory proving the generation's identity is absent.
    pub finalized_page: MusubiArchiveLocationPageV1,
}
impl PublicationArchiveLocationTerminalV1 {
    #[allow(
        clippy::too_many_lines,
        reason = "the terminal validator keeps all finalized-floor, absence, and retirement invariants in one security-sensitive state check"
    )]
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered_archive: &PublicationRegisteredArchiveV1,
        attempt: &PublicationArchiveLocationAttemptV1,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
        floor: &PublicationArchiveLocationTerminalFloorV1,
    ) -> Result<(), PublicationError> {
        attempt.intent.validate_for(
            operation_id,
            request,
            registered_archive,
            prior_location_ids,
        )?;
        validate_archive_location_page(request, registered_archive, &self.finalized_page)?;
        let floor_page = match (floor, attempt.registration.as_ref()) {
            (PublicationArchiveLocationTerminalFloorV1::Prepared, None) => {
                &attempt.intent.prepared_page
            }
            (PublicationArchiveLocationTerminalFloorV1::Registered, Some(registration)) => {
                &registration.finalized_page
            }
            (
                PublicationArchiveLocationTerminalFloorV1::Replication(checkpoint),
                Some(registration),
            ) => {
                checkpoint.validate_for(request, registration)?;
                &checkpoint.finalized_page
            }
            _ => {
                return Err(PublicationError::InvalidEvidence {
                    phase: PublicationPhaseV1::Replication,
                    reason: "archive-location terminal used an invalid durable floor".to_owned(),
                });
            }
        };
        let requires_strict_revision = !matches!(
            self.reason,
            PublicationArchiveLocationTerminalReasonV1::RegistryExpired { .. }
        );
        if finalized_page_progress(floor_page, &self.finalized_page)?
            != PublicationLocationProgressV1::Current
            || (requires_strict_revision
                && self.finalized_page.archive.location_revision
                    <= floor_page.archive.location_revision)
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Replication,
                reason: "archive-location terminal regressed its durable finalized floor"
                    .to_owned(),
            });
        }
        let absent = self
            .finalized_page
            .archive
            .location_ids
            .binary_search(&attempt.intent.location_id)
            .is_err()
            && self
                .finalized_page
                .items
                .binary_search_by_key(&attempt.intent.location_id, |location| location.location_id)
                .is_err();
        let reason_is_valid = match self.reason {
            PublicationArchiveLocationTerminalReasonV1::RejectedRebase { block_height } => {
                attempt.registration.is_none()
                    && block_height > attempt.intent.prepared_page.snapshot.finalized_height
                    && block_height <= self.finalized_page.snapshot.finalized_height
                    && self.finalized_page.archive.location_revision
                        > attempt.intent.expected_location_revision
            }
            PublicationArchiveLocationTerminalReasonV1::RegistryExpired { block_height } => {
                attempt.registration.is_none()
                    && block_height.is_none_or(|height| {
                        height > attempt.intent.prepared_page.snapshot.finalized_height
                            && height <= self.finalized_page.snapshot.finalized_height
                    })
                    && self.finalized_page.archive.location_revision
                        >= attempt.intent.expected_location_revision
            }
            PublicationArchiveLocationTerminalReasonV1::AppliedThenRetired { applied_height } => {
                attempt.registration.is_none()
                    && applied_height > attempt.intent.prepared_page.snapshot.finalized_height
                    && applied_height <= self.finalized_page.snapshot.finalized_height
                    && self.finalized_page.archive.location_revision
                        > attempt.intent.expected_location_revision.saturating_add(1)
            }
            PublicationArchiveLocationTerminalReasonV1::Retired => {
                attempt.registration.as_ref().is_some_and(|registration| {
                    self.finalized_page.snapshot.finalized_height
                        > registration.finalized_page.snapshot.finalized_height
                        && self.finalized_page.snapshot.index_revision
                            >= registration.finalized_page.snapshot.index_revision
                        && self.finalized_page.archive.location_revision
                            > registration.finalized_page.archive.location_revision
                })
            }
        };
        if self.transaction_hash != attempt.intent.transaction_hash
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || self.finalized_page.snapshot.finalized_height
                < attempt.intent.prepared_page.snapshot.finalized_height
            || self.finalized_page.snapshot.index_revision
                < attempt.intent.prepared_page.snapshot.index_revision
            || (self.finalized_page.snapshot.finalized_height
                == attempt.intent.prepared_page.snapshot.finalized_height
                && self.finalized_page.snapshot != attempt.intent.prepared_page.snapshot)
            || (self.finalized_page.snapshot == attempt.intent.prepared_page.snapshot
                && (self.finalized_page.archive != attempt.intent.prepared_page.archive
                    || self.finalized_page.items != attempt.intent.prepared_page.items))
            || (self.finalized_page.archive.location_revision
                == attempt.intent.prepared_page.archive.location_revision
                && (self.finalized_page.archive != attempt.intent.prepared_page.archive
                    || self.finalized_page.items != attempt.intent.prepared_page.items))
            || !absent
            || !reason_is_valid
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Replication,
                reason: "archive-location terminal or retirement evidence was substituted"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
/// One bounded append-only archive-location transaction generation.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationArchiveLocationAttemptV1 {
    /// One-based contiguous generation number.
    pub generation: u8,
    /// Exact signed transaction persisted before its first submission.
    pub intent: PublicationArchiveLocationIntentV1,
    /// Finalized application evidence, appended after the transaction applies.
    pub registration: Option<PublicationArchiveRegistrationV1>,
    /// Finalized terminal evidence, appended before a later generation is allowed.
    pub terminal: Option<PublicationArchiveLocationTerminalV1>,
    /// Finalized floor against which `terminal` was accepted, retained for journal recovery.
    pub terminal_floor: Option<PublicationArchiveLocationTerminalFloorV1>,
}
impl PublicationArchiveLocationAttemptV1 {
    fn new(generation: u8, intent: PublicationArchiveLocationIntentV1) -> Self {
        Self {
            generation,
            intent,
            registration: None,
            terminal: None,
            terminal_floor: None,
        }
    }
}
/// Result of submitting or recovering one exact archive-location transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed advance protocol returns complete finalized location evidence without changing its stable API"
)]
pub enum PublicationArchiveLocationAdvanceV1 {
    /// The exact transaction remains pending or not yet authoritatively terminal.
    Pending,
    /// The exact transaction and current same-ID location are finalized.
    Registered(PublicationArchiveRegistrationV1),
    /// The exact transaction is terminal and the complete finalized directory excludes its ID.
    Terminal(PublicationArchiveLocationTerminalV1),
}
/// Result of polling the current finalized state of the active location generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationReplicationAdvanceV1 {
    /// The location exists but is not currently healthy at quorum, or the query is not yet current.
    Pending,
    /// Current finalized healthy location and the complete directory snapshot that authenticated it.
    Healthy(PublicationReplicationCheckpointV1),
    /// Complete finalized proof that the stable location identity was retired.
    Retired(PublicationArchiveLocationTerminalV1),
}
/// Durable finalized replication floor for one active archive-location generation.
///
/// Retaining the complete directory page prevents a later lagging absence response from being
/// mistaken for retirement after the target location or another directory entry has advanced.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReplicationCheckpointV1 {
    /// Complete finalized archive-location directory containing the active healthy location.
    pub finalized_page: MusubiArchiveLocationPageV1,
}
impl PublicationReplicationCheckpointV1 {
    /// Return the active generation's exact location from this finalized page.
    pub(crate) fn location(
        &self,
        registration: &PublicationArchiveRegistrationV1,
    ) -> Result<&MusubiArchiveLocationV1, PublicationError> {
        self.finalized_page
            .items
            .binary_search_by_key(&registration.location_id(), |location| location.location_id)
            .ok()
            .map(|index| &self.finalized_page.items[index])
            .ok_or_else(|| PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Replication,
                reason: "finalized replication checkpoint is missing its active location"
                    .to_owned(),
            })
    }
    pub(crate) fn validate_for(
        &self,
        request: &PublicationRequestV1,
        registration: &PublicationArchiveRegistrationV1,
    ) -> Result<(), PublicationError> {
        self.finalized_page
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::Replication, error))?;
        registration.validate_polled_page(request, &self.finalized_page)?;
        validate_replication(request, registration, self.location(registration)?)
    }
}
pub(crate) fn validate_archive_location_page(
    request: &PublicationRequestV1,
    registered: &PublicationRegisteredArchiveV1,
    page: &MusubiArchiveLocationPageV1,
) -> Result<(), PublicationError> {
    page.validate()
        .map_err(|error| invalid(PublicationPhaseV1::ArchiveRegistration, error))?;
    if page.network_id != request.network_id()
        || page.archive.registration_projection() != registered.archive.registration_projection()
        || page.snapshot.finalized_height < registered.snapshot.finalized_height
        || page.snapshot.index_revision < registered.snapshot.index_revision
        || (page.snapshot.finalized_height == registered.snapshot.finalized_height
            && page.snapshot != registered.snapshot)
        || page.archive.location_revision < registered.archive.location_revision
        || (page.snapshot == registered.snapshot && page.archive != registered.archive)
        || page.next_cursor.is_some()
        || page.items.len() != page.archive.location_ids.len()
        || page
            .items
            .iter()
            .zip(&page.archive.location_ids)
            .any(|(location, location_id)| {
                location.location_id != *location_id
                    || location.archive_id != page.archive.archive_id
                    || location.finalized_height > page.snapshot.finalized_height
                    || location.state == MusubiArchiveLocationStateV1::Retired
                    || location.validate().is_err()
            })
    {
        return Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::ArchiveRegistration,
            reason: "finalized archive-location page was incomplete or substituted".to_owned(),
        });
    }
    Ok(())
}
/// Exact public evidence returned after one provider readback.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReadbackEvidenceV1 {
    /// Provider through which the complete archive was read back.
    pub provider: ProviderId,
    /// Finalized location used for the readback.
    pub location_id: MusubiArchiveLocationIdV1,
    /// Replication order whose completion authorized this provider.
    pub replication_order: ReplicationOrderId,
    /// Exact commitment reproduced by parsing and verifying the returned CAR.
    pub commitment: MusubiArchiveCommitmentV1,
    /// Semantic release digest parsed from the returned canonical bundle.
    pub semantic_release_digest: MusubiSemanticReleaseDigestV1,
    /// Verification-lock digest parsed from the returned canonical bundle.
    pub verification_lock_digest: MusubiVerificationLockDigestV1,
}
impl PublicationReadbackEvidenceV1 {
    fn validate_for(
        &self,
        request: &PublicationRequestV1,
        location: &MusubiArchiveLocationV1,
        expected_provider: ProviderId,
    ) -> Result<(), PublicationError> {
        if self.provider != expected_provider
            || self.location_id != location.location_id
            || self.replication_order != location.replication_order
            || self.commitment != request.archive_commitment
            || self.semantic_release_digest != request.publication.manifest.semantic_digest()
            || self.verification_lock_digest
                != request.publication.manifest.verification_lock_digest
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::Readback,
                reason: "provider readback evidence was substituted".to_owned(),
            });
        }
        Ok(())
    }
}
fn validate_readback_subset(
    request: &PublicationRequestV1,
    location: &MusubiArchiveLocationV1,
    readbacks: &[PublicationReadbackEvidenceV1],
) -> Result<(), PublicationError> {
    let is_strictly_ordered = readbacks
        .windows(2)
        .all(|pair| pair[0].provider < pair[1].provider);
    let all_are_location_providers = readbacks
        .iter()
        .all(|readback| location.providers.binary_search(&readback.provider).is_ok());
    if readbacks.len() != 2 || !is_strictly_ordered || !all_are_location_providers {
        return Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::Readback,
            reason:
                "provider readbacks were not a strictly ordered distinct location-provider subset"
                    .to_owned(),
        });
    }
    for readback in readbacks {
        readback.validate_for(request, location, readback.provider)?;
    }
    Ok(())
}
/// Finalized replication and readback floor that authorized one release signature.
///
/// The floor is retained inside each attempt rather than inferred from the journal head. A
/// location retirement can therefore move the workflow back to replication without erasing the
/// exact storage evidence under which an earlier, potentially submitted transaction was signed.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReleasePreparationFloorV1 {
    /// One-based archive-location generation that produced the selected location.
    pub location_generation: u8,
    /// Exact healthy location selected from `replication`.
    pub location_id: MusubiArchiveLocationIdV1,
    /// Complete finalized healthy-location directory used before signing.
    pub replication: PublicationReplicationCheckpointV1,
    /// Exact two-provider readbacks used before signing.
    pub readbacks: Vec<PublicationReadbackEvidenceV1>,
}
impl PublicationReleasePreparationFloorV1 {
    /// Construct and validate an independently auditable release-preparation floor.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence when the replication checkpoint, selected location generation, or
    /// two provider readbacks do not match the immutable publication request.
    pub fn try_new(
        location_generation: u8,
        replication: PublicationReplicationCheckpointV1,
        readbacks: Vec<PublicationReadbackEvidenceV1>,
        request: &PublicationRequestV1,
        registration: &PublicationArchiveRegistrationV1,
    ) -> Result<Self, PublicationError> {
        let floor = Self {
            location_generation,
            location_id: registration.location_id(),
            replication,
            readbacks,
        };
        floor.validate_for(request)?;
        floor.validate_for_registration(request, registration)?;
        Ok(floor)
    }
    fn validate_for(&self, request: &PublicationRequestV1) -> Result<(), PublicationError> {
        let page = &self.replication.finalized_page;
        page.validate()
            .map_err(|error| invalid(PublicationPhaseV1::ReleaseSubmission, error))?;
        let location = page
            .items
            .binary_search_by_key(&self.location_id, |location| location.location_id)
            .ok()
            .map(|index| &page.items[index]);
        let exact_archive = page.archive.archive_id == request.archive_commitment.archive_id()
            && page.archive.commitment == request.archive_commitment
            && page.archive.registered_by == request.publisher
            && page
                .archive
                .staging_receipt
                .verify(
                    &request.receipt_binding(),
                    page.archive.staging_receipt.payload.issued_at_ms,
                )
                .is_ok();
        if page.network_id != request.network_id()
            || !exact_archive
            || page.next_cursor.is_some()
            || page.items.len() != page.archive.location_ids.len()
            || self.readbacks.len() != 2
            || location.is_none()
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "release preparation floor was incomplete or substituted".to_owned(),
            });
        }
        let location = location.expect("checked above");
        if location.state != MusubiArchiveLocationStateV1::Healthy
            || location.providers.len() < usize::from(MUSUBI_MIN_HEALTHY_REPLICAS_V1)
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "release preparation floor was not healthy at replication quorum"
                    .to_owned(),
            });
        }
        validate_readback_subset(request, location, &self.readbacks)
    }
    fn location(&self) -> Option<&MusubiArchiveLocationV1> {
        self.replication
            .finalized_page
            .items
            .binary_search_by_key(&self.location_id, |location| location.location_id)
            .ok()
            .map(|index| &self.replication.finalized_page.items[index])
    }
    fn validate_for_registration(
        &self,
        request: &PublicationRequestV1,
        registration: &PublicationArchiveRegistrationV1,
    ) -> Result<(), PublicationError> {
        if self.location_generation == 0
            || self.location_generation != registration.intent.generation
            || self.location_id != registration.location_id()
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "release preparation floor names a different location generation"
                    .to_owned(),
            });
        }
        self.replication.validate_for(request, registration)?;
        let location = self.replication.location(registration)?;
        validate_readback_subset(request, location, &self.readbacks)
    }
}
/// Compact, reconstructable authorization envelope for an exact release transaction.
///
/// Immutable request fields and the sole publish instruction are deliberately not duplicated.
/// Metadata is always empty and proof attachments are always absent in V1.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationReleaseSignedEnvelopeV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReleaseSignedEnvelopeV1 {
    /// Exact signature-bound creation time in Unix milliseconds.
    pub creation_time_ms: u64,
    /// Exact non-zero signature-bound transaction lifetime in milliseconds.
    pub time_to_live_ms: NonZeroU64,
    /// Optional exact signature-bound transaction nonce.
    pub nonce: Option<NonZeroU32>,
    /// Exact fee payer and charge bounds accepted by the signer.
    pub fee_payment: FeePaymentIntent,
    /// Primary transaction signature retained byte-for-byte.
    pub signature: TransactionSignature,
    /// Complete canonical multisig proof bundle, when the publisher is multisig.
    pub multisig_signatures: Option<MultisigSignatures>,
}
impl PublicationReleaseSignedEnvelopeV1 {
    /// Extract a compact envelope only from the exact canonical V1 release transaction shape.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence when the transaction shape is not the fixed release protocol or
    /// the compact envelope cannot reconstruct its exact signed bytes.
    pub fn try_from_signed_transaction(
        request: &PublicationRequestV1,
        signed_transaction: &SignedTransaction,
    ) -> Result<Self, PublicationError> {
        validate_release_signed_transaction_shape(request, signed_transaction)?;
        let payload = signed_transaction.payload();
        let envelope = Self {
            creation_time_ms: payload.creation_time_ms,
            time_to_live_ms: payload
                .time_to_live_ms
                .expect("release transaction shape requires a non-zero lifetime"),
            nonce: payload.nonce,
            fee_payment: payload.fee_payment.clone(),
            signature: signed_transaction.signature().clone(),
            multisig_signatures: signed_transaction.multisig_signatures().cloned(),
        };
        let reconstructed = envelope.reconstruct_signed_transaction(request)?;
        if &reconstructed != signed_transaction
            || release_signed_transaction_wire_v1(&reconstructed)?
                != release_signed_transaction_wire_v1(signed_transaction)?
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "compact release envelope did not reconstruct the exact signed transaction"
                    .to_owned(),
            });
        }
        Ok(envelope)
    }
    /// Reconstruct and validate the sole exact signed release transaction.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence when the compact payload, multisig bundle, or signature cannot
    /// reconstruct the fixed release transaction shape.
    pub fn reconstruct_signed_transaction(
        &self,
        request: &PublicationRequestV1,
    ) -> Result<SignedTransaction, PublicationError> {
        let payload = TransactionPayload {
            domain: iroha_data_model::transaction::TransactionDomain::Network(request.network_id()),
            authority: request.publisher.clone(),
            creation_time_ms: self.creation_time_ms,
            instructions: vec![InstructionBox::from(request.publish_instruction())].into(),
            time_to_live_ms: Some(self.time_to_live_ms),
            nonce: self.nonce,
            fee_payment: self.fee_payment.clone(),
            metadata: Metadata::default(),
            attachments: None,
        };
        let mut builder = TransactionBuilder::from_payload(payload).map_err(|error| {
            PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: format!("compact release envelope has an invalid payload: {error}"),
            }
        })?;
        if let Some(multisig_signatures) = &self.multisig_signatures {
            builder = builder.with_multisig_signatures(multisig_signatures.clone());
        }
        let signed_transaction = builder.build_with_signature(self.signature.payload().clone());
        validate_release_signed_transaction_shape(request, &signed_transaction)?;
        Ok(signed_transaction)
    }
}
/// Durable compact intent for one exact fee-quoted release transaction.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationReleaseSubmissionIntentV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReleaseSubmissionIntentV1 {
    /// Stable publication operation that owns this intent.
    pub operation_id: PublicationOperationIdV1,
    /// Exact finalized replication and two-provider readback floor used before signing.
    pub preparation: PublicationReleasePreparationFloorV1,
    /// Domain-separated digest of the sole [`PublishMusubiReleaseV1`] instruction.
    pub instruction_digest: [u8; 32],
    /// Local replay-integrity digest of the complete fixed-V1 signed transaction wire bytes.
    ///
    /// Authoritative transaction status is keyed by `transaction_hash` and does not attest
    /// this authorization-inclusive digest.
    // TODO: Bind this digest to authoritative committed-wire evidence when Torii exposes it.
    pub signed_transaction_digest: [u8; 32],
    /// Iroha transaction identity, which intentionally excludes authorization proofs.
    pub transaction_hash: [u8; 32],
    /// Minimal fields needed to reconstruct the exact signed transaction.
    pub envelope: PublicationReleaseSignedEnvelopeV1,
}
impl PublicationReleaseSubmissionIntentV1 {
    /// Extract, reconstruct, and bind one exact signed transaction before any submission.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence when the preparation floor or signed transaction is malformed,
    /// substituted, or exceeds the fixed release-intent budget.
    pub fn try_new(
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        preparation: PublicationReleasePreparationFloorV1,
        signed_transaction: &SignedTransaction,
    ) -> Result<Self, PublicationError> {
        preparation.validate_for(request)?;
        let envelope = PublicationReleaseSignedEnvelopeV1::try_from_signed_transaction(
            request,
            signed_transaction,
        )?;
        let wire = release_signed_transaction_wire_v1(signed_transaction)?;
        let intent = Self {
            operation_id,
            preparation,
            instruction_digest: domain_hash(
                PUBLISH_INSTRUCTION_DOMAIN,
                &request.publish_instruction().encode(),
            ),
            signed_transaction_digest: domain_hash(RELEASE_SIGNED_TRANSACTION_DOMAIN, &wire),
            transaction_hash: *signed_transaction.hash().as_ref(),
            envelope,
        };
        intent.validate_for(operation_id, request)?;
        Ok(intent)
    }
    /// Reconstruct and validate the complete transaction represented by this compact intent.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence when the compact envelope, instruction digest, signed-wire
    /// digest, transaction hash, or operation binding differs.
    pub fn reconstruct_signed_transaction(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
    ) -> Result<SignedTransaction, PublicationError> {
        self.preparation.validate_for(request)?;
        let signed_transaction = self.envelope.reconstruct_signed_transaction(request)?;
        let wire = release_signed_transaction_wire_v1(&signed_transaction)?;
        if self.operation_id != operation_id
            || self.instruction_digest
                != domain_hash(
                    PUBLISH_INSTRUCTION_DOMAIN,
                    &request.publish_instruction().encode(),
                )
            || self.signed_transaction_digest
                != domain_hash(RELEASE_SIGNED_TRANSACTION_DOMAIN, &wire)
            || self.signed_transaction_digest.iter().all(|byte| *byte == 0)
            || self.transaction_hash != *signed_transaction.hash().as_ref()
            || self.transaction_hash.iter().all(|byte| *byte == 0)
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "compact release submission intent was substituted".to_owned(),
            });
        }
        Ok(signed_transaction)
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
    ) -> Result<(), PublicationError> {
        ensure_release_component_budget(
            self,
            MAX_RELEASE_INTENT_CANONICAL_BYTES,
            "release submission intent",
            PublicationPhaseV1::ReleaseSubmission,
        )?;
        self.reconstruct_signed_transaction(operation_id, request)
            .map(|_| ())
    }
}
/// Synchronized finalized proof that the exact release was absent at one consensus time.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReleaseAbsenceEvidenceV1 {
    /// Complete empty universal resolver page for the exact package and `=VERSION` requirement.
    pub resolver_page: MusubiResolverIndexPageV1,
    /// Exact archive-retention request pinned to `resolver_page.snapshot`.
    pub retention_query: MusubiArchiveRetentionQueryV1,
    /// Complete same-snapshot retention response and consensus-committed block time.
    pub retention_page: MusubiArchiveRetentionPageV1,
}
impl PublicationReleaseAbsenceEvidenceV1 {
    pub(crate) fn validate_for(
        &self,
        request: &PublicationRequestV1,
    ) -> Result<(), PublicationError> {
        self.resolver_page
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ReleaseSubmission, error))?;
        self.retention_query
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ReleaseSubmission, error))?;
        self.retention_page
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::ReleaseSubmission, error))?;
        let exact_requirement = MusubiVersionReqV1::from_str(&format!(
            "={}",
            request.publication.manifest.release.version
        ))
        .map_err(|error| invalid(PublicationPhaseV1::ReleaseSubmission, error))?;
        let exact_retention_query = MusubiArchiveRetentionQueryV1 {
            archive_ids: vec![request.archive_commitment.archive_id()],
            expected_snapshot: Some(self.resolver_page.snapshot),
        };
        let [retention] = self.retention_page.items.as_slice() else {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "finalized exact-release absence evidence had a partial retention page"
                    .to_owned(),
            });
        };
        if self.resolver_page.network_id != request.network_id()
            || self.resolver_page.query.package != request.publication.manifest.release.package
            || self.resolver_page.query.requirement.as_ref() != Some(&exact_requirement)
            || self.resolver_page.query.page.cursor.is_some()
            || !self.resolver_page.items.is_empty()
            || self.resolver_page.next_cursor.is_some()
            || self.retention_query != exact_retention_query
            || self.retention_page.network_id != request.network_id()
            || self.retention_page.snapshot != self.resolver_page.snapshot
            || self.retention_page.finalized_time_ms == 0
            || retention.archive_id != request.archive_commitment.archive_id()
            || retention.disposition == MusubiArchiveRetentionDispositionV1::RetainUnknown
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "finalized exact-release absence evidence was substituted".to_owned(),
            });
        }
        Ok(())
    }
    fn snapshot(&self) -> MusubiRegistrySnapshotV1 {
        self.resolver_page.snapshot
    }
    fn finalized_time_ms(&self) -> u64 {
        self.retention_page.finalized_time_ms
    }
}
/// Authoritative terminal classification for one exact release transaction generation.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PublicationReleaseSubmissionTerminalReasonV1 {
    /// The exact transaction reached an authoritative finalized expired status.
    #[codec(index = 0)]
    RegistryExpired {
        /// Finalized block supplied by the authoritative status record.
        block_height: u64,
        /// Same-or-later synchronized finalized exact-release absence.
        absence: PublicationReleaseAbsenceEvidenceV1,
    },
    /// Consensus time passed the signature-bound deadline while the exact release stayed absent.
    #[codec(index = 1)]
    FinalizedValidityWindowElapsed {
        /// Synchronized exact-release absence and consensus-time evidence.
        absence: PublicationReleaseAbsenceEvidenceV1,
    },
    /// Core finalized a deterministic rejection while the exact release stayed absent.
    #[codec(index = 2)]
    RegistryRejected {
        /// Finalized rejection height.
        block_height: u64,
        /// Same-or-later synchronized finalized exact-release absence.
        absence: PublicationReleaseAbsenceEvidenceV1,
    },
}
/// Terminal evidence appended before a successor release signature may be persisted.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationReleaseSubmissionTerminalV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReleaseSubmissionTerminalV1 {
    /// Iroha transaction identity of the exact terminal attempt.
    pub transaction_hash: [u8; 32],
    /// Full signed-wire digest, including every authorization proof byte.
    pub signed_transaction_digest: [u8; 32],
    /// Authoritative terminal classification.
    pub reason: PublicationReleaseSubmissionTerminalReasonV1,
}
impl PublicationReleaseSubmissionTerminalV1 {
    /// Bind an authoritative expired status to one exact compact intent.
    #[must_use]
    pub fn registry_expired(
        intent: &PublicationReleaseSubmissionIntentV1,
        block_height: u64,
        absence: PublicationReleaseAbsenceEvidenceV1,
    ) -> Self {
        Self {
            transaction_hash: intent.transaction_hash,
            signed_transaction_digest: intent.signed_transaction_digest,
            reason: PublicationReleaseSubmissionTerminalReasonV1::RegistryExpired {
                block_height,
                absence,
            },
        }
    }
    /// Bind finalized consensus-time expiry and exact-release absence to one intent.
    #[must_use]
    pub fn finalized_validity_window_elapsed(
        intent: &PublicationReleaseSubmissionIntentV1,
        absence: PublicationReleaseAbsenceEvidenceV1,
    ) -> Self {
        Self {
            transaction_hash: intent.transaction_hash,
            signed_transaction_digest: intent.signed_transaction_digest,
            reason: PublicationReleaseSubmissionTerminalReasonV1::FinalizedValidityWindowElapsed {
                absence,
            },
        }
    }
    /// Bind an authoritative finalized rejection to one exact compact intent.
    #[must_use]
    pub fn registry_rejected(
        intent: &PublicationReleaseSubmissionIntentV1,
        block_height: u64,
        absence: PublicationReleaseAbsenceEvidenceV1,
    ) -> Self {
        Self {
            transaction_hash: intent.transaction_hash,
            signed_transaction_digest: intent.signed_transaction_digest,
            reason: PublicationReleaseSubmissionTerminalReasonV1::RegistryRejected {
                block_height,
                absence,
            },
        }
    }
    fn validate_for(
        &self,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
    ) -> Result<(), PublicationError> {
        ensure_release_component_budget(
            self,
            MAX_RELEASE_OUTCOME_CANONICAL_BYTES,
            "release terminal evidence",
            PublicationPhaseV1::ReleaseSubmission,
        )?;
        let preparation_height = intent
            .preparation
            .replication
            .finalized_page
            .snapshot
            .finalized_height;
        let preparation_index_revision = intent
            .preparation
            .replication
            .finalized_page
            .snapshot
            .index_revision;
        let reason_is_valid = match &self.reason {
            PublicationReleaseSubmissionTerminalReasonV1::RegistryExpired {
                block_height,
                absence,
            }
            | PublicationReleaseSubmissionTerminalReasonV1::RegistryRejected {
                block_height,
                absence,
            } => {
                absence.validate_for(request)?;
                *block_height > preparation_height
                    && absence.snapshot().finalized_height >= *block_height
            }
            PublicationReleaseSubmissionTerminalReasonV1::FinalizedValidityWindowElapsed {
                absence,
            } => {
                absence.validate_for(request)?;
                absence.snapshot().finalized_height > preparation_height
                    && release_submission_valid_until_ms(intent)
                        .is_some_and(|deadline| absence.finalized_time_ms() > deadline)
            }
        };
        if self.transaction_hash != intent.transaction_hash
            || self.signed_transaction_digest != intent.signed_transaction_digest
            || self.absence().snapshot().index_revision < preparation_index_revision
            || !reason_is_valid
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "release submission terminal evidence was substituted".to_owned(),
            });
        }
        Ok(())
    }
    fn absence(&self) -> &PublicationReleaseAbsenceEvidenceV1 {
        match &self.reason {
            PublicationReleaseSubmissionTerminalReasonV1::RegistryExpired { absence, .. }
            | PublicationReleaseSubmissionTerminalReasonV1::FinalizedValidityWindowElapsed {
                absence,
            }
            | PublicationReleaseSubmissionTerminalReasonV1::RegistryRejected { absence, .. } => {
                absence
            }
        }
    }
}
/// Append-only authoritative outcome of one exact release transaction generation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationReleaseSubmissionOutcomeV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[allow(
    clippy::large_enum_variant,
    reason = "the stable wire enum retains complete applied or terminal evidence inline for deterministic journal recovery"
)]
pub enum PublicationReleaseSubmissionOutcomeV1 {
    /// The journaled payload transaction was finalized applied through Native AMX.
    #[codec(index = 0)]
    Applied {
        /// Existing application evidence retained for final verification.
        submission: PublicationAmxSubmissionV1,
        /// Local signed-wire replay binding retained alongside payload application evidence.
        signed_transaction_digest: [u8; 32],
    },
    /// The exact transaction became provably terminal without application.
    #[codec(index = 1)]
    Terminal(PublicationReleaseSubmissionTerminalV1),
}
/// Authoritative payload progress for one already-journaled release transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed backend advance API returns complete authoritative evidence without heap indirection"
)]
pub enum PublicationReleaseSubmissionAdvanceV1 {
    /// The payload transaction is absent, live, pending, or not yet authoritatively resolved.
    Pending,
    /// The payload transaction was finalized as applied through Native AMX.
    Applied(PublicationAmxSubmissionV1),
    /// The exact transaction is terminal and synchronized exact-release absence was proven.
    Terminal(PublicationReleaseSubmissionTerminalV1),
}
impl PublicationReleaseSubmissionOutcomeV1 {
    /// Retain finalized payload application evidence with the intent's local wire binding.
    #[must_use]
    pub fn applied(
        intent: &PublicationReleaseSubmissionIntentV1,
        submission: PublicationAmxSubmissionV1,
    ) -> Self {
        Self::Applied {
            submission,
            signed_transaction_digest: intent.signed_transaction_digest,
        }
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
    ) -> Result<(), PublicationError> {
        match self {
            Self::Applied {
                submission,
                signed_transaction_digest,
            } => {
                submission.validate_for(operation_id, &request.publish_instruction())?;
                if submission.transaction_hash != intent.transaction_hash
                    || *signed_transaction_digest != intent.signed_transaction_digest
                    || submission.applied_height
                        <= intent
                            .preparation
                            .replication
                            .finalized_page
                            .snapshot
                            .finalized_height
                {
                    return Err(PublicationError::InvalidEvidence {
                        phase: PublicationPhaseV1::ReleaseSubmission,
                        reason: "applied release outcome names a different compact intent"
                            .to_owned(),
                    });
                }
                Ok(())
            }
            Self::Terminal(terminal) => terminal.validate_for(request, intent),
        }
    }
}
/// One bounded append-only release transaction generation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationReleaseSubmissionAttemptV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationReleaseSubmissionAttemptV1 {
    /// One-based contiguous generation number.
    pub generation: u8,
    /// Exact compact signed transaction and the storage floor that authorized it.
    pub intent: PublicationReleaseSubmissionIntentV1,
    /// Applied or terminal evidence appended before any later journal transition.
    pub outcome: Option<PublicationReleaseSubmissionOutcomeV1>,
}
impl PublicationReleaseSubmissionAttemptV1 {
    /// Construct a live release generation that has not acquired terminal evidence.
    #[must_use]
    pub fn new(generation: u8, intent: PublicationReleaseSubmissionIntentV1) -> Self {
        Self {
            generation,
            intent,
            outcome: None,
        }
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
    ) -> Result<(), PublicationError> {
        ensure_release_component_budget(
            self,
            MAX_RELEASE_ATTEMPT_CANONICAL_BYTES,
            "release submission attempt",
            PublicationPhaseV1::ReleaseSubmission,
        )?;
        self.intent.validate_for(operation_id, request)?;
        if let Some(outcome) = &self.outcome {
            ensure_release_component_budget(
                outcome,
                MAX_RELEASE_OUTCOME_CANONICAL_BYTES,
                "release submission outcome",
                PublicationPhaseV1::ReleaseSubmission,
            )?;
            outcome.validate_for(operation_id, request, &self.intent)?;
        }
        Ok(())
    }
}
/// Return the signature-bound validity deadline for one release intent.
pub(crate) fn release_submission_valid_until_ms(
    intent: &PublicationReleaseSubmissionIntentV1,
) -> Option<u64> {
    intent
        .envelope
        .creation_time_ms
        .checked_add(intent.envelope.time_to_live_ms.get())
}
fn validate_release_signed_transaction_shape(
    request: &PublicationRequestV1,
    signed_transaction: &SignedTransaction,
) -> Result<(), PublicationError> {
    let expected_instruction = InstructionBox::from(request.publish_instruction());
    let exact_instruction = matches!(
        signed_transaction.instructions(),
        Executable::Instructions(instructions)
            if instructions.len() == 1
                && instructions.iter().next() == Some(&expected_instruction)
    );
    let payload = signed_transaction.payload();
    let lifetime_is_valid = payload.time_to_live_ms.is_some_and(|time_to_live_ms| {
        payload.creation_time_ms > 0
            && payload
                .creation_time_ms
                .checked_add(time_to_live_ms.get())
                .is_some()
    });
    let signature_count = signed_transaction.signature_count();
    let multisig_is_canonical = signed_transaction
        .multisig_signatures()
        .is_none_or(|signatures| signatures.validate_canonical().is_ok());
    if signed_transaction.network_id().copied() != Some(request.network_id())
        || signed_transaction.authority() != &request.publisher
        || !exact_instruction
        || !lifetime_is_valid
        || !signed_transaction.metadata().is_empty()
        || signed_transaction.attachments().is_some()
        || signed_transaction.fee_payment_intent().validate().is_err()
        || signature_count == 0
        || signature_count > MUSUBI_MAX_RELEASE_SIGNATURES_V1
        || !multisig_is_canonical
        || signed_transaction.verify_signature().is_err()
    {
        return Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::ReleaseSubmission,
            reason: "release transaction was not the exact bounded canonical publish shape"
                .to_owned(),
        });
    }
    Ok(())
}
fn release_signed_transaction_wire_v1(
    signed_transaction: &SignedTransaction,
) -> Result<Vec<u8>, PublicationError> {
    signed_transaction
        .encode_wire_v1()
        .map_err(|error| PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::ReleaseSubmission,
            reason: format!("release transaction V1 wire encoding failed: {error}"),
        })
}
/// Idempotent Native AMX submission and authoritative application evidence.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationAmxSubmissionV1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationAmxSubmissionV1 {
    /// Operation identifier passed to the backend idempotency boundary.
    pub operation_id: PublicationOperationIdV1,
    /// Digest of the exact [`PublishMusubiReleaseV1`] instruction accepted by AMX.
    pub instruction_digest: [u8; 32],
    /// Submitted payload transaction hash.
    pub transaction_hash: [u8; 32],
    /// Authoritative block height at which the payload transaction was applied.
    pub applied_height: u64,
}
impl PublicationAmxSubmissionV1 {
    /// Bind an applied payload hash and height to the exact idempotent publish instruction.
    #[must_use]
    pub fn new(
        operation_id: PublicationOperationIdV1,
        instruction: &PublishMusubiReleaseV1,
        transaction_hash: [u8; 32],
        applied_height: u64,
    ) -> Self {
        Self {
            operation_id,
            instruction_digest: domain_hash(PUBLISH_INSTRUCTION_DOMAIN, &instruction.encode()),
            transaction_hash,
            applied_height,
        }
    }
    fn validate_for(
        &self,
        operation_id: PublicationOperationIdV1,
        instruction: &PublishMusubiReleaseV1,
    ) -> Result<(), PublicationError> {
        ensure_release_component_budget(
            self,
            MAX_RELEASE_SUBMISSION_CANONICAL_BYTES,
            "release submission evidence",
            PublicationPhaseV1::ReleaseSubmission,
        )?;
        if self.operation_id != operation_id
            || self.instruction_digest
                != domain_hash(PUBLISH_INSTRUCTION_DOMAIN, &instruction.encode())
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || self.applied_height == 0
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::ReleaseSubmission,
                reason: "Native AMX submission evidence was substituted".to_owned(),
            });
        }
        Ok(())
    }
}
/// Exact finalized home-dataspace and universal-index publication result.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationFinalEvidenceV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationFinalEvidenceV1 {
    /// Exact genesis-derived network identity returned with the universal-index row.
    pub network_id: NetworkId,
    /// Finalized universal registry snapshot used for the exact verification.
    pub snapshot: MusubiRegistrySnapshotV1,
    /// Exact authoritative release record in the stable home dataspace.
    pub home_release: MusubiReleaseRecordV1,
    /// Exact compact release row in the universal sparse index.
    pub universal_release: MusubiResolverReleaseRowV1,
}
impl PublicationFinalEvidenceV1 {
    fn validate_for(
        &self,
        request: &PublicationRequestV1,
        submission: &PublicationAmxSubmissionV1,
    ) -> Result<(), PublicationError> {
        ensure_release_component_budget(
            self,
            MAX_RELEASE_FINAL_QUERY_EVIDENCE_CANONICAL_BYTES,
            "release final evidence",
            PublicationPhaseV1::FinalVerification,
        )?;
        self.snapshot
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::FinalVerification, error))?;
        self.home_release
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::FinalVerification, error))?;
        self.universal_release
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::FinalVerification, error))?;
        MusubiExactReleaseSnapshotV1 {
            network_id: request.network_id,
            snapshot: self.snapshot,
            home_release: self.home_release.clone(),
            universal_release: self.universal_release.clone(),
        }
        .validate()
        .map_err(|error| invalid(PublicationPhaseV1::FinalVerification, error))?;
        let manifest = &request.publication.manifest;
        let row = &self.universal_release;
        if self.network_id != request.network_id
            || self.snapshot.finalized_height
                < request.publication.resolution.snapshot.finalized_height
            || self.snapshot.finalized_height < submission.applied_height
            || self.snapshot.index_revision < request.publication.resolution.snapshot.index_revision
            || &self.home_release.manifest != manifest
            || self.home_release.release_digest != manifest.release_digest()
            || self.home_release.published_by != request.publisher
            || self.home_release.published_at_height > self.snapshot.finalized_height
            || row.release != manifest.release
            || row.release_digest != manifest.release_digest()
            || row.archive_id != manifest.archive_id
            || row.source_digest != request.archive_commitment.source_tree_digest
            || row.interface_digest != manifest.interface_digest
            || row.abi != manifest.abi
            || row.dependencies != manifest.dependencies
            || row.index_revision > self.snapshot.index_revision
            || row.selection.storage.index_revision > row.index_revision
            || row.selection.storage.archive_id != manifest.archive_id
            || row.selection.storage.finalized_height > self.snapshot.finalized_height
            || (row.selection.storage.finalized_height == self.snapshot.finalized_height
                && row.selection.storage.finalized_block_hash != self.snapshot.finalized_block_hash)
            || row.selection.yank != self.home_release.yank
            || row.selection.governance != self.home_release.artifact_governance
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::FinalVerification,
                reason: "finalized home record or universal resolver entry was substituted"
                    .to_owned(),
            });
        }
        Ok(())
    }
}
/// Compact local journal commitment to one fully verified paired release projection.
///
/// The checkpoint binds the immutable request and canonical projection digests, but its public
/// self-digest is not an authenticated finalized-query receipt. Completed resume therefore relies
/// on the publication journal's trusted private-storage boundary.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationFinalCheckpointV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationFinalCheckpointV1 {
    /// Stable request-derived operation identity, including the public anti-replay nonce.
    pub operation_id: PublicationOperationIdV1,
    /// Exact genesis-derived network identity returned with the exact projections.
    pub network_id: NetworkId,
    /// Finalized registry snapshot at which both projections were verified.
    pub snapshot: MusubiRegistrySnapshotV1,
    /// Exact structural release identity.
    pub release: MusubiReleaseIdV1,
    /// Digest of the complete immutable release manifest, including its archive identity.
    pub release_digest: MusubiReleaseDigestV1,
    /// Exact immutable source archive identity.
    pub archive_id: ArchiveId,
    /// Domain-separated canonical digest of the verified home-dataspace record.
    pub home_release_digest: [u8; 32],
    /// Domain-separated canonical digest of the verified universal resolver row.
    pub universal_release_digest: [u8; 32],
    /// Integrity digest binding every compact checkpoint field and projection digest.
    pub checkpoint_digest: [u8; 32],
}
impl PublicationFinalCheckpointV1 {
    fn from_verified(
        request: &PublicationRequestV1,
        submission: &PublicationAmxSubmissionV1,
        evidence: &PublicationFinalEvidenceV1,
    ) -> Result<Self, PublicationError> {
        evidence.validate_for(request, submission)?;
        let home_release = norito::encode_canonical(&evidence.home_release).map_err(|error| {
            PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::FinalVerification,
                reason: format!("home release could not be canonically encoded: {error}"),
            }
        })?;
        let universal_release =
            norito::encode_canonical(&evidence.universal_release).map_err(|error| {
                PublicationError::InvalidEvidence {
                    phase: PublicationPhaseV1::FinalVerification,
                    reason: format!(
                        "universal release row could not be canonically encoded: {error}"
                    ),
                }
            })?;
        let mut checkpoint = Self {
            operation_id: request.operation_id(),
            network_id: evidence.network_id,
            snapshot: evidence.snapshot,
            release: evidence.home_release.manifest.release.clone(),
            release_digest: evidence.home_release.release_digest,
            archive_id: evidence.universal_release.archive_id,
            home_release_digest: domain_hash(FINAL_HOME_RELEASE_DOMAIN, &home_release),
            universal_release_digest: domain_hash(
                FINAL_UNIVERSAL_RELEASE_DOMAIN,
                &universal_release,
            ),
            checkpoint_digest: [0; 32],
        };
        checkpoint.checkpoint_digest = checkpoint.digest()?;
        checkpoint.validate_for(request, submission)?;
        Ok(checkpoint)
    }
    fn digest(&self) -> Result<[u8; 32], PublicationError> {
        let mut payload = self.clone();
        payload.checkpoint_digest = [0; 32];
        let canonical = norito::encode_canonical(&payload).map_err(|error| {
            PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::FinalVerification,
                reason: format!("final checkpoint could not be canonically encoded: {error}"),
            }
        })?;
        Ok(domain_hash(FINAL_CHECKPOINT_DOMAIN, &canonical))
    }
    fn validate_for(
        &self,
        request: &PublicationRequestV1,
        submission: &PublicationAmxSubmissionV1,
    ) -> Result<(), PublicationError> {
        ensure_release_component_budget(
            self,
            MAX_RELEASE_FINAL_CHECKPOINT_CANONICAL_BYTES,
            "release final checkpoint",
            PublicationPhaseV1::FinalVerification,
        )?;
        self.snapshot
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::FinalVerification, error))?;
        self.release
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::FinalVerification, error))?;
        let manifest = &request.publication.manifest;
        if self.operation_id != request.operation_id()
            || self.operation_id != submission.operation_id
            || self.network_id != request.network_id
            || self.snapshot.finalized_height
                < request.publication.resolution.snapshot.finalized_height
            || self.snapshot.finalized_height < submission.applied_height
            || self.snapshot.index_revision < request.publication.resolution.snapshot.index_revision
            || self.release != manifest.release
            || self.release_digest != manifest.release_digest()
            || self.archive_id != manifest.archive_id
            || self.home_release_digest.iter().all(|byte| *byte == 0)
            || self.universal_release_digest.iter().all(|byte| *byte == 0)
            || self.checkpoint_digest.iter().all(|byte| *byte == 0)
            || self.checkpoint_digest != self.digest()?
        {
            return Err(PublicationError::InvalidEvidence {
                phase: PublicationPhaseV1::FinalVerification,
                reason: "compact final publication checkpoint was substituted".to_owned(),
            });
        }
        Ok(())
    }
}
/// Completed publication result returned by ordinary publish or resume.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationResultV1 {
    /// Stable operation identifier.
    pub operation_id: PublicationOperationIdV1,
    /// Final Native AMX submission.
    pub submission: PublicationAmxSubmissionV1,
    /// Compact local commitment to the verified exact registry projections.
    pub final_checkpoint: PublicationFinalCheckpointV1,
}
/// Durable, secret-free operation journal.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "musubi::publish::PublicationJournalV1")]
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PublicationJournalV1 {
    /// Fixed schema marker.
    pub schema: String,
    /// Fixed first-release schema version.
    pub version: u8,
    /// Monotonic local compare-and-set revision.
    pub revision: u64,
    /// Stable idempotency identifier derived from the request.
    pub operation_id: PublicationOperationIdV1,
    /// Immutable public request.
    pub request: PublicationRequestV1,
    /// Current phase; a completed journal remains at `FinalVerification`.
    pub phase: PublicationPhaseV1,
    /// Successful clean-package validation evidence.
    pub validation: Option<PublicationValidationEvidenceV1>,
    /// Authenticated seed-ingress receipt.
    pub staging_receipt: Option<MusubiSeedIngressReceiptV1>,
    /// Bounded append-only exact registration transaction generations.
    pub archive_registration_attempts: Vec<PublicationArchiveRegistrationAttemptV1>,
    /// Finalized authoritative archive record persisted before storage coordination.
    pub registered_archive: Option<PublicationRegisteredArchiveV1>,
    /// Compact append-only anchors for immutable provider set and transaction sidecars.
    pub provider_registration_checkpoints: Vec<PublicationProviderRegistrationCheckpointV1>,
    /// Bounded append-only signed archive-location transaction generations.
    pub archive_location_attempts: Vec<PublicationArchiveLocationAttemptV1>,
    /// Complete finalized page containing the healthy active location and compact proof-set digest.
    pub replication: Option<PublicationReplicationCheckpointV1>,
    /// Two distinct provider readback results.
    pub readbacks: Vec<PublicationReadbackEvidenceV1>,
    /// Bounded append-only compact release transaction generations.
    pub release_submission_attempts: Vec<PublicationReleaseSubmissionAttemptV1>,
    /// Idempotent Native AMX submission result.
    pub submission: Option<PublicationAmxSubmissionV1>,
    /// Present only after exact finalized home/index verification and compaction.
    pub completion: Option<PublicationFinalCheckpointV1>,
}
impl PublicationJournalV1 {
    fn new(request: PublicationRequestV1) -> Result<Self, PublicationError> {
        request.validate()?;
        let operation_id = request.operation_id();
        Ok(Self {
            schema: JOURNAL_SCHEMA.to_owned(),
            version: JOURNAL_VERSION,
            revision: 1,
            operation_id,
            request,
            phase: PublicationPhaseV1::Validation,
            validation: None,
            staging_receipt: None,
            archive_registration_attempts: Vec::new(),
            registered_archive: None,
            provider_registration_checkpoints: Vec::new(),
            archive_location_attempts: Vec::new(),
            replication: None,
            readbacks: Vec::new(),
            release_submission_attempts: Vec::new(),
            submission: None,
            completion: None,
        })
    }
    /// Validate schema, operation identity, exact evidence, and phase consistency.
    ///
    /// # Errors
    ///
    /// Returns an invalid-journal or invalid-evidence error when any persisted phase, append-only
    /// history, canonical budget, replay binding, or finalized checkpoint is inconsistent.
    #[allow(
        clippy::too_many_lines,
        reason = "the journal validator keeps the complete append-only security state machine and all phase invariants adjacent"
    )]
    pub fn validate(&self) -> Result<(), PublicationError> {
        if self.schema != JOURNAL_SCHEMA
            || self.version != JOURNAL_VERSION
            || self.revision == 0
            || self.operation_id.is_zero()
        {
            return Err(PublicationError::InvalidJournal(
                "journal schema, version, revision, or operation id is invalid".to_owned(),
            ));
        }
        self.validate_canonical_budgets()?;
        self.request.validate()?;
        if self.operation_id != self.request.operation_id() {
            return Err(PublicationError::InvalidJournal(
                "journal operation id does not bind its immutable request".to_owned(),
            ));
        }
        let required = self.phase as u8;
        validate_option(
            required >= PublicationPhaseV1::SeedIngress as u8,
            self.validation.as_ref(),
        )?;
        validate_option(
            required >= PublicationPhaseV1::ArchiveRegistration as u8,
            self.staging_receipt.as_ref(),
        )?;
        if self.archive_registration_attempts.len() > MUSUBI_MAX_ARCHIVE_REGISTRATION_ATTEMPTS_V1 {
            return Err(PublicationError::InvalidJournal(
                "journal exceeds the archive-registration attempt bound".to_owned(),
            ));
        }
        for (index, attempt) in self.archive_registration_attempts.iter().enumerate() {
            let generation = u8::try_from(index + 1).expect("attempt bound fits u8");
            if attempt.generation != generation
                || (index + 1 < self.archive_registration_attempts.len()
                    && attempt.terminal.is_none())
            {
                return Err(PublicationError::InvalidJournal(
                    "archive-registration attempts are not contiguous and append-only".to_owned(),
                ));
            }
            attempt.validate_for(self.operation_id, &self.request)?;
        }
        let active_attempt = self
            .archive_registration_attempts
            .last()
            .filter(|attempt| attempt.terminal.is_none());
        let registration_complete = required >= PublicationPhaseV1::Replication as u8;
        if registration_complete {
            if active_attempt.is_none() {
                return Err(PublicationError::InvalidJournal(
                    "completed archive registration is missing its active exact attempt".to_owned(),
                ));
            }
            validate_option(true, self.registered_archive.as_ref())?;
        } else if required < PublicationPhaseV1::ArchiveRegistration as u8 {
            validate_option(false, self.registered_archive.as_ref())?;
            if !self.archive_location_attempts.is_empty() {
                return Err(PublicationError::InvalidJournal(
                    "archive-location attempts are present before archive finality".to_owned(),
                ));
            }
            if active_attempt.is_some()
                || (self.phase == PublicationPhaseV1::Validation
                    && !self.archive_registration_attempts.is_empty())
            {
                return Err(PublicationError::InvalidJournal(
                    "a live archive-registration attempt is present outside its phase".to_owned(),
                ));
            }
        } else if self.registered_archive.is_some() && active_attempt.is_none() {
            return Err(PublicationError::InvalidJournal(
                "archive registration checkpoints are not monotonic".to_owned(),
            ));
        }
        if self.provider_registration_checkpoints.len() > MUSUBI_MAX_ARCHIVE_LOCATION_ATTEMPTS_V1
            || self.provider_registration_checkpoints.len()
                > self.archive_location_attempts.len().saturating_add(1)
            || (required < PublicationPhaseV1::ArchiveRegistration as u8
                && !self.provider_registration_checkpoints.is_empty())
        {
            return Err(PublicationError::InvalidJournal(
                "provider-registration checkpoint history is out of phase or over bound".to_owned(),
            ));
        }
        for (index, checkpoint) in self.provider_registration_checkpoints.iter().enumerate() {
            let generation = u8::try_from(index + 1).expect("location-attempt bound fits u8");
            checkpoint.validate_for(&self.request, generation)?;
            if let Some(attempt) = self.archive_location_attempts.get(index)
                && (attempt.intent.generation != checkpoint.generation
                    || attempt.intent.replication_order != checkpoint.replication_order
                    || attempt.intent.provider_attestation_set_digest
                        != checkpoint.provider_attestation_set_digest)
            {
                return Err(PublicationError::InvalidJournal(
                    "location intent does not bind its provider-registration checkpoint".to_owned(),
                ));
            }
        }
        if self.archive_location_attempts.len() > MUSUBI_MAX_ARCHIVE_LOCATION_ATTEMPTS_V1 {
            return Err(PublicationError::InvalidJournal(
                "journal exceeds the archive-location attempt bound".to_owned(),
            ));
        }
        let mut prior_location_ids = Vec::with_capacity(self.archive_location_attempts.len());
        for (index, attempt) in self.archive_location_attempts.iter().enumerate() {
            let generation = u8::try_from(index + 1).expect("location-attempt bound fits u8");
            if attempt.generation != generation
                || attempt.intent.generation != generation
                || (index + 1 < self.archive_location_attempts.len() && attempt.terminal.is_none())
            {
                return Err(PublicationError::InvalidJournal(
                    "archive-location attempts are not contiguous and append-only".to_owned(),
                ));
            }
            let registered = self.registered_archive.as_ref().ok_or_else(|| {
                PublicationError::InvalidJournal(
                    "archive-location attempt is missing authoritative archive finality".to_owned(),
                )
            })?;
            attempt.intent.validate_for(
                self.operation_id,
                &self.request,
                registered,
                &prior_location_ids,
            )?;
            if let Some(previous) = index
                .checked_sub(1)
                .and_then(|previous| self.archive_location_attempts.get(previous))
            {
                let terminal = previous.terminal.as_ref().ok_or_else(|| {
                    PublicationError::InvalidJournal(
                        "a replacement archive location lacks prior terminal finality".to_owned(),
                    )
                })?;
                let prepared = &attempt.intent.prepared_page;
                let prior_finalized = &terminal.finalized_page;
                if prepared.snapshot.finalized_height < prior_finalized.snapshot.finalized_height
                    || prepared.snapshot.index_revision < prior_finalized.snapshot.index_revision
                    || (prepared.snapshot.finalized_height
                        == prior_finalized.snapshot.finalized_height
                        && prepared != prior_finalized)
                    || (prepared.snapshot == prior_finalized.snapshot
                        && (prepared.archive != prior_finalized.archive
                            || prepared.items != prior_finalized.items))
                    || prepared.archive.location_revision
                        < prior_finalized.archive.location_revision
                    || (prepared.archive.location_revision
                        == prior_finalized.archive.location_revision
                        && (prepared.archive != prior_finalized.archive
                            || prepared.items != prior_finalized.items))
                {
                    return Err(PublicationError::InvalidJournal(
                        "a replacement archive location regressed prior terminal finality"
                            .to_owned(),
                    ));
                }
            }
            if let Some(registration) = &attempt.registration {
                registration.validate_for(
                    self.operation_id,
                    &self.request,
                    registered,
                    &prior_location_ids,
                )?;
                if registration.intent != attempt.intent {
                    return Err(PublicationError::InvalidJournal(
                        "archive-location finality names a different signed intent".to_owned(),
                    ));
                }
            }
            if attempt.terminal.is_some() != attempt.terminal_floor.is_some() {
                return Err(PublicationError::InvalidJournal(
                    "archive-location terminal evidence is missing its durable floor".to_owned(),
                ));
            }
            if let (Some(terminal), Some(floor)) = (&attempt.terminal, &attempt.terminal_floor) {
                terminal.validate_for(
                    self.operation_id,
                    &self.request,
                    registered,
                    attempt,
                    &prior_location_ids,
                    floor,
                )?;
            }
            prior_location_ids.push(attempt.intent.location_id);
        }
        let active_location_attempt = self
            .archive_location_attempts
            .last()
            .filter(|attempt| attempt.terminal.is_none());
        if registration_complete
            && active_location_attempt
                .and_then(|attempt| attempt.registration.as_ref())
                .is_none()
        {
            return Err(PublicationError::InvalidJournal(
                "replication phase is missing a finalized active location generation".to_owned(),
            ));
        }
        validate_option(
            required >= PublicationPhaseV1::Readback as u8,
            self.replication.as_ref(),
        )?;
        let expects_readbacks = required >= PublicationPhaseV1::ReleaseSubmission as u8;
        if self.readbacks.len() != if expects_readbacks { 2 } else { 0 } {
            return Err(PublicationError::InvalidJournal(
                "journal readback count is inconsistent with its phase".to_owned(),
            ));
        }
        if self.release_submission_attempts.len() > MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1 {
            return Err(PublicationError::InvalidJournal(
                "journal exceeds the release-submission attempt bound".to_owned(),
            ));
        }
        if required < PublicationPhaseV1::ArchiveRegistration as u8
            && !self.release_submission_attempts.is_empty()
        {
            return Err(PublicationError::InvalidJournal(
                "release-submission attempts are present before archive registration".to_owned(),
            ));
        }
        let mut prior_release_hashes = Vec::with_capacity(self.release_submission_attempts.len());
        let mut prior_release_digests = Vec::with_capacity(self.release_submission_attempts.len());
        for (index, attempt) in self.release_submission_attempts.iter().enumerate() {
            let generation = u8::try_from(index + 1).expect("release-attempt bound fits u8");
            if attempt.generation != generation
                || (index + 1 < self.release_submission_attempts.len()
                    && !matches!(
                        &attempt.outcome,
                        Some(PublicationReleaseSubmissionOutcomeV1::Terminal(_))
                    ))
                || prior_release_hashes.contains(&attempt.intent.transaction_hash)
                || prior_release_digests.contains(&attempt.intent.signed_transaction_digest)
            {
                return Err(PublicationError::InvalidJournal(
                    "release-submission attempts are not unique, contiguous, and append-only"
                        .to_owned(),
                ));
            }
            attempt.validate_for(self.operation_id, &self.request)?;
            let location_attempt = attempt
                .intent
                .preparation
                .location_generation
                .checked_sub(1)
                .map(usize::from)
                .and_then(|index| self.archive_location_attempts.get(index))
                .filter(|location_attempt| {
                    location_attempt.generation == attempt.intent.preparation.location_generation
                })
                .ok_or_else(|| {
                    PublicationError::InvalidJournal(
                        "release intent is missing its journaled archive-location generation"
                            .to_owned(),
                    )
                })?;
            let location_registration =
                location_attempt.registration.as_ref().ok_or_else(|| {
                    PublicationError::InvalidJournal(
                        "release intent location generation lacks finalized registration"
                            .to_owned(),
                    )
                })?;
            attempt
                .intent
                .preparation
                .validate_for_registration(&self.request, location_registration)?;
            if let Some((previous, previous_terminal)) = index
                .checked_sub(1)
                .and_then(|previous| self.release_submission_attempts.get(previous))
                .and_then(|previous| match &previous.outcome {
                    Some(PublicationReleaseSubmissionOutcomeV1::Terminal(terminal)) => {
                        Some((previous, terminal))
                    }
                    _ => None,
                })
            {
                let prior_snapshot = previous_terminal.absence().snapshot();
                let next_snapshot = &attempt
                    .intent
                    .preparation
                    .replication
                    .finalized_page
                    .snapshot;
                if next_snapshot.finalized_height < prior_snapshot.finalized_height
                    || next_snapshot.index_revision < prior_snapshot.index_revision
                    || (next_snapshot.finalized_height == prior_snapshot.finalized_height
                        && next_snapshot.finalized_block_hash
                            != prior_snapshot.finalized_block_hash)
                {
                    return Err(PublicationError::InvalidJournal(
                        "successor release intent does not cover prior terminal finality"
                            .to_owned(),
                    ));
                }
                if let PublicationReleaseSubmissionTerminalReasonV1::RegistryRejected {
                    block_height,
                    ..
                } = &previous_terminal.reason
                {
                    let prior_location = previous
                        .intent
                        .preparation
                        .location()
                        .expect("validated release preparation contains its location");
                    let next_location = attempt
                        .intent
                        .preparation
                        .location()
                        .expect("validated release preparation contains its location");
                    let higher_same_location = attempt.intent.preparation.location_generation
                        == previous.intent.preparation.location_generation
                        && next_location.location_id == prior_location.location_id
                        && next_location.revision > prior_location.revision
                        && next_location.finalized_height >= *block_height;
                    let prior_location_terminal = previous
                        .intent
                        .preparation
                        .location_generation
                        .checked_sub(1)
                        .map(usize::from)
                        .and_then(|index| self.archive_location_attempts.get(index))
                        .and_then(|attempt| attempt.terminal.as_ref());
                    let retired_then_replaced = attempt.intent.preparation.location_generation
                        > previous.intent.preparation.location_generation
                        && prior_location_terminal.is_some_and(|terminal| {
                            matches!(
                                terminal.reason,
                                PublicationArchiveLocationTerminalReasonV1::Retired
                            ) && terminal.finalized_page.snapshot.finalized_height >= *block_height
                        });
                    if !higher_same_location && !retired_then_replaced {
                        return Err(PublicationError::InvalidJournal(
                            "rejected release successor did not refresh or replace its location"
                                .to_owned(),
                        ));
                    }
                }
            }
            match &attempt.outcome {
                None => {
                    if self.phase != PublicationPhaseV1::ReleaseSubmission
                        || index + 1 != self.release_submission_attempts.len()
                        || location_attempt.terminal.is_some()
                        || self.replication.as_ref()
                            != Some(&attempt.intent.preparation.replication)
                        || self.readbacks != attempt.intent.preparation.readbacks
                    {
                        return Err(PublicationError::InvalidJournal(
                            "live release intent is outside its exact current preparation floor"
                                .to_owned(),
                        ));
                    }
                }
                Some(PublicationReleaseSubmissionOutcomeV1::Applied { .. }) => {
                    if self.phase != PublicationPhaseV1::FinalVerification
                        || index + 1 != self.release_submission_attempts.len()
                    {
                        return Err(PublicationError::InvalidJournal(
                            "applied release outcome is outside final verification".to_owned(),
                        ));
                    }
                }
                Some(PublicationReleaseSubmissionOutcomeV1::Terminal(_)) => {}
            }
            prior_release_hashes.push(attempt.intent.transaction_hash);
            prior_release_digests.push(attempt.intent.signed_transaction_digest);
        }
        if required >= PublicationPhaseV1::ReleaseSubmission as u8
            && self.release_submission_attempts.is_empty()
        {
            return Err(PublicationError::InvalidJournal(
                "release submission is missing its persist-before-send exact intent".to_owned(),
            ));
        }
        if self.phase == PublicationPhaseV1::FinalVerification
            && !matches!(
                self.release_submission_attempts
                    .last()
                    .and_then(|attempt| attempt.outcome.as_ref()),
                Some(PublicationReleaseSubmissionOutcomeV1::Applied { .. })
            )
        {
            return Err(PublicationError::InvalidJournal(
                "final verification is missing the exact applied release outcome".to_owned(),
            ));
        }
        validate_option(
            required >= PublicationPhaseV1::FinalVerification as u8,
            self.submission.as_ref(),
        )?;
        if self.completion.is_some() && self.phase != PublicationPhaseV1::FinalVerification {
            return Err(PublicationError::InvalidJournal(
                "journal completion is present before final verification".to_owned(),
            ));
        }
        if let Some(validation) = &self.validation {
            validation.validate_for(&self.request)?;
        }
        if let Some(receipt) = &self.staging_receipt {
            receipt
                .verify(
                    &self.request.receipt_binding(),
                    receipt.payload.issued_at_ms,
                )
                .map_err(|error| invalid(PublicationPhaseV1::SeedIngress, error))?;
        }
        if let Some(attempt) = active_attempt
            && self.staging_receipt.as_ref() != Some(&attempt.intent.staging_receipt)
        {
            return Err(PublicationError::InvalidJournal(
                "active archive-registration attempt is missing its exact staging receipt"
                    .to_owned(),
            ));
        }
        if let Some(registered) = &self.registered_archive {
            registered.validate_for(
                &self.request,
                active_attempt
                    .map(|attempt| &attempt.intent)
                    .ok_or_else(|| {
                        PublicationError::InvalidJournal(
                            "authoritative archive is missing its registration intent".to_owned(),
                        )
                    })?,
            )?;
        }
        if let Some(checkpoint) = &self.replication {
            checkpoint.validate_for(&self.request, self.registration()?)?;
        }
        if let Some(checkpoint) = &self.replication {
            let location = checkpoint.location(self.registration()?)?;
            if !self.readbacks.is_empty() {
                validate_readback_subset(&self.request, location, &self.readbacks)?;
            }
        }
        if let Some(submission) = &self.submission {
            submission.validate_for(self.operation_id, &self.request.publish_instruction())?;
            if let Some(last_attempt) = self.release_submission_attempts.last() {
                let applied_submission = match &last_attempt.outcome {
                    Some(PublicationReleaseSubmissionOutcomeV1::Applied { submission, .. }) => {
                        Some(submission)
                    }
                    _ => None,
                };
                if applied_submission != Some(submission) {
                    return Err(PublicationError::InvalidJournal(
                        "Native AMX submission does not equal the append-only applied outcome"
                            .to_owned(),
                    ));
                }
            }
        }
        if let Some(completion) = &self.completion {
            completion.validate_for(
                &self.request,
                self.submission.as_ref().ok_or_else(|| {
                    PublicationError::InvalidJournal(
                        "final checkpoint is missing its Native AMX submission".to_owned(),
                    )
                })?,
            )?;
        }
        Ok(())
    }
    fn validate_canonical_budgets(&self) -> Result<(), PublicationError> {
        let full_size = canonical_encoded_len(self).map_err(PublicationError::InvalidJournal)?;
        if full_size > MAX_JOURNAL_BYTES_USIZE {
            return Err(PublicationError::InvalidJournal(format!(
                "journal canonical size {full_size} exceeds {MAX_JOURNAL_BYTES_USIZE} bytes"
            )));
        }
        let mut non_release = self.clone();
        non_release.release_submission_attempts.clear();
        non_release.submission = None;
        non_release.completion = None;
        let non_release_size =
            canonical_encoded_len(&non_release).map_err(PublicationError::InvalidJournal)?;
        if non_release_size > JOURNAL_NON_RELEASE_BUDGET_BYTES {
            return Err(PublicationError::InvalidJournal(format!(
                "non-release journal state canonical size {non_release_size} exceeds its derived \
                 {JOURNAL_NON_RELEASE_BUDGET_BYTES}-byte budget"
            )));
        }
        let mut release_attempts_size = 0_usize;
        for attempt in &self.release_submission_attempts {
            let attempt_size =
                canonical_encoded_len(attempt).map_err(PublicationError::InvalidJournal)?;
            let intent_size =
                canonical_encoded_len(&attempt.intent).map_err(PublicationError::InvalidJournal)?;
            let outcome_size = attempt
                .outcome
                .as_ref()
                .map(canonical_encoded_len)
                .transpose()
                .map_err(PublicationError::InvalidJournal)?
                .unwrap_or_default();
            if attempt_size > MAX_RELEASE_ATTEMPT_CANONICAL_BYTES
                || intent_size > MAX_RELEASE_INTENT_CANONICAL_BYTES
                || outcome_size > MAX_RELEASE_OUTCOME_CANONICAL_BYTES
            {
                return Err(PublicationError::InvalidJournal(
                    "release attempt exceeds its multiplicity-derived canonical budget".to_owned(),
                ));
            }
            release_attempts_size =
                release_attempts_size
                    .checked_add(attempt_size)
                    .ok_or_else(|| {
                        PublicationError::InvalidJournal(
                            "release history canonical size overflowed".to_owned(),
                        )
                    })?;
        }
        if release_attempts_size > JOURNAL_RELEASE_ATTEMPTS_BUDGET_BYTES {
            return Err(PublicationError::InvalidJournal(format!(
                "release attempts canonical size {release_attempts_size} exceeds their derived \
                 {JOURNAL_RELEASE_ATTEMPTS_BUDGET_BYTES}-byte budget"
            )));
        }
        let submission_size = self
            .submission
            .as_ref()
            .map(canonical_encoded_len)
            .transpose()
            .map_err(PublicationError::InvalidJournal)?;
        let completion_size = self
            .completion
            .as_ref()
            .map(canonical_encoded_len)
            .transpose()
            .map_err(PublicationError::InvalidJournal)?;
        if submission_size.is_some_and(|size| size > MAX_RELEASE_SUBMISSION_CANONICAL_BYTES)
            || completion_size
                .is_some_and(|size| size > MAX_RELEASE_FINAL_CHECKPOINT_CANONICAL_BYTES)
        {
            return Err(PublicationError::InvalidJournal(
                "release submission or final checkpoint exceeds its reserved canonical budget"
                    .to_owned(),
            ));
        }
        let mut final_state_size = 0_usize;
        for component_size in [submission_size, completion_size].into_iter().flatten() {
            final_state_size = final_state_size
                .checked_add(component_size)
                .ok_or_else(|| {
                    PublicationError::InvalidJournal(
                        "release history canonical size overflowed".to_owned(),
                    )
                })?;
        }
        if final_state_size > JOURNAL_RELEASE_FINAL_STATE_BUDGET_BYTES {
            return Err(PublicationError::InvalidJournal(format!(
                "release final state canonical size {final_state_size} exceeds its reserved \
                 {JOURNAL_RELEASE_FINAL_STATE_BUDGET_BYTES}-byte budget"
            )));
        }
        Ok(())
    }
    fn registration(&self) -> Result<&PublicationArchiveRegistrationV1, PublicationError> {
        self.archive_location_attempts
            .last()
            .filter(|attempt| attempt.terminal.is_none())
            .and_then(|attempt| attempt.registration.as_ref())
            .ok_or_else(|| {
                PublicationError::InvalidJournal(
                    "journal is missing an active finalized archive location".to_owned(),
                )
            })
    }
    /// Convert a completed journal into its stable publication result.
    pub fn result(&self) -> Option<PublicationResultV1> {
        Some(PublicationResultV1 {
            operation_id: self.operation_id,
            submission: self.submission?,
            final_checkpoint: self.completion.clone()?,
        })
    }
}
fn validate_option<T>(required: bool, value: Option<&T>) -> Result<(), PublicationError> {
    if required != value.is_some() {
        return Err(PublicationError::InvalidJournal(
            "journal evidence presence is inconsistent with its phase".to_owned(),
        ));
    }
    Ok(())
}
fn archive_registration_attempts_are_append_only(
    previous: &[PublicationArchiveRegistrationAttemptV1],
    next: &[PublicationArchiveRegistrationAttemptV1],
) -> bool {
    if previous.len() > next.len() || next.len() > previous.len().saturating_add(1) {
        return false;
    }
    if previous == next.get(..previous.len()).unwrap_or_default() {
        return true;
    }
    if previous.len() != next.len() || previous.is_empty() {
        return false;
    }
    let last = previous.len() - 1;
    previous[..last] == next[..last]
        && previous[last].generation == next[last].generation
        && previous[last].intent == next[last].intent
        && previous[last].terminal.is_none()
        && next[last].terminal.is_some()
}
fn provider_registration_checkpoints_are_append_only(
    previous: &[PublicationProviderRegistrationCheckpointV1],
    next: &[PublicationProviderRegistrationCheckpointV1],
) -> bool {
    if previous == next {
        return true;
    }
    if next.len() == previous.len().saturating_add(1) {
        return previous == &next[..previous.len()]
            && next.last().is_some_and(|checkpoint| {
                usize::from(checkpoint.generation) == next.len()
                    && checkpoint.transactions.is_empty()
            });
    }
    if previous.len() != next.len() || previous.is_empty() {
        return false;
    }
    let last = previous.len() - 1;
    let before = &previous[last];
    let after = &next[last];
    previous[..last] == next[..last]
        && before.generation == after.generation
        && before.archive_id == after.archive_id
        && before.replication_order == after.replication_order
        && before.provider_attestation_set_digest == after.provider_attestation_set_digest
        && before.set_sidecar_hash == after.set_sidecar_hash
        && after.transactions.len() == before.transactions.len().saturating_add(1)
        && before.transactions == after.transactions[..before.transactions.len()]
}
fn archive_location_attempts_are_append_only(
    previous: &[PublicationArchiveLocationAttemptV1],
    next: &[PublicationArchiveLocationAttemptV1],
) -> bool {
    if previous.len() > next.len() || next.len() > previous.len().saturating_add(1) {
        return false;
    }
    if previous == next.get(..previous.len()).unwrap_or_default() {
        return true;
    }
    if previous.len() != next.len() || previous.is_empty() {
        return false;
    }
    let last = previous.len() - 1;
    if previous[..last] != next[..last]
        || previous[last].generation != next[last].generation
        || previous[last].intent != next[last].intent
    {
        return false;
    }
    let before = &previous[last];
    let after = &next[last];
    let registration_was_absent = before.registration.is_none();
    let registration_is_present = after.registration.is_some();
    let registration_appended = registration_was_absent
        && registration_is_present
        && before.terminal == after.terminal
        && before.terminal_floor == after.terminal_floor;
    let terminal_was_absent = before.terminal.is_none();
    let terminal_is_present = after.terminal.is_some();
    let terminal_appended = before.registration == after.registration
        && terminal_was_absent
        && terminal_is_present
        && before.terminal_floor.is_none()
        && after.terminal_floor.is_some();
    registration_appended || terminal_appended
}
fn release_submission_attempts_are_append_only(
    previous: &[PublicationReleaseSubmissionAttemptV1],
    next: &[PublicationReleaseSubmissionAttemptV1],
) -> bool {
    if previous.len() > next.len() || next.len() > previous.len().saturating_add(1) {
        return false;
    }
    if next.len() == previous.len().saturating_add(1) {
        let Some(appended) = next.last() else {
            return false;
        };
        return previous == &next[..previous.len()]
            && appended.outcome.is_none()
            && usize::from(appended.generation) == next.len()
            && previous.last().is_none_or(|attempt| {
                matches!(
                    attempt.outcome,
                    Some(PublicationReleaseSubmissionOutcomeV1::Terminal(_))
                )
            });
    }
    if previous == next {
        return true;
    }
    if previous.is_empty() {
        return false;
    }
    let last = previous.len() - 1;
    previous[..last] == next[..last]
        && previous[last].generation == next[last].generation
        && previous[last].intent == next[last].intent
        && previous[last].outcome.is_none()
        && next[last].outcome.is_some()
}
/// Runtime-only source of exact CAR bytes and their canonical build-plan witness.
pub trait PublicationCarSource {
    /// Open a new reader at byte zero. Implementations must not persist their path or credentials.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the exact bounded CAR cannot be opened safely at byte zero.
    fn open_car(&self) -> io::Result<Box<dyn Read + '_>>;
    /// Return the exact validated seed-ingress wire plan for this CAR.
    ///
    /// The plan is runtime-only publication input. Implementations must not put its bytes or a
    /// filesystem path into the secret-free publication journal.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the immutable plan cannot be reopened, decoded canonically, or
    /// validated against the complete archive commitment.
    fn car_plan(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> io::Result<MusubiSeedIngressCarPlanV1>;
}
/// Deterministic operation-local CAR and plan stored beside, but never inside, the journal.
#[derive(Clone, Debug)]
pub struct PublicationStagedCarSourceV1 {
    root: PathBuf,
    path: PathBuf,
    plan_path: PathBuf,
    expected_size: u64,
}
impl PublicationStagedCarSourceV1 {
    /// Bind immutable CAR and plan locations for one operation below an explicit state root.
    #[must_use]
    pub fn new(
        user_state_root: &Path,
        operation_id: PublicationOperationIdV1,
        expected_size: u64,
    ) -> Self {
        Self {
            root: user_state_root.to_path_buf(),
            path: user_state_root.join(staged_car_relative_path(operation_id)),
            plan_path: user_state_root.join(staged_plan_relative_path(operation_id)),
            expected_size,
        }
    }
    /// Return the deterministic operation-local path without persisting it in the journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Return the deterministic immutable plan-sidecar path outside the journal.
    #[must_use]
    pub fn plan_path(&self) -> &Path {
        &self.plan_path
    }
    /// Durably stage exact CAR bytes and their canonical plan below the private operation directory.
    ///
    /// Identical retries reuse both verified regular files. A different body or plan at the same
    /// operation id, an unsafe filesystem entry, or bytes that disagree with the request
    /// commitment fail closed without replacing either existing path.
    ///
    /// # Errors
    ///
    /// Returns invalid evidence, invalid journal state, or an I/O error when the CAR or plan is
    /// unbounded, differs from its commitment, or cannot be staged and revalidated safely.
    pub fn stage_bytes(
        user_state_root: &Path,
        operation_id: PublicationOperationIdV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        bytes: &[u8],
    ) -> Result<Self, PublicationError> {
        commitment
            .validate()
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        let wire_plan = MusubiSeedIngressCarPlanV1::from_car_build_plan(plan, commitment)
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        let canonical_digest = wire_plan
            .canonical_digest()
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        let plan_bytes = wire_plan
            .canonical_bytes()
            .map_err(|error| invalid(PublicationPhaseV1::Validation, error))?;
        if commitment.car_size == 0
            || commitment.car_size > MUSUBI_MAX_CAR_BYTES_V1
            || u64::try_from(bytes.len()).ok() != Some(commitment.car_size)
            || blake3::hash(bytes).as_bytes() != commitment.car_digest.as_bytes()
            || plan_bytes.is_empty()
            || plan_bytes.len() > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1
            || canonical_digest.is_zero()
        {
            return Err(invalid_staged_car_plan());
        }
        if !staged_car_plan_matches_commitment(commitment, plan, bytes) {
            return Err(invalid_staged_car_plan());
        }
        let source = Self::new(user_state_root, operation_id, commitment.car_size);
        let root = AtomicWriteRoot::new(user_state_root).map_err(PublicationError::JournalWrite)?;
        root.install_immutable(&staged_plan_relative_path(operation_id), &plan_bytes)
            .map_err(PublicationError::JournalWrite)?;
        root.install_immutable(&staged_car_relative_path(operation_id), bytes)
            .map_err(PublicationError::JournalWrite)?;
        source.verify_digest(commitment.car_digest)?;
        let reopened = source
            .car_plan(commitment)
            .map_err(PublicationError::CarSource)?;
        if reopened != wire_plan {
            return Err(PublicationError::InvalidJournal(
                "existing staged plan differs from the immutable publication request".to_owned(),
            ));
        }
        Ok(source)
    }
    fn reopen_plan(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> io::Result<MusubiSeedIngressCarPlanV1> {
        let root = AtomicWriteRoot::new(&self.root)
            .map_err(|_| invalid_plan_source("staged publication plan root is unsafe"))?;
        let bytes = root
            .load_private_descriptor_rooted(
                self.plan_path
                    .strip_prefix(&self.root)
                    .map_err(|_| invalid_plan_source("staged publication plan escaped its root"))?,
                MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1,
            )
            .map_err(|_| invalid_plan_source("staged publication plan could not be opened safely"))?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "staged publication plan sidecar is missing",
                )
            })?;
        let plan: MusubiSeedIngressCarPlanV1 =
            norito::decode_canonical_with_limits(&bytes, STAGED_PLAN_DECODE_LIMITS).map_err(
                |_| invalid_plan_source("staged publication plan is not canonical Norito"),
            )?;
        let canonical_digest = plan
            .canonical_digest()
            .map_err(|_| invalid_plan_source("staged publication plan digest is invalid"))?;
        let canonical = plan.canonical_bytes().map_err(|_| {
            invalid_plan_source("staged publication plan cannot be encoded canonically")
        })?;
        if canonical != bytes || canonical_digest.is_zero() {
            return Err(invalid_plan_source(
                "staged publication plan has a noncanonical representation",
            ));
        }
        plan.validate(commitment).map_err(|_| {
            invalid_plan_source("staged publication plan differs from the commitment")
        })?;
        let car_plan = plan
            .to_car_build_plan(commitment)
            .map_err(|_| invalid_plan_source("staged publication plan cannot be reconstructed"))?;
        let car = self.load_car_bytes_for_plan()?;
        if !staged_car_plan_matches_commitment(commitment, &car_plan, &car) {
            return Err(invalid_plan_source(
                "staged publication CAR and plan do not reproduce their archive commitment",
            ));
        }
        Ok(plan)
    }
    fn load_car_bytes_for_plan(&self) -> io::Result<Vec<u8>> {
        if self.expected_size == 0 || self.expected_size > MUSUBI_MAX_CAR_BYTES_V1 {
            return Err(invalid_plan_source(
                "staged publication CAR length is outside its bound",
            ));
        }
        let size = usize::try_from(self.expected_size).map_err(|_| {
            invalid_plan_source("staged publication CAR length does not fit this platform")
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            invalid_plan_source("staged publication CAR buffer could not be allocated")
        })?;
        bytes.resize(size, 0);
        let mut reader = self.open_car()?;
        reader.read_exact(&mut bytes)?;
        let mut trailing = [0_u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(invalid_plan_source(
                "staged publication CAR exceeds its committed length",
            ));
        }
        Ok(bytes)
    }
    fn verify_digest(
        &self,
        expected_digest: MusubiContentDigestV1,
    ) -> Result<(), PublicationError> {
        let mut reader = self.open_car().map_err(PublicationError::CarSource)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut observed = 0_u64;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(PublicationError::CarSource)?;
            if read == 0 {
                break;
            }
            observed = observed
                .checked_add(u64::try_from(read).expect("read buffer length fits u64"))
                .ok_or_else(|| {
                    PublicationError::InvalidJournal("staged CAR length overflowed".to_owned())
                })?;
            if observed > self.expected_size {
                return Err(PublicationError::InvalidJournal(
                    "staged CAR grew while it was verified".to_owned(),
                ));
            }
            hasher.update(&buffer[..read]);
        }
        if observed != self.expected_size
            || hasher.finalize().as_bytes() != expected_digest.as_bytes()
        {
            return Err(PublicationError::InvalidJournal(
                "existing staged CAR differs from the immutable publication request".to_owned(),
            ));
        }
        Ok(())
    }
}
fn invalid_staged_car_plan() -> PublicationError {
    PublicationError::InvalidEvidence {
        phase: PublicationPhaseV1::Validation,
        reason: "staged CAR and plan do not reproduce their bounded archive commitment".to_owned(),
    }
}
fn staged_car_plan_matches_commitment(
    commitment: &MusubiArchiveCommitmentV1,
    plan: &CarBuildPlan,
    bytes: &[u8],
) -> bool {
    let Ok(verified) = CarVerifier::verify_canonical_car_with_plan_retained(plan, bytes) else {
        return false;
    };
    let stats = verified.stats();
    let observed_car_digest = stats.car_archive_digest.as_bytes();
    let expected_car_digest = commitment.car_digest.as_bytes();
    let observed_content_length = stats.payload_bytes;
    let expected_content_length = commitment.content_length;
    let observed_root_cid = stats.root_cids.first().map(Vec::as_slice);
    let expected_root_cid: &[u8] = commitment.root_cid.as_bytes();
    if stats.car_size != commitment.car_size
        || observed_car_digest != expected_car_digest
        || observed_content_length != expected_content_length
        || stats.chunk_count != usize::try_from(commitment.chunk_count).unwrap_or(usize::MAX)
        || stats.chunk_profile != plan.chunk_profile
        || stats.root_cids.len() != 1
        || observed_root_cid != Some(expected_root_cid)
    {
        return false;
    }
    let Ok(mut chunk_store) = ChunkStore::with_profile_and_heap_limit(
        plan.chunk_profile,
        STAGED_CAR_PLAN_HEAP_LIMIT_BYTES_V1,
    ) else {
        return false;
    };
    let mut payload_reader = verified.payload_reader();
    if chunk_store
        .ingest_plan_stream(plan, &mut payload_reader)
        .is_err()
    {
        return false;
    }
    chunk_store.payload_digest() == &plan.payload_digest
        && chunk_store.por_tree().root() == commitment.por_root.as_bytes()
}
impl PublicationCarSource for PublicationStagedCarSourceV1 {
    fn open_car(&self) -> io::Result<Box<dyn Read + '_>> {
        if self.expected_size == 0 || self.expected_size > MUSUBI_MAX_CAR_BYTES_V1 {
            return Err(invalid_plan_source(
                "staged publication CAR length is outside its bound",
            ));
        }
        let file = RetainedFile::open_private(&self.path).map_err(car_custody_error)?;
        let initial = file.snapshot().map_err(car_custody_error)?;
        if file.file().metadata()?.len() != self.expected_size {
            return Err(invalid_plan_source(
                "staged publication CAR is not the expected bounded regular file",
            ));
        }
        file.revalidate().map_err(car_custody_error)?;
        Ok(Box::new(StableCarReader {
            file,
            initial,
            expected_size: self.expected_size,
            observed: 0,
            complete: false,
        }))
    }
    fn car_plan(
        &self,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> io::Result<MusubiSeedIngressCarPlanV1> {
        self.reopen_plan(commitment)
    }
}
fn invalid_plan_source(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn car_custody_error(error: io::Error) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
    ) {
        io::Error::new(io::ErrorKind::InvalidData, error)
    } else {
        error
    }
}
struct StableCarReader {
    file: RetainedFile,
    initial: FileSnapshot,
    expected_size: u64,
    observed: u64,
    complete: bool,
}
impl StableCarReader {
    fn validate_complete_snapshot(&self) -> io::Result<()> {
        if self.file.snapshot().ok().as_ref() != Some(&self.initial)
            || self.file.file().metadata()?.len() != self.expected_size
        {
            return Err(invalid_plan_source(
                "staged publication CAR changed while it was read",
            ));
        }
        Ok(())
    }
}
impl Read for StableCarReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.complete || buffer.is_empty() {
            return Ok(0);
        }
        let remaining = usize::try_from(self.expected_size - self.observed).unwrap_or(usize::MAX);
        let length = buffer.len().min(remaining);
        let read = self.file.file_mut().read(&mut buffer[..length])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "staged publication CAR ended before its committed length",
            ));
        }
        self.observed = self
            .observed
            .checked_add(u64::try_from(read).expect("read length fits u64"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CAR length overflowed"))?;
        if self.observed > self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staged publication CAR exceeded its committed length",
            ));
        }
        if self.observed == self.expected_size {
            self.validate_complete_snapshot()?;
            self.complete = true;
        }
        Ok(read)
    }
}
/// Classification for a transport or remote-state failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationBackendFailureClass {
    /// Retrying the same idempotent transition may succeed.
    Retryable,
    /// Retrying without changing external state cannot succeed.
    Permanent,
}
/// Redacted backend failure carrying only a stable public code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationBackendError {
    class: PublicationBackendFailureClass,
    code: String,
}
impl PublicationBackendError {
    /// Construct a retryable backend failure from a bounded stable code.
    #[must_use]
    pub fn retryable(code: impl Into<String>) -> Self {
        Self::new(PublicationBackendFailureClass::Retryable, code)
    }
    /// Construct a permanent backend failure from a bounded stable code.
    #[must_use]
    pub fn permanent(code: impl Into<String>) -> Self {
        Self::new(PublicationBackendFailureClass::Permanent, code)
    }
    fn new(class: PublicationBackendFailureClass, code: impl Into<String>) -> Self {
        let candidate = code.into();
        let code = if !candidate.is_empty()
            && candidate.len() <= 96
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            candidate
        } else {
            "MUSUBI_BACKEND_FAILURE".to_owned()
        };
        Self { class, code }
    }
    /// Return whether the same idempotent call may be retried.
    #[must_use]
    pub const fn class(&self) -> PublicationBackendFailureClass {
        self.class
    }
    /// Return the stable, redacted failure code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}
impl fmt::Display for PublicationBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.code)
    }
}
impl Error for PublicationBackendError {}
/// Runtime publication adapter. Credentials and endpoints remain inside this object.
pub trait PublicationBackend {
    /// Return current Unix time in milliseconds for receipt validation.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the trusted publication clock cannot be sampled.
    fn current_time_ms(&mut self) -> Result<u64, PublicationBackendError>;
    /// Validate and compiler-check the clean CAR and exact dependency graph.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the exact CAR cannot be read, validated, or compiler-checked.
    fn validate_clean_package(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        car: &mut dyn Read,
    ) -> Result<PublicationValidationEvidenceV1, PublicationBackendError>;
    /// Stage the CAR only through an admitted, authenticated seed-ingress service.
    ///
    /// # Errors
    ///
    /// Returns a backend error when authenticated staging or receipt verification cannot complete.
    fn stage_authenticated_seed_ingress(
        &mut self,
        operation_id: PublicationOperationIdV1,
        expected: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &MusubiSeedIngressCarPlanV1,
        car: &mut dyn Read,
    ) -> Result<MusubiSeedIngressReceiptV1, PublicationBackendError>;
    /// Prebuild, fee-quote, and sign the exact archive-registration transaction without submitting it.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the exact registration intent cannot be built or signed.
    fn prepare_archive_registration_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        receipt: &MusubiSeedIngressReceiptV1,
    ) -> Result<PublicationArchiveRegistrationIntentV1, PublicationBackendError>;
    /// Submit or recover the exact durable registration transaction and authoritative archive.
    ///
    /// # Errors
    ///
    /// Returns a backend error when transaction status, submission, or finalized archive recovery
    /// is unavailable or invalid.
    fn submit_or_recover_archive_registration(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        intent: &PublicationArchiveRegistrationIntentV1,
    ) -> Result<PublicationArchiveRegistrationAdvanceV1, PublicationBackendError>;
    /// Revalidate or extend the compact provider-sidecar anchor before any proof submission.
    ///
    /// Backends that do not use detached provider-registration sidecars may retain this ready
    /// default. Production Musubi returns `Updated` after installing each new immutable sidecar;
    /// the engine journals that anchor and stops before the sidecar transaction can be submitted.
    ///
    /// # Errors
    ///
    /// Returns a backend error when provider sidecars cannot be revalidated or extended safely.
    fn checkpoint_archive_location_provider_registrations(
        &mut self,
        _operation_id: PublicationOperationIdV1,
        _request: &PublicationRequestV1,
        _registered: &PublicationRegisteredArchiveV1,
        _generation: u8,
        _prior_location_ids: &[MusubiArchiveLocationIdV1],
        _checkpoint: Option<&PublicationProviderRegistrationCheckpointV1>,
    ) -> Result<PublicationProviderRegistrationCheckpointAdvanceV1, PublicationBackendError> {
        Ok(PublicationProviderRegistrationCheckpointAdvanceV1::Ready)
    }
    /// Coordinate and sign one exact location CAS without submitting it.
    ///
    /// # Errors
    ///
    /// Returns a backend error when storage coordination, fee quotation, or exact CAS signing fails.
    fn prepare_archive_location_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        generation: u8,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationIntentV1, PublicationBackendError>;
    /// Submit or recover the exact journaled location CAS and finalized directory state.
    ///
    /// # Errors
    ///
    /// Returns a backend error when location submission, status recovery, or finalized directory
    /// retrieval fails.
    fn submit_or_recover_archive_location(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        intent: &PublicationArchiveLocationIntentV1,
        prior_location_ids: &[MusubiArchiveLocationIdV1],
    ) -> Result<PublicationArchiveLocationAdvanceV1, PublicationBackendError>;
    /// Poll finalized provider completions and return a healthy location at quorum.
    ///
    /// # Errors
    ///
    /// Returns a backend error when finalized replication state cannot be queried or verified.
    fn finalized_replication(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registration: &PublicationArchiveRegistrationV1,
    ) -> Result<PublicationReplicationAdvanceV1, PublicationBackendError>;
    /// Read and fully verify the archive through one selected finalized provider.
    ///
    /// # Errors
    ///
    /// Returns a backend error when provider readback or complete archive verification fails.
    fn readback_provider(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        registered: &PublicationRegisteredArchiveV1,
        location: &MusubiArchiveLocationV1,
        provider: ProviderId,
    ) -> Result<PublicationReadbackEvidenceV1, PublicationBackendError>;
    /// Prebuild, fee-quote, and sign one exact release transaction without submitting it.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the exact release transaction cannot be built, quoted, or
    /// signed against the supplied preparation floor.
    fn prepare_release_submission_intent(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        preparation: &PublicationReleasePreparationFloorV1,
    ) -> Result<PublicationReleaseSubmissionIntentV1, PublicationBackendError>;
    /// Query status first, then submit or replay the exact journaled release transaction.
    ///
    /// When `allow_absent_submission` is false, an absent transaction must remain unsent; exact
    /// pending, applied, and terminal status recovery remains available.
    ///
    /// # Errors
    ///
    /// Returns a backend error when authoritative status recovery or permitted exact submission
    /// cannot complete.
    fn submit_or_recover_release_submission(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        intent: &PublicationReleaseSubmissionIntentV1,
        allow_absent_submission: bool,
    ) -> Result<PublicationReleaseSubmissionAdvanceV1, PublicationBackendError>;
    /// Poll finality and query both the exact home record and exact universal index row.
    ///
    /// # Errors
    ///
    /// Returns a backend error when synchronized finalized release projections cannot be queried.
    fn finalized_release_and_index(
        &mut self,
        operation_id: PublicationOperationIdV1,
        request: &PublicationRequestV1,
        submission: &PublicationAmxSubmissionV1,
    ) -> Result<Option<PublicationFinalEvidenceV1>, PublicationBackendError>;
}
/// One step of a resumable publication.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed engine result returns complete publication evidence inline without changing its stable API"
)]
pub enum PublicationAdvanceV1 {
    /// A durable transition completed and the journal now names this phase.
    Progressed(PublicationPhaseV1),
    /// Finalized external state is not ready; retry from the unchanged phase.
    Pending(PublicationPhaseV1),
    /// Exact home and universal-index verification completed.
    Complete(PublicationResultV1),
}
/// Durable operation-journal storage below an explicit user-level state root.
#[derive(Debug)]
pub struct PublicationJournalStore {
    root: AtomicWriteRoot,
    directory: PrivateDirectory,
}
struct PublicationOperationLockV1<'a> {
    file: File,
    identity: FileIdentity,
    directory: &'a PrivateDirectory,
    name: String,
}
impl PublicationOperationLockV1<'_> {
    fn validate(&self) -> Result<(), PublicationError> {
        // Reopen without creation through the retained private parent. This validates the
        // current ACL/mode and single-link custody in addition to matching the held object.
        let named = self
            .directory
            .open_existing_lock(&self.name)
            .map_err(journal_custody_error)?;
        let opened = self.file.metadata().map_err(PublicationError::JournalIo)?;
        if opened.len() != 0
            || named.metadata().map_err(PublicationError::JournalIo)?.len() != 0
            || FileIdentity::of(&self.file).map_err(PublicationError::JournalIo)? != self.identity
            || FileIdentity::of(&named).map_err(PublicationError::JournalIo)? != self.identity
        {
            return Err(PublicationError::InvalidJournal(
                "publication operation lock changed identity".to_owned(),
            ));
        }
        self.directory.revalidate().map_err(journal_custody_error)
    }
    fn finish<T>(self, result: Result<T, PublicationError>) -> Result<T, PublicationError> {
        let unlock = File::unlock(&self.file).map_err(PublicationError::JournalIo);
        match result {
            Err(error) => Err(error),
            Ok(value) => unlock.map(|()| value),
        }
    }
}
impl PublicationJournalStore {
    /// Open or create the private `publication-v1` journal directory.
    ///
    /// # Errors
    ///
    /// Returns a journal error when the existing state root or private publication directory
    /// cannot be opened, created, synchronized, or proven to retain native owner custody.
    pub fn open(user_state_root: &Path) -> Result<Self, PublicationError> {
        Self::open_with_creation(user_state_root, true)
    }
    /// Open retained publication custody without creating its root or inner journal directory.
    ///
    /// All generated actions use original custody initialized before generation publication.
    /// A missing retained directory is a custody refusal, never an empty new operation history.
    /// # Errors
    /// Refuses missing, unsafe or changed custody and native I/O failures.
    pub fn open_existing(user_state_root: &Path) -> Result<Self, PublicationError> {
        Self::open_with_creation(user_state_root, false)
    }
    fn open_with_creation(user_state_root: &Path, create: bool) -> Result<Self, PublicationError> {
        let root = AtomicWriteRoot::new(user_state_root).map_err(PublicationError::JournalWrite)?;
        let directory = if create {
            publication_client_journal::open_or_create(root.path())
        } else {
            publication_client_journal::open_existing(root.path())
        }
        .map_err(journal_custody_error)?;
        Ok(Self { root, directory })
    }
    /// Persist a new operation, or return the identical existing operation idempotently.
    ///
    /// # Errors
    ///
    /// Returns a publication error when the request is invalid, the operation identity collides,
    /// the operation lock cannot be acquired, or the journal cannot be persisted safely.
    pub fn create(
        &self,
        request: PublicationRequestV1,
    ) -> Result<PublicationJournalV1, PublicationError> {
        let journal = PublicationJournalV1::new(request)?;
        let operation_lock = self.lock_operation(journal.operation_id)?;
        let result = (|| {
            match self.load(journal.operation_id) {
                Ok(existing) if existing.request == journal.request => return Ok(existing),
                Ok(_) => {
                    return Err(PublicationError::InvalidJournal(
                        "operation id collision has different immutable request bytes".to_owned(),
                    ));
                }
                Err(PublicationError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
            operation_lock.validate()?;
            self.write(&journal)?;
            operation_lock.validate()?;
            Ok(journal)
        })();
        operation_lock.finish(result)
    }
    /// Load and fully validate one journal by typed operation id.
    ///
    /// # Errors
    ///
    /// Returns not-found, journal I/O, or invalid-journal errors when the bounded private
    /// journal cannot be read through retained custody, decoded canonically, or fully validated.
    pub fn load(
        &self,
        operation_id: PublicationOperationIdV1,
    ) -> Result<PublicationJournalV1, PublicationError> {
        let name = format!("{operation_id}.{JOURNAL_EXTENSION}");
        #[cfg(all(test, unix))]
        substitute_publication_read_target_with_fifo_for_test(&self.directory.path().join(&name))
            .map_err(PublicationError::JournalIo)?;
        let bytes = self
            .directory
            .read_optional(&name, MAX_JOURNAL_BYTES_USIZE)
            .map_err(journal_custody_error)?
            .ok_or(PublicationError::NotFound(operation_id))?;
        let journal = decode_publication_journal(&bytes)?;
        if journal.operation_id != operation_id {
            return Err(PublicationError::InvalidJournal(
                "journal filename and encoded operation id differ".to_owned(),
            ));
        }
        journal.validate()?;
        Ok(journal)
    }
    fn write(&self, journal: &PublicationJournalV1) -> Result<(), PublicationError> {
        journal.validate()?;
        let bytes = norito::encode_canonical(journal).map_err(|error| {
            PublicationError::InvalidJournal(format!(
                "journal could not be canonically encoded: {error}"
            ))
        })?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(PublicationError::InvalidJournal(
                "journal exceeds its fixed size bound".to_owned(),
            ));
        }
        self.directory
            .write_atomic(
                format!("{}.{}", journal.operation_id, JOURNAL_EXTENSION),
                &bytes,
                PublishMode::Replace,
            )
            .map_err(journal_custody_error)
    }
    fn transition(
        &self,
        previous: &PublicationJournalV1,
        mut next: PublicationJournalV1,
    ) -> Result<PublicationJournalV1, PublicationError> {
        let operation_lock = self.lock_operation(previous.operation_id)?;
        let result = (|| {
            let current = self.load(previous.operation_id)?;
            if current.revision != previous.revision || current != *previous {
                return Err(PublicationError::ConcurrentJournalUpdate);
            }
            if !archive_registration_attempts_are_append_only(
                &previous.archive_registration_attempts,
                &next.archive_registration_attempts,
            ) {
                return Err(PublicationError::InvalidJournal(
                    "archive-registration attempt history is not append-only".to_owned(),
                ));
            }
            if !archive_location_attempts_are_append_only(
                &previous.archive_location_attempts,
                &next.archive_location_attempts,
            ) {
                return Err(PublicationError::InvalidJournal(
                    "archive-location attempt history is not append-only".to_owned(),
                ));
            }
            if !provider_registration_checkpoints_are_append_only(
                &previous.provider_registration_checkpoints,
                &next.provider_registration_checkpoints,
            ) {
                return Err(PublicationError::InvalidJournal(
                    "provider-registration checkpoint history is not append-only".to_owned(),
                ));
            }
            if !release_submission_attempts_are_append_only(
                &previous.release_submission_attempts,
                &next.release_submission_attempts,
            ) {
                return Err(PublicationError::InvalidJournal(
                    "release-submission attempt history is not append-only".to_owned(),
                ));
            }
            if previous.completion.is_some() && previous.completion != next.completion {
                return Err(PublicationError::InvalidJournal(
                    "compact final checkpoint is not append-only".to_owned(),
                ));
            }
            next.revision = previous.revision.checked_add(1).ok_or_else(|| {
                PublicationError::InvalidJournal("journal revision overflowed".to_owned())
            })?;
            operation_lock.validate()?;
            self.write(&next)?;
            operation_lock.validate()?;
            let persisted = self.load(next.operation_id)?;
            if persisted != next {
                return Err(PublicationError::ConcurrentJournalUpdate);
            }
            Ok(persisted)
        })();
        operation_lock.finish(result)
    }
    fn lock_operation(
        &self,
        operation_id: PublicationOperationIdV1,
    ) -> Result<PublicationOperationLockV1<'_>, PublicationError> {
        let name = format!("{operation_id}.{JOURNAL_LOCK_EXTENSION}");
        let file = self
            .directory
            .open_lock(&name)
            .map_err(journal_custody_error)?;
        if file.metadata().map_err(PublicationError::JournalIo)?.len() != 0 {
            return Err(PublicationError::InvalidJournal(
                "publication operation lock is not a private empty regular file".to_owned(),
            ));
        }
        file.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => PublicationError::ConcurrentJournalUpdate,
            fs::TryLockError::Error(error) => PublicationError::JournalIo(error),
        })?;
        let operation_lock = PublicationOperationLockV1 {
            identity: FileIdentity::of(&file).map_err(PublicationError::JournalIo)?,
            file,
            directory: &self.directory,
            name,
        };
        operation_lock.validate()?;
        Ok(operation_lock)
    }
}
fn release_successor_preparation_is_ready(
    journal: &PublicationJournalV1,
    preparation: &PublicationReleasePreparationFloorV1,
) -> Result<bool, PublicationError> {
    let Some(previous) = journal.release_submission_attempts.last() else {
        return Ok(true);
    };
    let Some(PublicationReleaseSubmissionOutcomeV1::Terminal(terminal)) = &previous.outcome else {
        return Err(PublicationError::InvalidJournal(
            "a new release intent requires terminal evidence for the preceding attempt".to_owned(),
        ));
    };
    let prior_snapshot = terminal.absence().snapshot();
    let next_snapshot = preparation.replication.finalized_page.snapshot;
    if next_snapshot.finalized_height < prior_snapshot.finalized_height
        || next_snapshot.index_revision < prior_snapshot.index_revision
        || (next_snapshot.finalized_height == prior_snapshot.finalized_height
            && next_snapshot.finalized_block_hash != prior_snapshot.finalized_block_hash)
    {
        return Ok(false);
    }
    let PublicationReleaseSubmissionTerminalReasonV1::RegistryRejected { block_height, .. } =
        &terminal.reason
    else {
        return Ok(true);
    };
    let prior_location = previous.intent.preparation.location().ok_or_else(|| {
        PublicationError::InvalidJournal(
            "release terminal is missing its exact preparation location".to_owned(),
        )
    })?;
    let next_location = preparation.location().ok_or_else(|| {
        PublicationError::InvalidJournal(
            "release successor is missing its exact preparation location".to_owned(),
        )
    })?;
    let higher_same_location = preparation.location_generation
        == previous.intent.preparation.location_generation
        && next_location.location_id == prior_location.location_id
        && next_location.revision > prior_location.revision
        && next_location.finalized_height >= *block_height;
    let retired_then_replaced = preparation.location_generation
        > previous.intent.preparation.location_generation
        && previous
            .intent
            .preparation
            .location_generation
            .checked_sub(1)
            .map(usize::from)
            .and_then(|index| journal.archive_location_attempts.get(index))
            .and_then(|attempt| attempt.terminal.as_ref())
            .is_some_and(|location_terminal| {
                matches!(
                    location_terminal.reason,
                    PublicationArchiveLocationTerminalReasonV1::Retired
                ) && location_terminal.finalized_page.snapshot.finalized_height >= *block_height
            });
    Ok(higher_same_location || retired_then_replaced)
}
fn prepare_release_submission_attempt(
    journal: &PublicationJournalV1,
    registration: &PublicationArchiveRegistrationV1,
    replication: PublicationReplicationCheckpointV1,
    readbacks: Vec<PublicationReadbackEvidenceV1>,
    backend: &mut dyn PublicationBackend,
) -> Result<Option<PublicationReleaseSubmissionAttemptV1>, PublicationError> {
    if journal.release_submission_attempts.len() >= MUSUBI_MAX_RELEASE_SUBMISSION_ATTEMPTS_V1 {
        return Err(PublicationError::Backend(
            PublicationBackendError::permanent("RELEASE_SUBMISSION_ATTEMPT_LIMIT_REACHED"),
        ));
    }
    let preparation = PublicationReleasePreparationFloorV1::try_new(
        registration.intent.generation,
        replication,
        readbacks,
        &journal.request,
        registration,
    )?;
    if !release_successor_preparation_is_ready(journal, &preparation)? {
        return Ok(None);
    }
    let intent = backend
        .prepare_release_submission_intent(journal.operation_id, &journal.request, &preparation)
        .map_err(PublicationError::Backend)?;
    intent.validate_for(journal.operation_id, &journal.request)?;
    if intent.preparation != preparation {
        return Err(PublicationError::InvalidEvidence {
            phase: PublicationPhaseV1::ReleaseSubmission,
            reason: "prepared release intent changed its exact storage/readback floor".to_owned(),
        });
    }
    let generation = u8::try_from(journal.release_submission_attempts.len() + 1)
        .expect("release-submission attempt bound fits u8");
    Ok(Some(PublicationReleaseSubmissionAttemptV1::new(
        generation, intent,
    )))
}
include!("publish_engine.rs");
#[cfg(test)]
fn journal_relative_path(operation_id: PublicationOperationIdV1) -> PathBuf {
    Path::new(publication_client_journal::DIRECTORY_NAME)
        .join(format!("{operation_id}.{JOURNAL_EXTENSION}"))
}
#[cfg(test)]
fn operation_lock_relative_path(operation_id: PublicationOperationIdV1) -> PathBuf {
    Path::new(publication_client_journal::DIRECTORY_NAME)
        .join(format!("{operation_id}.{JOURNAL_LOCK_EXTENSION}"))
}
fn staged_car_relative_path(operation_id: PublicationOperationIdV1) -> PathBuf {
    PathBuf::from(publication_client_journal::DIRECTORY_NAME)
        .join(format!("{operation_id}.{STAGED_CAR_EXTENSION}"))
}
fn staged_plan_relative_path(operation_id: PublicationOperationIdV1) -> PathBuf {
    PathBuf::from(publication_client_journal::DIRECTORY_NAME)
        .join(format!("{operation_id}.{STAGED_PLAN_EXTENSION}"))
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(
        &u64::try_from(domain.len())
            .expect("publication domain length fits u64")
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        &u64::try_from(bytes.len())
            .expect("bounded publication payload length fits u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
fn canonical_encoded_len<T: norito::NoritoSerialize>(value: &T) -> Result<usize, String> {
    norito::encode_canonical(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("canonical Norito encoding failed: {error}"))
}
fn ensure_release_component_budget<T: norito::NoritoSerialize>(
    value: &T,
    maximum: usize,
    component: &str,
    phase: PublicationPhaseV1,
) -> Result<(), PublicationError> {
    let observed = canonical_encoded_len(value)
        .map_err(|reason| PublicationError::InvalidEvidence { phase, reason })?;
    if observed > maximum {
        return Err(PublicationError::InvalidEvidence {
            phase,
            reason: format!("{component} canonical size {observed} exceeds the limit {maximum}"),
        });
    }
    Ok(())
}
fn archive_registration_instruction_digest(instruction: &RegisterMusubiArchiveV1) -> [u8; 32] {
    let canonical = norito::encode_canonical(instruction)
        .expect("typed archive registration instruction has a canonical Norito encoding");
    domain_hash(ARCHIVE_REGISTRATION_INSTRUCTION_DOMAIN, &canonical)
}
fn archive_location_instruction_digest(instruction: &AddMusubiArchiveLocationV1) -> [u8; 32] {
    let canonical = norito::encode_canonical(instruction)
        .expect("typed archive location instruction has a canonical Norito encoding");
    domain_hash(ARCHIVE_LOCATION_INSTRUCTION_DOMAIN, &canonical)
}
fn journal_custody_error(error: io::Error) -> PublicationError {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => {
            PublicationError::InvalidJournal(format!("unsafe publication journal custody: {error}"))
        }
        _ => PublicationError::JournalIo(error),
    }
}
#[cfg(all(test, unix))]
fn substitute_publication_read_target_with_fifo_for_test(path: &Path) -> io::Result<()> {
    let substitute = TEST_PUBLICATION_READ_FIFO_SUBSTITUTIONS.with(|remaining| {
        let count = remaining.get();
        remaining.set(count.saturating_sub(1));
        count != 0
    });
    if !substitute {
        return Ok(());
    }
    fs::remove_file(path)?;
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            "test fixture could not substitute a FIFO publication input",
        ))
    }
}
#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn missing_retained_publication_directory_is_not_an_absent_operation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("operations");
        let _outer = iroha_fs::PrivateDirectory::open_or_create(&root).unwrap();
        let store = super::PublicationJournalStore::open(&root).unwrap();
        let operation = super::PublicationOperationIdV1([0x37; 32]);
        assert!(matches!(
            store.load(operation),
            Err(super::PublicationError::NotFound(actual)) if actual == operation
        ));
        let path = store.directory.path().to_path_buf();
        let moved = root.join("original-publication");
        std::fs::rename(&path, &moved).unwrap();
        let result = store.load(operation);
        std::fs::rename(&moved, &path).unwrap();
        assert!(matches!(
            result,
            Err(super::PublicationError::JournalIo(error))
                if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(matches!(
            store.load(operation),
            Err(super::PublicationError::NotFound(actual)) if actual == operation
        ));
    }

    #[test]
    fn existing_publication_journal_open_never_recreates_missing_custody() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("operations");
        assert!(super::PublicationJournalStore::open_existing(&root).is_err());
        assert!(super::PublicationJournalStore::open(&root).is_err());
        assert!(!root.exists());
        let outer = iroha_fs::PrivateDirectory::open_or_create(&root).unwrap();
        assert!(super::PublicationJournalStore::open_existing(&root).is_err());
        assert!(outer.entries(1).unwrap().is_empty());
        let created = super::PublicationJournalStore::open(&root).unwrap();
        let identity = created.directory.identity().unwrap();
        drop(created);
        let retained = super::PublicationJournalStore::open_existing(&root).unwrap();
        assert_eq!(retained.directory.identity().unwrap(), identity);
        assert!(retained.directory.entries(1).unwrap().is_empty());
        drop(retained);
        std::fs::remove_dir(root.join(super::publication_client_journal::DIRECTORY_NAME)).unwrap();
        assert!(super::PublicationJournalStore::open_existing(&root).is_err());
        assert!(outer.entries(1).unwrap().is_empty());
        drop(outer);
        std::fs::remove_dir(&root).unwrap();
        assert!(super::PublicationJournalStore::open_existing(&root).is_err());
        assert!(!root.exists());
    }

    include!("publish_fixture_tests.rs");
    include!("publish_backend_test_support.rs");
    include!("publish_recovery_tests.rs");
}

#[cfg(test)]
#[path = "publish/frame_identity_tests.rs"]
mod frame_identity_tests;
