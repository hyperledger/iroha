//! Opaque signer operations with authoritative reservation and signature-release fences.
//!
//! The operation provider has no key import, export, wrapping or generation API. An independently
//! configured state source authenticates custody state and owns durable exclusive reservations and
//! operation commits. It must not obtain its trust, clock or current head from the signing request.
//! Provider signatures remain internal until every sub-operation, durable commit and final state
//! observation succeeds. Failure leaves a recoverable reservation tombstone; it never frees an
//! operation id for an untracked retry. The source must recover committed operations explicitly.
//! This boundary verifies custody, ordering and completion, not application payload semantics.
//! Its crate-private producer must validate the canonical role/purpose request and construct
//! provenance binding the exact active custody record and current anchor before supplying bytes.
//! A nonzero request digest or a provider signature cannot replace those producer checks.
//!
//! Release manifests use the concrete purpose-bound producer and immutable private receipt journal
//! below; enrollment, renewal and terminal revocation use the authoritative control transitions.
//! TODO: Replace the remaining role service/journal private-key sites and migrate their runtime and
//! receipt consumers atomically. Configured signer and finalized state adapters remain required. This
//! module's injected test providers exercise races and failures without establishing deployment readiness.

use iroha_crypto::Signature;
use iroha_data_model::sorafs::stream_token_authority::StreamTokenReviewedV1;
use sorafs_manifest::signer::{
    custody::{
        SignerCustodyBindingV1, SignerCustodyErrorV1, SignerCustodyTrustV1,
        SignerCustodyUseContextV1, VerifiedSignerCustodyV1, verify_signer_custody_use_v1,
    },
    protocol::{
        SignerKeyOperationPurposeV1, SignerOperationActionV1, SignerOperationAuditHeadV1,
        SignerOperationCommitmentV1, SignerOperationCustodyV1, SignerOperationIntentV1,
        SignerOperationReservationV1, SignerRoleV1,
    },
    stream_token::{SignerStreamTokenExpectedV1, SignerStreamTokenRequestV1},
};
use sorafs_manifest::{StreamTokenBodyV1, token::STREAM_TOKEN_SIGNATURE_DOMAIN_V1};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

mod authority;
/// Authoritative enrollment and terminal custody-control transitions.
pub mod control;
/// Owner-only supervisor-credential software key provider for opaque operations.
pub mod credential_provider;
/// Canonical final-promotion producer with immutable receipts and fresh audit predecessors.
// TODO: Compile the final-promotion producer outside tests once a configured finalized state
// source and the production signing command own it; until then only its unit tests reach it.
#[cfg(all(unix, test))]
pub mod final_promotion;
/// Immutable bounded receipt staging shared by canonical signer operation producers.
pub mod journal;
mod recovery;
use authority::SignerOperationAuthorityV1;
pub use authority::SignerOperationFinalizedReadSourceV1;
/// Exact reviewed release-manifest producer with mandatory durable private receipt staging.
// TODO: Compile the release-manifest producer outside tests once the canonical runtime/CLI
// contract and a configured state source own it; until then only its unit tests reach it.
#[cfg(all(unix, test))]
pub mod release_manifest;
/// Provider-scoped stream-token producer with durable recovery and no raw signature output.
pub mod stream_token;
use recovery::{RecoveredSignerOperationV1, RecoveredSignerSignatureV1};

const SIGNER_MAX_REQUEST_PAYLOAD_BYTES_V1: usize = 32 * 1024 * 1024;
const SIGNER_MAX_SIGNATURE_BYTES_V1: usize = 4 * 1024;

const SIGNATURES_DOMAIN: &[u8] = b"iroha.sorafs.signer.operation.signatures.v1";
const MAX_RESERVATION_MS: u64 = 60_000;

/// Privately constructed request for one authoritative exclusive reservation.
pub struct SignerOperationReservationRequestV1<'a> {
    intent: &'a SignerOperationIntentV1,
    intent_digest: [u8; 32],
    custody: &'a VerifiedSignerCustodyV1,
}
impl SignerOperationReservationRequestV1<'_> {
    /// Exact action and journal predecessor to compare and reserve atomically.
    #[must_use]
    pub const fn intent(&self) -> &SignerOperationIntentV1 {
        self.intent
    }
    /// Canonical digest of the exact intent.
    #[must_use]
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }
    /// Independently verified active generation and current custody control-state expectation.
    #[must_use]
    pub const fn custody(&self) -> &VerifiedSignerCustodyV1 {
        self.custody
    }
}

/// Sealed, purpose-bound role-11 review presented only with the exact Reserve CAS.
///
/// Its constructor is private to the canonical stream-token service/coordinator. A native source
/// must still independently authenticate finalized custody, the audit predecessor and CAS state.
pub struct SignerStreamTokenReservationReviewV1<'a> {
    body: &'a StreamTokenBodyV1,
    signing_payload: &'a [u8],
    reviewed: &'a StreamTokenReviewedV1,
}
impl SignerStreamTokenReservationReviewV1<'_> {
    /// Exact canonical body from which the request and time window were derived.
    #[must_use]
    pub const fn body(&self) -> &StreamTokenBodyV1 {
        self.body
    }
    /// Exact domain-prefixed canonical bytes that the role key will sign.
    #[must_use]
    pub const fn signing_payload(&self) -> &[u8] {
        self.signing_payload
    }
    /// Exact body, original custody and audit-predecessor claim to submit as native Reserve.
    #[must_use]
    pub const fn reviewed(&self) -> &StreamTokenReviewedV1 {
        self.reviewed
    }
}

/// Privately constructed expectation for checking exclusive reservation ownership.
pub struct SignerOperationReservationCheckV1<'a> {
    request: SignerOperationReservationRequestV1<'a>,
    reservation: SignerOperationReservationV1,
}
impl SignerOperationReservationCheckV1<'_> {
    /// Exact intent and last verified custody state.
    #[must_use]
    pub const fn request(&self) -> &SignerOperationReservationRequestV1<'_> {
        &self.request
    }
    /// Exact unexpired reservation and fencing generation that must still be owned.
    #[must_use]
    pub const fn reservation(&self) -> SignerOperationReservationV1 {
        self.reservation
    }
}

/// Privately constructed request for durable completion of the exact reserved aggregate action.
pub struct SignerOperationCommitRequestV1<'a> {
    check: SignerOperationReservationCheckV1<'a>,
    commitment: SignerOperationCommitmentV1,
    signatures_digest: [u8; 32],
    original_custody: SignerOperationCustodyV1,
}
impl SignerOperationCommitRequestV1<'_> {
    /// Exact reservation ownership and current custody state to compare atomically.
    #[must_use]
    pub const fn check(&self) -> &SignerOperationReservationCheckV1<'_> {
        &self.check
    }
    /// Exact durably persisted audit successor and response to commit.
    #[must_use]
    pub const fn commitment(&self) -> SignerOperationCommitmentV1 {
        self.commitment
    }
    /// Digest of every ordered purpose, exact signing message and provider signature.
    #[must_use]
    pub const fn signatures_digest(&self) -> [u8; 32] {
        self.signatures_digest
    }
    /// Exact original custody identity to persist and compare on every completed-row observation.
    #[must_use]
    pub const fn original_custody(&self) -> SignerOperationCustodyV1 {
        self.original_custody
    }
}

/// Exact fresh observation point while an exclusive reservation is still live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerReservedObservationPhaseV1 {
    /// Immediately before an opaque key operation or initial reserved admission.
    BeforeProvider,
    /// Immediately after the opaque provider returns, before retaining its signature.
    AfterProvider,
    /// Immediately before the authoritative completion or control transition CAS.
    BeforeCommit,
}

/// Exact fresh observation point after an immutable completed operation exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerCommittedObservationPhaseV1 {
    /// Authenticate exact durable completion after CAS or at the beginning of recovery.
    AfterCommit,
    /// Reobserve exact completion and custody immediately before exposing signatures.
    BeforeRelease,
}

/// Raw authoritative response used only to prepare a fresh ordinary signing intent.
///
/// Both fields must be authenticated for the same binding from the exact same finalized source
/// snapshot. This is not a verified marker. Signed current-only custody observation evidence does
/// not commit the audit head and, by itself, cannot implement this response. The source must
/// independently authenticate that head and atomically compare it with custody during reservation.
pub struct SignerOperationSigningStateV1 {
    /// Fresh exact active custody, policy, revocation, finalized anchor and trusted time.
    pub custody: SignerCustodyUseContextV1,
    /// Exact currently committed per-binding audit predecessor, including the empty initial head.
    pub audit_head: SignerOperationAuditHeadV1,
}

/// Independently configured custody observations and durable ordinary-operation authority.
///
/// Implementations authenticate finalized per-role custody control state, trust and current time
/// independently of candidate requests. Reservations/journal commits are outside the custody
/// control-state digest. Every CAS must compare the exact role, active record/generation/control
/// state, action, operation id, request digest, journal predecessor and reservation fence. Expired,
/// failed or abandoned reservations retain replay tombstones; they cannot silently become fresh
/// operations. Authenticated software providers are supported; an in-memory journal or an
/// unauthenticated local-state fallback cannot replace finalized durable operation authority.
/// Enrollment and audited terminal custody mutation require the separate explicit
/// [`control::SignerCustodyEnrollmentStateSourceV1`] and
/// [`control::SignerCustodyControlStateSourceV1`] capabilities.
pub trait SignerOperationStateSourceV1: Send + Sync {
    /// Authenticate a fresh signing snapshot and its exact current per-binding audit predecessor.
    ///
    /// Both fields must come from the same finalized authoritative snapshot for `binding`.
    /// Neither a caller-supplied head, constructor-cached head nor current-only signed custody
    /// evidence establishes this response. Reservation CAS must compare this exact head together
    /// with verified active custody; races fail closed without replacing the prepared intent.
    /// Recovery does not call this method or substitute a newer predecessor into an old receipt.
    ///
    /// # Errors
    /// Fails unless both the exact current custody and audit head can be independently authenticated.
    fn observe_signing_state(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerOperationSigningStateV1, SignerOperationErrorV1>;

    /// Read a fresh independently authenticated active-head, policy and revocation snapshot.
    ///
    /// # Errors
    /// Fails when a fresh authoritative snapshot cannot be authenticated.
    fn observe(
        &self,
        binding: &SignerCustodyBindingV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1>;

    /// Durably reserve the exact next journal slot under exclusive ownership using CAS.
    ///
    /// # Errors
    /// Fails on custody drift, journal drift, replay, conflict or inability to persist the fence.
    fn reserve(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1>;

    /// Reserve a role-11 operation using the sealed canonical body and reviewed request.
    ///
    /// Implementations must rederive the body window and request digest from these exact inputs,
    /// then durably submit and authenticate the native Reserve under the original custody and
    /// audit predecessor. The generic `reserve` method does not receive a role-11 Sign operation.
    ///
    /// # Errors
    /// Fails on substituted body/request, custody or audit drift, replay, or unavailable finality.
    fn reserve_stream_token(
        &self,
        request: &SignerOperationReservationRequestV1<'_>,
        review: &SignerStreamTokenReservationReviewV1<'_>,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1>;

    /// Authenticate exact still-exclusive, unexpired ownership and return fresh custody state.
    ///
    /// Obtain a new authenticated observation for this exact phase and reserved operation.
    /// A cached pre-provider response cannot stand in for an after-provider or before-commit read.
    ///
    /// # Errors
    /// Fails on a lost fence, changed predecessor, expiry, unavailable state or custody drift.
    fn observe_reserved(
        &self,
        check: &SignerOperationReservationCheckV1<'_>,
        phase: SignerReservedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1>;

    /// Atomically compare all expectations, verify durable audit/response persistence and commit.
    ///
    /// The returned context is authenticated after the durable completion transaction. Success
    /// must prove completion before the reservation's exclusive expiry, never precede persistence
    /// or be synthesized from the request. Finality and observation may occur after that expiry;
    /// current custody must remain eligible. This ordinary-use CAS cannot rotate or revoke custody.
    ///
    /// # Errors
    /// Fails closed if the exact reservation and immutable successor cannot be committed.
    fn commit(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1>;

    /// Independently authenticate the exact durable completed operation and fresh custody state.
    ///
    /// Each phase requires a fresh independently authenticated observation of this exact operation.
    /// `AfterCommit` evidence cannot satisfy the later `BeforeRelease` boundary.
    ///
    /// The stored completion must prove that the original exclusive reservation was committed
    /// before its expiry. Completed-response recovery may happen after that expiry; it never
    /// renews a reservation or authorizes another provider call. An abandoned reservation or a
    /// late/failed commit is not a completed operation and must remain ineligible for recovery.
    /// The original record/control-state digests must be stored and match `original_custody`;
    /// comparing only request/response/signature hashes cannot fence same-key custody renewal.
    ///
    /// # Errors
    /// Fails when completion changed, is not durable, is unavailable, or custody is ineligible.
    fn observe_committed(
        &self,
        request: &SignerOperationCommitRequestV1<'_>,
        phase: SignerCommittedObservationPhaseV1,
    ) -> Result<SignerCustodyUseContextV1, SignerOperationErrorV1>;
}

/// Privately constructed bounded exact-message request presented to an opaque key provider.
pub struct SignerKeyOperationRequestV1<'a> {
    check: SignerOperationReservationCheckV1<'a>,
    purpose: SignerKeyOperationPurposeV1,
    ordinal: u8,
    message: &'a [u8],
}
impl SignerKeyOperationRequestV1<'_> {
    /// Verified custody and exact authoritative operation reservation.
    #[must_use]
    pub const fn check(&self) -> &SignerOperationReservationCheckV1<'_> {
        &self.check
    }
    /// Exact sub-operation purpose, distinct from the custody role's application purpose.
    #[must_use]
    pub const fn purpose(&self) -> SignerKeyOperationPurposeV1 {
        self.purpose
    }
    /// One-based ordered sub-operation within this reservation; never retried by this boundary.
    #[must_use]
    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }
    /// Exact bounded signing bytes; never log or persist application payloads in provider errors.
    #[must_use]
    pub const fn message(&self) -> &[u8] {
        self.message
    }
}
impl fmt::Debug for SignerKeyOperationRequestV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerKeyOperationRequestV1")
            .field("purpose", &self.purpose)
            .field("ordinal", &self.ordinal)
            .finish_non_exhaustive()
    }
}

/// Deployment-injected signing operations, with no private-key export API.
///
/// The adapter resolves the exact opaque handle from verified authorization, uses the bound key
/// and honors the operation fence. Software and optional hardware providers share this contract.
/// Key material and credentials stay inside the adapter; no candidate record selects an implementation.
pub trait SignerKeyOperationProviderV1: Send + Sync {
    /// Sign the exact authorized message with the exact independently qualified opaque key.
    ///
    /// # Errors
    /// Returns a fixed failure class when the provider, credentials or the operation fence fail.
    fn sign(
        &self,
        request: &SignerKeyOperationRequestV1<'_>,
    ) -> Result<Signature, SignerOperationErrorV1>;
}

/// Fixed secret-free operation failures; backend messages are never retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerOperationErrorV1 {
    /// Invalid action, digest, message, bounds, signature order or successor.
    InvalidOperation,
    /// The independent custody verifier rejected the active record.
    Custody(SignerCustodyErrorV1),
    /// Active custody changed or an authoritative observation moved backwards.
    CustodyChanged,
    /// The state source could not authenticate fresh authoritative state.
    StateUnavailable,
    /// A reservation, journal predecessor, expiry or durable completion CAS failed.
    ReservationConflict,
    /// The configured signer rejected or could not perform the operation.
    ProviderUnavailable,
    /// The configured signer returned an invalid or incorrect-key/message signature.
    InvalidSignature,
    /// A previous failed sub-operation made this operation permanently unusable.
    Poisoned,
}
impl fmt::Display for SignerOperationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperation => "invalid signer operation",
            Self::Custody(_) => "signer operation custody rejected",
            Self::CustodyChanged => "signer operation custody changed",
            Self::StateUnavailable => "signer authoritative state unavailable",
            Self::ReservationConflict => "signer operation reservation conflict",
            Self::ProviderUnavailable => "signer provider operation unavailable",
            Self::InvalidSignature => "signer signature invalid",
            Self::Poisoned => "signer operation poisoned",
        })
    }
}
impl std::error::Error for SignerOperationErrorV1 {}

/// Service-owned coordinator with separately injected signer and authoritative-state owners.
pub struct SignerOperationCoordinatorV1 {
    binding: SignerCustodyBindingV1,
    record: Vec<u8>,
    trust: SignerCustodyTrustV1,
    provider: Arc<dyn SignerKeyOperationProviderV1>,
    source: Arc<dyn SignerOperationStateSourceV1>,
}
impl SignerOperationCoordinatorV1 {
    /// Verify independently supplied configuration and current state before constructing a signer.
    ///
    /// This constructor accepts only public custody metadata and opaque operations, never key
    /// material. Ordinary actions obtain new authoritative observations and reservations.
    ///
    /// # Errors
    /// Fails for invalid custody, unavailable state or untrusted expected configuration.
    pub fn new(
        binding: SignerCustodyBindingV1,
        record: Vec<u8>,
        trust: SignerCustodyTrustV1,
        provider: Arc<dyn SignerKeyOperationProviderV1>,
        source: Arc<dyn SignerOperationStateSourceV1>,
    ) -> Result<Self, SignerOperationErrorV1> {
        let coordinator = Self {
            binding,
            record,
            trust,
            provider,
            source,
        };
        coordinator.verify(&coordinator.source.observe(&coordinator.binding)?)?;
        Ok(coordinator)
    }

    fn authority(&self) -> SignerOperationAuthorityV1<'_> {
        SignerOperationAuthorityV1 {
            binding: &self.binding,
            record: &self.record,
            trust: &self.trust,
            source: &self.source,
        }
    }

    fn verify(
        &self,
        context: &SignerCustodyUseContextV1,
    ) -> Result<VerifiedSignerCustodyV1, SignerOperationErrorV1> {
        self.authority().verify(context)
    }

    /// Begin only after the trusted service has validated the canonical role/purpose request.
    #[cfg(test)]
    fn begin(
        &self,
        intent: SignerOperationIntentV1,
    ) -> Result<SignerOperationV1<'_>, SignerOperationErrorV1> {
        if self.binding.role == SignerRoleV1::StreamToken
            && intent.action == SignerOperationActionV1::Sign
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.begin_with_reservation(intent, |request| self.source.reserve(request))
    }

    /// Keep the exact reviewed body/window in scope until the native role-11 Reserve CAS.
    fn begin_stream_token(
        &self,
        intent: SignerOperationIntentV1,
        body: &StreamTokenBodyV1,
        signing_payload: &[u8],
        expected: &SignerStreamTokenExpectedV1,
        reviewed: &StreamTokenReviewedV1,
    ) -> Result<SignerOperationV1<'_>, SignerOperationErrorV1> {
        if self.binding.role != SignerRoleV1::StreamToken
            || intent.action != SignerOperationActionV1::Sign
            || reviewed.intent != intent
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        let body_bytes = signing_payload
            .strip_prefix(STREAM_TOKEN_SIGNATURE_DOMAIN_V1)
            .ok_or(SignerOperationErrorV1::InvalidOperation)?;
        norito::verify_exact_canonical_frame(body, body_bytes)
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        self.begin_with_reservation(intent, |request| {
            expected
                .validate_time_at(request.custody().verified_at_unix_ms())
                .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
            // The request constructor rederives `expected` from this exact body and fresh
            // custody. Do not allocate another intermediate expected/payload before Reserve.
            let exact = SignerStreamTokenRequestV1::new(request.custody(), expected, body)
                .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
            if reviewed.request != exact
                || reviewed.intent.request_digest
                    != exact
                        .digest()
                        .map_err(|_| SignerOperationErrorV1::InvalidOperation)?
                || reviewed.intent != *request.intent()
            {
                return Err(SignerOperationErrorV1::InvalidOperation);
            }
            self.source.reserve_stream_token(
                request,
                &SignerStreamTokenReservationReviewV1 {
                    body,
                    signing_payload,
                    reviewed,
                },
            )
        })
    }

    fn begin_with_reservation(
        &self,
        intent: SignerOperationIntentV1,
        reserve: impl FnOnce(
            &SignerOperationReservationRequestV1<'_>,
        ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1>,
    ) -> Result<SignerOperationV1<'_>, SignerOperationErrorV1> {
        let intent_digest = intent
            .digest()
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        let custody = self.verify(&self.source.observe(&self.binding)?)?;
        let reservation = reserve(&SignerOperationReservationRequestV1 {
            intent: &intent,
            intent_digest,
            custody: &custody,
        })?;
        let mut operation = SignerOperationV1 {
            coordinator: self,
            intent,
            intent_digest,
            reservation,
            custody,
            signatures: Vec::new(),
            poisoned: false,
        };
        operation.validate_reservation()?;
        operation.refresh_reserved(SignerReservedObservationPhaseV1::BeforeProvider)?;
        Ok(operation)
    }
}
impl fmt::Debug for SignerOperationCoordinatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerOperationCoordinatorV1")
            .finish_non_exhaustive()
    }
}

fn reservation_check<'a>(
    intent: &'a SignerOperationIntentV1,
    intent_digest: [u8; 32],
    custody: &'a VerifiedSignerCustodyV1,
    reservation: SignerOperationReservationV1,
) -> SignerOperationReservationCheckV1<'a> {
    SignerOperationReservationCheckV1 {
        request: SignerOperationReservationRequestV1 {
            intent,
            intent_digest,
            custody,
        },
        reservation,
    }
}

fn required_purposes(action: SignerOperationActionV1) -> &'static [SignerKeyOperationPurposeV1] {
    use SignerKeyOperationPurposeV1::{AuditRecord, Provenance, Response, RolePayload};
    match action {
        SignerOperationActionV1::Sign => &[RolePayload, AuditRecord, Provenance, Response],
        SignerOperationActionV1::Qualify | SignerOperationActionV1::Status => {
            &[AuditRecord, Provenance, Response]
        }
        SignerOperationActionV1::ActivateCustody | SignerOperationActionV1::RevokeCustody => {
            &[AuditRecord]
        }
    }
}

/// Internal in-progress action. Staged signatures never cross the public release boundary.
struct SignerOperationV1<'a> {
    coordinator: &'a SignerOperationCoordinatorV1,
    intent: SignerOperationIntentV1,
    intent_digest: [u8; 32],
    reservation: SignerOperationReservationV1,
    custody: VerifiedSignerCustodyV1,
    signatures: Vec<StagedSignature>,
    poisoned: bool,
}
struct StagedSignature {
    purpose: SignerKeyOperationPurposeV1,
    message_digest: [u8; 32],
    signature: Zeroizing<Vec<u8>>,
}
impl SignerOperationV1<'_> {
    fn check(&self) -> SignerOperationReservationCheckV1<'_> {
        reservation_check(
            &self.intent,
            self.intent_digest,
            &self.custody,
            self.reservation,
        )
    }
    fn validate_reservation(&self) -> Result<(), SignerOperationErrorV1> {
        let now = self.custody.verified_at_unix_ms();
        if self.reservation.reservation_id == [0; 32]
            || self.reservation.fence == 0
            || self.reservation.expires_at_unix_ms <= now
            || self.reservation.expires_at_unix_ms > self.custody.statement().expires_at_unix_ms
            || self.reservation.expires_at_unix_ms.saturating_sub(now) > MAX_RESERVATION_MS
        {
            return Err(SignerOperationErrorV1::ReservationConflict);
        }
        Ok(())
    }
    fn accept_custody_context(
        &mut self,
        context: &SignerCustodyUseContextV1,
    ) -> Result<(), SignerOperationErrorV1> {
        let current = self.coordinator.verify(context)?;
        if !current.continues_active_state(&self.custody) {
            return Err(SignerOperationErrorV1::CustodyChanged);
        }
        self.custody = current;
        Ok(())
    }
    fn refresh_reserved(
        &mut self,
        phase: SignerReservedObservationPhaseV1,
    ) -> Result<(), SignerOperationErrorV1> {
        let context = self
            .coordinator
            .source
            .observe_reserved(&self.check(), phase)?;
        self.accept_custody_context(&context)?;
        self.validate_reservation()
    }
    /// Prepare a sub-signature solely for internal canonical journal/response construction.
    ///
    /// The trusted producer owns exact role-payload authorization and canonical custody-bound
    /// provenance construction. This method checks purpose order, bounded bytes, cryptography and
    /// current custody; it does not derive application intent from the supplied message.
    fn sign(
        &mut self,
        purpose: SignerKeyOperationPurposeV1,
        message: &[u8],
    ) -> Result<&[u8], SignerOperationErrorV1> {
        if self.poisoned {
            return Err(SignerOperationErrorV1::Poisoned);
        }
        // Poison first: every early error, including invalid ordering, permanently fences retries.
        self.poisoned = true;
        if required_purposes(self.intent.action).get(self.signatures.len()) != Some(&purpose)
            || message.is_empty()
            || message.len() > SIGNER_MAX_REQUEST_PAYLOAD_BYTES_V1
            || (purpose != SignerKeyOperationPurposeV1::RolePayload && message.len() != 32)
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        self.refresh_reserved(SignerReservedObservationPhaseV1::BeforeProvider)?;
        let ordinal = u8::try_from(self.signatures.len() + 1)
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?;
        let signature = Zeroizing::new(self.coordinator.provider.sign(
            &SignerKeyOperationRequestV1 {
                check: self.check(),
                purpose,
                ordinal,
                message,
            },
        )?);
        if signature.payload().len() > SIGNER_MAX_SIGNATURE_BYTES_V1
            || signature
                .verify(&self.coordinator.binding.public_key, message)
                .is_err()
        {
            return Err(SignerOperationErrorV1::InvalidSignature);
        }
        self.refresh_reserved(SignerReservedObservationPhaseV1::AfterProvider)?;
        self.signatures.push(StagedSignature {
            purpose,
            message_digest: digest_parts(b"iroha.sorafs.signer.operation.message.v1", &[message]),
            signature: Zeroizing::new(signature.payload().to_vec()),
        });
        self.poisoned = false;
        self.signatures
            .last()
            .map(|signature| signature.signature.as_slice())
            .ok_or(SignerOperationErrorV1::InvalidSignature)
    }
    /// Commit the aggregate action and release signatures only after a fresh committed-state fence.
    fn finish(
        mut self,
        commitment: SignerOperationCommitmentV1,
    ) -> Result<CompletedSignerOperationV1, SignerOperationErrorV1> {
        if self.poisoned {
            return Err(SignerOperationErrorV1::Poisoned);
        }
        if matches!(
            self.intent.action,
            SignerOperationActionV1::ActivateCustody | SignerOperationActionV1::RevokeCustody
        ) {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        if self.signatures.len() != required_purposes(self.intent.action).len()
            || commitment.audit.sequence != self.intent.previous_audit.sequence + 1
            || commitment.audit.digest == [0; 32]
            || commitment.audit.digest == self.intent.previous_audit.digest
            || commitment.response_digest == [0; 32]
        {
            return Err(SignerOperationErrorV1::InvalidOperation);
        }
        for (purpose, message) in [
            (
                SignerKeyOperationPurposeV1::AuditRecord,
                commitment.audit.signing_message(),
            ),
            (
                SignerKeyOperationPurposeV1::Response,
                commitment.response_signing_message(),
            ),
        ] {
            let digest = digest_parts(b"iroha.sorafs.signer.operation.message.v1", &[&message]);
            if !self
                .signatures
                .iter()
                .any(|signature| signature.purpose == purpose && signature.message_digest == digest)
            {
                return Err(SignerOperationErrorV1::InvalidOperation);
            }
        }
        self.refresh_reserved(SignerReservedObservationPhaseV1::BeforeCommit)?;
        // Commit exact signature bytes through a domain-separated digest, without making a
        // second unzeroized copy of any unreleased signature for canonical serialization.
        let encoded_signatures = Zeroizing::new(
            norito::encode_canonical(
                &self
                    .signatures
                    .iter()
                    .map(|signature| {
                        (
                            signature.purpose,
                            signature.message_digest,
                            digest_parts(
                                b"iroha.sorafs.signer.operation.signature.v1",
                                &[signature.signature.as_slice()],
                            ),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| SignerOperationErrorV1::InvalidOperation)?,
        );
        let signatures_digest = digest_parts(SIGNATURES_DOMAIN, &[encoded_signatures.as_slice()]);
        let original_custody = SignerOperationCustodyV1::from_verified(&self.custody);
        let commit = SignerOperationCommitRequestV1 {
            check: self.check(),
            commitment,
            signatures_digest,
            original_custody,
        };
        let committed = self.coordinator.source.commit(&commit)?;
        // The source proves timely durable completion. Later finality observations must recheck
        // current custody and the exact completed row, without renewing the spent reservation.
        self.accept_custody_context(&committed)?;
        let commit = SignerOperationCommitRequestV1 {
            check: self.check(),
            commitment,
            signatures_digest,
            original_custody,
        };
        let after_commit = self
            .coordinator
            .source
            .observe_committed(&commit, SignerCommittedObservationPhaseV1::AfterCommit)?;
        self.accept_custody_context(&after_commit)?;
        let commit = SignerOperationCommitRequestV1 {
            check: self.check(),
            commitment,
            signatures_digest,
            original_custody,
        };
        let final_context = self
            .coordinator
            .source
            .observe_committed(&commit, SignerCommittedObservationPhaseV1::BeforeRelease)?;
        self.accept_custody_context(&final_context)?;
        Ok(CompletedSignerOperationV1 {
            original_custody,
            custody: self.custody,
            reservation: self.reservation,
            commitment,
            intent_digest: self.intent_digest,
            signatures_digest,
            signatures: self.signatures,
        })
    }
}

/// Privately constructed result of exact durable completion and final custody revalidation.
pub struct CompletedSignerOperationV1 {
    original_custody: SignerOperationCustodyV1,
    custody: VerifiedSignerCustodyV1,
    reservation: SignerOperationReservationV1,
    commitment: SignerOperationCommitmentV1,
    intent_digest: [u8; 32],
    signatures_digest: [u8; 32],
    signatures: Vec<StagedSignature>,
}
impl CompletedSignerOperationV1 {
    /// Exact original record/control-state identity authenticated by durable completion.
    #[must_use]
    pub const fn original_custody(&self) -> SignerOperationCustodyV1 {
        self.original_custody
    }
    /// Fresh verified active record and current finalized anchor at release.
    #[must_use]
    pub const fn custody(&self) -> &VerifiedSignerCustodyV1 {
        &self.custody
    }
    /// Exact completed reservation coordinates.
    #[must_use]
    pub const fn reservation(&self) -> SignerOperationReservationV1 {
        self.reservation
    }
    /// Exact immutable audit successor and response committed by authoritative CAS.
    #[must_use]
    pub const fn commitment(&self) -> SignerOperationCommitmentV1 {
        self.commitment
    }
    /// Canonical digest of the exact completed intent.
    #[must_use]
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }
    /// Commitment to all ordered exact-message signatures.
    #[must_use]
    pub const fn signatures_digest(&self) -> [u8; 32] {
        self.signatures_digest
    }
    /// Release one signature only from a successfully completed and fenced aggregate action.
    #[must_use]
    pub fn signature(&self, purpose: SignerKeyOperationPurposeV1) -> Option<&[u8]> {
        self.signatures
            .iter()
            .find(|signature| signature.purpose == purpose)
            .map(|signature| signature.signature.as_slice())
    }
}
impl fmt::Debug for CompletedSignerOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedSignerOperationV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;

pub(crate) fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
pub(crate) fn digest_canonical<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], ()> {
    let bytes = norito::encode_canonical(value).map_err(|_| ())?;
    Ok(digest_parts(domain, &[&bytes]))
}
