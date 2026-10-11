//! Shared wallet control around the stock-phone `Advance` custody authority.
//!
//! Frozen G1 inputs are durable before Advance. Only its retained completion authorizes a
//! completed operation; an archive, checkpoint or proof never does. Reconciliation follows
//! the provider-selected capsule chain and indexes permanent credit identities. Folding
//! consumes that chain in order, persists every sub-proof, self-verifies Ω including both
//! curve decides through [`NativeProofs`], and records exactly one Ω per head.
//!
//! The native transition/recursive relation implementation is an injected, mandatory
//! dependency. This module does not substitute a structural G1 check for a proof verifier.
//! SDKs should own I/O and call this shared state machine rather than reproduce its rules.
//!
//! Archive storage must share the provider's non-backup custody root and exclusive lifetime.
//! [`ProviderArchive`] and [`AdvanceHandle`] share one exclusive provider. Every archive call
//! uses its protected-data bracket; fixed manifests bind index roots in source-selected
//! metadata generations and the existing iOS rollback anchor. [`FsArchive`] is a low-level
//! standalone store for tests/diagnostics and does not itself provide those brackets.
//! No archive record grants monetary authority independently of Advance.
//!
//! Collection records a source-selected intent before deleting historical witness objects.
//! A newer verified Ω supplies coverage; Send additionally needs pending-map nonmembership.
//! Earned-fee Payments have separate custody until their exact finalized payout is verified.
// TODO(G3/G4): qualify the installed full-catalog native owner through wallet/SDK delivery and
// the complete custody/proof lifetime on stock phones. Run relations remain artifact-dependent.
// Persistent replay metadata and unreachable immutable index nodes remain retained; a future
// compactor must preserve source-selected reachable roots without full-history hot-path scans.

use std::collections::BTreeMap;

use iroha_data_model::kagemusha::*;

use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAdvanceOutcomeV1 as AdvanceOutcome,
    KagemushaWalletAdvanceRequestV1 as AdvanceRequest,
    KagemushaWalletExpectedHeadV1 as ExpectedHead, KagemushaWalletLookupV1 as Lookup,
    KagemushaWalletNotPerformedV1 as NotPerformed, KagemushaWalletProviderErrorV1 as ProviderError,
    KagemushaWalletRetainedV1 as Retained, KagemushaWalletSlotStatusV1 as SlotStatus,
};

mod archive;
mod capacity;
mod collection;
mod credit_tree;
mod custody;
mod fee_claims;
mod fold_custody;
mod folding;
mod index;
mod lifecycle;
mod manifest;
mod map_custody;
mod map_tree;
mod native_owner;
mod native_worker;
mod policy_custody;
pub use native_owner::{
    ActivationFinalityProgressV1, LEDGER_INSTRUCTION_MAX_BYTES_V1, LEDGER_PROOF_MAX_BYTES_V1,
    LedgerProgressV1, NativeEpochProgressV1, NativeInstallationConfigV1, NativeOpenErrorV1,
    NativeOpenFailureV1, NativeOperationReviewV1, NativePreparedLedgerLoadV1,
    NativeReleasedOutputV1, NativeStartupFailureV1, NativeWalletCoordinatorV1,
    NativeWalletMetadataV1, NativeWalletProofsV1, NativeWalletRuntimeV1,
    PAYOUT_RECORD_MAX_BYTES_V1, PendingNativeWalletOpenV1, ReviewedOperationV1,
    UnloadFinalityProgressV1,
};
mod preparation_custody;
mod scheduling;
mod session_custody;
mod snapshot;
mod transition_custody;

pub use archive::{ArchiveKey, ArchiveStore, FsArchive};
pub use collection::CollectionStatus;
pub(crate) use custody::NativeObservationsV1;
pub use custody::{
    AdvanceHandle, Custody, CustodyDeletionProgressV1, CustodyDeletionReviewV1, ProviderArchive,
    ReviewedCustodyDeletionV1, TransitionOwner,
};
pub use fee_claims::{FEE_CLAIM_MAX_BYTES_V1, FinalizedPayoutEvidence, RetainedFeeClaim};
pub use fold_custody::FoldCustodyV1;
pub use folding::{FoldStatus, LineageCache};
pub use index::{IndexRoot, ObjectStore};
pub(crate) use lifecycle::ArchiveIntentV1;
pub use lifecycle::{
    ChargeOriginalsV1, CreditProjectionV1, NativeIntentV1, NativePreparation, OperationActionV1,
    OperationRequestV1, PREPARATION_MAX_BYTES, PreparationSourceV1, REQUEST_MAX_BYTES,
    RequestStatusV1,
};
pub use map_custody::{PreparationMapV1, PreparationMapsV1};
pub(crate) use native_worker::NativeFoldWorkerV1;
pub(crate) use policy_custody::{
    BlacklistOriginalReferenceV1, publish_blacklist_original, verify_policy_update_original,
};
pub use preparation_custody::{PreparationCustodyV1, PreparationOriginalV1};
pub use scheduling::{Cancellation, PaymentGuard, Scheduler};
pub use session_custody::DirectTimeExchangeV1;
pub use snapshot::{Snapshot, SnapshotFold};
pub use transition_custody::TransitionCustodyV1;

/// Errors distinguish uncertain custody from invalid input and missing retained witnesses.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The source custody authority could not complete the request.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// A G1 object failed its canonical or native validation.
    #[error("invalid wallet object: {0}")]
    Invalid(&'static str),
    /// An I/O failure gives no evidence of absence or failure to commit.
    #[error("wallet archive unavailable: {0}")]
    Storage(#[from] std::io::Error),
    /// Required source-bound input is absent or corrupt; never wait silently for it.
    #[error("wallet fold witness custody lost: {0}")]
    WitnessLost(&'static str),
    /// Requested historical witnesses were intentionally collected after a covering fold.
    #[error("historical witnesses were collected")]
    Collected,
    /// A previously used credit identity names different canonical Payment bytes.
    #[error("conflicting Payment for an already consumed credit")]
    CreditConflict,
    /// A lifecycle operation identity already retains different exact user input.
    #[error("conflicting lifecycle request for an already retained operation")]
    OperationConflict,
    /// The operation needs Ω of the current head.
    #[error("current head is not folded")]
    FoldRequired,
    /// The selected operation has not durably completed yet.
    #[error("selected operation is pending")]
    Pending,
    /// No active or released head is available.
    #[error("wallet has no usable head")]
    NoHead,
    /// Payment work cancelled the current sub-proof.
    #[error("fold cancelled at a cooperative boundary")]
    Cancelled,
    /// Reinstallable original proving material is unavailable; monetary custody is retained.
    #[error("native proof artifacts unavailable: {0}")]
    ArtifactsUnavailable(&'static str),
    /// A required native proof, source or key failed verification.
    #[error("native proof rejected: {0}")]
    Proof(&'static str),
    /// Design §5.3: free custody storage does not cover this operation's reservation and fold
    /// witnesses. Refused before commit; nothing was debited or credited, and the retained
    /// Request, receipt or Payment stays deliverable. Retry after freeing storage.
    #[error("not enough storage for this operation")]
    NotEnoughStorage,
    /// Design §5.3: memory available to the app does not cover the peak proving memory of the
    /// installed relations. Refused before commit; nothing was debited or credited. Retry after
    /// freeing memory. Never a device verdict.
    #[error("not enough memory for this operation")]
    NotEnoughMemory,
}

fn valid<T>(result: Result<T, KagemushaWalletValidationErrorV1>) -> Result<T, Error> {
    result.map_err(|_| Error::Invalid("G1 validation"))
}

/// Immutable pre-signing inputs, including the credential needed to resume assembly.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::FrozenTransition")]
pub struct FrozenTransition {
    /// Credential of this successor head; issuer authentication belongs to `NativeProofs`.
    pub credential: KagemushaWalletCredentialV1,
    /// Marker-bound actual state, σ, map openings and retained canonical input bytes.
    pub capsule: KagemushaWalletRecoveryCapsuleV1,
}

impl FrozenTransition {
    /// Check canonical bindings; this is additional to the mandatory native verifier.
    ///
    /// # Errors
    /// Rejects malformed objects, another wallet/credential, a mismatching statement, or
    /// successor regulatory policy/lease fields that differ from the credential.
    pub fn validate(&self) -> Result<(), Error> {
        valid(self.capsule.to_canonical_bytes())?;
        valid(self.credential.validate())?;
        valid(
            self.capsule
                .successor_state
                .validate_for_credential(&self.credential),
        )?;
        valid(
            self.capsule
                .statement
                .validate_for_credential(&self.credential),
        )?;
        if self.credential.body.wallet_id != self.capsule.wallet_id {
            return Err(Error::Invalid("frozen wallet"));
        }
        Ok(())
    }

    fn expected(&self) -> Result<ExpectedHead, Error> {
        let c = &self.capsule;
        if let KagemushaWalletEffectV1::Bootstrap {
            enrollment_marker, ..
        } = c.statement.effect
        {
            Ok(ExpectedHead::Enrollment {
                marker_digest: enrollment_marker,
            })
        } else {
            Ok(ExpectedHead::Released {
                sequence: c
                    .statement
                    .sequence
                    .checked_sub(1)
                    .ok_or(Error::Invalid("sequence"))?,
                head: c.statement.predecessor,
                capsule_digest: c.predecessor_capsule_digest,
            })
        }
    }

    fn request(&self) -> Result<AdvanceRequest<KagemushaWalletRecoveryCapsuleV1>, Error> {
        Ok(AdvanceRequest {
            expected: self.expected()?,
            operation_id: self.capsule.operation_id,
            new_head: self.capsule.statement.successor,
            proof_digest: valid(self.capsule.proof_digest())?,
            capsule: self.capsule.clone(),
            // The archive has already made its growth durable. G2 reserves its own copies.
            growth_bytes: 0,
        })
    }
}

/// Mandatory native relation boundary. Implementations use the frozen artifact allowlist.
///
/// There is deliberately no default implementation. G1 structural validation is insufficient
/// for any method. A production implementation must verify σ, all consumed objects and map
/// roots before Advance, and both Pasta accumulator decides when verifying Ω.
pub trait NativeProofs {
    /// Opaque, verified inputs for the final check after durable publication.
    /// Production tokens retain no advice/proof workspace or caller-supplied verdict.
    type AdvanceCheck;

    /// Exact admitted enrollment certificate set for this generation-zero credential.
    /// Later credentials use their source-selected snapshot instead.
    ///
    /// # Errors
    /// The owner has no matching admitted credential or its retained originals are unavailable.
    fn enrollment_certificates(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> Result<Vec<u8>, Error>;
    /// Trusted scheme and Global chain label selected when the authenticated artifacts were
    /// loaded. Witnesses and payout evidence must never supply or override these identities.
    ///
    /// # Errors
    /// Artifacts or their independently configured scheme/chain binding are unavailable.
    fn ledger_scope(&self) -> Result<(KagemushaWalletSchemeV1, String), Error>;

    /// Verify exact delivery evidence against the original Request and Payment, including
    /// every native signature/binding check and the installed package or lineage proof.
    /// This read-only verdict cannot authorize Archive or replace its step and fold proofs.
    /// # Errors
    /// Invalid evidence, unavailable artifacts or cancelled verification yield no verdict.
    fn verify_credited(
        &self,
        credited: &KagemushaWalletCreditedV1,
        request: &KagemushaWalletRequestV1,
        payment: &KagemushaWalletPaymentV1,
    ) -> Result<(), Error>;

    /// Design §5.3 bounds derived from the installed, authenticated relations: the largest
    /// peak proving memory of any relation that proves a step or folds it, and the largest
    /// fold-witness storage one step adds until a durable Ω covers it. The coordinator adds
    /// the operation's own custody reservation. No phone model, class or roster is consulted.
    ///
    /// # Errors
    /// Unavailable artifacts or a descriptor whose bound cannot be computed.
    fn runtime_capacity(
        &self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1, Error>;

    /// Ordered intermediate proof layouts from the authenticated artifact schedule for this
    /// operation. The final Ω follows these checkpoints and keeps its separate wire bound.
    ///
    /// # Errors
    /// Reject unavailable artifacts or a schedule not bound to this transition's relation.
    fn fold_schedule(
        &self,
        witness: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        custody: Option<&mut FoldCustodyV1<'_>>,
    ) -> Result<Vec<CheckpointLayout>, Error>;
    /// Verify the transition, inputs and σ against the actual selected predecessor state.
    /// `folded` is the exact Ω already verified and recorded for that predecessor.
    /// `custody` holds the exact retained preparation and source-selected originals.
    ///
    /// # Errors
    /// Reject invalid/missing proofs, credentials, historical controls, amounts or map roots.
    fn verify_transition(
        &self,
        next: &FrozenTransition,
        predecessor: Option<&ReleasedStep>,
        folded: Option<&KagemushaWalletFoldRecordV1>,
        custody: &mut TransitionCustodyV1<'_>,
    ) -> Result<Self::AdvanceCheck, Error>;

    /// Consume the verified token immediately before the sole irreversible Advance.
    /// Enabled Send controls use a fresh native observation here, after archive writes.
    /// Already selected Pending/Complete retries bypass this new-operation check.
    ///
    /// # Errors
    /// Expired controls, a changed quota window charge or unavailable native clock.
    fn check_advance(&self, check: Self::AdvanceCheck) -> Result<(), Error>;

    /// Verify Ω in full, including its deferred values and both curve accumulator decides.
    ///
    /// # Errors
    /// Reject any invalid proof, binding, artifact or decide. Background callers supply
    /// their operation signal; cancellation yields no proof verdict.
    fn verify_lineage(
        &self,
        lineage: &KagemushaWalletLineageV1,
        cancellation: Option<&Cancellation>,
    ) -> Result<(), Error>;

    /// Compute exactly the next sub-proof of one released transition. `checkpoints` holds
    /// every prior original checkpoint in authenticated schedule order, after the coordinator
    /// checked its exact layout and durable source chain. Genuine native restoration must
    /// rederive each prior A/W source in order; the latest proof alone cannot supply that source.
    /// Poll cancellation at every task boundary and release proof workspaces before returning.
    ///
    /// # Errors
    /// Return `Cancelled` on preemption; reject unavailable/invalid relation inputs.
    fn fold_next(
        &self,
        witness: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        checkpoints: &[Vec<u8>],
        custody: Option<&mut FoldCustodyV1<'_>>,
        cancellation: &Cancellation,
    ) -> Result<FoldProgress, Error>;
}

/// One authenticated released transition; inputs and output remain byte-exact.
#[derive(Debug, Clone)]
pub struct ReleasedStep {
    /// Frozen capsule and credential selected by Advance.
    pub frozen: FrozenTransition,
    /// Original retained completion; never assembled again after release.
    pub retained: Retained<KagemushaWalletCompletionRecordV1>,
}

/// Exact intermediate output layout from the authenticated native proof schedule.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::CheckpointLayout")]
pub struct CheckpointLayout {
    /// Digest binding the proof type, curve, stage and exact circuit/descriptor.
    pub artifact_digest: [u8; 32],
    /// Exact checkpoint payload length, derived from that descriptor's proof layout.
    pub payload_bytes: u32,
}

impl CheckpointLayout {
    fn record_limit(self) -> Result<usize, Error> {
        if self.artifact_digest == [0; 32] || self.payload_bytes == 0 {
            return Err(Error::Proof("checkpoint layout"));
        }
        usize::try_from(self.payload_bytes)
            .ok()
            .and_then(|n| n.checked_add(archive::METADATA_BOUND))
            .ok_or(Error::Proof("checkpoint layout size"))
    }
}

/// One sub-proof result, checked against the authenticated native stage's exact layout.
#[derive(Debug, Clone)]
pub enum FoldProgress {
    /// Persist this result before asking for the next sub-proof.
    Checkpoint(Vec<u8>),
    /// Final Ω. A Receive's burn result determines its first credit-digest leaf.
    Complete {
        /// Candidate lineage, verified natively before it becomes folded.
        lineage: KagemushaWalletLineageV1,
        /// Must be false for a non-Receive operation.
        burned: bool,
    },
}

/// What the caller may display after a serialized transition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// Original released output bytes. This is the only successful completion result.
    Complete(Vec<u8>),
    /// Fresh CreditStatus for an identical duplicate Receive whose old evidence was collected.
    CreditStatus(Vec<u8>),
    /// A selected or uncertain operation needs reconciliation, never a new debit.
    Pending,
    /// The custody authority definitively did not select the operation.
    NotPerformed(NotPerformed),
    /// A retained result was pruned after its permanent tombstone.
    Archived,
    /// Released bytes were lost; the debit remains committed.
    DeliveryDataLoss,
}

/// Permanent native replay entry. Payment digest is outside the monetary σ state leaf.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ConsumedCredit")]
pub struct ConsumedCredit {
    /// First canonical Payment digest, never replaced on duplicate delivery.
    pub payment_digest: [u8; 32],
    /// Amount of the first credit.
    pub amount: u128,
    /// Sequence of the crediting Receive.
    pub sequence: u128,
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::Checkpoint")]
struct Checkpoint {
    layout: CheckpointLayout,
    capsule_digest: [u8; 32],
    predecessor_fold: [u8; 32],
    previous: [u8; 32],
    ordinal: u32,
    proof: Vec<u8>,
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::RecordedFold")]
struct RecordedFold {
    record: KagemushaWalletFoldRecordV1,
    burned: bool,
}

/// Shared Rust coordinator. The owned custody handle serializes all monetary transitions.
///
/// Permanent replay/step/fold indexes and the credit-digest tree have source-selected roots.
/// Normal operations traverse bounded paths; interrupted indexing streams one tail capsule
/// at a time. Collection removes covered historical witness objects in bounded turns, while
/// unresolved Sends and unpaid fee-claim Payments retain separate durable custody.
pub struct Coordinator<C, A, N> {
    custody: C,
    archive: A,
    proofs: N,
    scheme_id: [u8; 32],
    wallet_id: [u8; 32],
    scheduler: Scheduler,
    verified_folds: BTreeMap<u128, Vec<u8>>,
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    #[cfg(test)]
    fn new(
        custody: C,
        archive: A,
        proofs: N,
        scheme_id: [u8; 32],
        wallet_id: [u8; 32],
    ) -> Result<Self, Error> {
        let mut this = Self {
            custody,
            archive,
            proofs,
            scheme_id,
            wallet_id,
            scheduler: Scheduler::new(),
            verified_folds: BTreeMap::new(),
        };
        this.initialize()?;
        Ok(this)
    }

    // The sole production caller retains this draft until initialization succeeds.
    // A failed read never consumes the provider or its original proving store.
    fn initialize(&mut self) -> Result<(), Error> {
        let (scheme, chain) = self.proofs.ledger_scope()?;
        valid(scheme.validate())?;
        if scheme.scheme_id() != self.scheme_id
            || chain.is_empty()
            || chain.len() > 1024
            || chain.chars().any(char::is_control)
        {
            return Err(Error::Invalid("native artifact ledger scope"));
        }
        if self.archive.binding() != (self.scheme_id, self.wallet_id) {
            return Err(Error::Invalid("archive incarnation"));
        }
        if !matches!(self.status()?, SlotStatus::Pending(_)) {
            let (_, manifest) = self.sync_manifest()?;
            if let Some(sequence) = manifest.folded {
                let step = self.indexed_step(&manifest, sequence)?;
                self.read_fold(&step)?;
            }
        }
        Ok(())
    }

    /// Share the scheduler with the UI/transport so payment arrival can preempt proving.
    #[must_use]
    pub fn scheduler(&self) -> Scheduler {
        self.scheduler.clone()
    }

    fn status(&mut self) -> Result<SlotStatus, Error> {
        let status = self.custody.status()?;
        if let Some(record) = status.marker() {
            let marker = record.marker();
            if marker.scheme_id != self.scheme_id || marker.wallet_id != self.wallet_id {
                return Err(Error::Invalid("provider incarnation"));
            }
        }
        Ok(status)
    }

    fn frozen(&mut self, digest: [u8; 32]) -> Result<FrozenTransition, Error> {
        let bytes = self
            .archive
            .get(
                ArchiveKey::Capsule(digest),
                KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1
                    + KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
                    + archive::METADATA_BOUND,
            )?
            .ok_or(Error::WitnessLost("selected capsule"))?;
        let frozen: FrozenTransition = archive::decode(&bytes)?;
        frozen.validate()?;
        if frozen.capsule.scheme_id != self.scheme_id
            || frozen.capsule.wallet_id != self.wallet_id
            || valid(frozen.capsule.capsule_digest())? != digest
        {
            return Err(Error::WitnessLost("capsule binding"));
        }
        Ok(frozen)
    }

    /// Explicit diagnostic export of the released chain, never inferred from filenames.
    /// This opt-in export allocates the full history; no normal coordinator operation uses it.
    ///
    /// # Errors
    /// Pending custody is `Pending`; intentional witness collection is `Collected`, while
    /// missing/corrupt retained witnesses outside a selected collection are custody loss.
    pub fn released_steps(&mut self) -> Result<Vec<ReleasedStep>, Error> {
        let (_, manifest) = self.sync_manifest()?;
        let Some(last) = manifest.indexed else {
            return Ok(Vec::new());
        };
        let mut steps = Vec::new();
        let mut predecessor = KagemushaWalletStateCommitmentV1 { value: [0; 32] };
        let mut previous_capsule = [0; 32];
        for sequence in 0..=last {
            // Intentional collection has its own error; it must not be relabelled custody loss.
            let step = self.indexed_step(&manifest, sequence)?;
            let capsule = &step.frozen.capsule;
            if capsule.statement.predecessor != predecessor
                || capsule.predecessor_capsule_digest != previous_capsule
            {
                return Err(Error::WitnessLost("capsule chain"));
            }
            predecessor = capsule.statement.successor;
            previous_capsule = valid(capsule.capsule_digest())?;
            steps.push(step);
        }
        self.status()?;
        Ok(steps)
    }

    /// Find a permanent Receive, including after unrelated operations or a restart.
    ///
    /// # Errors
    /// Reject conflicting Payment bytes and propagate custody/reconciliation failures.
    pub fn consumed_credit(
        &mut self,
        credit_id: &[u8; 32],
        payment_digest: &[u8; 32],
    ) -> Result<Option<ConsumedCredit>, Error> {
        let (_, manifest) = self.sync_manifest()?;
        let credit = self.indexed_credit(&manifest, credit_id)?;
        if credit.is_some_and(|entry| entry.payment_digest != *payment_digest) {
            return Err(Error::CreditConflict);
        }
        Ok(credit)
    }

    /// Return an operation's exact source-bound output; never construct another Payment.
    ///
    /// # Errors
    /// Provider unavailability is retriable and does not imply an unknown operation.
    pub fn retry(&mut self, operation_id: &[u8; 32]) -> Result<Option<Completion>, Error> {
        // Lookup owns reconciliation and both storage probes, including delivery-loss
        // classification. A separate status call could hide that authoritative classification.
        Ok(match self.custody.lookup(operation_id)? {
            Lookup::Retained(retained) => Some(Completion::Complete(retained.record.output)),
            Lookup::SelectedUnsigned { .. } => Some(Completion::Pending),
            Lookup::Archived(_) => Some(Completion::Archived),
            Lookup::DeliveryDataLoss => Some(Completion::DeliveryDataLoss),
            Lookup::Unknown => None,
        })
    }

    /// Validate and durably freeze a transition before dispatching it to Advance.
    ///
    /// # Errors
    /// Invalid proofs/inputs, conflicting replay, missing fold or unavailable custody reject
    /// before mutation. Once Advance selects a head its own Pending/Released rule applies.
    pub fn commit(&mut self, frozen: FrozenTransition) -> Result<Completion, Error> {
        let _payment = self.scheduler.payment();
        frozen.validate()?;
        let c = &frozen.capsule;
        if c.scheme_id != self.scheme_id || c.wallet_id != self.wallet_id {
            return Err(Error::Invalid("transition incarnation"));
        }
        let request = frozen.request()?;
        let owner = TransitionOwner::new(frozen.credential.clone());
        let lookup = self.custody.lookup(&c.operation_id)?;
        // A released Receive is recognized by its permanent credit identity even after its
        // completion was collected. Validate the original Payment below before returning its
        // first evidence or a fresh CreditStatus. Pending and delivery-loss answers retain
        // Advance's source authority and cannot be turned into a new Receive.
        let released_receive =
            matches!(c.statement.effect, KagemushaWalletEffectV1::Receive { .. })
                && matches!(&lookup, Lookup::Retained(_) | Lookup::Archived(_));
        if lookup != Lookup::Unknown && !released_receive {
            return self
                .custody
                .advance(&owner, &request)
                .map(map_outcome)
                .map_err(Error::from);
        }
        let (_, manifest) = self.sync_manifest()?;
        if let KagemushaWalletEffectV1::Receive { credit_id, .. } = c.statement.effect {
            if let Some(credit) = self.indexed_credit(&manifest, &credit_id)? {
                let original = c
                    .retained_inputs
                    .iter()
                    .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Payment)
                    .ok_or(Error::Invalid("duplicate Payment original"))?;
                let payment = valid(KagemushaWalletPaymentV1::decode_canonical(
                    &original.bytes,
                    &self.scheme_id,
                ))?;
                let identity = valid(payment.digests())?;
                if credit.payment_digest != c.payment_digest
                    || identity.payment != credit.payment_digest
                    || identity.credit_id != credit_id
                    || payment.request.body.amount != credit.amount
                {
                    return Err(Error::CreditConflict);
                }
                let entry = self.step_entry(&manifest, credit.sequence)?;
                if entry.collected {
                    let status = self.credit_status(&credit_id, &credit.payment_digest)?;
                    return Ok(Completion::CreditStatus(archive::encode(&status)?));
                }
                return Ok(Completion::Complete(
                    self.indexed_step(&manifest, credit.sequence)?
                        .retained
                        .record
                        .output,
                ));
            }
        }
        if released_receive {
            return Err(Error::WitnessLost("released Receive index"));
        }
        // Design §5.3: a fresh transition checks this phone again before it commits. Retained
        // and duplicate outcomes above never depend on current capacity.
        self.require_runtime_capacity()?;
        let predecessor = manifest
            .indexed
            .map(|sequence| self.indexed_step(&manifest, sequence))
            .transpose()?;
        let folded = match predecessor.as_ref() {
            Some(step) => self.read_fold(step)?.map(|fold| fold.record),
            None => None,
        };
        if send_class(c.kind) {
            let fold = folded.as_ref().ok_or(Error::FoldRequired)?;
            if c.predecessor_lineage() != Some(&fold.lineage) {
                return Err(Error::Invalid("recorded predecessor Ω"));
            }
        }
        let prepared = self.transition_preparation(&manifest, &frozen)?;
        let selected_source = if let Some(prepared) = &prepared {
            let previous = predecessor
                .as_ref()
                .ok_or(Error::WitnessLost("prepared predecessor"))?;
            if prepared.source != valid(previous.frozen.capsule.capsule_digest())? {
                return Err(Error::WitnessLost("prepared transition source"));
            }
            Some(self.preparation_source_custody(&manifest, previous, c.kind, folded.as_ref())?)
        } else {
            None
        };
        let refresh = match c.statement.effect {
            KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } => Some(update_kind),
            _ => None,
        };
        let view = selected_source
            .as_ref()
            .map(|(source, state)| {
                PreparationCustodyV1::new(
                    &mut self.archive,
                    source,
                    state,
                    c.kind,
                    refresh,
                    manifest.issued_requests,
                    manifest.direct_anchors,
                    manifest.finality_epochs,
                )
            })
            .transpose()?;
        let mut context = TransitionCustodyV1::new(prepared, view)?;
        let advance_check = self.proofs.verify_transition(
            &frozen,
            predecessor.as_ref(),
            folded.as_ref(),
            &mut context,
        )?;
        let mut next_custody = context.finish(&c.successor_state)?;
        if c.kind == KagemushaWalletOperationKindV1::Bootstrap {
            if predecessor.is_some() {
                return Err(Error::Invalid("bootstrap predecessor"));
            }
            let certificates = self.proofs.enrollment_certificates(&frozen.credential)?;
            next_custody = Some(preparation_custody::SourceCustodyV1::bootstrap(
                &mut self.archive,
                &c.successor_state,
                &valid(frozen.credential.to_canonical_bytes())?,
                &certificates,
            )?);
        }
        let digest = valid(c.capsule_digest())?;
        if let Some(source) = next_custody {
            self.retain_source_custody(digest, &source)?;
        }
        self.archive
            .put(ArchiveKey::Capsule(digest), &archive::encode(&frozen)?)?;
        self.status()?;
        self.proofs.check_advance(advance_check)?;
        let outcome = map_outcome(self.custody.advance(&owner, &request)?);
        if matches!(outcome, Completion::Complete(_)) {
            self.sync_manifest()?;
        }
        Ok(outcome)
    }

    /// Resume the source-selected operation using its frozen capsule; no new proof or inputs.
    ///
    /// # Errors
    /// Missing frozen inputs are custody loss. Provider failures retain pending semantics.
    pub fn resume(&mut self) -> Result<Option<Completion>, Error> {
        let _payment = self.scheduler.payment();
        let status = self.status()?;
        let SlotStatus::Pending(marker) = status else {
            return Ok(None);
        };
        let (_, _, digest) = marker.head().ok_or(Error::NoHead)?;
        let frozen = self.frozen(digest)?;
        self.status()?;
        let owner = TransitionOwner::new(frozen.credential.clone());
        let outcome = map_outcome(self.custody.advance(&owner, &frozen.request()?)?);
        if matches!(outcome, Completion::Complete(_)) {
            self.sync_manifest()?;
        }
        Ok(Some(outcome))
    }
}

fn send_class(kind: KagemushaWalletOperationKindV1) -> bool {
    matches!(
        kind,
        KagemushaWalletOperationKindV1::Send
            | KagemushaWalletOperationKindV1::Unload
            | KagemushaWalletOperationKindV1::Retiring
    )
}

fn map_outcome(outcome: AdvanceOutcome<KagemushaWalletCompletionRecordV1>) -> Completion {
    match outcome {
        AdvanceOutcome::Released { retained, .. } => Completion::Complete(retained.record.output),
        AdvanceOutcome::Pending { .. } => Completion::Pending,
        AdvanceOutcome::NotPerformed(reason) => Completion::NotPerformed(reason),
        AdvanceOutcome::Archived(_) => Completion::Archived,
        AdvanceOutcome::DeliveryDataLoss { .. } => Completion::DeliveryDataLoss,
    }
}

#[cfg(test)]
mod tests;
