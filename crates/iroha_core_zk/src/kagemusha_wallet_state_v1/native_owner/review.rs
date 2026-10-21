//! Whole native financial checks for hardware UI approval, without a monetary operation.
//!
//! A Send review may also have its `σ_send` proved speculatively while the user looks at it
//! (design §5.1, Payment row), the way the fold worker proves: a scheduler slot with payment
//! priority over folds, a locked prepare under the wallet owner that derives the Send on a
//! throwaway draft, and a proof without the owner. Nothing is written, signed or debited
//! before `execute_reviewed`, which uses that σ only after hardware approval, its fresh
//! recheck and an identical derivation. A declined review drops the σ unsigned.

use super::super::object_workspace::{DraftWorkspace, WorkspaceLimits};
use super::super::scheduling::{Speculation, SpeculationJob};
use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1, kagemusha_wallet_archive_checkpoint_digest_v1,
    kagemusha_wallet_provider_digest_v1,
};
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::WalletSourcesErrorV1;
use crate::kagemusha_wallet_intake_v1::{self as intake, ACCOUNT_ORIGINAL_MAX_BYTES_V1};
use crate::kagemusha_wallet_preparation_v1::{
    SendControlsV1, SpeculativeSendStepV1, SpeculativeSigmaV1, UnloadChargeOriginalsV1,
};

/// Authenticated financial projection for fresh hardware UI approval.
/// This copyable DATA grants no wallet admission, signature, proof or Advance authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeOperationReviewV1 {
    /// Exactly Send or Unload.
    pub kind: KagemushaWalletOperationKindV1,
    /// Exact requested offline face amount.
    pub amount: u128,
    /// Authenticated Send fee or separate online Unload charge.
    pub fee: u128,
    /// Actual offline debit: Send amount plus fee; Unload face amount.
    pub gross_debit: u128,
    /// Receiver credit for Send; account payout after online charge for Unload.
    pub net_destination_amount: u128,
    /// Bound Send receiver wallet; absent for ledger-account Unload.
    pub receiver_wallet_id: Option<[u8; 32]>,
    /// Bound receiver account for Send; current enrolled account for Unload.
    pub destination_account_digest: [u8; 32],
    /// Exact canonical `AccountId` original bound to the authenticated Send destination.
    /// Absent for Unload. Copying this display DATA grants no operation authority.
    pub destination_account_original: Option<Vec<u8>>,
    /// Genuine signed Request digest for Send; zero for Unload.
    pub request_digest: [u8; 32],
    /// Genuine signed charge-quote digest for Unload; zero for Send/default zero charge.
    pub charge_quote_digest: [u8; 32],
    /// Exact admitted scheme.
    pub scheme_id: [u8; 32],
    /// Exact enrolled payer incarnation.
    pub wallet_id: [u8; 32],
    /// Current released and fully folded head.
    pub current_head: [u8; 32],
    /// Commitment recomputed from the complete retained source state.
    pub source_state_commitment: [u8; 32],
    /// Exact source recovery capsule.
    pub source_capsule_digest: [u8; 32],
    /// Exact current issuer-authenticated payer credential.
    pub credential_digest: [u8; 32],
    /// Exact enrolled hardware payment key.
    pub payment_key: KagemushaDevicePublicKeyV1,
    /// Actual signed installed runtime/artifact manifest identity.
    pub artifact_manifest_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewSourceV1 {
    marker: KagemushaWalletMarkerV1,
    completion: [u8; 32],
    archive_checkpoint: [u8; 32],
    artifact_manifest: [u8; 32],
    selected_generation: u128,
}

// Call only after review_send_terms has authenticated the complete signed Request,
// its receiver credential/certificates and the current payer's ordinary Send controls.
fn send_destination_original(
    original: &[u8],
    request: &KagemushaWalletRequestV1,
) -> Result<Vec<u8>, Error> {
    intake::account(original, &request.body.receiver_account_digest).map_err(|error| {
        error.into_state_error(Error::Invalid("review destination account original"))
    })?;
    Ok(original.to_vec())
}

// Call only after review_unload_terms authenticates this exact quote and its certificate set.
fn unload_beneficiary_original(
    scheme: &[u8; 32],
    charge: Option<&ChargeOriginalsV1>,
    original: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, Error> {
    match (charge, original) {
        (None, None) => Ok(None),
        (Some(charge), Some(original)) => {
            let quote = read_model_original(
                || KagemushaWalletChargeQuoteV1::decode_canonical(&charge.quote, scheme),
                Error::Invalid("G1 validation"),
            )?;
            intake::account(original, &quote.body.beneficiary_account_digest).map_err(|error| {
                error.into_state_error(Error::Invalid("review Unload beneficiary original"))
            })?;
            Ok(Some(original.to_vec()))
        }
        _ => Err(Error::Invalid("review Unload beneficiary presence")),
    }
}

/// Opaque one-use review owned by the single admitted Native coordinator.
/// No public constructor, clone or codec can reconstruct it from projection DATA.
/// Mobile boundaries must retain this actual value under an owner-local one-use token.
/// A fresh hardware UI approval precedes consuming it through `execute_reviewed`.
///
/// ```compile_fail
/// use iroha_core_zk::kagemusha_wallet_state_v1::ReviewedOperationV1;
/// fn duplicate(review: ReviewedOperationV1) { let _other = review.clone(); }
/// ```
/// ```compile_fail
/// use iroha_core_zk::kagemusha_wallet_state_v1::ReviewedOperationV1;
/// fn replay(review: ReviewedOperationV1) { let _first = review; let _second = review; }
/// ```
pub struct ReviewedOperationV1 {
    projection: NativeOperationReviewV1,
    source: ReviewSourceV1,
    action: OperationActionV1,
    unload_beneficiary: Option<Vec<u8>>,
    // The σ_send this Send review may have proved speculatively. Dropping the review cancels
    // it and drops any finished σ unsigned.
    speculation: Option<Speculation<SpeculativeSendV1>>,
}
// A review must stay `Send`, so it can never retain a call-scoped, `!Send` native
// derivation (`NativePreparedOperationV1`), independently of any mobile boundary bound.
const _: () = {
    const fn send<T: Send>() {}
    send::<ReviewedOperationV1>();
    send::<SpeculativeSendJobV1>();
    send::<SpeculativeProofV1>();
};
impl ReviewedOperationV1 {
    /// Borrow the immutable financial DATA for hardware UI approval.
    #[must_use]
    pub const fn projection(&self) -> &NativeOperationReviewV1 {
        &self.projection
    }
    /// The job that may prove this Send review's `σ_send` speculatively without the wallet
    /// owner; `None` for Unload and for a Send whose controls need a clock reading. Each call
    /// returns a handle to the same single speculation.
    #[must_use]
    pub fn speculation(&self) -> Option<SpeculativeSendJobV1> {
        let OperationActionV1::Send { request } = &self.action else {
            return None;
        };
        Some(SpeculativeSendJobV1 {
            job: self.speculation.as_ref()?.job(),
            request: request.clone(),
            source: self.source.clone(),
        })
    }
    /// Exact Native-authenticated signed Request original; absent for Unload.
    #[must_use]
    pub fn send_original(&self) -> Option<&[u8]> {
        match &self.action {
            OperationActionV1::Send { request } => Some(request),
            _ => None,
        }
    }
    /// Exact authenticated Unload quote and certificate set; absent for zero charge/Send.
    #[must_use]
    pub fn charge_originals(&self) -> Option<(&[u8], &[u8])> {
        match &self.action {
            OperationActionV1::Unload {
                charge: Some(charge),
                ..
            } => Some((&charge.quote, &charge.certificates)),
            _ => None,
        }
    }

    fn require_recheck(&self, fresh: &Self) -> Result<(), Error> {
        if self.action != fresh.action
            || self.projection != fresh.projection
            || self.source != fresh.source
            || self.unload_beneficiary != fresh.unload_beneficiary
        {
            return Err(Error::OperationConflict);
        }
        Ok(())
    }

    fn into_request(self, request_id: [u8; 32]) -> Result<OperationRequestV1, Error> {
        if request_id == [0; 32] {
            return Err(Error::Invalid("review request identity"));
        }
        Ok(OperationRequestV1 {
            request_id,
            action: self.action,
        })
    }

    // The exact request and the σ_send its speculation finished, if any. Taking the
    // speculation ends it either way.
    fn into_execution(
        mut self,
        request_id: [u8; 32],
    ) -> Result<(OperationRequestV1, Option<SpeculativeSendV1>), Error> {
        let speculative = self.speculation.take().and_then(Speculation::take);
        Ok((self.into_request(request_id)?, speculative))
    }
}

// Domain of the private Request identity a speculation is bound to; never persisted.
const SPECULATIVE_REQUEST_DOMAIN: &str = "wallet-speculative-send-request";
// The derivation reads only the Send action; this identity is never bound or published.
const SPECULATIVE_REQUEST_ID: [u8; 32] = [0x5a; 32];

/// One finished speculative `σ_send` of a review (design §5.1, Payment row). It is never
/// signed or written: execution plans with its nonce and freezes its σ only for exactly the
/// request, source, installation and derived statement it was proved for.
pub struct SpeculativeSendV1 {
    manifest: [u8; 32],
    source: [u8; 32],
    request: [u8; 32],
    nonce: [u8; 32],
    sigma: SpeculativeSigmaV1,
}

impl SpeculativeSendV1 {
    // Whether this speculation was made for this exact Send, installation and source capsule.
    pub(super) fn made_for(
        &self,
        manifest: [u8; 32],
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
    ) -> bool {
        let same_request = matches!(
            request.user_request().map(|user| &user.action),
            Some(OperationActionV1::Send { request: original })
                if kagemusha_wallet_provider_digest_v1(SPECULATIVE_REQUEST_DOMAIN, original)
                    == self.request
        );
        same_request
            && self.manifest == manifest
            && self.source == source.released().frozen.capsule.custody_digest()
            && !NativeChoicesV1::needs_clock(request, source)
    }

    pub(super) const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub(super) fn into_sigma(self) -> SpeculativeSigmaV1 {
        self.sigma
    }
}

/// The job side of one Send review's speculative `σ_send`, for its locked prepare under the
/// wallet owner (`prepare_speculation`). It copies the review's exact Request original and
/// source binding and grants no review, proof, signing or Advance authority.
pub struct SpeculativeSendJobV1 {
    job: SpeculationJob<SpeculativeSendV1>,
    request: Vec<u8>,
    source: ReviewSourceV1,
}

/// The unlocked half of one speculative `σ_send`: it waits for the scheduler's speculation slot
/// and proves without the wallet owner. It holds no custody, original store, plan or signing
/// capability.
pub struct SpeculativeProofV1 {
    job: SpeculationJob<SpeculativeSendV1>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    read: ReadConfig,
    budget: MemoryBudget,
    step: SpeculativeSendStepV1,
    manifest: [u8; 32],
    source: [u8; 32],
    request: [u8; 32],
    nonce: [u8; 32],
}

fn speculative_source_error(error: WalletSourcesErrorV1) -> Error {
    if error.is_cancelled() {
        Error::Cancelled
    } else if error.is_unavailable() {
        Error::ArtifactsUnavailable("qualified sigma original import")
    } else {
        Error::Proof("qualified sigma original import")
    }
}

impl SpeculativeProofV1 {
    /// Wait for `scheduler`'s speculation slot ([`Scheduler::speculate`]), rebuild the `σ_send`
    /// key from its sealed source (the locked prepare revalidated its originals), prove under
    /// the review's cancellation signal and publish the σ for the review. Call this without
    /// the wallet owner. The prover's memory is released before the slot.
    ///
    /// # Errors
    /// Cancellation (an ended review or close), unavailable artifacts or a failed proof; the
    /// review then executes with a fresh proof.
    pub fn prove(self, scheduler: &Scheduler) -> Result<(), Error> {
        let run = scheduler.speculate(&self.job).ok_or(Error::Cancelled)?;
        let sigma = self.sigma(run.token());
        let Self {
            job,
            installed,
            sources,
            step,
            manifest,
            source,
            request,
            nonce,
            ..
        } = self;
        // The derivation and source handles go before the slot is released.
        drop((job, installed, sources, step));
        let sigma = sigma?;
        run.finish(SpeculativeSendV1 {
            manifest,
            source,
            request,
            nonce,
            sigma,
        });
        Ok(())
    }

    // Rebuild the key and prove; the prover is released when this returns.
    fn sigma(&self, token: &Cancellation) -> Result<SpeculativeSigmaV1, Error> {
        token.check()?;
        let imported = self
            .sources
            .bind_sigma_cancellable(self.step.selector(), self.read, Some(token.prover_token()))
            .map_err(speculative_source_error)?;
        token.check()?;
        let preparation =
            proof(PreparationV1::new(&self.installed))?.with_cancellation(token.prover_token());
        self.step.prove(&preparation, imported, self.budget)
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    fn review_source(
        &mut self,
        archive_checkpoint: [u8; 32],
        manifest: &manifest::Manifest,
        released: &ReleasedStep,
    ) -> Result<ReviewSourceV1, Error> {
        let SlotStatus::Released(marker) = self.status()? else {
            return Err(Error::Pending);
        };
        let capsule = &released.frozen.capsule;
        let original_manifest = self
            .custody
            .archive_checkpoint()?
            .ok_or(Error::WitnessLost("review manifest"))?;
        if original_manifest.1.len() > KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1
            || original_manifest.0 != archive_checkpoint
            || kagemusha_wallet_archive_checkpoint_digest_v1(&original_manifest.1)
                != archive_checkpoint
            || original_manifest.1 != archive::encode(manifest)?
            || marker.archive_checkpoint() != archive_checkpoint
        {
            return Err(Error::WitnessLost("review source manifest"));
        }
        let KagemushaWalletMarkerStateV1::Head {
            sequence,
            operation_id,
            head,
            capsule_digest,
            ..
        } = marker.marker().state
        else {
            return Err(Error::NoHead);
        };
        if marker.marker().scheme_id != self.scheme_id
            || marker.marker().wallet_id != self.wallet_id
            || marker.payment_key() != &released.frozen.credential.body.payment_key
            || sequence != capsule.body().statement.sequence
            || operation_id != capsule.body().operation_id
            || head != capsule.body().statement.successor
            || head != valid(capsule.body().successor_state.commitment())?
            || capsule_digest != capsule.custody_digest()
            || capsule_digest != released.retained.capsule_digest
            || operation_id != released.retained.operation_id
            || marker.selected_generation() != Some(released.retained.selected_generation)
            || marker.completion_digest() != Some(released.retained.completion_digest)
        {
            return Err(Error::WitnessLost("review selected source"));
        }
        Ok(ReviewSourceV1 {
            marker: *marker.marker(),
            completion: released.retained.completion_digest,
            archive_checkpoint,
            artifact_manifest: self.proofs.installed.verifier().manifest_digest(),
            selected_generation: released.retained.selected_generation,
        })
    }

    // `speculate` gives a Send review its speculation slot; a recheck never has one.
    fn review_action(
        &mut self,
        action: OperationActionV1,
        destination_original: Option<&[u8]>,
        unload_beneficiary: Option<&[u8]>,
        speculate: bool,
    ) -> Result<ReviewedOperationV1, Error> {
        let kind = match &action {
            OperationActionV1::Send { request }
                if unload_beneficiary.is_none()
                    && !request.is_empty()
                    && request.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
                    && destination_original.is_some_and(|original| {
                        !original.is_empty() && original.len() <= ACCOUNT_ORIGINAL_MAX_BYTES_V1
                    }) =>
            {
                KagemushaWalletOperationKindV1::Send
            }
            OperationActionV1::Unload { charge, .. }
                if destination_original.is_none()
                    && charge.is_some() == unload_beneficiary.is_some()
                    && unload_beneficiary.is_none_or(|original| {
                        !original.is_empty() && original.len() <= ACCOUNT_ORIGINAL_MAX_BYTES_V1
                    }) =>
            {
                KagemushaWalletOperationKindV1::Unload
            }
            _ => return Err(Error::Invalid("review operation")),
        };
        let (selected, manifest) = self.sync_manifest()?;
        let released = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        let binding = self.review_source(selected, &manifest, &released)?;
        let fold = self
            .read_fold(&released)?
            .ok_or(Error::FoldRequired)?
            .record;
        let (snapshot, map_state) =
            self.preparation_source_custody(&manifest, &released, kind, Some(&fold))?;
        let preparation = proof(PreparationV1::new(&self.proofs.installed))?;
        let mut custody = PreparationCustodyV1::new(
            &mut self.archive,
            &snapshot,
            &map_state,
            kind,
            None,
            manifest.issued_requests,
            manifest.direct_anchors,
            manifest.finality_epochs,
            manifest.blacklist.clone(),
        )?;
        let credential = custody
            .original(PreparationOriginalV1::CurrentCredential)?
            .ok_or(Error::WitnessLost("review credential"))?;
        let certificates = custody
            .original(PreparationOriginalV1::EnrollmentCertificates)?
            .ok_or(Error::WitnessLost("review issuer certificates"))?;
        let owner = preparation.authenticate_credential_set(&credential, &certificates)?;
        let predecessor =
            proof(preparation.folded_state(&owner, &released, &fold, self.proofs.budget))?;
        let before = predecessor.source_state();
        let mut destination_account_original = None;
        let mut verified_unload_beneficiary = None;
        let (
            amount,
            fee,
            gross_debit,
            net_destination_amount,
            receiver_wallet_id,
            destination_account_digest,
            request_digest,
            charge_quote_digest,
        ) = match &action {
            OperationActionV1::Send { request } => {
                // A listed receiver is refused here, before the user is asked to confirm.
                let blacklist = custody.local_blacklist()?;
                let share = if before.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
                    let original = custody
                        .original(PreparationOriginalV1::QuotaShare)?
                        .ok_or(Error::WitnessLost("review quota share"))?;
                    Some(read_model_original(
                        || {
                            KagemushaWalletQuotaShareV1::decode_canonical(
                                &original,
                                &self.scheme_id,
                            )
                        },
                        Error::Invalid("G1 validation"),
                    )?)
                } else {
                    None
                };
                let anchored = if before.send_requires_time_anchor() {
                    custody.anchored_time()?
                } else {
                    None
                };
                let now = if before.send_requires_time_anchor() {
                    Some(self.proofs.observations.time()?)
                } else {
                    None
                };
                let usage = custody.maps().quota_usage()?;
                let (request, _) = proof(preparation.review_send_terms(
                    &owner,
                    &predecessor,
                    request,
                    &SendControlsV1 {
                        anchored: anchored.as_ref(),
                        now: now.as_ref(),
                        blacklist: blacklist.as_ref(),
                        quota_share: share.as_ref(),
                        quota_usage: &usage,
                    },
                ))?;
                // The companion is DATA: only this whole authenticated Request supplies
                // the destination digest. No caller digest, literal or verifier verdict.
                destination_account_original = Some(send_destination_original(
                    destination_original.ok_or(Error::Invalid("review destination original"))?,
                    &request,
                )?);
                let body = &request.body;
                (
                    body.amount,
                    body.fee,
                    body.amount
                        .checked_add(body.fee)
                        .ok_or(Error::Invalid("review gross"))?,
                    body.amount,
                    Some(body.receiver_wallet_id),
                    body.receiver_account_digest,
                    request.request_digest(),
                    [0; 32],
                )
            }
            OperationActionV1::Unload { amount, charge } => {
                let (fee, digest) = proof(preparation.review_unload_terms(
                    &owner,
                    &predecessor,
                    *amount,
                    charge.as_ref().map(|c| UnloadChargeOriginalsV1 {
                        quote: &c.quote,
                        certificate_set: &c.certificates,
                    }),
                ))?;
                verified_unload_beneficiary = unload_beneficiary_original(
                    &self.scheme_id,
                    charge.as_ref(),
                    unload_beneficiary,
                )?;
                (
                    *amount,
                    fee,
                    *amount,
                    valid(kagemusha_wallet_unload_account_payout_v1(*amount, fee))?,
                    None,
                    owner.credential().body.account_digest,
                    [0; 32],
                    digest,
                )
            }
            _ => return Err(Error::Invalid("review operation")),
        };
        let projection = NativeOperationReviewV1 {
            kind,
            amount,
            fee,
            gross_debit,
            net_destination_amount,
            receiver_wallet_id,
            destination_account_digest,
            destination_account_original,
            request_digest,
            charge_quote_digest,
            scheme_id: self.scheme_id,
            wallet_id: self.wallet_id,
            current_head: released.frozen.capsule.body().statement.successor.value,
            source_state_commitment: valid(before.commitment())?.value,
            source_capsule_digest: released.retained.capsule_digest,
            credential_digest: owner.credential().credential_digest(),
            payment_key: owner.credential().body.payment_key,
            artifact_manifest_digest: self.proofs.installed.verifier().manifest_digest(),
        };
        // Preparation reads are complete before checking actual selection again.
        let (current_selected, current) = self.sync_manifest()?;
        if current_selected != selected
            || current.capsule != released.retained.capsule_digest
            || self.review_source(current_selected, &current, &released)? != binding
        {
            return Err(Error::OperationConflict);
        }
        // A Send whose controls need a clock reading keeps execute-time choices: its σ binds
        // the accepted interval of that reading.
        let speculation = (speculate
            && kind == KagemushaWalletOperationKindV1::Send
            && !released
                .frozen
                .capsule
                .body()
                .successor_state
                .send_requires_time_anchor())
        .then(Speculation::new);
        Ok(ReviewedOperationV1 {
            projection,
            source: binding,
            action,
            unload_beneficiary: verified_unload_beneficiary,
            speculation,
        })
    }

    /// Locked prepare of a Send review's speculative `σ_send`, before its proof is admitted.
    /// It requires the review's exact source to be current and the phone to have the proving
    /// capacity, draws the speculative nonce with the ordinary sampler, derives the Send with
    /// today's preparation on a throwaway draft (nothing is written) and revalidates the
    /// `σ_send` originals. `Ok(None)` when the review ended, a payment already holds priority
    /// or the review's source changed; execution then proves itself.
    ///
    /// # Errors
    /// Unavailable custody, capacity, artifacts or entropy, or a refused derivation. Nothing
    /// durable changed and the review executes with a fresh proof.
    pub fn prepare_speculation(
        &mut self,
        job: &SpeculativeSendJobV1,
    ) -> Result<Option<SpeculativeProofV1>, Error> {
        if job.job.ended() || self.scheduler.payment_pending() {
            return Ok(None);
        }
        let (selected, manifest) = self.sync_manifest()?;
        let released = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        if self.review_source(selected, &manifest, &released)? != job.source {
            return Ok(None);
        }
        let fold = self
            .read_fold(&released)?
            .ok_or(Error::FoldRequired)?
            .record;
        let intent = NativeIntentV1::user(OperationRequestV1 {
            request_id: SPECULATIVE_REQUEST_ID,
            action: OperationActionV1::Send {
                request: job.request.clone(),
            },
        });
        let source = PreparationSourceV1 {
            released: &released,
            folded: Some(&fold),
        };
        if NativeChoicesV1::needs_clock(&intent, &source) {
            return Ok(None);
        }
        // The same admission execute applies before it proves.
        self.require_runtime_capacity(NativeAdmissionPhaseV1::Speculation)?;
        let (snapshot, map_state) = self.preparation_source_custody(
            &manifest,
            &released,
            KagemushaWalletOperationKindV1::Send,
            Some(&fold),
        )?;
        let nonce = NativeChoicesV1::fresh_nonce(
            &released
                .frozen
                .capsule
                .body()
                .successor_state
                .core
                .state_nonce,
        )?;
        // The same binding fresh choices have; a speculation never carries a clock reading.
        let choices = NativeChoicesV1::speculated(
            self.proofs.installed.verifier().manifest_digest(),
            &intent,
            &source,
            nonce,
        )?;
        let prepared = {
            // Map insertions stage in memory only; the draft is dropped unpublished.
            let mut draft = DraftWorkspace::new(
                &mut self.archive,
                WorkspaceLimits {
                    max_bytes: super::super::lifecycle::INTAKE_DRAFT_BYTES,
                    max_objects: super::super::lifecycle::INTAKE_DRAFT_OBJECTS,
                },
            );
            let mut custody = PreparationCustodyV1::new(
                &mut draft,
                &snapshot,
                &map_state,
                KagemushaWalletOperationKindV1::Send,
                None,
                manifest.issued_requests,
                manifest.direct_anchors,
                manifest.finality_epochs,
                manifest.blacklist.clone(),
            )?;
            proof(PreparationV1::new(&self.proofs.installed))?.prepare_operation(
                &intent,
                &source,
                &mut custody,
                &OperationPreparationV1 {
                    sources: &self.proofs.sources,
                    choices: &choices,
                    budget: self.proofs.budget,
                },
            )?
        };
        let Some(step) = prepared.into_speculative_send()? else {
            return Ok(None);
        };
        // A confirmation that arrived meanwhile proves itself; skip the original reads.
        if self.scheduler.payment_pending() {
            return Ok(None);
        }
        // Every σ use revalidates its signed originals under the owner of the sole store.
        {
            let mut originals = self
                .proofs
                .originals
                .lock()
                .map_err(|_| Error::ArtifactsUnavailable("proving original owner poisoned"))?;
            self.proofs
                .sources
                .revalidate_sigma_cancellable(
                    step.selector(),
                    &mut *originals,
                    self.proofs.read,
                    Some(job.job.token().prover_token()),
                )
                .map_err(speculative_source_error)?;
        }
        Ok(Some(SpeculativeProofV1 {
            job: job.job.clone(),
            installed: Arc::clone(&self.proofs.installed),
            sources: Arc::clone(&self.proofs.sources),
            read: self.proofs.read,
            budget: self.proofs.budget,
            step,
            manifest: self.proofs.installed.verifier().manifest_digest(),
            source: released.frozen.capsule.custody_digest(),
            request: kagemusha_wallet_provider_digest_v1(SPECULATIVE_REQUEST_DOMAIN, &job.request),
            nonce,
        }))
    }

    /// Authenticate an exact signed Request against the current folded payer and all controls.
    /// No nonce, map insertion, proof, hardware signature or Advance is produced. The review
    /// may then have its `σ_send` proved speculatively ([`ReviewedOperationV1::speculation`]).
    /// A running local fold continues; an uncovered current head returns `FoldRequired`.
    /// # Errors
    /// Invalid/foreign Request, missing or changed source/fold/originals, failed controls or unavailable storage/observations.
    pub fn review_send(
        &mut self,
        request_original: &[u8],
        destination_account_original: &[u8],
    ) -> Result<ReviewedOperationV1, Error> {
        if request_original.is_empty()
            || request_original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
            || destination_account_original.is_empty()
            || destination_account_original.len() > ACCOUNT_ORIGINAL_MAX_BYTES_V1
        {
            return Err(Error::Invalid("review Request bound"));
        }
        self.review_action(
            OperationActionV1::Send {
                request: request_original.to_vec(),
            },
            Some(destination_account_original),
            None,
            true,
        )
    }

    /// Authenticate current folded Unload amount/destination and optional signed charge.
    /// The fee is withheld from the ledger payout; the offline debit remains the face amount.
    /// No nonce, map insertion, proof, signature or Advance is produced.
    /// A running local fold continues; execution alone takes payment priority and rechecks
    /// the review's source after hardware approval.
    /// # Errors
    /// Unavailable or changed source, missing fold, invalid amount or foreign/malformed
    /// quote/certificates/beneficiary. Charged reviews require the exact canonical beneficiary.
    pub fn review_unload(
        &mut self,
        amount: u128,
        charge: Option<ChargeOriginalsV1>,
        beneficiary_original: Option<&[u8]>,
    ) -> Result<ReviewedOperationV1, Error> {
        self.review_action(
            OperationActionV1::Unload { amount, charge },
            None,
            beneficiary_original,
            false,
        )
    }

    /// Consume one actual review after fresh hardware UI approval and recheck its exact source.
    /// The caller supplies only a nonzero local retry identity. Amount and all originals are
    /// taken from the privately retained review. Ordinary execute/preAdvance remain mandatory.
    /// # Errors
    /// Changed source/runtime/action, failed current controls, invalid identity, unavailable custody or ordinary execution errors.
    pub fn execute_reviewed(
        &mut self,
        review: ReviewedOperationV1,
        request_id: [u8; 32],
    ) -> Result<Completion, Error> {
        // Payment priority also joins an admitted speculative σ_send of this review, without
        // cancelling it, so a finished speculation is found below.
        let _payment = self.scheduler.payment();
        if request_id == [0; 32] {
            return Err(Error::Invalid("review request identity"));
        }
        // The exact companion remains privately retained with this actual one-use review.
        // Reauthenticate its canonical bytes/digest against the fresh whole signed Request;
        // projection copies and caller presentation settings cannot supply a replacement.
        let fresh = self.review_action(
            review.action.clone(),
            review.projection.destination_account_original.as_deref(),
            review.unload_beneficiary.as_deref(),
            false,
        )?;
        review.require_recheck(&fresh)?;
        // Only an identical source and action reach here. The speculative σ is DATA until
        // execution plans with its nonce and finds an identical derivation; τ_send, Advance
        // and the debit happen only inside this execution.
        let (request, speculative) = review.into_execution(request_id)?;
        self.execute_speculated(request, speculative)
    }
}

#[cfg(test)]
mod tests;
