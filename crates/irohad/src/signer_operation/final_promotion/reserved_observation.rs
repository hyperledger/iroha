//! A signed role-15 Reserve remains the sole source for a fresh BeforeProvider Check.
//!
//! This bounded owner pins an independent chain floor before it submits the original Reserve.
//! It later derives the Reserved subject from one real State cut, but only Core's signed-entry,
//! successful-execution and State/Kura/QC proof can turn that subject into authority. Injected
//! transport, observer, clock and floor implementations still require production qualification.
//! TODO: Connect the independent native floor pin, funded proof replay and deployment providers
//! before implementing the production role-14 operation-state source.

use std::{sync::Arc, time::Duration};

use iroha_core::{
    query::{
        final_promotion_account_custody::observation::{
            FinalPromotionAccountEligibilityTimeIntervalV1,
            validate_final_promotion_account_transaction_envelope_v1,
        },
        final_promotion_authority::{
            observation::{
                FinalPromotionCheckExpectedV1, FinalPromotionCheckFloorV1,
                FinalPromotionCheckSourceV1, FinalPromotionEligibilityTimeIntervalV1,
                FinalPromotionObservationErrorV1, VerifiedFinalPromotionCheckV1,
                begin_final_promotion_check_v1,
            },
            read_final_promotion_authority_at_v1,
        },
        signer_finality::verify_signer_finality_v1,
    },
    state::{State, StateView},
};
use iroha_data_model::{
    account::AccountId,
    isi::sorafs::MutateSorafsFinalPromotionAuthority,
    sorafs::final_promotion_authority::{
        FinalPromotionAuthorityActionV1, FinalPromotionCheckSubjectV1,
        FinalPromotionOperationOutcomeV1,
    },
    transaction::Executable,
};
use sorafs_manifest::signer::{
    custody::SignerCustodyUseContextV1, final_promotion::SignerFinalPromotionRequestV1,
    protocol::SignerOperationActionV1,
};

use super::{
    account_transaction::SignedFinalPromotionAccountTransactionV1,
    current_observation::{
        FinalPromotionCheckObservationErrorV1 as Error, FinalPromotionNativeSubmissionV1,
        FinalPromotionNativeSubmitOutcomeV1, FinalPromotionObserverCheckPayloadV1,
        FinalPromotionObserverCheckSignerV1, FinalPromotionQualifiedUtcV1,
        FinalPromotionRetainedFloorV1, signing_context,
    },
    observer_transaction::{
        FinalPromotionObserverTransactionErrorV1, FinalPromotionObserverTransactionsV1,
    },
    pending_reserve_journal::{
        FinalPromotionPendingReserveJournalErrorV1, FinalPromotionPendingReserveJournalV1,
        RecoveredPendingReserveV1,
    },
};

/// Pre-submission Reserve owner with the exact signed role-15 envelope and independent floor.
///
/// This is not a finalized reservation. Only an actual successful native Reserve followed by a
/// fresh finalized observer Check can produce a verified `BeforeProvider` phase.
pub struct FinalPromotionReservedCheckRuntimeV1 {
    state: Arc<State>,
    observer: FinalPromotionObserverTransactionsV1,
    request: SignerFinalPromotionRequestV1,
    signed_reserve: SignedFinalPromotionAccountTransactionV1,
    pending_reserve: RecoveredPendingReserveV1,
    pre_reserve_floor: FinalPromotionCheckFloorV1,
    max_elapsed: Duration,
}

impl FinalPromotionReservedCheckRuntimeV1 {
    /// Pin the configured request and independent floor while this operation has no native row.
    ///
    /// The signed owner came from the role-15 continuation and cannot be replaced by decoded
    /// Reserve bytes. A floor read after Reserve application cannot initialize this owner.
    ///
    /// # Errors
    /// Rejects another account, request, native action, custody/control cut or unavailable floor.
    pub fn new(
        state: Arc<State>,
        observer: FinalPromotionObserverTransactionsV1,
        request: SignerFinalPromotionRequestV1,
        signed_reserve: SignedFinalPromotionAccountTransactionV1,
        max_elapsed: Duration,
        floor: &mut impl FinalPromotionRetainedFloorV1,
        journal: &FinalPromotionPendingReserveJournalV1,
    ) -> Result<Self, Error> {
        if max_elapsed.is_zero()
            || max_elapsed > Duration::from_secs(60)
            || state.network_id_ref().as_bytes() != &observer.receipt_binding().network_id
            || state.chain_id_ref().to_string() != observer.receipt_binding().chain_id
            || request
                .validate_binding(observer.receipt_binding())
                .is_err()
        {
            return Err(Error::Binding);
        }
        let pre_reserve_floor = floor.read().map_err(|_| Error::Floor)?;
        let current_check_floor = signed_reserve.original_current_check().applied_floor();
        // A retained floor older than the signed Current Check's authenticated applied cut is
        // a rollback. Equal heights must retain the same hash and committee context.
        if pre_reserve_floor.height < current_check_floor.height
            || (pre_reserve_floor.height == current_check_floor.height
                && pre_reserve_floor != current_check_floor)
        {
            return Err(Error::Floor);
        }
        let view = state.view();
        authenticate_pre_reserve_floor_at_v1(&view, pre_reserve_floor)?;
        if pre_reserve_floor != current_check_floor {
            authenticate_pre_reserve_floor_at_v1(&view, current_check_floor)?;
        }
        // TODO: Reprove successor continuity and historical floor issuance after restart before
        // using the journaled floor for any later operation phase.
        let height = u64::try_from(view.height()).map_err(|_| Error::Check)?;
        let snapshot = read_final_promotion_authority_at_v1(
            &view,
            observer.receipt_binding(),
            height,
            Some(request.operation_id),
        )
        .map_err(|_| Error::Check)?
        .ok_or(Error::Custody)?;
        if pre_reserve_floor.height > height
            || snapshot.operations.active_operation.is_some()
            || snapshot.operation.is_some()
            || snapshot.custody_anchor.state_digest != request.original_custody.control_state_digest
            || snapshot
                .control
                .active_head
                .is_none_or(|head| head.record_digest != request.original_custody.record_digest)
        {
            return Err(Error::Check);
        }
        let signed = signed_reserve.reconciliation_transaction();
        let payload = signed.payload();
        validate_final_promotion_account_transaction_envelope_v1(payload)
            .map_err(|_| Error::Payload)?;
        signed.verify_signature().map_err(|_| Error::Payload)?;
        let Executable::Instructions(instructions) = &payload.instructions else {
            return Err(Error::Payload);
        };
        let instruction = instructions
            .first()
            .filter(|_| instructions.len() == 1)
            .and_then(|entry| {
                entry
                    .as_any()
                    .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
            })
            .ok_or(Error::Payload)?;
        let FinalPromotionAuthorityActionV1::Reserve(reserve) = &instruction.action else {
            return Err(Error::Payload);
        };
        let authority = AccountId::new(observer.account_binding().public_key.clone());
        if payload.authority != authority
            || payload.network_id().map(iroha_data_model::NetworkId::as_bytes)
                != Some(&observer.receipt_binding().network_id)
            || &instruction.deployment_id
                != match &observer.receipt_binding().purpose {
                    sorafs_manifest::signer::protocol::SignerPurposeBindingV1::FinalPromotionProvenance {
                        deployment_id,
                    } => deployment_id,
                    _ => return Err(Error::Binding),
                }
            || instruction.expected_control_revision != snapshot.control_record.revision
            || instruction.expected_control_digest != snapshot.custody_anchor.state_digest
            || reserve.intent.action != SignerOperationActionV1::Sign
            || reserve.intent.operation_id != request.operation_id
            || reserve.intent.request_digest != request.digest().map_err(|_| Error::Binding)?
            || reserve.intent.previous_audit != snapshot.operations.audit
            || reserve.custody != request.original_custody
        {
            return Err(Error::Binding);
        }
        drop(view);
        let pending_reserve = journal
            .stage(
                request,
                super::pending_reserve_journal::ReserveBindings {
                    receipt_binding: observer.receipt_binding(),
                    account_binding: observer.account_binding(),
                    observer: observer.observer(),
                },
                pre_reserve_floor,
                signed_reserve.original_current_check(),
                signed_reserve.reconciliation_transaction(),
            )
            .map_err(|error| match error {
                FinalPromotionPendingReserveJournalErrorV1::LocalCapacity => Error::LocalCapacity,
                FinalPromotionPendingReserveJournalErrorV1::Unavailable => Error::Journal,
            })?;
        Ok(Self {
            state,
            observer,
            request,
            signed_reserve,
            pending_reserve,
            pre_reserve_floor,
            max_elapsed,
        })
    }

    /// Submit the original signed Reserve once, reconciling only that same envelope if ambiguous.
    ///
    /// The returned owner still has no finality claim. The exact pending envelope was staged and
    /// read back before this method; recovery can inspect it but cannot submit or renew authority.
    ///
    /// # Errors
    /// Rejects a changed pre-Reserve floor, stale original Checks, unavailable transport or
    /// unresolved same-envelope status before another transaction can be submitted.
    pub fn submit_reserve_with(
        self,
        receipt_time: FinalPromotionEligibilityTimeIntervalV1,
        account_time: FinalPromotionAccountEligibilityTimeIntervalV1,
        floor: &mut impl FinalPromotionRetainedFloorV1,
        submission: &mut impl FinalPromotionNativeSubmissionV1,
    ) -> Result<FinalPromotionSubmittedReserveV1, Error> {
        if floor.read().map_err(|_| Error::Floor)? != self.pre_reserve_floor {
            return Err(Error::Floor);
        }
        // This is a same-height State/Kura/QC context preflight, not a replacement for Core's
        // later full source-to-Check successor proof or an independently funded floor issuer.
        let view = self.state.view();
        authenticate_pre_reserve_floor_at_v1(&view, self.pre_reserve_floor)?;
        drop(view);
        let original = self
            .signed_reserve
            .for_submission(receipt_time, account_time)
            .map_err(|_| Error::Check)?;
        self.pending_reserve
            .matches_live(
                &self.request,
                self.pre_reserve_floor,
                self.signed_reserve.original_current_check(),
                original,
            )
            .map_err(|_| Error::Journal)?;
        let outcome = submission
            .submit_exact(original)
            .map_err(|_| Error::Submission)?;
        if outcome == FinalPromotionNativeSubmitOutcomeV1::Ambiguous {
            submission
                .reconcile_exact(self.signed_reserve.reconciliation_transaction())
                .map_err(|_| Error::Submission)?;
        }
        Ok(FinalPromotionSubmittedReserveV1(self))
    }
}

// Reject a false or unavailable independently retained floor before Reserve reaches transport.
// The separately governed floor issuer and funded successor replay remain production gates.
fn authenticate_pre_reserve_floor_at_v1(
    view: &StateView<'_>,
    floor: FinalPromotionCheckFloorV1,
) -> Result<(), Error> {
    if floor.height == 0 || floor.height > u64::try_from(view.height()).map_err(|_| Error::Floor)? {
        return Err(Error::Floor);
    }
    // The floor must be this view's certified block at its height (network, hash and the
    // certified block id of its header and result).
    let finality = verify_signer_finality_v1(view, floor.height, floor.block_hash)
        .map_err(|_| Error::Floor)?;
    if finality.context_id() != floor.context_id {
        return Err(Error::Floor);
    }
    Ok(())
}

/// Exact submitted Reserve awaiting a fresh finalized `BeforeProvider` observer Check.
pub struct FinalPromotionSubmittedReserveV1(FinalPromotionReservedCheckRuntimeV1);

impl FinalPromotionSubmittedReserveV1 {
    /// Challenge the real Reserved row, then prove the original Reserve and fresh Check in Core.
    ///
    /// The original pre-Reserve floor must still be the independently retained floor. Neither a
    /// transport acknowledgement nor the decoded row authorizes the phase. The floor advances
    /// only after Core proves both exact signed entries, successful execution and certified finality.
    ///
    /// # Errors
    /// Rejects missing/substituted Reserve, post-Reserve floor, stale Check, unqualified time,
    /// failed submission, missing finality or changed custody.
    pub fn observe_before_provider_with(
        self,
        payload: &mut impl FinalPromotionObserverCheckPayloadV1,
        signer: &mut impl FinalPromotionObserverCheckSignerV1,
        submission: &mut impl FinalPromotionNativeSubmissionV1,
        clock: &mut impl FinalPromotionQualifiedUtcV1,
        floor: &mut impl FinalPromotionRetainedFloorV1,
    ) -> Result<FinalPromotionReservedPostPersistenceV1, Error> {
        let owner = self.0;
        owner
            .pending_reserve
            .recheck()
            .map_err(|_| Error::Journal)?;
        if floor.read().map_err(|_| Error::Floor)? != owner.pre_reserve_floor {
            return Err(Error::Floor);
        }
        let view = owner.state.view();
        let height = u64::try_from(view.height()).map_err(|_| Error::Check)?;
        let snapshot = read_final_promotion_authority_at_v1(
            &view,
            owner.observer.receipt_binding(),
            height,
            Some(owner.request.operation_id),
        )
        .map_err(|_| Error::Check)?
        .ok_or(Error::Check)?;
        let operation = snapshot.operation.ok_or(Error::Check)?;
        if snapshot.operations.active_operation != Some(owner.request.operation_id)
            || operation.outcome != FinalPromotionOperationOutcomeV1::Reserved
            || operation.reserved.height <= owner.pre_reserve_floor.height
            || operation.intent.operation_id != owner.request.operation_id
            || operation.intent.request_digest
                != owner.request.digest().map_err(|_| Error::Binding)?
            || operation.custody != owner.request.original_custody
        {
            return Err(Error::Check);
        }
        let expected = FinalPromotionCheckExpectedV1 {
            binding: owner.observer.receipt_binding().clone(),
            observer: owner.observer.observer().clone(),
            expected_operator: AccountId::new(owner.observer.account_binding().public_key.clone()),
            request: owner.request,
            subject: FinalPromotionCheckSubjectV1::BeforeProvider(operation),
            control_revision: snapshot.control_record.revision,
            control_digest: snapshot.custody_anchor.state_digest,
            floor: owner.pre_reserve_floor,
        };
        drop(view);
        let prepared =
            begin_final_promotion_check_v1(Arc::clone(&owner.state), expected, owner.max_elapsed)
                .map_err(|_| Error::Check)?;
        let unsigned = payload
            .prepare(prepared.instruction())
            .map_err(|_| Error::Payload)?;
        let pending = owner
            .observer
            .sign_receipt_with(prepared, unsigned, |request| signer.sign(request))
            .map_err(|error| match error {
                FinalPromotionObserverTransactionErrorV1::Provider => Error::Provider,
                FinalPromotionObserverTransactionErrorV1::Payload => Error::Payload,
                FinalPromotionObserverTransactionErrorV1::Unavailable => Error::LocalCapacity,
                _ => Error::Check,
            })?;
        pending.ensure_live().map_err(|_| Error::Check)?;
        let outcome = submission
            .submit_exact(pending.signed_transaction())
            .map_err(|_| Error::Submission)?;
        if outcome == FinalPromotionNativeSubmitOutcomeV1::Ambiguous {
            pending.ensure_live().map_err(|_| Error::Check)?;
            submission
                .reconcile_exact(pending.signed_transaction())
                .map_err(|_| Error::Submission)?;
        }
        pending.ensure_live().map_err(|_| Error::Check)?;
        let mut verify = |pending: iroha_core::query::final_promotion_authority::observation::PendingFinalPromotionCheckV1| {
            pending.verify_finalized(
                FinalPromotionCheckSourceV1::Reserved(owner.signed_reserve.reconciliation_transaction()),
                || clock.sample().map_err(|_| FinalPromotionObservationErrorV1::Clock),
            )
        };
        let verified = crate::native_check_binding::complete_check(verify(pending), |failure| {
            verify(failure.into_pending())
        })
        .map_err(super::current_observation::verification_error)?;
        if verified.applied_floor().height <= owner.pre_reserve_floor.height {
            return Err(Error::Floor);
        }
        signing_context(
            &verified,
            owner.observer.receipt_binding(),
            verified.eligibility_time_interval(),
        )?;
        let applied = verified.applied_floor();
        if floor
            .advance_and_readback(owner.pre_reserve_floor, applied)
            .map_err(|_| Error::Floor)?
            != applied
        {
            return Err(Error::Floor);
        }
        Ok(FinalPromotionReservedPostPersistenceV1 {
            verified: Some(verified),
            binding: owner.observer.receipt_binding().clone(),
        })
    }
}

/// In-memory verified Check retained after the durable floor advanced.
///
/// A failed post-persistence clock sample leaves this owner available for a fresh sample within
/// the original Check lifetime. It cannot survive process loss: production still needs a durable
/// pending-envelope and pre-Reserve source-floor recovery journal before signing is enabled.
#[must_use = "finish this Check under a fresh qualified clock sample"]
pub struct FinalPromotionReservedPostPersistenceV1 {
    verified: Option<VerifiedFinalPromotionCheckV1>,
    binding: sorafs_manifest::signer::custody::SignerCustodyBindingV1,
}

impl FinalPromotionReservedPostPersistenceV1 {
    /// Applied descendant floor already retained by the independent floor provider.
    #[must_use]
    pub fn applied_floor(&self) -> Option<FinalPromotionCheckFloorV1> {
        self.verified
            .as_ref()
            .map(VerifiedFinalPromotionCheckV1::applied_floor)
    }

    /// Recheck a fresh qualified time after floor persistence without losing this owner on error.
    ///
    /// # Errors
    /// Fails closed but preserves the verified Check when the clock is unavailable or out of the
    /// original interval. A later call cannot extend the Check's monotonic lifetime.
    pub fn finish_with(
        &mut self,
        clock: &mut impl FinalPromotionQualifiedUtcV1,
    ) -> Result<FinalPromotionReservedObservationV1, Error> {
        let verified = self.verified.as_ref().ok_or(Error::Check)?;
        let after_persistence = clock.sample().map_err(|_| Error::Clock)?;
        verified
            .recheck_use_interval(after_persistence)
            .map_err(|_| Error::Clock)?;
        let custody = signing_context(verified, &self.binding, after_persistence)?;
        let verified = self.verified.take().ok_or(Error::Check)?;
        Ok(FinalPromotionReservedObservationV1 { verified, custody })
    }
}

/// One exact finalized `BeforeProvider` Check and same-cut eligible custody observation.
#[must_use = "consume this verified Reserved Check within its original interval"]
pub struct FinalPromotionReservedObservationV1 {
    verified: VerifiedFinalPromotionCheckV1,
    custody: SignerCustodyUseContextV1,
}

impl FinalPromotionReservedObservationV1 {
    /// Authenticated applied descendant floor already retained durably by the floor provider.
    #[must_use]
    pub const fn applied_floor(&self) -> FinalPromotionCheckFloorV1 {
        self.verified.applied_floor()
    }

    /// Consume the verified phase and custody from the same authenticated State cut.
    ///
    /// # Errors
    /// Rejects expiry of the original Check before its source consumes this result.
    pub fn into_reserved_context(
        self,
    ) -> Result<(VerifiedFinalPromotionCheckV1, SignerCustodyUseContextV1), Error> {
        self.verified.ensure_live().map_err(|_| Error::Check)?;
        Ok((self.verified, self.custody))
    }
}
