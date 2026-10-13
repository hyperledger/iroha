//! Pure state-machine logic for the durable native SoraFS reserve worker.
//!
//! This module deliberately contains no queue, signer, filesystem, or wall-clock
//! access. The supervised runtime supplies one coherent finalized snapshot and
//! the exact committed-envelope observation, then applies the returned action
//! through [`sorafs_node::reserve_transaction_forwarder`]. Keeping these
//! decisions pure makes policy rotation, foreign-chain rejection, restart
//! recovery, and idempotent semantic reconciliation byte-for-byte testable.
use iroha_data_model::{
    account::AccountId,
    sorafs::reserve::{
        ReserveAppealRecordV1, ReserveAppealStatusV1, ReserveAuthorityPolicyRecordV1,
        ReserveFinalizedCursorV1, ReserveMovementRecordV1, ReserveMovementStatusV1,
        ReserveProviderAccountV1,
    },
};
use iroha_model_base::chain::ChainId;
use sorafs_node::reserve_transaction_forwarder::{
    ReserveOperationV1, ReserveTransactionDeliveryStateV1, ReserveTransactionPendingV1,
    ReserveTransactionProjectionV1, ReserveTransactionReconciliationV1,
    validate_reserve_pending_delivery_v1, validate_reserve_reconciliation_material_v1,
};
/// Complete operation-scoped data read from one immutable finalized state view.
///
/// Query failures are represented outside this type: a caller must defer the
/// scan rather than synthesize an incomplete snapshot. `None` therefore means
/// that the queried record is authoritatively absent at `finalized_cursor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveFinalizedSnapshotV1 {
    /// Finalized block anchor shared by every field.
    pub finalized_cursor: ReserveFinalizedCursorV1,
    /// Current-chain hash resolved at the retained baseline height.
    ///
    /// An advanced tip is not sufficient by itself: this binding prevents a
    /// checkpoint from an abandoned fork with the same chain identifier from
    /// being signed or reconciled against the replacement history.
    pub baseline_block_hash: Option<[u8; 32]>,
    /// Active reserve governance policy, if one exists.
    pub policy_record: Option<ReserveAuthorityPolicyRecordV1>,
    /// Current provider-registry owner for registration operations.
    pub provider_owner: Option<AccountId>,
    /// Current reserve provider account for the affected provider.
    pub provider: Option<ReserveProviderAccountV1>,
    /// Current movement record for movement-identity operations.
    pub movement: Option<ReserveMovementRecordV1>,
    /// Current appeal record for appeal-identity operations.
    pub appeal: Option<ReserveAppealRecordV1>,
}
/// Result of comparing retained semantic material with finalized ledger state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveSemanticReconciliationV1 {
    /// Finalized state still exactly matches the retained signing preconditions.
    Ready(ReserveFinalizedCursorV1),
    /// The exact semantic operation was committed through any ingress.
    Finalized(ReserveFinalizedCursorV1),
    /// A coherent state view could not yet be compared with the retained base.
    Deferred,
    /// Pending and retained checkpoint material do not describe one operation.
    InvalidDurableState,
    /// Finalized state contradicts the retained operation.
    Conflict(ReserveFinalizedCursorV1),
}
/// Observation of the exact retained signed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveEnvelopeReconciliationV1 {
    /// The delivery has no signed bytes yet.
    NotSigned,
    /// The exact transaction remains queued as of the supplied finalized view.
    Pending {
        /// Digest used for the exact pipeline/committed lookup.
        transaction_digest: [u8; 32],
        /// Current finalized view at which the pending result was observed.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// The exact transaction committed successfully.
    Applied {
        /// Digest of the exact applied canonical transaction.
        transaction_digest: [u8; 32],
        /// Current finalized view in which application was resolved.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// The exact transaction committed with a terminal execution rejection.
    Rejected {
        /// Digest of the exact rejected canonical transaction.
        transaction_digest: [u8; 32],
        /// Current finalized view in which rejection was resolved.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// The exact transaction is absent after this finalized anchor.
    Absent {
        /// Digest used for the exact absence proof.
        transaction_digest: [u8; 32],
        /// Current finalized view through which absence was established.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// Durable block/index state could not be inspected coherently.
    Unavailable,
}
/// Payload-free reason why one worker entry is intentionally left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveWorkerDeferReasonV1 {
    /// A finalized query or committed-block lookup was unavailable.
    FinalizedStateUnavailable,
    /// The configured runtime signer does not own the retained exact authority.
    SignerAuthorityMismatch,
    /// A signer-only claim is in progress and must be recovered by durable open.
    SigningClaimInProgress,
    /// The exact transaction remains queued or has not advanced past its base.
    AwaitingFinality,
    /// Durable signed-byte metadata is internally incomplete.
    InvalidDurableState,
}
/// One side-effect requested from the supervised reserve worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveWorkerActionV1 {
    /// Claim the operation durably, then ask the injected external signer.
    ClaimForSigning,
    /// Begin durable submission of the already retained exact signed bytes.
    SubmitSignedBytes,
    /// Adopt an exact transaction observed pending through another ingress.
    ///
    /// A `Signed` entry must first be durably moved through `begin_submission`;
    /// an `Ambiguous` entry can be marked submitted directly.
    AdoptExactPending,
    /// Complete the operation using the exact retained transaction digest.
    FinalizeExact {
        /// Digest of the exact canonical signed bytes.
        transaction_digest: [u8; 32],
        /// Block that finalized the exact envelope.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// Complete an idempotent semantic operation committed through another ingress.
    FinalizeSemantic {
        /// Finalized block containing or proving the semantic result.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// Clear a terminally rejected envelope for bounded replacement signing.
    ///
    /// A `Signed` entry must first be durably moved through `begin_submission`
    /// before calling the forwarder's rejection transition.
    MarkTransactionRejected {
        /// Finalized block containing the rejected transaction.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// Retry the exact bytes only after finalized absence was proven.
    MarkFinalizedAbsent {
        /// Later finalized anchor at which the transaction was absent.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// Dead-letter a semantic identity contradicted by finalized state.
    DeadLetterConflict {
        /// Finalized block at which the contradiction was observed.
        finalized_cursor: ReserveFinalizedCursorV1,
    },
    /// Leave the durable entry untouched until a later bounded scan.
    Defer(ReserveWorkerDeferReasonV1),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizedCursorRelationV1 {
    Same,
    Advanced,
    Older,
    ForkConflict,
    Invalid,
}
/// Compare one retained reserve operation with an exact finalized projection.
///
/// Unique registration, movement, appeal, and decision identities can be completed semantically
/// after a cross-peer duplicate submission. Rent, lifecycle, draw, and repayment operations
/// intentionally require exact transaction reconciliation because their revision identity alone
/// cannot prove which payload changed the provider account.
pub fn reconcile_reserve_semantics(
    expected_chain_id: &ChainId,
    delivery: &ReserveTransactionPendingV1,
    retained: &ReserveTransactionReconciliationV1,
    finalized: &ReserveFinalizedSnapshotV1,
) -> ReserveSemanticReconciliationV1 {
    let cursor = finalized.finalized_cursor;
    if validate_reserve_reconciliation_material_v1(delivery, retained).is_err() {
        return ReserveSemanticReconciliationV1::InvalidDurableState;
    }
    if &delivery.chain_id != expected_chain_id || &retained.request.chain_id != expected_chain_id {
        return if valid_finalized_cursor(cursor) {
            ReserveSemanticReconciliationV1::Conflict(cursor)
        } else {
            ReserveSemanticReconciliationV1::Deferred
        };
    }
    let relation = finalized_cursor_relation(delivery, cursor);
    match relation {
        FinalizedCursorRelationV1::Invalid | FinalizedCursorRelationV1::Older => {
            return ReserveSemanticReconciliationV1::Deferred;
        }
        FinalizedCursorRelationV1::ForkConflict => {
            return ReserveSemanticReconciliationV1::Conflict(cursor);
        }
        FinalizedCursorRelationV1::Same | FinalizedCursorRelationV1::Advanced => {}
    }
    let Some(current_baseline_block_hash) = finalized.baseline_block_hash else {
        return ReserveSemanticReconciliationV1::Deferred;
    };
    if current_baseline_block_hash != delivery.baseline_finalized_block_hash {
        return ReserveSemanticReconciliationV1::Conflict(cursor);
    }
    if relation == FinalizedCursorRelationV1::Advanced {
        match unique_semantic_result(retained, finalized) {
            UniqueSemanticResultV1::Finalized => {
                return ReserveSemanticReconciliationV1::Finalized(cursor);
            }
            UniqueSemanticResultV1::Conflict => {
                return ReserveSemanticReconciliationV1::Conflict(cursor);
            }
            UniqueSemanticResultV1::NotApplicableOrAbsent => {}
        }
    }
    if finalized.policy_record.as_ref() != Some(&retained.policy_record)
        || !finalized_projection_matches_retained(retained, finalized)
        || finalized_authority(retained, finalized) != Some(&retained.request.authority)
    {
        return ReserveSemanticReconciliationV1::Conflict(cursor);
    }
    ReserveSemanticReconciliationV1::Ready(cursor)
}
/// Select one safe durable transition for a pending delivery.
///
/// Exact committed-envelope results take precedence over semantic projection changes. This is what
/// allows restart reconciliation after Torii's transient pipeline cache has expired.
pub fn plan_reserve_worker_action(
    expected_chain_id: &ChainId,
    configured_signer_authority: Option<&AccountId>,
    delivery: &ReserveTransactionPendingV1,
    envelope: ReserveEnvelopeReconciliationV1,
    semantics: ReserveSemanticReconciliationV1,
) -> ReserveWorkerActionV1 {
    let semantic_cursor = semantic_cursor(semantics);
    if semantics == ReserveSemanticReconciliationV1::InvalidDurableState
        || !valid_pending_delivery(delivery)
    {
        return ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState);
    }
    if semantic_cursor.is_some_and(|cursor| !valid_finalized_cursor(cursor)) {
        return ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable);
    }
    if &delivery.chain_id != expected_chain_id {
        return semantic_cursor.map_or(
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable),
            |finalized_cursor| ReserveWorkerActionV1::DeadLetterConflict { finalized_cursor },
        );
    }
    if !envelope_is_coherent(delivery, envelope, semantic_cursor) {
        return ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable);
    }
    match envelope {
        ReserveEnvelopeReconciliationV1::Applied {
            transaction_digest,
            finalized_cursor,
        } => {
            return ReserveWorkerActionV1::FinalizeExact {
                transaction_digest,
                finalized_cursor,
            };
        }
        ReserveEnvelopeReconciliationV1::Rejected {
            finalized_cursor, ..
        } => {
            return if delivery.transaction_digest.is_some()
                && matches!(
                    delivery.state,
                    ReserveTransactionDeliveryStateV1::Signed
                        | ReserveTransactionDeliveryStateV1::Ambiguous
                        | ReserveTransactionDeliveryStateV1::Submitted
                ) {
                ReserveWorkerActionV1::MarkTransactionRejected { finalized_cursor }
            } else {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState)
            };
        }
        ReserveEnvelopeReconciliationV1::NotSigned
        | ReserveEnvelopeReconciliationV1::Pending { .. }
        | ReserveEnvelopeReconciliationV1::Absent { .. }
        | ReserveEnvelopeReconciliationV1::Unavailable => {}
    }
    if let ReserveSemanticReconciliationV1::Finalized(finalized_cursor) = semantics {
        return ReserveWorkerActionV1::FinalizeSemantic { finalized_cursor };
    }
    if matches!(envelope, ReserveEnvelopeReconciliationV1::Pending { .. }) {
        return match delivery.state {
            ReserveTransactionDeliveryStateV1::Signed
            | ReserveTransactionDeliveryStateV1::Ambiguous => {
                ReserveWorkerActionV1::AdoptExactPending
            }
            ReserveTransactionDeliveryStateV1::Submitted => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::AwaitingFinality)
            }
            ReserveTransactionDeliveryStateV1::Ready
            | ReserveTransactionDeliveryStateV1::Signing => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState)
            }
        };
    }
    if matches!(envelope, ReserveEnvelopeReconciliationV1::Unavailable)
        && matches!(
            delivery.state,
            ReserveTransactionDeliveryStateV1::Signed
                | ReserveTransactionDeliveryStateV1::Ambiguous
                | ReserveTransactionDeliveryStateV1::Submitted
        )
    {
        return ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable);
    }
    match semantics {
        ReserveSemanticReconciliationV1::Conflict(finalized_cursor) => {
            return ReserveWorkerActionV1::DeadLetterConflict { finalized_cursor };
        }
        ReserveSemanticReconciliationV1::Deferred => {
            return ReserveWorkerActionV1::Defer(
                ReserveWorkerDeferReasonV1::FinalizedStateUnavailable,
            );
        }
        ReserveSemanticReconciliationV1::InvalidDurableState => {
            unreachable!("invalid durable state returns before envelope reconciliation")
        }
        ReserveSemanticReconciliationV1::Ready(_) => {}
        ReserveSemanticReconciliationV1::Finalized(_) => {
            unreachable!("semantic finalization returns before delivery-state planning")
        }
    }
    match delivery.state {
        ReserveTransactionDeliveryStateV1::Ready => {
            if delivery.signed_transaction_bytes.is_some() || delivery.transaction_digest.is_some()
            {
                return ReserveWorkerActionV1::Defer(
                    ReserveWorkerDeferReasonV1::InvalidDurableState,
                );
            }
            if configured_signer_authority != Some(&delivery.authority) {
                return ReserveWorkerActionV1::Defer(
                    ReserveWorkerDeferReasonV1::SignerAuthorityMismatch,
                );
            }
            ReserveWorkerActionV1::ClaimForSigning
        }
        ReserveTransactionDeliveryStateV1::Signing => {
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::SigningClaimInProgress)
        }
        ReserveTransactionDeliveryStateV1::Signed => match envelope {
            ReserveEnvelopeReconciliationV1::Pending { .. } => {
                ReserveWorkerActionV1::AdoptExactPending
            }
            ReserveEnvelopeReconciliationV1::Absent { .. } => {
                ReserveWorkerActionV1::SubmitSignedBytes
            }
            ReserveEnvelopeReconciliationV1::Unavailable => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable)
            }
            ReserveEnvelopeReconciliationV1::NotSigned => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState)
            }
            ReserveEnvelopeReconciliationV1::Applied { .. }
            | ReserveEnvelopeReconciliationV1::Rejected { .. } => unreachable!(
                "terminal exact-envelope outcomes return before delivery-state planning"
            ),
        },
        ReserveTransactionDeliveryStateV1::Ambiguous
        | ReserveTransactionDeliveryStateV1::Submitted => match envelope {
            ReserveEnvelopeReconciliationV1::Pending { .. }
                if delivery.state == ReserveTransactionDeliveryStateV1::Ambiguous =>
            {
                ReserveWorkerActionV1::AdoptExactPending
            }
            ReserveEnvelopeReconciliationV1::Absent {
                finalized_cursor, ..
            } if finalized_cursor.height > delivery.baseline_finalized_height => {
                ReserveWorkerActionV1::MarkFinalizedAbsent { finalized_cursor }
            }
            ReserveEnvelopeReconciliationV1::Unavailable => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable)
            }
            ReserveEnvelopeReconciliationV1::NotSigned => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState)
            }
            ReserveEnvelopeReconciliationV1::Pending { .. }
            | ReserveEnvelopeReconciliationV1::Absent { .. }
            | ReserveEnvelopeReconciliationV1::Applied { .. }
            | ReserveEnvelopeReconciliationV1::Rejected { .. } => {
                ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::AwaitingFinality)
            }
        },
    }
}
fn envelope_is_coherent(
    delivery: &ReserveTransactionPendingV1,
    envelope: ReserveEnvelopeReconciliationV1,
    semantic_cursor: Option<ReserveFinalizedCursorV1>,
) -> bool {
    if !valid_pending_delivery(delivery) {
        return false;
    }
    let signed_material_is_complete = delivery.signed_transaction_bytes.is_some();
    let signed_material_is_absent = delivery.signed_transaction_bytes.is_none();
    match envelope {
        ReserveEnvelopeReconciliationV1::NotSigned => signed_material_is_absent,
        ReserveEnvelopeReconciliationV1::Unavailable => true,
        ReserveEnvelopeReconciliationV1::Pending {
            transaction_digest,
            finalized_cursor,
        }
        | ReserveEnvelopeReconciliationV1::Applied {
            transaction_digest,
            finalized_cursor,
        }
        | ReserveEnvelopeReconciliationV1::Rejected {
            transaction_digest,
            finalized_cursor,
        }
        | ReserveEnvelopeReconciliationV1::Absent {
            transaction_digest,
            finalized_cursor,
        } => {
            signed_material_is_complete
                && delivery.transaction_digest == Some(transaction_digest)
                && transaction_digest != [0; 32]
                && valid_finalized_cursor(finalized_cursor)
                && semantic_cursor == Some(finalized_cursor)
        }
    }
}
fn valid_pending_delivery(delivery: &ReserveTransactionPendingV1) -> bool {
    validate_reserve_pending_delivery_v1(delivery).is_ok()
}
fn valid_finalized_cursor(cursor: ReserveFinalizedCursorV1) -> bool {
    cursor.height != 0 && cursor.block_hash != [0; 32]
}
fn finalized_cursor_relation(
    delivery: &ReserveTransactionPendingV1,
    cursor: ReserveFinalizedCursorV1,
) -> FinalizedCursorRelationV1 {
    if !valid_finalized_cursor(cursor)
        || delivery.baseline_finalized_height == 0
        || delivery.baseline_finalized_block_hash == [0; 32]
    {
        return FinalizedCursorRelationV1::Invalid;
    }
    match cursor.height.cmp(&delivery.baseline_finalized_height) {
        core::cmp::Ordering::Less => FinalizedCursorRelationV1::Older,
        core::cmp::Ordering::Greater => FinalizedCursorRelationV1::Advanced,
        core::cmp::Ordering::Equal
            if cursor.block_hash == delivery.baseline_finalized_block_hash =>
        {
            FinalizedCursorRelationV1::Same
        }
        core::cmp::Ordering::Equal => FinalizedCursorRelationV1::ForkConflict,
    }
}
fn finalized_projection_matches_retained(
    retained: &ReserveTransactionReconciliationV1,
    finalized: &ReserveFinalizedSnapshotV1,
) -> bool {
    match &retained.projection {
        ReserveTransactionProjectionV1::Registration { provider_owner } => {
            finalized.provider.is_none()
                && finalized.provider_owner.as_ref() == Some(provider_owner)
                && finalized.movement.is_none()
                && finalized.appeal.is_none()
        }
        ReserveTransactionProjectionV1::Provider { account } => {
            finalized.provider.as_ref() == Some(account)
                && finalized.movement.is_none()
                && finalized.appeal.is_none()
        }
        ReserveTransactionProjectionV1::MovementDecision { account, movement } => {
            finalized.provider.as_ref() == Some(account)
                && finalized.movement.as_ref() == Some(movement)
                && finalized.appeal.is_none()
        }
        ReserveTransactionProjectionV1::AppealDecision { account, appeal } => {
            finalized.provider.as_ref() == Some(account)
                && finalized.appeal.as_ref() == Some(appeal)
                && finalized.movement.is_none()
        }
    }
}
fn finalized_authority<'a>(
    retained: &ReserveTransactionReconciliationV1,
    finalized: &'a ReserveFinalizedSnapshotV1,
) -> Option<&'a AccountId> {
    let policy = finalized.policy_record.as_ref()?;
    match &retained.request.operation {
        ReserveOperationV1::RegisterProvider(_)
        | ReserveOperationV1::ChargeRent(_)
        | ReserveOperationV1::AdvanceLifecycle(_)
        | ReserveOperationV1::DrawCredit(_) => Some(&policy.policy.operations_authority),
        ReserveOperationV1::DecideMovement(_) | ReserveOperationV1::DecideAppeal(_) => {
            Some(&policy.policy.decision_authority)
        }
        ReserveOperationV1::RequestMovement(_)
        | ReserveOperationV1::RepayCredit(_)
        | ReserveOperationV1::SubmitAppeal(_) => finalized
            .provider
            .as_ref()
            .map(|provider| &provider.terms.provider_account),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniqueSemanticResultV1 {
    NotApplicableOrAbsent,
    Finalized,
    Conflict,
}
fn unique_semantic_result(
    retained: &ReserveTransactionReconciliationV1,
    finalized: &ReserveFinalizedSnapshotV1,
) -> UniqueSemanticResultV1 {
    match &retained.request.operation {
        ReserveOperationV1::RegisterProvider(instruction) => {
            let Some(provider) = finalized.provider.as_ref() else {
                return UniqueSemanticResultV1::NotApplicableOrAbsent;
            };
            if &provider.terms == instruction.terms()
                && provider.policy_digest == *instruction.policy_digest()
                && provider.revision != 0
            {
                UniqueSemanticResultV1::Finalized
            } else {
                UniqueSemanticResultV1::Conflict
            }
        }
        ReserveOperationV1::RequestMovement(instruction) => {
            let Some(movement) = finalized.movement.as_ref() else {
                return UniqueSemanticResultV1::NotApplicableOrAbsent;
            };
            if movement.movement_id == *instruction.movement_id()
                && movement.provider_id == *instruction.provider_id()
                && movement.kind == *instruction.kind()
                && &movement.amount == instruction.amount()
                && movement.requested_by == retained.request.authority
                && movement.expected_provider_revision == *instruction.expected_provider_revision()
                && movement.policy_digest == *instruction.policy_digest()
                && movement.requested_at_unix != 0
            {
                UniqueSemanticResultV1::Finalized
            } else {
                UniqueSemanticResultV1::Conflict
            }
        }
        ReserveOperationV1::DecideMovement(instruction) => {
            let Some(movement) = finalized.movement.as_ref() else {
                return UniqueSemanticResultV1::Conflict;
            };
            let ReserveTransactionProjectionV1::MovementDecision {
                movement: retained_movement,
                ..
            } = &retained.projection
            else {
                return UniqueSemanticResultV1::Conflict;
            };
            if movement.status == ReserveMovementStatusV1::Pending {
                return if movement == retained_movement {
                    UniqueSemanticResultV1::NotApplicableOrAbsent
                } else {
                    UniqueSemanticResultV1::Conflict
                };
            }
            let expected_status = if *instruction.approve() {
                ReserveMovementStatusV1::Approved
            } else {
                ReserveMovementStatusV1::Rejected
            };
            if same_movement_request(movement, retained_movement)
                && movement.status == expected_status
                && movement.decided_by.as_ref() == Some(&retained.request.authority)
                && movement
                    .decided_at_unix
                    .is_some_and(|timestamp| timestamp != 0)
                && movement.rationale.as_deref() == Some(instruction.rationale())
            {
                UniqueSemanticResultV1::Finalized
            } else {
                UniqueSemanticResultV1::Conflict
            }
        }
        ReserveOperationV1::SubmitAppeal(instruction) => {
            let Some(appeal) = finalized.appeal.as_ref() else {
                return UniqueSemanticResultV1::NotApplicableOrAbsent;
            };
            if appeal.appeal_id == *instruction.appeal_id()
                && appeal.provider_id == *instruction.provider_id()
                && appeal.submitted_by == retained.request.authority
                && appeal.expected_provider_revision == *instruction.expected_provider_revision()
                && appeal.requested_stage == *instruction.requested_stage()
                && appeal.reason.as_str() == instruction.reason()
                && appeal.evidence_digest == *instruction.evidence_digest()
                && appeal.submitted_at_unix != 0
            {
                UniqueSemanticResultV1::Finalized
            } else {
                UniqueSemanticResultV1::Conflict
            }
        }
        ReserveOperationV1::DecideAppeal(instruction) => {
            let Some(appeal) = finalized.appeal.as_ref() else {
                return UniqueSemanticResultV1::Conflict;
            };
            let ReserveTransactionProjectionV1::AppealDecision {
                appeal: retained_appeal,
                ..
            } = &retained.projection
            else {
                return UniqueSemanticResultV1::Conflict;
            };
            if appeal.status == ReserveAppealStatusV1::Pending {
                return if appeal == retained_appeal {
                    UniqueSemanticResultV1::NotApplicableOrAbsent
                } else {
                    UniqueSemanticResultV1::Conflict
                };
            }
            let expected_status = if *instruction.accept() {
                ReserveAppealStatusV1::Accepted
            } else {
                ReserveAppealStatusV1::Rejected
            };
            if same_appeal_request(appeal, retained_appeal)
                && appeal.status == expected_status
                && appeal.decided_by.as_ref() == Some(&retained.request.authority)
                && appeal
                    .decided_at_unix
                    .is_some_and(|timestamp| timestamp != 0)
                && appeal.rationale.as_deref() == Some(instruction.rationale())
            {
                UniqueSemanticResultV1::Finalized
            } else {
                UniqueSemanticResultV1::Conflict
            }
        }
        ReserveOperationV1::ChargeRent(_)
        | ReserveOperationV1::AdvanceLifecycle(_)
        | ReserveOperationV1::DrawCredit(_)
        | ReserveOperationV1::RepayCredit(_) => UniqueSemanticResultV1::NotApplicableOrAbsent,
    }
}
fn same_movement_request(
    current: &ReserveMovementRecordV1,
    retained: &ReserveMovementRecordV1,
) -> bool {
    current.movement_id == retained.movement_id
        && current.provider_id == retained.provider_id
        && current.kind == retained.kind
        && current.amount == retained.amount
        && current.requested_by == retained.requested_by
        && current.expected_provider_revision == retained.expected_provider_revision
        && current.policy_digest == retained.policy_digest
        && current.requested_at_unix == retained.requested_at_unix
}
fn same_appeal_request(current: &ReserveAppealRecordV1, retained: &ReserveAppealRecordV1) -> bool {
    current.appeal_id == retained.appeal_id
        && current.provider_id == retained.provider_id
        && current.submitted_by == retained.submitted_by
        && current.requested_stage == retained.requested_stage
        && current.reason == retained.reason
        && current.evidence_digest == retained.evidence_digest
        && current.expected_provider_revision == retained.expected_provider_revision
        && current.submitted_at_unix == retained.submitted_at_unix
}
fn semantic_cursor(semantics: ReserveSemanticReconciliationV1) -> Option<ReserveFinalizedCursorV1> {
    match semantics {
        ReserveSemanticReconciliationV1::Ready(cursor)
        | ReserveSemanticReconciliationV1::Finalized(cursor)
        | ReserveSemanticReconciliationV1::Conflict(cursor) => Some(cursor),
        ReserveSemanticReconciliationV1::Deferred
        | ReserveSemanticReconciliationV1::InvalidDurableState => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        asset::AssetDefinitionId,
        isi::sorafs::{
            AdvanceSorafsReserveLifecycle, ChargeSorafsReserveRent, DecideSorafsReserveAppeal,
            DecideSorafsReserveMovement, DrawSorafsReserveCredit, RegisterSorafsReserveAccount,
            RepaySorafsReserveCredit, RequestSorafsReserveMovement, SubmitSorafsReserveAppeal,
        },
        sorafs::{
            capacity::ProviderId,
            pin_registry::StorageClass,
            reserve::{
                RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAppealRecordV1, ReserveAppealStatusV1,
                ReserveAuthorityPolicyRecordV1, ReserveAuthorityPolicyV1, ReserveDuration,
                ReserveFinalizedCursorV1, ReserveLifecycleStage, ReserveMovementKindV1,
                ReserveMovementRecordV1, ReserveMovementStatusV1, ReservePolicyV1,
                ReserveProviderAccountV1, ReserveProviderTermsV1, ReserveTier,
            },
        },
    };
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use sorafs_manifest::deal::XorQuantity;
    use sorafs_node::reserve_transaction_forwarder::{
        ReserveOperationV1, ReserveTransactionContextV1, ReserveTransactionDeliveryStateV1,
        ReserveTransactionForwarder, ReserveTransactionForwarderPolicyV1,
        ReserveTransactionProjectionV1, ReserveTransactionReconciliationV1,
    };
    use tempfile::TempDir;
    const CHAIN: &str = "reserve-worker-test";
    fn key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test key")
    }
    fn account(key: &KeyPair) -> AccountId {
        AccountId::new(key.public_key().clone())
    }
    fn provider_id(seed: u8) -> ProviderId {
        ProviderId::new([seed; 32])
    }
    fn cursor(height: u64, seed: u8) -> ReserveFinalizedCursorV1 {
        ReserveFinalizedCursorV1 {
            height,
            block_hash: [seed; 32],
        }
    }
    fn policy_record(
        operations: &KeyPair,
        decision: &KeyPair,
        revision: u64,
        predecessor_policy_digest: Option<[u8; 32]>,
    ) -> ReserveAuthorityPolicyRecordV1 {
        let policy = ReserveAuthorityPolicyV1 {
            version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
            revision,
            predecessor_policy_digest,
            economics: ReservePolicyV1::default(),
            asset_definition: AssetDefinitionId::derive_from_components(
                DomainId::try_new("reserve", "universal").expect("domain"),
                "xor".parse().expect("asset name"),
            ),
            custody_account: account(&key(0xC1)),
            treasury_account: account(&key(0xC2)),
            operations_authority: account(operations),
            decision_authority: account(decision),
            grace_period_days: 7,
            default_after_days: 30,
            max_provider_debt: XorQuantity::try_from_micro(1_000_000_000).expect("debt cap"),
            max_pending_movements_per_provider: 8,
            max_open_appeals_per_provider: 4,
        };
        let policy_digest = policy.digest().expect("policy digest");
        ReserveAuthorityPolicyRecordV1 {
            policy,
            policy_digest,
            activated_by: account(operations),
            activated_at_unix: revision,
        }
    }
    fn provider_account(
        provider: &KeyPair,
        policy_digest: [u8; 32],
        revision: u64,
    ) -> ReserveProviderAccountV1 {
        ReserveProviderAccountV1 {
            terms: ReserveProviderTermsV1 {
                provider_id: provider_id(0x51),
                provider_account: account(provider),
                tier: ReserveTier::TierA,
                storage_class: StorageClass::Hot,
                duration: ReserveDuration::Monthly,
                capacity_gib: 64,
            },
            policy_digest,
            revision,
            reserve_balance: XorQuantity::try_from_micro(100_000_000).expect("reserve"),
            debt_principal: XorQuantity::try_from_micro(10_000_000).expect("principal"),
            accrued_interest: XorQuantity::try_from_micro(1_000_000).expect("interest"),
            credit_cap: XorQuantity::try_from_micro(100_000_000).expect("credit cap"),
            lifecycle_stage: ReserveLifecycleStage::Warning,
            days_past_due: 2,
            pending_movements: 1,
            open_appeals: 1,
            rent_charged_through_unix: 100,
            interest_accrued_at_unix: 100,
            updated_at_unix: 100,
        }
    }
    fn provider_context(
        operations: &KeyPair,
        decision: &KeyPair,
        provider: &KeyPair,
    ) -> ReserveTransactionContextV1 {
        let policy_record = policy_record(operations, decision, 1, None);
        ReserveTransactionContextV1 {
            network_id: crate::signed_query_test_network_id(),
            chain_id: ChainId::from(CHAIN),
            projection: ReserveTransactionProjectionV1::Provider {
                account: provider_account(provider, policy_record.policy_digest, 7),
            },
            policy_record,
            finalized_cursor: cursor(11, 0x11),
        }
    }
    fn movement_context(
        operations: &KeyPair,
        decision: &KeyPair,
        provider: &KeyPair,
    ) -> ReserveTransactionContextV1 {
        let mut context = provider_context(operations, decision, provider);
        let ReserveTransactionProjectionV1::Provider { account } = context.projection else {
            unreachable!()
        };
        context.projection = ReserveTransactionProjectionV1::MovementDecision {
            movement: ReserveMovementRecordV1 {
                movement_id: [0x61; 32],
                provider_id: account.terms.provider_id,
                kind: ReserveMovementKindV1::TopUp,
                amount: XorQuantity::try_from_micro(3_000_000).expect("movement"),
                requested_by: account.terms.provider_account.clone(),
                expected_provider_revision: 6,
                policy_digest: context.policy_record.policy_digest,
                status: ReserveMovementStatusV1::Pending,
                requested_at_unix: 90,
                decided_by: None,
                decided_at_unix: None,
                rationale: None,
            },
            account,
        };
        context
    }
    fn appeal_context(
        operations: &KeyPair,
        decision: &KeyPair,
        provider: &KeyPair,
    ) -> ReserveTransactionContextV1 {
        let mut context = provider_context(operations, decision, provider);
        let ReserveTransactionProjectionV1::Provider { account } = context.projection else {
            unreachable!()
        };
        context.projection = ReserveTransactionProjectionV1::AppealDecision {
            appeal: ReserveAppealRecordV1 {
                appeal_id: [0x71; 32],
                provider_id: account.terms.provider_id,
                submitted_by: account.terms.provider_account.clone(),
                requested_stage: ReserveLifecycleStage::Active,
                reason: "review lifecycle evidence".to_owned(),
                evidence_digest: Some([0x72; 32]),
                expected_provider_revision: 6,
                status: ReserveAppealStatusV1::Pending,
                submitted_at_unix: 90,
                decided_by: None,
                decided_at_unix: None,
                rationale: None,
            },
            account,
        };
        context
    }
    fn registration_context(
        operations: &KeyPair,
        decision: &KeyPair,
        provider: &KeyPair,
    ) -> ReserveTransactionContextV1 {
        ReserveTransactionContextV1 {
            network_id: crate::signed_query_test_network_id(),
            chain_id: ChainId::from(CHAIN),
            policy_record: policy_record(operations, decision, 1, None),
            projection: ReserveTransactionProjectionV1::Registration {
                provider_owner: account(provider),
            },
            finalized_cursor: cursor(11, 0x11),
        }
    }
    fn forwarder() -> (ReserveTransactionForwarder, TempDir) {
        let state_dir = tempfile::tempdir().expect("reserve forwarder state directory");
        let forwarder = ReserveTransactionForwarder::open(
            state_dir.path(),
            ReserveTransactionForwarderPolicyV1 {
                max_pending: 32,
                max_completed: 32,
                max_dead_letters: 32,
                max_attempts: 4,
                max_transaction_bytes: 512 * 1024,
                checkpoint_max_bytes: 4 * 1024 * 1024,
            },
        )
        .expect("durable reserve forwarder");
        (forwarder, state_dir)
    }
    fn retained_delivery(
        operation: ReserveOperationV1,
        context: &ReserveTransactionContextV1,
    ) -> (
        ReserveTransactionPendingV1,
        ReserveTransactionReconciliationV1,
    ) {
        let (forwarder, _state_dir) = forwarder();
        let operation_id = forwarder
            .enqueue_unsigned_operation(operation, context)
            .expect("enqueue")
            .operation_id();
        let delivery = forwarder.pending(1).expect("pending").remove(0);
        let retained = forwarder
            .operation_for_reconciliation(operation_id)
            .expect("retained");
        (delivery, retained)
    }
    fn snapshot_from_retained(
        delivery: &ReserveTransactionPendingV1,
        retained: &ReserveTransactionReconciliationV1,
        finalized_cursor: ReserveFinalizedCursorV1,
    ) -> ReserveFinalizedSnapshotV1 {
        let mut snapshot = ReserveFinalizedSnapshotV1 {
            finalized_cursor,
            baseline_block_hash: Some(delivery.baseline_finalized_block_hash),
            policy_record: Some(retained.policy_record.clone()),
            provider_owner: None,
            provider: None,
            movement: None,
            appeal: None,
        };
        match &retained.projection {
            ReserveTransactionProjectionV1::Registration { provider_owner } => {
                snapshot.provider_owner = Some(provider_owner.clone());
            }
            ReserveTransactionProjectionV1::Provider { account } => {
                snapshot.provider = Some(account.clone());
            }
            ReserveTransactionProjectionV1::MovementDecision { account, movement } => {
                snapshot.provider = Some(account.clone());
                snapshot.movement = Some(movement.clone());
            }
            ReserveTransactionProjectionV1::AppealDecision { account, appeal } => {
                snapshot.provider = Some(account.clone());
                snapshot.appeal = Some(appeal.clone());
            }
        }
        snapshot
    }
    #[test]
    fn all_nine_native_operations_are_ready_only_on_the_exact_finalized_projection() {
        let operations = key(0x31);
        let decision = key(0x32);
        let provider = key(0x33);
        let registration = registration_context(&operations, &decision, &provider);
        let provider_projection = provider_context(&operations, &decision, &provider);
        let movement_projection = movement_context(&operations, &decision, &provider);
        let appeal_projection = appeal_context(&operations, &decision, &provider);
        let ReserveTransactionProjectionV1::Provider {
            account: provider_account,
        } = &provider_projection.projection
        else {
            unreachable!()
        };
        let provider_account = provider_account.clone();
        let ReserveTransactionProjectionV1::MovementDecision { movement, .. } =
            &movement_projection.projection
        else {
            unreachable!()
        };
        let movement = movement.clone();
        let ReserveTransactionProjectionV1::AppealDecision { appeal, .. } =
            &appeal_projection.projection
        else {
            unreachable!()
        };
        let appeal = appeal.clone();
        let operations_and_contexts = vec![
            (
                ReserveOperationV1::RegisterProvider(RegisterSorafsReserveAccount::new(
                    ReserveProviderTermsV1 {
                        provider_id: provider_id(0x51),
                        provider_account: account(&provider),
                        tier: ReserveTier::TierA,
                        storage_class: StorageClass::Hot,
                        duration: ReserveDuration::Monthly,
                        capacity_gib: 64,
                    },
                    registration.policy_record.policy_digest,
                )),
                registration,
            ),
            (
                ReserveOperationV1::RequestMovement(RequestSorafsReserveMovement::new(
                    [0x81; 32],
                    provider_account.terms.provider_id,
                    ReserveMovementKindV1::TopUp,
                    XorQuantity::try_from_micro(2_000_000).expect("movement"),
                    provider_account.revision,
                    provider_projection.policy_record.policy_digest,
                )),
                provider_projection.clone(),
            ),
            (
                ReserveOperationV1::DecideMovement(DecideSorafsReserveMovement::new(
                    movement.movement_id,
                    provider_account.revision,
                    movement_projection.policy_record.policy_digest,
                    true,
                    "approved".to_owned(),
                )),
                movement_projection,
            ),
            (
                ReserveOperationV1::ChargeRent(ChargeSorafsReserveRent::new(
                    provider_account.terms.provider_id,
                    provider_account.revision,
                    1,
                    provider_projection.policy_record.policy_digest,
                )),
                provider_projection.clone(),
            ),
            (
                ReserveOperationV1::AdvanceLifecycle(AdvanceSorafsReserveLifecycle::new(
                    provider_account.terms.provider_id,
                    provider_account.revision,
                    3,
                    provider_projection.policy_record.policy_digest,
                )),
                provider_projection.clone(),
            ),
            (
                ReserveOperationV1::DrawCredit(DrawSorafsReserveCredit::new(
                    provider_account.terms.provider_id,
                    provider_account.revision,
                    XorQuantity::try_from_micro(1_000_000).expect("draw"),
                    provider_projection.policy_record.policy_digest,
                )),
                provider_projection.clone(),
            ),
            (
                ReserveOperationV1::RepayCredit(RepaySorafsReserveCredit::new(
                    provider_account.terms.provider_id,
                    provider_account.revision,
                    XorQuantity::try_from_micro(1_000_000).expect("repayment"),
                    provider_projection.policy_record.policy_digest,
                )),
                provider_projection.clone(),
            ),
            (
                ReserveOperationV1::SubmitAppeal(SubmitSorafsReserveAppeal::new(
                    [0x82; 32],
                    provider_account.terms.provider_id,
                    provider_account.revision,
                    ReserveLifecycleStage::Active,
                    "review evidence".to_owned(),
                    Some([0x83; 32]),
                    provider_projection.policy_record.policy_digest,
                )),
                provider_projection,
            ),
            (
                ReserveOperationV1::DecideAppeal(DecideSorafsReserveAppeal::new(
                    appeal.appeal_id,
                    provider_account.revision,
                    appeal_projection.policy_record.policy_digest,
                    true,
                    "accepted".to_owned(),
                )),
                appeal_projection,
            ),
        ];
        for (operation, context) in operations_and_contexts {
            let (delivery, retained) = retained_delivery(operation, &context);
            let snapshot = snapshot_from_retained(&delivery, &retained, context.finalized_cursor);
            assert_eq!(
                reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &retained, &snapshot,),
                ReserveSemanticReconciliationV1::Ready(context.finalized_cursor),
                "operation kind {:?}",
                delivery.kind,
            );
        }
    }
    #[test]
    fn reconciliation_rejects_a_same_summary_substituted_operation() {
        let operations = key(0x38);
        let decision = key(0x39);
        let provider = key(0x3A);
        let context = provider_context(&operations, &decision, &provider);
        let ReserveTransactionProjectionV1::Provider { account } = &context.projection else {
            unreachable!()
        };
        let original = ReserveOperationV1::ChargeRent(ChargeSorafsReserveRent::new(
            account.terms.provider_id,
            account.revision,
            1,
            context.policy_record.policy_digest,
        ));
        let (delivery, retained) = retained_delivery(original, &context);
        let snapshot = snapshot_from_retained(&delivery, &retained, context.finalized_cursor);
        let mut substituted = retained;
        substituted.request.operation =
            ReserveOperationV1::ChargeRent(ChargeSorafsReserveRent::new(
                account.terms.provider_id,
                account.revision,
                2,
                context.policy_record.policy_digest,
            ));
        assert_eq!(
            reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &substituted, &snapshot,),
            ReserveSemanticReconciliationV1::InvalidDurableState,
            "same kind/provider/revision metadata must not hide a different operation payload",
        );
    }
    #[test]
    fn policy_rotation_and_foreign_chain_are_terminal_conflicts() {
        let operations = key(0x41);
        let decision = key(0x42);
        let provider = key(0x43);
        let context = provider_context(&operations, &decision, &provider);
        let ReserveTransactionProjectionV1::Provider {
            account: provider_account,
        } = &context.projection
        else {
            unreachable!()
        };
        let operation = ReserveOperationV1::ChargeRent(ChargeSorafsReserveRent::new(
            provider_account.terms.provider_id,
            provider_account.revision,
            1,
            context.policy_record.policy_digest,
        ));
        let (delivery, retained) = retained_delivery(operation, &context);
        let advanced = cursor(12, 0x12);
        let mut snapshot = snapshot_from_retained(&delivery, &retained, advanced);
        snapshot.baseline_block_hash = Some([0xEE; 32]);
        assert_eq!(
            reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &retained, &snapshot,),
            ReserveSemanticReconciliationV1::Conflict(advanced),
        );
        snapshot.baseline_block_hash = None;
        assert_eq!(
            reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &retained, &snapshot,),
            ReserveSemanticReconciliationV1::Deferred,
        );
        snapshot.baseline_block_hash = Some(delivery.baseline_finalized_block_hash);
        snapshot.policy_record = Some(policy_record(
            &operations,
            &decision,
            2,
            Some(retained.policy_record.policy_digest),
        ));
        assert_eq!(
            reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &retained, &snapshot,),
            ReserveSemanticReconciliationV1::Conflict(advanced),
        );
        assert_eq!(
            reconcile_reserve_semantics(
                &ChainId::from("another-chain"),
                &delivery,
                &retained,
                &snapshot,
            ),
            ReserveSemanticReconciliationV1::Conflict(advanced),
        );
    }
    #[test]
    fn unique_movement_and_appeal_results_finalize_across_policy_rotation() {
        let operations = key(0x51);
        let decision = key(0x52);
        let provider = key(0x53);
        let context = provider_context(&operations, &decision, &provider);
        let ReserveTransactionProjectionV1::Provider { account } = &context.projection else {
            unreachable!()
        };
        let request = ReserveOperationV1::RequestMovement(RequestSorafsReserveMovement::new(
            [0x91; 32],
            account.terms.provider_id,
            ReserveMovementKindV1::Withdrawal,
            XorQuantity::try_from_micro(1_000_000).expect("movement"),
            account.revision,
            context.policy_record.policy_digest,
        ));
        let (delivery, retained) = retained_delivery(request.clone(), &context);
        let mut snapshot = snapshot_from_retained(&delivery, &retained, cursor(12, 0x12));
        let ReserveOperationV1::RequestMovement(instruction) = request else {
            unreachable!()
        };
        snapshot.movement = Some(ReserveMovementRecordV1 {
            movement_id: *instruction.movement_id(),
            provider_id: *instruction.provider_id(),
            kind: *instruction.kind(),
            amount: instruction.amount().clone(),
            requested_by: retained.request.authority.clone(),
            expected_provider_revision: *instruction.expected_provider_revision(),
            policy_digest: *instruction.policy_digest(),
            status: ReserveMovementStatusV1::Pending,
            requested_at_unix: 111,
            decided_by: None,
            decided_at_unix: None,
            rationale: None,
        });
        snapshot.policy_record = Some(policy_record(
            &operations,
            &decision,
            2,
            Some(retained.policy_record.policy_digest),
        ));
        assert_eq!(
            reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &retained, &snapshot,),
            ReserveSemanticReconciliationV1::Finalized(cursor(12, 0x12)),
        );
        let appeal = ReserveOperationV1::SubmitAppeal(SubmitSorafsReserveAppeal::new(
            [0x92; 32],
            account.terms.provider_id,
            account.revision,
            ReserveLifecycleStage::Active,
            "review evidence".to_owned(),
            Some([0x93; 32]),
            context.policy_record.policy_digest,
        ));
        let (delivery, retained) = retained_delivery(appeal.clone(), &context);
        let mut snapshot = snapshot_from_retained(&delivery, &retained, cursor(12, 0x12));
        let ReserveOperationV1::SubmitAppeal(instruction) = appeal else {
            unreachable!()
        };
        snapshot.appeal = Some(ReserveAppealRecordV1 {
            appeal_id: *instruction.appeal_id(),
            provider_id: *instruction.provider_id(),
            submitted_by: retained.request.authority.clone(),
            requested_stage: *instruction.requested_stage(),
            reason: instruction.reason().to_owned(),
            evidence_digest: *instruction.evidence_digest(),
            expected_provider_revision: *instruction.expected_provider_revision(),
            status: ReserveAppealStatusV1::Pending,
            submitted_at_unix: 112,
            decided_by: None,
            decided_at_unix: None,
            rationale: None,
        });
        snapshot.policy_record = Some(policy_record(
            &operations,
            &decision,
            2,
            Some(retained.policy_record.policy_digest),
        ));
        assert_eq!(
            reconcile_reserve_semantics(&ChainId::from(CHAIN), &delivery, &retained, &snapshot,),
            ReserveSemanticReconciliationV1::Finalized(cursor(12, 0x12)),
        );
    }
    #[test]
    fn exact_envelope_results_precede_semantic_conflicts_and_restart_absence_retries() {
        let operations = key(0x61);
        let decision = key(0x62);
        let provider = key(0x63);
        let context = provider_context(&operations, &decision, &provider);
        let ReserveTransactionProjectionV1::Provider { account } = &context.projection else {
            unreachable!()
        };
        let operation = ReserveOperationV1::ChargeRent(ChargeSorafsReserveRent::new(
            account.terms.provider_id,
            account.revision,
            1,
            context.policy_record.policy_digest,
        ));
        let (mut delivery, _) = retained_delivery(operation, &context);
        let signed_transaction_bytes = vec![1, 2, 3];
        let transaction_digest = *blake3::hash(&signed_transaction_bytes).as_bytes();
        delivery.state = ReserveTransactionDeliveryStateV1::Submitted;
        delivery.attempts = 1;
        delivery.transaction_digest = Some(transaction_digest);
        delivery.signed_transaction_bytes = Some(signed_transaction_bytes);
        let applied = cursor(12, 0x12);
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Applied {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::InvalidDurableState,
            ),
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState),
        );
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Applied {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Conflict(applied),
            ),
            ReserveWorkerActionV1::FinalizeExact {
                transaction_digest,
                finalized_cursor: applied,
            },
        );
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Applied {
                    transaction_digest: [0xA1; 32],
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Conflict(applied),
            ),
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable),
            "a committed status for another transaction must not finalize this delivery",
        );
        delivery.state = ReserveTransactionDeliveryStateV1::Ambiguous;
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Pending {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Conflict(applied),
            ),
            ReserveWorkerActionV1::AdoptExactPending,
        );
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Unavailable,
                ReserveSemanticReconciliationV1::Conflict(applied),
            ),
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable),
        );
        delivery.state = ReserveTransactionDeliveryStateV1::Signed;
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Absent {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Ready(applied),
            ),
            ReserveWorkerActionV1::SubmitSignedBytes,
        );
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Absent {
                    transaction_digest,
                    finalized_cursor: cursor(13, 0x13),
                },
                ReserveSemanticReconciliationV1::Ready(applied),
            ),
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::FinalizedStateUnavailable),
        );
        delivery.state = ReserveTransactionDeliveryStateV1::Submitted;
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Absent {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Ready(applied),
            ),
            ReserveWorkerActionV1::MarkFinalizedAbsent {
                finalized_cursor: applied,
            },
        );
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::Rejected {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Ready(applied),
            ),
            ReserveWorkerActionV1::MarkTransactionRejected {
                finalized_cursor: applied,
            },
        );
        let mut corrupted = delivery;
        corrupted.signed_transaction_bytes = Some(vec![9, 9, 9]);
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&corrupted.authority),
                &corrupted,
                ReserveEnvelopeReconciliationV1::Applied {
                    transaction_digest,
                    finalized_cursor: applied,
                },
                ReserveSemanticReconciliationV1::Ready(applied),
            ),
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::InvalidDurableState),
            "signed-byte digest corruption must not be treated as transient chain absence",
        );
    }
    #[test]
    fn ready_delivery_requires_the_exact_injected_authority() {
        let operations = key(0x71);
        let decision = key(0x72);
        let provider = key(0x73);
        let context = provider_context(&operations, &decision, &provider);
        let ReserveTransactionProjectionV1::Provider {
            account: provider_account,
        } = &context.projection
        else {
            unreachable!()
        };
        let operation = ReserveOperationV1::ChargeRent(ChargeSorafsReserveRent::new(
            provider_account.terms.provider_id,
            provider_account.revision,
            1,
            context.policy_record.policy_digest,
        ));
        let (delivery, _) = retained_delivery(operation, &context);
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&delivery.authority),
                &delivery,
                ReserveEnvelopeReconciliationV1::NotSigned,
                ReserveSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            ReserveWorkerActionV1::ClaimForSigning,
        );
        let wrong = account(&key(0x74));
        assert_eq!(
            plan_reserve_worker_action(
                &ChainId::from(CHAIN),
                Some(&wrong),
                &delivery,
                ReserveEnvelopeReconciliationV1::NotSigned,
                ReserveSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            ReserveWorkerActionV1::Defer(ReserveWorkerDeferReasonV1::SignerAuthorityMismatch),
        );
    }
}
