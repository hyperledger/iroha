//! Pure state-machine logic for the durable native SoraFS orderbook worker.
//!
//! This module performs no queue, signer, filesystem, or wall-clock access. The supervised Torii
//! adapter supplies one coherent finalized-ledger observation keyed by the exact retained
//! transaction digest. The returned action is then applied through the shared
//! [`sorafs_node::orderbook_transaction_forwarder`].
//!
//! Match and maintenance operations deliberately do not complete from a book revision change alone.
//! Their bounded limits are part of the instruction but not the revision identity, so only an exact
//! committed envelope proves their semantic result. Settlement receipts have a globally unique
//! receipt identity and retain their exact canonical payload on-chain; those may be reconciled
//! idempotently across ingress peers.
use iroha_crypto::Algorithm;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::sorafs::{MaintainSorafsOrderbook, MatchSorafsOrderbook},
    sorafs::orderbook::{
        OrderbookAdmissionPolicyRecord, OrderbookFinalizedCursorV1, OrderbookLedgerStatusV1,
        OrderbookSettlementChannelRecord, OrderbookSettlementChannelStatusV1,
        OrderbookSettlementReceiptRecord,
    },
};
use sorafs_manifest::orderbook::{
    OrderbookSignatureV1, decode_settlement_receipt_v1, deterministic_settlement_split_v1,
    verify_settlement_receipt_signature_v1,
};
use sorafs_node::orderbook_transaction_forwarder::{
    ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1, OrderbookFinalizedContextValidationV1,
    OrderbookOperationV1, OrderbookTransactionDeliveryStateV1, OrderbookTransactionPendingV1,
    OrderbookTransactionSigningRequestV1, validate_orderbook_finalized_context_v1,
    validate_orderbook_pending_delivery_v1, validate_orderbook_reconciliation_material_v1,
};
/// Complete operation-scoped data read from one immutable finalized state.
///
/// Query failures are represented outside this type: the caller must defer the
/// scan instead of constructing a partial snapshot. A missing receipt therefore
/// means authoritative absence for the requested receipt identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderbookFinalizedSnapshotV1 {
    /// Finalized tip shared by the policy, status, and receipt queries.
    pub finalized_cursor: OrderbookFinalizedCursorV1,
    /// Finalized block timestamp used for receipt freshness decisions.
    pub finalized_at_unix: u64,
    /// Current-chain block hash resolved at the delivery's retained baseline.
    ///
    /// This binds an advanced tip to the same history and rejects checkpoints
    /// retained from an abandoned fork with the same chain identifier.
    pub baseline_block_hash: Option<[u8; 32]>,
    /// Active governed orderbook policy.
    pub policy_record: Option<OrderbookAdmissionPolicyRecord>,
    /// Authoritative orderbook counters, including the current book revision.
    pub status: Option<OrderbookLedgerStatusV1>,
    /// Receipt queried by the retained receipt identity, when applicable.
    pub settlement_receipt: Option<OrderbookSettlementReceiptRecord>,
    /// Channel queried by the retained receipt's channel identity, when applicable.
    pub settlement_channel: Option<OrderbookSettlementChannelRecord>,
}
/// Result of comparing retained semantic material with finalized ledger state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookSemanticReconciliationV1 {
    /// Finalized policy, authority, and revision still permit the operation.
    Ready(OrderbookFinalizedCursorV1),
    /// The exact uniquely identified receipt committed through any ingress.
    Finalized(OrderbookFinalizedCursorV1),
    /// A coherent finalized state view was not available.
    Deferred,
    /// Pending and retained checkpoint material do not describe one operation.
    InvalidDurableState,
    /// Finalized state contradicts or has consumed the retained precondition.
    Conflict(OrderbookFinalizedCursorV1),
}
/// Observation keyed by the exact retained signed-transaction digest.
///
/// The digest is repeated in every signed outcome so a caller cannot accidentally feed a status for
/// a different transaction into this worker. Every signed outcome is anchored at the same current
/// finalized cursor as the semantic snapshot; a containing block's older height/hash is not an
/// ancestry proof and must not be supplied in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookEnvelopeReconciliationV1 {
    /// The delivery has no signed bytes yet.
    NotSigned,
    /// The exact transaction remains queued.
    Pending {
        /// Digest used for the exact committed/pipeline lookup.
        transaction_digest: [u8; 32],
        /// Finalized view at which the pending result was observed.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// The exact transaction committed successfully.
    Applied {
        /// Digest of the exact applied canonical transaction.
        transaction_digest: [u8; 32],
        /// Current finalized view in which exact application was resolved.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// The exact transaction committed with terminal execution rejection.
    Rejected {
        /// Digest of the exact rejected canonical transaction.
        transaction_digest: [u8; 32],
        /// Current finalized view in which exact rejection was resolved.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// The exact transaction is absent from the finalized chain and queue.
    Absent {
        /// Digest used for the exact absence proof.
        transaction_digest: [u8; 32],
        /// Finalized view through which absence was established.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// The exact transaction index or committed blocks were unavailable.
    Unavailable,
}
/// Payload-free reason why an entry is intentionally left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookWorkerDeferReasonV1 {
    /// A finalized query or exact committed-envelope lookup was unavailable.
    FinalizedStateUnavailable,
    /// The configured injected signer does not own the governed authority.
    SignerAuthorityMismatch,
    /// A signer-only claim must first be recovered by durable forwarder open.
    SigningClaimInProgress,
    /// The exact transaction remains queued or has not advanced past its base.
    AwaitingFinality,
    /// Durable delivery material is missing, inconsistent, or corrupted.
    InvalidDurableState,
}
/// One side effect requested from the supervised orderbook worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookWorkerActionV1 {
    /// Claim durably, then ask the injected external signer.
    ClaimForSigning,
    /// Begin durable submission of the retained exact signed bytes.
    SubmitSignedBytes,
    /// Adopt an exact transaction observed pending through another ingress.
    ///
    /// A `Signed` entry first passes through `begin_submission`; an
    /// `Ambiguous` entry can be marked submitted directly.
    AdoptExactPending,
    /// Complete using the exact retained transaction digest.
    FinalizeExact {
        /// Digest of the exact canonical signed transaction.
        transaction_digest: [u8; 32],
        /// Current finalized anchor proving the exact envelope outcome.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// Complete a uniquely identified receipt committed through another ingress.
    FinalizeSemantic {
        /// Finalized anchor proving the semantic receipt record.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// Clear a terminally rejected envelope for bounded replacement signing.
    ///
    /// A `Signed` entry first passes through `begin_submission` before the
    /// forwarder's rejection transition is applied.
    MarkTransactionRejected {
        /// Current finalized anchor proving exact rejection.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// Re-enable the same exact bytes after finalized absence.
    MarkFinalizedAbsent {
        /// Later finalized anchor proving absence.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// Dead-letter a semantic identity contradicted by finalized state.
    DeadLetterConflict {
        /// Finalized anchor at which the contradiction was observed.
        finalized_cursor: OrderbookFinalizedCursorV1,
    },
    /// Leave the durable entry untouched until a later bounded scan.
    Defer(OrderbookWorkerDeferReasonV1),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizedCursorRelationV1 {
    Same,
    Advanced,
    Older,
    ForkConflict,
    Invalid,
}
/// Compare one retained operation with an exact finalized projection.
///
/// The snapshot must come from one immutable state view. In particular, the policy and status must
/// never be assembled from independently advancing queries.
pub fn reconcile_orderbook_semantics(
    expected_network_id: &NetworkId,
    delivery: &OrderbookTransactionPendingV1,
    retained: &OrderbookTransactionSigningRequestV1,
    finalized: &OrderbookFinalizedSnapshotV1,
) -> OrderbookSemanticReconciliationV1 {
    let cursor = finalized.finalized_cursor;
    if validate_orderbook_reconciliation_material_v1(delivery, retained).is_err() {
        return OrderbookSemanticReconciliationV1::InvalidDurableState;
    }
    if &delivery.network_id != expected_network_id || &retained.network_id != expected_network_id {
        return if valid_finalized_cursor(cursor) {
            OrderbookSemanticReconciliationV1::Conflict(cursor)
        } else {
            OrderbookSemanticReconciliationV1::Deferred
        };
    }
    match finalized_cursor_relation(delivery, cursor) {
        FinalizedCursorRelationV1::Invalid | FinalizedCursorRelationV1::Older => {
            return OrderbookSemanticReconciliationV1::Deferred;
        }
        FinalizedCursorRelationV1::ForkConflict => {
            return OrderbookSemanticReconciliationV1::Conflict(cursor);
        }
        FinalizedCursorRelationV1::Same | FinalizedCursorRelationV1::Advanced => {}
    }
    let Some(current_baseline_block_hash) = finalized.baseline_block_hash else {
        return OrderbookSemanticReconciliationV1::Deferred;
    };
    if current_baseline_block_hash != delivery.baseline_finalized_block_hash {
        return OrderbookSemanticReconciliationV1::Conflict(cursor);
    }
    if let OrderbookOperationV1::SettlementReceipt(instruction) = &retained.operation {
        match exact_receipt_result(
            instruction.receipt_payload(),
            delivery.policy_digest,
            finalized.settlement_receipt.as_ref(),
            finalized.settlement_channel.as_ref(),
        ) {
            ExactReceiptResultV1::Finalized => {
                return OrderbookSemanticReconciliationV1::Finalized(cursor);
            }
            ExactReceiptResultV1::Conflict => {
                return OrderbookSemanticReconciliationV1::Conflict(cursor);
            }
            ExactReceiptResultV1::Absent => {}
        }
    } else if finalized.settlement_receipt.is_some() || finalized.settlement_channel.is_some() {
        // A caller supplied a receipt projection for a revision-scoped
        // operation. Treat the incoherent operation-scoped query as unavailable
        // rather than acting on an accidental record.
        return OrderbookSemanticReconciliationV1::Deferred;
    }
    let Some(policy_record) = finalized.policy_record.as_ref() else {
        return OrderbookSemanticReconciliationV1::Deferred;
    };
    let Some(status) = finalized.status.as_ref() else {
        return OrderbookSemanticReconciliationV1::Deferred;
    };
    if matches!(&retained.operation, OrderbookOperationV1::Match(_))
        && retained.operation.expected_book_revision() == Some(status.book_revision)
        && status.last_match_scan_book_revision == status.book_revision
    {
        return OrderbookSemanticReconciliationV1::Conflict(cursor);
    }
    if let OrderbookOperationV1::SettlementReceipt(instruction) = &retained.operation {
        let Ok(receipt) = decode_settlement_receipt_v1(instruction.receipt_payload()) else {
            return OrderbookSemanticReconciliationV1::InvalidDurableState;
        };
        let Some(channel) = finalized.settlement_channel.as_ref() else {
            return OrderbookSemanticReconciliationV1::Conflict(cursor);
        };
        match validate_receipt_admission_context(
            &receipt,
            channel,
            policy_record,
            finalized.finalized_at_unix,
        ) {
            ReceiptAdmissionContextV1::Ready => {}
            ReceiptAdmissionContextV1::Unavailable => {
                return OrderbookSemanticReconciliationV1::Deferred;
            }
            ReceiptAdmissionContextV1::Conflict => {
                return OrderbookSemanticReconciliationV1::Conflict(cursor);
            }
        }
    }
    match validate_orderbook_finalized_context_v1(
        delivery,
        retained,
        policy_record,
        status.book_revision,
    ) {
        OrderbookFinalizedContextValidationV1::Ready => {
            OrderbookSemanticReconciliationV1::Ready(cursor)
        }
        OrderbookFinalizedContextValidationV1::Conflict => {
            OrderbookSemanticReconciliationV1::Conflict(cursor)
        }
        OrderbookFinalizedContextValidationV1::InvalidDurableState => {
            OrderbookSemanticReconciliationV1::InvalidDurableState
        }
        OrderbookFinalizedContextValidationV1::InvalidFinalizedContext => {
            OrderbookSemanticReconciliationV1::Deferred
        }
    }
}
/// Select one safe durable transition for a pending delivery.
///
/// Exact-envelope outcomes take precedence. If signed bytes exist, semantic
/// completion is considered only after the exact envelope is proven absent;
/// pending or unavailable exact status always defers semantic completion.
pub fn plan_orderbook_worker_action(
    expected_network_id: &NetworkId,
    configured_signer_authority: Option<&AccountId>,
    delivery: &OrderbookTransactionPendingV1,
    envelope: OrderbookEnvelopeReconciliationV1,
    semantics: OrderbookSemanticReconciliationV1,
) -> OrderbookWorkerActionV1 {
    let semantic_cursor = semantic_cursor(semantics);
    if semantics == OrderbookSemanticReconciliationV1::InvalidDurableState
        || validate_orderbook_pending_delivery_v1(delivery).is_err()
    {
        return OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::InvalidDurableState);
    }
    if semantic_cursor.is_some_and(|cursor| !valid_finalized_cursor(cursor)) {
        return OrderbookWorkerActionV1::Defer(
            OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,
        );
    }
    if &delivery.network_id != expected_network_id {
        return semantic_cursor.map_or(
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable),
            |finalized_cursor| OrderbookWorkerActionV1::DeadLetterConflict { finalized_cursor },
        );
    }
    if !envelope_is_coherent(delivery, envelope, semantic_cursor) {
        return OrderbookWorkerActionV1::Defer(
            OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,
        );
    }
    match envelope {
        OrderbookEnvelopeReconciliationV1::Applied {
            transaction_digest,
            finalized_cursor,
        } => {
            return OrderbookWorkerActionV1::FinalizeExact {
                transaction_digest,
                finalized_cursor,
            };
        }
        OrderbookEnvelopeReconciliationV1::Rejected {
            finalized_cursor, ..
        } => {
            return if matches!(
                delivery.state,
                OrderbookTransactionDeliveryStateV1::Signed
                    | OrderbookTransactionDeliveryStateV1::Ambiguous
                    | OrderbookTransactionDeliveryStateV1::Submitted
            ) {
                OrderbookWorkerActionV1::MarkTransactionRejected { finalized_cursor }
            } else {
                OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::InvalidDurableState)
            };
        }
        OrderbookEnvelopeReconciliationV1::NotSigned
        | OrderbookEnvelopeReconciliationV1::Pending { .. }
        | OrderbookEnvelopeReconciliationV1::Absent { .. }
        | OrderbookEnvelopeReconciliationV1::Unavailable => {}
    }
    if matches!(envelope, OrderbookEnvelopeReconciliationV1::Pending { .. }) {
        return match delivery.state {
            OrderbookTransactionDeliveryStateV1::Signed
            | OrderbookTransactionDeliveryStateV1::Ambiguous => {
                OrderbookWorkerActionV1::AdoptExactPending
            }
            OrderbookTransactionDeliveryStateV1::Submitted => {
                OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::AwaitingFinality)
            }
            OrderbookTransactionDeliveryStateV1::Ready
            | OrderbookTransactionDeliveryStateV1::Signing => {
                OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::InvalidDurableState)
            }
        };
    }
    if matches!(envelope, OrderbookEnvelopeReconciliationV1::Unavailable)
        && matches!(
            delivery.state,
            OrderbookTransactionDeliveryStateV1::Signed
                | OrderbookTransactionDeliveryStateV1::Ambiguous
                | OrderbookTransactionDeliveryStateV1::Submitted
        )
    {
        return OrderbookWorkerActionV1::Defer(
            OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,
        );
    }
    if let OrderbookSemanticReconciliationV1::Finalized(finalized_cursor) = semantics {
        return OrderbookWorkerActionV1::FinalizeSemantic { finalized_cursor };
    }
    match semantics {
        OrderbookSemanticReconciliationV1::Conflict(finalized_cursor) => {
            return OrderbookWorkerActionV1::DeadLetterConflict { finalized_cursor };
        }
        OrderbookSemanticReconciliationV1::Deferred => {
            return OrderbookWorkerActionV1::Defer(
                OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,
            );
        }
        OrderbookSemanticReconciliationV1::InvalidDurableState => {
            unreachable!("invalid durable state returns before envelope reconciliation")
        }
        OrderbookSemanticReconciliationV1::Ready(_) => {}
        OrderbookSemanticReconciliationV1::Finalized(_) => {
            unreachable!("semantic finalization returns before state planning")
        }
    }
    match delivery.state {
        OrderbookTransactionDeliveryStateV1::Ready => {
            if configured_signer_authority != Some(&delivery.authority) {
                return OrderbookWorkerActionV1::Defer(
                    OrderbookWorkerDeferReasonV1::SignerAuthorityMismatch,
                );
            }
            OrderbookWorkerActionV1::ClaimForSigning
        }
        OrderbookTransactionDeliveryStateV1::Signing => {
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::SigningClaimInProgress)
        }
        OrderbookTransactionDeliveryStateV1::Signed => match envelope {
            OrderbookEnvelopeReconciliationV1::Absent { .. } => {
                OrderbookWorkerActionV1::SubmitSignedBytes
            }
            OrderbookEnvelopeReconciliationV1::Unavailable => OrderbookWorkerActionV1::Defer(
                OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,
            ),
            OrderbookEnvelopeReconciliationV1::NotSigned => {
                OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::InvalidDurableState)
            }
            OrderbookEnvelopeReconciliationV1::Pending { .. }
            | OrderbookEnvelopeReconciliationV1::Applied { .. }
            | OrderbookEnvelopeReconciliationV1::Rejected { .. } => {
                unreachable!("exact-envelope outcomes return before delivery-state planning")
            }
        },
        OrderbookTransactionDeliveryStateV1::Ambiguous
        | OrderbookTransactionDeliveryStateV1::Submitted => match envelope {
            OrderbookEnvelopeReconciliationV1::Absent {
                finalized_cursor, ..
            } if finalized_cursor.height > delivery.baseline_finalized_height => {
                OrderbookWorkerActionV1::MarkFinalizedAbsent { finalized_cursor }
            }
            OrderbookEnvelopeReconciliationV1::Unavailable => OrderbookWorkerActionV1::Defer(
                OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,
            ),
            OrderbookEnvelopeReconciliationV1::NotSigned => {
                OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::InvalidDurableState)
            }
            OrderbookEnvelopeReconciliationV1::Pending { .. }
            | OrderbookEnvelopeReconciliationV1::Absent { .. }
            | OrderbookEnvelopeReconciliationV1::Applied { .. }
            | OrderbookEnvelopeReconciliationV1::Rejected { .. } => {
                OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::AwaitingFinality)
            }
        },
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactReceiptResultV1 {
    Absent,
    Finalized,
    Conflict,
}
fn exact_receipt_result(
    canonical_receipt: &[u8],
    policy_digest: [u8; 32],
    finalized: Option<&OrderbookSettlementReceiptRecord>,
    channel: Option<&OrderbookSettlementChannelRecord>,
) -> ExactReceiptResultV1 {
    let Some(record) = finalized else {
        return ExactReceiptResultV1::Absent;
    };
    let Ok(receipt) = decode_settlement_receipt_v1(canonical_receipt) else {
        return ExactReceiptResultV1::Conflict;
    };
    if verify_settlement_receipt_signature_v1(&receipt).is_err()
        || canonical_receipt.len() > ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1
        || record.canonical_receipt.len() > ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1
    {
        return ExactReceiptResultV1::Conflict;
    }
    let Some(channel) = channel else {
        return ExactReceiptResultV1::Conflict;
    };
    if record.receipt_id == receipt.receipt_id
        && record.channel_id == receipt.channel_id
        && record.trade_id == receipt.trade_id
        && record.canonical_receipt.as_slice() == canonical_receipt
        && record.admitted_policy_digest == policy_digest
        && record.admitted_at_unix != 0
        && record.admitted_at_unix < channel.expires_at_unix
        && channel.channel_id == receipt.channel_id
        && channel.trade_id == receipt.trade_id
        && signature_matches_account(&channel.provider, &receipt.settlement_signature)
    {
        ExactReceiptResultV1::Finalized
    } else {
        ExactReceiptResultV1::Conflict
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptAdmissionContextV1 {
    Ready,
    Unavailable,
    Conflict,
}
fn validate_receipt_admission_context(
    receipt: &sorafs_manifest::orderbook::SettlementReceiptV1,
    channel: &OrderbookSettlementChannelRecord,
    policy_record: &OrderbookAdmissionPolicyRecord,
    finalized_at_unix: u64,
) -> ReceiptAdmissionContextV1 {
    if finalized_at_unix == 0 {
        return ReceiptAdmissionContextV1::Unavailable;
    }
    if policy_record.policy.validate().is_err()
        || policy_record.policy_digest == [0; 32]
        || policy_record.policy.digest().ok() != Some(policy_record.policy_digest)
        || verify_settlement_receipt_signature_v1(receipt).is_err()
    {
        return ReceiptAdmissionContextV1::Conflict;
    }
    if channel.channel_id != receipt.channel_id
        || channel.trade_id != receipt.trade_id
        || channel.status != OrderbookSettlementChannelStatusV1::Open
        || channel.expires_at_unix == 0
        || finalized_at_unix >= channel.expires_at_unix
        || receipt.issued_at_unix >= channel.expires_at_unix
        || receipt.bytes_delivered > policy_record.policy.max_receipt_bytes
        || !signature_matches_account(&channel.provider, &receipt.settlement_signature)
    {
        return ReceiptAdmissionContextV1::Conflict;
    }
    let Ok(expected_split) = deterministic_settlement_split_v1(
        &channel.remaining_xor_locked,
        &channel.remaining_fee_xor_locked,
        receipt.bytes_delivered,
        channel.remaining_bytes,
    ) else {
        return ReceiptAdmissionContextV1::Conflict;
    };
    if receipt.xor_debited != expected_split.xor_debited
        || receipt.provider_credit != expected_split.provider_credit
        || receipt.fee_amount != expected_split.fee_amount
    {
        return ReceiptAdmissionContextV1::Conflict;
    }
    if receipt.issued_at_unix > finalized_at_unix {
        if receipt.issued_at_unix - finalized_at_unix > policy_record.policy.max_clock_skew_secs {
            return ReceiptAdmissionContextV1::Conflict;
        }
    } else if finalized_at_unix - receipt.issued_at_unix > policy_record.policy.max_receipt_age_secs
    {
        return ReceiptAdmissionContextV1::Conflict;
    }
    ReceiptAdmissionContextV1::Ready
}
fn signature_matches_account(account: &AccountId, signature: &OrderbookSignatureV1) -> bool {
    if signature.algorithm != sorafs_manifest::provider_advert::SignatureAlgorithm::Ed25519 {
        return false;
    }
    account
        .try_signatory()
        .and_then(|public_key| public_key.try_to_bytes().ok())
        .is_some_and(|(algorithm, bytes)| {
            algorithm == Algorithm::Ed25519 && bytes == signature.public_key.as_slice()
        })
}
fn envelope_is_coherent(
    delivery: &OrderbookTransactionPendingV1,
    envelope: OrderbookEnvelopeReconciliationV1,
    semantic_cursor: Option<OrderbookFinalizedCursorV1>,
) -> bool {
    let expected_digest = delivery.transaction_digest;
    match envelope {
        OrderbookEnvelopeReconciliationV1::NotSigned => expected_digest.is_none(),
        OrderbookEnvelopeReconciliationV1::Unavailable => true,
        OrderbookEnvelopeReconciliationV1::Pending {
            transaction_digest,
            finalized_cursor,
        }
        | OrderbookEnvelopeReconciliationV1::Applied {
            transaction_digest,
            finalized_cursor,
        }
        | OrderbookEnvelopeReconciliationV1::Rejected {
            transaction_digest,
            finalized_cursor,
        }
        | OrderbookEnvelopeReconciliationV1::Absent {
            transaction_digest,
            finalized_cursor,
        } => {
            expected_digest == Some(transaction_digest)
                && transaction_digest != [0; 32]
                && valid_finalized_cursor(finalized_cursor)
                && semantic_cursor == Some(finalized_cursor)
        }
    }
}
fn valid_finalized_cursor(cursor: OrderbookFinalizedCursorV1) -> bool {
    cursor.height != 0 && cursor.block_hash != [0; 32]
}
fn finalized_cursor_relation(
    delivery: &OrderbookTransactionPendingV1,
    cursor: OrderbookFinalizedCursorV1,
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
fn semantic_cursor(
    semantics: OrderbookSemanticReconciliationV1,
) -> Option<OrderbookFinalizedCursorV1> {
    match semantics {
        OrderbookSemanticReconciliationV1::Ready(cursor)
        | OrderbookSemanticReconciliationV1::Finalized(cursor)
        | OrderbookSemanticReconciliationV1::Conflict(cursor) => Some(cursor),
        OrderbookSemanticReconciliationV1::Deferred
        | OrderbookSemanticReconciliationV1::InvalidDurableState => None,
    }
}
/// Whether one exact finalized view proves native maintenance is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookMaintenanceDueV1 {
    /// At least one open order or channel is expired at the finalized time.
    Due,
    /// Every active record in the bounded projection is still live.
    NotDue,
    /// The active projection exceeded its configured bound.
    Unknown,
}
/// Coherent finalized material used only to generate native worker operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderbookGenerationSnapshotV1 {
    /// Finalized anchor shared by policy, status, and maintenance projection.
    pub finalized_cursor: OrderbookFinalizedCursorV1,
    /// Finalized block timestamp, or zero when the block body is unavailable.
    pub finalized_at_unix: u64,
    /// Exact active native policy.
    pub policy_record: OrderbookAdmissionPolicyRecord,
    /// Exact native counter snapshot.
    pub status: OrderbookLedgerStatusV1,
    /// Bounded expiry conclusion from this same state view.
    pub maintenance_due: OrderbookMaintenanceDueV1,
}
/// Fixed generation validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookGenerationErrorV1 {
    /// The finalized policy/status snapshot is malformed.
    InvalidSnapshot,
    /// A config-provided instruction bound is invalid.
    InvalidBounds,
    /// Maintenance state could not be covered by the configured projection.
    ProjectionUnavailable,
}
/// Select at most one native revision-scoped operation.
///
/// Expiry maintenance has priority over matching so two worker replicas do not
/// intentionally submit mutually stale operations for the same revision.
pub fn plan_orderbook_generation(
    snapshot: &OrderbookGenerationSnapshotV1,
    match_batch_limit: u32,
    maintenance_batch_limit: u32,
) -> Result<Option<OrderbookOperationV1>, OrderbookGenerationErrorV1> {
    if !valid_finalized_cursor(snapshot.finalized_cursor)
        || snapshot.policy_record.policy.validate().is_err()
        || snapshot.policy_record.policy_digest == [0; 32]
        || snapshot.policy_record.policy.digest().ok() != Some(snapshot.policy_record.policy_digest)
        || snapshot.policy_record.activated_at_unix == 0
        || snapshot.status.next_admission_sequence == 0
        || snapshot.status.next_trade_sequence == 0
        || snapshot.status.last_match_scan_book_revision > snapshot.status.book_revision
        || snapshot.status.open_settlement_channels
            > u64::from(
                iroha_data_model::sorafs::orderbook::ORDERBOOK_MAX_OPEN_SETTLEMENT_CHANNELS_V1,
            )
    {
        return Err(OrderbookGenerationErrorV1::InvalidSnapshot);
    }
    if !(1..=iroha_data_model::sorafs::orderbook::ORDERBOOK_MAX_FILLS_PER_EXECUTION_V1)
        .contains(&match_batch_limit)
        || !(1..=iroha_data_model::sorafs::orderbook::ORDERBOOK_MAX_MAINTENANCE_ITEMS_V1)
            .contains(&maintenance_batch_limit)
    {
        return Err(OrderbookGenerationErrorV1::InvalidBounds);
    }
    match snapshot.maintenance_due {
        OrderbookMaintenanceDueV1::Due => {
            return Ok(Some(OrderbookOperationV1::Maintain(
                MaintainSorafsOrderbook::new(
                    snapshot.policy_record.policy_digest,
                    snapshot.status.book_revision,
                    maintenance_batch_limit,
                ),
            )));
        }
        OrderbookMaintenanceDueV1::Unknown => {
            return Err(OrderbookGenerationErrorV1::ProjectionUnavailable);
        }
        OrderbookMaintenanceDueV1::NotDue => {}
    }
    if snapshot.status.last_match_scan_book_revision == snapshot.status.book_revision {
        return Ok(None);
    }
    let active_orders = snapshot
        .status
        .open_orders
        .checked_add(snapshot.status.partially_filled_orders)
        .ok_or(OrderbookGenerationErrorV1::InvalidSnapshot)?;
    if active_orders < 2 {
        return Ok(None);
    }
    Ok(Some(OrderbookOperationV1::Match(
        MatchSorafsOrderbook::new(
            snapshot.policy_record.policy_digest,
            snapshot.status.book_revision,
            match_batch_limit,
        ),
    )))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        block::BlockHeader,
        isi::sorafs::{
            MaintainSorafsOrderbook, MatchSorafsOrderbook, RecordSorafsOrderbookSettlementReceipt,
        },
        sorafs::orderbook::{OrderbookAdmissionPolicyV1, OrderbookSettlementReceiptRecord},
    };
    use sorafs_manifest::{
        deal::XorQuantity,
        orderbook::{
            ByteRangeV1, OrderbookSignatureV1, SETTLEMENT_RECEIPT_VERSION_V1, SettlementReceiptV1,
            sign_settlement_receipt_ed25519_v1,
        },
        provider_advert::SignatureAlgorithm,
    };
    use sorafs_node::orderbook_transaction_forwarder::{
        OrderbookTransactionContextV1, OrderbookTransactionForwarder,
        OrderbookTransactionForwarderPolicyV1,
    };
    use tempfile::TempDir;
    fn foreign_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xF1; 32]),
        ))
    }
    fn key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed.max(1); 32], Algorithm::Ed25519)
            .expect("deterministic Ed25519 key")
    }
    fn account(key: &KeyPair) -> AccountId {
        AccountId::new(key.public_key().clone())
    }
    fn cursor(height: u64, hash_byte: u8) -> OrderbookFinalizedCursorV1 {
        OrderbookFinalizedCursorV1 {
            height,
            block_hash: [hash_byte; 32],
        }
    }
    fn context(
        matcher: &KeyPair,
        settlement: &KeyPair,
        book_revision: u64,
        finalized_cursor: OrderbookFinalizedCursorV1,
    ) -> OrderbookTransactionContextV1 {
        let policy = OrderbookAdmissionPolicyV1 {
            version: 1,
            revision: 1,
            predecessor_policy_digest: None,
            market_id: [0x41; 32],
            matcher_authority: account(matcher),
            settlement_authority: account(settlement),
            paused: false,
            min_order_gib: 1,
            max_order_gib: 1_024,
            price_tick_micro_xor: 1,
            max_maker_fee_bps: 100,
            max_taker_fee_bps: 100,
            max_order_lifetime_secs: 86_400,
            max_receipt_age_secs: 3_600,
            max_clock_skew_secs: 30,
            max_receipt_bytes: 1 << 30,
            max_receipts_per_channel: 128,
        };
        let policy_digest = policy.digest().expect("policy digest");
        OrderbookTransactionContextV1 {
            network_id: crate::signed_query_test_network_id(),
            policy_record: OrderbookAdmissionPolicyRecord {
                policy,
                policy_digest,
                activated_at_unix: 1,
                activated_by: account(matcher),
            },
            book_revision,
            finalized_cursor,
        }
    }
    fn forwarder() -> (OrderbookTransactionForwarder, TempDir) {
        let state_dir = tempfile::tempdir().expect("orderbook forwarder state directory");
        let forwarder = OrderbookTransactionForwarder::open(
            state_dir.path(),
            OrderbookTransactionForwarderPolicyV1 {
                max_pending: 16,
                max_completed: 16,
                max_dead_letters: 16,
                max_attempts: 3,
                max_transaction_bytes: 512 * 1024,
                checkpoint_max_bytes: 4 * 1024 * 1024,
            },
        )
        .expect("durable orderbook forwarder");
        (forwarder, state_dir)
    }
    fn match_operation(context: &OrderbookTransactionContextV1) -> OrderbookOperationV1 {
        OrderbookOperationV1::Match(MatchSorafsOrderbook::new(
            context.policy_record.policy_digest,
            context.book_revision,
            8,
        ))
    }
    fn maintain_operation(context: &OrderbookTransactionContextV1) -> OrderbookOperationV1 {
        OrderbookOperationV1::Maintain(MaintainSorafsOrderbook::new(
            context.policy_record.policy_digest,
            context.book_revision,
            16,
        ))
    }
    fn settlement_operation(
        context: &OrderbookTransactionContextV1,
        receipt_id: [u8; 32],
    ) -> OrderbookOperationV1 {
        let signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let receipt = SettlementReceiptV1 {
            version: SETTLEMENT_RECEIPT_VERSION_V1,
            receipt_id,
            channel_id: [0x52; 32],
            trade_id: [0x53; 32],
            range: ByteRangeV1 { start: 0, end: 32 },
            chunk_hash: [0x54; 32],
            bytes_delivered: 32,
            xor_debited: XorQuantity::try_from_micro(100).expect("xor debit"),
            provider_credit: XorQuantity::try_from_micro(90).expect("provider credit"),
            fee_amount: XorQuantity::try_from_micro(10).expect("fee"),
            issued_at_unix: 10,
            settlement_signature: OrderbookSignatureV1 {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![1; 32],
                signature: vec![1; 64],
            },
        };
        let receipt =
            sign_settlement_receipt_ed25519_v1(receipt, &signing_key).expect("sign receipt");
        OrderbookOperationV1::SettlementReceipt(RecordSorafsOrderbookSettlementReceipt::new(
            norito::to_bytes(&receipt).expect("encode receipt"),
            context.policy_record.policy_digest,
        ))
    }
    fn channel_for_receipt(
        receipt: &SettlementReceiptV1,
        settlement_authority: AccountId,
        buyer: AccountId,
    ) -> OrderbookSettlementChannelRecord {
        OrderbookSettlementChannelRecord {
            channel_id: receipt.channel_id,
            trade_id: receipt.trade_id,
            buyer,
            provider: AccountId::new(
                iroha_crypto::PublicKey::from_bytes(
                    Algorithm::Ed25519,
                    &receipt.settlement_signature.public_key,
                )
                .expect("receipt provider public key"),
            ),
            provider_id: iroha_data_model::sorafs::capacity::ProviderId::new([0x62; 32]),
            settlement_authority,
            total_bytes: 32,
            remaining_bytes: 32,
            initial_xor_locked: XorQuantity::try_from_micro(100).expect("initial lock"),
            remaining_xor_locked: XorQuantity::try_from_micro(100).expect("remaining lock"),
            initial_fee_xor_locked: XorQuantity::try_from_micro(10).expect("initial fee lock"),
            remaining_fee_xor_locked: XorQuantity::try_from_micro(10).expect("remaining fee lock"),
            status: OrderbookSettlementChannelStatusV1::Open,
            opened_at_unix: 1,
            expires_at_unix: 100,
            updated_at_unix: 1,
        }
    }
    fn retained_delivery(
        operation: OrderbookOperationV1,
        context: &OrderbookTransactionContextV1,
    ) -> (
        OrderbookTransactionPendingV1,
        OrderbookTransactionSigningRequestV1,
    ) {
        let (forwarder, _state_dir) = forwarder();
        let operation_id = enqueue_test_operation(&forwarder, operation, context)
            .expect("enqueue")
            .operation_id();
        let delivery = forwarder.pending(1).expect("pending").remove(0);
        let retained = forwarder
            .operation_for_reconciliation(operation_id)
            .expect("retained operation");
        (delivery, retained)
    }
    fn enqueue_test_operation(
        forwarder: &OrderbookTransactionForwarder,
        operation: OrderbookOperationV1,
        context: &OrderbookTransactionContextV1,
    ) -> Result<
        sorafs_node::orderbook_transaction_forwarder::OrderbookTransactionEnqueueResultV1,
        sorafs_node::orderbook_transaction_forwarder::OrderbookTransactionForwarderError,
    > {
        if operation.kind()
            == sorafs_node::orderbook_transaction_forwarder::OrderbookTransactionKindV1::SettlementReceipt
        {
            forwarder.enqueue_unsigned_operation_with_authority(account(&key(0x7A)), operation, context)
        } else {
            forwarder.enqueue_unsigned_operation(operation, context)
        }
    }
    fn status(book_revision: u64) -> OrderbookLedgerStatusV1 {
        OrderbookLedgerStatusV1 {
            open_orders: 0,
            partially_filled_orders: 0,
            filled_orders: 0,
            cancelled_orders: 0,
            expired_orders: 0,
            provider_revoked_orders: 0,
            trades: 0,
            settlement_receipts: 0,
            settlement_channels: 0,
            open_settlement_channels: 0,
            book_revision,
            last_match_scan_book_revision: 0,
            next_admission_sequence: 1,
            next_trade_sequence: 1,
            updated_at_unix: 1,
        }
    }
    fn snapshot(
        delivery: &OrderbookTransactionPendingV1,
        context: &OrderbookTransactionContextV1,
        finalized_cursor: OrderbookFinalizedCursorV1,
    ) -> OrderbookFinalizedSnapshotV1 {
        OrderbookFinalizedSnapshotV1 {
            finalized_cursor,
            finalized_at_unix: 10,
            baseline_block_hash: Some(delivery.baseline_finalized_block_hash),
            policy_record: Some(context.policy_record.clone()),
            status: Some(status(context.book_revision)),
            settlement_receipt: None,
            settlement_channel: None,
        }
    }
    fn mark_signed(
        delivery: &mut OrderbookTransactionPendingV1,
        state: OrderbookTransactionDeliveryStateV1,
    ) -> [u8; 32] {
        let bytes = vec![0xA5, 0x5A, 0x11];
        let digest = *blake3::hash(&bytes).as_bytes();
        delivery.state = state;
        delivery.attempts = 1;
        delivery.signed_transaction_bytes = Some(bytes);
        delivery.transaction_digest = Some(digest);
        digest
    }
    #[test]
    fn match_and_maintenance_require_exact_policy_authority_revision_and_history() {
        let matcher = key(0x11);
        let settlement = key(0x12);
        let context = context(&matcher, &settlement, 7, cursor(10, 0x10));
        for operation in [match_operation(&context), maintain_operation(&context)] {
            let (delivery, retained) = retained_delivery(operation, &context);
            let exact = snapshot(&delivery, &context, context.finalized_cursor);
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &retained,
                    &exact,
                ),
                OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
            );
            let mut stale = exact.clone();
            stale.finalized_cursor = cursor(9, 0x09);
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &retained,
                    &stale,
                ),
                OrderbookSemanticReconciliationV1::Deferred,
            );
            let mut fork = exact.clone();
            fork.finalized_cursor = cursor(10, 0xEE);
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &retained,
                    &fork,
                ),
                OrderbookSemanticReconciliationV1::Conflict(cursor(10, 0xEE)),
            );
            let advanced = cursor(11, 0x11);
            let mut changed_revision = exact.clone();
            changed_revision.finalized_cursor = advanced;
            changed_revision.status = Some(status(8));
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &retained,
                    &changed_revision,
                ),
                OrderbookSemanticReconciliationV1::Conflict(advanced),
            );
            let mut abandoned_baseline = exact.clone();
            abandoned_baseline.finalized_cursor = advanced;
            abandoned_baseline.baseline_block_hash = Some([0xEF; 32]);
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &retained,
                    &abandoned_baseline,
                ),
                OrderbookSemanticReconciliationV1::Conflict(advanced),
            );
            let rotated_matcher = key(0x13);
            let mut rotated = context.policy_record.policy.clone();
            rotated.revision = 2;
            rotated.predecessor_policy_digest = Some(context.policy_record.policy_digest);
            rotated.matcher_authority = account(&rotated_matcher);
            let rotated_digest = rotated.digest().expect("rotated digest");
            let mut authority_rotation = exact.clone();
            authority_rotation.finalized_cursor = advanced;
            authority_rotation.policy_record = Some(OrderbookAdmissionPolicyRecord {
                policy: rotated,
                policy_digest: rotated_digest,
                activated_at_unix: 2,
                activated_by: account(&matcher),
            });
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &retained,
                    &authority_rotation,
                ),
                OrderbookSemanticReconciliationV1::Conflict(advanced),
            );
        }
    }
    #[test]
    fn exact_receipt_projection_converges_duplicates_across_peers() {
        let matcher = key(0x21);
        let settlement = key(0x22);
        let context = context(&matcher, &settlement, 9, cursor(20, 0x20));
        let operation = settlement_operation(&context, [0x61; 32]);
        let (delivery, retained) = retained_delivery(operation.clone(), &context);
        let OrderbookOperationV1::SettlementReceipt(instruction) = &operation else {
            unreachable!()
        };
        let receipt =
            decode_settlement_receipt_v1(instruction.receipt_payload()).expect("decode receipt");
        let advanced = cursor(21, 0x21);
        let mut finalized = snapshot(&delivery, &context, advanced);
        finalized.settlement_channel = Some(channel_for_receipt(
            &receipt,
            retained.authority.clone(),
            account(&matcher),
        ));
        finalized.settlement_receipt = Some(OrderbookSettlementReceiptRecord {
            receipt_id: receipt.receipt_id,
            channel_id: receipt.channel_id,
            trade_id: receipt.trade_id,
            canonical_receipt: instruction.receipt_payload().clone(),
            admitted_policy_digest: context.policy_record.policy_digest,
            admitted_at_unix: 11,
            recorded_by: retained.authority.clone(),
        });
        // A current policy rotation cannot invalidate an already committed,
        // byte-identical receipt from the preceding authority.
        let rotated_settlement = key(0x23);
        let mut rotated = context.policy_record.policy.clone();
        rotated.revision = 2;
        rotated.predecessor_policy_digest = Some(context.policy_record.policy_digest);
        rotated.settlement_authority = account(&rotated_settlement);
        let rotated_digest = rotated.digest().expect("rotated digest");
        let rotated_record = OrderbookAdmissionPolicyRecord {
            policy: rotated,
            policy_digest: rotated_digest,
            activated_at_unix: 12,
            activated_by: account(&matcher),
        };
        let mut absent_after_rotation = snapshot(&delivery, &context, advanced);
        absent_after_rotation.policy_record = Some(rotated_record.clone());
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &absent_after_rotation,
            ),
            OrderbookSemanticReconciliationV1::Conflict(advanced),
        );
        finalized.policy_record = Some(rotated_record);
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &finalized,
            ),
            OrderbookSemanticReconciliationV1::Finalized(advanced),
        );
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::NotSigned,
                OrderbookSemanticReconciliationV1::Finalized(advanced),
            ),
            OrderbookWorkerActionV1::FinalizeSemantic {
                finalized_cursor: advanced,
            },
        );
        let (duplicate, _duplicate_state_dir) = forwarder();
        let first =
            enqueue_test_operation(&duplicate, operation.clone(), &context).expect("first enqueue");
        let replay =
            enqueue_test_operation(&duplicate, operation, &context).expect("idempotent replay");
        assert_eq!(first.operation_id(), replay.operation_id());
        let mut substituted = finalized;
        substituted
            .settlement_receipt
            .as_mut()
            .expect("receipt")
            .canonical_receipt
            .push(0);
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &substituted,
            ),
            OrderbookSemanticReconciliationV1::Conflict(advanced),
        );
    }
    #[test]
    fn exact_envelope_status_precedes_conflicts_and_absence_controls_retry() {
        let matcher = key(0x31);
        let settlement = key(0x32);
        let context = context(&matcher, &settlement, 4, cursor(30, 0x30));
        let (mut delivery, _) = retained_delivery(match_operation(&context), &context);
        let digest = mark_signed(
            &mut delivery,
            OrderbookTransactionDeliveryStateV1::Submitted,
        );
        let applied = cursor(31, 0x31);
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Applied {
                    transaction_digest: digest,
                    finalized_cursor: applied,
                },
                OrderbookSemanticReconciliationV1::Conflict(applied),
            ),
            OrderbookWorkerActionV1::FinalizeExact {
                transaction_digest: digest,
                finalized_cursor: applied,
            },
        );
        let later_snapshot = cursor(32, 0x32);
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Applied {
                    transaction_digest: digest,
                    finalized_cursor: applied,
                },
                OrderbookSemanticReconciliationV1::Conflict(later_snapshot),
            ),
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,),
        );
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Rejected {
                    transaction_digest: digest,
                    finalized_cursor: applied,
                },
                OrderbookSemanticReconciliationV1::Ready(applied),
            ),
            OrderbookWorkerActionV1::MarkTransactionRejected {
                finalized_cursor: applied,
            },
        );
        delivery.state = OrderbookTransactionDeliveryStateV1::Ambiguous;
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Pending {
                    transaction_digest: digest,
                    finalized_cursor: applied,
                },
                OrderbookSemanticReconciliationV1::Conflict(applied),
            ),
            OrderbookWorkerActionV1::AdoptExactPending,
        );
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Unavailable,
                OrderbookSemanticReconciliationV1::Finalized(applied),
            ),
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,),
        );
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Absent {
                    transaction_digest: digest,
                    finalized_cursor: applied,
                },
                OrderbookSemanticReconciliationV1::Ready(applied),
            ),
            OrderbookWorkerActionV1::MarkFinalizedAbsent {
                finalized_cursor: applied,
            },
        );
        // Absence at the retained baseline is not a retry authorization.
        let baseline = context.finalized_cursor;
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Absent {
                    transaction_digest: digest,
                    finalized_cursor: baseline,
                },
                OrderbookSemanticReconciliationV1::Ready(baseline),
            ),
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::AwaitingFinality),
        );
    }
    #[test]
    fn signed_delivery_submits_only_after_exact_absence_and_digest_match() {
        let matcher = key(0x41);
        let settlement = key(0x42);
        let context = context(&matcher, &settlement, 5, cursor(40, 0x40));
        let (mut delivery, _) = retained_delivery(maintain_operation(&context), &context);
        let digest = mark_signed(&mut delivery, OrderbookTransactionDeliveryStateV1::Signed);
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Absent {
                    transaction_digest: digest,
                    finalized_cursor: context.finalized_cursor,
                },
                OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            OrderbookWorkerActionV1::SubmitSignedBytes,
        );
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::Absent {
                    transaction_digest: [0xFF; 32],
                    finalized_cursor: context.finalized_cursor,
                },
                OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::FinalizedStateUnavailable,),
        );
    }
    #[test]
    fn corrupted_durable_identity_and_signed_metadata_fail_closed() {
        let matcher = key(0x51);
        let settlement = key(0x52);
        let context = context(&matcher, &settlement, 6, cursor(50, 0x50));
        let (delivery, retained) = retained_delivery(match_operation(&context), &context);
        let exact = snapshot(&delivery, &context, context.finalized_cursor);
        let mut corrupt_identity = delivery.clone();
        corrupt_identity.operation_id[0] ^= 1;
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &corrupt_identity,
                &retained,
                &exact,
            ),
            OrderbookSemanticReconciliationV1::InvalidDurableState,
        );
        let mut corrupt_semantic = delivery.clone();
        corrupt_semantic.semantic_digest[0] ^= 1;
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &corrupt_semantic,
                &retained,
                &exact,
            ),
            OrderbookSemanticReconciliationV1::InvalidDurableState,
        );
        let mut corrupt_signed = delivery;
        let digest = mark_signed(
            &mut corrupt_signed,
            OrderbookTransactionDeliveryStateV1::Submitted,
        );
        corrupt_signed.transaction_digest = Some([0xEE; 32]);
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&corrupt_signed.authority),
                &corrupt_signed,
                OrderbookEnvelopeReconciliationV1::Applied {
                    transaction_digest: digest,
                    finalized_cursor: cursor(51, 0x51),
                },
                OrderbookSemanticReconciliationV1::Ready(cursor(51, 0x51)),
            ),
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::InvalidDurableState,),
        );
    }
    #[test]
    fn canonical_forwarder_validator_rejects_each_retained_field_substitution() {
        let matcher = key(0x58);
        let settlement = key(0x59);
        let context = context(&matcher, &settlement, 6, cursor(55, 0x55));
        let (delivery, retained) = retained_delivery(match_operation(&context), &context);
        let exact = snapshot(&delivery, &context, context.finalized_cursor);
        let mut wrong_operation_id = retained.clone();
        wrong_operation_id.operation_id[0] ^= 1;
        let mut wrong_network = retained.clone();
        wrong_network.network_id = foreign_network_id();
        let mut wrong_authority = retained.clone();
        wrong_authority.authority = account(&key(0x5A));
        let mut wrong_operation = retained;
        wrong_operation.operation = OrderbookOperationV1::Match(MatchSorafsOrderbook::new(
            context.policy_record.policy_digest,
            context.book_revision,
            7,
        ));
        for substituted in [
            wrong_operation_id,
            wrong_network,
            wrong_authority,
            wrong_operation,
        ] {
            assert_eq!(
                reconcile_orderbook_semantics(
                    &crate::signed_query_test_network_id(),
                    &delivery,
                    &substituted,
                    &exact,
                ),
                OrderbookSemanticReconciliationV1::InvalidDurableState,
            );
        }
    }
    #[test]
    fn ready_delivery_requires_exact_governed_signer_and_network() {
        let matcher = key(0x61);
        let settlement = key(0x62);
        let context = context(&matcher, &settlement, 3, cursor(60, 0x60));
        let (delivery, _) = retained_delivery(match_operation(&context), &context);
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::NotSigned,
                OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            OrderbookWorkerActionV1::ClaimForSigning,
        );
        let wrong = account(&key(0x63));
        assert_eq!(
            plan_orderbook_worker_action(
                &crate::signed_query_test_network_id(),
                Some(&wrong),
                &delivery,
                OrderbookEnvelopeReconciliationV1::NotSigned,
                OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            OrderbookWorkerActionV1::Defer(OrderbookWorkerDeferReasonV1::SignerAuthorityMismatch,),
        );
        assert_eq!(
            plan_orderbook_worker_action(
                &foreign_network_id(),
                Some(&delivery.authority),
                &delivery,
                OrderbookEnvelopeReconciliationV1::NotSigned,
                OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
            ),
            OrderbookWorkerActionV1::DeadLetterConflict {
                finalized_cursor: context.finalized_cursor,
            },
        );
    }
    #[test]
    fn receipt_reconciliation_requires_fresh_provider_bound_signature() {
        let matcher = key(0x64);
        let settlement = key(0x65);
        let context = context(&matcher, &settlement, 4, cursor(64, 0x64));
        let operation = settlement_operation(&context, [0x66; 32]);
        let (delivery, retained) = retained_delivery(operation, &context);
        let OrderbookOperationV1::SettlementReceipt(instruction) = &retained.operation else {
            unreachable!()
        };
        let receipt =
            decode_settlement_receipt_v1(instruction.receipt_payload()).expect("decode receipt");
        let mut finalized = snapshot(&delivery, &context, context.finalized_cursor);
        finalized.finalized_at_unix = 20;
        let mut channel =
            channel_for_receipt(&receipt, retained.authority.clone(), account(&matcher));
        channel.expires_at_unix = 10_000;
        finalized.settlement_channel = Some(channel.clone());
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &finalized,
            ),
            OrderbookSemanticReconciliationV1::Ready(context.finalized_cursor),
        );
        let mut stale = finalized.clone();
        stale.finalized_at_unix =
            receipt.issued_at_unix + context.policy_record.policy.max_receipt_age_secs + 1;
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &stale,
            ),
            OrderbookSemanticReconciliationV1::Conflict(context.finalized_cursor),
        );
        let mut substituted_provider = finalized.clone();
        substituted_provider
            .settlement_channel
            .as_mut()
            .expect("channel")
            .provider = account(&key(0x67));
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &substituted_provider,
            ),
            OrderbookSemanticReconciliationV1::Conflict(context.finalized_cursor),
        );
        finalized.finalized_at_unix = 0;
        assert_eq!(
            reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                &delivery,
                &retained,
                &finalized,
            ),
            OrderbookSemanticReconciliationV1::Deferred,
        );
    }
    #[test]
    fn generation_prioritizes_due_maintenance_and_never_guesses_unknown_projection() {
        let matcher = key(0x68);
        let settlement = key(0x69);
        let context = context(&matcher, &settlement, 12, cursor(68, 0x68));
        let mut ledger_status = status(context.book_revision);
        ledger_status.open_orders = 2;
        let mut generation = OrderbookGenerationSnapshotV1 {
            finalized_cursor: context.finalized_cursor,
            finalized_at_unix: 100,
            policy_record: context.policy_record.clone(),
            status: ledger_status,
            maintenance_due: OrderbookMaintenanceDueV1::NotDue,
        };
        assert!(matches!(
            plan_orderbook_generation(&generation, 8, 16),
            Ok(Some(OrderbookOperationV1::Match(_)))
        ));
        generation.maintenance_due = OrderbookMaintenanceDueV1::Due;
        assert!(matches!(
            plan_orderbook_generation(&generation, 8, 16),
            Ok(Some(OrderbookOperationV1::Maintain(_)))
        ));
        generation.maintenance_due = OrderbookMaintenanceDueV1::Unknown;
        assert_eq!(
            plan_orderbook_generation(&generation, 8, 16),
            Err(OrderbookGenerationErrorV1::ProjectionUnavailable),
        );
    }
    #[test]
    fn sealed_no_fill_revision_conflicts_distinct_peer_envelopes_and_stays_sealed_after_restart() {
        let matcher = key(0x6A);
        let settlement = key(0x6B);
        let context = context(&matcher, &settlement, 14, cursor(70, 0x70));
        let first_operation = OrderbookOperationV1::Match(MatchSorafsOrderbook::new(
            context.policy_record.policy_digest,
            context.book_revision,
            8,
        ));
        let second_operation = OrderbookOperationV1::Match(MatchSorafsOrderbook::new(
            context.policy_record.policy_digest,
            context.book_revision,
            7,
        ));
        // Independent replicas have independent durable outboxes, so both
        // distinct envelopes may exist before either observes the finalized
        // no-fill marker for this revision.
        let (first_delivery, first_retained) = retained_delivery(first_operation, &context);
        let (second_delivery, second_retained) = retained_delivery(second_operation, &context);
        for (delivery, retained) in [
            (&first_delivery, &first_retained),
            (&second_delivery, &second_retained),
        ] {
            let mut sealed = snapshot(delivery, &context, context.finalized_cursor);
            let status = sealed.status.as_mut().expect("status");
            status.open_orders = 1;
            status.partially_filled_orders = 1;
            status.last_match_scan_book_revision = status.book_revision;
            let semantics = reconcile_orderbook_semantics(
                &crate::signed_query_test_network_id(),
                delivery,
                retained,
                &sealed,
            );
            assert_eq!(
                semantics,
                OrderbookSemanticReconciliationV1::Conflict(context.finalized_cursor),
                "the committed no-fill marker semantically seals the unchanged revision"
            );
            assert_eq!(
                plan_orderbook_worker_action(
                    &crate::signed_query_test_network_id(),
                    Some(&delivery.authority),
                    delivery,
                    OrderbookEnvelopeReconciliationV1::NotSigned,
                    semantics,
                ),
                OrderbookWorkerActionV1::DeadLetterConflict {
                    finalized_cursor: context.finalized_cursor,
                },
            );
        }
        let mut restarted_status = status(context.book_revision);
        restarted_status.open_orders = 1;
        restarted_status.partially_filled_orders = 1;
        restarted_status.last_match_scan_book_revision = context.book_revision;
        let restarted = OrderbookGenerationSnapshotV1 {
            finalized_cursor: context.finalized_cursor,
            finalized_at_unix: 100,
            policy_record: context.policy_record,
            status: restarted_status,
            maintenance_due: OrderbookMaintenanceDueV1::NotDue,
        };
        assert_eq!(
            plan_orderbook_generation(&restarted, 8, 16),
            Ok(None),
            "a restarted replica must not regenerate a sealed no-fill revision"
        );
        assert_eq!(
            plan_orderbook_generation(&restarted, 7, 16),
            Ok(None),
            "changing the local batch limit cannot reopen the sealed revision"
        );
    }
}
