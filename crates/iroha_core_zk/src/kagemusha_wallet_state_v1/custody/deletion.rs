//! Exact-state destructive review and reconciliation on the retained provider owner.

use super::*;
use crate::kagemusha_wallet_advance_v1::KagemushaWalletDestructiveConfirmationV1;

/// Display DATA describing the exact retained state whose custody would be destroyed.
/// Gross balance and core burns are not a fully folded spendable-value verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyDeletionReviewV1 {
    /// A committed operation still lacks its released completion.
    pub pending: bool,
    /// Actual retained lifecycle; Retiring does not authorize deletion.
    pub lifecycle: KagemushaWalletLifecycleV1,
    /// Operation that selected this capsule.
    pub operation_kind: KagemushaWalletOperationKindV1,
    /// The retained outgoing map is nonempty; absence is not proof of safe deletion.
    pub pending_outgoing: bool,
    /// The retained fee recovery map is nonempty.
    pub fee_claims: bool,
    /// The retained Load/Unload recovery map is nonempty.
    pub load_redeem: bool,
    /// Exact private slot being reviewed.
    pub slot: [u8; 32],
    /// Exact marker original; any subsequent metadata publication invalidates this review.
    pub marker_file_digest: [u8; 32],
    /// Enrolled scheme.
    pub scheme_id: [u8; 32],
    /// Exact registered asset scope.
    pub asset_digest: [u8; 32],
    /// Enrolled wallet incarnation.
    pub wallet_id: [u8; 32],
    /// Exact selected state commitment.
    pub head: [u8; 32],
    /// Exact selected sequence, including zero for Bootstrap.
    pub sequence: u128,
    /// Retained gross balance in integer asset units.
    pub gross_balance: u128,
    /// Last resynchronized core burn total; further proof work can reveal more burns.
    pub core_burned_total: u128,
}

/// Actual non-Clone owner-local review. Projection DATA cannot reconstruct it.
/// Before consuming it, show the irreversible loss of payment-key and offline-value recovery,
/// pending delivery and unpaid late claims; require fresh explicit destructive confirmation.
pub struct ReviewedCustodyDeletionV1 {
    owner: Arc<()>,
    confirmation: KagemushaWalletDestructiveConfirmationV1,
    projection: CustodyDeletionReviewV1,
}
impl ReviewedCustodyDeletionV1 {
    /// Borrow exact retained display DATA; this is not itself approval.
    #[must_use]
    pub const fn projection(&self) -> &CustodyDeletionReviewV1 {
        &self.projection
    }
}

/// Actual provider outcome after explicit confirmation or terminal reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyDeletionProgressV1 {
    /// Terminal marker is durable and custody cleanup completed. Money operations stay closed.
    Deleted {
        /// Exact retained terminal marker original.
        marker_file_digest: [u8; 32],
    },
    /// Reconciliation found no terminal publication. A fresh review/confirmation is required.
    NotDeleted,
}

pub(super) enum DeletionState {
    Open,
    Attempted,
    Deleted,
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> AdvanceHandle<F, P> {
    pub(crate) fn require_custody_operations(&self) -> Result<(), ProviderError> {
        match self.deletion {
            DeletionState::Open => Ok(()),
            DeletionState::Attempted | DeletionState::Deleted => Err(ProviderError::Terminal),
        }
    }

    pub(crate) fn review_custody_deletion(
        &mut self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
    ) -> Result<ReviewedCustodyDeletionV1, ProviderError> {
        let mut provider = self.lock()?;
        let status = provider.status(&self.slot)?;
        let confirmation = KagemushaWalletDestructiveConfirmationV1::for_status(self.slot, &status)
            .ok_or(ProviderError::Invalid {
                field: "custody.review head",
            })?;
        let pending = matches!(status, SlotStatus::Pending(_));
        let record = status.marker().ok_or(ProviderError::Invalid {
            field: "custody.review marker",
        })?;
        let capsule = provider
            .current_capsule(&self.slot)?
            .ok_or(ProviderError::Invalid {
                field: "custody.review capsule",
            })?;
        let after = provider.status(&self.slot)?;
        if after != status
            || record.marker().scheme_id != *scheme
            || record.marker().wallet_id != *wallet
        {
            return Err(ProviderError::Invalid {
                field: "custody.review changed",
            });
        }
        let core = &capsule.successor_state.core;
        let KagemushaWalletMarkerStateV1::Head { sequence, head, .. } = record.marker().state
        else {
            return Err(ProviderError::Invalid {
                field: "custody.review head",
            });
        };
        let head = head.value;
        let empty = kagemusha_wallet_empty_map_root_v1();
        let projection = CustodyDeletionReviewV1 {
            pending,
            lifecycle: core.lifecycle,
            operation_kind: capsule.kind,
            pending_outgoing: core.pending_outgoing_root != empty,
            fee_claims: core.fee_claim_root != empty,
            load_redeem: core.load_redeem_recovery_root != empty,
            slot: self.slot.0,
            marker_file_digest: confirmation.marker_file_digest,
            scheme_id: core.scheme_id,
            asset_digest: core.asset_digest,
            wallet_id: core.wallet_id,
            head,
            sequence,
            gross_balance: core.balance,
            core_burned_total: core.burned_total,
        };
        if [
            projection.slot,
            projection.marker_file_digest,
            projection.scheme_id,
            projection.asset_digest,
            projection.wallet_id,
            projection.head,
        ]
        .contains(&[0; 32])
            || projection.core_burned_total > projection.gross_balance
            || projection.scheme_id != *scheme
            || projection.wallet_id != *wallet
            || core.sequence != sequence
        {
            return Err(ProviderError::Invalid {
                field: "custody.review state",
            });
        }
        Ok(ReviewedCustodyDeletionV1 {
            owner: Arc::clone(&self.deletion_owner),
            confirmation,
            projection,
        })
    }

    pub(crate) fn confirm_custody_deletion(
        &mut self,
        review: ReviewedCustodyDeletionV1,
    ) -> Result<CustodyDeletionProgressV1, ProviderError> {
        self.require_custody_operations()?;
        if !Arc::ptr_eq(&self.deletion_owner, &review.owner) {
            return Err(ProviderError::Invalid {
                field: "custody.review owner",
            });
        }
        // Freeze before entering any call that may publish a terminal marker. An error gives
        // no permission to continue money operations; only actual reconciliation can reopen.
        self.deletion = DeletionState::Attempted;
        let status = self
            .provider
            .lock()
            .map_err(|_| ProviderError::Invalid {
                field: "provider handle poisoned",
            })?
            .delete_custody(&self.slot, &review.confirmation)?;
        let result = deleted(&status)?;
        self.deletion = DeletionState::Deleted;
        Ok(result)
    }

    pub(crate) fn resume_custody_deletion(
        &mut self,
    ) -> Result<CustodyDeletionProgressV1, ProviderError> {
        if matches!(self.deletion, DeletionState::Open) {
            return Err(ProviderError::Invalid {
                field: "custody.no deletion attempt",
            });
        }
        // status reconciles an already published terminal marker and resumes D2-D4; it never
        // creates a new terminal marker. Thus a definite noncommit needs new user approval.
        let status = self
            .provider
            .lock()
            .map_err(|_| ProviderError::Invalid {
                field: "provider handle poisoned",
            })?
            .status(&self.slot)?;
        match status {
            SlotStatus::Released(_) | SlotStatus::Pending(_)
                if matches!(self.deletion, DeletionState::Attempted) =>
            {
                self.deletion = DeletionState::Open;
                Ok(CustodyDeletionProgressV1::NotDeleted)
            }
            _ => {
                let result = deleted(&status)?;
                self.deletion = DeletionState::Deleted;
                Ok(result)
            }
        }
    }
}

fn deleted(status: &SlotStatus) -> Result<CustodyDeletionProgressV1, ProviderError> {
    match status {
        SlotStatus::Terminal(record)
            if matches!(
                record.marker().state,
                KagemushaWalletMarkerStateV1::Terminal {
                    reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
                    ..
                }
            ) =>
        {
            Ok(CustodyDeletionProgressV1::Deleted {
                marker_file_digest: *record.marker_file_digest(),
            })
        }
        _ => Err(ProviderError::Terminal),
    }
}
