//! Borrowed SCCP eligibility facts from one original current or pre-block World.
//!
//! Replacement blocks use their actual reverted MV baseline, not a new view of the
//! still-published successor. All nested values remain borrowed from their original owners.

use super::{hold, pause_record::RetainedSccpFastPause, reconciliation_store, store};
use crate::state::{WorldBlock, WorldReadOnly, WorldTransaction};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{inbound::SccpInboundRecordV1, params::SccpParametersV1, registry::SccpRouteV1},
};
use mv::storage::StorageReadOnly as _;

/// The four original facts used by fee eligibility and block cap classification.
pub(crate) trait EligibilityRead {
    /// Original current generation's immutable start time and degraded-height counter.
    fn heartbeat_facts(&self) -> Option<(u64, u32)>;
    /// Earliest original reconciliation deadline; the ordered index is derived from records.
    fn reconciliation_due_at_ms(&self) -> Option<u64>;
    /// A retained original panel round reached quorum and requires a next-pass recheck.
    fn fast_pause_due(&self) -> bool;
    /// SCCP's original parameters, including exemption caps and enabled status.
    fn parameters(&self) -> Option<&SccpParametersV1>;
    /// Original route, without copying its revision graph.
    fn route(&self, network: SccpNetworkV1) -> Option<&SccpRouteV1>;
    /// Original record, before any block-start or transaction effects.
    fn inbound(&self, message: &[u8; 32]) -> Option<&SccpInboundRecordV1>;
    /// Highest native forgery generation in the same original observation.
    fn forgery_max_generation(&self) -> Option<u64>;
    /// Original fixed reconciliation rate and cumulative settled face.
    fn reconciliation(
        &self,
        key: (SccpNetworkV1, u32),
    ) -> Option<&iroha_data_model::sccp::reconciliation::SccpReconciliationStateV1>;
    /// Original pending refund reservation of the revision.
    fn pending_refunds(&self, key: (SccpNetworkV1, u32)) -> u128;
    /// Original retained pause; no DTO clone or replacement credit is introduced.
    fn pause(&self, network: SccpNetworkV1) -> Option<&RetainedSccpFastPause>;
}

/// Ordinary committed World read already retained by its caller.
pub(crate) struct Current<'a, W: WorldReadOnly + ?Sized>(pub(crate) &'a W);
impl<W: WorldReadOnly + ?Sized> Copy for Current<'_, W> {}
impl<W: WorldReadOnly + ?Sized> Clone for Current<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: WorldReadOnly + ?Sized> EligibilityRead for Current<'_, W> {
    fn fast_pause_due(&self) -> bool {
        store::fast_pause_rounds::iter(self.0).any(|(_, round)| round.certify_due)
    }
    fn reconciliation_due_at_ms(&self) -> Option<u64> {
        self.0
            .sccp_reconciliation_due()
            .iter()
            .next()
            .map(|(key, _)| key.0)
    }
    fn heartbeat_facts(&self) -> Option<(u64, u32)> {
        let generation =
            store::committee_generations::get(self.0, store::committee_current::get(self.0))?;
        Some((
            generation.start_timestamp_ms,
            *store::degraded_run::get(self.0),
        ))
    }
    fn parameters(&self) -> Option<&SccpParametersV1> {
        store::parameters::get(self.0).as_ref()
    }
    fn route(&self, network: SccpNetworkV1) -> Option<&SccpRouteV1> {
        store::routes::get(self.0, &network)
    }
    fn inbound(&self, message: &[u8; 32]) -> Option<&SccpInboundRecordV1> {
        store::inbound_messages::get(self.0, message)
    }
    fn forgery_max_generation(&self) -> Option<u64> {
        store::forgery_max_generation(self.0)
    }
    fn reconciliation(
        &self,
        key: (SccpNetworkV1, u32),
    ) -> Option<&iroha_data_model::sccp::reconciliation::SccpReconciliationStateV1> {
        reconciliation_store::get(self.0, &key)
    }
    fn pending_refunds(&self, key: (SccpNetworkV1, u32)) -> u128 {
        reconciliation_store::pending_refunds(self.0, &key)
    }
    fn pause(&self, network: SccpNetworkV1) -> Option<&RetainedSccpFastPause> {
        store::fast_pauses::get(self.0, &network)
    }
}

/// Exact pre-block values retained by the acquired ordinary or replacement block.
#[derive(Clone, Copy)]
pub(crate) struct BlockParent<'a, 'world>(pub(crate) &'a WorldBlock<'world>);
/// Exact pre-block values including this still-unapplied transaction's preimages.
#[derive(Clone, Copy)]
pub(crate) struct TransactionParent<'a, 'block, 'world>(
    pub(crate) &'a WorldTransaction<'block, 'world>,
);
macro_rules! parent_read {
    ($owner:ty) => {
        impl EligibilityRead for $owner {
            fn fast_pause_due(&self) -> bool {
                if cfg!(all(test, sumeragi_core_mutation = "HC302")) {
                    return self
                        .0
                        .sccp_fast_pause_rounds
                        .iter()
                        .any(|(_, round)| round.certify_due);
                }
                self.0
                    .sccp_fast_pause_rounds
                    .iter_before_block()
                    .any(|(_, round)| round.certify_due)
            }
            fn reconciliation_due_at_ms(&self) -> Option<u64> {
                self.0
                    .sccp_reconciliation_due
                    .iter_before_block()
                    .next()
                    .map(|(key, _)| key.0)
            }
            fn heartbeat_facts(&self) -> Option<(u64, u32)> {
                let current = self.0.sccp_committee_current.get_before_block();
                let generation = self
                    .0
                    .sccp_committee_generations
                    .get_before_block(current)?;
                Some((
                    generation.start_timestamp_ms,
                    *self.0.sccp_degraded_run.get_before_block(),
                ))
            }
            fn parameters(&self) -> Option<&SccpParametersV1> {
                if cfg!(all(test, sumeragi_core_mutation = "HC243")) {
                    return self.0.sccp_parameters.get().as_ref();
                }
                self.0.sccp_parameters.get_before_block().as_ref()
            }
            fn route(&self, network: SccpNetworkV1) -> Option<&SccpRouteV1> {
                if cfg!(all(test, sumeragi_core_mutation = "HC243")) {
                    return self.0.sccp_routes.get(&network);
                }
                self.0.sccp_routes.get_before_block(&network)
            }
            fn inbound(&self, message: &[u8; 32]) -> Option<&SccpInboundRecordV1> {
                if cfg!(all(test, sumeragi_core_mutation = "HC243")) {
                    return self.0.sccp_inbound_messages.get(message);
                }
                self.0.sccp_inbound_messages.get_before_block(message)
            }
            fn forgery_max_generation(&self) -> Option<u64> {
                *self.0.sccp_forgery_max_generation.get_before_block()
            }
            fn reconciliation(
                &self,
                key: (SccpNetworkV1, u32),
            ) -> Option<&iroha_data_model::sccp::reconciliation::SccpReconciliationStateV1> {
                self.0.sccp_reconciliations.get_before_block(&key)
            }
            fn pending_refunds(&self, key: (SccpNetworkV1, u32)) -> u128 {
                self.0
                    .sccp_pending_refund_amount
                    .get_before_block(&key)
                    .copied()
                    .unwrap_or(0)
            }
            fn pause(&self, network: SccpNetworkV1) -> Option<&RetainedSccpFastPause> {
                if cfg!(all(test, sumeragi_core_mutation = "HC243")) {
                    return self.0.sccp_fast_pauses.get(&network);
                }
                self.0.sccp_fast_pauses.get_before_block(&network)
            }
        }
    };
}
parent_read!(BlockParent<'_, '_>);
parent_read!(TransactionParent<'_, '_, '_>);

/// Shared progress kernel for the current World and original fee-eligibility preimage.
pub(crate) fn inbound_may_progress(
    source: &(impl EligibilityRead + ?Sized),
    record: &SccpInboundRecordV1,
    amount: u128,
    committed_time_ms: Option<u64>,
) -> bool {
    let enabled = source.parameters().is_some_and(|params| params.enabled);
    let revision = source
        .route(record.network)
        .and_then(|route| route.revisions.get(&record.revision));
    !hold::taira_from_parts(
        enabled,
        revision.map(|r| r.activation),
        source.pause(record.network),
        committed_time_ms,
    ) && record.status.is_pending()
        && revision.is_some_and(|r| {
            r.activation.settles()
                && if let Some(accounting) = source
                    .reconciliation((record.network, record.revision))
                    .filter(|record| record.rho.is_some())
                {
                    let rate = accounting.rho.expect("filtered reconciled rate");
                    iroha_sccp::v1::reconciliation::payout(
                        rate.backing,
                        rate.denominator,
                        accounting.settled_face,
                        amount,
                        r.liability.saturating_sub(
                            source.pending_refunds((record.network, record.revision)),
                        ),
                    )
                    .is_some_and(|payout| payout > 0)
                } else {
                    r.liability >= amount
                        && !r.forgery_held(source.forgery_max_generation())
                        && r.quarantine.is_none()
                }
        })
}
