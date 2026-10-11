//! Original pre-effect physical policy projection for authenticated native Network inputs.
//!
//! Native lanes order transactions and identify receipts. Physical Nexus lanes govern
//! manifest/privacy/compliance policy. Their identifiers are independent; their dataspaces
//! must agree. Every ordinary/expanded source is captured against the acquired h−1 World,
//! before staking, schedules or any prefix effect. A normal source never resolves again.
//! Routing failures are bounded transaction outcomes, while missing/foreign source custody
//! invalidates the carrier. Stateless signature/network validation still precedes these outcomes.
//! Sealed reveals bind the outer ordinal/hash and inner signed hash. Commitments keep their
//! protocol-only validator. Authenticated genesis alone retains in-progress bootstrap routing.

use super::*;
use crate::{
    execution_attempt::{ExecutionAttemptError, ExecutionDeferred},
    queue::{
        RoutingDecision, RoutingPlan,
        policy_route::{PhysicalExecutionPolicyRoute, PhysicalPolicyRouteRejection},
    },
    tx::AcceptedTransaction,
};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_data_model::{
    block::{ExternalExecutionRouteRole, consensus::SumeragiRootScope},
    transaction::error::TransactionRejectionReason,
};
use std::borrow::Cow;

#[derive(Clone, Copy)]
enum PolicyProjection {
    Signed(Result<PhysicalExecutionPolicyRoute, PhysicalPolicyRouteRejection>),
    Genesis(SumeragiRootScope),
    SealedCommitment,
}

/// A source-bound capability. Only the pristine owner (or explicit component test scope)
/// constructs it; an arbitrary native route cannot grant physical policy authority.
#[derive(Clone, Copy)]
pub(crate) struct CapturedNetworkPolicyRoute {
    native: RoutingDecision,
    signed_hash: Option<HashOf<SignedTransaction>>,
    projection: PolicyProjection,
}

/// Opaque instruction bootstrap authority for one original authenticated Network input.
/// Its scope cannot be constructed from a height-one header or mutable local configuration.
pub(crate) struct GenesisExecutionScope {
    scope: SumeragiRootScope,
    header: BlockHeader,
    entrypoint: HashOf<TransactionEntrypoint>,
    index: u64,
}

impl GenesisExecutionScope {
    /// Keep nested effects within the original authenticated genesis input's overlay.
    pub(crate) fn for_transaction(
        &self,
        state: &StateTransaction<'_, '_>,
    ) -> Option<SumeragiRootScope> {
        (state._curr_block == self.header
            && state.block_hashes.is_empty()
            && state.current_network_entrypoint_hash == Some(self.entrypoint)
            && state.current_entrypoint_index == Some(self.index))
        .then_some(self.scope)
    }
}

impl CapturedNetworkPolicyRoute {
    /// Bind the signed genesis route to the separately authenticated original input.
    pub(crate) fn genesis_execution_scope(
        self,
        tx: &SignedTransaction,
        state: &StateTransaction<'_, '_>,
        genesis: Option<&crate::block::AuthenticatedGenesisTransaction>,
    ) -> Result<Option<GenesisExecutionScope>, TransactionRejectionReason> {
        match (self.projection, genesis) {
            (PolicyProjection::Genesis(scope), Some(genesis)) => {
                genesis.validate(tx, state).map_err(policy_rejection)?;
                if self.signed_hash != Some(tx.hash())
                    || self.native.dataspace_id != scope.dataspace_id()
                {
                    return Err(policy_rejection(
                        "genesis instruction scope lost its original source",
                    ));
                }
                Ok(Some(GenesisExecutionScope {
                    scope,
                    header: state._curr_block,
                    entrypoint: tx.hash_as_entrypoint(),
                    index: state.current_entrypoint_index.ok_or_else(|| {
                        policy_rejection("genesis instruction source index is absent")
                    })?,
                }))
            }
            (PolicyProjection::Genesis(_), None) | (_, Some(_)) => Err(policy_rejection(
                "genesis instruction scope requires its exact authenticated source",
            )),
            (_, None) => Ok(None),
        }
    }

    pub(crate) fn for_signed(
        self,
        tx: &SignedTransaction,
        state: &StateTransaction<'_, '_>,
        native: RoutingDecision,
    ) -> Result<PhysicalExecutionPolicyRoute, ExecutionAttemptError<TransactionRejectionReason>>
    {
        if self.native != native || self.signed_hash != Some(tx.hash()) {
            return Err(policy_rejection(
                "physical policy capability belongs to another signed source",
            )
            .into());
        }
        let route = match self.projection {
            PolicyProjection::Signed(result) => result.map_err(Into::into),
            PolicyProjection::Genesis(scope) if state.block_height() == 1 => {
                let accepted = AcceptedTransaction::new_unchecked(Cow::Borrowed(tx));
                PhysicalExecutionPolicyRoute::genesis(
                    &state.nexus,
                    &state.world,
                    &accepted,
                    state.block_unix_timestamp_ms(),
                    scope,
                )
                .and_then(|route| match scope {
                    // The authenticated global genesis provisions child dataspaces before
                    // their native lanes exist. Only this original genesis capability
                    // permits physical bootstrap execution outside its root dataspace.
                    SumeragiRootScope::Global => Ok(route),
                    SumeragiRootScope::Dataspace { .. } => {
                        route.require_dataspace(native).map_err(Into::into)
                    }
                })
            }
            _ => {
                return Err(
                    policy_rejection("source has no signed physical policy capability").into(),
                );
            }
        };
        route.map_err(|error| error.map_rejection(|error| policy_rejection(error.to_string())))
    }

    /// Preflight fraud classification uses the same frozen physical lane as stateful admission.
    pub(super) fn physical(self) -> Option<PhysicalExecutionPolicyRoute> {
        match self.projection {
            PolicyProjection::Signed(Ok(route)) => Some(route),
            _ => None,
        }
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn for_component(
        tx: &AcceptedTransaction<'_>,
        state: &StateTransaction<'_, '_>,
        native: RoutingDecision,
    ) -> Result<Self, ExecutionDeferred> {
        let projection = if tx.external().is_some() {
            let resolved = PhysicalExecutionPolicyRoute::resolve(
                &state.nexus,
                &state.world,
                tx,
                state.block_height().saturating_sub(1),
                state.block_unix_timestamp_ms(),
            )
            .and_then(|route| route.require_dataspace(native).map_err(Into::into));
            PolicyProjection::Signed(match resolved {
                Ok(route) => Ok(route),
                Err(ExecutionAttemptError::Rejected(error)) => Err(error),
                Err(ExecutionAttemptError::Deferred(reason)) => return Err(reason),
            })
        } else {
            PolicyProjection::SealedCommitment
        };
        Ok(Self {
            native,
            signed_hash: tx.external().map(SignedTransaction::hash),
            projection,
        })
    }
}

fn policy_rejection(message: impl Into<String>) -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(iroha_data_model::ValidationFail::NotPermitted(
        message.into(),
    ))
}

#[derive(Clone, Copy)]
struct SourceRow {
    entrypoint: HashOf<TransactionEntrypoint>,
    route: CapturedNetworkPolicyRoute,
}

/// Fixed backing remains charged while output/transaction owners coexist with these rows.
/// No row owns a String, Vec, reconstructed World, or second authority snapshot.
pub(super) struct CapturedNetworkPolicyRoutes {
    carrier: HashOf<BlockHeader>,
    rows: ChargedBuffer<SourceRow>,
    invalid_context: Option<&'static str>,
    captured: bool,
}

impl CapturedNetworkPolicyRoutes {
    pub(super) fn reserve(
        source: &SignedBlock,
        budget: &AllocationBudget,
    ) -> Result<Self, ExecutionDeferred> {
        let rows =
            ChargedBuffer::new(source.network_entrypoint_count(), budget).map_err(|error| {
                match error {
                    ChargedBufferError::Admission(refusal) => ExecutionDeferred::from(refusal),
                    ChargedBufferError::Allocator { .. } => {
                        ivm::error::ExecutionDeferral::AllocationUnavailable.into()
                    }
                }
            })?;
        Ok(Self {
            carrier: source.hash(),
            rows,
            invalid_context: None,
            captured: false,
        })
    }

    pub(super) fn fill_from_preblock(
        &mut self,
        state: &StateBlock<'_>,
        source: &SignedBlock,
    ) -> Result<(), ExecutionDeferred> {
        if self.captured {
            self.invalid_context = Some("physical policy capture is not repeatable");
            return Ok(());
        }
        self.captured = true;
        match self.capture(state, source) {
            Ok(()) => Ok(()),
            Err(ExecutionAttemptError::Rejected(error)) => {
                self.invalid_context = Some(error);
                Ok(())
            }
            Err(ExecutionAttemptError::Deferred(reason)) => Err(reason),
        }
    }

    fn capture(
        &mut self,
        state: &StateBlock<'_>,
        source: &SignedBlock,
    ) -> Result<(), ExecutionAttemptError<&'static str>> {
        if self.carrier != source.hash()
            || state._curr_block != source.header()
            || !self.rows.as_slice().is_empty()
        {
            return Err("physical policy capture lost its original carrier".into());
        }
        let height = source.header().height().get();
        let genesis = source.header().is_genesis() && state.block_hashes.is_empty();
        let context = match (
            source.header().execution_context_hash(),
            source.execution_context(),
        ) {
            (None, None) if genesis || source.network_entrypoint_count() == 0 => None,
            (Some(expected), Some(context))
                if context.has_current_version()
                    && HashOf::new(context) == expected
                    && context.external.len() == source.network_entrypoint_count() =>
            {
                Some(context)
            }
            _ => return Err("Network source has an invalid execution context".into()),
        };
        // Use the same committed ledger time as RoutingSnapshot::of, including replacement
        // owners whose history has already been rewound to the actual predecessor.
        let ledger_time_ms = state
            .latest_block()
            .map_err(|error| {
                error.map_rejection(|_| "Network parent history is unavailable or invalid")
            })?
            .and_then(|block| u64::try_from(block.header().creation_time().as_millis()).ok())
            .unwrap_or(0);
        let root_scope = if genesis {
            // A height-one header alone is not genesis authority. Reuse the canonical
            // original-signature/domain/committee verifier before reading its scope.
            iroha_data_model::sumeragi_finality::authenticated_genesis(source)
                .map(|genesis| genesis.into_parts().0)
                .map_err(|error| {
                    crate::execution_attempt::genesis_read_attempt_error(error, |_| {
                        "Network genesis has no authenticated original authority".into()
                    })
                })?;
            Some(
                iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(source)
                    .map_err(|error| {
                        crate::execution_attempt::genesis_read_attempt_error(error, |_| {
                            "Network genesis has no valid signed root scope".into()
                        })
                    })?
                    .sumeragi_context
                    .root_scope,
            )
        } else {
            crate::sumeragi::lanes::routing::read_routing_root_scope(&state.world)
                .map_err(ExecutionAttemptError::Deferred)?
        };
        let root_scope = root_scope.ok_or("Network source has no immutable root scope")?;
        let policy = crate::sumeragi::lanes::lane_policy(&state.world)
            .map_err(ExecutionAttemptError::Deferred)?;
        let routes = crate::sumeragi::lanes::routing::RoutingInputs {
            root_scope: Some(root_scope),
            policy: policy.as_ref(),
            lanes: state.world.sumeragi_lanes(),
            dataspaces: &state.nexus.dataspace_catalog,
            world: &state.world,
            ledger_time_ms,
        };
        for (index, input) in source.network_entrypoints().enumerate() {
            let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(input));
            let native = if genesis {
                RoutingDecision::new(
                    crate::sumeragi::lanes::routing::GLOBAL_LANE,
                    root_scope.dataspace_id(),
                )
            } else {
                routes
                    .execution_route(&accepted, height)
                    .map_err(ExecutionAttemptError::Deferred)?
                    .ok_or("Network source has no exact active native lane")?
            };
            if let Some(context) = context {
                let embedded = &context.external[index];
                if embedded.entrypoint_hash != input.hash()
                    || embedded.lane_id != native.lane_id
                    || embedded.dataspace_id != native.dataspace_id
                    || embedded.routing_plan_digest != RoutingPlan::single(native).digest()
                    || !matches!(embedded.routing_plan_legs.as_slice(), [leg] if leg.lane_id == native.lane_id
                        && leg.dataspace_id == native.dataspace_id && leg.role == ExternalExecutionRouteRole::Coordinator)
                {
                    return Err(
                        "Network context differs from its exact pre-block native route".into(),
                    );
                }
            }
            let projection = if genesis {
                if !matches!(input, TransactionEntrypoint::External(_)) {
                    return Err("authenticated genesis contains a non-signed Network source".into());
                }
                PolicyProjection::Genesis(root_scope)
            } else if accepted.external().is_some() {
                let resolved = PhysicalExecutionPolicyRoute::resolve(
                    &state.nexus,
                    &state.world,
                    &accepted,
                    height.saturating_sub(1),
                    ledger_time_ms,
                )
                .and_then(|route| route.require_dataspace(native).map_err(Into::into));
                PolicyProjection::Signed(match resolved {
                    Ok(route) => Ok(route),
                    Err(ExecutionAttemptError::Rejected(error)) => Err(error),
                    Err(ExecutionAttemptError::Deferred(reason)) => {
                        return Err(ExecutionAttemptError::Deferred(reason));
                    }
                })
            } else {
                PolicyProjection::SealedCommitment
            };
            self.rows
                .append(&[SourceRow {
                    entrypoint: input.hash(),
                    route: CapturedNetworkPolicyRoute {
                        native,
                        signed_hash: accepted.external().map(SignedTransaction::hash),
                        projection,
                    },
                }])
                .expect("one prepaid row per exact Network input");
        }
        Ok(())
    }

    pub(super) fn validate_carrier(&self, source: &SignedBlock) -> Result<(), &'static str> {
        if !self.captured {
            return Err("physical policy owner was not captured from pristine State");
        }
        if let Some(error) = self.invalid_context {
            return Err(error);
        }
        if source.hash() != self.carrier
            || source.network_entrypoint_count() != self.rows.as_slice().len()
        {
            return Err("physical policy owner belongs to another carrier");
        }
        Ok(())
    }

    pub(super) fn get(
        &self,
        source: &SignedBlock,
        index: usize,
    ) -> Result<(RoutingDecision, CapturedNetworkPolicyRoute), &'static str> {
        self.validate_carrier(source)?;
        let row = self
            .rows
            .as_slice()
            .get(index)
            .ok_or("physical policy source ordinal is absent")?;
        if source
            .network_entrypoint_at(index)
            .map(TransactionEntrypoint::hash)
            != Some(row.entrypoint)
        {
            return Err("physical policy source ordinal/hash changed");
        }
        Ok((row.route.native, row.route))
    }
}

#[cfg(test)]
#[path = "network_policy_routes_tests.rs"]
mod tests;
