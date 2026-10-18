//! Lane routing (`specs/sumeragi_lanes.md` §5.1) from immutable root scope and committed state.
//! A private root owns lane zero in its signed dataspace and admits no foreign/global work.
//! Missing or malformed genesis metadata grants no execution route.
//!
//! Concrete instruction/address scopes choose the matching admitted fixed dataspace lane;
//! control-plane registry batches use lane zero. Otherwise the policy's explicit routes apply,
//! followed by lane zero and the admitted elastic lanes sharded by `H(authority)`. A concrete
//! universal target may use only universal lanes. An inactive or absent private lane has no
//! execution route. The global chain re-evaluates the route at merge from committed state.

use iroha_crypto::Hash;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    nexus::DataSpaceCatalog,
    parameter::system::{ConsensusHandshakeMetadata, consensus_metadata},
    sumeragi_lanes::{SumeragiLanePolicy, SumeragiLaneState},
};
use iroha_model_base::topology::LaneId;
use norito::codec::Encode as _;

use crate::{
    queue::{TransactionRoutingView, matchers_match_with_world, native_execution_target},
    state::{StateReadOnly, WorldReadOnly},
};

/// Lane zero of the authenticated root ledger (global or private dataspace).
pub const GLOBAL_LANE: LaneId = LaneId::new(0);

/// Routing inputs taken from committed state.
pub struct RoutingInputs<'a, W> {
    /// Immutable signed root scope. Missing or malformed metadata admits no route.
    pub root_scope: Option<SumeragiRootScope>,
    /// The committed lane policy (`None`: the chain has only lane `0`).
    pub policy: Option<&'a SumeragiLanePolicy>,
    /// The committed lane set.
    pub lanes: &'a SumeragiLaneState,
    /// The committed dataspace catalog (for account matchers).
    pub dataspaces: &'a DataSpaceCatalog,
    /// The world state the matchers read.
    pub world: &'a W,
    /// Deterministic ledger time of the height (for time-dependent matchers).
    pub ledger_time_ms: u64,
}

impl<W> Clone for RoutingInputs<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<W> Copy for RoutingInputs<'_, W> {}

impl<W: WorldReadOnly> RoutingInputs<'_, W> {
    /// Whether `lane` receives transactions at global height `height`: authenticated lane `0`, any
    /// other lane while its record admits blocks anchored at `height - 1`, the tip a block at
    /// `height` is built on (a lane carries nothing before the global chain has applied its
    /// activation height, and nothing anchored from its closing height).
    #[must_use]
    pub fn admitted(&self, lane: LaneId, height: u64) -> bool {
        let Some(scope) = self.root_scope.filter(|scope| scope.validate().is_ok()) else {
            return false;
        };
        lane == GLOBAL_LANE
            || matches!(scope, SumeragiRootScope::Global)
                && self
                    .lanes
                    .lane(lane)
                    .is_some_and(|record| record.admits_anchor(height.saturating_sub(1)))
    }

    /// The sole execution route of a transaction at the next global height.
    /// Lane zero owns the signed root scope; another lane keeps its original record's
    /// dataspace even when the global chain rescues the transaction directly.
    ///
    /// # Errors
    ///
    /// Returns the original resource deferral if reading the committed routing
    /// authority cannot complete.
    pub fn execution_route(
        &self,
        tx: &dyn TransactionRoutingView,
        height: u64,
    ) -> Result<Option<crate::queue::RoutingDecision>, crate::execution_attempt::ExecutionDeferred>
    {
        let Some(lane) = self.route(tx, height)? else {
            return Ok(None);
        };
        let dataspace = if lane == GLOBAL_LANE {
            let Some(scope) = self.root_scope else {
                return Ok(None);
            };
            scope.dataspace_id()
        } else {
            let Some(record) = self.lanes.lane(lane) else {
                return Ok(None);
            };
            record.dataspace
        };
        Ok(Some(crate::queue::RoutingDecision::new(lane, dataspace)))
    }

    /// The default-route lanes at `height`: lane `0` and the admitted elastic lanes, ascending.
    #[must_use]
    pub fn shards(&self, height: u64) -> Vec<LaneId> {
        let Some(scope) = self.root_scope.filter(|scope| scope.validate().is_ok()) else {
            return Vec::new();
        };
        if matches!(scope, SumeragiRootScope::Dataspace { .. }) {
            return vec![GLOBAL_LANE];
        }
        let mut shards = vec![GLOBAL_LANE];
        if let Some(policy) = self.policy {
            shards.extend(
                self.lanes
                    .lanes
                    .iter()
                    .filter(|record| {
                        policy.is_elastic(record.lane)
                            && record.admits_anchor(height.saturating_sub(1))
                    })
                    .map(|record| record.lane),
            );
        }
        shards
    }

    /// The lane of `tx` at global height `height`. An unresolved or inactive concrete
    /// dataspace fails closed; it must never be executed in the universal dataspace.
    ///
    /// # Errors
    ///
    /// Returns the original resource deferral if reading the committed routing
    /// authority cannot complete.
    pub fn route(
        &self,
        tx: &dyn TransactionRoutingView,
        height: u64,
    ) -> Result<Option<LaneId>, crate::execution_attempt::ExecutionDeferred> {
        let Some(scope) = self.root_scope.filter(|scope| scope.validate().is_ok()) else {
            return Ok(None);
        };
        let target =
            match native_execution_target(tx, self.dataspaces, self.world, self.ledger_time_ms) {
                Ok(target) => target,
                Err(crate::queue::RoutingResolveError::Deferred(reason)) => return Err(reason),
                Err(_) => return Ok(None),
            };
        if let SumeragiRootScope::Dataspace { dataspace_id, .. } = scope {
            if self.dataspaces.by_id(dataspace_id).is_none() {
                return Ok(None);
            }
            if matches!(
                tx.executable(),
                Some(
                    iroha_data_model::transaction::Executable::Ivm(_)
                        | iroha_data_model::transaction::Executable::IvmProved(_)
                )
            ) {
                return Ok(None);
            }
            // TODO: Define a typed local-control allowlist before private roots admit
            // parameter changes. Mixed batches must not disguise global control work.
            let changes_parameters = tx.any_matching_instruction(&mut |instruction| {
                instruction
                    .as_any()
                    .is::<iroha_data_model::isi::SetParameter>()
            });
            return Ok((!target.global
                && !changes_parameters
                && target.dataspace.is_none_or(|target| target == dataspace_id))
            .then_some(GLOBAL_LANE));
        }
        if target.global {
            return Ok(Some(GLOBAL_LANE));
        }
        if let Some(dataspace) = target
            .dataspace
            .filter(|dataspace| *dataspace != iroha_model_base::topology::DataSpaceId::UNIVERSAL)
        {
            if self.dataspaces.by_id(dataspace).is_none() {
                return Ok(None);
            }
            // Physical dataspace routing selects its first admitted fixed lane. The
            // policy binds that lane's exact committee and its record pins the scope.
            let Some(policy) = self.policy else {
                return Ok(None);
            };
            return Ok(policy
                .fixed
                .iter()
                .find(|fixed| {
                    fixed.dataspace == dataspace
                        && self.admitted(fixed.lane, height)
                        && self.lanes.lane(fixed.lane).is_some_and(|record| {
                            record.dataspace == dataspace && record.committee == fixed.committee
                        })
                })
                .map(|fixed| fixed.lane));
        }
        let Some(policy) = self.policy else {
            return Ok(Some(GLOBAL_LANE));
        };
        for route in &policy.routes {
            if matchers_match_with_world(
                route.account.as_deref(),
                route.instruction.as_deref(),
                tx,
                self.dataspaces,
                self.world,
                Some(self.ledger_time_ms),
            )? {
                return Ok(Some(
                    if self.admitted(route.lane, height)
                        && target.dataspace.is_none_or(|dataspace| {
                            route.lane == GLOBAL_LANE
                                || self
                                    .lanes
                                    .lane(route.lane)
                                    .is_some_and(|record| record.dataspace == dataspace)
                        })
                    {
                        route.lane
                    } else {
                        GLOBAL_LANE
                    },
                ));
            }
        }
        let mut shards = self.shards(height);
        if let Some(dataspace) = target.dataspace {
            shards.retain(|lane| {
                *lane == GLOBAL_LANE
                    || self
                        .lanes
                        .lane(*lane)
                        .is_some_and(|record| record.dataspace == dataspace)
            });
        }
        let Some(authority) = tx.authority_opt() else {
            return Ok(Some(GLOBAL_LANE));
        };
        Ok(Some(shards[default_shard(authority, shards.len())]))
    }
}

/// Routing inputs owned for one pass over many transactions: read once from a state view.
#[derive(Clone, Debug)]
pub struct RoutingSnapshot {
    root_scope: Option<SumeragiRootScope>,
    policy: Option<SumeragiLanePolicy>,
    lanes: SumeragiLaneState,
    dataspaces: DataSpaceCatalog,
    ledger_time_ms: u64,
}

impl RoutingSnapshot {
    /// The routing inputs of the committed state `view` (for the height after its tip).
    ///
    /// # Errors
    ///
    /// Returns the original resource deferral if reading the committed routing
    /// authority cannot complete.
    pub fn of(
        view: &impl StateReadOnly,
    ) -> Result<Self, crate::execution_attempt::ExecutionDeferred> {
        Ok(Self {
            root_scope: read_routing_root_scope(view.world())?,
            policy: super::lane_policy(view.world())?,
            lanes: view.world().sumeragi_lanes().clone(),
            dataspaces: view.nexus().dataspace_catalog.clone(),
            ledger_time_ms: view.authenticated_query_ledger_time_ms().unwrap_or(0),
        })
    }

    /// The committed lane policy.
    #[must_use]
    pub fn policy(&self) -> Option<&SumeragiLanePolicy> {
        self.policy.as_ref()
    }

    /// Whether the chain routes anything off lane `0`.
    #[must_use]
    pub fn has_lanes(&self) -> bool {
        self.policy.is_some() && !self.lanes.lanes.is_empty()
    }

    /// The borrowed inputs over `world`.
    #[must_use]
    pub fn inputs<'a, W>(&'a self, world: &'a W) -> RoutingInputs<'a, W> {
        RoutingInputs {
            root_scope: self.root_scope,
            policy: self.policy.as_ref(),
            lanes: &self.lanes,
            dataspaces: &self.dataspaces,
            world,
            ledger_time_ms: self.ledger_time_ms,
        }
    }
}

/// Read the root scope exclusively from immutable, validated genesis metadata in World.
/// Missing, malformed or unsupported metadata never acquires global routing authority.
pub fn committed_root_scope(world: &impl WorldReadOnly) -> Option<SumeragiRootScope> {
    read_committed_root_scope(world).ok().flatten()
}

/// Preserve original root decoding through native routing and pre-effect capture.
/// Completed malformed metadata remains scope absence; local refusal never does.
/// Off-chain proof serving uses this same owner before projecting a capacity observation.
/// # Errors
/// Returns the original local decoding refusal; no root authority is inferred from failure.
pub fn read_routing_root_scope(
    world: &impl WorldReadOnly,
) -> Result<Option<SumeragiRootScope>, crate::execution_attempt::ExecutionDeferred> {
    let read = norito::core::classify_decode_attempt(|| {
        read_committed_root_scope(world).map_err(norito::json::Error::into_core_error)
    });
    match read {
        Ok(scope) => Ok(scope),
        Err(error) => match crate::execution_attempt::canonical_decode_attempt_error(error, |_| ())
        {
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                if cfg!(all(test, sumeragi_core_mutation = "HC39")) {
                    return Ok(None);
                }
                Err(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Rejected(()) => Ok(None),
        },
    }
}

/// Read the same immutable scope while preserving the original JSON decoder failure.
/// Execution must retain a local refusal; a missing or malformed owner never grants scope.
pub(crate) fn read_committed_root_scope(
    world: &impl WorldReadOnly,
) -> Result<Option<SumeragiRootScope>, norito::json::Error> {
    let parameters = world.parameters();
    let Some(metadata) = parameters
        .custom()
        .get(&consensus_metadata::handshake_meta_id())
    else {
        return Ok(None);
    };
    let metadata: ConsensusHandshakeMetadata =
        norito::json::from_str(metadata.payload().get().as_str())?;
    if metadata.validate().is_err()
        || metadata.wire_protocol_version != u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION)
    {
        return Ok(None);
    }
    Ok(Some(metadata.sumeragi_context.root_scope))
}

#[cfg(test)]
#[path = "routing/test_support.rs"]
pub(crate) mod test_support;

/// The default-route shard of `authority` among `count` shards: `H(authority) mod count` over
/// the first eight digest bytes.
#[must_use]
pub fn default_shard(authority: &iroha_data_model::account::AccountId, count: usize) -> usize {
    let digest: [u8; 32] = Hash::new(authority.encode()).into();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let count = u64::try_from(count.max(1)).unwrap_or(u64::MAX);
    usize::try_from(u64::from_be_bytes(prefix) % count).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        isi::{InstructionBox, Log},
        parameter::system::SumeragiParameters,
        sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneAutoscale, SumeragiLaneFrontier, SumeragiLaneRecord,
            SumeragiLaneRoute,
        },
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::topology::DataSpaceId;

    use super::*;
    use crate::{state::World, tx::AcceptedTransaction};

    fn record(lane: u32, active_from: u64, closing: Option<u64>) -> SumeragiLaneRecord {
        SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(lane),
            dataspace: DataSpaceId::new(0),
            incarnation: [u8::try_from(lane).unwrap(); 32],
            params: SumeragiParameters::default(),
            committee: Vec::new(),
            created_at: active_from.saturating_sub(2),
            active_from,
            closing,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: active_from,
            rescued: 0,
        }
    }

    fn lanes(records: Vec<SumeragiLaneRecord>) -> SumeragiLaneState {
        let mut state = SumeragiLaneState::default();
        for record in records {
            state.upsert(record);
        }
        state
    }

    fn tx(seed: u8) -> AcceptedTransaction<'static> {
        let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
        let signed = TransactionBuilder::new(
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"routing-test",
            ))),
            AccountId::new(pair.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "routed".to_owned(),
        ))])
        .sign(pair.private_key());
        AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(signed))
    }

    fn policy(routes: Vec<SumeragiLaneRoute>) -> SumeragiLanePolicy {
        SumeragiLanePolicy {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            anchor_freshness: 16,
            max_merge_blocks: 32,
            stall_window: 256,
            lane_params: SumeragiParameters::default(),
            fixed: vec![SumeragiFixedLane {
                lane: LaneId::new(3),
                dataspace: DataSpaceId::new(0),
                committee: Vec::new(),
            }],
            routes,
            autoscale: Some(SumeragiLaneAutoscale {
                min_lane: LaneId::new(16),
                max_lane_exclusive: LaneId::new(32),
                dataspace: DataSpaceId::new(0),
                committee_size: 4,
                per_lane_target_tps: 100,
                window: 8,
                scale_out_permille: 750,
                scale_in_permille: 250,
                cooldown: 8,
            }),
        }
    }

    #[test]
    fn default_route_shards_by_authority_over_admitted_elastic_lanes() {
        let world = test_support::world(SumeragiRootScope::Global);
        let dataspaces = DataSpaceCatalog::default();
        let policy = policy(Vec::new());
        let open = lanes(vec![record(16, 10, None), record(17, 10, None)]);
        let transactions = (1u8..41).map(tx).collect::<Vec<_>>();
        let view = world.view();
        let inputs = RoutingInputs {
            root_scope: committed_root_scope(&view),
            policy: Some(&policy),
            lanes: &open,
            dataspaces: &dataspaces,
            world: &view,
            ledger_time_ms: 0,
        };
        let routed = transactions
            .iter()
            .map(|tx| inputs.route(tx, 20).expect("completed routing read"))
            .collect::<Vec<_>>();
        for lane in [0, 16, 17] {
            assert!(
                routed.contains(&Some(LaneId::new(lane))),
                "lane {lane} receives traffic"
            );
        }
        // The same account always routes to the same lane.
        assert_eq!(
            inputs
                .route(&transactions[2], 20)
                .expect("completed routing read"),
            inputs
                .route(&transactions[2], 20)
                .expect("completed routing read")
        );
        // Until the global chain has applied the activation height, and from the height after
        // closing, a lane receives nothing.
        assert!(
            transactions.iter().all(
                |tx| inputs.route(tx, 10).expect("completed routing read") == Some(GLOBAL_LANE)
            )
        );
        assert!(
            transactions.iter().any(
                |tx| inputs.route(tx, 11).expect("completed routing read") != Some(GLOBAL_LANE)
            )
        );
        let closing = lanes(vec![record(16, 10, Some(15)), record(17, 10, Some(15))]);
        let inputs = RoutingInputs {
            lanes: &closing,
            ..inputs
        };
        assert!(
            transactions.iter().any(
                |tx| inputs.route(tx, 15).expect("completed routing read") != Some(GLOBAL_LANE)
            )
        );
        assert!(
            transactions.iter().all(
                |tx| inputs.route(tx, 16).expect("completed routing read") == Some(GLOBAL_LANE)
            )
        );
        // Without a policy every transaction belongs to lane 0.
        let inputs = RoutingInputs {
            policy: None,
            lanes: &open,
            ..inputs
        };
        assert!(
            transactions.iter().all(
                |tx| inputs.route(tx, 20).expect("completed routing read") == Some(GLOBAL_LANE)
            )
        );
    }

    #[test]
    fn explicit_routes_target_admitted_lanes_only() {
        let world = test_support::world(SumeragiRootScope::Global);
        let dataspaces = DataSpaceCatalog::default();
        let fixed = lanes(vec![record(3, 5, None)]);
        let transaction = tx(1);
        let view = world.view();
        let with_policy = |policy: &SumeragiLanePolicy, height: u64| {
            RoutingInputs {
                root_scope: committed_root_scope(&view),
                policy: Some(policy),
                lanes: &fixed,
                dataspaces: &dataspaces,
                world: &view,
                ledger_time_ms: 0,
            }
            .route(&transaction, height)
            .expect("completed routing read")
        };
        let to = |lane: u32, instruction: &str| SumeragiLaneRoute {
            lane: LaneId::new(lane),
            account: None,
            instruction: Some(instruction.to_owned()),
        };
        assert_eq!(
            with_policy(&policy(vec![to(3, "Log")]), 6),
            Some(LaneId::new(3))
        );
        // A fixed lane that is not admitted at the height falls back to the global lane.
        assert_eq!(
            with_policy(&policy(vec![to(3, "Log")]), 5),
            Some(GLOBAL_LANE)
        );
        // A route whose matcher does not match leaves the default route (lane 0 only here).
        assert_eq!(
            with_policy(&policy(vec![to(3, "Mint")]), 6),
            Some(GLOBAL_LANE)
        );
    }
    #[test]
    fn execution_route_preserves_actual_pinned_dataspace_and_closing_boundary() {
        let world = test_support::world(SumeragiRootScope::Global);
        let view = world.view();
        let dataspaces = DataSpaceCatalog::default();
        let mut pinned = record(3, 5, Some(8));
        pinned.dataspace = DataSpaceId::new(7);
        let lanes = lanes(vec![pinned]);
        let tx = tx(1);
        let policy = policy(vec![SumeragiLaneRoute {
            lane: LaneId::new(3),
            account: None,
            instruction: Some("Log".into()),
        }]);
        let inputs = RoutingInputs {
            root_scope: committed_root_scope(&view),
            policy: Some(&policy),
            lanes: &lanes,
            dataspaces: &dataspaces,
            world: &view,
            ledger_time_ms: 0,
        };
        assert_eq!(
            inputs
                .execution_route(&tx, 6)
                .expect("completed routing read"),
            Some(crate::queue::RoutingDecision::new(
                LaneId::new(3),
                DataSpaceId::new(7)
            ))
        );
        assert_eq!(
            inputs
                .execution_route(&tx, 8)
                .expect("completed routing read"),
            Some(crate::queue::RoutingDecision::new(
                LaneId::new(3),
                DataSpaceId::new(7)
            ))
        );
        assert_eq!(
            inputs
                .execution_route(&tx, 9)
                .expect("completed routing read"),
            Some(crate::queue::RoutingDecision::new(
                GLOBAL_LANE,
                DataSpaceId::UNIVERSAL
            ))
        );
    }

    #[test]
    fn missing_malformed_or_invalid_scope_never_defaults_to_global() {
        use iroha_data_model::parameter::{Parameter, custom::CustomParameter};
        let world = World::new();
        let absent = world.view();
        assert_eq!(committed_root_scope(&absent), None);
        assert_eq!(read_routing_root_scope(&absent).unwrap(), None);
        drop(absent);
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(Parameter::Custom(CustomParameter::new(
                consensus_metadata::handshake_meta_id(),
                iroha_primitives::json::Json::from_norito_value_ref(&norito::json::Value::Bool(
                    false,
                ))
                .unwrap(),
            )))
            .expect("valid fixture parameters");
        parameters.commit();
        let view = world.view();
        assert_eq!(committed_root_scope(&view), None);
        assert_eq!(read_routing_root_scope(&view).unwrap(), None);
        let dataspaces = DataSpaceCatalog::default();
        let lanes = SumeragiLaneState::default();
        let inputs = RoutingInputs {
            root_scope: committed_root_scope(&view),
            policy: None,
            lanes: &lanes,
            dataspaces: &dataspaces,
            world: &view,
            ledger_time_ms: 0,
        };
        assert!(!inputs.admitted(GLOBAL_LANE, 2));
        assert!(inputs.shards(2).is_empty());
        assert_eq!(
            inputs
                .execution_route(&tx(1), 2)
                .expect("completed routing read"),
            None
        );
        let invalid = RoutingInputs {
            root_scope: Some(SumeragiRootScope::Dataspace {
                parent_network_id: tx(1).external().unwrap().network_id().copied().unwrap(),
                dataspace_id: DataSpaceId::UNIVERSAL,
            }),
            ..inputs
        };
        assert!(!invalid.admitted(GLOBAL_LANE, 2));
        assert!(invalid.shards(2).is_empty());
        assert_eq!(
            invalid
                .execution_route(&tx(1), 2)
                .expect("completed routing read"),
            None
        );
    }

    #[test]
    fn private_root_owns_exact_full_width_scope_and_refuses_global_or_foreign_work() {
        use iroha_data_model::{
            isi::{SetParameter, smart_contract_code::RegisterSmartContractBytes},
            nexus::DataSpaceMetadata,
            smart_contract::ContractAddress,
            transaction::{Executable, executable::ContractInvocation},
        };
        let pair = KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519);
        let authority = AccountId::new(pair.public_key().clone());
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"private-root"),
        ));
        let own = DataSpaceId::new((1_u64 << 40) + 7);
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: network,
            dataspace_id: own,
        };
        let world = test_support::world(scope);
        let view = world.view();
        let dataspaces = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: own,
                alias: "owner-private".into(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .unwrap();
        let lanes = lanes(vec![record(16, 1, None)]);
        let policy = policy(vec![SumeragiLaneRoute {
            lane: LaneId::new(16),
            account: None,
            instruction: None,
        }]);
        let inputs = RoutingInputs {
            root_scope: committed_root_scope(&view),
            policy: Some(&policy),
            lanes: &lanes,
            dataspaces: &dataspaces,
            world: &view,
            ledger_time_ms: 0,
        };
        assert_eq!(inputs.root_scope, Some(scope));
        assert_eq!(inputs.shards(2), vec![GLOBAL_LANE]);
        assert!(!inputs.admitted(LaneId::new(16), 2));
        let make = |executable| {
            AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(
                TransactionBuilder::new(
                    network,
                    authority.clone(),
                    FeePaymentIntent::authority(Vec::new(), None),
                )
                .with_executable(executable)
                .sign(pair.private_key()),
            ))
        };
        let expected = Some(crate::queue::RoutingDecision::new(GLOBAL_LANE, own));
        let upload = make(Executable::Instructions(
            vec![
                RegisterSmartContractBytes {
                    artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                        own,
                        Hash::new(b"routing-only-artifact"),
                    ),
                    code: vec![1],
                }
                .into(),
            ]
            .into(),
        ));
        assert_eq!(
            inputs
                .execution_route(&upload, 2)
                .expect("completed routing read"),
            expected
        );
        for (target, expected) in [
            (own, expected),
            (DataSpaceId::new(7), None),
            (DataSpaceId::UNIVERSAL, None),
        ] {
            let call = make(Executable::ContractCall(ContractInvocation {
                contract_address: ContractAddress::derive(&network, &authority, 0, target).unwrap(),
                expected_code_hash: Hash::new(b"routing-only-artifact"),
                entrypoint: "call".into(),
                arguments: None,
            }));
            assert_eq!(
                inputs
                    .execution_route(&call, 2)
                    .expect("completed routing read"),
                expected
            );
        }
        let control: InstructionBox =
            SetParameter::new(test_support::metadata(SumeragiRootScope::Global)).into();
        let control_only = make(Executable::Instructions(vec![control.clone()].into()));
        let mixed = make(Executable::Instructions(
            vec![
                control,
                Log::new(iroha_data_model::Level::INFO, "disguise".into()).into(),
            ]
            .into(),
        ));
        assert_eq!(
            inputs
                .execution_route(&control_only, 2)
                .expect("completed routing read"),
            None
        );
        assert_eq!(
            inputs
                .execution_route(&mixed, 2)
                .expect("completed routing read"),
            None
        );
        let no_catalog = DataSpaceCatalog::default();
        assert_eq!(
            RoutingInputs {
                dataspaces: &no_catalog,
                ..inputs
            }
            .execution_route(&upload, 2)
            .expect("completed routing read"),
            None
        );
    }

    #[test]
    fn original_root_json_owner_survives_queue_vm_adapters_and_same_source_retry() {
        use crate::execution_attempt::ExecutionDeferred;
        use iroha_data_model::parameter::Parameter;
        let world = test_support::world(SumeragiRootScope::Global);
        let view = world.view();
        let original_parameter = view
            .parameters()
            .custom()
            .get(&consensus_metadata::handshake_meta_id())
            .unwrap()
            .clone();
        assert_eq!(
            read_routing_root_scope(&view).unwrap(),
            Some(SumeragiRootScope::Global)
        );
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let original = norito::with_decode_limits_scope(limits, || read_routing_root_scope(&view))
            .unwrap_err();
        let observed = original
            .decode_refusal()
            .expect("actual original root parser scope")
            .clone();
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(original.allocation_refusal().is_none());
        assert!(original.verification_refusal().is_none());
        assert!(matches!(observed.resource_error(),
            norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
            if attempted > 0));
        let independent =
            norito::with_decode_limits_scope(limits, || read_routing_root_scope(&view))
                .unwrap_err();
        let independent_cause = independent
            .decode_refusal()
            .expect("independent actual parser scope");
        assert_eq!(independent_cause.kind(), observed.kind());
        assert_eq!(
            independent_cause.resource_error(),
            observed.resource_error()
        );
        assert_ne!(
            independent_cause, &observed,
            "separate reads do not share observer identity"
        );
        let crate::queue::Error::Deferred(queued) =
            crate::queue::Error::from(crate::queue::RoutingResolveError::Deferred(original))
        else {
            panic!("unfinished original root read became a terminal queue rejection");
        };
        assert_eq!(queued.decode_refusal(), Some(&observed));
        let moved = ExecutionDeferred::try_from_vm_error(queued.into_vm_error()).unwrap();
        assert_eq!(moved.decode_refusal(), Some(&observed));
        assert_eq!(
            read_routing_root_scope(&view).unwrap(),
            Some(SumeragiRootScope::Global)
        );
        assert_eq!(
            view.parameters().custom().get(original_parameter.id()),
            Some(&original_parameter)
        );
        drop(view);
        // A protocol-version mismatch is a completed absent root, even when JSON is valid.
        let Parameter::Custom(parameter) = test_support::metadata(SumeragiRootScope::Global) else {
            unreachable!();
        };
        let mut metadata: ConsensusHandshakeMetadata =
            norito::json::from_str(parameter.payload().get()).unwrap();
        metadata.wire_protocol_version =
            u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION) + 1;
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    consensus_metadata::handshake_meta_id(),
                    iroha_primitives::json::Json::new(metadata),
                ),
            ))
            .unwrap();
        parameters.commit();
        assert_eq!(read_routing_root_scope(&world.view()).unwrap(), None);
    }

    #[test]
    fn lane_policy_original_scope_and_completed_absence_keep_distinct_outcomes() {
        use crate::execution_attempt::ExecutionDeferred;
        use iroha_data_model::parameter::{CustomParameter, Parameter};
        let world = World::new();
        assert!(
            crate::sumeragi::lanes::lane_policy(&world.view())
                .unwrap()
                .is_none()
        );
        let policy = SumeragiLanePolicy::for_chain(
            SumeragiParameters::default(),
            iroha_sumeragi::availability::recommended_data_availability_layout(),
        );
        policy.validate().unwrap();
        let original_parameter = policy.clone().into_custom_parameter();
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(Parameter::Custom(original_parameter.clone()))
            .unwrap();
        parameters.commit();
        let view = world.view();
        assert_eq!(
            crate::sumeragi::lanes::lane_policy(&view).unwrap(),
            Some(policy.clone())
        );
        let original = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
            || crate::sumeragi::lanes::lane_policy(&view),
        )
        .unwrap_err();
        let observed = original
            .decode_refusal()
            .expect("actual lane policy parser scope")
            .clone();
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(original.allocation_refusal().is_none());
        assert!(original.verification_refusal().is_none());
        let moved = ExecutionDeferred::try_from_vm_error(original.into_vm_error()).unwrap();
        assert_eq!(moved.decode_refusal(), Some(&observed));
        assert_eq!(
            crate::sumeragi::lanes::lane_policy(&view).unwrap(),
            Some(policy.clone())
        );
        assert_eq!(
            view.parameters().custom().get(original_parameter.id()),
            Some(&original_parameter)
        );
        drop(view);
        let mut invalid = policy;
        invalid.anchor_freshness = 0;
        assert!(invalid.validate().is_err());
        for parameter in [
            CustomParameter::new(
                SumeragiLanePolicy::parameter_id(),
                iroha_primitives::json::Json::new(()),
            ),
            invalid.into_custom_parameter(),
        ] {
            let mut parameters = world.parameters.block();
            parameters
                .set_parameter(Parameter::Custom(parameter.clone()))
                .unwrap();
            parameters.commit();
            let view = world.view();
            assert!(
                crate::sumeragi::lanes::lane_policy(&view)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                view.parameters().custom().get(parameter.id()),
                Some(&parameter)
            );
        }
    }
}
