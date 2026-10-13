//! Physical policy routing, distinct from native Sumeragi ordering lanes.

use super::*;

/// A resolved physical policy lane; native ordering identifiers cannot construct it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalExecutionPolicyRoute(RoutingDecision);

/// Fixed-size retained refusal. Resolver-owned diagnostic strings never enter source rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhysicalPolicyRouteRejection {
    /// Stable resolver classification; every label is a static closed-set value.
    Routing(&'static str),
    /// The current executor admits exactly one physical route.
    MultipleRoutes,
    /// An authenticated native source cannot change physical dataspace authority.
    DataspaceMismatch,
}

impl std::fmt::Display for PhysicalPolicyRouteRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Routing(label) => write!(f, "physical policy routing failed: {label}"),
            Self::MultipleRoutes => f.write_str("physical policy requires one executable route"),
            Self::DataspaceMismatch => {
                f.write_str("physical policy dataspace differs from authenticated native source")
            }
        }
    }
}

/// Both ingress and execution require activity at the committed and proposal heights.
pub(super) fn resolve_plan_for_admission(
    plan: RoutingPlan,
    nexus: &Nexus,
    committed_height: u64,
) -> Result<RoutingPlan, RoutingResolveError> {
    let plan = super::resolve_routing_plan_against_nexus_at_height(plan, nexus, committed_height)?;
    let Some(next_height) = committed_height.checked_add(1) else {
        let route = plan.coordinator_route();
        return Err(RoutingResolveError::InactiveLane {
            lane_id: route.lane_id,
            dataspace_id: route.dataspace_id,
        });
    };
    super::ensure_routing_plan_active_at_height(&plan, nexus, next_height)?;
    Ok(plan)
}

impl PhysicalExecutionPolicyRoute {
    pub(crate) fn decision(self) -> RoutingDecision {
        self.0
    }

    pub(crate) fn require_dataspace(
        self,
        native: RoutingDecision,
    ) -> Result<Self, PhysicalPolicyRouteRejection> {
        if self.0.dataspace_id != native.dataspace_id {
            return Err(PhysicalPolicyRouteRejection::DataspaceMismatch.into());
        }
        Ok(self)
    }

    pub(crate) fn resolve<W: WorldReadOnly>(
        nexus: &Nexus,
        world: &W,
        tx: &dyn TransactionRoutingView,
        committed_height: u64,
        ledger_time_ms: u64,
    ) -> Result<Self, crate::execution_attempt::ExecutionAttemptError<PhysicalPolicyRouteRejection>>
    {
        let plan = evaluate_policy_plan_with_nexus_and_world_at_block_height(
            nexus,
            tx,
            world,
            ledger_time_ms,
            committed_height,
        )
        .and_then(|plan| resolve_plan_for_admission(plan, nexus, committed_height))
        .map_err(|error| match error {
            RoutingResolveError::Deferred(reason) => {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
            }
            error => PhysicalPolicyRouteRejection::Routing(error.as_label()).into(),
        })?;
        Self::single(plan).map_err(Into::into)
    }

    /// Genesis retains bootstrap routing against its authenticated in-progress World.
    /// This constructor is used only by the opaque genesis source capability.
    pub(crate) fn genesis<W: WorldReadOnly>(
        nexus: &Nexus,
        world: &W,
        tx: &dyn TransactionRoutingView,
        ledger_time_ms: u64,
        scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Result<Self, crate::execution_attempt::ExecutionAttemptError<PhysicalPolicyRouteRejection>>
    {
        if let iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
            dataspace_id,
            ..
        } = scope
        {
            let Some(iroha_data_model::transaction::Executable::Instructions(instructions)) =
                tx.executable()
            else {
                return Err(PhysicalPolicyRouteRejection::Routing(
                    "private_genesis_requires_instructions",
                )
                .into());
            };
            for instruction in instructions {
                let target = private_genesis_instruction_target(
                    &**instruction,
                    &nexus.dataspace_catalog,
                    world,
                    ledger_time_ms,
                )
                .map_err(|error| match error {
                    RoutingResolveError::Deferred(reason) => {
                        crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
                    }
                    error => PhysicalPolicyRouteRejection::Routing(error.as_label()).into(),
                })?;
                if target.global
                    || target
                        .dataspace
                        .is_some_and(|target| target != dataspace_id)
                {
                    return Err(PhysicalPolicyRouteRejection::DataspaceMismatch.into());
                }
            }
            let route = super::resolve_routing_decision(
                RoutingDecision::new(nexus.routing_policy.default_lane, dataspace_id),
                &nexus.lane_catalog,
                &nexus.dataspace_catalog,
            )
            .map_err(|error| PhysicalPolicyRouteRejection::Routing(error.as_label()))?;
            return Ok(Self(route));
        }
        Self::single(
            evaluate_policy_plan_with_nexus_and_world_at_block_height(
                nexus,
                tx,
                world,
                ledger_time_ms,
                1,
            )
            .map_err(|error| match error {
                RoutingResolveError::Deferred(reason) => {
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
                }
                error => PhysicalPolicyRouteRejection::Routing(error.as_label()).into(),
            })?,
        )
        .map_err(Into::into)
    }

    fn single(plan: RoutingPlan) -> Result<Self, PhysicalPolicyRouteRejection> {
        let RoutingPlan::Single(leg) = plan else {
            return Err(PhysicalPolicyRouteRejection::MultipleRoutes);
        };
        Ok(Self(leg.route))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::nexus::{
        AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_MANAGED, LaneConfig,
    };
    use nonzero_ext::nonzero;

    #[test]
    fn private_genesis_alias_projection_is_exact_while_ordinary_registry_stays_global() {
        use iroha_data_model::{
            NetworkId,
            alias_setup::{
                AliasDataSpaceIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1, AliasQuoteGuardV1,
                ResolvedDataSpaceV1,
            },
            block::consensus::SumeragiRootScope,
            isi::{Log, alias_setup::EnsureAlias},
            nexus::{DataSpaceCatalog, DataSpaceMetadata},
            transaction::{FeePaymentIntent, TransactionBuilder},
        };
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        let ds = DataSpaceId::new(u64::MAX - 23);
        let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"parent"),
        ));
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: network,
            dataspace_id: ds,
        };
        let mut nexus = Nexus::default();
        nexus.lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                dataspace_id: ds,
                ..LaneConfig::default()
            }],
        )
        .unwrap();
        nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: ds,
            alias: "private".into(),
            description: None,
            fault_tolerance: 1,
        }])
        .unwrap();
        nexus.routing_policy.default_dataspace = ds;
        let world = crate::state::World::new();
        for target in [ds, DataSpaceId::UNIVERSAL, DataSpaceId::new(23)] {
            let instruction = EnsureAlias::new(
                AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                    dataspace: ResolvedDataSpaceV1::new("private".parse().unwrap(), target),
                    owner: ALICE_ID.clone(),
                }),
                AliasLeaseAcquisitionV1::new(1, None),
                AliasQuoteGuardV1 {
                    expected_policy_version: 1,
                    expected_payment_asset:
                        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                            .parse()
                            .unwrap(),
                    max_amount: 1_u32.into(),
                    valid_until_ms: u64::MAX,
                },
            );
            let signed = TransactionBuilder::new(
                network,
                ALICE_ID.clone(),
                FeePaymentIntent::authority(vec![], None),
            )
            .with_instructions(vec![
                iroha_data_model::isi::InstructionBox::from(Log::new(
                    iroha_logger::Level::INFO,
                    "bootstrap".into(),
                )),
                instruction.into(),
            ])
            .sign(ALICE_KEYPAIR.private_key());
            let accepted =
                crate::tx::AcceptedTransaction::new_unchecked(std::borrow::Cow::Owned(signed));
            assert!(
                PhysicalExecutionPolicyRoute::resolve(&nexus, &world.view(), &accepted, 1, 0)
                    .is_err(),
                "ordinary alias acquisition must retain parent-registry routing"
            );
            let bootstrap =
                PhysicalExecutionPolicyRoute::genesis(&nexus, &world.view(), &accepted, 0, scope);
            if target == ds {
                assert_eq!(bootstrap.unwrap().decision().dataspace_id, ds);
            } else {
                assert!(matches!(
                    bootstrap,
                    Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                        PhysicalPolicyRouteRejection::DataspaceMismatch
                    ))
                ));
            }
        }
    }

    #[test]
    fn queue_and_execution_share_both_height_guards_and_checked_successor() {
        let mut lane = LaneConfig {
            id: LaneId::new(1),
            alias: "elastic-lane-1".into(),
            ..Default::default()
        };
        lane.metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "true".into());
        lane.metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.into(), "3".into());
        crate::state::attach_synthetic_autoscale_committee_for_test(&mut lane);
        let mut nexus = Nexus::default();
        nexus.autoscale.enabled = true;
        nexus.autoscale.min_lane_id = nonzero!(1_u32);
        nexus.autoscale.max_lane_id_exclusive = nonzero!(4_u32);
        nexus.lane_catalog =
            LaneCatalog::new(nonzero!(2_u32), vec![LaneConfig::default(), lane]).unwrap();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        let plan =
            RoutingPlan::single(RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL));
        assert!(
            super::super::resolve_routing_plan_for_queue_admission(plan.clone(), &nexus, 2)
                .is_err()
        );
        assert!(resolve_plan_for_admission(plan.clone(), &nexus, 2).is_err());
        assert_eq!(
            resolve_plan_for_admission(plan.clone(), &nexus, 3).unwrap(),
            plan
        );
        assert_eq!(
            super::super::resolve_routing_plan_for_queue_admission(plan.clone(), &nexus, 3)
                .unwrap(),
            plan
        );
        assert!(resolve_plan_for_admission(plan, &nexus, u64::MAX).is_err());
    }

    #[test]
    fn physical_identity_requires_equal_dataspace_but_never_equal_lane_number() {
        let route =
            PhysicalExecutionPolicyRoute::single(RoutingPlan::single(RoutingDecision::default()))
                .unwrap();
        assert_eq!(
            route
                .require_dataspace(RoutingDecision::new(
                    LaneId::new(99),
                    DataSpaceId::UNIVERSAL
                ))
                .unwrap(),
            route
        );
        assert_eq!(
            route.require_dataspace(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::new(1))),
            Err(PhysicalPolicyRouteRejection::DataspaceMismatch.into())
        );
    }
}
