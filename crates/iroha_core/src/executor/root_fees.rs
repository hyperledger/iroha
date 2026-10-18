//! One committed root fee policy; execution consumes only its captured predecessor projection.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use iroha_data_model::block::consensus::{RootFeePolicy, SumeragiRootScope};

fn invalid(reason: impl Into<String>) -> NexusFeeAdmissionError {
    NexusFeeAdmissionError::ConfigInvalid(reason.into())
}

fn scope(
    world: &impl WorldReadOnly,
) -> Result<SumeragiRootScope, ExecutionAttemptError<NexusFeeAdmissionError>> {
    crate::sumeragi::lanes::routing::read_routing_root_scope(world)
        .map_err(ExecutionAttemptError::Deferred)?
        .ok_or_else(|| invalid("fee admission requires immutable root scope").into())
}

/// Validate the captured predecessor policy without reading a later parameter value.
/// Presence is mandatory; the only unconfigured context is H1, whose caller skips fees.
pub(super) fn effective(
    world: &impl WorldReadOnly,
    captured: &RootFeePolicy,
) -> Result<RootFeePolicy, ExecutionAttemptError<NexusFeeAdmissionError>> {
    if world.parameters().root_fees().is_none() {
        return Err(invalid("committed root fee policy is absent").into());
    }
    let scope = scope(world)?;
    captured
        .validate_for_scope(&scope)
        .map_err(|error| invalid(format!("invalid committed root fee policy: {error}")))?;
    if let SumeragiRootScope::Dataspace { dataspace_id, .. } = scope {
        let definition = world
            .asset_definition(&captured.fee_asset_id)
            .map_err(|_| invalid("private fee asset is not registered"))?;
        let domain = definition
            .owning_domain
            .as_ref()
            .ok_or_else(|| invalid("private fee asset requires an owning domain"))?;
        if definition.balance_scope_policy() != AssetBalancePolicy::DataspaceRestricted
            || world
                .dataspace_catalog()
                .by_alias(domain.dataspace().as_ref())
                .map(|entry| entry.id)
                != Some(dataspace_id)
            || world.domain(domain).is_err()
        {
            return Err(invalid(
                "private fee asset must belong to the exact signed root dataspace",
            )
            .into());
        }
    }
    Ok(captured.clone())
}

/// Public quoting is evaluated against the supplied committed World. A caller-supplied
/// Nexus value cannot supply monetary policy; the usual captured view takes no clone.
pub(super) fn quote_nexus<'a>(
    world: &impl WorldReadOnly,
    nexus: &'a iroha_config::parameters::actual::Nexus,
) -> Result<
    std::borrow::Cow<'a, iroha_config::parameters::actual::Nexus>,
    ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    let policy = world
        .parameters()
        .root_fees()
        .ok_or_else(|| invalid("committed root fee policy is absent"))?;
    let policy = effective(world, policy)?;
    if policy == nexus.fees {
        Ok(std::borrow::Cow::Borrowed(nexus))
    } else {
        let mut projected = nexus.clone();
        projected.fees = policy;
        Ok(std::borrow::Cow::Owned(projected))
    }
}

pub(super) fn currency(
    world: &impl WorldReadOnly,
    fees: &RootFeePolicy,
    observation_time_ms: u64,
) -> Result<AssetDefinitionId, ExecutionAttemptError<NexusFeeAdmissionError>> {
    if matches!(scope(world)?, SumeragiRootScope::Dataspace { .. }) {
        return Ok(fees.fee_asset_id.clone());
    }
    crate::block::resolve_network_xor_asset_definition(
        world,
        &fees.fee_asset_id.canonical_address(),
        observation_time_ms,
    )
    .map_err(ExecutionAttemptError::Deferred)?
    .ok_or_else(|| {
        invalid("invalid Nexus fee asset; expected the committed global XOR identity").into()
    })
}

pub(super) fn private_scope(
    world: &impl WorldReadOnly,
    route: Option<DataSpaceId>,
) -> Result<Option<DataSpaceId>, ExecutionAttemptError<NexusFeeAdmissionError>> {
    let SumeragiRootScope::Dataspace { dataspace_id, .. } = scope(world)? else {
        return Ok(None);
    };
    if route != Some(dataspace_id) {
        return Err(invalid("private fee debit requires the exact captured root dataspace").into());
    }
    Ok(Some(dataspace_id))
}

pub(super) fn permits_public_exemption(
    world: &impl WorldReadOnly,
) -> Result<bool, crate::execution_attempt::ExecutionDeferred> {
    Ok(
        crate::sumeragi::lanes::routing::read_routing_root_scope(world)?
            == Some(SumeragiRootScope::Global),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{Asset, AssetDefinition},
        block::BlockHeader,
        domain::Domain,
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        parameter::{CustomParameter, Parameter},
        transaction::TransactionBuilder,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};

    fn fixture(with_policy: bool, restricted: bool) -> (State, DataSpaceId, AssetDefinitionId) {
        let ds = DataSpaceId::new(u64::MAX - 19);
        let domain = DomainId::parse_fully_qualified("app.privatefees").unwrap();
        let asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "gas".parse().unwrap());
        let mut definition = AssetDefinition::numeric(
            asset.clone(),
            "Private gas",
            if restricted {
                AssetBalancePolicy::DataspaceRestricted
            } else {
                AssetBalancePolicy::Global
            },
            Some(domain.clone()),
        )
        .build(&ALICE_ID);
        definition.total_quantity = Quantity::from(1000_u32);
        let world = World::with_assets(
            [Domain::new(domain).build(&ALICE_ID)],
            [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
            [definition],
            [Asset::new(
                AssetId::with_scope(
                    asset.clone(),
                    ALICE_ID.clone(),
                    if restricted {
                        AssetBalanceScope::Dataspace(ds)
                    } else {
                        AssetBalanceScope::Global
                    },
                ),
                Quantity::from(1000_u32),
            )],
            [],
        );
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"fee parent")),
            ),
            dataspace_id: ds,
        };
        let mut parameters = world.parameters.block();
        parameters
            .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                scope,
            ))
            .expect("valid fixture parameters");
        if with_policy {
            parameters
                .set_parameter(Parameter::Custom(
                    RootFeePolicy {
                        fee_asset_id: asset.clone(),
                        base_fee: 2_u32.into(),
                        per_byte_fee: Quantity::zero(),
                        per_instruction_fee: 3_u32.into(),
                        per_gas_unit_fee: 4_u32.into(),
                        ..iroha_config::parameters::defaults::nexus::fees::genesis_policy()
                    }
                    .into_custom_parameter()
                    .unwrap(),
                ))
                .expect("valid fixture parameters");
        }
        parameters.commit();
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            id: ds,
            alias: "privatefees".into(),
            description: None,
            fault_tolerance: 1,
        }])
        .unwrap();
        nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
        nexus.lane_catalog = LaneCatalog::new(
            std::num::NonZeroU32::new(1).unwrap(),
            vec![LaneConfig {
                dataspace_id: ds,
                visibility: LaneVisibility::Restricted,
                ..LaneConfig::default()
            }],
        )
        .unwrap();
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.routing_policy.default_dataspace = ds;
        nexus.fees.fee_asset_id = asset.clone();
        let state = State::new_with_nexus_for_testing(world, nexus, LiveQueryStore::start_test());
        if !with_policy {
            let mut parameters = state.world.parameters.block();
            parameters.remove_custom_parameter(&RootFeePolicy::parameter_id());
            parameters.commit();
        }
        (state, ds, asset)
    }

    #[test]
    fn private_fee_policy_is_frozen_before_transaction_parameter_writes() {
        let (state, _, asset) = fixture(true, true);
        let mut block = state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
        let mut tx = block.transaction();
        let before = tx.nexus.fees.clone();
        let frozen_gas = tx.pipeline.gas.clone();
        let mut next = before.clone();
        next.base_fee = 7_u32.into();
        next.per_gas_unit_fee = 9_u32.into();
        tx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(
                next.clone().into_custom_parameter().unwrap(),
            ))
            .unwrap();
        Executor::validate_root_fee_policy(&mut tx).unwrap();
        assert_eq!(tx.world.parameters().root_fees(), Some(&next));
        assert_eq!(tx.nexus.fees, before);
        assert_eq!(tx.nexus.fees.fee_asset_id, asset);
        assert_eq!(tx.pipeline.gas, frozen_gas);
        let original_parameters = tx.world.parameters().clone();
        assert!(
            tx.world
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    RootFeePolicy::parameter_id(),
                    iroha_primitives::json::Json::new("malformed policy"),
                )))
                .is_err()
        );
        assert_eq!(tx.world.parameters(), &original_parameters);
        assert_eq!(tx.nexus.fees, before);
        assert_eq!(tx.pipeline.gas, frozen_gas);
    }

    #[test]
    fn committed_private_schedule_ignores_local_zero_rates_and_quotes_exact_scoped_asset() {
        let (state, ds, asset) = fixture(true, true);
        let view = state.view();
        let mut nexus = view.nexus().clone();
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus.fees.fee_asset_id =
            iroha_config::parameters::defaults::nexus::fees::genesis_policy().fee_asset_id;
        let transaction = TransactionBuilder::new(
            *view.network_id(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], None),
        )
        .with_instructions([iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "private paid work".into(),
        )])
        .sign(ALICE_KEYPAIR.private_key());
        let quote = quote_nexus_fee_admission_draft(
            view.world(),
            &nexus,
            &Pipeline::default(),
            &crate::gas::DEFAULT_ZK_GAS,
            transaction.payload(),
            0,
            crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                .expect("original committed fixture time"),
            2,
            Some(ds),
        )
        .unwrap();
        assert_eq!(quote.quote.charges.len(), 1);
        assert_eq!(quote.quote.charges[0].asset_definition_id, asset);
        assert!(!quote.quote.charges[0].max_bound.is_zero());
        assert_eq!(
            quote.quote.authority_charge_assets[&FeeChargeKind::Nexus].scope,
            AssetBalanceScope::Dataspace(ds)
        );
        assert!(private_scope(view.world(), None).is_err());
        assert!(private_scope(view.world(), Some(DataSpaceId::UNIVERSAL)).is_err());
        assert!(!permits_public_exemption(view.world()).unwrap());
    }

    #[test]
    fn private_fee_readers_preserve_local_scope_decode_refusal_and_retry() {
        let (state, ds, asset) = fixture(true, true);
        let view = state.view();
        let original = effective(view.world(), &view.nexus().fees).unwrap();
        for reader in 0..4 {
            let refused = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || {
                    match reader {
                        0 => quote_nexus(view.world(), view.nexus()).map(|_| ()),
                        1 => effective(view.world(), &view.nexus().fees).map(|_| ()),
                        2 => currency(view.world(), &view.nexus().fees, 0).map(|_| ()),
                        _ => private_scope(view.world(), Some(ds)).map(|_| ()),
                    }
                    .unwrap_err()
                },
            );
            assert!(
                matches!(refused, ExecutionAttemptError::Deferred(_)),
                "reader {reader}: {refused:?}"
            );
        }
        assert_eq!(
            effective(view.world(), &view.nexus().fees).unwrap(),
            original
        );
        assert_eq!(
            currency(view.world(), &view.nexus().fees, 0).unwrap(),
            asset
        );
        assert_eq!(private_scope(view.world(), Some(ds)).unwrap(), Some(ds));
        assert!(!permits_public_exemption(view.world()).unwrap());
    }

    fn original_fee_decode_context(
        pool: &iroha_allocation::AllocationBudget,
        bytes: usize,
    ) -> norito::core::DecodeBudgetContext {
        norito::core::DecodeBudgetContext::try_new_owned(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 128),
            pool,
        )
        .expect("actual State pool funds the original decode counter")
    }

    fn original_private_root_demand(
        world: &impl WorldReadOnly,
        pool: &iroha_allocation::AllocationBudget,
    ) -> usize {
        let calibration = original_fee_decode_context(pool, usize::MAX);
        assert!(matches!(
            calibration
                .with(|| crate::sumeragi::lanes::routing::read_routing_root_scope(world))
                .unwrap(),
            Some(SumeragiRootScope::Dataspace { .. })
        ));
        let bytes = usize::try_from(calibration.consumed_allocated_bytes()).unwrap();
        assert!(
            bytes > 0,
            "the real root prelude must be measured before policy refusal"
        );
        bytes
    }

    #[test]
    fn committed_policy_projection_preserves_original_decode_refusal_and_retry() {
        let (state, _, _) = fixture(true, true);
        let view = state.view();
        let pool = state.ivm_execution_budget();
        let parameter = view
            .world()
            .parameters()
            .custom()
            .get(&RootFeePolicy::parameter_id())
            .unwrap()
            .clone();
        let original = view.world().parameters().clone();
        for restore in [false, true] {
            let baseline = pool.reserved_bytes();
            let context = original_fee_decode_context(&pool, 0);
            let funded = pool.reserved_bytes();
            assert!(funded > baseline);
            let mut owner = original.clone();
            let error = context
                .with(|| {
                    if restore {
                        crate::pipeline_gas_policy::StateParameters::try_from(
                            (**view.world().parameters()).clone(),
                        )
                        .map(|_| ())
                    } else {
                        owner.set_parameter(Parameter::Custom(parameter.clone()))
                    }
                })
                .unwrap_err();
            assert_eq!(
                owner, original,
                "refused source and cached projection remain atomic"
            );
            let refused = crate::execution_attempt::norito_decode_attempt_error(error, |_| ());
            let ExecutionAttemptError::Deferred(owner) = refused else {
                panic!("actual policy producer must retain decoder cause: {refused:?}");
            };
            let original_cause = owner
                .decode_refusal()
                .expect("original policy parser owner")
                .clone();
            assert_eq!(
                original_cause.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert!(
                matches!(original_cause.resource_error(), norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit } if attempted > limit && limit == 0)
            );
            assert!(owner.allocation_refusal().is_none());
            assert!(owner.allocator_refusal().is_none());
            drop(context);
            assert_eq!(
                pool.reserved_bytes(),
                funded,
                "the exported cause keeps its original counter funded"
            );
            let mut exported = None;
            let allocations = crate::test_allocations::allocations_during(|| {
                exported = Some(owner.into_vm_error())
            });
            assert_eq!(allocations, 0);
            let ivm::VMError::DecodeDeferred(exported) = exported.unwrap() else {
                panic!("preserve actual decoder owner");
            };
            assert_eq!(exported, original_cause);
            let mut retry = original.clone();
            retry
                .set_parameter(Parameter::Custom(parameter.clone()))
                .unwrap();
            assert_eq!(retry, original);
            assert_eq!(
                crate::pipeline_gas_policy::StateParameters::try_from(
                    (**view.world().parameters()).clone()
                )
                .unwrap(),
                original
            );
            drop((exported, original_cause));
            assert_eq!(pool.reserved_bytes(), baseline);
        }
    }

    #[test]
    fn private_fee_validation_retains_original_scope_refusal_before_changing_fees_or_gas() {
        let (state, ds, asset) = fixture(true, true);
        let pool = state.ivm_execution_budget();
        let view = state.view();
        let root_bytes = original_private_root_demand(view.world(), &pool) - 1;
        let id = RootFeePolicy::parameter_id();
        let source = view
            .world()
            .parameters()
            .custom()
            .get(&id)
            .unwrap()
            .payload()
            .get()
            .to_owned();
        drop(view);
        {
            let mut block =
                state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
            let mut tx = block.transaction();
            let before = tx.nexus.fees.clone();
            let gas = tx.pipeline.gas.clone();
            let context = original_fee_decode_context(&pool, root_bytes);
            assert!(
                context
                    .with(|| Executor::validate_root_fee_policy(&mut tx))
                    .is_err()
            );
            assert!(context.consumed_allocated_bytes() <= u64::try_from(root_bytes).unwrap());
            let original = tx
                .borrow_execution_deferral()
                .expect("live State bridge keeps original")
                .decode_refusal()
                .expect("actual policy scope")
                .clone();
            assert!(
                matches!(original.resource_error(), norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit } if attempted > limit && limit == u64::try_from(root_bytes).unwrap())
            );
            drop(context);
            let moved = tx.ensure_execution_ready().unwrap_err();
            assert_eq!(moved.decode_refusal(), Some(&original));
            assert!(tx.is_execution_deferred());
            assert!(tx.borrow_execution_deferral().is_none());
            assert_eq!(tx.nexus.fees.fee_asset_id, before.fee_asset_id);
            assert_eq!(
                tx.nexus.fees.fee_sink_account_id,
                before.fee_sink_account_id
            );
            assert_eq!(tx.nexus.fees.base_fee, before.base_fee);
            assert_eq!(tx.nexus.fees.per_byte_fee, before.per_byte_fee);
            assert_eq!(
                tx.nexus.fees.per_instruction_fee,
                before.per_instruction_fee
            );
            assert_eq!(tx.nexus.fees.per_gas_unit_fee, before.per_gas_unit_fee);
            assert_eq!(
                tx.nexus.fees.sponsor_vault_custody_account_id,
                before.sponsor_vault_custody_account_id
            );
            assert_eq!(
                tx.nexus.fees.successful_claim_fee_exempt_authorities,
                before.successful_claim_fee_exempt_authorities
            );
            assert_eq!(tx.pipeline.gas, gas);
            let scoped = AssetId::with_scope(
                asset.clone(),
                ALICE_ID.clone(),
                AssetBalanceScope::Dataspace(ds),
            );
            assert_eq!(
                tx.world.assets().get(&scoped).unwrap().as_ref(),
                &Quantity::from(1000_u32)
            );
            assert_eq!(
                tx.world.asset_definition(&asset).unwrap().total_quantity(),
                &Quantity::from(1000_u32)
            );
            assert_eq!(
                tx.world
                    .parameters()
                    .custom()
                    .get(&id)
                    .unwrap()
                    .payload()
                    .get(),
                &source
            );
        }
        // Retry the identical immutable source in a fresh transaction: refused State is sticky.
        let mut block = state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
        let mut retry = block.transaction();
        let gas = retry.pipeline.gas.clone();
        Executor::validate_root_fee_policy(&mut retry).unwrap();
        assert!(!retry.is_execution_deferred());
        assert_eq!(retry.nexus.fees.base_fee, Quantity::from(2_u32));
        assert_eq!(retry.nexus.fees.per_gas_unit_fee, Quantity::from(4_u32));
        assert_eq!(retry.pipeline.gas, gas);
        assert_eq!(
            retry
                .world
                .parameters()
                .custom()
                .get(&id)
                .unwrap()
                .payload()
                .get(),
            &source
        );
    }

    #[test]
    fn private_fee_burn_debits_local_balance_and_supply_with_signed_limits() {
        let (state, ds, asset) = fixture(true, true);
        let transaction = TransactionBuilder::new(
            *state.view().network_id(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset.clone(),
                    Quantity::from(9_u32),
                )],
                None,
            ),
        )
        .with_instructions([iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "charge".into(),
        )])
        .sign(ALICE_KEYPAIR.private_key());
        let mut block = state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
        let mut tx = block.transaction();
        tx.current_dataspace_id = Some(ds);
        tx.world.current_dataspace_id = Some(ds);
        // Supply the exact signed owner captured by Network execution before fee settlement.
        tx.current_entrypoint_index = Some(0);
        tx.current_network_entrypoint_hash = Some(transaction.hash_as_entrypoint());
        tx.current_tx_hash = Some(transaction.hash());
        tx.tx_call_hash = Some(Hash::from(transaction.hash_as_entrypoint()));
        tx.current_lane_id = Some(iroha_model_base::topology::LaneId::SINGLE);
        let tx_bytes_len = norito::canonical_frame_len(transaction.payload()).unwrap();
        Executor::charge_nexus_fees(&mut tx, &ALICE_ID, &transaction, None, tx_bytes_len, 1, 1)
            .unwrap();
        let scoped = AssetId::with_scope(
            asset.clone(),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(ds),
        );
        assert_eq!(
            tx.world.assets().get(&scoped).unwrap().as_ref(),
            &Quantity::from(991_u32)
        );
        assert_eq!(
            tx.world.asset_definition(&asset).unwrap().total_quantity(),
            &Quantity::from(991_u32)
        );
        assert!(
            tx.world
                .assets()
                .get(&AssetId::new(asset, ALICE_ID.clone()))
                .is_none()
        );
        assert_eq!(tx.current_dataspace_id, Some(ds));
        assert_eq!(tx.world.current_dataspace_id, Some(ds));
    }

    #[test]
    fn private_fee_limits_and_funding_reject_before_any_balance_or_supply_change() {
        for (limit, gas) in [(8_u32, 1_u64), (2000, 300)] {
            let (state, ds, asset) = fixture(true, true);
            let signed = TransactionBuilder::new(
                *state.view().network_id(),
                ALICE_ID.clone(),
                FeePaymentIntent::authority(
                    vec![FeeChargeLimit::new(
                        FeeChargeKind::Nexus,
                        asset.clone(),
                        limit.into(),
                    )],
                    None,
                ),
            )
            .with_instructions([iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                "bounded paid work".into(),
            )])
            .sign(ALICE_KEYPAIR.private_key());
            let mut block =
                state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
            let mut tx = block.transaction();
            tx.current_dataspace_id = Some(ds);
            tx.world.current_dataspace_id = Some(ds);
            tx.current_entrypoint_index = Some(0);
            tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
            tx.current_tx_hash = Some(signed.hash());
            tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
            tx.current_lane_id = Some(iroha_model_base::topology::LaneId::SINGLE);
            let tx_bytes_len = norito::canonical_frame_len(signed.payload()).unwrap();
            assert!(
                Executor::charge_nexus_fees(
                    &mut tx,
                    &ALICE_ID,
                    &signed,
                    None,
                    tx_bytes_len,
                    1,
                    gas
                )
                .is_err()
            );
            let scoped = AssetId::with_scope(
                asset.clone(),
                ALICE_ID.clone(),
                AssetBalanceScope::Dataspace(ds),
            );
            assert_eq!(
                tx.world.assets().get(&scoped).unwrap().as_ref(),
                &Quantity::from(1000_u32)
            );
            assert_eq!(
                tx.world.asset_definition(&asset).unwrap().total_quantity(),
                &Quantity::from(1000_u32)
            );
            assert_eq!(tx.current_dataspace_id, Some(ds));
            assert_eq!(tx.world.current_dataspace_id, Some(ds));
        }
    }

    #[test]
    fn private_fee_sponsor_cannot_select_an_unscoped_public_vault() {
        let (state, ds, _) = fixture(true, true);
        let view = state.view();
        let transaction = TransactionBuilder::new(
            *view.network_id(),
            ALICE_ID.clone(),
            FeePaymentIntent::sponsor(
                FeeSponsorProgramId::new(ALICE_ID.clone(), "public_vault".parse().unwrap()),
                1,
                vec![],
                None,
            ),
        )
        .with_instructions([iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "sponsored work".into(),
        )])
        .sign(ALICE_KEYPAIR.private_key());
        let error = quote_nexus_fee_admission_draft(
            view.world(),
            view.nexus(),
            &Pipeline::default(),
            &crate::gas::DEFAULT_ZK_GAS,
            transaction.payload(),
            0,
            crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                .expect("original committed fixture time"),
            2,
            Some(ds),
        )
        .unwrap_err();
        assert_eq!(
            crate::execution_attempt::expect_completed_rejection(error),
            NexusFeeAdmissionError::ConfigInvalid(
                "private-root fee sponsors require a scoped vault owner".into()
            )
        );
    }

    #[test]
    fn private_policy_refuses_missing_malformed_global_assets_and_unbound_roots() {
        let (missing, _, _) = fixture(false, true);
        let missing_view = missing.view();
        assert!(effective(missing_view.world(), &missing_view.nexus().fees).is_err());
        let (global_asset, _, _) = fixture(true, false);
        let global_view = global_asset.view();
        assert!(effective(global_view.world(), &global_view.nexus().fees).is_err());
        assert!(
            effective(
                &World::new().view(),
                &iroha_config::parameters::defaults::nexus::fees::genesis_policy()
            )
            .is_err()
        );
        let (state, _, _) = fixture(true, true);
        let mut block = state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
        let mut tx = block.transaction();
        let original = tx.world.parameters().clone();
        assert!(
            tx.world
                .parameters
                .get_mut()
                .set_parameter(Parameter::Custom(CustomParameter::new(
                    RootFeePolicy::parameter_id(),
                    iroha_primitives::json::Json::new(false),
                )))
                .is_err()
        );
        assert_eq!(tx.world.parameters(), &original);
        Executor::validate_root_fee_policy(&mut tx).unwrap();
    }
}
