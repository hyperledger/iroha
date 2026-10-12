//! Signed private-root fee currency and schedule; the parent currency is never a fallback.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use iroha_data_model::block::consensus::{PrivateRootFeePolicy, SumeragiRootScope};

fn invalid(reason: impl Into<String>) -> NexusFeeAdmissionError {
    NexusFeeAdmissionError::ConfigInvalid(reason.into())
}

/// Read the immutable root's complete fee policy and validate its local monetary namespace.
pub(crate) fn policy(
    world: &impl WorldReadOnly,
) -> Result<
    Option<(DataSpaceId, PrivateRootFeePolicy)>,
    ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    let scope = crate::sumeragi::lanes::routing::read_routing_root_scope(world)
        .map_err(ExecutionAttemptError::Deferred)?
        .ok_or_else(|| invalid("fee admission requires immutable root scope"))?;
    let SumeragiRootScope::Dataspace { dataspace_id, .. } = scope else {
        return Ok(None);
    };
    let parameter_id = PrivateRootFeePolicy::parameter_id();
    let parameter = world
        .parameters()
        .custom()
        .get(&parameter_id)
        .ok_or_else(|| invalid("signed private root fee policy is absent"))?;
    if parameter.id() != &parameter_id {
        return Err(invalid("private root fee policy has a foreign parameter identity").into());
    }
    let policy: PrivateRootFeePolicy =
        norito::json::from_str(parameter.payload().get()).map_err(|error| {
            crate::execution_attempt::json_decode_attempt_error(error, |error| {
                invalid(format!("invalid signed private fee policy: {error}"))
            })
        })?;
    policy
        .validate()
        .map_err(|error| invalid(format!("invalid signed private fee policy: {error}")))?;
    let definition = world
        .asset_definition(&policy.asset_definition_id)
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
        return Err(
            invalid("private fee asset must belong to the exact signed root dataspace").into(),
        );
    }
    Ok(Some((dataspace_id, policy)))
}

pub(super) fn effective(
    world: &impl WorldReadOnly,
    configured: &NexusFees,
) -> Result<NexusFees, ExecutionAttemptError<NexusFeeAdmissionError>> {
    let mut fees = configured.clone();
    if let Some((_, policy)) = policy(world)? {
        fees.fee_asset_id = policy.asset_definition_id.canonical_address();
        fees.base_fee = policy.base_fee;
        fees.per_byte_fee = policy.per_byte_fee;
        fees.per_instruction_fee = policy.per_instruction_fee;
        fees.per_gas_unit_fee = policy.per_gas_unit_fee;
        fees.successful_claim_fee_exempt_authorities.clear();
    }
    Ok(fees)
}

pub(super) fn currency(
    world: &impl WorldReadOnly,
    fees: &NexusFees,
    observation_time_ms: u64,
) -> Result<
    AssetDefinitionId,
    crate::execution_attempt::ExecutionAttemptError<NexusFeeAdmissionError>,
> {
    if let Some((_, policy)) = policy(world)? {
        return Ok(policy.asset_definition_id);
    }
    crate::block::resolve_network_xor_asset_definition(
        world,
        &fees.fee_asset_id,
        observation_time_ms,
    )
    .map_err(crate::execution_attempt::ExecutionAttemptError::Deferred)?
    .ok_or_else(|| {
        invalid("invalid Nexus fee asset; expected the committed global XOR identity").into()
    })
}

pub(super) fn private_scope(
    world: &impl WorldReadOnly,
    route: Option<DataSpaceId>,
) -> Result<Option<DataSpaceId>, ExecutionAttemptError<NexusFeeAdmissionError>> {
    let Some((dataspace, _)) = policy(world)? else {
        return Ok(None);
    };
    if route != Some(dataspace) {
        return Err(invalid("private fee debit requires the exact captured root dataspace").into());
    }
    Ok(Some(dataspace))
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
                    PrivateRootFeePolicy {
                        asset_definition_id: asset.clone(),
                        base_fee: 2_u32.into(),
                        per_byte_fee: Quantity::zero(),
                        per_instruction_fee: 3_u32.into(),
                        per_gas_unit_fee: 4_u32.into(),
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
        nexus.fees.fee_asset_id = asset.canonical_address();
        (
            State::new_with_nexus_for_testing(world, nexus, LiveQueryStore::start_test()),
            ds,
            asset,
        )
    }

    #[test]
    fn private_fee_refresh_preserves_signed_schedule_and_frozen_pipeline_gas() {
        let (state, _, asset) = fixture(true, true);
        let mut block = state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
        let mut tx = block.transaction();
        tx.nexus.fees.base_fee = Quantity::zero();
        tx.nexus.fees.per_gas_unit_fee = Quantity::zero();
        let frozen_gas = tx.pipeline.gas.clone();
        Executor::refresh_private_fee_policy(&mut tx).unwrap();
        assert_eq!(tx.nexus.fees.fee_asset_id, asset.canonical_address());
        assert_eq!(tx.nexus.fees.base_fee, Quantity::from(2_u32));
        assert_eq!(tx.nexus.fees.per_gas_unit_fee, Quantity::from(4_u32));
        assert_eq!(tx.pipeline.gas, frozen_gas);
        // A private-root fee error must still fail rather than select local fees.
        tx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(CustomParameter::new(
                PrivateRootFeePolicy::parameter_id(),
                iroha_primitives::json::Json::new("malformed private policy"),
            )))
            .expect("valid fixture parameters");
        assert!(Executor::refresh_private_fee_policy(&mut tx).is_err());
        assert_eq!(tx.pipeline.gas, frozen_gas);
    }

    #[test]
    fn committed_private_schedule_ignores_local_zero_rates_and_quotes_exact_scoped_asset() {
        let (state, ds, asset) = fixture(true, true);
        let view = state.view();
        let mut nexus = view.nexus().clone();
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus.fees.fee_asset_id = "xor#universal".into();
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
        let original = policy(view.world()).unwrap();
        for reader in 0..4 {
            let refused = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || {
                    match reader {
                        0 => policy(view.world()).map(|_| ()),
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
        assert_eq!(policy(view.world()).unwrap(), original);
        assert_eq!(
            currency(view.world(), &view.nexus().fees, 0).unwrap(),
            asset
        );
        assert_eq!(private_scope(view.world(), Some(ds)).unwrap(), Some(ds));
        assert!(!permits_public_exemption(view.world()).unwrap());
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
            2,
            Some(ds),
        )
        .unwrap_err();
        assert_eq!(
            error,
            NexusFeeAdmissionError::ConfigInvalid(
                "private-root fee sponsors require a scoped vault owner".into()
            )
            .into()
        );
    }

    #[test]
    fn private_policy_refuses_missing_malformed_global_assets_and_unbound_roots() {
        let (missing, _, _) = fixture(false, true);
        assert!(policy(missing.view().world()).is_err());
        let (global_asset, _, _) = fixture(true, false);
        assert!(policy(global_asset.view().world()).is_err());
        assert!(policy(&World::new().view()).is_err());
        let (state, _, _) = fixture(true, true);
        let mut block = state.block(BlockHeader::new(2.try_into().unwrap(), None, None, 1000, 0));
        let mut tx = block.transaction();
        tx.world
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(CustomParameter::new(
                PrivateRootFeePolicy::parameter_id(),
                iroha_primitives::json::Json::new(false),
            )))
            .expect("valid fixture parameters");
        assert!(policy(&tx.world).is_err());
    }
}
