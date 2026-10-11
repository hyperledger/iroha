// Exact observed monetary plans for the staking execution fixtures.
// These helpers only construct signed inputs; execution must independently verify them.

#[test]
fn genesis_monetary_scope_requires_exact_height_without_npos_parameters() {
    let state = setup_state();
    let mut genesis = state.block(block_header_with_height(1));
    let mut stx = genesis.transaction_for_callback_testing();
    stx.world
        .parameters
        .get_mut()
        .custom
        .remove(&SumeragiNposParameters::parameter_id());
    assert!(
        stx.world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .is_none()
    );
    assert!(effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, 1).is_ok());
    for invalid_height in [0, 2] {
        let error = effects::validate_plan_context(
            &stx,
            &PublicLaneMonetaryScopeV1::Genesis,
            invalid_height,
        )
        .expect_err("genesis consent must expire at its exact height");
        assert!(error.to_string().contains("genesis height"));
    }
    let error = effects::validate_plan_context(
        &stx,
        &PublicLaneMonetaryScopeV1::Network(*stx.network_id()),
        1,
    )
    .expect_err("network consent still requires a committed epoch schedule");
    assert!(
        error
            .to_string()
            .contains("committed NPoS epoch parameters")
    );

    drop(stx);
    drop(genesis);
    let mut next_block = state.block(block_header_with_height(2));
    let next_stx = next_block.transaction_for_callback_testing();
    let error = effects::validate_plan_context(&next_stx, &PublicLaneMonetaryScopeV1::Genesis, 2)
        .expect_err("genesis scope must not authorize a later block");
    assert!(
        error
            .to_string()
            .contains("authenticated genesis or network scope")
    );
}

fn fixture_transfer_plan(
    stx: &StateTransaction<'_, '_>,
    source_asset: AssetId,
    destination_asset: AssetId,
    amount: Quantity,
    precondition: PublicLaneMonetaryPreconditionV1,
) -> PublicLaneMonetaryPlanV1 {
    PublicLaneMonetaryPlanV1 {
        network_scope: PublicLaneMonetaryScopeV1::Network(*stx.network_id()),
        valid_until_height: stx.block_height(),
        source_asset,
        destination_asset,
        amount,
        precondition,
    }
}

fn fixture_registration_plan(
    stx: &StateTransaction<'_, '_>,
    lane: LaneId,
    staker: &AccountId,
    amount: impl std::borrow::Borrow<Quantity>,
) -> PublicLaneMonetaryPlanV1 {
    let context = stake_context(
        &stx.world,
        &stx.nexus.dataspace_catalog,
        &stx.nexus.staking,
        staker,
        stx.block_unix_timestamp_ms(),
    )
    .expect("fixture configured registration custody");
    fixture_transfer_plan(
        stx,
        context.staker_asset,
        context.escrow_asset,
        amount.borrow().clone(),
        PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
            activation_height: scheduled_validator_eligibility_height(stx, lane)
                .expect("fixture election height"),
        }),
    )
}

fn fixture_bond_plan(
    stx: &StateTransaction<'_, '_>,
    lane: LaneId,
    validator: &AccountId,
    staker: &AccountId,
    amount: impl std::borrow::Borrow<Quantity>,
) -> PublicLaneMonetaryPlanV1 {
    let context = stake_context(
        &stx.world,
        &stx.nexus.dataspace_catalog,
        &stx.nexus.staking,
        staker,
        stx.block_unix_timestamp_ms(),
    )
    .expect("fixture configured bond custody");
    let record = stx
        .world
        .public_lane_validators
        .get(&(lane, validator.clone()))
        .expect("fixture validator tenure");
    fixture_transfer_plan(
        stx,
        context.staker_asset,
        context.escrow_asset,
        amount.borrow().clone(),
        PublicLaneMonetaryPreconditionV1::Bond(PublicLaneMonetaryBondV1 {
            activation_height: record.activation_height,
            peer_id: record.peer_id.clone(),
        }),
    )
}

fn fixture_unbond_plan(
    stx: &StateTransaction<'_, '_>,
    lane: LaneId,
    validator: &AccountId,
    staker: &AccountId,
    request_id: impl std::borrow::Borrow<Hash>,
) -> PublicLaneMonetaryPlanV1 {
    let source = stx
        .world
        .public_lane_stake_custody
        .get(&(lane, validator.clone()))
        .expect("fixture retained withdrawal custody")
        .0
        .clone();
    let destination =
        AssetId::with_scope(source.definition().clone(), staker.clone(), *source.scope());
    let record = stx
        .world
        .public_lane_validators
        .get(&(lane, validator.clone()))
        .expect("fixture validator tenure");
    let request = stx
        .world
        .public_lane_stake_shares
        .get(&stake_key(lane, validator, staker))
        .expect("fixture withdrawal share")
        .pending_unbonds
        .get(request_id.borrow())
        .expect("fixture pending withdrawal");
    fixture_transfer_plan(
        stx,
        source,
        destination,
        request.amount.clone(),
        PublicLaneMonetaryPreconditionV1::Unbond(PublicLaneMonetaryUnbondV1 {
            activation_height: record.activation_height,
            request_hash: public_lane_unbonding_commitment(request)
                .expect("fixture withdrawal commitment"),
        }),
    )
}

fn fixture_slash_plan(
    stx: &StateTransaction<'_, '_>,
    lane: LaneId,
    validator: &AccountId,
    offence_height: u64,
    amount: impl std::borrow::Borrow<Quantity>,
) -> PublicLaneMonetaryPlanV1 {
    let source = stx
        .world
        .public_lane_stake_custody
        .get(&(lane, validator.clone()))
        .expect("fixture retained slash custody")
        .0
        .clone();
    let receiver = parse_staking_account_literal(
        &stx.world,
        &stx.nexus.dataspace_catalog,
        &stx.nexus.staking.slash_sink_account_id,
        "slash_sink_account_id",
        stx.block_unix_timestamp_ms(),
    )
    .expect("fixture slash receiver");
    let destination = AssetId::with_scope(source.definition().clone(), receiver, *source.scope());
    let record = stx
        .world
        .public_lane_validators
        .get(&(lane, validator.clone()))
        .expect("fixture validator tenure");
    let mut exposure = Quantity::zero();
    for (_, share) in stx
        .world
        .public_lane_stake_shares
        .iter()
        .filter(|(key, share)| {
            key.0 == lane && &key.1 == validator && public_lane_stake_share_matches_key(key, share)
        })
    {
        exposure = exposure
            .checked_add(&share.bonded)
            .expect("fixture bonded exposure");
        for pending in share
            .pending_unbonds
            .values()
            .filter(|pending| offence_height <= pending.slashable_through_height)
        {
            exposure = exposure
                .checked_add(&pending.amount)
                .expect("fixture pending exposure");
        }
    }
    fixture_transfer_plan(
        stx,
        source,
        destination,
        amount.borrow().clone(),
        PublicLaneMonetaryPreconditionV1::Slash(PublicLaneMonetarySlashV1 {
            activation_height: record.activation_height,
            slashable_exposure: exposure,
        }),
    )
}

#[test]
fn registration_rejects_changed_signed_monetary_fields_without_custody_writes() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(1));
    let mut stx = block.transaction_for_callback_testing();
    let (validator, recipient, escrow, definition) = prepare_accounts(&mut stx);
    let lane = LaneId::new(42);
    let instruction = RegisterPublicLaneValidator::new(
        lane,
        validator.clone(),
        validator_peer_id(&validator),
        validator.clone(),
        Quantity::from(1_000_u64),
        Metadata::default(),
        fixture_registration_plan(&stx, lane, &validator, Quantity::from(1_000_u64)),
    );
    let source = AssetId::new(definition.clone(), validator.clone());
    let destination = AssetId::new(definition.clone(), escrow);
    let balance = stx.world.assets.get(&source).cloned();
    for mutation in 0..7 {
        let mut altered = instruction.clone();
        match mutation {
            0 => {
                altered.monetary_plan.network_scope = PublicLaneMonetaryScopeV1::Network(
                    iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                        Hash::new("different fixture genesis"),
                    )),
                )
            }
            1 => altered.monetary_plan.valid_until_height = 0,
            2 => {
                altered.monetary_plan.valid_until_height = stx.block_height()
                    + stx
                        .world
                        .sumeragi_npos_parameters()
                        .expect("original policy decoder completes")
                        .unwrap()
                        .epoch_length_blocks
                        .get()
                    + 1
            }
            3 => {
                altered.monetary_plan.source_asset =
                    AssetId::new(definition.clone(), recipient.clone())
            }
            4 => {
                altered.monetary_plan.destination_asset =
                    AssetId::new(definition.clone(), recipient.clone())
            }
            5 => altered.monetary_plan.amount = Quantity::from(999_u64),
            6 => {
                altered.monetary_plan.precondition = PublicLaneMonetaryPreconditionV1::Registration(
                    PublicLaneMonetaryRegistrationV1 {
                        activation_height: 2,
                    },
                )
            }
            _ => unreachable!(),
        }
        let error = altered
            .execute(&validator, &mut stx)
            .expect_err("changed plan must reject");
        assert!(
            error.to_string().contains("monetary plan"),
            "mutation {mutation}: {error}"
        );
        assert_eq!(stx.world.assets.get(&source), balance.as_ref());
        assert!(stx.world.assets.get(&destination).is_none());
        assert!(
            stx.world
                .public_lane_validators
                .get(&(lane, validator.clone()))
                .is_none()
        );
        assert!(
            stx.world
                .public_lane_stake_custody
                .get(&(lane, validator.clone()))
                .is_none()
        );
        assert!(
            stx.world
                .public_lane_stake_reserves
                .get(&destination)
                .is_none()
        );
    }
    instruction
        .execute(&validator, &mut stx)
        .expect("unchanged exact plan must register");
}
