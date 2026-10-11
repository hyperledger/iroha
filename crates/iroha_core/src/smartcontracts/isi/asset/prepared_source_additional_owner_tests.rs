// Source-occurrence tests live inside the private asset ISI owner boundary.

use crate::{
    kura::Kura,
    privacy_state::PrivacyPublicReserveOwnerV1,
    query::store::LiveQueryStore,
    state::{State, StateTransaction, World},
};
use iroha_data_model::{IntoKeyValue, asset::AssetBalanceScope, block::BlockHeader};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use nonzero_ext::nonzero;

fn wonderland_domain_id() -> DomainId {
    DomainId::try_new("wonderland", "universal").unwrap()
}

fn wonderland_asset_definition_id(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(wonderland_domain_id(), name.parse().unwrap())
}

fn build_numeric_asset_definition(
    id: &AssetDefinitionId,
    name: &str,
    owner: &AccountId,
) -> AssetDefinition {
    AssetDefinition::numeric(
        id.clone(),
        name.to_owned(),
        AssetBalancePolicy::Global,
        None,
    )
    .build(owner)
}

fn asset_route_test_state(world: World) -> State {
    State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn build_asset_transfer_control_test_state(balance: u32) -> (State, AssetDefinitionId, AssetId) {
    let definition = wonderland_asset_definition_id("rose");
    let source = AssetId::new(definition.clone(), ALICE_ID.clone());
    let world = World::with_assets(
        [Domain::new(wonderland_domain_id()).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [build_numeric_asset_definition(
            &definition,
            "rose",
            &ALICE_ID,
        )],
        [Asset::new(source.clone(), Quantity::from(balance))],
        [],
    );
    (asset_route_test_state(world), definition, source)
}

fn asset_balance_or_zero(tx: &StateTransaction<'_, '_>, id: &AssetId) -> Quantity {
    tx.world
        .assets
        .get(id)
        .map(|asset| asset.as_ref().clone())
        .unwrap_or_else(Quantity::zero)
}

fn seed_prepared_test_orchard_reserve(
    tx: &mut StateTransaction<'_, '_>,
    id: &AssetId,
) -> PrivacyPublicReserveOwnerV1 {
    use iroha_data_model::privacy::{
        PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyOrchardPoolBootstrapDigestV1,
        PrivacyPoolIdV1, PrivacyPoolNamespaceV1, PrivacyProtocolIdV1,
    };

    let owner = PrivacyPublicReserveOwnerV1::Orchard {
        namespace: PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
                pool_id: PrivacyPoolIdV1::new([0xD1; 32]),
            }),
        ),
        bootstrap_digest: PrivacyOrchardPoolBootstrapDigestV1::new([0xD2; 32]),
    };
    tx.world.privacy_commitments.insert(
        crate::privacy_state::PrivacyCommitmentKeyV1::public_reserve_custody(
            owner.protocol_id(),
            id,
        )
        .expect("reserve custody key"),
        crate::privacy_state::PrivacyStateItemRecordV1::public_reserve_custody(id.clone(), owner)
            .expect("reserve custody row"),
    );
    owner
}

#[test]
fn privacy_public_reserve_apply_rejects_nonconserving_delta_before_balances_change() {
    let (state, definition_id, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(definition_id, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut transaction = block.transaction();
    let owner = seed_prepared_test_orchard_reserve(&mut transaction, &reserve_asset_id);
    let exact = transaction
        .world
        .precheck_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &Quantity::one(),
        )
        .expect("reserve withdrawal has a valid transparent delta");
    let mut forged = exact.clone();
    forged.to_balance_after = Quantity::from(2_u32);
    let error = transaction
        .world
        .apply_prechecked_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &exact.amount,
            &forged,
            NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner),
        )
        .expect_err("one-unit reserve debit cannot create two recipient units");
    assert!(error.to_string().contains("reserve delta must conserve"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::zero()
    );
    let mut forged_debit = exact.clone();
    forged_debit.from_balance_after = Quantity::from(8_u32);
    let error = transaction
        .world
        .apply_prechecked_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &exact.amount,
            &forged_debit,
            NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner),
        )
        .expect_err("one-unit reserve debit cannot remove two source units");
    assert!(error.to_string().contains("reserve delta must conserve"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::zero()
    );
    let mut forged_amount = exact.clone();
    forged_amount.amount = Quantity::from(2_u32);
    let error = transaction
        .world
        .apply_prechecked_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &exact.amount,
            &forged_amount,
            NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner),
        )
        .expect_err("delta cannot replace the authorized amount");
    assert!(error.to_string().contains("authorized amount"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::zero()
    );
    transaction
        .world
        .apply_prechecked_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &exact.amount,
            &exact,
            NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner),
        )
        .expect("exact one-unit delta remains admissible to the apply owner");
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(9_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::one()
    );
}

#[test]
fn privacy_public_reserve_apply_rejects_stale_destination_balance() {
    let (state, definition_id, reserve_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(definition_id, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut transaction = block.transaction();
    let owner = seed_prepared_test_orchard_reserve(&mut transaction, &reserve_asset_id);
    let exact = transaction
        .world
        .precheck_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &Quantity::one(),
        )
        .expect("reserve withdrawal has a valid transparent delta");
    let (_, destination_value) = Asset::new(destination_asset_id.clone(), 1_u32).into_key_value();
    transaction.world.track_asset_holder(&destination_asset_id);
    transaction
        .world
        .assets
        .insert(destination_asset_id.clone(), destination_value);

    let error = transaction
        .world
        .apply_prechecked_numeric_asset_transfer_delta_exact(
            &reserve_asset_id,
            &destination_asset_id,
            &exact.amount,
            &exact,
            NumericAssetTransferSourcePolicy::PrivacyPoolBridge(owner),
        )
        .expect_err("the destination changed after reserve preparation");
    assert!(error.to_string().contains("reserve delta must conserve"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &reserve_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_asset_id),
        Quantity::one()
    );
}

#[test]
fn prepared_user_transfer_rechecks_new_privacy_reserve_custody_at_apply() {
    let (state, definition_id, source_id) = build_asset_transfer_control_test_state(10);
    let destination_id = AssetId::new(definition_id, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut transaction = block.transaction();
    let plan = PreparedNumericTransferPlan::prepare_user(
        &mut transaction,
        &ALICE_ID,
        source_id.clone(),
        destination_id.clone(),
        Quantity::one(),
    )
    .expect("ungoverned source can be prepared");
    seed_prepared_test_orchard_reserve(&mut transaction, &source_id);

    let error = plan
        .apply(&mut transaction)
        .err()
        .expect("prepared user transfer cannot debit new governed custody");
    assert!(error.to_string().contains("exact verified pool bridge"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &source_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_id),
        Quantity::zero()
    );
}

#[test]
fn prepared_batch_transfer_rechecks_new_privacy_reserve_custody_at_apply() {
    let (state, definition_id, source_id) = build_asset_transfer_control_test_state(10);
    let destination_id = AssetId::new(definition_id, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut transaction = block.transaction();
    let plan = PreparedNumericTransferPlan::prepare(
        &mut transaction,
        &ALICE_ID,
        source_id.clone(),
        destination_id.clone(),
        Quantity::one(),
        NumericAssetTransferScopePolicy::Ambient,
        NumericAssetTransferAuthorityPolicy::UserSource,
        NumericAssetTransferSourcePolicy::User,
        NumericAssetTransferControlPolicy::StakingUnbond,
        NumericAssetDestinationAdmissionPolicy::ExistingAccount,
    )
    .expect("ungoverned source can be prepared without a control update");
    seed_prepared_test_orchard_reserve(&mut transaction, &source_id);

    let error = plan
        .apply_after_batch_preflight(&mut transaction)
        .err()
        .expect("prepared batch transfer cannot debit new governed custody");
    assert!(error.to_string().contains("exact verified pool bridge"));
    assert_eq!(
        asset_balance_or_zero(&transaction, &source_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&transaction, &destination_id),
        Quantity::zero()
    );
}

fn occurrence_header() -> BlockHeader {
    BlockHeader::new(nonzero!(1_u64), None, None, 86_400_000, 0)
}

fn expected_occurrence(
    hash: Hash,
    deltas: Vec<TransferDeltaTranscript>,
) -> iroha_data_model::fastpq::TransferTranscript {
    iroha_data_model::fastpq::TransferTranscript {
        batch_hash: hash,
        authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
        poseidon_preimage_digest: match deltas.as_slice() {
            [delta] => Some(crate::fastpq::poseidon_preimage_digest(delta, &hash)),
            _ => None,
        },
        deltas,
    }
}

#[test]
fn aggregate_batch_preserves_one_ordered_occurrence_for_repeated_and_self_legs() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let hash = Hash::new(b"prepared aggregate occurrence");
    let mut tx = block.transaction_for_fastpq_testing(hash);
    let batch = PreparedNumericAssetMovementBatch::prepare_user(
        &mut tx,
        &ALICE_ID,
        &[
            (source.clone(), destination.clone(), Quantity::from(3_u32)),
            (source.clone(), destination.clone(), Quantity::from(2_u32)),
            (source.clone(), source.clone(), Quantity::one()),
        ],
    )
    .unwrap();
    let deltas = batch
        .plans
        .iter()
        .map(|plan| plan.prechecked_delta.clone())
        .collect::<Vec<_>>();
    assert_eq!(deltas[1].from_balance_before, Quantity::from(7_u32));
    assert_eq!(deltas[1].to_balance_before, Quantity::from(3_u32));
    assert_eq!(deltas[2].from_balance_before, Quantity::from(5_u32));
    assert_eq!(deltas[2].to_balance_after, Quantity::from(5_u32));
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    let applied = batch.apply(&mut tx).unwrap();
    assert_eq!(applied.len(), 3);
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 1);
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(5_u32));
    assert_eq!(
        asset_balance_or_zero(&tx, &destination),
        Quantity::from(5_u32)
    );
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    let expected = expected_occurrence(hash, deltas);
    assert_eq!(transcripts[&hash], vec![expected.clone()]);
    assert_eq!(expected.poseidon_preimage_digest, None);
    assert_eq!(
        norito::encode_canonical(&transcripts[&hash][0]).unwrap(),
        norito::encode_canonical(&expected).unwrap()
    );
    assert!(!block.captured_fastpq_transcript_sources().unwrap()[&hash].is_protocol_purpose());
}

#[test]
fn native_batch_keeps_typed_purpose_and_finalizes_a_single_leg() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut tx = block.transaction_for_fastpq_protocol_testing();
    assert!(tx.tx_call_hash.is_none());
    let authorization = NumericAssetMovementAuthorization::bilateral(
        &ALICE_ID,
        "prepared-test-native-batch",
        vec![0x53],
    );
    let bindings = vec![(source, destination, Quantity::from(3_u32))];
    let hash = authorization
        .resolve_transcript_identity(&tx, &bindings)
        .unwrap();
    let batch = PreparedNumericAssetMovementBatch::prepare_with_authorization(
        &mut tx,
        &bindings,
        authorization,
    )
    .unwrap();
    let expected = expected_occurrence(hash, vec![batch.plans[0].prechecked_delta.clone()]);
    batch.apply(&mut tx).unwrap();
    assert!(tx.tx_call_hash.is_none());
    tx.apply();
    assert_eq!(block.drain_transfer_transcripts()[&hash], vec![expected]);
    assert!(block.captured_fastpq_transcript_sources().unwrap()[&hash].is_protocol_purpose());
}

#[test]
fn stale_aggregate_batch_rejects_before_balance_and_occurrence_writes() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut tx = block.transaction_for_fastpq_testing(Hash::new(b"stale aggregate occurrence"));
    let batch = PreparedNumericAssetMovementBatch::prepare_user(
        &mut tx,
        &ALICE_ID,
        &[(source.clone(), destination.clone(), Quantity::from(3_u32))],
    )
    .unwrap();
    **tx.world.assets.get_mut(&source).unwrap() = Quantity::from(9_u32);
    let events_before = tx.world.internal_event_buf.len();
    let error = match batch.apply(&mut tx) {
        Ok(_) => panic!("stale aggregate batch must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("balance changed"));
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(9_u32));
    assert_eq!(asset_balance_or_zero(&tx, &destination), Quantity::zero());
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    assert_eq!(tx.world.internal_event_buf.len(), events_before);
}

fn pair_state() -> (State, [AssetId; 4]) {
    let domain = wonderland_domain_id();
    let first = wonderland_asset_definition_id("rose");
    let second = wonderland_asset_definition_id("lily");
    let ids = [
        AssetId::new(first.clone(), ALICE_ID.clone()),
        AssetId::new(first.clone(), BOB_ID.clone()),
        AssetId::new(second.clone(), ALICE_ID.clone()),
        AssetId::new(second.clone(), BOB_ID.clone()),
    ];
    let world = World::with_assets(
        [Domain::new(domain).build(&ALICE_ID)],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
        ],
        [
            build_numeric_asset_definition(&first, "rose", &ALICE_ID),
            build_numeric_asset_definition(&second, "lily", &ALICE_ID),
        ],
        [
            Asset::new(ids[0].clone(), Quantity::from(10_u32)),
            Asset::new(ids[2].clone(), Quantity::from(20_u32)),
        ],
        [],
    );
    (asset_route_test_state(world), ids)
}

fn prepared_pair(
    tx: &mut StateTransaction<'_, '_>,
    ids: &[AssetId; 4],
) -> PreparedNumericTransferPair {
    prepare_authorized_numeric_asset_pair(
        tx,
        &ALICE_ID,
        ids[0].clone(),
        ids[1].clone(),
        Quantity::from(3_u32),
        ids[2].clone(),
        ids[3].clone(),
        Quantity::from(7_u32),
    )
    .unwrap()
}

#[test]
fn native_fx_apply_boundary_keeps_pair_order_and_one_multi_delta_occurrence() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, ids) = pair_state();
    let mut block = state.block(occurrence_header());
    let hash = Hash::new(b"prepared FX pair application");
    let mut tx = block.transaction_for_fastpq_testing(hash);
    let pair = prepared_pair(&mut tx, &ids);
    let expected = expected_occurrence(
        hash,
        vec![
            pair.source.prechecked_delta.clone(),
            pair.destination.prechecked_delta.clone(),
        ],
    );
    let (first, second) = pair
        .apply_with_transcript(&mut tx, &ALICE_ID, hash)
        .unwrap();
    assert_eq!(first.delta, expected.deltas[0]);
    assert_eq!(second.delta, expected.deltas[1]);
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 1);
    for (id, amount) in ids.iter().zip([7_u32, 3, 13, 7]) {
        assert_eq!(asset_balance_or_zero(&tx, id), Quantity::from(amount));
    }
    tx.apply();
    assert_eq!(block.drain_transfer_transcripts()[&hash], vec![expected]);
}

#[test]
fn second_pair_apply_error_stages_nothing_and_parent_rollback_remains_required() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, ids) = pair_state();
    let mut block = state.block(occurrence_header());
    {
        let hash = Hash::new(b"stale second FX pair leg");
        let mut tx = block.transaction_for_fastpq_testing(hash);
        let pair = prepared_pair(&mut tx, &ids);
        **tx.world.assets.get_mut(&ids[2]).unwrap() = Quantity::from(19_u32);
        let error = match pair.apply_with_transcript(&mut tx, &ALICE_ID, hash) {
            Ok(_) => panic!("stale second leg must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("balance changed"));
        assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
        // The occurrence helper does not invent a nested world rollback: the first
        // existing leg already applied, and the enclosing transaction must be discarded.
        assert_eq!(asset_balance_or_zero(&tx, &ids[0]), Quantity::from(7_u32));
    }
    assert!(block.drain_transfer_transcripts().is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    let tx = block.transaction();
    assert_eq!(asset_balance_or_zero(&tx, &ids[0]), Quantity::from(10_u32));
    assert_eq!(asset_balance_or_zero(&tx, &ids[2]), Quantity::from(20_u32));
}

#[test]
fn optimized_detached_merges_keep_each_prepared_call_after_final_hash_clear() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let hashes = [
        Hash::new(b"optimized prepared first"),
        Hash::new(b"optimized prepared second"),
    ];
    for hash in hashes {
        block.admit_fastpq_source_for_testing(hash);
    }
    let mut tx = block.transaction();
    let mut expected = Vec::new();
    for (hash, amount) in hashes.into_iter().zip([3_u32, 2]) {
        tx.tx_call_hash = Some(hash);
        let amount = Quantity::from(amount);
        let delta = tx
            .world
            .precheck_numeric_asset_transfer_delta_exact(&source, &destination, &amount)
            .unwrap();
        expected.push(expected_occurrence(hash, vec![delta]));
        assert!(
            execute_batch_merge_eligible_user_numeric_asset_transfer(
                &mut tx,
                &ALICE_ID,
                source.clone(),
                BOB_ID.clone(),
                amount
            )
            .unwrap()
        );
    }
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 2);
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(5_u32));
    tx.tx_call_hash = None;
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    let sources = block.captured_fastpq_transcript_sources().unwrap();
    for occurrence in expected {
        let hash = occurrence.batch_hash;
        assert_eq!(transcripts[&hash], vec![occurrence]);
        assert!(!sources[&hash].is_protocol_purpose());
    }
}

#[test]
fn optimized_detached_fallbacks_preserve_balances_events_and_occurrences() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition.clone(), BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut tx = block.transaction();
    let events_before = tx.world.internal_event_buf.len();
    assert!(
        !execute_batch_merge_eligible_user_numeric_asset_transfer(
            &mut tx,
            &ALICE_ID,
            source.clone(),
            iroha_test_samples::CARPENTER_ID.clone(),
            Quantity::one()
        )
        .unwrap()
    );
    assert_eq!(tx.world.internal_event_buf.len(), events_before);
    SetAssetTransferControl::new(
        ALICE_ID.clone(),
        definition,
        vec![AssetTransferLimit {
            window: AssetTransferControlWindow::Day,
            cap_amount: Some(Quantity::from(10_u32)),
        }],
    )
    .execute(&ALICE_ID, &mut tx)
    .unwrap();
    let events_before = tx.world.internal_event_buf.len();
    assert!(
        !execute_batch_merge_eligible_user_numeric_asset_transfer(
            &mut tx,
            &ALICE_ID,
            source.clone(),
            BOB_ID.clone(),
            Quantity::one()
        )
        .unwrap()
    );
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(10_u32));
    assert_eq!(asset_balance_or_zero(&tx, &destination), Quantity::zero());
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    assert_eq!(tx.world.internal_event_buf.len(), events_before);
}

#[test]
fn optimized_detached_missing_identity_rejects_before_balance_and_event_writes() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut tx = block.transaction();
    let events_before = tx.world.internal_event_buf.len();
    let error = execute_batch_merge_eligible_user_numeric_asset_transfer(
        &mut tx,
        &ALICE_ID,
        source.clone(),
        BOB_ID.clone(),
        Quantity::one(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("call_hash"));
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(10_u32));
    assert_eq!(asset_balance_or_zero(&tx, &destination), Quantity::zero());
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    assert_eq!(tx.world.internal_event_buf.len(), events_before);
}

#[test]
fn numeric_transfer_precheck_preserves_typed_source_and_receiver_controls() {
    use NumericAssetTransferControlPolicy as Policy;

    for (policy, outbound_exempt, credit_exempt) in [
        (Policy::Enforce, false, false),
        (Policy::OraclePenalty, true, false),
        (Policy::OracleDisputeResolution, true, false),
        (Policy::StakingUnbond, true, false),
        (Policy::StakingSlash, true, true),
        (Policy::ModerationChallengeSettlement, true, true),
        (Policy::GovernanceSlash, true, false),
        (Policy::GovernanceRestitution, true, false),
        (Policy::GovernanceUnlock, true, false),
        (Policy::CitizenshipRelease, true, false),
    ] {
        let (state, definition, source) = build_asset_transfer_control_test_state(10);
        let destination = AssetId::new(definition.clone(), BOB_ID.clone());
        let mut block = state.block(occurrence_header());
        let mut tx = block.transaction();
        let amount = Quantity::from(3_u32);
        SetAssetTransferAvailability::new(
            ALICE_ID.clone(),
            definition.clone(),
            0,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Disabled,
            None,
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        assert!(matches!(
            tx.world
                .precheck_numeric_asset_transfer_delta_exact(&source, &destination, &amount),
            Err(Error::AssetTransferAdmission(
                AssetTransferAdmissionError::OutgoingDisabled(_)
            ))
        ));
        let precheck = |tx: &StateTransaction<'_, '_>, amount: &Quantity| {
            tx.world
                .precheck_numeric_asset_transfer_delta_exact_with_control_policy(
                    &source,
                    &destination,
                    amount,
                    policy,
                )
        };
        let outgoing_result = precheck(&tx, &amount);
        if outbound_exempt {
            let delta = outgoing_result.unwrap_or_else(|error| panic!("{policy:?}: {error}"));
            assert_eq!(delta.from_balance_before, Quantity::from(10_u32));
            assert_eq!(delta.from_balance_after, Quantity::from(7_u32));
            assert_eq!(delta.to_balance_before, Quantity::zero());
            assert_eq!(delta.to_balance_after, amount);
        } else {
            assert!(
                matches!(
                    outgoing_result,
                    Err(Error::AssetTransferAdmission(
                        AssetTransferAdmissionError::OutgoingDisabled(_)
                    ))
                ),
                "{policy:?}: {outgoing_result:?}"
            );
        }
        SetAssetTransferAvailability::new(
            ALICE_ID.clone(),
            definition.clone(),
            1,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Enabled,
            None,
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        SetAssetTransferAvailability::new(
            BOB_ID.clone(),
            definition.clone(),
            0,
            AssetTransferAvailability::Disabled,
            AssetTransferAvailability::Enabled,
            None,
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        let incoming_result = precheck(&tx, &amount);
        if credit_exempt {
            incoming_result.unwrap_or_else(|error| panic!("{policy:?}: {error}"));
        } else {
            assert!(
                matches!(
                    incoming_result,
                    Err(Error::AssetTransferAdmission(
                        AssetTransferAdmissionError::IncomingDisabled(_)
                    ))
                ),
                "{policy:?}: {incoming_result:?}"
            );
        }
        SetAssetTransferAvailability::new(
            BOB_ID.clone(),
            definition.clone(),
            1,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Enabled,
            None,
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        SetAssetHoldingLimit::new(
            BOB_ID.clone(),
            definition.clone(),
            Some(Quantity::from(2_u32)),
        )
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
        let holding_result = precheck(&tx, &amount);
        if credit_exempt {
            holding_result.unwrap_or_else(|error| panic!("{policy:?}: {error}"));
        } else {
            assert!(
                matches!(
                    holding_result,
                    Err(Error::AssetTransferAdmission(
                        AssetTransferAdmissionError::HoldingLimitExceeded(_)
                    ))
                ),
                "{policy:?}: {holding_result:?}"
            );
        }
        SetAssetHoldingLimit::new(BOB_ID.clone(), definition, None)
            .execute(&ALICE_ID, &mut tx)
            .unwrap();
        let insufficient = precheck(&tx, &Quantity::from(11_u32));
        assert!(
            matches!(insufficient, Err(Error::Math(MathError::NotEnoughQuantity))),
            "{policy:?}: {insufficient:?}"
        );
        assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(10_u32));
        assert_eq!(asset_balance_or_zero(&tx, &destination), Quantity::zero());
    }
}

#[test]
fn exact_same_account_scope_transfer_rebuilds_all_holder_indexes_after_source_exhaustion() {
    let domain = wonderland_domain_id();
    let definition = wonderland_asset_definition_id("scoped-index-owner");
    let source = AssetId::with_scope(
        definition.clone(),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    let destination = AssetId::with_scope(
        definition.clone(),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(8)),
    );
    let asset_definition = AssetDefinition::numeric(
        definition.clone(),
        "Scoped",
        AssetBalancePolicy::DataspaceRestricted,
        Some(domain.clone()),
    )
    .build(&ALICE_ID);
    let world = World::with_assets(
        [Domain::new(domain.clone()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [asset_definition],
        [Asset::new(source.clone(), Quantity::from(10_u32))],
        [],
    );
    let state = asset_route_test_state(world);
    let mut block = state.block(occurrence_header());
    let mut transaction =
        block.transaction_for_fastpq_testing(Hash::new(b"same account distinct exact scopes"));
    let amount = Quantity::from(10_u32);
    let delta = transaction
        .world
        .precheck_numeric_asset_transfer_delta_exact(&source, &destination, &amount)
        .unwrap();
    transaction
        .world
        .apply_prechecked_numeric_asset_transfer_delta_exact(
            &source,
            &destination,
            &amount,
            &delta,
            NumericAssetTransferSourcePolicy::User,
        )
        .unwrap();
    assert!(transaction.world.assets.get(&source).is_none());
    assert_eq!(asset_balance_or_zero(&transaction, &destination), amount);
    let definition_assets = transaction
        .world
        .asset_definition_assets
        .get(&definition)
        .unwrap();
    assert!(!definition_assets.contains(&source));
    assert!(definition_assets.contains(&destination));
    assert_eq!(definition_assets.len(), 1);
    let account_assets = transaction.world.assets_by_account.get(&ALICE_ID).unwrap();
    assert!(!account_assets.contains(&source));
    assert!(account_assets.contains(&destination));
    let domain_assets = transaction.world.assets_by_domain.get(&domain).unwrap();
    assert!(!domain_assets.contains(&source));
    assert!(domain_assets.contains(&destination));
    assert_eq!(
        transaction
            .world
            .asset_definition_holders
            .get(&definition)
            .unwrap()
            .len(),
        1
    );
    assert!(
        transaction
            .world
            .asset_definition_holders
            .get(&definition)
            .unwrap()
            .contains(&ALICE_ID)
    );
    assert_eq!(
        transaction
            .world
            .asset_definition_nonzero_holders
            .get(&definition)
            .unwrap()
            .len(),
        1
    );
    assert!(
        transaction
            .world
            .asset_definition_nonzero_holders
            .get(&definition)
            .unwrap()
            .contains(&ALICE_ID)
    );
    assert_eq!(
        transaction
            .world
            .asset_definition(&definition)
            .unwrap()
            .total_quantity(),
        &amount
    );
}

#[test]
fn exact_pair_rechecks_destination_before_touching_source_or_its_indexes() {
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::of(definition.clone(), BOB_ID.clone());
    let mut block = state.block(occurrence_header());
    let mut transaction =
        block.transaction_for_fastpq_testing(Hash::new(b"paired write fallible precheck"));
    let amount = Quantity::from(10_u32);
    let delta = transaction
        .world
        .precheck_numeric_asset_transfer_delta_exact(&source, &destination, &amount)
        .unwrap();
    transaction.world.accounts.remove(BOB_ID.clone());
    assert!(
        transaction
            .world
            .apply_prechecked_numeric_asset_transfer_delta_exact(
                &source,
                &destination,
                &amount,
                &delta,
                NumericAssetTransferSourcePolicy::User
            )
            .is_err()
    );
    assert_eq!(asset_balance_or_zero(&transaction, &source), amount);
    assert!(transaction.world.assets.get(&destination).is_none());
    assert!(
        transaction
            .world
            .asset_definition_assets
            .get(&definition)
            .unwrap()
            .contains(&source)
    );
    assert!(
        transaction
            .world
            .asset_definition_nonzero_holders
            .get(&definition)
            .unwrap()
            .contains(&ALICE_ID)
    );
}

#[test]
fn original_supply_preparation_is_read_only_and_consumes_exact_balance_then_total() {
    for (mint, amount, expected) in [(true, 3_u32, 13_u32), (false, 3, 7), (false, 10, 0)] {
        let (state, definition, source) = build_asset_transfer_control_test_state(10);
        let mut block = state.block(occurrence_header());
        let mut transaction = block.transaction();
        let amount = Quantity::from(amount);
        let events_before = transaction.world.internal_event_buf.len();
        let prepared =
            PreparedNumericSupplyChange::prepare(&mut transaction, &source, &amount, mint).unwrap();
        assert_eq!(prepared.balance_after, Quantity::from(expected));
        assert_eq!(
            prepared.supply_after.as_ref().unwrap(),
            &Quantity::from(expected)
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &source),
            Quantity::from(10_u32)
        );
        assert_eq!(
            transaction
                .world
                .asset_definition(&definition)
                .unwrap()
                .total_quantity(),
            &Quantity::from(10_u32)
        );
        assert_eq!(transaction.world.internal_event_buf.len(), events_before);
        let total = prepared.apply_balance(&mut transaction.world).unwrap();
        assert_eq!(
            asset_balance_or_zero(&transaction, &source),
            Quantity::from(expected)
        );
        assert_eq!(
            transaction
                .world
                .asset_definition(&definition)
                .unwrap()
                .total_quantity(),
            &Quantity::from(10_u32)
        );
        total.apply(&mut transaction.world, &amount).unwrap();
        assert_eq!(
            transaction
                .world
                .asset_definition(&definition)
                .unwrap()
                .total_quantity(),
            &Quantity::from(expected)
        );
        if expected == 0 {
            assert!(transaction.world.assets.get(&source).is_none());
            assert!(
                !transaction
                    .world
                    .asset_definition_nonzero_holders
                    .get(&definition)
                    .is_some_and(|holders| holders.contains(&ALICE_ID))
            );
        }
        drop(transaction);
        assert_eq!(
            block.world.assets.get(&source).unwrap().as_ref(),
            &Quantity::from(10_u32)
        );
        assert_eq!(
            block
                .world
                .asset_definition(&definition)
                .unwrap()
                .total_quantity(),
            &Quantity::from(10_u32)
        );
    }
}

#[test]
fn original_supply_preparation_preserves_deferred_total_error_and_rollback() {
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let mut block = state.block(occurrence_header());
    let mut transaction = block.transaction();
    // Deliberately corrupt this private diagnostic overlay: the original aggregate
    // failure occurs after the debit, and must never publish a complete capture.
    transaction
        .world
        .asset_definitions
        .get_mut(&definition)
        .unwrap()
        .total_quantity = Quantity::one();
    let amount = Quantity::from(2_u32);
    let prepared =
        PreparedNumericSupplyChange::prepare(&mut transaction, &source, &amount, false).unwrap();
    assert!(matches!(
        &prepared.supply_after,
        Err(Error::Math(MathError::NotEnoughQuantity))
    ));
    assert_eq!(
        asset_balance_or_zero(&transaction, &source),
        Quantity::from(10_u32)
    );
    let total = prepared.apply_balance(&mut transaction.world).unwrap();
    assert_eq!(
        asset_balance_or_zero(&transaction, &source),
        Quantity::from(8_u32)
    );
    assert!(matches!(
        total.apply(&mut transaction.world, &amount),
        Err(Error::Math(MathError::NotEnoughQuantity))
    ));
    assert_eq!(
        transaction
            .world
            .asset_definition(&definition)
            .unwrap()
            .total_quantity(),
        &Quantity::one()
    );
    drop(transaction);
    assert_eq!(
        block.world.assets.get(&source).unwrap().as_ref(),
        &Quantity::from(10_u32)
    );
    assert_eq!(
        block
            .world
            .asset_definition(&definition)
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}

#[test]
fn original_supply_preparation_rejects_source_and_recipient_controls_before_writes() {
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let mut block = state.block(occurrence_header());
    let mut transaction = block.transaction();
    let amount = Quantity::one();
    SetAssetHoldingLimit::new(
        ALICE_ID.clone(),
        definition.clone(),
        Some(Quantity::from(10_u32)),
    )
    .execute(&ALICE_ID, &mut transaction)
    .unwrap();
    let events_before = transaction.world.internal_event_buf.len();
    assert!(matches!(
        PreparedNumericSupplyChange::prepare(&mut transaction, &source, &amount, true),
        Err(Error::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_)
        ))
    ));
    assert_eq!(transaction.world.internal_event_buf.len(), events_before);
    seed_prepared_test_orchard_reserve(&mut transaction, &source);
    let events_before = transaction.world.internal_event_buf.len();
    let error = PreparedNumericSupplyChange::prepare(&mut transaction, &source, &amount, false)
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("public reserve cannot be burned")
    );
    assert_eq!(transaction.world.internal_event_buf.len(), events_before);
    assert_eq!(
        asset_balance_or_zero(&transaction, &source),
        Quantity::from(10_u32)
    );
    assert_eq!(
        transaction
            .world
            .asset_definition(&definition)
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}
