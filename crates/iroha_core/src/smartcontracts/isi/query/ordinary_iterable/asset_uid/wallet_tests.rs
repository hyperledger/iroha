//! Staged end-to-end native source controls; no server or native execution claimed yet.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::{
    Registrable,
    asset::{
        AssetBalancePolicy, AssetDefinition,
        uid::{AssetUidBindingV1, AssetUidDailyWindowV1},
    },
    prelude::{Account, BlockHeader},
};
use std::{collections::BTreeSet, num::NonZeroU64};

fn limits() -> OrdinaryQueryExecutionLimits {
    let items = 2;
    let source = 16_384;
    let response = 32_768;
    let archive = 4_096;
    let decode = norito::DecodeLimits::new(4096, 16_384, 8192, 131_072, 32);
    let execution = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
        items, source, response, 4096, archive, decode,
    )
    .unwrap();
    let cursor = OrdinaryQueryExecutionLimits::required_cursor_retained_bytes(
        items, source, source, archive,
    )
    .unwrap();
    OrdinaryQueryExecutionLimits::try_new(
        1,
        crate::smartcontracts::isi::query::QueryExecutionBudget::from_weighted_limit(
            4_194_304, 1, 1,
        ),
        items,
        execution,
        source,
        response,
        items,
        source,
        cursor,
        4096,
        archive,
        decode,
    )
    .unwrap()
}
fn params() -> QueryParams {
    QueryParams {
        fetch_size: iroha_data_model::query::parameters::FetchSize::new(NonZeroU64::new(1)),
        ..QueryParams::default()
    }
}
fn fixture_with_cut(capture_cut: bool) -> (State, FindAssetUidPoliciesV1) {
    let wallet = iroha_test_samples::ALICE_ID.clone();
    let definition = iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes([
        0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0x48, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8,
        0xa8,
    ])
    .unwrap();
    let world = World::with(
        [],
        [Account::new(wallet.clone()).build(&wallet)],
        [
            AssetDefinition::numeric(definition.clone(), "DS", AssetBalancePolicy::Global, None)
                .build(&wallet),
        ],
    );
    let policy = AssetUidPolicyV1 {
        asset_definition_id: definition.clone(),
        uid: [7; 32],
        revision: 1,
        accounts: BTreeSet::from([wallet.clone()]),
        holding_limit: Some(100_u32.into()),
        daily_window: AssetUidDailyWindowV1::UtcDay,
        daily_spend_limit: None,
        daily_outgoing_limit: None,
    };
    {
        let mut records = world.smart_contract_state.block();
        records.insert(
            asset_uid::policy_key(&definition, &policy.uid),
            norito::encode_canonical(&policy).unwrap(),
        );
        records.insert(
            asset_uid::binding_key(&definition, &wallet),
            norito::encode_canonical(&AssetUidBindingV1 {
                asset_definition_id: definition.clone(),
                account_id: wallet.clone(),
                uid: policy.uid,
            })
            .unwrap(),
        );
        records.commit();
    }
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 1_000, 0);
    if capture_cut {
        state
            .block(header.clone())
            .commit_empty_block_for_testing()
            .unwrap();
        state.update_latest_block_header_cache_for_tests(header);
    }
    (
        state,
        FindAssetUidPoliciesV1 {
            asset_definition_id: definition,
            uid: Some([7; 32]),
            wallet_account_id: Some(wallet),
        },
    )
}
fn fixture() -> (State, FindAssetUidPoliciesV1) {
    fixture_with_cut(true)
}
#[test]
fn actual_admitted_route_returns_requested_product_at_captured_time_and_height() {
    let (state, query) = fixture();
    let view = state.view();
    // Replacing the external cache cannot retarget an already captured view.
    state.update_latest_block_header_cache_for_tests(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        None,
        None,
        9_000,
        0,
    ));
    let query_params = params();
    let (mut rows, stats) = super::super::execute::<AssetUidPolicyViewV1, _, Error>(
        query.clone(),
        CompoundPredicate::PASS,
        &query_params,
        OrdinaryCursorMode::Stored,
        Some(limits()),
        &view,
    )
    .unwrap();
    let row = rows.next().unwrap();
    assert_eq!((row.ledger_time_ms, row.as_of_height), (1_000, 1));
    let wallet = row.wallet_holdings.unwrap();
    assert_eq!(Some(wallet.account_id), query.wallet_account_id);
    assert_eq!(wallet.total, Quantity::zero());
    assert_eq!(wallet.pending_incoming, Quantity::zero());
    assert!(rows.next().is_none());
    assert!(
        stats.processed_items() >= 12,
        "both native ownership passes share metered lookups"
    );
}
#[test]
fn wallet_selection_requires_exact_existing_policy_and_reciprocal_member() {
    let (state, query) = fixture();
    for variant in 0..3 {
        let mut request = query.clone();
        match variant {
            0 => request.uid = None,
            1 => request.uid = Some([8; 32]),
            _ => request.wallet_account_id = Some(iroha_test_samples::BOB_ID.clone()),
        }
        assert!(
            collect_asset_uid_policies(
                &request,
                &params(),
                OrdinaryCursorMode::Stored,
                limits(),
                &state.view()
            )
            .is_err()
        );
    }
}
#[test]
fn legacy_unadmitted_wallet_route_refuses_but_aggregate_remains_explicit_none() {
    let (state, mut query) = fixture();
    assert!(
        super::super::execute::<AssetUidPolicyViewV1, _, Error>(
            query.clone(),
            CompoundPredicate::PASS,
            &params(),
            OrdinaryCursorMode::Stored,
            None,
            &state.view()
        )
        .is_err()
    );
    query.wallet_account_id = None;
    let (mut rows, _) = collect_asset_uid_policies(
        &query,
        &params(),
        OrdinaryCursorMode::Stored,
        limits(),
        &state.view(),
    )
    .unwrap();
    assert!(rows.next().unwrap().wallet_holdings.is_none());
}
#[test]
fn missing_authenticated_cut_and_oversized_binding_refuse_without_wallet_zero() {
    let (state, query) = fixture();
    let (unanchored, unanchored_query) = fixture_with_cut(false);
    let error = collect_asset_uid_policies(
        &unanchored_query,
        &params(),
        OrdinaryCursorMode::Stored,
        limits(),
        &unanchored.view(),
    )
    .err()
    .expect("missing authenticated cut");
    assert!(
        matches!(error, Error::Conversion(message) if message.contains("authenticated ledger time"))
    );
    {
        let mut values = state.world.smart_contract_state.block();
        values.insert(
            asset_uid::binding_key(
                &query.asset_definition_id,
                query.wallet_account_id.as_ref().unwrap(),
            ),
            vec![0; 16_385],
        );
        values.commit();
    }
    assert!(
        collect_asset_uid_policies(
            &query,
            &params(),
            OrdinaryCursorMode::Stored,
            limits(),
            &state.view()
        )
        .is_err()
    );
}
