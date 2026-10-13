// Canonical fanout admission tests exercise the snapshot-owned query guards.
use iroha_data_model::query::dsl::CompoundPredicate;
fn canonical_reader_world(mut world: World) -> World {
    let permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::query::CanReadAllLedgerData.into();
    world
        .account_permissions
        .insert(ALICE_ID.clone(), [permission].into_iter().collect());
    world
}
fn assert_opaque_canonical_start_rejected(error: SnapshotQueryError) {
    assert!(matches!(error, SnapshotQueryError::Execution(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message)
    ) if message == "canonical fanout rejects opaque canonical starts before nested payload, predicate, or selector decoding"));
}
fn canonical_test_limits(max_items: u64) -> QueryLimits {
    use crate::smartcontracts::isi::query::{
        CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES, CanonicalQueryOutputLimits,
    };
    QueryLimits::from_defaults().with_canonical_output_limits(CanonicalQueryOutputLimits::new(
        max_items,
        CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES,
        1024 * 1024,
        8 * 1024 * 1024,
        8 * 1024 * 1024,
    ))
}
fn find_role_ids_start(
    params: QueryParams,
    selector: iroha_data_model::query::dsl::SelectorTuple<RoleId>,
) -> QueryRequest {
    find_role_ids_start_with_predicate(
        params,
        iroha_data_model::query::dsl::CompoundPredicate::PASS,
        selector,
    )
}
fn find_role_ids_start_with_predicate(
    params: QueryParams,
    predicate: iroha_data_model::query::dsl::CompoundPredicate<RoleId>,
    selector: iroha_data_model::query::dsl::SelectorTuple<RoleId>,
) -> QueryRequest {
    let payload =
        norito::codec::Encode::encode(&iroha_data_model::query::role::prelude::FindRoleIds);
    let erased =
        iroha_data_model::query::ErasedIterQuery::<RoleId>::new(predicate, selector, payload);
    let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
    QueryRequest::Start(
        iroha_data_model::query::QueryWithParams::new(&qbox, params)
            .expect("role-id query type has a canonical mapping"),
    )
}
#[test]
fn canonical_role_ids_rejects_large_filter_before_source_execution() {
    let predicate = CompoundPredicate::<RoleId>::build(|prototype| {
        prototype.exists("untrusted-filter-path-".repeat(64 * 1024))
    });
    let world = World::with_assets_and_roles(
        [],
        [alice_account()],
        [],
        [],
        [],
        [
            Role::new("canonical-role".parse().expect("role id"), ALICE_ID.clone())
                .build(&ALICE_ID),
        ],
    );
    let store = LiveQueryStore::start_test();
    let state = Arc::new(State::new_with_chain(
        canonical_reader_world(world),
        Kura::blank_kura_for_testing(),
        store.clone(),
        ChainId::from("canonical-filter-rejection"),
    ));
    let error = run_on_snapshot_ephemeral_with_budget_arc(
        &state,
        &store,
        &ALICE_ID,
        find_role_ids_start_with_predicate(
            QueryParams::default(),
            predicate,
            SelectorTuple::default(),
        ),
        canonical_test_limits(1),
        QueryExecutionBudget::from_weighted_limit(1024 * 1024, 1, 1),
    )
    .expect_err("filtered role IDs must reject before source execution");
    assert_opaque_canonical_start_rejected(error);
}
#[test]
fn budgeted_arc_snapshot_canonical_mode_rejects_an_opaque_start_with_bounded_pagination() {
    let domain = Domain::new(DomainId::try_new("canonical", "universal").expect("domain id"))
        .build(&ALICE_ID);
    let roles = ["canonical-z", "canonical-a", "canonical-m"]
        .map(|name| Role::new(name.parse().expect("role id"), ALICE_ID.clone()).build(&ALICE_ID));
    let world = World::with_assets_and_roles([domain], [alice_account()], [], [], [], roles);
    let store = LiveQueryStore::start_test();
    let state = Arc::new(State::new_with_chain(
        canonical_reader_world(world),
        Kura::blank_kura_for_testing(),
        store.clone(),
        ChainId::from("canonical-snapshot"),
    ));
    let params = QueryParams {
        pagination: Pagination::new(Some(nonzero_ext::nonzero!(2_u64)), 1),
        ..QueryParams::default()
    };
    let error = run_on_snapshot_ephemeral_with_budget_arc(
        &state,
        &store,
        &ALICE_ID,
        find_role_ids_start(
            params,
            iroha_data_model::query::dsl::SelectorTuple::default(),
        ),
        canonical_test_limits(3),
        QueryExecutionBudget::from_weighted_limit(16 * 1024 * 1024, 1, 1),
    )
    .expect_err("bounded pagination cannot authorize opaque canonical source decoding");
    assert_opaque_canonical_start_rejected(error);
}
#[test]
fn budgeted_arc_snapshot_canonical_mode_rejects_unbounded_domain_source() {
    let domain =
        Domain::new(DomainId::try_new("canonical-unbounded", "universal").expect("domain id"))
            .build(&ALICE_ID);
    let world = World::with([domain], [alice_account()], []);
    let store = LiveQueryStore::start_test();
    let state = Arc::new(State::new_with_chain(
        canonical_reader_world(world),
        Kura::blank_kura_for_testing(),
        store.clone(),
        ChainId::from("canonical-source-rejection"),
    ));
    let error = run_on_snapshot_ephemeral_with_budget_arc(
        &state,
        &store,
        &ALICE_ID,
        find_domains_start(QueryParams::default()),
        canonical_test_limits(1),
        QueryExecutionBudget::from_weighted_limit(16 * 1024 * 1024, 1, 1),
    )
    .expect_err("unbounded domain rows must be rejected before query execution");
    assert_opaque_canonical_start_rejected(error);
}
#[test]
fn canonical_roles_by_large_multisig_rejects_before_concrete_payload_decode() {
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let members = (1_u8..=128)
        .map(|seed| {
            let keypair = iroha_crypto::KeyPair::try_from_seed(
                vec![seed; 32],
                iroha_crypto::Algorithm::Ed25519,
            )
            .expect("deterministic member key");
            MultisigMember::new(keypair.public_key().clone(), 1).expect("multisig member")
        })
        .collect();
    let account_id = AccountId::new_multisig(
        MultisigPolicy::new(1, members).expect("large valid multisig policy"),
    );
    let payload = norito::codec::Encode::encode(
        &iroha_data_model::query::role::prelude::FindRolesByAccountId::new(account_id),
    );
    let erased = iroha_data_model::query::ErasedIterQuery::<RoleId>::new(
        CompoundPredicate::PASS,
        SelectorTuple::default(),
        payload,
    );
    let qbox: iroha_data_model::query::QueryBox<_> = Box::new(erased);
    let request = QueryRequest::Start(
        iroha_data_model::query::QueryWithParams::new(&qbox, QueryParams::default())
            .expect("role-id query type has a canonical mapping"),
    );
    let world = World::with([], [alice_account()], []);
    let store = LiveQueryStore::start_test();
    let state = Arc::new(State::new_with_chain(
        canonical_reader_world(world),
        Kura::blank_kura_for_testing(),
        store.clone(),
        ChainId::from("canonical-multisig-rejection"),
    ));
    let error = run_on_snapshot_ephemeral_with_budget_arc(
        &state,
        &store,
        &ALICE_ID,
        request,
        canonical_test_limits(1),
        QueryExecutionBudget::from_weighted_limit(1024 * 1024, 1, 1),
    )
    .expect_err("parameterized multisig query must reject before payload decode");
    assert_opaque_canonical_start_rejected(error);
}
#[test]
fn canonical_opaque_start_rejects_before_nested_component_decode() {
    let world = World::with([], [alice_account()], []);
    let store = LiveQueryStore::start_test();
    let state = Arc::new(State::new_with_chain(
        canonical_reader_world(world),
        Kura::blank_kura_for_testing(),
        store.clone(),
        ChainId::from("canonical-opaque-rejection"),
    ));
    let error = run_on_snapshot_ephemeral_with_budget_arc(
        &state,
        &store,
        &ALICE_ID,
        find_domains_start(QueryParams::default()),
        canonical_test_limits(1),
        QueryExecutionBudget::from_weighted_limit(1024 * 1024, 1, 1),
    )
    .expect_err("opaque canonical start must fail closed");
    assert_opaque_canonical_start_rejected(error);
}
