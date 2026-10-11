//! Narrow authorization reads use real original readers and protected native catalog bytes.

use super::*;
use crate::query::store::LiveQueryStore;
use norito::DecodeLimits;
use std::cell::Cell as LocalCell;

fn run(test: impl FnOnce() + Send + 'static) {
    let result = std::thread::Builder::new()
        .name("authorization-reader-test".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(test)
        .expect("spawn original State reader test")
        .join();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

fn state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn context(allocated: usize) -> DecodeBudgetContext {
    let pool = iroha_allocation::AllocationBudget::new(2 * 1024 * 1024);
    DecodeBudgetContext::try_new_owned(
        DecodeLimits::new(100_000, 1024 * 1024, 100_000, allocated, 32),
        &pool,
    )
    .expect("original caller admits its cumulative counter")
}

fn header(height: u64, previous: Option<HashOf<BlockHeader>>, time: u64) -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(height).unwrap(), previous, None, time, 0)
}

/// Isolated source-owner fixture, not a signed global catalog activation proof.
fn install_catalog(state: &State, catalog: NexusRuntimeCatalogV1) {
    let mut notice = state.state_view_publication();
    let publication = notice.begin();
    let mut world = state.world.block();
    world
        .parameters
        .get_mut()
        .set_parameter(iroha_data_model::parameter::Parameter::Custom(
            catalog
                .into_custom_parameter()
                .expect("canonical protected fixture"),
        ));
    world.commit();
    drop(publication);
    drop(notice);
}

// Native runtime additions bind their identity to this exact manifest hash.
const ADDITIVE_MANIFEST_HASH: [u8; 32] = [9; 32];
const ADDITIVE_DATASPACE_ID: DataSpaceId = DataSpaceId::from_hash(&ADDITIVE_MANIFEST_HASH);

fn additive_catalog(state: &State) -> NexusRuntimeCatalogV1 {
    NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: iroha_data_model::nexus::dataspace_catalog_hash(
            &state.nexus.read().configured_dataspace_catalog,
        ),
        baseline_manifests_hash: Hash::prehashed(
            state
                .lane_manifests
                .read()
                .baseline_consensus_policy_digest(),
        ),
        dataspaces: vec![RuntimeDataSpaceAdditionV1 {
            descriptor: DataSpaceMetadata {
                id: ADDITIVE_DATASPACE_ID,
                alias: "nine".to_owned(),
                description: Some("retained committed descriptor".to_owned()),
                fault_tolerance: 1,
            },
            manifest_hash: ADDITIVE_MANIFEST_HASH,
        }],
        manifests: vec![],
    }
}

fn install_additive_runtime(state: &State) {
    let mut notice = state.state_view_publication();
    let publication = notice.begin();
    let mut runtime = state.canonical_runtime.block();
    runtime
        .get_mut()
        .owner_policy
        .dataspaces
        .push(SnapshotDataSpaceMetadata {
            id: ADDITIVE_DATASPACE_ID,
            alias: "nine".to_owned(),
            fault_tolerance: 1,
        });
    runtime.get_mut().lane_count = 2;
    runtime
        .get_mut()
        .lanes
        .push(iroha_data_model::nexus::LaneConfig {
            id: LaneId::new(1),
            alias: "nine-lane".to_owned(),
            dataspace_id: ADDITIVE_DATASPACE_ID,
            ..Default::default()
        });
    runtime.commit();
    drop(publication);
    drop(notice);
}

#[test]
fn authorization_reader_borrows_baseline_and_runs_callback_once() {
    run(|| {
        let state = state();
        let configured = state.nexus.read();
        let runtime = state.canonical_runtime.view();
        let calls = LocalCell::new(0);
        let counter = context(1024 * 1024);
        let height = state
            .try_with_authorization_view(&counter, |view| {
                calls.set(calls.get() + 1);
                assert!(std::ptr::eq(
                    view.catalog().by_id(DataSpaceId::UNIVERSAL).unwrap(),
                    configured
                        .configured_dataspace_catalog
                        .by_id(DataSpaceId::UNIVERSAL)
                        .unwrap(),
                ));
                assert!(std::ptr::eq(
                    view.active_lanes().as_ptr(),
                    runtime.lanes.as_ptr()
                ));
                assert_eq!(view.ledger_time_ms(), 0);
                assert_eq!(view.generation() % 2, 0);
                assert!(view.world().dataspace_catalog.entries().is_empty());
                view.height()
            })
            .unwrap();
        assert_eq!((height, calls.get()), (0, 1));
    });
}

#[test]
fn authorization_reader_refuses_busy_sources_without_replaying_callback() {
    run(|| {
        let state = state();
        let calls = LocalCell::new(0);
        let counter = context(1024 * 1024);
        state.with_held_header_for_reader_test(|_| {
            assert!(matches!(
                state.try_with_authorization_view(&counter, |_| calls.set(1)),
                Err(StateViewError::Busy(_))
            ));
        });
        let mut notice = state.state_view_publication();
        let publication = notice.begin();
        assert!(matches!(
            state.try_with_authorization_view(&counter, |_| calls.set(2)),
            Err(StateViewError::Busy(_))
        ));
        drop(publication);
        drop(notice);
        assert_eq!(calls.get(), 0);
        state
            .try_with_authorization_view(&counter, |_| calls.set(3))
            .unwrap();
        assert_eq!(calls.get(), 3);
    });
}

#[test]
fn authorization_reader_joins_two_real_successor_frontiers_and_times() {
    run(|| {
        let state = state();
        let first = header(1, None, 111);
        let second = header(2, Some(first.hash()), 222);
        let counter = context(1024 * 1024);
        state.append_committed_block_header_for_tests(first);
        let first_view = state
            .try_with_authorization_view(&counter, |view| {
                (view.height(), view.ledger_time_ms(), view.generation())
            })
            .unwrap();
        state.append_committed_block_header_for_tests(second);
        let second_view = state
            .try_with_authorization_view(&counter, |view| {
                (view.height(), view.ledger_time_ms(), view.generation())
            })
            .unwrap();
        assert_eq!((first_view.0, first_view.1), (1, 111));
        assert_eq!((second_view.0, second_view.1), (2, 222));
        assert!(second_view.2 > first_view.2);
        *state.latest_block_header.write() = None;
        assert!(
            matches!(
                state.try_with_authorization_view(&counter, |_| ()),
                Err(StateViewError::Runtime(_))
            ),
            "committed hashes without authenticated tip cannot invent ledger time"
        );
    });
}

#[test]
fn authorization_reader_uses_committed_additions_and_the_supplied_counter() {
    run(|| {
        let state = state();
        install_catalog(&state, additive_catalog(&state));
        install_additive_runtime(&state);
        let counter = context(1024 * 1024);
        let before = counter.consumed_allocated_bytes();
        state
            .try_with_authorization_view(&counter, |view| {
                let entry = view.catalog().by_alias("nine").unwrap();
                assert_eq!(entry.id, ADDITIVE_DATASPACE_ID);
                assert!(std::ptr::eq(
                    entry,
                    view.catalog().by_id(ADDITIVE_DATASPACE_ID).unwrap()
                ));
                assert_eq!(view.active_lanes()[1].dataspace_id, entry.id);
            })
            .unwrap();
        assert!(counter.consumed_allocated_bytes() > before);
        let after = counter.consumed_allocated_bytes();
        state.try_with_authorization_view(&counter, |_| ()).unwrap();
        assert!(
            counter.consumed_allocated_bytes() > after,
            "a second read cannot reset the original counter"
        );
        let calls = LocalCell::new(0);
        let refused = context(0);
        assert!(matches!(
            state.try_with_authorization_view(&refused, |_| calls.set(1)),
            Err(StateViewError::Runtime(_))
        ));
        assert_eq!(calls.get(), 0);
    });
}

#[test]
fn authorization_reader_rejects_malformed_or_foreign_catalog_authority() {
    run(|| {
        let state = state();
        let counter = context(1024 * 1024);
        let mut foreign = additive_catalog(&state);
        foreign.baseline_dataspaces_hash = Hash::new(b"foreign baseline");
        install_catalog(&state, foreign);
        install_additive_runtime(&state);
        assert!(matches!(
            state.try_with_authorization_view(&counter, |_| ()),
            Err(StateViewError::Runtime(_))
        ));
        let mut foreign = additive_catalog(&state);
        foreign.baseline_manifests_hash = Hash::new(b"foreign manifest source");
        install_catalog(&state, foreign);
        assert!(matches!(
            state.try_with_authorization_view(&counter, |_| ()),
            Err(StateViewError::Runtime(_))
        ));
        install_catalog(&state, additive_catalog(&state));
        let mut retained = state.canonical_runtime.block();
        retained.get_mut().owner_policy.dataspaces[1].alias = "substituted".to_owned();
        retained.commit();
        assert!(matches!(
            state.try_with_authorization_view(&counter, |_| ()),
            Err(StateViewError::Runtime(_))
        ));
        let mut world = state.world.block();
        world
            .parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                iroha_data_model::parameter::CustomParameter::new(
                    NexusRuntimeCatalogV1::parameter_id(),
                    iroha_primitives::json::Json::new(norito::json!({"version": 255})),
                ),
            ));
        world.commit();
        assert!(matches!(
            state.try_with_authorization_view(&counter, |_| ()),
            Err(StateViewError::Runtime(_))
        ));
    });
}
