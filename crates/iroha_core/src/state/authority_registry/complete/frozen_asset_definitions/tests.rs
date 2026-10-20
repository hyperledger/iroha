//! Actual seven-original histories, semantic precedence and retained encoding custody.
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{
        State, World,
        authority_registry::{
            complete::{
                capture_asset_definitions_once, table_capture::frozen::capture_original_table_once,
            },
            grouped_ownership::{
                GroupImage, GroupMismatch, GroupedOwnershipError,
                asset_definition_test_support as fixture,
            },
        },
        block_field::BlockField,
    },
};
use iroha_data_model::{account::Account, block::BlockHeader, prelude::Registrable};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::{BlockRetirement as _, storage::StorageReadOnly};
use norito::codec::Encode;
use std::num::NonZeroU64;
fn state(world: World) -> State {
    State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0)
}
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 64,
        max_payload_bytes: 65536,
        max_ordered_table_bytes: 131_072,
        max_streamed_value_bytes: 131_072,
    }
}
fn other_domain() -> DomainId {
    DomainId::try_new("other", "universal").unwrap()
}
fn unused_domain() -> DomainId {
    DomainId::try_new("unused", "universal").unwrap()
}
fn initial(more_pending: bool) -> World {
    World::with(
        [
            Domain::new(fixture::domain()).build(&ALICE_ID),
            Domain::new(unused_domain()).build(&ALICE_ID),
        ],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [
            fixture::definition(0, &ALICE_ID, true, Some(41)),
            fixture::definition(2, &ALICE_ID, false, None),
            fixture::definition(3, &ALICE_ID, true, more_pending.then_some(41)),
        ],
    )
}
fn changed() -> AssetDefinition {
    let mut value = AssetDefinition::numeric(
        fixture::id(0),
        "coin0",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(other_domain()),
    )
    .build(&BOB_ID);
    value.set_confidential_policy(
        *fixture::definition(0, &BOB_ID, false, Some(42)).confidential_policy(),
    );
    value
}
fn expected() -> World {
    World::with(
        [
            Domain::new(fixture::domain()).build(&ALICE_ID),
            Domain::new(other_domain()).build(&ALICE_ID),
        ],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&BOB_ID),
        ],
        [
            changed(),
            fixture::definition(1, &ALICE_ID, true, Some(42)),
            fixture::definition(2, &ALICE_ID, false, None),
        ],
    )
}
fn freeze(block: &mut StateBlock<'_>) {
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}
fn stage(block: &mut StateBlock<'_>) {
    block
        .world
        .asset_definitions
        .insert(fixture::id(0), changed());
    block.world.asset_definitions.insert(
        fixture::id(1),
        fixture::definition(1, &ALICE_ID, true, Some(42)),
    );
    block.world.asset_definitions.insert(
        fixture::id(2),
        fixture::definition(2, &ALICE_ID, false, None),
    );
    block.world.asset_definitions.remove(fixture::id(3));
    block.world.asset_definitions.remove(fixture::id(99));
    block.world.domains.insert(
        fixture::domain(),
        Domain::new(fixture::domain()).build(&ALICE_ID),
    );
    block
        .world
        .domains
        .insert(other_domain(), Domain::new(other_domain()).build(&ALICE_ID));
    block.world.domains.remove(unused_domain());
    block
        .world
        .asset_definition_domains
        .insert(fixture::id(0), other_domain());
    block
        .world
        .asset_definition_domains
        .insert(fixture::id(1), fixture::domain());
    block.world.asset_definition_domains.remove(fixture::id(3));
    block.world.asset_definition_domains.remove(fixture::id(99));
    macro_rules! reset_members {
        ($field:ident, $rows:expr) => {{
            let old: Vec<_> = block
                .world
                .$field
                .iter()
                .map(|(key, ())| key.clone())
                .collect();
            for key in old {
                block.world.$field.remove(key);
            }
            for key in $rows {
                block.world.$field.insert(key, ());
            }
        }};
    }
    reset_members!(
        domain_asset_definitions,
        [
            (fixture::domain(), fixture::id(1)),
            (other_domain(), fixture::id(0)),
        ]
    );
    reset_members!(
        asset_definitions_by_owner,
        [
            (ALICE_ID.clone(), fixture::id(1)),
            (ALICE_ID.clone(), fixture::id(2)),
            (BOB_ID.clone(), fixture::id(0)),
        ]
    );
    block
        .world
        .confidential_policy_transition_index
        .remove((41, fixture::id(0)));
    block
        .world
        .confidential_policy_transition_index
        .insert((42, fixture::id(0)), ());
    block
        .world
        .confidential_policy_transition_index
        .insert((42, fixture::id(1)), ());
    block
        .world
        .confidential_policy_transition_index
        .remove((99, fixture::id(99)));
    block.world.confidential_policy_transition_counts.remove(41);
    block
        .world
        .confidential_policy_transition_counts
        .insert(42, 2);
    block.world.confidential_policy_transition_counts.remove(99);
}
fn exact(original: &Original<'_>) -> u64 {
    fixture::full_work(
        &original.rows,
        &original.domains,
        &original.contexts,
        &original.by_domain,
        &original.by_owner,
        &original.transitions,
        &original.counts,
    )
}
fn equal(actual: &CanonicalTablePairedSnapshot, expected: &CanonicalTablePairedSnapshot) {
    assert_eq!(actual.table_id(), expected.table_id());
    assert_eq!(actual.row_count(), expected.row_count());
    assert_eq!(actual.root(), expected.root());
    assert_eq!(actual.lookup_root(), expected.lookup_root());
    assert_eq!(actual.ordered_root(), expected.ordered_root());
}
#[test]
fn ordinary_definition_owner_domain_transition_insert_delete_noop_and_absent_images() {
    let state = state(initial(false));
    let mut block = state.block(header());
    stage(&mut block);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    assert_eq!(original.rows.mode(), mv::BlockMode::Ordinary);
    assert!(original.rows.undo_entries().any(|(id, prior)| {
        id == &fixture::id(2)
            && prior
                .as_ref()
                .is_some_and(|value| value.owned_by() == &*ALICE_ID)
    }));
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &fixture::id(99) && prior.is_none())
    );
    assert!(
        original
            .contexts
            .undo_entries()
            .any(|(id, prior)| id == &fixture::id(99) && prior.is_none())
    );
    assert!(
        original
            .transitions
            .undo_entries()
            .any(|(key, prior)| key == &(99, fixture::id(99)) && prior.is_none())
    );
    assert!(
        original
            .counts
            .undo_entries()
            .any(|(key, prior)| *key == 99 && prior.is_none())
    );
    let work = exact(&original);
    assert_eq!(
        capture(&block, limits(), work - 1).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    let snapshot = capture(&block, limits(), work).unwrap().unwrap();
    assert_eq!(snapshot.row_count(), 3);
    let control = self::state(expected());
    equal(
        &snapshot,
        &capture_asset_definitions_once(&control, limits())
            .unwrap()
            .unwrap(),
    );
    equal(
        &snapshot,
        &capture_original_table_once(&block, "world.asset_definitions", limits(), work)
            .unwrap()
            .unwrap(),
    );
    let current: Vec<_> = original
        .rows
        .current_entries()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    let view = control.world.asset_definitions.view();
    let control_bytes: Vec<_> = view
        .iter()
        .map(|(id, value)| (id.encode(), value.encode()))
        .collect();
    assert_eq!(current, control_bytes);
}

// Apply the same concrete mutation either to a native tip fixture or the actual
// executing journal. This is test data, never a production provider/publication.
macro_rules! alter {
    ($target:expr,tip,$field:ident,$key:expr,$value:expr) => {{
        let mut field = $target.$field.block();
        match $value {
            Some(value) => {
                field.insert($key, value);
            }
            None => {
                field.remove($key);
            }
        }
        field.commit();
    }};
    ($target:expr,journal,$field:ident,$key:expr,$value:expr) => {{
        match $value {
            Some(value) => {
                $target.$field.insert($key, value);
            }
            None => {
                $target.$field.remove($key);
            }
        }
    }};
}
macro_rules! defect {
    ($target:expr,$kind:ident,$case:expr,$restore:expr) => {{
        let restore = $restore;
        let case = $case;
        match case {
            0 | 1 | 10 => {
                let mut value = fixture::definition(0, &ALICE_ID, true, Some(41));
                if !restore {
                    if case == 0 {
                        value = AssetDefinition::numeric(
                            fixture::id(0),
                            "coin0",
                            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                            None,
                        )
                        .build(&ALICE_ID);
                    }
                    if case == 1 {
                        value = AssetDefinition::numeric(
                            fixture::id(0),
                            "coin0",
                            iroha_data_model::asset::AssetBalancePolicy::Global,
                            Some(other_domain()),
                        )
                        .build(&ALICE_ID);
                    }
                    if case == 10 {
                        let mut policy = *value.confidential_policy();
                        policy.pending_transition.as_mut().unwrap().effective_height = 0;
                        value.set_confidential_policy(policy);
                    }
                }
                alter!(
                    $target,
                    $kind,
                    asset_definitions,
                    fixture::id(0),
                    Some(value)
                );
            }
            2 => alter!(
                $target,
                $kind,
                asset_definition_domains,
                fixture::id(0),
                restore.then(fixture::domain)
            ),
            3 => alter!(
                $target,
                $kind,
                asset_definition_domains,
                fixture::id(99),
                (!restore).then(fixture::domain)
            ),
            4 => alter!(
                $target,
                $kind,
                asset_definitions_by_owner,
                (ALICE_ID.clone(), fixture::id(0)),
                restore.then_some(())
            ),
            5 | 6 => alter!(
                $target,
                $kind,
                asset_definitions_by_owner,
                (BOB_ID.clone(), fixture::id(if case == 5 { 99 } else { 0 })),
                (!restore).then_some(())
            ),
            7 => alter!(
                $target,
                $kind,
                domain_asset_definitions,
                (fixture::domain(), fixture::id(0)),
                restore.then_some(())
            ),
            8 | 9 => alter!(
                $target,
                $kind,
                domain_asset_definitions,
                (unused_domain(), fixture::id(if case == 8 { 99 } else { 0 })),
                (!restore).then_some(())
            ),
            11 => alter!(
                $target,
                $kind,
                confidential_policy_transition_index,
                (41, fixture::id(0)),
                restore.then_some(())
            ),
            12 => alter!(
                $target,
                $kind,
                confidential_policy_transition_index,
                (42, fixture::id(0)),
                (!restore).then_some(())
            ),
            13 => alter!(
                $target,
                $kind,
                confidential_policy_transition_counts,
                41,
                restore.then_some(1)
            ),
            14..=16 => alter!(
                $target,
                $kind,
                confidential_policy_transition_counts,
                41,
                Some(if restore {
                    if case == 15 { 2 } else { 1 }
                } else {
                    match case {
                        14 => 0,
                        15 => 1,
                        _ => 3,
                    }
                })
            ),
            17 => alter!(
                $target,
                $kind,
                confidential_policy_transition_counts,
                99,
                (!restore).then_some(1)
            ),
            _ => unreachable!(),
        }
    }};
}
fn error(case: usize, previous: bool) -> GroupedOwnershipError {
    let image = if previous {
        GroupImage::Predecessor
    } else {
        GroupImage::Current
    };
    let reason = match case {
        0 => Some("restricted definition has no owning domain"),
        1 => Some("owning domain is absent"),
        10 => Some("invalid pending confidential-policy transition"),
        _ => None,
    };
    if let Some(reason) = reason {
        return GroupedOwnershipError::Source {
            table: "world.asset_definitions",
            image,
            reason,
        };
    }
    let index = match case {
        2 | 3 => "world.asset_definition_domains",
        4..=6 => "world.asset_definitions_by_owner",
        7..=9 => "world.domain_asset_definitions",
        11 | 12 => "world.confidential_policy_transition_index",
        _ => "world.confidential_policy_transition_counts",
    };
    let mismatch = match case {
        2 | 4 | 7 | 11 | 13 | 15 => GroupMismatch::MissingMember,
        14 => GroupMismatch::EmptyGroup,
        _ => GroupMismatch::ForeignMember,
    };
    GroupedOwnershipError::Corrupt {
        index,
        image,
        mismatch,
    }
}
#[test]
fn all_existing_context_group_policy_and_count_defects_reject_both_images() {
    for previous in [false, true] {
        for case in 0..18 {
            let state = state(initial(case == 15));
            if previous {
                defect!(state.world, tip, case, false);
            }
            let mut block = state.block(header());
            defect!(block.world, journal, case, previous);
            freeze(&mut block);
            assert_eq!(
                capture(&block, limits(), 0).err(),
                Some(LeafError::GroupedOwnership(
                    GroupedOwnershipError::WorkLimit
                ))
            );
            assert_eq!(
                capture(&block, limits(), 16_777_216).err(),
                Some(LeafError::GroupedOwnership(error(case, previous)))
            );
        }
    }
}

#[test]
fn replace_preserves_actual_rewound_seven_owner_modes_and_predecessors() {
    let state = state(initial(false));
    // Genuine native tip changes create the old pair before replacement.
    {
        let mut tip = state.world.asset_definitions.block();
        tip.insert(fixture::id(0), changed());
        tip.commit();
    }
    {
        let mut tip = state.world.domains.block();
        tip.insert(other_domain(), Domain::new(other_domain()).build(&ALICE_ID));
        tip.commit();
    }
    {
        let mut tip = state.world.asset_definition_domains.block();
        tip.insert(fixture::id(0), other_domain());
        tip.commit();
    }
    {
        let mut tip = state.world.domain_asset_definitions.block();
        tip.remove((fixture::domain(), fixture::id(0)));
        tip.insert((other_domain(), fixture::id(0)), ());
        tip.commit();
    }
    {
        let mut tip = state.world.asset_definitions_by_owner.block();
        tip.remove((ALICE_ID.clone(), fixture::id(0)));
        tip.insert((BOB_ID.clone(), fixture::id(0)), ());
        tip.commit();
    }
    {
        let mut tip = state.world.confidential_policy_transition_index.block();
        tip.remove((41, fixture::id(0)));
        tip.insert((42, fixture::id(0)), ());
        tip.commit();
    }
    {
        let mut tip = state.world.confidential_policy_transition_counts.block();
        tip.remove(41);
        tip.insert(42, 1);
        tip.commit();
    }
    let mut block = state.block_and_revert(header());
    assert_eq!(
        block
            .world
            .asset_definitions
            .get(&fixture::id(0))
            .unwrap()
            .owned_by(),
        &*ALICE_ID
    );
    block.world.asset_definitions.remove(fixture::id(99));
    block.world.asset_definition_domains.remove(fixture::id(99));
    block
        .world
        .confidential_policy_transition_index
        .remove((99, fixture::id(99)));
    block.world.confidential_policy_transition_counts.remove(99);
    freeze(&mut block);
    let original = Original::retain(&block).unwrap();
    for mode in [
        original.rows.mode(),
        original.domains.mode(),
        original.contexts.mode(),
        original.by_domain.mode(),
        original.by_owner.mode(),
        original.transitions.mode(),
        original.counts.mode(),
    ] {
        assert_eq!(mode, mv::BlockMode::Replace);
    }
    assert!(
        original
            .rows
            .undo_entries()
            .any(|(id, prior)| id == &fixture::id(99) && prior.is_none())
    );
    let control = self::state(initial(false));
    equal(
        &capture(&block, limits(), exact(&original))
            .unwrap()
            .unwrap(),
        &capture_asset_definitions_once(&control, limits())
            .unwrap()
            .unwrap(),
    );
    assert_ne!(
        capture_asset_definitions_once(&state, limits())
            .unwrap()
            .unwrap()
            .root(),
        capture(&block, limits(), 16_777_216)
            .unwrap()
            .unwrap()
            .root()
    );
}

#[test]
fn each_foreign_released_partial_and_mixed_mode_original_refuses() {
    for source in 0..7 {
        for mixed in [false, true] {
            let state = state(initial(false));
            let foreign = self::state(initial(false));
            let mut block = state.block(header());
            assert!(capture(&block, limits(), 0).unwrap().is_none());
            let target = if mixed { &state } else { &foreign };
            macro_rules! replace {
                ($field:ident) => {{
                    block.world.$field.release_writers();
                    block.world.$field = BlockField::new(if mixed {
                        target.world.$field.block_and_revert()
                    } else {
                        target.world.$field.block()
                    });
                }};
            }
            match source {
                0 => replace!(asset_definitions),
                1 => replace!(domains),
                2 => replace!(asset_definition_domains),
                3 => replace!(domain_asset_definitions),
                4 => replace!(asset_definitions_by_owner),
                5 => replace!(confidential_policy_transition_index),
                6 => replace!(confidential_policy_transition_counts),
                _ => unreachable!(),
            }
            freeze(&mut block);
            assert!(capture(&block, limits(), 0).unwrap().is_none());
        }
    }
    for source in 0..7 {
        let state = state(initial(false));
        let mut block = state.block(header());
        freeze(&mut block);
        match source {
            0 => block.world.asset_definitions.release_writers(),
            1 => block.world.domains.release_writers(),
            2 => block.world.asset_definition_domains.release_writers(),
            3 => block.world.domain_asset_definitions.release_writers(),
            4 => block.world.asset_definitions_by_owner.release_writers(),
            5 => block
                .world
                .confidential_policy_transition_index
                .release_writers(),
            6 => block
                .world
                .confidential_policy_transition_counts
                .release_writers(),
            _ => unreachable!(),
        }
        assert!(capture(&block, limits(), 0).unwrap().is_none());
    }
    let state = state(initial(false));
    let mut block = state.block(header());
    block.world.asset_definitions.begin_freeze();
    block.world.asset_definitions.finish_freeze();
    assert!(capture(&block, limits(), 0).unwrap().is_none());
}
#[test]
fn original_asset_pool_work_row_payload_retry_and_last_owner_refund() {
    let _pin = crossbeam_epoch::pin();
    let state = state(initial(false));
    let pool = state.ivm_execution_budget();
    let limit = pool.limit_bytes();
    let mut block = state.block(header());
    stage(&mut block);
    let pointer = core::ptr::from_ref(block.world.asset_definitions.get(&fixture::id(0)).unwrap());
    freeze(&mut block);
    let baseline = pool.reserved_bytes();
    assert_eq!(
        capture(&block, limits(), 0).err(),
        Some(LeafError::GroupedOwnership(
            GroupedOwnershipError::WorkLimit
        ))
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture(&block, limits(), 16_777_216),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(limit);
    for (small, error) in [
        (
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            LeafError::RowLimit,
        ),
        (
            LeafLimits {
                max_payload_bytes: 0,
                ..limits()
            },
            LeafError::PayloadLimit,
        ),
    ] {
        assert_eq!(capture(&block, small, 16_777_216).err(), Some(error));
        assert_eq!(pool.reserved_bytes(), baseline);
    }
    let snapshot = std::sync::Arc::new(capture(&block, limits(), 16_777_216).unwrap().unwrap());
    assert!(pool.reserved_bytes() > baseline);
    assert_eq!(
        core::ptr::from_ref(block.world.asset_definitions.get(&fixture::id(0)).unwrap()),
        pointer
    );
    let retained = snapshot.clone();
    drop(snapshot);
    assert!(pool.reserved_bytes() > baseline);
    drop(retained);
    assert_eq!(pool.reserved_bytes(), baseline);
}
#[test]
fn later_equal_or_changed_publications_cannot_refresh_any_frozen_asset_original() {
    for source in 0..7 {
        for changed_value in [false, true] {
            let state = state(initial(false));
            let mut block = state.block(header());
            stage(&mut block);
            freeze(&mut block);
            let snapshot = capture(&block, limits(), 16_777_216).unwrap().unwrap();
            let original = Original::retain(&block).unwrap();
            let identity = original.rows.publication_identity();
            macro_rules! publish {
                ($field:ident,$key:expr,$value:expr) => {{
                    let mut target = state.world.$field.block();
                    if changed_value {
                        target.insert($key, $value);
                    }
                    target.commit();
                }};
            }
            match source {
                0 => publish!(
                    asset_definitions,
                    fixture::id(99),
                    fixture::definition(99, &ALICE_ID, false, None)
                ),
                1 => publish!(
                    domains,
                    other_domain(),
                    Domain::new(other_domain()).build(&ALICE_ID)
                ),
                2 => publish!(asset_definition_domains, fixture::id(99), other_domain()),
                3 => publish!(
                    domain_asset_definitions,
                    (other_domain(), fixture::id(99)),
                    ()
                ),
                4 => publish!(
                    asset_definitions_by_owner,
                    (BOB_ID.clone(), fixture::id(99)),
                    ()
                ),
                5 => publish!(
                    confidential_policy_transition_index,
                    (99, fixture::id(99)),
                    ()
                ),
                6 => publish!(confidential_policy_transition_counts, 99, 1),
                _ => unreachable!(),
            }
            assert_eq!(original.rows.publication_identity(), identity);
            equal(
                &snapshot,
                &capture(&block, limits(), 16_777_216).unwrap().unwrap(),
            );
        }
    }
}
