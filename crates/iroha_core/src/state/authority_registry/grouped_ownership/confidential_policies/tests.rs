//! Pending policy checks retain actual source/index images without allocation.

use super::*;
use crate::test_allocations::allocations_during;
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::{
        AssetBalancePolicy,
        definition::{
            AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
        },
    },
    prelude::Registrable,
};
use iroha_test_samples::ALICE_ID;

fn id(number: usize) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("policies", "universal").unwrap(),
        format!("coin{number}").parse().unwrap(),
    )
}

fn definition(number: usize, height: Option<u64>) -> AssetDefinition {
    let mut definition = AssetDefinition::numeric(
        id(number),
        format!("coin{number}"),
        AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let mut policy = AssetConfidentialPolicy::convertible();
    policy.pending_transition = height.map(|height| ConfidentialPolicyTransition {
        new_mode: ConfidentialPolicyMode::ShieldedOnly,
        effective_height: height,
        previous_mode: ConfidentialPolicyMode::Convertible,
        transition_id: Hash::new(number.to_le_bytes()),
        conversion_window: Some(1),
    });
    definition.set_confidential_policy(policy);
    definition
}

fn fixture() -> World {
    let mut world = World::default();
    for number in 0..3 {
        world
            .asset_definitions
            .insert(id(number), definition(number, (number < 2).then_some(41)));
    }
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    world
}

fn validate(world: &World, max_work: u64) -> Result<(), GroupedOwnershipError> {
    let definitions = world.asset_definitions.try_committed_view_nonblocking()?;
    let policies = RetainedConfidentialPolicies::retain(world)?;
    let outcome = policies.validate(&definitions, &mut AssetDefinitionWork::bounded(max_work));
    // Mirror the enclosing checked capture: identity changes take precedence
    // even when validation found malformed data or exhausted its local work.
    let sources_current = definitions.try_matches_current(&world.asset_definitions)?;
    let indexes_current = policies.matches_current()?;
    if !sources_current || !indexes_current {
        return Err(PublicationPreparationError::Changed.into());
    }
    outcome
}

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(validate(world, work))),
        0,
        "checked projection must not allocate its source or index scratch"
    );
    result.unwrap()
}

fn image(previous: bool) -> GroupImage {
    if previous {
        GroupImage::Predecessor
    } else {
        GroupImage::Current
    }
}

fn corrupt(index: &'static str, previous: bool, mismatch: GroupMismatch) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index,
        image: image(previous),
        mismatch,
    }
}

#[test]
fn consumed_moved_and_redundant_transitions_keep_both_original_images() {
    let mut world = fixture();
    {
        let mut block = world.asset_definitions.block();
        block.insert(id(0), definition(0, None));
        block.insert(id(1), definition(1, Some(42)));
        block.insert(id(2), definition(2, None));
        block.insert(id(3), definition(3, Some(42)));
        block.remove(id(99));
        block.commit();
    }
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    assert_eq!(check(&world, 16_777_216), Ok(()));
    let rows = world
        .asset_definitions
        .try_committed_view_nonblocking()
        .unwrap();
    let policies = RetainedConfidentialPolicies::retain(&world).unwrap();
    assert!(get_at(&policies.transitions, GroupImage::Current, &(41, id(0))).is_none());
    assert_eq!(
        get_at(&policies.transitions, GroupImage::Predecessor, &(41, id(0))),
        Some(&())
    );
    assert_eq!(get_at(&policies.counts, GroupImage::Current, &42), Some(&2));
    assert_eq!(
        get_at(&policies.counts, GroupImage::Predecessor, &41),
        Some(&2)
    );
    assert!(rows.undo().contains_key(&id(2)));
    assert!(rows.undo().contains_key(&id(99)));
    assert!(policies.matches_current().unwrap());
    drop((rows, policies));
    world.block_and_revert().commit();
    assert_eq!(check(&world, 16_777_216), Ok(()));
}

#[test]
fn both_legal_directions_and_absent_transitions_need_no_zk_asset_row() {
    let mut world = fixture();
    let mut returning = definition(3, Some(41));
    let mut policy = AssetConfidentialPolicy::shielded_only();
    policy.pending_transition = Some(ConfidentialPolicyTransition {
        new_mode: ConfidentialPolicyMode::Convertible,
        effective_height: 41,
        previous_mode: ConfidentialPolicyMode::ShieldedOnly,
        transition_id: Hash::new(b"returning-policy"),
        conversion_window: None,
    });
    returning.set_confidential_policy(policy);
    world.asset_definitions.insert(id(3), returning);
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    assert!(world.zk_assets.view().iter().next().is_none());
    assert_eq!(check(&world, 16_777_216), Ok(()));
}

#[test]
fn invalid_pending_shape_rejects_before_index_inspection_in_either_image() {
    for previous in [false, true] {
        for defect in 0..6 {
            let mut world = fixture();
            let mut malformed = definition(0, Some(41));
            let mut policy = *malformed.confidential_policy();
            let transition = policy.pending_transition.as_mut().unwrap();
            match defect {
                0 => transition.previous_mode = ConfidentialPolicyMode::ShieldedOnly,
                1 => transition.new_mode = ConfidentialPolicyMode::TransparentOnly,
                2 => transition.new_mode = ConfidentialPolicyMode::Convertible,
                3 => transition.effective_height = 0,
                4 => transition.conversion_window = None,
                5 => transition.conversion_window = Some(42),
                _ => unreachable!(),
            }
            malformed.set_confidential_policy(policy);
            world.asset_definitions.insert(id(0), malformed);
            if previous {
                let mut block = world.asset_definitions.block();
                block.insert(id(0), definition(0, Some(41)));
                block.commit();
            }
            assert_eq!(
                check(&world, 16_777_216),
                Err(GroupedOwnershipError::Source {
                    table: "world.asset_definitions",
                    image: image(previous),
                    reason: "invalid pending confidential-policy transition",
                })
            );
        }
    }
}

#[test]
fn missing_wrong_extra_and_foreign_transition_rows_reject_in_either_image() {
    for previous in [false, true] {
        for defect in 0..4 {
            let mut world = fixture();
            let bad_key = if defect == 3 {
                (41, id(99))
            } else {
                (42, id(0))
            };
            if defect < 2 {
                world.confidential_policy_transition_index =
                    [((41, id(1)), ())].into_iter().collect();
            }
            if defect != 0 {
                world
                    .confidential_policy_transition_index
                    .insert(bad_key.clone(), ());
            }
            if previous {
                let mut block = world.confidential_policy_transition_index.block();
                block.insert((41, id(0)), ());
                block.remove(bad_key);
                block.commit();
            }
            assert_eq!(
                check(&world, 16_777_216),
                Err(corrupt(
                    TRANSITIONS,
                    previous,
                    if defect < 2 {
                        GroupMismatch::MissingMember
                    } else {
                        GroupMismatch::ForeignMember
                    }
                ))
            );
        }
    }
}

#[test]
fn missing_zero_under_over_and_foreign_counts_reject_in_either_image() {
    for previous in [false, true] {
        for defect in 0..5 {
            let mut world = fixture();
            match defect {
                0 => {
                    world.confidential_policy_transition_counts = mv::storage::Storage::new();
                }
                1 => {
                    world.confidential_policy_transition_counts.insert(41, 0);
                }
                2 => {
                    world.confidential_policy_transition_counts.insert(41, 1);
                }
                3 => {
                    world.confidential_policy_transition_counts.insert(41, 3);
                }
                4 => {
                    world.confidential_policy_transition_counts.insert(99, 1);
                }
                _ => unreachable!(),
            }
            if previous {
                let mut block = world.confidential_policy_transition_counts.block();
                block.insert(41, 2);
                block.remove(99);
                block.commit();
            }
            assert_eq!(
                check(&world, 16_777_216),
                Err(corrupt(
                    COUNTS,
                    previous,
                    match defect {
                        0 | 2 => GroupMismatch::MissingMember,
                        1 => GroupMismatch::EmptyGroup,
                        _ => GroupMismatch::ForeignMember,
                    }
                ))
            );
        }
    }
}

#[test]
fn physical_masked_rows_and_tombstones_consume_work_before_filtering() {
    let world = fixture();
    let required = super::super::asset_definitions::test_support::world_policy_work(&world);
    assert_eq!(required, 1710);
    assert_eq!(
        check(&world, required - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    {
        let mut block = world.asset_definitions.block();
        block.insert(id(0), definition(0, Some(41)));
        block.remove(id(99));
        block.commit();
    }
    // The predecessor definition pass and per-height source count each see
    // both the masked old row and its redundant/tombstone undo rows.
    assert_eq!(
        super::super::asset_definitions::test_support::world_policy_work(&world),
        required + 808
    );
    assert_eq!(
        check(&world, required + 808 - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, required + 808), Ok(()));
    {
        let mut block = world.confidential_policy_transition_index.block();
        block.remove((99, id(99)));
        block.commit();
    }
    assert_eq!(
        super::super::asset_definitions::test_support::world_policy_work(&world),
        required + 808 + 300
    );
    assert_eq!(
        check(&world, required + 808),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, required + 808 + 300), Ok(()));
    {
        let mut block = world.confidential_policy_transition_counts.block();
        block.remove(99);
        block.commit();
    }
    assert_eq!(
        super::super::asset_definitions::test_support::world_policy_work(&world),
        required + 808 + 300 + 57
    );
    assert_eq!(
        check(&world, required + 808 + 300),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, required + 808 + 300 + 57), Ok(()));
}

#[test]
fn dense_valid_heights_defer_locally_then_retry_with_more_work() {
    let mut world = World::default();
    for number in 0..128 {
        world
            .asset_definitions
            .insert(id(number), definition(number, Some(number as u64 + 1)));
    }
    world
        .rebuild_confidential_policy_transition_index()
        .unwrap();
    assert_eq!(
        check(&world, 128 * 128),
        Err(GroupedOwnershipError::WorkLimit)
    );
    let required = super::super::asset_definitions::test_support::world_policy_work(&world);
    assert_eq!(required, 5_575_936);
    assert_eq!(
        check(&world, required - 1),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check(&world, required), Ok(()));
}

#[test]
fn every_original_definition_and_policy_index_identity_is_observed() {
    for changed in 0..3 {
        let world = fixture();
        let definitions = world
            .asset_definitions
            .try_committed_view_nonblocking()
            .unwrap();
        let policies = RetainedConfidentialPolicies::retain(&world).unwrap();
        policies
            .validate(&definitions, &mut AssetDefinitionWork::bounded(16_777_216))
            .unwrap();
        match changed {
            0 => world.asset_definitions.block().commit(),
            1 => world.confidential_policy_transition_index.block().commit(),
            2 => world.confidential_policy_transition_counts.block().commit(),
            _ => unreachable!(),
        }
        let definitions_current = definitions
            .try_matches_current(&world.asset_definitions)
            .unwrap();
        let policies_current = policies.matches_current().unwrap();
        assert!(!definitions_current || !policies_current);
    }
}
