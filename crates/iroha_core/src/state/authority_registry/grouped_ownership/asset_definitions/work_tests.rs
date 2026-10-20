//! Independent full geometry and refusal boundaries over real native originals.
use super::test_support as reference;
use super::*;
use crate::test_allocations::allocations_during;
use iroha_crypto::Hash;
use iroha_data_model::{
    asset::definition::{
        AssetConfidentialPolicy, ConfidentialPolicyMode, ConfidentialPolicyTransition,
    },
    prelude::Registrable,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;

fn check(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(
            || result = Some(CheckedAssetDefinitions::capture(world, work).map(|_| ()))
        ),
        0
    );
    result.unwrap()
}
#[test]
fn independent_reference_and_original_fixture_have_exact_full_boundaries() {
    for (context, expected) in [(false, 428), (true, 1206)] {
        let mut world = reference::world(context, None);
        // The original fixture's no-pending mode does not constrain feature policy.
        let mut value = reference::definition(0, &ALICE_ID, context, None);
        value.set_confidential_policy(AssetConfidentialPolicy::transparent());
        world.asset_definitions.insert(reference::id(0), value);
        assert_eq!(reference::world_work(&world), expected);
        assert_eq!(
            check(&world, expected - 1),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, expected), Ok(()));
    }
    let text = "d".repeat(63);
    let domain = DomainId::try_new(&text, &text).unwrap();
    let mut value = AssetDefinition::numeric(
        reference::id(0),
        "coin",
        AssetBalancePolicy::Global,
        Some(domain.clone()),
    )
    .build(&ALICE_ID);
    value.set_confidential_policy(
        *reference::definition(0, &ALICE_ID, false, Some(41)).confidential_policy(),
    );
    let world = World::with([Domain::new(domain).build(&ALICE_ID)], [], [value]);
    assert_eq!(ASSET_DEFINITION_WORK_PER_ROW, 2 * (831 + 204 + 575 + 318));
    assert_eq!(reference::world_work(&world), 3856);
    assert_eq!(check(&world, 3855), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 3856), Ok(()));
}
#[test]
fn every_original_physical_mask_lookup_and_member_tail_is_prepaid() {
    let first = reference::id(0);
    let second = reference::id(1);
    let absent = reference::id(99);
    let rows: Storage<AssetDefinitionId, u32> = [(first.clone(), 1), (second.clone(), 2)]
        .into_iter()
        .collect();
    {
        let mut block = rows.block();
        block.insert(first.clone(), 1);
        block.remove(absent);
        block.commit();
    }
    let view = rows.try_committed_view_nonblocking().unwrap();
    assert_eq!(
        (view.current_entries().len(), view.undo_entries().len()),
        (2, 2)
    );
    // current2 + both current×undo full ID mask comparisons4×33 + undo2×(advance+tag).
    let visit = 2 + 4 * 33 + 2 * 2;
    let mut seen = 0;
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut AssetDefinitionWork::bounded(visit),
            |_, _, _| {
                seen += 1;
                Ok(())
            }
        ),
        Ok(())
    );
    assert_eq!(seen, 2);
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut AssetDefinitionWork::bounded(visit - 1),
            |_, _, _| Ok(())
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    for id in [&first, &second] {
        let exact = visit + 2 * 32;
        assert_eq!(
            lookup(
                &view,
                GroupImage::Predecessor,
                id,
                &mut AssetDefinitionWork::bounded(exact - 1)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            lookup(
                &view,
                GroupImage::Predecessor,
                id,
                &mut AssetDefinitionWork::bounded(exact)
            ),
            Ok(view.current().get(id))
        );
    }
    let members = [first.clone(), second.clone()];
    let member_rows: Storage<_, _> = members
        .iter()
        .map(|member| ((first.clone(), member.clone()), ()))
        .collect();
    let member_view = member_rows.try_committed_view_nonblocking().unwrap();
    for id in &members {
        assert_eq!(
            contains(
                &member_view,
                GroupImage::Current,
                &first,
                id,
                &mut AssetDefinitionWork::bounded(2 * (66) - 3)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            contains(
                &member_view,
                GroupImage::Current,
                &first,
                id,
                &mut AssetDefinitionWork::bounded(2 * (66) - 2)
            ),
            Ok(true)
        );
    }
}
#[test]
fn asset_id_domain_controller_policy_and_count_geometry_preserve_typed_refusal() {
    #[derive(Debug, PartialEq, Eq)]
    struct Refused;
    let mut called = 0;
    assert_eq!(
        prepay_asset_definition_id(&reference::id(0), |amount| {
            called += 1;
            assert_eq!(amount, 16);
            Err(Refused)
        }),
        Err(Refused)
    );
    assert_eq!(called, 1);
    let left = DomainId::try_new("prefix", "universal").unwrap();
    let right = DomainId::try_new("prefix", "universe").unwrap();
    let exact = 2 * 6 + 9 + 8;
    assert_eq!(
        equal(&left, &right, &mut AssetDefinitionWork::bounded(exact - 1)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        equal(&left, &right, &mut AssetDefinitionWork::bounded(exact)),
        Ok(false)
    );
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    let owner = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    let exact = 2 * (12 + 2 + 2 * (3 + 32));
    assert_eq!(
        equal(&owner, &owner, &mut AssetDefinitionWork::bounded(exact - 1)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        equal(&owner, &owner, &mut AssetDefinitionWork::bounded(exact)),
        Ok(true)
    );
    for (window, amount) in [(None, 45), (Some(1), 53)] {
        let policy = AssetConfidentialPolicy {
            pending_transition: Some(ConfidentialPolicyTransition {
                new_mode: ConfidentialPolicyMode::ShieldedOnly,
                effective_height: 41,
                previous_mode: ConfidentialPolicyMode::Convertible,
                transition_id: Hash::new(b"geometry"),
                conversion_window: window,
            }),
            ..AssetConfidentialPolicy::convertible()
        };
        assert_eq!(
            confidential_policies::prepay_policy(
                &policy,
                &mut AssetDefinitionWork::bounded(amount - 1)
            ),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            confidential_policies::prepay_policy(
                &policy,
                &mut AssetDefinitionWork::bounded(amount)
            ),
            Ok(())
        );
    }
    assert_eq!(
        confidential_policies::prepay_policy(
            &AssetConfidentialPolicy::transparent(),
            &mut AssetDefinitionWork::bounded(1)
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        confidential_policies::prepay_policy(
            &AssetConfidentialPolicy::transparent(),
            &mut AssetDefinitionWork::bounded(2)
        ),
        Ok(())
    );
}
#[test]
fn malformed_typed_identity_and_unused_policy_fields_add_no_validity_rule() {
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let owner = AccountId::new(key);
    let mut value = reference::definition(1, &owner, false, None); // embedded id differs from stored key
    let mut policy = AssetConfidentialPolicy::transparent();
    policy.vk_set_hash = Some(Hash::new(b"unused"));
    policy.poseidon_params_id = Some(u32::MAX);
    policy.pedersen_params_id = Some(u32::MAX);
    value.set_confidential_policy(policy);
    let mut world = World::default();
    world.asset_definitions.insert(reference::id(0), value);
    world
        .asset_definitions_by_owner
        .insert((owner, reference::id(0)), ());
    assert!(world.accounts.view().iter().next().is_none());
    assert!(world.zk_assets.view().iter().next().is_none());
    assert_eq!(reference::world_work(&world), 172);
    assert_eq!(check(&world, 171), Err(GroupedOwnershipError::WorkLimit));
    assert_eq!(check(&world, 172), Ok(()));
}
#[test]
fn phased_predecessor_reference_and_owner_failures_keep_original_precedence() {
    let mut world = reference::world(true, None);
    let bad = AssetDefinition::numeric(
        reference::id(0),
        "coin",
        AssetBalancePolicy::DataspaceRestricted,
        None,
    )
    .build(&ALICE_ID);
    world.asset_definitions.insert(reference::id(0), bad);
    {
        let mut block = world.asset_definitions.block();
        block.insert(
            reference::id(0),
            reference::definition(0, &ALICE_ID, true, None),
        );
        block.commit();
    }
    world.asset_definitions_by_owner = Storage::default();
    assert_eq!(
        check(&world, 16_777_216),
        Err(GroupedOwnershipError::Source {
            table: "world.asset_definitions",
            image: GroupImage::Predecessor,
            reason: "restricted definition has no owning domain"
        })
    );
    let mut world = reference::world(false, Some(41));
    let mut value = reference::definition(0, &ALICE_ID, false, Some(41));
    let mut policy = *value.confidential_policy();
    policy.pending_transition.as_mut().unwrap().effective_height = 0;
    value.set_confidential_policy(policy);
    world.asset_definitions.insert(reference::id(0), value);
    world.asset_definitions_by_owner = Storage::default();
    assert_eq!(
        check(&world, 16_777_216),
        Err(GroupedOwnershipError::Corrupt {
            index: "world.asset_definitions_by_owner",
            image: GroupImage::Current,
            mismatch: GroupMismatch::MissingMember
        })
    );
}
