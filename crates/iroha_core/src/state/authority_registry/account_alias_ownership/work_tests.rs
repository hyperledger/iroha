//! Exact admission and borrowed geometry without new alias/controller predicates.

use super::{test_support::*, *};
use iroha_data_model::account::{AccountAliasDomain, MultisigMember, MultisigPolicy};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use std::{cell::Cell, collections::BTreeMap};

#[test]
fn every_alias_physical_advance_mask_and_lookup_tail_is_prepaid() {
    let world = fixture();
    let rows = world
        .account_aliases
        .try_committed_view_nonblocking()
        .unwrap();
    let advances = Cell::new(0);
    let mut physical = rows
        .current_entries()
        .inspect(|_| advances.set(advances.get() + 1));
    assert_eq!(
        next_physical(&mut physical, &mut Work(0)),
        Err(AliasOwnershipError::WorkLimit)
    );
    assert_eq!(advances.get(), 0);
    assert!(
        next_physical(&mut physical, &mut Work(1))
            .unwrap()
            .is_some()
    );
    assert_eq!(advances.get(), 1);
    assert!(
        next_physical(&mut physical, &mut Work(0))
            .unwrap()
            .is_none()
    );
    let merchant = alias("merchant"); //17 complete bytes
    let tail = alias("zz-tail"); //16 complete bytes
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(merchant.clone(), ALICE_ID.clone())]),
        BTreeMap::from([
            (merchant.clone(), Some(BOB_ID.clone())),
            (tail.clone(), None),
        ]),
    );
    let rows = rows.try_committed_view_nonblocking().unwrap();
    // First mask matches, but the second original candidate and both undo
    // advances remain admitted:1+(1+17+17)+(1+17+16)+2=72.
    let exact = 1 + (1 + 17 + 17) + (1 + 17 + 16) + 2;
    assert_eq!(exact, 72);
    assert_eq!(
        without_allocations(|| visit_original(
            &rows,
            AliasImage::Predecessor,
            &mut Work(exact - 1),
            |_, _, _| Ok(())
        )),
        Err(AliasOwnershipError::WorkLimit)
    );
    let mut inspected = 0;
    without_allocations(|| {
        visit_original(
            &rows,
            AliasImage::Predecessor,
            &mut Work(exact),
            |key, value, _| {
                assert_eq!(key, &merchant);
                assert_eq!(value, &*BOB_ID);
                inspected += 1;
                Ok(())
            },
        )
    })
    .unwrap();
    assert_eq!(inspected, 1);
    let two = Storage::from_iter([
        (merchant.clone(), ALICE_ID.clone()),
        (tail.clone(), BOB_ID.clone()),
    ]);
    let two = two.try_committed_view_nonblocking().unwrap();
    let exact = (1 + 17 + 17) + (1 + 16 + 17);
    assert_eq!(
        without_allocations(|| lookup_original(
            &two,
            AliasImage::Current,
            &merchant,
            &mut Work(exact - 1)
        )),
        Err(AliasOwnershipError::WorkLimit)
    );
    assert_eq!(
        without_allocations(|| lookup_original(
            &two,
            AliasImage::Current,
            &merchant,
            &mut Work(exact)
        )),
        Ok(Some(&*ALICE_ID))
    );
    let members = BTreeSet::from([merchant.clone(), tail]);
    assert_eq!(
        without_allocations(|| contains_original(&members, &merchant, &mut Work(exact - 1))),
        Err(AliasOwnershipError::WorkLimit)
    );
    assert_eq!(
        without_allocations(|| contains_original(&members, &merchant, &mut Work(exact))),
        Ok(true)
    );
}

#[test]
fn full_alias_bytes_options_dataspaces_and_controller_members_are_funded() {
    let left = AccountAlias::new(
        "商店".parse().unwrap(),
        Some(AccountAliasDomain::new("domain".parse().unwrap())),
        DataSpaceId::new(7),
    );
    let mut right = left.clone();
    right.dataspace = DataSpaceId::new(8);
    let width = 6 + 1 + 6 + 8;
    for allowance in 0..2 * width {
        assert_eq!(
            without_allocations(|| equal(&left, &right, &mut Work(allowance))),
            Err(AliasOwnershipError::WorkLimit)
        );
    }

    assert_eq!(
        without_allocations(|| equal(&left, &right, &mut Work(2 * width - 1))),
        Err(AliasOwnershipError::WorkLimit)
    );
    assert_eq!(
        without_allocations(|| equal(&left, &right, &mut Work(2 * width))),
        Ok(false)
    );
    right.dataspace = left.dataspace;
    right.domain = Some(AccountAliasDomain::new("domaintail".parse().unwrap()));
    let other = 6 + 1 + 10 + 8;
    assert_eq!(
        equal(&left, &right, &mut Work(width + other - 1)),
        Err(AliasOwnershipError::WorkLimit)
    );
    assert_eq!(equal(&left, &right, &mut Work(width + other)), Ok(false));
    right.domain = None;
    assert_eq!(
        equal(&left, &right, &mut Work(width + 6 + 1 + 8)),
        Ok(false)
    );
    let multi = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    assert_eq!(
        without_allocations(|| equal(&multi, &*ALICE_ID, &mut Work(84 + 34 - 1))),
        Err(AliasOwnershipError::WorkLimit)
    );
    assert_eq!(
        without_allocations(|| equal(&multi, &*ALICE_ID, &mut Work(84 + 34))),
        Ok(false)
    );
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let discarded = AccountId::new(key);
    assert_eq!(
        without_allocations(|| equal(&discarded, &*ALICE_ID, &mut Work(2 + 34))),
        Ok(false)
    );
    let mut world = World::new();
    world.accounts = Storage::from_iter([(discarded.clone(), details(None))]);
    world.account_aliases = Storage::from_iter([(alias("merchant"), discarded.clone())]);
    world.account_aliases_by_account =
        Storage::from_iter([(discarded, BTreeSet::from([alias("merchant")]))]);
    let exact = exact_world_work(&world);
    without_allocations(|| CheckedAccountAliases::capture(&world, exact)).unwrap();
    assert_eq!(
        without_allocations(|| CheckedAccountAliases::capture(&world, exact - 1)).err(),
        Some(AliasOwnershipError::WorkLimit)
    );
}

#[test]
fn committed_alias_reference_and_full_fixture_work_have_independent_boundaries() {
    let world = fixture();
    assert_eq!(exact_world_work(&world), 722);
    assert_eq!(
        without_allocations(|| CheckedAccountAliases::capture(&world, 721)).err(),
        Some(AliasOwnershipError::WorkLimit)
    );
    without_allocations(|| CheckedAccountAliases::capture(&world, 722)).unwrap();
    let label = AccountAlias::new(
        "a".repeat(255).parse().unwrap(),
        Some(AccountAliasDomain::new("d".repeat(255).parse().unwrap())),
        DataSpaceId::new(19),
    );
    let mut world = World::default();
    world
        .accounts
        .insert(ALICE_ID.clone(), details(Some(label.clone())));
    world
        .account_aliases
        .insert(label.clone(), ALICE_ID.clone());
    world
        .account_aliases_by_account
        .insert(ALICE_ID.clone(), BTreeSet::from([label]));
    let key = 255 + 1 + 255 + 8;
    let accounts = 1 + 1 + 255 + (1 + 2 * key) + 2 * 34;
    let aliases = 1 + 255 + (1 + 2 * 34) + (1 + 2 * 34) + (1 + 2 * key);
    let reverse = 1 + 1 + 1 + (1 + 2 * key) + 2 * 34;
    assert_eq!((accounts, aliases, reverse), (1364, 1433, 1110));
    let exact = 2 * (accounts + aliases + reverse);
    assert_eq!(exact, ACCOUNT_ALIAS_WORK_PER_ROW);
    assert_eq!(exact_world_work(&world), exact);
    assert_eq!(
        without_allocations(|| CheckedAccountAliases::capture(&world, exact - 1)).err(),
        Some(AliasOwnershipError::WorkLimit)
    );
    without_allocations(|| CheckedAccountAliases::capture(&world, exact)).unwrap();
}

#[test]
fn pii_primary_label_and_all_six_mismatches_keep_current_prior_precedence() {
    for name in ["123abc456", "商店", "1234567", "1234567890123456"] {
        let mut world = fixture();
        let label = alias(name);
        world.account_aliases.insert(label.clone(), BOB_ID.clone());
        world
            .accounts
            .insert(BOB_ID.clone(), details(Some(label.clone())));
        world
            .account_aliases_by_account
            .insert(BOB_ID.clone(), BTreeSet::from([label]));
        let exact = exact_world_work(&world);
        without_allocations(|| CheckedAccountAliases::capture(&world, exact)).unwrap();
    }
    for primary in [false, true] {
        let mut world = fixture();
        let label = alias("12345678");
        if primary {
            world
                .accounts
                .insert(ALICE_ID.clone(), details(Some(label)));
        } else {
            world.account_aliases.insert(label, ALICE_ID.clone());
        }
        assert_eq!(
            without_allocations(|| CheckedAccountAliases::capture(&world, 16_777_216)).err(),
            Some(corrupt(AliasImage::Current, AliasMismatch::PrivateLabel))
        );
        assert_eq!(
            without_allocations(|| CheckedAccountAliases::capture(&world, 0)).err(),
            Some(AliasOwnershipError::WorkLimit)
        );
    }
    // Current primary-label failure precedes the current missing-account pass.
    let mut world = fixture();
    world
        .accounts
        .insert(ALICE_ID.clone(), details(Some(alias("unbound"))));
    world.account_aliases.insert(
        alias("ghost"),
        AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![55; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        ),
    );
    assert_eq!(
        CheckedAccountAliases::capture(&world, 16_777_216).err(),
        Some(corrupt(AliasImage::Current, AliasMismatch::PrimaryLabel))
    );
    // Current reverse failure precedes a predecessor primary-label failure.
    let mut world = fixture();
    world.accounts = Storage::from_snapshot_parts(
        BTreeMap::from([
            (ALICE_ID.clone(), details(None)),
            (BOB_ID.clone(), details(None)),
        ]),
        BTreeMap::from([(
            ALICE_ID.clone(),
            Some(details(Some(alias("prior-unbound")))),
        )]),
    );
    world
        .account_aliases_by_account
        .insert(BOB_ID.clone(), BTreeSet::new());
    assert_eq!(
        CheckedAccountAliases::capture(&world, 16_777_216).err(),
        Some(corrupt(AliasImage::Current, AliasMismatch::EmptyBucket))
    );
}
