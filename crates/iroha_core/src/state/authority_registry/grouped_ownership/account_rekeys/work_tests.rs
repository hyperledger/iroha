//! Independent literal schedules, complete typed operands and original native refusals.
use super::test_support::{Geometry as _, fixture, phase_work, world_work};
use super::*;
use crate::test_allocations::allocations_during;
use iroha_data_model::{
    IntoKeyValue,
    account::{
        Account, AccountRekeyTransitionProvenance as Provenance, MultisigMember, MultisigPolicy,
    },
    prelude::Registrable,
};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::{ALICE_ID, BOB_ID, CARPENTER_ID};
use mv::storage::Storage;
fn check_work(world: &World, work: u64) -> Result<(), GroupedOwnershipError> {
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(CheckedAccountRekeys::capture(world, work).map(|_| ()))),
        0
    );
    result.unwrap()
}
fn phases(world: &World, image: GroupImage) -> [u64; 4] {
    phase_work(
        &world
            .account_rekey_records
            .try_committed_view_nonblocking()
            .unwrap(),
        &world.accounts.try_committed_view_nonblocking().unwrap(),
        &world
            .account_aliases
            .try_committed_view_nonblocking()
            .unwrap(),
        &world
            .account_rekey_records_by_account
            .try_committed_view_nonblocking()
            .unwrap(),
        image,
    )
}
#[test]
fn independent_four_phase_singletons_reference_and_dense_work_match_literal_equations() {
    let world = fixture();
    assert_eq!(phases(&world, GroupImage::Current), [536, 238, 344, 108]);
    assert_eq!(world_work(&world), 2452);
    assert_eq!(
        check_work(&world, 2451),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&world, 2452), Ok(()));
    let mut bootstrap = World::default();
    let (id, value) = Account::new(BOB_ID.clone()).build(&BOB_ID).into_key_value();
    bootstrap.accounts.insert(id, value);
    bootstrap.account_rekey_records.insert(
        test_support::alias("wallet"),
        AccountRekeyRecord::new(test_support::alias("wallet"), BOB_ID.clone()),
    );
    bootstrap
        .account_aliases
        .insert(test_support::alias("wallet"), BOB_ID.clone());
    bootstrap.rebuild_account_rekey_records().unwrap();
    assert_eq!(phases(&bootstrap, GroupImage::Current), [223, 169, 103, 49]);
    assert_eq!(world_work(&bootstrap), 1088);
    assert_eq!(
        check_work(&bootstrap, 1087),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&bootstrap, 1088), Ok(()));
    let retired = AccountRekeyRecord::new(test_support::alias("wallet"), CARPENTER_ID.clone())
        .repoint_for_account_id_rekey(BOB_ID.clone())
        .unwrap();
    bootstrap
        .account_rekey_records
        .insert(test_support::alias("wallet"), retired);
    bootstrap.rebuild_account_rekey_records().unwrap();
    assert_eq!(world_work(&bootstrap), 2594);
    assert_eq!(
        check_work(&bootstrap, 2593),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&bootstrap, 2594), Ok(()));
    let mut reference = fixture();
    let alias = AccountAlias::new(
        "x".repeat(255).parse().unwrap(),
        Some("d".repeat(255).parse().unwrap()),
        DataSpaceId::UNIVERSAL,
    );
    let mut row = test_support::record();
    row.label = alias.clone();
    reference.account_rekey_records = [(alias.clone(), row)].into_iter().collect();
    reference.account_aliases = [(alias, BOB_ID.clone())].into_iter().collect();
    reference.rebuild_account_rekey_records().unwrap();
    assert_eq!(
        phases(&reference, GroupImage::Current),
        [3809, 1246, 2360, 2124]
    );
    assert_eq!(world_work(&reference), 19078);
    assert_eq!(ACCOUNT_REKEY_WORK_PER_ROW, 2 * (3809 + 1246 + 2360 + 2124));
    assert_eq!(
        check_work(&reference, 19077),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&reference, 19078), Ok(()));
    let mut dense = fixture();
    let mut row = test_support::record();
    row.previous_account_ids = vec![ALICE_ID.clone(); 128];
    row.transition_provenance = vec![Provenance::AliasReassignment; 128];
    dense
        .account_rekey_records
        .insert(test_support::alias("wallet"), row);
    dense.rebuild_account_rekey_records().unwrap();
    assert_eq!(
        phases(&dense, GroupImage::Current),
        [22761, 238, 17870, 1378]
    );
    assert_eq!(world_work(&dense), 84494);
    assert_eq!(
        check_work(&dense, 84493),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&dense, 84494), Ok(()));
    assert_eq!(16 * ACCOUNT_REKEY_WORK_PER_ROW, 305248);
}
#[test]
fn complete_mask_lookup_member_and_absent_preimage_tails_keep_exact_work() {
    let first = test_support::alias("wallet");
    let second = test_support::alias("second");
    let absent = test_support::alias("absent");
    let rows: Storage<AccountAlias, u32> = [(first.clone(), 1), (second.clone(), 2)]
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
    let mut count = 0;
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut RekeyWork(130),
            |_, _, _| {
                count += 1;
                Ok(())
            }
        ),
        Ok(())
    );
    assert_eq!(count, 2);
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut RekeyWork(129),
            |_, _, _| Ok(())
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    for key in [&first, &second] {
        assert_eq!(
            lookup(&view, GroupImage::Predecessor, key, &mut RekeyWork(189)),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(
            lookup(&view, GroupImage::Predecessor, key, &mut RekeyWork(190)),
            Ok(view.current().get(key))
        );
    }
    let members = BTreeSet::from([first.clone(), second.clone()]);
    assert_eq!(
        contains_alias(&members, &first, &mut RekeyWork(61)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        contains_alias(&members, &first, &mut RekeyWork(62)),
        Ok(true)
    );
    let world = fixture();
    {
        let mut rows = world.account_rekey_records.block();
        rows.remove(test_support::alias("absent"));
        rows.commit();
    }
    assert_eq!(world_work(&world), 2650);
    assert_eq!(
        check_work(&world, 2649),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&world, 2650), Ok(()));
    let world = fixture();
    {
        let mut rows = world.account_rekey_records.block();
        rows.insert(test_support::alias("wallet"), test_support::record());
        rows.remove(test_support::alias("absent"));
        rows.commit();
    }
    assert_eq!(world_work(&world), 2848);
    assert_eq!(
        check_work(&world, 2847),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(check_work(&world, 2848), Ok(()));
}
#[test]
fn controller_alias_domain_option_and_dataspace_operands_are_fully_prepaid() {
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    );
    for (account, units) in [(&*ALICE_ID, 34), (&multisig, 84)] {
        assert_eq!(account.units(), units);
        assert_eq!(
            equal(account, account, &mut RekeyWork(2 * units - 1)),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(equal(account, account, &mut RekeyWork(2 * units)), Ok(true));
    }
    let alias = AccountAlias::new(
        "é".parse().unwrap(),
        Some("銀行".parse().unwrap()),
        DataSpaceId::new(7),
    );
    assert_eq!(alias.units(), 17);
    let mut other = alias.clone();
    other.dataspace = DataSpaceId::new(8);
    assert_eq!(
        equal(&alias, &other, &mut RekeyWork(33)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(equal(&alias, &other, &mut RekeyWork(34)), Ok(false));
    other.dataspace = alias.dataspace;
    other.domain = None;
    assert_eq!(other.units(), 11);
    assert_eq!(
        equal(&alias, &other, &mut RekeyWork(27)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(equal(&alias, &other, &mut RekeyWork(28)), Ok(false));
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let account = AccountId::new(key);
    assert_eq!(account.units(), 2);
    let mut result = None;
    assert_eq!(
        allocations_during(|| result = Some(equal(&account, &account, &mut RekeyWork(4)))),
        0
    );
    assert_eq!(result, Some(Ok(true)));
}
#[test]
fn native_iterator_refusal_happens_before_advancing_original_storage() {
    let members = [ALICE_ID.clone(), BOB_ID.clone()];
    let mut iter = members.iter();
    assert_eq!(
        next_physical(&mut iter, &mut RekeyWork(0)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(iter.len(), 2);
    assert_eq!(
        next_physical(&mut iter, &mut RekeyWork(1)).unwrap(),
        Some(&members[0])
    );
    assert_eq!(iter.len(), 1);
    assert_eq!(
        contains_account(members.iter(), &ALICE_ID, &mut RekeyWork(137)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        contains_account(members.iter(), &ALICE_ID, &mut RekeyWork(138)),
        Ok(true)
    );
    assert_eq!(
        contains_account(members.iter(), &CARPENTER_ID, &mut RekeyWork(138)),
        Ok(false)
    );
}
#[test]
fn canonical_provenance_metadata_and_all_tags_precede_nominal_failure_or_suffix() {
    let mut bad = test_support::record();
    bad.transition_provenance = vec![Provenance::AccountIdRekey; 4096];
    assert_eq!(
        funded_predecessors(&bad, GroupImage::Predecessor, &mut RekeyWork(20495)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        funded_predecessors(&bad, GroupImage::Predecessor, &mut RekeyWork(20496)),
        Err(source(
            GroupImage::Predecessor,
            "transition provenance length differs from account history"
        ))
    );
    let mut valid = AccountRekeyRecord::new(test_support::alias("wallet"), CARPENTER_ID.clone())
        .repoint_for_account_id_rekey(BOB_ID.clone())
        .unwrap();
    assert_eq!(
        funded_predecessors(&valid, GroupImage::Current, &mut RekeyWork(20)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        funded_predecessors(&valid, GroupImage::Current, &mut RekeyWork(21)),
        Ok(valid.previous_account_ids.as_slice())
    );
    valid.transition_provenance[0] = Provenance::AliasReassignment;
    assert_eq!(
        funded_predecessors(&valid, GroupImage::Current, &mut RekeyWork(21)),
        Ok(&[][..])
    );
}
#[test]
fn every_changed_original_precedes_semantic_or_local_work_refusal() {
    for owner in 0..4 {
        for validation in 0..3 {
            let world = fixture();
            let checked = CheckedAccountRekeys::capture(&world, 2452).unwrap();
            match owner {
                0 => world.account_rekey_records.block().commit(),
                1 => world.accounts.block().commit(),
                2 => world.account_aliases.block().commit(),
                3 => world.account_rekey_records_by_account.block().commit(),
                _ => unreachable!(),
            };
            let result = match validation {
                0 => Ok(()),
                1 => Err(GroupedOwnershipError::WorkLimit),
                _ => Err(corrupt(GroupImage::Current, GroupMismatch::ForeignMember)),
            };
            assert_eq!(
                checked.finish_validation(result).err(),
                Some(GroupedOwnershipError::Publication(
                    PublicationPreparationError::Changed
                ))
            );
        }
    }
}
#[test]
fn actual_later_native_busy_refusal_is_not_short_circuited_by_changed_rows() {
    let world = fixture();
    let checked = CheckedAccountRekeys::capture(&world, 2452).unwrap();
    world.account_rekey_records.block().commit();
    let detached = world
        .account_rekey_records_by_account
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&world.account_rekey_records_by_account, |_, _| {
            Ok::<_, ()>(())
        })
        .unwrap_or_else(|(_, e, _)| panic!("original occurrence prepare: {e:?}"));
    let refusal = checked
        .occurrences
        .try_matches_current(&world.account_rekey_records_by_account)
        .unwrap_err();
    assert!(matches!(refusal, PublicationPreparationError::Busy(_)));
    assert_eq!(
        checked
            .finish_validation(Err(GroupedOwnershipError::WorkLimit))
            .err(),
        Some(GroupedOwnershipError::Publication(refusal))
    );
    drop(prepared);
    assert_eq!(check_work(&world, 2452), Ok(()));
}
