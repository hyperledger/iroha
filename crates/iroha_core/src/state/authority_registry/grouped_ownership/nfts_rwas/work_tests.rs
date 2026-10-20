//! Independent literal work, complete original tails and typed refusal controls.
use super::test_support::*;
use super::*;
use iroha_crypto::Hash;
use iroha_data_model::account::{MultisigMember, MultisigPolicy};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use mv::storage::Storage;
use std::collections::BTreeMap;

fn corrupt(
    index: &'static str,
    image: GroupImage,
    mismatch: GroupMismatch,
) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index,
        image,
        mismatch,
    }
}
fn multisig() -> AccountId {
    AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(ALICE_ID.expect_single_signatory().clone(), 1).unwrap(),
                MultisigMember::new(BOB_ID.expect_single_signatory().clone(), 2).unwrap(),
            ],
        )
        .unwrap(),
    )
}
fn exact_equality<K: BorrowedKey>(left: &K, right: &K, exact: u64, truth: bool) {
    assert_eq!(
        equal(left, right, &mut NftRwaWork::bounded(exact - 1)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    let mut work = NftRwaWork::bounded(exact);
    assert_eq!(equal(left, right, &mut work), Ok(truth));
    assert_eq!(work.0, 0);
}
#[test]
fn independent_nft_rwa_reference_and_original_fixture_work_are_exact() {
    // Both images of a no-undo singleton: 8 + 8*complete ID + 8*group key.
    assert_eq!(
        NFT_WORK_PER_ROW,
        (8 + 8 * 189 + 8 * 34) + (8 + 8 * 189 + 8 * 126)
    );
    assert_eq!(
        RWA_WORK_PER_ROW,
        (8 + 8 * 158 + 8 * 34) + (8 + 8 * 158 + 8 * 64) + (8 + 8 * 158 + 8)
    );
    let world = fixture();
    for (rwa, exact) in [(false, 720), (true, 1464)] {
        assert_eq!(world_work(&world, rwa), exact);
        assert_eq!(
            without_allocations(|| if rwa {
                CheckedRwas::capture(&world, exact - 1).map(|_| ())
            } else {
                CheckedNfts::capture(&world, exact - 1).map(|_| ())
            }),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(check(&world, rwa), Ok(()));
    }
    let mut reference = fixture();
    let domain = DomainId::try_new("d".repeat(63), "s".repeat(63)).unwrap();
    let nft = NftId::new(domain.clone(), "n".repeat(63).parse().unwrap());
    let rwa = RwaId::generated(domain, Hash::new(b"reference RWA"));
    let nft_value = reference.nfts.view().get(&nft_id()).unwrap().clone();
    let mut rwa_value = reference.rwas.view().get(&rwa_id()).unwrap().clone();
    rwa_value.status = Some("s".repeat(63).parse().unwrap());
    reference.nfts = [(nft, nft_value)].into_iter().collect();
    reference.rwas = [(rwa, rwa_value)].into_iter().collect();
    reference.rebuild_nft_owner_index();
    reference.rebuild_rwa_indexes();
    assert_eq!(world_work(&reference, false), 4320);
    assert_eq!(world_work(&reference, true), 4608);
    assert!(CheckedNfts::capture(&reference, 4320).is_ok());
    assert!(matches!(
        CheckedNfts::capture(&reference, 4319),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    assert!(CheckedRwas::capture(&reference, 4608).is_ok());
    assert!(matches!(
        CheckedRwas::capture(&reference, 4607),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    let mut active = fixture();
    let mut value = active.rwas.view().get(&rwa_id()).unwrap().clone();
    value.status = Some("active".parse().unwrap());
    active.rwas.insert(rwa_id(), value);
    active.rebuild_rwa_indexes();
    assert_eq!(world_work(&active, true), 1512);
    assert!(CheckedRwas::capture(&active, 1512).is_ok());
    assert!(matches!(
        CheckedRwas::capture(&active, 1511),
        Err(GroupedOwnershipError::WorkLimit)
    ));
}
#[test]
fn all_nft_rwa_physical_mask_lookup_and_member_tails_are_prepaid() {
    macro_rules! tails {
        ($first:expr, $second:expr, $absent:expr, $visit:expr, $lookup:expr, $member:expr) => {{
            let first = $first;
            let second = $second;
            let rows: Storage<_, u32> = [(first.clone(), 1), (second.clone(), 2)]
                .into_iter()
                .collect();
            {
                let mut block = rows.block();
                block.insert(first.clone(), 1);
                block.remove($absent);
                block.commit();
            }
            let view = rows.try_committed_view_nonblocking().unwrap();
            assert_eq!(
                (view.current_entries().len(), view.undo_entries().len()),
                (2, 2)
            );
            assert_eq!(
                view.undo_entries()
                    .filter(|(_, value)| value.is_some())
                    .count(),
                1
            );
            let mut callbacks = 0;
            assert_eq!(
                visit_original(
                    &view,
                    GroupImage::Predecessor,
                    &mut NftRwaWork::bounded($visit),
                    |_, _, _| {
                        callbacks += 1;
                        Ok(())
                    }
                ),
                Ok(())
            );
            assert_eq!(callbacks, 2);
            assert_eq!(
                visit_original(
                    &view,
                    GroupImage::Predecessor,
                    &mut NftRwaWork::bounded($visit - 1),
                    |_, _, _| Ok(())
                ),
                Err(GroupedOwnershipError::WorkLimit)
            );
            let members = [first.clone(), second.clone()];
            let member_rows: Storage<_, _> = members
                .iter()
                .map(|member| ((first.clone(), member.clone()), ()))
                .collect();
            let member_view = member_rows.try_committed_view_nonblocking().unwrap();
            for key in [&first, &second] {
                assert_eq!(
                    lookup(
                        &view,
                        GroupImage::Predecessor,
                        key,
                        &mut NftRwaWork::bounded($lookup - 1)
                    ),
                    Err(GroupedOwnershipError::WorkLimit)
                );
                assert_eq!(
                    lookup(
                        &view,
                        GroupImage::Predecessor,
                        key,
                        &mut NftRwaWork::bounded($lookup)
                    ),
                    Ok(view.current().get(key))
                );
                assert_eq!(
                    contains(
                        &member_view,
                        GroupImage::Current,
                        &first,
                        key,
                        &mut NftRwaWork::bounded(2 * ($member) - 3)
                    ),
                    Err(GroupedOwnershipError::WorkLimit)
                );
                assert_eq!(
                    contains(
                        &member_view,
                        GroupImage::Current,
                        &first,
                        key,
                        &mut NftRwaWork::bounded(2 * ($member) - 2)
                    ),
                    Ok(true)
                );
            }
        }};
    }
    // NFT C2/U2: 2+4*(1+19+19)+4; lookup adds2*38; members add2*39.
    tails!(
        nft_id(),
        NftId::new(domain(), "two".parse().unwrap()),
        NftId::new(domain(), "nil".parse().unwrap()),
        162,
        238,
        78
    );
    // RWA C2/U2: 2+4*(1+48+48)+4; lookup adds2*96; members add2*97.
    tails!(
        rwa_id(),
        RwaId::generated(domain(), Hash::new(b"second")),
        RwaId::generated(domain(), Hash::new(b"absent")),
        394,
        586,
        194
    );
    struct Count(usize);
    impl Iterator for Count {
        type Item = ();
        fn next(&mut self) -> Option<()> {
            self.0 += 1;
            Some(())
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (1, Some(1))
        }
    }
    impl ExactSizeIterator for Count {}
    let mut rows = Count(0);
    assert_eq!(
        next_physical(&mut rows, &mut NftRwaWork::bounded(0)),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(rows.0, 0);
    assert_eq!(
        next_physical(&mut rows, &mut NftRwaWork::bounded(1)),
        Ok(Some(()))
    );
    assert_eq!(rows.0, 1);
    let mut empty = std::iter::empty::<()>();
    assert_eq!(
        next_physical(&mut empty, &mut NftRwaWork::bounded(0)),
        Ok(None)
    );
}
#[test]
fn both_complete_id_domain_name_hash_operands_precede_equal_or_unequal_keys() {
    exact_equality(&domain(), &domain(), 32, true);
    exact_equality(&nft_id(), &nft_id(), 38, true);
    exact_equality(&rwa_id(), &rwa_id(), 96, true);
    let other_domain = DomainId::try_new("changed", "universal").unwrap();
    exact_equality(&domain(), &other_domain, 32, false);
    exact_equality(
        &nft_id(),
        &NftId::new(other_domain.clone(), "lot".parse().unwrap()),
        38,
        false,
    );
    exact_equality(
        &rwa_id(),
        &RwaId::generated(other_domain, Hash::new(b"grouped source")),
        96,
        false,
    );
    exact_equality(
        &nft_id(),
        &NftId::new(domain(), "é".parse().unwrap()),
        37,
        false,
    );
    exact_equality(
        &rwa_id(),
        &RwaId::generated(domain(), Hash::new(b"other hash")),
        96,
        false,
    );
    let long = DomainId::try_new("d".repeat(63), "s".repeat(63)).unwrap();
    exact_equality(&long, &long, 252, true);
    exact_equality(
        &NftId::new(long.clone(), "n".repeat(63).parse().unwrap()),
        &NftId::new(long.clone(), "n".repeat(63).parse().unwrap()),
        378,
        true,
    );
    exact_equality(
        &RwaId::generated(long.clone(), Hash::new(b"long")),
        &RwaId::generated(long, Hash::new(b"long")),
        316,
        true,
    );
}
#[test]
fn borrowed_controller_geometry_preserves_every_tag_member_payload_admission() {
    let wide = multisig();
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let discarded = AccountId::new(key);
    exact_equality(&*ALICE_ID, &*ALICE_ID, 68, true);
    exact_equality(&wide, &wide, 168, true);
    exact_equality(&*ALICE_ID, &wide, 118, false);
    exact_equality(&discarded, &discarded, 4, true);
    // The same shared borrowed-controller owner preserves every original callback.
    let mut admissions = Vec::new();
    assert_eq!(
        prepay_account_id(&wide, |amount| {
            admissions.push(amount);
            Ok::<_, GroupedOwnershipError>(())
        }),
        Ok(())
    );
    assert_eq!(admissions.iter().sum::<usize>(), 84);
    for stop in 0..admissions.len() {
        let mut calls = 0;
        assert_eq!(
            prepay_account_id(&wide, |_| {
                let current = calls;
                calls += 1;
                if current == stop {
                    Err(GroupedOwnershipError::WorkLimit)
                } else {
                    Ok(())
                }
            }),
            Err(GroupedOwnershipError::WorkLimit)
        );
        assert_eq!(calls, stop + 1);
    }
}
#[test]
fn rwa_status_option_name_and_boolean_geometry_has_exact_refusal_boundaries() {
    let active = Some("active".parse::<Name>().unwrap());
    exact_equality(&None::<Name>, &None, 2, true);
    exact_equality(&None, &active, 8, false);
    exact_equality(&active, &active, 14, true);
    exact_equality(&false, &false, 2, true);
    exact_equality(&false, &true, 2, false);
    let mut work = NftRwaWork::bounded(0);
    assert_eq!(
        active.prepay(&mut work),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(work.0, 0);
    let mut work = NftRwaWork::bounded(1);
    assert_eq!(
        active.prepay(&mut work),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(work.0, 0);
}
#[test]
fn masked_absent_noop_and_matching_predecessor_tails_keep_actual_callbacks() {
    let absent = NftId::new(domain(), "absent".parse().unwrap());
    let rows = Storage::from_snapshot_parts(
        BTreeMap::from([(nft_id(), 1_u32)]),
        BTreeMap::from([(nft_id(), None), (absent.clone(), None)]),
    );
    let view = rows.try_committed_view_nonblocking().unwrap();
    // Fully masked: 1 + (1+19+19) + (1+19+22) + 4 =86, no logical callback.
    let mut callbacks = 0;
    assert_eq!(
        visit_original(
            &view,
            GroupImage::Predecessor,
            &mut NftRwaWork::bounded(86),
            |_, _, _| {
                callbacks += 1;
                Ok(())
            }
        ),
        Ok(())
    );
    assert_eq!(callbacks, 0);
    assert_eq!(
        lookup(
            &view,
            GroupImage::Predecessor,
            &nft_id(),
            &mut NftRwaWork::bounded(85)
        ),
        Err(GroupedOwnershipError::WorkLimit)
    );
    assert_eq!(
        lookup(
            &view,
            GroupImage::Predecessor,
            &nft_id(),
            &mut NftRwaWork::bounded(86)
        ),
        Ok(None)
    );
    let world = fixture();
    {
        let mut block = world.nfts.block();
        block.remove(absent);
        block.commit();
    }
    assert_eq!(world_work(&world, false), 896);
    assert!(matches!(
        CheckedNfts::capture(&world, 895),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    assert!(CheckedNfts::capture(&world, 896).is_ok());
    {
        let mut block = world.rwas.block();
        block.remove(RwaId::generated(domain(), Hash::new(b"absent RWA")));
        block.commit();
    }
    assert_eq!(world_work(&world, true), 2058);
    assert!(matches!(
        CheckedRwas::capture(&world, 2057),
        Err(GroupedOwnershipError::WorkLimit)
    ));
    assert!(CheckedRwas::capture(&world, 2058).is_ok());
}
#[test]
fn nft_owner_domain_and_rwa_owner_status_frozen_phases_keep_first_failure() {
    let mut world = fixture();
    world.nfts_by_owner = Storage::default();
    {
        let mut block = world.nfts_by_owner.block();
        block.insert((ALICE_ID.clone(), nft_id()), ());
        block.commit();
    }
    world.nfts_by_domain = Storage::default();
    assert_eq!(
        check(&world, false),
        Err(corrupt(
            "world.nfts_by_owner",
            GroupImage::Predecessor,
            GroupMismatch::MissingMember
        ))
    );
    let mut world = fixture();
    world.rwas_by_status = Storage::default();
    {
        let mut block = world.rwas_by_status.block();
        block.insert((None, rwa_id()), ());
        block.commit();
    }
    world.rwas_by_frozen = Storage::default();
    assert_eq!(
        check(&world, true),
        Err(corrupt(
            "world.rwas_by_status",
            GroupImage::Predecessor,
            GroupMismatch::MissingMember
        ))
    );
    let mut world = fixture();
    world.rwas_by_owner = Storage::default();
    world.rwas_by_status = Storage::default();
    world.rwas_by_frozen = Storage::default();
    assert_eq!(
        check(&world, true),
        Err(corrupt(
            "world.rwas_by_owner",
            GroupImage::Current,
            GroupMismatch::MissingMember
        ))
    );
}
fn publish(world: &World, rwa: bool, source: usize) {
    match (rwa, source) {
        (false, 0) => world.nfts.block().commit(),
        (false, 1) => world.nfts_by_owner.block().commit(),
        (false, 2) => world.nfts_by_domain.block().commit(),
        (true, 0) => world.rwas.block().commit(),
        (true, 1) => world.rwas_by_owner.block().commit(),
        (true, 2) => world.rwas_by_status.block().commit(),
        (true, 3) => world.rwas_by_frozen.block().commit(),
        _ => unreachable!(),
    }
}
#[test]
fn all_original_nft_rwa_results_precede_actual_native_refusal_propagation() {
    let world = fixture();
    let checked = CheckedNfts::capture(&world, 720).unwrap();
    publish(&world, false, 0);
    let detached = world
        .nfts_by_owner
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&world.nfts_by_owner, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, e, _)| panic!("original NFT preparation: {e:?}"));
    let refusal = checked
        .owners
        .try_matches_current(&world.nfts_by_owner)
        .unwrap_err();
    assert!(matches!(refusal, PublicationPreparationError::Busy(_)));
    assert_eq!(
        checked
            .finish_validation(Err(GroupedOwnershipError::WorkLimit))
            .err(),
        Some(GroupedOwnershipError::Publication(refusal))
    );
    drop(prepared);
    assert_eq!(check(&world, false), Ok(()));
    let world = fixture();
    let checked = CheckedRwas::capture(&world, 1464).unwrap();
    publish(&world, true, 0);
    publish(&world, true, 2);
    let detached = world
        .rwas_by_frozen
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let prepared = detached
        .try_prepare_publication(&world.rwas_by_frozen, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, e, _)| panic!("original RWA preparation: {e:?}"));
    let refusal = checked
        .frozen
        .try_matches_current(&world.rwas_by_frozen)
        .unwrap_err();
    assert!(matches!(refusal, PublicationPreparationError::Busy(_)));
    assert_eq!(
        checked
            .finish_validation(Err(GroupedOwnershipError::WorkLimit))
            .err(),
        Some(GroupedOwnershipError::Publication(refusal))
    );
    drop(prepared);
    assert_eq!(check(&world, true), Ok(()));
}
#[test]
fn changed_original_sources_precede_stable_work_or_corruption_results() {
    for rwa in [false, true] {
        for source in 0..if rwa { 4 } else { 3 } {
            for validation in 0..3 {
                let world = fixture();
                let result = match validation {
                    0 => Ok(()),
                    1 => Err(GroupedOwnershipError::WorkLimit),
                    _ => Err(corrupt(
                        "world.nfts_by_domain",
                        GroupImage::Current,
                        GroupMismatch::ForeignMember,
                    )),
                };
                if rwa {
                    let checked = CheckedRwas::capture(&world, 1464).unwrap();
                    publish(&world, true, source);
                    assert!(matches!(
                        checked.finish_validation(result),
                        Err(GroupedOwnershipError::Publication(
                            PublicationPreparationError::Changed
                        ))
                    ));
                } else {
                    let checked = CheckedNfts::capture(&world, 720).unwrap();
                    publish(&world, false, source);
                    assert!(matches!(
                        checked.finish_validation(result),
                        Err(GroupedOwnershipError::Publication(
                            PublicationPreparationError::Changed
                        ))
                    ));
                }
            }
        }
    }
}
#[test]
fn unused_record_fields_and_unknown_accounts_domains_add_no_authority() {
    let mut world = fixture();
    let mut key = ALICE_ID.expect_single_signatory().clone();
    key.zeroize_for_confidential_discard();
    let discarded = AccountId::new(key);
    let mut nft = world.nfts.view().get(&nft_id()).unwrap().clone();
    nft.owned_by = discarded.clone();
    let mut rwa = world.rwas.view().get(&rwa_id()).unwrap().clone();
    rwa.owned_by = discarded;
    rwa.quantity = iroha_primitives::numeric::Quantity::zero();
    rwa.primary_reference = String::new();
    rwa.controls.freeze_enabled = false;
    world.accounts = Storage::default();
    world.domains = Storage::default();
    world.nfts.insert(nft_id(), nft);
    world.rwas.insert(rwa_id(), rwa);
    world.rebuild_nft_owner_index();
    world.rebuild_rwa_indexes();
    assert_eq!(check(&world, false), Ok(()));
    assert_eq!(check(&world, true), Ok(()));
    let source = include_str!("../nfts_rwas.rs");
    let source = source.split("#[cfg(test)]").next().unwrap();
    for retired in [
        ".get(",
        ".contains(",
        ".contains_key(",
        ".range(",
        ".clone(",
        ".sort(",
        ".collect(",
        "::parse",
    ] {
        assert!(
            !source.contains(retired),
            "unfunded NFT/RWA relation: {retired}"
        );
    }
}
