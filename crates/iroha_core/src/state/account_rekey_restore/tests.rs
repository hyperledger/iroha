//! Restore rejects corrupt predecessor rows without repairing authoritative data.

use super::*;
use iroha_data_model::{
    IntoKeyValue,
    account::{Account, AccountRekeyTransitionProvenance as Provenance},
    prelude::Registrable,
};
use iroha_test_samples::{ALICE_ID, BOB_ID, CARPENTER_ID};
use norito::codec::DecodeAll;

fn alias(name: &str) -> AccountAlias {
    AccountAlias::domainless(name.parse().unwrap(), DataSpaceId::UNIVERSAL)
}

fn account(id: &AccountId) -> AccountValue {
    Account::new(id.clone()).build(id).into_key_value().1
}

fn encoded<K: mv::Key + Encode, V: mv::Value + Encode>(store: &Storage<K, V>) -> String {
    let mut result = String::new();
    snapshot_storage::serialize(store, &mut result);
    result
}

fn roundtrip<K, V>(store: &Storage<K, V>) -> Storage<K, V>
where
    K: mv::Key + Encode + DecodeAll,
    V: mv::Value + Encode + DecodeAll,
{
    json::from_str::<snapshot_storage::SnapshotStorage>(&encoded(store))
        .unwrap()
        .decode("account rekey fixture", |_, _| true)
        .unwrap()
}

fn sources(world: &World) -> [String; 3] {
    [
        encoded(&world.accounts),
        encoded(&world.account_aliases),
        encoded(&world.account_rekey_records),
    ]
}

fn fixture() -> World {
    let mut world = World::default();
    for id in [&*ALICE_ID, &*BOB_ID] {
        world.accounts.insert(id.clone(), account(id));
    }
    let label = alias("wallet");
    world.account_rekey_records.insert(
        label.clone(),
        AccountRekeyRecord::new(label.clone(), ALICE_ID.clone()),
    );
    world
        .account_aliases
        .insert(label.clone(), ALICE_ID.clone());
    // This deliberately stale skipped index must survive every failed rebuild.
    world
        .account_rekey_records_by_account
        .insert(CARPENTER_ID.clone(), BTreeSet::from([alias("stale-index")]));
    world
}

fn assert_refusal(world: &mut World, prior: bool, reason: &str) {
    let before = sources(world);
    let index = encoded(&world.account_rekey_records_by_account);
    let error = rebuild(world).expect_err("corrupt source image cannot be restored");
    assert!(
        error.contains(if prior { "predecessor" } else { "current" }),
        "{error}"
    );
    assert!(error.contains(reason), "{error}");
    assert_eq!(sources(world), before);
    assert_eq!(encoded(&world.account_rekey_records_by_account), index);
}

#[test]
fn malformed_records_in_either_image_leave_all_sources_and_existing_index_unchanged() {
    for prior in [false, true] {
        for case in 0..7 {
            let mut world = fixture();
            let label = if case == 1 {
                alias("1234567890")
            } else {
                alias("wallet")
            };
            let good = AccountRekeyRecord::new(label.clone(), ALICE_ID.clone());
            let mut bad = good.clone();
            let reason = match case {
                0 => {
                    bad.label = alias("wrong-key");
                    "mismatched label"
                }
                1 => "raw PII",
                2 => {
                    bad.active_account_id = CARPENTER_ID.clone();
                    "missing account"
                }
                3 => {
                    bad.previous_account_ids.push(CARPENTER_ID.clone());
                    "malformed provenance"
                }
                4 => {
                    bad.previous_account_ids = vec![ALICE_ID.clone()];
                    bad.transition_provenance = vec![Provenance::AccountIdRekey];
                    "cycle"
                }
                5 => {
                    bad.previous_account_ids = vec![CARPENTER_ID.clone(); 2];
                    bad.transition_provenance = vec![Provenance::AccountIdRekey; 2];
                    "repeats active"
                }
                6 => {
                    bad.previous_account_ids = vec![BOB_ID.clone()];
                    bad.transition_provenance = vec![Provenance::AccountIdRekey];
                    "independently live account"
                }
                _ => unreachable!(),
            };
            // PII is invalid as a key in either image. For the predecessor case
            // remove it in current instead of giving current the same bad key.
            world.account_rekey_records = if prior {
                let current = if case == 1 {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(label.clone(), good)])
                };
                Storage::from_snapshot_parts(current, BTreeMap::from([(label, Some(bad))]))
            } else {
                Storage::from_snapshot_parts(BTreeMap::from([(label, bad)]), BTreeMap::new())
            };
            world.account_aliases = Storage::default();
            assert_refusal(&mut world, prior, reason);
        }
    }
}

#[test]
fn alias_and_account_references_are_checked_against_the_matching_image() {
    for prior in [false, true] {
        for case in 0..3 {
            let mut world = fixture();
            let label = if case == 0 {
                alias("missing-record")
            } else {
                alias("wallet")
            };
            let target = if case == 2 {
                CARPENTER_ID.clone()
            } else {
                BOB_ID.clone()
            };
            world.account_aliases = if prior {
                Storage::from_snapshot_parts(
                    BTreeMap::from([(alias("wallet"), ALICE_ID.clone())]),
                    BTreeMap::from([(label, Some(target))]),
                )
            } else {
                Storage::from_snapshot_parts(BTreeMap::from([(label, target)]), BTreeMap::new())
            };
            let reason = [
                "missing its continuity record",
                "continuity record points",
                "missing account",
            ][case];
            assert_refusal(&mut world, prior, reason);
        }
    }
    let mut world = fixture();
    world.accounts = Storage::from_snapshot_parts(
        BTreeMap::from([(ALICE_ID.clone(), account(&ALICE_ID))]),
        BTreeMap::from([(ALICE_ID.clone(), None)]),
    );
    assert_refusal(&mut world, true, "missing account");
}

#[test]
fn ambiguous_targets_are_rejected_in_the_predecessor_even_after_current_cleanup() {
    let mut world = fixture();
    let records = [ALICE_ID.clone(), BOB_ID.clone()]
        .into_iter()
        .enumerate()
        .map(|(i, active)| {
            let label = alias(&format!("wallet{i}"));
            let record = AccountRekeyRecord::new(label.clone(), CARPENTER_ID.clone())
                .repoint_for_account_id_rekey(active)
                .unwrap();
            (label, Some(record))
        })
        .collect();
    world.account_rekey_records = Storage::from_snapshot_parts(BTreeMap::new(), records);
    world.account_aliases = Storage::default();
    assert_refusal(&mut world, true, "ambiguously targets");
}

#[test]
fn a_real_account_rekey_uses_retired_and_created_accounts_from_each_original_image() {
    let mut world = fixture();
    let label = alias("wallet");
    let previous = AccountRekeyRecord::new(label.clone(), ALICE_ID.clone());
    let current = previous
        .repoint_for_account_id_rekey(BOB_ID.clone())
        .unwrap();
    world.accounts = Storage::from_snapshot_parts(
        BTreeMap::from([(BOB_ID.clone(), account(&BOB_ID))]),
        BTreeMap::from([
            (ALICE_ID.clone(), Some(account(&ALICE_ID))),
            (BOB_ID.clone(), None),
        ]),
    );
    world.account_aliases = Storage::from_snapshot_parts(
        BTreeMap::from([(label.clone(), BOB_ID.clone())]),
        BTreeMap::from([(label.clone(), Some(ALICE_ID.clone()))]),
    );
    world.account_rekey_records = Storage::from_snapshot_parts(
        BTreeMap::from([(label.clone(), current)]),
        BTreeMap::from([(label.clone(), Some(previous))]),
    );
    let before = sources(&world);
    rebuild(&mut world).unwrap();
    assert_eq!(sources(&world), before);
    let history = world.account_rekey_records_by_account.history();
    for id in [&*ALICE_ID, &*BOB_ID] {
        assert_eq!(
            history.current().get(id),
            Some(&BTreeSet::from([label.clone()]))
        );
    }
    assert_eq!(
        history.get_before_block(&*ALICE_ID),
        Some(&BTreeSet::from([label]))
    );
    assert!(history.get_before_block(&*BOB_ID).is_none());
    assert_eq!(history.revert_map().len(), 2);
}

#[test]
fn alias_reassignment_and_expired_alias_cleanup_keep_audit_occurrences() {
    let mut world = fixture();
    let label = alias("wallet");
    let record = AccountRekeyRecord::new(label.clone(), ALICE_ID.clone())
        .reassign_alias_to_account(BOB_ID.clone())
        .unwrap()
        .reassign_alias_to_account(ALICE_ID.clone())
        .unwrap()
        .reassign_alias_to_account(BOB_ID.clone())
        .unwrap();
    world.account_rekey_records.insert(label.clone(), record);
    world.account_aliases = Storage::default();
    let before = sources(&world);
    rebuild(&mut world).unwrap();
    assert_eq!(sources(&world), before);
    let view = world.account_rekey_records_by_account.view();
    assert_eq!(view.len(), 2);
    for id in [&*ALICE_ID, &*BOB_ID] {
        assert_eq!(view.get(id), Some(&BTreeSet::from([label.clone()])));
    }
}

#[test]
fn snapshot_roundtrip_preserves_complete_shared_buckets_and_redundant_touches() {
    let mut world = fixture();
    world.account_aliases = Storage::default();
    let wallet = alias("wallet");
    let old = AccountRekeyRecord::new(wallet.clone(), ALICE_ID.clone());
    let moved = old.reassign_alias_to_account(BOB_ID.clone()).unwrap();
    let untouched = alias("untouched");
    let redundant = alias("redundant");
    let deleted = alias("deleted");
    let inserted = alias("inserted");
    let same = AccountRekeyRecord::new(redundant.clone(), ALICE_ID.clone());
    world.account_rekey_records = Storage::from_snapshot_parts(
        BTreeMap::from([
            (wallet.clone(), moved),
            (
                untouched.clone(),
                AccountRekeyRecord::new(untouched.clone(), ALICE_ID.clone()),
            ),
            (redundant.clone(), same.clone()),
            (
                inserted.clone(),
                AccountRekeyRecord::new(inserted.clone(), BOB_ID.clone()),
            ),
        ]),
        BTreeMap::from([
            (wallet.clone(), Some(old)),
            (redundant.clone(), Some(same)),
            (
                deleted.clone(),
                Some(AccountRekeyRecord::new(deleted.clone(), ALICE_ID.clone())),
            ),
            (inserted.clone(), None),
            (alias("absent-touch"), None),
        ]),
    );
    world.accounts = roundtrip(&world.accounts);
    world.account_aliases = roundtrip(&world.account_aliases);
    world.account_rekey_records = roundtrip(&world.account_rekey_records);
    let before = sources(&world);
    rebuild(&mut world).unwrap();
    assert_eq!(sources(&world), before);
    let index = encoded(&world.account_rekey_records_by_account);
    rebuild(&mut world).unwrap();
    assert_eq!(encoded(&world.account_rekey_records_by_account), index);
    let history = world.account_rekey_records_by_account.history();
    assert_eq!(
        history.current().get(&*ALICE_ID),
        Some(&BTreeSet::from([
            wallet.clone(),
            untouched.clone(),
            redundant.clone()
        ]))
    );
    assert_eq!(
        history.current().get(&*BOB_ID),
        Some(&BTreeSet::from([wallet.clone(), inserted]))
    );
    assert_eq!(
        history.get_before_block(&*ALICE_ID),
        Some(&BTreeSet::from([wallet, untouched, redundant, deleted]))
    );
    assert!(history.get_before_block(&*BOB_ID).is_none());
    assert_eq!(history.revert_map().len(), 2);
}

#[test]
fn only_the_maximal_rekey_suffix_requires_retired_predecessors_in_each_image() {
    let retired = AccountId::new(crate::state::checked_keypair().public_key().clone());
    for prior in [false, true] {
        let mut world = fixture();
        world
            .accounts
            .insert(CARPENTER_ID.clone(), account(&CARPENTER_ID));
        let label = alias("wallet");
        let record = AccountRekeyRecord::new(label.clone(), ALICE_ID.clone())
            .repoint_for_account_id_rekey(CARPENTER_ID.clone())
            .unwrap()
            .reassign_alias_to_account(retired.clone())
            .unwrap()
            .repoint_for_account_id_rekey(BOB_ID.clone())
            .unwrap();
        world.account_rekey_records.insert(label.clone(), record);
        world.account_aliases.insert(label, BOB_ID.clone());
        // The reassignment breaks continuity with both still-live old accounts.
        rebuild(&mut world).unwrap();
        let mut current = [&*ALICE_ID, &*BOB_ID, &*CARPENTER_ID]
            .into_iter()
            .map(|id| (id.clone(), account(id)))
            .collect::<BTreeMap<_, _>>();
        let undo = if prior {
            BTreeMap::from([(retired.clone(), Some(account(&retired)))])
        } else {
            current.insert(retired.clone(), account(&retired));
            BTreeMap::from([(retired.clone(), None)])
        };
        world.accounts = Storage::from_snapshot_parts(current, undo);
        assert_refusal(&mut world, prior, "independently live account");
    }
}

#[test]
fn unchanged_membership_retains_its_explicit_undo_bucket() {
    let mut world = fixture();
    let label = alias("wallet");
    let record = AccountRekeyRecord::new(label.clone(), ALICE_ID.clone());
    world.account_rekey_records = Storage::from_snapshot_parts(
        BTreeMap::from([(label.clone(), record.clone())]),
        BTreeMap::from([(label.clone(), Some(record))]),
    );
    rebuild(&mut world).unwrap();
    let history = world.account_rekey_records_by_account.history();
    let bucket = BTreeSet::from([label]);
    assert_eq!(history.current().get(&*ALICE_ID), Some(&bucket));
    assert_eq!(history.revert_map().get(&*ALICE_ID), Some(&Some(bucket)));
}
