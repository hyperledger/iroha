//! Account-scope replacement history from actual account, alias and binding publications.

use super::*;
use iroha_data_model::account::AccountDetails;
use norito::codec::DecodeAll;

fn members<K: mv::Key, M: mv::Key>(
    index: &impl StorageReadOnly<(K, M), ()>,
    key: &K,
) -> Option<BTreeSet<M>> {
    let members: BTreeSet<_> = index
        .iter()
        .filter(|((bucket, _), ())| bucket == key)
        .map(|((_, member), ())| member.clone())
        .collect();
    (!members.is_empty()).then_some(members)
}

fn alias(name: &str, dataspace: u64, domain: Option<&str>) -> AccountAlias {
    AccountAlias::new(
        name.parse().unwrap(),
        domain.map(|domain| AccountAliasDomain::new(domain.parse().unwrap())),
        DataSpaceId::new(dataspace),
    )
}

fn account(uaid: UniversalAccountId, primary: Option<AccountAlias>) -> AccountValue {
    AccountValue::new(AccountDetails::new(
        Metadata::default(),
        primary,
        Some(uaid),
        Vec::new(),
    ))
}

fn binding(dataspace: u64, account: &AccountId) -> UaidDataspaceBindings {
    let mut result = UaidDataspaceBindings::default();
    result.bind_account(DataSpaceId::new(dataspace), account.clone());
    result
}

fn encoded<K: mv::Key + Encode, V: mv::Value + Encode>(store: &Storage<K, V>) -> String {
    let mut result = String::new();
    snapshot_storage::serialize(store, &mut result);
    result
}

fn restored<K, V>(store: &Storage<K, V>) -> Storage<K, V>
where
    K: mv::Key + Encode + DecodeAll,
    V: mv::Value + Encode + DecodeAll,
{
    json::from_str::<snapshot_storage::SnapshotStorage>(&encoded(store))
        .unwrap()
        .decode("scope fixture", |_, _| true)
        .unwrap()
}

fn scopes(world: &World) -> (String, String, String) {
    (
        encoded(&world.account_scope_directory),
        encoded(&world.account_scope_accounts),
        encoded(&world.account_scope_account_counts),
    )
}

fn sources(world: &World) -> (String, String, String) {
    (
        encoded(&world.accounts),
        encoded(&world.account_aliases),
        encoded(&world.uaid_dataspaces),
    )
}

fn fixture() -> (Box<World>, UniversalAccountId, UniversalAccountId) {
    let mut world = Box::new(World::default());
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    let first = UniversalAccountId::from_hash(Hash::new(b"scope alice"));
    let second = UniversalAccountId::from_hash(Hash::new(b"scope bob"));
    world.accounts.insert(alice.clone(), account(first, None));
    world.accounts.insert(bob.clone(), account(second, None));
    world
        .account_aliases
        .insert(alias("moving", 7, Some("shared")), alice.clone());
    world
        .account_aliases
        .insert(alias("stable", 7, Some("shared")), bob.clone());
    world
        .account_aliases
        .insert(alias("sole", 13, Some("only")), bob.clone());
    world
        .account_aliases
        .insert(alias("removed", 9, Some("old")), alice.clone());
    world
        .account_aliases
        .insert(alias("root", 11, None), alice.clone());
    world.uaid_dataspaces.insert(first, binding(17, &alice));
    world.uaid_dataspaces.insert(second, binding(23, &bob));
    world.rebuild_account_alias_index().unwrap();
    world.rebuild_account_scope_directory().unwrap();
    (world, first, second)
}

#[test]
fn changed_and_removed_aliases_and_bindings_restore_both_scope_owners() {
    let (world, first, second) = fixture();
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    let prior_directory = world
        .account_scope_directory
        .view()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Directory>();
    {
        let mut block = world.block();
        block
            .account_aliases
            .insert(alias("moving", 7, Some("shared")), bob.clone());
        block
            .account_aliases
            .remove(alias("removed", 9, Some("old")));
        block.uaid_dataspaces.insert(first, binding(19, &alice));
        block.uaid_dataspaces.remove(second);
        block.commit();
    }
    let authoritative = sources(&world);
    let mut restart = Box::new(World::default());
    restart.accounts = restored(&world.accounts);
    restart.account_aliases = restored(&world.account_aliases);
    restart.uaid_dataspaces = restored(&world.uaid_dataspaces);
    restart.rebuild_account_scope_directory().unwrap();
    assert_eq!(sources(&restart), authoritative);
    let shared = (
        DataSpaceId::new(7),
        AccountAliasDomain::new("shared".parse().unwrap()),
    );
    assert_eq!(
        members(&restart.account_scope_accounts.view(), &shared).as_ref(),
        Some(&BTreeSet::from([bob.clone()]))
    );
    {
        let directory = restart.account_scope_directory.view();
        let alice_scope: BTreeSet<_> = directory
            .get(&alice)
            .unwrap()
            .iter()
            .map(|(dataspace, _)| *dataspace)
            .collect();
        assert!(alice_scope.contains(&DataSpaceId::new(19)));
        assert!(!alice_scope.contains(&DataSpaceId::new(17)));
        assert!(
            !directory
                .get(&bob)
                .unwrap()
                .iter()
                .any(|(dataspace, _)| *dataspace == DataSpaceId::new(23))
        );
    }
    assert!(
        restart
            .account_scope_directory
            .view()
            .get(&alice)
            .unwrap()
            .iter()
            .any(|(dataspace, domains)| *dataspace == DataSpaceId::new(11) && domains.is_empty())
    );
    assert_eq!(
        restart.account_scope_account_counts.view().get(&shared),
        Some(&1)
    );
    let tip = scopes(&restart);
    {
        let replacement = restart.block_and_revert();
        for (account, entry) in &prior_directory {
            assert_eq!(
                replacement.account_scope_directory.get(account),
                Some(entry)
            );
        }
        assert_eq!(
            replacement.account_scope_account_counts.get(&shared),
            Some(&2)
        );
        assert_eq!(
            members(&replacement.account_scope_accounts, &shared).as_ref(),
            Some(&BTreeSet::from([alice.clone(), bob.clone()]))
        );
    }
    assert_eq!(sources(&restart), authoritative);
    assert_eq!(scopes(&restart), tip);
    restart.rebuild_account_scope_directory().unwrap();
    assert_eq!(
        scopes(&restart),
        tip,
        "repeat restore retains exact touched-key history"
    );
    restart.block_and_revert().commit();
    restart.rebuild_account_scope_directory().unwrap();
    for (account, entry) in prior_directory {
        assert_eq!(
            restart.account_scope_directory.view().get(&account),
            Some(&entry)
        );
    }
}

#[test]
fn account_removal_primary_reassignment_and_absent_touch_survive_replacement() {
    let mut world = Box::new(World::default());
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"scope reassigned primary"));
    let primary = alias("primary", 7, Some("owned"));
    let absent = AccountId::new(
        KeyPair::try_from_seed(vec![0x39; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    world
        .accounts
        .insert(alice.clone(), account(uaid, Some(primary.clone())));
    world.account_aliases.insert(primary.clone(), alice.clone());
    world.uaid_dataspaces.insert(uaid, binding(17, &alice));
    rebuild(&mut world).unwrap();
    {
        let mut block = world.block();
        block.accounts.remove(alice.clone());
        block.accounts.remove(absent.clone());
        block
            .accounts
            .insert(bob.clone(), account(uaid, Some(primary.clone())));
        block.account_aliases.insert(primary.clone(), bob.clone());
        block.uaid_dataspaces.insert(uaid, binding(19, &bob));
        block.commit();
    }
    rebuild(&mut world).unwrap();
    assert!(world.account_scope_directory.view().get(&alice).is_none());
    assert!(
        !world
            .account_scope_directory
            .view()
            .get(&bob)
            .unwrap()
            .iter()
            .any(|(dataspace, _)| *dataspace == DataSpaceId::UNIVERSAL)
    );
    assert_eq!(
        world
            .account_scope_directory
            .snapshot()
            .revert_map()
            .get(&absent),
        Some(&None)
    );
    assert_eq!(
        world
            .account_scope_directory
            .snapshot()
            .revert_map()
            .get(&bob),
        Some(&None)
    );
    let before = (sources(&world), scopes(&world));
    for commit in [false, true] {
        let mut replacement = world.block_and_revert();
        assert!(replacement.account_scope_directory.get(&alice).is_some());
        assert!(replacement.account_scope_directory.get(&bob).is_none());
        {
            let mut tx = replacement.transaction_without_telemetry(LaneConfig::default(), 0);
            tx.insert_account_alias_binding(alias("replacement", 31, Some("new")), alice.clone());
            tx.apply();
        }
        if commit {
            replacement.commit();
        } else {
            drop(replacement);
            assert_eq!((sources(&world), scopes(&world)), before);
        }
    }
    let source_tip = sources(&world);
    rebuild(&mut world).unwrap();
    assert_eq!(sources(&world), source_tip);
    assert!(
        world
            .account_scope_directory
            .view()
            .get(&alice)
            .unwrap()
            .iter()
            .any(|(dataspace, _)| *dataspace == DataSpaceId::new(31))
    );
    let replacement = world.block_and_revert();
    assert!(
        !replacement
            .account_scope_directory
            .get(&alice)
            .unwrap()
            .iter()
            .any(|(dataspace, _)| *dataspace == DataSpaceId::new(31))
    );
}

#[test]
fn invalid_predecessor_alias_rejects_before_either_scope_owner_changes() {
    for missing_owner in [false, true] {
        let mut world = Box::new(World::default());
        let alice = iroha_test_samples::ALICE_ID.clone();
        let bob = iroha_test_samples::BOB_ID.clone();
        let uaid = UniversalAccountId::from_hash(Hash::new(b"scope invalid prior"));
        let primary = alias("primary", 7, Some("owned"));
        world.accounts.insert(alice.clone(), account(uaid, None));
        rebuild(&mut world).unwrap();
        // An actual publication removes the invalid prior material, leaving a valid tip.
        if missing_owner {
            world.account_aliases.insert(primary.clone(), bob);
        } else {
            world
                .accounts
                .insert(alice.clone(), account(uaid, Some(primary.clone())));
        }
        {
            let mut block = world.block();
            block.account_aliases.remove(primary.clone());
            block.accounts.insert(alice.clone(), account(uaid, None));
            block.commit();
        }
        let before = (sources(&world), scopes(&world));
        let error = rebuild(&mut world).unwrap_err();
        assert!(error.contains("predecessor account scope"), "{error}");
        assert!(
            error.contains(if missing_owner {
                "missing account"
            } else {
                "primary label"
            }),
            "{error}"
        );
        assert_eq!((sources(&world), scopes(&world)), before);
    }
}

#[test]
fn live_entry_semantics_ignore_nonmember_bindings_and_preserve_universal_fallback() {
    let (mut world, first, _) = fixture();
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    world.uaid_dataspaces.insert(first, binding(29, &bob));
    rebuild(&mut world).unwrap();
    let view = world.view();
    let derived = derive_account_scope_directory_entry(&view, &alice).unwrap();
    assert_eq!(view.account_scope_directory.get(&alice), Some(&derived));
    assert!(
        !derived
            .iter()
            .any(|(dataspace, _)| *dataspace == DataSpaceId::new(29))
    );
    assert!(
        derived
            .iter()
            .any(|(dataspace, _)| *dataspace == DataSpaceId::UNIVERSAL)
    );
    assert!(
        derive_account_scope_directory_entry(
            &view,
            &AccountId::new(
                KeyPair::try_from_seed(vec![0x40; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone()
            )
        )
        .is_none()
    );
}

#[test]
fn inverse_rebuild_preserves_catalog_pruning_and_redundant_touched_buckets() {
    let (mut world, _, _) = fixture();
    let alice = iroha_test_samples::ALICE_ID.clone();
    let bob = iroha_test_samples::BOB_ID.clone();
    let original = world
        .account_scope_accounts
        .view()
        .iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect::<AccountsIndex>();
    {
        let mut block = world.account_scope_directory.block();
        let mut alice_entry = block.get(&alice).unwrap().clone();
        alice_entry.retain_dataspaces(&BTreeSet::from([DataSpaceId::UNIVERSAL]));
        block.insert(alice.clone(), alice_entry);
        let unchanged_bob = block.get(&bob).unwrap().clone();
        block.insert(bob.clone(), unchanged_bob);
        block.commit();
    }
    world.rebuild_account_scope_accounts_index();
    let shared = (
        DataSpaceId::new(7),
        AccountAliasDomain::new("shared".parse().unwrap()),
    );
    assert_eq!(
        members(&world.account_scope_accounts.view(), &shared).as_ref(),
        Some(&BTreeSet::from([bob.clone()]))
    );
    let unchanged = (
        DataSpaceId::new(13),
        AccountAliasDomain::new("only".parse().unwrap()),
    );
    assert_eq!(
        world
            .account_scope_accounts
            .snapshot()
            .revert_map()
            .get(&(unchanged, bob.clone())),
        Some(&Some(()))
    );
    let rebuilt = scopes(&world);
    world.rebuild_account_scope_accounts_index();
    assert_eq!(scopes(&world), rebuilt);
    {
        let replacement = world.block_and_revert();
        assert_eq!(
            replacement.account_scope_account_counts.get(&shared),
            Some(&2)
        );
        assert_eq!(
            members(&replacement.account_scope_accounts, &shared).as_ref(),
            Some(&BTreeSet::from([alice, bob]))
        );
    }
    assert_eq!(scopes(&world), rebuilt);
    world.block_and_revert().commit();
    assert_eq!(
        world
            .account_scope_accounts
            .view()
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect::<AccountsIndex>(),
        original
    );
}
