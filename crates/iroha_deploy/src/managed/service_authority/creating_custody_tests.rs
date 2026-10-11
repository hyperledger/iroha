//! One Custody creator keeps fresh native admission and exact original caller-budget fallback.

use super::creating_original_tests::{fixture, limits, parsed};
use super::*;
use crate::managed::{ManagedStreamTokenCustody, native_operation::test_support::UnavailablePeers};
use iroha_fs::{FileIdentity, PublishMode};
use norito::core::DecodeBudgetContext;
use std::{cell::Cell, rc::Rc};

fn create(parent: &ServiceAuthority, provider: ProviderId) -> Result<ServiceAuthority> {
    ServiceAuthority::open_provider_from_original(parent, provider, ProviderPurpose::Custody)
}
fn ordinary(parent: &ServiceAuthority, provider: ProviderId) -> Result<ServiceAuthority> {
    ServiceAuthority::open_provider(&parent.prepared, provider, ProviderPurpose::Custody)
}
fn custody_path(parent: &ServiceAuthority, provider: ProviderId) -> std::path::PathBuf {
    parent
        .profile
        .runtime()
        .path()
        .join("service-operations/providers")
        .join(parent.manifest.provider(provider).unwrap().slot.to_string())
        .join(ProviderPurpose::Custody.directory_name())
}

#[test]
fn custody_creator_keeps_fresh_absence_exact_provider_lock_and_original_projection() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut parent) = fixture();
    let mut peers = UnavailablePeers::start(&parent.prepared);
    let providers = parent.manifest.providers.clone();
    for inventory in &providers {
        let provider = inventory.provider_id;
        let path = custody_path(&parent, provider);
        assert!(!path.exists());
        let (baseline_absent, parses) =
            parsed(|| ManagedStreamTokenCustody::open_existing(&parent.prepared, provider));
        assert!(baseline_absent.unwrap().is_none());
        assert_eq!(parses, 1);
        assert!(!path.exists());
        let ((absent, parses), checks) = profile_validation_test_support::count(|| {
            parsed(|| {
                ManagedStreamTokenCustody::open_existing_from_original(&parent, provider, None)
            })
        });
        assert!(absent.unwrap().is_none());
        assert_eq!(parses, 0);
        assert_eq!(checks, 2);
        assert!(
            !path.exists(),
            "ordinary absence admission cannot create the purpose"
        );
        let (owner, parses) =
            parsed(|| ManagedStreamTokenCustody::open_from_original(&parent, provider));
        let owner = owner.unwrap();
        assert_eq!(parses, 0);
        assert!(path.is_dir());
        assert!(
            ordinary(&parent, provider).is_err(),
            "typed Custody retains this provider's exact lock"
        );
        drop(owner);
        let (expected, parses) = parsed(|| ordinary(&parent, provider));
        let expected = expected.unwrap();
        assert_eq!(parses, 1);
        assert_eq!(expected.provider_id().unwrap(), provider);
        assert_eq!(expected.directory.path(), path);
        let directory = expected.directory.retain().unwrap();
        let identity = directory.identity().unwrap();
        let lock_identity = FileIdentity::of(&expected._lock).unwrap();
        let names = directory.entries(2).unwrap();
        let lock_bytes = directory.read("operation.lock", 4096).unwrap();
        let config = expected.config.clone();
        let genesis = expected.genesis.clone();
        let ids: Vec<_> = expected.peers.iter().map(|(id, _)| id.clone()).collect();
        drop(expected);
        let original_config = parent.config.clone();
        let original_genesis = parent.genesis.clone();
        parent.config.chain = "changed-custody-projection".parse().unwrap();
        parent.config.account_chain_discriminant ^= 1;
        parent.genesis.chain_id.push_str("-projection");
        parent.peers.reverse();
        let ((actual, parses), checks) =
            profile_validation_test_support::count(|| parsed(|| create(&parent, provider)));
        let actual = actual.unwrap();
        assert_eq!((parses, checks), (0, 2));
        assert!(matches!(&actual.profile, AuthorityProfile::Shared(_)));
        assert!(
            actual.checkpoint_import_scope().is_none(),
            "Advance adds no lexical import sharing"
        );
        assert_eq!(actual.provider_id().unwrap(), provider);
        assert_eq!(actual.directory.identity().unwrap(), identity);
        assert_eq!(FileIdentity::of(&actual._lock).unwrap(), lock_identity);
        assert_eq!(actual.config.chain, config.chain);
        assert_eq!(actual.config.network_id, config.network_id);
        assert_eq!(actual.config.account, config.account);
        assert_eq!(
            actual.config.key_pair.public_key(),
            config.key_pair.public_key()
        );
        assert_eq!(
            actual.config.account_chain_discriminant,
            config.account_chain_discriminant
        );
        assert_eq!(actual.config.torii_api_url, config.torii_api_url);
        assert_eq!(actual.genesis, genesis);
        assert_eq!(
            actual
                .peers
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>(),
            ids
        );
        assert!(ordinary(&parent, provider).is_err());
        actual.validate_profile().unwrap();
        drop(actual);
        parent.config = original_config;
        parent.genesis = original_genesis;
        parent.peers.reverse();
        let retry = ordinary(&parent, provider).unwrap();
        assert_eq!(retry.directory.identity().unwrap(), identity);
        assert_eq!(FileIdentity::of(&retry._lock).unwrap(), lock_identity);
        drop(retry);
        assert_eq!(directory.entries(2).unwrap(), names);
        assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
        parent.validate_profile().unwrap();
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn custody_creator_closes_parent_on_native_errors_and_refuses_replacement_with_retry() {
    let _guard = crate::managed::native_test_guard();
    let (temporary, parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    let path = custody_path(&parent, provider);
    let parent_identity = parent.directory.identity().unwrap();
    let mut peers = UnavailablePeers::start(&parent.prepared);
    let generation =
        PrivateDirectory::open_exact(parent.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.push(0);
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    assert!(create(&parent, provider).is_err());
    assert!(
        !path.exists(),
        "parent entry refuses before native creation"
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let selected = parent
        .profile
        .runtime()
        .ensure_child("service-operations")
        .unwrap()
        .ensure_child("providers")
        .unwrap()
        .ensure_child("0")
        .unwrap();
    selected
        .write_atomic(
            ProviderPurpose::Custody.directory_name(),
            b"wrong native kind",
            PublishMode::CreateNew,
        )
        .unwrap();
    let ((refused, parses), checks) =
        profile_validation_test_support::count(|| parsed(|| create(&parent, provider)));
    assert!(refused.is_err());
    assert_eq!(
        (parses, checks),
        (0, 2),
        "ordinary native failure still closes the original parent"
    );
    selected
        .remove_private(ProviderPurpose::Custody.directory_name())
        .unwrap();
    let held = create(&parent, provider).unwrap();
    let directory = held.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&held._lock).unwrap();
    let lock_bytes = directory.read("operation.lock", 4096).unwrap();
    let ((locked, parses), checks) =
        profile_validation_test_support::count(|| parsed(|| create(&parent, provider)));
    assert!(locked.is_err());
    assert_eq!((parses, checks), (0, 2));
    // Force genuine closing drift on an ordinary lock-refusal Result, never a forged success.
    let reached = Rc::new(Cell::new(false));
    let mark = Rc::clone(&reached);
    let generation_for_hook = generation.retain().unwrap();
    let hook_changed = zeroize::Zeroizing::new(changed.to_vec());
    let hook = ServiceAuthority::test_on_creating_child_exit(move || {
        mark.set(true);
        generation_for_hook
            .write_atomic("peer3.toml", &hook_changed, PublishMode::Replace)
            .unwrap();
    });
    let closing_error = create(&parent, provider).err().unwrap();
    assert!(reached.get());
    assert_eq!(
        closing_error.to_string(),
        parent.validate_profile().err().unwrap().to_string(),
        "the real closing parent refusal supersedes the ordinary child-lock refusal"
    );
    drop(hook);
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    held.validate_profile().unwrap();
    #[cfg(unix)]
    {
        let saved = temporary.path().join("saved-custody");
        std::fs::rename(&path, &saved).unwrap();
        let replacement = PrivateDirectory::open_or_create(&path).unwrap();
        assert!(
            held.validate_profile().is_err(),
            "the held original child cannot accept a replacement"
        );
        drop(replacement);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved, &path).unwrap();
        held.validate_profile().unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(&path, temporary.path().join("saved-custody")).is_err());
        assert!(
            std::fs::rename(
                path.join("operation.lock"),
                path.join("saved-operation.lock")
            )
            .is_err()
        );
        held.validate_profile().unwrap();
    }
    drop(held);
    #[cfg(unix)]
    {
        let parent_path = parent.directory.path();
        let saved_parent = temporary.path().join("saved-bootstrap-parent");
        std::fs::rename(parent_path, &saved_parent).unwrap();
        let replacement = PrivateDirectory::open_or_create(parent_path).unwrap();
        assert!(
            create(&parent, provider).is_err(),
            "a replaced original parent grants no child admission"
        );
        drop(replacement);
        std::fs::remove_dir(parent_path).unwrap();
        std::fs::rename(&saved_parent, parent_path).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(
            std::fs::rename(
                parent.directory.path(),
                temporary.path().join("saved-bootstrap-parent")
            )
            .is_err()
        );
    }
    let retry = create(&parent, provider).unwrap();
    assert_eq!(retry.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&retry._lock).unwrap(), lock_identity);
    drop(retry);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    assert_eq!(
        generation.read("peer3.toml", 1024 * 1024).unwrap(),
        original
    );
    assert_eq!(parent.directory.identity().unwrap(), parent_identity);
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn custody_creator_preserves_full_active_decode_and_owned_parent_fallback() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    let mut peers = UnavailablePeers::start(&parent.prepared);
    // Compare the changed existing admission while the actual purpose is absent.
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) = parsed(|| {
        baseline.with(|| ManagedStreamTokenCustody::open_existing(&parent.prepared, provider))
    });
    assert!(expected.unwrap().is_none());
    assert_eq!(parses, 1);
    let absence_charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(absence_charge > 0);
    let exact = DecodeBudgetContext::new(limits(absence_charge));
    let (actual, parses) = parsed(|| {
        exact.with(|| {
            ManagedStreamTokenCustody::open_existing_from_original(&parent, provider, None)
        })
    });
    assert!(actual.unwrap().is_none());
    assert_eq!(parses, 1);
    assert_eq!(exact.consumed_allocated_bytes(), absence_charge as u64);
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) = parsed(|| baseline.with(|| ordinary(&parent, provider)));
    let expected = expected.unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(&expected.profile, AuthorityProfile::Owned(_)));
    let identity = expected.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    drop(expected);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (actual, parses) = parsed(|| exact.with(|| create(&parent, provider)));
    let actual = actual.unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(&actual.profile, AuthorityProfile::Owned(_)));
    assert!(actual.checkpoint_import_scope().is_none());
    assert_eq!(exact.consumed_allocated_bytes(), charge as u64);
    assert_eq!(actual.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&actual._lock).unwrap(), lock_identity);
    drop(actual);
    for allocated in [0, charge - 1] {
        let expected_budget = DecodeBudgetContext::new(limits(allocated));
        let expected = expected_budget
            .with(|| ordinary(&parent, provider))
            .err()
            .unwrap();
        let actual_budget = DecodeBudgetContext::new(limits(allocated));
        let actual = actual_budget
            .with(|| create(&parent, provider))
            .err()
            .unwrap();
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
    }
    let prepared = parent.prepared.clone();
    drop(parent);
    let entry = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let parent = entry
        .with(|| {
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
        })
        .unwrap()
        .unwrap();
    assert!(matches!(&parent.profile, AuthorityProfile::Owned(_)));
    assert!(!norito::core::decode_limits_active());
    let (actual, parses) = parsed(|| create(&parent, provider));
    let actual = actual.unwrap();
    assert_eq!(
        parses, 1,
        "Owned parent keeps the original full capture outside its old scope"
    );
    assert!(matches!(&actual.profile, AuthorityProfile::Shared(_)));
    assert!(actual.checkpoint_import_scope().is_none());
    assert_eq!(actual.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&actual._lock).unwrap(), lock_identity);
    drop(actual);
    let (actual, parses) =
        parsed(|| ManagedStreamTokenCustody::open_existing_from_original(&parent, provider, None));
    assert_eq!(parses, 1);
    drop(actual.unwrap().unwrap());
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
