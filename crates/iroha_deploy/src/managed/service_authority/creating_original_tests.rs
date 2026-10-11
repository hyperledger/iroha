//! Reserve creation borrows immutable intent while retaining fresh native child and parent custody.

use super::*;
use crate::managed::{
    ManagedInitialReservePolicy, native_operation::test_support::UnavailablePeers,
};
use iroha_fs::{FileIdentity, PublishMode};
use norito::core::DecodeBudgetContext;
use std::{cell::RefCell, rc::Rc};

thread_local! {
    static AFTER_CHILD: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}
pub(super) struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        AFTER_CHILD.with(|hook| *hook.borrow_mut() = None);
    }
}
pub(super) fn install(action: impl FnOnce() + 'static) -> HookGuard {
    AFTER_CHILD.with(|hook| {
        assert!(hook.borrow().is_none());
        *hook.borrow_mut() = Some(Box::new(action));
    });
    HookGuard
}
pub(super) fn after_child() {
    let action = AFTER_CHILD.with(|hook| hook.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}
pub(super) fn fixture() -> (tempfile::TempDir, ServiceAuthority) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "reserve-creating-original",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let parent =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    (temporary, parent)
}
pub(super) fn parsed<T>(action: impl FnOnce() -> T) -> (T, usize) {
    crate::localnet::service_authorities::count_profile_validations(action)
}
fn create(parent: &ServiceAuthority) -> Result<ServiceAuthority> {
    ServiceAuthority::open_network_from_original(parent, NetworkPurpose::InitialReservePolicy)
}
fn ordinary(parent: &ServiceAuthority) -> Result<ServiceAuthority> {
    ServiceAuthority::open_network(&parent.prepared, NetworkPurpose::InitialReservePolicy)
}
fn reserve_path(parent: &ServiceAuthority) -> std::path::PathBuf {
    parent
        .directory
        .path()
        .parent()
        .unwrap()
        .join(NetworkPurpose::InitialReservePolicy.directory_name())
}

#[test]
fn reserve_creator_reuses_immutable_original_and_holds_the_exact_native_purpose() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut parent) = fixture();
    let mut peers = UnavailablePeers::start(&parent.prepared);
    assert!(!reserve_path(&parent).exists());
    let (first, parses) = parsed(|| ManagedInitialReservePolicy::open_from_original(&parent));
    let first = first.unwrap();
    assert_eq!(parses, 0);
    assert!(reserve_path(&parent).is_dir());
    assert!(
        ordinary(&parent).is_err(),
        "the typed creator holds Reserve's lock"
    );
    drop(first);
    let (expected, parses) = parsed(|| ordinary(&parent));
    let expected = expected.unwrap();
    assert_eq!(parses, 1);
    assert!(create(&parent).is_err());
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
    parent.config.chain = "changed-reserve-projection".parse().unwrap();
    parent.config.account_chain_discriminant ^= 1;
    parent.config.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"changed reserve projection"),
        ));
    parent.genesis.chain_id.push_str("-projection");
    parent.peers.reverse();
    let ((actual, parses), checks) =
        profile_validation_test_support::count(|| parsed(|| create(&parent)));
    let actual = actual.unwrap();
    assert_eq!(parses, 0);
    assert_eq!(
        checks, 2,
        "fresh parent entry and ordinary exit remain real"
    );
    assert!(matches!(&actual.profile, AuthorityProfile::Shared(_)));
    assert!(actual.checkpoint_import_scope().is_none());
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
    assert!(ordinary(&parent).is_err());
    actual.validate_profile().unwrap();
    drop(actual);
    parent.config = original_config;
    parent.genesis = original_genesis;
    parent.peers.reverse();
    let retry = ordinary(&parent).unwrap();
    assert_eq!(retry.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&retry._lock).unwrap(), lock_identity);
    drop(retry);
    assert_eq!(directory.entries(2).unwrap(), names);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn reserve_creator_refuses_fresh_profile_native_substitution_and_closes_parent_exit() {
    let _guard = crate::managed::native_test_guard();
    let (temporary, parent) = fixture();
    let parent_identity = parent.directory.identity().unwrap();
    let parent_lock_identity = FileIdentity::of(&parent._lock).unwrap();
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
    let (refused, parses) = parsed(|| ManagedInitialReservePolicy::open_from_original(&parent));
    assert!(refused.is_err());
    assert_eq!(parses, 0);
    assert!(
        !reserve_path(&parent).exists(),
        "entry refusal cannot create Reserve custody"
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let network = PrivateDirectory::open_exact(parent.directory.path().parent().unwrap()).unwrap();
    network
        .write_atomic(
            NetworkPurpose::InitialReservePolicy.directory_name(),
            b"wrong native kind",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(create(&parent).is_err());
    network
        .remove_private(NetworkPurpose::InitialReservePolicy.directory_name())
        .unwrap();
    let child = create(&parent).unwrap();
    let directory = child.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&child._lock).unwrap();
    let lock_bytes = directory.read("operation.lock", 4096).unwrap();
    #[cfg(unix)]
    {
        let saved = temporary.path().join("saved-reserve");
        std::fs::rename(directory.path(), &saved).unwrap();
        let replacement = PrivateDirectory::open_or_create(directory.path()).unwrap();
        assert!(child.validate_profile().is_err());
        drop(replacement);
        std::fs::remove_dir(directory.path()).unwrap();
        std::fs::rename(&saved, directory.path()).unwrap();
        child.validate_profile().unwrap();
        let lock = directory.path().join("operation.lock");
        let saved_lock = directory.path().join("saved-operation.lock");
        std::fs::rename(&lock, &saved_lock).unwrap();
        directory
            .write_atomic("operation.lock", &lock_bytes, PublishMode::CreateNew)
            .unwrap();
        assert!(child.validate_profile().is_err());
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(&saved_lock, &lock).unwrap();
        child.validate_profile().unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(directory.path(), temporary.path().join("saved-reserve")).is_err());
        assert!(
            std::fs::rename(
                directory.path().join("operation.lock"),
                directory.path().join("saved-operation.lock")
            )
            .is_err()
        );
        child.validate_profile().unwrap();
    }
    drop(child);
    let reached = Rc::new(std::cell::Cell::new(false));
    let mark = Rc::clone(&reached);
    let generation_for_hook = generation.retain().unwrap();
    let directory_for_hook = directory.retain().unwrap();
    let hook_changed = zeroize::Zeroizing::new(changed.to_vec());
    let _hook = install(move || {
        mark.set(true);
        match directory_for_hook.open_existing_lock("operation.lock") {
            Ok(lock) => assert!(
                lock.try_lock().is_err(),
                "real successful child Result still owns its native lock"
            ),
            Err(error) => {
                assert!(cfg!(windows));
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            }
        }
        generation_for_hook
            .write_atomic("peer3.toml", &hook_changed, PublishMode::Replace)
            .unwrap();
    });
    let ((refused, parses), checks) =
        profile_validation_test_support::count(|| parsed(|| create(&parent)));
    assert_eq!(checks, 2);
    assert!(reached.get());
    assert!(AFTER_CHILD.with(|hook| hook.borrow().is_none()));
    assert!(
        refused.is_err(),
        "late parent profile drift closes a successful child Result"
    );
    assert_eq!(parses, 0);
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let retry = create(&parent).unwrap();
    assert_eq!(retry.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&retry._lock).unwrap(), lock_identity);
    retry.validate_profile().unwrap();
    drop(retry);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    assert_eq!(
        generation.read("peer3.toml", 1024 * 1024).unwrap(),
        original
    );
    assert_eq!(parent.directory.identity().unwrap(), parent_identity);
    assert_eq!(
        FileIdentity::of(&parent._lock).unwrap(),
        parent_lock_identity
    );
    assert_eq!(
        FileIdentity::of(&parent.directory.open_read("operation.lock").unwrap()).unwrap(),
        parent_lock_identity
    );
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

pub(super) fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}
#[test]
fn reserve_creator_preserves_full_active_decode_and_owned_parent_fallback() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let mut peers = UnavailablePeers::start(&parent.prepared);
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) = parsed(|| baseline.with(|| ordinary(&parent)));
    let expected = expected.unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(&expected.profile, AuthorityProfile::Owned(_)));
    let directory = expected.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    drop(expected);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (actual, parses) = parsed(|| exact.with(|| create(&parent)));
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
        let (expected, parses) = parsed(|| expected_budget.with(|| ordinary(&parent)));
        assert_eq!(parses, 1);
        let expected = expected.err().unwrap();
        let actual_budget = DecodeBudgetContext::new(limits(allocated));
        let (actual, parses) = parsed(|| actual_budget.with(|| create(&parent)));
        assert_eq!(parses, 1);
        assert_eq!(actual.err().unwrap().to_string(), expected.to_string());
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
    }
    let (retry, parses) = parsed(|| create(&parent));
    assert_eq!(parses, 0);
    drop(retry.unwrap());
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
    let (actual, parses) = parsed(|| create(&parent));
    let actual = actual.unwrap();
    assert_eq!(
        parses, 1,
        "Owned parent requires a full capture outside its old caller scope"
    );
    assert!(matches!(&actual.profile, AuthorityProfile::Shared(_)));
    assert!(actual.checkpoint_import_scope().is_none());
    assert_eq!(actual.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&actual._lock).unwrap(), lock_identity);
    actual.validate_profile().unwrap();
    drop(actual);
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
