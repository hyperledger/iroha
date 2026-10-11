//! Funding creators borrow original intent while retaining independent native admission.

use super::*;
use crate::managed::native_operation::test_support::UnavailablePeers;
use iroha_data_model::sorafs::capacity::ProviderId;
use iroha_fs::{FileIdentity, PrivateDirectory, PublishMode};
use norito::core::DecodeBudgetContext;
use std::{cell::Cell, rc::Rc};

fn fixture() -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "funding-original-creators",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    (temporary, prepared)
}
fn parsed<T>(action: impl FnOnce() -> T) -> (T, usize) {
    crate::localnet::service_authorities::count_profile_validations(action)
}
fn parent(prepared: &PreparedLocalnet, provider: ProviderId) -> ServiceAuthority {
    ProviderFundingBootstrap::open(prepared, provider)
        .unwrap()
        .authority
}
macro_rules! cases {
    ($case:ident, $parent:expr, $provider:expr) => {
        $case!(
            ManagedReserveTopUpRequest,
            ProviderPurpose::ReserveTopUpRequest,
            "reserve-top-up-request",
            $parent,
            $provider
        );
        $case!(
            ManagedReserveTopUpApproval,
            ProviderPurpose::ReserveTopUpApproval,
            "reserve-top-up-approval",
            $parent,
            $provider
        );
        $case!(
            ManagedInitialProviderCredit,
            ProviderPurpose::InitialProviderCredit,
            "initial-provider-credit",
            $parent,
            $provider
        );
        $case!(
            ManagedProviderCapacity,
            ProviderPurpose::ProviderCapacityDeclaration,
            "provider-capacity-declaration",
            $parent,
            $provider
        );
    };
}
#[expect(
    clippy::too_many_arguments,
    reason = "Compare the four actual typed entrypoints against one exact native purpose"
)]
fn purpose_parity<T>(
    parent: &ServiceAuthority,
    provider: ProviderId,
    purpose: impl Fn() -> ProviderPurpose,
    name: &str,
    ordinary: impl Fn() -> Result<T>,
    borrowed: impl Fn() -> Result<T>,
    ordinary_existing: impl Fn() -> Result<Option<T>>,
    borrowed_existing: impl Fn() -> Result<Option<T>>,
) {
    let path = parent.directory.path().parent().unwrap().join(name);
    assert!(!path.exists());
    let (absent, ordinary_probe_parses) = parsed(&ordinary_existing);
    assert!(absent.unwrap().is_none());
    assert_eq!(ordinary_probe_parses, 1);
    let (absent, borrowed_probe_parses) = parsed(&borrowed_existing);
    assert!(absent.unwrap().is_none());
    assert_eq!(borrowed_probe_parses, 0);
    assert!(
        !path.exists(),
        "fresh existing-only probes cannot create a purpose"
    );

    let ((first, borrowed_creator_parses), checks) =
        crate::managed::service_authority::profile_validation_test_support::count(|| {
            parsed(&borrowed)
        });
    let first = first.unwrap();
    assert_eq!(borrowed_creator_parses, 0);
    assert_eq!(
        checks,
        if name == "provider-capacity-declaration" {
            3
        } else {
            2
        },
        "all-result parent entry/exit and Capacity plan postcondition remain real"
    );
    assert!(
        ordinary().is_err(),
        "the typed creator holds the expected native purpose"
    );
    drop(first);
    let expected = ServiceAuthority::open_provider(&parent.prepared, provider, purpose()).unwrap();
    assert_eq!(expected.provider_id().unwrap(), provider);
    assert_eq!(expected.directory.path(), path);
    let directory = expected.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let names = directory.entries(2).unwrap();
    let lock_bytes = directory.read("operation.lock", 4096).unwrap();
    let config = expected.config.clone();
    let genesis = expected.genesis.clone();
    let peer_ids: Vec<_> = expected.peers.iter().map(|(id, _)| id.clone()).collect();
    let plan = expected.provider_plan().unwrap();
    assert!(
        borrowed().is_err(),
        "the ordinary expected-purpose lock fences the typed creator"
    );
    drop(expected);
    let (baseline, ordinary_creator_parses) = parsed(&ordinary);
    let baseline = baseline.unwrap();
    assert_eq!(ordinary_creator_parses, 1);
    assert!(borrowed_existing().is_err());
    drop(baseline);
    assert_eq!(ordinary_probe_parses + ordinary_creator_parses, 2);
    assert_eq!(borrowed_probe_parses + borrowed_creator_parses, 0);

    let (actual, parses) = parsed(&borrowed);
    let actual = actual.unwrap();
    assert_eq!(parses, 0);
    assert!(
        ordinary_existing().is_err(),
        "the borrowed creator retains the same exclusive lock"
    );
    assert_eq!(directory.identity().unwrap(), identity);
    assert_eq!(
        FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
        lock_identity
    );
    assert_eq!(directory.entries(2).unwrap(), names);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    drop(actual);
    // Inspect the same closed native purpose through the common original-profile producer.
    let actual =
        ServiceAuthority::open_provider_existing_from_original(parent, provider, purpose(), None)
            .unwrap()
            .unwrap();
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
        peer_ids
    );
    let actual_plan = actual.provider_plan().unwrap();
    assert_eq!(actual_plan.network_id(), plan.network_id());
    assert_eq!(actual_plan.provider_id(), plan.provider_id());
    assert_eq!(actual_plan.slot(), plan.slot());
    assert_eq!(
        actual_plan.original_profile_commitment(),
        plan.original_profile_commitment()
    );
    assert_eq!(actual_plan.reserve_terms(), plan.reserve_terms());
    assert_eq!(actual_plan.pricing(), plan.pricing());
    assert_eq!(actual_plan.declaration(), plan.declaration());
    assert_eq!(actual_plan.admission_material(), plan.admission_material());
    assert_eq!(actual_plan.https_origin(), plan.https_origin());
    assert!(actual.checkpoint_import_scope().is_none());
    actual.validate_profile().unwrap();
    drop(actual);
    let (existing, parses) = parsed(&borrowed_existing);
    assert!(existing.unwrap().is_some());
    assert_eq!(parses, 0);
    assert_eq!(directory.entries(2).unwrap(), names);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    directory.revalidate().unwrap();
}
macro_rules! parity {
    ($owner:ty, $purpose:expr, $name:expr, $parent:expr, $provider:expr) => {
        purpose_parity(
            $parent,
            $provider,
            || $purpose,
            $name,
            || <$owner>::open(&$parent.prepared, $provider),
            || <$owner>::open_from_original($parent, $provider),
            || <$owner>::open_existing(&$parent.prepared, $provider),
            || <$owner>::open_existing_from_original($parent, $provider, None),
        );
    };
}
#[test]
fn funding_creators_preserve_all_provider_purpose_locks_and_original_inputs() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let providers = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers
        .each_ref()
        .map(|value| value.provider_id);
    for provider in providers {
        let mut parent = parent(&prepared, provider);
        let config = parent.config.clone();
        let genesis = parent.genesis.clone();
        parent.config.chain = "mutable-funding-projection".parse().unwrap();
        parent.config.network_id = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                b"mutable funding projection",
            )),
        );
        parent.config.account_chain_discriminant ^= 1;
        parent.genesis.chain_id.push_str("-projection");
        parent.peers.reverse();
        cases!(parity, &parent, provider);
        parent.config = config;
        parent.genesis = genesis;
        parent.peers.reverse();
        parent.validate_profile().unwrap();
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

fn native_boundary<T>(
    temporary: &tempfile::TempDir,
    parent: &ServiceAuthority,
    provider: ProviderId,
    purpose: impl Fn() -> ProviderPurpose,
    name: &str,
    borrowed: impl Fn() -> Result<T>,
) {
    let selected = PrivateDirectory::open_exact(parent.directory.path().parent().unwrap()).unwrap();
    let generation =
        PrivateDirectory::open_exact(parent.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.push(0);
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    let (refused, parses) = parsed(&borrowed);
    assert!(refused.is_err());
    assert_eq!(parses, 0);
    assert!(
        !selected.path().join(name).exists(),
        "changed original source refuses before creation"
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    selected
        .write_atomic(name, b"wrong native kind", PublishMode::CreateNew)
        .unwrap();
    assert!(borrowed().is_err());
    selected.remove_private(name).unwrap();
    let expected = ServiceAuthority::open_provider(&parent.prepared, provider, purpose()).unwrap();
    let directory = expected.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let lock_bytes = directory.read("operation.lock", 4096).unwrap();
    assert!(borrowed().is_err(), "ordinary child lock remains exclusive");
    #[cfg(unix)]
    {
        let saved = temporary.path().join(format!("saved-{name}"));
        std::fs::rename(directory.path(), &saved).unwrap();
        selected
            .write_atomic(name, b"replaced native kind", PublishMode::CreateNew)
            .unwrap();
        assert!(borrowed().is_err());
        assert!(expected.validate_profile().is_err());
        selected.remove_private(name).unwrap();
        std::fs::rename(&saved, directory.path()).unwrap();
        expected.validate_profile().unwrap();
        let lock_path = directory.path().join("operation.lock");
        let saved_lock = directory.path().join("saved-operation.lock");
        std::fs::rename(&lock_path, &saved_lock).unwrap();
        let replacement = directory.ensure_child("operation.lock").unwrap();
        assert!(borrowed().is_err());
        assert!(expected.validate_profile().is_err());
        drop(replacement);
        std::fs::remove_dir(&lock_path).unwrap();
        std::fs::rename(&saved_lock, &lock_path).unwrap();
        expected.validate_profile().unwrap();
    }
    #[cfg(windows)]
    {
        assert!(
            std::fs::rename(
                directory.path(),
                temporary.path().join(format!("saved-{name}"))
            )
            .is_err()
        );
        assert!(
            std::fs::rename(
                directory.path().join("operation.lock"),
                directory.path().join("saved-operation.lock")
            )
            .is_err()
        );
        assert!(borrowed().is_err());
        expected.validate_profile().unwrap();
    }
    drop(expected);
    let reached = Rc::new(Cell::new(false));
    let mark = Rc::clone(&reached);
    let generation_for_hook = generation.retain().unwrap();
    let directory_for_hook = directory.retain().unwrap();
    let hook_changed = zeroize::Zeroizing::new(changed.to_vec());
    let hook = ServiceAuthority::test_on_creating_child_exit(move || {
        mark.set(true);
        match directory_for_hook.open_existing_lock("operation.lock") {
            Ok(lock) => assert!(
                lock.try_lock().is_err(),
                "successful child Result still holds its real native lock"
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
    let (refused, parses) = parsed(&borrowed);
    assert!(reached.get());
    assert_eq!(parses, 0);
    assert_eq!(
        refused.err().unwrap().to_string(),
        parent.validate_profile().err().unwrap().to_string()
    );
    drop(hook);
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    // A successful original re-open proves that the refused held child Result released its lock.
    let retry = ServiceAuthority::open_provider(&parent.prepared, provider, purpose()).unwrap();
    assert_eq!(retry.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&retry._lock).unwrap(), lock_identity);
    retry.validate_profile().unwrap();
    drop(retry);
    let (retry, parses) = parsed(&borrowed);
    assert_eq!(parses, 0);
    drop(retry.unwrap());
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    assert_eq!(
        generation.read("peer3.toml", 1024 * 1024).unwrap(),
        original
    );
    directory.revalidate().unwrap();
}
#[test]
fn funding_creators_refuse_fresh_native_changes_and_release_children_on_parent_exit() {
    let _guard = crate::managed::native_test_guard();
    let (temporary, prepared) = fixture();
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[0]
        .provider_id;
    let parent = parent(&prepared, provider);
    let identity = parent.directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&parent._lock).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    macro_rules! boundary {
        ($owner:ty, $purpose:expr, $name:expr, $parent:expr, $provider:expr) => {
            native_boundary(
                &temporary,
                $parent,
                $provider,
                || $purpose,
                $name,
                || <$owner>::open_from_original($parent, $provider),
            );
        };
    }
    cases!(boundary, &parent, provider);
    #[cfg(unix)]
    {
        let lock = parent.directory.path().join("operation.lock");
        let saved = parent.directory.path().join("saved-parent.lock");
        std::fs::rename(&lock, &saved).unwrap();
        assert!(ManagedReserveTopUpRequest::open_from_original(&parent, provider).is_err());
        std::fs::rename(&saved, &lock).unwrap();
    }
    #[cfg(windows)]
    assert!(
        std::fs::rename(
            parent.directory.path().join("operation.lock"),
            parent.directory.path().join("saved-parent.lock")
        )
        .is_err()
    );
    assert_eq!(parent.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&parent._lock).unwrap(), lock_identity);
    assert_eq!(
        FileIdentity::of(&parent.directory.open_read("operation.lock").unwrap()).unwrap(),
        lock_identity
    );
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}
fn active_parity<T>(ordinary: impl Fn() -> Result<T>, borrowed: impl Fn() -> Result<T>) {
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) = parsed(|| baseline.with(&ordinary));
    drop(expected.unwrap());
    assert_eq!(parses, 1);
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (actual, parses) = parsed(|| exact.with(&borrowed));
    drop(actual.unwrap());
    assert_eq!(parses, 1);
    assert_eq!(exact.consumed_allocated_bytes(), charge as u64);
    for allocated in [0, charge - 1] {
        let expected_budget = DecodeBudgetContext::new(limits(allocated));
        let (expected, parses) = parsed(|| expected_budget.with(&ordinary));
        assert_eq!(parses, 1);
        let expected = expected.err().unwrap();
        let actual_budget = DecodeBudgetContext::new(limits(allocated));
        let (actual, parses) = parsed(|| actual_budget.with(&borrowed));
        assert_eq!(parses, 1);
        assert_eq!(actual.err().unwrap().to_string(), expected.to_string());
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
    }
    let (retry, parses) = parsed(&borrowed);
    drop(retry.unwrap());
    assert_eq!(parses, 0);
}
macro_rules! active {
    ($owner:ty, $purpose:expr, $name:expr, $parent:expr, $provider:expr) => {
        active_parity(
            || <$owner>::open(&$parent.prepared, $provider),
            || <$owner>::open_from_original($parent, $provider),
        );
        active_parity(
            || <$owner>::open_existing(&$parent.prepared, $provider),
            || <$owner>::open_existing_from_original($parent, $provider, None),
        );
    };
}
macro_rules! owned {
    ($owner:ty, $purpose:expr, $name:expr, $parent:expr, $provider:expr) => {
        let (owner, parses) = parsed(|| <$owner>::open_from_original($parent, $provider));
        drop(owner.unwrap());
        assert_eq!(
            parses, 1,
            "Owned parent retains full creating admission outside its old scope"
        );
        let (owner, parses) =
            parsed(|| <$owner>::open_existing_from_original($parent, $provider, None));
        assert!(owner.unwrap().is_some());
        assert_eq!(
            parses, 1,
            "Owned parent retains full existing admission outside its old scope"
        );
    };
}
#[test]
fn funding_creators_preserve_full_active_decode_and_owned_parent_fallback() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[0]
        .provider_id;
    let parent = parent(&prepared, provider);
    let mut peers = UnavailablePeers::start(&prepared);
    cases!(active, &parent, provider);
    drop(parent);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let parent = caller
        .with(|| {
            ServiceAuthority::open_provider_existing(
                &prepared,
                provider,
                ProviderPurpose::ProviderFundingBootstrap,
            )
        })
        .unwrap()
        .unwrap();
    assert!(!norito::core::decode_limits_active());
    assert!(parent.original_intent_if_shared().unwrap().is_none());
    cases!(owned, &parent, provider);
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
