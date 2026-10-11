//! Actual bootstrap child constructors retain native custody and the live creation boundary.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers,
    service_authority::{ProviderPurpose, profile_validation_test_support},
};
use iroha_fs::FileIdentity;
use norito::core::DecodeBudgetContext;
use std::{
    cell::Cell,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct Fixture {
    temporary: tempfile::TempDir,
    authority: ServiceAuthority,
    original: Original,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "bootstrap-remaining-creators",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let authority =
            ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
        let original = Original::select(
            &authority,
            generated_fees(Instant::now() + Duration::from_secs(60)).unwrap(),
        )
        .unwrap();
        authority
            .directory
            .ensure_child("initial")
            .unwrap()
            .write_atomic(
                "original.nrt",
                &encode(&original, MAX_ORIGINAL_BYTES).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        Self {
            temporary,
            authority,
            original,
        }
    }
    fn run<'a>(
        &'a self,
        mode: Mode,
        authorization: Option<&'a GeneratedBootstrapAuthorization>,
        deadline: Instant,
    ) -> Run<'a> {
        Run {
            authority: &self.authority,
            original: &self.original,
            deadline,
            mode,
            authorization,
            checkpoint_import_scope: if mode == Mode::Advance {
                None
            } else {
                CheckpointImportScope::for_original(&self.authority)
            },
        }
    }
    fn original_bytes(&self) -> Vec<u8> {
        self.authority
            .directory
            .open_child("initial")
            .unwrap()
            .read("original.nrt", MAX_ORIGINAL_BYTES)
            .unwrap()
            .to_vec()
    }
}
fn parsed<T>(action: impl FnOnce() -> T) -> (T, usize) {
    crate::localnet::service_authorities::count_profile_validations(action)
}
macro_rules! cases {
    ($case:ident, $parent:expr, $provider:expr) => {
        $case!(
            ManagedReserveAccountRegistration,
            ProviderPurpose::ReserveAccountRegistration,
            $parent,
            $provider,
            2
        );
        $case!(
            ProviderFundingBootstrap,
            ProviderPurpose::ProviderFundingBootstrap,
            $parent,
            $provider,
            3
        );
        $case!(
            ManagedInitialProviderIngestAuthority,
            ProviderPurpose::InitialProviderIngestAuthority,
            $parent,
            $provider,
            2
        );
        $case!(
            ManagedInitialGatewaySetup,
            ProviderPurpose::InitialGatewaySetup,
            $parent,
            $provider,
            2
        );
    };
}
fn parity<T>(
    seed: impl Fn() -> Result<ServiceAuthority>,
    ordinary: impl Fn() -> Result<T>,
    borrowed: impl Fn() -> Result<T>,
    existing: impl Fn() -> Result<Option<T>>,
    expected_checks: usize,
) {
    let (absent, parses) = parsed(&existing);
    assert!(absent.unwrap().is_none());
    assert_eq!(parses, 0);
    let ((first, parses), checks) = profile_validation_test_support::count(|| parsed(&borrowed));
    let first = first.unwrap();
    assert_eq!((parses, checks), (0, expected_checks));
    assert!(
        seed().is_err(),
        "actual typed owner holds the exact ordinary purpose lock"
    );
    drop(first);
    let expected = seed().unwrap();
    let directory = expected.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let names = directory.entries(2).unwrap();
    let bytes = directory.read("operation.lock", 4096).unwrap();
    assert!(
        borrowed().is_err(),
        "ordinary expected-purpose owner fences this typed creator"
    );
    drop(expected);
    let (ordinary, parses) = parsed(&ordinary);
    let ordinary = ordinary.unwrap();
    assert_eq!(parses, 1);
    assert!(existing().is_err());
    drop(ordinary);
    let (actual, parses) = parsed(&borrowed);
    let actual = actual.unwrap();
    assert_eq!(parses, 0);
    assert!(seed().is_err());
    assert_eq!(directory.identity().unwrap(), identity);
    assert_eq!(
        FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
        lock_identity
    );
    assert_eq!(directory.entries(2).unwrap(), names);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), bytes);
    drop(actual);
    let (retry, parses) = parsed(&existing);
    drop(retry.unwrap().unwrap());
    assert_eq!(parses, 0);
    directory.revalidate().unwrap();
}
macro_rules! parity_case {
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr, $checks:expr) => {
        parity(
            || ServiceAuthority::open_provider(&$parent.prepared, $provider, $purpose),
            || <$owner>::open(&$parent.prepared, $provider),
            || <$owner>::open_from_original($parent, $provider),
            || <$owner>::open_existing_from_original($parent, $provider, None),
            $checks,
        );
    };
}
fn empty_readers(fixture: &Fixture) {
    let authority = &fixture.authority;
    let original = &fixture.original;
    let deadline = Instant::now() + Duration::from_secs(60);
    for (slot, selected) in original.policies.providers.iter().enumerate() {
        let provider = selected.provider_id;
        let mut account =
            ManagedReserveAccountRegistration::open_from_original(authority, provider).unwrap();
        assert!(
            account
                .recover_local_selected_if_present(
                    &original.policies.network.reserve,
                    &original.underwriting[slot],
                    &original.fees,
                    deadline
                )
                .unwrap()
                .is_none()
        );
        drop(account);
        let mut funding =
            ProviderFundingBootstrap::open_from_original(authority, provider).unwrap();
        assert!(
            funding
                .recover_local_selected_if_present(
                    &original.policies.network.reserve,
                    &original.fees,
                    deadline
                )
                .unwrap()
                .is_none()
        );
        drop(funding);
        let mut ingest =
            ManagedInitialProviderIngestAuthority::open_from_original(authority, provider).unwrap();
        assert!(
            ingest
                .recover_local_selected_if_present(
                    &selected.provider_ingest,
                    &original.fees,
                    deadline
                )
                .unwrap()
                .is_none()
        );
        drop(ingest);
        let mut gateway =
            ManagedInitialGatewaySetup::open_from_original(authority, provider).unwrap();
        assert!(
            gateway
                .recover_local_selected_if_present(&selected.gateway, &original.fees, deadline)
                .unwrap()
                .is_none()
        );
    }
    let mut reputation = ManagedInitialReputationPolicy::open_from_original(authority).unwrap();
    assert!(
        reputation
            .recover_local_selected_if_present(
                &original.policies.gateway_labels(),
                &original.policies.network.reputation,
                &original.fees,
                deadline
            )
            .unwrap()
            .is_none()
    );
}
#[test]
fn bootstrap_creators_preserve_fixed_purposes_plans_and_immutable_inputs() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let config = fixture.authority.config.clone();
    let genesis = fixture.authority.genesis.clone();
    fixture.authority.config.chain = "mutable-bootstrap-creator".parse().unwrap();
    fixture.authority.config.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"mutable bootstrap creator",
        )),
    );
    fixture.authority.config.account_chain_discriminant ^= 1;
    fixture.authority.genesis.chain_id.push_str("-projection");
    fixture.authority.peers.reverse();
    for selected in &fixture.original.policies.providers {
        cases!(parity_case, &fixture.authority, selected.provider_id);
    }
    let authority = &fixture.authority;
    parity(
        || {
            ServiceAuthority::open_network(
                &authority.prepared,
                NetworkPurpose::InitialReputationPolicy,
            )
        },
        || ManagedInitialReputationPolicy::open(&authority.prepared),
        || ManagedInitialReputationPolicy::open_from_original(authority),
        || ManagedInitialReputationPolicy::open_existing_from_original(authority, None),
        2,
    );
    // These are genuine selected-policy readers, not comparisons of copied constructor fields.
    empty_readers(&fixture);
    fixture.authority.config = config;
    fixture.authority.genesis = genesis;
    fixture.authority.peers.reverse();
    empty_readers(&fixture);
    fixture.authority.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

fn native_boundary<T>(
    fixture: &Fixture,
    seed: impl Fn() -> Result<ServiceAuthority>,
    borrowed: impl Fn() -> Result<T>,
) {
    let expected = seed().unwrap();
    let directory = expected.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let bytes = directory.read("operation.lock", 4096).unwrap();
    assert!(borrowed().is_err());
    #[cfg(unix)]
    {
        let name = directory.path().file_name().unwrap();
        let saved = fixture.temporary.path().join(name);
        std::fs::rename(directory.path(), &saved).unwrap();
        let selected = PrivateDirectory::open_exact(directory.path().parent().unwrap()).unwrap();
        selected
            .write_atomic(name, b"wrong native kind", PublishMode::CreateNew)
            .unwrap();
        assert!(borrowed().is_err());
        assert!(expected.validate_profile().is_err());
        selected.remove_private(name).unwrap();
        std::fs::rename(&saved, directory.path()).unwrap();
        expected.validate_profile().unwrap();
    }
    #[cfg(windows)]
    assert!(
        std::fs::rename(
            directory.path(),
            fixture
                .temporary
                .path()
                .join(directory.path().file_name().unwrap())
        )
        .is_err()
    );
    drop(expected);
    let generation = PrivateDirectory::open_exact(
        fixture
            .authority
            .prepared
            .context
            .client_config
            .parent()
            .unwrap(),
    )
    .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.push(0);
    let reached = Rc::new(Cell::new(false));
    let mark = Rc::clone(&reached);
    let generation_for_hook = generation.retain().unwrap();
    let directory_for_hook = directory.retain().unwrap();
    let hook = ServiceAuthority::test_on_creating_child_exit(move || {
        mark.set(true);
        match directory_for_hook.open_existing_lock("operation.lock") {
            Ok(lock) => assert!(lock.try_lock().is_err()),
            Err(error) => {
                assert!(cfg!(windows));
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            }
        }
        generation_for_hook
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
    });
    assert!(borrowed().is_err());
    assert!(reached.get());
    drop(hook);
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let retry = seed().unwrap();
    assert_eq!(retry.directory.identity().unwrap(), identity);
    assert_eq!(FileIdentity::of(&retry._lock).unwrap(), lock_identity);
    retry.validate_profile().unwrap();
    drop(retry);
    drop(borrowed().unwrap());
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), bytes);
}
#[test]
fn bootstrap_creators_refuse_fresh_source_and_native_changes_with_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let authority = &fixture.authority;
    let provider = fixture.original.policies.providers[0].provider_id;
    let generation =
        PrivateDirectory::open_exact(authority.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.push(0);
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    macro_rules! refuse {
        ($owner:ty, $purpose:expr, $parent:expr, $provider:expr, $checks:expr) => {
            let (refused, parses) = parsed(|| <$owner>::open_from_original($parent, $provider));
            assert!(refused.is_err());
            assert_eq!(parses, 0);
        };
    }
    cases!(refuse, authority, provider);
    assert!(ManagedInitialReputationPolicy::open_from_original(authority).is_err());
    let operations = authority
        .directory
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    assert!(!operations.join("providers").exists());
    assert!(
        !authority
            .directory
            .path()
            .parent()
            .unwrap()
            .join("initial-reputation-policy")
            .exists()
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    macro_rules! boundary {
        ($owner:ty, $purpose:expr, $parent:expr, $provider:expr, $checks:expr) => {
            native_boundary(
                &fixture,
                || ServiceAuthority::open_provider(&$parent.prepared, $provider, $purpose),
                || <$owner>::open_from_original($parent, $provider),
            );
        };
    }
    cases!(boundary, authority, provider);
    native_boundary(
        &fixture,
        || {
            ServiceAuthority::open_network(
                &authority.prepared,
                NetworkPurpose::InitialReputationPolicy,
            )
        },
        || ManagedInitialReputationPolicy::open_from_original(authority),
    );
    assert_eq!(
        generation.read("peer3.toml", 1024 * 1024).unwrap(),
        original
    );
    authority.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}
fn active_parity<T>(ordinary: impl Fn() -> Result<T>, borrowed: impl Fn() -> Result<T>) {
    let budget = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) = parsed(|| budget.with(&ordinary));
    drop(expected.unwrap());
    assert_eq!(parses, 1);
    let charge = usize::try_from(budget.consumed_allocated_bytes()).unwrap();
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
        let actual_budget = DecodeBudgetContext::new(limits(allocated));
        let (actual, parses) = parsed(|| actual_budget.with(&borrowed));
        assert_eq!(parses, 1);
        assert_eq!(
            actual.err().unwrap().to_string(),
            expected.err().unwrap().to_string()
        );
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
    }
    let (retry, parses) = parsed(&borrowed);
    drop(retry.unwrap());
    assert_eq!(parses, 0);
}
macro_rules! active_case {
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr, $checks:expr) => {
        active_parity(
            || <$owner>::open(&$parent.prepared, $provider),
            || <$owner>::open_from_original($parent, $provider),
        );
        active_parity(
            || <$owner>::open_existing(&$parent.prepared, $provider).map(|owner| owner.unwrap()),
            || {
                <$owner>::open_existing_from_original($parent, $provider, None)
                    .map(|owner| owner.unwrap())
            },
        );
    };
}
macro_rules! owned_case {
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr, $checks:expr) => {
        let (actual, parses) = parsed(|| <$owner>::open_from_original($parent, $provider));
        drop(actual.unwrap());
        assert_eq!(parses, 1);
        let (actual, parses) =
            parsed(|| <$owner>::open_existing_from_original($parent, $provider, None));
        drop(actual.unwrap().unwrap());
        assert_eq!(parses, 1);
    };
}
#[test]
fn bootstrap_creators_preserve_full_active_decode_and_owned_parent_fallback() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let authority = &fixture.authority;
    let mut peers = UnavailablePeers::start(&authority.prepared);
    let provider = fixture.original.policies.providers[0].provider_id;
    cases!(active_case, authority, provider);
    active_parity(
        || ManagedInitialReputationPolicy::open(&authority.prepared),
        || ManagedInitialReputationPolicy::open_from_original(authority),
    );
    active_parity(
        || {
            ManagedInitialReputationPolicy::open_existing(&authority.prepared)
                .map(|owner| owner.unwrap())
        },
        || {
            ManagedInitialReputationPolicy::open_existing_from_original(authority, None)
                .map(|owner| owner.unwrap())
        },
    );
    let prepared = authority.prepared.clone();
    drop(fixture.authority);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let authority = caller
        .with(|| {
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
        })
        .unwrap()
        .unwrap();
    assert!(authority.original_intent_if_shared().unwrap().is_none());
    cases!(owned_case, &authority, provider);
    let (actual, parses) =
        parsed(|| ManagedInitialReputationPolicy::open_from_original(&authority));
    drop(actual.unwrap());
    assert_eq!(parses, 1);
    let (actual, parses) =
        parsed(|| ManagedInitialReputationPolicy::open_existing_from_original(&authority, None));
    drop(actual.unwrap().unwrap());
    assert_eq!(parses, 1);
    authority.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

// Exercise the shipping macro itself, returning only its genuine admitted native owner.
// This helper does not create a bootstrap history, paid carrier or service-completion report.
macro_rules! admit {
    ($run:expr, $owner:ty, $step:expr $(, $provider:expr)?) => {{
        let owner = open_child!($run, $owner, $step $(, $provider)?);
        Ok(Phase::Complete(owner))
    }};
}
fn check_admission<T>(
    fixture: &Fixture,
    admit: impl Fn(&Run<'_>) -> Result<Phase<T>>,
    expected_step: ServiceBootstrapStep,
    path: &std::path::Path,
) {
    let deadline = Instant::now() + Duration::from_secs(60);
    assert!(!path.exists());
    for mode in [Mode::Local, Mode::Recover] {
        match admit(&fixture.run(mode, None, deadline)).unwrap() {
            Phase::Incomplete(Incomplete::Pending { step, status }) => {
                assert_eq!(step, expected_step);
                assert_eq!(status, OperationStatus::Absent);
            }
            _ => panic!("absent constructor must report its exact purpose"),
        }
        assert!(!path.exists());
    }
    assert!(
        matches!(admit(&fixture.run(Mode::Advance, None, deadline)).err().unwrap(),
        crate::managed::Error::Invalid(message) if message == "bootstrap advance requires its live worker authorization")
    );
    assert!(
        !path.exists(),
        "missing live authorization cannot create custody"
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let authorization = GeneratedBootstrapAuthorization::issue(
        &fixture.authority,
        fixture.original.clone(),
        deadline,
        Arc::clone(&cancelled),
    )
    .unwrap();
    let epochs = fixture
        .authority
        .directory
        .open_child("initial")
        .unwrap()
        .open_child("epochs")
        .unwrap();
    let names = epochs.entries(64).unwrap();
    let records: Vec<_> = names
        .iter()
        .map(|name| (name.clone(), epochs.read(name, 64 * 1024).unwrap()))
        .collect();
    assert!(matches!(
        admit(&fixture.run(
            Mode::Advance,
            Some(&authorization),
            Instant::now() - Duration::from_secs(1)
        ))
        .err()
        .unwrap(),
        crate::managed::Error::Bootstrap(
            crate::managed::ManagedBootstrapFailure::AuthorizationExpired
        )
    ));
    assert!(
        !path.exists(),
        "expired original authorization cannot create custody"
    );
    cancelled.store(true, Ordering::Release);
    assert!(matches!(
        admit(&fixture.run(Mode::Advance, Some(&authorization), deadline))
            .err()
            .unwrap(),
        crate::managed::Error::Bootstrap(crate::managed::ManagedBootstrapFailure::Cancelled)
    ));
    assert!(
        !path.exists(),
        "cancelled original authorization cannot create custody"
    );
    assert_eq!(epochs.entries(64).unwrap(), names);
    for (name, bytes) in records {
        assert_eq!(epochs.read(name, 64 * 1024).unwrap(), bytes);
    }
    let fresh = GeneratedBootstrapAuthorization::issue(
        &fixture.authority,
        fixture.original.clone(),
        deadline,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    match admit(&fixture.run(Mode::Advance, Some(&fresh), deadline)).unwrap() {
        Phase::Complete(owner) => {
            assert!(path.is_dir());
            drop(owner);
        }
        _ => panic!("real live authorization must reach the actual creator"),
    }
}
#[test]
fn bootstrap_open_child_requires_live_authorization_before_creation() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let provider = fixture.original.policies.providers[0].provider_id;
    let original = fixture.original_bytes();
    let operations = fixture
        .authority
        .directory
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let selected = operations.join("providers/0");
    check_admission(
        &fixture,
        |run| {
            admit!(
                run,
                ManagedReserveAccountRegistration,
                ServiceBootstrapStep::ReserveAccount {
                    provider_id: provider
                },
                provider
            )
        },
        ServiceBootstrapStep::ReserveAccount {
            provider_id: provider,
        },
        &selected.join("reserve-account-registration"),
    );
    check_admission(
        &fixture,
        |run| {
            admit!(
                run,
                ProviderFundingBootstrap,
                ServiceBootstrapStep::ProviderFunding {
                    provider_id: provider
                },
                provider
            )
        },
        ServiceBootstrapStep::ProviderFunding {
            provider_id: provider,
        },
        &selected.join("provider-funding-bootstrap"),
    );
    check_admission(
        &fixture,
        |run| {
            admit!(
                run,
                ManagedInitialProviderIngestAuthority,
                ServiceBootstrapStep::ProviderIngest {
                    provider_id: provider
                },
                provider
            )
        },
        ServiceBootstrapStep::ProviderIngest {
            provider_id: provider,
        },
        &selected.join("initial-provider-ingest-authority"),
    );
    check_admission(
        &fixture,
        |run| {
            admit!(
                run,
                ManagedInitialGatewaySetup,
                ServiceBootstrapStep::Gateway {
                    provider_id: provider
                },
                provider
            )
        },
        ServiceBootstrapStep::Gateway {
            provider_id: provider,
        },
        &selected.join("initial-gateway-setup"),
    );
    check_admission(
        &fixture,
        |run| {
            admit!(
                run,
                ManagedInitialReputationPolicy,
                ServiceBootstrapStep::Reputation
            )
        },
        ServiceBootstrapStep::Reputation,
        &fixture
            .authority
            .directory
            .path()
            .parent()
            .unwrap()
            .join("initial-reputation-policy"),
    );
    assert_eq!(fixture.original_bytes(), original);
    fixture.authority.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
