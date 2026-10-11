//! Real typed graph constructors retain exact child locks and fresh original-profile admission.

use super::*;
use crate::managed::{
    ManagedInitialProviderCredit, ManagedProviderCapacity, ManagedReserveTopUpApproval,
    ManagedReserveTopUpRequest, native_operation::test_support::UnavailablePeers,
    service_authority::ProviderPurpose,
};
use iroha_fs::FileIdentity;
use norito::core::DecodeBudgetContext;
use std::time::Duration;

struct Fixture {
    temporary: tempfile::TempDir,
    parent: ServiceAuthority,
    original: Original,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "graph-original-profile",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let parent =
            ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
        let original = Original::select(
            &parent,
            generated_fees(Instant::now() + Duration::from_secs(60)).unwrap(),
        )
        .unwrap();
        Self {
            temporary,
            parent,
            original,
        }
    }
}

// Every changed typed constructor is exercised, including all three distinct provider slots.
macro_rules! network_cases {
    ($case:ident, $parent:expr) => {
        $case!(
            ManagedInitialReservePolicy,
            NetworkPurpose::InitialReservePolicy,
            $parent
        );
        $case!(
            ManagedInitialReputationPolicy,
            NetworkPurpose::InitialReputationPolicy,
            $parent
        );
    };
}
macro_rules! provider_cases {
    ($case:ident, $parent:expr, $provider:expr) => {
        $case!(
            ManagedStreamTokenCustody,
            ProviderPurpose::Custody,
            $parent,
            $provider
        );
        $case!(
            ManagedReserveAccountRegistration,
            ProviderPurpose::ReserveAccountRegistration,
            $parent,
            $provider
        );
        $case!(
            ProviderFundingBootstrap,
            ProviderPurpose::ProviderFundingBootstrap,
            $parent,
            $provider
        );
        $case!(
            ManagedInitialProviderIngestAuthority,
            ProviderPurpose::InitialProviderIngestAuthority,
            $parent,
            $provider
        );
        $case!(
            ManagedInitialGatewaySetup,
            ProviderPurpose::InitialGatewaySetup,
            $parent,
            $provider
        );
        $case!(
            ManagedReserveTopUpRequest,
            ProviderPurpose::ReserveTopUpRequest,
            $parent,
            $provider
        );
        $case!(
            ManagedReserveTopUpApproval,
            ProviderPurpose::ReserveTopUpApproval,
            $parent,
            $provider
        );
        $case!(
            ManagedInitialProviderCredit,
            ProviderPurpose::InitialProviderCredit,
            $parent,
            $provider
        );
        $case!(
            ManagedProviderCapacity,
            ProviderPurpose::ProviderCapacityDeclaration,
            $parent,
            $provider
        );
    };
}

fn parsed<T>(action: impl FnOnce() -> T) -> (T, usize) {
    crate::localnet::service_authorities::count_profile_validations(action)
}

fn purpose_parity<T>(
    seed: impl Fn() -> Result<ServiceAuthority>,
    ordinary: impl Fn() -> Result<Option<T>>,
    borrowed: impl Fn() -> Result<Option<T>>,
) {
    let (absent, parses) = parsed(&ordinary);
    assert!(absent.unwrap().is_none());
    assert_eq!(parses, 1);
    let (absent, parses) = parsed(&borrowed);
    assert!(absent.unwrap().is_none());
    assert_eq!(parses, 0);

    let expected = seed().unwrap();
    let directory = expected.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&expected._lock).unwrap();
    let names = directory.entries(2).unwrap();
    let lock_bytes = directory.read("operation.lock", 4096).unwrap();
    let (refused, parses) = parsed(&borrowed);
    assert!(
        refused.is_err(),
        "the expected ordinary purpose lock is already held"
    );
    assert_eq!(parses, 0);
    drop(expected);

    let (expected, parses) = parsed(&ordinary);
    let expected = expected.unwrap().unwrap();
    assert_eq!(parses, 1);
    assert!(borrowed().is_err());
    drop(expected);
    let (actual, parses) = parsed(&borrowed);
    let actual = actual.unwrap().unwrap();
    assert_eq!(parses, 0);
    assert!(
        ordinary().is_err(),
        "borrowed owner holds that same expected purpose lock"
    );
    assert_eq!(directory.identity().unwrap(), identity);
    assert_eq!(
        FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
        lock_identity
    );
    assert_eq!(directory.entries(2).unwrap(), names);
    assert_eq!(directory.read("operation.lock", 4096).unwrap(), lock_bytes);
    drop(actual);
    assert!(ordinary().unwrap().is_some());
    directory.revalidate().unwrap();
}

macro_rules! parity {
    ($owner:ty, $purpose:expr, $parent:expr) => {
        purpose_parity(
            || ServiceAuthority::open_network(&$parent.prepared, $purpose),
            || <$owner>::open_existing(&$parent.prepared),
            || <$owner>::open_existing_from_original($parent, None),
        );
    };
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr) => {
        purpose_parity(
            || ServiceAuthority::open_provider(&$parent.prepared, $provider, $purpose),
            || <$owner>::open_existing(&$parent.prepared, $provider),
            || <$owner>::open_existing_from_original($parent, $provider, None),
        );
    };
}

// These real local readers validate the generated role/plan/policy before returning absence.
// Nested funding histories are covered by the original paid-funding and parent native controls.
fn require_empty_recoveries(fixture: &Fixture) {
    let parent = &fixture.parent;
    let original = &fixture.original;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut reserve = ManagedInitialReservePolicy::open_existing_from_original(parent, None)
        .unwrap()
        .unwrap();
    assert!(
        reserve
            .recover_local_selected_if_present(
                &original.policies.network.reserve,
                &original.fees,
                deadline
            )
            .unwrap()
            .is_none()
    );
    drop(reserve);
    for (slot, selected) in original.policies.providers.iter().enumerate() {
        let provider = selected.provider_id;
        let mut custody =
            ManagedStreamTokenCustody::open_existing_from_original(parent, provider, None)
                .unwrap()
                .unwrap();
        assert!(
            custody
                .recover_configure_local_selected_if_present(
                    &selected.custody,
                    &original.fees,
                    deadline
                )
                .unwrap()
                .is_none()
        );
        assert!(
            custody
                .recover_enroll_local_selected_if_present(
                    &selected.custody,
                    &original.fees,
                    deadline
                )
                .unwrap()
                .is_none()
        );
        drop(custody);
        let mut account =
            ManagedReserveAccountRegistration::open_existing_from_original(parent, provider, None)
                .unwrap()
                .unwrap();
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
            ProviderFundingBootstrap::open_existing_from_original(parent, provider, None)
                .unwrap()
                .unwrap();
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
        let mut ingest = ManagedInitialProviderIngestAuthority::open_existing_from_original(
            parent, provider, None,
        )
        .unwrap()
        .unwrap();
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
            ManagedInitialGatewaySetup::open_existing_from_original(parent, provider, None)
                .unwrap()
                .unwrap();
        assert!(
            gateway
                .recover_local_selected_if_present(&selected.gateway, &original.fees, deadline)
                .unwrap()
                .is_none()
        );
    }
    let mut reputation = ManagedInitialReputationPolicy::open_existing_from_original(parent, None)
        .unwrap()
        .unwrap();
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
fn graph_original_profile_constructors_preserve_all_purpose_locks_and_immutable_projections() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.parent.prepared);
    let config = fixture.parent.config.clone();
    let genesis = fixture.parent.genesis.clone();
    fixture.parent.config.chain = "mutable-graph-projection".parse().unwrap();
    fixture.parent.config.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"mutable graph projection",
        )),
    );
    fixture.parent.config.account_chain_discriminant ^= 1;
    fixture
        .parent
        .genesis
        .chain_id
        .push_str("-mutable-projection");
    fixture.parent.peers.reverse();
    let parent = &fixture.parent;
    network_cases!(parity, parent);
    for selected in &fixture.original.policies.providers {
        provider_cases!(parity, parent, selected.provider_id);
    }
    require_empty_recoveries(&fixture);
    fixture.parent.config = config;
    fixture.parent.genesis = genesis;
    fixture.parent.peers.reverse();
    require_empty_recoveries(&fixture);
    fixture.parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

macro_rules! seed {
    ($owner:ty, $purpose:expr, $parent:expr) => {
        drop(ServiceAuthority::open_network(&$parent.prepared, $purpose).unwrap());
    };
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr) => {
        drop(ServiceAuthority::open_provider(&$parent.prepared, $provider, $purpose).unwrap());
    };
}

fn seed_children(parent: &ServiceAuthority) {
    network_cases!(seed, parent);
    for selected in &parent.manifest.providers {
        provider_cases!(seed, parent, selected.provider_id);
    }
}

macro_rules! refused {
    ($owner:ty, $purpose:expr, $parent:expr) => {
        let (result, parses) = parsed(|| <$owner>::open_existing_from_original($parent, None));
        assert!(result.is_err());
        assert_eq!(parses, 0);
    };
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr) => {
        let (result, parses) =
            parsed(|| <$owner>::open_existing_from_original($parent, $provider, None));
        assert!(result.is_err());
        assert_eq!(parses, 0);
    };
}

fn require_all_refused(parent: &ServiceAuthority) {
    network_cases!(refused, parent);
    for selected in &parent.manifest.providers {
        provider_cases!(refused, parent, selected.provider_id);
    }
}

#[test]
fn graph_original_profile_constructors_refuse_fresh_profile_lock_and_native_parent_changes() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let parent = &fixture.parent;
    let mut peers = UnavailablePeers::start(&parent.prepared);
    seed_children(parent);
    let generation =
        PrivateDirectory::open_exact(parent.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let runtime = generation.open_child("runtime").unwrap();
    let authorities = runtime.open_child("stream-token-authorities").unwrap();
    let parent_identity = parent.directory.identity().unwrap();
    let parent_lock_identity = FileIdentity::of(&parent._lock).unwrap();
    for (directory, name, maximum) in [
        (&generation, "peer3.toml", 1024 * 1024),
        (
            &generation,
            "genesis.signed.nrt",
            iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
        ),
        (&runtime, "onboarding-signer.key", 4096),
        (&authorities, "authorities.json", 512 * 1024),
    ] {
        let original = directory.read(name, maximum).unwrap();
        let mut changed = original.to_vec();
        changed.push(0);
        directory
            .write_atomic(name, &changed, PublishMode::Replace)
            .unwrap();
        require_all_refused(parent);
        directory
            .write_atomic(name, &original, PublishMode::Replace)
            .unwrap();
        require_empty_recoveries(&fixture);
        assert_eq!(directory.read(name, maximum).unwrap(), original);
    }
    #[cfg(unix)]
    {
        let lock = parent.directory.path().join("operation.lock");
        let saved_lock = parent.directory.path().join("saved-original.lock");
        let bytes = parent.directory.read("operation.lock", 4096).unwrap();
        std::fs::rename(&lock, &saved_lock).unwrap();
        require_all_refused(parent);
        parent
            .directory
            .write_atomic("operation.lock", &bytes, PublishMode::CreateNew)
            .unwrap();
        require_all_refused(parent);
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(&saved_lock, &lock).unwrap();
        require_empty_recoveries(&fixture);
        let saved = fixture.temporary.path().join("saved-generation");
        std::fs::rename(generation.path(), &saved).unwrap();
        require_all_refused(parent);
        let replacement = PrivateDirectory::open_or_create(generation.path()).unwrap();
        require_all_refused(parent);
        drop(replacement);
        std::fs::remove_dir(generation.path()).unwrap();
        std::fs::rename(&saved, generation.path()).unwrap();
    }
    #[cfg(windows)]
    {
        let saved = fixture.temporary.path().join("saved-generation");
        assert!(std::fs::rename(generation.path(), &saved).is_err());
        assert!(
            std::fs::rename(
                parent.directory.path().join("operation.lock"),
                parent.directory.path().join("saved-original.lock")
            )
            .is_err()
        );
    }
    require_empty_recoveries(&fixture);
    assert_eq!(parent.directory.identity().unwrap(), parent_identity);
    assert_eq!(
        FileIdentity::of(&parent._lock).unwrap(),
        parent_lock_identity
    );
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

fn active_parity<T>(
    ordinary: impl Fn() -> Result<Option<T>>,
    borrowed: impl Fn() -> Result<Option<T>>,
) {
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) = parsed(|| baseline.with(&ordinary));
    assert!(expected.unwrap().is_some());
    assert_eq!(parses, 1);
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (actual, parses) = parsed(|| exact.with(&borrowed));
    assert!(actual.unwrap().is_some());
    assert_eq!(parses, 1);
    assert_eq!(exact.consumed_allocated_bytes(), charge as u64);
    for allocated in [0, charge - 1] {
        let ordinary_budget = DecodeBudgetContext::new(limits(allocated));
        let (expected, parses) = parsed(|| ordinary_budget.with(&ordinary));
        assert_eq!(parses, 1);
        let expected = expected.err().unwrap();
        let borrowed_budget = DecodeBudgetContext::new(limits(allocated));
        let (actual, parses) = parsed(|| borrowed_budget.with(&borrowed));
        assert_eq!(parses, 1);
        assert_eq!(actual.err().unwrap().to_string(), expected.to_string());
        assert_eq!(
            borrowed_budget.consumed_allocated_bytes(),
            ordinary_budget.consumed_allocated_bytes()
        );
    }
    let (retry, parses) = parsed(&borrowed);
    assert!(retry.unwrap().is_some());
    assert_eq!(parses, 0);
}

macro_rules! active {
    ($owner:ty, $purpose:expr, $parent:expr) => {
        active_parity(
            || <$owner>::open_existing(&$parent.prepared),
            || <$owner>::open_existing_from_original($parent, None),
        );
    };
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr) => {
        active_parity(
            || <$owner>::open_existing(&$parent.prepared, $provider),
            || <$owner>::open_existing_from_original($parent, $provider, None),
        );
    };
}

macro_rules! owned {
    ($owner:ty, $purpose:expr, $parent:expr) => {
        let (result, parses) = parsed(|| <$owner>::open_existing_from_original($parent, None));
        assert!(result.unwrap().is_some());
        assert_eq!(
            parses, 1,
            "an Owned parent outside its old caller scope still captures fully"
        );
    };
    ($owner:ty, $purpose:expr, $parent:expr, $provider:expr) => {
        let (result, parses) =
            parsed(|| <$owner>::open_existing_from_original($parent, $provider, None));
        assert!(result.unwrap().is_some());
        assert_eq!(
            parses, 1,
            "an Owned parent outside its old caller scope still captures fully"
        );
    };
}

#[test]
fn graph_original_profile_constructors_preserve_active_decode_and_owned_parent_fallback() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.parent.prepared);
    seed_children(&fixture.parent);
    let parent = &fixture.parent;
    let provider = parent.manifest.providers[0].provider_id;
    network_cases!(active, parent);
    provider_cases!(active, parent, provider);
    let prepared = parent.prepared.clone();
    drop(fixture.parent);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let parent = caller
        .with(|| {
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
        })
        .unwrap()
        .unwrap();
    assert!(!norito::core::decode_limits_active());
    network_cases!(owned, &parent);
    provider_cases!(owned, &parent, provider);
    parent.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
