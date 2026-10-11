//! Real startup capabilities and bounded immutable epoch records. No native completion is forged.
use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers, service_bootstrap::ManagedServiceBootstrap,
};
use std::time::Duration;

fn fixture() -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "epoch-authority",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    (temporary, prepared)
}
#[test]
fn epochs_are_actual_finite_new_starts_with_one_exact_unsigned_replacement_claim() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let deadline = Instant::now() + Duration::from_secs(300);
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    let first = owner
        .authorize_generated_startup(deadline, Arc::clone(&cancelled))
        .unwrap()
        .unwrap();
    assert_eq!(first.lease.epoch.ordinal, 1);
    let original = first
        .lease
        .directory
        .read("original.nrt", super::super::MAX_ORIGINAL_BYTES)
        .unwrap();
    let first_epoch = first
        .lease
        .directory
        .open_child("epochs")
        .unwrap()
        .read("0001.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let child = first.child(Purpose::ReservePolicy).unwrap();
    child.claim_replacement([1; 32], deadline).unwrap();
    child.claim_replacement([1; 32], deadline).unwrap();
    assert!(matches!(
        child.claim_replacement([2; 32], deadline),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::ReplacementLimit
        ))
    ));
    assert!(
        first
            .child(Purpose::Reputation)
            .unwrap()
            .claim_replacement([1; 32], deadline)
            .is_err()
    );
    assert!(
        first
            .child(Purpose::Gateway(ProviderId::new([0xFA; 32])))
            .is_err()
    );
    let provider = first.original.policies.providers[0].provider_id;
    assert!(
        first
            .child(Purpose::CustodyRenewal {
                provider,
                sequence: 2
            })
            .is_err()
    );
    let funding = first.funding(provider).unwrap();
    assert!(funding.child(Purpose::Gateway(provider)).is_err());
    assert!(
        funding
            .child(Purpose::FundingCredit(
                first.original.policies.providers[1].provider_id
            ))
            .is_err()
    );
    funding
        .child(Purpose::FundingCredit(provider))
        .unwrap()
        .check(Purpose::FundingCredit(provider), deadline)
        .unwrap();
    let second = owner
        .authorize_generated_startup(deadline, Arc::clone(&cancelled))
        .unwrap()
        .unwrap();
    assert_eq!(second.lease.epoch.ordinal, 2);
    assert_eq!(
        second.lease.epoch.previous,
        Some(digest(&first.lease.epoch).unwrap())
    );
    assert!(first.check(deadline).is_err());
    second.check(deadline).unwrap();
    assert_eq!(
        second
            .lease
            .directory
            .read("original.nrt", super::super::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
    assert_eq!(
        second
            .lease
            .directory
            .open_child("epochs")
            .unwrap()
            .read("0001.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        first_epoch
    );
    let inventory = second
        .lease
        .directory
        .open_child("epochs")
        .unwrap()
        .entries(128)
        .unwrap();
    cancelled.store(true, Ordering::Release);
    assert!(matches!(
        second.check(deadline),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::Cancelled
        ))
    ));
    assert!(
        owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .is_err()
    );
    assert_eq!(
        second
            .lease
            .directory
            .open_child("epochs")
            .unwrap()
            .entries(128)
            .unwrap(),
        inventory
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn epoch_gap_trailing_foreign_and_overbound_material_refuse_before_new_authorization() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let deadline = Instant::now() + Duration::from_secs(300);
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let first = owner
        .authorize_generated_startup(deadline, Arc::clone(&cancelled))
        .unwrap()
        .unwrap();
    let root = first.lease.directory.open_child("epochs").unwrap();
    let bytes = root.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    for changed in [
        bytes
            .as_slice()
            .iter()
            .copied()
            .chain([0])
            .collect::<Vec<_>>(),
        vec![0xAB; attempts::MAX_RECORD_BYTES + 1],
    ] {
        root.write_atomic("0001.nrt", &changed, iroha_fs::PublishMode::Replace)
            .unwrap();
        assert!(
            owner
                .authorize_generated_startup(deadline, Arc::clone(&cancelled))
                .is_err()
        );
        assert!(!root.path().join("0002.nrt").exists());
        root.write_atomic("0001.nrt", &bytes, iroha_fs::PublishMode::Replace)
            .unwrap();
    }
    let mut foreign = first.lease.epoch.clone();
    foreign.parent_intent[0] ^= 1;
    root.write_atomic(
        "0001.nrt",
        &encode(&foreign, attempts::MAX_RECORD_BYTES).unwrap(),
        iroha_fs::PublishMode::Replace,
    )
    .unwrap();
    assert!(
        owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .is_err()
    );
    root.write_atomic("0001.nrt", &bytes, iroha_fs::PublishMode::Replace)
        .unwrap();
    std::fs::rename(root.path().join("0001.nrt"), root.path().join("0002.nrt")).unwrap();
    assert!(
        owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .is_err()
    );
    assert!(!root.path().join("0001.nrt").exists());
    std::fs::rename(root.path().join("0002.nrt"), root.path().join("0001.nrt")).unwrap();
    root.write_atomic("unknown.nrt", b"unknown", iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .is_err()
    );
    assert!(!root.path().join("0002.nrt").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn actual_epoch_history_has_a_finite_limit_and_never_rewrites_older_epochs() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let mut owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let deadline = Instant::now() + Duration::from_secs(600);
    let cancelled = Arc::new(AtomicBool::new(false));
    let first = owner
        .authorize_generated_startup(deadline, Arc::clone(&cancelled))
        .unwrap()
        .unwrap();
    let root = first.lease.directory.open_child("epochs").unwrap();
    let first_bytes = root.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap();
    for ordinal in 2..=MAX_EPOCHS {
        // Each epoch models a distinct worker startup, with its own finite I/O budget.
        // Retained epoch terms remain immutable; no deadline is renewed within a startup.
        let deadline = Instant::now() + Duration::from_secs(600);
        assert_eq!(
            usize::from(
                owner
                    .authorize_generated_startup(deadline, Arc::clone(&cancelled))
                    .unwrap()
                    .unwrap()
                    .lease
                    .epoch
                    .ordinal
            ),
            ordinal
        );
    }
    // The next independently budgeted startup must fail on the durable history cap.
    let deadline = Instant::now() + Duration::from_secs(600);
    assert!(matches!(
        owner.authorize_generated_startup(deadline, cancelled),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::EpochLimit
        ))
    ));
    assert_eq!(root.entries(128).unwrap().len(), MAX_EPOCHS);
    assert_eq!(
        root.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap(),
        first_bytes
    );
}

#[test]
fn bootstrap_original_policy_and_expiry_do_not_reparse_the_live_authority() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let deadline = Instant::now() + Duration::from_secs(300);
    let cancelled = Arc::new(AtomicBool::new(false));
    let (mut owner, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            ManagedServiceBootstrap::open(&prepared).unwrap()
        });
    assert_eq!(parses, 1);
    let mut peers = UnavailablePeers::start(&prepared);
    // The distinct child open-existing owner still performs its own canonical capture.
    // Only repeated reads through this live parent reuse its original parsed profile.
    let (first, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .unwrap()
            .unwrap()
    });
    assert_eq!(parses, 1);
    let (second, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .unwrap()
            .unwrap()
    });
    assert_eq!(parses, 1);
    let (_, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        first.original.validate(&owner.authority).unwrap();
        first.original.policies.validate(&owner.authority).unwrap();
        assert!(profile_expiry(&owner.authority, &first.original).unwrap() > now_ms().unwrap());
        let exact = encode(&first.original, super::super::MAX_ORIGINAL_BYTES).unwrap();
        assert_eq!(second.lease.epoch.ordinal, first.lease.epoch.ordinal + 1);
        assert_eq!(
            encode(&second.original, super::super::MAX_ORIGINAL_BYTES).unwrap(),
            exact
        );
        assert!(first.check(deadline).is_err());
        second.check(deadline).unwrap();

        // All three consumers reject byte drift and cannot mint another epoch from retained plans.
        let generation =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(b"\n# same parsed policy, different original image\n");
        let epochs = second.lease.directory.open_child("epochs").unwrap();
        let inventory = epochs.entries(128).unwrap();
        generation
            .write_atomic("peer3.toml", &changed, iroha_fs::PublishMode::Replace)
            .unwrap();
        assert!(second.original.validate(&owner.authority).is_err());
        assert!(second.original.policies.validate(&owner.authority).is_err());
        assert!(profile_expiry(&owner.authority, &second.original).is_err());
        assert!(
            owner
                .authorize_generated_startup(deadline, Arc::clone(&cancelled))
                .is_err()
        );
        assert_eq!(epochs.entries(128).unwrap(), inventory);
        generation
            .write_atomic("peer3.toml", &original, iroha_fs::PublishMode::Replace)
            .unwrap();
        second.original.validate(&owner.authority).unwrap();
        second.original.policies.validate(&owner.authority).unwrap();
        assert!(profile_expiry(&owner.authority, &second.original).unwrap() > now_ms().unwrap());
        assert_eq!(
            encode(&second.original, super::super::MAX_ORIGINAL_BYTES).unwrap(),
            exact
        );
    });
    assert_eq!(parses, 0);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
