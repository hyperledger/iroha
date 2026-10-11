//! Lost parent custody refuses child presence without writing or interpreting native state.
use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers, service_authority::ProviderPurpose,
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[test]
fn absent_parent_refuses_later_child_material_before_creating_initial_custody() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "lost-parent-census",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    // Generation is complete; the mock peers now own the exact reserved HTTP endpoints.
    drop(ports);
    let mut owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let provider = owner
        .authority
        .prepared
        .provider_service_plans()
        .unwrap()
        .unwrap()[2]
        .provider_id();
    let later = ServiceAuthority::open_provider(
        &prepared,
        provider,
        ProviderPurpose::ProviderCapacityDeclaration,
    )
    .unwrap();
    let child = later.directory.ensure_child("declare").unwrap();
    // This arbitrary marker tests presence-only refusal. It is never decoded as paid evidence.
    child
        .write_atomic("original.nrt", b"retained material", PublishMode::CreateNew)
        .unwrap();
    drop(later);
    let mut peers = UnavailablePeers::start(&prepared);
    let parent_names = owner.authority.directory.entries(4).unwrap();
    for initial_exists in [false, true] {
        if initial_exists {
            owner.authority.directory.ensure_child("initial").unwrap();
        }
        let names = owner.authority.directory.entries(4).unwrap();
        assert!(
            owner
                .authorize_generated_startup(
                    Instant::now() + Duration::from_secs(60),
                    Arc::new(AtomicBool::new(false))
                )
                .is_err()
        );
        assert_eq!(owner.authority.directory.entries(4).unwrap(), names);
        if initial_exists {
            require_empty(&owner.authority.directory.open_child("initial").unwrap()).unwrap();
        } else {
            assert_eq!(names, parent_names);
            assert!(!owner.authority.directory.path().join("initial").exists());
        }
        assert_eq!(
            child.read("original.nrt", 64).unwrap().as_slice(),
            b"retained material"
        );
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    // A clean preflight directory is harmless; it supplies no native authority.
    std::fs::remove_file(child.path().join("original.nrt")).unwrap();
    let (authorization, authority_opens) =
        crate::managed::service_authority::ServiceChildInventory::test_count_authority_opens(
            || {
                owner.authorize_generated_startup(
                    Instant::now() + Duration::from_secs(60),
                    Arc::new(AtomicBool::new(false)),
                )
            },
        );
    assert!(authorization.unwrap().is_some());
    // The retained empty capacity purpose is reconstructed in each complete census (two opens).
    // The fresh first-reserve absence probe consumes the same parent custody without an open.
    // Every other exact absent census child uses the same authenticated parent.
    assert_eq!(authority_opens, 2);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
