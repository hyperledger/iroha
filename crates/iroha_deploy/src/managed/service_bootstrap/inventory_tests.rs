//! Lost parent custody refuses child presence without writing or interpreting native state.
use super::*;
use crate::managed::{
    native_operation::{attempts::metadata, test_support::UnavailablePeers},
    service_authority::ProviderPurpose,
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
    let child = metadata::ensure_operation(&later.directory, "declare").unwrap();
    let unselected = child
        .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
        .unwrap();
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
    // Removing later material restores the exact Unselected image, not a raw empty child.
    std::fs::remove_file(child.path().join("original.nrt")).unwrap();
    let image_path = child.path().join(metadata::FILE);
    let held_image = temporary.path().join("held-operation.nrt");
    let child_identity = child.identity().unwrap();
    let parent_names = owner.authority.directory.entries(4).unwrap();
    std::fs::rename(&image_path, &held_image).unwrap();
    let error = match owner.authorize_generated_startup(
        Instant::now() + Duration::from_secs(60),
        Arc::new(AtomicBool::new(false)),
    ) {
        Err(error) => error,
        Ok(_) => panic!("a retained empty child cannot reconstruct its missing operation image"),
    };
    assert!(
        matches!(&error, crate::managed::Error::Invalid(message)
            if message == "later bootstrap material exists behind an incomplete prerequisite"),
        "{error:?}"
    );
    assert_eq!(owner.authority.directory.entries(4).unwrap(), parent_names);
    require_empty(&owner.authority.directory.open_child("initial").unwrap()).unwrap();
    assert!(child.entries(1).unwrap().is_empty());
    assert!(!image_path.exists());
    assert_eq!(child.identity().unwrap(), child_identity);
    assert!(peers.requests.lock().unwrap().is_empty());
    std::fs::rename(&held_image, &image_path).unwrap();
    assert_eq!(
        child
            .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
            .unwrap(),
        unselected
    );
    // An explicitly initialized Unselected child is harmless and supplies no native authority.
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
    // The retained Unselected capacity purpose is reconstructed in each census (two opens).
    // The fresh first-reserve absence probe consumes the same parent custody without an open.
    // Every other exact absent census child uses the same authenticated parent.
    assert_eq!(authority_opens, 2);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
