//! Real enrollment-slot census controls; name presence never substitutes body authentication.

use super::*;
use crate::managed::stream_token_custody::renewal_tests::Fixture;

fn empty() -> (tempfile::TempDir, ManagedStreamTokenCustody) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "enrollment-census",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let owner = ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    (temporary, owner)
}

fn inspect(owner: &ManagedStreamTokenCustody, purpose: CustodyPurpose) -> Result<()> {
    BodyHistory::open(owner, purpose).map(|_| ())
}

fn full(owner: &ManagedStreamTokenCustody) -> Result<()> {
    inspect(owner, CustodyPurpose::InitialEnroll)?;
    for sequence in 2..=64 {
        inspect(owner, CustodyPurpose::Renewal(sequence))?;
    }
    Ok(())
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        1024 * 1024,
        MAX_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        allocation,
        64,
    )
}

#[test]
fn present_slot_census_skips_only_joint_absence_and_keeps_original_slot_order() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, owner) = empty();
    let directory = &owner.authority.directory;
    let names = directory.entries(131).unwrap();
    let mut visited = Vec::new();
    validate_enrollment_slots(&owner, |owner, purpose| {
        visited.push(purpose);
        inspect(owner, purpose)
    })
    .unwrap();
    assert!(visited.is_empty());
    assert_eq!(directory.entries(131).unwrap(), names);
    let budget = norito::core::DecodeBudgetContext::new(limits(256 * 1024 * 1024));
    budget
        .with(|| {
            validate_enrollment_slots(&owner, |owner, purpose| {
                visited.push(purpose);
                inspect(owner, purpose)
            })
        })
        .unwrap();
    assert_eq!(
        visited,
        std::iter::once(CustodyPurpose::InitialEnroll)
            .chain((2..=64).map(CustodyPurpose::Renewal))
            .collect::<Vec<_>>()
    );
    assert_eq!(directory.entries(131).unwrap(), names);

    // A body alone reaches the original parser and refuses incomplete native contents.
    drop(directory.create_child("enroll").unwrap());
    visited.clear();
    assert!(
        validate_enrollment_slots(&owner, |owner, purpose| {
            visited.push(purpose);
            inspect(owner, purpose)
        })
        .is_err()
    );
    assert_eq!(visited, vec![CustodyPurpose::InitialEnroll]);
    std::fs::remove_dir(directory.path().join("enroll")).unwrap();

    // A reference alone, including a malformed leaf, is also present material.
    let last_reference = format!("{}-selection.nrt", renewal::directory_name(64).unwrap());
    directory
        .write_atomic(&last_reference, b"malformed", PublishMode::CreateNew)
        .unwrap();
    visited.clear();
    assert!(
        validate_enrollment_slots(&owner, |owner, purpose| {
            visited.push(purpose);
            inspect(owner, purpose)
        })
        .is_err()
    );
    assert_eq!(visited, vec![CustodyPurpose::Renewal(64)]);
    let earlier = renewal::directory_name(2).unwrap();
    drop(directory.create_child(&earlier).unwrap());
    visited.clear();
    assert!(
        validate_enrollment_slots(&owner, |owner, purpose| {
            visited.push(purpose);
            inspect(owner, purpose)
        })
        .is_err()
    );
    assert_eq!(visited, vec![CustodyPurpose::Renewal(2)]);
    std::fs::remove_dir(directory.path().join(earlier)).unwrap();
    std::fs::remove_file(directory.path().join(last_reference)).unwrap();
    assert_eq!(directory.entries(131).unwrap(), names);
    validate_enrollment_slots(&owner, inspect).unwrap();
}

#[test]
fn present_slot_census_keeps_signed_history_and_exact_active_decode_charges() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(120_000);
    let owner = &fixture.owner;
    let directory = &owner.authority.directory;
    let names = directory.entries(131).unwrap();
    let mut visited = Vec::new();
    validate_enrollment_slots(owner, |owner, purpose| {
        visited.push(purpose);
        inspect(owner, purpose)
    })
    .unwrap();
    assert_eq!(visited, vec![CustodyPurpose::InitialEnroll]);
    assert_eq!(directory.entries(131).unwrap(), names);
    assert_eq!(fixture.native.chain.height(), 4);
    let ceiling = 256 * 1024 * 1024;
    let original = norito::core::DecodeBudgetContext::new(limits(ceiling));
    original.with(|| full(owner)).unwrap();
    let charge = original.consumed_allocated_bytes();
    assert!(charge > 0 && charge < ceiling as u64);
    let exact = norito::core::DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    exact
        .with(|| validate_enrollment_slots(owner, inspect))
        .unwrap();
    assert_eq!(exact.consumed_allocated_bytes(), charge);
    for allocation in [0, usize::try_from(charge - 1).unwrap()] {
        let original = norito::core::DecodeBudgetContext::new(limits(allocation));
        let expected = original.with(|| full(owner)).unwrap_err().to_string();
        let actual = norito::core::DecodeBudgetContext::new(limits(allocation));
        assert_eq!(
            actual
                .with(|| validate_enrollment_slots(owner, inspect))
                .unwrap_err()
                .to_string(),
            expected
        );
        assert_eq!(
            actual.consumed_allocated_bytes(),
            original.consumed_allocated_bytes()
        );
    }
    assert!(!norito::core::decode_limits_active());
    let initial = directory.open_child("enroll").unwrap();
    let anchor = initial.read("anchor.nrt", MAX_CHECKPOINT_BYTES).unwrap();
    initial
        .write_atomic("anchor.nrt", b"malformed", PublishMode::Replace)
        .unwrap();
    assert!(validate_enrollment_slots(owner, inspect).is_err());
    initial
        .write_atomic("anchor.nrt", &anchor, PublishMode::Replace)
        .unwrap();
    validate_enrollment_slots(owner, inspect).unwrap();
    assert_eq!(directory.entries(131).unwrap(), names);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn present_slot_census_closes_names_profile_lock_and_original_directory_on_errors() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(120_000);
    let owner = &fixture.owner;
    let directory = &owner.authority.directory;
    let names = directory.entries(131).unwrap();
    let late = format!("{}-selection.nrt", renewal::directory_name(64).unwrap());
    assert!(
        validate_enrollment_slots(owner, |owner, purpose| {
            inspect(owner, purpose)?;
            directory
                .write_atomic(&late, b"malformed", PublishMode::CreateNew)
                .unwrap();
            Ok(())
        })
        .is_err()
    );
    std::fs::remove_file(directory.path().join(&late)).unwrap();
    validate_enrollment_slots(owner, inspect).unwrap();

    // The same endpoint name check still closes an ordinary original-parser error.
    directory
        .write_atomic(&late, b"malformed", PublishMode::CreateNew)
        .unwrap();
    let error = validate_enrollment_slots(owner, |owner, purpose| {
        let result = inspect(owner, purpose);
        if purpose == CustodyPurpose::Renewal(64) {
            std::fs::remove_file(directory.path().join(&late)).unwrap();
        }
        result
    })
    .unwrap_err();
    assert!(matches!(error, crate::managed::Error::Invalid(message)
        if message == "custody enrollment census changed during inspection"));
    validate_enrollment_slots(owner, inspect).unwrap();

    let peer = &owner.authority.prepared.peers[0].config_path;
    let original_peer = std::fs::read(peer).unwrap();
    assert!(
        validate_enrollment_slots(owner, |owner, purpose| {
            inspect(owner, purpose)?;
            let mut changed = original_peer.clone();
            changed.push(b'\n');
            std::fs::write(peer, changed).unwrap();
            Ok(())
        })
        .is_err()
    );
    std::fs::write(peer, &original_peer).unwrap();
    validate_enrollment_slots(owner, inspect).unwrap();

    let identity = directory.identity().unwrap();
    let lock_identity =
        iroha_fs::FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap();
    let displaced = directory.path().with_file_name("displaced-custody");
    #[cfg(unix)]
    {
        let lock = directory.path().join("operation.lock");
        let saved_lock = directory.path().with_file_name("original-custody.lock");
        assert!(
            validate_enrollment_slots(owner, |owner, purpose| {
                inspect(owner, purpose)?;
                std::fs::rename(&lock, &saved_lock).unwrap();
                directory
                    .write_atomic("operation.lock", b"", PublishMode::CreateNew)
                    .unwrap();
                Ok(())
            })
            .is_err()
        );
        std::fs::remove_file(&lock).unwrap();
        std::fs::rename(&saved_lock, &lock).unwrap();
        assert_eq!(
            iroha_fs::FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
            lock_identity
        );
        validate_enrollment_slots(owner, inspect).unwrap();
        assert!(
            validate_enrollment_slots(owner, |owner, purpose| {
                inspect(owner, purpose)?;
                std::fs::rename(directory.path(), &displaced).unwrap();
                std::fs::create_dir(directory.path()).unwrap();
                Ok(())
            })
            .is_err()
        );
        std::fs::remove_dir(directory.path()).unwrap();
        std::fs::rename(&displaced, directory.path()).unwrap();
    }
    #[cfg(windows)]
    {
        validate_enrollment_slots(owner, |owner, purpose| {
            inspect(owner, purpose)?;
            assert!(std::fs::rename(directory.path(), &displaced).is_err());
            assert!(
                directory
                    .write_atomic("operation.lock", b"", PublishMode::Replace)
                    .is_err()
            );
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(directory.identity().unwrap(), identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
        lock_identity
    );
    assert_eq!(directory.entries(131).unwrap(), names);
    validate_enrollment_slots(owner, inspect).unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}
