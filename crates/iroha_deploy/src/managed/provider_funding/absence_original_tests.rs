//! Funding absence checks retain original profile and fresh native child custody.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers,
    service_authority::profile_validation_test_support as checks,
};
use iroha_fs::{FileIdentity, PrivateDirectory, PublishMode};
use norito::core::DecodeBudgetContext;
use std::{cell::Cell, rc::Rc};

fn parsed<T>(action: impl FnOnce() -> T) -> (T, usize) {
    crate::localnet::service_authorities::count_profile_validations(action)
}
fn purpose() -> ProviderPurpose {
    ProviderPurpose::InitialProviderCredit
}
fn probe(owner: &ProviderFundingBootstrap) -> Result<()> {
    owner.require_empty_child(purpose(), "install")
}
// The exact former constructor and unchanged absence tail are a test-only baseline.
// This invokes the real profile producer; no wire/proof decoder is duplicated.
fn ordinary(owner: &ProviderFundingBootstrap) -> Result<()> {
    let Some(child) = ServiceAuthority::open_provider_existing(
        &owner.authority.prepared,
        owner.authority.provider_id()?,
        purpose(),
    )?
    else {
        return Ok(());
    };
    child.validate_profile()?;
    if child
        .directory
        .entries(2)?
        .iter()
        .any(|name| name != "operation.lock" && name != "install")
    {
        return Err(invalid(
            "later funding purpose contains unknown retained material",
        ));
    }
    match child.directory.open_child_optional("install")? {
        Some(directory) => require_empty(&directory),
        None => Ok(()),
    }
}
fn child(owner: &ProviderFundingBootstrap) -> ServiceAuthority {
    ServiceAuthority::open_provider(
        &owner.authority.prepared,
        owner.authority.provider_id().unwrap(),
        purpose(),
    )
    .unwrap()
}
fn child_path(owner: &ProviderFundingBootstrap) -> std::path::PathBuf {
    owner
        .authority
        .directory
        .path()
        .parent()
        .unwrap()
        .join("initial-provider-credit")
}
fn outcome(value: Result<()>) -> std::result::Result<(), String> {
    value.map_err(|error| error.to_string())
}
fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

#[test]
fn funding_absence_census_reuses_original_without_creating_or_retaining_children() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, owner) = tests::fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let funding = owner.authority.directory.ensure_child("funding").unwrap();
    let selected =
        PrivateDirectory::open_exact(owner.authority.directory.path().parent().unwrap()).unwrap();
    let names = selected.entries(8).unwrap();
    for (step, later) in [
        (FundingStep::Request, 3),
        (FundingStep::Approval, 2),
        (FundingStep::Credit, 1),
        (FundingStep::Capacity, 0),
    ] {
        let ((result, parses), validations) =
            checks::count(|| parsed(|| owner.require_no_later_material(step)));
        result.unwrap();
        assert_eq!(parses, 0);
        assert_eq!(
            validations,
            2 * later,
            "both parent boundaries for every absent child"
        );
    }
    let ((result, parses), validations) =
        checks::count(|| parsed(|| owner.require_no_child_material()));
    result.unwrap();
    assert_eq!((parses, validations), (0, 8));
    assert_eq!(selected.entries(8).unwrap(), names);
    require_empty(&funding).unwrap();
    assert!(!child_path(&owner).exists());
    let (result, parses) = parsed(|| ordinary(&owner));
    result.unwrap();
    assert_eq!(
        parses, 1,
        "the old absence recipe really reparses the signed profile"
    );
    assert!(!child_path(&owner).exists());

    let later = child(&owner);
    let directory = later.directory.retain().unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&later._lock).unwrap();
    assert_eq!(
        outcome(probe(&owner)),
        outcome(ordinary(&owner)),
        "held child still refuses"
    );
    drop(later);
    for installed in [false, true] {
        let install = installed.then(|| directory.ensure_child("install").unwrap());
        let names = directory.entries(2).unwrap();
        let ((actual, parses), validations) = checks::count(|| parsed(|| probe(&owner)));
        actual.unwrap();
        assert_eq!((parses, validations), (0, 3));
        let (expected, parses) = parsed(|| ordinary(&owner));
        expected.unwrap();
        assert_eq!(parses, 1);
        assert_eq!(directory.entries(2).unwrap(), names);
        assert_eq!(directory.identity().unwrap(), identity);
        assert_eq!(
            FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
            lock_identity
        );
        let reopened = child(&owner);
        assert!(reopened.checkpoint_import_scope().is_none());
        drop(reopened); // A successful read returned no live child lock or proof scope.
        if let Some(install) = install {
            install
                .write_atomic("original.nrt", b"retained", PublishMode::CreateNew)
                .unwrap();
            assert_eq!(outcome(probe(&owner)), outcome(ordinary(&owner)));
            assert!(probe(&owner).is_err());
            assert_eq!(
                install.read("original.nrt", 8).unwrap().as_slice(),
                b"retained"
            );
            assert!(!install.path().join("attempts").exists());
        }
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn funding_absence_keeps_original_parent_entry_and_all_result_exit_precedence() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, owner) = tests::fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.push(0);
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    let ((result, parses), validations) = checks::count(|| parsed(|| probe(&owner)));
    assert_eq!(outcome(result), outcome(owner.authority.validate_profile()));
    assert_eq!((parses, validations), (0, 1));
    assert!(
        !child_path(&owner).exists(),
        "entry refusal creates no later purpose"
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();

    // None, successful held child, and ordinary child lock failure all close the same parent.
    for state in 0..3 {
        let held = (state > 0).then(|| child(&owner));
        let directory = held.as_ref().map(|child| child.directory.retain().unwrap());
        let held = if state == 1 {
            drop(held);
            None
        } else {
            held
        };
        let reached = Rc::new(Cell::new(false));
        let mark = Rc::clone(&reached);
        let root = generation.retain().unwrap();
        let bytes = zeroize::Zeroizing::new(changed.to_vec());
        let hook = checks::on_existing_child_exit(move |result| {
            mark.set(true);
            match state {
                0 => assert!(matches!(result, Ok(None))),
                1 => {
                    let child = result.as_ref().unwrap().as_ref().unwrap();
                    assert!(child.checkpoint_import_scope().is_none());
                    match child.directory.open_existing_lock("operation.lock") {
                        Ok(lock) => assert!(
                            lock.try_lock().is_err(),
                            "actual child Result retains its exclusive lock through parent exit"
                        ),
                        Err(error) => {
                            assert!(cfg!(windows));
                            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                        }
                    }
                }
                2 => assert_eq!(
                    result.as_ref().err().unwrap().to_string(),
                    "another managed native operation holds this generation"
                ),
                _ => unreachable!(),
            }
            root.write_atomic("peer3.toml", &bytes, PublishMode::Replace)
                .unwrap();
        });
        let ((refused, parses), validations) = checks::count(|| parsed(|| probe(&owner)));
        assert!(reached.get());
        assert_eq!((parses, validations), (0, 2));
        assert_eq!(
            outcome(refused),
            outcome(owner.authority.validate_profile()),
            "parent exit wins over the original ordinary child result"
        );
        drop(hook);
        generation
            .write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
        drop(held);
        probe(&owner).unwrap();
        if let Some(directory) = directory {
            let reopened = child(&owner);
            assert_eq!(
                reopened.directory.identity().unwrap(),
                directory.identity().unwrap()
            );
            drop(reopened);
        }
    }
    owner.authority.validate_profile().unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn funding_absence_observes_appeared_child_material_and_native_substitution() {
    let _guard = crate::managed::native_test_guard();
    let (temporary, prepared, owner) = tests::fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    let later = child(&owner);
    let directory = later.directory.retain().unwrap();
    let install = directory.ensure_child("install").unwrap();
    let identity = directory.identity().unwrap();
    let lock_identity = FileIdentity::of(&later._lock).unwrap();
    drop(later);
    let appeared = install.retain().unwrap();
    let hook = checks::on_existing_child_exit(move |result| {
        assert!(matches!(result, Ok(Some(_))));
        appeared
            .write_atomic("original.nrt", b"new", PublishMode::CreateNew)
            .unwrap();
    });
    assert!(
        probe(&owner).is_err(),
        "a fresh child tail must see appeared retained material"
    );
    drop(hook);
    assert_eq!(install.read("original.nrt", 3).unwrap().as_slice(), b"new");
    install.remove_private("original.nrt").unwrap();
    probe(&owner).unwrap();

    #[cfg(unix)]
    for replace_parent in [false, true] {
        let source = if replace_parent {
            &owner.authority.directory
        } else {
            &directory
        };
        let source_path = source.path().to_path_buf();
        let saved = temporary.path().join(if replace_parent {
            "parent-lock"
        } else {
            "child-lock"
        });
        let source_for_hook = source.retain().unwrap();
        let saved_for_hook = saved.clone();
        let hook = checks::on_existing_child_exit(move |result| {
            assert!(matches!(result, Ok(Some(_))));
            std::fs::rename(
                source_for_hook.path().join("operation.lock"),
                &saved_for_hook,
            )
            .unwrap();
            source_for_hook
                .write_atomic("operation.lock", b"replacement", PublishMode::CreateNew)
                .unwrap();
        });
        let ((result, parses), validations) = checks::count(|| parsed(|| probe(&owner)));
        assert!(result.is_err());
        assert_eq!(parses, 0);
        assert_eq!(validations, if replace_parent { 2 } else { 3 });
        drop(hook);
        source.remove_private("operation.lock").unwrap();
        std::fs::rename(&saved, source_path.join("operation.lock")).unwrap();
        probe(&owner).unwrap();
    }
    #[cfg(windows)]
    {
        let held = child(&owner);
        assert!(
            std::fs::rename(
                directory.path().join("operation.lock"),
                temporary.path().join("child-lock")
            )
            .is_err()
        );
        assert!(
            std::fs::rename(
                owner.authority.directory.path().join("operation.lock"),
                temporary.path().join("parent-lock")
            )
            .is_err()
        );
        assert!(probe(&owner).is_err());
        drop(held);
        probe(&owner).unwrap();
    }
    directory
        .write_atomic("unknown.nrt", b"x", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(outcome(probe(&owner)), outcome(ordinary(&owner)));
    assert!(probe(&owner).is_err());
    directory.remove_private("unknown.nrt").unwrap();
    assert_eq!(directory.identity().unwrap(), identity);
    assert_eq!(
        FileIdentity::of(&directory.open_read("operation.lock").unwrap()).unwrap(),
        lock_identity
    );
    probe(&owner).unwrap();
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn funding_absence_keeps_exact_active_budget_and_owned_parent_capture_recipe() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, owner) = tests::fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    for present in [false, true] {
        if present {
            drop(child(&owner));
        }
        let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
        let (expected, parses) = parsed(|| baseline.with(|| ordinary(&owner)));
        expected.unwrap();
        assert_eq!(parses, 1);
        let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
        assert!(charge > 1);
        for allocated in [0, 1, charge - 1, charge] {
            let expected_budget = DecodeBudgetContext::new(limits(allocated));
            let actual_budget = DecodeBudgetContext::new(limits(allocated));
            let (expected, old_parses) = parsed(|| expected_budget.with(|| ordinary(&owner)));
            let (actual, new_parses) = parsed(|| actual_budget.with(|| probe(&owner)));
            assert_eq!((old_parses, new_parses), (1, 1));
            assert_eq!(expected.is_ok(), allocated == charge);
            assert_eq!(outcome(actual), outcome(expected));
            assert_eq!(
                actual_budget.consumed_allocated_bytes(),
                expected_budget.consumed_allocated_bytes()
            );
            if allocated == charge {
                assert_eq!(actual_budget.consumed_allocated_bytes(), charge as u64);
            }
        }
        let (result, parses) = parsed(|| probe(&owner));
        result.unwrap();
        assert_eq!(parses, 0);
        assert_eq!(child_path(&owner).exists(), present);
    }
    let provider = owner.authority.provider_id().unwrap();
    drop(owner);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let authority = caller
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
    assert!(authority.original_intent_if_shared().unwrap().is_none());
    let owner = ProviderFundingBootstrap { authority };
    for (purpose, child) in [
        (ProviderPurpose::InitialProviderCredit, "install"),
        (ProviderPurpose::ReserveTopUpApproval, "approval"),
    ] {
        let (result, parses) = parsed(|| owner.require_empty_child(purpose, child));
        result.unwrap();
        assert_eq!(
            parses, 1,
            "Owned parent keeps literal full capture even after active scope ends"
        );
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
