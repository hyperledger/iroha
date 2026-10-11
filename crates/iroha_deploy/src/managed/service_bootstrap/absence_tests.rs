//! Genuine first-reserve absence, original child refusal and independent caller admission.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers, service_authority::ServiceChildInventory,
};
use norito::core::DecodeBudgetContext;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    authority: ServiceAuthority,
    original: Original,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "first-reserve-absence",
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
        let initial = authority.directory.ensure_child("initial").unwrap();
        initial
            .write_atomic(
                "original.nrt",
                &encode(&original, MAX_ORIGINAL_BYTES).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        Self {
            _temporary: temporary,
            authority,
            original,
        }
    }

    fn reserve(
        &self,
        mode: Mode,
        authorization: Option<&GeneratedBootstrapAuthorization>,
        deadline: Instant,
    ) -> Result<Phase<ManagedTransactionFinality>> {
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
        .reserve()
    }

    fn custody(
        &self,
        mode: Mode,
        authorization: Option<&GeneratedBootstrapAuthorization>,
        deadline: Instant,
    ) -> Result<Phase<(ManagedTransactionFinality, ManagedTransactionFinality)>> {
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
        .custody(&self.original.policies.providers[0], 1)
    }

    fn network(&self) -> PrivateDirectory {
        PrivateDirectory::open_exact(self.authority.directory.path().parent().unwrap()).unwrap()
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

fn measured<T>(action: impl FnOnce() -> T) -> (T, usize, usize) {
    let ((result, opens), parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            ServiceChildInventory::test_count_authority_opens(action)
        });
    (result, opens, parses)
}

fn assert_absent(value: Phase<ManagedTransactionFinality>) {
    match value {
        Phase::Incomplete(Incomplete::Pending { step, status }) => {
            assert_eq!(step, ServiceBootstrapStep::ReservePolicy);
            assert_eq!(status, OperationStatus::Absent);
        }
        _ => panic!("missing reserve purpose must preserve the exact unfinished step"),
    }
}

#[test]
fn absent_first_reserve_is_fresh_readonly_without_child_capture_http_or_original_changes() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let network = fixture.network();
    let names = network.entries(64).unwrap();
    let parent_names = fixture.authority.directory.entries(4).unwrap();
    let original = fixture.original_bytes();
    for mode in [Mode::Local, Mode::Recover] {
        let (result, opens, parses) =
            measured(|| fixture.reserve(mode, None, Instant::now() + Duration::from_secs(60)));
        assert_absent(result.unwrap());
        assert_eq!((opens, parses), (0, 0));
        assert_eq!(network.entries(64).unwrap(), names);
        assert_eq!(
            fixture.authority.directory.entries(4).unwrap(),
            parent_names
        );
        assert_eq!(fixture.original_bytes(), original);
        assert!(
            !fixture
                .authority
                .directory
                .path()
                .join("initial/epochs")
                .exists()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    peers.finish();
}

#[test]
fn present_first_reserve_keeps_empty_dirty_link_and_native_lock_owner_refusals() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let network = fixture.network();
    let purpose = network.ensure_child("initial-reserve-policy").unwrap();
    let original = fixture.original_bytes();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (empty, opens, parses) = measured(|| fixture.reserve(Mode::Local, None, deadline));
    assert_absent(empty.unwrap());
    assert_eq!(
        (opens, parses),
        (1, 0),
        "present prefix keeps fresh native admission without reparsing the original profile"
    );
    assert!(purpose.entries(1).unwrap().is_empty());
    purpose
        .write_atomic(
            "unknown.nrt",
            b"retained presence only",
            PublishMode::CreateNew,
        )
        .unwrap();
    let (dirty, opens, parses) = measured(|| fixture.reserve(Mode::Local, None, deadline));
    assert!(dirty.is_err());
    assert_eq!((opens, parses), (1, 0));
    assert_eq!(
        purpose.read("unknown.nrt", 64).unwrap().as_slice(),
        b"retained presence only"
    );
    assert!(!purpose.path().join("operation.lock").exists());
    std::fs::remove_file(purpose.path().join("unknown.nrt")).unwrap();
    let held = ManagedInitialReservePolicy::open(&fixture.authority.prepared).unwrap();
    let (locked, opens, parses) = measured(|| fixture.reserve(Mode::Local, None, deadline));
    assert!(locked.is_err());
    assert_eq!((opens, parses), (1, 0));
    drop(held);
    let (retried, opens, parses) = measured(|| fixture.reserve(Mode::Local, None, deadline));
    assert_absent(retried.unwrap());
    assert_eq!((opens, parses), (1, 0));
    assert!(!purpose.path().join("set").exists());
    #[cfg(unix)]
    {
        std::fs::remove_file(purpose.path().join("operation.lock")).unwrap();
        std::fs::remove_dir(purpose.path()).unwrap();
        std::os::unix::fs::symlink(fixture.authority.directory.path(), purpose.path()).unwrap();
        let (linked, opens, parses) = measured(|| fixture.reserve(Mode::Local, None, deadline));
        assert!(linked.is_err());
        assert_eq!((opens, parses), (1, 0));
        std::fs::remove_file(purpose.path()).unwrap();
        let (retried, opens, parses) = measured(|| fixture.reserve(Mode::Local, None, deadline));
        assert_absent(retried.unwrap());
        assert_eq!((opens, parses), (0, 0));
    }
    assert_eq!(fixture.original_bytes(), original);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

fn caller_limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        8 * 1024 * 1024,
        64 * 1024 * 1024,
        8 * 1024 * 1024,
        allocation,
        64,
    )
}

#[test]
fn enclosing_budget_keeps_original_absent_child_capture_charges_and_refusal_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let original = fixture.original_bytes();
    let names = fixture.network().entries(64).unwrap();
    let original_budget = DecodeBudgetContext::new(caller_limits(64 * 1024 * 1024));
    let (expected, opens, parses) = measured(|| {
        original_budget
            .with(|| ManagedInitialReservePolicy::open_existing(&fixture.authority.prepared))
    });
    assert!(expected.unwrap().is_none());
    assert_eq!((opens, parses), (1, 1));
    let charge = original_budget.consumed_allocated_bytes();
    assert!(charge > 0);
    let phase_budget = DecodeBudgetContext::new(caller_limits(usize::try_from(charge).unwrap()));
    let (result, opens, parses) = measured(|| {
        phase_budget
            .with(|| fixture.reserve(Mode::Local, None, Instant::now() + Duration::from_secs(60)))
    });
    assert_absent(result.unwrap());
    assert_eq!((opens, parses), (1, 1));
    assert_eq!(phase_budget.consumed_allocated_bytes(), charge);
    let expected_budget = DecodeBudgetContext::new(caller_limits(0));
    let (expected, opens, parses) = measured(|| {
        expected_budget
            .with(|| ManagedInitialReservePolicy::open_existing(&fixture.authority.prepared))
    });
    let expected = expected.err().unwrap();
    assert!(
        matches!(&expected, crate::managed::Error::Invalid(message) if message == "retained stream-token authority prerequisites are invalid")
    );
    assert_eq!((opens, parses), (1, 1));
    let refusing_budget = DecodeBudgetContext::new(caller_limits(0));
    let (refused, opens, parses) = measured(|| {
        refusing_budget
            .with(|| fixture.reserve(Mode::Local, None, Instant::now() + Duration::from_secs(60)))
    });
    let refused = refused.err().unwrap();
    assert_eq!(format!("{refused:?}"), format!("{expected:?}"));
    assert_eq!((opens, parses), (1, 1));
    assert_eq!(
        refusing_budget.consumed_allocated_bytes(),
        expected_budget.consumed_allocated_bytes()
    );
    assert_eq!(fixture.original_bytes(), original);
    assert_eq!(fixture.network().entries(64).unwrap(), names);
    let (retried, opens, parses) =
        measured(|| fixture.reserve(Mode::Local, None, Instant::now() + Duration::from_secs(60)));
    assert_absent(retried.unwrap());
    assert_eq!((opens, parses), (0, 0));
    assert_eq!(
        refusing_budget.consumed_allocated_bytes(),
        expected_budget.consumed_allocated_bytes()
    );
    assert_eq!(fixture.original_bytes(), original);
}

#[test]
fn absent_advance_requires_real_live_authorization_before_any_child_creation() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(60);
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
    let epoch_names = epochs.entries(64).unwrap();
    let epoch_bytes = epochs.read("0001.nrt", 64 * 1024).unwrap();
    let original = fixture.original_bytes();
    let names = fixture.network().entries(64).unwrap();
    let (expired, opens, parses) = measured(|| {
        fixture.reserve(
            Mode::Advance,
            Some(&authorization),
            Instant::now() - Duration::from_secs(1),
        )
    });
    assert!(matches!(
        expired.err().unwrap(),
        crate::managed::Error::Bootstrap(
            crate::managed::ManagedBootstrapFailure::AuthorizationExpired
        )
    ));
    assert_eq!((opens, parses), (0, 0));
    cancelled.store(true, Ordering::Release);
    let (stopped, opens, parses) =
        measured(|| fixture.reserve(Mode::Advance, Some(&authorization), deadline));
    assert!(matches!(
        stopped.err().unwrap(),
        crate::managed::Error::Bootstrap(crate::managed::ManagedBootstrapFailure::Cancelled)
    ));
    assert_eq!((opens, parses), (0, 0));
    assert_eq!(fixture.network().entries(64).unwrap(), names);
    assert_eq!(fixture.original_bytes(), original);
    assert_eq!(epochs.entries(64).unwrap(), epoch_names);
    assert_eq!(epochs.read("0001.nrt", 64 * 1024).unwrap(), epoch_bytes);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn custody_absence_keeps_original_authorization_and_enclosing_admission_before_creation() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.authority.prepared);
    let runtime = fixture
        .authority
        .directory
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let purpose = runtime.join("service-operations/providers/0/stream-token-custody");
    assert!(!purpose.exists());
    let original = fixture.original_bytes();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (missing, opens, parses) = measured(|| fixture.custody(Mode::Advance, None, deadline));
    assert!(
        matches!(missing.err().unwrap(), crate::managed::Error::Invalid(message)
        if message == "bootstrap advance requires its live worker authorization")
    );
    assert_eq!((opens, parses), (1, 0));
    assert!(!purpose.exists());
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
    let epoch = epochs.read("0001.nrt", 64 * 1024).unwrap();
    let (expired, opens, parses) = measured(|| {
        fixture.custody(
            Mode::Advance,
            Some(&authorization),
            Instant::now() - Duration::from_secs(1),
        )
    });
    assert!(matches!(
        expired.err().unwrap(),
        crate::managed::Error::Bootstrap(
            crate::managed::ManagedBootstrapFailure::AuthorizationExpired
        )
    ));
    assert_eq!((opens, parses), (1, 0));
    assert!(!purpose.exists());
    cancelled.store(true, Ordering::Release);
    let (stopped, opens, parses) =
        measured(|| fixture.custody(Mode::Advance, Some(&authorization), deadline));
    assert!(matches!(
        stopped.err().unwrap(),
        crate::managed::Error::Bootstrap(crate::managed::ManagedBootstrapFailure::Cancelled)
    ));
    assert_eq!((opens, parses), (1, 0));
    assert!(!purpose.exists());
    let refusing = DecodeBudgetContext::new(caller_limits(0));
    let (expected, opens, parses) = measured(|| {
        refusing.with(|| {
            ManagedStreamTokenCustody::open_existing(
                &fixture.authority.prepared,
                fixture.original.policies.providers[0].provider_id,
            )
        })
    });
    let expected = expected.err().unwrap();
    assert_eq!((opens, parses), (1, 1));
    let admission = DecodeBudgetContext::new(caller_limits(0));
    let (actual, opens, parses) = measured(|| {
        admission.with(|| fixture.custody(Mode::Advance, Some(&authorization), deadline))
    });
    assert_eq!(
        actual.err().unwrap().to_string(),
        expected.to_string(),
        "active admission refuses before original authorization, as the standalone producer did"
    );
    assert_eq!((opens, parses), (1, 1));
    assert_eq!(
        admission.consumed_allocated_bytes(),
        refusing.consumed_allocated_bytes()
    );
    assert!(!purpose.exists());
    assert_eq!(fixture.original_bytes(), original);
    assert_eq!(epochs.entries(64).unwrap(), names);
    assert_eq!(epochs.read("0001.nrt", 64 * 1024).unwrap(), epoch);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
