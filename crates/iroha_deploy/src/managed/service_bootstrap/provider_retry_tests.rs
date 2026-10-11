//! Fresh-worker retries retain genuine startup authority without waiting for sibling completion.
//! These are scheduling tests; paid history and once-only wallet recovery stay in native DAG tests.

use super::*;
use crate::managed::ManagedBootstrapFailure;
use std::{
    ffi::OsString,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use zeroize::Zeroizing;

type RetainedEvidence = (Zeroizing<Vec<u8>>, Vec<(OsString, Zeroizing<Vec<u8>>)>);

struct Fixture {
    _temporary: tempfile::TempDir,
    _ports: crate::managed::LocalnetPorts,
    owner: ManagedServiceBootstrap,
    authorization: GeneratedBootstrapAuthorization,
    cancelled: Arc<AtomicBool>,
    original: Original,
    deadline: Instant,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "fresh-provider-retry",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let mut owner = ManagedServiceBootstrap::open(&prepared).unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let cancelled = Arc::new(AtomicBool::new(false));
        let authorization = owner
            .authorize_generated_startup(deadline, Arc::clone(&cancelled))
            .unwrap()
            .unwrap();
        let directory = owner.authority.directory.open_child("initial").unwrap();
        let original = read_original(&directory, &owner.authority)
            .unwrap()
            .unwrap();
        Self {
            _temporary: temporary,
            _ports: ports,
            owner,
            authorization,
            cancelled,
            original,
            deadline,
        }
    }

    fn run(&self, deadline: Instant) -> Run<'_> {
        Run {
            authority: &self.owner.authority,
            original: &self.original,
            deadline,
            mode: Mode::Advance,
            authorization: Some(&self.authorization),
            checkpoint_import_scope: None,
        }
    }

    fn evidence(&self) -> RetainedEvidence {
        let directory = self
            .owner
            .authority
            .directory
            .open_child("initial")
            .unwrap();
        let epochs = directory.open_child("epochs").unwrap();
        (
            directory.read("original.nrt", MAX_ORIGINAL_BYTES).unwrap(),
            epochs
                .entries(128)
                .unwrap()
                .into_iter()
                .map(|name| {
                    let bytes = epochs
                        .read(
                            &name,
                            crate::managed::native_operation::attempts::MAX_RECORD_BYTES,
                        )
                        .unwrap();
                    (name, bytes)
                })
                .collect(),
        )
    }
}

#[test]
fn fresh_provider_retries_before_a_sibling_finishes_without_replacing_authority() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let evidence = fixture.evidence();
    let run = fixture.run(fixture.deadline);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (retried_tx, retried_rx) = mpsc::sync_channel(1);
    let sibling_done = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let provider_id = fixture.original.policies.providers[2].provider_id;
    std::thread::scope(|scope| {
        let run_ref = &run;
        let sibling_done_ref = &sibling_done;
        let slow = scope.spawn(move || {
            retry_fresh_provider(run_ref, || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                sibling_done_ref.store(true, Ordering::Release);
                Ok(Phase::Complete(()))
            })
        });
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let fast = scope.spawn(|| {
            retry_fresh_provider(&run, || match calls.fetch_add(1, Ordering::AcqRel) {
                0 => Err(invalid("transient native proof unavailable")),
                1 => absent(ServiceBootstrapStep::ProviderFunding { provider_id }),
                2 => {
                    retried_tx
                        .send(!sibling_done.load(Ordering::Acquire))
                        .unwrap();
                    Ok(Phase::Complete(()))
                }
                _ => panic!("completed provider was retried"),
            })
        });
        let retried_before_release = retried_rx.recv_timeout(Duration::from_secs(5));
        // Always release and join owned siblings before asserting the scheduling observation.
        release_tx.send(()).unwrap();
        let fast = fast.join().unwrap();
        let slow = slow.join().unwrap();
        assert_eq!(retried_before_release, Ok(true));
        assert!(matches!(fast, Ok(Phase::Complete(()))));
        assert!(matches!(slow, Ok(Phase::Complete(()))));
    });
    assert_eq!(calls.load(Ordering::Acquire), 3);
    assert!(sibling_done.load(Ordering::Acquire));
    assert_eq!(fixture.evidence(), evidence);
    assert_eq!(fixture.authorization.test_ordinal(), 1);
}

#[test]
fn fresh_provider_retry_stops_terminal_cancellation_and_original_deadline() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let evidence = fixture.evidence();
    let run = fixture.run(fixture.deadline);
    let mut calls = 0;
    let terminal = retry_fresh_provider::<()>(&run, || {
        calls += 1;
        Err(ManagedBootstrapFailure::SignedUnresolved.into())
    });
    assert!(matches!(
        terminal,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::SignedUnresolved
        ))
    ));
    assert_eq!(calls, 1);

    let limited = fixture.run(Instant::now() + Duration::from_secs(2));
    let mut calls = 0;
    let expired = retry_fresh_provider::<()>(&limited, || {
        calls += 1;
        std::thread::sleep(limited.deadline.saturating_duration_since(Instant::now()));
        Err(invalid(
            "transient refusal returned at the original deadline",
        ))
    });
    assert!(matches!(
        expired,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::AuthorizationExpired
        ))
    ));
    assert_eq!(calls, 1);
    assert!(matches!(
        retry_fresh_provider::<()>(&limited, || panic!("expired worker ran another turn")),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::AuthorizationExpired
        ))
    ));

    let mut calls = 0;
    let cancelled = retry_fresh_provider::<()>(&run, || {
        calls += 1;
        fixture.cancelled.store(true, Ordering::Release);
        Err(invalid(
            "transient refusal concurrent with original cancellation",
        ))
    });
    assert!(matches!(
        cancelled,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::Cancelled
        ))
    ));
    assert_eq!(calls, 1);
    assert!(matches!(
        retry_fresh_provider::<()>(&run, || panic!("cancelled worker ran another turn")),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::Cancelled
        ))
    ));
    assert_eq!(fixture.evidence(), evidence);
    assert_eq!(fixture.authorization.test_ordinal(), 1);
}
