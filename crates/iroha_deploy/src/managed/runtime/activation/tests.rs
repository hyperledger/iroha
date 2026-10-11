//! Original profile and clock/refusal controls; these do not fabricate native service readiness.

use super::*;
use crate::managed::{native_operation::test_support::UnavailablePeers, runtime::progress::Cause};
use iroha_crypto::{Hash, HashOf};

fn fixture(profile: LocalnetServiceProfile) -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "activation",
        &temporary.path().join("generation"),
        &ports,
        profile,
        None,
    )
    .unwrap();
    (temporary, prepared)
}
fn budget() -> Budget {
    Budget {
        started: Instant::now(),
        timeout: Duration::from_secs(120),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    }
}

#[test]
fn generated_preparation_retains_one_original_without_http_or_bootstrap_execution() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let root = prepared.context.client_config.parent().unwrap();
    let original_configs: Vec<_> = prepared
        .peers
        .iter()
        .map(|peer| {
            iroha_fs::read_private(&peer.config_path, 1024 * 1024)
                .unwrap()
                .to_vec()
        })
        .collect();
    let first = prepare(&prepared, &budget()).unwrap();
    let original = iroha_fs::read_private(
        &root.join("runtime/service-operations/network/service-bootstrap/initial/original.nrt"),
        512 * 1024,
    )
    .unwrap();
    assert!(
        prepare(&prepared, &budget()).is_err(),
        "sole renderer lock must be retained"
    );
    drop(first);
    let second = prepare(&prepared, &budget()).unwrap();
    assert_eq!(
        iroha_fs::read_private(
            &root.join("runtime/service-operations/network/service-bootstrap/initial/original.nrt"),
            512 * 1024
        )
        .unwrap()
        .as_slice(),
        original.as_slice()
    );
    for (peer, expected) in prepared.peers.iter().zip(original_configs) {
        assert_eq!(
            iroha_fs::read_private(&peer.config_path, 1024 * 1024)
                .unwrap()
                .as_slice(),
            expected.as_slice()
        );
    }
    for slot in 0..3 {
        assert!(
            !root
                .join(format!(
                    "runtime/service-operations/providers/{slot}/stream-token-custody"
                ))
                .exists()
        );
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    drop(second);
    peers.finish();
}

#[test]
fn standard_selection_is_lazy_and_cancelled_or_expired_generated_selection_creates_no_owner() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, standard) = fixture(LocalnetServiceProfile::Standard);
    assert!(prepare(&standard, &budget()).unwrap().launch.is_none());
    assert!(
        !standard
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime/service-operations/network/service-bootstrap")
            .exists()
    );
    let (_temporary, generated) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&generated);
    let cancelled = budget();
    cancelled.cancelled.store(true, Ordering::Release);
    assert!(
        matches!(prepare(&generated, &cancelled), Err(failure) if failure == cancelled.progress.cancelled())
    );
    let expired = Budget {
        started: Instant::now() - Duration::from_secs(121),
        ..budget()
    };
    assert!(
        matches!(prepare(&generated, &expired), Err(failure) if failure == expired.progress.deadline())
    );
    assert!(
        !generated
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime/service-operations/network/service-bootstrap")
            .exists()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn exact_original_transaction_height_hash_and_time_remain_required() {
    // Structural rejection only; these values do not construct native or renderer authority.
    let original = ManagedTransactionFinality {
        transaction_hash: HashOf::from_untyped_unchecked(Hash::new(b"comparison-only-tx")),
        height: 13,
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"comparison-only-header")),
        block_time_ms: 1,
    };
    require_original_transactions(&[original], &[original]).unwrap();
    assert!(require_original_transactions(&[original], &[]).is_err());
    assert!(require_original_transactions(&[], &[original]).is_err());
    for changed in [
        ManagedTransactionFinality {
            height: 12,
            ..original
        },
        ManagedTransactionFinality {
            block_hash: HashOf::from_untyped_unchecked(Hash::new(b"comparison-only-other-header")),
            ..original
        },
        ManagedTransactionFinality {
            transaction_hash: HashOf::from_untyped_unchecked(Hash::new(
                b"comparison-only-other-tx",
            )),
            ..original
        },
        ManagedTransactionFinality {
            block_time_ms: 2,
            ..original
        },
    ] {
        assert!(require_original_transactions(&[original], &[changed]).is_err());
    }
    let zero = ManagedTransactionFinality {
        height: 0,
        ..original
    };
    assert!(require_original_transactions(&[zero], &[zero]).is_err());
}

#[test]
fn observation_uses_both_clocks_and_never_renews_on_wall_clock_rollback() {
    let observed_at = Instant::now();
    let utc = now_ms().unwrap();
    let selected = ReadinessExpiry::select(utc + 10_000, observed_at, utc).unwrap();
    assert!(selected.current_at(observed_at + Duration::from_secs(9), utc + 9_999));
    assert!(!selected.current_at(observed_at + Duration::from_secs(10), utc - 1));
    assert!(!selected.current_at(observed_at, utc + 10_000));
    assert!(ReadinessExpiry::select(utc, observed_at, utc).is_err());
    assert!(ReadinessExpiry::select(utc + 1, observed_at - Duration::from_secs(1), utc).is_err());
}

#[test]
fn phase_failures_and_late_or_cancelled_results_use_only_closed_diagnostics() {
    let selected = budget();
    assert_eq!(
        selected.progress.deadline(),
        Failure::Activation {
            phase: Phase::Selection,
            cause: Cause::Deadline
        },
    );
    for (phase, description) in [
        (
            Phase::Selection,
            "retaining the original generated service selection",
        ),
        (
            Phase::InitialReadiness,
            "proving the original readiness transaction",
        ),
        (
            Phase::Bootstrap,
            "recovering and advancing the original native service bootstrap",
        ),
        (
            Phase::Carrier0,
            "confirming the original bootstrap carrier on validator 0",
        ),
        (
            Phase::Carrier1,
            "confirming the original bootstrap carrier on validator 1",
        ),
        (
            Phase::Carrier2,
            "confirming the original bootstrap carrier on validator 2",
        ),
        (
            Phase::Carrier3,
            "confirming the original bootstrap carrier on validator 3",
        ),
        (
            Phase::CarrierPeers,
            "confirming the original bootstrap carrier on all four validators",
        ),
        (
            Phase::Catalog,
            "publishing the exact generated gateway catalog",
        ),
        (
            Phase::Restart,
            "restarting the owned validators with the retained service revision",
        ),
        (
            Phase::Receipt,
            "reproving the same readiness transaction after restart",
        ),
        (
            Phase::PromotedCatalog,
            "checking the exact promoted catalog after restart",
        ),
        (
            Phase::ProviderAdvertisement,
            "publishing the original provider advertisement",
        ),
        (
            Phase::Discovery,
            "authenticating current native provider and signer discovery",
        ),
        (
            Phase::CustodyRenewal,
            "recovering and advancing the exact bounded custody renewal",
        ),
        (
            Phase::ProgramAdmission,
            "verifying the installed runtime and opening its control session",
        ),
        (
            Phase::CustodyMaterial,
            "retaining current native custody material",
        ),
        (
            Phase::StreamTokenRevision,
            "preparing the current stream-token runtime revision",
        ),
    ] {
        selected.progress.enter(phase);
        for (failure, cause, prefix) in [
            (
                selected.progress.deadline(),
                Cause::Deadline,
                "startup deadline expired",
            ),
            (
                selected.progress.unconfirmed(),
                Cause::Unconfirmed,
                "startup could not be confirmed",
            ),
            (
                selected.progress.cancelled(),
                Cause::Cancelled,
                "startup was cancelled",
            ),
        ] {
            // Exact phase equality catches an incorrect AtomicU8 mapping as well as
            // a later phase accidentally reusing the preceding stage's safe message.
            assert_eq!(failure, Failure::Activation { phase, cause });
            assert_eq!(failure.message(), format!("{prefix} while {description}"));
            assert!(failure.message().starts_with("startup"));
            assert!(failure.message().len() < 180);
            assert!(!failure.message().contains("http"));
        }
        let mut expired = budget();
        expired.progress.enter(phase);
        expired.timeout = Duration::ZERO;
        assert_eq!(
            expired.check(),
            Err(Failure::Activation {
                phase,
                cause: Cause::Deadline
            })
        );
        expired.cancelled.store(true, Ordering::Release);
        assert_eq!(
            expired.check(),
            Err(Failure::Activation {
                phase,
                cause: Cause::Cancelled
            })
        );
    }
    let invoked = std::cell::Cell::new(false);
    selected.cancelled.store(true, Ordering::Release);
    assert!(
        selected
            .call(|_| {
                invoked.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!invoked.get());
    let result = budget();
    assert!(
        result
            .call(|_| {
                result.cancelled.store(true, Ordering::Release);
                Ok(())
            })
            .is_err(),
        "late cancellation wins over a successful action"
    );
}

#[test]
fn later_and_equal_height_transactions_do_not_replace_any_original_receipt() {
    let original = ManagedTransactionFinality {
        transaction_hash: HashOf::from_untyped_unchecked(Hash::new(b"original-membership")),
        height: 13,
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"original-membership-block")),
        block_time_ms: 10,
    };
    let sibling = ManagedTransactionFinality {
        transaction_hash: HashOf::from_untyped_unchecked(Hash::new(b"sibling-membership")),
        ..original
    };
    let later = ManagedTransactionFinality {
        transaction_hash: HashOf::from_untyped_unchecked(Hash::new(b"later-membership")),
        height: 14,
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"later-membership-block")),
        block_time_ms: 11,
    };
    assert!(require_original_transactions(&[original, sibling], &[later]).is_err());
    assert!(require_original_transactions(&[original, sibling], &[sibling, later]).is_err());
    assert!(require_original_transactions(&[original, sibling], &[original, later]).is_err());
    require_original_transactions(&[original, sibling], &[original, sibling, later]).unwrap();
    assert!(require_original_transactions(&[original; 33], &[original]).is_err());
    assert!(require_original_transactions(&[original], &[original; 33]).is_err());
}
