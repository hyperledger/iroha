//! Genuine Finish-local wallet reuse retains fresh callbacks, custody and decoder refusal.

use super::*;
use crate::managed::stream_token_custody::tests::count_wallet_constructions;
use iroha_wallet::operations::{NativePreparationPhase, VerifiedNativePreparation};
use std::{cell::Cell, rc::Rc};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ReaderWork {
    constructed: usize,
    reused: usize,
}
thread_local! {
    static READER_WORK: Cell<Option<ReaderWork>> = const { Cell::new(None) };
}

// Observe actual reader selection only; this cannot supply a wallet result or bypass I/O.
pub(super) fn reader_used(created: bool) {
    READER_WORK.with(|state| {
        if let Some(mut work) = state.get() {
            work.constructed += usize::from(created);
            work.reused += usize::from(!created);
            state.set(Some(work));
        }
    });
}

fn count_readers<T>(read: impl FnOnce() -> T) -> (T, ReaderWork) {
    struct Restore(Option<ReaderWork>);
    impl Drop for Restore {
        fn drop(&mut self) {
            READER_WORK.with(|state| state.set(self.0));
        }
    }
    let _restore = Restore(READER_WORK.with(|state| state.replace(Some(ReaderWork::default()))));
    let result = read();
    (result, READER_WORK.with(|state| state.get().unwrap()))
}

fn same_history(actual: &BodyHistory, original: &BodyHistory) {
    assert_eq!(
        actual.selection.digest().unwrap(),
        original.selection.digest().unwrap()
    );
    assert!(same(&actual.anchor, &original.anchor, MAX_BODY_BYTES).unwrap());
    assert!(Arc::ptr_eq(&actual.root, &original.root));
    assert_eq!(actual.bodies.len(), original.bodies.len());
    for (actual, original) in actual.bodies.iter().zip(&original.bodies) {
        assert_eq!(actual.semantic, original.semantic);
        assert_eq!(
            actual.reservation.digest().unwrap(),
            original.reservation.digest().unwrap()
        );
        assert!(Arc::ptr_eq(&actual.directory, &original.directory));
    }
    assert_eq!(
        actual
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        original
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
    );
    actual.revalidate_handles().unwrap();
}

fn inspection(
    value: Result<VerifiedNativePreparation>,
) -> std::result::Result<(NativePreparationPhase, String), String> {
    value
        .map(|value| {
            assert!(value.signed_transaction().is_none());
            assert!(value.unprepared_status().is_none());
            (value.phase(), value.request_sha256().unwrap().to_owned())
        })
        .map_err(|error| error.to_string())
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn finish_wallet_reparses_reuse_readers_and_keep_every_actual_callback() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let callbacks = Rc::new(Cell::new([0usize; 3]));
    let observe = || {
        let callbacks = Rc::clone(&callbacks);
        move |point| {
            if let parser_handle_tests::Point::WalletInspected(index) = point {
                let mut values = callbacks.get();
                values[index] += 1;
                callbacks.set(values);
            }
            Ok(())
        }
    };
    let ((), original_accounts) = count_wallet_constructions(|| {
        parser_handle_tests::with_hook(observe(), || {
            for _ in 0..4 {
                same_history(&history.read_current(&fixture.owner).unwrap(), &history);
            }
        })
    });
    assert_eq!(original_accounts, 4);
    assert_eq!(callbacks.replace([0; 3]), [8, 8, 0]);

    let account = FinishWalletAccount::new(&fixture.owner, Arc::clone(&history.root));
    let mut readers = FinishWalletReads::new(&account);
    let (((), accounts), work) = count_readers(|| {
        count_wallet_constructions(|| {
            parser_handle_tests::with_hook(observe(), || {
                for _ in 0..4 {
                    let actual = history
                        .read_current_with_wallets(&fixture.owner, Some(&mut readers))
                        .unwrap();
                    same_history(&actual, &history);
                }
            })
        })
    });
    assert_eq!(accounts, 1, "one lazy immutable account within this Finish");
    assert_eq!(callbacks.replace([0; 3]), [8, 8, 0]);
    assert_eq!(
        work,
        ReaderWork {
            constructed: 2,
            reused: 14
        }
    );
    // A fresh Finish owns fresh readers; the retained object itself never owns this reuse.
    drop(readers);
    let account = FinishWalletAccount::new(&fixture.owner, Arc::clone(&history.root));
    let mut readers = FinishWalletReads::new(&account);
    let (actual, work) =
        count_readers(|| history.read_current_with_wallets(&fixture.owner, Some(&mut readers)));
    same_history(&actual.unwrap(), &history);
    assert_eq!(
        work,
        ReaderWork {
            constructed: 2,
            reused: 2
        }
    );
    // A later canonical source fence must discard every reader, even if its own
    // wallet observation already succeeded. Preserve and restore the original bytes.
    let changed = Rc::new(Cell::new(false));
    let observed = Rc::clone(&changed);
    let directory = Arc::clone(&history.bodies[0].directory);
    let original = directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let mut replacement = original.clone();
    replacement[0] ^= 1;
    let failed = parser_handle_tests::with_hook(
        move |point| {
            if point == parser_handle_tests::Point::WalletInspected(0) && !observed.replace(true) {
                directory.write_atomic("original.nrt", &replacement, PublishMode::Replace)?;
            }
            Ok(())
        },
        || history.read_current_with_wallets(&fixture.owner, Some(&mut readers)),
    );
    history.bodies[0]
        .directory
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert!(
        changed.get(),
        "mutation follows a genuine successful wallet callback"
    );
    assert!(
        failed.is_err(),
        "the canonical retained-source exit must refuse"
    );
    let (restored, work) =
        count_readers(|| history.read_current_with_wallets(&fixture.owner, Some(&mut readers)));
    same_history(&restored.unwrap(), &history);
    assert_eq!(
        work,
        ReaderWork {
            constructed: 2,
            reused: 2
        },
        "source refusal clears both body readers"
    );
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn finish_wallet_reuse_refuses_changed_records_locks_and_foreign_owners() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let predecessor = history
        .current_history()
        .unwrap()
        .test_owned_predecessor_closure_history()
        .unwrap();
    let attempt = predecessor.last().unwrap();
    let body = &history.bodies[1];
    let original = body.original.as_ref().unwrap();
    let ordinal = body.reservation.ordinal;
    let account = FinishWalletAccount::new(&fixture.owner, Arc::clone(&history.root));
    let mut readers = FinishWalletReads::new(&account);
    let inspect = |readers: &mut FinishWalletReads<'_>| {
        inspection(readers.inspect(&fixture.owner, &history.root, ordinal, original, attempt))
    };
    let expected = inspect(&mut readers);
    assert_eq!(
        expected.as_ref().unwrap().0,
        NativePreparationPhase::Retired
    );
    let path = attempt.directory().path().join("transaction");
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    let baseline_account = fixture.owner.wallet().unwrap();
    let ordinary = || {
        inspection(
            original
                .request(
                    attempt.terms(),
                    attempt.observation().unwrap(),
                    Instant::now(),
                )
                .unwrap()
                .inspect_in_parent(&baseline_account, attempt.directory()),
        )
    };
    assert_eq!(ordinary(), expected);
    // The caller's expected request is fresh even when actual journal bytes match.
    let mut changed_request = original.clone();
    changed_request.selection.expected_revision = changed_request
        .selection
        .expected_revision
        .checked_add(1)
        .unwrap();
    let changed_baseline = inspection(
        changed_request
            .request(
                attempt.terms(),
                attempt.observation().unwrap(),
                Instant::now(),
            )
            .unwrap()
            .inspect_in_parent(&baseline_account, attempt.directory()),
    );
    assert!(changed_baseline.is_err());
    assert_eq!(
        inspection(readers.inspect(
            &fixture.owner,
            &history.root,
            ordinal,
            &changed_request,
            attempt
        )),
        changed_baseline
    );
    let (restored, work) = count_readers(|| inspect(&mut readers));
    assert_eq!(restored, expected);
    assert_eq!(
        work,
        ReaderWork {
            constructed: 1,
            reused: 0
        }
    );

    for name in ["preparation.json", "retired.json"] {
        assert_eq!(inspect(&mut readers), expected);
        let bytes = std::fs::read(path.join(name)).unwrap();
        directory
            .write_atomic(name, b"{", PublishMode::Replace)
            .unwrap();
        let baseline = ordinary();
        assert!(baseline.is_err());
        assert_eq!(inspect(&mut readers), baseline);
        assert_eq!(std::fs::read(path.join(name)).unwrap(), b"{");
        directory
            .write_atomic(name, &bytes, PublishMode::Replace)
            .unwrap();
        assert_eq!(inspect(&mut readers), expected);
        assert_eq!(std::fs::read(path.join(name)).unwrap(), bytes);
    }
    // The previous successful observation retained no journal handle or native lock.
    let held = iroha_operation_journal::Journal::open(&path).unwrap();
    assert!(ordinary().is_err());
    assert!(inspect(&mut readers).is_err());
    drop(held);
    assert_eq!(inspect(&mut readers), expected);

    let other_root = fixture
        .owner
        .authority
        .directory
        .open_child("configure")
        .unwrap();
    assert!(
        readers
            .inspect(&fixture.owner, &other_root, ordinal, original, attempt)
            .is_err()
    );
    let foreign = ManagedStreamTokenCustody::open(
        &fixture.prepared,
        crate::managed::native_operation::test_support::provider_id(&fixture.prepared, 1),
    )
    .unwrap();
    assert!(
        readers
            .inspect(&foreign, &history.root, ordinal, original, attempt)
            .is_err()
    );
    // Even a separately constructed account owner cannot borrow the original reader set.
    let foreign_account = FinishWalletAccount::new(&foreign, Arc::clone(&history.root));
    let mut foreign_readers = FinishWalletReads::new(&foreign_account);
    assert!(
        foreign_readers
            .inspect(&fixture.owner, &history.root, ordinal, original, attempt)
            .is_err()
    );
    assert_eq!(inspect(&mut readers), expected);
    same_history(&history.read_current(&fixture.owner).unwrap(), &history);
    for name in ["payload.json", "operation.json", "submission.json"] {
        assert!(!path.join(name).exists());
    }
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn finish_wallet_inherited_and_late_decoders_keep_the_original_physical_recipe() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, history) = shared_snapshot_tests::history_with_bodies(3);
    let predecessor = history
        .current_history()
        .unwrap()
        .test_owned_predecessor_closure_history()
        .unwrap();
    let attempt = predecessor.last().unwrap();
    let body = &history.bodies[1];
    let original = body.original.as_ref().unwrap();
    let ordinal = body.reservation.ordinal;
    let baseline_account = fixture.owner.wallet().unwrap();
    let expected = inspection(
        original
            .request(
                attempt.terms(),
                attempt.observation().unwrap(),
                Instant::now(),
            )
            .unwrap()
            .inspect_in_parent(&baseline_account, attempt.directory()),
    );
    assert_eq!(
        expected.as_ref().unwrap().0,
        NativePreparationPhase::Retired
    );
    for warm in [false, true] {
        for capacity in [0, 1, 256 * 1024 * 1024] {
            let account = FinishWalletAccount::new(&fixture.owner, Arc::clone(&history.root));
            let mut readers = FinishWalletReads::new(&account);
            if warm {
                assert_eq!(
                    inspection(readers.inspect(
                        &fixture.owner,
                        &history.root,
                        ordinal,
                        original,
                        attempt
                    )),
                    expected
                );
            }
            let (ordinary, ordinary_usage) =
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    inspection((|| {
                        original
                            .request(attempt.terms(), attempt.observation()?, Instant::now())?
                            .inspect_in_parent(&baseline_account, attempt.directory())
                    })())
                });
            let ((actual, usage), work) = count_readers(|| {
                norito::core::with_decode_limits_measured(limits(capacity), || {
                    inspection(readers.inspect(
                        &fixture.owner,
                        &history.root,
                        ordinal,
                        original,
                        attempt,
                    ))
                })
            });
            assert_eq!(actual, ordinary);
            assert_eq!(
                work,
                ReaderWork::default(),
                "inherited owner bypasses retained readers"
            );
            if capacity <= 1 {
                assert!(actual.is_err());
                assert_eq!(usage, ordinary_usage);
            } else {
                assert_eq!(actual, expected);
                assert!(
                    usage.total_allocated_bytes() > 1 && usage.total_allocated_bytes() <= capacity
                );
                assert!(
                    ordinary_usage.total_allocated_bytes() > 1
                        && ordinary_usage.total_allocated_bytes() <= capacity
                );
            }
            // A decoder installed after priming cannot leave an eligible old reader behind.
            let (again, work) = count_readers(|| {
                inspection(readers.inspect(
                    &fixture.owner,
                    &history.root,
                    ordinal,
                    original,
                    attempt,
                ))
            });
            assert_eq!(again, expected);
            assert_eq!(
                work,
                ReaderWork {
                    constructed: 1,
                    reused: 0
                }
            );
        }
    }
    // The full canonical reparse also bypasses reuse when the owner is inherited at entry.
    let account = FinishWalletAccount::new(&fixture.owner, Arc::clone(&history.root));
    let mut readers = FinishWalletReads::new(&account);
    history
        .read_current_with_wallets(&fixture.owner, Some(&mut readers))
        .unwrap();
    for capacity in [0, 1, 256 * 1024 * 1024] {
        let (ordinary, ordinary_usage) =
            norito::core::with_decode_limits_measured(limits(capacity), || {
                history.read_current(&fixture.owner)
            });
        let ((actual, usage), work) = count_readers(|| {
            norito::core::with_decode_limits_measured(limits(capacity), || {
                history.read_current_with_wallets(&fixture.owner, Some(&mut readers))
            })
        });
        assert_eq!(work, ReaderWork::default());
        if capacity <= 1 {
            assert!(ordinary.is_err() && actual.is_err());
        } else {
            assert!(
                ordinary.is_ok() && actual.is_ok(),
                "ample inherited owner must parse the genuine history"
            );
        }
        match (ordinary, actual) {
            (Ok(ordinary), Ok(actual)) => {
                same_history(&ordinary, &history);
                same_history(&actual, &history);
            }
            (Err(ordinary), Err(actual)) => assert_eq!(ordinary.to_string(), actual.to_string()),
            _ => panic!("inherited canonical parser outcome changed"),
        }
        assert_eq!(usage, ordinary_usage);
    }
    assert_eq!(fixture.native.chain.height(), 4);
}
