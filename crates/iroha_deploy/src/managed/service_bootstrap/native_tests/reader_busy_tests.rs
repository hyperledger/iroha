//! The shared native fixture retries the original State-reader release, never a proof verdict.

use super::*;
use iroha_core::state::StateViewError;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn native_snapshot_reader_busy_retries_the_complete_original_certified_cut() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "native-snapshot-reader",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let signed = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "genuine paid native snapshot reader successor".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed]), vec![true]);
    assert_eq!(native.chain.height(), 2);
    let provider = owner.authority.provider_plans().unwrap()[0].provider_id();
    let checkpoint = native.observe(&owner.authority);
    let verified = checkpoint.verified_tip().unwrap();
    let tip = native.chain.committed(native.chain.height());
    let state = native.chain.state();
    let read_budget = AllocationBudget::new(32 * 1024 * 1024);
    let consumed = AtomicUsize::new(0);
    let capture = || {
        state.with_native_stream_token_custody_snapshot_v1(
            &tip,
            provider,
            &read_budget,
            |snapshot, actual_owner, current| {
                // Authenticate the whole real snapshot and its selected original owner.
                // This paid successor has not enrolled the provider; its absence is native.
                let authenticated = snapshot
                    .authenticate(&verified)
                    .map_err(|error| error.to_string())?;
                authenticated
                    .verify_table_value("world.provider_owners", &provider, actual_owner)
                    .map_err(|error| error.to_string())?;
                assert!(current.is_none());
                consumed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
    };
    capture().unwrap();
    assert_eq!(consumed.load(Ordering::SeqCst), 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    let attempts = AtomicUsize::new(0);
    let (observed, original_busy) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        // A World execution overlay does not hold the published State reader.
        // Retain the actual header writer without changing this certified cut.
        let reader = state.with_held_header_for_reader_test(|expected| {
            match capture() {
                Err(WorldStateSnapshotError::View(StateViewError::Busy(actual))) => {
                    assert_eq!(actual, expected);
                }
                result => panic!("the original header writer must refuse State reading: {result:?}"),
            }
            assert_eq!(consumed.load(Ordering::SeqCst), 1);
            assert_eq!(read_budget.reserved_bytes(), 0);
            let attempts = &attempts;
            let capture = &capture;
            let budget = &read_budget;
            let reader = scope.spawn(move || {
                bounded_native_snapshot(budget, deadline, || {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    let result = capture();
                    if attempt == 0 {
                        match &result {
                            Err(WorldStateSnapshotError::View(StateViewError::Busy(actual))) => {
                                assert_eq!(*actual, expected);
                            }
                            result => panic!("the original header reader must remain the retry source: {result:?}"),
                        }
                        observed.send(()).unwrap();
                    }
                    result
                })
            });
            original_busy
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            assert_eq!(consumed.load(Ordering::SeqCst), 1);
            reader
        });
        // The original header guard drops before joining, including if this scope unwinds.
        reader.join().unwrap().unwrap();
    });
    assert!(attempts.load(Ordering::SeqCst) >= 2);
    assert_eq!(consumed.load(Ordering::SeqCst), 2);
    assert_eq!(read_budget.reserved_bytes(), 0);

    // Holding the same physical source through expiry never invokes the consumer or
    // reopens a deadline. Dropping it afterwards permits the complete original proof.
    let mut attempts = 0;
    let result = state.with_held_header_for_reader_test(|expected| {
        bounded_native_snapshot(
            &read_budget,
            Instant::now() + Duration::from_secs(1),
            || {
                attempts += 1;
                let result = capture();
                match &result {
                    Err(WorldStateSnapshotError::View(StateViewError::Busy(actual))) => {
                        assert_eq!(*actual, expected);
                    }
                    result => panic!(
                        "the original header reader must remain busy through expiry: {result:?}"
                    ),
                }
                result
            },
        )
    });
    assert!(matches!(result, Err(crate::managed::Error::NativeDeadline)));
    assert_eq!(attempts, 1);
    assert_eq!(consumed.load(Ordering::SeqCst), 2);
    assert_eq!(read_budget.reserved_bytes(), 0);
    bounded_native_snapshot(
        &read_budget,
        Instant::now() + Duration::from_secs(10),
        capture,
    )
    .unwrap();
    assert_eq!(consumed.load(Ordering::SeqCst), 3);
    assert_eq!(read_budget.reserved_bytes(), 0);
}

#[test]
fn native_snapshot_reader_retry_keeps_changed_poisoned_and_text_only_refusals() {
    let budget = AllocationBudget::new(1024);
    for error in [
        WorldStateSnapshotError::View(StateViewError::Changed),
        WorldStateSnapshotError::View(StateViewError::Poisoned),
        WorldStateSnapshotError::Invalid(
            "World snapshot State view: original State reader is busy".into(),
        ),
    ] {
        let expected = error.to_string();
        let mut original = Some(error);
        let mut attempts = 0;
        let refused: Result<()> =
            bounded_native_snapshot(&budget, Instant::now() + Duration::from_secs(1), || {
                attempts += 1;
                Err(original.take().expect("ordinary refusal cannot retry"))
            });
        assert!(
            matches!(refused, Err(crate::managed::Error::Invalid(message)) if message == expected)
        );
        assert_eq!(attempts, 1);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
