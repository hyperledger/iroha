//! Stack bounds and apply/discard semantics for the owned transaction journal.

use super::*;

#[test]
fn state_transaction_keeps_world_journal_off_the_stack() {
    // Ordinary output execution moves this handle through several nested frames.
    // Growing it with every World store previously exhausted a 2 MiB test stack.
    assert!(
        size_of::<StateTransaction<'_, '_>>() <= 32 * 1024,
        "StateTransaction must remain a compact owner, got {} bytes",
        size_of::<StateTransaction<'_, '_>>(),
    );
}

#[test]
fn world_transaction_apply_discard_and_unwind_on_bounded_stack() {
    std::thread::Builder::new()
        .name("world-transaction-stack".into())
        // Pin the ordinary libtest budget even if the caller sets RUST_MIN_STACK.
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let world = World::default();
            let mut block = world.block();
            block.tx_sequences.insert(ALICE_ID.clone(), 7);
            *block.soradns_last_publish_ms.get_mut() = Some(11);
            let initial_catalog = block.dataspace_catalog.clone();
            let changed_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
                description: Some("transaction-local catalog".into()),
                ..DataSpaceMetadata::default()
            }])
            .expect("valid catalog");
            let event = EventBox::Time(TimeEvent::new(
                iroha_data_model::events::time::TimeInterval {
                    since_ms: 11,
                    length_ms: 1,
                },
            ));

            // Both an ordinary discard and unwinding must restore the original
            // map/cell checkpoints and leave the parent event/catalog sinks alone.
            for unwind in [false, true] {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut transaction =
                        block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
                    transaction.tx_sequences.insert(ALICE_ID.clone(), 8);
                    *transaction.soradns_last_publish_ms.get_mut() = Some(12);
                    transaction.dataspace_catalog = changed_catalog.clone();
                    transaction.external_event_buf.push(event.clone());
                    assert!(!unwind, "discard the original journal during unwinding")
                }));
                assert_eq!(result.is_err(), unwind);
                assert_eq!(block.tx_sequences.get(&ALICE_ID), Some(&7));
                assert_eq!(*block.soradns_last_publish_ms.get(), Some(11));
                assert_eq!(block.dataspace_catalog, initial_catalog);
                assert!(block.external_event_buf.is_empty());
            }

            let mut transaction =
                block.transaction_without_telemetry(RuntimeLaneConfig::default(), 0);
            transaction.tx_sequences.insert(ALICE_ID.clone(), 9);
            *transaction.soradns_last_publish_ms.get_mut() = Some(13);
            transaction.dataspace_catalog = changed_catalog.clone();
            transaction.external_event_buf.push(event.clone());
            transaction.apply();
            assert_eq!(block.tx_sequences.get(&ALICE_ID), Some(&9));
            assert_eq!(*block.soradns_last_publish_ms.get(), Some(13));
            assert_eq!(block.dataspace_catalog, changed_catalog);
            assert_eq!(block.external_event_buf, vec![event]);
        })
        .expect("spawn with the ordinary stack budget")
        .join()
        .expect("transaction apply and discard stay within the stack budget");
}
