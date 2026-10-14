// Remaining live writer boundaries: exact files, rollback images and independent recounts.

#[test]
fn physical_debug_dump_counts_each_actual_append_including_identical_lines() {
    let directory = TempDir::new().unwrap();
    let mut config = kura_config_for_dir(&directory, BLOCKS_IN_MEMORY);
    config.debug_output_new_blocks = true;
    let (kura, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .unwrap();
    let path = kura.block_plain_text_path.lock().clone().unwrap();
    let before = metadata_physical_register(&kura);
    let block = NativeBlocks::new().next();
    let (mut prune_releases, mut canonical_releases, mut geometry_releases, mut sidecar_releases) = (
        kura.prune_lock.defer_notifications(),
        kura.canonical_chain_lock.defer_notifications(),
        kura.lane_geometry_lock.defer_notifications(),
        kura.sidecar_lock.defer_notifications(),
    );
    let _prune = prune_releases.lock();
    let _canonical = canonical_releases.lock();
    kura.append_debug_block_dump(&block, &mut geometry_releases, &mut sidecar_releases);
    let once = metadata_physical_assert_actual(&kura);
    let line = fs::read(&path).unwrap();
    assert!(!line.is_empty());
    assert_eq!(
        once[ResourceFamily::StorageBytes as usize].storage_bytes
            - before[ResourceFamily::StorageBytes as usize].storage_bytes,
        line.len() as u64
    );
    kura.append_debug_block_dump(&block, &mut geometry_releases, &mut sidecar_releases);
    let twice = metadata_physical_assert_actual(&kura);
    assert_eq!(
        twice[ResourceFamily::StorageBytes as usize].storage_bytes
            - once[ResourceFamily::StorageBytes as usize].storage_bytes,
        line.len() as u64
    );
    assert_eq!(fs::read(&path).unwrap(), [line.clone(), line].concat());
}

mod original_durable_release_tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::AtomicUsize,
        task::{Context, Wake, Waker},
    };

    struct Probe {
        kura: Arc<Kura>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
        reentered: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let physical_free = self
                .kura
                .publication_fences_for_test()
                .iter()
                .all(|(_, lock)| lock.try_lock().is_some());
            let writer_free = self.kura.block_store_write_lock.try_lock().is_some();
            let store_free = self.kura.block_store.try_lock().is_some();
            let data_free = self.kura.block_data.try_lock().is_some();
            let path_free = self.kura.block_plain_text_path.try_lock().is_some();
            if physical_free && writer_free && store_free && data_free && path_free {
                let result = self.kura.try_publication_lease();
                if matches!(result, Err(KuraPublicationPreparationError::Busy { .. })) {
                    self.blocked.fetch_add(1, Ordering::SeqCst);
                } else {
                    self.reentered.fetch_add(1, Ordering::SeqCst);
                }
                drop(result);
            } else {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn observe_original_release<T>(
        kura: &Arc<Kura>,
        fence: usize,
        operation: impl FnOnce() -> T,
    ) -> T {
        let budget = kura.transaction_history_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let original = kura.publication_fences_for_test()[fence]
            .1
            .observe_release();
        let mut wait = original.wait_for_release(&mut registration);
        let probe = Arc::new(Probe {
            kura: Arc::clone(kura),
            calls: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
            reentered: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let unrelated = Kura::blank_kura_for_testing();
        drop(unrelated.canonical_chain_lock.lock());
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "foreign store release"
        );
        let result = operation();
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            1,
            "one original physical release"
        );
        assert_eq!(
            probe.blocked.load(Ordering::SeqCst),
            0,
            "original durable publication notice must wait for every storage fence"
        );
        assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(wait);
        assert!(registration.belongs_to(&budget));
        let reserved = budget.reserved_bytes();
        let charge = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
        assert!(reserved >= charge);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), reserved - charge);
        result
    }

    fn fixture(debug: bool) -> (TempDir, Arc<Kura>) {
        let directory = TempDir::new().unwrap();
        let mut config = kura_config_for_dir(&directory, BLOCKS_IN_MEMORY);
        config.debug_output_new_blocks = debug;
        let (kura, _) = Kura::open_test_kura_with_configured_lane_config(
            &config,
            &RuntimeLaneConfig::default(),
        )
        .unwrap();
        (directory, kura)
    }

    #[test]
    fn original_durable_append_notifies_after_every_storage_fence() {
        let (_directory, kura) = fixture(false);
        let block = NativeBlocks::new().next();
        let wire = block.encode_wire().unwrap();
        observe_original_release(&kura, 1, || kura.store_block(block)).unwrap();
        assert_eq!(kura.exact_durable_blocks_count().unwrap(), 1);
        assert_eq!(
            kura.canonical_block_wire_bytes_for_testing(nonzero!(1_usize))
                .unwrap(),
            wire
        );
    }

    #[test]
    fn original_durable_retry_notifies_after_every_storage_fence() {
        let (_directory, kura) = fixture(false);
        let block = NativeBlocks::new().next();
        let wire = block.encode_wire().unwrap();
        kura.store_block(block.clone()).unwrap();
        let before = metadata_physical_register(&kura);
        observe_original_release(&kura, 1, || kura.store_block(block)).unwrap();
        assert_eq!(kura.exact_durable_blocks_count().unwrap(), 1);
        assert_eq!(
            kura.canonical_block_wire_bytes_for_testing(nonzero!(1_usize))
                .unwrap(),
            wire
        );
        assert_eq!(metadata_physical_assert_actual(&kura), before);
    }

    #[test]
    fn original_durable_refusal_notifies_after_every_storage_fence() {
        let (_directory, kura) = fixture(false);
        let mut blocks = NativeBlocks::new();
        let _genesis = blocks.next();
        let successor = blocks.next();
        let before = metadata_physical_register(&kura);
        let result = observe_original_release(&kura, 1, || kura.store_block(successor));
        assert!(matches!(
            result,
            Err(Error::BlockHeightGap {
                expected_next_height: 1,
                actual_height: 2
            })
        ));
        assert_eq!(kura.exact_durable_blocks_count().unwrap(), 0);
        assert_eq!(metadata_physical_assert_actual(&kura), before);
    }

    #[test]
    fn original_durable_debug_append_notifies_after_outer_writer_retires() {
        let (_directory, kura) = fixture(true);
        metadata_physical_register(&kura);
        let block = NativeBlocks::new().next();
        let path = kura.block_plain_text_path.lock().clone().unwrap();
        let mut expected = norito::json::to_vec(block.as_ref()).unwrap();
        expected.push(b'\n');
        observe_original_release(&kura, 3, || kura.store_block(block)).unwrap();
        assert_eq!(fs::read(path).unwrap(), expected);
        assert_eq!(kura.exact_durable_blocks_count().unwrap(), 1);
        metadata_physical_assert_actual(&kura);
    }
}
