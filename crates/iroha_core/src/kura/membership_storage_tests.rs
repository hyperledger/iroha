//! Real-descriptor controls for finite membership range custody.

use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

use super::*;

fn kura_with_limit(records: u64) -> Arc<Kura> {
    let mut kura = Kura::blank_kura_for_testing();
    Arc::get_mut(&mut kura)
        .expect("original fixture owner")
        .membership_storage = MembershipStorage::new(KuraMembershipStoragePolicy {
        max_bytes: NonZeroU64::new(records * MEMBERSHIP_RECORD_BYTES).expect("nonzero cap"),
        memory_bytes: NonZeroUsize::new(64 * 1024).expect("finite memory"),
    })
    .expect("fund original segment control");
    kura
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn completed_range_retains_original_read_extent_and_releases_only_unwritten_tail() {
    let kura = kura_with_limit(4);
    let physical_before = kura.kura_disk_usage_bytes().expect("physical baseline");
    let mut first = kura
        .reserve_membership_range(3)
        .expect("first original range");
    assert_eq!(first.generation(), NonZeroU64::MIN);
    assert_eq!(
        (
            first.start_offset(),
            first.reserved_end(),
            first.base_readable_end()
        ),
        (0, 552, 0)
    );
    assert_eq!(kura.membership_storage.pending_bytes(), 552);
    let frame = [0x39; 184];
    assert_eq!(
        first
            .write_at(0, &frame[..7])
            .expect("actual partial prefix"),
        7
    );
    assert_eq!(
        first
            .write_at(7, &frame[7..])
            .expect("finish original frame"),
        177
    );
    assert_eq!(first.write_at(184, &[]).expect("zero write"), 0);
    assert!(matches!(
        first.complete(184),
        Err(MembershipStorageError::NotSynced)
    ));
    assert_eq!(kura.membership_storage.pending_bytes(), 368);
    first.sync_data().expect("sync exact original descriptor");
    first.complete(184).expect("release proven unwritten tail");
    first.complete(184).expect("same completion is idempotent");
    assert!(matches!(
        first.complete(0),
        Err(MembershipStorageError::Closed)
    ));
    assert!(matches!(
        first.write_at(0, &frame),
        Err(MembershipStorageError::Closed)
    ));
    assert_eq!(kura.membership_storage.pending_bytes(), 0);
    let mut second = kura
        .reserve_membership_range(1)
        .expect("next original range");
    assert_eq!(
        (second.start_offset(), second.base_readable_end()),
        (184, 184)
    );
    let mut loaded = [0; 184];
    second
        .read_exact(0, &mut loaded)
        .expect("same retained base");
    assert_eq!(loaded, frame);
    assert_eq!(second.write_at(184, &[0x72; 184]).expect("next frame"), 184);
    second.sync_data().expect("sync next frame");
    second.complete(368).expect("complete next range");
    first
        .read_exact(0, &mut loaded)
        .expect("old read lease stays valid");
    assert_eq!(loaded, frame);
    assert!(matches!(
        first.read_exact(184, &mut loaded),
        Err(MembershipStorageError::Bounds)
    ));
    assert_eq!(
        kura.kura_disk_usage_bytes()
            .expect("actual segment included"),
        physical_before + 368
    );
    assert!(kura.physical_resource_path_is_owned(&kura.store_root.join(SEGMENT_NAME)));
    assert!(
        kura.physical_resource_fixed_root_files()
            .contains(&kura.store_root.join(SEGMENT_NAME))
    );
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn range_refusal_preserves_capacity_and_drop_marks_abandoned_without_refund() {
    let kura = kura_with_limit(2);
    assert!(matches!(
        kura.reserve_membership_range(u64::MAX),
        Err(MembershipStorageError::Bounds)
    ));
    assert!(matches!(
        kura.reserve_membership_range(3),
        Err(MembershipStorageError::Capacity { .. })
    ));
    assert!(!kura.store_root.join(SEGMENT_NAME).exists());
    let range = kura
        .reserve_membership_range(2)
        .expect("finite original range");
    assert!(matches!(
        kura.reserve_membership_range(0),
        Err(MembershipStorageError::Busy { .. })
    ));
    assert!(matches!(
        range.write_at(369, &[1]),
        Err(MembershipStorageError::Bounds)
    ));
    assert!(matches!(
        range.write_at(1, &[1]),
        Err(MembershipStorageError::Bounds)
    ));
    assert_eq!(
        range.write_at(0, &[9; 13]).expect("real incomplete write"),
        13
    );
    assert_eq!(kura.membership_storage.pending_bytes(), 368 - 13);
    drop(range);
    assert_eq!(kura.membership_storage.pending_bytes(), 368 - 13);
    assert_eq!(
        std::fs::read(kura.store_root.join(SEGMENT_NAME)).expect("original partial bytes"),
        [9; 13]
    );
    assert!(matches!(
        kura.reserve_membership_range(1),
        Err(MembershipStorageError::Abandoned)
    ));
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn actual_global_disk_budget_counts_pending_and_transferred_segment_bytes_once() {
    let mut kura = kura_with_limit(4);
    let used = kura.kura_disk_usage_bytes().expect("actual baseline");
    Arc::get_mut(&mut kura)
        .expect("original configuration")
        .max_disk_usage_bytes = used + 184;
    assert!(matches!(
        kura.reserve_membership_range(2),
        Err(MembershipStorageError::Kura(
            super::super::Error::StorageBudgetExceeded { .. }
        ))
    ));
    assert_eq!(kura.membership_storage.pending_bytes(), 0);
    assert!(!kura.store_root.join(SEGMENT_NAME).exists());
    let mut range = kura
        .reserve_membership_range(1)
        .expect("exact finite disk fit");
    assert_eq!(kura.membership_storage.pending_bytes(), 184);
    assert_eq!(
        range.write_at(0, &[3; 184]).expect("physical transfer"),
        184
    );
    assert_eq!(kura.membership_storage.pending_bytes(), 0);
    assert_eq!(
        kura.kura_disk_usage_bytes()
            .expect("actual complete file bytes"),
        used + 184
    );
    range.sync_data().expect("sync original");
    range.complete(184).expect("close original");
    assert!(matches!(
        kura.reserve_membership_range(1),
        Err(MembershipStorageError::Kura(
            super::super::Error::StorageBudgetExceeded { .. }
        ))
    ));
    assert_eq!(kura.membership_storage.pending_bytes(), 0);
}

#[test]
fn segment_control_is_exactly_prepaid_and_released_after_its_actual_owner() {
    let layout = Layout::new::<Mutex<SegmentControl>>();
    let policy = KuraMembershipStoragePolicy {
        max_bytes: NonZeroU64::new(184).expect("one record"),
        memory_bytes: NonZeroUsize::new(layout.size()).expect("real control size"),
    };
    let storage = MembershipStorage::new(policy).expect("exact actual allocation fits");
    let pool = storage.budget.clone();
    assert_eq!(pool.reserved_bytes(), layout.size());
    assert!(matches!(
        pool.try_reserve(Layout::new::<u8>()),
        Err(AllocationRefusal::Capacity { .. })
    ));
    drop(storage);
    assert_eq!(pool.reserved_bytes(), 0);
    let rejected = MembershipStorage::new(KuraMembershipStoragePolicy {
        memory_bytes: NonZeroUsize::new(layout.size() - 1).expect("less than control"),
        ..policy
    });
    assert!(matches!(
        rejected,
        Err(MembershipStorageError::Allocation(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn empty_and_partial_existing_segments_require_authenticated_restart_recovery() {
    for bytes in [Vec::new(), vec![0x41; 17], vec![0x52; 184]] {
        let kura = kura_with_limit(4);
        let path = kura.store_root.join(SEGMENT_NAME);
        std::fs::write(&path, &bytes).expect("retained restart residue");
        assert!(matches!(
            kura.reserve_membership_range(1),
            Err(MembershipStorageError::RecoveryRequired)
        ));
        assert_eq!(std::fs::read(&path).expect("same forensic bytes"), bytes);
        assert_eq!(kura.membership_storage.pending_bytes(), 184);
        assert!(matches!(
            kura.reserve_membership_range(1),
            Err(MembershipStorageError::Abandoned)
        ));
    }
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn range_unwind_retains_original_pending_bytes_and_never_reopens_an_attempt() {
    let kura = kura_with_limit(2);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let range = kura.reserve_membership_range(2).expect("original range");
        range
            .write_at(0, &[0x66; 184])
            .expect("first complete frame before unwind");
        panic!("caller unwinds before authenticating and sealing its root");
    }));
    assert!(failure.is_err());
    assert_eq!(kura.membership_storage.pending_bytes(), 184);
    assert_eq!(
        std::fs::read(kura.store_root.join(SEGMENT_NAME)).expect("retained original"),
        [0x66; 184]
    );
    assert!(matches!(
        kura.reserve_membership_range(1),
        Err(MembershipStorageError::Abandoned)
    ));
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn original_descriptor_rejects_substitution_symlinks_and_extra_links() {
    use std::os::unix::fs::symlink;
    for mode in 0..3 {
        let kura = kura_with_limit(2);
        let range = kura
            .reserve_membership_range(2)
            .expect("original bound descriptor");
        range.write_at(0, &[0x28; 184]).expect("original content");
        let path = kura.store_root.join(SEGMENT_NAME);
        let saved = kura.store_root.join("original-membership-forensics");
        if mode == 2 {
            std::fs::hard_link(&path, &saved).expect("foreign extra link");
        } else {
            std::fs::rename(&path, &saved).expect("substitute namespace");
            if mode == 0 {
                std::fs::write(&path, [0x98; 184]).expect("substitute file");
            } else {
                symlink(&saved, &path).expect("substitute symlink");
            }
        }
        let mut frame = [0; 184];
        assert!(matches!(
            range.read_exact(0, &mut frame),
            Err(MembershipStorageError::NamespaceChanged)
        ));
        assert!(matches!(
            range.write_at(184, &[1; 184]),
            Err(MembershipStorageError::NamespaceChanged)
        ));
        assert!(matches!(
            range.sync_data(),
            Err(MembershipStorageError::NamespaceChanged)
        ));
        assert_eq!(
            std::fs::read(&saved).expect("original inode unchanged"),
            [0x28; 184]
        );
        assert_eq!(kura.membership_storage.pending_bytes(), 184);
    }
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn external_length_change_is_not_adopted_as_a_completed_or_free_extent() {
    let kura = kura_with_limit(3);
    let mut range = kura.reserve_membership_range(3).expect("original range");
    range
        .write_at(0, &[0x61; 184])
        .expect("original complete bytes");
    range.sync_data().expect("original sync");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(kura.store_root.join(SEGMENT_NAME))
        .expect("external mutation fixture");
    file.set_len(0).expect("external truncation");
    assert!(matches!(
        range.complete(0),
        Err(MembershipStorageError::NamespaceChanged)
    ));
    assert!(matches!(
        range.write_at(0, &[0x61; 184]),
        Err(MembershipStorageError::NamespaceChanged)
    ));
    assert_eq!(kura.membership_storage.pending_bytes(), 368);
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn post_write_metadata_failure_recovers_only_its_exact_original_pending_request() {
    use super::super::{
        PHYSICAL_RESOURCE_FAMILIES, ResourceFamily, resource_inventory::Unavailable,
    };
    use std::{os::unix::fs::FileExt as _, sync::mpsc, time::Duration};

    for (corrupt, grow) in [(false, false), (true, false), (false, true)] {
        let kura = kura_with_limit(4);
        // Register the actual bounded filesystem observation, not invented counters.
        let generation = kura.resource_inventory.reconciliation_generation().unwrap();
        let observed = kura
            .physical_resource_scope()
            .unwrap()
            .observe(kura.evidence_resource_limits())
            .expect("original physical namespace");
        kura.resource_inventory
            .initialize(
                generation,
                &PHYSICAL_RESOURCE_FAMILIES.map(|family| (family, observed[family as usize])),
            )
            .expect("initialize actual physical families");
        let mut old = kura
            .reserve_membership_range(1)
            .expect("original old range");
        old.write_at(0, &[0x19; 184]).expect("old complete frame");
        old.sync_data().expect("old original sync");
        old.complete(184).expect("old immutable read extent");
        drop(old.take_cleanup().expect("old actual cleanup"));

        let mut range = kura.reserve_membership_range(3).expect("original range");
        let before = kura.kura_disk_usage_bytes().expect("physical baseline");
        let original_counts = kura
            .physical_resource_scope()
            .unwrap()
            .observe(kura.evidence_resource_limits())
            .expect("independent retained base count");
        for family in PHYSICAL_RESOURCE_FAMILIES {
            assert_eq!(
                kura.resource_inventory
                    .component_usage_for_tests(family)
                    .unwrap(),
                original_counts[family as usize],
            );
        }
        if grow {
            EXTEND_MEMBERSHIP_POST_WRITE.with(|fault| fault.set(Some(552)));
        } else {
            FAIL_MEMBERSHIP_POST_WRITE_METADATA.with(|fault| fault.set(true));
        }
        let result = range.write_at(184, &[0x37; 184]);
        assert!(if grow {
            matches!(result, Err(MembershipStorageError::NamespaceChanged))
        } else {
            matches!(result, Err(MembershipStorageError::Io(_)))
        });
        assert!(!FAIL_MEMBERSHIP_POST_WRITE_METADATA.with(std::cell::Cell::get));
        assert_eq!(
            EXTEND_MEMBERSHIP_POST_WRITE.with(std::cell::Cell::get),
            None
        );
        assert!(
            range.pending_disk.borrow().is_some(),
            "retain the actual original physical mutation"
        );
        assert_eq!(
            kura.membership_storage.pending_bytes(),
            552,
            "uncertain transfer remains reserved"
        );
        assert_eq!(
            std::fs::metadata(kura.store_root.join(SEGMENT_NAME))
                .expect("actual write occurred")
                .len(),
            if grow { 552 } else { 368 }
        );
        // The short disk-cache guard must have retired even though the physical
        // inventory mutation remains installed on this original range.
        assert_eq!(
            kura.disk_usage_total_accounting.lock().mutations_in_flight,
            0
        );
        let (send, receive) = mpsc::channel();
        let scanning_kura = Arc::clone(&kura);
        let scan = std::thread::spawn(move || {
            send.send(scanning_kura.refresh_disk_usage_bytes()).unwrap();
        });
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(30))
                .expect("actual disk scan must finish during owned uncertainty")
                .expect("scan counts actual materialized bytes"),
            before + if grow { 368 } else { 184 },
        );
        scan.join().expect("disk scanner completed");
        for family in PHYSICAL_RESOURCE_FAMILIES {
            assert_eq!(
                kura.resource_inventory.component_usage_for_tests(family),
                Err(Unavailable::Busy),
                "a disk scan must not publish the retained physical mutation",
            );
        }
        let mut old_bytes = [0; 184];
        old.read_exact(0, &mut old_bytes)
            .expect("old completed read lease survives another range's uncertain tail");
        assert_eq!(old_bytes, [0x19; 184]);
        assert!(range.pending_disk.borrow().is_some());
        assert_eq!(kura.membership_storage.pending_bytes(), 552);

        if corrupt || grow {
            if corrupt {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(kura.store_root.join(SEGMENT_NAME))
                    .expect("foreign writer")
                    .write_all_at(&[0x99; 184], 184)
                    .expect("foreign pending prefix only");
            }
            let rejected_bytes = std::fs::read(kura.store_root.join(SEGMENT_NAME))
                .expect("retain exact untrusted suffix for refusal assertions");
            assert!(matches!(
                range.write_at(184, &[0x37; 184]),
                Err(MembershipStorageError::NamespaceChanged)
            ));
            assert!(range.pending_disk.borrow().is_some());
            assert_eq!(kura.membership_storage.pending_bytes(), 552);
            assert!(matches!(
                range.sync_data(),
                Err(MembershipStorageError::NamespaceChanged)
            ));
            assert!(matches!(
                range.complete(552),
                Err(MembershipStorageError::NamespaceChanged)
            ));
            assert_eq!(
                std::fs::read(kura.store_root.join(SEGMENT_NAME)).unwrap(),
                rejected_bytes
            );
            assert_eq!(kura.membership_storage.control.lock().physical_len, 184);
            old.read_exact(0, &mut old_bytes)
                .expect("foreign tail cannot revoke original base read extent");
            assert_eq!(old_bytes, [0x19; 184]);
            for family in PHYSICAL_RESOURCE_FAMILIES {
                assert_eq!(
                    kura.resource_inventory.component_usage_for_tests(family),
                    Err(Unavailable::Busy)
                );
            }
        } else {
            // A read retry resolves only the same installed descriptor/request.
            let mut bytes = [0; 184];
            range
                .read_exact(184, &mut bytes)
                .expect("same descriptor/request recovery");
            assert_eq!(bytes, [0x37; 184]);
            assert!(range.pending_disk.borrow().is_none());
            assert_eq!(kura.membership_storage.pending_bytes(), 368);
            let recovered = kura
                .physical_resource_scope()
                .unwrap()
                .observe(kura.evidence_resource_limits())
                .expect("independent physical recount");
            for family in PHYSICAL_RESOURCE_FAMILIES {
                assert_eq!(
                    kura.resource_inventory
                        .component_usage_for_tests(family)
                        .unwrap(),
                    recovered[family as usize]
                );
                let mut expected = original_counts[family as usize];
                if family == ResourceFamily::StorageBytes {
                    expected.storage_bytes += 184;
                }
                assert_eq!(
                    recovered[family as usize], expected,
                    "exact single original delta for {family:?}"
                );
            }
            assert_eq!(
                kura.refresh_disk_usage_bytes()
                    .expect("recount cannot double-charge recovered bytes"),
                before + 184
            );
            assert_eq!(
                range
                    .write_at(184, &[0x37; 184])
                    .expect("same offset retry"),
                184
            );
            range.sync_data().expect("sync recovered original");
            range.complete(368).expect("seal recovered original");
            assert_eq!(
                kura.kura_disk_usage_bytes()
                    .expect("exact actual transferred bytes"),
                before + 184
            );
            for family in PHYSICAL_RESOURCE_FAMILIES {
                assert_eq!(
                    kura.resource_inventory
                        .component_usage_for_tests(family)
                        .unwrap(),
                    recovered[family as usize]
                );
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "espidf")))]
#[test]
fn original_range_wait_tracks_completion_and_abandonment_after_outer_cleanup() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    struct Probe {
        kura: Arc<Kura>,
        calls: AtomicUsize,
        locked: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.kura.prune_lock.try_lock().is_none()
                || self.kura.canonical_chain_lock.try_lock().is_none()
            {
                self.locked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    for abandon in [false, true] {
        let kura = kura_with_limit(2);
        let mut registration =
            crate::unit_test_support::release_registration(&kura.transaction_history_budget());
        let mut range = kura.reserve_membership_range(1).expect("original range");
        let wait = match kura
            .reserve_membership_range(1)
            .expect_err("real contention")
        {
            MembershipStorageError::Busy { release } => release,
            error => panic!("unexpected {error}"),
        };
        let foreign = kura_with_limit(1);
        let foreign_range = foreign.reserve_membership_range(1).expect("foreign owner");
        let foreign_wait = match foreign
            .reserve_membership_range(1)
            .expect_err("foreign busy")
        {
            MembershipStorageError::Busy { release } => release,
            error => panic!("unexpected {error}"),
        };
        assert_ne!(wait, foreign_wait);
        drop(foreign_range);
        let probe = Arc::new(Probe {
            kura: Arc::clone(&kura),
            calls: AtomicUsize::new(0),
            locked: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        assert_eq!(
            registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
            Poll::Pending
        );
        if abandon {
            // The enclosing owner drops physical guards before the retained range.
            let outer = kura.canonical_chain_lock.lock();
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            drop(outer);
            drop(range);
            assert!(matches!(
                kura.reserve_membership_range(1),
                Err(MembershipStorageError::Abandoned)
            ));
        } else {
            range.sync_data().expect("sync empty original");
            range.complete(0).expect("complete actual owner");
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            let release = range.take_cleanup().expect("original deferred completion");
            assert!(range.take_cleanup().is_none());
            let outer = kura.canonical_chain_lock.lock();
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            drop(outer);
            drop(release);
            drop(range);
        }
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.locked.load(Ordering::SeqCst), 0);
        assert_eq!(
            registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
            Poll::Ready(())
        );
        registration.cancel();
        // No polling registration was needed to observe this actual earlier release.
        assert_eq!(
            registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
            Poll::Ready(())
        );
        let budget = kura.transaction_history_budget();
        let reserved = budget.reserved_bytes();
        let bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
        assert!(registration.belongs_to(&budget));
        assert!(
            reserved >= bytes,
            "completed registration retains its physical charge"
        );
        drop(registration);
        assert_eq!(budget.reserved_bytes(), reserved - bytes);
    }
}

#[cfg(not(all(unix, not(target_os = "espidf"))))]
#[test]
fn unsupported_descriptor_platform_refuses_without_an_alternate_file_path() {
    let kura = kura_with_limit(1);
    assert!(matches!(
        kura.reserve_membership_range(1),
        Err(MembershipStorageError::Unsupported)
    ));
    assert!(!kura.store_root.join(SEGMENT_NAME).exists());
}
