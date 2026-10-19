// Exact original raw destination and current logical-scope continuation controls.
use super::*;
use crate::{
    execution_attempt::{ExecutionAttemptError, kura_read_attempt_error},
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_allocation::{AllocationBudget, ChargedBufferFromChargeError};
use std::alloc::Layout;

fn fixture(evicted: bool) -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    if evicted {
        let wire = chain.committed(2).block().encode_wire().unwrap();
        let mut store = chain.kura().block_store.lock();
        store.write_da_block_bytes(2, &wire).unwrap();
        store
            .write_block_index(1, EVICTED_BLOCK_START, wire.len() as u64)
            .unwrap();
        store.publish_commit_marker(2).unwrap();
    }
    chain
}

// Exercise the two actual production handle forms through their one storage kernel.
enum Original<'a> {
    Borrowed(NativeFrameRead<'a>),
    Owned(OwnedNativeFrameRead),
}
impl<'a> Original<'a> {
    fn new(chain: &'a CertifiedTestChain, owned: bool) -> Self {
        let hash = chain.committed(2).block_hash();
        if owned {
            Self::Owned(
                chain
                    .kura()
                    .native_frame_read_owned(2, hash)
                    .unwrap()
                    .unwrap(),
            )
        } else {
            Self::Borrowed(chain.kura().native_frame_read(2, hash).unwrap().unwrap())
        }
    }
    fn binding(&self) -> &NativeFrameBinding {
        match self {
            Self::Borrowed(s) => &s.binding,
            Self::Owned(s) => &s.binding,
        }
    }
    fn read(&mut self, pool: &AllocationBudget) -> Result<Option<NativeFrameBytes>> {
        match self {
            Self::Borrowed(s) => s.read_original(s.wire_len(), pool),
            Self::Owned(s) => s.read_original(s.wire_len(), pool),
        }
    }
}

#[test]
fn original_raw_frame_physical_refusal_retains_charge_and_retries_without_credit() {
    for evicted in [false, true] {
        for owned in [false, true] {
            let chain = fixture(evicted);
            let wire = chain.committed(2).block().encode_wire().unwrap();
            let layout = Layout::array::<u8>(wire.len()).unwrap();
            let pool = AllocationBudget::new(layout.size());
            let mut source = Original::new(&chain, owned);
            for _ in 0..2 {
                let (result, denied) = refuse_one_layout_during(layout, || source.read(&pool));
                assert!(denied, "actual destination allocator must refuse");
                let error = result.unwrap_err();
                assert!(
                    matches!(&error, Error::NativeFrameConstruction(ChargedBufferFromChargeError::Allocator { layout: original }) if *original == layout)
                );
                assert_eq!(
                    pool.reserved_bytes(),
                    layout.size(),
                    "raw-frame refusal must retain the exact original backing charge"
                );
                let destination = source.binding().destination.as_ref().unwrap();
                assert!(destination.charge.is_some() && destination.bytes.is_none());
                assert!(destination.budget.same_pool(&pool));
                assert_eq!(destination.length, Some(wire.len()));
                let mut transported = None;
                assert_eq!(
                    allocations_during(|| {
                        transported = Some(kura_read_attempt_error(error, |original| original));
                    }),
                    0
                );
                let ExecutionAttemptError::Deferred(original) = transported.unwrap() else {
                    panic!("original physical constructor refusal must remain retryable");
                };
                assert_eq!(
                    original
                        .allocator_refusal()
                        .unwrap()
                        .buffer_from_charge_error(),
                    Some(&ChargedBufferFromChargeError::Allocator { layout })
                );
                assert!(original.allocation_refusal().is_none());
            }
            let foreign = AllocationBudget::new(layout.size());
            assert!(matches!(
                source.read(&foreign),
                Err(Error::CanonicalBlockWireMismatch { height: 2 })
            ));
            assert_eq!(foreign.reserved_bytes(), 0);
            assert_eq!(pool.reserved_bytes(), layout.size());
            let bytes = source.read(&pool).unwrap().unwrap();
            assert_eq!(bytes.as_slice(), wire);
            assert!(bytes.belongs_to(&pool));
            assert!(
                source
                    .binding()
                    .destination
                    .as_ref()
                    .unwrap()
                    .charge
                    .is_none()
            );
            assert!(
                source
                    .binding()
                    .destination
                    .as_ref()
                    .unwrap()
                    .bytes
                    .is_none()
            );
            // Delivery transfers the same credit. A second independent read has no free backing.
            assert!(matches!(
                source.read(&pool),
                Err(Error::NativeFrameAllocation(
                    iroha_allocation::ChargedBufferError::Admission(
                        iroha_allocation::AllocationRefusal::Capacity { .. }
                    )
                ))
            ));
            assert_eq!(pool.reserved_bytes(), layout.size());
            drop(bytes);
            assert_eq!(pool.reserved_bytes(), 0);
            assert_eq!(source.read(&pool).unwrap().unwrap().as_slice(), wire);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn original_raw_frame_retry_refuses_replaced_sidecar_before_backing_allocation() {
    for owned in [false, true] {
        let chain = fixture(true);
        let wire = chain.committed(2).block().encode_wire().unwrap();
        let layout = Layout::array::<u8>(wire.len()).unwrap();
        let pool = AllocationBudget::new(wire.len());
        let mut source = Original::new(&chain, owned);
        let (first, denied) = refuse_one_layout_during(layout, || source.read(&pool));
        assert!(denied && matches!(first, Err(Error::NativeFrameConstruction(_))));
        assert_eq!(pool.reserved_bytes(), wire.len());
        assert!(source.binding().sidecar.is_some());
        let path = chain.kura().block_store.lock().da_block_path(2);
        let retained = path.with_extension("original-test-image");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, &wire).unwrap();
        // The replacement has identical wire bytes and length, but a different original inode.
        let (result, allocated) = refuse_one_layout_during(layout, || source.read(&pool));
        assert!(
            matches!(&result, Err(Error::IO(error, actual))
            if error.kind() == ErrorKind::InvalidData
                && error.to_string() == "sidecar differs from its original admitted image"
                && actual == &path),
            "raw-frame retry must reject the original sidecar image substitution before body allocation"
        );
        assert!(!allocated);
        assert_eq!(pool.reserved_bytes(), wire.len());
        assert!(
            source
                .binding()
                .destination
                .as_ref()
                .unwrap()
                .bytes
                .is_none()
        );
        let original_error = result.unwrap_err();
        assert!(matches!(
            kura_read_attempt_error(original_error, |original| original),
            ExecutionAttemptError::Rejected(Error::IO(..))
        ));
        // Restore the original inode. Rename changes ctime on some platforms, so this
        // operation may remain permanently rejected; it cannot invent a fresh receipt.
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&retained, &path).unwrap();
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn original_raw_frame_narrower_scope_replay_retains_physical_charge_and_source() {
    const PROBE: usize = 16 * 1024 * 1024;
    for evicted in [false, true] {
        for owned in [false, true] {
            let chain = fixture(evicted);
            let wire = chain.committed(2).block().encode_wire().unwrap();
            let layout = Layout::array::<u8>(wire.len()).unwrap();
            let pool = AllocationBudget::new(wire.len());
            let mut source = Original::new(&chain, owned);
            let wide = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, PROBE, 64);
            // Measure actual original metadata plus frame admission at the physical refusal.
            let spent = norito::with_decode_limits_scope(wide, || {
                let (result, denied) = refuse_one_layout_during(layout, || source.read(&pool));
                assert!(denied && matches!(result, Err(Error::NativeFrameConstruction(_))));
                let norito::Error::TotalAllocationExceeded { attempted, limit } =
                    norito::core::reserve_decode_allocation(PROBE).unwrap_err()
                else {
                    panic!("probe must observe actual cumulative logical consumption");
                };
                usize::try_from(attempted - limit).unwrap()
            });
            assert!(spent >= wire.len());
            let narrow =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, spent - 1, 64);
            norito::with_decode_limits_scope(narrow, || {
                let (result, allocated) = refuse_one_layout_during(layout, || source.read(&pool));
                let Error::CodecAttempt(error) = result.unwrap_err() else {
                    panic!("narrower replay must preserve its genuine logical refusal");
                };
                let original = error.local_refusal().unwrap();
                assert_eq!(
                    original.kind(),
                    norito::core::DecodeLocalRefusalKind::EnclosingLimit
                );
                assert_eq!(
                    original.resource_error(),
                    norito::core::DecodeResourceError::TotalAllocationExceeded {
                        attempted: spent as u64,
                        limit: (spent - 1) as u64,
                    }
                );
                assert!(!allocated, "logical refusal precedes physical retry");
                assert_eq!(pool.reserved_bytes(), wire.len());
                let destination = source.binding().destination.as_ref().unwrap();
                assert!(destination.charge.is_some() && destination.bytes.is_none());
                assert!(destination.budget.same_pool(&pool));
                assert_eq!(error.into_local_refusal().unwrap(), original);
            });
            let bytes = norito::with_decode_limits_scope(wide, || source.read(&pool))
                .unwrap()
                .unwrap();
            assert_eq!(bytes.as_slice(), wire);
            assert!(bytes.belongs_to(&pool));
            drop(bytes);
            drop(source);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn original_raw_frame_partial_backing_survives_narrower_replay_and_abandonment() {
    const PROBE: usize = 16 * 1024 * 1024;
    for owned in [false, true] {
        let chain = fixture(true);
        let wire = chain.committed(2).block().encode_wire().unwrap();
        // Same real occupied slot, but a stable shorter sidecar: body storage must
        // reject after acquiring and reading the original partial backing.
        chain
            .kura()
            .block_store
            .lock()
            .write_da_block_bytes(2, &wire[..wire.len() - 1])
            .unwrap();
        let pool = AllocationBudget::new(wire.len());
        let mut source = Original::new(&chain, owned);
        let wide = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, PROBE, 64);
        let spent = norito::with_decode_limits_scope(wide, || {
            assert!(matches!(
                source.read(&pool),
                Err(Error::CanonicalBlockWireMismatch { height: 2 })
            ));
            let norito::Error::TotalAllocationExceeded { attempted, limit } =
                norito::core::reserve_decode_allocation(PROBE).unwrap_err()
            else {
                panic!("actual scope probe");
            };
            usize::try_from(attempted - limit).unwrap()
        });
        let destination = source.binding().destination.as_ref().unwrap();
        let backing = destination.bytes.as_ref().unwrap().as_slice().as_ptr();
        assert_eq!(
            destination.bytes.as_ref().unwrap().as_slice(),
            &wire[..wire.len() - 1]
        );
        assert_eq!(pool.reserved_bytes(), wire.len() - 1);
        let narrow = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, spent - 1, 64);
        norito::with_decode_limits_scope(narrow, || {
            let Error::CodecAttempt(error) = source.read(&pool).unwrap_err() else {
                panic!("original scope refusal");
            };
            assert_eq!(
                error.local_refusal().unwrap().resource_error(),
                norito::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: spent as u64,
                    limit: (spent - 1) as u64,
                }
            );
        });
        assert_eq!(
            source
                .binding()
                .destination
                .as_ref()
                .unwrap()
                .bytes
                .as_ref()
                .unwrap()
                .as_slice()
                .as_ptr(),
            backing
        );
        // The legitimate scope retries the same malformed original; no new backing
        // or a different error is allowed to replace the completed partial read.
        let layout = Layout::array::<u8>(wire.len() - 1).unwrap();
        let (result, allocated) = refuse_one_layout_during(layout, || {
            norito::with_decode_limits_scope(wide, || source.read(&pool))
        });
        assert!(!allocated);
        assert!(matches!(
            result,
            Err(Error::CanonicalBlockWireMismatch { height: 2 })
        ));
        assert_eq!(
            source
                .binding()
                .destination
                .as_ref()
                .unwrap()
                .bytes
                .as_ref()
                .unwrap()
                .as_slice()
                .as_ptr(),
            backing
        );
        assert_eq!(pool.reserved_bytes(), wire.len() - 1);
        drop(source);
        assert_eq!(pool.reserved_bytes(), 0);
        assert!(chain.kura().prune_lock.try_lock().is_some());
        assert!(chain.kura().canonical_chain_lock.try_lock().is_some());
        assert!(chain.kura().block_store.try_lock().is_some());
    }
}

#[test]
fn original_raw_frame_capacity_and_slot_refusal_preserve_fixed_pool_retry() {
    for evicted in [false, true] {
        let chain = fixture(evicted);
        let wire = chain.committed(2).block().encode_wire().unwrap();
        let pool = AllocationBudget::new(wire.len());
        let blocker = pool.try_reserve_bytes(1).unwrap();
        let mut source = Original::new(&chain, true);
        let original = source.read(&pool).unwrap_err();
        assert!(
            matches!(&original, Error::NativeFrameAllocation(iroha_allocation::ChargedBufferError::Admission(
            iroha_allocation::AllocationRefusal::Capacity { requested_bytes: requested, reserved_bytes: reserved, limit_bytes: limit, .. }))
            if *requested == wire.len() && *reserved == 1 && *limit == wire.len())
        );
        let destination = source.binding().destination.as_ref().unwrap();
        assert!(destination.charge.is_none() && destination.bytes.is_none());
        assert!(destination.budget.same_pool(&pool));
        assert_eq!(pool.reserved_bytes(), 1);
        let foreign = AllocationBudget::new(wire.len());
        assert!(matches!(
            source.read(&foreign),
            Err(Error::CanonicalBlockWireMismatch { height: 2 })
        ));
        assert_eq!(foreign.reserved_bytes(), 0);
        drop(blocker);
        let start = source.binding().start;
        {
            let mut store = chain.kura().block_store.lock();
            store
                .write_block_index(1, start.wrapping_add(1), wire.len() as u64)
                .unwrap();
        }
        assert!(matches!(
            source.read(&pool),
            Err(Error::CanonicalBlockWireMismatch { height: 2 })
        ));
        assert_eq!(pool.reserved_bytes(), 0);
        {
            let mut store = chain.kura().block_store.lock();
            store
                .write_block_index(1, start, wire.len() as u64)
                .unwrap();
        }
        // Exact restoration in the same journal object permits the original slot
        // to retry. No copied or replacement source receipt is needed.
        let bytes = source.read(&pool).unwrap().unwrap();
        drop(source);
        assert_eq!(bytes.as_slice(), wire);
        drop(bytes);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn original_raw_frame_abandonment_refunds_after_all_storage_guards_retire() {
    use std::{
        future::Future,
        sync::atomic::AtomicUsize,
        task::{Context, Wake, Waker},
    };
    struct Probe {
        kura: Arc<Kura>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.kura.prune_lock.try_lock().is_none()
                || self.kura.canonical_chain_lock.try_lock().is_none()
                || self.kura.block_store.try_lock().is_none()
            {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    for evicted in [false, true] {
        for owned in [false, true] {
            let chain = fixture(evicted);
            let wire = chain.committed(2).block().encode_wire().unwrap();
            let layout = Layout::array::<u8>(wire.len()).unwrap();
            let registration_bytes =
                iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
            let pool = AllocationBudget::new(wire.len() + registration_bytes);
            let mut registration = crate::unit_test_support::release_registration(&pool);
            let mut source = Original::new(&chain, owned);
            let (result, denied) = refuse_one_layout_during(layout, || source.read(&pool));
            assert!(denied && matches!(result, Err(Error::NativeFrameConstruction(_))));
            let iroha_allocation::AllocationRefusal::Capacity { release, .. } =
                pool.try_reserve_bytes(1).unwrap_err()
            else {
                panic!("original frame must occupy its entire finite pool");
            };
            let probe = Arc::new(Probe {
                kura: Arc::clone(chain.kura()),
                calls: AtomicUsize::new(0),
                blocked: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let mut context = Context::from_waker(&waker);
            let mut wait = release.wait_for_release(&mut registration);
            assert!(
                std::pin::Pin::new(&mut wait)
                    .poll(&mut context)
                    .is_pending()
            );
            let (result, denied) = refuse_one_layout_during(layout, || source.read(&pool));
            assert!(denied && matches!(result, Err(Error::NativeFrameConstruction(_))));
            assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
            assert!(
                std::pin::Pin::new(&mut wait)
                    .poll(&mut context)
                    .is_pending()
            );
            drop(source);
            assert_eq!(pool.reserved_bytes(), registration_bytes);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
            assert!(std::pin::Pin::new(&mut wait).poll(&mut context).is_ready());
            drop(wait);
            drop(registration);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}
