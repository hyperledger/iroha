//! Actual model/BLS controls for retained registry ownership and fallible merge reads.

use super::*;

#[test]
fn original_native_lane_authority_refusal_reaches_merge_and_original_pool_retry() {
    use crate::sumeragi::runtime_availability::NativeLaneStoreAuthorities;
    use std::task::Context;
    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let ceiling = budget.limit_bytes();
    for height in 1..=4 {
        chain
            .kura()
            .get_block(std::num::NonZeroUsize::new(height).unwrap(), &budget)
            .expect("original committed history read completes")
            .expect("original committed block is retained");
    }
    let crypto = Arc::new(crate::sumeragi::crypto::BlsCrypto::new());
    let authorities = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(state),
        Arc::clone(&crypto),
    ));
    let stores = LaneStores::new(
        chain.kura().store_root().join("lanes"),
        *state.network_id_ref(),
        state.chain_id_ref().to_string(),
        crypto,
        budget.clone(),
        authorities,
    );
    let occupied = budget
        .try_reserve_bytes(ceiling - budget.reserved_bytes())
        .unwrap();
    let error = stores.tip(record.lane, &record.incarnation).unwrap_err();
    let Attempt::Deferred(original) = &error else {
        panic!("original native authority was erased: {error:?}")
    };
    let original = original.clone();
    let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        original.allocation_refusal()
    else {
        panic!("actual original archive capacity")
    };
    let wait = release.clone();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&wait, &mut context).is_pending());
    assert!(
        matches!(crate::block::BlockValidationError::from(crate::sumeragi::lanes::merge::MergeError::Storage(error)), crate::block::BlockValidationError::ExecutionDeferred(retained) if retained == original)
    );
    assert_eq!(budget.reserved_bytes(), ceiling);
    drop(occupied);
    assert!(registration.poll_wait(&wait, &mut context).is_ready());
    assert_eq!(
        stores.tip(record.lane, &record.incarnation).unwrap(),
        Some(0)
    );
    assert_eq!(budget.limit_bytes(), ceiling);
    drop(stores);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
}
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::{
    crypto::KeyPairSigner,
    lanes::{LaneBatch, record::tests::fixture},
};
use iroha_allocation::ChargedBuffer;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::sumeragi_lanes::{
    SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord,
};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody, PayloadAuthoring, PayloadBytes},
    crypto::Signer,
    message::Qc,
    types::HeightConfig,
};
use std::{
    fs,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

const LANE: LaneId = LaneId::new(2);
const INCARNATION: [u8; 32] = [0x45; 32];
struct Schedule {
    instance: Hash32,
    config: HeightConfig,
}
impl AvailabilitySchedule for Schedule {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, _: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        Ok(Some(self.config.clone()))
    }
}
struct Authorities {
    schedule: Arc<Schedule>,
    missing: AtomicBool,
    corrupt: AtomicBool,
    calls: AtomicUsize,
}

// Independent authority for the disjoint empty incarnation used below. Both schedules are
// pinned before any decoder refusal; no bytes from the pending artifact select this authority.
struct DisjointAuthorities {
    first: Arc<Authorities>,
    other_lane: LaneId,
    other_incarnation: [u8; 32],
    other: Arc<Schedule>,
}
impl LaneStoreAuthorities for DisjointAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<
        Option<LaneStoreAuthority>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        if lane == self.other_lane && *incarnation == self.other_incarnation {
            assert_eq!(instance, self.other.instance);
            return Ok(Some(LaneStoreAuthority {
                schedule: self.other.clone(),
            }));
        }
        self.first.authority(lane, incarnation, instance)
    }
}
impl LaneStoreAuthorities for Authorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<
        Option<LaneStoreAuthority>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        assert_eq!(lane, LANE);
        assert_eq!(*incarnation, INCARNATION);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.missing.load(Ordering::SeqCst) {
            return Ok(None);
        }
        if self.corrupt.load(Ordering::SeqCst) {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "bad authenticated activation").into(),
            );
        }
        // A separate test deliberately supplies a foreign schedule; registry must refuse it.
        assert_ne!(instance, Hash32::ZERO);
        Ok(Some(LaneStoreAuthority {
            schedule: self.schedule.clone(),
        }))
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    stores: LaneStores,
    body: AvailableBody,
    qc: Qc,
    source: AvailabilitySource,
    authorities: Arc<Authorities>,
}
impl Fixture {
    fn new(valid_batch: bool) -> Self {
        Self::with_transactions(valid_batch, Vec::new())
    }
    fn with_transactions(
        valid_batch: bool,
        transactions: Vec<iroha_data_model::transaction::SignedTransaction>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (body, mut qc, old_source, budget, crypto) = fixture(1025);
        let crypto: SharedCrypto = Arc::new(crypto);
        let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"registry network",
        )));
        let instance =
            incarnation_instance(&*crypto, &network, "registry-chain", LANE, &INCARNATION);
        let mut signers: Vec<_> = (1..=4)
            .map(|seed| {
                KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
                    .unwrap()
            })
            .collect();
        signers.sort_by(|a, b| a.public_key().cmp(b.public_key()));
        let mut header = body.header().clone();
        header.instance = instance;
        let payload = if valid_batch {
            let bytes = LaneBatch {
                anchor_height: 7,
                anchor_hash: network.into_genesis_hash(),
                transactions,
            }
            .to_payload();
            let mut charged = ChargedBuffer::new(bytes.len(), &budget).unwrap();
            for byte in bytes {
                charged.push_reserved(byte);
            }
            PayloadBytes::from_charged(charged, &budget)
                .unwrap_or_else(|_| panic!("original batch backing/control"))
        } else {
            body.payload().clone()
        };
        header.payload_hash = iroha_sumeragi::preimage::payload_hash(&*crypto, payload.as_slice());
        header.payload_len = u32::try_from(payload.as_slice().len()).unwrap();
        let authored = PayloadAuthoring::new(header, payload)
            .complete(
                instance,
                old_source.config(),
                &budget,
                &*crypto,
                &signers[0],
            )
            .unwrap_or_else(|(_, error)| panic!("original signed fixture: {error:?}"));
        drop(authored.codeword);
        let body = authored.body;
        qc.instance = instance;
        qc.block_hash = body.hash(&*crypto);
        qc.agg_sig = crypto.aggregate(
            &signers[..3]
                .iter()
                .map(|s| s.sign(&qc.preimage()))
                .collect::<Vec<_>>(),
        );
        let source =
            AvailabilitySource::new(instance, 1, qc.block_hash, old_source.config().clone())
                .unwrap();
        let authorities = Arc::new(Authorities {
            schedule: Arc::new(Schedule {
                instance,
                config: source.config().clone(),
            }),
            missing: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let stores = LaneStores::new(
            dir.path().to_path_buf(),
            network,
            "registry-chain".into(),
            crypto,
            budget,
            authorities.clone(),
        );
        Self {
            dir,
            stores,
            body,
            qc,
            source,
            authorities,
        }
    }
    fn path(&self) -> PathBuf {
        self.dir
            .path()
            .join(hex::encode(self.source.instance().0))
            .join("00000000000000000001.frame")
    }
    fn publish(&self) {
        self.stores
            .store(LANE, &INCARNATION)
            .unwrap()
            .append(&self.body, &self.qc)
            .unwrap();
    }

    fn lane_state(&self) -> SumeragiLaneState {
        let mut committee: Vec<_> = (1..=4)
            .map(|seed| {
                let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
                SumeragiLaneMember {
                    peer: PeerId::new(pair.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
                }
            })
            .collect();
        committee.sort_by(|left, right| left.peer.cmp(&right.peer));
        SumeragiLaneState {
            lanes: vec![SumeragiLaneRecord {
                da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
                lane: LANE,
                dataspace: DataSpaceId::new(0),
                incarnation: INCARNATION,
                params: Default::default(),
                committee,
                created_at: 1,
                active_from: 3,
                closing: None,
                anchor_freshness: 4,
                merged: SumeragiLaneFrontier::default(),
                merged_at: 3,
                rescued: 0,
            }],
            incarnations: 1,
            ..SumeragiLaneState::default()
        }
    }
}

#[test]
fn authenticated_registry_batch_decode_refusal_is_retryable_not_byzantine() {
    use iroha_data_model::{
        Level,
        account::AccountId,
        isi::Log,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let pair = KeyPair::from_seed(vec![0x35; 32], Algorithm::Ed25519);
    let transaction = TransactionBuilder::new(
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"registry network",
        ))),
        AccountId::new(pair.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "original lane transaction".into())])
    .sign(pair.private_key());
    let mut f = Fixture::with_transactions(true, vec![transaction.clone()]);
    let other_lane = LaneId::new(3);
    let other_incarnation = [0x46; 32];
    let other = Arc::new(Schedule {
        instance: f.stores.instance(other_lane, &other_incarnation),
        config: f.source.config().clone(),
    });
    f.stores.authorities = Arc::new(DisjointAuthorities {
        first: f.authorities.clone(),
        other_lane,
        other_incarnation,
        other,
    });
    f.publish();
    let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let other_store = f.stores.store(other_lane, &other_incarnation).unwrap();
    assert_eq!(other_store.height(), 0);
    let frame = fs::read(f.path()).unwrap();
    // Norito uses Vec::try_reserve, whose physical minimum can exceed one element.
    let mut destination = Vec::<iroha_data_model::transaction::SignedTransaction>::new();
    destination.try_reserve(1).unwrap();
    let layout = std::alloc::Layout::array::<iroha_data_model::transaction::SignedTransaction>(
        destination.capacity(),
    )
    .unwrap();
    drop(destination);
    let (outcome, refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
        f.stores.block(LANE, &INCARNATION, 1)
    });
    assert!(
        refused,
        "the exact original batch transaction destination must be refused"
    );
    let error = outcome.expect_err("local decoder refusal is never a Byzantine verdict");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(
        matches!(error, Attempt::Deferred(_)),
        "refusal must not box a replacement diagnostic"
    );
    let (body_pointer, signers_pointer) = {
        let slot = store.batch_read.lock();
        let read = slot
            .as_ref()
            .expect("batch decode retains the original ready body");
        assert_eq!(read.body.header().height, 1);
        assert_eq!(read.body.source(), &f.source);
        assert!(read.body.admitted_to(&f.stores.budget));
        (
            read.body.payload().as_slice().as_ptr(),
            read.qc.signers.as_bytes().as_ptr(),
        )
    };
    let retained = f.stores.budget.reserved_bytes();
    // Local refusal in the first lane cannot block an authenticated disjoint incarnation.
    let other_read = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, 1 << 25, usize::MAX, 0, 32),
        || f.stores.block(other_lane, &other_incarnation, 1),
    )
    .expect("a disjoint empty lane does not decode the refused first-lane batch");
    assert!(other_read.is_none());
    assert_eq!(f.stores.budget.reserved_bytes(), retained);
    assert_eq!(
        store
            .batch_read
            .lock()
            .as_ref()
            .unwrap()
            .body
            .payload()
            .as_slice()
            .as_ptr(),
        body_pointer
    );
    // Retirement keeps the exact historical owner, original backing and exclusive disk lock.
    f.stores.release_retired(&SumeragiLaneState::default());
    f.stores.release(LANE, &INCARNATION);
    assert!(Arc::ptr_eq(
        &store,
        &f.stores.store(LANE, &INCARNATION).unwrap()
    ));
    assert!(matches!(
        f.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Ready(..))
    ));
    assert!(
        FileLaneBlockStore::begin_open(
            f.stores.root(),
            &f.source.instance(),
            f.stores.crypto.clone(),
            f.stores.budget.clone(),
            f.authorities.schedule.clone(),
        )
        .is_err(),
        "retirement cannot relinquish the refused original batch's native lock"
    );
    // A different requested height cannot discard the earlier refused owner.
    for height in [1, 2] {
        let error = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(96, 1 << 25, usize::MAX, 0, 32),
            || f.stores.block(LANE, &INCARNATION, height),
        )
        .unwrap_err();
        assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
        assert!(matches!(error, Attempt::Deferred(_)));
        let slot = store.batch_read.lock();
        let read = slot.as_ref().unwrap();
        assert_eq!(read.body.header().height, 1);
        assert_eq!(read.body.payload().as_slice().as_ptr(), body_pointer);
        assert_eq!(read.qc.signers.as_bytes().as_ptr(), signers_pointer);
        assert_eq!(f.stores.budget.reserved_bytes(), retained);
    }
    assert_eq!(store.height(), 1);
    assert!(Arc::ptr_eq(
        &store,
        &f.stores.store(LANE, &INCARNATION).unwrap()
    ));
    assert_eq!(fs::read(f.path()).unwrap(), frame);
    let completed = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(completed.block_hash, f.qc.block_hash);
    assert_eq!(completed.result, f.qc.result);
    assert_eq!(completed.batch.unwrap().transactions, vec![transaction]);
    assert!(store.batch_read.lock().is_none());
    assert!(f.stores.block(LANE, &INCARNATION, 2).unwrap().is_none());
    drop(store);
    f.stores.release(LANE, &INCARNATION);
    assert!(!f.stores.stores.lock().contains_key(&(LANE, INCARNATION)));
}

#[test]
fn complete_registry_reads_share_owner_and_preserve_valid_or_byzantine_payload_distinction() {
    for valid_batch in [false, true] {
        let f = Fixture::new(valid_batch);
        assert_eq!(f.stores.root(), f.dir.path());
        assert_eq!(f.stores.instance(LANE, &INCARNATION), f.source.instance());
        assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(0));
        assert!(f.stores.block(LANE, &INCARNATION, 1).unwrap().is_none());
        f.publish();
        let a = f.stores.store(LANE, &INCARNATION).unwrap();
        let b = f.stores.store(LANE, &INCARNATION).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(f.authorities.calls.load(Ordering::SeqCst), 1);
        let block = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
        assert_eq!(block.block_hash, f.qc.block_hash);
        assert_eq!(block.result, f.qc.result);
        assert_eq!(block.batch.is_some(), valid_batch);
        if let Some(batch) = block.batch {
            assert_eq!(batch.anchor_height, 7);
            assert!(batch.transactions.is_empty());
        }
        assert!(
            f.stores
                .wait_for(LANE, &INCARNATION, 1, Duration::ZERO)
                .unwrap()
        );
        assert!(
            !f.stores
                .wait_for(LANE, &INCARNATION, 2, Duration::ZERO)
                .unwrap()
        );
        f.stores.release(LANE, &INCARNATION);
        assert!(Arc::ptr_eq(
            &a,
            &f.stores.store(LANE, &INCARNATION).unwrap()
        ));
        assert!(matches!(
            f.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Ready(..))
        ));
        drop((a, b));
        f.stores.release(LANE, &INCARNATION);
        assert!(!f.stores.stores.lock().contains_key(&(LANE, INCARNATION)));
        assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    }
}

#[test]
fn unresolved_corrupt_and_foreign_authority_never_become_an_empty_store() {
    let mut f = Fixture::new(true);
    f.authorities.missing.store(true, Ordering::SeqCst);
    for error in [
        f.stores.tip(LANE, &INCARNATION).unwrap_err(),
        f.stores.block(LANE, &INCARNATION, 1).unwrap_err(),
        f.stores
            .wait_for(LANE, &INCARNATION, 1, Duration::ZERO)
            .unwrap_err(),
    ] {
        assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    }
    assert!(f.stores.stores.lock().is_empty());
    f.authorities.missing.store(false, Ordering::SeqCst);
    f.authorities.corrupt.store(true, Ordering::SeqCst);
    assert_eq!(
        f.stores.tip(LANE, &INCARNATION).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    let provider = Arc::new(Authorities {
        schedule: Arc::new(Schedule {
            instance: Hash32([0x88; 32]),
            config: f.source.config().clone(),
        }),
        missing: AtomicBool::new(false),
        corrupt: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    f.stores.authorities = provider;
    assert_eq!(
        f.stores.tip(LANE, &INCARNATION).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert!(!f.path().exists());
}

#[test]
fn registry_retains_opening_lock_and_exact_charges_across_refusal() {
    let f = Fixture::new(true);
    f.publish();
    f.stores.release(LANE, &INCARNATION);
    let raw = fs::metadata(f.path()).unwrap().len() as usize;
    let baseline = f.stores.budget.reserved_bytes();
    f.stores.budget.set_limit_bytes(baseline + raw);
    assert_eq!(
        f.stores.store(LANE, &INCARNATION).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.stores.budget.reserved_bytes(), baseline + raw);
    assert!(matches!(
        f.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Opening(..))
    ));
    let calls = f.authorities.calls.load(Ordering::SeqCst);
    f.authorities.corrupt.store(true, Ordering::SeqCst);
    assert_eq!(
        f.stores.tip(LANE, &INCARNATION).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.stores.budget.reserved_bytes(), baseline + raw);
    assert_eq!(
        f.authorities.calls.load(Ordering::SeqCst),
        calls,
        "retry retains the original independently selected authority"
    );
    assert!(
        FileLaneBlockStore::begin_open(
            f.dir.path(),
            &f.source.instance(),
            f.stores.crypto.clone(),
            f.stores.budget.clone(),
            f.authorities.schedule.clone()
        )
        .is_err()
    );
    f.stores.budget.set_limit_bytes(1 << 25);
    assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    assert_eq!(f.stores.budget.reserved_bytes(), baseline);
    assert!(matches!(
        f.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Ready(..))
    ));
}

#[test]
fn retired_failed_openings_release_original_funding_and_lock_but_keep_replay_frames() {
    for recreated in [false, true] {
        let f = Fixture::new(true);
        f.publish();
        let original = fs::read(f.path()).unwrap();
        f.stores.release(LANE, &INCARNATION);
        let baseline = f.stores.budget.reserved_bytes();
        f.stores.budget.set_limit_bytes(baseline + original.len());
        assert_eq!(
            f.stores
                .runtime_store(LANE, &INCARNATION)
                .unwrap_err()
                .io_kind(),
            io::ErrorKind::WouldBlock
        );
        let mut lanes = f.lane_state();
        f.stores.release_retired(&lanes);
        assert_eq!(f.stores.budget.reserved_bytes(), baseline + original.len());
        assert!(matches!(
            f.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Opening(..))
        ));
        if recreated {
            lanes.lanes[0].incarnation = [0x46; 32];
        } else {
            lanes.lanes.clear();
        }
        f.stores.release_retired(&lanes);
        assert!(f.stores.stores.lock().is_empty());
        assert_eq!(f.stores.budget.reserved_bytes(), baseline);
        assert_eq!(fs::read(f.path()).unwrap(), original);
        // A historical reader reopening this retired incarnation owns its retry. Later
        // runner reconciliations must not discard its funded prefix or exclusive lock.
        assert_eq!(
            f.stores.store(LANE, &INCARNATION).unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        f.stores.release_retired(&lanes);
        assert_eq!(f.stores.budget.reserved_bytes(), baseline + original.len());
        assert!(matches!(
            f.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Opening(_, true))
        ));
        f.stores.budget.set_limit_bytes(1 << 25);
        assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
        f.stores.release_retired(&lanes);
        assert!(f.stores.stores.lock().is_empty());
        assert_eq!(fs::read(f.path()).unwrap(), original);
        assert!(f.stores.block(LANE, &INCARNATION, 1).unwrap().is_some());
    }
}

#[test]
fn retired_ready_owner_preserves_outstanding_reader_and_replay_custody() {
    let f = Fixture::new(true);
    f.publish();
    let reader = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    f.stores.release_retired(&f.lane_state());
    assert!(Arc::ptr_eq(
        &reader,
        &f.stores.store(LANE, &INCARNATION).unwrap()
    ));
    f.stores.release_retired(&SumeragiLaneState::default());
    assert!(matches!(
        f.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Ready(..))
    ));
    assert!(Arc::ptr_eq(
        &reader,
        &f.stores.store(LANE, &INCARNATION).unwrap()
    ));
    assert!(reader.committed_body(1).unwrap().is_some());
    assert!(
        FileLaneBlockStore::begin_open(
            f.dir.path(),
            &f.source.instance(),
            f.stores.crypto.clone(),
            f.stores.budget.clone(),
            f.authorities.schedule.clone()
        )
        .is_err(),
        "retirement must not revoke an outstanding authenticated reader's lock"
    );
    drop(reader);
    f.stores.release(LANE, &INCARNATION);
    assert!(f.stores.stores.lock().is_empty());
    assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    assert!(f.stores.block(LANE, &INCARNATION, 1).unwrap().is_some());
}

#[test]
fn storage_corruption_is_repeated_error_not_missing_block_or_recovered_tip() {
    let f = Fixture::new(true);
    f.publish();
    let original = f.stores.store(LANE, &INCARNATION).unwrap();
    let weak = Arc::downgrade(&original);
    let authority_calls = f.authorities.calls.load(Ordering::SeqCst);
    drop(original);
    let mut bytes = fs::read(f.path()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(f.path(), bytes).unwrap();
    for _ in 0..2 {
        assert_eq!(
            f.stores.block(LANE, &INCARNATION, 1).unwrap_err().io_kind(),
            io::ErrorKind::InvalidData
        );
    }
    let retained_bytes = f.stores.budget.reserved_bytes();
    f.stores.release(LANE, &INCARNATION);
    for _ in 0..2 {
        assert_eq!(
            f.stores.tip(LANE, &INCARNATION).unwrap_err().io_kind(),
            io::ErrorKind::InvalidData
        );
    }
    let original = weak
        .upgrade()
        .expect("the exact corrupt pending read must retain its original store owner");
    let stores = f.stores.stores.lock();
    let Some(StoreSlot::Ready(retained)) = stores.get(&(LANE, INCARNATION)) else {
        panic!("a corrupt pending read must not be dropped and reopened");
    };
    assert!(Arc::ptr_eq(&original, retained));
    assert!(retained.retains_pending_work());
    assert_eq!(f.stores.budget.reserved_bytes(), retained_bytes);
    assert_eq!(f.authorities.calls.load(Ordering::SeqCst), authority_calls);
}

#[test]
fn retired_historical_ready_store_releases_last_owner_after_completed_reader() {
    let f = Fixture::new(true);
    f.publish();
    let frame = fs::read(f.path()).unwrap();
    let reader = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let weak = Arc::downgrade(&reader);
    let original_limit = f.stores.budget.limit_bytes();
    let retired = SumeragiLaneState::default();
    f.stores.release_retired(&retired);
    assert!(matches!(
        f.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Ready(..))
    ));
    let (body, certificate) = reader.committed_body(1).unwrap().unwrap();
    assert_eq!(certificate, f.qc);
    assert_eq!(body.source(), &f.source);
    assert_eq!(body.hash(&*f.stores.crypto), f.qc.block_hash);
    drop(body);
    f.stores.release_retired(&retired);
    assert!(
        weak.upgrade().is_some(),
        "an actual reader still owns its exact store"
    );
    drop(reader);
    f.stores.release_retired(&retired);
    assert!(
        weak.upgrade().is_none(),
        "completed historical reader must release the last ready store owner"
    );
    assert!(f.stores.stores.lock().is_empty());
    assert_eq!(f.stores.budget.limit_bytes(), original_limit);
    assert_eq!(
        fs::read(f.path()).unwrap(),
        frame,
        "releasing ready memory and lock must preserve certified replay frames"
    );
    assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(replay.block_hash, f.qc.block_hash);
    assert_eq!(replay.result, f.qc.result);
    assert!(replay.batch.is_some());
}

// Append inside the existing lanes::registry::tests module. The actual fixture,
// registry, signed BLS certificate and independently selected schedule remain unchanged.

fn retire_exact_ready_owner(stores: &LaneStores, explicit_release: bool) {
    if explicit_release {
        stores.release(LANE, &INCARNATION);
    } else {
        stores.release_retired(&SumeragiLaneState::default());
    }
}

#[test]
fn retired_ready_store_preserves_original_read_refusal_before_batch_population() {
    for explicit_release in [false, true] {
        let f = Fixture::new(true);
        f.publish();
        let frame = fs::read(f.path()).unwrap();
        let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
        let weak = Arc::downgrade(&store);
        let baseline = f.stores.budget.reserved_bytes();
        let ceiling = f.stores.budget.limit_bytes();
        let occupied = f
            .stores
            .budget
            .try_reserve_bytes(
                ceiling
                    .checked_sub(baseline)
                    .unwrap()
                    .checked_sub(frame.len())
                    .unwrap(),
            )
            .unwrap();
        let error = f.stores.block(LANE, &INCARNATION, 1).unwrap_err();
        let Attempt::Deferred(original) = error else {
            panic!("actual restoration must preserve its original refusal: {error:?}");
        };
        let Some(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            ..
        }) = original.allocation_refusal()
        else {
            panic!("the next restoration allocation must refuse from the original pool");
        };
        assert!(*requested_bytes > 0);
        assert_eq!(*reserved_bytes, ceiling);
        assert_eq!(*limit_bytes, ceiling);
        assert_eq!(f.stores.budget.reserved_bytes(), ceiling);
        assert!(
            store.batch_read.lock().is_none(),
            "the source restoration refused before producing an authenticated batch owner"
        );
        drop(store);
        retire_exact_ready_owner(&f.stores, explicit_release);
        assert_eq!(
            f.stores.budget.reserved_bytes(),
            ceiling,
            "retirement must retain the exact original frame/restoration allocation"
        );
        let same = weak
            .upgrade()
            .expect("pending read retains the original ready owner");
        let still_registered = f.stores.store(LANE, &INCARNATION).unwrap();
        assert!(Arc::ptr_eq(&same, &still_registered));
        assert!(still_registered.batch_read.lock().is_none());
        assert_eq!(fs::read(f.path()).unwrap(), frame);
        assert!(
            FileLaneBlockStore::begin_open(
                f.dir.path(),
                &f.source.instance(),
                f.stores.crypto.clone(),
                f.stores.budget.clone(),
                f.authorities.schedule.clone(),
            )
            .is_err(),
            "the unfinished original reader still owns the native lock"
        );
        drop(still_registered);
        drop(same);
        let error = f.stores.block(LANE, &INCARNATION, 1).unwrap_err();
        assert!(
            matches!(error, Attempt::Deferred(_)),
            "unchanged original pressure must not become missing or completed-invalid"
        );
        assert_eq!(f.stores.budget.reserved_bytes(), ceiling);
        drop(occupied);
        let restored = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
        assert_eq!(restored.block_hash, f.qc.block_hash);
        assert_eq!(restored.result, f.qc.result);
        assert!(restored.batch.is_some());
        drop(restored);
        retire_exact_ready_owner(&f.stores, explicit_release);
        assert!(
            weak.upgrade().is_none(),
            "a completed read can release its final store owner"
        );
        assert_eq!(f.stores.budget.reserved_bytes(), baseline);
        assert_eq!(f.stores.budget.limit_bytes(), ceiling);
        assert_eq!(fs::read(f.path()).unwrap(), frame);
        let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
        assert_eq!(replay.block_hash, f.qc.block_hash);
        assert_eq!(replay.result, f.qc.result);
    }
}

struct RetiredReadyPublicationFault {
    armed: AtomicBool,
}
impl crate::sumeragi::records::Faults for RetiredReadyPublicationFault {
    fn before(&self, step: crate::sumeragi::records::FsStep, _: &Path) -> io::Result<()> {
        if step == crate::sumeragi::records::FsStep::CreateTemp
            && self.armed.swap(false, Ordering::SeqCst)
        {
            return Err(io::Error::other("retained ready publication refusal"));
        }
        Ok(())
    }
}

#[test]
fn retired_ready_store_preserves_original_unfinished_publication_until_exact_retry() {
    for explicit_release in [false, true] {
        let f = Fixture::new(true);
        let faults = Arc::new(RetiredReadyPublicationFault {
            armed: AtomicBool::new(false),
        });
        // Use the existing faulted physical constructor with this fixture's independently
        // selected authority. Only test registry insertion differs from the normal factory.
        let store = FileLaneBlockStore::begin_open_with_faults(
            f.dir.path(),
            &f.source.instance(),
            f.stores.crypto.clone(),
            f.stores.budget.clone(),
            f.authorities.schedule.clone(),
            faults.clone(),
        )
        .unwrap()
        .complete()
        .unwrap_or_else(|(_, error)| panic!("empty source store: {error:?}"));
        let store = Arc::new(store);
        assert!(
            f.stores
                .stores
                .lock()
                .insert((LANE, INCARNATION), StoreSlot::Ready(store.clone()),)
                .is_none()
        );
        let weak = Arc::downgrade(&store);
        let baseline = f.stores.budget.reserved_bytes();
        let ceiling = f.stores.budget.limit_bytes();
        faults.armed.store(true, Ordering::SeqCst);
        let error = store.append(&f.body, &f.qc).unwrap_err();
        assert_eq!(error.io_kind(), io::ErrorKind::Other);
        assert!(
            error
                .to_string()
                .contains("retained ready publication refusal")
        );
        assert_eq!(store.height(), 0);
        assert!(!f.path().exists());
        assert!(store.batch_read.lock().is_none());
        let retained = f.stores.budget.reserved_bytes();
        assert!(
            retained > baseline,
            "the actual prepared canonical frame is funded before I/O"
        );
        drop(store);
        retire_exact_ready_owner(&f.stores, explicit_release);
        assert_eq!(
            f.stores.budget.reserved_bytes(),
            retained,
            "the exact prepared output cannot be dropped by retired reconciliation"
        );
        let same = weak
            .upgrade()
            .expect("original pending publication retains its ready store");
        assert!(Arc::ptr_eq(
            &same,
            &f.stores.store(LANE, &INCARNATION).unwrap()
        ));
        assert_eq!(same.height(), 0);
        assert!(!f.path().exists());
        assert!(
            FileLaneBlockStore::begin_open(
                f.dir.path(),
                &f.source.instance(),
                f.stores.crypto.clone(),
                f.stores.budget.clone(),
                f.authorities.schedule.clone(),
            )
            .is_err(),
            "another writer cannot replace original unfinished publication custody"
        );
        let occupied = f
            .stores
            .budget
            .try_reserve_bytes(ceiling - retained)
            .unwrap();
        same.append(&f.body, &f.qc).unwrap();
        assert_eq!(same.height(), 1);
        assert!(f.path().exists());
        drop(occupied);
        drop(same);
        retire_exact_ready_owner(&f.stores, explicit_release);
        assert!(weak.upgrade().is_none());
        assert_eq!(f.stores.budget.reserved_bytes(), baseline);
        assert_eq!(f.stores.budget.limit_bytes(), ceiling);
        let frame = fs::read(f.path()).unwrap();
        let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
        assert_eq!(replay.block_hash, f.qc.block_hash);
        assert_eq!(replay.result, f.qc.result);
        assert_eq!(fs::read(f.path()).unwrap(), frame);
    }
}

#[test]
fn historical_join_of_runtime_opening_retains_original_recovery_after_lane_retirement() {
    let f = Fixture::new(true);
    f.publish();
    let frame = fs::read(f.path()).unwrap();
    f.stores.release(LANE, &INCARNATION);
    assert!(f.stores.stores.lock().is_empty());
    let baseline = f.stores.budget.reserved_bytes();
    let ceiling = f.stores.budget.limit_bytes();
    let occupied = f
        .stores
        .budget
        .try_reserve_bytes(
            ceiling
                .checked_sub(baseline)
                .unwrap()
                .checked_sub(frame.len())
                .unwrap(),
        )
        .unwrap();
    let runtime_error = f.stores.runtime_store(LANE, &INCARNATION).unwrap_err();
    assert!(matches!(runtime_error, Attempt::Deferred(_)));
    assert_eq!(f.stores.budget.reserved_bytes(), ceiling);
    let authority_calls = f.authorities.calls.load(Ordering::SeqCst);
    let historical_error = f.stores.store(LANE, &INCARNATION).unwrap_err();
    assert!(matches!(historical_error, Attempt::Deferred(_)));
    assert_eq!(f.authorities.calls.load(Ordering::SeqCst), authority_calls);
    assert_eq!(f.stores.budget.reserved_bytes(), ceiling);
    f.stores.release_retired(&SumeragiLaneState::default());
    assert!(
        matches!(
            f.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Opening(..))
        ),
        "an actual historical caller joined this original unfinished recovery"
    );
    assert_eq!(
        f.stores.budget.reserved_bytes(),
        ceiling,
        "retirement must not erase the historical join's exact original frame allocation"
    );
    assert_eq!(f.authorities.calls.load(Ordering::SeqCst), authority_calls);
    assert_eq!(fs::read(f.path()).unwrap(), frame);
    drop(occupied);
    assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    assert_eq!(
        f.authorities.calls.load(Ordering::SeqCst),
        authority_calls,
        "same recovery retains its independently selected authority"
    );
    let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(replay.block_hash, f.qc.block_hash);
    assert_eq!(replay.result, f.qc.result);
    drop(replay);
    assert_eq!(f.stores.budget.reserved_bytes(), baseline);
    f.stores.release(LANE, &INCARNATION);
    assert!(f.stores.stores.lock().is_empty());
}

/// The ordinary cached runtime height cannot certify away an actual reader failure.
#[test]
fn ready_tip_preserves_same_original_authentication_failure_without_reopening() {
    let f = Fixture::new(true);
    f.publish();
    let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let authority_calls = f.authorities.calls.load(Ordering::SeqCst);
    let mut corrupt = fs::read(f.path()).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fs::write(f.path(), &corrupt).unwrap();
    let original = f.stores.block(LANE, &INCARNATION, 1).unwrap_err();
    let Attempt::Rejected(rejected) = original else {
        panic!("the actual corrupted signed frame must reject authentication");
    };
    assert_eq!(rejected.kind(), io::ErrorKind::InvalidData);
    let cause = rejected.to_string();
    let retained = f.stores.budget.reserved_bytes();
    assert_eq!(store.height(), 1, "runtime committed height is unchanged");
    f.stores.release(LANE, &INCARNATION);
    for _ in 0..2 {
        let error = f.stores.tip(LANE, &INCARNATION).unwrap_err();
        let Attempt::Rejected(rejected) = error else {
            panic!("an original authentication failure must not become a local refusal");
        };
        assert_eq!(rejected.kind(), io::ErrorKind::InvalidData);
        assert_eq!(rejected.to_string(), cause);
        assert!(
            Arc::ptr_eq(&store, &f.stores.store(LANE, &INCARNATION).unwrap()),
            "tip observation retains the same original Ready owner"
        );
        assert_eq!(
            f.authorities.calls.load(Ordering::SeqCst),
            authority_calls,
            "tip must not reopen with a new authority or restoration graph"
        );
        assert_eq!(f.stores.budget.reserved_bytes(), retained);
        assert_eq!(fs::read(f.path()).unwrap(), corrupt);
        assert_eq!(store.height(), 1);
    }
}

#[test]
fn ready_tip_retains_original_pool_refusal_and_completed_read_until_normal_consumption() {
    let f = Fixture::new(true);
    f.publish();
    let frame = fs::read(f.path()).unwrap();
    let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let weak = Arc::downgrade(&store);
    let authority_calls = f.authorities.calls.load(Ordering::SeqCst);
    let baseline = f.stores.budget.reserved_bytes();
    let ceiling = f.stores.budget.limit_bytes();
    let occupied = f
        .stores
        .budget
        .try_reserve_bytes(
            ceiling
                .checked_sub(baseline)
                .unwrap()
                .checked_sub(frame.len())
                .unwrap(),
        )
        .unwrap();
    let error = f.stores.block(LANE, &INCARNATION, 1).unwrap_err();
    let Attempt::Deferred(original) = error else {
        panic!("actual original frame restoration must return its local refusal");
    };
    let Some(iroha_allocation::AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    }) = original.allocation_refusal()
    else {
        panic!("actual restoration must retain complete original Capacity evidence");
    };
    assert!(*requested_bytes > 0);
    assert_eq!(*reserved_bytes, ceiling);
    assert_eq!(*limit_bytes, ceiling);
    // An independent refusal from the same still-full finite pool identifies
    // its exact release observation without exposing or reconstructing a pool.
    let original_pool_probe = f
        .stores
        .budget
        .try_reserve_bytes(*requested_bytes)
        .err()
        .expect("original occupied pool must refuse the same actual demand");
    assert_eq!(original.allocation_refusal(), Some(&original_pool_probe));
    assert!(store.batch_read.lock().is_none());
    for _ in 0..2 {
        let error = f.stores.tip(LANE, &INCARNATION).unwrap_err();
        let Attempt::Deferred(retained) = error else {
            panic!("tip must propagate the same original unfinished local attempt");
        };
        assert_eq!(
            retained, original,
            "tip must preserve original cause, Capacity fields and pool release owner"
        );
        assert!(Arc::ptr_eq(
            &store,
            &f.stores.store(LANE, &INCARNATION).unwrap()
        ));
        assert_eq!(f.stores.budget.reserved_bytes(), ceiling);
        assert_eq!(f.authorities.calls.load(Ordering::SeqCst), authority_calls);
        assert_eq!(
            store.height(),
            1,
            "the runtime committed-height contract is unchanged"
        );
        assert_eq!(fs::read(f.path()).unwrap(), frame);
    }
    drop(occupied);
    assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    assert!(
        f.stores.budget.reserved_bytes() > baseline,
        "successful tip retains the physically funded original ready artifact"
    );
    let ready_reserved = f.stores.budget.reserved_bytes();
    for _ in 0..2 {
        assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
        assert_eq!(
            f.stores.budget.reserved_bytes(),
            ready_reserved,
            "completed tip observation never polls or consumes an already-ready source"
        );
    }
    assert!(
        store.batch_read.lock().is_none(),
        "tip does not replace read custody with a decoded merge batch"
    );
    drop(store);
    f.stores.release_retired(&SumeragiLaneState::default());
    let same = weak
        .upgrade()
        .expect("the original completed read stays pending for its normal consumer");
    assert!(Arc::ptr_eq(
        &same,
        &f.stores.store(LANE, &INCARNATION).unwrap()
    ));
    assert_eq!(f.authorities.calls.load(Ordering::SeqCst), authority_calls);
    drop(same);
    let restored = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(restored.block_hash, f.qc.block_hash);
    assert_eq!(restored.result, f.qc.result);
    assert!(restored.batch.is_some());
    drop(restored);
    f.stores.release_retired(&SumeragiLaneState::default());
    assert!(
        weak.upgrade().is_none(),
        "normal read completion permits final idle retirement"
    );
    assert_eq!(f.stores.budget.reserved_bytes(), baseline);
    assert_eq!(f.stores.budget.limit_bytes(), ceiling);
    assert_eq!(fs::read(f.path()).unwrap(), frame);
    assert_eq!(f.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
}
