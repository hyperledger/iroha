//! Actual model/BLS controls for retained registry ownership and fallible merge reads.

use super::*;
use iroha_data_model::transaction::TransactionEntrypoint;

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
    let observed_allocation = original.allocation_refusal().unwrap().clone();
    let Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) =
        original.allocation_refusal()
    else {
        panic!("actual original archive capacity")
    };
    let wait = release.clone();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&wait, &mut context).is_pending());
    assert!(
        matches!(crate::block::BlockValidationError::from(crate::sumeragi::lanes::merge::MergeError::Storage(error)), crate::block::BlockValidationError::ExecutionDeferred(retained) if retained.allocation_refusal() == Some(&observed_allocation))
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
        Self::with_transactions_for_state(valid_batch, transactions, None)
    }
    fn with_transactions_for_state(
        valid_batch: bool,
        transactions: Vec<iroha_data_model::transaction::SignedTransaction>,
        state: Option<&crate::state::State>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (body, mut qc, old_source, fixture_budget, crypto) = fixture(1025);
        let budget = state.map_or(fixture_budget, crate::state::State::ivm_execution_budget);
        let crypto: SharedCrypto = Arc::new(crypto);
        let network = state.map_or_else(
            || {
                NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                    b"registry network",
                )))
            },
            |state| *state.network_id_ref(),
        );
        let chain_id = state.map_or_else(
            || "registry-chain".to_owned(),
            |state| state.chain_id_ref().to_string(),
        );
        let instance = incarnation_instance(&*crypto, &network, &chain_id, LANE, &INCARNATION);
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
                transactions: transactions
                    .into_iter()
                    .map(TransactionEntrypoint::External)
                    .collect(),
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
        qc.agg_sig = crypto
            .aggregate(
                &signers[..3]
                    .iter()
                    .map(|s| s.sign(&qc.preimage()).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
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
            chain_id,
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
                params: iroha_data_model::parameter::system::SumeragiParameters::default(),
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
    let mut destination = Vec::<TransactionEntrypoint>::new();
    destination.try_reserve(1).unwrap();
    let layout =
        std::alloc::Layout::array::<TransactionEntrypoint>(destination.capacity()).unwrap();
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
    assert_eq!(
        completed.batch.unwrap().transactions,
        vec![TransactionEntrypoint::External(transaction)]
    );
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
    let raw =
        usize::try_from(fs::metadata(f.path()).unwrap().len()).expect("fixture value fits usize");
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
        .expect_err("original occupied pool must refuse the same actual demand");
    assert_eq!(original.allocation_refusal(), Some(&original_pool_probe));
    assert!(store.batch_read.lock().is_none());
    for _ in 0..2 {
        let error = f.stores.tip(LANE, &INCARNATION).unwrap_err();
        let Attempt::Deferred(retained) = error else {
            panic!("tip must propagate the same original unfinished local attempt");
        };
        assert_eq!(
            retained.allocation_refusal(),
            original.allocation_refusal(),
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

/// A real original-pool notification probes the registry without blocking on the defect.
struct RegistryRefundProbe {
    fixture: std::sync::Weak<Fixture>,
    calls: AtomicUsize,
    registry_free: AtomicBool,
    reentered: AtomicBool,
    remaining_bytes: AtomicUsize,
}

impl std::task::Wake for RegistryRefundProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fixture = self.fixture.upgrade().unwrap();
        self.remaining_bytes
            .store(fixture.stores.budget.reserved_bytes(), Ordering::SeqCst);
        let guard = fixture.stores.stores.try_lock();
        // Registry ownership includes the per-key recovery guard. A refund cannot
        // run beneath it merely because unrelated map lookups are already available.
        let free = guard.as_ref().is_some_and(|stores| {
            stores
                .get(&(LANE, INCARNATION))
                .is_none_or(|slot| match slot {
                    StoreSlot::Opening(opening, _) => opening.progress.try_lock().is_some(),
                    StoreSlot::Ready(_) => true,
                })
        });
        drop(guard);
        self.registry_free.store(free, Ordering::SeqCst);
        if free {
            fixture.stores.release(LANE, &INCARNATION);
            self.reentered.store(true, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy)]
enum OriginalOpeningCompletion {
    ExplicitRetirement,
    AppliedRetirement,
    Recovery,
}

fn original_opening_refund_control(completion: OriginalOpeningCompletion) {
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::task::{Context, Poll, Waker};

    let fixture = Arc::new(Fixture::new(true));
    fixture.publish();
    let original = fs::read(fixture.path()).unwrap();
    fixture.stores.release(LANE, &INCARNATION);
    let budget = &fixture.stores.budget;
    let initial = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained + original.len());
    assert_eq!(
        fixture
            .stores
            .runtime_store(LANE, &INCARNATION)
            .unwrap_err()
            .io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(budget.reserved_bytes(), retained + original.len());
    assert!(matches!(
        fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Opening(_, false))
    ));
    // Restore the unchanged fixture's original ceiling before registering a fresh refusal.
    // Its real opening still owns the original buffer; no release notification is inherited.
    if matches!(completion, OriginalOpeningCompletion::Recovery) {
        budget.set_limit_bytes(original_limit);
    }
    let AllocationRefusal::Capacity { release, .. } =
        budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
    else {
        panic!("the original registry pool supplies a real capacity refusal");
    };
    let probe = Arc::new(RegistryRefundProbe {
        fixture: Arc::downgrade(&fixture),
        calls: AtomicUsize::new(0),
        registry_free: AtomicBool::new(false),
        reentered: AtomicBool::new(false),
        remaining_bytes: AtomicUsize::new(usize::MAX),
    });
    let waker = Waker::from(probe.clone());
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    let recovered = match completion {
        OriginalOpeningCompletion::ExplicitRetirement => {
            fixture.stores.release(LANE, &INCARNATION);
            None
        }
        OriginalOpeningCompletion::AppliedRetirement => {
            fixture
                .stores
                .release_retired(&SumeragiLaneState::default());
            None
        }
        OriginalOpeningCompletion::Recovery => {
            Some(fixture.stores.runtime_store(LANE, &INCARNATION).unwrap())
        }
    };
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(
        probe.registry_free.load(Ordering::SeqCst),
        "original lane store refund must run after the registry lock releases"
    );
    assert!(probe.reentered.load(Ordering::SeqCst));
    assert_eq!(probe.remaining_bytes.load(Ordering::SeqCst), retained);
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    if let Some(store) = recovered {
        assert_eq!(store.height(), 1);
        assert!(Arc::ptr_eq(
            &store,
            &fixture.stores.runtime_store(LANE, &INCARNATION).unwrap()
        ));
        drop(store);
        fixture.stores.release(LANE, &INCARNATION);
    }
    assert!(fixture.stores.stores.lock().is_empty());
    assert_eq!(fs::read(fixture.path()).unwrap(), original);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), initial);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn original_runtime_opening_explicit_retirement_refunds_after_registry_unlock() {
    original_opening_refund_control(OriginalOpeningCompletion::ExplicitRetirement);
}

#[test]
fn original_runtime_opening_applied_retirement_refunds_after_registry_unlock() {
    original_opening_refund_control(OriginalOpeningCompletion::AppliedRetirement);
}

#[test]
fn original_runtime_opening_recovery_refunds_after_registry_unlock() {
    original_opening_refund_control(OriginalOpeningCompletion::Recovery);
}

struct RunnerRetirementRefundProbe {
    stores: std::sync::Weak<LaneStores>,
    runner: std::sync::Weak<super::super::runner::RetirementControl>,
    calls: AtomicUsize,
    registry_free: AtomicBool,
    running_free: AtomicBool,
    reentered: AtomicBool,
}

impl std::task::Wake for RunnerRetirementRefundProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stores = self.stores.upgrade().unwrap();
        let runner = self.runner.upgrade().unwrap();
        let registry = stores.stores.try_lock();
        let registry_free = registry.is_some();
        drop(registry);
        let running_free = runner.running_lock_available();
        self.registry_free.store(registry_free, Ordering::SeqCst);
        self.running_free.store(running_free, Ordering::SeqCst);
        if registry_free && running_free {
            assert_eq!(runner.running_count(), 0);
            stores.release(LANE, &INCARNATION);
            self.reentered.store(true, Ordering::SeqCst);
        }
    }
}

struct RetirementNoFrames;
impl crate::sumeragi::driver::traits::Net for RetirementNoFrames {
    fn send(
        &self,
        _: &iroha_sumeragi::types::PublicKey,
        _: &crate::sumeragi::driver::traits::Frame,
    ) -> crate::sumeragi::driver::traits::SendOutcome {
        panic!("retired empty topology cannot send a consensus frame")
    }
}

#[test]
fn original_runtime_retirement_refunds_after_registry_and_runner_unlock() {
    use crate::{
        state::{World, WorldReadOnly},
        sumeragi::{
            crypto::BlsCrypto,
            driver::DriverConfig,
            lanes::{
                global::AppliedWatch,
                runner::{LaneRunnerInputs, RetirementControl},
            },
            records::FileRecordStore,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::task::{Context, Poll, Waker};

    let chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 1)).unwrap();
    let state = chain.state().clone();
    assert!(state.view().world().sumeragi_lanes().lanes.is_empty());
    let fixture = Fixture::with_transactions_for_state(true, Vec::new(), Some(&state));
    fixture.publish();
    fixture.stores.release(LANE, &INCARNATION);
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    let budget = state.ivm_execution_budget();
    assert!(budget.same_pool(&fixture.stores.budget));
    let Fixture {
        dir,
        stores,
        body,
        qc,
        source,
        authorities,
    } = fixture;
    let stores = Arc::new(stores);
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
    let runner = Arc::new(RetirementControl::new(LaneRunnerInputs {
        state: state.clone(),
        queue: Arc::new(crate::queue::Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        )),
        watch: Arc::new(AppliedWatch::new(
            chain.height(),
            state.view().latest_block_hash(),
        )),
        stores: stores.clone(),
        crypto: Arc::new(BlsCrypto::new()),
        net: Arc::new(RetirementNoFrames),
        ingress: None,
        records: Arc::new(
            FileRecordStore::open(
                dir.path().join("records"),
                dir.path().join("keys/installation.log"),
            )
            .unwrap(),
        ),
        global_instance: chain.instance(),
        bodies_dir: dir.path().join("bodies"),
        key_pair: KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal),
        local: iroha_config::parameters::actual::SumeragiLocalOverrides::default(),
        driver: DriverConfig::default(),
        network: chain.network_id(),
        chain_id: state.chain_id_ref().to_string(),
    }));
    let original_limit = budget.limit_bytes();
    let initial = budget.reserved_bytes();
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained + original.len());
    assert_eq!(
        stores
            .runtime_store(LANE, &INCARNATION)
            .unwrap_err()
            .io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(budget.reserved_bytes(), retained + original.len());
    let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("the original lane recovery exhausts its actual State pool");
    };
    let probe = Arc::new(RunnerRetirementRefundProbe {
        stores: Arc::downgrade(&stores),
        runner: Arc::downgrade(&runner),
        calls: AtomicUsize::new(0),
        registry_free: AtomicBool::new(false),
        running_free: AtomicBool::new(false),
        reentered: AtomicBool::new(false),
    });
    let waker = Waker::from(probe.clone());
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    runner.reconcile();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(
        probe.registry_free.load(Ordering::SeqCst) && probe.running_free.load(Ordering::SeqCst),
        "original lane retirement refund must wait for both registry and runner unlock"
    );
    assert!(probe.reentered.load(Ordering::SeqCst));
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    assert!(stores.stores.lock().is_empty());
    assert_eq!(runner.running_count(), 0);
    assert_eq!(fs::read(&path).unwrap(), original);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), initial);
    budget.set_limit_bytes(original_limit);
    drop((runner, stores, body, qc, source, authorities, dir));
}

// Actual State reader release observations, independent of allocation refunds.
struct NativeReaderProbe {
    provider: std::sync::Weak<crate::sumeragi::runtime_availability::NativeLaneStoreAuthorities>,
    stores: Option<std::sync::Weak<LaneStores>>,
    lane: LaneId,
    incarnation: [u8; 32],
    instance: Hash32,
    calls: AtomicUsize,
    scan_free: AtomicBool,
    registry_free: AtomicBool,
    state_free: AtomicBool,
    reentered: AtomicBool,
    ready: Mutex<Option<Arc<FileLaneBlockStore>>>,
    acquired: Option<std::sync::mpsc::Sender<()>>,
}
impl std::task::Wake for NativeReaderProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let provider = self.provider.upgrade().unwrap();
        let scan_free = provider.scan_unlocked_for_reader_test();
        self.scan_free.store(scan_free, Ordering::SeqCst);
        let stores = self.stores.as_ref().map(|stores| stores.upgrade().unwrap());
        let registry_free = stores.as_ref().is_none_or(|stores| {
            let guard = stores.stores.try_lock();
            guard.is_some()
        });
        self.registry_free.store(registry_free, Ordering::SeqCst);
        if let Some(acquired) = &self.acquired {
            // The independently held manifest writer is deliberately still busy.
            // Tell its owner to release it; never block this callback on that writer.
            acquired.send(()).unwrap();
        } else if scan_free && registry_free {
            provider.assert_original_state_readers_available_for_test();
            self.state_free.store(true, Ordering::SeqCst);
            if let Some(stores) = stores {
                let ready = stores.runtime_store(self.lane, &self.incarnation).unwrap();
                *self.ready.lock() = Some(ready);
            } else {
                let _ = provider.authority(self.lane, &self.incarnation, self.instance);
            }
            self.reentered.store(true, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy)]
enum NativeReaderCase {
    Present,
    Absent,
    ArchiveError,
    RegistryReentry,
}

fn original_native_reader_control(case: NativeReaderCase) {
    use crate::sumeragi::runtime_availability::NativeLaneStoreAuthorities;
    use iroha_allocation::release::ReleaseRegistration;
    use std::task::{Context, Poll, Waker};

    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let ceiling = budget.limit_bytes();
    let crypto = Arc::new(crate::sumeragi::crypto::BlsCrypto::new());
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(state),
        Arc::clone(&crypto),
    ));
    let stores = Arc::new(LaneStores::new(
        chain.kura().store_root().join("lanes"),
        *state.network_id_ref(),
        state.chain_id_ref().to_string(),
        crypto,
        budget.clone(),
        provider.clone(),
    ));
    let (lane, incarnation) = if matches!(case, NativeReaderCase::Absent) {
        (LaneId::new(99), [99; 32])
    } else {
        (record.lane, record.incarnation)
    };
    let archive = chain.kura().store_root().join("native-contexts");
    let retained = chain
        .kura()
        .store_root()
        .join("reader-held-native-contexts");
    if matches!(case, NativeReaderCase::ArchiveError) {
        fs::rename(&archive, &retained).unwrap();
    }
    let probe = Arc::new(NativeReaderProbe {
        provider: Arc::downgrade(&provider),
        stores: matches!(case, NativeReaderCase::RegistryReentry).then(|| Arc::downgrade(&stores)),
        lane,
        incarnation,
        instance: stores.instance(lane, &incarnation),
        calls: AtomicUsize::new(0),
        scan_free: AtomicBool::new(false),
        registry_free: AtomicBool::new(false),
        state_free: AtomicBool::new(false),
        reentered: AtomicBool::new(false),
        ready: Mutex::new(None),
        acquired: None,
    });
    let mut registration = ReleaseRegistration::from_reservation(
        &mut budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    let release = state.lane_manifests.observe_release();
    let waker = Waker::from(Arc::clone(&probe));
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    drop(state.da_pin_intents.read());
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        0,
        "another original State source cannot wake this reader"
    );
    if matches!(case, NativeReaderCase::RegistryReentry) {
        let outer = stores.runtime_store(lane, &incarnation).unwrap();
        assert!(
            probe.scan_free.load(Ordering::SeqCst) && probe.registry_free.load(Ordering::SeqCst),
            "original State reader notices must follow scan and registry unlock"
        );
        assert!(
            probe
                .ready
                .lock()
                .as_ref()
                .is_some_and(|inner| Arc::ptr_eq(inner, &outer)),
            "authority lookup must retain a reentrant original Ready owner"
        );
    } else {
        let result = provider.authority(lane, &incarnation, probe.instance);
        match case {
            NativeReaderCase::Present => assert!(result.unwrap().is_some()),
            NativeReaderCase::Absent => assert!(result.unwrap().is_none()),
            NativeReaderCase::ArchiveError => {
                assert_ne!(result.err().unwrap().io_kind(), io::ErrorKind::WouldBlock);
                fs::rename(&retained, &archive).unwrap();
            }
            NativeReaderCase::RegistryReentry => unreachable!(),
        }
    }
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(
        probe.scan_free.load(Ordering::SeqCst) && probe.registry_free.load(Ordering::SeqCst),
        "original State reader notices must follow scan and registry unlock"
    );
    assert!(probe.state_free.load(Ordering::SeqCst));
    assert!(probe.reentered.load(Ordering::SeqCst));
    assert_eq!(
        registration.poll_wait(&release, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    assert_eq!(budget.limit_bytes(), ceiling);
}

#[test]
fn original_native_history_reader_success_reenters_after_scan_unlock() {
    original_native_reader_control(NativeReaderCase::Present);
}
#[test]
fn original_native_history_reader_absence_reenters_after_scan_unlock() {
    original_native_reader_control(NativeReaderCase::Absent);
}
#[test]
fn original_native_history_reader_error_reenters_after_scan_unlock() {
    original_native_reader_control(NativeReaderCase::ArchiveError);
}
#[test]
fn original_native_history_reader_reentry_preserves_concurrent_ready_owner() {
    original_native_reader_control(NativeReaderCase::RegistryReentry);
}

#[test]
fn original_native_history_partial_reader_refusal_retains_exact_source_after_unlock() {
    use crate::sumeragi::runtime_availability::NativeLaneStoreAuthorities;
    use std::task::{Context, Waker};
    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
    let state = chain.state();
    let budget = state.ivm_execution_budget();
    let crypto = Arc::new(crate::sumeragi::crypto::BlsCrypto::new());
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(state),
        crypto.clone(),
    ));
    let instance = incarnation_instance(
        &*crypto,
        state.network_id_ref(),
        state.chain_id_ref().as_ref(),
        record.lane,
        &record.incarnation,
    );
    let (acquired, read_acquired) = std::sync::mpsc::channel();
    let probe = Arc::new(NativeReaderProbe {
        provider: Arc::downgrade(&provider),
        stores: None,
        lane: record.lane,
        incarnation: record.incarnation,
        instance,
        calls: AtomicUsize::new(0),
        scan_free: AtomicBool::new(false),
        registry_free: AtomicBool::new(false),
        state_free: AtomicBool::new(false),
        reentered: AtomicBool::new(false),
        ready: Mutex::new(None),
        acquired: Some(acquired),
    });
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let release = state.world.accounts.observe_reader_release();
    let waker = Waker::from(probe.clone());
    assert!(
        registration
            .poll_wait(&release, &mut Context::from_waker(&waker))
            .is_pending()
    );
    let held = state.lane_manifests.write();
    let original_wait = state.lane_manifests.observe_release();
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| provider.authority(record.lane, &record.incarnation, instance));
        let notified = read_acquired.recv_timeout(std::time::Duration::from_secs(30));
        drop(held);
        notified.expect("actual earlier World reader completes before the later manifest writer");
        worker.join().unwrap()
    });
    assert!(
        probe.scan_free.load(Ordering::SeqCst),
        "original State reader notices must follow scan and registry unlock"
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    let error = result
        .err()
        .expect("partial reader acquisition preserves its original refusal");
    let Attempt::Rejected(error) = error else {
        panic!("physical reader refusal keeps its typed IO source")
    };
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    let crate::state::StateViewError::Busy(retained) = error
        .get_ref()
        .unwrap()
        .downcast_ref::<crate::state::StateViewError>()
        .unwrap()
    else {
        panic!("original State reader wait")
    };
    assert_eq!(*retained, original_wait);
    assert!(
        registration
            .poll_wait(&release, &mut Context::from_waker(&waker))
            .is_ready()
    );
    assert!(
        provider
            .authority(record.lane, &record.incarnation, instance)
            .unwrap()
            .is_some()
    );
}

#[test]
fn original_authority_recheck_retains_reentrant_opening_and_historical_interest() {
    struct ReentrantAuthority {
        original: Arc<Authorities>,
        fixture: std::sync::OnceLock<std::sync::Weak<Fixture>>,
        entered: AtomicBool,
        unlocked: AtomicBool,
    }
    impl LaneStoreAuthorities for ReentrantAuthority {
        fn authority(
            &self,
            lane: LaneId,
            incarnation: &[u8; 32],
            instance: Hash32,
        ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
            if !self.entered.swap(true, Ordering::SeqCst) {
                let fixture = self.fixture.get().unwrap().upgrade().unwrap();
                let unlocked = fixture.stores.stores.try_lock().is_some();
                self.unlocked.store(unlocked, Ordering::SeqCst);
                if unlocked {
                    let error = fixture.stores.runtime_store(lane, incarnation).unwrap_err();
                    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
                    assert!(matches!(
                        fixture.stores.stores.lock().get(&(lane, *incarnation)),
                        Some(StoreSlot::Opening(_, false))
                    ));
                }
            }
            self.original.authority(lane, incarnation, instance)
        }
    }
    let mut fixture = Fixture::new(true);
    fixture.publish();
    let bytes = fs::read(fixture.path()).unwrap();
    fixture.stores.release(LANE, &INCARNATION);
    let authority = Arc::new(ReentrantAuthority {
        original: Arc::clone(&fixture.authorities),
        fixture: std::sync::OnceLock::new(),
        entered: AtomicBool::new(false),
        unlocked: AtomicBool::new(false),
    });
    fixture.stores.authorities = authority.clone();
    let fixture = Arc::new(fixture);
    assert!(authority.fixture.set(Arc::downgrade(&fixture)).is_ok());
    let budget = &fixture.stores.budget;
    let ceiling = budget.limit_bytes();
    let baseline = budget.reserved_bytes();
    budget.set_limit_bytes(baseline + bytes.len());
    let error = fixture.stores.store(LANE, &INCARNATION).unwrap_err();
    assert!(
        authority.unlocked.load(Ordering::SeqCst),
        "original State reader notices must follow scan and registry unlock"
    );
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(
        matches!(
            fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Opening(_, true))
        ),
        "historical interest must join the exact reentrant opening"
    );
    assert_eq!(budget.reserved_bytes(), baseline + bytes.len());
    fixture.stores.release(LANE, &INCARNATION);
    assert!(matches!(
        fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
        Some(StoreSlot::Opening(_, true))
    ));
    budget.set_limit_bytes(ceiling);
    let original = fixture.stores.store(LANE, &INCARNATION).unwrap();
    assert_eq!(original.height(), 1);
    assert!(Arc::ptr_eq(
        &original,
        &fixture.stores.runtime_store(LANE, &INCARNATION).unwrap()
    ));
    drop(original);
    fixture.stores.release(LANE, &INCARNATION);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
}

#[path = "isolation_tests.rs"]
mod isolation_tests;
