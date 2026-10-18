//! Native signed lane startup recovery must not stall another lane's lifecycle delivery.

use super::*;
use crate::{
    state::WorldReadOnly,
    sumeragi::{
        crypto::{BlsCrypto, KeyPairSigner},
        driver::{
            DriverConfig,
            traits::{Frame, Net, RetiredPublication, SendOutcome},
        },
        lanes::{
            Admission, LaneBatch, LaneChainView, admit,
            global::{AppliedWatch, GlobalAnchors, StatelessChecks},
            lane_genesis_hash, lane_genesis_result, lane_height_config,
            runner::{LaneRunner, LaneRunnerInputs},
        },
        records::{Faults, FileRecordStore, FsStep},
        runtime_availability::NativeLaneStoreAuthorities,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Level,
    account::AccountId,
    isi::Log,
    parameter::Parameter,
    sumeragi_lanes::{SumeragiLanePolicy, SumeragiLaneRecord},
    transaction::{FeePaymentIntent, TransactionBuilder, TransactionEntrypoint},
};
use iroha_sumeragi::{
    availability::{AvailableBody, PayloadAuthoring, PayloadBytes},
    crypto::Signer,
    message::{BlockHeader, Qc, VoteKind},
    types::{AggregateSignature, Bitmap, PublicKey, SIGNATURE_LEN},
};
use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender},
    },
};

const STARTING: LaneId = LaneId::new(7);
const RUNNING: LaneId = LaneId::new(8);

fn add_running_lane(config: &mut TestChainConfig) {
    for parameter in &mut config.genesis_parameters {
        if let Parameter::Custom(custom) = parameter
            && let Some(decoded) = SumeragiLanePolicy::from_custom_parameter(custom)
        {
            let mut policy = decoded.unwrap();
            let mut running = policy.fixed[0].clone();
            running.lane = RUNNING;
            policy.fixed.push(running);
            *custom = policy.into_custom_parameter();
            return;
        }
    }
    panic!("the signed genesis fixture must contain its lane policy");
}

struct CountNativeAuthority {
    original: NativeLaneStoreAuthorities,
    calls: AtomicUsize,
}
impl LaneStoreAuthorities for CountNativeAuthority {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.original.authority(lane, incarnation, instance)
    }
}

/// One real synchronization gate for the exact original authenticated startup frame.
pub struct StartupSyncGate {
    path: PathBuf,
    calls: AtomicUsize,
    entered: SyncSender<()>,
    observed: Mutex<Receiver<()>>,
    resume: Mutex<Receiver<()>>,
    release: Mutex<Option<SyncSender<()>>>,
}
impl StartupSyncGate {
    /// Wait for the real recovery publication to reach its original frame synchronization.
    ///
    /// # Errors
    /// The original synchronization was not reached before the observation timeout, or
    /// its sender disconnected before delivering the observation.
    pub fn wait_entered(&self) -> Result<(), RecvTimeoutError> {
        self.observed.lock().recv_timeout(Duration::from_secs(5))
    }

    /// Release the original native operation exactly once, including during test unwinding.
    pub fn release(&self) {
        let release = self.release.lock().take();
        if let Some(release) = release {
            let _ = release.send(());
        }
    }
}
impl Faults for StartupSyncGate {
    fn before(&self, step: FsStep, path: &Path) -> io::Result<()> {
        if step != FsStep::SyncFile {
            return Ok(());
        }
        if path != self.path {
            return Err(io::Error::other(
                "startup synchronization targeted another native frame",
            ));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.send(()).map_err(io::Error::other)?;
            // The existing five-second gate is cleanup protection, not the progress deadline.
            self.resume
                .lock()
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}
struct ReleaseStartupOnDrop(Arc<StartupSyncGate>);
impl Drop for ReleaseStartupOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Original native startup and a distinct applied lane observed through the real runner.
pub struct StartupRecoveryObservation<'a> {
    /// Actual coordinator; the test supplies only its existing lifecycle thread.
    pub runner: &'a LaneRunner,
    /// The independently activated lane already occupied by an original live driver.
    pub active: (LaneId, [u8; 32]),
    /// Native storage gate selected only after real runtime authority acquisition.
    pub gate: &'a Arc<StartupSyncGate>,
    stores: &'a LaneStores,
    starting: (LaneId, [u8; 32]),
    instance: Hash32,
    original: &'a Mutex<Option<Arc<StoreOpening>>>,
}
impl StartupRecoveryObservation<'_> {
    /// Retain and inspect the actual in-flight opening without waiting on either owner lock.
    #[must_use]
    pub fn original_opening_is_busy(&self) -> bool {
        let opening = {
            let Some(stores) = self.stores.stores.try_lock() else {
                return false;
            };
            let Some(StoreSlot::Opening(opening, false)) = stores.get(&self.starting) else {
                return false;
            };
            Arc::clone(opening)
        };
        let busy = opening.instance == self.instance && opening.progress.try_lock().is_none();
        let replaced = { self.original.lock().replace(opening) };
        drop(replaced);
        busy
    }
}

struct StartupNoPeers;
impl Net for StartupNoPeers {
    fn send(&self, _: &PublicKey, _: &Frame) -> SendOutcome {
        SendOutcome::Rejected
    }
}

fn sign_original_frame(
    record: &SumeragiLaneRecord,
    source: &CertifiedTestChain,
    shared: &SharedCrypto,
    config: &iroha_sumeragi::types::HeightConfig,
    bytes: &[u8],
    result: Hash32,
) -> (AvailableBody, Qc) {
    let budget = source.state().ivm_execution_budget();
    let instance = super::super::lane_instance(
        &**shared,
        &source.network_id(),
        source.state().chain_id_ref().as_ref(),
        record,
    );
    let mut payload = iroha_allocation::ChargedBuffer::new(bytes.len(), &budget).unwrap();
    payload.append(bytes).unwrap();
    let payload = PayloadBytes::from_charged(payload, &budget)
        .unwrap_or_else(|_| panic!("original startup payload backing and control"));
    let mut signers: Vec<_> = (41..45)
        .map(|seed| {
            KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)).unwrap()
        })
        .collect();
    signers.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    let header = BlockHeader {
        instance,
        epoch: config.epoch.id,
        height: 1,
        origin_view: 0,
        parent_hash: lane_genesis_hash(&source.network_id(), record),
        parent_result: lane_genesis_result(record),
        payload_hash: iroha_sumeragi::preimage::payload_hash(&**shared, payload.as_slice()),
        availability_digest: Hash32::ZERO,
        payload_len: u32::try_from(payload.as_slice().len()).unwrap(),
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: iroha_sumeragi::types::ControlWitness::empty(),
    };
    let authored = PayloadAuthoring::new(header, payload)
        .complete(instance, config, &budget, &**shared, &signers[0])
        .unwrap_or_else(|(_, error)| panic!("original signed RS16 startup body: {error:?}"));
    drop(authored.codeword);
    let body = authored.body;
    let mut qc = Qc {
        kind: VoteKind::Commit,
        instance,
        epoch: config.epoch.id,
        height: 1,
        view: 0,
        block_hash: body.hash(&**shared),
        result,
        signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
        agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
    };
    qc.agg_sig = shared
        .aggregate(
            &signers[..3]
                .iter()
                .map(|signer| signer.sign(&qc.preimage()).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    (body, qc)
}

fn original_signed_frame(
    chain: &CertifiedTestChain,
    record: &SumeragiLaneRecord,
    crypto: &Arc<BlsCrypto>,
    root: &Path,
) -> (AvailableBody, Qc, PathBuf) {
    let budget = chain.state().ivm_execution_budget();
    let shared: SharedCrypto = crypto.clone();
    let instance = super::super::lane_instance(
        &*shared,
        &chain.network_id(),
        chain.state().chain_id_ref().as_ref(),
        record,
    );
    let authority = NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::clone(crypto))
        .authority(record.lane, &record.incarnation, instance)
        .unwrap()
        .unwrap();
    let config = lane_height_config(record).unwrap();
    assert_eq!(
        authority.schedule.height_config(1).unwrap(),
        Some(config.clone())
    );
    let anchor = chain.state().view().latest_block_hash().unwrap();
    let anchors = GlobalAnchors::new(
        Arc::clone(chain.state()),
        Arc::new(AppliedWatch::new(chain.height(), Some(anchor))),
    );
    let sender = KeyPair::from_seed(vec![0x57; 32], Algorithm::Ed25519);
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(sender.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(
        Level::INFO,
        "original native startup frame".into(),
    )]);
    builder.set_creation_time(
        chain
            .committed(chain.height())
            .block()
            .header()
            .creation_time(),
    );
    let bytes = LaneBatch {
        anchor_height: chain.height(),
        anchor_hash: anchor,
        transactions: vec![TransactionEntrypoint::External(
            builder.sign(sender.private_key()),
        )],
    }
    .to_payload();
    let Admission::Valid(result) = admit(
        record,
        &anchors,
        &LaneChainView::default(),
        &StatelessChecks::new(chain.network_id()),
        &config,
        &bytes,
    )
    .unwrap() else {
        panic!("the original native lane payload must be intrinsically valid");
    };
    let (body, qc) = sign_original_frame(record, chain, &shared, &config, &bytes, result.hash());
    let store =
        FileLaneBlockStore::begin_open(root, &instance, shared, budget.clone(), authority.schedule)
            .unwrap()
            .complete()
            .unwrap_or_else(|(_, error)| panic!("original frame owner: {error}"));
    let store = Arc::new(store);
    let publication = crate::sumeragi::driver::PublicationSession::start(store.clone(), &budget);
    store.append(&body, &qc).unwrap();
    assert_eq!(store.height(), 1);
    drop(publication);
    drop(store);
    let path = root
        .join(hex::encode(instance.0))
        .join("00000000000000000001.frame");
    (body, qc, path)
}

fn startup_runner(
    chain: &CertifiedTestChain,
    stores: Arc<LaneStores>,
    crypto: Arc<BlsCrypto>,
    queue: Arc<crate::queue::Queue>,
    root: &Path,
) -> LaneRunner {
    LaneRunner::for_retirement_test(LaneRunnerInputs {
        state: Arc::clone(chain.state()),
        queue,
        watch: Arc::new(AppliedWatch::new(
            chain.height(),
            chain.state().view().latest_block_hash(),
        )),
        stores,
        crypto,
        net: Arc::new(StartupNoPeers),
        ingress: None,
        records: Arc::new(
            FileRecordStore::open(root.join("records"), root.join("keys/installation.log"))
                .unwrap(),
        ),
        global_instance: chain.instance(),
        bodies_dir: root.join("bodies"),
        key_pair: KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal),
        local: iroha_config::parameters::actual::SumeragiLocalOverrides::default(),
        driver: DriverConfig::default(),
        network: chain.network_id(),
        chain_id: chain.state().chain_id_ref().to_string(),
    })
}

fn verify_original_startup(
    stores: Arc<LaneStores>,
    starting: (LaneId, [u8; 32]),
    original: Option<Arc<StoreOpening>>,
    frame: (AvailableBody, Qc, PathBuf),
    expected: (Vec<u8>, usize),
    budget: &AllocationBudget,
) {
    // Every lifecycle/driver join has completed before these ownership and causal checks.
    let store = stores.store(starting.0, &starting.1).unwrap();
    let original = original.expect("the native in-flight opening was observed");
    let same = matches!(&*original.progress.lock(), OpeningProgress::Ready(ready) if Arc::ptr_eq(ready, &store));
    drop(original);
    assert!(
        same,
        "startup must publish the exact originally observed opening"
    );
    assert!(RetiredPublication::belongs_to(&*store, budget));
    assert_eq!(store.height(), 1);
    let (replayed_body, replayed_qc) = store.committed_body(1).unwrap().unwrap();
    assert_eq!(replayed_body, frame.0);
    assert_eq!(replayed_qc, frame.1);
    assert_eq!(fs::read(&frame.2).unwrap(), expected.0);
    assert_eq!(budget.limit_bytes(), expected.1);
    drop(stores);
    assert_eq!(
        Arc::strong_count(&store),
        1,
        "all startup driver and registry references to the exact native store must retire"
    );
}

fn finish_original_startup(
    runner: &LaneRunner,
    record: &SumeragiLaneRecord,
    instance: Hash32,
) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        runner.drive_retirement_for_test();
        if runner.instances().iter().any(|lane| {
            lane.lane == record.lane
                && lane.incarnation == record.incarnation
                && lane.instance == instance
        }) {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Observe real startup recovery, then join owners and authenticate the unchanged frame again.
pub fn observe_startup_sync_for_test<R>(
    observe: impl FnOnce(StartupRecoveryObservation<'_>) -> R,
) -> R {
    let (chain, record, _epoch) =
        crate::sumeragi::runtime_availability::tests::fixed_lane_chain_with_config(
            4,
            Some(iroha_data_model::parameter::system::SumeragiNposParameters::default()),
            Arc::new(super::super::merge::NoLanes),
            add_running_lane,
        );
    let active = chain
        .state()
        .view()
        .world()
        .sumeragi_lanes()
        .lane(RUNNING)
        .unwrap()
        .clone();
    assert_eq!(record.lane, STARTING);
    assert!(record.active_from <= chain.height());
    assert!(active.active_from <= chain.height());
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("lanes");
    let crypto = Arc::new(BlsCrypto::new());
    let budget = chain.state().ivm_execution_budget();
    let ceiling = budget.limit_bytes();
    let (body, qc, path) = original_signed_frame(&chain, &record, &crypto, &root);
    let original_bytes = fs::read(&path).unwrap();
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (release, resume) = std::sync::mpsc::sync_channel(1);
    let gate = Arc::new(StartupSyncGate {
        path: path.clone(),
        calls: AtomicUsize::new(0),
        entered,
        observed: Mutex::new(observed),
        resume: Mutex::new(resume),
        release: Mutex::new(Some(release)),
    });
    // A fresh native provider must authenticate the runtime call. No pre-start registry
    // lookup, injected schedule, Ready slot, or constructed Opening can satisfy the latch.
    let authorities = Arc::new(CountNativeAuthority {
        original: NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::clone(&crypto)),
        calls: AtomicUsize::new(0),
    });
    let shared: SharedCrypto = crypto.clone();
    let mut stores = LaneStores::new(
        root,
        chain.network_id(),
        chain.state().chain_id_ref().to_string(),
        shared,
        budget.clone(),
        authorities.clone(),
    );
    let instance = stores.instance(record.lane, &record.incarnation);
    stores.opening_faults = Some((instance, gate.clone()));
    assert!(stores.stores.lock().is_empty());
    assert_eq!(authorities.calls.load(Ordering::SeqCst), 0);
    let stores = Arc::new(stores);
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
    let queue = Arc::new(crate::queue::Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ));
    let reservation = queue.reserve_sumeragi_start(&budget).unwrap();
    let runner = startup_runner(&chain, Arc::clone(&stores), crypto, queue, directory.path());
    let _release = ReleaseStartupOnDrop(Arc::clone(&gate));
    let original = Mutex::new(None);
    let result = observe(StartupRecoveryObservation {
        runner: &runner,
        active: (active.lane, active.incarnation),
        gate: &gate,
        stores: &stores,
        starting: (record.lane, record.incarnation),
        instance,
        original: &original,
    });
    gate.release();
    let started = finish_original_startup(&runner, &record, instance);
    drop(runner);
    drop(reservation);
    assert!(
        started,
        "the same eligible native lane must finish startup after original I/O resumes"
    );
    assert_eq!(authorities.calls.load(Ordering::SeqCst), 1);
    assert_eq!(gate.calls.load(Ordering::SeqCst), 1);
    verify_original_startup(
        stores,
        (record.lane, record.incarnation),
        original.into_inner(),
        (body, qc, path),
        (original_bytes, ceiling),
        &budget,
    );
    result
}
