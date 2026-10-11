//! Real BLS lane store custody, retained opening and no-clobber publication regressions.

use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::{crypto::KeyPairSigner, lanes::record::tests::fixture, records::FsStep};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_sumeragi::{
    crypto::{Crypto, Signer},
    types::{Bitmap, HeightConfig},
};
use std::sync::atomic::{AtomicBool, Ordering};

struct Schedule {
    instance: Hash32,
    config: HeightConfig,
}

#[test]
fn read_only_frame_inspection_authenticates_without_acquiring_store_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let path = store.dir.join(frame_name(1));
    let original = fs::read(&path).unwrap();
    let mut read = LaneFrameRead::open(
        &path,
        1,
        Arc::clone(&crypto),
        budget.clone(),
        schedule(&source),
    )
    .unwrap();
    let (restored, certificate) = read.poll().unwrap();
    assert_eq!(restored, body);
    assert_eq!(certificate, qc);
    assert!(restored.admitted_to(&budget));
    assert!(read.poll().is_err());
    assert_eq!(store.height(), 1);
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn read_only_frame_inspection_retains_original_funding_across_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let path = store.dir.join(frame_name(1));
    let length = usize::try_from(fs::metadata(&path).unwrap().len()).unwrap();
    drop(store);
    drop(body);
    drop(qc);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(length);
    let mut read =
        LaneFrameRead::open(&path, 1, crypto, budget.clone(), schedule(&source)).unwrap();
    for _ in 0..2 {
        let error = read.poll().unwrap_err();
        assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
        assert!(
            matches!(error, Attempt::Deferred(_)),
            "lane refusal must not allocate a diagnostic"
        );
        assert_eq!(budget.reserved_bytes(), length);
    }
    budget.set_limit_bytes(1 << 25);
    let (body, certificate) = read.poll().unwrap();
    assert!(body.admitted_to(&budget));
    assert_eq!(body.source(), &source);
    assert_eq!(certificate.block_hash, source.block_hash());
    drop(body);
    drop(certificate);
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn read_only_frame_inspection_rejects_wrong_height_and_historical_instance() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let path = store.dir.join(frame_name(1));
    for (height, instance) in [(2, source.instance()), (1, Hash32([9; 32]))] {
        let schedule = Arc::new(Schedule {
            instance,
            config: source.config().clone(),
        });
        let mut read =
            LaneFrameRead::open(&path, height, Arc::clone(&crypto), budget.clone(), schedule)
                .unwrap();
        assert_eq!(
            read.poll().unwrap_err().io_kind(),
            io::ErrorKind::InvalidData
        );
    }
}
impl AvailabilitySchedule for Schedule {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, _: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        Ok(Some(self.config.clone()))
    }
}
pub(super) fn schedule(source: &AvailabilitySource) -> Arc<dyn AvailabilitySchedule> {
    Arc::new(Schedule {
        instance: source.instance(),
        config: source.config().clone(),
    })
}
pub(super) fn open(
    path: &Path,
    source: &AvailabilitySource,
    crypto: SharedCrypto,
    budget: &AllocationBudget,
    faults: Arc<dyn Faults>,
) -> FileLaneBlockStore {
    FileLaneBlockStore::begin_open_with_faults(
        path,
        &source.instance(),
        crypto,
        budget.clone(),
        schedule(source),
        faults,
    )
    .unwrap()
    .complete()
    .unwrap_or_else(|(_, e)| panic!("empty valid store: {e}"))
}
struct FailAfterLink {
    armed: AtomicBool,
}
impl Faults for FailAfterLink {
    fn before(&self, step: FsStep, _: &Path) -> io::Result<()> {
        if step == FsStep::SyncDir && self.armed.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected directory durability failure"));
        }
        Ok(())
    }
}
pub(super) fn alternative(qc: &Qc, crypto: &dyn Crypto) -> Qc {
    let mut signers: Vec<_> = (1..=4)
        .map(|seed| {
            KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)).unwrap()
        })
        .collect();
    signers.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let mut other = qc.clone();
    other.signers = Bitmap::from_indices(4, [1, 2, 3]).unwrap();
    other.agg_sig = crypto.aggregate(
        &signers[1..]
            .iter()
            .map(|s| s.sign(&other.preimage()))
            .collect::<Vec<_>>(),
    );
    other
}

#[test]
fn original_publication_retry_is_exact_but_durable_equivalent_quorum_preserves_original() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let faults = Arc::new(FailAfterLink {
        armed: AtomicBool::new(false),
    });
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        faults.clone(),
    );
    faults.armed.store(true, Ordering::SeqCst);
    assert!(store.append(&body, &qc).is_err());
    assert_eq!(store.height(), 0);
    let path = store.dir.join(frame_name(1));
    let original = fs::read(&path).unwrap();
    let pointer = store
        .state
        .lock()
        .write
        .as_mut()
        .unwrap()
        .prepare(&budget)
        .unwrap()
        .as_ptr();
    let other = alternative(&qc, &*crypto);
    assert_eq!(
        store.append(&body, &other).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        store
            .state
            .lock()
            .write
            .as_mut()
            .unwrap()
            .prepare(&budget)
            .unwrap()
            .as_ptr(),
        pointer
    );
    store.append(&body, &qc).unwrap();
    assert_eq!(store.height(), 1);
    store.append(&body, &other).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(store.entry(1).unwrap().unwrap().commit_qc, qc);
}

#[test]
fn startup_and_entry_keep_original_allocations_across_resource_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(23572);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let path = store.dir.join(frame_name(1));
    let raw = fs::metadata(&path).unwrap().len() as usize;
    drop(store);
    drop(body);
    drop(qc);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(raw);
    let start = FileLaneBlockStore::begin_open(
        dir.path(),
        &source.instance(),
        Arc::clone(&crypto),
        budget.clone(),
        schedule(&source),
    )
    .unwrap();
    let (start, error) = start.complete().err().unwrap();
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert_eq!(budget.reserved_bytes(), raw);
    let (start, error) = start.complete().err().unwrap();
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert_eq!(budget.reserved_bytes(), raw);
    assert!(
        FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            Arc::clone(&crypto),
            budget.clone(),
            schedule(&source)
        )
        .is_err()
    );
    budget.set_limit_bytes(1 << 25);
    let store = start
        .complete()
        .unwrap_or_else(|(_, e)| panic!("resumed original startup {e}"));
    assert_eq!(store.height(), 1);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(raw);
    assert_eq!(
        store.entry(1).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(budget.reserved_bytes(), raw);
    assert_eq!(
        store.entry(1).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(budget.reserved_bytes(), raw);
    budget.set_limit_bytes(1 << 25);
    let entry = store.entry(1).unwrap().unwrap();
    assert_eq!(entry.manifest.header.height, 1);
    drop(entry);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn corrupted_or_noncanonical_frame_never_becomes_absent_or_a_recovered_tip() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let path = store.dir.join(frame_name(1));
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        store.entry(1).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        store.entry(1).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    drop(store);
    let start = FileLaneBlockStore::begin_open(
        dir.path(),
        &source.instance(),
        Arc::clone(&crypto),
        budget.clone(),
        schedule(&source),
    )
    .unwrap();
    let (start, e) = start.complete().err().unwrap();
    assert_eq!(e.io_kind(), io::ErrorKind::InvalidData);
    let (_, e) = start.complete().err().unwrap();
    assert_eq!(e.io_kind(), io::ErrorKind::InvalidData);
}

#[test]
fn startup_authenticates_signature_and_requires_exact_commit_quorum() {
    // Authenticate real signatures with too few, exactly enough, and too many equal votes.
    for signer_count in [0, 2, 3, 4] {
        let dir = tempfile::tempdir().unwrap();
        let (body, mut qc, source, budget, crypto) = fixture(1025);
        let crypto: SharedCrypto = Arc::new(crypto);
        let mut signers: Vec<_> = (1..=4)
            .map(|seed| {
                KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
                    .unwrap()
            })
            .collect();
        signers.sort_by(|a, b| a.public_key().cmp(b.public_key()));
        if signer_count == 0 {
            qc.agg_sig.0[0] ^= 1;
            let keys: Vec<_> = signers[..3].iter().map(Signer::public_key).collect();
            assert!(!crypto.verify_aggregate(&keys, &qc.preimage(), &qc.agg_sig));
        } else {
            qc.signers = Bitmap::from_indices(
                4,
                (0..signer_count).map(|index| u32::try_from(index).unwrap()),
            )
            .unwrap();
            let signatures: Vec<_> = signers[..signer_count]
                .iter()
                .map(|signer| signer.sign(&qc.preimage()))
                .collect();
            qc.agg_sig = crypto.aggregate(&signatures);
            let keys: Vec<_> = signers[..signer_count]
                .iter()
                .map(Signer::public_key)
                .collect();
            assert!(crypto.verify_aggregate(&keys, &qc.preimage(), &qc.agg_sig));
        }
        // Place canonical bytes directly: startup must authenticate the complete
        // certificate against its independently selected committee and exact q.
        let mut prepared = PreparedLaneWrite::new(body, qc);
        let bytes = prepared.prepare(&budget).unwrap();
        let root = dir.path().join(hex::encode(source.instance().0));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(frame_name(1));
        fs::write(&path, bytes).unwrap();
        let original = fs::read(&path).unwrap();
        let start = FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            crypto,
            budget.clone(),
            schedule(&source),
        )
        .unwrap();
        if signer_count == 3 {
            let store = start
                .complete()
                .unwrap_or_else(|(_, error)| panic!("exact authenticated quorum: {error}"));
            assert_eq!(store.height(), 1);
            assert!(store.entry(1).unwrap().is_some());
        } else {
            let (start, error) = match start.complete() {
                Err(failure) => failure,
                Ok(_) => panic!("invalid certificate must refuse startup"),
            };
            assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
            let (_, error) = match start.complete() {
                Err(failure) => failure,
                Ok(_) => panic!("same original invalid certificate must still refuse"),
            };
            assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
        }
        assert_eq!(fs::read(path).unwrap(), original);
    }
}

#[test]
fn body_reader_binds_independent_source_and_retains_allocation_refusal() {
    use crate::sumeragi::body_read::BodyReadPoll;
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(retained);
    let mut read = store.begin_read(source.clone()).unwrap();
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    let foreign = AllocationBudget::new(1 << 25);
    assert!(matches!(
        read.poll(&foreign),
        Err(BodyReadError::ForeignBudget)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    budget.set_limit_bytes(1 << 25);
    let Ok(BodyReadPoll::Ready(job)) = read.poll(&budget) else {
        panic!("funded read")
    };
    let restored = job
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("strict body restoration"));
    assert_eq!(restored, body);
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Completed)));
    let wrong = AvailabilitySource::new(
        source.instance(),
        1,
        Hash32([9; 32]),
        source.config().clone(),
    )
    .unwrap();
    let mut read = store.begin_read(wrong).unwrap();
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Io(_))));
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Io(_))));
}

#[test]
fn directory_and_instance_guards_remain_strict() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, source, budget, crypto) = fixture(1);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let sentinel = store.dir.join("active.tmp");
    fs::write(&sentinel, b"original").unwrap();
    assert!(
        FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            Arc::clone(&crypto),
            budget.clone(),
            schedule(&source)
        )
        .is_err()
    );
    assert!(sentinel.exists());
    drop(store);
    let path = dir.path().join(hex::encode(source.instance().0));
    fs::write(path.join("2.frame"), b"bad").unwrap();
    assert!(
        FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            Arc::clone(&crypto),
            budget.clone(),
            schedule(&source)
        )
        .is_err()
    );
    assert!(
        FileLaneBlockStore::begin_open(
            dir.path(),
            &Hash32([9; 32]),
            crypto,
            budget,
            schedule(&source)
        )
        .is_err()
    );
}

fn at_height(
    body: &AvailableBody,
    qc: &Qc,
    source: &AvailabilitySource,
    budget: &AllocationBudget,
    crypto: &dyn Crypto,
    height: u64,
    parent: Hash32,
) -> (AvailableBody, Qc) {
    let mut signers: Vec<_> = (1..=4)
        .map(|seed| {
            KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)).unwrap()
        })
        .collect();
    signers.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let mut header = body.header().clone();
    header.height = height;
    header.parent_hash = parent;
    header.parent_result = qc.result;
    let authored =
        iroha_sumeragi::availability::PayloadAuthoring::new(header, body.payload().clone())
            .complete(
                source.instance(),
                source.config(),
                budget,
                crypto,
                &signers[0],
            )
            .unwrap_or_else(|_| panic!("actual next original lane author"));
    let body = authored.body;
    drop(authored.codeword);
    let mut qc = qc.clone();
    qc.height = height;
    qc.block_hash = body.hash(crypto);
    qc.agg_sig = crypto.aggregate(
        &signers[..3]
            .iter()
            .map(|s| s.sign(&qc.preimage()))
            .collect::<Vec<_>>(),
    );
    (body, qc)
}

#[test]
fn contiguous_heights_context_conflicts_and_reopening_preserve_prior_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let (first, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert_eq!(store.height(), 0);
    for index in 0..3 {
        let mut bad = qc.clone();
        match index {
            0 => bad.instance = Hash32([9; 32]),
            1 => bad.epoch.context = Hash32([9; 32]),
            2 => bad.height = 2,
            _ => unreachable!(),
        };
        assert!(store.append(&first, &bad).is_err());
        assert_eq!(store.height(), 0);
    }
    store.append(&first, &qc).unwrap();
    store.append(&first, &qc).unwrap();
    let (gap, gap_qc) = at_height(
        &first,
        &qc,
        &source,
        &budget,
        &*crypto,
        3,
        first.hash(&*crypto),
    );
    assert!(store.append(&gap, &gap_qc).is_err());
    assert_eq!(store.height(), 1);
    let (second, second_qc) = at_height(
        &first,
        &qc,
        &source,
        &budget,
        &*crypto,
        2,
        first.hash(&*crypto),
    );
    store.append(&second, &second_qc).unwrap();
    assert!(store.wait_for(2, Duration::ZERO));
    assert!(!store.wait_for(3, Duration::ZERO));
    assert_eq!(
        store
            .availability_source(1, qc.block_hash)
            .unwrap()
            .unwrap(),
        source
    );
    let (other, other_qc) = at_height(&first, &qc, &source, &budget, &*crypto, 2, Hash32([7; 32]));
    assert!(store.append(&other, &other_qc).is_err());
    let mut invalid_qc = gap_qc;
    invalid_qc.block_hash = Hash32([8; 32]);
    assert!(store.append(&gap, &invalid_qc).is_err());
    drop(store);
    let reopened = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert_eq!(reopened.height(), 2);
    assert_eq!(
        reopened.entry(2).unwrap().unwrap().manifest.header,
        *second.header()
    );
    assert!(reopened.entry(0).unwrap().is_none());
    assert!(reopened.entry(3).unwrap().is_none());
}

struct FailBeforeLink(AtomicBool);
impl Faults for FailBeforeLink {
    fn before(&self, step: FsStep, _: &Path) -> io::Result<()> {
        if step == FsStep::Rename && self.0.swap(false, Ordering::SeqCst) {
            Err(io::Error::other("injected pre-publication failure"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn prepublication_failure_has_no_frame_and_noncontiguous_directory_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(FailBeforeLink(AtomicBool::new(true))),
    );
    assert!(store.append(&body, &qc).is_err());
    assert_eq!(store.height(), 0);
    assert!(!store.dir.join(frame_name(1)).exists());
    assert_eq!(
        fs::read_dir(&store.dir).unwrap().count(),
        1,
        "only ownership file remains"
    );
    drop(store);
    let reopened = open(
        dir.path(),
        &source,
        Arc::clone(&crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert_eq!(reopened.height(), 0);
    reopened.append(&body, &qc).unwrap();
    assert_eq!(reopened.height(), 1);
    drop(reopened);
    let gapdir = tempfile::tempdir().unwrap();
    let frames = gapdir.path().join(hex::encode(source.instance().0));
    fs::create_dir_all(&frames).unwrap();
    fs::write(frames.join(frame_name(2)), b"not contiguous").unwrap();
    assert!(
        FileLaneBlockStore::begin_open(
            gapdir.path(),
            &source.instance(),
            crypto,
            budget,
            schedule(&source)
        )
        .is_err()
    );
}

#[test]
fn committed_body_preserves_authentication_and_original_pool_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(4097);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert!(store.committed_body(1).unwrap().is_none());
    store.append(&body, &qc).unwrap();
    let (restored, certificate) = store.committed_body(1).unwrap().unwrap();
    assert_eq!(restored, body);
    assert_eq!(certificate, qc);
    assert!(restored.admitted_to(&budget));
    assert!(store.state.lock().read.is_none());
    assert!(store.committed_body(0).unwrap().is_none());
    let mut wrong_result = qc.clone();
    wrong_result.result = Hash32([0x33; 32]);
    let wrong_result = alternative(&wrong_result, &*store.crypto);
    assert_eq!(
        store.append(&body, &wrong_result).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert!(
        store.state.lock().read.is_none(),
        "rejected incoming decision cannot pin completed original read"
    );
    assert_eq!(store.committed_body(1).unwrap().unwrap().0, body);
}

#[test]
fn append_rejects_body_from_another_committee_even_with_a_valid_store_commit_qc() {
    use iroha_sumeragi::{availability::BodyRestoration, crypto::Verifier, types::Committee};
    let dir = tempfile::tempdir().unwrap();
    let (body, mut qc, original, budget, crypto) = fixture(1025);
    let mut members: Vec<_> = (11..=14)
        .map(|seed| {
            let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            crypto
                .admit(
                    pair.public_key(),
                    &iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
                )
                .unwrap();
            KeyPairSigner::new(&pair).unwrap()
        })
        .collect();
    members.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let mut authorized = original.config().clone();
    authorized.committee = Committee::new(
        members
            .iter()
            .map(|signer| signer.public_key().clone())
            .collect(),
    )
    .unwrap();
    // The original body was authored using a copied epoch identity with foreign committee A.
    // The store's independent authority is committee B. B's valid QC is not A's author proof.
    let source = AvailabilitySource::new(
        original.instance(),
        original.height(),
        original.block_hash(),
        authorized,
    )
    .unwrap();
    qc.agg_sig = crypto.aggregate(
        &members[..3]
            .iter()
            .map(|signer| signer.sign(&qc.preimage()))
            .collect::<Vec<_>>(),
    );
    assert!(
        Verifier::new(
            &crypto,
            &source.instance(),
            &source.config().epoch.id,
            &source.config().committee,
        )
        .verify_commit_qc(&qc, Some(body.header()))
    );
    let (_, error) = BodyRestoration::new(
        source.clone(),
        body.header().clone(),
        body.availability().clone(),
        body.payload().clone(),
    )
    .complete(&budget, &crypto)
    .err()
    .expect("foreign author must fail independent restoration");
    assert!(!error.is_local_refusal());
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert_eq!(
        store
            .append(&body, &qc)
            .expect_err("foreign verified context must not become durable")
            .io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(store.height(), 0);
    assert!(!store.dir.join(frame_name(1)).exists());
}

#[test]
fn committed_body_moves_the_exact_completed_read_without_metadata_clone_or_readmission() {
    let directory = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let store = open(
        directory.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    store.append(&body, &qc).unwrap();
    drop(body);
    drop(qc);
    assert_eq!(budget.reserved_bytes(), 0);
    let (payload, epoch) = {
        let mut state = store.state.lock();
        let prepared = store.read_prepared(&mut state, 1).unwrap();
        (
            prepared.body().payload().as_slice().as_ptr(),
            std::ptr::from_ref(&*prepared.body().source().config().epoch),
        )
    };
    let retained = budget.reserved_bytes();
    assert!(retained > 0);
    budget.set_limit_bytes(0);
    let (body, qc) = store.committed_body(1).unwrap().unwrap();
    assert_eq!(body.payload().as_slice().as_ptr(), payload);
    assert_eq!(std::ptr::from_ref(&*body.source().config().epoch), epoch);
    assert!(body.admitted_to(&budget));
    assert!(store.state.lock().read.is_none());
    assert_eq!(budget.reserved_bytes(), retained);
    drop(body);
    drop(qc);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cancelled_lane_read_finishes_original_custody_before_a_different_height() {
    for invalid_certificate in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (first, first_qc, source, budget, crypto) = fixture(1025);
        let crypto: SharedCrypto = Arc::new(crypto);
        let store = open(
            dir.path(),
            &source,
            Arc::clone(&crypto),
            &budget,
            Arc::new(NoFaults),
        );
        let (second, second_qc) = at_height(
            &first,
            &first_qc,
            &source,
            &budget,
            &*crypto,
            2,
            source.block_hash(),
        );
        let second_hash = second_qc.block_hash;
        store.append(&first, &first_qc).unwrap();
        store.append(&second, &second_qc).unwrap();
        let path = store.dir.join(frame_name(1));
        if invalid_certificate {
            let mut forged = first_qc.clone();
            forged.result = Hash32([0xEE; 32]);
            let mut frame = PreparedLaneWrite::new(first.clone(), forged);
            fs::write(&path, frame.prepare(&budget).unwrap()).unwrap();
        }
        drop((first, first_qc, second, second_qc));
        assert_eq!(budget.reserved_bytes(), 0);
        let raw = usize::try_from(fs::metadata(path).unwrap().len()).unwrap();
        budget.set_limit_bytes(raw);
        assert_eq!(
            store.committed_body(1).unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(budget.reserved_bytes(), raw);
        // The worker can cancel height one while this store still owns its refused read.
        // New metadata and payload requests must preserve that owner until it completes.
        assert_eq!(
            store.entry(2).unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(store.state.lock().read.as_ref().unwrap().height, 1);
        assert_eq!(budget.reserved_bytes(), raw);
        budget.set_limit_bytes(1 << 25);
        if invalid_certificate {
            assert_eq!(
                store.committed_body(2).unwrap_err().io_kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(store.state.lock().read.as_ref().unwrap().height, 1);
        } else {
            let (body, certificate) = store.committed_body(2).unwrap().unwrap();
            assert_eq!(body.source().height(), 2);
            assert_eq!(certificate.block_hash, second_hash);
            assert!(body.admitted_to(&budget));
            assert!(store.state.lock().read.is_none());
            drop((body, certificate));
            assert_eq!(budget.reserved_bytes(), 0);
            let first_again = store.entry(1).unwrap().unwrap();
            assert_eq!(first_again.commit_qc.block_hash, source.block_hash());
            drop(first_again);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}
