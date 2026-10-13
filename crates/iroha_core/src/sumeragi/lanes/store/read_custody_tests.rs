//! Completed native restoration remains original-owned across late namespace refusal.

use super::super::tests::open;
use super::*;
use crate::sumeragi::{crypto::BlsCrypto, lanes::record::tests::fixture, records::NoFaults};
use iroha_sumeragi::{
    crypto::{AggregationError, Crypto},
    types::{AggregateSignature, Hash32, PublicKey, Signature},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct ReplaceAfterAuthenticating {
    inner: BlsCrypto,
    selected: PathBuf,
    retained: PathBuf,
    armed: AtomicBool,
    verified: AtomicUsize,
}
impl Crypto for ReplaceAfterAuthenticating {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        self.inner.hash_chunks(chunks)
    }
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        let valid = self.inner.verify(pk, msg, sig);
        assert!(
            valid,
            "every original availability signature must genuinely verify"
        );
        self.verified.fetch_add(1, Ordering::SeqCst);
        if self.armed.swap(false, Ordering::SeqCst) {
            fs::rename(&self.selected, &self.retained).unwrap();
            fs::create_dir(&self.selected).unwrap();
        }
        valid
    }
    fn aggregate(&self, sigs: &[Signature]) -> Result<AggregateSignature, AggregationError> {
        self.inner.aggregate(sigs)
    }
    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool {
        self.inner.verify_aggregate(pks, msg, agg)
    }
    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        agg: &AggregateSignature,
    ) -> bool {
        self.inner.verify_aggregate_multi(groups, agg)
    }
}

#[test]
fn completed_restoration_retains_its_exact_body_before_switching_requested_heights() {
    let root = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let concrete = Arc::new(ReplaceAfterAuthenticating {
        inner: crypto,
        selected: root.path().join(hex::encode(source.instance().0)),
        retained: root.path().join("original-instance"),
        armed: AtomicBool::new(false),
        verified: AtomicUsize::new(0),
    });
    let crypto: SharedCrypto = concrete.clone();
    let store = open(root.path(), &source, crypto, &budget, Arc::new(NoFaults));
    use crate::sumeragi::driver::traits::BlockStore as _;
    store.append(&body, &qc).unwrap();
    let mut state = store.state.lock();
    state.read = Some(super::super::PendingRead {
        height: 1,
        job: store.restore(1).unwrap(),
        ready: None,
    });
    concrete.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        store
            .read_prepared(&mut state, 2)
            .err()
            .expect("completed original must remain retained")
            .io_kind(),
        io::ErrorKind::Other
    );
    assert!(!concrete.armed.load(Ordering::SeqCst));
    let original = state.read.as_ref().unwrap();
    assert_eq!(original.height, 1);
    assert!(original.ready.is_none());
    let RestoreState::Ready(prepared) = &original.job.state else {
        panic!("all genuine restoration work must already be complete");
    };
    assert_eq!(prepared.body(), &body);
    assert_eq!(prepared.commit_qc(), &qc);
    let pointer = prepared.body().payload().as_slice().as_ptr();
    let charged = budget.reserved_bytes();
    let verified = concrete.verified.load(Ordering::SeqCst);
    assert!(
        verified > 1,
        "the original manifest and real signed rows must all verify"
    );
    assert_eq!(
        store.read_prepared(&mut state, 2).err().unwrap().io_kind(),
        io::ErrorKind::Other
    );
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(concrete.verified.load(Ordering::SeqCst), verified);
    assert_eq!(fs::read_dir(&concrete.selected).unwrap().count(), 0);
    fs::remove_dir(&concrete.selected).unwrap();
    fs::rename(&concrete.retained, &concrete.selected).unwrap();
    let prepared = store.read_prepared(&mut state, 1).unwrap();
    assert_eq!(prepared.body().payload().as_slice().as_ptr(), pointer);
    assert_eq!(prepared.body(), &body);
    assert_eq!(prepared.commit_qc(), &qc);
    assert_eq!(
        concrete.verified.load(Ordering::SeqCst),
        verified,
        "retry must use the already completed original body"
    );
    assert_eq!(budget.reserved_bytes(), charged);
}
