//! Real BLS frames and original-pool configuration/source ownership through refusal and failure.
use super::*;
use crate::{
    state::StateReadOnly,
    sumeragi::{
        crypto::{BlsCrypto, KeyPairSigner},
        lanes::record::PreparedLaneWrite,
        runtime_availability::history::{HistoryCapture, HistoryScan, LaneEvidenceContext},
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_sumeragi::{
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::Signer,
    message::{BlockHeader, VoteKind},
    types::{AggregateSignature, Bitmap, ControlWitness, SIGNATURE_LEN},
};

fn context() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    LaneEvidenceContext,
    crossbeam_epoch::Guard,
) {
    let (chain, record, epoch) =
        crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(3);
    let state = chain.state();
    let generation = state.state_view_generation();
    let (capture, scope) = {
        let view = state.view();
        let tip = view.native_execution_tip().unwrap();
        (
            HistoryCapture::from_view(state, &view, generation)
                .unwrap()
                .unwrap(),
            iroha_data_model::block::consensus::LaneEvidenceScope {
                lane: record.lane,
                incarnation: record.incarnation,
                created_at: record.created_at,
                admission_parent_height: tip.height(),
                admission_parent_hash: tip.iroha_hash(),
                admission_parent_core_hash: tip.core_hash().0,
                admission_parent_result: tip.result().0,
            },
        )
    };
    let mut read = HistoryScan::open_for_evidence(capture, scope).unwrap();
    read.complete().unwrap();
    let context = read
        .finish_evidence()
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    (chain, context, epoch)
}

fn frame(
    context: &LaneEvidenceContext,
    path: &std::path::Path,
    invalid_signature: bool,
) -> (Hash32, BlsCrypto) {
    let crypto = BlsCrypto::new();
    let mut keys: Vec<_> = (41..45)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    keys.sort_by_key(|key| crate::sumeragi::crypto::core_key(key.public_key()).unwrap());
    for key in &keys {
        crypto
            .admit(
                key.public_key(),
                &iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            )
            .unwrap();
    }
    let signers: Vec<_> = keys
        .iter()
        .map(|key| KeyPairSigner::new(key).unwrap())
        .collect();
    let mut payload = PayloadBytes::from_untrusted(vec![3; 33]).unwrap();
    payload.admit(&context.budget).unwrap();
    let genesis = context.authority.genesis();
    let header = BlockHeader {
        instance: context.instance,
        epoch: context.authority.config().epoch.id,
        height: 1,
        origin_view: 0,
        parent_hash: Hash32(genesis.block_hash),
        parent_result: Hash32(genesis.result),
        payload_hash: iroha_sumeragi::preimage::payload_hash(&crypto, payload.as_slice()),
        availability_digest: Hash32::ZERO,
        payload_len: 33,
        proposer: 0,
        skipped_leaders: Vec::new(),
        control_witness: ControlWitness::empty(),
    };
    let authored = PayloadAuthoring::new(header, payload)
        .complete(
            context.instance,
            context.authority.config(),
            &context.budget,
            &crypto,
            &signers[0],
        )
        .unwrap_or_else(|_| panic!("original signed frame"));
    let hash = authored.body.hash(&crypto);
    let mut qc = Qc {
        kind: VoteKind::Commit,
        instance: context.instance,
        epoch: context.authority.config().epoch.id,
        height: 1,
        view: 0,
        block_hash: hash,
        result: Hash32([73; 32]),
        signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
        agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
    };
    let signatures: Vec<_> = signers[..3]
        .iter()
        .map(|signer| signer.sign(&qc.preimage()).unwrap())
        .collect();
    qc.agg_sig = crypto.aggregate(&signatures).unwrap();
    if invalid_signature {
        qc.agg_sig.0[0] ^= 1;
    }
    let mut prepared = PreparedLaneWrite::new(authored.body, qc);
    std::fs::write(path, prepared.prepare(&context.budget).unwrap()).unwrap();
    (hash, crypto)
}

#[test]
fn funded_lane_frame_retains_config_and_exact_source_through_original_pool_refusal() {
    let (_chain, context, _epoch) = context();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("00000000000000000001.frame");
    let (hash, crypto) = frame(&context, &path, false);
    let baseline = context.budget.reserved_bytes();
    let config = context.authority.copy_config(&context.budget).unwrap();
    let pointer = std::ptr::from_ref(config.get().epoch.as_ref());
    let charged = context.budget.reserved_bytes();
    let source = FundedLaneSource::new(config, context.instance, 1, hash, &context.budget)
        .unwrap_or_else(|_| panic!("original source"));
    let mut read = FundedLaneFrameRead::new(
        iroha_fs::OwnerDirectory::open(path.parent().unwrap()).unwrap(),
        source,
        context.budget.clone(),
    );
    let foreign = AllocationBudget::new(context.budget.limit_bytes());
    assert_eq!(
        read.poll(&foreign, &crypto).err().unwrap().io_kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(foreign.reserved_bytes(), 0);
    context.budget.set_limit_bytes(charged);
    let error = read
        .poll(&context.budget, &crypto)
        .err()
        .expect("raw backing denied");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(matches!(error, Attempt::Deferred(_)));
    assert_eq!(context.budget.reserved_bytes(), charged);
    assert_eq!(
        std::ptr::from_ref(
            read.source
                .as_ref()
                .unwrap()
                .0
                .get()
                .config()
                .epoch
                .as_ref()
        ),
        pointer
    );
    context.budget.set_limit_bytes(1 << 30);
    let original = read.poll(&context.budget, &crypto).unwrap();
    assert_eq!(
        std::ptr::from_ref(original.body.source().config().epoch.as_ref()),
        pointer
    );
    assert_eq!(original.body.source().block_hash(), hash);
    assert_eq!(original.qc.block_hash, hash);
    assert!(original.body.admitted_to(&context.budget));
    assert_eq!(
        read.poll(&context.budget, &crypto).err().unwrap().io_kind(),
        io::ErrorKind::InvalidInput
    );
    drop(original);
    drop(read);
    assert_eq!(context.budget.reserved_bytes(), baseline);
}

#[test]
fn funded_lane_source_foreign_pool_returns_the_identical_configuration_owner() {
    let (_chain, context, _epoch) = context();
    let baseline = context.budget.reserved_bytes();
    let config = context.authority.copy_config(&context.budget).unwrap();
    let pointer = std::ptr::from_ref(config.get().epoch.as_ref());
    let charged = context.budget.reserved_bytes();
    let foreign = AllocationBudget::new(context.budget.limit_bytes());
    let (config, error) =
        FundedLaneSource::new(config, context.instance, 1, Hash32::ZERO, &foreign)
            .err()
            .expect("foreign source funding");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(context.budget.reserved_bytes(), charged);
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(std::ptr::from_ref(config.get().epoch.as_ref()), pointer);
    drop(config);
    assert_eq!(context.budget.reserved_bytes(), baseline);
}

#[test]
fn funded_lane_frame_retains_original_invalid_certificate_after_file_replacement() {
    let (_chain, context, _epoch) = context();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("00000000000000000001.frame");
    let (hash, crypto) = frame(&context, &path, true);
    let baseline = context.budget.reserved_bytes();
    let config = context.authority.copy_config(&context.budget).unwrap();
    let pointer = std::ptr::from_ref(config.get().epoch.as_ref());
    let source = FundedLaneSource::new(config, context.instance, 1, hash, &context.budget)
        .unwrap_or_else(|_| panic!("original independent source"));
    let mut read = FundedLaneFrameRead::new(
        iroha_fs::OwnerDirectory::open(path.parent().unwrap()).unwrap(),
        source,
        context.budget.clone(),
    );
    assert_eq!(
        read.poll(&context.budget, &crypto).err().unwrap().io_kind(),
        io::ErrorKind::InvalidData
    );
    let held = context.budget.reserved_bytes();
    assert_eq!(frame(&context, &path, false).0, hash);
    assert_eq!(
        read.poll(&context.budget, &crypto).err().unwrap().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(context.budget.reserved_bytes(), held);
    assert_eq!(
        std::ptr::from_ref(
            read.source
                .as_ref()
                .unwrap()
                .0
                .get()
                .config()
                .epoch
                .as_ref()
        ),
        pointer
    );
    drop(read);
    assert_eq!(context.budget.reserved_bytes(), baseline);
}

#[test]
fn funded_lane_frame_outer_decode_refusal_retries_the_same_original_bytes() {
    let (_chain, context, _epoch) = context();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("00000000000000000001.frame");
    let (hash, crypto) = frame(&context, &path, false);
    let baseline = context.budget.reserved_bytes();
    let config = context.authority.copy_config(&context.budget).unwrap();
    let pointer = std::ptr::from_ref(config.get().epoch.as_ref());
    let source = FundedLaneSource::new(config, context.instance, 1, hash, &context.budget)
        .unwrap_or_else(|_| panic!("original selected configuration"));
    let mut read = FundedLaneFrameRead::new(
        iroha_fs::OwnerDirectory::open(path.parent().unwrap()).unwrap(),
        source,
        context.budget.clone(),
    );
    let error = norito::core::with_decode_limits_scope(
        norito::core::DecodeLimits::new(1, 1, 1, 1, 1),
        || read.poll(&context.budget, &crypto),
    )
    .err()
    .expect("outer scope refuses the valid original frame");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(matches!(error, Attempt::Deferred(_)));
    assert!(context.budget.reserved_bytes() > baseline);
    // Completion has already acquired the original raw file. A later replacement cannot
    // provide authority or make the retained decode depend on fresh source bytes.
    std::fs::write(path, [0; 16]).unwrap();
    let original = read.poll(&context.budget, &crypto).unwrap();
    assert_eq!(original.body.source().block_hash(), hash);
    assert_eq!(
        std::ptr::from_ref(original.body.source().config().epoch.as_ref()),
        pointer
    );
    assert!(original.body.admitted_to(&context.budget));
    drop(original);
    drop(read);
    assert_eq!(context.budget.reserved_bytes(), baseline);
}

#[cfg(unix)]
struct ReplaceNativeDirectoryAfterAuthentication {
    inner: BlsCrypto,
    selected: std::path::PathBuf,
    retained: std::path::PathBuf,
    armed: std::sync::atomic::AtomicBool,
    verified: std::sync::atomic::AtomicUsize,
}
#[cfg(unix)]
impl Crypto for ReplaceNativeDirectoryAfterAuthentication {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        self.inner.hash_chunks(chunks)
    }
    fn verify(
        &self,
        pk: &iroha_sumeragi::types::PublicKey,
        msg: &[u8],
        sig: &iroha_sumeragi::types::Signature,
    ) -> bool {
        use std::sync::atomic::Ordering;
        let valid = self.inner.verify(pk, msg, sig);
        assert!(valid, "actual original availability signature");
        self.verified.fetch_add(1, Ordering::SeqCst);
        if self.armed.swap(false, Ordering::SeqCst) {
            std::fs::rename(&self.selected, &self.retained).unwrap();
            std::fs::create_dir(&self.selected).unwrap();
        }
        valid
    }
    fn aggregate(
        &self,
        sigs: &[iroha_sumeragi::types::Signature],
    ) -> Result<AggregateSignature, iroha_sumeragi::crypto::AggregationError> {
        self.inner.aggregate(sigs)
    }
    fn verify_aggregate(
        &self,
        pks: &[&iroha_sumeragi::types::PublicKey],
        msg: &[u8],
        agg: &AggregateSignature,
    ) -> bool {
        self.inner.verify_aggregate(pks, msg, agg)
    }
    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&iroha_sumeragi::types::PublicKey>, Vec<u8>)],
        agg: &AggregateSignature,
    ) -> bool {
        self.inner.verify_aggregate_multi(groups, agg)
    }
}

#[test]
#[cfg(unix)]
fn funded_lane_frame_late_namespace_refusal_retains_completed_original_body() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (_chain, context, _epoch) = context();
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("original-instance");
    std::fs::create_dir(&selected).unwrap();
    let path = selected.join("00000000000000000001.frame");
    let (hash, inner) = frame(&context, &path, false);
    let baseline = context.budget.reserved_bytes();
    let limit = context.budget.limit_bytes();
    let config = context.authority.copy_config(&context.budget).unwrap();
    let pointer = std::ptr::from_ref(config.get().epoch.as_ref());
    let source = FundedLaneSource::new(config, context.instance, 1, hash, &context.budget)
        .unwrap_or_else(|_| panic!("original independent source"));
    let mut read = FundedLaneFrameRead::new(
        iroha_fs::OwnerDirectory::open(path.parent().unwrap()).unwrap(),
        source,
        context.budget.clone(),
    );
    let crypto = ReplaceNativeDirectoryAfterAuthentication {
        inner,
        selected,
        retained: root.path().join("retained-instance"),
        armed: AtomicBool::new(true),
        verified: AtomicUsize::new(0),
    };
    let error = read
        .poll(&context.budget, &crypto)
        .err()
        .expect("original native lane namespace must remain retained");
    assert_eq!(error.io_kind(), io::ErrorKind::Other);
    assert!(!crypto.armed.load(Ordering::SeqCst));
    let verified = crypto.verified.load(Ordering::SeqCst);
    assert!(
        verified > 1,
        "actual manifest and row authentication completed"
    );
    let Stage::Ready(complete) = &read.stage else {
        panic!("late refusal retains the completed original body");
    };
    let body_pointer = complete.body.payload().as_slice().as_ptr();
    let held = context.budget.reserved_bytes();
    assert!(held > baseline);
    context.budget.set_limit_bytes(held);
    assert_eq!(
        read.poll(&context.budget, &crypto).err().unwrap().io_kind(),
        io::ErrorKind::Other
    );
    assert_eq!(crypto.verified.load(Ordering::SeqCst), verified);
    assert_eq!(context.budget.reserved_bytes(), held);
    std::fs::remove_dir(&crypto.selected).unwrap();
    std::fs::rename(&crypto.retained, &crypto.selected).unwrap();
    let original = read.poll(&context.budget, &crypto).unwrap();
    assert_eq!(
        std::ptr::from_ref(original.body.source().config().epoch.as_ref()),
        pointer
    );
    assert_eq!(original.body.source().block_hash(), hash);
    assert_eq!(original.body.payload().as_slice().as_ptr(), body_pointer);
    assert_eq!(original.qc.block_hash, hash);
    assert!(original.body.admitted_to(&context.budget));
    assert_eq!(crypto.verified.load(Ordering::SeqCst), verified);
    assert_eq!(context.budget.reserved_bytes(), held);
    assert_eq!(
        read.poll(&context.budget, &crypto).err().unwrap().io_kind(),
        io::ErrorKind::InvalidInput
    );
    context.budget.set_limit_bytes(limit);
    drop(original);
    drop(read);
    assert_eq!(context.budget.reserved_bytes(), baseline);
}
