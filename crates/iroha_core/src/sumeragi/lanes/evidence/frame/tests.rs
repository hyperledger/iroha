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
        .map(|signer| signer.sign(&qc.preimage()))
        .collect();
    qc.agg_sig = crypto.aggregate(&signatures);
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
    let mut read = FundedLaneFrameRead::new(path, source, context.budget.clone());
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
    let mut read = FundedLaneFrameRead::new(path.clone(), source, context.budget.clone());
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
    let mut read = FundedLaneFrameRead::new(path.clone(), source, context.budget.clone());
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
