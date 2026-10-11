//! Global availability binds signed genesis and configured chain to the global instance.
use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_sumeragi::preimage::{InstanceKind, instance_id};
#[test]
fn constructor_binds_authenticated_genesis_and_chain_to_the_global_instance() {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let state = chain.state().clone();
    let crypto = Arc::new(BlsCrypto::new());
    let genesis = crate::sumeragi::startup::core_hash_of(chain.genesis());
    let chain_id = state.chain_id_ref().to_string();
    assert_eq!(genesis.0, *state.network_id_ref().as_bytes());
    for (genesis, chain_id) in [
        (Hash32([0xab; 32]), chain_id.as_bytes()),
        (genesis, b"another-chain".as_slice()),
    ] {
        let wrong = instance_id(&*crypto, &genesis, chain_id, InstanceKind::Global, 0);
        assert_ne!(wrong, chain.instance());
        assert!(NativeGlobalAvailability::new(state.clone(), wrong, crypto.clone()).is_err());
    }
    let provider = NativeGlobalAvailability::new(state, chain.instance(), crypto).unwrap();
    assert_eq!(provider.instance(), chain.instance());
    assert!(provider.height_config(1).unwrap().is_none());
    assert!(provider.height_config(2).unwrap().is_some());
}

#[test]
fn historical_schedule_comes_from_native_execution_ancestry_without_rechecking_local_qcs() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let expected = {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let parent = reader.certified(2).unwrap();
        let ScheduledSlot::Ready(config) = &parent.committed().commitment().schedule.next else {
            panic!("exact parent schedule")
        };
        config.height_config().unwrap()
    };
    let provider = NativeGlobalAvailability::new(
        chain.state().clone(),
        chain.instance(),
        Arc::new(BlsCrypto::new()),
    )
    .unwrap();
    let (result, counts) =
        crate::sumeragi::certified_chain::relation_counts::measure(|| provider.height_config(3));
    assert_eq!(result.unwrap(), Some(expected));
    assert!(
        counts.qcs.is_empty(),
        "local quorum bytes are not native execution authority"
    );
    assert!(
        counts.frames.contains(&2),
        "actual authenticated parent frame must be read"
    );
}

pub(super) fn fixed_lane_chain() -> (
    CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    fixed_lane_chain_at(4)
}

pub(super) fn fixed_lane_chain_at(
    height: u64,
) -> (
    CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    fixed_lane_chain_with_policy(height, false)
}

pub(in crate::sumeragi) fn npos_fixed_lane_chain_at(
    height: u64,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    fixed_lane_chain_with_policy(height, true)
}

fn fixed_lane_chain_with_policy(
    height: u64,
    npos: bool,
) -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    fixed_lane_chain_with_source(
        height,
        npos,
        Arc::new(crate::sumeragi::lanes::merge::NoLanes),
    )
}

pub(in crate::sumeragi) fn fixed_lane_chain_with_source(
    height: u64,
    npos: bool,
    source: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
) -> (
    CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    fixed_lane_chain_with_source_and_policy(
        height,
        npos.then(iroha_data_model::parameter::system::SumeragiNposParameters::default),
        source,
    )
}

pub(in crate::sumeragi) fn fixed_lane_chain_with_source_and_policy(
    height: u64,
    npos: Option<iroha_data_model::parameter::system::SumeragiNposParameters>,
    source: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
) -> (
    CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    fixed_lane_chain_with_config(height, npos, source, |_| {})
}

pub(in crate::sumeragi) fn fixed_lane_chain_with_config(
    height: u64,
    npos: Option<iroha_data_model::parameter::system::SumeragiNposParameters>,
    source: Arc<dyn crate::sumeragi::lanes::merge::LaneBlockSource>,
    configure: fn(&mut TestChainConfig),
) -> (
    CertifiedTestChain,
    iroha_data_model::sumeragi_lanes::SumeragiLaneRecord,
    crossbeam_epoch::Guard,
) {
    // Fixture publications retire charged State generations into the shared collector.
    // Retain their real EBR lifetime through each exact baseline assertion, including when
    // unrelated Rayon work collects epochs. Reader buffers/shared controls reclaim directly.
    let epoch = crossbeam_epoch::pin();
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        parameter::Parameter,
        sumeragi_lanes::{SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy},
    };
    use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
    let mut members = (41..45)
        .map(|seed| {
            let key = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            SumeragiLaneMember {
                peer: PeerId::new(key.public_key().clone()),
                pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            }
        })
        .collect::<Vec<_>>();
    members.sort_by(|a, b| a.peer.cmp(&b.peer));
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 4,
        max_merge_blocks: 16,
        stall_window: 10_000,
        lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: LaneId::new(7),
            dataspace: DataSpaceId::new(0),
            committee: members,
        }],
        routes: Vec::new(),
        autoscale: None,
    };
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.lane_blocks = source;
    if let Some(parameters) = npos {
        use iroha_data_model::parameter::system::SumeragiConsensusMode;
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config
            .genesis_parameters
            .push(Parameter::Custom(parameters.into_custom_parameter()));
    }
    config
        .genesis_parameters
        .push(Parameter::Custom(policy.into_custom_parameter()));
    configure(&mut config);
    let mut chain = CertifiedTestChain::start(config).unwrap();
    for _ in 1..height {
        chain.commit(Vec::new());
    }
    let record = chain
        .state()
        .view()
        .world()
        .sumeragi_lanes()
        .lane(LaneId::new(7))
        .unwrap()
        .clone();
    (chain, record, epoch)
}

#[test]
fn historical_lane_authority_retains_original_creation_bytes_and_prepaid_config_until_drop() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let original = chain.committed(2);
    let budget = chain.state().ivm_execution_budget();
    let before = budget.reserved_bytes();
    let crypto = Arc::new(BlsCrypto::new());
    let instance = super::super::lanes::lane_instance(
        &*crypto,
        &chain.network_id(),
        &chain.state().chain_id_ref().to_string(),
        &record,
    );
    let provider = NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::clone(&crypto));
    let owner = provider
        .authority(record.lane, &record.incarnation, instance)
        .unwrap()
        .unwrap();
    assert!(
        budget.reserved_bytes() > before,
        "installed schedule must keep original bytes and every selected config charge"
    );
    assert_eq!(
        owner.schedule.height_config(1).unwrap().unwrap(),
        super::super::lanes::lane_height_config(&record).unwrap()
    );
    assert_eq!(crypto.admitted_len(), record.committee.len());
    // The original authority verifies exact BLS quorums and rejects a changed signature
    // without replacing its retained schedule owner.
    {
        use crate::sumeragi::crypto::KeyPairSigner;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_model_base::peer::PeerId;
        use iroha_sumeragi::{
            crypto::{CertError, Crypto, Signer, Verifier},
            message::{Qc, VoteKind},
            types::{AggregateSignature, Bitmap, SIGNATURE_LEN},
        };
        let retained = budget.reserved_bytes();
        let original_tip = chain.state().view().native_execution_tip();
        let config = owner.schedule.height_config(1).unwrap().unwrap();
        let mut keys = (41..45)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        for (key, member) in keys.iter().zip(&record.committee) {
            assert_eq!(key.public_key(), member.peer.public_key());
        }
        let mut qc = Qc {
            kind: VoteKind::Commit,
            instance,
            epoch: config.epoch.id,
            height: 1,
            view: 0,
            block_hash: Hash32([0x71; 32]),
            result: original.result(),
            signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
            agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
        };
        let sign_qc = |qc: &mut Qc| {
            qc.agg_sig = crypto.aggregate(
                &keys[..3]
                    .iter()
                    .map(|key| KeyPairSigner::new(key).unwrap().sign(&qc.preimage()))
                    .collect::<Vec<_>>(),
            );
        };
        let epoch = qc.epoch;
        let verifier = Verifier::new(&*crypto, &instance, &epoch, &config.committee);
        sign_qc(&mut qc);
        verifier.verify_qc(&qc).unwrap();
        qc.agg_sig.0[0] ^= 1;
        assert_eq!(verifier.verify_qc(&qc), Err(CertError::BadSignature));
        assert_eq!(owner.schedule.height_config(1).unwrap(), Some(config));
        assert_eq!(chain.state().view().native_execution_tip(), original_tip);
        assert_eq!(budget.reserved_bytes(), retained);
        assert!(provider.scan.lock().is_none());
    }
    drop(owner);
    assert_eq!(budget.reserved_bytes(), before);
    assert!(provider.scan.lock().is_none());
}

#[test]
fn historical_lane_authority_refusal_keeps_original_file_and_rejects_a_fresh_replacement() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let before = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    let provider =
        NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::new(BlsCrypto::new()));
    budget.set_limit_bytes(before);
    let error = provider
        .historical_record(record.lane, record.incarnation)
        .err()
        .expect("archive admission refusal");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(provider.scan.lock().is_some());
    let path = chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            1,
            hex::encode(chain.genesis().hash().as_ref())
        ));
    let held = path.with_extension("original-held");
    std::fs::rename(&path, &held).unwrap();
    std::fs::write(&path, b"changed creation source").unwrap();
    budget.set_limit_bytes(limit);
    let owner = provider
        .historical_record(record.lane, record.incarnation)
        .unwrap()
        .expect("same original read descriptor retries");
    assert!(owner.belongs_to(&budget));
    assert_eq!(
        owner.config(),
        &super::super::lanes::lane_height_config(&record).unwrap()
    );
    drop(owner);
    assert_eq!(budget.reserved_bytes(), before);
    assert!(
        provider
            .historical_record(record.lane, record.incarnation)
            .is_err(),
        "a new lookup must not treat replacement bytes as original source"
    );
    assert!(
        provider.scan.lock().is_none(),
        "terminal source failure releases sole pending slot"
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(held, path).unwrap();
}

#[test]
fn historical_lane_authority_progresses_cancelled_original_scan_before_new_request() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let before = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    let provider =
        NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::new(BlsCrypto::new()));
    budget.set_limit_bytes(before);
    let error = provider
        .historical_record(LaneId::new(99), [99; 32])
        .err()
        .expect("original refusal");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        provider
            .historical_record(record.lane, record.incarnation)
            .err()
            .unwrap()
            .io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(
        provider
            .scan
            .lock()
            .as_ref()
            .unwrap()
            .matches(LaneId::new(99), &[99; 32])
    );
    budget.set_limit_bytes(limit);
    let owner = provider
        .historical_record(record.lane, record.incarnation)
        .unwrap()
        .unwrap();
    assert_eq!(owner.lane(), record.lane);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn historical_lane_authority_rejects_changed_complete_creation_write_root() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let creation = chain.committed(record.created_at);
    assert!(creation.block().belongs_to(&budget));
    // Include the actual retained creation block in the fixture baseline;
    // the refused scan must refund only the owners it acquired itself.
    let before = budget.reserved_bytes();
    let path = chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            record.created_at,
            hex::encode(creation.block().hash().as_ref())
        ));
    let original = std::fs::read(&path).unwrap();
    let mut changed: crate::state::NativeExecutionProjectionV1 =
        norito::decode_canonical(&original).unwrap();
    changed
        .ordinary_writes
        .push(iroha_data_model::block::consensus::ExecKv {
            key: b"substituted-creation-write".to_vec(),
            value: vec![1],
        });
    std::fs::write(&path, norito::encode_canonical(&changed).unwrap()).unwrap();
    let provider =
        NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::new(BlsCrypto::new()));
    let error = provider
        .historical_record(record.lane, record.incarnation)
        .err()
        .expect("complete creation root must match original R");
    assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
    assert!(provider.scan.lock().is_none());
    assert_eq!(budget.reserved_bytes(), before);
    std::fs::write(&path, original).unwrap();
    assert!(
        provider
            .historical_record(record.lane, record.incarnation)
            .unwrap()
            .is_some()
    );
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn historical_lane_authority_rechecks_original_publication_after_refused_scan() {
    let (mut chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let limit = budget.limit_bytes();
    let provider =
        NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::new(BlsCrypto::new()));
    budget.set_limit_bytes(budget.reserved_bytes());
    assert_eq!(
        provider
            .historical_record(record.lane, record.incarnation)
            .err()
            .unwrap()
            .io_kind(),
        io::ErrorKind::WouldBlock
    );
    budget.set_limit_bytes(limit);
    chain.commit(Vec::new());
    let before = budget.reserved_bytes();
    let error = provider
        .historical_record(record.lane, record.incarnation)
        .err()
        .expect("captured publication is stale");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(error.to_string().contains("publication changed"));
    assert!(provider.scan.lock().is_none());
    assert_eq!(budget.reserved_bytes(), before);
    assert!(
        provider
            .historical_record(record.lane, record.incarnation)
            .unwrap()
            .is_some()
    );
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn creation_tip_is_pending_until_the_authenticated_activation_height() {
    let (mut chain, record, _epoch) = fixed_lane_chain_at(1);
    assert_eq!(record.created_at, 1);
    assert_eq!(record.active_from, 3);
    let provider =
        NativeLaneStoreAuthorities::new(Arc::clone(chain.state()), Arc::new(BlsCrypto::new()));
    assert!(
        provider
            .historical_record(record.lane, record.incarnation)
            .unwrap()
            .is_none()
    );
    chain.commit(Vec::new());
    assert!(
        provider
            .historical_record(record.lane, record.incarnation)
            .unwrap()
            .is_none()
    );
    chain.commit(Vec::new());
    assert!(
        provider
            .historical_record(record.lane, record.incarnation)
            .unwrap()
            .is_some()
    );
}
