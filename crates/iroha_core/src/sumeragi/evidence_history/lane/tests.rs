//! Original global frontier, real signed native ancestry, and retained source refusal tests.
#[path = "tests/replacement.rs"]
mod replacement;

use super::*;
use crate::{
    state::{StateReadOnly, WorldReadOnly},
    sumeragi::{
        crypto::KeyPairSigner,
        lanes::{
            merge::{CommittedLaneBlock, LaneBlockSource},
            record::PreparedLaneWrite,
        },
        runtime_availability::history::{HistoryCapture, HistoryScan},
        test_chain::CertifiedTestChain,
    },
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::{
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::{Crypto, Signer},
    message::{BlockHeader, Qc, Vote, VoteKind},
    types::{AggregateSignature, Bitmap, ControlWitness, SIGNATURE_LEN, Signature},
};
use mv::storage::StorageReadOnly;
use std::{sync::Arc, time::Duration};

#[derive(Default)]
struct OriginalFrames(parking_lot::RwLock<Vec<CommittedLaneBlock>>);
impl LaneBlockSource for OriginalFrames {
    fn tip(
        &self,
        lane: LaneId,
        _: &[u8; 32],
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<io::Error>> {
        assert_eq!(lane, LaneId::new(7));
        Ok(Some(self.0.read().len() as u64))
    }
    fn block(
        &self,
        lane: LaneId,
        _: &[u8; 32],
        height: u64,
    ) -> Result<
        Option<CommittedLaneBlock>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        assert_eq!(lane, LaneId::new(7));
        Ok(self
            .0
            .read()
            .get(height.checked_sub(1).unwrap() as usize)
            .cloned())
    }
    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        _: Duration,
    ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<io::Error>> {
        Ok(self
            .tip(lane, incarnation)?
            .is_some_and(|tip| tip >= height))
    }
}
fn capture_parts(
    chain: &CertifiedTestChain,
) -> (
    HistoryCapture,
    iroha_data_model::block::consensus::LaneEvidenceScope,
) {
    let state = chain.state();
    let generation = state.state_view_generation();
    let (capture, scope) = {
        let view = state.view();
        let record = view.world().sumeragi_lanes().lane(LaneId::new(7)).unwrap();
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
    (capture, scope)
}
fn capture(chain: &CertifiedTestChain) -> LaneEvidenceContext {
    let (capture, scope) = capture_parts(chain);
    let mut history = HistoryScan::open_for_evidence(capture, scope).unwrap();
    history.complete().unwrap();
    history
        .finish_evidence()
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}
fn keys() -> Vec<KeyPair> {
    let mut keys: Vec<_> = (41..45)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    keys.sort_by_key(|key| crate::sumeragi::crypto::core_key(key.public_key()).unwrap());
    keys
}
fn vote_pair(reader: &LaneProofRead, height: u64) -> Evidence {
    let signer = KeyPairSigner::new(&keys()[2]).unwrap();
    let vote = |byte| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance: reader.instance,
            epoch: reader.cursor.config().epoch.id,
            height,
            view: 5,
            block_hash: Hash32([byte; 32]),
            result: Hash32([73; 32]),
            signer: 2,
            sig: Signature([0; SIGNATURE_LEN]),
        };
        vote.sig = signer.sign(&vote.preimage());
        vote
    };
    Evidence::VoteEquivocation(vote(71), vote(72))
}
fn anchored_chain(count: u64) -> (CertifiedTestChain, crossbeam_epoch::Guard) {
    anchored_chain_with_policy(
        count,
        iroha_data_model::parameter::system::SumeragiNposParameters::default(),
    )
}
fn anchored_chain_with_policy(
    count: u64,
    parameters: iroha_data_model::parameter::system::SumeragiNposParameters,
) -> (CertifiedTestChain, crossbeam_epoch::Guard) {
    anchored_chain_with_config(count, parameters, |_| {})
}
fn anchored_chain_with_config(
    count: u64,
    parameters: iroha_data_model::parameter::system::SumeragiNposParameters,
    configure: fn(&mut crate::sumeragi::test_chain::TestChainConfig),
) -> (CertifiedTestChain, crossbeam_epoch::Guard) {
    let source = Arc::new(OriginalFrames::default());
    let (mut chain, _, guard) =
        crate::sumeragi::runtime_availability::tests::fixed_lane_chain_with_config(
            3,
            Some(parameters),
            source.clone(),
            configure,
        );
    if count > 0 {
        let context = capture(&chain);
        let crypto = BlsCrypto::new();
        let keys = keys();
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
        let mut parent = context.authority.genesis();
        let dir = context
            .kura
            .store_root()
            .join("lanes")
            .join(hex::encode(context.instance.0));
        std::fs::create_dir_all(&dir).unwrap();
        for height in 1..=count {
            let mut payload = PayloadBytes::from_untrusted(vec![3; 33]).unwrap();
            payload.admit(&context.budget).unwrap();
            let header = BlockHeader {
                instance: context.instance,
                epoch: context.authority.config().epoch.id,
                height,
                origin_view: 0,
                parent_hash: Hash32(parent.block_hash),
                parent_result: Hash32(parent.result),
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
                .unwrap_or_else(|_| panic!("signed original lane frame"));
            let hash = authored.body.hash(&crypto);
            let mut qc = Qc {
                kind: VoteKind::Commit,
                instance: context.instance,
                epoch: context.authority.config().epoch.id,
                height,
                view: 0,
                block_hash: hash,
                result: Hash32([height as u8; 32]),
                signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
                agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
            };
            qc.agg_sig = crypto.aggregate(
                &signers[..3]
                    .iter()
                    .map(|signer| signer.sign(&qc.preimage()))
                    .collect::<Vec<_>>(),
            );
            assert!(
                iroha_sumeragi::crypto::Verifier::new(
                    &crypto,
                    &context.instance,
                    &qc.epoch,
                    &context.authority.config().committee
                )
                .verify_commit_qc(&qc, Some(authored.body.header()))
            );
            parent = iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier {
                height,
                block_hash: hash.0,
                result: qc.result.0,
            };
            let mut prepared = PreparedLaneWrite::new(authored.body, qc);
            std::fs::write(
                dir.join(format!("{height:020}.frame")),
                prepared.prepare(&context.budget).unwrap(),
            )
            .unwrap();
            // Only metadata from the original real-BLS certificate is exposed to global merge.
            // Its malformed lane batch is canonically merged without transaction effects.
            source.0.write().push(CommittedLaneBlock {
                block_hash: hash,
                result: Hash32(parent.result),
                batch: None,
            });
        }
        drop(context);
        chain.commit(Vec::new());
    }
    (chain, guard)
}

#[test]
fn lane_proof_genesis_parent_uses_original_creation_and_distinct_native_height() {
    let (chain, _guard) = anchored_chain(0);
    let context = capture(&chain);
    let scope = context.scope;
    let mut reader =
        LaneProofRead::new(context, 1).unwrap_or_else(|_| panic!("original active custody"));
    reader.poll().unwrap();
    assert!(reader.headers.as_slice().is_empty());
    let proof = vote_pair(&reader, 1);
    let verified = reader.verify(&proof).unwrap();
    assert_eq!(
        verified.scope(),
        iroha_data_model::block::consensus::EvidenceScope::Lane(scope)
    );
    assert_eq!(verified.height(), 1);
    assert_eq!(scope.admission_parent_height, 3);
    assert_eq!(verified.offenders()[0].signer, 2);
    assert_eq!(
        verified.offenders()[0].peer_id.public_key(),
        keys()[2].public_key()
    );
    assert!(
        verified.offenders()[0].lane_stake.is_none(),
        "fixed committee without genuine escrow is forensic-only"
    );
    assert!(
        reader.verify(&vote_pair(&reader, 2)).is_err(),
        "another native subject cannot reuse the parent"
    );
}

#[test]
fn lane_proof_replays_complete_anchored_demotion_history_and_original_pool_after_refusal() {
    let (chain, _guard) = anchored_chain(5);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let context = capture(&chain);
    assert_eq!(
        context
            .payload
            .custody_record(&context.scope.incarnation)
            .unwrap()
            .unwrap()
            .frontier()
            .height,
        5
    );
    let mut reader = LaneProofRead::new(context, 4).unwrap_or_else(|_| panic!("covered parent"));
    let pointer = std::ptr::from_ref(reader.cursor.config().epoch.as_ref());
    let held = budget.reserved_bytes();
    budget.set_limit_bytes(held);
    let error = reader.poll().unwrap_err();
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(matches!(
        error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(_)
    ));
    assert_eq!(reader.cursor.next_height(), Some(5));
    assert_eq!(
        std::ptr::from_ref(reader.cursor.config().epoch.as_ref()),
        pointer
    );
    assert_eq!(budget.reserved_bytes(), held);
    budget.set_limit_bytes(1 << 30);
    reader.poll().unwrap();
    assert_eq!(
        reader
            .headers
            .as_slice()
            .iter()
            .map(|body| body.body.header().height)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(reader.parent.as_ref().unwrap().height, 3);
    assert!(reader.verify(&vote_pair(&reader, 4)).is_ok());
    assert!(
        reader
            .headers
            .as_slice()
            .iter()
            .all(|body| body.body.admitted_to(&budget))
    );
    let complete = budget.reserved_bytes();
    reader.poll().unwrap();
    assert_eq!(budget.reserved_bytes(), complete);
    drop(reader);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn lane_proof_refuses_uncovered_parent_and_missing_original_ancestry_without_advancing() {
    let (chain, _guard) = anchored_chain(3);
    let context = capture(&chain);
    let pointer = std::ptr::from_ref(context.authority.config().epoch.as_ref());
    let (context, error) = LaneProofRead::new(context, 5)
        .err()
        .expect("uncovered parent");
    assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        std::ptr::from_ref(context.authority.config().epoch.as_ref()),
        pointer
    );
    let path = context
        .kura
        .store_root()
        .join("lanes")
        .join(hex::encode(context.instance.0))
        .join("00000000000000000003.frame");
    std::fs::remove_file(path).unwrap();
    let mut reader =
        LaneProofRead::new(context, 3).unwrap_or_else(|_| panic!("covered original parent"));
    assert_eq!(
        reader.poll().unwrap_err().io_kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(reader.cursor.next_height(), Some(3));
    assert!(reader.verify(&vote_pair(&reader, 3)).is_err());
    assert!(
        reader.frame.is_some(),
        "missing original source is retained, not replaced"
    );
}

fn proposal_pair(reader: &LaneProofRead) -> Evidence {
    use iroha_sumeragi::topology::{Topology, committee_permutation, demoted_set};
    let config = reader.cursor.config();
    let height = reader.cursor.parent_height() + 1;
    let demoted = demoted_set(
        &config.committee,
        height,
        0,
        reader.cursor.configuration_owner().demotion_window(),
        reader
            .headers
            .as_slice()
            .iter()
            .map(|body| body.body.header()),
    );
    let topology = Topology::from_parts(
        committee_permutation(
            &reader.crypto,
            &reader.instance,
            &config.epoch,
            &config.committee,
        ),
        &demoted,
        height,
    )
    .unwrap();
    let proposer = topology.leader(0);
    let signer = KeyPairSigner::new(&keys()[proposer as usize]).unwrap();
    let parent = reader.parent.as_ref().unwrap();
    let proposal = |payload| {
        let header = BlockHeader {
            instance: reader.instance,
            epoch: config.epoch.id,
            height,
            origin_view: 0,
            parent_hash: parent.block_hash,
            parent_result: parent.result,
            payload_hash: Hash32([payload; 32]),
            availability_digest: Hash32([payload; 32]),
            payload_len: 1,
            proposer,
            skipped_leaders: topology.skipped_leader_keys(&config.committee, 0),
            control_witness: ControlWitness::empty(),
        };
        let mut proposal = iroha_sumeragi::message::Proposal {
            instance: reader.instance,
            height,
            view: 0,
            header,
            justify: None,
            parent_qc: None,
            sig: Signature([0; SIGNATURE_LEN]),
        };
        proposal.sig = signer.sign(&proposal.signing_preimage(&reader.crypto));
        proposal
    };
    Evidence::ProposalEquivocation(Box::new(proposal(31)), Box::new(proposal(32)))
}

#[test]
fn lane_proof_requires_complete_ordered_original_demotion_custody_for_proposal_attribution() {
    let (chain, _guard) = anchored_chain(5);
    let mut reader =
        LaneProofRead::new(capture(&chain), 4).unwrap_or_else(|_| panic!("covered parent"));
    reader.poll().unwrap();
    let proof = proposal_pair(&reader);
    assert!(reader.verify(&proof).is_ok());
    reader.headers.as_mut_slice().reverse();
    assert!(matches!(
        reader.verify(&proof),
        Err(super::super::NativeEvidenceError::Proof(
            iroha_sumeragi::evidence::EvidenceError::DemotionHistory
        ))
    ));
    reader.headers.as_mut_slice().reverse();
    let last = reader.headers.pop().unwrap();
    assert!(matches!(
        reader.verify(&proof),
        Err(super::super::NativeEvidenceError::Proof(
            iroha_sumeragi::evidence::EvidenceError::DemotionHistory
        ))
    ));
    reader
        .headers
        .try_push(last)
        .unwrap_or_else(|_| panic!("original admitted descriptor slot"));
    assert!(reader.verify(&proof).is_ok());
}

#[test]
fn lane_proof_rejects_valid_same_height_certificate_on_an_unmerged_branch() {
    let (chain, _guard) = anchored_chain(3);
    let context = capture(&chain);
    let mut reader = LaneProofRead::new(context, 3).unwrap_or_else(|_| panic!("covered parent"));
    let expected = reader.cursor.next_frontier().unwrap();
    let path = reader
        .kura
        .store_root()
        .join("lanes")
        .join(hex::encode(reader.instance.0))
        .join(format!("{:020}.frame", expected.height));
    let config = reader
        .cursor
        .configuration_owner()
        .copy_config(&reader.budget)
        .unwrap();
    let source = FundedLaneSource::new(
        config,
        reader.instance,
        expected.height,
        Hash32(expected.block_hash),
        &reader.budget,
    )
    .unwrap_or_else(|_| panic!("original source"));
    let original = FundedLaneFrameRead::new(path.clone(), source, reader.budget.clone())
        .poll(&reader.budget, &reader.crypto)
        .unwrap();
    let mut payload = PayloadBytes::from_untrusted(vec![4; 33]).unwrap();
    payload.admit(&reader.budget).unwrap();
    let mut header = original.body.header().clone();
    header.payload_hash =
        iroha_sumeragi::preimage::payload_hash(&reader.crypto, payload.as_slice());
    header.availability_digest = Hash32::ZERO;
    let signers: Vec<_> = keys()
        .iter()
        .map(|key| KeyPairSigner::new(key).unwrap())
        .collect();
    let authored = PayloadAuthoring::new(header, payload)
        .complete(
            reader.instance,
            reader.cursor.config(),
            &reader.budget,
            &reader.crypto,
            &signers[0],
        )
        .unwrap_or_else(|_| panic!("other actual signed branch"));
    let mut qc = original.qc;
    qc.block_hash = authored.body.hash(&reader.crypto);
    qc.agg_sig = reader.crypto.aggregate(
        &signers[..3]
            .iter()
            .map(|signer| signer.sign(&qc.preimage()))
            .collect::<Vec<_>>(),
    );
    assert_ne!(qc.block_hash.0, expected.block_hash);
    assert!(
        iroha_sumeragi::crypto::Verifier::new(
            &reader.crypto,
            &reader.instance,
            &qc.epoch,
            &reader.cursor.config().committee
        )
        .verify_commit_qc(&qc, Some(authored.body.header()))
    );
    let mut replacement = PreparedLaneWrite::new(authored.body, qc);
    std::fs::write(path, replacement.prepare(&reader.budget).unwrap()).unwrap();
    assert_eq!(
        reader.poll().unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(reader.cursor.next_frontier().unwrap(), expected);
    assert!(reader.verify(&vote_pair(&reader, 3)).is_err());
}

#[test]
fn retained_lane_evidence_read_preserves_original_capture_across_open_failure_and_pool_refusal() {
    use super::super::{LaneEvidenceRead, NativeEvidenceError};
    let (chain, _guard) = anchored_chain(3);
    let mut proof_context =
        LaneProofRead::new(capture(&chain), 3).unwrap_or_else(|_| panic!("original subject"));
    proof_context.poll().unwrap();
    let proof = vote_pair(&proof_context, 3);
    drop(proof_context);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let (capture, scope) = capture_parts(&chain);
    let expected_tip = chain.state().view().native_execution_tip().unwrap();
    let mut reader = LaneEvidenceRead::new(capture, scope, 3);
    let path = chain.kura().store_root().join("native-contexts");
    let held = path.with_extension("original-held");
    std::fs::rename(&path, &held).unwrap();
    let error = reader.poll(&proof).unwrap_err();
    assert!(
        matches!(error, NativeEvidenceError::Source(ref error) if error.io_kind() == io::ErrorKind::NotFound)
    );
    std::fs::rename(&held, &path).unwrap();
    budget.set_limit_bytes(baseline);
    let error = reader.poll(&proof).unwrap_err();
    assert!(
        matches!(error, NativeEvidenceError::Source(ref error) if error.io_kind() == io::ErrorKind::WouldBlock && matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(_)))
    );
    budget.set_limit_bytes(1 << 30);
    let verified = reader.poll(&proof).unwrap();
    assert_eq!(verified.tip(), expected_tip);
    assert_eq!(
        verified.scope(),
        iroha_data_model::block::consensus::EvidenceScope::Lane(scope)
    );
    assert_eq!(verified.height(), 3);
    let attribution = verified.into_attribution();
    assert_eq!(attribution.height, 3);
    assert_eq!(
        attribution.scope,
        iroha_data_model::block::consensus::EvidenceScope::Lane(scope)
    );
    assert_eq!(attribution.offenders[0].signer, 2);
    drop(reader);
    assert!(
        budget.reserved_bytes() > baseline,
        "the immutable attribution still owns its actual graph"
    );
    drop(attribution);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn retained_lane_evidence_read_never_upgrades_original_cut_after_publication() {
    use super::super::LaneEvidenceRead;
    let (mut chain, _guard) = anchored_chain(3);
    let mut proof_context =
        LaneProofRead::new(capture(&chain), 3).unwrap_or_else(|_| panic!("original subject"));
    proof_context.poll().unwrap();
    let proof = vote_pair(&proof_context, 3);
    drop(proof_context);
    let (capture, scope) = capture_parts(&chain);
    let original = chain.state().view().native_execution_tip().unwrap();
    let mut reader = LaneEvidenceRead::new(capture, scope, 3);
    chain.commit(Vec::new());
    assert_ne!(
        chain.state().view().native_execution_tip().unwrap(),
        original
    );
    let verified = reader.poll(&proof).unwrap();
    assert_eq!(verified.tip(), original);
    assert_eq!(
        verified.scope(),
        iroha_data_model::block::consensus::EvidenceScope::Lane(scope)
    );
    // This verifies the old cut only. Installation is separately bound to the captured
    // State generation; a successful read cannot authorize effects in the successor.
}

#[test]
fn admission_owner_keeps_native_height_separate_and_original_history_job_on_refusal() {
    use crate::sumeragi::evidence::{EvidenceAdmissionError, admission::AdmissionRead};
    let (chain, _guard) = anchored_chain(7);
    let mut proof_context = LaneProofRead::new(capture(&chain), 7)
        .unwrap_or_else(|_| panic!("original native subject"));
    proof_context.poll().unwrap();
    let native = vote_pair(&proof_context, 7);
    drop(proof_context);
    let proof = iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap();
    let state = chain.state();
    let generation = state.state_view_generation();
    let history_pool = state.ivm_execution_budget();
    let history_before = history_pool.reserved_bytes();
    let preparation_before = state.evidence_preparation_budget().reserved_bytes();
    let carrier = 5;
    let mut read = {
        let view = state.view();
        assert_eq!(view.height(), 4);
        AdmissionRead::capture(
            state,
            &view,
            generation,
            carrier,
            std::slice::from_ref(&proof),
        )
        .unwrap()
    };
    history_pool.set_limit_bytes(history_before);
    assert!(
        matches!(read.complete(), Err(EvidenceAdmissionError::Source(ref error)) if error.io_kind() == io::ErrorKind::WouldBlock && matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(_)))
    );
    assert!(read.matches(generation, carrier, std::slice::from_ref(&proof)));
    history_pool.set_limit_bytes(1 << 30);
    read.complete().unwrap();
    let admitted = read.finish().unwrap();
    let attribution = admitted.as_slice()[0].attribution();
    assert_eq!(
        attribution.height, 7,
        "native height may exceed its root carrier height"
    );
    let iroha_data_model::block::consensus::EvidenceScope::Lane(scope) = attribution.scope else {
        panic!("original lane scope")
    };
    assert_eq!(scope.admission_parent_height + 1, carrier);
    assert!(attribution.offenders[0].lane_stake.is_none());
    drop(admitted);
    assert_eq!(history_pool.reserved_bytes(), history_before);
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        preparation_before
    );
}

#[test]
fn state_admission_cache_retains_lane_jobs_until_retry_and_refunds_original_pools() {
    use crate::sumeragi::evidence::admission::prepare_admissions;
    let _epoch = crossbeam_epoch::pin();
    let (chain, _guard) = anchored_chain(7);
    let mut reader =
        LaneProofRead::new(capture(&chain), 7).unwrap_or_else(|_| panic!("covered native subject"));
    reader.poll().unwrap();
    let proof =
        iroha_data_model::block::consensus::Evidence::from_native(&vote_pair(&reader, 7)).unwrap();
    drop(reader);
    let state = chain.state();
    let generation = state.state_view_generation();
    let carrier = state.view().native_execution_tip().unwrap().height() + 1;
    let original = state.ivm_execution_budget();
    let original_base = original.reserved_bytes();
    let admission_base = state.evidence_preparation_budget().reserved_bytes();
    original.set_limit_bytes(original_base);
    assert!(
        matches!(prepare_admissions(state, generation, carrier, std::slice::from_ref(&proof)),
        Err(crate::sumeragi::evidence::EvidenceAdmissionError::Source(ref error))
        if error.io_kind() == io::ErrorKind::WouldBlock && matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(_)))
    );
    let waiting = state.evidence_preparation_budget().reserved_bytes();
    assert!(
        waiting > admission_base,
        "State retains the original canonical proof batch"
    );
    let empty = prepare_admissions(state, generation, carrier, &[]).unwrap();
    assert!(empty.as_slice().is_empty());
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        waiting
    );
    original.set_limit_bytes(1 << 30);
    let admitted = prepare_admissions(state, generation, carrier, &[proof]).unwrap();
    assert_eq!(admitted.as_slice()[0].attribution().height, 7);
    assert!(matches!(admitted.as_slice()[0].attribution().scope,
        iroha_data_model::block::consensus::EvidenceScope::Lane(scope)
        if scope.admission_parent_height + 1 == carrier));
    drop(admitted);
    assert_eq!(original.reserved_bytes(), original_base);
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        admission_base
    );
}

#[test]
fn native_lane_admission_and_restore_keep_original_carrier_clock_through_penalty_finality() {
    use crate::sumeragi::{evidence, test_chain::Signers};
    use iroha_data_model::{
        block::consensus::{EvidencePenaltyStatus, EvidenceScope},
        consensus::NposConsensusEffects,
    };
    let _epoch = crossbeam_epoch::pin();
    let (mut chain, _guard) = anchored_chain_with_policy(
        7,
        iroha_data_model::parameter::system::SumeragiNposParameters {
            slashing_delay_blocks: 2,
            ..Default::default()
        },
    );
    let mut reader = LaneProofRead::new(capture(&chain), 7)
        .unwrap_or_else(|_| panic!("original merged coverage"));
    reader.poll().unwrap();
    let native = vote_pair(&reader, 7);
    drop(reader);
    let proof = iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap();
    let key = evidence::evidence_key(&proof);
    let parent = chain.state().view().native_execution_tip().unwrap();
    let carrier = parent.height() + 1;
    chain.commit_with_proposal(
        None,
        Vec::new(),
        Signers::Quorum,
        Default::default(),
        |proposal| {
            let parent_service_commit_qc = proposal
                .npos_consensus_effects()
                .and_then(|effects| effects.parent_service_commit_qc.clone());
            proposal.set_npos_consensus_effects(Some(NposConsensusEffects {
                parent_service_commit_qc,
                evidence_admissions: vec![proof.clone()],
                penalty_actions: Vec::new(),
            }));
        },
    );
    let original_record = chain
        .state()
        .view()
        .world()
        .consensus_evidence()
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(original_record.recorded_at_height, carrier);
    assert_eq!(original_record.attribution.height, 7);
    assert!(
        7 > carrier,
        "lane heights cannot be ordered against global carriers"
    );
    assert_eq!(
        original_record.penalty_status,
        EvidencePenaltyStatus::Pending
    );
    assert!(
        original_record
            .attribution
            .offenders
            .iter()
            .all(|offender| offender.lane_stake.is_none())
    );
    assert!(
        matches!(original_record.attribution.scope, EvidenceScope::Lane(scope)
        if scope.admission_parent_height == parent.height()
            && scope.admission_parent_hash == parent.iroha_hash())
    );
    let budget = chain.state().ivm_execution_budget();
    let base = budget.reserved_bytes();
    budget.set_limit_bytes(base);
    assert!(
        matches!(evidence::validate_persisted_records(chain.state()),
        Err(evidence::EvidenceAdmissionError::Source(ref error)) if error.io_kind() == io::ErrorKind::WouldBlock)
    );
    budget.set_limit_bytes(1 << 30);
    evidence::validate_persisted_records(chain.state()).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        base,
        "completed restore releases every original native read owner"
    );
    let delay = chain
        .state()
        .view()
        .world()
        .sumeragi_npos_parameters()
        .expect("original policy decoder completes")
        .unwrap()
        .slashing_delay_blocks();
    let due = carrier + delay;
    while (chain.state().view().height() as u64) < due {
        chain.commit(Vec::new());
    }
    let current = chain
        .state()
        .view()
        .world()
        .consensus_evidence()
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(
        current.penalty_status,
        EvidencePenaltyStatus::Applied { height: due }
    );
    assert_eq!(current.attribution, original_record.attribution);
    evidence::validate_persisted_records(chain.state()).unwrap();
    let replay = {
        let state = chain.state();
        let generation = state.state_view_generation();
        evidence::admission::prepare_admissions(state, generation, due + 1, &[proof])
    };
    assert!(
        matches!(replay, Err(evidence::EvidenceAdmissionError::Invalid(reason)) if reason == "evidence is already committed")
    );

    let mut forged = current.canonical_projection();
    let EvidenceScope::Lane(scope) = &mut forged.attribution.scope else {
        panic!("lane scope")
    };
    scope.admission_parent_core_hash[0] ^= 1;
    let forged = crate::state::RetainedEvidenceRecord::from_fixture(
        forged,
        &chain.state().ivm_execution_budget(),
    )
    .unwrap();
    let mut records = chain.state().world.consensus_evidence.block();
    records.insert(key, forged);
    records.commit();
    assert!(evidence::validate_persisted_records(chain.state()).is_err());
    let mut records = chain.state().world.consensus_evidence.block();
    records.insert(key, current);
    records.commit();
    evidence::validate_persisted_records(chain.state()).unwrap();
}

// These two view-only phases must return before nested native history reads start.
// Keep their concrete StateView temporaries off the enclosing default-stack test frame.
#[inline(never)]
fn original_lane_observer_carrier(state: &crate::state::State) -> u64 {
    assert!(
        state
            .view()
            .world()
            .consensus_evidence()
            .iter()
            .next()
            .is_none()
    );
    state.view().height() as u64 + 1
}

#[inline(never)]
fn assert_original_lane_observer_record(
    state: &crate::state::State,
    key: iroha_crypto::Hash,
    proof: &iroha_data_model::block::consensus::Evidence,
    carrier: u64,
) {
    use iroha_data_model::block::consensus::EvidencePenaltyStatus;
    let view = state.view();
    let record = view.world().consensus_evidence().get(&key).unwrap();
    assert_eq!(record.native_evidence(), Some(proof));
    assert_eq!(record.recorded_at_height, carrier);
    assert_eq!(record.penalty_status, EvidencePenaltyStatus::Pending);
    assert_eq!(
        view.world().consensus_evidence().iter().count(),
        1,
        "forged observations never gain World authority"
    );
    drop(view);
}

#[test]
fn native_lane_observer_proposes_only_original_authenticated_reports_after_local_retry() {
    use crate::sumeragi::{evidence, lanes::runner::evidence_observer};
    use iroha_data_model::parameter::system::SumeragiNposParameters;
    let (mut chain, _guard) = anchored_chain_with_policy(
        7,
        SumeragiNposParameters {
            slashing_delay_blocks: 2,
            ..SumeragiNposParameters::default()
        },
    );
    let mut reader = LaneProofRead::new(capture(&chain), 7)
        .unwrap_or_else(|_| panic!("original merged coverage"));
    reader.poll().unwrap();
    let native = vote_pair(&reader, 7);
    let scope = reader.scope;
    drop(reader);
    let state = Arc::clone(chain.state());
    let proof = iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap();
    let key = evidence::evidence_key(&proof);
    let budget = state.evidence_preparation_budget();
    let initial = budget.reserved_bytes();
    let foreign = evidence_observer(Arc::clone(&state), scope.lane, [0xEE; 32]);
    foreign.evidence(&native);
    assert_eq!(
        budget.reserved_bytes(),
        initial,
        "foreign incarnations never enter the local source pool"
    );
    let observer = evidence_observer(Arc::clone(&state), scope.lane, scope.incarnation);
    // An observer callback is not authority: even a malformed callback stays untrusted until
    // the shared original-history verifier rejects it during optional proposal selection.
    let mut forged = native.clone();
    let Evidence::VoteEquivocation(first, _) = &mut forged else {
        panic!("vote fixture")
    };
    first.sig.0[0] ^= 1;
    observer.evidence(&forged);
    observer.evidence(&native);
    let retained = budget.reserved_bytes();
    assert!(retained > initial);
    let carrier = original_lane_observer_carrier(&state);
    assert!(
        7 > carrier,
        "local lane height must not exclude a global proposal"
    );
    let generation = state.state_view_generation();
    let original_pool = state.ivm_execution_budget();
    let original_base = original_pool.reserved_bytes();
    original_pool.set_limit_bytes(original_base);
    assert!(evidence::pending_evidence_admissions(&state, carrier, generation).is_empty());
    let waiting = budget.reserved_bytes();
    assert!(
        waiting > retained,
        "the refused original reader remains owned by State"
    );
    assert!(evidence::pending_evidence_admissions(&state, carrier, generation).is_empty());
    assert_eq!(
        budget.reserved_bytes(),
        waiting,
        "retry does not accumulate replacement source jobs"
    );
    original_pool.set_limit_bytes(1 << 30);
    assert_eq!(
        evidence::pending_evidence_admissions(&state, carrier, generation),
        [proof.clone()]
    );
    assert_eq!(original_pool.reserved_bytes(), original_base);
    assert_eq!(budget.reserved_bytes(), retained);
    chain.commit(Vec::new());
    assert_original_lane_observer_record(&state, key, &proof, carrier);
    evidence::validate_persisted_records(&state).unwrap();
}

fn original_validator_account_key() -> KeyPair {
    KeyPair::from_seed(vec![0xE4; 32], Algorithm::Ed25519)
}

fn reported_original_lane_equivocation(context: &LaneEvidenceContext) -> Evidence {
    use crate::sumeragi::driver::{
        DriverConfig, Kernel, KernelStart, Op, Report,
        ingress::{Ingress, IngressLimits},
    };
    use iroha_sumeragi::{
        api::{Init, LocalParams},
        message::WireMessage,
        types::{ConfigSlot, PublicKey},
    };

    // This deterministic host starts a non-voting observer from the actual lane
    // creation record. Only the scripted remote peer equivocates; production
    // node configuration and signing paths have no fault controls.
    let crypto = BlsCrypto::new();
    context
        .authority
        .visit_members(|key, proof| {
            let key = iroha_crypto::PublicKey::from_bytes(Algorithm::BlsNormal, key)
                .expect("original lane member key");
            crypto.admit(&key, proof).expect("original lane member PoP");
            Ok(())
        })
        .expect("authenticated original lane committee");
    let config = context.authority.config().clone();
    let genesis = context.authority.genesis();
    assert_eq!(genesis.height, 0);
    let (mut kernel, _) = Kernel::start(KernelStart {
        allocation_budget: context.budget.clone(),
        local: LocalParams::default(),
        init: Init {
            instance: context.instance,
            records: Vec::new(),
            genesis_height: genesis.height,
            demotion_window: context.authority.demotion_window(),
            nonce: 1,
            tip: CommittedTip {
                height: genesis.height,
                block_hash: Hash32(genesis.block_hash),
                result: Hash32(genesis.result),
                header: None,
                commit_qc: None,
            },
            configs: vec![
                (1, ConfigSlot::Ready(config.clone())),
                (2, ConfigSlot::Ready(config.clone())),
            ],
            recent_headers: Vec::new(),
        },
        signers: Vec::new(),
        crypto: Box::new(crypto),
        hasher: Box::new(BlsCrypto::new()),
        now: 0,
        ingress: Arc::new(parking_lot::Mutex::new(Ingress::new(
            IngressLimits::default(),
        ))),
        config: DriverConfig::default(),
    })
    .expect("production detector starts from authenticated lane genesis");

    fn deliver(kernel: &mut Kernel, from: &PublicKey, vote: Vote) -> Vec<Evidence> {
        let message = WireMessage::Vote(vote);
        let class = message.traffic_class();
        kernel.receive(from.clone(), message, class);
        let mut handled = 0;
        while let Some(input) = kernel.next_input(0) {
            handled += 1;
            assert!(handled <= 16, "one deterministic input must drain promptly");
            kernel.handle(0, input);
        }
        kernel
            .poll(0)
            .into_iter()
            .filter_map(|operation| match operation {
                Op::Report(Report::Evidence(evidence)) => Some(*evidence),
                Op::Report(report) => panic!("unexpected detector report: {report:?}"),
                Op::Exec(_) | Op::Persist { .. } => {
                    panic!("the non-voting detector cannot fabricate execution or signing")
                }
                Op::Send { msg, .. } => {
                    assert!(!matches!(msg, WireMessage::Vote(_)));
                    None
                }
                Op::Serve(_) => None,
            })
            .collect()
    }

    let key = keys()[2].clone();
    let signer = KeyPairSigner::new(&key).unwrap();
    let from = crate::sumeragi::crypto::core_key(key.public_key()).unwrap();
    assert_eq!(config.committee.members()[2], from);
    let signed_vote = |block| {
        let mut vote = Vote {
            kind: VoteKind::Prepare,
            instance: context.instance,
            epoch: config.epoch.id,
            height: 1,
            view: 0,
            block_hash: Hash32([block; 32]),
            result: Hash32([73; 32]),
            signer: 2,
            sig: Signature([0; SIGNATURE_LEN]),
        };
        vote.sig = signer.sign(&vote.preimage());
        vote
    };
    let first = signed_vote(71);
    let second = signed_vote(72);
    assert!(deliver(&mut kernel, &from, first.clone()).is_empty());
    let mut bad_signature = second.clone();
    bad_signature.sig.0[0] ^= 1;
    let mut foreign_epoch = second.clone();
    foreign_epoch.epoch.epoch += 1;
    foreign_epoch.sig = signer.sign(&foreign_epoch.preimage());
    let mut foreign_instance = second.clone();
    foreign_instance.instance.0[0] ^= 1;
    foreign_instance.sig = signer.sign(&foreign_instance.preimage());
    for invalid in [bad_signature, foreign_epoch, foreign_instance] {
        assert!(
            deliver(&mut kernel, &from, invalid).is_empty(),
            "unauthenticated or foreign votes cannot become slash evidence"
        );
    }
    let mut reports = deliver(&mut kernel, &from, second.clone());
    assert_eq!(
        reports.len(),
        1,
        "the actual detector reports the conflicting slot"
    );
    let report = reports.pop().unwrap();
    assert_eq!(
        report,
        Evidence::VoteEquivocation(first.clone(), second.clone())
    );
    for replay in [first, second] {
        assert!(
            deliver(&mut kernel, &from, replay).is_empty(),
            "replayed votes cannot report the same offence twice"
        );
    }
    report
}

fn fund_original_validator_in_signed_genesis(
    config: &mut crate::sumeragi::test_chain::TestChainConfig,
) {
    use crate::state::World;
    use iroha_data_model::{Registrable, domain::Domain};
    use iroha_data_model::{
        account::{Account, AccountId},
        asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
        isi::RegisterPublicLaneValidator,
        nexus::PublicLaneMonetaryPlanV1,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::{NumericSpec, Quantity};
    let original_keys = keys();
    let peer = iroha_model_base::peer::PeerId::new(original_keys[2].public_key().clone());
    config.validator_keys = Some(original_keys);
    let owner = AccountId::new(config.genesis_key.public_key().clone());
    // The staker signs account transactions with the admitted account algorithm;
    // its independently registered BLS peer remains the original consensus seat.
    let validator = AccountId::new(original_validator_account_key().public_key().clone());
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    // Both static lanes are configured in the same physical dataspace. Its canonical
    // lowest stake-elected owner is lane 0; merely sharing a BLS key is insufficient.
    nexus.lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        std::num::NonZeroU32::new(8).unwrap(),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            iroha_data_model::nexus::LaneConfig {
                id: LaneId::new(7),
                alias: "original-custody-lane".to_owned(),
                ..iroha_data_model::nexus::LaneConfig::default()
            },
        ],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.staking.max_slash_bps = 1_000;
    let sink = AccountId::new(
        KeyPair::from_seed(vec![0xE3; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    nexus.staking.slash_sink_account_id = sink.to_string();
    let staking = &nexus.staking;
    let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
    assert_eq!(
        definition,
        iroha_data_model::parameter::system::SumeragiNposParameters::default()
            .xor_asset_definition_id
    );
    let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
    assert_ne!(escrow, sink, "a slash must physically leave stake escrow");
    let source_asset = AssetId::new(definition.clone(), validator.clone());
    let escrow_asset = AssetId::new(definition.clone(), escrow.clone());
    let amount = Quantity::from(10_000_u64);
    config.world = World::with_assets(
        [Domain::new(DomainId::try_new("nexus", "universal").unwrap()).build(&owner)],
        [
            Account::new(validator.clone()).build(&owner),
            Account::new(escrow).build(&owner),
            Account::new(sink).build(&owner),
        ],
        [AssetDefinition::new(
            definition,
            "XOR",
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&owner)],
        // Only `amount` enters stake custody. The second allocation stays liquid
        // in this exact account-owned XOR asset to pay ordinary signed operations.
        [Asset::new(
            source_asset.clone(),
            amount.checked_add(&Quantity::from(10_000_u64)).unwrap(),
        )],
        [],
    );
    config.nexus = Some(nexus);
    config.genesis_instructions.push(
        RegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            peer_id: peer,
            stake_account: validator,
            initial_stake: amount.clone(),
            metadata: Default::default(),
            monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                source_asset,
                escrow_asset,
                amount,
            ),
        }
        .into(),
    );
}

#[test]
fn native_lane_original_genesis_escrow_is_debited_only_by_delayed_authenticated_admission() {
    // Quoted signed staking now reaches the real detector and full cold replay.
    // Run that complete State/Kernel stack under its existing production bound,
    // as the native publication fixtures do, rather than libtest's small default.
    crate::sumeragi::threads::sumeragi_thread_builder("funded-lane-slashing-test")
        .spawn(|| funded_original_lane_slashing_scenario(false))
        .expect("spawn funded native lane fixture")
        .join()
        .expect("funded native lane fixture");
}

fn funded_original_lane_slashing_scenario(complete_replacement: bool) {
    use crate::{
        smartcontracts::isi::staking::preparation::prepare_public_lane_plan,
        sumeragi::{evidence, lanes::runner::evidence_observer},
    };
    use iroha_data_model::{
        account::AccountId,
        asset::AssetId,
        block::consensus::{EvidencePenaltyStatus, NexusFeeSettlementV1},
        isi::{FinalizePublicLaneUnbond, SchedulePublicLaneUnbond},
        nexus::{
            FeeDebitSource, PublicLanePreparationOperationV1, PublicLanePreparationRequestV1,
            PublicLanePrepareUnbondV1, PublicLanePreparedPlanV1, PublicLaneStakeShare,
        },
        parameter::system::SumeragiNposParameters,
        transaction::{FeeChargeKind, FeePaymentIntent, SignedTransaction, TransactionBuilder},
    };
    use iroha_primitives::numeric::Quantity;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CustodySnapshot {
        custody: (AssetId, Quantity),
        reserve: Quantity,
        share: PublicLaneStakeShare,
        escrow_balance: Quantity,
        sink_balance: Quantity,
        staker_balance: Quantity,
        total_supply: Quantity,
    }

    let policy = if complete_replacement {
        replacement::policy()
    } else {
        SumeragiNposParameters {
            slashing_delay_blocks: 2,
            ..SumeragiNposParameters::default()
        }
    };
    let configure = if complete_replacement {
        replacement::fund_signed_genesis
    } else {
        fund_original_validator_in_signed_genesis
    };
    let (mut chain, _guard) = anchored_chain_with_config(7, policy.clone(), configure);
    assert!(
        chain
            .genesis()
            .output_results()
            .all(|result| result.as_ref().is_ok()),
        "signed genesis executed original registration and escrow transfer"
    );
    let state = Arc::clone(chain.state());
    let original_height = chain.height();
    let validator_key = original_validator_account_key();
    let validator = AccountId::new(validator_key.public_key().clone());
    let stake_key = (LaneId::SINGLE, validator.clone());
    let share_key = (LaneId::SINGLE, validator.clone(), validator.clone());
    let (escrow_asset, sink_asset, staker_asset) = {
        let view = state.view();
        let registration = view
            .world()
            .public_lane_validators()
            .get(&stake_key)
            .unwrap();
        assert_eq!(registration.peer_id.public_key(), keys()[2].public_key());
        assert_ne!(
            registration.peer_id.public_key(),
            validator_key.public_key()
        );
        let escrow = &view
            .world()
            .public_lane_stake_custody()
            .get(&stake_key)
            .unwrap()
            .0;
        let sink = AccountId::parse_encoded(&view.nexus().staking.slash_sink_account_id).unwrap();
        (
            escrow.clone(),
            AssetId::with_scope(escrow.definition().clone(), sink, *escrow.scope()),
            AssetId::with_scope(
                escrow.definition().clone(),
                validator.clone(),
                *escrow.scope(),
            ),
        )
    };
    let snapshot = |state: &crate::state::State| {
        let view = state.view();
        let world = view.world();
        let balance = |asset: &AssetId| {
            world
                .assets()
                .get(asset)
                .map_or_else(Quantity::zero, |value| value.as_ref().clone())
        };
        CustodySnapshot {
            custody: world
                .public_lane_stake_custody()
                .get(&stake_key)
                .unwrap()
                .clone(),
            reserve: world
                .public_lane_stake_reserves()
                .get(&escrow_asset)
                .unwrap()
                .clone(),
            share: world
                .public_lane_stake_shares()
                .get(&share_key)
                .unwrap()
                .clone(),
            escrow_balance: balance(&escrow_asset),
            sink_balance: balance(&sink_asset),
            staker_balance: balance(&staker_asset),
            total_supply: world
                .asset_definition(escrow_asset.definition())
                .unwrap()
                .total_quantity()
                .clone(),
        }
    };
    let initial = snapshot(&state);
    let principal = Quantity::from(10_000_u64);
    assert_eq!(initial.custody, (escrow_asset.clone(), principal.clone()));
    assert_eq!(initial.reserve, principal);
    assert_eq!(initial.share.bonded, principal);
    assert_eq!(initial.escrow_balance, principal);
    assert_eq!(initial.sink_balance, Quantity::zero());
    assert_eq!(initial.staker_balance, Quantity::from(10_000_u64));

    let sign_paid = |chain: &CertifiedTestChain,
                     instruction: iroha_data_model::isi::InstructionBox,
                     created_at_ms: u64| {
        let mut builder = TransactionBuilder::new(
            chain.network_id(),
            validator.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction]);
        builder.set_creation_time(Duration::from_millis(created_at_ms));
        let draft = builder.clone().sign(validator_key.private_key());
        let view = chain.state().view();
        let quote = crate::executor::quote_nexus_fee_admission_draft(
            view.world(),
            view.nexus(),
            view.pipeline(),
            draft.payload(),
            created_at_ms,
            chain.height() + 1,
            Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
        )
        .expect("ordinary staking work has separately funded exact signed XOR fee bounds");
        assert_eq!(
            quote.quote.debit_source,
            FeeDebitSource::Account(validator.clone())
        );
        assert_eq!(quote.quote.authority_balances.len(), 1);
        assert_eq!(
            quote
                .quote
                .authority_charge_assets
                .get(&FeeChargeKind::Nexus),
            Some(&staker_asset)
        );
        builder
            .with_fee_payment_intent(quote.recommended_intent)
            .sign(validator_key.private_key())
    };
    let actual_fee = |chain: &CertifiedTestChain, signed: &SignedTransaction| {
        let committed = chain.committed(chain.height());
        let receipt = committed
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .nexus_fee_receipt()
            .expect("attempted staking work burns its separately funded fee");
        assert_eq!(
            receipt.source_id,
            *iroha_crypto::Hash::from(signed.hash_as_entrypoint()).as_ref()
        );
        assert_eq!(receipt.block_height, chain.height());
        assert_eq!(receipt.fee_asset_id, *staker_asset.definition());
        assert_eq!(
            receipt.debit_source,
            FeeDebitSource::Account(validator.clone())
        );
        assert_eq!(receipt.settlement, NexusFeeSettlementV1::Burn);
        assert!(!receipt.fee_amount.is_zero());
        let view = chain.state().view();
        let policy = &view.nexus().fees;
        assert_eq!(receipt.schedule.base_fee, policy.base_fee);
        assert_eq!(receipt.schedule.per_byte_fee, policy.per_byte_fee);
        assert_eq!(
            receipt.schedule.per_instruction_fee,
            policy.per_instruction_fee
        );
        assert_eq!(receipt.schedule.per_gas_unit_fee, policy.per_gas_unit_fee);
        let payload_bytes = norito::canonical_frame_len(signed.payload()).unwrap();
        assert_eq!(receipt.schedule.tx_bytes_len, payload_bytes as u64);
        assert_eq!(receipt.schedule.instruction_count, 1);
        assert_eq!(
            receipt.fee_amount,
            crate::executor::compute_nexus_fee_amount(
                policy,
                payload_bytes,
                1,
                receipt.schedule.gas_used,
            )
            .unwrap()
        );
        let limit = signed
            .fee_payment_intent()
            .charge_limits()
            .iter()
            .find(|limit| limit.kind == FeeChargeKind::Nexus)
            .unwrap();
        assert_eq!(limit.asset_definition_id, *staker_asset.definition());
        assert!(receipt.fee_amount <= limit.max_amount);
        receipt.fee_amount.clone()
    };

    // The staker can request exit, but the original live seats keep all principal
    // liable. Scheduling is an ordinary signed transaction, not an overlay edit.
    let request_id = iroha_crypto::Hash::new(b"original lane offence pending unbond");
    let schedule_created_at_ms = chain.committed(chain.height()).block_time_ms();
    let release_at_ms = {
        let view = state.view();
        let cadence_ms = view
            .world()
            .consensus_schedule()
            .ready(chain.height() + 1)
            .expect("authenticated next carrier schedule")
            .params
            .block_time_ms;
        let delay_ms = u64::try_from(view.nexus().staking.unbonding_delay.as_millis())
            .expect("configured unbonding delay fits the fixture clock");
        schedule_created_at_ms
            .checked_add(cadence_ms)
            .and_then(|time| time.checked_add(delay_ms))
            .expect("exact configured unbond release time")
    };
    let schedule = sign_paid(
        &chain,
        SchedulePublicLaneUnbond {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            amount: principal.clone(),
            release_at_ms,
        }
        .into(),
        schedule_created_at_ms,
    );
    let schedule_result = chain.commit(vec![schedule.clone()]);
    assert_eq!(
        schedule_result,
        [true],
        "signed unbond scheduling: {:?}",
        chain
            .committed(chain.height())
            .block()
            .network_output_at(0)
            .map(|(_, output)| &output.result)
    );
    let schedule_fee = actual_fee(&chain, &schedule);
    let scheduled = snapshot(&state);
    assert_eq!(scheduled.share.bonded, Quantity::zero());
    assert_eq!(scheduled.share.pending_unbonds.len(), 1);
    let pending = scheduled.share.pending_unbonds.get(&request_id).unwrap();
    assert_eq!(pending.amount, principal);
    assert_eq!(pending.release_at_ms, release_at_ms);
    let mut expected_scheduled = initial;
    expected_scheduled.share = scheduled.share.clone();
    expected_scheduled.staker_balance = expected_scheduled
        .staker_balance
        .checked_sub(&schedule_fee)
        .unwrap();
    expected_scheduled.total_supply = expected_scheduled
        .total_supply
        .checked_sub(&schedule_fee)
        .unwrap();
    assert_eq!(
        scheduled, expected_scheduled,
        "scheduling releases no custody and burns only the separate liquid fee"
    );
    let context = capture(&chain);
    let native = reported_original_lane_equivocation(&context);
    let mut reader =
        LaneProofRead::new(context, 1).unwrap_or_else(|_| panic!("original merged branch"));
    reader.poll().unwrap();
    let original = reader.verify(&native).unwrap();
    assert_eq!(original.offenders().len(), 1);
    let binding = original.offenders()[0]
        .lane_stake
        .expect("original creation authenticated genuine positive escrow");
    assert!(binding.names_account(LaneId::SINGLE, &validator).unwrap());
    let scope = reader.scope;
    drop(reader);
    let proof = iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap();
    let key = evidence::evidence_key(&proof);
    evidence_observer(Arc::clone(&state), scope.lane, scope.incarnation).evidence(&native);
    assert!(
        state
            .view()
            .world()
            .consensus_evidence()
            .get(&key)
            .is_none(),
        "a real detector report still needs an independently finalized admission carrier"
    );
    let carrier = state.view().height() as u64 + 1;
    chain.commit(Vec::new());
    assert_eq!(
        state
            .view()
            .world()
            .consensus_evidence()
            .get(&key)
            .unwrap()
            .penalty_status,
        EvidencePenaltyStatus::Pending
    );
    assert_eq!(
        snapshot(&state),
        scheduled,
        "the admission carrier cannot debit its own report"
    );
    chain.commit(Vec::new());
    assert_eq!(
        snapshot(&state),
        scheduled,
        "the complete immutable delay is preserved"
    );
    chain.commit(Vec::new());
    let remainder = Quantity::from(9_000_u64);
    let penalty = Quantity::from(1_000_u64);
    let mut expected_custody = scheduled;
    expected_custody.custody.1 = remainder.clone();
    expected_custody.reserve = remainder.clone();
    expected_custody
        .share
        .pending_unbonds
        .get_mut(&request_id)
        .unwrap()
        .amount = remainder.clone();
    expected_custody.escrow_balance = remainder.clone();
    expected_custody.sink_balance = penalty;
    assert_eq!(
        snapshot(&state),
        expected_custody,
        "delayed penalty physically transfers only the liable principal"
    );
    assert_eq!(
        expected_custody
            .escrow_balance
            .checked_add(&expected_custody.sink_balance)
            .unwrap(),
        principal,
        "slashing conserves real XOR across the distinct custody accounts"
    );
    let view = state.view();
    let record = view.world().consensus_evidence().get(&key).unwrap();
    assert_eq!(
        record.penalty_status,
        EvidencePenaltyStatus::Applied {
            height: carrier + 2
        }
    );
    assert_eq!(record.attribution.offenders[0].lane_stake, Some(binding));
    let expected_record = record.clone();
    let registration = view
        .world()
        .public_lane_validators()
        .get(&stake_key)
        .unwrap();
    assert!(
        crate::state::validator_committee::peer_has_committee_obligation(
            view.world(),
            chain
                .committed(chain.height())
                .commitment()
                .schedule
                .current
                .committee
                .iter()
                .map(|seat| &seat.validator),
            &registration.peer_id,
        )
    );
    assert!(
        crate::sumeragi::lanes::custody::retains_registration(
            view.world(),
            registration,
            chain.height() + 1,
        )
        .unwrap()
    );
    let prepared = prepare_public_lane_plan(
        &view,
        PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 1,
            operation: PublicLanePreparationOperationV1::FinalizeUnbond(
                PublicLanePrepareUnbondV1 {
                    validator: validator.clone(),
                    staker: validator.clone(),
                    request_id,
                },
            ),
        },
    )
    .unwrap();
    let PublicLanePreparedPlanV1::Monetary(monetary_plan) = prepared.plan else {
        panic!("exact remaining unbond monetary plan");
    };
    assert_eq!(monetary_plan.amount, remainder);
    assert_eq!(monetary_plan.source_asset, escrow_asset);
    assert_eq!(monetary_plan.destination_asset, staker_asset);
    drop(view);

    // Time maturity and an exact signed plan do not release an unchanged global
    // or lane seat. Only an authenticated replacement can permit withdrawal.
    let withdrawal_created_at_ms = chain
        .committed(chain.height())
        .block_time_ms()
        .max(release_at_ms.saturating_sub(1));
    let withdrawal = sign_paid(
        &chain,
        FinalizePublicLaneUnbond {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            monetary_plan,
        }
        .into(),
        withdrawal_created_at_ms,
    );
    assert_eq!(chain.commit(vec![withdrawal.clone()]), [false]);
    let withdrawal_fee = actual_fee(&chain, &withdrawal);
    expected_custody.staker_balance = expected_custody
        .staker_balance
        .checked_sub(&withdrawal_fee)
        .unwrap();
    expected_custody.total_supply = expected_custody
        .total_supply
        .checked_sub(&withdrawal_fee)
        .unwrap();
    let rejected = chain.committed(chain.height());
    assert!(rejected.block_time_ms() >= release_at_ms);
    let rejection = rejected
        .block()
        .network_output_at(0)
        .unwrap()
        .1
        .result
        .as_ref()
        .unwrap_err();
    assert!(format!("{rejection:?}").contains(
        "unbond withdrawal requires authenticated release of current and frozen committee obligations"
    ), "the unchanged seats reject withdrawal: {rejection:?}");
    assert_eq!(
        snapshot(&state),
        expected_custody,
        "rejected withdrawal preserves custody and burns only its separate liquid fee"
    );
    let final_height = chain.height();
    evidence::validate_persisted_records(&state).unwrap();

    // A new executor/State starts from the same original signed genesis and native
    // frontier, then independently replays the exact admitted and penalized suffix.
    let (mut replay, _replay_guard) = anchored_chain_with_config(7, policy, configure);
    assert_eq!(replay.genesis().hash(), chain.genesis().hash());
    assert_eq!(replay.state().view().height() as u64, original_height);
    replay.replay_from(&chain).unwrap();
    evidence::validate_persisted_records(replay.state()).unwrap();
    for _ in 0..2 {
        let view = replay.state().view();
        assert_eq!(
            view.world().consensus_evidence().get(&key),
            Some(&expected_record)
        );
        assert_eq!(view.height() as u64, final_height);
        drop(view);
        assert_eq!(snapshot(replay.state()), expected_custody);
        replay.replay_from(&chain).unwrap();
    }
    if complete_replacement {
        replacement::finish_after_real_detector_penalty(
            &mut chain,
            &mut replay,
            &validator_key,
            request_id,
            release_at_ms,
            &key,
            &expected_record,
        );
    }
}

#[test]
fn lane_admission_capture_checks_inclusive_deadline_and_missing_original_incarnation() {
    use crate::sumeragi::evidence::EvidenceAdmissionError;
    use crate::sumeragi::evidence::admission::AdmissionRead;
    use iroha_data_model::parameter::system::SumeragiNposParameters;
    let (chain, _guard) = anchored_chain_with_policy(
        7,
        SumeragiNposParameters {
            evidence_horizon_blocks: 2,
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        },
    );
    let mut native_read = LaneProofRead::new(capture(&chain), 3)
        .unwrap_or_else(|_| panic!("original native coverage"));
    native_read.poll().unwrap();
    let proof =
        iroha_data_model::block::consensus::Evidence::from_native(&vote_pair(&native_read, 3))
            .unwrap();
    let instance = native_read.instance.0;
    drop(native_read);
    let state = chain.state();
    let generation = state.state_view_generation();
    let budget = state.evidence_preparation_budget();
    let baseline = budget.reserved_bytes();
    let original = state.view().world().sumeragi_lanes().clone();
    // These explicit preflight inputs are not authenticated retirement carriers. A
    // successful capture below is not admission: the retained history read must still
    // authenticate retirement from the original carrier before it can finish.
    let replace_retirement = |retired_at| {
        let mut rows = state.world.sumeragi_lanes.block();
        rows.get_mut()
            .custody
            .iter_mut()
            .find(|row| row.instance == instance)
            .unwrap()
            .retired_at = retired_at;
        rows.commit();
    };
    replace_retirement(Some(3));
    let captured = AdmissionRead::capture(
        state,
        &state.view(),
        generation,
        5,
        std::slice::from_ref(&proof),
    )
    .unwrap();
    drop(captured);
    assert_eq!(budget.reserved_bytes(), baseline);
    replace_retirement(Some(2));
    assert!(
        matches!(AdmissionRead::capture(state, &state.view(), generation, 5,
        std::slice::from_ref(&proof)), Err(EvidenceAdmissionError::Invalid(reason))
        if reason.contains("outside original custody admission"))
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    for recreate in [false, true] {
        let mut rows = state.world.sumeragi_lanes.block();
        *rows.get_mut() = original.clone();
        if recreate {
            let row = rows
                .get_mut()
                .custody
                .iter_mut()
                .find(|row| row.instance == instance)
                .unwrap();
            row.incarnation = [0x99; 32];
            row.instance = [0x98; 32];
        } else {
            rows.get_mut()
                .custody
                .retain(|row| row.instance != instance);
        }
        rows.commit();
        assert!(
            AdmissionRead::capture(
                state,
                &state.view(),
                generation,
                5,
                std::slice::from_ref(&proof)
            )
            .is_err(),
            "a reclaimed or recreated row cannot reopen old proof admission"
        );
        assert_eq!(budget.reserved_bytes(), baseline);
    }
}

#[test]
fn terminal_lane_source_failure_cannot_pin_competing_original_admission_forever() {
    use crate::sumeragi::{
        evidence::{EvidenceAdmissionError, admission::prepare_admissions},
        test_chain::Signers,
    };
    let (chain, _guard) = anchored_chain(7);
    let mut reader =
        LaneProofRead::new(capture(&chain), 3).unwrap_or_else(|_| panic!("covered native branch"));
    reader.poll().unwrap();
    let proof =
        iroha_data_model::block::consensus::Evidence::from_native(&vote_pair(&reader, 3)).unwrap();
    let path = reader
        .kura
        .store_root()
        .join("lanes")
        .join(hex::encode(reader.instance.0))
        .join("00000000000000000007.frame");
    drop(reader);
    let root = Evidence::ConflictingCertificates(
        chain.commit_qc(3, Hash32([0x31; 32]), Hash32([0x32; 32]), Signers::Quorum),
        chain.commit_qc(
            3,
            Hash32([0x33; 32]),
            Hash32([0x34; 32]),
            Signers::LastThree,
        ),
    );
    let root = iroha_data_model::block::consensus::Evidence::from_native(&root).unwrap();
    std::fs::remove_file(path).unwrap();
    let state = chain.state();
    let generation = state.state_view_generation();
    let baseline = state.ivm_execution_budget().reserved_bytes();
    let preparation = state.evidence_preparation_budget().reserved_bytes();
    assert!(matches!(prepare_admissions(state, generation, 5, &[proof]),
        Err(EvidenceAdmissionError::Source(error)) if error.io_kind() == io::ErrorKind::NotFound));
    let admitted = prepare_admissions(state, generation, 5, &[root])
        .expect("terminal lane storage failure cannot retain the same-cut admission slot");
    assert_eq!(admitted.as_slice().len(), 1);
    assert_eq!(
        admitted.as_slice()[0].attribution().scope,
        iroha_data_model::block::consensus::EvidenceScope::Root
    );
    drop(admitted);
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), baseline);
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        preparation
    );
    assert_eq!(state.view().world().consensus_evidence().iter().count(), 0);
}

#[test]
fn local_proposer_skips_terminal_lane_source_without_deleting_observation() {
    use crate::sumeragi::{evidence, test_chain::Signers};
    let (chain, _guard) = anchored_chain(7);
    let mut reader = LaneProofRead::new(capture(&chain), 3)
        .unwrap_or_else(|_| panic!("original native coverage"));
    reader.poll().unwrap();
    let native = vote_pair(&reader, 3);
    let scope = reader.scope;
    let lane = iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap();
    let path = reader
        .kura
        .store_root()
        .join("lanes")
        .join(hex::encode(reader.instance.0))
        .join("00000000000000000007.frame");
    drop(reader);
    let (root_native, root) = (1..=255_u8)
        .find_map(|marker| {
            let proof = Evidence::ConflictingCertificates(
                chain.commit_qc(3, Hash32([marker; 32]), Hash32([0x32; 32]), Signers::Quorum),
                chain.commit_qc(3, Hash32([0; 32]), Hash32([0x34; 32]), Signers::LastThree),
            );
            let wire = iroha_data_model::block::consensus::Evidence::from_native(&proof).unwrap();
            (evidence::evidence_key(&wire) > evidence::evidence_key(&lane)).then_some((proof, wire))
        })
        .expect("bounded deterministic fixture selects a later canonical root key");
    let state = chain.state();
    assert!(evidence::observe_lane(state, scope.lane, scope.incarnation, &native).unwrap());
    assert!(evidence::observe(state, &root_native).unwrap());
    std::fs::remove_file(path).unwrap();
    let preparation = state.evidence_preparation_budget().reserved_bytes();
    let original_pool = state.ivm_execution_budget().reserved_bytes();
    assert_eq!(
        evidence::pending_evidence_admissions(state, 5, state.state_view_generation()),
        vec![root]
    );
    assert!(
        !evidence::observe_lane(state, scope.lane, scope.incarnation, &native).unwrap(),
        "storage failure cannot delete or blame the original signed local observation"
    );
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        preparation
    );
    assert_eq!(state.ivm_execution_budget().reserved_bytes(), original_pool);
    assert_eq!(state.view().world().consensus_evidence().iter().count(), 0);
}

#[test]
fn original_lane_context_retains_custody_on_native_constructor_decode_refusal() {
    let (chain, _guard) = anchored_chain(3);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let context = capture(&chain);
    let retained = budget.reserved_bytes();
    let expected_scope = context.scope;
    let expected_tip = context.original_tip;
    let (context, error) = norito::core::with_decode_limits_scope(
        norito::core::DecodeLimits::new(1024, 1, 4096, 0, 32),
        || {
            LaneProofRead::new(context, 3)
                .err()
                .expect("field ceiling refuses original custody inspection")
        },
    );
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(matches!(
        error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(_)
    ));
    assert_eq!(context.scope, expected_scope);
    assert_eq!(context.original_tip, expected_tip);
    assert!(context.budget.same_pool(&budget));
    assert_eq!(budget.reserved_bytes(), retained);
    let mut reader =
        LaneProofRead::new(context, 3).unwrap_or_else(|(_, error)| panic!("retry: {error}"));
    reader.poll().unwrap();
    assert!(reader.verify(&vote_pair(&reader, 3)).is_ok());
    drop(reader);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_lane_verification_defers_typed_custody_decode_refusal() {
    let (chain, _guard) = anchored_chain(3);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut reader =
        LaneProofRead::new(capture(&chain), 3).unwrap_or_else(|_| panic!("original custody"));
    reader.poll().unwrap();
    let proof = vote_pair(&reader, 3);
    let retained = budget.reserved_bytes();
    norito::core::with_decode_limits_scope(
        norito::core::DecodeLimits::new(1024, 1, 4096, 0, 32),
        || {
            assert!(
                matches!(reader.verify(&proof), Err(super::super::NativeEvidenceError::Source(error))
            if error.io_kind() == io::ErrorKind::WouldBlock && matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(_)))
            )
        },
    );
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(reader.verify(&proof).is_ok());
    drop(reader);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_lane_observer_late_policy_refusal_retains_observation_and_retries() {
    use crate::execution_attempt::ExecutionAttemptError;
    use crate::sumeragi::evidence;
    let (chain, _guard) = anchored_chain(7);
    let mut reader = LaneProofRead::new(capture(&chain), 3)
        .unwrap_or_else(|_| panic!("original native coverage"));
    reader.poll().unwrap();
    let native = vote_pair(&reader, 3);
    let scope = reader.scope;
    drop(reader);
    let state = chain.state();
    assert!(evidence::observe_lane(state, scope.lane, scope.incarnation, &native).unwrap());
    let original = iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap();
    let reserved = state.evidence_preparation_budget().reserved_bytes();
    let ceiling = 1024 * 1024;
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let policy_bytes = norito::with_decode_limits_scope(limits(ceiling), || {
        assert!(
            state
                .view()
                .world()
                .sumeragi_npos_parameters()
                .unwrap()
                .is_some()
        );
        let norito::Error::TotalAllocationExceeded { attempted, limit } =
            norito::core::reserve_decode_allocation(ceiling + 1).unwrap_err()
        else {
            panic!("non-charging allocation probe");
        };
        assert_eq!(limit, u64::try_from(ceiling).unwrap());
        usize::try_from(attempted).unwrap() - ceiling - 1
    });
    assert!(policy_bytes > 0);
    norito::with_decode_limits_scope(limits(policy_bytes), || {
        assert!(
            state
                .view()
                .world()
                .sumeragi_npos_parameters()
                .unwrap()
                .is_some()
        );
    });
    // Scope admission consumes exactly one original policy read. The existing
    // retained collection requires a second read before pruning any entry.
    let error = norito::with_decode_limits_scope(limits(policy_bytes), || {
        evidence::observe_lane(state, scope.lane, scope.incarnation, &native)
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            evidence::EvidenceAdmissionError::Policy(ExecutionAttemptError::Deferred(_))
        ),
        "{error:?}"
    );
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        reserved
    );
    assert!(!evidence::observe_lane(state, scope.lane, scope.incarnation, &native).unwrap());
    assert_eq!(
        state.evidence_preparation_budget().reserved_bytes(),
        reserved
    );
    assert_eq!(
        iroha_data_model::block::consensus::Evidence::from_native(&native).unwrap(),
        original
    );
    let carrier = state.view().height() as u64 + 1;
    assert_eq!(
        evidence::pending_evidence_admissions(state, carrier, state.state_view_generation()),
        [original]
    );
}

#[test]
fn lane_verified_offender_graph_refuses_occupied_original_pool_and_retries() {
    let (chain, _guard) = anchored_chain(3);
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut reader = LaneProofRead::new(capture(&chain), 3)
        .unwrap_or_else(|(_, error)| panic!("original lane custody: {error}"));
    reader.poll().unwrap();
    let proof = vote_pair(&reader, 3);
    let config = std::ptr::from_ref(reader.cursor.config().epoch.as_ref());
    let headers = reader.headers.as_slice().as_ptr();
    let retained = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    let compact_bytes = reader.cursor.config().committee.members()[2]
        .as_bytes()
        .len()
        + 1;
    let expected = budget
        .try_reserve(std::alloc::Layout::array::<u8>(compact_bytes).unwrap())
        .unwrap_err();
    assert!(matches!(
        &expected,
        iroha_allocation::AllocationRefusal::Capacity { .. }
    ));
    let result = reader.verify(&proof);
    let error = result.expect_err(
        "occupied original offender pool must refuse before constructing a verified graph",
    );
    let classified = crate::sumeragi::evidence::EvidenceAdmissionError::from(error);
    assert!(matches!(classified,
        crate::sumeragi::evidence::EvidenceAdmissionError::Preparation(
            crate::state::EvidencePreparationError::Admission(actual)) if actual == expected));
    assert_eq!(
        std::ptr::from_ref(reader.cursor.config().epoch.as_ref()),
        config
    );
    assert_eq!(reader.headers.as_slice().as_ptr(), headers);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), retained);
    let verified = reader.verify(&proof).unwrap();
    assert_eq!(verified.tip(), reader.tip);
    assert_eq!(verified.offenders()[0].signer, 2);
    let vector = verified.offenders().as_ptr();
    let compact = verified.offenders()[0]
        .peer_id
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let held = budget.reserved_bytes();
    assert!(held > retained);
    let attribution = verified.into_attribution();
    assert!(attribution.belongs_to(&budget));
    assert_eq!(attribution.offenders.as_ptr(), vector);
    assert_eq!(
        attribution.offenders[0]
            .peer_id
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        compact
    );
    assert_eq!(budget.reserved_bytes(), held);
    drop(attribution);
    assert_eq!(budget.reserved_bytes(), retained);
    drop(reader);
    assert_eq!(budget.reserved_bytes(), baseline);
}
