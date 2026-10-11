//! Actual BLS evidence against original genesis execution and Worker publications.
use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};

fn chain() -> CertifiedTestChain {
    CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap()
}

fn conflict(chain: &CertifiedTestChain, height: u64) -> Evidence {
    Evidence::ConflictingCertificates(
        chain.commit_qc(
            height,
            Hash32([0x31; 32]),
            Hash32([0x32; 32]),
            Signers::Quorum,
        ),
        chain.commit_qc(
            height,
            Hash32([0x33; 32]),
            Hash32([0x34; 32]),
            Signers::LastThree,
        ),
    )
}

#[test]
fn original_genesis_authenticates_current_height_report_and_exact_signer_intersection() {
    let chain = chain();
    let evidence = conflict(&chain, 2);
    let view = chain.state().view();
    let mut reads = Vec::new();
    let verified = verify_from_state(&view, &evidence, |count, bytes| {
        reads.push((count, bytes));
        Ok(())
    })
    .unwrap();
    assert_eq!(verified.tip(), view.native_execution_tip().unwrap());
    assert_eq!(verified.instance(), chain.instance());
    assert_eq!(verified.height(), 2);
    assert!(verified.safety_violation());
    assert_eq!(
        verified
            .offenders()
            .iter()
            .map(|offender| offender.signer)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    for offender in verified.offenders() {
        assert_eq!(
            &offender.peer_id,
            &chain.validators()[offender.signer as usize].0
        );
        assert!(offender.lane_stake.is_none());
    }
    let config = view
        .world()
        .consensus_schedule()
        .ready(2)
        .unwrap()
        .height_config()
        .unwrap();
    assert_eq!(verified.epoch(), config.epoch.id);
    assert_eq!(
        verified.authority_generation(),
        config.epoch.authority_generation
    );
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].0, 1);
    assert!(reads[0].1 > 0);
}

#[test]
fn old_subject_uses_original_history_after_schedule_window_advances() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let evidence = conflict(&chain, 2);
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let view = chain.state().view();
    assert!(view.world().consensus_schedule().ready(2).is_err());
    let mut reads = 0;
    let verified = verify_from_state(&view, &evidence, |count, _| {
        reads += count;
        Ok(())
    })
    .unwrap();
    assert_eq!(verified.height(), 2);
    assert_eq!(verified.tip().height(), 4);
    assert_eq!(
        reads, 4,
        "one reverse walk includes the tip and original genesis"
    );
}

#[test]
fn interval_traversal_charges_each_source_once_and_preserves_descending_order() {
    let mut chain = chain();
    for _ in 0..3 {
        chain.commit(Vec::new());
    }
    let view = chain.state().view();
    let mut reads = 0;
    let mut selected = Vec::new();
    view.canonical_history()
        .visit_executed_backwards(
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(3).unwrap(),
            |count, _| {
                reads += count;
                Ok(())
            },
            |receipt| {
                selected.push(receipt.height());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(reads, 3);
    assert_eq!(selected, [3, 2]);
    assert!(
        view.canonical_history()
            .visit_executed_backwards(
                NonZeroUsize::new(3).unwrap(),
                NonZeroUsize::new(2).unwrap(),
                |_, _| panic!("reversed interval must not read"),
                |_| Ok(()),
            )
            .is_err()
    );
}

#[test]
fn foreign_instance_and_epoch_cannot_borrow_an_honest_historical_committee() {
    let chain = chain();
    let mut evidence = conflict(&chain, 2);
    let Evidence::ConflictingCertificates(first, _) = &mut evidence else {
        unreachable!()
    };
    first.instance.0[0] ^= 1;
    assert!(matches!(
        verify_from_state(&chain.state().view(), &evidence, |_, _| panic!(
            "foreign instance must not read"
        )),
        Err(NativeEvidenceError::Context(_))
    ));
    let mut evidence = conflict(&chain, 2);
    let Evidence::ConflictingCertificates(first, _) = &mut evidence else {
        unreachable!()
    };
    first.epoch.context.0[0] ^= 1;
    assert!(matches!(
        verify_from_state(&chain.state().view(), &evidence, |_, _| Ok(())),
        Err(NativeEvidenceError::Proof(_))
    ));
    let mut foreign = TestChainConfig::new(World::new(), 1_000);
    foreign.chain_id = "different-native-evidence-chain".into();
    let foreign = CertifiedTestChain::start(foreign).unwrap();
    assert!(matches!(
        verify_from_state(
            &foreign.state().view(),
            &conflict(&chain, 2),
            |_, _| panic!("foreign configured chain must not read")
        ),
        Err(NativeEvidenceError::Context(_))
    ));
}

#[test]
fn local_history_refusal_and_corrupt_original_tip_never_become_attribution() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let evidence = conflict(&chain, 2);
    let mut reads = 0;
    assert!(matches!(
        verify_from_state(&chain.state().view(), &evidence, |count, _| {
            reads += count;
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into()))
        }),
        Err(NativeEvidenceError::History(
            crate::execution_attempt::ExecutionAttemptError::Deferred(local)
        )) if local.reason() == ivm::error::ExecutionDeferral::CanonicalHistoryCapacity
    ));
    assert_eq!(reads, 1);
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(2).unwrap());
    let mut reads = 0;
    assert!(matches!(
        verify_from_state(&chain.state().view(), &evidence, |count, _| {
            reads += count;
            Ok(())
        }),
        Err(NativeEvidenceError::History(_))
    ));
    assert_eq!(reads, 1, "corruption stops at the first actual source");
}

#[test]
fn below_quorum_and_identical_certificate_values_are_rejected() {
    let chain = chain();
    let mut evidence = conflict(&chain, 2);
    let Evidence::ConflictingCertificates(first, _) = &mut evidence else {
        unreachable!()
    };
    *first = chain.commit_qc(
        2,
        Hash32([0x31; 32]),
        Hash32([0x32; 32]),
        Signers::BelowQuorum,
    );
    assert!(matches!(
        verify_from_state(&chain.state().view(), &evidence, |_, _| Ok(())),
        Err(NativeEvidenceError::Proof(_))
    ));
    let mut evidence = conflict(&chain, 2);
    let Evidence::ConflictingCertificates(first, second) = &mut evidence else {
        unreachable!()
    };
    *second = first.clone();
    assert!(matches!(
        verify_from_state(&chain.state().view(), &evidence, |_, _| Ok(())),
        Err(NativeEvidenceError::Proof(EvidenceError::NotConflicting))
    ));
}

#[test]
fn original_history_refuses_false_parent_qc_reports_and_preserves_signed_safety_evidence() {
    use crate::sumeragi::crypto::KeyPairSigner;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::peer::PeerId;
    use iroha_sumeragi::{
        crypto::{Crypto, Signer, Verifier},
        message::{BlockHeader, Defect, Proposal, Qc},
        topology::Topology,
        types::{ControlWitness, SIGNATURE_LEN, Signature},
    };

    let mut chain = chain();
    chain.commit(Vec::new());
    let original_tip = chain.state().view().native_execution_tip().unwrap();
    let instance = chain.instance();
    let parent = chain.committed(2);
    let genesis = chain.committed(1);
    let ScheduledSlot::Ready(parent_slot) = &genesis.commitment().schedule.next else {
        panic!("original genesis authorizes the parent")
    };
    let parent_config = parent_slot.height_config().unwrap();
    let mut keys = [0xC1, 0xC2, 0xC3, 0xC4]
        .into_iter()
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let crypto = BlsCrypto::new();
    for (key, (peer, proof)) in keys.iter().zip(chain.validators()) {
        assert_eq!(key.public_key(), peer.public_key());
        crypto.admit(key.public_key(), proof).unwrap();
    }
    let view = chain.state().view();
    let config = view
        .world()
        .consensus_schedule()
        .ready(3)
        .unwrap()
        .height_config()
        .unwrap();
    let window = view.world().parameters().sumeragi().demotion_window.get();
    let topology = Topology::compute(
        &crypto,
        &chain.instance(),
        &config.epoch,
        &config.committee,
        3,
        GENESIS_HEIGHT,
        window,
        &[parent.header().unwrap().clone()],
    );
    let leader = topology.leader(0);
    let sign_qc = |qc: &mut Qc| {
        qc.agg_sig = crypto.aggregate(
            &qc.signers
                .ones()
                .map(|index| {
                    KeyPairSigner::new(&keys[index as usize])
                        .unwrap()
                        .sign(&qc.preimage())
                })
                .collect::<Vec<_>>(),
        );
    };
    let report = |qc, defect| {
        let mut proposal = Proposal {
            instance: chain.instance(),
            height: 3,
            view: 0,
            header: BlockHeader {
                instance: chain.instance(),
                epoch: config.epoch.id,
                height: 3,
                origin_view: 0,
                parent_hash: parent.core_hash(),
                parent_result: parent.result(),
                payload_hash: Hash32([0x71; 32]),
                availability_digest: Hash32([0x72; 32]),
                payload_len: 1,
                proposer: leader,
                skipped_leaders: topology.skipped_leader_keys(&config.committee, 0),
                control_witness: ControlWitness::empty(),
            },
            justify: None,
            parent_qc: Some(qc),
            sig: Signature([0; SIGNATURE_LEN]),
        };
        proposal.sig = KeyPairSigner::new(&keys[leader as usize])
            .unwrap()
            .sign(&proposal.signing_preimage(&crypto));
        Evidence::InvalidProposal {
            proposal: Box::new(proposal),
            defect,
        }
    };
    let ordinary = chain.commit_qc(2, parent.core_hash(), parent.result(), Signers::Quorum);
    let parent_epoch = ordinary.epoch;
    let verifier = Verifier::new(&crypto, &instance, &parent_epoch, &parent_config.committee);
    verifier.verify_qc(&ordinary).unwrap();
    assert!(matches!(
        verify_from_state(
            &view,
            &report(ordinary.clone(), Defect::InvalidParentQc),
            |_, _| Ok(())
        ),
        Err(NativeEvidenceError::Proof(EvidenceError::DefectMismatch))
    ));

    // Genuine conflicting exact quorums remain attributable independent of application state.
    let Evidence::ConflictingCertificates(mut first, mut second) = conflict(&chain, 3) else {
        unreachable!()
    };
    sign_qc(&mut first);
    sign_qc(&mut second);
    let verified = verify_from_state(
        &view,
        &Evidence::ConflictingCertificates(first, second),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(verified.safety_violation());
    assert_eq!(
        verified
            .offenders()
            .iter()
            .map(|offender| offender.signer)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(verified.tip(), original_tip);
    assert_eq!(view.native_execution_tip(), Some(original_tip));
    assert_eq!(
        chain.state().view().native_execution_tip(),
        Some(original_tip)
    );
}
