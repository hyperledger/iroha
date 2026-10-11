//! Native evidence attribution controls over original signed protocol fixtures.

use super::*;
use crate::{
    crypto::Signer,
    message::{Qc, Vote},
    testing::{FakeValidators, TEST_EPOCH},
    types::{ChainParams, ControlWitness, EpochId, ValidatorIndex},
};

const I: Hash32 = Hash32([0x51; 32]);
fn h(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

struct Fixture {
    validators: FakeValidators,
    config: HeightConfig,
    parent: CommittedTip,
}
impl Fixture {
    fn new() -> Self {
        let validators = FakeValidators::new(4, 8001, None);
        let config = HeightConfig {
            epoch: Box::new(TEST_EPOCH),
            committee: validators.committee.clone(),
            params: ChainParams::default(),
        };
        Self {
            validators,
            config,
            parent: CommittedTip {
                height: 1,
                block_hash: h(1),
                result: h(2),
                header: None,
                commit_qc: None,
            },
        }
    }
    fn context(&self) -> EvidenceContext<'_> {
        EvidenceContext {
            instance: I,
            height: 2,
            config: &self.config,
            genesis_height: 1,
            parent: &self.parent,
            parent_config: None,
            demotion_window: 0,
            demotion_headers: &[],
        }
    }
    fn verify(&self, evidence: &Evidence) -> Result<EvidenceAttribution, EvidenceError> {
        verify_evidence(&self.validators.crypto, &self.context(), evidence)
    }
    fn header(&self, view: u64) -> BlockHeader {
        let topology = self.context().topology(&self.validators.crypto).unwrap();
        BlockHeader {
            instance: I,
            epoch: TEST_EPOCH.id,
            height: 2,
            origin_view: view,
            parent_hash: self.parent.block_hash,
            parent_result: self.parent.result,
            payload_hash: h(3),
            availability_digest: crate::types::Hash32::ZERO,
            payload_len: 1,
            proposer: topology.leader(view),
            skipped_leaders: topology.skipped_leader_keys(&self.config.committee, view),

            control_witness: ControlWitness::empty(),
        }
    }
    fn proposal(&self, header: BlockHeader, view: u64) -> Proposal {
        let leader = self
            .context()
            .topology(&self.validators.crypto)
            .unwrap()
            .leader(view);
        self.validators
            .proposal(leader, &I, 2, view, header, None, None)
    }
    fn resign(&self, proposal: &mut Proposal) {
        let leader = self
            .context()
            .topology(&self.validators.crypto)
            .unwrap()
            .leader(proposal.view);
        proposal.sig = self
            .validators
            .signer(leader)
            .sign(&proposal.signing_preimage(&self.validators.crypto));
    }
    fn vote(&self, block: u8) -> Vote {
        self.validators
            .vote(VoteKind::Prepare, 1, &I, 2, 0, &h(block), &h(9))
    }
    fn qc(&self, kind: VoteKind, view: u64, block: u8, signers: &[ValidatorIndex]) -> Qc {
        self.validators
            .qc(kind, &I, 2, view, &h(block), &h(9), signers)
    }
}

#[test]
fn vote_conflicts_bind_all_signed_values_and_original_signer() {
    let fixture = Fixture::new();
    let first = fixture.vote(3);
    let second = fixture.vote(4);
    let proof = Evidence::VoteEquivocation(first, second);
    let result = fixture.verify(&proof).unwrap();
    assert_eq!(result.offenders.ones().collect::<Vec<_>>(), [1]);
    assert!(!result.safety_violation());
    assert_eq!(result.height(), 2);
    assert_eq!(result.offenders().count_ones(), 1);
    let mut forged = second;
    forged.sig.0[0] ^= 1;
    assert!(matches!(
        fixture.verify(&Evidence::VoteEquivocation(first, forged)),
        Err(EvidenceError::Signature(_))
    ));
    let mut other_signer = second;
    other_signer.signer = 2;
    assert_eq!(
        fixture.verify(&Evidence::VoteEquivocation(first, other_signer)),
        Err(EvidenceError::NotConflicting)
    );
    let unsigned = first;
    assert_eq!(
        fixture.verify(&Evidence::VoteEquivocation(first, unsigned)),
        Err(EvidenceError::NotConflicting)
    );
}

#[test]
fn instance_epoch_context_and_height_replay_do_not_attribute() {
    let fixture = Fixture::new();
    let proof = Evidence::VoteEquivocation(fixture.vote(3), fixture.vote(4));
    let mut context = fixture.context();
    context.instance = h(99);
    assert_eq!(
        verify_evidence(&fixture.validators.crypto, &context, &proof),
        Err(EvidenceError::Signature(CertError::WrongInstance))
    );
    let mut config = fixture.config.clone();
    config.epoch.id = EpochId {
        epoch: 1,
        context: TEST_EPOCH.id.context,
    };
    context = fixture.context();
    context.config = &config;
    assert_eq!(
        verify_evidence(&fixture.validators.crypto, &context, &proof),
        Err(EvidenceError::Signature(CertError::WrongEpoch))
    );
    let mut different_context = fixture.config.clone();
    different_context.epoch.id = EpochId {
        epoch: 0,
        context: h(0xEE),
    };
    context.config = &different_context;
    assert_eq!(
        verify_evidence(&fixture.validators.crypto, &context, &proof),
        Err(EvidenceError::Signature(CertError::WrongEpoch))
    );
    context = fixture.context();
    context.height = 3;
    assert_eq!(
        verify_evidence(&fixture.validators.crypto, &context, &proof),
        Err(EvidenceError::Context)
    );
}

#[test]
fn noncommittee_geometry_and_missing_demotion_history_fail_closed() {
    let fixture = Fixture::new();
    let proof = Evidence::VoteEquivocation(fixture.vote(3), fixture.vote(4));
    let mut config = fixture.config.clone();
    config.committee = FakeValidators::new(5, 8, None).committee;
    let mut context = fixture.context();
    context.config = &config;
    assert_eq!(
        verify_evidence(&fixture.validators.crypto, &context, &proof),
        Err(EvidenceError::Context)
    );
    let parent = CommittedTip {
        height: 4,
        ..fixture.parent.clone()
    };
    context = fixture.context();
    context.height = 5;
    context.parent = &parent;
    context.parent_config = Some(&fixture.config);
    context.demotion_window = 2;
    assert_eq!(
        context.topology(&fixture.validators.crypto),
        Err(EvidenceError::DemotionHistory)
    );
    let mut headers = [fixture.header(0), fixture.header(0)];
    headers[1].height = 3;
    context.demotion_headers = &headers;
    assert!(context.topology(&fixture.validators.crypto).is_ok());
    let mut foreign_headers = headers.clone();
    foreign_headers[1].instance = h(98);
    context.demotion_headers = &foreign_headers;
    assert_eq!(
        context.topology(&fixture.validators.crypto),
        Err(EvidenceError::DemotionHistory)
    );
}

#[test]
fn proposal_equivocation_requires_actual_leader_and_distinct_signed_content() {
    let fixture = Fixture::new();
    let first = fixture.proposal(fixture.header(0), 0);
    let mut header = fixture.header(0);
    header.payload_hash = h(4);
    let second = fixture.proposal(header, 0);
    let expected = fixture
        .context()
        .topology(&fixture.validators.crypto)
        .unwrap()
        .leader(0);
    assert_eq!(
        fixture
            .verify(&Evidence::ProposalEquivocation(
                Box::new(first.clone()),
                Box::new(second.clone())
            ))
            .unwrap()
            .offenders
            .ones()
            .collect::<Vec<_>>(),
        [expected]
    );
    // A relay's corrupt availability carrier cannot manufacture signed equivocation.
    let unsigned = crate::message::ProposalMessage {
        proposal: first.clone(),
        availability: crate::availability::AvailabilityFrame::from_untrusted(vec![0xff; 4])
            .unwrap(),
    };
    assert_eq!(
        fixture.verify(&Evidence::ProposalEquivocation(
            Box::new(first.clone()),
            Box::new(unsigned.proposal)
        )),
        Err(EvidenceError::NotConflicting)
    );
    let mut wrong_leader = second;
    wrong_leader.sig = fixture
        .validators
        .signer((expected + 1) % 4)
        .sign(&wrong_leader.signing_preimage(&fixture.validators.crypto));
    assert_eq!(
        fixture.verify(&Evidence::ProposalEquivocation(
            Box::new(first),
            Box::new(wrong_leader)
        )),
        Err(EvidenceError::Signature(CertError::BadSignature))
    );
}

#[test]
fn timeout_evidence_compares_signed_highest_view_and_verifies_carried_qc() {
    let fixture = Fixture::new();
    let first = fixture.validators.timeout(1, &I, 2, 2, None);
    let second = fixture.validators.timeout(
        1,
        &I,
        2,
        2,
        Some(fixture.qc(VoteKind::Prepare, 1, 7, &[0, 1, 2])),
    );
    assert_eq!(
        fixture
            .verify(&Evidence::TimeoutEquivocation(
                Box::new(first.clone()),
                Box::new(second.clone())
            ))
            .unwrap()
            .offenders
            .ones()
            .collect::<Vec<_>>(),
        [1]
    );
    let same_view = fixture.validators.timeout(
        1,
        &I,
        2,
        2,
        Some(fixture.qc(VoteKind::Prepare, 1, 8, &[0, 1, 2])),
    );
    assert_eq!(
        fixture.verify(&Evidence::TimeoutEquivocation(
            Box::new(second.clone()),
            Box::new(same_view)
        )),
        Err(EvidenceError::NotConflicting)
    );
    let mut bad = second;
    bad.high_pqc.as_mut().unwrap().agg_sig.0[0] ^= 1;
    assert_eq!(
        fixture.verify(&Evidence::TimeoutEquivocation(
            Box::new(first),
            Box::new(bad)
        )),
        Err(EvidenceError::Signature(CertError::HighQcInvalid))
    );
}

#[test]
fn only_same_view_certificate_intersection_is_accountable() {
    let fixture = Fixture::new();
    let first = fixture.qc(VoteKind::Commit, 0, 3, &[0, 1, 2]);
    let second = fixture.qc(VoteKind::Commit, 0, 4, &[1, 2, 3]);
    let same = fixture
        .verify(&Evidence::ConflictingCertificates(first.clone(), second))
        .unwrap();
    assert!(same.safety_violation);
    assert_eq!(same.offenders.ones().collect::<Vec<_>>(), [1, 2]);
    let later = fixture.qc(VoteKind::Commit, 1, 4, &[1, 2, 3]);
    let cross = fixture
        .verify(&Evidence::ConflictingCertificates(first.clone(), later))
        .unwrap();
    assert!(cross.safety_violation);
    assert_eq!(cross.offenders.count_ones(), 0);
    let extra = fixture.qc(VoteKind::Commit, 0, 4, &[0, 1, 2, 3]);
    assert_eq!(
        fixture.verify(&Evidence::ConflictingCertificates(first.clone(), extra)),
        Err(EvidenceError::Signature(CertError::TooManySigners))
    );
    let below = fixture.qc(VoteKind::Commit, 0, 4, &[1, 2]);
    assert_eq!(
        fixture.verify(&Evidence::ConflictingCertificates(first, below)),
        Err(EvidenceError::Signature(CertError::TooFewSigners))
    );
}

#[test]
fn signed_header_defects_reproduce_but_poison_execution_does_not() {
    let fixture = Fixture::new();
    let ordinary = fixture.proposal(fixture.header(0), 0);
    for defect in [
        Defect::HeaderInstance,
        Defect::HeaderHeight,
        Defect::ParentHash,
        Defect::ParentResult,
        Defect::PayloadTooLarge,
        Defect::EmptyPayload,
        Defect::OriginView,
        Defect::Proposer,
        Defect::SkippedLeaders,
    ] {
        let mut header = fixture.header(0);
        match defect {
            Defect::HeaderInstance => header.instance = h(98),
            Defect::HeaderHeight => header.height += 1,
            Defect::ParentHash => header.parent_hash = h(98),
            Defect::ParentResult => header.parent_result = h(98),
            Defect::PayloadTooLarge => {
                header.payload_len = fixture.config.params.max_block_bytes + 1
            }
            Defect::EmptyPayload => header.payload_len = 0,
            Defect::OriginView => header.origin_view = 1,
            Defect::Proposer => header.proposer = (header.proposer + 1) % 4,
            Defect::SkippedLeaders => header.skipped_leaders.push(fixture.validators.key(0)),
            _ => unreachable!(),
        }
        let report = Evidence::InvalidProposal {
            proposal: Box::new(fixture.proposal(header, 0)),
            defect,
        };
        assert!(fixture.verify(&report).is_ok(), "{defect:?}");
        assert_eq!(
            fixture.verify(&Evidence::InvalidProposal {
                proposal: Box::new(ordinary.clone()),
                defect
            }),
            Err(EvidenceError::DefectMismatch)
        );
    }
    // The carrier fails availability verification; it does not prove a signed empty payload.
    let poison = crate::message::ProposalMessage {
        proposal: ordinary.clone(),
        availability: crate::availability::AvailabilityFrame::from_untrusted(vec![0xff; 4])
            .unwrap(),
    };
    assert_eq!(
        fixture.verify(&Evidence::InvalidProposal {
            proposal: Box::new(poison.proposal),
            defect: Defect::EmptyPayload
        }),
        Err(EvidenceError::DefectMismatch)
    );
}

/// Follower stage of the resource contract (`specs/zk_resource_contract.json`,
/// `block.max_block_bytes`): the signed payload length is inclusive at the committed limit,
/// and one byte over is the same reproducible defect for every independent verifier.
#[test]
fn payload_limit_is_inclusive_and_one_over_rejects_identically_on_every_verifier() {
    let verdicts = |fixture: &Fixture| {
        let limit = fixture.config.params.max_block_bytes;
        let report = |payload_len: u32| {
            let mut header = fixture.header(0);
            header.payload_len = payload_len;
            fixture.verify(&Evidence::InvalidProposal {
                proposal: Box::new(fixture.proposal(header, 0)),
                defect: Defect::PayloadTooLarge,
            })
        };
        (report(limit), report(limit + 1), report(u32::MAX))
    };
    let first = verdicts(&Fixture::new());
    // A payload of exactly the limit carries no defect: the accusation does not reproduce.
    assert_eq!(first.0, Err(EvidenceError::DefectMismatch));
    // One byte over is malformed carried evidence: it reproduces from the signed header alone.
    let over = first.1.as_ref().expect("one byte over is a signed defect");
    assert_eq!(over.offenders.count_ones(), 1);
    assert!(first.2.is_ok());
    // A second, independently constructed verifier derives the identical verdicts.
    assert_eq!(verdicts(&Fixture::new()), first);
    // The verdict follows the committed limit, never a local setting.
    let mut smaller = Fixture::new();
    smaller.config.params.max_block_bytes = 1;
    let (at_limit, one_over, _) = verdicts(&smaller);
    assert_eq!(at_limit, Err(EvidenceError::DefectMismatch));
    assert!(one_over.is_ok());
}

#[test]
fn justification_defect_and_tc_rule_require_original_signed_attachments() {
    let fixture = Fixture::new();
    let missing = fixture.proposal(fixture.header(1), 1);
    assert!(
        fixture
            .verify(&Evidence::InvalidProposal {
                proposal: Box::new(missing),
                defect: Defect::MissingJustify
            })
            .is_ok()
    );
    let mut unexpected = fixture.proposal(fixture.header(0), 0);
    unexpected.justify = Some(
        fixture
            .validators
            .tc(&I, 2, 0, &[(0, None), (1, None), (2, None)]),
    );
    fixture.resign(&mut unexpected);
    assert!(
        fixture
            .verify(&Evidence::InvalidProposal {
                proposal: Box::new(unexpected),
                defect: Defect::UnexpectedJustify
            })
            .is_ok()
    );
    let mut invalid = fixture.proposal(fixture.header(1), 1);
    invalid.justify = Some(
        fixture
            .validators
            .tc(&I, 2, 2, &[(0, None), (1, None), (2, None)]),
    );
    fixture.resign(&mut invalid);
    assert!(
        fixture
            .verify(&Evidence::InvalidProposal {
                proposal: Box::new(invalid),
                defect: Defect::InvalidJustify
            })
            .is_ok()
    );
    let mut tc_rule = fixture.proposal(fixture.header(1), 1);
    tc_rule.justify = Some(fixture.validators.tc(
        &I,
        2,
        0,
        &[
            (0, Some(fixture.qc(VoteKind::Prepare, 0, 98, &[0, 1, 2]))),
            (1, None),
            (2, None),
        ],
    ));
    fixture.resign(&mut tc_rule);
    assert!(
        fixture
            .verify(&Evidence::InvalidProposal {
                proposal: Box::new(tc_rule),
                defect: Defect::TcRule
            })
            .is_ok()
    );
}

#[test]
fn evidence_errors_remain_distinct() {
    assert_ne!(
        EvidenceError::Context.to_string(),
        EvidenceError::DemotionHistory.to_string()
    );
    assert_ne!(
        EvidenceError::NotConflicting.to_string(),
        EvidenceError::DefectMismatch.to_string()
    );
    assert!(
        EvidenceError::from(CertError::WrongEpoch)
            .to_string()
            .contains("WrongEpoch")
    );
}

#[test]
fn parent_defects_use_the_authenticated_parent_configuration() {
    let fixture = Fixture::new();
    let parent = CommittedTip {
        height: 2,
        block_hash: h(3),
        result: h(9),
        header: None,
        commit_qc: None,
    };
    let mut context = fixture.context();
    context.height = 3;
    context.parent = &parent;
    context.parent_config = Some(&fixture.config);
    let topology = context.topology(&fixture.validators.crypto).unwrap();
    let mut header = fixture.header(0);
    header.height = 3;
    header.proposer = topology.leader(0);
    header.parent_hash = parent.block_hash;
    header.parent_result = parent.result;
    let leader = topology.leader(0);
    let missing = fixture
        .validators
        .proposal(leader, &I, 3, 0, header.clone(), None, None);
    assert!(
        verify_evidence(
            &fixture.validators.crypto,
            &context,
            &Evidence::InvalidProposal {
                proposal: Box::new(missing),
                defect: Defect::MissingParentQc
            }
        )
        .is_ok()
    );
    let wrong = fixture.validators.proposal(
        leader,
        &I,
        3,
        0,
        header.clone(),
        None,
        Some(fixture.qc(VoteKind::Commit, 0, 98, &[0, 1, 2])),
    );
    assert!(
        verify_evidence(
            &fixture.validators.crypto,
            &context,
            &Evidence::InvalidProposal {
                proposal: Box::new(wrong),
                defect: Defect::InvalidParentQc
            }
        )
        .is_ok()
    );
    let valid = fixture.validators.proposal(
        leader,
        &I,
        3,
        0,
        header,
        None,
        Some(fixture.qc(VoteKind::Commit, 0, 3, &[0, 1, 2])),
    );
    assert_eq!(
        verify_evidence(
            &fixture.validators.crypto,
            &context,
            &Evidence::InvalidProposal {
                proposal: Box::new(valid),
                defect: Defect::InvalidParentQc
            }
        ),
        Err(EvidenceError::DefectMismatch)
    );
    context.parent_config = None;
    assert_eq!(context.validate(), Err(EvidenceError::Context));
    let mut unexpected = fixture.proposal(fixture.header(0), 0);
    unexpected.parent_qc = Some(fixture.qc(VoteKind::Commit, 0, 3, &[0, 1, 2]));
    fixture.resign(&mut unexpected);
    assert!(
        fixture
            .verify(&Evidence::InvalidProposal {
                proposal: Box::new(unexpected),
                defect: Defect::UnexpectedParentQc
            })
            .is_ok()
    );
}

/// A well-formed epoch boundary reproduces no signed defect under its authenticated context.
#[test]
fn epoch_boundary_is_no_signed_defect() {
    let fixture = Fixture::new();
    let mut config = fixture.config.clone();
    config.epoch.last_height = 2;
    let mut context = fixture.context();
    context.config = &config;

    let header = fixture.header(0);
    let proposal = fixture.proposal(header, 0);
    for defect in [
        Defect::UnexpectedJustify,
        Defect::MissingJustify,
        Defect::InvalidJustify,
        Defect::MissingParentQc,
        Defect::UnexpectedParentQc,
        Defect::InvalidParentQc,
        Defect::HeaderInstance,
        Defect::HeaderHeight,
        Defect::EpochContext,
        Defect::ParentHash,
        Defect::ParentResult,
        Defect::PayloadTooLarge,
        Defect::TcRule,
        Defect::OriginView,
        Defect::Proposer,
        Defect::SkippedLeaders,
        Defect::EmptyPayload,
    ] {
        assert_eq!(
            verify_evidence(
                &fixture.validators.crypto,
                &context,
                &Evidence::InvalidProposal {
                    proposal: Box::new(proposal.clone()),
                    defect,
                }
            ),
            Err(EvidenceError::DefectMismatch),
            "claimed {defect:?}"
        );
    }
}

#[test]
fn borrowed_demotion_owners_preserve_slice_topology_and_every_interval_rejection() {
    struct OriginalHeader(Box<BlockHeader>);
    impl Borrow<BlockHeader> for OriginalHeader {
        fn borrow(&self) -> &BlockHeader {
            &self.0
        }
    }
    let fixture = Fixture::new();
    let parent = CommittedTip {
        height: 4,
        ..fixture.parent.clone()
    };
    let mut first = fixture.header(0);
    first.height = 2;
    first.skipped_leaders = vec![fixture.config.committee.members()[1].clone()];
    let mut second = first.clone();
    second.height = 3;
    second.skipped_leaders = vec![fixture.config.committee.members()[2].clone()];
    let headers = [first, second];
    let context = EvidenceContext {
        instance: I,
        height: 5,
        config: &fixture.config,
        genesis_height: 1,
        parent: &parent,
        parent_config: Some(&fixture.config),
        demotion_window: 2,
        demotion_headers: &headers,
    };
    let expected = context.topology(&fixture.validators.crypto).unwrap();
    for case in 0..5 {
        let mut source = headers.to_vec();
        match case {
            0 => {}
            1 => {
                source.pop();
            }
            2 => source[1] = source[0].clone(),
            3 => source.swap(0, 1),
            4 => source[1].instance = h(99),
            _ => unreachable!(),
        }
        let owners: Vec<_> = source
            .into_iter()
            .map(|header| OriginalHeader(Box::new(header)))
            .collect();
        let borrowed = EvidenceContext {
            instance: context.instance,
            height: context.height,
            config: context.config,
            genesis_height: context.genesis_height,
            parent: context.parent,
            parent_config: context.parent_config,
            demotion_window: context.demotion_window,
            demotion_headers: &owners,
        };
        let actual = borrowed.topology(&fixture.validators.crypto);
        if case == 0 {
            assert_eq!(actual, Ok(expected.clone()));
        } else {
            assert_eq!(actual, Err(EvidenceError::DemotionHistory), "case {case}");
        }
    }
}
