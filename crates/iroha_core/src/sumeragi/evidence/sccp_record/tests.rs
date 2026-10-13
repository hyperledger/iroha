//! Structural-custody DATA controls; no valid signature or admission is claimed here.
use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    sccp::native::SccpForgeryRuleV1,
    sumeragi_finality::certified_result::{
        FLAG_ACTIVE, SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1,
    },
};
use iroha_model_base::{peer::PeerId, topology::LaneId};
use iroha_sccp::v1::finality::QcFixedV1;
use norito::codec::Encode as _;

pub(super) fn claim() -> EvidenceRecord {
    let account = AccountId::new(
        KeyPair::try_from_seed(vec![11; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    let peer = KeyPair::try_from_seed(vec![12; 32], Algorithm::BlsNormal).unwrap();
    let header = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: [1; 32],
        height: 2,
        timestamp_ms: 2_000,
        flags: FLAG_ACTIVE,
        generation: 7,
        committee_root: [3; 32],
        ..Default::default()
    })
    .unwrap();
    let qc = QcFixedV1 {
        epoch: 3,
        epoch_context: [4; 32],
        view: 5,
        block_hash: [6; 32],
        result_body: [7; 32],
        signers: 7,
    };
    EvidenceRecord {
        evidence: RecordedEvidenceV1::SccpForgery(Box::new(SccpForgeryRecordV1 {
            evidence: SubmitSccpForgeryEvidenceV1 {
                qc: qc.encode(),
                header: *header.as_bytes(),
                aggregate_signature: [0; 96],
                anchor: None,
            },
            rule: SccpForgeryRuleV1::E2,
            generation: 7,
            start_height: 1,
            offenders: vec![SccpForgeryOffenderV1 {
                signer: 0,
                lane_id: LaneId::SINGLE,
                validator: account,
                activation_height: 1,
            }],
        })),
        attribution: EvidenceAttribution {
            scope: EvidenceScope::SccpGeneration { generation: 7 },
            instance: [9; 32],
            height: 1,
            epoch: 3,
            context_id: [4; 32],
            authority_generation: [3; 32],
            offenders: vec![EvidenceOffender {
                signer: 0,
                peer_id: PeerId::new(peer.public_key().clone()),
                lane_stake: None,
            }],
            safety_violation: true,
        },
        recorded_at_height: 9,
        recorded_at_view: 1,
        recorded_at_ms: 9_000,
        penalty_status: iroha_data_model::block::consensus::EvidencePenaltyStatus::Pending,
    }
}
fn parse(
    record: &EvidenceRecord,
    budget: &AllocationBudget,
) -> Result<RetainedEvidenceRecord, Error> {
    let text = json::to_json(record).unwrap();
    super::super::parse_record(&mut Parser::new(&text), budget)
}
#[test]
fn closed_sccp_claim_roundtrips_exact_wire_and_shares_original_graph() {
    let source = claim();
    let pool = AllocationBudget::new(1 << 20);
    let owner = parse(&source, &pool).unwrap();
    assert!(owner.native_evidence().is_none());
    assert_eq!(owner.canonical_projection(), source);
    assert_eq!(owner.encode(), source.encode());
    assert_eq!(
        json::to_json(&owner).unwrap(),
        json::to_json(&source).unwrap()
    );
    let retained = pool.reserved_bytes();
    assert!(retained > 0);
    assert!(owner.body_belongs_to(&pool));
    let mut successor = owner.clone();
    assert_eq!(pool.reserved_bytes(), retained);
    assert!(owner.shares_body(&successor));
    successor.penalty_status =
        iroha_data_model::block::consensus::EvidencePenaltyStatus::Applied { height: 10 };
    assert_ne!(owner, successor);
    assert_eq!(owner.penalty_status, source.penalty_status);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), retained);
    drop(successor);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn source_scope_signer_coordinates_and_lifecycle_material_cannot_be_substituted() {
    let source = claim();
    let pool = AllocationBudget::new(1 << 20);
    for variant in 0..8 {
        let mut bad = source.clone();
        match variant {
            0 => bad.attribution.scope = EvidenceScope::Root,
            1 => bad.attribution.scope = EvidenceScope::SccpGeneration { generation: 8 },
            2 => bad.attribution.height = 2,
            3 => bad.attribution.epoch += 1,
            4 => bad.attribution.context_id[0] ^= 1,
            5 => bad.attribution.authority_generation[0] ^= 1,
            6 => bad.attribution.safety_violation = false,
            7 => bad.attribution.offenders[0].signer = 1,
            _ => unreachable!(),
        }
        assert!(parse(&bad, &pool).is_err(), "substitution {variant}");
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let mut native = source.clone();
    native.evidence = RecordedEvidenceV1::Native(iroha_data_model::block::consensus::Evidence {
        native: Vec::new(),
    });
    assert!(parse(&native, &pool).is_err());
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn tiny_original_pool_and_active_outer_decoder_refuse_without_retained_graph() {
    let source = claim();
    let pool = AllocationBudget::new(0);
    assert!(matches!(
        parse(&source, &pool),
        Err(Error::Preparation(Preparation::Admission(_)))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(1 << 20);
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let result = norito::core::with_decode_limits_scope(limits, || parse(&source, &pool));
    assert!(result.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(parse(&source, &pool).is_ok());
}
#[test]
fn canonical_closed_discriminator_rejects_bare_unknown_and_truncated_records() {
    let source = json::to_json(&claim()).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let unknown = source.replace("sccp_forgery", "not_a_material");
    assert!(super::super::parse_record(&mut Parser::new(&unknown), &pool).is_err());
    for end in [0, 1, source.len() / 2, source.len() - 1] {
        assert!(super::super::parse_record(&mut Parser::new(&source[..end]), &pool).is_err());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn discriminator_and_escaped_keys_are_charged_before_branch_selection() {
    let valid = json::to_json(&claim()).unwrap();
    let absent = AllocationBudget::new(0);
    assert!(matches!(
        material_kind(&valid, &absent),
        Err(Error::Preparation(Preparation::Admission(_)))
    ));
    assert_eq!(absent.reserved_bytes(), 0);
    for raw in [
        valid.replace("sccp_forgery", &"x".repeat(16384)),
        valid.replace("evidence", &format!("{}evidence", "\\u0061".repeat(16384))),
    ] {
        let pool = AllocationBudget::new(512);
        assert!(
            matches!(
                material_kind(&raw, &pool),
                Err(Error::Logical(_)) | Err(Error::Preparation(_))
            ),
            "oversized discriminator/key must refuse original resources"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let pool = AllocationBudget::new(1 << 20);
    assert!(matches!(
        material_kind(&valid, &pool),
        Ok(MaterialKind::SccpForgery)
    ));
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "branch scratch retires before the selected body decode"
    );
}

#[test]
fn verified_claim_box_is_exactly_funded_refunds_late_refusal_and_retries() {
    use crate::{
        smartcontracts::isi::sccp::{
            forgery::{
                tests::{active_member_chain, future},
                verify_committed,
            },
            read::native::SccpNativeReadControl,
        },
        state::StateReadOnly as _,
    };
    use iroha_allocation::AllocationRefusal;
    use std::{
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };

    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let view = chain.state().view();
    let scratch = AllocationBudget::new(
        iroha_crypto::bls::consensus::ConsensusAggregateScratch::<()>::backing_bytes(),
    );
    let stop = AtomicBool::new(false);
    let verified = verify_committed(
        &view,
        &evidence,
        view.native_execution_tip().unwrap().creation_time_ms() + 1_000,
        &scratch,
        SccpNativeReadControl {
            deadline: Instant::now() + Duration::from_secs(60),
            stop: &stop,
        },
    )
    .unwrap();
    assert_eq!(scratch.reserved_bytes(), 0);
    let count = usize::try_from(verified.qc().signers.count_ones()).unwrap();
    let mut account_bytes = 0;
    let mut account_allocations = 0;
    for (_, _, member) in verified.signers() {
        member
            .unwrap()
            .validator
            .for_each_admission_clone_layout(|layout| {
                account_bytes += layout.size();
                account_allocations += 1;
            })
            .unwrap();
    }
    // Each compact BLS key owns its one-byte algorithm tag and exact 48-byte key.
    // The ledger has one slot per account backing, key, vector, and record Box.
    let expected = Layout::new::<SccpForgeryRecordV1>().size()
        + Layout::array::<SccpForgeryOffenderV1>(count)
            .unwrap()
            .size()
        + Layout::array::<EvidenceOffender>(count).unwrap().size()
        + Layout::array::<AllocationCharge>(account_allocations + count + 3)
            .unwrap()
            .size()
        + ChargedShared::<SccpRecordBody>::allocation_layout().size()
        + account_bytes
        + count * 49;
    let pool = AllocationBudget::new(expected);
    let occupied = pool.try_reserve_bytes(1).unwrap();
    let error = prepare_claim(&verified, verified.qc().signers, &pool)
        .err()
        .expect("last compact key must refuse with one byte occupied");
    let Preparation::Admission(AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        ..
    }) = error
    else {
        panic!("original exact-pool capacity refusal: {error:?}")
    };
    assert_eq!(requested_bytes, 49);
    assert_eq!(reserved_bytes, expected - 49 + 1);
    assert_eq!(limit_bytes, expected);
    assert_eq!(
        pool.reserved_bytes(),
        1,
        "partial record, accounts and keys refund"
    );
    drop(occupied);
    assert_eq!(pool.reserved_bytes(), 0);
    let prepared = prepare_claim(&verified, verified.qc().signers, &pool).unwrap();
    assert_eq!(pool.reserved_bytes(), expected);
    assert_eq!(prepared.body.allocation_bytes(), Some(expected));
    assert!(prepared.body.belongs_to(&pool));
    assert!(prepared.body.graph_belongs_to(&pool));
    let RecordedEvidenceV1::SccpForgery(material) = &prepared.fields().evidence else {
        panic!("closed SCCP record")
    };
    assert_eq!(material.evidence, evidence);
    assert_eq!(material.offenders.len(), count);
    assert_eq!(material.generation, verified.generation().generation);
    let successor = prepared.body.clone();
    drop(prepared);
    assert_eq!(
        pool.reserved_bytes(),
        expected,
        "shared owner keeps every original charge"
    );
    drop(successor);
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "last owner refunds the complete original graph"
    );
    assert_eq!(scratch.reserved_bytes(), 0);
}
