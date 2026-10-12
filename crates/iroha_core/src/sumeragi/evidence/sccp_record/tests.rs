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
        evidence: RecordedEvidenceV1::SccpForgery(SccpForgeryRecordV1 {
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
        }),
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
