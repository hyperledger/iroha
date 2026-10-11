//! Native evidence framing, canonical pair order and required historical attribution.

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::block::consensus::{
    Evidence, EvidenceAttribution, EvidenceOffender, EvidencePenaltyStatus, EvidenceRecord,
};
use iroha_data_model::consensus::NposConsensusEffects;
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    message::{Evidence as NativeEvidence, MAX_EVIDENCE_FRAME_BYTES, Vote, VoteKind},
    types::{EpochId, Hash32, SIGNATURE_LEN, Signature},
};
use norito::codec::{DecodeAll, Encode};

fn native() -> NativeEvidence {
    let first = Vote {
        kind: VoteKind::Prepare,
        instance: Hash32([1; 32]),
        epoch: EpochId {
            epoch: 7,
            context: Hash32([2; 32]),
        },
        height: 12,
        view: 3,
        block_hash: Hash32([3; 32]),
        result: Hash32([4; 32]),
        signer: 2,
        sig: Signature([5; SIGNATURE_LEN]),
    };
    let mut second = first.clone();
    second.block_hash = Hash32([6; 32]);
    NativeEvidence::VoteEquivocation(first, second)
}
fn record() -> EvidenceRecord {
    let key = KeyPair::try_from_seed(vec![7; 32], Algorithm::Ed25519).expect("fixture key");
    EvidenceRecord {
        evidence: Evidence::from_native(&native()).expect("bounded original frame"),
        attribution: EvidenceAttribution {
            scope: iroha_data_model::block::consensus::EvidenceScope::Root,
            instance: [1; 32],
            height: 12,
            epoch: 7,
            context_id: [2; 32],
            authority_generation: [8; 32],
            offenders: vec![EvidenceOffender {
                lane_stake: None,
                signer: 2,
                peer_id: PeerId::from(key.public_key().clone()),
            }],
            safety_violation: false,
        },
        recorded_at_height: 13,
        recorded_at_view: 1,
        recorded_at_ms: 1234,
        penalty_status: EvidencePenaltyStatus::Pending,
    }
}
#[test]
fn native_pair_constructor_is_order_independent_and_wire_is_strict() {
    let evidence = Evidence::from_native(&native()).unwrap();
    let NativeEvidence::VoteEquivocation(first, second) = evidence.decode_native().unwrap() else {
        panic!("vote pair")
    };
    let reversed = NativeEvidence::VoteEquivocation(second, first);
    assert_eq!(Evidence::from_native(&reversed).unwrap(), evidence);
    let invalid = Evidence {
        native: reversed.encode().unwrap(),
    };
    assert!(invalid.decode_native().is_err());
    assert!(Evidence::decode_all(&mut invalid.encode().as_slice()).is_err());
    assert!(norito::json::from_str::<Evidence>(&norito::json::to_json(&invalid).unwrap()).is_err());
    assert_eq!(evidence.native_frame(), evidence.native.as_slice());
}

#[test]
fn nested_native_evidence_resource_refusal_is_preserved_and_retryable() {
    #[derive(norito::Encode, norito::Decode, norito::derive::JsonDeserialize)]
    struct UncheckedEvidence {
        native: Vec<u8>,
    }
    let evidence = Evidence::from_native(&native()).unwrap();
    let binary = evidence.encode();
    let json = norito::json::to_json(&evidence).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 4);
    norito::with_decode_limits_scope(limits, || {
        let wire = UncheckedEvidence::decode_all(&mut binary.as_slice()).unwrap();
        assert_eq!(wire.native, evidence.native);
    });
    let error =
        norito::with_decode_limits_scope(limits, || Evidence::decode_all(&mut binary.as_slice()))
            .unwrap_err();
    assert!(
        matches!(error, norito::Error::NestingDepthExceeded { limit: 4, .. }),
        "{error:?}"
    );
    // JSON has no outer binary field scope, so the same native depth is one lower.
    let json_limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 3);
    norito::with_decode_limits_scope(json_limits, || {
        let wire: UncheckedEvidence = norito::json::from_str(&json).unwrap();
        assert_eq!(wire.native, evidence.native);
    });
    let error =
        norito::with_decode_limits_scope(json_limits, || norito::json::from_str::<Evidence>(&json))
            .unwrap_err();
    assert!(
        matches!(
            error,
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::NestingDepthExceeded { limit: 3, .. }
            )
        ),
        "{error:?}"
    );
    assert_eq!(
        Evidence::decode_all(&mut binary.as_slice()).unwrap(),
        evidence
    );
    assert_eq!(norito::json::from_str::<Evidence>(&json).unwrap(), evidence);
    assert_eq!(evidence.encode(), binary);
}

#[test]
fn native_evidence_roundtrips_with_exact_attribution() {
    let record = record();
    assert_eq!(
        EvidenceRecord::decode_all(&mut record.encode().as_slice()).unwrap(),
        record
    );
    let json = norito::json::to_value(&record).unwrap();
    assert_eq!(
        norito::json::from_value::<EvidenceRecord>(json.clone()).unwrap(),
        record
    );
    for field in [
        "evidence",
        "attribution",
        "recorded_at_height",
        "recorded_at_view",
        "recorded_at_ms",
        "penalty_status",
    ] {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            norito::json::from_value::<EvidenceRecord>(missing).is_err(),
            "missing {field}"
        );
    }
    for field in [
        "scope",
        "instance",
        "height",
        "epoch",
        "context_id",
        "authority_generation",
        "offenders",
        "safety_violation",
    ] {
        let mut missing = json.clone();
        missing
            .as_object_mut()
            .unwrap()
            .get_mut("attribution")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            norito::json::from_value::<EvidenceRecord>(missing).is_err(),
            "missing attribution {field}"
        );
    }
}
#[test]
fn native_evidence_rejects_removed_authority_wrapper_and_malformed_frames() {
    let evidence = Evidence::from_native(&native()).unwrap();
    for value in [
        norito::json!({}),
        norito::json!({"equivocation": {}}),
        norito::json!({"native": [], "context": {}}),
    ] {
        assert!(norito::json::from_value::<Evidence>(value).is_err());
    }
    let mut suffixed = evidence.native.clone();
    suffixed.push(0);
    for frame in [
        Vec::new(),
        evidence.native[..evidence.native.len() - 1].to_vec(),
        suffixed,
        vec![0; MAX_EVIDENCE_FRAME_BYTES + 1],
    ] {
        let malformed = Evidence { native: frame };
        assert!(malformed.decode_native().is_err());
        assert!(Evidence::decode_all(&mut malformed.encode().as_slice()).is_err());
    }
}
#[test]
fn native_effects_require_parent_service_and_both_vectors_and_reject_retired_slots() {
    let empty = NposConsensusEffects::default();
    assert!(empty.is_empty());
    let effects = NposConsensusEffects {
        parent_service_commit_qc: None,
        evidence_admissions: vec![record().evidence],
        penalty_actions: Vec::new(),
    };
    assert!(!effects.is_empty());
    assert_eq!(
        NposConsensusEffects::decode_all(&mut effects.encode().as_slice()).unwrap(),
        effects
    );
    let json = norito::json::to_value(&effects).unwrap();
    assert_eq!(
        norito::json::from_value::<NposConsensusEffects>(json.clone()).unwrap(),
        effects
    );
    for field in [
        "parent_service_commit_qc",
        "evidence_admissions",
        "penalty_actions",
    ] {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            norito::json::from_value::<NposConsensusEffects>(missing).is_err(),
            "missing {field}"
        );
    }
    for field in ["finalized_global_beacon_pulse", "v2_evidence_admissions"] {
        let mut retired = json.clone();
        retired
            .as_object_mut()
            .unwrap()
            .insert(field.into(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<NposConsensusEffects>(retired).is_err(),
            "retired {field}"
        );
    }
}

#[test]
fn lane_attribution_roundtrip_preserves_native_height_and_original_root_cut() {
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        block::consensus::{EvidenceScope, LaneEvidenceScope},
        sumeragi_lanes::SumeragiLaneStakeBinding,
    };
    use iroha_model_base::topology::LaneId;
    let mut record = record();
    let parent = u64::MAX - 2;
    let scope = LaneEvidenceScope {
        lane: LaneId::new(7),
        incarnation: [0x31; 32],
        created_at: 23,
        admission_parent_height: parent,
        admission_parent_hash: HashOf::from_untyped_unchecked(Hash::new(b"original parent")),
        admission_parent_core_hash: [0x32; 32],
        admission_parent_result: [0x33; 32],
    };
    record.attribution.scope = EvidenceScope::Lane(scope);
    record.attribution.height = 9;
    record.recorded_at_height = parent + 1;
    record.attribution.offenders[0].lane_stake = Some(SumeragiLaneStakeBinding {
        owner_lane: LaneId::new(0),
        validator: Hash::new(b"original account"),
        activation_height: 11,
        tenure: Hash::new(b"original escrow and registration"),
    });
    let wire = record.encode();
    assert_eq!(
        EvidenceRecord::decode_all(&mut wire.as_slice()).unwrap(),
        record
    );
    let json = norito::json::to_value(&record).unwrap();
    assert_eq!(
        norito::json::from_value::<EvidenceRecord>(json).unwrap(),
        record
    );
    assert_eq!(record.attribution.height, 9);
    assert_eq!(record.recorded_at_height, u64::MAX - 1);
    for field in [
        "lane",
        "incarnation",
        "created_at",
        "admission_parent_height",
        "admission_parent_hash",
        "admission_parent_core_hash",
        "admission_parent_result",
    ] {
        let mut missing = norito::json::to_value(&scope).unwrap();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            norito::json::from_value::<LaneEvidenceScope>(missing).is_err(),
            "missing {field}"
        );
    }
    let mut substituted = norito::json::to_value(&scope).unwrap();
    substituted
        .as_object_mut()
        .unwrap()
        .insert("global_offence_height".into(), 9_u64.into());
    assert!(norito::json::from_value::<LaneEvidenceScope>(substituted).is_err());
}

#[test]
fn native_parent_service_original_is_required_nonempty_bundle_input() {
    let effects = NposConsensusEffects {
        parent_service_commit_qc: Some(vec![0x19, 0x2a, 0x3b]),
        ..Default::default()
    };
    assert!(!effects.is_empty());
    assert_eq!(
        NposConsensusEffects::decode_all(&mut effects.encode().as_slice()).unwrap(),
        effects
    );
    let json = norito::json::to_value(&effects).unwrap();
    assert_eq!(
        norito::json::from_value::<NposConsensusEffects>(json).unwrap(),
        effects
    );
    assert_ne!(
        iroha_crypto::HashOf::new(&effects),
        iroha_crypto::HashOf::new(&NposConsensusEffects::default())
    );
}
