//! Unit tests for the SCCP v1 data events.

use super::*;
use crate::sccp::{
    light_client::{SccpLcEquivocationFreezeV1, SccpLcParliamentFreezeV1},
    test_support::{assert_rejects_unknown_field, roundtrip},
};
use iroha_crypto::{Algorithm, KeyPair};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;

fn account(seed: u8) -> AccountId {
    let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("deterministic Ed25519 seed");
    AccountId::new(key_pair.public_key().clone())
}

fn point() -> SccpLcPointV1 {
    SccpLcPointV1 {
        source_height: 21_000_000,
        block_hash: [0x21; 32],
        source_time_ms: 1_758_000_000_000,
    }
}

/// Codec index of every first-release variant, in declaration order.
const CODEC_INDICES: [u32; 29] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28,
];

/// One event of every variant, in declaration order, with its JSON tag.
#[allow(clippy::too_many_lines)]
fn every_event() -> Vec<(SccpEvent, &'static str)> {
    vec![
        (
            SccpEvent::MessageRecorded(SccpMessageRecordedV1 {
                message_id: [1; 32],
                network: ETH,
                revision: 1,
                nonce: 0,
                height: 10,
                commitment_index: 0,
                deadline_ms: 1_758_604_800_000,
            }),
            "message_recorded",
        ),
        (
            SccpEvent::BlockCommitted(SccpBlockCommittedV1 {
                height: 10,
                root: [2; 32],
                count: 3,
                history_size: 4,
            }),
            "block_committed",
        ),
        (
            SccpEvent::InboundProven(SccpInboundProvenV1 {
                message_id: [8; 32],
                network: TON,
                revision: 1,
                amount: u128::MAX,
                source_locator: SccpSourceLocatorV1 {
                    source_height: 50_000_000,
                    block_hash: [9; 32],
                    index_in_block: 2,
                },
                fee_due: 10_000_000,
            }),
            "inbound_proven",
        ),
        (
            SccpEvent::RecipientRegistered(SccpRecipientRegisteredV1 {
                account: account(3),
                network: TON,
                message_id: Some([8; 32]),
            }),
            "recipient_registered",
        ),
        (
            SccpEvent::InboundReleased(SccpInboundReleasedV1 {
                message_id: [8; 32],
                network: TON,
                revision: 1,
                recipient: account(3),
                amount: 5_000_000_000,
                fee: 10_000_000,
            }),
            "inbound_released",
        ),
        (
            SccpEvent::InboundBounced(SccpInboundBouncedV1 {
                message_id: [10; 32],
                network: ETH,
                revision: 1,
                bounce_message_id: [11; 32],
                bounce_revision: 2,
                amount: 7,
                reason: SccpBounceReasonV1::EscrowRecipient,
            }),
            "inbound_bounced",
        ),
        (
            SccpEvent::InboundLiabilityShortfall(SccpInboundLiabilityShortfallV1 {
                message_id: [12; 32],
                network: ETH,
                revision: 1,
                amount: 9,
                liability: 8,
            }),
            "inbound_liability_shortfall",
        ),
        (
            SccpEvent::OutboundVoided(SccpOutboundVoidedV1 {
                message_id: [13; 32],
                network: ETH,
                revision: 1,
                nonce: 4,
                kind: SccpVoidKindV1::Frozen,
                refund_pending: true,
            }),
            "outbound_voided",
        ),
        (
            SccpEvent::OutboundRefunded(SccpOutboundRefundedV1 {
                message_id: [13; 32],
                network: ETH,
                revision: 1,
                nonce: 4,
                recipient: account(4),
                amount: 1_000_000_000,
            }),
            "outbound_refunded",
        ),
        (
            SccpEvent::OutboundStranded(SccpOutboundStrandedV1 {
                message_id: [14; 32],
                network: ETH,
                revision: 1,
                nonce: 5,
                amount: 1_000_000_000,
            }),
            "outbound_stranded",
        ),
        (
            SccpEvent::StrandedReleased(SccpStrandedReleasedV1 {
                network: ETH,
                recipient: account(6),
                amount: 1_000_000_000,
                memo: "return bounced value".to_owned(),
                proposal_id: [15; 32],
            }),
            "stranded_released",
        ),
        (
            SccpEvent::LightClientAdvanced(SccpLightClientAdvancedV1 {
                network: ETH,
                latest_set_id: 1_400,
                latest_finalized: point(),
                state_hash: [16; 32],
            }),
            "light_client_advanced",
        ),
        (
            SccpEvent::LightClientFrozen(SccpLightClientFrozenV1 {
                network: ETH,
                reason: SccpLcFreezeReasonV1::Equivocation(SccpLcEquivocationFreezeV1 {
                    evidence_hash: [17; 32],
                }),
            }),
            "light_client_frozen",
        ),
        (
            SccpEvent::LightClientInitialized(SccpLightClientInitializedV1 {
                network: ETH,
                latest_set_id: 1_399,
                latest_finalized: point(),
                state_hash: [18; 32],
                proposal_id: [19; 32],
            }),
            "light_client_initialized",
        ),
        (
            SccpEvent::TrustedCheckpointInstalled(SccpTrustedCheckpointInstalledV1 {
                network: ETH,
                source_height: 20_000_000,
                block_hash: [20; 32],
                proposal_id: [21; 32],
            }),
            "trusted_checkpoint_installed",
        ),
        (
            SccpEvent::RevisionActivationChanged(SccpRevisionActivationChangedV1 {
                network: ETH,
                revision: 1,
                from: Some(SccpRouteActivationV1::Staged),
                to: Some(SccpRouteActivationV1::Bidirectional),
            }),
            "revision_activation_changed",
        ),
        (
            SccpEvent::ControlRecorded(SccpControlRecordedV1 {
                network: ETH,
                revision: 1,
                control_nonce: 1,
                track: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0,
                certificate_id: [4; 32],
                height: 30,
                commitment_index: 0,
            }),
            "control_recorded",
        ),
        (
            SccpEvent::GovernanceEnacted(SccpGovernanceEnactedV1 {
                proposal_id: [22; 32],
                subjects: vec![
                    SccpGovernanceSubjectV1::Route(ETH),
                    SccpGovernanceSubjectV1::RouteControl(ETH),
                    SccpGovernanceSubjectV1::Parameters,
                ],
            }),
            "governance_enacted",
        ),
        (
            SccpEvent::CommitteeGenerationCreated(SccpCommitteeGenerationCreatedV1 {
                generation: 1,
                cause: SccpGenerationCauseV1::Genesis,
                committee_root: [23; 32],
                start_height: 1,
                deadline_ms: 1_758_604_800_000,
            }),
            "committee_generation_created",
        ),
        (
            SccpEvent::GenerationMemberUnslashable(SccpGenerationMemberUnslashableV1 {
                generation: 1,
                index: 3,
            }),
            "generation_member_unslashable",
        ),
        (
            SccpEvent::CommitteeResync(SccpCommitteeResyncV1 {
                generation: 2,
                committee_root: [24; 32],
                start_height: 10,
            }),
            "committee_resync",
        ),
        (
            SccpEvent::GenerationDestinationCleared(SccpGenerationDestinationClearedV1 {
                generation: 1,
                lc: 1_759_000_000_000,
            }),
            "generation_destination_cleared",
        ),
        (
            SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
                height: 11,
                reason: SccpFinalityDegradedReasonV1::MissingInputs,
            }),
            "finality_degraded",
        ),
        (
            SccpEvent::FastPauseLapsed(SccpFastPauseLapsedV1 {
                network: ETH,
                certificate_id: [29; 32],
                until_ms: 1_758_604_800_000,
            }),
            "fast_pause_lapsed",
        ),
        (
            SccpEvent::ForgeryEvidenceRecorded(SccpForgeryEvidenceRecordedV1 {
                evidence_id: [8; 32],
                generation: 7,
                height: 123,
                rule: SccpForgeryRuleV1::E4,
                offenders: vec![SccpForgeryOffenderV1 {
                    signer: 2,
                    lane_id: iroha_model_base::topology::LaneId::new(1),
                    validator: account(7),
                    activation_height: 11,
                }],
            }),
            "forgery_evidence_recorded",
        ),
        (
            SccpEvent::ForgeryOffenderUnslashable(SccpForgeryOffenderUnslashableV1 {
                generation: 7,
                signer: 1,
            }),
            "forgery_offender_unslashable",
        ),
        (
            SccpEvent::RevisionForgeryHeld(SccpRevisionForgeryHeldV1 {
                network: ETH,
                revision: 2,
                forgery_floor: 7,
                generation: 8,
            }),
            "revision_forgery_held",
        ),
        (
            SccpEvent::RevisionForgeryReleased(SccpRevisionForgeryReleasedV1 {
                network: ETH,
                revision: 2,
                forgery_floor: 9,
            }),
            "revision_forgery_released",
        ),
        (
            SccpEvent::RevisionQuarantined(SccpRevisionQuarantinedV1 {
                network: TON,
                revision: 3,
                certificate_id: [9; 32],
                since_height: 45,
            }),
            "revision_quarantined",
        ),
    ]
}

#[test]
fn every_event_roundtrips_with_a_snake_case_tag() {
    let events = every_event();
    assert_eq!(
        events.len(),
        CODEC_INDICES.len(),
        "one event of every variant"
    );
    for (event, tag) in &events {
        roundtrip(event);
        let value = norito::json::to_value(event).expect("value");
        assert_eq!(
            value.get("event").and_then(norito::json::Value::as_str),
            Some(*tag)
        );
        assert_rejects_unknown_field(event, &[]);
        assert_rejects_unknown_field(event, &["payload"]);
    }
}

#[test]
fn codec_indices_are_explicit_and_contiguous() {
    let events = every_event();
    assert_eq!(events.len(), CODEC_INDICES.len());
    for ((event, _), index) in events.into_iter().zip(CODEC_INDICES) {
        assert!(event.encode().starts_with(&index.encode()), "{event:?}");
    }
    assert!(CODEC_INDICES.is_sorted());
    assert_eq!(
        CODEC_INDICES,
        core::array::from_fn(|index| u32::try_from(index).expect("event fixture index fits u32"))
    );
}

#[test]
fn sccp_event_rejects_the_retired_attestation_and_roster_tags() {
    use norito::codec::DecodeAll as _;

    // The freed indices and the first index above the last variant decode to nothing, whatever
    // payload follows.
    for index in [29_u32, u32::MAX] {
        for filler in [0, 1, 32, 256] {
            let mut encoded = index.encode();
            encoded.extend_from_slice(&vec![0x11; filler]);
            assert!(
                SccpEvent::decode_all(&mut encoded.as_slice()).is_err(),
                "event index {index} with {filler} payload bytes"
            );
        }
    }
    let (kept, _) = every_event().swap_remove(1);
    let kept_json = norito::json::to_json(&kept).expect("json");
    assert!(
        kept_json.contains(r#""event":"block_committed""#),
        "{kept_json}"
    );
    for tag in [
        "subject_created",
        "attestation_signed",
        "block_attested",
        "roster_generation_created",
        "roster_derivation_failed",
        "handoff_stalled",
        "bridge_key_set",
        "attestation_fault",
    ] {
        let retired = kept_json.replace("block_committed", tag);
        assert!(
            norito::json::from_json::<SccpEvent>(&retired).is_err(),
            "{retired}"
        );
        let empty = format!(r#"{{"event":"{tag}","payload":{{}}}}"#);
        assert!(
            norito::json::from_json::<SccpEvent>(&empty).is_err(),
            "{empty}"
        );
    }
}

#[test]
fn event_set_matches_exactly_its_variant() {
    let events = every_event();
    let all = SccpEventSet::all();
    for (index, (event, _)) in events.iter().enumerate() {
        assert!(all.matches(event));
        assert!(!SccpEventSet::empty().matches(event));
        let matching: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, (candidate, _))| {
                std::mem::discriminant(candidate) == std::mem::discriminant(event)
            })
            .map(|(position, _)| position)
            .collect();
        assert_eq!(matching, vec![index]);
    }
    let set = SccpEventSet::MessageRecorded | SccpEventSet::GovernanceEnacted;
    let matched: Vec<&str> = events
        .iter()
        .filter(|(event, _)| set.matches(event))
        .map(|(_, tag)| *tag)
        .collect();
    assert_eq!(matched, vec!["message_recorded", "governance_enacted"]);
}

#[test]
fn optional_payload_fields_are_explicit_and_cover_none() {
    let removal = SccpEvent::RevisionActivationChanged(SccpRevisionActivationChangedV1 {
        network: TON,
        revision: 3,
        from: Some(SccpRouteActivationV1::Staged),
        to: None,
    });
    roundtrip(&removal);
    let registration = SccpRevisionActivationChangedV1 {
        network: TON,
        revision: 1,
        from: None,
        to: Some(SccpRouteActivationV1::Staged),
    };
    roundtrip(&registration);
    let mut value = norito::json::to_value(&registration).expect("value");
    value.as_object_mut().expect("object").remove("from");
    let json = norito::json::to_json(&value).expect("json");
    assert!(norito::json::from_json::<SccpRevisionActivationChangedV1>(&json).is_err());
    roundtrip(&SccpRecipientRegisteredV1 {
        account: account(1),
        network: ETH,
        message_id: None,
    });
}

#[test]
fn enum_payloads_roundtrip_in_every_variant() {
    for reason in [
        SccpBounceReasonV1::UndecodableRecipient,
        SccpBounceReasonV1::EscrowRecipient,
        SccpBounceReasonV1::InadmissibleController,
        SccpBounceReasonV1::UnregistrableRecipient,
    ] {
        roundtrip(&reason);
    }
    roundtrip(&SccpEvent::LightClientFrozen(SccpLightClientFrozenV1 {
        network: TON,
        reason: SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {
            proposal_id: [1; 32],
        }),
    }));
}

#[test]
fn finality_degraded_reasons_are_closed_and_have_explicit_tags() {
    use norito::codec::DecodeAll as _;

    let reasons = [
        (
            SccpFinalityDegradedReasonV1::MissingInputs,
            "missing_inputs",
        ),
        (
            SccpFinalityDegradedReasonV1::InvalidInputs,
            "invalid_inputs",
        ),
        (
            SccpFinalityDegradedReasonV1::MissingGeneration,
            "missing_generation",
        ),
        (
            SccpFinalityDegradedReasonV1::InvalidGeneration,
            "invalid_generation",
        ),
        (
            SccpFinalityDegradedReasonV1::MissingParent,
            "missing_parent",
        ),
        (
            SccpFinalityDegradedReasonV1::CounterExhausted,
            "counter_exhausted",
        ),
    ];
    for (index, (reason, tag)) in reasons.into_iter().enumerate() {
        roundtrip(&reason);
        assert!(
            reason.encode().starts_with(
                &u32::try_from(index)
                    .expect("closed reason discriminant")
                    .encode()
            )
        );
        let event = SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
            height: u64::MAX,
            reason,
        });
        roundtrip(&event);
        let value = norito::json::to_value(&reason).expect("reason JSON");
        assert_eq!(
            value.get("reason").and_then(norito::json::Value::as_str),
            Some(tag)
        );
        assert_rejects_unknown_field(&reason, &[]);
        assert_rejects_unknown_field(&event, &["payload", "reason"]);
    }
    for index in [6_u32, u32::MAX] {
        assert!(SccpFinalityDegradedReasonV1::decode_all(&mut index.encode().as_slice()).is_err());
    }
    for tag in ["allocation_failed", "storage_unavailable", "unknown"] {
        let json = format!(r#"{{"reason":"{tag}","detail":null}}"#);
        assert!(norito::json::from_json::<SccpFinalityDegradedReasonV1>(&json).is_err());
    }
}

#[test]
fn generation_event_set_selects_each_native_variant() {
    let sets = [
        (SccpEventSet::FinalityDegraded, "finality_degraded"),
        (
            SccpEventSet::CommitteeGenerationCreated,
            "committee_generation_created",
        ),
        (SccpEventSet::CommitteeResync, "committee_resync"),
        (
            SccpEventSet::GenerationMemberUnslashable,
            "generation_member_unslashable",
        ),
        (
            SccpEventSet::GenerationDestinationCleared,
            "generation_destination_cleared",
        ),
    ];
    let events = every_event();
    for (set, tag) in sets {
        let matches: Vec<_> = events
            .iter()
            .filter(|(event, _)| set.matches(event))
            .map(|(_, tag)| *tag)
            .collect();
        assert_eq!(matches, vec![tag]);
    }
}

#[test]
fn native_generation_event_payload_fields_are_required() {
    for (event, tag) in every_event().into_iter().skip(18) {
        let value = norito::json::to_value(&event).expect("event JSON");
        let fields: Vec<_> = value
            .get("payload")
            .and_then(norito::json::Value::as_object)
            .expect("event payload")
            .keys()
            .cloned()
            .collect();
        for field in fields {
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .expect("event")
                .get_mut("payload")
                .and_then(norito::json::Value::as_object_mut)
                .expect("event payload")
                .remove(&field);
            let json = norito::json::to_json(&missing).expect("missing-field JSON");
            assert!(
                norito::json::from_json::<SccpEvent>(&json).is_err(),
                "{tag} accepted missing {field}"
            );
        }
    }
}

#[test]
fn amounts_are_decimal_strings() {
    let (event, _) = every_event()
        .into_iter()
        .find(|(event, _)| matches!(event, SccpEvent::InboundProven(_)))
        .expect("inbound proven sample");
    let json = norito::json::to_json(&event).expect("json");
    assert!(
        json.contains(&format!("\"amount\":\"{}\"", u128::MAX)),
        "{json}"
    );
    assert!(json.contains("\"fee_due\":\"10000000\""), "{json}");
}

#[test]
fn every_native_degradation_reason_is_copyable_closed_and_roundtrips() {
    use norito::codec::DecodeAll as _;
    fn copy_value<T: Copy>(value: T) -> (T, T) {
        (value, value)
    }
    for (index, reason) in [
        SccpFinalityDegradedReasonV1::MissingInputs,
        SccpFinalityDegradedReasonV1::InvalidInputs,
        SccpFinalityDegradedReasonV1::MissingGeneration,
        SccpFinalityDegradedReasonV1::InvalidGeneration,
        SccpFinalityDegradedReasonV1::MissingParent,
        SccpFinalityDegradedReasonV1::CounterExhausted,
    ]
    .into_iter()
    .enumerate()
    {
        let (original, copied) = copy_value(reason);
        assert_eq!(original, copied);
        roundtrip(&reason);
        assert!(
            reason
                .encode()
                .starts_with(&u32::try_from(index).unwrap().encode())
        );
        let event = SccpFinalityDegradedV1 { height: 3, reason };
        roundtrip(&SccpEvent::FinalityDegraded(event));
        assert_eq!(copy_value(event), (event, event));
    }
    assert!(SccpFinalityDegradedReasonV1::decode_all(&mut 6_u32.encode().as_slice()).is_err());
    let retired = r#"{"height":3,"reason":"missing_inputs"}"#;
    assert!(norito::json::from_json::<SccpFinalityDegradedV1>(retired).is_err());
}

#[test]
fn fast_pause_lapsed_payload_keeps_original_identity_in_closed_schema() {
    let event = SccpFastPauseLapsedV1 {
        network: ETH,
        certificate_id: [31; 32],
        until_ms: u64::MAX,
    };
    roundtrip(&event);
    let schema = SccpEvent::schema();
    let Some(iroha_schema::Metadata::Struct(fields)) = schema.get::<SccpFastPauseLapsedV1>() else {
        panic!("the event must include its named lapse payload schema");
    };
    assert_eq!(
        fields
            .declarations
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["network", "certificate_id", "until_ms"]
    );
    for missing in ["network", "certificate_id", "until_ms"] {
        let mut value = norito::json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().remove(missing);
        assert!(
            norito::json::from_json::<SccpFastPauseLapsedV1>(
                &norito::json::to_json(&value).unwrap()
            )
            .is_err()
        );
    }
    assert_rejects_unknown_field(&event, &[]);
}
