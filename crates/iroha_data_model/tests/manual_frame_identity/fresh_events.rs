//! Public event frame capture using complete values and mandatory binary fields.

use crate::frame_identity_test_support::record_checked;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, derive_non_signing_ed25519_public_key};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    events::{
        EventBox, EventFilterBox,
        data::{game::GameSessionEventV1, prelude::*},
        stream::{EventMessage, EventSubscriptionRequest},
        time::{ExecutionTime, TimeEvent, TimeEventFilter, TimeInterval},
    },
    game::{
        GameItemStakeV1, GamePayoutClaimV1, GameResourceReservationRecordV1,
        GameResourceReservationSetV1, GameResourceReturnPolicyV1,
    },
    nft::NftId,
    nft_market::NftCustodyPurposeV1,
    proof::ProofId,
};
use iroha_primitives::numeric::Quantity;
use norito::{
    NoritoDeserialize, NoritoSerialize,
    codec::Encode as _,
    core as ncore,
    json::{JsonDeserialize, JsonSerialize, Value},
};
use std::time::Duration;

fn json_value<T: JsonSerialize>(value: &T) -> Value {
    norito::json::from_json(&norito::json::to_json(value).unwrap()).unwrap()
}

// Stream owners deliberately do not need public Eq: JSON covers every field,
// and the shared binary checker requires exact payload/frame re-encoding.
fn record<T>(rows: &mut Vec<Value>, case: &str, value: &T)
where
    T: norito::NoritoSchema
        + NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + JsonSerialize
        + JsonDeserialize,
{
    let json = norito::json::to_json(value).unwrap();
    record_checked(rows, case, value, |decoded| {
        assert_eq!(
            norito::json::to_json(decoded).unwrap(),
            json,
            "{case}: all JSON fields"
        );
    });
    let decoded: T = norito::json::from_json(&json).unwrap();
    assert_eq!(
        decoded.encode(),
        value.encode(),
        "{case}: exact JSON payload"
    );
    assert_eq!(norito::json::to_json(&decoded).unwrap(), json);
    rows.last_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("json".into(), Value::String(json));
}

fn family<T>(rows: &mut Vec<Value>, name: &str, values: &[T])
where
    T: norito::NoritoSchema
        + Clone
        + NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + JsonSerialize
        + JsonDeserialize,
{
    assert!(!values.is_empty());
    let mut seen = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let semantic = json_value(value);
        assert!(
            !seen.contains(&semantic),
            "distinct complete fixture values"
        );
        seen.push(semantic);
        record(rows, &format!("{name}/root_{index}"), value);
        record(
            rows,
            &format!("{name}/option_{index}"),
            &Some(value.clone()),
        );
    }
    record(rows, &format!("{name}/option_none"), &None::<T>);
    record(rows, &format!("{name}/vec_empty"), &Vec::<T>::new());
    record(rows, &format!("{name}/vec_all"), &values.to_vec());
}

fn bounded_json<T: JsonSerialize>(value: &T) {
    let json = norito::json::to_json(value).unwrap();
    assert_eq!(
        norito::json::to_json_bounded(value, json.len()).unwrap(),
        json
    );
    assert_eq!(
        norito::json::to_json_bounded(value, json.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
}

fn payload<T: ncore::SerializePayload>(value: &T) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut bytes = Vec::new();
    ncore::serialize_to_buffer(value, &mut bytes).unwrap();
    bytes
}

fn fields(parts: &[Vec<u8>]) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
    let mut bytes = Vec::new();
    for part in parts {
        ncore::write_len_header_to_vec(&mut bytes, u64::try_from(part.len()).unwrap());
        bytes.extend_from_slice(part);
    }
    bytes
}

fn reject_payload<T>(bytes: &[u8])
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de>,
{
    let flags = ncore::default_encode_flags();
    let frame = ncore::frame_bare_with_header_flags::<T>(bytes, flags).unwrap();
    let view = ncore::from_bytes_view(&frame).expect("authentic malformed-field metadata");
    assert_eq!(view.as_bytes(), bytes);
    assert!(
        view.decode_exact_with::<T, _, _>(ncore::decode_field_canonical::<T>)
            .is_err()
    );
    assert!(norito::decode_canonical::<T>(&frame).is_err());
    let _flags = ncore::DecodeFlagsGuard::enter(flags);
    let _ctx = ncore::PayloadCtxGuard::enter_with_schema_and_flags(bytes, view.schema(), flags);
    let archived = ncore::from_bytes::<T>(&frame).expect("valid typed archive metadata");
    assert!(<T as ncore::DeserializePayload<'_>>::try_deserialize(archived).is_err());
}

fn reject_stream_payload<T>(bytes: &[u8])
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + for<'de> ncore::DecodeFromSlice<'de>,
{
    reject_payload::<T>(bytes);
    let frame =
        ncore::frame_bare_with_header_flags::<T>(bytes, ncore::default_encode_flags()).unwrap();
    let view = ncore::from_bytes_view(&frame).unwrap();
    assert!(
        view.decode_exact_with::<T, _, _>(<T as ncore::DecodeFromSlice>::decode_from_slice)
            .is_err()
    );
}

fn check_slice<T>(value: &T)
where
    T: NoritoSerialize
        + for<'de> NoritoDeserialize<'de>
        + for<'de> ncore::DecodeFromSlice<'de>
        + JsonSerialize,
{
    let frame = norito::encode_canonical(value).unwrap();
    let view = ncore::from_bytes_view(&frame).unwrap();
    let expected = norito::json::to_json(value).unwrap();
    let decoded = view
        .decode_exact_with::<T, _, _>(|bytes| {
            let (decoded, used) = <T as ncore::DecodeFromSlice>::decode_from_slice(bytes)?;
            assert_eq!(used, bytes.len(), "complete public owner slice consumption");
            Ok((decoded, used))
        })
        .expect("slice decoder reconstructs its own complete owner");
    assert_eq!(norito::json::to_json(&decoded).unwrap(), expected);
    assert_eq!(norito::encode_canonical(&decoded).unwrap(), frame);
}

fn filter_cases() -> Vec<(u32, DataEventFilter)> {
    vec![
        (0, DataEventFilter::Any),
        (1, DataEventFilter::Peer(PeerEventFilter::new())),
        (2, DataEventFilter::Domain(DomainEventFilter::new())),
        (3, DataEventFilter::Account(AccountEventFilter::new())),
        (4, DataEventFilter::Asset(AssetEventFilter::new())),
        (
            5,
            DataEventFilter::AssetDefinition(AssetDefinitionEventFilter::new()),
        ),
        (6, DataEventFilter::Nft(NftEventFilter::new())),
        (7, DataEventFilter::Rwa(RwaEventFilter::new())),
        (8, DataEventFilter::Trigger(TriggerEventFilter::new())),
        (9, DataEventFilter::Role(RoleEventFilter::new())),
        (
            10,
            DataEventFilter::Configuration(ConfigurationEventFilter::new()),
        ),
        (11, DataEventFilter::Executor(ExecutorEventFilter::new())),
        (12, DataEventFilter::Proof(ProofEventFilter::new())),
        (
            13,
            DataEventFilter::VerifyingKey(VerifyingKeyEventFilter::new()),
        ),
        (
            14,
            DataEventFilter::RuntimeUpgrade(RuntimeUpgradeEventFilter::new()),
        ),
        (
            15,
            DataEventFilter::Soradns(SoradnsDirectoryEventFilter::new()),
        ),
        (16, DataEventFilter::Sorafs(SorafsGatewayEventFilter::new())),
        (17, DataEventFilter::Musubi(MusubiEventFilter::new())),
        (
            18,
            DataEventFilter::SpaceDirectory(SpaceDirectoryEventFilter::new()),
        ),
        (19, DataEventFilter::Escrow(EscrowEventFilter::new())),
        (20, DataEventFilter::Oracle(OracleEventFilter::new())),
        (21, DataEventFilter::Social(SocialEventFilter::new())),
        (22, DataEventFilter::Bridge(BridgeEventFilter::new())),
        (24, DataEventFilter::GameSession(None)),
        (
            24,
            DataEventFilter::GameSession(Some(Hash::new(b"fresh-game-session"))),
        ),
        (
            12,
            DataEventFilter::Proof(ProofEventFilter::new().for_proof(ProofId {
                backend: "halo2/ipa".into(),
                proof_hash: [0x31; 32],
            })),
        ),
    ]
}

fn check_filter(tag: u32, value: &DataEventFilter) {
    assert_eq!(&value.encode()[..4], &tag.to_le_bytes());
    bounded_json(value);
    let frame = norito::encode_canonical(value).unwrap();
    let encoded = STANDARD.encode(&frame);
    let json = norito::json::to_json(value).unwrap();
    assert_eq!(
        json,
        norito::json::to_json(&encoded).unwrap(),
        "filter JSON is its canonical typed frame"
    );
    let canonical_flags = ncore::from_bytes_view(&frame).unwrap().flags();
    let flags = canonical_flags ^ ncore::header_flags::COMPACT_LEN;
    let alternate = {
        let _flags = ncore::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            norito::json::to_json(value).unwrap(),
            json,
            "JSON ignores ambient layout"
        );
        assert_eq!(ncore::effective_decode_flags(), Some(flags));
        let mut bare = Vec::new();
        ncore::serialize_to_buffer(value, &mut bare).unwrap();
        // A unit variant has no length field, so ordinary encoding correctly
        // clears the unused flag. Advertise the alternate flag explicitly to
        // create a distinct, authenticated noncanonical negative control.
        ncore::frame_bare_with_header_flags::<DataEventFilter>(&bare, flags).unwrap()
    };
    assert_ne!(
        alternate, frame,
        "negative control differs from the canonical frame"
    );
    let alternate_view = ncore::from_bytes_view(&alternate).unwrap();
    assert_eq!(alternate_view.flags(), flags);
    assert_eq!(
        alternate_view
            .decode_exact_with::<DataEventFilter, _, _>(
                ncore::decode_field_canonical::<DataEventFilter>
            )
            .expect("alternate archive still reconstructs the complete filter"),
        *value
    );
    let alternate_json = norito::json::to_json(&STANDARD.encode(&alternate)).unwrap();
    assert!(norito::json::from_json::<DataEventFilter>(&alternate_json).is_err());
    let mut unknown = value.encode();
    unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    reject_payload::<DataEventFilter>(&unknown);
}

fn fixture_network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"fresh-event-network",
    )))
}

fn custody(session_id: Hash, nft_id: &NftId, purpose: NftCustodyPurposeV1) -> AccountId {
    AccountId::new(derive_non_signing_ed25519_public_key(
        b"iroha:nft:custody:v1",
        &[
            fixture_network().as_bytes(),
            session_id.as_ref(),
            &purpose.encode(),
            &nft_id.encode(),
        ],
    ))
}

fn game(open: bool) -> GameSessionEventV1 {
    let session_id = Hash::new(b"fresh-game-session");
    let key = KeyPair::try_from_seed(vec![0x41; 32], Algorithm::Ed25519).unwrap();
    let owner = AccountId::new(key.public_key().clone());
    let item_id: NftId = "prize$equipment.universal".parse().unwrap();
    let resource_id: NftId = "engine$equipment.universal".parse().unwrap();
    let resources = vec![GameResourceReservationRecordV1 {
        slot: 0,
        nft_id: resource_id.clone(),
        metadata_hash: Hash::new(b"equipment-metadata"),
        role_id: Hash::new(b"engine-role"),
        policy: GameResourceReturnPolicyV1::ReturnToOriginalOwnerAtTerminal,
        original_owner: owner.clone(),
        custody: custody(session_id, &resource_id, NftCustodyPurposeV1::GameResource),
        reserved_at_height: 10,
        released_at_height: if open { None } else { Some(40) },
    }];
    GameResourceReservationSetV1 {
        version: 1,
        network_id: fixture_network(),
        session_id,
        records: resources.clone(),
    }
    .validate_for_owners(std::slice::from_ref(&owner))
    .expect("valid populated resource record geometry");
    GameSessionEventV1 {
        session_id,
        revision: if open { 7 } else { 11 },
        phase: if open { 1 } else { 6 },
        dispute_root: Hash::new(b"fresh-dispute-root"),
        payout_claims: if open {
            Vec::new()
        } else {
            vec![GamePayoutClaimV1 {
                slot: 0,
                amount: Quantity::from(12_u64),
                remaining: Quantity::from(5_u64),
            }]
        },
        item_stakes: vec![GameItemStakeV1 {
            slot: 0,
            nft_id: item_id.clone(),
            custody: custody(session_id, &item_id, NftCustodyPurposeV1::GameWager),
            metadata_hash: Hash::new(b"prize-metadata"),
            recipient: if open { None } else { Some(owner) },
            claimed: !open,
        }],
        resources,
        terminal_at_height: if open { None } else { Some(40) },
    }
}

fn game_fields(value: &GameSessionEventV1) -> Vec<Vec<u8>> {
    vec![
        payload(&value.session_id),
        payload(&value.revision),
        payload(&value.phase),
        payload(&value.dispute_root),
        payload(&value.payout_claims),
        payload(&value.item_stakes),
        payload(&value.resources),
        payload(&value.terminal_at_height),
    ]
}

fn check_game(value: &GameSessionEventV1) {
    bounded_json(value);
    let parts = game_fields(value);
    assert_eq!(
        fields(&parts),
        value.encode(),
        "all game field lengths and payloads match the actual owner"
    );
    for index in 0..parts.len() {
        let mut malformed = parts.clone();
        assert!(malformed[index].pop().is_some());
        reject_payload::<GameSessionEventV1>(&fields(&malformed));
    }
    let mut unknown_policy = json_value(value);
    let resource = unknown_policy
        .as_object_mut()
        .unwrap()
        .get_mut("resources")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .as_object_mut()
        .unwrap();
    resource.insert("policy".into(), norito::json!({"kind":"unsupported"}));
    assert!(
        norito::json::from_json::<GameSessionEventV1>(
            &norito::json::to_json(&unknown_policy).unwrap()
        )
        .is_err()
    );
    let mut invalid_bool = json_value(value);
    invalid_bool
        .as_object_mut()
        .unwrap()
        .get_mut("item_stakes")
        .unwrap()
        .as_array_mut()
        .unwrap()[0]
        .as_object_mut()
        .unwrap()
        .insert("claimed".into(), Value::String("true".into()));
    assert!(
        norito::json::from_json::<GameSessionEventV1>(
            &norito::json::to_json(&invalid_bool).unwrap()
        )
        .is_err()
    );
}

fn subscription_filters() -> Vec<EventFilterBox> {
    vec![
        EventFilterBox::Data(DataEventFilter::Proof(ProofEventFilter::new())),
        EventFilterBox::Data(DataEventFilter::GameSession(Some(Hash::new(
            b"fresh-game-session",
        )))),
        EventFilterBox::Time(TimeEventFilter::new(ExecutionTime::PreCommit)),
    ]
}

fn subscription(mask: u8, empty: bool) -> (EventSubscriptionRequest, Vec<Vec<u8>>) {
    let filters = subscription_filters();
    let backend = (mask & 1 != 0).then(|| {
        if empty {
            Vec::new()
        } else {
            vec!["halo2/ipa".to_owned(), "stark/fri".to_owned()]
        }
    });
    let calls = (mask & 2 != 0).then(|| {
        if empty {
            Vec::<[u8; 32]>::new()
        } else {
            vec![[0x11; 32], [0x22; 32]]
        }
    });
    let envelopes = (mask & 4 != 0).then(|| {
        if empty {
            Vec::<[u8; 32]>::new()
        } else {
            vec![[0x33; 32], [0x44; 32]]
        }
    });
    let call_json = calls.as_ref().map(|values| {
        values
            .iter()
            .map(|bytes| bytes.to_vec())
            .collect::<Vec<_>>()
    });
    let envelope_json = envelopes.as_ref().map(|values| {
        values
            .iter()
            .map(|bytes| bytes.to_vec())
            .collect::<Vec<_>>()
    });
    // The public JSON constructor covers private model fields without adding an API.
    let expected = norito::json!({"filters":(filters.clone()),"proof_backend":(backend.clone()),
        "proof_call_hash":call_json,"proof_envelope_hash":envelope_json});
    let value: EventSubscriptionRequest =
        norito::json::from_json(&norito::json::to_json(&expected).unwrap()).unwrap();
    assert_eq!(
        json_value(&value),
        expected,
        "every public JSON field retained"
    );
    let parts = vec![
        payload(&filters),
        payload(&backend),
        payload(&calls),
        payload(&envelopes),
    ];
    assert_eq!(
        fields(&parts),
        value.encode(),
        "complete four-field subscription composer positive control"
    );
    (value, parts)
}

fn check_subscription(value: &EventSubscriptionRequest, parts: &[Vec<u8>]) {
    bounded_json(value);
    check_slice(value);
    assert_eq!(fields(parts), value.encode());
    // None is a mandatory encoded Option value. JSON defaults do not authorize
    // any old binary record that omits one or more positional proof fields.
    for retained in 1..4 {
        reject_stream_payload::<EventSubscriptionRequest>(&fields(&parts[..retained]));
    }
    for index in 1..4 {
        let mut malformed = parts.to_vec();
        assert!(malformed[index].pop().is_some());
        reject_stream_payload::<EventSubscriptionRequest>(&fields(&malformed));
        let mut bad_option = parts.to_vec();
        assert!(
            bad_option[index][0] <= 1,
            "actual Option tag positive control"
        );
        bad_option[index][0] = 2;
        reject_stream_payload::<EventSubscriptionRequest>(&fields(&bad_option));
    }
    let recovered: EventSubscriptionRequest =
        norito::decode_canonical(&norito::encode_canonical(value).unwrap()).unwrap();
    assert_eq!(
        json_value(&recovered),
        json_value(value),
        "rejected tails do not poison subsequent valid decoding"
    );
}

fn capture_values() -> Vec<Value> {
    let mut rows = Vec::new();
    let cases = filter_cases();
    assert_eq!(cases.len(), 26);
    for (tag, value) in &cases {
        check_filter(*tag, value);
    }
    let filters: Vec<_> = cases.into_iter().map(|(_, value)| value).collect();
    family(&mut rows, "data_filter", &filters);

    {
        let value = DataEventFilter::Governance(GovernanceEventFilter::new());
        check_filter(23, &value);
        family(&mut rows, "data_filter_governance", &[value]);
    }
    let open = game(true);
    let terminal = game(false);
    check_game(&open);
    check_game(&terminal);
    let empty = GameSessionEventV1 {
        session_id: Hash::new(b"fresh-empty-session"),
        revision: 0,
        phase: 0,
        dispute_root: Hash::new(b"fresh-empty-dispute"),
        payout_claims: Vec::new(),
        item_stakes: Vec::new(),
        resources: Vec::new(),
        terminal_at_height: None,
    };
    // This wire record owns a u8 phase and u64 revision, not Core transition policy.
    let maximum = GameSessionEventV1 {
        revision: u64::MAX,
        phase: u8::MAX,
        terminal_at_height: Some(u64::MAX),
        ..empty.clone()
    };
    family(
        &mut rows,
        "game_session_event",
        &[empty, open.clone(), terminal.clone(), maximum],
    );
    let time = EventBox::Time(TimeEvent::new(TimeInterval::new(
        Duration::from_millis(17),
        Duration::from_millis(23),
    )));
    let events = [
        time,
        EventBox::Data(DataEvent::GameSession(open).into()),
        EventBox::Data(DataEvent::GameSession(terminal).into()),
    ];
    let messages: Vec<_> = events.iter().cloned().map(EventMessage::new).collect();
    for (event, message) in events.iter().zip(&messages) {
        assert_eq!(EventBox::from(message.clone()), *event);
        let parts = vec![payload(event)];
        assert_eq!(
            fields(&parts),
            message.encode(),
            "EventMessage owns a framed tuple field"
        );
        assert_ne!(
            message.encode(),
            event.encode(),
            "repr transparent is not wire transparent"
        );
        assert!(
            norito::decode_canonical::<EventMessage>(&norito::encode_canonical(event).unwrap())
                .is_err()
        );
        assert!(
            norito::decode_canonical::<EventBox>(&norito::encode_canonical(message).unwrap())
                .is_err()
        );
        let mut unknown = payload(event);
        unknown[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        reject_stream_payload::<EventMessage>(&fields(&[unknown]));
        check_slice(message);
        bounded_json(message);
    }
    family(&mut rows, "event_message", &messages);
    let mut subscriptions = Vec::new();
    for mask in 0..8 {
        let (value, parts) = subscription(mask, false);
        check_subscription(&value, &parts);
        subscriptions.push(value);
    }
    let (empty_proof, parts) = subscription(7, true);
    check_subscription(&empty_proof, &parts);
    subscriptions.push(empty_proof);
    let no_filters = EventSubscriptionRequest::new(Vec::new());
    let empty_parts = vec![
        payload(&Vec::<EventFilterBox>::new()),
        payload(&None::<Vec<String>>),
        payload(&None::<Vec<[u8; 32]>>),
        payload(&None::<Vec<[u8; 32]>>),
    ];
    check_subscription(&no_filters, &empty_parts);
    subscriptions.push(no_filters);
    let from_constructor = EventSubscriptionRequest::new(subscription_filters());
    assert_eq!(from_constructor.encode(), subscriptions[0].encode());
    let omitted_json = norito::json!({"filters":(subscription_filters())});
    let defaulted: EventSubscriptionRequest =
        norito::json::from_json(&norito::json::to_json(&omitted_json).unwrap()).unwrap();
    assert_eq!(
        defaulted.encode(),
        from_constructor.encode(),
        "public JSON omission writes complete None binary fields"
    );
    for name in ["proof_call_hash", "proof_envelope_hash"] {
        for length in [31, 33] {
            let mut malformed = json_value(&subscriptions[7]);
            malformed
                .as_object_mut()
                .unwrap()
                .insert(name.into(), norito::json!(vec![vec![0x11_u8; length]]));
            assert!(
                norito::json::from_json::<EventSubscriptionRequest>(
                    &norito::json::to_json(&malformed).unwrap()
                )
                .is_err()
            );
        }
    }
    family(&mut rows, "event_subscription", &subscriptions);
    assert_eq!(rows.len(), 103);
    rows
}

fn current_identity_capture() -> Value {
    norito::json!({
        "format_version": 1,
        "purpose": "public event owners before identity declaration",
        "default_encode_flags": (ncore::default_encode_flags()),
        "rows": (capture_values()),
    })
}

#[test]
fn public_fresh_event_frames_match_capture() {
    let evidence = current_identity_capture();
    let captured: Value =
        norito::json::from_json(include_str!("../fixtures/fresh_event_identity_frames.json"))
            .expect("decode immutable actual pre-declaration capture");
    assert_eq!(evidence, captured);
}

#[test]
#[ignore = "explicit first-release event wire fixture capture"]
fn capture_current_fresh_event_identity_frames() {
    eprintln!(
        "FRESH_EVENT_CANONICAL_CAPTURE={}",
        norito::json::to_json(&current_identity_capture()).expect("encode current event capture")
    );
}
