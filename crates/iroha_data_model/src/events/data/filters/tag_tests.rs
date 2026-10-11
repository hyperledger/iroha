//! Data-event filter wire tags remain fixed across optional capability builds.

use super::*;
use norito::{SerializePayload, core as ncore};

fn layouts() -> impl Iterator<Item = u8> {
    (0..=ncore::supported_header_flags())
        .filter(|flags| ncore::validate_header_flags(*flags).is_ok())
}

fn canonical_cases() -> Vec<(&'static str, u32, DataEventFilter)> {
    vec![
        ("Any", 0, DataEventFilter::Any),
        ("Peer", 1, DataEventFilter::Peer(PeerEventFilter::new())),
        (
            "Domain",
            2,
            DataEventFilter::Domain(DomainEventFilter::new()),
        ),
        (
            "Account",
            3,
            DataEventFilter::Account(AccountEventFilter::new()),
        ),
        ("Asset", 4, DataEventFilter::Asset(AssetEventFilter::new())),
        (
            "AssetDefinition",
            5,
            DataEventFilter::AssetDefinition(AssetDefinitionEventFilter::new()),
        ),
        ("Nft", 6, DataEventFilter::Nft(NftEventFilter::new())),
        ("Rwa", 7, DataEventFilter::Rwa(RwaEventFilter::new())),
        (
            "Trigger",
            8,
            DataEventFilter::Trigger(TriggerEventFilter::new()),
        ),
        ("Role", 9, DataEventFilter::Role(RoleEventFilter::new())),
        (
            "Configuration",
            10,
            DataEventFilter::Configuration(ConfigurationEventFilter::new()),
        ),
        (
            "Executor",
            11,
            DataEventFilter::Executor(ExecutorEventFilter::new()),
        ),
        ("Proof", 12, DataEventFilter::Proof(ProofEventFilter::new())),
        (
            "VerifyingKey",
            13,
            DataEventFilter::VerifyingKey(VerifyingKeyEventFilter::new()),
        ),
        (
            "RuntimeUpgrade",
            14,
            DataEventFilter::RuntimeUpgrade(RuntimeUpgradeEventFilter::new()),
        ),
        (
            "Soradns",
            15,
            DataEventFilter::Soradns(SoradnsDirectoryEventFilter::new()),
        ),
        (
            "Sorafs",
            16,
            DataEventFilter::Sorafs(SorafsGatewayEventFilter::new()),
        ),
        (
            "Musubi",
            17,
            DataEventFilter::Musubi(MusubiEventFilter::new()),
        ),
        (
            "SpaceDirectory",
            18,
            DataEventFilter::SpaceDirectory(SpaceDirectoryEventFilter::new()),
        ),
        (
            "Escrow",
            19,
            DataEventFilter::Escrow(EscrowEventFilter::new()),
        ),
        (
            "Oracle",
            20,
            DataEventFilter::Oracle(OracleEventFilter::new()),
        ),
        (
            "Social",
            21,
            DataEventFilter::Social(SocialEventFilter::new()),
        ),
        (
            "Bridge",
            22,
            DataEventFilter::Bridge(BridgeEventFilter::new()),
        ),
        #[cfg(feature = "governance")]
        (
            "Governance",
            23,
            DataEventFilter::Governance(GovernanceEventFilter::new()),
        ),
        ("GameSession", 24, DataEventFilter::GameSession(None)),
        ("Sccp", 25, DataEventFilter::Sccp(SccpEventFilter::new())),
        (
            "KagemushaLoadCommitted",
            26,
            DataEventFilter::KagemushaLoadCommitted(None),
        ),
    ]
}

fn payload(value: &DataEventFilter, flags: u8) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(flags);
    let mut bytes = Vec::new();
    value
        .serialize(&mut ncore::Encoder::for_buffer(&mut bytes))
        .expect("serialize the declared filter layout");
    bytes
}

fn decode(payload: &[u8], flags: u8) -> Result<DataEventFilter, ncore::Error> {
    let frame = ncore::frame_bare_with_header_flags::<DataEventFilter>(payload, flags)
        .expect("frame the advertised filter layout");
    norito::decode_from_bytes::<DataEventFilter>(&frame)
}

#[test]
fn data_event_filter_codec_tags_match_canonical_inventory() {
    for (name, tag, value) in canonical_cases() {
        for flags in layouts() {
            let bytes = payload(&value, flags);
            assert_eq!(&bytes[..4], &tag.to_le_bytes(), "{name}, flags {flags:#x}");
            assert_eq!(
                decode(&bytes, flags).expect("decode canonical filter"),
                value
            );
        }
    }
}

#[test]
fn data_event_filter_schema_tags_match_canonical_inventory() {
    let schema = <DataEventFilter as iroha_schema::IntoSchema>::schema();
    let iroha_schema::Metadata::Enum(metadata) = schema
        .get::<DataEventFilter>()
        .expect("the filter owns an enum schema")
    else {
        panic!("DataEventFilter must describe an enum");
    };
    let expected = canonical_cases()
        .into_iter()
        .map(|(name, tag, _)| (name, tag))
        .collect::<Vec<_>>();
    assert_eq!(
        metadata
            .variants
            .iter()
            .map(|variant| {
                assert_eq!(variant.ty.is_some(), variant.tag != "Any");
                (variant.tag.as_str(), variant.discriminant)
            })
            .collect::<Vec<_>>(),
        expected,
    );
}

#[test]
fn game_session_filter_preserves_tag_and_optional_identity() {
    for game_id in [None, Some(iroha_crypto::Hash::prehashed([0xA7; 32]))] {
        let value = DataEventFilter::GameSession(game_id);
        for flags in layouts() {
            let bytes = payload(&value, flags);
            assert_eq!(&bytes[..4], &24_u32.to_le_bytes());
            let decoded = decode(&bytes, flags).expect("decode game-session filter");
            assert_eq!(decoded, value);
            assert_eq!(payload(&decoded, flags), bytes);
        }
    }
}

#[test]
fn sccp_filter_preserves_tag_network_and_event_set() {
    let values = [
        SccpEventFilter::new(),
        SccpEventFilter::new().for_network(crate::bridge::SccpNetworkV1::TonMainnet),
        SccpEventFilter::new().for_events(
            crate::sccp::events::SccpEventSet::MessageRecorded
                | crate::sccp::events::SccpEventSet::ControlRecorded,
        ),
    ];
    for value in values.map(DataEventFilter::Sccp) {
        for flags in layouts() {
            let bytes = payload(&value, flags);
            assert_eq!(&bytes[..4], &25_u32.to_le_bytes());
            let decoded = decode(&bytes, flags).expect("decode SCCP filter");
            assert_eq!(decoded, value);
            assert_eq!(payload(&decoded, flags), bytes);
        }
    }
}

#[test]
fn data_event_filter_rejects_unassigned_tags() {
    for tag in [27_u32, u32::MAX] {
        for flags in layouts() {
            assert!(matches!(
                decode(&tag.to_le_bytes(), flags),
                Err(ncore::Error::Message(message)) if message == "invalid enum discriminant"
            ));
        }
    }
}

#[cfg(not(feature = "governance"))]
#[test]
fn disabled_governance_tag_is_never_decoded_as_game_session() {
    for game_id in [None, Some(iroha_crypto::Hash::prehashed([0xB9; 32]))] {
        for flags in layouts() {
            let mut bytes = payload(&DataEventFilter::GameSession(game_id), flags);
            assert_eq!(&bytes[..4], &24_u32.to_le_bytes());
            // Reserved Governance tag with an otherwise valid GameSession body:
            // the disabled decoder must reject the tag before interpreting fields.
            bytes[..4].copy_from_slice(&23_u32.to_le_bytes());
            assert!(matches!(
                decode(&bytes, flags),
                Err(ncore::Error::Message(message)) if message == "invalid enum discriminant"
            ));
        }
    }
}

#[cfg(feature = "governance")]
#[test]
fn enabled_governance_filter_retains_tag_and_scope_fields() {
    let value = DataEventFilter::Governance(
        GovernanceEventFilter::new()
            .for_proposal([0xC3; 32])
            .for_referendum(String::from("retained-reference")),
    );
    for flags in layouts() {
        let bytes = payload(&value, flags);
        assert_eq!(&bytes[..4], &23_u32.to_le_bytes());
        assert_eq!(
            decode(&bytes, flags).expect("decode governance filter"),
            value
        );
    }
}

#[cfg(feature = "http")]
#[test]
fn event_subscription_preserves_game_session_filters() {
    use crate::events::{EventFilterBox, stream::EventSubscriptionRequest};

    let filters: Vec<EventFilterBox> = [
        DataEventFilter::Any,
        DataEventFilter::GameSession(Some(iroha_crypto::Hash::prehashed([0xD5; 32]))),
        DataEventFilter::Social(SocialEventFilter::new()),
        DataEventFilter::GameSession(None),
    ]
    .into_iter()
    .map(EventFilterBox::from)
    .collect();
    let request = EventSubscriptionRequest::new(filters.clone());
    let frame = norito::encode_canonical(&request).expect("encode event subscription frame");
    let decoded: EventSubscriptionRequest =
        norito::decode_canonical(&frame).expect("decode event subscription frame");
    assert_eq!(decoded.filters, filters);
    assert!(decoded.proof_backend.is_none());
    assert!(decoded.proof_call_hash.is_none());
    assert!(decoded.proof_envelope_hash.is_none());
    assert_eq!(
        norito::encode_canonical(&decoded).expect("re-encode event subscription frame"),
        frame,
    );
}
