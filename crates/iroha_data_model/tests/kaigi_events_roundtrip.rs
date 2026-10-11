//! Roundtrip coverage for Kaigi domain event summaries.
use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1;
use iroha_data_model::{
    events::data::prelude::{
        KaigiRelayRegistrationSummary, KaigiRelayUnregistrationSummary, KaigiStatusSummary,
    },
    prelude::{
        AccountId, Decode, DomainEvent, Encode, KaigiId, KaigiParticipantCommitment,
        KaigiPrivacyMode, KaigiRelayHealthStatus, KaigiRelayHealthSummary,
        KaigiRelayManifestSummary, KaigiRosterSummary, KaigiStatus, KaigiUsageSummary,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
fn sample_domain_id() -> DomainId {
    DomainId::try_new("kaigi_domain", "universal").expect("domain id")
}
fn sample_call_id() -> KaigiId {
    KaigiId::new(
        sample_domain_id(),
        "daily-standup".parse::<Name>().expect("call name"),
    )
}
fn checked_random_account_id() -> AccountId {
    AccountId::new(
        KeyPair::try_random()
            .expect("generate checked Kaigi relay account keypair")
            .public_key()
            .clone(),
    )
}
#[test]
fn roster_summary_roundtrips_via_norito() {
    let summary = DomainEvent::KaigiRosterSummary(KaigiRosterSummary::new(
        sample_call_id(),
        KaigiPrivacyMode::ZkRosterV1,
        0,
        3,
        2,
        Some(Hash::prehashed([0x55; 32])),
    ));
    let bytes = summary.encode();
    let decoded = DomainEvent::decode(&mut bytes.as_slice()).expect("decode roster summary");
    assert_eq!(summary, decoded);
}
#[test]
fn relay_manifest_summary_roundtrips_via_norito() {
    let summary = DomainEvent::KaigiRelayManifestUpdated(KaigiRelayManifestSummary::new(
        sample_call_id(),
        5,
        123_456,
    ));
    let bytes = summary.encode();
    let decoded =
        DomainEvent::decode(&mut bytes.as_slice()).expect("decode relay manifest summary");
    assert_eq!(summary, decoded);
}
#[test]
fn usage_summary_roundtrips_via_norito() {
    let summary =
        DomainEvent::KaigiUsageSummary(KaigiUsageSummary::new(sample_call_id(), 42_000, 1234, 7));
    let bytes = summary.encode();
    let decoded = DomainEvent::decode(&mut bytes.as_slice()).expect("decode usage summary");
    assert_eq!(summary, decoded);
}
#[test]
fn participant_commitment_roundtrip_preserves_payload() {
    let commitment = KaigiParticipantCommitment {
        commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x2A; 32]).unwrap(),
    };
    let bytes = commitment.encode();
    let decoded =
        KaigiParticipantCommitment::decode(&mut bytes.as_slice()).expect("decode commitment");
    assert_eq!(commitment, decoded);
}
#[test]
fn relay_registration_summary_roundtrips_via_norito() {
    let domain_id = sample_domain_id();
    let relay_id = checked_random_account_id();
    let summary = DomainEvent::KaigiRelayRegistered(KaigiRelayRegistrationSummary::new(
        domain_id,
        relay_id.clone(),
        9,
        Hash::prehashed([0xAB; 32]),
    ));
    let bytes = summary.encode();
    let decoded =
        DomainEvent::decode(&mut bytes.as_slice()).expect("decode relay registration summary");
    assert_eq!(summary, decoded);
    if let DomainEvent::KaigiRelayRegistered(decoded_summary) = decoded {
        assert_eq!(decoded_summary.relay(), &relay_id);
        assert_eq!(*decoded_summary.bandwidth_class(), 9);
    } else {
        panic!("unexpected domain event variant");
    }
}
#[test]
fn relay_health_summary_roundtrips_via_norito() {
    let call = sample_call_id();
    let relay_domain = DomainId::try_new("relay", "universal").expect("valid relay domain");
    let relay = checked_random_account_id();
    let summary = DomainEvent::KaigiRelayHealthUpdated(KaigiRelayHealthSummary::new(
        relay_domain.clone(),
        call.clone(),
        relay.clone(),
        KaigiRelayHealthStatus::Unavailable,
        123_456,
    ));
    let bytes = summary.encode();
    let decoded = DomainEvent::decode(&mut bytes.as_slice()).expect("decode relay health summary");
    assert_eq!(summary, decoded);
    if let DomainEvent::KaigiRelayHealthUpdated(decoded_summary) = decoded {
        assert_eq!(decoded_summary.domain(), &relay_domain);
        assert_eq!(decoded_summary.call(), &call);
        assert_eq!(decoded_summary.relay(), &relay);
        assert_eq!(
            *decoded_summary.status(),
            KaigiRelayHealthStatus::Unavailable
        );
    } else {
        panic!("unexpected domain event variant");
    }
}
#[test]
fn relay_unregistration_summary_roundtrips_via_norito() {
    let domain = sample_domain_id();
    let relay = checked_random_account_id();
    let summary = DomainEvent::KaigiRelayUnregistered(KaigiRelayUnregistrationSummary::new(
        domain.clone(),
        relay.clone(),
    ));
    let bytes = summary.encode();
    let decoded =
        DomainEvent::decode(&mut bytes.as_slice()).expect("decode relay unregistration summary");
    assert_eq!(summary, decoded);
    if let DomainEvent::KaigiRelayUnregistered(decoded_summary) = decoded {
        assert_eq!(decoded_summary.domain(), &domain);
        assert_eq!(decoded_summary.relay(), &relay);
    } else {
        panic!("unexpected domain event variant");
    }
}
#[test]
fn kaigi_status_summary_roundtrips_via_norito() {
    let call = sample_call_id();
    let summary = DomainEvent::KaigiStatusChanged(KaigiStatusSummary::new(
        call.clone(),
        KaigiStatus::Ended,
        Some(123_456),
    ));
    let bytes = summary.encode();
    let decoded = DomainEvent::decode(&mut bytes.as_slice()).expect("decode Kaigi status summary");
    assert_eq!(summary, decoded);
    if let DomainEvent::KaigiStatusChanged(decoded_summary) = decoded {
        assert_eq!(decoded_summary.call(), &call);
        assert_eq!(*decoded_summary.status(), KaigiStatus::Ended);
        assert_eq!(*decoded_summary.ended_at_ms(), Some(123_456));
    } else {
        panic!("unexpected domain event variant");
    }
}
