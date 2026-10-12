//! Installation intent controls; no credential files or sockets are opened by these tests.
use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::block::BlockHeader;

fn selection() -> MusubiPublicationInstallation {
    let signer = KeyPair::from_seed(vec![0x39; 32], Algorithm::Ed25519);
    MusubiPublicationInstallation {
        network_id: Some(NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new([0x23; 32])),
        )),
        seed_provider_hex: Some("14".repeat(32)),
        ingress_broker: Some(AccountId::new(signer.public_key().clone()).to_string()),
        pin_session_hex: Some("25".repeat(32)),
        broker_key_file: Some(WithOrigin::inline(PathBuf::from("missing-owner.key"))),
        pin_key_file: Some(WithOrigin::inline(PathBuf::from("missing-pin.key"))),
        tls_server_name: Some("original.publication.localhost".into()),
        tls_certificate_file: Some(WithOrigin::inline(PathBuf::from("missing-leaf.der"))),
        tls_private_key_file: Some(WithOrigin::inline(PathBuf::from("missing-leaf.key.der"))),
        tls_root_certificate_file: Some(WithOrigin::inline(PathBuf::from("missing-root.der"))),
        readback_request_timeout_ms: None,
        pin_authorization_window_ms: Some(600_000),
        pin_max_check_rounds: Some(16),
        pin_fee_asset: Some(
            AssetDefinitionId::parse_address_literal("6TEAJqbb8oEPmLncoNiMRbLEK6tw").unwrap(),
        ),
        pin_per_transaction_fee_limit: Some(Quantity::from(1u64)),
        pin_total_fee_limit: Some(Quantity::from(64u64)),
    }
}

fn parse(selected: MusubiPublicationInstallation) -> Option<actual::MusubiPublicationInstallation> {
    let mut emitter = Emitter::new();
    let result = selected.parse(&mut emitter);
    emitter.into_result().unwrap();
    result
}

#[test]
fn absent_installation_remains_inactive_and_complete_intent_requires_no_files() {
    assert!(parse(MusubiPublicationInstallation::default()).is_none());
    let original = selection();
    let actual = parse(original.clone()).unwrap();
    assert_eq!(actual.network_id, original.network_id.unwrap());
    assert_eq!(*actual.seed_provider.as_bytes(), [0x14; 32]);
    assert_eq!(actual.pin_session, [0x25; 32]);
    assert_eq!(actual.broker_key_file, PathBuf::from("missing-owner.key"));
    assert_eq!(actual.pin_key_file, PathBuf::from("missing-pin.key"));
    assert_eq!(actual.tls_server_name, "original.publication.localhost");
    assert_eq!(actual.readback_request_timeout_ms, 30_000);
    assert_eq!(actual.pin_authorization_window_ms, 600_000);
    assert_eq!(actual.pin_max_check_rounds, 16);
    assert_eq!(actual.pin_per_transaction_fee_limit, Quantity::from(1u64));
    assert_eq!(actual.pin_total_fee_limit, Quantity::from(64u64));
}

#[test]
fn every_partial_installation_is_a_closed_parse_error() {
    let remove: [fn(&mut MusubiPublicationInstallation); 15] = [
        |s| s.network_id = None,
        |s| s.seed_provider_hex = None,
        |s| s.ingress_broker = None,
        |s| s.pin_session_hex = None,
        |s| s.broker_key_file = None,
        |s| s.pin_key_file = None,
        |s| s.tls_server_name = None,
        |s| s.tls_certificate_file = None,
        |s| s.tls_private_key_file = None,
        |s| s.tls_root_certificate_file = None,
        |s| s.pin_authorization_window_ms = None,
        |s| s.pin_max_check_rounds = None,
        |s| s.pin_fee_asset = None,
        |s| s.pin_per_transaction_fee_limit = None,
        |s| s.pin_total_fee_limit = None,
    ];
    for remove in remove {
        let mut incomplete = selection();
        remove(&mut incomplete);
        let mut emitter = Emitter::new();
        assert!(incomplete.parse(&mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}

#[test]
fn installation_rejects_unbounded_authorization_and_noncanonical_identity() {
    let mutate: [fn(&mut MusubiPublicationInstallation); 12] = [
        |s| s.pin_authorization_window_ms = Some(0),
        |s| s.pin_authorization_window_ms = Some(3_600_001),
        |s| s.pin_max_check_rounds = Some(0),
        |s| s.pin_max_check_rounds = Some(17),
        |s| s.pin_per_transaction_fee_limit = Some(Quantity::from(0u64)),
        |s| s.pin_total_fee_limit = Some(Quantity::from(0u64)),
        |s| s.seed_provider_hex = Some("00".repeat(32)),
        |s| s.pin_session_hex = Some("AB".repeat(32)),
        |s| s.pin_session_hex = Some("00".repeat(32)),
        |s| s.ingress_broker.as_mut().unwrap().push(' '),
        |s| s.broker_key_file = Some(WithOrigin::inline(PathBuf::new())),
        |s| s.tls_server_name = Some("127.0.0.1".into()),
    ];
    for mutate in mutate {
        let mut invalid = selection();
        mutate(&mut invalid);
        let mut emitter = Emitter::new();
        assert!(invalid.parse(&mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}

#[test]
fn canonical_publication_dns_rejects_urls_wildcards_and_label_overflow() {
    assert!(canonical_dns_name("original.publication.localhost"));
    for bad in [
        "",
        "LOCALHOST",
        "localhost.",
        "https://localhost",
        "host:8443",
        "*.localhost",
        "a..localhost",
        "-bad.localhost",
        "bad-.localhost",
        "127.0.0.1",
        "::1",
    ] {
        assert!(!canonical_dns_name(bad), "{bad}");
    }
    assert!(!canonical_dns_name(&format!(
        "{}.localhost",
        "a".repeat(64)
    )));
}

#[test]
fn readback_timeout_defaults_and_preserves_its_independent_closed_range() {
    use iroha_config_base::{read::ConfigReader, toml::TomlSource};

    let empty = ConfigReader::new()
        .with_toml_source(TomlSource::inline(toml::Table::new()))
        .read_and_complete::<MusubiPublicationInstallation>()
        .unwrap();
    assert!(empty.readback_request_timeout_ms.is_none());
    assert!(parse(empty).is_none());
    assert_eq!(
        parse(selection()).unwrap().readback_request_timeout_ms,
        30_000
    );
    for timeout in [1, 30_000, 120_000] {
        let mut table = toml::Table::new();
        table.insert(
            "readback_request_timeout_ms".into(),
            toml::Value::Integer(timeout),
        );
        let read = ConfigReader::new()
            .with_toml_source(TomlSource::inline(table))
            .read_and_complete::<MusubiPublicationInstallation>()
            .unwrap();
        assert_eq!(
            read.readback_request_timeout_ms,
            Some(u64::try_from(timeout).expect("positive fixture timeout"))
        );
        let mut complete = selection();
        complete.readback_request_timeout_ms = read.readback_request_timeout_ms;
        let actual = parse(complete).unwrap();
        assert_eq!(
            actual.readback_request_timeout_ms,
            u64::try_from(timeout).expect("positive fixture timeout")
        );
        assert_eq!(actual.pin_authorization_window_ms, 600_000);
        assert_eq!(actual.pin_max_check_rounds, 16);
        assert_eq!(actual.pin_per_transaction_fee_limit, Quantity::from(1u64));
        assert_eq!(actual.pin_total_fee_limit, Quantity::from(64u64));
        // A defaultable bound alone cannot install a service or select identity/credentials.
        let mut emitter = Emitter::new();
        assert!(read.parse(&mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
    for timeout in [0, 120_001, u64::MAX] {
        let mut selected = selection();
        selected.readback_request_timeout_ms = Some(timeout);
        let mut emitter = Emitter::new();
        assert!(selected.parse(&mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}
