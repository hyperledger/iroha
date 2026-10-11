//! Typed Activate instruction parity against the actual Kotlin constructor output.
//!
//! This checks framing, preserved original bytes and registry dispatch only. The shared
//! Activation vector contains a stand-in Bootstrap proof. No execution, activation,
//! signature authority or device qualification is established by these codec checks.

use iroha_data_model::{
    isi::{
        kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
        registry,
    },
    kagemusha::KagemushaWalletActivationV1,
};

#[test]
#[ignore = "requires fresh Kotlin Activate constructor output; codec parity only"]
fn kotlin_activate_frames_match_independent_rust_registry() {
    let path = std::path::PathBuf::from(
        std::env::var_os("KAGEMUSHA_KOTLIN_ACTIVATE_FIXTURE")
            .expect("set the absolute fresh Kotlin parity output path"),
    );
    assert!(path.is_absolute());
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.len() <= 65_536);
    let mut frames = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, bytes) = line.split_once('=').expect("name=hex fixture line");
        assert!(frames.insert(name, hex::decode(bytes).unwrap()).is_none());
    }
    assert_eq!(frames.len(), 3);
    let fixtures: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let row = fixtures["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some("KagemushaWalletActivationV1"))
        .unwrap();
    assert_eq!(row["stand_in_proof"].as_bool(), Some(true));
    let original = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let activation: KagemushaWalletActivationV1 = norito::decode_from_bytes(&original).unwrap();
    let registry = registry::default();
    for (name, scheme, activation_original) in [
        (
            "activation_fixture",
            activation.control.body.scheme_id,
            original,
        ),
        ("minimum_opaque", [1; 32], vec![0x7f]),
        (
            "maximum_opaque",
            [1; 32],
            (0u8..=u8::MAX).cycle().take(16_384).collect(),
        ),
    ] {
        let expected = KagemushaWalletLedgerV1::new(
            scheme,
            KagemushaWalletLedgerActionV1::Activate(activation_original),
        );
        let bytes = frames.remove(name).expect("exact required case");
        assert_eq!(bytes, norito::to_bytes(&expected).unwrap(), "frame: {name}");
        assert_eq!(&bytes[40..48], &[0; 8]);
        let decoded: KagemushaWalletLedgerV1 = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap();
        assert_eq!(decoded, expected, "typed fields: {name}");
        assert_eq!(
            registry
                .decode(KagemushaWalletLedgerV1::WIRE_ID, &bytes)
                .unwrap()
                .unwrap()
                .as_any()
                .downcast_ref::<KagemushaWalletLedgerV1>(),
            Some(&expected),
            "registry: {name}",
        );
    }
    assert!(frames.is_empty());
}
