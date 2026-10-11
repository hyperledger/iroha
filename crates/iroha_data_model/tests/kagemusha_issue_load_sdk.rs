//! Production `IssueLoad` codec and SDK-frame parity through public model/registry APIs.
//!
//! These checks cover canonical framing, typed fields and dispatch only. They do not
//! establish issuer authority, ledger execution/finality, Native wallet readiness or
//! Android device qualification. The ignored parity case requires pinned Kotlin output.

use iroha_data_model::{
    account::AccountId,
    isi::{
        InstructionBox,
        kagemusha_wallet::{
            KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1, KagemushaWalletLoadChargeV1,
        },
        registry,
    },
};

fn sdk_uncharged_issue_load(ordinal: u128, amount: u128) -> KagemushaWalletLedgerV1 {
    KagemushaWalletLedgerV1::new(
        [1; 32],
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: [2; 32],
            asset: [4; 32],
            ordinal,
            request_id: [3; 32],
            amount,
            charge: None,
        },
    )
}

#[test]
fn issue_load_preserves_frozen_complete_frame_and_alignment() {
    assert_eq!(
        norito::core::archived_payload_align::<KagemushaWalletLedgerActionV1>(),
        16
    );
    assert_eq!(
        norito::core::archived_payload_align::<KagemushaWalletLedgerV1>(),
        16
    );
    assert_eq!(norito::core::Header::SIZE, 40);
    let fixtures: norito::json::Value = norito::json::from_str(include_str!(
        "fixtures/instruction_record_generated_identity_frames.json"
    ))
    .unwrap();
    let row = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["nominal"].as_str()
                == Some("iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1")
        })
        .unwrap();
    let expected = hex::decode(row["cases"][0]["frame"].as_str().unwrap()).unwrap();
    let value = sdk_uncharged_issue_load(0, 7);
    let actual = norito::to_bytes(&value).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 222);
    assert_eq!(&actual[40..48], &[0; 8]);
    let decoded: KagemushaWalletLedgerV1 = norito::decode_canonical_with_limits(
        &actual,
        norito::canonical_decode_limits(actual.len()),
    )
    .unwrap();
    assert_eq!(decoded, value);
}

#[test]
#[ignore = "requires fresh core-jvm IssueLoad constructor test output; codec parity only"]
fn kotlin_issue_load_frames_match_independent_rust_registry() {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::kagemusha::KagemushaWalletChargeQuoteV1;

    let path = std::path::PathBuf::from(
        std::env::var_os("KAGEMUSHA_KOTLIN_ISSUE_LOAD_FIXTURE")
            .expect("set the absolute fresh Kotlin parity output path"),
    );
    assert!(path.is_absolute());
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.len() <= 16_384);
    let mut frames = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, bytes) = line.split_once('=').expect("name=hex fixture line");
        assert!(
            frames.insert(name, hex::decode(bytes).unwrap()).is_none(),
            "duplicate case"
        );
    }
    assert_eq!(frames.len(), 3);

    // Same original signed Load quote used by the native finality boundary test.
    // This comparison authenticates no transaction execution or funded ledger state.
    let fixtures: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let row = fixtures["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["type"].as_str() == Some("KagemushaWalletChargeQuoteV1")
                && row["variant"].as_str() == Some("Load")
        })
        .unwrap();
    let quote_bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let quote: KagemushaWalletChargeQuoteV1 = norito::decode_from_bytes(&quote_bytes).unwrap();
    let charged = KagemushaWalletLedgerV1::new(
        quote.body.scheme_id,
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: quote.body.wallet_id,
            asset: quote.body.asset_digest,
            ordinal: quote.body.ordinal,
            request_id: [7; 32],
            amount: quote.body.net_amount,
            charge: Some(KagemushaWalletLoadChargeV1 {
                quote: quote_bytes,
                beneficiary: AccountId::new(
                    KeyPair::from_seed(vec![0x5b; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                ),
            }),
        },
    );
    let registry = registry::default();
    for (name, expected) in [
        ("uncharged", sdk_uncharged_issue_load(0, 7)),
        ("u128_max", sdk_uncharged_issue_load(u128::MAX, u128::MAX)),
        ("charged", charged),
    ] {
        let original = frames.remove(name).expect("required exact case");
        assert_eq!(
            original,
            norito::to_bytes(&expected).unwrap(),
            "full frame: {name}"
        );
        let decoded: KagemushaWalletLedgerV1 = norito::decode_canonical_with_limits(
            &original,
            norito::canonical_decode_limits(original.len()),
        )
        .unwrap();
        assert_eq!(decoded, expected, "typed fields: {name}");
        assert_eq!(
            registry
                .decode(KagemushaWalletLedgerV1::WIRE_ID, &original)
                .unwrap()
                .unwrap()
                .as_any()
                .downcast_ref::<KagemushaWalletLedgerV1>(),
            Some(&expected),
            "registry: {name}"
        );
    }
    assert!(frames.is_empty());
}

#[test]
fn verifier_install_instruction_preserves_pin_asset_and_original_frame() {
    let action = KagemushaWalletLedgerActionV1::InstallVerifierPack {
        asset: [2; 32],
        manifest_digest: [3; 32],
        pack: vec![4, 5, 6, 0, 255],
    };
    let original = KagemushaWalletLedgerV1::new([1; 32], action);
    let bytes = norito::to_bytes(&original).unwrap();
    let recovered: KagemushaWalletLedgerV1 =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    assert_eq!(recovered, original);
    let json = norito::json::to_json(&original).unwrap();
    let from_json: KagemushaWalletLedgerV1 = norito::json::from_str(&json).unwrap();
    assert_eq!(from_json, original);
}

#[test]
fn ledger_instruction_roundtrips_through_canonical_registry_and_json() {
    let value = KagemushaWalletLedgerV1::new(
        [1; 32],
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: [2; 32],
            asset: [4; 32],
            ordinal: 0,
            request_id: [3; 32],
            amount: 7,
            charge: None,
        },
    );
    let bytes = norito::to_bytes(&value).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<KagemushaWalletLedgerV1>(&bytes).unwrap(),
        value
    );
    let json = norito::json::to_json(&value).unwrap();
    assert_eq!(
        norito::json::from_str::<KagemushaWalletLedgerV1>(&json).unwrap(),
        value
    );
    let registry = registry::default();
    let boxed: InstructionBox = value.clone().into();
    assert_eq!(
        boxed.as_any().downcast_ref::<KagemushaWalletLedgerV1>(),
        Some(&value)
    );
    assert_eq!(
        registry.wire_id(core::any::type_name::<KagemushaWalletLedgerV1>()),
        Some(KagemushaWalletLedgerV1::WIRE_ID)
    );
    assert_eq!(
        registry
            .decode(KagemushaWalletLedgerV1::WIRE_ID, &bytes)
            .unwrap()
            .unwrap()
            .as_any()
            .downcast_ref::<KagemushaWalletLedgerV1>(),
        Some(&value)
    );
}

#[test]
fn retired_load_instruction_without_asset_and_ordinal_is_rejected() {
    // Exact retired root frames before and after the verifier-install variant
    // was added. The latter uses the current IssueLoad tag but still lacks the
    // required asset/ordinal fields; neither payload may be decoded.
    for retired in [
        "4e52543000008eef66c2b4be9ed7b2604aec85793350007b000000000000000a09ab00d41fc01a020000000000000000200101010101010101010101010101010101010101010101010101010101010101590400000020020202020202020202020202020202020202020202020202020202020202020220030303030303030303030303030303030303030303030303030303030303030310070000000000000000000000000000000100",
        "4e52543000008eef66c2b4be9ed7b2604aec85793350007b00000000000000d6e8c972dd8bf2a0020000000000000000200101010101010101010101010101010101010101010101010101010101010101590500000020020202020202020202020202020202020202020202020202020202020202020220030303030303030303030303030303030303030303030303030303030303030310070000000000000000000000000000000100",
    ] {
        let retired = hex::decode(retired).unwrap();
        assert!(
            norito::decode_from_bytes::<KagemushaWalletLedgerV1>(&retired).is_err(),
            "retired Load instructions must not decode"
        );
    }
}
