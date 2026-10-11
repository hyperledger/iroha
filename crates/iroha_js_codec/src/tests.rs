//! Account admission, strict instruction contracts and canonical archive regressions.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::{AccountId, NewAccount, address::AccountAddress},
    escrow::EscrowId,
    isi::{
        InstructionBox,
        escrow::CancelAssetLock,
        smart_contract_code::{
            CommitContractDeployment, FinalizeSmartContractCodeUpload, UploadSmartContractCodeChunk,
        },
    },
    smart_contract::{ContractArtifactId, manifest::ContractManifest},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use norito::{
    codec::Encode,
    json::{self, Value},
};

use super::*;

const FIXTURE_NETWORK_PREFIX: u16 = 753;

type Encoder = fn(&str, u16) -> CodecResult<Vec<u8>>;
type Decoder = fn(&[u8], u16) -> CodecResult<String>;

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn account() -> AccountId {
    let key = KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519).expect("fixture key");
    AccountId::new(key.public_key().clone())
}

fn text(value: &Value) -> String {
    json::to_json(value).expect("fixture JSON")
}

fn cancel_payload() -> Value {
    json::to_value(&CancelAssetLock::new(
        EscrowId::new(Hash::new(b"shared-codec-cancel")),
        Quantity::from(15_u32),
    ))
    .expect("cancel fixture")
}

fn assert_strict_rejection(value: &Value) {
    for encode in [encode_instruction_frame, encode_instruction_archive] {
        let error = encode(&text(value), FIXTURE_NETWORK_PREFIX)
            .expect_err("strict admission must reject input");
        assert_eq!(error.kind(), CodecErrorKind::InvalidArgument, "{error}");
    }
}

#[test]
fn account_admission_preserves_discriminants_and_rejects_malformed_controllers() {
    let native = AccountAddress::from_account_id(&account()).expect("native account");
    let canonical = hex::decode(
        native
            .canonical_hex()
            .expect("canonical hex")
            .trim_start_matches("0x"),
    )
    .expect("controller bytes");
    for prefix in [369, 42] {
        let rendered = account_address_render(&canonical, prefix).expect("render account");
        assert_eq!(
            rendered.i105,
            native
                .to_i105_for_discriminant(prefix)
                .expect("native I105")
        );
        assert_eq!(
            rendered.canonical_hex,
            native.canonical_hex().expect("native hex")
        );
        let parsed = account_address_parse_encoded(&rendered.i105, None).expect("infer prefix");
        assert_eq!(parsed.canonical_bytes, canonical);
        assert_eq!(parsed.network_prefix, prefix);
        let error = account_address_parse_encoded(&rendered.i105, Some(prefix + 1)).unwrap_err();
        let native_error =
            AccountAddress::parse_encoded(&rendered.i105, Some(prefix + 1)).unwrap_err();
        assert_eq!(error.kind(), CodecErrorKind::InvalidArgument);
        assert_eq!(
            error.reason(),
            format!("{}: {native_error}", native_error.code_str())
        );
        assert!(account_address_parse_encoded(&format!(" {}", rendered.i105), None).is_err());
    }
    for first_byte in [0, 1] {
        let mut malformed = vec![0x02, 0, 1, 32];
        malformed.resize(36, 0);
        malformed[4] = first_byte;
        assert_eq!(
            account_address_render(&malformed, 369).unwrap_err().kind(),
            CodecErrorKind::InvalidArgument
        );
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert!(account_address_render(&trailing, 369).is_err());
}

#[test]
fn instruction_frames_and_archives_preserve_existing_golden_bytes() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    for source in [
        include_str!("../../../fixtures/norito_instructions/mint_asset_quantity.json"),
        include_str!("../../../fixtures/norito_instructions/burn_asset_fractional.json"),
        include_str!("../../../fixtures/norito_instructions/burn_trigger_repetitions.json"),
    ] {
        let fixture: Value = json::from_json(source).expect("golden fixture");
        let frame = STANDARD
            .decode(
                fixture
                    .get("instruction")
                    .and_then(Value::as_str)
                    .expect("frame base64"),
            )
            .expect("frame bytes");
        let archive = hex::decode(
            fixture
                .get("encoded_hex")
                .and_then(Value::as_str)
                .expect("archive hex"),
        )
        .expect("archive bytes");
        let decoded =
            decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX).expect("decode golden frame");
        assert_eq!(
            encode_instruction_frame(&decoded, FIXTURE_NETWORK_PREFIX).expect("encode frame"),
            frame
        );
        assert_eq!(
            encode_instruction_archive(&decoded, FIXTURE_NETWORK_PREFIX).expect("encode archive"),
            archive
        );
        assert_eq!(
            decode_instruction_archive(&archive, FIXTURE_NETWORK_PREFIX).expect("decode archive"),
            decoded
        );
        let native = instruction_from_json(&decoded).expect("native instruction");
        assert_eq!(archive, native.encode());
        assert_eq!(
            frame,
            norito::encode_canonical(&native).expect("native frame")
        );
    }
}

#[test]
fn canonical_codec_restores_ambient_layout_on_success_and_error() {
    let input = text(&object([("CancelAssetLock", cancel_payload())]));
    let frame = encode_instruction_frame(&input, FIXTURE_NETWORK_PREFIX).expect("canonical frame");
    let archive =
        encode_instruction_archive(&input, FIXTURE_NETWORK_PREFIX).expect("canonical archive");
    let outer = norito::core::DecodeFlagsGuard::enter(0);
    assert_eq!(
        encode_instruction_frame(&input, FIXTURE_NETWORK_PREFIX)
            .expect("frame under ambient flags"),
        frame
    );
    assert_eq!(norito::core::get_decode_flags(), 0);
    assert_eq!(
        encode_instruction_archive(&input, FIXTURE_NETWORK_PREFIX)
            .expect("archive under ambient flags"),
        archive
    );
    assert_eq!(norito::core::get_decode_flags(), 0);
    decode_instruction_archive(&archive, FIXTURE_NETWORK_PREFIX)
        .expect("decode under ambient flags");
    assert_eq!(norito::core::get_decode_flags(), 0);
    decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX)
        .expect("decode frame under ambient flags");
    assert_eq!(norito::core::get_decode_flags(), 0);
    assert!(decode_instruction_frame(&[1], FIXTURE_NETWORK_PREFIX).is_err());
    assert_eq!(norito::core::get_decode_flags(), 0);
    assert!(decode_instruction_archive(&[1], FIXTURE_NETWORK_PREFIX).is_err());
    assert_eq!(norito::core::get_decode_flags(), 0);
    assert!(encode_instruction_frame("{", FIXTURE_NETWORK_PREFIX).is_err());
    assert_eq!(norito::core::get_decode_flags(), 0);
    drop(outer);
}

#[test]
fn archive_admission_rejects_frames_trailing_bytes_and_noncanonical_inner_layout() {
    let input = text(&object([("CancelAssetLock", cancel_payload())]));
    let archive = encode_instruction_archive(&input, FIXTURE_NETWORK_PREFIX).expect("archive");
    assert!(
        decode_instruction_archive(
            &encode_instruction_frame(&input, FIXTURE_NETWORK_PREFIX).expect("frame"),
            FIXTURE_NETWORK_PREFIX
        )
        .is_err()
    );
    assert!(
        decode_instruction_archive(&archive[..archive.len() - 1], FIXTURE_NETWORK_PREFIX).is_err()
    );
    let mut trailing = archive.clone();
    trailing.push(0);
    assert!(decode_instruction_archive(&trailing, FIXTURE_NETWORK_PREFIX).is_err());
    assert!(archive[0] < 0x80, "fixture first length fits one byte");
    let mut overlong_length = vec![archive[0] | 0x80, 0];
    overlong_length.extend_from_slice(&archive[1..]);
    assert!(decode_instruction_archive(&overlong_length, FIXTURE_NETWORK_PREFIX).is_err());
    let mut wrong_schema = archive;
    let frame_offset = wrong_schema
        .windows(4)
        .position(|window| window == b"NRT0")
        .expect("inner frame");
    // Schema identity is in the header, outside the payload CRC. A checksum-only
    // decoder would miss this mutation.
    wrong_schema[frame_offset + 6] ^= 1;
    assert!(decode_instruction_archive(&wrong_schema, FIXTURE_NETWORK_PREFIX).is_err());
}

#[test]
fn cancel_lock_strict_fields_and_quantities_survive_extraction() {
    let canonical = cancel_payload();
    for missing in ["escrow_id", "expected_remaining_amount"] {
        let mut payload = canonical.clone();
        payload.as_object_mut().expect("payload").remove(missing);
        assert_strict_rejection(&object([("CancelAssetLock", payload)]));
    }
    for quantity in [
        Value::String("0".to_owned()),
        Value::String("-1".to_owned()),
        Value::String("01".to_owned()),
        Value::String("1.0".to_owned()),
        Value::from(15_u64),
    ] {
        let mut payload = canonical.clone();
        payload
            .as_object_mut()
            .expect("payload")
            .insert("expected_remaining_amount".to_owned(), quantity);
        assert_strict_rejection(&object([("CancelAssetLock", payload)]));
    }
    let mut unknown = canonical.clone();
    unknown
        .as_object_mut()
        .expect("payload")
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert_strict_rejection(&object([("CancelAssetLock", unknown)]));
    let mut noncanonical_hash = canonical.clone();
    let lowercase_hash = noncanonical_hash
        .get("escrow_id")
        .and_then(Value::as_str)
        .expect("canonical hash")
        .to_ascii_lowercase();
    noncanonical_hash
        .as_object_mut()
        .expect("payload")
        .insert("escrow_id".to_owned(), Value::String(lowercase_hash));
    assert_strict_rejection(&object([("CancelAssetLock", noncanonical_hash)]));
    assert_strict_rejection(&object([
        ("CancelAssetLock", canonical),
        ("unexpected", Value::Null),
    ]));
}

#[test]
fn register_account_requires_canonical_fields_and_rejects_unknown_envelopes() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let account_json = json::to_value(&NewAccount::new(account())).expect("new account JSON");
    let canonical = object([("Register", object([("Account", account_json.clone())]))]);
    encode_instruction_frame(&text(&canonical), FIXTURE_NETWORK_PREFIX)
        .expect("canonical account registration");
    encode_instruction_archive(&text(&canonical), FIXTURE_NETWORK_PREFIX)
        .expect("canonical account registration archive");
    for field in ["id", "metadata", "label", "uaid", "opaque_ids"] {
        let mut incomplete = account_json.clone();
        incomplete
            .as_object_mut()
            .expect("account object")
            .remove(field)
            .expect("required canonical field");
        let payload = text(&object([("Register", object([("Account", incomplete)]))]));
        for encode in [encode_instruction_frame, encode_instruction_archive] {
            let error = encode(&payload, FIXTURE_NETWORK_PREFIX)
                .expect_err("canonical account fields are required");
            assert_eq!(error.kind(), CodecErrorKind::InvalidArgument, "{error}");
            assert!(
                error.reason().contains(&format!("missing field `{field}`")),
                "{error}"
            );
        }
    }
    let mut unknown = account_json.clone();
    unknown
        .as_object_mut()
        .expect("account object")
        .insert("unexpected".to_owned(), Value::Bool(true));
    for encode in [encode_instruction_frame, encode_instruction_archive] {
        let error = encode(
            &text(&object([(
                "Register",
                object([("Account", unknown.clone())]),
            )])),
            FIXTURE_NETWORK_PREFIX,
        )
        .expect_err("native account rejects unknown fields");
        assert_eq!(error.kind(), CodecErrorKind::InvalidArgument);
    }
    assert_strict_rejection(&object([(
        "Register",
        object([("Account", account_json.clone()), ("Domain", Value::Null)]),
    )]));
    assert_strict_rejection(&object([
        ("Register", object([("Account", account_json)])),
        ("SetParameter", Value::Null),
    ]));
    assert_strict_rejection(&object([("Register", Value::Null)]));
}

#[test]
fn nested_custom_multisig_payload_is_preserved_by_both_encodings() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let literal = account().canonical_i105().expect("account I105");
    let payload = object([(
        "Propose",
        object([
            ("account", Value::String(literal)),
            (
                "instructions",
                Value::Array(vec![object([(
                    "Log",
                    Value::String("nested instruction".to_owned()),
                )])]),
            ),
            ("transaction_ttl_ms", Value::from(30_000_u64)),
        ]),
    )]);
    let input = object([("Custom", object([("payload", payload)]))]);
    let source = text(&input);
    for decoded in [
        decode_instruction_frame(
            &encode_instruction_frame(&source, FIXTURE_NETWORK_PREFIX).expect("frame"),
            FIXTURE_NETWORK_PREFIX,
        )
        .expect("frame JSON"),
        decode_instruction_archive(
            &encode_instruction_archive(&source, FIXTURE_NETWORK_PREFIX).expect("archive"),
            FIXTURE_NETWORK_PREFIX,
        )
        .expect("archive JSON"),
    ] {
        assert_eq!(
            json::from_json::<Value>(&decoded).expect("decoded JSON"),
            input
        );
    }
    let native: InstructionBox = instruction_from_json(&source).expect("native custom instruction");
    assert!(
        native
            .as_any()
            .downcast_ref::<iroha_data_model::isi::CustomInstruction>()
            .is_some()
    );
}

fn assert_typed_instruction_roundtrip(instruction: &InstructionBox, value: &Value) {
    let input = text(value);
    let native_frame = norito::encode_canonical(instruction).expect("native instruction frame");
    let native_archive = instruction.encode();
    assert_eq!(
        encode_instruction_frame(&input, FIXTURE_NETWORK_PREFIX).expect("encode typed frame"),
        native_frame
    );
    assert_eq!(
        encode_instruction_archive(&input, FIXTURE_NETWORK_PREFIX).expect("encode typed archive"),
        native_archive
    );
    for decoded in [
        decode_instruction_frame(&native_frame, FIXTURE_NETWORK_PREFIX)
            .expect("decode typed frame"),
        decode_instruction_archive(&native_archive, FIXTURE_NETWORK_PREFIX)
            .expect("decode typed archive"),
    ] {
        assert_eq!(
            json::from_json::<Value>(&decoded).expect("decoded JSON"),
            *value
        );
        assert_eq!(
            encode_instruction_frame(&decoded, FIXTURE_NETWORK_PREFIX)
                .expect("reencode typed frame"),
            native_frame
        );
        assert_eq!(
            encode_instruction_archive(&decoded, FIXTURE_NETWORK_PREFIX)
                .expect("reencode typed archive"),
            native_archive
        );
    }
    let Value::Object(fields) = value else {
        panic!("instruction envelope");
    };
    let mut extra_envelope = fields.clone();
    extra_envelope.insert("unrecognized_instruction".to_owned(), Value::Null);
    assert_strict_rejection(&Value::Object(extra_envelope));
    let (name, payload) = fields.first_key_value().expect("one instruction");
    let mut extra_payload = payload.as_object().expect("instruction payload").clone();
    extra_payload.insert("unrecognized_field".to_owned(), Value::Null);
    assert_strict_rejection(&object([(name.as_str(), Value::Object(extra_payload))]));
}

#[test]
fn all_browser_contract_deployment_instructions_roundtrip_exact_native_bytes() {
    let code_hash = Hash::new(b"browser-deployment-code");
    let address = "irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp"
        .parse()
        .expect("canonical contract address");
    let artifact_id = ContractArtifactId::for_address(&address, code_hash)
        .expect("exact contract artifact dataspace");
    let manifest = ContractManifest {
        seiyaku_name: None,
        code_hash: Some(code_hash),
        abi_hash: Some(Hash::new(b"browser-deployment-abi")),
        compiler_fingerprint: Some("codec-fixture".to_owned()),
        features_bitmap: Some(0),
        access_set_hints: None,
        permissions: Vec::new(),
        events: Vec::new(),
        entrypoints: None,
        states: None,
        kotoba: None,
        error_messages: None,
        error_types: None,
        enum_types: Vec::new(),
        provenance: None,
    };
    let instructions: Vec<InstructionBox> = vec![
        Box::new(UploadSmartContractCodeChunk {
            artifact_id,
            total_size: 4,
            chunk_index: 0,
            chunk_count: 1,
            chunk: vec![1, 2, 3, 4],
        })
        .into_instruction_box(),
        Box::new(FinalizeSmartContractCodeUpload {
            artifact_id,
            total_size: 4,
            chunk_count: 1,
        })
        .into_instruction_box(),
        Box::new(CancelSmartContractCodeUpload { artifact_id }).into_instruction_box(),
        Box::new(RegisterSmartContractCode {
            artifact_id,
            manifest,
        })
        .into_instruction_box(),
        Box::new(CommitContractDeployment {
            expected_deploy_nonce: u64::MAX,
            contract_address: address,
            code_hash,
            contract_alias: "demo::universal".parse().expect("contract alias"),
            lease_expiry_ms: Some(u64::MAX),
            expected_previous_contract_address: None,
        })
        .into_instruction_box(),
    ];
    for instruction in instructions {
        let value = instruction_to_json_value(&instruction).expect("deployment JSON");
        assert_typed_instruction_roundtrip(&instruction, &value);
    }
    let cancel = object([(
        "CancelSmartContractCodeUpload",
        object([(
            "artifact_id",
            lifecycle_instructions::render_artifact_id(&artifact_id).expect("artifact JSON"),
        )]),
    )]);
    let proposed = custom_json_value(object([(
        "Propose",
        object([("instructions", Value::Array(vec![cancel.clone()]))]),
    )]));
    let decoded = decode_instruction_archive(
        &encode_instruction_archive(&text(&proposed), FIXTURE_NETWORK_PREFIX).unwrap(),
        FIXTURE_NETWORK_PREFIX,
    )
    .unwrap();
    assert_eq!(json::from_json::<Value>(&decoded).unwrap(), proposed);
    assert_strict_rejection(&object([("CancelSmartContractCodeUpload", object([]))]));
    assert_strict_rejection(&object([(
        "CancelSmartContractCodeUpload",
        object([(
            "code_hash",
            json::to_value(&code_hash).expect("retired hash field"),
        )]),
    )]));
    assert_strict_rejection(&object([(
        "CancelSmartContractCodeUpload",
        object([(
            "artifact_id",
            object([
                (
                    "dataspace_id",
                    Value::String(artifact_id.dataspace_id.as_u64().to_string()),
                ),
                ("code_hash", Value::String("not-a-hash".to_owned())),
            ]),
        )]),
    )]));
}

fn fixture_value(fixture: &Value, name: &str) -> Value {
    fixture["vectors"]
        .as_array()
        .expect("fixture vectors")
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
        .expect(name)["value"]
        .clone()
}

/// Explicit game catalog payloads assembled from the shared native fixture vectors.
fn game_fixture_payloads() -> [(&'static str, Value); 14] {
    let fixture: Value = json::from_json(include_str!(
        "../../../javascript/iroha_js/test/fixtures/game-v1-codec.json"
    ))
    .expect("native game fixture");
    let checkpoint = fixture_value(&fixture, "SignedGameCheckpointV1");
    let session = checkpoint["checkpoint"]["session_id"].clone();
    let signature = checkpoint["signatures"][0]["signature"].clone();
    let commitment = fixture_value(&fixture, "GameCommitmentSetBodyV1");
    let proof = fixture_value(&fixture, "ExecutionProofEnvelopeV1");
    let mut frontier = commitment.as_object().unwrap().clone();
    frontier.insert("signatures".to_owned(), checkpoint["signatures"].clone());
    [
        (
            "OpenGameSessionV1",
            fixture_value(&fixture, "OpenGameSessionV1"),
        ),
        (
            "JoinGameSessionV1",
            fixture_value(&fixture, "JoinGameSessionV1"),
        ),
        (
            "StartGameSessionV1",
            object([("session_id", session.clone())]),
        ),
        (
            "CommitGameCheckpointV1",
            object([
                ("session_id", session.clone()),
                ("checkpoint", checkpoint),
                ("frontier", Value::Object(frontier)),
            ]),
        ),
        (
            "ChallengeGameSessionV1",
            object([
                ("session_id", session.clone()),
                ("epoch", Value::from(2_u64)),
                ("slot", Value::from(0_u64)),
                ("signature", signature.clone()),
            ]),
        ),
        (
            "CommitGameInputsV1",
            object([(
                "input",
                object([
                    ("session_id", session.clone()),
                    ("epoch", Value::from(2_u64)),
                    ("start_tick", Value::from(0_u64)),
                    ("slot", Value::from(0_u64)),
                    ("commitment", commitment["commitments"][0].clone()),
                    ("signature", signature),
                ]),
            )]),
        ),
        (
            "RevealGameInputsV1",
            object([("reveal", fixture_value(&fixture, "GameInputRevealV1"))]),
        ),
        (
            "AdvanceGameDeadlineV1",
            object([("session_id", session.clone())]),
        ),
        (
            "SettleGameSessionV1",
            object([
                ("session_id", session.clone()),
                ("proof", proof.clone()),
                ("outcome", fixture_value(&fixture, "GameOutcomeV1")),
            ]),
        ),
        ("ExpireGameSessionV1", object([("session_id", session)])),
        (
            "ClaimGamePayoutV1",
            fixture_value(&fixture, "ClaimGamePayoutV1"),
        ),
        (
            "StakeGameItemV1",
            fixture_value(&fixture, "StakeGameItemV1"),
        ),
        (
            "RegisterExecutionProofProfileV1",
            object([("profile_id", proof["profile_id"].clone())]),
        ),
        ("VerifyExecutionProofV1", object([("proof", proof)])),
    ]
}

#[test]
fn all_browser_game_instruction_families_roundtrip_native_json() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    for (name, payload) in game_fixture_payloads() {
        macro_rules! native_from_catalog {
            ($($variant:ident => $ty:ty,)*) => {
                match name {
                    $(stringify!($variant) => {
                        let typed: $ty = json::from_value(payload.clone()).expect(name);
                        Box::new(typed).into_instruction_box()
                    },)*
                    _ => panic!("fixture outside explicit catalog: {name}"),
                }
            };
        }
        let instruction = native_from_catalog! {
            OpenGameSessionV1 => iroha_data_model::isi::game::OpenGameSessionV1,
            JoinGameSessionV1 => iroha_data_model::isi::game::JoinGameSessionV1,
            StartGameSessionV1 => iroha_data_model::isi::game::StartGameSessionV1,
            CommitGameCheckpointV1 => iroha_data_model::isi::game::CommitGameCheckpointV1,
            ChallengeGameSessionV1 => iroha_data_model::isi::game::ChallengeGameSessionV1,
            CommitGameInputsV1 => iroha_data_model::isi::game::CommitGameInputsV1,
            RevealGameInputsV1 => iroha_data_model::isi::game::RevealGameInputsV1,
            AdvanceGameDeadlineV1 => iroha_data_model::isi::game::AdvanceGameDeadlineV1,
            SettleGameSessionV1 => iroha_data_model::isi::game::SettleGameSessionV1,
            ExpireGameSessionV1 => iroha_data_model::isi::game::ExpireGameSessionV1,
            ClaimGamePayoutV1 => iroha_data_model::isi::game::ClaimGamePayoutV1,
            StakeGameItemV1 => iroha_data_model::isi::game::StakeGameItemV1,
            RegisterExecutionProofProfileV1 => iroha_data_model::isi::game::RegisterExecutionProofProfileV1,
            VerifyExecutionProofV1 => iroha_data_model::isi::game::VerifyExecutionProofV1,
        };
        assert_typed_instruction_roundtrip(&instruction, &object([(name, payload)]));
    }
}

#[test]
fn all_browser_nft_market_instruction_families_preserve_native_fixture_frames() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let fixture: Value = json::from_json(include_str!(
        "../../../javascript/iroha_js/test/fixtures/nft-market-v1-codec.json"
    ))
    .expect("native NFT fixture");
    for name in ["OfferNftV1", "BuyNftV1", "CancelNftOfferV1"] {
        let mut payload = fixture_value(&fixture, name);
        let terms = if name == "BuyNftV1" {
            payload.as_object_mut().unwrap().get_mut("offer").unwrap()
        } else {
            &mut payload
        };
        if let Some(expiry) = terms.as_object_mut().unwrap().get_mut("expires_at_height") {
            *expiry = Value::String(expiry.as_u64().unwrap().to_string());
        }
        let row = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"].as_str() == Some(name))
            .unwrap();
        // The NFT catalog stores the compact InstructionBox archive, including
        // its typed frame, in instruction_hex; encoded_hex is the bare payload.
        let archive = hex::decode(
            row["instruction_hex"]
                .as_str()
                .expect("native NFT instruction archive"),
        )
        .expect("native NFT archive hex");
        let instruction: InstructionBox =
            norito::codec::decode_adaptive(&archive).expect("native NFT instruction");
        assert_eq!(instruction.encode(), archive, "{name} native archive");
        assert_typed_instruction_roundtrip(&instruction, &object([(name, payload)]));
    }
}

#[test]
fn set_parameter_explicit_json_roundtrips_through_both_native_encodings() {
    let parameter = CustomParameter::new(
        "codec_fixture".parse().expect("parameter name"),
        Json::new(object([("enabled", Value::Bool(true))])),
    );
    let instruction = InstructionBox::from(SetParameter::new(Parameter::Custom(parameter)));
    let value = instruction_to_json_value(&instruction).expect("parameter JSON");
    let input = text(&value);
    let frame = encode_instruction_frame(&input, FIXTURE_NETWORK_PREFIX).expect("parameter frame");
    let archive =
        encode_instruction_archive(&input, FIXTURE_NETWORK_PREFIX).expect("parameter archive");
    assert_eq!(
        decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX).unwrap(),
        input
    );
    assert_eq!(
        decode_instruction_archive(&archive, FIXTURE_NETWORK_PREFIX).unwrap(),
        input
    );
    assert_eq!(archive, instruction.encode());
}

#[test]
fn validation_fee_policy_requires_the_exact_public_instruction_box_frame() {
    use iroha_data_model::{
        smart_contract::ContractAddress,
        validation_fee::{
            RetailFeeScheduleV1, VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS,
            ValidationFeeChargingMode, ValidationFeeRewardCustodyV1,
        },
    };

    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed([7; 32])),
    );
    let contract_address =
        ContractAddress::derive(&network_id, &account(), 42, DataSpaceId::UNIVERSAL)
            .expect("fixture treasury contract");
    let ds_asset_id: iroha_data_model::asset::AssetDefinitionId =
        "62Fk4FPcMuLvW5QjDGNF2a4jAmjM".parse().unwrap();
    let typed = ProposeValidationFeePolicy {
        policy: ValidationFeePolicyV1 {
            schema_version: 1,
            network_id,
            policy_version: 1,
            previous_policy_hash: None,
            ds_asset_id: ds_asset_id.clone(),
            ds_scale: 2,
            retail_schedule: RetailFeeScheduleV1::default(),
            effective_from_ms: 1_793_451_600_000,
            notice_published_at_ms: 1_790_859_600_000,
            fee: "0.1".parse().unwrap(),
            treasury_account_id: contract_address.subject_id(),
            charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
            exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.to_owned()],
            reward_custody: ValidationFeeRewardCustodyV1 {
                treasury_account_id: contract_address.subject_id(),
                contract_address,
                ds_asset_id,
                xor_asset_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
                reward_pool_account_id: account(),
                validator_lane_id: iroha_model_base::topology::LaneId::SINGLE,
            },
        },
    };
    assert_eq!(typed.policy.policy_invariant_error(), None);
    let boxed = InstructionBox::from(typed.clone());
    let frame = norito::encode_canonical(&boxed).unwrap();
    let json = decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX).unwrap();
    assert_eq!(
        encode_instruction_frame(&json, FIXTURE_NETWORK_PREFIX).unwrap(),
        frame
    );
    let concrete = norito::encode_canonical(&typed).unwrap();
    assert_ne!(concrete, frame);
    assert!(decode_instruction_aligned(&concrete).is_err());
    assert!(decode_instruction_frame(&concrete, FIXTURE_NETWORK_PREFIX).is_err());
    assert!(decode_instruction_archive(&concrete, FIXTURE_NETWORK_PREFIX).is_err());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decode_instruction_aligned(&trailing).is_err());
    assert!(decode_instruction_aligned(&frame[..frame.len() - 1]).is_err());
}

#[test]
fn structured_asset_holding_limit_roundtrips_the_existing_model_json_contract() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let instruction = InstructionBox::from(
        iroha_data_model::isi::asset_transfer_control::SetAssetHoldingLimit::new(
            account(),
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
                .parse()
                .expect("native fixture asset"),
            Some(Quantity::from(5_u32)),
        ),
    );
    let value = instruction_to_json_value(&instruction).expect("holding limit JSON");
    let input = text(&value);
    let archive =
        encode_instruction_archive(&input, FIXTURE_NETWORK_PREFIX).expect("holding limit archive");
    assert_eq!(archive, instruction.encode());
    assert_eq!(
        decode_instruction_archive(&archive, FIXTURE_NETWORK_PREFIX).unwrap(),
        input
    );
    let frame = encode_instruction_frame(&input, FIXTURE_NETWORK_PREFIX).unwrap();
    assert_eq!(
        decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX).unwrap(),
        input
    );
}

#[test]
fn deployment_json_rejects_noncanonical_integer_and_incomplete_payloads() {
    let valid = instruction_to_json_value(
        &Box::new(FinalizeSmartContractCodeUpload {
            artifact_id: ContractArtifactId::new(
                DataSpaceId::new(u64::MAX),
                Hash::new(b"strict-upload"),
            ),
            total_size: 4,
            chunk_count: 1,
        })
        .into_instruction_box(),
    )
    .unwrap();
    for replacement in ["01", "+4", " 4", "18446744073709551616"] {
        let mut payload = valid["FinalizeSmartContractCodeUpload"]
            .as_object()
            .unwrap()
            .clone();
        payload.insert(
            "total_size".to_owned(),
            Value::String(replacement.to_owned()),
        );
        assert_strict_rejection(&object([(
            "FinalizeSmartContractCodeUpload",
            Value::Object(payload),
        )]));
    }
    let payload = valid["FinalizeSmartContractCodeUpload"]
        .as_object()
        .unwrap();
    for key in payload.keys() {
        let mut missing = payload.clone();
        missing.remove(key);
        assert_strict_rejection(&object([(
            "FinalizeSmartContractCodeUpload",
            Value::Object(missing),
        )]));
    }
}

#[test]
fn checked_network_prefix_rejects_numeric_coercion() {
    for prefix in [
        -1.0,
        65536.0,
        0.5,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        assert_eq!(
            checked_network_prefix(prefix).unwrap_err().kind(),
            CodecErrorKind::InvalidArgument
        );
    }
    for prefix in [0_u16, 42, 369, 753, u16::MAX] {
        assert_eq!(checked_network_prefix(f64::from(prefix)).unwrap(), prefix);
    }
}

#[test]
fn instruction_account_helper_requires_exact_literals_in_the_selected_context() {
    let _outer = ChainDiscriminantGuard::enter(1234);
    let account = account();
    for prefix in [0_u16, 42, 369, 753, u16::MAX] {
        {
            let _selected = ChainDiscriminantGuard::enter(prefix);
            let literal = account.to_i105_for_discriminant(prefix).unwrap();
            assert_eq!(parse_account_id(&literal, "operand").unwrap(), account);
            for invalid in [
                account
                    .to_i105_for_discriminant(prefix.wrapping_add(1))
                    .unwrap(),
                format!(" {literal}"),
                format!("{literal}\n"),
                account.to_canonical_hex().unwrap(),
                "account@universal".to_owned(),
            ] {
                let error = parse_account_id(&invalid, "operand").unwrap_err();
                assert_eq!(error.kind(), CodecErrorKind::InvalidArgument);
                assert!(error.reason().starts_with("invalid operand: "));
                assert_eq!(chain_discriminant(), prefix);
            }
        }
        assert_eq!(chain_discriminant(), 1234);
    }
}

#[test]
fn instruction_network_context_is_explicit_and_restored_on_success_and_failure() {
    let _outer = ChainDiscriminantGuard::enter(1234);
    let account = account();
    let mut identity_bytes = None;
    for prefix in [0_u16, 42, 369, 753, u16::MAX] {
        let literal = account.to_i105_for_discriminant(prefix).unwrap();
        let source = text(&object([(
            "Unregister",
            object([("Account", Value::String(literal))]),
        )]));
        let frame = encode_instruction_frame(&source, prefix).unwrap();
        assert_eq!(chain_discriminant(), 1234);
        let archive = encode_instruction_archive(&source, prefix).unwrap();
        assert_eq!(chain_discriminant(), 1234);
        assert_eq!(decode_instruction_frame(&frame, prefix).unwrap(), source);
        assert_eq!(chain_discriminant(), 1234);
        assert_eq!(
            decode_instruction_archive(&archive, prefix).unwrap(),
            source
        );
        assert_eq!(chain_discriminant(), 1234);
        if let Some((expected_frame, expected_archive)) = &identity_bytes {
            assert_eq!(
                &frame, expected_frame,
                "display prefix cannot alter domainless identity bytes"
            );
            assert_eq!(&archive, expected_archive);
        } else {
            identity_bytes = Some((frame.clone(), archive.clone()));
        }
        let other = prefix.wrapping_add(1);
        let other_source = text(&object([(
            "Unregister",
            object([(
                "Account",
                Value::String(account.to_i105_for_discriminant(other).unwrap()),
            )]),
        )]));
        assert_eq!(
            decode_instruction_frame(&frame, other).unwrap(),
            other_source
        );
        assert_eq!(chain_discriminant(), 1234);
        assert_eq!(
            decode_instruction_archive(&archive, other).unwrap(),
            other_source
        );
        assert_eq!(chain_discriminant(), 1234);
        for encode in [encode_instruction_frame, encode_instruction_archive] {
            assert!(
                encode(&source, other).is_err(),
                "foreign network operand must fail"
            );
            assert_eq!(chain_discriminant(), 1234);
            assert!(encode("{", prefix).is_err());
            assert_eq!(chain_discriminant(), 1234);
        }
        for decode in [decode_instruction_frame, decode_instruction_archive] {
            assert!(decode(&[0], prefix).is_err());
            assert_eq!(chain_discriminant(), 1234);
        }
    }
}

#[test]
fn typed_registration_respects_selected_context_and_native_error_categories() {
    let _outer = ChainDiscriminantGuard::enter(42);
    let source = {
        let _selected = ChainDiscriminantGuard::enter(369);
        text(&object([(
            "Register",
            object([(
                "Account",
                json::to_value(&NewAccount::new(account())).unwrap(),
            )]),
        )]))
    };
    let codecs: [(Encoder, Decoder); 2] = [
        (encode_instruction_frame, decode_instruction_frame),
        (encode_instruction_archive, decode_instruction_archive),
    ];
    for (encode, decode) in codecs {
        let bytes = encode(&source, 369).unwrap();
        assert_eq!(chain_discriminant(), 42);
        assert_eq!(decode(&bytes, 369).unwrap(), source);
        assert_eq!(chain_discriminant(), 42);
        assert_eq!(
            encode(&source, 42).unwrap_err().kind(),
            CodecErrorKind::InvalidArgument
        );
        assert_eq!(chain_discriminant(), 42);
    }
}

#[test]
fn instruction_network_context_is_thread_local() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    // Spawn every worker before joining any: each waits on the shared barrier.
    let workers = [369_u16, 42].map(|prefix| {
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            let _outer = ChainDiscriminantGuard::enter(prefix.wrapping_add(10));
            let source = text(&object([(
                "Unregister",
                object([(
                    "Account",
                    Value::String(account().to_i105_for_discriminant(prefix).unwrap()),
                )]),
            )]));
            barrier.wait();
            let bytes = encode_instruction_archive(&source, prefix).unwrap();
            barrier.wait();
            assert_eq!(decode_instruction_archive(&bytes, prefix).unwrap(), source);
            assert_eq!(chain_discriminant(), prefix.wrapping_add(10));
            bytes
        })
    });
    let bytes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(bytes[0], bytes[1]);
}

#[test]
fn network_prefix_admission_accepts_only_exact_u16_integers() {
    for (prefix, expected) in [(0.0, 0_u16), (-0.0, 0), (753.0, 753), (65_535.0, u16::MAX)] {
        assert_eq!(checked_network_prefix(prefix).unwrap(), expected);
    }
    for invalid in [
        -1.0,
        0.5,
        65_535.5,
        65_536.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        assert_eq!(
            checked_network_prefix(invalid).unwrap_err().kind(),
            CodecErrorKind::InvalidArgument,
            "{invalid}"
        );
    }
}

#[test]
fn sole_instruction_payload_requires_a_single_envelope_field() {
    let mut envelope = json::Map::new();
    envelope.insert("Other".to_owned(), Value::Null);
    assert!(sole_instruction_payload(&mut envelope, "Named").is_none());
    assert_eq!(
        envelope.len(),
        1,
        "an absent key leaves the envelope unchanged"
    );

    envelope.insert("Named".to_owned(), Value::Bool(true));
    envelope.insert("Another".to_owned(), Value::Null);
    let error = sole_instruction_payload(&mut envelope, "Named")
        .expect("present key")
        .unwrap_err();
    assert_eq!(error.kind(), CodecErrorKind::InvalidArgument);
    assert_eq!(
        error.reason(),
        "Named instruction envelope contains unexpected field(s): Another, Other"
    );
    assert!(
        !envelope.contains_key("Named"),
        "the probed key is consumed"
    );

    let mut sole = json::Map::new();
    sole.insert("Named".to_owned(), Value::Bool(true));
    assert_eq!(
        sole_instruction_payload(&mut sole, "Named")
            .expect("present key")
            .unwrap(),
        Value::Bool(true)
    );
    assert!(sole.is_empty());
}

fn register_code_payload() -> Value {
    let code_hash = Hash::new(b"precedence-code");
    let manifest = ContractManifest {
        seiyaku_name: None,
        code_hash: Some(code_hash),
        abi_hash: Some(Hash::new(b"precedence-abi")),
        compiler_fingerprint: Some("codec-fixture".to_owned()),
        features_bitmap: Some(0),
        access_set_hints: None,
        permissions: Vec::new(),
        events: Vec::new(),
        entrypoints: None,
        states: None,
        kotoba: None,
        error_messages: None,
        error_types: None,
        enum_types: Vec::new(),
        provenance: None,
    };
    object([
        (
            "artifact_id",
            lifecycle_instructions::render_artifact_id(&ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                manifest.code_hash.expect("fixture code hash"),
            ))
            .expect("artifact JSON"),
        ),
        (
            "manifest",
            json::to_value(&manifest).expect("manifest JSON"),
        ),
    ])
}

#[test]
fn artifact_envelopes_reject_extra_keys_before_any_parser_consumes_them() {
    // An earlier strict key sees every later key as an unexpected envelope field.
    let error = value_to_instruction(object([
        ("CancelAssetLock", cancel_payload()),
        ("Mint", Value::Null),
    ]))
    .unwrap_err();
    assert_eq!(
        error.reason(),
        "CancelAssetLock instruction envelope contains unexpected field(s): Mint"
    );
    // Even a null earlier key must remain visible when admitting an artifact.
    // Previously the Mint parser silently removed it before the strict check.
    for mint in [Value::Null, object([])] {
        let error = value_to_instruction(object([
            ("Mint", mint),
            ("RegisterSmartContractCode", register_code_payload()),
        ]))
        .unwrap_err();
        assert!(error.reason().contains("unexpected [Mint]"), "{error}");
    }
    // A later key that was never probed remains visible to the strict check.
    let error = value_to_instruction(object([
        ("RegisterSmartContractCode", register_code_payload()),
        ("Zk", Value::Null),
    ]))
    .unwrap_err();
    assert!(error.reason().contains("unexpected [Zk]"), "{error}");
}

#[test]
fn grant_rendering_covers_only_account_permission_grants() {
    let _network = ChainDiscriminantGuard::enter(FIXTURE_NETWORK_PREFIX);
    let permission: Permission = json::from_value(object([
        ("name", Value::String("CanUnregisterDomain".to_owned())),
        (
            "payload",
            object([("domain", Value::String("wonderland".to_owned()))]),
        ),
    ]))
    .expect("permission");
    let granted = InstructionBox::from(GrantBox::Permission(Grant::account_permission(
        permission,
        account(),
    )));
    let value = instruction_to_json_value(&granted).expect("permission grant JSON");
    assert!(value["Grant"]["Permission"].is_object(), "{value:?}");
    let restored = value_to_instruction(value.clone()).expect("permission grant");
    assert_eq!(
        norito::encode_canonical(&restored).unwrap(),
        norito::encode_canonical(&granted).unwrap()
    );
    let role: RoleId = json::from_value(Value::String("auditor".to_owned())).expect("role id");
    let role_grant = InstructionBox::from(GrantBox::Role(Grant::account_role(role, account())));
    let error = instruction_to_json_value(&role_grant).unwrap_err();
    assert_eq!(error.kind(), CodecErrorKind::Failure);
    assert_eq!(
        error.reason(),
        "unsupported instruction variant; JSON conversion is not yet implemented for this instruction"
    );
}

/// Render, re-admit and re-render a native instruction through its strict JSON contract.
fn assert_native_json_roundtrip(instruction: &InstructionBox) -> Value {
    let value = instruction_to_json_value(instruction).expect("strict JSON rendering");
    let restored = value_to_instruction(value.clone()).expect("strict JSON admission");
    assert_eq!(
        norito::encode_canonical(&restored).expect("restored frame"),
        norito::encode_canonical(instruction).expect("native frame"),
        "{value:?}"
    );
    assert_eq!(
        instruction_to_json_value(&restored).expect("re-rendered JSON"),
        value
    );
    value
}

#[test]
fn rwa_lot_instructions_roundtrip_through_boxed_and_concrete_renderers() {
    let rwa = RwaId::new(
        DomainId::try_new("commodities", "sora").expect("domain"),
        Hash::new(b"codec-rwa"),
    );
    let lot = Value::String(rwa.to_string());
    let quantity = Quantity::from(3_u32);
    let cases: Vec<(RwaInstructionBox, InstructionBox, Value)> = vec![
        (
            FreezeRwa { rwa: rwa.clone() }.into(),
            Box::new(FreezeRwa { rwa: rwa.clone() }).into_instruction_box(),
            object([("FreezeRwa", object([("rwa", lot.clone())]))]),
        ),
        (
            UnfreezeRwa { rwa: rwa.clone() }.into(),
            Box::new(UnfreezeRwa { rwa: rwa.clone() }).into_instruction_box(),
            object([("UnfreezeRwa", object([("rwa", lot.clone())]))]),
        ),
        (
            RedeemRwa {
                rwa: rwa.clone(),
                quantity: quantity.clone(),
            }
            .into(),
            Box::new(RedeemRwa {
                rwa: rwa.clone(),
                quantity: quantity.clone(),
            })
            .into_instruction_box(),
            object([(
                "RedeemRwa",
                object([
                    ("rwa", lot.clone()),
                    ("quantity", json::to_value(&quantity).unwrap()),
                ]),
            )]),
        ),
        (
            HoldRwa {
                rwa: rwa.clone(),
                quantity: quantity.clone(),
            }
            .into(),
            Box::new(HoldRwa {
                rwa: rwa.clone(),
                quantity: quantity.clone(),
            })
            .into_instruction_box(),
            object([(
                "HoldRwa",
                object([
                    ("rwa", lot.clone()),
                    ("quantity", json::to_value(&quantity).unwrap()),
                ]),
            )]),
        ),
        (
            ReleaseRwa {
                rwa: rwa.clone(),
                quantity: quantity.clone(),
            }
            .into(),
            Box::new(ReleaseRwa {
                rwa: rwa.clone(),
                quantity: quantity.clone(),
            })
            .into_instruction_box(),
            object([(
                "ReleaseRwa",
                object([
                    ("rwa", lot.clone()),
                    ("quantity", json::to_value(&quantity).unwrap()),
                ]),
            )]),
        ),
    ];
    for (boxed, concrete, expected) in cases {
        let boxed = InstructionBox::from(boxed);
        assert_eq!(assert_native_json_roundtrip(&boxed), expected);
        assert_eq!(instruction_to_json_value(&concrete).unwrap(), expected);
    }
    let merge = MergeRwas {
        parents: vec![RwaParentRef::new(rwa.clone(), Quantity::from(1_u32))],
        primary_reference: "blend-cert-007".to_owned(),
        status: Some("blended".parse().expect("status")),
        metadata: Metadata::default(),
    };
    let boxed = InstructionBox::from(RwaInstructionBox::from(merge.clone()));
    let value = assert_native_json_roundtrip(&boxed);
    assert_eq!(
        value["MergeRwas"]["parents"][0]["rwa"],
        Value::String(rwa.to_string())
    );
    assert_eq!(
        instruction_to_json_value(&Box::new(merge).into_instruction_box()).unwrap(),
        value
    );
}

#[test]
fn alias_and_zk_ballot_instructions_roundtrip_through_infallible_renderers() {
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("staking", "universal").expect("domain"),
        "coin".parse().expect("asset name"),
    );
    let alias: AssetDefinitionAlias = "usd#issuer.main".parse().expect("alias");
    for instruction in [
        SetAssetDefinitionAlias::bind(definition.clone(), alias, Some(u64::MAX)),
        SetAssetDefinitionAlias::clear(definition),
    ] {
        let value = assert_native_json_roundtrip(&InstructionBox::from(instruction));
        assert!(value["SetAssetDefinitionAlias"].is_object(), "{value:?}");
    }
    let ballot = Box::new(CastZkBallot {
        election_id: "election-1".to_owned(),
        proof_b64: "AAAA".to_owned(),
        public_inputs_json: "{}".to_owned(),
    })
    .into_instruction_box();
    let value = assert_native_json_roundtrip(&ballot);
    assert_eq!(
        value,
        object([(
            "CastZkBallot",
            object([
                ("election_id", Value::String("election-1".to_owned())),
                ("proof_b64", Value::String("AAAA".to_owned())),
                ("public_inputs_json", Value::String("{}".to_owned())),
            ]),
        )])
    );
}

fn direct_dataspace_registration_fixture(
    dataspace_id: u64,
    balance_policy: iroha_data_model::asset::AssetBalancePolicy,
) -> RegisterDataspaceAssetDefinition {
    let id = AssetDefinitionId::from_uuid_bytes([
        0x91, 0x21, 0x63, 0x05, 0x0a, 0xb8, 0x46, 0x22, 0xab, 0x0d, 0x09, 0x0c, 0x31, 0x41, 0x51,
        0x61,
    ])
    .expect("public synthetic UUIDv4");
    RegisterDataspaceAssetDefinition::new(
        DataSpaceId::new(dataspace_id),
        AssetDefinition::numeric(id, "Native unit", balance_policy, None),
    )
    .expect("explicit direct-dataspace registration")
}

#[test]
fn direct_dataspace_registration_codec_preserves_native_u64_and_definition_bytes() {
    use iroha_data_model::asset::AssetBalancePolicy;
    for dataspace in [(1_u64 << 53) + 1, u64::MAX] {
        for policy in [
            AssetBalancePolicy::Global,
            AssetBalancePolicy::DataspaceRestricted,
        ] {
            let registration = direct_dataspace_registration_fixture(dataspace, policy);
            let original_definition = registration.object.encode();
            let instruction = InstructionBox::from(registration);
            let value = assert_native_json_roundtrip(&instruction);
            assert_eq!(
                value["RegisterDataspaceAssetDefinition"]["dataspace_id"].as_u64(),
                Some(dataspace)
            );
            let decoded = value_to_instruction(value).expect("strict direct envelope");
            let typed = decoded
                .as_any()
                .downcast_ref::<RegisterDataspaceAssetDefinition>()
                .expect("standalone instruction type");
            assert_eq!(typed.dataspace_id.as_u64(), dataspace);
            assert_eq!(typed.object.balance_scope_policy, policy);
            assert_eq!(typed.object.encode(), original_definition);
            assert_eq!(typed.object.owning_domain, None);
        }
    }
}

#[test]
fn direct_dataspace_registration_codec_rejects_conflicting_or_ambiguous_inputs() {
    let registration = direct_dataspace_registration_fixture(
        42,
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
    );
    let payload = json::to_value(&registration).expect("native typed fields");
    for invalid_dataspace in [
        Value::from(0_u64),
        Value::String("42".to_owned()),
        Value::from(-1_i64),
        Value::Null,
    ] {
        let mut invalid = payload.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert("dataspace_id".to_owned(), invalid_dataspace);
        assert_strict_rejection(&instruction_envelope(
            "RegisterDataspaceAssetDefinition",
            invalid,
        ));
    }
    for missing in ["dataspace_id", "object"] {
        let mut invalid = payload.clone();
        invalid.as_object_mut().unwrap().remove(missing);
        assert_strict_rejection(&instruction_envelope(
            "RegisterDataspaceAssetDefinition",
            invalid,
        ));
    }
    let mut conflicting = registration.clone();
    conflicting.object.owning_domain = Some(DomainId::try_new("issuer", "public").expect("domain"));
    assert_strict_rejection(&instruction_envelope(
        "RegisterDataspaceAssetDefinition",
        json::to_value(&conflicting).expect("conflicting fields"),
    ));
    assert!(instruction_to_json_value(&InstructionBox::from(conflicting)).is_err());

    let mut unexpected = payload.clone();
    unexpected
        .as_object_mut()
        .unwrap()
        .insert("owning_dataspace".to_owned(), Value::from(43_u64));
    assert_strict_rejection(&instruction_envelope(
        "RegisterDataspaceAssetDefinition",
        unexpected,
    ));
    for direct in [payload.clone(), Value::Null] {
        assert_strict_rejection(&object([
            ("RegisterDataspaceAssetDefinition", direct),
            ("Mint", object([])),
        ]));
    }
    assert_strict_rejection(&instruction_envelope(
        "registerdataspaceassetdefinition",
        payload,
    ));
    let boxed = InstructionBox::from(registration);
    let base64_envelope = json::to_value(&boxed).expect("native base64 instruction form");
    assert_strict_rejection(&base64_envelope);
}

#[test]
fn direct_dataspace_registration_codec_rejects_u64_overflow_before_native_construction() {
    let registration = direct_dataspace_registration_fixture(
        u64::MAX,
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
    );
    let canonical =
        text(&instruction_to_json_value(&registration.into()).expect("canonical envelope"));
    let overflow = canonical.replace("18446744073709551615", "18446744073709551616");
    assert_ne!(overflow, canonical);
    for encode in [encode_instruction_frame, encode_instruction_archive] {
        assert!(encode(&overflow, FIXTURE_NETWORK_PREFIX).is_err());
    }
}

#[test]
fn artifact_instruction_codecs_preserve_exact_dataspace_and_reject_alternate_envelopes() {
    let code_hash = Hash::new(b"dataspace-scoped-codec-artifact");
    let mut frames_by_variant = std::collections::BTreeMap::<String, Vec<Vec<u8>>>::new();
    for dataspace in [0, (1_u64 << 53) + 1, u64::MAX] {
        let artifact_id = ContractArtifactId::new(DataSpaceId::new(dataspace), code_hash);
        let manifest = ContractManifest {
            seiyaku_name: None,
            code_hash: Some(code_hash),
            abi_hash: Some(Hash::new(b"dataspace-scoped-codec-abi")),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            permissions: Vec::new(),
            events: Vec::new(),
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            enum_types: Vec::new(),
            provenance: None,
        };
        let instructions: [InstructionBox; 6] = [
            RegisterSmartContractCode {
                artifact_id,
                manifest,
            }
            .into(),
            RegisterSmartContractBytes {
                artifact_id,
                code: vec![1, 2, 3, 4],
            }
            .into(),
            UploadSmartContractCodeChunk {
                artifact_id,
                total_size: 4,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![1, 2, 3, 4],
            }
            .into(),
            FinalizeSmartContractCodeUpload {
                artifact_id,
                total_size: 4,
                chunk_count: 1,
            }
            .into(),
            CancelSmartContractCodeUpload { artifact_id }.into(),
            RemoveSmartContractBytes {
                artifact_id,
                reason: None,
            }
            .into(),
        ];
        for instruction in instructions {
            let value = instruction_to_json_value(&instruction).expect("scoped artifact JSON");
            let (variant, payload) = value.as_object().unwrap().first_key_value().unwrap();
            assert_eq!(
                payload["artifact_id"]["dataspace_id"],
                Value::String(dataspace.to_string())
            );
            assert_eq!(
                payload["artifact_id"]["code_hash"],
                json::to_value(&code_hash).unwrap()
            );
            assert_typed_instruction_roundtrip(&instruction, &value);
            for extra in ["Mint", "Zk", "UploadSmartContractCodeChunk"] {
                if extra != variant {
                    let mut malformed = value.clone();
                    malformed
                        .as_object_mut()
                        .unwrap()
                        .insert(extra.into(), Value::Null);
                    assert_strict_rejection(&malformed);
                }
            }
            let frame = norito::encode_canonical(&instruction).unwrap();
            let previous = frames_by_variant.entry(variant.clone()).or_default();
            assert!(
                !previous.contains(&frame),
                "different dataspaces must have different signed bytes"
            );
            assert_strict_rejection(&Value::String(STANDARD.encode(&frame)));
            assert_strict_rejection(&json::to_value(&instruction).unwrap());
            previous.push(frame);

            // Removing scope must never recover the retired code-hash-only grammar.
            let mut retired = payload.as_object().unwrap().clone();
            retired.remove("artifact_id");
            retired.insert("code_hash".into(), json::to_value(&code_hash).unwrap());
            assert_strict_rejection(&object([(variant.as_str(), Value::Object(retired))]));
            for invalid_scope in [
                Value::Null,
                Value::from(dataspace),
                Value::String("01".into()),
                Value::String("18446744073709551616".into()),
            ] {
                let mut malformed = value.clone();
                malformed
                    .as_object_mut()
                    .unwrap()
                    .get_mut(variant)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("artifact_id")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("dataspace_id".into(), invalid_scope);
                assert_strict_rejection(&malformed);
            }
            for missing in ["dataspace_id", "code_hash"] {
                let mut malformed = value.clone();
                malformed
                    .as_object_mut()
                    .unwrap()
                    .get_mut(variant)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("artifact_id")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(missing);
                assert_strict_rejection(&malformed);
            }
            let mut extra = value.clone();
            extra
                .as_object_mut()
                .unwrap()
                .get_mut(variant)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .get_mut("artifact_id")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), Value::Null);
            assert_strict_rejection(&extra);
        }
    }
    assert_eq!(frames_by_variant.len(), 6);
    assert!(frames_by_variant.values().all(|frames| frames.len() == 3));
}

#[test]
fn artifact_registry_instructions_bind_full_width_dataspace_without_hash_only_alias() {
    use iroha_data_model::{
        isi::smart_contract_code::{RegisterSmartContractBytes, RemoveSmartContractBytes},
        smart_contract::ContractArtifactId,
    };
    use iroha_model_base::topology::DataSpaceId;
    let manifest: ContractManifest =
        json::from_value(register_code_payload()["manifest"].clone()).unwrap();
    let code_hash = manifest.code_hash.unwrap();
    let artifact_id = ContractArtifactId::new(DataSpaceId::new(u64::MAX), code_hash);
    let instructions: Vec<InstructionBox> = vec![
        RegisterSmartContractCode {
            artifact_id,
            manifest,
        }
        .into(),
        RegisterSmartContractBytes {
            artifact_id,
            code: vec![1],
        }
        .into(),
        UploadSmartContractCodeChunk {
            artifact_id,
            total_size: 1,
            chunk_index: 0,
            chunk_count: 1,
            chunk: vec![1],
        }
        .into(),
        FinalizeSmartContractCodeUpload {
            artifact_id,
            total_size: 1,
            chunk_count: 1,
        }
        .into(),
        CancelSmartContractCodeUpload { artifact_id }.into(),
        RemoveSmartContractBytes {
            artifact_id,
            reason: None,
        }
        .into(),
    ];
    for instruction in instructions {
        let value = instruction_to_json_value(&instruction).unwrap();
        assert_typed_instruction_roundtrip(&instruction, &value);
        let (name, payload) = value.as_object().unwrap().iter().next().unwrap();
        assert_eq!(
            payload["artifact_id"]["dataspace_id"],
            Value::String(u64::MAX.to_string())
        );
        let original = instruction.encode();
        let mut foreign = payload.clone();
        foreign
            .as_object_mut()
            .unwrap()
            .get_mut("artifact_id")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("dataspace_id".into(), Value::String("0".into()));
        let foreign = value_to_instruction(object([(name.as_str(), foreign)])).unwrap();
        assert_ne!(
            foreign.encode(),
            original,
            "scope must be part of canonical signed bytes"
        );
        let mut hash_only = payload.clone();
        let fields = hash_only.as_object_mut().unwrap();
        fields.remove("artifact_id");
        fields.insert("code_hash".into(), json::to_value(&code_hash).unwrap());
        assert_strict_rejection(&object([(name.as_str(), hash_only)]));
        let mut extra_payload = payload.clone();
        extra_payload
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), Value::Null);
        assert_strict_rejection(&object([(name.as_str(), extra_payload)]));
        let mut extra = value.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), Value::Null);
        assert_strict_rejection(&extra);
        for malformed in [
            Value::from(u64::MAX),
            Value::String("01".into()),
            Value::String("18446744073709551616".into()),
        ] {
            let mut invalid = payload.clone();
            invalid
                .as_object_mut()
                .unwrap()
                .get_mut("artifact_id")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("dataspace_id".into(), malformed);
            assert_strict_rejection(&object([(name.as_str(), invalid)]));
        }
    }
}
