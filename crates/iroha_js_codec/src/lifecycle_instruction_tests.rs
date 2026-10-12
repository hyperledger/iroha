//! Native model, fixed NFT vectors, exact JSON, frame and archive regressions.

use iroha_crypto::Hash;
use iroha_data_model::isi::InstructionBox;
use norito::{
    codec::Encode,
    json::{self, Value},
};

const FIXTURE_NETWORK_PREFIX: u16 = 753;

type DecodeFn = fn(&[u8], u16) -> CodecResult<String>;

use super::*;
use crate::{
    decode_instruction_archive, decode_instruction_frame, encode_instruction_archive,
    encode_instruction_frame, instruction_from_json, instruction_to_json_value,
};

fn text(value: &Value) -> String {
    json::to_json(value).expect("test JSON")
}

fn object(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn fields(value: &mut Value) -> &mut json::Map {
    let Value::Object(fields) = value else {
        panic!("object fixture")
    };
    fields
}

fn named(name: &'static str, payload: Value) -> Value {
    object([(name, payload)])
}

fn roundtrip(value: &Value) -> InstructionBox {
    let source = text(value);
    let native = instruction_from_json(&source).expect("typed instruction");
    assert!(is_lifecycle_instruction(&native));
    assert_eq!(instruction_to_json_value(&native).unwrap(), *value);
    let archive = encode_instruction_archive(&source, FIXTURE_NETWORK_PREFIX).expect("archive");
    let frame = encode_instruction_frame(&source, FIXTURE_NETWORK_PREFIX).expect("frame");
    assert_eq!(
        archive,
        native.encode(),
        "archive must be native adaptive encoding"
    );
    assert_eq!(
        frame,
        norito::encode_canonical(&native).unwrap(),
        "frame must be native canonical encoding"
    );
    for decoded in [
        decode_instruction_archive(&archive, FIXTURE_NETWORK_PREFIX),
        decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX),
    ] {
        assert_eq!(json::from_json::<Value>(&decoded.unwrap()).unwrap(), *value);
    }
    assert!(
        decode_instruction_archive(&frame, FIXTURE_NETWORK_PREFIX).is_err(),
        "public frame is not an archive"
    );
    assert!(
        decode_instruction_frame(&archive, FIXTURE_NETWORK_PREFIX).is_err(),
        "archive is not a public frame"
    );
    let encodings: [(Vec<u8>, DecodeFn); 2] = [
        (archive, decode_instruction_archive),
        (frame, decode_instruction_frame),
    ];
    for (bytes, decode) in encodings {
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            decode(&trailing, FIXTURE_NETWORK_PREFIX).is_err(),
            "trailing bytes must fail"
        );
        assert!(
            decode(&bytes[..bytes.len() - 1], FIXTURE_NETWORK_PREFIX).is_err(),
            "truncation must fail"
        );
    }
    native
}

fn rejects(value: &Value) {
    for encode in [encode_instruction_archive, encode_instruction_frame] {
        let error =
            encode(&text(value), FIXTURE_NETWORK_PREFIX).expect_err("strict input must fail");
        assert_eq!(error.kind(), CodecErrorKind::InvalidArgument, "{error}");
    }
}

fn nft_vectors() -> Vec<(String, Value, String)> {
    let fixtures: Value = json::from_json(include_str!(
        "../../../javascript/iroha_js/test/fixtures/nft-market-v1-codec.json"
    ))
    .unwrap();
    fixtures
        .get("vectors")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|vector| {
            let name = vector.get("name").unwrap().as_str().unwrap();
            if !matches!(name, "OfferNftV1" | "BuyNftV1" | "CancelNftOfferV1") {
                return None;
            }
            let mut payload = vector.get("value").unwrap().clone();
            let terms = if name == "BuyNftV1" {
                fields(&mut payload).get_mut("offer").unwrap()
            } else {
                &mut payload
            };
            if let Some(expiry) = fields(terms).get_mut("expires_at_height") {
                *expiry = Value::String(expiry.as_u64().unwrap().to_string());
            }
            Some((
                name.to_owned(),
                payload,
                vector
                    .get("instruction_hex")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ))
        })
        .collect()
}

fn nft(name: &str) -> Value {
    let (name, payload, _) = nft_vectors()
        .into_iter()
        .find(|entry| entry.0 == name)
        .unwrap();
    Value::Object([(name, payload)].into_iter().collect())
}

fn hash() -> Value {
    render_model(&Hash::new(b"lifecycle-codec-test")).unwrap()
}

fn contract_address() -> Value {
    Value::String("irohac1qyqqqqqqqqqqqq8y2pcrtkxvkrn5nt74kjjkjcst6kc56qcqa2dqp".to_owned())
}

fn deployment(name: &'static str) -> Value {
    let mut payload = match name {
        "UploadSmartContractCodeChunk" => object([
            ("total_size", Value::String("4".into())),
            ("chunk_index", Value::from(0_u32)),
            ("chunk_count", Value::from(1_u32)),
            ("chunk", Value::String("AQIDBA==".into())),
        ]),
        "FinalizeSmartContractCodeUpload" => object([
            ("total_size", Value::String("4".into())),
            ("chunk_count", Value::from(1_u32)),
        ]),
        "CommitContractDeployment" => object([
            ("expected_deploy_nonce", Value::String("7".into())),
            ("contract_address", contract_address()),
            ("contract_alias", Value::String("demo::universal".into())),
            ("lease_expiry_ms", Value::String("123456".into())),
            ("expected_previous_contract_address", Value::Null),
        ]),
        _ => panic!("deployment variant"),
    };
    if name == "CommitContractDeployment" {
        fields(&mut payload).insert("code_hash".into(), hash());
    } else {
        let address = parse_model(contract_address(), "fixture contract address").unwrap();
        let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::for_address(
            &address,
            Hash::new(b"lifecycle-codec-test"),
        )
        .expect("same deployment address and code hash");
        fields(&mut payload).insert(
            "artifact_id".into(),
            render_artifact_id(&artifact_id).unwrap(),
        );
    }
    named(name, payload)
}

fn digest(byte: u8) -> Value {
    Value::String(hex::encode([byte; 32]))
}

fn replication(name: &'static str) -> Value {
    let mut payload = match name {
        "IssueReplicationOrder" => object([
            (
                "order_payload",
                Value::String(STANDARD.encode(include_bytes!(
                    "../../../fixtures/sorafs_manifest/replication_order/order_v1.to"
                ))),
            ),
            ("issued_epoch", Value::from(20_u64)),
            ("deadline_epoch", Value::from(28_u64)),
            ("musubi_archive", Value::Null),
        ]),
        "CompleteReplicationOrder" => object([
            ("provider_id", digest(0x10)),
            ("completion_epoch", Value::from(27_u64)),
            (
                "expected_authority",
                object([
                    (
                        "provider_owner",
                        Value::String(
                            "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV".into(),
                        ),
                    ),
                    (
                        "completion_signer",
                        render_model(&iroha_data_model::account::AccountId::new(
                            iroha_crypto::KeyPair::try_from_seed(
                                vec![0xd3; 32],
                                iroha_crypto::Algorithm::Ed25519,
                            )
                            .expect("dedicated completion key")
                            .public_key()
                            .clone(),
                        ))
                        .expect("canonical completion account"),
                    ),
                    (
                        "signer_policy",
                        object([
                            ("policy_id", digest(0x21)),
                            ("revision", Value::from(2_u64)),
                            ("predecessor_digest", digest(0x32)),
                            ("policy_digest", digest(0x43)),
                        ]),
                    ),
                ]),
            ),
            ("expected_assignment_revision", Value::from(3_u64)),
            (
                "finalized_anchor",
                object([
                    ("height", Value::from(41_u64)),
                    ("block_hash", digest(0x54)),
                ]),
            ),
        ]),
        "ExpireReplicationOrder" => object([("expiration_epoch", Value::from(29_u64))]),
        _ => panic!("replication variant"),
    };
    fields(&mut payload).insert("order_id".into(), digest(0x2b));
    named(name, payload)
}

fn all() -> Vec<Value> {
    ["OfferNftV1", "BuyNftV1", "CancelNftOfferV1"]
        .into_iter()
        .map(nft)
        .chain(
            [
                "UploadSmartContractCodeChunk",
                "FinalizeSmartContractCodeUpload",
                "CommitContractDeployment",
            ]
            .into_iter()
            .map(deployment),
        )
        .chain(
            [
                "IssueReplicationOrder",
                "CompleteReplicationOrder",
                "ExpireReplicationOrder",
            ]
            .into_iter()
            .map(replication),
        )
        .collect()
}

#[test]
fn nft_instructions_match_existing_native_archive_vectors() {
    let vectors = nft_vectors();
    assert_eq!(vectors.len(), 3);
    for (name, payload, expected) in vectors {
        let value = Value::Object([(name, payload)].into_iter().collect());
        let native = roundtrip(&value);
        assert_eq!(hex::encode_upper(native.encode()), expected);
    }
}

#[test]
fn contract_deployment_instructions_roundtrip_frames_and_archives() {
    for name in [
        "UploadSmartContractCodeChunk",
        "FinalizeSmartContractCodeUpload",
        "CommitContractDeployment",
    ] {
        roundtrip(&deployment(name));
    }
}

#[test]
fn artifact_identity_preserves_full_dataspace_range_and_rejects_retired_layouts() {
    for name in [
        "UploadSmartContractCodeChunk",
        "FinalizeSmartContractCodeUpload",
    ] {
        for dataspace in [0_u64, 42, u64::MAX] {
            let mut value = deployment(name);
            fields(
                fields(fields(&mut value).get_mut(name).unwrap())
                    .get_mut("artifact_id")
                    .unwrap(),
            )
            .insert("dataspace_id".into(), Value::String(dataspace.to_string()));
            let native = roundtrip(&value);
            let actual = if name == "UploadSmartContractCodeChunk" {
                native
                    .as_any()
                    .downcast_ref::<UploadSmartContractCodeChunk>()
                    .unwrap()
                    .artifact_id
            } else {
                native
                    .as_any()
                    .downcast_ref::<FinalizeSmartContractCodeUpload>()
                    .unwrap()
                    .artifact_id
            };
            assert_eq!(actual.dataspace_id.as_u64(), dataspace);
            assert_eq!(actual.code_hash, Hash::new(b"lifecycle-codec-test"));
        }
        let original = deployment(name);
        for replacement in [
            Value::Null,
            Value::from(42_u64),
            Value::String("01".into()),
            Value::String("+42".into()),
            Value::String("18446744073709551616".into()),
        ] {
            let mut value = original.clone();
            fields(
                fields(fields(&mut value).get_mut(name).unwrap())
                    .get_mut("artifact_id")
                    .unwrap(),
            )
            .insert("dataspace_id".into(), replacement);
            rejects(&value);
        }
        for field in ["dataspace_id", "code_hash"] {
            let mut value = original.clone();
            fields(
                fields(fields(&mut value).get_mut(name).unwrap())
                    .get_mut("artifact_id")
                    .unwrap(),
            )
            .remove(field);
            rejects(&value);
        }
        let mut extra = original.clone();
        fields(
            fields(fields(&mut extra).get_mut(name).unwrap())
                .get_mut("artifact_id")
                .unwrap(),
        )
        .insert("unrecognized".into(), Value::Null);
        rejects(&extra);
        let mut retired = original.clone();
        let payload = fields(fields(&mut retired).get_mut(name).unwrap());
        payload.remove("artifact_id");
        payload.insert("code_hash".into(), hash());
        rejects(&retired);
    }
}

#[test]
fn replication_instructions_roundtrip_all_authority_anchor_and_archive_fields() {
    for name in [
        "IssueReplicationOrder",
        "CompleteReplicationOrder",
        "ExpireReplicationOrder",
    ] {
        roundtrip(&replication(name));
    }
    let mut value = replication("IssueReplicationOrder");
    fields(fields(&mut value).get_mut("IssueReplicationOrder").unwrap())
        .insert("musubi_archive".into(), digest(0xcd));
    roundtrip(&value);
}

#[test]
fn every_named_envelope_and_top_level_field_is_closed() {
    for original in all() {
        let (name, payload) = original.as_object().unwrap().iter().next().unwrap();
        let mut extra_envelope = original.clone();
        fields(&mut extra_envelope).insert("other".into(), Value::Null);
        rejects(&extra_envelope);
        for field in payload.as_object().unwrap().keys() {
            let mut missing = original.clone();
            fields(fields(&mut missing).get_mut(name).unwrap()).remove(field);
            rejects(&missing);
        }
        for replacement in [
            Value::Null,
            Value::Array(Vec::new()),
            Value::String("payload".into()),
        ] {
            let mut malformed = original.clone();
            fields(&mut malformed).insert(name.clone(), replacement);
            rejects(&malformed);
        }
        let mut extra = original.clone();
        fields(fields(&mut extra).get_mut(name).unwrap())
            .insert("arbitrary_code".into(), Value::Array(Vec::new()));
        rejects(&extra);
    }
}

#[test]
fn nested_nft_and_replication_contracts_require_every_exact_field() {
    for (original, path) in [
        (nft("BuyNftV1"), vec!["BuyNftV1", "offer"]),
        (
            replication("CompleteReplicationOrder"),
            vec!["CompleteReplicationOrder", "expected_authority"],
        ),
        (
            replication("CompleteReplicationOrder"),
            vec![
                "CompleteReplicationOrder",
                "expected_authority",
                "signer_policy",
            ],
        ),
        (
            replication("CompleteReplicationOrder"),
            vec!["CompleteReplicationOrder", "finalized_anchor"],
        ),
    ] {
        let mut nested = &original;
        for name in &path {
            nested = nested.get(*name).unwrap();
        }
        let keys = nested
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for key in keys.iter().map(Some).chain(std::iter::once(None)) {
            let mut candidate = original.clone();
            let mut nested = &mut candidate;
            for name in &path {
                nested = fields(nested).get_mut(*name).unwrap();
            }
            if let Some(key) = key {
                fields(nested).remove(key);
            } else {
                fields(nested).insert("ignored".into(), Value::Null);
            }
            rejects(&candidate);
        }
    }
}

#[test]
fn generic_native_envelopes_cannot_bypass_named_contracts() {
    for value in all() {
        let native = instruction_from_json(&text(&value)).unwrap();
        let generic = json::to_value(&native).expect("native instruction JSON");
        assert_ne!(
            generic, value,
            "registry envelope is distinct from SDK object"
        );
        rejects(&generic);
    }
    assert!(from_json(&Value::Null).is_none());
    assert!(from_json(&object([("UnknownInstruction", Value::Null)])).is_none());
    let other: InstructionBox = iroha_data_model::isi::escrow::CancelAssetLock::new(
        iroha_data_model::escrow::EscrowId::new(Hash::new(b"other")),
        iroha_primitives::numeric::Quantity::from(1_u32),
    )
    .into();
    assert!(!is_lifecycle_instruction(&other));
    assert!(to_json(&other).is_none());
}

#[test]
fn native_operand_spellings_and_integer_ranges_are_exact() {
    for invalid in [
        Value::String("01".into()),
        Value::String("+1".into()),
        Value::String(" 1".into()),
        Value::String("18446744073709551616".into()),
        Value::from(1_u64),
        Value::Null,
    ] {
        assert!(parse_u64_text(invalid, "u64").is_err());
    }
    assert_eq!(
        parse_u64_text(Value::String(u64::MAX.to_string()), "u64").unwrap(),
        u64::MAX
    );
    assert_eq!(
        render_u64_text(&u64::MAX).unwrap(),
        Value::String(u64::MAX.to_string())
    );
    assert_eq!(
        parse_u32_number(Value::from(u32::MAX), "u32").unwrap(),
        u32::MAX
    );
    for invalid in [
        Value::from(u64::from(u32::MAX) + 1),
        Value::from(-1_i64),
        Value::String("1".into()),
    ] {
        assert!(parse_u32_number(invalid, "u32").is_err());
    }
    for (name, field, replacement) in [
        ("OfferNftV1", "offer_id", Value::String("ab".repeat(32))),
        ("OfferNftV1", "price", Value::String("3.1250".into())),
        (
            "OfferNftV1",
            "reserved_buyer",
            Value::String(" account ".into()),
        ),
    ] {
        let mut value = nft(name);
        fields(fields(&mut value).get_mut(name).unwrap()).insert(field.into(), replacement);
        rejects(&value);
    }
}

#[test]
fn base64_and_digest_operands_reject_alternate_representations() {
    for invalid in [
        Value::Array(vec![Value::from(1_u8)]),
        Value::String("AQ".into()),
        Value::String("AR==".into()),
        Value::String("AQ==\n".into()),
    ] {
        assert!(parse_bytes(invalid, "bytes").is_err());
    }
    assert_eq!(
        parse_bytes(Value::String("AQIDBA==".into()), "bytes").unwrap(),
        vec![1, 2, 3, 4]
    );
    for invalid in [
        Value::Array(Vec::new()),
        Value::String("AB".repeat(32)),
        Value::String(format!("0x{}", "ab".repeat(32))),
        Value::String("ab".repeat(31)),
    ] {
        assert!(parse_digest(invalid, "digest").is_err());
    }
    assert_eq!(parse_digest(digest(0xab), "digest").unwrap(), [0xab; 32]);
}

#[test]
fn optional_operands_preserve_null_some_and_full_u64_values() {
    let mut deployment = deployment("CommitContractDeployment");
    let values = fields(
        fields(&mut deployment)
            .get_mut("CommitContractDeployment")
            .unwrap(),
    );
    values.insert(
        "expected_deploy_nonce".into(),
        Value::String(u64::MAX.to_string()),
    );
    values.insert("lease_expiry_ms".into(), Value::Null);
    values.insert(
        "expected_previous_contract_address".into(),
        contract_address(),
    );
    roundtrip(&deployment);
    let mut offer = nft("OfferNftV1");
    fields(fields(&mut offer).get_mut("OfferNftV1").unwrap())
        .insert("reserved_buyer".into(), Value::Null);
    roundtrip(&offer);
    let mut completion = replication("CompleteReplicationOrder");
    let authority = fields(
        fields(&mut completion)
            .get_mut("CompleteReplicationOrder")
            .unwrap(),
    )
    .get_mut("expected_authority")
    .unwrap();
    let policy = fields(fields(authority).get_mut("signer_policy").unwrap());
    policy.insert("revision".into(), Value::from(1_u64));
    policy.insert("predecessor_digest".into(), Value::Null);
    roundtrip(&completion);
}

#[test]
fn typed_codec_preserves_values_without_asserting_ledger_admission() {
    // Structural conversion is independent of runtime state/configuration:
    // zero terms and opaque bytes remain typed inputs for the executor to reject.
    let mut upload = deployment("UploadSmartContractCodeChunk");
    let values = fields(
        fields(&mut upload)
            .get_mut("UploadSmartContractCodeChunk")
            .unwrap(),
    );
    values.insert("total_size".into(), Value::String("0".into()));
    values.insert("chunk_count".into(), Value::from(0_u32));
    values.insert("chunk".into(), Value::String(String::new()));
    roundtrip(&upload);
    let mut issue = replication("IssueReplicationOrder");
    fields(fields(&mut issue).get_mut("IssueReplicationOrder").unwrap())
        .insert("order_payload".into(), Value::String("AQ==".into()));
    roundtrip(&issue);
}

#[test]
fn replication_number_only_operands_enforce_safe_integer_json_boundaries() {
    let operands = [
        (
            "IssueReplicationOrder",
            "/IssueReplicationOrder/issued_epoch",
        ),
        (
            "IssueReplicationOrder",
            "/IssueReplicationOrder/deadline_epoch",
        ),
        (
            "CompleteReplicationOrder",
            "/CompleteReplicationOrder/completion_epoch",
        ),
        (
            "CompleteReplicationOrder",
            "/CompleteReplicationOrder/expected_assignment_revision",
        ),
        (
            "CompleteReplicationOrder",
            "/CompleteReplicationOrder/expected_authority/signer_policy/revision",
        ),
        (
            "CompleteReplicationOrder",
            "/CompleteReplicationOrder/finalized_anchor/height",
        ),
        (
            "ExpireReplicationOrder",
            "/ExpireReplicationOrder/expiration_epoch",
        ),
    ];
    for (name, pointer) in operands {
        let original = replication(name);
        let mut boundary = original.clone();
        *boundary.pointer_mut(pointer).unwrap() = Value::from(MAX_SAFE_INTEGER);
        roundtrip(&boundary);
        for number in [MAX_SAFE_INTEGER + 1, u64::MAX] {
            let mut oversized = original.clone();
            *oversized.pointer_mut(pointer).unwrap() = Value::from(number);
            rejects(&oversized);
        }
        // This corridor has number-only operands. Large-string projection belongs
        // to other contracts; it must not silently widen this one.
        for number in [0, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER + 1, u64::MAX] {
            let mut alternate = original.clone();
            *alternate.pointer_mut(pointer).unwrap() = Value::String(number.to_string());
            rejects(&alternate);
        }
    }
    assert_eq!(
        parse_u64_number(Value::from(MAX_SAFE_INTEGER), "operand").unwrap(),
        MAX_SAFE_INTEGER
    );
    assert_eq!(
        render_u64_number(&MAX_SAFE_INTEGER).unwrap(),
        Value::from(MAX_SAFE_INTEGER)
    );
    for number in [MAX_SAFE_INTEGER + 1, u64::MAX] {
        assert!(parse_u64_number(Value::from(number), "operand").is_err());
        assert!(render_u64_number(&number).is_err());
    }
}

#[test]
fn replication_native_frames_and_archives_reject_unsafe_integer_projection() {
    let mut mutations: Vec<InstructionBox> = Vec::new();
    macro_rules! mutate_operand {
        ($ty:ident, $($field:ident).+) => {{
            let native = instruction_from_json(&text(&replication(stringify!($ty)))).unwrap();
            let instruction: &dyn Instruction = &*native;
            let typed = instruction.as_any().downcast_ref::<$ty>().unwrap();
            for number in [MAX_SAFE_INTEGER + 1, u64::MAX] {
                let mut mutated = typed.clone();
                mutated.$($field).+ = number;
                mutations.push(mutated.into());
            }
        }};
    }
    mutate_operand!(IssueReplicationOrder, issued_epoch);
    mutate_operand!(IssueReplicationOrder, deadline_epoch);
    mutate_operand!(CompleteReplicationOrder, completion_epoch);
    mutate_operand!(CompleteReplicationOrder, expected_assignment_revision);
    mutate_operand!(
        CompleteReplicationOrder,
        expected_authority.signer_policy.revision
    );
    mutate_operand!(CompleteReplicationOrder, finalized_anchor.height);
    mutate_operand!(ExpireReplicationOrder, expiration_epoch);
    assert_eq!(mutations.len(), 14);
    for native in mutations {
        assert_eq!(
            instruction_to_json_value(&native).unwrap_err().kind(),
            CodecErrorKind::InvalidArgument
        );
        // Encode the mutated Rust value directly. This bypasses JSON admission
        // and proves that each decoder independently enforces the number bound.
        let archive = native.encode();
        let frame = norito::encode_canonical(&native).unwrap();
        for result in [
            decode_instruction_archive(&archive, FIXTURE_NETWORK_PREFIX),
            decode_instruction_frame(&frame, FIXTURE_NETWORK_PREFIX),
        ] {
            let error = result.expect_err("unsafe integer must not be projected into SDK JSON");
            assert_eq!(error.kind(), CodecErrorKind::InvalidArgument, "{error}");
            assert!(error.reason().contains("maximum safe integer"), "{error}");
        }
    }
}

#[test]
fn replication_completion_signer_is_distinct_required_and_canonical() {
    let original = replication("CompleteReplicationOrder");
    let authority = original
        .get("CompleteReplicationOrder")
        .unwrap()
        .get("expected_authority")
        .unwrap();
    assert_ne!(
        authority.get("provider_owner"),
        authority.get("completion_signer")
    );
    roundtrip(&original);
    for replacement in [
        Value::Null,
        Value::String(String::new()),
        Value::String("not-an-account".into()),
    ] {
        let mut candidate = original.clone();
        let authority = fields(
            fields(
                fields(&mut candidate)
                    .get_mut("CompleteReplicationOrder")
                    .unwrap(),
            )
            .get_mut("expected_authority")
            .unwrap(),
        );
        authority.insert("completion_signer".into(), replacement);
        rejects(&candidate);
    }
}
