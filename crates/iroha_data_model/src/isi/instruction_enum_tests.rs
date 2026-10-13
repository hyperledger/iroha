#![allow(clippy::too_many_lines)]
use super::*;
use crate::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::const_vec::ConstVec;
const RECORD_BRIDGE_RECEIPT_WIRE_ID: &str = "iroha.instruction.v1::bridge::RecordBridgeReceipt";
macro_rules! check_enum {
        ($name:ident { $($variant:ident),+ $(,)? }) => {
            $(assert_eq!($name::try_from($name::$variant as u8).unwrap(), $name::$variant);)+
            assert!($name::try_from(u8::MAX).is_err());
            $(assert_eq!(format!("{}", $name::$variant), stringify!($variant));)+
        };
    }
struct RegistryGuard;
impl RegistryGuard {
    fn set(registry: InstructionRegistry) -> Self {
        set_instruction_registry(registry);
        Self
    }
}
impl Drop for RegistryGuard {
    fn drop(&mut self) {
        set_instruction_registry(crate::instruction_registry::default());
    }
}
fn bridge_receipt(recipient: &[u8]) -> crate::bridge::BridgeReceipt {
    crate::bridge::BridgeReceipt {
        lane: iroha_model_base::topology::LaneId::from(1),
        direction: b"mint".to_vec(),
        source_tx: [0x44; 32],
        dest_tx: None,
        proof_hash: [0x45; 32],
        amount: 7_u32.into(),
        asset_id: b"wrapped#bridge".to_vec(),
        recipient: recipient.to_vec(),
    }
}
fn test_domain_id() -> DomainId {
    DomainId::try_new("wonderland", "universal").expect("domain id")
}
fn framed_instruction_payload<T>(value: &T) -> Vec<u8>
where
    T: Instruction + norito::codec::Encode + 'static + norito::core::NoritoSerialize,
{
    let (payload, flags) = norito::codec::encode_with_header_flags(value);
    norito::core::frame_bare_with_header_flags::<T>(&payload, flags)
        .expect("frame instruction payload")
}
fn bare_instruction_pair(name: &str, framed_payload: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::new();
    norito::core::serialize_to_buffer(&(name.to_owned(), framed_payload), &mut bytes)
        .expect("serialize instruction pair");
    bytes
}
fn framed_instruction_pair(name: &str, framed_payload: Vec<u8>) -> Vec<u8> {
    norito::core::to_bytes(&(name.to_owned(), framed_payload))
        .expect("serialize framed instruction pair")
}
#[test]
fn aa_setup_instruction_registry() {
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
}
#[test]
fn register_and_decode_instruction() {
    let registry = InstructionRegistry::new().register_with_id_slice::<Log>(Log::WIRE_ID);
    // The concrete type name selects encoding only; the wire ID selects decoding.
    assert!(
        !registry.is_empty(),
        "registry should contain at least one entry"
    );
    assert!(registry.contains(Log::WIRE_ID));
    assert!(!registry.contains(std::any::type_name::<Log>()));
    let name = std::any::type_name::<Log>();
    let instruction = Log {
        level: Level::INFO,
        msg: "test".into(),
    };
    let (payload, flags) = norito::codec::encode_with_header_flags(&instruction);
    let bytes = norito::core::frame_bare_with_header_flags::<Log>(&payload, flags)
        .expect("frame instruction payload");
    // Use the decode API directly to ensure local registry wiring works
    let decoded = InstructionRegistry::decode(&registry, Log::WIRE_ID, &bytes)
        .expect("constructor not found in decode map")
        .expect("failed to decode");
    // Verify type id and payload equivalence without relying on downcast
    assert_eq!(Instruction::id(&*decoded), name);
    assert_eq!(Instruction::dyn_encode(&*decoded), payload);
}

#[test]
fn instruction_box_json_is_canonical_and_ambient_independent() {
    let registry = InstructionRegistry::new().register_with_id_slice::<Log>(Log::WIRE_ID);
    let _registry = RegistryGuard::set(registry);
    let instruction = InstructionBox::from(Log::new(
        Level::INFO,
        "canonical JSON instruction".to_owned(),
    ));
    let canonical_json =
        norito::json::to_json(&instruction).expect("encode canonical InstructionBox JSON");
    assert_eq!(
        norito::json::to_json_bounded(&instruction, canonical_json.len())
            .expect("encode InstructionBox at its exact JSON bound"),
        canonical_json
    );
    assert_eq!(
        norito::json::to_json_bounded(&instruction, canonical_json.len() - 1),
        Err(norito::json::BoundedJsonError::BodyTooLarge)
    );
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_eq!(
            norito::json::to_json(&instruction)
                .expect("encode InstructionBox JSON under alternate ambient layout"),
            canonical_json
        );
    }
    let alternate_frame = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&instruction).expect("encode alternate-layout InstructionBox")
    };
    let alternate_json = norito::json::to_json(&STANDARD.encode(alternate_frame))
        .expect("encode alternate frame as JSON string");
    norito::json::from_json::<InstructionBox>(&alternate_json)
        .expect_err("alternate-layout InstructionBox JSON must be rejected");
}
#[test]
fn decode_unregistered_instruction() {
    let registry = InstructionRegistry::new();
    assert!(registry.decode("missing", &[]).is_none());
}
#[test]
fn record_bridge_receipt_registry_roundtrip_preserves_payload_bytes() {
    let registry = InstructionRegistry::new()
        .register_with_id_slice::<RecordBridgeReceipt>(RECORD_BRIDGE_RECEIPT_WIRE_ID);
    let _guard = RegistryGuard::set(registry);
    let instruction = RecordBridgeReceipt::new(bridge_receipt(&[0xAA, 0xBB, 0xCC]));
    let (bytes, expected_flags) = norito::codec::encode_with_header_flags(&instruction);
    let framed = frame_instruction_payload(RECORD_BRIDGE_RECEIPT_WIRE_ID, &bytes)
        .expect("record bridge receipt must frame");
    let view = norito::core::from_bytes_view(&framed).expect("framed instruction payload");
    assert_eq!(view.flags(), expected_flags);
    let decoded = decode_instruction_from_pair(RECORD_BRIDGE_RECEIPT_WIRE_ID, &framed)
        .expect("record bridge receipt must decode");
    let decoded = decoded
        .as_any()
        .downcast_ref::<RecordBridgeReceipt>()
        .expect("decoded instruction type");
    assert_eq!(decoded.receipt, bridge_receipt(&[0xAA, 0xBB, 0xCC]));
}
#[test]
fn registry_decode_accepts_misaligned_framed_payload() {
    let registry = InstructionRegistry::new().register_with_id_slice::<Log>(Log::WIRE_ID);
    let name = std::any::type_name::<Log>();
    let instruction = Log::new(Level::INFO, "misaligned framed payload".to_owned());
    let payload = instruction.encode();
    let framed =
        frame_instruction_payload(Log::WIRE_ID, &payload).expect("frame instruction payload");
    let mut misaligned = Vec::with_capacity(framed.len() + 1);
    misaligned.push(0xAA);
    misaligned.extend_from_slice(&framed);
    let decoded = InstructionRegistry::decode(&registry, Log::WIRE_ID, &misaligned[1..])
        .expect("constructor not found in decode map")
        .expect("decode misaligned framed payload");
    assert_eq!(Instruction::id(&*decoded), name);
    assert_eq!(Instruction::dyn_encode(&*decoded), payload);
}
#[test]
fn instruction_box_embeds_instruction_payload_with_recorded_flags() {
    let registry = InstructionRegistry::new()
        .register_with_id_slice::<RecordBridgeReceipt>(RECORD_BRIDGE_RECEIPT_WIRE_ID);
    let _guard = RegistryGuard::set(registry);
    let instruction = RecordBridgeReceipt::new(bridge_receipt(&[0xAA, 0xBB, 0xCC]));
    let (_, expected_flags) = norito::codec::encode_with_header_flags(&instruction);
    let boxed = InstructionBox::from(instruction);
    let (_, framed_payload) =
        super::encoded_instruction_pair_payload(&boxed).expect("instruction pair payload");
    let view = norito::core::from_bytes_view(&framed_payload).expect("framed instruction payload");
    assert_eq!(view.flags(), expected_flags);
}
#[test]
fn frame_payload_accepts_non_static_wire_id() {
    let log = Log::new(Level::INFO, "framed".to_string());
    let payload = log.encode();
    let wire_id = Log::WIRE_ID.to_owned();
    let framed = frame_instruction_payload(&wire_id, &payload).expect("frame instruction payload");
    let decoded: Log = norito::decode_from_bytes(&framed).expect("decode framed payload");
    assert_eq!(decoded, log);
}
#[test]
fn public_pair_helpers_reject_type_name_decode_aliases_with_bounded_errors() {
    let log = Log::new(Level::INFO, "type-name alias rejection".to_owned());
    let payload = log.encode();
    let framed = frame_instruction_payload(Log::WIRE_ID, &payload).expect("frame log payload");
    let type_name = std::any::type_name::<Log>();
    for error in [
        frame_instruction_payload(type_name, &payload).expect_err("frame alias must fail"),
        decode_instruction_from_pair(type_name, &framed).expect_err("decode alias must fail"),
        decode_instruction_from_pair(&"x".repeat(4096), &framed)
            .expect_err("unknown oversized wire identifier must fail"),
    ] {
        assert_eq!(error.to_string(), "unknown instruction wire identifier");
    }
}
#[test]
fn dyn_encode_matches_instruction_box() {
    let log = Log {
        level: Level::INFO,
        msg: "test".to_string(),
    };
    let boxed = InstructionBox::from(log.clone());
    let expected = Instruction::dyn_encode(&*boxed);
    let actual = Instruction::dyn_encode(&log);
    assert_eq!(actual, expected);
}
#[test]
fn dyn_encode_into_matches_dyn_encode() {
    let log = Log {
        level: Level::INFO,
        msg: "stream encode".to_string(),
    };
    let expected = Instruction::dyn_encode(&log);
    let mut actual = Vec::with_capacity(
        Instruction::dyn_encode_capacity_hint(&log).expect("encode capacity hint"),
    );
    Instruction::dyn_encode_into(&log, &mut actual);
    assert_eq!(actual, expected);
}
#[test]
fn as_any_downcasts() {
    let log = Log {
        level: Level::INFO,
        msg: "downcast".to_string(),
    };
    let instr: &dyn Instruction = &log;
    assert!(instr.as_any().downcast_ref::<Log>().is_some());
}
#[test]
fn into_instruction_box_produces_equivalent() {
    let log = Log {
        level: Level::INFO,
        msg: "into".to_string(),
    };
    let boxed = Instruction::into_instruction_box(Box::new(log.clone()));
    let expected = Instruction::dyn_encode(&*InstructionBox::from(log));
    assert_eq!(Instruction::dyn_encode(&*boxed), expected);
}
#[test]
fn dyn_execute_does_not_panic() {
    let log = InstructionBox::from(Log {
        level: Level::INFO,
        msg: "exec".to_string(),
    });
    Instruction::dyn_execute(&*log);
}
#[test]
fn instruction_box_display() {
    let log = InstructionBox::from(Log {
        level: Level::INFO,
        msg: "display".to_string(),
    });
    assert_eq!(log.to_string(), "InstructionBox");
}
#[test]
fn norito_serialize_trait_object() {
    let log = Log {
        level: Level::INFO,
        msg: "serialize".to_string(),
    };
    let boxed = InstructionBox::from(log.clone());
    let bytes = norito::core::to_bytes(&boxed).expect("serialize");
    let archived = norito::core::from_bytes::<(String, Vec<u8>)>(&bytes).expect("from_bytes");
    let (name, payload) =
        norito::core::DeserializePayload::try_deserialize(archived).expect("deserialize");
    assert_eq!(name, Log::WIRE_ID);
    let bare = Instruction::dyn_encode(&log);
    let payload_slice = payload.as_slice();
    assert!(
        payload_slice.starts_with(&norito::core::MAGIC),
        "Instruction payload must include Norito header",
    );
    assert!(
        payload.len() >= norito::core::Header::SIZE,
        "Instruction payload shorter than Norito header",
    );
    assert_eq!(
        &payload_slice[norito::core::Header::SIZE..],
        bare.as_slice()
    );
}
#[test]
fn instruction_box_direct_serialize_matches_tuple_wire_layout() {
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let boxed = InstructionBox::from(Log {
        level: Level::INFO,
        msg: "tuple layout".to_string(),
    });
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        let (name, payload) =
            super::encoded_instruction_pair_payload(&boxed).expect("instruction pair payload");
        let expected_pair = (name.to_owned(), payload);
        let mut expected = Vec::new();
        norito::core::serialize_to_buffer(&expected_pair, &mut expected)
            .expect("serialize expected tuple");
        let mut actual = Vec::new();
        norito::core::serialize_to_buffer(&boxed, &mut actual).expect("serialize instruction box");
        assert_eq!(actual, expected, "flags=0x{flags:02x}");
    }
}
#[test]
fn instruction_box_encoded_len_exact_matches_norito() {
    let boxed = InstructionBox::from(Log {
        level: Level::INFO,
        msg: "exact length".to_string(),
    });
    let expected = norito::core::to_bytes(&boxed)
        .expect("serialize instruction box")
        .len()
        - norito::core::Header::SIZE;
    assert_eq!(
        norito::core::SerializePayload::encoded_len_exact(&boxed)
            .expect("instruction box exact len"),
        expected
    );
}
#[test]
fn instruction_box_len_hint_does_not_force_exact_inner_len() {
    let boxed = InstructionBox::from(CustomInstruction::new("custom length hint"));
    let exact = norito::core::SerializePayload::encoded_len_exact(&boxed);
    let hint = norito::core::SerializePayload::encoded_len_hint(&boxed)
        .expect("instruction box length hint");
    let actual = norito::core::to_bytes(&boxed)
        .expect("serialize instruction box")
        .len()
        - norito::core::Header::SIZE;
    assert!(
        exact.is_none() || exact == Some(actual),
        "exact length must be absent or byte-accurate"
    );
    assert!(hint >= actual, "length hint must not under-reserve");
}
#[test]
fn norito_roundtrip_trait_object_deserialize() {
    let log = Log {
        level: Level::INFO,
        msg: "deserialize".to_string(),
    };
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let boxed = InstructionBox::from(log.clone());
    let bytes = norito::core::to_bytes(&boxed).expect("serialize");
    let archived = norito::core::from_bytes::<InstructionBox>(&bytes).expect("from_bytes");
    let decoded = norito::core::DeserializePayload::try_deserialize(archived).expect("deserialize");
    // Validate via type id and payload equality rather than downcast
    assert_eq!(Instruction::id(&*decoded), Instruction::id(&log));
    assert_eq!(
        Instruction::dyn_encode(&*decoded),
        Instruction::dyn_encode(&log)
    );
}
#[test]
fn instruction_pair_canonical_decode_covers_payload_body() {
    let expected = ("force-decode".to_owned(), vec![1_u8, 2, 3, 4]);
    let framed =
        norito::core::to_bytes(&expected).expect("serialize instruction tuple with Norito");
    let archived =
        norito::core::from_bytes::<(String, Vec<u8>)>(&framed).expect("decode framed tuple");
    let decoded = norito::core::DeserializePayload::try_deserialize(archived).expect("decode");
    assert_eq!(decoded, expected);
}
#[test]
fn borrowed_instruction_pair_decodes_without_owned_payload() {
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let expected = InstructionBox::from(Log::new(Level::INFO, "borrowed pair".to_owned()));
    let mut bytes = Vec::new();
    norito::core::serialize_to_buffer(&expected, &mut bytes)
        .expect("serialize instruction box tuple");
    let (decoded, used) =
        super::decode_instruction_from_borrowed_pair(&bytes).expect("borrowed pair decode");
    assert_eq!(used, bytes.len());
    assert_eq!(Instruction::id(&*decoded), Instruction::id(&*expected));
    assert_eq!(
        Instruction::dyn_encode(&*decoded),
        Instruction::dyn_encode(&*expected)
    );
}
#[test]
fn borrowed_instruction_pair_honors_inner_frame_flags_under_outer_canonical_layout() {
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let log = Log::new(Level::INFO, "inner compact frame".to_owned());
    let expected = InstructionBox::from(log.clone());
    let framed_payload = framed_instruction_payload(&log);
    assert_eq!(
        framed_payload[norito::core::Header::SIZE - 1] & norito::core::header_flags::COMPACT_LEN,
        norito::core::header_flags::COMPACT_LEN
    );
    let _layout = norito::core::DecodeFlagsGuard::enter(0);
    let bytes = bare_instruction_pair(Log::WIRE_ID, framed_payload);
    let (decoded, used) =
        super::decode_instruction_from_borrowed_pair(&bytes).expect("borrowed pair decode");
    assert_eq!(used, bytes.len());
    assert_eq!(Instruction::id(&*decoded), Instruction::id(&*expected));
    assert_eq!(
        Instruction::dyn_encode(&*decoded),
        Instruction::dyn_encode(&*expected)
    );
}
#[test]
fn instruction_box_decode_from_slice_accepts_misaligned_borrowed_pair() {
    use norito::core::DecodeFromSlice;
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let expected = InstructionBox::from(Log::new(Level::INFO, "misaligned pair".to_owned()));
    let mut bytes = vec![0xAA];
    norito::core::serialize_to_buffer(&expected, &mut bytes)
        .expect("serialize instruction box tuple");
    let (decoded, used) =
        InstructionBox::decode_from_slice(&bytes[1..]).expect("decode misaligned pair");
    assert_eq!(used, bytes.len() - 1);
    assert_eq!(Instruction::id(&*decoded), Instruction::id(&*expected));
    assert_eq!(
        Instruction::dyn_encode(&*decoded),
        Instruction::dyn_encode(&*expected)
    );
}
#[test]
fn instruction_box_rejects_non_norito_payload() {
    use norito::core::DecodeFromSlice;
    let err = InstructionBox::decode_from_slice(&[0x01, 0x02])
        .expect_err("non-canonical payload must be rejected");
    match err {
        norito::core::Error::Message(msg) => assert!(
            msg.contains("canonical Norito framing"),
            "error should steer callers to the canonical encoding: {msg}"
        ),
        other => panic!("unexpected error variant: {other:?}"),
    }
}
#[test]
fn instruction_box_lossy_deserialize_maps_malformed_pair_payload_to_invalid_instruction() {
    let malformed_pair_payload = vec![0xFF; 32];
    let framed = norito::core::frame_bare_with_header_flags::<InstructionBox>(
        &malformed_pair_payload,
        norito::core::default_encode_flags(),
    )
    .expect("frame malformed instruction-box payload");
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed).expect("instruction-box frame");
    assert!(
        norito::core::DeserializePayload::try_deserialize(archived).is_err(),
        "strict decode must reject malformed pair payloads"
    );
    let decoded: InstructionBox = norito::core::DeserializePayload::deserialize(archived);
    let invalid = decoded
        .as_any()
        .downcast_ref::<transparent::InvalidInstruction>()
        .expect("malformed pair becomes invalid placeholder");
    assert_eq!(invalid.wire_id, "<norito>");
    assert_eq!(invalid.payload_hash, [0; 32]);
    assert!(
        invalid.message.len() <= 256,
        "Norito tuple decode error should be bounded, got {} bytes",
        invalid.message.len()
    );
}
#[test]
fn instruction_box_decoders_reject_registered_wire_id_with_unframed_payload() {
    use norito::core::DecodeFromSlice;
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let malformed_payload = vec![0x01, 0x02, 0x03];
    let framed_pair = framed_instruction_pair(Log::WIRE_ID, malformed_payload.clone());
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed_pair).expect("instruction pair");
    assert!(
        norito::core::DeserializePayload::try_deserialize(archived).is_err(),
        "strict decode must reject unframed payload bytes for registered wire ids"
    );
    let bare_pair = bare_instruction_pair(Log::WIRE_ID, malformed_payload.clone());
    assert!(
        InstructionBox::decode_from_slice(&bare_pair).is_err(),
        "borrowed-pair decode must reject unframed payload bytes for registered wire ids"
    );
    let decoded: InstructionBox = norito::core::DeserializePayload::deserialize(archived);
    let invalid = decoded
        .as_any()
        .downcast_ref::<transparent::InvalidInstruction>()
        .expect("malformed registered payload becomes invalid placeholder");
    let expected_hash: [u8; 32] = iroha_crypto::Hash::new(&malformed_payload).into();
    assert_eq!(invalid.wire_id, Log::WIRE_ID);
    assert_eq!(invalid.payload_hash, expected_hash);
}
#[test]
fn instruction_box_strict_decoders_reject_removed_direct_instruction_pairs() {
    use norito::core::DecodeFromSlice;
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let direct_register = Register::domain(Domain::new(test_domain_id()));
    let direct_repo = repo::RepoMarginCallIsi::new(
        "instruction_box_removed_direct"
            .parse()
            .expect("repo agreement id"),
    );
    for (removed_name, framed_payload) in [
        (
            std::any::type_name::<Register<Domain>>(),
            framed_instruction_payload(&direct_register),
        ),
        (
            repo::RepoMarginCallIsi::WIRE_ID,
            framed_instruction_payload(&direct_repo),
        ),
    ] {
        let framed_pair = framed_instruction_pair(removed_name, framed_payload.clone());
        let archived = norito::core::from_bytes::<InstructionBox>(&framed_pair)
            .expect("instruction pair bytes");
        assert!(
            norito::core::DeserializePayload::try_deserialize(archived).is_err(),
            "{removed_name} must be rejected by strict InstructionBox deserialization"
        );
        let bare_pair = bare_instruction_pair(removed_name, framed_payload);
        assert!(
            InstructionBox::decode_from_slice(&bare_pair).is_err(),
            "{removed_name} must be rejected by canonical borrowed-pair decoding"
        );
    }
}
#[test]
fn instruction_box_lossy_deserialize_maps_removed_direct_pair_to_invalid_instruction() {
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let direct_register = Register::domain(Domain::new(test_domain_id()));
    let removed_name = std::any::type_name::<Register<Domain>>();
    let framed_payload = framed_instruction_payload(&direct_register);
    let framed_pair = framed_instruction_pair(removed_name, framed_payload.clone());
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed_pair).expect("instruction pair");
    let decoded: InstructionBox = norito::core::DeserializePayload::deserialize(archived);
    let invalid = decoded
        .as_any()
        .downcast_ref::<transparent::InvalidInstruction>()
        .expect("removed direct instruction becomes invalid placeholder");
    let expected_hash: [u8; 32] = iroha_crypto::Hash::new(&framed_payload).into();
    assert_eq!(invalid.wire_id, removed_name);
    assert_eq!(invalid.payload_hash, expected_hash);
    assert!(
        invalid.message.contains("not registered")
            || invalid.message.contains("unknown instruction"),
        "invalid placeholder should preserve the decode failure: {}",
        invalid.message
    );
}
#[test]
fn instruction_box_strict_decoders_reject_cross_family_instruction_pairs() {
    use norito::core::DecodeFromSlice;
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let register_payload = framed_instruction_payload(&RegisterBox::Domain(Register::domain(
        Domain::new(test_domain_id()),
    )));
    let repo_payload = framed_instruction_payload(&repo::RepoInstructionBox::MarginCall(
        repo::RepoMarginCallIsi::new("instruction_box_cross_family".parse().expect("repo id")),
    ));
    for (spoofed_name, mismatched_payload) in [
        (MintBox::WIRE_ID, register_payload),
        (settlement::SettlementInstructionBox::WIRE_ID, repo_payload),
    ] {
        let framed_pair = framed_instruction_pair(spoofed_name, mismatched_payload.clone());
        let archived = norito::core::from_bytes::<InstructionBox>(&framed_pair)
            .expect("instruction pair bytes");
        assert!(
            norito::core::DeserializePayload::try_deserialize(archived).is_err(),
            "{spoofed_name} must reject a payload from another boxed family"
        );
        let bare_pair = bare_instruction_pair(spoofed_name, mismatched_payload);
        assert!(
            InstructionBox::decode_from_slice(&bare_pair).is_err(),
            "{spoofed_name} must reject mismatched borrowed-pair payloads"
        );
    }
}
#[test]
fn instruction_box_lossy_deserialize_maps_cross_family_pair_to_invalid_instruction() {
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let framed_payload = framed_instruction_payload(&RegisterBox::Domain(Register::domain(
        Domain::new(test_domain_id()),
    )));
    let framed_pair = framed_instruction_pair(MintBox::WIRE_ID, framed_payload.clone());
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed_pair).expect("instruction pair");
    let decoded: InstructionBox = norito::core::DeserializePayload::deserialize(archived);
    let invalid = decoded
        .as_any()
        .downcast_ref::<transparent::InvalidInstruction>()
        .expect("cross-family instruction becomes invalid placeholder");
    let expected_hash: [u8; 32] = iroha_crypto::Hash::new(&framed_payload).into();
    assert_eq!(invalid.wire_id, MintBox::WIRE_ID);
    assert_eq!(invalid.payload_hash, expected_hash);
}
#[test]
fn instruction_box_lossy_deserialize_bounds_unknown_wire_error_message() {
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let hostile_name = format!("iroha.{}", "x".repeat(2048));
    let framed_pair = framed_instruction_pair(&hostile_name, Vec::new());
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed_pair).expect("instruction pair");
    let decoded: InstructionBox = norito::core::DeserializePayload::deserialize(archived);
    let invalid = decoded
        .as_any()
        .downcast_ref::<transparent::InvalidInstruction>()
        .expect("unknown instruction becomes invalid placeholder");
    let expected_hash: [u8; 32] = iroha_crypto::Hash::new([]).into();
    assert_eq!(invalid.wire_id, hostile_name);
    assert_eq!(invalid.payload_hash, expected_hash);
    assert!(
        invalid.message.len() <= 256,
        "decode error should be bounded, got {} bytes",
        invalid.message.len()
    );
    assert!(
        invalid.message.contains("unknown instruction"),
        "invalid placeholder should explain the rejected wire id"
    );
}
#[test]
fn instruction_box_decode_from_slice_rejects_trailing_bytes_after_valid_pair() {
    use norito::core::DecodeFromSlice;
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let boxed = InstructionBox::from(Log::new(Level::INFO, "pair tail".to_owned()));
    let mut bare_pair = Vec::new();
    norito::core::serialize_to_buffer(&boxed, &mut bare_pair)
        .expect("serialize instruction box pair");
    bare_pair.extend_from_slice(&[0xAA, 0x55]);
    let err = InstructionBox::decode_from_slice(&bare_pair)
        .expect_err("trailing bytes after a valid pair must be rejected");
    match err {
        norito::core::Error::Message(msg) => assert!(
            msg.contains("canonical Norito framing"),
            "error should reject non-canonical trailing bytes: {msg}"
        ),
        other => panic!("unexpected error variant: {other:?}"),
    }
}
#[test]
fn instruction_box_try_deserialize_rejects_trailing_bytes_inside_framed_pair() {
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let boxed = InstructionBox::from(Log::new(Level::INFO, "framed pair tail".to_owned()));
    let mut bare_pair = Vec::new();
    norito::core::serialize_to_buffer(&boxed, &mut bare_pair)
        .expect("serialize instruction box pair");
    bare_pair.extend_from_slice(&[0xAA, 0x55]);
    let framed = norito::core::frame_bare_with_header_flags::<InstructionBox>(
        &bare_pair,
        norito::core::default_encode_flags(),
    )
    .expect("frame tailed instruction pair");
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed).expect("instruction box frame");
    let err = norito::core::DeserializePayload::try_deserialize(archived)
        .expect_err("framed instruction pairs with trailing bytes must be rejected");
    match err {
        norito::core::Error::Message(msg) => assert!(
            msg.contains("canonical Norito framing"),
            "error should reject non-canonical trailing bytes: {msg}"
        ),
        other => panic!("unexpected error variant: {other:?}"),
    }
}
#[test]
fn instruction_box_lossy_deserialize_maps_trailing_pair_bytes_to_invalid_instruction() {
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let boxed = InstructionBox::from(Log::new(Level::INFO, "lossy pair tail".to_owned()));
    let (wire_id, framed_payload) =
        encoded_instruction_pair_payload(&boxed).expect("encoded instruction payload");
    assert_eq!(wire_id, Log::WIRE_ID);
    let mut bare_pair = Vec::new();
    norito::core::serialize_to_buffer(&boxed, &mut bare_pair)
        .expect("serialize instruction box pair");
    bare_pair.extend_from_slice(&[0xAA, 0x55]);
    let framed = norito::core::frame_bare_with_header_flags::<InstructionBox>(
        &bare_pair,
        norito::core::default_encode_flags(),
    )
    .expect("frame tailed instruction pair");
    let archived =
        norito::core::from_bytes::<InstructionBox>(&framed).expect("instruction box frame");
    let decoded: InstructionBox = norito::core::DeserializePayload::deserialize(archived);
    let invalid = decoded
        .as_any()
        .downcast_ref::<transparent::InvalidInstruction>()
        .expect("tailed instruction pair becomes invalid placeholder");
    let expected_hash: [u8; 32] = iroha_crypto::Hash::new(&framed_payload).into();
    assert_eq!(invalid.wire_id, Log::WIRE_ID);
    assert_eq!(invalid.payload_hash, expected_hash);
    assert!(
        invalid.message.contains("canonical Norito framing"),
        "invalid placeholder should explain non-canonical trailing bytes: {}",
        invalid.message
    );
}
#[test]
fn const_vec_instruction_box_rejects_zeroed_varint_element_length() {
    let _guard = RegistryGuard::set(instruction_registry_with_ids![Log]);
    let instruction = InstructionBox::from(Log {
        level: Level::INFO,
        msg: "varint tail regression".to_owned(),
    });
    let original = ConstVec::from(vec![instruction]);
    let framed = norito::core::to_bytes(&original).expect("serialize ConstVec<InstructionBox>");
    let flags = framed[norito::core::Header::SIZE - 1];
    let payload = &framed[norito::core::Header::SIZE..];
    let mut mutated = payload.to_vec();
    let (len, used_hdr) = {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        norito::core::read_seq_len_slice(&mutated).expect("sequence header")
    };
    assert_eq!(len, 1);
    {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        let mut cursor = used_hdr;
        for _ in 0..len {
            let (_, hdr) =
                norito::core::read_len_dyn_slice(&mutated[cursor..]).expect("element header");
            for byte in &mut mutated[cursor..cursor + hdr] {
                *byte = 0;
            }
            cursor += hdr;
        }
    }
    let error = {
        let _guard = norito::core::DecodeFlagsGuard::enter(flags);
        norito::core::decode_field_canonical::<ConstVec<InstructionBox>>(&mutated)
            .expect_err("zeroed element length must not activate a tail-offset fallback")
    };
    norito::core::reset_decode_state();
    assert!(
        matches!(error, norito::core::Error::LengthMismatch),
        "unexpected rejection for zeroed element length: {error:?}"
    );
}
#[test]
fn encode_as_instruction_box_uses_encode() {
    let log = Log {
        level: Level::INFO,
        msg: "encode".to_string(),
    };
    let expected = log.encode();
    let actual = BuiltInInstruction::encode_as_instruction_box(&log);
    assert_eq!(actual, expected);
}
#[test]
fn default_registry_roundtrip_selected_instructions() {
    // Install default registry covering built-ins and keep a local handle
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let local_registry = crate::instruction_registry::default();
    // Build a small suite of representative instructions
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let account_id = AccountId::new(
        "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
            .parse()
            .unwrap(),
    );
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_id = AssetId::of(asset_def_id.clone(), account_id.clone());
    let nft_id: NftId = "n0$wonderland".parse().unwrap();
    let role_id: RoleId = "auditor".parse().unwrap();
    let key: Name = "k".parse().unwrap();
    let cases: Vec<InstructionBox> = vec![
        // Register/Unregister
        Register::domain(Domain::new(domain_id.clone())).into(),
        Unregister::domain(domain_id.clone()).into(),
        // Set/Remove metadata
        SetKeyValue::domain(domain_id.clone(), key.clone(), Json::new(1u32)).into(),
        RemoveKeyValue::domain(domain_id.clone(), key.clone()).into(),
        // Mint/Burn asset
        Mint::asset_quantity(10_u32, asset_id.clone()).into(),
        Burn::asset_quantity(5_u32, asset_id.clone()).into(),
        // Transfer asset
        Transfer::asset_quantity(asset_id.clone(), 1_u32, account_id.clone()).into(),
        // NFT register + transfer
        Register::nft(Nft::new(nft_id.clone(), Metadata::default())).into(),
        Transfer::nft(account_id.clone(), nft_id.clone(), account_id.clone()).into(),
        // Grant/Revoke role
        Grant::account_role(role_id.clone(), account_id.clone()).into(),
        Revoke::account_role(role_id.clone(), account_id.clone()).into(),
        // SetParameter
        SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::MaxInstructions(nonzero_ext::nonzero!(10_u64)),
        ))
        .into(),
        // Log
        Log::new(Level::INFO, "hello".into()).into(),
    ];
    for instr in cases {
        let bytes = norito::to_bytes(&instr).expect("serialize");
        // Decode without relying on the global registry during this window
        let (name, payload) =
            norito::decode_from_bytes::<(String, Vec<u8>)>(&bytes).expect("extract tag + payload");
        let decoded = local_registry
            .decode(&name, &payload)
            .unwrap_or_else(|| panic!("instruction `{name}` is not registered"))
            .expect("decode via default registry");
        assert_eq!(instr, decoded);
    }
}
#[test]
fn revoke_encode_as_instruction_box_uses_encode() {
    let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let signatory = "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
        .parse()
        .unwrap();
    let account_id = AccountId::new(signatory);
    let permission = Permission::new("dummy".parse().unwrap(), Json::new(()));
    let revoke = Revoke::account_permission(permission, account_id);
    let expected = revoke.encode();
    let actual = BuiltInInstruction::encode_as_instruction_box(&revoke);
    assert_eq!(actual, expected);
}
#[test]
fn discriminant_roundtrip() {
    check_enum!(SetKeyValueType {
        Domain,
        Account,
        AssetDefinition,
        Nft,
        Trigger
    });
    check_enum!(RemoveKeyValueType {
        Domain,
        Account,
        AssetDefinition,
        Nft,
        Trigger
    });
    check_enum!(RegisterType {
        Peer,
        Domain,
        Account,
        AssetDefinition,
        Nft,
        Role,
        Trigger
    });
    check_enum!(UnregisterType {
        Peer,
        Domain,
        Account,
        AssetDefinition,
        Nft,
        Role,
        Trigger
    });
    check_enum!(MintType {
        Asset,
        TriggerRepetitions
    });
    check_enum!(BurnType {
        Asset,
        TriggerRepetitions
    });
    check_enum!(TransferType {
        Domain,
        AssetDefinition,
        Asset,
        Nft
    });
    check_enum!(GrantType {
        Permission,
        Role,
        RolePermission
    });
    check_enum!(RevokeType {
        Permission,
        Role,
        RolePermission
    });
}
#[test]
fn ordering_is_preserved_across_roundtrip() {
    // Ensure the total ordering of InstructionBox is stable after Norito roundtrip.
    let _guard = RegistryGuard::set(crate::instruction_registry::default());
    let domain_id: DomainId = DomainId::try_new("alice", "universal").unwrap();
    let account_id = AccountId::new(
        "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245"
            .parse()
            .expect("public key"),
    );
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("alice", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
    let asset_id = AssetId::of(asset_def_id.clone(), account_id.clone());
    let role_id: RoleId = "auditor".parse().unwrap();
    let mut instrs = vec![
        Register::domain(Domain::new(domain_id.clone())).into(),
        Grant::account_role(role_id.clone(), account_id.clone()).into(),
        Mint::asset_quantity(5_u32, asset_id.clone()).into(),
        Transfer::asset_quantity(asset_id.clone(), 1_u32, account_id.clone()).into(),
        Burn::asset_quantity(1_u32, asset_id.clone()).into(),
        Unregister::domain(domain_id.clone()).into(),
        Log::new(Level::INFO, "x".into()).into(),
    ];
    // Sort by Ord
    instrs.sort();
    // Roundtrip each via Norito bytes
    let rt: Vec<InstructionBox> = instrs
        .iter()
        // Explicitly specify the generic type so the compiler knows which
        // `NoritoSerialize` implementation to use for the `InstructionBox`
        // trait object reference.
        .map(|i| norito::to_bytes::<InstructionBox>(i).expect("encode"))
        .map(|b| norito::decode_from_bytes::<InstructionBox>(&b).expect("decode"))
        .collect();
    let mut rt_sorted = rt.clone();
    rt_sorted.sort();
    assert_eq!(instrs, rt_sorted);
}
include!("default_registry_tail_test.rs");
/// SCCP v1 instruction registration (`specs/sccp.md` §4): every instruction boxes, carries its
/// `iroha.instruction.v1::sccp::<Name>` wire id and round-trips through the default registry.
pub mod sccp_instruction_enum {
    use super::RegistryGuard;
    use crate::{
        bridge::SccpNetworkV1,
        isi::{
            Instruction, InstructionBox,
            sccp::{
                AcceptSccpPausePanelSeatV1, AdvanceSccpLightClientV1, EndorseSccpFastPauseV1,
                InitializeSccpV1, ProveSccpForgedMintV1, RecordSccpMessage,
                ReportSccpLightClientEquivocationV1, SettleSccpV1, SubmitSccpForgeryEvidenceV1,
                SubmitSccpInboundMessageV1, SubmitSccpOutboundVoidV1,
            },
        },
        sccp::{
            inbound::SccpSourceProofBytesV1,
            light_client::{SccpLcAdvanceBytesV1, SccpLcEvidenceBytesV1},
            params::SccpParametersV1,
            reconciliation::{SccpForgedMintPayloadV1, SccpForgedMintProofV1},
        },
    };
    use iroha_primitives::numeric::Numeric;

    /// Deterministic populated initialization of the native SCCP instruction family.
    pub fn initialize() -> InitializeSccpV1 {
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        }
    }

    /// Populated outbound record request.
    pub fn record() -> RecordSccpMessage {
        RecordSccpMessage {
            network: SccpNetworkV1::EthereumMainnet,
            expected_revision: 1,
            amount: Numeric::new(1_500_000_000_u64, 9),
            recipient: vec![0x22; 20],
        }
    }

    /// Populated inbound proof submission.
    pub fn submit_inbound() -> SubmitSccpInboundMessageV1 {
        SubmitSccpInboundMessageV1 {
            network: SccpNetworkV1::TonMainnet,
            revision: 2,
            payload: vec![2, 1, 0, 0, 0, 4],
            proof: SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54, 0x30, 0x01])
                .expect("bounded proof"),
        }
    }

    /// Populated settlement retry.
    pub fn settle() -> SettleSccpV1 {
        SettleSccpV1::refund(SccpNetworkV1::BscMainnet, 1, 7)
    }

    /// Populated void proof submission.
    pub fn submit_void() -> SubmitSccpOutboundVoidV1 {
        SubmitSccpOutboundVoidV1 {
            network: SccpNetworkV1::BscMainnet,
            revision: 1,
            proof: SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54, 0x30, 0x02])
                .expect("bounded proof"),
        }
    }

    /// Populated light-client advance.
    pub fn advance() -> AdvanceSccpLightClientV1 {
        AdvanceSccpLightClientV1 {
            network: SccpNetworkV1::EthereumMainnet,
            expected_state_hash: Some([8; 32]),
            advance: SccpLcAdvanceBytesV1::new(vec![1; 64]).expect("bounded advance"),
        }
    }

    /// Populated light-client equivocation report.
    pub fn report_equivocation() -> ReportSccpLightClientEquivocationV1 {
        ReportSccpLightClientEquivocationV1 {
            network: SccpNetworkV1::BscMainnet,
            a: SccpLcEvidenceBytesV1::new(vec![1, 2]).expect("bounded evidence"),
            b: SccpLcEvidenceBytesV1::new(vec![3, 4]).expect("bounded evidence"),
        }
    }

    /// Syntax-only native forgery submission; codec coverage asserts no BLS authority.
    pub fn submit_forgery() -> SubmitSccpForgeryEvidenceV1 {
        SubmitSccpForgeryEvidenceV1 {
            qc: [0xa1; 116],
            header: [0xb2; 221],
            aggregate_signature: [0xc3; 96],
            anchor: Some(crate::sccp::native::SccpAnchorWitnessV1 {
                core_hash: [1; 32],
                result: [0; 32],
                path: [[2; 32]; 12],
            }),
        }
    }

    /// Populated permissionless forged-mint proof with its canonical payload preimage.
    pub fn accept_panel() -> AcceptSccpPausePanelSeatV1 {
        AcceptSccpPausePanelSeatV1 { panel_seq: 7 }
    }

    pub fn endorse_pause() -> EndorseSccpFastPauseV1 {
        EndorseSccpFastPauseV1 {
            network_id: crate::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                crate::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::new([7; 32])
            )),
            network: SccpNetworkV1::EthereumMainnet,
            panel_id: [8; 32],
            head: 9,
            incident_digest: [10; 32],
        }
    }

    pub fn prove_forged_mint() -> ProveSccpForgedMintV1 {
        ProveSccpForgedMintV1 {
            network: SccpNetworkV1::BscMainnet,
            revision: 1,
            proof: SccpForgedMintProofV1 {
                source: SccpSourceProofBytesV1::new(vec![1, 2, 3]).expect("bounded source proof"),
                payload: SccpForgedMintPayloadV1::new(vec![2, 1, 0, 0]).expect("bounded payload"),
            },
        }
    }

    /// Every SCCP v1 instruction with its expected wire id.
    pub fn boxed_samples() -> Vec<(&'static str, InstructionBox)> {
        vec![
            (
                "iroha.instruction.v1::sccp::InitializeSccpV1",
                initialize().into(),
            ),
            (
                "iroha.instruction.v1::sccp::RecordSccpMessage",
                record().into(),
            ),
            (
                "iroha.instruction.v1::sccp::SubmitSccpInboundMessageV1",
                submit_inbound().into(),
            ),
            ("iroha.instruction.v1::sccp::SettleSccpV1", settle().into()),
            (
                "iroha.instruction.v1::sccp::SubmitSccpOutboundVoidV1",
                submit_void().into(),
            ),
            (
                "iroha.instruction.v1::sccp::AdvanceSccpLightClientV1",
                advance().into(),
            ),
            (
                "iroha.instruction.v1::sccp::ReportSccpLightClientEquivocationV1",
                report_equivocation().into(),
            ),
            (
                "iroha.instruction.v1::sccp::SubmitSccpForgeryEvidenceV1",
                submit_forgery().into(),
            ),
            (
                "iroha.instruction.v1::sccp::ProveSccpForgedMintV1",
                prove_forged_mint().into(),
            ),
            (
                "iroha.instruction.v1::sccp::AcceptSccpPausePanelSeatV1",
                accept_panel().into(),
            ),
            (
                "iroha.instruction.v1::sccp::EndorseSccpFastPauseV1",
                endorse_pause().into(),
            ),
        ]
    }

    #[test]
    fn sccp_instructions_use_their_v1_wire_ids() {
        let registry = crate::instruction_registry::default();
        let samples = boxed_samples();
        assert_eq!(samples.len(), 11, "the complete SCCP v1 instruction set");
        for (wire_id, instruction) in &samples {
            let type_name = Instruction::id(&**instruction);
            assert!(
                type_name.starts_with("iroha_data_model::isi::sccp::"),
                "{type_name}"
            );
            assert_eq!(registry.wire_id(type_name), Some(*wire_id), "{type_name}");
            assert!(registry.contains(wire_id), "{wire_id}");
            assert!(
                !registry.contains(type_name),
                "the Rust path is not a decoding key: {type_name}"
            );
            assert!(crate::isi::registry::is_instruction_wire_id_registered(
                wire_id
            ));
        }
    }

    #[test]
    fn sccp_instructions_roundtrip_through_the_default_registry() {
        let _guard = RegistryGuard::set(crate::instruction_registry::default());
        let registry = crate::instruction_registry::default();
        for (wire_id, instruction) in boxed_samples() {
            let bytes = norito::to_bytes(&instruction).expect("serialize instruction box");
            let (name, payload) = norito::decode_from_bytes::<(String, Vec<u8>)>(&bytes)
                .expect("extract wire id and payload");
            assert_eq!(name, wire_id);
            let decoded = registry
                .decode(&name, &payload)
                .unwrap_or_else(|| panic!("`{name}` is not registered"))
                .expect("decode through the default registry");
            assert_eq!(decoded, instruction, "{wire_id}");
            let boxed: InstructionBox =
                norito::decode_from_bytes(&bytes).expect("decode the instruction box");
            assert_eq!(boxed, instruction, "{wire_id}");
        }
    }

    #[test]
    #[ignore = "explicit maintenance command prints the SCCP v1 instruction record fixture rows"]
    fn print_sccp_instruction_record_fixture_rows() {
        use crate::isi::generated_record_identity_tests::capture;
        let rows = [
            capture(initialize()),
            capture(record()),
            capture(submit_inbound()),
            capture(settle()),
            capture(submit_void()),
            capture(advance()),
            capture(report_equivocation()),
            capture(submit_forgery()),
            capture(prove_forged_mint()),
            capture(accept_panel()),
            capture(endorse_pause()),
            capture(crate::isi::chain::Keepalive {}),
        ];
        for row in rows {
            println!(
                "SCCP_RECORD_FIXTURE_ROW={}",
                norito::json::to_json(&row).expect("SCCP record fixture row")
            );
        }
    }

    #[test]
    fn sccp_instructions_downcast_from_their_boxes() {
        let samples = boxed_samples();
        assert!(
            samples[0]
                .1
                .as_any()
                .downcast_ref::<InitializeSccpV1>()
                .is_some()
        );
        assert_eq!(
            samples[1].1.as_any().downcast_ref::<RecordSccpMessage>(),
            Some(&record())
        );
        assert_eq!(
            samples[3].1.as_any().downcast_ref::<SettleSccpV1>(),
            Some(&settle())
        );
    }

    #[test]
    fn chain_keepalive_has_one_wire_identity_and_roundtrips_without_payload() {
        let _guard = RegistryGuard::set(crate::instruction_registry::default());
        let registry = crate::instruction_registry::default();
        let value: InstructionBox = crate::isi::chain::Keepalive {}.into();
        assert_eq!(
            registry.wire_id(Instruction::id(&*value)),
            Some("iroha.chain.keepalive.v1")
        );
        let frame = norito::to_bytes(&value).expect("frame");
        assert_eq!(
            norito::decode_from_bytes::<InstructionBox>(&frame).expect("decode"),
            value
        );
        assert!(
            value
                .as_any()
                .downcast_ref::<crate::isi::chain::Keepalive>()
                .is_some()
        );
        for wrong in [
            "iroha.instruction.v1::chain::Keepalive",
            "iroha.chain.keepalive.v2",
            "iroha_data_model::isi::chain::Keepalive",
        ] {
            assert!(!registry.contains(wrong));
            assert!(registry.decode(wrong, &[]).is_none());
        }
    }

    #[test]
    fn retired_sccp_wire_ids_are_unregistered() {
        let _guard = RegistryGuard::set(crate::instruction_registry::default());
        let registry = crate::instruction_registry::default();
        for name in [
            "SetSccpBridgeKeyV1",
            "SubmitSccpAttestationsV1",
            "SubmitSccpAttestationFaultV1",
        ] {
            let wire_id = format!("iroha.instruction.v1::sccp::{name}");
            assert!(!registry.contains(&wire_id), "{wire_id}");
            assert!(
                !crate::isi::registry::is_instruction_wire_id_registered(&wire_id),
                "{wire_id}"
            );
            assert!(registry.decode(&wire_id, &[]).is_none(), "{wire_id}");
            let type_name = format!("iroha_data_model::isi::sccp::{name}");
            assert_eq!(registry.wire_id(&type_name), None, "{type_name}");
            // A boxed instruction frame that names the retired wire id does not decode.
            let frame = norito::to_bytes(&(wire_id.clone(), vec![0_u8; 64]))
                .expect("serialize a retired instruction frame");
            assert!(
                norito::decode_from_bytes::<InstructionBox>(&frame).is_err(),
                "{wire_id}"
            );
        }
        let sccp_wire_ids: Vec<&str> = boxed_samples()
            .iter()
            .map(|(wire_id, _)| *wire_id)
            .collect();
        assert_eq!(
            sccp_wire_ids,
            [
                "iroha.instruction.v1::sccp::InitializeSccpV1",
                "iroha.instruction.v1::sccp::RecordSccpMessage",
                "iroha.instruction.v1::sccp::SubmitSccpInboundMessageV1",
                "iroha.instruction.v1::sccp::SettleSccpV1",
                "iroha.instruction.v1::sccp::SubmitSccpOutboundVoidV1",
                "iroha.instruction.v1::sccp::AdvanceSccpLightClientV1",
                "iroha.instruction.v1::sccp::ReportSccpLightClientEquivocationV1",
                "iroha.instruction.v1::sccp::SubmitSccpForgeryEvidenceV1",
                "iroha.instruction.v1::sccp::ProveSccpForgedMintV1",
                "iroha.instruction.v1::sccp::AcceptSccpPausePanelSeatV1",
                "iroha.instruction.v1::sccp::EndorseSccpFastPauseV1",
            ]
        );
    }
}
