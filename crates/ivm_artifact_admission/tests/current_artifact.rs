//! Exact-current positive and forbidden-syscall admission vectors.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_crypto::Hash;
use iroha_data_model::prelude::{
    DecimalValueV1, IntValueV1, NUMERIC_FRAME_HEADER_BYTES_V1, NumericAbiError, QuantityValueV1,
};
use ivm_abi::{
    SyscallPolicy,
    metadata::{
        EmbeddedContractInterfaceV1, LiteralKindV1, ProgramMetadata, decode_literal_descriptor,
    },
    pointer_abi::{PointerType, validate_tlv_bytes},
};
use ivm_artifact_admission::verify_contract_artifact;
use std::ops::Range;
const CURRENT_FIXTURE: &str =
    include_str!("../../../javascript/iroha_js/test/fixtures/current_rust_contract_artifact.json");
const INTEGER_FIXTURE: &[u8] =
    include_bytes!("../../kotodama_lang/src/samples/tuple_return_demo.to");
const DECIMAL_FIXTURE: &[u8] = include_bytes!("../../../demo/irohaswap.to");
const QUANTITY_FIXTURE: &[u8] = include_bytes!("../../../demo/prediction_market.to");
const STRUCTURED_FIXTURE: &[u8] = include_bytes!("../../ivm/docs/examples/12_nft_flow.to");
const ASSET_DEFINITION_FIXTURE: &[u8] =
    include_bytes!("../../ivm/docs/examples/13_register_and_mint.to");
const DOMAIN_FIXTURE: &[u8] = include_bytes!("../../ivm/docs/examples/16_register_domain.to");
const NUMERIC_FRAME_CHECKSUM_OFFSET: usize = 31;
const POINTER_ENVELOPE_HEADER_BYTES: usize = 7;
const SEMANTIC_LITERAL_ERROR: &str =
    "invalid contract artifact: literal index validation failed: invalid program metadata";
struct CurrentFixture {
    artifact: Vec<u8>,
    code_hash_hex: String,
    abi_hash_hex: String,
    header_len: usize,
    code_offset: usize,
    entrypoint_count: usize,
}
fn current_fixture() -> CurrentFixture {
    let fixture = norito::json::from_str::<norito::json::Value>(CURRENT_FIXTURE)
        .expect("parse exact-current fixture metadata");
    let fixture = fixture
        .as_object()
        .expect("exact-current fixture metadata must be an object");
    let encoded = fixture
        .get("artifact_base64")
        .and_then(norito::json::Value::as_str)
        .expect("fixture carries artifact_base64");
    let semantics = fixture
        .get("artifact_semantics")
        .and_then(norito::json::Value::as_object)
        .expect("fixture carries artifact_semantics");
    let string_field = |name| {
        semantics
            .get(name)
            .and_then(norito::json::Value::as_str)
            .unwrap_or_else(|| panic!("artifact_semantics carries string {name}"))
            .to_owned()
    };
    let usize_field = |name| {
        semantics
            .get(name)
            .and_then(norito::json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or_else(|| panic!("artifact_semantics carries usize {name}"))
    };
    CurrentFixture {
        artifact: STANDARD.decode(encoded).expect("decode fixture artifact"),
        code_hash_hex: string_field("code_hash_hex"),
        abi_hash_hex: string_field("abi_hash_hex"),
        header_len: usize_field("header_len"),
        code_offset: usize_field("code_offset"),
        entrypoint_count: usize_field("entrypoint_count"),
    }
}

fn rewrite_interface(
    artifact: &[u8],
    mutate: impl FnOnce(&mut EmbeddedContractInterfaceV1),
) -> Vec<u8> {
    let parsed = ProgramMetadata::parse(artifact).expect("parse contract fixture metadata");
    let section_start = parsed.header_len;
    assert_eq!(
        artifact.get(section_start..section_start + 4),
        Some(b"CNTR".as_slice()),
        "contract fixture starts with its required CNTR section"
    );
    let payload_len = usize::try_from(u32::from_le_bytes(
        artifact[section_start + 4..section_start + 8]
            .try_into()
            .expect("CNTR payload length is four bytes"),
    ))
    .expect("u32 CNTR payload length fits usize");
    let section_end = section_start + 8 + payload_len;
    let mut interface = parsed
        .contract_interface
        .expect("contract fixture carries CNTR");
    mutate(&mut interface);
    let replacement = interface.encode_section();
    let mut rewritten =
        Vec::with_capacity(artifact.len() - (section_end - section_start) + replacement.len());
    rewritten.extend_from_slice(&artifact[..section_start]);
    rewritten.extend_from_slice(&replacement);
    if let Some(section) = parsed.literal_section {
        assert_eq!(section.start, section_end, "LTLB directly follows CNTR");
        let literal_start = rewritten.len();
        rewritten.extend_from_slice(&artifact[section.start..section.data_end]);
        let padding = (4 - (rewritten.len() - parsed.header_len) % 4) % 4;
        rewritten[literal_start + 8..literal_start + 12].copy_from_slice(
            &u32::try_from(padding)
                .expect("literal padding is below four bytes")
                .to_le_bytes(),
        );
        rewritten.resize(rewritten.len() + padding, 0);
    } else {
        assert_eq!(
            section_end, parsed.code_offset,
            "code directly follows CNTR"
        );
    }
    rewritten.extend_from_slice(&artifact[parsed.code_offset..]);
    rewritten
}

fn numeric_fixtures() -> [(&'static str, &'static [u8], PointerType); 3] {
    [
        ("int", INTEGER_FIXTURE, PointerType::Int),
        ("decimal", DECIMAL_FIXTURE, PointerType::Decimal),
        ("quantity", QUANTITY_FIXTURE, PointerType::Quantity),
    ]
}
fn pointer_literal_range(artifact: &[u8], expected_type: PointerType) -> Range<usize> {
    let parsed = ProgramMetadata::parse(artifact).expect("parse numeric contract fixture");
    let section = parsed
        .literal_section
        .expect("numeric contract fixture carries LTLB");
    let descriptors = (0..section.count)
        .map(|index| {
            let entry_start = section.entries_start + index * 8;
            let raw = u64::from_le_bytes(
                artifact[entry_start..entry_start + 8]
                    .try_into()
                    .expect("literal descriptor is eight bytes"),
            );
            let (kind, relative) =
                decode_literal_descriptor(raw).expect("decode literal descriptor");
            let target = section.start
                + usize::try_from(relative).expect("fixture literal offset fits usize");
            (kind, target)
        })
        .collect::<Vec<_>>();
    descriptors
        .iter()
        .enumerate()
        .find_map(|(index, (kind, start))| {
            if *kind != LiteralKindV1::PointerTlv {
                return None;
            }
            let end = descriptors
                .get(index + 1)
                .map_or(section.data_end, |(_, target)| *target);
            let tlv = validate_tlv_bytes(&artifact[*start..end])
                .expect("generated pointer literal has a valid outer envelope");
            (tlv.type_id == expected_type).then_some(*start..end)
        })
        .unwrap_or_else(|| panic!("fixture carries a {expected_type:?} literal"))
}
fn pointer_payload_range(artifact: &[u8], envelope: &Range<usize>) -> Range<usize> {
    let payload_len = usize::try_from(u32::from_be_bytes(
        artifact[envelope.start + 3..envelope.start + POINTER_ENVELOPE_HEADER_BYTES]
            .try_into()
            .expect("pointer envelope length is four bytes"),
    ))
    .expect("u32 payload length fits usize");
    let start = envelope.start + POINTER_ENVELOPE_HEADER_BYTES;
    let end = start + payload_len;
    assert_eq!(
        end + Hash::LENGTH,
        envelope.end,
        "pointer envelope must contain exactly one payload and hash"
    );
    start..end
}
fn reseal_pointer_hash(artifact: &mut [u8], envelope: &Range<usize>) {
    let payload = pointer_payload_range(artifact, envelope);
    let digest = Hash::new(&artifact[payload.clone()]);
    artifact[payload.end..envelope.end].copy_from_slice(digest.as_ref());
}
fn reseal_numeric_checksum_and_pointer_hash(artifact: &mut [u8], envelope: &Range<usize>) {
    let payload = pointer_payload_range(artifact, envelope);
    let checksum = norito::core::hardware_crc64(
        &artifact[payload.start + NUMERIC_FRAME_HEADER_BYTES_V1..payload.end],
    );
    artifact[payload.start + NUMERIC_FRAME_CHECKSUM_OFFSET
        ..payload.start + NUMERIC_FRAME_CHECKSUM_OFFSET + 8]
        .copy_from_slice(&checksum.to_le_bytes());
    reseal_pointer_hash(artifact, envelope);
}
fn decode_numeric_payload(
    artifact: &[u8],
    envelope: &Range<usize>,
    pointer_type: PointerType,
) -> Result<(), NumericAbiError> {
    let payload = pointer_payload_range(artifact, envelope);
    match pointer_type {
        PointerType::Int => IntValueV1::decode_frame(&artifact[payload]).map(|_| ()),
        PointerType::Decimal => DecimalValueV1::decode_frame(&artifact[payload]).map(|_| ()),
        PointerType::Quantity => QuantityValueV1::decode_frame(&artifact[payload]).map(|_| ()),
        other => panic!("expected numeric pointer type, got {other:?}"),
    }
}
fn assert_outer_envelope_valid(
    artifact: &[u8],
    envelope: &Range<usize>,
    pointer_type: PointerType,
) {
    let tlv = validate_tlv_bytes(&artifact[envelope.clone()])
        .expect("outer pointer envelope remains hash-valid");
    assert_eq!(tlv.type_id, pointer_type);
}
fn assert_shared_admission_rejects_semantic_literal(
    artifact: &[u8],
    envelope: &Range<usize>,
    pointer_type: PointerType,
) {
    assert_outer_envelope_valid(artifact, envelope, pointer_type);
    let error = verify_contract_artifact(artifact)
        .expect_err("semantically malformed numeric literal must fail shared admission");
    assert_eq!(error.to_string(), SEMANTIC_LITERAL_ERROR);
}
#[test]
fn exact_current_compiler_artifact_is_admitted() {
    let fixture = current_fixture();
    let verified = verify_contract_artifact(&fixture.artifact)
        .expect("exact-current compiler artifact must satisfy shared admission");
    assert_eq!(verified.header_len, fixture.header_len);
    assert_eq!(verified.code_offset, fixture.code_offset);
    assert_eq!(
        verified.contract_interface.entrypoints.len(),
        fixture.entrypoint_count
    );
    assert_eq!(
        hex::encode(verified.code_hash.as_ref()),
        fixture.code_hash_hex
    );
    assert_eq!(
        hex::encode(verified.abi_hash.as_ref()),
        fixture.abi_hash_hex
    );
}
#[test]
fn foreign_vm_modules_cannot_enter_native_ivm_admission() {
    let minimal_foreign_module = b"\0asm\x01\0\0\0";
    let mut substituted = current_fixture().artifact;
    substituted[..4].copy_from_slice(&minimal_foreign_module[..4]);
    for artifact in [minimal_foreign_module.as_slice(), substituted.as_slice()] {
        let error = verify_contract_artifact(artifact)
            .expect_err("only canonical IVM artifacts may enter contract admission");
        assert_eq!(error.into_vm_error(), ivm_abi::VMError::InvalidMetadata);
    }
}

#[test]
fn host_private_system_syscall_is_rejected() {
    let fixture = current_fixture();
    let mut mutated = fixture.artifact;
    // Canonical wide SYSTEM encoding for host-private syscall 0x00fe0000.
    mutated[fixture.code_offset..fixture.code_offset + 4]
        .copy_from_slice(&[0x00, 0x00, 0xfe, 0x62]);
    let error = verify_contract_artifact(&mutated)
        .expect_err("host-private SYSTEM syscall must fail shared admission");
    assert!(error.to_string().contains("disallowed syscall 0xfe0000"));
}

#[test]
fn stale_header_and_cntr_abi_hashes_are_rejected() {
    let fixture = current_fixture();
    let mut stale_header = fixture.artifact.clone();
    stale_header[17] ^= 0x80;
    let stale_cntr = rewrite_interface(&fixture.artifact, |interface| {
        interface.abi_hash[0] ^= 0x80;
    });
    for (location, artifact) in [("header", stale_header), ("CNTR", stale_cntr)] {
        let error = verify_contract_artifact(&artifact)
            .err()
            .unwrap_or_else(|| panic!("stale {location} ABI hash must fail shared admission"));
        assert_eq!(
            error.to_string(),
            "invalid contract artifact: contract interface abi_hash does not match the runtime ABI descriptor",
            "unexpected stale-{location} error"
        );
    }
}

#[test]
fn every_public_entrypoint_requires_an_explicit_unit_return_descriptor() {
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source("seiyaku UnitBoundary { view fn inspect() authorize(anyone) { () } }")
        .expect("compile implicit Unit source return");
    verify_contract_artifact(&artifact).expect("explicit Unit descriptor is admitted");
    for (remove_type, remove_schema) in [(true, false), (false, true), (true, true)] {
        let mutated = rewrite_interface(&artifact, |interface| {
            let entrypoint = interface
                .entrypoints
                .iter_mut()
                .find(|entrypoint| entrypoint.name == "inspect")
                .expect("inspect descriptor");
            assert_eq!(entrypoint.return_type.as_deref(), Some("()"));
            assert_eq!(
                entrypoint.return_schema.as_ref().unwrap().nodes,
                vec![ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Unit]
            );
            if remove_type {
                entrypoint.return_type = None;
            }
            if remove_schema {
                entrypoint.return_schema = None;
            }
        });
        let error =
            verify_contract_artifact(&mutated).expect_err("missing return descriptor is invalid");
        assert!(
            error.to_string().contains("missing its exact return"),
            "{error}"
        );
    }
}

#[test]
fn cntr_return_type_schema_mismatch_is_rejected() {
    let source = r"
        seiyaku SchemaBound {
            view fn inspect() authorize(anyone) -> int { return 1; }
        }
    ";
    let (artifact, _) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile schema-bound contract");
    let mutated = rewrite_interface(&artifact, |interface| {
        let inspect = interface
            .entrypoints
            .iter_mut()
            .find(|entrypoint| entrypoint.name == "inspect")
            .expect("schema-bound fixture carries inspect entrypoint");
        assert_eq!(inspect.return_type.as_deref(), Some("int"));
        assert!(inspect.return_schema.is_some());
        inspect.return_type = Some("Foo".to_owned());
    });
    let error = verify_contract_artifact(&mutated)
        .expect_err("CNTR return type/schema mismatch must fail shared admission");
    assert!(
        error
            .to_string()
            .contains("entrypoint `inspect` has a return schema that does not match"),
        "unexpected CNTR/schema error: {error}"
    );
}

#[test]
fn unassigned_exact_json_getter_syscalls_are_rejected() {
    let fixture = current_fixture();
    for number in 0x01_0163..=0x01_0165 {
        assert!(
            !ivm_abi::syscalls::is_syscall_allowed(SyscallPolicy::AbiV1, number),
            "reserved exact-number gap {number:#08x} must stay outside ABI V1"
        );
        let mut mutated = fixture.artifact.clone();
        mutated[fixture.code_offset..fixture.code_offset + 4]
            .copy_from_slice(&ivm_abi::encoding::wide::encode_syscallx(number).to_le_bytes());
        let error = verify_contract_artifact(&mutated)
            .expect_err("reserved exact-number syscall must fail shared admission");
        assert!(
            error
                .to_string()
                .contains(&format!("disallowed syscall {number:#08x}")),
            "unexpected reserved-syscall error for {number:#08x}: {error}"
        );
    }
}

#[test]
fn malformed_numeric_pointer_envelopes_are_rejected() {
    type EnvelopeMutation = fn(&mut [u8], &Range<usize>);
    for (name, fixture, pointer_type) in numeric_fixtures() {
        let envelope = pointer_literal_range(fixture, pointer_type);
        let mutations: [(&str, EnvelopeMutation); 4] = [
            ("type", |bytes: &mut [u8], range: &Range<usize>| {
                bytes[range.start..range.start + 2].copy_from_slice(&u16::MAX.to_be_bytes());
            }),
            ("version", |bytes, range| bytes[range.start + 2] = 2),
            ("length", |bytes, range| {
                let offset = range.start + 3;
                let length = u32::from_be_bytes(
                    bytes[offset..offset + 4]
                        .try_into()
                        .expect("pointer length is four bytes"),
                );
                bytes[offset..offset + 4].copy_from_slice(&length.saturating_add(1).to_be_bytes());
            }),
            ("hash", |bytes, range| bytes[range.end - 1] ^= 0x01),
        ];
        for (fault, mutate) in mutations {
            let mut mutated = fixture.to_vec();
            mutate(&mut mutated, &envelope);
            assert!(
                validate_tlv_bytes(&mutated[envelope.clone()]).is_err(),
                "{name} {fault} mutation must invalidate its outer envelope"
            );
            let error = verify_contract_artifact(&mutated).err().unwrap_or_else(|| {
                panic!("malformed {name} {fault} envelope must fail shared admission")
            });
            assert_eq!(error.to_string(), SEMANTIC_LITERAL_ERROR);
        }
    }
}

#[test]
fn canonical_durable_numeric_state_is_admitted() {
    let source = r#"
        seiyaku DurableNumericState { permission WriteState;
            state int Whole;
            state decimal Rate;
            state quantity Supply;

            hajimari() {
                let int zero_whole = 0;
                let decimal zero_rate = 0;
                let quantity zero_supply = 0;
                Whole = zero_whole;
                Rate = zero_rate;
                Supply = zero_supply;
            }

            kotoage fn store() authorize(WriteState) -> int {
                Whole = 1606938044258990275541962092341162602522202993782792835301376;
                Rate = -12345678901234567890.125;
                Supply = 12345678901234567890.0000000000000000000000000001;
                return 1;
            }
        }
    "#;
    let (artifact, _) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile exact durable numeric-state artifact");
    let verified = verify_contract_artifact(&artifact)
        .expect("canonical exact durable numeric state must pass shared admission");
    let states = verified
        .manifest
        .states
        .expect("compiler artifact exposes durable state descriptors");
    let state_types = states
        .iter()
        .map(|state| (state.name.as_str(), state.type_name.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        state_types,
        [
            ("Whole", "int"),
            ("Rate", "decimal"),
            ("Supply", "quantity")
        ]
    );
}

#[test]
fn hash_valid_numeric_literals_with_inner_checksum_faults_are_rejected() {
    for (name, fixture, pointer_type) in numeric_fixtures() {
        verify_contract_artifact(fixture)
            .unwrap_or_else(|error| panic!("canonical {name} fixture must be admitted: {error}"));
        let mut mutated = fixture.to_vec();
        let envelope = pointer_literal_range(&mutated, pointer_type);
        let payload = pointer_payload_range(&mutated, &envelope);
        mutated[payload.start + NUMERIC_FRAME_CHECKSUM_OFFSET] ^= 0x01;
        reseal_pointer_hash(&mut mutated, &envelope);
        assert!(
            matches!(
                decode_numeric_payload(&mutated, &envelope, pointer_type),
                Err(NumericAbiError::Norito(_))
            ),
            "{name} decoder must observe the inner checksum fault"
        );
        assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, pointer_type);
    }
}
#[test]
fn hash_valid_numeric_literals_with_wrong_schemas_are_rejected() {
    for (name, fixture, pointer_type) in numeric_fixtures() {
        let mut mutated = fixture.to_vec();
        let envelope = pointer_literal_range(&mutated, pointer_type);
        let payload = pointer_payload_range(&mutated, &envelope);
        mutated[payload.start + 6] ^= 0x01;
        reseal_pointer_hash(&mut mutated, &envelope);
        assert_eq!(
            decode_numeric_payload(&mutated, &envelope, pointer_type),
            Err(NumericAbiError::SchemaMismatch),
            "{name} decoder must observe the nominal schema fault"
        );
        assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, pointer_type);
    }
}
#[test]
fn hash_valid_structured_literals_with_wrong_schemas_are_rejected() {
    for (name, fixture, pointer_type) in [
        ("account", STRUCTURED_FIXTURE, PointerType::AccountId),
        ("nft", STRUCTURED_FIXTURE, PointerType::NftId),
        ("name", STRUCTURED_FIXTURE, PointerType::Name),
        ("json", STRUCTURED_FIXTURE, PointerType::Json),
        (
            "asset definition",
            ASSET_DEFINITION_FIXTURE,
            PointerType::AssetDefinitionId,
        ),
        ("domain", DOMAIN_FIXTURE, PointerType::DomainId),
    ] {
        verify_contract_artifact(fixture)
            .unwrap_or_else(|error| panic!("canonical {name} fixture must be admitted: {error}"));
        let mut mutated = fixture.to_vec();
        let envelope = pointer_literal_range(&mutated, pointer_type);
        let payload = pointer_payload_range(&mutated, &envelope);
        assert!(
            payload.len() > 6,
            "{name} canonical Norito frame carries its schema field"
        );
        mutated[payload.start + 6] ^= 0x01;
        reseal_pointer_hash(&mut mutated, &envelope);
        assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, pointer_type);
    }
}
#[test]
fn hash_valid_noncanonical_integer_literal_is_rejected() {
    let mut mutated = INTEGER_FIXTURE.to_vec();
    let envelope = pointer_literal_range(&mutated, PointerType::Int);
    let payload = pointer_payload_range(&mutated, &envelope);
    let body_start = payload.start + NUMERIC_FRAME_HEADER_BYTES_V1;
    assert_eq!(
        u32::from_le_bytes(
            mutated[body_start..body_start + 4]
                .try_into()
                .expect("integer mantissa length")
        ),
        1
    );
    mutated[body_start + 4] = 0;
    reseal_numeric_checksum_and_pointer_hash(&mut mutated, &envelope);
    assert_eq!(
        decode_numeric_payload(&mutated, &envelope, PointerType::Int),
        Err(NumericAbiError::NonCanonicalMantissa)
    );
    assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, PointerType::Int);
}
#[test]
fn hash_valid_noncanonical_decimal_literal_is_rejected() {
    verify_contract_artifact(DECIMAL_FIXTURE).expect("canonical decimal fixture must be admitted");
    let mut mutated = DECIMAL_FIXTURE.to_vec();
    let envelope = pointer_literal_range(&mutated, PointerType::Decimal);
    let payload = pointer_payload_range(&mutated, &envelope);
    let body_start = payload.start + NUMERIC_FRAME_HEADER_BYTES_V1;
    assert_eq!(
        u32::from_le_bytes(
            mutated[body_start..body_start + 4]
                .try_into()
                .expect("decimal mantissa length")
        ),
        1
    );
    // Ten at scale one must normalize to one at scale zero. Preserve the
    // current one-byte mantissa and complete literal geometry while mutating it.
    mutated[body_start + 4] = 10;
    mutated[body_start + 5] = 1;
    reseal_numeric_checksum_and_pointer_hash(&mut mutated, &envelope);
    assert_eq!(
        decode_numeric_payload(&mutated, &envelope, PointerType::Decimal),
        Err(NumericAbiError::NonCanonicalDecimal)
    );
    assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, PointerType::Decimal);
}
#[test]
fn hash_valid_negative_quantity_literal_is_rejected() {
    let mut mutated = QUANTITY_FIXTURE.to_vec();
    let envelope = pointer_literal_range(&mutated, PointerType::Quantity);
    let payload = pointer_payload_range(&mutated, &envelope);
    let body_start = payload.start + NUMERIC_FRAME_HEADER_BYTES_V1;
    assert_eq!(
        u32::from_le_bytes(
            mutated[body_start..body_start + 4]
                .try_into()
                .expect("quantity mantissa length")
        ),
        1
    );
    mutated[body_start + 4] = 0xff;
    mutated[body_start + 5] = 0;
    reseal_numeric_checksum_and_pointer_hash(&mut mutated, &envelope);
    assert_eq!(
        decode_numeric_payload(&mutated, &envelope, PointerType::Quantity),
        Err(NumericAbiError::NegativeQuantity)
    );
    assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, PointerType::Quantity);
}
#[test]
fn hash_valid_noncanonical_quantity_literal_is_rejected() {
    let mut mutated = QUANTITY_FIXTURE.to_vec();
    let envelope = pointer_literal_range(&mutated, PointerType::Quantity);
    let payload = pointer_payload_range(&mutated, &envelope);
    let body_start = payload.start + NUMERIC_FRAME_HEADER_BYTES_V1;
    mutated[body_start + 4] = 10;
    mutated[body_start + 5] = 1;
    reseal_numeric_checksum_and_pointer_hash(&mut mutated, &envelope);
    assert_eq!(
        decode_numeric_payload(&mutated, &envelope, PointerType::Quantity),
        Err(NumericAbiError::NonCanonicalDecimal)
    );
    assert_shared_admission_rejects_semantic_literal(&mutated, &envelope, PointerType::Quantity);
}
