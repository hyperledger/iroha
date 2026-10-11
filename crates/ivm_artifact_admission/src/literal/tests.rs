//! Canonical literal errors remain local only for original enclosing refusals.

use super::*;
use ivm_abi::{
    error::ExecutionDeferral,
    metadata::{LITERAL_SECTION_MAGIC, ProgramMetadata},
    pointer_abi::PointerType,
};
use norito::core::{DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError};

fn limit(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn program(ty: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut bytes = ProgramMetadata::default().encode();
    bytes.extend_from_slice(&section(ty, payload, 0));
    bytes
}

fn section(ty: PointerType, payload: &[u8], preceding_prefix: usize) -> Vec<u8> {
    let mut envelope = (ty as u16).to_be_bytes().to_vec();
    envelope.push(1);
    envelope.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("fixture value fits u32")
            .to_be_bytes(),
    );
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(iroha_crypto::Hash::new(payload).as_ref());
    let padding = (4 - (preceding_prefix + 24 + envelope.len()) % 4) % 4;
    let mut bytes = LITERAL_SECTION_MAGIC.to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(padding)
            .expect("fixture value fits u32")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u32::try_from(envelope.len())
            .expect("fixture value fits u32")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&24_u64.to_le_bytes());
    bytes.extend_from_slice(&envelope);
    bytes.extend(std::iter::repeat_n(0, padding));
    bytes
}

#[test]
fn canonical_json_literals_preserve_each_actual_cumulative_refusal_and_retry() {
    let value = Json::from_str_norito(r#"{"literal":[1,2,"value"]}"#).unwrap();
    let payload = norito::encode_canonical(&value).unwrap();
    let program = program(PointerType::Json, &payload);
    let parsed = ProgramMetadata::parse(&program).unwrap();
    let protocol = ivm_abi::codec::canonical_norito_decode_limits(payload.len());
    let mut allowance = 0;
    let mut refusals = 0;
    loop {
        let result = norito::with_decode_limits_scope(limit(allowance), || {
            norito::decode_canonical_for_admission::<Json>(&payload, protocol)
        });
        match result {
            Ok(decoded) => {
                assert_eq!(decoded, value);
                break;
            }
            Err(error) => {
                refusals += 1;
                assert_eq!(error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
                let outcome = norito::with_decode_limits_scope(limit(allowance), || {
                    validate_literal_table(&program, &parsed, &[])
                })
                .unwrap_err();
                assert_eq!(
                    outcome.local_vm_error(),
                    Some(VMError::ExecutionDeferred(
                        ExecutionDeferral::ActiveMemoryCapacity
                    ))
                );
                let Some(DecodeResourceError::TotalAllocationExceeded { attempted, .. }) =
                    error.into_error().decode_resource_error()
                else {
                    panic!("original cumulative refusal");
                };
                let next = usize::try_from(attempted).unwrap();
                assert!(next > allowance && next < 1_048_576);
                allowance = next;
            }
        }
    }
    assert!(refusals > 1);
    validate_literal_table(&program, &parsed, &[]).unwrap();
}

#[test]
fn malformed_literal_frames_and_opcode_kinds_remain_deterministic() {
    let bad_frame = [0xff; 16];
    let program = program(PointerType::Name, &bad_frame);
    let parsed = ProgramMetadata::parse(&program).unwrap();
    for allowance in [0, usize::MAX] {
        let error = norito::with_decode_limits_scope(limit(allowance), || {
            validate_literal_table(&program, &parsed, &[])
        })
        .unwrap_err();
        assert_eq!(error.local_vm_error(), None);
        assert_eq!(error.into_vm_error(), VMError::InvalidMetadata);
    }
    let program = self::program(PointerType::Blob, b"opaque");
    let parsed = ProgramMetadata::parse(&program).unwrap();
    for (opcode, index) in [
        (ivm_abi::instruction::wide::memory::LDI64, 0),
        (ivm_abi::instruction::wide::memory::LDLIT, 1),
    ] {
        let decoded = [DecodedOp {
            pc: 0,
            inst: ivm_abi::encoding::wide::encode_literal(opcode, 5, index),
        }];
        assert_eq!(
            validate_literal_table(&program, &parsed, &decoded)
                .unwrap_err()
                .into_vm_error(),
            VMError::InvalidMetadata
        );
    }
}

#[test]
fn actual_artifact_admission_keeps_literal_refusal_after_metadata_succeeds() {
    let mut artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku LiteralAdmission { view fn main() authorize(anyone) -> bool { true } }",
        )
        .unwrap();
    let original = ProgramMetadata::parse(&artifact).unwrap();
    let value = Json::from_str_norito(r#"{"payload":["first","second"]}"#).unwrap();
    let payload = norito::encode_canonical(&value).unwrap();
    let old = original
        .literal_section
        .expect("compiled literal directory");
    let previous = LiteralDirectory::validate(
        &artifact,
        original.header_len,
        Some(old),
        SyscallPolicy::AbiV1,
    )
    .unwrap();
    let old_values = previous
        .iter()
        .map(|value| match value {
            ValidatedLiteral::Pointer { address, .. } => (false, address),
            ValidatedLiteral::I64(value) => (true, value),
        })
        .collect::<Vec<_>>();
    // Appending one descriptor moves all old payloads forward by eight bytes.
    // Existing instruction indexes keep their original order and scalar bits.
    let added = section(PointerType::Json, &payload, 0);
    let added_len = u32::from_le_bytes(added[12..16].try_into().unwrap()) as usize;
    let old_data_len = old.data_end - old.data_start;
    let data_len = old_data_len + added_len;
    let count = old.count + 1;
    let padding = (4 - (old.start - original.header_len + 16 + 8 * count + data_len) % 4) % 4;
    let mut replacement = LITERAL_SECTION_MAGIC.to_vec();
    replacement.extend_from_slice(
        &u32::try_from(count)
            .expect("fixture value fits u32")
            .to_le_bytes(),
    );
    replacement.extend_from_slice(
        &u32::try_from(padding)
            .expect("fixture value fits u32")
            .to_le_bytes(),
    );
    replacement.extend_from_slice(
        &u32::try_from(data_len)
            .expect("fixture value fits u32")
            .to_le_bytes(),
    );
    for raw in artifact[old.entries_start..old.data_start].chunks_exact(8) {
        let (kind, offset) = ivm_abi::metadata::decode_literal_descriptor(u64::from_le_bytes(
            raw.try_into().unwrap(),
        ))
        .unwrap();
        replacement.extend_from_slice(
            &ivm_abi::metadata::encode_literal_descriptor(kind, offset + 8)
                .unwrap()
                .to_le_bytes(),
        );
    }
    replacement.extend_from_slice(&((old.data_end - old.start + 8) as u64).to_le_bytes());
    replacement.extend_from_slice(&artifact[old.data_start..old.data_end]);
    replacement.extend_from_slice(&added[24..24 + added_len]);
    replacement.extend(std::iter::repeat_n(0, padding));
    let old_instructions = artifact[original.code_offset..].to_vec();
    artifact.splice(old.start..old.code_offset, replacement);
    let updated = ProgramMetadata::parse(&artifact).unwrap();
    assert_eq!(&artifact[updated.code_offset..], old_instructions);
    let directory = LiteralDirectory::validate(
        &artifact,
        updated.header_len,
        updated.literal_section,
        SyscallPolicy::AbiV1,
    )
    .unwrap();
    assert_eq!(directory.len(), old_values.len() + 1);
    for (index, (scalar, value)) in old_values.into_iter().enumerate() {
        assert!(match directory.get(index).unwrap() {
            ValidatedLiteral::I64(actual) => scalar && actual == value,
            ValidatedLiteral::Pointer { address, .. } => !scalar && address == value + 8,
        });
    }
    let baseline = crate::verify_contract_artifact(&artifact).unwrap();
    let protocol = limit(usize::MAX);
    let (parsed, usage) =
        norito::core::with_decode_limits_measured(protocol, || ProgramMetadata::parse(&artifact));
    parsed.unwrap();
    let metadata_bytes = usage.total_allocated_bytes();
    assert!(metadata_bytes > 0);
    let refused = norito::with_decode_limits_scope(limit(metadata_bytes), || {
        crate::verify_contract_artifact(&artifact)
    })
    .unwrap_err();
    assert!(
        refused.to_string().contains("literal index validation"),
        "{refused}"
    );
    assert_eq!(
        refused.into_vm_error(),
        VMError::ExecutionDeferred(ExecutionDeferral::ActiveMemoryCapacity)
    );
    let retried = crate::verify_contract_artifact(&artifact).unwrap();
    assert_eq!(retried.code_hash, baseline.code_hash);
    assert_eq!(retried.manifest, baseline.manifest);
}
