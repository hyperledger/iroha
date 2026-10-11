//! Emit the canonical first-release verifying-key instruction fixture for SDKs.

use std::{fmt::Write as _, ops::Range};

use iroha_data_model::{
    confidential::ConfidentialStatus,
    isi::verifying_keys::RegisterVerifyingKey,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use norito::{NoritoSchema, core::Header, json};

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02X}").expect("write to String");
    }
    result
}

fn field(bytes: &[u8], offset: &mut usize, flags: u8) -> (Range<usize>, Range<usize>) {
    let start = *offset;
    let (length, prefix) =
        norito::core::read_len_from_slice_with_flags(&bytes[start..], flags).expect("field length");
    let payload = start + prefix..start + prefix + length;
    assert!(payload.end <= bytes.len());
    *offset = payload.end;
    (start..payload.end, payload)
}

fn main() {
    let mut record = VerifyingKeyRecord::new(
        1,
        "c",
        BackendTag::NativePipaRPasta,
        "unknown",
        [0; 32],
        [0x11; 32],
    );
    record.vk_len = 1;
    record.status = ConfidentialStatus::Withdrawn;
    let instruction = RegisterVerifyingKey::new(VerifyingKeyId::new("pipa-r/pasta", "x"), record);
    let bytes = norito::to_bytes(&instruction).expect("encode canonical instruction");
    let decoded: RegisterVerifyingKey =
        norito::decode_from_bytes(&bytes).expect("decode canonical instruction");
    assert_eq!(decoded, instruction);
    let header = Header::read(bytes.as_slice()).expect("read header");
    assert_eq!(
        header.schema,
        norito::schema::identity::frame_hash::<RegisterVerifyingKey>()
    );
    let mut offset = Header::SIZE;
    field(&bytes, &mut offset, header.flags);
    let (_, record_payload) = field(&bytes, &mut offset, header.flags);
    assert_eq!(offset, bytes.len());
    offset = record_payload.start;
    let mut fields = Vec::new();
    while offset < record_payload.end {
        fields.push(field(&bytes, &mut offset, header.flags));
    }
    assert_eq!(fields.len(), 17);
    assert_eq!(offset, record_payload.end);
    let backend = fields[4].0.clone();
    let absent_key = fields[15].0.clone();
    let status = fields[16].0.clone();
    assert_eq!(&bytes[fields[4].1.clone()], &[0; 4]);
    assert_eq!(&bytes[fields[15].1.clone()], &[0]);
    assert_eq!(&bytes[fields[16].1.clone()], &2_u32.to_le_bytes());
    let value = norito::json!({
        "schema_version": 1,
        "wire_name": "iroha.instruction.v1::verifying_keys::RegisterVerifyingKey",
        "rust_record_type": (VerifyingKeyRecord::frame_name()),
        "request": {
            "backend": "pipa-r/pasta", "name": "x", "version": 1, "circuit_id": "c",
            "public_inputs_schema_hash_hex": ("00".repeat(32)),
            "commitment_hex": ("11".repeat(32)), "vk_len": 1, "status": "Withdrawn"
        },
        "expected_inner_frame_bytes": (bytes.len()),
        "expected_inner_frame_hex": (hex(&bytes)),
        "backend_tag_frame": {"offset": (backend.start), "hex": (hex(&bytes[backend])), "width_bits": 32},
        "status_boundary": {
            "offset": (absent_key.start), "hex": (hex(&bytes[absent_key.start..status.end])),
            "preceding_absent_key_frame_hex": (hex(&bytes[absent_key])),
            "status_frame_hex": (hex(&bytes[status])), "status_discriminant": 2, "status_width_bits": 32
        }
    });
    println!(
        "{}",
        json::to_json_pretty(&value).expect("encode fixture JSON")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifying_key_fixture_preserves_canonical_frame_and_field_boundaries() {
        main();
    }
}
