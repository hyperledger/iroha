use super::*;
use crate::proof::{VerifyingKeyId, VerifyingKeyRecord};
isi! {
    /// Register a new verifying key record into the WSV.
    #[norito_schema(name = "iroha_data_model::isi::verifying_keys::RegisterVerifyingKey")]
    #[derive(derive_more::Constructor)]
    pub struct RegisterVerifyingKey {
        /// Identifier of the verifying key (backend + name).
        pub id: VerifyingKeyId,
        /// Verifying key record with version, commitment, and optional stored key bytes.
        pub record: VerifyingKeyRecord,
    }
}
isi! {
    /// Rotate an existing verifying key record to a higher version.
    ///
    /// The record remains bound to its originally registered circuit identifier.
    /// Register a distinct [`VerifyingKeyId`] when introducing a different circuit.
    #[norito_schema(name = "iroha_data_model::isi::verifying_keys::UpdateVerifyingKey")]
    pub struct UpdateVerifyingKey {
        /// Identifier of the verifying key to update.
        pub id: VerifyingKeyId,
        /// New record with a strictly greater version and the same circuit identifier.
        pub record: VerifyingKeyRecord,
    }
}
// Seal implementations so these types participate as instructions
impl crate::seal::Instruction for RegisterVerifyingKey {}
impl crate::seal::Instruction for UpdateVerifyingKey {}
fn verifying_key_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_decode_verifying_key_instruction {
    ($ty:ident) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = verifying_key_decode_flags();
                let mut offset = 0usize;
                let id = super::decode_aos_canonical_field::<VerifyingKeyId>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                let record = super::decode_aos_canonical_field::<VerifyingKeyRecord>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { id, record }, offset))
            }
        }
    };
}
impl_decode_verifying_key_instruction!(RegisterVerifyingKey);
impl_decode_verifying_key_instruction!(UpdateVerifyingKey);
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{
        assert_registry_decodes_registered_type as assert_registry_decodes, assert_slice_roundtrip,
    };
    use crate::{proof::VerifyingKeyRecord, zk::BackendTag};
    fn key_id(name: &str) -> VerifyingKeyId {
        VerifyingKeyId::new("pipa-r/pasta", name)
    }
    fn record(version: u32) -> VerifyingKeyRecord {
        VerifyingKeyRecord::new(
            version,
            "pipa-r/pasta/confidential-transfer-v1",
            BackendTag::NativePipaRPasta,
            "vesta",
            [0x11; 32],
            [0x22; 32],
        )
    }
    #[test]
    fn verifying_key_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RegisterVerifyingKey {
            id: key_id("vk_a"),
            record: record(1),
        });
        assert_slice_roundtrip(UpdateVerifyingKey {
            id: key_id("vk_a"),
            record: record(2),
        });
    }
    #[test]
    fn verifying_key_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterVerifyingKey>(
                "iroha.instruction.v1::verifying_keys::RegisterVerifyingKey",
            )
            .register_with_id_slice::<UpdateVerifyingKey>(
                "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey",
            );
        assert_registry_decodes(
            &registry,
            RegisterVerifyingKey {
                id: key_id("vk_b"),
                record: record(1),
            },
        );
        assert_registry_decodes(
            &registry,
            UpdateVerifyingKey {
                id: key_id("vk_b"),
                record: record(2),
            },
        );
    }

    #[test]
    fn verifying_key_sdk_fixture_matches_native_frame() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/zk/verifying_key_record_v1.json"
        ))
        .expect("SDK fixture JSON");
        let mut record = VerifyingKeyRecord::new(
            1,
            "c",
            BackendTag::NativePipaRPasta,
            "unknown",
            [0; 32],
            [0x11; 32],
        );
        record.vk_len = 1;
        record.status = crate::confidential::ConfidentialStatus::Withdrawn;
        let value = RegisterVerifyingKey {
            id: key_id("x"),
            record,
        };
        let expected = hex::decode(
            fixture["expected_inner_frame_hex"]
                .as_str()
                .expect("fixture frame"),
        )
        .expect("hex frame");
        let encoded = norito::to_bytes(&value).expect("canonical native frame");
        assert_eq!(encoded, expected);
        assert_eq!(
            norito::decode_from_bytes::<RegisterVerifyingKey>(&expected).expect("fixture decode"),
            value
        );
        let mut wrong_schema = expected;
        wrong_schema[6] ^= 1;
        assert!(norito::decode_from_bytes::<RegisterVerifyingKey>(&wrong_schema).is_err());
    }
}
