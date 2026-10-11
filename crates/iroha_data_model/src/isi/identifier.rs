//! Hidden-function-backed identifier policy instructions.
use super::*;
use crate::{
    account::AccountId,
    identifier::{IdentifierPolicy, IdentifierPolicyId, IdentifierResolutionReceipt},
};
isi! {
    /// Register a new identifier policy namespace in the world state.
    #[norito_schema(name = "iroha_data_model::isi::identifier::RegisterIdentifierPolicy")]
    pub struct RegisterIdentifierPolicy {
        /// Identifier policy record to register.
        pub policy: IdentifierPolicy,
    }
}
impl crate::seal::Instruction for RegisterIdentifierPolicy {}
isi! {
    /// Activate an existing identifier policy namespace.
    #[norito_schema(name = "iroha_data_model::isi::identifier::ActivateIdentifierPolicy")]
    pub struct ActivateIdentifierPolicy {
        /// Policy namespace to activate.
        pub policy_id: IdentifierPolicyId,
    }
}
impl crate::seal::Instruction for ActivateIdentifierPolicy {}
isi! {
    /// Bind an attested opaque identifier receipt to the UAID attached to an account.
    #[norito_schema(name = "iroha_data_model::isi::identifier::ClaimIdentifier")]
    pub struct ClaimIdentifier {
        /// Account whose UAID should own the receipt-bound opaque identifier.
        pub account: AccountId,
        /// Receipt emitted by the configured identifier resolver.
        pub receipt: IdentifierResolutionReceipt,
    }
}
impl crate::seal::Instruction for ClaimIdentifier {}
isi! {
    /// Revoke a previously claimed opaque identifier.
    #[norito_schema(name = "iroha_data_model::isi::identifier::RevokeIdentifier")]
    pub struct RevokeIdentifier {
        /// Policy namespace under which the opaque identifier was claimed.
        pub policy_id: IdentifierPolicyId,
        /// Opaque identifier to revoke.
        pub opaque_id: OpaqueAccountId,
    }
}
impl crate::seal::Instruction for RevokeIdentifier {}
fn identifier_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_decode_one_field {
    ($ty:ident { $field:ident: $field_ty:ty }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = identifier_decode_flags();
                let mut offset = 0usize;
                let $field = super::decode_aos_canonical_field::<$field_ty>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $field }, offset))
            }
        }
    };
}
macro_rules! impl_decode_two_fields {
    ($ty:ident { $first:ident: $first_ty:ty, $second:ident: $second_ty:ty }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = identifier_decode_flags();
                let mut offset = 0usize;
                let $first = super::decode_aos_canonical_field::<$first_ty>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                let $second = super::decode_aos_canonical_field::<$second_ty>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $first, $second }, offset))
            }
        }
    };
}
impl_decode_one_field!(RegisterIdentifierPolicy {
    policy: IdentifierPolicy
});
impl_decode_one_field!(ActivateIdentifierPolicy {
    policy_id: IdentifierPolicyId
});
impl_decode_two_fields!(ClaimIdentifier {
    account: AccountId,
    receipt: IdentifierResolutionReceipt
});
impl_decode_two_fields!(RevokeIdentifier {
    policy_id: IdentifierPolicyId,
    opaque_id: OpaqueAccountId
});
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use crate::{
        nexus::UniversalAccountId,
        ram_lfe::{
            RamLfeExecutionReceiptPayload, RamLfeOutputOpening, RamLfeOutputOpeningPayload,
            RamLfeProgramId, RamLfeReceiptAttestation,
        },
    };
    use iroha_crypto::{
        Algorithm, Hash, KeyPair, PublicKey, RamLfeBackend, RamLfeVerificationMode, Signature,
        SignatureOf,
    };
    fn checked_seed_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked identifier instruction fixture keypair")
    }
    fn checked_signature<T: norito::codec::Encode>(
        signer: &KeyPair,
        payload: &T,
    ) -> SignatureOf<T> {
        SignatureOf::try_new(signer.private_key(), payload)
            .expect("sign checked identifier instruction fixture payload")
    }
    fn public_key(seed: u8) -> PublicKey {
        let key_pair = checked_seed_keypair(seed);
        key_pair.public_key().clone()
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(public_key(seed))
    }
    fn policy_id() -> IdentifierPolicyId {
        "email#retail".parse().expect("policy id")
    }
    fn program_id() -> RamLfeProgramId {
        "email_retail".parse().expect("program id")
    }
    fn policy() -> IdentifierPolicy {
        IdentifierPolicy::new(
            policy_id(),
            account(0xF1),
            crate::identifier::IdentifierNormalization::EmailAddress,
            program_id(),
        )
        .with_note("retail email")
    }
    fn receipt() -> IdentifierResolutionReceipt {
        let account_id = account(0xF2);
        let opening_payload = RamLfeOutputOpeningPayload {
            program_id: program_id(),
            input_ciphertext_hash: Hash::new(b"input-ciphertext"),
            output_ciphertext_hash: Hash::new(b"output-ciphertext"),
            parameter_digest: Hash::new(b"parameters"),
            evaluation_key_digest: Hash::new(b"evaluation-keys"),
            opened_output_hash: Hash::new(b"opened-output"),
            opened_at_ms: 1_777_777_777_001,
            expires_at_ms: Some(1_777_777_877_000),
        };
        let opening_signer = checked_seed_keypair(0xF4);
        let opening_signature = checked_signature(&opening_signer, &opening_payload);
        opening_signature
            .verify(opening_signer.public_key(), &opening_payload)
            .expect("checked output-opening fixture signature verifies");
        let opening = RamLfeOutputOpening {
            signature: Signature::try_from_bytes(opening_signature.payload())
                .expect("checked output-opening fixture signature passes admission"),
            payload: opening_payload,
        };
        let payload = crate::identifier::IdentifierResolutionReceiptPayload {
            network_id: crate::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"identifier-component-network",
                )),
            ),
            policy_id: policy_id(),
            execution: RamLfeExecutionReceiptPayload {
                program_id: program_id(),
                program_digest: Hash::new(b"program"),
                backend: RamLfeBackend::BfvProgrammedV1,
                verification_mode: RamLfeVerificationMode::Signed,
                input_ciphertext_hash: Hash::new(b"input-ciphertext"),
                output_ciphertext_hash: Hash::new(b"output-ciphertext"),
                parameter_digest: Hash::new(b"parameters"),
                evaluation_key_digest: Hash::new(b"evaluation-keys"),
                output_hash: Hash::new(b"output"),
                associated_data_hash: Hash::new(b"associated-data"),
                executed_at_ms: 1_777_777_777_000,
                expires_at_ms: Some(1_777_777_877_000),
            },
            opening,
            opaque_id: OpaqueAccountId::from_hash(Hash::new(b"opaque")),
            receipt_hash: Hash::new(b"receipt"),
            uaid: UniversalAccountId::from_hash(Hash::new(b"uaid")),
            account_id,
        };
        let signer = checked_seed_keypair(0xF3);
        let signature = checked_signature(&signer, &payload);
        signature
            .verify(signer.public_key(), &payload)
            .expect("checked identifier receipt fixture signature verifies");
        IdentifierResolutionReceipt {
            payload,
            attestation: RamLfeReceiptAttestation::Signed(
                Signature::try_from_bytes(signature.payload())
                    .expect("checked identifier receipt fixture signature passes admission"),
            ),
            phone_retail_canonicality: None,
        }
    }
    #[test]
    fn identifier_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RegisterIdentifierPolicy { policy: policy() });
        assert_slice_roundtrip(ActivateIdentifierPolicy {
            policy_id: policy_id(),
        });
        assert_slice_roundtrip(ClaimIdentifier {
            account: account(0xF4),
            receipt: receipt(),
        });
        assert_slice_roundtrip(RevokeIdentifier {
            policy_id: policy_id(),
            opaque_id: OpaqueAccountId::from_hash(Hash::new(b"opaque")),
        });
    }
    #[test]
    fn identifier_registry_decodes_stable_ids() {
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterIdentifierPolicy>(
                "identity::RegisterIdentifierPolicy",
            )
            .register_with_id_slice::<ActivateIdentifierPolicy>(
                "identity::ActivateIdentifierPolicy",
            )
            .register_with_id_slice::<ClaimIdentifier>("identity::ClaimIdentifier")
            .register_with_id_slice::<RevokeIdentifier>("identity::RevokeIdentifier");
        assert_registry_decodes(
            &registry,
            "identity::RegisterIdentifierPolicy",
            RegisterIdentifierPolicy { policy: policy() },
        );
        assert_registry_decodes(
            &registry,
            "identity::ActivateIdentifierPolicy",
            ActivateIdentifierPolicy {
                policy_id: policy_id(),
            },
        );
        assert_registry_decodes(
            &registry,
            "identity::ClaimIdentifier",
            ClaimIdentifier {
                account: account(0xF5),
                receipt: receipt(),
            },
        );
        assert_registry_decodes(
            &registry,
            "identity::RevokeIdentifier",
            RevokeIdentifier {
                policy_id: policy_id(),
                opaque_id: OpaqueAccountId::from_hash(Hash::new(b"opaque")),
            },
        );
    }

    fn current_claim_fixture_cases() -> Vec<norito::json::Value> {
        let rejected: norito::json::Value = norito::json::from_str(include_str!(
            "../../tests/fixtures/claim_identifier_networkless_rejected_frames.json"
        ))
        .expect("networkless ClaimIdentifier negative controls");
        let frames = rejected.get("frames").unwrap().as_array().unwrap();
        assert_eq!(frames.len(), 2, "preserve both original account cases");
        frames
            .iter()
            .map(|frame| {
                let retired = hex::decode(frame.as_str().unwrap()).unwrap();
                assert!(norito::decode_from_bytes::<ClaimIdentifier>(&retired).is_err());
                // Inspect only the unchanged outer account field through its
                // current codec; no networkless receipt decoder is introduced.
                let view = norito::core::from_bytes_view(&retired).unwrap();
                assert_eq!(
                    view.schema(),
                    norito::schema::identity::frame_hash::<ClaimIdentifier>()
                );
                let mut offset = 0;
                let original_account =
                    super::super::read_aos_field(view.as_bytes(), &mut offset, view.flags())
                        .unwrap();
                let account = super::super::decode_aos_canonical_field::<AccountId>(
                    original_account,
                    view.flags(),
                )
                .unwrap();
                // Preserve the captured account itself, rather than assuming
                // a historical keypair generator reproduces its bytes.
                super::super::generated_record_identity_tests::capture(ClaimIdentifier {
                    account,
                    receipt: receipt(),
                })
            })
            .collect()
    }

    #[test]
    fn current_claim_cases_preserve_accounts_and_reject_networkless_receipts() {
        assert_eq!(current_claim_fixture_cases().len(), 2);
    }

    #[test]
    #[ignore = "explicit native capture after the mandatory signed receipt network change"]
    fn print_current_claim_identifier_fixture_cases() {
        let cases = norito::json::Value::Array(current_claim_fixture_cases());
        println!(
            "CURRENT_IDENTIFIER_CLAIM_CASES_V1\t{}",
            norito::json::to_json(&cases).expect("current ClaimIdentifier capture")
        );
    }
}
