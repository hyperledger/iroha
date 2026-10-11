//! Captured nominal and directional identities for transaction wire owners.
//!
//! Payload, signing and admission checks remain in their owning transaction suites.

/// Compare one existing owner against its independently captured codec identities.
fn check<T>(nominal: &str, serialize_hash: &str, deserialize_hash: &str)
where
    T: norito::NoritoSchema + norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    let parse = |value: &str| -> [u8; 16] {
        hex::decode(value)
            .expect("captured hexadecimal schema hash")
            .try_into()
            .expect("captured schema hash has sixteen bytes")
    };
    let serialize_hash = parse(serialize_hash);
    let deserialize_hash = parse(deserialize_hash);
    assert_eq!(T::nominal_name(), nominal);
    assert_eq!(T::frame_name(), nominal);
    assert_eq!(norito::schema::identity::frame_hash::<T>(), serialize_hash);
    assert_eq!(
        norito::schema::identity::frame_hash::<T>(),
        deserialize_hash
    );
    assert_eq!(norito::schema::identity::frame_hash::<T>(), serialize_hash);
    assert_eq!(
        norito::schema::identity::frame_hash::<T>(),
        deserialize_hash
    );
}

#[test]
fn captured_signed_transaction_owner_identities() {
    check::<super::signed::FeeChargeKind>(
        "iroha_data_model::transaction::signed::model::FeeChargeKind",
        "29b7bffd4931356a9a7d6bf3896a7b9d",
        "29b7bffd4931356a9a7d6bf3896a7b9d",
    );
    check::<super::signed::FeeChargeLimit>(
        "iroha_data_model::transaction::signed::model::FeeChargeLimit",
        "46ad6f94f1805768bfe1149bf8638e84",
        "46ad6f94f1805768bfe1149bf8638e84",
    );
    check::<super::signed::AuthorityFeePayment>(
        "iroha_data_model::transaction::signed::model::AuthorityFeePayment",
        "2cbc3b0656a40521ca3be86dcb8066e2",
        "2cbc3b0656a40521ca3be86dcb8066e2",
    );
    check::<super::signed::SponsorFeePayment>(
        "iroha_data_model::transaction::signed::model::SponsorFeePayment",
        "ce8e250de157d76b0bb1f93cf9fc18a9",
        "ce8e250de157d76b0bb1f93cf9fc18a9",
    );
    check::<super::signed::FeePaymentIntent>(
        "iroha_data_model::transaction::signed::model::FeePaymentIntent",
        "b2af78f4ab51dfb6898be9939425dfe4",
        "b2af78f4ab51dfb6898be9939425dfe4",
    );
    check::<super::signed::TransactionPayload>(
        "iroha_data_model::transaction::signed::model::TransactionPayload",
        "6bb8ee3fc1560f7ab7a11c3ec37b1d36",
        "6bb8ee3fc1560f7ab7a11c3ec37b1d36",
    );
    check::<super::signed::TransactionSignature>(
        "iroha_data_model::transaction::signed::model::TransactionSignature",
        "02f005cc75d189fc035ea83fd81a170d",
        "02f005cc75d189fc035ea83fd81a170d",
    );
    check::<super::signed::MultisigSignature>(
        "iroha_data_model::transaction::signed::model::MultisigSignature",
        "35f7c038c9aac750c7153b2cc45dc825",
        "35f7c038c9aac750c7153b2cc45dc825",
    );
    check::<super::signed::MultisigSignatures>(
        "iroha_data_model::transaction::signed::model::MultisigSignatures",
        "8245293a76134736b7f6bdab0685629f",
        "8245293a76134736b7f6bdab0685629f",
    );
    check::<super::signed::SealedTransactionCommitmentPayload>(
        "iroha_data_model::transaction::signed::model::SealedTransactionCommitmentPayload",
        "c590916d86e002c837d6a1a933608a03",
        "c590916d86e002c837d6a1a933608a03",
    );
    check::<super::signed::SignedSealedTransactionCommitment>(
        "iroha_data_model::transaction::signed::model::SignedSealedTransactionCommitment",
        "84f839d61a2c4874d7427019e8354bf5",
        "84f839d61a2c4874d7427019e8354bf5",
    );
    check::<super::signed::SealedTransactionReveal>(
        "iroha_data_model::transaction::signed::model::SealedTransactionReveal",
        "3813639aff857718e6ee9ec1fd163563",
        "3813639aff857718e6ee9ec1fd163563",
    );
    check::<super::signed::TransactionResult>(
        "iroha_data_model::transaction::signed::model::TransactionResult",
        "b36be47efd054c2f460d92b4de6e3b00",
        "b36be47efd054c2f460d92b4de6e3b00",
    );
    check::<super::signed::ExecutionStep>(
        "iroha_data_model::transaction::signed::model::ExecutionStep",
        "ba7e5332ca333cd1779959196cfdce1e",
        "ba7e5332ca333cd1779959196cfdce1e",
    );
}

#[test]
fn captured_executable_transaction_owner_identities() {
    check::<super::executable::Executable>(
        "iroha_data_model::transaction::executable::model::Executable",
        "650b24a40c83bc711543d7e26a7f6f42",
        "650b24a40c83bc711543d7e26a7f6f42",
    );
    check::<super::executable::ExecutableBatchItem>(
        "iroha_data_model::transaction::executable::model::ExecutableBatchItem",
        "d555e094491582e0225ee429dd88fc2e",
        "d555e094491582e0225ee429dd88fc2e",
    );
    check::<super::executable::IvmBytecode>(
        "iroha_data_model::transaction::executable::model::IvmBytecode",
        "9df552a68613c84484d0dad8ab60a33d",
        "9df552a68613c84484d0dad8ab60a33d",
    );
    check::<super::executable::IvmProved>(
        "iroha_data_model::transaction::executable::model::IvmProved",
        "bf74afa86140bbe2570bdbccec48a517",
        "bf74afa86140bbe2570bdbccec48a517",
    );
    check::<super::executable::ContractInvocation>(
        "iroha_data_model::transaction::executable::model::ContractInvocation",
        "9e15966ef924eafa3d85eb2fa02a7cc4",
        "9e15966ef924eafa3d85eb2fa02a7cc4",
    );
}

#[test]
fn captured_error_transaction_owner_identities() {
    check::<super::error::TransactionLimitError>(
        "iroha_data_model::transaction::error::model::TransactionLimitError",
        "4563dda30801b8560de8d967157e6457",
        "4563dda30801b8560de8d967157e6457",
    );
    check::<super::error::InstructionExecutionFail>(
        "iroha_data_model::transaction::error::model::InstructionExecutionFail",
        "926cc4dc9d097148920b6e3eddaed440",
        "926cc4dc9d097148920b6e3eddaed440",
    );
    check::<super::error::TriggerExecutionFail>(
        "iroha_data_model::transaction::error::model::TriggerExecutionFail",
        "fddfff69f087d2b2ce030b5c9f880bce",
        "fddfff69f087d2b2ce030b5c9f880bce",
    );
    check::<super::error::TransactionRejectionReason>(
        "iroha_data_model::transaction::error::model::TransactionRejectionReason",
        "cf59f6c47df110ccb8d627b64ef5c7eb",
        "cf59f6c47df110ccb8d627b64ef5c7eb",
    );
}
