#[cfg(test)]
mod attachments_tests {
    use super::*;
    #[test]
    fn signed_tx_with_attachments_roundtrip() {
        let network_id = test_network_id(0x2E);
        let private_key: iroha_crypto::PrivateKey =
            "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
                .parse()
                .unwrap();
        let authority = AccountId::new(iroha_crypto::PublicKey::from(private_key.clone()));
        let attachment = |proof: Vec<u8>| {
            crate::proof::ProofAttachment::new_ref(
                "halo2/ipa".into(),
                crate::proof::ProofBox::new("halo2/ipa".into(), proof),
                crate::proof::VerifyingKeyId::new("halo2/ipa", "vk_1"),
            )
        };
        let tx: SignedTransaction = TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::Instructions(Vec::new().into()))
        .with_proof_attachments([attachment(vec![1, 2, 3])])
        .expect("one proof attachment is a valid carrier")
        .sign(&private_key);
        let bytes = norito::to_bytes(&tx).expect("encode");
        let archived = norito::from_bytes::<SignedTransaction>(&bytes).expect("archived");
        let decoded: SignedTransaction = norito::core::DeserializePayload::deserialize(archived);
        assert_eq!(decoded, tx);
        assert_eq!(
            decoded.proof_attachments_v1().expect("canonical carrier"),
            vec![attachment(vec![1, 2, 3])]
        );
        decoded
            .validate_signed_attachments_v1()
            .expect("round-tripped attachments stay bound to the payload");
        decoded
            .verify_signature()
            .expect("round-tripped attachment remains signature-bound");
        assert_eq!(
            norito::decode_canonical::<SignedTransaction>(
                &norito::encode_canonical(&tx).expect("canonical frame")
            )
            .expect("canonical decode"),
            tx
        );
        let original_hash = decoded.hash();
        let original_intent = decoded.ordered_intent_digest_v1().expect("intent");
        let mut tampered = decoded;
        tampered.payload.attachments = Some(
            crate::transaction::signed_attachments::SignedAttachmentPlanV1::transaction_proofs(&[
                attachment(vec![9, 9, 9]),
            ])
            .expect("one proof attachment is a valid carrier")
            .declare(),
        );
        tampered
            .payload
            .bind_attachment_statements_v1()
            .expect("bound statements");
        assert_eq!(
            tampered.ordered_intent_digest_v1().expect("intent"),
            original_intent,
            "generated proof bytes are outside the ordered intent"
        );
        assert_ne!(
            tampered.hash(),
            original_hash,
            "execution-affecting attachments must change transaction identity"
        );
        tampered
            .verify_signature()
            .expect_err("an attachment mutation must invalidate authorization");
    }
}
