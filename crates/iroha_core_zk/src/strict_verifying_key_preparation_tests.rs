#[cfg(test)]
mod strict_verifying_key_preparation_tests {
    use super::*;

    #[test]
    fn native_key_validation_reuses_compiled_key_and_rejects_empty_substitution() {
        let first = native_pipa_r::kaigi_verifying_key(kaigi_zk::native::NativeRelationV1::Usage)
            .expect("compiled native key");
        let second = native_pipa_r::kaigi_verifying_key(kaigi_zk::native::NativeRelationV1::Usage)
            .expect("reused compiled native key");
        assert_eq!(first, second);
        for key in [&first, &second] {
            native_pipa_r::validate_key(ZK_BACKEND_NATIVE_PIPA_R, KAIGI_USAGE_CIRCUIT_ID_V1, key)
                .expect("exact compiled key");
        }
        let empty = VerifyingKeyBox::new(ZK_BACKEND_NATIVE_PIPA_R.to_owned(), Vec::new());
        assert!(
            native_pipa_r::validate_key(
                ZK_BACKEND_NATIVE_PIPA_R,
                KAIGI_USAGE_CIRCUIT_ID_V1,
                &empty,
            )
            .is_err(),
            "a cached key must never replace absent supplied key bytes"
        );
    }

    fn portable_off_ledger_record() -> VerifyingKeyRecord {
        let mut record = VerifyingKeyRecord::new(
            1,
            confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            iroha_data_model::zk::BackendTag::NativePipaRPasta,
            "vesta",
            iroha_crypto::Hash::new(
                confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1,
            )
            .into(),
            [0x42; 32],
        );
        record.gas_schedule_id = Some("native_pipa_r_default".to_owned());
        record
    }

    #[test]
    fn record_preparation_rejects_empty_activation_window() {
        let id = VerifyingKeyId::new(ZK_BACKEND_NATIVE_PIPA_R, "empty-window");
        let mut record = portable_off_ledger_record();
        record.activation_height = Some(10);
        record.withdraw_height = Some(10);
        let error = validate_and_prepare_verifying_key_record_v1(&id, &record)
            .expect_err("an empty activation window must not enter persistent state");
        assert!(error.contains("greater"), "unexpected error: {error}");
    }

    #[test]
    fn record_preparation_rejects_nonportable_metadata() {
        let id = VerifyingKeyId::new(ZK_BACKEND_NATIVE_PIPA_R, "bad-metadata");
        let mut record = portable_off_ledger_record();
        record.metadata_uri_cid = Some("ipfs://cid?query".to_owned());
        let error = validate_and_prepare_verifying_key_record_v1(&id, &record)
            .expect_err("nonportable metadata must not poison registry rehydration");
        assert!(error.contains("metadata URI"), "unexpected error: {error}");
    }

    #[test]
    fn record_preparation_rejects_oversized_off_ledger_declaration() {
        let id = VerifyingKeyId::new(ZK_BACKEND_NATIVE_PIPA_R, "oversized-off-ledger");
        let mut record = VerifyingKeyRecord::new(
            1,
            confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            iroha_data_model::zk::BackendTag::NativePipaRPasta,
            "vesta",
            iroha_crypto::Hash::new(
                confidential_v2::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1,
            )
            .into(),
            [0x42; 32],
        );
        record.vk_len = u32::try_from(NATIVE_PIPA_R_VERIFYING_KEY_V1_MAX_BYTES + 1)
            .expect("test length fits u32");
        let error = validate_and_prepare_verifying_key_record_v1(&id, &record)
            .expect_err("an off-ledger key declaration must obey the backend container bound");
        assert!(error.contains("declared"), "unexpected error: {error}");
    }
    #[test]
    fn record_preparation_rejects_noncanonical_native_schema_hash() {
        let id = VerifyingKeyId::new(ZK_BACKEND_NATIVE_PIPA_R, "wrong-schema");
        let mut record = portable_off_ledger_record();
        record.public_inputs_schema_hash = iroha_crypto::Hash::new(b"noncanonical-schema").into();
        let error = validate_and_prepare_verifying_key_record_v1(&id, &record)
            .expect_err("a production native key must bind the circuit's canonical schema");
        assert!(error.contains("schema hash"), "unexpected error: {error}");
    }
    #[test]
    fn binding_only_ivm_verifier_records_are_not_admitted() {
        let halo2_id = VerifyingKeyId::new(ZK_BACKEND_NATIVE_PIPA_R, "ivm-binding");
        let mut halo2_record = portable_off_ledger_record();
        halo2_record.backend = iroha_data_model::zk::BackendTag::NativePipaRPasta;
        halo2_record.curve = "vesta".to_owned();
        halo2_record.circuit_id = "halo2/pasta/ipa/ivm-execution-v1".to_owned();
        halo2_record.public_inputs_schema_hash = [0x22; 32];
        let halo2_error = validate_and_prepare_verifying_key_record_v1(&halo2_id, &halo2_record)
            .expect_err("binding-only Halo2 IVM key must not enter state");
        assert!(halo2_error.contains("not admitted"), "{halo2_error}");

        let stark_id = VerifyingKeyId::new(ZK_BACKEND_STARK_FRI_V1, "ivm-binding");
        let mut stark_record = VerifyingKeyRecord::new(
            1,
            format!("{ZK_BACKEND_STARK_FRI_V1}:{IVM_EXECUTION_V1_CIRCUIT_ID}"),
            iroha_data_model::zk::BackendTag::Stark,
            "goldilocks",
            [0x22; 32],
            [0x42; 32],
        );
        stark_record.gas_schedule_id = Some("stark_default".to_owned());
        let stark_error = validate_and_prepare_verifying_key_record_v1(&stark_id, &stark_record)
            .expect_err("binding-only STARK IVM key must not enter state");
        assert!(stark_error.contains("not admitted"), "{stark_error}");
    }
    #[test]
    fn record_preparation_rejects_oversized_stark_off_ledger_declaration() {
        let id = VerifyingKeyId::new(ZK_BACKEND_STARK_FRI_V1, "generic-binding-air");
        let mut record = VerifyingKeyRecord::new(
            1,
            format!("{ZK_BACKEND_STARK_FRI_V1}:generic-binding-air"),
            iroha_data_model::zk::BackendTag::Stark,
            "goldilocks",
            [0x51; 32],
            [0x52; 32],
        );
        record.vk_len =
            u32::try_from(STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES + 1).expect("test length fits u32");
        let error = validate_and_prepare_verifying_key_record_v1(&id, &record)
            .expect_err("an off-ledger STARK key declaration must obey the backend bound");
        assert!(error.contains("declared"), "unexpected error: {error}");
    }
    #[test]
    fn native_preparation_rejects_oversized_container_before_backend_decode() {
        let vk = VerifyingKeyBox::new(
            ZK_BACKEND_NATIVE_PIPA_R.into(),
            vec![0_u8; NATIVE_PIPA_R_VERIFYING_KEY_V1_MAX_BYTES + 1],
        );
        let error = validate_and_prepare_verifying_key_material_v1(
            ZK_BACKEND_NATIVE_PIPA_R,
            confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            iroha_data_model::zk::BackendTag::NativePipaRPasta,
            &vk,
        )
        .expect_err("oversized native key must fail before backend decoding");
        assert!(error.contains("invalid native PIPA-R key container"), "unexpected error: {error}");
    }
    #[test]
    fn native_preparation_rejects_retired_tlv_container() {
        let mut bytes = b"ZK1\0CID1".to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let vk = VerifyingKeyBox::new(ZK_BACKEND_NATIVE_PIPA_R.into(), bytes);
        assert!(
            validate_and_prepare_verifying_key_material_v1(
                ZK_BACKEND_NATIVE_PIPA_R,
                confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
                iroha_data_model::zk::BackendTag::NativePipaRPasta,
                &vk,
            )
            .is_err(),
            "a tiny key container must not honor an attacker-declared TLV allocation"
        );
    }
    #[cfg(feature = "zk-stark")]
    #[test]
    fn stark_preparation_rejects_oversized_declared_string_from_tiny_container() {
        let backend = "stark/fri/poseidon-x7-goldilocks-6x64-v1";
        let circuit_id = "stark/fri/poseidon-x7-goldilocks-6x64-v1:bounded-vk-test";
        let payload = crate::stark::StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id: circuit_id.to_owned(),
            n_log2: crate::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
            blowup_log2: crate::stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: crate::stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        };
        let mut bytes = norito::encode_canonical(&payload).expect("encode canonical STARK key");
        let circuit = circuit_id.as_bytes();
        let circuit_offset = bytes
            .windows(circuit.len())
            .position(|window| window == circuit)
            .expect("encoded circuit id");
        assert!(circuit_offset > 0, "circuit id must carry a length prefix");
        bytes[circuit_offset - 1] = u8::MAX;
        let vk = VerifyingKeyBox::new(backend.into(), bytes);
        assert!(
            validate_and_prepare_verifying_key_material_v1(
                backend,
                circuit_id,
                iroha_data_model::zk::BackendTag::Stark,
                &vk,
            )
            .is_err(),
            "bounded preparation must reject an oversized declared string before allocation"
        );
    }
}
