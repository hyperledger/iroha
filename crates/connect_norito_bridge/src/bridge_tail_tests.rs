#[cfg(test)]
mod signed_transaction_fixture_tests {
    use super::decode_signed_transaction;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        Level, NetworkId,
        account::AccountId,
        block::BlockHeader,
        isi::Log,
        transaction::{SignedTransaction, TransactionBuilder},
    };
    use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};
    use std::time::Duration;
    // Matches account::address::DEFAULT_CHAIN_DISCRIMINANT (i105 discriminant).
    const FIXTURE_CHAIN_DISCRIMINANT: u16 = 0x02F1;
    fn fixture_key_pair() -> KeyPair {
        KeyPair::try_from_seed(vec![0xA5; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    fn fixture_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            b"connect-norito-signed-transaction-fixture-genesis",
        )))
    }
    fn split_default_norito_fields(bytes: &[u8], count: usize) -> Vec<Vec<u8>> {
        let flags = norito::core::default_encode_flags();
        let mut offset = 0;
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let (len, prefix) = norito::core::read_len_from_slice_with_flags(
                bytes.get(offset..).expect("Norito field prefix"),
                flags,
            )
            .expect("Norito field length");
            let start = offset.checked_add(prefix).expect("Norito field start");
            let end = start.checked_add(len).expect("Norito field end");
            fields.push(
                bytes
                    .get(start..end)
                    .expect("complete Norito field")
                    .to_vec(),
            );
            offset = end;
        }
        assert_eq!(offset, bytes.len(), "unexpected trailing Norito fields");
        fields
    }
    fn encode_default_norito_fields(fields: &[Vec<u8>]) -> Vec<u8> {
        let flags = norito::core::default_encode_flags();
        let mut bytes = Vec::new();
        for field in fields {
            norito::core::write_len_to_vec_with_flags(
                &mut bytes,
                u64::try_from(field.len()).expect("Norito field length fits u64"),
                flags,
            );
            bytes.extend_from_slice(field);
        }
        bytes
    }
    fn signed_transaction_with_type_name_instruction_pair(
        canonical: &[u8],
        concrete_type_name: &str,
    ) -> Vec<u8> {
        assert_eq!(canonical.first(), Some(&1));
        let mut signed = split_default_norito_fields(&canonical[1..], 3);
        let mut payload = split_default_norito_fields(&signed[1], 9);

        assert_eq!(&payload[3][..4], &0_u32.to_le_bytes());
        let executable_fields = split_default_norito_fields(&payload[3][4..], 1);
        let sequence = &executable_fields[0];
        assert_eq!(&sequence[..8], &1_u64.to_le_bytes());
        let sequence_fields = split_default_norito_fields(&sequence[8..], 1);
        let mut instruction = split_default_norito_fields(&sequence_fields[0], 2);
        let wire_id = split_default_norito_fields(&instruction[0], 1);
        assert_eq!(wire_id[0], b"iroha.log");

        instruction[0] = encode_default_norito_fields(&[concrete_type_name.as_bytes().to_vec()]);
        let instruction = encode_default_norito_fields(&instruction);
        let mut sequence = 1_u64.to_le_bytes().to_vec();
        sequence.extend_from_slice(&encode_default_norito_fields(&[instruction]));
        let mut executable = 0_u32.to_le_bytes().to_vec();
        executable.extend_from_slice(&encode_default_norito_fields(&[sequence]));
        payload[3] = executable;
        signed[1] = encode_default_norito_fields(&payload);

        let mut alternate = vec![1];
        alternate.extend_from_slice(&encode_default_norito_fields(&signed));
        alternate
    }
    #[test]
    fn fixture_key_pair_uses_checked_seed_derivation() {
        assert_eq!(fixture_key_pair().algorithm(), Algorithm::Ed25519);
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn signed_transaction_decoder_accepts_only_versioned_bytes() {
        let _scope = super::test_support::ChainDiscriminantScope::enter(FIXTURE_CHAIN_DISCRIMINANT);
        let keypair = fixture_key_pair();
        let authority = AccountId::new(keypair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            fixture_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1));
        let tx = builder.sign(keypair.private_key());
        let versioned = tx.encode_versioned();
        decode_signed_transaction(&versioned).expect("decode versioned signed tx");
        let bytes = norito::codec::encode_adaptive(&tx);
        assert!(decode_signed_transaction(&bytes).is_err());
        let framed = norito::to_bytes(&tx).expect("encode framed signed tx");
        assert!(decode_signed_transaction(&framed).is_err());
    }
    #[test]
    fn signed_transaction_versioned_reencode_match() {
        let _scope = super::test_support::ChainDiscriminantScope::enter(FIXTURE_CHAIN_DISCRIMINANT);
        let keypair = fixture_key_pair();
        let authority = AccountId::new(keypair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            fixture_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1));
        let tx = builder.sign(keypair.private_key());
        let bytes = tx.encode_versioned();
        let signed = decode_signed_transaction(&bytes).expect("decode versioned signed tx");
        assert_eq!(signed.encode_versioned(), bytes);
    }
    #[test]
    fn signed_transaction_decoder_rejects_registered_type_name_alias() {
        let _scope = super::test_support::ChainDiscriminantScope::enter(FIXTURE_CHAIN_DISCRIMINANT);
        let keypair = fixture_key_pair();
        let authority = AccountId::new(keypair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            fixture_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "noncanonical instruction alias".to_owned(),
        )]);
        builder.set_creation_time(Duration::from_millis(1));
        let transaction = builder.sign(keypair.private_key());
        let canonical = transaction
            .encode_wire_v1()
            .expect("encode canonical signed transaction");
        decode_signed_transaction(&canonical).expect("canonical instruction wire is accepted");
        let alternate = signed_transaction_with_type_name_instruction_pair(
            &canonical,
            std::any::type_name::<Log>(),
        );

        assert_ne!(alternate, canonical);
        let error = SignedTransaction::decode_all_versioned(&alternate)
            .expect_err("canonical V1 decoding must reject the concrete type-name alias");
        assert!(
            matches!(error, iroha_version::error::Error::NoritoCodec(_)),
            "alias rejection must remain a codec failure: {error}"
        );
        assert!(
            decode_signed_transaction(&alternate).is_err(),
            "the bridge must reject every noncanonical instruction alias"
        );
    }
    #[test]
    fn generated_signed_transaction_versioned_bytes_prefix_bare_payload() {
        let _scope = super::test_support::ChainDiscriminantScope::enter(FIXTURE_CHAIN_DISCRIMINANT);
        let keypair = fixture_key_pair();
        let authority = AccountId::new(keypair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            fixture_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1));
        let tx = builder.sign(keypair.private_key());
        let versioned = tx.encode_versioned();
        let bare = norito::codec::encode_adaptive(&tx);
        assert_eq!(versioned.first().copied(), Some(1));
        assert_eq!(&versioned[1..], bare.as_slice());
    }
}
#[cfg(test)]
mod da_proof_summary_tests {
    use super::*;
    use std::{fs, path::Path};
    #[test]
    fn da_proof_summary_via_ffi() {
        let (manifest_bytes, payload) = sample_manifest_bytes();
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_da_proof_summary(
                manifest_bytes.as_ptr(),
                manifest_bytes.len() as c_ulong,
                payload.as_ptr(),
                payload.len() as c_ulong,
                2,
                0,
                ptr::null(),
                0,
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(status, 0, "da proof summary call failed");
        assert!(!out_ptr.is_null());
        let summary_bytes = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        connect_norito_free(out_ptr);
        let value: JsonValue = norito::json::from_slice(&summary_bytes).expect("json summary");
        assert!(value.get("proofs").is_some(), "missing proofs array");
        assert!(
            value.get("blob_hash_hex").is_some(),
            "missing blob hash field"
        );
    }
    fn sample_manifest_bytes() -> (Vec<u8>, Vec<u8>) {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .join("fixtures/da/reconstruct/rs_parity_v1");
        let manifest_hex = fs::read_to_string(fixture_root.join("manifest.norito.hex"))
            .expect("read shared DA manifest fixture");
        let manifest_bytes = hex::decode(manifest_hex).expect("decode shared DA manifest fixture");
        let payload =
            fs::read(fixture_root.join("payload.bin")).expect("read shared DA payload fixture");
        (manifest_bytes, payload)
    }
}
#[cfg(test)]
mod manifest_boundary_tests {
    /// Crate manifest whose dependency edges ship in every native SDK library.
    const BRIDGE_MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

    /// Returns every dependency name declared in any `*dependencies` table,
    /// including target-specific tables and dotted `name.workspace = true` keys.
    fn declared_dependency_names(manifest: &str) -> Vec<String> {
        let mut in_dependency_table = false;
        let mut names = Vec::new();
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_dependency_table = line.ends_with("dependencies]");
                continue;
            }
            if !in_dependency_table || line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, _)) = line.split_once('=') {
                let name = key.split('.').next().unwrap_or(key).trim();
                names.push(name.trim_matches('"').to_owned());
            }
        }
        names
    }

    #[test]
    fn dependency_name_parser_reads_every_dependency_table_and_skips_other_keys() {
        let manifest = r#"
[package]
name = "bridge"
[dependencies]
# comment = "ignored"
alpha = { workspace = true }
beta.workspace = true
[dev-dependencies]
gamma = "1"
[features]
delta = []
[target.'cfg(unix)'.dependencies]
"epsilon" = "0.1"
"#;
        assert_eq!(
            declared_dependency_names(manifest),
            ["alpha", "beta", "gamma", "epsilon"]
        );
    }

    #[test]
    fn native_bridge_links_owner_crates_without_the_rust_client_sdk() {
        let names = declared_dependency_names(BRIDGE_MANIFEST);
        for owner in ["iroha_data_model", "iroha_crypto", "norito", "jni"] {
            assert!(
                names.iter().any(|name| name == owner),
                "bridge manifest parser lost owner dependency {owner}: {names:?}"
            );
        }
        // The SDK FFI surface links data-model, crypto and proof owners directly;
        // the Rust client SDK and its Torii route surface never ship in it.
        assert!(
            !names.iter().any(|name| name == "iroha"),
            "connect_norito_bridge must not depend on the iroha client SDK: {names:?}"
        );
    }
}
