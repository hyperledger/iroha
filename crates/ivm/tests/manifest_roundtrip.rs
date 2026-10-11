//! Round-trip coverage for the complete canonical contract manifest.
use iroha_crypto::Hash;
use iroha_data_model::smart_contract::manifest::{
    AccessSetHints, ContractErrorMessage, ContractErrorTypeDescriptor,
    ContractErrorVariantDescriptor, ContractManifest,
};
#[test]
fn contract_manifest_roundtrip_norito() {
    let manifest = ContractManifest {
        permissions: Vec::new(),
        events: Vec::new(),
        seiyaku_name: None,
        code_hash: Some(Hash::new(b"code-hash")),
        abi_hash: Some(Hash::new(b"abi-hash")),
        compiler_fingerprint: Some("kotodama-0.1.0".to_string()),
        features_bitmap: Some(0b1010_0001),
        access_set_hints: Some(AccessSetHints {
            read_keys: vec![
                "account:sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV".to_string(),
            ],
            write_keys: vec!["asset:62Fk4FPcMuLvW5QjDGNF2a4jAmjM".to_string()],
            dynamic_reads: Vec::new(),
            dynamic_writes: Vec::new(),
        }),
        entrypoints: None,
        states: None,
        kotoba: None,
        error_messages: Some(vec![ContractErrorMessage {
            error_type: "Vault::Failure".into(),
            code: 1,
            message: "残高が不足しています".into(),
        }]),
        error_types: Some(vec![ContractErrorTypeDescriptor {
            identity: "Vault::Failure".into(),
            variants: vec![ContractErrorVariantDescriptor {
                name: "Insufficient".into(),
                code: 1,
            }],
        }]),
        enum_types: Vec::new(),
        provenance: None,
    };
    let bytes = norito::to_bytes(&manifest).expect("encode manifest");
    let decoded: ContractManifest = norito::decode_from_bytes(&bytes).expect("decode manifest");
    assert_eq!(decoded, manifest);
    let json = norito::json::to_json(&manifest).expect("encode manifest JSON");
    let decoded: ContractManifest = norito::json::from_str(&json).expect("decode manifest JSON");
    assert_eq!(decoded, manifest);
}
