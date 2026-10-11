//! Norito and JSON roundtrip tests for ZK envelope types.
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
#[test]
fn norito_roundtrip_open_verify_envelope() {
    let mut vk = [0u8; 32];
    vk[0] = 1;
    vk[31] = 2;
    let env = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: "poly-open".to_string(),
        vk_hash: vk,
        public_inputs: vec![1, 2, 3, 4, 5],
        proof_bytes: vec![9, 8, 7],
        aux: br#"{"hint":"toy"}"#.to_vec(),
    };
    // Header-framed Norito roundtrip using archived access + deserialize
    let bytes = norito::to_bytes(&env).expect("encode");
    let archived = norito::from_bytes::<OpenVerifyEnvelope>(&bytes).expect("archived");
    let got = norito::core::DeserializePayload::deserialize(archived);
    assert_eq!(got, env);
}
#[test]
fn json_roundtrip_open_verify_envelope() {
    let env = OpenVerifyEnvelope::new(
        BackendTag::NativePipaRPasta,
        "plonk-std",
        [0u8; 32],
        vec![0xAA, 0xBB],
        vec![0xCC, 0xDD],
    );
    let s = norito::json::to_json(&env).expect("to json");
    let got: OpenVerifyEnvelope = norito::json::from_str(&s).expect("from json");
    assert_eq!(got, env);
}
