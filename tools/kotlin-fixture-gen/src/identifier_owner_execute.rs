//! Native evaluator/signature DATA for SDK execute consistency tests.
//! All seeds and inputs below are public test data. This is no admission evidence.

use iroha_crypto::{
    Algorithm, ClientRequest, Hash, HashOf, KeyPair, RamLfeBackend, RamLfeVerificationMode,
    SignatureOf, evaluate_commitment, identifier_hashes_from_output_hash, policy_commitment,
    ram_lfe_output_hash,
};
use iroha_data_model::{
    NetworkId,
    identifier::{
        hkdf_identifier_execution_metadata_v1, hkdf_identifier_input_commitment_v1,
        hkdf_identifier_request_payload_v1,
    },
    ram_lfe::{RamLfeExecutionReceiptPayload, RamLfeProgramId},
};
use norito::{json, json::Value};

const NORMALIZED_INPUT: &str = "public-fixture@example.org";
const PUBLIC_POLICY_SECRET: &[u8] = b"identifier-owner-execute-v1-public-software-DATA-policy";
const PUBLIC_SIGNING_SEED: &[u8] = b"identifier-owner-execute-v1-public-software-DATA-resolver";
const NONCE: [u8; 32] = [0x12; 32];

fn fixture() -> Value {
    let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"identifier-owner-execute-v1-public-DATA-network",
    )));
    let program: RamLfeProgramId = "identifier_lookup_retail".parse().expect("program DATA");
    let mut program_frame = Vec::new();
    norito::core::write_canonical_to_writer(&program, &mut program_frame)
        .expect("native canonical program frame");
    assert!(!program_frame.is_empty() && program_frame.len() <= 4096);
    let decoded: RamLfeProgramId =
        norito::decode_canonical(&program_frame).expect("native canonical program round trip");
    assert_eq!(decoded, program);
    let commitment = policy_commitment(PUBLIC_POLICY_SECRET, b"public-DATA-parameters-v1".to_vec())
        .expect("native HKDF commitment");
    let request = ClientRequest {
        normalized_input: hkdf_identifier_request_payload_v1(&network, &program, NORMALIZED_INPUT)
            .expect("native owner input"),
        associated_data: program_frame.clone(),
    };
    let mut evaluated = evaluate_commitment(PUBLIC_POLICY_SECRET, &commitment, &request)
        .expect("native HKDF public DATA evaluation");
    // Mirror owner_prf: opaque32 is the output; the evaluator echo is not exposed.
    evaluated.output.fill(0);
    let opaque_output = evaluated.opaque_id.as_ref();
    let output_hash = ram_lfe_output_hash(opaque_output);
    let (opaque_hash, receipt_hash) =
        identifier_hashes_from_output_hash(&program_frame, &output_hash);
    let associated_data_hash = Hash::new(&program_frame);
    let (program_digest, parameter_digest, evaluation_key_digest) =
        hkdf_identifier_execution_metadata_v1(&commitment).expect("current HKDF metadata");
    let payload = RamLfeExecutionReceiptPayload {
        program_id: program.clone(),
        program_digest,
        backend: RamLfeBackend::HkdfSha3_512PrfV1,
        verification_mode: RamLfeVerificationMode::Signed,
        input_ciphertext_hash: hkdf_identifier_input_commitment_v1(
            &network,
            &program,
            NORMALIZED_INPUT,
            &NONCE,
        )
        .expect("native private input commitment over public DATA"),
        output_ciphertext_hash: output_hash,
        parameter_digest,
        evaluation_key_digest,
        output_hash,
        associated_data_hash,
        executed_at_ms: 1_735_000_000_000,
        expires_at_ms: Some(1_735_000_060_000),
    };
    let resolver = KeyPair::from_seed(PUBLIC_SIGNING_SEED.to_vec(), Algorithm::Ed25519);
    let signature =
        SignatureOf::<RamLfeExecutionReceiptPayload>::new(resolver.private_key(), &payload);
    signature
        .verify(resolver.public_key(), &payload)
        .expect("genuine DATA signature");
    let mut changed = payload.clone();
    changed.output_hash = Hash::new(b"tampered-output-DATA");
    assert!(signature.verify(resolver.public_key(), &changed).is_err());
    let mut canonical_payload = Vec::new();
    norito::codec::encode_adaptive_into(&payload, &mut canonical_payload)
        .expect("native signature payload bytes");
    let prehash: Hash = HashOf::new(&payload).into();
    assert_eq!(Hash::new(&canonical_payload), prehash);
    let public_payload = json!({
        "program_id": (program.to_string()), "program_digest": (hex::encode(program_digest.as_ref())),
        "backend": "hkdf-sha3-512-prf-v1", "verification_mode": "signed",
        "input_ciphertext_hash": (hex::encode(payload.input_ciphertext_hash.as_ref())),
        "output_ciphertext_hash": (hex::encode(output_hash.as_ref())),
        "parameter_digest": (hex::encode(parameter_digest.as_ref())),
        "evaluation_key_digest": (hex::encode(evaluation_key_digest.as_ref())),
        "output_hash": (hex::encode(output_hash.as_ref())),
        "associated_data_hash": (hex::encode(associated_data_hash.as_ref())),
        "executed_at_ms": (payload.executed_at_ms),
        "expires_at_ms": (payload.expires_at_ms),
    });
    json!({
        "schema": "iroha.identifier.owner-execute.v1",
        "classification": "PUBLIC_SOFTWARE_DATA_UNADMITTED",
        "network_id": (hex::encode(network.as_bytes())),
        "normalized_input": (NORMALIZED_INPUT), "input_nonce": (hex::encode(NONCE)),
        "resolver_public_key": (resolver.public_key().to_string()),
        "canonical_execution_payload_hex": (hex::encode_upper(canonical_payload)),
        "execution_prehash_hex": (hex::encode(HashOf::new(&payload).as_ref())),
        "response": {
            "program_id": (program.to_string()),
            "program_id_canonical": (hex::encode_upper(program_frame)),
            "opaque_hash": (hex::encode(opaque_hash.as_ref())),
            "receipt_hash": (hex::encode(receipt_hash.as_ref())),
            "opaque_output": (hex::encode_upper(opaque_output)),
            "output_hash": (hex::encode(output_hash.as_ref())),
            "associated_data_hash": (hex::encode(associated_data_hash.as_ref())),
            "executed_at_ms": (payload.executed_at_ms),
            "expires_at_ms": (payload.expires_at_ms),
            "backend": "hkdf-sha3-512-prf-v1", "verification_mode": "signed",
            "receipt": {
                "payload": (public_payload),
                "attestation": {"kind": "signed", "signature": (hex::encode_upper(signature.payload()))},
            },
        },
    })
}

pub(crate) fn emit() {
    println!(
        "{}",
        norito::json::to_json(&fixture()).expect("public execute DATA JSON")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_public_data_fixture_is_deterministic() {
        let first = norito::json::to_json(&fixture()).unwrap();
        assert_eq!(first, norito::json::to_json(&fixture()).unwrap());
        let parsed: Value = norito::json::from_str(&first).unwrap();
        assert_eq!(
            parsed.get("classification").unwrap().as_str(),
            Some("PUBLIC_SOFTWARE_DATA_UNADMITTED")
        );
    }
}
