//! Genuine admitted confidential-relation proofs for generic records and events.
//!
//! The deterministic wallet openings and tree are synthetic local statements,
//! never ledger-authorized roots. Only generic verification/storage is exercised;
//! these fixtures confer no execution or value-transfer authority.
use iroha_core_zk::{
    self as zk,
    confidential::{ConfidentialProver, ConfidentialTree},
    confidential_v2::{
        ConfidentialUnshieldInputV2, compute_confidential_merkle_path_v2,
        confidential_unshield_v2_vk_record, default_confidential_diversifier_v2,
        derive_confidential_note_v2, derive_confidential_owner_tag_v2_with_diversifier,
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    asset::AssetDefinitionId,
    block::BlockHeader,
    isi::verifying_keys,
    proof::{ProofAttachment, ProofBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::{NativePipaRProofV1, OpenVerifyEnvelope},
};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

pub(super) fn confidential_attachment(
    statement: &str,
    vk_name: &str,
) -> (ProofAttachment, verifying_keys::RegisterVerifyingKey) {
    // Reuse the exact generated native bytes for repeated statement identities.
    // The production prover supplies its own cryptographic randomness.
    static PROOFS: OnceLock<Mutex<BTreeMap<String, (ProofBox, VerifyingKeyRecord)>>> =
        OnceLock::new();
    let mut proofs = PROOFS
        .get_or_init(Mutex::default)
        .lock()
        .expect("fixture cache");
    let (proof, record) = proofs
        .entry(statement.to_owned())
        .or_insert_with(|| {
            let spend_key = Zeroizing::new([0x31; 32]);
            let network_id =
                NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                    Hash::new(b"generic-proof-local-tree"),
                ));
            let asset = AssetDefinitionId::from_uuid_bytes([
                1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
            ])
            .expect("fixture asset identity");
            let mut rho = [0; 32];
            rho[..16].copy_from_slice(&Hash::new(statement).as_ref()[..16]);
            let input = ConfidentialUnshieldInputV2 {
                amount: 9,
                rho,
                diversifier: default_confidential_diversifier_v2(),
                leaf_index: 0,
            };
            let owner = derive_confidential_owner_tag_v2_with_diversifier(
                spend_key.as_ref(),
                input.diversifier,
            )
            .expect("native owner tag");
            let commitment =
                derive_confidential_note_v2(&asset.to_string(), input.amount, input.rho, owner)
                    .expect("native note commitment");
            let path = compute_confidential_merkle_path_v2(&[commitment], 0)
                .expect("native full-depth membership path");
            let paths = [path];
            let result = ConfidentialProver::new(network_id, &asset, spend_key)
                .expect("local prover")
                .prove_unshield(
                    ConfidentialTree::Paths {
                        root: paths[0].root,
                        paths: &paths,
                    },
                    vec![input],
                    9,
                    None,
                )
                .expect("genuine complete confidential relation");
            assert_eq!(result.relation, zk::ProofRelation::ConfidentialFullUnshield);
            assert_eq!(result.root, paths[0].root);
            assert_eq!(result.nullifiers.len(), 1);
            assert!(result.output_commitments.is_empty());
            let record = confidential_unshield_v2_vk_record("integration", 1)
                .expect("canonical confidential registry key");
            let envelope: OpenVerifyEnvelope =
                norito::decode_canonical(&result.proof.bytes).expect("canonical wallet envelope");
            let schema_hash: [u8; 32] = Hash::new(&envelope.public_inputs).into();
            assert_eq!(schema_hash, record.public_inputs_schema_hash);
            assert_eq!(envelope.vk_hash, record.commitment);
            assert_eq!(envelope.circuit_id, record.circuit_id);
            assert!(zk::verify_backend(
                &result.proof.backend,
                &result.proof,
                record.key.as_ref()
            ));
            (result.proof, record)
        })
        .clone();
    let id = VerifyingKeyId::new(&proof.backend, vk_name);
    (
        ProofAttachment::new_ref(proof.backend.clone(), proof, id.clone()),
        verifying_keys::RegisterVerifyingKey { id, record },
    )
}

pub(super) fn rejected_confidential_attachment(statement: &str, vk_name: &str) -> ProofAttachment {
    let (mut attachment, _) = confidential_attachment(statement, vk_name);
    attachment.proof = corrupt_native_proof(&attachment.proof);
    attachment
}

pub(super) fn corrupt_native_proof(proof: &ProofBox) -> ProofBox {
    let mut envelope: OpenVerifyEnvelope =
        norito::decode_canonical(&proof.bytes).expect("canonical genuine native envelope");
    // Preserve the canonical carrier, exact public column, schema and key while
    // corrupting only one byte of the native transcript.
    let mut carrier: NativePipaRProofV1 =
        norito::decode_canonical(&envelope.proof_bytes).expect("canonical native proof carrier");
    assert!(!carrier.proof.is_empty());
    let middle = carrier.proof.len() / 2;
    carrier.proof[middle] ^= 1;
    envelope.proof_bytes = norito::encode_canonical(&carrier).expect("canonical damaged carrier");
    ProofBox::new(
        proof.backend.clone(),
        norito::encode_canonical(&envelope).expect("canonical damaged proof"),
    )
}

#[test]
fn confidential_fixtures_verify_and_reject_only_native_proof_corruption() {
    let (valid, registration) = confidential_attachment("native-control", "native_control_vk");
    let invalid = rejected_confidential_attachment("native-control", "native_control_vk");
    let key = registration
        .record
        .key
        .as_ref()
        .expect("inline canonical key");
    assert!(zk::verify_backend(
        &valid.proof.backend,
        &valid.proof,
        Some(key)
    ));
    assert!(!zk::verify_backend(
        &invalid.proof.backend,
        &invalid.proof,
        Some(key)
    ));
    let valid_env: OpenVerifyEnvelope = norito::decode_canonical(&valid.proof.bytes).unwrap();
    let invalid_env: OpenVerifyEnvelope = norito::decode_canonical(&invalid.proof.bytes).unwrap();
    assert_eq!(
        valid_env.circuit_id,
        zk::confidential_v2::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID
    );
    assert_eq!(valid_env.public_inputs, invalid_env.public_inputs);
    let valid_carrier: NativePipaRProofV1 =
        norito::decode_canonical(&valid_env.proof_bytes).unwrap();
    let invalid_carrier: NativePipaRProofV1 =
        norito::decode_canonical(&invalid_env.proof_bytes).unwrap();
    assert_eq!(valid_carrier.public_inputs, invalid_carrier.public_inputs);
    assert_eq!(valid_carrier.proof.len(), invalid_carrier.proof.len());
    assert_eq!(
        valid_carrier
            .proof
            .iter()
            .zip(&invalid_carrier.proof)
            .filter(|(a, b)| a != b)
            .count(),
        1
    );
    assert_eq!(valid_env.vk_hash, invalid_env.vk_hash);
    assert_eq!(valid_env.circuit_id, invalid_env.circuit_id);
    assert_eq!(valid_env.proof_bytes.len(), invalid_env.proof_bytes.len());
    assert_ne!(valid_env.proof_bytes, invalid_env.proof_bytes);
    assert_eq!(valid.vk_ref, invalid.vk_ref);
    assert!(valid.proof.bytes.len() <= registration.record.max_proof_bytes as usize);
}
