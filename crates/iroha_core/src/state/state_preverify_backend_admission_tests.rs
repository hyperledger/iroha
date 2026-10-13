//! Current State preverification originals, fixed native keys and dedup publication.
//! Lightweight acceptance never establishes cryptographic verification.
use super::*;
use crate::{kura::Kura, zk::PreverifyResult};
use iroha_data_model::{
    block::BlockHeader,
    proof::{ProofBox, VerifyingKeyBox},
    zk::{BackendTag, OpenVerifyEnvelope},
};
use std::{num::NonZeroU64, sync::Arc};

fn test_state() -> State {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    State::new_for_testing(World::default(), Arc::clone(&kura), query)
}
fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0)
}
fn native_originals() -> (ProofBox, VerifyingKeyBox) {
    let original = crate::zk::test_utils::native_confidential_fixture_envelope();
    let backend = crate::zk::ZK_BACKEND_NATIVE_PIPA_R;
    (
        original.proof_box(backend),
        original.vk_box(backend).unwrap(),
    )
}
fn assert_unseen(transaction: &StateTransaction<'_, '_>, proof: &ProofBox, commitment: [u8; 32]) {
    // Observation is confined to this bounded test, never the production path.
    let mut observed = transaction.zk_dedup.clone();
    assert!(observed.check_and_insert_with_commitment(proof, Some(commitment)));
}

#[test]
fn unsupported_retired_and_claimed_backends_fail_state_admission() {
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    // These retired names are explicit denylist inputs, never dispatch aliases.
    for backend in [
        "halo2/ipa",
        "halo2/bn254",
        "halo2/bn254/vote",
        "halo2/kzg",
        "halo2/debug",
        "halo2/mock",
        "halo2/unknown-native-v1",
        "halo2/ipa:ivm-replay-binding-v1",
        "halo2/ipa:production-ready",
        "halo2/ipa:claimed-mainnet",
        "pipa-r/pasta:production-ready",
        "pipa-r/pasta/unreviewed",
    ] {
        let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
        for active in [false, true] {
            assert_eq!(
                transaction
                    .preverify_proof(&proof, None, 0, None, None, active)
                    .expect("preverification must complete for this semantic fixture"),
                PreverifyResult::UnsupportedBackend,
                "backend admission must precede key activity: {backend}, active={active}"
            );
            let mut observed = transaction.zk_dedup.clone();
            assert!(observed.check_and_insert_with_commitment(&proof, None));
        }
    }
}

#[test]
fn stark_fri_profile_labels_require_enveloped_state_preverify_metadata() {
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    let backend = crate::zk::ZK_BACKEND_STARK_FRI_V1;
    // This case exercises lightweight framing only; the separate genuine
    // STARK case below supplies the actual fixed native verifier/proof.
    let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xA5, 0x5A, 0xC3]);
    let commitment = crate::zk::hash_vk(&vk);
    let raw = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
    assert_eq!(
        transaction
            .preverify_proof(&raw, Some(&vk), 0, Some(commitment), Some(commitment), true)
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::MalformedProof
    );
    assert_unseen(&transaction, &raw, commitment);
    let envelope = OpenVerifyEnvelope {
        backend: BackendTag::Stark,
        circuit_id: format!("{backend}:state-preverify-test"),
        vk_hash: commitment,
        public_inputs: vec![0x55; 32],
        proof_bytes: vec![0xAA, 0xBB, 0xCC],
        aux: Vec::new(),
    };
    let proof = ProofBox::new(
        backend.to_owned(),
        norito::encode_canonical(&envelope).unwrap(),
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&vk),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Accepted
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&vk),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Duplicate
    );
}

#[test]
fn native_compiled_descriptor_refusal_preserves_key_admission_and_original_retry() {
    let (proof, key) = native_originals();
    assert!(
        crate::zk::verify_backend(&proof.backend, &proof, Some(&key))
            .expect("completed native verification")
    );
    let envelope: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
    let original: crate::zk::native_pipa_r::CompiledVerifyingKeyV1 =
        norito::decode_canonical(&key.bytes).unwrap();
    assert!(!original.descriptor.is_empty());
    assert!(!original.key.is_empty());
    let mut changed_descriptor = original.clone();
    changed_descriptor.descriptor[0] ^= 1;
    let mut changed_key = original.clone();
    changed_key.key[0] ^= 1;
    let mut no_descriptor = original.clone();
    no_descriptor.descriptor.clear();
    let mut trailing = key.bytes.clone();
    trailing.push(0);
    let foreign_relation =
        crate::zk::native_pipa_r::kaigi_verifying_key(kaigi_zk::native::NativeRelationV1::Usage)
            .unwrap();
    let cases = [
        (
            "descriptor",
            norito::encode_canonical(&changed_descriptor).unwrap(),
        ),
        (
            "processed key",
            norito::encode_canonical(&changed_key).unwrap(),
        ),
        (
            "missing descriptor",
            norito::encode_canonical(&no_descriptor).unwrap(),
        ),
        ("bare processed key", original.key),
        ("trailing bytes", trailing),
        ("foreign relation", foreign_relation.bytes),
        (
            "bounded original",
            vec![0; crate::zk::native_pipa_r::MAX_KEY_BYTES + 1],
        ),
    ];
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    for (case, bytes) in cases {
        let foreign = VerifyingKeyBox::new(proof.backend.clone(), bytes);
        let commitment = crate::zk::hash_vk(&foreign);
        let mut rehashed = envelope.clone();
        rehashed.vk_hash = commitment;
        let original_foreign = ProofBox::new(
            proof.backend.clone(),
            norito::encode_canonical(&rehashed).unwrap(),
        );
        // The original CoreZK metadata preflight accepts these consistently
        // bound originals. HC146 therefore really removes the only State
        // compiled-material check, rather than exercising another refusal.
        assert!(
            matches!(
                crate::zk::preverify_with_budget(
                    &original_foreign,
                    Some(&foreign),
                    &mut crate::zk::DedupCache::new(),
                    0,
                    Some(commitment),
                    Some(commitment),
                    true,
                ),
                Ok(PreverifyResult::Accepted)
            ),
            "metadata preflight for {case}"
        );
        assert_eq!(
            transaction
                .preverify_proof(
                    &original_foreign,
                    Some(&foreign),
                    0,
                    Some(commitment),
                    Some(commitment),
                    false,
                )
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::VerifyingKeyInactive,
            "inactive-key order for {case}"
        );
        assert_eq!(
            transaction
                .preverify_proof(&original_foreign, Some(&foreign), 0, None, None, true)
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::VerifyingKeyMissing,
            "bound-key admission order for {case}"
        );
        for _ in 0..2 {
            assert_eq!(
                transaction
                    .preverify_proof(
                        &original_foreign,
                        Some(&foreign),
                        0,
                        Some(commitment),
                        Some(commitment),
                        true,
                    )
                    .expect("preverification must complete for this semantic fixture"),
                PreverifyResult::VerifyingKeyMismatch,
                "compiled original refusal for {case}"
            );
            assert_unseen(&transaction, &original_foreign, commitment);
        }
    }
    let commitment = crate::zk::hash_vk(&key);
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Accepted,
        "the exact original compiled key remains admitted"
    );
    assert_eq!(
        transaction
            .preverify_proof(&proof, Some(&key), 0, None, Some(commitment), true)
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Duplicate,
        "resolved and supplied bound commitments have the identical dedup preimage"
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                false
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::VerifyingKeyInactive,
        "already cached originals must still recheck key activity"
    );
}

#[test]
fn native_state_payload_caps_commitments_and_metadata_precede_dedup_publication() {
    let (proof, key) = native_originals();
    let commitment = crate::zk::hash_vk(&key);
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    let empty = ProofBox::new(proof.backend.clone(), Vec::new());
    assert_eq!(
        transaction
            .preverify_proof(&empty, Some(&key), 0, None, None, false)
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::MalformedProof,
        "empty State payload refusal remains first"
    );
    transaction.zk.preverify_max_bytes = proof.bytes.len() - 1;
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                false
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::ProofTooBig,
        "State payload cap precedes key activity"
    );
    assert_unseen(&transaction, &proof, commitment);
    transaction.zk.preverify_max_bytes = proof.bytes.len();
    transaction.zk.preverify_budget_bytes = (proof.bytes.len() - 1) as u64;
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                false
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::PreverifyBudgetExceeded,
        "State byte budget precedes key activity"
    );
    assert_unseen(&transaction, &proof, commitment);
    transaction.zk.preverify_budget_bytes = 0;
    for (supplied, expected, refusal) in [
        (None, None, PreverifyResult::VerifyingKeyMissing),
        (
            Some([0; 32]),
            Some(commitment),
            PreverifyResult::VerifyingKeyMismatch,
        ),
        (
            Some(commitment),
            Some([0; 32]),
            PreverifyResult::VerifyingKeyMismatch,
        ),
        (
            Some([1; 32]),
            Some(commitment),
            PreverifyResult::VerifyingKeyMismatch,
        ),
    ] {
        assert_eq!(
            transaction
                .preverify_proof(&proof, Some(&key), 0, supplied, expected, true)
                .expect("preverification must complete for this semantic fixture"),
            refusal
        );
        assert_unseen(&transaction, &proof, commitment);
    }
    let original: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
    let mut schema = original.clone();
    schema.public_inputs[0] ^= 1;
    let mut auxiliary = original.clone();
    auxiliary.aux.push(1);
    let mut relation = original.clone();
    relation.circuit_id = "pipa-r/pasta/unreviewed".into();
    for changed in [schema, auxiliary, relation] {
        let changed = ProofBox::new(
            proof.backend.clone(),
            norito::encode_canonical(&changed).unwrap(),
        );
        // Metadata growth remains inside the test's explicit State payload cap.
        transaction.zk.preverify_max_bytes = changed.bytes.len().max(proof.bytes.len());
        assert_eq!(
            transaction
                .preverify_proof(
                    &changed,
                    Some(&key),
                    0,
                    Some(commitment),
                    Some(commitment),
                    false
                )
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::VerifyingKeyInactive
        );
        assert_eq!(
            transaction
                .preverify_proof(
                    &changed,
                    Some(&key),
                    0,
                    Some(commitment),
                    Some(commitment),
                    true
                )
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::MalformedProof
        );
        assert_unseen(&transaction, &changed, commitment);
    }
    transaction.zk.preverify_budget_bytes = proof.bytes.len() as u64;
    assert_eq!(
        transaction
            .preverify_proof(&proof, Some(&key), 0, None, Some(commitment), true)
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Accepted
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Duplicate
    );
}

#[cfg(feature = "zk-stark")]
#[test]
fn genuine_stark_originals_preserve_independent_admission_and_key_activity() {
    let fixture = crate::zk::test_utils::stark_public_binding_fixture_envelope();
    let backend = crate::zk::ZK_BACKEND_STARK_FRI_V1;
    let proof = fixture.proof_box(backend);
    let key = fixture.vk_box(backend).unwrap();
    assert!(
        crate::zk::verify_backend(backend, &proof, Some(&key))
            .expect("completed STARK verification")
    );
    let commitment = crate::zk::hash_vk(&key);
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                false
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::VerifyingKeyInactive
    );
    assert_unseen(&transaction, &proof, commitment);
    assert_eq!(
        transaction
            .preverify_proof(&proof, Some(&key), 0, None, Some(commitment), true)
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Accepted
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::Duplicate
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                false
            )
            .expect("preverification must complete for this semantic fixture"),
        PreverifyResult::VerifyingKeyInactive
    );
}

#[test]
fn retired_ipa_profile_labels_refuse_even_native_envelope() {
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    let (original, key) = native_originals();
    let commitment = crate::zk::hash_vk(&key);
    let proof = ProofBox::new("halo2/ipa:ivm-replay-binding-v1".into(), original.bytes);
    for active in [false, true] {
        assert_eq!(
            transaction
                .preverify_proof(&proof, None, 0, Some(commitment), Some(commitment), active)
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::UnsupportedBackend,
            "an exact native envelope cannot authorize a retired backend alias"
        );
        assert_unseen(&transaction, &proof, commitment);
    }
}

#[test]
fn native_and_stark_key_refusals_preserve_original_dedup_for_retry() {
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    for backend in [
        crate::zk::ZK_BACKEND_NATIVE_PIPA_R,
        crate::zk::ZK_BACKEND_STARK_FRI_V1,
    ] {
        // Deliberately malformed originals test refusal ordering, not verifier success.
        let proof = ProofBox::new(backend.to_owned(), vec![1, 2, 3, 4]);
        let vk = VerifyingKeyBox::new(backend.to_owned(), vec![0xA5, 0x5A, 0xC3]);
        let commitment = crate::zk::hash_vk(&vk);
        assert_eq!(
            transaction
                .preverify_proof(&proof, None, 0, None, None, true)
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::VerifyingKeyMissing,
        );
        assert_unseen(&transaction, &proof, commitment);
        assert_eq!(
            transaction
                .preverify_proof(
                    &proof,
                    Some(&vk),
                    0,
                    Some(commitment),
                    Some(commitment),
                    false
                )
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::VerifyingKeyInactive,
        );
        assert_unseen(&transaction, &proof, commitment);
        let mut foreign_commitment = commitment;
        foreign_commitment[0] ^= 1;
        assert_eq!(
            transaction
                .preverify_proof(
                    &proof,
                    Some(&vk),
                    0,
                    Some(commitment),
                    Some(foreign_commitment),
                    true
                )
                .expect("preverification must complete for this semantic fixture"),
            PreverifyResult::VerifyingKeyMismatch,
        );
        assert_unseen(&transaction, &proof, commitment);
        for _ in 0..2 {
            assert_eq!(
                transaction
                    .preverify_proof(
                        &proof,
                        Some(&vk),
                        0,
                        Some(commitment),
                        Some(commitment),
                        true
                    )
                    .expect("preverification must complete for this semantic fixture"),
                PreverifyResult::MalformedProof,
                "{backend} must recheck the unchanged original envelope on retry",
            );
            assert_unseen(&transaction, &proof, commitment);
        }
    }
}

#[test]
fn original_state_preverify_refusal_does_not_publish_dedup_and_retries() {
    let (proof, key) = native_originals();
    let bytes = proof.bytes.clone();
    let commitment = crate::zk::hash_vk(&key);
    let state = test_state();
    let mut block = state.block(header());
    let mut transaction = block.transaction();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let original = norito::with_decode_limits_scope(limits, || {
        transaction.preverify_proof(
            &proof,
            Some(&key),
            0,
            Some(commitment),
            Some(commitment),
            true,
        )
    })
    .unwrap_err();
    let captured = original.decode_refusal().unwrap().clone();
    assert_unseen(&transaction, &proof, commitment);
    norito::with_decode_limits_scope(limits, || {
        assert_eq!(original.decode_refusal(), Some(&captured))
    });
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .unwrap(),
        PreverifyResult::Accepted
    );
    assert_eq!(
        transaction
            .preverify_proof(
                &proof,
                Some(&key),
                0,
                Some(commitment),
                Some(commitment),
                true
            )
            .unwrap(),
        PreverifyResult::Duplicate
    );
    assert_eq!(proof.bytes, bytes);
}

#[test]
fn proof_quota_preflight_is_nonmutating_and_registration_preserves_limits() {
    let state = test_state();
    let mut block = state.block(header());
    let mut tx = block.transaction();
    tx.zk.max_verify_calls_per_tx = 1;
    tx.check_confidential_proof(16).unwrap();
    assert_eq!(
        (
            tx.zk_confidential_ops_in_tx,
            tx.zk_verify_calls_in_tx,
            tx.zk_proof_bytes_in_tx
        ),
        (0, 0, 0)
    );
    tx.register_confidential_proof(16).unwrap();
    let completed = (
        tx.zk_confidential_ops_in_tx,
        tx.zk_verify_calls_in_tx,
        tx.zk_proof_bytes_in_tx,
    );
    assert_eq!(completed, (1, 1, 16));
    let before = tx.check_confidential_proof(1).unwrap_err();
    let during = tx.register_confidential_proof(1).unwrap_err();
    assert_eq!(before, during);
    assert_eq!(
        (
            tx.zk_confidential_ops_in_tx,
            tx.zk_verify_calls_in_tx,
            tx.zk_proof_bytes_in_tx
        ),
        completed
    );
}
