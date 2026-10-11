//! One immutable body keeps its full source/consistency admission and fresh signature checks.

use super::*;
use norito::core::DecodeBudgetContext;

// The complete pre-change tail is an independent active-owner and refusal-order oracle.
#[inline(never)]
fn original_finish_attestation(
    view: &impl StateReadOnly,
    status: SumeragiStatus,
    identity: &NodeIdentity,
    build_fingerprint: Hash,
    challenge: [u8; 32],
    signer: &KeyPair,
    proofs: AttestationProofs,
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    use AttestationBuildError as Error;
    let chain = CertifiedChain::new(view).map_err(|error| Error::FinalityProof(error.into()))?;
    if status.instance != chain.instance().0 {
        return Err(Error::InvalidStatus);
    }
    // Only a height mismatch after successful proof and identity validation is retryable.
    if status.applied_height != proofs.committed || status.committed_height != proofs.committed {
        return Err(Error::StatusHeightMismatch);
    }
    let observed_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|reading| u64::try_from(reading.as_millis()).ok())
        .filter(|reading| *reading != 0)
        .ok_or(Error::ClockUnavailable)?;
    let body = SumeragiFinalityAttestationBody {
        challenge,
        observed_at_unix_ms,
        network_id: *view.network_id(),
        node_id: identity.node_id.clone(),
        node_fingerprint: Hash::new(identity.node_id.encode()),
        build_fingerprint,
        config_fingerprint: identity.config_fingerprint,
        genesis_block_hash: proofs.genesis_block_hash,
        genesis_finality_proof: proofs.genesis,
        status,
        finality_proof: proofs.tip,
    };
    body.validate_consistency().map_err(Error::InvalidBody)?;
    let signature = SignatureOf::try_from_hash(signer.private_key(), body.signing_hash())
        .map_err(|error| Error::Signing(error.to_string()))?;
    let attestation = SumeragiFinalityAttestation { body, signature };
    attestation.verify().map_err(Error::InvalidBody)?;
    Ok(attestation)
}

#[inline(never)]
fn finish_selected(
    view: &impl StateReadOnly,
    chain: &CertifiedTestChain,
    original: &SumeragiFinalityAttestation,
    challenge: [u8; 32],
    signer: &KeyPair,
    prior_recipe: bool,
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    let identity = NodeIdentity {
        node_id: original.body.node_id.clone(),
        config_fingerprint: original.body.config_fingerprint,
    };
    let proofs = AttestationProofs {
        committed: chain.height(),
        genesis_block_hash: original.body.genesis_block_hash,
        tip: original.body.finality_proof.clone(),
        genesis: original.body.genesis_finality_proof.clone(),
    };
    if prior_recipe {
        original_finish_attestation(
            view,
            status(chain),
            &identity,
            original.body.build_fingerprint,
            challenge,
            signer,
            proofs,
        )
    } else {
        finish_attestation(
            view,
            status(chain),
            &identity,
            original.body.build_fingerprint,
            challenge,
            signer,
            proofs,
        )
    }
}

fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

#[test]
fn attestation_tail_retains_fresh_signature_and_body_before_signature_refusals() {
    with_chain_at(2, check_signature_and_order);
}

#[inline(never)]
fn check_signature_and_order(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = capture(&view, chain, [51; 32], status(chain)).unwrap();
    let signer = installed_signer();
    let fresh = finish_selected(&view, chain, &original, [52; 32], &signer, false).unwrap();
    assert_eq!(
        fresh.body.genesis_finality_proof,
        original.body.genesis_finality_proof
    );
    assert_eq!(fresh.body.finality_proof, original.body.finality_proof);
    assert_eq!(fresh.body.challenge, [52; 32]);
    assert_ne!(fresh.signature, original.signature);
    fresh.verify().unwrap();
    let wrong_signer = KeyPair::from_seed(vec![0xD1; 32], Algorithm::BlsNormal);
    assert_ne!(wrong_signer.public_key(), signer.public_key());
    for challenge in [[53; 32], [0; 32]] {
        let expected =
            finish_selected(&view, chain, &original, challenge, &wrong_signer, true).unwrap_err();
        let actual =
            finish_selected(&view, chain, &original, challenge, &wrong_signer, false).unwrap_err();
        assert!(matches!(actual, AttestationBuildError::InvalidBody(_)));
        assert_eq!(actual.to_string(), expected.to_string());
        if challenge == [0; 32] {
            assert_eq!(
                actual.to_string(),
                "current finality: attestation challenge, identity or durable-tip binding differs"
            );
        }
    }
    finish_selected(&view, chain, &original, [54; 32], &signer, false)
        .unwrap()
        .verify()
        .unwrap();
}

#[test]
fn attestation_tail_still_decodes_each_original_genesis_and_tip_witness() {
    with_chain_at(2, check_body_witness_refusals);
}

#[inline(never)]
fn check_body_witness_refusals(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = capture(&view, chain, [55; 32], status(chain)).unwrap();
    let signer = installed_signer();
    for mutation in 0..3 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.body.genesis_finality_proof.block_wire.push(0),
            1 => changed.body.finality_proof.block_wire.push(0),
            _ => changed.body.finality_proof.committee[0].proof_of_possession[0] ^= 1,
        }
        let expected =
            finish_selected(&view, chain, &changed, [56; 32], &signer, true).unwrap_err();
        let actual = finish_selected(&view, chain, &changed, [56; 32], &signer, false).unwrap_err();
        assert!(matches!(actual, AttestationBuildError::InvalidBody(_)));
        assert_eq!(actual.to_string(), expected.to_string());
    }
    let restored = finish_selected(&view, chain, &original, [57; 32], &signer, false).unwrap();
    assert_eq!(
        restored.body.genesis_finality_proof,
        original.body.genesis_finality_proof
    );
    assert_eq!(restored.body.finality_proof, original.body.finality_proof);
    restored.verify().unwrap();
}

#[test]
fn attestation_tail_active_owner_keeps_original_recipe_and_finite_resource_refusals() {
    with_chain_at(2, check_active_original_recipe);
}

#[inline(never)]
fn check_active_original_recipe(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = capture(&view, chain, [58; 32], status(chain)).unwrap();
    let signer = installed_signer();
    let pool = view.execution_budget();
    let reserved = pool.reserved_bytes();
    const CEILING: usize = 64 * 1024 * 1024;
    let expected_budget = DecodeBudgetContext::new(limits(CEILING));
    let expected = expected_budget
        .with(|| finish_selected(&view, chain, &original, [59; 32], &signer, true))
        .unwrap();
    let actual_budget = DecodeBudgetContext::new(limits(CEILING));
    let actual = actual_budget
        .with(|| finish_selected(&view, chain, &original, [59; 32], &signer, false))
        .unwrap();
    expected.verify().unwrap();
    actual.verify().unwrap();
    for budget in [&expected_budget, &actual_budget] {
        assert!(budget.consumed_allocated_bytes() > 1);
        assert!(budget.consumed_allocated_bytes() <= CEILING as u64);
    }
    // The actual fresh wall-clock captures may differ. All other signed values remain exact.
    let mut expected_body = expected.body;
    let mut actual_body = actual.body;
    expected_body.observed_at_unix_ms = 1;
    actual_body.observed_at_unix_ms = 1;
    assert_eq!(actual_body, expected_body);
    assert_eq!(pool.reserved_bytes(), reserved);
    for cap in [0, 1] {
        let expected_budget = DecodeBudgetContext::new(limits(cap));
        let expected = expected_budget
            .with(|| finish_selected(&view, chain, &original, [60; 32], &signer, true))
            .unwrap_err();
        let actual_budget = DecodeBudgetContext::new(limits(cap));
        let actual = actual_budget
            .with(|| finish_selected(&view, chain, &original, [60; 32], &signer, false))
            .unwrap_err();
        assert!(matches!(
            actual,
            AttestationBuildError::FinalityProof(ProofError::Deferred(_))
        ));
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
        assert_eq!(pool.reserved_bytes(), reserved);
    }
    finish_selected(&view, chain, &original, [61; 32], &signer, false)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(pool.reserved_bytes(), reserved);
}
