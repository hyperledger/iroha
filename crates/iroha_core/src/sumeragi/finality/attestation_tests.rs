//! Genuine source and allocation controls for one-cut challenged attestation proof production.

use super::*;
use crate::{
    state::World,
    sumeragi::{
        certified_chain::{QcVerification, relation_counts},
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    },
};

fn installed_signer() -> KeyPair {
    KeyPair::from_seed(vec![0xC1; 32], Algorithm::BlsNormal)
}

fn status(chain: &CertifiedTestChain) -> SumeragiStatus {
    let signer = installed_signer();
    assert!(
        chain
            .validators()
            .iter()
            .any(|(peer, _)| peer.public_key() == signer.public_key())
    );
    SumeragiStatus {
        protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
        config_fingerprint: Hash::new(b"exact attestation proof reader configuration"),
        beacon_horizon: None,
        instance: chain.instance().0,
        height: chain.height() + 1,
        view: 0,
        stage: 0,
        leader: None,
        proxy_tail: None,
        high_qc_view: None,
        level: 0,
        start_level: 0,
        t_retx_ms: 100,
        committed_height: chain.height(),
        applied_height: chain.height(),
        awaiting: false,
        signer: Some(signer.public_key().clone()),
        unanchored: false,
        abstaining: false,
        halted: None,
        footprint: iroha_data_model::sumeragi::SumeragiFootprint::default(),
    }
}

fn capture(
    view: &impl StateReadOnly,
    chain: &CertifiedTestChain,
    challenge: [u8; 32],
    status: SumeragiStatus,
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    let signer = installed_signer();
    let identity = NodeIdentity {
        node_id: iroha_model_base::peer::PeerId::new(signer.public_key().clone()),
        config_fingerprint: Hash::new(b"exact attestation proof reader configuration"),
    };
    build_attestation(
        view,
        status,
        &identity,
        Hash::new(b"exact attestation proof reader build"),
        chain.height(),
        challenge,
        &signer,
    )
}

#[inline(never)]
fn with_chain_at(height: u64, check_original: fn(&CertifiedTestChain)) {
    let mut chain = if height == 10 {
        CertifiedTestChain::npos_boundary_fixture()
    } else {
        CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap()
    };
    while chain.height() < height {
        chain.commit(Vec::new());
    }
    assert_eq!(chain.height(), height);
    check_original(&chain);
}

#[inline(never)]
fn check_original_attestation(chain: &CertifiedTestChain) {
    let height = chain.height();
    let view = chain.state().view();
    // Independently exercised public producers are the byte-for-byte comparison oracle.
    let original_genesis = build_proof(&view, 1).unwrap();
    let original_tip = build_proof(&view, height).unwrap();
    let expected_frames = if height == 1 {
        vec![1, 1]
    } else if height == 2 {
        vec![1, 1, 2]
    } else {
        let mut frames = vec![1, 1];
        frames.extend((1..=height).rev());
        frames
    };
    let (produced, checked) =
        relation_counts::measure(|| capture(&view, chain, [41; 32], status(chain)));
    let produced = produced.unwrap();
    assert_eq!(
        checked.frames, expected_frames,
        "one genesis successor and the original current execution bind the proofs"
    );
    assert_eq!(
        checked.qcs,
        if height > 2 {
            vec![height, 2]
        } else {
            (2..=height).collect::<Vec<_>>()
        },
        "the current target and the genesis successor each retain exact native verification"
    );
    assert_eq!(produced.body.genesis_finality_proof, original_genesis);
    assert_eq!(produced.body.finality_proof, original_tip);
    assert_eq!(produced.body.challenge, [41; 32]);
    assert_eq!(produced.body.network_id, chain.network_id());
    assert_eq!(produced.body.genesis_block_hash, chain.genesis().hash());
    assert_eq!(produced.body.status.instance, chain.instance().0);
    produced.verify().unwrap();
    if height == 10 {
        let native = CertifiedChain::new(&view)
            .unwrap()
            .certified(height)
            .unwrap();
        assert_eq!(native.verification(), QcVerification::Verified);
        assert!(native.commitment().schedule.boundary.is_some());

        let qc = native.commit_qc().unwrap();
        assert_eq!(qc.signers.count_ones(), 3);
    }
    let fresh = capture(&view, chain, [42; 32], status(chain)).unwrap();
    assert_eq!(
        fresh.body.genesis_finality_proof,
        produced.body.genesis_finality_proof
    );
    assert_eq!(fresh.body.finality_proof, produced.body.finality_proof);
    assert_eq!(fresh.body.challenge, [42; 32]);
    assert_ne!(
        fresh.signature, produced.signature,
        "each actual challenge is separately signed"
    );
    fresh.verify().unwrap();
}

#[test]
fn challenged_genesis_attestation_keeps_exact_original_proof() {
    with_chain_at(1, check_original_attestation);
}

#[test]
fn challenged_tip_attestation_checks_one_original_native_prefix() {
    with_chain_at(2, check_original_attestation);
}

#[test]
fn challenged_boundary_attestation_checks_exact_target_and_genesis_successor_quorums() {
    with_chain_at(10, check_original_attestation);
}

#[test]
fn attestation_resource_refusal_retries_the_same_original_source_without_retained_cache() {
    with_chain_at(2, check_resource_retry);
}

#[inline(never)]
fn check_resource_retry(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let source_genesis = chain.genesis().encode_wire().unwrap();
    let source_tip = chain.committed(2).block().encode_wire().unwrap();
    let hashes = view.block_hashes().iter().copied().collect::<Vec<_>>();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    let original = capture(&view, chain, [43; 32], status(chain)).unwrap();
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || capture(&view, chain, [44; 32], status(chain)),
    )
    .unwrap_err();
    assert!(
        matches!(
            refused,
            AttestationBuildError::GenesisFinalityProof(ProofError::Deferred(_))
                | AttestationBuildError::FinalityProof(ProofError::Deferred(_))
        ),
        "the real original native decoder retains local resource refusal: {refused:?}"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(chain.height(), 2);
    assert_eq!(
        view.block_hashes().iter().copied().collect::<Vec<_>>(),
        hashes
    );
    assert_eq!(chain.genesis().encode_wire().unwrap(), source_genesis);
    assert_eq!(
        chain.committed(2).block().encode_wire().unwrap(),
        source_tip
    );
    let (retried, checked) =
        relation_counts::measure(|| capture(&view, chain, [44; 32], status(chain)));
    let retried = retried.unwrap();
    assert_eq!(checked.frames, vec![1, 1, 2]);
    assert_eq!(
        checked.qcs,
        vec![2],
        "a new attempt verifies its own actual certificate"
    );
    assert_eq!(
        retried.body.genesis_finality_proof,
        original.body.genesis_finality_proof
    );
    assert_eq!(retried.body.finality_proof, original.body.finality_proof);
    assert_eq!(retried.body.challenge, [44; 32]);
    retried.verify().unwrap();
    assert_eq!(budget.reserved_bytes(), reserved);
}

#[test]
fn attestation_checks_original_tip_certificate_before_status_instance_and_height_errors() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    chain.commit(Vec::new());
    let mut invalid_instance = status(&chain);
    invalid_instance.instance[0] ^= 1;
    let mut invalid_height = status(&chain);
    invalid_height.committed_height -= 1;
    invalid_height.applied_height -= 1;
    invalid_height.height -= 1;
    {
        let view = chain.state().view();
        let (result, checked) =
            relation_counts::measure(|| capture(&view, &chain, [45; 32], invalid_instance.clone()));
        assert!(matches!(result, Err(AttestationBuildError::InvalidStatus)));
        assert_eq!(checked.frames, vec![1, 1, 2]);
        assert_eq!(checked.qcs, vec![2]);
        assert!(matches!(
            capture(&view, &chain, [45; 32], invalid_height.clone()),
            Err(AttestationBuildError::StatusHeightMismatch)
        ));
    }
    chain.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
    let view = chain.state().view();
    for status in [invalid_instance, invalid_height] {
        assert!(
            matches!(
                capture(&view, &chain, [45; 32], status),
                Err(AttestationBuildError::FinalityProof(ProofError::Chain(
                    ChainReadError::Certificate { height: 2, .. }
                )))
            ),
            "an invalid native original still refuses before later status checks"
        );
    }
}

// These calls start with portable proofs emitted by the unchanged public producer.
// The new tail must still acquire its own genuine current native source.
fn capture_original_tail(
    view: &impl StateReadOnly,
    chain: &CertifiedTestChain,
    original: &SumeragiFinalityAttestation,
    status: SumeragiStatus,
    challenge: [u8; 32],
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    let signer = installed_signer();
    let identity = NodeIdentity {
        node_id: iroha_model_base::peer::PeerId::new(signer.public_key().clone()),
        config_fingerprint: original.body.config_fingerprint,
    };
    finish_attestation(
        view,
        status,
        &identity,
        original.body.build_fingerprint,
        challenge,
        &signer,
        AttestationProofs {
            committed: chain.height(),
            genesis_block_hash: original.body.genesis_block_hash,
            genesis: original.body.genesis_finality_proof.clone(),
            tip: original.body.finality_proof.clone(),
        },
    )
}

#[test]
fn attestation_tail_keeps_real_boundary_proofs_status_order_and_active_charges() {
    // Use the ordinary test thread and real NPoS boundary, without a stack override.
    with_chain_at(10, check_original_tail);
}

#[inline(never)]
fn check_original_tail(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    let original = capture(&view, chain, [46; 32], status(chain)).unwrap();
    let limits = |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 64);
    let (finished, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        capture_original_tail(&view, chain, &original, status(chain), [47; 32])
    });
    let finished = finished.unwrap();
    assert_eq!(
        finished.body.genesis_finality_proof,
        original.body.genesis_finality_proof
    );
    assert_eq!(finished.body.finality_proof, original.body.finality_proof);
    assert_eq!(finished.body.network_id, original.body.network_id);
    assert_eq!(
        finished.body.genesis_block_hash,
        original.body.genesis_block_hash
    );
    assert_eq!(finished.body.node_id, original.body.node_id);
    assert_eq!(
        finished.body.config_fingerprint,
        original.body.config_fingerprint
    );
    assert_eq!(
        finished.body.build_fingerprint,
        original.body.build_fingerprint
    );
    assert_eq!(finished.body.challenge, [47; 32]);
    assert_ne!(finished.signature, original.signature);
    finished.verify().unwrap();
    assert_eq!(budget.reserved_bytes(), reserved);

    let mut invalid_height = status(chain);
    invalid_height.committed_height -= 1;
    invalid_height.applied_height -= 1;
    invalid_height.height -= 1;
    let mut invalid_instance_and_height = invalid_height.clone();
    invalid_instance_and_height.instance[0] ^= 1;
    assert!(matches!(
        capture_original_tail(
            &view,
            chain,
            &original,
            invalid_instance_and_height,
            [48; 32]
        ),
        Err(AttestationBuildError::InvalidStatus)
    ));
    assert!(matches!(
        capture_original_tail(&view, chain, &original, invalid_height, [48; 32]),
        Err(AttestationBuildError::StatusHeightMismatch)
    ));

    let exact = usage.total_allocated_bytes();
    assert!(exact > 1);
    for bytes in [0, 1] {
        let refused = norito::with_decode_limits_scope(limits(bytes), || {
            capture_original_tail(&view, chain, &original, status(chain), [48; 32])
        });
        assert!(matches!(
            refused,
            Err(AttestationBuildError::FinalityProof(ProofError::Deferred(
                _
            )))
        ));
        assert_eq!(budget.reserved_bytes(), reserved);
    }
    let (retried, retry_usage) = norito::core::with_decode_limits_measured(limits(exact), || {
        capture_original_tail(&view, chain, &original, status(chain), [48; 32])
    });
    let retried = retried.unwrap();
    assert_eq!(retry_usage, usage);
    assert_eq!(
        retried.body.genesis_finality_proof,
        original.body.genesis_finality_proof
    );
    assert_eq!(retried.body.finality_proof, original.body.finality_proof);
    assert_eq!(retried.body.challenge, [48; 32]);
    retried.verify().unwrap();
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(chain.height(), 10);
}

#[cfg(unix)]
#[test]
fn attestation_tail_refuses_changed_native_genesis_before_status_and_retries_original_inode() {
    with_chain_at(2, check_tail_source_retry);
}

#[cfg(unix)]
#[inline(never)]
fn check_tail_source_retry(chain: &CertifiedTestChain) {
    use std::os::unix::fs::MetadataExt as _;
    let original_height = chain.height();
    let view = chain.state().view();
    let original = capture(&view, chain, [49; 32], status(chain)).unwrap();
    let source =
        crate::kura::Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let saved = source.with_extension("attestation-tail-original");
    let bytes = std::fs::read(&source).unwrap();
    let original_identity = std::fs::metadata(&source).unwrap().ino();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    struct RestoreJournal<'a> {
        source: &'a std::path::Path,
        saved: &'a std::path::Path,
    }
    impl Drop for RestoreJournal<'_> {
        fn drop(&mut self) {
            if std::fs::symlink_metadata(self.source).is_ok() {
                std::fs::remove_file(self.source).unwrap();
            }
            std::fs::rename(self.saved, self.source).unwrap();
        }
    }
    for kind in ["missing", "same-bytes-replacement", "symlink"] {
        std::fs::rename(&source, &saved).unwrap();
        let restore = RestoreJournal {
            source: &source,
            saved: &saved,
        };
        match kind {
            "missing" => assert!(!source.exists()),
            "same-bytes-replacement" => {
                std::fs::copy(&saved, &source).unwrap();
                assert_eq!(std::fs::read(&source).unwrap(), bytes);
                assert_ne!(std::fs::metadata(&source).unwrap().ino(), original_identity);
            }
            "symlink" => std::os::unix::fs::symlink(&saved, &source).unwrap(),
            _ => unreachable!(),
        }
        let expected = AttestationBuildError::FinalityProof(ProofError::from(
            CertifiedChain::new(&view).unwrap_err(),
        ));
        assert!(matches!(
            capture(&view, chain, [50; 32], status(chain)),
            Err(AttestationBuildError::GenesisFinalityProof(_))
        ));
        assert_eq!(budget.reserved_bytes(), reserved);
        for invalid_instance in [false, true] {
            let mut invalid = status(chain);
            invalid.committed_height -= 1;
            invalid.applied_height -= 1;
            invalid.height -= 1;
            if invalid_instance {
                invalid.instance[0] ^= 1;
            }
            let actual =
                capture_original_tail(&view, chain, &original, invalid, [50; 32]).unwrap_err();
            assert!(matches!(
                actual,
                AttestationBuildError::FinalityProof(ProofError::Chain(
                    ChainReadError::NotInView { height: 1 }
                ))
            ));
            assert_eq!(actual.to_string(), expected.to_string());
            assert_eq!(budget.reserved_bytes(), reserved);
        }
        assert_eq!(std::fs::read(&saved).unwrap(), bytes);
        drop(restore);
        assert_eq!(std::fs::metadata(&source).unwrap().ino(), original_identity);
        assert_eq!(std::fs::read(&source).unwrap(), bytes);
        let retried =
            capture_original_tail(&view, chain, &original, status(chain), [50; 32]).unwrap();
        assert_eq!(
            retried.body.genesis_finality_proof,
            original.body.genesis_finality_proof
        );
        assert_eq!(retried.body.finality_proof, original.body.finality_proof);
        assert_eq!(retried.body.challenge, [50; 32]);
        retried.verify().unwrap();
        assert_eq!(budget.reserved_bytes(), reserved);
    }
    assert_eq!(chain.height(), original_height);
}

#[path = "attestation_signature_tests.rs"]
mod signature_tests;

#[path = "attestation_execution_tests.rs"]
mod execution_tests;
