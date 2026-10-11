//! Actual execution-rooted current attestations, unchanged export, and original-source refusals.

use super::*;
use std::num::NonZeroUsize;

fn full_prefix_capture(
    view: &impl StateReadOnly,
    chain: &CertifiedTestChain,
    challenge: [u8; 32],
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    let (genesis, tip) = {
        let reader = CertifiedChain::new(view)
            .map_err(|error| AttestationBuildError::GenesisFinalityProof(error.into()))?;
        let genesis =
            proof_from_chain(&reader, 1).map_err(AttestationBuildError::GenesisFinalityProof)?;
        let tip = proof_from_chain(&reader, chain.height())
            .map_err(AttestationBuildError::FinalityProof)?;
        (genesis, tip)
    };
    let signer = installed_signer();
    let identity = NodeIdentity {
        node_id: iroha_model_base::peer::PeerId::new(signer.public_key().clone()),
        config_fingerprint: status(chain).config_fingerprint,
    };
    finish_attestation(
        view,
        status(chain),
        &identity,
        Hash::new(b"exact attestation proof reader build"),
        challenge,
        &signer,
        AttestationProofs {
            committed: chain.height(),
            genesis_block_hash: chain.genesis().hash(),
            genesis,
            tip,
        },
    )
}

fn same_body_except_fresh_clock(
    actual: &SumeragiFinalityAttestation,
    original: &SumeragiFinalityAttestation,
) {
    actual.verify().unwrap();
    original.verify().unwrap();
    let mut expected = original.body.clone();
    // Each real invocation must read its own clock; every other body byte is unchanged.
    expected.observed_at_unix_ms = actual.body.observed_at_unix_ms;
    assert_eq!(actual.body.encode(), expected.encode());
}

#[test]
fn current_attestation_uses_joined_native_source_and_two_quorums_at_h3_and_npos_boundary() {
    with_chain_at(3, check_joined_source);
    with_chain_at(10, check_joined_source);
}

#[inline(never)]
fn check_joined_source(chain: &CertifiedTestChain) {
    let height = chain.height();
    let view = chain.state().view();
    let lengths = (1..=height)
        .map(|at| chain.committed(at).block().encode_wire().unwrap().len() as u64)
        .collect::<Vec<_>>();
    chain.kura().reset_canonical_query_reads_for_test();
    let (original, before) =
        relation_counts::measure(|| full_prefix_capture(&view, chain, [61; 32]));
    let original = original.unwrap();
    assert_eq!(before.qcs, (2..=height).collect::<Vec<_>>());
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        (
            height as usize + 3,
            4 * lengths[0] + lengths[1..].iter().sum::<u64>()
        )
    );
    chain.kura().reset_canonical_query_reads_for_test();
    let (actual, after) =
        relation_counts::measure(|| capture(&view, chain, [61; 32], status(chain)));
    let actual = actual.unwrap();
    let mut expected_frames = vec![1, 1];
    expected_frames.extend((1..=height).rev());
    assert_eq!(after.frames, expected_frames);
    assert_eq!(after.qcs, [height, 2]);
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        (
            height as usize + 4,
            4 * lengths[0] + lengths.iter().sum::<u64>()
        )
    );
    same_body_except_fresh_clock(&actual, &original);
    assert_eq!(
        actual.body.genesis_finality_proof.encode(),
        build_proof(&view, 1).unwrap().encode()
    );
    assert_eq!(
        actual.body.finality_proof.encode(),
        build_proof(&view, height).unwrap().encode()
    );
    let fresh = capture(&view, chain, [62; 32], status(chain)).unwrap();
    fresh.verify().unwrap();
    assert_ne!(fresh.signature, actual.signature);

    // Every source frame is still required. A damaged intermediate is not a cache hit.
    let at = NonZeroUsize::new((height - 1) as usize).unwrap();
    chain.kura().corrupt_native_frame_for_test(at);
    assert!(capture(&view, chain, [63; 32], status(chain)).is_err());
    chain.kura().corrupt_native_frame_for_test(at);
    same_body_except_fresh_clock(
        &capture(&view, chain, [61; 32], status(chain)).unwrap(),
        &original,
    );
}

#[test]
fn current_attestation_keeps_original_active_prefix_charges_and_refusals() {
    with_chain_at(10, check_active_prefix);
}

#[inline(never)]
fn check_active_prefix(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let limits = |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 64);
    let ((original, before), original_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            relation_counts::measure(|| full_prefix_capture(&view, chain, [64; 32]))
        });
    let original = original.unwrap();
    let ((actual, after), actual_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            relation_counts::measure(|| capture(&view, chain, [64; 32], status(chain)))
        });
    same_body_except_fresh_clock(&actual.unwrap(), &original);
    assert_eq!(after.frames, before.frames);
    assert_eq!(after.qcs, before.qcs);
    assert_eq!(actual_usage, original_usage);
    let exact = original_usage.total_allocated_bytes();
    assert!(exact > 1);
    for capacity in [0, 1, exact - 1] {
        let old = norito::with_decode_limits_scope(limits(capacity), || {
            full_prefix_capture(&view, chain, [64; 32])
        })
        .unwrap_err();
        let new = norito::with_decode_limits_scope(limits(capacity), || {
            capture(&view, chain, [64; 32], status(chain))
        })
        .unwrap_err();
        assert_eq!(new.to_string(), old.to_string());
    }
    let (retry, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
        capture(&view, chain, [64; 32], status(chain))
    });
    same_body_except_fresh_clock(&retry.unwrap(), &original);
    assert_eq!(usage, original_usage);
}

#[test]
fn current_attestation_rejects_changed_state_and_selected_certificates_but_export_checks_all_qcs() {
    with_chain_at(10, check_source_and_certificates);
}

#[inline(never)]
fn check_source_and_certificates(chain: &CertifiedTestChain) {
    let view = chain.state().view();
    let original = capture(&view, chain, [65; 32], status(chain)).unwrap();
    // Retain the exact published target, then replace only its signed availability bytes.
    let target = chain.committed(10).block().clone();
    let certificate = target.commit_certificate().unwrap();
    let mut availability = certificate.availability().to_vec();
    *availability.last_mut().unwrap() ^= 1;
    let changed_target = target.as_ref().clone().with_commit_certificate(Some(
        iroha_data_model::block::CommitCertificate::from_untrusted_parts(
            certificate.consensus_header().to_vec(),
            certificate.commit_qc().to_vec(),
            certificate.result_preimage().to_vec(),
            availability,
        ),
    ));
    let path =
        crate::kura::Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let restore = RestoreBytes {
        bytes: std::fs::read(&path).unwrap(),
        path,
    };
    let mut changed = restore.bytes.clone();
    replace_frame(
        &mut changed,
        &target.encode_wire().unwrap(),
        &changed_target.encode_wire().unwrap(),
    );
    std::fs::write(&restore.path, changed).unwrap();
    assert!(capture(&view, chain, [65; 32], status(chain)).is_err());
    drop(restore);
    let originals = [2_u64, 5, 10].map(|height| {
        (
            height,
            chain
                .committed(height)
                .block()
                .commit_certificate()
                .unwrap()
                .commit_qc()
                .to_vec(),
        )
    });
    for (height, original_qc) in &originals {
        chain.corrupt_local_quorum_for_test(*height, Signers::BelowQuorum);
        let result = capture(&view, chain, [65; 32], status(chain));
        if *height == 5 {
            same_body_except_fresh_clock(&result.unwrap(), &original);
        } else {
            assert!(matches!(
                result,
                Err(AttestationBuildError::FinalityProof(_))
            ));
        }
        assert!(
            build_proof(&view, 10).is_err(),
            "standalone export still checks every QC"
        );
        chain
            .kura()
            .corrupt_commit_certificate_for_testing(
                NonZeroUsize::new(*height as usize).unwrap(),
                Some(original_qc.clone()),
            )
            .unwrap();
    }
    for signers in [Signers::BelowQuorum, Signers::All] {
        chain.corrupt_local_quorum_for_test(10, signers);
        let mut wrong_status = status(chain);
        wrong_status.instance[0] ^= 1;
        assert!(matches!(
            capture(&view, chain, [65; 32], wrong_status),
            Err(AttestationBuildError::FinalityProof(_))
        ));
        chain
            .kura()
            .corrupt_commit_certificate_for_testing(
                NonZeroUsize::new(10).unwrap(),
                Some(originals[2].1.clone()),
            )
            .unwrap();
    }
    let mut forged: iroha_sumeragi::message::Qc =
        norito::decode_canonical(&originals[2].1).unwrap();
    forged.agg_sig.0[5] ^= 1;
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            NonZeroUsize::new(10).unwrap(),
            Some(norito::encode_canonical(&forged).unwrap()),
        )
        .unwrap();
    assert!(capture(&view, chain, [65; 32], status(chain)).is_err());
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            NonZeroUsize::new(10).unwrap(),
            Some(originals[2].1.clone()),
        )
        .unwrap();
    let mut foreign = chain.state().view();
    foreign.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed([0x6d; 32])),
    );
    assert!(capture(&foreign, chain, [65; 32], status(chain)).is_err());
    let earlier = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    let mut earlier_view = earlier.state().view();
    let mut mismatched = chain.state().view();
    std::mem::swap(
        &mut mismatched.native_execution_tip,
        &mut earlier_view.native_execution_tip,
    );
    assert!(matches!(
        capture(&mismatched, chain, [65; 32], status(chain)),
        Err(AttestationBuildError::FinalityProof(
            ProofError::NativeExecution(_)
        ))
    ));
    let unanchored = crate::state::State::new_for_testing(
        World::new(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let mut empty_view = unanchored.view();
    let mut missing = chain.state().view();
    std::mem::swap(
        &mut missing.native_execution_tip,
        &mut empty_view.native_execution_tip,
    );
    assert!(missing.native_execution_tip().is_none());
    assert!(matches!(
        capture(&missing, chain, [65; 32], status(chain)),
        Err(AttestationBuildError::FinalityProof(
            ProofError::NativeExecution(_)
        ))
    ));
    same_body_except_fresh_clock(
        &capture(&view, chain, [65; 32], status(chain)).unwrap(),
        &original,
    );
}

struct RestoreBytes {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
}
impl Drop for RestoreBytes {
    fn drop(&mut self) {
        std::fs::write(&self.path, &self.bytes).unwrap();
    }
}

fn replace_frame(file: &mut [u8], original: &[u8], replacement: &[u8]) {
    assert_eq!(original.len(), replacement.len());
    let offsets = file
        .windows(original.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == original).then_some(at))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1, "one exact retained native frame");
    file[offsets[0]..offsets[0] + original.len()].copy_from_slice(replacement);
}

#[test]
fn current_attestation_refuses_coherent_genesis_and_h2_replacement_under_unchanged_proposal_hashes()
{
    with_chain_at(5, check_coherent_replacement);
}

#[inline(never)]
fn check_coherent_replacement(chain: &CertifiedTestChain) {
    use crate::sumeragi::{
        block_store::commit_certificate, commitment::ExecutionResultCommitment, crypto::BlsCrypto,
    };
    use iroha_data_model::block::CommitCertificate;
    use iroha_sumeragi::types::Hash32;
    let view = chain.state().view();
    let original = capture(&view, chain, [66; 32], status(chain)).unwrap();
    let genesis = chain.committed(1).block().clone();
    let second = chain.committed(2).block().clone();
    let certificate = genesis.commit_certificate().unwrap();
    let mut result = ExecutionResultCommitment::decode(certificate.result_preimage()).unwrap();
    result.execution.world_state_root = Hash::new(b"different coherent genesis execution");
    let preimage = result.preimage().unwrap();
    let changed_genesis = crate::block::reserve_block_for_tests().initialize(
        genesis.as_ref().clone().with_commit_certificate(Some(
            CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                certificate.commit_qc().to_vec(),
                preimage.clone(),
                certificate.availability().to_vec(),
            ),
        )),
    );
    let second_certificate = second.commit_certificate().unwrap();
    let mut header: iroha_sumeragi::message::BlockHeader =
        norito::decode_canonical(second_certificate.consensus_header()).unwrap();
    header.parent_result = crate::sumeragi::commitment::result_of_preimage(&preimage);
    header.availability_digest = Hash32::ZERO;
    let mut payload = Vec::new();
    second.write_resultless_proposal_wire(&mut payload).unwrap();
    let available = chain.author_payload(header, payload);
    let qc = chain.commit_qc(
        2,
        available.header().hash(&BlsCrypto::new()),
        crate::sumeragi::commitment::result_of_preimage(second_certificate.result_preimage()),
        Signers::Quorum,
    );
    let changed_second = crate::block::reserve_block_for_tests().initialize(
        second.as_ref().clone().with_commit_certificate(Some(
            commit_certificate(
                available.header(),
                &qc,
                second_certificate.result_preimage().to_vec(),
                norito::encode_canonical(available.availability()).unwrap(),
            )
            .unwrap(),
        )),
    );
    assert_eq!(changed_genesis.hash(), genesis.hash());
    assert_eq!(changed_second.hash(), second.hash());
    let frames = [changed_genesis.clone(), changed_second.clone()];
    let hashes = frames.iter().map(|block| block.hash()).collect::<Vec<_>>();
    let candidate =
        CertifiedChain::from_frames(view.chain_id(), view.network_id(), &hashes, &frames).unwrap();
    candidate
        .certified(2)
        .expect("independently genuine quorum and availability for the different execution");
    // A separately projected genuine signed genesis with another R cannot be joined
    // to this original State merely because its proposal hash is the same.
    let alternate_genesis = candidate.certified(1).unwrap();
    let different_genesis = GenesisDecision {
        block_hash: alternate_genesis.block_hash(),
        core_hash: alternate_genesis.core_hash(),
        result: alternate_genesis.result(),
    };
    let current_source = CertifiedChain::new(&view).unwrap();
    assert!(matches!(
        current_execution_proof(&current_source, chain.height(), different_genesis),
        Err(ProofError::Chain(ChainReadError::Discontinuous {
            height: 2
        }))
    ));
    let path =
        crate::kura::Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let restore = RestoreBytes {
        bytes: std::fs::read(&path).unwrap(),
        path,
    };
    let mut changed_file = restore.bytes.clone();
    replace_frame(
        &mut changed_file,
        &genesis.encode_wire().unwrap(),
        &changed_genesis.encode_wire().unwrap(),
    );
    replace_frame(
        &mut changed_file,
        &second.encode_wire().unwrap(),
        &changed_second.encode_wire().unwrap(),
    );
    std::fs::write(&restore.path, &changed_file).unwrap();
    let independent = CertifiedChain::new(&view).unwrap();
    independent
        .certified(2)
        .expect("genesis and H2 alone cannot detect the original State mismatch");
    independent
        .certified_from_execution(NonZeroUsize::new(5).unwrap(), |_, _| Ok(()))
        .expect("a disconnected current-tip check alone also accepts its separate original root");
    assert!(build_proof(&view, 5).is_err());
    assert!(matches!(
        capture(&view, chain, [66; 32], status(chain)),
        Err(AttestationBuildError::FinalityProof(
            ProofError::NativeExecution(_)
        ))
    ));
    drop(restore);
    same_body_except_fresh_clock(
        &capture(&view, chain, [66; 32], status(chain)).unwrap(),
        &original,
    );
}

#[cfg(unix)]
#[test]
fn current_execution_attestation_refuses_missing_replaced_and_symlink_native_source() {
    with_chain_at(10, check_tail_source_retry);
}
