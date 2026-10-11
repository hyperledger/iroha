//! Genuine single-terminal Bootstrap parity for the metadata-only native Omega owner.
//! The real fixture is expensive and opt-in. No fabricated Omega source is admitted,
//! and this component test does not qualify the complete terminal catalog or RAM gate.

use super::*;
use iroha_kagemusha_proof::omega::native::{Error, Input, Layout, Program, Prover};
use iroha_pasta::CancellationToken;
use iroha_plonk::keys::{CosetCachePolicy, pk::artifact::ReadConfig};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{CryptoRng, Error as RngError, RngCore, SeedableRng},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct RecoveryLog {
    contexts: Mutex<Vec<[u8; 32]>>,
    bytes: AtomicUsize,
}
struct RecordedRng {
    stream: ChaCha20Rng,
    log: Arc<RecoveryLog>,
}
impl RngCore for RecordedRng {
    fn next_u32(&mut self) -> u32 {
        self.log.bytes.fetch_add(4, Ordering::SeqCst);
        self.stream.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.log.bytes.fetch_add(8, Ordering::SeqCst);
        self.stream.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.log.bytes.fetch_add(bytes.len(), Ordering::SeqCst);
        self.stream.fill_bytes(bytes);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), RngError> {
        self.log.bytes.fetch_add(bytes.len(), Ordering::SeqCst);
        self.stream.try_fill_bytes(bytes)
    }
}
impl CryptoRng for RecordedRng {}

fn recovery(log: Arc<RecoveryLog>, cancel: Option<CancellationToken>) -> ProverRandomness<'static> {
    ProverRandomness::recovery(move |context: &[u8; 32]| {
        log.contexts.lock().unwrap().push(*context);
        if let Some(token) = cancel {
            // This happens only after the actual PK rebuild and witness construction.
            // The next native cancellation checkpoint must stop the proof attempt.
            token.cancel();
        }
        Ok::<_, ()>(RecordedRng {
            stream: ChaCha20Rng::from_seed([0x63; 32]),
            log,
        })
    })
}
fn contexts(log: &RecoveryLog) -> Vec<[u8; 32]> {
    log.contexts.lock().unwrap().clone()
}
fn read_config(original: &[u8]) -> ReadConfig {
    ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
fn input(artifact: &RootedBootstrapOmega) -> Input {
    Input {
        key: artifact.source.key.clone(),
        frame: artifact.source.instances.clone().try_into().unwrap(),
        proof: artifact.source.proof.clone(),
        public: artifact.source.state.lineage,
        pallas: artifact.source.pallas.clone(),
    }
}

#[test]
#[ignore = "genuine Bootstrap chain plus fresh/rebuilt k16 Omega parity; run optimized after resource handoff"]
fn actual_bootstrap_omega_rebuild_preserves_proof_restore_and_cancellation() {
    let artifact = compact_bootstrap::rooted_compact_bootstrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta_params = PinnedParams::<Eq>::derive(16).unwrap();
    let catalog = vec![artifact.source.key.to_bytes().to_vec()];
    let program = Program::for_compiled_catalog(
        artifact.source.binding.encoded(),
        &catalog,
        vesta_params.clone(),
        params.clone(),
    )
    .unwrap();
    let blank = program.source_circuit().unwrap();

    // Reconstruct the exact real witness/layout used by the existing rooted fixture.
    // The native owner independently derives the same source from its fixed catalog.
    let (circuit, public, folded_vesta) = wrapper(&artifact.source);
    let circuit = circuit
        .with_key_catalog(vec![artifact.source.key.clone()])
        .unwrap();
    let (spans, schedule) = compact_layout(&circuit, &public, false).unwrap();
    let circuit = circuit.with_secondary_layout(spans, schedule);
    assert_eq!(public, artifact.instances);
    assert_eq!(folded_vesta, artifact.vesta);
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = false;
    config.coset_cache = CosetCachePolicy::OnDemand;
    let key = keygen_pk_v2(&params, &blank, &config).unwrap();
    assert_eq!(key.binding(), &artifact.binding);
    assert_eq!(key.vk().to_bytes(), artifact.key.to_bytes());
    assert!(!key.has_coset_cache());
    assert_eq!(key.commitment_tables().present(), (false, false));
    let original = key.artifact_bytes_v2().unwrap();
    drop(blank);

    // Baseline is the actual engine with a freshly generated exact-source PK.
    // Public deterministic recovery coins are confined to this ignored test.
    let direct_log = Arc::new(RecoveryLog::default());
    let direct = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &public).unwrap(),
        recovery(direct_log.clone(), None),
        ProverConfig::default(),
    )
    .unwrap();
    drop(key);
    drop(circuit);
    iroha_plonk::verify_full(
        &params,
        &artifact.binding,
        &artifact.key,
        &public,
        &direct.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    direct
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    artifact
        .source
        .pallas
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    folded_vesta
        .decide(&vesta_params, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(contexts(&direct_log).len(), 1);
    assert_eq!(direct_log.bytes.load(Ordering::SeqCst), 32);

    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        Prover::from_original_artifact_cancellable(
            program.clone(),
            artifact.binding.encoded(),
            artifact.key.to_bytes(),
            &original,
            read_config(&original),
            Some(&token),
        )
        .err(),
        Some(Error::Cancelled)
    );

    // A different source layout must still fail the unchanged strict importer;
    // matching descriptor/VK originals cannot mint metadata on their own.
    let foreign_program = Program::new(
        artifact.source.binding.encoded(),
        &catalog,
        vesta_params.clone(),
        params.clone(),
        Layout::Ordinary,
    )
    .unwrap();
    assert_eq!(
        Prover::from_original_artifact(
            foreign_program,
            artifact.binding.encoded(),
            artifact.key.to_bytes(),
            &original,
            read_config(&original),
        )
        .err(),
        Some(Error::Artifact)
    );
    let mut foreign_vk = artifact.key.to_bytes().to_vec();
    let other =
        iroha_plonk::transcript::encode_point::<Ep>(&(-artifact.key.fixed_commitments()[0]));
    assert_ne!(&foreign_vk[10..42], other.as_slice());
    foreign_vk[10..42].copy_from_slice(&other);
    // Negation of a finite prime-order point is canonical and distinct; this
    // isolates installed identity, rather than relying on a malformed encoding.
    iroha_plonk::VerifyingKey::<Ep>::read(&foreign_vk, &artifact.binding).unwrap();
    assert_eq!(
        Prover::from_original_artifact(
            program.clone(),
            artifact.binding.encoded(),
            &foreign_vk,
            &original,
            read_config(&original),
        )
        .err(),
        Some(Error::Artifact)
    );

    let owner = Prover::from_original_artifact(
        program.clone(),
        artifact.binding.encoded(),
        artifact.key.to_bytes(),
        &original,
        read_config(&original),
    )
    .unwrap();
    drop(original);
    assert_eq!(owner.binding(), &artifact.binding);
    assert_eq!(owner.verifying_key().to_bytes(), artifact.key.to_bytes());
    // Consume the strict owner and borrow the already retained exact public graph.
    let expected_proof_bytes = iroha_plonk::Protocol::new(owner.binding().descriptor())
        .unwrap()
        .proof_length();
    let expected_key_digest = owner
        .verifying_key()
        .kagemusha_digest(owner.binding())
        .unwrap();
    let (binding, verifier, seal) = owner.into_metadata().into_parts();
    assert!(
        seal.bind(&binding, &verifier, Some(&token))
            .unwrap_err()
            .is_cancelled()
    );
    let foreign_key = iroha_plonk::VerifyingKey::<Ep>::read(&foreign_vk, &binding).unwrap();
    assert!(seal.bind(&binding, &foreign_key, None).is_err());
    let bound = seal.bind(&binding, &verifier, None).unwrap();
    assert!(core::ptr::eq(bound.binding(), &binding));
    assert!(core::ptr::eq(bound.verifying_key(), &verifier));
    let owner =
        iroha_kagemusha_proof::omega::native::ProverView::from_source_bound(&program, bound)
            .unwrap();
    assert_eq!(
        iroha_plonk::Protocol::new(owner.binding().descriptor())
            .unwrap()
            .proof_length(),
        expected_proof_bytes
    );
    assert_eq!(
        owner
            .verifying_key()
            .kagemusha_digest(owner.binding())
            .unwrap(),
        expected_key_digest
    );
    let session = owner
        .prepare(
            input(&artifact),
            Fq::from(101).to_repr(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    let never = Arc::new(RecoveryLog::default());
    assert_eq!(
        session
            .prove(
                recovery(never.clone(), None),
                ProverConfig {
                    cancellation: Some(&token),
                    ..ProverConfig::default()
                },
            )
            .err(),
        Some(Error::Cancelled)
    );
    assert!(contexts(&never).is_empty());
    assert_eq!(never.bytes.load(Ordering::SeqCst), 0);

    // A cancelled attempt after rebuilding/assigning owns no returned output.
    // A fresh attempt must work with the same metadata after lexical PK cleanup.
    let during = CancellationToken::new();
    let cancelled_log = Arc::new(RecoveryLog::default());
    assert_eq!(
        session
            .prove(
                recovery(cancelled_log.clone(), Some(during.clone())),
                ProverConfig {
                    cancellation: Some(&during),
                    ..ProverConfig::default()
                },
            )
            .err(),
        Some(Error::Cancelled)
    );
    assert_eq!(contexts(&cancelled_log), contexts(&direct_log));
    assert_eq!(cancelled_log.bytes.load(Ordering::SeqCst), 32);

    let rebuilt_log = Arc::new(RecoveryLog::default());
    let rebuilt = session
        .prove(recovery(rebuilt_log.clone(), None), ProverConfig::default())
        .unwrap();
    assert_eq!(contexts(&rebuilt_log), contexts(&direct_log));
    assert_eq!(rebuilt_log.bytes.load(Ordering::SeqCst), 32);
    assert_eq!(rebuilt.proof, direct.proof);
    assert_eq!(rebuilt.instances, public);
    assert_eq!(rebuilt.pallas, artifact.source.pallas);
    assert_eq!(rebuilt.vesta, folded_vesta);
    assert_eq!(rebuilt.opening.g(), direct.opening.g());
    assert_eq!(rebuilt.opening.challenges(), direct.opening.challenges());
    let transport = rebuilt.transport();
    let mut direct_transport = direct.proof.clone();
    direct_transport.extend_from_slice(&artifact.source.pallas.to_bytes());
    direct_transport.extend_from_slice(&folded_vesta.to_bytes());
    assert_eq!(transport, direct_transport);
    assert_eq!(rebuilt.proof.len(), expected_proof_bytes);
    assert_eq!(
        transport.len(),
        expected_proof_bytes + 2 * iroha_plonk_recursion::ACCUMULATOR_BYTES
    );
    let restored = session
        .restore_transport(&transport, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(restored.transport(), transport);
    assert_eq!(restored.proof, rebuilt.proof);
    assert_eq!(restored.instances, rebuilt.instances);
    assert_eq!(restored.pallas, rebuilt.pallas);
    assert_eq!(restored.vesta, rebuilt.vesta);
    assert_eq!(restored.opening, rebuilt.opening);
    assert_eq!(
        session
            .restore_transport(&restored.transport(), MemoryBudget::DEFAULT)
            .unwrap()
            .transport(),
        transport
    );
    assert_eq!(
        session
            .restore_transport_cancellable(&transport, MemoryBudget::DEFAULT, Some(&token))
            .err(),
        Some(Error::Cancelled)
    );
    assert_eq!(
        session
            .restore_transport(&transport[..transport.len() - 1], MemoryBudget::DEFAULT)
            .err(),
        Some(Error::Input)
    );
    let mut trailing = transport.clone();
    trailing.push(0);
    assert_eq!(
        session
            .restore_transport(&trailing, MemoryBudget::DEFAULT)
            .err(),
        Some(Error::Input)
    );
    // Canonical but foreign P and V must fail the prepared-source equality check
    // independently, before either can be treated as an accepted carried claim.
    for (offset, point) in [
        (
            expected_proof_bytes,
            iroha_plonk::transcript::encode_point::<Ep>(&(-*rebuilt.pallas.g())),
        ),
        (
            expected_proof_bytes + iroha_plonk_recursion::ACCUMULATOR_BYTES,
            iroha_plonk::transcript::encode_point::<Eq>(&(-*rebuilt.vesta.g())),
        ),
    ] {
        let mut foreign = transport.clone();
        assert_ne!(&foreign[offset..offset + 32], point.as_slice());
        foreign[offset..offset + 32].copy_from_slice(&point);
        assert_eq!(
            session
                .restore_transport(&foreign, MemoryBudget::DEFAULT)
                .err(),
            Some(Error::Input)
        );
    }
    let mut corrupt = transport.clone();
    corrupt[0] ^= 1;
    assert!(
        session
            .restore_transport(&corrupt, MemoryBudget::DEFAULT)
            .is_err()
    );
    assert_eq!(
        owner
            .verifying_key()
            .kagemusha_digest(owner.binding())
            .unwrap(),
        expected_key_digest
    );
    assert_eq!(owner.binding(), &artifact.binding);
    assert_eq!(owner.verifying_key().to_bytes(), artifact.key.to_bytes());
    assert_eq!(contexts(&rebuilt_log), contexts(&direct_log));
    assert_eq!(rebuilt_log.bytes.load(Ordering::SeqCst), 32);
    // Restores have no randomness argument and the production call graph has no
    // rebuild edge. These checks do not claim an allocator/RSS observation.
    eprintln!(
        "OMEGA_METADATA_REBUILD_PARITY complete_additional_outer_proofs=2 cancelled_after_rebuild=1 exact_proof_bytes=true exact_transport_bytes=true recovery_context_and_32_bytes_equal=true transport_restore_exact=true full_catalog=false release_qualified=false"
    );
}
