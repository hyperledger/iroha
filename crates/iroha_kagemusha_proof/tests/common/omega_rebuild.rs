//! Genuine single-terminal Bootstrap parity for the metadata-only native Omega owner.
//! The real fixture is expensive and opt-in. No fabricated Omega source is admitted,
//! and this component test does not qualify the complete terminal catalog or RAM gate.

use super::*;
use iroha_kagemusha_proof::omega::native::{Error, Input, Layout, Program, Prover};
use iroha_pasta::CancellationToken;
use iroha_plonk::keys::{CosetCachePolicy, pk::artifact::ReadConfig};
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
    // The producer uses fresh entropy; this exact original is retained for restore.
    let direct = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &public).unwrap(),
        ProverRandomness::hedged(),
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
    assert!(core::ptr::eq(bound.binding(), &raw const binding));
    assert!(core::ptr::eq(bound.verifying_key(), &raw const verifier));
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
            diagnostic_omega_tape(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    assert_eq!(
        session
            .prove(
                ProverRandomness::hedged(),
                ProverConfig {
                    cancellation: Some(&token),
                    ..ProverConfig::default()
                },
            )
            .err(),
        Some(Error::Cancelled)
    );

    let rebuilt = session
        .prove(ProverRandomness::hedged(), ProverConfig::default())
        .unwrap();
    assert_ne!(rebuilt.proof, direct.proof, "fresh attempt entropy");
    assert_eq!(rebuilt.instances, public);
    assert_eq!(rebuilt.pallas, artifact.source.pallas);
    assert_eq!(rebuilt.vesta, folded_vesta);
    let transport = rebuilt.transport();
    let mut direct_transport = direct.proof.clone();
    direct_transport.extend_from_slice(&artifact.source.pallas.to_bytes());
    direct_transport.extend_from_slice(&folded_vesta.to_bytes());
    assert_ne!(transport, direct_transport);
    assert_eq!(rebuilt.proof.len(), expected_proof_bytes);
    assert_eq!(
        transport.len(),
        expected_proof_bytes + 2 * iroha_plonk_recursion::ACCUMULATOR_BYTES
    );
    // Transport acceptance is the installed verifier's complete lineage verification
    // (`kagemusha_wallet_proofs_v1::verify_lineage`), which replaced the prover-session
    // restore. This mirrors its checks on the exact transport: the exact length split, two
    // canonical claims, the context D_A that binds acc_P (D_A is a hash over the source
    // public fields and acc_P, so a different acc_P yields a different context), full
    // verification of Omega under the instances that bind the carried Vesta claim, then both
    // complete decides on independent owners. The corruption cases of the deleted restore are
    // checked at that boundary.
    let installed_pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let installed_vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let verify_transport = |bytes: &[u8], cancellation: Option<&CancellationToken>| {
        let accumulator = iroha_plonk_recursion::ACCUMULATOR_BYTES;
        if bytes.len() != expected_proof_bytes + 2 * accumulator {
            return Err("length");
        }
        let (proof, claims) = bytes.split_at(expected_proof_bytes);
        let (pallas, vesta) = claims.split_at(accumulator);
        let pallas = AccumulatorT::<Ep>::from_bytes(pallas).map_err(|_| "Pallas claim")?;
        let vesta = AccumulatorT::<Eq>::from_bytes(vesta).map_err(|_| "Vesta claim")?;
        if pallas != artifact.source.pallas {
            return Err("context");
        }
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(vesta.g());
        let instances = vec![
            public[0].clone(),
            vec![x, y],
            vesta
                .challenges()
                .iter()
                .map(|value| Fq::from_repr(value.to_repr()).unwrap())
                .collect(),
        ];
        iroha_plonk::verifier::verify_full_cancellable(
            &installed_pallas,
            &artifact.binding,
            &artifact.key,
            &instances,
            proof,
            MemoryBudget::DEFAULT,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                "cancelled"
            } else {
                "Omega"
            }
        })?;
        pallas
            .decide_cancellable(&installed_pallas, MemoryBudget::DEFAULT, cancellation)
            .map_err(|_| "Pallas decide")?;
        vesta
            .decide_cancellable(&installed_vesta, MemoryBudget::DEFAULT, cancellation)
            .map_err(|_| "Vesta decide")?;
        Ok(())
    };
    assert_eq!(verify_transport(&transport, Some(&token)), Err("cancelled"));
    assert_eq!(verify_transport(&transport, None), Ok(()));
    assert_eq!(verify_transport(&transport, None), Ok(()));
    assert_eq!(verify_transport(&transport, Some(&token)), Err("cancelled"));
    assert_eq!(
        verify_transport(&transport[..transport.len() - 1], None),
        Err("length")
    );
    let mut trailing = transport.clone();
    trailing.push(0);
    assert_eq!(verify_transport(&trailing, None), Err("length"));
    // Canonical but foreign P and V are refused: P by its context binding, V by the Omega
    // instances that bind it (and its own decide).
    for (offset, point, refusal) in [
        (
            expected_proof_bytes,
            iroha_plonk::transcript::encode_point::<Ep>(&(-*rebuilt.pallas.g())),
            "context",
        ),
        (
            expected_proof_bytes + iroha_plonk_recursion::ACCUMULATOR_BYTES,
            iroha_plonk::transcript::encode_point::<Eq>(&(-*rebuilt.vesta.g())),
            "Omega",
        ),
    ] {
        let mut foreign = transport.clone();
        assert_ne!(&foreign[offset..offset + 32], point.as_slice());
        foreign[offset..offset + 32].copy_from_slice(&point);
        assert_eq!(verify_transport(&foreign, None), Err(refusal));
    }
    for index in [0, expected_proof_bytes / 2, expected_proof_bytes - 1] {
        let mut corrupt = transport.clone();
        corrupt[index] ^= 1;
        assert!(
            verify_transport(&corrupt, None).is_err(),
            "proof byte {index}"
        );
    }
    // The exact transport is still accepted after every refusal (nothing negative is kept).
    assert_eq!(verify_transport(&transport, None), Ok(()));
    // Observe both genuine originals with the one-read full verifier. This is
    // exact source parity; Core's installed boundary owns lineage authorization.
    for (retained, proof, instances, p, v, g, challenges) in [
        (
            direct_transport.as_slice(),
            direct.proof.as_slice(),
            &public,
            &artifact.source.pallas,
            &folded_vesta,
            direct.opening.g(),
            direct.opening.challenges(),
        ),
        (
            transport.as_slice(),
            rebuilt.proof.as_slice(),
            &rebuilt.instances,
            &rebuilt.pallas,
            &rebuilt.vesta,
            rebuilt.opening.g(),
            &rebuilt.opening.challenges()[..],
        ),
    ] {
        for _ in 0..2 {
            let (observed_proof, claims) = retained.split_at(expected_proof_bytes);
            let (observed_p, observed_v) =
                claims.split_at(iroha_plonk_recursion::ACCUMULATOR_BYTES);
            let observed_p =
                iroha_plonk_recursion::AccumulatorT::<Ep>::from_bytes(observed_p).unwrap();
            let observed_v =
                iroha_plonk_recursion::AccumulatorT::<Eq>::from_bytes(observed_v).unwrap();
            assert_eq!(observed_proof, proof);
            assert_eq!(&observed_p, p);
            assert_eq!(&observed_v, v);
            let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(observed_v.g());
            let observed_instances = vec![
                public[0].clone(),
                vec![x, y],
                observed_v
                    .challenges()
                    .iter()
                    .map(|u| Fq::from_repr(u.to_repr()).unwrap())
                    .collect(),
            ];
            assert_eq!(&observed_instances, instances);
            let opening = iroha_plonk::verifier::verify_full_opening_cancellable(
                &params,
                &binding,
                &verifier,
                &observed_instances,
                observed_proof,
                MemoryBudget::DEFAULT,
                None,
            )
            .unwrap();
            assert_eq!(opening.g(), g);
            assert_eq!(opening.challenges(), challenges);
            observed_p.decide(&params, MemoryBudget::DEFAULT).unwrap();
            observed_v
                .decide(&vesta_params, MemoryBudget::DEFAULT)
                .unwrap();
            let mut observed = observed_proof.to_vec();
            observed.extend_from_slice(&observed_p.to_bytes());
            observed.extend_from_slice(&observed_v.to_bytes());
            assert_eq!(observed, retained);
        }
    }
    assert_eq!(
        owner
            .verifying_key()
            .kagemusha_digest(owner.binding())
            .unwrap(),
        expected_key_digest
    );
    assert_eq!(owner.binding(), &artifact.binding);
    assert_eq!(owner.verifying_key().to_bytes(), artifact.key.to_bytes());
    // Owner entry/cancellation is measured in the private Omega unit. These retained
    // original observations do not replace the deferred installed-verifier M1 test.
    eprintln!(
        "OMEGA_METADATA_REBUILD_PARITY complete_additional_outer_proofs=2 late_cancel_coverage=omega_boundary_unit fresh_proofs_distinct=true retained_original_bytes_exact=true original_read_replays=4 producer_entry_coverage=omega_boundary_unit installed_replay_coverage=core_native_exchange full_catalog=false release_qualified=false"
    );
}
