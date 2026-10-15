//! Exact private Omega owner entry, cancellation and read-only original replay.
//! Only shared builder items are reused; integration suites stay independently registered.

#[path = "../tests/common/proof_fixtures/a_recursive.rs"]
mod bootstrap_chain;
include!("../tests/common/proof_fixtures/bootstrap_omega_body.rs");
mod compact_bootstrap {
    include!("../tests/common/proof_fixtures/compact_bootstrap_body.rs");
}

#[test]
#[ignore = "genuine compact Bootstrap source and metadata Omega boundary; run optimized"]
fn omega_owner_early_and_late_cancel_then_fresh_proof_and_exact_read_only_replay() {
    use crate::omega::native::{Input, Program, Prover, ProverView};
    use iroha_plonk::keys::{CosetCachePolicy, pk::artifact::ReadConfig};
    let artifact = compact_bootstrap::rooted_compact_bootstrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = PinnedParams::<Eq>::derive(16).unwrap();
    let catalog = vec![artifact.source.key.to_bytes().to_vec()];
    let program = Program::for_compiled_catalog(
        artifact.source.binding.encoded(),
        &catalog,
        vparams.clone(),
        params.clone(),
    )
    .unwrap();
    let blank = program.source_circuit().unwrap();
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = false;
    config.coset_cache = CosetCachePolicy::OnDemand;
    let key = keygen_pk_v2(&params, &blank, &config).unwrap();
    assert_eq!(key.binding(), &artifact.binding);
    assert_eq!(key.vk().to_bytes(), artifact.key.to_bytes());
    let original = key.artifact_bytes_v2().unwrap();
    drop(key);
    drop(blank);
    let owner = Prover::from_original_artifact(
        program.clone(),
        artifact.binding.encoded(),
        artifact.key.to_bytes(),
        &original,
        ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        },
    )
    .unwrap();
    drop(original);
    let (binding, verifier, seal) = owner.into_metadata().into_parts();
    let view =
        ProverView::from_source_bound(&program, seal.bind(&binding, &verifier, None).unwrap())
            .unwrap();
    let session = view
        .prepare(
            Input {
                key: artifact.source.key.clone(),
                frame: artifact.source.instances.clone().try_into().unwrap(),
                proof: artifact.source.proof.clone(),
                public: artifact.source.state.lineage,
                pallas: artifact.source.pallas.clone(),
            },
            diagnostic_omega_tape(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    crate::proof_entry_probe::assert_owner_cancellation(
        |token| {
            session.prove(
                ProverRandomness::hedged(),
                ProverConfig {
                    cancellation: Some(token),
                    ..ProverConfig::default()
                },
            )
        },
        |error| error.is_cancelled(),
    );
    let entry = crate::proof_entry_probe::Guard::new(None);
    let fresh = session
        .prove(ProverRandomness::hedged(), ProverConfig::default())
        .unwrap();
    assert_eq!(
        entry.entries(),
        1,
        "fresh attempt succeeds after both cancellations"
    );
    let retained = fresh.transport();
    let proof_bytes = fresh.proof.len();
    assert_eq!(
        retained.len(),
        proof_bytes + 2 * iroha_plonk_recursion::ACCUMULATOR_BYTES
    );
    // Test-owned read-only observation; installed acceptance and expected-lineage
    // mutation controls live in Core native_exchange::omega_replay.
    for _ in 0..2 {
        let (proof, claims) = retained.split_at(proof_bytes);
        let (p, v) = claims.split_at(iroha_plonk_recursion::ACCUMULATOR_BYTES);
        let p = iroha_plonk_recursion::AccumulatorT::<Ep>::from_bytes(p).unwrap();
        let v = iroha_plonk_recursion::AccumulatorT::<Eq>::from_bytes(v).unwrap();
        assert_eq!(proof, fresh.proof);
        assert_eq!(p, fresh.pallas);
        assert_eq!(v, fresh.vesta);
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<Eq>(v.g());
        let instances = vec![
            fresh.instances[0].clone(),
            vec![x, y],
            v.challenges()
                .iter()
                .map(|u| Fq::from_repr(u.to_repr()).unwrap())
                .collect(),
        ];
        assert_eq!(instances, fresh.instances);
        let opening = iroha_plonk::verifier::verify_full_opening_cancellable(
            &params,
            &binding,
            &verifier,
            &instances,
            proof,
            MemoryBudget::DEFAULT,
            None,
        )
        .unwrap();
        assert_eq!(opening.g(), fresh.opening.g());
        assert_eq!(opening.challenges(), fresh.opening.challenges());
        p.decide(&params, MemoryBudget::DEFAULT).unwrap();
        v.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
        let mut observed = proof.to_vec();
        observed.extend_from_slice(&p.to_bytes());
        observed.extend_from_slice(&v.to_bytes());
        assert_eq!(observed, retained);
    }
    assert_eq!(fresh.transport(), retained, "exact original preserved");
    assert_eq!(
        entry.entries(),
        1,
        "read-only replay does not enter the producer"
    );
}
