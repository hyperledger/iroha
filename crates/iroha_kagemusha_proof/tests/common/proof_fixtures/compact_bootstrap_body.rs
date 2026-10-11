// Shared genuine builder items. Registered tests remain in the integration harness.
use super::*;

/// Produces the single-terminal compact component with exact key continuity.
/// Defaults and the oversized diagnostic helpers remain separate profiles.
pub(crate) fn rooted_compact_bootstrap() -> RootedBootstrapOmega {
    rooted_compact_bootstrap_with_identity(bootstrap_chain::BootstrapIdentity::Payer)
}

/// Rebuilds an independently enrolled wallet under its actual compact outer key.
/// Identity changes only witnesses; all descriptor/key continuity checks remain.
pub(crate) fn rooted_compact_bootstrap_with_identity(
    identity: bootstrap_chain::BootstrapIdentity,
) -> RootedBootstrapOmega {
    let profile = bootstrap_chain::SourceProfile::Tagged { buses: 3 };
    let initial = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        Fp::from(91),
        profile,
        Some(2),
        identity,
    );
    let (initial_circuit, initial_public, _) = wrapper(&initial);
    let initial_circuit = initial_circuit
        .with_key_catalog(vec![initial.key.clone()])
        .unwrap();
    let (spans, schedule) = compact_layout(&initial_circuit, &initial_public, false)
        .expect("actual one-terminal compact predicate fits unchanged hard limits");
    let initial_circuit = initial_circuit.with_secondary_layout(spans, schedule.clone());
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = false;
    let initial_key = keygen_pk_v2(&params, &initial_circuit, &config).unwrap();
    let initial_binding = initial_key.binding().clone();
    let initial_vk = initial_key.vk().clone();
    let digest = initial_vk.kagemusha_digest(&initial_binding).unwrap();
    let original = initial_key.artifact_bytes_v2().unwrap();
    drop(initial_key);

    // The installation factory independently reconstructs the same source from
    // only the terminal originals. It must not need the valid source witness used
    // by the engineering diagnostic above or change the already selected key.
    let catalog = [initial.key.to_bytes().to_vec()];
    let native_program = iroha_kagemusha_proof::omega::native::Program::for_compiled_catalog(
        initial.binding.encoded(),
        &catalog,
        PinnedParams::<Eq>::derive(16).unwrap(),
        params.clone(),
    )
    .unwrap();
    let factory = native_program.source_circuit().unwrap();
    let (factory_binding, factory_key) =
        iroha_plonk::keys::keygen_vk_with_binding_v2(&params, &factory, &config).unwrap();
    assert_eq!(factory_binding, initial_binding);
    assert_eq!(factory_key.to_bytes(), initial_vk.to_bytes());
    let native = iroha_kagemusha_proof::omega::native::Prover::from_original_artifact(
        native_program.clone(),
        initial_binding.encoded(),
        initial_vk.to_bytes(),
        &original,
        iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        },
    )
    .unwrap();
    assert_eq!(native.binding(), &initial_binding);
    assert_eq!(native.verifying_key().to_bytes(), initial_vk.to_bytes());
    drop(native);
    drop(original);
    for bad_catalog in [vec![], vec![catalog[0].clone(), catalog[0].clone()]] {
        assert!(
            iroha_kagemusha_proof::omega::native::Program::for_compiled_catalog(
                initial.binding.encoded(),
                &bad_catalog,
                PinnedParams::<Eq>::derive(16).unwrap(),
                params.clone(),
            )
            .is_err()
        );
    }

    // The signed credential, receipt, sigma, Q and each A/W stage are rebuilt
    // with the actual digest. No public word is changed after a proof exists.
    let source = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        digest,
        profile,
        Some(2),
        identity,
    );
    assert_eq!(source.state.lineage[17], digest);
    assert_eq!(initial.binding, source.binding);
    assert_eq!(initial.key.to_bytes(), source.key.to_bytes());
    let (circuit, public, vesta) = wrapper(&source);
    let circuit = circuit
        .with_key_catalog(vec![source.key.clone()])
        .unwrap()
        .with_secondary_layout(spans, schedule);
    let assigned = synthesize(&circuit, 16, Some(&public)).unwrap();
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let unknown = synthesize(
        &iroha_plonk::frontend::Circuit::without_witnesses(&circuit),
        16,
        None,
    )
    .unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    drop(assigned);
    drop(unknown);

    let key = keygen_pk_v2(&params, &circuit, &config).unwrap();
    assert_eq!(key.binding(), &initial_binding);
    assert_eq!(key.vk().to_bytes(), initial_vk.to_bytes());
    let protocol = Protocol::new(key.binding().descriptor()).unwrap();
    assert_eq!(protocol.shape().degree, 9);
    assert_eq!(protocol.shape().lookups, 1);
    assert_eq!(protocol.proof_length(), 3712);
    let output = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &public).unwrap(),
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    let verified = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &output.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    verified.decide(&params, MemoryBudget::DEFAULT).unwrap();
    vesta
        .decide(
            &PinnedParams::<Eq>::derive(16).unwrap(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    assert_eq!(output.proof.len(), 3712);
    let opening =
        iroha_plonk_recursion::FoldInput::from_opening(*verified.g(), verified.challenges())
            .unwrap();
    for (column, row) in [(0, 0), (1, 0), (2, 0)] {
        let mut wrong = public.clone();
        wrong[column][row] += Fq::ONE;
        assert!(
            iroha_plonk::verify_full(
                &params,
                key.binding(),
                key.vk(),
                &wrong,
                &output.proof,
                MemoryBudget::DEFAULT,
            )
            .is_err()
        );
    }
    let mut wrong_proof = output.proof.clone();
    wrong_proof[0] ^= 1;
    assert!(
        iroha_plonk::verify_full(
            &params,
            key.binding(),
            key.vk(),
            &public,
            &wrong_proof,
            MemoryBudget::DEFAULT,
        )
        .is_err()
    );
    eprintln!(
        "ROOTED_COMPACT_BOOTSTRAP actual_proof_bytes={} transport_bytes={} lineage_rebound=true source_key_immutable=true outer_key_immutable=true decides=2 catalog_terminals=1 full_catalog=false release_qualified=false",
        output.proof.len(),
        output.proof.len() + 1088,
    );
    RootedBootstrapOmega {
        source,
        key: key.vk().clone(),
        binding: key.binding().clone(),
        proof: output.proof,
        instances: public,
        opening,
        vesta,
    }
}
