// Shared core builders are also used by the private compact-owner unit test.
include!("bootstrap_omega_shared.rs");

/// Checks the complete compact predicate and reports its exact row/byte gates.
pub fn compact_diagnostic(circuit: &OmegaCircuit, public: &[Vec<Fq>]) {
    let _ = compact_layout(circuit, public, true);
}

/// Rebuilds all authenticated witnesses against the actual immutable outer key.
pub fn rooted_bootstrap_omega(diagnostics: bool) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_layout(diagnostics, 0)
}

/// Rooted component with an explicit common source profile. Shared-range
/// profiles disable Omega selector compression so catalog size cannot alter
/// the predecessor descriptor before the terminal keys are constructed.
pub fn rooted_bootstrap_omega_with_layout(
    diagnostics: bool,
    source_buses: usize,
) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_profile(
        diagnostics,
        bootstrap_chain::SourceProfile::ordinary(source_buses),
    )
}

/// Named source profile, identically used before and after immutable-key rebinding.
pub fn rooted_bootstrap_omega_with_profile(
    diagnostics: bool,
    profile: bootstrap_chain::SourceProfile,
) -> RootedBootstrapOmega {
    rooted_bootstrap_omega_with_identity(
        diagnostics,
        profile,
        bootstrap_chain::BootstrapIdentity::Payer,
    )
}

/// Root the same Bootstrap key with a separately enrolled receiver identity.
pub fn rooted_bootstrap_omega_with_identity(
    diagnostics: bool,
    profile: bootstrap_chain::SourceProfile,
    identity: bootstrap_chain::BootstrapIdentity,
) -> RootedBootstrapOmega {
    let first = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        Fp::from(91),
        profile,
        identity,
    );
    let (first_circuit, _, _) = wrapper(&first);
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = profile == bootstrap_chain::SourceProfile::Generic;
    let first_key = keygen_pk_v2(&params, &first_circuit, &config).unwrap();
    let omega_digest = first_key
        .vk()
        .kagemusha_digest(first_key.binding())
        .unwrap();
    let first_binding = first_key.binding().clone();
    let first_vk = first_key.vk().clone();
    drop(first_key);
    // Rebuild every signed object and proof with the actual admitted Omega key
    // digest, then prove that neither A nor Omega key depends on that witness.
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        omega_digest,
        profile,
        identity,
    );
    assert_eq!(first.binding, bootstrap.binding);
    assert_eq!(
        first.key.kagemusha_digest(&first.binding).unwrap(),
        bootstrap.key.kagemusha_digest(&bootstrap.binding).unwrap()
    );
    eprintln!(
        "AUTHENTICATED_BOOTSTRAP_A_SOURCE shape={:?}",
        Protocol::new(bootstrap.binding.descriptor())
            .unwrap()
            .shape()
    );
    let source_bytes = bootstrap.proof.len();
    let (circuit, public, vesta) = wrapper(&bootstrap);
    if diagnostics {
        compact_diagnostic(&circuit, &public);
    }
    let assigned = synthesize(&circuit, 16, Some(&public)).unwrap();
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let lanes: Vec<_> = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
        .collect();
    drop(assigned);
    let key = keygen_pk_v2(&params, &circuit, &config).unwrap();
    assert_eq!(key.binding(), &first_binding);
    assert_eq!(key.vk().to_bytes(), first_vk.to_bytes());
    let witness = Witness::from_circuit(&key, &circuit, &public).unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        witness,
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    let verified = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    verified.decide(&params, MemoryBudget::DEFAULT).unwrap();
    eprintln!(
        "AUTHENTICATED_BOOTSTRAP_OMEGA source_A_bytes={source_bytes} lanes={lanes:?} actual_proof_bytes={} transport_bytes={} source_operation_authenticated=true actual_omega_key_bound=true production_size_pass={} release_qualified=false",
        proof.proof.len(),
        proof.proof.len() + 1088,
        proof.proof.len() + 1088 <= 4821
    );
    RootedBootstrapOmega {
        source: bootstrap,
        key: key.vk().clone(),
        binding: key.binding().clone(),
        proof: proof.proof,
        instances: public,
        opening: iroha_plonk_recursion::FoldInput::from_opening(
            *verified.g(),
            verified.challenges(),
        )
        .unwrap(),
        vesta,
    }
}

fn serialized_foreign_inventory(range_buses: usize) {
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_layout(
        false,
        iroha_pasta::Fp::from(91),
        range_buses,
    );
    source_outer_inventory(&bootstrap, range_buses);
}

fn source_outer_inventory(bootstrap: &bootstrap_chain::AuthenticatedBootstrap, range_buses: usize) {
    let source = Protocol::new(bootstrap.binding.descriptor()).unwrap();
    eprintln!(
        "SERIALIZED_FF_BOOTSTRAP_A_SOURCE total_buses={range_buses} shape={:?} actual_proof_bytes={}",
        source.shape(),
        bootstrap.proof.len()
    );
    let (circuit, public, _) = wrapper(bootstrap);
    compact_diagnostic(&circuit, &public);
    let pinned = circuit
        .clone()
        .with_key_catalog(vec![bootstrap.key.clone()])
        .unwrap();
    eprintln!("AUTHENTICATED_BOOTSTRAP_PINNED_KEY_CATALOG entries=1 full_catalog=false");
    compact_diagnostic(&pinned, &public);
}
