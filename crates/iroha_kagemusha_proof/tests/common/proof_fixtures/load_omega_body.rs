// Shared genuine builder items. Registered tests remain in the integration harness.
use ff::PrimeField;
use iroha_kagemusha_proof::omega::{OmegaCircuit, OmegaPlan, OmegaWitness};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned_with_claim,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_recursion::{AccumulatorT, FoldConfig, create_fold};
pub use load_chain::LoadFixture;

/// Complete outer artifacts, carrying the construction's explicit provenance.
#[allow(dead_code)]
pub(crate) struct DiagnosticLoadOmega {
    pub(crate) source: load_chain::AuthenticatedLoad,
    pub(crate) key: iroha_plonk::VerifyingKey<Ep>,
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Vec<Fq>>,
    pub(crate) opening: iroha_plonk_recursion::FoldInput<Ep>,
    pub(crate) vesta: AccumulatorT<Eq>,
}

/// Produces a real native outer proof while retaining the Bootstrap-only
/// predecessor catalog. Its carried outer key is not rebound to the resulting
/// Load-only wrapper, so this cannot serve as a continuity-checked predecessor.
pub(crate) fn diagnostic_load_omega(
    diagnostics: bool,
    fixture: &LoadFixture,
) -> DiagnosticLoadOmega {
    let predecessor = load_chain::bootstrap_outer::rooted_bootstrap_omega_with_profile(
        false,
        load_chain::bootstrap_outer::bootstrap_chain::SourceProfile::Tagged { buses: 3 },
        Some(2),
    );
    let load = load_chain::authenticated_load(&predecessor, fixture);
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let (fold, vesta) = create_fold(
        &params,
        &[
            load.vesta_part.as_input(),
            load.opening.clone(),
            load.predecessor_vesta.as_input(),
            trivial.as_input(),
        ],
        Fq::from(141).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    vesta.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let (x, y) = vesta.g().coordinates().unwrap();
    let public = vec![
        vec![Fq::from_repr(load.instances[0].to_repr()).unwrap()],
        vec![x, y],
        vesta
            .challenges()
            .iter()
            .map(|v| Fq::from_repr(v.to_repr()).unwrap())
            .collect(),
    ];
    let digest = load.key.kagemusha_digest(&load.binding).unwrap();
    let plan = OmegaPlan::new(load.binding.clone(), params, vec![digest]).unwrap();
    let circuit = OmegaCircuit::new(
        plan,
        OmegaWitness {
            key: load.key.clone(),
            instances: load.instances.clone(),
            length: u32::try_from(load.proof.len()).unwrap(),
            proof: load.proof.clone(),
            fold: fold.to_bytes(),
        },
    )
    .unwrap();
    if diagnostics {
        eprintln!(
            "LOAD_COMPACT_CANDIDATE source_buses=3 operation_authorization_complete=true full_catalog=false carried_outer_key_rebound=false"
        );
        load_chain::bootstrap_outer::compact_diagnostic(&circuit, &public);
        let pinned = circuit
            .clone()
            .with_key_catalog(vec![load.key.clone()])
            .unwrap();
        load_chain::bootstrap_outer::compact_diagnostic(&pinned, &public);
    }
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let witness = Witness::from_circuit(&key, &circuit, &public).unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        witness,
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    let opened = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opened.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let opening =
        iroha_plonk_recursion::FoldInput::from_opening(*opened.g(), opened.challenges()).unwrap();
    eprintln!(
        "LOAD_OMEGA source_A_bytes={} actual_proof_bytes={} transport_bytes={} operation_authorization_complete=true full_catalog=false carried_outer_key_rebound=false production_size_pass={} release_qualified=false",
        load.proof.len(),
        proof.proof.len(),
        proof.proof.len() + 1088,
        proof.proof.len() + 1088 <= 4821,
    );
    DiagnosticLoadOmega {
        source: load,
        key: key.vk().clone(),
        binding: key.binding().clone(),
        proof: proof.proof,
        instances: public,
        opening,
        vesta,
    }
}

/// Run the retained composition assertions with genuine native Load originals.
/// The `load_omega` ignored integration test supplies the native BLS receipt fixture.
#[allow(dead_code)] // Shared by integration harnesses selecting different component scopes.
pub fn native_load_reaches_complete_outer_predicate(fixture: &LoadFixture) {
    let _ = diagnostic_load_omega(true, fixture);
}

/// A common-key Bootstrap→Load component catalog, with exact carried-key continuity.
/// This deliberately contains only the two implemented terminal keys; production
/// admission still requires the complete operation catalog and size qualification.
#[allow(dead_code)]
pub(crate) struct TwoTerminalLoadOmega {
    pub(crate) artifact: DiagnosticLoadOmega,
    pub(crate) catalog: [iroha_plonk::VerifyingKey<Eq>; 2],
}
#[derive(Clone, Copy)]
struct OuterSource<'a> {
    key: &'a iroha_plonk::VerifyingKey<Eq>,
    binding: &'a iroha_plonk::DescriptorBinding,
    proof: &'a [u8],
    instances: &'a [Fp],
    part: &'a AccumulatorT<Eq>,
    opening: &'a iroha_plonk_recursion::FoldInput<Eq>,
    predecessor: &'a AccumulatorT<Eq>,
}
fn catalog_wrapper(
    source: OuterSource<'_>,
    catalog: &[iroha_plonk::VerifyingKey<Eq>; 2],
) -> (OmegaCircuit, Vec<Vec<Fq>>, AccumulatorT<Eq>) {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let (fold, vesta) = create_fold(
        &params,
        &[
            source.part.as_input(),
            source.opening.clone(),
            source.predecessor.as_input(),
            trivial.as_input(),
        ],
        Fq::from(151).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    vesta.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let (x, y) = vesta.g().coordinates().unwrap();
    let public = vec![
        vec![Fq::from_repr(source.instances[0].to_repr()).unwrap()],
        vec![x, y],
        vesta
            .challenges()
            .iter()
            .map(|v| Fq::from_repr(v.to_repr()).unwrap())
            .collect(),
    ];
    let allowlist = catalog
        .iter()
        .map(|key| key.kagemusha_digest(source.binding).unwrap())
        .collect();
    // Both operations use this exact fixed descriptor and complete two-key
    // allowlist. Key selection remains a constrained witness, not a native bypass.
    let plan = OmegaPlan::new(source.binding.clone(), params, allowlist).unwrap();
    let circuit = OmegaCircuit::new(
        plan,
        OmegaWitness {
            key: source.key.clone(),
            instances: source.instances.to_vec(),
            proof: source.proof.to_vec(),
            length: source.proof.len().try_into().unwrap(),
            fold: fold.to_bytes(),
        },
    )
    .unwrap();
    (circuit, public, vesta)
}
fn prove_catalog_wrapper(
    circuit: &OmegaCircuit,
    public: &[Vec<Fq>],
    expected: &iroha_plonk::ProvingKey<Ep>,
) -> iroha_plonk::ProverOutput<Ep> {
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let key = keygen_pk_v2(&params, circuit, &catalog_key_config()).unwrap();
    assert_eq!(key.binding(), expected.binding());
    assert_eq!(
        key.vk().to_bytes(),
        expected.vk().to_bytes(),
        "one immutable Omega key for both terminal variants"
    );
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, circuit, public).unwrap(),
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    let claim = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim.decide(&params, MemoryBudget::DEFAULT).unwrap();
    assert_eq!(claim.g(), proof.opening.g());
    assert_eq!(claim.challenges(), proof.opening.challenges());
    proof
}
fn catalog_key_config() -> KeygenConfigV2 {
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = false;
    config
}
/// Rebuild both complete source chains under one immutable two-terminal Omega key.
/// Every before/after terminal key and descriptor must remain exactly identical.
#[allow(dead_code)]
pub(crate) fn two_terminal_load_omega(fixture: &LoadFixture) -> TwoTerminalLoadOmega {
    use load_chain::bootstrap_outer::{RootedBootstrapOmega, bootstrap_chain};
    let initial_predecessor = load_chain::bootstrap_outer::rooted_bootstrap_omega_with_profile(
        false,
        bootstrap_chain::SourceProfile::Tagged { buses: 3 },
        Some(2),
    );
    let initial_load = load_chain::authenticated_load(&initial_predecessor, fixture);
    let initial_bootstrap = &initial_predecessor.source;
    assert_eq!(
        initial_load.binding, initial_bootstrap.binding,
        "one source descriptor for both terminals"
    );
    let catalog = [initial_bootstrap.key.clone(), initial_load.key.clone()];
    assert_ne!(catalog[0].to_bytes(), catalog[1].to_bytes());
    let vparams = PinnedParams::<Eq>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
    let initial_part = initial_bootstrap.vesta_part.clone();
    let (circuit, _, _) = catalog_wrapper(
        OuterSource {
            key: &initial_bootstrap.key,
            binding: &initial_bootstrap.binding,
            proof: &initial_bootstrap.proof,
            instances: &initial_bootstrap.instances,
            part: &initial_part,
            opening: &initial_bootstrap.opening,
            predecessor: &trivial,
        },
        &catalog,
    );
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let outer_key = keygen_pk_v2(&params, &circuit, &catalog_key_config()).unwrap();
    eprintln!(
        "TWO_TERMINAL_DESCRIPTOR_BASELINE one_key={:?} two_keys={:?}",
        iroha_plonk::Protocol::new(initial_predecessor.binding.descriptor())
            .unwrap()
            .shape(),
        iroha_plonk::Protocol::new(outer_key.binding().descriptor())
            .unwrap()
            .shape(),
    );
    assert_eq!(
        &initial_predecessor.binding,
        outer_key.binding(),
        "catalog size1→2 must retain the exact predecessor program descriptor",
    );
    eprintln!(
        "TWO_TERMINAL_PROFILE source_range_buses=3 q_range_buses=2 outer_compress_selectors=false catalog_size1_to2_descriptor_equal=true outer_shape={:?} compact_production_profile=false",
        iroha_plonk::Protocol::new(outer_key.binding().descriptor())
            .unwrap()
            .shape(),
    );
    let digest = outer_key
        .vk()
        .kagemusha_digest(outer_key.binding())
        .unwrap();
    let bootstrap = bootstrap_chain::authenticated_bootstrap_with_profile(
        false,
        digest,
        bootstrap_chain::SourceProfile::Tagged { buses: 3 },
        Some(2),
    );
    assert_eq!(initial_bootstrap.binding, bootstrap.binding);
    assert_eq!(initial_bootstrap.key.to_bytes(), bootstrap.key.to_bytes());
    assert_eq!(bootstrap.state.lineage[17], digest);
    let bootstrap_part = bootstrap.vesta_part.clone();
    let (circuit, public, vesta) = catalog_wrapper(
        OuterSource {
            key: &bootstrap.key,
            binding: &bootstrap.binding,
            proof: &bootstrap.proof,
            instances: &bootstrap.instances,
            part: &bootstrap_part,
            opening: &bootstrap.opening,
            predecessor: &trivial,
        },
        &catalog,
    );
    let proof = prove_catalog_wrapper(&circuit, &public, &outer_key);
    let bootstrap = RootedBootstrapOmega {
        source: bootstrap,
        key: outer_key.vk().clone(),
        binding: outer_key.binding().clone(),
        instances: public,
        proof: proof.proof,
        opening: iroha_plonk_recursion::FoldInput::from_opening(
            *proof.opening.g(),
            proof.opening.challenges(),
        )
        .unwrap(),
        vesta,
    };
    let load = load_chain::authenticated_load(&bootstrap, fixture);
    assert_eq!(initial_load.binding, load.binding);
    assert_eq!(initial_load.key.to_bytes(), load.key.to_bytes());
    assert_eq!(load.state.lineage[17], digest);
    let (circuit, public, vesta) = catalog_wrapper(
        OuterSource {
            key: &load.key,
            binding: &load.binding,
            proof: &load.proof,
            instances: &load.instances,
            part: &load.vesta_part,
            opening: &load.opening,
            predecessor: &load.predecessor_vesta,
        },
        &catalog,
    );
    let proof = prove_catalog_wrapper(&circuit, &public, &outer_key);
    let opening = iroha_plonk_recursion::FoldInput::from_opening(
        *proof.opening.g(),
        proof.opening.challenges(),
    )
    .unwrap();
    eprintln!(
        "TWO_TERMINAL_BOOTSTRAP_LOAD actual_source_keys_equal=true descriptor_equal=true actual_omega_key_bound=true full_catalog=false production_size_pass=false release_qualified=false"
    );
    TwoTerminalLoadOmega {
        artifact: DiagnosticLoadOmega {
            source: load,
            key: outer_key.vk().clone(),
            binding: outer_key.binding().clone(),
            proof: proof.proof,
            instances: public,
            opening,
            vesta,
        },
        catalog,
    }
}
/// Run the retained composition assertions with genuine native Load originals.
/// The `load_omega` ignored integration test supplies the native BLS receipt fixture.
#[allow(dead_code)] // Shared by integration harnesses selecting different component scopes.
pub fn common_bootstrap_load_catalog_rebinds_every_proof_and_key(fixture: &LoadFixture) {
    let output = two_terminal_load_omega(fixture);
    assert_eq!(
        output.artifact.source.state.lineage[17],
        output
            .artifact
            .key
            .kagemusha_digest(&output.artifact.binding)
            .unwrap()
    );
}
