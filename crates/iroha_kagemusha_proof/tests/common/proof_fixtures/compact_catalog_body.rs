// Shared genuine builder items. Registered tests remain in the integration harness.
use bootstrap_outer::{RootedBootstrapOmega, bootstrap_chain};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::omega::{OmegaCircuit, OmegaPlan, OmegaWitness, native};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, PastaCurve, msm::MemoryBudget};
use iroha_plonk::{
    DescriptorBinding, Protocol, ProverConfig, ProverRandomness, VerifyingKey, Witness,
    create_proof_owned_with_claim,
    frontend::{Circuit, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::range::secondary::SecondaryPlan;
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, create_fold, verifier::CompactSpans,
};
use load_outer::{
    DiagnosticLoadOmega,
    load_chain::{self, bootstrap_outer},
};

pub use load_chain::LoadFixture;

const PROFILE: bootstrap_chain::SourceProfile = bootstrap_chain::SourceProfile::Tagged { buses: 3 };

/// Genuine terminal originals, including the exact lineage prefix and full P claim.
#[derive(Clone, Copy)]
pub struct Terminal<'a> {
    pub(crate) key: &'a VerifyingKey<Eq>,
    pub(crate) binding: &'a DescriptorBinding,
    pub(crate) proof: &'a [u8],
    pub(crate) instances: &'a [Fp],
    pub(crate) public: &'a [Fp; 18],
    pub(crate) pallas: &'a AccumulatorT<Ep>,
    pub(crate) opening: &'a FoldInput<Eq>,
}

fn wrap(
    source: Terminal<'_>,
    catalog: &[VerifyingKey<Eq>],
) -> (OmegaCircuit, Vec<Vec<Fq>>, AccumulatorT<Eq>) {
    let params = PinnedParams::<Eq>::derive(16).unwrap();
    let frame: [Fp; 69] = source.instances.try_into().unwrap();
    let slots = native::terminal_fold_inputs(&frame, source.opening.clone()).unwrap();
    let (fold, vesta) = create_fold(
        &params,
        &slots,
        Fq::from(181).to_repr(),
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
            .map(|value| Fq::from_repr(value.to_repr()).unwrap())
            .collect(),
    ];
    let digests = catalog
        .iter()
        .map(|key| key.kagemusha_digest(source.binding).unwrap())
        .collect();
    let plan = OmegaPlan::new(source.binding.clone(), params, digests)
        .and_then(|plan| plan.with_key_catalog(catalog.to_vec()))
        .unwrap();
    // One canonical pinned-catalog source, identical to the native importer.
    // Catalog selection and complete membership remain circuit constrained.
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

/// Immutable test catalog using the production native pinned-key source.
pub struct Program {
    native: native::Prover,
    source_binding: DescriptorBinding,
    catalog: Vec<VerifyingKey<Eq>>,
    spans: CompactSpans,
    schedule: SecondaryPlan,
    binding: DescriptorBinding,
    key: VerifyingKey<Ep>,
}
/// Actual native outer proof and all obligations needed by the next operation.
pub struct Outer {
    pub(crate) proof: Vec<u8>,
    pub(crate) public: Vec<Vec<Fq>>,
    pub(crate) opening: FoldInput<Ep>,
    pub(crate) vesta: AccumulatorT<Eq>,
}
fn key_config() -> KeygenConfigV2 {
    let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    config.compress_selectors = false;
    config
}
impl Program {
    fn new(
        source: Terminal<'_>,
        catalog: Vec<VerifyingKey<Eq>>,
        predecessor_binding: &DescriptorBinding,
    ) -> Self {
        let (circuit, public, _) = wrap(source, &catalog);
        let (spans, schedule) = bootstrap_outer::compact_layout(&circuit, &public, false)
            .expect("common catalog must fit unchanged k16 range/shared capacity");
        let circuit = circuit.with_secondary_layout(spans, schedule.clone());
        let params = PinnedParams::<Ep>::derive(16).unwrap();
        let key = keygen_pk_v2(&params, &circuit, &key_config()).unwrap();
        let protocol = Protocol::new(key.binding().descriptor()).unwrap();
        assert_eq!(protocol.shape().degree, 9);
        assert_eq!(protocol.shape().lookups, 1);
        assert_eq!(protocol.proof_length(), 3712);
        assert_eq!(
            key.binding(),
            predecessor_binding,
            "catalog growth must preserve the exact predecessor descriptor"
        );
        eprintln!(
            "COMPACT_CATALOG_KEY terminals={} descriptor_unchanged=true shape={:?} expected_transport=4800 actual_proof=false",
            catalog.len(),
            protocol.shape()
        );
        let original = key.artifact_bytes_v2().unwrap();
        let native_program = native::Program::new(
            source.binding.encoded(),
            &catalog
                .iter()
                .map(|key| key.to_bytes().to_vec())
                .collect::<Vec<_>>(),
            PinnedParams::<Eq>::derive(16).unwrap(),
            params,
            native::Layout::Secondary {
                spans,
                schedule: schedule.clone(),
            },
        )
        .unwrap();
        let native = native::Prover::from_original_artifact(
            native_program,
            key.binding().encoded(),
            key.vk().to_bytes(),
            &original,
            iroha_plonk::keys::pk::artifact::ReadConfig {
                maximum_bytes: original.len(),
                maximum_rows: 1 << 16,
                coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
                msm_budget: MemoryBudget::DEFAULT,
            },
        )
        .unwrap();
        Self {
            native,
            source_binding: source.binding.clone(),
            catalog,
            spans,
            schedule,
            binding: key.binding().clone(),
            key: key.vk().clone(),
        }
    }
    /// Exact outer-key digest carried by all rebuilt signed sources.
    pub fn digest(&self) -> Fp {
        self.key.kagemusha_digest(&self.binding).unwrap()
    }
    /// Exact descriptor of the immutable native outer source.
    pub fn binding(&self) -> &DescriptorBinding {
        &self.binding
    }
    /// Immutable outer verifier shared by the rebuilt wallets.
    pub fn verifying_key(&self) -> &VerifyingKey<Ep> {
        &self.key
    }
    /// Complete pinned set of permitted terminal verifier keys.
    pub fn catalog(&self) -> &[VerifyingKey<Eq>] {
        &self.catalog
    }
    /// Prove and restore an actual terminal through the original-key native producer.
    pub fn prove(&self, source: Terminal<'_>, label: &str) -> Outer {
        assert_eq!(source.binding, &self.source_binding);
        let (circuit, public, vesta) = wrap(source, &self.catalog);
        let circuit = circuit.with_secondary_layout(self.spans, self.schedule.clone());
        let assigned = synthesize(&circuit, 16, Some(&public)).unwrap();
        let report = iroha_plonk::check::check(
            &assigned.cs,
            &assigned.tables,
            iroha_plonk::check::CheckMode::Strict,
        )
        .unwrap();
        assert!(
            report.is_satisfied(),
            "{label}: {:?}",
            report.failures().first()
        );
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            assigned.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        drop(assigned);
        drop(unknown);
        let params = PinnedParams::<Ep>::derive(16).unwrap();
        let key = keygen_pk_v2(&params, &circuit, &key_config()).unwrap();
        assert_eq!(key.binding(), &self.binding);
        assert_eq!(
            key.vk().to_bytes(),
            self.key.to_bytes(),
            "{label}: immutable common outer key"
        );
        drop(key);
        let session = self
            .native
            .prepare(
                native::Input {
                    key: source.key.clone(),
                    proof: source.proof.to_vec(),
                    frame: source.instances.try_into().unwrap(),
                    public: *source.public,
                    pallas: source.pallas.clone(),
                },
                Fq::from(181).to_repr(),
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        let output = session
            .prove(ProverRandomness::os(), ProverConfig::default())
            .unwrap();
        assert_eq!(output.instances, public);
        assert_eq!(output.pallas, *source.pallas);
        assert_eq!(output.vesta, vesta);
        let transport = output.transport();
        let restored = session
            .restore_transport(&transport, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(restored.transport(), transport);
        assert_eq!(restored.proof, output.proof);
        assert_eq!(restored.instances, output.instances);
        assert_eq!(restored.pallas, output.pallas);
        assert_eq!(restored.vesta, output.vesta);
        assert_eq!(restored.opening, output.opening);
        assert_eq!(output.proof.len(), 3712);
        let opened = accumulate_generator(
            &params,
            &self.binding,
            &self.key,
            &public,
            &output.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        opened.decide(&params, MemoryBudget::DEFAULT).unwrap();
        assert_eq!(opened.g(), output.opening.g());
        assert_eq!(opened.challenges(), output.opening.challenges());
        for (column, row) in [(0, 0), (1, 0), (2, 0)] {
            let mut changed = public.clone();
            changed[column][row] += Fq::ONE;
            assert!(
                iroha_plonk::verify_full(
                    &params,
                    &self.binding,
                    &self.key,
                    &changed,
                    &output.proof,
                    MemoryBudget::DEFAULT
                )
                .is_err()
            );
        }
        eprintln!(
            "COMPACT_CATALOG_OUTER terminal={label} catalog_size={} actual_proof=3712 transport=4800 native_original_import=true native_transport_restore=true known_unknown_equal=true immutable_key=true decides=2 full_catalog=false release_qualified=false",
            self.catalog.len()
        );
        Outer {
            proof: output.proof,
            public,
            opening: FoldInput::from_opening(*opened.g(), opened.challenges()).unwrap(),
            vesta,
        }
    }
}

fn bootstrap_terminal(source: &bootstrap_chain::AuthenticatedBootstrap) -> Terminal<'_> {
    Terminal {
        key: &source.key,
        binding: &source.binding,
        proof: &source.proof,
        instances: &source.instances,
        public: &source.state.lineage,
        pallas: &source.pallas,
        opening: &source.opening,
    }
}

fn load_terminal(source: &load_chain::AuthenticatedLoad) -> Terminal<'_> {
    Terminal {
        key: &source.key,
        binding: &source.binding,
        proof: &source.proof,
        instances: &source.instances,
        public: &source.state.lineage,
        pallas: &source.pallas,
        opening: &source.opening,
    }
}

fn rebuild_bootstrap_load(
    program: &Program,
    initial_bootstrap: &bootstrap_chain::AuthenticatedBootstrap,
    initial_load: &load_chain::AuthenticatedLoad,
    fixture: &LoadFixture,
) -> DiagnosticLoadOmega {
    let source = bootstrap_chain::authenticated_bootstrap_with_profile(
        false,
        program.digest(),
        PROFILE,
        Some(2),
    );
    assert_eq!(source.binding, initial_bootstrap.binding);
    assert_eq!(source.key.to_bytes(), initial_bootstrap.key.to_bytes());
    assert_eq!(source.state.lineage[17], program.digest());
    let outer = program.prove(bootstrap_terminal(&source), "Bootstrap");
    let rooted = RootedBootstrapOmega {
        source,
        key: program.key.clone(),
        binding: program.binding.clone(),
        proof: outer.proof,
        instances: outer.public,
        opening: outer.opening,
        vesta: outer.vesta,
    };
    let source = load_chain::authenticated_load(&rooted, fixture);
    assert_eq!(source.binding, initial_load.binding);
    assert_eq!(source.key.to_bytes(), initial_load.key.to_bytes());
    assert_eq!(source.state.lineage[17], program.digest());
    let outer = program.prove(load_terminal(&source), "Load");
    source
        .pallas
        .decide(
            &PinnedParams::<Ep>::derive(16).unwrap(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    DiagnosticLoadOmega {
        source,
        key: program.key.clone(),
        binding: program.binding.clone(),
        proof: outer.proof,
        instances: outer.public,
        opening: outer.opening,
        vesta: outer.vesta,
    }
}

/// Independently enrolled wallets under one genuine two-terminal compact key.
/// The payer has completed Load; the receiver is at Bootstrap. The catalog admits
/// only those two source relations and does not qualify a Receive terminal.
pub struct SharedKeyWallets {
    /// Payer predecessor with spendable loaded value and a verified outer proof.
    pub(crate) payer: DiagnosticLoadOmega,
    /// Distinct receiver with its own signed enrollment and verified outer proof.
    pub(crate) receiver: RootedBootstrapOmega,
}

fn compact_load_program(
    fixture: &LoadFixture,
) -> (
    Program,
    bootstrap_chain::AuthenticatedBootstrap,
    load_chain::AuthenticatedLoad,
) {
    let initial_root = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    let initial_load = load_chain::authenticated_load(&initial_root, fixture);
    let initial_bootstrap = &initial_root.source;
    assert_eq!(initial_bootstrap.binding, initial_load.binding);
    let program = Program::new(
        bootstrap_terminal(initial_bootstrap),
        vec![initial_bootstrap.key.clone(), initial_load.key.clone()],
        &initial_root.binding,
    );
    (program, initial_root.source, initial_load)
}

/// Rebuilds the payer's exact signed Bootstrap/Load chain under the immutable
/// two-terminal compact key. No receiver is constructed and no additional
/// operation terminal is admitted by this component catalog.
#[allow(dead_code)] // Consumed by real Unload/Retiring integration fixtures.
pub(crate) fn compact_payer_load(fixture: &LoadFixture) -> DiagnosticLoadOmega {
    let (program, initial_bootstrap, initial_load) = compact_load_program(fixture);
    rebuild_bootstrap_load(&program, &initial_bootstrap, &initial_load, fixture)
}

/// Rebuilds both wallets' exact signed objects and all recursive source proofs
/// under the same immutable compact Bootstrap/Load catalog key. No statement or
/// state word is changed after proving; both retained accumulators are decided.
#[allow(dead_code)] // Consumed by the accepted Receive integration fixture.
pub(crate) fn compact_payer_load_and_receiver(fixture: &LoadFixture) -> SharedKeyWallets {
    compact_shared_wallets_and_program(fixture).1
}
fn compact_shared_wallets_and_program(fixture: &LoadFixture) -> (Program, SharedKeyWallets) {
    let (_, program, wallets) = compact_shared_wallet_seed(fixture.clone());
    (program, wallets)
}

/// Original measured Bootstrap/Load terminal identities retained for immutable rebuilding.
pub struct CatalogSeed {
    bootstrap: bootstrap_chain::AuthenticatedBootstrap,
    load: load_chain::AuthenticatedLoad,
    fixture: LoadFixture,
}

/// Exact Bootstrap terminal identity retained for an unfunded component catalog.
/// This seed carries no Load authority, proving key or fabricated accepted head.
pub struct BootstrapCatalogSeed {
    binding: DescriptorBinding,
    key: VerifyingKey<Eq>,
}
impl BootstrapCatalogSeed {
    /// Extend the immutable catalog and rebuild the signed receiver Bootstrap.
    /// Every proposed terminal must later reproduce its exact planned source key.
    pub fn extend(
        &self,
        program: &Program,
        receiver: &RootedBootstrapOmega,
        extra_binding: &DescriptorBinding,
        extra: Vec<VerifyingKey<Eq>>,
    ) -> (Program, RootedBootstrapOmega) {
        assert!(!extra.is_empty());
        assert_eq!(extra_binding, &self.binding);
        assert_eq!(receiver.source.binding, self.binding);
        assert_eq!(receiver.source.key.to_bytes(), self.key.to_bytes());
        assert_eq!(receiver.binding, program.binding);
        assert_eq!(receiver.key.to_bytes(), program.key.to_bytes());
        assert_eq!(receiver.source.state.lineage[17], program.digest());
        let mut catalog = program.catalog.clone();
        catalog.extend(extra);
        let next = Program::new(
            bootstrap_terminal(&receiver.source),
            catalog,
            &program.binding,
        );
        let receiver = rebuild_receiver_bootstrap(&next, &self.binding, &self.key);
        (next, receiver)
    }
}

/// Build a genuine zero-balance receiver under a one-terminal native catalog.
/// Native original import, exact native transport replay and both decisions are checked.
pub fn compact_bootstrap_catalog_seed() -> (BootstrapCatalogSeed, Program, RootedBootstrapOmega) {
    let mut receiver = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap_with_identity(
        bootstrap_chain::BootstrapIdentity::Receiver,
    );
    let seed = BootstrapCatalogSeed {
        binding: receiver.source.binding.clone(),
        key: receiver.source.key.clone(),
    };
    let program = Program::new(
        bootstrap_terminal(&receiver.source),
        vec![seed.key.clone()],
        &receiver.binding,
    );
    assert_eq!(program.key.to_bytes(), receiver.key.to_bytes());
    assert_eq!(program.digest(), receiver.source.state.lineage[17]);
    let outer = program.prove(
        bootstrap_terminal(&receiver.source),
        "Receiver-Bootstrap-only",
    );
    receiver.proof = outer.proof;
    receiver.instances = outer.public;
    receiver.opening = outer.opening;
    receiver.vesta = outer.vesta;
    (seed, program, receiver)
}
impl CatalogSeed {
    /// Extend the exact current catalog, then rebuild every signed source under its new key.
    /// Extra keys are provisional until actual source proving reproduces them byte for byte.
    pub fn extend(
        &self,
        program: &Program,
        wallets: &SharedKeyWallets,
        extra_binding: &DescriptorBinding,
        extra: Vec<VerifyingKey<Eq>>,
    ) -> (Program, SharedKeyWallets) {
        assert!(
            !extra.is_empty(),
            "catalog extension must add an actual terminal key"
        );
        assert_eq!(extra_binding, &self.bootstrap.binding);
        assert_eq!(extra_binding, &self.load.binding);
        assert_eq!(wallets.payer.key.to_bytes(), program.key.to_bytes());
        assert_eq!(wallets.receiver.key.to_bytes(), program.key.to_bytes());
        assert_eq!(wallets.receiver.binding, program.binding);
        assert_eq!(wallets.payer.binding, program.binding);
        let mut catalog = program.catalog.clone();
        catalog.extend(extra);
        let next = Program::new(
            bootstrap_terminal(&wallets.receiver.source),
            catalog,
            &program.binding,
        );
        let wallets = rebuild_shared_wallets(&next, &self.bootstrap, &self.load, &self.fixture);
        (next, wallets)
    }
}

/// Build a genuine shared-key pair once and retain the exact source identities for extensions.
pub fn compact_shared_wallet_seed(
    fixture: LoadFixture,
) -> (CatalogSeed, Program, SharedKeyWallets) {
    let (program, bootstrap, load) = compact_load_program(&fixture);
    let wallets = rebuild_shared_wallets(&program, &bootstrap, &load, &fixture);
    (
        CatalogSeed {
            bootstrap,
            load,
            fixture,
        },
        program,
        wallets,
    )
}

fn rebuild_shared_wallets(
    program: &Program,
    initial_bootstrap: &bootstrap_chain::AuthenticatedBootstrap,
    initial_load: &load_chain::AuthenticatedLoad,
    fixture: &LoadFixture,
) -> SharedKeyWallets {
    let payer = rebuild_bootstrap_load(program, initial_bootstrap, initial_load, fixture);
    let receiver =
        rebuild_receiver_bootstrap(program, &initial_bootstrap.binding, &initial_bootstrap.key);
    assert_ne!(
        receiver.source.state.core[5..7],
        payer.source.state.core[5..7]
    );
    assert_eq!(payer.binding, receiver.binding);
    assert_eq!(payer.key.to_bytes(), receiver.key.to_bytes());
    assert_eq!(
        payer.source.state.lineage[17],
        receiver.source.state.lineage[17]
    );
    eprintln!(
        "COMPACT_SHARED_WALLETS payer=Load receiver=Bootstrap distinct_wallets=true immutable_key=true signed_objects_rebuilt=true all_native_proofs=true transport=4800 source_terminals_rebuilt=true extra_terminal_proofs_pending=true full_catalog=false"
    );
    SharedKeyWallets { payer, receiver }
}

fn rebuild_receiver_bootstrap(
    program: &Program,
    expected_binding: &DescriptorBinding,
    expected_key: &VerifyingKey<Eq>,
) -> RootedBootstrapOmega {
    let source = bootstrap_chain::authenticated_bootstrap_with_identity(
        false,
        program.digest(),
        PROFILE,
        Some(2),
        bootstrap_chain::BootstrapIdentity::Receiver,
    );
    assert_eq!(&source.binding, expected_binding);
    assert_eq!(source.key.to_bytes(), expected_key.to_bytes());
    assert_eq!(source.state.lineage[17], program.digest());
    let outer = program.prove(bootstrap_terminal(&source), "Receiver-Bootstrap");
    source
        .pallas
        .decide(
            &PinnedParams::<Ep>::derive(16).unwrap(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    RootedBootstrapOmega {
        source,
        key: program.key.clone(),
        binding: program.binding.clone(),
        proof: outer.proof,
        instances: outer.public,
        opening: outer.opening,
        vesta: outer.vesta,
    }
}

/// Adversarial component only: the real Omega proof still verifies, but its
/// carried Vesta claim is false. Production/full-head decide must reject it.
/// This gives Receive a genuine corrected-claim witness under the identical key.
#[allow(dead_code)] // Used by the corrected-V Receive owner-chain fixture.
pub(crate) fn compact_payer_load_and_receiver_with_bad_vesta(
    fixture: &LoadFixture,
) -> (SharedKeyWallets, iroha_pasta::EqAffine) {
    let (program, wallets) = compact_shared_wallets_and_program(fixture);
    program.with_nondeciding_payer(wallets)
}

impl Program {
    /// Reprove only the payer's outer proof with a deliberately non-deciding Vesta claim.
    ///
    /// This adversarial fixture keeps the exact current catalog and original terminal.
    /// The full outer proof verifies; production full-head decision must reject it.
    pub fn with_nondeciding_payer(
        &self,
        mut wallets: SharedKeyWallets,
    ) -> (SharedKeyWallets, iroha_pasta::EqAffine) {
        assert_eq!(wallets.payer.binding, self.binding);
        assert_eq!(wallets.receiver.binding, self.binding);
        assert_eq!(wallets.payer.key.to_bytes(), self.key.to_bytes());
        assert_eq!(wallets.receiver.key.to_bytes(), self.key.to_bytes());
        assert_eq!(wallets.payer.source.binding, self.source_binding);
        assert_eq!(wallets.receiver.source.binding, self.source_binding);
        let (outer, corrected) = self.prove_nondeciding_vesta(load_terminal(&wallets.payer.source));
        wallets.payer.proof = outer.proof;
        wallets.payer.instances = outer.public;
        wallets.payer.opening = outer.opening;
        wallets.payer.vesta = outer.vesta;
        (wallets, corrected)
    }
}

// Deliberately dishonest PIPA-AS prover, copied in structure from the recursion
// adversarial test. It satisfies the succinct equation but chooses round points
// without the generator witness. No production prover calls this helper.
fn forged_fold<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
) -> iroha_plonk_recursion::FoldWitness<C> {
    use iroha_plonk::{
        pcs::ipa::fold_evaluation,
        transcript::{BasePoseidonHash, Transcript, TranscriptWrite, TranscriptWriter},
    };
    let salt = C::Base::from(123);
    let mut t = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    t.common_base(&salt).unwrap();
    t.common_base(&C::Base::from(u64::try_from(inputs.len()).unwrap()))
        .unwrap();
    for input in inputs {
        t.common_point(input.g()).unwrap();
        t.common_base(&C::Base::from(u64::from(input.source_k())))
            .unwrap();
        for challenge in input.challenges() {
            t.common_scalar(challenge);
        }
    }
    let alpha = t.squeeze_challenge();
    let z = t.squeeze_challenge();
    let zeta = t.squeeze_challenge();
    let mut equation = C::identity();
    let mut evaluation = C::ScalarExt::ZERO;
    for input in inputs.iter().rev() {
        equation = equation * alpha + C::from(*input.g());
        evaluation = evaluation * alpha + fold_evaluation(z, input.challenges());
    }
    equation -= C::from(params.params().g()[0]) * evaluation;
    let mut challenges = [C::ScalarExt::ZERO; iroha_plonk_recursion::K];
    for challenge in &mut challenges {
        let left = C::generator().to_affine();
        let right = (C::generator() * C::ScalarExt::from(2)).to_affine();
        t.write_point(&left).unwrap();
        t.write_point(&right).unwrap();
        *challenge = t.squeeze_challenge();
        equation =
            equation + C::from(left) * challenge.invert().unwrap() + C::from(right) * *challenge;
    }
    t.write_scalar(&C::ScalarExt::ONE);
    equation -= C::from(params.params().u()) * (fold_evaluation(z, &challenges) * zeta);
    t.append_unabsorbed_point(&equation.to_affine()).unwrap();
    iroha_plonk_recursion::FoldWitness::new(salt.to_repr(), &t.finish()).unwrap()
}
fn deciding_correction<C: PastaCurve>(
    params: &PinnedParams<C>,
    original: &AccumulatorT<C>,
) -> C::AffineExt {
    let scalars = iroha_plonk::pcs::ipa::fold_scalars(original.challenges(), C::ScalarExt::ONE);
    let point = iroha_plonk::pcs::ipa::commit::msm_complete::<C>(
        &scalars,
        params.params().g(),
        MemoryBudget::DEFAULT,
    )
    .to_affine();
    assert_ne!(&point, original.g());
    AccumulatorT::new(point, *original.challenges())
        .unwrap()
        .decide(params, MemoryBudget::DEFAULT)
        .unwrap();
    point
}
impl Program {
    fn prove_nondeciding_vesta(&self, source: Terminal<'_>) -> (Outer, iroha_pasta::EqAffine) {
        let vparams = PinnedParams::<Eq>::derive(16).unwrap();
        let frame: [Fp; 69] = source.instances.try_into().unwrap();
        let claims = native::terminal_fold_inputs(&frame, source.opening.clone()).unwrap();
        let fold = forged_fold(&vparams, &claims);
        let vesta =
            iroha_plonk_recursion::verify_fold(&vparams, &claims, &fold, &FoldConfig::default())
                .unwrap();
        assert!(vesta.decide(&vparams, MemoryBudget::DEFAULT).is_err());
        let corrected = deciding_correction(&vparams, &vesta);
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
        let digests = self
            .catalog
            .iter()
            .map(|key| key.kagemusha_digest(source.binding).unwrap())
            .collect();
        let plan = OmegaPlan::new(source.binding.clone(), vparams, digests)
            .and_then(|plan| plan.with_key_catalog(self.catalog.clone()))
            .unwrap();
        let circuit = OmegaCircuit::new(
            plan,
            OmegaWitness {
                key: source.key.clone(),
                instances: source.instances.to_vec(),
                length: source.proof.len().try_into().unwrap(),
                proof: source.proof.to_vec(),
                fold: fold.to_bytes(),
            },
        )
        .unwrap()
        .with_secondary_layout(self.spans, self.schedule.clone());
        let known = synthesize(&circuit, 16, Some(&public)).unwrap();
        assert!(
            iroha_plonk::check::check(
                &known.cs,
                &known.tables,
                iroha_plonk::check::CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        let params = PinnedParams::<Ep>::derive(16).unwrap();
        let key = keygen_pk_v2(&params, &circuit, &key_config()).unwrap();
        assert_eq!(key.binding(), &self.binding);
        assert_eq!(key.vk().to_bytes(), self.key.to_bytes());
        let proof = create_proof_owned_with_claim(
            &params,
            &key,
            Witness::from_circuit(&key, &circuit, &public).unwrap(),
            ProverRandomness::os(),
            ProverConfig::default(),
        )
        .unwrap();
        iroha_plonk::verify_full(
            &params,
            &self.binding,
            &self.key,
            &public,
            &proof.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        assert_eq!(proof.proof.len(), 3712);
        let opening =
            FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap();
        eprintln!(
            "ADVERSARIAL_COMPACT_VESTA genuine_omega_verifies=true carried_vesta_decides=false distinct_same_challenges_correction_decides=true immutable_key=true source_A_unchanged=true full_head_accepted=false"
        );
        (
            Outer {
                proof: proof.proof,
                public,
                opening,
                vesta,
            },
            corrected,
        )
    }
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn compact_distinct_wallets_share_the_exact_predecessor_catalog(fixture: &LoadFixture) {
    let wallets = compact_payer_load_and_receiver(fixture);
    assert_eq!(wallets.payer.binding, wallets.receiver.binding);
    assert_eq!(
        wallets.payer.key.to_bytes(),
        wallets.receiver.key.to_bytes()
    );
    assert_eq!(wallets.payer.proof.len(), 3712);
    assert_eq!(wallets.receiver.proof.len(), 3712);
    assert_ne!(
        wallets.payer.source.state.core[5..7],
        wallets.receiver.source.state.core[5..7]
    );
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn compact_payer_load_retains_the_exact_predecessor_catalog(fixture: &LoadFixture) {
    let payer = compact_payer_load(fixture);
    assert_eq!(payer.proof.len(), 3712);
    assert_eq!(
        payer.source.state.lineage[17],
        payer.key.kagemusha_digest(&payer.binding).unwrap()
    );
}
