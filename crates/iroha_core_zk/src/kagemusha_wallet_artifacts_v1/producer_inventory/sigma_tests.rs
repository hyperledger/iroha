//! Actual sigma-source imports; Q/A/W/Omega and finality remain unqualified here.

use iroha_kagemusha_proof::admin_sigma::{BootstrapCircuit, native::*};
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::{
    ProvingKey,
    frontend::Circuit,
    keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2, pk::artifact::ReadConfig},
    pcs::ipa::PinnedParams,
};

use super::*;

fn config() -> ReadConfig {
    ReadConfig {
        maximum_bytes: 1 << 28,
        maximum_rows: 1 << 14,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}

#[test]
fn sigma_policy_has_all_exact_selector_recipes_and_bounded_intake() {
    let policy = compiled_sigma_policy().unwrap();
    assert_eq!(&policy[..6], &[1, 0, 16, 0, 0, 0]);
    assert_eq!(policy.len(), 166);
    for (i, ((kind, mask), item)) in SIGMA_CATALOG_V1
        .iter()
        .zip(policy[6..].chunks_exact(10))
        .enumerate()
    {
        assert_eq!(item[0], *kind);
        assert_eq!(&item[1..5], &mask.to_le_bytes());
        let recipe = if (2..=11).contains(&i) {
            let k = if *kind == 3 && mask & 2 != 0 { 14 } else { 12 };
            [1, k, 1, k - 1, 1]
        } else {
            [0, 12, 0, 0, 0]
        };
        assert_eq!(&item[5..], &recipe);
    }
    let selected = AuthenticatedProducerInventoryV1 {
        inventory: structural_inventory(),
        scheme_id: [1; 32],
        manifest_digest: [2; 32],
    };
    let mut source = memory();
    let mut limit = config();
    limit.maximum_bytes = 2;
    assert!(matches!(
        selected.qualify_sigmas(&mut source, limit),
        Err(SigmaQualificationErrorV1::Original(_))
    ));
    assert_eq!(source.opens, 0);
}

fn key(selector: usize, params: &PinnedParams<Eq>) -> ProvingKey<Eq> {
    fn admin<C: Circuit<Fp>>(source: &C, params: &PinnedParams<Eq>) -> ProvingKey<Eq> {
        let mut cfg = KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec());
        cfg.coset_cache = CosetCachePolicy::OnDemand;
        keygen_pk_v2(params, source, &cfg).unwrap()
    }
    match selector {
        0 => admin(&BootstrapProver::source_circuit(), params),
        1 => admin(&LoadProver::source_circuit(), params),
        12 => admin(&ArchiveProver::source_circuit(), params),
        13 => admin(&UnloadProver::source_circuit(), params),
        14 => admin(&RefreshProver::source_circuit(), params),
        15 => admin(&RetiringProver::source_circuit(), params),
        2..=11 => {
            let relation = if selector < 10 {
                iroha_kagemusha_proof::SigmaRelation::send(u32::try_from(selector - 2).unwrap())
            } else {
                iroha_kagemusha_proof::SigmaRelation::receive(u32::try_from(selector - 10).unwrap())
            };
            let shape = iroha_kagemusha_proof::wallet_monetary_shape(relation).unwrap();
            admin(
                &iroha_kagemusha_proof::SigmaCircuit::<Fp>::keygen(shape.params),
                params,
            )
        }
        _ => panic!("undefined test selector"),
    }
}

struct Disk {
    directory: tempfile::TempDir,
    opens: usize,
}
impl Disk {
    fn put(&self, bytes: &[u8]) -> BlobV1 {
        let blob = BlobV1::of(bytes);
        std::fs::write(self.directory.path().join(hex::encode(blob.sha256)), bytes).unwrap();
        blob
    }
}
impl OriginalSourceV1 for Disk {
    fn open(&mut self, hash: [u8; 32]) -> Result<Box<dyn std::io::Read + '_>, Error> {
        self.opens += 1;
        let file = std::fs::File::open(self.directory.path().join(hex::encode(hash)))
            .map_err(|_| Error::Inventory)?;
        Ok(Box::new(file))
    }
}

fn real_sigma_store() -> (Disk, Vec<OriginalV1>, Vec<StepOriginalV1>) {
    let params12 = PinnedParams::derive(12).unwrap();
    let params14 = PinnedParams::derive(14).unwrap();
    let disk = Disk {
        directory: tempfile::tempdir().unwrap(),
        opens: 0,
    };
    let mut originals = Vec::new();
    let mut steps = Vec::new();
    for (selector, (tag, mask)) in SIGMA_CATALOG_V1.into_iter().enumerate() {
        let params = if tag == 3 && mask & 2 != 0 {
            &params14
        } else {
            &params12
        };
        let key = key(selector, params);
        let descriptor = key.binding().encoded().to_vec();
        let verifying_key = key.vk().to_bytes().to_vec();
        let proving_key = key.artifact_bytes_v2().unwrap();
        let reference = OriginalV1 {
            descriptor: disk.put(&descriptor),
            verifying_key: disk.put(&verifying_key),
            proving_key: disk.put(&proving_key),
        };
        steps.push(StepOriginalV1 {
            kind: *KagemushaWalletOperationKindV1::ALL
                .iter()
                .find(|kind| kind.tag() == tag)
                .unwrap(),
            enabled_controls: mask,
            artifact: ArtifactOriginalV1 {
                descriptor: descriptor.clone(),
                verifying_key: verifying_key.clone(),
            },
        });
        drop(key);
        let original = OriginalBytesV1 {
            descriptor,
            verifying_key,
            proving_key,
        };
        let wrong = (selector + 1) % 16;
        assert!(
            sigma::import(wrong, &original, &params12, &params14, config()).is_err(),
            "foreign selector {selector}->{wrong}"
        );
        let mut corrupted = original;
        let last = corrupted.proving_key.len() - 1;
        corrupted.proving_key[last] ^= 1;
        assert!(
            sigma::import(selector, &corrupted, &params12, &params14, config()).is_err(),
            "changed PK {selector}"
        );
        eprintln!(
            "SIGMA_SOURCE_STORED selector={selector} k={} original_bytes={}",
            params.k(),
            reference.proving_key.bytes
        );
        originals.push(reference);
    }
    (disk, originals, steps)
}

#[test]
#[ignore = "actual sixteen-source key generation and strict imports; run optimized explicitly"]
fn signed_sixteen_sigmas_qualify_exact_sources_and_reject_substitutions() {
    let (mut disk, originals, steps) = real_sigma_store();
    let (pack, installation, catalog) =
        engineering_fixture::signed_inventory_with_sources(steps, |pack| {
            let mut inventory = structural_inventory();
            inventory.originals = originals;
            // Explicit framing-only Omega and operation graph, never granted source admission.
            inventory.originals.push(OriginalV1 {
                descriptor: BlobV1::of(&pack.lineage.descriptor),
                verifying_key: BlobV1::of(&pack.lineage.verifying_key),
                proving_key: BlobV1::of(&[1]),
            });
            inventory.sigma = core::array::from_fn(|i| u32::try_from(i).unwrap());
            inventory.omega = 16;
            Some(inventory.to_canonical_bytes().unwrap())
        });
    let installed =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let authenticated = installed
        .authenticate_producer_inventory(&catalog.unwrap())
        .unwrap();
    let qualified = authenticated.qualify_sigmas(&mut disk, config()).unwrap();
    assert_eq!(qualified.installation(), authenticated.installation());
    assert_eq!(disk.opens, 48, "one descriptor/VK/PK read per selector");
    for (selector, step) in pack.steps.iter().enumerate() {
        let key = qualified.key(u8::try_from(selector).unwrap()).unwrap();
        assert_eq!(key.binding().encoded(), step.artifact.descriptor);
        assert_eq!(key.key().to_bytes(), step.artifact.verifying_key);
    }
    assert!(qualified.key(16).is_none());
    // Real source-qualified sigmas cannot upgrade framing-only operations or
    // a foreign native genesis into the complete wallet capability.
    let native = iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture::new_with_explicit_parameters();
    let mut foreign = AuthenticatedProducerInventoryV1 {
        inventory: authenticated.inventory.clone(),
        scheme_id: authenticated.scheme_id,
        manifest_digest: authenticated.manifest_digest,
    };
    foreign.manifest_digest[0] ^= 1;
    assert!(matches!(
        foreign.qualify_wallet(&installed, &native.verifier(), &mut disk, config(),),
        Err(WalletSourcesErrorV1::Original(Error::Authority))
    ));
    assert_eq!(disk.opens, 48, "installation mismatch must precede reads");
    assert!(matches!(
        authenticated.qualify_wallet(&installed, &native.verifier(), &mut disk, config(),),
        Err(WalletSourcesErrorV1::Finality(
            FinalityQualificationErrorV1::AnchorMismatch
        ))
    ));
    assert_eq!(disk.opens, 48, "native genesis mismatch must precede reads");
    eprintln!(
        "SIGMA_SOURCES_QUALIFIED count=16 signed_inventory=true one_active_original=true wallet_grant=false"
    );
}

fn signed_sources(
    steps: Vec<StepOriginalV1>,
    originals: Vec<OriginalV1>,
    program_q: Option<(usize, [OriginalV1; 2])>,
) -> (InstalledVerifierPackV1, AuthenticatedProducerInventoryV1) {
    let (pack, installation, catalog) =
        engineering_fixture::signed_inventory_with_sources(steps, |pack| {
            let mut inventory = structural_inventory();
            inventory.originals = originals;
            inventory.originals.push(OriginalV1 {
                descriptor: BlobV1::of(&pack.lineage.descriptor),
                verifying_key: BlobV1::of(&pack.lineage.verifying_key),
                proving_key: BlobV1::of(&[1]),
            });
            inventory.sigma = core::array::from_fn(|i| u32::try_from(i).unwrap());
            inventory.omega = 16;
            if let Some((program, q)) = program_q {
                inventory.originals.extend(q);
                inventory.operations[program].q = vec![17, 18];
            }
            Some(inventory.to_canonical_bytes().unwrap())
        });
    let installed =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let authenticated = installed
        .authenticate_producer_inventory(&catalog.unwrap())
        .unwrap();
    (installed, authenticated)
}

fn real_q_fixture(
    program: usize,
) -> (
    Disk,
    InstalledVerifierPackV1,
    AuthenticatedProducerInventoryV1,
    QualifiedQProgramV1,
) {
    use iroha_kagemusha_proof::{
        q_sigma::QSigmaPlan,
        q_signature::{QSignaturePlan, SignatureKey, SignatureSlot, native::QSignatureProver},
    };
    use iroha_plonk_gadgets::p256::VerifyMode;
    let program_index = u32::try_from(program).unwrap();
    let (mut disk, originals, steps) = real_sigma_store();
    let (installed, authenticated) = signed_sources(steps.clone(), originals.clone(), None);
    let sigmas = authenticated.qualify_sigmas(&mut disk, config()).unwrap();
    let (source, signatures) = q::source(
        &authenticated.inventory.operations[program],
        installed.verifier().scheme(),
        sigmas.metadata(),
    )
    .unwrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let mut cfg = KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec());
    cfg.coset_cache = CosetCachePolicy::OnDemand;
    let key = keygen_pk_v2(&params, &source.source_circuit().unwrap(), &cfg).unwrap();
    let persist = |key: ProvingKey<Ep>| {
        let metadata = OriginalV1 {
            descriptor: disk.put(key.binding().encoded()),
            verifying_key: disk.put(key.vk().to_bytes()),
            proving_key: disk.put(&key.artifact_bytes_v2().unwrap()),
        };
        drop(key);
        metadata
    };
    let sigma_q = persist(key);
    cfg = KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec());
    cfg.coset_cache = CosetCachePolicy::OnDemand;
    let key = keygen_pk_v2(&params, &signatures[0].source_circuit().unwrap(), &cfg).unwrap();
    let signature_q = persist(key);
    let (installed2, authenticated2) =
        signed_sources(steps, originals, Some((program, [sigma_q, signature_q])));
    let mut read = config();
    read.maximum_rows = 1 << 16;
    let before = disk.opens;
    assert!(
        authenticated2
            .qualify_q_program(&installed2, &sigmas, program_index, &mut disk, read)
            .is_err()
    );
    assert_eq!(disk.opens, before, "old installation rejected before reads");
    let sigmas2 = authenticated2.qualify_sigmas(&mut disk, read).unwrap();
    let before = disk.opens;
    let qualified = authenticated2
        .qualify_q_program(&installed2, &sigmas2, program_index, &mut disk, read)
        .unwrap();
    assert_eq!(
        qualified.identity(),
        (authenticated2.installation(), program_index)
    );
    assert_eq!(qualified.keys().len(), 2);
    assert_eq!(qualified.sigma().slot_count(), 1);
    assert_eq!(qualified.signatures()[0].slots(), signatures[0].slots());
    assert_eq!(disk.opens - before, 6);
    for (metadata, key) in [sigma_q, signature_q].into_iter().zip(qualified.keys()) {
        assert_eq!(metadata.descriptor, BlobV1::of(key.binding().encoded()));
        assert_eq!(metadata.verifying_key, BlobV1::of(key.key().to_bytes()));
    }
    assert!(
        authenticated2
            .qualify_q_program(&installed, &sigmas2, program_index, &mut disk, read)
            .is_err()
    );
    assert!(
        authenticated2
            .qualify_q_program(&installed2, &sigmas2, u32::MAX, &mut disk, read)
            .is_err()
    );
    let bytes = authenticated2
        .read_original(18, &mut disk, read.maximum_bytes)
        .unwrap();
    let mut slots = signatures[0].slots().to_vec();
    let SignatureKey::Fixed(root) = slots[2].key else {
        panic!("fixed original root");
    };
    slots[2].key = SignatureKey::Fixed(root.neg());
    let changed = QSignaturePlan::new(slots).unwrap();
    assert!(
        QSignatureProver::from_original_artifact(
            changed,
            params.clone(),
            &bytes.descriptor,
            &bytes.verifying_key,
            &bytes.proving_key,
            read
        )
        .is_err()
    );
    let changed = QSignaturePlan::new(vec![
        SignatureSlot {
            mode: VerifyMode::Soft,
            key: SignatureKey::Variable
        };
        3
    ])
    .unwrap();
    assert!(
        QSignatureProver::from_original_artifact(
            changed,
            params,
            &bytes.descriptor,
            &bytes.verifying_key,
            &bytes.proving_key,
            read
        )
        .is_err()
    );
    drop(bytes);
    let path = disk
        .directory
        .path()
        .join(hex::encode(sigma_q.proving_key.sha256));
    let mut changed = std::fs::read(&path).unwrap();
    let last = changed.pop().unwrap();
    std::fs::write(&path, &changed).unwrap();
    assert!(
        authenticated2
            .qualify_q_program(&installed2, &sigmas2, program_index, &mut disk, read)
            .is_err()
    );
    changed.push(last);
    std::fs::write(&path, &changed).unwrap();
    eprintln!(
        "QUALIFIED_PROGRAM_Q program={program} count=2 actual16sigma=true serialized2=true fixed_root=true one_active_original=true wallet_grant=false"
    );
    (disk, installed2, authenticated2, qualified)
}

#[test]
#[ignore = "actual sigma and Bootstrap Q original sources; run optimized explicitly"]
fn signed_bootstrap_q_qualifies_originals_and_rejects_foreign_installation_and_root() {
    drop(real_q_fixture(0));
}

#[test]
#[ignore = "actual complete Bootstrap Q/A/W strict originals; run optimized explicitly"]
fn signed_bootstrap_program_qualifies_whole_context_and_all_original_stages() {
    use iroha_kagemusha_proof::{
        a_relation::{native::artifact::KeyArtifact, split::WKey},
        omega::OmegaPlan,
    };
    use iroha_plonk::cs::InstanceType;
    let (mut disk, installed, authenticated, qualified_q) = real_q_fixture(0);
    let plan = bootstrap::plan(
        SourceScopeV1::from_scheme(installed.verifier().scheme()).unwrap(),
        qualified_q.recipe(),
    )
    .unwrap();
    let schema: Vec<_> = plan
        .context()
        .schema()
        .iter()
        .map(PrimeField::to_repr)
        .collect();
    let eq = PinnedParams::<Eq>::derive(16).unwrap();
    let ep = PinnedParams::<Ep>::derive(16).unwrap();
    let mut acfg = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    acfg.compress_selectors = false;
    acfg.coset_cache = CosetCachePolicy::OnDemand;
    let mut wcfg = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    wcfg.coset_cache = CosetCachePolicy::OnDemand;
    fn persist<C: PastaCurve>(disk: &Disk, key: ProvingKey<C>) -> (OriginalV1, KeyArtifact<C>) {
        let reference = OriginalV1 {
            descriptor: disk.put(key.binding().encoded()),
            verifying_key: disk.put(key.vk().to_bytes()),
            proving_key: disk.put(&key.artifact_bytes_v2().unwrap()),
        };
        let metadata = KeyArtifact::new(key.binding().clone(), key.vk().clone()).unwrap();
        drop(key);
        (reference, metadata)
    }
    let (first, first_key) = persist(
        &disk,
        keygen_pk_v2(&eq, &plan.source_circuit(0, None).unwrap(), &acfg).unwrap(),
    );
    let (wrapper, wrapper_key) = persist(
        &disk,
        keygen_pk_v2(
            &ep,
            &plan
                .wrapper_source(0, first_key.binding(), first_key.key())
                .unwrap(),
            &wcfg,
        )
        .unwrap(),
    );
    let previous = WKey::from_artifact(
        plan.context(),
        0,
        wrapper_key.binding().clone(),
        ep,
        wrapper_key.key().clone(),
    )
    .unwrap();
    let (terminal, terminal_key) = persist(
        &disk,
        keygen_pk_v2(&eq, &plan.source_circuit(1, Some(previous)).unwrap(), &acfg).unwrap(),
    );
    let (pack, installation, catalog) =
        engineering_fixture::signed_inventory_with_sources(installed.pack.steps.clone(), |_| {
            let mut inventory = authenticated.inventory.clone();
            assert_eq!(inventory.originals.len(), 19);
            inventory.originals.extend([first, wrapper, terminal]);
            inventory.operations[0].a = vec![19, 21];
            inventory.operations[0].w = vec![20];
            inventory.operations[0].context = schema.clone();
            inventory.terminals = vec![21, 0];
            Some(inventory.to_canonical_bytes().unwrap())
        });
    let installed2 =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let authenticated2 = installed2
        .authenticate_producer_inventory(&catalog.unwrap())
        .unwrap();
    let mut read = config();
    read.maximum_rows = 1 << 16;
    let before = disk.opens;
    assert!(
        authenticated2
            .qualify_bootstrap_program(&installed2, &qualified_q, 0, &mut disk, read)
            .is_err()
    );
    assert_eq!(disk.opens, before);
    let sigmas = authenticated2.qualify_sigmas(&mut disk, read).unwrap();
    let q = authenticated2
        .qualify_q_program(&installed2, &sigmas, 0, &mut disk, read)
        .unwrap();
    let before = disk.opens;
    let qualified = authenticated2
        .qualify_bootstrap_program(&installed2, &q, 0, &mut disk, read)
        .unwrap();
    assert_eq!(qualified.identity(), (authenticated2.installation(), 0));
    assert_eq!(
        disk.opens - before,
        15,
        "six metadata reads plus nine bounded original reads"
    );
    for (role, expected) in [(19, &first_key), (21, &terminal_key)] {
        let original = authenticated2
            .read_original(role, &mut disk, read.maximum_bytes)
            .unwrap();
        let actual = if role == 19 {
            qualified
                .prover()
                .import_first(&original.proving_key, read)
                .unwrap()
        } else {
            qualified
                .prover()
                .import_terminal(&original.proving_key, read)
                .unwrap()
        };
        let view = if role == 19 {
            qualified.prover().bind_first(&actual, None).unwrap()
        } else {
            qualified.prover().bind_terminal(&actual, None).unwrap()
        };
        expected.require_source_bound(&view).unwrap();
    }
    // Acquisition reuses only the exact prior strict-origin seal; every selected
    // original remains mandatory, even though no PK import is repeated here.
    let before = disk.opens;
    assert!(qualified.bind_a(0, 21, None).is_err());
    assert!(qualified.bind_w(0, 19, None).is_err());
    assert_eq!(
        disk.opens, before,
        "member mismatch must precede source I/O"
    );
    let acquire = |disk: &mut Disk, cap: ReadConfig, cancellation| {
        let view = qualified.bind_a(0, 19, cancellation).unwrap();
        wallet::revalidate_stage(&authenticated2, 19, view, disk, cap, cancellation)
    };
    let too_few_rows = ReadConfig {
        maximum_rows: (1 << 16) - 1,
        ..read
    };
    assert!(matches!(
        acquire(&mut disk, too_few_rows, None),
        Err(wallet::WalletSourcesErrorV1::Original(Error::Inventory))
    ));
    assert_eq!(
        disk.opens, before,
        "a tighter current row cap precedes source I/O"
    );
    let zero_bytes = ReadConfig {
        maximum_bytes: 0,
        ..read
    };
    assert!(matches!(
        acquire(&mut disk, zero_bytes, None),
        Err(wallet::WalletSourcesErrorV1::Original(Error::Inventory))
    ));
    assert_eq!(disk.opens, before, "a tighter byte cap precedes source I/O");
    let view = acquire(&mut disk, read, None).unwrap();
    first_key.require_source_bound(&view).unwrap();
    assert_eq!(
        disk.opens - before,
        3,
        "every acquisition streams D, VK and PK"
    );
    let selected = authenticated2.inventory.originals[19];
    for blob in [
        selected.descriptor,
        selected.verifying_key,
        selected.proving_key,
    ] {
        let path = disk.directory.path().join(hex::encode(blob.sha256));
        let saved = path.with_extension("retained");
        std::fs::rename(&path, &saved).unwrap();
        assert!(
            acquire(&mut disk, read, None).is_err(),
            "missing role cannot grant a view"
        );
        std::fs::write(&path, [0u8]).unwrap();
        assert!(
            matches!(
                acquire(&mut disk, read, None),
                Err(wallet::WalletSourcesErrorV1::Original(Error::Inventory))
            ),
            "changed role cannot grant a view"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(saved, path).unwrap();
    }
    let before = disk.opens;
    let token = iroha_pasta::CancellationToken::new();
    token.cancel();
    assert!(qualified.bind_a(0, 19, Some(&token)).is_err());
    let admitted = qualified.bind_a(0, 19, None).unwrap();
    assert!(
        wallet::revalidate_stage(
            &authenticated2,
            19,
            admitted,
            &mut disk,
            too_few_rows,
            Some(&token)
        )
        .unwrap_err()
        .is_cancelled(),
        "cancellation precedes cap rejection and I/O"
    );
    assert_eq!(disk.opens, before);
    let route = authenticated2
        .qualify_operation_route(&installed2, &q, 0, &mut disk, read)
        .unwrap();
    assert_eq!(route.identity(), (authenticated2.installation(), 0, 0));
    assert!(matches!(
        route.owner(),
        QualifiedOperationOwnerV1::Bootstrap(_)
    ));
    assert!(route.candidate_omega().is_none());
    assert_eq!(route.terminal().binding(), terminal_key.binding());
    assert_eq!(
        route.terminal().key().to_bytes(),
        terminal_key.key().to_bytes()
    );
    let before = disk.opens;
    assert!(matches!(
        authenticated2.qualify_omega(&installed2, &[route], &mut disk, read),
        Err(OmegaQualificationErrorV1::Routes)
    ));
    assert_eq!(
        disk.opens, before,
        "one actual route cannot close the entire catalog"
    );
    // Negative private metadata mutation exercises the second source boundary;
    // external callers cannot fabricate an authenticated inventory or Q grant.
    let mut changed = authenticated2;
    let before = disk.opens;
    for index in 0..schema.len() {
        changed.inventory.operations[0].context[index][0] ^= 1;
        assert!(
            changed
                .qualify_bootstrap_program(&installed2, &q, 0, &mut disk, read)
                .is_err(),
            "schema word {index}"
        );
        changed.inventory.operations[0].context[index][0] ^= 1;
    }
    assert_eq!(
        disk.opens, before,
        "whole context checked before any original read"
    );
    let original = changed
        .read_original(19, &mut disk, read.maximum_bytes)
        .unwrap();
    assert!(
        qualified
            .prover()
            .import_terminal(&original.proving_key, read)
            .is_err()
    );
    eprintln!(
        "QUALIFIED_BOOTSTRAP_PROGRAM q=2 a=2 w=1 context_words={} all_originals=true metadata_only=true omega_grant=false",
        schema.len()
    );
}

#[test]
#[ignore = "actual Retiring Q/A/W source originals; run optimized explicitly"]
fn signed_retiring_route_imports_each_stage_and_keeps_candidate_omega_unqualified() {
    use iroha_kagemusha_proof::{
        a_relation::{native::artifact::KeyArtifact, split::WKey},
        omega::OmegaPlan,
    };
    use iroha_plonk::cs::InstanceType;
    let program = Variant::ALL
        .iter()
        .position(|v| *v == Variant::Retiring)
        .unwrap();
    let route_index = compiled_routes()
        .iter()
        .position(|r| r.variant == Variant::Retiring)
        .unwrap();
    let program_index = u32::try_from(program).unwrap();
    let route_index = u32::try_from(route_index).unwrap();
    let (mut disk, installed, authenticated, qualified_q) = real_q_fixture(program);
    // This exact signed engineering Omega is deliberately only a candidate. It
    // exercises non-Bootstrap source intake, not catalog capacity or real funding.
    let omega_original = &installed.pack.lineage;
    disk.put(&omega_original.descriptor);
    disk.put(&omega_original.verifying_key);
    let binding = DescriptorBinding::decode_v2(&omega_original.descriptor).unwrap();
    let key = VerifyingKey::read(&omega_original.verifying_key, &binding).unwrap();
    let omega = KeyArtifact::new(binding, key).unwrap();
    let route = compiled_routes()[usize::try_from(route_index).unwrap()];
    let operation::Plan::Consuming(plan) = operation::plan(
        route,
        SourceScopeV1::from_scheme(installed.verifier().scheme()).unwrap(),
        qualified_q.recipe(),
        &omega,
    )
    .unwrap() else {
        panic!("Retiring uses the shared consuming source");
    };
    let schema: Vec<_> = plan
        .context()
        .schema()
        .iter()
        .map(PrimeField::to_repr)
        .collect();
    let eq = PinnedParams::<Eq>::derive(16).unwrap();
    let ep = PinnedParams::<Ep>::derive(16).unwrap();
    let mut acfg = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    acfg.compress_selectors = false;
    acfg.coset_cache = CosetCachePolicy::OnDemand;
    let mut wcfg = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    wcfg.coset_cache = CosetCachePolicy::OnDemand;
    fn persist<C: PastaCurve>(disk: &Disk, key: ProvingKey<C>) -> (OriginalV1, KeyArtifact<C>) {
        let reference = OriginalV1 {
            descriptor: disk.put(key.binding().encoded()),
            verifying_key: disk.put(key.vk().to_bytes()),
            proving_key: disk.put(&key.artifact_bytes_v2().unwrap()),
        };
        let metadata = KeyArtifact::new(key.binding().clone(), key.vk().clone()).unwrap();
        drop(key);
        (reference, metadata)
    }
    let mut previous = None;
    let mut a = Vec::new();
    let mut w = Vec::new();
    let mut terminal = None;
    for stage in 0..plan.context().stage_count() {
        let circuit = plan.source_circuit(stage, previous.take()).unwrap();
        let (original, key) = persist(&disk, keygen_pk_v2(&eq, &circuit, &acfg).unwrap());
        a.push(original);
        if stage + 1 < plan.context().stage_count() {
            let circuit = plan
                .wrapper_source(stage, key.binding(), key.key())
                .unwrap();
            let (original, wrapper) = persist(&disk, keygen_pk_v2(&ep, &circuit, &wcfg).unwrap());
            w.push(original);
            previous = Some(
                WKey::from_artifact(
                    plan.context(),
                    stage,
                    wrapper.binding().clone(),
                    ep.clone(),
                    wrapper.key().clone(),
                )
                .unwrap(),
            );
        }
        terminal = Some(key);
    }
    let (pack, installation, catalog) =
        engineering_fixture::signed_inventory_with_sources(installed.pack.steps.clone(), |_| {
            let mut inventory = authenticated.inventory.clone();
            let start = inventory.originals.len();
            inventory.originals.extend(a);
            inventory.originals.extend(w);
            inventory.operations[program].a = (start..start + 4)
                .map(|i| u32::try_from(i).unwrap())
                .collect();
            inventory.operations[program].w = (start + 4..start + 7)
                .map(|i| u32::try_from(i).unwrap())
                .collect();
            inventory.operations[program].context = schema.clone();
            inventory.terminals = vec![0, u32::try_from(start + 3).unwrap()];
            Some(inventory.to_canonical_bytes().unwrap())
        });
    let installed2 =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let mut authenticated2 = installed2
        .authenticate_producer_inventory(&catalog.unwrap())
        .unwrap();
    let mut read = config();
    read.maximum_rows = 1 << 16;
    let before = disk.opens;
    assert!(
        authenticated2
            .qualify_operation_route(&installed2, &qualified_q, route_index, &mut disk, read)
            .is_err()
    );
    assert_eq!(disk.opens, before);
    let sigmas = authenticated2.qualify_sigmas(&mut disk, read).unwrap();
    let q = authenticated2
        .qualify_q_program(&installed2, &sigmas, program_index, &mut disk, read)
        .unwrap();
    let before = disk.opens;
    let qualified = authenticated2
        .qualify_operation_route(&installed2, &q, route_index, &mut disk, read)
        .unwrap();
    assert_eq!(
        qualified.identity(),
        (authenticated2.installation(), route_index, program_index)
    );
    assert_eq!(
        disk.opens - before,
        37,
        "2 Omega + 14 A/W metadata + 21 strict original reads"
    );
    assert!(matches!(
        qualified.owner(),
        QualifiedOperationOwnerV1::Consuming(_)
    ));
    let terminal = terminal.unwrap();
    assert_eq!(qualified.terminal().binding(), terminal.binding());
    assert_eq!(
        qualified.terminal().key().to_bytes(),
        terminal.key().to_bytes()
    );
    assert_eq!(
        qualified.candidate_omega().unwrap().key().to_bytes(),
        omega.key().to_bytes()
    );
    for index in 0..schema.len() {
        let before = disk.opens;
        authenticated2.inventory.operations[program].context[index][0] ^= 1;
        assert!(
            authenticated2
                .qualify_operation_route(&installed2, &q, route_index, &mut disk, read)
                .is_err()
        );
        authenticated2.inventory.operations[program].context[index][0] ^= 1;
        assert_eq!(
            disk.opens - before,
            2,
            "only candidate Omega metadata precedes context equality"
        );
    }
    let before = disk.opens;
    assert!(matches!(
        authenticated2.qualify_omega(&installed2, &[qualified], &mut disk, read),
        Err(OmegaQualificationErrorV1::Routes)
    ));
    assert_eq!(disk.opens, before);
    eprintln!(
        "QUALIFIED_RETIRING_ROUTE q=2 a=4 w=3 all_originals=true candidate_omega_unqualified=true complete_catalog=false"
    );
}
