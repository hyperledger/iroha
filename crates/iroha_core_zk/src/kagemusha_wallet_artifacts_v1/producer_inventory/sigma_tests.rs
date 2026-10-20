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
    assert_eq!(&policy[..6], &[1, 0, 11, 0, 0, 0]);
    assert_eq!(policy.len(), 116);
    for (i, ((kind, mask), item)) in SIGMA_CATALOG_V1
        .iter()
        .zip(policy[6..].chunks_exact(10))
        .enumerate()
    {
        assert_eq!(item[0], *kind);
        assert_eq!(&item[1..5], &mask.to_le_bytes());
        let recipe = if (2..=6).contains(&i) {
            let k = if *kind == 3 && mask & 1 != 0 { 14 } else { 12 };
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

#[test]
fn reused_sigma_parameter_domain_is_rejected_before_reading_originals() {
    let selected = AuthenticatedProducerInventoryV1 {
        inventory: structural_inventory(),
        scheme_id: [1; 32],
        manifest_digest: [2; 32],
    };
    let wrong = PinnedParams::<Eq>::derive(6).unwrap();
    let mut source = memory();
    assert!(matches!(
        selected.qualify_sigmas_with_params(&mut source, config(), &wrong, &wrong),
        Err(SigmaQualificationErrorV1::Parameters)
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
        7 => admin(&ArchiveProver::source_circuit(), params),
        8 => admin(&UnloadProver::source_circuit(), params),
        9 => admin(&RefreshProver::source_circuit(), params),
        10 => admin(&RetiringProver::source_circuit(), params),
        2..=6 => {
            let relation = if selector < 6 {
                iroha_kagemusha_proof::SigmaRelation::send(u32::try_from(selector - 2).unwrap())
            } else {
                iroha_kagemusha_proof::SigmaRelation::RECEIVE
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
        let params = if tag == 3 && mask & 1 != 0 {
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
        let wrong = (selector + 1) % 11;
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
#[ignore = "actual eleven-source key generation and strict imports; run optimized explicitly"]
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
            inventory.omega = 11;
            Some(inventory.to_canonical_bytes().unwrap())
        });
    let installed =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let authenticated = installed
        .authenticate_producer_inventory(&catalog.unwrap())
        .unwrap();
    let qualified = authenticated.qualify_sigmas(&mut disk, config()).unwrap();
    assert_eq!(qualified.installation(), authenticated.installation());
    assert_eq!(disk.opens, 33, "one descriptor/VK/PK read per selector");
    for (selector, step) in pack.steps.iter().enumerate() {
        let key = qualified.key(u8::try_from(selector).unwrap()).unwrap();
        assert_eq!(key.binding().encoded(), step.artifact.descriptor);
        assert_eq!(key.key().to_bytes(), step.artifact.verifying_key);
    }
    assert!(qualified.key(11).is_none());
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
    assert_eq!(disk.opens, 33, "installation mismatch must precede reads");
    assert!(matches!(
        authenticated.qualify_wallet(&installed, &native.verifier(), &mut disk, config(),),
        Err(WalletSourcesErrorV1::Finality(
            FinalityQualificationErrorV1::AnchorMismatch
        ))
    ));
    assert_eq!(disk.opens, 33, "native genesis mismatch must precede reads");
    eprintln!(
        "SIGMA_SOURCES_QUALIFIED count=11 signed_inventory=true one_active_original=true wallet_grant=false"
    );
}

fn signed_sources(
    steps: Vec<StepOriginalV1>,
    originals: Vec<OriginalV1>,
    program_q: Option<(usize, Vec<OriginalV1>)>,
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
            inventory.omega = 11;
            if let Some((program, q)) = program_q {
                let start = inventory.originals.len();
                inventory.operations[program].q = (start..start + q.len())
                    .map(|index| u32::try_from(index).unwrap())
                    .collect();
                inventory.originals.extend(q);
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

// D5: every sigma use binds the private seal its qualification minted, revalidates
// the signed originals under current limits and rebuilds from the compiled source of
// that selector, as Q/A/W/Omega do. No strict re-import exists to fall back to.
#[test]
#[ignore = "actual eleven-source sealed sigma rebuilds; run optimized explicitly"]
fn qualified_sigma_seals_rebuild_exact_originals_and_refuse_every_foreign_use() {
    use iroha_kagemusha_proof::SigmaError;
    use iroha_plonk::keys::{RebuildError, SourceBoundViewV2};
    fn rebuild(
        selector: usize,
        view: SourceBoundViewV2<'_, Eq>,
        params: (&PinnedParams<Eq>, &PinnedParams<Eq>),
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ImportedSigmaV1, WalletSourcesErrorV1> {
        Ok(sigma::rebuild_prover(
            selector,
            view,
            params.0,
            params.1,
            CosetCachePolicy::OnDemand,
            cancellation,
        )?)
    }
    let (mut disk, originals, steps) = real_sigma_store();
    let (_installed, authenticated) = signed_sources(steps, originals, None);
    let qualified = authenticated.qualify_sigmas(&mut disk, config()).unwrap();
    let params12 = PinnedParams::<Eq>::derive(12).unwrap();
    let params14 = PinnedParams::<Eq>::derive(14).unwrap();
    let params = (&params12, &params14);
    let member = |selector: usize| authenticated.inventory.sigma[selector];
    let cancelled = iroha_pasta::CancellationToken::new();
    cancelled.cancel();
    let mut stale_sources = 0;
    for selector in 0..11 {
        let selected = u8::try_from(selector).unwrap();
        let foreign = (selector + 1) % 11;
        let expected = qualified.key(selected).unwrap();
        // A seal is authority only for its own signed member; binding precedes I/O.
        let before = disk.opens;
        assert!(matches!(
            qualified.bind(selected, member(foreign), None),
            Err(Error::Inventory)
        ));
        assert!(matches!(
            qualified.bind(selected, member(selector), Some(&cancelled)),
            Err(Error::Cancelled)
        ));
        assert!(matches!(
            qualified.bind(11, member(selector), None),
            Err(Error::Inventory)
        ));
        assert_eq!(disk.opens, before, "seal binding precedes source I/O");
        let view = qualified.bind(selected, member(selector), None).unwrap();
        let view = wallet::revalidate_stage(
            &authenticated,
            member(selector),
            view,
            &mut disk,
            config(),
            None,
        )
        .unwrap();
        assert_eq!(disk.opens - before, 3, "every use streams D, VK and PK");
        assert!(rebuild(selector, view, params, Some(&cancelled)).is_err_and(|e| e.is_cancelled()));
        let rebuilt = rebuild(selector, view, params, None).unwrap();
        let original = authenticated
            .read_original(member(selector), &mut disk, config().maximum_bytes)
            .unwrap();
        assert_eq!(
            rebuilt.proving_key().artifact_bytes_v2().unwrap(),
            original.proving_key,
            "selector {selector} rebuilds exactly its signed original"
        );
        assert_eq!(rebuilt.proving_key().binding(), expected.binding());
        assert_eq!(
            rebuilt.proving_key().vk().to_bytes(),
            expected.key().to_bytes()
        );
        drop(rebuilt);
        // The selector alone chooses the compiled circuit. Another selector's source
        // never rebuilds under this seal, and its failure is never reinstallable.
        let error = rebuild(foreign, view, params, None)
            .err()
            .expect("foreign compiled source");
        assert!(!error.is_cancelled() && !error.is_unavailable());
        // Only an equal-descriptor neighbour reaches the source comparison, and the
        // fixture's selector compression may leave none. The deterministic exact
        // `Source` refusal is the admin seal-rebuild matrix in
        // `iroha_kagemusha_proof/tests/admin_sigma.rs`.
        if qualified
            .key(u8::try_from(foreign).unwrap())
            .unwrap()
            .binding()
            == expected.binding()
        {
            stale_sources += 1;
            assert!(
                matches!(
                    error,
                    WalletSourcesErrorV1::Sigma(
                        SigmaQualificationErrorV1::Monetary(SigmaError::Rebuild(
                            RebuildError::Source
                        )) | SigmaQualificationErrorV1::Administrative(AdminSigmaError::Rebuild(
                            RebuildError::Source
                        ))
                    )
                ),
                "stale compiled source {foreign} under seal {selector}: {error:?}"
            );
        }
    }
    // Current limits apply before any read, and a changed signed original fails
    // custody revalidation before a rebuild. The same seal serves the exact retry.
    let index = member(2);
    let mut rows = config();
    rows.maximum_rows = qualified.key(2).unwrap().binding().n() - 1;
    let before = disk.opens;
    assert!(matches!(
        wallet::revalidate_stage(
            &authenticated,
            index,
            qualified.bind(2, index, None).unwrap(),
            &mut disk,
            rows,
            None,
        ),
        Err(WalletSourcesErrorV1::Original(Error::Inventory))
    ));
    assert_eq!(disk.opens, before, "a tighter row cap precedes source I/O");
    let blob = authenticated.inventory.member(index).unwrap().proving_key;
    let path = disk.directory.path().join(hex::encode(blob.sha256));
    let mut changed = std::fs::read(&path).unwrap();
    changed[0] ^= 1;
    std::fs::write(&path, &changed).unwrap();
    assert!(matches!(
        wallet::revalidate_stage(
            &authenticated,
            index,
            qualified.bind(2, index, None).unwrap(),
            &mut disk,
            config(),
            None,
        ),
        Err(WalletSourcesErrorV1::Original(Error::Inventory))
    ));
    changed[0] ^= 1;
    std::fs::write(&path, &changed).unwrap();
    let view = wallet::revalidate_stage(
        &authenticated,
        index,
        qualified.bind(2, index, None).unwrap(),
        &mut disk,
        config(),
        None,
    )
    .unwrap();
    drop(rebuild(2, view, params, None).unwrap());
    eprintln!(
        "SIGMA_SEALS_REBUILT count=11 exact_originals=true foreign_member=refused foreign_circuit=refused stale_source_pairs={stale_sources} changed_original=refused strict_reimport=false"
    );
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
        &|k| {
            installed
                .verifier()
                .vesta_parameters(k)
                .map(|params| params.as_ref().clone())
                .map_err(QQualificationErrorV1::Original)
        },
    )
    .unwrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let persist = |key: ProvingKey<Ep>| {
        let metadata = OriginalV1 {
            descriptor: disk.put(key.binding().encoded()),
            verifying_key: disk.put(key.vk().to_bytes()),
            proving_key: disk.put(&key.artifact_bytes_v2().unwrap()),
        };
        drop(key);
        metadata
    };
    // A lean route proves its own step inline: its only Q is the signature leaf.
    let sigma_q = source.as_ref().map(|source| {
        let mut cfg = KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec());
        cfg.coset_cache = CosetCachePolicy::OnDemand;
        persist(keygen_pk_v2(&params, &source.source_circuit().unwrap(), &cfg).unwrap())
    });
    let mut cfg = KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec());
    cfg.coset_cache = CosetCachePolicy::OnDemand;
    let key = keygen_pk_v2(&params, &signatures[0].source_circuit().unwrap(), &cfg).unwrap();
    let signature_q = persist(key);
    let originals_q: Vec<_> = sigma_q.into_iter().chain([signature_q]).collect();
    let (installed2, authenticated2) =
        signed_sources(steps, originals, Some((program, originals_q.clone())));
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
    assert_eq!(qualified.keys().len(), originals_q.len());
    assert_eq!(qualified.sigma().is_some(), sigma_q.is_some());
    if let Some(sigma) = qualified.sigma() {
        assert_eq!(sigma.slot_count(), 1);
    }
    assert_eq!(qualified.signatures()[0].slots(), signatures[0].slots());
    assert_eq!(disk.opens - before, 3 * originals_q.len());
    for (metadata, key) in originals_q.iter().zip(qualified.keys()) {
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
    let signature_index = authenticated2.inventory.operations[program]
        .q
        .last()
        .copied()
        .unwrap();
    let bytes = authenticated2
        .read_original(signature_index, &mut disk, read.maximum_bytes)
        .unwrap();
    let slots = signatures[0].slots().to_vec();
    // Only a route that verifies a certificate has a fixed policy root to substitute.
    if let Some(index) = slots
        .iter()
        .position(|slot| matches!(slot.key, SignatureKey::Fixed(_)))
    {
        let mut slots = slots.clone();
        let SignatureKey::Fixed(root) = slots[index].key else {
            panic!("fixed original root");
        };
        slots[index].key = SignatureKey::Fixed(root.neg());
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
    }
    let changed = QSignaturePlan::new(vec![
        SignatureSlot {
            mode: VerifyMode::Soft,
            key: SignatureKey::Variable
        };
        slots.len()
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
        .join(hex::encode(originals_q[0].proving_key.sha256));
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
        "QUALIFIED_PROGRAM_Q program={program} count={} own_sigma={} one_active_original=true wallet_grant=false",
        originals_q.len(),
        sigma_q.is_some()
    );
    (disk, installed2, authenticated2, qualified)
}

#[test]
#[ignore = "actual sigma and Bootstrap Q original sources; run optimized explicitly"]
fn signed_bootstrap_q_qualifies_originals_and_rejects_foreign_installation_and_root() {
    drop(real_q_fixture(0));
}

#[test]
#[ignore = "actual complete Bootstrap Q/A strict originals; run optimized explicitly"]
fn signed_bootstrap_program_qualifies_whole_context_and_its_original_stage() {
    use iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact;
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
    let mut acfg = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    acfg.compress_selectors = false;
    acfg.coset_cache = CosetCachePolicy::OnDemand;
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
    // Lean Bootstrap is one unsplit terminal A: no A1 or W0 original exists.
    let (terminal, terminal_key) = persist(
        &disk,
        keygen_pk_v2(&eq, &plan.source_circuit().unwrap(), &acfg).unwrap(),
    );
    let (pack, installation, catalog) =
        engineering_fixture::signed_inventory_with_sources(installed.pack.steps.clone(), |_| {
            let mut inventory = authenticated.inventory.clone();
            // Eleven sigma originals, the framing Omega and the one signature Q.
            assert_eq!(inventory.originals.len(), 13);
            inventory.originals.push(terminal);
            inventory.operations[0].a = vec![13];
            inventory.operations[0].w = Vec::new();
            inventory.operations[0].context = schema.clone();
            inventory.terminals = vec![13, 0];
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
        5,
        "two metadata reads plus three bounded original reads"
    );
    let original = authenticated2
        .read_original(13, &mut disk, read.maximum_bytes)
        .unwrap();
    let actual = qualified
        .prover()
        .import_terminal(&original.proving_key, read)
        .unwrap();
    let view = qualified.prover().bind_terminal(&actual, None).unwrap();
    terminal_key.require_source_bound(&view).unwrap();
    // Acquisition reuses only the exact prior strict-origin seal; every selected
    // original remains mandatory, even though no PK import is repeated here.
    let before = disk.opens;
    assert!(qualified.bind_a(0, 12, None).is_err());
    assert!(qualified.bind_a(1, 13, None).is_err());
    assert_eq!(
        disk.opens, before,
        "member and stage mismatch must precede source I/O"
    );
    let acquire = |disk: &mut Disk, cap: ReadConfig, cancellation| {
        let view = qualified.bind_a(0, 13, cancellation).unwrap();
        wallet::revalidate_stage(&authenticated2, 13, view, disk, cap, cancellation)
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
    terminal_key.require_source_bound(&view).unwrap();
    assert_eq!(
        disk.opens - before,
        3,
        "every acquisition streams D, VK and PK"
    );
    let selected = authenticated2.inventory.originals[13];
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
    assert!(qualified.bind_a(0, 13, Some(&token)).is_err());
    let admitted = qualified.bind_a(0, 13, None).unwrap();
    assert!(
        wallet::revalidate_stage(
            &authenticated2,
            13,
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
    // A genuine foreign original, the Pallas signature Q, cannot import as the terminal A.
    let original = changed
        .read_original(12, &mut disk, read.maximum_bytes)
        .unwrap();
    assert!(
        qualified
            .prover()
            .import_terminal(&original.proving_key, read)
            .is_err()
    );
    eprintln!(
        "QUALIFIED_BOOTSTRAP_PROGRAM q=1 a=1 w=0 context_words={} all_originals=true metadata_only=true omega_grant=false",
        schema.len()
    );
}

#[test]
#[ignore = "actual Retiring Q/A source originals; run optimized explicitly"]
fn signed_retiring_route_imports_each_stage_and_keeps_candidate_omega_unqualified() {
    use iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact;
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
    let mut acfg = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    acfg.compress_selectors = false;
    acfg.coset_cache = CosetCachePolicy::OnDemand;
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
    // Lean Retiring is one terminal A: no W source follows it.
    let circuit = plan.source_circuit().unwrap();
    let (original, key) = persist(&disk, keygen_pk_v2(&eq, &circuit, &acfg).unwrap());
    let a = vec![original];
    let w: Vec<OriginalV1> = Vec::new();
    let terminal = Some(key);
    let (pack, installation, catalog) =
        engineering_fixture::signed_inventory_with_sources(installed.pack.steps.clone(), |_| {
            let mut inventory = authenticated.inventory.clone();
            let start = inventory.originals.len();
            let (a_count, w_count) = (a.len(), w.len());
            inventory.originals.extend(a);
            inventory.originals.extend(w);
            inventory.operations[program].a = (start..start + a_count)
                .map(|i| u32::try_from(i).unwrap())
                .collect();
            inventory.operations[program].w = (start + a_count..start + a_count + w_count)
                .map(|i| u32::try_from(i).unwrap())
                .collect();
            inventory.operations[program].context = schema.clone();
            inventory.terminals = vec![0, u32::try_from(start + a_count - 1).unwrap()];
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
    // Lean Retiring: one terminal A and no W; it costs 2 metadata and 3 strict original
    // reads.
    let stages = 2 * plan.context().stage_count() - 1;
    assert_eq!(
        disk.opens - before,
        2 + 5 * stages,
        "2 Omega + A/W metadata + strict original reads"
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
        "QUALIFIED_RETIRING_ROUTE q=1 a=1 w=0 all_originals=true candidate_omega_unqualified=true complete_catalog=false"
    );
}
