//! Sign and strictly qualify a complete generated engineering catalog.
//!
//! No source is substituted and no deployment authority is claimed. The final
//! capability is created only by the production complete-source constructor.

use super::*;
use crate::kagemusha_wallet_artifacts_v1::InstalledVerifierPackV1;
use p256::ecdsa::{Signature, signature::Signer};

#[path = "acquisition_tests.rs"]
mod acquisition_tests;

struct Counted<'a> {
    source: &'a mut dyn OriginalSourceV1,
    reads: usize,
}
impl OriginalSourceV1 for Counted<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.reads += 1;
        self.source.open(digest)
    }
}

struct Withheld<'a> {
    source: &'a mut dyn OriginalSourceV1,
    proving_key: [u8; 32],
}
impl OriginalSourceV1 for Withheld<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        if digest == self.proving_key {
            return Err(Error::Unavailable);
        }
        self.source.open(digest)
    }
}

// This phase needs the actual complete grant. It cannot manufacture one from
// component fixtures or use successful key generation as a qualification verdict.
fn active_imports(
    qualified: &QualifiedWalletSourcesV1,
    originals: &mut Counted<'_>,
    config: ReadConfig,
) -> (usize, usize) {
    let cancellation = iroha_pasta::CancellationToken::new();
    cancellation.cancel();
    let before = originals.reads;
    assert!(
        qualified
            .import_sigma_cancellable(0, originals, config, Some(&cancellation))
            .is_err_and(|error| error.is_cancelled())
    );
    assert_eq!(
        originals.reads, before,
        "cancelled sigma must not open originals"
    );
    let inventory = qualified.inventory();
    let sigma_key = inventory
        .member(inventory.sigma[0])
        .unwrap()
        .proving_key
        .sha256;
    assert!(
        qualified
            .import_sigma(
                0,
                &mut Withheld {
                    source: originals,
                    proving_key: sigma_key
                },
                config
            )
            .is_err_and(|error| error.is_unavailable())
    );
    for selector in 0..inventory.sigma.len() {
        // Every owner is dropped before the next original is read. The first
        // success is also an exact retry after a withheld reinstallable PK.
        drop(
            qualified
                .import_sigma(u8::try_from(selector).unwrap(), originals, config)
                .unwrap(),
        );
    }
    let mut programs = std::collections::BTreeSet::new();
    let mut q_imports = 0;
    for route in compiled_routes() {
        let (_, _, program) = qualified.route(route).unwrap().identity();
        if !programs.insert(program) {
            continue;
        }
        let record = &inventory.operations[usize::try_from(program).unwrap()];
        for (stage, index) in record.q.iter().enumerate() {
            let before = originals.reads;
            assert!(
                qualified
                    .import_q_cancellable(route, stage, originals, config, Some(&cancellation))
                    .is_err_and(|error| error.is_cancelled())
            );
            assert_eq!(
                originals.reads, before,
                "cancelled Q must not open originals"
            );
            if q_imports == 0 {
                let proving_key = inventory.member(*index).unwrap().proving_key.sha256;
                assert!(
                    qualified
                        .import_q(
                            route,
                            stage,
                            &mut Withheld {
                                source: originals,
                                proving_key
                            },
                            config
                        )
                        .is_err_and(|error| error.is_unavailable())
                );
            }
            drop(qualified.import_q(route, stage, originals, config).unwrap());
            q_imports += 1;
        }
    }
    assert_eq!(programs.len(), inventory.operations.len());
    (inventory.sigma.len(), q_imports)
}

fn signature(key: &SigningKey, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: Signature = key.sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}

pub(super) fn accept(
    output: &Path,
    draft: WalletArtifactDraftV1,
    wallet: &mut Originals,
    native: &SumeragiFinalityVerifier,
    config: ReadConfig,
) -> (InstalledVerifierPackV1, QualifiedWalletSourcesV1) {
    // Public deterministic engineering authority only. The production draft owns
    // every generated body and verifies both original signatures in finish().
    let root = SigningKey::from_bytes((&[0x11; 32]).into()).unwrap();
    let artifact = SigningKey::from_bytes((&[0x18; 32]).into()).unwrap();
    let certificate_body = KagemushaWalletSignerCertificateBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: draft.scheme().scheme_id(),
        role: KagemushaWalletSignerRoleV1::Artifact,
        key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            artifact.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        serial: 1,
    };
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        certificate_body,
        draft.scheme(),
        signature(&root, &certificate_body.signing_message()),
    )
    .unwrap();
    let certificate_bytes = certificate.to_canonical_bytes().unwrap();
    let body = draft.manifest_body(&certificate_bytes).unwrap();
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        body,
        &certificate,
        signature(&artifact, &body.signing_message()),
    )
    .unwrap();
    let installation = InstallationV1 {
        scheme_id: draft.scheme().scheme_id(),
        manifest_digest: manifest.manifest_digest(),
    };
    let complete = draft
        .finish(&certificate_bytes, &manifest.to_canonical_bytes().unwrap())
        .unwrap();
    // Retain signed engineering material before acceptance, without upgrading it.
    publish(
        &output.join("engineering-verifier-pack.norito"),
        complete.verifier_pack(),
    )
    .unwrap();
    publish(
        &output.join("engineering-installation.norito"),
        &norito::to_bytes(&(installation.scheme_id, installation.manifest_digest)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        bounded_file(
            &output.join("producer-inventory.norito"),
            CATALOG_MAX_BYTES_V1
        )
        .unwrap(),
        complete.producer_inventory(),
    );
    qualify(
        output,
        complete.verifier_pack(),
        complete.producer_inventory(),
        installation,
        wallet,
        native,
        config,
    )
}

fn qualify(
    output: &Path,
    pack_bytes: &[u8],
    producer: &[u8],
    installation: InstallationV1,
    source: &mut dyn OriginalSourceV1,
    native: &SumeragiFinalityVerifier,
    config: ReadConfig,
) -> (InstalledVerifierPackV1, QualifiedWalletSourcesV1) {
    let inventory: ProducerInventoryV1 = norito::decode_canonical_with_limits(
        producer,
        norito::canonical_decode_limits(producer.len()),
    )
    .unwrap();
    inventory.validate().unwrap();
    assert_eq!(inventory.routes.len(), compiled_routes().len());
    let installed = InstalledVerifierPackV1::load(pack_bytes, installation).unwrap();
    let authenticated = installed.authenticate_producer_inventory(producer).unwrap();
    qualify_authenticated(output, installed, authenticated, source, native, config)
}

fn qualify_authenticated(
    output: &Path,
    installed: InstalledVerifierPackV1,
    authenticated: AuthenticatedProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    native: &SumeragiFinalityVerifier,
    config: ReadConfig,
) -> (InstalledVerifierPackV1, QualifiedWalletSourcesV1) {
    let installation = InstallationV1 {
        scheme_id: installed.verifier().scheme().scheme_id(),
        manifest_digest: installed.verifier().manifest_digest(),
    };
    let mut originals = Counted { source, reads: 0 };
    let qualified = authenticated
        .qualify_wallet(&installed, native, &mut originals, config)
        .unwrap();
    assert_eq!(
        qualified.installation(),
        (installation.scheme_id, installation.manifest_digest)
    );
    assert_eq!(qualified.scope(), fixture_scope());
    assert_eq!(
        qualified.finality().verifier().initial_epoch(),
        native.initial_epoch()
    );
    for route in compiled_routes() {
        qualified.route(route).unwrap();
        qualified.q(route).unwrap();
    }
    let (sigma_imports, q_imports) = active_imports(&qualified, &mut originals, config);
    let acquisition_cases = acquisition_tests::run(&qualified, &mut originals, config);
    let inventory = qualified.inventory();
    publish(
        &output.join("qualified-source-membership.json"),
        &super::transport::qualified_membership(&qualified).unwrap(),
    )
    .unwrap();
    publish(
        &output.join("engineering-source-acceptance.norito"),
        &norito::to_bytes(&(
            b"complete generated engineering source qualification; no deployment authority"
                .to_vec(),
            installation.scheme_id,
            installation.manifest_digest,
            u64::try_from(inventory.routes.len()).unwrap(),
            u64::try_from(originals.reads).unwrap(),
            u64::try_from(sigma_imports).unwrap(),
            u64::try_from(q_imports).unwrap(),
        ))
        .unwrap(),
    )
    .unwrap();
    eprintln!(
        "WALLET_SOURCE_ACCEPTED engineering=true deployment_authority=false complete_routes={} strict_original_reads={} active_sigma_imports={} active_q_imports={} cancelled_import_opens=0 unavailable_retry=true active_seal_acquisition_cases={} scheme={} manifest={} genuine_receipt=false native_wallet_open=false",
        inventory.routes.len(),
        originals.reads,
        sigma_imports,
        q_imports,
        acquisition_cases,
        hex::encode(installation.scheme_id),
        hex::encode(installation.manifest_digest),
    );
    (installed, qualified)
}

#[test]
#[ignore = "strict complete52 engineering acceptance from independently pinned persisted originals; no key regeneration or deployment authority"]
fn qualify_signed_wallet_catalog_from_pinned_originals() {
    let output = PathBuf::from(std::env::var_os("KAGEMUSHA_WALLET_ACCEPTANCE_OUTPUT").unwrap());
    let (_installed, _qualified, _native, _originals) =
        crate::kagemusha_wallet_artifacts_v1::producer_inventory::open_pinned_engineering_wallet_sources(&output);
}

/// Exact owners returned only after genuine pinned engineering source admission.
pub(crate) type EngineeringWalletSources = (
    std::sync::Arc<InstalledVerifierPackV1>,
    std::sync::Arc<QualifiedWalletSourcesV1>,
    SumeragiFinalityVerifier,
    DirectoryOriginalsV1,
);

struct PinnedEngineeringInputs {
    installed: InstalledVerifierPackV1,
    authenticated: AuthenticatedProducerInventoryV1,
    native: SumeragiFinalityVerifier,
    catalog: PathBuf,
    inventory_pin: [u8; 32],
    pack_pin: [u8; 32],
}

// Signed installation and native root admission creates no proving capability.
fn pinned_engineering_inputs(output: &Path) -> PinnedEngineeringInputs {
    let fixture = pinned_genesis_fixture();
    let catalog = PathBuf::from(std::env::var_os("KAGEMUSHA_WALLET_SIGNED_CATALOG").unwrap());
    regular_directory(&catalog).unwrap();
    let producer_pin = pin("KAGEMUSHA_WALLET_CATALOG_PRODUCER_SHA256");
    let source_pin = pin("KAGEMUSHA_WALLET_CATALOG_SOURCE_SHA256");
    let inventory_pin = pin("KAGEMUSHA_WALLET_CATALOG_INVENTORY_SHA256");
    let pack_pin = pin("KAGEMUSHA_WALLET_CATALOG_PACK_SHA256");
    let installation = InstallationV1 {
        scheme_id: pin("KAGEMUSHA_WALLET_SCHEME_ID"),
        manifest_digest: pin("KAGEMUSHA_WALLET_MANIFEST_DIGEST"),
    };
    let pack_bytes = pinned_file(
        &catalog.join("engineering-verifier-pack.norito"),
        CATALOG_MAX_BYTES_V1 + (64 << 10),
        pack_pin,
    )
    .unwrap();
    assert_eq!(
        bounded_file(&catalog.join("binary.sha256"), 32).unwrap(),
        producer_pin
    );
    assert_eq!(
        bounded_file(&catalog.join("source.sha256"), 32).unwrap(),
        source_pin
    );
    let bytes = pinned_file(
        &catalog.join("producer-inventory.norito"),
        CATALOG_MAX_BYTES_V1,
        inventory_pin,
    )
    .unwrap();
    let inventory: ProducerInventoryV1 =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap();
    inventory.validate().unwrap();
    let scope = fixture_scope();
    assert_eq!(
        bounded_file(&catalog.join("source-policy.norito"), 4096).unwrap(),
        norito::to_bytes(&(scope.provider(), scope.root().x, scope.root().y)).unwrap()
    );
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory
        .create(output)
        .expect("fresh acceptance output, original compiler directory remains unchanged");
    publish(
        &output.join("signed-input-pins.norito"),
        &norito::to_bytes(&(
            producer_pin,
            source_pin,
            inventory_pin,
            pack_pin,
            installation.scheme_id,
            installation.manifest_digest,
            BlobV1::of(&fixture).sha256,
        ))
        .unwrap(),
    )
    .unwrap();
    let installed = InstalledVerifierPackV1::load(&pack_bytes, installation).unwrap();
    let authenticated = installed.authenticate_producer_inventory(&bytes).unwrap();
    PinnedEngineeringInputs {
        installed,
        authenticated,
        native: native_finality(&fixture),
        catalog,
        inventory_pin,
        pack_pin,
    }
}

/// Load exact pinned generated originals into fresh sealed custody, then obtain
/// the complete capability through the ordinary production source constructor.
/// This is an engineering fixture: it grants no deployment authority and cannot
/// return a grant from marker files, a subset, or a caller-provided verdict.
pub(crate) fn open_pinned_engineering_wallet_sources(output: &Path) -> EngineeringWalletSources {
    let PinnedEngineeringInputs {
        installed,
        authenticated,
        native,
        catalog,
        inventory_pin,
        pack_pin,
    } = pinned_engineering_inputs(output);
    let mut wallet = Originals {
        root: catalog.join("originals"),
        bytes: 0,
        count: 0,
    };
    regular_directory(&wallet.root).unwrap();
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let private = iroha_fs::PrivateDirectory::open_or_create(output.join("originals")).unwrap();
    let mut sealed =
        DirectoryOriginalsV1::open_existing(private.path(), PROVING_KEY_MAX_BYTES_V1).unwrap();
    let (copied_count, copied_bytes) =
        super::transport::copy(&authenticated, &mut wallet, &mut sealed).unwrap();
    publish(
        &output.join("sealed-transport.norito"),
        &norito::to_bytes(&(
            b"exact signed original transport; no source qualification".to_vec(),
            inventory_pin,
            pack_pin,
            u64::try_from(copied_count).unwrap(),
            copied_bytes,
        ))
        .unwrap(),
    )
    .unwrap();
    let (installed, qualified) = qualify_authenticated(
        output,
        installed,
        authenticated,
        &mut sealed,
        &native,
        config,
    );
    (
        std::sync::Arc::new(installed),
        std::sync::Arc::new(qualified),
        native,
        sealed,
    )
}

/// Native finality owner selected independently of any proving original.
pub(crate) type EngineeringFinalitySources = (
    std::sync::Arc<InstalledVerifierPackV1>,
    QualifiedReceiptSourceV1,
    SumeragiFinalityVerifier,
    DirectoryOriginalsV1,
);

/// Bind a signed engineering wallet installation to authenticated native genesis.
pub(crate) fn open_pinned_engineering_finality_sources(
    output: &Path,
) -> EngineeringFinalitySources {
    let PinnedEngineeringInputs {
        installed,
        authenticated,
        native,
        ..
    } = pinned_engineering_inputs(output);
    let qualified = authenticated.qualify_finality(&installed, &native).unwrap();
    assert_eq!(qualified.verifier().initial_epoch(), native.initial_epoch());
    let private = iroha_fs::PrivateDirectory::open_or_create(output.join("originals")).unwrap();
    let sealed =
        DirectoryOriginalsV1::open_existing(private.path(), PROVING_KEY_MAX_BYTES_V1).unwrap();
    (std::sync::Arc::new(installed), qualified, native, sealed)
}

#[test]
#[ignore = "independently pinned signed catalog and native genesis"]
fn qualify_native_finality_without_proof_artifacts() {
    let output =
        PathBuf::from(std::env::var_os("KAGEMUSHA_NATIVE_FINALITY_ACCEPTANCE_OUTPUT").unwrap());
    let (_, qualified, native, _) = open_pinned_engineering_finality_sources(&output);
    assert_eq!(qualified.verifier().initial_epoch(), native.initial_epoch());
}
