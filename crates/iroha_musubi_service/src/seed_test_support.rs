//! Canonical seed bundle fixture shared by service and daemon adapter tests.
use crate::MusubiSeedIngressReceiptBindingV1;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    musubi::{
        MusubiAbiBindingV1, MusubiArtifactDescriptorV1, MusubiContentDigestV1,
        MusubiKotodamaEditionV1, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiReleaseIdV1,
        MusubiReleaseMetadataV1, MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1,
    },
    sorafs::pin_registry::{ChunkerProfileHandle, ManifestRootCid},
};
use iroha_data_model::{musubi::MusubiArchiveCommitmentV1, sorafs::capacity::ProviderId};
use iroha_model_base::topology::DataSpaceId;
use norito::codec::Encode as _;
use sorafs_car::CarBuildPlan;
use sorafs_car::{
    CarWriter, FileEntry, compute_chunk_plan_digest_sha3, compute_por_root,
    musubi::{
        MUSUBI_BUNDLE_ARTIFACT_DESCRIPTOR_PATH_V1, MUSUBI_BUNDLE_SEMANTIC_RELEASE_PATH_V1,
        MUSUBI_BUNDLE_VERIFICATION_LOCK_PATH_V1,
    },
};

fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}
fn digest(domain: &[u8], material: &[u8]) -> MusubiContentDigestV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(material.len() as u64).to_be_bytes());
    hasher.update(material);
    MusubiContentDigestV1::new(*hasher.finalize().as_bytes())
}
fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("test signing key")
}
fn path(value: &str) -> Vec<String> {
    value.split('/').map(str::to_owned).collect()
}
#[allow(
    clippy::too_many_lines,
    reason = "one complete canonical Musubi bundle fixture"
)]
/// Build one exact bundle, receipt binding, and canonical CAR for adapter tests.
pub fn fixture() -> (
    MusubiSeedIngressReceiptBindingV1,
    MusubiArchiveCommitmentV1,
    CarBuildPlan,
    Vec<u8>,
) {
    let release = MusubiReleaseIdV1::new(
        MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "seed-stage".parse().expect("package name"),
        ),
        "1.0.0".parse().expect("package version"),
    );
    let lock = MusubiVerificationLockV1 {
        schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
        version: 1,
        root: release.clone(),
        root_dependencies: Vec::new(),
        nodes: Vec::new(),
    };
    let semantic = MusubiSemanticReleaseManifestV1 {
        release,
        edition: MusubiKotodamaEditionV1::V1,
        abi: MusubiAbiBindingV1::new([0x71; 32]).expect("ABI"),
        dependencies: Vec::new(),
        exports: Vec::new(),
        interface_digest: MusubiContentDigestV1::new([0x72; 32]),
        metadata: MusubiReleaseMetadataV1::default(),
        verification_lock_digest: lock.digest(),
    };
    let source_path = "Musubi.toml";
    let source_data = b"[package]\nname='seed-stage'\n".to_vec();
    let mut source_material = Vec::new();
    frame(&mut source_material, b"musubi-source-tree-v1\0");
    source_material.extend_from_slice(&1u32.to_be_bytes());
    frame(&mut source_material, source_path.as_bytes());
    source_material.extend_from_slice(&(source_data.len() as u64).to_be_bytes());
    source_material.extend_from_slice(blake3::hash(&source_data).as_bytes());
    let source_digest = digest(b"musubi-source-tree-v1\0", &source_material);
    let descriptor = MusubiArtifactDescriptorV1::new(
        semantic.semantic_digest(),
        source_digest,
        lock.digest(),
        source_data.len() as u64,
        1,
    )
    .expect("descriptor");
    let semantic_bytes = semantic.encode();
    let descriptor_bytes = descriptor.encode();
    let lock_bytes = lock.encode();
    let mut descriptor_material = Vec::new();
    frame(&mut descriptor_material, b"musubi-artifact-descriptor-v1\0");
    frame(&mut descriptor_material, &descriptor_bytes);
    let descriptor_digest = digest(b"musubi-artifact-descriptor-v1\0", &descriptor_material);
    let mut bundle_material = Vec::new();
    for bytes in [
        b"musubi-bundle-v1\0".as_slice(),
        semantic_bytes.as_slice(),
        descriptor_material.as_slice(),
        source_material.as_slice(),
        lock_bytes.as_slice(),
    ] {
        frame(&mut bundle_material, bytes);
    }
    let bundle_digest = digest(b"musubi-bundle-v1\0", &bundle_material);
    let entries = vec![
        FileEntry {
            path: path(source_path),
            data: source_data,
        },
        FileEntry {
            path: path(MUSUBI_BUNDLE_SEMANTIC_RELEASE_PATH_V1),
            data: semantic_bytes,
        },
        FileEntry {
            path: path(MUSUBI_BUNDLE_ARTIFACT_DESCRIPTOR_PATH_V1),
            data: descriptor_bytes,
        },
        FileEntry {
            path: path(MUSUBI_BUNDLE_VERIFICATION_LOCK_PATH_V1),
            data: lock_bytes,
        },
    ];
    let (plan, payload) = CarBuildPlan::from_files(entries).expect("plan");
    let mut car = Vec::new();
    let stats = CarWriter::new(&plan, &payload)
        .expect("CAR writer")
        .write_to(&mut car)
        .expect("canonical CAR");
    let registered = sorafs_car::chunker_registry::default_descriptor();
    let commitment = MusubiArchiveCommitmentV1 {
        root_cid: ManifestRootCid::try_from(stats.root_cids[0].clone()).expect("canonical root"),
        chunker: ChunkerProfileHandle {
            profile_id: registered.id.0,
            namespace: registered.namespace.to_owned(),
            name: registered.name.to_owned(),
            semver: registered.semver.to_owned(),
            multihash_code: registered.multihash_code,
        },
        chunk_plan_digest: MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(&plan.chunks)),
        por_root: MusubiContentDigestV1::new(compute_por_root(&payload, &plan).expect("PoR")),
        content_length: plan.content_length,
        car_digest: MusubiContentDigestV1::new(*stats.car_archive_digest.as_bytes()),
        car_size: stats.car_size,
        bundle_digest,
        source_tree_digest: source_digest,
        descriptor_digest,
        file_count: 1,
        chunk_count: u32::try_from(plan.chunks.len()).expect("fixture chunk count fits u32"),
    };
    let publisher = AccountId::new(key(0x31).public_key().clone());
    let broker = AccountId::new(key(0x32).public_key().clone());
    let binding = MusubiSeedIngressReceiptBindingV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new([0x15; 32]),
        )),
        publisher,
        ingress_broker: broker,
        seed_provider: ProviderId::new([0x33; 32]),
        semantic_release_manifest_digest: semantic.semantic_digest(),
        archive_id: commitment.archive_id(),
        car_body_digest: commitment.car_digest,
        car_body_length: commitment.car_size,
        nonce: [0x34; 32],
    };
    (binding, commitment, plan, car)
}
