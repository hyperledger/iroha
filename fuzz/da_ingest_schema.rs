#![no_main]
use arbitrary::Arbitrary;
use flate2::{
    Compression as FlateCompression,
    write::{DeflateEncoder, GzEncoder},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{NetworkId, account::AccountId, block::BlockHeader, da::prelude::*};
use iroha_model_base::topology::LaneId;
use libfuzzer_sys::fuzz_target;
use norito::{decode_from_bytes, to_bytes};
use std::io::Write;
use zstd::stream::encode_all as zstd_encode_all;
#[derive(Debug, Arbitrary)]
struct MetadataSeed {
    key: String,
    #[arbitrary(with = limit_vec_64)]
    value: Vec<u8>,
    visibility: u8,
}
#[derive(Debug, Arbitrary)]
struct FuzzCase {
    lane: u32,
    epoch: u64,
    sequence: u64,
    blob_class: u8,
    #[arbitrary(with = limit_string_32)]
    codec: String,
    #[arbitrary(with = limit_vec_2048)]
    payload: Vec<u8>,
    #[arbitrary(with = limit_metadata)]
    metadata: Vec<MetadataSeed>,
    include_manifest: bool,
    compression: u8,
}
fn limit_vec_64(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=64_usize)?;
    let mut bytes = vec![0u8; len];
    u.fill_buffer(&mut bytes)?;
    Ok(bytes)
}
fn limit_vec_2048(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=2_048_usize)?;
    let mut bytes = vec![0u8; len];
    u.fill_buffer(&mut bytes)?;
    Ok(bytes)
}
fn limit_string_32(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=32_usize)?;
    let mut buf = vec![0u8; len];
    u.fill_buffer(&mut buf)?;
    let filtered = buf
        .into_iter()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => b,
            _ => b'a' + (b % 26),
        })
        .collect::<Vec<_>>();
    Ok(String::from_utf8_lossy(&filtered).into_owned())
}
fn limit_metadata(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<MetadataSeed>> {
    let mut items = Vec::new();
    let count = u.int_in_range(0..=8_usize)?;
    for _ in 0..count {
        items.push(MetadataSeed::arbitrary(u)?);
    }
    Ok(items)
}
#[derive(Debug)]
struct ConstructedCase {
    request: DaIngestRequest,
    manifest: Option<DaManifestV1>,
}
fn build_case(seed: FuzzCase) -> ConstructedCase {
    let payload = if seed.payload.is_empty() {
        vec![0u8; 1]
    } else {
        seed.payload
    };
    let compression = match seed.compression % 4 {
        0 => Compression::Identity,
        1 => Compression::Gzip,
        2 => Compression::Deflate,
        _ => Compression::Zstd,
    };
    let encoded_payload = match compression {
        Compression::Identity => payload.clone(),
        Compression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), FlateCompression::default());
            encoder
                .write_all(&payload)
                .expect("writing gzip payload into memory must succeed");
            encoder
                .finish()
                .expect("finishing gzip payload into memory must succeed")
        }
        Compression::Deflate => {
            let mut encoder = DeflateEncoder::new(Vec::new(), FlateCompression::default());
            encoder
                .write_all(&payload)
                .expect("writing deflate payload into memory must succeed");
            encoder
                .finish()
                .expect("finishing deflate payload into memory must succeed")
        }
        Compression::Zstd => zstd_encode_all(payload.as_slice(), 0)
            .expect("encoding zstd payload in memory must succeed"),
    };
    let client_blob_id = BlobDigest::new(iroha_crypto::blake3_256(&payload));
    let blob_class = match seed.blob_class % 4 {
        0 => BlobClass::TaikaiSegment,
        1 => BlobClass::NexusLaneSidecar,
        2 => BlobClass::GovernanceArtifact,
        _ => BlobClass::Custom((seed.blob_class / 4) as u16),
    };
    let metadata_items = seed
        .metadata
        .into_iter()
        .enumerate()
        .map(|(idx, item)| {
            let key = if item.key.is_empty() {
                format!("meta-{idx}")
            } else {
                item.key
            };
            let visibility = match item.visibility % 2 {
                0 => MetadataVisibility::Public,
                _ => MetadataVisibility::GovernanceOnly,
            };
            MetadataEntry {
                key,
                value: item.value,
                visibility,
                encryption: MetadataEncryption::None,
            }
        })
        .collect::<Vec<_>>();
    let extra_metadata = ExtraMetadata {
        items: metadata_items,
    };
    let codec = if seed.codec.is_empty() {
        BlobCodec::new("octet-stream")
    } else {
        BlobCodec::new(seed.codec)
    };
    let erasure_profile = ErasureProfile::default();
    let retention_policy = RetentionPolicy::default();
    let chunk_size = 1 << 10;
    let total_size = payload.len() as u64;
    let keypair = KeyPair::try_from_seed(vec![0x5A; 32], Algorithm::Ed25519)
        .expect("fixed fuzz signing seed must derive an Ed25519 key");
    let mut manifest = None;
    let manifest_bytes = if seed.include_manifest {
        let blob_hash = BlobDigest::new(iroha_crypto::blake3_256(&payload));
        let chunk_commitments = Vec::<ChunkCommitment>::new();
        let da_manifest = DaManifestV1 {
            version: DaManifestV1::VERSION,
            client_blob_id,
            lane_id: LaneId::new(seed.lane),
            epoch: seed.epoch,
            blob_class,
            codec: codec.clone(),
            blob_hash,
            chunk_root: client_blob_id,
            storage_ticket: StorageTicketId::new([0xAB; 32]),
            total_size,
            chunk_size,
            total_stripes: 0,
            shards_per_stripe: 0,
            erasure_profile,
            retention_policy: retention_policy.clone(),
            rent_quote: DaRentQuote::default(),
            chunks: chunk_commitments,
            ipa_commitment: BlobDigest::default(),
            metadata: extra_metadata.clone(),
            issued_at_unix: seed.sequence,
        };
        manifest = Some(da_manifest.clone());
        to_bytes(&da_manifest).ok()
    } else {
        None
    };
    let request = DaIngestRequestIntentV1 {
        network_id: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0xA5; 32]),
        )),
        owner: AccountId::new(keypair.public_key().clone()),
        client_blob_id,
        lane_id: LaneId::new(seed.lane),
        epoch: seed.epoch,
        sequence: seed.sequence,
        blob_class,
        codec,
        erasure_profile,
        retention_policy,
        chunk_size,
        total_size,
        payload_hash: BlobDigest::new(iroha_crypto::blake3_256(&payload)),
        compression,
        norito_manifest: manifest_bytes,
        payload: encoded_payload,
        metadata: extra_metadata,
    }
    .try_sign(&keypair)
    .expect("fixed Ed25519 key must sign the fuzz request");
    ConstructedCase { request, manifest }
}
fuzz_target!(|seed: FuzzCase| {
    let constructed = build_case(seed);
    let request_bytes =
        to_bytes(&constructed.request).expect("DA ingest request should Norito-encode");
    let decoded_request: DaIngestRequest =
        decode_from_bytes(&request_bytes).expect("encoded request should decode");
    assert_eq!(constructed.request, decoded_request);
    if let Some(manifest) = constructed.manifest {
        let manifest_bytes = to_bytes(&manifest).expect("DA manifest should Norito-encode cleanly");
        let decoded_manifest: DaManifestV1 =
            decode_from_bytes(&manifest_bytes).expect("encoded manifest should decode");
        assert_eq!(manifest, decoded_manifest);
    }
});
