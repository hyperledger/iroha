//! Round-trip tests for DA ingest/manifest Norito types.
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PublicKey, Signature};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    da::prelude::*,
    sorafs::pin_registry::{ManifestDigest, StorageClass},
};
use iroha_model_base::topology::LaneId;
use norito::{
    DeserializePayload,
    codec::{DecodeAll as _, Encode as _},
    from_bytes,
};
use std::{convert::TryFrom, str::FromStr};
fn sample_digest(seed: u8) -> BlobDigest {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let offset = u8::try_from(idx).expect("digest index fits in u8");
        *byte = seed.wrapping_add(offset);
    }
    BlobDigest::new(bytes)
}
fn sample_signature(seed: u8) -> Signature {
    let mut payload = [0u8; 64];
    for (idx, byte) in payload.iter_mut().enumerate() {
        let offset = u8::try_from(idx).expect("signature index fits in u8");
        *byte = seed.wrapping_add(offset);
    }
    Signature::try_from_bytes(&payload).expect("DA ingest fixture signature must pass admission")
}
fn sample_public_key() -> PublicKey {
    PublicKey::from_str("ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03")
        .expect("ed25519 test key")
}
fn sample_ticket(seed: u8) -> StorageTicketId {
    let digest = sample_digest(seed);
    StorageTicketId::new(*digest.as_bytes())
}
fn sample_network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([seed; 32]),
    ))
}
fn sample_pdp_commitment_bytes() -> Vec<u8> {
    (0..96)
        .map(|idx| {
            let offset = u8::try_from(idx).expect("commitment index fits in u8");
            0xA0u8.wrapping_add(offset)
        })
        .collect()
}
fn sample_ingest_request() -> DaIngestRequest {
    DaIngestRequest {
        network_id: sample_network_id(0xA5),
        owner: AccountId::new(sample_public_key()),
        client_blob_id: sample_digest(0x11),
        lane_id: LaneId::new(2),
        epoch: 42,
        sequence: 7,
        blob_class: BlobClass::TaikaiSegment,
        codec: BlobCodec::new("cmaf"),
        erasure_profile: ErasureProfile {
            data_shards: 8,
            parity_shards: 4,
            row_parity_stripes: 2,
            chunk_alignment: 12,
            fec_scheme: FecScheme::Rs12_10,
        },
        retention_policy: RetentionPolicy {
            hot_retention_secs: 86_400,
            cold_retention_secs: 30 * 86_400,
            required_replicas: 4,
            storage_class: StorageClass::Hot,
            governance_tag: GovernanceTag::new("da.test"),
        },
        chunk_size: 1 << 20,
        total_size: 5_242_880,
        payload_hash: sample_digest(0x12),
        compression: Compression::Identity,
        norito_manifest: Some(vec![0xAA, 0xBB, 0xCC]),
        payload: b"hello data availability".to_vec(),
        metadata: ExtraMetadata {
            items: vec![
                MetadataEntry::new(
                    "content_type",
                    b"video/mp4".to_vec(),
                    MetadataVisibility::Public,
                ),
                MetadataEntry::new(
                    "operator_notes",
                    b"ingest-test".to_vec(),
                    MetadataVisibility::GovernanceOnly,
                ),
            ],
        },
        signatures: vec![DaIngestSignatureV1 {
            signer: sample_public_key(),
            signature: sample_signature(0x42),
        }],
        pin_scope_signatures: Vec::new(),
    }
}

#[test]
fn pin_scope_witnesses_roundtrip_without_changing_primary_digest() {
    let mut request = sample_ingest_request();
    let primary_digest = request.signing_digest();
    let scope = DaPinScopeV1::new(
        &request.authorization(),
        sample_ticket(0x41),
        ManifestDigest::new(*sample_digest(0x42).as_bytes()),
        Some("roundtrip.example".to_owned()),
    );
    let key_pair = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
        .expect("valid deterministic scope witness key");
    request
        .try_add_pin_scope_signature(&scope, &key_pair)
        .expect("add pin-scope witness");
    assert_eq!(request.signing_digest(), primary_digest);
    assert!(
        request
            .pin_scope_authorization(scope)
            .has_valid_canonical_signatures()
    );

    let bytes = norito::to_bytes(&request).expect("encode request with pin-scope witness");
    let decoded: DaIngestRequest =
        norito::decode_from_bytes(&bytes).expect("decode request with pin-scope witness");
    assert_eq!(decoded, request);
}
fn sample_ingest_receipt() -> DaIngestReceipt {
    DaIngestReceipt {
        client_blob_id: sample_digest(0x51),
        lane_id: LaneId::new(3),
        epoch: 1024,
        blob_hash: sample_digest(0x52),
        chunk_root: sample_digest(0x53),
        manifest_hash: sample_digest(0x54),
        storage_ticket: sample_ticket(0x55),
        pdp_commitment: Some(sample_pdp_commitment_bytes()),
        stripe_layout: DaStripeLayout {
            total_stripes: 4,
            shards_per_stripe: 12,
            row_parity_stripes: 1,
        },
        queued_at_unix: 1_707_100_000,
        rent_quote: DaRentQuote::default(),
        operator_signature: sample_signature(0x99),
    }
}
#[derive(Clone, Copy)]
enum JsonPath<'a> {
    Key(&'a str),
    Index(usize),
}
fn insert_unknown_at_path(value: &mut norito::json::Value, path: &[JsonPath<'_>]) {
    let mut cursor = value;
    for component in path {
        cursor = match *component {
            JsonPath::Key(key) => cursor
                .as_object_mut()
                .unwrap_or_else(|| panic!("expected JSON object before key `{key}`"))
                .get_mut(key)
                .unwrap_or_else(|| panic!("missing JSON key `{key}`")),
            JsonPath::Index(index) => cursor
                .as_array_mut()
                .unwrap_or_else(|| panic!("expected JSON array before index {index}"))
                .get_mut(index)
                .unwrap_or_else(|| panic!("missing JSON index {index}")),
        };
    }
    cursor
        .as_object_mut()
        .expect("unknown-field target must be a JSON object")
        .insert(
            "pre_release_extension".to_owned(),
            norito::json::Value::Bool(true),
        );
}
#[test]
fn da_ingest_request_norito_roundtrip() {
    let request = sample_ingest_request();
    let buf = norito::to_bytes(&request).expect("serialize ingest request");
    let archived = from_bytes::<DaIngestRequest>(&buf).expect("decode request");
    let decoded = DaIngestRequest::deserialize(archived);
    assert_eq!(decoded, request);
}
#[test]
fn da_ingest_signature_binds_complete_request_intent() {
    let key_pair = KeyPair::try_from_seed(vec![0x19; 32], Algorithm::Ed25519)
        .expect("derive deterministic DA submitter");
    let owner = AccountId::new(key_pair.public_key().clone());
    let payload = b"hello data availability".to_vec();
    let intent = DaIngestRequestIntentV1 {
        network_id: sample_network_id(0xA5),
        owner,
        client_blob_id: sample_digest(0x11),
        lane_id: LaneId::new(2),
        epoch: 42,
        sequence: 7,
        blob_class: BlobClass::TaikaiSegment,
        codec: BlobCodec::new("cmaf"),
        erasure_profile: ErasureProfile {
            data_shards: 8,
            parity_shards: 4,
            row_parity_stripes: 2,
            chunk_alignment: 12,
            fec_scheme: FecScheme::Rs12_10,
        },
        retention_policy: RetentionPolicy {
            hot_retention_secs: 86_400,
            cold_retention_secs: 30 * 86_400,
            required_replicas: 4,
            storage_class: StorageClass::Hot,
            governance_tag: GovernanceTag::new("da.test"),
        },
        chunk_size: 1 << 20,
        total_size: 23,
        payload_hash: BlobDigest::from_hash(blake3::hash(&payload)),
        compression: Compression::Identity,
        norito_manifest: Some(vec![0xAA, 0xBB, 0xCC]),
        payload,
        metadata: ExtraMetadata {
            items: vec![MetadataEntry::new(
                "content_type",
                b"video/mp4".to_vec(),
                MetadataVisibility::Public,
            )],
        },
    };
    let expected_digest = intent.signing_digest();
    assert_eq!(
        hex::encode_upper(expected_digest),
        "B97871DB051776138277C9000393FDC259910663A8C751D37BD054A0DA369DDA",
        "DA intent digest is a cross-SDK protocol vector"
    );
    let request = intent
        .try_sign(&key_pair)
        .expect("sign complete DA request intent");
    assert_eq!(request.signing_digest(), expected_digest);
    request
        .verify_signatures()
        .expect("unchanged request must verify");
    let mut changed_profile = request.clone();
    changed_profile.erasure_profile.parity_shards += 1;
    assert!(changed_profile.verify_signatures().is_err());
    let mut changed_lane = request.clone();
    changed_lane.lane_id = LaneId::new(3);
    assert!(changed_lane.verify_signatures().is_err());
    let mut replayed_under_new_nonce = request.clone();
    replayed_under_new_nonce.sequence += 1;
    assert!(
        replayed_under_new_nonce.verify_signatures().is_err(),
        "one signed DA authorization cannot be replayed under another sequence"
    );
    let mut changed_network = request.clone();
    changed_network.network_id = sample_network_id(0xB6);
    assert!(changed_network.verify_signatures().is_err());
    let mut changed_payload = request.clone();
    changed_payload.payload[0] ^= 0xFF;
    assert!(changed_payload.verify_signatures().is_err());
    let mut changed_payload_charge = request.clone();
    changed_payload_charge.total_size += 1;
    assert!(changed_payload_charge.verify_signatures().is_err());
    let mut changed_metadata = request.clone();
    changed_metadata.metadata.items.push(MetadataEntry::new(
        "tampered",
        b"yes".to_vec(),
        MetadataVisibility::Public,
    ));
    assert!(changed_metadata.verify_signatures().is_err());
    let other = KeyPair::try_from_seed(vec![0x20; 32], Algorithm::Ed25519)
        .expect("derive alternate DA submitter");
    let mut changed_signer = request;
    changed_signer.signatures[0].signer = other.public_key().clone();
    assert!(changed_signer.verify_signatures().is_err());
}
fn sample_manifest() -> DaManifestV1 {
    DaManifestV1 {
        version: DaManifestV1::VERSION,
        client_blob_id: sample_digest(0x21),
        lane_id: LaneId::new(7),
        epoch: 777,
        blob_class: BlobClass::GovernanceArtifact,
        codec: BlobCodec::new("norito-batch"),
        blob_hash: sample_digest(0x22),
        chunk_root: sample_digest(0x23),
        storage_ticket: sample_ticket(0x24),
        total_size: 9_437_184,
        chunk_size: 512 * 1024,
        total_stripes: 6,
        shards_per_stripe: 16,
        erasure_profile: ErasureProfile {
            data_shards: 10,
            parity_shards: 6,
            row_parity_stripes: 2,
            chunk_alignment: 10,
            fec_scheme: FecScheme::Rs18_14,
        },
        retention_policy: RetentionPolicy {
            hot_retention_secs: 48 * 3_600,
            cold_retention_secs: 120 * 86_400,
            required_replicas: 5,
            storage_class: StorageClass::Warm,
            governance_tag: GovernanceTag::new("da.governance"),
        },
        rent_quote: DaRentQuote::default(),
        chunks: vec![
            ChunkCommitment::new_with_role(
                0,
                0,
                512 * 1024,
                sample_digest(0x30),
                ChunkRole::Data,
                0,
            ),
            ChunkCommitment::new_with_role(
                1,
                512 * 1024,
                512 * 1024,
                sample_digest(0x31),
                ChunkRole::LocalParity,
                0,
            ),
            ChunkCommitment::new_with_role(
                10,
                10 * 512 * 1024,
                512 * 1024,
                sample_digest(0x32),
                ChunkRole::StripeParity,
                4,
            ),
        ],
        ipa_commitment: sample_digest(0x33),
        metadata: ExtraMetadata {
            items: vec![
                MetadataEntry::new(
                    "category",
                    b"governance".to_vec(),
                    MetadataVisibility::Public,
                ),
                MetadataEntry::with_encryption(
                    "review-note",
                    b"sealed".to_vec(),
                    MetadataVisibility::GovernanceOnly,
                    MetadataEncryption::chacha20poly1305_with_label(None::<String>),
                ),
            ],
        },
        issued_at_unix: 1_707_000_000,
    }
}
#[test]
fn da_manifest_roundtrip() {
    let manifest = sample_manifest();
    let buf = norito::to_bytes(&manifest).expect("serialize manifest");
    let archived = from_bytes::<DaManifestV1>(&buf).expect("decode manifest");
    let decoded = DaManifestV1::deserialize(archived);
    assert_eq!(decoded, manifest);
}
#[test]
fn da_manifest_json_roundtrip_is_exact() {
    let mut manifest = sample_manifest();
    manifest.erasure_profile.row_parity_stripes = 0;
    manifest.ipa_commitment = BlobDigest::default();
    let value = norito::json::to_value(&manifest).expect("serialize current manifest");
    let object = value.as_object().expect("manifest JSON object");
    for field in [
        "total_stripes",
        "shards_per_stripe",
        "rent_quote",
        "ipa_commitment",
    ] {
        assert!(object.contains_key(field), "manifest must emit {field}");
    }
    assert!(
        object
            .get("erasure_profile")
            .and_then(norito::json::Value::as_object)
            .and_then(|profile| profile.get("row_parity_stripes"))
            .is_some_and(|value| value.as_u64() == Some(0)),
        "zero row parity must be explicit"
    );
    assert!(
        object
            .get("metadata")
            .and_then(norito::json::Value::as_object)
            .and_then(|metadata| metadata.get("items"))
            .and_then(norito::json::Value::as_array)
            .and_then(|items| items.get(1))
            .and_then(norito::json::Value::as_object)
            .and_then(|entry| entry.get("encryption"))
            .and_then(norito::json::Value::as_object)
            .and_then(|encryption| encryption.get("params"))
            .and_then(norito::json::Value::as_object)
            .and_then(|params| params.get("key_label"))
            .is_some_and(norito::json::Value::is_null),
        "an absent metadata key label must be an explicit null"
    );
    assert_eq!(
        norito::json::from_value::<DaManifestV1>(value).expect("decode current manifest JSON"),
        manifest
    );
}
#[test]
fn da_manifest_json_rejects_missing_current_fields() {
    let manifest = sample_manifest();
    for field in [
        "total_stripes",
        "shards_per_stripe",
        "rent_quote",
        "ipa_commitment",
    ] {
        let mut value = norito::json::to_value(&manifest).expect("serialize manifest");
        value
            .as_object_mut()
            .expect("manifest JSON object")
            .remove(field)
            .unwrap_or_else(|| panic!("fixture must contain {field}"));
        assert!(
            norito::json::from_value::<DaManifestV1>(value).is_err(),
            "V1 must reject a manifest missing {field}"
        );
    }

    let mut missing_row_parity =
        norito::json::to_value(&manifest).expect("serialize manifest for nested omission");
    missing_row_parity
        .as_object_mut()
        .and_then(|object| object.get_mut("erasure_profile"))
        .and_then(norito::json::Value::as_object_mut)
        .expect("erasure profile JSON object")
        .remove("row_parity_stripes")
        .expect("current profile contains row parity");
    assert!(
        norito::json::from_value::<DaManifestV1>(missing_row_parity).is_err(),
        "V1 must reject a manifest with the pre-release erasure profile"
    );

    let mut missing_encryption =
        norito::json::to_value(&manifest).expect("serialize manifest for metadata omission");
    missing_encryption
        .as_object_mut()
        .and_then(|object| object.get_mut("metadata"))
        .and_then(norito::json::Value::as_object_mut)
        .and_then(|metadata| metadata.get_mut("items"))
        .and_then(norito::json::Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(norito::json::Value::as_object_mut)
        .expect("metadata entry JSON object")
        .remove("encryption")
        .expect("current metadata entry contains encryption");
    assert!(
        norito::json::from_value::<DaManifestV1>(missing_encryption).is_err(),
        "V1 must reject a pre-release metadata entry without encryption"
    );

    let mut missing_key_label =
        norito::json::to_value(&manifest).expect("serialize manifest for envelope omission");
    missing_key_label
        .as_object_mut()
        .and_then(|object| object.get_mut("metadata"))
        .and_then(norito::json::Value::as_object_mut)
        .and_then(|metadata| metadata.get_mut("items"))
        .and_then(norito::json::Value::as_array_mut)
        .and_then(|items| items.get_mut(1))
        .and_then(norito::json::Value::as_object_mut)
        .and_then(|entry| entry.get_mut("encryption"))
        .and_then(norito::json::Value::as_object_mut)
        .and_then(|encryption| encryption.get_mut("params"))
        .and_then(norito::json::Value::as_object_mut)
        .expect("metadata cipher envelope JSON object")
        .remove("key_label")
        .expect("current envelope contains key label");
    assert!(
        norito::json::from_value::<DaManifestV1>(missing_key_label).is_err(),
        "V1 must reject a cipher envelope without its nullable key-label slot"
    );
}
#[test]
fn da_manifest_json_rejects_unknown_fields_at_manifest_owned_boundaries() {
    let manifest = sample_manifest();
    let cases = vec![
        ("manifest", vec![]),
        ("blob class", vec![JsonPath::Key("blob_class")]),
        ("erasure profile", vec![JsonPath::Key("erasure_profile")]),
        (
            "FEC scheme",
            vec![
                JsonPath::Key("erasure_profile"),
                JsonPath::Key("fec_scheme"),
            ],
        ),
        ("retention policy", vec![JsonPath::Key("retention_policy")]),
        ("rent quote", vec![JsonPath::Key("rent_quote")]),
        (
            "chunk commitment",
            vec![JsonPath::Key("chunks"), JsonPath::Index(0)],
        ),
        (
            "chunk role",
            vec![
                JsonPath::Key("chunks"),
                JsonPath::Index(0),
                JsonPath::Key("role"),
            ],
        ),
        ("metadata container", vec![JsonPath::Key("metadata")]),
        (
            "metadata entry",
            vec![
                JsonPath::Key("metadata"),
                JsonPath::Key("items"),
                JsonPath::Index(0),
            ],
        ),
        (
            "metadata visibility",
            vec![
                JsonPath::Key("metadata"),
                JsonPath::Key("items"),
                JsonPath::Index(0),
                JsonPath::Key("visibility"),
            ],
        ),
        (
            "metadata encryption",
            vec![
                JsonPath::Key("metadata"),
                JsonPath::Key("items"),
                JsonPath::Index(1),
                JsonPath::Key("encryption"),
            ],
        ),
        (
            "metadata cipher envelope",
            vec![
                JsonPath::Key("metadata"),
                JsonPath::Key("items"),
                JsonPath::Index(1),
                JsonPath::Key("encryption"),
                JsonPath::Key("params"),
            ],
        ),
    ];
    for (name, path) in cases {
        let mut value = norito::json::to_value(&manifest).expect("serialize manifest");
        insert_unknown_at_path(&mut value, &path);
        assert!(
            norito::json::from_value::<DaManifestV1>(value).is_err(),
            "unknown fields in the {name} must fail closed"
        );
    }
}
#[test]
fn da_manifest_binary_rejects_pre_release_omission_layouts() {
    #[derive(norito::codec::Encode)]
    struct PreReleaseManifest {
        version: u16,
        client_blob_id: BlobDigest,
        lane_id: LaneId,
        epoch: u64,
        blob_class: BlobClass,
        codec: BlobCodec,
        blob_hash: BlobDigest,
        chunk_root: BlobDigest,
        storage_ticket: StorageTicketId,
        total_size: u64,
        chunk_size: u32,
        erasure_profile: ErasureProfile,
        retention_policy: RetentionPolicy,
        chunks: Vec<ChunkCommitment>,
        metadata: ExtraMetadata,
        issued_at_unix: u64,
    }
    #[derive(norito::codec::Encode)]
    struct PreReleaseErasureProfile {
        data_shards: u16,
        parity_shards: u16,
        chunk_alignment: u16,
        fec_scheme: FecScheme,
    }
    #[derive(norito::codec::Encode)]
    struct PreReleaseMetadataEntry {
        key: String,
        value: Vec<u8>,
        visibility: MetadataVisibility,
    }
    #[derive(norito::codec::Encode)]
    struct PreReleaseMetadataCipherEnvelope;
    #[allow(dead_code)]
    #[derive(norito::codec::Encode)]
    enum PreReleaseMetadataEncryption {
        None,
        ChaCha20Poly1305,
    }

    let manifest = sample_manifest();
    let pre_release_manifest = PreReleaseManifest {
        version: manifest.version,
        client_blob_id: manifest.client_blob_id,
        lane_id: manifest.lane_id,
        epoch: manifest.epoch,
        blob_class: manifest.blob_class,
        codec: manifest.codec,
        blob_hash: manifest.blob_hash,
        chunk_root: manifest.chunk_root,
        storage_ticket: manifest.storage_ticket,
        total_size: manifest.total_size,
        chunk_size: manifest.chunk_size,
        erasure_profile: manifest.erasure_profile,
        retention_policy: manifest.retention_policy,
        chunks: manifest.chunks,
        metadata: manifest.metadata,
        issued_at_unix: manifest.issued_at_unix,
    };
    let bytes = pre_release_manifest.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        DaManifestV1::decode_all(&mut cursor).is_err(),
        "V1 must reject a manifest without stripe, rent, and IPA fields"
    );

    let profile = PreReleaseErasureProfile {
        data_shards: 10,
        parity_shards: 4,
        chunk_alignment: 10,
        fec_scheme: FecScheme::Rs12_10,
    };
    let bytes = profile.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        ErasureProfile::decode_all(&mut cursor).is_err(),
        "V1 must reject an erasure profile without row parity"
    );

    let entry = PreReleaseMetadataEntry {
        key: "category".to_owned(),
        value: b"governance".to_vec(),
        visibility: MetadataVisibility::Public,
    };
    let bytes = entry.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        MetadataEntry::decode_all(&mut cursor).is_err(),
        "V1 must reject a metadata entry without encryption"
    );

    let bytes = PreReleaseMetadataCipherEnvelope.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        MetadataCipherEnvelope::decode_all(&mut cursor).is_err(),
        "V1 must reject a cipher envelope without its key-label slot"
    );

    let bytes = PreReleaseMetadataEncryption::ChaCha20Poly1305.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        MetadataEncryption::decode_all(&mut cursor).is_err(),
        "V1 must reject encrypted metadata without its cipher envelope"
    );
}
#[test]
fn da_ingest_receipt_roundtrip() {
    let receipt = sample_ingest_receipt();
    let buf = norito::to_bytes(&receipt).expect("serialize receipt");
    let archived = from_bytes::<DaIngestReceipt>(&buf).expect("decode receipt");
    let decoded = DaIngestReceipt::deserialize(archived);
    assert_eq!(decoded, receipt);
}

#[test]
fn da_ingest_binary_rejects_pre_release_omission_layouts() {
    #[derive(norito::codec::Encode)]
    struct PreReleaseStripeLayout {
        total_stripes: u32,
        shards_per_stripe: u32,
    }

    #[derive(norito::codec::Encode)]
    struct PreReleaseIngestRequest {
        network_id: NetworkId,
        owner: AccountId,
        client_blob_id: BlobDigest,
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        blob_class: BlobClass,
        codec: BlobCodec,
        erasure_profile: ErasureProfile,
        retention_policy: RetentionPolicy,
        chunk_size: u32,
        total_size: u64,
        payload_hash: BlobDigest,
        payload: Vec<u8>,
        metadata: ExtraMetadata,
        signatures: Vec<DaIngestSignatureV1>,
    }

    #[derive(norito::codec::Encode)]
    struct PreReleaseIngestReceipt {
        client_blob_id: BlobDigest,
        lane_id: LaneId,
        epoch: u64,
        blob_hash: BlobDigest,
        chunk_root: BlobDigest,
        manifest_hash: BlobDigest,
        storage_ticket: StorageTicketId,
        queued_at_unix: u64,
        operator_signature: Signature,
    }

    let stripe = PreReleaseStripeLayout {
        total_stripes: 4,
        shards_per_stripe: 12,
    };
    let bytes = stripe.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        DaStripeLayout::decode_all(&mut cursor).is_err(),
        "V1 must reject a pre-release stripe layout without row parity"
    );

    let request = sample_ingest_request();
    let pre_release_request = PreReleaseIngestRequest {
        network_id: request.network_id,
        owner: request.owner,
        client_blob_id: request.client_blob_id,
        lane_id: request.lane_id,
        epoch: request.epoch,
        sequence: request.sequence,
        blob_class: request.blob_class,
        codec: request.codec,
        erasure_profile: request.erasure_profile,
        retention_policy: request.retention_policy,
        chunk_size: request.chunk_size,
        total_size: request.total_size,
        payload_hash: request.payload_hash,
        payload: request.payload,
        metadata: request.metadata,
        signatures: request.signatures,
    };
    let bytes = pre_release_request.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        DaIngestRequest::decode_all(&mut cursor).is_err(),
        "V1 must reject a pre-release request without compression and manifest slots"
    );

    let receipt = sample_ingest_receipt();
    let pre_release_receipt = PreReleaseIngestReceipt {
        client_blob_id: receipt.client_blob_id,
        lane_id: receipt.lane_id,
        epoch: receipt.epoch,
        blob_hash: receipt.blob_hash,
        chunk_root: receipt.chunk_root,
        manifest_hash: receipt.manifest_hash,
        storage_ticket: receipt.storage_ticket,
        queued_at_unix: receipt.queued_at_unix,
        operator_signature: receipt.operator_signature,
    };
    let bytes = pre_release_receipt.encode();
    let mut cursor = bytes.as_slice();
    assert!(
        DaIngestReceipt::decode_all(&mut cursor).is_err(),
        "V1 must reject a pre-release receipt without PDP, stripe, and rent fields"
    );
}

#[test]
fn da_ingest_json_requires_current_fields_and_rejects_unknown_fields() {
    let request = sample_ingest_request();
    let mut nullable_request = request.clone();
    nullable_request.norito_manifest = None;
    let value = norito::json::to_value(&nullable_request).expect("serialize nullable request");
    assert!(
        value
            .as_object()
            .and_then(|object| object.get("norito_manifest"))
            .is_some_and(norito::json::Value::is_null),
        "V1 must serialize the absent manifest as an explicit null slot"
    );
    assert_eq!(
        norito::json::from_value::<DaIngestRequest>(value).expect("decode explicit null manifest"),
        nullable_request
    );
    for field in ["compression", "norito_manifest"] {
        let mut value = norito::json::to_value(&request).expect("serialize ingest request");
        assert!(
            value
                .as_object_mut()
                .expect("ingest request JSON object")
                .remove(field)
                .is_some(),
            "fixture must contain {field}"
        );
        assert!(
            norito::json::from_value::<DaIngestRequest>(value).is_err(),
            "V1 must require request field {field}"
        );
    }
    let mut value = norito::json::to_value(&request).expect("serialize ingest request");
    value
        .as_object_mut()
        .expect("ingest request JSON object")
        .insert(
            "pre_release_extension".to_owned(),
            norito::json::Value::Bool(true),
        );
    assert!(
        norito::json::from_value::<DaIngestRequest>(value).is_err(),
        "V1 must reject unknown ingest request fields"
    );

    let stripe = request.erasure_profile.row_parity_stripes;
    let layout = DaStripeLayout {
        total_stripes: 4,
        shards_per_stripe: 12,
        row_parity_stripes: stripe,
    };
    let mut value = norito::json::to_value(&layout).expect("serialize stripe layout");
    value
        .as_object_mut()
        .expect("stripe layout JSON object")
        .remove("row_parity_stripes")
        .expect("fixture contains row parity");
    assert!(
        norito::json::from_value::<DaStripeLayout>(value).is_err(),
        "V1 must require stripe row parity"
    );

    let receipt = sample_ingest_receipt();
    let mut nullable_receipt = receipt.clone();
    nullable_receipt.pdp_commitment = None;
    let value = norito::json::to_value(&nullable_receipt).expect("serialize nullable receipt");
    assert!(
        value
            .as_object()
            .and_then(|object| object.get("pdp_commitment"))
            .is_some_and(norito::json::Value::is_null),
        "V1 must serialize the absent PDP commitment as an explicit null slot"
    );
    assert_eq!(
        norito::json::from_value::<DaIngestReceipt>(value).expect("decode explicit null PDP slot"),
        nullable_receipt
    );
    for field in ["pdp_commitment", "stripe_layout", "rent_quote"] {
        let mut value = norito::json::to_value(&receipt).expect("serialize ingest receipt");
        assert!(
            value
                .as_object_mut()
                .expect("ingest receipt JSON object")
                .remove(field)
                .is_some(),
            "fixture must contain {field}"
        );
        assert!(
            norito::json::from_value::<DaIngestReceipt>(value).is_err(),
            "V1 must require receipt field {field}"
        );
    }
    let mut value = norito::json::to_value(&receipt).expect("serialize ingest receipt");
    value
        .as_object_mut()
        .expect("ingest receipt JSON object")
        .insert(
            "pre_release_extension".to_owned(),
            norito::json::Value::Bool(true),
        );
    assert!(
        norito::json::from_value::<DaIngestReceipt>(value).is_err(),
        "V1 must reject unknown ingest receipt fields"
    );
}
