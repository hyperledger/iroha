//! Norito Streaming integration test helpers and vectors.
use core::convert::TryFrom;
use hex::encode as hex_encode;
use iroha_config::parameters::actual;
use iroha_core::streaming::{StreamingHandle, StreamingProcessError};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::peer::Peer;
use iroha_primitives::addr::SocketAddr;
use norito::{
    json,
    streaming::{
        BUNDLED_RANS_GPU_BUILD_AVAILABLE, BundledTelemetry, CapabilityFlags, CapabilityRole,
        EntropyMode, Hash, HpkeSuite, ManifestAnnounceFrame, ManifestV1, PrivacyBucketGranularity,
        StreamingTicket, TicketCapabilities, TicketPolicy, TicketRevocation,
        TransportCapabilityResolution, chunk,
        codec::{
            BaselineEncoder, BaselineEncoderConfig, BaselineManifestParams, EncodedSegment,
            FrameDimensions, RawFrame, load_bundle_tables_from_toml,
        },
    },
    to_bytes,
};
use std::path::PathBuf;
/// Default capability mask used by streaming integration tests.
pub const BASE_CAPABILITIES: CapabilityFlags = CapabilityFlags::from_bits(
    CapabilityFlags::FEATURE_FEEDBACK_HINTS
        | CapabilityFlags::FEATURE_PRIVACY_PROVIDER
        | CapabilityFlags::FEATURE_ENTROPY_BUNDLED,
);
/// Deterministic Norito Streaming vector exercised by the end-to-end integration test.
#[derive(Clone)]
pub struct StreamingTestVector {
    /// Manifest template prior to capability stamping.
    pub manifest: ManifestV1,
    /// Encoded manifest bytes for the template form.
    pub manifest_bytes: Vec<u8>,
    /// Chunk payloads emitted by the encoder.
    pub chunk_payloads: Vec<Vec<u8>>,
    /// Merkle commitments for each chunk payload.
    pub chunk_commitments: Vec<Hash>,
    /// Storage commitment derived from the chunk set.
    pub storage_commitment: Hash,
    /// Data-availability root derived from the chunk set.
    pub da_root: Hash,
    /// Canonical capability ticket emitted alongside the segment.
    pub ticket: StreamingTicket,
    /// Revocation payload matching the canonical ticket.
    pub ticket_revocation: TicketRevocation,
}
impl StreamingTestVector {
    /// Return the maximum chunk length inside the vector.
    #[must_use]
    pub fn max_chunk_len(&self) -> usize {
        self.chunk_payloads
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or_default()
    }
    /// Encode the manifest after capability stamping into bytes.
    ///
    /// # Errors
    ///
    /// Propagates codec failures while serialising the manifest.
    pub fn manifest_wire_bytes(manifest: &ManifestV1) -> Result<Vec<u8>, norito::Error> {
        to_bytes(manifest)
    }
    /// Build a JSON snapshot describing the template vector contents.
    ///
    /// The string is suitable for sharing with partner SDKs as a canonical reference, and it
    /// encodes ticket-related fields as stable structured JSON with hex-encoded byte arrays.
    ///
    /// # Errors
    ///
    /// Returns [`norito::Error`] if JSON encoding fails.
    pub fn snapshot_json(&self) -> Result<String, norito::Error> {
        let manifest_hex = hex_encode(&self.manifest_bytes);
        let chunk_root_hex = hex_encode(self.manifest.chunk_root);
        let chunk_commitments: Vec<String> =
            self.chunk_commitments.iter().map(hex_encode).collect();
        let chunk_payloads: Vec<String> = self.chunk_payloads.iter().map(hex_encode).collect();
        let storage_commitment_hex = hex_encode(self.storage_commitment);
        let da_root_hex = hex_encode(self.da_root);
        let mut map = norito::json::Map::new();
        map.insert(
            "manifest_template_hex".into(),
            json::to_value(&manifest_hex)?,
        );
        map.insert("chunk_root".into(), json::to_value(&chunk_root_hex)?);
        map.insert(
            "chunk_commitments".into(),
            json::to_value(&chunk_commitments)?,
        );
        map.insert("chunk_payloads".into(), json::to_value(&chunk_payloads)?);
        map.insert(
            "storage_commitment".into(),
            json::to_value(&storage_commitment_hex)?,
        );
        map.insert("da_root".into(), json::to_value(&da_root_hex)?);
        map.insert("ticket".into(), ticket_json_value(&self.ticket)?);
        map.insert(
            "ticket_revocation".into(),
            ticket_revocation_json_value(&self.ticket_revocation),
        );
        let json_value = norito::json::Value::Object(map);
        json::to_string_pretty(&json_value).map_err(norito::Error::from)
    }
}
fn ticket_json_value(ticket: &StreamingTicket) -> Result<norito::json::Value, norito::Error> {
    let mut map = norito::json::Map::new();
    map.insert(
        "capabilities".into(),
        norito::json::Value::from(ticket.capabilities.bits()),
    );
    map.insert(
        "chunk_teu".into(),
        norito::json::Value::from(ticket.chunk_teu),
    );
    map.insert("commitment".into(), hex_value(ticket.commitment));
    map.insert("contract_sig".into(), hex_value(ticket.contract_sig));
    map.insert("dsid".into(), norito::json::Value::from(ticket.dsid));
    map.insert(
        "expire_slot".into(),
        norito::json::Value::from(ticket.expire_slot),
    );
    map.insert(
        "expires_at".into(),
        norito::json::Value::from(ticket.expires_at),
    );
    map.insert(
        "fanout_quota".into(),
        norito::json::Value::from(ticket.fanout_quota),
    );
    map.insert(
        "issued_at".into(),
        norito::json::Value::from(ticket.issued_at),
    );
    map.insert("key_commitment".into(), hex_value(ticket.key_commitment));
    map.insert("lane_id".into(), norito::json::Value::from(ticket.lane_id));
    map.insert("nonce".into(), norito::json::Value::from(ticket.nonce));
    map.insert("nullifier".into(), hex_value(ticket.nullifier));
    map.insert(
        "owner".into(),
        norito::json::Value::from(ticket.owner.as_str()),
    );
    map.insert("policy".into(), ticket_policy_json(ticket.policy.as_ref())?);
    map.insert("prepaid_teu".into(), u128_json_value(ticket.prepaid_teu));
    map.insert("proof_id".into(), hex_value(ticket.proof_id));
    map.insert(
        "settlement_bucket".into(),
        norito::json::Value::from(ticket.settlement_bucket),
    );
    map.insert(
        "start_slot".into(),
        norito::json::Value::from(ticket.start_slot),
    );
    map.insert("ticket_id".into(), hex_value(ticket.ticket_id));
    Ok(norito::json::Value::Object(map))
}
fn ticket_policy_json(policy: Option<&TicketPolicy>) -> Result<norito::json::Value, norito::Error> {
    let Some(policy) = policy else {
        return Ok(norito::json::Value::Null);
    };
    let mut map = norito::json::Map::new();
    map.insert(
        "allowed_regions".into(),
        json::to_value(&policy.allowed_regions)?,
    );
    let max_bandwidth = policy
        .max_bandwidth_kbps
        .map_or(norito::json::Value::Null, norito::json::Value::from);
    map.insert("max_bandwidth_kbps".into(), max_bandwidth);
    map.insert(
        "max_relays".into(),
        norito::json::Value::from(policy.max_relays),
    );
    Ok(norito::json::Value::Object(map))
}
fn ticket_revocation_json_value(revocation: &TicketRevocation) -> norito::json::Value {
    let mut map = norito::json::Map::new();
    map.insert("nullifier".into(), hex_value(revocation.nullifier));
    map.insert(
        "reason_code".into(),
        norito::json::Value::from(revocation.reason_code),
    );
    map.insert(
        "revocation_signature".into(),
        hex_value(revocation.revocation_signature),
    );
    map.insert("ticket_id".into(), hex_value(revocation.ticket_id));
    norito::json::Value::Object(map)
}
fn hex_value(bytes: impl AsRef<[u8]>) -> norito::json::Value {
    norito::json::Value::from(hex_encode(bytes.as_ref()))
}
fn u128_json_value(value: u128) -> norito::json::Value {
    u64::try_from(value).map_or_else(
        |_| norito::json::Value::from(value.to_string()),
        norito::json::Value::from,
    )
}
/// Construct a deterministic baseline segment and the encoder configuration used to produce it.
#[must_use]
pub fn baseline_segment(
    frame_count: usize,
) -> (BaselineEncoderConfig, EncodedSegment, Vec<RawFrame>) {
    assert!(frame_count > 0, "frame_count must be non-zero");
    let dims = FrameDimensions::new(8, 8);
    let frame_duration_ns = 25_000_000u32;
    let mut frames = Vec::with_capacity(frame_count);
    let base_luma = vec![0x55; dims.pixel_count()];
    for _ in 0..frame_count {
        frames.push(RawFrame::new(dims, base_luma.clone()).expect("valid frame"));
    }
    let config = BaselineEncoderConfig {
        frame_dimensions: dims,
        frame_duration_ns,
        duration_ns: frame_duration_ns
            .saturating_mul(u32::try_from(frame_count).expect("frame count fits u32")),
        quantizer: 0,
        ..BaselineEncoderConfig::default()
    };
    let mut encoder = BaselineEncoder::new(config.clone());
    let segment = encoder
        .encode_segment(5, 1_000_000, 3, &frames, None)
        .expect("encode baseline segment");
    (config, segment, frames)
}
fn vector_from_segment(segment: &EncodedSegment) -> StreamingTestVector {
    let manifest = build_manifest(segment);
    let chunk_refs: Vec<(u16, &[u8])> = segment
        .descriptors
        .iter()
        .zip(segment.chunks.iter())
        .map(|(descriptor, chunk)| (descriptor.chunk_id, chunk.as_slice()))
        .collect();
    let chunk_commitments = chunk::chunk_commitments(segment.header.segment_number, &chunk_refs);
    let chunk_ids: Vec<_> = segment
        .descriptors
        .iter()
        .map(|descriptor| descriptor.chunk_id)
        .collect();
    let storage_commitment = chunk::storage_commitment(
        segment.header.segment_number,
        segment.header.content_key_id,
        &segment.header.chunk_merkle_root,
        &chunk_ids,
    )
    .expect("storage commitment");
    let da_root = chunk::data_availability_root(
        segment.header.segment_number,
        segment.header.content_key_id,
        &segment.header.chunk_merkle_root,
        &chunk_ids,
    )
    .expect("da root");
    let manifest_bytes = to_bytes(&manifest).expect("serialize manifest template");
    let capabilities = TicketCapabilities::from_bits(
        TicketCapabilities::LIVE | TicketCapabilities::HDR | TicketCapabilities::SPATIAL_AUDIO,
    );
    let ticket_policy = TicketPolicy {
        max_relays: 4,
        allowed_regions: vec!["us".into(), "jp".into()],
        max_bandwidth_kbps: Some(15_000),
    };
    let ticket = StreamingTicket {
        ticket_id: fill_hash(0x44),
        owner: "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE".into(),
        dsid: 42,
        lane_id: 7,
        capabilities,
        policy: Some(ticket_policy),
        issued_at: 1_703_500_000,
        expires_at: 1_703_800_000,
        settlement_bucket: 1_024,
        start_slot: 10_000,
        expire_slot: 12_000,
        prepaid_teu: 64_000,
        chunk_teu: 32,
        fanout_quota: 4,
        key_commitment: fill_hash(0x45),
        nonce: 42,
        contract_sig: fill_signature(0x46),
        commitment: fill_hash(0x47),
        nullifier: fill_hash(0x48),
        proof_id: fill_hash(0x49),
    };
    let ticket_revocation = TicketRevocation {
        ticket_id: ticket.ticket_id,
        nullifier: ticket.nullifier,
        reason_code: 17,
        revocation_signature: fill_signature(0xCC),
    };
    StreamingTestVector {
        manifest,
        manifest_bytes,
        chunk_payloads: segment.chunks.clone(),
        chunk_commitments,
        storage_commitment,
        da_root,
        ticket,
        ticket_revocation,
    }
}
/// Construct a deterministic baseline streaming vector for integration testing.
#[must_use]
pub fn baseline_test_vector() -> StreamingTestVector {
    baseline_test_vector_with_frames(2)
}
/// Construct a deterministic baseline streaming vector with the requested frame count.
#[must_use]
pub fn baseline_test_vector_with_frames(frame_count: usize) -> StreamingTestVector {
    let (_config, segment, _frames) = baseline_segment(frame_count);
    vector_from_segment(&segment)
}
/// Construct a bundled segment using the repository bundle tables.
#[must_use]
pub fn bundled_segment(
    frame_count: usize,
    bundle_width: u8,
) -> (
    BaselineEncoderConfig,
    EncodedSegment,
    Vec<RawFrame>,
    BundledTelemetry,
) {
    assert!(frame_count > 0, "frame_count must be non-zero");
    let dims = FrameDimensions::new(8, 8);
    let frame_duration_ns = 25_000_000u32;
    let mut frames = Vec::with_capacity(frame_count);
    let base_luma = vec![0x33; dims.pixel_count()];
    for _ in 0..frame_count {
        frames.push(RawFrame::new(dims, base_luma.clone()).expect("valid frame"));
    }
    let bundle_tables = load_bundle_tables_from_toml(repo_rans_tables_path())
        .expect("load bundle tables from repository fixture");
    let max_width = bundle_tables.max_width().max(2);
    let configured_width = bundle_width.clamp(2, max_width);
    let config = BaselineEncoderConfig {
        frame_dimensions: dims,
        frame_duration_ns,
        duration_ns: frame_duration_ns
            .saturating_mul(u32::try_from(frame_count).expect("frame count fits u32")),
        quantizer: 1,
        entropy_mode: EntropyMode::RansBundled,
        bundle_width: configured_width,
        bundle_tables: bundle_tables.clone(),
        ..BaselineEncoderConfig::default()
    };
    let mut encoder = BaselineEncoder::new(config.clone());
    let segment = encoder
        .encode_segment(6, 2_000_000, 9, &frames, None)
        .expect("encode bundled segment");
    let telemetry = encoder
        .bundled_telemetry()
        .cloned()
        .expect("bundled telemetry recorded");
    (config, segment, frames, telemetry)
}
/// Construct a bundled streaming vector with deterministic frames.
#[must_use]
pub fn bundled_test_vector() -> StreamingTestVector {
    bundled_test_vector_with_frames(2, 4)
}
/// Construct a bundled streaming vector with the desired frame count and bundle width.
#[must_use]
pub fn bundled_test_vector_with_frames(
    frame_count: usize,
    bundle_width: u8,
) -> StreamingTestVector {
    let (_config, segment, _frames, _telemetry) = bundled_segment(frame_count, bundle_width);
    vector_from_segment(&segment)
}
fn build_manifest(segment: &EncodedSegment) -> ManifestV1 {
    use norito::streaming::{FecScheme, Multiaddr, StreamMetadata};
    let params = BaselineManifestParams {
        stream_id: fill_hash(0x31),
        protocol_version: 1,
        published_at: 1_703_000_000,
        da_endpoint: Multiaddr::from("/ip4/127.0.0.1/udp/9100/quic"),
        privacy_routes: Vec::new(),
        public_metadata: StreamMetadata {
            title: "NSC Baseline Vector".into(),
            description: Some("Canonical manifest for Norito streaming harness.".into()),
            access_policy_id: None,
            tags: vec!["nsc".into(), "baseline".into()],
        },
        capabilities: BASE_CAPABILITIES,
        signature: fill_signature(0x41),
        fec_suite: FecScheme::Rs12_10,
        neural_bundle: None,
        transport_capabilities_hash: [0u8; 32],
    };
    segment.build_manifest(params)
}
fn fill_hash(byte: u8) -> Hash {
    [byte; 32]
}
fn fill_signature(byte: u8) -> norito::streaming::Signature {
    [byte; 64]
}
fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("Cargo.lock").exists() {
        dir = dir
            .parent()
            .expect("workspace root should contain Cargo.lock")
            .to_path_buf();
    }
    dir
}
fn repo_rans_tables_path() -> PathBuf {
    workspace_root().join("codec/rans/tables/rans_seed0.toml")
}
/// Construct a deterministic [`Peer`] for the supplied key pair and port.
#[must_use]
pub fn make_peer(key_pair: &KeyPair, port: u16) -> Peer {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    Peer::new(SocketAddr::from(addr), key_pair.public_key().clone())
}
/// Create a streaming handle with default capabilities suited for the tests.
#[must_use]
pub fn streaming_handle() -> StreamingHandle {
    let flags = BASE_CAPABILITIES;
    let mut codec = actual::StreamingCodec::from_defaults();
    codec.rans_tables_path = repo_rans_tables_path();
    StreamingHandle::new()
        .with_capabilities(flags)
        .with_codec_config(&codec)
        .expect("codec config defaults must load bundle tables")
}
/// Create a streaming handle configured for bundled rANS mode with the specified width.
#[must_use]
pub fn bundled_streaming_handle(bundle_width: u8) -> StreamingHandle {
    bundled_streaming_handle_with_accel(bundle_width, actual::BundleAcceleration::None)
}
/// Create a bundled streaming handle that advertises the requested acceleration mode.
#[must_use]
pub fn bundled_streaming_handle_with_accel(
    bundle_width: u8,
    accel: actual::BundleAcceleration,
) -> StreamingHandle {
    let flags = BASE_CAPABILITIES;
    let mut codec = actual::StreamingCodec::from_defaults();
    codec.rans_tables_path = repo_rans_tables_path();
    let max_width = load_bundle_tables_from_toml(&codec.rans_tables_path)
        .expect("bundle tables must load for width selection")
        .max_width();
    codec.entropy_mode = EntropyMode::RansBundled;
    codec.bundle_width = bundle_width.max(2).min(max_width);
    codec.bundle_accel = accel;
    StreamingHandle::new()
        .with_capabilities(flags)
        .with_codec_config(&codec)
        .expect("bundled codec config must load bundle tables")
}
/// Generate deterministic key material for the publisher and viewer roles.
#[must_use]
pub fn test_keypairs() -> (KeyPair, KeyPair) {
    (
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked streaming publisher Ed25519 keypair"),
        KeyPair::try_random().expect("generate checked streaming viewer keypair"),
    )
}
/// Build a manifest announce frame after stamping capabilities for the provided viewer.
///
/// # Errors
///
/// Propagates failures while applying the transport capabilities.
pub fn manifest_announce_for_viewer(
    handle: &StreamingHandle,
    viewer: &Peer,
    mut manifest: ManifestV1,
) -> Result<ManifestAnnounceFrame, iroha_core::streaming::StreamingProcessError> {
    handle.apply_manifest_transport_capabilities(viewer.id(), &mut manifest)?;
    Ok(ManifestAnnounceFrame { manifest })
}
/// Record transport capabilities and negotiated bits for a viewer peer, returning the resolution.
pub fn seed_viewer_negotiation(
    handle: &StreamingHandle,
    viewer: &Peer,
    negotiated_flags: CapabilityFlags,
    max_chunk_len: usize,
) -> TransportCapabilityResolution {
    let resolution = TransportCapabilityResolution {
        hpke_suite: HpkeSuite::Kyber768AuthPsk,
        use_datagram: true,
        max_segment_datagram_size: u16::try_from(max_chunk_len).unwrap_or(u16::MAX),
        fec_feedback_interval_ms: 250,
        privacy_bucket_granularity: PrivacyBucketGranularity::StandardV1,
    };
    handle
        .record_transport_capabilities(viewer, CapabilityRole::Viewer, resolution)
        .expect("record viewer transport capabilities");
    handle
        .record_negotiated_capabilities(viewer, CapabilityRole::Viewer, negotiated_flags)
        .expect("record viewer negotiated capabilities");
    resolution
}
#[cfg(test)]
mod tests {
    use super::*;
    use norito::{
        json::Value,
        streaming::{
            CapabilityFlags, CapabilityRole, HpkeSuite, PrivacyBucketGranularity,
            TransportCapabilityResolution,
        },
    };
    fn expect_u64_field(map: &norito::json::Map, key: &str) -> u64 {
        match map.get(key) {
            Some(Value::Number(value)) => value
                .as_u64()
                .unwrap_or_else(|| panic!("{key} must be a non-negative integer")),
            _ => panic!("{key} must be a number"),
        }
    }
    #[test]
    fn baseline_snapshot_matches_golden_fixture() {
        let vector = baseline_test_vector();
        let snapshot = vector.snapshot_json().expect("snapshot serializes");
        let expected = include_str!("../../fixtures/norito_streaming/rans/baseline.json")
            .replace("\r\n", "\n");
        let snapshot_trimmed = snapshot.trim_end();
        let expected_trimmed = expected.trim_end();
        if snapshot_trimmed != expected_trimmed {
            println!("--- actual snapshot ---\n{snapshot_trimmed}\n--- end actual snapshot ---");
            println!(
                "expected length: {}, actual length: {}",
                expected_trimmed.len(),
                snapshot_trimmed.len()
            );
            for (idx, (actual_ch, expected_ch)) in snapshot_trimmed
                .chars()
                .zip(expected_trimmed.chars())
                .enumerate()
            {
                assert_eq!(
                    expected_ch, actual_ch,
                    "baseline snapshot mismatch at char {idx}: actual `{actual_ch}` vs expected `{expected_ch}`"
                );
            }
            panic!(
                "baseline snapshot mismatch (lengths {} vs {})",
                snapshot_trimmed.len(),
                expected_trimmed.len()
            );
        }
    }
    #[test]
    fn bundled_snapshot_matches_golden_fixture() {
        let vector = bundled_test_vector();
        let snapshot = vector.snapshot_json().expect("snapshot serializes");
        let expected =
            include_str!("../../fixtures/norito_streaming/rans/bundled.json").replace("\r\n", "\n");
        let snapshot_trimmed = snapshot.trim_end();
        let expected_trimmed = expected.trim_end();
        if snapshot_trimmed != expected_trimmed {
            println!("--- bundled snapshot ---\n{snapshot_trimmed}\n--- end bundled snapshot ---");
            println!(
                "expected length: {}, actual length: {}",
                expected_trimmed.len(),
                snapshot_trimmed.len()
            );
            for (idx, (actual, expected)) in snapshot_trimmed
                .chars()
                .zip(expected_trimmed.chars())
                .enumerate()
            {
                assert_eq!(
                    expected, actual,
                    "bundled snapshot mismatch at char {idx}: actual `{actual}` vs expected `{expected}`"
                );
            }
            panic!(
                "bundled snapshot mismatch (lengths {} vs {})",
                snapshot_trimmed.len(),
                expected_trimmed.len()
            );
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn snapshot_json_encodes_ticket_fields() {
        let vector = baseline_test_vector();
        let snapshot = vector.snapshot_json().expect("snapshot serializes");
        let value: norito::json::Value =
            norito::json::from_str(&snapshot).expect("snapshot parses");
        let norito::json::Value::Object(root) = value else {
            panic!("snapshot root must be an object");
        };
        let ticket = root.get("ticket").expect("ticket field present");
        let norito::json::Value::Object(ticket_map) = ticket else {
            panic!("ticket must be an object");
        };
        let expected_ticket_id = hex_encode(vector.ticket.ticket_id);
        let ticket_id = match ticket_map.get("ticket_id") {
            Some(Value::String(value)) => value,
            _ => panic!("ticket_id must be a string"),
        };
        assert_eq!(ticket_id, &expected_ticket_id);
        let key_commitment = match ticket_map.get("key_commitment") {
            Some(Value::String(value)) => value,
            _ => panic!("key_commitment must be a string"),
        };
        assert_eq!(key_commitment, &hex_encode(vector.ticket.key_commitment));
        let contract_sig = match ticket_map.get("contract_sig") {
            Some(Value::String(value)) => value,
            _ => panic!("contract_sig must be a string"),
        };
        assert_eq!(contract_sig, &hex_encode(vector.ticket.contract_sig));
        let commitment = match ticket_map.get("commitment") {
            Some(Value::String(value)) => value,
            _ => panic!("commitment must be a string"),
        };
        assert_eq!(commitment, &hex_encode(vector.ticket.commitment));
        let nullifier = match ticket_map.get("nullifier") {
            Some(Value::String(value)) => value,
            _ => panic!("nullifier must be a string"),
        };
        assert_eq!(nullifier, &hex_encode(vector.ticket.nullifier));
        let proof_id = match ticket_map.get("proof_id") {
            Some(Value::String(value)) => value,
            _ => panic!("proof_id must be a string"),
        };
        assert_eq!(proof_id, &hex_encode(vector.ticket.proof_id));
        let owner = match ticket_map.get("owner") {
            Some(Value::String(value)) => value,
            _ => panic!("owner must be a string"),
        };
        assert_eq!(owner, &vector.ticket.owner);
        let dsid = expect_u64_field(ticket_map, "dsid");
        assert_eq!(dsid, vector.ticket.dsid);
        let lane_id = expect_u64_field(ticket_map, "lane_id");
        assert_eq!(lane_id, u64::from(vector.ticket.lane_id));
        let settlement_bucket = expect_u64_field(ticket_map, "settlement_bucket");
        assert_eq!(settlement_bucket, vector.ticket.settlement_bucket);
        let start_slot = expect_u64_field(ticket_map, "start_slot");
        assert_eq!(start_slot, vector.ticket.start_slot);
        let expire_slot = expect_u64_field(ticket_map, "expire_slot");
        assert_eq!(expire_slot, vector.ticket.expire_slot);
        let prepaid_teu = expect_u64_field(ticket_map, "prepaid_teu");
        assert_eq!(
            prepaid_teu,
            u64::try_from(vector.ticket.prepaid_teu).expect("prepaid fits u64")
        );
        let chunk_teu = expect_u64_field(ticket_map, "chunk_teu");
        assert_eq!(chunk_teu, u64::from(vector.ticket.chunk_teu));
        let fanout_quota = expect_u64_field(ticket_map, "fanout_quota");
        assert_eq!(fanout_quota, u64::from(vector.ticket.fanout_quota));
        let issued_at = expect_u64_field(ticket_map, "issued_at");
        assert_eq!(issued_at, vector.ticket.issued_at);
        let expires_at = expect_u64_field(ticket_map, "expires_at");
        assert_eq!(expires_at, vector.ticket.expires_at);
        let capabilities = expect_u64_field(ticket_map, "capabilities");
        assert_eq!(capabilities, u64::from(vector.ticket.capabilities.bits()));
        let policy = match ticket_map.get("policy") {
            Some(Value::Object(value)) => value,
            _ => panic!("policy must be an object"),
        };
        let allowed_regions = match policy.get("allowed_regions") {
            Some(Value::Array(values)) => values,
            _ => panic!("policy.allowed_regions must be an array"),
        };
        let regions: Vec<&str> = allowed_regions
            .iter()
            .map(|value| match value {
                Value::String(value) => value.as_str(),
                _ => panic!("allowed_regions entries must be strings"),
            })
            .collect();
        assert_eq!(regions, vec!["us", "jp"]);
        let max_bandwidth = expect_u64_field(policy, "max_bandwidth_kbps");
        assert_eq!(max_bandwidth, 15_000);
        let max_relays = expect_u64_field(policy, "max_relays");
        assert_eq!(
            max_relays,
            u64::from(vector.ticket.policy.as_ref().unwrap().max_relays)
        );
        let revocation = root
            .get("ticket_revocation")
            .expect("ticket_revocation field present");
        let norito::json::Value::Object(revocation_map) = revocation else {
            panic!("ticket_revocation must be an object");
        };
        let revocation_ticket_id = match revocation_map.get("ticket_id") {
            Some(Value::String(value)) => value,
            _ => panic!("ticket_revocation.ticket_id must be a string"),
        };
        let revocation_nullifier = match revocation_map.get("nullifier") {
            Some(Value::String(value)) => value,
            _ => panic!("ticket_revocation.nullifier must be a string"),
        };
        let revocation_signature = match revocation_map.get("revocation_signature") {
            Some(Value::String(value)) => value,
            _ => panic!("ticket_revocation.revocation_signature must be a string"),
        };
        let revocation_reason = expect_u64_field(revocation_map, "reason_code");
        assert_eq!(revocation_ticket_id, &expected_ticket_id);
        assert_eq!(revocation_nullifier, &hex_encode(vector.ticket.nullifier));
        assert_eq!(
            revocation_signature,
            &hex_encode(vector.ticket_revocation.revocation_signature)
        );
        assert_eq!(
            revocation_reason,
            u64::from(vector.ticket_revocation.reason_code)
        );
    }
    #[test]
    fn snapshot_json_uses_string_for_large_prepaid_teu() {
        let mut vector = baseline_test_vector();
        vector.ticket.prepaid_teu = u128::from(u64::MAX) + 1;
        let snapshot = vector.snapshot_json().expect("snapshot serializes");
        let value: norito::json::Value =
            norito::json::from_str(&snapshot).expect("snapshot parses");
        let norito::json::Value::Object(root) = value else {
            panic!("snapshot root must be an object");
        };
        let ticket = root.get("ticket").expect("ticket field present");
        let norito::json::Value::Object(ticket_map) = ticket else {
            panic!("ticket must be an object");
        };
        let prepaid_teu = match ticket_map.get("prepaid_teu") {
            Some(Value::String(value)) => value,
            _ => panic!("prepaid_teu must be a string"),
        };
        assert_eq!(prepaid_teu, &vector.ticket.prepaid_teu.to_string());
    }
    #[test]
    fn helper_functions_remain_consistent() {
        let vector = baseline_test_vector_with_frames(2);
        // Ensure helper reports actual maximum chunk length.
        let expected_max = vector
            .chunk_payloads
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or_default();
        assert_eq!(vector.max_chunk_len(), expected_max);
        // Manifest wire bytes should match template serialization.
        let manifest_bytes = StreamingTestVector::manifest_wire_bytes(&vector.manifest)
            .expect("manifest serializes");
        assert_eq!(manifest_bytes, vector.manifest_bytes);
        // Construct peer/network fixtures and ensure manifest announce succeeds.
        let handle = streaming_handle();
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_345);
        // Seed negotiated capability state to mirror the runtime handshake.
        let max_datagram = u16::try_from(vector.max_chunk_len()).unwrap_or(u16::MAX);
        let resolution = TransportCapabilityResolution {
            hpke_suite: HpkeSuite::Kyber768AuthPsk,
            use_datagram: true,
            max_segment_datagram_size: max_datagram,
            fec_feedback_interval_ms: 250,
            privacy_bucket_granularity: PrivacyBucketGranularity::StandardV1,
        };
        handle
            .record_transport_capabilities(&viewer_peer, CapabilityRole::Viewer, resolution)
            .expect("record viewer transport capabilities");
        handle
            .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Viewer, BASE_CAPABILITIES)
            .expect("record viewer negotiated capabilities");
        let announce = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect("announce manifest");
        assert_eq!(announce.manifest.chunk_root, vector.manifest.chunk_root);
    }
    #[test]
    fn bundled_handle_negotiation_smoke() {
        let handle = bundled_streaming_handle(4);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_346);
        let negotiated = BASE_CAPABILITIES;
        let max_chunk_len = 4096;
        let resolution = seed_viewer_negotiation(&handle, &viewer_peer, negotiated, max_chunk_len);
        assert_eq!(
            resolution.max_segment_datagram_size,
            u16::try_from(max_chunk_len).unwrap_or(u16::MAX)
        );
    }
    #[test]
    fn bundled_vector_includes_entropy_metadata() {
        let vector = bundled_test_vector();
        assert_eq!(vector.manifest.entropy_mode, EntropyMode::RansBundled);
        assert!(
            vector
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled manifests must set the entropy capability bit"
        );
        assert!(
            vector.manifest.entropy_tables_checksum.is_some(),
            "bundled manifests must carry table checksums"
        );
        assert!(
            !vector.chunk_payloads.is_empty(),
            "bundled harness should emit chunk payloads"
        );
    }
    #[test]
    fn bundled_manifest_rejected_without_viewer_entropy_flag() {
        let handle = bundled_streaming_handle(4);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_347);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES.remove(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let err = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect_err("viewer lacking bundled bit must be rejected");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestEntropyModeNotNegotiated { .. }
        ));
    }
    #[test]
    fn bundled_manifest_rejected_without_viewer_acceleration_flag() {
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::CpuSimd);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_348);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES;
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let err = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect_err("viewer lacking acceleration bit must be rejected");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestAccelerationNotNegotiated { .. }
        ));
    }
    #[test]
    fn bundled_manifest_sets_acceleration_bits_when_supported() {
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::CpuSimd);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_349);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD);
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let announce = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect("viewer advertising bundled + accel bits should succeed");
        let capabilities = announce.manifest.capabilities;
        assert!(
            capabilities.contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
            "bundled manifests must keep the entropy capability bit",
        );
        assert!(
            capabilities.contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "manifest must advertise the negotiated acceleration bit",
        );
    }
    #[test]
    fn bundled_manifest_rejected_without_viewer_gpu_flag() {
        if !BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            eprintln!(
                "skipping bundled_manifest_rejected_without_viewer_gpu_flag: GPU bundle acceleration unavailable"
            );
            return;
        }
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::Gpu);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_350);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES;
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let err = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect_err("viewer lacking GPU acceleration bit must be rejected");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestAccelerationNotNegotiated { .. }
        ));
    }
    #[test]
    fn bundled_manifest_rejected_when_viewer_only_advertises_gpu_for_cpu_handle() {
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::CpuSimd);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_351);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU);
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let err = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect_err("CPU-only handle must reject GPU-only viewers");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestAccelerationNotNegotiated { .. }
        ));
    }
    #[test]
    fn bundled_manifest_sets_gpu_acceleration_bit_when_supported() {
        if !BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            eprintln!(
                "skipping bundled_manifest_sets_gpu_acceleration_bit_when_supported: GPU bundle acceleration unavailable"
            );
            return;
        }
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::Gpu);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_352);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU);
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let announce = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect("GPU viewers advertising bundled + acceleration bits should succeed");
        assert!(
            announce
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "manifest must advertise the negotiated GPU acceleration bit",
        );
        assert!(
            !announce
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "GPU manifests must not leak CPU-specific capability bits",
        );
    }
    #[test]
    fn bundled_manifest_strips_gpu_bit_for_cpu_handle() {
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::CpuSimd);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_353);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES.insert(
            CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        );
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let announce = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect("CPU handle should normalize viewer GPU bits");
        assert!(
            announce
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "CPU manifests keep the CPU acceleration bit"
        );
        assert!(
            !announce
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "CPU manifests must drop GPU acceleration bits"
        );
    }
    #[test]
    fn bundled_manifest_strips_cpu_bit_for_gpu_handle() {
        if !BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            eprintln!(
                "skipping bundled_manifest_strips_cpu_bit_for_gpu_handle: GPU bundle acceleration unavailable"
            );
            return;
        }
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::Gpu);
        let (_publisher, viewer) = test_keypairs();
        let viewer_peer = make_peer(&viewer, 12_354);
        let vector = bundled_test_vector();
        let negotiated = BASE_CAPABILITIES.insert(
            CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        );
        seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
        let announce = manifest_announce_for_viewer(&handle, &viewer_peer, vector.manifest.clone())
            .expect("GPU handle should normalize viewer CPU bits");
        assert!(
            announce
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "GPU manifests must advertise the GPU acceleration bit"
        );
        assert!(
            !announce
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "GPU manifests must drop CPU acceleration bits"
        );
    }
    #[test]
    fn bundled_manifest_handles_hybrid_viewers() {
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::CpuSimd);
        let vector = bundled_test_vector();
        let (_publisher, hybrid_viewer) = test_keypairs();
        let hybrid_peer = make_peer(&hybrid_viewer, 12_356);
        let negotiated_hybrid = BASE_CAPABILITIES.insert(
            CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD
                | CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU,
        );
        seed_viewer_negotiation(
            &handle,
            &hybrid_peer,
            negotiated_hybrid,
            vector.max_chunk_len(),
        );
        let hybrid_manifest =
            manifest_announce_for_viewer(&handle, &hybrid_peer, vector.manifest.clone())
                .expect("hybrid viewer with both accel bits should succeed");
        assert!(
            hybrid_manifest
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "CPU acceleration bit must be retained for hybrid viewers"
        );
        assert!(
            !hybrid_manifest
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "CPU handle must normalize away GPU-only bits"
        );
        // Ensure subsequent announcements for the hybrid viewer remain valid.
        manifest_announce_for_viewer(&handle, &hybrid_peer, vector.manifest.clone())
            .expect("hybrid viewer must continue to receive normalized manifests");
    }
    #[test]
    fn bundled_gpu_handle_rejects_cpu_viewers() {
        if !BUNDLED_RANS_GPU_BUILD_AVAILABLE {
            eprintln!(
                "skipping bundled_gpu_handle_rejects_cpu_viewers: GPU bundle acceleration unavailable"
            );
            return;
        }
        let handle = bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::Gpu);
        let vector = bundled_test_vector();
        let (_publisher, gpu_viewer) = test_keypairs();
        let (_publisher2, cpu_viewer) = test_keypairs();
        let gpu_peer = make_peer(&gpu_viewer, 12_358);
        let cpu_peer = make_peer(&cpu_viewer, 12_359);
        let negotiated_gpu = BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU);
        seed_viewer_negotiation(&handle, &gpu_peer, negotiated_gpu, vector.max_chunk_len());
        let gpu_manifest =
            manifest_announce_for_viewer(&handle, &gpu_peer, vector.manifest.clone())
                .expect("GPU viewer must negotiate successfully");
        assert!(
            gpu_manifest
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
            "GPU handle must advertise GPU acceleration bit"
        );
        assert!(
            !gpu_manifest
                .manifest
                .capabilities
                .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
            "GPU manifests must not leak CPU acceleration bits"
        );
        let cpu_caps = BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD);
        seed_viewer_negotiation(&handle, &cpu_peer, cpu_caps, vector.max_chunk_len());
        let err = manifest_announce_for_viewer(&handle, &cpu_peer, vector.manifest.clone())
            .expect_err("GPU handle must reject CPU-only viewers");
        assert!(matches!(
            err,
            StreamingProcessError::ManifestAccelerationNotNegotiated { .. }
        ));
        manifest_announce_for_viewer(&handle, &gpu_peer, vector.manifest.clone())
            .expect("GPU viewer must continue to receive manifests after CPU rejection");
    }
    #[test]
    fn bundled_telemetry_invariants_hold() {
        let (config, _segment, _frames, telemetry) = bundled_segment(2, 4);
        let stats = &telemetry.stats;
        assert_eq!(
            stats.bundle_width, config.bundle_width,
            "bundle width must match config"
        );
        assert_eq!(stats.blocks_encoded, 2, "two frames encoded");
        assert!(
            stats.flush_end_of_block >= stats.blocks_encoded,
            "every block must flush at end of block"
        );
        assert!(
            telemetry.bundles.len() as u64 >= stats.blocks_encoded,
            "bundle stream must contain at least one record per block"
        );
        assert!(
            !telemetry.tokens.is_empty(),
            "bundled token stream must not be empty"
        );
        let tables = load_bundle_tables_from_toml(repo_rans_tables_path())
            .expect("load bundle tables from fixture");
        assert_eq!(
            telemetry.tables_checksum,
            tables.checksum(),
            "telemetry checksum must match fixture tables"
        );
    }
}
