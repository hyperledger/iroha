//! DA-4 regression: Torii must enforce the configured retention profile even
//! when callers submit stale values. The manifest fetched from Torii should
//! always expose the canonical policy, not the caller intent.
use eyre::{Result, eyre};
use hex::encode as hex_encode;
use integration_tests::sandbox::start_network_async_or_skip;
use iroha_config::parameters::actual::DaReplicationPolicy;
use iroha_crypto::Signature;
use iroha_data_model::{
    da::{
        ingest::{DaIngestReceipt, DaIngestRequest, DaIngestRequestIntentV1, DaPinScopeV1},
        manifest::{ChunkCommitment, ChunkRole, DaManifestV1},
        types::{
            BlobClass, BlobCodec, BlobDigest, Compression, DaRentPolicyV1, DaRentQuote,
            ErasureProfile, ExtraMetadata, GovernanceTag, RetentionPolicy, StorageTicketId,
        },
    },
    parameter::system::SumeragiNposParameters,
    sorafs::pin_registry::StorageClass,
    taikai::TaikaiAvailabilityClass,
};
use iroha_model_base::topology::LaneId;
use iroha_test_network::{Network, NetworkBuilder};
use iroha_test_samples::ALICE_KEYPAIR;
use iroha_torii::{
    HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP_MS, Method, Uri,
    canonical_network_request_signature_message, signature_header_value,
};
use norito::{
    json::{self, Value},
    to_bytes,
};
use reqwest::{Client, StatusCode};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::tempdir;
use toml::value::{Table, Value as TomlValue};
const TEST_NAME: &str = "da_replication_policy_is_enforced";
#[tokio::test]
async fn da_replication_policy_is_enforced() -> Result<()> {
    let manifest_dir = tempdir()?;
    let replay_dir = tempdir()?;
    let default_policy = PolicyNumbers {
        hot_retention_secs: 900,
        cold_retention_secs: 3600,
        required_replicas: 3,
        storage_class: "warm",
        governance_tag: "da.test.default",
    };
    let override_policy = PolicyNumbers {
        hot_retention_secs: 1800,
        cold_retention_secs: 7200,
        required_replicas: 5,
        storage_class: "hot",
        governance_tag: "da.test.taikai",
    };
    let stake_amount = SumeragiNposParameters::default().min_self_bond().clone();
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_npos_genesis_bootstrap(stake_amount)
        .with_config_layer(|layer| {
            configure_da_ingest_layer(
                layer,
                manifest_dir.path(),
                replay_dir.path(),
                &default_policy,
                &override_policy,
            );
        });
    let Some(network) = start_network_async_or_skip(builder, TEST_NAME).await? else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let caller_policy = RetentionPolicy {
        hot_retention_secs: 60,
        cold_retention_secs: 120,
        required_replicas: 1,
        storage_class: StorageClass::Cold,
        governance_tag: GovernanceTag::new("da.intent.client"),
    };
    let http = Client::new();
    let enforced_policy = retention_from_numbers(&override_policy);
    let outcome = ingest_and_fetch_manifest(&network, &http, caller_policy).await?;
    assert!(
        outcome.response.get("sampling_plan").is_none(),
        "manifest retrieval must not synthesize a caller-selectable sampling plan"
    );
    assert_override_applied(&outcome.manifest, &override_policy);
    assert_rent_quote_consistency(&outcome);
    assert_rent_quote_matches_policy(&outcome, &enforced_policy);
    network.shutdown().await;
    Ok(())
}
fn build_da_request(network: &Network, retention_policy: RetentionPolicy) -> DaIngestRequest {
    let payload = b"da retention regression vector payload".to_vec();
    let client_blob_id = BlobDigest::from_hash(blake3::hash(&payload));
    DaIngestRequestIntentV1 {
        network_id: *network.client().client().network_id(),
        owner: network.client().client().account().clone(),
        client_blob_id,
        lane_id: LaneId::SINGLE,
        epoch: 7,
        sequence: 0,
        blob_class: BlobClass::NexusLaneSidecar,
        codec: BlobCodec("video/cmaf".into()),
        erasure_profile: ErasureProfile::default(),
        retention_policy,
        chunk_size: 1024,
        total_size: payload.len() as u64,
        payload_hash: BlobDigest::from_hash(blake3::hash(&payload)),
        compression: Compression::Identity,
        norito_manifest: None,
        payload,
        metadata: ExtraMetadata::default(),
    }
    .try_sign(&ALICE_KEYPAIR)
    .expect("sign canonical DA ingest request")
}
struct ManifestFetchOutcome {
    receipt: DaIngestReceipt,
    manifest: DaManifestV1,
    response: Value,
}

#[derive(Debug, norito::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct DaIngestHttpResponse {
    status: String,
    duplicate: bool,
    receipt: Option<DaIngestReceipt>,
    pin_scope: Option<DaPinScopeV1>,
}

async fn ingest_and_fetch_manifest(
    network: &Network,
    http: &Client,
    caller_policy: RetentionPolicy,
) -> Result<ManifestFetchOutcome> {
    const MAX_INGEST_POSTS: usize = 2;

    let ingest_request = build_da_request(network, caller_policy);
    let ingest_url = network
        .client()
        .client()
        .endpoint()
        .join("/v1/da/ingest")
        .expect("compose DA ingest URL");
    let mut ingest_posts = 1_usize;
    let first = post_da_ingest_once(network, http, &ingest_url, &ingest_request, "prepare").await?;
    assert_eq!(
        first.status, "pending_pin_authorization",
        "the prepare submission must wait for an exact producer-approved pin scope"
    );
    assert!(!first.duplicate, "the prepare submission must be fresh");
    let first_receipt = first
        .receipt
        .clone()
        .expect("the prepare response must include the durable receipt");
    let pin_scope = first
        .pin_scope
        .clone()
        .expect("the pending prepare response must include its exact pin scope");

    let mut authorized_request = ingest_request.clone();
    authorized_request
        .try_add_pin_scope_signature(&pin_scope, &ALICE_KEYPAIR)
        .expect("sign the exact post-ingest pin scope");
    assert!(
        ingest_posts < MAX_INGEST_POSTS,
        "pin-scope finalization must have exactly one bounded retry available"
    );
    ingest_posts += 1;
    let finalized =
        post_da_ingest_once(network, http, &ingest_url, &authorized_request, "finalize").await?;
    assert_eq!(
        finalized.status, "accepted",
        "one producer-authorized retry must finalize the DA pin"
    );
    assert!(
        finalized.duplicate,
        "the bounded finalize retry must reuse the prepared durable artifacts"
    );
    assert_eq!(
        finalized.pin_scope.as_ref(),
        Some(&pin_scope),
        "the finalize response must retain the exact producer-approved scope"
    );
    let receipt = finalized
        .receipt
        .expect("the finalized response must include the durable receipt");
    assert_eq!(
        receipt, first_receipt,
        "the bounded finalize retry must not replace the prepared receipt"
    );
    assert_eq!(
        ingest_posts, MAX_INGEST_POSTS,
        "DA pin authorization is bounded to one prepare plus one retry"
    );
    let manifest_ticket_hex = hex_encode(receipt.storage_ticket.as_bytes());
    let manifest_url = network
        .client()
        .client()
        .endpoint()
        .join(&format!("/v1/da/manifests/{manifest_ticket_hex}"))
        .expect("compose manifest fetch URL");
    let manifest_response = http
        .get(manifest_url)
        .header("Accept", "application/json")
        .send()
        .await?;
    assert!(
        manifest_response.status() == StatusCode::OK,
        "manifest fetch failed: {}",
        manifest_response.status()
    );
    let manifest_value: Value =
        json::from_slice(&manifest_response.bytes().await?).expect("manifest response JSON");
    let manifest_obj = manifest_value
        .get("manifest")
        .cloned()
        .unwrap_or_else(|| manifest_value.clone());
    let manifest: DaManifestV1 = json::from_value(manifest_obj)?;
    Ok(ManifestFetchOutcome {
        receipt,
        manifest,
        response: manifest_value,
    })
}

async fn post_da_ingest_once(
    network: &Network,
    http: &Client,
    ingest_url: &reqwest::Url,
    request: &DaIngestRequest,
    phase: &str,
) -> Result<DaIngestHttpResponse> {
    static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

    let body = json::to_vec(request)?;
    let timestamp_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let nonce = format!(
        "da-replication-policy-{phase}-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let signing_uri: Uri = match ingest_url.query() {
        Some(query) => format!("{}?{query}", ingest_url.path()).parse()?,
        None => ingest_url.path().parse()?,
    };
    let message = canonical_network_request_signature_message(
        &network.network_id(),
        &Method::POST,
        &signing_uri,
        &body,
        timestamp_ms,
        &nonce,
    )?;
    let signature = Signature::try_new(ALICE_KEYPAIR.private_key(), &message)
        .expect("sign canonical DA ingest HTTP request");
    let response = http
        .post(ingest_url.clone())
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header(HEADER_ACCOUNT, request.owner.to_canonical_hex()?)
        .header(HEADER_SIGNATURE, signature_header_value(&signature)?)
        .header(HEADER_TIMESTAMP_MS, timestamp_ms.to_string())
        .header(HEADER_NONCE, nonce)
        .body(body)
        .send()
        .await?;
    let status = response.status();
    let response_body = response.bytes().await?;
    if status != StatusCode::ACCEPTED && status != StatusCode::OK {
        return Err(eyre!(
            "DA ingest {phase} submission failed with {status}: {}",
            String::from_utf8_lossy(&response_body)
        ));
    }
    Ok(json::from_slice(&response_body)?)
}
fn assert_override_applied(manifest: &DaManifestV1, override_policy: &PolicyNumbers) {
    let enforced = retention_from_numbers(override_policy);
    assert_eq!(
        manifest.retention_policy.hot_retention_secs, enforced.hot_retention_secs,
        "hot retention must match the configured override"
    );
    assert_eq!(
        manifest.retention_policy.cold_retention_secs, enforced.cold_retention_secs,
        "cold retention must match the configured override"
    );
    assert_eq!(
        manifest.retention_policy.required_replicas, enforced.required_replicas,
        "required replicas must match the configured override"
    );
    assert_eq!(
        manifest.retention_policy.storage_class, enforced.storage_class,
        "storage class must match the configured override"
    );
    assert_eq!(
        manifest.retention_policy.governance_tag.0, enforced.governance_tag.0,
        "governance tag must match the configured override"
    );
}
fn configure_da_ingest_layer<'a>(
    layer: &'a mut iroha_config_base::toml::Writer<'a>,
    manifest_dir: &Path,
    replay_dir: &Path,
    default_policy: &PolicyNumbers,
    override_policy: &PolicyNumbers,
) {
    layer
        .write(
            ["torii", "da_ingest", "manifest_store_dir"],
            manifest_dir.display().to_string(),
        )
        .write(
            ["torii", "da_ingest", "replay_cache_store_dir"],
            replay_dir.display().to_string(),
        )
        .write(
            [
                "torii",
                "da_ingest",
                "replication_policy",
                "default_retention",
            ],
            retention_table(default_policy),
        )
        .write(
            ["torii", "da_ingest", "replication_policy", "overrides"],
            TomlValue::Array(vec![override_entry("nexus_lane_sidecar", override_policy)]),
        )
        .write(
            [
                "torii",
                "da_ingest",
                "replication_policy",
                "taikai_availability",
            ],
            taikai_availability_overrides(),
        );
}
fn retention_table(policy: &PolicyNumbers) -> TomlValue {
    let mut table = Table::new();
    table.insert(
        "hot_retention_secs".into(),
        TomlValue::Integer(
            i64::try_from(policy.hot_retention_secs).expect("hot retention fits in i64"),
        ),
    );
    table.insert(
        "cold_retention_secs".into(),
        TomlValue::Integer(
            i64::try_from(policy.cold_retention_secs).expect("cold retention fits in i64"),
        ),
    );
    table.insert(
        "required_replicas".into(),
        TomlValue::Integer(policy.required_replicas.into()),
    );
    table.insert(
        "storage_class".into(),
        TomlValue::String(policy.storage_class.into()),
    );
    table.insert(
        "governance_tag".into(),
        TomlValue::String(policy.governance_tag.into()),
    );
    TomlValue::Table(table)
}
fn override_entry(class_label: &str, policy: &PolicyNumbers) -> TomlValue {
    let mut entry = Table::new();
    entry.insert("class".into(), TomlValue::String(class_label.into()));
    entry.insert("retention".into(), retention_table(policy));
    TomlValue::Table(entry)
}
fn taikai_availability_overrides() -> TomlValue {
    let entries = iroha_config::parameters::defaults::torii::taikai_availability_overrides()
        .into_iter()
        .map(|(availability_class, policy)| {
            let mut entry = Table::new();
            entry.insert(
                "availability_class".into(),
                TomlValue::String(
                    match availability_class {
                        TaikaiAvailabilityClass::Hot => "hot",
                        TaikaiAvailabilityClass::Warm => "warm",
                        TaikaiAvailabilityClass::Cold => "cold",
                    }
                    .into(),
                ),
            );
            entry.insert("retention".into(), retention_table_from_policy(&policy));
            TomlValue::Table(entry)
        })
        .collect();
    TomlValue::Array(entries)
}
fn retention_table_from_policy(policy: &RetentionPolicy) -> TomlValue {
    let mut table = Table::new();
    table.insert(
        "hot_retention_secs".into(),
        TomlValue::Integer(
            i64::try_from(policy.hot_retention_secs).expect("hot retention fits in i64"),
        ),
    );
    table.insert(
        "cold_retention_secs".into(),
        TomlValue::Integer(
            i64::try_from(policy.cold_retention_secs).expect("cold retention fits in i64"),
        ),
    );
    table.insert(
        "required_replicas".into(),
        TomlValue::Integer(policy.required_replicas.into()),
    );
    table.insert(
        "storage_class".into(),
        TomlValue::String(
            match policy.storage_class {
                StorageClass::Hot => "hot",
                StorageClass::Cold => "cold",
                StorageClass::Warm => "warm",
            }
            .into(),
        ),
    );
    table.insert(
        "governance_tag".into(),
        TomlValue::String(policy.governance_tag.0.clone()),
    );
    TomlValue::Table(table)
}
fn retention_from_numbers(policy: &PolicyNumbers) -> RetentionPolicy {
    RetentionPolicy {
        hot_retention_secs: policy.hot_retention_secs,
        cold_retention_secs: policy.cold_retention_secs,
        required_replicas: policy.required_replicas,
        storage_class: match policy.storage_class {
            "hot" => StorageClass::Hot,
            "cold" => StorageClass::Cold,
            _ => StorageClass::Warm,
        },
        governance_tag: GovernanceTag::new(policy.governance_tag),
    }
}
#[derive(Clone, Copy)]
struct PolicyNumbers {
    hot_retention_secs: u64,
    cold_retention_secs: u64,
    required_replicas: u16,
    storage_class: &'static str,
    governance_tag: &'static str,
}
#[test]
fn retention_from_numbers_maps_fields() {
    let input = PolicyNumbers {
        hot_retention_secs: 1,
        cold_retention_secs: 2,
        required_replicas: 3,
        storage_class: "warm",
        governance_tag: "demo",
    };
    let policy = retention_from_numbers(&input);
    assert_eq!(policy.hot_retention_secs, 1);
    assert_eq!(policy.cold_retention_secs, 2);
    assert_eq!(policy.required_replicas, 3);
    assert_eq!(policy.storage_class, StorageClass::Warm);
    assert_eq!(policy.governance_tag.0, "demo");
}
#[test]
fn caller_policy_mismatch_is_detected() {
    let baseline = retention_from_numbers(&PolicyNumbers {
        hot_retention_secs: 10,
        cold_retention_secs: 20,
        required_replicas: 4,
        storage_class: "hot",
        governance_tag: "da.baseline",
    });
    let mut overrides = BTreeMap::new();
    overrides.insert(BlobClass::GovernanceArtifact, baseline.clone());
    let policy = DaReplicationPolicy::new(baseline.clone(), overrides, BTreeMap::new());
    let caller = RetentionPolicy {
        hot_retention_secs: 5,
        cold_retention_secs: 5,
        required_replicas: 1,
        storage_class: StorageClass::Cold,
        governance_tag: GovernanceTag::new("stale"),
    };
    let (enforced, mismatch) = policy.enforce(BlobClass::GovernanceArtifact, None, &caller);
    assert!(mismatch);
    assert_eq!(enforced, &baseline);
}
#[test]
fn policy_override_matches_expected_defaults() {
    let policy = DaReplicationPolicy::default();
    let stale_policy = RetentionPolicy {
        hot_retention_secs: 42,
        cold_retention_secs: 120,
        required_replicas: 1,
        storage_class: StorageClass::Cold,
        governance_tag: GovernanceTag::new("da.intent.stale"),
    };
    let (enforced, mismatch) = policy.enforce(BlobClass::TaikaiSegment, None, &stale_policy);
    assert!(
        mismatch,
        "callers supplying stale policies must trigger overrides"
    );
    assert_eq!(enforced.hot_retention_secs, 86_400);
    assert_eq!(enforced.cold_retention_secs, 1_209_600);
    assert_eq!(enforced.required_replicas, 5);
    assert_eq!(enforced.storage_class, StorageClass::Hot);
    assert_eq!(enforced.governance_tag.0, "da.taikai.live");
    let default_template = policy
        .retention_for(BlobClass::NexusLaneSidecar, None)
        .clone();
    let (default_result, default_mismatch) =
        policy.enforce(BlobClass::NexusLaneSidecar, None, &default_template);
    assert!(
        !default_mismatch,
        "caller policies that match the default must be accepted as-is"
    );
    assert_eq!(default_result, &default_template);
}
#[test]
fn manifest_encoding_is_stable_after_enforcement() {
    let policy = DaReplicationPolicy::default();
    let default_policy = RetentionPolicy::default();
    let caller_policy = RetentionPolicy {
        hot_retention_secs: 1,
        cold_retention_secs: 2,
        required_replicas: 1,
        storage_class: StorageClass::Cold,
        governance_tag: GovernanceTag::new("da.intent.client"),
    };
    let manifest_a =
        manifest_bytes_after_enforcement(&policy, BlobClass::TaikaiSegment, &default_policy);
    let manifest_b =
        manifest_bytes_after_enforcement(&policy, BlobClass::TaikaiSegment, &caller_policy);
    assert_eq!(
        manifest_a, manifest_b,
        "manifest encoding must remain stable once the policy override is applied"
    );
}
fn manifest_bytes_after_enforcement(
    policy: &DaReplicationPolicy,
    class: BlobClass,
    requested: &RetentionPolicy,
) -> Vec<u8> {
    let (enforced, _) = policy.enforce(class, None, requested);
    let manifest = sample_manifest(enforced.clone(), class);
    to_bytes(&manifest).expect("encode manifest")
}
fn sample_manifest(retention_policy: RetentionPolicy, blob_class: BlobClass) -> DaManifestV1 {
    DaManifestV1 {
        version: DaManifestV1::VERSION,
        client_blob_id: BlobDigest::new([0xAA; 32]),
        lane_id: LaneId::from(9_u32),
        epoch: 12,
        blob_class,
        codec: BlobCodec("raw".into()),
        blob_hash: BlobDigest::new([0xBB; 32]),
        chunk_root: BlobDigest::new([0xCC; 32]),
        storage_ticket: StorageTicketId::new([0xDD; 32]),
        total_size: 65_536,
        chunk_size: 1_024,
        total_stripes: 1,
        shards_per_stripe: u32::from(
            ErasureProfile::default().data_shards + ErasureProfile::default().parity_shards,
        ),
        erasure_profile: ErasureProfile::default(),
        retention_policy,
        rent_quote: DaRentQuote::default(),
        chunks: vec![ChunkCommitment::new_with_role(
            0,
            0,
            1_024,
            BlobDigest::new([0xEE; 32]),
            ChunkRole::Data,
            0,
        )],
        ipa_commitment: BlobDigest::new([0xCC; 32]),
        metadata: ExtraMetadata::default(),
        issued_at_unix: 1_700_000_000,
    }
}
fn assert_rent_quote_consistency(outcome: &ManifestFetchOutcome) {
    assert_eq!(
        outcome.receipt.rent_quote, outcome.manifest.rent_quote,
        "rent quote must match between the ingestion receipt and canonical manifest"
    );
}
fn assert_rent_quote_matches_policy(
    outcome: &ManifestFetchOutcome,
    enforced_retention: &RetentionPolicy,
) {
    let expected = expected_rent_quote(outcome.manifest.total_size, enforced_retention);
    assert_eq!(
        outcome.manifest.rent_quote, expected,
        "rent quote must be derived from the configured rent policy"
    );
}
fn expected_rent_quote(total_size: u64, retention: &RetentionPolicy) -> DaRentQuote {
    let policy = DaRentPolicyV1::default();
    let (rent_gib, rent_months) = rent_usage(total_size, retention);
    policy
        .quote(rent_gib, rent_months)
        .expect("default rent policy should quote incoming submissions")
}
fn rent_usage(total_size: u64, retention: &RetentionPolicy) -> (u64, u32) {
    let adjusted_size = total_size.max(1);
    let gib = ceil_div_u64(adjusted_size, BYTES_PER_GIB).max(1);
    let retention_secs = retention
        .hot_retention_secs
        .max(retention.cold_retention_secs)
        .max(1);
    let months = ceil_div_u64(retention_secs, SECS_PER_MONTH).max(1);
    let months_u32 = u32::try_from(months).unwrap_or(u32::MAX);
    (gib, months_u32)
}
fn ceil_div_u64(value: u64, divisor: u64) -> u64 {
    if divisor == 0 || value == 0 {
        return 0;
    }
    value.div_ceil(divisor)
}
const BYTES_PER_GIB: u64 = 1 << 30;
const SECS_PER_MONTH: u64 = 30 * 24 * 60 * 60;
