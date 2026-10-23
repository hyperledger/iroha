//! Runtime upgrade app API handlers.
use crate::{
    NoritoJson,
    json_macros::{JsonDeserialize, JsonSerialize},
};
use axum::{extract::Path, response::IntoResponse};
#[cfg(feature = "app_api")]
use iroha_core::query::index_status::QueryIndexStatus;
use iroha_core::state::StateReadOnly;
use iroha_core::state::WorldReadOnly;
use iroha_core::{
    query::projection_checkpoint::{
        QUERY_PROJECTION_DA_BLOB_CLASS_CUSTOM_ID, QUERY_PROJECTION_DA_CODEC,
        QUERY_PROJECTION_DA_COMPRESSION, QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
        QUERY_PROJECTION_SCHEMA_VERSION, QueryProjectionCheckpoint, QueryProjectionResourceKind,
        query_projection_default_partition_for_account, query_projection_partition_for_key,
    },
    query::projection_rowset::{
        QueryProjectionAccountAssetRow, QueryProjectionAccountAssetsShardRowSet,
        QueryProjectionAccountRow, QueryProjectionAccountsShardRowSet,
        QueryProjectionAssetDefinitionRow, QueryProjectionAssetDefinitionsShardRowSet,
        QueryProjectionAssetHolderRow, QueryProjectionAssetHoldersShardRowSet,
        QueryProjectionDomainRow, QueryProjectionDomainsShardRowSet, QueryProjectionMetadataEntry,
        QueryProjectionShardRowSet,
    },
    query::projection_shard::{
        QUERY_PROJECTION_METADATA_ASSET_KEY, QUERY_PROJECTION_METADATA_BLOCK_HASH_KEY,
        QUERY_PROJECTION_METADATA_EMITTED_AT_KEY, QUERY_PROJECTION_METADATA_HEIGHT_KEY,
        QUERY_PROJECTION_METADATA_LOCATOR_KEY, QUERY_PROJECTION_METADATA_PARTITION_KEY,
        QUERY_PROJECTION_METADATA_RESOURCE_KEY, QUERY_PROJECTION_METADATA_ROW_COUNT_KEY,
        QUERY_PROJECTION_METADATA_ROWSET_CODEC_KEY, QUERY_PROJECTION_METADATA_ROWSET_HASH_KEY,
        QUERY_PROJECTION_SHARD_ARCHIVE_VERSION, QUERY_PROJECTION_SHARD_ROWSET_CODEC,
        QueryProjectionShardArchive,
    },
};
#[cfg(all(test, feature = "app_api"))]
use iroha_crypto::Algorithm;
use iroha_data_model::{
    HasMetadata, Identifiable,
    account::curve::CurveId,
    da::types::{BlobClass, Compression},
    transaction::SignedTransaction,
};
use iroha_logger::warn;
use mv::storage::StorageReadOnly;
use norito::derive::{NoritoDeserialize, NoritoSerialize};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
const CURVE_REGISTRY_VERSION: u32 = 1;
#[cfg(feature = "app_api")]
const QUERY_PROJECTION_SHARD_CATALOG_VERSION: u16 = 1;
#[cfg(feature = "app_api")]
const QUERY_PROJECTION_SHARD_CATALOG_DEFAULT_LIMIT: u32 = 1024;
#[cfg(feature = "app_api")]
const QUERY_PROJECTION_SHARD_CATALOG_MAX_LIMIT: u32 = 8192;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeCapabilitiesResponse")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Node capabilities advert (subset)
pub struct NodeCapabilitiesResponse {
    /// ABI version accepted by this node.
    pub abi_version: u16,
    /// Data model compatibility version for SDK handshakes.
    pub data_model_version: u32,
    /// Norito schema hash for `SignedTransaction` submit payloads.
    pub signed_transaction_schema_hash_hex: String,
    /// Implementation capabilities, local generation defaults and committed signing policy
    pub crypto: NodeCryptoCapabilities,
    /// Query DSL and projection-index capabilities.
    pub query: NodeQueryCapabilities,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeCryptoCapabilities")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Crypto capability advert (currently SM-focused).
pub struct NodeCryptoCapabilities {
    /// SM cryptography capability manifest.
    pub sm: NodeSmCapabilities,
    /// Curve capability advert anchored to the registry.
    pub curves: NodeCurveCapabilities,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeSmCapabilities")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// SM capability manifest exported by the node.
pub struct NodeSmCapabilities {
    /// Whether this node contains the SM2 verification implementation; not chain admission.
    pub enabled: bool,
    /// Node-local generation hash preference; it does not select transaction hashing or admission.
    pub default_hash: String,
    /// Exact committed ordinary signing policy, in canonical algorithm tag order.
    pub allowed_signing: Vec<String>,
    /// Node-local SM2 generation DistID; the omitted IVM operand uses the fixed protocol constant.
    pub sm2_distid_default: String,
    /// Whether the OpenSSL/Tongsuo preview backend is toggled on.
    pub openssl_preview: bool,
    /// Acceleration advert (scalar/NEON policy).
    pub acceleration: NodeSmAcceleration,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeSmAcceleration")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Hardware/software acceleration advert for SM algorithms.
pub struct NodeSmAcceleration {
    /// Scalar implementation availability (always true).
    pub scalar: bool,
    /// NEON accelerated SM3 hashing available.
    pub neon_sm3: bool,
    /// NEON accelerated SM4 block operations available.
    pub neon_sm4: bool,
    /// Dispatch policy string (`auto`, `force-enable`, `force-disable`, `scalar-only`).
    pub policy: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeCurveCapabilities")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Curve capability advert emitted by `/v1/node/capabilities`.
pub struct NodeCurveCapabilities {
    /// Registry version referenced by this advert.
    pub registry_version: u32,
    /// Allowed curve identifiers (as published in the registry).
    pub allowed_curve_ids: Vec<u8>,
    /// Bitmap of allowed curve identifiers (bit `i` ⇒ curve id `i`).
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub allowed_curve_bitmap: Vec<u64>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeQueryCapabilities")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Query capability advert emitted by `/v1/node/capabilities`.
pub struct NodeQueryCapabilities {
    /// Aggregate query support exposed today.
    pub aggregate: NodeAggregateQueryCapabilities,
    /// Reserved DA-backed projection checkpoint contract.
    pub projection: NodeProjectionCapabilities,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeAggregateQueryCapabilities")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Aggregate DSL capability advert emitted by `/v1/node/capabilities`.
pub struct NodeAggregateQueryCapabilities {
    /// Whether aggregate DSL v1 is available.
    pub v1: bool,
    /// Whether the current aggregate implementation is exact rather than approximate.
    pub exact_results: bool,
    /// Collections (`specs/torii/collection_queries.md`) whose reads accept `aggregate`.
    pub supported_resources: Vec<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionCapabilities")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Reserved DA query projection capability advert.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Projection contracts and enabled worker features are independent advertised capabilities."
)]
pub struct NodeProjectionCapabilities {
    /// Whether the checkpoint descriptor contract is defined and stable.
    pub checkpoint_contract_v1: bool,
    /// Whether the DA-backed cold projection worker is enabled.
    pub da_v1_enabled: bool,
    /// Whether the node can enumerate the canonical live shard set directly.
    pub shard_catalog_v1: bool,
    /// Whether the node can export canonical projection shard archives directly.
    pub archive_export_v1: bool,
    /// Version of the immutable shard archive payload carried inside DA blobs.
    pub archive_version: u16,
    /// Schema version of the reserved checkpoint shard payload.
    pub schema_version: u32,
    /// Reserved `BlobClass::Custom(..)` identifier for query projection shards.
    pub blob_class_custom_id: u16,
    /// Reserved codec label for query projection shards.
    pub codec: String,
    /// Codec label for the logical rowset bytes inside the shard archive.
    pub rowset_codec: String,
    /// Compression used for reserved query projection shards.
    pub compression: String,
    /// Default partition count for account-scoped projection shards.
    pub default_partition_count: u32,
    /// Canonical public metadata keys expected on DA payloads for query projection shards.
    pub metadata_keys: Vec<String>,
    /// Resource families the shard export contract currently supports.
    pub export_supported_resources: Vec<String>,
    /// Latest indexed height covered by a persisted projection checkpoint, if any.
    pub latest_checkpoint_indexed_height: Option<u64>,
    /// Latest indexed block hash covered by a persisted projection checkpoint, if any.
    pub latest_checkpoint_block_hash_hex: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionCheckpointResponse")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Response for the latest persisted query projection checkpoint descriptor.
pub struct NodeProjectionCheckpointResponse {
    /// Descriptor payload version.
    pub version: u16,
    /// Projection shard schema version covered by this checkpoint.
    pub schema_version: u32,
    /// Semantic blob class label used by the referenced shard payloads.
    pub blob_class: String,
    /// Custom blob class id when `blob_class` is `custom`.
    pub blob_class_custom_id: Option<u16>,
    /// Codec label used by the referenced shard payloads.
    pub codec: String,
    /// Compression used by the referenced shard payloads.
    pub compression: String,
    /// Latest block height covered by this checkpoint.
    pub indexed_height: u64,
    /// Latest block hash covered by this checkpoint, hex-encoded when present.
    pub indexed_block_hash_hex: Option<String>,
    /// Unix timestamp when the checkpoint descriptor was emitted.
    pub emitted_at_unix: u64,
    /// Immutable shard references that make up this checkpoint.
    pub shards: Vec<NodeProjectionCheckpointShardRef>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionCheckpointShardRef")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// JSON/Norito-friendly representation of one shard reference inside a checkpoint.
pub struct NodeProjectionCheckpointShardRef {
    /// Stable resource family identifier.
    pub resource: String,
    /// Stable partition identifier inside the resource family.
    pub partition_id: u32,
    /// Optional asset definition discriminator for holder shards.
    pub asset_definition_id: Option<String>,
    /// Manifest digest, lowercase hex.
    pub manifest_digest_hex: String,
    /// Storage ticket id, lowercase hex.
    pub storage_ticket_hex: String,
    /// Compressed blob hash, lowercase hex.
    pub blob_hash_hex: String,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionShardCatalogResponse")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Response for the live projection shard catalog of one resource family.
#[cfg(feature = "app_api")]
pub struct NodeProjectionShardCatalogResponse {
    /// Catalog payload version.
    pub version: u16,
    /// Stable resource family identifier.
    pub resource: String,
    /// Projection shard schema version covered by the listed entries.
    pub schema_version: u32,
    /// Latest block height covered by this live catalog snapshot.
    pub indexed_height: u64,
    /// Latest block hash covered by this live catalog snapshot, hex-encoded when present.
    pub indexed_block_hash_hex: Option<String>,
    /// Canonical partition count for account-scoped shard resources.
    pub default_partition_count: u32,
    /// Offset applied to the stable ordered entry set.
    pub offset: u64,
    /// Maximum number of entries returned in this page.
    pub limit: u32,
    /// Total number of matching non-empty shard entries.
    pub total_entries: u64,
    /// Offset to request the next page, when more entries remain.
    pub next_offset: Option<u64>,
    /// Stable ordered non-empty shard entries for the selected resource family.
    pub entries: Vec<NodeProjectionShardCatalogEntry>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionShardCatalogEntry")]
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// One stable shard entry inside the live projection catalog.
#[cfg(feature = "app_api")]
pub struct NodeProjectionShardCatalogEntry {
    /// Stable partition identifier inside the resource family.
    pub partition_id: u32,
    /// Exact logical row count for the shard.
    pub row_count: u64,
    /// Optional asset-definition discriminator for holder shards.
    pub asset_definition_id: Option<String>,
    /// Optional display alias for `asset_definition_id`.
    pub asset_alias: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionShardExportQuery")]
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, JsonDeserialize, NoritoDeserialize)]
/// Query parameters for exporting one canonical query projection shard archive.
pub struct NodeProjectionShardExportQuery {
    /// Canonical or alias asset-definition selector required for `asset_holders`.
    pub asset_definition_id: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::NodeProjectionShardCatalogQuery")]
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, JsonDeserialize, NoritoDeserialize)]
/// Query parameters for enumerating the live projection shard catalog of one resource family.
pub struct NodeProjectionShardCatalogQuery {
    /// Canonical or alias asset-definition selector used to narrow `asset_holders` entries.
    pub asset_definition_id: Option<String>,
    /// Stable entry offset within the canonical ordered catalog.
    pub offset: Option<u64>,
    /// Maximum number of entries to return.
    pub limit: Option<u32>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::RuntimeMetricsResponse")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// JSON summary of runtime-related metrics of interest
pub struct RuntimeMetricsResponse {
    /// ABI version accepted by the runtime.
    pub abi_version: u16,
    /// Upgrade lifecycle event counters
    pub upgrade_events_total: UpgradeEventsCounters,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::UpgradeEventsCounters")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
pub struct UpgradeEventsCounters {
    pub proposed: u64,
    pub activated: u64,
    pub canceled: u64,
}
#[derive(
    Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii::runtime::RuntimeAbiActiveResponse")]
pub struct RuntimeAbiActiveResponse {
    pub abi_version: u16,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::RuntimeAbiHashResponse")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
/// Response with the node's canonical ABI hash for the active policy.
pub struct RuntimeAbiHashResponse {
    /// Policy label (first release: always "V1").
    pub policy: String,
    /// 32-byte lowercase hex digest of the ABI surface.
    pub abi_hash_hex: String,
}
// Tests omitted to keep feature-gating friction low; behavior is trivial (hash compute) and
// exercised by doc-sync tests in the ivm crate.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::RuntimeUpgradeListItem")]
#[derive(Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize)]
pub struct RuntimeUpgradeListItem {
    pub id_hex: String,
    pub record: iroha_data_model::runtime::RuntimeUpgradeRecord,
}
#[derive(
    Debug, JsonSerialize, JsonDeserialize, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii::runtime::RuntimeUpgradesListResponse")]
pub struct RuntimeUpgradesListResponse {
    pub items: Vec<RuntimeUpgradeListItem>,
}
/// GET /v1/runtime/abi/active
pub async fn handle_runtime_abi_active(
    state: Arc<iroha_core::state::State>,
) -> Result<RuntimeAbiActiveResponse, crate::Error> {
    let world = state.world_view();
    Ok(RuntimeAbiActiveResponse {
        abi_version: world.abi_version(),
    })
}
/// GET /v1/node/capabilities — advertise the fixed runtime ABI version and defaults
pub async fn handle_node_capabilities(
    state: Arc<iroha_core::state::State>,
) -> Result<NodeCapabilitiesResponse, crate::Error> {
    let world = state.world_view();
    let crypto_cfg = state.crypto();
    let policy = world
        .transaction_admission_parameters()
        .require_crypto_policy()
        .map_err(|_| {
            crate::Error::TransactionAdmissionDeferred(
                ivm::error::ExecutionDeferral::CryptoAdmissionPolicyUnavailable.into(),
            )
        })?;
    let allowed_signing: Vec<String> = policy
        .allowed_algorithms()
        .iter()
        .map(|algo| algo.as_static_str().to_string())
        .collect();
    let latest_projection_checkpoint = state.query_projection_checkpoint_snapshot();
    let curve_caps = summarize_curve_capabilities(policy);
    #[cfg(feature = "sm")]
    let (neon_sm3, neon_sm4, policy_string) = {
        let advert = iroha_crypto::sm::acceleration_advert();
        (
            advert.neon_sm3,
            advert.neon_sm4,
            advert.as_policy_str().to_string(),
        )
    };
    #[cfg(not(feature = "sm"))]
    let (neon_sm3, neon_sm4, policy_string) = (false, false, "scalar-only".to_string());
    #[cfg(feature = "app_api")]
    let aggregate_supported_resources = crate::collections::aggregate_collections()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    #[cfg(not(feature = "app_api"))]
    let aggregate_supported_resources = Vec::new();
    #[cfg(feature = "app_api")]
    let projection_export_supported_resources = crate::collections::PROJECTION_EXPORT_COLLECTIONS
        .map(str::to_owned)
        .to_vec();
    #[cfg(not(feature = "app_api"))]
    let projection_export_supported_resources = Vec::new();
    Ok(NodeCapabilitiesResponse {
        abi_version: world.abi_version(),
        data_model_version: iroha_data_model::DATA_MODEL_VERSION,
        signed_transaction_schema_hash_hex: signed_transaction_schema_hash_hex(),
        crypto: NodeCryptoCapabilities {
            sm: NodeSmCapabilities {
                enabled: iroha_crypto::Algorithm::Sm2
                    .require_implementation(iroha_crypto::CryptoOperation::VerifySignature)
                    .is_ok(),
                default_hash: crypto_cfg.default_hash.clone(),
                allowed_signing,
                sm2_distid_default: crypto_cfg.sm2_distid_default.clone(),
                openssl_preview: crypto_cfg.enable_sm_openssl_preview,
                acceleration: NodeSmAcceleration {
                    scalar: true,
                    neon_sm3,
                    neon_sm4,
                    policy: policy_string,
                },
            },
            curves: curve_caps,
        },
        query: NodeQueryCapabilities {
            aggregate: NodeAggregateQueryCapabilities {
                v1: true,
                exact_results: true,
                supported_resources: aggregate_supported_resources,
            },
            projection: NodeProjectionCapabilities {
                checkpoint_contract_v1: true,
                da_v1_enabled: false,
                shard_catalog_v1: cfg!(feature = "app_api"),
                archive_export_v1: cfg!(feature = "app_api"),
                archive_version: QUERY_PROJECTION_SHARD_ARCHIVE_VERSION,
                schema_version: QUERY_PROJECTION_SCHEMA_VERSION,
                blob_class_custom_id: QUERY_PROJECTION_DA_BLOB_CLASS_CUSTOM_ID,
                codec: QUERY_PROJECTION_DA_CODEC.to_string(),
                rowset_codec: QUERY_PROJECTION_SHARD_ROWSET_CODEC.to_string(),
                compression: compression_name(QUERY_PROJECTION_DA_COMPRESSION).to_string(),
                default_partition_count: QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
                metadata_keys: vec![
                    QUERY_PROJECTION_METADATA_LOCATOR_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_RESOURCE_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_PARTITION_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_ASSET_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_HEIGHT_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_BLOCK_HASH_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_ROW_COUNT_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_ROWSET_CODEC_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_ROWSET_HASH_KEY.to_string(),
                    QUERY_PROJECTION_METADATA_EMITTED_AT_KEY.to_string(),
                ],
                export_supported_resources: projection_export_supported_resources,
                latest_checkpoint_indexed_height: latest_projection_checkpoint
                    .as_ref()
                    .map(|checkpoint| checkpoint.indexed_height),
                latest_checkpoint_block_hash_hex: latest_projection_checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.indexed_block_hash)
                    .map(|hash| hex::encode(hash.as_ref())),
            },
        },
    })
}
/// GET /v1/privacy/capabilities — return the canonical committed Exact12 manifest.
pub async fn handle_privacy_capabilities(
    state: Arc<iroha_core::state::State>,
) -> Result<iroha_data_model::privacy::PrivacyExact12CapabilityManifestV1, crate::Error> {
    let snapshot = state
        .view()
        .privacy_capability_snapshot_v1()
        .map_err(|source| crate::Error::AppServiceUnavailable {
            code: "privacy_capability_snapshot_invalid",
            message: source.to_string(),
        })?;
    snapshot.exact12_capability_manifest_v1().map_err(|source| {
        crate::Error::AppServiceUnavailable {
            code: "privacy_exact12_capability_manifest_invalid",
            message: source.to_string(),
        }
    })
}
/// GET /v1/node/query/projection/checkpoint — return the latest persisted checkpoint descriptor.
#[must_use]
pub async fn handle_node_query_projection_checkpoint(
    state: Arc<iroha_core::state::State>,
) -> Option<NodeProjectionCheckpointResponse> {
    state
        .query_projection_checkpoint_snapshot()
        .map(node_projection_checkpoint_response)
}
fn node_projection_checkpoint_response(
    checkpoint: QueryProjectionCheckpoint,
) -> NodeProjectionCheckpointResponse {
    NodeProjectionCheckpointResponse {
        version: checkpoint.version,
        schema_version: checkpoint.schema_version,
        blob_class: blob_class_name(checkpoint.blob_class).to_string(),
        blob_class_custom_id: blob_class_custom_id(checkpoint.blob_class),
        codec: checkpoint.codec.0,
        compression: compression_name(checkpoint.compression).to_string(),
        indexed_height: checkpoint.indexed_height,
        indexed_block_hash_hex: checkpoint
            .indexed_block_hash
            .map(|hash| hex::encode(hash.as_ref())),
        emitted_at_unix: checkpoint.emitted_at_unix,
        shards: checkpoint
            .shards
            .into_iter()
            .map(|shard| NodeProjectionCheckpointShardRef {
                resource: shard.resource.as_stable_str().to_string(),
                partition_id: shard.partition_id,
                asset_definition_id: shard.asset_definition_id,
                manifest_digest_hex: hex::encode(shard.manifest_digest.as_bytes()),
                storage_ticket_hex: hex::encode(shard.storage_ticket.as_bytes()),
                blob_hash_hex: hex::encode(shard.blob_hash.as_bytes()),
            })
            .collect(),
    }
}
/// GET /v1/node/query/projection/catalog/{resource} — enumerate the canonical live shard set.
#[cfg(feature = "app_api")]
pub async fn handle_node_query_projection_shard_catalog(
    state: Arc<iroha_core::state::State>,
    resource: String,
    query: NodeProjectionShardCatalogQuery,
) -> Result<NodeProjectionShardCatalogResponse, crate::Error> {
    let view = state.query_view();
    let index_status = query_projection_snapshot_status(&view);
    match resource.trim().to_ascii_lowercase().as_str() {
        "accounts" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for accounts catalog (got `{asset_definition_id}`)"
                )));
            }
            build_projection_shard_catalog_response(
                QueryProjectionResourceKind::Accounts,
                index_status.indexed_height,
                index_status
                    .indexed_block_hash
                    .map(|hash| hex::encode(hash.as_ref())),
                query.offset,
                query.limit,
                build_accounts_projection_shard_catalog_entries(&view),
            )
        }
        "account_assets" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for account_assets catalog (got `{asset_definition_id}`)"
                )));
            }
            build_projection_shard_catalog_response(
                QueryProjectionResourceKind::AccountAssets,
                index_status.indexed_height,
                index_status
                    .indexed_block_hash
                    .map(|hash| hex::encode(hash.as_ref())),
                query.offset,
                query.limit,
                build_account_assets_projection_shard_catalog_entries(&view),
            )
        }
        "asset_holders" => build_projection_shard_catalog_response(
            QueryProjectionResourceKind::AssetHolders,
            index_status.indexed_height,
            index_status
                .indexed_block_hash
                .map(|hash| hex::encode(hash.as_ref())),
            query.offset,
            query.limit,
            build_asset_holders_projection_shard_catalog_entries(
                &view,
                query.asset_definition_id.as_deref(),
            )?,
        ),
        "asset_definitions" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for asset_definitions catalog (got `{asset_definition_id}`)"
                )));
            }
            build_projection_shard_catalog_response(
                QueryProjectionResourceKind::AssetDefinitions,
                index_status.indexed_height,
                index_status
                    .indexed_block_hash
                    .map(|hash| hex::encode(hash.as_ref())),
                query.offset,
                query.limit,
                build_asset_definitions_projection_shard_catalog_entries(&view),
            )
        }
        "domains" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for domains catalog (got `{asset_definition_id}`)"
                )));
            }
            build_projection_shard_catalog_response(
                QueryProjectionResourceKind::Domains,
                index_status.indexed_height,
                index_status
                    .indexed_block_hash
                    .map(|hash| hex::encode(hash.as_ref())),
                query.offset,
                query.limit,
                build_domains_projection_shard_catalog_entries(&view),
            )
        }
        other => Err(projection_export_conversion_error(format!(
            "unsupported projection resource `{other}`"
        ))),
    }
}
/// GET /v1/node/query/projection/shards/{resource}/{partition_id} — export one canonical shard archive.
#[cfg(feature = "app_api")]
pub async fn handle_node_query_projection_shard_export(
    state: Arc<iroha_core::state::State>,
    resource: String,
    partition_id: u32,
    query: NodeProjectionShardExportQuery,
) -> Result<QueryProjectionShardArchive, crate::Error> {
    validate_projection_partition_id(partition_id)?;
    let emitted_at_unix = current_unix_seconds();
    let view = state.query_view();
    match resource.trim().to_ascii_lowercase().as_str() {
        "accounts" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for accounts export (got `{asset_definition_id}`)"
                )));
            }
            build_accounts_projection_shard_archive(&view, partition_id, emitted_at_unix)
        }
        "account_assets" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for account_assets export (got `{asset_definition_id}`)"
                )));
            }
            build_account_assets_projection_shard_archive(&view, partition_id, emitted_at_unix)
        }
        "asset_holders" => {
            let selector = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    projection_export_conversion_error(
                        "asset_definition_id is required for asset_holders export".to_owned(),
                    )
                })?;
            build_asset_holders_projection_shard_archive(
                &view,
                selector,
                partition_id,
                emitted_at_unix,
            )
        }
        "asset_definitions" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for asset_definitions export (got `{asset_definition_id}`)"
                )));
            }
            build_asset_definitions_projection_shard_archive(&view, partition_id, emitted_at_unix)
        }
        "domains" => {
            if let Some(asset_definition_id) = query
                .asset_definition_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Err(projection_export_conversion_error(format!(
                    "asset_definition_id is not supported for domains export (got `{asset_definition_id}`)"
                )));
            }
            build_domains_projection_shard_archive(&view, partition_id, emitted_at_unix)
        }
        other => Err(projection_export_conversion_error(format!(
            "unsupported projection resource `{other}`"
        ))),
    }
}
#[cfg(feature = "app_api")]
fn build_projection_shard_catalog_response(
    resource: QueryProjectionResourceKind,
    indexed_height: u64,
    indexed_block_hash_hex: Option<String>,
    offset: Option<u64>,
    limit: Option<u32>,
    mut entries: Vec<NodeProjectionShardCatalogEntry>,
) -> Result<NodeProjectionShardCatalogResponse, crate::Error> {
    let offset = offset.unwrap_or(0);
    let limit = match limit.unwrap_or(QUERY_PROJECTION_SHARD_CATALOG_DEFAULT_LIMIT) {
        0 => {
            return Err(projection_export_conversion_error(
                "limit must be greater than zero".to_owned(),
            ));
        }
        limit if limit > QUERY_PROJECTION_SHARD_CATALOG_MAX_LIMIT => {
            return Err(projection_export_conversion_error(format!(
                "limit must be less than or equal to {QUERY_PROJECTION_SHARD_CATALOG_MAX_LIMIT}"
            )));
        }
        limit => limit,
    };
    let total_entries = entries.len() as u64;
    let start = usize::try_from(offset.min(total_entries)).unwrap_or(entries.len());
    let end = start
        .saturating_add(usize::try_from(limit).unwrap_or(usize::MAX))
        .min(entries.len());
    let next_offset = (end < entries.len()).then_some(end as u64);
    entries = entries
        .into_iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();
    Ok(NodeProjectionShardCatalogResponse {
        version: QUERY_PROJECTION_SHARD_CATALOG_VERSION,
        resource: resource.as_stable_str().to_string(),
        schema_version: QUERY_PROJECTION_SCHEMA_VERSION,
        indexed_height,
        indexed_block_hash_hex,
        default_partition_count: QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
        offset,
        limit,
        total_entries,
        next_offset,
        entries,
    })
}
#[cfg(feature = "app_api")]
fn query_projection_snapshot_status(state: &impl StateReadOnly) -> QueryIndexStatus {
    QueryIndexStatus {
        indexed_height: u64::try_from(state.height())
            .expect("supported target pointer widths fit the committed state height into u64"),
        indexed_block_hash: state.latest_block_hash(),
    }
}
#[cfg(feature = "app_api")]
fn build_accounts_projection_shard_catalog_entries(
    state: &impl StateReadOnly,
) -> Vec<NodeProjectionShardCatalogEntry> {
    let accounts = crate::routing::collect_subject_accounts(state.world());
    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for account in accounts {
        let partition_id =
            query_projection_default_partition_for_account(&account.id().to_string());
        *counts.entry(partition_id).or_default() += 1;
    }
    counts
        .into_iter()
        .map(
            |(partition_id, row_count)| NodeProjectionShardCatalogEntry {
                partition_id,
                row_count,
                asset_definition_id: None,
                asset_alias: None,
            },
        )
        .collect()
}
#[cfg(feature = "app_api")]
pub fn build_accounts_projection_shard_archive(
    state: &impl StateReadOnly,
    partition_id: u32,
    emitted_at_unix: u64,
) -> Result<QueryProjectionShardArchive, crate::Error> {
    let accounts = crate::routing::collect_subject_accounts(state.world());
    let mut rows = Vec::new();
    for account in accounts {
        let account_id = account.id().to_string();
        if query_projection_default_partition_for_account(&account_id) != partition_id {
            continue;
        }
        let alias = crate::routing::PrimaryAliasProjection::default();
        rows.push(QueryProjectionAccountRow {
            account_id,
            primary_alias: alias.literal,
            primary_alias_name: alias.name,
            primary_alias_dataspace: alias.dataspace,
            primary_alias_domain: alias.domain,
            has_primary_alias: alias.has_primary_alias,
        });
    }
    rows.sort_by(|left, right| left.account_id.cmp(&right.account_id));
    let rowset = QueryProjectionShardRowSet::Accounts(QueryProjectionAccountsShardRowSet::new(
        partition_id,
        rows,
    ));
    let row_count = rowset.row_count();
    let payload = rowset.encode_payload().map_err(|err| {
        projection_export_conversion_error(format!(
            "failed to encode accounts projection shard rowset: {err}"
        ))
    })?;
    Ok(QueryProjectionShardArchive::from_index_status(
        query_projection_snapshot_status(state),
        emitted_at_unix,
        QueryProjectionResourceKind::Accounts,
        partition_id,
        None,
        row_count,
        payload,
    ))
}
#[cfg(feature = "app_api")]
fn build_account_assets_projection_shard_catalog_entries(
    state: &impl StateReadOnly,
) -> Vec<NodeProjectionShardCatalogEntry> {
    let world = state.world();
    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for asset in world.assets_iter() {
        let partition_id =
            query_projection_default_partition_for_account(&asset.id().account().to_string());
        *counts.entry(partition_id).or_default() += 1;
    }
    counts
        .into_iter()
        .map(
            |(partition_id, row_count)| NodeProjectionShardCatalogEntry {
                partition_id,
                row_count,
                asset_definition_id: None,
                asset_alias: None,
            },
        )
        .collect()
}
#[cfg(feature = "app_api")]
pub fn build_account_assets_projection_shard_archive(
    state: &impl StateReadOnly,
    partition_id: u32,
    emitted_at_unix: u64,
) -> Result<QueryProjectionShardArchive, crate::Error> {
    let world = state.world();
    let mut rows = Vec::new();
    for asset in world.assets_iter() {
        let account_id = asset.id().account().to_string();
        if query_projection_default_partition_for_account(&account_id) != partition_id {
            continue;
        }
        let definition_id = asset.id().definition().clone();
        let (asset_name, asset_alias) = world.asset_definition(&definition_id).map_or_else(
            |_| (definition_id.to_string(), None),
            |definition| {
                (
                    definition.name().clone(),
                    definition
                        .alias()
                        .as_ref()
                        .map(|alias| alias.as_ref().to_owned()),
                )
            },
        );
        let alias = crate::routing::PrimaryAliasProjection::default();
        rows.push(QueryProjectionAccountAssetRow {
            account_id,
            asset: definition_id.to_string(),
            asset_name,
            asset_alias,
            scope: crate::routing::asset_balance_scope_literal(asset.id().scope()),
            quantity: asset.value().clone().into_inner(),
            primary_alias: alias.literal,
            primary_alias_name: alias.name,
            primary_alias_dataspace: alias.dataspace,
            primary_alias_domain: alias.domain,
            has_primary_alias: alias.has_primary_alias,
        });
    }
    rows.sort_by(|left, right| {
        left.account_id
            .cmp(&right.account_id)
            .then(left.asset.cmp(&right.asset))
            .then(left.scope.cmp(&right.scope))
    });
    let rowset = QueryProjectionShardRowSet::AccountAssets(
        QueryProjectionAccountAssetsShardRowSet::new(partition_id, rows),
    );
    let row_count = rowset.row_count();
    let payload = rowset.encode_payload().map_err(|err| {
        projection_export_conversion_error(format!(
            "failed to encode account_assets projection shard rowset: {err}"
        ))
    })?;
    Ok(QueryProjectionShardArchive::from_index_status(
        query_projection_snapshot_status(state),
        emitted_at_unix,
        QueryProjectionResourceKind::AccountAssets,
        partition_id,
        None,
        row_count,
        payload,
    ))
}
#[cfg(feature = "app_api")]
fn build_asset_definitions_projection_shard_catalog_entries(
    state: &impl StateReadOnly,
) -> Vec<NodeProjectionShardCatalogEntry> {
    let world = state.world();
    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for definition in world.asset_definitions_iter() {
        let id = definition.id().to_string();
        let partition_id = query_projection_partition_for_key(
            id.as_bytes(),
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
        );
        *counts.entry(partition_id).or_default() += 1;
    }
    counts
        .into_iter()
        .map(
            |(partition_id, row_count)| NodeProjectionShardCatalogEntry {
                partition_id,
                row_count,
                asset_definition_id: None,
                asset_alias: None,
            },
        )
        .collect()
}
#[cfg(feature = "app_api")]
pub fn build_asset_definitions_projection_shard_archive(
    state: &impl StateReadOnly,
    partition_id: u32,
    emitted_at_unix: u64,
) -> Result<QueryProjectionShardArchive, crate::Error> {
    let now_ms = state.query_ledger_time_ms();
    let world = state.world();
    let alias_bindings: BTreeMap<_, _> = world
        .asset_definition_alias_bindings()
        .iter()
        .map(|(definition_id, binding)| {
            (
                definition_id.clone(),
                crate::routing::asset_alias_binding_dto(binding, now_ms),
            )
        })
        .collect();
    let mut rows = Vec::new();
    for definition in world.asset_definitions_iter() {
        let definition = world
            .asset_definition(definition.id())
            .map_err(|err| projection_export_conversion_error(err.to_string()))?;
        let id = definition.id().to_string();
        let definition_partition = query_projection_partition_for_key(
            id.as_bytes(),
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
        );
        if definition_partition != partition_id {
            continue;
        }
        let binding = alias_bindings.get(definition.id());
        let mut metadata = definition
            .metadata()
            .iter()
            .map(|(key, value)| QueryProjectionMetadataEntry {
                key: key.to_string(),
                value_json: value.get().clone(),
            })
            .collect::<Vec<_>>();
        metadata.sort_by(|left, right| left.key.cmp(&right.key));
        rows.push(QueryProjectionAssetDefinitionRow {
            id,
            name: definition.name().clone(),
            alias: definition.alias().as_ref().map(ToString::to_string),
            alias_binding_alias: binding.map(|binding| binding.alias.clone()),
            alias_binding_status: binding.map(|binding| binding.status.clone()),
            alias_binding_lease_expiry_ms: binding.and_then(|binding| binding.lease_expiry_ms),
            alias_binding_grace_until_ms: binding.and_then(|binding| binding.grace_until_ms),
            alias_binding_bound_at_ms: binding.map(|binding| binding.bound_at_ms),
            metadata,
        });
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let rowset = QueryProjectionShardRowSet::AssetDefinitions(
        QueryProjectionAssetDefinitionsShardRowSet::new(partition_id, rows),
    );
    let row_count = rowset.row_count();
    let payload = rowset.encode_payload().map_err(|err| {
        projection_export_conversion_error(format!(
            "failed to encode asset_definitions projection shard rowset: {err}"
        ))
    })?;
    Ok(QueryProjectionShardArchive::from_index_status(
        query_projection_snapshot_status(state),
        emitted_at_unix,
        QueryProjectionResourceKind::AssetDefinitions,
        partition_id,
        None,
        row_count,
        payload,
    ))
}
#[cfg(feature = "app_api")]
fn build_domains_projection_shard_catalog_entries(
    state: &impl StateReadOnly,
) -> Vec<NodeProjectionShardCatalogEntry> {
    let world = state.world();
    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for domain in world.domains_iter() {
        let id = domain.id().to_string();
        let partition_id = query_projection_partition_for_key(
            id.as_bytes(),
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
        );
        *counts.entry(partition_id).or_default() += 1;
    }
    counts
        .into_iter()
        .map(
            |(partition_id, row_count)| NodeProjectionShardCatalogEntry {
                partition_id,
                row_count,
                asset_definition_id: None,
                asset_alias: None,
            },
        )
        .collect()
}
#[cfg(feature = "app_api")]
pub fn build_domains_projection_shard_archive(
    state: &impl StateReadOnly,
    partition_id: u32,
    emitted_at_unix: u64,
) -> Result<QueryProjectionShardArchive, crate::Error> {
    let world = state.world();
    let mut rows = Vec::new();
    for domain in world.domains_iter() {
        let id = domain.id().to_string();
        let domain_partition = query_projection_partition_for_key(
            id.as_bytes(),
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT,
        );
        if domain_partition == partition_id {
            rows.push(QueryProjectionDomainRow { id });
        }
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let rowset = QueryProjectionShardRowSet::Domains(QueryProjectionDomainsShardRowSet::new(
        partition_id,
        rows,
    ));
    let row_count = rowset.row_count();
    let payload = rowset.encode_payload().map_err(|err| {
        projection_export_conversion_error(format!(
            "failed to encode domains projection shard rowset: {err}"
        ))
    })?;
    Ok(QueryProjectionShardArchive::from_index_status(
        query_projection_snapshot_status(state),
        emitted_at_unix,
        QueryProjectionResourceKind::Domains,
        partition_id,
        None,
        row_count,
        payload,
    ))
}
#[cfg(feature = "app_api")]
fn build_asset_holders_projection_shard_catalog_entries(
    state: &impl StateReadOnly,
    asset_definition_selector: Option<&str>,
) -> Result<Vec<NodeProjectionShardCatalogEntry>, crate::Error> {
    let now_ms = state.query_ledger_time_ms();
    let world = state.world();
    let selected_definition_id = asset_definition_selector
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|selector| crate::routing::resolve_asset_definition_selector(world, selector, now_ms))
        .transpose()?;
    let mut counts: BTreeMap<(iroha_data_model::asset::AssetDefinitionId, u32), u64> =
        BTreeMap::new();
    match selected_definition_id {
        Some(definition_id) => {
            for asset in world.asset_entries_by_definition_iter(&definition_id) {
                let partition_id = query_projection_default_partition_for_account(
                    &asset.id().account().to_string(),
                );
                *counts
                    .entry((definition_id.clone(), partition_id))
                    .or_default() += 1;
            }
        }
        None => {
            for asset in world.assets_iter() {
                let partition_id = query_projection_default_partition_for_account(
                    &asset.id().account().to_string(),
                );
                *counts
                    .entry((asset.id().definition().clone(), partition_id))
                    .or_default() += 1;
            }
        }
    }
    let mut entries = Vec::with_capacity(counts.len());
    for ((definition_id, partition_id), row_count) in counts {
        let asset_alias = world
            .asset_definition(&definition_id)
            .ok()
            .and_then(|definition| definition.alias().as_ref().map(ToString::to_string));
        entries.push(NodeProjectionShardCatalogEntry {
            partition_id,
            row_count,
            asset_definition_id: Some(definition_id.to_string()),
            asset_alias,
        });
    }
    Ok(entries)
}
#[cfg(feature = "app_api")]
pub fn build_asset_holders_projection_shard_archive(
    state: &impl StateReadOnly,
    asset_definition_selector: &str,
    partition_id: u32,
    emitted_at_unix: u64,
) -> Result<QueryProjectionShardArchive, crate::Error> {
    let now_ms = state.query_ledger_time_ms();
    let world = state.world();
    let definition_id = crate::routing::resolve_asset_definition_selector(
        world,
        asset_definition_selector,
        now_ms,
    )?;
    let asset_alias = world
        .asset_definition(&definition_id)
        .ok()
        .and_then(|definition| definition.alias().as_ref().map(ToString::to_string));
    let mut aggregated: BTreeMap<
        (
            iroha_data_model::account::AccountId,
            iroha_data_model::asset::AssetBalanceScope,
        ),
        iroha_primitives::numeric::Quantity,
    > = BTreeMap::new();
    for asset in world.asset_entries_by_definition_iter(&definition_id) {
        let account_id = asset.id().account().clone();
        let scope = asset.id().scope().clone();
        let entry = aggregated
            .entry((account_id, scope))
            .or_insert_with(iroha_primitives::numeric::Quantity::zero);
        if let Ok(sum) = entry.checked_add(asset.value().as_ref()) {
            *entry = sum;
        }
    }
    let alias_cache: BTreeMap<_, _> = aggregated
        .keys()
        .map(|(account_id, _)| {
            (
                account_id.clone(),
                crate::routing::PrimaryAliasProjection::default(),
            )
        })
        .collect();
    let mut rows = Vec::new();
    for ((account_id, scope), quantity) in aggregated {
        let canonical_id = account_id.to_string();
        if query_projection_default_partition_for_account(&canonical_id) != partition_id {
            continue;
        }
        let alias = alias_cache.get(&account_id).cloned().unwrap_or_default();
        rows.push(QueryProjectionAssetHolderRow {
            account_id: canonical_id,
            scope: crate::routing::asset_balance_scope_literal(&scope),
            quantity,
            primary_alias: alias.literal,
            primary_alias_name: alias.name,
            primary_alias_dataspace: alias.dataspace,
            primary_alias_domain: alias.domain,
            has_primary_alias: alias.has_primary_alias,
        });
    }
    rows.sort_by(|left, right| {
        left.account_id
            .cmp(&right.account_id)
            .then(left.scope.cmp(&right.scope))
    });
    let rowset =
        QueryProjectionShardRowSet::AssetHolders(QueryProjectionAssetHoldersShardRowSet::new(
            partition_id,
            definition_id.to_string(),
            asset_alias,
            rows,
        ));
    let row_count = rowset.row_count();
    let payload = rowset.encode_payload().map_err(|err| {
        projection_export_conversion_error(format!(
            "failed to encode asset_holders projection shard rowset: {err}"
        ))
    })?;
    Ok(QueryProjectionShardArchive::from_index_status(
        query_projection_snapshot_status(state),
        emitted_at_unix,
        QueryProjectionResourceKind::AssetHolders,
        partition_id,
        rowset.asset_definition_id().map(ToOwned::to_owned),
        row_count,
        payload,
    ))
}
#[cfg(feature = "app_api")]
fn projection_export_conversion_error(message: impl Into<String>) -> crate::Error {
    crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message.into()),
    ))
}
#[cfg(feature = "app_api")]
fn validate_projection_partition_id(partition_id: u32) -> Result<(), crate::Error> {
    if partition_id >= QUERY_PROJECTION_DEFAULT_PARTITION_COUNT {
        return Err(projection_export_conversion_error(format!(
            "partition_id must be less than {}",
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT
        )));
    }
    Ok(())
}
#[cfg(feature = "app_api")]
fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
fn signed_transaction_schema_hash_hex() -> String {
    hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>())
}
fn summarize_curve_capabilities(
    policy: &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1,
) -> NodeCurveCapabilities {
    let ids = policy
        .allowed_curves()
        .map(CurveId::as_u8)
        .collect::<Vec<_>>();
    let bitmap = curve_bitmap_from_ids(&ids);
    NodeCurveCapabilities {
        registry_version: CURVE_REGISTRY_VERSION,
        allowed_curve_ids: ids,
        allowed_curve_bitmap: bitmap,
    }
}
fn curve_bitmap_from_ids(ids: &[u8]) -> Vec<u64> {
    if ids.is_empty() {
        return Vec::new();
    }
    // 256 identifier slots => four 64-bit lanes; trim trailing zeros later.
    let mut lanes = [0u64; 4];
    for &id in ids {
        let lane = (id / 64) as usize;
        let offset = id % 64;
        if let Some(slot) = lanes.get_mut(lane) {
            *slot |= 1u64 << offset;
        }
    }
    let mut vec = lanes.to_vec();
    while vec.len() > 1 && matches!(vec.last(), Some(&0)) {
        vec.pop();
    }
    if vec.len() == 1 && vec[0] == 0 {
        vec.clear();
    }
    vec
}
fn compression_name(compression: Compression) -> &'static str {
    match compression {
        Compression::Identity => "identity",
        Compression::Gzip => "gzip",
        Compression::Deflate => "deflate",
        Compression::Zstd => "zstd",
    }
}
fn blob_class_name(blob_class: BlobClass) -> &'static str {
    match blob_class {
        BlobClass::TaikaiSegment => "taikai_segment",
        BlobClass::NexusLaneSidecar => "nexus_lane_sidecar",
        BlobClass::GovernanceArtifact => "governance_artifact",
        BlobClass::Custom(_) => "custom",
    }
}
fn blob_class_custom_id(blob_class: BlobClass) -> Option<u16> {
    match blob_class {
        BlobClass::Custom(id) => Some(id),
        _ => None,
    }
}
#[cfg(test)]
mod bitmap_tests {
    use super::curve_bitmap_from_ids;
    #[test]
    fn bitmap_handles_edges() {
        assert!(curve_bitmap_from_ids(&[]).is_empty());
        assert_eq!(curve_bitmap_from_ids(&[0]), vec![1]);
        assert_eq!(
            curve_bitmap_from_ids(&[1, 63]),
            vec![(1u64 << 1) | (1u64 << 63)]
        );
        // Highest identifier should land in the final lane.
        let mut ids = vec![255];
        let bitmap = curve_bitmap_from_ids(&ids);
        assert_eq!(bitmap.len(), 4);
        assert_eq!(bitmap[3], 1u64 << 63);
        assert_eq!(bitmap[0..3], [0, 0, 0]);
        // Multiple lanes retain intermediate zeros.
        ids.extend([0, 128]);
        let bitmap = curve_bitmap_from_ids(&ids);
        assert_eq!(bitmap, vec![1, 0, 1, 1u64 << 63]);
    }
}
/// GET /v1/runtime/metrics — expose runtime metrics summary
pub async fn handle_runtime_metrics(
    state: Arc<iroha_core::state::State>,
) -> Result<RuntimeMetricsResponse, crate::Error> {
    let world = state.world_view();
    let mut proposed: u64 = 0;
    let mut activated: u64 = 0;
    let mut canceled: u64 = 0;
    for (_id, rec) in world.runtime_upgrades().iter() {
        proposed = proposed.saturating_add(1);
        match rec.status {
            iroha_data_model::runtime::RuntimeUpgradeStatus::ActivatedAt(_) => {
                activated = activated.saturating_add(1)
            }
            iroha_data_model::runtime::RuntimeUpgradeStatus::Canceled => {
                canceled = canceled.saturating_add(1)
            }
            _ => {}
        }
    }
    Ok(RuntimeMetricsResponse {
        abi_version: world.abi_version(),
        upgrade_events_total: UpgradeEventsCounters {
            proposed,
            activated,
            canceled,
        },
    })
}
/// GET /v1/runtime/abi/hash — return the canonical ABI hash for the node's active policy.
pub async fn handle_runtime_abi_hash(
    _state: Arc<iroha_core::state::State>,
) -> Result<RuntimeAbiHashResponse, crate::Error> {
    // First release: single policy V1
    let h = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    Ok(RuntimeAbiHashResponse {
        policy: "V1".to_string(),
        abi_hash_hex: hex::encode::<[u8; 32]>(h),
    })
}
/// GET /v1/runtime/upgrades
///
/// # Errors
/// Returns an error if the state view cannot be acquired or serialized.
pub async fn handle_runtime_upgrades_list(
    state: Arc<iroha_core::state::State>,
) -> Result<RuntimeUpgradesListResponse, crate::Error> {
    let world = state.world_view();
    let mut items: Vec<RuntimeUpgradeListItem> = Vec::new();
    for (id, rec) in world.runtime_upgrades().iter() {
        items.push(RuntimeUpgradeListItem {
            id_hex: hex::encode(id.0),
            record: rec.clone(),
        });
    }
    // Stable sort: by start_height then abi_version
    items.sort_by_key(|it| {
        (
            it.record.manifest.start_height,
            it.record.manifest.abi_version,
        )
    });
    Ok(RuntimeUpgradesListResponse { items })
}
#[derive(Debug, JsonDeserialize, NoritoDeserialize, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::ProposeUpgradeDto")]
pub struct ProposeUpgradeDto(pub iroha_data_model::runtime::RuntimeUpgradeManifest);
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::TxInstr")]
#[derive(Debug, JsonSerialize, NoritoSerialize)]
pub struct TxInstr {
    pub wire_id: String,
    pub payload_hex: String,
}
fn instruction_box_to_tx_instr(boxed: iroha_data_model::isi::InstructionBox) -> TxInstr {
    let (wire_id, framed) = iroha_data_model::isi::framed_instruction_payload(&boxed)
        .expect("instruction must have a canonical V1 wire identifier and Norito frame");
    TxInstr {
        wire_id: wire_id.to_owned(),
        payload_hex: hex::encode(framed),
    }
}
#[derive(Debug, JsonSerialize, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::ProposeUpgradeResponse")]
pub struct ProposeUpgradeResponse {
    pub ok: bool,
    pub tx_instructions: Vec<TxInstr>,
}
/// POST /v1/runtime/upgrades/propose
pub async fn handle_runtime_propose_upgrade(
    NoritoJson(ProposeUpgradeDto(manifest)): NoritoJson<ProposeUpgradeDto>,
) -> Result<ProposeUpgradeResponse, crate::Error> {
    let manifest_bytes = norito::to_bytes(&manifest).map_err(|e| {
        crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
                "encode manifest: {e}"
            )),
        ))
    })?;
    let isi = iroha_data_model::isi::runtime_upgrade::ProposeRuntimeUpgrade { manifest_bytes };
    let boxed: iroha_data_model::isi::InstructionBox = isi.into();
    let tx_instructions = vec![instruction_box_to_tx_instr(boxed)];
    Ok(ProposeUpgradeResponse {
        ok: true,
        tx_instructions,
    })
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::runtime::ActivateCancelResponse")]
#[derive(Debug, JsonSerialize, NoritoSerialize)]
/// Response payload describing the outcome of runtime activation/cancellation helpers.
pub struct ActivateCancelResponse {
    /// Indicates whether the operation succeeded.
    pub ok: bool,
    /// Instructions (if any) that must be signed and submitted by the caller.
    pub tx_instructions: Vec<TxInstr>,
}
impl IntoResponse for ActivateCancelResponse {
    fn into_response(self) -> axum::response::Response {
        crate::JsonBody(self).into_response()
    }
}
/// POST /v1/runtime/upgrades/activate/{id}
///
/// # Errors
/// Returns an error when the provided upgrade identifier is malformed or activation fails.
pub async fn handle_runtime_activate_upgrade(
    Path(id): Path<String>,
) -> Result<ActivateCancelResponse, crate::Error> {
    let s = id.trim_start_matches("0x");
    let bytes = hex::decode(s).map_err(|_| {
        crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion("invalid id".into()),
        ))
    })?;
    if bytes.len() != 32 {
        return Err(crate::Error::Query(
            iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "invalid id length".into(),
                ),
            ),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let isi = iroha_data_model::isi::runtime_upgrade::ActivateRuntimeUpgrade {
        id: iroha_data_model::runtime::RuntimeUpgradeId(arr),
    };
    let boxed: iroha_data_model::isi::InstructionBox = isi.into();
    let tx_instructions = vec![instruction_box_to_tx_instr(boxed)];
    Ok(ActivateCancelResponse {
        ok: true,
        tx_instructions,
    })
}
/// POST /v1/runtime/upgrades/cancel/{id}
///
/// # Errors
/// Returns an error when the identifier cannot be decoded or cancellation fails.
pub async fn handle_runtime_cancel_upgrade(
    Path(id): Path<String>,
) -> Result<ActivateCancelResponse, crate::Error> {
    let s = id.trim_start_matches("0x");
    let bytes = hex::decode(s).map_err(|_| {
        crate::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion("invalid id".into()),
        ))
    })?;
    if bytes.len() != 32 {
        return Err(crate::Error::Query(
            iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(
                    "invalid id length".into(),
                ),
            ),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let isi = iroha_data_model::isi::runtime_upgrade::CancelRuntimeUpgrade {
        id: iroha_data_model::runtime::RuntimeUpgradeId(arr),
    };
    let boxed: iroha_data_model::isi::InstructionBox = isi.into();
    let tx_instructions = vec![instruction_box_to_tx_instr(boxed)];
    Ok(ActivateCancelResponse {
        ok: true,
        tx_instructions,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use iroha_core::{kura::Kura, query::store::LiveQueryStore, state::State};

    #[test]
    fn runtime_upgrade_instruction_drafts_use_canonical_wire_ids_and_frames() {
        let boxed: iroha_data_model::isi::InstructionBox =
            iroha_data_model::isi::runtime_upgrade::CancelRuntimeUpgrade {
                id: iroha_data_model::runtime::RuntimeUpgradeId([0xA5; 32]),
            }
            .into();
        let draft = instruction_box_to_tx_instr(boxed);

        assert_eq!(draft.wire_id, "iroha.runtime_upgrade.cancel");
        let framed = hex::decode(&draft.payload_hex).expect("decode framed instruction hex");
        let decoded = iroha_data_model::isi::decode_instruction_from_pair(&draft.wire_id, &framed)
            .expect("decode canonical runtime-upgrade instruction pair");
        assert_eq!(
            iroha_data_model::isi::Instruction::id(&*decoded),
            std::any::type_name::<iroha_data_model::isi::runtime_upgrade::CancelRuntimeUpgrade>()
        );
    }

    #[cfg(feature = "app_api")]
    fn checked_projection_ed25519_keypair(seed: u8) -> iroha_crypto::KeyPair {
        iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("test projection fixture key derivation should succeed")
    }
    #[cfg(feature = "app_api")]
    fn checked_projection_account(seed: u8) -> iroha_data_model::account::AccountId {
        iroha_data_model::account::AccountId::new(
            checked_projection_ed25519_keypair(seed)
                .public_key()
                .clone(),
        )
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn checked_projection_ed25519_keypair_uses_fallible_seed_derivation() {
        assert_eq!(
            checked_projection_ed25519_keypair(0x50).algorithm(),
            Algorithm::Ed25519
        );
        assert!(
            iroha_crypto::KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
        assert_ne!(
            checked_projection_account(0x51),
            checked_projection_account(0x52)
        );
    }
    #[tokio::test]
    async fn runtime_abi_hash_matches_ivm() {
        // Build a minimal state (not used by the handler, but required by signature)
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        let state = State::new_for_testing(world, kura, query_handle);
        let resp = handle_runtime_abi_hash(std::sync::Arc::new(state))
            .await
            .expect("ok");
        crate::frame_test_support::assert_current_frame(
            &resp,
            "iroha_torii::runtime::RuntimeAbiHashResponse",
        );
        assert_eq!(resp.policy, "V1");
        // Expected hex length for 32 bytes
        assert_eq!(resp.abi_hash_hex.len(), 64);
        let expected = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
        assert_eq!(resp.abi_hash_hex, hex::encode::<[u8; 32]>(expected));
    }
    #[tokio::test]
    async fn node_capabilities_reports_v1() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        {
            let mut block = world.block();
            let policy =
                iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    Algorithm::Ed25519,
                ])
                .unwrap();
            block
                .parameters
                .set_parameter(policy.into_parameter().unwrap())
                .unwrap();
            block.commit();
        }
        let state = State::new_for_testing(world, kura, query_handle);
        let resp = handle_node_capabilities(std::sync::Arc::new(state))
            .await
            .expect("ok");
        crate::frame_test_support::assert_current_frame(
            &resp,
            "iroha_torii::runtime::NodeCapabilitiesResponse",
        );
        assert_eq!(resp.abi_version, 1);
        assert_eq!(
            resp.data_model_version,
            iroha_data_model::DATA_MODEL_VERSION
        );
        assert_eq!(resp.crypto.sm.allowed_signing, vec!["ed25519".to_owned()]);
        assert_eq!(
            resp.crypto.curves.allowed_curve_ids,
            vec![CurveId::ED25519.as_u8()]
        );
        assert_eq!(resp.signed_transaction_schema_hash_hex.len(), 32);
        assert_eq!(
            resp.signed_transaction_schema_hash_hex,
            hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>())
        );
        assert_eq!(resp.crypto.curves.registry_version, CURVE_REGISTRY_VERSION);
        assert!(resp.query.aggregate.v1);
        assert!(resp.query.aggregate.exact_results);
        #[cfg(feature = "app_api")]
        let supported_resources = crate::collections::aggregate_collections()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        #[cfg(not(feature = "app_api"))]
        let supported_resources = Vec::<String>::new();
        assert_eq!(
            resp.query.aggregate.supported_resources,
            supported_resources
        );
        assert!(resp.query.projection.checkpoint_contract_v1);
        assert!(!resp.query.projection.da_v1_enabled);
        assert_eq!(
            resp.query.projection.shard_catalog_v1,
            cfg!(feature = "app_api")
        );
        assert_eq!(
            resp.query.projection.archive_export_v1,
            cfg!(feature = "app_api")
        );
        assert_eq!(
            resp.query.projection.archive_version,
            QUERY_PROJECTION_SHARD_ARCHIVE_VERSION
        );
        assert_eq!(
            resp.query.projection.blob_class_custom_id,
            QUERY_PROJECTION_DA_BLOB_CLASS_CUSTOM_ID
        );
        assert_eq!(resp.query.projection.codec, QUERY_PROJECTION_DA_CODEC);
        assert_eq!(
            resp.query.projection.rowset_codec,
            QUERY_PROJECTION_SHARD_ROWSET_CODEC
        );
        assert_eq!(resp.query.projection.compression, "zstd");
        assert_eq!(
            resp.query.projection.default_partition_count,
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT
        );
        #[cfg(feature = "app_api")]
        assert_eq!(
            resp.query.projection.export_supported_resources,
            crate::collections::PROJECTION_EXPORT_COLLECTIONS
                .map(str::to_owned)
                .to_vec()
        );
        #[cfg(not(feature = "app_api"))]
        assert!(resp.query.projection.export_supported_resources.is_empty());
        assert!(
            resp.query
                .projection
                .metadata_keys
                .contains(&QUERY_PROJECTION_METADATA_LOCATOR_KEY.to_string())
        );
        assert!(
            resp.query
                .projection
                .metadata_keys
                .contains(&QUERY_PROJECTION_METADATA_ROWSET_HASH_KEY.to_string())
        );
        assert!(
            resp.query
                .projection
                .latest_checkpoint_indexed_height
                .is_none()
        );
        assert!(
            resp.query
                .projection
                .latest_checkpoint_block_hash_hex
                .is_none()
        );
        assert!(
            resp.crypto
                .curves
                .allowed_curve_ids
                .contains(&CurveId::ED25519.as_u8()),
            "expected ED25519 curve id to be advertised"
        );
    }
    #[tokio::test]
    async fn node_capabilities_without_initial_policy_is_local_readiness() {
        let state = State::new_for_testing(
            iroha_core::state::World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let error = handle_node_capabilities(Arc::new(state)).await.unwrap_err();
        assert!(
            matches!(error, crate::Error::TransactionAdmissionDeferred(original)
            if original.reason() == ivm::error::ExecutionDeferral::CryptoAdmissionPolicyUnavailable)
        );
    }
    #[tokio::test]
    async fn privacy_capabilities_are_built_from_one_committed_state_view() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        let state = State::new_for_testing(world, kura, query_handle);
        let manifest = handle_privacy_capabilities(std::sync::Arc::new(state))
            .await
            .expect("valid committed Exact12 capability manifest");
        assert_eq!(manifest.committed_height, 0);
        assert_eq!(
            manifest.consensus_policy,
            iroha_data_model::privacy::PrivacyConsensusPolicyV1::taira_default()
        );
        assert_eq!(
            manifest
                .protocols
                .iter()
                .map(|row| row.protocol_id)
                .collect::<Vec<_>>(),
            iroha_data_model::privacy::PrivacyProtocolIdV1::ALL
        );
        let jindo = &manifest.protocols[6];
        assert_eq!(
            jindo.readiness,
            iroha_data_model::privacy::PrivacyCapabilityReadinessV1::Unavailable(
                iroha_data_model::privacy::PrivacyCapabilityUnavailableReasonV1::NotRegistered
            )
        );
        for row in [&manifest.protocols[3], &manifest.protocols[5]] {
            assert!(matches!(
                row.readiness,
                iroha_data_model::privacy::PrivacyCapabilityReadinessV1::Unavailable(_)
            ));
            assert!(!row.is_network_available());
        }
        manifest.validate().expect("manifest validates");
        assert!(!manifest.manifest_digest.is_zero());
        let json = norito::json::to_json(&manifest).expect("manifest JSON");
        assert!(json.contains("iroha-bootle-lantern-anoncred-v1"));
        assert!(json.contains("zk_x509_identity_presentation_v1"));
        assert!(json.contains("not-registered"));
        assert!(!json.contains("available-experimental"));
        assert!(!json.contains("limitation"));
        assert!(!json.contains("iroha-bootle-genisis-ac-stark-v0"));
        assert!(!json.contains("production_ready"));
        assert!(!json.contains("production_gate"));
        let archive = manifest
            .canonical_bytes()
            .expect("canonical manifest Norito");
        assert_eq!(
            archive,
            norito::to_bytes(&manifest).expect("Torii manifest Norito")
        );
        let decoded: iroha_data_model::privacy::PrivacyExact12CapabilityManifestV1 =
            norito::decode_from_bytes(&archive).expect("decode manifest Norito");
        assert_eq!(decoded, manifest);
        decoded.validate().expect("decoded manifest validates");
        let (parts, body) =
            crate::utils::respond_with_format(manifest, crate::utils::ResponseFormat::Norito)
                .into_parts();
        assert_eq!(
            parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .expect("Torii capability content type"),
            crate::utils::NORITO_MIME_TYPE
        );
        let response_bytes = body
            .collect()
            .await
            .expect("collect Torii capability response")
            .to_bytes();
        assert_eq!(response_bytes.as_ref(), archive.as_slice());
    }
    #[tokio::test]
    async fn node_capabilities_reports_projection_checkpoint_snapshot_when_present() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        let state = State::new_for_testing(world, kura, query_handle);
        let expected_hash =
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::new([0x5A; iroha_crypto::Hash::LENGTH]),
            );
        state.persist_query_projection_checkpoint(Some(
            iroha_core::query::projection_checkpoint::QueryProjectionCheckpoint::from_index_status(
                iroha_core::query::index_status::QueryIndexStatus {
                    indexed_height: 44,
                    indexed_block_hash: Some(expected_hash),
                },
                1_714_000_444,
                Vec::new(),
            ),
        ));
        let resp = handle_node_capabilities(std::sync::Arc::new(state))
            .await
            .expect("ok");
        assert_eq!(
            resp.query.projection.archive_version,
            QUERY_PROJECTION_SHARD_ARCHIVE_VERSION
        );
        assert_eq!(
            resp.query.projection.rowset_codec,
            QUERY_PROJECTION_SHARD_ROWSET_CODEC
        );
        assert_eq!(
            resp.query.projection.archive_export_v1,
            cfg!(feature = "app_api")
        );
        assert_eq!(
            resp.query.projection.shard_catalog_v1,
            cfg!(feature = "app_api")
        );
        assert_eq!(
            resp.query.projection.latest_checkpoint_indexed_height,
            Some(44)
        );
        assert_eq!(
            resp.query.projection.latest_checkpoint_block_hash_hex,
            Some(hex::encode(expected_hash.as_ref()))
        );
    }
    #[tokio::test]
    async fn node_query_projection_checkpoint_returns_none_when_absent() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        let state = State::new_for_testing(world, kura, query_handle);
        assert!(
            handle_node_query_projection_checkpoint(std::sync::Arc::new(state))
                .await
                .is_none()
        );
    }
    #[tokio::test]
    async fn node_query_projection_checkpoint_returns_persisted_descriptor() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        let state = State::new_for_testing(world, kura, query_handle);
        let expected_hash =
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::new([0x5A; iroha_crypto::Hash::LENGTH]),
            );
        state.persist_query_projection_checkpoint(Some(
            iroha_core::query::projection_checkpoint::QueryProjectionCheckpoint::from_index_status(
                iroha_core::query::index_status::QueryIndexStatus {
                    indexed_height: 44,
                    indexed_block_hash: Some(expected_hash),
                },
                1_714_000_444,
                vec![iroha_core::query::projection_checkpoint::QueryProjectionCheckpointShard {
                    resource:
                        iroha_core::query::projection_checkpoint::QueryProjectionResourceKind::AssetHolders,
                    partition_id: 7,
                    asset_definition_id: Some("pkr#paynet".to_string()),
                    manifest_digest: iroha_data_model::da::types::BlobDigest::new([0x11; 32]),
                    storage_ticket: iroha_data_model::da::types::StorageTicketId::new([0x22; 32]),
                    blob_hash: iroha_data_model::da::types::BlobDigest::new([0x33; 32]),
                }],
            ),
        ));
        let resp = handle_node_query_projection_checkpoint(std::sync::Arc::new(state))
            .await
            .expect("checkpoint response");
        assert_eq!(resp.version, 1);
        assert_eq!(resp.schema_version, QUERY_PROJECTION_SCHEMA_VERSION);
        assert_eq!(resp.blob_class, "custom");
        assert_eq!(
            resp.blob_class_custom_id,
            Some(QUERY_PROJECTION_DA_BLOB_CLASS_CUSTOM_ID)
        );
        assert_eq!(resp.codec, QUERY_PROJECTION_DA_CODEC);
        assert_eq!(resp.compression, "zstd");
        assert_eq!(resp.indexed_height, 44);
        assert_eq!(
            resp.indexed_block_hash_hex,
            Some(hex::encode(expected_hash.as_ref()))
        );
        assert_eq!(resp.emitted_at_unix, 1_714_000_444);
        assert_eq!(resp.shards.len(), 1);
        assert_eq!(resp.shards[0].resource, "asset_holders");
        assert_eq!(resp.shards[0].partition_id, 7);
        assert_eq!(
            resp.shards[0].asset_definition_id.as_deref(),
            Some("pkr#paynet")
        );
        assert_eq!(resp.shards[0].manifest_digest_hex, hex::encode([0x11; 32]));
        assert_eq!(resp.shards[0].storage_ticket_hex, hex::encode([0x22; 32]));
        assert_eq!(resp.shards[0].blob_hash_hex, hex::encode([0x33; 32]));
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn node_query_projection_shard_catalog_builds_accounts_entries() {
        use iroha_data_model::Registrable;
        use iroha_data_model::prelude::{Account, Domain};
        use iroha_model_base::domain::DomainId;
        let authority_id = checked_projection_account(0x85);
        let alice_id = checked_projection_account(0x86);
        let bob_id = checked_projection_account(0x87);
        let domain_id = DomainId::try_new("projection-catalog", "universal").expect("domain");
        let world = iroha_core::state::World::with(
            [Domain::new(domain_id).build(&authority_id)],
            [
                Account::new(authority_id.clone()).build(&authority_id),
                Account::new(alice_id.clone()).build(&authority_id),
                Account::new(bob_id.clone()).build(&authority_id),
            ],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let response = handle_node_query_projection_shard_catalog(
            std::sync::Arc::new(state),
            "accounts".to_string(),
            NodeProjectionShardCatalogQuery {
                asset_definition_id: None,
                offset: None,
                limit: None,
            },
        )
        .await
        .expect("catalog");
        assert_eq!(response.version, QUERY_PROJECTION_SHARD_CATALOG_VERSION);
        assert_eq!(response.resource, "accounts");
        assert_eq!(
            response.default_partition_count,
            QUERY_PROJECTION_DEFAULT_PARTITION_COUNT
        );
        assert!(
            !response.entries.is_empty(),
            "expected at least one non-empty shard"
        );
        assert_eq!(
            response
                .entries
                .iter()
                .map(|entry| entry.row_count)
                .sum::<u64>(),
            3
        );
        assert!(
            response.entries.iter().all(|entry| {
                entry.asset_definition_id.is_none() && entry.asset_alias.is_none()
            })
        );
        assert_eq!(response.total_entries, response.entries.len() as u64);
        assert!(response.next_offset.is_none());
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn node_query_projection_shard_catalog_builds_asset_holder_entries() {
        use iroha_data_model::Registrable;
        use iroha_data_model::prelude::{
            Account, Asset, AssetDefinition, AssetDefinitionId, AssetId, Domain,
        };
        use iroha_model_base::domain::DomainId;
        use iroha_primitives::numeric::Quantity;
        let authority_id = checked_projection_account(0x88);
        let alice_id = checked_projection_account(0x89);
        let bob_id = checked_projection_account(0x8A);
        let domain_id =
            DomainId::try_new("projection-catalog-assets", "universal").expect("domain");
        let rose_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "rose".parse().expect("name"),
        );
        let tulip_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "tulip".parse().expect("name"),
        );
        let rose_definition = AssetDefinition::numeric(
            rose_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority_id);
        let tulip_definition = AssetDefinition::numeric(
            tulip_definition_id.clone(),
            "tulip".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority_id);
        let world = iroha_core::state::World::with_assets(
            [Domain::new(domain_id).build(&authority_id)],
            [
                Account::new(authority_id.clone()).build(&authority_id),
                Account::new(alice_id.clone()).build(&authority_id),
                Account::new(bob_id.clone()).build(&authority_id),
            ],
            [rose_definition, tulip_definition],
            [
                Asset::new(
                    AssetId::new(rose_definition_id.clone(), alice_id.clone()),
                    Quantity::from(10_u32),
                ),
                Asset::new(
                    AssetId::new(rose_definition_id.clone(), bob_id.clone()),
                    Quantity::from(25_u32),
                ),
                Asset::new(
                    AssetId::new(tulip_definition_id.clone(), alice_id.clone()),
                    Quantity::from(50_u32),
                ),
            ],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let response = handle_node_query_projection_shard_catalog(
            std::sync::Arc::new(state),
            "asset_holders".to_string(),
            NodeProjectionShardCatalogQuery {
                asset_definition_id: None,
                offset: Some(0),
                limit: Some(1),
            },
        )
        .await
        .expect("catalog");
        assert_eq!(response.resource, "asset_holders");
        assert_eq!(response.limit, 1);
        assert!(response.total_entries >= 2);
        assert_eq!(response.entries.len(), 1);
        assert_eq!(response.next_offset, Some(1));
        assert!(
            response.entries[0].asset_definition_id.is_some(),
            "holder catalog must retain the asset discriminator"
        );
        assert!(
            response.entries[0].row_count > 0,
            "holder catalog entries must represent non-empty shards"
        );
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn node_query_projection_shard_export_builds_accounts_archive() {
        use iroha_data_model::Registrable;
        use iroha_data_model::prelude::{Account, Domain};
        use iroha_model_base::domain::DomainId;
        let authority_id = checked_projection_account(0x8B);
        let alice_id = checked_projection_account(0x8C);
        let domain_id = DomainId::try_new("projection", "universal").expect("domain");
        let world = iroha_core::state::World::with(
            [Domain::new(domain_id).build(&authority_id)],
            [
                Account::new(authority_id.clone()).build(&authority_id),
                Account::new(alice_id.clone()).build(&authority_id),
            ],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let partition_id = query_projection_default_partition_for_account(&alice_id.to_string());
        let archive = handle_node_query_projection_shard_export(
            std::sync::Arc::new(state),
            "accounts".to_string(),
            partition_id,
            NodeProjectionShardExportQuery {
                asset_definition_id: None,
            },
        )
        .await
        .expect("export accounts shard");
        assert_eq!(archive.resource, QueryProjectionResourceKind::Accounts);
        assert_eq!(archive.partition_id, partition_id);
        let rowset: QueryProjectionShardRowSet =
            norito::decode_from_bytes(&archive.payload).expect("decode rowset");
        match rowset {
            QueryProjectionShardRowSet::Accounts(rowset) => {
                assert_eq!(rowset.partition_id, partition_id);
                assert!(
                    rowset
                        .rows
                        .iter()
                        .any(|row| row.account_id == alice_id.to_string()),
                    "expected exported partition to contain alice"
                );
                assert!(rowset.rows.iter().all(|row| {
                    query_projection_default_partition_for_account(&row.account_id) == partition_id
                }));
            }
            other => panic!("unexpected rowset variant: {other:?}"),
        }
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn projection_archive_marker_is_derived_from_the_same_state_view_as_rows() {
        let mut state = State::new_for_testing(
            iroha_core::state::World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let expected_hash =
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::new([0xA7; iroha_crypto::Hash::LENGTH]),
            );
        state.push_block_hash_for_testing(expected_hash);
        let view = state.query_view();

        let archive = build_accounts_projection_shard_archive(&view, 0, 1_714_002_777)
            .expect("build projection archive from one committed view");

        assert_eq!(archive.indexed_height, 1);
        assert_eq!(archive.indexed_block_hash, Some(expected_hash));
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn node_query_projection_shard_export_builds_asset_holders_archive() {
        use iroha_data_model::Registrable;
        use iroha_data_model::prelude::{
            Account, Asset, AssetDefinition, AssetDefinitionId, AssetId, Domain,
        };
        use iroha_model_base::domain::DomainId;
        use iroha_primitives::numeric::Quantity;
        let authority_id = checked_projection_account(0x8D);
        let alice_id = checked_projection_account(0x8E);
        let bob_id = checked_projection_account(0x8F);
        let domain_id = DomainId::try_new("projection-holders", "universal").expect("domain");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "rose".parse().expect("name"),
        );
        let definition = AssetDefinition::numeric(
            definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&authority_id);
        let world = iroha_core::state::World::with_assets(
            [Domain::new(domain_id).build(&authority_id)],
            [
                Account::new(authority_id.clone()).build(&authority_id),
                Account::new(alice_id.clone()).build(&authority_id),
                Account::new(bob_id.clone()).build(&authority_id),
            ],
            [definition],
            [
                Asset::new(
                    AssetId::new(definition_id.clone(), alice_id.clone()),
                    Quantity::from(10_u32),
                ),
                Asset::new(
                    AssetId::new(definition_id.clone(), bob_id.clone()),
                    Quantity::from(20_u32),
                ),
            ],
            [],
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let partition_id = query_projection_default_partition_for_account(&alice_id.to_string());
        let archive = handle_node_query_projection_shard_export(
            std::sync::Arc::new(state),
            "asset_holders".to_string(),
            partition_id,
            NodeProjectionShardExportQuery {
                asset_definition_id: Some(definition_id.to_string()),
            },
        )
        .await
        .expect("export asset holders shard");
        assert_eq!(archive.resource, QueryProjectionResourceKind::AssetHolders);
        assert_eq!(archive.partition_id, partition_id);
        assert_eq!(archive.asset_definition_id, Some(definition_id.to_string()));
        let rowset: QueryProjectionShardRowSet =
            norito::decode_from_bytes(&archive.payload).expect("decode rowset");
        match rowset {
            QueryProjectionShardRowSet::AssetHolders(rowset) => {
                assert_eq!(rowset.partition_id, partition_id);
                assert_eq!(rowset.asset_definition_id, definition_id.to_string());
                assert!(
                    rowset
                        .rows
                        .iter()
                        .any(|row| row.account_id == alice_id.to_string()),
                    "expected exported partition to contain alice holder row"
                );
                assert!(rowset.rows.iter().all(|row| {
                    query_projection_default_partition_for_account(&row.account_id) == partition_id
                }));
            }
            other => panic!("unexpected rowset variant: {other:?}"),
        }
    }
    #[tokio::test]
    async fn runtime_metrics_defaults() {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let world = iroha_core::state::World::default();
        let state = State::new_for_testing(world, kura, query_handle);
        let resp = handle_runtime_metrics(std::sync::Arc::new(state))
            .await
            .expect("ok");
        assert_eq!(resp.abi_version, 1);
        assert_eq!(resp.upgrade_events_total.proposed, 0);
        assert_eq!(resp.upgrade_events_total.activated, 0);
        assert_eq!(resp.upgrade_events_total.canceled, 0);
    }
}
