//! Native MCP endpoint support for Torii.
//!
//! This module exposes a lightweight JSON-RPC bridge that maps MCP tool calls to existing Torii
//! HTTP routes. OpenAPI supplies operation schemas, but an HTTP operation becomes an MCP tool only
//! after its exact method/path pair opts into the catalog's MCP projection. Purpose-built `iroha.*`
//! tools form a separate, explicit allowlist.
//!
//! Route response bytes never become raw MCP JSON or free-form success text. JSON responses are
//! parsed into [`norito::json::Value`], other response bodies become JSON strings, and the typed
//! value is placed under `structuredContent`. This keeps ledger-controlled content in the data
//! plane instead of promoting it into the MCP result's text summary.
use crate::{
    ReviewedMcpJsonRpcError, ReviewedProtocolNativeError, SharedAppState, limits, openapi,
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use blake3::Hasher as Blake3Hasher;
use iroha_crypto::PublicKey;
use iroha_data_model::{
    account::AccountAddress, governance::types::MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1,
};
use iroha_torii_shared::parliament_api::{
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1, ParliamentTimedOvnCastingProofRequestV1,
};
use iroha_torii_shared::{
    PipelineTransactionStatusResponse,
    route_catalog::{
        self, AdmissionPolicy, ApiSurface, AuthenticationPolicy, CatalogProjection,
        EnabledFeatures, HttpMethod as CatalogHttpMethod, RouteCatalog, RouteDescriptor,
        RouteEffect,
    },
};
use norito::json::{self, BoundedJsonError, FastJsonWrite, JsonWriteSink, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Write as _,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, LazyLock, Mutex, RwLock},
    time::Duration,
};
use tower::ServiceExt as _;
mod collection_query_tools;
mod connect_session_tools;
mod contract_view_tools;
mod governance_ballot_tools;
mod protocol;
mod registry;
mod resources;
mod response;
mod transaction_artifacts;
use collection_query_tools::{
    CollectionQueryShape, collection_get_route, collection_post_body, collection_query_tool,
    expand_collection_query_schema,
};
use connect_session_tools::{build_connect_session_create_body, decode_canonical, required_string};
use contract_view_tools::{dispatch_contract_view, iroha_contracts_view_tool};
use governance_ballot_tools::{
    governance_selector_v1_schema, iroha_gov_ballots_plain_tool,
    iroha_gov_ballots_zk_v1_ballot_proof_tool, iroha_gov_ballots_zk_v1_tool,
};
pub(crate) use protocol::{
    ValidatedRequest as ValidatedProtocolRequest, ValidationErrorKind, decorate_modern_response,
    validate_request as validate_protocol_request,
};
use registry::semantics::{
    AuthorityClass, MutationNature, OperationKind, RetrySemantics, Sensitivity, ToolSemantics,
    WorldBoundary, authority_for_route, mutation_nature_for_operation, sensitivity_for,
    world_boundary_for_tool,
};
pub(crate) use response::{
    BoundedJsonArray, bounded_modern_jsonrpc_http_response, jsonrpc_response_too_large,
};
use response::{
    bounded_json_value_len, error_envelope_value, http_status_error_code, jsonrpc_error_response,
    jsonrpc_result_response,
};
const JSONRPC_VERSION: &str = "2.0";
const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
pub(crate) const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_INTERNAL_ERROR: i64 = -32603;
const MCP_TOOL_EXECUTION_ERROR: i64 = -32001;
const MCP_RESPONSE_TOO_LARGE: i64 = -32002;
const MCP_REQUEST_TIMEOUT: i64 = -32003;
const MCP_DISPATCH_CAPACITY_EXHAUSTED: i64 = -32004;
const MCP_RATE_LIMITED: i64 = -32029;
const MODERN_IROHA_TOOL_EXECUTION_ERROR: i64 = 1_001;
const MODERN_IROHA_RESPONSE_TOO_LARGE: i64 = 1_002;
const MODERN_IROHA_REQUEST_TIMEOUT: i64 = 1_003;
const MODERN_IROHA_DISPATCH_CAPACITY_EXHAUSTED: i64 = 1_004;
const MODERN_IROHA_RATE_LIMITED: i64 = 1_029;
const MCP_CANCELLATION_FINGERPRINT_DOMAIN: &[u8] = b"iroha.mcp.cancellation.client.v1\0";
const MCP_CANCELLATION_NONCE_META_KEY: &str = "iroha/cancellationNonce";
const MAX_MCP_PROJECTION_KEYS: usize = 64;
const MAX_MCP_PROJECTION_KEY_CHARS: usize = 128;
/// First-release ceiling for the explicitly advertised `tools/call_batch` extension.
pub(crate) const MAX_JSONRPC_BATCH_DISPATCHES: usize = 64;
const MAX_MCP_LONG_POLL_DISPATCHES: usize = 8;
/// Reserve most dispatch slots for bounded tools instead of ten-minute transaction waits.
pub(crate) fn long_poll_dispatch_capacity(max_inflight_dispatches: usize) -> usize {
    if max_inflight_dispatches < 2 {
        return 0;
    }
    (max_inflight_dispatches / 4)
        .max(1)
        .min(MAX_MCP_LONG_POLL_DISPATCHES)
        .min(max_inflight_dispatches - 1)
}
fn is_long_poll_tool(name: &str) -> bool {
    matches!(
        name,
        "iroha.transactions.wait"
            | "iroha.transactions.submit_and_wait"
            | "iroha.contracts.call_and_wait"
    )
}
/// Absolute deadline for collecting one MCP request or nested-route response body.
pub(crate) const MCP_BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Listener deadline covering the longest supported tool wait plus body collection and margin.
pub(crate) const MCP_ROUTE_EXECUTION_TIMEOUT: Duration = Duration::from_secs(10 * 60 + 15);
const MCP_TOOL_NOT_ALLOWED: &str = "tool_not_allowed";
const MCP_TOOL_NOT_FOUND: &str = "tool_not_found";
const MCP_TOOL_UNAVAILABLE: &str = "tool_unavailable";
const MCP_TOOL_EXECUTION_ERROR_CODE: &str = "tool_execution_error";
const MCP_BATCH_TOO_LARGE_CODE: &str = "batch_too_large";
const MCP_RESPONSE_TOO_LARGE_CODE: &str = "response_too_large";
const MCP_RESPONSE_READ_FAILED_CODE: &str = "response_read_failed";
const MCP_RESPONSE_TIMEOUT_CODE: &str = "response_timeout";
const TARGET_RESPONSE_TOO_LARGE_MESSAGE: &str =
    "target response body exceeds the configured MCP envelope byte limit";
const TARGET_RESPONSE_READ_FAILED_MESSAGE: &str = "target response body could not be read";
const TARGET_RESPONSE_TIMEOUT_MESSAGE: &str = "target response body read timed out";
const MCP_STRICT_BODY_SCHEMA_EXTENSION: &str = "x-iroha-mcp-strict-body";
const NONZERO_UPPER_HEX_PATTERN: &str = "^(?!0+$)(?:[0-9A-F]{2})+$";
const GOVERNANCE_PROPOSAL_ID_V1_PATTERN: &str = "^[0-9a-f]{64}$";
const HEADER_X_API_TOKEN: &str = "x-api-token";
const HEADER_MCP_PROTOCOL_VERSION: &str = protocol::HEADER_PROTOCOL_VERSION;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExactJsonRpcId {
    kind: ExactJsonRpcIdKind,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ExactJsonRpcIdKind {
    String(String),
    I64(i64),
    U64(u64),
}

impl ExactJsonRpcId {
    fn from_value(value: &Value) -> Option<Self> {
        let kind = match value {
            Value::String(value) => ExactJsonRpcIdKind::String(value.clone()),
            Value::Number(json::native::Number::I64(value)) => ExactJsonRpcIdKind::I64(*value),
            Value::Number(json::native::Number::U64(value)) => ExactJsonRpcIdKind::U64(*value),
            Value::Number(json::native::Number::U128(value)) => {
                ExactJsonRpcIdKind::U64(u64::try_from(*value).ok()?)
            }
            _ => return None,
        };
        Some(Self { kind })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct McpInflightKey {
    client_fingerprint: [u8; 32],
    request_id: ExactJsonRpcId,
}

struct McpInflightEntry {
    cancellation_nonce: [u8; 32],
    cancellation: tokio::sync::watch::Sender<bool>,
}

/// Process-local registry for best-effort cancellation of exact authenticated MCP calls.
#[derive(Default)]
pub(crate) struct McpInflightRegistry {
    entries: Mutex<HashMap<McpInflightKey, McpInflightEntry>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum McpInflightRegistrationError {
    Duplicate,
    Capacity,
    InvalidNonce,
}

struct McpInflightRegistration {
    registry: Arc<McpInflightRegistry>,
    key: McpInflightKey,
    cancellation: tokio::sync::watch::Receiver<bool>,
}

impl McpInflightRegistry {
    fn register(
        self: &Arc<Self>,
        key: McpInflightKey,
        cancellation_nonce: [u8; 32],
        capacity: usize,
    ) -> Result<McpInflightRegistration, McpInflightRegistrationError> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.contains_key(&key) {
            return Err(McpInflightRegistrationError::Duplicate);
        }
        if entries.len() >= capacity {
            return Err(McpInflightRegistrationError::Capacity);
        }
        let (cancellation, receiver) = tokio::sync::watch::channel(false);
        entries.insert(
            key.clone(),
            McpInflightEntry {
                cancellation_nonce,
                cancellation,
            },
        );
        drop(entries);
        Ok(McpInflightRegistration {
            registry: Arc::clone(self),
            key,
            cancellation: receiver,
        })
    }

    fn cancel(&self, key: &McpInflightKey, cancellation_nonce: &[u8; 32]) -> bool {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = entries.get(key) else {
            return false;
        };
        if entry.cancellation_nonce != *cancellation_nonce {
            return false;
        }
        entry.cancellation.send_replace(true);
        true
    }
}

impl McpInflightRegistration {
    async fn cancelled(&mut self) {
        if *self.cancellation.borrow() {
            return;
        }
        while self.cancellation.changed().await.is_ok() {
            if *self.cancellation.borrow() {
                return;
            }
        }
    }
}

impl Drop for McpInflightRegistration {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.remove(&self.key);
    }
}

/// Result of executing one request-bearing MCP JSON-RPC message.
pub(crate) enum JsonRpcRequestOutcome {
    /// A JSON-RPC response must be returned to the caller.
    Response(Value),
    /// The exact authenticated request was cancelled; no JSON-RPC response is emitted.
    Cancelled,
}
static ADVERTISED_REGEX_CACHE: LazyLock<RwLock<BTreeMap<String, regex::Regex>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));
#[cfg(test)]
static ADVERTISED_REGEX_COMPILE_COUNTS: LazyLock<RwLock<BTreeMap<String, usize>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));
const HEADER_X_IROHA_ACCOUNT: &str = "x-iroha-account";
const HEADER_X_IROHA_SIGNATURE: &str = "x-iroha-signature";
const HEADER_X_IROHA_TIMESTAMP_MS: &str = "x-iroha-timestamp-ms";
const HEADER_X_IROHA_NONCE: &str = "x-iroha-nonce";
const HEADER_X_IROHA_WITNESS: &str = "x-iroha-witness";
const CANONICAL_PADDED_BASE64_PATTERN: &str =
    "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";
const CANONICAL_ACCOUNT_HEADER_PATTERN: &str = "^(?:0x(?:[0-9a-f]{2})+|[!-~]+@[!-~]+)$";
const CANONICAL_SIGNATURE_MAX_ENCODED_BYTES: usize =
    ((crate::app_auth::CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 + 2) / 3) * 4;
const CANONICAL_WITNESS_MAX_ENCODED_BYTES: usize =
    ((crate::app_auth::CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1 + 2) / 3) * 4;
// Canonical public keys allow the longest 28-byte algorithm prefix, a colon,
// two at-most-two-byte multihash varints, and the bounded hex payload.
const OPERATOR_PUBLIC_KEY_MAX_LITERAL_BYTES: usize =
    28 + 1 + 2 * (2 + 2 + iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES);
const DEFAULT_TX_SUBMIT_WAIT_TIMEOUT_MS: u64 = 30_000;
const MAX_TX_SUBMIT_WAIT_TIMEOUT_MS: u64 = 600_000;
const DEFAULT_TX_SUBMIT_WAIT_POLL_INTERVAL_MS: u64 = 500;
const MIN_TX_SUBMIT_WAIT_POLL_INTERVAL_MS: u64 = 50;
const CANONICAL_TRANSACTION_HASH_HEX_BYTES: usize = iroha_crypto::Hash::LENGTH * 2;
const QUERY_PROJECTION_SHARD_CATALOG_FIELDS: &[&str] = &["asset_definition_id", "limit", "offset"];
/// Metadata and exact execution backing used for MCP dispatch.
#[derive(Debug, Clone)]
pub(crate) struct ToolSpec {
    pub(crate) name: String,
    pub(crate) description: String,
    backing: ToolBacking,
    pub(crate) input_schema: Value,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolEffect {
    Read,
    BuildInstruction,
    Write,
    Operator,
}

/// Purpose-built capabilities that execute locally inside the existing Torii
/// MCP handler instead of projecting another HTTP route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InProcessTool {
    TransactionsPrepare,
    TransactionsInspect,
}

impl InProcessTool {
    const fn name(self) -> &'static str {
        match self {
            Self::TransactionsPrepare => "iroha.transactions.prepare",
            Self::TransactionsInspect => "iroha.transactions.inspect",
        }
    }

    fn semantics(self) -> ToolSemantics {
        let (operation, requires_external_signature) = match self {
            Self::TransactionsPrepare => (OperationKind::Construct, true),
            Self::TransactionsInspect => (OperationKind::Observe, false),
        };
        ToolSemantics::try_new(
            operation,
            AuthorityClass::ListenerCredential,
            MutationNature::None,
            RetrySemantics::Safe,
            WorldBoundary::ToriiLocal,
            Sensitivity::Sensitive,
            requires_external_signature,
        )
        .expect("in-process transaction tools have non-mutating semantics")
    }
}

/// Exact execution backing for one advertised capability.
#[derive(Clone, Debug)]
enum ToolBacking {
    /// Re-enter one exact route through Torii's authoritative in-process router.
    Route {
        /// Compatibility effect used while route-backed tools migrate to explicit semantics.
        effect: ToolEffect,
        /// Exact target method.
        method: Method,
        /// Exact target path template.
        path_template: String,
    },
    /// Execute a pure bounded helper in the current Torii process.
    InProcess(InProcessTool),
}
/// Unforgeable-over-HTTP marker for a route request dispatched internally by MCP.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InternalMcpDispatch;
#[derive(Debug, Clone, Copy)]
struct MusubiV1ToolDefinition {
    name: &'static str,
    description: &'static str,
    path: &'static str,
    effect: ToolEffect,
}
const MUSUBI_V1_TOOL_DEFINITIONS: &[MusubiV1ToolDefinition] = &[
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.exact_package",
        description: "Fetch one exact structural Musubi V1 package record.",
        path: route_catalog::musubi::EXACT_PACKAGE.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.exact_release",
        description: "Fetch one coherent finalized Musubi V1 home/universal release snapshot.",
        path: route_catalog::musubi::EXACT_RELEASE.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.provider_bundle_attestation",
        description: "Audit one exact immutable Musubi V1 provider bundle attestation.",
        path: route_catalog::musubi::PROVIDER_BUNDLE_ATTESTATION.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.resolver_index",
        description: "Fetch a finalized page from the universal Musubi V1 resolver index.",
        path: route_catalog::musubi::RESOLVER_INDEX.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.versions",
        description: "Fetch a finalized page of structured Musubi V1 versions.",
        path: route_catalog::musubi::VERSIONS.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.maintainers",
        description: "Fetch accepted Musubi V1 package members and pending maintainer invitations.",
        path: route_catalog::musubi::MAINTAINERS.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.archive_locations",
        description: "Fetch a finalized page of renewable Musubi V1 archive locations.",
        path: route_catalog::musubi::ARCHIVE_LOCATIONS.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.archive_retention",
        description: "Classify a bounded exact batch of Musubi V1 archives for safe cache retention with its consensus-finalized block time.",
        path: route_catalog::musubi::ARCHIVE_RETENTION.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.alias",
        description: "Fetch one exact permanent Musubi V1 global alias record.",
        path: route_catalog::musubi::ALIAS.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.alias_history",
        description: "Fetch a finalized page of permanent Musubi V1 alias history.",
        path: route_catalog::musubi::ALIAS_HISTORY.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.ordered_prefix",
        description: "Fetch a finalized byte-ordered Musubi V1 package-prefix page.",
        path: route_catalog::musubi::ORDERED_PREFIX.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.queries.search",
        description: "Search finalized Musubi V1 package metadata by exact normalized terms.",
        path: route_catalog::musubi::SEARCH.path(),
        effect: ToolEffect::Read,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.namespace_binding_register",
        description: "Build an unsigned Musubi V1 namespace-binding registration.",
        path: route_catalog::musubi::NAMESPACE_BINDING_REGISTER.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.archive_register",
        description: "Build an unsigned Musubi V1 archive registration.",
        path: route_catalog::musubi::ARCHIVE_REGISTER.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.provider_bundle_attestation_register",
        description: "Build an unsigned immutable Musubi V1 provider bundle-attestation registration.",
        path: route_catalog::musubi::PROVIDER_BUNDLE_ATTESTATION_REGISTER.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.archive_location_add",
        description: "Build an unsigned Musubi V1 archive-location add or renewal.",
        path: route_catalog::musubi::ARCHIVE_LOCATION_ADD.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.archive_location_retire",
        description: "Build an unsigned Musubi V1 archive-location retirement.",
        path: route_catalog::musubi::ARCHIVE_LOCATION_RETIRE.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.release_publish",
        description: "Build an unsigned Musubi V1 release publication.",
        path: route_catalog::musubi::RELEASE_PUBLISH.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.release_yank_set",
        description: "Build an unsigned reversible Musubi V1 yank transition.",
        path: route_catalog::musubi::RELEASE_YANK_SET.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_metadata_set",
        description: "Build an unsigned Musubi V1 package metadata replacement.",
        path: route_catalog::musubi::PACKAGE_METADATA_SET.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_member_invite",
        description: "Build an unsigned Musubi V1 package-member invitation.",
        path: route_catalog::musubi::PACKAGE_MEMBER_INVITE.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_member_accept",
        description: "Build an unsigned Musubi V1 package-member invitation acceptance.",
        path: route_catalog::musubi::PACKAGE_MEMBER_ACCEPT.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_member_invitation_revoke",
        description: "Build an unsigned Musubi V1 pending package-member invitation revocation.",
        path: route_catalog::musubi::PACKAGE_MEMBER_INVITATION_REVOKE.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_member_set_role",
        description: "Build an unsigned Musubi V1 package-member role replacement.",
        path: route_catalog::musubi::PACKAGE_MEMBER_SET_ROLE.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_member_remove",
        description: "Build an unsigned Musubi V1 package-member removal.",
        path: route_catalog::musubi::PACKAGE_MEMBER_REMOVE.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.alias_register",
        description: "Build an unsigned paid permanent Musubi V1 alias registration.",
        path: route_catalog::musubi::ALIAS_REGISTER.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.package_recover",
        description: "Build an unsigned Parliament-enacted Musubi V1 package recovery.",
        path: route_catalog::musubi::PACKAGE_RECOVER.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.alias_retarget",
        description: "Build an unsigned Parliament-enacted Musubi V1 alias retarget.",
        path: route_catalog::musubi::ALIAS_RETARGET.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.artifact_takedown",
        description: "Build an unsigned Parliament-enacted Musubi V1 artifact takedown.",
        path: route_catalog::musubi::ARTIFACT_TAKEDOWN.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.registry_policy_set",
        description: "Build an unsigned Parliament-enacted Musubi V1 registry-policy update.",
        path: route_catalog::musubi::REGISTRY_POLICY_SET.path(),
        effect: ToolEffect::BuildInstruction,
    },
    MusubiV1ToolDefinition {
        name: "iroha.musubi.instructions.release_digest_assert",
        description: "Build an unsigned exact Musubi V1 release-digest assertion.",
        path: route_catalog::musubi::RELEASE_DIGEST_ASSERT.path(),
        effect: ToolEffect::BuildInstruction,
    },
];
fn musubi_v1_tool_definition(name: &str) -> Option<&'static MusubiV1ToolDefinition> {
    MUSUBI_V1_TOOL_DEFINITIONS
        .iter()
        .find(|definition| definition.name == name)
}
impl ToolSpec {
    fn route(
        name: String,
        description: String,
        effect: ToolEffect,
        method: Method,
        path_template: String,
        input_schema: Value,
    ) -> Self {
        Self {
            name,
            description,
            backing: ToolBacking::Route {
                effect,
                method,
                path_template,
            },
            input_schema,
        }
    }

    fn in_process(tool: InProcessTool, description: String, input_schema: Value) -> Self {
        Self {
            name: tool.name().to_owned(),
            description,
            backing: ToolBacking::InProcess(tool),
            input_schema,
        }
    }

    const fn backing(&self) -> &ToolBacking {
        &self.backing
    }

    fn route_backing(&self) -> Option<(ToolEffect, &Method, &str)> {
        let ToolBacking::Route {
            effect,
            method,
            path_template,
        } = &self.backing
        else {
            return None;
        };
        Some((*effect, method, path_template.as_str()))
    }

    pub(crate) fn descriptor(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("name".into(), Value::String(self.name.clone()));
        obj.insert(
            "description".into(),
            Value::String(self.description.clone()),
        );
        obj.insert(
            "inputSchema".into(),
            advertised_tool_input_schema(&self.input_schema),
        );
        obj.insert("outputSchema".into(), default_tool_output_schema());
        let semantics = tool_semantics(self);
        obj.insert("annotations".into(), semantics.annotations().into_value());
        let mut meta = Map::new();
        meta.insert("iroha/semantics".into(), semantics.metadata());
        if let Some(route_auth) = tool_route_auth_metadata(self) {
            meta.insert("iroha/routeAuth".into(), route_auth);
        }
        obj.insert("_meta".into(), Value::Object(meta));
        Value::Object(obj)
    }
}

fn tool_route_auth_metadata(tool: &ToolSpec) -> Option<Value> {
    let (_, method, path_template) = tool.route_backing()?;
    let descriptor =
        catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template)?;
    Some(norito::json!({
        "schemaVersion": (descriptor.auth_metadata_schema_version()),
        "stableRouteId": (descriptor.stable_route_id()),
        "authentication": (descriptor.authentication().as_str()),
        "admission": (descriptor.admission().as_str())
    }))
}
fn tool_semantics(tool: &ToolSpec) -> ToolSemantics {
    let (effect, method, path_template) = match tool.backing() {
        ToolBacking::InProcess(tool) => return tool.semantics(),
        ToolBacking::Route {
            effect,
            method,
            path_template,
        } => (*effect, method, path_template.as_str()),
    };
    let route =
        catalog_descriptor_for_method_path(CATALOG_PROJECTION_GROUPS, method, path_template);
    let operation = match effect {
        ToolEffect::Read => OperationKind::Observe,
        ToolEffect::BuildInstruction => OperationKind::Construct,
        ToolEffect::Write => OperationKind::Mutate,
        ToolEffect::Operator => match route.map(|route| route.effect()) {
            Some(
                RouteEffect::ReadOnly
                | RouteEffect::ExpensiveCompute
                | RouteEffect::LongLivedStream,
            ) => OperationKind::Observe,
            Some(RouteEffect::Mutation) | None => OperationKind::Mutate,
        },
    };
    let authority = if effect == ToolEffect::Operator {
        AuthorityClass::Operator
    } else {
        route
            .map(authority_for_route)
            .unwrap_or(AuthorityClass::ListenerCredential)
    };
    // TODO: Move audited `AdditiveOnly` declarations into explicit curated capability entries as
    // each legacy `ToolEffect` descriptor is migrated. Unknown mutations stay destructive.
    let mutation = mutation_nature_for_operation(operation, false);
    let retry = match operation {
        OperationKind::Observe | OperationKind::Construct => RetrySemantics::Safe,
        OperationKind::Mutate
            if path_template == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path() =>
        {
            RetrySemantics::ExactIdentityDeduplicated
        }
        OperationKind::Mutate => RetrySemantics::Unsafe,
    };
    let world = world_boundary_for_tool(&tool.name, path_template);
    let sensitivity = sensitivity_for(authority, world, route.map(|route| route.surface()));
    let requires_external_signature = operation == OperationKind::Construct
        || authority.requires_external_signature()
        || path_template == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path();
    ToolSemantics::try_new(
        operation,
        authority,
        mutation,
        retry,
        world,
        sensitivity,
        requires_external_signature,
    )
    .expect("MCP semantic classifier must preserve operation/mutation invariants")
}
// Visit only JSON Schema subschemas. Values of const/enum/default/examples and
// extension metadata are application data, even when they contain schema keys.
fn visit_schema_children(schema: &mut Map, depth: usize, mut visit: impl FnMut(&mut Value, usize)) {
    for (keyword, value) in schema {
        match keyword.as_str() {
            "properties" | "patternProperties" | "dependentSchemas" | "$defs" | "definitions"
            | "dependencies" => {
                if let Some(children) = value.as_object_mut() {
                    for child in children.values_mut() {
                        // Legacy dependencies can also contain property-name arrays.
                        if child.is_object() || matches!(child, Value::Bool(_)) {
                            visit(child, depth + 2);
                        }
                    }
                }
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                if let Some(children) = value.as_array_mut() {
                    for child in children {
                        visit(child, depth + 2);
                    }
                }
            }
            "items" if value.is_array() => {
                for child in value.as_array_mut().expect("schema array") {
                    visit(child, depth + 2);
                }
            }
            "additionalProperties"
            | "additionalItems"
            | "items"
            | "contains"
            | "propertyNames"
            | "not"
            | "if"
            | "then"
            | "else"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contentSchema" => {
                visit(value, depth + 1);
            }
            _ => {}
        }
    }
}

fn advertised_tool_input_schema(schema: &Value) -> Value {
    // Norito permits 32 nested JSON containers. Keep each schema segment within
    // 12 containers, including its root/$defs placement, leaving space for the
    // descriptor, JSON-RPC envelope, and literal keyword values. Literal data
    // remains subject to the final serializer's unchanged depth/byte bounds.
    const MAX_SCHEMA_SEGMENT_DEPTH: usize = 12;

    fn factor(
        schema: &mut Value,
        depth: usize,
        definitions: &mut Map,
        reserved: &mut BTreeSet<String>,
        next: &mut usize,
        scoped_references: &mut bool,
    ) {
        let Some(object) = schema.as_object_mut() else {
            return;
        };
        *scoped_references |= [
            "$id",
            "id",
            "$anchor",
            "$dynamicAnchor",
            "$ref",
            "$dynamicRef",
            "$recursiveRef",
        ]
        .iter()
        .any(|keyword| object.contains_key(*keyword));
        *scoped_references |= object.get("$defs").is_some_and(|value| !value.is_object());
        if depth >= MAX_SCHEMA_SEGMENT_DEPTH {
            let name = loop {
                let name = format!("mcp_schema_{next}");
                *next += 1;
                if reserved.insert(name.clone()) {
                    break name;
                }
            };
            let mut definition = std::mem::replace(schema, Value::Null);
            // inputSchema -> $defs -> definition: three JSON containers.
            factor(
                &mut definition,
                3,
                definitions,
                reserved,
                next,
                scoped_references,
            );
            definitions.insert(name.clone(), definition);
            *schema = norito::json!({ "$ref": (format!("#/$defs/{name}")) });
        } else {
            visit_schema_children(object, depth, |child, child_depth| {
                factor(
                    child,
                    child_depth,
                    definitions,
                    reserved,
                    next,
                    scoped_references,
                );
            });
        }
    }

    let original = sanitize_tool_input_schema(schema);
    let mut advertised = original.clone();
    let mut reserved = advertised
        .get("$defs")
        .and_then(Value::as_object)
        .map(|definitions| definitions.keys().cloned().collect())
        .unwrap_or_default();
    let mut definitions = Map::new();
    let mut scoped_references = false;
    factor(
        &mut advertised,
        1,
        &mut definitions,
        &mut reserved,
        &mut 0,
        &mut scoped_references,
    );
    // Registry schemas are expanded and ref-free. Preserve any future resource
    // identifiers verbatim rather than changing their reference resolution base.
    if scoped_references {
        return original;
    }
    if !definitions.is_empty() {
        let root = advertised.as_object_mut().expect("factored schema object");
        let existing = root
            .entry("$defs".into())
            .or_insert_with(|| Value::Object(Map::new()));
        existing
            .as_object_mut()
            .expect("schema definitions object")
            .extend(definitions);
    }
    advertised
}

fn sanitize_tool_input_schema(schema: &Value) -> Value {
    let root = match schema {
        Value::Object(map) => map,
        _ => {
            return norito::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            });
        }
    };
    let strict_body = root
        .get(MCP_STRICT_BODY_SCHEMA_EXTENSION)
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_object_schema = root.get("type").and_then(Value::as_str) == Some("object");
    if is_object_schema {
        let mut strict = schema.clone();
        if let Some(object) = strict.as_object_mut() {
            object.remove(MCP_STRICT_BODY_SCHEMA_EXTENSION);
        }
        stricten_tool_input_schema(&mut strict, false, strict_body);
        return strict;
    }
    norito::json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}
fn stricten_tool_input_schema(schema: &mut Value, inside_body: bool, strict_body: bool) {
    stricten_tool_input_schema_inner(schema, inside_body, strict_body, true);
}
fn stricten_tool_input_schema_inner(
    schema: &mut Value,
    inside_body: bool,
    strict_body: bool,
    close_current_object: bool,
) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    let is_object_schema = object.get("type").and_then(Value::as_str) == Some("object")
        || object.contains_key("properties");
    if is_object_schema && close_current_object {
        if inside_body && strict_body {
            object.insert("additionalProperties".into(), Value::Bool(false));
        } else {
            object.insert("additionalProperties".into(), Value::Bool(inside_body));
        }
    }
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        for (name, value) in properties {
            stricten_tool_input_schema_inner(
                value,
                inside_body || name == "body",
                strict_body,
                true,
            );
        }
    }
    for keyword in ["items", "additionalItems", "contains"] {
        if let Some(value) = object.get_mut(keyword) {
            stricten_tool_input_schema_inner(value, inside_body, strict_body, true);
        }
    }
    for keyword in ["anyOf", "oneOf", "allOf"] {
        if let Some(values) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for value in values {
                // Applicator branches constrain the same instance as their
                // parent. Do not synthesize a closed object around a partial
                // branch, but continue tightening objects declared below it.
                stricten_tool_input_schema_inner(value, inside_body, strict_body, false);
            }
        }
    }
    if let Some(value) = object.get_mut("not") {
        stricten_tool_input_schema_inner(value, inside_body, strict_body, false);
    }
    for keyword in ["if", "then", "else"] {
        if let Some(value) = object.get_mut(keyword) {
            // Conditional schemas constrain the same instance as their parent.
            // Preserve their own open-world semantics while still tightening
            // any nested object properties they describe.
            stricten_tool_input_schema_inner(value, inside_body, strict_body, false);
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParameterInfo {
    name: String,
    location: String,
    required: bool,
    schema: Value,
}
#[derive(Debug, Clone, Copy)]
struct CatalogProjectionGroup {
    routes: &'static [RouteDescriptor],
    enabled_features: EnabledFeatures<'static>,
}
const COMPILED_CATALOG_FEATURES: &[&str] = &[
    #[cfg(feature = "app_api")]
    "app_api",
    #[cfg(feature = "profiling")]
    "profiling",
    #[cfg(feature = "schema")]
    "schema",
    #[cfg(feature = "telemetry")]
    "telemetry",
    #[cfg(feature = "connect")]
    "connect",
];
// OpenAPI-derived tools fail closed against this catalog. A route which has not
// entered the authoritative catalog is not an MCP operation; adding it to
// OpenAPI alone can never expand the agent-facing tool surface.
const CATALOG_PROJECTION_GROUPS: &[CatalogProjectionGroup] = &[CatalogProjectionGroup {
    routes: route_catalog::CATALOGED_ROUTES,
    enabled_features: EnabledFeatures::new(COMPILED_CATALOG_FEATURES),
}];
static VALIDATED_MCP_ROUTE_CATALOG: LazyLock<()> = LazyLock::new(|| {
    for group in CATALOG_PROJECTION_GROUPS {
        if let Err(errors) = RouteCatalog::new(group.routes).validate() {
            panic!("invalid Torii route catalog used for MCP projection: {errors:?}");
        }
    }
});
/// Build the MCP tool registry from OpenAPI operations.
pub(crate) fn build_tool_specs(cfg: &iroha_config::parameters::actual::ToriiMcp) -> Vec<ToolSpec> {
    LazyLock::force(&VALIDATED_MCP_ROUTE_CATALOG);
    let mut tools = Vec::new();
    let spec = openapi::compiled_spec();
    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return tools;
    };
    let allow_operator_routes = cfg.expose_operator_routes
        && cfg.profile == iroha_config::parameters::actual::ToriiMcpProfile::Operator;
    for (path, path_item) in paths {
        let Some(path_map) = path_item.as_object() else {
            continue;
        };
        let path_parameters = parse_parameters(spec, path_map.get("parameters"));
        for method_key in ["get", "post", "put", "patch", "delete", "head", "options"] {
            let Some(operation) = path_map.get(method_key).and_then(Value::as_object) else {
                continue;
            };
            let Some(method) = method_from_key(method_key) else {
                continue;
            };
            let catalog_descriptor = catalog_descriptor_for_method_path(
                CATALOG_PROJECTION_GROUPS,
                &method,
                path.as_str(),
            );
            if catalog_descriptor.is_some_and(catalog_route_requires_operator)
                && !allow_operator_routes
            {
                continue;
            }
            if should_skip_operation(spec, path, operation, allow_operator_routes)
                || catalog_mcp_projection_decision(
                    CATALOG_PROJECTION_GROUPS,
                    &method,
                    path.as_str(),
                ) != Some(true)
            {
                continue;
            }
            // Keep OpenAPI-derived names stable regardless of mutable `operationId` fields.
            let operation_id = generated_operation_id(method_key, path);
            let description = operation
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| operation.get("description").and_then(Value::as_str))
                .unwrap_or("Torii API operation")
                .to_owned();
            let mut parameters = path_parameters.clone();
            parameters.extend(parse_parameters(spec, operation.get("parameters")));
            let mut input_schema =
                build_input_schema(spec, path, &parameters, operation.get("requestBody"));
            harden_governance_openapi_input_schema(
                spec,
                operation.get("requestBody"),
                &method,
                path,
                &mut input_schema,
            );
            let effect = openapi_tool_effect(path, method_key, operation);
            tools.push(ToolSpec::route(
                format!("torii.{operation_id}"),
                description,
                effect,
                method,
                path.clone(),
                input_schema,
            ));
        }
    }
    tools.push(iroha_connect_ws_ticket_tool());
    tools.push(iroha_connect_session_create_tool());
    tools.push(iroha_connect_session_delete_tool());
    tools.push(iroha_connect_session_status_tool());
    tools.push(iroha_vpn_profile_tool());
    tools.push(iroha_vpn_quotes_create_tool());
    tools.push(iroha_vpn_sessions_create_tool());
    tools.push(iroha_vpn_sessions_get_tool());
    tools.push(iroha_vpn_receipts_list_tool());
    tools.push(iroha_vpn_receipts_submit_tool());
    tools.push(iroha_health_tool());
    tools.push(iroha_parameters_get_tool());
    tools.push(iroha_node_capabilities_tool());
    tools.push(iroha_node_query_projection_shard_catalog_tool());
    tools.push(iroha_node_query_projection_checkpoint_tool());
    tools.push(iroha_da_ingest_tool());
    tools.push(iroha_da_proof_policies_tool());
    tools.push(iroha_da_manifests_get_tool());
    tools.push(iroha_da_commitments_list_tool());
    tools.push(iroha_da_commitments_prove_tool());
    tools.push(iroha_da_commitments_verify_tool());
    tools.push(iroha_da_pin_intents_list_tool());
    tools.push(iroha_da_pin_intents_prove_tool());
    tools.push(iroha_da_pin_intents_verify_tool());
    tools.push(iroha_runtime_abi_active_tool());
    tools.push(iroha_runtime_abi_hash_tool());
    tools.push(iroha_runtime_metrics_tool());
    tools.push(iroha_runtime_upgrades_list_tool());
    tools.push(iroha_runtime_upgrades_propose_tool());
    tools.push(iroha_runtime_upgrades_activate_tool());
    tools.push(iroha_runtime_upgrades_cancel_tool());
    tools.push(iroha_bridge_finality_proof_tool());
    tools.push(iroha_bridge_finality_bundle_tool());
    tools.push(iroha_proofs_query_tool());
    tools.push(iroha_gov_contract_get_tool());
    tools.push(iroha_gov_proposals_deploy_contract_tool());
    tools.push(iroha_gov_parliament_attempt_draft_tool());
    tools.push(iroha_gov_parliament_attempt_get_tool());
    tools.push(iroha_gov_parliament_timed_ovn_casting_context_get_tool());
    tools.push(iroha_gov_parliament_timed_ovn_casting_proof_get_tool());
    tools.push(iroha_gov_parliament_tle_release_context_get_tool());
    tools.push(iroha_gov_parliament_tle_partial_release_create_tool());
    tools.push(iroha_gov_parliament_transition_draft_tool());
    tools.push(iroha_gov_proposals_get_tool());
    tools.push(iroha_gov_locks_get_tool());
    tools.push(iroha_gov_referenda_get_tool());
    tools.push(iroha_gov_tally_get_tool());
    tools.push(iroha_gov_ballots_zk_v1_tool());
    tools.push(iroha_gov_ballots_zk_v1_ballot_proof_tool());
    tools.push(iroha_gov_ballots_plain_tool());
    tools.push(iroha_gov_protected_namespaces_list_tool());
    tools.push(iroha_gov_protected_namespaces_update_tool());
    tools.push(iroha_gov_unlocks_stats_tool());
    tools.push(iroha_gov_citizens_count_tool());
    tools.push(iroha_aliases_resolve_tool());
    tools.push(iroha_aliases_resolve_index_tool());
    tools.push(iroha_aliases_by_account_tool());
    tools.push(iroha_contracts_code_get_tool());
    tools.push(iroha_contracts_code_bytes_get_tool());
    tools.push(iroha_contracts_call_tool());
    tools.push(iroha_contracts_view_tool());
    tools.push(iroha_contracts_call_and_wait_tool());
    tools.push(iroha_contracts_state_get_tool());
    tools.push(iroha_accounts_list_tool());
    tools.push(iroha_accounts_get_tool());
    tools.push(iroha_accounts_qr_tool());
    tools.push(iroha_accounts_query_tool());
    tools.push(iroha_accounts_onboard_plan_tool());
    tools.push(iroha_accounts_onboard_prepare_tool());
    tools.push(iroha_accounts_onboard_submit_tool());
    if paths.contains_key("/v1/accounts/faucet/policy") {
        tools.push(iroha_accounts_faucet_policy_tool());
    }
    if paths.contains_key("/v1/accounts/faucet/prepare")
        && paths.contains_key("/v1/accounts/faucet")
    {
        tools.push(iroha_accounts_faucet_prepare_tool());
        tools.push(iroha_accounts_faucet_submit_tool());
    }
    tools.push(iroha_account_transactions_tool());
    tools.push(iroha_account_history_tool());
    tools.push(iroha_account_history_query_tool());
    tools.push(iroha_contracts_activity_query_tool());
    tools.push(iroha_contracts_events_query_tool());
    tools.push(iroha_explorer_accounts_query_tool());
    tools.push(iroha_explorer_domains_query_tool());
    tools.push(iroha_explorer_asset_definitions_query_tool());
    tools.push(iroha_explorer_assets_query_tool());
    tools.push(iroha_explorer_nfts_query_tool());
    tools.push(iroha_explorer_rwas_query_tool());
    tools.push(iroha_explorer_blocks_query_tool());
    tools.push(iroha_explorer_transactions_query_tool());
    tools.push(iroha_explorer_transactions_latest_query_tool());
    tools.push(iroha_explorer_instructions_query_tool());
    tools.push(iroha_explorer_instructions_latest_query_tool());
    tools.push(iroha_account_transactions_query_tool());
    tools.push(iroha_transactions_query_tool());
    tools.push(iroha_account_assets_tool());
    tools.push(iroha_account_assets_query_tool());
    tools.push(iroha_account_permissions_tool());
    tools.push(iroha_account_permissions_query_tool());
    tools.push(iroha_subscriptions_plans_query_tool());
    tools.push(iroha_subscriptions_query_tool());
    tools.push(iroha_uaid_manifests_tool());
    tools.push(iroha_uaid_manifests_query_tool());
    tools.push(iroha_account_portfolio_tool());
    tools.push(iroha_domains_list_tool());
    tools.push(iroha_domains_get_tool());
    tools.push(iroha_domains_query_tool());
    tools.extend(iroha_musubi_v1_tools(spec));
    tools.push(iroha_subscriptions_plans_list_tool());
    tools.push(iroha_subscriptions_plans_create_tool());
    tools.push(iroha_subscriptions_list_tool());
    tools.push(iroha_subscriptions_create_tool());
    tools.push(iroha_subscriptions_get_tool());
    tools.push(iroha_subscriptions_pause_tool());
    tools.push(iroha_subscriptions_resume_tool());
    tools.push(iroha_subscriptions_cancel_tool());
    tools.push(iroha_subscriptions_keep_tool());
    tools.push(iroha_subscriptions_usage_tool());
    tools.push(iroha_subscriptions_charge_now_tool());
    tools.push(iroha_asset_definitions_tool());
    tools.push(iroha_asset_definitions_get_tool());
    tools.push(iroha_asset_definitions_query_tool());
    tools.push(iroha_asset_holders_tool());
    tools.push(iroha_asset_holders_query_tool());
    tools.push(iroha_assets_list_tool());
    tools.push(iroha_assets_get_tool());
    tools.push(iroha_nfts_chain_list_tool());
    tools.push(iroha_nfts_list_tool());
    tools.push(iroha_nfts_get_tool());
    tools.push(iroha_nfts_query_tool());
    tools.push(iroha_rwas_chain_list_tool());
    tools.push(iroha_rwas_list_tool());
    tools.push(iroha_rwas_get_tool());
    tools.push(iroha_rwas_query_tool());
    tools.push(iroha_iso20022_pacs008_submit_tool());
    tools.push(iroha_iso20022_pacs009_submit_tool());
    tools.push(iroha_iso20022_pacs002_submit_tool());
    tools.push(iroha_iso20022_pacs004_submit_tool());
    tools.push(iroha_iso20022_camt056_submit_tool());
    tools.push(iroha_iso20022_sese023_submit_tool());
    tools.push(iroha_iso20022_sese024_submit_tool());
    tools.push(iroha_iso20022_sese025_submit_tool());
    tools.push(iroha_iso20022_colr012_submit_tool());
    tools.push(iroha_iso20022_status_get_tool());
    tools.push(iroha_queries_submit_tool());
    tools.push(iroha_transactions_list_tool());
    tools.push(iroha_transactions_get_tool());
    tools.push(iroha_instructions_list_tool());
    tools.push(iroha_instructions_get_tool());
    tools.push(iroha_blocks_list_tool());
    tools.push(iroha_blocks_get_tool());
    tools.push(iroha_transactions_prepare_tool());
    tools.push(iroha_transactions_inspect_tool());
    tools.push(iroha_transactions_submit_tool());
    tools.push(iroha_transactions_submit_and_wait_tool());
    tools.push(iroha_transactions_wait_tool());
    tools.push(iroha_transactions_status_tool());
    // Generated OpenAPI tools require an explicit MCP projection. Purpose-built
    // iroha.* tools form a separate audited allowlist and still follow catalog
    // feature gates.
    retain_catalog_mcp_tools(&mut tools, CATALOG_PROJECTION_GROUPS);
    apply_catalog_auth_schemas_to_tools(&mut tools, CATALOG_PROJECTION_GROUPS);
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    if let Err(error) = validate_tool_registry(&tools, CATALOG_PROJECTION_GROUPS) {
        panic!("invalid Torii MCP tool registry: {error}");
    }
    tools
}

fn canonical_signature_tuple_headers_schema(description: &str) -> Value {
    norito::json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "X-Iroha-Account",
            "X-Iroha-Signature",
            "X-Iroha-Timestamp-Ms",
            "X-Iroha-Nonce"
        ],
        "properties": {
            "X-Iroha-Account": {
                "type": "string",
                "minLength": 1,
                "maxLength": (crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1),
                "pattern": (CANONICAL_ACCOUNT_HEADER_PATTERN),
                "description": "Exact lowercase canonical 0x account-address hex or exact canonical printable-ASCII account alias; I105 is not an HTTP header encoding. The pattern is a lexical prefilter; Torii performs exact canonical address or alias parsing before dispatch."
            },
            "X-Iroha-Signature": {
                "type": "string",
                "minLength": 4,
                "maxLength": (CANONICAL_SIGNATURE_MAX_ENCODED_BYTES),
                "pattern": (CANONICAL_PADDED_BASE64_PATTERN)
            },
            "X-Iroha-Timestamp-Ms": {
                "type": "string",
                "minLength": 1,
                "maxLength": 20,
                "pattern": "^(0|[1-9][0-9]*)$"
            },
            "X-Iroha-Nonce": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[!-~]+$"
            }
        },
        "description": description
    })
}

fn canonical_account_auth_headers_schema(description: &str) -> Value {
    let mut schema = canonical_signature_tuple_headers_schema(description);
    let object = schema
        .as_object_mut()
        .expect("canonical authentication header schema is an object");
    object.remove("required");
    let properties = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("canonical authentication header properties are an object");
    properties.insert(
        crate::HEADER_WITNESS.to_owned(),
        norito::json!({
            "type": "string",
            "minLength": 4,
            "maxLength": (CANONICAL_WITNESS_MAX_ENCODED_BYTES),
            "pattern": (CANONICAL_PADDED_BASE64_PATTERN),
            "description": "Canonical padded-base64 Norito V1 canonical-request witness."
        }),
    );
    object.insert(
        "oneOf".to_owned(),
        norito::json!([
            {
                "required": [
                    "X-Iroha-Account",
                    "X-Iroha-Signature",
                    "X-Iroha-Timestamp-Ms",
                    "X-Iroha-Nonce"
                ],
                "not": { "required": ["X-Iroha-Witness"] }
            },
            {
                "required": ["X-Iroha-Witness"],
                "not": {
                    "anyOf": [
                        { "required": ["X-Iroha-Signature"] },
                        { "required": ["X-Iroha-Timestamp-Ms"] },
                        { "required": ["X-Iroha-Nonce"] }
                    ]
                }
            }
        ]),
    );
    schema
}
fn operator_auth_headers_schema() -> Value {
    norito::json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "X-Iroha-Operator-Public-Key",
            "X-Iroha-Operator-Timestamp-Ms",
            "X-Iroha-Operator-Nonce",
            "X-Iroha-Operator-Signature"
        ],
        "properties": {
            "X-Iroha-Operator-Public-Key": {
                "type": "string",
                "minLength": 1,
                "maxLength": (OPERATOR_PUBLIC_KEY_MAX_LITERAL_BYTES),
                "pattern": "^[!-~]+$",
                "description": "Canonical Iroha multihash public-key literal. The pattern is a lexical prefilter; Torii performs exact canonical public-key parsing."
            },
            "X-Iroha-Operator-Timestamp-Ms": {
                "type": "string",
                "minLength": 1,
                "maxLength": 20,
                "pattern": "^(0|[1-9][0-9]*)$"
            },
            "X-Iroha-Operator-Nonce": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[!-~]+$"
            },
            "X-Iroha-Operator-Signature": {
                "type": "string",
                "minLength": 4,
                "maxLength": (CANONICAL_SIGNATURE_MAX_ENCODED_BYTES),
                "pattern": (CANONICAL_PADDED_BASE64_PATTERN)
            }
        },
        "description": "Complete exact-network operator signature tuple for the exact target method, path, query, and body."
    })
}
fn visible_tools_for_policy<'a>(
    cfg: &iroha_config::parameters::actual::ToriiMcp,
    tools: &'a [ToolSpec],
) -> Vec<&'a ToolSpec> {
    tools
        .iter()
        .filter(|tool| is_tool_allowed_by_policy(cfg, tool))
        .collect()
}

fn tool_is_runtime_available(app: &SharedAppState, tool: &ToolSpec) -> bool {
    if matches!(
        tool.name.as_str(),
        "iroha.accounts.faucet.policy"
            | "iroha.accounts.faucet.prepare"
            | "iroha.accounts.faucet.submit"
    ) {
        #[cfg(feature = "app_api")]
        return app.account_faucet.is_some();
        #[cfg(not(feature = "app_api"))]
        return false;
    }
    true
}

fn visible_tools_for_app(app: &SharedAppState) -> Vec<&ToolSpec> {
    visible_tools_for_policy(&app.mcp, app.mcp_tools.as_slice())
        .into_iter()
        .filter(|tool| tool_is_runtime_available(app, tool))
        .collect()
}

fn server_info_payload() -> Map {
    let mut server_info = Map::new();
    server_info.insert("name".into(), Value::String("iroha-torii-mcp".to_owned()));
    server_info.insert(
        "version".into(),
        Value::String(env!("CARGO_PKG_VERSION").to_owned()),
    );
    server_info
}
fn modern_discovery_payload(tools: &[&ToolSpec]) -> Value {
    let toolset_version = compute_toolset_version(tools);
    let mut tools_capability = Map::new();
    tools_capability.insert("listChanged".into(), Value::Bool(false));
    let mut capabilities = Map::new();
    capabilities.insert("tools".into(), Value::Object(tools_capability));
    capabilities.insert("resources".into(), resources::resources_capability());
    capabilities.insert(
        "extensions".into(),
        norito::json!({
            "org.hyperledger.iroha/tools": {
                "toolsetVersion": (toolset_version),
                "callBatch": {
                    "method": "tools/call_batch",
                    "maxDispatches": MAX_JSONRPC_BATCH_DISPATCHES
                }
            }
        }),
    );
    norito::json!({
        "supportedVersions": [(protocol::MODERN_PROTOCOL_VERSION)],
        "capabilities": (Value::Object(capabilities)),
        "instructions": "Prefer curated iroha.* capabilities and rediscover schemas before each workflow. Keep signing keys and authentication secrets outside MCP. Prepare and inspect unsigned operations, sign with an external wallet or deployment-owned signer, then submit only the signed envelope.",
        "_meta": {
            "io.modelcontextprotocol/serverInfo": (Value::Object(server_info_payload()))
        }
    })
}
fn default_tool_output_schema() -> Value {
    norito::json!({
        "type": "object",
        "description": "Tool structured output payload. Route-dispatched tools include status/headers/content_type/body.",
        "properties": {
            "status": { "type": "integer", "minimum": 100, "maximum": 599 },
            "headers": {
                "type": "object",
                "additionalProperties": { "type": "string" }
            },
            "content_type": {
                "oneOf": [{ "type": "string" }, { "type": "null" }]
            },
            "body": {}
        },
        "additionalProperties": true
    })
}
fn compute_toolset_version(tools: &[&ToolSpec]) -> String {
    let mut hasher = Blake3Hasher::new();
    for tool in tools {
        let rendered =
            norito::json::to_string(&tool.descriptor()).unwrap_or_else(|_| tool.name.clone());
        hasher.update(rendered.as_bytes());
        hasher.update(&[0x0a]);
    }
    hasher.finalize().to_hex().to_string()
}
fn is_tool_allowed_by_policy(
    cfg: &iroha_config::parameters::actual::ToriiMcp,
    tool: &ToolSpec,
) -> bool {
    use iroha_config::parameters::actual::ToriiMcpProfile;
    if tool_requires_operator(tool)
        && !(cfg.expose_operator_routes && cfg.profile == ToriiMcpProfile::Operator)
    {
        return false;
    }
    let semantics = tool_semantics(tool);
    let profile_allowed = match (cfg.profile, semantics.operation(), semantics.authority()) {
        (ToriiMcpProfile::Operator, _, _) => true,
        (ToriiMcpProfile::Writer, _, AuthorityClass::Operator) => false,
        (ToriiMcpProfile::Writer, _, _) => true,
        (ToriiMcpProfile::ReadOnly, OperationKind::Observe | OperationKind::Construct, _) => true,
        (ToriiMcpProfile::ReadOnly, OperationKind::Mutate, _) => false,
    };
    if !profile_allowed {
        return false;
    }
    if cfg
        .deny_tool_prefixes
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .any(|prefix| !prefix.is_empty() && tool.name.starts_with(prefix))
    {
        return false;
    }
    if cfg.allow_tool_prefixes.is_empty() {
        return true;
    }
    cfg.allow_tool_prefixes
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .any(|prefix| !prefix.is_empty() && tool.name.starts_with(prefix))
}
fn openapi_tool_effect(path: &str, method_key: &str, operation: &Map) -> ToolEffect {
    let value = operation
        .get(openapi::TOOL_EFFECT_EXTENSION)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "OpenAPI operation {method_key} {path} is missing `{}`",
                openapi::TOOL_EFFECT_EXTENSION
            )
        });
    parse_tool_effect(value).unwrap_or_else(|| {
        panic!(
            "OpenAPI operation {method_key} {path} has invalid `{}` value `{value}`",
            openapi::TOOL_EFFECT_EXTENSION
        )
    })
}
fn parse_tool_effect(value: &str) -> Option<ToolEffect> {
    match value {
        "read" => Some(ToolEffect::Read),
        "build_instruction" => Some(ToolEffect::BuildInstruction),
        "write" => Some(ToolEffect::Write),
        "operator" => Some(ToolEffect::Operator),
        _ => None,
    }
}
fn manual_tool_effect_from_name(name: &str) -> ToolEffect {
    if is_operator_tool_name(name) {
        return ToolEffect::Operator;
    }
    if let Some(definition) = musubi_v1_tool_definition(name) {
        return definition.effect;
    }
    if is_audited_manual_read_tool_name(name) {
        return ToolEffect::Read;
    }
    ToolEffect::Write
}
fn is_operator_tool_name(name: &str) -> bool {
    name == "iroha.gov.protected_namespaces.update"
}
fn is_audited_manual_read_tool_name(name: &str) -> bool {
    matches!(
        name,
        "iroha.connect.session.status"
            | "iroha.contracts.view"
            | "iroha.vpn.profile"
            | "iroha.vpn.sessions.get"
            | "iroha.vpn.receipts.list"
            | "iroha.health"
            | "iroha.accounts.faucet.policy"
            | "iroha.parameters.get"
            | "iroha.node.capabilities"
            | "iroha.node.query_projection_checkpoint"
            | "iroha.da.proof_policies"
            | "iroha.runtime.abi.active"
            | "iroha.runtime.abi.hash"
            | "iroha.runtime.metrics"
            | "iroha.runtime.upgrades.list"
            | "iroha.gov.proposals.get"
            | "iroha.gov.locks.get"
            | "iroha.gov.referenda.get"
            | "iroha.gov.tally.get"
            | "iroha.gov.protected_namespaces.list"
            | "iroha.gov.unlocks.stats"
            | "iroha.gov.citizens.count"
            | "iroha.nfts.chain.list"
            | "iroha.rwas.chain.list"
            | "iroha.iso20022.status.get"
            | "iroha.da.commitments.list"
            | "iroha.da.commitments.prove"
            | "iroha.da.commitments.verify"
            | "iroha.da.pin_intents.list"
            | "iroha.da.pin_intents.prove"
            | "iroha.da.pin_intents.verify"
            | "iroha.proofs.query"
            | "iroha.gov.parliament.ballots.timed_ovn_casting_proof.get"
            | "iroha.gov.ballots.zk_v1"
            | "iroha.gov.ballots.zk_v1.ballot_proof"
            | "iroha.gov.ballots.plain"
            | "iroha.transactions.query"
            | "iroha.accounts.history.query"
            | "iroha.contracts.activity.query"
            | "iroha.contracts.events.query"
            | "iroha.queries.submit"
    )
}
pub(crate) fn jsonrpc_invalid_request(message: &str) -> Value {
    jsonrpc_error_response(None, JSONRPC_INVALID_REQUEST, message, None)
}
/// Return the number of rate-limit tokens represented by one parsed MCP request.
///
/// The explicitly advertised `tools/call_batch` extension is charged for every
/// requested tool dispatch. Other values cost one token, including malformed
/// values, so the extension cannot amplify work relative to the caller's budget.
pub(crate) fn jsonrpc_dispatch_cost(payload: &Value) -> usize {
    payload
        .as_object()
        .filter(|request| request.get("method").and_then(Value::as_str) == Some("tools/call_batch"))
        .and_then(|request| request.get("params"))
        .and_then(Value::as_object)
        .and_then(|params| params.get("calls"))
        .and_then(Value::as_array)
        .map_or(1, |calls| calls.len().max(1))
}
/// Return a typed JSON-RPC payload for a request body that stalled while being
/// collected.
pub(crate) fn jsonrpc_request_timeout() -> Value {
    let timeout_ms = u64::try_from(MCP_BODY_READ_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    jsonrpc_error_response(
        None,
        MCP_REQUEST_TIMEOUT,
        "mcp request body read timed out",
        Some(norito::json!({
            "error_code": "request_timeout",
            "timeout_ms": (timeout_ms)
        })),
    )
}
pub(crate) fn jsonrpc_request_timeout_for_headers(_headers: &HeaderMap) -> Value {
    let mut response = jsonrpc_request_timeout();
    remap_modern_application_error(&mut response);
    response
}
/// Return a typed JSON-RPC payload for a request-body transport failure.
pub(crate) fn jsonrpc_request_body_read_failed() -> Value {
    jsonrpc_error_response(
        None,
        JSONRPC_INVALID_REQUEST,
        "mcp request body could not be read",
        Some(norito::json!({ "error_code": "request_body_read_failed" })),
    )
}
pub(crate) fn jsonrpc_rate_limited() -> Value {
    jsonrpc_error_response(
        None,
        MCP_RATE_LIMITED,
        "mcp request rate limited",
        Some(norito::json!({
            "error": "rate_limited"
        })),
    )
}
pub(crate) fn jsonrpc_rate_limited_for_headers(_headers: &HeaderMap) -> Value {
    let mut response = jsonrpc_rate_limited();
    remap_modern_application_error(&mut response);
    response
}
/// Return whether an optional browser Origin is trusted for MCP transport use.
///
/// Non-browser clients normally omit Origin and remain supported. When Origin
/// is present, exactly one value must match Torii's explicit CORS allowlist;
/// CORS response headers alone do not prevent DNS-rebinding requests.
pub(crate) fn origin_is_allowed(headers: &HeaderMap, allowed_origins: &[HeaderValue]) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    allowed_origins.iter().any(|allowed| allowed == origin)
}
pub(crate) fn jsonrpc_origin_forbidden() -> Value {
    jsonrpc_error_response(
        None,
        JSONRPC_INVALID_REQUEST,
        "mcp request origin is not allowed",
        Some(norito::json!({ "error_code": "origin_forbidden" })),
    )
}
/// Wrap one handler-owned MCP transport failure without losing JSON-RPC framing
/// at Torii's global typed-error boundary.
pub(crate) fn jsonrpc_transport_error_response(
    kind: ReviewedMcpJsonRpcError,
    payload: Value,
) -> Response {
    let mut response = private_no_store_response((kind.status(), crate::utils::JsonBody(payload)));
    response.headers_mut().insert(
        HeaderName::from_static(crate::MCP_NATIVE_ERROR_HEADER),
        HeaderValue::from_static(kind.code()),
    );
    if kind == ReviewedMcpJsonRpcError::RateLimited {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
        .extensions_mut()
        .insert(ReviewedProtocolNativeError::McpJsonRpc(kind));
    response
}

/// Apply the stateless protocol's early-error envelope rules before returning
/// one handler-owned transport failure.
pub(crate) fn jsonrpc_transport_error_response_for_headers(
    _headers: &HeaderMap,
    kind: ReviewedMcpJsonRpcError,
    mut payload: Value,
) -> Response {
    adapt_transport_error(&mut payload);
    jsonrpc_transport_error_response(kind, payload)
}

fn adapt_transport_error(payload: &mut Value) {
    remap_modern_application_error(payload);
    if payload.get("id").is_some_and(Value::is_null)
        && let Some(payload) = payload.as_object_mut()
    {
        payload.remove("id");
    }
}
pub(crate) fn protocol_version_is_supported(headers: &HeaderMap) -> bool {
    let mut versions = headers.get_all(HEADER_MCP_PROTOCOL_VERSION).iter();
    let Some(version) = versions.next() else {
        return false;
    };
    versions.next().is_none() && version.as_bytes() == protocol::MODERN_PROTOCOL_VERSION.as_bytes()
}

fn authenticated_cancellation_client_fingerprint(
    app: &SharedAppState,
    headers: &HeaderMap,
) -> Option<[u8; 32]> {
    let principal = app.authenticated_api_token_principal(headers)?;
    let mut hasher = Blake3Hasher::new();
    hasher.update(MCP_CANCELLATION_FINGERPRINT_DOMAIN);
    hasher.update(principal.as_bytes());
    Some(*hasher.finalize().as_bytes())
}

fn cancellation_nonce_from_params(params: &Map) -> Result<Option<[u8; 32]>, ()> {
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    let Some(meta) = meta.as_object() else {
        return Err(());
    };
    let Some(encoded) = meta.get(MCP_CANCELLATION_NONCE_META_KEY) else {
        return Ok(None);
    };
    let Some(encoded) = encoded.as_str() else {
        return Err(());
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ())?;
    let nonce: [u8; 32] = decoded.try_into().map_err(|_| ())?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce) != encoded {
        return Err(());
    }
    Ok(Some(nonce))
}

fn register_authenticated_inflight_request(
    app: &SharedAppState,
    headers: &HeaderMap,
    id: Option<&Value>,
    params: &Map,
) -> Result<Option<McpInflightRegistration>, McpInflightRegistrationError> {
    let Some(client_fingerprint) = authenticated_cancellation_client_fingerprint(app, headers)
    else {
        return Ok(None);
    };
    let cancellation_nonce = cancellation_nonce_from_params(params)
        .map_err(|()| McpInflightRegistrationError::InvalidNonce)?;
    let Some(cancellation_nonce) = cancellation_nonce else {
        return Ok(None);
    };
    let Some(request_id) = id.and_then(ExactJsonRpcId::from_value) else {
        return Ok(None);
    };
    app.mcp_inflight_requests
        .register(
            McpInflightKey {
                client_fingerprint,
                request_id,
            },
            cancellation_nonce,
            app.mcp.max_inflight_dispatches.get(),
        )
        .map(Some)
}

async fn finish_cancellable_dispatch<F>(
    mut registration: Option<McpInflightRegistration>,
    dispatch: F,
) -> JsonRpcRequestOutcome
where
    F: Future<Output = Value>,
{
    let Some(registration) = registration.as_mut() else {
        return JsonRpcRequestOutcome::Response(dispatch.await);
    };
    tokio::pin!(dispatch);
    tokio::select! {
        biased;
        () = registration.cancelled() => JsonRpcRequestOutcome::Cancelled,
        response = &mut dispatch => JsonRpcRequestOutcome::Response(response),
    }
}

fn cancellation_registration_error(
    id: Option<Value>,
    error: McpInflightRegistrationError,
    capacity: usize,
) -> JsonRpcRequestOutcome {
    if error == McpInflightRegistrationError::InvalidNonce {
        return JsonRpcRequestOutcome::Response(jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "cancellation nonce must be canonical unpadded base64url encoding exactly 32 bytes",
            Some(norito::json!({
                "error_code": "invalid_cancellation_nonce",
                "meta_key": (MCP_CANCELLATION_NONCE_META_KEY)
            })),
        ));
    }
    let (message, error_code) = match error {
        McpInflightRegistrationError::Duplicate => (
            "an authenticated MCP request with this id is already in flight",
            "request_id_in_use",
        ),
        McpInflightRegistrationError::Capacity => (
            "the authenticated MCP cancellation registry is at capacity",
            "cancellation_registry_capacity_exhausted",
        ),
        McpInflightRegistrationError::InvalidNonce => unreachable!("handled above"),
    };
    JsonRpcRequestOutcome::Response(jsonrpc_error_response(
        id,
        MCP_DISPATCH_CAPACITY_EXHAUSTED,
        message,
        Some(norito::json!({
            "error_code": (error_code),
            "max_inflight_dispatches": (capacity),
            "retryable": true
        })),
    ))
}

/// Execute a validated tool call, including cancellation registration.
pub(crate) async fn handle_tool_call_request(
    app: SharedAppState,
    inbound_headers: &HeaderMap,
    request: Value,
) -> JsonRpcRequestOutcome {
    let Value::Object(mut req_obj) = request else {
        return JsonRpcRequestOutcome::Response(jsonrpc_invalid_request(
            "request must be an object",
        ));
    };
    let id = req_obj.remove("id");
    if id.as_ref().is_some_and(|id| !is_jsonrpc_id(id)) {
        return JsonRpcRequestOutcome::Response(jsonrpc_error_response(
            None,
            JSONRPC_INVALID_REQUEST,
            "id must be a non-null string or number",
            None,
        ));
    }
    if req_obj.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return JsonRpcRequestOutcome::Response(jsonrpc_error_response(
            id,
            JSONRPC_INVALID_REQUEST,
            "jsonrpc must be \"2.0\"",
            None,
        ));
    }
    let Some(Value::String(method)) = req_obj.remove("method") else {
        return JsonRpcRequestOutcome::Response(jsonrpc_error_response(
            id,
            JSONRPC_INVALID_REQUEST,
            "method must be a string",
            None,
        ));
    };
    let params = match req_obj.remove("params") {
        Some(Value::Object(params)) => params,
        None => Map::new(),
        Some(_) => {
            return JsonRpcRequestOutcome::Response(jsonrpc_error_response(
                id,
                JSONRPC_INVALID_PARAMS,
                "params must be an object when present",
                None,
            ));
        }
    };
    match method.as_str() {
        "tools/call_batch" | "tools/call" => {
            let registration = match register_authenticated_inflight_request(
                &app,
                inbound_headers,
                id.as_ref(),
                &params,
            ) {
                Ok(registration) => registration,
                Err(error) => {
                    return cancellation_registration_error(
                        id,
                        error,
                        app.mcp.max_inflight_dispatches.get(),
                    );
                }
            };
            if method == "tools/call_batch" {
                finish_cancellable_dispatch(
                    registration,
                    handle_tools_call_batch(id, app, inbound_headers, &params),
                )
                .await
            } else {
                finish_cancellable_dispatch(
                    registration,
                    handle_tools_call(id, app, inbound_headers, &params),
                )
                .await
            }
        }
        _ => JsonRpcRequestOutcome::Response(jsonrpc_error_response(
            id,
            JSONRPC_METHOD_NOT_FOUND,
            "method not found",
            Some(norito::json!({ "method": method })),
        )),
    }
}
/// Dispatch one validated stateless MCP request.
pub(crate) async fn handle_validated_jsonrpc_request(
    app: SharedAppState,
    inbound_headers: &HeaderMap,
    request: Value,
    validated: &ValidatedProtocolRequest,
) -> JsonRpcRequestOutcome {
    let id = request
        .as_object()
        .and_then(|request| request.get("id"))
        .cloned();
    let mut outcome = match validated.method.as_str() {
        "server/discover" => {
            let only_meta = request
                .as_object()
                .and_then(|request| request.get("params"))
                .and_then(Value::as_object)
                .is_some_and(|params| params.len() == 1 && params.contains_key("_meta"));
            if !only_meta {
                JsonRpcRequestOutcome::Response(jsonrpc_error_response(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "server/discover accepts no params beyond standard _meta",
                    None,
                ))
            } else {
                let visible_tools = visible_tools_for_app(&app);
                JsonRpcRequestOutcome::Response(jsonrpc_result_response(
                    id,
                    modern_discovery_payload(&visible_tools),
                ))
            }
        }
        "tools/list" => JsonRpcRequestOutcome::Response(handle_tools_list(
            id,
            &app,
            validated_modern_request_params(&request),
        )),
        "tools/call" | "tools/call_batch" => {
            handle_tool_call_request(app, inbound_headers, request).await
        }
        "resources/list" => {
            let params = validated_modern_request_params(&request);
            JsonRpcRequestOutcome::Response(handle_resources_list(id, params))
        }
        "resources/read" => {
            let params = validated_modern_request_params(&request);
            JsonRpcRequestOutcome::Response(
                handle_resources_read(id, &app, inbound_headers, params).await,
            )
        }
        _ => JsonRpcRequestOutcome::Response(jsonrpc_error_response(
            id,
            JSONRPC_METHOD_NOT_FOUND,
            "method not found",
            Some(norito::json!({ "method": (validated.method.as_str()) })),
        )),
    };
    if let JsonRpcRequestOutcome::Response(response) = &mut outcome {
        decorate_modern_response(validated.method.as_str(), response);
        remap_modern_application_error(response);
    }
    outcome
}

fn validated_modern_request_params(request: &Value) -> &Map {
    request
        .get("params")
        .and_then(Value::as_object)
        .expect("modern protocol validation requires object params")
}

fn handle_resources_list(id: Option<Value>, params: &Map) -> Value {
    if let Err(message) = reject_unknown_arguments(params, &["_meta", "cursor"], "resources/list") {
        return jsonrpc_error_response(id, JSONRPC_INVALID_PARAMS, &message, None);
    }
    if params.contains_key("cursor") {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "resources/list cursor is invalid for the complete fixed resource catalogue",
            Some(norito::json!({ "error_code": "invalid_resource_cursor" })),
        );
    }
    match resources::resources_list_result() {
        Ok(result) => jsonrpc_result_response(id, result),
        Err(_) => jsonrpc_error_response(
            id,
            JSONRPC_INTERNAL_ERROR,
            "MCP resource catalogue is unavailable",
            Some(norito::json!({ "error_code": "resource_registry_invalid" })),
        ),
    }
}

async fn handle_resources_read(
    id: Option<Value>,
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    params: &Map,
) -> Value {
    if let Err(message) = reject_unknown_arguments(params, &["_meta", "uri"], "resources/read") {
        return jsonrpc_error_response(id, JSONRPC_INVALID_PARAMS, &message, None);
    }
    let Some(uri) = params.get("uri").and_then(Value::as_str) else {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "resources/read params.uri must be a string",
            None,
        );
    };
    match resources::read_resource(app, inbound_headers, uri).await {
        Ok(result) => jsonrpc_result_response(id, result),
        Err(resources::ResourceReadError::UnknownUri(uri)) => jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "Resource not found",
            Some(norito::json!({ "uri": uri })),
        ),
        Err(resources::ResourceReadError::CapacityExhausted) => jsonrpc_error_response(
            id,
            MCP_DISPATCH_CAPACITY_EXHAUSTED,
            "mcp resource dispatch capacity is exhausted",
            Some(norito::json!({
                "error_code": "dispatch_capacity_exhausted",
                "max_inflight_dispatches": (app.mcp.max_inflight_dispatches.get()),
                "retryable": true
            })),
        ),
        Err(resources::ResourceReadError::RouteStatus(status)) => jsonrpc_error_response(
            id,
            JSONRPC_INTERNAL_ERROR,
            "MCP resource route rejected the read",
            Some(norito::json!({
                "error_code": "resource_route_failed",
                "target_status": status
            })),
        ),
        Err(
            resources::ResourceReadError::InvalidRegistry(_)
            | resources::ResourceReadError::DispatchFailed(_)
            | resources::ResourceReadError::MalformedRouteResponse(_)
            | resources::ResourceReadError::BodyEncodingFailed(_),
        ) => jsonrpc_error_response(
            id,
            JSONRPC_INTERNAL_ERROR,
            "MCP resource read failed",
            Some(norito::json!({ "error_code": "resource_read_failed" })),
        ),
    }
}

fn remap_modern_application_error(response: &mut Value) {
    remap_modern_error_code(response);
    if let Some(results) = response
        .pointer_mut("/result/results")
        .and_then(Value::as_array_mut)
    {
        for result in results {
            remap_modern_error_code(result);
        }
    }
}

fn remap_modern_error_code(response: &mut Value) {
    let Some(code) = response
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
    else {
        return;
    };
    let modern = match code {
        MCP_TOOL_EXECUTION_ERROR => MODERN_IROHA_TOOL_EXECUTION_ERROR,
        MCP_RESPONSE_TOO_LARGE => MODERN_IROHA_RESPONSE_TOO_LARGE,
        MCP_REQUEST_TIMEOUT => MODERN_IROHA_REQUEST_TIMEOUT,
        MCP_DISPATCH_CAPACITY_EXHAUSTED => MODERN_IROHA_DISPATCH_CAPACITY_EXHAUSTED,
        MCP_RATE_LIMITED => MODERN_IROHA_RATE_LIMITED,
        _ => return,
    };
    if let Some(code) = response
        .get_mut("error")
        .and_then(|error| error.get_mut("code"))
    {
        *code = Value::from(modern);
    }
}

/// Return the top-level JSON-RPC error code, if the value is an error response.
pub(crate) fn jsonrpc_response_error_code(response: &Value) -> Option<i64> {
    response
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
}
/// Return true when a payload is a syntactically valid JSON-RPC notification.
pub(crate) fn is_jsonrpc_notification(request: &Value) -> bool {
    let Some(req_obj) = request.as_object() else {
        return false;
    };
    if req_obj.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return false;
    }
    req_obj.get("id").is_none() && req_obj.get("method").and_then(Value::as_str).is_some()
}

/// Return true for the standard best-effort cancellation notification.
pub(crate) fn is_cancelled_notification(request: &Value) -> bool {
    is_jsonrpc_notification(request)
        && request
            .as_object()
            .and_then(|request| request.get("method"))
            .and_then(Value::as_str)
            == Some("notifications/cancelled")
}

/// Best-effort cancel one exact request owned by the same authenticated API-token principal.
///
/// Malformed, unknown, completed, anonymous, and cross-principal notifications are deliberately
/// indistinguishable to the caller. Notifications never receive a JSON-RPC response.
pub(crate) fn handle_cancelled_notification(
    app: &SharedAppState,
    headers: &HeaderMap,
    notification: &Value,
) {
    let Some(client_fingerprint) = authenticated_cancellation_client_fingerprint(app, headers)
    else {
        return;
    };
    let Some(params) = notification
        .as_object()
        .and_then(|notification| notification.get("params"))
        .and_then(Value::as_object)
    else {
        return;
    };
    if params
        .get("reason")
        .is_some_and(|reason| !reason.is_string())
    {
        return;
    }
    let Some(request_id) = params.get("requestId").and_then(ExactJsonRpcId::from_value) else {
        return;
    };
    let Ok(Some(cancellation_nonce)) = cancellation_nonce_from_params(params) else {
        return;
    };
    let _ = app.mcp_inflight_requests.cancel(
        &McpInflightKey {
            client_fingerprint,
            request_id,
        },
        &cancellation_nonce,
    );
}

fn is_jsonrpc_id(id: &Value) -> bool {
    match id {
        Value::String(_) => true,
        Value::Number(json::native::Number::U128(value)) => u64::try_from(*value).is_ok(),
        Value::Number(_) => true,
        _ => false,
    }
}
fn handle_tools_list(id: Option<Value>, app: &SharedAppState, params: &Map) -> Value {
    let visible_tools = visible_tools_for_app(app);
    let toolset_version = compute_toolset_version(&visible_tools);
    let list_changed = params
        .get("toolsetVersion")
        .and_then(Value::as_str)
        .is_some_and(|client| client != toolset_version);
    let requested_start = match params.get("cursor") {
        None => 0,
        Some(Value::String(cursor)) => match cursor.parse::<usize>() {
            Ok(start) if start <= visible_tools.len() => start,
            _ => {
                return jsonrpc_error_response(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "tools/list params.cursor is invalid or out of range",
                    Some(norito::json!({ "error_code": "invalid_cursor" })),
                );
            }
        },
        Some(_) => {
            return jsonrpc_error_response(
                id,
                JSONRPC_INVALID_PARAMS,
                "tools/list params.cursor must be a string",
                Some(norito::json!({ "error_code": "invalid_cursor" })),
            );
        }
    };
    let start = requested_start;
    let page_size = app.mcp.max_tools_per_list.max(1);
    let limit = start.saturating_add(page_size).min(visible_tools.len());
    let mut tools = Vec::new();
    let mut tools_bytes = 0_usize;
    let mut response =
        tools_list_page_response(id.clone(), Vec::new(), None, &toolset_version, list_changed);
    for (index, tool) in visible_tools.iter().enumerate().take(limit).skip(start) {
        let next_cursor = (index + 1 < visible_tools.len()).then_some(index + 1);
        let mut candidate = tools_list_page_response(
            id.clone(),
            vec![tool.descriptor()],
            next_cursor,
            &toolset_version,
            list_changed,
        );
        // Measure each descriptor at its actual JSON nesting depth, with the
        // exact id, cursor and protocol metadata. Previously admitted tool bytes
        // contribute additively, so pagination never repeatedly serializes them.
        let separator = usize::from(!tools.is_empty());
        let remaining = app
            .mcp
            .max_request_bytes
            .checked_sub(tools_bytes)
            .and_then(|remaining| remaining.checked_sub(separator));
        let measured = remaining
            .ok_or(BoundedJsonError::BodyTooLarge)
            .and_then(|remaining| bounded_json_value_len(&candidate, remaining));
        let candidate_bytes = match measured {
            Ok(bytes) => bytes,
            Err(BoundedJsonError::BodyTooLarge) if !tools.is_empty() => break,
            Err(BoundedJsonError::BodyTooLarge) => {
                return jsonrpc_response_too_large(id, app.mcp.max_request_bytes);
            }
            Err(error) => {
                let error_class = match error {
                    BoundedJsonError::Unsupported => "unsupported",
                    BoundedJsonError::LengthMismatch => "length_mismatch",
                    BoundedJsonError::AllocationFailed
                    | BoundedJsonError::DecodeResource(_)
                    | BoundedJsonError::ScopedDecodeResource(_) => "allocation_failed",
                    BoundedJsonError::BodyTooLarge => unreachable!("handled above"),
                };
                return jsonrpc_error_response(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "MCP tool descriptor cannot be serialized within its response envelope",
                    Some(norito::json!({
                        "error_code": "response_serialization_failed",
                        "tool": (tool.name.as_str()),
                        "serialization_error": error_class
                    })),
                );
            }
        };
        let descriptor = candidate
            .pointer_mut("/result/tools")
            .and_then(Value::as_array_mut)
            .and_then(Vec::pop)
            .expect("one measured tool descriptor");
        let envelope_bytes = bounded_json_value_len(&candidate, app.mcp.max_request_bytes)
            .expect("removing a measured descriptor cannot exceed its envelope bounds");
        tools_bytes += separator + candidate_bytes - envelope_bytes;
        tools.push(descriptor);
        response = candidate;
    }
    *response
        .pointer_mut("/result/tools")
        .expect("tools-list response has its exact tools slot") = Value::Array(tools);
    response
}

fn tools_list_page_response(
    id: Option<Value>,
    tools: Vec<Value>,
    next_cursor: Option<usize>,
    toolset_version: &str,
    list_changed: bool,
) -> Value {
    let mut result = Map::new();
    result.insert("tools".into(), Value::Array(tools));
    if let Some(end) = next_cursor {
        result.insert("nextCursor".into(), Value::String(end.to_string()));
    }
    result.insert(
        "_meta".into(),
        norito::json!({
            "iroha": {
                "listChanged": list_changed,
                "toolsetVersion": toolset_version
            }
        }),
    );
    let mut response = jsonrpc_result_response(id, Value::Object(result));
    decorate_modern_response("tools/list", &mut response);
    response
}
async fn handle_tools_call(
    id: Option<Value>,
    app: SharedAppState,
    inbound_headers: &HeaderMap,
    params: &Map,
) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "tools/call params.name must be a string",
            None,
        );
    };
    let empty_arguments = Map::new();
    let arguments = match params.get("arguments") {
        None => &empty_arguments,
        Some(Value::Object(arguments)) => arguments,
        Some(_) => {
            return jsonrpc_error_response(
                id,
                JSONRPC_INVALID_PARAMS,
                "tools/call params.arguments must be an object",
                None,
            );
        }
    };
    handle_named_tool_call(id, app, inbound_headers, name, arguments).await
}

async fn handle_named_tool_call(
    id: Option<Value>,
    app: SharedAppState,
    inbound_headers: &HeaderMap,
    name: &str,
    arguments: &Map,
) -> Value {
    let Some(tool_spec) = find_tool_spec_by_name(app.mcp_tools.as_slice(), name) else {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "tool not found",
            Some(norito::json!({ "name": (name), "error_code": (MCP_TOOL_NOT_FOUND) })),
        );
    };
    if !is_tool_allowed_by_policy(&app.mcp, tool_spec) {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "tool is not enabled by MCP policy",
            Some(norito::json!({ "name": (name), "error_code": (MCP_TOOL_NOT_ALLOWED) })),
        );
    }
    if !tool_is_runtime_available(&app, tool_spec) {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "tool is unavailable in this node's runtime configuration",
            Some(norito::json!({ "name": (name), "error_code": (MCP_TOOL_UNAVAILABLE) })),
        );
    }
    if let Err(message) = validate_tool_arguments(tool_spec, arguments) {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            message.as_str(),
            Some(norito::json!({
                "name": name,
                "error_code": "tool_schema_validation_failed"
            })),
        );
    }
    let _long_poll_permit = if is_long_poll_tool(name) {
        match app.mcp_long_poll_inflight.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return jsonrpc_error_response(
                    id,
                    MCP_DISPATCH_CAPACITY_EXHAUSTED,
                    "mcp long-poll dispatch capacity is exhausted",
                    Some(norito::json!({
                        "error_code": "long_poll_capacity_exhausted",
                        "retryable": true
                    })),
                );
            }
        }
    } else {
        None
    };
    let _dispatch_permit = match app.mcp_dispatch_inflight.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return jsonrpc_error_response(
                id,
                MCP_DISPATCH_CAPACITY_EXHAUSTED,
                "mcp tool dispatch capacity is exhausted",
                Some(norito::json!({
                    "error_code": "dispatch_capacity_exhausted",
                    "max_inflight_dispatches": (app.mcp.max_inflight_dispatches.get()),
                    "retryable": true
                })),
            );
        }
    };
    if let ToolBacking::InProcess(in_process) = tool_spec.backing() {
        let tool_result = match in_process {
            InProcessTool::TransactionsPrepare => {
                dispatch_iroha_transactions_prepare(&app, arguments)
            }
            InProcessTool::TransactionsInspect => {
                dispatch_iroha_transactions_inspect(&app, arguments)
            }
        }
        .map_or_else(mcp_tool_error, mcp_tool_success);
        return jsonrpc_result_response(id, tool_result);
    }
    let purpose_built_dispatch = match validate_purpose_built_dispatch_backing(tool_spec) {
        Ok(purpose_built_dispatch) => purpose_built_dispatch,
        Err(error) => {
            return jsonrpc_result_response(id, mcp_tool_error(error));
        }
    };
    if !purpose_built_dispatch {
        let tool_result = dispatch_openapi_tool(&app, inbound_headers, tool_spec, arguments)
            .await
            .map_or_else(mcp_tool_error, mcp_tool_success);
        return jsonrpc_result_response(id, tool_result);
    }
    let result = select_purpose_built_tool_dispatch(&app, inbound_headers, name, arguments).await;
    let tool_result = result.map_or_else(mcp_tool_error, mcp_tool_success);
    jsonrpc_result_response(id, tool_result)
}
/// Select one heap-owned handler before polling its forwarded HTTP route.
/// Selection scratch space is released before the nested router and Core reader run.
fn select_purpose_built_tool_dispatch<'a>(
    app: &'a SharedAppState,
    inbound_headers: &'a HeaderMap,
    name: &'a str,
    arguments: &'a Map,
) -> std::pin::Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>> {
    match name {
        "iroha.connect.ws.ticket" => {
            Box::pin(async move { build_connect_ws_ticket(arguments, inbound_headers) })
        }
        "iroha.connect.session.create" => Box::pin(dispatch_connect_session_create(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.connect.session.delete" => Box::pin(dispatch_connect_session_delete(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.connect.session.status" => Box::pin(dispatch_connect_session_status(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.vpn.profile" => {
            Box::pin(dispatch_iroha_vpn_profile(app, inbound_headers, arguments))
        }
        "iroha.vpn.quotes.create" => Box::pin(dispatch_iroha_vpn_quotes_create(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.vpn.sessions.create" => Box::pin(dispatch_iroha_vpn_sessions_create(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.vpn.sessions.get" => Box::pin(dispatch_iroha_vpn_sessions_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.vpn.receipts.list" => Box::pin(dispatch_iroha_vpn_receipts_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.vpn.receipts.submit" => Box::pin(dispatch_iroha_vpn_receipts_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.health" => Box::pin(dispatch_iroha_health(app, inbound_headers, arguments)),
        "iroha.parameters.get" => Box::pin(dispatch_iroha_parameters_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.node.capabilities" => Box::pin(dispatch_iroha_node_capabilities(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.node.query_projection_shard_catalog" => Box::pin(
            dispatch_iroha_node_query_projection_shard_catalog(app, inbound_headers, arguments),
        ),
        "iroha.node.query_projection_checkpoint" => Box::pin(
            dispatch_iroha_node_query_projection_checkpoint(app, inbound_headers, arguments),
        ),
        "iroha.da.ingest" => Box::pin(dispatch_iroha_da_ingest(app, inbound_headers, arguments)),
        "iroha.da.proof_policies" => Box::pin(dispatch_iroha_da_proof_policies(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.manifests.get" => Box::pin(dispatch_iroha_da_manifests_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.commitments.list" => Box::pin(dispatch_iroha_da_commitments_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.commitments.prove" => Box::pin(dispatch_iroha_da_commitments_prove(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.commitments.verify" => Box::pin(dispatch_iroha_da_commitments_verify(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.pin_intents.list" => Box::pin(dispatch_iroha_da_pin_intents_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.pin_intents.prove" => Box::pin(dispatch_iroha_da_pin_intents_prove(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.da.pin_intents.verify" => Box::pin(dispatch_iroha_da_pin_intents_verify(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.abi.active" => Box::pin(dispatch_iroha_runtime_abi_active(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.abi.hash" => Box::pin(dispatch_iroha_runtime_abi_hash(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.metrics" => Box::pin(dispatch_iroha_runtime_metrics(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.upgrades.list" => Box::pin(dispatch_iroha_runtime_upgrades_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.upgrades.propose" => Box::pin(dispatch_iroha_runtime_upgrades_propose(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.upgrades.activate" => Box::pin(dispatch_iroha_runtime_upgrades_activate(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.runtime.upgrades.cancel" => Box::pin(dispatch_iroha_runtime_upgrades_cancel(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.bridge.finality.proof" => Box::pin(dispatch_iroha_bridge_finality_proof(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.bridge.finality.bundle" => Box::pin(dispatch_iroha_bridge_finality_bundle(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.proofs.query" => {
            Box::pin(dispatch_iroha_proofs_query(app, inbound_headers, arguments))
        }
        "iroha.gov.contract.get" => Box::pin(dispatch_iroha_gov_contract_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.proposals.deploy_contract" => Box::pin(
            dispatch_iroha_gov_proposals_deploy_contract(app, inbound_headers, arguments),
        ),
        "iroha.gov.parliament.attempts.draft" => Box::pin(
            dispatch_iroha_gov_parliament_attempt_draft(app, inbound_headers, arguments),
        ),
        "iroha.gov.parliament.attempts.get" => Box::pin(dispatch_iroha_gov_parliament_attempt_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.parliament.ballots.timed_ovn_casting_context.get" => {
            Box::pin(dispatch_iroha_gov_parliament_timed_ovn_casting_context_get(
                app,
                inbound_headers,
                arguments,
            ))
        }
        "iroha.gov.parliament.ballots.timed_ovn_casting_proof.get" => {
            Box::pin(dispatch_iroha_gov_parliament_timed_ovn_casting_proof_get(
                app,
                inbound_headers,
                arguments,
            ))
        }
        "iroha.gov.parliament.ballots.tle_release_context.get" => Box::pin(
            dispatch_iroha_gov_parliament_tle_release_context_get(app, inbound_headers, arguments),
        ),
        "iroha.gov.parliament.ballots.tle_partial_release.create" => {
            Box::pin(dispatch_iroha_gov_parliament_tle_partial_release_create(
                app,
                inbound_headers,
                arguments,
            ))
        }
        "iroha.gov.parliament.transitions.draft" => Box::pin(
            dispatch_iroha_gov_parliament_transition_draft(app, inbound_headers, arguments),
        ),
        "iroha.gov.proposals.get" => Box::pin(dispatch_iroha_gov_proposals_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.locks.get" => Box::pin(dispatch_iroha_gov_locks_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.referenda.get" => Box::pin(dispatch_iroha_gov_referenda_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.tally.get" => Box::pin(dispatch_iroha_gov_tally_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.ballots.zk_v1" => Box::pin(dispatch_iroha_gov_ballots_zk_v1(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.ballots.zk_v1.ballot_proof" => Box::pin(
            dispatch_iroha_gov_ballots_zk_v1_ballot_proof(app, inbound_headers, arguments),
        ),
        "iroha.gov.ballots.plain" => Box::pin(dispatch_iroha_gov_ballots_plain(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.protected_namespaces.list" => Box::pin(
            dispatch_iroha_gov_protected_namespaces_list(app, inbound_headers, arguments),
        ),
        "iroha.gov.protected_namespaces.update" => Box::pin(
            dispatch_iroha_gov_protected_namespaces_update(app, inbound_headers, arguments),
        ),
        "iroha.gov.unlocks.stats" => Box::pin(dispatch_iroha_gov_unlocks_stats(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.gov.citizens.count" => Box::pin(dispatch_iroha_gov_citizens_count(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.aliases.resolve" => Box::pin(dispatch_iroha_aliases_resolve(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.aliases.resolve_index" => Box::pin(dispatch_iroha_aliases_resolve_index(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.aliases.by_account" => Box::pin(dispatch_iroha_aliases_by_account(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.code.get" => Box::pin(dispatch_iroha_contracts_code_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.code.bytes.get" => Box::pin(dispatch_iroha_contracts_code_bytes_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.call" => Box::pin(dispatch_iroha_contracts_call(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.view" => Box::pin(dispatch_contract_view(app, inbound_headers, arguments)),
        "iroha.contracts.call_and_wait" => Box::pin(dispatch_iroha_contracts_call_and_wait(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.state.get" => Box::pin(dispatch_iroha_contracts_state_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.list" => Box::pin(dispatch_iroha_accounts_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.get" => {
            Box::pin(dispatch_iroha_accounts_get(app, inbound_headers, arguments))
        }
        "iroha.accounts.qr" => {
            Box::pin(dispatch_iroha_accounts_qr(app, inbound_headers, arguments))
        }
        "iroha.accounts.query" => Box::pin(dispatch_iroha_accounts_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.onboard.submit" => Box::pin(dispatch_iroha_accounts_onboard_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.onboard.plan" => Box::pin(dispatch_iroha_accounts_onboard_plan(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.onboard.prepare" => Box::pin(dispatch_iroha_accounts_onboard_prepare(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.faucet.policy" => Box::pin(dispatch_iroha_accounts_faucet_policy(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.faucet.prepare" => Box::pin(dispatch_iroha_accounts_faucet_prepare(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.faucet.submit" => Box::pin(dispatch_iroha_accounts_faucet_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.transactions" => Box::pin(dispatch_iroha_account_transactions(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.history" => Box::pin(dispatch_iroha_account_history(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.transactions.query" => Box::pin(dispatch_iroha_account_transactions_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.history.query" => Box::pin(dispatch_iroha_account_history_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.activity.query" => Box::pin(dispatch_iroha_contracts_activity_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.contracts.events.query" => Box::pin(dispatch_iroha_contracts_events_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.transactions.query" => Box::pin(dispatch_iroha_transactions_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.assets" => Box::pin(dispatch_iroha_account_assets(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.assets.query" => Box::pin(dispatch_iroha_account_assets_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.permissions.query" => Box::pin(dispatch_iroha_account_permissions_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.plans.query" => Box::pin(dispatch_iroha_subscriptions_plans_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.query" => Box::pin(dispatch_iroha_subscriptions_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.space_directory.manifests" => Box::pin(dispatch_iroha_uaid_manifests(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.space_directory.manifests.query" => Box::pin(dispatch_iroha_uaid_manifests_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.permissions" => Box::pin(dispatch_iroha_account_permissions(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.accounts.portfolio" => Box::pin(dispatch_iroha_account_portfolio(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.domains.list" => {
            Box::pin(dispatch_iroha_domains_list(app, inbound_headers, arguments))
        }
        "iroha.domains.get" => {
            Box::pin(dispatch_iroha_domains_get(app, inbound_headers, arguments))
        }
        "iroha.domains.query" => Box::pin(dispatch_iroha_domains_query(
            app,
            inbound_headers,
            arguments,
        )),
        name if musubi_v1_tool_definition(name).is_some() => Box::pin(dispatch_iroha_musubi_v1(
            app,
            inbound_headers,
            name,
            arguments,
        )),
        "iroha.subscriptions.plans.list" => Box::pin(dispatch_iroha_subscriptions_plans_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.plans.create" => Box::pin(dispatch_iroha_subscriptions_plans_create(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.list" => Box::pin(dispatch_iroha_subscriptions_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.create" => Box::pin(dispatch_iroha_subscriptions_create(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.get" => Box::pin(dispatch_iroha_subscriptions_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.pause" => Box::pin(dispatch_iroha_subscriptions_pause(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.resume" => Box::pin(dispatch_iroha_subscriptions_resume(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.cancel" => Box::pin(dispatch_iroha_subscriptions_cancel(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.keep" => Box::pin(dispatch_iroha_subscriptions_keep(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.usage" => Box::pin(dispatch_iroha_subscriptions_usage(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.subscriptions.charge_now" => Box::pin(dispatch_iroha_subscriptions_charge_now(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.assets.definitions" => Box::pin(dispatch_iroha_asset_definitions(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.assets.definitions.get" => Box::pin(dispatch_iroha_asset_definitions_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.assets.definitions.query" => Box::pin(dispatch_iroha_asset_definitions_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.assets.holders" => Box::pin(dispatch_iroha_asset_holders(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.assets.holders.query" => Box::pin(dispatch_iroha_asset_holders_query(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.assets.list" => {
            Box::pin(dispatch_iroha_assets_list(app, inbound_headers, arguments))
        }
        "iroha.assets.get" => Box::pin(dispatch_iroha_assets_get(app, inbound_headers, arguments)),
        "iroha.nfts.chain.list" => Box::pin(dispatch_iroha_nfts_chain_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.nfts.list" => Box::pin(dispatch_iroha_nfts_list(app, inbound_headers, arguments)),
        "iroha.nfts.get" => Box::pin(dispatch_iroha_nfts_get(app, inbound_headers, arguments)),
        "iroha.nfts.query" => Box::pin(dispatch_iroha_nfts_query(app, inbound_headers, arguments)),
        "iroha.rwas.chain.list" => Box::pin(dispatch_iroha_rwas_chain_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.rwas.list" => Box::pin(dispatch_iroha_rwas_list(app, inbound_headers, arguments)),
        "iroha.rwas.get" => Box::pin(dispatch_iroha_rwas_get(app, inbound_headers, arguments)),
        "iroha.rwas.query" => Box::pin(dispatch_iroha_rwas_query(app, inbound_headers, arguments)),
        "iroha.iso20022.pacs008.submit" => Box::pin(dispatch_iroha_iso20022_pacs008_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.iso20022.pacs009.submit" => Box::pin(dispatch_iroha_iso20022_pacs009_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.iso20022.pacs002.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/pacs002",
        )),
        "iroha.iso20022.pacs004.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/pacs004",
        )),
        "iroha.iso20022.camt056.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/camt056",
        )),
        "iroha.iso20022.sese023.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/sese023",
        )),
        "iroha.iso20022.sese024.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/sese024",
        )),
        "iroha.iso20022.sese025.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/sese025",
        )),
        "iroha.iso20022.colr012.submit" => Box::pin(dispatch_iroha_iso20022_lifecycle_submit(
            app,
            inbound_headers,
            arguments,
            "/v1/iso20022/colr012",
        )),
        "iroha.iso20022.status.get" => Box::pin(dispatch_iroha_iso20022_status_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.queries.submit" => Box::pin(dispatch_iroha_queries_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.transactions.list" => Box::pin(dispatch_iroha_transactions_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.transactions.get" => Box::pin(dispatch_iroha_transactions_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.instructions.list" => Box::pin(dispatch_iroha_instructions_list(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.instructions.get" => Box::pin(dispatch_iroha_instructions_get(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.blocks.list" => {
            Box::pin(dispatch_iroha_blocks_list(app, inbound_headers, arguments))
        }
        "iroha.blocks.get" => Box::pin(dispatch_iroha_blocks_get(app, inbound_headers, arguments)),
        "iroha.transactions.submit" => Box::pin(dispatch_iroha_transactions_submit(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.transactions.submit_and_wait" => Box::pin(
            dispatch_iroha_transactions_submit_and_wait(app, inbound_headers, arguments),
        ),
        "iroha.transactions.wait" => Box::pin(dispatch_iroha_transactions_wait(
            app,
            inbound_headers,
            arguments,
        )),
        "iroha.transactions.status" => Box::pin(dispatch_iroha_transactions_status(
            app,
            inbound_headers,
            arguments,
        )),
        _ => Box::pin(async move {
            Err(format!(
                "purpose-built dispatch contract `{name}` has no implementation"
            ))
        }),
    }
}
fn validate_tool_arguments(tool: &ToolSpec, arguments: &Map) -> Result<(), String> {
    let schema = sanitize_tool_input_schema(&tool.input_schema);
    validate_json_schema_value(&schema, &Value::Object(arguments.clone()), "arguments")
}
fn validate_json_schema_value(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let Some(schema) = schema.as_object() else {
        return Ok(());
    };
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            validate_json_schema_value(branch, value, path)?;
        }
    }
    if let Some(branches) = schema.get("anyOf").and_then(Value::as_array)
        && !branches
            .iter()
            .any(|branch| validate_json_schema_value(branch, value, path).is_ok())
    {
        return Err(format!("{path} does not match any advertised schema"));
    }
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array)
        && branches
            .iter()
            .filter(|branch| validate_json_schema_value(branch, value, path).is_ok())
            .count()
            != 1
    {
        return Err(format!("{path} must match exactly one advertised schema"));
    }
    if schema
        .get("not")
        .is_some_and(|branch| validate_json_schema_value(branch, value, path).is_ok())
    {
        return Err(format!("{path} matches a forbidden advertised schema"));
    }
    if let Some(condition) = schema.get("if") {
        let condition_matches = validate_json_schema_value(condition, value, path).is_ok();
        let branch = if condition_matches {
            schema.get("then")
        } else {
            schema.get("else")
        };
        if let Some(branch) = branch {
            validate_json_schema_value(branch, value, path)?;
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.iter().any(|candidate| candidate == value)
    {
        return Err(format!("{path} is not one of the advertised values"));
    }
    if let Some(constant) = schema.get("const")
        && constant != value
    {
        return Err(format!("{path} does not match the advertised constant"));
    }
    if let Some(expected) = schema.get("type") {
        let matches = match expected {
            Value::String(expected) => schema_type_matches(expected, value),
            Value::Array(expected) => expected
                .iter()
                .filter_map(Value::as_str)
                .any(|expected| schema_type_matches(expected, value)),
            _ => true,
        };
        if !matches {
            return Err(format!("{path} has the wrong advertised JSON type"));
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            return Err(format!("{path} is shorter than the advertised minimum"));
        }
        if schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            return Err(format!("{path} is longer than the advertised maximum"));
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            match advertised_pattern_matches(pattern, text) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(format!("{path} does not match the advertised pattern"));
                }
                Err(message) => return Err(message),
            }
        }
    }
    if let Some(number) = value.as_f64() {
        if schema
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|minimum| number < minimum)
        {
            return Err(format!("{path} is below the advertised minimum"));
        }
        if schema
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| number > maximum)
        {
            return Err(format!("{path} is above the advertised maximum"));
        }
        if schema
            .get("exclusiveMinimum")
            .and_then(Value::as_f64)
            .is_some_and(|minimum| number <= minimum)
        {
            return Err(format!(
                "{path} is not above the advertised exclusive minimum"
            ));
        }
        if schema
            .get("exclusiveMaximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| number >= maximum)
        {
            return Err(format!(
                "{path} is not below the advertised exclusive maximum"
            ));
        }
    }
    if let Some(items) = value.as_array() {
        let length = items.len() as u64;
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            return Err(format!("{path} has fewer items than advertised"));
        }
        if schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            return Err(format!("{path} has more items than advertised"));
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate_json_schema_value(item_schema, item, &format!("{path}[{index}]"))?;
            }
        }
        if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            let mut seen = BTreeSet::new();
            for item in items {
                let encoded = json::to_string(item).map_err(|error| {
                    format!("{path} could not be canonicalized for uniqueness: {error}")
                })?;
                if !seen.insert(encoded) {
                    return Err(format!("{path} contains duplicate items"));
                }
            }
        }
    }
    if let Some(object) = value.as_object() {
        let length = object.len() as u64;
        if schema
            .get("minProperties")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            return Err(format!("{path} has fewer properties than advertised"));
        }
        if schema
            .get("maxProperties")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            return Err(format!("{path} has more properties than advertised"));
        }
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(format!("{path}.{field} is required"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (field, field_value) in object {
            let field_path = format!("{path}.{field}");
            if let Some(field_schema) = properties.and_then(|properties| properties.get(field)) {
                validate_json_schema_value(field_schema, field_value, &field_path)?;
                continue;
            }
            match schema.get("additionalProperties") {
                Some(Value::Bool(false)) => {
                    return Err(format!("{field_path} is not an advertised argument"));
                }
                Some(additional_schema @ Value::Object(_)) => {
                    validate_json_schema_value(additional_schema, field_value, &field_path)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}
fn advertised_pattern_matches(pattern: &str, value: &str) -> Result<bool, String> {
    if let Some(matches) = custom_advertised_pattern_matches(pattern, value) {
        return Ok(matches);
    }
    compiled_advertised_pattern(pattern)
        .map(|pattern| pattern.is_match(value))
        .map_err(|error| {
            format!("advertised schema contains unsupported pattern `{pattern}`: {error}")
        })
}
fn compiled_advertised_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    if let Some(compiled) = ADVERTISED_REGEX_CACHE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(pattern)
        .cloned()
    {
        return Ok(compiled);
    }
    let mut cache = ADVERTISED_REGEX_CACHE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(compiled) = cache.get(pattern).cloned() {
        return Ok(compiled);
    }
    let compiled = regex::Regex::new(pattern)?;
    #[cfg(test)]
    {
        let mut counts = ADVERTISED_REGEX_COMPILE_COUNTS
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *counts.entry(pattern.to_owned()).or_default() += 1;
    }
    cache.insert(pattern.to_owned(), compiled.clone());
    Ok(compiled)
}
fn custom_advertised_pattern_matches(pattern: &str, value: &str) -> Option<bool> {
    let lower_hex_is_nonzero = |value: &str, digits: usize| {
        value.len() == digits
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            && value.bytes().any(|byte| byte != b'0')
    };
    match pattern {
        NONZERO_UPPER_HEX_PATTERN => Some(
            value.len() >= 2
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
                && value.bytes().any(|byte| byte != b'0'),
        ),
        "^(?!0{64}$)[0-9a-f]{64}$" => Some(lower_hex_is_nonzero(value, 64)),
        "^(?!0{128}$)[0-9a-f]{128}$" => Some(lower_hex_is_nonzero(value, 128)),
        "^(?!\\s)(?:[^\\u0000-\\u001F\\u007F-\\u009F])*[^\\s\\u0000-\\u001F\\u007F-\\u009F]$" => {
            let mut chars = value.chars();
            let Some(first) = chars.next() else {
                return Some(false);
            };
            let is_forbidden_control =
                |character: char| matches!(character as u32, 0x0000..=0x001f | 0x007f..=0x009f);
            let last = value
                .chars()
                .next_back()
                .expect("non-empty value has a last char");
            Some(
                !first.is_whitespace()
                    && !last.is_whitespace()
                    && value
                        .chars()
                        .all(|character| !is_forbidden_control(character)),
            )
        }
        _ => None,
    }
}
fn validate_advertised_schema_patterns(schema: &Value, path: &str) -> Result<(), String> {
    match schema {
        Value::Object(object) => {
            if let Some(pattern) = object.get("pattern").and_then(Value::as_str)
                && custom_advertised_pattern_matches(pattern, "").is_none()
            {
                compiled_advertised_pattern(pattern).map_err(|error| {
                    format!("{path}.pattern uses unsupported regex `{pattern}`: {error}")
                })?;
            }
            for (key, value) in object {
                validate_advertised_schema_patterns(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_advertised_schema_patterns(value, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn reject_unresolved_schema_refs(schema: &Value, path: &str) -> Result<(), String> {
    match schema {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref") {
                let reference = reference.as_str().unwrap_or("<non-string $ref>");
                return Err(format!(
                    "{path} contains unresolved OpenAPI reference `{reference}`"
                ));
            }
            for (key, value) in object {
                reject_unresolved_schema_refs(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_unresolved_schema_refs(value, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn schema_type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_bool(),
        "null" => value.is_null(),
        _ => true,
    }
}
async fn handle_tools_call_batch(
    id: Option<Value>,
    app: SharedAppState,
    inbound_headers: &HeaderMap,
    params: &Map,
) -> Value {
    let Some(calls) = params.get("calls").and_then(Value::as_array) else {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "tools/call_batch params.calls must be an array",
            None,
        );
    };
    if calls.len() > MAX_JSONRPC_BATCH_DISPATCHES {
        return jsonrpc_error_response(
            id,
            JSONRPC_INVALID_PARAMS,
            "tools/call_batch exceeds the first-release dispatch limit",
            Some(norito::json!({
                "error_code": MCP_BATCH_TOO_LARGE_CODE,
                "max_batch_dispatches": MAX_JSONRPC_BATCH_DISPATCHES
            })),
        );
    }
    let mut results = match BoundedJsonArray::new(calls.len(), app.mcp.max_request_bytes) {
        Ok(results) => results,
        Err(BoundedJsonError::BodyTooLarge) => {
            return jsonrpc_response_too_large(id, app.mcp.max_request_bytes);
        }
        Err(_) => {
            return jsonrpc_error_response(
                id,
                JSONRPC_INTERNAL_ERROR,
                "failed to reserve MCP batch result storage",
                Some(norito::json!({ "error_code": "allocation_failed" })),
            );
        }
    };
    for call in calls {
        let result = if let Some(call_obj) = call.as_object() {
            let Some(name) = call_obj.get("name").and_then(Value::as_str) else {
                let result = norito::json!({
                    "error": {
                        "code": JSONRPC_INVALID_PARAMS,
                        "message": "batch item `name` must be a string",
                        "data": { "error_code": "invalid_params" }
                    }
                });
                if results.try_push(result).is_err() {
                    return jsonrpc_response_too_large(id, app.mcp.max_request_bytes);
                }
                continue;
            };
            let empty_arguments = Map::new();
            let arguments = match call_obj.get("arguments") {
                None => &empty_arguments,
                Some(Value::Object(arguments)) => arguments,
                Some(_) => {
                    let result = norito::json!({
                        "error": {
                            "code": JSONRPC_INVALID_PARAMS,
                            "message": "batch item `arguments` must be an object",
                            "data": { "error_code": "invalid_params" }
                        }
                    });
                    if results.try_push(result).is_err() {
                        return jsonrpc_response_too_large(id, app.mcp.max_request_bytes);
                    }
                    continue;
                }
            };
            let response =
                handle_named_tool_call(None, app.clone(), inbound_headers, name, arguments).await;
            let Value::Object(mut response) = response else {
                let result = norito::json!({
                    "error": {
                        "code": JSONRPC_INTERNAL_ERROR,
                        "message": "batch item returned malformed response",
                        "data": { "error_code": "internal_error" }
                    }
                });
                if results.try_push(result).is_err() {
                    return jsonrpc_response_too_large(id, app.mcp.max_request_bytes);
                }
                continue;
            };
            if let Some(result) = response.remove("result") {
                norito::json!({ "result": result })
            } else if let Some(error) = response.remove("error") {
                norito::json!({ "error": error })
            } else {
                norito::json!({
                    "error": {
                        "code": JSONRPC_INTERNAL_ERROR,
                        "message": "batch item returned malformed response",
                        "data": { "error_code": "internal_error" }
                    }
                })
            }
        } else {
            norito::json!({
                "error": {
                    "code": JSONRPC_INVALID_PARAMS,
                    "message": "batch item must be an object",
                    "data": { "error_code": "invalid_params" }
                }
            })
        };
        if results.try_push(result).is_err() {
            return jsonrpc_response_too_large(id, app.mcp.max_request_bytes);
        }
    }
    let results = results.into_values();
    jsonrpc_result_response(id, norito::json!({ "results": (results) }))
}
fn mcp_tool_success(structured: Value) -> Value {
    let status = structured.get("status").and_then(Value::as_u64);
    let is_http_error = status.is_some_and(|code| code >= 400);
    let mut structured = structured;
    if is_http_error && let Some(map) = structured.as_object_mut() {
        let error_code = status
            .map(http_status_error_code)
            .unwrap_or("http_error")
            .to_owned();
        map.entry("error_code".into())
            .or_insert(Value::String(error_code));
    }
    let text = match status {
        Some(code) if is_http_error => format!("http error {code}"),
        Some(code) => format!("http {code}"),
        None => "ok".to_owned(),
    };
    norito::json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "isError": is_http_error,
        "structuredContent": structured
    })
}
fn mcp_tool_error(message: String) -> Value {
    let error_message = message.clone();
    let error_code = match message.as_str() {
        TARGET_RESPONSE_TOO_LARGE_MESSAGE => MCP_RESPONSE_TOO_LARGE_CODE,
        TARGET_RESPONSE_READ_FAILED_MESSAGE => MCP_RESPONSE_READ_FAILED_CODE,
        TARGET_RESPONSE_TIMEOUT_MESSAGE => MCP_RESPONSE_TIMEOUT_CODE,
        _ => MCP_TOOL_EXECUTION_ERROR_CODE,
    };
    let envelope = error_envelope_value(
        error_code,
        error_message.as_str(),
        Some(norito::json!({
            "layer": "mcp"
        })),
    );
    norito::json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true,
        "structuredContent": envelope
    })
}
fn parse_parameters(spec: &Value, value: Option<&Value>) -> Vec<ParameterInfo> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    array
        .iter()
        .map(|param| deref_openapi_value(spec, param))
        .filter_map(Value::as_object)
        .filter_map(|param| {
            let name = param.get("name").and_then(Value::as_str)?;
            let location = param.get("in").and_then(Value::as_str)?;
            let required = param
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let schema = param
                .get("schema")
                .map(|schema| inline_openapi_schema(spec, schema, 0))
                .unwrap_or_else(string_schema);
            Some(ParameterInfo {
                name: name.to_owned(),
                location: location.to_owned(),
                required,
                schema,
            })
        })
        .collect()
}
fn build_input_schema(
    spec: &Value,
    path: &str,
    parameters: &[ParameterInfo],
    request_body: Option<&Value>,
) -> Value {
    let mut path_props = Map::new();
    let mut path_required = Vec::new();
    let mut query_props = Map::new();
    let mut header_props = Map::new();
    for param in parameters {
        match param.location.as_str() {
            "path" => {
                path_props.insert(param.name.clone(), param.schema.clone());
                if param.required || path.contains(&format!("{{{}}}", param.name)) {
                    path_required.push(Value::String(param.name.clone()));
                }
            }
            "query" => {
                query_props.insert(param.name.clone(), param.schema.clone());
            }
            "header" => {
                header_props.insert(param.name.clone(), param.schema.clone());
            }
            _ => {}
        }
    }
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut has_request_body = false;
    let mut request_body_required = false;
    let mut content_type_schema = string_schema();
    if !path_props.is_empty() {
        let mut path_schema = Map::new();
        path_schema.insert("type".into(), Value::String("object".to_owned()));
        path_schema.insert("properties".into(), Value::Object(path_props));
        path_schema.insert("additionalProperties".into(), Value::Bool(false));
        if !path_required.is_empty() {
            path_schema.insert("required".into(), Value::Array(path_required));
        }
        properties.insert("path".into(), Value::Object(path_schema));
        required.push(Value::String("path".to_owned()));
    }
    if !query_props.is_empty() {
        let mut query_schema = Map::new();
        query_schema.insert("type".into(), Value::String("object".to_owned()));
        query_schema.insert("properties".into(), Value::Object(query_props));
        query_schema.insert("additionalProperties".into(), Value::Bool(false));
        properties.insert("query".into(), Value::Object(query_schema));
    }
    if !header_props.is_empty() {
        let mut headers_schema = Map::new();
        headers_schema.insert("type".into(), Value::String("object".to_owned()));
        headers_schema.insert("properties".into(), Value::Object(header_props));
        headers_schema.insert("additionalProperties".into(), Value::Bool(false));
        properties.insert("headers".into(), Value::Object(headers_schema));
    } else {
        properties.insert(
            "headers".into(),
            norito::json!({
                "type": "object",
                "additionalProperties": false
            }),
        );
    }
    if let Some(request_body) = request_body {
        let request_body_descriptor = deref_openapi_value(spec, request_body);
        has_request_body = true;
        request_body_required = request_body_descriptor
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let body_schema = build_request_body_schema(spec, request_body);
        properties.insert(
            "body".into(),
            body_schema.unwrap_or_else(|| {
                norito::json!({
                    "description": "Request body payload. JSON values are encoded as application/json unless `content_type` overrides it."
                })
            }),
        );
        properties.insert(
            "body_base64".into(),
            norito::json!({
                "type": "string",
                "description": "Base64-encoded request body payload for binary formats."
            }),
        );
        let media_types = request_body_media_types(spec, request_body);
        if let [media_type] = media_types.as_slice() {
            content_type_schema = norito::json!({
                "type": "string",
                "const": (media_type),
                "default": (media_type),
                "description": "The sole media type accepted by this route. Omission uses this value."
            });
        }
    }
    properties.insert("content_type".into(), content_type_schema);
    properties.insert("accept".into(), string_schema());
    properties.insert(
        "project".into(),
        norito::json!({
            "type": "array",
            "description": "Optional projection keys applied to `structuredContent.body` object items.",
            "maxItems": (MAX_MCP_PROJECTION_KEYS),
            "uniqueItems": true,
            "items": {
                "type": "string",
                "maxLength": (MAX_MCP_PROJECTION_KEY_CHARS)
            }
        }),
    );
    let mut schema = Map::new();
    schema.insert("type".into(), Value::String("object".to_owned()));
    schema.insert("properties".into(), Value::Object(properties));
    schema.insert("additionalProperties".into(), Value::Bool(false));
    if !required.is_empty() {
        schema.insert("required".into(), Value::Array(required));
    }
    if has_request_body {
        schema.insert(
            "not".into(),
            norito::json!({ "required": ["body", "body_base64"] }),
        );
        if request_body_required {
            schema.insert(
                "anyOf".into(),
                norito::json!([
                    { "required": ["body"] },
                    { "required": ["body_base64"] }
                ]),
            );
        }
    }
    Value::Object(schema)
}
fn request_body_media_types(spec: &Value, request_body: &Value) -> Vec<String> {
    let request_body = deref_openapi_value(spec, request_body);
    let Some(content) = request_body.get("content").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut media_types: Vec<_> = content.keys().cloned().collect();
    media_types.sort();
    media_types.dedup();
    media_types
}
fn build_request_body_schema(spec: &Value, request_body: &Value) -> Option<Value> {
    let request_body = deref_openapi_value(spec, request_body);
    let content = request_body.get("content").and_then(Value::as_object)?;
    let mut schemas = Vec::new();
    for media in content.values() {
        let Some(media_obj) = media.as_object() else {
            continue;
        };
        let Some(schema) = media_obj.get("schema") else {
            continue;
        };
        schemas.push(inline_openapi_schema(spec, schema, 0));
    }
    match schemas.len() {
        0 => None,
        1 => schemas.into_iter().next(),
        _ => Some(norito::json!({ "oneOf": schemas })),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GovernanceOpenapiValidation {
    ProposalPath {
        field: &'static str,
    },
    SelectorPath {
        field: &'static str,
        label: &'static str,
    },
    SelectorBody {
        field: &'static str,
    },
}
impl GovernanceOpenapiValidation {
    const fn requires_body(self) -> bool {
        matches!(self, Self::SelectorBody { .. })
    }
}
fn governance_openapi_validation(
    method: &Method,
    path: &str,
) -> Option<GovernanceOpenapiValidation> {
    match (method.as_str(), path) {
        ("GET", "/v1/gov/proposals/{id}") => {
            Some(GovernanceOpenapiValidation::ProposalPath { field: "id" })
        }
        ("GET", "/v1/gov/locks/{rid}") => Some(GovernanceOpenapiValidation::SelectorPath {
            field: "rid",
            label: "referendum id",
        }),
        ("GET", "/v1/gov/referenda/{id}") => Some(GovernanceOpenapiValidation::SelectorPath {
            field: "id",
            label: "referendum id",
        }),
        ("GET", "/v1/gov/tally/{id}") => Some(GovernanceOpenapiValidation::SelectorPath {
            field: "id",
            label: "tally id",
        }),
        ("POST", "/v1/zk/vote/tally")
        | ("POST", "/v1/gov/ballots/zk-v1")
        | ("POST", "/v1/gov/ballots/zk-v1/ballot-proof") => {
            Some(GovernanceOpenapiValidation::SelectorBody {
                field: "election_id",
            })
        }
        ("POST", "/v1/gov/ballots/plain") => Some(GovernanceOpenapiValidation::SelectorBody {
            field: "referendum_id",
        }),
        _ => None,
    }
}
fn harden_governance_openapi_input_schema(
    spec: &Value,
    request_body: Option<&Value>,
    method: &Method,
    path: &str,
    schema: &mut Value,
) {
    let Some(validation) = governance_openapi_validation(method, path) else {
        return;
    };
    if !validation.requires_body() {
        return;
    }
    let schema = schema
        .as_object_mut()
        .expect("OpenAPI-derived MCP input schema is an object");
    schema.insert(
        MCP_STRICT_BODY_SCHEMA_EXTENSION.to_owned(),
        Value::Bool(true),
    );
    let properties = schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("OpenAPI-derived MCP input properties are an object");
    let json_body_schema = request_body
        .map(|request_body| deref_openapi_value(spec, request_body))
        .and_then(|request_body| request_body.get("content"))
        .and_then(Value::as_object)
        .and_then(|content| content.get("application/json"))
        .and_then(|media| media.get("schema"))
        .map(|schema| inline_openapi_schema(spec, schema, 0))
        .expect("governance MCP routes must expose one typed application/json body");
    properties.insert("body".to_owned(), json_body_schema);
    properties.remove("body_base64");
    properties.insert(
        "content_type".to_owned(),
        norito::json!({
            "type": "string",
            "const": "application/json",
            "description": "Governance identifier preflight requires the exact JSON body representation."
        }),
    );
    let required = schema
        .entry("required".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("OpenAPI-derived MCP required fields are an array");
    if !required.iter().any(|field| field.as_str() == Some("body")) {
        required.push(Value::String("body".to_owned()));
    }
}
fn deref_openapi_value<'a>(spec: &'a Value, value: &'a Value) -> &'a Value {
    let mut current = value;
    for _ in 0..8 {
        let Some(reference) = current
            .as_object()
            .and_then(|obj| obj.get("$ref"))
            .and_then(Value::as_str)
        else {
            break;
        };
        let Some(resolved) = resolve_openapi_ref(spec, reference) else {
            break;
        };
        current = resolved;
    }
    current
}
fn inline_openapi_schema(spec: &Value, value: &Value, depth: usize) -> Value {
    const MAX_INLINE_SCHEMA_DEPTH: usize = 64;
    if depth >= MAX_INLINE_SCHEMA_DEPTH {
        return value.clone();
    }
    if let Some(reference) = value
        .as_object()
        .and_then(|object| object.get("$ref"))
        .and_then(Value::as_str)
        && let Some(resolved) = resolve_openapi_ref(spec, reference)
    {
        return inline_openapi_schema(spec, resolved, depth + 1);
    }
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(name, value)| (name.clone(), inline_openapi_schema(spec, value, depth + 1)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| inline_openapi_schema(spec, item, depth + 1))
                .collect(),
        ),
        _ => value.clone(),
    }
}
fn resolve_openapi_ref<'a>(spec: &'a Value, reference: &str) -> Option<&'a Value> {
    let path = reference.strip_prefix("#/")?;
    let mut current = spec;
    for raw in path.split('/') {
        let key = raw.replace("~1", "/").replace("~0", "~");
        current = current.get(key.as_str())?;
    }
    Some(current)
}
fn string_schema() -> Value {
    norito::json!({ "type": "string" })
}
fn method_from_key(key: &str) -> Option<Method> {
    match key {
        "get" => Some(Method::GET),
        "post" => Some(Method::POST),
        "put" => Some(Method::PUT),
        "patch" => Some(Method::PATCH),
        "delete" => Some(Method::DELETE),
        "head" => Some(Method::HEAD),
        "options" => Some(Method::OPTIONS),
        _ => None,
    }
}
fn catalog_method(method: &Method) -> Option<CatalogHttpMethod> {
    match *method {
        Method::GET => Some(CatalogHttpMethod::Get),
        Method::POST => Some(CatalogHttpMethod::Post),
        Method::PUT => Some(CatalogHttpMethod::Put),
        Method::PATCH => Some(CatalogHttpMethod::Patch),
        Method::DELETE => Some(CatalogHttpMethod::Delete),
        _ => None,
    }
}
include!("mcp/catalog_projection.rs");
fn catalog_route_requires_operator(route: &RouteDescriptor) -> bool {
    route.surface() == ApiSurface::Operator
        || route.admission() == AdmissionPolicy::Operator
        || matches!(
            route.authentication(),
            AuthenticationPolicy::OperatorSignature
                | AuthenticationPolicy::OperatorCredentialExchange
        )
}
fn tool_requires_operator(tool: &ToolSpec) -> bool {
    tool_semantics(tool).authority() == AuthorityClass::Operator
}
fn is_audited_protocol_handshake_tool(tool: &ToolSpec) -> bool {
    let Some((_, method, path_template)) = tool.route_backing() else {
        return false;
    };
    matches!(
        (tool.name.as_str(), method.as_str(), path_template),
        ("iroha.connect.ws.ticket", "GET", "/v1/connect/ws")
            | (
                "iroha.connect.session.create",
                "POST",
                "/v1/connect/session"
            )
            | (
                "iroha.connect.session.delete",
                "DELETE",
                "/v1/connect/session/{sid}"
            )
            | ("iroha.connect.session.status", "GET", "/v1/connect/status")
            | (
                "iroha.accounts.faucet.prepare",
                "POST",
                "/v1/accounts/faucet/prepare"
            )
            | (
                "iroha.accounts.faucet.submit",
                "POST",
                "/v1/accounts/faucet"
            )
    )
}
fn apply_catalog_auth_schemas_to_tools(tools: &mut [ToolSpec], groups: &[CatalogProjectionGroup]) {
    for tool in tools {
        let Some((_, method, path_template)) = tool.route_backing() else {
            continue;
        };
        let Some(descriptor) = catalog_descriptor_for_method_path(groups, method, path_template)
        else {
            continue;
        };
        let Some(schema) = tool.input_schema.as_object_mut() else {
            continue;
        };
        let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) else {
            continue;
        };
        match descriptor.authentication() {
            AuthenticationPolicy::CanonicalAccountSignature => {
                // Purpose-built VPN tools carry a typed `canonical_auth`
                // envelope and normalize it into headers only after bounded
                // wire preflight.
                if properties.contains_key("canonical_auth")
                    || tool.name.starts_with("iroha.gov.ballots.")
                {
                    continue;
                }
                properties.insert(
                    "headers".to_owned(),
                    canonical_account_auth_headers_schema(
                        "Canonical proof signed for the exact target method, path, query, and body.",
                    ),
                );
            }
            AuthenticationPolicy::OptionalCanonicalAccountSignature => {
                properties.insert(
                    "headers".to_owned(),
                    canonical_account_auth_headers_schema(
                        "Optional canonical proof signed for the exact target method, path, query, and body. Omit the envelope for the anonymous public-dataspace view.",
                    ),
                );
                continue;
            }
            AuthenticationPolicy::OperatorSignature => {
                if properties.contains_key("operator_auth") {
                    continue;
                }
                properties.insert("headers".to_owned(), operator_auth_headers_schema());
            }
            _ => continue,
        }
        let required = schema
            .entry("required".to_owned())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("tool schema `required` is an array");
        if !required
            .iter()
            .any(|value| value.as_str() == Some("headers"))
        {
            required.push(Value::String("headers".to_owned()));
        }
    }
}

/// Verify that a name-dispatched purpose-built wrapper advertises the exact
/// method and path template which its implementation executes.
///
/// `Ok(false)` identifies route-backed tools which use the generic adapter.
/// Keeping that distinction explicit makes constructor drift fail closed both
/// while building the registry and in tests which inject their own tool set.
fn validate_purpose_built_dispatch_backing(tool: &ToolSpec) -> Result<bool, String> {
    let Some((expected_method, expected_path_template)) =
        purpose_built_dispatch_route_contract(&tool.name)
    else {
        return Ok(false);
    };
    let Some((_, method, path_template)) = tool.route_backing() else {
        return Err(format!(
            "purpose-built tool `{}` must use HTTP route backing",
            tool.name
        ));
    };
    if method.as_str() != expected_method || path_template != expected_path_template {
        return Err(format!(
            "purpose-built tool `{}` backing drifted: expected {} {}, got {} {}",
            tool.name, expected_method, expected_path_template, method, path_template
        ));
    }
    Ok(true)
}

fn validate_tool_registry(
    tools: &[ToolSpec],
    groups: &[CatalogProjectionGroup],
) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for tool in tools {
        let advertised_schema = sanitize_tool_input_schema(&tool.input_schema);
        validate_advertised_schema_patterns(
            &advertised_schema,
            &format!("tool `{}` input schema", tool.name),
        )?;
        reject_unresolved_schema_refs(
            &advertised_schema,
            &format!("tool `{}` input schema", tool.name),
        )?;
        if !names.insert(tool.name.as_str()) {
            return Err(format!("duplicate tool name `{}`", tool.name));
        }
        let (effect, method, path_template) = match tool.backing() {
            ToolBacking::InProcess(in_process) => {
                if tool.name != in_process.name() {
                    return Err(format!(
                        "in-process tool `{}` must use its canonical name `{}`",
                        tool.name,
                        in_process.name()
                    ));
                }
                if !tool.name.starts_with("iroha.") {
                    return Err(format!(
                        "in-process tool `{}` is outside the explicit iroha.* namespace",
                        tool.name
                    ));
                }
                continue;
            }
            ToolBacking::Route {
                effect,
                method,
                path_template,
            } => {
                if matches!(
                    tool.name.as_str(),
                    "iroha.transactions.prepare" | "iroha.transactions.inspect"
                ) {
                    return Err(format!(
                        "in-process tool name `{}` cannot use HTTP route backing",
                        tool.name
                    ));
                }
                (*effect, method, path_template.as_str())
            }
        };
        validate_purpose_built_dispatch_backing(tool)?;
        let descriptor = catalog_descriptor_for_method_path(groups, method, path_template);
        if let Some(route) = descriptor {
            if route.authentication() == AuthenticationPolicy::ProtocolHandshake
                && !is_audited_protocol_handshake_tool(tool)
            {
                return Err(format!(
                    "protocol-handshake route tool `{}` lacks an exact audited MCP wrapper",
                    tool.name
                ));
            }
            if matches!(
                route.authentication(),
                AuthenticationPolicy::OperatorCredentialExchange
                    | AuthenticationPolicy::NestedRouteAuthentication
            ) {
                return Err(format!(
                    "credential-exchange or nested transport route `{}` cannot be an MCP tool",
                    tool.name
                ));
            }
            if route.effect() == RouteEffect::Mutation
                && matches!(effect, ToolEffect::Read | ToolEffect::BuildInstruction)
            {
                return Err(format!(
                    "mutating route tool `{}` cannot advertise a non-mutating effect",
                    tool.name
                ));
            }
            if route.effect() == RouteEffect::LongLivedStream
                && !is_audited_protocol_handshake_tool(tool)
            {
                return Err(format!(
                    "long-lived route `{}` cannot be dispatched as a bounded MCP tool",
                    tool.name
                ));
            }
        }
        match descriptor.map(|route| route.authentication()) {
            Some(AuthenticationPolicy::CanonicalAccountSignature) => {
                validate_canonical_auth_tool_schema(tool)?;
            }
            Some(AuthenticationPolicy::OptionalCanonicalAccountSignature) => {
                validate_optional_canonical_auth_tool_schema(tool)?;
            }
            Some(AuthenticationPolicy::OperatorSignature) => {
                validate_operator_auth_tool_schema(tool)?;
            }
            _ => {}
        }
        if !tool.name.starts_with("torii.") {
            if !tool.name.starts_with("iroha.") {
                return Err(format!(
                    "purpose-built tool `{}` is outside the explicit iroha.* namespace",
                    tool.name
                ));
            }
            continue;
        }
        if catalog_mcp_projection_decision(groups, method, path_template) != Some(true) {
            return Err(format!(
                "OpenAPI-derived tool `{}` lacks an enabled exact catalog MCP projection for {} {}",
                tool.name, method, path_template
            ));
        }
        descriptor.expect("an enabled catalog MCP projection has an exact descriptor");
        let Some(method_key) = canonical_tool_method_key(method) else {
            return Err(format!(
                "OpenAPI-derived tool `{}` uses unsupported HTTP method {}",
                tool.name, method
            ));
        };
        let expected = format!(
            "torii.{}",
            generated_operation_id(method_key, path_template)
        );
        if tool.name != expected {
            return Err(format!(
                "OpenAPI-derived tool `{}` is an alias; canonical exact name is `{expected}`",
                tool.name
            ));
        }
    }
    Ok(())
}
fn validate_canonical_auth_tool_schema(tool: &ToolSpec) -> Result<(), String> {
    validate_canonical_auth_tool_schema_with_requirement(tool, true)
}
fn validate_optional_canonical_auth_tool_schema(tool: &ToolSpec) -> Result<(), String> {
    validate_canonical_auth_tool_schema_with_requirement(tool, false)
}
fn validate_canonical_auth_tool_schema_with_requirement(
    tool: &ToolSpec,
    authentication_required: bool,
) -> Result<(), String> {
    let schema = tool.input_schema.as_object().ok_or_else(|| {
        format!(
            "canonical-auth tool `{}` must publish an object input schema",
            tool.name
        )
    })?;
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!(
            "canonical-auth tool `{}` must publish an object input schema",
            tool.name
        ));
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!(
                "canonical-auth tool `{}` must publish input properties",
                tool.name
            )
        })?;
    if let Some(auth) = properties.get("canonical_auth").and_then(Value::as_object) {
        let auth_properties =
            auth.get("properties")
                .and_then(Value::as_object)
                .filter(|properties| {
                    auth.get("type").and_then(Value::as_str) == Some("object")
                        && auth.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                        && object_has_exact_properties(
                            properties,
                            &["account", "signature", "timestamp_ms", "nonce", "witness"],
                        )
                });
        let constrained = auth_properties.is_some_and(|properties| {
            bounded_string_schema(
                properties.get("account"),
                1,
                crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
                None,
            ) && bounded_string_schema(
                properties.get("signature"),
                4,
                CANONICAL_SIGNATURE_MAX_ENCODED_BYTES,
                Some(CANONICAL_PADDED_BASE64_PATTERN),
            ) && properties
                .get("timestamp_ms")
                .and_then(Value::as_object)
                .is_some_and(|property| {
                    property.get("type").and_then(Value::as_str) == Some("integer")
                        && property.get("minimum").and_then(Value::as_u64) == Some(0)
                        && property.get("maximum").and_then(Value::as_u64) == Some(u64::MAX)
                })
                && bounded_string_schema(properties.get("nonce"), 1, 256, Some("^[!-~]+$"))
                && bounded_string_schema(
                    properties.get("witness"),
                    4,
                    CANONICAL_WITNESS_MAX_ENCODED_BYTES,
                    Some(CANONICAL_PADDED_BASE64_PATTERN),
                )
        });
        if schema_requires(schema, "canonical_auth") == authentication_required
            && constrained
            && auth_schema_has_exclusive_branches(
                auth,
                "account",
                "signature",
                "timestamp_ms",
                "nonce",
                "witness",
            )
        {
            return Ok(());
        }
        return Err(format!(
            "canonical-auth tool `{}` must require a closed, bounded typed canonical_auth envelope with exclusive signature and witness branches",
            tool.name
        ));
    }
    let headers = properties
        .get("headers")
        .and_then(Value::as_object)
        .filter(|headers| {
            headers.get("type").and_then(Value::as_str) == Some("object")
                && headers.get("additionalProperties").and_then(Value::as_bool) == Some(false)
        });
    let Some(header_properties) = headers
        .and_then(|headers| headers.get("properties"))
        .and_then(Value::as_object)
    else {
        return Err(format!(
            "canonical-auth tool `{}` must publish closed target header properties",
            tool.name
        ));
    };
    if !object_has_exact_properties(
        header_properties,
        &[
            crate::HEADER_ACCOUNT,
            crate::HEADER_SIGNATURE,
            crate::HEADER_TIMESTAMP_MS,
            crate::HEADER_NONCE,
            crate::HEADER_WITNESS,
        ],
    ) {
        return Err(format!(
            "canonical-auth tool `{}` must publish the exact target header properties",
            tool.name
        ));
    }
    let constrained = bounded_string_schema(
        header_properties.get(crate::HEADER_ACCOUNT),
        1,
        crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
        Some(CANONICAL_ACCOUNT_HEADER_PATTERN),
    ) && bounded_string_schema(
        header_properties.get(crate::HEADER_SIGNATURE),
        4,
        CANONICAL_SIGNATURE_MAX_ENCODED_BYTES,
        Some(CANONICAL_PADDED_BASE64_PATTERN),
    ) && bounded_string_schema(
        header_properties.get(crate::HEADER_TIMESTAMP_MS),
        1,
        20,
        Some("^(0|[1-9][0-9]*)$"),
    ) && bounded_string_schema(
        header_properties.get(crate::HEADER_NONCE),
        1,
        256,
        Some("^[!-~]+$"),
    ) && bounded_string_schema(
        header_properties.get(crate::HEADER_WITNESS),
        4,
        CANONICAL_WITNESS_MAX_ENCODED_BYTES,
        Some(CANONICAL_PADDED_BASE64_PATTERN),
    );
    if schema_requires(schema, "headers") != authentication_required
        || !constrained
        || !auth_schema_has_exclusive_branches(
            headers.expect("closed headers schema exists"),
            crate::HEADER_ACCOUNT,
            crate::HEADER_SIGNATURE,
            crate::HEADER_TIMESTAMP_MS,
            crate::HEADER_NONCE,
            crate::HEADER_WITNESS,
        )
    {
        return Err(format!(
            "canonical-auth tool `{}` must require strict bounded target authentication headers with exclusive signature and witness branches",
            tool.name
        ));
    }
    Ok(())
}
fn validate_operator_auth_tool_schema(tool: &ToolSpec) -> Result<(), String> {
    let schema = tool.input_schema.as_object().ok_or_else(|| {
        format!(
            "operator-auth tool `{}` must publish an object input schema",
            tool.name
        )
    })?;
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!(
            "operator-auth tool `{}` must publish an object input schema",
            tool.name
        ));
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("operator-auth tool `{}` lacks properties", tool.name))?;
    if let Some(auth) = properties.get("operator_auth").and_then(Value::as_object) {
        let auth_properties =
            auth.get("properties")
                .and_then(Value::as_object)
                .filter(|properties| {
                    auth.get("type").and_then(Value::as_str) == Some("object")
                        && auth.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                        && object_has_exact_properties(
                            properties,
                            &["public_key", "timestamp_ms", "nonce", "signature"],
                        )
                });
        let valid = auth_properties.is_some_and(|properties| {
            bounded_string_schema(
                properties.get("public_key"),
                1,
                OPERATOR_PUBLIC_KEY_MAX_LITERAL_BYTES,
                Some("^[!-~]+$"),
            ) && properties
                .get("timestamp_ms")
                .and_then(Value::as_object)
                .is_some_and(|property| {
                    property.get("type").and_then(Value::as_str) == Some("integer")
                        && property.get("minimum").and_then(Value::as_u64) == Some(0)
                        && property.get("maximum").and_then(Value::as_u64) == Some(u64::MAX)
                })
                && bounded_string_schema(properties.get("nonce"), 1, 256, Some("^[!-~]+$"))
                && bounded_string_schema(
                    properties.get("signature"),
                    4,
                    CANONICAL_SIGNATURE_MAX_ENCODED_BYTES,
                    Some(CANONICAL_PADDED_BASE64_PATTERN),
                )
        }) && schema_has_exact_required(
            auth,
            &["public_key", "timestamp_ms", "nonce", "signature"],
        );
        if schema_requires(schema, "operator_auth") && valid {
            return Ok(());
        }
    } else if let Some(headers) = properties.get("headers").and_then(Value::as_object) {
        let header_properties =
            headers
                .get("properties")
                .and_then(Value::as_object)
                .filter(|properties| {
                    headers.get("type").and_then(Value::as_str) == Some("object")
                        && headers.get("additionalProperties").and_then(Value::as_bool)
                            == Some(false)
                        && object_has_exact_properties(
                            properties,
                            &[
                                "X-Iroha-Operator-Public-Key",
                                "X-Iroha-Operator-Timestamp-Ms",
                                "X-Iroha-Operator-Nonce",
                                "X-Iroha-Operator-Signature",
                            ],
                        )
                });
        let valid = header_properties.is_some_and(|properties| {
            bounded_string_schema(
                properties.get("X-Iroha-Operator-Public-Key"),
                1,
                OPERATOR_PUBLIC_KEY_MAX_LITERAL_BYTES,
                Some("^[!-~]+$"),
            ) && bounded_string_schema(
                properties.get("X-Iroha-Operator-Timestamp-Ms"),
                1,
                20,
                Some("^(0|[1-9][0-9]*)$"),
            ) && bounded_string_schema(
                properties.get("X-Iroha-Operator-Nonce"),
                1,
                256,
                Some("^[!-~]+$"),
            ) && bounded_string_schema(
                properties.get("X-Iroha-Operator-Signature"),
                4,
                CANONICAL_SIGNATURE_MAX_ENCODED_BYTES,
                Some(CANONICAL_PADDED_BASE64_PATTERN),
            ) && schema_has_exact_required(
                headers,
                &[
                    "X-Iroha-Operator-Public-Key",
                    "X-Iroha-Operator-Timestamp-Ms",
                    "X-Iroha-Operator-Nonce",
                    "X-Iroha-Operator-Signature",
                ],
            )
        });
        if schema_requires(schema, "headers") && valid {
            return Ok(());
        }
    }
    Err(format!(
        "operator-auth tool `{}` must require a complete closed and bounded operator signature tuple",
        tool.name
    ))
}
fn bounded_string_schema(
    value: Option<&Value>,
    min_length: usize,
    max_length: usize,
    pattern: Option<&str>,
) -> bool {
    value.and_then(Value::as_object).is_some_and(|property| {
        property.get("type").and_then(Value::as_str) == Some("string")
            && property.get("minLength").and_then(Value::as_u64) == u64::try_from(min_length).ok()
            && property.get("maxLength").and_then(Value::as_u64) == u64::try_from(max_length).ok()
            && pattern.is_none_or(|pattern| {
                property.get("pattern").and_then(Value::as_str) == Some(pattern)
            })
    })
}
fn object_has_exact_properties(properties: &Map, expected: &[&str]) -> bool {
    properties.len() == expected.len() && expected.iter().all(|name| properties.contains_key(*name))
}
fn schema_requires(schema: &Map, field: &str) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|value| value.as_str() == Some(field)))
}
fn schema_has_exact_required(schema: &Map, expected: &[&str]) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| {
            required.len() == expected.len()
                && expected
                    .iter()
                    .all(|name| required.iter().any(|value| value.as_str() == Some(*name)))
        })
}
fn auth_schema_has_exclusive_branches(
    schema: &Map,
    account: &str,
    signature: &str,
    timestamp: &str,
    nonce: &str,
    witness: &str,
) -> bool {
    let Some(branches) = schema.get("oneOf").and_then(Value::as_array) else {
        return false;
    };
    if branches.len() != 2 {
        return false;
    }
    let signature_branch = branches.iter().find_map(|branch| {
        let branch = branch.as_object()?;
        schema_requires(branch, signature).then_some(branch)
    });
    let witness_branch = branches.iter().find_map(|branch| {
        let branch = branch.as_object()?;
        schema_requires(branch, witness).then_some(branch)
    });
    let signature_valid = signature_branch.is_some_and(|branch| {
        schema_has_exact_required(branch, &[account, signature, timestamp, nonce])
            && branch
                .get("not")
                .and_then(Value::as_object)
                .is_some_and(|not| schema_has_exact_required(not, &[witness]))
    });
    let witness_valid = witness_branch.is_some_and(|branch| {
        schema_has_exact_required(branch, &[witness])
            && branch
                .get("not")
                .and_then(Value::as_object)
                .and_then(|not| not.get("anyOf"))
                .and_then(Value::as_array)
                .is_some_and(|forbidden| {
                    forbidden.len() == 3
                        && [signature, timestamp, nonce].iter().all(|name| {
                            forbidden.iter().any(|branch| {
                                branch.as_object().is_some_and(|branch| {
                                    branch
                                        .get("required")
                                        .and_then(Value::as_array)
                                        .is_some_and(|required| {
                                            required.len() == 1 && schema_requires(branch, name)
                                        })
                                })
                            })
                        })
                })
    });
    signature_valid && witness_valid
}
fn catalog_descriptor_for_method_path(
    groups: &[CatalogProjectionGroup],
    method: &Method,
    path: &str,
) -> Option<&'static RouteDescriptor> {
    let method = catalog_method(method)?;
    groups
        .iter()
        .flat_map(|group| group.routes)
        .find(|route| route.method() == method && route.path() == path)
}
fn catalog_descriptor_for_dispatch(
    groups: &[CatalogProjectionGroup],
    method: &Method,
    path_and_query: &str,
) -> Result<&'static RouteDescriptor, String> {
    let method = catalog_method(method)
        .ok_or_else(|| format!("MCP dispatch method is not catalogable: {method}"))?;
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    let routes = groups.iter().flat_map(|group| group.routes);
    if let Some(exact) = routes
        .clone()
        .find(|route| route.method() == method && route.path() == path)
    {
        return Ok(exact);
    }
    let mut matches = routes
        .filter(|route| route.method() == method && route_template_matches(route.path(), path));
    let method_name = method.as_str();
    let first = matches
        .next()
        .ok_or_else(|| format!("MCP dispatch target is not cataloged: {method_name} {path}"))?;
    if let Some(second) = matches.next() {
        return Err(format!(
            "MCP dispatch target is ambiguous between `{}` and `{}`: {method_name} {path}",
            first.path(),
            second.path()
        ));
    }
    Ok(first)
}
fn route_template_matches(template: &str, path: &str) -> bool {
    let mut template_segments = template.trim_start_matches('/').split('/');
    let mut path_segments = path.trim_start_matches('/').split('/');
    loop {
        match (template_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(segment), Some(path_segment))
                if segment.starts_with("{*") && segment.ends_with('}') =>
            {
                return !path_segment.is_empty();
            }
            (Some(template_segment), Some(path_segment))
                if template_segment.starts_with('{') && template_segment.ends_with('}') =>
            {
                if path_segment.is_empty() {
                    return false;
                }
            }
            (Some(template_segment), Some(path_segment)) if template_segment == path_segment => {}
            _ => return false,
        }
    }
}
fn canonical_tool_method_key(method: &Method) -> Option<&'static str> {
    match *method {
        Method::GET => Some("get"),
        Method::POST => Some("post"),
        Method::PUT => Some("put"),
        Method::PATCH => Some("patch"),
        Method::DELETE => Some("delete"),
        _ => None,
    }
}
fn operation_uses_streaming_transport(spec: &Value, operation: &Map) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .is_some_and(|responses| {
            responses.iter().any(|(status, response)| {
                if status == "101" {
                    return true;
                }
                let response = deref_openapi_value(spec, response);
                response
                    .get("content")
                    .and_then(Value::as_object)
                    .is_some_and(|content| {
                        content.keys().any(|media_type| {
                            media_type.split(';').next().is_some_and(|essence| {
                                essence.trim().eq_ignore_ascii_case("text/event-stream")
                            })
                        })
                    })
            })
        })
}
fn should_skip_operation(
    spec: &Value,
    path: &str,
    operation: &Map,
    expose_operator_routes: bool,
) -> bool {
    if path == iroha_torii_shared::route_catalog::streaming::SUBSCRIPTION_WS.path()
        || path == iroha_torii_shared::route_catalog::streaming::BLOCKS_WS.path()
        || matches!(path, "/v1/connect/ws" | "/v1/mcp")
    {
        return true;
    }
    if path.ends_with("/sse") {
        return true;
    }
    if operation_uses_streaming_transport(spec, operation) {
        return true;
    }
    if path == "/openapi.json" {
        return true;
    }
    if !expose_operator_routes {
        let has_operator_tag =
            operation
                .get("tags")
                .and_then(Value::as_array)
                .is_some_and(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .any(|tag| tag == "OperatorAuth")
                });
        if has_operator_tag || path.starts_with("/v1/operator/") {
            return true;
        }
    }
    false
}
fn generated_operation_id(method: &str, path: &str) -> String {
    let mut out = String::new();
    out.push_str(method);
    out.push('_');
    for c in path.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_owned()
}
fn find_tool_spec_by_name<'a>(tools: &'a [ToolSpec], requested_name: &str) -> Option<&'a ToolSpec> {
    tools.iter().find(|tool| tool.name == requested_name)
}
async fn dispatch_openapi_tool(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    tool: &ToolSpec,
    arguments: &Map,
) -> Result<Value, String> {
    let Some((_, method, path_template)) = tool.route_backing() else {
        return Err(format!(
            "in-process tool `{}` cannot be dispatched through the HTTP route adapter",
            tool.name
        ));
    };
    validate_governance_openapi_dispatch(method, path_template, arguments)?;
    let route = fill_path_template(path_template, arguments.get("path"))?;
    let route = append_query(route, arguments.get("query"))?;
    let default_content_type = tool
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("content_type"))
        .and_then(|schema| schema.get("const"))
        .and_then(Value::as_str);
    let (body, content_type) = build_request_body(arguments, default_content_type)?;
    let accept = arguments.get("accept").and_then(Value::as_str);
    let structured = dispatch_route_borrowed(
        app,
        inbound_headers,
        method.clone(),
        route.as_str(),
        arguments.get("headers"),
        body,
        content_type,
        accept,
    )
    .await?;
    Ok(apply_body_projection(structured, arguments.get("project")))
}
async fn dispatch_connect_session_create(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_connect_session_create_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/connect/session",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_connect_session_delete(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["sid", "token_management", "headers", "accept"],
        "iroha.connect.session.delete",
    )?;
    let sid = canonical_connect_sid_argument(arguments)?;
    let mut path = String::from("/v1/connect/session/");
    try_append_percent_encoded_path_component(&mut path, sid)?;
    let management_token = arguments
        .get("token_management")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty());
    dispatch_route_with_borrowed_headers(
        app,
        inbound_headers,
        Method::DELETE,
        path.as_str(),
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments.get("accept").and_then(Value::as_str),
        ExtraHeaderPolicy::ConnectManagement,
        management_token,
    )
    .await
}
include!("mcp/connect_status_tools.rs");
include!("mcp/borrowed_dispatch.rs");
macro_rules! declare_mcp_dispatch_wrappers {
    (
        direct_get {
            $( $direct_get_name:ident => $direct_get_route:literal; )*
        }
        object_post {
            $( $object_post_name:ident => $object_post_route:literal; )*
        }
        list_query {
            $( $list_query_name:ident => $list_query_route:literal; )*
        }
        collection_get {
            $( $collection_get_name:ident => $collection_get_route:literal; )*
        }
        collection_post {
            $( $collection_post_name:ident => $collection_post_route:literal; )*
        }
        path_get {
            $(
                $path_get_name:ident => (
                    $path_get_key:literal,
                    |$path_get_arguments:ident| $path_get_extract:expr,
                    $path_get_route:literal
                );
            )*
        }
        path_query_get {
            $(
                $path_query_get_name:ident => (
                    $path_query_get_key:literal,
                    |$path_query_get_arguments:ident| $path_query_get_extract:expr,
                    $path_query_get_route:literal
                );
            )*
        }
        path_collection_get {
            $(
                $path_collection_get_name:ident => (
                    $path_collection_get_key:literal,
                    |$path_collection_get_arguments:ident| $path_collection_get_extract:expr,
                    $path_collection_get_route:literal
                );
            )*
        }
        path_collection_post {
            $(
                $path_collection_post_name:ident => (
                    $path_collection_post_key:literal,
                    |$path_collection_post_arguments:ident| $path_collection_post_extract:expr,
                    $path_collection_post_route:literal
                );
            )*
        }
    ) => {
        $(
            async fn $direct_get_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::GET,
                    $direct_get_route,
                    arguments.get("headers"),
                    Vec::new(),
                    None,
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $object_post_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let body =
                    build_required_object_body(arguments)?;
                let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::POST,
                    $object_post_route,
                    arguments.get("headers"),
                    body_bytes,
                    Some("application/json".to_owned()),
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $list_query_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let route = append_query_arguments(
                    $list_query_route.to_owned(),
                    arguments,
                    &["query", "headers", "accept"],
                )?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::GET,
                    route.as_str(),
                    arguments.get("headers"),
                    Vec::new(),
                    None,
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $collection_get_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let route = collection_get_route($collection_get_route.to_owned(), arguments)?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::GET,
                    route.as_str(),
                    arguments.get("headers"),
                    Vec::new(),
                    None,
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $collection_post_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let body = collection_post_body(arguments)?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::POST,
                    $collection_post_route,
                    arguments.get("headers"),
                    body,
                    Some("application/json".to_owned()),
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $path_get_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let route = {
                    let $path_get_arguments: &Map = arguments;
                    single_path_route($path_get_route, $path_get_key, $path_get_extract?)?
                };
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::GET,
                    route.as_str(),
                    arguments.get("headers"),
                    Vec::new(),
                    None,
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $path_query_get_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let route = {
                    let $path_query_get_arguments: &Map = arguments;
                    single_path_route(
                        $path_query_get_route,
                        $path_query_get_key,
                        $path_query_get_extract?,
                    )?
                };
                let route = append_query_arguments(
                    route,
                    arguments,
                    &["path", $path_query_get_key, "query", "headers", "accept"],
                )?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::GET,
                    route.as_str(),
                    arguments.get("headers"),
                    Vec::new(),
                    None,
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $path_collection_get_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let route = {
                    let $path_collection_get_arguments: &Map = arguments;
                    single_path_route(
                        $path_collection_get_route,
                        $path_collection_get_key,
                        $path_collection_get_extract?,
                    )?
                };
                let route = collection_get_route(route, arguments)?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::GET,
                    route.as_str(),
                    arguments.get("headers"),
                    Vec::new(),
                    None,
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
        $(
            async fn $path_collection_post_name(
                app: &SharedAppState,
                inbound_headers: &HeaderMap,
                arguments: &Map,
            ) -> Result<Value, String> {
                let route = {
                    let $path_collection_post_arguments: &Map = arguments;
                    single_path_route(
                        $path_collection_post_route,
                        $path_collection_post_key,
                        $path_collection_post_extract?,
                    )?
                };
                let body = collection_post_body(arguments)?;
                dispatch_route(
                    app,
                    inbound_headers,
                    Method::POST,
                    route.as_str(),
                    arguments.get("headers"),
                    body,
                    Some("application/json".to_owned()),
                    arguments
                        .get("accept")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
                .await
            }
        )*
    };
}

declare_mcp_dispatch_wrappers! {
    direct_get {
        dispatch_iroha_vpn_profile => "/v1/vpn/profile";
        dispatch_iroha_health => "/health";
        dispatch_iroha_accounts_faucet_policy => "/v1/accounts/faucet/policy";
        dispatch_iroha_parameters_get => "/v1/parameters";
        dispatch_iroha_node_capabilities => "/v1/node/capabilities";
        dispatch_iroha_node_query_projection_checkpoint => "/v1/node/query/projection/checkpoint";
        dispatch_iroha_da_proof_policies => "/v1/da/proof-policies";
        dispatch_iroha_runtime_abi_active => "/v1/runtime/abi/active";
        dispatch_iroha_runtime_abi_hash => "/v1/runtime/abi/hash";
        dispatch_iroha_runtime_metrics => "/v1/runtime/metrics";
        dispatch_iroha_runtime_upgrades_list => "/v1/runtime/upgrades";
        dispatch_iroha_gov_protected_namespaces_list => "/v1/gov/protected-namespaces";
        dispatch_iroha_gov_unlocks_stats => "/v1/gov/unlocks/stats";
        dispatch_iroha_gov_citizens_count => "/v1/gov/citizens";
    }
    object_post {
        dispatch_iroha_da_ingest => "/v1/da/ingest";
        dispatch_iroha_da_commitments_list => "/v1/da/commitments";
        dispatch_iroha_da_commitments_prove => "/v1/da/commitments/prove";
        dispatch_iroha_da_commitments_verify => "/v1/da/commitments/verify";
        dispatch_iroha_da_pin_intents_list => "/v1/da/pin-intents";
        dispatch_iroha_da_pin_intents_prove => "/v1/da/pin-intents/prove";
        dispatch_iroha_da_pin_intents_verify => "/v1/da/pin-intents/verify";
        dispatch_iroha_runtime_upgrades_propose => "/v1/runtime/upgrades/propose";
        dispatch_iroha_proofs_query => "/v1/proofs/query";
        dispatch_iroha_gov_proposals_deploy_contract => "/v1/gov/proposals/deploy-contract";
        dispatch_iroha_gov_protected_namespaces_update => "/v1/gov/protected-namespaces";
        dispatch_iroha_aliases_resolve => "/v1/aliases/resolve";
        dispatch_iroha_aliases_resolve_index => "/v1/aliases/resolve-index";
        dispatch_iroha_aliases_by_account => "/v1/aliases/by-account";
    }
    list_query {
        dispatch_iroha_contracts_state_get => "/v1/contracts/state";
        dispatch_iroha_assets_list => "/v1/explorer/assets";
        dispatch_iroha_nfts_list => "/v1/explorer/nfts";
        dispatch_iroha_rwas_list => "/v1/explorer/rwas";
    }
    collection_get {
        dispatch_iroha_subscriptions_list => "/v1/subscriptions";
        dispatch_iroha_subscriptions_plans_list => "/v1/subscriptions/plans";
        dispatch_iroha_accounts_list => "/v1/accounts";
        dispatch_iroha_domains_list => "/v1/domains";
        dispatch_iroha_asset_definitions => "/v1/assets/definitions";
        dispatch_iroha_nfts_chain_list => "/v1/nfts";
        dispatch_iroha_rwas_chain_list => "/v1/rwas";
    }
    collection_post {
        dispatch_iroha_subscriptions_plans_query => "/v1/subscriptions/plans/query";
        dispatch_iroha_subscriptions_query => "/v1/subscriptions/query";
        dispatch_iroha_accounts_query => "/v1/accounts/query";
        dispatch_iroha_domains_query => "/v1/domains/query";
        dispatch_iroha_asset_definitions_query => "/v1/assets/definitions/query";
        dispatch_iroha_nfts_query => "/v1/nfts/query";
        dispatch_iroha_rwas_query => "/v1/rwas/query";
        dispatch_iroha_transactions_query => "/v1/transactions/query";
        dispatch_iroha_contracts_activity_query => "/v1/contracts/activity/query";
        dispatch_iroha_contracts_events_query => "/v1/contracts/events/query";
    }
    path_get {
        dispatch_iroha_bridge_finality_proof => (
            "height",
            |arguments| extract_height_argument(arguments),
            "/v1/bridge/finality/{height}"
        );
        dispatch_iroha_bridge_finality_bundle => (
            "height",
            |arguments| extract_height_argument(arguments),
            "/v1/bridge/finality/bundle/{height}"
        );
        dispatch_iroha_da_manifests_get => (
            "ticket",
            |arguments| extract_ticket_argument(arguments),
            "/v1/da/manifests/{ticket}"
        );
        dispatch_iroha_gov_contract_get => (
            "contract_address",
            |arguments| extract_contract_address_argument(arguments),
            "/v1/gov/contracts/{contract_address}"
        );
        dispatch_iroha_gov_proposals_get => (
            "id",
            |arguments| extract_governance_proposal_id_argument(arguments),
            "/v1/gov/proposals/{id}"
        );
        dispatch_iroha_gov_locks_get => (
            "rid",
            |arguments| extract_governance_selector_argument(arguments, "rid", "referendum id"),
            "/v1/gov/locks/{rid}"
        );
        dispatch_iroha_gov_referenda_get => (
            "id",
            |arguments| extract_governance_selector_argument(arguments, "id", "referendum id"),
            "/v1/gov/referenda/{id}"
        );
        dispatch_iroha_gov_tally_get => (
            "id",
            |arguments| extract_governance_selector_argument(arguments, "id", "tally id"),
            "/v1/gov/tally/{id}"
        );
        dispatch_iroha_accounts_get => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}"
        );
        dispatch_iroha_accounts_qr => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/explorer/accounts/{account_id}/qr"
        );
        dispatch_iroha_domains_get => (
            "domain_id",
            |arguments| extract_domain_id_argument(arguments),
            "/v1/explorer/domains/{domain_id}"
        );
        dispatch_iroha_subscriptions_get => (
            "subscription_id",
            |arguments| extract_subscription_id_argument(arguments),
            "/v1/subscriptions/{subscription_id}"
        );
        dispatch_iroha_assets_get => (
            "asset_id",
            |arguments| extract_asset_id_argument(arguments),
            "/v1/explorer/assets/{asset_id}"
        );
        dispatch_iroha_nfts_get => (
            "nft_id",
            |arguments| extract_nft_id_argument(arguments),
            "/v1/explorer/nfts/{nft_id}"
        );
        dispatch_iroha_rwas_get => (
            "rwa_id",
            |arguments| extract_rwa_id_argument(arguments),
            "/v1/explorer/rwas/{rwa_id}"
        );
        dispatch_iroha_transactions_get => (
            "hash",
            |arguments| extract_transaction_hash_argument(arguments),
            "/v1/explorer/transactions/{hash}"
        );
        dispatch_iroha_blocks_get => (
            "identifier",
            |arguments| extract_block_identifier_argument(arguments),
            "/v1/explorer/blocks/{identifier}"
        );
    }
    path_query_get {
        dispatch_iroha_account_portfolio => (
            "uaid",
            |arguments| extract_uaid_argument(arguments),
            "/v1/accounts/{uaid}/portfolio"
        );
    }
    path_collection_get {
        dispatch_iroha_account_history => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/history"
        );

        dispatch_iroha_account_permissions => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/permissions"
        );
        dispatch_iroha_uaid_manifests => (
            "uaid", |arguments| extract_uaid_argument(arguments),
            "/v1/space-directory/uaids/{uaid}/manifests"
        );
        dispatch_iroha_account_transactions => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/transactions"
        );
        dispatch_iroha_account_assets => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/assets"
        );
        dispatch_iroha_asset_holders => (
            "definition_id",
            |arguments| extract_definition_id_argument(arguments),
            "/v1/assets/{definition_id}/holders"
        );
    }
    path_collection_post {
        dispatch_iroha_account_history_query => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/history/query"
        );

        dispatch_iroha_account_permissions_query => (
            "account_id", |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/permissions/query"
        );
        dispatch_iroha_uaid_manifests_query => (
            "uaid", |arguments| extract_uaid_argument(arguments),
            "/v1/space-directory/uaids/{uaid}/manifests/query"
        );
        dispatch_iroha_account_transactions_query => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/transactions/query"
        );
        dispatch_iroha_account_assets_query => (
            "account_id",
            |arguments| extract_account_id_argument(arguments),
            "/v1/accounts/{account_id}/assets/query"
        );
        dispatch_iroha_asset_holders_query => (
            "definition_id",
            |arguments| extract_definition_id_argument(arguments),
            "/v1/assets/{definition_id}/holders/query"
        );
    }
}
/// Fill a single-parameter route template with one extracted path value.
fn single_path_route(template: &str, key: &str, value: String) -> Result<String, String> {
    let mut path_args = Map::new();
    path_args.insert(key.into(), Value::String(value));
    fill_path_template(template, Some(&Value::Object(path_args)))
}
async fn dispatch_explorer_history_list(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    route: &str,
    query_fields: &[&str],
    context: &str,
) -> Result<Value, String> {
    let route = append_explorer_history_query_arguments(
        route.to_owned(),
        arguments,
        query_fields,
        context,
    )?;
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_transactions_list(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_explorer_history_list(
        app,
        inbound_headers,
        arguments,
        "/v1/explorer/transactions",
        &[
            "cursor",
            "limit",
            "authority",
            "block",
            "status",
            "asset_id",
        ],
        "Explorer transaction history request",
    )
    .await
}
async fn dispatch_iroha_instructions_list(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_explorer_history_list(
        app,
        inbound_headers,
        arguments,
        "/v1/explorer/instructions",
        &[
            "cursor",
            "limit",
            "authority",
            "account",
            "transaction_hash",
            "transaction_status",
            "block",
            "kind",
            "asset_id",
        ],
        "Explorer instruction history request",
    )
    .await
}
async fn dispatch_iroha_blocks_list(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_explorer_history_list(
        app,
        inbound_headers,
        arguments,
        "/v1/explorer/blocks",
        &["cursor", "limit"],
        "Explorer block history request",
    )
    .await
}
/// Render an exact MCP account input into the strict ASCII auth-header form.
fn vpn_canonical_auth_account_header_value(account: &str) -> Result<String, String> {
    if account.is_empty() || account.trim() != account {
        return Err("`canonical_auth.account` must be exact and non-empty".to_owned());
    }
    if account.len() > crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1 {
        return Err(format!(
            "`canonical_auth.account` exceeds the V1 limit of {} bytes",
            crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1
        ));
    }
    match AccountAddress::parse_encoded(account, None) {
        Ok(address) => {
            let rendered = address
                .canonical_hex()
                .map_err(|err| format!("failed to encode `canonical_auth.account`: {err}"))?;
            crate::app_auth::validate_canonical_request_auth_wire_values(
                Some(&rendered),
                None,
                None,
                None,
                None,
            )
            .map_err(|err| format!("invalid `canonical_auth.account`: {err}"))?;
            Ok(rendered)
        }
        Err(_) if account.is_ascii() => {
            crate::app_auth::validate_canonical_request_auth_wire_values(
                Some(account),
                None,
                None,
                None,
                None,
            )
            .map_err(|err| format!("invalid `canonical_auth.account`: {err}"))?;
            try_copy_auth_header_value(account, "canonical_auth.account")
        }
        Err(_) => Err(
            "`canonical_auth.account` must be a canonical I105 account or printable ASCII account alias"
                .to_owned(),
        ),
    }
}
fn try_copy_auth_header_value(value: &str, context: &str) -> Result<String, String> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| format!("failed to allocate `{context}` header value"))?;
    copied.push_str(value);
    Ok(copied)
}
fn try_render_u64_auth_header_value(value: u64, context: &str) -> Result<String, String> {
    let mut digits = [0_u8; 20];
    let mut start = digits.len();
    let mut remaining = value;
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(remaining % 10).expect("decimal digit fits in u8");
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let rendered = std::str::from_utf8(&digits[start..]).expect("decimal digits are valid UTF-8");
    try_copy_auth_header_value(rendered, context)
}
fn vpn_canonical_auth_headers(arguments: &Map) -> Result<Value, String> {
    let auth = arguments
        .get("canonical_auth")
        .ok_or_else(|| {
            "`canonical_auth` is required and must be signed for the exact inner VPN route"
                .to_owned()
        })?
        .as_object()
        .ok_or_else(|| "`canonical_auth` must be an object".to_owned())?;
    reject_unknown_arguments(
        auth,
        &["account", "signature", "timestamp_ms", "nonce", "witness"],
        "VPN canonical authentication",
    )?;
    let string_field = |name: &str| -> Result<Option<&str>, String> {
        auth.get(name)
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| format!("`canonical_auth.{name}` must be a string"))
            })
            .transpose()
    };
    let account = string_field("account")?;
    let signature = string_field("signature")?;
    let nonce = string_field("nonce")?;
    let witness = string_field("witness")?;
    let timestamp_ms = auth
        .get("timestamp_ms")
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                "`canonical_auth.timestamp_ms` must be an unsigned integer".to_owned()
            })
        })
        .transpose()?;
    let mut headers = Map::new();
    match (signature, timestamp_ms, nonce, witness) {
        (Some(signature), Some(timestamp_ms), Some(nonce), None) => {
            let account = account.ok_or_else(|| {
                "signature authentication requires `canonical_auth.account`".to_owned()
            })?;
            let account = vpn_canonical_auth_account_header_value(&account)?;
            let timestamp_ms = timestamp_ms.to_string();
            crate::app_auth::validate_canonical_request_auth_wire_values(
                Some(&account),
                Some(signature),
                Some(&timestamp_ms),
                Some(nonce),
                None,
            )
            .map_err(|err| format!("invalid VPN canonical authentication: {err}"))?;
            let signature = try_copy_auth_header_value(signature, "canonical_auth.signature")?;
            let nonce = try_copy_auth_header_value(nonce, "canonical_auth.nonce")?;
            headers.insert(crate::HEADER_ACCOUNT.into(), Value::String(account));
            headers.insert(crate::HEADER_SIGNATURE.into(), Value::String(signature));
            headers.insert(
                crate::HEADER_TIMESTAMP_MS.into(),
                Value::String(timestamp_ms),
            );
            headers.insert(crate::HEADER_NONCE.into(), Value::String(nonce));
        }
        (None, None, None, Some(witness)) => {
            let account = account
                .map(vpn_canonical_auth_account_header_value)
                .transpose()?;
            crate::app_auth::validate_canonical_request_auth_wire_values(
                account.as_deref(),
                None,
                None,
                None,
                Some(witness),
            )
            .map_err(|err| format!("invalid VPN canonical authentication: {err}"))?;
            let witness = try_copy_auth_header_value(witness, "canonical_auth.witness")?;
            if let Some(account) = account {
                headers.insert(crate::HEADER_ACCOUNT.into(), Value::String(account));
            }
            headers.insert(crate::HEADER_WITNESS.into(), Value::String(witness));
        }
        (signature, timestamp_ms, nonce, witness) => {
            let supplied_signature_field = signature.is_some();
            let supplied_timestamp = timestamp_ms.is_some();
            let supplied_nonce = nonce.is_some();
            let supplied_witness = witness.is_some();
            return Err(
                if supplied_witness
                    && (supplied_signature_field || supplied_timestamp || supplied_nonce)
                {
                    "`canonical_auth.witness` is mutually exclusive with signature, timestamp_ms, and nonce"
                        .to_owned()
                } else {
                    "`canonical_auth` must contain either account/signature/timestamp_ms/nonce together or witness (with optional account)"
                        .to_owned()
                },
            );
        }
    }
    Ok(Value::Object(headers))
}
#[allow(clippy::too_many_arguments)]
async fn dispatch_vpn_route_with_canonical_auth(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    method: Method,
    path_and_query: &str,
    canonical_headers: &Value,
    body: Vec<u8>,
    content_type: Option<String>,
    accept: Option<String>,
) -> Result<Value, String> {
    dispatch_route_with_extra_header_policy(
        app,
        inbound_headers,
        method,
        path_and_query,
        Some(canonical_headers),
        body,
        content_type,
        accept,
        ExtraHeaderPolicy::CanonicalAccountAuthentication,
    )
    .await
}
async fn dispatch_iroha_vpn_quotes_create(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["body", "canonical_auth", "accept"],
        "VPN quote tool call",
    )?;
    let canonical_headers = vpn_canonical_auth_headers(arguments)?;
    let body = build_required_exact_object_body(
        arguments,
        &["exit_class", "metering_public_key_hex"],
        &["metering_public_key_hex"],
        "VPN quote request body",
    )?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_vpn_route_with_canonical_auth(
        app,
        inbound_headers,
        Method::POST,
        "/v1/vpn/quotes",
        &canonical_headers,
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_vpn_sessions_create(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["body", "canonical_auth", "accept"],
        "VPN session create tool call",
    )?;
    let canonical_headers = vpn_canonical_auth_headers(arguments)?;
    let body = build_required_exact_object_body(
        arguments,
        &[
            "exit_class",
            "quote_id",
            "payment_tx_hash",
            "metering_public_key_hex",
        ],
        &["quote_id", "payment_tx_hash", "metering_public_key_hex"],
        "VPN session request body",
    )?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_vpn_route_with_canonical_auth(
        app,
        inbound_headers,
        Method::POST,
        "/v1/vpn/sessions",
        &canonical_headers,
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_vpn_sessions_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["session_id", "canonical_auth", "accept"],
        "VPN session get tool call",
    )?;
    let canonical_headers = vpn_canonical_auth_headers(arguments)?;
    let session_id = extract_vpn_session_id_argument(arguments)?;
    let route = single_path_route("/v1/vpn/sessions/{session_id}", "session_id", session_id)?;
    dispatch_vpn_route_with_canonical_auth(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        &canonical_headers,
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_vpn_receipts_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["body", "canonical_auth", "accept"],
        "VPN receipt submit tool call",
    )?;
    let canonical_headers = vpn_canonical_auth_headers(arguments)?;
    let body = build_required_exact_object_body(
        arguments,
        &["relay_receipt_hex", "client_voucher_hex", "lease_id_hex"],
        &["relay_receipt_hex", "client_voucher_hex"],
        "VPN receipt request body",
    )?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_vpn_route_with_canonical_auth(
        app,
        inbound_headers,
        Method::POST,
        "/v1/vpn/receipts",
        &canonical_headers,
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_vpn_receipts_list(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["canonical_auth", "accept"],
        "VPN receipt list tool call",
    )?;
    let canonical_headers = vpn_canonical_auth_headers(arguments)?;
    dispatch_vpn_route_with_canonical_auth(
        app,
        inbound_headers,
        Method::GET,
        "/v1/vpn/receipts",
        &canonical_headers,
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_node_query_projection_shard_catalog(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let resource = arguments
        .get("resource")
        .and_then(Value::as_str)
        .ok_or_else(|| "`resource` is required".to_owned())?;
    let route = single_path_route(
        "/v1/node/query/projection/catalog/{resource}",
        "resource",
        resource.to_owned(),
    )?;
    let route = append_named_query_fields(route, arguments, QUERY_PROJECTION_SHARD_CATALOG_FIELDS)?;
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_runtime_upgrades_activate(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_runtime_upgrades_action(
        app,
        inbound_headers,
        arguments,
        "/v1/runtime/upgrades/activate/{id}",
    )
    .await
}
async fn dispatch_iroha_runtime_upgrades_cancel(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_runtime_upgrades_action(
        app,
        inbound_headers,
        arguments,
        "/v1/runtime/upgrades/cancel/{id}",
    )
    .await
}
async fn dispatch_iroha_runtime_upgrades_action(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    route_template: &str,
) -> Result<Value, String> {
    let upgrade_id = extract_runtime_upgrade_id_argument(arguments)?;
    let route = single_path_route(route_template, "id", upgrade_id)?;
    let body = build_required_object_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        route.as_str(),
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
fn parliament_json_body(arguments: &Map, context: &str) -> Result<Vec<u8>, String> {
    reject_unknown_arguments(arguments, &["body", "headers", "accept"], context)?;
    let body = arguments
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("`body` must be an object for {context}"))?;
    encode_mcp_json_body(
        &Value::Object(body.clone()),
        "encode Parliament request body",
    )
}
async fn dispatch_iroha_gov_parliament_attempt_draft(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = parliament_json_body(arguments, "Parliament attempt draft")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        iroha_torii_shared::route_catalog::runtime_governance::GOV_PARLIAMENT_ATTEMPT_DRAFT.path(),
        arguments.get("headers"),
        body,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
fn extract_parliament_attempt_id_argument(arguments: &Map) -> Result<String, String> {
    reject_unknown_arguments(
        arguments,
        &["path", "headers", "accept"],
        "Parliament attempt read",
    )?;
    let path = arguments
        .get("path")
        .and_then(Value::as_object)
        .ok_or_else(|| "`path` must be an object for Parliament attempt read".to_owned())?;
    reject_unknown_arguments(
        path,
        &["governance_attempt_id"],
        "Parliament attempt read path",
    )?;
    let attempt_id = path
        .get("governance_attempt_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "string `path.governance_attempt_id` is required".to_owned())?;
    require_governance_proposal_id_v1("governance attempt id", attempt_id)?;
    if attempt_id.bytes().all(|byte| byte == b'0') {
        return Err("`governance attempt id` must not be the zero identifier".to_owned());
    }
    Ok(attempt_id.to_owned())
}
async fn dispatch_iroha_gov_parliament_attempt_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let attempt_id = extract_parliament_attempt_id_argument(arguments)?;
    let mut path = String::from("/v1/gov/parliament/attempts/");
    path.push_str(&attempt_id);
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        &path,
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
fn extract_parliament_ballot_attempt_id_argument(
    arguments: &Map,
    context: &str,
) -> Result<String, String> {
    reject_unknown_arguments(arguments, &["path", "headers", "accept"], context)?;
    extract_parliament_ballot_attempt_id_path(arguments, context)
}
fn extract_parliament_ballot_attempt_id_path(
    arguments: &Map,
    context: &str,
) -> Result<String, String> {
    let path = arguments
        .get("path")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("`path` must be an object for {context}"))?;
    reject_unknown_arguments(path, &["ballot_attempt_id"], &format!("{context} path"))?;
    let ballot_attempt_id = path
        .get("ballot_attempt_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "string `path.ballot_attempt_id` is required".to_owned())?;
    require_governance_proposal_id_v1("ballot attempt id", ballot_attempt_id)?;
    if ballot_attempt_id.bytes().all(|byte| byte == b'0') {
        return Err("`ballot attempt id` must not be the zero identifier".to_owned());
    }
    Ok(ballot_attempt_id.to_owned())
}
async fn dispatch_iroha_gov_parliament_tle_release_context_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let ballot_attempt_id = extract_parliament_ballot_attempt_id_argument(
        arguments,
        "Parliament TLE release-context read",
    )?;
    let path = format!("/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context");
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        &path,
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_gov_parliament_timed_ovn_casting_context_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let ballot_attempt_id = extract_parliament_ballot_attempt_id_argument(
        arguments,
        "Parliament timed-OVN casting-context read",
    )?;
    let path = format!("/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context");
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        &path,
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
fn parliament_timed_ovn_casting_proof_request(
    arguments: &Map,
) -> Result<ParliamentTimedOvnCastingProofRequestV1, String> {
    reject_unknown_arguments(
        arguments,
        &["path", "trusted_checkpoint_height", "headers"],
        "Parliament timed-OVN casting-proof read",
    )?;
    let trusted_checkpoint_height = arguments
        .get("trusted_checkpoint_height")
        .and_then(Value::as_u64)
        .filter(|height| *height != 0)
        .ok_or_else(|| "non-zero integer `trusted_checkpoint_height` is required".to_owned())?;
    Ok(ParliamentTimedOvnCastingProofRequestV1 {
        version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
        trusted_checkpoint_height,
    })
}
fn parliament_timed_ovn_casting_proof_request_bytes(arguments: &Map) -> Result<Vec<u8>, String> {
    let request = parliament_timed_ovn_casting_proof_request(arguments)?;
    norito::to_bytes(&request)
        .map_err(|error| format!("failed to frame Parliament casting-proof request: {error}"))
}
async fn dispatch_iroha_gov_parliament_timed_ovn_casting_proof_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let ballot_attempt_id = extract_parliament_ballot_attempt_id_path(
        arguments,
        "Parliament timed-OVN casting-proof read",
    )?;
    let request = parliament_timed_ovn_casting_proof_request_bytes(arguments)?;
    let path = format!("/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof");
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        &path,
        arguments.get("headers"),
        request,
        Some(crate::utils::NORITO_MIME_TYPE.to_owned()),
        Some(crate::utils::NORITO_MIME_TYPE.to_owned()),
    )
    .await
}
async fn dispatch_iroha_gov_parliament_tle_partial_release_create(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let ballot_attempt_id = extract_parliament_ballot_attempt_id_argument(
        arguments,
        "Parliament TLE partial-release request",
    )?;
    let path = format!("/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release");
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        &path,
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_gov_parliament_transition_draft(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = parliament_json_body(arguments, "Parliament transition draft")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        iroha_torii_shared::route_catalog::runtime_governance::GOV_PARLIAMENT_TRANSITION_DRAFT
            .path(),
        arguments.get("headers"),
        body,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_gov_ballots_zk_v1(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_required_object_body(arguments)?;
    require_borrowed_governance_selector_body(&body, "election_id")?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/gov/ballots/zk-v1",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_gov_ballots_zk_v1_ballot_proof(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_required_object_body(arguments)?;
    require_borrowed_governance_selector_body(&body, "election_id")?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/gov/ballots/zk-v1/ballot-proof",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_gov_ballots_plain(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_required_object_body(arguments)?;
    require_borrowed_governance_selector_body(&body, "referendum_id")?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/gov/ballots/plain",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_contracts_call(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_contracts_post(app, inbound_headers, arguments, "/v1/contracts/call").await
}
async fn dispatch_iroha_contracts_call_and_wait(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    const ALLOWED_ARGUMENTS: &[&str] = &[
        "body",
        "hash",
        "timeout_ms",
        "poll_interval_ms",
        "status_accept",
        "headers",
        "accept",
    ];
    reject_unknown_arguments(
        arguments,
        ALLOWED_ARGUMENTS,
        "canonical contract call-and-wait request",
    )?;
    let timeout_ms = resolve_submit_wait_timeout_ms(arguments)?;
    let poll_interval_ms = resolve_submit_wait_poll_interval_ms(arguments)?;
    let explicit_tx_hash = extract_optional_transaction_hash_argument(arguments)?;
    let body = arguments
        .get("body")
        .ok_or_else(|| "`body` is required".to_owned())?;
    body.as_object()
        .ok_or_else(|| "`body` must be an object".to_owned())?;
    let body_bytes = encode_mcp_json_body(body, "encode contract call request body")?;
    let submit = dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/contracts/call",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await?;
    let submit_status = submit.get("status").and_then(Value::as_u64).unwrap_or(0);
    if !(200..300).contains(&submit_status) {
        return Ok(submit);
    }
    let submitted_hash;
    let tx_hash = if let Some(hash) = explicit_tx_hash {
        hash
    } else {
        submitted_hash = extract_transaction_hash_from_submit_result(&submit).map_err(|_| {
            "could not resolve transaction hash; provide canonical `hash` explicitly".to_owned()
        })?;
        &submitted_hash
    };
    wait_for_transaction_applied(
        app,
        inbound_headers,
        arguments,
        tx_hash,
        Some(submit),
        timeout_ms,
        poll_interval_ms,
    )
    .await
}
async fn dispatch_iroha_contracts_post(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    route: &str,
) -> Result<Value, String> {
    let body = build_required_object_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        route,
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_accounts_onboard_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_accounts_onboard_submit_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/accounts/onboard",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_accounts_onboard_prepare(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_accounts_onboard_prepare_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/accounts/onboard/prepare",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_accounts_faucet_prepare(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_accounts_faucet_prepare_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/accounts/faucet/prepare",
        None,
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_accounts_faucet_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_accounts_faucet_submit_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/accounts/faucet",
        None,
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_accounts_onboard_plan(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_accounts_onboard_plan_body(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/accounts/onboard/plan",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_musubi_v1(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    name: &str,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["body", "headers", "accept"],
        "Musubi V1 tool arguments",
    )?;
    let definition = musubi_v1_tool_definition(name)
        .ok_or_else(|| format!("unknown Musubi V1 tool `{name}`"))?;
    let body = arguments
        .get("body")
        .ok_or_else(|| "`body` is required for typed Musubi V1 tools".to_owned())?;
    body.as_object()
        .ok_or_else(|| "`body` must be an object".to_owned())?;
    let body_bytes = encode_mcp_json_body(body, "encode Musubi V1 request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        definition.path,
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_subscriptions_plans_create(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = build_object_body_or_default(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/subscriptions/plans",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_subscriptions_create(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["body", "headers", "accept"],
        "subscription creation draft",
    )?;
    let body = build_required_exact_object_body(
        arguments,
        &[
            "authority",
            "subscription_id",
            "plan_id",
            "billing_trigger_id",
            "usage_trigger_id",
            "first_charge_ms",
            "grant_usage_to_provider",
        ],
        &["authority", "subscription_id", "plan_id"],
        "subscription creation draft body",
    )?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        "/v1/subscriptions",
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_subscriptions_cancel(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_subscription_draft_action(app, inbound_headers, arguments, "cancel").await
}
async fn dispatch_iroha_subscriptions_pause(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_subscription_draft_action(app, inbound_headers, arguments, "pause").await
}
async fn dispatch_iroha_subscriptions_resume(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_subscription_draft_action(app, inbound_headers, arguments, "resume").await
}
async fn dispatch_iroha_subscriptions_keep(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_subscription_draft_action(app, inbound_headers, arguments, "keep").await
}
async fn dispatch_iroha_subscriptions_usage(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_subscription_action(app, inbound_headers, arguments, "usage").await
}
async fn dispatch_iroha_subscriptions_charge_now(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_iroha_subscription_draft_action(app, inbound_headers, arguments, "charge-now").await
}
async fn dispatch_iroha_subscription_draft_action(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    action: &str,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["subscription_id", "body", "headers", "accept"],
        "subscription action draft",
    )?;
    let subscription_id = extract_exact_subscription_id_argument(arguments)?;
    let route = single_path_route(
        format!("/v1/subscriptions/{{subscription_id}}/{action}").as_str(),
        "subscription_id",
        subscription_id,
    )?;
    let (body_fields, required_fields): (&[&str], &[&str]) = match action {
        "pause" | "keep" => (&["authority"], &["authority"]),
        "resume" | "charge-now" => (&["authority", "charge_at_ms"], &["authority"]),
        "cancel" => (&["authority", "cancel_mode"], &["authority", "cancel_mode"]),
        _ => return Err(format!("unsupported subscription draft action `{action}`")),
    };
    let body = build_required_exact_object_body(
        arguments,
        body_fields,
        required_fields,
        "subscription action draft body",
    )?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        route.as_str(),
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_subscription_action(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    action: &str,
) -> Result<Value, String> {
    let subscription_id = extract_subscription_id_argument(arguments)?;
    let route = single_path_route(
        format!("/v1/subscriptions/{{subscription_id}}/{action}").as_str(),
        "subscription_id",
        subscription_id,
    )?;
    let body = build_object_body_or_default(arguments)?;
    let body_bytes = encode_mcp_json_body(&body, "encode request body")?;
    dispatch_route(
        app,
        inbound_headers,
        Method::POST,
        route.as_str(),
        arguments.get("headers"),
        body_bytes,
        Some("application/json".to_owned()),
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_asset_definitions_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let definition_id = extract_definition_id_argument(arguments)?;
    let route = single_path_route(
        "/v1/explorer/asset-definitions/{definition_id}",
        "definition_id",
        definition_id,
    )?;
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_instructions_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let hash = extract_transaction_hash_argument(arguments)?;
    let index = extract_instruction_index_argument(arguments)?;
    let mut path_args = Map::new();
    path_args.insert("hash".into(), Value::String(hash));
    path_args.insert("index".into(), Value::String(index));
    let path_value = Value::Object(path_args);
    let route = fill_path_template(
        "/v1/explorer/instructions/{hash}/{index}",
        Some(&path_value),
    )?;
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
fn dispatch_iroha_transactions_prepare(
    app: &SharedAppState,
    arguments: &Map,
) -> Result<Value, String> {
    let bytes = canonical_padded_base64_argument(arguments, "transaction_payload_base64")?;
    transaction_artifacts::prepare_transaction_payload_bytes(app.state.network_id_ref(), &bytes)
        .map(|artifact| artifact.to_mcp_value())
        .map_err(|error| error.to_string())
}

fn dispatch_iroha_transactions_inspect(
    app: &SharedAppState,
    arguments: &Map,
) -> Result<Value, String> {
    let (kind, field) = match (
        arguments.contains_key("transaction_payload_base64"),
        arguments.contains_key("signed_transaction_base64"),
    ) {
        (true, false) => (
            transaction_artifacts::TransactionArtifactKind::TransactionPayload,
            "transaction_payload_base64",
        ),
        (false, true) => (
            transaction_artifacts::TransactionArtifactKind::SignedTransaction,
            "signed_transaction_base64",
        ),
        _ => {
            return Err(
                "exactly one of transaction_payload_base64 or signed_transaction_base64 is required"
                    .to_owned(),
            );
        }
    };
    let bytes = canonical_padded_base64_argument(arguments, field)?;
    transaction_artifacts::inspect_transaction_artifact(app.state.network_id_ref(), kind, &bytes)
        .map(|artifact| artifact.to_mcp_value())
        .map_err(|error| error.to_string())
}

fn canonical_padded_base64_argument(arguments: &Map, field: &str) -> Result<Vec<u8>, String> {
    let encoded = arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a string"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|error| format!("{field} must be canonical padded standard Base64: {error}"))?;
    if bytes.is_empty() || base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded {
        return Err(format!(
            "{field} must be non-empty canonical padded standard Base64"
        ));
    }
    Ok(bytes)
}

async fn dispatch_iroha_transactions_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = canonical_norito_body_base64(
        arguments,
        "versioned SignedTransaction",
        &["body_base64", "headers", "accept"],
    )?;
    dispatch_iroha_transactions_submit_body(app, inbound_headers, arguments, body).await
}
async fn dispatch_iroha_transactions_submit_body(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    body: Vec<u8>,
) -> Result<Value, String> {
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::POST,
        iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path(),
        arguments.get("headers"),
        body,
        Some(crate::utils::NORITO_MIME_TYPE),
        arguments.get("accept").and_then(Value::as_str),
    )
    .await
}
async fn dispatch_iroha_queries_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let body = canonical_norito_body_base64(
        arguments,
        "versioned SignedQuery",
        &["body_base64", "headers", "accept"],
    )?;
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::POST,
        iroha_torii_shared::route_catalog::pipeline::QUERY.path(),
        arguments.get("headers"),
        body,
        Some(crate::utils::NORITO_MIME_TYPE),
        arguments.get("accept").and_then(Value::as_str),
    )
    .await
}
fn canonical_norito_body_base64(
    arguments: &Map,
    label: &str,
    allowed_fields: &[&str],
) -> Result<Vec<u8>, String> {
    reject_unknown_arguments(
        arguments,
        allowed_fields,
        &format!("canonical {label} submission"),
    )?;
    decode_canonical_norito_body_base64(arguments, label)
}
fn decode_canonical_norito_body_base64(arguments: &Map, label: &str) -> Result<Vec<u8>, String> {
    let encoded = arguments
        .get("body_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("body_base64 is required for canonical {label} submission"))?;
    decode_base64_any(encoded, "body_base64 must be valid base64/base64url")
}
fn reject_unknown_arguments(
    arguments: &Map,
    allowed_fields: &[&str],
    context: &str,
) -> Result<(), String> {
    for field in arguments.keys() {
        if !allowed_fields.contains(&field.as_str()) {
            return Err(format!(
                "unexpected `{field}` for {context}; allowed fields: {}",
                allowed_fields.join(", ")
            ));
        }
    }
    Ok(())
}
fn build_iso20022_payload_body(arguments: &Map) -> Result<(Vec<u8>, Option<&str>), String> {
    reject_unknown_arguments(
        arguments,
        &[
            "body_base64",
            "content_type",
            "profile",
            "operator_auth",
            "accept",
        ],
        "ISO 20022 submission",
    )?;
    let encoded = arguments
        .get("body_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| "string `body_base64` is required for ISO 20022 submission".to_owned())?;
    let body = decode_base64_any(
        encoded,
        "ISO 20022 `body_base64` must be valid base64/base64url",
    )?;
    let content_type = arguments
        .get("content_type")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "`content_type` must be a string".to_owned())
        })
        .transpose()?
        .or(Some("application/xml"));
    Ok((body, content_type))
}
fn iso20022_operator_auth_headers(arguments: &Map) -> Result<Value, String> {
    let auth = arguments
        .get("operator_auth")
        .ok_or_else(|| {
            "`operator_auth` is required and must be signed for the exact inner ISO 20022 route"
                .to_owned()
        })?
        .as_object()
        .ok_or_else(|| "`operator_auth` must be an object".to_owned())?;
    reject_unknown_arguments(
        auth,
        &["public_key", "timestamp_ms", "nonce", "signature"],
        "ISO 20022 operator authentication",
    )?;
    let required_string = |name: &str| -> Result<&str, String> {
        auth.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("non-empty `operator_auth.{name}` is required"))
    };
    let timestamp_ms = auth
        .get("timestamp_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "unsigned integer `operator_auth.timestamp_ms` is required".to_owned())?;
    let public_key = required_string("public_key")?;
    let nonce = required_string("nonce")?;
    let signature = required_string("signature")?;
    let timestamp_ms =
        try_render_u64_auth_header_value(timestamp_ms, "operator_auth.timestamp_ms")?;
    validate_operator_auth_wire_values(public_key, &timestamp_ms, nonce, signature)?;
    let public_key = try_copy_auth_header_value(public_key, "operator_auth.public_key")?;
    let nonce = try_copy_auth_header_value(nonce, "operator_auth.nonce")?;
    let signature = try_copy_auth_header_value(signature, "operator_auth.signature")?;
    let mut headers = Map::new();
    headers.insert(
        "X-Iroha-Operator-Public-Key".to_owned(),
        Value::String(public_key),
    );
    headers.insert(
        "X-Iroha-Operator-Timestamp-Ms".to_owned(),
        Value::String(timestamp_ms),
    );
    headers.insert("X-Iroha-Operator-Nonce".to_owned(), Value::String(nonce));
    headers.insert(
        "X-Iroha-Operator-Signature".to_owned(),
        Value::String(signature),
    );
    Ok(Value::Object(headers))
}
fn iso20022_route_with_profile(base: &str, arguments: &Map) -> Result<String, String> {
    let Some(raw_profile) = arguments.get("profile") else {
        return Ok(base.to_owned());
    };
    let profile = raw_profile
        .as_str()
        .ok_or_else(|| "`profile` must be a string".to_owned())?
        .trim();
    if profile.is_empty() {
        return Err("`profile` must not be empty".to_owned());
    }
    let profile_bytes = percent_encoded_path_component_len(profile)?;
    let query_bytes = "profile="
        .len()
        .checked_add(profile_bytes)
        .ok_or_else(|| "ISO 20022 profile query length overflow".to_owned())?;
    if query_bytes > crate::app_auth::CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1 {
        return Err("`profile` exceeds the canonical request query limit".to_owned());
    }
    let mut route = base.to_owned();
    let additional = query_bytes
        .checked_add(1)
        .ok_or_else(|| "ISO 20022 profile route length overflow".to_owned())?;
    route
        .try_reserve_exact(additional)
        .map_err(|_| "failed to reserve ISO 20022 profile route".to_owned())?;
    route.push_str("?profile=");
    try_append_percent_encoded_path_component(&mut route, profile)?;
    Ok(route)
}
async fn dispatch_iroha_iso20022_pacs008_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let headers = iso20022_operator_auth_headers(arguments)?;
    let (body, content_type) = build_iso20022_payload_body(arguments)?;
    let route = iso20022_route_with_profile("/v1/iso20022/pacs008", arguments)?;
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::POST,
        &route,
        Some(&headers),
        body,
        content_type,
        arguments.get("accept").and_then(Value::as_str),
    )
    .await
}
async fn dispatch_iroha_iso20022_pacs009_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let headers = iso20022_operator_auth_headers(arguments)?;
    let (body, content_type) = build_iso20022_payload_body(arguments)?;
    let route = iso20022_route_with_profile("/v1/iso20022/pacs009", arguments)?;
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::POST,
        &route,
        Some(&headers),
        body,
        content_type,
        arguments.get("accept").and_then(Value::as_str),
    )
    .await
}
async fn dispatch_iroha_iso20022_lifecycle_submit(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    route: &str,
) -> Result<Value, String> {
    let headers = iso20022_operator_auth_headers(arguments)?;
    let (body, content_type) = build_iso20022_payload_body(arguments)?;
    let route = iso20022_route_with_profile(route, arguments)?;
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::POST,
        &route,
        Some(&headers),
        body,
        content_type,
        arguments.get("accept").and_then(Value::as_str),
    )
    .await
}
async fn dispatch_iroha_iso20022_status_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &["path", "operator_auth", "accept"],
        "ISO 20022 status request",
    )?;
    let headers = iso20022_operator_auth_headers(arguments)?;
    let msg_id = extract_iso20022_message_id_argument(arguments)?;
    let route = single_path_route("/v1/iso20022/messages/{msg_id}", "msg_id", msg_id)?;
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        Some(&headers),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_transactions_submit_and_wait(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let timeout_ms = resolve_submit_wait_timeout_ms(arguments)?;
    let poll_interval_ms = resolve_submit_wait_poll_interval_ms(arguments)?;
    reject_unknown_arguments(
        arguments,
        &[
            "body_base64",
            "hash",
            "timeout_ms",
            "poll_interval_ms",
            "status_accept",
            "headers",
            "accept",
        ],
        "canonical submit-and-wait transaction submission",
    )?;
    let explicit_tx_hash = extract_optional_transaction_hash_argument(arguments)?;
    let body = decode_canonical_norito_body_base64(arguments, "versioned SignedTransaction")?;
    let submit =
        dispatch_iroha_transactions_submit_body(app, inbound_headers, arguments, body).await?;
    let submit_status = submit.get("status").and_then(Value::as_u64).unwrap_or(0);
    if !(200..300).contains(&submit_status) {
        return Ok(submit);
    }
    let submitted_hash;
    let tx_hash = if let Some(hash) = explicit_tx_hash {
        hash
    } else {
        submitted_hash = extract_transaction_hash_from_submit_result(&submit).map_err(|_| {
            "could not resolve transaction hash; provide canonical `hash` explicitly".to_owned()
        })?;
        &submitted_hash
    };
    wait_for_transaction_applied(
        app,
        inbound_headers,
        arguments,
        tx_hash,
        Some(submit),
        timeout_ms,
        poll_interval_ms,
    )
    .await
}
async fn dispatch_iroha_transactions_wait(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &[
            "query",
            "timeout_ms",
            "poll_interval_ms",
            "status_accept",
            "headers",
            "accept",
        ],
        "canonical transaction wait request",
    )?;
    let timeout_ms = resolve_submit_wait_timeout_ms(arguments)?;
    let poll_interval_ms = resolve_submit_wait_poll_interval_ms(arguments)?;
    let tx_hash = extract_transaction_status_hash_argument(arguments)?;
    wait_for_transaction_applied(
        app,
        inbound_headers,
        arguments,
        tx_hash,
        None,
        timeout_ms,
        poll_interval_ms,
    )
    .await
}
async fn wait_for_transaction_applied(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    tx_hash: &str,
    mut submit: Option<Value>,
    timeout_ms: u64,
    poll_interval_ms: u64,
) -> Result<Value, String> {
    let start = tokio::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let poll_interval = Duration::from_millis(poll_interval_ms);
    let mut attempts = 0_u64;
    let mut last_kind: Option<String> = None;
    let status_accept = arguments
        .get("status_accept")
        .or_else(|| arguments.get("accept"))
        .and_then(Value::as_str)
        .unwrap_or("application/json");
    loop {
        attempts = attempts.saturating_add(1);
        let status_result = dispatch_iroha_transaction_status_poll(
            app,
            inbound_headers,
            tx_hash,
            arguments.get("headers"),
            status_accept,
        )
        .await?;
        if exact_pipeline_status_poll_has_body(&status_result, tx_hash)? {
            let status = decode_exact_global_pipeline_status(&status_result, tx_hash)?;
            let kind = status.status.kind.as_str();
            last_kind = Some(kind.to_owned());
            if fixed_pipeline_status_is_applied(&status)
                .map_err(|error| format!("transaction `{tx_hash}` {error}; last_status={kind}"))?
            {
                let elapsed_ms = start
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX))
                    .try_into()
                    .unwrap_or(u64::MAX);
                return build_transaction_applied_wait_result(
                    tx_hash,
                    attempts,
                    elapsed_ms,
                    submit.take(),
                    status_result,
                );
            }
        }
        if start.elapsed() >= timeout {
            break;
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
    let last_kind = last_kind
        .map(|kind| format!(" (last status kind: `{kind}`)"))
        .unwrap_or_else(|| " (last status kind: `not_observed`)".to_owned());
    Err(format!(
        "timed out waiting for state-resolved Applied after {timeout_ms}ms for `{tx_hash}`{last_kind}"
    ))
}
fn exact_pipeline_status_poll_has_body(
    status_result: &Value,
    tx_hash: &str,
) -> Result<bool, String> {
    let status_code = status_result
        .get("status")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    match status_code {
        200 => Ok(true),
        404 => {
            let content_type = status_result
                .get("content_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !content_type
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
            {
                return Err("pipeline status absence requires application/json".to_owned());
            }
            let body = status_result
                .get("body")
                .ok_or_else(|| "pipeline status absence omitted its body".to_owned())?;
            let _bounded = json::to_json_bounded_boxed(
                body,
                iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_MAX_BYTES,
            )
            .map_err(|error| format!("pipeline status absence exceeds its JSON bound: {error}"))?;
            let envelope: iroha_torii_shared::ErrorEnvelope = json::from_value(body.clone())
                .map_err(|error| {
                    format!("invalid pipeline status absence ErrorEnvelope: {error}")
                })?;
            let hash = canonical_transaction_hash(tx_hash)?;
            let expected = hash
                .parse::<iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>>()
                .map_err(|error| format!("invalid requested transaction hash: {error}"))?;
            if envelope.code() != iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE
                || !envelope
                    .details
                    .as_ref()
                    .and_then(|details| details.pipeline_transaction_status_not_found.as_ref())
                    .is_some_and(|absence| absence.matches(&expected, "global"))
            {
                return Err(
                    "HTTP 404 does not establish exact global transaction status absence"
                        .to_owned(),
                );
            }
            Ok(false)
        }
        status_code => Err(format!(
            "transaction `{tx_hash}` status poll returned HTTP {status_code}; expected exact HTTP 200 with a status payload or typed scoped HTTP 404 while pending"
        )),
    }
}
fn build_transaction_applied_wait_result(
    tx_hash: &str,
    attempts: u64,
    elapsed_ms: u64,
    submit: Option<Value>,
    final_result: Value,
) -> Result<Value, String> {
    let mut out = Map::new();
    out.insert("status".into(), Value::from(200_u64));
    out.insert(
        "hash".into(),
        Value::String(try_copy_canonical_transaction_hash(tx_hash)?),
    );
    out.insert("terminal_kind".into(), Value::String("Applied".to_owned()));
    out.insert("attempts".into(), Value::from(attempts));
    out.insert("elapsed_ms".into(), Value::from(elapsed_ms));
    if let Some(submit) = submit {
        out.insert("submit".into(), submit);
    }
    out.insert("final".into(), final_result);
    Ok(Value::Object(out))
}
async fn dispatch_iroha_transactions_status(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    let tx_hash = extract_transaction_status_hash_argument(arguments)?;
    let route = append_transaction_status_query(
        "/v1/pipeline/transactions/status".to_owned(),
        arguments,
        tx_hash,
    )?;
    dispatch_route_borrowed(
        app,
        inbound_headers,
        Method::GET,
        route.as_str(),
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments.get("accept").and_then(Value::as_str),
    )
    .await
}
fn resolve_submit_wait_timeout_ms(arguments: &Map) -> Result<u64, String> {
    let timeout_ms = match arguments.get("timeout_ms") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "`timeout_ms` must be an unsigned integer".to_owned())?,
        None => DEFAULT_TX_SUBMIT_WAIT_TIMEOUT_MS,
    };
    if timeout_ms == 0 {
        return Err("`timeout_ms` must be greater than zero".to_owned());
    }
    if timeout_ms > MAX_TX_SUBMIT_WAIT_TIMEOUT_MS {
        return Err(format!(
            "`timeout_ms` must be <= {MAX_TX_SUBMIT_WAIT_TIMEOUT_MS}"
        ));
    }
    Ok(timeout_ms)
}
fn resolve_submit_wait_poll_interval_ms(arguments: &Map) -> Result<u64, String> {
    let poll_interval_ms = match arguments.get("poll_interval_ms") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| "`poll_interval_ms` must be an unsigned integer".to_owned())?,
        None => DEFAULT_TX_SUBMIT_WAIT_POLL_INTERVAL_MS,
    };
    if poll_interval_ms < MIN_TX_SUBMIT_WAIT_POLL_INTERVAL_MS {
        return Err(format!(
            "`poll_interval_ms` must be >= {MIN_TX_SUBMIT_WAIT_POLL_INTERVAL_MS}"
        ));
    }
    Ok(poll_interval_ms)
}
fn extract_optional_transaction_hash_argument(arguments: &Map) -> Result<Option<&str>, String> {
    if arguments.contains_key("transaction_hash") || arguments.contains_key("query") {
        return Err(
            "optional transaction hash accepts only the exact top-level `hash` field".to_owned(),
        );
    }
    arguments
        .get("hash")
        .and_then(Value::as_str)
        .filter(|hash| !hash.is_empty())
        .map(canonical_transaction_hash)
        .transpose()
}
fn extract_transaction_status_hash_argument(arguments: &Map) -> Result<&str, String> {
    if arguments.contains_key("hash") || arguments.contains_key("transaction_hash") {
        return Err("transaction status accepts only the exact `query.hash` field".to_owned());
    }
    let query = arguments
        .get("query")
        .and_then(Value::as_object)
        .ok_or_else(|| "`query` must be an object".to_owned())?;
    reject_unknown_arguments(query, &["hash"], "transaction status query")?;
    let hash = query
        .get("hash")
        .and_then(Value::as_str)
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| "non-empty `query.hash` is required".to_owned())?;
    canonical_transaction_hash(hash)
}
fn canonical_transaction_hash(hash: &str) -> Result<&str, String> {
    let marker_is_set = hash
        .as_bytes()
        .last()
        .is_some_and(|byte| matches!(byte, b'1' | b'3' | b'5' | b'7' | b'9' | b'b' | b'd' | b'f'));
    if hash.len() != CANONICAL_TRANSACTION_HASH_HEX_BYTES
        || !hash
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || !marker_is_set
    {
        return Err(format!(
            "transaction hash must be exactly {CANONICAL_TRANSACTION_HASH_HEX_BYTES} lowercase hexadecimal digits with the Iroha hash marker set"
        ));
    }
    Ok(hash)
}
fn try_copy_canonical_transaction_hash(hash: &str) -> Result<String, String> {
    let hash = canonical_transaction_hash(hash)?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(hash.len())
        .map_err(|_| "failed to reserve canonical transaction hash".to_owned())?;
    owned.push_str(hash);
    Ok(owned)
}
fn canonical_connect_sid_argument(arguments: &Map) -> Result<&str, String> {
    decode_canonical(arguments, "sid", 32)?;
    required_string(arguments, "sid")
}
fn extract_vpn_session_id_argument(arguments: &Map) -> Result<String, String> {
    let session_id = arguments
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|session_id| !session_id.is_empty())
        .ok_or_else(|| "non-empty `session_id` is required".to_owned())?;
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("`session_id` must be exactly 32 lowercase hexadecimal digits".to_owned());
    }
    Ok(session_id.to_owned())
}
fn extract_transaction_hash_from_submit_result(submit_result: &Value) -> Result<String, String> {
    let status = submit_result
        .get("status")
        .and_then(Value::as_u64)
        .ok_or_else(|| "submit response missing HTTP status".to_owned())?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "submit response status `{status}` is not successful"
        ));
    }
    let body = submit_result
        .get("body")
        .ok_or_else(|| "submit response missing `body`".to_owned())?;
    if let Some(hash) = body.get("tx_hash_hex").and_then(Value::as_str) {
        return try_copy_canonical_transaction_hash(hash);
    }
    if let Some(hash) = body
        .get("payload")
        .and_then(|payload| payload.get("signed_transaction_hash"))
        .and_then(Value::as_str)
    {
        return try_copy_canonical_transaction_hash(hash);
    }
    if let Some(encoded) = body.as_str().filter(|body| !body.is_empty()) {
        let bytes = decode_base64_any(
            encoded,
            "submission response body is not valid base64/base64url",
        )?;
        let receipt: iroha_data_model::transaction::TransactionSubmissionReceipt =
            norito::decode_from_bytes(&bytes)
                .map_err(|err| format!("decode submission receipt: {err}"))?;
        let hash = receipt
            .payload
            .signed_transaction_hash
            .as_ref()
            .ok_or_else(|| "submission receipt is missing its signed transaction hash".to_owned())?
            .to_string();
        return try_copy_canonical_transaction_hash(&hash);
    }
    Err("submission response missing exact signed transaction hash field (`tx_hash_hex`, `payload.signed_transaction_hash`, or base64 Norito receipt body)".to_owned())
}
fn decode_exact_global_pipeline_status(
    status_result: &Value,
    expected_hash: &str,
) -> Result<PipelineTransactionStatusResponse, String> {
    let body = status_result
        .get("body")
        .ok_or_else(|| "status polling response is missing `body`".to_owned())?;
    let status = json::from_value::<PipelineTransactionStatusResponse>(body.clone())
        .map_err(|error| format!("status polling response is not exact V1 JSON: {error}"))?;
    canonical_transaction_hash(&status.hash)
        .map_err(|error| format!("status polling response hash is not canonical: {error}"))?;
    if status.hash != expected_hash {
        return Err(format!(
            "status polling response hash `{}` does not match requested `{expected_hash}`",
            status.hash
        ));
    }
    if status.scope != "global" {
        return Err(format!(
            "status polling response scope must be exact `global`, got `{}`",
            status.scope
        ));
    }
    if !matches!(status.resolved_from.as_str(), "cache" | "queue" | "state") {
        return Err(format!(
            "status polling response has unknown resolution source `{}`",
            status.resolved_from
        ));
    }
    Ok(status)
}
fn fixed_pipeline_status_is_applied(
    status: &PipelineTransactionStatusResponse,
) -> Result<bool, String> {
    match status.status.kind.as_str() {
        "Applied" => Ok(status.resolved_from == "state"),
        "Rejected" | "Expired" if status.resolved_from == "state" => Err(format!(
            "reached fixed terminal failure status `{}` (resolved_from={})",
            status.status.kind, status.resolved_from
        )),
        "Queued" | "Approved" | "Committed" | "Rejected" | "Expired" => Ok(false),
        other => Err(format!("returned unsupported exact status kind `{other}`")),
    }
}
fn extract_canonical_path_string_argument(
    arguments: &Map,
    canonical_field: &str,
) -> Result<String, String> {
    arguments
        .get("path")
        .and_then(Value::as_object)
        .and_then(|path| path.get(canonical_field))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("string `path.{canonical_field}` is required"))
}
fn extract_canonical_path_value_argument(
    arguments: &Map,
    canonical_field: &str,
) -> Result<String, String> {
    arguments
        .get("path")
        .and_then(Value::as_object)
        .and_then(|path| path.get(canonical_field))
        .and_then(value_to_string)
        .ok_or_else(|| format!("scalar `path.{canonical_field}` is required"))
}
fn extract_account_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "account_id")
}
fn extract_uaid_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "uaid")
}
fn extract_domain_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "domain_id")
}
fn extract_subscription_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "subscription_id")
}
fn extract_exact_subscription_id_argument(arguments: &Map) -> Result<String, String> {
    if arguments.contains_key("id") || arguments.contains_key("path") {
        return Err(
            "subscription draft actions accept only the exact top-level `subscription_id` field"
                .to_owned(),
        );
    }
    arguments
        .get("subscription_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "non-empty `subscription_id` is required".to_owned())
}
fn extract_iso20022_message_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "msg_id")
}
fn extract_ticket_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "ticket")
}
fn require_governance_selector_v1(label: &str, value: &str) -> Result<(), String> {
    if !iroha_data_model::governance::is_valid_governance_selector_v1(value) {
        return Err(format!(
            "`{label}` must match {}",
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN
        ));
    }
    Ok(())
}
fn require_governance_proposal_id_v1(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "`{label}` must be exactly 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}
fn extract_governance_selector_argument(
    arguments: &Map,
    path_key: &str,
    label: &str,
) -> Result<String, String> {
    reject_unknown_arguments(arguments, &["path", "headers", "accept"], label)?;
    let path = arguments
        .get("path")
        .and_then(Value::as_object)
        .ok_or_else(|| "`path` must be an object".to_owned())?;
    reject_unknown_arguments(path, &[path_key], label)?;
    let value = path
        .get(path_key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("string `path.{path_key}` is required"))?;
    require_governance_selector_v1(label, &value)?;
    Ok(value)
}
fn extract_governance_proposal_id_argument(arguments: &Map) -> Result<String, String> {
    reject_unknown_arguments(arguments, &["path", "headers", "accept"], "proposal id")?;
    let path = arguments
        .get("path")
        .and_then(Value::as_object)
        .ok_or_else(|| "`path` must be an object".to_owned())?;
    reject_unknown_arguments(path, &["id"], "proposal id")?;
    let value = path
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "string `path.id` is required".to_owned())?;
    require_governance_proposal_id_v1("proposal id", &value)?;
    Ok(value)
}
fn require_governance_body_string<'a>(body: &'a Value, field: &str) -> Result<&'a str, String> {
    let body = body
        .as_object()
        .ok_or_else(|| "governance request body must be an object".to_owned())?;
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{field}` must be a string"))
}
fn require_governance_selector_body<'a>(body: &'a Value, field: &str) -> Result<&'a str, String> {
    let value = require_governance_body_string(body, field)?;
    require_governance_selector_v1(field, value)?;
    Ok(value)
}
fn require_governance_openapi_path_string<'a>(
    arguments: &'a Map,
    field: &str,
) -> Result<&'a str, String> {
    let path = arguments
        .get("path")
        .and_then(Value::as_object)
        .ok_or_else(|| "`path` must be an object".to_owned())?;
    path.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`path.{field}` must be a string"))
}
fn require_governance_openapi_json_body(arguments: &Map) -> Result<&Value, String> {
    if arguments.contains_key("body_base64") {
        return Err(
            "governance MCP identifier preflight requires `body`; `body_base64` is unsupported"
                .to_owned(),
        );
    }
    if let Some(content_type) = arguments.get("content_type") {
        if content_type.as_str() != Some("application/json") {
            return Err(
                "governance MCP identifier preflight requires `content_type` to be `application/json`"
                    .to_owned(),
            );
        }
    }
    arguments
        .get("body")
        .ok_or_else(|| "`body` is required for governance MCP identifier preflight".to_owned())
}
fn validate_governance_openapi_dispatch(
    method: &Method,
    path_template: &str,
    arguments: &Map,
) -> Result<(), String> {
    let Some(validation) = governance_openapi_validation(method, path_template) else {
        return Ok(());
    };
    match validation {
        GovernanceOpenapiValidation::ProposalPath { field } => {
            let value = require_governance_openapi_path_string(arguments, field)?;
            require_governance_proposal_id_v1("proposal id", value)
        }
        GovernanceOpenapiValidation::SelectorPath { field, label } => {
            let value = require_governance_openapi_path_string(arguments, field)?;
            require_governance_selector_v1(label, value)
        }
        GovernanceOpenapiValidation::SelectorBody { field } => {
            let body = require_governance_openapi_json_body(arguments)?;
            require_governance_selector_body(body, field).map(|_| ())
        }
    }
}
fn extract_runtime_upgrade_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "id")
}
fn extract_height_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_value_argument(arguments, "height")
}
fn extract_definition_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "definition_id")
}
fn extract_asset_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "asset_id")
}
fn extract_nft_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "nft_id")
}
fn extract_rwa_id_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "rwa_id")
}
fn extract_transaction_hash_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "hash")
}
fn contract_artifact_route(arguments: &Map, bytes: bool) -> Result<String, String> {
    let dataspace = extract_canonical_path_string_argument(arguments, "dataspace_id")?;
    let hash = extract_canonical_path_string_argument(arguments, "code_hash")?;
    let artifact = crate::routing::parse_contract_artifact_path(&dataspace, &hash)
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "/v1/contracts/artifacts/{}/{}{}",
        artifact.dataspace_id.as_u64(),
        hex::encode(artifact.code_hash.as_ref()),
        if bytes { "/bytes" } else { "" }
    ))
}
async fn dispatch_contract_artifact(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
    bytes: bool,
) -> Result<Value, String> {
    let route = contract_artifact_route(arguments, bytes)?;
    dispatch_route(
        app,
        inbound_headers,
        Method::GET,
        &route,
        arguments.get("headers"),
        Vec::new(),
        None,
        arguments
            .get("accept")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .await
}
async fn dispatch_iroha_contracts_code_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_contract_artifact(app, inbound_headers, arguments, false).await
}
async fn dispatch_iroha_contracts_code_bytes_get(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    arguments: &Map,
) -> Result<Value, String> {
    dispatch_contract_artifact(app, inbound_headers, arguments, true).await
}
fn extract_contract_address_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_string_argument(arguments, "contract_address")
}
fn extract_instruction_index_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_value_argument(arguments, "index")
}
fn extract_block_identifier_argument(arguments: &Map) -> Result<String, String> {
    extract_canonical_path_value_argument(arguments, "identifier")
}
#[allow(clippy::too_many_arguments)]
async fn dispatch_route(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    method: Method,
    path_and_query: &str,
    extra_headers: Option<&Value>,
    body: Vec<u8>,
    content_type: Option<String>,
    accept: Option<String>,
) -> Result<Value, String> {
    dispatch_route_with_extra_header_policy(
        app,
        inbound_headers,
        method,
        path_and_query,
        extra_headers,
        body,
        content_type,
        accept,
        ExtraHeaderPolicy::Default,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn dispatch_route_borrowed(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    method: Method,
    path_and_query: &str,
    extra_headers: Option<&Value>,
    body: Vec<u8>,
    content_type: Option<&str>,
    accept: Option<&str>,
) -> Result<Value, String> {
    dispatch_route_with_borrowed_headers(
        app,
        inbound_headers,
        method,
        path_and_query,
        extra_headers,
        body,
        content_type,
        accept,
        ExtraHeaderPolicy::Default,
        None,
    )
    .await
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtraHeaderPolicy {
    Default,
    ConnectManagement,
    CanonicalAccountAuthentication,
    OptionalCanonicalAccountAuthentication,
    OperatorAuthentication,
}
impl ExtraHeaderPolicy {
    fn allows_reserved_extra_header(self, lowered: &str) -> bool {
        match self {
            Self::Default => false,
            Self::ConnectManagement => lowered == "authorization",
            Self::CanonicalAccountAuthentication | Self::OptionalCanonicalAccountAuthentication => {
                is_canonical_account_auth_header(lowered)
            }
            Self::OperatorAuthentication => is_operator_auth_header(lowered),
        }
    }
}
fn target_extra_header_policy(
    method: &Method,
    path_and_query: &str,
) -> Result<ExtraHeaderPolicy, String> {
    let descriptor =
        catalog_descriptor_for_dispatch(CATALOG_PROJECTION_GROUPS, method, path_and_query)?;
    Ok(match descriptor.authentication() {
        AuthenticationPolicy::CanonicalAccountSignature => {
            ExtraHeaderPolicy::CanonicalAccountAuthentication
        }
        AuthenticationPolicy::OptionalCanonicalAccountSignature => {
            ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication
        }
        AuthenticationPolicy::OperatorSignature => ExtraHeaderPolicy::OperatorAuthentication,
        AuthenticationPolicy::NestedRouteAuthentication => {
            return Err("recursive MCP route dispatch is forbidden".to_owned());
        }
        _ => ExtraHeaderPolicy::Default,
    })
}
#[allow(clippy::too_many_arguments)]
async fn dispatch_route_with_extra_header_policy(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    method: Method,
    path_and_query: &str,
    extra_headers: Option<&Value>,
    body: Vec<u8>,
    content_type: Option<String>,
    accept: Option<String>,
    extra_header_policy: ExtraHeaderPolicy,
) -> Result<Value, String> {
    dispatch_route_with_borrowed_headers(
        app,
        inbound_headers,
        method,
        path_and_query,
        extra_headers,
        body,
        content_type.as_deref(),
        accept.as_deref(),
        extra_header_policy,
        None,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn dispatch_route_with_borrowed_headers(
    app: &SharedAppState,
    inbound_headers: &HeaderMap,
    method: Method,
    path_and_query: &str,
    extra_headers: Option<&Value>,
    body: Vec<u8>,
    content_type: Option<&str>,
    accept: Option<&str>,
    extra_header_policy: ExtraHeaderPolicy,
    connect_management_token: Option<&str>,
) -> Result<Value, String> {
    let extra_header_policy = if extra_header_policy == ExtraHeaderPolicy::Default {
        target_extra_header_policy(&method, path_and_query)?
    } else {
        extra_header_policy
    };
    let dispatched_remote_ip = dispatched_remote_ip(inbound_headers);
    let dispatched_connect_addr = dispatched_connect_addr(dispatched_remote_ip);
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path_and_query)
        .body(Body::from(body))
        .map_err(|err| format!("build request: {err}"))?;
    request.extensions_mut().insert(InternalMcpDispatch);
    {
        let headers = request.headers_mut();
        forward_dispatch_auth_headers(headers, inbound_headers, &method, path_and_query)?;
        apply_extra_headers_with_policy(headers, extra_headers, extra_header_policy)?;
        if extra_header_policy == ExtraHeaderPolicy::ConnectManagement
            && let Some(token) = connect_management_token
            && !extra_headers.is_some_and(extra_headers_contain_authorization)
        {
            let value = connect_management_authorization_value(token)?;
            headers.insert(header::AUTHORIZATION, value);
        }
        if let Some(accept_value) = accept {
            let value = HeaderValue::from_str(accept_value)
                .map_err(|err| format!("invalid accept header: {err}"))?;
            headers.insert(header::ACCEPT, value);
        }
        if let Some(content_type_value) = content_type {
            let value = HeaderValue::from_str(content_type_value)
                .map_err(|err| format!("invalid content_type header: {err}"))?;
            headers.insert(header::CONTENT_TYPE, value);
        }
        let remote_addr_header = HeaderName::from_static(limits::REMOTE_ADDR_HEADER);
        headers.remove(&remote_addr_header);
        if let Some(remote_ip) = dispatched_remote_ip {
            let value = HeaderValue::from_str(&remote_ip.to_string())
                .map_err(|err| format!("invalid remote addr header: {err}"))?;
            headers.insert(remote_addr_header, value);
        }
    }
    let router = app
        .mcp_dispatch_router
        .load()
        .ok_or_else(|| "mcp router unavailable".to_owned())?;
    let service = router
        .into_make_service_with_connect_info::<SocketAddr>()
        .oneshot(dispatched_connect_addr)
        .await
        .map_err(|err| format!("dispatch connect-info failed: {err}"))?;
    let response = service
        .oneshot(request)
        .await
        .map_err(|err| format!("dispatch failed: {err}"))?;
    response_to_value(response, app.mcp.max_request_bytes)
        .await
        .map_err(|error| error.to_owned())
}
fn dispatched_remote_ip(inbound_headers: &HeaderMap) -> Option<IpAddr> {
    inbound_headers
        .get(limits::REMOTE_ADDR_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}
fn dispatched_connect_addr(remote_ip: Option<IpAddr>) -> SocketAddr {
    SocketAddr::new(remote_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0)
}
fn build_request_body<'a>(
    arguments: &'a Map,
    default_content_type: Option<&'a str>,
) -> Result<(Vec<u8>, Option<&'a str>), String> {
    if arguments.contains_key("body") && arguments.contains_key("body_base64") {
        return Err("`body` and `body_base64` are mutually exclusive".to_owned());
    }
    if let Some(encoded) = arguments.get("body_base64") {
        let encoded = encoded
            .as_str()
            .ok_or_else(|| "`body_base64` must be a string".to_owned())?;
        let bytes = decode_base64_any(encoded, "body_base64 must be valid base64/base64url")?;
        let content_type = arguments
            .get("content_type")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "`content_type` must be a string".to_owned())
            })
            .transpose()?
            .or(default_content_type)
            .or(Some(crate::utils::NORITO_MIME_TYPE));
        return Ok((bytes, content_type));
    }
    if let Some(body_value) = arguments.get("body") {
        let content_type = arguments
            .get("content_type")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "`content_type` must be a string".to_owned())
            })
            .transpose()?
            .or(default_content_type)
            .or(Some("application/json"));
        let bytes = if content_type.is_some_and(is_raw_text_request_media_type) {
            body_value
                .as_str()
                .ok_or_else(|| "text or XML `body` must be a string".to_owned())?
                .as_bytes()
                .to_vec()
        } else {
            encode_mcp_json_body(body_value, "encode body")?
        };
        return Ok((bytes, content_type));
    }
    Ok((Vec::new(), None))
}
fn is_raw_text_request_media_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    essence == "application/xml" || essence == "text/xml" || essence.starts_with("text/")
}
fn fill_path_template(path_template: &str, path_args: Option<&Value>) -> Result<String, String> {
    let empty_args = Map::new();
    let args = path_args.and_then(Value::as_object).unwrap_or(&empty_args);
    let mut out = String::new();
    let initial_capacity = path_template
        .len()
        .checked_add(16)
        .ok_or_else(|| "MCP route template length overflow".to_owned())?;
    out.try_reserve_exact(initial_capacity)
        .map_err(|_| "failed to reserve MCP route template".to_owned())?;
    let mut chars = path_template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '{' {
            out.push(ch);
            continue;
        }
        let mut key = String::new();
        while let Some(next) = chars.next() {
            if next == '}' {
                break;
            }
            key.push(next);
        }
        if key.is_empty() {
            return Err("invalid path template placeholder".to_owned());
        }
        let value = args
            .get(&key)
            .ok_or_else(|| format!("missing required path argument `{key}`"))?;
        let rendered;
        let value = if let Some(value) = value.as_str() {
            value
        } else {
            rendered =
                value_to_string(value).ok_or_else(|| format!("invalid path argument `{key}`"))?;
            rendered.as_str()
        };
        try_append_percent_encoded_path_component(&mut out, value)?;
    }
    Ok(out)
}
fn append_query(path: String, query: Option<&Value>) -> Result<String, String> {
    let Some(map) = query.and_then(Value::as_object) else {
        return Ok(path);
    };
    append_borrowed_query_pairs(path, map.iter().map(|(key, value)| (key.as_str(), value)))
}
fn value_to_string(value: &Value) -> Option<String> {
    if value.is_null() {
        return None;
    }
    if let Some(s) = value.as_str() {
        return Some(s.to_owned());
    }
    if let Some(i) = value.as_i64() {
        return Some(i.to_string());
    }
    if let Some(u) = value.as_u64() {
        return Some(u.to_string());
    }
    if let Some(f) = value.as_f64() {
        return Some(f.to_string());
    }
    if let Some(b) = value.as_bool() {
        return Some(b.to_string());
    }
    None
}
fn forward_auth_headers(out: &mut HeaderMap, inbound: &HeaderMap) -> Result<(), String> {
    for name in [
        header::AUTHORIZATION,
        HeaderName::from_static(HEADER_X_API_TOKEN),
    ] {
        let mut supplied = inbound.get_all(&name).iter();
        if let Some(value) = supplied.next() {
            if supplied.next().is_some() {
                return Err(format!("multiple {name} headers are not allowed"));
            }
            let mut value = value.clone();
            value.set_sensitive(true);
            out.insert(name, value);
        }
    }
    Ok(())
}
fn forward_dispatch_auth_headers(
    out: &mut HeaderMap,
    inbound: &HeaderMap,
    method: &Method,
    path_and_query: &str,
) -> Result<(), String> {
    forward_auth_headers(out, inbound)?;
    if is_onboarding_dispatch_route(method, path_and_query) {
        forward_onboarding_auth_header(out, inbound)?;
    }
    Ok(())
}
fn is_onboarding_dispatch_route(method: &Method, path_and_query: &str) -> bool {
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    (method == Method::POST
        && matches!(
            path,
            "/v1/accounts/onboard" | "/v1/accounts/onboard/plan" | "/v1/accounts/onboard/prepare"
        ))
        || (method == Method::GET && path == "/v1/accounts/onboarding/readiness")
}
fn forward_onboarding_auth_header(out: &mut HeaderMap, inbound: &HeaderMap) -> Result<(), String> {
    let header_name = HeaderName::from_static(crate::HEADER_ONBOARDING_API_TOKEN);
    let mut supplied = inbound.get_all(&header_name).iter();
    let Some(value) = supplied.next() else {
        return Ok(());
    };
    if supplied.next().is_some() {
        return Err(format!(
            "multiple {} headers are not allowed",
            crate::HEADER_ONBOARDING_API_TOKEN
        ));
    }
    let mut value = value.clone();
    value.set_sensitive(true);
    out.insert(header_name, value);
    Ok(())
}
#[cfg(test)]
fn apply_extra_headers(out: &mut HeaderMap, value: Option<&Value>) -> Result<(), String> {
    apply_extra_headers_with_policy(out, value, ExtraHeaderPolicy::Default)
}
fn apply_extra_headers_with_policy(
    out: &mut HeaderMap,
    value: Option<&Value>,
    policy: ExtraHeaderPolicy,
) -> Result<(), String> {
    match policy {
        ExtraHeaderPolicy::CanonicalAccountAuthentication
        | ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication => {
            remove_canonical_account_auth_headers(out)
        }
        ExtraHeaderPolicy::OperatorAuthentication => remove_operator_auth_headers(out),
        ExtraHeaderPolicy::Default | ExtraHeaderPolicy::ConnectManagement => {}
    }
    let headers_obj = match value {
        Some(Value::Object(headers_obj)) => headers_obj,
        Some(_)
            if matches!(
                policy,
                ExtraHeaderPolicy::CanonicalAccountAuthentication
                    | ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication
                    | ExtraHeaderPolicy::OperatorAuthentication
            ) =>
        {
            return Err("target authentication headers must be an object".to_owned());
        }
        None if matches!(
            policy,
            ExtraHeaderPolicy::CanonicalAccountAuthentication
                | ExtraHeaderPolicy::OperatorAuthentication
        ) =>
        {
            return Err("target authentication headers are required".to_owned());
        }
        _ => return Ok(()),
    };
    validate_target_authentication_headers(headers_obj, policy)?;
    for (raw_name, raw_value) in headers_obj {
        let lowered = raw_name.to_ascii_lowercase();
        if matches!(
            policy,
            ExtraHeaderPolicy::CanonicalAccountAuthentication
                | ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication
                | ExtraHeaderPolicy::OperatorAuthentication
        ) && !policy.allows_reserved_extra_header(&lowered)
        {
            return Err(format!(
                "unexpected `{raw_name}` in target authentication header map"
            ));
        }
        if is_reserved_extra_header(&lowered) && !policy.allows_reserved_extra_header(&lowered) {
            continue;
        }
        let header_name: HeaderName = raw_name
            .parse()
            .map_err(|err| format!("invalid header name `{raw_name}`: {err}"))?;
        let mut header_value = if matches!(
            policy,
            ExtraHeaderPolicy::CanonicalAccountAuthentication
                | ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication
                | ExtraHeaderPolicy::OperatorAuthentication
        ) {
            let exact = raw_value.as_str().ok_or_else(|| {
                format!("target authentication header `{raw_name}` must be a string")
            })?;
            HeaderValue::from_str(exact)
                .map_err(|err| format!("invalid header value for `{raw_name}`: {err}"))?
        } else if let Some(exact) = raw_value.as_str() {
            HeaderValue::from_str(exact)
                .map_err(|err| format!("invalid header value for `{raw_name}`: {err}"))?
        } else {
            let rendered = value_to_string(raw_value)
                .ok_or_else(|| format!("invalid header value for `{raw_name}`"))?;
            HeaderValue::from_str(&rendered)
                .map_err(|err| format!("invalid header value for `{raw_name}`: {err}"))?
        };
        if matches!(
            policy,
            ExtraHeaderPolicy::CanonicalAccountAuthentication
                | ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication
                | ExtraHeaderPolicy::OperatorAuthentication
        ) || (policy == ExtraHeaderPolicy::ConnectManagement && lowered == "authorization")
        {
            header_value.set_sensitive(true);
        }
        out.insert(header_name, header_value);
    }
    Ok(())
}
fn validate_target_authentication_headers(
    headers: &Map,
    policy: ExtraHeaderPolicy,
) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for name in headers.keys() {
        let lowered = name.to_ascii_lowercase();
        if !names.insert(lowered) {
            return Err(format!(
                "duplicate case-insensitive target authentication header `{name}`"
            ));
        }
    }
    match policy {
        ExtraHeaderPolicy::CanonicalAccountAuthentication
        | ExtraHeaderPolicy::OptionalCanonicalAccountAuthentication => {
            let has = |name: &str| names.contains(name);
            let signature_tuple = has(HEADER_X_IROHA_ACCOUNT)
                && has(HEADER_X_IROHA_SIGNATURE)
                && has(HEADER_X_IROHA_TIMESTAMP_MS)
                && has(HEADER_X_IROHA_NONCE)
                && !has(HEADER_X_IROHA_WITNESS);
            let witness = has(HEADER_X_IROHA_WITNESS)
                && !has(HEADER_X_IROHA_SIGNATURE)
                && !has(HEADER_X_IROHA_TIMESTAMP_MS)
                && !has(HEADER_X_IROHA_NONCE);
            if !(signature_tuple || witness) {
                return Err(
                    "canonical target authentication requires the complete account/signature/timestamp/nonce tuple or an exclusive witness"
                        .to_owned(),
                );
            }
            let value = |lowered_name: &str| -> Result<Option<&str>, String> {
                headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(lowered_name))
                    .map(|(name, value)| {
                        value.as_str().ok_or_else(|| {
                            format!(
                                "canonical target authentication header `{name}` must be a string"
                            )
                        })
                    })
                    .transpose()
            };
            crate::app_auth::validate_canonical_request_auth_wire_values(
                value(HEADER_X_IROHA_ACCOUNT)?,
                value(HEADER_X_IROHA_SIGNATURE)?,
                value(HEADER_X_IROHA_TIMESTAMP_MS)?,
                value(HEADER_X_IROHA_NONCE)?,
                value(HEADER_X_IROHA_WITNESS)?,
            )
            .map_err(|err| format!("invalid canonical target authentication headers: {err}"))?;
        }
        ExtraHeaderPolicy::OperatorAuthentication => {
            for required in [
                HEADER_X_IROHA_OPERATOR_PUBLIC_KEY,
                HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS,
                HEADER_X_IROHA_OPERATOR_NONCE,
                HEADER_X_IROHA_OPERATOR_SIGNATURE,
            ] {
                if !names.contains(required) {
                    return Err(format!(
                        "operator target authentication requires `{required}`"
                    ));
                }
            }
            let value = |lowered_name: &str| -> Result<&str, String> {
                headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(lowered_name))
                    .and_then(|(_, value)| value.as_str())
                    .ok_or_else(|| {
                        format!(
                            "operator target authentication header `{lowered_name}` must be a string"
                        )
                    })
            };
            validate_operator_auth_wire_values(
                value(HEADER_X_IROHA_OPERATOR_PUBLIC_KEY)?,
                value(HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS)?,
                value(HEADER_X_IROHA_OPERATOR_NONCE)?,
                value(HEADER_X_IROHA_OPERATOR_SIGNATURE)?,
            )?;
        }
        ExtraHeaderPolicy::Default | ExtraHeaderPolicy::ConnectManagement => {}
    }
    Ok(())
}
fn is_canonical_account_auth_header(lowered: &str) -> bool {
    matches!(
        lowered,
        HEADER_X_IROHA_ACCOUNT
            | HEADER_X_IROHA_SIGNATURE
            | HEADER_X_IROHA_TIMESTAMP_MS
            | HEADER_X_IROHA_NONCE
            | HEADER_X_IROHA_WITNESS
    )
}
const HEADER_X_IROHA_OPERATOR_PUBLIC_KEY: &str = "x-iroha-operator-public-key";
const HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS: &str = "x-iroha-operator-timestamp-ms";
const HEADER_X_IROHA_OPERATOR_NONCE: &str = "x-iroha-operator-nonce";
const HEADER_X_IROHA_OPERATOR_SIGNATURE: &str = "x-iroha-operator-signature";
fn validate_operator_auth_wire_values(
    public_key: &str,
    timestamp_ms: &str,
    nonce: &str,
    signature: &str,
) -> Result<(), String> {
    if public_key.is_empty()
        || public_key.len() > OPERATOR_PUBLIC_KEY_MAX_LITERAL_BYTES
        || public_key.trim() != public_key
    {
        return Err("invalid operator public-key header value".to_owned());
    }
    let public_key = PublicKey::from_canonical_str_for_decode(public_key)
        .map_err(|_| "invalid operator public-key header value".to_owned())?;
    let expected_signature_bytes = public_key
        .try_algorithm()
        .map_err(|_| "invalid operator public-key header value".to_owned())?
        .signature_payload_len();
    if expected_signature_bytes == 0
        || expected_signature_bytes > crate::app_auth::CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1
    {
        return Err("unsupported operator signature payload size".to_owned());
    }
    let timestamp = timestamp_ms.as_bytes();
    if timestamp.is_empty()
        || timestamp.len() > 20
        || !timestamp.iter().all(u8::is_ascii_digit)
        || (timestamp.len() > 1 && timestamp[0] == b'0')
        || timestamp_ms.parse::<u64>().is_err()
    {
        return Err("invalid operator timestamp header value".to_owned());
    }
    if nonce.is_empty()
        || nonce.len() > 256
        || !nonce.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err("invalid operator nonce header value".to_owned());
    }
    let signature_bytes = crate::app_auth::decode_bounded_canonical_base64_value(
        signature,
        expected_signature_bytes,
        "operator signature",
    )
    .map_err(|err| format!("invalid operator signature header value: {err}"))?;
    if signature_bytes.len() != expected_signature_bytes
        || signature_bytes.is_empty()
        || signature_bytes.iter().all(|byte| *byte == 0)
    {
        return Err("invalid operator signature header payload".to_owned());
    }
    Ok(())
}
fn is_operator_auth_header(lowered: &str) -> bool {
    matches!(
        lowered,
        HEADER_X_IROHA_OPERATOR_PUBLIC_KEY
            | HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS
            | HEADER_X_IROHA_OPERATOR_NONCE
            | HEADER_X_IROHA_OPERATOR_SIGNATURE
    )
}
fn remove_canonical_account_auth_headers(headers: &mut HeaderMap) {
    for name in [
        HEADER_X_IROHA_ACCOUNT,
        HEADER_X_IROHA_SIGNATURE,
        HEADER_X_IROHA_TIMESTAMP_MS,
        HEADER_X_IROHA_NONCE,
        HEADER_X_IROHA_WITNESS,
    ] {
        headers.remove(HeaderName::from_static(name));
    }
}
fn remove_operator_auth_headers(headers: &mut HeaderMap) {
    for name in [
        HEADER_X_IROHA_OPERATOR_PUBLIC_KEY,
        HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS,
        HEADER_X_IROHA_OPERATOR_NONCE,
        HEADER_X_IROHA_OPERATOR_SIGNATURE,
    ] {
        headers.remove(HeaderName::from_static(name));
    }
}
/// Prevent generic HTTP intermediaries from retaining target-derived MCP responses.
///
/// Native MCP cache hints live inside complete results and are keyed by the
/// request method, result-affecting params, and authorization scope. They do
/// not make the shared JSON-RPC POST URL safe for ordinary HTTP caching.
pub(crate) fn private_no_store_response(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}
fn is_reserved_extra_header(lowered: &str) -> bool {
    matches!(
        lowered,
        "authorization"
            | "content-length"
            | "host"
            | "connection"
            | limits::FORWARDED_FOR_HEADER
            | "x-forwarded-client-cert"
            | HEADER_X_IROHA_TIMESTAMP_MS
            | HEADER_X_IROHA_NONCE
            | HEADER_X_IROHA_WITNESS
            | HEADER_X_IROHA_OPERATOR_PUBLIC_KEY
            | HEADER_X_IROHA_OPERATOR_TIMESTAMP_MS
            | HEADER_X_IROHA_OPERATOR_NONCE
            | HEADER_X_IROHA_OPERATOR_SIGNATURE
    ) || lowered == HEADER_X_API_TOKEN
        || lowered == HEADER_X_IROHA_ACCOUNT
        || lowered == HEADER_X_IROHA_SIGNATURE
        || lowered == crate::HEADER_ONBOARDING_API_TOKEN
        || lowered == limits::REMOTE_ADDR_HEADER
        || lowered.starts_with("x-iroha-internal-")
}
/// Return true when an HTTP body error was caused by the configured byte cap.
pub(crate) fn body_error_is_length_limit(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        current = error.source();
    }
    false
}

async fn response_to_value(
    response: Response,
    max_body_bytes: usize,
) -> Result<Value, &'static str> {
    let (parts, body) = response.into_parts();
    let status = parts.status;
    let headers = parts.headers;
    let body_bytes = match tokio::time::timeout(
        MCP_BODY_READ_TIMEOUT,
        axum::body::to_bytes(body, max_body_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(error)) if body_error_is_length_limit(&error) => {
            return Err(TARGET_RESPONSE_TOO_LARGE_MESSAGE);
        }
        Ok(Err(_)) => return Err(TARGET_RESPONSE_READ_FAILED_MESSAGE),
        Err(_) => return Err(TARGET_RESPONSE_TIMEOUT_MESSAGE),
    };
    let headers_value = headers_to_value(&headers);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body_value = decode_response_body(&body_bytes, content_type.as_deref());
    let mut structured = Map::new();
    structured.insert("status".into(), Value::from(u64::from(status.as_u16())));
    structured.insert("headers".into(), headers_value);
    structured.insert(
        "content_type".into(),
        content_type.map(Value::String).unwrap_or(Value::Null),
    );
    structured.insert("body".into(), body_value);
    Ok(Value::Object(structured))
}
fn headers_to_value(headers: &HeaderMap) -> Value {
    let mut out = Map::new();
    for (name, value) in headers {
        if let Ok(as_str) = value.to_str() {
            out.insert(name.as_str().to_owned(), Value::String(as_str.to_owned()));
        }
    }
    Value::Object(out)
}
fn decode_response_body(bytes: &[u8], content_type: Option<&str>) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    // Reparse JSON into the typed value tree before it crosses the MCP
    // boundary. Malformed route output is carried as an escaped string below;
    // response bytes are never spliced into the outer JSON-RPC document.
    if content_type.is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
        && let Ok(value) = json::from_slice::<Value>(bytes)
    {
        return value;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Value::String(text.to_owned());
    }
    Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
}
fn apply_body_projection(mut structured: Value, projection: Option<&Value>) -> Value {
    let Some(keys) = projection.and_then(parse_projection_keys) else {
        return structured;
    };
    if keys.is_empty() {
        return structured;
    }
    if let Some(body) = structured
        .as_object_mut()
        .and_then(|payload| payload.get_mut("body"))
    {
        project_value_keys(body, &keys);
    }
    structured
}
fn parse_projection_keys(value: &Value) -> Option<BTreeSet<String>> {
    let keys = value
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    Some(keys)
}
fn project_value_keys(value: &mut Value, keys: &BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            object.retain(|key, _| keys.contains(key));
        }
        Value::Array(items) => {
            for item in items {
                if let Some(object) = item.as_object_mut() {
                    object.retain(|key, _| keys.contains(key));
                }
            }
        }
        _ => {}
    }
}
fn build_connect_ws_ticket(arguments: &Map, _inbound_headers: &HeaderMap) -> Result<Value, String> {
    reject_unknown_arguments(
        arguments,
        &[
            "sid",
            "role",
            "token",
            "token_app",
            "token_wallet",
            "node_url",
        ],
        "iroha.connect.ws.ticket",
    )?;
    let sid = canonical_connect_sid_argument(arguments)?;
    let role = arguments
        .get("role")
        .and_then(Value::as_str)
        .ok_or_else(|| "`role` is required".to_owned())?;
    if role != "app" && role != "wallet" {
        return Err("`role` must be `app` or `wallet`".to_owned());
    }
    let token = arguments
        .get("token")
        .and_then(Value::as_str)
        .or_else(|| match role {
            "app" => arguments.get("token_app").and_then(Value::as_str),
            "wallet" => arguments.get("token_wallet").and_then(Value::as_str),
            _ => None,
        })
        .ok_or_else(|| {
            "`token` is required (or provide `token_app`/`token_wallet` matching `role`)".to_owned()
        })?;
    let token_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "Connect role token must be canonical base64url without padding".to_owned())?;
    if token_bytes.len() != 32
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes) != token
    {
        return Err("Connect role token must encode exactly 32 bytes canonically".to_owned());
    }
    let authorization_header = format!("Bearer {token}");
    HeaderValue::from_str(&authorization_header)
        .map_err(|_| "Connect role token cannot form a valid Authorization header".to_owned())?;
    let node = required_string(arguments, "node_url")?;
    let mut url = parse_node_url(node)?;
    url.set_path("/v1/connect/ws");
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        query.append_pair("sid", sid);
        query.append_pair("role", role);
    }
    let protocol_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token.as_bytes());
    Ok(norito::json!({
        "ws_url": (url.to_string()),
        "authorization_header": (authorization_header),
        "sec_websocket_protocol": (format!("iroha-connect.token.v1.{protocol_token}"))
    }))
}
fn parse_node_url(raw: &str) -> Result<url::Url, String> {
    let mut url =
        url::Url::parse(raw).map_err(|err| format!("invalid absolute node url `{raw}`: {err}"))?;
    if url.host_str().is_none() {
        return Err("node URL must include a host".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("node URL must not contain user information".to_owned());
    }
    if url.fragment().is_some() {
        return Err("node URL must not contain a fragment".to_owned());
    }
    match url.scheme() {
        "http" => {
            url.set_scheme("ws")
                .map_err(|_| "failed to convert http->ws".to_owned())?;
        }
        "https" => {
            url.set_scheme("wss")
                .map_err(|_| "failed to convert https->wss".to_owned())?;
        }
        "ws" | "wss" => {}
        other => {
            return Err(format!(
                "unsupported node URL scheme `{other}`; expected http/https/ws/wss"
            ));
        }
    }
    Ok(url)
}
const MANUAL_STATIC_TOOL_ASSET_VERSION: u64 = 1;
const MANUAL_STATIC_TOOL_ASSET_DESCRIPTOR_COUNT: usize = 79;
// Includes the fully typed account-onboarding receipt schemas in the embedded catalog.
const MANUAL_STATIC_TOOL_ASSET_MAX_BYTES: usize = 128 * 1024;
const MANUAL_STATIC_TOOL_HISTORICAL_RUST_PREIMAGE_SHA256: &str =
    "1273686f98de21c686573d399d511be7606155b9d09de21869a8c060436242b4";
const MANUAL_STATIC_TOOL_ASSET: &[u8] = include_bytes!("mcp/manual_tool_descriptors_v1.json");
// Reject oversized embedded assets at compile time as well as in the loader.
const _: () = assert!(
    MANUAL_STATIC_TOOL_ASSET.len() <= MANUAL_STATIC_TOOL_ASSET_MAX_BYTES,
    "embedded manual MCP descriptor asset exceeds its byte budget"
);

#[derive(Clone)]
struct ManualStaticToolDescriptor {
    name: String,
    effect: ToolEffect,
    description: String,
    method: Method,
    path_template: String,
    input_schema: Value,
}

static MANUAL_STATIC_TOOL_DESCRIPTORS: LazyLock<BTreeMap<String, ManualStaticToolDescriptor>> =
    LazyLock::new(load_manual_static_tool_descriptors);

/// Route contracts for purpose-built dispatchers whose descriptors are not
/// loaded from `manual_tool_descriptors_v1.json`.
///
/// `handle_named_tool_call` admits a route-backed tool to its specialized
/// name-dispatch match only when it appears here or in the immutable descriptor
/// asset below. Therefore adding a specialized match arm without an execution
/// contract cannot silently bypass the generic backing-driven adapter.
const INLINE_PURPOSE_BUILT_DISPATCH_ROUTES: &[(&str, &str, &str)] = &[
    ("iroha.connect.session.status", "GET", "/v1/connect/status"),
    ("iroha.vpn.profile", "GET", "/v1/vpn/profile"),
    ("iroha.vpn.quotes.create", "POST", "/v1/vpn/quotes"),
    ("iroha.vpn.sessions.create", "POST", "/v1/vpn/sessions"),
    (
        "iroha.vpn.sessions.get",
        "GET",
        "/v1/vpn/sessions/{session_id}",
    ),
    ("iroha.vpn.receipts.list", "GET", "/v1/vpn/receipts"),
    ("iroha.vpn.receipts.submit", "POST", "/v1/vpn/receipts"),
    ("iroha.health", "GET", "/health"),
    (
        "iroha.accounts.faucet.policy",
        "GET",
        "/v1/accounts/faucet/policy",
    ),
    ("iroha.parameters.get", "GET", "/v1/parameters"),
    ("iroha.node.capabilities", "GET", "/v1/node/capabilities"),
    (
        "iroha.node.query_projection_checkpoint",
        "GET",
        "/v1/node/query/projection/checkpoint",
    ),
    ("iroha.da.ingest", "POST", "/v1/da/ingest"),
    ("iroha.da.proof_policies", "GET", "/v1/da/proof-policies"),
    ("iroha.da.commitments.list", "POST", "/v1/da/commitments"),
    (
        "iroha.da.commitments.prove",
        "POST",
        "/v1/da/commitments/prove",
    ),
    (
        "iroha.da.commitments.verify",
        "POST",
        "/v1/da/commitments/verify",
    ),
    ("iroha.da.pin_intents.list", "POST", "/v1/da/pin-intents"),
    (
        "iroha.da.pin_intents.prove",
        "POST",
        "/v1/da/pin-intents/prove",
    ),
    (
        "iroha.da.pin_intents.verify",
        "POST",
        "/v1/da/pin-intents/verify",
    ),
    ("iroha.runtime.abi.active", "GET", "/v1/runtime/abi/active"),
    ("iroha.runtime.abi.hash", "GET", "/v1/runtime/abi/hash"),
    ("iroha.runtime.metrics", "GET", "/v1/runtime/metrics"),
    ("iroha.runtime.upgrades.list", "GET", "/v1/runtime/upgrades"),
    (
        "iroha.runtime.upgrades.propose",
        "POST",
        "/v1/runtime/upgrades/propose",
    ),
    ("iroha.proofs.query", "POST", "/v1/proofs/query"),
    (
        "iroha.gov.proposals.deploy_contract",
        "POST",
        "/v1/gov/proposals/deploy-contract",
    ),
    (
        "iroha.gov.parliament.attempts.draft",
        "POST",
        "/v1/gov/parliament/attempts/draft",
    ),
    (
        "iroha.gov.parliament.attempts.get",
        "GET",
        "/v1/gov/parliament/attempts/{governance_attempt_id}",
    ),
    (
        "iroha.gov.parliament.ballots.timed_ovn_casting_context.get",
        "GET",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context",
    ),
    (
        "iroha.gov.parliament.ballots.timed_ovn_casting_proof.get",
        "POST",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof",
    ),
    (
        "iroha.gov.parliament.ballots.tle_release_context.get",
        "GET",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context",
    ),
    (
        "iroha.gov.parliament.ballots.tle_partial_release.create",
        "POST",
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release",
    ),
    (
        "iroha.gov.parliament.transitions.draft",
        "POST",
        "/v1/gov/parliament/transitions/draft",
    ),
    ("iroha.gov.proposals.get", "GET", "/v1/gov/proposals/{id}"),
    ("iroha.gov.locks.get", "GET", "/v1/gov/locks/{rid}"),
    ("iroha.gov.referenda.get", "GET", "/v1/gov/referenda/{id}"),
    ("iroha.gov.tally.get", "GET", "/v1/gov/tally/{id}"),
    ("iroha.gov.ballots.zk_v1", "POST", "/v1/gov/ballots/zk-v1"),
    (
        "iroha.gov.ballots.zk_v1.ballot_proof",
        "POST",
        "/v1/gov/ballots/zk-v1/ballot-proof",
    ),
    ("iroha.gov.ballots.plain", "POST", "/v1/gov/ballots/plain"),
    (
        "iroha.gov.protected_namespaces.list",
        "GET",
        "/v1/gov/protected-namespaces",
    ),
    (
        "iroha.gov.protected_namespaces.update",
        "POST",
        "/v1/gov/protected-namespaces",
    ),
    ("iroha.gov.unlocks.stats", "GET", "/v1/gov/unlocks/stats"),
    ("iroha.gov.citizens.count", "GET", "/v1/gov/citizens"),
    ("iroha.contracts.call", "POST", "/v1/contracts/call"),
    ("iroha.contracts.view", "POST", "/v1/contracts/view"),
    (
        "iroha.accounts.faucet.prepare",
        "POST",
        "/v1/accounts/faucet/prepare",
    ),
    (
        "iroha.accounts.faucet.submit",
        "POST",
        "/v1/accounts/faucet",
    ),
    ("iroha.transactions.query", "POST", "/v1/transactions/query"),
    (
        "iroha.subscriptions.pause",
        "POST",
        "/v1/subscriptions/{subscription_id}/pause",
    ),
    (
        "iroha.subscriptions.resume",
        "POST",
        "/v1/subscriptions/{subscription_id}/resume",
    ),
    (
        "iroha.subscriptions.cancel",
        "POST",
        "/v1/subscriptions/{subscription_id}/cancel",
    ),
    (
        "iroha.subscriptions.keep",
        "POST",
        "/v1/subscriptions/{subscription_id}/keep",
    ),
    (
        "iroha.subscriptions.usage",
        "POST",
        "/v1/subscriptions/{subscription_id}/usage",
    ),
    (
        "iroha.subscriptions.charge_now",
        "POST",
        "/v1/subscriptions/{subscription_id}/charge-now",
    ),
    ("iroha.nfts.chain.list", "GET", "/v1/nfts"),
    ("iroha.rwas.chain.list", "GET", "/v1/rwas"),
    (
        "iroha.iso20022.pacs008.submit",
        "POST",
        "/v1/iso20022/pacs008",
    ),
    (
        "iroha.iso20022.pacs009.submit",
        "POST",
        "/v1/iso20022/pacs009",
    ),
    (
        "iroha.iso20022.pacs002.submit",
        "POST",
        "/v1/iso20022/pacs002",
    ),
    (
        "iroha.iso20022.pacs004.submit",
        "POST",
        "/v1/iso20022/pacs004",
    ),
    (
        "iroha.iso20022.camt056.submit",
        "POST",
        "/v1/iso20022/camt056",
    ),
    (
        "iroha.iso20022.sese023.submit",
        "POST",
        "/v1/iso20022/sese023",
    ),
    (
        "iroha.iso20022.sese024.submit",
        "POST",
        "/v1/iso20022/sese024",
    ),
    (
        "iroha.iso20022.sese025.submit",
        "POST",
        "/v1/iso20022/sese025",
    ),
    (
        "iroha.iso20022.colr012.submit",
        "POST",
        "/v1/iso20022/colr012",
    ),
    (
        "iroha.iso20022.status.get",
        "GET",
        "/v1/iso20022/messages/{msg_id}",
    ),
    ("iroha.queries.submit", "POST", "/v1/query"),
    (
        "iroha.transactions.submit",
        "POST",
        "/v1/pipeline/transactions",
    ),
    (
        "iroha.transactions.submit_and_wait",
        "POST",
        "/v1/pipeline/transactions",
    ),
];

fn purpose_built_dispatch_route_contract(name: &str) -> Option<(&'static str, &'static str)> {
    if let Some((_, method, path_template)) = INLINE_PURPOSE_BUILT_DISPATCH_ROUTES
        .iter()
        .find(|(tool_name, _, _)| *tool_name == name)
    {
        return Some((*method, *path_template));
    }
    MANUAL_STATIC_TOOL_DESCRIPTORS
        .values()
        .find(|descriptor| descriptor.name == name)
        .map(|descriptor| {
            (
                descriptor.method.as_str(),
                descriptor.path_template.as_str(),
            )
        })
}

fn take_manual_static_tool_asset_string(
    record: &mut Map,
    field: &str,
    record_index: usize,
) -> String {
    let Some(value) = record.remove(field) else {
        panic!("manual MCP descriptor asset record {record_index} is missing `{field}`");
    };
    let Value::String(value) = value else {
        panic!("manual MCP descriptor asset record {record_index} field `{field}` is not a string");
    };
    value
}

fn manual_static_tool_asset_identifier_is_valid(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if first != b'_' && !first.is_ascii_alphabetic() {
        return false;
    }
    for byte in bytes {
        if byte != b'_' && !byte.is_ascii_alphanumeric() {
            return false;
        }
    }
    true
}

fn load_manual_static_tool_descriptors() -> BTreeMap<String, ManualStaticToolDescriptor> {
    parse_manual_static_tool_descriptors(MANUAL_STATIC_TOOL_ASSET)
}

fn parse_manual_static_tool_descriptors(
    asset_bytes: &[u8],
) -> BTreeMap<String, ManualStaticToolDescriptor> {
    // The binary embeds these bytes directly. Enforce schema and resource policy,
    // not a duplicate content fingerprint that can drift after a descriptor edit.
    assert!(
        asset_bytes.len() <= MANUAL_STATIC_TOOL_ASSET_MAX_BYTES,
        "manual MCP descriptor asset exceeds the byte limit"
    );
    let asset = match json::from_slice::<Value>(asset_bytes) {
        Ok(asset) => asset,
        Err(error) => panic!("manual MCP descriptor asset is not valid Norito JSON: {error}"),
    };
    let Value::Object(mut root) = asset else {
        panic!("manual MCP descriptor asset root is not an object");
    };
    assert!(
        root.len() == 3
            && root.contains_key("schema_version")
            && root.contains_key("historical_rust_preimage_sha256")
            && root.contains_key("descriptors"),
        "manual MCP descriptor asset root fields drifted"
    );
    let Some(version_value) = root.remove("schema_version") else {
        unreachable!("schema_version presence was checked");
    };
    let Some(version) = version_value.as_u64() else {
        panic!("manual MCP descriptor asset schema_version is not an unsigned integer");
    };
    assert_eq!(
        version, MANUAL_STATIC_TOOL_ASSET_VERSION,
        "manual MCP descriptor asset schema version drifted"
    );
    let Some(historical_preimage_value) = root.remove("historical_rust_preimage_sha256") else {
        unreachable!("historical_rust_preimage_sha256 presence was checked");
    };
    let Value::String(historical_preimage) = historical_preimage_value else {
        panic!("manual MCP descriptor asset historical preimage digest is not a string");
    };
    assert_eq!(
        historical_preimage, MANUAL_STATIC_TOOL_HISTORICAL_RUST_PREIMAGE_SHA256,
        "manual MCP descriptor asset historical preimage digest drifted"
    );
    let Some(descriptors_value) = root.remove("descriptors") else {
        unreachable!("descriptors presence was checked");
    };
    let Value::Array(descriptors) = descriptors_value else {
        panic!("manual MCP descriptor asset descriptors field is not an array");
    };
    assert_eq!(
        descriptors.len(),
        MANUAL_STATIC_TOOL_ASSET_DESCRIPTOR_COUNT,
        "manual MCP descriptor asset count drifted"
    );

    let mut by_function = BTreeMap::new();
    let mut tool_names = BTreeSet::new();
    for (record_index, descriptor) in descriptors.into_iter().enumerate() {
        let Value::Object(mut record) = descriptor else {
            panic!("manual MCP descriptor asset record {record_index} is not an object");
        };
        assert!(
            record.len() == 7
                && record.contains_key("function")
                && record.contains_key("name")
                && record.contains_key("effect")
                && record.contains_key("description")
                && record.contains_key("method")
                && record.contains_key("path_template")
                && record.contains_key("input_schema"),
            "manual MCP descriptor asset record {record_index} fields drifted"
        );
        let function = take_manual_static_tool_asset_string(&mut record, "function", record_index);
        assert!(
            manual_static_tool_asset_identifier_is_valid(&function),
            "manual MCP descriptor asset record {record_index} has an invalid function identifier"
        );
        let name = take_manual_static_tool_asset_string(&mut record, "name", record_index);
        assert!(
            !name.is_empty() && tool_names.insert(name.clone()),
            "manual MCP descriptor asset record {record_index} has an empty or duplicate tool name"
        );
        let effect_name = take_manual_static_tool_asset_string(&mut record, "effect", record_index);
        let effect = match effect_name.as_str() {
            "read" => ToolEffect::Read,
            "build_instruction" => ToolEffect::BuildInstruction,
            "write" => ToolEffect::Write,
            "operator" => ToolEffect::Operator,
            _ => panic!(
                "manual MCP descriptor asset record {record_index} has invalid effect `{effect_name}`"
            ),
        };
        let description =
            take_manual_static_tool_asset_string(&mut record, "description", record_index);
        assert!(
            !description.is_empty(),
            "manual MCP descriptor asset record {record_index} has an empty description"
        );
        let method_name = take_manual_static_tool_asset_string(&mut record, "method", record_index);
        let method = match method_name.as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "PATCH" => Method::PATCH,
            "DELETE" => Method::DELETE,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            _ => panic!(
                "manual MCP descriptor asset record {record_index} has invalid method `{method_name}`"
            ),
        };
        let path_template =
            take_manual_static_tool_asset_string(&mut record, "path_template", record_index);
        assert!(
            path_template.starts_with('/'),
            "manual MCP descriptor asset record {record_index} has an invalid path template"
        );
        let Some(mut input_schema) = record.remove("input_schema") else {
            unreachable!("input_schema presence was checked");
        };
        assert!(
            input_schema.is_object(),
            "manual MCP descriptor asset record {record_index} input_schema is not an object"
        );
        // Collection tools carry a shape marker instead of repeating the shared
        // query-control schema in every record.
        if let Err(error) = expand_collection_query_schema(&mut input_schema) {
            panic!("manual MCP descriptor asset record {record_index}: {error}");
        }
        let previous = by_function.insert(
            function,
            ManualStaticToolDescriptor {
                name,
                effect,
                description,
                method,
                path_template,
                input_schema,
            },
        );
        assert!(
            previous.is_none(),
            "manual MCP descriptor asset contains a duplicate function identifier"
        );
    }
    by_function
}

fn manual_static_tool(function: &str, expected_name: &str) -> ToolSpec {
    let Some(descriptor) = MANUAL_STATIC_TOOL_DESCRIPTORS.get(function) else {
        panic!("manual MCP descriptor asset is missing function `{function}`");
    };
    assert_eq!(
        descriptor.name, expected_name,
        "manual MCP descriptor wrapper `{function}` name drifted"
    );
    ToolSpec::route(
        descriptor.name.clone(),
        descriptor.description.clone(),
        descriptor.effect,
        descriptor.method.clone(),
        descriptor.path_template.clone(),
        descriptor.input_schema.clone(),
    )
}

macro_rules! manual_tool {
    ($function:ident, $name:literal) => {
        fn $function() -> ToolSpec {
            manual_static_tool(stringify!($function), $name)
        }
    };
    ($($function:ident => $name:literal;)+) => {
        $(manual_tool!($function, $name);)+
    };
}
manual_tool! {
    iroha_connect_ws_ticket_tool => "iroha.connect.ws.ticket";
    iroha_connect_session_create_tool => "iroha.connect.session.create";
    iroha_connect_session_delete_tool => "iroha.connect.session.delete";
    iroha_node_query_projection_shard_catalog_tool => "iroha.node.query_projection_shard_catalog";
    iroha_da_manifests_get_tool => "iroha.da.manifests.get";
    iroha_runtime_upgrades_activate_tool => "iroha.runtime.upgrades.activate";
    iroha_runtime_upgrades_cancel_tool => "iroha.runtime.upgrades.cancel";
    iroha_bridge_finality_proof_tool => "iroha.bridge.finality.proof";
    iroha_bridge_finality_bundle_tool => "iroha.bridge.finality.bundle";
    iroha_gov_contract_get_tool => "iroha.gov.contract.get";
    iroha_aliases_resolve_tool => "iroha.aliases.resolve";
    iroha_aliases_resolve_index_tool => "iroha.aliases.resolve_index";
    iroha_aliases_by_account_tool => "iroha.aliases.by_account";
    iroha_contracts_code_get_tool => "iroha.contracts.code.get";
    iroha_contracts_code_bytes_get_tool => "iroha.contracts.code.bytes.get";
    iroha_contracts_call_and_wait_tool => "iroha.contracts.call_and_wait";
    iroha_contracts_state_get_tool => "iroha.contracts.state.get";
    iroha_accounts_list_tool => "iroha.accounts.list";
    iroha_accounts_get_tool => "iroha.accounts.get";
    iroha_accounts_qr_tool => "iroha.accounts.qr";
    iroha_accounts_query_tool => "iroha.accounts.query";
    iroha_accounts_onboard_plan_tool => "iroha.accounts.onboard.plan";
    iroha_accounts_onboard_prepare_tool => "iroha.accounts.onboard.prepare";
    iroha_accounts_onboard_submit_tool => "iroha.accounts.onboard.submit";
    iroha_account_transactions_tool => "iroha.accounts.transactions";
    iroha_account_history_tool => "iroha.accounts.history";
    iroha_account_history_query_tool => "iroha.accounts.history.query";
    iroha_contracts_activity_query_tool => "iroha.contracts.activity.query";
    iroha_contracts_events_query_tool => "iroha.contracts.events.query";
    iroha_explorer_accounts_query_tool => "iroha.explorer.accounts.query";
    iroha_explorer_domains_query_tool => "iroha.explorer.domains.query";
    iroha_explorer_asset_definitions_query_tool => "iroha.explorer.asset_definitions.query";
    iroha_explorer_assets_query_tool => "iroha.explorer.assets.query";
    iroha_explorer_nfts_query_tool => "iroha.explorer.nfts.query";
    iroha_explorer_rwas_query_tool => "iroha.explorer.rwas.query";
    iroha_explorer_blocks_query_tool => "iroha.explorer.blocks.query";
    iroha_explorer_transactions_query_tool => "iroha.explorer.transactions.query";
    iroha_explorer_transactions_latest_query_tool => "iroha.explorer.transactions.latest.query";
    iroha_explorer_instructions_query_tool => "iroha.explorer.instructions.query";
    iroha_explorer_instructions_latest_query_tool => "iroha.explorer.instructions.latest.query";
    iroha_account_transactions_query_tool => "iroha.accounts.transactions.query";
    iroha_account_assets_tool => "iroha.accounts.assets";
    iroha_account_assets_query_tool => "iroha.accounts.assets.query";
    iroha_account_permissions_tool => "iroha.accounts.permissions";
    iroha_account_permissions_query_tool => "iroha.accounts.permissions.query";
    iroha_subscriptions_plans_query_tool => "iroha.subscriptions.plans.query";
    iroha_subscriptions_query_tool => "iroha.subscriptions.query";
    iroha_uaid_manifests_tool => "iroha.space_directory.manifests";
    iroha_uaid_manifests_query_tool => "iroha.space_directory.manifests.query";
    iroha_account_portfolio_tool => "iroha.accounts.portfolio";
    iroha_domains_list_tool => "iroha.domains.list";
    iroha_domains_get_tool => "iroha.domains.get";
    iroha_domains_query_tool => "iroha.domains.query";
    iroha_subscriptions_plans_list_tool => "iroha.subscriptions.plans.list";
    iroha_subscriptions_plans_create_tool => "iroha.subscriptions.plans.create";
    iroha_subscriptions_list_tool => "iroha.subscriptions.list";
    iroha_subscriptions_create_tool => "iroha.subscriptions.create";
    iroha_subscriptions_get_tool => "iroha.subscriptions.get";
    iroha_asset_definitions_tool => "iroha.assets.definitions";
    iroha_asset_definitions_get_tool => "iroha.assets.definitions.get";
    iroha_asset_definitions_query_tool => "iroha.assets.definitions.query";
    iroha_asset_holders_tool => "iroha.assets.holders";
    iroha_asset_holders_query_tool => "iroha.assets.holders.query";
    iroha_assets_list_tool => "iroha.assets.list";
    iroha_assets_get_tool => "iroha.assets.get";
    iroha_nfts_list_tool => "iroha.nfts.list";
    iroha_nfts_get_tool => "iroha.nfts.get";
    iroha_nfts_query_tool => "iroha.nfts.query";
    iroha_rwas_list_tool => "iroha.rwas.list";
    iroha_rwas_get_tool => "iroha.rwas.get";
    iroha_rwas_query_tool => "iroha.rwas.query";
    iroha_transactions_list_tool => "iroha.transactions.list";
    iroha_transactions_get_tool => "iroha.transactions.get";
    iroha_instructions_list_tool => "iroha.instructions.list";
    iroha_instructions_get_tool => "iroha.instructions.get";
    iroha_blocks_list_tool => "iroha.blocks.list";
    iroha_blocks_get_tool => "iroha.blocks.get";
    iroha_transactions_wait_tool => "iroha.transactions.wait";
    iroha_transactions_status_tool => "iroha.transactions.status";
}
fn account_faucet_tool_input_schema(path: &str) -> Value {
    let spec = openapi::compiled_spec();
    let operation = spec
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(path))
        .and_then(Value::as_object)
        .and_then(|path| path.get("post"))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("faucet MCP tool route POST {path} is absent from OpenAPI"));
    let body_schema = operation
        .get("requestBody")
        .and_then(|request_body| build_request_body_schema(spec, request_body))
        .unwrap_or_else(|| panic!("faucet MCP tool route POST {path} lacks a typed request body"));
    let mut properties = Map::new();
    properties.insert("body".to_owned(), body_schema);
    properties.insert("accept".to_owned(), string_schema());
    let mut schema = Map::new();
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert(
        MCP_STRICT_BODY_SCHEMA_EXTENSION.to_owned(),
        Value::Bool(true),
    );
    schema.insert("additionalProperties".to_owned(), Value::Bool(false));
    schema.insert(
        "required".to_owned(),
        Value::Array(vec![Value::String("body".to_owned())]),
    );
    schema.insert("properties".to_owned(), Value::Object(properties));
    Value::Object(schema)
}
fn iroha_accounts_faucet_policy_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.accounts.faucet.policy",
        "Read the enabled faucet's public network, address profile, authority, asset and amount policy. This unsigned discovery response must be checked against an independently trusted operator policy before preparing or submitting funding.",
        "/v1/accounts/faucet/policy",
    )
}
fn iroha_accounts_faucet_prepare_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.accounts.faucet.prepare".to_owned(),
        "Validate one faucet proof-of-work claim and return an exact faucet-authority-signed transaction envelope. Successful ledger execution consumes the claim through a durable authority-scoped consensus marker, so distinct preparations of the same claim cannot both commit."
            .to_owned(),
        ToolEffect::Write,
        Method::POST,
        "/v1/accounts/faucet/prepare".to_owned(),
        account_faucet_tool_input_schema("/v1/accounts/faucet/prepare"),
    )
}
fn iroha_accounts_faucet_submit_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.accounts.faucet.submit".to_owned(),
        "Submit only the exact authenticated envelope returned by iroha.accounts.faucet.prepare. Consensus rejects a semantic claim already consumed through any peer, binding, restart, or generic transaction ingress."
            .to_owned(),
        ToolEffect::Write,
        Method::POST,
        "/v1/accounts/faucet".to_owned(),
        account_faucet_tool_input_schema("/v1/accounts/faucet"),
    )
}
fn simple_manual_get_tool(name: &str, description: &str, path_template: &str) -> ToolSpec {
    ToolSpec::route(
        name.to_owned(),
        description.to_owned(),
        manual_tool_effect_from_name(name),
        Method::GET,
        path_template.to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn simple_manual_raw_body_post_tool(
    name: &str,
    description: &str,
    path_template: &str,
    body_description: &str,
) -> ToolSpec {
    ToolSpec::route(
        name.to_owned(),
        description.to_owned(),
        manual_tool_effect_from_name(name),
        Method::POST,
        path_template.to_owned(),
        norito::json!({
            "type": "object",
            "required": ["body"],
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": true,
                    "description": body_description
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_vpn_profile_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.vpn.profile",
        "Fetch the public Sora VPN profile advertised by Torii.",
        "/v1/vpn/profile",
    )
}
fn vpn_canonical_auth_schema() -> Value {
    norito::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Canonical account proof signed for the exact inner VPN method, path, query, and request body. This proof is distinct from authentication on the outer /v1/mcp request and is validated by the VPN route's normal canonical verifier.",
        "properties": {
            "account": {
                "type": "string",
                "minLength": 1,
                "maxLength": (crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1),
                "description": "Exact canonical I105 AccountId or active printable-ASCII account alias. I105 is forwarded in X-Iroha-Account as lowercase canonical address hex. Required for a signature tuple and optional when the witness identifies the subject account."
            },
            "signature": {
                "type": "string",
                "minLength": 4,
                "maxLength": (CANONICAL_SIGNATURE_MAX_ENCODED_BYTES),
                "pattern": (CANONICAL_PADDED_BASE64_PATTERN),
                "description": "Canonical padded-base64 canonical-request signature for the exact inner VPN target."
            },
            "timestamp_ms": {
                "type": "integer",
                "minimum": 0,
                "maximum": (u64::MAX),
                "description": "Unsigned Unix timestamp in milliseconds bound into the signature."
            },
            "nonce": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[!-~]+$",
                "description": "Fresh nonce bound into the signature."
            },
            "witness": {
                "type": "string",
                "minLength": 4,
                "maxLength": (CANONICAL_WITNESS_MAX_ENCODED_BYTES),
                "pattern": (CANONICAL_PADDED_BASE64_PATTERN),
                "description": "Canonical padded-base64 Norito V1 canonical-request witness for the exact inner VPN target."
            }
        },
        "oneOf": [
            {
                "required": ["account", "signature", "timestamp_ms", "nonce"],
                "not": { "required": ["witness"] }
            },
            {
                "required": ["witness"],
                "not": {
                    "anyOf": [
                        { "required": ["signature"] },
                        { "required": ["timestamp_ms"] },
                        { "required": ["nonce"] }
                    ]
                }
            }
        ]
    })
}
fn iroha_vpn_quotes_create_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.vpn.quotes.create".to_owned(),
        "Create a Sora VPN XOR escrow quote. `canonical_auth` must be signed for POST /v1/vpn/quotes and the exact Norito JSON serialization of `body`; outer MCP authentication is never reused for the inner target."
            .to_owned(),
        manual_tool_effect_from_name("iroha.vpn.quotes.create"),
        Method::POST,
        "/v1/vpn/quotes".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "x-iroha-mcp-strict-body": true,
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["metering_public_key_hex"],
                    "properties": {
                        "exit_class": { "type": "string" },
                        "metering_public_key_hex": { "type": "string" }
                    },
                    "description": "Exact VPN quote request object serialized by Norito JSON before inner canonical verification. Successful responses include the required `open_lease_instruction` native `OpenVpnLeaseEscrow` skeleton for client signing/submission."
                },
                "canonical_auth": (vpn_canonical_auth_schema()),
                "accept": { "type": "string" }
            },
            "required": ["body", "canonical_auth"]
        }),
    )
}
fn iroha_vpn_sessions_create_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.vpn.sessions.create".to_owned(),
        "Create a Sora VPN session after committing the quoted XOR escrow payment. `canonical_auth` must be signed for POST /v1/vpn/sessions and the exact Norito JSON serialization of `body`; outer MCP authentication is never reused for the inner target."
            .to_owned(),
        manual_tool_effect_from_name("iroha.vpn.sessions.create"),
        Method::POST,
        "/v1/vpn/sessions".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "x-iroha-mcp-strict-body": true,
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["quote_id", "payment_tx_hash", "metering_public_key_hex"],
                    "properties": {
                        "exit_class": { "type": "string" },
                        "quote_id": { "type": "string" },
                        "payment_tx_hash": { "type": "string" },
                        "metering_public_key_hex": { "type": "string" }
                    },
                    "description": "Exact VPN session request object serialized by Norito JSON before inner canonical verification."
                },
                "canonical_auth": (vpn_canonical_auth_schema()),
                "accept": { "type": "string" }
            },
            "required": ["body", "canonical_auth"]
        }),
    )
}
fn iroha_vpn_sessions_get_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.vpn.sessions.get".to_owned(),
        "Fetch a Sora VPN session with `canonical_auth` signed for the exact inner GET path; outer MCP authentication is never reused for the inner target."
            .to_owned(),
        manual_tool_effect_from_name("iroha.vpn.sessions.get"),
        Method::GET,
        "/v1/vpn/sessions/{session_id}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "session_id": { "type": "string", "pattern": "^[0-9a-f]{32}$" },
                "canonical_auth": (vpn_canonical_auth_schema()),
                "accept": { "type": "string" }
            },
            "required": ["session_id", "canonical_auth"],
            "description": "Provide the exact `session_id` plus a proof signed for the resolved inner path."
        }),
    )
}
fn iroha_vpn_receipts_submit_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.vpn.receipts.submit".to_owned(),
        "Submit a relay receipt plus client usage voucher for Sora VPN XOR settlement. `canonical_auth` must be signed for POST /v1/vpn/receipts and the exact Norito JSON serialization of `body`; outer MCP authentication is never reused for the inner target."
            .to_owned(),
        manual_tool_effect_from_name("iroha.vpn.receipts.submit"),
        Method::POST,
        "/v1/vpn/receipts".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "x-iroha-mcp-strict-body": true,
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["relay_receipt_hex", "client_voucher_hex"],
                    "properties": {
                        "relay_receipt_hex": { "type": "string" },
                        "client_voucher_hex": { "type": "string" },
                        "lease_id_hex": { "type": "string" }
                    },
                    "description": "Exact VPN receipt settlement object serialized by Norito JSON before inner canonical verification. Successful responses include the optional `settle_lease_instruction` native `SettleVpnLease` skeleton when operator signing/submission is required."
                },
                "canonical_auth": (vpn_canonical_auth_schema()),
                "accept": { "type": "string" }
            },
            "required": ["body", "canonical_auth"]
        }),
    )
}
fn iroha_vpn_receipts_list_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.vpn.receipts.list".to_owned(),
        "List canonical Sora VPN receipts with `canonical_auth` signed for GET /v1/vpn/receipts; outer MCP authentication is never reused for the inner target."
            .to_owned(),
        manual_tool_effect_from_name("iroha.vpn.receipts.list"),
        Method::GET,
        "/v1/vpn/receipts".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "canonical_auth": (vpn_canonical_auth_schema()),
                "accept": { "type": "string" }
            },
            "required": ["canonical_auth"]
        }),
    )
}
fn iroha_health_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.health",
        "Get node liveness status (`/health`).",
        "/health",
    )
}
fn iroha_parameters_get_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.parameters.get",
        "Get node parameters snapshot (`/v1/parameters`).",
        "/v1/parameters",
    )
}
fn iroha_node_capabilities_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.node.capabilities",
        "Get node capability metadata (`/v1/node/capabilities`).",
        "/v1/node/capabilities",
    )
}
fn iroha_node_query_projection_checkpoint_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.node.query_projection_checkpoint",
        "Fetch the latest query projection checkpoint descriptor (`/v1/node/query/projection/checkpoint`).",
        "/v1/node/query/projection/checkpoint",
    )
}
fn iroha_da_ingest_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.ingest",
        "Ingest DA payload (`/v1/da/ingest`); the request payload is the required `body` object.",
        "/v1/da/ingest",
        "Raw DA ingest request payload.",
    )
}
fn iroha_da_proof_policies_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.da.proof_policies",
        "Fetch DA proof policies (`/v1/da/proof-policies`).",
        "/v1/da/proof-policies",
    )
}
fn iroha_da_commitments_list_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.commitments.list",
        "List DA commitments (`/v1/da/commitments`); the request payload is the required `body` object.",
        "/v1/da/commitments",
        "Raw DA commitment list request payload.",
    )
}
fn iroha_da_commitments_prove_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.commitments.prove",
        "Compute a DA commitment Merkle proof (`/v1/da/commitments/prove`); the request payload is the required `body` object.",
        "/v1/da/commitments/prove",
        "Raw DA commitment proof request payload.",
    )
}
fn iroha_da_commitments_verify_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.commitments.verify",
        "Verify DA commitment payload (`/v1/da/commitments/verify`); the request payload is the required `body` object.",
        "/v1/da/commitments/verify",
        "Raw DA commitment verification request payload.",
    )
}
fn iroha_da_pin_intents_list_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.pin_intents.list",
        "List DA pin intents (`/v1/da/pin-intents`); the request payload is the required `body` object.",
        "/v1/da/pin-intents",
        "Raw DA pin-intents listing request payload.",
    )
}
fn iroha_da_pin_intents_prove_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.pin_intents.prove",
        "Build a DA pin-intent Merkle membership proof bound to the exact committed block bundle (`/v1/da/pin-intents/prove`); the request payload is the required `body` object.",
        "/v1/da/pin-intents/prove",
        "Raw DA pin-intents prove request payload.",
    )
}
fn iroha_da_pin_intents_verify_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.da.pin_intents.verify",
        "Verify a DA pin-intent Merkle membership proof against its committed block header (`/v1/da/pin-intents/verify`); the request payload is the required `body` object.",
        "/v1/da/pin-intents/verify",
        "Raw DA pin-intents verification request payload.",
    )
}
fn iroha_runtime_abi_active_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.runtime.abi.active",
        "Fetch the active runtime ABI version (`/v1/runtime/abi/active`).",
        "/v1/runtime/abi/active",
    )
}
fn iroha_runtime_abi_hash_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.runtime.abi.hash",
        "Fetch active runtime ABI hash (`/v1/runtime/abi/hash`).",
        "/v1/runtime/abi/hash",
    )
}
fn iroha_runtime_metrics_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.runtime.metrics",
        "Fetch runtime metrics (`/v1/runtime/metrics`).",
        "/v1/runtime/metrics",
    )
}
fn iroha_runtime_upgrades_list_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.runtime.upgrades.list",
        "List runtime upgrades (`/v1/runtime/upgrades`).",
        "/v1/runtime/upgrades",
    )
}
fn iroha_runtime_upgrades_propose_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.runtime.upgrades.propose",
        "Propose a runtime upgrade (`/v1/runtime/upgrades/propose`); the request payload is the required `body` object.",
        "/v1/runtime/upgrades/propose",
        "Raw runtime-upgrade proposal payload.",
    )
}
fn iroha_proofs_query_tool() -> ToolSpec {
    simple_manual_raw_body_post_tool(
        "iroha.proofs.query",
        "Query proof records (`/v1/proofs/query`); the request payload is the required `body` object.",
        "/v1/proofs/query",
        "Raw proof query payload.",
    )
}
fn governance_proposal_id_v1_schema(description: &str) -> Value {
    norito::json!({
        "type": "string",
        "minLength": 64,
        "maxLength": 64,
        "pattern": GOVERNANCE_PROPOSAL_ID_V1_PATTERN,
        "description": description
    })
}
/// Build a governance POST tool whose `body` requires exactly the listed fields.
fn iroha_gov_post_tool_with_fields(
    name: &str,
    description: &str,
    path_template: &str,
    fields: &[(&str, Value)],
) -> ToolSpec {
    let mut body_properties = Map::new();
    for (field, schema) in fields {
        body_properties.insert((*field).to_owned(), schema.clone());
    }
    let required_fields = fields
        .iter()
        .map(|(field, _)| Value::String((*field).to_owned()))
        .collect::<Vec<_>>();
    let mut tool = iroha_gov_post_tool(name, description, path_template);
    let body = tool
        .input_schema
        .as_object_mut()
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("body"))
        .and_then(Value::as_object_mut)
        .expect("governance MCP body schema is an object");
    body.insert("properties".to_owned(), Value::Object(body_properties));
    if !required_fields.is_empty() {
        body.insert("required".to_owned(), Value::Array(required_fields));
    }
    tool
}
fn iroha_gov_post_tool(name: &str, description: &str, path_template: &str) -> ToolSpec {
    let input_schema = norito::json!({
        "type": "object",
        "required": ["body"],
        "properties": {
            "body": {
                "type": "object",
                "additionalProperties": true,
                "properties": {},
                "description": "Raw governance request payload."
            },
            "headers": {
                "type": "object",
                "additionalProperties": { "type": "string" }
            },
            "accept": { "type": "string" }
        }
    });
    ToolSpec::route(
        name.to_owned(),
        description.to_owned(),
        manual_tool_effect_from_name(name),
        Method::POST,
        path_template.to_owned(),
        input_schema,
    )
}
fn iroha_gov_proposals_deploy_contract_tool() -> ToolSpec {
    iroha_gov_post_tool(
        "iroha.gov.proposals.deploy_contract",
        "Propose contract deployment (`/v1/gov/proposals/deploy-contract`); the request payload is the required `body` object.",
        "/v1/gov/proposals/deploy-contract",
    )
}
fn iroha_gov_parliament_attempt_draft_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.attempts.draft".to_owned(),
        "Draft one canonical attempt-based Parliament proposal for local signing. The canonical account proof must bind the exact V1 JSON body.".to_owned(),
        ToolEffect::BuildInstruction,
        Method::POST,
        "/v1/gov/parliament/attempts/draft".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["body"],
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["version", "proposal", "attempt_sequence"],
                    "properties": {
                        "version": { "type": "integer", "const": 1 },
                        "proposal": { "type": "object" },
                        "attempt_sequence": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": (u64::from(MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1))
                        }
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string", "const": "application/json" }
            }
        }),
    )
}
fn iroha_gov_parliament_attempt_get_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.attempts.get".to_owned(),
        "Read one complete committed Parliament attempt by its exact canonical identifier."
            .to_owned(),
        ToolEffect::Read,
        Method::GET,
        "/v1/gov/parliament/attempts/{governance_attempt_id}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["governance_attempt_id"],
                    "properties": {
                        "governance_attempt_id": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$"
                        }
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string", "const": "application/json" }
            }
        }),
    )
}
fn iroha_gov_parliament_tle_release_context_get_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.ballots.tle_release_context.get".to_owned(),
        "Read one Core-authorized bounded public TLE release context for a Parliament ballot already in Opening. No ballot corpora, shares, secrets, or individual openings are returned."
            .to_owned(),
        ToolEffect::Read,
        Method::GET,
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["ballot_attempt_id"],
                    "properties": {
                        "ballot_attempt_id": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$"
                        }
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string", "const": "application/json" }
            }
        }),
    )
}
fn iroha_gov_parliament_timed_ovn_casting_context_get_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.ballots.timed_ovn_casting_context.get".to_owned(),
        "Inspect one node-local Core-replay-validated public timed-OVN casting context. This unauthenticated-by-consensus view is for diagnostics only and MUST NOT be used as native-wallet or seed-unsealing input."
            .to_owned(),
        ToolEffect::Read,
        Method::GET,
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["ballot_attempt_id"],
                    "properties": {
                        "ballot_attempt_id": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$"
                        }
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string", "const": "application/json" }
            }
        }),
    )
}
fn iroha_gov_parliament_timed_ovn_casting_proof_get_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.ballots.timed_ovn_casting_proof.get".to_owned(),
        format!(
            "Transport one bounded consensus-authenticated Parliament casting-proof page as canonical Norito (`{PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1}`). The MCP response body is base64 canonical Norito, not a verified wallet context: native code MUST independently pin the network id and exact checkpoint context, verify every finality proof and membership witness, and replay the archive before accessing seed material."
        ),
        manual_tool_effect_from_name("iroha.gov.parliament.ballots.timed_ovn_casting_proof.get"),
        Method::POST,
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path", "trusted_checkpoint_height"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["ballot_attempt_id"],
                    "properties": {
                        "ballot_attempt_id": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$"
                        }
                    }
                },
                "trusted_checkpoint_height": {
                    "type": "integer",
                    "format": "uint64",
                    "minimum": 1,
                    "description": "Height of the caller's externally pinned finality checkpoint; the exact trusted context id stays local to the native verifier."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Canonical account authentication for the exact POST target and canonical Norito request bytes."
                }
            }
        }),
    )
}
fn iroha_gov_parliament_tle_partial_release_create_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.ballots.tle_partial_release.create".to_owned(),
        "Request this node's Core-authorized proof-carrying TLE partial release for one Parliament ballot in Opening. The request has no body and returns no secret-share material."
            .to_owned(),
        ToolEffect::Write,
        Method::POST,
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["ballot_attempt_id"],
                    "properties": {
                        "ballot_attempt_id": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$"
                        }
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string", "const": "application/json" }
            }
        }),
    )
}
fn iroha_gov_parliament_transition_draft_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.gov.parliament.transitions.draft".to_owned(),
        "Draft one exact closed Parliament lifecycle transition for local signing. Consensus rechecks authority, state, phase, proof, and roster bindings.".to_owned(),
        ToolEffect::BuildInstruction,
        Method::POST,
        "/v1/gov/parliament/transitions/draft".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["body"],
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["version", "governance_attempt_id", "transition"],
                    "properties": {
                        "version": { "type": "integer", "const": 1 },
                        "governance_attempt_id": {
                            "type": "string",
                            "minLength": 64,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$"
                        },
                        "transition": { "type": "object" }
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string", "const": "application/json" }
            }
        }),
    )
}
fn iroha_gov_proposals_get_tool() -> ToolSpec {
    let proposal_id_schema = governance_proposal_id_v1_schema(
        "Exact 64-character lowercase hexadecimal governance proposal id.",
    );
    ToolSpec::route(
        "iroha.gov.proposals.get".to_owned(),
        "Fetch governance proposal detail by canonical `path.id` (`/v1/gov/proposals/{id}`)."
            .to_owned(),
        manual_tool_effect_from_name("iroha.gov.proposals.get"),
        Method::GET,
        "/v1/gov/proposals/{id}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id"],
                    "properties": {
                        "id": proposal_id_schema
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_gov_locks_get_tool() -> ToolSpec {
    let referendum_id_schema =
        governance_selector_v1_schema("Canonical first-release governance referendum selector.");
    ToolSpec::route(
        "iroha.gov.locks.get".to_owned(),
        "Fetch governance lock records by canonical `path.rid` (`/v1/gov/locks/{rid}`).".to_owned(),
        manual_tool_effect_from_name("iroha.gov.locks.get"),
        Method::GET,
        "/v1/gov/locks/{rid}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["rid"],
                    "properties": {
                        "rid": referendum_id_schema
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_gov_referenda_get_tool() -> ToolSpec {
    let referendum_id_schema =
        governance_selector_v1_schema("Canonical first-release governance referendum selector.");
    ToolSpec::route(
        "iroha.gov.referenda.get".to_owned(),
        "Fetch governance referendum detail by canonical `path.id` (`/v1/gov/referenda/{id}`)."
            .to_owned(),
        manual_tool_effect_from_name("iroha.gov.referenda.get"),
        Method::GET,
        "/v1/gov/referenda/{id}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id"],
                    "properties": {
                        "id": referendum_id_schema
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_gov_tally_get_tool() -> ToolSpec {
    let tally_id_schema =
        governance_selector_v1_schema("Canonical first-release governance tally selector.");
    ToolSpec::route(
        "iroha.gov.tally.get".to_owned(),
        "Fetch governance tally detail by canonical `path.id` (`/v1/gov/tally/{id}`).".to_owned(),
        manual_tool_effect_from_name("iroha.gov.tally.get"),
        Method::GET,
        "/v1/gov/tally/{id}".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id"],
                    "properties": {
                        "id": tally_id_schema
                    }
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_gov_protected_namespaces_list_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.gov.protected_namespaces.list",
        "List protected governance namespaces (`/v1/gov/protected-namespaces`).",
        "/v1/gov/protected-namespaces",
    )
}
fn iroha_gov_protected_namespaces_update_tool() -> ToolSpec {
    iroha_gov_post_tool(
        "iroha.gov.protected_namespaces.update",
        "Update protected governance namespaces (`/v1/gov/protected-namespaces`); the request payload is the required `body` object.",
        "/v1/gov/protected-namespaces",
    )
}
fn iroha_gov_unlocks_stats_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.gov.unlocks.stats",
        "Fetch governance unlock statistics (`/v1/gov/unlocks/stats`).",
        "/v1/gov/unlocks/stats",
    )
}
fn iroha_gov_citizens_count_tool() -> ToolSpec {
    simple_manual_get_tool(
        "iroha.gov.citizens.count",
        "Fetch exact governance citizenship registry count (`/v1/gov/citizens`).",
        "/v1/gov/citizens",
    )
}
fn iroha_contracts_post_tool(name: &str, description: &str, path_template: &str) -> ToolSpec {
    ToolSpec::route(
        name.to_owned(),
        description.to_owned(),
        manual_tool_effect_from_name(name),
        Method::POST,
        path_template.to_owned(),
        norito::json!({
            "type": "object",
            "required": ["body"],
            "properties": {
                "body": {
                    "type": "object",
                    "additionalProperties": true,
                    "description": "Raw request payload."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_contracts_call_tool() -> ToolSpec {
    iroha_contracts_post_tool(
        "iroha.contracts.call",
        "Call a deployed contract instance (`/v1/contracts/call`).",
        "/v1/contracts/call",
    )
}
fn iroha_transactions_query_tool() -> ToolSpec {
    collection_query_tool(
        "iroha.transactions.query",
        "Query committed transactions (`POST /v1/transactions/query`), newest first; intended for privileged operator and developer use. Fields: `entrypoint_hash`, `block_hash`, `authority`, `entrypoint_kind`, `block_height`, `block_index`, `timestamp_ms`, `result_ok`, `asset_ids`, `asset_definition_ids` and `metadata.<key>`; `block_height` bounds in the filter's top-level `and` also bound the scan. Example: {\"filter\": \"authority = 'sorau…' and block_height >= 1200\", \"limit\": 20}. The order is fixed (no `sort`, `include_total` or `aggregate`), and a page may hold fewer than `limit` rows, even none, while `next_cursor` is set: keep passing `next_cursor` as `cursor` until it is null.",
        "/v1/transactions/query",
        CollectionQueryShape::HistoryPost,
    )
}
fn iroha_musubi_v1_tools(spec: &Value) -> impl Iterator<Item = ToolSpec> + '_ {
    MUSUBI_V1_TOOL_DEFINITIONS
        .iter()
        .filter(|definition| {
            catalog_mcp_projection_decision(
                CATALOG_PROJECTION_GROUPS,
                &Method::POST,
                definition.path,
            ) == Some(true)
        })
        .map(|definition| {
            let request_body = spec
                .get("paths")
                .and_then(Value::as_object)
                .and_then(|paths| paths.get(definition.path))
                .and_then(Value::as_object)
                .and_then(|path| path.get("post"))
                .and_then(Value::as_object)
                .and_then(|operation| operation.get("requestBody"))
                .unwrap_or_else(|| {
                    panic!(
                        "Musubi V1 OpenAPI operation {} is missing its typed request body",
                        definition.path
                    )
                });
            let body_schema = build_request_body_schema(spec, request_body)
                .map(|schema| inline_openapi_schema(spec, &schema, 0))
                .unwrap_or_else(|| {
                    panic!(
                        "Musubi V1 OpenAPI operation {} has no JSON request schema",
                        definition.path
                    )
                });
            ToolSpec::route(
                definition.name.to_owned(),
                definition.description.to_owned(),
                definition.effect,
                Method::POST,
                definition.path.to_owned(),
                norito::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "x-iroha-mcp-strict-body": true,
                    "required": ["body", "headers"],
                    "properties": {
                        "body": (body_schema),
                        "headers": {
                            "type": "object",
                            "additionalProperties": { "type": "string" }
                        },
                        "accept": { "type": "string" }
                    }
                }),
            )
        })
}
fn iroha_subscriptions_cancel_tool() -> ToolSpec {
    iroha_subscription_draft_action_tool(
        "iroha.subscriptions.cancel",
        "Build an unsigned subscription cancellation draft for local signing.",
        "cancel",
    )
}
fn iroha_subscriptions_pause_tool() -> ToolSpec {
    iroha_subscription_draft_action_tool(
        "iroha.subscriptions.pause",
        "Build an unsigned subscription pause draft for local signing.",
        "pause",
    )
}
fn iroha_subscriptions_resume_tool() -> ToolSpec {
    iroha_subscription_draft_action_tool(
        "iroha.subscriptions.resume",
        "Build an unsigned subscription resume draft for local signing.",
        "resume",
    )
}
fn iroha_subscriptions_keep_tool() -> ToolSpec {
    iroha_subscription_draft_action_tool(
        "iroha.subscriptions.keep",
        "Build an unsigned subscription keep-active draft for local signing.",
        "keep",
    )
}
fn iroha_subscriptions_usage_tool() -> ToolSpec {
    iroha_subscription_action_tool(
        "iroha.subscriptions.usage",
        "Record subscription usage for canonical `path.subscription_id`.",
        "usage",
        "Optional usage payload. When omitted, `{}` is submitted.",
    )
}
fn iroha_subscriptions_charge_now_tool() -> ToolSpec {
    iroha_subscription_draft_action_tool(
        "iroha.subscriptions.charge_now",
        "Build an unsigned subscription charge-now draft for local signing.",
        "charge-now",
    )
}
fn iroha_subscription_draft_action_tool(name: &str, description: &str, action: &str) -> ToolSpec {
    let mut body_properties = Map::new();
    body_properties.insert(
        "authority".to_owned(),
        norito::json!({ "type": "string", "minLength": 1 }),
    );
    let mut body_required = vec![Value::String("authority".to_owned())];
    match action {
        "resume" | "charge-now" => {
            body_properties.insert(
                "charge_at_ms".to_owned(),
                norito::json!({ "type": "integer", "minimum": 0 }),
            );
        }
        "cancel" => {
            body_required.push(Value::String("cancel_mode".to_owned()));
            body_properties.insert(
                "cancel_mode".to_owned(),
                norito::json!({
                    "oneOf": [
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["mode", "value"],
                            "properties": {
                                "mode": { "const": "immediate" },
                                "value": { "type": "null" }
                            }
                        },
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["mode", "value"],
                            "properties": {
                                "mode": { "const": "period_end" },
                                "value": { "type": "null" }
                            }
                        }
                    ]
                }),
            );
        }
        "pause" | "keep" => {}
        _ => unreachable!("subscription draft action tool uses a closed action set"),
    }
    ToolSpec::route(
        name.to_owned(),
        description.to_owned(),
        manual_tool_effect_from_name(name),
        Method::POST,
        format!("/v1/subscriptions/{{subscription_id}}/{action}"),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["subscription_id", "body"],
            "properties": {
                "subscription_id": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Exact subscription NFT identifier."
                },
                "body": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": body_required,
                    "properties": body_properties,
                    "description": "Exact first-release subscription action draft request. Private keys are forbidden."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_subscription_action_tool(
    name: &str,
    description: &str,
    action: &str,
    body_description: &str,
) -> ToolSpec {
    ToolSpec::route(
        name.to_owned(),
        description.to_owned(),
        manual_tool_effect_from_name(name),
        Method::POST,
        format!("/v1/subscriptions/{{subscription_id}}/{action}"),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["subscription_id"],
                    "properties": {
                        "subscription_id": { "type": "string" }
                    }
                },
                "body": {
                    "type": "object",
                    "additionalProperties": true,
                    "description": body_description
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_nfts_chain_list_tool() -> ToolSpec {
    collection_query_tool(
        "iroha.nfts.chain.list",
        "List NFTs from chain state (`GET /v1/nfts`). Fields: `id`, `owned_by` (sortable) and `metadata.<key>` (the NFT content); default order `id`. Example: {\"filter\": \"owned_by = 'sorau…'\", \"limit\": 20}. Each page is {items, next_cursor}: pass `next_cursor` as `cursor` until it is null.",
        "/v1/nfts",
        CollectionQueryShape::Get,
    )
}
fn iroha_rwas_chain_list_tool() -> ToolSpec {
    collection_query_tool(
        "iroha.rwas.chain.list",
        "List RWA lots from chain state (`GET /v1/rwas`). Fields: `id`, `owned_by`, `primary_reference`, `status`, `quantity` (sortable), `is_frozen` and `metadata.<key>`; default order `id`. Example: {\"filter\": \"quantity > 0 and is_frozen = false\", \"sort\": \"-quantity\"}. Each page is {items, next_cursor}: pass `next_cursor` as `cursor` until it is null.",
        "/v1/rwas",
        CollectionQueryShape::Get,
    )
}
include!("mcp/iso20022_tools.rs");
fn iroha_queries_submit_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.queries.submit".to_owned(),
        "Submit a versioned SignedQuery encoded as canonical Norito bytes in `body_base64`."
            .to_owned(),
        manual_tool_effect_from_name("iroha.queries.submit"),
        Method::POST,
        iroha_torii_shared::route_catalog::pipeline::QUERY
            .path()
            .to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["body_base64"],
            "properties": {
                "body_base64": {
                    "type": "string",
                    "description": "Base64/base64url encoded versioned SignedQuery bytes."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_transactions_prepare_tool() -> ToolSpec {
    ToolSpec::in_process(
        InProcessTool::TransactionsPrepare,
        "Validate and freeze one already-built canonical unsigned TransactionPayload for external signing. This pure in-process Torii capability does not quote or rewrite fees, simulate state, sign, submit, or make a nested network request.".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["transaction_payload_base64"],
            "properties": {
                "transaction_payload_base64": {
                    "type": "string",
                    "minLength": 4,
                    "pattern": (CANONICAL_PADDED_BASE64_PATTERN),
                    "description": "Canonical padded standard-Base64 bytes emitted by TransactionBuilder::encode_payload."
                }
            }
        }),
    )
}
fn iroha_transactions_inspect_tool() -> ToolSpec {
    ToolSpec::in_process(
        InProcessTool::TransactionsInspect,
        "Structurally inspect exactly one canonical unsigned TransactionPayload or fixed-V1 SignedTransaction wire inside Torii. Signed envelopes receive canonical signature verification, but this pure operation does not perform state admission, fee quoting, execution, simulation, signing, submission, or a nested network request.".to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "oneOf": [
                {
                    "required": ["transaction_payload_base64"],
                    "not": { "required": ["signed_transaction_base64"] }
                },
                {
                    "required": ["signed_transaction_base64"],
                    "not": { "required": ["transaction_payload_base64"] }
                }
            ],
            "properties": {
                "transaction_payload_base64": {
                    "type": "string",
                    "minLength": 4,
                    "pattern": (CANONICAL_PADDED_BASE64_PATTERN),
                    "description": "Canonical padded standard-Base64 bytes emitted by TransactionBuilder::encode_payload."
                },
                "signed_transaction_base64": {
                    "type": "string",
                    "minLength": 4,
                    "pattern": (CANONICAL_PADDED_BASE64_PATTERN),
                    "description": "Canonical padded standard-Base64 fixed-V1 SignedTransaction wire bytes."
                }
            }
        }),
    )
}
fn iroha_transactions_submit_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.transactions.submit".to_owned(),
        "Submit a versioned SignedTransaction encoded as canonical Norito bytes in `body_base64`."
            .to_owned(),
        manual_tool_effect_from_name("iroha.transactions.submit"),
        Method::POST,
        iroha_torii_shared::route_catalog::pipeline::TRANSACTION
            .path()
            .to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["body_base64"],
            "properties": {
                "body_base64": {
                    "type": "string",
                    "description": "Base64/base64url encoded versioned SignedTransaction bytes."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
fn iroha_transactions_submit_and_wait_tool() -> ToolSpec {
    ToolSpec::route(
        "iroha.transactions.submit_and_wait".to_owned(),
        "Submit a versioned SignedTransaction from canonical `body_base64` bytes and poll exact global pipeline status until state-resolved Applied; state-resolved Rejected and Expired fail. Status polling decodes only exact HTTP 200 payloads, treats only HTTP 404 as pending, and rejects every other HTTP status. The Applied result has exactly `status`, `hash`, `terminal_kind`, `attempts`, `elapsed_ms`, optional `submit`, and `final`.".to_owned(),
        manual_tool_effect_from_name("iroha.transactions.submit_and_wait"),
        Method::POST,
        iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path().to_owned(),
        norito::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["body_base64"],
            "properties": {
                "body_base64": {
                    "type": "string",
                    "description": "Base64/base64url encoded versioned SignedTransaction bytes."
                },
                "hash": {
                    "type": "string",
                    "minLength": 64,
                    "maxLength": 64,
                    "pattern": "^[0-9a-f]{63}[13579bdf]$",
                    "description": "Optional exact canonical Iroha transaction hash; if omitted the tool decodes the exact submission response."
                },
                "timeout_ms": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 600000,
                    "description": "Polling timeout in milliseconds (default 30000, max 600000)."
                },
                "poll_interval_ms": {
                    "type": "integer",
                    "minimum": 50,
                    "description": "Polling interval in milliseconds (default 500, minimum 50)."
                },
                "status_accept": {
                    "type": "string",
                    "description": "Optional Accept header for status polling calls (defaults to application/json)."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        }),
    )
}
/// Build the HTTP status + JSON-RPC error payload for oversized requests.
pub(crate) fn oversized_payload_response(max_request_bytes: usize) -> (StatusCode, Value) {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        jsonrpc_error_response(
            None,
            JSONRPC_INVALID_REQUEST,
            "mcp request body exceeds configured size limit",
            Some(norito::json!({
                "error_code": "request_payload_too_large",
                "max_request_bytes": max_request_bytes
            })),
        ),
    )
}
pub(crate) fn invalid_json_payload(err: &json::Error) -> Value {
    let mut msg = String::from("invalid json payload: ");
    let _ = write!(msg, "{err}");
    jsonrpc_error_response(None, JSONRPC_PARSE_ERROR, &msg, None)
}
#[cfg(all(test, feature = "app_api"))]
mod tests {
    include!("mcp/catalog_and_policy_tests.rs");
    include!("mcp/dispatch_and_argument_tests.rs");
    include!("mcp/iso20022_operator_auth_tests.rs");
    include!("mcp/body_builder_tests.rs");
    include!("mcp/bounds_tests.rs");

    #[test]
    fn jsonrpc_numeric_ids_reject_u128_above_u64() {
        let largest_supported = Value::Number(json::native::Number::U128(u64::MAX.into()));
        assert!(is_jsonrpc_id(&largest_supported));
        assert_eq!(
            ExactJsonRpcId::from_value(&largest_supported),
            Some(ExactJsonRpcId {
                kind: ExactJsonRpcIdKind::U64(u64::MAX),
            })
        );

        let too_large = Value::Number(json::native::Number::U128(u128::from(u64::MAX) + 1));
        assert!(!is_jsonrpc_id(&too_large));
        assert_eq!(ExactJsonRpcId::from_value(&too_large), None);
    }

    #[test]
    fn parliament_attempt_draft_tool_caps_attempt_sequence_at_retry_limit() {
        let tool = iroha_gov_parliament_attempt_draft_tool();
        let properties = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("attempt-draft tool properties");
        let body_properties = properties
            .get("body")
            .and_then(Value::as_object)
            .and_then(|body| body.get("properties"))
            .and_then(Value::as_object)
            .expect("attempt-draft body properties");
        assert_eq!(
            body_properties
                .get("attempt_sequence")
                .and_then(Value::as_object)
                .and_then(|sequence| sequence.get("maximum"))
                .and_then(Value::as_u64),
            Some(u64::from(MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1))
        );
    }

    #[test]
    fn simple_manual_get_tools_share_the_exact_read_contract() {
        let tools = [
            iroha_vpn_profile_tool(),
            iroha_health_tool(),
            iroha_parameters_get_tool(),
            iroha_node_capabilities_tool(),
            iroha_node_query_projection_checkpoint_tool(),
            iroha_da_proof_policies_tool(),
            iroha_runtime_abi_active_tool(),
            iroha_runtime_abi_hash_tool(),
            iroha_runtime_metrics_tool(),
            iroha_runtime_upgrades_list_tool(),
            iroha_gov_protected_namespaces_list_tool(),
            iroha_gov_unlocks_stats_tool(),
            iroha_gov_citizens_count_tool(),
        ];
        let audited_names = [
            "iroha.da.proof_policies",
            "iroha.gov.citizens.count",
            "iroha.gov.protected_namespaces.list",
            "iroha.gov.unlocks.stats",
            "iroha.health",
            "iroha.node.capabilities",
            "iroha.node.query_projection_checkpoint",
            "iroha.parameters.get",
            "iroha.runtime.abi.active",
            "iroha.runtime.abi.hash",
            "iroha.runtime.metrics",
            "iroha.runtime.upgrades.list",
            "iroha.vpn.profile",
        ];
        let expected_schema = norito::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "accept": { "type": "string" }
            }
        });

        assert_eq!(tools.len(), audited_names.len());
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<BTreeSet<_>>(),
            audited_names.into_iter().collect::<BTreeSet<_>>()
        );
        for tool in tools {
            assert!(is_audited_manual_read_tool_name(&tool.name));
            let (effect, method, path_template) = tool
                .route_backing()
                .expect("simple manual GET tool must be route-backed");
            assert_eq!(effect, manual_tool_effect_from_name(&tool.name));
            assert_eq!(method, &Method::GET);
            assert_eq!(tool.input_schema, expected_schema);
            assert!(!tool.name.is_empty());
            assert!(!tool.description.is_empty());
            assert!(path_template.starts_with('/'));
        }
    }

    #[test]
    fn simple_manual_raw_body_tools_share_the_exact_post_contract() {
        let tools = [
            iroha_da_ingest_tool(),
            iroha_da_commitments_list_tool(),
            iroha_da_commitments_prove_tool(),
            iroha_da_commitments_verify_tool(),
            iroha_da_pin_intents_list_tool(),
            iroha_da_pin_intents_prove_tool(),
            iroha_da_pin_intents_verify_tool(),
            iroha_runtime_upgrades_propose_tool(),
            iroha_proofs_query_tool(),
        ];

        assert_eq!(tools.len(), 9);
        for tool in tools {
            let (effect, method, _) = tool
                .route_backing()
                .expect("simple manual POST tool must be route-backed");
            assert_eq!(effect, manual_tool_effect_from_name(&tool.name));
            assert_eq!(method, &Method::POST);
            let schema = tool.input_schema.as_object().expect("input schema");
            // Flat top-level body shortcuts are retired: callers must pass `body`, and
            // the sanitized advertised schema closes the top level.
            assert_eq!(schema.get("additionalProperties"), None);
            assert_eq!(
                schema.get("required"),
                Some(&norito::json!(["body"])),
                "{} must require the raw `body` object",
                tool.name
            );
            assert_eq!(
                sanitize_tool_input_schema(&tool.input_schema)
                    .get("additionalProperties")
                    .and_then(Value::as_bool),
                Some(false)
            );
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .expect("input properties");
            let body = properties
                .get("body")
                .and_then(Value::as_object)
                .expect("body schema");
            assert_eq!(
                body.get("additionalProperties").and_then(Value::as_bool),
                Some(true)
            );
            assert!(
                body.get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|description| !description.is_empty())
            );
            assert!(properties.contains_key("headers"));
            assert!(properties.contains_key("accept"));
        }
    }

    #[test]
    fn transaction_prepare_and_inspect_store_in_process_backings() {
        let prepare = iroha_transactions_prepare_tool();
        assert!(matches!(
            prepare.backing(),
            ToolBacking::InProcess(InProcessTool::TransactionsPrepare)
        ));
        assert!(prepare.route_backing().is_none());

        let inspect = iroha_transactions_inspect_tool();
        assert!(matches!(
            inspect.backing(),
            ToolBacking::InProcess(InProcessTool::TransactionsInspect)
        ));
        assert!(inspect.route_backing().is_none());
    }

    #[test]
    fn vpn_canonical_auth_emits_ascii_account_headers() {
        let expected = AccountAddress::parse_encoded(TEST_ACCOUNT_I105, None)
            .expect("canonical I105 fixture")
            .canonical_hex()
            .expect("canonical account hex");
        for arguments in [
            norito::json!({
                "canonical_auth": {
                    "account": TEST_ACCOUNT_I105,
                    "signature": "AQ==",
                    "timestamp_ms": 1_u64,
                    "nonce": "nonce"
                }
            }),
            norito::json!({
                "canonical_auth": {
                    "account": TEST_ACCOUNT_I105,
                    "witness": (canonical_test_witness_header())
                }
            }),
        ] {
            let headers = vpn_canonical_auth_headers(arguments.as_object().expect("arguments"))
                .expect("canonical authentication headers");
            let account = headers
                .as_object()
                .and_then(|headers| headers.get(crate::HEADER_ACCOUNT))
                .and_then(Value::as_str)
                .expect("account header");
            assert_eq!(account, expected);
            assert!(account.is_ascii());
        }

        let alias_arguments = norito::json!({
            "canonical_auth": {
                "account": "operator@sora",
                "witness": (canonical_test_witness_header())
            }
        });
        let alias_headers =
            vpn_canonical_auth_headers(alias_arguments.as_object().expect("alias arguments"))
                .expect("ASCII alias authentication headers");
        assert_eq!(
            alias_headers
                .as_object()
                .and_then(|headers| headers.get(crate::HEADER_ACCOUNT))
                .and_then(Value::as_str),
            Some("operator@sora")
        );
    }

    #[test]
    fn vpn_canonical_auth_rejects_inexact_or_non_ascii_aliases() {
        for account in [" operator@sora", "Operator@sora", "operator alias", "账户"] {
            let arguments = norito::json!({
                "canonical_auth": {
                    "account": (account),
                    "witness": (canonical_test_witness_header())
                }
            });
            vpn_canonical_auth_headers(arguments.as_object().expect("arguments"))
                .expect_err("only exact printable ASCII aliases are supported");
        }
    }

    #[test]
    fn vpn_canonical_auth_rejects_noncanonical_wire_values() {
        for arguments in [
            norito::json!({
                "canonical_auth": {
                    "account": TEST_ACCOUNT_I105,
                    "signature": "AA==",
                    "timestamp_ms": 1_u64,
                    "nonce": "nonce"
                }
            }),
            norito::json!({
                "canonical_auth": {
                    "account": TEST_ACCOUNT_I105,
                    "signature": "not-base64",
                    "timestamp_ms": 1_u64,
                    "nonce": "nonce"
                }
            }),
            norito::json!({
                "canonical_auth": {
                    "account": TEST_ACCOUNT_I105,
                    "signature": "AQ==",
                    "timestamp_ms": 1_u64,
                    "nonce": "contains space"
                }
            }),
            norito::json!({
                "canonical_auth": {
                    "witness": "not-base64"
                }
            }),
        ] {
            vpn_canonical_auth_headers(arguments.as_object().expect("arguments"))
                .expect_err("noncanonical typed authentication must fail before dispatch");
        }
    }

    #[test]
    fn parliament_casting_proof_tool_builds_one_canonical_checkpoint_request() {
        let arguments = norito::json!({
            "path": {
                "ballot_attempt_id": "0101010101010101010101010101010101010101010101010101010101010101"
            },
            "trusted_checkpoint_height": 17_u64,
            "headers": {}
        });
        let arguments = arguments.as_object().expect("arguments");
        let request = parliament_timed_ovn_casting_proof_request(arguments)
            .expect("bounded casting-proof request");
        assert_eq!(
            request.version,
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1
        );
        assert_eq!(request.trusted_checkpoint_height, 17);
        let encoded = parliament_timed_ovn_casting_proof_request_bytes(arguments)
            .expect("framed casting-proof request");
        assert_eq!(
            hex::encode(&encoded),
            "4e5254300000adccf322a5fcf43040e20bea238f55f3000c00000000000000dfab61022cefc29f02020100081100000000000000"
        );
        assert_eq!(
            norito::decode_from_bytes::<ParliamentTimedOvnCastingProofRequestV1>(&encoded)
                .expect("canonical casting-proof request"),
            request
        );
    }

    #[test]
    fn parliament_casting_proof_tool_rejects_unpinned_or_ambiguous_requests() {
        for arguments in [
            norito::json!({
                "path": {
                    "ballot_attempt_id": "0101010101010101010101010101010101010101010101010101010101010101"
                },
                "trusted_checkpoint_height": 0_u64
            }),
            norito::json!({
                "path": {
                    "ballot_attempt_id": "0101010101010101010101010101010101010101010101010101010101010101"
                },
                "trusted_checkpoint_height": 41_u64,
                "network_id": "node-selected-network"
            }),
        ] {
            parliament_timed_ovn_casting_proof_request(arguments.as_object().expect("arguments"))
                .expect_err("untrusted or ambiguous checkpoint request must fail closed");
        }
        let tool = iroha_gov_parliament_timed_ovn_casting_proof_get_tool();
        let (_, method, _) = tool
            .route_backing()
            .expect("casting-proof tool must be route-backed");
        assert_eq!(method, &Method::POST);
        assert!(
            tool.description
                .contains("MUST independently pin the network id")
        );
        assert!(
            iroha_gov_parliament_timed_ovn_casting_context_get_tool()
                .description
                .contains("MUST NOT be used")
        );
    }
}

#[cfg(test)]
mod contract_artifact_route_tests {
    use super::*;

    #[test]
    fn embedded_manual_descriptors_fit_the_reviewed_bound_and_excess_is_rejected() {
        assert_eq!(
            parse_manual_static_tool_descriptors(MANUAL_STATIC_TOOL_ASSET).len(),
            MANUAL_STATIC_TOOL_ASSET_DESCRIPTOR_COUNT,
        );
        let oversized = vec![b' '; MANUAL_STATIC_TOOL_ASSET_MAX_BYTES + 1];
        assert!(
            std::panic::catch_unwind(|| parse_manual_static_tool_descriptors(&oversized)).is_err()
        );
    }
    #[test]
    fn artifact_tools_require_exact_full_width_scope() {
        let hash = hex::encode(iroha_crypto::Hash::new(b"MCP artifact").as_ref());
        let arguments = norito::json!({"path": {"dataspace_id": "18446744073709551615", "code_hash": (hash.clone())}});
        let arguments = arguments.as_object().unwrap();
        assert_eq!(
            contract_artifact_route(arguments, false).unwrap(),
            format!("/v1/contracts/artifacts/{}/{hash}", u64::MAX)
        );
        assert_eq!(
            contract_artifact_route(arguments, true).unwrap(),
            format!("/v1/contracts/artifacts/{}/{hash}/bytes", u64::MAX)
        );
        for dataspace in ["", "00", "18446744073709551616", "../0"] {
            let bad =
                norito::json!({"path": {"dataspace_id": dataspace, "code_hash": (hash.clone())}});
            assert!(contract_artifact_route(bad.as_object().unwrap(), false).is_err());
        }
        let missing = norito::json!({"path": {"code_hash": hash}});
        assert!(contract_artifact_route(missing.as_object().unwrap(), true).is_err());
    }
}

#[cfg(test)]
#[path = "mcp/compiled_catalog_tests.rs"]
mod compiled_catalog_tests;
