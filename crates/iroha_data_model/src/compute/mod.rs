//! Compute lane data model and pricing helpers.
//!
//! This module defines the request/receipt schema for SoraNet's paid compute
//! lane along with manifest metadata, sandbox guards, and metering helpers.
//! All types derive Norito serialization so manifests, calls, and receipts can
//! be persisted on-chain or shipped between Torii and SDKs deterministically.

use crate::nexus::UniversalAccountId;
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_crypto::{Hash, HashOf};
use iroha_model_base::name::Name;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
};

mod policy_json;
/// Payload codec expected by a compute route.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "codec", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeCodec")]
pub enum ComputeCodec {
    /// Norito-encoded JSON payload.
    NoritoJson,
    /// Norito-encoded binary payload.
    NoritoBinary,
    /// Standards-based JSON payload.
    ApplicationJson,
    /// Opaque binary payload.
    OctetStream,
}
/// Price weights used to turn metering data into chargeable compute units.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputePriceWeights")]
pub struct ComputePriceWeights {
    /// Number of cycles consumed per compute unit (ceil-divided).
    pub cycles_per_unit: NonZeroU64,
    /// Number of egress bytes per compute unit (ceil-divided).
    pub egress_bytes_per_unit: NonZeroU64,
    /// Human-readable unit label (e.g., "cu").
    pub unit_label: String,
}
impl ComputePriceWeights {
    /// Compute the chargeable units for a metering record using ceil-division.
    #[must_use]
    pub fn charge_units(&self, metering: &ComputeMetering) -> u64 {
        let cycles_units = ceil_div(metering.cycles, self.cycles_per_unit.get());
        let egress_units = ceil_div(metering.egress_bytes, self.egress_bytes_per_unit.get());
        cycles_units.saturating_add(egress_units)
    }
}
/// Multipliers applied to compute units based on execution hints and determinism.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputePriceAmplifiers")]
pub struct ComputePriceAmplifiers {
    /// Basis-point multiplier for GPU execution (`10_000` = 1.0x).
    pub gpu_bps: NonZeroU32,
    /// Basis-point multiplier for TEE execution (`10_000` = 1.0x).
    pub tee_bps: NonZeroU32,
    /// Basis-point multiplier applied when a call opts into best-effort determinism.
    pub best_effort_bps: NonZeroU32,
}
impl ComputePriceAmplifiers {
    /// Default GPU multiplier (1.3x).
    pub const DEFAULT_GPU_BPS: u32 = 13_000;
    /// Default TEE multiplier (1.5x).
    pub const DEFAULT_TEE_BPS: u32 = 15_000;
    /// Default best-effort multiplier (1.25x).
    pub const DEFAULT_BEST_EFFORT_BPS: u32 = 12_500;
    /// Apply the configured multipliers to a base unit count.
    #[must_use]
    pub fn apply(
        &self,
        base_units: u64,
        execution_class: ComputeExecutionClass,
        determinism: ComputeDeterminism,
    ) -> u64 {
        let class_bps = match execution_class {
            ComputeExecutionClass::Cpu => 10_000,
            ComputeExecutionClass::Gpu => self.gpu_bps.get(),
            ComputeExecutionClass::Tee => self.tee_bps.get(),
        };
        let mut units = scale_bps(base_units, class_bps);
        if matches!(determinism, ComputeDeterminism::BestEffort) {
            units = scale_bps(units, self.best_effort_bps.get());
        }
        units
    }
}
impl Default for ComputePriceAmplifiers {
    fn default() -> Self {
        Self {
            gpu_bps: NonZeroU32::new(Self::DEFAULT_GPU_BPS).expect("nonzero gpu bps"),
            tee_bps: NonZeroU32::new(Self::DEFAULT_TEE_BPS).expect("nonzero tee bps"),
            best_effort_bps: NonZeroU32::new(Self::DEFAULT_BEST_EFFORT_BPS)
                .expect("nonzero best-effort bps"),
        }
    }
}
/// Determinism guarantees requested by a compute route or call.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Default,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "determinism", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeDeterminism")]
pub enum ComputeDeterminism {
    /// Deterministic execution only (no non-deterministic syscalls or variable outputs).
    #[default]
    Strict,
    /// Best-effort execution that may rely on non-deterministic helpers.
    BestEffort,
}
/// Execution class requested for the route (affects scheduling and routing).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Default,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "class", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeExecutionClass")]
pub enum ComputeExecutionClass {
    /// CPU-only execution.
    #[default]
    Cpu,
    /// GPU-capable execution (deterministic fallbacks must exist).
    Gpu,
    /// Trusted execution environment (TEE) execution class.
    Tee,
}
/// Reference to a model or dataset stored in `SoraFS`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeModelRef")]
pub struct ComputeModelRef {
    /// Content hash of the `SoraFS` bundle backing the model/dataset.
    pub bundle_hash: Hash,
    /// Path inside the bundle for the model payload.
    pub path: String,
    /// Expected total size of the model (bytes).
    pub expected_bytes: NonZeroU64,
    /// Chunk size used when streaming the model from `SoraFS`.
    pub chunk_size_bytes: NonZeroU64,
}
impl ComputeModelRef {
    /// Validate that the model reference is internally consistent.
    ///
    /// # Errors
    /// Returns [`ComputeManifestError::InvalidModel`] when the chunk size exceeds the
    /// expected bytes or when the model path is empty.
    pub fn validate(&self) -> Result<(), ComputeManifestError> {
        if self.chunk_size_bytes > self.expected_bytes {
            return Err(ComputeManifestError::InvalidModel {
                id: None,
                reason: format!(
                    "chunk_size_bytes ({}) exceeds expected_bytes ({})",
                    self.chunk_size_bytes, self.expected_bytes
                ),
            });
        }
        if self.path.is_empty() {
            return Err(ComputeManifestError::InvalidModel {
                id: None,
                reason: "model path must not be empty".to_string(),
            });
        }
        Ok(())
    }
}
/// Limits applied to caller-supplied inputs for a compute route.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeInputLimits")]
pub struct ComputeInputLimits {
    /// Maximum inline payload size allowed for requests (bytes).
    pub max_inline_bytes: NonZeroU64,
    /// Maximum number of external chunks that may be fetched from `SoraFS`.
    pub max_chunks: NonZeroU32,
    /// Expected chunk size for streamed inputs (bytes).
    pub chunk_size_bytes: NonZeroU64,
}
impl ComputeInputLimits {
    /// Validate input limits against the owning route.
    ///
    /// # Errors
    /// Returns [`ComputeManifestError::InvalidInputLimits`] if `max_inline_bytes` exceeds the
    /// route's `max_request_bytes`.
    fn validate(&self, route: &ComputeRoute) -> Result<(), ComputeManifestError> {
        if self.max_inline_bytes > route.max_request_bytes {
            return Err(ComputeManifestError::InvalidInputLimits {
                id: Some(route.id.clone()),
                reason: format!(
                    "max_inline_bytes ({}) exceeds route max_request_bytes ({})",
                    self.max_inline_bytes, route.max_request_bytes
                ),
            });
        }
        Ok(())
    }
}
/// Fee split applied to compute charges (basis points, denominator = `10_000`).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeFeeSplit")]
pub struct ComputeFeeSplit {
    /// Portion of fees burned (bps).
    pub burn_bps: u16,
    /// Portion of fees paid to validators (bps).
    pub validators_bps: u16,
    /// Portion of fees paid to providers/executors (bps).
    pub providers_bps: u16,
}
impl ComputeFeeSplit {
    /// Basis points denominator for fee splits.
    pub const BPS_DENOMINATOR: u16 = 10_000;
    /// Sum of all fee buckets.
    #[must_use]
    pub const fn total_bps(&self) -> u16 {
        self.burn_bps
            .saturating_add(self.validators_bps)
            .saturating_add(self.providers_bps)
    }
}
/// Sponsor budget caps for subsidised compute calls.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeSponsorPolicy")]
pub struct ComputeSponsorPolicy {
    /// Maximum compute units a sponsor may cover per call.
    pub max_cu_per_call: NonZeroU64,
    /// Maximum compute units a sponsor may cover per day.
    pub max_daily_cu: NonZeroU64,
}
/// Risk classes applied to price families for governance-bound deltas.
///
/// JSON values and object keys use the exact variant names: `Low`, `Balanced`, and `High`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputePriceRiskClass")]
pub enum ComputePriceRiskClass {
    /// Low-risk price families (tight delta bounds).
    Low,
    /// Balanced/default price families.
    Balanced,
    /// High-risk price families with relaxed bounds.
    High,
}
/// Delta bounds (basis points) used to constrain governance price updates.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputePriceDeltaBounds")]
pub struct ComputePriceDeltaBounds {
    /// Maximum delta for `cycles_per_unit` vs baseline (bps).
    pub max_cycles_delta_bps: NonZeroU16,
    /// Maximum delta for `egress_bytes_per_unit` vs baseline (bps).
    pub max_egress_delta_bps: NonZeroU16,
}
/// Resource budget applied to a compute route/profile.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeResourceBudget")]
#[norito(deny_unknown_fields)]
pub struct ComputeResourceBudget {
    /// Maximum deterministic cycle budget allowed for a call.
    pub max_cycles: NonZeroU64,
    /// Maximum linear memory available to the sandbox (bytes).
    pub max_memory_bytes: NonZeroU64,
    /// Maximum IVM stack size allowed for the program (bytes).
    pub max_stack_bytes: NonZeroU64,
    /// Maximum combined IO budget (ingress + internal temp buffers) in bytes.
    pub max_io_bytes: NonZeroU64,
    /// Maximum response egress allowed for the route (bytes).
    pub max_egress_bytes: NonZeroU64,
    /// Whether GPU hints are allowed (deterministic fallbacks must exist).
    pub allow_gpu_hints: bool,
}
/// Deterministic randomness policy for compute calls, encoded as its exact variant name in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeRandomnessPolicy")]
pub enum ComputeRandomnessPolicy {
    /// Disallow randomness entirely.
    None,
    /// Seed deterministic randomness from the request hash.
    SeededFromRequest,
}
/// IVM storage policy, encoded as its exact variant name in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeStorageAccess")]
pub enum ComputeStorageAccess {
    /// Allow read-only `SoraFS` bundle access; writes are rejected.
    ReadOnly,
    /// Allow limited deterministic writes (e.g., logs), still sandboxed.
    ReadWrite,
}
/// IVM guardrails shared by compute manifests.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeSandboxRules")]
#[norito(deny_unknown_fields)]
pub struct ComputeSandboxRules {
    /// Deterministic randomness policy.
    pub randomness: ComputeRandomnessPolicy,
    /// Storage access policy.
    pub storage: ComputeStorageAccess,
    /// Whether non-deterministic syscalls should be rejected at admission.
    #[norito(default)]
    pub deny_nondeterministic_syscalls: bool,
    /// Whether GPU hints are allowed to influence routing.
    #[norito(default)]
    pub allow_gpu_hints: bool,
    /// Whether TEE hints are allowed to influence routing.
    #[norito(default)]
    pub allow_tee_hints: bool,
}
/// Authentication policy for a compute route, encoded as its exact variant name in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeAuthPolicy")]
pub enum ComputeAuthPolicy {
    /// Permit only public calls (no UAID binding).
    PublicOnly,
    /// Require authenticated callers with UAID/session material.
    AuthenticatedOnly,
    /// Permit both public and authenticated callers.
    Either,
}
/// Unique identifier for a compute route.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeRouteId")]
pub struct ComputeRouteId {
    /// Service namespace.
    pub service: Name,
    /// Method within the service.
    pub method: Name,
}
impl ComputeRouteId {
    /// Build a new route identifier.
    #[must_use]
    pub fn new(service: Name, method: Name) -> Self {
        Self { service, method }
    }
}
/// Route descriptor stored inside the compute manifest.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeRoute")]
pub struct ComputeRoute {
    /// Route identifier (service + method).
    pub id: ComputeRouteId,
    /// Kotodama entrypoint this route should call.
    pub entrypoint: String,
    /// Allowed payload codecs.
    #[norito(default)]
    pub codecs: Vec<ComputeCodec>,
    /// Maximum TTL permitted for calls (slots).
    pub ttl_slots: NonZeroU64,
    /// Maximum gas/cycle budget permitted for calls on this route.
    pub gas_budget: NonZeroU64,
    /// Maximum request payload size (bytes).
    pub max_request_bytes: NonZeroU64,
    /// Maximum response payload size (bytes).
    pub max_response_bytes: NonZeroU64,
    /// Determinism guarantee applied to this route.
    #[norito(default)]
    pub determinism: ComputeDeterminism,
    /// Execution class requested for scheduling/routing.
    #[norito(default)]
    pub execution_class: ComputeExecutionClass,
    /// Optional input limits for streamed `SoraFS` payloads.
    #[norito(default)]
    pub input_limits: Option<ComputeInputLimits>,
    /// Optional model/dataset reference stored in `SoraFS`.
    #[norito(default)]
    pub model: Option<ComputeModelRef>,
    /// Price family identifier for this route.
    pub price_family: Name,
    /// Resource profile required by the route.
    pub resource_profile: Name,
    /// Authentication policy enforced for this route.
    pub auth: ComputeAuthPolicy,
}
impl ComputeRoute {
    fn validate_shape(&self) -> Result<(), ComputeManifestError> {
        if let Some(limits) = &self.input_limits {
            limits.validate(self)?;
        }
        if let Some(model) = &self.model {
            let mut validated = model.validate();
            if let Err(ComputeManifestError::InvalidModel { ref mut id, .. }) = validated {
                *id = Some(self.id.clone());
            }
            validated?;
        }
        Ok(())
    }
}
/// Compute manifest binding services/methods to Kotodama entrypoints.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeManifest")]
pub struct ComputeManifest {
    /// Namespace protecting the routes under this manifest.
    pub namespace: Name,
    /// Manifest ABI version (frozen for compatibility).
    pub abi_version: u32,
    /// Sandbox guardrails applied to all routes.
    pub sandbox: ComputeSandboxRules,
    /// Route descriptors.
    #[norito(default)]
    pub routes: Vec<ComputeRoute>,
}
impl ComputeManifest {
    /// Current ABI version for the compute manifest.
    pub const ABI_VERSION: u32 = 1;
    /// Validate manifest consistency (duplicate routes, codec allowlists).
    ///
    /// # Errors
    /// Returns an error when duplicate routes exist, codec allowlists are empty, route
    /// validation fails, or the ABI version is unsupported.
    pub fn validate(&self) -> Result<(), ComputeManifestError> {
        let mut seen = std::collections::BTreeSet::new();
        for route in &self.routes {
            if !seen.insert(route.id.clone()) {
                return Err(ComputeManifestError::DuplicateRoute {
                    id: route.id.clone(),
                });
            }
            if route.codecs.is_empty() {
                return Err(ComputeManifestError::EmptyCodecAllowlist {
                    id: route.id.clone(),
                });
            }
            route.validate_shape()?;
        }
        if self.abi_version != Self::ABI_VERSION {
            return Err(ComputeManifestError::UnsupportedAbiVersion {
                provided: self.abi_version,
                expected: Self::ABI_VERSION,
            });
        }
        Ok(())
    }
    /// Find a route descriptor by identifier.
    #[must_use]
    pub fn route(&self, id: &ComputeRouteId) -> Option<&ComputeRoute> {
        self.routes.iter().find(|route| &route.id == id)
    }
    /// Validate a call against the manifest/route constraints.
    ///
    /// # Errors
    /// Returns a [`ComputeValidationError`] when the namespace, route, codec, execution class,
    /// determinism, or size limits violate manifest rules.
    pub fn validate_call(&self, call: &ComputeCall) -> Result<(), ComputeValidationError> {
        if self.namespace != call.namespace {
            return Err(ComputeValidationError::NamespaceMismatch {
                expected: self.namespace.clone(),
                provided: call.namespace.clone(),
            });
        }
        let Some(route) = self.route(&call.route) else {
            return Err(ComputeValidationError::UnknownRoute {
                route: call.route.clone(),
            });
        };
        route.validate_call(call)?;
        match call.execution_class {
            ComputeExecutionClass::Gpu if !self.sandbox.allow_gpu_hints => {
                return Err(ComputeValidationError::ExecutionClassNotAllowed {
                    provided: call.execution_class,
                });
            }
            ComputeExecutionClass::Tee if !self.sandbox.allow_tee_hints => {
                return Err(ComputeValidationError::ExecutionClassNotAllowed {
                    provided: call.execution_class,
                });
            }
            _ => {}
        }
        Ok(())
    }
}
/// Manifest validation errors.
#[derive(thiserror::Error, Debug, PartialEq, Eq, DeriveJsonSerialize, DeriveJsonDeserialize)]
#[norito(tag = "error", content = "data")]
pub enum ComputeManifestError {
    /// Duplicate route identifiers are not allowed.
    #[error("duplicate compute route {id:?}")]
    DuplicateRoute {
        /// Conflicting route identifier.
        id: ComputeRouteId,
    },
    /// Codec allowlist must not be empty.
    #[error("route {id:?} must declare at least one codec")]
    EmptyCodecAllowlist {
        /// Route missing codec allowlist.
        id: ComputeRouteId,
    },
    /// Input limits must be internally consistent.
    #[error("invalid input limits for route {id:?}: {reason}")]
    InvalidInputLimits {
        /// Route identifier, if available.
        #[norito(default, skip_serializing_if = "Option::is_none")]
        id: Option<ComputeRouteId>,
        /// Reason for invalid limits.
        reason: String,
    },
    /// Model reference must be internally consistent.
    #[error("invalid model reference for route {id:?}: {reason}")]
    InvalidModel {
        /// Route identifier, if available.
        #[norito(default, skip_serializing_if = "Option::is_none")]
        id: Option<ComputeRouteId>,
        /// Reason for invalid model reference.
        reason: String,
    },
    /// ABI version mismatch.
    #[error("compute manifest ABI version {provided} unsupported (expected {expected})")]
    UnsupportedAbiVersion {
        /// Provided ABI version.
        provided: u32,
        /// Supported ABI version.
        expected: u32,
    },
}
/// Canonical request envelope hashed to derive idempotency/replay keys.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeRequest")]
pub struct ComputeRequest {
    /// Deterministically ordered headers (case preserved).
    #[norito(default)]
    pub headers: BTreeMap<String, String>,
    /// Hash of the payload.
    pub payload_hash: Hash,
}
impl ComputeRequest {
    /// Compute the canonical hash of this request envelope.
    #[must_use]
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(self)
    }
}
/// Authentication payload for an authenticated compute call.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeAuthn")]
pub struct ComputeAuthn {
    /// Universal account identifier for the caller.
    pub uaid: UniversalAccountId,
    /// Optional session hash to distinguish client sessions.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub session_hash: Option<Hash>,
}
/// Authentication material provided by the caller.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "mode", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeAuthz")]
pub enum ComputeAuthz {
    /// Public call with no UAID/session binding.
    Public,
    /// Authenticated call bound to a UAID (optional session hash).
    Authenticated(ComputeAuthn),
}
/// Caller-supplied request to the compute gateway.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeCall")]
pub struct ComputeCall {
    /// Target namespace.
    pub namespace: Name,
    /// Target route identifier.
    pub route: ComputeRouteId,
    /// Payload codec requested by the caller.
    pub codec: ComputeCodec,
    /// TTL applied to the call (slots).
    pub ttl_slots: NonZeroU64,
    /// Gas limit for the call (must respect route budget).
    pub gas_limit: NonZeroU64,
    /// Maximum response size allowed for this call (bytes).
    pub max_response_bytes: NonZeroU64,
    /// Determinism guarantee requested by the caller.
    #[norito(default)]
    pub determinism: ComputeDeterminism,
    /// Requested execution class (CPU/GPU/TEE).
    #[norito(default)]
    pub execution_class: ComputeExecutionClass,
    /// Declared inline input size for streamed requests (bytes).
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub declared_input_bytes: Option<NonZeroU64>,
    /// Declared number of streamed chunks for `SoraFS` inputs.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub declared_input_chunks: Option<NonZeroU32>,
    /// Optional sponsor-provided compute unit budget for this call.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub sponsor_budget_cu: Option<NonZeroU64>,
    /// Price family to charge for this call.
    pub price_family: Name,
    /// Resource profile requested for execution.
    pub resource_profile: Name,
    /// Caller authentication.
    pub auth: ComputeAuthz,
    /// Canonical request envelope (headers + payload hash).
    pub request: ComputeRequest,
}
impl ComputeCall {
    /// Canonical hash of the request envelope (used for replay keys).
    #[must_use]
    pub fn request_hash(&self) -> HashOf<ComputeRequest> {
        self.request.hash()
    }
}
impl ComputeRoute {
    /// Validate a call against the route caps and allowlists.
    ///
    /// # Errors
    /// Returns a [`ComputeValidationError`] when the call violates TTL, gas, codec,
    /// determinism, execution class, size, or authentication constraints for the route.
    pub fn validate_call(&self, call: &ComputeCall) -> Result<(), ComputeValidationError> {
        if self.id != call.route {
            return Err(ComputeValidationError::UnknownRoute {
                route: call.route.clone(),
            });
        }
        if call.ttl_slots.get() > self.ttl_slots.get() {
            return Err(ComputeValidationError::TtlExceeded {
                provided: call.ttl_slots.get(),
                max: self.ttl_slots.get(),
            });
        }
        if call.gas_limit.get() > self.gas_budget.get() {
            return Err(ComputeValidationError::GasExceeded {
                provided: call.gas_limit.get(),
                max: self.gas_budget.get(),
            });
        }
        if call.max_response_bytes.get() > self.max_response_bytes.get() {
            return Err(ComputeValidationError::ResponseSizeExceeded {
                provided: call.max_response_bytes.get(),
                max: self.max_response_bytes.get(),
            });
        }
        if !self.codecs.contains(&call.codec) {
            return Err(ComputeValidationError::CodecNotAllowed {
                codec: call.codec,
                route: self.id.clone(),
            });
        }
        if matches!(
            (&self.determinism, &call.determinism),
            (ComputeDeterminism::Strict, ComputeDeterminism::BestEffort)
        ) {
            return Err(ComputeValidationError::DeterminismMismatch {
                expected: self.determinism,
                provided: call.determinism,
            });
        }
        if self.execution_class != call.execution_class {
            return Err(ComputeValidationError::ExecutionClassMismatch {
                expected: self.execution_class,
                provided: call.execution_class,
            });
        }
        if call.price_family != self.price_family {
            return Err(ComputeValidationError::PriceFamilyMismatch {
                expected: self.price_family.clone(),
                provided: call.price_family.clone(),
            });
        }
        if call.resource_profile != self.resource_profile {
            return Err(ComputeValidationError::ResourceProfileMismatch {
                expected: self.resource_profile.clone(),
                provided: call.resource_profile.clone(),
            });
        }
        match (&self.auth, &call.auth) {
            (ComputeAuthPolicy::PublicOnly, ComputeAuthz::Authenticated(_))
            | (ComputeAuthPolicy::AuthenticatedOnly, ComputeAuthz::Public) => {
                return Err(ComputeValidationError::AuthPolicyMismatch {
                    expected: self.auth,
                });
            }
            _ => {}
        }
        if let Some(limits) = &self.input_limits {
            if let Some(bytes) = call.declared_input_bytes
                && bytes > limits.max_inline_bytes
            {
                return Err(ComputeValidationError::InputBytesExceeded {
                    provided: bytes.get(),
                    max: limits.max_inline_bytes.get(),
                });
            }
            if let Some(chunks) = call.declared_input_chunks
                && chunks > limits.max_chunks
            {
                return Err(ComputeValidationError::InputChunksExceeded {
                    provided: chunks.get(),
                    max: limits.max_chunks.get(),
                });
            }
        }
        if let (Some(model), Some(bytes)) = (&self.model, call.declared_input_bytes)
            && bytes > model.expected_bytes
        {
            return Err(ComputeValidationError::ModelSizeExceeded {
                provided: bytes.get(),
                max: model.expected_bytes.get(),
            });
        }
        Ok(())
    }
}
/// Validation errors surfaced while checking a compute call against manifest caps.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ComputeValidationError {
    /// Route not present in the manifest.
    #[error("unknown compute route {route:?}")]
    UnknownRoute {
        /// Missing route identifier.
        route: ComputeRouteId,
    },
    /// Namespace mismatch between call and manifest.
    #[error("namespace mismatch: expected {expected:?}, got {provided:?}")]
    NamespaceMismatch {
        /// Expected namespace.
        expected: Name,
        /// Provided namespace.
        provided: Name,
    },
    /// TTL exceeds manifest cap.
    #[error("ttl {provided} exceeds route cap {max}")]
    TtlExceeded {
        /// TTL requested by the caller.
        provided: u64,
        /// TTL permitted by the route.
        max: u64,
    },
    /// Gas budget exceeds manifest cap.
    #[error("gas limit {provided} exceeds route cap {max}")]
    GasExceeded {
        /// Gas requested by the caller.
        provided: u64,
        /// Gas permitted by the route.
        max: u64,
    },
    /// Response size exceeds manifest cap.
    #[error("response cap {provided} exceeds route cap {max}")]
    ResponseSizeExceeded {
        /// Response size allowed by the caller.
        provided: u64,
        /// Response size permitted by the route.
        max: u64,
    },
    /// Codec not allowed for this route.
    #[error("codec {codec:?} not allowed on route {route:?}")]
    CodecNotAllowed {
        /// Unsupported codec.
        codec: ComputeCodec,
        /// Route identifier.
        route: ComputeRouteId,
    },
    /// Price family mismatch.
    #[error("price family {provided:?} does not match route {expected:?}")]
    PriceFamilyMismatch {
        /// Expected price family.
        expected: Name,
        /// Provided price family.
        provided: Name,
    },
    /// Resource profile mismatch.
    #[error("resource profile {provided:?} does not match route {expected:?}")]
    ResourceProfileMismatch {
        /// Expected resource profile.
        expected: Name,
        /// Provided resource profile.
        provided: Name,
    },
    /// Authentication policy violation.
    #[error("authentication policy mismatch; expected {expected:?}")]
    AuthPolicyMismatch {
        /// Route authentication policy.
        expected: ComputeAuthPolicy,
    },
    /// Determinism policy violation.
    #[error("determinism {provided:?} not allowed; expected {expected:?}")]
    DeterminismMismatch {
        /// Route determinism.
        expected: ComputeDeterminism,
        /// Determinism requested by caller.
        provided: ComputeDeterminism,
    },
    /// Execution class mismatch (CPU vs GPU vs TEE).
    #[error("execution class {provided:?} does not match route {expected:?}")]
    ExecutionClassMismatch {
        /// Expected execution class.
        expected: ComputeExecutionClass,
        /// Provided execution class.
        provided: ComputeExecutionClass,
    },
    /// Execution class not allowed by sandbox guardrails.
    #[error("execution class {provided:?} is not permitted by sandbox rules")]
    ExecutionClassNotAllowed {
        /// Provided execution class.
        provided: ComputeExecutionClass,
    },
    /// Inline input exceeds configured limit.
    #[error("inline input {provided} bytes exceeds limit {max}")]
    InputBytesExceeded {
        /// Input bytes declared by the caller.
        provided: u64,
        /// Maximum permitted inline input size.
        max: u64,
    },
    /// Chunk count exceeds configured limit.
    #[error("input chunks {provided} exceeds limit {max}")]
    InputChunksExceeded {
        /// Chunks requested by the caller.
        provided: u32,
        /// Maximum permitted chunks.
        max: u32,
    },
    /// Model-bound input exceeds the expected model size.
    #[error("input bytes {provided} exceed model expectation {max}")]
    ModelSizeExceeded {
        /// Declared bytes for the request/model binding.
        provided: u64,
        /// Maximum allowed bytes derived from the model.
        max: u64,
    },
}
/// Governance errors surfaced when applying price or sponsor updates.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ComputeGovernanceError {
    /// Price family not found.
    #[error("unknown price family {family:?}")]
    UnknownPriceFamily {
        /// Missing family identifier.
        family: Name,
    },
    /// Risk class mapping missing for a price family.
    #[error("price family {family:?} missing risk class mapping")]
    MissingRiskClass {
        /// Family without a risk class.
        family: Name,
    },
    /// Risk class bounds missing.
    #[error("missing price bounds for risk class {class:?}")]
    MissingRiskBounds {
        /// Risk class lacking bounds.
        class: ComputePriceRiskClass,
    },
    /// Unit label change is not permitted.
    #[error("unit label change not permitted for {family:?}: {from} -> {to}")]
    UnitLabelChanged {
        /// Price family being updated.
        family: Name,
        /// Previous label.
        from: String,
        /// New label.
        to: String,
    },
    /// Cycles delta exceeds allowed bound.
    #[error("cycles delta {delta_bps}bps exceeds bound {max_bps}bps for {family:?}")]
    CyclesDeltaExceeded {
        /// Price family being updated.
        family: Name,
        /// Observed delta in basis points.
        delta_bps: u128,
        /// Maximum permitted delta in basis points.
        max_bps: u16,
    },
    /// Egress delta exceeds allowed bound.
    #[error("egress delta {delta_bps}bps exceeds bound {max_bps}bps for {family:?}")]
    EgressDeltaExceeded {
        /// Price family being updated.
        family: Name,
        /// Observed delta in basis points.
        delta_bps: u128,
        /// Maximum permitted delta in basis points.
        max_bps: u16,
    },
    /// Fee split percentages do not sum to 10000 bps.
    #[error("fee split bps must sum to 10000 (got {total})")]
    InvalidFeeSplit {
        /// Total basis points provided.
        total: u16,
    },
    /// Sponsor caps exceeded for a request.
    #[error("sponsor cap exceeded: attempted {requested} cu (limit {limit})")]
    SponsorCapExceeded {
        /// Exact requested compute units, including accumulated daily usage on a daily refusal.
        requested: u128,
        /// Allowed compute units.
        limit: u64,
    },
}
/// Validate a proposed price family update against risk-class delta bounds.
///
/// # Errors
/// Returns a [`ComputeGovernanceError`] when a price family is unknown, lacks a
/// risk class/bounds entry, changes unit labels, or exceeds the configured delta bounds.
pub fn validate_price_update(
    baseline: &BTreeMap<Name, ComputePriceWeights>,
    proposed: &BTreeMap<Name, ComputePriceWeights>,
    risk_classes: &BTreeMap<Name, ComputePriceRiskClass>,
    bounds: &BTreeMap<ComputePriceRiskClass, ComputePriceDeltaBounds>,
) -> Result<(), ComputeGovernanceError> {
    for (family, updated) in proposed {
        let Some(current) = baseline.get(family) else {
            return Err(ComputeGovernanceError::UnknownPriceFamily {
                family: family.clone(),
            });
        };
        let class =
            risk_classes
                .get(family)
                .ok_or_else(|| ComputeGovernanceError::MissingRiskClass {
                    family: family.clone(),
                })?;
        let delta_bounds = bounds
            .get(class)
            .ok_or_else(|| ComputeGovernanceError::MissingRiskBounds { class: *class })?;
        validate_price_family_update(family, current, updated, delta_bounds)?;
    }
    Ok(())
}
/// Validate one price family against its original baseline and risk-class bounds.
///
/// The caller resolves the baseline and risk-class bounds before this check. Deltas
/// retain their full integer basis-point value, including values larger than the
/// configured `u16` bound domain; they are never truncated or saturated to that domain.
///
/// # Errors
/// Returns [`ComputeGovernanceError::UnitLabelChanged`] before any numeric refusal,
/// then [`ComputeGovernanceError::CyclesDeltaExceeded`] before
/// [`ComputeGovernanceError::EgressDeltaExceeded`] if both bounds are exceeded.
pub fn validate_price_family_update(
    family: &Name,
    current: &ComputePriceWeights,
    updated: &ComputePriceWeights,
    bounds: &ComputePriceDeltaBounds,
) -> Result<(), ComputeGovernanceError> {
    if current.unit_label != updated.unit_label {
        return Err(ComputeGovernanceError::UnitLabelChanged {
            family: family.clone(),
            from: current.unit_label.clone(),
            to: updated.unit_label.clone(),
        });
    }
    let cycles_delta = delta_bps(current.cycles_per_unit, updated.cycles_per_unit);
    if cycles_delta > u128::from(bounds.max_cycles_delta_bps.get()) {
        return Err(ComputeGovernanceError::CyclesDeltaExceeded {
            family: family.clone(),
            delta_bps: cycles_delta,
            max_bps: bounds.max_cycles_delta_bps.get(),
        });
    }
    let egress_delta = delta_bps(current.egress_bytes_per_unit, updated.egress_bytes_per_unit);
    if egress_delta > u128::from(bounds.max_egress_delta_bps.get()) {
        return Err(ComputeGovernanceError::EgressDeltaExceeded {
            family: family.clone(),
            delta_bps: egress_delta,
            max_bps: bounds.max_egress_delta_bps.get(),
        });
    }
    Ok(())
}
/// Enforce sponsor caps for a given request against accumulated usage.
///
/// # Errors
/// Returns [`ComputeGovernanceError::SponsorCapExceeded`] when the per-call or
/// per-day limits would be violated.
pub fn enforce_sponsor_policy(
    policy: &ComputeSponsorPolicy,
    requested_cu: u64,
    consumed_today: u64,
) -> Result<(), ComputeGovernanceError> {
    if requested_cu > policy.max_cu_per_call.get() {
        return Err(ComputeGovernanceError::SponsorCapExceeded {
            requested: u128::from(requested_cu),
            limit: policy.max_cu_per_call.get(),
        });
    }
    // The sum of two u64 values is below 2^65; widen before adding so even
    // a maximum configured daily cap cannot turn overflow into acceptance.
    #[cfg(not(all(test, sumeragi_model_mutation = "DM42")))]
    let running_total = u128::from(consumed_today) + u128::from(requested_cu);
    #[cfg(all(test, sumeragi_model_mutation = "DM42"))]
    let running_total = u128::from(consumed_today.saturating_add(requested_cu));
    if running_total > u128::from(policy.max_daily_cu.get()) {
        return Err(ComputeGovernanceError::SponsorCapExceeded {
            requested: running_total,
            limit: policy.max_daily_cu.get(),
        });
    }
    Ok(())
}
/// Summary of the call recorded in receipts.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeCallSummary")]
pub struct ComputeCallSummary {
    /// Target namespace.
    pub namespace: Name,
    /// Route identifier.
    pub route: ComputeRouteId,
    /// Canonical request hash.
    pub request_hash: HashOf<ComputeRequest>,
    /// Price family charged for this call.
    pub price_family: Name,
    /// Resource profile used for execution.
    pub resource_profile: Name,
    /// Payload codec used by the caller.
    pub codec: ComputeCodec,
    /// Determinism guarantee requested by the caller.
    pub determinism: ComputeDeterminism,
    /// Requested execution class (CPU/GPU/TEE).
    pub execution_class: ComputeExecutionClass,
    /// TTL applied to the call (slots).
    pub ttl_slots: NonZeroU64,
    /// Gas limit enforced for the call.
    pub gas_limit: NonZeroU64,
    /// Response cap applied during execution (bytes).
    pub max_response_bytes: NonZeroU64,
    /// Declared inline input size for streamed requests (bytes).
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub declared_input_bytes: Option<NonZeroU64>,
    /// Declared number of streamed chunks for `SoraFS` inputs.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub declared_input_chunks: Option<NonZeroU32>,
    /// Optional sponsor-provided compute unit budget for this call.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub sponsor_budget_cu: Option<NonZeroU64>,
    /// Caller authentication material.
    pub auth: ComputeAuthz,
}
impl From<&ComputeCall> for ComputeCallSummary {
    fn from(call: &ComputeCall) -> Self {
        Self {
            namespace: call.namespace.clone(),
            route: call.route.clone(),
            request_hash: call.request_hash(),
            price_family: call.price_family.clone(),
            resource_profile: call.resource_profile.clone(),
            codec: call.codec,
            determinism: call.determinism,
            execution_class: call.execution_class,
            ttl_slots: call.ttl_slots,
            gas_limit: call.gas_limit,
            max_response_bytes: call.max_response_bytes,
            declared_input_bytes: call.declared_input_bytes,
            declared_input_chunks: call.declared_input_chunks,
            sponsor_budget_cu: call.sponsor_budget_cu,
            auth: call.auth,
        }
    }
}
/// Metering data recorded after execution.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeMetering")]
pub struct ComputeMetering {
    /// Total cycles consumed.
    pub cycles: u64,
    /// Total ingress bytes (request + headers).
    pub ingress_bytes: u64,
    /// Total egress bytes (response + headers).
    pub egress_bytes: u64,
    /// Duration of execution in milliseconds.
    pub duration_ms: u64,
    /// Price family used to rate this call.
    pub price_family: Name,
    /// Chargeable compute units.
    pub charged_units: u64,
}
/// Outcome kind for a compute call.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "outcome", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::compute::ComputeOutcomeKind")]
pub enum ComputeOutcomeKind {
    /// Successful execution.
    Success,
    /// Execution timed out.
    Timeout,
    /// Execution exhausted linear memory.
    OutOfMemory,
    /// Execution exceeded gas budget.
    BudgetExhausted,
    /// Internal host or runtime error.
    InternalError,
}
/// Execution outcome plus optional response details.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeOutcome")]
pub struct ComputeOutcome {
    /// Outcome classification.
    pub kind: ComputeOutcomeKind,
    /// Optional response hash when available.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<Hash>,
    /// Optional response size in bytes.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    /// Optional response codec when a payload exists.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub response_codec: Option<ComputeCodec>,
}
/// Receipt emitted after a compute call executes.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::compute::ComputeReceipt")]
pub struct ComputeReceipt {
    /// Call summary.
    pub call: ComputeCallSummary,
    /// Metering data.
    pub metering: ComputeMetering,
    /// Outcome classification and response hashes.
    pub outcome: ComputeOutcome,
}
fn ceil_div(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_add(denominator.saturating_sub(1))
        .saturating_div(denominator)
}
fn scale_bps(value: u64, bps: u32) -> u64 {
    value
        .saturating_mul(u64::from(bps))
        .saturating_add(9_999)
        .saturating_div(10_000)
}
fn delta_bps(current: NonZeroU64, updated: NonZeroU64) -> u128 {
    let current = u128::from(current.get());
    let delta = u128::from(updated.get()).abs_diff(current);
    // A difference between two u64 values times 10,000 is below 2^78,
    // so the complete numerator fits u128 before the original floor division.
    let numerator = delta * 10_000;
    #[cfg(all(test, sumeragi_model_mutation = "DM43"))]
    let numerator = numerator.min(u128::from(u64::MAX));
    #[cfg(all(test, sumeragi_model_mutation = "DM41"))]
    {
        (numerator / current).min(u128::from(u16::MAX))
    }
    #[cfg(not(all(test, sumeragi_model_mutation = "DM41")))]
    {
        numerator / current
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::nexus::UniversalAccountId;
    use norito::json;
    use std::{
        num::{NonZeroU16, NonZeroU64},
        str::FromStr,
    };
    fn name(value: &str) -> Name {
        Name::from_str(value).expect("name")
    }
    fn sample_uaid() -> UniversalAccountId {
        UniversalAccountId::from_hash(Hash::new(b"uaid::compute"))
    }
    fn sample_request() -> ComputeRequest {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-request-id".to_string(), "req-42".to_string());
        ComputeRequest {
            headers,
            payload_hash: Hash::new(br#"{"pair":"XOR/USD"}"#),
        }
    }
    fn sample_route() -> ComputeRoute {
        ComputeRoute {
            id: ComputeRouteId::new(name("payments"), name("quote")),
            entrypoint: "quote_entry".to_string(),
            codecs: vec![ComputeCodec::NoritoJson, ComputeCodec::OctetStream],
            ttl_slots: NonZeroU64::new(64).unwrap(),
            gas_budget: NonZeroU64::new(5_000_000).unwrap(),
            max_request_bytes: NonZeroU64::new(262_144).unwrap(),
            max_response_bytes: NonZeroU64::new(262_144).unwrap(),
            determinism: ComputeDeterminism::Strict,
            execution_class: ComputeExecutionClass::Cpu,
            input_limits: Some(ComputeInputLimits {
                max_inline_bytes: NonZeroU64::new(262_144).unwrap(),
                max_chunks: NonZeroU32::new(32).unwrap(),
                chunk_size_bytes: NonZeroU64::new(65_536).unwrap(),
            }),
            model: Some(ComputeModelRef {
                bundle_hash: Hash::new(b"model:payments"),
                path: "models/payments.bin".to_string(),
                expected_bytes: NonZeroU64::new(1_048_576).unwrap(),
                chunk_size_bytes: NonZeroU64::new(131_072).unwrap(),
            }),
            price_family: name("default"),
            resource_profile: name("cpu-small"),
            auth: ComputeAuthPolicy::Either,
        }
    }
    fn sample_manifest() -> ComputeManifest {
        ComputeManifest {
            namespace: name("compute"),
            abi_version: ComputeManifest::ABI_VERSION,
            sandbox: ComputeSandboxRules {
                randomness: ComputeRandomnessPolicy::SeededFromRequest,
                storage: ComputeStorageAccess::ReadOnly,
                deny_nondeterministic_syscalls: true,
                allow_gpu_hints: false,
                allow_tee_hints: false,
            },
            routes: vec![sample_route()],
        }
    }
    fn sample_call() -> ComputeCall {
        ComputeCall {
            namespace: name("compute"),
            route: ComputeRouteId::new(name("payments"), name("quote")),
            codec: ComputeCodec::NoritoJson,
            ttl_slots: NonZeroU64::new(32).unwrap(),
            gas_limit: NonZeroU64::new(1_000_000).unwrap(),
            max_response_bytes: NonZeroU64::new(65_536).unwrap(),
            determinism: ComputeDeterminism::Strict,
            execution_class: ComputeExecutionClass::Cpu,
            declared_input_bytes: NonZeroU64::new(1_024).map(Some).unwrap(),
            declared_input_chunks: NonZeroU32::new(1).map(Some).unwrap(),
            sponsor_budget_cu: NonZeroU64::new(8_000).map(Some).unwrap(),
            price_family: name("default"),
            resource_profile: name("cpu-small"),
            auth: ComputeAuthz::Authenticated(ComputeAuthn {
                uaid: sample_uaid(),
                session_hash: Some(Hash::new(b"session:demo")),
            }),
            request: sample_request(),
        }
    }
    fn sample_pricing() -> ComputePriceWeights {
        ComputePriceWeights {
            cycles_per_unit: NonZeroU64::new(1_000_000).unwrap(),
            egress_bytes_per_unit: NonZeroU64::new(1024).unwrap(),
            unit_label: "cu".to_string(),
        }
    }
    fn sample_metering() -> ComputeMetering {
        let pricing = sample_pricing();
        let metering = ComputeMetering {
            cycles: 8_000_000,
            ingress_bytes: 768,
            egress_bytes: 2_048,
            duration_ms: 25,
            price_family: name("default"),
            charged_units: 0,
        };
        let charged = pricing.charge_units(&metering);
        ComputeMetering {
            charged_units: charged,
            ..metering
        }
    }
    fn sample_receipt() -> ComputeReceipt {
        let call = sample_call();
        let metering = sample_metering();
        ComputeReceipt {
            call: ComputeCallSummary::from(&call),
            metering,
            outcome: ComputeOutcome {
                kind: ComputeOutcomeKind::Success,
                response_hash: Some(Hash::new(b"response:ok")),
                response_bytes: Some(128),
                response_codec: Some(ComputeCodec::NoritoJson),
            },
        }
    }
    #[test]
    fn manifest_detects_duplicates_and_codecs() {
        let mut manifest = sample_manifest();
        manifest.routes.push(sample_route());
        assert!(matches!(
            manifest.validate(),
            Err(ComputeManifestError::DuplicateRoute { .. })
        ));
        let mut manifest = sample_manifest();
        manifest.routes[0].codecs.clear();
        assert!(matches!(
            manifest.validate(),
            Err(ComputeManifestError::EmptyCodecAllowlist { .. })
        ));
    }
    #[test]
    fn route_validation_enforces_caps() {
        let manifest = sample_manifest();
        let mut call = sample_call();
        assert_eq!(Ok(()), manifest.validate());
        assert_eq!(Ok(()), manifest.validate_call(&call));
        call.ttl_slots = NonZeroU64::new(128).unwrap();
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::TtlExceeded { .. })
        ));
    }
    #[test]
    fn best_effort_requires_opt_in() {
        let manifest = sample_manifest();
        let mut call = sample_call();
        call.determinism = ComputeDeterminism::BestEffort;
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::DeterminismMismatch { .. })
        ));
    }
    #[test]
    fn input_limits_gate_calls() {
        let manifest = sample_manifest();
        let mut call = sample_call();
        call.declared_input_bytes = NonZeroU64::new(300_000).map(Some).unwrap();
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::InputBytesExceeded { .. })
        ));
        let mut call = sample_call();
        call.declared_input_chunks = NonZeroU32::new(128).map(Some).unwrap();
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::InputChunksExceeded { .. })
        ));
    }
    #[test]
    fn execution_class_is_enforced() {
        let mut call = sample_call();
        call.execution_class = ComputeExecutionClass::Gpu;
        let manifest = sample_manifest();
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::ExecutionClassMismatch { .. })
        ));
        let mut call = sample_call();
        call.execution_class = ComputeExecutionClass::Gpu;
        let mut manifest = sample_manifest();
        manifest.sandbox.allow_gpu_hints = true;
        manifest.routes[0].execution_class = ComputeExecutionClass::Gpu;
        assert!(matches!(manifest.validate_call(&call), Ok(())));
        let mut call = sample_call();
        call.execution_class = ComputeExecutionClass::Tee;
        let mut manifest = sample_manifest();
        manifest.routes[0].execution_class = ComputeExecutionClass::Tee;
        manifest.sandbox.allow_tee_hints = false;
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::ExecutionClassNotAllowed { .. })
        ));
    }
    #[test]
    fn model_expectation_caps_input_bytes() {
        let mut manifest = sample_manifest();
        manifest.routes[0].input_limits = None;
        let mut call = sample_call();
        let expected = manifest
            .routes
            .first()
            .and_then(|route| route.model.as_ref())
            .map(|model| model.expected_bytes.get())
            .expect("sample route must include model expectations");
        call.declared_input_bytes = NonZeroU64::new(expected + 1).map(Some).unwrap();
        assert!(matches!(
            manifest.validate_call(&call),
            Err(ComputeValidationError::ModelSizeExceeded { .. })
        ));
    }
    #[test]
    fn manifest_rejects_invalid_input_limits() {
        let mut manifest = sample_manifest();
        manifest.routes[0].input_limits = Some(ComputeInputLimits {
            max_inline_bytes: NonZeroU64::new(1_000_000).unwrap(),
            max_chunks: NonZeroU32::new(1).unwrap(),
            chunk_size_bytes: NonZeroU64::new(65_536).unwrap(),
        });
        assert!(matches!(
            manifest.validate(),
            Err(ComputeManifestError::InvalidInputLimits { .. })
        ));
    }
    #[test]
    fn request_hash_is_stable() {
        let hash = sample_request().hash();
        assert_eq!(
            hash.to_string(),
            "d570a087266f13717baa72b7cec5e164ac0b7c21d2b4f3ba9512a2748579d79d",
            "update the compute request fixture if this hash intentionally changes"
        );
    }
    #[test]
    fn pricing_rounds_up_units() {
        let pricing = sample_pricing();
        let metering = sample_metering();
        assert_eq!(10, pricing.charge_units(&metering));
    }
    #[test]
    fn fixtures_round_trip() {
        let manifest: ComputeManifest = json::from_str(include_str!(
            "../../../../fixtures/compute/manifest_compute_payments.json"
        ))
        .expect("manifest fixture");
        let call: ComputeCall = json::from_str(include_str!(
            "../../../../fixtures/compute/call_compute_payments.json"
        ))
        .expect("call fixture");
        let receipt: ComputeReceipt = json::from_str(include_str!(
            "../../../../fixtures/compute/receipt_compute_payments.json"
        ))
        .expect("receipt fixture");
        assert_eq!(sample_manifest(), manifest);
        assert_eq!(sample_call(), call);
        assert_eq!(sample_receipt(), receipt);
    }
    #[test]
    #[ignore = "prints compute fixtures for manual regeneration"]
    fn print_compute_fixtures() {
        let manifest = sample_manifest();
        let call = sample_call();
        let receipt = sample_receipt();
        let manifest_json =
            json::to_string_pretty(&json::to_value(&manifest).expect("manifest json value"))
                .expect("manifest json");
        let call_json = json::to_string_pretty(&json::to_value(&call).expect("call json value"))
            .expect("call json");
        let receipt_json =
            json::to_string_pretty(&json::to_value(&receipt).expect("receipt json value"))
                .expect("receipt json");
        println!("{manifest_json}");
        println!("{call_json}");
        println!("{receipt_json}");
    }
    #[test]
    fn price_delta_bounds_enforced() {
        let mut baseline = BTreeMap::new();
        baseline.insert("default".parse().unwrap(), sample_pricing());
        let mut proposed = baseline.clone();
        proposed.insert(
            "default".parse().unwrap(),
            ComputePriceWeights {
                cycles_per_unit: NonZeroU64::new(1_100_000).unwrap(),
                egress_bytes_per_unit: NonZeroU64::new(1024).unwrap(),
                unit_label: "cu".to_string(),
            },
        );
        let mut risk_classes = BTreeMap::new();
        risk_classes.insert("default".parse().unwrap(), ComputePriceRiskClass::Balanced);
        let mut bounds = BTreeMap::new();
        bounds.insert(
            ComputePriceRiskClass::Balanced,
            ComputePriceDeltaBounds {
                max_cycles_delta_bps: NonZeroU16::new(2_500).unwrap(),
                max_egress_delta_bps: NonZeroU16::new(2_500).unwrap(),
            },
        );
        assert!(validate_price_update(&baseline, &proposed, &risk_classes, &bounds).is_ok());
        proposed.insert(
            "default".parse().unwrap(),
            ComputePriceWeights {
                cycles_per_unit: NonZeroU64::new(2_000_000).unwrap(),
                egress_bytes_per_unit: NonZeroU64::new(1024).unwrap(),
                unit_label: "cu".to_string(),
            },
        );
        assert!(matches!(
            validate_price_update(&baseline, &proposed, &risk_classes, &bounds),
            Err(ComputeGovernanceError::CyclesDeltaExceeded { .. })
        ));
    }
    #[test]
    fn sponsor_policy_caps_requests() {
        let policy = ComputeSponsorPolicy {
            max_cu_per_call: NonZeroU64::new(10).unwrap(),
            max_daily_cu: NonZeroU64::new(20).unwrap(),
        };
        assert!(enforce_sponsor_policy(&policy, 5, 8).is_ok());
        assert!(matches!(
            enforce_sponsor_policy(&policy, 15, 0),
            Err(ComputeGovernanceError::SponsorCapExceeded { .. })
        ));
        assert!(matches!(
            enforce_sponsor_policy(&policy, 8, 15),
            Err(ComputeGovernanceError::SponsorCapExceeded { .. })
        ));
    }

    #[test]
    fn price_delta_bounds_keep_full_width_before_comparison() {
        let family: Name = "default".parse().unwrap();
        let cases: [(u64, u64, u16, Option<u128>); 12] = [
            (1, 4_097, u16::MAX, Some(40_960_000)),
            (1, 4_097, 1_500, Some(40_960_000)),
            (
                1,
                u64::MAX,
                u16::MAX,
                Some((u128::from(u64::MAX) - 1) * 10_000),
            ),
            (u64::MAX / 2, u64::MAX, 1_500, Some(10_000)),
            (u64::MAX, 1, 9_998, Some(9_999)),
            (u64::MAX, 1, 9_999, None),
            (u64::MAX - 1, u64::MAX, 1, None),
            (10_000, 11_500, 1_500, None),
            (10_000, 11_501, 1_500, Some(1_501)),
            (10_000, 75_535, u16::MAX, None),
            (10_000, 75_536, u16::MAX, Some(65_536)),
            (u64::MAX, u64::MAX, 1, None),
        ];
        for component in ["cycles", "egress"] {
            for &(original, proposed, maximum, rejected_delta) in &cases {
                let current = ComputePriceWeights {
                    cycles_per_unit: NonZeroU64::new(original).unwrap(),
                    egress_bytes_per_unit: NonZeroU64::new(original).unwrap(),
                    unit_label: "cu".to_owned(),
                };
                let mut updated = current.clone();
                match component {
                    "cycles" => updated.cycles_per_unit = NonZeroU64::new(proposed).unwrap(),
                    "egress" => updated.egress_bytes_per_unit = NonZeroU64::new(proposed).unwrap(),
                    _ => unreachable!("fixed components"),
                }
                let bounds = ComputePriceDeltaBounds {
                    max_cycles_delta_bps: NonZeroU16::new(maximum).unwrap(),
                    max_egress_delta_bps: NonZeroU16::new(maximum).unwrap(),
                };
                let expected = rejected_delta.map_or(Ok(()), |delta_bps| {
                    Err(match component {
                        "cycles" => ComputeGovernanceError::CyclesDeltaExceeded {
                            family: family.clone(),
                            delta_bps,
                            max_bps: maximum,
                        },
                        "egress" => ComputeGovernanceError::EgressDeltaExceeded {
                            family: family.clone(),
                            delta_bps,
                            max_bps: maximum,
                        },
                        _ => unreachable!("fixed components"),
                    })
                });
                assert_eq!(
                    validate_price_family_update(&family, &current, &updated, &bounds),
                    expected,
                    "price updates must compare full-width deltas before applying bounds\n{component} {original} -> {proposed}",
                );
                let baseline = BTreeMap::from([(family.clone(), current)]);
                let proposed = BTreeMap::from([(family.clone(), updated)]);
                let classes = BTreeMap::from([(family.clone(), ComputePriceRiskClass::Balanced)]);
                let all_bounds = BTreeMap::from([(ComputePriceRiskClass::Balanced, bounds)]);
                assert_eq!(
                    validate_price_update(&baseline, &proposed, &classes, &all_bounds),
                    expected,
                    "the map validator must use the same full-width {component} rule",
                );
            }
        }
    }

    #[test]
    fn sponsor_caps_keep_exact_daily_total_and_per_call_precedence() {
        let cases = [
            (u64::MAX, u64::MAX, 0, u64::MAX, None),
            (u64::MAX, u64::MAX, 1, u64::MAX - 1, None),
            (
                u64::MAX,
                u64::MAX,
                1,
                u64::MAX,
                Some((u128::from(u64::MAX) + 1, u64::MAX)),
            ),
            (
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                Some((2 * u128::from(u64::MAX), u64::MAX)),
            ),
            (2, u64::MAX, 3, u64::MAX, Some((3, 2))),
            (10, 20, 8, 12, None),
            (10, 20, 8, 13, Some((21, 20))),
        ];
        for (per_call, daily, requested, consumed, refused) in cases {
            let policy = ComputeSponsorPolicy {
                max_cu_per_call: NonZeroU64::new(per_call).unwrap(),
                max_daily_cu: NonZeroU64::new(daily).unwrap(),
            };
            let expected = refused.map_or(Ok(()), |(requested, limit)| {
                Err(ComputeGovernanceError::SponsorCapExceeded { requested, limit })
            });
            assert_eq!(
                enforce_sponsor_policy(&policy, requested, consumed),
                expected,
                "the full daily sum must retain per-call refusal precedence"
            );
        }
    }
    #[test]
    fn price_delta_wide_numerator_rejects_extreme_reduction() {
        let family: Name = "default".parse().unwrap();
        let current = ComputePriceWeights {
            cycles_per_unit: NonZeroU64::MAX,
            egress_bytes_per_unit: NonZeroU64::MAX,
            unit_label: "cu".to_owned(),
        };
        let bounds = ComputePriceDeltaBounds {
            max_cycles_delta_bps: NonZeroU16::new(1_500).unwrap(),
            max_egress_delta_bps: NonZeroU16::new(1_500).unwrap(),
        };
        for component in ["cycles", "egress"] {
            let mut updated = current.clone();
            let expected = if component == "cycles" {
                updated.cycles_per_unit = NonZeroU64::new(1).unwrap();
                ComputeGovernanceError::CyclesDeltaExceeded {
                    family: family.clone(),
                    delta_bps: 9_999,
                    max_bps: 1_500,
                }
            } else {
                updated.egress_bytes_per_unit = NonZeroU64::new(1).unwrap();
                ComputeGovernanceError::EgressDeltaExceeded {
                    family: family.clone(),
                    delta_bps: 9_999,
                    max_bps: 1_500,
                }
            };
            assert_eq!(
                validate_price_family_update(&family, &current, &updated, &bounds),
                Err(expected),
                "price percentage must widen the numerator before multiplication",
            );
        }
    }
}

#[cfg(test)]
mod captured_compute_schema_tests;

#[cfg(test)]
mod ivm_only_tests;
