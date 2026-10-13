//! Native bindings exposed to the JavaScript SDK.
#![allow(
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::implicit_clone,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::option_if_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]
mod authenticated_block_proofs;
mod transaction_attachment_context;
pub use transaction_attachment_context::{
    JsTransactionAttachmentContextV1, inspect_transaction_attachment_context_v1,
};
mod kaigi_authorization_v1;
mod kaigi_proof_v1;
mod kaigi_usage_v1;
pub use kaigi_authorization_v1::{JsKaigiAuthorizationProofV1, build_kaigi_authorization_proof_v1};
pub use kaigi_usage_v1::{JsKaigiUsageProofV1, build_kaigi_usage_proof_v1};
mod private_settlement_response;
mod secure_private_fs;
mod sorafs_orderbook_submission;
macro_rules! norito_json {
    ({ $($key:literal : $value:expr),+ $(,)? }) => {{
        let mut object = norito::json::Map::new();
        $(
            object.insert(
                $key.to_string(),
                norito::json::to_value(&$value)
                    .expect("serialize iroha_js_host JSON payload"),
            );
        )*
        norito::json::Value::Object(object)
    }};
}
#[cfg(test)]
mod confidential_proof_boundary_tests;
mod confidential_wallet;
#[cfg(test)]
mod shared_codec_tests;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use blake3::hash as blake3_hash;
use iroha_core_privacy::privacy_profiles::{
    compiled_privacy_profile_catalog_v1, validate_local_privacy_compiled_profile_catalog_archive_v1,
};
use iroha_core_zk::confidential_v2::{
    self, ConfidentialTransferInputV2, ConfidentialTransferOutputV2, ConfidentialUnshieldInputV2,
    ConfidentialUnshieldOutputV3,
};
use iroha_crypto::{
    Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair, PrivateKey, PublicKey, Signature,
    confidential_memo::generate_confidential_memo_keypair_v1 as generate_confidential_memo_native_keypair_v1,
    derive_keyset_from_slice,
    sm::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature, encode_sm2_public_key_payload},
};
use iroha_data_model::{
    HasMetadata, NetworkId,
    account::{
        AccountId,
        address::{AccountAddress, AccountAddressError, ChainDiscriminantGuard},
    },
    asset::id::{AssetDefinitionId, AssetId},
    block::BlockHeader,
    confidential::{ConfidentialMemoEnvelopeV1, ConfidentialMemoSuiteV1},
    da::manifest::DaManifestV1,
    domain::Domain,
    events::time::{ExecutionTime, Schedule as TimeSchedule, TimeEventFilter},
    governance::types::{
        ProposalKind, ValidationFeePayoutLifecycleProposal, ValidationFeePolicyProposal,
    },
    isi::{InstructionBox, Register, Transfer},
    nexus::{
        AxtDescriptor, AxtDescriptorBuilder, AxtTouchFragment, TouchManifest,
        compute_descriptor_binding, validate_descriptor,
    },
    privacy::{
        PRIVACY_BRIDGE_ABI_VERSION_V1, PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1,
        PrivacyCompiledProfileCatalogV1, PrivacyExact12CapabilityManifestV1, PrivacyProtocolIdV1,
        validate_privacy_capability_archive_v1,
    },
    proof::ProofAttachment,
    smart_contract::ContractAddress,
    sorafs::orderbook_submission::{
        parse_sorafs_orderbook_cancel_reason_v1, parse_sorafs_orderbook_decimal_u64_v1,
        parse_sorafs_orderbook_fee_bps_v1, parse_sorafs_orderbook_payload_kind_v1,
        parse_sorafs_orderbook_side_v1, parse_sorafs_orderbook_tier_v1,
        parse_sorafs_orderbook_xor_quantity_v1, validate_sorafs_orderbook_owner_account_v1,
    },
    transaction::{
        Executable, ExecutableBatchItem, FeePaymentIntent, IvmProved, TransactionPayload,
        executable::{ContractArgumentRecord, ContractInvocation},
        signed::{SignedTransaction, TransactionBuilder},
    },
    trigger::action::{Action, Repeats},
    validation_fee::{ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use iroha_storage_client::da::{
    DaProofConfig as IrohaDaProofConfig,
    generate_da_proof_summary as iroha_generate_da_proof_summary,
};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    fmt, fs,
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
    ptr,
    str::FromStr,
    time::Duration,
};
// These types only construct fixtures in the in-file test module.
// Keeping them cfg-scoped avoids carrying test topology into production builds.
// Production receives the evidence through decoded instructions instead;
// direct construction remains deliberately confined to tests.
#[cfg(test)]
use iroha_data_model::{
    account::NewAccount,
    asset::{AssetTransferControlWindow, AssetTransferLimit},
    escrow::EscrowId,
    governance::types::{AbiVersion, ContractAbiHash, ContractCodeHash},
    isi::{
        EndKaigi, Instruction as InstructionTrait, ReportKaigiRelayHealth, SetKeyValue,
        TransferAssetBatch,
        asset_transfer_control::{SetAssetTransferBlacklist, SetAssetTransferControl},
        escrow::CancelAssetLock,
        ministry::SubmitAgendaProposal,
        settlement::{FxCorridorOracleEvidence, SettleFxCorridor, SettlementInstructionBox},
    },
    kaigi::{
        KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiRelayHealthStatus,
        scalar::KaigiAuthorizationScalarV1,
    },
    rwa::{NewRwa, RwaParentRef},
    trigger::Trigger,
};
#[cfg(test)]
use iroha_primitives::numeric::Numeric;
use iroha_primitives::{
    json::Json,
    numeric::Quantity,
    soradns::{
        GatewayHostBindings, GatewayHostProfile, derive_gateway_hosts,
        derive_gateway_hosts_with_profile,
    },
};
use iroha_service_model::soranet::{AnonymityPolicy, RolloutPhase, TransportPolicy, WriteModeHint};
use kotodama_lang::{encoding, instruction, metadata::ProgramMetadata, syscalls};
use napi::{
    ValueType,
    bindgen_prelude::{
        BigInt, Buffer, FromNapiValue, ToNapiValue, TypeName, Uint8Array, ValidateNapiValue,
    },
    sys,
};
use napi_derive::napi;
#[cfg(test)]
use norito::core as norito_core;
use norito::{
    decode_from_bytes,
    json::{self, Map, Value},
};
use sorafs_car::{
    CarBuildPlan, CarChunk, ChunkFetchSpec, ChunkStore, ChunkStoreError, FilePlan, InMemoryPayload,
    PorProof,
    fetch_plan::chunk_fetch_plan_from_json,
    gateway::{GatewayFetchConfig, GatewayProviderInput},
    local_fetch::{
        self, LocalFetchError, LocalFetchOptions, LocalProviderInput, ProviderMetadataInput,
        RangeCapabilityInput, StreamBudgetInput, TelemetryEntryInput, TransportHintInput,
    },
    multi_fetch::{
        self, AttemptError, AttemptFailure, CapabilityMismatch, ChunkVerificationError,
        MultiSourceError,
    },
};
use sorafs_manifest::{
    FixtureBundlePayloadKindV1, FixtureBundlePayloadV1, OrderCancelReasonV1, OrderSideV1,
    OrderTierV1, OrderbookOrderCancelFieldsV1, OrderbookOrderRequestFieldsV1,
    OrderbookSettlementReceiptFieldsV1, OrderbookValidationPayloadKindV1, XorQuantity,
    alias_cache::{
        AliasCachePolicy, AliasProofEvaluation, AliasProofState,
        decode_alias_proof_untrusted_signers, unix_now_secs,
    },
    build_signed_orderbook_order_cancel_bytes_ed25519_v1,
    build_signed_orderbook_order_request_bytes_ed25519_v1,
    build_signed_orderbook_settlement_receipt_bytes_ed25519_v1,
    capacity::ReplicationOrderV1,
    derive_orderbook_order_id_v1,
    pin_registry::{
        AliasBindingV1, AliasProofBundleV1, alias_merkle_root, alias_proof_signature_digest,
    },
    reference_ffi::{
        SORAFS_REFERENCE_FFI_MAX_BUNDLE_PAYLOADS_V1,
        SORAFS_REFERENCE_FFI_MAX_BUNDLE_TOTAL_BYTES_V1, SORAFS_REFERENCE_FFI_MAX_INPUT_BYTES_V1,
        SORAFS_REFERENCE_FFI_MAX_LABEL_BYTES_V1, SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1,
        SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1,
    },
    sign_orderbook_payload_bytes_ed25519_v1, validate_appeal_finance_cancel_asset_lock_bytes,
    validate_fixture_bundle_payloads, validate_governance_dag_block_bytes,
    validate_governance_dag_head_chain_bytes, validate_governance_log_node_bytes,
    validate_orderbook_payload_bytes, validate_pdp_challenge_bytes,
    validate_pdp_challenge_proof_bytes, validate_pdp_commitment_bytes,
    validate_pdp_commitment_challenge_bytes, validate_pdp_commitment_challenge_proof_bytes,
    validate_pdp_proof_bytes,
};
use sorafs_orchestrator::{
    FetchSession, GatewayOrchestratorError, OrchestratorConfig, OrchestratorError,
    fetch_via_gateway,
    proxy::{
        LocalQuicProxyConfig, ProxyCarBridgeConfig, ProxyKaigiBridgeConfig, ProxyMode,
        ProxyNoritoBridgeConfig,
    },
};
use tokio::runtime::Runtime;
const SM2_PRIVATE_KEY_LENGTH: usize = 32;
const SM2_PUBLIC_KEY_LENGTH: usize = 65;
const SM2_SIGNATURE_LENGTH: usize = Sm2Signature::LENGTH;
const SORAFS_ALIAS_POSITIVE_TTL_SECS: u64 = 10 * 60;
const SORAFS_ALIAS_REFRESH_WINDOW_SECS: u64 = 2 * 60;
const SORAFS_ALIAS_HARD_EXPIRY_SECS: u64 = 15 * 60;
const SORAFS_ALIAS_NEGATIVE_TTL_SECS: u64 = 60;
const SORAFS_ALIAS_REVOCATION_TTL_SECS: u64 = 5 * 60;
const SORAFS_ALIAS_ROTATION_MAX_AGE_SECS: u64 = 6 * 60 * 60;
const SORAFS_ALIAS_SUCCESSOR_GRACE_SECS: u64 = 5 * 60;
const SORAFS_ALIAS_GOVERNANCE_GRACE_SECS: u64 = 0;
const JS_MAX_SAFE_INTEGER_U64: u64 = 9_007_199_254_740_991;
const JS_MAX_SAFE_INTEGER_F64: f64 = 9_007_199_254_740_991.0;
/// Report the stable C bridge ABI expected by the JavaScript privacy host.
///
/// Keeping this as an exported N-API function lets JavaScript fail closed when
/// a stale native module happens to expose similarly named privacy functions.
#[napi(js_name = "connectNoritoBridgeAbiVersion")]
pub fn connect_norito_bridge_abi_version() -> u32 {
    PRIVACY_BRIDGE_ABI_VERSION_V1
}
fn validation_fee_fixed_hash(value: &Uint8Array, label: &str) -> napi::Result<[u8; 32]> {
    let bytes: [u8; 32] = value.as_ref().try_into().map_err(|_| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("{label} must contain exactly 32 bytes"),
        )
    })?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{label} must be a non-zero 32-byte digest"),
        ));
    }
    Ok(bytes)
}
fn validation_fee_iroha_hash(value: &Uint8Array, label: &str) -> napi::Result<[u8; 32]> {
    let bytes = validation_fee_fixed_hash(value, label)?;
    if bytes[31] & 1 == 0 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{label} must carry the canonical Iroha hash marker"),
        ));
    }
    Ok(bytes)
}
fn validation_fee_checkpoint(
    bytes: &[u8],
) -> napi::Result<iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint> {
    use iroha_data_model::sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityVerifier,
    };
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(bytes).map_err(|error| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("trustedCheckpointNorito is not a canonical native checkpoint: {error}"),
        )
    })?;
    // Import is an explicit independent trust-root choice. Internal native consistency is still
    // checked before its height can drive a request; the response additionally pins network_id.
    SumeragiFinalityVerifier::from_trusted_checkpoint(
        &checkpoint,
        &checkpoint.network_id(),
        checkpoint.chain_id(),
    )
    .map_err(|error| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("trustedCheckpointNorito failed native validation: {error}"),
        )
    })?;
    Ok(checkpoint)
}

/// Encode the canonical Norito request derived from one independently selected full checkpoint.
#[napi(js_name = "validationFeeCurrentPolicyProofRequestV1")]
pub fn validation_fee_current_policy_proof_request_v1(
    trusted_checkpoint_norito: Uint8Array,
) -> napi::Result<Buffer> {
    let checkpoint = validation_fee_checkpoint(trusted_checkpoint_norito.as_ref())?;
    let request = iroha::client::ValidationFeeCurrentPolicyProofRequestV1 {
        version: iroha::client::VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
        trusted_checkpoint_height: checkpoint.height(),
    };
    norito::encode_canonical(&request)
        .map(Buffer::from)
        .map_err(|error| {
            napi::Error::new(
                napi::Status::GenericFailure,
                format!("failed to encode validation-fee proof request: {error}"),
            )
        })
}

/// Locally verified policy and exact native checkpoint promoted by that same verification.
#[napi(object)]
pub struct ValidationFeeVerifiedPageV1 {
    /// Policy projection rendered with the caller's required account network prefix.
    pub projection_json: String,
    /// Complete canonical checkpoint for durable retention and the next proof-page request.
    pub promoted_checkpoint_norito: Buffer,
}

/// Locally verify one validation-fee proof page under immutable deployment bindings.
/// The full checkpoint must be independently selected; the response cannot choose its own root.
/// Account projections use the caller's required network prefix for this operation.
#[napi(js_name = "validationFeeVerifyCurrentPolicyProofV1")]
pub fn validation_fee_verify_current_policy_proof_v1(
    proof_norito: Uint8Array,
    network_id: Uint8Array,
    policy_chain_genesis_hash: Uint8Array,
    trusted_checkpoint_norito: Uint8Array,
    network_prefix: f64,
) -> napi::Result<ValidationFeeVerifiedPageV1> {
    const MAX_PROOF_BYTES: usize = iroha::client::VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES;
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    let _chain_guard = ChainDiscriminantGuard::enter(prefix);
    if proof_norito.is_empty() || proof_norito.len() > MAX_PROOF_BYTES {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("proofNorito must contain 1..{MAX_PROOF_BYTES} bytes"),
        ));
    }
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(validation_fee_iroha_hash(&network_id, "networkId")?),
    ));
    let policy_chain_genesis_hash =
        validation_fee_iroha_hash(&policy_chain_genesis_hash, "policyChainGenesisHash")?;
    let checkpoint = validation_fee_checkpoint(trusted_checkpoint_norito.as_ref())?;
    let proof: iroha::client::ValidationFeeCurrentPolicyProofV1 =
        norito::decode_canonical_with_limits(
            proof_norito.as_ref(),
            norito::canonical_decode_limits(proof_norito.len()),
        )
        .map_err(|error| {
            napi::Error::new(
                napi::Status::InvalidArg,
                format!("proofNorito is not a canonical validation-fee proof: {error}"),
            )
        })?;
    let (projection, promoted) = proof
        .verify_with_immutable_binding(network_id, policy_chain_genesis_hash, &checkpoint)
        .map_err(napi::Error::from_reason)?;
    Ok(ValidationFeeVerifiedPageV1 {
        projection_json: json::to_json(&projection).map_err(norito_to_napi)?,
        promoted_checkpoint_norito: promoted
            .encode_canonical()
            .map(Buffer::from)
            .map_err(|error| napi::Error::from_reason(error.to_string()))?,
    })
}
const SUPPORTED_CRYPTO_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Secp256k1,
    Algorithm::BlsNormal,
    Algorithm::BlsSmall,
    Algorithm::MlDsa,
    Algorithm::Gost3410_2012_256ParamSetA,
    Algorithm::Gost3410_2012_256ParamSetB,
    Algorithm::Gost3410_2012_256ParamSetC,
    Algorithm::Gost3410_2012_512ParamSetA,
    Algorithm::Gost3410_2012_512ParamSetB,
    Algorithm::Sm2,
];
const MAX_KOTODAMA_SOURCE_NAME_BYTES: usize = 4096;
/// Bounded canonical Kotodama compiler request accepted by the Node binding.
#[napi(object)]
pub struct JsKotodamaCompileRequest {
    /// Complete compiled contracts owned by the root source set.
    pub artifacts: Vec<JsKotodamaContractArtifact>,
    /// Complete deployable Kotodama source.
    pub source: String,
    /// Optional logical source path preserved in diagnostics and sidecars.
    pub source_name: Option<String>,
    /// Explicit companion sources, resolved without filesystem access.
    pub sources: Option<Vec<JsKotodamaSourceFile>>,
    /// Explicit root dependency aliases bound to locked package identities.
    pub imports: Option<Vec<JsKotodamaSourceImport>>,
    /// Complete immutable locked dependency graph, with no network resolution.
    pub packages: Option<Vec<JsKotodamaSourcePackage>>,
    /// Whether to compile with the canonical ZK contract policy.
    pub zk: bool,
}
/// One bounded source file supplied to the canonical compiler.
#[napi(object)]
pub struct JsKotodamaSourceFile {
    /// Portable source-set-relative logical path.
    pub source_name: String,
    /// Complete UTF-8 source text.
    pub source: String,
}
/// One complete compiled interface, owned by a source package and admitted before use.
#[napi(object)]
pub struct JsKotodamaContractArtifact {
    /// Portable owner-relative `.to` path.
    pub source_name: String,
    /// Exact complete deployable artifact bytes.
    pub artifact: Vec<u8>,
}
fn kotodama_contract_artifact(
    artifact: &JsKotodamaContractArtifact,
) -> kotodama_lang::linker::SourceContractArtifact {
    kotodama_lang::linker::SourceContractArtifact {
        source_name: artifact.source_name.clone(),
        artifact: artifact.artifact.clone(),
    }
}
/// One dependency alias bound to an immutable package identity.
#[napi(object)]
pub struct JsKotodamaSourceImport {
    /// Alias used by source declarations.
    pub alias: String,
    /// Locked package identity.
    pub package: String,
}
/// Immutable sources and dependency bindings for one locked package.
#[napi(object)]
pub struct JsKotodamaSourcePackage {
    /// Complete compiled contracts authenticated with this exact package.
    pub artifacts: Vec<JsKotodamaContractArtifact>,
    /// Canonical package identity.
    pub identity: String,
    /// Explicit library entry modules.
    pub modules: Vec<JsKotodamaSourceFile>,
    /// Companion fragments and locally imported modules.
    pub sources: Option<Vec<JsKotodamaSourceFile>>,
    /// Public function identities exported by the package.
    pub exports: Vec<String>,
    /// Locked dependency aliases visible within this package.
    pub imports: Option<Vec<JsKotodamaSourceImport>>,
}
fn kotodama_source_file(source: &JsKotodamaSourceFile) -> kotodama_lang::linker::SourceModuleUnit {
    kotodama_lang::linker::SourceModuleUnit {
        source_name: source.source_name.clone(),
        source: source.source.clone(),
    }
}
fn kotodama_source_import(
    binding: &JsKotodamaSourceImport,
) -> kotodama_lang::linker::ImportBinding {
    kotodama_lang::linker::ImportBinding {
        alias: binding.alias.clone(),
        package: binding.package.clone(),
    }
}
/// Compile Kotodama with the canonical Rust compiler without blocking the Node event loop.
#[allow(
    clippy::trailing_empty_array,
    reason = "the N-API macro conditionally emits its fixed ABI descriptor shape; changing the exported signature would break the JavaScript API"
)]
#[napi(js_name = "compileKotodama")]
pub async fn compile_kotodama(
    request: JsKotodamaCompileRequest,
) -> napi::Result<JsKotodamaCompileResult> {
    tokio::task::spawn_blocking(move || compile_kotodama_request(&request))
        .await
        .map_err(|err| napi::Error::from_reason(format!("Kotodama compiler task failed: {err}")))?
        .map_err(napi::Error::from_reason)
}
fn validate_kotodama_source_name(source_name: Option<&str>) -> Result<(), String> {
    let Some(source_name) = source_name else {
        return Ok(());
    };
    if source_name.is_empty() {
        return Err("Kotodama sourceName must not be empty".to_owned());
    }
    if source_name.len() > MAX_KOTODAMA_SOURCE_NAME_BYTES {
        return Err(format!(
            "Kotodama sourceName exceeds the {MAX_KOTODAMA_SOURCE_NAME_BYTES}-byte limit"
        ));
    }
    if source_name.chars().any(char::is_control) {
        return Err("Kotodama sourceName must not contain control characters".to_owned());
    }
    Ok(())
}
fn compile_kotodama_request(
    request: &JsKotodamaCompileRequest,
) -> Result<JsKotodamaCompileResult, String> {
    validate_kotodama_source_name(request.source_name.as_deref())?;
    let session =
        kotodama_lang::session::CompilerSession::new(kotodama_lang::compiler::CompilerOptions {
            force_zk: request.zk,
            ..kotodama_lang::compiler::CompilerOptions::default()
        });
    let compiled = if !request.artifacts.is_empty()
        || request.sources.is_some()
        || request.imports.is_some()
        || request.packages.is_some()
    {
        let sources = request.sources.as_deref().unwrap_or_default();
        let packages = request.packages.as_deref().unwrap_or_default();
        for package in packages {
            if package
                .exports
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != package.exports.len()
            {
                return Err("locked package contains duplicate exports".into());
            }
        }
        let source_name = request
            .source_name
            .as_deref()
            .ok_or_else(|| "sourceName is required when sources are supplied".to_owned())?;
        let graph = kotodama_lang::linker::SourceLinkRequest {
            artifacts: request
                .artifacts
                .iter()
                .map(kotodama_contract_artifact)
                .collect(),
            root: kotodama_lang::linker::SourceModuleUnit {
                source_name: source_name.into(),
                source: request.source.clone(),
            },
            sources: sources
                .iter()
                .map(|source| kotodama_lang::linker::SourceModuleUnit {
                    source_name: source.source_name.clone(),
                    source: source.source.clone(),
                })
                .collect(),
            imports: request
                .imports
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(kotodama_source_import)
                .collect(),
            packages: packages
                .iter()
                .map(|package| kotodama_lang::linker::SourcePackageUnit {
                    artifacts: package
                        .artifacts
                        .iter()
                        .map(kotodama_contract_artifact)
                        .collect(),
                    identity: package.identity.clone(),
                    modules: package.modules.iter().map(kotodama_source_file).collect(),
                    sources: package
                        .sources
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(kotodama_source_file)
                        .collect(),
                    exports: package.exports.iter().cloned().collect(),
                    imports: package
                        .imports
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(kotodama_source_import)
                        .collect(),
                })
                .collect(),
        };
        kotodama_lang::driver::BuildDriver::new(session, "iroha-js-host")
            .compile_project(graph, source_name)
            .map_err(|error| {
                error.into_diagnostics().unwrap_or_else(|error| {
                    kotodama_lang::diagnostic::DiagnosticBundle::single(
                        kotodama_lang::diagnostic::Diagnostic::error(
                            "K0000",
                            kotodama_lang::diagnostic::DiagnosticPhase::Resolve,
                            error.to_string(),
                            None,
                        ),
                    )
                })
            })
    } else {
        session.build(kotodama_lang::session::CompileRequest {
            source: &request.source,
            source_name: request.source_name.as_deref(),
        })
    };
    let output = match compiled {
        Ok(output) => output,
        Err(diagnostics) => {
            let diagnostics_json = diagnostics
                .render_json()
                .map_err(|err| format!("encode Kotodama diagnostics: {err}"))?;
            return Ok(JsKotodamaCompileResult {
                ok: false,
                output: None,
                diagnostics_json: Some(diagnostics_json),
            });
        }
    };
    let source_map_json = output
        .report
        .render_source_map_json()
        .map_err(|err| format!("encode Kotodama source map: {err}"))?;
    let budget_report_json = output
        .report
        .render_budget_json()
        .map_err(|err| format!("encode Kotodama budget report: {err}"))?;
    let artifact = output.artifact;
    let manifest = output.manifest;
    let manifest_json = norito::json::to_json(&manifest)
        .map_err(|err| format!("encode Kotodama manifest: {err}"))?;
    let code_hash = manifest
        .code_hash
        .ok_or_else(|| "Kotodama manifest is missing code_hash".to_owned())?;
    let abi_hash = manifest
        .abi_hash
        .ok_or_else(|| "Kotodama manifest is missing abi_hash".to_owned())?;
    Ok(JsKotodamaCompileResult {
        ok: true,
        output: Some(JsKotodamaCompileOutput {
            artifact_bytes: artifact.into(),
            manifest_json,
            code_hash: code_hash.to_string(),
            abi_hash: abi_hash.to_string(),
            source_map_json,
            budget_report_json,
        }),
        diagnostics_json: None,
    })
}
/// Ed25519 key pair returned to JavaScript.
#[napi(object)]
pub struct JsKeyPair {
    /// Algorithm identifier (`"ed25519"`).
    pub algorithm: String,
    /// Raw public key bytes.
    pub public_key: Buffer,
    /// Raw private key bytes (ed25519 seed material).
    pub private_key: Buffer,
    /// Optional distinguishing identifier for algorithms that require it (SM2).
    pub distid: Option<String>,
}
/// Typed ML-KEM keypair used only by the first-release confidential memo API.
#[napi(object)]
pub struct JsConfidentialMemoKeypairV1 {
    /// Exact confidential-memo suite label.
    pub suite: String,
    /// Canonical suite-sized ML-KEM public key.
    pub public_key: Buffer,
    /// Canonical suite-sized ML-KEM secret key retained by the local caller.
    pub secret_key: Buffer,
}
/// Canonical Kotodama compilation result envelope returned by the Rust compiler.
///
/// Source errors are data, not rejected JavaScript promises. Both result fields
/// are always present: the inactive field is an explicit JavaScript `null`;
/// rejected promises are reserved for task or serialization failures.
#[napi(object, use_nullable = true)]
pub struct JsKotodamaCompileResult {
    /// Whether canonical compilation succeeded.
    pub ok: bool,
    /// Successful deployable output.
    pub output: Option<JsKotodamaCompileOutput>,
    /// Canonical Norito JSON diagnostic array on compilation failure.
    pub diagnostics_json: Option<String>,
}
/// Successful canonical Kotodama compilation output returned by the Rust compiler.
#[napi(object)]
pub struct JsKotodamaCompileOutput {
    /// Complete deployable `.to` artifact.
    pub artifact_bytes: Buffer,
    /// Canonical Norito JSON representation of the embedded manifest.
    pub manifest_json: String,
    /// Domain-separated full-artifact code hash.
    pub code_hash: String,
    /// ABI policy hash.
    pub abi_hash: String,
    /// Canonical source-map sidecar, bound to `code_hash`.
    pub source_map_json: String,
    /// Canonical compiler-budget sidecar, bound to `code_hash`.
    pub budget_report_json: String,
}
/// Confidential key hierarchy returned to JavaScript callers.
#[napi(object)]
pub struct JsConfidentialKeyset {
    /// Confidential spend key (input seed).
    pub sk_spend: Buffer,
    /// Nullifier key (nk).
    pub nk: Buffer,
    /// Incoming view key (ivk).
    pub ivk: Buffer,
    /// Outgoing view key (ovk).
    pub ovk: Buffer,
    /// Full view key (fvk).
    pub fvk: Buffer,
}
/// Canonical SM2 fixture describing deterministic signing outputs.
#[napi(object)]
pub struct JsSm2Fixture {
    /// Distinguishing identifier used for ZA derivation.
    pub distid: String,
    /// Seed rendered as uppercase hexadecimal.
    pub seed_hex: String,
    /// Message rendered as uppercase hexadecimal.
    pub message_hex: String,
    /// Private key encoded as uppercase hexadecimal.
    pub private_key_hex: String,
    /// SEC1 uncompressed public key (uppercase hex).
    pub public_key_sec1_hex: String,
    /// Multihash string for the SM2 public key.
    pub public_key_multihash: String,
    /// Prefixed multihash string (`"sm2:"` prefix).
    pub public_key_prefixed: String,
    /// ZA (user information hash) in uppercase hexadecimal.
    pub za: String,
    /// Deterministic SM2 signature (r∥s) in uppercase hex.
    pub signature: String,
    /// Canonical `r` component (uppercase hex).
    pub r: String,
    /// Canonical `s` component (uppercase hex).
    pub s: String,
}
/// Optional overrides for `SoraFS` alias cache policy (all values in seconds).
#[napi(object)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_field_names)] // field names mirror the JavaScript property surface
pub struct JsAliasPolicy {
    /// Time-to-live for positively resolved aliases.
    pub positive_ttl_secs: Option<i64>,
    /// Max age before refreshing cached aliases.
    pub refresh_window_secs: Option<i64>,
    /// Hard expiry after which cached aliases are invalid.
    pub hard_expiry_secs: Option<i64>,
    /// Negative cache duration for unresolved aliases.
    pub negative_ttl_secs: Option<i64>,
    /// Time-to-live for revocation records.
    pub revocation_ttl_secs: Option<i64>,
    /// Maximum age before alias rotation is required.
    pub rotation_max_age_secs: Option<i64>,
    /// Grace window applied after a successor manifest is approved.
    pub successor_grace_secs: Option<i64>,
    /// Grace window applied to governance-triggered alias rotations.
    pub governance_grace_secs: Option<i64>,
}
/// Evaluation output exposed to JavaScript callers.
#[napi(object)]
pub struct JsAliasEvaluation {
    /// Current cache state classification.
    pub state: String,
    /// Human-readable status label.
    pub status_label: String,
    /// Whether rotation is due under the cache policy.
    pub rotation_due: bool,
    /// Age of the proof bundle in seconds.
    pub age_seconds: i64,
    /// UNIX timestamp when the bundle was generated.
    pub generated_at_unix: i64,
    /// UNIX timestamp when the bundle expires.
    pub expires_at_unix: i64,
    /// Remaining lifetime in seconds, if calculable.
    pub expires_in_seconds: Option<i64>,
    /// Whether the bundle should be served to clients.
    pub servable: bool,
}
/// Result of parsing an account address string via the shared codec.
#[napi(object)]
pub struct JsAccountAddressParse {
    /// Canonical bytes for the parsed account address.
    pub canonical_bytes: Buffer,
    /// Network prefix inferred while parsing the encoded literal.
    pub network_prefix: Option<u16>,
}
/// Rendered textual encodings for an account address.
#[napi(object)]
pub struct JsAccountAddressRender {
    /// Canonical hexadecimal encoding with `0x` prefix.
    pub canonical_hex: String,
    /// I105 encoding generated with the supplied network prefix.
    pub i105: String,
}
/// Deterministic gateway host bindings exposed to JavaScript callers.
#[napi(object)]
pub struct JsGatewayHosts {
    /// Canonicalised `SoraDNS` FQDN used for hashing.
    pub normalized_name: String,
    /// Blake3 + base32 label that prefixes the canonical host.
    pub canonical_label: String,
    /// Canonical gateway host (`<hash>.gw.sora.id`).
    pub canonical_host: String,
    /// Wildcard pattern that must be present in GAR host lists.
    pub canonical_wildcard: String,
    /// Pretty gateway host (`<fqdn>.gw.sora.name`).
    pub pretty_host: String,
    /// Host patterns the runtime must authorise (canonical, wildcard, pretty).
    pub host_patterns: Vec<String>,
}
/// Fixture options for generating synthetic alias proof bundles.
#[napi(object)]
#[derive(Default)]
pub struct JsAliasProofFixtureOptions {
    /// Alias string placed into the generated bundle.
    pub alias: Option<String>,
    /// Optional manifest CID encoded as hexadecimal.
    pub manifest_cid_hex: Option<String>,
    /// Override for the `generated_at` UNIX timestamp.
    pub generated_at_unix: Option<i64>,
    /// Override for the `expires_at` UNIX timestamp.
    pub expires_at_unix: Option<i64>,
    /// Optional override for the `bound_at` epoch field.
    pub bound_at_epoch: Option<i64>,
    /// Optional override for the expiry epoch value.
    pub expiry_epoch: Option<i64>,
}
/// Alias proof fixture payload returned to JavaScript.
#[napi(object)]
pub struct JsAliasProofFixture {
    /// Generated proof bundle encoded as base64.
    pub proof_b64: String,
    /// Alias name embedded in the fixture.
    pub alias: String,
    /// UNIX timestamp when the proof bundle was generated.
    pub generated_at_unix: i64,
    /// UNIX timestamp when the proof bundle expires.
    pub expires_at_unix: i64,
    /// Hexadecimal encoding of the registry root.
    pub registry_root_hex: String,
    /// Registry tree height encoded into the bundle.
    pub registry_height: i64,
}
/// Assignment entry returned when decoding a replication order.
#[napi(object)]
pub struct JsReplicationAssignment {
    /// Provider identifier encoded as lowercase hex.
    pub provider_id_hex: String,
    /// Capacity slice allocated to the provider (GiB).
    pub slice_gib: i64,
    /// Optional lane hint supplied by governance.
    pub lane: Option<String>,
}
/// SLA parameters returned when decoding a replication order.
#[derive(Clone, Copy)]
#[napi(object)]
pub struct JsReplicationSla {
    /// Ingestion deadline window (seconds).
    pub ingest_deadline_secs: u32,
    /// Minimum availability percentage scaled by 1000.
    pub min_availability_percent_milli: u32,
    /// Minimum `PoR` success percentage scaled by 1000.
    pub min_por_success_percent_milli: u32,
}
/// Metadata entry embedded in a replication order.
#[napi(object)]
pub struct JsReplicationMetadataEntry {
    /// Metadata key.
    pub key: String,
    /// Metadata value.
    pub value: String,
}
/// Result of decoding a Norito-encoded replication order.
#[napi(object)]
pub struct JsReplicationOrder {
    /// Schema version for the replication order.
    pub schema_version: u8,
    /// Order identifier encoded as lowercase hex.
    pub order_id_hex: String,
    /// Manifest CID encoded as lowercase hex.
    pub manifest_cid_hex: String,
    /// Manifest CID encoded as UTF-8 when possible.
    pub manifest_cid_utf8: Option<String>,
    /// Manifest CID encoded as base64.
    pub manifest_cid_base64: String,
    /// Canonical manifest digest (lowercase hex).
    pub manifest_digest_hex: String,
    /// Required chunking profile handle.
    pub chunking_profile: String,
    /// Desired redundancy level (number of replicas).
    pub target_replicas: u32,
    /// Provider assignments mandated by the order.
    pub assignments: Vec<JsReplicationAssignment>,
    /// UNIX timestamp when the order was issued.
    pub issued_at_unix: i64,
    /// UNIX timestamp when ingestion must complete.
    pub deadline_at_unix: i64,
    /// Service-level agreement settings.
    pub sla: JsReplicationSla,
    /// Metadata entries attached to the order.
    pub metadata: Vec<JsReplicationMetadataEntry>,
}
/// One governance DAG block in an ordered contiguous tail supplied to head validation.
#[napi(object)]
pub struct JsSorafsGovernanceDagBlockInput {
    /// Canonical `GovernanceDagBlockV1` Norito bytes.
    pub bytes: Buffer,
    /// UTF-8 diagnostic label preserved in `ValidationOutcomeV1.inputs`.
    pub label: String,
}
/// One typed canonical payload supplied to heterogeneous fixture-bundle validation.
#[napi(object)]
pub struct JsSorafsReferenceBundlePayload {
    /// Canonical V1 payload selector such as `replication-order` or `por-proof`.
    pub kind: String,
    /// Canonical Norito payload bytes.
    pub bytes: Buffer,
    /// UTF-8 diagnostic label preserved in `ValidationOutcomeV1.inputs`.
    pub label: String,
}
/// Return the immutable source revision embedded by the release build.
#[napi]
#[must_use]
pub fn embedded_source_revision() -> String {
    option_env!("IROHA_GIT_COMMIT_HASH")
        .unwrap_or("unknown")
        .to_owned()
}
/// Derive deterministic `SoraDNS` gateway hosts from an FQDN.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String` for bindings
pub fn soradns_derive_gateway_hosts(fqdn: String) -> napi::Result<JsGatewayHosts> {
    let bindings = derive_gateway_hosts(&fqdn).map_err(|err| {
        napi::Error::from_reason(format!("failed to derive deterministic hosts: {err}"))
    })?;
    js_gateway_hosts_from_bindings(&bindings)
}
/// Derive deterministic `SoraDNS` gateway hosts using a custom pretty suffix.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String` for bindings
pub fn soradns_derive_gateway_hosts_with_pretty_suffix(
    fqdn: String,
    pretty_suffix: String,
) -> napi::Result<JsGatewayHosts> {
    let bindings =
        derive_gateway_hosts_with_profile(&fqdn, GatewayHostProfile::new(&pretty_suffix)).map_err(
            |err| napi::Error::from_reason(format!("failed to derive deterministic hosts: {err}")),
        )?;
    js_gateway_hosts_from_bindings(&bindings)
}
fn js_gateway_hosts_from_bindings(bindings: &GatewayHostBindings) -> napi::Result<JsGatewayHosts> {
    let host_patterns = bindings
        .host_patterns()
        .into_iter()
        .map(str::to_string)
        .collect();
    Ok(JsGatewayHosts {
        normalized_name: bindings.normalized_name().to_string(),
        canonical_label: bindings.canonical_label().to_string(),
        canonical_host: bindings.canonical_host().to_string(),
        canonical_wildcard: GatewayHostBindings::canonical_wildcard().to_string(),
        pretty_host: bindings.pretty_host().to_string(),
        host_patterns,
    })
}
/// Parse an account address string in strict encoded form (canonical I105).
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String` for bindings
pub fn account_address_parse_encoded(
    input: String,
    expected_prefix: Option<u16>,
) -> napi::Result<JsAccountAddressParse> {
    let parsed = iroha_js_codec::account_address_parse_encoded(&input, expected_prefix)
        .map_err(codec_to_napi)?;
    Ok(JsAccountAddressParse {
        canonical_bytes: Buffer::from(parsed.canonical_bytes),
        network_prefix: Some(parsed.network_prefix),
    })
}
/// Render canonical account address bytes into textual encodings.
#[allow(clippy::needless_pass_by_value)] // napi binding prefers owned typed arrays
#[napi]
pub fn account_address_render(
    bytes: Uint8Array,
    network_prefix: u16,
) -> napi::Result<JsAccountAddressRender> {
    let rendered = iroha_js_codec::account_address_render(bytes.as_ref(), network_prefix)
        .map_err(codec_to_napi)?;
    Ok(JsAccountAddressRender {
        canonical_hex: rendered.canonical_hex,
        i105: rendered.i105,
    })
}
fn parse_account_id(input: &str, label: &str) -> napi::Result<AccountId> {
    iroha_js_codec::parse_account_id(input, label).map_err(codec_to_napi)
}
#[cfg(test)]
fn i105_discriminant_hint(input: &str) -> Option<u16> {
    AccountAddress::i105_discriminant(input).ok()
}
fn scoped_chain_discriminant_for_literal(input: &str) -> napi::Result<ChainDiscriminantGuard> {
    let prefix =
        AccountAddress::i105_discriminant(input).map_err(|error| account_address_err(&error))?;
    Ok(ChainDiscriminantGuard::enter(prefix))
}
/// Build a canonical public `AssetId` literal from definition/account parts.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String` inputs at the boundary
pub fn encode_asset_id(asset_definition_id: String, account_id: String) -> napi::Result<String> {
    let definition =
        AssetDefinitionId::parse_address_literal(&asset_definition_id).map_err(|err| {
            napi::Error::new(
                napi::Status::InvalidArg,
                format!("invalid asset definition id: {err}"),
            )
        })?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&account_id)?;
    let account = parse_account_id(&account_id, "account id")?;
    Ok(AssetId::new(definition, account).canonical_literal())
}
#[napi(js_name = "blake3Hash")]
/// Compute the BLAKE3-256 digest for the provided payload.
#[allow(clippy::unnecessary_wraps, clippy::needless_pass_by_value)]
pub fn blake3_hash_bytes(payload: Uint8Array) -> napi::Result<Buffer> {
    let digest = blake3_hash(payload.as_ref());
    Ok(Buffer::from(digest.as_bytes().to_vec()))
}
fn parse_fixed32(value: &Uint8Array, context: &str) -> napi::Result<[u8; 32]> {
    let bytes = value.as_ref();
    if bytes.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must be exactly 32 bytes"),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
fn checked_keygen_seed(seed: Uint8Array) -> napi::Result<Vec<u8>> {
    if seed.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "key-generation seed must be exactly 32 bytes",
        ));
    }
    Ok(seed.to_vec())
}
/// Generate an Ed25519 key pair using `iroha_crypto`.
///
/// When supplied, `seed` must be a secret 32-byte value with at least 256 bits
/// of entropy. Omit it for operating-system-random production keys.
#[napi]
pub fn ed25519_keypair(seed: Option<Uint8Array>) -> napi::Result<JsKeyPair> {
    let keypair = match seed {
        Some(seed) => KeyPair::try_from_seed(checked_keygen_seed(seed)?, Algorithm::Ed25519),
        None => KeyPair::try_random_with_algorithm(Algorithm::Ed25519),
    }
    .map_err(norito_to_napi)?;
    let public_bytes = checked_public_key_payload(keypair.public_key())?;
    let (_, private_bytes) = keypair.private_key().to_bytes();
    Ok(JsKeyPair {
        algorithm: "ed25519".to_owned(),
        public_key: Buffer::from(public_bytes.to_vec()),
        private_key: Buffer::from(private_bytes),
        distid: None,
    })
}
/// Parse an exact canonical `iroha_crypto` algorithm label; `None` selects Ed25519.
fn parse_crypto_algorithm(value: Option<&str>) -> napi::Result<Algorithm> {
    let value = value.unwrap_or(iroha_crypto::ED_25519);
    value.parse::<Algorithm>().map_err(|_| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported crypto algorithm: {value}"),
        )
    })
}
fn checked_public_key_payload(public_key: &PublicKey) -> napi::Result<&[u8]> {
    public_key
        .try_to_bytes()
        .map(|(_algorithm, payload)| payload)
        .map_err(norito_to_napi)
}
fn js_keypair_from_keypair(keypair: KeyPair) -> napi::Result<JsKeyPair> {
    let algorithm = keypair.algorithm();
    let public_bytes = checked_public_key_payload(keypair.public_key())?;
    let (_, private_bytes) = keypair.private_key().to_bytes();
    Ok(JsKeyPair {
        algorithm: algorithm.as_static_str().to_owned(),
        public_key: Buffer::from(public_bytes.to_vec()),
        private_key: Buffer::from(private_bytes),
        distid: None,
    })
}
/// Return canonical algorithm labels available through the JavaScript native binding.
#[napi(js_name = "supportedCryptoAlgorithms")]
pub fn supported_crypto_algorithms_js() -> Vec<String> {
    SUPPORTED_CRYPTO_ALGORITHMS
        .iter()
        .map(|algorithm| algorithm.as_static_str().to_owned())
        .collect()
}
/// Generate or deterministically derive a key pair for any supported Iroha signing algorithm.
///
/// When supplied, `seed` must be a secret 32-byte value with at least 256 bits
/// of entropy. Omit it for operating-system-random production keys.
#[napi(js_name = "cryptoKeypair")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_keypair(
    algorithm: Option<String>,
    seed: Option<Uint8Array>,
) -> napi::Result<JsKeyPair> {
    let algorithm = parse_crypto_algorithm(algorithm.as_deref())?;
    let keypair = match seed {
        Some(seed) => KeyPair::try_from_seed(checked_keygen_seed(seed)?, algorithm),
        None => KeyPair::try_random_with_algorithm(algorithm),
    }
    .map_err(norito_to_napi)?;
    js_keypair_from_keypair(keypair)
}
/// Reconstruct a key pair from private-key bytes for any supported Iroha signing algorithm.
#[napi(js_name = "cryptoKeypairFromPrivate")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_keypair_from_private(
    algorithm: String,
    private_key: Uint8Array,
) -> napi::Result<JsKeyPair> {
    let algorithm = parse_crypto_algorithm(Some(&algorithm))?;
    let private_key =
        PrivateKey::from_bytes(algorithm, private_key.as_ref()).map_err(norito_to_napi)?;
    let keypair = KeyPair::from_private_key(private_key).map_err(norito_to_napi)?;
    js_keypair_from_keypair(keypair)
}
/// Derive public-key bytes from private-key bytes for any supported Iroha signing algorithm.
#[napi(js_name = "cryptoPublicKeyFromPrivate")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_public_key_from_private(
    algorithm: String,
    private_key: Uint8Array,
) -> napi::Result<Buffer> {
    let algorithm = parse_crypto_algorithm(Some(&algorithm))?;
    let private_key =
        PrivateKey::from_bytes(algorithm, private_key.as_ref()).map_err(norito_to_napi)?;
    let public_key = PublicKey::from(private_key);
    let public_bytes = checked_public_key_payload(&public_key)?;
    Ok(Buffer::from(public_bytes.to_vec()))
}
/// Sign a message with private-key bytes for any supported Iroha signing algorithm.
#[napi(js_name = "cryptoSign")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_sign(
    algorithm: String,
    private_key: Uint8Array,
    message: Uint8Array,
) -> napi::Result<Buffer> {
    let algorithm = parse_crypto_algorithm(Some(&algorithm))?;
    let private_key =
        PrivateKey::from_bytes(algorithm, private_key.as_ref()).map_err(norito_to_napi)?;
    let signature = Signature::try_new(&private_key, message.as_ref()).map_err(norito_to_napi)?;
    Ok(Buffer::from(signature.payload().to_vec()))
}
/// Verify a signature against public-key bytes for any supported Iroha signing algorithm.
#[napi(js_name = "cryptoVerify")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_verify(
    algorithm: String,
    public_key: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
) -> napi::Result<bool> {
    let algorithm = parse_crypto_algorithm(Some(&algorithm))?;
    let public_key =
        PublicKey::from_bytes(algorithm, public_key.as_ref()).map_err(norito_to_napi)?;
    let signature = match algorithm {
        Algorithm::Ed25519 => match iroha_crypto::ed25519_parse_signature(signature.as_ref()) {
            Ok(signature) => signature,
            Err(_) => return Ok(false),
        },
        Algorithm::MlDsa => match iroha_crypto::mldsa65_parse_signature(signature.as_ref()) {
            Ok(signature) => signature,
            Err(_) => return Ok(false),
        },
        _ => match Signature::try_from_bytes(signature.as_ref()) {
            Ok(signature) => signature,
            Err(_) => return Ok(false),
        },
    };
    Ok(signature.verify(&public_key, message.as_ref()).is_ok())
}
/// Encode public-key bytes as an Iroha multihash literal.
#[napi(js_name = "cryptoPublicKeyMultihash")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_public_key_multihash(
    algorithm: String,
    public_key: Uint8Array,
) -> napi::Result<String> {
    let algorithm = parse_crypto_algorithm(Some(&algorithm))?;
    PublicKey::from_bytes(algorithm, public_key.as_ref())
        .and_then(|public_key| public_key.try_to_multihash_string())
        .map_err(norito_to_napi)
}
/// Encode private-key bytes as an exposed Iroha multihash literal.
#[napi(js_name = "cryptoPrivateKeyMultihash")]
#[allow(clippy::needless_pass_by_value)]
pub fn crypto_private_key_multihash(
    algorithm: String,
    private_key: Uint8Array,
) -> napi::Result<String> {
    let algorithm = parse_crypto_algorithm(Some(&algorithm))?;
    let private_key =
        PrivateKey::from_bytes(algorithm, private_key.as_ref()).map_err(norito_to_napi)?;
    ExposedPrivateKey(private_key)
        .try_to_multihash_string()
        .map_err(norito_to_napi)
}
/// Derive an Ed25519 public key from a private key seed or keypair payload.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs typed arrays require owned values at the boundary
pub fn ed25519_public_key_from_private(private_key: Uint8Array) -> napi::Result<Buffer> {
    let secret =
        PrivateKey::from_bytes(Algorithm::Ed25519, private_key.as_ref()).map_err(norito_to_napi)?;
    let keypair = KeyPair::from_private_key(secret).map_err(norito_to_napi)?;
    let public_bytes = checked_public_key_payload(keypair.public_key())?;
    Ok(Buffer::from(public_bytes.to_vec()))
}
/// Return the default SM2 distinguishing identifier used when none is provided.
#[napi]
pub fn sm2_default_distid() -> String {
    Sm2PublicKey::default_distid()
}
/// Generate an SM2 key pair using `iroha_crypto` defaults.
#[napi]
pub fn sm2_keypair(distid: Option<String>) -> napi::Result<JsKeyPair> {
    let distid = sm2_distid_arg(distid);
    let private = Sm2PrivateKey::try_random_from_os(distid.clone()).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("failed to generate SM2 key pair: {err}"),
        )
    })?;
    let public = private.public_key();
    let private_bytes = private.secret_bytes();
    let public_bytes = public.to_sec1_bytes(false);
    Ok(JsKeyPair {
        algorithm: "sm2".to_owned(),
        public_key: Buffer::from(public_bytes),
        private_key: Buffer::from(private_bytes.to_vec()),
        distid: Some(distid),
    })
}
/// Derive an SM2 key pair deterministically from a seed.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sm2_keypair_from_seed(distid: Option<String>, seed: Uint8Array) -> napi::Result<JsKeyPair> {
    let distid = sm2_distid_arg(distid);
    let private = Sm2PrivateKey::from_seed(distid.clone(), seed.as_ref()).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("failed to derive SM2 private key from seed: {err}"),
        )
    })?;
    let public = private.public_key();
    let private_bytes = private.secret_bytes();
    let public_bytes = public.to_sec1_bytes(false);
    Ok(JsKeyPair {
        algorithm: "sm2".to_owned(),
        public_key: Buffer::from(public_bytes),
        private_key: Buffer::from(private_bytes.to_vec()),
        distid: Some(distid),
    })
}
/// Reconstruct an SM2 key pair from raw private-key bytes.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sm2_keypair_from_private(
    distid: Option<String>,
    private_key: Uint8Array,
) -> napi::Result<JsKeyPair> {
    let private = parse_sm2_private_key(distid, private_key.as_ref())?;
    let public = private.public_key();
    let private_bytes = private.secret_bytes();
    let public_bytes = public.to_sec1_bytes(false);
    Ok(JsKeyPair {
        algorithm: "sm2".to_owned(),
        public_key: Buffer::from(public_bytes),
        private_key: Buffer::from(private_bytes.to_vec()),
        distid: Some(private.distid().to_owned()),
    })
}
/// Compute the canonical multihash string for an SM2 public key.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sm2_public_key_multihash(
    public_key: Uint8Array,
    distid: Option<String>,
) -> napi::Result<String> {
    let payload = public_key.as_ref();
    if payload.len() != SM2_PUBLIC_KEY_LENGTH {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "sm2 public key must be {SM2_PUBLIC_KEY_LENGTH} bytes, got {}",
                payload.len()
            ),
        ));
    }
    let distid = sm2_distid_arg(distid);
    let _ = parse_sm2_public_key(Some(distid.clone()), payload)?;
    let encoded = encode_sm2_public_key_payload(&distid, payload)
        .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err.to_string()))?;
    PublicKey::from_bytes(Algorithm::Sm2, &encoded)
        .and_then(|pk| pk.try_to_multihash_string())
        .map_err(norito_to_napi)
}
/// Sign a message using an SM2 private key.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sm2_sign(
    private_key: Uint8Array,
    message: Uint8Array,
    distid: Option<String>,
) -> napi::Result<Buffer> {
    let private = parse_sm2_private_key(distid, private_key.as_ref())?;
    let signature = try_sign_sm2_message(&private, message.as_ref())?;
    Ok(Buffer::from(signature.to_vec()))
}
/// Verify an SM2 signature against the provided message and public key.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sm2_verify(
    public_key: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    distid: Option<String>,
) -> napi::Result<bool> {
    let public = parse_sm2_public_key(distid, public_key.as_ref())?;
    let signature = parse_sm2_signature(signature.as_ref())?;
    Ok(public.verify(message.as_ref(), &signature).is_ok())
}
/// Encode an instruction JSON payload to canonical Norito bytes.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String` for `#[napi]` bindings
pub fn norito_encode_instruction(
    json_payload: String,
    network_prefix: f64,
) -> napi::Result<Buffer> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    iroha_js_codec::encode_instruction_frame(&json_payload, prefix)
        .map(Buffer::from)
        .map_err(codec_to_napi)
}
/// Encode strict instruction JSON as a canonical compact transaction archive.
#[napi]
pub fn norito_encode_instruction_box_archive(
    json_payload: String,
    network_prefix: f64,
) -> napi::Result<Buffer> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    iroha_js_codec::encode_instruction_archive(&json_payload, prefix)
        .map(Buffer::from)
        .map_err(codec_to_napi)
}

/// Decode one exact canonical compact transaction instruction archive into JSON.
#[napi]
pub fn norito_decode_instruction_box_archive(
    bytes: Uint8Array,
    network_prefix: f64,
) -> napi::Result<String> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    iroha_js_codec::decode_instruction_archive(bytes.as_ref(), prefix).map_err(codec_to_napi)
}
fn subscription_syscall_program_bytes(syscall: u32, max_cycles: NonZeroU64) -> Vec<u8> {
    let opcode = u8::try_from(syscall).expect("subscription syscall opcode fits in u8");
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(instruction::wide::system::SCALL, opcode).to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut artifact = ProgramMetadata {
        max_cycles: max_cycles.get(),
        ..ProgramMetadata::default()
    }
    .encode();
    artifact.extend_from_slice(&code);
    artifact
}
/// Inspect and fail closed on one subscription trigger action returned inside
/// a Torii unsigned mutation draft.
///
/// The returned summary is intentionally small: this function first verifies that the full action
/// contains only the exact first-release billing or usage syscall program, repetition policy, event
/// filter, retry policy, and metadata shape. JavaScript then binds the trusted summary to the
/// reviewed account, subscription, trigger, and charge time before signing.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn inspect_subscription_trigger_action(
    encoded_action: String,
    network_prefix: f64,
) -> napi::Result<String> {
    use iroha_data_model::{
        events::EventFilterBox,
        subscription::{SUBSCRIPTION_TRIGGER_REF_METADATA_KEY, SubscriptionTriggerRef},
    };
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    let _chain_guard = ChainDiscriminantGuard::enter(prefix);
    let action: Action =
        json::from_value(json::Value::String(encoded_action)).map_err(norito_to_napi)?;
    let Executable::Ivm(bytecode) = action.executable() else {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "subscription trigger executable must be exact IVM bytecode",
        ));
    };
    let parsed = ProgramMetadata::parse(bytecode.as_ref()).map_err(norito_to_napi)?;
    let max_cycles = NonZeroU64::new(parsed.metadata.max_cycles).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            "subscription trigger max_cycles must be non-zero",
        )
    })?;
    let program_kind = if bytecode.as_ref()
        == subscription_syscall_program_bytes(syscalls::SYSCALL_SUBSCRIPTION_BILL, max_cycles)
    {
        "billing"
    } else if bytecode.as_ref()
        == subscription_syscall_program_bytes(
            syscalls::SYSCALL_SUBSCRIPTION_RECORD_USAGE,
            max_cycles,
        )
    {
        "usage"
    } else {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "subscription trigger contains an unexpected IVM program",
        ));
    };
    if action.retry_policy().is_some() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "subscription trigger retry_policy must be null",
        ));
    }
    let mut summary = json::Map::new();
    summary.insert(
        "version".to_owned(),
        json::Value::Number(json::Number::from(1_u64)),
    );
    summary.insert(
        "kind".to_owned(),
        json::Value::String(program_kind.to_owned()),
    );
    summary.insert(
        "authority".to_owned(),
        json::Value::String(account_id_to_canonical_i105(action.authority())?),
    );
    summary.insert(
        "max_cycles".to_owned(),
        json::Value::String(max_cycles.get().to_string()),
    );
    match program_kind {
        "billing" => {
            if action.repeats() != Repeats::Exactly(1) {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "billing subscription trigger must repeat exactly once",
                ));
            }
            let EventFilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))) =
                action.filter()
            else {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "billing subscription trigger must use an exact one-shot time schedule",
                ));
            };
            if schedule.period_ms.is_some() {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "billing subscription trigger schedule period must be null",
                ));
            }
            if action.metadata().iter().len() != 1 {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "billing subscription trigger metadata must contain only subscription_ref",
                ));
            }
            let reference = action
                .metadata()
                .get(SUBSCRIPTION_TRIGGER_REF_METADATA_KEY)
                .ok_or_else(|| {
                    napi::Error::new(
                        napi::Status::InvalidArg,
                        "billing subscription trigger is missing subscription_ref metadata",
                    )
                })?;
            let reference: SubscriptionTriggerRef =
                reference.try_into_any_norito().map_err(norito_to_napi)?;
            summary.insert(
                "charge_at_ms".to_owned(),
                json::Value::Number(json::Number::from(schedule.start_ms)),
            );
            summary.insert(
                "subscription_id".to_owned(),
                json::Value::String(reference.subscription_nft_id.to_string()),
            );
        }
        "usage" => {
            if action.repeats() != Repeats::Indefinitely {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "usage subscription trigger must repeat indefinitely",
                ));
            }
            let EventFilterBox::ExecuteTrigger(filter) = action.filter() else {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "usage subscription trigger must use an execute-trigger filter",
                ));
            };
            let trigger_id = filter.trigger_id().ok_or_else(|| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    "usage subscription trigger filter must bind a trigger id",
                )
            })?;
            let filter_authority = filter.authority().ok_or_else(|| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    "usage subscription trigger filter must bind an authority",
                )
            })?;
            if filter_authority != action.authority() {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "usage subscription trigger filter authority must match its action authority",
                ));
            }
            if !action.metadata().is_empty() {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    "usage subscription trigger metadata must be empty",
                ));
            }
            summary.insert(
                "trigger_id".to_owned(),
                json::Value::String(trigger_id.to_string()),
            );
        }
        _ => unreachable!("subscription program kind is classified above"),
    }
    json::to_json(&json::Value::Object(summary)).map_err(norito_to_napi)
}
/// Decode canonical Norito bytes for an instruction back into JSON form.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned typed arrays for `#[napi]` bindings
pub fn norito_decode_instruction(bytes: Uint8Array, network_prefix: f64) -> napi::Result<String> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    iroha_js_codec::decode_instruction_frame(bytes.as_ref(), prefix).map_err(codec_to_napi)
}
/// Compute the canonical native fingerprint for one validation-fee policy proposal.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn validation_fee_policy_proposal_fingerprint_v1(
    proposal_operator: String,
    policy_json: String,
) -> napi::Result<Buffer> {
    let _chain_guard = scoped_chain_discriminant_for_literal(&proposal_operator)?;
    let proposal_operator = validation_fee_proposal_operator(&proposal_operator)?;
    let policy_value: json::Value = json::from_json(&policy_json).map_err(norito_to_napi)?;
    let policy = validation_fee_policy_from_json_value(policy_value)?;
    validate_validation_fee_policy_proposal(&policy)?;
    let fingerprint = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator,
        policy,
    })
    .fingerprint();
    Ok(Buffer::from(fingerprint.to_vec()))
}
/// Compute the canonical native fingerprint for one validation-fee payout lifecycle proposal.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn validation_fee_payout_lifecycle_proposal_fingerprint_v1(
    proposal_operator: String,
    payout_binding_json: String,
) -> napi::Result<Buffer> {
    let _chain_guard = scoped_chain_discriminant_for_literal(&proposal_operator)?;
    let proposal_operator = validation_fee_proposal_operator(&proposal_operator)?;
    let payout_binding_value: json::Value =
        json::from_json(&payout_binding_json).map_err(norito_to_napi)?;
    let payout_binding =
        validation_fee_payout_binding_from_json_value(payout_binding_value, "payout binding")?;
    validate_validation_fee_payout_binding(&payout_binding)?;
    let fingerprint =
        ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
            proposal_operator,
            payout_binding,
        })
        .fingerprint();
    Ok(Buffer::from(fingerprint.to_vec()))
}
/// Touch manifest output returned to JavaScript callers.
#[napi(object)]
pub struct JsTouchManifest {
    /// Manifest rendered as Norito JSON.
    pub manifest_json: String,
}
/// Canonicalise a touch manifest by trimming keys, dropping blanks, then sorting and deduplicating.
#[napi]
pub fn axt_touch_manifest(read: Vec<String>, write: Vec<String>) -> napi::Result<JsTouchManifest> {
    let manifest = TouchManifest::from_read_write(read, write);
    Ok(JsTouchManifest {
        manifest_json: json::to_json(&manifest).map_err(norito_to_napi)?,
    })
}
/// Canonicalised AXT descriptor and derived binding bytes.
#[napi(object)]
pub struct JsAxtDescriptorArtifacts {
    /// Descriptor rendered as Norito JSON.
    pub descriptor_json: String,
    /// Descriptor encoded as Norito bytes.
    pub descriptor_bytes: Buffer,
    /// Optional touch manifest fragments rendered as Norito JSON.
    pub touch_manifest_json: String,
    /// Poseidon-derived binding in hexadecimal form.
    pub binding_hex: String,
    /// Poseidon-derived binding bytes.
    pub binding: Buffer,
}
/// Touch declaration provided by JavaScript callers.
#[napi(object)]
pub struct JsAxtTouchSpec {
    /// Dataspace identifier associated with the touch spec.
    pub dsid: u32,
    /// Declared read set (deduplicated and sorted internally).
    pub read: Option<Vec<String>>,
    /// Declared write set (deduplicated and sorted internally).
    pub write: Option<Vec<String>>,
}
/// Build a canonical AXT descriptor and binding from JavaScript inputs.
#[napi]
pub fn axt_build_descriptor(
    dataspace_ids: Vec<u32>,
    touches: Vec<JsAxtTouchSpec>,
) -> napi::Result<JsAxtDescriptorArtifacts> {
    let mut builder = AxtDescriptorBuilder::new();
    for dsid in dataspace_ids {
        builder = builder.dataspace(DataSpaceId::new(dsid.into()));
    }
    for touch in touches {
        let manifest = TouchManifest::from_read_write(
            touch.read.unwrap_or_default(),
            touch.write.unwrap_or_default(),
        );
        builder = builder.touch(
            DataSpaceId::new(u64::from(touch.dsid)),
            manifest.read,
            manifest.write,
        );
    }
    let descriptor = builder
        .build()
        .map_err(|err| norito_to_napi(format!("{err}")))?;
    validate_descriptor(&descriptor).map_err(|err| norito_to_napi(format!("{err}")))?;
    let descriptor_json = json::to_json(&descriptor).map_err(norito_to_napi)?;
    let descriptor_bytes =
        norito::to_bytes(&descriptor).map_err(|err| norito_to_napi(format!("{err}")))?;
    let binding_bytes = compute_descriptor_binding(&descriptor).map_err(norito_to_napi)?;
    let touch_manifest: Vec<AxtTouchFragment> = descriptor
        .touches
        .iter()
        .map(|touch| AxtTouchFragment {
            dsid: touch.dsid,
            manifest: TouchManifest {
                read: touch.read.clone(),
                write: touch.write.clone(),
            },
        })
        .collect();
    Ok(JsAxtDescriptorArtifacts {
        descriptor_json,
        descriptor_bytes: Buffer::from(descriptor_bytes),
        touch_manifest_json: json::to_json(&touch_manifest).map_err(norito_to_napi)?,
        binding_hex: hex::encode(binding_bytes),
        binding: Buffer::from(binding_bytes.to_vec()),
    })
}
/// Compute an AXT binding from canonical Norito descriptor bytes.
#[napi]
pub fn axt_compute_binding(descriptor_bytes: Buffer) -> napi::Result<Buffer> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let descriptor: AxtDescriptor = decode_from_bytes(descriptor_bytes.as_ref())
        .map_err(|err| norito_to_napi(format!("{err}")))?;
    let canonical = norito::to_bytes(&descriptor).map_err(norito_to_napi)?;
    if canonical.as_slice() != descriptor_bytes.as_ref() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "AXT descriptor bytes must use the canonical Norito V1 layout",
        ));
    }
    validate_descriptor(&descriptor).map_err(|err| norito_to_napi(format!("{err}")))?;
    let binding_bytes = compute_descriptor_binding(&descriptor).map_err(norito_to_napi)?;
    Ok(Buffer::from(binding_bytes.to_vec()))
}
#[allow(unsafe_code)]
#[cfg(test)]
fn decode_instruction_aligned(bytes: &[u8]) -> Result<InstructionBox, norito_core::Error> {
    iroha_js_codec::decode_instruction_aligned(bytes)
}
/// Generate one local ML-KEM keypair for the exact-eight-slot confidential memo API.
#[napi]
pub fn generate_confidential_memo_keypair_v1(
    suite: String,
) -> napi::Result<JsConfidentialMemoKeypairV1> {
    let suite = parse_confidential_memo_suite_v1(&suite)?;
    let keypair =
        generate_confidential_memo_native_keypair_v1(suite.into()).map_err(norito_to_napi)?;
    Ok(JsConfidentialMemoKeypairV1 {
        suite: confidential_memo_suite_label_v1(suite).to_owned(),
        public_key: Buffer::from(keypair.public_key().to_vec()),
        secret_key: Buffer::from(keypair.secret_key().to_vec()),
    })
}

/// Seal a memo for one to eight typed ML-KEM public keys.
#[napi]
pub fn seal_confidential_memo_v1(
    suite: String,
    recipient_public_keys: Vec<Buffer>,
    plaintext: Uint8Array,
) -> napi::Result<Buffer> {
    let suite = parse_confidential_memo_suite_v1(&suite)?;
    let recipients = recipient_public_keys
        .iter()
        .map(|key| key.as_ref().to_vec())
        .collect::<Vec<_>>();
    let envelope = ConfidentialMemoEnvelopeV1::seal(suite, &recipients, plaintext.as_ref())
        .map_err(norito_to_napi)?;
    envelope
        .encode_wire()
        .map(Buffer::from)
        .map_err(norito_to_napi)
}

/// Open one canonical exact-eight-slot memo with a local ML-KEM secret key.
#[napi]
pub fn open_confidential_memo_v1(
    suite: String,
    recipient_secret_key: Uint8Array,
    envelope_wire: Uint8Array,
) -> napi::Result<Buffer> {
    let suite = parse_confidential_memo_suite_v1(&suite)?;
    let envelope =
        ConfidentialMemoEnvelopeV1::decode_wire(envelope_wire.as_ref()).map_err(norito_to_napi)?;
    envelope
        .open(suite, recipient_secret_key.as_ref())
        .map(Buffer::from)
        .map_err(norito_to_napi)
}

/// Derive the confidential key hierarchy from a 32-byte spend key.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API typed arrays require ownership at the boundary
pub fn derive_confidential_keyset(spend_key: Uint8Array) -> napi::Result<JsConfidentialKeyset> {
    let seed = spend_key.as_ref();
    if seed.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential spend key must be 32 bytes",
        ));
    }
    let keyset = derive_keyset_from_slice(seed).map_err(norito_to_napi)?;
    Ok(JsConfidentialKeyset {
        sk_spend: Buffer::from(keyset.spend_key().to_vec()),
        nk: Buffer::from(keyset.nullifier_key().to_vec()),
        ivk: Buffer::from(keyset.incoming_view_key().to_vec()),
        ovk: Buffer::from(keyset.outgoing_view_key().to_vec()),
        fvk: Buffer::from(keyset.full_view_key().to_vec()),
    })
}
/// Derive the confidential v2 owner tag from a 32-byte spend key.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn derive_confidential_owner_tag_v2(
    spend_key: Uint8Array,
    diversifier_hex: Option<String>,
) -> napi::Result<Buffer> {
    let diversifier_hex = zeroize::Zeroizing::new(diversifier_hex);
    let spend_key = spend_key.as_ref();
    if spend_key.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential spend key must be 32 bytes",
        ));
    }
    let diversifier = zeroize::Zeroizing::new(parse_required_confidential_diversifier_hex(
        "diversifier_hex",
        diversifier_hex.as_deref(),
    )?);
    Ok(Buffer::from(
        confidential_v2::derive_confidential_owner_tag_v2_with_diversifier(spend_key, *diversifier)
            .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))?
            .to_vec(),
    ))
}
/// Derive a canonical confidential v2 note diversifier from seed material.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn derive_confidential_diversifier_v2(seed: Uint8Array) -> napi::Result<Buffer> {
    let seed = seed.as_ref();
    if seed.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential diversifier seed must not be empty",
        ));
    }
    Ok(Buffer::from(
        confidential_v2::derive_confidential_diversifier_v2(seed).to_vec(),
    ))
}
/// Derive a diversified confidential v2 receive address from a spend key and seed.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn derive_confidential_receive_address_v2(
    spend_key: Uint8Array,
    diversifier_seed: Uint8Array,
) -> napi::Result<JsConfidentialReceiveAddressV2> {
    let spend_key = spend_key.as_ref();
    if spend_key.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential spend key must be 32 bytes",
        ));
    }
    let seed = diversifier_seed.as_ref();
    if seed.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential diversifier seed must not be empty",
        ));
    }
    let diversifier = confidential_v2::derive_confidential_diversifier_v2(seed);
    let owner_tag =
        confidential_v2::derive_confidential_owner_tag_v2_with_diversifier(spend_key, diversifier)
            .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))?;
    Ok(JsConfidentialReceiveAddressV2 {
        owner_tag_hex: hex::encode(owner_tag),
        diversifier_hex: hex::encode(diversifier),
    })
}
/// Derive a confidential v2 note commitment from note material.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn derive_confidential_note_v2(
    asset_definition_id: String,
    amount: String,
    rho_hex: String,
    owner_tag_hex: String,
) -> napi::Result<Buffer> {
    let amount = zeroize::Zeroizing::new(amount);
    let rho_hex = zeroize::Zeroizing::new(rho_hex);
    let owner_tag_hex = zeroize::Zeroizing::new(owner_tag_hex);
    let asset_definition_id: AssetDefinitionId = asset_definition_id.parse().map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid asset definition id: {err}"),
        )
    })?;
    let amount = zeroize::Zeroizing::new(parse_confidential_amount_u128("amount", &amount)?);
    let rho = zeroize::Zeroizing::new(parse_fixed_32_hex("rho_hex", &rho_hex)?);
    let owner_tag = zeroize::Zeroizing::new(parse_fixed_32_hex("owner_tag_hex", &owner_tag_hex)?);
    let commitment = confidential_v2::derive_confidential_note_v2(
        &asset_definition_id.to_string(),
        *amount,
        *rho,
        *owner_tag,
    )
    .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))?;
    Ok(Buffer::from(commitment.to_vec()))
}
/// Derive a confidential v2 nullifier from spend key material.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn derive_confidential_nullifier_v2(
    network_id: Uint8Array,
    asset_definition_id: String,
    spend_key: Uint8Array,
    rho_hex: String,
) -> napi::Result<Buffer> {
    let rho_hex = zeroize::Zeroizing::new(rho_hex);
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let spend_key = spend_key.as_ref();
    if spend_key.len() != 32 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "confidential spend key must be 32 bytes",
        ));
    }
    let asset_definition_id: AssetDefinitionId = asset_definition_id.parse().map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid asset definition id: {err}"),
        )
    })?;
    let rho = zeroize::Zeroizing::new(parse_fixed_32_hex("rho_hex", &rho_hex)?);
    let asset_tag =
        confidential_v2::derive_confidential_asset_tag_v3(&asset_definition_id.to_string())
            .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))?;
    let network_tag = confidential_v2::derive_confidential_network_tag_v3(&network_id)
        .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))?;
    let nullifier =
        confidential_v2::derive_confidential_nullifier_v3(spend_key, *rho, asset_tag, network_tag)
            .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))?;
    Ok(Buffer::from(nullifier.to_vec()))
}
/// Produce the canonical SM2 fixture output for the given distinguishing ID, seed, and message.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sm2_fixture_from_seed(
    distid: String,
    seed: Uint8Array,
    message: Uint8Array,
) -> napi::Result<JsSm2Fixture> {
    let seed_bytes = seed.to_vec();
    let message_bytes = message.to_vec();
    let private = Sm2PrivateKey::from_seed(distid.as_str(), &seed_bytes).map_err(norito_to_napi)?;
    let public = private.public_key();
    let secret_hex = hex::encode_upper(private.secret_bytes());
    let public_bytes = public.to_sec1_bytes(false);
    let public_hex = hex::encode_upper(&public_bytes);
    let payload =
        encode_sm2_public_key_payload(distid.as_str(), &public_bytes).map_err(norito_to_napi)?;
    let public_key = PublicKey::from_bytes(Algorithm::Sm2, &payload).map_err(norito_to_napi)?;
    let multihash = public_key
        .try_to_multihash_string()
        .map_err(norito_to_napi)?;
    let prefixed = public_key
        .try_to_prefixed_string()
        .map_err(norito_to_napi)?;
    let za = public.compute_z(distid.as_str()).map_err(norito_to_napi)?;
    let za_hex = hex::encode_upper(za);
    let signature = private
        .try_sign(&message_bytes)
        .map_err(|err| norito_to_napi(format!("failed to sign SM2 fixture message: {err}")))?;
    let signature_bytes = signature.as_bytes();
    let signature_hex = hex::encode_upper(signature_bytes);
    let r_hex = hex::encode_upper(signature.r);
    let s_hex = hex::encode_upper(signature.s);
    Ok(JsSm2Fixture {
        distid,
        seed_hex: hex::encode_upper(seed_bytes),
        message_hex: hex::encode_upper(message_bytes),
        private_key_hex: secret_hex,
        public_key_sec1_hex: public_hex,
        public_key_multihash: multihash,
        public_key_prefixed: prefixed,
        za: za_hex,
        signature: signature_hex,
        r: r_hex,
        s: s_hex,
    })
}
fn sm2_distid_arg(distid: Option<String>) -> String {
    distid.unwrap_or_else(Sm2PublicKey::default_distid)
}
fn parse_sm2_private_key(distid: Option<String>, bytes: &[u8]) -> napi::Result<Sm2PrivateKey> {
    if bytes.len() != SM2_PRIVATE_KEY_LENGTH {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "sm2 private key must be {SM2_PRIVATE_KEY_LENGTH} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    let distid = sm2_distid_arg(distid);
    Sm2PrivateKey::from_bytes(distid, bytes)
        .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err.to_string()))
}
fn try_sign_sm2_message(
    private: &Sm2PrivateKey,
    message: &[u8],
) -> napi::Result<[u8; SM2_SIGNATURE_LENGTH]> {
    private
        .try_sign(message)
        .map(|signature| signature.as_bytes())
        .map_err(|err| norito_to_napi(format!("failed to sign SM2 message: {err}")))
}
fn parse_sm2_public_key(distid: Option<String>, bytes: &[u8]) -> napi::Result<Sm2PublicKey> {
    if bytes.len() != SM2_PUBLIC_KEY_LENGTH {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "sm2 public key must be {SM2_PUBLIC_KEY_LENGTH} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    let distid = sm2_distid_arg(distid);
    Sm2PublicKey::from_sec1_bytes(distid, bytes)
        .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err.to_string()))
}
fn parse_sm2_signature(bytes: &[u8]) -> napi::Result<Sm2Signature> {
    if bytes.len() != SM2_SIGNATURE_LENGTH {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "sm2 signature must be {SM2_SIGNATURE_LENGTH} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    let mut array = [0u8; SM2_SIGNATURE_LENGTH];
    array.copy_from_slice(bytes);
    Sm2Signature::from_bytes(&array)
        .map_err(|err| napi::Error::new(napi::Status::InvalidArg, err.to_string()))
}
fn account_address_err(err: &AccountAddressError) -> napi::Error {
    codec_to_napi(iroha_js_codec::account_address_err(err))
}
fn codec_to_napi(error: iroha_js_codec::CodecError) -> napi::Error {
    let status = match error.kind() {
        iroha_js_codec::CodecErrorKind::InvalidArgument => napi::Status::InvalidArg,
        iroha_js_codec::CodecErrorKind::Failure => napi::Status::GenericFailure,
    };
    napi::Error::new(status, error.to_string())
}
fn norito_to_napi<E: fmt::Display>(error: E) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, error.to_string())
}
fn parse_confidential_memo_suite_v1(value: &str) -> napi::Result<ConfidentialMemoSuiteV1> {
    match value {
        "ml-kem-768-xchacha20-poly1305-v1" => {
            Ok(ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305)
        }
        "ml-kem-1024-xchacha20-poly1305-v1" => {
            Ok(ConfidentialMemoSuiteV1::MlKem1024XChaCha20Poly1305)
        }
        _ => Err(napi::Error::new(
            napi::Status::InvalidArg,
            "suite must be exactly ml-kem-768-xchacha20-poly1305-v1 or ml-kem-1024-xchacha20-poly1305-v1",
        )),
    }
}
const fn confidential_memo_suite_label_v1(suite: ConfidentialMemoSuiteV1) -> &'static str {
    match suite {
        ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305 => "ml-kem-768-xchacha20-poly1305-v1",
        ConfidentialMemoSuiteV1::MlKem1024XChaCha20Poly1305 => "ml-kem-1024-xchacha20-poly1305-v1",
    }
}
fn sign_js_transaction(
    builder: TransactionBuilder,
    private_key: &PrivateKey,
    context: &str,
) -> napi::Result<SignedTransaction> {
    builder
        .try_sign(private_key)
        .map_err(|err| norito_to_napi(format!("failed to sign {context} transaction: {err}",)))
}
fn alias_policy_from_js(policy: Option<&JsAliasPolicy>) -> napi::Result<AliasCachePolicy> {
    let mut positive = SORAFS_ALIAS_POSITIVE_TTL_SECS;
    let mut refresh = SORAFS_ALIAS_REFRESH_WINDOW_SECS;
    let mut hard = SORAFS_ALIAS_HARD_EXPIRY_SECS;
    let mut negative = SORAFS_ALIAS_NEGATIVE_TTL_SECS;
    let mut revocation = SORAFS_ALIAS_REVOCATION_TTL_SECS;
    let mut rotation = SORAFS_ALIAS_ROTATION_MAX_AGE_SECS;
    let mut successor = SORAFS_ALIAS_SUCCESSOR_GRACE_SECS;
    let mut governance = SORAFS_ALIAS_GOVERNANCE_GRACE_SECS;
    if let Some(policy) = policy {
        if let Some(value) = policy.positive_ttl_secs {
            positive = ensure_positive(value, "positiveTtlSecs")?;
        }
        if let Some(value) = policy.refresh_window_secs {
            refresh = ensure_positive(value, "refreshWindowSecs")?;
        }
        if let Some(value) = policy.hard_expiry_secs {
            hard = ensure_positive(value, "hardExpirySecs")?;
        }
        if let Some(value) = policy.negative_ttl_secs {
            negative = ensure_positive(value, "negativeTtlSecs")?;
        }
        if let Some(value) = policy.revocation_ttl_secs {
            revocation = ensure_positive(value, "revocationTtlSecs")?;
        }
        if let Some(value) = policy.rotation_max_age_secs {
            rotation = ensure_positive(value, "rotationMaxAgeSecs")?;
        }
        if let Some(value) = policy.successor_grace_secs {
            successor = ensure_positive(value, "successorGraceSecs")?;
        }
        if let Some(value) = policy.governance_grace_secs {
            governance = ensure_non_negative(value, "governanceGraceSecs")?;
        }
    }
    if refresh > positive {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "refreshWindowSecs must not exceed positiveTtlSecs",
        ));
    }
    if hard < positive {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "hardExpirySecs must be greater than or equal to positiveTtlSecs",
        ));
    }
    Ok(AliasCachePolicy::new(
        Duration::from_secs(positive),
        Duration::from_secs(refresh),
        Duration::from_secs(hard),
        Duration::from_secs(negative),
        Duration::from_secs(revocation),
        Duration::from_secs(rotation),
        Duration::from_secs(successor),
        Duration::from_secs(governance),
    ))
}
fn ensure_positive(value: i64, name: &str) -> napi::Result<u64> {
    if value <= 0 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{name} must be greater than zero"),
        ));
    }
    js_number_to_u64(value, name)
}
fn ensure_non_negative(value: i64, name: &str) -> napi::Result<u64> {
    js_number_to_u64(value, name)
}
fn parse_hex_bytes(input: &str, context: &str) -> napi::Result<Vec<u8>> {
    let trimmed = input.trim_start_matches("0x");
    if !trimmed.len().is_multiple_of(2) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must contain an even number of hex characters"),
        ));
    }
    hex::decode(trimmed).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("failed to decode {context}: {err}"),
        )
    })
}
/// Return the default alias cache policy used by `SoraFS` gateways.
#[napi]
pub fn sorafs_alias_policy_defaults() -> JsAliasPolicy {
    JsAliasPolicy {
        positive_ttl_secs: Some(
            i64::try_from(SORAFS_ALIAS_POSITIVE_TTL_SECS).expect("alias TTL fits in i64"),
        ),
        refresh_window_secs: Some(
            i64::try_from(SORAFS_ALIAS_REFRESH_WINDOW_SECS).expect("refresh window fits in i64"),
        ),
        hard_expiry_secs: Some(
            i64::try_from(SORAFS_ALIAS_HARD_EXPIRY_SECS).expect("hard expiry fits in i64"),
        ),
        negative_ttl_secs: Some(
            i64::try_from(SORAFS_ALIAS_NEGATIVE_TTL_SECS).expect("negative TTL fits in i64"),
        ),
        revocation_ttl_secs: Some(
            i64::try_from(SORAFS_ALIAS_REVOCATION_TTL_SECS).expect("revocation TTL fits in i64"),
        ),
        rotation_max_age_secs: Some(
            i64::try_from(SORAFS_ALIAS_ROTATION_MAX_AGE_SECS).expect("rotation age fits in i64"),
        ),
        successor_grace_secs: Some(
            i64::try_from(SORAFS_ALIAS_SUCCESSOR_GRACE_SECS).expect("successor grace fits in i64"),
        ),
        governance_grace_secs: Some(
            i64::try_from(SORAFS_ALIAS_GOVERNANCE_GRACE_SECS)
                .expect("governance grace fits in i64"),
        ),
    }
}
/// Evaluate an alias proof bundle against the provided or default policy.
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String`/struct inputs
#[napi]
pub fn sorafs_evaluate_alias_proof(
    proof_b64: String,
    policy: Option<JsAliasPolicy>,
    now_secs: Option<i64>,
) -> napi::Result<JsAliasEvaluation> {
    let policy = alias_policy_from_js(policy.as_ref())?;
    let now = match now_secs {
        Some(value) => js_number_to_u64(value, "now_secs")?,
        None => unix_now_secs(),
    };
    let trimmed = proof_b64.trim();
    if trimmed.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "proof must not be empty",
        ));
    }
    let proof_bytes = STANDARD.decode(trimmed.as_bytes()).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("failed to decode base64 proof: {err}"),
        )
    })?;
    let bundle = decode_alias_proof_untrusted_signers(&proof_bytes).map_err(norito_to_napi)?;
    let evaluation = policy.evaluate(&bundle, now);
    alias_evaluation_to_js(evaluation)
}
fn u64_to_js_number(value: u64, field: &str) -> napi::Result<i64> {
    if value > JS_MAX_SAFE_INTEGER_U64 {
        return Err(napi::Error::new(
            napi::Status::GenericFailure,
            format!("{field} exceeds JavaScript safe integer range"),
        ));
    }
    i64::try_from(value).map_err(|_| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("{field} exceeds JavaScript safe integer range"),
        )
    })
}
fn alias_evaluation_to_js(evaluation: AliasProofEvaluation) -> napi::Result<JsAliasEvaluation> {
    let state = match evaluation.state {
        AliasProofState::Fresh => "fresh",
        AliasProofState::RefreshWindow => "refresh_window",
        AliasProofState::Expired => "expired",
        AliasProofState::HardExpired => "hard_expired",
    }
    .to_owned();
    let status_label = evaluation.status_label().to_owned();
    let age_seconds = u64_to_js_number(evaluation.age.as_secs(), "age_seconds")?;
    let generated_at_unix = u64_to_js_number(evaluation.generated_at_unix, "generated_at_unix")?;
    let expires_at_unix = u64_to_js_number(evaluation.expires_at_unix, "expires_at_unix")?;
    let expires_in_seconds = evaluation
        .expires_in
        .map(|duration| u64_to_js_number(duration.as_secs(), "expires_in_seconds"))
        .transpose()?;
    Ok(JsAliasEvaluation {
        state,
        status_label,
        rotation_due: evaluation.rotation_due,
        age_seconds,
        generated_at_unix,
        expires_at_unix,
        expires_in_seconds,
        servable: evaluation.state.is_servable(),
    })
}
fn resolve_manifest_cid(opts: &JsAliasProofFixtureOptions) -> napi::Result<Vec<u8>> {
    if let Some(hex) = opts.manifest_cid_hex.as_ref() {
        let cid = parse_hex_bytes(hex, "manifestCidHex")?;
        if cid.is_empty() {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "manifestCidHex must not decode to an empty value",
            ));
        }
        Ok(cid)
    } else {
        Ok(sorafs_manifest::canonical_manifest_root_cid([0xAA; 32]))
    }
}
fn js_number_to_u64(value: i64, field: &str) -> napi::Result<u64> {
    let value = u64::try_from(value).map_err(|_| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("{field} must be non-negative and within JavaScript safe integer range"),
        )
    })?;
    if value > JS_MAX_SAFE_INTEGER_U64 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{field} must be non-negative and within JavaScript safe integer range"),
        ));
    }
    Ok(value)
}
fn resolve_fixture_timestamps(
    opts: &JsAliasProofFixtureOptions,
    now: u64,
) -> napi::Result<(u64, u64)> {
    let generated = match opts.generated_at_unix {
        Some(value) => js_number_to_u64(value, "generatedAtUnix")?,
        None => now.saturating_sub(60),
    };
    let expires = if let Some(value) = opts.expires_at_unix {
        js_number_to_u64(value, "expiresAtUnix")?
    } else {
        let expires = generated
            .checked_add(SORAFS_ALIAS_POSITIVE_TTL_SECS)
            .ok_or_else(|| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    "default expiresAtUnix exceeds JavaScript safe integer range",
                )
            })?;
        if expires > JS_MAX_SAFE_INTEGER_U64 {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "default expiresAtUnix exceeds JavaScript safe integer range",
            ));
        }
        expires
    };
    if expires <= generated {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "expiresAtUnix must be greater than generatedAtUnix",
        ));
    }
    Ok((generated, expires))
}
fn resolve_fixture_epochs(opts: &JsAliasProofFixtureOptions) -> napi::Result<(u64, u64)> {
    let bound_at = opts
        .bound_at_epoch
        .map(|value| js_number_to_u64(value, "boundAtEpoch"))
        .transpose()?
        .unwrap_or(1);
    let expiry_epoch = opts
        .expiry_epoch
        .map(|value| js_number_to_u64(value, "expiryEpoch"))
        .transpose()?
        .unwrap_or(bound_at + 100);
    Ok((bound_at, expiry_epoch))
}
fn sign_bundle_with_council(bundle: &mut AliasProofBundleV1) -> napi::Result<()> {
    let root = alias_merkle_root(&bundle.binding, &bundle.merkle_path).map_err(norito_to_napi)?;
    bundle.registry_root = root;
    let digest = alias_proof_signature_digest(bundle);
    let keypair = KeyPair::from_private_key(
        PrivateKey::from_bytes(Algorithm::Ed25519, &[0x55; 32]).expect("seeded key"),
    )
    .expect("derive keypair");
    let signature =
        Signature::try_new(keypair.private_key(), digest.as_ref()).map_err(norito_to_napi)?;
    let signer_bytes = checked_public_key_payload(keypair.public_key())?;
    let signer: [u8; 32] = signer_bytes
        .try_into()
        .map_err(|_| generic_failure("ed25519 public key must be 32 bytes"))?;
    bundle
        .council_signatures
        .push(sorafs_manifest::CouncilSignature {
            signer,
            signature: signature.payload().to_vec(),
        });
    bundle.validate().map_err(norito_to_napi)
}
/// Produce a deterministic alias proof example for documentation and testing.
#[napi]
pub fn sorafs_alias_proof_fixture(
    options: Option<JsAliasProofFixtureOptions>,
) -> napi::Result<JsAliasProofFixture> {
    let opts = options.unwrap_or_default();
    let alias = opts.alias.as_deref().unwrap_or("docs/sora").to_owned();
    let manifest_cid = resolve_manifest_cid(&opts)?;
    let now = unix_now_secs();
    let (generated, expires) = resolve_fixture_timestamps(&opts, now)?;
    let (bound_at, expiry_epoch) = resolve_fixture_epochs(&opts)?;
    let binding = AliasBindingV1 {
        alias: alias.clone(),
        manifest_cid,
        bound_at,
        expiry_epoch,
    };
    let mut bundle = AliasProofBundleV1 {
        binding,
        registry_root: [0u8; 32],
        registry_height: 1,
        generated_at_unix: generated,
        expires_at_unix: expires,
        merkle_path: Vec::new(),
        council_signatures: Vec::new(),
    };
    sign_bundle_with_council(&mut bundle)?;
    let proof_bytes = norito::to_bytes(&bundle).map_err(norito_to_napi)?;
    let proof_b64 = STANDARD.encode(proof_bytes);
    let registry_root_hex = hex::encode(bundle.registry_root);
    let generated_i64 = u64_to_js_number(generated, "generated_at_unix")?;
    let expires_i64 = u64_to_js_number(expires, "expires_at_unix")?;
    Ok(JsAliasProofFixture {
        proof_b64,
        alias,
        generated_at_unix: generated_i64,
        expires_at_unix: expires_i64,
        registry_root_hex,
        registry_height: u64_to_js_number(bundle.registry_height, "registry_height")?,
    })
}
#[napi(object)]
/// Provider descriptor used by `sorafsMultiFetchLocal`.
pub struct JsLocalProviderSpec {
    /// Human-readable provider identifier (emitted in receipts and reports).
    pub name: String,
    /// Filesystem path to the local chunk source backing this provider.
    pub path: String,
    /// Optional cap on concurrent chunk requests served from this provider.
    pub max_concurrent: Option<u32>,
    /// Optional weighting applied during scoreboard normalisation.
    pub weight: Option<u32>,
    /// Optional provider metadata (range capability, quotas, etc.).
    pub metadata: Option<JsProviderMetadata>,
}
#[napi(object)]
#[derive(Clone, Copy)]
/// Server-advertised chunk range limits for `SoraFS` providers.
pub struct JsRangeCapability {
    /// Maximum contiguous chunk span that the provider can deliver.
    pub max_chunk_span: u32,
    /// Smallest chunk granularity the provider supports.
    pub min_granularity: u32,
    /// Whether the provider can fetch discontiguous chunk offsets in one request.
    pub supports_sparse_offsets: Option<bool>,
    /// Whether fetch requests must align on chunk boundaries.
    pub requires_alignment: Option<bool>,
    /// Whether the provider can attach Merkle proofs alongside chunks.
    pub supports_merkle_proof: Option<bool>,
}
#[napi(object)]
#[derive(Clone, Copy)]
/// Concurrency and throughput quotas enforced during orchestrated fetches.
pub struct JsStreamBudget {
    /// Maximum simultaneous chunks placed in-flight for this provider.
    pub max_in_flight: u16,
    /// Sustained byte-per-second limit for the stream.
    pub max_bytes_per_sec: JsU64,
    /// Optional burst allowance expressed in bytes.
    pub burst_bytes: Option<JsU64>,
}
#[napi(object)]
/// Transport hint describing how to reach a provider.
pub struct JsTransportHint {
    /// Transport protocol label understood by the orchestrator.
    pub protocol: String,
    /// Integer protocol identifier used in orchestrator internals.
    pub protocol_id: u8,
    /// Relative priority applied when choosing between multiple hints.
    pub priority: u8,
}
/// Lossless wrapper that accepts JavaScript `number` (within safe range) or `bigint` and stores it as `u64`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsU64(pub u64);
impl TypeName for JsU64 {
    fn type_name() -> &'static str {
        "number | bigint"
    }
    fn value_type() -> ValueType {
        ValueType::Unknown
    }
}
impl ValidateNapiValue for JsU64 {
    #[allow(unsafe_code)]
    unsafe fn validate(
        env: sys::napi_env,
        napi_val: sys::napi_value,
    ) -> napi::Result<sys::napi_value> {
        match napi::type_of!(env, napi_val)? {
            ValueType::Number | ValueType::BigInt => Ok(ptr::null_mut()),
            other => Err(napi::Error::new(
                napi::Status::InvalidArg,
                format!("expected number or bigint, received {other}"),
            )),
        }
    }
}
impl FromNapiValue for JsU64 {
    #[allow(unsafe_code)]
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> napi::Result<Self> {
        match napi::type_of!(env, napi_val)? {
            ValueType::Number => {
                let mut raw = 0f64;
                let raw_ptr = ptr::addr_of_mut!(raw);
                unsafe {
                    napi::check_status!(sys::napi_get_value_double(env, napi_val, raw_ptr))?;
                }
                if !raw.is_finite() {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        "expected finite number",
                    ));
                }
                if raw < 0.0 {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        "expected non-negative number",
                    ));
                }
                if raw.fract() != 0.0 {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        "expected integer-valued number",
                    ));
                }
                if raw > JS_MAX_SAFE_INTEGER_F64 {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        "number exceeds JavaScript safe integer range; use bigint",
                    ));
                }
                let coerced = {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        raw as u64
                    }
                };
                Ok(Self(coerced))
            }
            ValueType::BigInt => {
                let bigint = unsafe { BigInt::from_napi_value(env, napi_val)? };
                let (sign_bit, value, lossless) = bigint.get_u64();
                if sign_bit {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        "bigint must be non-negative",
                    ));
                }
                if !lossless {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        "bigint exceeds u64 range",
                    ));
                }
                Ok(Self(value))
            }
            other => Err(napi::Error::new(
                napi::Status::InvalidArg,
                format!("expected number or bigint, received {other}"),
            )),
        }
    }
}
impl ToNapiValue for JsU64 {
    #[allow(unsafe_code)]
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> napi::Result<sys::napi_value> {
        let mut raw = ptr::null_mut();
        let raw_ptr = ptr::addr_of_mut!(raw);
        unsafe {
            napi::check_status!(sys::napi_create_bigint_uint64(env, val.0, raw_ptr))?;
        }
        Ok(raw)
    }
}
impl From<JsU64> for u64 {
    fn from(value: JsU64) -> Self {
        value.0
    }
}
impl From<u64> for JsU64 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
#[napi(object)]
/// Detailed provider metadata consumed by the orchestrator.
pub struct JsProviderMetadata {
    /// Optional provider identifier override; falls back to the alias when missing.
    pub provider_id: Option<String>,
    /// Optional identifier of the advertised profile.
    pub profile_id: Option<String>,
    /// Alternate aliases pointing at the same profile.
    pub profile_aliases: Option<Vec<String>>,
    /// Provider availability note (e.g., `"online"`, maintenance message).
    pub availability: Option<String>,
    /// Optional staking weight associated with the provider.
    pub stake_amount: Option<String>,
    /// Maximum concurrent stream slots offered by the provider.
    pub max_streams: Option<u32>,
    /// Deadline (Unix seconds) after which the provider should be refreshed.
    pub refresh_deadline: Option<JsU64>,
    /// Expiration timestamp for the metadata entry.
    pub expires_at: Option<JsU64>,
    /// Suggested time-to-live for cached metadata.
    pub ttl_secs: Option<JsU64>,
    /// Whether unknown capabilities should be tolerated.
    pub allow_unknown_capabilities: Option<bool>,
    /// Capability names declared by the provider.
    pub capability_names: Option<Vec<String>>,
    /// Rendezvous topics used during provider discovery.
    pub rendezvous_topics: Option<Vec<String>>,
    /// Free-form notes supplied by the provider.
    pub notes: Option<String>,
    /// Range capability information for chunk scheduling.
    pub range_capability: Option<JsRangeCapability>,
    /// Stream quota policy for orchestrated fetches.
    pub stream_budget: Option<JsStreamBudget>,
    /// Transport hints advertising available protocols.
    pub transport_hints: Option<Vec<JsTransportHint>>,
}
#[napi(object)]
/// Snapshot of provider telemetry inputs for scoreboard weighting.
pub struct JsTelemetryEntry {
    /// Provider identifier referenced by the telemetry source.
    pub provider_id: String,
    /// Quality of service score in the range [0, 1].
    pub qos_score: Option<f64>,
    /// Observed 95th percentile latency in milliseconds.
    pub latency_p95_ms: Option<f64>,
    /// Exponentially weighted median failure rate.
    pub failure_rate_ewma: Option<f64>,
    /// Token health metric used for staking-aware weighting.
    pub token_health: Option<f64>,
    /// Stake weight observed for the provider.
    pub staking_weight: Option<f64>,
    /// Reputation score in basis points, where `10_000` is full reputation.
    pub reputation_score_bps: Option<u16>,
    /// Whether the provider is currently penalised.
    pub penalty: Option<bool>,
    /// Last update timestamp expressed in Unix seconds.
    pub last_updated_unix: Option<JsU64>,
}
#[napi(object)]
/// Scoreboard boost configuration for a specific provider.
pub struct JsProviderBoost {
    /// Provider identifier to adjust.
    pub provider: String,
    /// Signed adjustment applied to the provider score.
    pub delta: i32,
}
#[napi(object)]
/// Scoreboard entry summarising eligibility and weighted score.
pub struct JsScoreboardEntry {
    /// Provider identifier tied to the scoreboard record.
    pub provider_id: String,
    /// Alias used for presenting the provider.
    pub alias: String,
    /// Raw score computed by the scoreboard.
    pub raw_score: f64,
    /// Normalised weight applied to scheduling decisions.
    pub normalized_weight: f64,
    /// Eligibility status string (or reason when ineligible).
    pub eligibility: String,
}
#[napi(object)]
#[derive(Default)]
/// Optional tuning knobs for the local multi-fetch helper.
pub struct JsMultiFetchOptions {
    /// Toggle Norito digest verification for each chunk.
    pub verify_digests: Option<bool>,
    /// Toggle byte-length verification for each chunk.
    pub verify_lengths: Option<bool>,
    /// Maximum number of retry attempts per chunk (>= 1).
    pub retry_budget: Option<u32>,
    /// Consecutive provider failures tolerated before disabling it.
    pub provider_failure_threshold: Option<u32>,
    /// Global parallelism limit applied to the orchestrator.
    pub max_parallel: Option<u32>,
    /// Upper bound for the number of providers considered eligible.
    pub max_peers: Option<u32>,
    /// Optional chunker handle used when deriving scoreboard plans.
    pub chunker_handle: Option<String>,
    /// Optional telemetry entries used when computing scoreboard weights.
    pub telemetry: Option<Vec<JsTelemetryEntry>>,
    /// Whether to derive provider weights from metadata + telemetry.
    pub use_scoreboard: Option<bool>,
    /// Override the scoreboard reference timestamp (Unix seconds).
    pub scoreboard_now_unix_secs: Option<JsU64>,
    /// Providers to skip deterministically via the scoring policy.
    pub deny_providers: Option<Vec<String>>,
    /// Providers to boost (positive) or penalise (negative) during scheduling.
    pub boost_providers: Option<Vec<JsProviderBoost>>,
    /// Include the computed scoreboard entries in the return payload.
    pub return_scoreboard: Option<bool>,
}
#[napi(object)]
/// Aggregate provider statistics produced by a multi-fetch run.
pub struct JsMultiFetchProviderReport {
    /// Provider identifier.
    pub provider: String,
    /// Number of successful chunk deliveries.
    pub successes: u32,
    /// Number of failed chunk attempts.
    pub failures: u32,
    /// Whether the provider was disabled due to failures.
    pub disabled: bool,
}
#[napi(object)]
/// Per-chunk execution details returned from multi-fetch.
pub struct JsMultiFetchChunkReceipt {
    /// Chunk index within the plan.
    pub chunk_index: u32,
    /// Provider that supplied the chunk.
    pub provider: String,
    /// Total attempts required until success.
    pub attempts: u32,
    /// Latency of the successful attempt in milliseconds.
    pub latency_ms: f64,
    /// Size of the chunk payload in bytes.
    pub bytes: u32,
}
#[napi(object)]
/// Result payload produced by `sorafsMultiFetchLocal`.
pub struct JsMultiFetchResult {
    /// Number of chunks assembled into the final payload.
    pub chunk_count: u32,
    /// Concatenated chunk payload (`CARv2` body) once the fetch completes.
    pub payload: Buffer,
    /// Summary statistics for each participating provider.
    pub provider_reports: Vec<JsMultiFetchProviderReport>,
    /// Receipts describing how each chunk was downloaded.
    pub chunk_receipts: Vec<JsMultiFetchChunkReceipt>,
    /// Optional scoreboard entries used for the fetch session.
    pub scoreboard: Option<Vec<JsScoreboardEntry>>,
}
/// Options controlling DA proof generation behaviour.
#[napi(object)]
#[derive(Default)]
pub struct JsDaProofOptions {
    /// Number of `PoR` leaves to sample deterministically (default: 8, min: 0).
    pub sample_count: Option<u32>,
    /// Seed forwarded to the deterministic sampler (default: 0).
    pub sample_seed: Option<JsU64>,
    /// Explicit `PoR` leaf indexes to verify.
    pub leaf_indexes: Option<Vec<u32>>,
}
/// Single proof-of-retrievability record returned to JavaScript callers.
#[derive(Clone)]
#[napi(object)]
pub struct JsDaProofRecord {
    /// Whether this proof was produced via sampling or explicit indexes.
    pub origin: String,
    /// Zero-based global leaf index covered by the proof.
    pub leaf_index: u32,
    /// Chunk index containing the leaf.
    pub chunk_index: u32,
    /// Segment index containing the leaf.
    pub segment_index: u32,
    /// Byte offset of the leaf slice.
    pub leaf_offset: JsU64,
    /// Leaf length in bytes.
    pub leaf_length: u32,
    #[doc = "Byte offset of the enclosing segment."]
    pub segment_offset: JsU64,
    #[doc = "Segment length in bytes."]
    pub segment_length: u32,
    #[doc = "Byte offset of the enclosing chunk."]
    pub chunk_offset: JsU64,
    #[doc = "Chunk length in bytes."]
    pub chunk_length: u32,
    #[doc = "Total payload length observed while proving."]
    pub payload_len: JsU64,
    #[doc = "Hex-encoded chunk digest."]
    pub chunk_digest_hex: String,
    #[doc = "Hex-encoded chunk Merkle root."]
    pub chunk_root_hex: String,
    #[doc = "Hex-encoded segment digest."]
    pub segment_digest_hex: String,
    #[doc = "Hex-encoded leaf digest."]
    pub leaf_digest_hex: String,
    #[doc = "Base64-encoded leaf bytes."]
    pub leaf_bytes_b64: String,
    #[doc = "Hex digests of sibling leaves within the segment."]
    pub segment_leaves_hex: Vec<String>,
    #[doc = "Hex digests for each segment-level branch."]
    pub chunk_segments_hex: Vec<String>,
    #[doc = "Total number of chunks committed by the `PoR` root."]
    pub chunk_count: JsU64,
    #[doc = "Hex digests in the chunk-level Merkle authentication path."]
    pub chunk_merkle_path_hex: Vec<String>,
    #[doc = "Whether the proof verified against the supplied root."]
    pub verified: bool,
}
/// Summary describing manifest/payload `PoR` verification results.
#[napi(object)]
pub struct JsDaProofSummary {
    #[doc = "Hex-encoded manifest blob hash."]
    pub blob_hash_hex: String,
    #[doc = "Hex-encoded manifest chunk root."]
    pub chunk_root_hex: String,
    #[doc = "Hex-encoded `PoR` root derived from the payload."]
    pub por_root_hex: String,
    #[doc = "Total number of leaves observed."]
    pub leaf_count: JsU64,
    #[doc = "Total number of segments observed."]
    pub segment_count: JsU64,
    #[doc = "Total number of chunks observed."]
    pub chunk_count: JsU64,
    #[doc = "Number of deterministically sampled proofs."]
    pub sample_count: u32,
    #[doc = "Seed used for deterministic sampling."]
    pub sample_seed: JsU64,
    #[doc = "Number of proofs returned (sampled + explicit)."]
    pub proof_count: u32,
    #[doc = "Individual proof records corresponding to the manifest/payload set."]
    pub proofs: Vec<JsDaProofRecord>,
}
#[derive(Clone)]
struct DaProofOptionsNormalized {
    sample_count: usize,
    sample_seed: u64,
    explicit_indexes: Vec<usize>,
}
impl DaProofOptionsNormalized {
    fn from_js(options: Option<JsDaProofOptions>) -> napi::Result<Self> {
        let sample_count = options
            .as_ref()
            .and_then(|opts| opts.sample_count)
            .unwrap_or(8);
        let sample_seed = options
            .as_ref()
            .and_then(|opts| opts.sample_seed)
            .map_or(0, |seed| seed.0);
        let explicit_indexes = options
            .and_then(|opts| opts.leaf_indexes)
            .unwrap_or_default()
            .into_iter()
            .map(|value| {
                usize::try_from(value)
                    .map_err(|_| invalid_arg("leafIndexes entries must fit within usize"))
            })
            .collect::<napi::Result<Vec<_>>>()?;
        Ok(Self {
            sample_count: usize::try_from(sample_count)
                .map_err(|_| invalid_arg("sampleCount must fit within usize"))?,
            sample_seed,
            explicit_indexes,
        })
    }
}
#[derive(Clone, Copy)]
enum ProofOrigin {
    Sampled,
    Explicit,
}
impl ProofOrigin {
    fn label(self) -> &'static str {
        match self {
            Self::Sampled => "sampled",
            Self::Explicit => "explicit",
        }
    }
}
struct ProofReport {
    origin: ProofOrigin,
    leaf_index: usize,
    proof: PorProof,
    verified: bool,
}
fn build_car_plan_from_manifest(manifest: &DaManifestV1) -> napi::Result<CarBuildPlan> {
    iroha_storage_client::da::build_car_plan_from_manifest(manifest)
        .map_err(|err| invalid_arg(format!("failed to build CAR plan: {err}")))
}
fn validate_manifest_consistency(manifest: &DaManifestV1, store: &ChunkStore) -> napi::Result<()> {
    let blob_hash_bytes = manifest.blob_hash.as_ref();
    if store.payload_digest().as_bytes() != blob_hash_bytes {
        return Err(napi::Error::from_reason(format!(
            "payload hash mismatch: manifest={} computed={}",
            hex::encode(blob_hash_bytes),
            hex::encode(store.payload_digest().as_bytes())
        )));
    }
    let chunk_root_bytes = manifest.chunk_root.as_ref();
    if store.por_tree().root() != chunk_root_bytes {
        return Err(napi::Error::from_reason(format!(
            "chunk root mismatch: manifest={} computed={}",
            hex::encode(chunk_root_bytes),
            hex::encode(store.por_tree().root())
        )));
    }
    Ok(())
}
#[allow(clippy::needless_pass_by_value)]
fn chunk_store_err(err: ChunkStoreError) -> napi::Error {
    napi::Error::from_reason(format!("chunk store error: {err}"))
}
fn collect_sampled_proofs(
    store: &ChunkStore,
    payload: &[u8],
    options: &DaProofOptionsNormalized,
    por_root: &[u8; 32],
) -> napi::Result<Vec<ProofReport>> {
    if options.sample_count == 0 {
        return Ok(Vec::new());
    }
    let mut source = InMemoryPayload::new(payload);
    let samples = store
        .sample_leaves_with(options.sample_count, options.sample_seed, &mut source)
        .map_err(chunk_store_err)?;
    Ok(samples
        .into_iter()
        .map(|(idx, proof)| ProofReport {
            origin: ProofOrigin::Sampled,
            leaf_index: idx,
            verified: proof.verify(por_root),
            proof,
        })
        .collect())
}
fn collect_explicit_proofs(
    store: &ChunkStore,
    payload: &[u8],
    options: &DaProofOptionsNormalized,
    por_root: &[u8; 32],
) -> napi::Result<Vec<ProofReport>> {
    if options.explicit_indexes.is_empty() {
        return Ok(Vec::new());
    }
    let mut source = InMemoryPayload::new(payload);
    let mut proofs = Vec::with_capacity(options.explicit_indexes.len());
    let mut seen = HashSet::new();
    for &leaf_index in &options.explicit_indexes {
        if !seen.insert(leaf_index) {
            continue;
        }
        let (chunk_idx, segment_idx, inner_idx) = store
            .por_tree()
            .leaf_path(leaf_index)
            .ok_or_else(|| invalid_arg(format!("leaf_index {leaf_index} out of range")))?;
        let proof = store
            .por_tree()
            .prove_leaf_with(chunk_idx, segment_idx, inner_idx, &mut source)
            .map_err(chunk_store_err)?
            .ok_or_else(|| invalid_arg(format!("missing PoR proof for leaf_index {leaf_index}")))?;
        proofs.push(ProofReport {
            origin: ProofOrigin::Explicit,
            leaf_index,
            verified: proof.verify(por_root),
            proof,
        });
    }
    Ok(proofs)
}
fn hex_list(values: &[[u8; 32]]) -> Vec<String> {
    values.iter().map(hex::encode).collect()
}
fn proof_to_js_record(report: &ProofReport) -> JsDaProofRecord {
    JsDaProofRecord {
        origin: report.origin.label().to_string(),
        leaf_index: u32::try_from(report.leaf_index).unwrap_or(u32::MAX),
        chunk_index: u32::try_from(report.proof.chunk_index).unwrap_or(u32::MAX),
        segment_index: u32::try_from(report.proof.segment_index).unwrap_or(u32::MAX),
        leaf_offset: JsU64(report.proof.leaf_offset),
        leaf_length: report.proof.leaf_length,
        segment_offset: JsU64(report.proof.segment_offset),
        segment_length: report.proof.segment_length,
        chunk_offset: JsU64(report.proof.chunk_offset),
        chunk_length: report.proof.chunk_length,
        payload_len: JsU64(report.proof.payload_len),
        chunk_digest_hex: hex::encode(report.proof.chunk_digest),
        chunk_root_hex: hex::encode(report.proof.chunk_root),
        segment_digest_hex: hex::encode(report.proof.segment_digest),
        leaf_digest_hex: hex::encode(report.proof.leaf_digest),
        leaf_bytes_b64: STANDARD.encode(&report.proof.leaf_bytes),
        segment_leaves_hex: hex_list(&report.proof.segment_leaves),
        chunk_segments_hex: hex_list(&report.proof.chunk_segments),
        chunk_count: JsU64(report.proof.chunk_count),
        chunk_merkle_path_hex: hex_list(&report.proof.chunk_merkle_path),
        verified: report.verified,
    }
}
#[napi(object)]
/// Norito bridge configuration for the local QUIC proxy.
pub struct JsProxyNoritoBridgeConfig {
    /// Directory where Norito payloads are spooled.
    pub spool_dir: String,
    /// Optional file extension applied to spool artefacts.
    pub extension: Option<String>,
}
#[napi(object)]
/// CAR bridge configuration for the local QUIC proxy.
pub struct JsProxyCarBridgeConfig {
    /// Directory where CAR archives are cached.
    pub cache_dir: String,
    /// Optional file extension applied to cached archives.
    pub extension: Option<String>,
    /// Whether `.zst` archives are permitted.
    pub allow_zst: Option<bool>,
}
#[napi(object)]
/// Kaigi bridge configuration for the local QUIC proxy.
pub struct JsProxyKaigiBridgeConfig {
    /// Directory where Kaigi spool entries are stored.
    pub spool_dir: String,
    /// Optional file extension applied to Kaigi spool files.
    pub extension: Option<String>,
    /// Optional room policy label (`public` or `authenticated`).
    pub room_policy: Option<String>,
}
#[napi(object)]
/// Optional local QUIC proxy configuration surfaced to gateway fetches.
pub struct JsLocalProxyConfig {
    /// Bind address (e.g. `127.0.0.1:0`) for the proxy.
    pub bind_addr: Option<String>,
    /// Telemetry label attached to proxy metrics.
    pub telemetry_label: Option<String>,
    /// Optional guard cache key rendered as hexadecimal.
    pub guard_cache_key_hex: Option<String>,
    /// Whether to emit browser manifests in the handshake.
    pub emit_browser_manifest: Option<bool>,
    /// Proxy mode label (`bridge` or `metadata-only`).
    pub proxy_mode: Option<String>,
    /// Whether circuits should be pre-warmed.
    pub prewarm_circuits: Option<bool>,
    /// Maximum concurrent streams per circuit.
    pub max_streams_per_circuit: Option<u32>,
    /// Suggested circuit TTL in seconds.
    pub circuit_ttl_hint_secs: Option<u32>,
    /// Optional Norito bridge configuration.
    pub norito_bridge: Option<JsProxyNoritoBridgeConfig>,
    /// Optional CAR bridge configuration.
    pub car_bridge: Option<JsProxyCarBridgeConfig>,
    /// Optional Kaigi bridge configuration.
    pub kaigi_bridge: Option<JsProxyKaigiBridgeConfig>,
}
#[napi(object)]
#[derive(Default)]
/// Options controlling `sorafsGatewayFetch`.
pub struct JsGatewayFetchOptions {
    /// Base64-encoded manifest envelope forwarded to providers.
    pub manifest_envelope_b64: Option<String>,
    /// Expected manifest CID expressed as hexadecimal.
    pub manifest_cid_hex: Option<String>,
    /// Expected cache version advertised by successful gateway responses.
    pub cache_version: Option<String>,
    /// Optional client identifier forwarded via headers.
    pub client_id: Option<String>,
    /// Telemetry region label attached to orchestrator metrics.
    pub telemetry_region: Option<String>,
    /// Rollout phase label controlling the default anonymity policy.
    pub rollout_phase: Option<String>,
    /// Maximum number of providers considered for the session.
    pub max_peers: Option<u32>,
    /// Retry budget applied per chunk (minimum 1).
    pub retry_budget: Option<u32>,
    /// Transport policy label (`soranet-first`, `soranet-strict`, `direct-only`).
    pub transport_policy: Option<String>,
    /// Anonymity policy label (`anon-guard-pq`, `anon-majority-pq`, `anon-strict-pq`).
    pub anonymity_policy: Option<String>,
    /// Write-mode hint controlling PQ enforcement (`read-only`, `upload-pq-only`).
    pub write_mode: Option<String>,
    /// Optional local proxy configuration for browser integrations.
    pub local_proxy: Option<JsLocalProxyConfig>,
    /// File path used to persist the computed scoreboard (mirrors `--scoreboard-out`).
    pub scoreboard_out_path: Option<String>,
    /// Override for the Unix timestamp used when evaluating adverts (`--scoreboard-now`).
    pub scoreboard_now_unix_secs: Option<JsU64>,
    /// Optional label recorded as the scoreboard `telemetry_source`.
    pub scoreboard_telemetry_label: Option<String>,
    /// Whether implicit provider metadata was allowed during scoring (metadata hint).
    pub scoreboard_allow_implicit_metadata: Option<bool>,
    /// Whether the caller allowed a temporary downgrade to a single provider.
    pub allow_single_source_fallback: Option<bool>,
}
#[napi(object)]
/// Gateway provider descriptor supplied to orchestrator fetches.
pub struct JsGatewayProviderSpec {
    /// Human-readable provider name.
    pub name: String,
    /// Provider identifier rendered as 32-byte hexadecimal.
    pub provider_id_hex: String,
    /// Ed25519 key that verifies the provider's stream token, as 32-byte hex.
    pub gateway_public_key_hex: String,
    /// Base URL for the Torii gateway.
    pub base_url: String,
    /// Stream token presented when fetching chunks.
    pub stream_token_b64: String,
    /// Optional privacy events endpoint.
    pub privacy_events_url: Option<String>,
}
#[napi(object)]
/// CAR archive statistics returned after verification.
pub struct JsCarArchiveStats {
    /// Total CAR archive size in bytes.
    pub size: JsU64,
    /// Hex-encoded digest of the CAR payload section.
    pub payload_digest_hex: String,
    /// Hex-encoded digest of the full CAR archive.
    pub archive_digest_hex: String,
    /// CID rendered as hexadecimal.
    pub cid_hex: String,
    /// Root CIDs for the archive rendered as hexadecimal.
    pub root_cids_hex: Vec<String>,
    /// Whether verification succeeded.
    pub verified: bool,
    /// Number of `PoR` leaves observed during verification.
    pub por_leaf_count: JsU64,
}
#[napi(object)]
/// Council signature exported from a manifest governance proof bundle.
pub struct JsCouncilSignature {
    /// Signer identifier rendered as hexadecimal.
    pub signer_hex: String,
    /// Raw signature rendered as hexadecimal.
    pub signature_hex: String,
}
#[napi(object)]
/// Governance proofs bundled with the manifest.
pub struct JsManifestGovernance {
    /// Council signatures authorising the manifest.
    pub council_signatures: Vec<JsCouncilSignature>,
}
#[napi(object)]
/// CAR verification artefacts emitted after gateway fetches.
pub struct JsCarVerification {
    /// Hex digest of the manifest.
    pub manifest_digest_hex: String,
    /// Hex digest of the manifest payload.
    pub manifest_payload_digest_hex: String,
    /// Hex digest of the CAR archive recorded in the manifest.
    pub manifest_car_digest_hex: String,
    /// Manifest-declared content length.
    pub manifest_content_length: JsU64,
    /// Manifest-declared chunk count.
    pub manifest_chunk_count: JsU64,
    /// Chunk profile handle advertised by the manifest.
    pub manifest_chunk_profile_handle: String,
    /// Governance proofs bundled with the manifest.
    pub manifest_governance: JsManifestGovernance,
    /// CAR archive statistics.
    pub car_archive: JsCarArchiveStats,
}
#[napi(object)]
/// Result payload produced by `sorafsGatewayFetch`.
pub struct JsGatewayFetchResult {
    /// Manifest identifier rendered as hexadecimal.
    pub manifest_id_hex: String,
    /// Chunker handle used for the session.
    pub chunker_handle: String,
    /// Number of chunks assembled.
    pub chunk_count: u32,
    /// Total assembled bytes.
    pub assembled_bytes: JsU64,
    /// Concatenated payload (`CARv2` body).
    pub payload: Buffer,
    /// Optional telemetry region label.
    pub telemetry_region: Option<String>,
    /// Requested anonymity policy label.
    pub anonymity_policy: String,
    /// Resulting policy status label.
    pub anonymity_status: String,
    /// Reason for policy fallback, if any.
    pub anonymity_reason: String,
    /// Number of `SoraNet` providers selected.
    pub anonymity_soranet_selected: u32,
    /// Number of PQ-capable providers selected.
    pub anonymity_pq_selected: u32,
    /// Number of classical providers selected.
    pub anonymity_classical_selected: u32,
    /// Ratio of classical providers in the selection.
    pub anonymity_classical_ratio: f64,
    /// Ratio of PQ-capable providers in the selection.
    pub anonymity_pq_ratio: f64,
    /// Ratio of PQ-capable candidates in the scoreboard.
    pub anonymity_candidate_ratio: f64,
    /// PQ deficit ratio relative to the requested policy.
    pub anonymity_deficit_ratio: f64,
    /// PQ supply delta between candidates and selection.
    pub anonymity_supply_delta: f64,
    /// Whether a brownout occurred.
    pub anonymity_brownout: bool,
    /// Whether the brownout should trigger operator alerts.
    pub anonymity_brownout_effective: bool,
    /// Whether classical providers participated.
    pub anonymity_uses_classical: bool,
    /// Provider-level outcome reports.
    pub provider_reports: Vec<JsMultiFetchProviderReport>,
    /// Per-chunk receipts summarising fetch attempts.
    pub chunk_receipts: Vec<JsMultiFetchChunkReceipt>,
    /// Browser manifest rendered as JSON when a local proxy is active.
    pub local_proxy_manifest_json: Option<String>,
    /// Manifest/CAR verification metadata.
    pub car_verification: Option<JsCarVerification>,
    /// Scoreboard metadata captured during the fetch session.
    pub metadata: JsGatewayMetadata,
}
#[napi(object)]
#[allow(clippy::struct_excessive_bools)]
/// Scoreboard metadata emitted by the gateway orchestrator.
pub struct JsGatewayMetadata {
    /// Number of direct `SoraNet` providers participating in the session.
    pub provider_count: JsU64,
    /// Number of Torii gateway providers participating in the session.
    pub gateway_provider_count: JsU64,
    /// Provider-mix label derived from the direct/gateway counts.
    pub provider_mix: String,
    /// Requested transport policy label.
    pub transport_policy: String,
    /// Whether a transport-policy override was applied.
    pub transport_policy_override: bool,
    /// Optional label describing the override that was applied.
    pub transport_policy_override_label: Option<String>,
    /// Requested anonymity policy label.
    pub anonymity_policy: String,
    /// Whether an anonymity-policy override was applied.
    pub anonymity_policy_override: bool,
    /// Optional label describing the anonymity override that was applied.
    pub anonymity_policy_override_label: Option<String>,
    /// Write-mode hint applied during the session.
    pub write_mode: String,
    /// Whether the write-mode enforces PQ-only transport.
    pub write_mode_enforces_pq: bool,
    /// Maximum number of parallel chunks fetched per batch.
    pub max_parallel: Option<JsU64>,
    /// Maximum number of providers considered for the session.
    pub max_peers: Option<JsU64>,
    /// Retry budget enforced per chunk.
    pub retry_budget: Option<JsU64>,
    /// Provider failure threshold enforced by the orchestrator.
    pub provider_failure_threshold: JsU64,
    /// Unix timestamp used when evaluating provider adverts.
    pub assume_now_unix: JsU64,
    /// Telemetry label recorded for the capture.
    pub telemetry_source_label: Option<String>,
    /// Telemetry region label recorded for the capture.
    pub telemetry_region: Option<String>,
    /// Whether a signed gateway manifest envelope was supplied.
    pub gateway_manifest_provided: bool,
    /// Optional manifest identifier recorded for the capture.
    pub gateway_manifest_id: Option<String>,
    /// Optional manifest CID recorded for the capture.
    pub gateway_manifest_cid: Option<String>,
    /// Whether downgrades to a single provider were permitted.
    pub allow_single_source_fallback: bool,
    /// Whether implicit provider metadata was allowed when scoring adverts.
    pub allow_implicit_metadata: bool,
}
fn js_range_capability_to_input(range: JsRangeCapability) -> RangeCapabilityInput {
    RangeCapabilityInput {
        max_chunk_span: range.max_chunk_span,
        min_granularity: range.min_granularity,
        supports_sparse_offsets: range.supports_sparse_offsets,
        requires_alignment: range.requires_alignment,
        supports_merkle_proof: range.supports_merkle_proof,
    }
}
fn js_stream_budget_to_input(budget: JsStreamBudget) -> StreamBudgetInput {
    StreamBudgetInput {
        max_in_flight: budget.max_in_flight,
        max_bytes_per_sec: budget.max_bytes_per_sec.into(),
        burst_bytes: budget.burst_bytes.map(Into::into),
    }
}
fn js_transport_hints_to_input(hints: &[JsTransportHint]) -> Vec<TransportHintInput> {
    hints
        .iter()
        .map(|hint| TransportHintInput {
            protocol: hint.protocol.clone(),
            protocol_id: hint.protocol_id,
            priority: hint.priority,
        })
        .collect()
}
fn js_metadata_to_input(metadata: JsProviderMetadata, alias: &str) -> ProviderMetadataInput {
    let JsProviderMetadata {
        provider_id,
        profile_id,
        profile_aliases,
        availability,
        stake_amount,
        max_streams,
        refresh_deadline,
        expires_at,
        ttl_secs,
        allow_unknown_capabilities,
        capability_names,
        rendezvous_topics,
        notes,
        range_capability,
        stream_budget,
        transport_hints,
    } = metadata;
    ProviderMetadataInput {
        provider_id: Some(provider_id.unwrap_or_else(|| alias.to_string())),
        profile_id,
        profile_aliases,
        availability,
        stake_amount,
        max_streams,
        refresh_deadline: refresh_deadline.map(Into::into),
        expires_at: expires_at.map(Into::into),
        ttl_secs: ttl_secs.map(Into::into),
        allow_unknown_capabilities,
        capability_names,
        rendezvous_topics,
        notes,
        range_capability: range_capability.map(js_range_capability_to_input),
        stream_budget: stream_budget.map(js_stream_budget_to_input),
        transport_hints: transport_hints.map(|hints| js_transport_hints_to_input(&hints)),
    }
}
#[allow(clippy::unnecessary_wraps)]
fn js_provider_to_local(spec: JsLocalProviderSpec) -> napi::Result<LocalProviderInput> {
    let metadata = match spec.metadata {
        Some(meta) => Some(js_metadata_to_input(meta, &spec.name)),
        None => None,
    };
    Ok(LocalProviderInput {
        name: spec.name,
        path: PathBuf::from(spec.path),
        max_concurrent: spec.max_concurrent,
        weight: spec.weight,
        metadata,
    })
}
fn js_telemetry_to_inputs(entries: &[JsTelemetryEntry]) -> Vec<TelemetryEntryInput> {
    entries
        .iter()
        .map(|entry| TelemetryEntryInput {
            provider_id: entry.provider_id.clone(),
            qos_score: entry.qos_score,
            latency_p95_ms: entry.latency_p95_ms,
            failure_rate_ewma: entry.failure_rate_ewma,
            token_health: entry.token_health,
            staking_weight: entry.staking_weight,
            reputation_score_bps: entry.reputation_score_bps,
            penalty: entry.penalty,
            last_updated_unix: entry.last_updated_unix.map(Into::into),
        })
        .collect()
}
#[allow(clippy::unnecessary_wraps)]
fn build_local_fetch_options(
    options: Option<JsMultiFetchOptions>,
) -> napi::Result<LocalFetchOptions> {
    let mut local = LocalFetchOptions::default();
    if let Some(opts) = options {
        local.verify_digests = opts.verify_digests;
        local.verify_lengths = opts.verify_lengths;
        local.retry_budget = opts.retry_budget;
        local.provider_failure_threshold = opts.provider_failure_threshold;
        local.max_parallel = opts.max_parallel;
        local.max_peers = opts.max_peers;
        local.chunker_handle = opts.chunker_handle;
        if let Some(entries) = opts.telemetry {
            local.telemetry = js_telemetry_to_inputs(&entries);
        }
        local.use_scoreboard = opts.use_scoreboard;
        local.scoreboard_now_unix_secs = opts.scoreboard_now_unix_secs.map(Into::into);
        if let Some(mut deny) = opts.deny_providers {
            local.deny_providers.append(&mut deny);
        }
        if let Some(boosts) = opts.boost_providers {
            local.boost_providers = boosts
                .into_iter()
                .map(|boost| (boost.provider, i64::from(boost.delta)))
                .collect();
        }
        local.return_scoreboard = opts.return_scoreboard;
    }
    Ok(local)
}
fn local_fetch_result_to_js(
    result: local_fetch::LocalFetchResult,
) -> napi::Result<JsMultiFetchResult> {
    let chunk_count = u32::try_from(result.chunk_count).map_err(|_| {
        napi::Error::new(
            napi::Status::GenericFailure,
            "chunk count exceeds JavaScript number range",
        )
    })?;
    let payload = Buffer::from(result.outcome.assemble_payload());
    let mut provider_reports = Vec::with_capacity(result.outcome.provider_reports.len());
    for report in &result.outcome.provider_reports {
        provider_reports.push(JsMultiFetchProviderReport {
            provider: report.provider.id().as_str().to_string(),
            successes: u32::try_from(report.successes).map_err(|_| {
                napi::Error::new(
                    napi::Status::GenericFailure,
                    "provider success count exceeds JavaScript number range",
                )
            })?,
            failures: u32::try_from(report.failures).map_err(|_| {
                napi::Error::new(
                    napi::Status::GenericFailure,
                    "provider failure count exceeds JavaScript number range",
                )
            })?,
            disabled: report.disabled,
        });
    }
    let mut chunk_receipts = Vec::with_capacity(result.outcome.chunk_receipts.len());
    for receipt in &result.outcome.chunk_receipts {
        chunk_receipts.push(JsMultiFetchChunkReceipt {
            chunk_index: u32::try_from(receipt.chunk_index).map_err(|_| {
                napi::Error::new(
                    napi::Status::GenericFailure,
                    "chunk index exceeds JavaScript number range",
                )
            })?,
            provider: receipt.provider.as_str().to_string(),
            attempts: u32::try_from(receipt.attempts).map_err(|_| {
                napi::Error::new(
                    napi::Status::GenericFailure,
                    "chunk attempt count exceeds JavaScript number range",
                )
            })?,
            latency_ms: receipt.latency_ms,
            bytes: receipt.bytes,
        });
    }
    let scoreboard = result.scoreboard.map(|entries| {
        entries
            .into_iter()
            .map(|entry| JsScoreboardEntry {
                provider_id: entry.provider_id,
                alias: entry.alias,
                raw_score: entry.raw_score,
                normalized_weight: entry.normalized_weight,
                eligibility: entry.eligibility,
            })
            .collect()
    });
    Ok(JsMultiFetchResult {
        chunk_count,
        payload,
        provider_reports,
        chunk_receipts,
        scoreboard,
    })
}
fn proxy_mode_from_label(label: &str) -> napi::Result<ProxyMode> {
    ProxyMode::parse(label).ok_or_else(|| {
        invalid_arg(format!(
            "proxy_mode must be one of 'bridge' or 'metadata-only', got '{label}'"
        ))
    })
}
fn build_local_proxy_config(cfg: &JsLocalProxyConfig) -> napi::Result<LocalQuicProxyConfig> {
    let mut proxy = LocalQuicProxyConfig::default();
    if let Some(bind) = cfg.bind_addr.as_ref() {
        let trimmed = bind.trim();
        if trimmed.is_empty() {
            return Err(invalid_arg(
                "localProxy.bindAddr must not be empty when provided",
            ));
        }
        proxy.bind_addr = trimmed.to_string();
    }
    proxy.telemetry_label = cfg
        .telemetry_label
        .as_ref()
        .map(|label| label.trim().to_string());
    proxy.guard_cache_key_hex = cfg
        .guard_cache_key_hex
        .as_ref()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(flag) = cfg.emit_browser_manifest {
        proxy.emit_browser_manifest = flag;
    }
    if let Some(mode) = cfg.proxy_mode.as_ref() {
        proxy.proxy_mode = proxy_mode_from_label(mode)?;
    }
    if let Some(prewarm) = cfg.prewarm_circuits {
        proxy.prewarm_circuits = prewarm;
    }
    proxy.max_streams_per_circuit = cfg.max_streams_per_circuit;
    proxy.circuit_ttl_hint_secs = cfg.circuit_ttl_hint_secs;
    if let Some(norito_cfg) = cfg.norito_bridge.as_ref() {
        let trimmed = norito_cfg.spool_dir.trim();
        if trimmed.is_empty() {
            return Err(invalid_arg(
                "localProxy.noritoBridge.spoolDir must not be empty when provided",
            ));
        }
        proxy.norito_bridge = Some(ProxyNoritoBridgeConfig {
            spool_dir: trimmed.to_string(),
            extension: norito_cfg
                .extension
                .as_ref()
                .map(|ext| ext.trim().to_string())
                .filter(|ext| !ext.is_empty()),
        });
    }
    if let Some(car_cfg) = cfg.car_bridge.as_ref() {
        let trimmed = car_cfg.cache_dir.trim();
        if trimmed.is_empty() {
            return Err(invalid_arg(
                "localProxy.carBridge.cacheDir must not be empty when provided",
            ));
        }
        proxy.car_bridge = Some(ProxyCarBridgeConfig {
            cache_dir: trimmed.to_string(),
            extension: car_cfg
                .extension
                .as_ref()
                .map(|ext| ext.trim().to_string())
                .filter(|ext| !ext.is_empty()),
            allow_zst: car_cfg.allow_zst.unwrap_or(false),
        });
    }
    if let Some(kaigi_cfg) = cfg.kaigi_bridge.as_ref() {
        let trimmed = kaigi_cfg.spool_dir.trim();
        if trimmed.is_empty() {
            return Err(invalid_arg(
                "localProxy.kaigiBridge.spoolDir must not be empty when provided",
            ));
        }
        let mut bridge = ProxyKaigiBridgeConfig {
            spool_dir: trimmed.to_string(),
            extension: kaigi_cfg
                .extension
                .as_ref()
                .map(|ext| ext.trim().to_string())
                .filter(|ext| !ext.is_empty()),
            room_policy: None,
        };
        if let Some(policy) = kaigi_cfg.room_policy.as_ref() {
            let normalized = policy.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "public" | "authenticated" => {
                    bridge.room_policy = Some(normalized);
                }
                _ => {
                    return Err(invalid_arg(
                        "localProxy.kaigiBridge.roomPolicy must be `public` or `authenticated`",
                    ));
                }
            }
        }
        proxy.kaigi_bridge = Some(bridge);
    }
    Ok(proxy)
}
fn build_gateway_provider_input(
    spec: &JsGatewayProviderSpec,
) -> napi::Result<GatewayProviderInput> {
    let name = spec.name.trim().to_string();
    if name.is_empty() {
        return Err(invalid_arg("provider name must not be empty"));
    }
    let provider_id = spec.provider_id_hex.trim().to_ascii_lowercase();
    if provider_id.len() != 64 || !provider_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid_arg(format!(
            "provider '{name}' has invalid providerIdHex; expected 32-byte hex"
        )));
    }
    let gateway_public_key = spec.gateway_public_key_hex.trim().to_ascii_lowercase();
    if gateway_public_key.len() != 64
        || !gateway_public_key
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(invalid_arg(format!(
            "provider '{name}' has invalid gatewayPublicKeyHex; expected 32-byte hex"
        )));
    }
    let base_url = spec.base_url.trim();
    if base_url.is_empty() {
        return Err(invalid_arg(format!(
            "provider '{name}' baseUrl must not be empty"
        )));
    }
    let stream_token = spec.stream_token_b64.trim();
    if stream_token.is_empty() {
        return Err(invalid_arg(format!(
            "provider '{name}' streamToken must not be empty"
        )));
    }
    let privacy_url = spec
        .privacy_events_url
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    Ok(GatewayProviderInput {
        name,
        provider_id_hex: provider_id,
        gateway_public_key_hex: gateway_public_key,
        base_url: base_url.to_string(),
        stream_token_b64: stream_token.to_string(),
        privacy_events_url: privacy_url,
    })
}
fn manifest_envelope_from_options(options: &JsGatewayFetchOptions) -> Option<String> {
    options
        .manifest_envelope_b64
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
fn client_id_from_options(options: &JsGatewayFetchOptions) -> Option<String> {
    options
        .client_id
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
fn build_gateway_fetch_config(
    manifest_id_hex: &str,
    chunker_handle: &str,
    options: &JsGatewayFetchOptions,
) -> napi::Result<GatewayFetchConfig> {
    let manifest_envelope_b64 = manifest_envelope_from_options(options);
    let client_id = client_id_from_options(options);
    let expected_cid_hex = options
        .manifest_cid_hex
        .as_ref()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let expected_cache_version = options
        .cache_version
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if let Some(ref cid) = expected_cid_hex
        && (cid.len() != 64 || !cid.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(invalid_arg(
            "manifestCidHex must be a 32-byte hex string when provided",
        ));
    }
    Ok(GatewayFetchConfig {
        manifest_id_hex: manifest_id_hex.to_string(),
        chunker_handle: chunker_handle.to_string(),
        manifest_envelope_b64,
        client_id,
        expected_manifest_cid_hex: expected_cid_hex,
        blinded_cid_b64: None,
        salt_epoch: None,
        expected_cache_version,
    })
}
fn build_gateway_plan(
    specs: &[ChunkFetchSpec],
    payload_digest: [u8; 32],
    chunker_handle: &str,
) -> napi::Result<CarBuildPlan> {
    let descriptor = sorafs_car::chunker_registry::lookup_by_handle(chunker_handle)
        .ok_or_else(|| invalid_arg(format!("unknown chunker handle '{chunker_handle}'")))?;
    let content_length = specs
        .iter()
        .map(|spec| spec.offset + u64::from(spec.length))
        .max()
        .unwrap_or(0);
    let chunks = specs
        .iter()
        .map(|spec| CarChunk {
            offset: spec.offset,
            length: spec.length,
            digest: spec.digest,
        })
        .collect();
    Ok(CarBuildPlan {
        chunk_profile: descriptor.profile,
        payload_digest: blake3::Hash::from_bytes(payload_digest),
        content_length,
        chunks,
        files: vec![FilePlan {
            path: vec!["payload.bin".to_string()],
            first_chunk: 0,
            chunk_count: specs.len(),
            size: content_length,
        }],
    })
}
fn scoreboard_path_from_options(options: &JsGatewayFetchOptions) -> napi::Result<Option<PathBuf>> {
    let Some(path) = options.scoreboard_out_path.as_ref() else {
        return Ok(None);
    };
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(invalid_arg(
            "scoreboardOutPath must not be empty when provided",
        ));
    }
    let pathbuf = PathBuf::from(trimmed);
    if let Some(parent) = pathbuf.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            generic_failure(format!(
                "failed to create scoreboard directory `{}`: {err}",
                parent.display()
            ))
        })?;
    }
    Ok(Some(pathbuf))
}
fn trimmed_string_option(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}
#[derive(Clone, Copy)]
struct ScoreboardMetadataInputs<'a> {
    allow_implicit_metadata: bool,
    telemetry_label: Option<&'a str>,
    telemetry_region: Option<&'a str>,
    gateway_manifest_provided: bool,
    gateway_manifest_id: Option<&'a str>,
    gateway_manifest_cid: Option<&'a str>,
    allow_single_source_fallback: bool,
}
fn option_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Null, Value::from)
}
fn opt_usize_to_u64(value: Option<usize>, field: &str) -> napi::Result<Option<u64>> {
    value
        .map(|val| {
            u64::try_from(val)
                .map_err(|_| invalid_arg(format!("{field} exceeds 64-bit range (value: {val})")))
        })
        .transpose()
}
fn transport_policy_labels(
    requested: TransportPolicy,
    override_policy: Option<TransportPolicy>,
) -> (&'static str, bool, Option<&'static str>) {
    override_policy.map_or_else(
        || (requested.label(), false, None),
        |policy| (policy.label(), true, Some(policy.label())),
    )
}
fn anonymity_policy_labels(
    requested: AnonymityPolicy,
    override_policy: Option<AnonymityPolicy>,
) -> (&'static str, bool, Option<&'static str>) {
    override_policy.map_or_else(
        || (requested.label(), false, None),
        |policy| (policy.label(), true, Some(policy.label())),
    )
}
#[allow(clippy::too_many_lines)]
fn build_scoreboard_metadata_value(
    provider_count: usize,
    gateway_provider_count: usize,
    config: &OrchestratorConfig,
    inputs: ScoreboardMetadataInputs<'_>,
) -> napi::Result<Value> {
    let provider_count_u64 = u64::try_from(provider_count).map_err(|_| {
        invalid_arg(format!(
            "provider_count exceeds 64-bit range (value: {provider_count})"
        ))
    })?;
    let gateway_count_u64 = u64::try_from(gateway_provider_count).map_err(|_| {
        invalid_arg(format!(
            "gateway_provider_count exceeds 64-bit range (value: {gateway_provider_count})"
        ))
    })?;
    let max_parallel = opt_usize_to_u64(config.fetch.global_parallel_limit, "max_parallel")?;
    let max_peers = opt_usize_to_u64(
        config.max_providers.map(std::num::NonZeroUsize::get),
        "max_peers",
    )?;
    let retry_budget = opt_usize_to_u64(config.fetch.per_chunk_retry_limit, "retry_budget")?;
    let provider_failure_threshold = u64::try_from(config.fetch.provider_failure_threshold)
        .map_err(|_| {
            invalid_arg(format!(
                "provider_failure_threshold exceeds 64-bit range (value: {})",
                config.fetch.provider_failure_threshold
            ))
        })?;
    let mut metadata = Map::new();
    metadata.insert("version".into(), Value::from(env!("CARGO_PKG_VERSION")));
    metadata.insert("use_scoreboard".into(), Value::from(true));
    metadata.insert(
        "allow_implicit_metadata".into(),
        Value::from(inputs.allow_implicit_metadata),
    );
    metadata.insert(
        "allow_single_source_fallback".into(),
        Value::from(inputs.allow_single_source_fallback),
    );
    metadata.insert("provider_count".into(), Value::from(provider_count_u64));
    metadata.insert(
        "gateway_provider_count".into(),
        Value::from(gateway_count_u64),
    );
    metadata.insert("max_parallel".into(), option_u64_value(max_parallel));
    metadata.insert("max_peers".into(), option_u64_value(max_peers));
    metadata.insert("retry_budget".into(), option_u64_value(retry_budget));
    metadata.insert(
        "provider_failure_threshold".into(),
        Value::from(provider_failure_threshold),
    );
    metadata.insert(
        "assume_now".into(),
        Value::from(config.scoreboard.now_unix_secs),
    );
    metadata.insert(
        "telemetry_source".into(),
        inputs
            .telemetry_label
            .map_or(Value::Null, |label| Value::from(label.to_string())),
    );
    metadata.insert(
        "telemetry_region".into(),
        inputs
            .telemetry_region
            .map_or(Value::Null, |label| Value::from(label.to_string())),
    );
    metadata.insert(
        "gateway_manifest_provided".into(),
        Value::from(inputs.gateway_manifest_provided),
    );
    metadata.insert(
        "gateway_manifest_id".into(),
        inputs
            .gateway_manifest_id
            .map_or(Value::Null, |value| Value::from(value.to_string())),
    );
    metadata.insert(
        "gateway_manifest_cid".into(),
        inputs
            .gateway_manifest_cid
            .map_or(Value::Null, |value| Value::from(value.to_string())),
    );
    let (transport_label, transport_override_flag, transport_override_label) =
        transport_policy_labels(
            config.transport_policy,
            config.policy_override.transport_policy,
        );
    metadata.insert("transport_policy".into(), Value::from(transport_label));
    metadata.insert(
        "transport_policy_override".into(),
        Value::from(transport_override_flag),
    );
    metadata.insert(
        "transport_policy_override_label".into(),
        transport_override_label.map_or(Value::Null, Value::from),
    );
    let (anonymity_label, anonymity_override_flag, anonymity_override_label) =
        anonymity_policy_labels(
            config.anonymity_policy,
            config.policy_override.anonymity_policy,
        );
    metadata.insert("anonymity_policy".into(), Value::from(anonymity_label));
    metadata.insert(
        "anonymity_policy_override".into(),
        Value::from(anonymity_override_flag),
    );
    metadata.insert(
        "anonymity_policy_override_label".into(),
        anonymity_override_label.map_or(Value::Null, Value::from),
    );
    metadata.insert("write_mode".into(), Value::from(config.write_mode.label()));
    metadata.insert(
        "write_mode_enforces_pq".into(),
        Value::from(config.write_mode.enforces_pq_only()),
    );
    Ok(Value::Object(metadata))
}
fn provider_mix_label_from_counts(direct: u64, gateway: u64) -> &'static str {
    match (direct > 0, gateway > 0) {
        (true, true) => "mixed",
        (true, false) => "direct-only",
        (false, true) => "gateway-only",
        (false, false) => "none",
    }
}
fn build_gateway_metadata(
    provider_count: usize,
    gateway_provider_count: usize,
    config: &OrchestratorConfig,
    inputs: &ScoreboardMetadataInputs<'_>,
) -> napi::Result<JsGatewayMetadata> {
    let provider_count_u64 = u64::try_from(provider_count).map_err(|_| {
        invalid_arg(format!(
            "provider_count exceeds 64-bit range (value: {provider_count})"
        ))
    })?;
    let gateway_count_u64 = u64::try_from(gateway_provider_count).map_err(|_| {
        invalid_arg(format!(
            "gateway_provider_count exceeds 64-bit range (value: {gateway_provider_count})"
        ))
    })?;
    let provider_mix = provider_mix_label_from_counts(provider_count_u64, gateway_count_u64);
    let (transport_label, transport_override_flag, transport_override_label) =
        transport_policy_labels(
            config.transport_policy,
            config.policy_override.transport_policy,
        );
    let (anonymity_label, anonymity_override_flag, anonymity_override_label) =
        anonymity_policy_labels(
            config.anonymity_policy,
            config.policy_override.anonymity_policy,
        );
    let max_parallel = opt_usize_to_u64(config.fetch.global_parallel_limit, "max_parallel")?;
    let max_peers = opt_usize_to_u64(
        config.max_providers.map(std::num::NonZeroUsize::get),
        "max_peers",
    )?;
    let retry_budget = opt_usize_to_u64(config.fetch.per_chunk_retry_limit, "retry_budget")?;
    let provider_failure_threshold = u64::try_from(config.fetch.provider_failure_threshold)
        .map_err(|_| {
            invalid_arg(format!(
                "provider_failure_threshold exceeds 64-bit range (value: {})",
                config.fetch.provider_failure_threshold
            ))
        })?;
    let write_mode_label = config.write_mode.label().to_string();
    let write_mode_enforces_pq = config.write_mode.enforces_pq_only();
    Ok(JsGatewayMetadata {
        provider_count: JsU64(provider_count_u64),
        gateway_provider_count: JsU64(gateway_count_u64),
        provider_mix: provider_mix.to_string(),
        transport_policy: transport_label.to_string(),
        transport_policy_override: transport_override_flag,
        transport_policy_override_label: transport_override_label.map(str::to_string),
        anonymity_policy: anonymity_label.to_string(),
        anonymity_policy_override: anonymity_override_flag,
        anonymity_policy_override_label: anonymity_override_label.map(str::to_string),
        write_mode: write_mode_label,
        write_mode_enforces_pq,
        max_parallel: max_parallel.map(JsU64),
        max_peers: max_peers.map(JsU64),
        retry_budget: retry_budget.map(JsU64),
        provider_failure_threshold: JsU64(provider_failure_threshold),
        assume_now_unix: JsU64(config.scoreboard.now_unix_secs),
        telemetry_source_label: inputs.telemetry_label.map(str::to_string),
        telemetry_region: inputs.telemetry_region.map(str::to_string),
        gateway_manifest_provided: inputs.gateway_manifest_provided,
        gateway_manifest_id: inputs.gateway_manifest_id.map(str::to_string),
        gateway_manifest_cid: inputs.gateway_manifest_cid.map(str::to_string),
        allow_single_source_fallback: inputs.allow_single_source_fallback,
        allow_implicit_metadata: inputs.allow_implicit_metadata,
    })
}
fn apply_gateway_options(
    config: &mut OrchestratorConfig,
    options: &JsGatewayFetchOptions,
) -> napi::Result<Option<usize>> {
    if let Some(budget) = options.retry_budget {
        if budget == 0 {
            config.fetch.per_chunk_retry_limit = None;
        } else {
            let limit = usize::try_from(budget).map_err(|_| {
                invalid_arg("retryBudget exceeds supported range (must fit within usize)")
            })?;
            config.fetch.per_chunk_retry_limit = Some(limit);
        }
    }
    let max_peers = if let Some(limit) = options.max_peers {
        let limit = usize::try_from(limit.max(1))
            .map_err(|_| invalid_arg("maxPeers exceeds supported range (must fit within usize)"))?;
        config.fetch.global_parallel_limit = Some(
            config
                .fetch
                .global_parallel_limit
                .map_or(limit, |existing| existing.min(limit)),
        );
        Some(limit)
    } else {
        None
    };
    if let Some(region) = options.telemetry_region.as_ref() {
        let trimmed = region.trim();
        if trimmed.is_empty() {
            return Err(invalid_arg(
                "telemetryRegion must not be empty when provided",
            ));
        }
        config.telemetry_region = Some(trimmed.to_string());
    }
    if let Some(phase) = options.rollout_phase.as_ref() {
        let parsed = RolloutPhase::parse(phase).ok_or_else(|| {
            invalid_arg("rolloutPhase must be one of 'canary', 'ramp', or 'default'")
        })?;
        config.rollout_phase = parsed;
        if config.anonymity_policy_override.is_none() {
            config.anonymity_policy = parsed.default_anonymity_policy();
        }
    }
    if let Some(policy) = options.transport_policy.as_ref() {
        config.transport_policy = TransportPolicy::parse(policy).ok_or_else(|| {
            invalid_arg(
                "transportPolicy must be one of 'soranet-first', 'soranet-strict', or 'direct-only'",
            )
        })?;
    }
    if let Some(policy) = options.anonymity_policy.as_ref() {
        config.anonymity_policy = AnonymityPolicy::parse(policy).ok_or_else(|| {
            invalid_arg(
                "anonymityPolicy must be one of 'anon-guard-pq', 'anon-majority-pq', or 'anon-strict-pq'",
            )
        })?;
        config.anonymity_policy_override = Some(config.anonymity_policy);
    }
    if let Some(mode) = options.write_mode.as_ref() {
        config.write_mode = WriteModeHint::parse(mode).ok_or_else(|| {
            invalid_arg("writeMode must be one of 'read-only' or 'upload-pq-only'")
        })?;
    }
    if let Some(proxy_cfg) = options.local_proxy.as_ref() {
        let config_value = build_local_proxy_config(proxy_cfg)?;
        config.local_proxy = Some(config_value);
    }
    Ok(max_peers)
}
fn usize_to_u32(value: usize, field: &str) -> napi::Result<u32> {
    u32::try_from(value)
        .map_err(|_| invalid_arg(format!("{field} exceeds 32-bit range (value: {value})")))
}
#[allow(clippy::too_many_lines)]
fn convert_fetch_session_to_js(
    session: FetchSession,
    manifest_id_hex: &str,
    chunker_handle: &str,
    expected_payload_digest: [u8; 32],
    telemetry_region: Option<String>,
    metadata: JsGatewayMetadata,
) -> napi::Result<JsGatewayFetchResult> {
    let outcome = session.outcome;
    let policy_report = session.policy_report;
    let payload_bytes = outcome.assemble_payload();
    if blake3_hash(&payload_bytes).as_bytes() != &expected_payload_digest {
        return Err(invalid_arg(
            "assembled payload digest does not match canonical chunk fetch plan",
        ));
    }
    let assembled_bytes_u64 = u64::try_from(payload_bytes.len()).map_err(|_| {
        invalid_arg("assembled payload exceeds u64 range (too large for JavaScript)")
    })?;
    let chunk_count = usize_to_u32(outcome.chunks.len(), "chunk_count")?;
    let provider_reports = outcome
        .provider_reports
        .iter()
        .map(|report| {
            Ok(JsMultiFetchProviderReport {
                provider: report.provider.id().as_str().to_string(),
                successes: u32::try_from(report.successes)
                    .map_err(|_| invalid_arg("provider success count exceeds 32-bit range"))?,
                failures: u32::try_from(report.failures)
                    .map_err(|_| invalid_arg("provider failure count exceeds 32-bit range"))?,
                disabled: report.disabled,
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;
    let chunk_receipts = outcome
        .chunk_receipts
        .iter()
        .map(|receipt| {
            Ok(JsMultiFetchChunkReceipt {
                chunk_index: u32::try_from(receipt.chunk_index)
                    .map_err(|_| invalid_arg("chunk index exceeds 32-bit range in receipt"))?,
                provider: receipt.provider.as_str().to_string(),
                attempts: u32::try_from(receipt.attempts).map_err(|_| {
                    invalid_arg("chunk attempt count exceeds 32-bit range in receipt")
                })?,
                latency_ms: receipt.latency_ms,
                bytes: receipt.bytes,
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;
    let local_proxy_manifest_json = match session.local_proxy_manifest.as_ref() {
        Some(manifest) => {
            let value = json::to_value(manifest).map_err(|err| {
                generic_failure(format!("failed to serialise proxy manifest: {err}"))
            })?;
            Some(json::to_string(&value).map_err(|err| {
                generic_failure(format!("failed to render proxy manifest json: {err}"))
            })?)
        }
        None => None,
    };
    let car_verification = session.car_verification.map(|verification| {
        let car_stats = verification.car_stats;
        let governance = JsManifestGovernance {
            council_signatures: verification
                .manifest_governance
                .council_signatures
                .iter()
                .map(|sig| JsCouncilSignature {
                    signer_hex: hex::encode_upper(sig.signer),
                    signature_hex: hex::encode_upper(sig.signature.as_slice()),
                })
                .collect(),
        };
        JsCarVerification {
            manifest_digest_hex: hex::encode_upper(verification.manifest_digest.as_bytes()),
            manifest_payload_digest_hex: hex::encode_upper(
                verification.manifest_payload_digest.as_bytes(),
            ),
            manifest_car_digest_hex: hex::encode_upper(verification.manifest_car_digest),
            manifest_content_length: JsU64(verification.manifest_content_length),
            manifest_chunk_count: JsU64(verification.manifest_chunk_count),
            manifest_chunk_profile_handle: verification.chunk_profile_handle,
            manifest_governance: governance,
            car_archive: JsCarArchiveStats {
                size: JsU64(car_stats.car_size),
                payload_digest_hex: hex::encode_upper(car_stats.car_payload_digest.as_bytes()),
                archive_digest_hex: hex::encode_upper(car_stats.car_archive_digest.as_bytes()),
                cid_hex: hex::encode_upper(car_stats.car_cid),
                root_cids_hex: car_stats.root_cids.iter().map(hex::encode_upper).collect(),
                verified: true,
                por_leaf_count: JsU64(
                    u64::try_from(verification.por_leaf_count).unwrap_or(u64::MAX),
                ),
            },
        }
    });
    Ok(JsGatewayFetchResult {
        manifest_id_hex: manifest_id_hex.to_string(),
        chunker_handle: chunker_handle.to_string(),
        chunk_count,
        assembled_bytes: JsU64(assembled_bytes_u64),
        payload: Buffer::from(payload_bytes),
        telemetry_region,
        anonymity_policy: policy_report.policy.label().to_string(),
        anonymity_status: policy_report.status_label().to_string(),
        anonymity_reason: policy_report.reason_label().to_string(),
        anonymity_soranet_selected: usize_to_u32(
            policy_report.selected_soranet_total,
            "anonymity_soranet_selected",
        )?,
        anonymity_pq_selected: usize_to_u32(policy_report.selected_pq, "anonymity_pq_selected")?,
        anonymity_classical_selected: usize_to_u32(
            policy_report.selected_classical(),
            "anonymity_classical_selected",
        )?,
        anonymity_classical_ratio: policy_report.classical_ratio(),
        anonymity_pq_ratio: policy_report.pq_ratio(),
        anonymity_candidate_ratio: policy_report.candidate_ratio(),
        anonymity_deficit_ratio: policy_report.deficit_ratio(),
        anonymity_supply_delta: policy_report.supply_delta_ratio(),
        anonymity_brownout: policy_report.is_brownout(),
        anonymity_brownout_effective: policy_report.should_flag_brownout(),
        anonymity_uses_classical: policy_report.uses_classical(),
        provider_reports,
        chunk_receipts,
        local_proxy_manifest_json,
        car_verification,
        metadata,
    })
}
#[cfg(test)]
type FetchViaGatewayOverride = Box<
    dyn Fn(
            OrchestratorConfig,
            &CarBuildPlan,
            GatewayFetchConfig,
            Vec<GatewayProviderInput>,
            Option<&sorafs_car::scoreboard::TelemetrySnapshot>,
            Option<usize>,
        ) -> Result<FetchSession, GatewayOrchestratorError>
        + Send
        + Sync,
>;
#[cfg(test)]
fn fetch_override_slot() -> &'static std::sync::Mutex<Option<FetchViaGatewayOverride>> {
    static STORAGE: std::sync::OnceLock<std::sync::Mutex<Option<FetchViaGatewayOverride>>> =
        std::sync::OnceLock::new();
    STORAGE.get_or_init(|| std::sync::Mutex::new(None))
}
#[cfg(test)]
pub(crate) struct FetchViaGatewayOverrideGuard;
#[cfg(test)]
pub(crate) fn set_fetch_via_gateway_override<F>(override_fn: F) -> FetchViaGatewayOverrideGuard
where
    F: Fn(
            OrchestratorConfig,
            &CarBuildPlan,
            GatewayFetchConfig,
            Vec<GatewayProviderInput>,
            Option<&sorafs_car::scoreboard::TelemetrySnapshot>,
            Option<usize>,
        ) -> Result<FetchSession, GatewayOrchestratorError>
        + Send
        + Sync
        + 'static,
{
    let slot = fetch_override_slot();
    *slot
        .lock()
        .expect("fetch_via_gateway override mutex poisoned") = Some(Box::new(override_fn));
    FetchViaGatewayOverrideGuard
}
#[cfg(test)]
impl Drop for FetchViaGatewayOverrideGuard {
    fn drop(&mut self) {
        let slot = fetch_override_slot();
        *slot
            .lock()
            .expect("fetch_via_gateway override mutex poisoned during drop") = None;
    }
}
async fn run_fetch_via_gateway(
    config: OrchestratorConfig,
    plan: &CarBuildPlan,
    gateway_config: GatewayFetchConfig,
    provider_inputs: Vec<GatewayProviderInput>,
    telemetry: Option<&sorafs_car::scoreboard::TelemetrySnapshot>,
    max_peers: Option<usize>,
) -> Result<FetchSession, GatewayOrchestratorError> {
    #[cfg(test)]
    if let Some(override_fn) = fetch_override_slot()
        .lock()
        .expect("fetch_via_gateway override mutex poisoned")
        .as_ref()
    {
        return override_fn(
            config,
            plan,
            gateway_config,
            provider_inputs,
            telemetry,
            max_peers,
        );
    }
    fetch_via_gateway(
        config,
        plan,
        gateway_config,
        provider_inputs,
        telemetry,
        max_peers,
    )
    .await
}
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
#[napi(js_name = "sorafsGatewayFetch")]
/// Execute a gateway-backed multi-provider fetch via the Rust orchestrator.
pub fn sorafs_gateway_fetch(
    manifest_id_hex: String,
    chunker_handle: String,
    plan_json: String,
    providers: Vec<JsGatewayProviderSpec>,
    options: Option<JsGatewayFetchOptions>,
) -> napi::Result<JsGatewayFetchResult> {
    if providers.is_empty() {
        return Err(invalid_arg(
            "providers list must contain at least one entry",
        ));
    }
    let manifest_id = manifest_id_hex.trim().to_ascii_lowercase();
    if manifest_id.len() != 64 || !manifest_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid_arg("manifestIdHex must be a 32-byte hex string"));
    }
    let chunker_handle_trimmed = chunker_handle.trim();
    if chunker_handle_trimmed.is_empty() {
        return Err(invalid_arg("chunkerHandle must not be empty"));
    }
    let plan_value: json::Value = json::from_str(&plan_json)
        .map_err(|err| invalid_arg(format!("failed to parse plan JSON: {err}")))?;
    let parsed_plan = chunk_fetch_plan_from_json(&plan_value)
        .map_err(|err| invalid_arg(format!("invalid chunk fetch plan: {err}")))?;
    let plan_payload_digest = parsed_plan.payload_digest;
    let mut specs = parsed_plan.chunk_fetch_specs;
    if specs.is_empty() {
        return Err(invalid_arg(
            "chunk fetch plan must contain at least one chunk",
        ));
    }
    specs.sort_by_key(|spec| spec.chunk_index);
    for (expected, spec) in specs.iter().enumerate() {
        if spec.chunk_index != expected {
            return Err(invalid_arg(format!(
                "chunk fetch plan missing chunk index {expected}"
            )));
        }
    }
    let plan = build_gateway_plan(&specs, plan_payload_digest, chunker_handle_trimmed)?;
    let provider_inputs = providers
        .iter()
        .map(build_gateway_provider_input)
        .collect::<napi::Result<Vec<_>>>()?;
    let opts = options.unwrap_or_default();
    let mut orchestrator_config = OrchestratorConfig::default();
    let mut scoreboard_path = scoreboard_path_from_options(&opts)?;
    if let Some(now) = opts.scoreboard_now_unix_secs.as_ref().map(|value| value.0) {
        orchestrator_config.scoreboard.now_unix_secs = now;
    }
    let telemetry_label = trimmed_string_option(opts.scoreboard_telemetry_label.as_deref());
    let allow_implicit_metadata = opts.scoreboard_allow_implicit_metadata.unwrap_or(false);
    let allow_single_source_fallback = opts.allow_single_source_fallback.unwrap_or(false);
    let max_peers = apply_gateway_options(&mut orchestrator_config, &opts)?;
    let telemetry_region = orchestrator_config.telemetry_region.clone();
    let gateway_config = build_gateway_fetch_config(&manifest_id, chunker_handle_trimmed, &opts)?;
    let manifest_envelope_present = gateway_config.manifest_envelope_b64.is_some();
    let manifest_cid_metadata = gateway_config.expected_manifest_cid_hex.clone();
    let direct_provider_count = 0usize;
    let gateway_provider_count = provider_inputs.len();
    let metadata_inputs = ScoreboardMetadataInputs {
        allow_implicit_metadata,
        telemetry_label: telemetry_label.as_deref(),
        telemetry_region: telemetry_region.as_deref(),
        gateway_manifest_provided: manifest_envelope_present,
        gateway_manifest_id: Some(manifest_id.as_str()),
        gateway_manifest_cid: manifest_cid_metadata.as_deref(),
        allow_single_source_fallback,
    };
    if let Some(path) = scoreboard_path.take() {
        let metadata = build_scoreboard_metadata_value(
            direct_provider_count,
            gateway_provider_count,
            &orchestrator_config,
            metadata_inputs,
        )?;
        orchestrator_config.scoreboard.persist_path = Some(path);
        orchestrator_config.scoreboard.persist_metadata = Some(metadata);
    }
    let js_metadata = build_gateway_metadata(
        direct_provider_count,
        gateway_provider_count,
        &orchestrator_config,
        &metadata_inputs,
    )?;
    let runtime = Runtime::new()
        .map_err(|err| generic_failure(format!("failed to initialise Tokio runtime: {err}")))?;
    let session = runtime
        .block_on(run_fetch_via_gateway(
            orchestrator_config,
            &plan,
            gateway_config,
            provider_inputs,
            None::<&sorafs_car::scoreboard::TelemetrySnapshot>,
            max_peers,
        ))
        .map_err(map_gateway_error)?;
    convert_fetch_session_to_js(
        session,
        &manifest_id,
        chunker_handle_trimmed,
        plan_payload_digest,
        telemetry_region,
        js_metadata,
    )
}
#[napi(js_name = "daManifestChunkerHandle")]
/// Derive the canonical chunker handle used to encode a DA manifest.
#[allow(clippy::needless_pass_by_value)]
pub fn da_manifest_chunker_handle(manifest_bytes: Uint8Array) -> napi::Result<String> {
    let manifest = decode_da_manifest(manifest_bytes.as_ref())?;
    derive_da_chunker_handle(&manifest)
}
#[napi(js_name = "daGenerateProofs")]
/// Generate `PoR` proofs for a DA payload using the canonical manifest chunk plan.
#[allow(clippy::needless_pass_by_value)]
pub fn da_generate_proofs(
    manifest_bytes: Uint8Array,
    payload_bytes: Uint8Array,
    options: Option<JsDaProofOptions>,
) -> napi::Result<JsDaProofSummary> {
    let manifest = decode_da_manifest(manifest_bytes.as_ref())?;
    let payload = payload_bytes.to_vec();
    let opts = DaProofOptionsInternal::from_js(options)?;
    let iroha_config = opts.to_iroha_config();
    let summary_value = iroha_generate_da_proof_summary(&manifest, &payload, &iroha_config)
        .map_err(|err| generic_failure(format!("failed to generate DA proof summary: {err}")))?;
    let summary = DaProofSummaryInternal::try_from(summary_value)?;
    Ok(summary.into())
}
const DEFAULT_DA_SAMPLE_COUNT: usize = 8;
#[derive(Clone)]
struct DaProofSummaryInternal {
    blob_hash_hex: String,
    chunk_root_hex: String,
    por_root_hex: String,
    leaf_count: usize,
    segment_count: usize,
    chunk_count: usize,
    sample_count: usize,
    sample_seed: u64,
    proofs: Vec<JsDaProofRecord>,
}
#[derive(Clone)]
struct DaProofOptionsInternal {
    sample_count: usize,
    sample_seed: u64,
    leaf_indexes: Vec<usize>,
}
impl DaProofOptionsInternal {
    fn from_js(options: Option<JsDaProofOptions>) -> napi::Result<Self> {
        let opts = options.unwrap_or_default();
        let sample_count = opts
            .sample_count
            .map(|value| {
                usize::try_from(value).map_err(|_| invalid_arg("sampleCount exceeds host limits"))
            })
            .transpose()?
            .unwrap_or(DEFAULT_DA_SAMPLE_COUNT);
        let sample_seed = opts.sample_seed.map_or(0, |value| {
            let raw: u64 = value.into();
            raw
        });
        let mut leaf_indexes = Vec::new();
        if let Some(values) = opts.leaf_indexes {
            for (idx, entry) in values.into_iter().enumerate() {
                let raw: u64 = entry.into();
                let coerced = usize::try_from(raw).map_err(|_| {
                    invalid_arg(format!(
                        "leafIndexes[{idx}] exceeds host limits (value must fit within usize)"
                    ))
                })?;
                leaf_indexes.push(coerced);
            }
        }
        Ok(Self {
            sample_count,
            sample_seed,
            leaf_indexes,
        })
    }
    fn to_iroha_config(&self) -> IrohaDaProofConfig {
        IrohaDaProofConfig {
            sample_count: self.sample_count,
            sample_seed: self.sample_seed,
            leaf_indexes: self.leaf_indexes.clone(),
        }
    }
}
impl From<DaProofSummaryInternal> for JsDaProofSummary {
    fn from(summary: DaProofSummaryInternal) -> Self {
        JsDaProofSummary {
            blob_hash_hex: summary.blob_hash_hex,
            chunk_root_hex: summary.chunk_root_hex,
            por_root_hex: summary.por_root_hex,
            leaf_count: JsU64(summary.leaf_count as u64),
            segment_count: JsU64(summary.segment_count as u64),
            chunk_count: JsU64(summary.chunk_count as u64),
            sample_count: u32::try_from(summary.sample_count).unwrap_or(u32::MAX),
            sample_seed: JsU64(summary.sample_seed),
            proof_count: u32::try_from(summary.proofs.len()).unwrap_or(u32::MAX),
            proofs: summary.proofs,
        }
    }
}
impl TryFrom<Value> for DaProofSummaryInternal {
    type Error = napi::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let map = value
            .as_object()
            .ok_or_else(|| invalid_arg("DA proof summary must be a JSON object"))?;
        let proofs_value = map
            .get("proofs")
            .ok_or_else(|| invalid_arg("DA proof summary missing `proofs` field"))?;
        let proofs_array = proofs_value
            .as_array()
            .ok_or_else(|| invalid_arg("`proofs` must be an array"))?;
        let mut proofs = Vec::with_capacity(proofs_array.len());
        for (idx, entry) in proofs_array.iter().enumerate() {
            proofs.push(parse_da_proof_record(entry, idx)?);
        }
        Ok(Self {
            blob_hash_hex: string_field(map, "blob_hash")?,
            chunk_root_hex: string_field(map, "chunk_root")?,
            por_root_hex: string_field(map, "por_root")?,
            leaf_count: usize_field(map, "leaf_count")?,
            segment_count: usize_field(map, "segment_count")?,
            chunk_count: usize_field(map, "chunk_count")?,
            sample_count: usize_field(map, "sample_count")?,
            sample_seed: u64_field(map, "sample_seed")?,
            proofs,
        })
    }
}
fn parse_da_proof_record(value: &Value, index: usize) -> napi::Result<JsDaProofRecord> {
    let ctx = format!("proofs[{index}]");
    let map = value
        .as_object()
        .ok_or_else(|| invalid_arg(format!("{ctx} must be an object")))?;
    Ok(JsDaProofRecord {
        origin: string_field_ctx(map, "origin", &ctx)?,
        leaf_index: u32_field_ctx(map, "leaf_index", &ctx)?,
        chunk_index: u32_field_ctx(map, "chunk_index", &ctx)?,
        segment_index: u32_field_ctx(map, "segment_index", &ctx)?,
        leaf_offset: JsU64(u64_field_ctx(map, "leaf_offset", &ctx)?),
        leaf_length: u32_field_ctx(map, "leaf_length", &ctx)?,
        segment_offset: JsU64(u64_field_ctx(map, "segment_offset", &ctx)?),
        segment_length: u32_field_ctx(map, "segment_length", &ctx)?,
        chunk_offset: JsU64(u64_field_ctx(map, "chunk_offset", &ctx)?),
        chunk_length: u32_field_ctx(map, "chunk_length", &ctx)?,
        payload_len: JsU64(u64_field_ctx(map, "payload_len", &ctx)?),
        chunk_digest_hex: string_field_ctx(map, "chunk_digest", &ctx)?,
        chunk_root_hex: string_field_ctx(map, "chunk_root", &ctx)?,
        segment_digest_hex: string_field_ctx(map, "segment_digest", &ctx)?,
        leaf_digest_hex: string_field_ctx(map, "leaf_digest", &ctx)?,
        leaf_bytes_b64: string_field_ctx(map, "leaf_bytes_b64", &ctx)?,
        segment_leaves_hex: string_list_field_ctx(map, "segment_leaves", &ctx)?,
        chunk_segments_hex: string_list_field_ctx(map, "chunk_segments", &ctx)?,
        chunk_count: JsU64(u64_field_ctx(map, "chunk_count", &ctx)?),
        chunk_merkle_path_hex: string_list_field_ctx(map, "chunk_merkle_path", &ctx)?,
        verified: bool_field_ctx(map, "verified", &ctx)?,
    })
}
fn string_field(map: &Map, key: &str) -> napi::Result<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid_arg(format!("DA proof summary missing string field `{key}`")))
}
fn string_field_ctx(map: &Map, key: &str, ctx: &str) -> napi::Result<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid_arg(format!("{ctx} missing string field `{key}`")))
}
fn string_list_field_ctx(map: &Map, key: &str, ctx: &str) -> napi::Result<Vec<String>> {
    let value = map
        .get(key)
        .ok_or_else(|| invalid_arg(format!("{ctx} missing `{key}` field")))?;
    let array = value
        .as_array()
        .ok_or_else(|| invalid_arg(format!("{ctx}.{key} must be an array")))?;
    let mut entries = Vec::with_capacity(array.len());
    for (idx, entry) in array.iter().enumerate() {
        if let Value::String(inner) = entry {
            entries.push(inner.clone());
        } else {
            return Err(invalid_arg(format!("{ctx}.{key}[{idx}] must be a string")));
        }
    }
    Ok(entries)
}
fn bool_field_ctx(map: &Map, key: &str, ctx: &str) -> napi::Result<bool> {
    match map.get(key) {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(invalid_arg(format!("{ctx} missing boolean field `{key}`"))),
    }
}
fn u64_field(map: &Map, key: &str) -> napi::Result<u64> {
    map.get(key)
        .and_then(value_to_u64)
        .ok_or_else(|| invalid_arg(format!("DA proof summary missing integer field `{key}`")))
}
fn u64_field_ctx(map: &Map, key: &str, ctx: &str) -> napi::Result<u64> {
    map.get(key)
        .and_then(value_to_u64)
        .ok_or_else(|| invalid_arg(format!("{ctx} missing integer field `{key}`")))
}
fn usize_field(map: &Map, key: &str) -> napi::Result<usize> {
    let value = u64_field(map, key)?;
    usize::try_from(value).map_err(|_| invalid_arg(format!("`{key}` exceeds host limits")))
}
fn u32_field_ctx(map: &Map, key: &str, ctx: &str) -> napi::Result<u32> {
    let value = u64_field_ctx(map, key, ctx)?;
    u32::try_from(value)
        .map_err(|_| invalid_arg(format!("{ctx}.{key} exceeds 32-bit integer limits")))
}
fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => raw.trim().parse::<u64>().ok(),
        _ => None,
    }
}
fn decode_da_manifest(bytes: &[u8]) -> napi::Result<DaManifestV1> {
    decode_from_bytes(bytes)
        .map_err(|err| invalid_arg(format!("failed to decode DA manifest: {err}")))
}
fn derive_da_chunker_handle(manifest: &DaManifestV1) -> napi::Result<String> {
    let plan = build_car_plan_from_manifest(manifest)
        .map_err(|err| invalid_arg(format!("failed to derive chunk plan from manifest: {err}")))?;
    let descriptor = sorafs_manifest::chunker_registry::lookup_by_profile(
        plan.chunk_profile,
        sorafs_manifest::chunker_registry::DEFAULT_MULTIHASH_CODE,
    )
    .unwrap_or_else(sorafs_manifest::chunker_registry::default_descriptor);
    Ok(format!(
        "{}.{}@{}",
        descriptor.namespace, descriptor.name, descriptor.semver
    ))
}
fn map_local_fetch_error(err: LocalFetchError) -> napi::Error {
    match err {
        LocalFetchError::NoProviders => {
            invalid_arg("providers list must contain at least one entry")
        }
        LocalFetchError::DuplicateProvider(name) => {
            invalid_arg(format!("duplicate provider '{name}'"))
        }
        LocalFetchError::ProviderPathMissing { path } => invalid_arg(format!(
            "provider payload '{}' does not exist",
            path.display()
        )),
        LocalFetchError::ProviderPathNotFile { path } => invalid_arg(format!(
            "provider payload '{}' is not a regular file",
            path.display()
        )),
        LocalFetchError::InvalidMaxConcurrent => {
            invalid_arg("max_concurrent must be greater than zero when provided")
        }
        LocalFetchError::InvalidWeight => {
            invalid_arg("weight must be greater than zero when provided")
        }
        LocalFetchError::InvalidPlan(err) => invalid_arg(err.to_string()),
        LocalFetchError::MissingScoreboardMetadata(name) => invalid_arg(format!(
            "scoreboard requires metadata for provider '{name}' (provide advert metadata or disable use_scoreboard)"
        )),
        LocalFetchError::ScoreboardExcludedAll => {
            invalid_arg("no providers available after applying scoreboard filters")
        }
        LocalFetchError::ScoreboardBuild(err) => {
            generic_failure(format!("failed to build scoreboard: {err}"))
        }
        LocalFetchError::Fetch(message) => {
            let status = if message.starts_with("multi-fetch failed:") {
                napi::Status::GenericFailure
            } else {
                napi::Status::InvalidArg
            };
            napi::Error::new(status, message)
        }
        LocalFetchError::UnknownChunkerHandle(handle) => {
            invalid_arg(format!("unknown chunker handle '{handle}'"))
        }
        LocalFetchError::IntegrityVerificationDisabled(field) => invalid_arg(format!(
            "{field} must remain enabled for first-release SoraFS fetch integrity"
        )),
    }
}
fn invalid_arg(message: impl Into<String>) -> napi::Error {
    napi::Error::new(napi::Status::InvalidArg, message.into())
}
fn generic_failure(message: impl Into<String>) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, message.into())
}
fn map_gateway_error(err: GatewayOrchestratorError) -> napi::Error {
    match err {
        GatewayOrchestratorError::Orchestrator(OrchestratorError::MultiSource(multi)) => {
            multi_source_js_error(multi)
        }
        other => generic_failure(format!("sorafs gateway fetch failed: {other}")),
    }
}
fn multi_source_js_error(error: MultiSourceError) -> napi::Error {
    use multi_fetch::MultiSourceError::*;
    let message = format!("{error}");
    let payload = match error {
        ResourceLimit(reason) => norito_json!({
            "kind": "multi_source", "code": "resource_limit", "message": message,
            "details": reason, "retryable": false,
        }),
        DeadlineExceeded => norito_json!({
            "kind": "multi_source", "code": "deadline_exceeded", "message": message,
            "retryable": true,
        }),
        InvalidPlan(reason) => norito_json!({
            "kind": "multi_source",
            "code": "invalid_plan",
            "message": message,
            "details": reason.to_string(),
            "retryable": false,
        }),
        NoProviders => norito_json!({
            "kind": "multi_source",
            "code": "no_providers",
            "message": message,
            "retryable": false,
        }),
        NoHealthyProviders {
            chunk_index,
            attempts,
            last_error,
        } => norito_json!({
            "kind": "multi_source",
            "code": "no_healthy_providers",
            "message": message,
            "chunkIndex": chunk_index,
            "attempts": attempts,
            "lastError": last_error.map(|error| attempt_error_to_value(*error)),
            "retryable": true,
        }),
        NoCompatibleProviders {
            chunk_index,
            providers,
        } => norito_json!({
            "kind": "multi_source",
            "code": "no_compatible_providers",
            "message": message,
            "chunkIndex": chunk_index,
            "providers": capability_mismatch_values(&providers),
            "retryable": false,
        }),
        NoPolicyEligibleProviders {
            chunk_index,
            providers,
        } => {
            let providers = Value::Array(
                providers
                    .into_iter()
                    .map(|provider| {
                        norito_json!({
                            "providerId": provider.to_string(),
                            "reason": "score_policy_denied",
                        })
                    })
                    .collect(),
            );
            norito_json!({
                "kind": "multi_source",
                "code": "no_policy_eligible_providers",
                "message": message,
                "chunkIndex": chunk_index,
                "providers": providers,
                "retryable": false,
            })
        }
        ExhaustedRetries {
            chunk_index,
            attempts,
            last_error,
        } => norito_json!({
            "kind": "multi_source",
            "code": "exhausted_retries",
            "message": message,
            "chunkIndex": chunk_index,
            "attempts": attempts,
            "lastError": attempt_error_to_value(*last_error),
            "retryable": false,
        }),
        ObserverFailed {
            chunk_index,
            source,
        } => norito_json!({
            "kind": "multi_source",
            "code": "observer_failed",
            "message": message,
            "chunkIndex": chunk_index,
            "observerError": source.to_string(),
            "retryable": false,
        }),
        InternalInvariant(reason) => norito_json!({
            "kind": "multi_source",
            "code": "internal_invariant",
            "message": message,
            "details": reason,
            "retryable": false,
        }),
    };
    norito::json::to_string(&payload).map_or_else(
        |_| napi::Error::new(napi::Status::GenericFailure, message),
        |rendered| napi::Error::new(napi::Status::GenericFailure, rendered),
    )
}
fn attempt_error_to_value(error: AttemptError) -> Value {
    norito_json!({
        "providerId": error.provider.to_string(),
        "failure": attempt_failure_to_value(error.failure),
    })
}
fn attempt_failure_to_value(failure: AttemptFailure) -> Value {
    match failure {
        AttemptFailure::Provider {
            message,
            policy_block,
        } => {
            let policy = policy_block.map(|policy| {
                norito_json!({
                    "observedStatus": policy.observed_status.as_u16(),
                    "code": policy.code,
                    "source": policy.source,
                    "catalogDigestHex": policy.catalog_digest_hex,
                })
            });
            norito_json!({
                "kind": "provider",
                "message": message,
                "policyBlock": policy,
            })
        }
        AttemptFailure::InvalidChunk(reason) => norito_json!({
            "kind": "invalid_chunk",
            "reason": chunk_verification_error_value(&reason),
        }),
    }
}
/// Verify a manifest/payload pair and emit `PoR` proofs for JavaScript callers.
#[napi]
/// Generate a summary digest describing the provided manifest/payload `PoR` proofs.
#[allow(clippy::needless_pass_by_value)]
pub fn da_generate_proof_summary(
    manifest_bytes: Buffer,
    payload_bytes: Buffer,
    options: Option<JsDaProofOptions>,
) -> napi::Result<JsDaProofSummary> {
    if manifest_bytes.is_empty() {
        return Err(invalid_arg("manifest bytes must not be empty"));
    }
    if payload_bytes.is_empty() {
        return Err(invalid_arg("payload bytes must not be empty"));
    }
    let manifest: DaManifestV1 = decode_from_bytes(manifest_bytes.as_ref()).map_err(|err| {
        napi::Error::from_reason(format!("failed to decode DA manifest bytes: {err}"))
    })?;
    if manifest.total_stripes == 0 || manifest.shards_per_stripe == 0 {
        return Err(invalid_arg(
            "DA manifest missing total_stripes or shards_per_stripe",
        ));
    }
    let plan = build_car_plan_from_manifest(&manifest)?;
    let mut store = ChunkStore::with_profile(plan.chunk_profile);
    let mut source = InMemoryPayload::new(payload_bytes.as_ref());
    store
        .ingest_plan_source(&plan, &mut source)
        .map_err(chunk_store_err)?;
    validate_manifest_consistency(&manifest, &store)?;
    let proof_options = DaProofOptionsNormalized::from_js(options)?;
    let por_root = *store.por_tree().root();
    let mut reports =
        collect_sampled_proofs(&store, payload_bytes.as_ref(), &proof_options, &por_root)?;
    let mut explicit =
        collect_explicit_proofs(&store, payload_bytes.as_ref(), &proof_options, &por_root)?;
    reports.append(&mut explicit);
    let proofs_js = reports.iter().map(proof_to_js_record).collect::<Vec<_>>();
    Ok(JsDaProofSummary {
        blob_hash_hex: hex::encode(manifest.blob_hash.as_ref()),
        chunk_root_hex: hex::encode(manifest.chunk_root.as_ref()),
        por_root_hex: hex::encode(por_root),
        leaf_count: JsU64(store.por_tree().leaf_count() as u64),
        segment_count: JsU64(store.por_tree().segment_count() as u64),
        chunk_count: JsU64(store.chunks().len() as u64),
        sample_count: u32::try_from(proof_options.sample_count).unwrap_or(u32::MAX),
        sample_seed: JsU64(proof_options.sample_seed),
        proof_count: u32::try_from(proofs_js.len()).unwrap_or(u32::MAX),
        proofs: proofs_js,
    })
}
fn chunk_verification_error_value(error: &ChunkVerificationError) -> Value {
    match error {
        ChunkVerificationError::LengthMismatch { expected, actual } => {
            norito_json!({
                "kind": "length_mismatch",
                "expected": *expected,
                "actual": *actual,
            })
        }
        ChunkVerificationError::DigestMismatch { expected, actual } => {
            norito_json!({
                "kind": "digest_mismatch",
                "expected": hex::encode(expected),
                "actual": hex::encode(actual),
            })
        }
    }
}
fn capability_mismatch_values(
    providers: &[(multi_fetch::ProviderId, CapabilityMismatch)],
) -> Value {
    let entries: Vec<Value> = providers
        .iter()
        .map(|(provider, mismatch)| capability_mismatch_entry(provider, mismatch))
        .collect();
    Value::Array(entries)
}
fn capability_mismatch_entry(
    provider: &multi_fetch::ProviderId,
    mismatch: &CapabilityMismatch,
) -> Value {
    match mismatch {
        CapabilityMismatch::MissingRangeCapability => norito_json!({
            "providerId": provider.to_string(),
            "reason": mismatch.to_string(),
        }),
        CapabilityMismatch::ChunkTooLarge {
            chunk_length,
            max_span,
        } => norito_json!({
            "providerId": provider.to_string(),
            "reason": mismatch.to_string(),
            "chunkLength": *chunk_length,
            "maxSpan": *max_span,
        }),
        CapabilityMismatch::OffsetMisaligned {
            offset,
            required_alignment,
        } => norito_json!({
            "providerId": provider.to_string(),
            "reason": mismatch.to_string(),
            "offset": *offset,
            "requiredAlignment": *required_alignment,
        }),
        CapabilityMismatch::LengthMisaligned {
            length,
            required_alignment,
        } => norito_json!({
            "providerId": provider.to_string(),
            "reason": mismatch.to_string(),
            "length": *length,
            "requiredAlignment": *required_alignment,
        }),
        CapabilityMismatch::StreamBurstTooSmall {
            chunk_length,
            burst_limit,
        } => norito_json!({
            "providerId": provider.to_string(),
            "reason": mismatch.to_string(),
            "chunkLength": *chunk_length,
            "burstLimit": *burst_limit,
        }),
    }
}
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned `String`
#[napi(js_name = "sorafsMultiFetchLocal")]
/// Execute a multi-provider fetch entirely against the local filesystem.
pub fn sorafs_multi_fetch_local(
    plan_json: String,
    providers: Vec<JsLocalProviderSpec>,
    options: Option<JsMultiFetchOptions>,
) -> napi::Result<JsMultiFetchResult> {
    let plan_value: json::Value = json::from_str(&plan_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("failed to parse plan JSON: {err}"),
        )
    })?;
    let provider_inputs = providers
        .into_iter()
        .map(js_provider_to_local)
        .collect::<napi::Result<Vec<_>>>()?;
    let options = build_local_fetch_options(options)?;
    let result = local_fetch::execute_local_fetch(&plan_value, provider_inputs, options)
        .map_err(map_local_fetch_error)?;
    local_fetch_result_to_js(result)
}
fn to_js_replication_assignments(
    assignments: Vec<sorafs_manifest::capacity::ReplicationAssignmentV1>,
) -> napi::Result<Vec<JsReplicationAssignment>> {
    assignments
        .into_iter()
        .map(|assignment| {
            let slice_gib = u64_to_js_number(assignment.slice_gib, "slice_gib")?;
            Ok(JsReplicationAssignment {
                provider_id_hex: hex::encode(assignment.provider_id),
                slice_gib,
                lane: assignment.lane,
            })
        })
        .collect()
}
fn to_js_replication_metadata(
    metadata: Vec<sorafs_manifest::capacity::CapacityMetadataEntry>,
) -> Vec<JsReplicationMetadataEntry> {
    metadata
        .into_iter()
        .map(|entry| JsReplicationMetadataEntry {
            key: entry.key,
            value: entry.value,
        })
        .collect()
}
fn to_js_replication_order(order: ReplicationOrderV1) -> napi::Result<JsReplicationOrder> {
    let ReplicationOrderV1 {
        version,
        order_id,
        manifest_cid,
        manifest_digest,
        chunking_profile,
        target_replicas,
        assignments,
        issued_at,
        deadline_at,
        sla,
        metadata,
    } = order;
    let manifest_cid_hex = hex::encode(&manifest_cid);
    let manifest_cid_base64 = STANDARD.encode(&manifest_cid);
    let manifest_cid_utf8 = String::from_utf8(manifest_cid).ok();
    let target_replicas = u32::from(target_replicas);
    let assignments = to_js_replication_assignments(assignments)?;
    let issued_at_unix = u64_to_js_number(issued_at, "issued_at")?;
    let deadline_at_unix = u64_to_js_number(deadline_at, "deadline_at")?;
    let js_sla = JsReplicationSla {
        ingest_deadline_secs: sla.ingest_deadline_secs,
        min_availability_percent_milli: sla.min_availability_percent_milli,
        min_por_success_percent_milli: sla.min_por_success_percent_milli,
    };
    Ok(JsReplicationOrder {
        schema_version: version,
        order_id_hex: hex::encode(order_id),
        manifest_cid_hex,
        manifest_cid_utf8,
        manifest_cid_base64,
        manifest_digest_hex: hex::encode(manifest_digest),
        chunking_profile,
        target_replicas,
        assignments,
        issued_at_unix,
        deadline_at_unix,
        sla: js_sla,
        metadata: to_js_replication_metadata(metadata),
    })
}
/// Decode a Norito-encoded replication order into a typed JavaScript object.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_decode_replication_order(bytes: Uint8Array) -> napi::Result<JsReplicationOrder> {
    let order: ReplicationOrderV1 =
        decode_from_bytes(bytes.as_ref()).map_err(|err| norito_to_napi(format!("{err}")))?;
    order
        .validate()
        .map_err(|err| norito_to_napi(format!("invalid replication order: {err}")))?;
    to_js_replication_order(order)
}
fn parse_sorafs_generated_at_unix(generated_at_unix: i64) -> napi::Result<u64> {
    js_number_to_u64(generated_at_unix, "generated_at_unix")
}
fn validate_sorafs_reference_label(label: &str, context: &str) -> napi::Result<()> {
    if label.is_empty() || label.trim().is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must not be blank"),
        ));
    }
    if label.trim() != label {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must not contain surrounding whitespace"),
        ));
    }
    if label.chars().any(char::is_control) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must not contain control characters"),
        ));
    }
    let maximum = SORAFS_REFERENCE_FFI_MAX_LABEL_BYTES_V1 as usize;
    if label.len() > maximum {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must be at most {maximum} UTF-8 bytes"),
        ));
    }
    Ok(())
}
fn validate_sorafs_reference_aggregate_bytes(
    context: &str,
    sizes: impl IntoIterator<Item = usize>,
) -> napi::Result<()> {
    let maximum = SORAFS_REFERENCE_FFI_MAX_INPUT_BYTES_V1 as usize;
    let mut total = 0usize;
    for size in sizes {
        total = total.checked_add(size).ok_or_else(|| {
            napi::Error::new(
                napi::Status::InvalidArg,
                format!("{context} aggregate byte length overflowed"),
            )
        })?;
        if total > maximum {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                format!("{context} inputs exceed {maximum} aggregate bytes"),
            ));
        }
    }
    Ok(())
}
fn validate_sorafs_reference_governance_cid<'a>(
    cid: Option<&'a [u8]>,
    context: &str,
) -> napi::Result<Option<&'a [u8]>> {
    let Some(cid) = cid else {
        return Ok(None);
    };
    let exact_bytes = SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1 as usize;
    if cid.len() != exact_bytes {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must contain exactly {exact_bytes} bytes"),
        ));
    }
    Ok(Some(cid))
}
fn parse_sorafs_orderbook_payload_kind(
    kind: &str,
) -> napi::Result<OrderbookValidationPayloadKindV1> {
    parse_sorafs_orderbook_payload_kind_v1(kind).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported SoraFS orderbook payload kind `{kind}`"),
        )
    })
}
fn parse_sorafs_orderbook_side(side: &str) -> napi::Result<OrderSideV1> {
    parse_sorafs_orderbook_side_v1(side).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported SoraFS orderbook side `{side}`"),
        )
    })
}
fn parse_sorafs_orderbook_tier(tier: &str) -> napi::Result<OrderTierV1> {
    parse_sorafs_orderbook_tier_v1(tier).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported SoraFS orderbook tier `{tier}`"),
        )
    })
}
fn parse_sorafs_orderbook_cancel_reason(reason: &str) -> napi::Result<OrderCancelReasonV1> {
    parse_sorafs_orderbook_cancel_reason_v1(reason, "owner-requested").ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported SoraFS orderbook cancel reason `{reason}`"),
        )
    })
}
fn parse_sorafs_decimal_u64(value: &str, context: &str) -> napi::Result<u64> {
    parse_sorafs_orderbook_decimal_u64_v1(value, context)
        .map_err(|error| napi::Error::new(napi::Status::InvalidArg, error))
}
fn parse_sorafs_xor_quantity(value: &str, context: &str) -> napi::Result<XorQuantity> {
    parse_sorafs_orderbook_xor_quantity_v1(value, context)
        .map_err(|error| napi::Error::new(napi::Status::InvalidArg, error))
}
fn parse_sorafs_fee_bps(value: u32, context: &str) -> napi::Result<u16> {
    parse_sorafs_orderbook_fee_bps_v1(value, context)
        .map_err(|error| napi::Error::new(napi::Status::InvalidArg, error))
}
fn parse_sorafs_fixed32(value: &Uint8Array, context: &str) -> napi::Result<[u8; 32]> {
    parse_fixed32(value, context)
}
/// Validate a canonical appeal-finance `CancelAssetLock` V1 payload.
#[napi]
pub fn sorafs_validate_appeal_finance_cancel_asset_lock_json(
    bytes: Uint8Array,
    label: String,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let outcome =
        validate_appeal_finance_cancel_asset_lock_bytes(bytes.as_ref(), label, generated_at);
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate a Norito-encoded orderbook payload and return canonical outcome JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_orderbook_payload_json(
    kind: String,
    bytes: Uint8Array,
    label: String,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let kind = parse_sorafs_orderbook_payload_kind(&kind)?;
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let outcome = validate_orderbook_payload_bytes(kind, bytes.as_ref(), label, generated_at);
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Sign an already-encoded mutable orderbook payload and return signed Norito bytes.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_sign_orderbook_payload(
    kind: String,
    bytes: Uint8Array,
    private_key: Uint8Array,
) -> napi::Result<Buffer> {
    let kind = parse_sorafs_orderbook_payload_kind(&kind)?;
    let signed =
        sign_orderbook_payload_bytes_ed25519_v1(kind, bytes.as_ref(), private_key.as_ref())
            .map_err(norito_to_napi)?;
    Ok(Buffer::from(signed))
}
/// Build and sign a canonical `SoraFS` orderbook order request from fields.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
#[allow(clippy::too_many_arguments)] // N-API field-level constructor surface
pub fn sorafs_build_signed_orderbook_order_request(
    order_id: Uint8Array,
    side: String,
    tier: String,
    price_per_gib: String,
    quantity_gib: String,
    remaining_gib: Option<String>,
    owner_account: Uint8Array,
    provider_id: Uint8Array,
    expiry_unix: String,
    nonce: String,
    maker_fee_bps: u32,
    taker_fee_bps: u32,
    private_key: Uint8Array,
) -> napi::Result<Buffer> {
    let quantity_gib = parse_sorafs_decimal_u64(&quantity_gib, "quantity_gib")?;
    validate_sorafs_orderbook_owner_account(owner_account.as_ref())?;
    let owner_account = owner_account.as_ref().to_vec();
    let nonce = parse_sorafs_decimal_u64(&nonce, "nonce")?;
    if nonce == 0 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "nonce must be positive",
        ));
    }
    let supplied_order_id = parse_sorafs_fixed32(&order_id, "order_id")?;
    let expected_order_id = derive_orderbook_order_id_v1(&owner_account, nonce);
    if supplied_order_id != expected_order_id {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "order_id must equal the canonical owner-and-nonce derivation {}",
                hex::encode(expected_order_id)
            ),
        ));
    }
    let side = parse_sorafs_orderbook_side(&side)?;
    let provider_id = if provider_id.is_empty() {
        None
    } else {
        let provider_id = parse_sorafs_fixed32(&provider_id, "provider_id")?;
        if provider_id == [0; 32] {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "provider_id must not be all zero",
            ));
        }
        Some(provider_id)
    };
    let fields = OrderbookOrderRequestFieldsV1 {
        side,
        tier: parse_sorafs_orderbook_tier(&tier)?,
        price_per_gib: parse_sorafs_xor_quantity(&price_per_gib, "price_per_gib")?,
        quantity_gib,
        remaining_gib: match remaining_gib {
            Some(value) => parse_sorafs_decimal_u64(&value, "remaining_gib")?,
            None => quantity_gib,
        },
        owner_account,
        provider_id,
        expiry_unix: parse_sorafs_decimal_u64(&expiry_unix, "expiry_unix")?,
        nonce,
        maker_fee_bps: parse_sorafs_fee_bps(maker_fee_bps, "maker_fee_bps")?,
        taker_fee_bps: parse_sorafs_fee_bps(taker_fee_bps, "taker_fee_bps")?,
    };
    build_signed_orderbook_order_request_bytes_ed25519_v1(fields, private_key.as_ref())
        .map(Buffer::from)
        .map_err(norito_to_napi)
}
/// Derive the canonical `V1` `SoraFS` orderbook order ID from owner bytes and nonce.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_derive_orderbook_order_id(
    owner_account: Uint8Array,
    nonce: String,
) -> napi::Result<Buffer> {
    validate_sorafs_orderbook_owner_account(owner_account.as_ref())?;
    let nonce = parse_sorafs_decimal_u64(&nonce, "nonce")?;
    if nonce == 0 {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "nonce must be positive",
        ));
    }
    Ok(Buffer::from(
        derive_orderbook_order_id_v1(owner_account.as_ref(), nonce).to_vec(),
    ))
}
/// Build and sign a canonical `SoraFS` orderbook cancellation from fields.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_build_signed_orderbook_order_cancel(
    order_id: Uint8Array,
    owner_account: Uint8Array,
    reason: String,
    nonce: String,
    private_key: Uint8Array,
) -> napi::Result<Buffer> {
    validate_sorafs_orderbook_owner_account(owner_account.as_ref())?;
    let fields = OrderbookOrderCancelFieldsV1 {
        order_id: parse_sorafs_fixed32(&order_id, "order_id")?,
        owner_account: owner_account.as_ref().to_vec(),
        reason: parse_sorafs_orderbook_cancel_reason(&reason)?,
        nonce: parse_sorafs_decimal_u64(&nonce, "nonce")?,
    };
    build_signed_orderbook_order_cancel_bytes_ed25519_v1(fields, private_key.as_ref())
        .map(Buffer::from)
        .map_err(norito_to_napi)
}
fn validate_sorafs_orderbook_owner_account(owner_account: &[u8]) -> napi::Result<()> {
    validate_sorafs_orderbook_owner_account_v1(owner_account)
        .map_err(|error| napi::Error::new(napi::Status::InvalidArg, error))
}
/// Build and sign a canonical `SoraFS` settlement receipt from fields.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
#[allow(clippy::too_many_arguments)] // N-API field-level constructor surface
pub fn sorafs_build_signed_orderbook_settlement_receipt(
    receipt_id: Uint8Array,
    channel_id: Uint8Array,
    trade_id: Uint8Array,
    range_start: String,
    range_end: String,
    chunk_hash: Uint8Array,
    bytes_delivered: String,
    xor_debited: String,
    provider_credit: String,
    fee_amount: String,
    issued_at_unix: String,
    private_key: Uint8Array,
) -> napi::Result<Buffer> {
    let fields = OrderbookSettlementReceiptFieldsV1 {
        receipt_id: parse_sorafs_fixed32(&receipt_id, "receipt_id")?,
        channel_id: parse_sorafs_fixed32(&channel_id, "channel_id")?,
        trade_id: parse_sorafs_fixed32(&trade_id, "trade_id")?,
        range_start: parse_sorafs_decimal_u64(&range_start, "range_start")?,
        range_end: parse_sorafs_decimal_u64(&range_end, "range_end")?,
        chunk_hash: parse_sorafs_fixed32(&chunk_hash, "chunk_hash")?,
        bytes_delivered: parse_sorafs_decimal_u64(&bytes_delivered, "bytes_delivered")?,
        xor_debited: parse_sorafs_xor_quantity(&xor_debited, "xor_debited")?,
        provider_credit: parse_sorafs_xor_quantity(&provider_credit, "provider_credit")?,
        fee_amount: parse_sorafs_xor_quantity(&fee_amount, "fee_amount")?,
        issued_at_unix: parse_sorafs_decimal_u64(&issued_at_unix, "issued_at_unix")?,
    };
    build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(fields, private_key.as_ref())
        .map(Buffer::from)
        .map_err(norito_to_napi)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SorafsPdpPayloadKind {
    Commitment,
    Challenge,
    Proof,
}
fn parse_sorafs_pdp_payload_kind(kind: &str) -> napi::Result<SorafsPdpPayloadKind> {
    match kind {
        "commitment" => Ok(SorafsPdpPayloadKind::Commitment),
        "challenge" => Ok(SorafsPdpPayloadKind::Challenge),
        "proof" => Ok(SorafsPdpPayloadKind::Proof),
        _ => Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported SoraFS PDP payload kind `{kind}`"),
        )),
    }
}
fn parse_sorafs_fixture_bundle_payload_kind(
    kind: &str,
) -> napi::Result<FixtureBundlePayloadKindV1> {
    match kind {
        "provider-advert" => Ok(FixtureBundlePayloadKindV1::ProviderAdvert),
        "provider-admission-envelope" => Ok(FixtureBundlePayloadKindV1::ProviderAdmissionEnvelope),
        "replication-order" => Ok(FixtureBundlePayloadKindV1::ReplicationOrder),
        "por-challenge" => Ok(FixtureBundlePayloadKindV1::PorChallenge),
        "por-proof" => Ok(FixtureBundlePayloadKindV1::PorProof),
        "potr-receipt" => Ok(FixtureBundlePayloadKindV1::PotrReceipt),
        "repair-evidence" => Ok(FixtureBundlePayloadKindV1::RepairEvidence),
        "repair-report" => Ok(FixtureBundlePayloadKindV1::RepairReport),
        "repair-task-record" => Ok(FixtureBundlePayloadKindV1::RepairTaskRecord),
        "repair-slash-proposal" => Ok(FixtureBundlePayloadKindV1::RepairSlashProposal),
        "repair-task-event" => Ok(FixtureBundlePayloadKindV1::RepairTaskEvent),
        "orderbook-order-request" => Ok(FixtureBundlePayloadKindV1::OrderbookOrderRequest),
        "orderbook-order-cancel" => Ok(FixtureBundlePayloadKindV1::OrderbookOrderCancel),
        "orderbook-trade-event" => Ok(FixtureBundlePayloadKindV1::OrderbookTradeEvent),
        "orderbook-settlement-channel" => {
            Ok(FixtureBundlePayloadKindV1::OrderbookSettlementChannel)
        }
        "orderbook-settlement-receipt" => {
            Ok(FixtureBundlePayloadKindV1::OrderbookSettlementReceipt)
        }
        "pdp-commitment" => Ok(FixtureBundlePayloadKindV1::PdpCommitment),
        "pdp-challenge" => Ok(FixtureBundlePayloadKindV1::PdpChallenge),
        "pdp-proof" => Ok(FixtureBundlePayloadKindV1::PdpProof),
        _ => Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("unsupported SoraFS fixture-bundle payload kind `{kind}`"),
        )),
    }
}
/// Validate a Norito-encoded PDP payload and return canonical outcome JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_pdp_payload_json(
    kind: String,
    bytes: Uint8Array,
    label: String,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let kind = parse_sorafs_pdp_payload_kind(&kind)?;
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let outcome = match kind {
        SorafsPdpPayloadKind::Commitment => {
            validate_pdp_commitment_bytes(bytes.as_ref(), label, generated_at)
        }
        SorafsPdpPayloadKind::Challenge => {
            validate_pdp_challenge_bytes(bytes.as_ref(), label, generated_at)
        }
        SorafsPdpPayloadKind::Proof => {
            validate_pdp_proof_bytes(bytes.as_ref(), label, generated_at)
        }
    };
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate PDP commitment/challenge binding and return canonical outcome JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_pdp_commitment_challenge_json(
    commitment: Uint8Array,
    commitment_label: String,
    challenge: Uint8Array,
    challenge_label: String,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let outcome = validate_pdp_commitment_challenge_bytes(
        commitment.as_ref(),
        challenge.as_ref(),
        commitment_label,
        challenge_label,
        generated_at,
    );
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate PDP challenge/proof binding and return canonical outcome JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_pdp_challenge_proof_json(
    challenge: Uint8Array,
    challenge_label: String,
    proof: Uint8Array,
    proof_label: String,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let outcome = validate_pdp_challenge_proof_bytes(
        challenge.as_ref(),
        proof.as_ref(),
        challenge_label,
        proof_label,
        generated_at,
    );
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate PDP commitment/challenge/proof binding and return canonical outcome JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_pdp_bundle_json(
    commitment: Uint8Array,
    commitment_label: String,
    challenge: Uint8Array,
    challenge_label: String,
    proof: Uint8Array,
    proof_label: String,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let outcome = validate_pdp_commitment_challenge_proof_bytes(
        commitment.as_ref(),
        challenge.as_ref(),
        proof.as_ref(),
        commitment_label,
        challenge_label,
        proof_label,
        generated_at,
    );
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate a bounded heterogeneous `SoraFS` fixture bundle and its canonical
/// cross-links, returning `ValidationOutcomeV1` JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API boundary requires owned inputs
pub fn sorafs_validate_fixture_bundle_json(
    payloads: Vec<JsSorafsReferenceBundlePayload>,
    now_unix: i64,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let maximum_payloads = SORAFS_REFERENCE_FFI_MAX_BUNDLE_PAYLOADS_V1 as usize;
    if payloads.is_empty() || payloads.len() > maximum_payloads {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("payloads must contain 1..={maximum_payloads} entries"),
        ));
    }
    let now = js_number_to_u64(now_unix, "now_unix")?;
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let mut kinds = Vec::with_capacity(payloads.len());
    let mut total_bytes = 0usize;
    for (index, payload) in payloads.iter().enumerate() {
        kinds.push(parse_sorafs_fixture_bundle_payload_kind(&payload.kind)?);
        validate_sorafs_reference_label(&payload.label, &format!("payloads[{index}].label"))?;
        total_bytes = total_bytes
            .checked_add(payload.bytes.len())
            .and_then(|total| total.checked_add(payload.label.len()))
            .ok_or_else(|| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    "fixture-bundle aggregate byte length overflowed",
                )
            })?;
        let maximum_bytes = SORAFS_REFERENCE_FFI_MAX_BUNDLE_TOTAL_BYTES_V1 as usize;
        if total_bytes > maximum_bytes {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                format!("fixture-bundle inputs exceed {maximum_bytes} aggregate bytes"),
            ));
        }
    }
    let borrowed = payloads
        .iter()
        .zip(kinds)
        .map(|(payload, kind)| {
            FixtureBundlePayloadV1::new(kind, payload.label.clone(), payload.bytes.as_ref())
        })
        .collect::<Vec<_>>();
    let outcome = validate_fixture_bundle_payloads(&borrowed, now, generated_at);
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate one canonical governance log node against its required expected CID.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_governance_log_node_json(
    bytes: Uint8Array,
    label: String,
    expected_node_cid: Uint8Array,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    validate_sorafs_reference_label(&label, "label")?;
    let expected_node_cid = validate_sorafs_reference_governance_cid(
        Some(expected_node_cid.as_ref()),
        "expected_node_cid",
    )?
    .expect("required CID was supplied");
    validate_sorafs_reference_aggregate_bytes(
        "governance log-node validation",
        [bytes.len(), label.len(), expected_node_cid.len()],
    )?;
    let outcome = validate_governance_log_node_bytes(
        bytes.as_ref(),
        label,
        Some(expected_node_cid),
        generated_at,
    );
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate one canonical governance DAG block and return outcome JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn sorafs_validate_governance_dag_block_json(
    bytes: Uint8Array,
    label: String,
    expected_block_cid: Option<Uint8Array>,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    validate_sorafs_reference_label(&label, "label")?;
    let expected_block_cid = expected_block_cid.as_ref().map(|cid| {
        let cid: &[u8] = cid.as_ref();
        cid
    });
    let expected_block_cid =
        validate_sorafs_reference_governance_cid(expected_block_cid, "expected_block_cid")?;
    validate_sorafs_reference_aggregate_bytes(
        "governance DAG block validation",
        [
            bytes.len(),
            label.len(),
            expected_block_cid.map_or(0, <[u8]>::len),
        ],
    )?;
    let outcome = validate_governance_dag_block_bytes(
        bytes.as_ref(),
        label,
        expected_block_cid,
        generated_at,
    );
    json::to_string(&outcome).map_err(norito_to_napi)
}
/// Validate a signed governance DAG head against an ordered contiguous block tail.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API boundary requires owned inputs
pub fn sorafs_validate_governance_dag_head_chain_json(
    head: Uint8Array,
    head_label: String,
    blocks: Vec<JsSorafsGovernanceDagBlockInput>,
    generated_at_unix: i64,
) -> napi::Result<String> {
    let generated_at = parse_sorafs_generated_at_unix(generated_at_unix)?;
    let maximum_blocks = SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1 as usize;
    if blocks.is_empty() || blocks.len() > maximum_blocks {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("blocks must contain 1..={maximum_blocks} entries"),
        ));
    }
    validate_sorafs_reference_label(&head_label, "head_label")?;
    let mut sizes = Vec::with_capacity(2 + blocks.len() * 2);
    sizes.extend([head.len(), head_label.len()]);
    for (index, block) in blocks.iter().enumerate() {
        validate_sorafs_reference_label(&block.label, &format!("blocks[{index}].label"))?;
        sizes.extend([block.bytes.len(), block.label.len()]);
    }
    validate_sorafs_reference_aggregate_bytes("governance DAG head-chain validation", sizes)?;
    let block_payloads = blocks
        .iter()
        .map(|block| (block.bytes.as_ref(), block.label.clone()))
        .collect::<Vec<_>>();
    let outcome = validate_governance_dag_head_chain_bytes(
        head.as_ref(),
        head_label,
        &block_payloads,
        generated_at,
    );
    json::to_string(&outcome).map_err(norito_to_napi)
}
#[cfg(test)]
mod sorafs_orderbook_validation_tests {
    use super::*;
    use sorafs_manifest::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1;
    #[test]
    fn parse_sorafs_orderbook_payload_kind_requires_exact_v1_name() {
        assert_eq!(
            parse_sorafs_orderbook_payload_kind("order-request").unwrap(),
            OrderbookValidationPayloadKindV1::OrderRequest
        );
        assert_eq!(
            parse_sorafs_orderbook_payload_kind("settlement-channel").unwrap(),
            OrderbookValidationPayloadKindV1::SettlementChannel
        );
        for retired in [
            "order",
            "order_request",
            " ORDER-REQUEST",
            "request",
            "runtime-snapshot",
        ] {
            assert!(parse_sorafs_orderbook_payload_kind(retired).is_err());
        }
        assert!(parse_sorafs_orderbook_side("Bid").is_err());
        assert!(parse_sorafs_orderbook_tier(" hot").is_err());
        assert!(parse_sorafs_orderbook_cancel_reason("owner_requested").is_err());
    }
    #[test]
    fn orderbook_owner_account_validation_enforces_v1_byte_ceiling() {
        let bounded =
            validate_sorafs_orderbook_owner_account(&[0x45; ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1]);
        assert!(bounded.is_ok());
        assert!(
            validate_sorafs_orderbook_owner_account(
                &[0x45; ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + 1]
            )
            .is_err()
        );
    }
    #[test]
    fn parse_sorafs_pdp_payload_kind_requires_exact_v1_name() {
        assert_eq!(
            parse_sorafs_pdp_payload_kind("commitment").unwrap(),
            SorafsPdpPayloadKind::Commitment
        );
        assert_eq!(
            parse_sorafs_pdp_payload_kind("challenge").unwrap(),
            SorafsPdpPayloadKind::Challenge
        );
        assert_eq!(
            parse_sorafs_pdp_payload_kind("proof").unwrap(),
            SorafsPdpPayloadKind::Proof
        );
        for retired in ["pdp-commitment", "pdp_challenge", " PROOF", "Proof"] {
            assert!(parse_sorafs_pdp_payload_kind(retired).is_err());
        }
    }
    #[test]
    fn fixture_bundle_selector_and_cross_links_are_exact() {
        assert_eq!(
            parse_sorafs_fixture_bundle_payload_kind("potr-receipt").unwrap(),
            FixtureBundlePayloadKindV1::PotrReceipt
        );
        for retired in ["potr_receipt", "PoR-proof", "proof", " repair-report"] {
            assert!(parse_sorafs_fixture_bundle_payload_kind(retired).is_err());
        }
        let order =
            include_bytes!("../../../fixtures/sorafs_manifest/replication_order/order_v1.to");
        let proof = include_bytes!("../../../fixtures/sorafs_manifest/por/proof_v1.to");
        let outcome_json = sorafs_validate_fixture_bundle_json(
            vec![
                JsSorafsReferenceBundlePayload {
                    kind: "replication-order".to_owned(),
                    bytes: Buffer::from(order.to_vec()),
                    label: "replication-order.to".to_owned(),
                },
                JsSorafsReferenceBundlePayload {
                    kind: "por-proof".to_owned(),
                    bytes: Buffer::from(proof.to_vec()),
                    label: "por-proof.to".to_owned(),
                },
            ],
            1_700_000_001,
            1_700_001_237,
        )
        .expect("validate fixture bundle");
        let outcome: json::Value = json::from_json(&outcome_json).expect("outcome JSON");
        assert_eq!(
            outcome.get("status").and_then(json::Value::as_str),
            Some("Ok")
        );
        assert_eq!(
            outcome.get("generated_at").and_then(json::Value::as_u64),
            Some(1_700_001_237)
        );
    }
    #[test]
    fn parse_sorafs_xor_quantity_preserves_the_exact_signed_512_boundary() {
        const MAX_SCALED: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824.503042047";
        assert_eq!(MAX_SCALED.len(), 155);
        assert_eq!(
            parse_sorafs_xor_quantity(MAX_SCALED, "amount")
                .expect("maximum scaled XOR quantity")
                .to_string(),
            MAX_SCALED
        );
        assert!(parse_sorafs_xor_quantity("0.000000001", "amount").is_ok());
        for invalid in ["1.0", "0.0000000001", &"1".repeat(156)] {
            assert!(parse_sorafs_xor_quantity(invalid, "amount").is_err());
        }
    }
    #[test]
    fn governance_dag_reference_bounds_are_enforced_before_native_dispatch() {
        let maximum_label = SORAFS_REFERENCE_FFI_MAX_LABEL_BYTES_V1 as usize;
        assert!(validate_sorafs_reference_label(&"a".repeat(maximum_label), "label").is_ok());
        assert!(validate_sorafs_reference_label(&"a".repeat(maximum_label + 1), "label").is_err());
        let maximum_input = SORAFS_REFERENCE_FFI_MAX_INPUT_BYTES_V1 as usize;
        assert!(
            validate_sorafs_reference_aggregate_bytes("governance DAG", [maximum_input]).is_ok()
        );
        assert!(
            validate_sorafs_reference_aggregate_bytes("governance DAG", [maximum_input, 1])
                .is_err()
        );
        assert!(validate_sorafs_reference_governance_cid(None, "expected CID").is_ok());
        let exact_cid = [0_u8; SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1 as usize];
        assert!(validate_sorafs_reference_governance_cid(Some(&exact_cid), "expected CID").is_ok());
        for invalid_length in [0, exact_cid.len() - 1, exact_cid.len() + 1] {
            let invalid = vec![0_u8; invalid_length];
            assert!(
                validate_sorafs_reference_governance_cid(Some(&invalid), "expected CID").is_err()
            );
        }
    }
    #[test]
    fn governance_log_node_reference_fixture_has_stable_outcome() {
        let node =
            include_bytes!("../../../fixtures/sorafs_manifest/moderation/governance_node_v1.to");
        let expected_node_cid =
            hex::decode("4dd7d8901fd8fdd78ce9edd0456fa1dc6bb072709ddc762e43116013c15ff20c")
                .expect("fixture node CID");
        let outcome = validate_governance_log_node_bytes(
            node,
            "moderation/governance_node_v1.to",
            Some(expected_node_cid.as_slice()),
            1_700_001_234,
        );
        assert_eq!(outcome.status.as_str(), "Ok");
        assert_eq!(outcome.code, "SFS-OK-000");
        assert_eq!(outcome.generated_at, 1_700_001_234);
    }
    #[test]
    fn appeal_finance_cancel_asset_lock_native_outcomes_are_stable() {
        let canonical = include_bytes!(
            "../../../fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.to"
        );
        let zero = include_bytes!(
            "../../../fixtures/sorafs_manifest/appeal_finance/negative/cancel_asset_lock_zero_expected_v1.to"
        );
        let accepted = sorafs_validate_appeal_finance_cancel_asset_lock_json(
            Uint8Array::from(canonical.to_vec()),
            "cancel_asset_lock_v1.to".to_owned(),
            41,
        )
        .expect("validate canonical CancelAssetLock");
        let accepted: json::Value = json::from_json(&accepted).expect("accepted outcome JSON");
        assert_eq!(
            accepted.get("code").and_then(json::Value::as_str),
            Some("SFS-OK-000")
        );
        let rejected = sorafs_validate_appeal_finance_cancel_asset_lock_json(
            Uint8Array::from(zero.to_vec()),
            "cancel_asset_lock_zero_expected_v1.to".to_owned(),
            42,
        )
        .expect("validate zero-quantity CancelAssetLock");
        let rejected: json::Value = json::from_json(&rejected).expect("rejected outcome JSON");
        assert_eq!(
            rejected.get("code").and_then(json::Value::as_str),
            Some("SFS-VAL-001")
        );
    }
    #[test]
    fn governance_dag_reference_fixtures_have_stable_positive_and_negative_outcomes() {
        let root = include_bytes!("../../../fixtures/sorafs_manifest/governance/dag_block_0_v1.to");
        let child =
            include_bytes!("../../../fixtures/sorafs_manifest/governance/dag_block_1_v1.to");
        let head = include_bytes!("../../../fixtures/sorafs_manifest/governance/dag_head_v1.to");
        let block_outcome =
            validate_governance_dag_block_bytes(root, "root.to", None, 1_700_001_234);
        assert!(block_outcome.is_ok());
        assert_eq!(block_outcome.generated_at, 1_700_001_234);
        let blocks = [
            (root.as_slice(), "root.to".to_owned()),
            (child.as_slice(), "child.to".to_owned()),
        ];
        let chain_outcome =
            validate_governance_dag_head_chain_bytes(head, "head.to", &blocks, 1_700_001_235);
        assert!(chain_outcome.is_ok());
        assert_eq!(chain_outcome.generated_at, 1_700_001_235);
        let reordered = [
            (child.as_slice(), "child.to".to_owned()),
            (root.as_slice(), "root.to".to_owned()),
        ];
        let negative =
            validate_governance_dag_head_chain_bytes(head, "head.to", &reordered, 1_700_001_236);
        assert_eq!(negative.status.as_str(), "Error");
        assert_eq!(negative.code, "SFS-GOV-006");
    }
}
fn parse_hash_value(value: json::Value, context: &str) -> napi::Result<Hash> {
    iroha_js_codec::parse_hash_value(value, context).map_err(codec_to_napi)
}
#[cfg(test)]
fn parse_optional_kaigi_scalar(
    value: Option<json::Value>,
    context: &str,
) -> napi::Result<Option<KaigiAuthorizationScalarV1>> {
    iroha_js_codec::parse_optional_kaigi_scalar(value, context).map_err(codec_to_napi)
}
#[cfg(test)]
fn parse_optional_commitment(
    value: Option<json::Value>,
    context: &str,
) -> napi::Result<Option<KaigiParticipantCommitment>> {
    iroha_js_codec::parse_optional_commitment(value, context).map_err(codec_to_napi)
}
#[cfg(test)]
fn parse_optional_nullifier(
    value: Option<json::Value>,
    context: &str,
) -> napi::Result<Option<KaigiParticipantNullifier>> {
    iroha_js_codec::parse_optional_nullifier(value, context).map_err(codec_to_napi)
}
#[cfg(test)]
fn optional_kaigi_scalar_to_json(value: Option<&KaigiAuthorizationScalarV1>) -> json::Value {
    iroha_js_codec::optional_kaigi_scalar_to_json(value)
}
#[cfg(test)]
fn optional_commitment_to_json(value: Option<&KaigiParticipantCommitment>) -> json::Value {
    iroha_js_codec::optional_commitment_to_json(value)
}
#[cfg(test)]
fn optional_nullifier_to_json(value: Option<&KaigiParticipantNullifier>) -> json::Value {
    iroha_js_codec::optional_nullifier_to_json(value)
}
fn account_id_to_canonical_i105(account_id: &AccountId) -> napi::Result<String> {
    iroha_js_codec::account_id_to_canonical_i105(account_id).map_err(codec_to_napi)
}
#[cfg(test)]
fn parse_rwa_parent_refs_value(
    value: json::Value,
    context: &str,
) -> napi::Result<Vec<RwaParentRef>> {
    iroha_js_codec::parse_rwa_parent_refs_value(value, context).map_err(codec_to_napi)
}
#[cfg(test)]
fn rwa_parent_refs_to_json(parents: &[RwaParentRef]) -> json::Value {
    iroha_js_codec::rwa_parent_refs_to_json(parents)
}
#[cfg(test)]
fn new_rwa_to_json(rwa: &NewRwa) -> napi::Result<json::Value> {
    iroha_js_codec::new_rwa_to_json(rwa).map_err(codec_to_napi)
}
#[cfg(test)]
fn normalize_zk_ballot_public_inputs(value: &mut json::Value, context: &str) -> napi::Result<()> {
    iroha_js_codec::normalize_zk_ballot_public_inputs(value, context).map_err(codec_to_napi)
}
fn require_exact_json_fields(
    fields: &json::Map,
    expected: &[&str],
    context: &str,
) -> napi::Result<()> {
    iroha_js_codec::require_exact_json_fields(fields, expected, context).map_err(codec_to_napi)
}
fn validation_fee_policy_from_json_value(
    value: json::Value,
) -> napi::Result<ValidationFeePolicyV1> {
    iroha_js_codec::validation_fee_policy_from_json_value(value).map_err(codec_to_napi)
}
fn validation_fee_payout_binding_from_json_value(
    value: json::Value,
    context: &str,
) -> napi::Result<ValidationFeeTreasuryPayoutBindingV1> {
    const FIELDS: &[&str] = &[
        "contract_address",
        "code_hash",
        "entrypoint",
        "treasury_account_id",
        "ds_asset_id",
        "xor_asset_id",
        "pool_contract_address",
        "pool_code_hash",
        "pool_vault_account_id",
        "reward_pool_account_id",
        "reference_feed_id",
        "reference_feed_config_version",
        "reference_provider_accounts",
        "max_sbd_per_attempt_minor",
        "max_sbd_per_day_minor",
        "min_interval_ms",
        "max_source_age_ms",
        "max_slippage_bps",
        "validator_lane_id",
        "min_reward_claim_xor_minor",
    ];
    let fields = value.as_object().ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must be an object"),
        )
    })?;
    require_exact_json_fields(fields, FIELDS, context)?;
    json::from_value(value).map_err(norito_to_napi)
}
fn validate_validation_fee_payout_binding(
    payout_binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> napi::Result<()> {
    if let Some(reason) = payout_binding.invariant_error() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid validation-fee payout binding: {reason}"),
        ));
    }
    if payout_binding.contract_address.subject_id() != payout_binding.treasury_account_id {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "validation-fee payout contract subject must equal the payout treasury",
        ));
    }
    Ok(())
}
fn validation_fee_proposal_operator(value: &str) -> napi::Result<AccountId> {
    if value.is_empty() || value.trim() != value {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "proposal operator must be one canonical domainless AccountId",
        ));
    }
    let account = AccountId::parse_encoded(value).map_err(|error| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid proposal operator: {error}"),
        )
    })?;
    if account.to_string() != value {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "proposal operator must use canonical AccountId form",
        ));
    }
    Ok(account)
}
fn validate_validation_fee_policy_proposal(policy: &ValidationFeePolicyV1) -> napi::Result<()> {
    iroha_js_codec::validate_validation_fee_policy_proposal(policy).map_err(codec_to_napi)
}
fn instruction_from_json(payload: &str) -> napi::Result<InstructionBox> {
    iroha_js_codec::instruction_from_json(payload).map_err(codec_to_napi)
}
fn parse_instruction_payloads(payloads: Vec<String>) -> napi::Result<Vec<InstructionBox>> {
    if payloads.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "instructions must be a non-empty array",
        ));
    }
    let mut instructions = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let instruction = instruction_from_json(&payload)?;
        instructions.push(instruction);
    }
    Ok(instructions)
}
fn parse_executable_batch_payloads(
    payloads: Vec<String>,
) -> napi::Result<Vec<ExecutableBatchItem>> {
    if payloads.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "executable batch entries must be a non-empty array",
        ));
    }
    let mut entries = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.into_iter().enumerate() {
        let value: json::Value = json::from_json(&payload).map_err(|err| {
            napi::Error::new(
                napi::Status::InvalidArg,
                format!("invalid executable batch entry {index} JSON: {err}"),
            )
        })?;
        let json::Value::Object(mut fields) = value else {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                format!("executable batch entry {index} must be an object"),
            ));
        };
        let kind = fields.remove("kind").ok_or_else(|| {
            napi::Error::new(
                napi::Status::InvalidArg,
                format!("executable batch entry {index} is missing kind"),
            )
        })?;
        let json::Value::String(kind) = kind else {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                format!("executable batch entry {index} kind must be a string"),
            ));
        };
        let entry = match kind.as_str() {
            "instruction" => {
                let instruction = fields.remove("instruction").ok_or_else(|| {
                    napi::Error::new(
                        napi::Status::InvalidArg,
                        format!("executable batch entry {index} is missing instruction"),
                    )
                })?;
                if !fields.is_empty() {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        format!("executable batch instruction entry {index} has unknown fields"),
                    ));
                }
                let instruction = match instruction {
                    json::Value::String(payload) => instruction_from_json(&payload)?,
                    value => value_to_instruction(value)?,
                };
                ExecutableBatchItem::Instruction(instruction)
            }
            "contractCall" => {
                let contract_address = fields.remove("contractAddress").ok_or_else(|| {
                    napi::Error::new(
                        napi::Status::InvalidArg,
                        format!(
                            "executable batch contract call {index} is missing contractAddress"
                        ),
                    )
                })?;
                let json::Value::String(contract_address) = contract_address else {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        format!(
                            "executable batch contract call {index} contractAddress must be a string"
                        ),
                    ));
                };
                if contract_address.trim() != contract_address {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        format!(
                            "executable batch contract call {index} contractAddress must be exact"
                        ),
                    ));
                }
                let contract_address: ContractAddress =
                    contract_address.parse().map_err(|err| {
                        napi::Error::new(
                            napi::Status::InvalidArg,
                            format!(
                                "invalid executable batch contractAddress at entry {index}: {err}"
                            ),
                        )
                    })?;
                let expected_code_hash = fields.remove("expectedCodeHash").ok_or_else(|| {
                    napi::Error::new(
                        napi::Status::InvalidArg,
                        format!(
                            "executable batch contract call {index} is missing expectedCodeHash"
                        ),
                    )
                })?;
                let expected_code_hash = parse_hash_value(
                    expected_code_hash,
                    &format!("executable batch contract call {index} expectedCodeHash"),
                )?;
                let entrypoint = fields.remove("entrypoint").ok_or_else(|| {
                    napi::Error::new(
                        napi::Status::InvalidArg,
                        format!("executable batch contract call {index} is missing entrypoint"),
                    )
                })?;
                let json::Value::String(entrypoint) = entrypoint else {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        format!(
                            "executable batch contract call {index} entrypoint must be a string"
                        ),
                    ));
                };
                if entrypoint.is_empty() || entrypoint.trim() != entrypoint {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        format!(
                            "executable batch contract call {index} entrypoint must be a non-empty exact string"
                        ),
                    ));
                }
                let arguments = match fields.remove("arguments") {
                    None | Some(json::Value::Null) => None,
                    Some(value) => {
                        let bytes: Vec<u8> = json::from_value(value).map_err(|err| {
                            napi::Error::new(
                                napi::Status::InvalidArg,
                                format!("invalid executable batch contract call {index} arguments: {err}"),
                            )
                        })?;
                        Some(ContractArgumentRecord::try_new(bytes).map_err(|err| {
                            napi::Error::new(napi::Status::InvalidArg, err.to_string())
                        })?)
                    }
                };
                if !fields.is_empty() {
                    return Err(napi::Error::new(
                        napi::Status::InvalidArg,
                        format!("executable batch contract call entry {index} has unknown fields"),
                    ));
                }
                ExecutableBatchItem::ContractCall(ContractInvocation {
                    contract_address,
                    expected_code_hash,
                    entrypoint,
                    arguments,
                })
            }
            _ => {
                return Err(napi::Error::new(
                    napi::Status::InvalidArg,
                    format!(
                        "executable batch entry {index} kind must be instruction or contractCall"
                    ),
                ));
            }
        };
        entries.push(entry);
    }
    Ok(entries)
}
fn encode_trigger_action(action: &Action) -> napi::Result<String> {
    norito::to_bytes(action)
        .map(|bytes| STANDARD.encode(bytes))
        .map_err(norito_to_napi)
}
fn parse_metadata_payload(context: &str, payload: Option<String>) -> napi::Result<Metadata> {
    payload.map_or_else(
        || Ok(Metadata::default()),
        |raw| {
            json::from_json(&raw).map_err(|err| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    format!("invalid {context} metadata json: {err}"),
                )
            })
        },
    )
}
#[cfg(test)]
fn validate_governance_instruction_selectors(value: &json::Value) -> napi::Result<()> {
    iroha_js_codec::validate_governance_instruction_selectors(value).map_err(codec_to_napi)
}
#[allow(clippy::too_many_lines)] // comprehensive translation keeps instruction handling centralized
fn value_to_instruction(value: json::Value) -> napi::Result<InstructionBox> {
    iroha_js_codec::value_to_instruction(value).map_err(codec_to_napi)
}
#[allow(clippy::too_many_lines)] // mirrors `value_to_instruction` for full roundtrips
#[cfg(test)]
fn instruction_to_json_value(instruction: &InstructionBox) -> napi::Result<json::Value> {
    iroha_js_codec::instruction_to_json_value(instruction).map_err(codec_to_napi)
}
#[cfg(test)]
fn custom_json_value(payload: json::Value) -> json::Value {
    iroha_js_codec::custom_json_value(payload)
}
fn encode_canonical_signed_transaction_v1(
    transaction: &SignedTransaction,
) -> napi::Result<Vec<u8>> {
    transaction.encode_wire_v1().map_err(norito_to_napi)
}
fn decode_canonical_signed_transaction_v1(bytes: &[u8]) -> napi::Result<SignedTransaction> {
    use iroha_version::codec::DecodeVersioned as _;

    if bytes.first() != Some(&1) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "signed transaction must be canonical VersionedSignedTransaction V1 bytes",
        ));
    }
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let transaction = SignedTransaction::decode_all_versioned(bytes).map_err(|error| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid canonical VersionedSignedTransaction V1: {error}"),
        )
    })?;
    let canonical = encode_canonical_signed_transaction_v1(&transaction)?;
    if canonical.as_slice() != bytes {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "signed transaction is not the exact canonical VersionedSignedTransaction V1 encoding",
        ));
    }
    Ok(transaction)
}
#[allow(clippy::too_many_arguments)] // mirrors TransactionBuilder inputs for clarity
/// Declare one proof attachment as the execution proof carrier of a proved IVM executable.
fn ivm_proved_execution_plan(
    attachment: &ProofAttachment,
) -> napi::Result<iroha_data_model::transaction::SignedAttachmentPlanV1> {
    let mut plan = iroha_data_model::transaction::SignedAttachmentPlanV1::new();
    plan.push_action(
        iroha_data_model::transaction::signed_attachments::PlannedActionV1::ivm_proved_execution(
            attachment,
        )
        .map_err(norito_to_napi)?,
    );
    Ok(plan)
}
fn configure_transaction_builder(
    mut builder: TransactionBuilder,
    metadata: Metadata,
    attachments: Option<iroha_data_model::transaction::SignedAttachmentPlanV1>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<TransactionBuilder> {
    if let Some(ms) = creation_time_ms {
        let millis = js_number_to_u64(ms, "creation_time_ms")?;
        builder.set_creation_time(Duration::from_millis(millis));
    }
    if let Some(ms) = ttl_ms {
        let millis = js_number_to_u64(ms, "ttl_ms")?;
        if millis == 0 {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "ttl_ms must be positive",
            ));
        }
        builder.set_ttl(Duration::from_millis(millis));
    }
    if let Some(value) = nonce {
        let nonce = NonZeroU32::new(value).ok_or_else(|| {
            napi::Error::new(
                napi::Status::InvalidArg,
                "nonce must be non-zero (fits in u32)",
            )
        })?;
        builder.set_nonce(nonce);
    }
    builder = builder.with_metadata(metadata);
    if let Some(attachments) = attachments {
        // The executable and every other signed field are final here, so the
        // declared actions are validated against the payload they are bound to.
        builder = builder
            .with_attachment_plan(attachments)
            .map_err(norito_to_napi)?;
    }
    Ok(builder)
}
fn parse_fee_payment_intent(fee_payment_json: &str) -> napi::Result<FeePaymentIntent> {
    let intent = norito::json::from_str::<FeePaymentIntent>(fee_payment_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid fee payment intent JSON: {err}"),
        )
    })?;
    intent.validate().map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid fee payment intent: {err}"),
        )
    })?;
    Ok(intent)
}
#[allow(clippy::too_many_arguments)] // mirrors TransactionBuilder inputs for clarity
fn assemble_executable_transaction(
    network_id: NetworkId,
    authority: AccountId,
    executable: Executable,
    fee_payment: FeePaymentIntent,
    metadata: Metadata,
    attachments: Option<iroha_data_model::transaction::SignedAttachmentPlanV1>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: &[u8],
    algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let builder = configure_transaction_builder(
        TransactionBuilder::new(network_id, authority, fee_payment).with_executable(executable),
        metadata,
        attachments,
        creation_time_ms,
        ttl_ms,
        nonce,
    )?;
    let algorithm = parse_crypto_algorithm(algorithm.as_deref())?;
    let private_key = PrivateKey::from_bytes(algorithm, secret).map_err(norito_to_napi)?;
    let signed = sign_js_transaction(builder, &private_key, "JavaScript host assembled")?;
    let signed_bytes = encode_canonical_signed_transaction_v1(&signed)?;
    let hash = Buffer::from(signed.hash().as_ref().to_vec());
    Ok(JsSignedTransaction {
        signed_transaction: Buffer::from(signed_bytes),
        hash,
    })
}
#[allow(clippy::too_many_arguments)] // mirrors TransactionBuilder inputs for clarity
fn assemble_transaction(
    network_id: NetworkId,
    authority: AccountId,
    instructions: Vec<InstructionBox>,
    fee_payment: FeePaymentIntent,
    metadata: Metadata,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: &[u8],
    algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    if instructions.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "instructions must be a non-empty array",
        ));
    }
    assemble_executable_transaction(
        network_id,
        authority,
        Executable::from(instructions),
        fee_payment,
        metadata,
        None,
        creation_time_ms,
        ttl_ms,
        nonce,
        secret,
        algorithm,
    )
}
fn checked_batch_executable(
    entries: Vec<ExecutableBatchItem>,
    fee_payment: &FeePaymentIntent,
) -> napi::Result<Executable> {
    if entries.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "executable batch entries must be a non-empty array",
        ));
    }
    let executable = Executable::Batch(entries.into());
    if executable.requires_transaction_gas_limit() && fee_payment.gas_limit().is_none() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "fee payment gas limit is required when an executable batch contains a contract call",
        ));
    }
    Ok(executable)
}
/// Compute the canonical pipeline hash for an exact `VersionedSignedTransaction` V1 wire.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API typed arrays require ownership at the boundary
pub fn hash_signed_transaction(bytes: Uint8Array) -> napi::Result<Buffer> {
    let tx = decode_canonical_signed_transaction_v1(bytes.as_ref())?;
    let hash = tx.hash();
    Ok(Buffer::from(hash.as_ref().to_vec()))
}
/// Compute the detached-signature preimage used by Torii for a signed
/// transaction scaffold: `HashOf::new(tx.payload())`.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API typed arrays require ownership at the boundary
pub fn hash_signed_transaction_payload(bytes: Uint8Array) -> napi::Result<Buffer> {
    let tx = decode_canonical_signed_transaction_v1(bytes.as_ref())?;
    let hash = iroha_crypto::HashOf::new(tx.payload());
    Ok(Buffer::from(hash.as_ref().to_vec()))
}
/// Compute the canonical identity of an authorized instruction batch. Torii
/// uses this hash as the multisig instruction commitment, independently of occurrence identity.
#[napi]
pub fn hash_instruction_batch(
    instructions_json: Vec<String>,
    network_prefix: f64,
) -> napi::Result<Buffer> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    let _chain_guard = ChainDiscriminantGuard::enter(prefix);
    let instructions = parse_instruction_payloads(instructions_json)?;
    let hash = iroha_crypto::HashOf::new(&instructions);
    Ok(Buffer::from(hash.as_ref().to_vec()))
}
/// Decode an exact canonical `VersionedSignedTransaction` V1 wire into JSON.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn decode_signed_transaction_json(
    bytes: Uint8Array,
    network_prefix: f64,
) -> napi::Result<String> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    let _chain_guard = ChainDiscriminantGuard::enter(prefix);
    let tx = decode_canonical_signed_transaction_v1(bytes.as_ref())?;
    json::to_json(&tx).map_err(norito_to_napi)
}
/// Encode one JSON contract-call payload with the exact Kotodama entrypoint
/// schema into the canonical signed `EntrypointArgumentRecordV1` bytes.
/// Account literals must match the caller's required network prefix.
#[napi]
pub fn encode_contract_argument_record_json(
    schema_json: String,
    payload_json: String,
    network_prefix: f64,
) -> napi::Result<Buffer> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    let _chain_guard = ChainDiscriminantGuard::enter(prefix);
    let schema_value = json::parse_value(&schema_json).map_err(norito_to_napi)?;
    let schema: iroha_data_model::smart_contract::entrypoint::EntrypointArgumentSchemaV1 =
        json::from_value(schema_value).map_err(norito_to_napi)?;
    let payload_value = json::parse_value(&payload_json).map_err(norito_to_napi)?;
    let payload: Json = json::from_value(payload_value).map_err(norito_to_napi)?;
    let record = ivm_abi::arguments::encode_argument_record_from_json(&schema, &payload)
        .map_err(norito_to_napi)?;
    Ok(Buffer::from(record))
}
/// Validate and return the exact canonical `VersionedSignedTransaction` V1 wire.
#[napi]
#[allow(clippy::needless_pass_by_value)] // Uint8Array boundary requires ownership
pub fn encode_signed_transaction_versioned(bytes: Uint8Array) -> napi::Result<Buffer> {
    let tx = decode_canonical_signed_transaction_v1(bytes.as_ref())?;
    Ok(Buffer::from(encode_canonical_signed_transaction_v1(&tx)?))
}
/// Encode a `/v1/pipeline/transactions/batch` payload as a framed Norito
/// `Vec<Vec<u8>>`, where every item is a versioned signed transaction payload.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API arrays own their buffers at the boundary
pub fn encode_transaction_payload_batch(payloads: Vec<Buffer>) -> napi::Result<Buffer> {
    if payloads.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transaction payload batch must contain at least one payload",
        ));
    }
    let payloads: Vec<Vec<u8>> = payloads
        .into_iter()
        .map(|payload| payload.as_ref().to_vec())
        .collect();
    let encoded = norito::to_bytes(&payloads).map_err(norito_to_napi)?;
    Ok(Buffer::from(encoded))
}
/// Re-sign an exact canonical `VersionedSignedTransaction` V1 wire with the provided Ed25519 private key
/// and return the updated signed transaction bytes.
///
/// The caller must provide the exact expected genesis-derived network identity;
/// foreign-network and genesis-domain payloads are rejected before signing.
#[napi]
#[allow(clippy::needless_pass_by_value)] // N-API typed arrays require ownership at the boundary
pub fn sign_transaction(
    network_id: Uint8Array,
    bytes: Uint8Array,
    secret: Uint8Array,
) -> napi::Result<Buffer> {
    let expected_network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let tx = decode_canonical_signed_transaction_v1(bytes.as_ref())?;
    require_expected_transaction_network_id(
        tx.network_id(),
        &expected_network_id,
        "JavaScript transaction re-signer",
    )?;
    let builder = TransactionBuilder::from_payload(tx.payload().clone()).map_err(norito_to_napi)?;
    let private_key =
        PrivateKey::from_bytes(Algorithm::Ed25519, secret.as_ref()).map_err(norito_to_napi)?;
    let signed = sign_js_transaction(builder, &private_key, "JavaScript host re-signed")?;
    Ok(Buffer::from(encode_canonical_signed_transaction_v1(
        &signed,
    )?))
}
fn privacy_compiled_profile_catalog() -> napi::Result<PrivacyCompiledProfileCatalogV1> {
    let catalog = compiled_privacy_profile_catalog_v1().map_err(|error| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("build local privacy compiled-profile catalog: {error}"),
        )
    })?;
    debug_assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::ALL.len());
    debug_assert!(
        catalog
            .protocols
            .iter()
            .map(|row| row.protocol_id)
            .eq(PrivacyProtocolIdV1::ALL)
    );
    Ok(catalog)
}
fn encode_privacy_compiled_profile_catalog_archive(
    value: &PrivacyCompiledProfileCatalogV1,
    context: &str,
) -> napi::Result<Buffer> {
    let mut bytes = norito::encode_canonical(value).map_err(|err| {
        napi::Error::new(napi::Status::GenericFailure, format!("{context}: {err}"))
    })?;
    if bytes.len() > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1 {
        bytes.fill(0);
        return Err(napi::Error::new(
            napi::Status::GenericFailure,
            format!(
                "{context}: encoded privacy compiled-profile catalog exceeds {PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1} bytes"
            ),
        ));
    }
    let status = validate_local_privacy_compiled_profile_catalog_archive_v1(&bytes);
    if !status.is_valid() {
        bytes.fill(0);
        return Err(napi::Error::new(
            napi::Status::GenericFailure,
            format!(
                "{context}: native archive validation failed with status {}",
                status.code()
            ),
        ));
    }
    Ok(Buffer::from(bytes))
}
#[napi]
/// Return this binary's canonical typed Norito V1 privacy compiled-profile catalog.
///
/// This local catalog contains no committed height, governance activation, or
/// readiness state. Those fields are authoritative only in a fresh
/// `PrivacyCapabilitySnapshotV1` fetched from live Torii.
pub fn privacy_compiled_profile_catalog_v1() -> napi::Result<Buffer> {
    let catalog = privacy_compiled_profile_catalog()?;
    encode_privacy_compiled_profile_catalog_archive(
        &catalog,
        "encode local privacy compiled-profile catalog",
    )
}
#[napi]
/// Validate an archive as this binary's exact canonical local compiled-profile catalog.
pub fn privacy_validate_compiled_profile_catalog_v1(archive: Uint8Array) -> i32 {
    validate_local_privacy_compiled_profile_catalog_archive_v1(archive.as_ref()).code()
}
fn decode_privacy_exact12_capability_manifest_v1(
    archive: &[u8],
) -> napi::Result<PrivacyExact12CapabilityManifestV1> {
    let status = validate_privacy_capability_archive_v1(archive);
    if !status.is_valid() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "invalid canonical Exact12 capability manifest archive (native status {})",
                status.code()
            ),
        ));
    }
    let manifest: PrivacyExact12CapabilityManifestV1 =
        norito::decode_from_bytes(archive).map_err(|_| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "native Exact12 capability manifest validation/decode disagreement",
            )
        })?;
    let canonical = manifest.canonical_bytes().map_err(|_| {
        napi::Error::new(
            napi::Status::GenericFailure,
            "native Exact12 capability manifest validation/re-encoding disagreement",
        )
    })?;
    if canonical.as_slice() != archive {
        return Err(napi::Error::new(
            napi::Status::GenericFailure,
            "native Exact12 capability manifest bytes changed after validation",
        ));
    }
    Ok(manifest)
}
#[napi(js_name = "privacyValidateExact12CapabilityManifestV1")]
/// Validate an archive as the exact canonical public Exact12 capability manifest.
pub fn privacy_validate_exact12_capability_manifest_v1(archive: Uint8Array) -> i32 {
    validate_privacy_capability_archive_v1(archive.as_ref()).code()
}
#[napi(js_name = "privacyExact12CapabilityManifestJsonV1")]
/// Decode a validated canonical Exact12 manifest to its lossless typed JSON projection.
pub fn privacy_exact12_capability_manifest_json_v1(archive: Uint8Array) -> napi::Result<String> {
    let manifest = decode_privacy_exact12_capability_manifest_v1(archive.as_ref())?;
    json::to_json(&manifest).map_err(norito_to_napi)
}
#[napi(js_name = "privacyRequireExact12CapabilityTupleV1")]
/// Require active committed admission, the authenticated transport's expected network,
/// and exact equality with this binary's local profile row.
pub fn privacy_require_exact12_capability_tuple_v1(
    archive: Uint8Array,
    protocol_id: String,
    expected_network_id: Uint8Array,
) -> napi::Result<bool> {
    let expected_network_id = parse_transaction_network_id_bytes(expected_network_id.as_ref())?;
    let protocol_id = PrivacyProtocolIdV1::from_canonical_label(&protocol_id).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            "protocol_id must be one exact retained Exact12 identifier; aliases and retired identifiers are rejected",
        )
    })?;
    let manifest = decode_privacy_exact12_capability_manifest_v1(archive.as_ref())?;
    let qualification = manifest.qualification.as_ref().ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            "Exact12 admission requires target-network production qualification",
        )
    })?;
    require_privacy_exact12_network_v1(
        &qualification.deployment_qualification.network_id,
        &qualification.deployment_qualification.genesis_hash,
        &expected_network_id,
    )?;
    let network_row = manifest
        .protocols
        .iter()
        .find(|row| row.protocol_id == protocol_id)
        .ok_or_else(|| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "validated Exact12 manifest omitted its selected canonical row",
            )
        })?;
    if !network_row.is_network_available() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "privacy protocol {} is not available in the committed Exact12 manifest",
                protocol_id.canonical_label()
            ),
        ));
    }
    let local_catalog = privacy_compiled_profile_catalog()?;
    let local_row = local_catalog
        .protocols
        .iter()
        .find(|row| row.protocol_id == protocol_id)
        .ok_or_else(|| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "validated local compiled-profile catalog omitted its selected canonical row",
            )
        })?;
    if network_row.compiled_profile != local_row.compiled_profile {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!(
                "local native profile for {} does not match the committed Exact12 capability tuple",
                protocol_id.canonical_label()
            ),
        ));
    }
    Ok(true)
}

fn require_privacy_exact12_network_v1(
    actual: &NetworkId,
    genesis_hash: &[u8; Hash::LENGTH],
    expected: &NetworkId,
) -> napi::Result<()> {
    if actual != expected || genesis_hash != expected.as_bytes() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "Exact12 deployment qualification does not match the authenticated Torii network",
        ));
    }
    Ok(())
}
/// Result of signing a transaction via the native helper.
#[napi(object)]
pub struct JsSignedTransaction {
    /// Exact canonical `VersionedSignedTransaction` V1 bytes.
    pub signed_transaction: Buffer,
    /// Canonical pipeline hash for the signed transaction.
    pub hash: Buffer,
}
/// Canonical transaction payload prepared for an external signer.
#[napi(object)]
pub struct JsTransactionPayload {
    /// Bare adaptive-Norito transaction payload bytes.
    pub payload_bytes: Buffer,
    /// Iroha transaction prehash signed by an external signer.
    pub payload_hash: Buffer,
}
/// Exact unsigned transaction draft whose field prefixes are the published JavaScript API.
#[napi(object)]
#[expect(clippy::struct_field_names)]
pub struct JsTransactionPayloadDraft {
    /// Canonical Norito JSON for `TransactionPayload`, sent unchanged to `/v1/fees/quote`.
    pub payload_json: String,
    /// Bare adaptive-Norito transaction payload bytes before the quote is applied.
    pub payload_bytes: Buffer,
    /// Iroha transaction prehash for the draft payload.
    pub payload_hash: Buffer,
}
/// Input accepted by the external-signature transaction finalizer.
#[napi(object)]
pub struct JsExternalTransactionSignature {
    /// Exact expected genesis-derived network identity.
    pub network_id: Buffer,
    /// Bare adaptive-Norito payload previously returned by the payload builder.
    pub payload_bytes: Buffer,
    /// Optional lowercase hexadecimal copy of the expected payload hash.
    pub payload_hash_hex: Option<String>,
    /// Raw Ed25519 signature bytes over the Iroha payload prehash.
    pub signature: Buffer,
    /// Raw Ed25519 public-key bytes expected to control the authority account.
    pub public_key: Buffer,
    /// Required canonical authority selecting the account network and binding the payload.
    pub authority: String,
}
/// Input note material for confidential transfer/unshield proof construction.
#[napi(object)]
#[derive(Clone)]
pub struct JsConfidentialTransferInputV2 {
    /// Whole-number base-unit amount carried by the note.
    pub amount: String,
    /// Note rho rendered as 32-byte hexadecimal.
    pub rho_hex: String,
    /// Required note diversifier rendered as 32-byte hexadecimal.
    pub diversifier_hex: Option<String>,
    /// Current note leaf index inside the confidential tree.
    pub leaf_index: u32,
}
/// Output note material for confidential transfer proof construction.
#[napi(object)]
#[derive(Clone)]
pub struct JsConfidentialTransferOutputV2 {
    /// Whole-number base-unit amount carried by the note.
    pub amount: String,
    /// Fresh note rho rendered as 32-byte hexadecimal.
    pub rho_hex: String,
    /// Recipient owner tag rendered as 32-byte hexadecimal.
    pub owner_tag_hex: String,
}
/// Output note material for confidential unshield v3 change-note construction.
#[napi(object)]
#[derive(Clone)]
pub struct JsConfidentialUnshieldOutputV3 {
    /// Whole-number base-unit amount carried by the note.
    pub amount: String,
    /// Fresh note rho rendered as 32-byte hexadecimal.
    pub rho_hex: String,
}
/// Diversified confidential v2 payment address material.
#[napi(object)]
pub struct JsConfidentialReceiveAddressV2 {
    /// Recipient owner tag rendered as 32-byte hexadecimal.
    pub owner_tag_hex: String,
    /// Note diversifier rendered as 32-byte hexadecimal.
    pub diversifier_hex: String,
}
/// Result of building a confidential transfer v2 proof envelope.
#[napi(object)]
pub struct JsConfidentialTransferProofEnvelopeV2 {
    /// Nullifiers consumed by the proof.
    pub nullifiers: Vec<Buffer>,
    /// Output commitments created by the proof.
    pub output_commitments: Vec<Buffer>,
    /// Merkle root bound into the proof.
    pub root: Buffer,
    /// Norito-encoded `OpenVerifyEnvelope` payload.
    pub proof: Buffer,
}
fn parse_fixed_32_hex(context: &str, value: &str) -> napi::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must be exactly 64 lowercase hex characters"),
        ));
    }
    let mut decoded = zeroize::Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(value, decoded.as_mut()).map_err(|_| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must be canonical hex"),
        )
    })?;
    Ok(*decoded)
}

fn parse_confidential_amount_u128(context: &str, value: &str) -> napi::Result<u128> {
    let normalized = value;
    if normalized.is_empty() || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must be a non-empty whole number"),
        ));
    }
    normalized.parse::<u128>().map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid {context} whole-number amount: {err}"),
        )
    })
}
fn parse_confidential_tree_commitments(
    commitments_hex: Vec<String>,
) -> napi::Result<Vec<[u8; 32]>> {
    parse_fixed_32_hex_list("tree_commitments_hex", commitments_hex)
}
fn parse_fixed_32_hex_list(context: &str, values: Vec<String>) -> napi::Result<Vec<[u8; 32]>> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| parse_fixed_32_hex(&format!("{context}[{index}]"), &value))
        .collect()
}
fn parse_required_confidential_diversifier_hex(
    context: &str,
    value: Option<&str>,
) -> napi::Result<[u8; 32]> {
    let value = value.ok_or_else(|| {
        napi::Error::new(napi::Status::InvalidArg, format!("{context} is required"))
    })?;
    if value.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} is required"),
        ));
    }
    if value.trim() != value {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} must not contain surrounding whitespace"),
        ));
    }
    parse_fixed_32_hex(context, value)
}
fn parse_confidential_transfer_inputs_v2(
    inputs: Vec<JsConfidentialTransferInputV2>,
) -> napi::Result<Vec<ConfidentialTransferInputV2>> {
    let inputs = zeroize::Zeroizing::new(inputs);
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            // Establish the clearing owner before any fallible private-field parsing.
            let mut parsed = ConfidentialTransferInputV2 {
                amount: 0,
                rho: [0; 32],
                diversifier: [0; 32],
                leaf_index: 0,
            };
            parsed.amount =
                parse_confidential_amount_u128(&format!("inputs[{index}].amount"), &input.amount)?;
            parsed.rho = parse_fixed_32_hex(&format!("inputs[{index}].rho_hex"), &input.rho_hex)?;
            parsed.diversifier = parse_required_confidential_diversifier_hex(
                &format!("inputs[{index}].diversifier_hex"),
                input.diversifier_hex.as_deref(),
            )?;
            parsed.leaf_index = usize::try_from(input.leaf_index).map_err(|_| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    format!("inputs[{index}].leaf_index is out of range"),
                )
            })?;
            Ok(parsed)
        })
        .collect()
}
fn parse_confidential_unshield_inputs_v2(
    inputs: Vec<JsConfidentialTransferInputV2>,
) -> napi::Result<Vec<ConfidentialUnshieldInputV2>> {
    let inputs = zeroize::Zeroizing::new(inputs);
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            // Establish the clearing owner before any fallible private-field parsing.
            let mut parsed = ConfidentialUnshieldInputV2 {
                amount: 0,
                rho: [0; 32],
                diversifier: [0; 32],
                leaf_index: 0,
            };
            parsed.amount =
                parse_confidential_amount_u128(&format!("inputs[{index}].amount"), &input.amount)?;
            parsed.rho = parse_fixed_32_hex(&format!("inputs[{index}].rho_hex"), &input.rho_hex)?;
            parsed.diversifier = parse_required_confidential_diversifier_hex(
                &format!("inputs[{index}].diversifier_hex"),
                input.diversifier_hex.as_deref(),
            )?;
            parsed.leaf_index = usize::try_from(input.leaf_index).map_err(|_| {
                napi::Error::new(
                    napi::Status::InvalidArg,
                    format!("inputs[{index}].leaf_index is out of range"),
                )
            })?;
            Ok(parsed)
        })
        .collect()
}
fn parse_confidential_transfer_outputs_v2(
    outputs: Vec<JsConfidentialTransferOutputV2>,
) -> napi::Result<Vec<ConfidentialTransferOutputV2>> {
    let outputs = zeroize::Zeroizing::new(outputs);
    outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let mut parsed = ConfidentialTransferOutputV2 {
                amount: 0,
                rho: [0; 32],
                owner_tag: [0; 32],
            };
            parsed.amount = parse_confidential_amount_u128(
                &format!("outputs[{index}].amount"),
                &output.amount,
            )?;
            parsed.rho = parse_fixed_32_hex(&format!("outputs[{index}].rho_hex"), &output.rho_hex)?;
            parsed.owner_tag = parse_fixed_32_hex(
                &format!("outputs[{index}].owner_tag_hex"),
                &output.owner_tag_hex,
            )?;
            Ok(parsed)
        })
        .collect()
}
fn parse_confidential_unshield_outputs_v3(
    outputs: Vec<JsConfidentialUnshieldOutputV3>,
) -> napi::Result<Vec<ConfidentialUnshieldOutputV3>> {
    let outputs = zeroize::Zeroizing::new(outputs);
    outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let mut parsed = ConfidentialUnshieldOutputV3 {
                amount: 0,
                rho: [0; 32],
            };
            parsed.amount = parse_confidential_amount_u128(
                &format!("outputs[{index}].amount"),
                &output.amount,
            )?;
            parsed.rho = parse_fixed_32_hex(&format!("outputs[{index}].rho_hex"), &output.rho_hex)?;
            Ok(parsed)
        })
        .collect()
}
const EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES: usize = 1024 * 1024;
const EXTERNAL_TRANSACTION_METADATA_MAX_BYTES: usize = 64 * 1024;
pub(crate) fn parse_transaction_network_id_bytes(value: &[u8]) -> napi::Result<NetworkId> {
    let bytes: [u8; Hash::LENGTH] = value.try_into().map_err(|_| {
        napi::Error::new(
            napi::Status::InvalidArg,
            "networkId must contain exactly 32 genesis-header hash bytes",
        )
    })?;
    let hash = hex::encode(bytes).parse::<Hash>().map_err(|error| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("networkId must contain a marked Iroha hash: {error}"),
        )
    })?;
    Ok(NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash),
    ))
}
fn require_expected_transaction_network_id(
    actual: Option<&NetworkId>,
    expected: &NetworkId,
    context: &str,
) -> napi::Result<()> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} payload NetworkId does not match the expected NetworkId"),
        )),
        None => Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{context} cannot accept a genesis-domain transaction"),
        )),
    }
}
fn require_matching_i105_discriminant(
    expected: u16,
    account: &str,
    label: &str,
) -> napi::Result<()> {
    let actual =
        AccountAddress::i105_discriminant(account).map_err(|error| account_address_err(&error))?;
    if actual != expected {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            format!("{label} uses chain discriminant {actual}, expected {expected} from authority"),
        ));
    }
    Ok(())
}
/// Build the exact transparent asset-transfer payload consumed by an external signer.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn build_transfer_asset_payload(
    network_id: Uint8Array,
    authority: String,
    source_asset_holding_id: String,
    quantity: String,
    destination_account_id: String,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<JsTransactionPayload> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    if authority.trim() != authority || destination_account_id.trim() != destination_account_id {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "authority and destination account ids must not contain surrounding whitespace",
        ));
    }
    if source_asset_holding_id.trim() != source_asset_holding_id {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "source asset holding id must not contain surrounding whitespace",
        ));
    }
    let authority_discriminant = AccountAddress::i105_discriminant(&authority)
        .map_err(|error| account_address_err(&error))?;
    require_matching_i105_discriminant(
        authority_discriminant,
        &destination_account_id,
        "destination account",
    )?;
    let source_account_literal = source_asset_holding_id.split('#').nth(1).ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            "source asset holding id must include an I105 owner account",
        )
    })?;
    require_matching_i105_discriminant(
        authority_discriminant,
        source_account_literal,
        "source asset owner",
    )?;
    if source_account_literal != authority {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transparent browser transfer requires the source asset owner to equal authority",
        ));
    }
    let _chain_guard = ChainDiscriminantGuard::enter(authority_discriminant);
    let authority = parse_account_id(&authority, "authority account id")?;
    let authority_signatory = authority.try_signatory().ok_or_else(|| {
        napi::Error::new(
            napi::Status::InvalidArg,
            "transparent browser transfer requires a single-key authority",
        )
    })?;
    if authority_signatory
        .try_algorithm()
        .map_err(norito_to_napi)?
        != Algorithm::Ed25519
    {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transparent browser transfer supports only Ed25519 authorities",
        ));
    }
    let source = AssetId::parse_literal(&source_asset_holding_id).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid source asset holding id: {err}"),
        )
    })?;
    if source.canonical_literal() != source_asset_holding_id {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "source asset holding id must use its exact canonical literal",
        ));
    }
    let destination = parse_account_id(&destination_account_id, "destination account id")?;
    let quantity = parse_positive_transfer_quantity(&quantity)?;
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    if metadata_json
        .as_ref()
        .is_some_and(|metadata| metadata.len() > EXTERNAL_TRANSACTION_METADATA_MAX_BYTES)
    {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transaction metadata json exceeds 65536 bytes",
        ));
    }
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    let instruction: InstructionBox =
        Transfer::asset_quantity(source, quantity, destination).into();
    let builder = configure_transaction_builder(
        TransactionBuilder::new(network_id, authority, fee_payment)
            .with_instructions([instruction]),
        metadata,
        None,
        creation_time_ms,
        ttl_ms,
        nonce,
    )?;
    let payload_bytes = builder.encode_payload();
    if payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transaction payload exceeds 1048576 bytes",
        ));
    }
    Ok(JsTransactionPayload {
        payload_hash: Buffer::from(builder.payload_hash_bytes().to_vec()),
        payload_bytes: Buffer::from(payload_bytes),
    })
}
fn parse_positive_transfer_quantity(source: &str) -> napi::Result<Quantity> {
    let quantity = Quantity::from_str(source).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid transfer quantity: {err}"),
        )
    })?;
    if quantity.to_string() != source {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transfer quantity must use its exact canonical decimal spelling",
        ));
    }
    if quantity.is_zero() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transfer quantity must be greater than zero",
        ));
    }
    Ok(quantity)
}
/// Finalize a signed transaction; its payload binds the exact `NetworkId`, not the genesis domain.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn finalize_signed_transaction(
    input: JsExternalTransactionSignature,
) -> napi::Result<JsSignedTransaction> {
    let _chain_guard = scoped_chain_discriminant_for_literal(&input.authority)?;
    let expected_authority = parse_account_id(&input.authority, "asserted authority account id")?;
    let expected_network_id = parse_transaction_network_id_bytes(input.network_id.as_ref())?;
    if input.payload_bytes.is_empty()
        || input.payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES
    {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "payloadBytes must contain 1..=1048576 bytes",
        ));
    }
    let builder =
        TransactionBuilder::decode_payload(input.payload_bytes.as_ref()).map_err(|err| {
            napi::Error::new(
                napi::Status::InvalidArg,
                format!("invalid canonical transaction payload: {err}"),
            )
        })?;
    require_expected_transaction_network_id(
        builder.payload().network_id(),
        &expected_network_id,
        "JavaScript external transaction finalizer",
    )?;

    let payload_hash = builder.payload_hash_bytes();
    if let Some(expected) = input.payload_hash_hex {
        let normalized = expected.strip_prefix("0x").unwrap_or(&expected);
        let decoded = hex::decode(normalized).map_err(|_| {
            napi::Error::new(
                napi::Status::InvalidArg,
                "payloadHashHex must be exactly 32 hexadecimal bytes",
            )
        })?;
        if decoded.len() != Hash::LENGTH || decoded.as_slice() != payload_hash {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "payloadHashHex does not match payloadBytes",
            ));
        }
    }
    let public_key = PublicKey::from_bytes(Algorithm::Ed25519, input.public_key.as_ref())
        .map_err(norito_to_napi)?;
    let signature =
        iroha_crypto::ed25519_parse_signature(input.signature.as_ref()).map_err(norito_to_napi)?;
    let tx = builder.build_with_signature(signature);
    if tx.authority().try_signatory() != Some(&public_key) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "publicKey does not control the transaction authority",
        ));
    }
    if tx.authority() != &expected_authority {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "asserted authority does not match payloadBytes",
        ));
    }
    tx.verify_signature().map_err(norito_to_napi)?;
    let signed_transaction = encode_canonical_signed_transaction_v1(&tx)?;
    Ok(JsSignedTransaction {
        signed_transaction: Buffer::from(signed_transaction),
        hash: Buffer::from(tx.hash().as_ref().to_vec()),
    })
}
/// Build and sign a single-instruction `RegisterDomain` transaction.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)] // JS bindings expose this exact surface to callers
pub fn build_register_domain_transaction(
    network_id: Uint8Array,
    authority: String,
    domain_id: String,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: Uint8Array,
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    let domain_id = DomainId::parse_fully_qualified(&domain_id).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid domain id: {err}"),
        )
    })?;
    let domain_metadata = parse_metadata_payload("domain", metadata_json)?;
    let new_domain = Domain::new(domain_id).with_metadata(domain_metadata);
    let instruction: InstructionBox = Register::<Domain>::domain(new_domain).into();
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    assemble_transaction(
        network_id,
        authority,
        vec![instruction],
        fee_payment,
        Metadata::default(),
        creation_time_ms,
        ttl_ms,
        nonce,
        secret.as_ref(),
        private_key_algorithm,
    )
}
#[allow(clippy::too_many_arguments)] // helper mirrors the JS surface for clarity
fn build_transaction_from_instructions_json(
    network_id: NetworkId,
    authority: AccountId,
    instructions_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: &[u8],
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let instructions = parse_instruction_payloads(instructions_json)?;
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    assemble_transaction(
        network_id,
        authority,
        instructions,
        fee_payment,
        metadata,
        creation_time_ms,
        ttl_ms,
        nonce,
        secret,
        private_key_algorithm,
    )
}
#[allow(clippy::too_many_arguments)]
fn build_transaction_payload_from_instructions_json(
    network_id: NetworkId,
    authority: AccountId,
    instructions_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<JsTransactionPayloadDraft> {
    let instructions = parse_instruction_payloads(instructions_json)?;
    if instructions.is_empty() {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "instructions must be a non-empty array",
        ));
    }
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    let builder = configure_transaction_builder(
        TransactionBuilder::new(network_id, authority, fee_payment).with_instructions(instructions),
        metadata,
        None,
        creation_time_ms,
        ttl_ms,
        nonce,
    )?;
    let payload_bytes = builder.encode_payload();
    if payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transaction payload exceeds 1048576 bytes",
        ));
    }
    let payload_json = json::to_json(builder.payload()).map_err(norito_to_napi)?;
    Ok(JsTransactionPayloadDraft {
        payload_json,
        payload_bytes: Buffer::from(payload_bytes),
        payload_hash: Buffer::from(builder.payload_hash_bytes().to_vec()),
    })
}
#[allow(clippy::too_many_arguments)]
fn build_transaction_payload_from_batch_json(
    network_id: NetworkId,
    authority: AccountId,
    entries_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<JsTransactionPayloadDraft> {
    let entries = parse_executable_batch_payloads(entries_json)?;
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    let executable = checked_batch_executable(entries, &fee_payment)?;
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    let builder = configure_transaction_builder(
        TransactionBuilder::new(network_id, authority, fee_payment).with_executable(executable),
        metadata,
        None,
        creation_time_ms,
        ttl_ms,
        nonce,
    )?;
    let payload_bytes = builder.encode_payload();
    if payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transaction payload exceeds 1048576 bytes",
        ));
    }
    let payload_json = json::to_json(builder.payload()).map_err(norito_to_napi)?;
    Ok(JsTransactionPayloadDraft {
        payload_json,
        payload_bytes: Buffer::from(payload_bytes),
        payload_hash: Buffer::from(builder.payload_hash_bytes().to_vec()),
    })
}
/// Build, but do not sign, the exact arbitrary-instruction payload sent to fee quoting.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn build_transaction_payload(
    network_id: Uint8Array,
    authority: String,
    instructions_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<JsTransactionPayloadDraft> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    build_transaction_payload_from_instructions_json(
        network_id,
        authority,
        instructions_json,
        fee_payment_json,
        metadata_json,
        creation_time_ms,
        ttl_ms,
        nonce,
    )
}
/// Build, but do not sign, an exact ordered mixed executable-batch payload.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn build_executable_batch_transaction_payload(
    network_id: Uint8Array,
    authority: String,
    entries_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<JsTransactionPayloadDraft> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    build_transaction_payload_from_batch_json(
        network_id,
        authority,
        entries_json,
        fee_payment_json,
        metadata_json,
        creation_time_ms,
        ttl_ms,
        nonce,
    )
}
fn same_fee_payer_selection(draft: &FeePaymentIntent, quoted: &FeePaymentIntent) -> bool {
    draft.has_same_payer_and_gas_bound(quoted)
}
fn scoped_chain_discriminant_for_transaction_payload(
    payload_json: &str,
) -> napi::Result<ChainDiscriminantGuard> {
    let payload: json::Value = json::from_json(payload_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid transaction payload JSON: {err}"),
        )
    })?;
    let authority = payload
        .get("authority")
        .and_then(json::Value::as_str)
        .ok_or_else(|| {
            napi::Error::new(
                napi::Status::InvalidArg,
                "transaction payload must contain a canonical authority account id",
            )
        })?;
    scoped_chain_discriminant_for_literal(authority)
}
/// Replace only an unsigned payload's fee limits with the quote result and sign it.
/// The payload must bind the caller's exact expected `NetworkId` and cannot use the genesis domain.
/// Its required authority selects the network prefix for all account literals.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sign_quoted_transaction_payload(
    network_id: Uint8Array,
    payload_json: String,
    quoted_fee_payment_json: String,
    secret: Uint8Array,
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let _chain_guard = scoped_chain_discriminant_for_transaction_payload(&payload_json)?;
    let expected_network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let mut payload: TransactionPayload = json::from_json(&payload_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid transaction payload JSON: {err}"),
        )
    })?;
    require_expected_transaction_network_id(
        payload.network_id(),
        &expected_network_id,
        "quoted JavaScript transaction signer",
    )?;
    let quoted_fee_payment = parse_fee_payment_intent(&quoted_fee_payment_json)?;
    if !same_fee_payer_selection(&payload.fee_payment, &quoted_fee_payment) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "quoted fee intent changed the selected payer, exact sponsor program revision, or gas bound",
        ));
    }
    payload.fee_payment = quoted_fee_payment;
    let builder = TransactionBuilder::from_payload(payload).map_err(norito_to_napi)?;
    let algorithm = parse_crypto_algorithm(private_key_algorithm.as_deref())?;
    let private_key = PrivateKey::from_bytes(algorithm, secret.as_ref()).map_err(norito_to_napi)?;
    let signed = sign_js_transaction(builder, &private_key, "quoted JavaScript payload")?;
    let signed_bytes = encode_canonical_signed_transaction_v1(&signed)?;
    Ok(JsSignedTransaction {
        signed_transaction: Buffer::from(signed_bytes),
        hash: Buffer::from(signed.hash().as_ref().to_vec()),
    })
}
/// Replace only an unsigned proved-IVM payload's fee limits, reattach its proof, and sign it.
/// The payload must bind the caller's exact expected `NetworkId` and cannot use the genesis domain.
/// Its required authority selects the network prefix for all account literals.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn sign_quoted_ivm_proved_transaction_payload(
    network_id: Uint8Array,
    payload_json: String,
    attachment_json: String,
    quoted_fee_payment_json: String,
    secret: Uint8Array,
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let _chain_guard = scoped_chain_discriminant_for_transaction_payload(&payload_json)?;
    let expected_network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let mut payload: TransactionPayload = json::from_json(&payload_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid transaction payload JSON: {err}"),
        )
    })?;
    require_expected_transaction_network_id(
        payload.network_id(),
        &expected_network_id,
        "quoted proved-IVM JavaScript transaction signer",
    )?;
    if !matches!(payload.instructions, Executable::IvmProved(_)) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "quoted proved-IVM signer requires an IvmProved executable",
        ));
    }
    let attachment: ProofAttachment = json::from_json(&attachment_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid ProofAttachment json: {err}"),
        )
    })?;
    let quoted_fee_payment = parse_fee_payment_intent(&quoted_fee_payment_json)?;
    if !same_fee_payer_selection(&payload.fee_payment, &quoted_fee_payment) {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "quoted fee intent changed the selected payer, exact sponsor program revision, or gas bound",
        ));
    }
    payload.fee_payment = quoted_fee_payment;
    let builder = TransactionBuilder::from_payload(payload)
        .map_err(norito_to_napi)?
        .with_attachment_plan(ivm_proved_execution_plan(&attachment)?)
        .map_err(norito_to_napi)?;
    let algorithm = parse_crypto_algorithm(private_key_algorithm.as_deref())?;
    let private_key = PrivateKey::from_bytes(algorithm, secret.as_ref()).map_err(norito_to_napi)?;
    let signed = sign_js_transaction(
        builder,
        &private_key,
        "quoted proved-IVM JavaScript payload",
    )?;
    let signed_bytes = encode_canonical_signed_transaction_v1(&signed)?;
    Ok(JsSignedTransaction {
        signed_transaction: Buffer::from(signed_bytes),
        hash: Buffer::from(signed.hash().as_ref().to_vec()),
    })
}
/// Build and sign a transaction from an array of instruction JSON payloads.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)] // JS bindings expose this exact surface to callers
pub fn build_transaction(
    network_id: Uint8Array,
    authority: String,
    instructions_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: Uint8Array,
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    build_transaction_from_instructions_json(
        network_id,
        authority,
        instructions_json,
        fee_payment_json,
        metadata_json,
        creation_time_ms,
        ttl_ms,
        nonce,
        secret.as_ref(),
        private_key_algorithm,
    )
}
/// Build and sign a transaction from ordered instruction and contract-call entries.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn build_executable_batch_transaction(
    network_id: Uint8Array,
    authority: String,
    entries_json: Vec<String>,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: Uint8Array,
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    let entries = parse_executable_batch_payloads(entries_json)?;
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    let executable = checked_batch_executable(entries, &fee_payment)?;
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    assemble_executable_transaction(
        network_id,
        authority,
        executable,
        fee_payment,
        metadata,
        None,
        creation_time_ms,
        ttl_ms,
        nonce,
        secret.as_ref(),
        private_key_algorithm,
    )
}
/// Build, but do not sign, an `Executable::IvmProved` payload and its proof attachment.
///
/// The returned payload is the exact payload that must be submitted to the fee-quote endpoint
/// before applying the quoted limits with [`sign_quoted_ivm_proved_transaction_payload`].
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn build_ivm_proved_transaction_payload(
    network_id: Uint8Array,
    authority: String,
    proved_json: String,
    attachment_json: String,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
) -> napi::Result<JsTransactionPayloadDraft> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    let proved: IvmProved = json::from_json(&proved_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid IvmProved json: {err}"),
        )
    })?;
    let attachment: ProofAttachment = json::from_json(&attachment_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid ProofAttachment json: {err}"),
        )
    })?;
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    let builder = configure_transaction_builder(
        TransactionBuilder::new(network_id, authority, fee_payment)
            .with_executable(Executable::IvmProved(proved)),
        metadata,
        Some(ivm_proved_execution_plan(&attachment)?),
        creation_time_ms,
        ttl_ms,
        nonce,
    )?;
    let payload_bytes = builder.encode_payload();
    if payload_bytes.len() > EXTERNAL_TRANSACTION_PAYLOAD_MAX_BYTES {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "transaction payload exceeds 1048576 bytes",
        ));
    }
    let payload_json = json::to_json(builder.payload()).map_err(norito_to_napi)?;
    Ok(JsTransactionPayloadDraft {
        payload_json,
        payload_bytes: Buffer::from(payload_bytes),
        payload_hash: Buffer::from(builder.payload_hash_bytes().to_vec()),
    })
}
/// Build and sign a transaction carrying an `Executable::IvmProved` payload and its proof attachment.
#[napi]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)] // JS bindings expose this exact surface to callers
pub fn build_ivm_proved_transaction(
    network_id: Uint8Array,
    authority: String,
    proved_json: String,
    attachment_json: String,
    fee_payment_json: String,
    metadata_json: Option<String>,
    creation_time_ms: Option<i64>,
    ttl_ms: Option<i64>,
    nonce: Option<u32>,
    secret: Uint8Array,
    private_key_algorithm: Option<String>,
) -> napi::Result<JsSignedTransaction> {
    let network_id = parse_transaction_network_id_bytes(network_id.as_ref())?;
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "authority account id")?;
    let proved: IvmProved = json::from_json(&proved_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid IvmProved json: {err}"),
        )
    })?;
    let attachment: ProofAttachment = json::from_json(&attachment_json).map_err(|err| {
        napi::Error::new(
            napi::Status::InvalidArg,
            format!("invalid ProofAttachment json: {err}"),
        )
    })?;
    let fee_payment = parse_fee_payment_intent(&fee_payment_json)?;
    let metadata = parse_metadata_payload("transaction", metadata_json)?;
    assemble_executable_transaction(
        network_id,
        authority,
        Executable::IvmProved(proved),
        fee_payment,
        metadata,
        Some(ivm_proved_execution_plan(&attachment)?),
        creation_time_ms,
        ttl_ms,
        nonce,
        secret.as_ref(),
        private_key_algorithm,
    )
}
/// Build a Norito-encoded trigger action that executes on a time schedule.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn build_time_trigger_action(
    authority: String,
    instructions_json: Vec<String>,
    start_timestamp_ms: i64,
    period_ms: Option<i64>,
    repeats: Option<u32>,
    metadata_json: Option<String>,
) -> napi::Result<String> {
    let start_timestamp_ms = ensure_positive(start_timestamp_ms, "start_timestamp_ms")?;
    let period_ms = if let Some(period) = period_ms {
        Some(ensure_positive(period, "period_ms")?)
    } else {
        None
    };
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "trigger authority")?;
    let instructions = parse_instruction_payloads(instructions_json)?;
    let executable = Executable::from(instructions);
    let repeats = match repeats {
        Some(0) => {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "repeats must be greater than zero when provided",
            ));
        }
        Some(value) => Repeats::Exactly(value),
        None => Repeats::Indefinitely,
    };
    let metadata = parse_metadata_payload("trigger", metadata_json)?;
    let mut schedule = TimeSchedule::starting_at(Duration::from_millis(start_timestamp_ms));
    if let Some(period) = period_ms {
        schedule = schedule.with_period(Duration::from_millis(period));
    }
    let action = Action::new(
        executable,
        repeats,
        authority,
        TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
    )
    .map_err(|error| napi::Error::new(napi::Status::InvalidArg, error.to_string()))?
    .with_metadata(metadata);
    encode_trigger_action(&action)
}
/// Build a Norito-encoded trigger action that fires at the pre-commit stage.
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn build_precommit_trigger_action(
    authority: String,
    instructions_json: Vec<String>,
    repeats: Option<u32>,
    metadata_json: Option<String>,
) -> napi::Result<String> {
    let _chain_guard = scoped_chain_discriminant_for_literal(&authority)?;
    let authority = parse_account_id(&authority, "trigger authority")?;
    let instructions = parse_instruction_payloads(instructions_json)?;
    let executable = Executable::from(instructions);
    let repeats = match repeats {
        Some(0) => {
            return Err(napi::Error::new(
                napi::Status::InvalidArg,
                "repeats must be greater than zero when provided",
            ));
        }
        Some(value) => Repeats::Exactly(value),
        None => Repeats::Indefinitely,
    };
    let metadata = parse_metadata_payload("trigger", metadata_json)?;
    let action = Action::new(
        executable,
        repeats,
        authority,
        TimeEventFilter::new(ExecutionTime::PreCommit),
    )
    .map_err(|error| napi::Error::new(napi::Status::InvalidArg, error.to_string()))?
    .with_metadata(metadata);
    encode_trigger_action(&action)
}
#[cfg(test)]
mod tests {
    fn test_network_id(label: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            label,
        )))
    }
    fn test_network_id_bytes(label: &[u8]) -> Uint8Array {
        Uint8Array::from(test_network_id(label).as_bytes().to_vec())
    }
    #[test]
    fn crypto_algorithm_parser_accepts_exact_canonical_labels() {
        assert_eq!(
            parse_crypto_algorithm(None).expect("default crypto algorithm"),
            Algorithm::Ed25519
        );
        for expected in SUPPORTED_CRYPTO_ALGORITHMS {
            let label = expected.as_static_str();
            assert_eq!(
                parse_crypto_algorithm(Some(label)).expect("canonical crypto algorithm label"),
                *expected,
                "{label}"
            );
        }
    }
    #[test]
    fn crypto_algorithm_parser_rejects_aliases_and_noncanonical_spellings() {
        for label in [
            "",
            "ed",
            "eddsa",
            "ed-25519",
            "ED25519",
            "secp",
            "SECP_256K1",
            "mldsa",
            "ML-DSA",
            "ML-DSA-65",
            "mldsa65",
            " ml-dsa",
            "ml-dsa ",
            "BLS-NORMAL",
            "bls12381g1",
            "blssmall",
            "gost256a",
            "GOST-3410-2012-256-PARAMSETA",
            "SM2",
            "ML-DSA-44",
            "ml\u{ff0d}dsa",
        ] {
            assert!(
                parse_crypto_algorithm(Some(label)).is_err(),
                "noncanonical crypto algorithm label {label:?} must fail"
            );
        }
    }
    #[test]
    fn transaction_network_id_requires_exact_marked_32_bytes() {
        let expected = test_network_id(b"js-network-id-boundary");
        assert_eq!(
            parse_transaction_network_id_bytes(expected.as_bytes())
                .expect("canonical network id bytes"),
            expected
        );
        for invalid in [vec![], vec![0; Hash::LENGTH - 1], vec![0; Hash::LENGTH + 1]] {
            assert!(
                parse_transaction_network_id_bytes(&invalid).is_err(),
                "network id byte length {} must be rejected",
                invalid.len()
            );
        }
        let mut unmarked = *expected.as_bytes();
        unmarked[Hash::LENGTH - 1] &= !1;
        assert!(
            parse_transaction_network_id_bytes(&unmarked).is_err(),
            "an unmarked digest must not be normalized into a NetworkId"
        );
    }
    #[test]
    fn axt_touch_manifest_trims_drops_and_orders_unicode_paths() {
        let bmp_private_use = "\u{e000}/bmp-private-use";
        let astral = "\u{10000}/astral";
        let manifest = axt_touch_manifest(
            vec![
                String::new(),
                " \t\n".to_owned(),
                "\u{85}".to_owned(),
                "\u{3000}".to_owned(),
                format!(" {astral} "),
                bmp_private_use.to_owned(),
                astral.to_owned(),
            ],
            vec!["\u{2003}write/path\u{202f}".to_owned(), "\r\n".to_owned()],
        )
        .expect("canonical touch manifest");
        let decoded: TouchManifest =
            json::from_json(&manifest.manifest_json).expect("decode touch manifest JSON");
        assert_eq!(
            decoded.read,
            vec![bmp_private_use.to_owned(), astral.to_owned()]
        );
        assert_eq!(decoded.write, vec!["write/path".to_owned()]);
    }
    #[test]
    fn axt_compute_binding_rejects_alternate_norito_layout() {
        let descriptor = AxtDescriptorBuilder::new()
            .dataspace(DataSpaceId::new(7))
            .touch(
                DataSpaceId::new(7),
                ["read/path".to_owned()],
                ["write/path".to_owned()],
            )
            .build()
            .expect("valid AXT descriptor");
        let canonical = {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::to_bytes(&descriptor).expect("encode canonical descriptor")
        };
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&descriptor).expect("encode alternate-layout descriptor")
        };
        assert_ne!(alternate, canonical);
        assert_eq!(
            decode_from_bytes::<AxtDescriptor>(&alternate)
                .expect("ordinary Norito accepts its advertised layout"),
            descriptor
        );
        let canonical_binding =
            axt_compute_binding(Buffer::from(canonical.clone())).expect("canonical descriptor");
        let error = axt_compute_binding(Buffer::from(alternate))
            .err()
            .expect("alternate Norito layout must be rejected");
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert!(error.reason.contains("canonical Norito V1 layout"));
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_before = norito::to_bytes(&descriptor).expect("encode ambient descriptor");
        let ambient_binding = axt_compute_binding(Buffer::from(canonical))
            .expect("canonical descriptor under alternate ambient flags");
        assert_eq!(
            ambient_binding.to_vec(),
            canonical_binding.to_vec(),
            "canonical binding must be independent of ambient Norito flags"
        );
        assert_eq!(
            norito::to_bytes(&descriptor).expect("encode after canonical binding"),
            ambient_before,
            "canonical decoding must restore the caller's ambient layout"
        );
    }
    #[test]
    fn validation_fee_hash_roles_distinguish_raw_digests_from_iroha_hashes() {
        let hash = Uint8Array::from(vec![0x02; 32]);
        assert_eq!(
            validation_fee_fixed_hash(&hash, "checkpoint")
                .expect("non-zero even-ending raw digest is valid"),
            [0x02; 32]
        );
        assert!(validation_fee_fixed_hash(&Uint8Array::from(vec![0; 32]), "checkpoint").is_err());
        assert!(validation_fee_iroha_hash(&hash, "checkpoint").is_err());
        assert_eq!(
            validation_fee_iroha_hash(&Uint8Array::from(vec![0x03; 32]), "checkpoint")
                .expect("marked Iroha hash"),
            [0x03; 32],
        );
    }
    fn replication_order_with_timestamps(issued_at: u64, deadline_at: u64) -> ReplicationOrderV1 {
        ReplicationOrderV1 {
            version: 1,
            order_id: [1; 32],
            manifest_cid: vec![1],
            manifest_digest: [1; 32],
            chunking_profile: String::new(),
            target_replicas: 0,
            assignments: Vec::new(),
            issued_at,
            deadline_at,
            sla: sorafs_manifest::capacity::ReplicationOrderSlaV1 {
                ingest_deadline_secs: 0,
                min_availability_percent_milli: 0,
                min_por_success_percent_milli: 0,
            },
            metadata: Vec::new(),
        }
    }
    fn transaction_builder_for_number_boundary() -> TransactionBuilder {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        TransactionBuilder::new(
            test_network_id(b"js-number-boundary"),
            AccountId::new(keypair.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
    }
    #[test]
    fn alias_policy_number_fields_accept_js_max_safe_integer() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let options = JsAliasPolicy {
            positive_ttl_secs: Some(maximum),
            refresh_window_secs: Some(maximum),
            hard_expiry_secs: Some(maximum),
            negative_ttl_secs: Some(maximum),
            revocation_ttl_secs: Some(maximum),
            rotation_max_age_secs: Some(maximum),
            successor_grace_secs: Some(maximum),
            governance_grace_secs: Some(maximum),
        };
        let policy = alias_policy_from_js(Some(&options))
            .expect("policy fields at JavaScript's safe integer limit must be accepted");
        for duration in [
            policy.positive_ttl(),
            policy.refresh_window(),
            policy.hard_expiry(),
            policy.negative_ttl(),
            policy.revocation_ttl(),
            policy.rotation_max_age(),
            policy.successor_grace(),
            policy.governance_grace(),
        ] {
            assert_eq!(duration.as_secs(), JS_MAX_SAFE_INTEGER_U64);
        }
    }
    #[test]
    fn alias_policy_number_fields_above_js_max_safe_integer_return_errors() {
        let over_limit = i64::try_from(JS_MAX_SAFE_INTEGER_U64 + 1)
            .expect("integer immediately above JavaScript's safe limit must fit in i64");
        let cases = [
            (
                "positiveTtlSecs",
                JsAliasPolicy {
                    positive_ttl_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "refreshWindowSecs",
                JsAliasPolicy {
                    refresh_window_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "hardExpirySecs",
                JsAliasPolicy {
                    hard_expiry_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "negativeTtlSecs",
                JsAliasPolicy {
                    negative_ttl_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "revocationTtlSecs",
                JsAliasPolicy {
                    revocation_ttl_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "rotationMaxAgeSecs",
                JsAliasPolicy {
                    rotation_max_age_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "successorGraceSecs",
                JsAliasPolicy {
                    successor_grace_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "governanceGraceSecs",
                JsAliasPolicy {
                    governance_grace_secs: Some(over_limit),
                    ..Default::default()
                },
            ),
        ];
        for (field, options) in cases {
            let error = alias_policy_from_js(Some(&options))
                .expect_err("policy field above JavaScript's safe integer limit must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("safe integer"));
        }
    }
    #[test]
    fn sorafs_generated_at_input_enforces_js_safe_integer_range() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        assert_eq!(
            parse_sorafs_generated_at_unix(maximum)
                .expect("JavaScript max safe integer must be accepted"),
            JS_MAX_SAFE_INTEGER_U64
        );
        let error = parse_sorafs_generated_at_unix(maximum + 1)
            .expect_err("timestamp above JavaScript's safe integer limit must be rejected");
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert!(error.reason.contains("generated_at_unix"));
        assert!(error.reason.contains("safe integer"));
    }
    #[test]
    fn transaction_timestamp_inputs_enforce_js_safe_integer_range() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let _ = configure_transaction_builder(
            transaction_builder_for_number_boundary(),
            Metadata::default(),
            None,
            Some(maximum),
            Some(maximum),
            None,
        )
        .expect("transaction timestamps at JavaScript's safe integer limit must be accepted");
        for (field, creation_time_ms, ttl_ms) in [
            ("creation_time_ms", Some(maximum + 1), None),
            ("ttl_ms", None, Some(maximum + 1)),
        ] {
            let error = configure_transaction_builder(
                transaction_builder_for_number_boundary(),
                Metadata::default(),
                None,
                creation_time_ms,
                ttl_ms,
                None,
            )
            .expect_err("transaction timestamp above the safe integer limit must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("safe integer"));
        }
    }
    #[test]
    fn time_trigger_inputs_enforce_js_safe_integer_range() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let accepted_error = build_time_trigger_action(
            String::new(),
            Vec::new(),
            maximum,
            Some(maximum),
            None,
            None,
        )
        .expect_err("invalid authority must fail after accepting safe timestamp inputs");
        assert!(!accepted_error.reason.contains("safe integer"));
        for (field, start_timestamp_ms, period_ms) in [
            ("start_timestamp_ms", maximum + 1, None),
            ("period_ms", 1, Some(maximum + 1)),
        ] {
            let error = build_time_trigger_action(
                String::new(),
                Vec::new(),
                start_timestamp_ms,
                period_ms,
                None,
                None,
            )
            .expect_err("trigger timestamp above the safe integer limit must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("safe integer"));
        }
    }
    #[test]
    fn alias_evaluation_dto_accepts_js_max_safe_integer_fields() {
        let maximum = JS_MAX_SAFE_INTEGER_U64;
        let expected = i64::try_from(maximum).expect("JavaScript safe integer must fit in i64");
        let evaluation = AliasProofEvaluation {
            state: AliasProofState::Fresh,
            rotation_due: false,
            age: std::time::Duration::from_secs(maximum),
            generated_at_unix: maximum,
            expires_at_unix: maximum,
            expires_in: Some(std::time::Duration::from_secs(maximum)),
        };
        let dto = alias_evaluation_to_js(evaluation)
            .expect("JavaScript max safe integer should be representable by the binding");
        assert_eq!(dto.age_seconds, expected);
        assert_eq!(dto.generated_at_unix, expected);
        assert_eq!(dto.expires_at_unix, expected);
        assert_eq!(dto.expires_in_seconds, Some(expected));
    }
    #[test]
    fn alias_evaluation_dto_fields_above_js_max_safe_integer_return_errors() {
        let over_limit = JS_MAX_SAFE_INTEGER_U64 + 1;
        let base = AliasProofEvaluation {
            state: AliasProofState::Fresh,
            rotation_due: false,
            age: std::time::Duration::ZERO,
            generated_at_unix: 1,
            expires_at_unix: 2,
            expires_in: Some(std::time::Duration::from_secs(1)),
        };
        let cases = [
            (
                "age_seconds",
                AliasProofEvaluation {
                    age: std::time::Duration::from_secs(over_limit),
                    ..base
                },
            ),
            (
                "generated_at_unix",
                AliasProofEvaluation {
                    generated_at_unix: over_limit,
                    ..base
                },
            ),
            (
                "expires_at_unix",
                AliasProofEvaluation {
                    expires_at_unix: over_limit,
                    ..base
                },
            ),
            (
                "expires_in_seconds",
                AliasProofEvaluation {
                    expires_in: Some(std::time::Duration::from_secs(over_limit)),
                    ..base
                },
            ),
        ];
        for (field, evaluation) in cases {
            let error = alias_evaluation_to_js(evaluation)
                .err()
                .expect("out-of-range alias evaluation field must return an error");
            assert_eq!(error.status, napi::Status::GenericFailure);
            assert!(
                error.reason.contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }
    #[test]
    fn alias_evaluation_now_secs_enforces_js_safe_integer_range() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let accepted_error = sorafs_evaluate_alias_proof(String::new(), None, Some(maximum))
            .err()
            .expect("empty proof must be rejected after accepting the timestamp");
        assert!(accepted_error.reason.contains("proof must not be empty"));
        let rejected_error = sorafs_evaluate_alias_proof(String::new(), None, Some(maximum + 1))
            .err()
            .expect("timestamp above JavaScript's safe integer limit must be rejected");
        assert_eq!(rejected_error.status, napi::Status::InvalidArg);
        assert!(rejected_error.reason.contains("now_secs"));
        assert!(rejected_error.reason.contains("safe integer"));
    }
    #[test]
    fn alias_fixture_explicit_timestamps_enforce_js_safe_integer_range() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let over_limit = maximum + 1;
        let accepted = resolve_fixture_timestamps(
            &JsAliasProofFixtureOptions {
                generated_at_unix: Some(maximum - 1),
                expires_at_unix: Some(maximum),
                ..Default::default()
            },
            0,
        )
        .expect("timestamps through JavaScript's safe integer limit must be accepted");
        assert_eq!(
            accepted,
            (JS_MAX_SAFE_INTEGER_U64 - 1, JS_MAX_SAFE_INTEGER_U64)
        );
        for (field, options) in [
            (
                "generatedAtUnix",
                JsAliasProofFixtureOptions {
                    generated_at_unix: Some(over_limit),
                    expires_at_unix: Some(over_limit + 1),
                    ..Default::default()
                },
            ),
            (
                "expiresAtUnix",
                JsAliasProofFixtureOptions {
                    generated_at_unix: Some(1),
                    expires_at_unix: Some(over_limit),
                    ..Default::default()
                },
            ),
        ] {
            let error = resolve_fixture_timestamps(&options, 0)
                .expect_err("timestamp above JavaScript's safe integer limit must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("safe integer"));
        }
    }
    #[test]
    fn alias_fixture_default_manifest_cid_is_canonical() {
        let cid = resolve_manifest_cid(&JsAliasProofFixtureOptions::default())
            .expect("default manifest CID should resolve");
        assert_eq!(
            cid,
            sorafs_manifest::canonical_manifest_root_cid([0xAA; 32])
        );
    }
    #[test]
    fn alias_fixture_epoch_overrides_enforce_js_safe_integer_range() {
        let maximum = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let over_limit = maximum + 1;
        let accepted = resolve_fixture_epochs(&JsAliasProofFixtureOptions {
            bound_at_epoch: Some(maximum),
            expiry_epoch: Some(maximum),
            ..Default::default()
        })
        .expect("epoch overrides through JavaScript's safe integer limit must be accepted");
        assert_eq!(accepted, (JS_MAX_SAFE_INTEGER_U64, JS_MAX_SAFE_INTEGER_U64));
        for (field, options) in [
            (
                "boundAtEpoch",
                JsAliasProofFixtureOptions {
                    bound_at_epoch: Some(over_limit),
                    ..Default::default()
                },
            ),
            (
                "expiryEpoch",
                JsAliasProofFixtureOptions {
                    expiry_epoch: Some(over_limit),
                    ..Default::default()
                },
            ),
        ] {
            let error = resolve_fixture_epochs(&options)
                .expect_err("epoch above JavaScript's safe integer limit must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("safe integer"));
        }
    }
    #[test]
    fn alias_fixture_default_expiry_accepts_js_max_safe_integer() {
        let generated_at_unix =
            i64::try_from(JS_MAX_SAFE_INTEGER_U64 - SORAFS_ALIAS_POSITIVE_TTL_SECS)
                .expect("JavaScript safe integer must fit in i64");
        let expected_expiry = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        let fixture = sorafs_alias_proof_fixture(Some(JsAliasProofFixtureOptions {
            generated_at_unix: Some(generated_at_unix),
            ..Default::default()
        }))
        .expect("default expiry at the JavaScript safe integer limit should be representable");
        assert_eq!(fixture.generated_at_unix, generated_at_unix);
        assert_eq!(fixture.expires_at_unix, expected_expiry);
    }
    #[test]
    fn alias_fixture_default_expiry_above_js_max_safe_integer_returns_error() {
        let generated_at_unix =
            i64::try_from(JS_MAX_SAFE_INTEGER_U64 - SORAFS_ALIAS_POSITIVE_TTL_SECS + 1)
                .expect("JavaScript safe integer must fit in i64");
        let error = sorafs_alias_proof_fixture(Some(JsAliasProofFixtureOptions {
            generated_at_unix: Some(generated_at_unix),
            ..Default::default()
        }))
        .err()
        .expect("out-of-range default expiry must return an error");
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert!(error.reason.contains("default expiresAtUnix"));
    }
    #[test]
    fn replication_assignment_slice_gib_accepts_js_max_safe_integer() {
        let assignments = to_js_replication_assignments(vec![
            sorafs_manifest::capacity::ReplicationAssignmentV1 {
                provider_id: [1; 32],
                slice_gib: JS_MAX_SAFE_INTEGER_U64,
                lane: None,
            },
        ])
        .expect("JavaScript max safe integer should be representable by the binding");
        assert_eq!(assignments.len(), 1);
        assert_eq!(
            assignments[0].slice_gib,
            i64::try_from(JS_MAX_SAFE_INTEGER_U64)
                .expect("JavaScript safe integer must fit in i64")
        );
    }
    #[test]
    fn replication_assignment_slice_gib_above_js_max_safe_integer_returns_error() {
        let error = to_js_replication_assignments(vec![
            sorafs_manifest::capacity::ReplicationAssignmentV1 {
                provider_id: [1; 32],
                slice_gib: JS_MAX_SAFE_INTEGER_U64 + 1,
                lane: None,
            },
        ])
        .err()
        .expect("slice_gib above JavaScript's safe integer limit must return an error");
        assert_eq!(error.status, napi::Status::GenericFailure);
        assert!(error.reason.contains("slice_gib"));
    }
    #[test]
    fn replication_order_timestamps_accept_js_max_safe_integer() {
        let order = to_js_replication_order(replication_order_with_timestamps(
            JS_MAX_SAFE_INTEGER_U64,
            JS_MAX_SAFE_INTEGER_U64,
        ))
        .expect("JavaScript max safe integer should be representable by the binding");
        let expected = i64::try_from(JS_MAX_SAFE_INTEGER_U64)
            .expect("JavaScript safe integer must fit in i64");
        assert_eq!(order.issued_at_unix, expected);
        assert_eq!(order.deadline_at_unix, expected);
    }
    #[test]
    fn replication_order_timestamps_above_js_max_safe_integer_return_errors() {
        let over_limit = JS_MAX_SAFE_INTEGER_U64 + 1;
        for (field, order) in [
            (
                "issued_at",
                replication_order_with_timestamps(over_limit, 1),
            ),
            (
                "deadline_at",
                replication_order_with_timestamps(1, over_limit),
            ),
        ] {
            let error = to_js_replication_order(order)
                .err()
                .expect("timestamp above JavaScript's safe integer limit must be rejected");
            assert_eq!(error.status, napi::Status::GenericFailure);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("safe integer"));
        }
    }
    #[test]
    fn confidential_network_tags_bind_the_exact_network() {
        let first = test_network_id(b"same-label-first-genesis");
        let second = test_network_id(b"same-label-second-genesis");
        assert_ne!(
            confidential_v2::derive_confidential_network_tag_v3(&first)
                .expect("first exact network tag"),
            confidential_v2::derive_confidential_network_tag_v3(&second)
                .expect("second exact network tag"),
            "equal display labels must not collapse distinct genesis identities"
        );
    }
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
    use iroha_data_model::{
        HasMetadata,
        account::AccountId,
        asset::id::{AssetDefinitionId, AssetId},
        da::manifest::DaManifestV1,
        events::EventFilterBox,
        isi::{
            Burn, BurnBox, CreateKaigi, CustomInstruction, InstructionBox, JoinKaigi, LeaveKaigi,
            Mint, MintBox, RecordKaigiUsage, RegisterBox, RegisterKaigiRelay, RegisterPeerWithPop,
            SetKaigiRelayManifest, Transfer, TransferBox, Unregister, UnregisterBox,
            UnregisterKaigiRelay,
            governance::{
                CastPlainBallot, CastZkBallot, ProposeDeployContract, ProposeValidationFeePolicy,
                RegisterCitizen,
            },
            smart_contract_code::{
                ActivateContractInstance, RegisterSmartContractBytes, RegisterSmartContractCode,
            },
        },
        kaigi::{
            KaigiId, KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiPrivacyMode,
            KaigiRelayHop, KaigiRelayManifest, KaigiRelayRegistration, KaigiRoomPolicy, NewKaigi,
        },
        ministry::{
            AgendaEvidenceAttachment, AgendaEvidenceKind, AgendaProposalAction,
            AgendaProposalSubmitter, AgendaProposalSummary, AgendaProposalTarget, AgendaProposalV1,
        },
        nft::NftId,
        peer::Peer,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        rwa::{NewRwa, RwaControlPolicy, RwaId, RwaParentRef},
        smart_contract::manifest::{
            AccessSetHints, ContractManifest, EntryPointKind, EntrypointDescriptor,
            EntrypointParamDescriptor, KotobaTranslation, KotobaTranslationEntry,
        },
        transaction::{
            Executable, IvmBytecode, IvmProved, TransactionSubmissionReceipt,
            TransactionSubmissionReceiptPayload,
        },
        trigger::TriggerId,
        validation_fee::{
            VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS, ValidationFeeChargingMode,
            ValidationFeeTreasuryPayoutBindingV1, initial_validation_fee_amount,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_model_base::peer::PeerId;
    use iroha_service_model::soranet::{AnonymityPolicy, RolloutPhase, TransportPolicy};
    use norito::{
        DeserializePayload,
        codec::{Decode as NoritoDecode, Encode as NoritoEncode},
        from_bytes,
        json::{self, Value},
        to_bytes,
    };
    use sorafs_car::{
        CarBuildPlan, CarWriter, chunker_registry, fetch_plan::chunk_fetch_plan_to_string,
    };
    use sorafs_chunker::ChunkProfile;
    use sorafs_manifest::{
        ChunkingProfileV1, CouncilSignature, GovernanceProofs, ManifestBuilder, PinPolicy,
        StorageClass, StreamTokenBodyV1, StreamTokenV1,
    };
    use sorafs_orchestrator::{
        GatewayCarVerification, OrchestratorConfig, PolicyOverride, PolicyReport, PolicyStatus,
        prelude::BrowserExtensionManifest, proxy::ProxyMode,
    };
    use std::{fs, io::Cursor, path::PathBuf, str::FromStr, sync::Arc};
    use tempfile::tempdir;
    #[test]
    fn retired_generic_zk_instruction_variants_are_not_parseable() {
        for variant in [
            ["Sh", "ield"].concat(),
            ["Zk", "Transfer"].concat(),
            ["Un", "shield"].concat(),
        ] {
            let payload = format!(r#"{{"Zk":{{"{variant}":{{}}}}}}"#);
            let error = instruction_from_json(&payload)
                .expect_err("retired generic privacy instruction must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert_eq!(error.reason, "unsupported zk instruction variant");
        }
        let source = include_str!("lib.rs");
        for retired_type_use in [
            ["let instruction: ", "Sh", "ield"].concat(),
            ["downcast_ref::<", "Sh", "ield", ">"].concat(),
            ["let instruction: ", "Zk", "Transfer"].concat(),
            ["downcast_ref::<", "Zk", "Transfer", ">"].concat(),
            ["let instruction: ", "Un", "shield"].concat(),
            ["downcast_ref::<", "Un", "shield", ">"].concat(),
        ] {
            assert!(
                !source.contains(&retired_type_use),
                "JS host must not compile against retired type use {retired_type_use}"
            );
        }
        assert!(source.contains("RegisterZkAsset"));
    }
    #[test]
    fn subscription_draft_instruction_json_roundtrips() {
        let authority = AccountId::new(
            KeyPair::random_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let trigger_id: TriggerId = "sub_bill_demo".parse().expect("trigger id");
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                Executable::from(Vec::<InstructionBox>::new()),
                Repeats::Indefinitely,
                authority,
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        let register =
            InstructionBox::from(RegisterBox::Trigger(Register::<Trigger>::trigger(trigger)));
        let register_json =
            instruction_to_json_value(&register).expect("register trigger instruction JSON");
        let register_fields = register_json
            .get("Register")
            .and_then(json::Value::as_object)
            .and_then(|value| value.get("Trigger"))
            .and_then(json::Value::as_object)
            .expect("register trigger fields");
        let trigger_id_literal = trigger_id.to_string();
        assert_eq!(
            register_fields.get("id").and_then(json::Value::as_str),
            Some(trigger_id_literal.as_str()),
        );
        let reparsed_register =
            value_to_instruction(register_json).expect("parse register trigger instruction JSON");
        assert_eq!(
            InstructionTrait::dyn_encode(&*register),
            InstructionTrait::dyn_encode(&*reparsed_register),
        );
        let nft_id: NftId = "sub_demo$subscriptions.universal"
            .parse()
            .expect("subscription NFT id");
        let set = InstructionBox::from(SetKeyValue::nft(
            nft_id.clone(),
            "subscription".parse().expect("subscription metadata key"),
            Json::new("active"),
        ));
        let set_json = instruction_to_json_value(&set).expect("set NFT value instruction JSON");
        let set_fields = set_json
            .get("SetKeyValue")
            .and_then(json::Value::as_object)
            .and_then(|value| value.get("Nft"))
            .and_then(json::Value::as_object)
            .expect("set NFT value fields");
        let nft_id_literal = nft_id.to_string();
        assert_eq!(
            set_fields.get("object").and_then(json::Value::as_str),
            Some(nft_id_literal.as_str()),
        );
        let reparsed_set =
            value_to_instruction(set_json).expect("parse set NFT value instruction JSON");
        assert_eq!(
            InstructionTrait::dyn_encode(&*set),
            InstructionTrait::dyn_encode(&*reparsed_set),
        );
    }
    #[test]
    fn subscription_trigger_action_inspection_binds_first_release_semantics() {
        use iroha_data_model::{
            events::execute_trigger::ExecuteTriggerEventFilter,
            subscription::{SUBSCRIPTION_TRIGGER_REF_METADATA_KEY, SubscriptionTriggerRef},
        };
        let authority = AccountId::new(
            KeyPair::random_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let subscription_id: NftId = "sub_demo$subscriptions.universal"
            .parse()
            .expect("subscription NFT id");
        let max_cycles = NonZeroU64::new(17).expect("positive cycle limit");
        let mut metadata = Metadata::default();
        metadata.insert(
            SUBSCRIPTION_TRIGGER_REF_METADATA_KEY
                .parse()
                .expect("subscription reference key"),
            Json::new(SubscriptionTriggerRef {
                subscription_nft_id: subscription_id.clone(),
            }),
        );
        let billing_action = Action::new(
            Executable::Ivm(IvmBytecode::from_compiled(
                subscription_syscall_program_bytes(
                    kotodama_lang::syscalls::SYSCALL_SUBSCRIPTION_BILL,
                    max_cycles,
                ),
            )),
            Repeats::Exactly(1),
            authority.clone(),
            TimeEventFilter(ExecutionTime::Schedule(TimeSchedule {
                start_ms: 42_000,
                period_ms: None,
            })),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_metadata(metadata);
        let encoded_billing = json::to_value(&billing_action)
            .expect("billing action JSON")
            .as_str()
            .expect("encoded billing action")
            .to_owned();
        let billing_summary: json::Value = json::from_json(
            &inspect_subscription_trigger_action(encoded_billing, 369.0)
                .expect("inspect billing subscription trigger"),
        )
        .expect("billing summary JSON");
        assert_eq!(
            billing_summary["kind"],
            json::Value::String("billing".to_owned())
        );
        assert_eq!(billing_summary["charge_at_ms"].as_u64(), Some(42_000));
        let subscription_id_literal = subscription_id.to_string();
        assert_eq!(
            billing_summary["subscription_id"].as_str(),
            Some(subscription_id_literal.as_str())
        );
        assert_eq!(
            billing_summary["authority"].as_str(),
            Some(authority.to_i105_for_discriminant(369).unwrap().as_str())
        );
        let usage_trigger_id: TriggerId = "sub_usage_demo".parse().expect("usage trigger id");
        let usage_action = Action::new(
            Executable::Ivm(IvmBytecode::from_compiled(
                subscription_syscall_program_bytes(
                    kotodama_lang::syscalls::SYSCALL_SUBSCRIPTION_RECORD_USAGE,
                    max_cycles,
                ),
            )),
            Repeats::Indefinitely,
            authority.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(usage_trigger_id.clone())
                .under_authority(authority),
        )
        .expect("trigger action fixture satisfies validation invariants");
        let encoded_usage = json::to_value(&usage_action)
            .expect("usage action JSON")
            .as_str()
            .expect("encoded usage action")
            .to_owned();
        let usage_summary: json::Value = json::from_json(
            &inspect_subscription_trigger_action(encoded_usage, 369.0)
                .expect("inspect usage subscription trigger"),
        )
        .expect("usage summary JSON");
        assert_eq!(
            usage_summary["kind"],
            json::Value::String("usage".to_owned())
        );
        let usage_trigger_id_literal = usage_trigger_id.to_string();
        assert_eq!(
            usage_summary["trigger_id"].as_str(),
            Some(usage_trigger_id_literal.as_str())
        );
    }
    fn canonical_kotodama_request(source: &str) -> JsKotodamaCompileRequest {
        JsKotodamaCompileRequest {
            artifacts: Vec::new(),
            source: source.to_owned(),
            source_name: None,
            sources: None,
            imports: None,
            packages: None,
            zk: false,
        }
    }
    #[test]
    fn multi_source_invalid_plan_is_a_structured_non_retryable_error() {
        let error = multi_source_js_error(MultiSourceError::InvalidPlan(
            sorafs_car::CarPlanError::EmptyInput,
        ));
        assert_eq!(error.status, napi::Status::GenericFailure);
        let payload: Value = json::from_str(&error.reason).expect("structured error JSON");
        assert_eq!(payload["kind"], Value::String("multi_source".to_owned()));
        assert_eq!(payload["code"], Value::String("invalid_plan".to_owned()));
        assert_eq!(payload["retryable"], Value::Bool(false));
        assert_eq!(
            payload["details"],
            Value::String("input payload is empty".to_owned())
        );
    }
    #[test]
    fn multi_source_resource_and_deadline_errors_preserve_structured_shape() {
        for (error, code, retryable) in [
            (
                MultiSourceError::ResourceLimit("eager payload limit"),
                "resource_limit",
                false,
            ),
            (
                MultiSourceError::DeadlineExceeded,
                "deadline_exceeded",
                true,
            ),
        ] {
            let error = multi_source_js_error(error);
            let payload: Value = json::from_str(&error.reason).expect("structured error JSON");
            assert_eq!(payload["kind"].as_str(), Some("multi_source"));
            assert_eq!(payload["code"].as_str(), Some(code));
            assert_eq!(payload["retryable"].as_bool(), Some(retryable));
        }
    }
    #[test]
    fn multi_source_policy_exclusion_is_a_structured_non_retryable_error() {
        let error = multi_source_js_error(MultiSourceError::NoPolicyEligibleProviders {
            chunk_index: 4,
            providers: vec![
                multi_fetch::ProviderId::new("alpha"),
                multi_fetch::ProviderId::new("beta"),
            ],
        });
        assert_eq!(error.status, napi::Status::GenericFailure);
        let payload: Value = json::from_str(&error.reason).expect("structured error JSON");
        assert_eq!(payload["kind"], Value::String("multi_source".to_owned()));
        assert_eq!(
            payload["code"],
            Value::String("no_policy_eligible_providers".to_owned())
        );
        assert_eq!(payload["chunkIndex"].as_u64(), Some(4));
        assert_eq!(
            payload["providers"],
            Value::Array(vec![
                norito_json!({
                    "providerId": "alpha",
                    "reason": "score_policy_denied",
                }),
                norito_json!({
                    "providerId": "beta",
                    "reason": "score_policy_denied",
                }),
            ])
        );
        assert_eq!(payload["retryable"], Value::Bool(false));
    }
    #[test]
    fn canonical_kotodama_binding_returns_full_artifact_manifest() {
        let request = canonical_kotodama_request(
            r"seiyaku Demo { permission RunDemo;
                hajimari() {}
                kaizen() {}
                kotoage fn run() authorize(RunDemo) {}
                view fn ping() authorize(anyone) -> int { return 1; }
            }",
        );
        let result = compile_kotodama_request(&request).expect("compile canonical Kotodama source");
        assert!(result.ok);
        assert!(result.diagnostics_json.is_none());
        let output = result.output.expect("successful compiler output");
        assert!(!output.artifact_bytes.is_empty());
        assert!(output.manifest_json.contains("compiler_fingerprint"));
        for branded in ["Kotoage", "View", "Hajimari", "Kaizen"] {
            assert!(
                output.manifest_json.contains(branded),
                "manifest omitted branded entrypoint kind {branded}: {}",
                output.manifest_json
            );
        }
        for retired in ["Public", "Init", "Upgrade"] {
            assert!(
                !output
                    .manifest_json
                    .contains(&format!(r#""kind":"{retired}""#)),
                "manifest exposed retired English entrypoint kind {retired}: {}",
                output.manifest_json
            );
        }
        assert_eq!(output.code_hash.len(), 64);
        assert_eq!(output.abi_hash.len(), 64);
        assert!(output.source_map_json.contains("\"kind\": \"source-map\""));
        assert!(output.source_map_json.contains(&output.code_hash));
        assert!(output.budget_report_json.contains("\"kind\": \"budget\""));
        assert!(output.budget_report_json.contains(&output.code_hash));
    }
    #[test]
    fn canonical_kotodama_binding_preserves_structured_unicode_diagnostics() {
        let source = "seiyaku Demo {\n🙂\n🙂\n}";
        let request = kotodama_lang::session::CompileRequest {
            source,
            source_name: None,
        };
        let expected = kotodama_lang::session::CompilerSession::default()
            .build(request)
            .expect_err("invalid Unicode tokens must fail compilation");
        assert!(
            expected.diagnostics.len() >= 2,
            "independent invalid tokens must produce multiple diagnostics"
        );
        let spans = expected
            .diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.primary_span.as_ref())
            .map(|span| (span.start.line, span.start.column, span.end.column))
            .collect::<Vec<_>>();
        assert!(spans.contains(&(2, 1, 2)));
        assert!(spans.contains(&(3, 1, 2)));
        let result = compile_kotodama_request(&canonical_kotodama_request(source))
            .expect("render compiler diagnostics");
        assert!(!result.ok);
        assert!(result.output.is_none());
        let expected_json = expected.render_json().expect("render expected diagnostics");
        assert_eq!(
            result.diagnostics_json.as_deref(),
            Some(expected_json.as_str()),
            "the binding must expose the canonical Norito JSON without reformatting fields"
        );
    }
    #[test]
    fn canonical_kotodama_request_preserves_source_name_and_selects_zk_policy() {
        let source = r"
seiyaku Privacy { permission CanCommitPrivateInput;
  kotoage fn commit() authorize(CanCommitPrivateInput) {
    let Secret<int> value = crypto::private_input(0);
    let Secret<int> blinding = crypto::private_input(1);
    let commitment = crypto::valcom(left: value, right: blinding);
    crypto::commit_output();
  }
}
";
        let request = JsKotodamaCompileRequest {
            artifacts: Vec::new(),
            source: source.to_owned(),
            source_name: Some("contracts/privacy.ko".to_owned()),
            sources: None,
            imports: None,
            packages: None,
            zk: true,
        };
        let result = compile_kotodama_request(&request).expect("compile canonical ZK request");
        assert!(result.ok);
        let output = result.output.expect("successful ZK compiler output");
        assert!(output.source_map_json.contains("contracts/privacy.ko"));
        assert!(output.budget_report_json.contains("contracts/privacy.ko"));
        let non_zk = JsKotodamaCompileRequest {
            artifacts: Vec::new(),
            zk: false,
            ..request
        };
        let result = compile_kotodama_request(&non_zk).expect("render non-ZK diagnostics");
        assert!(!result.ok);
        assert!(
            result
                .diagnostics_json
                .as_deref()
                .is_some_and(|diagnostics| diagnostics.contains("E_SECRET_REQUIRES_ZK"))
        );
    }
    #[test]
    fn canonical_kotodama_request_compiles_named_companion_inventory() {
        let request = JsKotodamaCompileRequest {
            artifacts: Vec::new(),
            source: "seiyaku App { include \"parts/view.ko\"; import \"math.ko\" as arith; }"
                .into(),
            source_name: Some("app.ko".into()),
            sources: Some(vec![
                JsKotodamaSourceFile {
                    source_name: "parts/view.ko".into(),
                    source: "view fn value() authorize(anyone) -> int { return arith::value(); }"
                        .into(),
                },
                JsKotodamaSourceFile {
                    source_name: "math.ko".into(),
                    source: "module Math { export fn value() -> int { return 7; } }".into(),
                },
            ]),
            imports: None,
            packages: None,
            zk: false,
        };
        let result = compile_kotodama_request(&request).expect("source inventory is bounded");
        assert!(result.ok, "{:?}", result.diagnostics_json);
        let output = result.output.expect("compiled source set");
        assert!(output.source_map_json.contains("parts/view.ko"));
        assert!(output.source_map_json.contains("math.ko"));
    }
    #[test]
    fn canonical_kotodama_request_compiles_locked_package_companions() {
        let mut request = JsKotodamaCompileRequest {
            artifacts: Vec::new(),
            source:
                "seiyaku App { view fn value() authorize(anyone) -> int { return calc::value(); } }"
                    .into(),
            source_name: Some("app.ko".into()),
            sources: None,
            imports: Some(vec![JsKotodamaSourceImport {
                alias: "calc".into(),
                package: "example/arithmetic@1".into(),
            }]),
            packages: Some(vec![JsKotodamaSourcePackage {
                artifacts: Vec::new(),
                identity: "example/arithmetic@1".into(),
                modules: vec![JsKotodamaSourceFile {
                    source_name: "src/lib.ko".into(),
                    source: "module Arithmetic { include \"body.ko\"; }".into(),
                }],
                sources: Some(vec![JsKotodamaSourceFile {
                    source_name: "src/body.ko".into(),
                    source: "export fn value() -> int { return 7; }".into(),
                }]),
                exports: vec!["value".into()],
                imports: None,
            }]),
            zk: false,
        };
        let result = compile_kotodama_request(&request).expect("bounded locked package request");
        assert!(result.ok, "{:?}", result.diagnostics_json);
        let output = result.output.expect("locked source bundle output");
        assert!(output.source_map_json.contains("src/body.ko"));
        assert!(output.source_map_json.contains("source_id"));
        request.packages.as_mut().expect("package")[0]
            .sources
            .as_mut()
            .expect("companions")[0]
            .source = "export fn value() -> int { return missing; }".into();
        let invalid = compile_kotodama_request(&request).expect("bounded invalid source");
        assert!(!invalid.ok);
        let diagnostics = invalid.diagnostics_json.expect("native package diagnostic");
        assert!(diagnostics.contains("src/body.ko"));
        assert!(diagnostics.contains("example/arithmetic@1"));
    }
    #[test]
    fn canonical_kotodama_request_rejects_unbounded_or_control_source_names() {
        for source_name in [
            String::new(),
            "contracts/private\nleak.ko".to_owned(),
            "x".repeat(MAX_KOTODAMA_SOURCE_NAME_BYTES + 1),
        ] {
            let request = JsKotodamaCompileRequest {
                artifacts: Vec::new(),
                source: "seiyaku Demo { view fn ping() authorize(anyone) -> int { return 1; } }"
                    .to_owned(),
                source_name: Some(source_name),
                sources: None,
                imports: None,
                packages: None,
                zk: false,
            };
            assert!(compile_kotodama_request(&request).is_err());
        }
    }
    #[test]
    fn disabled_local_fetch_integrity_checks_are_invalid_arguments() {
        for field in ["verify_digests", "verify_lengths"] {
            let error =
                map_local_fetch_error(LocalFetchError::IntegrityVerificationDisabled(field));
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains(field));
            assert!(error.reason.contains("must remain enabled"));
        }
    }
    #[test]
    fn privacy_compiled_profile_catalog_is_the_exact_closed_local_registry() {
        let catalog = privacy_compiled_profile_catalog().expect("compiled-profile catalog");
        catalog
            .validate()
            .expect("canonical compiled-profile catalog");
        assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::COUNT);
        assert!(
            catalog
                .protocols
                .iter()
                .map(|row| row.protocol_id)
                .eq(PrivacyProtocolIdV1::ALL)
        );
    }
    #[test]
    fn privacy_compiled_profile_catalog_napi_archive_round_trips_and_rejects_substitution() {
        let bytes = privacy_compiled_profile_catalog_v1()
            .expect("encode N-API compiled-profile catalog")
            .to_vec();
        assert_eq!(
            privacy_validate_compiled_profile_catalog_v1(Uint8Array::from(bytes.clone())),
            iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid
                .code()
        );
        let catalog: PrivacyCompiledProfileCatalogV1 =
            norito::decode_from_bytes(&bytes).expect("decode N-API compiled-profile catalog");
        catalog.validate().expect("N-API compiled-profile catalog");
        assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::COUNT);
        assert!(
            norito::decode_from_bytes::<iroha_data_model::privacy::PrivacyCapabilitySnapshotV1>(
                &bytes
            )
            .is_err(),
            "a local compiled-profile catalog must not decode as network readiness"
        );
        assert!(
            !iroha_data_model::privacy::validate_privacy_capability_archive_v1(&bytes).is_valid(),
            "a local compiled-profile catalog must not pass snapshot admission"
        );
        let mut one_byte_fake = norito::encode_canonical(&0_u8).expect("encode one-byte fake");
        one_byte_fake[6..22].copy_from_slice(&bytes[6..22]);
        assert_ne!(
            privacy_validate_compiled_profile_catalog_v1(Uint8Array::from(one_byte_fake)),
            iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid
                .code()
        );
        let mut substituted = catalog;
        let profile = substituted
            .protocols
            .iter_mut()
            .find_map(|row| match &mut row.compiled_profile {
                iroha_data_model::privacy::PrivacyCompiledProfileResultV1::Available(profile) => {
                    Some(profile)
                }
                iroha_data_model::privacy::PrivacyCompiledProfileResultV1::Unavailable(_) => None,
            })
            .expect("at least one compiled profile");
        let mut digest = *profile.parameter_digest.as_bytes();
        digest[0] ^= 0x80;
        profile.parameter_digest = iroha_data_model::privacy::PrivacyParameterDigestV1::new(digest);
        profile
            .validate()
            .expect("substituted profile remains structurally valid");
        let substituted = norito::encode_canonical(&substituted).expect("encode substitution");
        assert_eq!(
            iroha_data_model::privacy::validate_privacy_compiled_profile_catalog_archive_v1(
                &substituted,
            ),
            iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid,
            "the generic validator must accept the structurally valid substitution",
        );
        assert_eq!(
            privacy_validate_compiled_profile_catalog_v1(Uint8Array::from(substituted)),
            iroha_data_model::privacy::PrivacyCompiledProfileCatalogArchiveValidationStatusV1::InvalidCatalog
                .code()
        );
    }
    fn active_exact12_capability_manifest_archive() -> (PrivacyProtocolIdV1, Vec<u8>) {
        use iroha_data_model::privacy::{
            PRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1, PrivacyActiveLifecycleV1,
            PrivacyCapabilityRowV1, PrivacyCapabilitySnapshotV1, PrivacyConsensusPolicyV1,
            PrivacyProtocolLifecycleV1,
        };
        let active_protocol = PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1;
        let catalog = privacy_compiled_profile_catalog().expect("compiled-profile catalog");
        let protocols = catalog
            .protocols
            .into_iter()
            .map(|row| {
                let activation = (row.protocol_id == active_protocol).then(|| {
                    iroha_core_privacy::privacy_profiles::compiled_privacy_profile_v1(
                        active_protocol,
                    )
                    .expect("selected native profile is available")
                    .activation_record(PrivacyProtocolLifecycleV1::Active(
                        PrivacyActiveLifecycleV1 {
                            proposed_at_height: 1,
                            activated_at_height: 2,
                            state_since_height: 2,
                        },
                    ))
                });
                PrivacyCapabilityRowV1 {
                    protocol_id: row.protocol_id,
                    compiled_profile: row.compiled_profile,
                    activation,
                }
            })
            .collect();
        let manifest = PrivacyCapabilitySnapshotV1 {
            version: PRIVACY_CAPABILITY_SNAPSHOT_VERSION_V1,
            committed_height: 3,
            consensus_policy: PrivacyConsensusPolicyV1::taira_default(),
            qualification: None,
            protocols,
        }
        .exact12_capability_manifest_v1()
        .expect("active Exact12 capability manifest");
        (
            active_protocol,
            manifest
                .canonical_bytes()
                .expect("canonical manifest bytes"),
        )
    }
    #[test]
    fn privacy_exact12_manifest_napi_validates_decodes_and_requires_local_tuple() {
        let (active_protocol, archive) = active_exact12_capability_manifest_archive();
        assert_eq!(
            privacy_validate_exact12_capability_manifest_v1(Uint8Array::from(archive.clone())),
            iroha_data_model::privacy::PrivacyCapabilityArchiveValidationStatusV1::Valid.code()
        );
        let json = privacy_exact12_capability_manifest_json_v1(Uint8Array::from(archive.clone()))
            .expect("decode canonical Exact12 manifest JSON");
        assert!(json.contains("manifest_digest"));
        assert!(json.contains("operation_schema"));
        assert!(json.contains("missing-production-qualification"));
        assert!(json.contains("qualification"));
        assert!(!json.contains("production_qualification"));
        assert!(!json.contains("available-experimental"));
        assert!(!json.contains("limitation"));
        assert!(
            privacy_require_exact12_capability_tuple_v1(
                Uint8Array::from(archive.clone()),
                active_protocol.canonical_label().to_owned(),
                test_network_id_bytes(b"privacy-exact12-network"),
            )
            .is_err()
        );
        assert!(
            privacy_require_exact12_capability_tuple_v1(
                Uint8Array::from(archive.clone()),
                PrivacyProtocolIdV1::IrohaZkAmsV1
                    .canonical_label()
                    .to_owned(),
                test_network_id_bytes(b"privacy-exact12-network"),
            )
            .is_err(),
            "local compilation without committed Active state must not authorize"
        );
        for retired in [
            "jindo-lattice-pcs-zk-v0",
            "sis-with-hints",
            "zk-ams-recursive-admission-v0",
        ] {
            assert!(
                privacy_require_exact12_capability_tuple_v1(
                    Uint8Array::from(archive.clone()),
                    retired.to_owned(),
                    test_network_id_bytes(b"privacy-exact12-network"),
                )
                .is_err(),
                "accepted retired or aliased protocol {retired}"
            );
        }
        let mut suffixed = archive;
        suffixed.push(0);
        assert_ne!(
            privacy_validate_exact12_capability_manifest_v1(Uint8Array::from(suffixed)),
            iroha_data_model::privacy::PrivacyCapabilityArchiveValidationStatusV1::Valid.code()
        );
    }
    #[test]
    fn privacy_exact12_admission_binds_expected_network_and_genesis() {
        let expected = test_network_id(b"privacy-exact12-network");
        let other = test_network_id(b"privacy-exact12-other-network");
        assert!(
            require_privacy_exact12_network_v1(&expected, expected.as_bytes(), &expected).is_ok()
        );
        assert!(
            require_privacy_exact12_network_v1(&other, expected.as_bytes(), &expected).is_err()
        );
        assert!(
            require_privacy_exact12_network_v1(&expected, other.as_bytes(), &expected).is_err()
        );
        assert!(require_privacy_exact12_network_v1(&other, other.as_bytes(), &expected).is_err());
    }
    fn hash_literal(byte: u8) -> String {
        let mut buf = [byte; Hash::LENGTH];
        buf[buf.len() - 1] |= 1;
        let hash = Hash::prehashed(buf);
        match json::to_value(&hash).expect("hash json value") {
            Value::String(s) => s,
            other => panic!("expected hash literal string, got {other:?}"),
        }
    }
    #[test]
    fn crypto_keypair_exports_checked_public_key_payload() {
        let seed = vec![0xA5; 32];
        let expected =
            KeyPair::try_from_seed(seed.clone(), Algorithm::Ed25519).expect("checked seed keypair");
        let (_, expected_public_key) = expected
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        let keypair = crypto_keypair(Some("ed25519".to_owned()), Some(Uint8Array::from(seed)))
            .expect("derive keypair");
        assert_eq!(keypair.algorithm, Algorithm::Ed25519.as_static_str());
        assert_eq!(keypair.public_key.as_ref(), expected_public_key);
    }
    #[test]
    fn ed25519_keypair_derives_checked_public_key_payload() {
        let seed = vec![0x5C; 32];
        let expected =
            KeyPair::try_from_seed(seed.clone(), Algorithm::Ed25519).expect("checked seed keypair");
        let (_, expected_public_key) = expected
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        let keypair = ed25519_keypair(Some(Uint8Array::from(seed))).expect("derive keypair");
        assert_eq!(keypair.algorithm, Algorithm::Ed25519.as_static_str());
        assert_eq!(keypair.public_key.as_ref(), expected_public_key);
    }
    #[test]
    fn keypair_bindings_reject_non_cryptographic_seed_lengths() {
        let short = Uint8Array::from(b"human password".to_vec());
        let err = ed25519_keypair(Some(short))
            .err()
            .expect("short Ed25519 seed must fail");
        assert!(err.reason.contains("exactly 32 bytes"));
        let short = Uint8Array::from(b"human password".to_vec());
        let err = crypto_keypair(Some("secp256k1".to_owned()), Some(short))
            .err()
            .expect("short generic seed must fail");
        assert!(err.reason.contains("exactly 32 bytes"));
    }
    #[test]
    fn crypto_keypair_random_path_uses_checked_generation() {
        let keypair = crypto_keypair(Some("ed25519".to_owned()), None)
            .expect("checked random keypair generation");
        assert_eq!(keypair.algorithm, Algorithm::Ed25519.as_static_str());
        assert_eq!(keypair.public_key.len(), 32);
    }
    #[test]
    fn crypto_public_key_from_private_exports_checked_payload() {
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes[31] = 1;
        let private_key =
            PrivateKey::from_bytes(Algorithm::Secp256k1, &private_key_bytes).expect("private key");
        let public_key = PublicKey::from(private_key);
        let (_, expected_public_key) = public_key
            .try_to_bytes()
            .expect("checked public-key payload");
        let public_key = crypto_public_key_from_private(
            "secp256k1".to_owned(),
            Uint8Array::from(private_key_bytes.to_vec()),
        )
        .expect("derive public key");
        assert_eq!(public_key.as_ref(), expected_public_key);
    }
    #[test]
    fn crypto_sign_exports_verifiable_signature() {
        let seed = vec![0x33; 32];
        let message = b"js-host-crypto-sign";
        let keypair =
            KeyPair::try_from_seed(seed.clone(), Algorithm::Ed25519).expect("checked seed keypair");
        let (_, public_key) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        let signature = crypto_sign(
            "ed25519".to_owned(),
            Uint8Array::from(seed),
            Uint8Array::from(message.to_vec()),
        )
        .expect("crypto sign");
        let verified = crypto_verify(
            "ed25519".to_owned(),
            Uint8Array::from(public_key.to_vec()),
            Uint8Array::from(message.to_vec()),
            Uint8Array::from(signature.as_ref().to_vec()),
        )
        .expect("crypto verify");
        assert!(verified);
    }
    #[test]
    fn crypto_verify_rejects_all_zero_signature_material() {
        let seed = vec![0x33; 32];
        let message = b"js-host-crypto-sign";
        let keypair =
            KeyPair::try_from_seed(seed, Algorithm::Ed25519).expect("checked seed keypair");
        let (_, public_key) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        let signature = vec![0_u8; 64];
        let verified = crypto_verify(
            "ed25519".to_owned(),
            Uint8Array::from(public_key.to_vec()),
            Uint8Array::from(message.to_vec()),
            Uint8Array::from(signature),
        )
        .expect("crypto verify");
        assert!(!verified);
    }
    #[test]
    fn crypto_verify_rejects_malformed_ed25519_signature_r() {
        const SMALL_ORDER_R: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_R: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let seed = vec![0x33; 32];
        let message = b"js-host-crypto-sign";
        let keypair =
            KeyPair::try_from_seed(seed, Algorithm::Ed25519).expect("checked seed keypair");
        let (_, public_key) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        let valid_signature = Signature::try_new(keypair.private_key(), message)
            .expect("checked Ed25519 JS host fixture signature");
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut signature = valid_signature.payload().to_vec();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            let verified = crypto_verify(
                "ed25519".to_owned(),
                Uint8Array::from(public_key.to_vec()),
                Uint8Array::from(message.to_vec()),
                Uint8Array::from(signature),
            )
            .expect("crypto verify should return false for malformed material");
            assert!(!verified, "{label} Ed25519 signature R must not verify");
        }
    }
    #[test]
    fn crypto_verify_rejects_malformed_mldsa_signature_lengths() {
        let seed = vec![0x44; 32];
        let message = b"js-host-crypto-mldsa-sign";
        let keypair =
            KeyPair::try_from_seed(seed, Algorithm::MlDsa).expect("checked ML-DSA keypair");
        let (_, public_key) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked ML-DSA public-key payload");
        let (_alg, private_key) = keypair.private_key().to_bytes();
        let public_key = public_key.to_vec();
        let signature = crypto_sign(
            Algorithm::MlDsa.as_static_str().to_owned(),
            Uint8Array::from(private_key),
            Uint8Array::from(message.to_vec()),
        )
        .expect("crypto sign");
        assert!(
            crypto_verify(
                Algorithm::MlDsa.as_static_str().to_owned(),
                Uint8Array::from(public_key.clone()),
                Uint8Array::from(message.to_vec()),
                Uint8Array::from(signature.as_ref().to_vec()),
            )
            .expect("crypto verify"),
            "valid ML-DSA signature must verify"
        );
        let mut short = signature.as_ref().to_vec();
        short.pop();
        let mut overlong = signature.as_ref().to_vec();
        overlong.push(0x42);
        for (label, malformed) in [
            ("short", short),
            ("overlong", overlong),
            ("all-zero", vec![0_u8; signature.as_ref().len()]),
        ] {
            let verified = crypto_verify(
                Algorithm::MlDsa.as_static_str().to_owned(),
                Uint8Array::from(public_key.clone()),
                Uint8Array::from(message.to_vec()),
                Uint8Array::from(malformed),
            )
            .expect("crypto verify should return false for malformed material");
            assert!(!verified, "{label} ML-DSA signature must not verify");
        }
    }
    #[test]
    fn crypto_verify_rejects_malformed_ed25519_public_key_material() {
        const SMALL_ORDER_PUBLIC_KEY: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_PUBLIC_KEY: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let seed = vec![0x33; 32];
        let message = b"js-host-crypto-public-key-admission";
        let keypair =
            KeyPair::try_from_seed(seed, Algorithm::Ed25519).expect("checked seed keypair");
        let signature = Signature::try_new(keypair.private_key(), message)
            .expect("checked Ed25519 JS host fixture signature");
        for (label, public_key, expected) in [
            ("all-zero", [0_u8; 32], "all zero"),
            ("small-order", SMALL_ORDER_PUBLIC_KEY, "small-order"),
            ("noncanonical", NONCANONICAL_PUBLIC_KEY, "canonical"),
        ] {
            let err = crypto_verify(
                "ed25519".to_owned(),
                Uint8Array::from(public_key.to_vec()),
                Uint8Array::from(message.to_vec()),
                Uint8Array::from(signature.payload().to_vec()),
            )
            .expect_err("malformed Ed25519 public key must fail admission");
            let message = err.to_string();
            assert!(
                message.contains(expected),
                "{label} public key produced unexpected error: {message}"
            );
        }
    }
    #[test]
    fn crypto_public_key_multihash_rejects_malformed_ed25519_public_key_material() {
        const SMALL_ORDER_PUBLIC_KEY: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        const NONCANONICAL_PUBLIC_KEY: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        for (label, public_key, expected) in [
            ("all-zero", [0_u8; 32], "all zero"),
            ("small-order", SMALL_ORDER_PUBLIC_KEY, "small-order"),
            ("noncanonical", NONCANONICAL_PUBLIC_KEY, "canonical"),
        ] {
            let err = crypto_public_key_multihash(
                "ed25519".to_owned(),
                Uint8Array::from(public_key.to_vec()),
            )
            .expect_err("malformed Ed25519 public key must fail multihash admission");
            let message = err.to_string();
            assert!(
                message.contains(expected),
                "{label} public key produced unexpected multihash error: {message}"
            );
        }
    }
    #[test]
    fn crypto_multihash_helpers_use_checked_formatters() {
        let seed = vec![0x5A; 32];
        let keypair =
            KeyPair::try_from_seed(seed, Algorithm::Ed25519).expect("fixture seed keypair");
        let (_, public_payload) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        let expected_public = keypair
            .public_key()
            .try_to_multihash_string()
            .expect("checked public-key multihash");
        let expected_private = ExposedPrivateKey(keypair.private_key().clone())
            .try_to_multihash_string()
            .expect("checked private-key multihash");
        let (_, private_payload) = keypair.private_key().to_bytes();
        assert_eq!(
            crypto_public_key_multihash(
                "ed25519".to_owned(),
                Uint8Array::from(public_payload.to_vec()),
            )
            .expect("format public key multihash"),
            expected_public
        );
        assert_eq!(
            crypto_private_key_multihash("ed25519".to_owned(), Uint8Array::from(private_payload),)
                .expect("format private key multihash"),
            expected_private
        );
    }
    #[test]
    fn sm2_fixture_from_seed_uses_checked_public_key_formatters() {
        let distid = "js-sm2-fixture".to_owned();
        let seed = b"js-sm2-fixture-seed".to_vec();
        let message = b"js-sm2-fixture-message".to_vec();
        let fixture = sm2_fixture_from_seed(
            distid.clone(),
            Uint8Array::from(seed.clone()),
            Uint8Array::from(message),
        )
        .expect("build SM2 fixture");
        let private = Sm2PrivateKey::from_seed(&distid, &seed).expect("derive SM2 key");
        let public_bytes = private.public_key().to_sec1_bytes(false);
        let payload =
            encode_sm2_public_key_payload(&distid, &public_bytes).expect("SM2 public payload");
        let public_key = PublicKey::from_bytes(Algorithm::Sm2, &payload).expect("SM2 public key");
        assert_eq!(
            fixture.public_key_multihash,
            public_key
                .try_to_multihash_string()
                .expect("checked SM2 public-key multihash")
        );
        assert_eq!(
            fixture.public_key_prefixed,
            public_key
                .try_to_prefixed_string()
                .expect("checked SM2 public-key prefixed multihash")
        );
    }
    #[test]
    fn sm2_sign_uses_checked_signing_and_verifies() {
        let distid = "js-sm2-checked-signing".to_owned();
        let private =
            Sm2PrivateKey::from_seed(&distid, b"js-sm2-checked-signing-seed").expect("SM2 key");
        let message = b"js-host SM2 checked signing";
        let signature = sm2_sign(
            Uint8Array::from(private.secret_bytes().to_vec()),
            Uint8Array::from(message.to_vec()),
            Some(distid.clone()),
        )
        .expect("checked SM2 signing");
        let verified = sm2_verify(
            Uint8Array::from(private.public_key().to_sec1_bytes(false)),
            Uint8Array::from(message.to_vec()),
            Uint8Array::from(signature.as_ref().to_vec()),
            Some(distid),
        )
        .expect("SM2 verify");
        assert!(verified);
    }
    #[test]
    fn sm2_verify_rejects_zero_scalar_signature_material() {
        let distid = "js-sm2-zero-scalar-signature".to_owned();
        let private =
            Sm2PrivateKey::from_seed(&distid, b"js-sm2-zero-scalar-seed").expect("SM2 key");
        let public_key = private.public_key().to_sec1_bytes(false);
        let message = b"js-host SM2 zero-scalar signature";
        let mut zero_r = [0u8; SM2_SIGNATURE_LENGTH];
        zero_r[SM2_SIGNATURE_LENGTH - 1] = 1;
        let mut zero_s = [0u8; SM2_SIGNATURE_LENGTH];
        zero_s[31] = 1;
        for (label, signature) in [
            ("all-zero", [0u8; SM2_SIGNATURE_LENGTH]),
            ("zero-r", zero_r),
            ("zero-s", zero_s),
        ] {
            let err = sm2_verify(
                Uint8Array::from(public_key.clone()),
                Uint8Array::from(message.to_vec()),
                Uint8Array::from(signature.to_vec()),
                Some(distid.clone()),
            )
            .expect_err("zero-scalar SM2 signature must fail before verification");
            assert!(
                err.to_string().contains("SM2 signature"),
                "{label} signature produced unexpected error: {err}"
            );
        }
    }
    #[test]
    fn alias_proof_fixture_uses_checked_council_signer_payload() {
        let fixture = sorafs_alias_proof_fixture(Some(JsAliasProofFixtureOptions {
            generated_at_unix: Some(10),
            expires_at_unix: Some(20),
            ..Default::default()
        }))
        .expect("build alias proof fixture");
        let proof_bytes = BASE64
            .decode(fixture.proof_b64.as_bytes())
            .expect("decode proof fixture");
        let bundle = decode_alias_proof_untrusted_signers(&proof_bytes)
            .expect("decode alias proof integrity");
        let keypair = KeyPair::from_private_key(
            PrivateKey::from_bytes(Algorithm::Ed25519, &[0x55; 32]).expect("seeded key"),
        )
        .expect("derive keypair");
        let (_, expected_signer) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked public-key payload");
        assert_eq!(bundle.council_signatures.len(), 1);
        assert_eq!(
            bundle.council_signatures[0].signer.as_slice(),
            expected_signer
        );
    }
    fn sample_hash(byte: u8) -> [u8; Hash::LENGTH] {
        let mut buf = [byte; Hash::LENGTH];
        buf[buf.len() - 1] |= 1;
        buf
    }
    fn sample_account(_domain: &str) -> AccountId {
        let keypair = KeyPair::random();
        AccountId::new(keypair.public_key().clone())
    }
    fn cast_plain_ballot_json(owner: &AccountId, amount: json::Value) -> json::Value {
        let mut fields = json::Map::new();
        fields.insert(
            "referendum_id".to_owned(),
            json::Value::String("ref-plain".to_owned()),
        );
        fields.insert(
            "owner".to_owned(),
            json::to_value(owner).expect("serialize ballot owner"),
        );
        fields.insert("amount".to_owned(), amount);
        fields.insert(
            "duration_blocks".to_owned(),
            json::to_value(&42_u64).expect("serialize ballot duration"),
        );
        fields.insert(
            "direction".to_owned(),
            json::to_value(&1_u8).expect("serialize ballot direction"),
        );
        json::Value::Object(json::Map::from_iter([(
            "CastPlainBallot".to_owned(),
            json::Value::Object(fields),
        )]))
    }
    fn governance_selector_instruction_json(variant: &str, selector: &str) -> json::Value {
        match variant {
            "CastZkBallot" => norito_json!({
                "CastZkBallot": norito_json!({ "election_id": selector })
            }),
            "CastPlainBallot" => {
                let mut value = cast_plain_ballot_json(
                    &sample_account("wonderland"),
                    json::Value::String("1".to_owned()),
                );
                value
                    .get_mut("CastPlainBallot")
                    .and_then(json::Value::as_object_mut)
                    .expect("complete plain ballot fixture")
                    .insert(
                        "referendum_id".to_owned(),
                        json::Value::String(selector.to_owned()),
                    );
                value
            }
            "CreateElection" => norito_json!({
                "zk": norito_json!({
                    "CreateElection": norito_json!({ "election_id": selector })
                })
            }),
            "SubmitBallot" => norito_json!({
                "zk": norito_json!({
                    "SubmitBallot": norito_json!({ "election_id": selector })
                })
            }),
            "FinalizeElection" => norito_json!({
                "zk": norito_json!({
                    "FinalizeElection": norito_json!({ "election_id": selector })
                })
            }),
            _ => panic!("unsupported governance selector instruction {variant}"),
        }
    }
    fn account_json_literal(account: &AccountId) -> String {
        json::to_value(account)
            .expect("serialize account id")
            .as_str()
            .expect("account id json literal should be string")
            .to_owned()
    }
    fn register_citizen_json(owner: &AccountId, amount: json::Value) -> json::Value {
        json::Value::Object(json::Map::from_iter([(
            "RegisterCitizen".to_owned(),
            json::Value::Object(json::Map::from_iter([
                (
                    "owner".to_owned(),
                    json::Value::String(account_json_literal(owner)),
                ),
                ("amount".to_owned(), amount),
            ])),
        )]))
    }
    fn canonical_owner_literal(_domain: &str) -> String {
        account_json_literal(&sample_account("wonderland"))
    }
    fn noncanonical_owner_literal(domain: &str) -> String {
        let account = sample_account(domain);
        format!("{}@{domain}", account_json_literal(&account))
    }
    fn sample_rwa_id(domain: &str, byte: u8) -> RwaId {
        RwaId::generated(
            DomainId::try_new(domain, "universal").expect("valid domain id"),
            Hash::prehashed(sample_hash(byte)),
        )
    }
    fn sample_kaigi_id(domain: &str, call_name: &str) -> KaigiId {
        let domain_id = DomainId::try_new(domain, "universal").expect("valid domain id");
        let call = Name::from_str(call_name).expect("valid kaigi name");
        KaigiId::new(domain_id, call)
    }
    fn sample_agenda_proposal() -> AgendaProposalV1 {
        AgendaProposalV1 {
            version: 1,
            proposal_id: "AC-2026-001".to_owned(),
            submitted_at_unix_ms: 1_770_000_000_000,
            language: "en".to_owned(),
            action: AgendaProposalAction::AddToDenylist,
            summary: AgendaProposalSummary {
                title: "Blacklist proposal for bafy-test".to_owned(),
                motivation: "Evidence review requested for the published CID.".to_owned(),
                expected_impact:
                    "Participating gateways would restrict delivery while the case is reviewed."
                        .to_owned(),
            },
            tags: vec!["spam".to_owned()],
            targets: vec![AgendaProposalTarget {
                label: "bafy-test".to_owned(),
                hash_family: "sorafs-root-cid".to_owned(),
                hash_hex: "11".repeat(32),
                reason: "spam moderation report".to_owned(),
            }],
            evidence: vec![AgendaEvidenceAttachment {
                kind: AgendaEvidenceKind::Url,
                uri: "https://example.invalid/case/1".to_owned(),
                digest_blake3_hex: Some("22".repeat(32)),
                description: Some("Captured gateway evidence".to_owned()),
            }],
            submitter: AgendaProposalSubmitter {
                name: "Explorer Moderator".to_owned(),
                contact: "moderation@example.invalid".to_owned(),
                organization: Some("Sora Ops".to_owned()),
                pgp_fingerprint: None,
            },
            duplicates: vec!["AC-2025-014".to_owned()],
        }
    }
    #[test]
    fn gateway_policy_block_uses_canonical_compliance_evidence_only() {
        let value = attempt_failure_to_value(AttemptFailure::Provider {
            message: "blocked".to_owned(),
            policy_block: Some(multi_fetch::PolicyBlockEvidence {
                observed_status: "451".parse().expect("valid HTTP status"),
                code: "gateway_compliance_denied".to_owned(),
                source: "legal_safety_hold".to_owned(),
                catalog_digest_hex:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            }),
        });
        let policy = value
            .get("policyBlock")
            .and_then(Value::as_object)
            .expect("policy block object");
        assert_eq!(policy.len(), 4);
        assert_eq!(
            policy.get("observedStatus").and_then(Value::as_u64),
            Some(451)
        );
        assert_eq!(
            policy.get("code").and_then(Value::as_str),
            Some("gateway_compliance_denied")
        );
        assert_eq!(
            policy.get("source").and_then(Value::as_str),
            Some("legal_safety_hold")
        );
        assert_eq!(
            policy.get("catalogDigestHex").and_then(Value::as_str),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        for removed in [
            "canonicalStatus",
            "cacheVersion",
            "denylistVersion",
            "proofTokenPresent",
            "message",
        ] {
            assert!(
                !policy.contains_key(removed),
                "removed policy evidence field `{removed}` must stay absent"
            );
        }
    }
    fn make_stream_token_b64(
        manifest_id_hex: &str,
        provider_id_hex: &str,
        profile: &str,
        max_streams: u16,
    ) -> String {
        let mut provider_id = [0u8; 32];
        provider_id
            .copy_from_slice(&hex::decode(provider_id_hex).expect("decode provider identifier"));
        let body = StreamTokenBodyV1 {
            token_id: "01TESTTOKEN0000000000000000".to_string(),
            manifest_cid: hex::decode(manifest_id_hex).expect("decode manifest id"),
            provider_id,
            profile_handle: profile.to_string(),
            max_streams,
            ttl_epoch: 9_999_999_999,
            rate_limit_bytes: 8 * 1024 * 1024,
            issued_at: 1_735_000_000,
            requests_per_minute: 120,
            token_pk_version: 1,
        };
        let signing_key = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
            .expect("derive deterministic stream-token signing key");
        let signing_payload = body
            .signing_payload_bytes()
            .expect("encode stream-token signing payload");
        let signature = Signature::try_new(signing_key.private_key(), &signing_payload)
            .expect("sign stream token");
        let token = StreamTokenV1 {
            body,
            signature: signature.payload().to_vec(),
        };
        let bytes = norito::encode_canonical(&token).expect("encode stream token");
        BASE64.encode(bytes)
    }
    fn da_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/da/reconstruct/rs_parity_v1")
            .join(name)
    }
    fn load_da_manifest_fixture() -> Vec<u8> {
        let hex_str =
            fs::read_to_string(da_fixture_path("manifest.norito.hex")).expect("read manifest hex");
        hex::decode(hex_str.trim()).expect("decode manifest hex")
    }
    fn load_da_payload_fixture() -> Vec<u8> {
        fs::read(da_fixture_path("payload.bin")).expect("read payload fixture")
    }
    #[test]
    fn da_fixtures_are_readable() {
        let manifest = load_da_manifest_fixture();
        assert!(
            !manifest.is_empty(),
            "DA manifest fixture should not be empty"
        );
        let payload = load_da_payload_fixture();
        assert!(
            !payload.is_empty(),
            "DA payload fixture should not be empty"
        );
    }
    fn empty_gateway_options() -> JsGatewayFetchOptions {
        JsGatewayFetchOptions {
            manifest_envelope_b64: None,
            manifest_cid_hex: None,
            cache_version: None,
            client_id: None,
            telemetry_region: None,
            rollout_phase: None,
            max_peers: None,
            retry_budget: None,
            transport_policy: None,
            anonymity_policy: None,
            write_mode: None,
            local_proxy: None,
            scoreboard_out_path: None,
            scoreboard_now_unix_secs: None,
            scoreboard_telemetry_label: None,
            scoreboard_allow_implicit_metadata: None,
            allow_single_source_fallback: None,
        }
    }
    #[test]
    fn gateway_rollout_phase_updates_default_anonymity() {
        let mut config = OrchestratorConfig {
            anonymity_policy: AnonymityPolicy::StrictPq,
            ..OrchestratorConfig::default()
        };
        assert!(config.anonymity_policy_override.is_none());
        let mut opts = empty_gateway_options();
        opts.rollout_phase = Some("ramp".to_string());
        apply_gateway_options(&mut config, &opts).expect("apply rollout phase");
        assert_eq!(config.rollout_phase, RolloutPhase::Ramp);
        assert_eq!(
            config.anonymity_policy,
            RolloutPhase::Ramp.default_anonymity_policy()
        );
        assert!(config.anonymity_policy_override.is_none());
    }
    #[test]
    fn gateway_rollout_phase_respects_anonymity_override() {
        let mut config = OrchestratorConfig {
            anonymity_policy: AnonymityPolicy::StrictPq,
            anonymity_policy_override: Some(AnonymityPolicy::StrictPq),
            ..OrchestratorConfig::default()
        };
        let mut opts = empty_gateway_options();
        opts.rollout_phase = Some("canary".to_string());
        apply_gateway_options(&mut config, &opts).expect("apply rollout phase");
        assert_eq!(config.rollout_phase, RolloutPhase::Canary);
        assert_eq!(config.anonymity_policy, AnonymityPolicy::StrictPq);
        assert_eq!(
            config.anonymity_policy_override,
            Some(AnonymityPolicy::StrictPq)
        );
    }
    #[test]
    fn gateway_retry_budget_zero_disables_cap() {
        let mut config = OrchestratorConfig::default();
        let mut opts = empty_gateway_options();
        opts.retry_budget = Some(0);
        apply_gateway_options(&mut config, &opts).expect("apply retry budget");
        assert!(config.fetch.per_chunk_retry_limit.is_none());
    }
    #[test]
    fn gateway_retry_budget_sets_positive_limit() {
        let mut config = OrchestratorConfig::default();
        let mut opts = empty_gateway_options();
        opts.retry_budget = Some(3);
        apply_gateway_options(&mut config, &opts).expect("apply retry budget");
        assert_eq!(config.fetch.per_chunk_retry_limit, Some(3));
    }
    #[test]
    fn gateway_write_mode_parses_upload_hint() {
        let mut config = OrchestratorConfig::default();
        let mut opts = empty_gateway_options();
        opts.write_mode = Some("upload-pq-only".to_string());
        apply_gateway_options(&mut config, &opts).expect("apply write mode");
        assert_eq!(config.write_mode, WriteModeHint::UploadPqOnly);
    }
    #[test]
    fn gateway_policy_options_accept_exact_v1_labels() {
        let mut config = OrchestratorConfig::default();
        let mut opts = empty_gateway_options();
        opts.rollout_phase = Some("default".to_string());
        opts.transport_policy = Some("direct-only".to_string());
        opts.anonymity_policy = Some("anon-strict-pq".to_string());
        opts.write_mode = Some("read-only".to_string());
        apply_gateway_options(&mut config, &opts).expect("apply exact V1 policy labels");
        assert_eq!(config.rollout_phase, RolloutPhase::Default);
        assert_eq!(config.transport_policy, TransportPolicy::DirectOnly);
        assert_eq!(config.anonymity_policy, AnonymityPolicy::StrictPq);
        assert_eq!(
            config.anonymity_policy_override,
            Some(AnonymityPolicy::StrictPq)
        );
        assert_eq!(config.write_mode, WriteModeHint::ReadOnly);
    }
    #[test]
    fn gateway_policy_options_reject_all_noncanonical_labels() {
        for alias in [
            "stage_a", "stage-a", "stagea", "stage_b", "stage-b", "stageb", "stage_c", "stage-c",
            "stagec", "ga", "CANARY", "Ramp", "DEFAULT", " canary", "canary ", "", "unknown",
        ] {
            let mut config = OrchestratorConfig::default();
            let mut opts = empty_gateway_options();
            opts.rollout_phase = Some(alias.to_string());
            let error = apply_gateway_options(&mut config, &opts)
                .expect_err("rollout aliases must fail closed");
            assert!(
                error.to_string().contains("rolloutPhase must be one of"),
                "unexpected rejection for {alias:?}: {error}"
            );
        }
        for alias in [
            "soranet_first",
            "soranet_strict",
            "soranet_only",
            "soranet-only",
            "direct_only",
            "SORANET-FIRST",
            "Soranet-Strict",
            "DIRECT-ONLY",
            " soranet-first",
            "soranet-first ",
            "",
            "unknown",
        ] {
            let mut config = OrchestratorConfig::default();
            let mut opts = empty_gateway_options();
            opts.transport_policy = Some(alias.to_string());
            let error = apply_gateway_options(&mut config, &opts)
                .expect_err("transport aliases must fail closed");
            assert!(
                error.to_string().contains("transportPolicy must be one of"),
                "unexpected rejection for {alias:?}: {error}"
            );
        }
        for alias in [
            "anon_guard_pq",
            "anon_majority_pq",
            "anon_strict_pq",
            "stage_a",
            "stage-a",
            "stagea",
            "stage_b",
            "stage-b",
            "stageb",
            "stage_c",
            "stage-c",
            "stagec",
            "ANON-GUARD-PQ",
            "Anon-Majority-Pq",
            "ANON-STRICT-PQ",
            " anon-guard-pq",
            "anon-guard-pq ",
            "",
            "unknown",
        ] {
            let mut config = OrchestratorConfig::default();
            let mut opts = empty_gateway_options();
            opts.anonymity_policy = Some(alias.to_string());
            let error = apply_gateway_options(&mut config, &opts)
                .expect_err("anonymity aliases must fail closed");
            assert!(
                error.to_string().contains("anonymityPolicy must be one of"),
                "unexpected rejection for {alias:?}: {error}"
            );
        }
        for alias in [
            "read_only",
            "upload_pq_only",
            "READ-ONLY",
            "Upload-Pq-Only",
            " read-only",
            "read-only ",
            "",
            "unknown",
        ] {
            let mut config = OrchestratorConfig::default();
            let mut opts = empty_gateway_options();
            opts.write_mode = Some(alias.to_string());
            let error = apply_gateway_options(&mut config, &opts)
                .expect_err("write-mode aliases must fail closed");
            assert!(
                error.to_string().contains("writeMode must be one of"),
                "unexpected rejection for {alias:?}: {error}"
            );
        }
    }
    #[test]
    fn scoreboard_metadata_records_effective_policy_labels() {
        let config = OrchestratorConfig {
            transport_policy: TransportPolicy::SoranetPreferred,
            anonymity_policy: AnonymityPolicy::GuardPq,
            ..OrchestratorConfig::default()
        };
        let metadata = build_scoreboard_metadata_value(
            2,
            2,
            &config,
            ScoreboardMetadataInputs {
                allow_implicit_metadata: false,
                telemetry_label: Some("sdk:js"),
                telemetry_region: Some("iad-prod"),
                gateway_manifest_provided: true,
                gateway_manifest_id: Some("feedface"),
                gateway_manifest_cid: Some("c0ffee"),
                allow_single_source_fallback: false,
            },
        )
        .expect("metadata");
        let map = metadata
            .as_object()
            .expect("scoreboard metadata should be an object");
        assert_eq!(
            map.get("transport_policy").and_then(Value::as_str),
            Some("soranet-first")
        );
        assert_eq!(
            map.get("transport_policy_override")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert!(
            map.get("transport_policy_override_label")
                .is_some_and(Value::is_null)
        );
        assert_eq!(
            map.get("anonymity_policy").and_then(Value::as_str),
            Some("anon-guard-pq")
        );
        assert_eq!(
            map.get("anonymity_policy_override")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert!(
            map.get("anonymity_policy_override_label")
                .is_some_and(Value::is_null)
        );
        assert_eq!(
            map.get("write_mode").and_then(Value::as_str),
            Some("read-only")
        );
        assert_eq!(
            map.get("write_mode_enforces_pq").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            map.get("gateway_manifest_id").and_then(Value::as_str),
            Some("feedface")
        );
        assert_eq!(
            map.get("gateway_manifest_cid").and_then(Value::as_str),
            Some("c0ffee")
        );
        assert_eq!(
            map.get("telemetry_region").and_then(Value::as_str),
            Some("iad-prod")
        );
    }
    #[test]
    fn scoreboard_metadata_records_policy_overrides() {
        let config = OrchestratorConfig {
            policy_override: PolicyOverride::new(
                Some(TransportPolicy::SoranetStrict),
                Some(AnonymityPolicy::StrictPq),
            ),
            ..OrchestratorConfig::default()
        };
        let metadata = build_scoreboard_metadata_value(
            1,
            1,
            &config,
            ScoreboardMetadataInputs {
                allow_implicit_metadata: true,
                telemetry_label: None,
                telemetry_region: None,
                gateway_manifest_provided: false,
                gateway_manifest_id: None,
                gateway_manifest_cid: None,
                allow_single_source_fallback: true,
            },
        )
        .expect("metadata");
        let map = metadata
            .as_object()
            .expect("scoreboard metadata should be an object");
        assert_eq!(
            map.get("transport_policy").and_then(Value::as_str),
            Some("soranet-strict")
        );
        assert_eq!(
            map.get("transport_policy_override")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            map.get("transport_policy_override_label")
                .and_then(Value::as_str),
            Some("soranet-strict")
        );
        assert_eq!(
            map.get("anonymity_policy").and_then(Value::as_str),
            Some("anon-strict-pq")
        );
        assert_eq!(
            map.get("anonymity_policy_override")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            map.get("anonymity_policy_override_label")
                .and_then(Value::as_str),
            Some("anon-strict-pq")
        );
        assert_eq!(
            map.get("write_mode").and_then(Value::as_str),
            Some("read-only")
        );
        assert_eq!(
            map.get("write_mode_enforces_pq").and_then(Value::as_bool),
            Some(false)
        );
        assert!(map.get("gateway_manifest_id").is_some_and(Value::is_null));
        assert!(map.get("gateway_manifest_cid").is_some_and(Value::is_null));
        assert!(map.get("telemetry_region").is_some_and(Value::is_null));
    }
    #[test]
    fn mint_asset_instruction_json_roundtrip() {
        let account_id = sample_account("wonderland");
        let asset_definition: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset_id = AssetId::new(asset_definition, account_id.clone());
        let mint_box: MintBox =
            Mint::asset_quantity("10".parse::<Quantity>().expect("valid quantity"), asset_id)
                .into();
        let instruction = InstructionBox::from(mint_box);
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize instruction to json");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Mint"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize instruction from json");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn asset_transfer_blacklist_instruction_json_roundtrip() {
        let account_id = sample_account("wonderland");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        );
        let instruction: InstructionBox =
            SetAssetTransferBlacklist::new(account_id.clone(), asset_definition.clone(), true)
                .into();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize SetAssetTransferBlacklist instruction");
        assert_eq!(
            json_value,
            norito_json!({
                "SetAssetTransferBlacklist": norito_json!({
                    "account_id": json::to_value(&account_id).expect("serialize account"),
                    "asset_definition_id": json::to_value(&asset_definition)
                        .expect("serialize asset definition"),
                    "blacklisted": true,
                }),
            })
        );
        let reconstructed = value_to_instruction(json_value)
            .expect("deserialize SetAssetTransferBlacklist instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn asset_transfer_control_instruction_json_roundtrip() {
        let account_id = sample_account("wonderland");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        );
        let instruction: InstructionBox = SetAssetTransferControl::new(
            account_id.clone(),
            asset_definition.clone(),
            vec![
                AssetTransferLimit {
                    window: AssetTransferControlWindow::Day,
                    cap_amount: Some(Quantity::from_str("10.5").expect("valid quantity")),
                },
                AssetTransferLimit {
                    window: AssetTransferControlWindow::Month,
                    cap_amount: None,
                },
            ],
        )
        .into();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize SetAssetTransferControl instruction");
        assert_eq!(
            json_value,
            norito_json!({
                "SetAssetTransferControl": norito_json!({
                    "account_id": json::to_value(&account_id).expect("serialize account"),
                    "asset_definition_id": json::to_value(&asset_definition)
                        .expect("serialize asset definition"),
                    "limits": vec![
                        norito_json!({"window": "Day", "cap_amount": "10.5"}),
                        norito_json!({"window": "Month", "cap_amount": json::Value::Null}),
                    ],
                }),
            })
        );
        let reconstructed = value_to_instruction(json_value)
            .expect("deserialize SetAssetTransferControl instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn asset_transfer_control_instruction_json_rejects_noncanonical_payloads() {
        let account_id = sample_account("wonderland");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        );
        let account_value = json::to_value(&account_id).expect("serialize account");
        let asset_definition_value = json::Value::String(asset_definition.to_string());
        let invalid = [
            (
                "blacklist type",
                norito_json!({
                    "SetAssetTransferBlacklist": norito_json!({
                        "account_id": account_value.clone(),
                        "asset_definition_id": asset_definition_value.clone(),
                        "blacklisted": "true",
                    }),
                }),
                "blacklisted must be a boolean",
            ),
            (
                "blacklist extra field",
                norito_json!({
                    "SetAssetTransferBlacklist": norito_json!({
                        "account_id": account_value.clone(),
                        "asset_definition_id": asset_definition_value.clone(),
                        "blacklisted": true,
                        "reason": "not on the wire",
                    }),
                }),
                "must contain exactly",
            ),
            (
                "window spelling",
                norito_json!({
                    "SetAssetTransferControl": norito_json!({
                        "account_id": account_value.clone(),
                        "asset_definition_id": asset_definition_value.clone(),
                        "limits": vec![norito_json!({
                            "window": "DAY",
                            "cap_amount": "1",
                        })],
                    }),
                }),
                "must be exactly",
            ),
            (
                "duplicate window",
                norito_json!({
                    "SetAssetTransferControl": norito_json!({
                        "account_id": account_value.clone(),
                        "asset_definition_id": asset_definition_value.clone(),
                        "limits": vec![
                            norito_json!({"window": "Day", "cap_amount": "1"}),
                            norito_json!({"window": "Day", "cap_amount": json::Value::Null}),
                        ],
                    }),
                }),
                "duplicates DAY",
            ),
            (
                "quantity spelling",
                norito_json!({
                    "SetAssetTransferControl": norito_json!({
                        "account_id": account_value.clone(),
                        "asset_definition_id": asset_definition_value.clone(),
                        "limits": vec![norito_json!({
                            "window": "Week",
                            "cap_amount": "01",
                        })],
                    }),
                }),
                "canonical Quantity text",
            ),
            (
                "limit extra field",
                norito_json!({
                    "SetAssetTransferControl": norito_json!({
                        "account_id": account_value,
                        "asset_definition_id": asset_definition_value,
                        "limits": vec![norito_json!({
                            "window": "Month",
                            "cap_amount": json::Value::Null,
                            "reset": true,
                        })],
                    }),
                }),
                "must contain exactly",
            ),
        ];
        for (label, value, expected) in invalid {
            let error = value_to_instruction(value)
                .expect_err("noncanonical asset-transfer control JSON must fail closed");
            assert!(
                error.reason.contains(expected),
                "{label} produced unexpected error: {}",
                error.reason
            );
        }
    }
    #[test]
    fn transfer_asset_batch_instruction_json_roundtrip() {
        let source = sample_account("wonderland");
        let destination = sample_account("looking_glass");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("valid domain"),
            "rose".parse().expect("valid asset name"),
        );
        let batch =
            TransferAssetBatch::new(vec![iroha_data_model::isi::TransferAssetBatchEntry::new(
                source,
                destination,
                asset_definition,
                "1.25".parse::<Quantity>().expect("valid quantity"),
            )]);
        let instruction = InstructionBox::from(batch);
        let mut json_value =
            instruction_to_json_value(&instruction).expect("serialize batch instruction to json");
        assert!(
            json_value.get("TransferAssetBatch").is_some(),
            "batch instruction JSON must retain its native variant"
        );
        let reconstructed = value_to_instruction(json_value.clone())
            .expect("deserialize batch instruction from native JSON");
        assert_eq!(reconstructed, instruction);
        let malformed = json_value
            .get_mut("TransferAssetBatch")
            .and_then(json::Value::as_object_mut)
            .expect("batch payload object");
        malformed.insert("redirect".to_owned(), json::Value::Bool(true));
        assert!(
            value_to_instruction(json_value).is_err(),
            "batch decoder must reject fields outside the native batch schema"
        );
    }
    #[test]
    fn kaigi_final_scalar_wire_matches_javascript_fixture() {
        let fixtures: json::Value = json::from_str(include_str!(
            "../../../javascript/iroha_js/test/fixtures/kaigi_authorization_scalar_wire_v1.json"
        ))
        .unwrap();
        let rows = fixtures.as_array().unwrap();
        assert_eq!(rows.len(), 5);
        for row in rows {
            let value = row.get("instruction").unwrap().clone();
            let encoded = STANDARD
                .decode(row.get("wire_base64").unwrap().as_str().unwrap())
                .unwrap();
            let instruction = value_to_instruction(value.clone()).unwrap();
            let native = norito_encode_instruction(
                json::to_json(&value).unwrap(),
                f64::from(iroha_data_model::account::address::chain_discriminant()),
            )
            .unwrap();
            assert_eq!(
                native.as_ref(),
                encoded.as_slice(),
                "exact JS/native Kaigi instruction wire"
            );
            let decoded: InstructionBox = decode_from_bytes(&encoded).unwrap();
            assert_eq!(decoded, instruction);
            assert_eq!(instruction_to_json_value(&decoded).unwrap(), value);
        }
    }
    #[test]
    fn kaigi_scalar_json_rejects_retired_fields_and_noncanonical_bytes() {
        let scalar = KaigiAuthorizationScalarV1::from_le_bytes([0x12; 32]).unwrap();
        let commitment = KaigiParticipantCommitment { commitment: scalar };
        let nullifier = KaigiParticipantNullifier { digest: scalar };
        let c = optional_commitment_to_json(Some(&commitment));
        let n = optional_nullifier_to_json(Some(&nullifier));
        assert_eq!(
            parse_optional_commitment(Some(c.clone()), "test").unwrap(),
            Some(commitment)
        );
        assert_eq!(
            parse_optional_nullifier(Some(n.clone()), "test").unwrap(),
            Some(nullifier)
        );
        assert_eq!(
            parse_optional_kaigi_scalar(Some(optional_kaigi_scalar_to_json(Some(&scalar))), "test")
                .unwrap(),
            Some(scalar)
        );
        assert_eq!(parse_optional_commitment(None, "test").unwrap(), None);
        assert_eq!(
            parse_optional_nullifier(Some(json::Value::Null), "test").unwrap(),
            None
        );
        assert_eq!(parse_optional_kaigi_scalar(None, "test").unwrap(), None);
        for field in ["alias_tag", "aliasTag", "unknown"] {
            let mut value = c.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), json::Value::Null);
            assert!(parse_optional_commitment(Some(value), "test").is_err());
        }
        for field in ["issued_at_ms", "issuedAtMs", "issuedAt", "hash"] {
            let mut value = n.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), json::to_value(&0_u64).unwrap());
            assert!(parse_optional_nullifier(Some(value), "test").is_err());
        }
        for value in [
            json::Value::Array(vec![json::Value::Number(json::Number::U64(255)); 32]),
            json::Value::Array(vec![json::Value::Number(json::Number::U64(0)); 31]),
            json::Value::String(hash_literal(0x12)),
        ] {
            assert!(parse_optional_kaigi_scalar(Some(value.clone()), "test").is_err());
            let mut changed_c = c.clone();
            changed_c
                .as_object_mut()
                .unwrap()
                .insert("commitment".into(), value.clone());
            assert!(parse_optional_commitment(Some(changed_c), "test").is_err());
            let mut changed_n = n.clone();
            changed_n
                .as_object_mut()
                .unwrap()
                .insert("digest".into(), value);
            assert!(parse_optional_nullifier(Some(changed_n), "test").is_err());
        }
    }
    #[test]
    fn kaigi_commitment_option_roundtrip() {
        let buf = [0x11u8; 32];
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes(buf).unwrap(),
        };
        let option = Some(commitment);
        let bytes = option.encode();
        let mut cursor = Cursor::new(bytes.as_slice());
        let decoded: Option<KaigiParticipantCommitment> =
            NoritoDecode::decode(&mut cursor).expect("decode option bytes");
        assert_eq!(decoded, Some(commitment));
    }
    #[test]
    fn burn_asset_instruction_json_roundtrip() {
        let account_id = sample_account("wonderland");
        let asset_definition: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset_id = AssetId::new(asset_definition, account_id.clone());
        let burn_box: BurnBox =
            Burn::asset_quantity("5".parse::<Quantity>().expect("valid quantity"), asset_id).into();
        let instruction = InstructionBox::from(burn_box);
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize instruction to json");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Burn"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize instruction from json");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn custom_instruction_json_roundtrip() {
        let account = sample_account("wonderland");
        let mut propose = json::Map::new();
        propose.insert(
            "account".to_owned(),
            json::Value::String(account_json_literal(&account)),
        );
        propose.insert(
            "instructions".to_owned(),
            json::Value::Array(vec![norito_json!({
                "Log": "hello-custom"
            })]),
        );
        propose.insert(
            "transaction_ttl_ms".to_owned(),
            json::Value::Number(json::Number::from(30_000_u64)),
        );
        let mut payload = json::Map::new();
        payload.insert("Propose".to_owned(), json::Value::Object(propose));
        let instruction_json = custom_json_value(json::Value::Object(payload));
        let instruction =
            value_to_instruction(instruction_json.clone()).expect("parse Custom instruction");
        assert!(
            instruction
                .as_any()
                .downcast_ref::<CustomInstruction>()
                .is_some(),
            "instruction must decode as CustomInstruction"
        );
        let rendered =
            instruction_to_json_value(&instruction).expect("render custom instruction to JSON");
        assert_eq!(rendered, instruction_json);
    }
    #[test]
    fn multisig_alias_payloads_decode_as_custom_instruction() {
        let account = sample_account("wonderland");
        let account_literal = account_json_literal(&account);
        let mut propose_fields = json::Map::new();
        propose_fields.insert(
            "account".to_owned(),
            json::Value::String(account_literal.clone()),
        );
        propose_fields.insert(
            "instructions".to_owned(),
            json::Value::Array(vec![norito_json!({
                "Log": "multisig-propose"
            })]),
        );
        let mut propose_outer = json::Map::new();
        propose_outer.insert(
            "MultisigPropose".to_owned(),
            json::Value::Object(propose_fields),
        );
        let propose_instruction = value_to_instruction(json::Value::Object(propose_outer))
            .expect("parse MultisigPropose alias");
        let propose_rendered =
            instruction_to_json_value(&propose_instruction).expect("render MultisigPropose alias");
        assert!(
            propose_rendered
                .get("Custom")
                .and_then(|value| value.get("payload"))
                .and_then(|value| value.get("Propose"))
                .is_some(),
            "MultisigPropose alias must map to Custom.payload.Propose"
        );
        let mut cancel_fields = json::Map::new();
        cancel_fields.insert(
            "account".to_owned(),
            json::Value::String(account_literal.clone()),
        );
        cancel_fields.insert(
            "instructions_hash".to_owned(),
            json::Value::String(hash_literal(0xBB)),
        );
        let mut cancel_outer = json::Map::new();
        cancel_outer.insert(
            "MultisigCancel".to_owned(),
            json::Value::Object(cancel_fields),
        );
        let cancel_instruction = value_to_instruction(json::Value::Object(cancel_outer))
            .expect("parse MultisigCancel alias");
        let cancel_rendered =
            instruction_to_json_value(&cancel_instruction).expect("render MultisigCancel alias");
        assert!(
            cancel_rendered
                .get("Custom")
                .and_then(|value| value.get("payload"))
                .and_then(|value| value.get("Cancel"))
                .and_then(|value| value.get("instructions_hash"))
                .is_some(),
            "MultisigCancel alias must map to Custom.payload.Cancel"
        );
        let mut approve_fields = json::Map::new();
        approve_fields.insert("account".to_owned(), json::Value::String(account_literal));
        approve_fields.insert(
            "instructions_hash".to_owned(),
            json::Value::String(hash_literal(0xCC)),
        );
        let mut multisig_payload = json::Map::new();
        multisig_payload.insert("Approve".to_owned(), json::Value::Object(approve_fields));
        let mut approve_outer = json::Map::new();
        approve_outer.insert("Multisig".to_owned(), json::Value::Object(multisig_payload));
        let approve_instruction =
            value_to_instruction(json::Value::Object(approve_outer)).expect("parse Multisig alias");
        let approve_rendered =
            instruction_to_json_value(&approve_instruction).expect("render Multisig alias");
        assert!(
            approve_rendered
                .get("Custom")
                .and_then(|value| value.get("payload"))
                .and_then(|value| value.get("Approve"))
                .is_some(),
            "Multisig alias must map to Custom.payload.Approve"
        );
    }
    #[test]
    fn sorafs_multi_fetch_local_executes_plan() {
        let tempdir = tempdir().expect("tempdir");
        let payload: Vec<u8> = (0..(6 * 1024_usize))
            .map(|idx| u8::try_from(idx % 241).expect("modulo fits in u8"))
            .collect();
        let alpha_path = tempdir.path().join("alpha.bin");
        let beta_path = tempdir.path().join("beta.bin");
        fs::write(&alpha_path, &payload).expect("write alpha payload");
        fs::write(&beta_path, &payload).expect("write beta payload");
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json = chunk_fetch_plan_to_string(&plan).expect("serialize plan");
        let providers = vec![
            JsLocalProviderSpec {
                name: "alpha".to_owned(),
                path: alpha_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
            JsLocalProviderSpec {
                name: "beta".to_owned(),
                path: beta_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
        ];
        let result = sorafs_multi_fetch_local(
            plan_json,
            providers,
            Some(JsMultiFetchOptions {
                max_peers: Some(1),
                ..Default::default()
            }),
        )
        .expect("multi-fetch succeeds");
        assert_eq!(
            result.chunk_count as usize,
            plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
        );
        assert_eq!(result.provider_reports.len(), 1);
        assert_eq!(result.provider_reports[0].provider, "alpha");
        assert_eq!(result.provider_reports[0].failures, 0);
        assert!(!result.provider_reports[0].disabled);
        assert_eq!(
            result.chunk_receipts.len(),
            plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
        );
        assert!(
            result
                .chunk_receipts
                .iter()
                .all(|receipt| receipt.provider == "alpha")
        );
        let payload_bytes = result.payload.to_vec();
        assert_eq!(payload_bytes, payload);
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn sorafs_gateway_fetch_returns_manifest_and_car_verification() {
        use sorafs_car::multi_fetch::{ChunkReceipt, FetchOutcome, FetchProvider, ProviderReport};
        let payload_len = 32 * 1024;
        let payload: Vec<u8> = (0..payload_len)
            .map(|idx| u8::try_from(idx % 251).expect("payload byte fits in u8"))
            .collect();
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let descriptor = chunker_registry::lookup_by_profile(
            ChunkProfile::DEFAULT,
            chunker_registry::DEFAULT_MULTIHASH_CODE,
        )
        .expect("lookup chunker profile");
        let chunker_handle = format!(
            "{}.{}@{}",
            descriptor.namespace, descriptor.name, descriptor.semver
        );
        let writer = CarWriter::new(&plan, &payload).expect("car writer");
        let car_stats = writer.write_to(std::io::sink()).expect("write car bytes");
        let manifest = ManifestBuilder::new()
            .root_cid(car_stats.root_cids[0].clone())
            .dag_codec(sorafs_manifest::DagCodecId(car_stats.dag_codec))
            .chunking_profile(ChunkingProfileV1::from_profile(
                plan.chunk_profile,
                chunker_registry::DEFAULT_MULTIHASH_CODE,
            ))
            .chunk_digest_sha3_256(sorafs_car::compute_chunk_plan_digest_sha3(&plan.chunks))
            .por_root(
                sorafs_car::compute_por_root(&payload, &plan)
                    .expect("derive canonical fixture PoR root"),
            )
            .content_length(plan.content_length)
            .car_digest(car_stats.car_archive_digest.into())
            .car_size(car_stats.car_size)
            .pin_policy(PinPolicy {
                min_replicas: 1,
                storage_class: StorageClass::Hot,
                retention_epoch: 0,
            })
            .governance(GovernanceProofs {
                council_signatures: vec![CouncilSignature {
                    signer: [0x11; 32],
                    signature: vec![0x22; 64],
                }],
            })
            .build()
            .expect("manifest");
        let manifest_bytes = manifest.encode().expect("encode manifest");
        let manifest_digest = manifest.digest().expect("manifest digest");
        let manifest_id_hex = hex::encode(manifest_digest.as_bytes());
        let manifest_governance = manifest.governance.clone();
        let manifest_digest_copy = manifest_digest;
        let provider_id_hex = "aa".repeat(32);
        let stream_token_b64 = make_stream_token_b64(
            &manifest_id_hex,
            &provider_id_hex,
            &chunker_handle,
            u16::try_from(plan.chunks.len()).expect("chunk count fits in u16"),
        );
        let plan_json = chunk_fetch_plan_to_string(&plan).expect("serialize plan");
        let tempdir = tempdir().expect("tempdir");
        let norito_dir = tempdir.path().join("norito");
        let car_dir = tempdir.path().join("car");
        let scoreboard_path = tempdir.path().join("scoreboard").join("scoreboard.json");
        fs::create_dir_all(&norito_dir).expect("create norito directory");
        fs::create_dir_all(&car_dir).expect("create car directory");
        let options = JsGatewayFetchOptions {
            manifest_envelope_b64: None,
            manifest_cid_hex: None,
            cache_version: None,
            client_id: Some("ci-test".into()),
            telemetry_region: Some("ci-region".into()),
            rollout_phase: Some("canary".into()),
            max_peers: Some(2),
            retry_budget: Some(3),
            transport_policy: Some("soranet-first".into()),
            anonymity_policy: None,
            write_mode: None,
            local_proxy: Some(JsLocalProxyConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                telemetry_label: Some("test-proxy".into()),
                guard_cache_key_hex: None,
                emit_browser_manifest: Some(true),
                proxy_mode: Some("bridge".into()),
                prewarm_circuits: Some(true),
                max_streams_per_circuit: Some(4),
                circuit_ttl_hint_secs: Some(180),
                norito_bridge: Some(JsProxyNoritoBridgeConfig {
                    spool_dir: norito_dir.to_string_lossy().into_owned(),
                    extension: Some("norito".into()),
                }),
                car_bridge: Some(JsProxyCarBridgeConfig {
                    cache_dir: car_dir.to_string_lossy().into_owned(),
                    extension: Some("car".into()),
                    allow_zst: Some(false),
                }),
                kaigi_bridge: None,
            }),
            scoreboard_out_path: Some(scoreboard_path.to_string_lossy().into_owned()),
            scoreboard_now_unix_secs: Some(JsU64(1_700_000_000)),
            scoreboard_telemetry_label: Some("ci-gateway".into()),
            scoreboard_allow_implicit_metadata: Some(true),
            allow_single_source_fallback: Some(false),
        };
        let manifest_bytes_clone = manifest_bytes.clone();
        let car_stats_clone = car_stats.clone();
        let payload_clone = payload.clone();
        let chunker_handle_clone = chunker_handle.clone();
        let override_guard = set_fetch_via_gateway_override(move |_, plan_override, _, _, _, _| {
            let provider = Arc::new(FetchProvider::new("alpha"));
            let chunk_specs = plan_override
                .try_chunk_fetch_specs()
                .expect("valid CAR plan");
            let mut chunks = Vec::with_capacity(chunk_specs.len());
            let mut receipts = Vec::with_capacity(chunk_specs.len());
            for spec in &chunk_specs {
                let offset = usize::try_from(spec.offset).expect("offset fits in usize");
                let length = usize::try_from(spec.length).expect("length fits in usize");
                let upper = offset
                    .checked_add(length)
                    .expect("chunk slice within payload bounds");
                assert!(
                    upper <= payload_clone.len(),
                    "chunk slice exceeds payload (offset={offset} length={length})"
                );
                let bytes = payload_clone[offset..upper].to_vec();
                chunks.push(bytes);
                receipts.push(ChunkReceipt {
                    chunk_index: spec.chunk_index,
                    provider: provider.id().clone(),
                    attempts: 1,
                    latency_ms: 12.5,
                    bytes: spec.length,
                });
            }
            let outcome = FetchOutcome {
                chunks,
                chunk_receipts: receipts,
                provider_reports: vec![ProviderReport {
                    provider: provider.clone(),
                    successes: chunk_specs.len(),
                    failures: 0,
                    disabled: false,
                }],
            };
            let policy_report = PolicyReport {
                policy: AnonymityPolicy::GuardPq,
                effective_policy: AnonymityPolicy::GuardPq,
                total_candidates: 1,
                pq_candidates: 1,
                selected_soranet_total: 1,
                selected_pq: 1,
                status: PolicyStatus::Met,
                fallback_reason: None,
            };
            let mut manifest_car_digest = [0u8; 32];
            manifest_car_digest.copy_from_slice(car_stats_clone.car_archive_digest.as_bytes());
            let car_verification = GatewayCarVerification {
                manifest_digest: manifest_digest_copy,
                manifest_payload_digest: plan_override.payload_digest,
                manifest_content_length: plan_override.content_length,
                manifest_chunk_count: u64::try_from(chunk_specs.len())
                    .expect("chunk count fits in u64"),
                manifest_car_digest,
                manifest_governance: manifest_governance.clone(),
                chunk_profile_handle: chunker_handle_clone.clone(),
                car_stats: car_stats_clone.clone(),
                por_leaf_count: 0,
            };
            let manifest_stub = BrowserExtensionManifest {
                version: 1,
                authority: "127.0.0.1:9000".into(),
                certificate_pem: BASE64.encode(&manifest_bytes_clone),
                cert_fingerprint_hex: Some("DEADBEEF".into()),
                alpn: Some("h3".into()),
                capabilities: vec!["raw-stream".into()],
                proxy_mode: ProxyMode::Bridge,
                session_id: Some("session".into()),
                telemetry_label: Some("test-proxy".into()),
                client_capability_hex: None,
                circuit: None,
                guard_selection: None,
                route_hints: Vec::new(),
                cache_tagging: None,
                telemetry_v2: None,
            };
            Ok(FetchSession {
                outcome,
                policy_report,
                local_proxy_manifest: Some(manifest_stub),
                car_verification: Some(car_verification),
            })
        });
        let result = sorafs_gateway_fetch(
            manifest_id_hex.clone(),
            chunker_handle.clone(),
            plan_json,
            vec![JsGatewayProviderSpec {
                name: "alpha".to_string(),
                provider_id_hex: provider_id_hex.clone(),
                gateway_public_key_hex:
                    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12".to_owned(),
                base_url: "https://stub".into(),
                stream_token_b64,
                privacy_events_url: None,
            }],
            Some(options),
        )
        .expect("gateway fetch result");
        drop(override_guard);
        assert_eq!(result.manifest_id_hex, manifest_id_hex);
        assert_eq!(result.chunker_handle, chunker_handle);
        assert_eq!(
            usize::try_from(result.chunk_count).expect("chunk count fits in usize"),
            plan.chunks.len()
        );
        assert_eq!(result.payload.len(), payload.len());
        assert_eq!(result.payload.as_ref(), payload.as_slice());
        assert_eq!(result.telemetry_region.as_deref(), Some("ci-region"));
        let manifest_json = result
            .local_proxy_manifest_json
            .as_ref()
            .expect("local proxy manifest");
        let manifest_value: Value = json::from_str(manifest_json).expect("parse manifest json");
        let authority = manifest_value
            .get("authority")
            .and_then(Value::as_str)
            .expect("manifest authority");
        assert!(
            authority.starts_with("127.0.0.1:"),
            "expected loopback authority, got {authority}"
        );
        let verification = result
            .car_verification
            .expect("car verification should be present");
        assert_eq!(
            verification.manifest_digest_hex,
            hex::encode_upper(manifest_digest.as_bytes())
        );
        assert_eq!(
            verification.manifest_payload_digest_hex,
            hex::encode_upper(plan.payload_digest.as_bytes())
        );
        assert_eq!(verification.manifest_content_length.0, plan.content_length);
        assert_eq!(
            verification.manifest_chunk_count.0,
            u64::try_from(plan.chunks.len()).expect("chunk count fits in u64")
        );
        assert_eq!(verification.manifest_governance.council_signatures.len(), 1);
        assert_eq!(
            verification.car_archive.payload_digest_hex,
            hex::encode_upper(car_stats.car_payload_digest.as_bytes())
        );
        assert_eq!(verification.car_archive.size.0, car_stats.car_size);
    }
    fn sample_js_range_capability() -> JsRangeCapability {
        let profile = ChunkProfile::DEFAULT;
        JsRangeCapability {
            max_chunk_span: u32::try_from(profile.max_size).expect("chunk span fits in u32"),
            min_granularity: u32::try_from(profile.min_size).expect("granularity fits in u32"),
            supports_sparse_offsets: Some(true),
            requires_alignment: Some(false),
            supports_merkle_proof: Some(true),
        }
    }
    fn sample_js_stream_budget() -> JsStreamBudget {
        JsStreamBudget {
            max_in_flight: 4,
            max_bytes_per_sec: JsU64(5_000_000),
            burst_bytes: Some(JsU64(5_000_000)),
        }
    }
    fn sample_provider_metadata(name: &str, issued_at: u64) -> JsProviderMetadata {
        JsProviderMetadata {
            provider_id: Some(name.to_string()),
            profile_id: Some("sorafs.sf1@1.0.0".into()),
            profile_aliases: Some(vec![name.to_string()]),
            availability: Some("hot".into()),
            stake_amount: Some("1000000".into()),
            max_streams: Some(4),
            refresh_deadline: Some(JsU64(issued_at + 1_800)),
            expires_at: Some(JsU64(issued_at + 3_600)),
            ttl_secs: Some(JsU64(3_600)),
            allow_unknown_capabilities: Some(false),
            capability_names: Some(vec!["torii_gateway".into(), "chunk_range_fetch".into()]),
            rendezvous_topics: None,
            notes: Some(format!("{name} provider")),
            range_capability: Some(sample_js_range_capability()),
            stream_budget: Some(sample_js_stream_budget()),
            transport_hints: None,
        }
    }
    struct DaManifestFixture {
        manifest_bytes: Vec<u8>,
        payload: Vec<u8>,
        blob_hash: [u8; 32],
        chunk_root: [u8; 32],
        leaf_count: usize,
    }
    fn build_da_manifest_fixture() -> DaManifestFixture {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture_root = crate_root
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .join("fixtures/da/reconstruct/rs_parity_v1");
        let manifest_hex = fs::read_to_string(fixture_root.join("manifest.norito.hex"))
            .expect("read shared DA manifest fixture");
        let manifest_bytes = hex::decode(manifest_hex).expect("decode shared DA manifest fixture");
        let manifest: DaManifestV1 =
            decode_from_bytes(&manifest_bytes).expect("decode shared DA manifest");
        let payload =
            fs::read(fixture_root.join("payload.bin")).expect("read shared DA payload fixture");
        let plan = sorafs_car::build_plan_from_da_manifest(&manifest)
            .expect("build shared DA manifest plan");
        let mut store = ChunkStore::with_profile(plan.chunk_profile);
        let mut source = InMemoryPayload::new(&payload);
        store
            .ingest_plan_source(&plan, &mut source)
            .expect("ingest payload");
        DaManifestFixture {
            manifest_bytes,
            payload,
            blob_hash: *manifest.blob_hash.as_ref(),
            chunk_root: *manifest.chunk_root.as_ref(),
            leaf_count: store.por_tree().leaf_count(),
        }
    }
    fn unix_time_now() -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
    }
    #[test]
    fn sorafs_multi_fetch_local_scoreboard_prefers_eligible_provider() {
        let tempdir = tempdir().expect("tempdir");
        let payload: Vec<u8> = (0..(4 * 1024_usize))
            .map(|idx| u8::try_from(idx % 211).expect("modulo fits in u8"))
            .collect();
        let alpha_path = tempdir.path().join("alpha.bin");
        let beta_path = tempdir.path().join("beta.bin");
        fs::write(&alpha_path, &payload).expect("write alpha payload");
        fs::write(&beta_path, &payload).expect("write beta payload");
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json = chunk_fetch_plan_to_string(&plan).expect("serialize plan");
        let issued_at = unix_time_now().unwrap_or(1_700_000_000);
        let providers = vec![
            JsLocalProviderSpec {
                name: "alpha".to_owned(),
                path: alpha_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: Some(sample_provider_metadata("alpha", issued_at)),
            },
            JsLocalProviderSpec {
                name: "beta".to_owned(),
                path: beta_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: Some(sample_provider_metadata("beta", issued_at)),
            },
        ];
        let telemetry = vec![
            JsTelemetryEntry {
                provider_id: "alpha".into(),
                qos_score: Some(40.0),
                latency_p95_ms: Some(900.0),
                failure_rate_ewma: Some(0.3),
                token_health: Some(0.6),
                staking_weight: Some(0.8),
                reputation_score_bps: Some(3_500),
                penalty: Some(true),
                last_updated_unix: Some(JsU64(issued_at)),
            },
            JsTelemetryEntry {
                provider_id: "beta".into(),
                qos_score: Some(95.0),
                latency_p95_ms: Some(140.0),
                failure_rate_ewma: Some(0.05),
                token_health: Some(0.98),
                staking_weight: Some(1.2),
                reputation_score_bps: Some(9_200),
                penalty: Some(false),
                last_updated_unix: Some(JsU64(issued_at)),
            },
        ];
        let result = sorafs_multi_fetch_local(
            plan_json,
            providers,
            Some(JsMultiFetchOptions {
                use_scoreboard: Some(true),
                telemetry: Some(telemetry),
                return_scoreboard: Some(true),
                ..Default::default()
            }),
        )
        .expect("multi-fetch succeeds with scoreboard");
        assert_eq!(
            result.chunk_count as usize,
            plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
        );
        assert_eq!(result.provider_reports.len(), 1);
        let beta_report = &result.provider_reports[0];
        assert_eq!(beta_report.provider, "beta");
        assert!(!beta_report.disabled);
        assert!(
            result
                .chunk_receipts
                .iter()
                .all(|receipt| receipt.provider == "beta")
        );
        let scoreboard = result
            .scoreboard
            .expect("scoreboard entries should be returned");
        assert!(
            scoreboard
                .iter()
                .any(|entry| entry.alias == "beta" && entry.eligibility == "eligible")
        );
        assert!(scoreboard.iter().any(|entry| entry.alias == "alpha"
            && entry.eligibility.to_ascii_lowercase().contains("penalty")));
    }
    #[test]
    fn sorafs_multi_fetch_local_policy_denies_provider() {
        let tempdir = tempdir().expect("tempdir");
        let payload: Vec<u8> = (0..(4 * 1024_usize))
            .map(|idx| u8::try_from(idx % 197).expect("modulo fits in u8"))
            .collect();
        let alpha_path = tempdir.path().join("alpha.bin");
        let beta_path = tempdir.path().join("beta.bin");
        fs::write(&alpha_path, &payload).expect("write alpha payload");
        fs::write(&beta_path, &payload).expect("write beta payload");
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json = chunk_fetch_plan_to_string(&plan).expect("serialize plan");
        let providers = vec![
            JsLocalProviderSpec {
                name: "alpha".to_owned(),
                path: alpha_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
            JsLocalProviderSpec {
                name: "beta".to_owned(),
                path: beta_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
        ];
        let result = sorafs_multi_fetch_local(
            plan_json,
            providers,
            Some(JsMultiFetchOptions {
                deny_providers: Some(vec!["alpha".into()]),
                ..Default::default()
            }),
        )
        .expect("multi-fetch succeeds with deny policy");
        assert_eq!(result.provider_reports.len(), 2);
        let alpha_report = result
            .provider_reports
            .iter()
            .find(|report| report.provider == "alpha")
            .expect("alpha report present");
        assert_eq!(alpha_report.successes, 0);
        assert_eq!(alpha_report.failures, 0);
        let beta_report = result
            .provider_reports
            .iter()
            .find(|report| report.provider == "beta")
            .expect("beta report present");
        assert_eq!(
            beta_report.successes as usize,
            plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
        );
        assert!(!beta_report.disabled);
        assert!(
            result
                .chunk_receipts
                .iter()
                .all(|receipt| receipt.provider == "beta")
        );
    }
    #[test]
    fn transfer_asset_instruction_json_roundtrip() {
        let source_account = sample_account("wonderland");
        let destination = sample_account("wonderland");
        let asset_definition: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset_id = AssetId::new(asset_definition, source_account.clone());
        let transfer_box: TransferBox = Transfer::asset_quantity(
            asset_id,
            Quantity::from_str("25").expect("valid quantity"),
            destination,
        )
        .into();
        let instruction = InstructionBox::from(transfer_box);
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize instruction to json");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Transfer"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize instruction from json");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    #[allow(clippy::too_many_lines)] // End-to-end JSON roundtrip coverage is easier to read as one consolidated case table.
    fn rwa_instruction_json_roundtrip() {
        let source_account = sample_account("wonderland");
        let destination = sample_account("wonderland");
        let rwa_id = sample_rwa_id("commodities", 0x31);
        let parent = RwaParentRef::new(
            sample_rwa_id("commodities", 0x32),
            Quantity::from_str("1.25").expect("valid quantity"),
        );
        let controls = RwaControlPolicy {
            controller_accounts: vec![source_account.clone()],
            controller_roles: Vec::new(),
            freeze_enabled: true,
            hold_enabled: true,
            force_transfer_enabled: true,
            redeem_enabled: false,
        };
        let new_rwa = NewRwa::new(
            DomainId::try_new("commodities", "universal").expect("valid domain id"),
            Quantity::from_str("10.5").expect("valid quantity"),
            iroha_primitives::numeric::NumericSpec::fractional(1),
            "vault-cert-001".to_owned(),
            Some(Name::from_str("Active").expect("valid status")),
            Metadata::default(),
            vec![parent.clone()],
            controls.clone(),
        );
        let cases = vec![
            norito_json!({
                "RegisterRwa": norito_json!({
                    "rwa": new_rwa_to_json(&new_rwa).expect("render new rwa"),
                })
            }),
            norito_json!({
                "TransferRwa": norito_json!({
                    "source": source_account.canonical_i105().expect("canonical I105 source"),
                    "rwa": rwa_id.to_string(),
                    "quantity": Quantity::from_str("2.5").expect("valid quantity"),
                    "destination": destination
                        .canonical_i105()
                        .expect("canonical I105 destination"),
                })
            }),
            norito_json!({
                "MergeRwas": norito_json!({
                    "parents": rwa_parent_refs_to_json(std::slice::from_ref(&parent)),
                    "primary_reference": "blend-001".to_owned(),
                    "status": Value::Null,
                    "metadata": Metadata::default(),
                })
            }),
            norito_json!({
                "RedeemRwa": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "quantity": Quantity::from_str("1").expect("valid quantity"),
                })
            }),
            norito_json!({ "FreezeRwa": norito_json!({ "rwa": rwa_id.to_string() }) }),
            norito_json!({ "UnfreezeRwa": norito_json!({ "rwa": rwa_id.to_string() }) }),
            norito_json!({
                "HoldRwa": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "quantity": Quantity::from_str("0.5").expect("valid quantity"),
                })
            }),
            norito_json!({
                "ReleaseRwa": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "quantity": Quantity::from_str("0.25").expect("valid quantity"),
                })
            }),
            norito_json!({
                "ForceTransferRwa": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "quantity": Quantity::from_str("1.5").expect("valid quantity"),
                    "destination": destination
                        .canonical_i105()
                        .expect("canonical I105 destination"),
                })
            }),
            norito_json!({
                "SetRwaControls": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "controls": controls.clone(),
                })
            }),
            norito_json!({
                "SetRwaKeyValue": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "key": Name::from_str("grade").expect("valid key"),
                    "value": norito_json!({
                        "origin": "AE",
                        "score": Numeric::from_str("9").expect("valid numeric"),
                    }),
                })
            }),
            norito_json!({
                "RemoveRwaKeyValue": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "key": Name::from_str("grade").expect("valid key"),
                })
            }),
        ];
        for json_value in cases {
            let instruction =
                value_to_instruction(json_value.clone()).expect("deserialize RWA instruction");
            let rendered =
                instruction_to_json_value(&instruction).expect("serialize RWA instruction");
            assert_eq!(rendered, json_value);
        }
        let negative = norito_json!({
            "TransferRwa": norito_json!({
                "source": source_account.canonical_i105().expect("canonical I105 source"),
                "rwa": rwa_id.to_string(),
                "quantity": "-1",
                "destination": destination
                    .canonical_i105()
                    .expect("canonical I105 destination"),
            })
        });
        assert!(
            value_to_instruction(negative).is_err(),
            "RWA instructions must reject negative signed quantity payloads"
        );
    }
    #[test]
    fn rwa_instruction_json_rejects_non_quantity_spellings() {
        let rwa_id = sample_rwa_id("commodities", 0x41);
        let parent_rwa_id = sample_rwa_id("commodities", 0x42);
        let invalid_quantities = [
            "-1".to_owned(),
            "1.0".to_owned(),
            "+1".to_owned(),
            "01".to_owned(),
            format!("0.{}1", "0".repeat(28)),
        ];
        for quantity in invalid_quantities {
            let instruction = norito_json!({
                "RedeemRwa": norito_json!({
                    "rwa": rwa_id.to_string(),
                    "quantity": quantity.clone(),
                })
            });
            assert!(
                value_to_instruction(instruction).is_err(),
                "RWA instruction must reject invalid quantity spelling {quantity:?}",
            );
            let parent = norito_json!({
                "rwa": parent_rwa_id.to_string(),
                "quantity": quantity.clone(),
            });
            assert!(
                parse_rwa_parent_refs_value(
                    json::Value::Array(vec![parent]),
                    "RegisterRwa.rwa.parents",
                )
                .is_err(),
                "RWA parent must reject invalid quantity spelling {quantity:?}",
            );
        }
    }
    #[test]
    fn kaigi_join_instruction_json_roundtrip() {
        let mut call_id = json::Map::new();
        call_id.insert("domain_id".into(), Value::String("wonderland.sora".into()));
        call_id.insert("call_name".into(), Value::String("weekly-sync".into()));
        let mut commitment = json::Map::new();
        commitment.insert(
            "commitment".into(),
            json::to_value(&KaigiAuthorizationScalarV1::from_le_bytes([0x11; 32]).unwrap())
                .unwrap(),
        );
        let mut nullifier = json::Map::new();
        nullifier.insert(
            "digest".into(),
            json::to_value(&KaigiAuthorizationScalarV1::from_le_bytes([0x22; 32]).unwrap())
                .unwrap(),
        );
        let participant = sample_account("wonderland");
        let mut join = json::Map::new();
        join.insert("call_id".into(), Value::Object(call_id));
        join.insert(
            "participant".into(),
            Value::String(account_json_literal(&participant)),
        );
        join.insert("commitment".into(), Value::Object(commitment));
        join.insert("nullifier".into(), Value::Object(nullifier));
        join.insert("roster_root".into(), Value::String(hash_literal(0x33)));
        join.insert("proof".into(), Value::String("qrvM".into()));
        let mut kaigi = json::Map::new();
        kaigi.insert("JoinKaigi".into(), Value::Object(join));
        let mut outer = json::Map::new();
        outer.insert("Kaigi".into(), Value::Object(kaigi));
        let json_value = Value::Object(outer);
        let instruction = value_to_instruction(json_value.clone()).expect("parse join json");
        let bytes = norito::to_bytes(&instruction).expect("encode join json");
        let decoded: InstructionBox = decode_from_bytes(&bytes).expect("decode join instruction");
        let rendered = instruction_to_json_value(&decoded).expect("render join json");
        assert_eq!(rendered, json_value);
    }
    #[test]
    fn mint_trigger_instruction_json_roundtrip() {
        let trigger_id: TriggerId = "notify-users".parse().expect("valid trigger id");
        let mint_box: MintBox = Mint::trigger_repetitions(3, trigger_id.clone()).into();
        let instruction = InstructionBox::from(mint_box);
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize instruction to json");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Mint"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize instruction from json");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn transfer_domain_instruction_json_roundtrip() {
        let source_account = sample_account("wonderland");
        let destination = sample_account("wonderland");
        let domain_id: DomainId =
            DomainId::try_new("wonderland", "universal").expect("valid domain id");
        let transfer_box: TransferBox = Transfer::domain(
            source_account.clone(),
            domain_id.clone(),
            destination.clone(),
        )
        .into();
        let instruction = InstructionBox::from(transfer_box);
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize instruction to json");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Transfer"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize instruction from json");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn register_peer_instruction_json_roundtrip() {
        let keypair = KeyPair::random();
        let peer_id = PeerId::from(keypair.public_key().clone());
        let register = RegisterPeerWithPop::new(peer_id.clone(), vec![0xAA, 0xBB]);
        let instruction = InstructionBox::from(RegisterBox::Peer(register));
        let json_value = instruction_to_json_value(&instruction).expect("serialize register peer");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Register"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize register peer");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn register_nft_instruction_json_roundtrip() {
        let nft_id: NftId = "collectible$wonderland".parse().expect("valid nft id");
        let mut nft_fields = json::Map::new();
        nft_fields.insert(
            "id".to_owned(),
            json::to_value(&nft_id).expect("serialize nft id"),
        );
        nft_fields.insert(
            "content".to_owned(),
            json::to_value(&Metadata::default()).expect("serialize metadata"),
        );
        let mut register_map = json::Map::new();
        register_map.insert("Nft".to_owned(), json::Value::Object(nft_fields));
        let mut outer = json::Map::new();
        outer.insert("Register".to_owned(), json::Value::Object(register_map));
        let json_value = json::Value::Object(outer);
        let instruction =
            value_to_instruction(json_value.clone()).expect("parse register nft instruction");
        let rendered =
            instruction_to_json_value(&instruction).expect("render register nft instruction");
        assert_eq!(rendered, json_value);
    }
    #[test]
    fn unregister_peer_instruction_json_roundtrip() {
        let keypair = KeyPair::random();
        let peer_id = PeerId::from(keypair.public_key().clone());
        let unregister = Unregister::<Peer>::peer(peer_id);
        let instruction = InstructionBox::from(UnregisterBox::Peer(unregister));
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize unregister peer");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Unregister"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize unregister peer");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn transfer_nft_instruction_json_roundtrip() {
        let source_account = sample_account("wonderland");
        let destination = sample_account("wonderland");
        let nft_id: NftId = "dragon$wonderland".parse().expect("valid nft id");
        let transfer_box: TransferBox =
            Transfer::nft(source_account.clone(), nft_id.clone(), destination.clone()).into();
        let instruction = InstructionBox::from(transfer_box);
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize instruction to json");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Transfer"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize instruction from json");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn create_kaigi_instruction_json_roundtrip() {
        let host = sample_account("wonderland");
        let relay = sample_account("wonderland");
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let manifest = KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: relay.clone(),
                hpke_public_key: vec![0x01, 0x02, 0x03, 0x04],
                weight: 7,
            }],
            expiry_ms: 1_700_000_500_000,
        };
        let call = NewKaigi {
            id: call_id.clone(),
            host: host.clone(),
            title: Some("Weekly Sync".to_owned()),
            description: Some("Roadmap alignment".to_owned()),
            max_participants: Some(16),
            gas_rate_per_minute: 120,
            metadata: Metadata::default(),
            scheduled_start_ms: Some(1_700_000_000_000),
            billing_account: Some(host.clone()),
            privacy_mode: KaigiPrivacyMode::Transparent,
            room_policy: KaigiRoomPolicy::Authenticated,
            relay_manifest: Some(manifest),
        };
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x11; 32]).unwrap(),
        };
        let nullifier = KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes([0x22; 32]).unwrap(),
        };
        let instruction: InstructionBox = Box::new(CreateKaigi {
            call,
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(Hash::new(b"roster-root")),
            proof: Some(vec![0xFA, 0xCE]),
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize Kaigi instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn join_kaigi_instruction_json_roundtrip() {
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let participant = sample_account("wonderland");
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x11; 32]).unwrap(),
        };
        let nullifier = KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes([0x22; 32]).unwrap(),
        };
        let roster_root = Hash::new(b"roster-root");
        let proof = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let join = JoinKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(roster_root),
            proof: Some(proof),
        };
        let instruction: InstructionBox = Box::new(join).into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi join instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize Kaigi join instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn join_kaigi_instruction_norito_roundtrip_from_json() {
        let participant = account_json_literal(&sample_account("wonderland"));
        let payload = r#"{
            "Kaigi": {
                "JoinKaigi": {
                    "call_id": {
                        "domain_id": "wonderland.sora",
                        "call_name": "weekly-sync"
                    },
                    "participant": "__PARTICIPANT__",
                    "commitment": {
                        "commitment": [17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17]
                    },
                    "nullifier": {
                        "digest": [34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34]
                    },
                    "roster_root": "hash:3333333333333333333333333333333333333333333333333333333333333333#70D6",
                    "proof": "qrvM"
                }
            }
        }"#;
        let payload = payload.replace("__PARTICIPANT__", &participant);
        let instruction =
            instruction_from_json(&payload).expect("builder JSON must translate into instruction");
        if let Some(join) = instruction.as_any().downcast_ref::<JoinKaigi>() {
            assert!(
                join.commitment().is_some(),
                "JSON builder should supply a commitment"
            );
            assert!(
                join.nullifier().is_some(),
                "JSON builder should supply a nullifier"
            );
            assert!(
                join.roster_root().is_some(),
                "JSON builder should supply a roster root"
            );
        } else {
            panic!("expected JoinKaigi instruction");
        }
        let encoded =
            norito::to_bytes(&instruction).expect("encoding JoinKaigi instruction to bytes");
        let decoded: InstructionBox =
            decode_from_bytes(&encoded).expect("deserialize JoinKaigi instruction");
        assert_eq!(decoded, instruction);
    }
    #[test]
    fn leave_kaigi_instruction_json_roundtrip() {
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let participant = sample_account("wonderland");
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x11; 32]).unwrap(),
        };
        let nullifier = KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes([0x22; 32]).unwrap(),
        };
        let roster_root = Hash::new(b"leave-root");
        let proof = vec![0xDE, 0xAD];
        let leave = LeaveKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(roster_root),
            proof: Some(proof),
        };
        let instruction: InstructionBox = Box::new(leave).into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi leave instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize Kaigi leave instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn end_kaigi_instruction_json_roundtrip() {
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let commitment = KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes([0x11; 32]).unwrap(),
        };
        let nullifier = KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes([0x22; 32]).unwrap(),
        };
        let end = EndKaigi {
            call_id: call_id.clone(),
            ended_at_ms: Some(1_700_222_000_000),
            commitment: Some(commitment),
            nullifier: Some(nullifier),
            roster_root: Some(Hash::new(b"roster-root")),
            proof: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let instruction: InstructionBox = Box::new(end).into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi end instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize Kaigi end instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn record_kaigi_usage_instruction_json_roundtrip() {
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let usage_commitment = KaigiAuthorizationScalarV1::from_le_bytes([0x33; 32]).unwrap();
        let proof = vec![0xAB, 0xCD];
        let usage = RecordKaigiUsage {
            call_id: call_id.clone(),
            duration_ms: 60_000,
            billed_gas: 512,
            usage_commitment: Some(usage_commitment),
            proof: Some(proof),
        };
        let instruction: InstructionBox = Box::new(usage).into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi usage instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize Kaigi usage instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn report_kaigi_relay_health_instruction_json_roundtrip() {
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let relay_id = sample_account("wonderland");
        let report = ReportKaigiRelayHealth {
            call_id: call_id.clone(),
            relay_id: relay_id.clone(),
            status: KaigiRelayHealthStatus::Degraded,
            reported_at_ms: 1_701_123_456_789,
            notes: Some("latency spike observed".to_owned()),
        };
        let instruction: InstructionBox = Box::new(report).into_instruction_box();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize Kaigi relay health instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed = value_to_instruction(json_value.clone())
            .expect("deserialize Kaigi relay health instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn set_kaigi_relay_manifest_instruction_json_roundtrip() {
        let call_id = sample_kaigi_id("wonderland", "weekly-sync");
        let relay = sample_account("wonderland");
        let manifest = KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: relay,
                hpke_public_key: vec![0x10, 0x11, 0x12],
                weight: 3,
            }],
            expiry_ms: 1_700_111_000_000,
        };
        let instruction: InstructionBox = Box::new(SetKaigiRelayManifest {
            call_id: call_id.clone(),
            relay_manifest: Some(manifest),
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi manifest instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed = value_to_instruction(json_value.clone())
            .expect("deserialize Kaigi manifest instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn register_kaigi_relay_instruction_json_roundtrip() {
        let relay = sample_account("wonderland");
        let instruction: InstructionBox = Box::new(RegisterKaigiRelay {
            relay: KaigiRelayRegistration {
                relay_id: relay,
                hpke_public_key: vec![0xAA, 0xBB, 0xCC, 0xDD],
                bandwidth_class: 9,
            },
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize Kaigi relay instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize Kaigi relay instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn unregister_kaigi_relay_instruction_json_roundtrip() {
        let relay_id = sample_account("wonderland");
        let instruction: InstructionBox =
            Box::new(UnregisterKaigiRelay { relay_id }).into_instruction_box();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize Kaigi relay unregistration instruction");
        let outer = json_value
            .as_object()
            .expect("instruction JSON should be an object");
        assert!(outer.contains_key("Kaigi"));
        let reconstructed = value_to_instruction(json_value)
            .expect("deserialize Kaigi relay unregistration instruction");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn governance_propose_deploy_contract_instruction_json_roundtrip() {
        let instruction: InstructionBox = Box::new(ProposeDeployContract {
            contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                .parse()
                .expect("contract address"),
            code_hash: ContractCodeHash::new([0xaa; 32]),
            abi_hash: ContractAbiHash::new([0xbb; 32]),
            abi_version: AbiVersion::new(1),
            manifest_provenance: None,
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize governance instruction");
        assert!(
            json_value
                .as_object()
                .and_then(|map| map.get("ProposeDeployContract"))
                .is_some()
        );
        let fields = json_value
            .as_object()
            .and_then(|map| map.get("ProposeDeployContract"))
            .and_then(json::Value::as_object)
            .expect("typed deploy proposal fields");
        assert!(fields.contains_key("code_hash"));
        assert!(fields.contains_key("abi_hash"));
        assert_eq!(fields.get("abi_version"), Some(&json::Value::from(1_u64)));
        for retired in ["code_hash_hex", "abi_hash_hex", "window", "mode"] {
            let mut legacy = json_value.clone();
            legacy
                .as_object_mut()
                .and_then(|map| map.get_mut("ProposeDeployContract"))
                .and_then(json::Value::as_object_mut)
                .expect("legacy deploy proposal fields")
                .insert(retired.to_owned(), json::Value::Null);
            let error = value_to_instruction(legacy)
                .expect_err("retired deploy proposal field must fail closed");
            assert!(
                error.reason.contains(retired),
                "{retired}: {}",
                error.reason
            );
        }
        let mut string_abi = json_value.clone();
        string_abi
            .as_object_mut()
            .and_then(|map| map.get_mut("ProposeDeployContract"))
            .and_then(json::Value::as_object_mut)
            .expect("string ABI deploy proposal fields")
            .insert(
                "abi_version".to_owned(),
                json::Value::String("1".to_owned()),
            );
        assert!(
            value_to_instruction(string_abi).is_err(),
            "string ABI version must fail closed"
        );
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize governance instruction");
        assert_eq!(reconstructed, instruction);
    }
    // Validation-fee wire, fingerprint, and rejection cases live in one bounded fragment.
    include!("validation_fee_tests.rs");
    #[test]
    fn retired_sns_mutation_instructions_are_rejected() {
        for retired in [
            "RegisterSnsName",
            "RenewSnsName",
            "TransferSnsName",
            "UpdateSnsNameControllers",
            "FreezeSnsName",
            "UnfreezeSnsName",
        ] {
            let value = json::Value::Object(json::Map::from_iter([(
                retired.to_owned(),
                json::Value::Object(json::Map::new()),
            )]));
            let error = value_to_instruction(value)
                .expect_err("retired SNS mutation instruction must not decode");
            assert!(
                error.reason.contains("unsupported instruction"),
                "unexpected rejection for {retired}: {}",
                error.reason
            );
        }
    }
    #[test]
    fn governance_cast_zk_ballot_instruction_json_roundtrip() {
        let instruction: InstructionBox = Box::new(CastZkBallot {
            election_id: "ref-1".to_owned(),
            proof_b64: STANDARD.encode([0x01, 0x02, 0x03]),
            public_inputs_json: r#"{"tally":"aye"}"#.to_owned(),
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize CastZkBallot instruction");
        assert!(
            json_value
                .as_object()
                .and_then(|map| map.get("CastZkBallot"))
                .is_some()
        );
        let reconstructed = value_to_instruction(json_value).expect("deserialize CastZkBallot");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn governance_selectors_are_canonical_at_instruction_construction() {
        const VARIANTS: [&str; 5] = [
            "CastZkBallot",
            "CastPlainBallot",
            "CreateElection",
            "SubmitBallot",
            "FinalizeElection",
        ];
        let maximum = "a".repeat(128);
        for selector in ["a", maximum.as_str()] {
            for variant in VARIANTS {
                let value = governance_selector_instruction_json(variant, selector);
                validate_governance_instruction_selectors(&value).unwrap_or_else(|error| {
                    panic!(
                        "valid {variant} selector of length {} was rejected: {}",
                        selector.len(),
                        error.reason
                    )
                });
            }
        }
        let overlong = "a".repeat(129);
        for (case, selector) in [
            ("empty", ""),
            ("dot", "."),
            ("leading dot", ".hidden"),
            ("slash", "a/b"),
            ("percent", "a%2Fb"),
            ("whitespace", "a b"),
            ("control", "a\0b"),
            ("Unicode", "投票"),
            ("129 bytes", overlong.as_str()),
        ] {
            for variant in VARIANTS {
                let error =
                    value_to_instruction(governance_selector_instruction_json(variant, selector))
                        .expect_err(
                            "noncanonical selector must fail before instruction construction",
                        );
                assert_eq!(error.status, napi::Status::InvalidArg);
                assert!(
                    error
                        .reason
                        .contains("must be 1-128 RFC 3986 unreserved ASCII characters"),
                    "unexpected {variant} {case} rejection: {}",
                    error.reason
                );
            }
        }
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_deprecated_keys() {
        let mut inner = json::Map::new();
        let owner = canonical_owner_literal("wonderland");
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01, 0x02])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String(format!(
                r#"{{"owner":"{owner}","amount":"10","durationBlocks":64}}"#
            )),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        assert!(value_to_instruction(json::Value::Object(outer)).is_err());
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_canonicalizes_hex_hints() {
        let mut inner = json::Map::new();
        let owner = canonical_owner_literal("wonderland");
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01, 0x02])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String(
                format!(
                    r#"{{"owner":"{owner}","amount":"10","duration_blocks":64,"root_hint":"0x{}","nullifier":"blake2b32:{}"}}"#,
                    "Aa".repeat(32),
                    "BB".repeat(32)
                ),
            ),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        let instruction =
            value_to_instruction(json::Value::Object(outer)).expect("deserialize CastZkBallot");
        let ballot = instruction
            .as_any()
            .downcast_ref::<CastZkBallot>()
            .expect("CastZkBallot");
        let parsed: json::Value =
            json::from_str(&ballot.public_inputs_json).expect("parse public inputs");
        let root_hint = parsed
            .get("root_hint")
            .and_then(json::Value::as_str)
            .expect("root_hint");
        let nullifier = parsed
            .get("nullifier")
            .and_then(json::Value::as_str)
            .expect("nullifier");
        assert_eq!(root_hint, "aa".repeat(32));
        assert_eq!(nullifier, "bb".repeat(32));
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_noncanonical_owner() {
        let mut inner = json::Map::new();
        let owner = noncanonical_owner_literal("wonderland");
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String(format!(
                r#"{{"owner":"{owner}","amount":"10","duration_blocks":64}}"#
            )),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        assert!(value_to_instruction(json::Value::Object(outer)).is_err());
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_accepts_fractional_and_wide_quantity_hints() {
        let owner = canonical_owner_literal("wonderland");
        let wide = "340282366920938463463374607431768211456.25";
        for amount in ["1.25", wide] {
            let mut value = norito_json!({
                "owner": owner,
                "amount": amount,
                "duration_blocks": 64,
            });
            normalize_zk_ballot_public_inputs(&mut value, "CastZkBallot.public_inputs_json")
                .expect("canonical Quantity lock hint must normalize");
            assert_eq!(
                value.get("amount").and_then(json::Value::as_str),
                Some(amount)
            );
        }
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_invalid_quantity_hints() {
        let owner = canonical_owner_literal("wonderland");
        let oversized = format!("1{}", "0".repeat(200));
        let invalid = [
            ("negative", json::Value::String("-1".to_owned())),
            ("leading zero", json::Value::String("01".to_owned())),
            (
                "trailing fractional zero",
                json::Value::String("1.0".to_owned()),
            ),
            ("explicit plus", json::Value::String("+1".to_owned())),
            ("leading whitespace", json::Value::String(" 1".to_owned())),
            ("trailing whitespace", json::Value::String("1 ".to_owned())),
            ("exponent", json::Value::String("1e3".to_owned())),
            ("overflow", json::Value::String(oversized)),
            (
                "number",
                json::from_str::<json::Value>("1").expect("JSON number"),
            ),
            ("boolean", json::Value::Bool(true)),
            ("array", json::Value::Array(Vec::new())),
            ("object", json::Value::Object(json::Map::new())),
        ];
        for (case, amount) in invalid {
            let mut map = json::Map::new();
            map.insert("owner".to_owned(), json::Value::String(owner.clone()));
            map.insert("amount".to_owned(), amount);
            map.insert(
                "duration_blocks".to_owned(),
                json::from_str::<json::Value>("64").expect("JSON number"),
            );
            let mut value = json::Value::Object(map);
            let error =
                normalize_zk_ballot_public_inputs(&mut value, "CastZkBallot.public_inputs_json")
                    .expect_err("invalid Quantity lock hint must be rejected");
            assert!(
                error.reason.contains(".amount"),
                "unexpected {case} rejection: {}",
                error.reason
            );
        }
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_partial_hints() {
        let mut inner = json::Map::new();
        let owner = canonical_owner_literal("wonderland");
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String(format!(r#"{{"owner":"{owner}"}}"#)),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        assert!(value_to_instruction(json::Value::Object(outer)).is_err());
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_deprecated_aliases() {
        let mut inner = json::Map::new();
        let owner = canonical_owner_literal("wonderland");
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String(format!(
                r#"{{"owner":"{owner}","amount":"10","duration_blocks":64,"rootHint":"aa"}}"#
            )),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        assert!(value_to_instruction(json::Value::Object(outer)).is_err());
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_invalid_hex() {
        let mut inner = json::Map::new();
        let owner = canonical_owner_literal("wonderland");
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String(format!(
                r#"{{"owner":"{owner}","amount":"10","duration_blocks":64,"root_hint":"not-hex"}}"#
            )),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        assert!(value_to_instruction(json::Value::Object(outer)).is_err());
    }
    #[test]
    fn governance_cast_zk_ballot_public_inputs_rejects_non_object_json() {
        let mut inner = json::Map::new();
        inner.insert(
            "election_id".to_owned(),
            json::Value::String("ref-1".to_owned()),
        );
        inner.insert(
            "proof_b64".to_owned(),
            json::Value::String(BASE64.encode([0x01])),
        );
        inner.insert(
            "public_inputs_json".to_owned(),
            json::Value::String("[1,2]".to_owned()),
        );
        let mut outer = json::Map::new();
        outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
        assert!(value_to_instruction(json::Value::Object(outer)).is_err());
    }
    #[test]
    fn governance_cast_plain_ballot_instruction_json_roundtrip() {
        let owner = sample_account("wonderland");
        let instruction: InstructionBox = Box::new(CastPlainBallot {
            referendum_id: "ref-plain".to_owned(),
            owner: owner.clone(),
            amount: 1_000_u64.into(),
            duration_blocks: 42,
            direction: 1,
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize CastPlainBallot instruction");
        assert!(
            json_value
                .as_object()
                .and_then(|map| map.get("CastPlainBallot"))
                .is_some()
        );
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize CastPlainBallot");
        assert_eq!(reconstructed, instruction);
        // Ensure owner round-tripped correctly.
        let owner_json = json_value
            .as_object()
            .unwrap()
            .get("CastPlainBallot")
            .and_then(|value| value.get("owner"))
            .and_then(|value| value.as_str())
            .expect("owner string present");
        assert_eq!(owner_json, account_json_literal(&owner));
    }
    #[test]
    fn governance_cast_plain_ballot_accepts_fractional_and_wide_quantities() {
        let owner = sample_account("wonderland");
        let wide = "340282366920938463463374607431768211456.25";
        for amount in ["1.25", wide] {
            let instruction = value_to_instruction(cast_plain_ballot_json(
                &owner,
                json::Value::String(amount.to_owned()),
            ))
            .expect("canonical plain-ballot Quantity must deserialize");
            let ballot = instruction
                .as_any()
                .downcast_ref::<CastPlainBallot>()
                .expect("CastPlainBallot");
            assert_eq!(ballot.amount.to_string(), amount);
            let encoded =
                instruction_to_json_value(&instruction).expect("serialize CastPlainBallot");
            assert_eq!(
                encoded
                    .get("CastPlainBallot")
                    .and_then(|value| value.get("amount"))
                    .and_then(json::Value::as_str),
                Some(amount)
            );
        }
    }
    #[test]
    fn governance_cast_plain_ballot_rejects_invalid_quantity_shapes_and_text() {
        let owner = sample_account("wonderland");
        let invalid = [
            ("negative", json::Value::String("-1".to_owned())),
            ("leading zero", json::Value::String("01".to_owned())),
            (
                "trailing fractional zero",
                json::Value::String("1.0".to_owned()),
            ),
            ("explicit plus", json::Value::String("+1".to_owned())),
            ("whitespace", json::Value::String(" 1".to_owned())),
            (
                "number",
                json::from_str::<json::Value>("1").expect("JSON number"),
            ),
            ("null", json::Value::Null),
            ("boolean", json::Value::Bool(true)),
            ("array", json::Value::Array(Vec::new())),
            ("object", json::Value::Object(json::Map::new())),
        ];
        for (case, amount) in invalid {
            let error = value_to_instruction(cast_plain_ballot_json(&owner, amount))
                .expect_err("invalid plain-ballot Quantity must be rejected");
            assert!(
                error.reason.contains("CastPlainBallot.amount"),
                "unexpected {case} rejection: {}",
                error.reason
            );
        }
    }
    #[test]
    fn governance_register_citizen_instruction_json_roundtrip() {
        let owner = sample_account("wonderland");
        let instruction: InstructionBox = Box::new(RegisterCitizen {
            owner: owner.clone(),
            amount: "10000.25".parse().expect("canonical Quantity"),
        })
        .into_instruction_box();
        let json_value =
            instruction_to_json_value(&instruction).expect("serialize RegisterCitizen instruction");
        assert!(
            json_value
                .as_object()
                .and_then(|map| map.get("RegisterCitizen"))
                .is_some()
        );
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize RegisterCitizen");
        assert_eq!(reconstructed, instruction);
        let owner_json = json_value
            .as_object()
            .unwrap()
            .get("RegisterCitizen")
            .and_then(|value| value.get("owner"))
            .and_then(|value| value.as_str())
            .expect("owner string present");
        assert_eq!(owner_json, account_json_literal(&owner));
    }
    #[test]
    fn governance_register_citizen_accepts_fractional_and_wide_quantities() {
        let owner = sample_account("wonderland");
        let wide = "340282366920938463463374607431768211456.25";
        for amount in ["1.25", wide] {
            let instruction = value_to_instruction(register_citizen_json(
                &owner,
                json::Value::String(amount.to_owned()),
            ))
            .expect("canonical citizen-bond Quantity must deserialize");
            let register = instruction
                .as_any()
                .downcast_ref::<RegisterCitizen>()
                .expect("RegisterCitizen");
            assert_eq!(register.amount.to_string(), amount);
        }
    }
    #[test]
    fn governance_register_citizen_rejects_invalid_quantity_shapes_and_text() {
        let owner = sample_account("wonderland");
        let invalid = [
            ("negative", json::Value::String("-1".to_owned())),
            ("leading zero", json::Value::String("01".to_owned())),
            (
                "trailing fractional zero",
                json::Value::String("1.0".to_owned()),
            ),
            ("explicit plus", json::Value::String("+1".to_owned())),
            ("leading whitespace", json::Value::String(" 1".to_owned())),
            ("trailing whitespace", json::Value::String("1 ".to_owned())),
            ("exponent", json::Value::String("1e3".to_owned())),
            (
                "number",
                json::from_str::<json::Value>("1").expect("JSON number"),
            ),
            ("null", json::Value::Null),
            ("boolean", json::Value::Bool(true)),
            ("array", json::Value::Array(Vec::new())),
            ("object", json::Value::Object(json::Map::new())),
        ];
        for (case, amount) in invalid {
            let error = value_to_instruction(register_citizen_json(&owner, amount))
                .expect_err("invalid citizen-bond Quantity must be rejected");
            assert!(
                error.reason.contains("RegisterCitizen.amount"),
                "unexpected {case} rejection: {}",
                error.reason
            );
        }
    }
    #[test]
    fn governance_submit_agenda_proposal_instruction_json_roundtrip() {
        let instruction: InstructionBox = Box::new(SubmitAgendaProposal {
            proposal: sample_agenda_proposal(),
        })
        .into_instruction_box();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize SubmitAgendaProposal instruction");
        assert!(
            json_value
                .as_object()
                .and_then(|map| map.get("SubmitAgendaProposal"))
                .is_some()
        );
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize SubmitAgendaProposal");
        assert_eq!(reconstructed, instruction);
        let proposal_id = json_value
            .as_object()
            .unwrap()
            .get("SubmitAgendaProposal")
            .and_then(|value| value.get("proposal"))
            .and_then(|value| value.get("proposal_id"))
            .and_then(|value| value.as_str())
            .expect("proposal id present");
        assert_eq!(proposal_id, "AC-2026-001");
    }
    #[test]
    fn smart_contract_code_instruction_json_roundtrip() {
        let signing_key = KeyPair::try_from_seed(vec![0x33; 32], Algorithm::Ed25519)
            .expect("fixture seed keypair");
        let max_frame_bytes = usize::try_from(
            iroha_data_model::parameter::system::TransactionParameters::default()
                .max_tx_bytes
                .get(),
        )
        .expect("canonical transaction byte ceiling");
        let signer_bytes = signing_key.public_key().retained_allocation_layout().size();
        let cumulative_bytes = max_frame_bytes
            .checked_add(signer_bytes)
            .expect("finite manifest allocation allowance");
        let physical_bytes = cumulative_bytes
            .checked_add(norito::core::DecodeBudgetContext::allocation_layout().size())
            .expect("finite manifest physical allowance");
        let pool = iroha_allocation::AllocationBudget::new(physical_bytes);
        let mut grant = pool
            .try_reserve_bytes(physical_bytes)
            .expect("fund original manifest codec allowance");
        let context = norito::core::DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(
                max_frame_bytes,
                max_frame_bytes,
                max_frame_bytes,
                cumulative_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            &mut grant,
        )
        .expect("retain original manifest accounting");
        let _signer_backing = grant
            .try_partition_bytes(signer_bytes)
            .expect("retain original compact signer backing");
        let manifest = ContractManifest {
            permissions: Vec::new(),
            events: Vec::new(),
            seiyaku_name: None,
            code_hash: Some(Hash::prehashed(sample_hash(0xAA))),
            abi_hash: Some(Hash::prehashed(sample_hash(0xBB))),
            compiler_fingerprint: Some("rustc-1.79".to_owned()),
            features_bitmap: Some(42),
            access_set_hints: Some(AccessSetHints {
                read_keys: vec!["account:alice".to_owned()],
                write_keys: vec!["contract:foo".to_owned()],
                dynamic_reads: Vec::new(),
                dynamic_writes: Vec::new(),
            }),
            entrypoints: Some(vec![EntrypointDescriptor {
                name: "kaizen".to_owned(),
                kind: EntryPointKind::Kaizen,
                params: vec![EntrypointParamDescriptor {
                    name: "reason".to_owned(),
                    type_name: "string".to_owned(),
                }],
                argument_schema: Some(
                    iroha_data_model::smart_contract::entrypoint::EntrypointArgumentSchemaV1 {
                        fields: vec![iroha_data_model::smart_contract::entrypoint::EntrypointArgumentFieldV1 {
                            name: "reason".to_owned(),
                            ty: iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                                    iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::String,
                                )],
                            },
                        }],
                    },
                ),
                return_type: Some("bool".to_owned()),
                return_schema: Some(
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                        nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                            iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::Bool,
                        )],
                    },
                ),
                authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::RuntimeLifecycle,
                read_keys: vec!["contract:ledger".to_owned()],
                write_keys: vec!["contract:ledger".to_owned()],
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
            }]),
            states: None,
            kotoba: Some(vec![KotobaTranslationEntry {
                msg_id: "contract.title".to_owned(),
                translations: vec![KotobaTranslation {
                    lang: "en".to_owned(),
                    text: "Ledger Contract".to_owned(),
                }],
            }]),
            error_messages: None,
            error_types: None,
            enum_types: Vec::new(),
            provenance: None,
        };
        let frame_bytes = context
            .with(|| {
                let _canonical =
                    norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
                norito::core::encoded_frame_len_bounded(
                    &manifest.signature_payload(),
                    max_frame_bytes,
                )
            })
            .expect("count canonical manifest payload");
        let frame = grant
            .try_partition_bytes(frame_bytes)
            .expect("admit exact canonical manifest payload");
        let manifest = manifest
            .try_signed(&context, frame_bytes, &signing_key)
            .expect("sign fixture manifest");
        drop(frame);
        let instruction: InstructionBox = Box::new(RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                DataSpaceId::new(u64::MAX),
                manifest.code_hash.expect("fixture manifest hash"),
            ),
            manifest,
        })
        .into_instruction_box();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize RegisterSmartContractCode instruction");
        assert!(
            json_value
                .as_object()
                .and_then(|map| map.get("RegisterSmartContractCode"))
                .is_some()
        );
        let payload = json_value
            .get("RegisterSmartContractCode")
            .expect("manifest instruction payload present");
        let artifact = payload
            .get("artifact_id")
            .expect("manifest artifact identity present");
        assert_eq!(
            artifact.get("dataspace_id"),
            Some(&json::Value::String(u64::MAX.to_string()))
        );
        assert_eq!(
            artifact.get("code_hash"),
            Some(&json::Value::String(hash_literal(0xAA)))
        );
        assert!(payload.get("code_hash").is_none());
        let reconstructed = value_to_instruction(json_value.clone())
            .expect("deserialize RegisterSmartContractCode");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn canonical_signed_transaction_decoder_rejects_framed_rpc_fixture() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/norito_rpc/transaction_fixtures.manifest.json");
        let manifest_bytes = fs::read(&manifest_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", manifest_path.display()));
        let manifest: Value = json::from_slice(&manifest_bytes)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", manifest_path.display()));
        let names = ["typed_fee_payment_gas_limit"];
        let fixtures = manifest
            .get("fixtures")
            .and_then(Value::as_array)
            .expect("norito fixture manifest fixtures array");
        for name in names {
            let matches: Vec<_> = fixtures
                .iter()
                .filter(|fixture| fixture.get("name").and_then(Value::as_str) == Some(name))
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "fixture {name} must occur exactly once in norito fixture manifest"
            );
            let fixture = matches[0];
            let signed_base64 = fixture
                .get("signed_base64")
                .and_then(Value::as_str)
                .expect("fixture signed_base64");
            let signed_bytes = BASE64
                .decode(signed_base64)
                .unwrap_or_else(|err| panic!("failed to decode {name} signed payload: {err}"));
            assert_eq!(
                BASE64.encode(&signed_bytes),
                signed_base64,
                "fixture {name} signed_base64 must be canonical"
            );
            assert_eq!(&signed_bytes[..4], b"NRT0");
            let error = decode_canonical_signed_transaction_v1(&signed_bytes)
                .expect_err("framed signed-transaction fixtures are not the V1 submission wire");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(error.reason.contains("VersionedSignedTransaction V1"));
        }
    }
    #[test]
    fn external_transfer_quantity_parser_enforces_nominal_positive_domain() {
        let quantity =
            parse_positive_transfer_quantity("1.25").expect("positive quantity must parse");
        assert_eq!(
            quantity,
            Quantity::from_str("1.25").expect("canonical quantity")
        );
        let zero = parse_positive_transfer_quantity("0").expect_err("zero must be rejected");
        assert_eq!(zero.status, napi::Status::InvalidArg);
        assert_eq!(zero.reason, "transfer quantity must be greater than zero");
        for source in ["-1", "1e3", "0.00000000000000000000000000001"] {
            let error = parse_positive_transfer_quantity(source)
                .expect_err("non-quantity input must be rejected");
            assert_eq!(error.status, napi::Status::InvalidArg);
            assert!(
                error.reason.starts_with("invalid transfer quantity:"),
                "unexpected error for {source}: {}",
                error.reason
            );
        }
    }
    fn authority_fee_payment_json() -> String {
        norito::json::to_json(&FeePaymentIntent::authority(Vec::new(), None))
            .expect("serialize authority fee payment")
    }
    fn authority_fee_payment_json_with_gas(gas_limit: u64) -> String {
        norito::json::to_json(&FeePaymentIntent::authority(
            Vec::new(),
            NonZeroU64::new(gas_limit),
        ))
        .expect("serialize authority fee payment with gas")
    }
    #[test]
    fn quoted_payload_signer_changes_only_fee_limits_and_rejects_payer_substitution() {
        let _outer = ChainDiscriminantGuard::enter(42);
        let keypair =
            KeyPair::try_from_seed(vec![0x6A; 32], Algorithm::Ed25519).expect("authority key");
        let authority = AccountId::new(keypair.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("authority address")
            .to_i105_for_discriminant(369)
            .expect("authority I105");
        let instruction: InstructionBox = Register::<Domain>::domain(Domain::new(
            DomainId::try_new("quote-flow", "universal").expect("domain id"),
        ))
        .into();
        let instruction_json = json::to_json(
            &instruction_to_json_value(&instruction).expect("instruction JSON value"),
        )
        .expect("instruction JSON");
        let network_id = test_network_id(b"quote-flow-network");
        let draft = build_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            authority_i105,
            vec![instruction_json],
            authority_fee_payment_json(),
            None,
            Some(1_700_000_000_000),
            Some(60_000),
            Some(7),
        )
        .expect("unsigned transaction draft");
        let mut expected: TransactionPayload = {
            let _selected = ChainDiscriminantGuard::enter(369);
            json::from_json(&draft.payload_json).expect("decode exact draft JSON")
        };
        let fee_asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "universal").expect("fee domain"),
            "xor".parse().expect("asset name"),
        );
        let quoted_intent = FeePaymentIntent::authority(
            vec![iroha_data_model::transaction::FeeChargeLimit::new(
                iroha_data_model::transaction::FeeChargeKind::Nexus,
                fee_asset,
                "42".parse().expect("fee quantity"),
            )],
            None,
        );
        let quoted_intent_json = json::to_json(&quoted_intent).expect("quote intent JSON");
        let (_, secret) = keypair.private_key().to_bytes();
        let result = sign_quoted_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            draft.payload_json.clone(),
            quoted_intent_json.clone(),
            Uint8Array::from(secret.clone()),
            Some("ed25519".to_owned()),
        )
        .expect("sign quoted payload");
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 42);
        let signed = decode_canonical_signed_transaction_v1(result.signed_transaction.as_ref())
            .expect("decode signed transaction");
        expected.fee_payment = quoted_intent;
        assert_eq!(signed.payload(), &expected);
        signed
            .verify_signature()
            .expect("quoted signature verifies");
        let foreign_error = sign_quoted_transaction_payload(
            test_network_id_bytes(b"foreign-quote-flow-network"),
            draft.payload_json.clone(),
            quoted_intent_json,
            Uint8Array::from(secret.clone()),
            Some("ed25519".to_owned()),
        )
        .err()
        .expect("quoted signer must reject a foreign NetworkId");
        assert!(foreign_error.reason.contains("does not match"));
        let genesis_payload = TransactionBuilder::new_genesis(
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        let genesis_error = sign_quoted_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            json::to_json(genesis_payload.payload()).expect("genesis payload JSON"),
            authority_fee_payment_json(),
            Uint8Array::from(secret.clone()),
            Some("ed25519".to_owned()),
        )
        .err()
        .expect("quoted signer must reject the genesis domain");
        assert!(genesis_error.reason.contains("genesis-domain"));
        let gas_error = sign_quoted_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            draft.payload_json.clone(),
            authority_fee_payment_json_with_gas(1),
            Uint8Array::from(secret.clone()),
            Some("ed25519".to_owned()),
        )
        .err()
        .expect("quote must not substitute the signed gas bound");
        assert!(gas_error.reason.contains("gas bound"));
        let substituted = FeePaymentIntent::sponsor(
            iroha_data_model::nexus::FeeSponsorProgramId::new(
                authority,
                "substituted".parse().expect("program name"),
            ),
            1,
            Vec::new(),
            None,
        );
        let error = sign_quoted_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            draft.payload_json,
            {
                let _selected = ChainDiscriminantGuard::enter(369);
                json::to_json(&substituted).expect("substituted intent JSON")
            },
            Uint8Array::from(secret),
            Some("ed25519".to_owned()),
        )
        .err()
        .expect("quote must not substitute the selected payer");
        assert!(error.reason.contains("changed the selected payer"));
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 42);
    }
    #[test]
    fn external_transfer_payload_builder_and_finalizer_match_native_transaction_model() {
        let _outer = ChainDiscriminantGuard::enter(42);
        let authority_key =
            KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).expect("authority key");
        let destination_key =
            KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519).expect("destination key");
        let authority = AccountId::new(authority_key.public_key().clone());
        let destination = AccountId::new(destination_key.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("authority address")
            .to_i105_for_discriminant(369)
            .expect("authority I105");
        let destination_i105 = AccountAddress::from_account_id(&destination)
            .expect("destination address")
            .to_i105_for_discriminant(369)
            .expect("destination I105");
        let definition: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("asset definition address");
        let source = {
            let _selected = ChainDiscriminantGuard::enter(369);
            AssetId::new(definition, authority.clone()).canonical_literal()
        };
        let network_id = test_network_id(b"browser-native-parity");
        let built = build_transfer_asset_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            authority_i105.clone(),
            source,
            "1.25".to_owned(),
            destination_i105,
            authority_fee_payment_json(),
            Some(r#"{"memo":"native","order":2}"#.to_owned()),
            Some(1_700_000_000_000),
            Some(5_000),
            Some(42),
        )
        .expect("build external transfer payload");
        assert!(!built.payload_bytes.is_empty());
        assert_eq!(built.payload_hash.len(), Hash::LENGTH);
        let builder = TransactionBuilder::decode_payload(built.payload_bytes.as_ref())
            .expect("native payload builder must emit canonical bytes");

        assert_eq!(builder.encode_payload(), built.payload_bytes.as_ref());
        assert_eq!(
            builder.payload_hash_bytes().as_slice(),
            built.payload_hash.as_ref()
        );
        let signature =
            Signature::try_new(authority_key.private_key(), built.payload_hash.as_ref())
                .expect("external payload signature");
        let (_, public_key_bytes) = authority_key
            .public_key()
            .try_to_bytes()
            .expect("raw Ed25519 public key");
        let finalized = finalize_signed_transaction(JsExternalTransactionSignature {
            network_id: Buffer::from(network_id.as_bytes().to_vec()),
            payload_bytes: Buffer::from(built.payload_bytes.as_ref().to_vec()),
            payload_hash_hex: Some(hex::encode(built.payload_hash.as_ref())),
            signature: Buffer::from(signature.payload().to_vec()),
            public_key: Buffer::from(public_key_bytes.to_vec()),
            authority: authority_i105,
        })
        .expect("finalize externally signed transaction");
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 42);
        let transaction =
            decode_canonical_signed_transaction_v1(finalized.signed_transaction.as_ref())
                .expect("finalized versioned transaction must decode");
        transaction
            .verify_signature()
            .expect("finalized transaction signature must verify");
        assert_eq!(transaction.authority(), &authority);
        assert_eq!(
            finalized.signed_transaction.as_ref(),
            transaction.encode_wire_v1().expect("canonical V1 wire")
        );
        assert_eq!(finalized.hash.as_ref(), transaction.hash().as_ref());
    }
    #[test]
    fn external_transfer_builder_and_finalizer_reject_adversarial_inputs() {
        let authority_key =
            KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519).expect("authority key");
        let other_key =
            KeyPair::try_from_seed(vec![0x61; 32], Algorithm::Ed25519).expect("other key");
        let authority = AccountId::new(authority_key.public_key().clone());
        let other = AccountId::new(other_key.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("authority address")
            .to_i105_for_discriminant(0x02F1)
            .expect("authority I105");
        let other_i105 = AccountAddress::from_account_id(&other)
            .expect("other address")
            .to_i105_for_discriminant(0x02F1)
            .expect("other I105");
        let wrong_network_i105 = AccountAddress::from_account_id(&other)
            .expect("other address")
            .to_i105_for_discriminant(42)
            .expect("other-network I105");
        let definition: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("asset definition address");
        let source = AssetId::new(definition.clone(), authority.clone()).canonical_literal();
        let other_source = AssetId::new(definition, other.clone()).canonical_literal();
        let network_id = test_network_id(b"browser-native-adversarial");
        assert!(
            build_transfer_asset_payload(
                Uint8Array::from(network_id.as_bytes().to_vec()),
                authority_i105.clone(),
                source.clone(),
                "1".to_owned(),
                wrong_network_i105,
                authority_fee_payment_json(),
                None,
                Some(1),
                None,
                None,
            )
            .is_err()
        );
        for invalid_quantity in [
            "-1".to_owned(),
            "1.0".to_owned(),
            "+1".to_owned(),
            "01".to_owned(),
            format!("0.{}1", "0".repeat(28)),
        ] {
            assert!(
                build_transfer_asset_payload(
                    Uint8Array::from(network_id.as_bytes().to_vec()),
                    authority_i105.clone(),
                    source.clone(),
                    invalid_quantity.clone(),
                    other_i105.clone(),
                    authority_fee_payment_json(),
                    None,
                    Some(1),
                    None,
                    None,
                )
                .is_err(),
                "external transfer must reject invalid quantity spelling {invalid_quantity:?}",
            );
        }
        assert!(
            build_transfer_asset_payload(
                Uint8Array::from(network_id.as_bytes().to_vec()),
                authority_i105.clone(),
                other_source,
                "1".to_owned(),
                other_i105.clone(),
                authority_fee_payment_json(),
                None,
                Some(1),
                None,
                None,
            )
            .is_err()
        );
        assert!(
            build_transfer_asset_payload(
                Uint8Array::from(network_id.as_bytes().to_vec()),
                authority_i105.clone(),
                source.clone(),
                "0".to_owned(),
                other_i105.clone(),
                authority_fee_payment_json(),
                None,
                Some(1),
                None,
                None,
            )
            .is_err()
        );
        let built = build_transfer_asset_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            authority_i105.clone(),
            source,
            "1".to_owned(),
            other_i105,
            authority_fee_payment_json(),
            None,
            Some(1),
            None,
            None,
        )
        .expect("valid adversarial baseline payload");
        let signature =
            Signature::try_new(authority_key.private_key(), built.payload_hash.as_ref())
                .expect("baseline signature");
        let (_, public_key_bytes) = authority_key
            .public_key()
            .try_to_bytes()
            .expect("authority public key bytes");
        let (_, other_public_key_bytes) = other_key
            .public_key()
            .try_to_bytes()
            .expect("other public key bytes");
        let valid_input = || JsExternalTransactionSignature {
            network_id: Buffer::from(network_id.as_bytes().to_vec()),
            payload_bytes: Buffer::from(built.payload_bytes.as_ref().to_vec()),
            payload_hash_hex: Some(hex::encode(built.payload_hash.as_ref())),
            signature: Buffer::from(signature.payload().to_vec()),
            public_key: Buffer::from(public_key_bytes.to_vec()),
            authority: authority_i105.clone(),
        };
        // The retired layout carried an admission-intent field after fee payment.
        // Insert that actual extra field; an unchanged current payload is valid.
        let flags = norito::core::default_encode_flags();
        let canonical = built.payload_bytes.as_ref();
        let mut after_fee = 0;
        for _ in 0..7 {
            let (len, prefix) =
                norito::core::read_len_from_slice_with_flags(&canonical[after_fee..], flags)
                    .expect("canonical transaction field length");
            after_fee += prefix + len;
        }
        let mut retired_bytes = canonical[..after_fee].to_vec();
        norito::core::write_len_to_vec_with_flags(&mut retired_bytes, 4, flags);
        retired_bytes.extend_from_slice(&0_u32.to_le_bytes());
        retired_bytes.extend_from_slice(&canonical[after_fee..]);
        let retired_hash = Hash::new(&retired_bytes);
        let retired_signature =
            Signature::try_new(authority_key.private_key(), retired_hash.as_ref())
                .expect("sign exact retired layout");
        let mut retired = valid_input();
        retired.payload_bytes = Buffer::from(retired_bytes);
        retired.payload_hash_hex = Some(hex::encode(retired_hash.as_ref()));
        retired.signature = Buffer::from(retired_signature.payload().to_vec());
        let error = finalize_signed_transaction(retired)
            .err()
            .expect("retired transaction layout must reject");
        assert!(
            error
                .reason
                .contains("invalid canonical transaction payload")
        );
        let mut missing_authority = valid_input();
        missing_authority.authority.clear();
        assert!(finalize_signed_transaction(missing_authority).is_err());
        let mut different_authority = valid_input();
        different_authority.authority = other.to_i105_for_discriminant(0x02F1).unwrap();
        assert!(finalize_signed_transaction(different_authority).is_err());
        let mut mismatched_hash = valid_input();
        mismatched_hash.payload_hash_hex = Some("00".repeat(Hash::LENGTH));
        assert!(finalize_signed_transaction(mismatched_hash).is_err());
        let mut wrong_public_key = valid_input();
        wrong_public_key.public_key = Buffer::from(other_public_key_bytes.to_vec());
        assert!(finalize_signed_transaction(wrong_public_key).is_err());
        let mut bad_signature = valid_input();
        bad_signature.signature[0] ^= 0x80;
        assert!(finalize_signed_transaction(bad_signature).is_err());
        let mut overlong_payload = valid_input();
        let canonical = overlong_payload.payload_bytes.as_ref();
        assert!(
            canonical[0] < 0x80,
            "fixture begins with a one-byte field length"
        );
        let mut overlong = Vec::with_capacity(canonical.len() + 1);
        overlong.extend_from_slice(&[canonical[0] | 0x80, 0]);
        overlong.extend_from_slice(&canonical[1..]);
        overlong_payload.payload_bytes = Buffer::from(overlong);
        overlong_payload.payload_hash_hex = None;
        assert!(finalize_signed_transaction(overlong_payload).is_err());
        let mut foreign_network = valid_input();
        foreign_network.network_id = Buffer::from(
            test_network_id(b"foreign-browser-network")
                .as_bytes()
                .to_vec(),
        );
        let error = finalize_signed_transaction(foreign_network)
            .err()
            .expect("external finalizer must reject a foreign NetworkId");
        assert!(error.reason.contains("does not match"));
        let genesis_builder = TransactionBuilder::new_genesis(
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        let genesis_payload_hash = genesis_builder.payload_hash_bytes();
        let genesis_signature =
            Signature::try_new(authority_key.private_key(), genesis_payload_hash.as_slice())
                .expect("genesis payload signature");
        let result = finalize_signed_transaction(JsExternalTransactionSignature {
            network_id: Buffer::from(network_id.as_bytes().to_vec()),
            payload_bytes: Buffer::from(genesis_builder.encode_payload()),
            payload_hash_hex: Some(hex::encode(genesis_payload_hash)),
            signature: Buffer::from(genesis_signature.payload().to_vec()),
            public_key: Buffer::from(public_key_bytes.to_vec()),
            authority: authority_i105.clone(),
        });
        let error = result.err().expect("genesis domain must fail");
        assert!(
            error.reason.contains(
                "genesis transaction domain is restricted to explicit genesis construction"
            ),
            "ordinary payload decoding must reject the genesis domain: {}",
            error.reason
        );
        assert!(finalize_signed_transaction(valid_input()).is_ok());
    }
    #[test]
    fn signed_transaction_codec_accepts_only_exact_canonical_v1_bytes() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"versioned-transaction");
        let mut builder = TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1));
        let signed = builder.sign(keypair.private_key());
        let versioned = encode_canonical_signed_transaction_v1(&signed)
            .expect("canonical signed transaction must encode");
        let decoded = decode_canonical_signed_transaction_v1(&versioned)
            .expect("canonical V1 signed transaction must decode");
        assert_eq!(decoded, signed);
        assert_eq!(
            encode_signed_transaction_versioned(Uint8Array::from(versioned.clone()))
                .expect("public canonical V1 validator must accept exact bytes")
                .as_ref(),
            versioned.as_slice()
        );

        let bare = NoritoEncode::encode(&signed);
        let framed = norito::to_bytes(&signed).expect("framed signed transaction");
        let headerless = versioned[1..].to_vec();
        let alternate_layout = {
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _alternate_flags = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            let mut bytes = vec![1];
            norito::core::serialize_to_buffer(&signed, &mut bytes)
                .expect("alternate-layout signed transaction");
            bytes
        };
        assert_ne!(alternate_layout, versioned);
        let mut unsupported = versioned.clone();
        unsupported[0] = 2;
        let mut trailing = versioned.clone();
        trailing.push(0);
        for (label, rejected) in [
            ("bare", bare),
            ("framed", framed),
            ("headerless", headerless),
            ("alternate-layout", alternate_layout),
            ("unsupported", unsupported),
            ("trailing", trailing),
        ] {
            let error = decode_canonical_signed_transaction_v1(&rejected)
                .expect_err("noncanonical signed transaction must fail closed");
            assert_eq!(error.status, napi::Status::InvalidArg, "{label}");
            let public_error = encode_signed_transaction_versioned(Uint8Array::from(rejected))
                .err()
                .expect("public canonical V1 validator must reject noncanonical bytes");
            assert_eq!(public_error.status, napi::Status::InvalidArg, "{label}");
        }
    }
    #[test]
    fn sign_js_transaction_checked_signing_verifies() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"checked-js-signing");
        let asset_definition: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset_id = AssetId::new(asset_definition, authority.clone());
        let instruction: InstructionBox =
            Mint::asset_quantity("10".parse::<Quantity>().expect("valid quantity"), asset_id)
                .into();
        let tx = sign_js_transaction(
            TransactionBuilder::new(
                network_id,
                authority.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([instruction]),
            keypair.private_key(),
            "test",
        )
        .expect("checked signing should succeed");
        assert_eq!(tx.authority(), &authority);
        tx.verify_signature()
            .expect("checked signed JS transaction should verify");
    }
    #[test]
    fn sign_transaction_preserves_exact_fee_payment_intent() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"fee-intent-preservation");
        let fee_asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "universal").expect("fee domain"),
            "xor".parse().expect("fee asset name"),
        );
        let intent = FeePaymentIntent::authority(
            vec![iroha_data_model::transaction::FeeChargeLimit::new(
                iroha_data_model::transaction::FeeChargeKind::Nexus,
                fee_asset,
                Quantity::from(42_u32),
            )],
            NonZeroU64::new(9_000),
        );
        let mut builder = TransactionBuilder::new(network_id, authority, intent.clone());
        builder.set_creation_time(Duration::from_millis(1));
        let original = builder.sign(keypair.private_key());
        let (_, secret) = keypair.private_key().to_bytes();
        let resigned = sign_transaction(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            Uint8Array::from(
                encode_canonical_signed_transaction_v1(&original)
                    .expect("canonical original transaction"),
            ),
            Uint8Array::from(secret),
        )
        .expect("re-sign transaction");
        let decoded = decode_canonical_signed_transaction_v1(resigned.as_ref())
            .expect("decode re-signed transaction");
        assert_eq!(decoded.fee_payment_intent(), &intent);
        decoded
            .verify_signature()
            .expect("re-signed transaction verifies");
    }
    #[test]
    fn sign_transaction_rejects_foreign_and_genesis_domains() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"sign-transaction-network");
        let foreign = TransactionBuilder::new(
            test_network_id(b"foreign-sign-transaction-network"),
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .sign(keypair.private_key());
        let transaction = TransactionBuilder::new_genesis(
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .sign(keypair.private_key());
        let (_, secret) = keypair.private_key().to_bytes();
        let foreign_error = sign_transaction(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            Uint8Array::from(
                encode_canonical_signed_transaction_v1(&foreign)
                    .expect("canonical foreign transaction"),
            ),
            Uint8Array::from(secret.clone()),
        )
        .err()
        .expect("JavaScript host must reject a foreign NetworkId");
        assert_eq!(foreign_error.status, napi::Status::InvalidArg);
        assert!(foreign_error.reason.contains("does not match"));
        let error = sign_transaction(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            Uint8Array::from(
                encode_canonical_signed_transaction_v1(&transaction)
                    .expect("canonical genesis transaction"),
            ),
            Uint8Array::from(secret),
        )
        .err()
        .expect("JavaScript host must reject the genesis transaction domain");
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert_eq!(
            error.reason,
            "JavaScript transaction re-signer cannot accept a genesis-domain transaction"
        );
    }
    #[test]
    fn smart_contract_bytes_instruction_json_roundtrip() {
        let code_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let instruction: InstructionBox = Box::new(RegisterSmartContractBytes {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                DataSpaceId::new(u64::MAX),
                Hash::prehashed(sample_hash(0xCC)),
            ),
            code: code_bytes.clone(),
        })
        .into_instruction_box();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize RegisterSmartContractBytes instruction");
        let payload = json_value
            .as_object()
            .and_then(|map| map.get("RegisterSmartContractBytes"))
            .and_then(|value| value.as_object())
            .expect("bytes payload present");
        let artifact = payload
            .get("artifact_id")
            .and_then(json::Value::as_object)
            .expect("exact artifact scope present");
        assert_eq!(
            artifact.get("code_hash"),
            Some(&json::Value::String(hash_literal(0xCC))),
        );
        assert_eq!(
            artifact.get("dataspace_id"),
            Some(&json::Value::String(u64::MAX.to_string())),
        );
        assert!(payload.get("code_hash").is_none());
        assert_eq!(
            payload.get("code"),
            Some(&json::Value::String(STANDARD.encode(&code_bytes))),
        );
        let reconstructed = value_to_instruction(json_value.clone())
            .expect("deserialize RegisterSmartContractBytes");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn activate_contract_instance_instruction_json_roundtrip() {
        let authority = AccountId::new(KeyPair::random().public_key().clone());
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &test_network_id(b"activate-contract-instance"),
            &authority,
            1,
            iroha_model_base::topology::DataSpaceId::new(0),
        )
        .expect("contract address");
        let instruction: InstructionBox = Box::new(ActivateContractInstance {
            contract_address,
            expected_revision: 7,
            code_hash: Hash::prehashed(sample_hash(0x44)),
        })
        .into_instruction_box();
        let json_value = instruction_to_json_value(&instruction)
            .expect("serialize ActivateContractInstance instruction");
        let payload = json_value
            .as_object()
            .and_then(|map| map.get("ActivateContractInstance"))
            .and_then(json::Value::as_object)
            .expect("activation JSON payload");
        assert_eq!(
            payload.get("expected_revision"),
            Some(&json::Value::String("7".to_owned()))
        );
        let reconstructed =
            value_to_instruction(json_value.clone()).expect("deserialize ActivateContractInstance");
        assert_eq!(reconstructed, instruction);
    }
    #[test]
    fn contract_lifecycle_instruction_json_requires_expected_revision() {
        let authority = AccountId::new(KeyPair::random().public_key().clone());
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &test_network_id(b"contract-lifecycle-cas"),
            &authority,
            1,
            iroha_model_base::topology::DataSpaceId::new(0),
        )
        .expect("contract address");
        for value in [
            norito_json!({
                "ActivateContractInstance": norito_json!({
                    "contract_address": contract_address.to_string(),
                    "code_hash": hash_literal(0x45),
                }),
            }),
            norito_json!({
                "DeactivateContractInstance": norito_json!({
                    "contract_address": contract_address.to_string(),
                    "reason": Value::Null,
                }),
            }),
        ] {
            let error = value_to_instruction(value)
                .expect_err("lifecycle CAS revision must not be inferred by the host");
            assert!(error.to_string().contains("expected_revision"));
        }
    }
    #[test]
    fn js_builder_create_kaigi_payload_matches() {
        // Mirrors the payload assembled by the JavaScript builders/tests.
        let host = account_json_literal(&sample_account("wonderland"));
        let billing_account = account_json_literal(&sample_account("wonderland"));
        let relay_id = account_json_literal(&sample_account("wonderland"));
        let payload = norito_json!({
            "Kaigi": norito_json!({
                "CreateKaigi": norito_json!({
                    "call": norito_json!({
                        "id": norito_json!({
                            "domain_id": "wonderland.sora",
                            "call_name": "weekly-sync"
                        }),
                        "host": host,
                        "title": "Weekly Sync",
                        "description": "Roadmap alignment",
                        "max_participants": 16,
                        "gas_rate_per_minute": 120,
                        "metadata": norito_json!({
                            "topic": "status"
                        }),
                        "scheduled_start_ms": 1_700_000_000_000_u64,
                        "billing_account": billing_account,
                        "privacy_mode": norito_json!({
                            "mode": "ZkRosterV1",
                            "state": json::Value::Null
                        }),
                        "room_policy": norito_json!({
                            "policy": "Authenticated",
                            "state": json::Value::Null
                        }),
                        "relay_manifest": norito_json!({
                            "hops": vec![norito_json!({
                                "relay_id": relay_id,
                                "hpke_public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                                "weight": 5
                            })],
                            "expiry_ms": 1_700_111_000_000_u64
                        })
                    })
                })
            })
        });
        let json_payload = json::to_json(&payload).expect("serialize payload to json");
        let value: json::Value =
            norito::json::from_json(&json_payload).expect("parse builder json into Value");
        if let Some(host) = value
            .get("Kaigi")
            .and_then(|v| v.get("CreateKaigi"))
            .and_then(|v| v.get("call"))
            .and_then(|v| v.get("host"))
            .and_then(|v| v.as_str())
        {
            AccountId::parse_encoded(host).expect("host account id");
        }
        if let Some(billing) = value
            .get("Kaigi")
            .and_then(|v| v.get("CreateKaigi"))
            .and_then(|v| v.get("call"))
            .and_then(|v| v.get("billing_account"))
            .and_then(|v| v.as_str())
        {
            AccountId::parse_encoded(billing).expect("billing account id");
        }
        if let Some(relay_id) = value
            .get("Kaigi")
            .and_then(|v| v.get("CreateKaigi"))
            .and_then(|v| v.get("call"))
            .and_then(|v| v.get("relay_manifest"))
            .and_then(|v| v.get("hops"))
            .and_then(|v| v.get(0))
            .and_then(|v| v.get("relay_id"))
            .and_then(|v| v.as_str())
        {
            AccountId::parse_encoded(relay_id).expect("relay account id");
        }
        instruction_from_json(&json_payload).expect("JS builder payload must be parsable");
    }
    #[test]
    fn decode_signed_contract_call_json_exposes_expected_code_hash() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"js-contract-call");
        let expected_code_hash = Hash::new(b"js-decoder-contract-code");
        let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
            &network_id,
            &authority,
            3,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let transaction = TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(Executable::ContractCall(
            iroha_data_model::transaction::executable::ContractInvocation {
                contract_address,
                expected_code_hash,
                entrypoint: "run".to_owned(),
                arguments: None,
            },
        ))
        .sign(keypair.private_key());
        let bytes = encode_canonical_signed_transaction_v1(&transaction)
            .expect("encode canonical signed transaction V1");
        let decoded = decode_signed_transaction_json(Uint8Array::from(bytes), 369.0)
            .expect("decode signed transaction JSON");
        let value: json::Value = json::from_str(&decoded).expect("parse decoder JSON");
        let expected_code_hash_literal =
            json::to_value(&expected_code_hash).expect("serialize expected code hash");
        assert_eq!(
            value
                .get("payload")
                .and_then(|payload| payload.get("instructions"))
                .and_then(|instructions| instructions.get("ContractCall"))
                .and_then(|call| call.get("expected_code_hash"))
                .and_then(json::Value::as_str),
            expected_code_hash_literal.as_str()
        );
    }
    #[test]
    fn build_transaction_from_instructions_json_roundtrip() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let network_id = test_network_id(b"instruction-json-roundtrip");
        let authority = AccountId::new(keypair.public_key().clone());
        let asset_definition: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
        let asset_id = AssetId::new(asset_definition, authority.clone());
        let instruction_box: InstructionBox = Mint::asset_quantity(
            Quantity::from_str("10").expect("valid quantity"),
            asset_id.clone(),
        )
        .into();
        let instruction_json = json::to_json(&instruction_to_json_value(&instruction_box).unwrap())
            .expect("instruction json");
        let (_, secret_bytes) = keypair.private_key().to_bytes();
        let result = build_transaction_from_instructions_json(
            network_id,
            authority.clone(),
            vec![instruction_json],
            authority_fee_payment_json(),
            None,
            Some(1_700_000_000_000),
            Some(5_000),
            Some(42),
            &secret_bytes,
            None,
        )
        .expect("transaction built");
        let tx = decode_canonical_signed_transaction_v1(result.signed_transaction.as_ref())
            .expect("decode");
        assert_eq!(tx.authority(), &authority);
        assert_eq!(tx.network_id(), Some(&network_id));
        tx.verify_signature()
            .expect("assembled transaction signature should verify");
        match tx.instructions() {
            Executable::Instructions(batch) => {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch.iter().next().unwrap(), &instruction_box);
            }
            other => panic!("expected instruction batch, got {other:?}"),
        }
        assert_eq!(
            result.hash.as_ref(),
            tx.hash().as_ref(),
            "hash must match signed transaction hash"
        );
    }
    #[test]
    fn build_executable_batch_transaction_preserves_mixed_order_and_tag() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"mixed-batch-network");
        let contract_address =
            ContractAddress::derive(&network_id, &authority, 9, DataSpaceId::UNIVERSAL)
                .expect("contract address");
        let expected_code_hash = Hash::new(b"js-host-mixed-batch-code");
        let instruction: InstructionBox = Register::<Domain>::domain(Domain::new(
            DomainId::try_new("mixed-batch", "universal").expect("domain id"),
        ))
        .into();
        let instruction_value =
            instruction_to_json_value(&instruction).expect("instruction JSON value");
        let instruction_entry = json::to_json(&norito_json!({
            "kind": "instruction",
            "instruction": instruction_value
        }))
        .expect("instruction entry JSON");
        let call_entry = json::to_json(&norito_json!({
            "kind": "contractCall",
            "contractAddress": contract_address.to_string(),
            "expectedCodeHash": hex::encode_upper(expected_code_hash.as_ref()),
            "entrypoint": "run",
            "arguments": vec![0x4b_u8, 0x4f, 0x54, 0x4f]
        }))
        .expect("contract-call entry JSON");
        let (_, secret) = keypair.private_key().to_bytes();
        let result = build_executable_batch_transaction(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            account_json_literal(&authority),
            vec![instruction_entry.clone(), call_entry, instruction_entry],
            authority_fee_payment_json_with_gas(10_000),
            None,
            Some(1_700_000_000_000),
            Some(5_000),
            Some(42),
            Uint8Array::from(secret),
            Some("ed25519".to_owned()),
        )
        .expect("mixed batch transaction");
        let tx = decode_canonical_signed_transaction_v1(result.signed_transaction.as_ref())
            .expect("decode");
        assert_eq!(&tx.instructions().encode()[..4], &4_u32.to_le_bytes());
        let Executable::Batch(entries) = tx.instructions() else {
            panic!("expected batch executable")
        };
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0], ExecutableBatchItem::Instruction(_)));
        let ExecutableBatchItem::ContractCall(invocation) = &entries[1] else {
            panic!("expected contract call in the middle")
        };
        assert_eq!(invocation.contract_address, contract_address);
        assert_eq!(invocation.expected_code_hash, expected_code_hash);
        assert_eq!(invocation.entrypoint, "run");
        assert_eq!(
            invocation.arguments.as_deref(),
            Some(&[0x4b, 0x4f, 0x54, 0x4f][..])
        );
        assert!(matches!(entries[2], ExecutableBatchItem::Instruction(_)));
    }
    #[test]
    fn executable_batch_parser_requires_gas_for_contract_calls() {
        let fee_payment = FeePaymentIntent::authority(Vec::new(), None);
        let error = checked_batch_executable(
            vec![ExecutableBatchItem::ContractCall(ContractInvocation {
                contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                    .parse()
                    .expect("contract address"),
                expected_code_hash: Hash::new(b"js-host-missing-gas"),
                entrypoint: "run".to_owned(),
                arguments: None,
            })],
            &fee_payment,
        )
        .expect_err("contract call requires gas");
        assert!(error.reason.contains("gas limit is required"));
    }
    #[test]
    fn build_ivm_proved_transaction_roundtrip() {
        let _outer = ChainDiscriminantGuard::enter(42);
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let network_id = test_network_id(b"ivm-proved-roundtrip");
        let authority = AccountId::new(keypair.public_key().clone());
        let proved = IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![0x4e, 0x52, 0x54, 0x30]),
            overlay: Vec::<InstructionBox>::new().into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas-policy"),
        };
        let attachment = ProofAttachment::new_ref(
            "pipa-r/pasta".parse().expect("backend ident"),
            ProofBox::new(
                "pipa-r/pasta".parse().expect("proof backend ident"),
                vec![0xAA, 0xBB, 0xCC],
            ),
            VerifyingKeyId::new("pipa-r/pasta", "ivm-exec-v1"),
        );
        let proved_json = json::to_json(&proved).expect("proved json");
        let attachment_json = json::to_json(&attachment).expect("attachment json");
        let (_, secret_bytes) = keypair.private_key().to_bytes();
        let draft = build_ivm_proved_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            authority.to_i105_for_discriminant(369).unwrap(),
            proved_json.clone(),
            attachment_json.clone(),
            authority_fee_payment_json_with_gas(1_000),
            None,
            Some(1_700_000_000_000),
            Some(5_000),
            Some(42),
        )
        .expect("unsigned transaction built");
        let draft_payload: TransactionPayload = {
            let _selected = ChainDiscriminantGuard::enter(369);
            json::from_json(&draft.payload_json).expect("decode unsigned payload")
        };
        assert_eq!(draft.payload_bytes.as_ref(), draft_payload.encode());
        assert_eq!(
            draft.payload_hash.as_ref(),
            TransactionBuilder::from_payload(draft_payload.clone())
                .expect("valid payload")
                .payload_hash_bytes()
        );
        assert_eq!(
            draft_payload.instructions,
            Executable::IvmProved(proved.clone())
        );
        let quoted = FeePaymentIntent::authority(
            vec![iroha_data_model::transaction::FeeChargeLimit::new(
                iroha_data_model::transaction::FeeChargeKind::PipelineGas,
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("fees", "universal").expect("fee domain"),
                    "xor".parse().expect("asset name"),
                ),
                "5".parse().expect("fee amount"),
            )],
            NonZeroU64::new(1_000),
        );
        let foreign_error = sign_quoted_ivm_proved_transaction_payload(
            test_network_id_bytes(b"foreign-ivm-proved-network"),
            draft.payload_json.clone(),
            attachment_json.clone(),
            json::to_json(&quoted).expect("quote json"),
            Uint8Array::from(secret_bytes.clone()),
            None,
        )
        .err()
        .expect("proved-IVM signer must reject a foreign NetworkId");
        assert!(foreign_error.reason.contains("does not match"));
        let mut genesis_payload = draft_payload.clone();
        genesis_payload.domain = iroha_data_model::transaction::TransactionDomain::Genesis;
        let genesis_error = sign_quoted_ivm_proved_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            json::to_json(&genesis_payload).expect("genesis proved-IVM payload JSON"),
            attachment_json.clone(),
            json::to_json(&quoted).expect("quote json"),
            Uint8Array::from(secret_bytes.clone()),
            None,
        )
        .err()
        .expect("proved-IVM signer must reject the genesis domain");
        assert!(genesis_error.reason.contains("genesis-domain"));
        let quoted_result = sign_quoted_ivm_proved_transaction_payload(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            draft.payload_json,
            attachment_json.clone(),
            json::to_json(&quoted).expect("quote json"),
            Uint8Array::from(secret_bytes.clone()),
            None,
        )
        .expect("quoted transaction signed");
        assert_eq!(iroha_data_model::account::address::chain_discriminant(), 42);
        let quoted_tx =
            decode_canonical_signed_transaction_v1(quoted_result.signed_transaction.as_ref())
                .expect("decode");
        assert_eq!(quoted_tx.fee_payment_intent(), &quoted);
        assert_eq!(
            quoted_tx.proof_attachments_v1().expect("execution carrier"),
            vec![attachment.clone()]
        );
        assert_eq!(
            quoted_tx.attachments().expect("attachments").actions()[0].operation,
            iroha_data_model::transaction::ActionOperationV1::IvmProvedExecution
        );
        quoted_tx
            .validate_signed_attachments_v1()
            .expect("statements are bound to the quoted payload");
        quoted_tx
            .verify_signature()
            .expect("quoted transaction signature verifies");
        let result = build_ivm_proved_transaction(
            Uint8Array::from(network_id.as_bytes().to_vec()),
            account_json_literal(&authority),
            proved_json,
            attachment_json,
            authority_fee_payment_json_with_gas(1_000),
            None,
            Some(1_700_000_000_000),
            Some(5_000),
            Some(42),
            Uint8Array::from(secret_bytes.to_vec()),
            None,
        )
        .expect("transaction built");
        let tx = decode_canonical_signed_transaction_v1(result.signed_transaction.as_ref())
            .expect("decode");
        assert_eq!(tx.authority(), &authority);
        assert_eq!(tx.network_id(), Some(&network_id));
        match tx.instructions() {
            Executable::IvmProved(decoded) => {
                assert_eq!(decoded, &proved);
            }
            other => panic!("expected IvmProved executable, got {other:?}"),
        }
        assert_eq!(
            tx.proof_attachments_v1().expect("execution carrier"),
            vec![attachment]
        );
        assert_eq!(
            result.hash.as_ref(),
            tx.hash().as_ref(),
            "hash must match signed transaction hash"
        );
    }
    #[test]
    fn parse_account_id_accepts_taira_i105_literals() {
        let _chain_guard = ChainDiscriminantGuard::enter(369);
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("account address")
            .to_i105_for_discriminant(369)
            .expect("taira i105");
        let parsed = parse_account_id(&authority_i105, "authority account id")
            .expect("parse Taira I105 account id");
        assert_eq!(parsed, authority);
    }
    #[test]
    fn i105_discriminant_hint_decodes_valid_literals_only() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("account address")
            .to_i105_for_discriminant(42)
            .expect("custom i105");
        assert_eq!(i105_discriminant_hint(&authority_i105), Some(42));
        assert_eq!(
            i105_discriminant_hint(&authority_i105.replacen("n42", "n00042", 1)),
            None
        );
        let mut chars = authority_i105.chars().collect::<Vec<_>>();
        let last = chars.len().saturating_sub(1);
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let tampered = chars.into_iter().collect::<String>();
        assert_eq!(i105_discriminant_hint(&tampered), None);
        assert_eq!(i105_discriminant_hint("n"), None);
        assert_eq!(i105_discriminant_hint("nabc"), None);
        assert_eq!(i105_discriminant_hint("n65536payload"), None);
    }
    #[test]
    fn account_address_parse_encoded_reports_embedded_numeric_prefix() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("account address")
            .to_i105_for_discriminant(42)
            .expect("custom i105");
        let inferred = account_address_parse_encoded(authority_i105.clone(), None)
            .expect("parse custom I105 address");
        assert_eq!(inferred.network_prefix, Some(42));
        let explicit =
            account_address_parse_encoded(authority_i105, Some(42)).expect("parse explicit I105");
        assert_eq!(explicit.network_prefix, Some(42));
    }
    #[test]
    fn parse_account_id_accepts_numeric_custom_i105_literals() {
        let _chain_guard = ChainDiscriminantGuard::enter(42);
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("account address")
            .to_i105_for_discriminant(42)
            .expect("custom i105");
        assert!(
            authority_i105.starts_with("n42"),
            "custom I105 account must use the numeric sentinel"
        );
        let parsed = parse_account_id(&authority_i105, "authority account id")
            .expect("parse custom I105 account id");
        assert_eq!(parsed, authority);
    }
    #[test]
    fn parse_account_id_rejects_noncanonical_and_tampered_numeric_custom_i105_literals() {
        let _chain_guard = ChainDiscriminantGuard::enter(42);
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let authority_i105 = AccountAddress::from_account_id(&authority)
            .expect("account address")
            .to_i105_for_discriminant(42)
            .expect("custom i105");
        let noncanonical = authority_i105.replacen("n42", "n00042", 1);
        assert!(
            parse_account_id(&noncanonical, "authority account id").is_err(),
            "noncanonical numeric sentinel must be rejected"
        );
        let mut chars = authority_i105.chars().collect::<Vec<_>>();
        let last = chars.len().saturating_sub(1);
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let tampered = chars.into_iter().collect::<String>();
        assert!(
            parse_account_id(&tampered, "authority account id").is_err(),
            "payload/checksum tampering must be rejected"
        );
    }
    #[test]
    fn decode_transaction_receipt_json_roundtrip() {
        let key_pair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let payload = TransactionSubmissionReceiptPayload {
            entrypoint_hash: HashOf::from_untyped_unchecked(Hash::prehashed([0xA5; 32])),
            signed_transaction_hash: None,
            submitted_at_ms: 42,
            submitted_at_height: 7,
            signer: key_pair.public_key().clone(),
        };
        let receipt = TransactionSubmissionReceipt::sign(payload, &key_pair);
        let bytes = to_bytes(&receipt).expect("encode receipt");
        let decoded = sorafs_orderbook_submission::decode_transaction_receipt_json(bytes.into())
            .expect("decode receipt into json");
        let expected = json::to_json(&receipt).expect("serialize receipt json");
        assert_eq!(decoded, expected);
    }
    #[test]
    fn build_transaction_with_empty_instructions_fails() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority = AccountId::new(keypair.public_key().clone());
        let network_id = test_network_id(b"empty-instructions");
        let (_, secret_bytes) = keypair.private_key().to_bytes();
        let result = build_transaction_from_instructions_json(
            network_id,
            authority,
            Vec::new(),
            authority_fee_payment_json(),
            None,
            None,
            None,
            None,
            &secret_bytes,
            None,
        );
        assert!(result.is_err());
    }
    #[test]
    fn instruction_batch_hash_binds_every_authorized_instruction() {
        let first = hash_instruction_batch(
            vec![
            "{\"Mint\":{\"TriggerRepetitions\":{\"object\":1,\"destination\":\"demo::trigger\"}}}"
                .to_owned(),
        ],
            369.0,
        )
        .expect("hash first instruction batch");
        let second = hash_instruction_batch(
            vec![
            "{\"Mint\":{\"TriggerRepetitions\":{\"object\":2,\"destination\":\"demo::trigger\"}}}"
                .to_owned(),
        ],
            369.0,
        )
        .expect("hash second instruction batch");
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert_ne!(first.as_ref(), second.as_ref());
    }
    #[test]
    fn cancel_asset_lock_json_uses_exact_compare_and_cancel_shape() {
        let cancel = CancelAssetLock::new(
            EscrowId::new(Hash::new(b"js-host-cancel-asset-lock")),
            Quantity::from(15_u32),
        );
        let input = norito_json!({
            "CancelAssetLock": json::to_value(&cancel).expect("cancel JSON")
        });
        let instruction = value_to_instruction(input.clone()).expect("parse CancelAssetLock");
        assert_eq!(
            instruction
                .as_any()
                .downcast_ref::<CancelAssetLock>()
                .expect("typed CancelAssetLock"),
            &cancel
        );
        assert_eq!(
            instruction_to_json_value(&instruction).expect("render CancelAssetLock"),
            input
        );
        let bytes = norito::to_bytes(&InstructionBox::from(cancel))
            .expect("encode CancelAssetLock instruction");
        let decoded =
            decode_instruction_aligned(&bytes).expect("decode CancelAssetLock instruction");
        assert!(
            decoded.as_any().downcast_ref::<CancelAssetLock>().is_some(),
            "native decoder must preserve the typed CancelAssetLock"
        );
    }
    #[test]
    fn cancel_asset_lock_json_rejects_legacy_zero_and_noncanonical_inputs() {
        let cancel = CancelAssetLock::new(
            EscrowId::new(Hash::new(b"js-host-cancel-asset-lock-strict")),
            Quantity::from(15_u32),
        );
        let canonical_payload = json::to_value(&cancel).expect("cancel JSON");
        for missing in ["escrow_id", "expected_remaining_amount"] {
            let mut payload = canonical_payload.clone();
            payload
                .as_object_mut()
                .expect("cancel payload object")
                .remove(missing);
            let error = value_to_instruction(norito_json!({
                "CancelAssetLock": payload
            }))
            .expect_err("missing CancelAssetLock field must be rejected");
            assert!(
                error.reason.contains("missing field"),
                "unexpected missing-{missing} error: {}",
                error.reason
            );
        }
        for amount in [
            json::Value::String("0".to_owned()),
            json::Value::String("-1".to_owned()),
            json::Value::String("01".to_owned()),
            json::Value::String("1.0".to_owned()),
            json::Value::Number(json::Number::from(1_u64)),
        ] {
            let mut payload = canonical_payload.clone();
            payload
                .as_object_mut()
                .expect("cancel payload object")
                .insert("expected_remaining_amount".to_owned(), amount);
            value_to_instruction(norito_json!({
                "CancelAssetLock": payload
            }))
            .expect_err("invalid CancelAssetLock quantity must be rejected");
        }
        let mut payload = canonical_payload.clone();
        payload
            .as_object_mut()
            .expect("cancel payload object")
            .insert("compatibility".to_owned(), json::Value::Bool(true));
        let error = value_to_instruction(norito_json!({
            "CancelAssetLock": payload
        }))
        .expect_err("CancelAssetLock must reject compatibility fields");
        assert!(error.reason.contains("unexpected field"));
        let canonical_escrow = canonical_payload
            .as_object()
            .and_then(|payload| payload.get("escrow_id"))
            .and_then(json::Value::as_str)
            .expect("canonical CancelAssetLock escrow id")
            .to_owned();
        let bare_escrow = canonical_escrow
            .strip_prefix("hash:")
            .and_then(|literal| literal.split_once('#'))
            .map(|(body, _)| body.to_owned())
            .expect("canonical hash literal");
        for escrow_id in [bare_escrow, canonical_escrow.to_lowercase()] {
            let mut payload = canonical_payload.clone();
            payload
                .as_object_mut()
                .expect("cancel payload object")
                .insert("escrow_id".to_owned(), json::Value::String(escrow_id));
            let error = value_to_instruction(norito_json!({
                "CancelAssetLock": payload
            }))
            .expect_err("noncanonical CancelAssetLock escrow id must be rejected");
            assert!(
                error
                    .reason
                    .contains("canonical uppercase checksummed hash literal"),
                "unexpected noncanonical escrow-id error: {}",
                error.reason
            );
        }
        let error = value_to_instruction(norito_json!({
            "CancelAssetLock": canonical_payload,
            "compatibility": true
        }))
        .expect_err("CancelAssetLock envelope must contain one instruction");
        assert!(error.reason.contains("envelope contains unexpected field"));
        let zero: InstructionBox = CancelAssetLock::new(
            EscrowId::new(Hash::new(b"js-host-zero-cancel-asset-lock")),
            Quantity::from(0_u32),
        )
        .into();
        let error = instruction_to_json_value(&zero)
            .expect_err("native renderer must reject a zero precondition");
        assert!(error.reason.contains("must be positive"));
    }
    #[test]
    fn settlement_instruction_json_is_explicit_and_canonical() {
        let request_hash = Hash::new(b"js-host-fx-oracle-request");
        let oracle_event = iroha_data_model::oracle::FeedEvent {
            feed_id: "aed_pkr_rate".parse().expect("feed id"),
            feed_config_version: iroha_data_model::oracle::FeedConfigVersion(1),
            slot: 7,
            request_hash,
            outcome: iroha_data_model::oracle::FeedEventOutcome::Success(
                iroha_data_model::oracle::FeedSuccess {
                    value: iroha_data_model::oracle::ObservationValue::new(76, 0),
                    entries: Vec::new(),
                },
            ),
        };
        let settle = SettleFxCorridor {
            policy_id: "aed_pkr".parse().expect("policy name"),
            expected_policy_revision: 3,
            source_asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("cbuae", "universal").expect("source asset domain"),
                "aed".parse().expect("source asset name"),
            ),
            destination_asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("sbp", "universal").expect("destination asset domain"),
                "pkr".parse().expect("destination asset name"),
            ),
            settlement_id: iroha_data_model::isi::SettlementId::new(
                sample_account("payer"),
                "fx_1".parse().expect("settlement reference"),
            ),
            recipient: AccountId::new(
                KeyPair::random_with_algorithm(Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ),
            source_amount: Quantity::from(5_u32),
            expected_destination_amount: Quantity::from(380_u32),
            oracle_evidence: FxCorridorOracleEvidence {
                feed_id: oracle_event.feed_id.clone(),
                feed_config_version: oracle_event.feed_config_version,
                slot: oracle_event.slot,
                request_hash: oracle_event.request_hash,
                event_hash: HashOf::new(&oracle_event),
            },
        };
        let input = norito_json!({
            "Settlement": norito_json!({
                "SettleFxCorridor": json::to_value(&settle).expect("settle JSON")
            })
        });
        let instruction = value_to_instruction(input.clone()).expect("parse settlement");
        assert!(
            instruction
                .as_any()
                .downcast_ref::<SettlementInstructionBox>()
                .is_some()
        );
        assert_eq!(
            instruction_to_json_value(&instruction).expect("render settlement"),
            input
        );
        let multiple = norito_json!({
            "Settlement": norito_json!({
                "SettleFxCorridor": json::to_value(&settle).expect("settle JSON"),
                "Dvp": Value::Object(Map::new())
            })
        });
        assert!(value_to_instruction(multiple).is_err());
        let mut invalid = json::to_value(&settle).expect("settle JSON");
        invalid
            .as_object_mut()
            .expect("settlement payload object")
            .insert("source_amount".into(), Value::String("-1".into()));
        let negative = norito_json!({
            "Settlement": norito_json!({
                "SettleFxCorridor": invalid
            })
        });
        assert!(value_to_instruction(negative).is_err());
        let mut unknown_payload = json::to_value(&settle).expect("settle JSON");
        unknown_payload
            .as_object_mut()
            .expect("settlement payload object")
            .insert("compatibility".to_owned(), Value::Bool(true));
        let unknown_field = norito_json!({
            "Settlement": norito_json!({
                "SettleFxCorridor": unknown_payload
            })
        });
        let error = value_to_instruction(unknown_field)
            .expect_err("SettleFxCorridor must reject unknown fields");
        assert!(error.reason.contains("unexpected field"));
        let mut missing_payload = json::to_value(&settle).expect("settle JSON");
        missing_payload
            .as_object_mut()
            .expect("settlement payload object")
            .remove("expected_policy_revision");
        let missing_field = norito_json!({
            "Settlement": norito_json!({
                "SettleFxCorridor": missing_payload
            })
        });
        let error = value_to_instruction(missing_field)
            .expect_err("SettleFxCorridor must reject missing fields");
        assert!(error.reason.contains("missing field"));
        let extra_envelope = norito_json!({
            "Settlement": norito_json!({
                "SettleFxCorridor": json::to_value(&settle).expect("settle JSON")
            }),
            "compatibility": true
        });
        let error = value_to_instruction(extra_envelope)
            .expect_err("Settlement must use the explicit envelope parser");
        assert!(error.reason.contains("envelope contains unexpected field"));
    }
    #[test]
    fn embedded_source_revision_reports_the_build_marker() {
        assert_eq!(
            embedded_source_revision(),
            option_env!("IROHA_GIT_COMMIT_HASH").unwrap_or("unknown")
        );
    }
    #[test]
    fn register_account_json_uses_the_explicit_strict_envelope_parser() {
        let account = NewAccount::new(AccountId::new(
            KeyPair::random_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        ));
        let account_json = json::to_value(&account).expect("serialize new account");
        let canonical = norito_json!({
            "Register": norito_json!({
                "Account": account_json.clone()
            })
        });
        value_to_instruction(canonical).expect("parse canonical account registration");
        let account_id = account_json
            .get("id")
            .cloned()
            .expect("serialized account id");
        let defaults = norito_json!({
            "Register": norito_json!({
                "Account": norito_json!({
                    "id": account_id
                })
            })
        });
        let error = value_to_instruction(defaults).expect_err("native account requires metadata");
        assert_eq!(error.status, napi::Status::InvalidArg);
        assert!(error.reason.contains("metadata"));
        let mut unknown_account_json = account_json.clone();
        unknown_account_json
            .as_object_mut()
            .expect("account JSON object")
            .insert("compatibility".to_owned(), json::Value::Bool(true));
        let unknown_field = norito_json!({
            "Register": norito_json!({
                "Account": unknown_account_json
            })
        });
        assert!(value_to_instruction(unknown_field).is_err());
        let extra_variant = norito_json!({
            "Register": norito_json!({
                "Account": account_json.clone(),
                "Compatibility": norito::json::Value::Object(norito::json::Map::new())
            })
        });
        assert!(value_to_instruction(extra_variant).is_err());
        let extra_envelope = norito_json!({
            "Register": norito_json!({
                "Account": account_json
            }),
            "SetParameter": norito::json::Value::Object(norito::json::Map::new())
        });
        let error = value_to_instruction(extra_envelope)
            .expect_err("Register envelope must reject sibling instructions");
        assert!(error.reason.contains("envelope contains unexpected field"));
        assert!(value_to_instruction(norito_json!({"Register": json::Value::Null})).is_err());
    }
    #[test]
    fn build_time_trigger_action_encodes_expected_schedule() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority_id = AccountId::new(keypair.public_key().clone());
        let encoded = build_time_trigger_action(
            account_json_literal(&authority_id),
            vec![
                "{\"Mint\":{\"TriggerRepetitions\":{\"object\":1,\"destination\":\"demo::trigger\"}}}"
                    .to_owned(),
            ],
            1_735_000_000_000i64,
            Some(60_000i64),
            Some(2),
            Some("{\"label\":\"demo\"}".to_owned()),
        )
        .expect("time trigger action");
        let bytes = STANDARD.decode(encoded).expect("base64");
        let archived = from_bytes::<Action>(&bytes).expect("decode action");
        let action = Action::try_deserialize(archived).expect("action value");
        assert_eq!(action.authority(), &authority_id);
        assert!(matches!(action.repeats(), Repeats::Exactly(2)));
        match action.filter() {
            EventFilterBox::Time(TimeEventFilter(ExecutionTime::Schedule(schedule))) => {
                assert_eq!(schedule.start_ms, 1_735_000_000_000);
                assert_eq!(schedule.period_ms, Some(60_000));
            }
            other => panic!("unexpected filter: {other:?}"),
        }
        assert!(
            action
                .metadata()
                .contains(&"label".parse().expect("label key"))
        );
    }
    #[test]
    fn build_precommit_trigger_action_encodes_filter() {
        let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
        let authority_id = AccountId::new(keypair.public_key().clone());
        let encoded = build_precommit_trigger_action(
            account_json_literal(&authority_id),
            vec![
                "{\"Mint\":{\"TriggerRepetitions\":{\"object\":1,\"destination\":\"demo::trigger\"}}}"
                    .to_owned(),
            ],
            None,
            None,
        )
        .expect("pre-commit action");
        let bytes = STANDARD.decode(encoded).expect("base64");
        let archived = from_bytes::<Action>(&bytes).expect("decode action");
        let action = Action::try_deserialize(archived).expect("action value");
        assert_eq!(action.authority(), &authority_id);
        assert!(matches!(action.repeats(), Repeats::Indefinitely));
        match action.filter() {
            EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)) => {}
            other => panic!("unexpected filter: {other:?}"),
        }
    }
    include!("sorafs_profile_and_integrity_tests.rs");
    #[test]
    fn da_proof_summary_binding_verifies_payload() {
        let fixture = build_da_manifest_fixture();
        let summary = da_generate_proof_summary(
            Buffer::from(fixture.manifest_bytes.clone()),
            Buffer::from(fixture.payload.clone()),
            Some(JsDaProofOptions {
                sample_count: Some(3),
                sample_seed: Some(JsU64(99)),
                leaf_indexes: Some(vec![0, 1]),
            }),
        )
        .expect("proof summary");
        assert_eq!(summary.blob_hash_hex, hex::encode(fixture.blob_hash));
        assert_eq!(summary.chunk_root_hex, hex::encode(fixture.chunk_root));
        assert_eq!(summary.leaf_count.0, fixture.leaf_count as u64);
        assert_eq!(summary.sample_count, 3);
        assert!(!summary.proofs.is_empty());
        assert!(summary.proofs.iter().all(|proof| proof.verified));
    }
}

/// Pure shared native construction of exact contract-multisig material.
#[napi]
pub fn build_canonical_multisig_contract_call_json(
    input: String,
    network_prefix: f64,
) -> napi::Result<String> {
    let prefix = iroha_js_codec::checked_network_prefix(network_prefix).map_err(codec_to_napi)?;
    iroha_js_codec::build_canonical_multisig_contract_call_json(&input, prefix)
        .map_err(codec_to_napi)
}

/// Derive a proposal occurrence through the canonical native model.
#[napi]
pub fn derive_multisig_proposal_id_json(input: String) -> napi::Result<String> {
    iroha_js_codec::derive_multisig_proposal_id_json(&input).map_err(codec_to_napi)
}
