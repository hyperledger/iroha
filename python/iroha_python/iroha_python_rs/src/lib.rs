//! Python bindings exposing a growing subset of the Iroha SDK surface.
#![deny(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)] // PyO3 generates historical wrappers that require this on edition 2024
mod acceleration_bn254;
mod acceleration_poseidon;
use acceleration_bn254::{bn254_add_many, bn254_mul_many, bn254_sub_many};
mod committed_transaction_verification;
mod confidential_wallet;
mod connect_key_bindings;
#[cfg(test)]
mod crypto_admission_tests;
mod identity_codec_v1;
mod privacy_capability_manifest;
pub mod privacy_native_actions;
pub mod privacy_wallet_bundle;
pub mod privacy_wallet_worker;
mod sorafs_orderbook_submission;
mod zk_vk_draft;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blake3::hash as blake3_hash;
use core::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    time::Duration,
};
use futures::executor::block_on;
use hex::encode as hex_encode;
use iroha_core_privacy::{
    privacy_engines::vega::{VegaMdlConsensusBindingV1, derive_device_authentication_digest_v1},
    privacy_profiles::{
        CompiledPrivacyProfileV1, compiled_privacy_profile_catalog_v1, compiled_privacy_profile_v1,
        validate_local_privacy_compiled_profile_catalog_archive_v1,
    },
};
use iroha_crypto::{
    Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair, LaneCommitmentId, PrivateKey, PublicKey,
    Signature, derive_keyset_from_slice, ed25519_parse_signature,
    error::ParseError,
    mldsa65_parse_signature,
    sm::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature, encode_sm2_public_key_payload},
};
use iroha_data_model::{
    NetworkId,
    account::{Account, address::AccountAddress},
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasFramedInstructionV1,
        AliasIntentV1, AliasLeaseAcquisitionV1, AliasPlanAnchorV1, AliasPlanDispositionV1,
        AliasPlanResourceV1, AliasQuoteGuardV1,
    },
    asset::{
        AssetBalanceScope, AssetTransferAvailability, AssetTransferControlWindow,
        AssetTransferLimit,
        alias::AssetDefinitionAlias,
        definition::{AssetBalancePolicy, validate_asset_name},
        prelude::{AssetDefinition, AssetDefinitionId, AssetId, Mintable},
    },
    block::{BlockHeader, SignedBlock, decode_framed_signed_block},
    domain::prelude::Domain,
    escrow::{
        AssetEscrowRecord, ConditionalEscrowCondition, ConditionalEscrowValue, EscrowId,
        hash_conditional_escrow_evidence_digest,
    },
    events::{
        data::prelude::{
            AssetBatchTransferLegStatus, AssetBatchTransferOutcome, AssetBatchTransferRejectionCode,
        },
        time::{ExecutionTime, Schedule as TimeSchedule, TimeEventFilter},
    },
    executor::ValidationFail,
    isi::{
        BatchMode, Burn, ExecuteTrigger, Grant, InstructionBox, Mint, Register, RemoveKeyValue,
        Revoke, SetAssetHoldingLimit, SetAssetTransferAvailability, SetAssetTransferBlacklist,
        SetAssetTransferControl, SetKeyValue, SetParameter, Transfer, TransferAssetBatch,
        TransferAssetBatchEntry, Unregister,
        error::{AssetTransferAdmissionError, InstructionExecutionError, MathError},
        escrow::{
            AttestEscrowCondition, CancelAssetLock, DrawdownAssetLock, ExpireAssetLock,
            ExpireConditionalEscrow, OpenAssetLock, OpenConditionalEscrow,
        },
        governance::UpdatePlainConviction,
        repo::{RepoIsi, RepoMarginCallIsi, ReverseRepoIsi},
        settlement::{
            DvpIsi, PvpIsi, SettlementAtomicity, SettlementExecutionOrder, SettlementId,
            SettlementLeg, SettlementPlan,
        },
        smart_contract_code::CommitContractDeployment,
        sorafs::{CompleteReplicationOrder, ExpireReplicationOrder, IssueReplicationOrder},
        zk::{RegisterZkAsset, VerifyProof},
    },
    musubi::ArchiveId,
    nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, FeeSponsorProgram, FeeSponsorProgramId,
        FeeSponsorProgramRevision, LANE_PRIVACY_MAX_MERKLE_DEPTH_V1, LaneLifecycleParameterV1,
        LaneLifecyclePlan, LaneLifecycleStatusV1, LanePrivacyProof,
    },
    nft::NftId,
    parameter::Parameter,
    permission::Permission,
    prelude::AccountId,
    privacy::{
        IrohaZkAmsProofV1, IrohaZkAmsStatementV1, IrohaZkX509StarkP256StatementV1,
        PRIVACY_BRIDGE_ABI_VERSION_V1, PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1,
        PrivacyChallengeV1, PrivacyCompiledProfileCatalogV1, PrivacyConsensusLimitsV1,
        PrivacyCredentialDocumentTypeV1, PrivacyIssuerIdV1, PrivacyP256PointV1,
        PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1,
        PrivacySessionTranscriptDigestV1, PrivacyStatementContextV1, PrivacyStatementV1,
        PrivacyTransactionIntentDigestV1, PrivacyVegaDeviceAuthenticationDigestV1,
        PrivacyVegaIssuerRecordDigestV1, PrivacyVegaMdlDateV1, PrivacyVegaMdlDigestAlgorithmV1,
        PrivacyVegaMdlNamespaceV1, PrivacyVegaMdlSignatureAlgorithmV1,
        PrivacyX509ExtendedKeyUsageV1, PrivacyZkAmsActionV1, VegaExistingCredentialStatementV1,
    },
    proof::{
        ProofAttachment, ProofAttachmentList, ProofBox, VerifyingKeyId,
        proof_box_max_proof_bytes_v1, verifying_key_id_field_is_portable,
    },
    query::{
        CommittedTransaction, CommittedTxFilters, QueryItemKind, QueryOutputBatchBox, QueryRequest,
        QueryResponse, QueryWithParams, SingularQueryBox,
        block::prelude::FindBlocks,
        dsl::{CompoundPredicate, SelectorTuple},
        escrow::prelude::{FindAssetEscrowById, FindAssetEscrowsByBuyer, FindAssetEscrowsBySeller},
        parameters::QueryParams,
        transaction::prelude::FindTransactions,
    },
    repo::prelude::{RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
    rwa::{NewRwa, RwaControlPolicy, RwaId, RwaParentRef},
    smart_contract::{ContractAddress, ContractAlias},
    sorafs::{
        capacity::ProviderId,
        orderbook_submission::{
            parse_sorafs_orderbook_cancel_reason_v1, parse_sorafs_orderbook_decimal_u64_v1,
            parse_sorafs_orderbook_fee_bps_v1, parse_sorafs_orderbook_payload_kind_v1,
            parse_sorafs_orderbook_side_v1, parse_sorafs_orderbook_tier_v1,
            parse_sorafs_orderbook_xor_quantity_v1, validate_sorafs_orderbook_owner_account_v1,
        },
        pin_registry::{
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId,
        },
    },
    transaction::{
        Executable, ExecutableBatchItem, FeePaymentIntent, IvmBytecode, SignedTransaction,
        TransactionBuilder as ModelTransactionBuilder, TransactionEntrypoint, TransactionPayload,
        error::TransactionRejectionReason,
        executable::{
            ContractArgumentRecord, ContractInvocation, MAX_CONTRACT_ARGUMENT_RECORD_BYTES,
        },
    },
    trigger::{
        Trigger, TriggerId,
        action::{Action as TriggerAction, Repeats},
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{
    json::Json,
    numeric::{NumericSpec, Quantity, XorQuantity},
};
use iroha_schema::Ident;
use iroha_service_model::{
    sorafs,
    soranet::{AnonymityPolicy, RolloutPhase, TransportPolicy},
};
use iroha_torii_shared::{
    connect::{
        AppMeta, ConnectCiphertextV1, ConnectControlV1, ConnectFrameV1, ConnectPayloadV1,
        Constraints, ControlAfterKeyV1, Dir, FrameKind, PermissionsV1, Role, ServerEventV1,
        SignInProofV1, WalletSignatureV1,
    },
    connect_sdk,
    private_settlement_api::{
        PrivateSettlementAuditApprovalRequestV1, PrivateSettlementAuditApprovalResponseV1,
        PrivateSettlementAuditorCapsuleRequestV1, PrivateSettlementAuditorCapsuleResponseV1,
        PrivateSettlementCommitteeProofResponseV1,
        validate_private_settlement_audit_approval_response_v1,
        validate_private_settlement_auditor_capsule_response_v1,
        validate_private_settlement_auditor_identity_v1,
        validate_private_settlement_committee_proof_response_v1,
    },
};
use iroha_version::codec::{DecodeVersioned, EncodeVersioned};
use norito::{
    codec, decode_from_bytes,
    derive::{Encode as NEnc, JsonDeserialize},
    json,
    json::JsonSerialize,
};
use pyo3::{
    Bound, FromPyObject, create_exception,
    exceptions::{PyException, PyRuntimeError, PyTypeError, PyValueError},
    prelude::*,
    types::{PyAny, PyBool, PyBytes, PyDict, PyDictMethods, PyList, PyModule, PyTuple, PyType},
    wrap_pyfunction,
};
use rand_core_06::{OsRng as OsRng06, RngCore as _};
use sha2::{Digest as _, Sha256};
use sorafs_car::{
    CarBuildPlan, CarChunk, FilePlan,
    fetch_plan::chunk_fetch_plan_from_json,
    gateway::{GatewayFetchConfig, GatewayProviderInput},
    multi_fetch::{
        AttemptError, AttemptFailure, CapabilityMismatch, ChunkResponse, ChunkVerificationError,
        FetchOptions, FetchProvider, FetchRequest, MultiSourceError, ProviderMetadata,
        ProviderScoreContext, ProviderScoreDecision, RangeCapability, ScorePolicy, StreamBudget,
        TransportHint, fetch_plan_parallel,
    },
    scoreboard::{self, Eligibility, ProviderTelemetry, ScoreboardConfig, TelemetrySnapshot},
};
use sorafs_chunker::ChunkProfile;
use sorafs_manifest::{
    FixtureBundlePayloadKindV1, FixtureBundlePayloadV1, OrderCancelReasonV1, OrderSideV1,
    OrderTierV1, OrderbookOrderCancelFieldsV1, OrderbookOrderRequestFieldsV1,
    OrderbookSettlementReceiptFieldsV1, OrderbookValidationPayloadKindV1, ValidationOutcomeV1,
    alias_cache::{
        AliasCachePolicy, AliasProofState, decode_alias_proof_untrusted_signers, unix_now_secs,
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
    DEFAULT_LOCAL_PROXY_BRIDGE_SPOOL_DIR, OrchestratorConfig, fetch_via_gateway,
    proxy::{
        LocalQuicProxyConfig, ProxyCarBridgeConfig, ProxyKaigiBridgeConfig, ProxyMode,
        ProxyNoritoBridgeConfig,
    },
};
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::runtime::Runtime;
use url::{Host, Url};
use zeroize::Zeroizing;
/// Raised when a non-Ed25519 key is passed to an Ed25519-only helper.
const ERR_EXPECTED_ED25519: &str = "expected Ed25519 key material";
const ERR_SM2_SIGNATURE_LEN: &str = "sm2 signature must be 64 bytes";
const SM2_PRIVATE_KEY_LENGTH: usize = 32;
const SM2_PUBLIC_KEY_UNCOMPRESSED_LENGTH: usize = 65;
const SM2_SIGNATURE_LENGTH: usize = Sm2Signature::LENGTH;
create_exception!(_crypto, SorafsMultiFetchError, PyException);
fn algorithm_guard(algorithm: Algorithm) -> PyResult<()> {
    if algorithm != Algorithm::Ed25519 {
        Err(PyValueError::new_err(ERR_EXPECTED_ED25519))
    } else {
        Ok(())
    }
}
fn supported_crypto_algorithms() -> Vec<Algorithm> {
    let mut algorithms = vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::MlDsa];
    algorithms.extend([
        Algorithm::Gost3410_2012_256ParamSetA,
        Algorithm::Gost3410_2012_256ParamSetB,
        Algorithm::Gost3410_2012_256ParamSetC,
        Algorithm::Gost3410_2012_512ParamSetA,
        Algorithm::Gost3410_2012_512ParamSetB,
    ]);
    algorithms.extend([Algorithm::BlsNormal, Algorithm::BlsSmall]);
    algorithms.push(Algorithm::Sm2);
    algorithms
}
fn parse_algorithm_arg(algorithm: &str) -> PyResult<Algorithm> {
    if algorithm.is_empty() {
        return Err(PyValueError::new_err(
            "algorithm must be a non-empty string",
        ));
    }
    if algorithm.trim() != algorithm {
        return Err(PyValueError::new_err(
            "algorithm must not contain surrounding whitespace",
        ));
    }
    if !algorithm
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(PyValueError::new_err(format!(
            "unsupported crypto algorithm `{algorithm}`"
        )));
    }
    let normalized = algorithm.to_ascii_lowercase();
    if let Ok(parsed) = Algorithm::from_str(&normalized) {
        return Ok(parsed);
    }
    let compact = normalized
        .chars()
        .map(|ch| match ch {
            '_' => '-',
            _ => ch,
        })
        .collect::<String>();
    let parsed = match compact.as_str() {
        "ed-25519" | "ed25519" => Some(Algorithm::Ed25519),
        "ecdsa"
        | "ecdsa-secp256k1"
        | "ecdsa-secp256k1-sha256"
        | "secp-256-k1"
        | "secp-256k1"
        | "secp256k1" => Some(Algorithm::Secp256k1),
        "ml-dsa" | "ml-dsa-65" | "mldsa" | "mldsa65" => Some(Algorithm::MlDsa),
        "gost-3410-2012-256-paramset-a" | "gost3410-2012-256-paramset-a" => {
            Some(Algorithm::Gost3410_2012_256ParamSetA)
        }
        "gost-3410-2012-256-paramset-b" | "gost3410-2012-256-paramset-b" => {
            Some(Algorithm::Gost3410_2012_256ParamSetB)
        }
        "gost-3410-2012-256-paramset-c" | "gost3410-2012-256-paramset-c" => {
            Some(Algorithm::Gost3410_2012_256ParamSetC)
        }
        "gost-3410-2012-512-paramset-a" | "gost3410-2012-512-paramset-a" => {
            Some(Algorithm::Gost3410_2012_512ParamSetA)
        }
        "gost-3410-2012-512-paramset-b" | "gost3410-2012-512-paramset-b" => {
            Some(Algorithm::Gost3410_2012_512ParamSetB)
        }
        "bls-normal" | "blsnormal" | "bls12-381-g1" | "bls12-381-normal" => {
            Some(Algorithm::BlsNormal)
        }
        "bls-small" | "blssmall" | "bls12-381-g2" | "bls12-381-small" => Some(Algorithm::BlsSmall),
        "sm2" => Some(Algorithm::Sm2),
        _ => None,
    };
    parsed
        .ok_or_else(|| PyValueError::new_err(format!("unsupported crypto algorithm `{algorithm}`")))
}
fn parse_err(kind: &str, err: ParseError) -> PyErr {
    PyValueError::new_err(format!("failed to parse {kind} key: {err}"))
}
fn parse_private_key(bytes: &[u8]) -> PyResult<PrivateKey> {
    PrivateKey::from_bytes(Algorithm::Ed25519, bytes).map_err(|err| parse_err("private", err))
}
fn parse_public_key(bytes: &[u8]) -> PyResult<PublicKey> {
    PublicKey::from_bytes(Algorithm::Ed25519, bytes).map_err(|err| parse_err("public", err))
}
fn parse_private_key_for_algorithm(algorithm: Algorithm, bytes: &[u8]) -> PyResult<PrivateKey> {
    PrivateKey::from_bytes(algorithm, bytes).map_err(|err| parse_err("private", err))
}
fn parse_public_key_for_algorithm(algorithm: Algorithm, bytes: &[u8]) -> PyResult<PublicKey> {
    PublicKey::from_bytes(algorithm, bytes).map_err(|err| parse_err("public", err))
}
fn proxy_mode_from_label_py(label: &str) -> PyResult<ProxyMode> {
    ProxyMode::parse(label.trim())
        .ok_or_else(|| PyValueError::new_err("proxy_mode must be 'bridge' or 'metadata-only'"))
}
fn sm2_distid_arg(distid: Option<&str>) -> String {
    distid
        .map(str::to_owned)
        .unwrap_or_else(Sm2PublicKey::default_distid)
}
fn parse_sm2_private_key(distid: Option<&str>, bytes: &[u8]) -> PyResult<Sm2PrivateKey> {
    if bytes.len() != SM2_PRIVATE_KEY_LENGTH {
        return Err(PyValueError::new_err(format!(
            "sm2 private key must be {SM2_PRIVATE_KEY_LENGTH} bytes, got {}",
            bytes.len()
        )));
    }
    let distid = sm2_distid_arg(distid);
    Sm2PrivateKey::from_bytes(distid, bytes)
        .map_err(|err| PyValueError::new_err(format!("failed to parse SM2 private key: {err}")))
}
fn parse_sm2_public_key(distid: Option<&str>, bytes: &[u8]) -> PyResult<Sm2PublicKey> {
    if bytes.len() != SM2_PUBLIC_KEY_UNCOMPRESSED_LENGTH {
        return Err(PyValueError::new_err(format!(
            "sm2 public key must be {SM2_PUBLIC_KEY_UNCOMPRESSED_LENGTH} bytes, got {}",
            bytes.len()
        )));
    }
    let distid = sm2_distid_arg(distid);
    Sm2PublicKey::from_sec1_bytes(distid, bytes)
        .map_err(|err| PyValueError::new_err(format!("failed to parse SM2 public key: {err}")))
}
fn parse_sm2_signature(bytes: &[u8]) -> PyResult<Sm2Signature> {
    let array: [u8; SM2_SIGNATURE_LENGTH] = bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(ERR_SM2_SIGNATURE_LEN))?;
    Sm2Signature::from_bytes(&array)
        .map_err(|err| PyValueError::new_err(format!("invalid SM2 signature: {err}")))
}
fn public_key_to_bytes<'a>(
    public_key: &'a PublicKey,
    context: &'static str,
) -> PyResult<(Algorithm, &'a [u8])> {
    public_key
        .try_to_bytes()
        .map_err(|err| PyValueError::new_err(format!("{context} is malformed: {err}")))
}
fn public_key_multihash_string(
    public_key: &PublicKey,
    prefixed: bool,
    context: &str,
) -> PyResult<String> {
    if prefixed {
        public_key.try_to_prefixed_string()
    } else {
        public_key.try_to_multihash_string()
    }
    .map_err(|err| PyValueError::new_err(format!("failed to format {context}: {err}")))
}
fn private_key_multihash_string(
    private_key: &ExposedPrivateKey,
    prefixed: bool,
    context: &str,
) -> PyResult<String> {
    if prefixed {
        private_key.try_to_prefixed_string()
    } else {
        private_key.try_to_multihash_string()
    }
    .map_err(|err| PyValueError::new_err(format!("failed to format {context}: {err}")))
}
fn keypair_to_py(py: Python<'_>, key_pair: KeyPair) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (_, public_bytes) = public_key_to_bytes(key_pair.public_key(), "public key")?;
    let (_, mut private_bytes) = key_pair.private_key().to_bytes();
    let public = Py::from(PyBytes::new(py, public_bytes));
    let private = Py::from(PyBytes::new(py, private_bytes.as_slice()));
    private_bytes.fill(0);
    Ok((private, public))
}
fn require_non_blank_unpadded(value: &str, field: &str) -> PyResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PyValueError::new_err(format!("{field} must not be blank")));
    }
    if trimmed != value {
        return Err(PyValueError::new_err(format!(
            "{field} must not contain surrounding whitespace"
        )));
    }
    Ok(())
}
fn parse_account_id(value: &str) -> PyResult<AccountId> {
    parse_exact_i105_account_id(value, "account_id")
}
fn parse_exact_i105_account_id(value: &str, field: &str) -> PyResult<AccountId> {
    require_non_blank_unpadded(value, field)?;
    if value.chars().any(char::is_whitespace)
        || value.contains('@')
        || value.contains('#')
        || value.contains('$')
    {
        return Err(PyValueError::new_err(format!(
            "{field} must be an exact canonical I105 account id"
        )));
    }
    let address = AccountAddress::parse_encoded(value, None).map_err(|err| {
        PyValueError::new_err(format!(
            "{field} must be an exact canonical I105 account id: {err}"
        ))
    })?;
    address.to_account_id().map_err(|err| {
        PyValueError::new_err(format!(
            "{field} must be an exact canonical I105 account id: {err}"
        ))
    })
}
fn parse_lower_hex_32(value: &str, field: &str) -> PyResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PyValueError::new_err(format!(
            "{field} must contain exactly 64 lowercase hexadecimal characters"
        )));
    }
    let decoded = hex::decode(value)
        .map_err(|err| PyValueError::new_err(format!("invalid {field}: {err}")))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{field} must contain exactly 32 bytes")))?;
    Ok(bytes)
}
fn parse_nonzero_lower_hex_32(value: &str, field: &str) -> PyResult<[u8; 32]> {
    let bytes = parse_lower_hex_32(value, field)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(PyValueError::new_err(format!(
            "{field} must not be the zero identifier"
        )));
    }
    Ok(bytes)
}
fn require_exact_dict_fields(
    value: &Bound<'_, PyDict>,
    fields: &[&str],
    context: &str,
) -> PyResult<()> {
    if value.len() != fields.len() {
        return Err(PyValueError::new_err(format!(
            "{context} must contain exactly [{}]",
            fields.join(", ")
        )));
    }
    for key in value.keys().iter() {
        let key = key
            .extract::<String>()
            .map_err(|_| PyTypeError::new_err(format!("{context} field names must be strings")))?;
        if !fields.contains(&key.as_str()) {
            return Err(PyValueError::new_err(format!(
                "{context} must contain exactly [{}]",
                fields.join(", ")
            )));
        }
    }
    Ok(())
}
fn required_dict_field<'py>(
    value: &Bound<'py, PyDict>,
    field: &str,
    context: &str,
) -> PyResult<Bound<'py, PyAny>> {
    value
        .get_item(field)?
        .ok_or_else(|| PyValueError::new_err(format!("{context}.{field} is required")))
}
fn required_dict_string(value: &Bound<'_, PyDict>, field: &str, context: &str) -> PyResult<String> {
    required_dict_field(value, field, context)?
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err(format!("{context}.{field} must be a string")))
}
fn required_dict_u64(value: &Bound<'_, PyDict>, field: &str, context: &str) -> PyResult<u64> {
    let field_value = required_dict_field(value, field, context)?;
    if field_value.is_instance_of::<pyo3::types::PyBool>() {
        return Err(PyTypeError::new_err(format!(
            "{context}.{field} must be an integer"
        )));
    }
    field_value
        .extract::<u64>()
        .map_err(|_| PyTypeError::new_err(format!("{context}.{field} must be a non-negative u64")))
}
fn parse_provider_ingest_completion_authority(
    value: &Bound<'_, PyDict>,
) -> PyResult<ProviderIngestCompletionAuthorityV1> {
    const CONTEXT: &str = "expected_authority";
    require_exact_dict_fields(
        value,
        &["provider_owner", "completion_signer", "signer_policy"],
        CONTEXT,
    )?;
    let provider_owner = required_dict_string(value, "provider_owner", CONTEXT)?;
    let completion_signer = required_dict_string(value, "completion_signer", CONTEXT)?;
    let signer_policy_value = required_dict_field(value, "signer_policy", CONTEXT)?;
    let signer_policy = signer_policy_value
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("expected_authority.signer_policy must be a mapping"))?;
    const POLICY_CONTEXT: &str = "expected_authority.signer_policy";
    require_exact_dict_fields(
        signer_policy,
        &[
            "policy_id",
            "revision",
            "predecessor_digest",
            "policy_digest",
        ],
        POLICY_CONTEXT,
    )?;
    let revision = required_dict_u64(signer_policy, "revision", POLICY_CONTEXT)?;
    if revision == 0 {
        return Err(PyValueError::new_err(
            "expected_authority.signer_policy.revision must be greater than zero",
        ));
    }
    let predecessor_value =
        required_dict_field(signer_policy, "predecessor_digest", POLICY_CONTEXT)?;
    let predecessor_digest = if predecessor_value.is_none() {
        None
    } else {
        let predecessor = predecessor_value.extract::<String>().map_err(|_| {
            PyTypeError::new_err(
                "expected_authority.signer_policy.predecessor_digest must be a string or null",
            )
        })?;
        Some(parse_nonzero_lower_hex_32(
            &predecessor,
            "expected_authority.signer_policy.predecessor_digest",
        )?)
    };
    match (revision, predecessor_digest) {
        (1, Some(_)) => {
            return Err(PyValueError::new_err(
                "expected_authority.signer_policy.predecessor_digest must be absent at revision one",
            ));
        }
        (2.., None) => {
            return Err(PyValueError::new_err(
                "expected_authority.signer_policy.predecessor_digest is required after revision one",
            ));
        }
        _ => {}
    }
    let signer_policy = ProviderIngestCompletionSignerPolicyV1 {
        policy_id: parse_nonzero_lower_hex_32(
            &required_dict_string(signer_policy, "policy_id", POLICY_CONTEXT)?,
            "expected_authority.signer_policy.policy_id",
        )?,
        revision,
        predecessor_digest,
        policy_digest: parse_nonzero_lower_hex_32(
            &required_dict_string(signer_policy, "policy_digest", POLICY_CONTEXT)?,
            "expected_authority.signer_policy.policy_digest",
        )?,
    };
    if !signer_policy.is_valid() {
        return Err(PyValueError::new_err(
            "expected_authority.signer_policy is not canonical",
        ));
    }
    Ok(ProviderIngestCompletionAuthorityV1::new(
        parse_exact_i105_account_id(&provider_owner, "expected_authority.provider_owner")?,
        parse_exact_i105_account_id(&completion_signer, "expected_authority.completion_signer")?,
        signer_policy,
    ))
}
fn parse_provider_ingest_finalized_anchor(
    value: &Bound<'_, PyDict>,
) -> PyResult<ProviderIngestFinalizedAnchorV1> {
    const CONTEXT: &str = "finalized_anchor";
    require_exact_dict_fields(value, &["height", "block_hash"], CONTEXT)?;
    let height = required_dict_u64(value, "height", CONTEXT)?;
    if height == 0 {
        return Err(PyValueError::new_err(
            "finalized_anchor.height must be greater than zero",
        ));
    }
    Ok(ProviderIngestFinalizedAnchorV1 {
        height,
        block_hash: parse_nonzero_lower_hex_32(
            &required_dict_string(value, "block_hash", CONTEXT)?,
            "finalized_anchor.block_hash",
        )?,
    })
}
fn parse_fee_sponsor_program_id(value: &str) -> PyResult<FeeSponsorProgramId> {
    require_non_blank_unpadded(value, "fee sponsor program id")?;
    let program_id = FeeSponsorProgramId::from_str(value).map_err(|err| {
        PyValueError::new_err(format!("invalid fee sponsor program id `{value}`: {err}"))
    })?;
    if program_id.to_string() != value {
        return Err(PyValueError::new_err(
            "fee sponsor program id must use its exact canonical encoding",
        ));
    }
    Ok(program_id)
}
fn parse_fee_payment_intent_json(value: &str) -> PyResult<FeePaymentIntent> {
    require_non_blank_unpadded(value, "fee payment intent JSON")?;
    let intent = json::from_str::<FeePaymentIntent>(value)
        .map_err(|err| PyValueError::new_err(format!("invalid fee payment intent JSON: {err}")))?;
    intent
        .validate()
        .map_err(|err| PyValueError::new_err(format!("invalid fee payment intent: {err}")))?;
    Ok(intent)
}
fn parse_asset_id(value: &str) -> PyResult<AssetId> {
    let raw = value.trim();
    if let Ok(asset_id) = raw.parse::<AssetId>() {
        return Ok(asset_id);
    }
    let mut parts = raw.split('#');
    let definition_literal = parts.next().ok_or_else(|| {
        PyValueError::new_err(format!(
            "invalid asset id `{value}`: missing asset definition id"
        ))
    })?;
    let account_literal = parts.next().ok_or_else(|| {
        PyValueError::new_err(format!("invalid asset id `{value}`: missing account id"))
    })?;
    let scope_literal = parts.next();
    if parts.next().is_some() {
        return Err(PyValueError::new_err(format!(
            "invalid asset id `{value}`: too many `#` segments"
        )));
    }
    let definition = AssetDefinitionId::parse_address_literal(definition_literal)
        .map_err(|err| PyValueError::new_err(format!("invalid asset id `{value}`: {err}")))?;
    let account = parse_account_id(account_literal)
        .map_err(|err| PyValueError::new_err(format!("invalid asset id `{value}`: {err}")))?;
    let scope = match scope_literal {
        None => AssetBalanceScope::Global,
        Some(raw_scope) => {
            let Some(dataspace) = raw_scope.strip_prefix("dataspace:") else {
                return Err(PyValueError::new_err(format!(
                    "invalid asset id `{value}`: scope must use `dataspace:<id>`"
                )));
            };
            let dataspace = dataspace
                .parse::<u64>()
                .map(DataSpaceId::new)
                .map_err(|_| {
                    PyValueError::new_err(format!(
                        "invalid asset id `{value}`: dataspace scope must be a u64"
                    ))
                })?;
            AssetBalanceScope::Dataspace(dataspace)
        }
    };
    Ok(AssetId::with_scope(definition, account, scope))
}
fn require_single_signatory<'a>(account: &'a AccountId, context: &str) -> PyResult<&'a PublicKey> {
    account.try_signatory().ok_or_else(|| {
        PyValueError::new_err(format!(
            "{context} requires a single-key account controller"
        ))
    })
}
fn ensure_ed25519_account(account: &AccountId) -> PyResult<()> {
    let signatory = require_single_signatory(account, "account")?;
    let (algorithm, _) = public_key_to_bytes(signatory, "account signatory public key")?;
    algorithm_guard(algorithm)
}
fn ensure_allowed_kwargs<'py>(
    kwargs: &Bound<'py, PyDict>,
    allowed: &[&str],
    context: &str,
) -> PyResult<()> {
    for key in kwargs.keys().iter() {
        let key_str = key.extract::<String>().map_err(|_| {
            PyTypeError::new_err(format!("{context} keyword arguments must be strings"))
        })?;
        if !allowed.contains(&key_str.as_str()) {
            return Err(PyTypeError::new_err(format!(
                "{context} got an unexpected keyword argument `{key_str}`"
            )));
        }
    }
    Ok(())
}
fn dict_require<'py, F>(dict: &Bound<'py, PyDict>, key: &str, err: F) -> PyResult<Bound<'py, PyAny>>
where
    F: FnOnce() -> PyErr,
{
    dict.get_item(key)?.ok_or_else(err)
}
#[derive(Debug)]
struct TimeTriggerKwargsParsed<'py> {
    period_ms: Option<u64>,
    repeats: Option<u32>,
    metadata: Option<Bound<'py, PyAny>>,
}
fn parse_time_trigger_kwargs<'py>(
    kwargs: Option<&Bound<'py, PyDict>>,
) -> PyResult<TimeTriggerKwargsParsed<'py>> {
    let Some(kwargs) = kwargs else {
        return Ok(TimeTriggerKwargsParsed {
            period_ms: None,
            repeats: None,
            metadata: None,
        });
    };
    ensure_allowed_kwargs(
        kwargs,
        &["period_ms", "repeats", "metadata"],
        "register_time_trigger()",
    )?;
    let period_ms = match kwargs.get_item("period_ms")? {
        Some(value) => Some(value.extract::<u64>()?),
        None => None,
    };
    let repeats = match kwargs.get_item("repeats")? {
        Some(value) => Some(value.extract::<u32>()?),
        None => None,
    };
    let metadata = kwargs.get_item("metadata")?;
    Ok(TimeTriggerKwargsParsed {
        period_ms,
        repeats,
        metadata,
    })
}
fn parse_connect_direction(value: &str) -> PyResult<Dir> {
    match value {
        "AppToWallet" => Ok(Dir::AppToWallet),
        "WalletToApp" => Ok(Dir::WalletToApp),
        other => Err(PyValueError::new_err(format!(
            "invalid connect direction `{other}`"
        ))),
    }
}
fn connect_direction_str(dir: Dir) -> &'static str {
    match dir {
        Dir::AppToWallet => "AppToWallet",
        Dir::WalletToApp => "WalletToApp",
    }
}
fn parse_connect_role(value: &str) -> PyResult<Role> {
    match value {
        "App" => Ok(Role::App),
        "Wallet" => Ok(Role::Wallet),
        other => Err(PyValueError::new_err(format!(
            "invalid connect role `{other}`"
        ))),
    }
}
fn connect_role_str(role: Role) -> &'static str {
    match role {
        Role::App => "App",
        Role::Wallet => "Wallet",
    }
}
fn fixed_array<const N: usize>(bytes: &[u8], context: &str) -> PyResult<[u8; N]> {
    if bytes.len() != N {
        return Err(PyValueError::new_err(format!(
            "{context} must be {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(bytes);
    Ok(arr)
}
fn checked_signature_from_bytes_for_algorithm(
    bytes: &[u8],
    algorithm: Algorithm,
    context: &str,
) -> PyResult<Signature> {
    let signature = match algorithm {
        Algorithm::Ed25519 => ed25519_parse_signature(bytes),
        Algorithm::MlDsa => mldsa65_parse_signature(bytes),
        _ => Signature::try_from_bytes(bytes).map_err(iroha_crypto::Error::from),
    };
    signature.map_err(|err| PyValueError::new_err(format!("{context} is malformed: {err}")))
}
fn py_text(value: &Bound<'_, PyAny>, context: &str) -> PyResult<String> {
    let text = value
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(PyValueError::new_err(format!(
            "{context} must be non-empty"
        )));
    }
    Ok(trimmed.to_owned())
}
fn py_bytes_or_hex(value: &Bound<'_, PyAny>, context: &str) -> PyResult<Vec<u8>> {
    if let Ok(text) = value.extract::<String>() {
        return parse_hex_bytes_py(&text, context);
    }
    value
        .extract::<Vec<u8>>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be bytes or hex string")))
}
fn py_fixed_array<const N: usize>(value: &Bound<'_, PyAny>, context: &str) -> PyResult<[u8; N]> {
    let bytes = py_bytes_or_hex(value, context)?;
    fixed_array::<N>(&bytes, context)
}
fn py_fixed_array_list(value: &Bound<'_, PyAny>, context: &str) -> PyResult<Vec<[u8; 32]>> {
    if let Ok(items) = value.cast::<PyList>() {
        let mut parsed = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            parsed.push(py_fixed_array::<32>(&item, &format!("{context}[{index}]"))?);
        }
        return Ok(parsed);
    }
    if let Ok(items) = value.cast::<PyTuple>() {
        let mut parsed = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            parsed.push(py_fixed_array::<32>(&item, &format!("{context}[{index}]"))?);
        }
        return Ok(parsed);
    }
    Err(PyTypeError::new_err(format!(
        "{context} must be a list or tuple"
    )))
}
fn dict_get_alias<'py>(
    dict: &Bound<'py, PyDict>,
    aliases: &[&str],
) -> PyResult<Option<Bound<'py, PyAny>>> {
    for alias in aliases {
        if let Some(value) = dict.get_item(alias)?
            && !value.is_none()
        {
            return Ok(Some(value));
        }
    }
    Ok(None)
}
#[cfg(test)]
fn parse_canonical_u128_text(value: &str, context: &str) -> PyResult<u128> {
    if value.is_empty()
        || value.len() > 39
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(PyValueError::new_err(format!(
            "{context} must use canonical unsigned-integer spelling"
        )));
    }
    value.parse::<u128>().map_err(|err| {
        PyValueError::new_err(format!("{context} must be an unsigned integer: {err}"))
    })
}
fn canonical_public_balance_scope_py(scope: AssetBalanceScope) -> PyResult<String> {
    crate::privacy_native_actions::canonical_public_balance_scope_v1(scope).ok_or_else(|| {
        PyRuntimeError::new_err(
            "authenticated privacy statement contains the reserved universal dataspace scope",
        )
    })
}
fn parse_verifying_key_id_text(value: &str, context: &str) -> PyResult<VerifyingKeyId> {
    let trimmed = value.trim();
    let Some((backend, name)) = trimmed.split_once(':') else {
        return Err(PyValueError::new_err(format!(
            "{context} must use 'backend:name' format"
        )));
    };
    let backend = backend.trim();
    let name = name.trim();
    if backend.is_empty() || name.is_empty() {
        return Err(PyValueError::new_err(format!(
            "{context} must include both backend and name"
        )));
    }
    let backend = Ident::from_str(backend).map_err(|err| {
        PyValueError::new_err(format!("invalid {context} backend identifier: {err}"))
    })?;
    Ok(VerifyingKeyId::new(backend, name))
}
fn parse_verifying_key_id_py(
    value: Option<&Bound<'_, PyAny>>,
    context: &str,
) -> PyResult<Option<VerifyingKeyId>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    if let Ok(text) = value.extract::<String>() {
        return parse_verifying_key_id_text(&text, context).map(Some);
    }
    let dict = value
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be a string or mapping")))?;
    let backend = dict_get_alias(dict, &["backend", "backendId"])?
        .ok_or_else(|| PyValueError::new_err(format!("{context}.backend is required")))?;
    let name = dict_get_alias(dict, &["name", "id", "key"])?
        .ok_or_else(|| PyValueError::new_err(format!("{context}.name is required")))?;
    let backend_text = py_text(&backend, &format!("{context}.backend"))?;
    let name_text = py_text(&name, &format!("{context}.name"))?;
    let backend = Ident::from_str(&backend_text).map_err(|err| {
        PyValueError::new_err(format!("invalid {context} backend identifier: {err}"))
    })?;
    Ok(Some(VerifyingKeyId::new(backend, name_text)))
}
fn py_exact_dict<'value, 'py>(
    value: &'value Bound<'py, PyAny>,
    context: &str,
    allowed_fields: &[&str],
) -> PyResult<&'value Bound<'py, PyDict>> {
    let dict = value
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be a mapping")))?;
    for (key, _) in dict.iter() {
        let key = key
            .extract::<String>()
            .map_err(|_| PyTypeError::new_err(format!("{context} field names must be strings")))?;
        if !allowed_fields.contains(&key.as_str()) {
            return Err(PyValueError::new_err(format!(
                "{context} contains unknown first-release field `{key}`"
            )));
        }
    }
    Ok(dict)
}
fn py_required_dict_field<'py>(
    dict: &Bound<'py, PyDict>,
    field: &str,
    context: &str,
) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(field)?
        .ok_or_else(|| PyValueError::new_err(format!("{context}.{field} is required")))
}
fn py_exact_bytes(value: &Bound<'_, PyAny>, context: &str) -> PyResult<Vec<u8>> {
    let bytes = value
        .cast::<PyBytes>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be bytes")))?;
    Ok(bytes.as_bytes().to_vec())
}
fn py_exact_fixed_bytes<const N: usize>(
    value: &Bound<'_, PyAny>,
    context: &str,
) -> PyResult<[u8; N]> {
    fixed_array::<N>(&py_exact_bytes(value, context)?, context)
}
fn py_portable_verifier_id_field(value: &Bound<'_, PyAny>, context: &str) -> PyResult<String> {
    let text = value
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be a string")))?;
    if !verifying_key_id_field_is_portable(&text) {
        return Err(PyValueError::new_err(format!(
            "{context} must use the bounded portable verifier-key registry grammar"
        )));
    }
    Ok(text)
}
fn py_exact_u16(value: &Bound<'_, PyAny>, context: &str) -> PyResult<u16> {
    if value.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err(format!(
            "{context} must be an unsigned 16-bit integer"
        )));
    }
    value
        .extract::<u16>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be an unsigned 16-bit integer")))
}
fn py_exact_u32(value: &Bound<'_, PyAny>, context: &str) -> PyResult<u32> {
    if value.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err(format!(
            "{context} must be an unsigned 32-bit integer"
        )));
    }
    value
        .extract::<u32>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be an unsigned 32-bit integer")))
}
fn parse_lane_privacy_proof_py(
    value: &Bound<'_, PyAny>,
    context: &str,
) -> PyResult<LanePrivacyProof> {
    let lane = py_exact_dict(value, context, &["commitment_id", "witness"])?;
    let commitment_id = py_exact_u16(
        &py_required_dict_field(lane, "commitment_id", context)?,
        &format!("{context}.commitment_id"),
    )?;
    let witness_value = py_required_dict_field(lane, "witness", context)?;
    let witness = py_exact_dict(
        &witness_value,
        &format!("{context}.witness"),
        &["kind", "payload"],
    )?;
    let kind = py_required_dict_field(witness, "kind", &format!("{context}.witness"))?
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err(format!("{context}.witness.kind must be a string")))?;
    if kind != "merkle" {
        return Err(PyValueError::new_err(format!(
            "{context}.witness.kind must be exactly `merkle`"
        )));
    }
    let payload_value = py_required_dict_field(witness, "payload", &format!("{context}.witness"))?;
    let payload = py_exact_dict(
        &payload_value,
        &format!("{context}.witness.payload"),
        &["leaf", "proof"],
    )?;
    let leaf = py_exact_fixed_bytes::<32>(
        &py_required_dict_field(payload, "leaf", &format!("{context}.witness.payload"))?,
        &format!("{context}.witness.payload.leaf"),
    )?;
    let merkle_value =
        py_required_dict_field(payload, "proof", &format!("{context}.witness.payload"))?;
    let merkle = py_exact_dict(
        &merkle_value,
        &format!("{context}.witness.payload.proof"),
        &["leaf_index", "audit_path"],
    )?;
    let leaf_index = py_exact_u32(
        &py_required_dict_field(
            merkle,
            "leaf_index",
            &format!("{context}.witness.payload.proof"),
        )?,
        &format!("{context}.witness.payload.proof.leaf_index"),
    )?;
    let path_value = py_required_dict_field(
        merkle,
        "audit_path",
        &format!("{context}.witness.payload.proof"),
    )?;
    let path = path_value.cast::<PyList>().map_err(|_| {
        PyTypeError::new_err(format!(
            "{context}.witness.payload.proof.audit_path must be a list"
        ))
    })?;
    if path.is_empty() || path.len() > LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 {
        return Err(PyValueError::new_err(format!(
            "{context}.witness.payload.proof.audit_path must contain between 1 and {LANE_PRIVACY_MAX_MERKLE_DEPTH_V1} siblings"
        )));
    }
    let mut audit_path = Vec::with_capacity(path.len());
    for (index, sibling) in path.iter().enumerate() {
        if sibling.is_none() {
            return Err(PyValueError::new_err(format!(
                "{context}.witness.payload.proof.audit_path[{index}] must contain a sibling"
            )));
        }
        audit_path.push(Some(py_exact_fixed_bytes::<32>(
            &sibling,
            &format!("{context}.witness.payload.proof.audit_path[{index}]"),
        )?));
    }
    LanePrivacyProof::merkle_from_raw_path(
        LaneCommitmentId::new(commitment_id),
        leaf,
        leaf_index,
        audit_path,
    )
    .map_err(|error| PyValueError::new_err(format!("{context} {error}")))
}
fn parse_zk_proof_attachment(value: &Bound<'_, PyAny>, context: &str) -> PyResult<ProofAttachment> {
    let dict = py_exact_dict(
        value,
        context,
        &[
            "backend",
            "proof",
            "vk_ref",
            "vk_commitment",
            "envelope_hash",
            "lane_privacy",
        ],
    )?;
    let backend_text = py_portable_verifier_id_field(
        &py_required_dict_field(dict, "backend", context)?,
        &format!("{context}.backend"),
    )?;
    let backend = Ident::from_str(&backend_text).map_err(|err| {
        PyValueError::new_err(format!("invalid {context} backend identifier: {err}"))
    })?;
    let proof_value = py_required_dict_field(dict, "proof", context)?;
    let proof = py_exact_dict(
        &proof_value,
        &format!("{context}.proof"),
        &["backend", "bytes"],
    )?;
    let proof_backend_text = py_portable_verifier_id_field(
        &py_required_dict_field(proof, "backend", &format!("{context}.proof"))?,
        &format!("{context}.proof.backend"),
    )?;
    if proof_backend_text != backend_text {
        return Err(PyValueError::new_err(format!(
            "{context}.proof.backend must match {context}.backend"
        )));
    }
    let proof_bytes_value = py_required_dict_field(proof, "bytes", &format!("{context}.proof"))?;
    let proof_bytes = proof_bytes_value
        .cast::<PyBytes>()
        .map_err(|_| PyTypeError::new_err(format!("{context}.proof.bytes must be bytes")))?;
    let proof_bytes = proof_bytes.as_bytes();
    if proof_bytes.is_empty() {
        return Err(PyValueError::new_err(format!(
            "{context}.proof.bytes must be non-empty"
        )));
    }
    let maximum_proof_bytes = proof_box_max_proof_bytes_v1(&backend_text).ok_or_else(|| {
        PyValueError::new_err(format!(
            "{context}.proof backend and canonical framing exceed the 64 MiB ProofBox limit"
        ))
    })?;
    if proof_bytes.len() > maximum_proof_bytes {
        return Err(PyValueError::new_err(format!(
            "{context}.proof.bytes exceeds the {maximum_proof_bytes}-byte limit for this backend"
        )));
    }
    let proof_bytes = proof_bytes.to_vec();
    let vk_value = py_required_dict_field(dict, "vk_ref", context)?;
    let vk = py_exact_dict(
        &vk_value,
        &format!("{context}.vk_ref"),
        &["backend", "name"],
    )?;
    let vk_backend_text = py_portable_verifier_id_field(
        &py_required_dict_field(vk, "backend", &format!("{context}.vk_ref"))?,
        &format!("{context}.vk_ref.backend"),
    )?;
    if vk_backend_text != backend_text {
        return Err(PyValueError::new_err(format!(
            "{context}.vk_ref.backend must match {context}.backend"
        )));
    }
    let vk_name = py_portable_verifier_id_field(
        &py_required_dict_field(vk, "name", &format!("{context}.vk_ref"))?,
        &format!("{context}.vk_ref.name"),
    )?;
    let mut attachment = ProofAttachment::new_ref(
        backend.clone(),
        ProofBox::new(backend.clone(), proof_bytes),
        VerifyingKeyId::new(backend, vk_name),
    );
    if let Some(commitment) = dict.get_item("vk_commitment")?
        && !commitment.is_none()
    {
        attachment.vk_commitment = Some(py_exact_fixed_bytes::<32>(
            &commitment,
            &format!("{context}.vk_commitment"),
        )?);
    }
    if let Some(envelope_hash) = dict.get_item("envelope_hash")?
        && !envelope_hash.is_none()
    {
        attachment.envelope_hash = Some(py_exact_fixed_bytes::<32>(
            &envelope_hash,
            &format!("{context}.envelope_hash"),
        )?);
    }
    if let Some(lane_privacy) = dict.get_item("lane_privacy")?
        && !lane_privacy.is_none()
    {
        attachment.lane_privacy = Some(parse_lane_privacy_proof_py(
            &lane_privacy,
            &format!("{context}.lane_privacy"),
        )?);
    }
    if let Some((field, message)) = attachment.structural_error() {
        return Err(PyValueError::new_err(format!(
            "{context}.{field} {message}"
        )));
    }
    Ok(attachment)
}
fn extract_optional_dict<'py>(
    value: Option<Bound<'py, PyAny>>,
    context: &str,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    match value {
        Some(obj) => {
            if obj.is_none() {
                Ok(None)
            } else {
                let dict = obj
                    .cast_into::<PyDict>()
                    .map_err(|_| PyTypeError::new_err(format!("{context} must be a mapping")))?;
                Ok(Some(dict))
            }
        }
        None => Ok(None),
    }
}
fn optional_string(value: Option<Bound<'_, PyAny>>) -> PyResult<Option<String>> {
    match value {
        Some(obj) if !obj.is_none() => obj.extract::<String>().map(Some),
        _ => Ok(None),
    }
}
fn parse_string_list(value: Option<Bound<'_, PyAny>>, context: &str) -> PyResult<Vec<String>> {
    match value {
        Some(obj) if !obj.is_none() => obj
            .extract::<Vec<String>>()
            .map_err(|_| PyTypeError::new_err(format!("{context} must be a sequence of strings"))),
        _ => Ok(Vec::new()),
    }
}
fn parse_permissions(
    value: Option<Bound<'_, PyAny>>,
    context: &str,
) -> PyResult<Option<PermissionsV1>> {
    let Some(mapping) = extract_optional_dict(value, context)? else {
        return Ok(None);
    };
    let methods = parse_string_list(mapping.get_item("methods")?, "permissions.methods")?;
    let events = parse_string_list(mapping.get_item("events")?, "permissions.events")?;
    let resources = match mapping.get_item("resources")? {
        Some(obj) if !obj.is_none() => Some(obj.extract::<Vec<String>>().map_err(|_| {
            PyTypeError::new_err("permissions.resources must be a sequence of strings")
        })?),
        _ => None,
    };
    Ok(Some(PermissionsV1 {
        methods,
        events,
        resources,
    }))
}
fn parse_app_metadata(value: Option<Bound<'_, PyAny>>) -> PyResult<Option<AppMeta>> {
    let Some(mapping) = extract_optional_dict(value, "metadata")? else {
        return Ok(None);
    };
    let name = dict_require(&mapping, "name", || {
        PyValueError::new_err("metadata.name is required")
    })?
    .extract::<String>()?;
    let url = optional_string(mapping.get_item("url")?)?;
    let icon_hash = optional_string(mapping.get_item("icon_hash")?)?;
    Ok(Some(AppMeta {
        name,
        url,
        icon_hash,
    }))
}
fn parse_sign_in_proof(value: Option<Bound<'_, PyAny>>) -> PyResult<Option<SignInProofV1>> {
    let Some(mapping) = extract_optional_dict(value, "proof")? else {
        return Ok(None);
    };
    let domain = dict_require(&mapping, "domain", || {
        PyValueError::new_err("proof.domain is required")
    })?
    .extract::<String>()?;
    let uri = dict_require(&mapping, "uri", || {
        PyValueError::new_err("proof.uri is required")
    })?
    .extract::<String>()?;
    let statement = dict_require(&mapping, "statement", || {
        PyValueError::new_err("proof.statement is required")
    })?
    .extract::<String>()?;
    let issued_at = dict_require(&mapping, "issued_at", || {
        PyValueError::new_err("proof.issued_at is required")
    })?
    .extract::<String>()?;
    let nonce = dict_require(&mapping, "nonce", || {
        PyValueError::new_err("proof.nonce is required")
    })?
    .extract::<String>()?;
    Ok(Some(SignInProofV1 {
        domain,
        uri,
        statement,
        issued_at,
        nonce,
    }))
}
fn parse_wallet_signature(fields: &Bound<'_, PyDict>) -> PyResult<WalletSignatureV1> {
    let sig_bytes = dict_require(fields, "signature", || {
        PyValueError::new_err("approve.signature is required")
    })?
    .extract::<Vec<u8>>()?;
    let sig = fixed_array::<64>(&sig_bytes, "signature")?;
    let algorithm = match fields.get_item("algorithm")? {
        Some(value) if !value.is_none() => {
            let alg_str = value.extract::<String>()?;
            Algorithm::from_str(&alg_str).map_err(|_| {
                PyValueError::new_err(format!(
                    "unsupported connect signature algorithm `{alg_str}`"
                ))
            })?
        }
        _ => Algorithm::Ed25519,
    };
    Ok(WalletSignatureV1::new(
        algorithm,
        checked_signature_from_bytes_for_algorithm(&sig, algorithm, "approve.signature")?,
    ))
}
fn parse_connect_control(fields: &Bound<'_, PyDict>) -> PyResult<ConnectControlV1> {
    let control_type = dict_require(fields, "control_type", || {
        PyValueError::new_err("connect frame control requires `control_type`")
    })?
    .extract::<String>()?;
    let fields_obj = dict_require(fields, "fields", || {
        PyValueError::new_err("connect frame control requires `fields`")
    })?;
    let payload = fields_obj
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("connect frame control `fields` must be a dict"))?;
    match control_type.as_str() {
        "Open" => {
            let pk_bytes = dict_require(payload, "app_public_key", || {
                PyValueError::new_err("open.app_public_key is required")
            })?
            .extract::<Vec<u8>>()?;
            let app_pk = fixed_array::<32>(&pk_bytes, "app_public_key")?;
            let network_id = *dict_require(payload, "network_id", || {
                PyValueError::new_err("open.network_id is required")
            })?
            .extract::<PyRef<'_, PyNetworkId>>()?
            .as_inner();
            let metadata = {
                let value = payload.get_item("metadata")?;
                parse_app_metadata(value)?
            };
            let permissions = {
                let value = payload.get_item("permissions")?;
                parse_permissions(value, "permissions")?
            };
            Ok(ConnectControlV1::Open {
                app_pk,
                app_meta: metadata,
                constraints: Constraints { network_id },
                permissions,
            })
        }
        "Approve" => {
            let pk_bytes = dict_require(payload, "wallet_public_key", || {
                PyValueError::new_err("approve.wallet_public_key is required")
            })?
            .extract::<Vec<u8>>()?;
            let wallet_pk = fixed_array::<32>(&pk_bytes, "wallet_public_key")?;
            let account_id = dict_require(payload, "account_id", || {
                PyValueError::new_err("approve.account_id is required")
            })?
            .extract::<String>()?;
            let permissions = {
                let value = payload.get_item("permissions")?;
                parse_permissions(value, "permissions")?
            };
            let proof = {
                let value = payload.get_item("proof")?;
                parse_sign_in_proof(value)?
            };
            let sig_wallet = parse_wallet_signature(payload)?;
            Ok(ConnectControlV1::Approve {
                wallet_pk,
                account_id,
                permissions,
                proof,
                sig_wallet,
            })
        }
        "Reject" => {
            let code = dict_require(payload, "code", || {
                PyValueError::new_err("reject.code is required")
            })?
            .extract::<u16>()?;
            let code_id = dict_require(payload, "code_id", || {
                PyValueError::new_err("reject.code_id is required")
            })?
            .extract::<String>()?;
            let reason = dict_require(payload, "reason", || {
                PyValueError::new_err("reject.reason is required")
            })?
            .extract::<String>()?;
            Ok(ConnectControlV1::Reject {
                code,
                code_id,
                reason,
            })
        }
        "Close" => {
            let role = dict_require(payload, "role", || {
                PyValueError::new_err("close.role is required")
            })?
            .extract::<String>()?;
            let who = parse_connect_role(&role)?;
            let code = dict_require(payload, "code", || {
                PyValueError::new_err("close.code is required")
            })?
            .extract::<u16>()?;
            let reason = dict_require(payload, "reason", || {
                PyValueError::new_err("close.reason is required")
            })?
            .extract::<String>()?;
            let retryable = dict_require(payload, "retryable", || {
                PyValueError::new_err("close.retryable is required")
            })?
            .extract::<bool>()?;
            Ok(ConnectControlV1::Close {
                who,
                code,
                reason,
                retryable,
            })
        }
        "Ping" => {
            let nonce = dict_require(payload, "nonce", || {
                PyValueError::new_err("ping.nonce is required")
            })?
            .extract::<u64>()?;
            Ok(ConnectControlV1::Ping { nonce })
        }
        "Pong" => {
            let nonce = dict_require(payload, "nonce", || {
                PyValueError::new_err("pong.nonce is required")
            })?
            .extract::<u64>()?;
            Ok(ConnectControlV1::Pong { nonce })
        }
        other => Err(PyValueError::new_err(format!(
            "unsupported connect control variant `{other}`"
        ))),
    }
}
fn parse_frame_kind(kind: &Bound<'_, PyDict>) -> PyResult<FrameKind> {
    let kind_type = dict_require(kind, "type", || {
        PyValueError::new_err("connect frame kind requires `type`")
    })?
    .extract::<String>()?;
    match kind_type.as_str() {
        "Control" => Ok(FrameKind::Control(parse_connect_control(kind)?)),
        "Ciphertext" => {
            let fields_obj = dict_require(kind, "fields", || {
                PyValueError::new_err("ciphertext frame requires `fields`")
            })?;
            let payload = fields_obj
                .cast::<PyDict>()
                .map_err(|_| PyTypeError::new_err("ciphertext fields must be a dict"))?;
            let direction = dict_require(payload, "direction", || {
                PyValueError::new_err("ciphertext.direction is required")
            })?
            .extract::<String>()?;
            let dir = parse_connect_direction(&direction)?;
            let aead = dict_require(payload, "aead", || {
                PyValueError::new_err("ciphertext.aead is required")
            })?
            .extract::<Vec<u8>>()?;
            Ok(FrameKind::Ciphertext(ConnectCiphertextV1 { dir, aead }))
        }
        other => Err(PyValueError::new_err(format!(
            "unsupported connect frame kind `{other}`"
        ))),
    }
}
fn parse_control_after_key(
    fields: &Bound<'_, PyDict>,
    variant: &str,
) -> PyResult<ControlAfterKeyV1> {
    match variant {
        "Close" => {
            let who_str = dict_require(fields, "who", || {
                PyValueError::new_err("close.who is required")
            })?
            .extract::<String>()?;
            let who = parse_connect_role(&who_str)?;
            let code = dict_require(fields, "code", || {
                PyValueError::new_err("close.code is required")
            })?
            .extract::<u16>()?;
            let reason = dict_require(fields, "reason", || {
                PyValueError::new_err("close.reason is required")
            })?
            .extract::<String>()?;
            let retryable = dict_require(fields, "retryable", || {
                PyValueError::new_err("close.retryable is required")
            })?
            .extract::<bool>()?;
            Ok(ControlAfterKeyV1::Close {
                who,
                code,
                reason,
                retryable,
            })
        }
        "Reject" => {
            let code = dict_require(fields, "code", || {
                PyValueError::new_err("reject.code is required")
            })?
            .extract::<u16>()?;
            let code_id = dict_require(fields, "code_id", || {
                PyValueError::new_err("reject.code_id is required")
            })?
            .extract::<String>()?;
            let reason = dict_require(fields, "reason", || {
                PyValueError::new_err("reject.reason is required")
            })?
            .extract::<String>()?;
            Ok(ControlAfterKeyV1::Reject {
                code,
                code_id,
                reason,
            })
        }
        other => Err(PyValueError::new_err(format!(
            "unsupported encrypted control variant `{other}`"
        ))),
    }
}
fn encode_wallet_signature_dict<'py>(
    py: Python<'py>,
    sig: &WalletSignatureV1,
) -> PyResult<Py<PyAny>> {
    let mapping = PyDict::new(py);
    mapping.set_item("algorithm", sig.algorithm.to_string())?;
    mapping.set_item("signature", PyBytes::new(py, sig.signature.payload()))?;
    Ok(mapping.into_any().unbind())
}
fn parse_connect_payload(payload: &Bound<'_, PyDict>) -> PyResult<ConnectPayloadV1> {
    let payload_type = dict_require(payload, "type", || {
        PyValueError::new_err("connect payload requires `type`")
    })?
    .extract::<String>()?;
    match payload_type.as_str() {
        "Control" => {
            let variant = dict_require(payload, "variant", || {
                PyValueError::new_err("control payload requires `variant`")
            })?
            .extract::<String>()?;
            let fields_obj = dict_require(payload, "fields", || {
                PyValueError::new_err("control payload requires `fields`")
            })?;
            let fields = fields_obj
                .cast::<PyDict>()
                .map_err(|_| PyTypeError::new_err("control payload `fields` must be a dict"))?;
            let control = parse_control_after_key(fields, &variant)?;
            Ok(ConnectPayloadV1::Control(control))
        }
        "SignRequestRaw" => {
            let domain_tag = dict_require(payload, "domain_tag", || {
                PyValueError::new_err("SignRequestRaw.domain_tag is required")
            })?
            .extract::<String>()?;
            let bytes = dict_require(payload, "bytes", || {
                PyValueError::new_err("SignRequestRaw.bytes is required")
            })?
            .extract::<Vec<u8>>()?;
            Ok(ConnectPayloadV1::SignRequestRaw { domain_tag, bytes })
        }
        "SignRequestTx" => {
            let tx_bytes = dict_require(payload, "tx_bytes", || {
                PyValueError::new_err("SignRequestTx.tx_bytes is required")
            })?
            .extract::<Vec<u8>>()?;
            Ok(ConnectPayloadV1::SignRequestTx { tx_bytes })
        }
        "SignResultOk" => {
            let signature_obj = dict_require(payload, "signature", || {
                PyValueError::new_err("SignResultOk.signature is required")
            })?;
            let signature_dict = signature_obj
                .cast::<PyDict>()
                .map_err(|_| PyTypeError::new_err("SignResultOk.signature must be a dict"))?;
            let signature = parse_wallet_signature(signature_dict)?;
            Ok(ConnectPayloadV1::SignResultOk { signature })
        }
        "SignResultErr" => {
            let code = dict_require(payload, "code", || {
                PyValueError::new_err("SignResultErr.code is required")
            })?
            .extract::<String>()?;
            let message = dict_require(payload, "message", || {
                PyValueError::new_err("SignResultErr.message is required")
            })?
            .extract::<String>()?;
            Ok(ConnectPayloadV1::SignResultErr { code, message })
        }
        "DisplayRequest" => {
            let title = dict_require(payload, "title", || {
                PyValueError::new_err("DisplayRequest.title is required")
            })?
            .extract::<String>()?;
            let body = dict_require(payload, "body", || {
                PyValueError::new_err("DisplayRequest.body is required")
            })?
            .extract::<String>()?;
            Ok(ConnectPayloadV1::DisplayRequest { title, body })
        }
        other => Err(PyValueError::new_err(format!(
            "unsupported connect payload type `{other}`"
        ))),
    }
}
fn encode_connect_payload<'py>(py: Python<'py>, payload: &ConnectPayloadV1) -> PyResult<Py<PyAny>> {
    let mapping = PyDict::new(py);
    match payload {
        ConnectPayloadV1::Control(control) => {
            mapping.set_item("type", "Control")?;
            match control {
                ControlAfterKeyV1::Close {
                    who,
                    code,
                    reason,
                    retryable,
                } => {
                    mapping.set_item("variant", "Close")?;
                    let fields = PyDict::new(py);
                    fields.set_item("who", connect_role_str(*who))?;
                    fields.set_item("code", code)?;
                    fields.set_item("reason", reason)?;
                    fields.set_item("retryable", retryable)?;
                    mapping.set_item("fields", fields)?;
                }
                ControlAfterKeyV1::Reject {
                    code,
                    code_id,
                    reason,
                } => {
                    mapping.set_item("variant", "Reject")?;
                    let fields = PyDict::new(py);
                    fields.set_item("code", code)?;
                    fields.set_item("code_id", code_id)?;
                    fields.set_item("reason", reason)?;
                    mapping.set_item("fields", fields)?;
                }
            }
        }
        ConnectPayloadV1::SignRequestRaw { domain_tag, bytes } => {
            mapping.set_item("type", "SignRequestRaw")?;
            mapping.set_item("domain_tag", domain_tag)?;
            mapping.set_item("bytes", PyBytes::new(py, bytes))?;
        }
        ConnectPayloadV1::SignRequestTx { tx_bytes } => {
            mapping.set_item("type", "SignRequestTx")?;
            mapping.set_item("tx_bytes", PyBytes::new(py, tx_bytes))?;
        }
        ConnectPayloadV1::SignResultOk { signature } => {
            mapping.set_item("type", "SignResultOk")?;
            let sig_dict = encode_wallet_signature_dict(py, signature)?;
            mapping.set_item("signature", sig_dict)?;
        }
        ConnectPayloadV1::SignResultErr { code, message } => {
            mapping.set_item("type", "SignResultErr")?;
            mapping.set_item("code", code)?;
            mapping.set_item("message", message)?;
        }
        ConnectPayloadV1::DisplayRequest { title, body } => {
            mapping.set_item("type", "DisplayRequest")?;
            mapping.set_item("title", title)?;
            mapping.set_item("body", body)?;
        }
    }
    Ok(mapping.into_any().unbind())
}
fn encode_permissions_dict<'py>(py: Python<'py>, perms: &Option<PermissionsV1>) -> Py<PyAny> {
    match perms {
        Some(p) => {
            let mapping = PyDict::new(py);
            mapping
                .set_item("methods", &p.methods)
                .expect("set methods");
            mapping.set_item("events", &p.events).expect("set events");
            match &p.resources {
                Some(resources) => {
                    mapping
                        .set_item("resources", resources)
                        .expect("set resources");
                }
                None => {
                    mapping.set_item("resources", py.None()).expect("set none");
                }
            }
            mapping.into_any().unbind()
        }
        None => py.None(),
    }
}
fn encode_app_meta_dict<'py>(py: Python<'py>, meta: &Option<AppMeta>) -> Py<PyAny> {
    match meta {
        Some(value) => {
            let mapping = PyDict::new(py);
            mapping.set_item("name", &value.name).expect("set");
            match &value.url {
                Some(url) => {
                    mapping.set_item("url", url).expect("set");
                }
                None => {
                    mapping.set_item("url", py.None()).expect("set none");
                }
            }
            match &value.icon_hash {
                Some(hash) => {
                    mapping.set_item("icon_hash", hash).expect("set");
                }
                None => {
                    mapping.set_item("icon_hash", py.None()).expect("set none");
                }
            }
            mapping.into_any().unbind()
        }
        None => py.None(),
    }
}
fn encode_proof_dict<'py>(py: Python<'py>, proof: &Option<SignInProofV1>) -> Py<PyAny> {
    match proof {
        Some(value) => {
            let mapping = PyDict::new(py);
            mapping.set_item("domain", &value.domain).expect("set");
            mapping.set_item("uri", &value.uri).expect("set");
            mapping
                .set_item("statement", &value.statement)
                .expect("set");
            mapping
                .set_item("issued_at", &value.issued_at)
                .expect("set");
            mapping.set_item("nonce", &value.nonce).expect("set");
            mapping.into_any().unbind()
        }
        None => py.None(),
    }
}
fn encode_frame_kind(py: Python<'_>, kind: &FrameKind) -> PyResult<Py<PyDict>> {
    let mapping = PyDict::new(py);
    match kind {
        FrameKind::Control(control) => {
            mapping.set_item("type", "Control")?;
            match control {
                ConnectControlV1::Open {
                    app_pk,
                    app_meta,
                    constraints,
                    permissions,
                } => {
                    mapping.set_item("control_type", "Open")?;
                    let fields = PyDict::new(py);
                    fields.set_item("app_public_key", PyBytes::new(py, app_pk))?;
                    fields.set_item(
                        "network_id",
                        Py::new(
                            py,
                            PyNetworkId {
                                inner: constraints.network_id,
                            },
                        )?,
                    )?;
                    fields.set_item("metadata", encode_app_meta_dict(py, app_meta))?;
                    fields.set_item("permissions", encode_permissions_dict(py, permissions))?;
                    mapping.set_item("fields", fields)?;
                }
                ConnectControlV1::Approve {
                    wallet_pk,
                    account_id,
                    permissions,
                    proof,
                    sig_wallet,
                } => {
                    mapping.set_item("control_type", "Approve")?;
                    let fields = PyDict::new(py);
                    fields.set_item("wallet_public_key", PyBytes::new(py, wallet_pk))?;
                    fields.set_item("account_id", account_id)?;
                    fields.set_item("permissions", encode_permissions_dict(py, permissions))?;
                    fields.set_item("proof", encode_proof_dict(py, proof))?;
                    fields.set_item(
                        "signature",
                        PyBytes::new(py, sig_wallet.signature.payload()),
                    )?;
                    fields.set_item("algorithm", sig_wallet.algorithm.as_static_str())?;
                    mapping.set_item("fields", fields)?;
                }
                ConnectControlV1::Reject {
                    code,
                    code_id,
                    reason,
                } => {
                    mapping.set_item("control_type", "Reject")?;
                    let fields = PyDict::new(py);
                    fields.set_item("code", code)?;
                    fields.set_item("code_id", code_id)?;
                    fields.set_item("reason", reason)?;
                    mapping.set_item("fields", fields)?;
                }
                ConnectControlV1::Close {
                    who,
                    code,
                    reason,
                    retryable,
                } => {
                    mapping.set_item("control_type", "Close")?;
                    let fields = PyDict::new(py);
                    fields.set_item("role", connect_role_str(*who))?;
                    fields.set_item("code", code)?;
                    fields.set_item("reason", reason)?;
                    fields.set_item("retryable", retryable)?;
                    mapping.set_item("fields", fields)?;
                }
                ConnectControlV1::Ping { nonce } => {
                    mapping.set_item("control_type", "Ping")?;
                    let fields = PyDict::new(py);
                    fields.set_item("nonce", nonce)?;
                    mapping.set_item("fields", fields)?;
                }
                ConnectControlV1::Pong { nonce } => {
                    mapping.set_item("control_type", "Pong")?;
                    let fields = PyDict::new(py);
                    fields.set_item("nonce", nonce)?;
                    mapping.set_item("fields", fields)?;
                }
                ConnectControlV1::ServerEvent { event } => {
                    mapping.set_item("control_type", "ServerEvent")?;
                    let fields = PyDict::new(py);
                    match event {
                        ServerEventV1::BlockProofs {
                            height,
                            entry_hash,
                            proofs_json,
                        } => {
                            fields.set_item("event_type", "BlockProofs")?;
                            fields.set_item("height", height)?;
                            fields.set_item("entry_hash", entry_hash)?;
                            fields.set_item("proofs_json", proofs_json)?;
                        }
                    }
                    mapping.set_item("fields", fields)?;
                }
            }
        }
        FrameKind::Ciphertext(ct) => {
            mapping.set_item("type", "Ciphertext")?;
            let fields = PyDict::new(py);
            fields.set_item("direction", connect_direction_str(ct.dir))?;
            fields.set_item("aead", PyBytes::new(py, &ct.aead))?;
            mapping.set_item("fields", fields)?;
        }
    }
    Ok(mapping.unbind())
}
fn decode_connect_frame_bytes(bytes: &[u8]) -> PyResult<ConnectFrameV1> {
    let (frame, used) = norito::core::decode_field_canonical::<ConnectFrameV1>(bytes)
        .map_err(|err| PyValueError::new_err(format!("failed to decode connect frame: {err}")))?;
    if used != bytes.len() {
        return Err(PyValueError::new_err(
            "connect frame payload contains trailing bytes",
        ));
    }
    Ok(frame)
}
fn sorafs_default_policy() -> AliasCachePolicy {
    AliasCachePolicy::new(
        Duration::from_secs(sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_REFRESH_WINDOW_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_HARD_EXPIRY_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_NEGATIVE_TTL_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_REVOCATION_TTL_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_ROTATION_MAX_AGE_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_SUCCESSOR_GRACE_SECS),
        Duration::from_secs(sorafs::DEFAULT_ALIAS_GOVERNANCE_GRACE_SECS),
    )
}
fn policy_override_u64<'py>(
    overrides: &Bound<'py, PyDict>,
    key: &str,
    allow_zero: bool,
) -> PyResult<Option<u64>> {
    let Some(value) = overrides.get_item(key)? else {
        return Ok(None);
    };
    if value.is_instance_of::<PyBool>() {
        return Err(PyValueError::new_err(format!("{key} must be an integer")));
    }
    let secs: u64 = value
        .extract()
        .map_err(|_| PyValueError::new_err(format!("{key} must be an integer")))?;
    if !allow_zero && secs == 0 {
        return Err(PyValueError::new_err(format!(
            "{key} must be greater than zero"
        )));
    }
    Ok(Some(secs))
}
fn alias_policy_from_py(overrides: Option<&Bound<'_, PyDict>>) -> PyResult<AliasCachePolicy> {
    let defaults = sorafs_default_policy();
    let mut positive = defaults.positive_ttl().as_secs();
    let mut refresh = defaults.refresh_window().as_secs();
    let mut hard = defaults.hard_expiry().as_secs();
    let mut negative = defaults.negative_ttl().as_secs();
    let mut revocation = defaults.revocation_ttl().as_secs();
    let mut rotation = defaults.rotation_max_age().as_secs();
    let mut successor = defaults.successor_grace().as_secs();
    let mut governance = defaults.governance_grace().as_secs();
    if let Some(mapping) = overrides {
        const FIELDS: [&str; 8] = [
            "positive_ttl_secs",
            "refresh_window_secs",
            "hard_expiry_secs",
            "negative_ttl_secs",
            "revocation_ttl_secs",
            "rotation_max_age_secs",
            "successor_grace_secs",
            "governance_grace_secs",
        ];
        for (key, _) in mapping.iter() {
            let key: String = key
                .extract()
                .map_err(|_| PyValueError::new_err("SoraFS alias policy fields must be strings"))?;
            if !FIELDS.contains(&key.as_str()) {
                return Err(PyValueError::new_err(format!(
                    "unsupported SoraFS alias policy field: {key}"
                )));
            }
        }
        if let Some(value) = policy_override_u64(mapping, "positive_ttl_secs", false)? {
            positive = value;
        }
        if let Some(value) = policy_override_u64(mapping, "refresh_window_secs", false)? {
            refresh = value;
        }
        if let Some(value) = policy_override_u64(mapping, "hard_expiry_secs", false)? {
            hard = value;
        }
        if let Some(value) = policy_override_u64(mapping, "negative_ttl_secs", false)? {
            negative = value;
        }
        if let Some(value) = policy_override_u64(mapping, "revocation_ttl_secs", false)? {
            revocation = value;
        }
        if let Some(value) = policy_override_u64(mapping, "rotation_max_age_secs", false)? {
            rotation = value;
        }
        if let Some(value) = policy_override_u64(mapping, "successor_grace_secs", true)? {
            successor = value;
        }
        if let Some(value) = policy_override_u64(mapping, "governance_grace_secs", true)? {
            governance = value;
        }
    }
    if refresh > positive {
        return Err(PyValueError::new_err(
            "refresh_window_secs must not exceed positive_ttl_secs",
        ));
    }
    if hard < positive {
        return Err(PyValueError::new_err(
            "hard_expiry_secs must be greater than or equal to positive_ttl_secs",
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
fn alias_policy_to_dict(py: Python<'_>, policy: &AliasCachePolicy) -> PyResult<Py<PyDict>> {
    let mapping = PyDict::new(py);
    mapping.set_item("positive_ttl_secs", policy.positive_ttl().as_secs())?;
    mapping.set_item("refresh_window_secs", policy.refresh_window().as_secs())?;
    mapping.set_item("hard_expiry_secs", policy.hard_expiry().as_secs())?;
    mapping.set_item("negative_ttl_secs", policy.negative_ttl().as_secs())?;
    mapping.set_item("revocation_ttl_secs", policy.revocation_ttl().as_secs())?;
    mapping.set_item("rotation_max_age_secs", policy.rotation_max_age().as_secs())?;
    mapping.set_item("successor_grace_secs", policy.successor_grace().as_secs())?;
    mapping.set_item("governance_grace_secs", policy.governance_grace().as_secs())?;
    Ok(mapping.unbind())
}
fn parse_hex_bytes_py(input: &str, context: &str) -> PyResult<Vec<u8>> {
    let trimmed = input.trim_start_matches("0x");
    if !trimmed.len().is_multiple_of(2) {
        return Err(PyValueError::new_err(format!(
            "{context} must contain an even number of hex characters"
        )));
    }
    hex::decode(trimmed)
        .map_err(|err| PyValueError::new_err(format!("failed to decode {context}: {err}")))
}
#[pyfunction]
#[pyo3(name = "sorafs_alias_policy_defaults")]
fn sorafs_alias_policy_defaults_py(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let policy = sorafs_default_policy();
    alias_policy_to_dict(py, &policy)
}
#[pyfunction]
#[pyo3(
    name = "sorafs_evaluate_alias_proof",
    signature = (proof_b64, policy_overrides=None, now_secs=None)
)]
fn sorafs_evaluate_alias_proof_py(
    py: Python<'_>,
    proof_b64: &str,
    policy_overrides: Option<&Bound<'_, PyDict>>,
    now_secs: Option<u64>,
) -> PyResult<Py<PyDict>> {
    let trimmed = proof_b64.trim();
    if trimmed.is_empty() {
        return Err(PyValueError::new_err("proof must not be empty"));
    }
    let policy = alias_policy_from_py(policy_overrides)?;
    let now = now_secs.unwrap_or_else(unix_now_secs);
    let proof_bytes = BASE64.decode(trimmed.as_bytes()).map_err(|err| {
        PyValueError::new_err(format!("failed to decode base64 alias proof: {err}"))
    })?;
    let bundle = decode_alias_proof_untrusted_signers(&proof_bytes)
        .map_err(|err| PyValueError::new_err(format!("invalid alias proof bundle: {err}")))?;
    let evaluation = policy.evaluate(&bundle, now);
    let state_label = match evaluation.state {
        AliasProofState::Fresh => "fresh",
        AliasProofState::RefreshWindow => "refresh_window",
        AliasProofState::Expired => "expired",
        AliasProofState::HardExpired => "hard_expired",
    };
    let dict = PyDict::new(py);
    dict.set_item("state", state_label)?;
    dict.set_item("status_label", evaluation.status_label())?;
    dict.set_item("rotation_due", evaluation.rotation_due)?;
    dict.set_item("age_seconds", evaluation.age.as_secs())?;
    dict.set_item("generated_at_unix", evaluation.generated_at_unix)?;
    dict.set_item("expires_at_unix", evaluation.expires_at_unix)?;
    if let Some(remain) = evaluation.expires_in {
        dict.set_item("expires_in_seconds", Some(remain.as_secs()))?;
    } else {
        dict.set_item("expires_in_seconds", Option::<u64>::None)?;
    }
    dict.set_item("servable", evaluation.state.is_servable())?;
    Ok(dict.unbind())
}
#[pyfunction]
#[pyo3(name = "sorafs_alias_proof_fixture", signature = (options=None))]
fn sorafs_alias_proof_fixture_py(
    py: Python<'_>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyDict>> {
    let mapping = options;
    let alias = if let Some(opts) = mapping {
        if let Some(value) = opts.get_item("alias")? {
            value
                .extract::<String>()
                .map_err(|_| PyValueError::new_err("alias must be a string when provided"))?
        } else {
            "docs/sora".to_owned()
        }
    } else {
        "docs/sora".to_owned()
    };
    let manifest_cid = if let Some(opts) = mapping {
        if let Some(value) = opts.get_item("manifest_cid_hex")? {
            let hex_str = value.extract::<String>().map_err(|_| {
                PyValueError::new_err("manifest_cid_hex must be a string when provided")
            })?;
            parse_hex_bytes_py(&hex_str, "manifest_cid_hex")?
        } else {
            sorafs_manifest::canonical_manifest_root_cid([0xAA; 32])
        }
    } else {
        sorafs_manifest::canonical_manifest_root_cid([0xAA; 32])
    };
    if manifest_cid.is_empty() {
        return Err(PyValueError::new_err(
            "manifest_cid_hex must not decode to an empty value",
        ));
    }
    let now = unix_now_secs();
    let generated = if let Some(opts) = mapping {
        if let Some(value) = opts.get_item("generated_at_unix")? {
            let secs: u64 = value.extract().map_err(|_| {
                PyValueError::new_err("generated_at_unix must be a non-negative integer")
            })?;
            secs
        } else {
            now.saturating_sub(60)
        }
    } else {
        now.saturating_sub(60)
    };
    let expires_default = || {
        generated
            .checked_add(sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS)
            .ok_or_else(|| {
                PyValueError::new_err("generated_at_unix overflows the default alias expiry")
            })
    };
    let expires = if let Some(opts) = mapping {
        if let Some(value) = opts.get_item("expires_at_unix")? {
            let secs: u64 = value.extract().map_err(|_| {
                PyValueError::new_err("expires_at_unix must be a non-negative integer")
            })?;
            secs
        } else {
            expires_default()?
        }
    } else {
        expires_default()?
    };
    if expires <= generated {
        return Err(PyValueError::new_err(
            "expires_at_unix must be greater than generated_at_unix",
        ));
    }
    let bound_at = if let Some(opts) = mapping {
        if let Some(value) = opts.get_item("bound_at_epoch")? {
            value.extract::<u64>().map_err(|_| {
                PyValueError::new_err("bound_at_epoch must be a non-negative integer")
            })?
        } else {
            1
        }
    } else {
        1
    };
    let expiry_epoch_default = || {
        bound_at.checked_add(100).ok_or_else(|| {
            PyValueError::new_err("bound_at_epoch overflows the default alias expiry")
        })
    };
    let expiry_epoch = if let Some(opts) = mapping {
        if let Some(value) = opts.get_item("expiry_epoch")? {
            value
                .extract::<u64>()
                .map_err(|_| PyValueError::new_err("expiry_epoch must be a non-negative integer"))?
        } else {
            expiry_epoch_default()?
        }
    } else {
        expiry_epoch_default()?
    };
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
    let root = alias_merkle_root(&bundle.binding, &bundle.merkle_path)
        .map_err(|err| PyValueError::new_err(format!("invalid alias proof bundle: {err}")))?;
    bundle.registry_root = root;
    let digest = alias_proof_signature_digest(&bundle);
    let keypair = KeyPair::from_private_key(
        PrivateKey::from_bytes(Algorithm::Ed25519, &[0x66; 32]).expect("seeded key"),
    )
    .expect("derive keypair");
    let signature = Signature::try_new(keypair.private_key(), digest.as_ref())
        .map_err(|err| PyValueError::new_err(format!("failed to sign alias proof: {err}")))?;
    let (_, signer_bytes) = public_key_to_bytes(keypair.public_key(), "alias proof signer")?;
    let signer: [u8; 32] = signer_bytes.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "alias proof signer must be 32 bytes, got {}",
            signer_bytes.len()
        ))
    })?;
    bundle
        .council_signatures
        .push(sorafs_manifest::CouncilSignature {
            signer,
            signature: signature.payload().to_vec(),
        });
    bundle
        .validate()
        .map_err(|err| PyValueError::new_err(format!("invalid alias proof bundle: {err}")))?;
    let proof_bytes = norito::to_bytes(&bundle)
        .map_err(|err| PyValueError::new_err(format!("failed to encode alias proof: {err}")))?;
    let proof_b64 = BASE64.encode(proof_bytes);
    let dict = PyDict::new(py);
    dict.set_item("alias", alias)?;
    dict.set_item("proof_b64", proof_b64)?;
    dict.set_item("generated_at_unix", generated)?;
    dict.set_item("expires_at_unix", expires)?;
    dict.set_item("registry_height", bundle.registry_height)?;
    dict.set_item("registry_root_hex", hex::encode(bundle.registry_root))?;
    Ok(dict.unbind())
}
#[derive(Clone, FromPyObject)]
struct PyRangeCapability {
    max_chunk_span: u32,
    min_granularity: u32,
    supports_sparse_offsets: Option<bool>,
    requires_alignment: Option<bool>,
    supports_merkle_proof: Option<bool>,
}
#[derive(Clone, FromPyObject)]
struct PyStreamBudget {
    max_in_flight: u16,
    max_bytes_per_sec: u64,
    burst_bytes: Option<u64>,
}
#[derive(Clone, FromPyObject)]
struct PyTransportHint {
    protocol: String,
    protocol_id: u8,
    priority: u8,
}
#[derive(Clone, FromPyObject)]
struct PyProviderMetadata {
    provider_id: Option<String>,
    profile_id: Option<String>,
    profile_aliases: Option<Vec<String>>,
    availability: Option<String>,
    stake_amount: Option<String>,
    max_streams: Option<u32>,
    refresh_deadline: Option<u64>,
    expires_at: Option<u64>,
    ttl_secs: Option<u64>,
    allow_unknown_capabilities: Option<bool>,
    capability_names: Option<Vec<String>>,
    rendezvous_topics: Option<Vec<String>>,
    notes: Option<String>,
    range_capability: Option<PyRangeCapability>,
    stream_budget: Option<PyStreamBudget>,
    transport_hints: Option<Vec<PyTransportHint>>,
}
#[derive(Clone, FromPyObject)]
struct PyTelemetryEntry {
    provider_id: String,
    qos_score: Option<f64>,
    latency_p95_ms: Option<f64>,
    failure_rate_ewma: Option<f64>,
    token_health: Option<f64>,
    staking_weight: Option<f64>,
    reputation_score_bps: Option<u16>,
    penalty: Option<bool>,
    last_updated_unix: Option<u64>,
}
#[derive(Clone, FromPyObject)]
struct PyProviderBoost {
    provider: String,
    delta: i64,
}
struct PyScorePolicy {
    deny: HashSet<String>,
    boosts: HashMap<String, i64>,
}
impl PyScorePolicy {
    fn new(deny: HashSet<String>, boosts: HashMap<String, i64>) -> Self {
        Self { deny, boosts }
    }
}
impl ScorePolicy for PyScorePolicy {
    fn score(&self, ctx: ProviderScoreContext<'_>) -> ProviderScoreDecision {
        let provider = ctx.provider.id().as_str();
        if self.deny.contains(provider) {
            return ProviderScoreDecision {
                priority_delta: 0,
                allow: false,
            };
        }
        let delta = self.boosts.get(provider).copied().unwrap_or(0);
        ProviderScoreDecision {
            priority_delta: delta,
            allow: true,
        }
    }
}
struct ProcessedPyProvider {
    name: String,
    max_concurrent: NonZeroUsize,
    weight: Option<NonZeroU32>,
    metadata: Option<ProviderMetadata>,
}
fn py_range_capability_to_internal(range: &PyRangeCapability) -> RangeCapability {
    RangeCapability {
        max_chunk_span: range.max_chunk_span,
        min_granularity: range.min_granularity,
        supports_sparse_offsets: range.supports_sparse_offsets.unwrap_or(true),
        requires_alignment: range.requires_alignment.unwrap_or(false),
        supports_merkle_proof: range.supports_merkle_proof.unwrap_or(true),
    }
}
fn py_stream_budget_to_internal(budget: &PyStreamBudget) -> StreamBudget {
    StreamBudget {
        max_in_flight: budget.max_in_flight,
        max_bytes_per_sec: budget.max_bytes_per_sec,
        burst_bytes: budget.burst_bytes,
    }
}
fn py_transport_hints_to_internal(hints: &[PyTransportHint]) -> Vec<TransportHint> {
    hints
        .iter()
        .map(|hint| TransportHint {
            protocol: hint.protocol.clone(),
            protocol_id: hint.protocol_id,
            priority: hint.priority,
        })
        .collect()
}
fn py_provider_metadata_to_internal(
    metadata: PyProviderMetadata,
    alias: &str,
) -> PyResult<ProviderMetadata> {
    let mut provider_metadata = ProviderMetadata::new();
    provider_metadata.provider_id = Some(metadata.provider_id.unwrap_or_else(|| alias.to_string()));
    provider_metadata.profile_id = metadata.profile_id;
    if let Some(aliases) = metadata.profile_aliases {
        provider_metadata.profile_aliases = aliases;
    }
    provider_metadata.availability = metadata.availability;
    provider_metadata.stake_amount = metadata.stake_amount;
    provider_metadata.max_streams = metadata.max_streams.map(|value| value as u16);
    provider_metadata.refresh_deadline = metadata.refresh_deadline;
    provider_metadata.expires_at = metadata.expires_at;
    provider_metadata.ttl_secs = metadata.ttl_secs;
    provider_metadata.allow_unknown_capabilities =
        metadata.allow_unknown_capabilities.unwrap_or(false);
    if let Some(names) = metadata.capability_names {
        provider_metadata.capability_names = names;
    }
    if let Some(notes) = metadata.notes {
        provider_metadata.notes = Some(notes);
    }
    if let Some(topics) = metadata.rendezvous_topics {
        provider_metadata.rendezvous_topics = topics;
    }
    if let Some(range) = metadata.range_capability {
        provider_metadata.range_capability = Some(py_range_capability_to_internal(&range));
    }
    if let Some(budget) = metadata.stream_budget {
        provider_metadata.stream_budget = Some(py_stream_budget_to_internal(&budget));
    }
    if let Some(hints) = metadata.transport_hints {
        provider_metadata.transport_hints = py_transport_hints_to_internal(&hints);
    }
    Ok(provider_metadata)
}
fn telemetry_snapshot_from_py(entries: &[PyTelemetryEntry]) -> PyResult<TelemetrySnapshot> {
    let records = entries
        .iter()
        .map(|entry| {
            if entry
                .reputation_score_bps
                .is_some_and(|score| score > 10_000)
            {
                return Err(PyValueError::new_err(
                    "telemetry reputation_score_bps must be in 0..=10000",
                ));
            }
            Ok(ProviderTelemetry {
                provider_id: entry.provider_id.clone(),
                qos_score: entry.qos_score,
                latency_p95_ms: entry.latency_p95_ms,
                failure_rate_ewma: entry.failure_rate_ewma,
                token_health: entry.token_health,
                staking_weight: entry.staking_weight,
                reputation_score_bps: entry.reputation_score_bps,
                penalty: entry.penalty.unwrap_or(false),
                last_updated_unix: entry.last_updated_unix,
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(TelemetrySnapshot::from_records(records))
}
#[derive(Clone, FromPyObject)]
struct PyLocalProviderSpec {
    name: String,
    path: String,
    max_concurrent: Option<usize>,
    weight: Option<u32>,
    metadata: Option<PyProviderMetadata>,
}
#[derive(Clone, Default, FromPyObject)]
struct PyMultiFetchOptions {
    verify_digests: Option<bool>,
    verify_lengths: Option<bool>,
    retry_budget: Option<usize>,
    provider_failure_threshold: Option<usize>,
    max_parallel: Option<usize>,
    max_peers: Option<usize>,
    chunker_handle: Option<String>,
    telemetry_region: Option<String>,
    telemetry: Option<Vec<PyTelemetryEntry>>,
    use_scoreboard: Option<bool>,
    deny_providers: Option<Vec<String>>,
    boost_providers: Option<Vec<PyProviderBoost>>,
    return_scoreboard: Option<bool>,
    scoreboard_out_path: Option<String>,
    scoreboard_now_unix_secs: Option<u64>,
    scoreboard_telemetry_label: Option<String>,
}
fn derive_python_scoreboard_label(
    options: &PyMultiFetchOptions,
    persist_path: bool,
) -> Option<String> {
    if let Some(label) = options
        .scoreboard_telemetry_label
        .as_deref()
        .map(str::trim)
        .filter(|trimmed| !trimmed.is_empty())
    {
        return Some(label.to_string());
    }
    if persist_path {
        Some("sdk:python".to_string())
    } else {
        None
    }
}
fn option_usize_to_json_value(value: Option<usize>) -> json::Value {
    value
        .and_then(|val| u64::try_from(val).ok())
        .map_or(json::Value::Null, json::Value::from)
}
fn transport_policy_labels(
    requested: TransportPolicy,
    override_policy: Option<TransportPolicy>,
) -> (&'static str, bool, Option<&'static str>) {
    match override_policy {
        Some(policy) => (policy.label(), true, Some(policy.label())),
        None => (requested.label(), false, None),
    }
}
fn anonymity_policy_labels(
    requested: AnonymityPolicy,
    override_policy: Option<AnonymityPolicy>,
) -> (&'static str, bool, Option<&'static str>) {
    match override_policy {
        Some(policy) => (policy.label(), true, Some(policy.label())),
        None => (requested.label(), false, None),
    }
}
#[allow(clippy::too_many_arguments)]
fn python_scoreboard_metadata(
    provider_count: usize,
    gateway_provider_count: usize,
    gateway_manifest_provided: bool,
    assume_now: u64,
    telemetry_label: &str,
    telemetry_region: Option<&str>,
    max_parallel: Option<usize>,
    max_peers: Option<usize>,
    retry_budget: Option<usize>,
    provider_failure_threshold: Option<usize>,
    transport_policy: TransportPolicy,
    transport_override: Option<TransportPolicy>,
    anonymity_policy: AnonymityPolicy,
    anonymity_override: Option<AnonymityPolicy>,
) -> json::Value {
    let mut map = json::Map::new();
    map.insert(
        "version".into(),
        json::Value::from(env!("CARGO_PKG_VERSION")),
    );
    map.insert("use_scoreboard".into(), json::Value::from(true));
    map.insert("allow_implicit_metadata".into(), json::Value::from(false));
    map.insert(
        "provider_count".into(),
        json::Value::from(u64::try_from(provider_count).unwrap_or(u64::MAX)),
    );
    map.insert(
        "gateway_provider_count".into(),
        json::Value::from(u64::try_from(gateway_provider_count).unwrap_or(u64::MAX)),
    );
    map.insert(
        "max_parallel".into(),
        option_usize_to_json_value(max_parallel),
    );
    map.insert("max_peers".into(), option_usize_to_json_value(max_peers));
    map.insert(
        "retry_budget".into(),
        option_usize_to_json_value(retry_budget),
    );
    map.insert(
        "provider_failure_threshold".into(),
        option_usize_to_json_value(provider_failure_threshold),
    );
    map.insert("assume_now".into(), json::Value::from(assume_now));
    map.insert(
        "telemetry_source".into(),
        json::Value::from(telemetry_label.to_string()),
    );
    map.insert(
        "telemetry_region".into(),
        telemetry_region
            .map(|label| json::Value::from(label.to_string()))
            .unwrap_or(json::Value::Null),
    );
    map.insert(
        "gateway_manifest_provided".into(),
        json::Value::from(gateway_manifest_provided),
    );
    let (transport_label, transport_override_flag, transport_override_label) =
        transport_policy_labels(transport_policy, transport_override);
    map.insert(
        "transport_policy".into(),
        json::Value::from(transport_label),
    );
    map.insert(
        "transport_policy_override".into(),
        json::Value::from(transport_override_flag),
    );
    map.insert(
        "transport_policy_override_label".into(),
        transport_override_label
            .map(json::Value::from)
            .unwrap_or(json::Value::Null),
    );
    let (anonymity_label, anonymity_override_flag, anonymity_override_label) =
        anonymity_policy_labels(anonymity_policy, anonymity_override);
    map.insert(
        "anonymity_policy".into(),
        json::Value::from(anonymity_label),
    );
    map.insert(
        "anonymity_policy_override".into(),
        json::Value::from(anonymity_override_flag),
    );
    map.insert(
        "anonymity_policy_override_label".into(),
        anonymity_override_label
            .map(json::Value::from)
            .unwrap_or(json::Value::Null),
    );
    json::Value::Object(map)
}
fn provider_mix_label_from_counts(direct: u64, gateway: u64) -> &'static str {
    match (direct > 0, gateway > 0) {
        (true, true) => "mixed",
        (true, false) => "direct-only",
        (false, true) => "gateway-only",
        (false, false) => "none",
    }
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_gateway_metadata_dict(
    py: Python<'_>,
    provider_count: usize,
    gateway_provider_count: usize,
    config: &OrchestratorConfig,
    telemetry_label: Option<&str>,
    telemetry_region: Option<&str>,
    manifest_id: &str,
    manifest_cid_hex: Option<&str>,
    manifest_envelope_present: bool,
    allow_implicit_metadata: bool,
) -> PyResult<Py<PyDict>> {
    let metadata = PyDict::new(py);
    let direct_count = u64::try_from(provider_count).unwrap_or(u64::MAX);
    let gateway_count = u64::try_from(gateway_provider_count).unwrap_or(u64::MAX);
    metadata.set_item("provider_count", direct_count)?;
    metadata.set_item("gateway_provider_count", gateway_count)?;
    metadata.set_item(
        "provider_mix",
        provider_mix_label_from_counts(direct_count, gateway_count),
    )?;
    let (transport_label, transport_override_flag, transport_override_label) =
        transport_policy_labels(
            config.transport_policy,
            config.policy_override.transport_policy,
        );
    metadata.set_item("transport_policy", transport_label)?;
    metadata.set_item("transport_policy_override", transport_override_flag)?;
    if let Some(label) = transport_override_label {
        metadata.set_item("transport_policy_override_label", label)?;
    } else {
        metadata.set_item("transport_policy_override_label", py.None())?;
    }
    let (anonymity_label, anonymity_override_flag, anonymity_override_label) =
        anonymity_policy_labels(
            config.anonymity_policy,
            config.policy_override.anonymity_policy,
        );
    metadata.set_item("anonymity_policy", anonymity_label)?;
    metadata.set_item("anonymity_policy_override", anonymity_override_flag)?;
    if let Some(label) = anonymity_override_label {
        metadata.set_item("anonymity_policy_override_label", label)?;
    } else {
        metadata.set_item("anonymity_policy_override_label", py.None())?;
    }
    if let Some(limit) = config.fetch.global_parallel_limit {
        let converted = u64::try_from(limit).unwrap_or(u64::MAX);
        metadata.set_item("max_parallel", converted)?;
    } else {
        metadata.set_item("max_parallel", py.None())?;
    }
    if let Some(limit) = config.max_providers {
        let converted = u64::try_from(limit.get()).unwrap_or(u64::MAX);
        metadata.set_item("max_peers", converted)?;
    } else {
        metadata.set_item("max_peers", py.None())?;
    }
    if let Some(limit) = config.fetch.per_chunk_retry_limit {
        let converted = u64::try_from(limit).unwrap_or(u64::MAX);
        metadata.set_item("retry_budget", converted)?;
    } else {
        metadata.set_item("retry_budget", py.None())?;
    }
    let provider_failure_threshold =
        u64::try_from(config.fetch.provider_failure_threshold).unwrap_or(u64::MAX);
    metadata.set_item("provider_failure_threshold", provider_failure_threshold)?;
    metadata.set_item("assume_now_unix", config.scoreboard.now_unix_secs)?;
    if let Some(label) = telemetry_label {
        metadata.set_item("telemetry_source_label", label)?;
    } else {
        metadata.set_item("telemetry_source_label", py.None())?;
    }
    if let Some(region) = telemetry_region {
        metadata.set_item("telemetry_region", region)?;
    } else {
        metadata.set_item("telemetry_region", py.None())?;
    }
    metadata.set_item("gateway_manifest_provided", manifest_envelope_present)?;
    metadata.set_item("gateway_manifest_id", manifest_id)?;
    if let Some(cid) = manifest_cid_hex {
        metadata.set_item("gateway_manifest_cid", cid)?;
    } else {
        metadata.set_item("gateway_manifest_cid", py.None())?;
    }
    metadata.set_item("allow_implicit_metadata", allow_implicit_metadata)?;
    Ok(metadata.unbind())
}
#[derive(Clone, FromPyObject)]
struct PyGatewayProviderSpec {
    name: String,
    provider_id_hex: String,
    gateway_public_key_hex: String,
    base_url: String,
    stream_token_b64: String,
    privacy_events_url: Option<String>,
}
const MAX_GATEWAY_PROVIDER_NAME_BYTES: usize = 128;
const MAX_GATEWAY_URL_BYTES: usize = 2_048;
const MAX_GATEWAY_TOKEN_BASE64_BYTES: usize = 90 * 1_024;
const MAX_GATEWAY_TOKEN_BYTES: usize = 64 * 1_024;
fn canonical_gateway_hex32(value: &str, field: &str) -> PyResult<String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(PyValueError::new_err(format!(
            "{field} must be non-zero canonical lowercase 32-byte hex"
        )));
    }
    Ok(value.to_owned())
}
fn canonical_gateway_token(value: &str) -> PyResult<String> {
    if value.is_empty() || value.len() > MAX_GATEWAY_TOKEN_BASE64_BYTES || value != value.trim() {
        return Err(PyValueError::new_err(
            "stream_token_b64 must be exact canonical standard base64",
        ));
    }
    let bytes = BASE64.decode(value).map_err(|_| {
        PyValueError::new_err("stream_token_b64 must be exact canonical standard base64")
    })?;
    if bytes.is_empty() || bytes.len() > MAX_GATEWAY_TOKEN_BYTES || BASE64.encode(bytes) != value {
        return Err(PyValueError::new_err(
            "stream_token_b64 must be exact canonical standard base64",
        ));
    }
    Ok(value.to_owned())
}
fn canonical_gateway_url(value: &str, field: &str, expected_path: &str) -> PyResult<String> {
    if value.is_empty()
        || value.len() > MAX_GATEWAY_URL_BYTES
        || value != value.trim()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PyValueError::new_err(format!(
            "{field} must be an exact canonical HTTPS URL"
        )));
    }
    let url = Url::parse(value).map_err(|_| {
        PyValueError::new_err(format!("{field} must be an exact canonical HTTPS URL"))
    })?;
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PyValueError::new_err(format!(
            "{field} must be an exact public HTTPS origin"
        )));
    }
    let host = url
        .host()
        .ok_or_else(|| PyValueError::new_err(format!("{field} must contain a canonical host")))?;
    let non_public = match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => !gateway_ip_is_public(IpAddr::V4(address)),
        Host::Ipv6(address) => !gateway_ip_is_public(IpAddr::V6(address)),
    };
    if non_public {
        return Err(PyValueError::new_err(format!(
            "{field} must not target a non-public address"
        )));
    }
    let origin = url.origin().ascii_serialization();
    let exact = if expected_path == "/" {
        value == origin || value == format!("{origin}/")
    } else {
        value == format!("{origin}{expected_path}")
    };
    if !exact || url.path() != expected_path {
        return Err(PyValueError::new_err(format!(
            "{field} must use the exact {expected_path} path"
        )));
    }
    Ok(value.to_owned())
}
fn gateway_ip_is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, third, _] = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !address.is_unspecified()
                && !address.is_multicast()
                && first != 0
                && !(first == 100 && (64..=127).contains(&second))
                && !(first == 192 && second == 0 && third == 0)
                && !(first == 192 && second == 88 && third == 99)
                && !(first == 198 && (18..=19).contains(&second))
                && first < 240
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            let global_unicast = segments[0] & 0xe000 == 0x2000;
            let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);
            let special_purpose = segments[0] == 0x2001 && segments[1] <= 0x01ff;
            global_unicast
                && !documentation
                && !special_purpose
                && segments[0] != 0x2002
                && !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
        }
    }
}
fn canonical_gateway_provider(spec: PyGatewayProviderSpec) -> PyResult<GatewayProviderInput> {
    if spec.name.is_empty()
        || spec.name.len() > MAX_GATEWAY_PROVIDER_NAME_BYTES
        || !spec
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'_'))
    {
        return Err(PyValueError::new_err(
            "provider name must be canonical ASCII and at most 128 bytes",
        ));
    }
    let provider_id_hex = canonical_gateway_hex32(&spec.provider_id_hex, "provider_id_hex")?;
    let gateway_public_key_hex =
        canonical_gateway_hex32(&spec.gateway_public_key_hex, "gateway_public_key_hex")?;
    let base_url = canonical_gateway_url(&spec.base_url, "base_url", "/")?;
    let stream_token_b64 = canonical_gateway_token(&spec.stream_token_b64)?;
    let privacy_events_url = spec
        .privacy_events_url
        .map(|value| canonical_gateway_url(&value, "privacy_events_url", "/privacy/events"))
        .transpose()?;
    Ok(GatewayProviderInput {
        name: spec.name,
        provider_id_hex,
        gateway_public_key_hex,
        base_url,
        stream_token_b64,
        privacy_events_url,
    })
}
#[derive(Clone, Default, FromPyObject)]
struct PyGatewayFetchOptions {
    manifest_envelope_b64: Option<String>,
    manifest_cid_hex: Option<String>,
    expected_cache_version: Option<String>,
    client_id: Option<String>,
    telemetry_region: Option<String>,
    scoreboard_telemetry_label: Option<String>,
    rollout_phase: Option<String>,
    max_peers: Option<usize>,
    retry_budget: Option<usize>,
    transport_policy: Option<String>,
    anonymity_policy: Option<String>,
    local_proxy: Option<PyLocalProxyOptions>,
}
#[derive(Clone, Default, FromPyObject)]
struct PyLocalProxyOptions {
    bind_addr: Option<String>,
    telemetry_label: Option<String>,
    guard_cache_key_hex: Option<String>,
    emit_browser_manifest: Option<bool>,
    proxy_mode: Option<String>,
    prewarm_circuits: Option<bool>,
    max_streams_per_circuit: Option<u32>,
    circuit_ttl_hint_secs: Option<u32>,
    norito_bridge: Option<PyLocalProxyNoritoBridgeOptions>,
    car_bridge: Option<PyLocalProxyCarBridgeOptions>,
    kaigi_bridge: Option<PyLocalProxyKaigiBridgeOptions>,
}
#[derive(Clone, Default, FromPyObject)]
struct PyLocalProxyNoritoBridgeOptions {
    spool_dir: String,
    extension: Option<String>,
}
#[derive(Clone, Default, FromPyObject)]
struct PyLocalProxyCarBridgeOptions {
    cache_dir: String,
    extension: Option<String>,
    allow_zst: Option<bool>,
}
#[derive(Clone, Default, FromPyObject)]
struct PyLocalProxyKaigiBridgeOptions {
    spool_dir: String,
    extension: Option<String>,
    room_policy: Option<String>,
}
fn chunk_verification_error_payload(
    py: Python<'_>,
    error: ChunkVerificationError,
) -> PyResult<Py<PyDict>> {
    let payload = PyDict::new(py);
    match error {
        ChunkVerificationError::LengthMismatch { expected, actual } => {
            payload.set_item("type", "length_mismatch")?;
            payload.set_item("expected", expected)?;
            payload.set_item("actual", actual)?;
        }
        ChunkVerificationError::DigestMismatch { expected, actual } => {
            payload.set_item("type", "digest_mismatch")?;
            payload.set_item("expected", hex_encode(expected))?;
            payload.set_item("actual", hex_encode(actual))?;
        }
    }
    Ok(payload.into())
}
fn capability_mismatch_payload(
    py: Python<'_>,
    mismatch: CapabilityMismatch,
) -> PyResult<Py<PyDict>> {
    let payload = PyDict::new(py);
    match mismatch {
        CapabilityMismatch::MissingRangeCapability => {
            payload.set_item("type", "missing_range_capability")?;
        }
        CapabilityMismatch::ChunkTooLarge {
            chunk_length,
            max_span,
        } => {
            payload.set_item("type", "chunk_too_large")?;
            payload.set_item("chunk_length", chunk_length)?;
            payload.set_item("max_span", max_span)?;
        }
        CapabilityMismatch::OffsetMisaligned {
            offset,
            required_alignment,
        } => {
            payload.set_item("type", "offset_misaligned")?;
            payload.set_item("offset", offset)?;
            payload.set_item("required_alignment", required_alignment)?;
        }
        CapabilityMismatch::LengthMisaligned {
            length,
            required_alignment,
        } => {
            payload.set_item("type", "length_misaligned")?;
            payload.set_item("length", length)?;
            payload.set_item("required_alignment", required_alignment)?;
        }
        CapabilityMismatch::StreamBurstTooSmall {
            chunk_length,
            burst_limit,
        } => {
            payload.set_item("type", "stream_burst_too_small")?;
            payload.set_item("chunk_length", chunk_length)?;
            payload.set_item("burst_limit", burst_limit)?;
        }
    }
    Ok(payload.into())
}
fn attempt_failure_payload(py: Python<'_>, failure: AttemptFailure) -> PyResult<Py<PyDict>> {
    let payload = PyDict::new(py);
    match failure {
        AttemptFailure::Provider {
            message,
            policy_block,
        } => {
            payload.set_item("type", "provider")?;
            payload.set_item("message", message)?;
            if let Some(policy) = policy_block {
                let policy_dict = PyDict::new(py);
                policy_dict.set_item("observed_status", policy.observed_status.as_u16())?;
                policy_dict.set_item("code", policy.code)?;
                policy_dict.set_item("source", policy.source)?;
                policy_dict.set_item("catalog_digest_hex", policy.catalog_digest_hex)?;
                payload.set_item("policy_block", policy_dict)?;
            }
        }
        AttemptFailure::InvalidChunk(error) => {
            payload.set_item("type", "invalid_chunk")?;
            payload.set_item("error", chunk_verification_error_payload(py, error)?)?;
        }
    }
    Ok(payload.into())
}
fn attempt_error_payload(py: Python<'_>, error: AttemptError) -> PyResult<Py<PyDict>> {
    let AttemptError { provider, failure } = error;
    let provider_name = provider.as_str().to_owned();
    let payload = PyDict::new(py);
    payload.set_item("provider", provider_name)?;
    payload.set_item("failure", attempt_failure_payload(py, failure)?)?;
    Ok(payload.into())
}
fn sorafs_multi_fetch_error(py: Python<'_>, err: MultiSourceError) -> PyErr {
    match build_multi_fetch_error_payload(py, err) {
        Ok(payload) => SorafsMultiFetchError::new_err(payload),
        Err(py_err) => py_err,
    }
}
fn build_multi_fetch_error_payload(py: Python<'_>, err: MultiSourceError) -> PyResult<Py<PyDict>> {
    let payload = PyDict::new(py);
    payload.set_item("message", err.to_string())?;
    match err {
        MultiSourceError::ResourceLimit(reason) => {
            payload.set_item("kind", "resource_limit")?;
            payload.set_item("reason", reason)?;
        }
        MultiSourceError::DeadlineExceeded => {
            payload.set_item("kind", "deadline_exceeded")?;
        }
        MultiSourceError::InvalidPlan(reason) => {
            payload.set_item("kind", "invalid_plan")?;
            payload.set_item("reason", reason.to_string())?;
        }
        MultiSourceError::NoProviders => {
            payload.set_item("kind", "no_providers")?;
        }
        MultiSourceError::NoHealthyProviders {
            chunk_index,
            attempts,
            last_error,
        } => {
            payload.set_item("kind", "no_healthy_providers")?;
            payload.set_item("chunk_index", chunk_index)?;
            payload.set_item("attempts", attempts)?;
            if let Some(error) = last_error {
                payload.set_item("last_error", attempt_error_payload(py, *error)?)?;
            } else {
                payload.set_item("last_error", py.None())?;
            }
        }
        MultiSourceError::NoCompatibleProviders {
            chunk_index,
            providers,
        } => {
            payload.set_item("kind", "no_compatible_providers")?;
            payload.set_item("chunk_index", chunk_index)?;
            let entries = PyList::empty(py);
            for (provider, reason) in providers {
                let entry = PyDict::new(py);
                entry.set_item("provider", provider.as_str())?;
                entry.set_item("reason", capability_mismatch_payload(py, reason)?)?;
                entries.append(entry)?;
            }
            payload.set_item("providers", entries)?;
        }
        MultiSourceError::NoPolicyEligibleProviders {
            chunk_index,
            providers,
        } => {
            payload.set_item("kind", "no_policy_eligible_providers")?;
            payload.set_item("chunk_index", chunk_index)?;
            let providers = providers
                .into_iter()
                .map(|provider| provider.as_str().to_owned())
                .collect::<Vec<_>>();
            payload.set_item("providers", providers)?;
        }
        MultiSourceError::ExhaustedRetries {
            chunk_index,
            attempts,
            last_error,
        } => {
            payload.set_item("kind", "exhausted_retries")?;
            payload.set_item("chunk_index", chunk_index)?;
            payload.set_item("attempts", attempts)?;
            payload.set_item("last_error", attempt_error_payload(py, *last_error)?)?;
        }
        MultiSourceError::ObserverFailed {
            chunk_index,
            source,
        } => {
            payload.set_item("kind", "observer_failed")?;
            payload.set_item("chunk_index", chunk_index)?;
            payload.set_item("observer_error", source.to_string())?;
        }
        MultiSourceError::InternalInvariant(reason) => {
            payload.set_item("kind", "internal_invariant")?;
            payload.set_item("reason", reason)?;
        }
    }
    Ok(payload.into())
}
#[pyfunction(
    name = "sorafs_multi_fetch_local",
    signature = (plan_json, providers, *, options=None)
)]
fn sorafs_multi_fetch_local_py(
    py: Python<'_>,
    plan_json: &str,
    providers: Vec<PyLocalProviderSpec>,
    options: Option<PyMultiFetchOptions>,
) -> PyResult<Py<PyDict>> {
    if providers.is_empty() {
        return Err(PyValueError::new_err(
            "providers list must contain at least one entry",
        ));
    }
    let options = options.unwrap_or_default();
    let plan_value: json::Value = json::from_str(plan_json)
        .map_err(|err| PyValueError::new_err(format!("failed to parse plan JSON: {err}")))?;
    let parsed_plan = chunk_fetch_plan_from_json(&plan_value)
        .map_err(|err| PyValueError::new_err(format!("invalid chunk fetch plan: {err}")))?;
    let plan_payload_digest = parsed_plan.payload_digest;
    let chunk_specs = parsed_plan.chunk_fetch_specs;
    if chunk_specs.is_empty() {
        return Err(PyValueError::new_err(
            "chunk fetch plan must contain at least one chunk",
        ));
    }
    let content_length = chunk_specs
        .iter()
        .map(|spec| spec.offset + u64::from(spec.length))
        .max()
        .unwrap_or(0);
    let chunk_profile = if let Some(handle) = options.chunker_handle.as_deref() {
        let descriptor = sorafs_car::chunker_registry::lookup_by_handle(handle)
            .ok_or_else(|| PyValueError::new_err(format!("unknown chunker handle '{handle}'")))?;
        descriptor.profile
    } else {
        ChunkProfile::DEFAULT
    };
    let plan = CarBuildPlan {
        chunk_profile,
        payload_digest: blake3::Hash::from_bytes(plan_payload_digest),
        content_length,
        chunks: chunk_specs
            .iter()
            .map(|spec| CarChunk {
                offset: spec.offset,
                length: spec.length,
                digest: spec.digest,
            })
            .collect(),
        files: vec![FilePlan {
            path: Vec::new(),
            first_chunk: 0,
            chunk_count: chunk_specs.len(),
            size: content_length,
        }],
    };
    let mut processed = Vec::with_capacity(providers.len());
    let mut provider_names = HashSet::new();
    let mut raw_path_lookup: HashMap<String, PathBuf> = HashMap::new();
    for spec in providers {
        if !provider_names.insert(spec.name.clone()) {
            return Err(PyValueError::new_err(format!(
                "duplicate provider '{}'",
                spec.name
            )));
        }
        let path = PathBuf::from(&spec.path);
        if !path.exists() {
            return Err(PyValueError::new_err(format!(
                "provider payload '{}' does not exist",
                spec.path
            )));
        }
        if !path.is_file() {
            return Err(PyValueError::new_err(format!(
                "provider payload '{}' is not a regular file",
                spec.path
            )));
        }
        raw_path_lookup.insert(spec.name.clone(), path.clone());
        let max_concurrent = spec
            .max_concurrent
            .and_then(NonZeroUsize::new)
            .unwrap_or_else(|| NonZeroUsize::new(2).expect("constant non-zero"));
        let weight = match spec.weight {
            Some(value) => Some(NonZeroU32::new(value).ok_or_else(|| {
                PyValueError::new_err("provider weight must be greater than zero")
            })?),
            None => None,
        };
        let metadata = match spec.metadata {
            Some(meta) => {
                let provider_metadata = py_provider_metadata_to_internal(meta, &spec.name)?;
                if let Some(provider_id) = provider_metadata.provider_id.clone() {
                    raw_path_lookup.insert(provider_id, path.clone());
                }
                Some(provider_metadata)
            }
            None => None,
        };
        processed.push(ProcessedPyProvider {
            name: spec.name,
            max_concurrent,
            weight,
            metadata,
        });
    }
    if options.scoreboard_telemetry_label.is_some() && options.scoreboard_out_path.is_none() {
        return Err(PyValueError::new_err(
            "scoreboard_telemetry_label requires scoreboard_out_path to be set",
        ));
    }
    let telemetry_region = if let Some(raw) = options.telemetry_region.as_ref() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(PyValueError::new_err("telemetry_region must not be empty"));
        }
        Some(trimmed.to_string())
    } else {
        None
    };
    let provider_count = processed.len();
    let mut scoreboard_config = ScoreboardConfig::default();
    if let Some(now) = options.scoreboard_now_unix_secs {
        scoreboard_config.now_unix_secs = now;
    }
    let scoreboard_out_raw = options
        .scoreboard_out_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(path_str) = scoreboard_out_raw {
        let path = PathBuf::from(path_str);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|err| {
                PyValueError::new_err(format!(
                    "failed to create scoreboard directory `{}`: {err}",
                    parent.display()
                ))
            })?;
        }
        scoreboard_config.persist_path = Some(path);
        if let Some(label) = derive_python_scoreboard_label(&options, true) {
            scoreboard_config.persist_metadata = Some(python_scoreboard_metadata(
                provider_count,
                0,
                false,
                scoreboard_config.now_unix_secs,
                &label,
                telemetry_region.as_deref(),
                options.max_parallel,
                options.max_peers,
                options.retry_budget,
                options.provider_failure_threshold,
                TransportPolicy::SoranetPreferred,
                None,
                AnonymityPolicy::GuardPq,
                None,
            ));
        }
    }
    let telemetry_snapshot = options.telemetry.as_ref().map_or_else(
        || Ok(TelemetrySnapshot::default()),
        |entries| telemetry_snapshot_from_py(entries),
    )?;
    let telemetry_provided = options
        .telemetry
        .as_ref()
        .is_some_and(|entries| !entries.is_empty());
    let scoreboard_requested = options.use_scoreboard.unwrap_or(false)
        || telemetry_provided
        || scoreboard_config.persist_path.is_some();
    let mut alias_by_provider_id: HashMap<String, String> = HashMap::new();
    let scoreboard_metadata = if scoreboard_requested {
        let mut list = Vec::with_capacity(processed.len());
        for provider in processed.iter_mut() {
            let mut metadata = provider.metadata.clone().ok_or_else(|| {
                PyValueError::new_err(format!(
                    "scoreboard requires metadata for provider '{}' (provide advert metadata or disable use_scoreboard)",
                    provider.name
                ))
            })?;
            let provider_id = metadata
                .provider_id
                .clone()
                .unwrap_or_else(|| provider.name.clone());
            alias_by_provider_id.insert(provider_id.clone(), provider.name.clone());
            if !raw_path_lookup.contains_key(&provider_id)
                && let Some(path) = raw_path_lookup.get(&provider.name)
            {
                raw_path_lookup.insert(provider_id.clone(), path.clone());
            }
            metadata.provider_id = Some(provider_id);
            provider.metadata = Some(metadata.clone());
            list.push(metadata);
        }
        list
    } else {
        Vec::new()
    };
    let scoreboard = if scoreboard_requested {
        Some(
            scoreboard::build_scoreboard(
                &plan,
                &scoreboard_metadata,
                &telemetry_snapshot,
                &scoreboard_config,
            )
            .map_err(|err| PyValueError::new_err(format!("failed to build scoreboard: {err}")))?,
        )
    } else {
        None
    };
    let include_scoreboard = options.return_scoreboard.unwrap_or(scoreboard_requested);
    let mut eligible_aliases: HashSet<String> = HashSet::new();
    let mut weight_by_alias: HashMap<String, NonZeroU32> = HashMap::new();
    let scoreboard_export = if let Some(scoreboard) = scoreboard.as_ref() {
        let mut entries: Vec<(String, String, f64, f64, String)> =
            Vec::with_capacity(scoreboard.entries().len());
        for entry in scoreboard.entries() {
            let provider_id = entry.provider.id().as_str();
            let alias = alias_by_provider_id
                .get(provider_id)
                .cloned()
                .unwrap_or_else(|| provider_id.to_string());
            match &entry.eligibility {
                Eligibility::Eligible => {
                    eligible_aliases.insert(alias.clone());
                    weight_by_alias.insert(alias.clone(), entry.provider.weight());
                    entries.push((
                        provider_id.to_string(),
                        alias,
                        entry.raw_score,
                        entry.normalised_weight,
                        "eligible".to_string(),
                    ));
                }
                Eligibility::Ineligible(reason) => {
                    entries.push((
                        provider_id.to_string(),
                        alias,
                        entry.raw_score,
                        entry.normalised_weight,
                        reason.to_string(),
                    ));
                }
            }
        }
        if scoreboard_requested && eligible_aliases.is_empty() {
            return Err(PyValueError::new_err("scoreboard excluded all providers"));
        }
        if include_scoreboard {
            Some(entries)
        } else {
            None
        }
    } else {
        None
    };
    let mut fetch_providers = Vec::with_capacity(processed.len());
    for provider in &processed {
        if scoreboard_requested && !eligible_aliases.contains(&provider.name) {
            continue;
        }
        let mut fetch_provider = FetchProvider::new(provider.name.clone())
            .with_max_concurrent_chunks(provider.max_concurrent);
        if let Some(weight) = weight_by_alias
            .get(&provider.name)
            .copied()
            .or(provider.weight)
        {
            fetch_provider = fetch_provider.with_weight(weight);
        }
        if let Some(metadata) = &provider.metadata {
            fetch_provider = fetch_provider.with_metadata(metadata.clone());
        }
        fetch_providers.push(fetch_provider);
    }
    if fetch_providers.is_empty() {
        return Err(PyValueError::new_err(
            "no providers available after applying scoreboard filters",
        ));
    }
    if let Some(limit) = options.max_peers {
        let limit = limit.max(1);
        if fetch_providers.len() > limit {
            fetch_providers.truncate(limit);
        }
    }
    let mut provider_paths: HashMap<String, PathBuf> = HashMap::new();
    for provider in &fetch_providers {
        if let Some(path) = raw_path_lookup.get(provider.id().as_str()) {
            provider_paths.insert(provider.id().as_str().to_string(), path.clone());
        }
        if let Some(metadata) = provider.metadata()
            && let Some(provider_id) = metadata.provider_id.as_ref()
            && let Some(path) = raw_path_lookup.get(provider_id)
        {
            provider_paths.insert(provider_id.clone(), path.clone());
        }
    }
    let path_map = Arc::new(provider_paths);
    let fetcher = move |request: FetchRequest| {
        let map = Arc::clone(&path_map);
        async move {
            let provider_name = request.provider.id().as_str();
            let path = map.get(provider_name).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("unknown provider '{provider_name}'"),
                )
            })?;
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(request.spec.offset))?;
            let mut buf = vec![0u8; request.spec.length as usize];
            file.read_exact(&mut buf)?;
            Ok::<ChunkResponse, std::io::Error>(ChunkResponse::new(buf))
        }
    };
    let mut fetch_options = FetchOptions::default();
    if let Some(flag) = options.verify_digests {
        fetch_options.verify_digests = flag;
    }
    if let Some(flag) = options.verify_lengths {
        fetch_options.verify_lengths = flag;
    }
    if let Some(limit) = options.retry_budget {
        fetch_options.per_chunk_retry_limit = Some(limit.max(1));
    }
    if let Some(threshold) = options.provider_failure_threshold {
        fetch_options.provider_failure_threshold = threshold;
    }
    if let Some(limit) = options.max_parallel {
        fetch_options.global_parallel_limit = Some(limit.max(1));
    }
    let policy_requested = options
        .deny_providers
        .as_ref()
        .is_some_and(|deny| !deny.is_empty())
        || options
            .boost_providers
            .as_ref()
            .is_some_and(|boosts| !boosts.is_empty());
    if policy_requested {
        let mut deny = HashSet::new();
        if let Some(entries) = options.deny_providers.as_ref() {
            for provider in entries {
                deny.insert(provider.clone());
            }
        }
        let mut boosts = HashMap::new();
        if let Some(entries) = options.boost_providers.as_ref() {
            for boost in entries {
                boosts.insert(boost.provider.clone(), boost.delta);
            }
        }
        fetch_options.score_policy = Some(Arc::new(PyScorePolicy::new(deny, boosts)));
    }
    let outcome = block_on(fetch_plan_parallel(
        &plan,
        fetch_providers,
        fetcher,
        fetch_options,
    ))
    .map_err(|err| sorafs_multi_fetch_error(py, err))?;
    let payload_bytes = outcome.assemble_payload();
    if blake3_hash(&payload_bytes) != plan.payload_digest {
        return Err(PyValueError::new_err(
            "assembled payload digest does not match canonical chunk fetch plan",
        ));
    }
    let result = PyDict::new(py);
    result.set_item("chunk_count", outcome.chunks.len())?;
    result.set_item("payload", PyBytes::new(py, &payload_bytes))?;
    let provider_list = PyList::empty(py);
    for report in &outcome.provider_reports {
        let entry = PyDict::new(py);
        entry.set_item("provider", report.provider.id().as_str())?;
        entry.set_item("successes", report.successes)?;
        entry.set_item("failures", report.failures)?;
        entry.set_item("disabled", report.disabled)?;
        provider_list.append(entry)?;
    }
    result.set_item("provider_reports", provider_list)?;
    let receipts_list = PyList::empty(py);
    for receipt in &outcome.chunk_receipts {
        let entry = PyDict::new(py);
        entry.set_item("chunk_index", receipt.chunk_index)?;
        entry.set_item("provider", receipt.provider.as_str())?;
        entry.set_item("attempts", receipt.attempts)?;
        entry.set_item("latency_ms", receipt.latency_ms)?;
        entry.set_item("bytes", receipt.bytes)?;
        receipts_list.append(entry)?;
    }
    result.set_item("chunk_receipts", receipts_list)?;
    if let Some(entries) = scoreboard_export {
        let scoreboard_list = PyList::empty(py);
        for (provider_id, alias, raw_score, normalised_weight, eligibility) in entries {
            let row = PyDict::new(py);
            row.set_item("provider_id", provider_id)?;
            row.set_item("alias", alias)?;
            row.set_item("raw_score", raw_score)?;
            row.set_item("normalized_weight", normalised_weight)?;
            row.set_item("eligibility", eligibility)?;
            scoreboard_list.append(row)?;
        }
        result.set_item("scoreboard", scoreboard_list)?;
    } else if include_scoreboard {
        result.set_item("scoreboard", py.None())?;
    }
    Ok(result.unbind())
}
fn parse_gateway_transport_policy_v1(raw: &str) -> PyResult<TransportPolicy> {
    if raw.is_empty() {
        return Err(PyValueError::new_err("transport_policy must not be empty"));
    }
    TransportPolicy::parse(raw).ok_or_else(|| {
        PyValueError::new_err(
            "transport_policy must be one of 'soranet-first', 'soranet-strict', or 'direct-only'",
        )
    })
}
fn parse_gateway_rollout_phase_v1(raw: &str) -> PyResult<RolloutPhase> {
    if raw.is_empty() {
        return Err(PyValueError::new_err("rollout_phase must not be empty"));
    }
    RolloutPhase::parse(raw).ok_or_else(|| {
        PyValueError::new_err("rollout_phase must be one of 'canary', 'ramp', or 'default'")
    })
}
fn parse_gateway_anonymity_policy_v1(raw: &str) -> PyResult<AnonymityPolicy> {
    if raw.is_empty() {
        return Err(PyValueError::new_err("anonymity_policy must not be empty"));
    }
    AnonymityPolicy::parse(raw).ok_or_else(|| {
        PyValueError::new_err(
            "anonymity_policy must be one of 'anon-guard-pq', 'anon-majority-pq', or 'anon-strict-pq'",
        )
    })
}
#[pyfunction]
#[pyo3(
    name = "sorafs_gateway_fetch",
    signature = (manifest_id_hex, chunker_handle, plan_json, providers, *, options=None)
)]
fn sorafs_gateway_fetch_py(
    py: Python<'_>,
    manifest_id_hex: &str,
    chunker_handle: &str,
    plan_json: &str,
    providers: Vec<PyGatewayProviderSpec>,
    options: Option<PyGatewayFetchOptions>,
) -> PyResult<Py<PyDict>> {
    if providers.is_empty() {
        return Err(PyValueError::new_err(
            "providers list must contain at least one entry",
        ));
    }
    let manifest_id = manifest_id_hex.trim().to_ascii_lowercase();
    if manifest_id.len() != 64 || !manifest_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PyValueError::new_err(
            "manifest_id_hex must be a 32-byte hex string",
        ));
    }
    let options = options.unwrap_or_default();
    let scoreboard_telemetry_label = options
        .scoreboard_telemetry_label
        .as_ref()
        .map(|label| {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                return Err(PyValueError::new_err(
                    "scoreboard_telemetry_label must not be empty when provided",
                ));
            }
            Ok(trimmed.to_string())
        })
        .transpose()?;
    let plan_value: json::Value = json::from_str(plan_json)
        .map_err(|err| PyValueError::new_err(format!("failed to parse plan JSON: {err}")))?;
    let parsed_plan = chunk_fetch_plan_from_json(&plan_value)
        .map_err(|err| PyValueError::new_err(format!("invalid chunk fetch plan: {err}")))?;
    let plan_payload_digest = parsed_plan.payload_digest;
    let mut chunk_specs = parsed_plan.chunk_fetch_specs;
    if chunk_specs.is_empty() {
        return Err(PyValueError::new_err(
            "chunk fetch plan must contain at least one chunk",
        ));
    }
    chunk_specs.sort_by_key(|spec| spec.chunk_index);
    for (idx, spec) in chunk_specs.iter().enumerate() {
        if spec.chunk_index != idx {
            return Err(PyValueError::new_err(format!(
                "chunk fetch plan missing chunk index {idx}"
            )));
        }
    }
    let content_length = chunk_specs
        .iter()
        .map(|spec| spec.offset + u64::from(spec.length))
        .max()
        .unwrap_or(0);
    let chunker_handle_trimmed = chunker_handle.trim();
    if chunker_handle_trimmed.is_empty() {
        return Err(PyValueError::new_err("chunker_handle must not be empty"));
    }
    let descriptor = sorafs_car::chunker_registry::lookup_by_handle(chunker_handle_trimmed)
        .ok_or_else(|| {
            PyValueError::new_err(format!("unknown chunker handle '{chunker_handle_trimmed}'"))
        })?;
    let plan = CarBuildPlan {
        chunk_profile: descriptor.profile,
        payload_digest: blake3::Hash::from_bytes(plan_payload_digest),
        content_length,
        chunks: chunk_specs
            .iter()
            .map(|spec| CarChunk {
                offset: spec.offset,
                length: spec.length,
                digest: spec.digest,
            })
            .collect(),
        files: vec![FilePlan {
            path: Vec::new(),
            first_chunk: 0,
            chunk_count: chunk_specs.len(),
            size: content_length,
        }],
    };
    let manifest_envelope_b64 = options
        .manifest_envelope_b64
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let manifest_envelope_present = manifest_envelope_b64.is_some();
    let manifest_cid_hex = options
        .manifest_cid_hex
        .as_ref()
        .map(|cid| cid.trim().to_ascii_lowercase());
    if let Some(cid) = &manifest_cid_hex
        && (cid.len() != 64 || !cid.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(PyValueError::new_err(
            "manifest_cid_hex must be a 32-byte hex string",
        ));
    }
    let expected_cache_version = options
        .expected_cache_version
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let client_id = options
        .client_id
        .as_ref()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    let telemetry_region = if let Some(raw) = options.telemetry_region.as_ref() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(PyValueError::new_err("telemetry_region must not be empty"));
        }
        Some(trimmed.to_string())
    } else {
        None
    };
    let manifest_cid_metadata = manifest_cid_hex.clone();
    let provider_inputs: Vec<GatewayProviderInput> = providers
        .into_iter()
        .map(canonical_gateway_provider)
        .collect::<PyResult<_>>()?;
    let unique_gateway_providers = provider_inputs
        .iter()
        .map(|provider| provider.provider_id_hex.as_str())
        .collect::<HashSet<_>>()
        .len();
    if unique_gateway_providers < 2 {
        return Err(PyValueError::new_err(
            "sorafs_gateway_fetch requires at least two unique gateway providers",
        ));
    }
    let mut orchestrator_config = OrchestratorConfig::default();
    if let Some(region) = telemetry_region.as_ref() {
        orchestrator_config = orchestrator_config.with_telemetry_region(region.clone());
    }
    if let Some(limit) = options.retry_budget {
        let limit = limit.max(1);
        orchestrator_config.fetch.per_chunk_retry_limit = Some(limit);
    }
    let max_peers = options.max_peers.map(|limit| limit.max(1));
    if let Some(limit) = max_peers {
        orchestrator_config.fetch.global_parallel_limit = Some(
            orchestrator_config
                .fetch
                .global_parallel_limit
                .map_or(limit, |existing| existing.min(limit)),
        );
    }
    if let Some(raw) = options.transport_policy.as_ref() {
        orchestrator_config.transport_policy = parse_gateway_transport_policy_v1(raw)?;
    }
    if let Some(raw) = options.rollout_phase.as_ref() {
        orchestrator_config =
            orchestrator_config.with_rollout_phase(parse_gateway_rollout_phase_v1(raw)?);
    }
    if let Some(raw) = options.anonymity_policy.as_ref() {
        let policy = parse_gateway_anonymity_policy_v1(raw)?;
        orchestrator_config.anonymity_policy = policy;
        orchestrator_config.anonymity_policy_override = Some(policy);
    }
    if let Some(proxy_opts) = options.local_proxy.as_ref() {
        let mut proxy_cfg = LocalQuicProxyConfig::default();
        if let Some(bind) = proxy_opts.bind_addr.as_ref() {
            let trimmed = bind.trim();
            if trimmed.is_empty() {
                return Err(PyValueError::new_err(
                    "local_proxy.bind_addr must not be empty when provided",
                ));
            }
            proxy_cfg.bind_addr = trimmed.to_string();
        }
        proxy_cfg.telemetry_label = proxy_opts
            .telemetry_label
            .as_ref()
            .map(|label| label.trim().to_string())
            .filter(|label| !label.is_empty());
        proxy_cfg.guard_cache_key_hex = proxy_opts
            .guard_cache_key_hex
            .as_ref()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        if let Some(flag) = proxy_opts.emit_browser_manifest {
            proxy_cfg.emit_browser_manifest = flag;
        }
        if let Some(mode) = proxy_opts.proxy_mode.as_ref() {
            proxy_cfg.proxy_mode = proxy_mode_from_label_py(mode)?;
        }
        if let Some(flag) = proxy_opts.prewarm_circuits {
            proxy_cfg.prewarm_circuits = flag;
        }
        proxy_cfg.max_streams_per_circuit = proxy_opts.max_streams_per_circuit;
        proxy_cfg.circuit_ttl_hint_secs = proxy_opts.circuit_ttl_hint_secs;
        if let Some(norito_cfg) = proxy_opts.norito_bridge.as_ref() {
            let trimmed = norito_cfg.spool_dir.trim();
            if trimmed.is_empty() {
                return Err(PyValueError::new_err(
                    "local_proxy.norito_bridge.spool_dir must not be empty when provided",
                ));
            }
            proxy_cfg.norito_bridge = Some(ProxyNoritoBridgeConfig {
                spool_dir: trimmed.to_string(),
                extension: norito_cfg
                    .extension
                    .as_ref()
                    .map(|ext| ext.trim().to_string())
                    .filter(|ext| !ext.is_empty()),
            });
        }
        if let Some(car_cfg) = proxy_opts.car_bridge.as_ref() {
            let trimmed = car_cfg.cache_dir.trim();
            if trimmed.is_empty() {
                return Err(PyValueError::new_err(
                    "local_proxy.car_bridge.cache_dir must not be empty when provided",
                ));
            }
            proxy_cfg.car_bridge = Some(ProxyCarBridgeConfig {
                cache_dir: trimmed.to_string(),
                extension: car_cfg
                    .extension
                    .as_ref()
                    .map(|ext| ext.trim().to_string())
                    .filter(|ext| !ext.is_empty()),
                allow_zst: car_cfg.allow_zst.unwrap_or(false),
            });
        }
        if let Some(kaigi_cfg) = proxy_opts.kaigi_bridge.as_ref() {
            let trimmed = kaigi_cfg.spool_dir.trim();
            if trimmed.is_empty() {
                return Err(PyValueError::new_err(
                    "local_proxy.kaigi_bridge.spool_dir must not be empty when provided",
                ));
            }
            let room_policy = if let Some(policy) = kaigi_cfg.room_policy.as_ref() {
                let normalized = policy.trim().to_ascii_lowercase();
                match normalized.as_str() {
                    "public" | "authenticated" => Some(normalized),
                    _ => {
                        return Err(PyValueError::new_err(
                            "local_proxy.kaigi_bridge.room_policy must be 'public' or 'authenticated'",
                        ));
                    }
                }
            } else {
                None
            };
            proxy_cfg.kaigi_bridge = Some(ProxyKaigiBridgeConfig {
                spool_dir: trimmed.to_string(),
                extension: kaigi_cfg
                    .extension
                    .as_ref()
                    .map(|ext| ext.trim().to_string())
                    .filter(|ext| !ext.is_empty()),
                room_policy,
            });
        }
        if matches!(proxy_cfg.proxy_mode, ProxyMode::Bridge) && proxy_cfg.norito_bridge.is_none() {
            proxy_cfg.norito_bridge = Some(ProxyNoritoBridgeConfig {
                spool_dir: DEFAULT_LOCAL_PROXY_BRIDGE_SPOOL_DIR.to_string(),
                extension: Some("norito".to_string()),
            });
        }
        if matches!(proxy_cfg.proxy_mode, ProxyMode::Bridge) && proxy_cfg.kaigi_bridge.is_none() {
            proxy_cfg.kaigi_bridge = Some(ProxyKaigiBridgeConfig {
                spool_dir: DEFAULT_LOCAL_PROXY_BRIDGE_SPOOL_DIR.to_string(),
                extension: Some("norito".to_string()),
                room_policy: Some("public".to_string()),
            });
        }
        orchestrator_config.local_proxy = Some(proxy_cfg);
    }
    let local_proxy_snapshot = orchestrator_config.local_proxy.clone();
    let gateway_provider_count = provider_inputs.len();
    let gateway_config = GatewayFetchConfig {
        manifest_id_hex: manifest_id.clone(),
        chunker_handle: chunker_handle_trimmed.to_string(),
        manifest_envelope_b64,
        client_id,
        expected_manifest_cid_hex: manifest_cid_hex,
        blinded_cid_b64: None,
        salt_epoch: None,
        expected_cache_version,
    };
    let metadata = build_gateway_metadata_dict(
        py,
        0,
        gateway_provider_count,
        &orchestrator_config,
        scoreboard_telemetry_label.as_deref(),
        telemetry_region.as_deref(),
        manifest_id.as_str(),
        manifest_cid_metadata.as_deref(),
        manifest_envelope_present,
        false,
    )?;
    let runtime = Runtime::new().map_err(|err| {
        PyValueError::new_err(format!("failed to initialise Tokio runtime: {err}"))
    })?;
    let session = runtime
        .block_on(fetch_via_gateway(
            orchestrator_config,
            &plan,
            gateway_config,
            provider_inputs,
            None::<&TelemetrySnapshot>,
            max_peers,
        ))
        .map_err(|err| PyValueError::new_err(format!("sorafs gateway fetch failed: {err}")))?;
    let outcome = &session.outcome;
    let policy_report = &session.policy_report;
    let payload_bytes = outcome.assemble_payload();
    if blake3_hash(&payload_bytes) != plan.payload_digest {
        return Err(PyValueError::new_err(
            "assembled payload digest does not match canonical chunk fetch plan",
        ));
    }
    let result = PyDict::new(py);
    result.set_item("manifest_id_hex", manifest_id)?;
    result.set_item("chunker_handle", chunker_handle_trimmed)?;
    result.set_item("chunk_count", outcome.chunks.len())?;
    result.set_item("assembled_bytes", payload_bytes.len())?;
    result.set_item("payload", PyBytes::new(py, &payload_bytes))?;
    result.set_item("metadata", metadata.clone_ref(py))?;
    if let Some(region) = telemetry_region.as_ref() {
        result.set_item("telemetry_region", region)?;
    }
    result.set_item(
        "anonymity_policy",
        anonymity_policy_label(policy_report.policy),
    )?;
    result.set_item("anonymity_status", policy_report.status_label())?;
    result.set_item("anonymity_reason", policy_report.reason_label())?;
    result.set_item(
        "anonymity_soranet_selected",
        policy_report.selected_soranet_total,
    )?;
    result.set_item("anonymity_pq_selected", policy_report.selected_pq)?;
    result.set_item(
        "anonymity_classical_selected",
        policy_report.selected_classical(),
    )?;
    result.set_item("anonymity_classical_ratio", policy_report.classical_ratio())?;
    result.set_item("anonymity_pq_ratio", policy_report.pq_ratio())?;
    result.set_item("anonymity_candidate_ratio", policy_report.candidate_ratio())?;
    result.set_item("anonymity_deficit_ratio", policy_report.deficit_ratio())?;
    result.set_item("anonymity_supply_delta", policy_report.supply_delta_ratio())?;
    result.set_item("anonymity_brownout", policy_report.is_brownout())?;
    result.set_item(
        "anonymity_brownout_effective",
        policy_report.should_flag_brownout(),
    )?;
    result.set_item("anonymity_uses_classical", policy_report.uses_classical())?;
    let provider_reports = PyList::empty(py);
    for report in &outcome.provider_reports {
        let entry = PyDict::new(py);
        entry.set_item("provider", report.provider.id().as_str())?;
        entry.set_item("successes", report.successes)?;
        entry.set_item("failures", report.failures)?;
        entry.set_item("disabled", report.disabled)?;
        provider_reports.append(entry)?;
    }
    result.set_item("provider_reports", provider_reports)?;
    let receipts = PyList::empty(py);
    for receipt in &outcome.chunk_receipts {
        let entry = PyDict::new(py);
        entry.set_item("chunk_index", receipt.chunk_index)?;
        entry.set_item("provider", receipt.provider.as_str())?;
        entry.set_item("attempts", receipt.attempts)?;
        entry.set_item("latency_ms", receipt.latency_ms)?;
        entry.set_item("bytes", receipt.bytes)?;
        receipts.append(entry)?;
    }
    result.set_item("chunk_receipts", receipts)?;
    if let Some(manifest) = &session.local_proxy_manifest {
        let manifest_value = json::to_value(manifest).map_err(|err| {
            PyValueError::new_err(format!("failed to serialise local proxy manifest: {err}"))
        })?;
        let manifest_json = json::to_string(&manifest_value).map_err(|err| {
            PyValueError::new_err(format!("failed to serialise local proxy manifest: {err}"))
        })?;
        let json_module = py.import("json")?;
        let parsed_manifest = json_module.getattr("loads")?.call1((manifest_json,))?;
        result.set_item("local_proxy_manifest", parsed_manifest)?;
    } else {
        result.set_item("local_proxy_manifest", py.None())?;
    }
    if let Some(proxy_cfg) = local_proxy_snapshot.as_ref() {
        result.set_item("local_proxy_mode", proxy_cfg.proxy_mode.as_str())?;
        if let Some(bridge) = proxy_cfg.norito_bridge.as_ref() {
            result.set_item("local_proxy_norito_spool", bridge.spool_dir.clone())?;
        } else {
            result.set_item("local_proxy_norito_spool", py.None())?;
        }
        if let Some(bridge) = proxy_cfg.kaigi_bridge.as_ref() {
            result.set_item("local_proxy_kaigi_spool", bridge.spool_dir.clone())?;
            let policy = bridge
                .room_policy
                .clone()
                .unwrap_or_else(|| "public".to_string());
            result.set_item("local_proxy_kaigi_policy", policy)?;
        } else {
            result.set_item("local_proxy_kaigi_spool", py.None())?;
            result.set_item("local_proxy_kaigi_policy", py.None())?;
        }
    } else {
        result.set_item("local_proxy_mode", py.None())?;
        result.set_item("local_proxy_norito_spool", py.None())?;
        result.set_item("local_proxy_kaigi_spool", py.None())?;
        result.set_item("local_proxy_kaigi_policy", py.None())?;
    }
    if let Some(verification) = &session.car_verification {
        let car_dict = PyDict::new(py);
        car_dict.set_item(
            "manifest_digest_hex",
            hex_encode(verification.manifest_digest.as_bytes()),
        )?;
        car_dict.set_item(
            "manifest_payload_digest_hex",
            hex_encode(verification.manifest_payload_digest.as_bytes()),
        )?;
        car_dict.set_item(
            "manifest_car_digest_hex",
            hex_encode(verification.manifest_car_digest),
        )?;
        car_dict.set_item(
            "manifest_content_length",
            verification.manifest_content_length,
        )?;
        car_dict.set_item("manifest_chunk_count", verification.manifest_chunk_count)?;
        car_dict.set_item(
            "manifest_chunk_profile_handle",
            verification.chunk_profile_handle.clone(),
        )?;
        let signatures = PyList::empty(py);
        for signature in &verification.manifest_governance.council_signatures {
            let entry = PyDict::new(py);
            entry.set_item("signer_hex", hex_encode(signature.signer))?;
            entry.set_item("signature_hex", hex_encode(&signature.signature))?;
            signatures.append(entry)?;
        }
        let governance_obj = PyDict::new(py);
        governance_obj.set_item("council_signatures", signatures)?;
        car_dict.set_item("manifest_governance", governance_obj)?;
        let car_obj = PyDict::new(py);
        car_obj.set_item("size", verification.car_stats.car_size)?;
        car_obj.set_item(
            "payload_digest_hex",
            hex_encode(verification.car_stats.car_payload_digest.as_bytes()),
        )?;
        car_obj.set_item(
            "archive_digest_hex",
            hex_encode(verification.car_stats.car_archive_digest.as_bytes()),
        )?;
        car_obj.set_item("cid_hex", hex_encode(&verification.car_stats.car_cid))?;
        let roots = PyList::empty(py);
        for cid in &verification.car_stats.root_cids {
            roots.append(hex_encode(cid))?;
        }
        car_obj.set_item("root_cids_hex", roots)?;
        car_obj.set_item("verified", true)?;
        car_obj.set_item("por_leaf_count", verification.por_leaf_count)?;
        car_dict.set_item("car_archive", car_obj)?;
        result.set_item("car_verification", car_dict)?;
    } else {
        result.set_item("car_verification", py.None())?;
    }
    Ok(result.unbind())
}
fn anonymity_policy_label(policy: AnonymityPolicy) -> &'static str {
    match policy {
        AnonymityPolicy::GuardPq => "anon-guard-pq",
        AnonymityPolicy::MajorityPq => "anon-majority-pq",
        AnonymityPolicy::StrictPq => "anon-strict-pq",
    }
}
#[pyfunction]
#[pyo3(name = "sorafs_decode_replication_order")]
fn sorafs_decode_replication_order_py(py: Python<'_>, norito_bytes: &[u8]) -> PyResult<Py<PyDict>> {
    let order: ReplicationOrderV1 = decode_from_bytes(norito_bytes).map_err(|err| {
        PyValueError::new_err(format!("failed to decode replication order: {err}"))
    })?;
    order
        .validate()
        .map_err(|err| PyValueError::new_err(format!("invalid replication order: {err}")))?;
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
    let dict = PyDict::new(py);
    dict.set_item("schema_version", version)?;
    dict.set_item("order_id_hex", hex::encode(order_id))?;
    let manifest_cid_base64 = BASE64.encode(&manifest_cid);
    dict.set_item("manifest_cid_base64", manifest_cid_base64)?;
    match String::from_utf8(manifest_cid) {
        Ok(value) => dict.set_item("manifest_cid_utf8", value)?,
        Err(_) => dict.set_item("manifest_cid_utf8", py.None())?,
    }
    dict.set_item("manifest_digest_hex", hex::encode(manifest_digest))?;
    dict.set_item("chunking_profile", chunking_profile)?;
    dict.set_item("target_replicas", u32::from(target_replicas))?;
    dict.set_item("issued_at_unix", issued_at)?;
    dict.set_item("deadline_at_unix", deadline_at)?;
    let sla_dict = PyDict::new(py);
    sla_dict.set_item("ingest_deadline_secs", sla.ingest_deadline_secs)?;
    sla_dict.set_item(
        "min_availability_percent_milli",
        sla.min_availability_percent_milli,
    )?;
    sla_dict.set_item(
        "min_por_success_percent_milli",
        sla.min_por_success_percent_milli,
    )?;
    dict.set_item("sla", sla_dict)?;
    let assignments_list = PyList::empty(py);
    for assignment in assignments {
        let entry = PyDict::new(py);
        entry.set_item("provider_id_hex", hex::encode(assignment.provider_id))?;
        entry.set_item("slice_gib", assignment.slice_gib)?;
        match assignment.lane {
            Some(lane) => entry.set_item("lane", lane)?,
            None => entry.set_item("lane", py.None())?,
        }
        assignments_list.append(entry)?;
    }
    dict.set_item("assignments", assignments_list)?;
    let metadata_list = PyList::empty(py);
    for entry in metadata {
        let meta = PyDict::new(py);
        meta.set_item("key", entry.key)?;
        meta.set_item("value", entry.value)?;
        metadata_list.append(meta)?;
    }
    dict.set_item("metadata", metadata_list)?;
    Ok(dict.unbind())
}
fn sorafs_validation_outcome_json(outcome: &ValidationOutcomeV1) -> PyResult<String> {
    json::to_string(outcome).map_err(|err| {
        PyValueError::new_err(format!("failed to serialize validation outcome: {err}"))
    })
}
fn validate_sorafs_reference_label_py(label: &str, context: &str) -> PyResult<()> {
    if label.is_empty() || label.trim().is_empty() {
        return Err(PyValueError::new_err(format!(
            "{context} must not be blank"
        )));
    }
    if label.trim() != label {
        return Err(PyValueError::new_err(format!(
            "{context} must not contain surrounding whitespace"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(PyValueError::new_err(format!(
            "{context} must not contain control characters"
        )));
    }
    let maximum = SORAFS_REFERENCE_FFI_MAX_LABEL_BYTES_V1 as usize;
    if label.len() > maximum {
        return Err(PyValueError::new_err(format!(
            "{context} must be at most {maximum} UTF-8 bytes"
        )));
    }
    Ok(())
}
fn validate_sorafs_reference_aggregate_bytes_py(
    context: &str,
    sizes: impl IntoIterator<Item = usize>,
) -> PyResult<()> {
    let maximum = SORAFS_REFERENCE_FFI_MAX_INPUT_BYTES_V1 as usize;
    let mut total = 0usize;
    for size in sizes {
        total = total.checked_add(size).ok_or_else(|| {
            PyValueError::new_err(format!("{context} aggregate byte length overflowed"))
        })?;
        if total > maximum {
            return Err(PyValueError::new_err(format!(
                "{context} inputs exceed {maximum} aggregate bytes"
            )));
        }
    }
    Ok(())
}
fn validate_sorafs_reference_governance_cid_py<'a>(
    cid: Option<&'a [u8]>,
    context: &str,
) -> PyResult<Option<&'a [u8]>> {
    let Some(cid) = cid else {
        return Ok(None);
    };
    let exact_bytes = SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1 as usize;
    if cid.len() != exact_bytes {
        return Err(PyValueError::new_err(format!(
            "{context} must contain exactly {exact_bytes} bytes"
        )));
    }
    Ok(Some(cid))
}
fn parse_sorafs_orderbook_payload_kind(kind: &str) -> PyResult<OrderbookValidationPayloadKindV1> {
    parse_sorafs_orderbook_payload_kind_v1(kind).ok_or_else(|| {
        PyValueError::new_err(format!(
            "unsupported SoraFS orderbook payload kind `{kind}`"
        ))
    })
}
fn parse_sorafs_orderbook_side_py(side: &str) -> PyResult<OrderSideV1> {
    parse_sorafs_orderbook_side_v1(side)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported SoraFS orderbook side `{side}`")))
}
fn parse_sorafs_orderbook_tier_py(tier: &str) -> PyResult<OrderTierV1> {
    parse_sorafs_orderbook_tier_v1(tier)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported SoraFS orderbook tier `{tier}`")))
}
fn parse_sorafs_orderbook_cancel_reason_py(reason: &str) -> PyResult<OrderCancelReasonV1> {
    parse_sorafs_orderbook_cancel_reason_v1(reason, "owner_requested").ok_or_else(|| {
        PyValueError::new_err(format!(
            "unsupported SoraFS orderbook cancel reason `{reason}`"
        ))
    })
}
fn parse_sorafs_decimal_u64_text_py(value: &str, context: &str) -> PyResult<u64> {
    parse_sorafs_orderbook_decimal_u64_v1(value, context).map_err(PyValueError::new_err)
}
fn parse_sorafs_xor_quantity_text_py(value: &str, context: &str) -> PyResult<XorQuantity> {
    parse_sorafs_orderbook_xor_quantity_v1(value, context).map_err(PyValueError::new_err)
}
fn parse_sorafs_fee_bps_py(value: u32, context: &str) -> PyResult<u16> {
    parse_sorafs_orderbook_fee_bps_v1(value, context).map_err(PyValueError::new_err)
}
fn sorafs_fixed32_from_bytes_py(value: &[u8], context: &str) -> PyResult<[u8; 32]> {
    fixed_array::<32>(value, context)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_appeal_finance_cancel_asset_lock_json")]
fn sorafs_validate_appeal_finance_cancel_asset_lock_json_py(
    norito_bytes: &[u8],
    label: &str,
    generated_at_unix: u64,
) -> PyResult<String> {
    let outcome = validate_appeal_finance_cancel_asset_lock_bytes(
        norito_bytes,
        label.to_owned(),
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SorafsPdpPayloadKind {
    Commitment,
    Challenge,
    Proof,
}
fn parse_sorafs_pdp_payload_kind(kind: &str) -> PyResult<SorafsPdpPayloadKind> {
    match kind {
        "commitment" => Ok(SorafsPdpPayloadKind::Commitment),
        "challenge" => Ok(SorafsPdpPayloadKind::Challenge),
        "proof" => Ok(SorafsPdpPayloadKind::Proof),
        _ => Err(PyValueError::new_err(format!(
            "unsupported SoraFS PDP payload kind `{kind}`"
        ))),
    }
}
fn parse_sorafs_fixture_bundle_payload_kind_py(kind: &str) -> PyResult<FixtureBundlePayloadKindV1> {
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
        _ => Err(PyValueError::new_err(format!(
            "unsupported SoraFS fixture-bundle payload kind `{kind}`"
        ))),
    }
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_orderbook_payload_json")]
fn sorafs_validate_orderbook_payload_json_py(
    kind: &str,
    norito_bytes: &[u8],
    label: &str,
    generated_at_unix: u64,
) -> PyResult<String> {
    let kind = parse_sorafs_orderbook_payload_kind(kind)?;
    let outcome =
        validate_orderbook_payload_bytes(kind, norito_bytes, label.to_owned(), generated_at_unix);
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_sign_orderbook_payload")]
fn sorafs_sign_orderbook_payload_py(
    py: Python<'_>,
    kind: &str,
    norito_bytes: &[u8],
    private_key: &[u8],
) -> PyResult<Py<PyBytes>> {
    let kind = parse_sorafs_orderbook_payload_kind(kind)?;
    let signed = sign_orderbook_payload_bytes_ed25519_v1(kind, norito_bytes, private_key)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
#[pyfunction]
#[pyo3(name = "sorafs_derive_orderbook_order_id")]
fn sorafs_derive_orderbook_order_id_py(
    py: Python<'_>,
    owner_account: &[u8],
    nonce: &str,
) -> PyResult<Py<PyBytes>> {
    validate_sorafs_orderbook_owner_account_py(owner_account)?;
    let nonce = parse_sorafs_decimal_u64_text_py(nonce, "nonce")?;
    if nonce == 0 {
        return Err(PyValueError::new_err("nonce must be positive"));
    }
    let order_id = derive_orderbook_order_id_v1(owner_account, nonce);
    Ok(Py::from(PyBytes::new(py, &order_id)))
}
#[pyfunction]
#[pyo3(name = "sorafs_build_signed_orderbook_order_request")]
#[allow(clippy::too_many_arguments)] // Python field-level constructor surface
fn sorafs_build_signed_orderbook_order_request_py(
    py: Python<'_>,
    order_id: &[u8],
    side: &str,
    tier: &str,
    price_per_gib: &str,
    quantity_gib: &str,
    remaining_gib: Option<&str>,
    owner_account: &[u8],
    provider_id: &[u8],
    expiry_unix: &str,
    nonce: &str,
    maker_fee_bps: u32,
    taker_fee_bps: u32,
    private_key: &[u8],
) -> PyResult<Py<PyBytes>> {
    let quantity_gib = parse_sorafs_decimal_u64_text_py(quantity_gib, "quantity_gib")?;
    validate_sorafs_orderbook_owner_account_py(owner_account)?;
    let nonce = parse_sorafs_decimal_u64_text_py(nonce, "nonce")?;
    if nonce == 0 {
        return Err(PyValueError::new_err("nonce must be positive"));
    }
    let supplied_order_id = sorafs_fixed32_from_bytes_py(order_id, "order_id")?;
    let expected_order_id = derive_orderbook_order_id_v1(owner_account, nonce);
    if supplied_order_id != expected_order_id {
        return Err(PyValueError::new_err(format!(
            "order_id must equal the canonical owner-and-nonce derivation {}",
            hex::encode(expected_order_id)
        )));
    }
    let side = parse_sorafs_orderbook_side_py(side)?;
    let provider_id = if provider_id.is_empty() {
        None
    } else {
        let provider_id = sorafs_fixed32_from_bytes_py(provider_id, "provider_id")?;
        if provider_id == [0; 32] {
            return Err(PyValueError::new_err("provider_id must not be all zero"));
        }
        Some(provider_id)
    };
    let fields = OrderbookOrderRequestFieldsV1 {
        side,
        tier: parse_sorafs_orderbook_tier_py(tier)?,
        price_per_gib: parse_sorafs_xor_quantity_text_py(price_per_gib, "price_per_gib")?,
        quantity_gib,
        remaining_gib: match remaining_gib {
            Some(value) => parse_sorafs_decimal_u64_text_py(value, "remaining_gib")?,
            None => quantity_gib,
        },
        owner_account: owner_account.to_vec(),
        provider_id,
        expiry_unix: parse_sorafs_decimal_u64_text_py(expiry_unix, "expiry_unix")?,
        nonce,
        maker_fee_bps: parse_sorafs_fee_bps_py(maker_fee_bps, "maker_fee_bps")?,
        taker_fee_bps: parse_sorafs_fee_bps_py(taker_fee_bps, "taker_fee_bps")?,
    };
    let signed = build_signed_orderbook_order_request_bytes_ed25519_v1(fields, private_key)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
#[pyfunction]
#[pyo3(name = "sorafs_build_signed_orderbook_order_cancel")]
fn sorafs_build_signed_orderbook_order_cancel_py(
    py: Python<'_>,
    order_id: &[u8],
    owner_account: &[u8],
    reason: &str,
    nonce: &str,
    private_key: &[u8],
) -> PyResult<Py<PyBytes>> {
    validate_sorafs_orderbook_owner_account_py(owner_account)?;
    let fields = OrderbookOrderCancelFieldsV1 {
        order_id: sorafs_fixed32_from_bytes_py(order_id, "order_id")?,
        owner_account: owner_account.to_vec(),
        reason: parse_sorafs_orderbook_cancel_reason_py(reason)?,
        nonce: parse_sorafs_decimal_u64_text_py(nonce, "nonce")?,
    };
    let signed = build_signed_orderbook_order_cancel_bytes_ed25519_v1(fields, private_key)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
fn validate_sorafs_orderbook_owner_account_py(owner_account: &[u8]) -> PyResult<()> {
    validate_sorafs_orderbook_owner_account_v1(owner_account).map_err(PyValueError::new_err)
}
#[pyfunction]
#[pyo3(name = "sorafs_build_signed_orderbook_settlement_receipt")]
#[allow(clippy::too_many_arguments)] // Python field-level constructor surface
fn sorafs_build_signed_orderbook_settlement_receipt_py(
    py: Python<'_>,
    receipt_id: &[u8],
    channel_id: &[u8],
    trade_id: &[u8],
    range_start: &str,
    range_end: &str,
    chunk_hash: &[u8],
    bytes_delivered: &str,
    xor_debited: &str,
    provider_credit: &str,
    fee_amount: &str,
    issued_at_unix: &str,
    private_key: &[u8],
) -> PyResult<Py<PyBytes>> {
    let fields = OrderbookSettlementReceiptFieldsV1 {
        receipt_id: sorafs_fixed32_from_bytes_py(receipt_id, "receipt_id")?,
        channel_id: sorafs_fixed32_from_bytes_py(channel_id, "channel_id")?,
        trade_id: sorafs_fixed32_from_bytes_py(trade_id, "trade_id")?,
        range_start: parse_sorafs_decimal_u64_text_py(range_start, "range_start")?,
        range_end: parse_sorafs_decimal_u64_text_py(range_end, "range_end")?,
        chunk_hash: sorafs_fixed32_from_bytes_py(chunk_hash, "chunk_hash")?,
        bytes_delivered: parse_sorafs_decimal_u64_text_py(bytes_delivered, "bytes_delivered")?,
        xor_debited: parse_sorafs_xor_quantity_text_py(xor_debited, "xor_debited")?,
        provider_credit: parse_sorafs_xor_quantity_text_py(provider_credit, "provider_credit")?,
        fee_amount: parse_sorafs_xor_quantity_text_py(fee_amount, "fee_amount")?,
        issued_at_unix: parse_sorafs_decimal_u64_text_py(issued_at_unix, "issued_at_unix")?,
    };
    let signed = build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(fields, private_key)
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_pdp_payload_json")]
fn sorafs_validate_pdp_payload_json_py(
    kind: &str,
    norito_bytes: &[u8],
    label: &str,
    generated_at_unix: u64,
) -> PyResult<String> {
    let kind = parse_sorafs_pdp_payload_kind(kind)?;
    let outcome = match kind {
        SorafsPdpPayloadKind::Commitment => {
            validate_pdp_commitment_bytes(norito_bytes, label.to_owned(), generated_at_unix)
        }
        SorafsPdpPayloadKind::Challenge => {
            validate_pdp_challenge_bytes(norito_bytes, label.to_owned(), generated_at_unix)
        }
        SorafsPdpPayloadKind::Proof => {
            validate_pdp_proof_bytes(norito_bytes, label.to_owned(), generated_at_unix)
        }
    };
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_pdp_commitment_challenge_json")]
fn sorafs_validate_pdp_commitment_challenge_json_py(
    commitment: &[u8],
    commitment_label: &str,
    challenge: &[u8],
    challenge_label: &str,
    generated_at_unix: u64,
) -> PyResult<String> {
    let outcome = validate_pdp_commitment_challenge_bytes(
        commitment,
        challenge,
        commitment_label.to_owned(),
        challenge_label.to_owned(),
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_pdp_challenge_proof_json")]
fn sorafs_validate_pdp_challenge_proof_json_py(
    challenge: &[u8],
    challenge_label: &str,
    proof: &[u8],
    proof_label: &str,
    generated_at_unix: u64,
) -> PyResult<String> {
    let outcome = validate_pdp_challenge_proof_bytes(
        challenge,
        proof,
        challenge_label.to_owned(),
        proof_label.to_owned(),
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_pdp_bundle_json")]
fn sorafs_validate_pdp_bundle_json_py(
    commitment: &[u8],
    commitment_label: &str,
    challenge: &[u8],
    challenge_label: &str,
    proof: &[u8],
    proof_label: &str,
    generated_at_unix: u64,
) -> PyResult<String> {
    let outcome = validate_pdp_commitment_challenge_proof_bytes(
        commitment,
        challenge,
        proof,
        commitment_label.to_owned(),
        challenge_label.to_owned(),
        proof_label.to_owned(),
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_fixture_bundle_json")]
fn sorafs_validate_fixture_bundle_json_py(
    payloads: Vec<(String, Vec<u8>, String)>,
    now_unix: u64,
    generated_at_unix: u64,
) -> PyResult<String> {
    let maximum_payloads = SORAFS_REFERENCE_FFI_MAX_BUNDLE_PAYLOADS_V1 as usize;
    if payloads.is_empty() || payloads.len() > maximum_payloads {
        return Err(PyValueError::new_err(format!(
            "payloads must contain 1..={maximum_payloads} entries"
        )));
    }
    let mut kinds = Vec::with_capacity(payloads.len());
    let mut aggregate_bytes = 0usize;
    for (index, (kind, bytes, label)) in payloads.iter().enumerate() {
        kinds.push(parse_sorafs_fixture_bundle_payload_kind_py(kind)?);
        validate_sorafs_reference_label_py(label, &format!("payloads[{index}].label"))?;
        aggregate_bytes = aggregate_bytes
            .checked_add(bytes.len())
            .and_then(|total| total.checked_add(label.len()))
            .ok_or_else(|| {
                PyValueError::new_err("fixture-bundle aggregate byte length overflowed")
            })?;
        let maximum_bytes = SORAFS_REFERENCE_FFI_MAX_BUNDLE_TOTAL_BYTES_V1 as usize;
        if aggregate_bytes > maximum_bytes {
            return Err(PyValueError::new_err(format!(
                "fixture-bundle inputs exceed {maximum_bytes} aggregate bytes"
            )));
        }
    }
    let borrowed = payloads
        .iter()
        .zip(kinds)
        .map(|((_, bytes, label), kind)| {
            FixtureBundlePayloadV1::new(kind, label.clone(), bytes.as_slice())
        })
        .collect::<Vec<_>>();
    let outcome = validate_fixture_bundle_payloads(&borrowed, now_unix, generated_at_unix);
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_governance_log_node_json")]
fn sorafs_validate_governance_log_node_json_py(
    norito_bytes: &[u8],
    label: &str,
    expected_node_cid: &[u8],
    generated_at_unix: u64,
) -> PyResult<String> {
    validate_sorafs_reference_label_py(label, "label")?;
    let expected_node_cid =
        validate_sorafs_reference_governance_cid_py(Some(expected_node_cid), "expected_node_cid")?
            .expect("required CID was supplied");
    validate_sorafs_reference_aggregate_bytes_py(
        "governance log-node validation",
        [norito_bytes.len(), label.len(), expected_node_cid.len()],
    )?;
    let outcome = validate_governance_log_node_bytes(
        norito_bytes,
        label.to_owned(),
        Some(expected_node_cid),
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_governance_dag_block_json")]
#[pyo3(signature = (norito_bytes, label, expected_block_cid, generated_at_unix))]
fn sorafs_validate_governance_dag_block_json_py(
    norito_bytes: &[u8],
    label: &str,
    expected_block_cid: Option<&[u8]>,
    generated_at_unix: u64,
) -> PyResult<String> {
    validate_sorafs_reference_label_py(label, "label")?;
    let expected_block_cid =
        validate_sorafs_reference_governance_cid_py(expected_block_cid, "expected_block_cid")?;
    validate_sorafs_reference_aggregate_bytes_py(
        "governance DAG block validation",
        [
            norito_bytes.len(),
            label.len(),
            expected_block_cid.map_or(0, <[u8]>::len),
        ],
    )?;
    let outcome = validate_governance_dag_block_bytes(
        norito_bytes,
        label.to_owned(),
        expected_block_cid,
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[pyfunction]
#[pyo3(name = "sorafs_validate_governance_dag_head_chain_json")]
fn sorafs_validate_governance_dag_head_chain_json_py(
    head: &[u8],
    head_label: &str,
    block_payloads: Vec<Vec<u8>>,
    block_labels: Vec<String>,
    generated_at_unix: u64,
) -> PyResult<String> {
    let maximum_blocks = SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1 as usize;
    if block_payloads.is_empty() || block_payloads.len() > maximum_blocks {
        return Err(PyValueError::new_err(format!(
            "block_payloads must contain 1..={maximum_blocks} entries"
        )));
    }
    if block_payloads.len() != block_labels.len() {
        return Err(PyValueError::new_err(
            "block_payloads and block_labels must contain the same number of entries",
        ));
    }
    validate_sorafs_reference_label_py(head_label, "head_label")?;
    let mut sizes = Vec::with_capacity(2 + block_payloads.len() * 2);
    sizes.extend([head.len(), head_label.len()]);
    for (index, (payload, label)) in block_payloads.iter().zip(&block_labels).enumerate() {
        validate_sorafs_reference_label_py(label, &format!("block_labels[{index}]"))?;
        sizes.extend([payload.len(), label.len()]);
    }
    validate_sorafs_reference_aggregate_bytes_py("governance DAG head-chain validation", sizes)?;
    let blocks = block_payloads
        .iter()
        .zip(block_labels)
        .map(|(bytes, label)| (bytes.as_slice(), label))
        .collect::<Vec<_>>();
    let outcome = validate_governance_dag_head_chain_bytes(
        head,
        head_label.to_owned(),
        &blocks,
        generated_at_unix,
    );
    sorafs_validation_outcome_json(&outcome)
}
#[cfg(test)]
mod sorafs_reference_validation_py_tests {
    use super::*;
    #[test]
    fn parse_sorafs_orderbook_payload_kind_requires_exact_v1_name() {
        assert!(matches!(
            parse_sorafs_orderbook_payload_kind("order-request"),
            Ok(OrderbookValidationPayloadKindV1::OrderRequest)
        ));
        assert!(matches!(
            parse_sorafs_orderbook_payload_kind("settlement-receipt"),
            Ok(OrderbookValidationPayloadKindV1::SettlementReceipt)
        ));
        for retired in [
            "order",
            "order_request",
            " ORDER-REQUEST",
            "request",
            "runtime-snapshot",
        ] {
            assert!(parse_sorafs_orderbook_payload_kind(retired).is_err());
        }
        assert!(parse_sorafs_orderbook_side_py("Bid").is_err());
        assert!(parse_sorafs_orderbook_tier_py(" hot").is_err());
        assert!(parse_sorafs_orderbook_cancel_reason_py("owner-requested").is_err());
    }
    #[test]
    fn parse_sorafs_pdp_payload_kind_requires_exact_v1_name() {
        assert_eq!(
            parse_sorafs_pdp_payload_kind("commitment").expect("commitment"),
            SorafsPdpPayloadKind::Commitment
        );
        assert_eq!(
            parse_sorafs_pdp_payload_kind("challenge").expect("challenge"),
            SorafsPdpPayloadKind::Challenge
        );
        assert_eq!(
            parse_sorafs_pdp_payload_kind("proof").expect("proof"),
            SorafsPdpPayloadKind::Proof
        );
        for retired in ["pdp-commitment", "pdp_challenge", " PROOF", "Proof"] {
            assert!(parse_sorafs_pdp_payload_kind(retired).is_err());
        }
    }
    #[test]
    fn governance_dag_reference_bounds_are_enforced_before_native_dispatch() {
        let maximum_label = SORAFS_REFERENCE_FFI_MAX_LABEL_BYTES_V1 as usize;
        assert!(validate_sorafs_reference_label_py(&"a".repeat(maximum_label), "label").is_ok());
        assert!(
            validate_sorafs_reference_label_py(&"a".repeat(maximum_label + 1), "label").is_err()
        );
        let maximum_input = SORAFS_REFERENCE_FFI_MAX_INPUT_BYTES_V1 as usize;
        assert!(
            validate_sorafs_reference_aggregate_bytes_py("governance DAG", [maximum_input]).is_ok()
        );
        assert!(
            validate_sorafs_reference_aggregate_bytes_py("governance DAG", [maximum_input, 1])
                .is_err()
        );
        assert!(validate_sorafs_reference_governance_cid_py(None, "expected CID").is_ok());
        let exact_cid = [0_u8; SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1 as usize];
        assert!(
            validate_sorafs_reference_governance_cid_py(Some(&exact_cid), "expected CID").is_ok()
        );
        for invalid_length in [0, exact_cid.len() - 1, exact_cid.len() + 1] {
            let invalid = vec![0_u8; invalid_length];
            assert!(
                validate_sorafs_reference_governance_cid_py(Some(&invalid), "expected CID")
                    .is_err()
            );
        }
    }
    #[test]
    fn governance_log_node_reference_fixture_has_stable_outcome() {
        let node =
            include_bytes!("../../../../fixtures/sorafs_manifest/moderation/governance_node_v1.to");
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
            "../../../../fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.to"
        );
        let zero = include_bytes!(
            "../../../../fixtures/sorafs_manifest/appeal_finance/negative/cancel_asset_lock_zero_expected_v1.to"
        );
        let accepted = sorafs_validate_appeal_finance_cancel_asset_lock_json_py(
            canonical,
            "cancel_asset_lock_v1.to",
            41,
        )
        .expect("validate canonical CancelAssetLock");
        let accepted: norito::json::Value =
            norito::json::from_json(&accepted).expect("accepted outcome JSON");
        assert_eq!(
            accepted.get("code").and_then(norito::json::Value::as_str),
            Some("SFS-OK-000")
        );
        let rejected = sorafs_validate_appeal_finance_cancel_asset_lock_json_py(
            zero,
            "cancel_asset_lock_zero_expected_v1.to",
            42,
        )
        .expect("validate zero-quantity CancelAssetLock");
        let rejected: norito::json::Value =
            norito::json::from_json(&rejected).expect("rejected outcome JSON");
        assert_eq!(
            rejected.get("code").and_then(norito::json::Value::as_str),
            Some("SFS-VAL-001")
        );
    }
    #[test]
    fn governance_dag_reference_fixtures_have_stable_positive_and_negative_outcomes() {
        let root =
            include_bytes!("../../../../fixtures/sorafs_manifest/governance/dag_block_0_v1.to");
        let child =
            include_bytes!("../../../../fixtures/sorafs_manifest/governance/dag_block_1_v1.to");
        let head = include_bytes!("../../../../fixtures/sorafs_manifest/governance/dag_head_v1.to");
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
        assert_eq!(negative.status, "Error");
        assert_eq!(negative.code, "SFS-GOV-006");
    }
}
fn confidential_vk_registration_payload_py(
    py: Python<'_>,
    record: iroha_data_model::proof::VerifyingKeyRecord,
    name: &str,
    label: &str,
) -> PyResult<Py<PyAny>> {
    let key = record.key.as_ref().ok_or_else(|| {
        PyValueError::new_err(format!(
            "{label} verifying-key record is missing inline key bytes"
        ))
    })?;
    let payload = PyDict::new(py);
    payload.set_item("backend", key.backend.as_str())?;
    payload.set_item("name", name)?;
    payload.set_item("version", record.version)?;
    payload.set_item("circuit_id", record.circuit_id)?;
    payload.set_item(
        "public_inputs_schema_hash_hex",
        hex_encode(record.public_inputs_schema_hash),
    )?;
    payload.set_item("curve", record.curve)?;
    payload.set_item("vk_len", record.vk_len)?;
    payload.set_item("max_proof_bytes", record.max_proof_bytes)?;
    payload.set_item("commitment_hex", hex_encode(record.commitment))?;
    if let Some(gas_schedule_id) = record.gas_schedule_id {
        payload.set_item("gas_schedule_id", gas_schedule_id)?;
    }
    payload.set_item("vk_bytes", BASE64.encode(&key.bytes))?;
    payload.set_item("status", "Active")?;
    Ok(payload.into_any().unbind())
}
#[pyfunction]
#[pyo3(name = "confidential_transfer_v2_verifying_key_registration_payload_v1")]
fn confidential_transfer_v2_verifying_key_registration_payload_v1_py(
    py: Python<'_>,
) -> PyResult<Py<PyAny>> {
    let record = iroha_core_zk::confidential_v2::confidential_transfer_v2_vk_record(
        "confidential_transfer_v2",
        1,
    )
    .map_err(|err| {
        PyValueError::new_err(format!(
            "failed to build confidential transfer v2 verifying-key registration payload: {err}"
        ))
    })?;
    confidential_vk_registration_payload_py(
        py,
        record,
        "confidential_transfer_v2",
        "confidential transfer v2",
    )
}
#[pyfunction]
#[pyo3(name = "confidential_unshield_v3_verifying_key_registration_payload_v1")]
fn confidential_unshield_v3_verifying_key_registration_payload_v1_py(
    py: Python<'_>,
) -> PyResult<Py<PyAny>> {
    let record = iroha_core_zk::confidential_v2::confidential_unshield_v3_vk_record(
        "confidential_unshield_v3",
        1,
    )
    .map_err(|err| {
        PyValueError::new_err(format!(
            "failed to build confidential unshield v3 verifying-key registration payload: {err}"
        ))
    })?;
    confidential_vk_registration_payload_py(
        py,
        record,
        "confidential_unshield_v3",
        "confidential unshield v3",
    )
}
fn py_sequence_items<'py>(
    value: &Bound<'py, PyAny>,
    context: &str,
) -> PyResult<Vec<Bound<'py, PyAny>>> {
    if let Ok(items) = value.cast::<PyList>() {
        return Ok(items.iter().collect());
    }
    if let Ok(items) = value.cast::<PyTuple>() {
        return Ok(items.iter().collect());
    }
    Err(PyTypeError::new_err(format!(
        "{context} must be a list or tuple"
    )))
}
fn dict_require_alias<'py>(
    dict: &Bound<'py, PyDict>,
    aliases: &[&str],
    context: &str,
) -> PyResult<Bound<'py, PyAny>> {
    dict_get_alias(dict, aliases)?
        .ok_or_else(|| PyValueError::new_err(format!("{context} is required")))
}
fn parse_confidential_amount_py(value: &Bound<'_, PyAny>, context: &str) -> PyResult<u128> {
    if value.is_instance_of::<pyo3::types::PyBool>() {
        return Err(PyTypeError::new_err(format!(
            "{context} must be a whole-number amount"
        )));
    }
    value
        .extract::<u128>()
        .map_err(|_| PyTypeError::new_err(format!("{context} must be a whole-number amount")))
}
fn parse_confidential_merkle_path_py(
    item: &Bound<'_, PyAny>,
    index: usize,
) -> PyResult<iroha_core_zk::confidential_v2::ConfidentialMerklePathV2> {
    let dict = item
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err(format!("input_paths[{index}] must be a mapping")))?;
    let siblings = dict_require_alias(
        dict,
        &["siblings"],
        &format!("input_paths[{index}].siblings"),
    )?;
    let directions = dict_require_alias(
        dict,
        &["directions"],
        &format!("input_paths[{index}].directions"),
    )?;
    let root = dict_require_alias(dict, &["root"], &format!("input_paths[{index}].root"))?;
    let witness_nodes = dict_get_alias(dict, &["witness_nodes", "witnessNodes"])?;
    let directions = py_sequence_items(&directions, &format!("input_paths[{index}].directions"))?
        .iter()
        .enumerate()
        .map(|(direction_index, item)| {
            item.extract::<u8>().map_err(|_| {
                PyTypeError::new_err(format!(
                    "input_paths[{index}].directions[{direction_index}] must be 0 or 1"
                ))
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    Ok(iroha_core_zk::confidential_v2::ConfidentialMerklePathV2 {
        siblings: py_fixed_array_list(&siblings, &format!("input_paths[{index}].siblings"))?,
        directions,
        witness_nodes: match witness_nodes {
            Some(value) => {
                py_fixed_array_list(&value, &format!("input_paths[{index}].witness_nodes"))?
            }
            None => Vec::new(),
        },
        root: py_fixed_array::<32>(&root, &format!("input_paths[{index}].root"))?,
    })
}
fn confidential_bytes_list_py<const N: usize>(
    py: Python<'_>,
    items: &[[u8; N]],
) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);
    for item in items {
        list.append(PyBytes::new(py, item))?;
    }
    Ok(list.unbind())
}
fn confidential_merkle_path_v2_py_dict(
    py: Python<'_>,
    leaf_index: usize,
    commitment: [u8; 32],
    path: iroha_core_zk::confidential_v2::ConfidentialMerklePathV2,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    let directions = PyList::empty(py);
    for direction in &path.directions {
        directions.append(*direction)?;
    }
    result.set_item("leaf_index", leaf_index)?;
    result.set_item("commitment", PyBytes::new(py, &commitment))?;
    result.set_item("siblings", confidential_bytes_list_py(py, &path.siblings)?)?;
    result.set_item("directions", directions)?;
    result.set_item(
        "witness_nodes",
        confidential_bytes_list_py(py, &path.witness_nodes)?,
    )?;
    result.set_item("root", PyBytes::new(py, &path.root))?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "compute_confidential_root_v2", signature = (tree_commitments))]
fn compute_confidential_root_v2_py(
    py: Python<'_>,
    tree_commitments: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let tree_commitments = py_fixed_array_list(tree_commitments, "tree_commitments")?;
    let root = iroha_core_zk::confidential_v2::compute_confidential_root_v2(&tree_commitments)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &root).unbind())
}
#[pyfunction]
#[pyo3(name = "derive_confidential_next_zero_path_v2", signature = (
    previous_leaf_commitment,
    previous_leaf_index,
    previous_path,
    root_hint
))]
fn derive_confidential_next_zero_path_v2_py(
    py: Python<'_>,
    previous_leaf_commitment: &Bound<'_, PyAny>,
    previous_leaf_index: usize,
    previous_path: &Bound<'_, PyAny>,
    root_hint: &Bound<'_, PyAny>,
) -> PyResult<Py<PyDict>> {
    let previous_leaf_commitment =
        py_fixed_array::<32>(previous_leaf_commitment, "previous_leaf_commitment")?;
    let previous_path = parse_confidential_merkle_path_py(previous_path, 0)?;
    let root_hint = py_fixed_array::<32>(root_hint, "root_hint")?;
    let path = iroha_core_zk::confidential_v2::derive_confidential_next_zero_path_v2(
        previous_leaf_commitment,
        previous_leaf_index,
        &previous_path,
        root_hint,
    )
    .map_err(PyValueError::new_err)?;
    let leaf_index = previous_leaf_index
        .checked_add(1)
        .ok_or_else(|| PyValueError::new_err("next zero leaf_index overflowed usize"))?;
    confidential_merkle_path_v2_py_dict(py, leaf_index, [0u8; 32], path)
}
#[pyfunction]
#[pyo3(name = "default_confidential_diversifier_v2")]
fn default_confidential_diversifier_v2_py(py: Python<'_>) -> Py<PyBytes> {
    PyBytes::new(
        py,
        &iroha_core_zk::confidential_v2::default_confidential_diversifier_v2(),
    )
    .unbind()
}
#[pyfunction]
#[pyo3(name = "derive_confidential_diversifier_v2", signature = (seed))]
fn derive_confidential_diversifier_v2_py(
    py: Python<'_>,
    seed: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let seed = confidential_wallet::secret_bytes(seed, 1024 * 1024)?;
    if seed.is_empty() {
        return Err(PyValueError::new_err(
            "confidential diversifier seed must not be empty",
        ));
    }
    let diversifier = iroha_core_zk::confidential_v2::derive_confidential_diversifier_v2(&seed);
    Ok(PyBytes::new(py, &diversifier).unbind())
}
#[pyfunction]
#[pyo3(name = "derive_confidential_owner_tag_v2", signature = (spend_key, diversifier))]
fn derive_confidential_owner_tag_v2_py(
    py: Python<'_>,
    spend_key: &Bound<'_, PyAny>,
    diversifier: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let spend_key = confidential_wallet::secret_bytes(spend_key, 1024 * 1024)?;
    if spend_key.is_empty() {
        return Err(PyValueError::new_err("spend_key must not be empty"));
    }
    let diversifier = confidential_wallet::secret_word(diversifier)?;
    let owner_tag =
        iroha_core_zk::confidential_v2::derive_confidential_owner_tag_v2_with_diversifier(
            &spend_key,
            *diversifier,
        )
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &owner_tag).unbind())
}
#[pyfunction]
#[pyo3(name = "derive_confidential_note_v2", signature = (
    asset_definition_id,
    amount,
    rho,
    owner_tag
))]
fn derive_confidential_note_v2_py(
    py: Python<'_>,
    asset_definition_id: String,
    amount: &Bound<'_, PyAny>,
    rho: &Bound<'_, PyAny>,
    owner_tag: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let asset_definition_id = asset_definition_id.trim();
    if asset_definition_id.is_empty() {
        return Err(PyValueError::new_err(
            "asset_definition_id must be non-empty",
        ));
    }
    let amount = Zeroizing::new(parse_confidential_amount_py(amount, "amount")?);
    let rho = confidential_wallet::secret_word(rho)?;
    let owner_tag = confidential_wallet::secret_word(owner_tag)?;
    let note_commitment = iroha_core_zk::confidential_v2::derive_confidential_note_v2(
        asset_definition_id,
        *amount,
        *rho,
        *owner_tag,
    )
    .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &note_commitment).unbind())
}
#[pyfunction]
#[pyo3(name = "seal_connect_payload")]
fn seal_connect_payload_py(
    py: Python<'_>,
    key: &[u8],
    sid: &[u8],
    direction: &str,
    sequence: u64,
    payload: &Bound<'_, PyDict>,
) -> PyResult<Py<PyBytes>> {
    let key_arr = fixed_array::<32>(key, "key")?;
    let sid_arr = fixed_array::<32>(sid, "sid")?;
    let dir = parse_connect_direction(direction)?;
    let payload = parse_connect_payload(payload)?;
    let frame = connect_sdk::seal_envelope(&key_arr, &sid_arr, dir, sequence, payload);
    let encoded = codec::Encode::encode(&frame);
    Ok(Py::from(PyBytes::new(py, encoded.as_slice())))
}
#[pyfunction]
#[pyo3(name = "open_connect_payload")]
fn open_connect_payload_py(py: Python<'_>, key: &[u8], frame_bytes: &[u8]) -> PyResult<Py<PyDict>> {
    let key_arr = fixed_array::<32>(key, "key")?;
    let frame = decode_connect_frame_bytes(frame_bytes)?;
    let envelope = connect_sdk::open_envelope(&key_arr, &frame).map_err(|err| {
        PyValueError::new_err(format!("failed to decrypt connect payload: {err}"))
    })?;
    let mapping = PyDict::new(py);
    mapping.set_item("seq", envelope.seq)?;
    let payload_dict = encode_connect_payload(py, &envelope.payload)?;
    mapping.set_item("payload", payload_dict)?;
    Ok(mapping.unbind())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use http::StatusCode;
    use ivm::bn254_vec::{self, FieldElem};
    use norito::to_bytes;
    use once_cell::sync::OnceCell;
    use pyo3::{
        Python,
        types::{PyBytes, PyDict, PyList},
    };
    use sorafs_car::multi_fetch::PolicyBlockEvidence;
    use std::fs;
    use tempfile::tempdir;
    const SAMPLE_RWA_ID: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities.universal";
    fn ensure_python() {
        static INIT: OnceCell<()> = OnceCell::new();
        INIT.get_or_init(|| {
            Python::initialize();
        });
    }
    #[test]
    fn confidential_registration_uses_exact_key_profile() {
        ensure_python();
        Python::attach(|py| {
            for backend in [
                "pipa-r/pasta/confidential-transfer-v1",
                "pipa-r/pasta/confidential-unshield-change-v1",
            ] {
                let mut record = iroha_data_model::proof::VerifyingKeyRecord::new(
                    1,
                    backend,
                    iroha_data_model::zk::BackendTag::NativePipaRPasta,
                    "vesta",
                    [0x11; 32],
                    [0x22; 32],
                );
                assert!(
                    confidential_vk_registration_payload_py(py, record.clone(), "key", "fixture")
                        .is_err()
                );
                record.vk_len = 3;
                record.key = Some(iroha_data_model::proof::VerifyingKeyBox::new(
                    backend.into(),
                    vec![1, 2, 3],
                ));
                let result = confidential_vk_registration_payload_py(py, record, "key", "fixture")
                    .expect("native registration payload");
                let fields = result
                    .bind(py)
                    .cast::<PyDict>()
                    .expect("payload dictionary");
                for (name, expected) in [
                    ("backend", backend),
                    ("circuit_id", backend),
                    ("vk_bytes", "AQID"),
                ] {
                    assert_eq!(
                        fields
                            .get_item(name)
                            .unwrap()
                            .unwrap()
                            .extract::<String>()
                            .unwrap(),
                        expected
                    );
                }
            }
        });
    }
    fn completion_authority_dict<'py>(
        py: Python<'py>,
        provider_owner: &str,
        completion_signer: &str,
    ) -> Bound<'py, PyDict> {
        let policy = PyDict::new(py);
        policy.set_item("policy_id", "21".repeat(32)).unwrap();
        policy.set_item("revision", 2).unwrap();
        policy
            .set_item("predecessor_digest", "32".repeat(32))
            .unwrap();
        policy.set_item("policy_digest", "43".repeat(32)).unwrap();
        let authority = PyDict::new(py);
        authority
            .set_item("provider_owner", provider_owner)
            .unwrap();
        authority
            .set_item("completion_signer", completion_signer)
            .unwrap();
        authority.set_item("signer_policy", policy).unwrap();
        authority
    }

    #[test]
    fn completion_authority_parser_preserves_distinct_signer_and_norito() {
        ensure_python();
        Python::attach(|py| {
            let owner = canonical_i105_from_seed(0x81);
            let signer = canonical_i105_from_seed(0x82);
            let mapping = completion_authority_dict(py, &owner, &signer);
            let parsed = parse_provider_ingest_completion_authority(&mapping).unwrap();
            assert_eq!(parsed.provider_owner.canonical_i105().unwrap(), owner);
            assert_eq!(parsed.completion_signer.canonical_i105().unwrap(), signer);
            assert_ne!(parsed.provider_owner, parsed.completion_signer);
            assert_eq!(parsed.signer_policy.revision, 2);
            assert_eq!(parsed.signer_policy.predecessor_digest, Some([0x32; 32]));
            let wire = norito::to_bytes(&parsed).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<ProviderIngestCompletionAuthorityV1>(&wire).unwrap(),
                parsed,
            );
            let json = norito::json::to_json(&parsed).unwrap();
            assert_eq!(
                norito::json::from_json::<ProviderIngestCompletionAuthorityV1>(&json).unwrap(),
                parsed,
            );
            mapping.set_item("completion_signer", &owner).unwrap();
            let changed = parse_provider_ingest_completion_authority(&mapping).unwrap();
            assert_eq!(changed.provider_owner, parsed.provider_owner);
            assert_eq!(changed.signer_policy, parsed.signer_policy);
            assert_ne!(changed.completion_signer, parsed.completion_signer);
            assert_ne!(norito::to_bytes(&changed).unwrap(), wire);
        });
    }

    #[test]
    fn completion_authority_parser_rejects_missing_and_unknown_fields() {
        ensure_python();
        Python::attach(|py| {
            let owner = canonical_i105_from_seed(0x81);
            let signer = canonical_i105_from_seed(0x82);
            let retired = completion_authority_dict(py, &owner, &signer);
            retired.del_item("completion_signer").unwrap();
            let error = parse_provider_ingest_completion_authority(&retired)
                .expect_err("retired owner-only authority cannot infer its signer");
            assert!(error.value(py).to_string().contains("completion_signer"));
            let substituted = completion_authority_dict(py, &owner, &signer);
            substituted.del_item("completion_signer").unwrap();
            substituted.set_item("signer", &signer).unwrap();
            assert!(parse_provider_ingest_completion_authority(&substituted).is_err());
            let extended = completion_authority_dict(py, &owner, &signer);
            extended.set_item("relayer", &signer).unwrap();
            assert!(parse_provider_ingest_completion_authority(&extended).is_err());
        });
    }

    #[test]
    fn completion_authority_parser_rejects_invalid_completion_signer() {
        ensure_python();
        Python::attach(|py| {
            let owner = canonical_i105_from_seed(0x81);
            let signer = canonical_i105_from_seed(0x82);
            let mapping = completion_authority_dict(py, &owner, &signer);
            for invalid in [
                String::new(),
                format!(" {signer}"),
                "merchant@bank".into(),
                "00".repeat(32),
            ] {
                mapping.set_item("completion_signer", invalid).unwrap();
                let error = parse_provider_ingest_completion_authority(&mapping)
                    .expect_err("completion signer must be an exact canonical account");
                assert!(error.value(py).to_string().contains("completion_signer"));
            }
            mapping.set_item("completion_signer", py.None()).unwrap();
            let error = parse_provider_ingest_completion_authority(&mapping)
                .expect_err("null completion signer must be refused");
            assert!(
                error
                    .value(py)
                    .to_string()
                    .contains("completion_signer must be a string")
            );
            mapping.set_item("completion_signer", 7).unwrap();
            assert!(parse_provider_ingest_completion_authority(&mapping).is_err());
        });
    }

    fn python_test_network_id() -> PyNetworkId {
        PyNetworkId::from_exact_bytes(&[0xA5; Hash::LENGTH]).expect("marked test NetworkId")
    }
    #[test]
    fn provider_completion_authority_requires_exact_distinct_signer() {
        ensure_python();
        let owner = AccountId::new(PublicKey::from(parse_private_key(&[0x11; 32]).unwrap()));
        let signer = AccountId::new(PublicKey::from(parse_private_key(&[0x22; 32]).unwrap()));
        Python::attach(|py| {
            let policy = PyDict::new(py);
            policy.set_item("policy_id", "21".repeat(32)).unwrap();
            policy.set_item("revision", 1).unwrap();
            policy.set_item("predecessor_digest", py.None()).unwrap();
            policy.set_item("policy_digest", "43".repeat(32)).unwrap();
            let authority = PyDict::new(py);
            authority
                .set_item("provider_owner", owner.canonical_i105().unwrap())
                .unwrap();
            authority
                .set_item("completion_signer", signer.canonical_i105().unwrap())
                .unwrap();
            authority.set_item("signer_policy", policy).unwrap();
            let decoded = parse_provider_ingest_completion_authority(&authority).unwrap();
            assert_eq!(decoded.provider_owner, owner);
            assert_eq!(decoded.completion_signer, signer);
            authority.del_item("completion_signer").unwrap();
            assert!(parse_provider_ingest_completion_authority(&authority).is_err());
            authority
                .set_item("completion_signer", "not-an-account")
                .unwrap();
            assert!(parse_provider_ingest_completion_authority(&authority).is_err());
        });
    }
    #[test]
    fn privacy_capability_native_builder_rejects_offline_inspection() {
        ensure_python();
        let private_key = parse_private_key(&[0x11; 32]).expect("seeded private key");
        let authority = AccountId::new(PublicKey::from(private_key))
            .canonical_i105()
            .expect("canonical authority");
        let mut builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("ordinary transaction builder");
        let inspected = privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1::test_binding_for_protocol(
            PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        );
        Python::attach(|py| {
            let manifest = Py::new(py, inspected).expect("native inspection object");
            let error = builder
                .bind_privacy_exact12_capability_manifest_v1(manifest.bind(py).borrow())
                .expect_err("public native builder must reject an offline archive");
            assert!(error.to_string().contains("inspection-only"));
        });
        assert!(builder.privacy_capability_manifest.is_none());
    }
    #[test]
    fn faucet_claim_hash_matches_canonical_payload_and_binds_all_three_fields() {
        ensure_python();
        use norito::codec::Encode as _;
        let account = taira_i105_from_seed(0x74);
        let claim = PythonAccountFaucetClaimV1 {
            account_id: account.clone(),
            pow_anchor_height: 7,
            pow_nonce_hex: "00ff".into(),
        };
        let encoded = claim.encode();
        let expected =
            Hash::new_from_chunks(&[b"iroha:accounts:faucet:claim:v1\0", encoded.as_slice()]);
        let actual = account_faucet_claim_hash_v1_py(&account, 7, "00ff").unwrap();
        assert_eq!(actual, hex_encode(expected.as_ref()));
        for (other_account, height, nonce) in [
            (taira_i105_from_seed(0x75), 7, "00ff"),
            (account.clone(), 8, "00ff"),
            (account.clone(), 7, "00fe"),
        ] {
            assert_ne!(
                account_faucet_claim_hash_v1_py(&other_account, height, nonce).unwrap(),
                actual
            );
        }
    }
    #[test]
    fn faucet_claim_hash_refuses_noncanonical_claim_fields() {
        ensure_python();
        let account = taira_i105_from_seed(0x74);
        assert!(account_faucet_claim_hash_v1_py(&account, 0, "00").is_err());
        for nonce in ["", "0", "AB", " 00", "00 ", "0x00", "gg", &"00".repeat(33)] {
            assert!(account_faucet_claim_hash_v1_py(&account, 1, nonce).is_err());
        }
        for invalid_account in [
            String::new(),
            "alias@domain".into(),
            format!(" {account}"),
            format!("{account} "),
        ] {
            assert!(account_faucet_claim_hash_v1_py(&invalid_account, 1, "00").is_err());
        }
        assert!(account_faucet_claim_hash_v1_py(&account, u64::MAX, &"ff".repeat(32)).is_ok());
    }
    #[test]
    fn prepared_binding_parser_accepts_only_the_exact_v1_shape() {
        let binding = r#"{
            "schema":"iroha.prepared-operation.binding.v1",
            "semantic_hash_hex":"0000000000000000000000000000000000000000000000000000000000000000",
            "kind":"faucet",
            "request_id":"1111111111111111111111111111111111111111111111111111111111111111",
            "execution_expires_at_unix_ms":1
        }"#;
        assert!(require_prepared_binding_json_v1(binding, "faucet").is_ok());
        assert!(require_prepared_binding_json_v1(binding, "onboarding").is_err());
        let with_legacy_field = binding.replace(
            "\"execution_expires_at_unix_ms\":1",
            "\"execution_expires_at_unix_ms\":1,\"legacy\":true",
        );
        assert!(require_prepared_binding_json_v1(&with_legacy_field, "faucet").is_err());
    }
    #[test]
    fn onboarding_receipt_verifier_rejects_non_v1_json_before_trust_pins() {
        let network_id = python_test_network_id();
        assert!(
            verify_account_onboarding_receipt_v1_py(
                "{}",
                &network_id,
                "not-an-account",
                "not-an-account",
                "merchant@universal",
                "[]",
            )
            .is_err()
        );
    }
    #[test]
    fn python_network_id_rejects_bare_labels_unmarked_hashes_and_noncanonical_literals() {
        ensure_python();
        assert!(PyNetworkId::parse("test-chain").is_err());
        assert!(PyNetworkId::from_exact_bytes(&[0xA4; Hash::LENGTH]).is_err());
        assert!(PyNetworkId::from_exact_bytes(&[0xA5; Hash::LENGTH - 1]).is_err());
        let network_id = python_test_network_id();
        let literal = network_id.literal().expect("canonical NetworkId literal");
        assert_eq!(
            literal,
            "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
        );
        assert_eq!(
            PyNetworkId::parse(&literal)
                .expect("canonical literal")
                .inner,
            network_id.inner
        );
        assert!(PyNetworkId::parse(&literal.to_ascii_lowercase()).is_err());
        assert_eq!(
            PyNetworkId::parse(&network_id.inner.to_string())
                .expect("NetworkId Display is the canonical Python input")
                .inner,
            network_id.inner
        );
    }
    #[test]
    fn sorafs_orderbook_owner_account_validation_enforces_v1_byte_ceiling() {
        ensure_python();
        assert!(
            validate_sorafs_orderbook_owner_account_py(
                &[0x45; sorafs_manifest::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1]
            )
            .is_ok()
        );
        assert!(
            validate_sorafs_orderbook_owner_account_py(
                &[0x45; sorafs_manifest::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + 1]
            )
            .is_err()
        );
    }
    fn py_err_message(err: pyo3::PyErr) -> String {
        ensure_python();
        Python::attach(|py| err.value(py).to_string())
    }
    #[test]
    fn sorafs_alias_defaults_match_the_canonical_service_policy() {
        let actual = sorafs_default_policy();
        assert_eq!(
            [
                actual.positive_ttl(),
                actual.refresh_window(),
                actual.hard_expiry(),
                actual.negative_ttl(),
                actual.revocation_ttl(),
                actual.rotation_max_age(),
                actual.successor_grace(),
                actual.governance_grace(),
            ],
            [
                Duration::from_secs(sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_REFRESH_WINDOW_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_HARD_EXPIRY_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_NEGATIVE_TTL_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_REVOCATION_TTL_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_ROTATION_MAX_AGE_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_SUCCESSOR_GRACE_SECS),
                Duration::from_secs(sorafs::DEFAULT_ALIAS_GOVERNANCE_GRACE_SECS),
            ]
        );
    }
    #[test]
    fn sorafs_alias_policy_parser_accepts_zero_grace_and_rejects_retired_shapes() {
        ensure_python();
        Python::attach(|py| {
            let defaults = sorafs_default_policy();
            let mapping = alias_policy_to_dict(py, &defaults).expect("encode default policy");
            let parsed = alias_policy_from_py(Some(mapping.bind(py)))
                .expect("the canonical default policy must parse");
            assert_eq!(parsed.successor_grace(), defaults.successor_grace());
            assert_eq!(parsed.governance_grace(), Duration::ZERO);

            let zero_successor = PyDict::new(py);
            zero_successor
                .set_item("successor_grace_secs", 0)
                .expect("set policy field");
            let parsed = alias_policy_from_py(Some(&zero_successor))
                .expect("zero successor grace must be accepted");
            assert_eq!(parsed.successor_grace(), Duration::ZERO);

            let camel_case = PyDict::new(py);
            camel_case
                .set_item("positiveTtlSecs", 600)
                .expect("set retired policy field");
            let err = alias_policy_from_py(Some(&camel_case))
                .expect_err("camel-case policy aliases must be rejected");
            assert!(err.value(py).to_string().contains("unsupported"));

            let boolean = PyDict::new(py);
            boolean
                .set_item("positive_ttl_secs", true)
                .expect("set invalid policy field");
            let err = alias_policy_from_py(Some(&boolean))
                .expect_err("boolean policy fields must be rejected");
            assert!(err.value(py).to_string().contains("must be an integer"));
        });
    }
    const MALFORMED_ED25519_PUBLIC_KEYS: [(&str, [u8; 32], &str); 3] = [
        ("all-zero", [0u8; 32], "all zero"),
        (
            "small-order",
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            "small-order",
        ),
        (
            "noncanonical",
            [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            "non-canonical",
        ),
    ];
    fn canonical_i105_from_seed(seed: u8) -> String {
        AccountId::new(PublicKey::from(parse_private_key(&[seed; 32]).unwrap()))
            .canonical_i105()
            .expect("canonical I105")
    }
    fn taira_i105_from_seed(seed: u8) -> String {
        AccountId::new(PublicKey::from(parse_private_key(&[seed; 32]).unwrap()))
            .to_i105_for_discriminant(369)
            .expect("Taira I105")
    }
    fn custom_i105_from_seed(seed: u8, discriminant: u16) -> String {
        AccountId::new(PublicKey::from(parse_private_key(&[seed; 32]).unwrap()))
            .to_i105_for_discriminant(discriminant)
            .expect("custom I105")
    }
    fn sample_account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive Python fixture account key");
        AccountId::new(keypair.public_key().clone())
    }
    fn authority_fee_payment_json() -> &'static str {
        r#"{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}}"#
    }
    fn envelope_json_with_crypto_fields(
        envelope: &SignedTransactionEnvelope,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> String {
        SignedTransactionEnvelope {
            network_id: envelope.network_id,
            authority: envelope.authority.clone(),
            signed_transaction: envelope.signed_transaction.clone(),
            signed_transaction_versioned: envelope.signed_transaction_versioned.clone(),
            hash: envelope.hash,
            signature,
            public_key,
        }
        .to_json()
        .expect("test envelope JSON")
    }
    include!("tests/python_crypto_boundary_tests.rs");
    #[test]
    fn native_sdk_bridge_abi_version_is_exactly_twenty_two() {
        assert_eq!(connect_norito_bridge_abi_version_py(), 31);
    }
    #[test]
    fn attachments_json_decodes_versioned_signed_transaction() {
        ensure_python();
        let signing = SigningKey::from_bytes(&[0x11u8; 32]);
        let private_key =
            parse_private_key(signing.as_bytes()).expect("ed25519 private key parses");
        let public_key = PublicKey::from(private_key.clone());
        let authority = AccountId::new(public_key.clone())
            .canonical_i105()
            .expect("canonical I105 authority");
        let mut builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs");
        let envelope = builder.sign(signing.as_bytes()).expect("transaction signs");
        let attachments = envelope
            .attachments_json()
            .expect("attachments decode succeeds");
        assert!(attachments.is_none());
        assert_eq!(envelope.network_id, python_test_network_id().inner);
        let wrong_network = PyNetworkId::from_exact_bytes(&[0xA7; Hash::LENGTH])
            .expect("marked wrong-network identity");
        assert!(
            signed_transaction_envelope_from_versioned_v1_py(
                &envelope.signed_transaction_versioned,
                &wrong_network,
            )
            .is_err(),
            "a valid signature from another NetworkId must reject",
        );
        let envelope_json = envelope.to_json().expect("envelope JSON");
        Python::attach(|py| {
            let envelope_dict = envelope.as_dict(py).expect("envelope dictionary");
            let dictionary_network_id = envelope_dict
                .bind(py)
                .get_item("network_id")
                .expect("read envelope network ID")
                .expect("envelope network ID is present")
                .extract::<String>()
                .expect("envelope network ID is a string");
            assert_eq!(
                dictionary_network_id,
                canonical_network_id_literal(&envelope.network_id)
            );
            let envelope_type = py.get_type::<SignedTransactionEnvelope>();
            let restored = SignedTransactionEnvelope::from_json(&envelope_type, &envelope_json)
                .expect("exact envelope JSON roundtrip");
            assert_eq!(restored.network_id, envelope.network_id);
            let short_signature_json = envelope_json_with_crypto_fields(
                &envelope,
                envelope.signature[..63].to_vec(),
                envelope.public_key.clone(),
            );
            let Err(error) =
                SignedTransactionEnvelope::from_json(&envelope_type, &short_signature_json)
            else {
                panic!("63-byte Ed25519 envelope signature must reject");
            };
            assert!(
                error
                    .to_string()
                    .contains("ed25519 signature must be 64 bytes"),
                "unexpected Ed25519 geometry error: {error}"
            );
            for retired_key in [
                "chain",
                "chainId",
                "chain_id",
                "canonicalGenesisHash",
                "canonical_genesis_hash",
                "genesisHash",
                "genesis_hash",
            ] {
                let retired =
                    envelope_json.replacen("\"network_id\"", &format!("\"{retired_key}\""), 1);
                assert!(
                    SignedTransactionEnvelope::from_json(&envelope_type, &retired).is_err(),
                    "retired {retired_key} envelope metadata must reject",
                );
            }
            let unsupported =
                envelope_json.replacen("\"authority\"", "\"unsupported\":true,\"authority\"", 1);
            assert!(
                SignedTransactionEnvelope::from_json(&envelope_type, &unsupported).is_err(),
                "unknown envelope metadata must reject",
            );
        });
        let recomputed =
            canonical_signed_transaction_hash_v1(&envelope.signed_transaction_versioned)
                .expect("exact signed envelope hashes");
        assert_eq!(recomputed, envelope.hash);
        assert!(
            verify_signed_transaction_versioned_py(&envelope.signed_transaction_versioned)
                .expect("canonical signed envelope verifies")
        );
        let mut tampered = envelope.signed_transaction_versioned.clone();
        let last = tampered
            .last_mut()
            .expect("signed transaction is non-empty");
        *last ^= 0x01;
        assert!(canonical_signed_transaction_hash_v1(&tampered).is_err());
    }
    #[test]
    fn ml_dsa_signed_transaction_envelope_json_roundtrip_is_algorithm_aware() {
        ensure_python();
        let keypair = KeyPair::try_from_seed(vec![0xA6; 32], Algorithm::MlDsa)
            .expect("derive ML-DSA-65 envelope fixture key");
        let authority = AccountId::new(keypair.public_key().clone());
        let fee_payment = parse_fee_payment_intent_json(authority_fee_payment_json())
            .expect("authority fee payment parses");
        let signed =
            ModelTransactionBuilder::new(python_test_network_id().inner, authority, fee_payment)
                .try_sign(keypair.private_key())
                .expect("ML-DSA-65 transaction signs");
        let envelope = signed_transaction_envelope_from_model_v1(&signed)
            .expect("authenticated ML-DSA-65 envelope");
        assert_eq!(
            envelope.signature.len(),
            Algorithm::MlDsa.signature_payload_len()
        );
        assert_eq!(envelope.public_key.len(), 1_952);
        let envelope_json = envelope.to_json().expect("ML-DSA-65 envelope JSON");
        Python::attach(|py| {
            let envelope_type = py.get_type::<SignedTransactionEnvelope>();
            let restored = SignedTransactionEnvelope::from_json(&envelope_type, &envelope_json)
                .expect("ML-DSA-65 envelope JSON roundtrip");
            assert_eq!(restored.signature, envelope.signature);
            assert_eq!(restored.public_key, envelope.public_key);

            let cases = [
                (
                    "short signature",
                    envelope.signature[..envelope.signature.len() - 1].to_vec(),
                    envelope.public_key.clone(),
                    "ml-dsa signature must be 3309 bytes",
                ),
                (
                    "short public key",
                    envelope.signature.clone(),
                    envelope.public_key[..envelope.public_key.len() - 1].to_vec(),
                    "invalid ML-DSA public key length",
                ),
                (
                    "all-zero signature",
                    vec![0; envelope.signature.len()],
                    envelope.public_key.clone(),
                    "all zero",
                ),
                (
                    "all-zero public key",
                    envelope.signature.clone(),
                    vec![0; envelope.public_key.len()],
                    "all-zero material",
                ),
            ];
            for (label, signature, public_key, expected) in cases {
                let malformed = envelope_json_with_crypto_fields(&envelope, signature, public_key);
                let Err(error) = SignedTransactionEnvelope::from_json(&envelope_type, &malformed)
                else {
                    panic!("{label} must reject");
                };
                assert!(
                    error.to_string().contains(expected),
                    "{label}: expected {expected:?}, got {error}"
                );
            }
        });
    }
    #[test]
    fn generated_sm2_keypair_uses_checked_os_entropy() {
        ensure_python();
        Python::attach(|py| {
            let distid = "python-sdk-random-key";
            let (private, public) =
                generate_sm2_keypair_py(py, Some(distid)).expect("generate checked SM2 keypair");
            let private_bytes = private.bind(py).as_bytes();
            let public_bytes = public.bind(py).as_bytes();
            assert_eq!(private_bytes.len(), SM2_PRIVATE_KEY_LENGTH);
            assert_eq!(public_bytes.len(), SM2_PUBLIC_KEY_UNCOMPRESSED_LENGTH);
            let parsed =
                Sm2PrivateKey::from_bytes(distid, private_bytes).expect("parse generated key");
            assert_eq!(parsed.public_key().to_sec1_bytes(false), public_bytes);
        });
    }
    #[test]
    fn transaction_builder_attachment_limits_are_atomic_and_remain_signable() {
        ensure_python();
        let signing = SigningKey::from_bytes(&[0x12_u8; 32]);
        let private_key = parse_private_key(signing.as_bytes()).expect("private key parses");
        let authority = AccountId::new(PublicKey::from(private_key.clone()))
            .canonical_i105()
            .expect("canonical I105 authority");
        let mut builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs");
        let attachment = |byte| {
            ProofAttachment::new_ref(
                "pipa-r/pasta".into(),
                ProofBox::new("pipa-r/pasta".into(), vec![byte]),
                VerifyingKeyId::new("pipa-r/pasta", "python-builder-vk"),
            )
        };
        for byte in 0..iroha_data_model::proof::PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1 {
            builder
                .try_add_proof_attachment(attachment(
                    u8::try_from(byte).expect("first-release attachment limit fits in u8"),
                ))
                .expect("attachment through the exact verifier batch boundary");
        }
        let before = norito::encode_canonical(
            builder
                .attachments
                .as_ref()
                .expect("maximum attachment list is present"),
        )
        .expect("encode maximum attachment list");
        let error = builder
            .try_add_proof_attachment(attachment(0xFF))
            .expect_err("the seventeenth attachment must be rejected");
        assert!(error.to_string().contains("maximum of 16"));
        assert_eq!(
            norito::encode_canonical(
                builder
                    .attachments
                    .as_ref()
                    .expect("rejected append preserves prior list"),
            )
            .expect("encode rolled-back attachment list"),
            before
        );
        let signed = builder
            .to_model_builder()
            .try_sign(&private_key)
            .expect("builder remains signable after rejected append");
        assert_eq!(
            signed
                .proof_attachments_v1()
                .expect("signed transaction retains its proof carriers")
                .len(),
            iroha_data_model::proof::PROOF_ATTACHMENT_LIST_MAX_ATTACHMENTS_V1
        );
        signed
            .validate_signed_attachments_v1()
            .expect("carriers are bound to the signed payload");
        signed.verify_signature().expect("signature remains valid");
        builder.clear_attachments();
        assert!(builder.attachments.is_none());
        builder
            .try_add_proof_attachment(attachment(7))
            .expect("builder is reusable after clearing attachments");
        assert_eq!(
            builder.attachments.as_ref().map(ProofAttachmentList::len),
            Some(1)
        );
    }
    #[test]
    fn transaction_builder_attachment_frame_rejection_rolls_back() {
        ensure_python();
        let signing = SigningKey::from_bytes(&[0x13_u8; 32]);
        let private_key = parse_private_key(signing.as_bytes()).expect("private key parses");
        let authority = AccountId::new(PublicKey::from(private_key))
            .canonical_i105()
            .expect("canonical I105 authority");
        let mut builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs");
        let attachment = |proof_bytes| {
            ProofAttachment::new_ref(
                "pipa-r/pasta".into(),
                ProofBox::new("pipa-r/pasta".into(), vec![0_u8; proof_bytes]),
                VerifyingKeyId::new("pipa-r/pasta", "python-builder-vk"),
            )
        };
        let mut low = 1_usize;
        let mut high = iroha_data_model::proof::PROOF_ATTACHMENT_LIST_MAX_CANONICAL_FRAME_BYTES_V1;
        while low < high {
            let midpoint = low + (high - low).div_ceil(2);
            if ProofAttachmentList::try_from(vec![attachment(midpoint)]).is_ok() {
                low = midpoint;
            } else {
                high = midpoint - 1;
            }
        }
        builder
            .try_add_proof_attachment(attachment(low))
            .expect("largest fitting first attachment");
        let before = norito::encode_canonical(
            builder
                .attachments
                .as_ref()
                .expect("large attachment list is present"),
        )
        .expect("encode exact-cap attachment list");
        let error = builder
            .try_add_proof_attachment(attachment(1))
            .expect_err("append over the frame ceiling must fail");
        assert!(error.to_string().contains("canonical frame"));
        assert_eq!(
            norito::encode_canonical(
                builder
                    .attachments
                    .as_ref()
                    .expect("rejected append preserves exact-cap list"),
            )
            .expect("encode rolled-back exact-cap list"),
            before
        );
        builder.clear_attachments();
        assert!(builder.attachments.is_none());
    }
    #[test]
    fn signed_transaction_python_boundaries_use_the_canonical_transaction_limit() {
        let maximum = usize::try_from(
            iroha_data_model::parameter::system::TransactionParameters::default()
                .max_tx_bytes()
                .get(),
        )
        .expect("canonical transaction limit fits the test platform");
        let adversarial = vec![0_u8; maximum + 1];
        assert!(require_canonical_signed_transaction_wire_size_v1(&[]).is_err());
        assert!(require_canonical_signed_transaction_wire_size_v1(&adversarial[..maximum]).is_ok());
        assert!(require_canonical_signed_transaction_wire_size_v1(&adversarial).is_err());
        let exact_bound_error = canonical_signed_transaction_hash_v1(&adversarial[..maximum])
            .expect_err("malformed exact-bound input must not authenticate");
        assert!(
            exact_bound_error
                .to_string()
                .contains("not a valid current signed transaction")
        );
        let oversized_error = canonical_signed_transaction_hash_v1(&adversarial)
            .expect_err("oversized input must reject before decoding");
        assert!(
            oversized_error
                .to_string()
                .contains(&format!("between 1 and {maximum} bytes"))
        );
        assert!(verify_signed_transaction_versioned_py(&[]).is_err());
        assert!(verify_signed_transaction_versioned_py(&adversarial[..maximum]).is_err());
        assert!(verify_signed_transaction_versioned_py(&adversarial).is_err());
    }
    #[test]
    fn transaction_builder_rejects_invalid_network_and_authority() {
        ensure_python();
        let signing = SigningKey::from_bytes(&[0x12u8; 32]);
        let public_key = PublicKey::from(parse_private_key(signing.as_bytes()).expect("private"));
        let authority = AccountId::new(public_key)
            .canonical_i105()
            .expect("canonical I105 authority");
        for padded_authority in [format!(" {authority}"), format!("{authority} ")] {
            let err = match TransactionBuilder::new(
                &python_test_network_id(),
                &padded_authority,
                authority_fee_payment_json(),
            ) {
                Ok(_) => panic!("padded authority must reject before account parsing"),
                Err(err) => err,
            };
            assert_eq!(
                err.to_string(),
                "ValueError: authority must not contain surrounding whitespace"
            );
        }
    }
    #[test]
    fn python_scoreboard_metadata_records_policy_labels() {
        let metadata = python_scoreboard_metadata(
            3,
            0,
            false,
            42,
            "sdk:python",
            Some("iad-prod"),
            Some(4),
            Some(2),
            Some(3),
            Some(5),
            TransportPolicy::SoranetPreferred,
            Some(TransportPolicy::DirectOnly),
            AnonymityPolicy::GuardPq,
            Some(AnonymityPolicy::StrictPq),
        );
        let map = metadata
            .as_object()
            .expect("scoreboard metadata should be an object");
        assert_eq!(
            map.get("gateway_provider_count")
                .and_then(json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            map.get("gateway_manifest_provided")
                .and_then(json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            map.get("transport_policy").and_then(json::Value::as_str),
            Some("direct-only")
        );
        assert_eq!(
            map.get("transport_policy_override")
                .and_then(json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            map.get("transport_policy_override_label")
                .and_then(json::Value::as_str),
            Some("direct-only")
        );
        assert_eq!(
            map.get("anonymity_policy").and_then(json::Value::as_str),
            Some("anon-strict-pq")
        );
        assert_eq!(
            map.get("anonymity_policy_override")
                .and_then(json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            map.get("telemetry_region").and_then(json::Value::as_str),
            Some("iad-prod")
        );
    }
    #[test]
    fn python_scoreboard_metadata_defaults_soranet_first() {
        let metadata = python_scoreboard_metadata(
            1,
            0,
            false,
            0,
            "sdk:python",
            None,
            None,
            None,
            None,
            None,
            TransportPolicy::SoranetPreferred,
            None,
            AnonymityPolicy::GuardPq,
            None,
        );
        let map = metadata
            .as_object()
            .expect("scoreboard metadata should be an object");
        assert_eq!(
            map.get("transport_policy").and_then(json::Value::as_str),
            Some("soranet-first")
        );
        assert_eq!(
            map.get("transport_policy_override")
                .and_then(json::Value::as_bool),
            Some(false)
        );
        assert!(
            map.get("transport_policy_override_label")
                .is_some_and(json::Value::is_null)
        );
        assert_eq!(
            map.get("anonymity_policy").and_then(json::Value::as_str),
            Some("anon-guard-pq")
        );
        assert!(
            map.get("anonymity_policy_override_label")
                .is_some_and(json::Value::is_null)
        );
    }
    #[test]
    fn python_gateway_policy_parsers_accept_only_exact_v1_labels() {
        ensure_python();
        for (label, expected) in [
            ("soranet-first", TransportPolicy::SoranetPreferred),
            ("soranet-strict", TransportPolicy::SoranetStrict),
            ("direct-only", TransportPolicy::DirectOnly),
        ] {
            assert_eq!(
                parse_gateway_transport_policy_v1(label).expect("canonical transport policy"),
                expected
            );
        }
        for rejected in [
            "",
            " soranet-first",
            "soranet-first ",
            "SORANET-FIRST",
            "soranet_first",
            "soranet_strict",
            "direct_only",
            "soranet-only",
            "soranet_only",
        ] {
            assert!(
                parse_gateway_transport_policy_v1(rejected).is_err(),
                "noncanonical transport label `{rejected}` must fail"
            );
        }
        for (label, expected) in [
            ("canary", RolloutPhase::Canary),
            ("ramp", RolloutPhase::Ramp),
            ("default", RolloutPhase::Default),
        ] {
            assert_eq!(
                parse_gateway_rollout_phase_v1(label).expect("canonical rollout phase"),
                expected
            );
        }
        for rejected in [
            "", " canary", "canary ", "CANARY", "stage_a", "stage-a", "stagea", "stage_b",
            "stage-b", "stageb", "stage_c", "stage-c", "stagec", "ga",
        ] {
            assert!(
                parse_gateway_rollout_phase_v1(rejected).is_err(),
                "noncanonical rollout label `{rejected}` must fail"
            );
        }
        for (label, expected) in [
            ("anon-guard-pq", AnonymityPolicy::GuardPq),
            ("anon-majority-pq", AnonymityPolicy::MajorityPq),
            ("anon-strict-pq", AnonymityPolicy::StrictPq),
        ] {
            assert_eq!(
                parse_gateway_anonymity_policy_v1(label).expect("canonical anonymity policy"),
                expected
            );
        }
        for rejected in [
            "",
            " anon-guard-pq",
            "anon-guard-pq ",
            "ANON-GUARD-PQ",
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
        ] {
            assert!(
                parse_gateway_anonymity_policy_v1(rejected).is_err(),
                "noncanonical anonymity label `{rejected}` must fail"
            );
        }
    }
    #[test]
    fn python_scoreboard_metadata_records_gateway_fields() {
        let metadata = python_scoreboard_metadata(
            0,
            2,
            true,
            0,
            "sdk:python",
            None,
            None,
            None,
            None,
            None,
            TransportPolicy::SoranetPreferred,
            None,
            AnonymityPolicy::GuardPq,
            None,
        );
        let map = metadata
            .as_object()
            .expect("scoreboard metadata should be an object");
        assert_eq!(
            map.get("gateway_provider_count")
                .and_then(json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            map.get("gateway_manifest_provided")
                .and_then(json::Value::as_bool),
            Some(true)
        );
    }
    #[test]
    fn direct_dataspace_registration_preserves_exact_native_id_and_definition() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            for id in [9_007_199_254_740_993, u64::MAX] {
                let dataspace = pyo3::types::PyInt::new(py, id);
                for policy in ["Global", "DataspaceRestricted"] {
                    let instruction = Instruction::register_dataspace_asset_definition(
                        &instruction_type,
                        py,
                        "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                        dataspace.as_any(),
                        policy,
                        "coin",
                        Some("direct namespace"),
                        None,
                        Some(2),
                        Some("Once"),
                        None,
                    )
                    .expect("explicit direct home builds");
                    let decoded = json::from_str::<InstructionBox>(
                        &instruction.to_json().expect("native instruction JSON"),
                    )
                    .expect("native instruction JSON decodes");
                    let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*decoded;
                    let direct = instruction_ref
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::RegisterDataspaceAssetDefinition>()
                        .expect("standalone direct-dataspace registration");
                    assert_eq!(direct.dataspace_id.as_u64(), id);
                    assert_eq!(
                        direct.object.balance_scope_policy,
                        parse_balance_scope_policy(policy).expect("policy")
                    );
                    assert!(direct.object.owning_domain.is_none());
                    assert_eq!(direct.object.name, "coin");
                    assert_eq!(
                        direct.object.description.as_deref(),
                        Some("direct namespace")
                    );
                    assert_eq!(
                        direct.object.spec,
                        numeric_spec_from_optional_scale(Some(2)).unwrap()
                    );
                    assert_eq!(direct.object.mintable, Mintable::Once);
                    assert_eq!(
                        instruction.to_json().expect("original instruction JSON"),
                        json::to_json(&decoded).expect("decoded instruction JSON")
                    );
                }
            }
        });
    }

    #[test]
    fn bilateral_settlement_retry_is_a_rejected_carrier_for_both_dispositions() {
        use iroha_data_model::executor::{SettlementReplayDispositionV1, SettlementReplayV1};
        let owner = parse_account_id(&canonical_i105_from_seed(0x11)).unwrap();
        for disposition in [
            SettlementReplayDispositionV1::AlreadySettled,
            SettlementReplayDispositionV1::ConflictingIntent,
        ] {
            let reason = TransactionRejectionReason::Validation(ValidationFail::SettlementReplay(
                Box::new(SettlementReplayV1 {
                    settlement_id: SettlementId::new(owner.clone(), "retry".parse().unwrap()),
                    disposition,
                    committed_block_height: 2,
                    committed_block_hash: HashOf::from_untyped_unchecked(Hash::new(
                        b"original successful payment",
                    )),
                }),
            ));
            assert_eq!(transaction_rejection_code(&reason), "SettlementReplay");
        }
    }

    #[test]
    fn bilateral_atomicity_rejects_retired_partial_names() {
        ensure_python();
        Python::attach(|_| {
            assert_eq!(
                parse_settlement_atomicity("all_or_nothing").unwrap(),
                SettlementAtomicity::AllOrNothing
            );
            for value in [
                "commit_first_leg",
                "commit_second_leg",
                "CommitFirstLeg",
                "CommitSecondLeg",
                "unknown",
            ] {
                let error = parse_settlement_atomicity(value).expect_err("closed atomicity policy");
                assert!(error.to_string().contains("unknown settlement atomicity"));
            }
        });
    }
    #[test]
    fn bilateral_settlement_identity_is_scoped_and_survives_native_json() {
        use iroha_data_model::isi::SettlementInstructionBox;
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let payer = canonical_i105_from_seed(0x11);
            let counterparty = canonical_i105_from_seed(0x22);
            let unrelated = canonical_i105_from_seed(0x33);
            let leg = |definition: &str, from: &str, to: &str| {
                let value = PyDict::new(py);
                value.set_item("asset_definition_id", definition).unwrap();
                value.set_item("quantity", "10").unwrap();
                value.set_item("from", from).unwrap();
                value.set_item("to", to).unwrap();
                value
            };
            let first = leg("7cgpbDVabB1g8uax9JkhGckEHwfe", &payer, &counterparty);
            let second = leg("4eaant86faGEgeH21U4qTTfpvwSb", &counterparty, &payer);
            let id = SettlementId::new(
                parse_account_id(&payer).unwrap(),
                "payment-42".parse().unwrap(),
            );
            for dvp in [true, false] {
                let build = |text: &str| {
                    if dvp {
                        Instruction::settlement_dvp(
                            &instruction_type,
                            text,
                            first.as_any(),
                            second.as_any(),
                            "delivery_then_payment",
                            "all_or_nothing",
                            None,
                        )
                    } else {
                        Instruction::settlement_pvp(
                            &instruction_type,
                            text,
                            first.as_any(),
                            second.as_any(),
                            "payment_then_delivery",
                            "all_or_nothing",
                            None,
                        )
                    }
                };
                let instruction = build(&id.to_string()).expect("scoped identity");
                let json = instruction.to_json().unwrap();
                let decoded = json::from_str::<InstructionBox>(&json).unwrap();
                assert_eq!(
                    norito::encode_canonical(&decoded).unwrap(),
                    norito::encode_canonical(&instruction.inner).unwrap()
                );
                let scoped_id = match decoded
                    .as_any()
                    .downcast_ref::<SettlementInstructionBox>()
                    .unwrap()
                {
                    SettlementInstructionBox::Dvp(value) => value.settlement_id(),
                    SettlementInstructionBox::Pvp(value) => value.settlement_id(),
                    _ => panic!("unexpected settlement variant"),
                };
                assert_eq!(scoped_id, &id);
                for invalid in [
                    "payment-42".to_owned(),
                    format!("payment-42${unrelated}"),
                    format!("payment-42${payer}@domain"),
                ] {
                    assert!(
                        build(&invalid).is_err(),
                        "accepted invalid owner identity {invalid}"
                    );
                }
            }
        });
    }

    #[test]
    fn transfer_rwa_instruction_classmethod_serializes_canonical_quantity_payload() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let source = canonical_i105_from_seed(0x11);
            let destination = canonical_i105_from_seed(0x22);
            let instruction = Instruction::transfer_rwa(
                &instruction_type,
                &source,
                SAMPLE_RWA_ID,
                "1.25",
                &destination,
            )
            .expect("transfer rwa builds");
            let decoded = json::from_str::<InstructionBox>(&instruction.to_json().expect("json"))
                .expect("instruction json decodes");
            let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*decoded;
            let Some(rwa_box) = instruction_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected TransferRwa instruction");
            };
            let iroha_data_model::isi::rwa::RwaInstructionBox::Transfer(transfer) = rwa_box else {
                panic!("expected TransferRwa instruction");
            };
            assert_eq!(
                transfer.source,
                parse_account_id(&source).expect("source parses")
            );
            assert_eq!(
                transfer.destination,
                parse_account_id(&destination).expect("destination parses")
            );
            assert_eq!(transfer.rwa, SAMPLE_RWA_ID.parse().expect("rwa id parses"));
            assert_eq!(
                transfer.quantity,
                Quantity::from_str("1.25").expect("quantity parses")
            );
        });
    }
    #[test]
    fn update_plain_conviction_instruction_has_exact_choice_free_native_wire() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let owner = canonical_i105_from_seed(0x47);
            let instruction = Instruction::update_plain_conviction(
                &instruction_type,
                "referendum-1",
                &owner,
                "2.5",
                42,
            )
            .expect("canonical conviction update");
            assert_eq!(
                instruction.wire_id().expect("wire id"),
                "iroha.instruction.v1::governance::UpdatePlainConviction"
            );
            let expected = InstructionBox::from(UpdatePlainConviction {
                referendum_id: "referendum-1".to_owned(),
                owner: parse_account_id(&owner).expect("owner parses"),
                amount: Quantity::from_str("2.5").expect("quantity parses"),
                duration_blocks: 42,
            });
            assert_eq!(
                norito::to_bytes(&instruction.inner).expect("native frame"),
                norito::to_bytes(&expected).expect("model frame")
            );
            for referendum_id in ["", ".hidden", "space value", &"x".repeat(129)] {
                assert!(
                    Instruction::update_plain_conviction(
                        &instruction_type,
                        referendum_id,
                        &owner,
                        "2.5",
                        42,
                    )
                    .is_err(),
                    "invalid selector: {referendum_id:?}"
                );
            }
            assert!(
                Instruction::update_plain_conviction(
                    &instruction_type,
                    "referendum-1",
                    "alice@example",
                    "2.5",
                    42,
                )
                .is_err(),
                "owner alias must be rejected"
            );
            for amount in ["01", " 2.5", "1e0"] {
                assert!(
                    Instruction::update_plain_conviction(
                        &instruction_type,
                        "referendum-1",
                        &owner,
                        amount,
                        42,
                    )
                    .is_err(),
                    "noncanonical quantity: {amount:?}"
                );
            }
        });
    }
    #[test]
    fn register_rwa_instruction_classmethod_serializes_payload() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let json_module = py.import("json").expect("json module");
            let payload = json_module
                .call_method1(
                    "loads",
                    (r#"{
                        "domain": "commodities.universal",
                        "quantity": "10.5",
                        "spec": {"scale": 1},
                        "primary_reference": "vault-cert-001",
                        "status": null,
                        "metadata": {"origin": "AE"},
                        "parents": [],
                        "controls": {
                            "controller_accounts": [],
                            "controller_roles": [],
                            "freeze_enabled": true,
                            "hold_enabled": false,
                            "force_transfer_enabled": false,
                            "redeem_enabled": false
                        }
                    }"#,),
                )
                .expect("register payload loads");
            let instruction =
                Instruction::register_rwa(&instruction_type, payload.as_any()).expect("builds");
            let decoded = json::from_str::<InstructionBox>(&instruction.to_json().expect("json"))
                .expect("instruction json decodes");
            let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*decoded;
            let Some(rwa_box) = instruction_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected RegisterRwa instruction");
            };
            let iroha_data_model::isi::rwa::RwaInstructionBox::Register(register) = rwa_box else {
                panic!("expected RegisterRwa instruction");
            };
            assert_eq!(
                register.rwa.domain,
                DomainId::try_new("commodities", "universal").expect("domain")
            );
            assert_eq!(
                register.rwa.quantity,
                Quantity::from_str("10.5").expect("quantity")
            );
            assert_eq!(register.rwa.primary_reference, "vault-cert-001");
            assert_eq!(
                register
                    .rwa
                    .metadata
                    .get("origin")
                    .and_then(|value| value.try_into_any_norito::<String>().ok())
                    .as_deref(),
                Some("AE")
            );
            assert!(register.rwa.controls.freeze_enabled);
        });
    }
    #[test]
    fn register_account_instruction_classmethod_is_domainless() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let account_id = canonical_i105_from_seed(0x33);
            let instruction =
                Instruction::register_account(&instruction_type, py, &account_id, None)
                    .expect("register account builds");
            let decoded = json::from_str::<InstructionBox>(&instruction.to_json().expect("json"))
                .expect("instruction json decodes");
            let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*decoded;
            let Some(register_box) = instruction_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::RegisterBox>()
            else {
                panic!("expected Register instruction");
            };
            let iroha_data_model::isi::RegisterBox::Account(register) = register_box else {
                panic!("expected Register<Account> instruction");
            };
            assert_eq!(
                register.object.id,
                parse_account_id(&account_id).expect("account parses")
            );
            assert_eq!(register.object.metadata, Metadata::default());
        });
    }
    #[test]
    fn python_proof_attachment_instruction_classmethod_serializes_payload() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let proof = PyDict::new(py);
            proof.set_item("backend", "pipa-r/pasta").expect("backend");
            let proof_box = PyDict::new(py);
            proof_box
                .set_item("backend", "pipa-r/pasta")
                .expect("proof backend");
            proof_box
                .set_item("bytes", PyBytes::new(py, b"proof"))
                .expect("proof bytes");
            proof.set_item("proof", proof_box).expect("proof box");
            let vk_ref = PyDict::new(py);
            vk_ref
                .set_item("backend", "pipa-r/pasta")
                .expect("vk backend");
            vk_ref
                .set_item("name", "component_verify_v1")
                .expect("vk name");
            proof.set_item("vk_ref", vk_ref).expect("vk ref");
            proof
                .set_item("vk_commitment", PyBytes::new(py, &[0x44; 32]))
                .expect("vk commitment");
            let expected_envelope_hash: [u8; 32] = Hash::new(b"proof").into();
            proof
                .set_item("envelope_hash", PyBytes::new(py, &expected_envelope_hash))
                .expect("envelope hash");
            let instruction = Instruction::verify_proof(&instruction_type, proof.as_any())
                .expect("VerifyProof instruction builds");
            let instruction_ref: &dyn iroha_data_model::isi::Instruction = &*instruction.inner;
            let verify = instruction_ref
                .as_any()
                .downcast_ref::<VerifyProof>()
                .expect("expected VerifyProof");
            assert_eq!(verify.attachment.backend.to_string(), "pipa-r/pasta");
            assert_eq!(verify.attachment.proof.bytes, b"proof");
            assert_eq!(verify.attachment.vk_ref.name, "component_verify_v1");
            assert_eq!(verify.attachment.vk_commitment, Some([0x44; 32]));
            assert_eq!(
                verify.attachment.envelope_hash,
                Some(expected_envelope_hash)
            );
        });
    }
    #[test]
    fn python_proof_attachment_parser_rejects_noncanonical_boundaries() {
        ensure_python();
        Python::attach(|py| {
            let canonical = |proof_bytes: &[u8]| {
                let attachment = PyDict::new(py);
                attachment
                    .set_item("backend", "pipa-r/pasta")
                    .expect("backend");
                let proof = PyDict::new(py);
                proof
                    .set_item("backend", "pipa-r/pasta")
                    .expect("proof backend");
                proof
                    .set_item("bytes", PyBytes::new(py, proof_bytes))
                    .expect("proof bytes");
                attachment.set_item("proof", proof).expect("proof");
                let vk_ref = PyDict::new(py);
                vk_ref
                    .set_item("backend", "pipa-r/pasta")
                    .expect("vk backend");
                vk_ref.set_item("name", "vk_transfer").expect("vk name");
                attachment.set_item("vk_ref", vk_ref).expect("vk ref");
                attachment
            };
            let valid = canonical(b"proof");
            parse_zk_proof_attachment(valid.as_any(), "proof")
                .expect("exact first-release attachment must parse");
            for alias in [
                "proof_bytes",
                "proof_b64",
                "verifying_key_ref",
                "verifying_key_commitment",
                "envelopeHash",
                "vk_inline",
            ] {
                let invalid = canonical(b"proof");
                invalid.set_item(alias, b"retired").expect("retired alias");
                let error = parse_zk_proof_attachment(invalid.as_any(), "proof")
                    .expect_err("retired aliases must reject");
                assert!(error.to_string().contains("unknown first-release field"));
            }
            let nested_alias = canonical(b"proof");
            nested_alias
                .get_item("proof")
                .expect("proof lookup")
                .expect("proof exists")
                .cast::<PyDict>()
                .expect("proof mapping")
                .set_item("bytes_b64", "cHJvb2Y=")
                .expect("retired nested alias");
            let error = parse_zk_proof_attachment(nested_alias.as_any(), "proof")
                .expect_err("nested aliases must reject");
            assert!(error.to_string().contains("unknown first-release field"));
            for (field, value) in [("backend", " Halo2/ipa"), ("backend", "halo2/ipa/../vk")] {
                let invalid = canonical(b"proof");
                invalid.set_item(field, value).expect("invalid selector");
                let error = parse_zk_proof_attachment(invalid.as_any(), "proof")
                    .expect_err("nonportable selectors must reject");
                assert!(error.to_string().contains("portable"));
            }
            let invalid_name = canonical(b"proof");
            invalid_name
                .get_item("vk_ref")
                .expect("vk lookup")
                .expect("vk exists")
                .cast::<PyDict>()
                .expect("vk mapping")
                .set_item("name", "vk_transfer_")
                .expect("invalid name");
            let error = parse_zk_proof_attachment(invalid_name.as_any(), "proof")
                .expect_err("nonportable VK name must reject");
            assert!(error.to_string().contains("portable"));
            let empty = canonical(b"");
            let error = parse_zk_proof_attachment(empty.as_any(), "proof")
                .expect_err("empty proof must reject");
            assert!(error.to_string().contains("proof.bytes must be non-empty"));
            let zero_commitment = canonical(b"proof");
            zero_commitment
                .set_item("vk_commitment", PyBytes::new(py, &[0; 32]))
                .expect("zero commitment");
            let error = parse_zk_proof_attachment(zero_commitment.as_any(), "proof")
                .expect_err("zero VK commitment must reject");
            assert!(error.to_string().contains("vk_commitment must be non-zero"));
            let forged_hash = canonical(b"proof");
            forged_hash
                .set_item("envelope_hash", PyBytes::new(py, &[0x55; 32]))
                .expect("forged envelope hash");
            let error = parse_zk_proof_attachment(forged_hash.as_any(), "proof")
                .expect_err("forged envelope hash must reject");
            assert!(error.to_string().contains("must match proof bytes"));
            let lane_attachment = canonical(b"proof");
            let lane = PyDict::new(py);
            lane.set_item("commitment_id", 7_u16)
                .expect("commitment id");
            let witness = PyDict::new(py);
            witness.set_item("kind", "merkle").expect("witness kind");
            let payload = PyDict::new(py);
            payload
                .set_item("leaf", PyBytes::new(py, &[0xAA; 32]))
                .expect("lane leaf");
            let merkle = PyDict::new(py);
            merkle.set_item("leaf_index", 1_u32).expect("leaf index");
            let path = PyList::new(py, [PyBytes::new(py, &[0x22; 32])]).expect("lane audit path");
            merkle.set_item("audit_path", path).expect("audit path");
            payload.set_item("proof", merkle).expect("merkle proof");
            witness
                .set_item("payload", payload)
                .expect("witness payload");
            lane.set_item("witness", witness).expect("lane witness");
            lane_attachment
                .set_item("lane_privacy", lane)
                .expect("lane privacy");
            parse_zk_proof_attachment(lane_attachment.as_any(), "proof")
                .expect("complete lane witness must parse");
            let sparse_lane_attachment = canonical(b"proof");
            let sparse_lane = PyDict::new(py);
            sparse_lane
                .set_item("commitment_id", 7_u16)
                .expect("commitment id");
            let sparse_witness = PyDict::new(py);
            sparse_witness
                .set_item("kind", "merkle")
                .expect("witness kind");
            let sparse_payload = PyDict::new(py);
            sparse_payload
                .set_item("leaf", PyBytes::new(py, &[0xAA; 32]))
                .expect("lane leaf");
            let sparse_merkle = PyDict::new(py);
            sparse_merkle
                .set_item("leaf_index", 0_u32)
                .expect("leaf index");
            sparse_merkle
                .set_item("audit_path", PyList::empty(py))
                .expect("empty audit path");
            sparse_payload
                .set_item("proof", sparse_merkle)
                .expect("merkle proof");
            sparse_witness
                .set_item("payload", sparse_payload)
                .expect("witness payload");
            sparse_lane
                .set_item("witness", sparse_witness)
                .expect("lane witness");
            sparse_lane_attachment
                .set_item("lane_privacy", sparse_lane)
                .expect("lane privacy");
            let error = parse_zk_proof_attachment(sparse_lane_attachment.as_any(), "proof")
                .expect_err("empty lane path must reject");
            assert!(error.to_string().contains("between 1 and 255"));
        });
    }
    #[test]
    fn merge_rwas_and_set_rwa_controls_classmethods_roundtrip_payloads() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let json_module = py.import("json").expect("json module");
            let controller = canonical_i105_from_seed(0x33);
            let merge_payload = json_module
                .call_method1(
                    "loads",
                    (r#"{
                            "parents": [
                                {
                                    "rwa": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities.universal",
                                    "quantity": "1.5"
                                }
                            ],
                            "primary_reference": "blend-cert-007",
                            "status": "blended",
                            "metadata": {"grade": "A"}
                        }"#,),
                )
                .expect("merge payload loads");
            let merge_instruction =
                Instruction::merge_rwas(&instruction_type, merge_payload.as_any())
                    .expect("merge builds");
            let merge_decoded =
                json::from_str::<InstructionBox>(&merge_instruction.to_json().expect("json"))
                    .expect("merge json decodes");
            let merge_ref: &dyn iroha_data_model::isi::Instruction = &*merge_decoded;
            let Some(rwa_box) = merge_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected MergeRwas instruction");
            };
            let iroha_data_model::isi::rwa::RwaInstructionBox::Merge(merge) = rwa_box else {
                panic!("expected MergeRwas instruction");
            };
            assert_eq!(merge.parents.len(), 1);
            assert_eq!(merge.primary_reference, "blend-cert-007");
            assert_eq!(
                merge.status.as_ref().map(ToString::to_string).as_deref(),
                Some("blended")
            );
            assert_eq!(
                merge
                    .metadata
                    .get("grade")
                    .and_then(|value| value.try_into_any_norito::<String>().ok())
                    .as_deref(),
                Some("A")
            );
            let controls_payload = json_module
                .call_method1(
                    "loads",
                    (format!(
                        r#"{{
                            "controller_accounts": ["{controller}"],
                            "controller_roles": [],
                            "freeze_enabled": true,
                            "hold_enabled": true,
                            "force_transfer_enabled": false,
                            "redeem_enabled": true
                        }}"#
                    ),),
                )
                .expect("controls payload loads");
            let controls_instruction = Instruction::set_rwa_controls(
                &instruction_type,
                SAMPLE_RWA_ID,
                controls_payload.as_any(),
            )
            .expect("controls build");
            let controls_decoded =
                json::from_str::<InstructionBox>(&controls_instruction.to_json().expect("json"))
                    .expect("controls json decodes");
            let controls_ref: &dyn iroha_data_model::isi::Instruction = &*controls_decoded;
            let Some(rwa_box) = controls_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected SetRwaControls instruction");
            };
            let iroha_data_model::isi::rwa::RwaInstructionBox::SetControls(controls) = rwa_box
            else {
                panic!("expected SetRwaControls instruction");
            };
            assert_eq!(controls.controls.controller_accounts.len(), 1);
            assert!(controls.controls.freeze_enabled);
            assert!(controls.controls.hold_enabled);
            assert!(controls.controls.redeem_enabled);
        });
    }
    #[test]
    fn rwa_scalar_instruction_classmethods_roundtrip_payloads() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let rwa_id = SAMPLE_RWA_ID;
            let destination = canonical_i105_from_seed(0x44);
            let redeem =
                Instruction::redeem_rwa(&instruction_type, rwa_id, "2.5").expect("redeem builds");
            let hold =
                Instruction::hold_rwa(&instruction_type, rwa_id, "1.25").expect("hold builds");
            let release =
                Instruction::release_rwa(&instruction_type, rwa_id, "0.5").expect("release builds");
            let force =
                Instruction::force_transfer_rwa(&instruction_type, rwa_id, "4", &destination)
                    .expect("force transfer builds");
            let freeze = Instruction::freeze_rwa(&instruction_type, rwa_id).expect("freeze builds");
            let unfreeze =
                Instruction::unfreeze_rwa(&instruction_type, rwa_id).expect("unfreeze builds");
            let metadata = PyDict::new(py);
            metadata.set_item("origin", "AE").expect("origin");
            metadata.set_item("lot", 3).expect("lot");
            let set_metadata = Instruction::set_rwa_key_value(
                &instruction_type,
                rwa_id,
                "grade",
                Some(metadata.as_any()),
            )
            .expect("set metadata builds");
            let remove_metadata =
                Instruction::remove_rwa_key_value(&instruction_type, rwa_id, "grade")
                    .expect("remove metadata builds");
            let decoded = |instruction: &Instruction| {
                json::from_str::<InstructionBox>(&instruction.to_json().expect("json"))
                    .expect("instruction json decodes")
            };
            let redeem_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&redeem);
            let hold_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&hold);
            let release_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&release);
            let force_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&force);
            let freeze_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&freeze);
            let unfreeze_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&unfreeze);
            let set_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&set_metadata);
            let remove_ref: &dyn iroha_data_model::isi::Instruction = &*decoded(&remove_metadata);
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::Redeem(redeem_box)) =
                redeem_ref
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected RedeemRwa");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::Hold(hold_box)) = hold_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected HoldRwa");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::Release(release_box)) =
                release_ref
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected ReleaseRwa");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::ForceTransfer(force_box)) =
                force_ref
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected ForceTransferRwa");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::Freeze(_)) = freeze_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected FreezeRwa");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::Unfreeze(_)) = unfreeze_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected UnfreezeRwa");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::SetKeyValue(set_box)) = set_ref
                .as_any()
                .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected SetRwaKeyValue");
            };
            let Some(iroha_data_model::isi::rwa::RwaInstructionBox::RemoveKeyValue(remove_box)) =
                remove_ref
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::rwa::RwaInstructionBox>()
            else {
                panic!("expected RemoveRwaKeyValue");
            };
            assert_eq!(
                redeem_box.quantity,
                Quantity::from_str("2.5").expect("quantity")
            );
            assert_eq!(
                hold_box.quantity,
                Quantity::from_str("1.25").expect("quantity")
            );
            assert_eq!(
                release_box.quantity,
                Quantity::from_str("0.5").expect("quantity")
            );
            assert_eq!(
                force_box.destination,
                parse_account_id(&destination).expect("destination parses")
            );
            assert_eq!(set_box.key.to_string(), "grade");
            assert_eq!(
                set_box
                    .value
                    .try_into_any_norito::<json::Value>()
                    .ok()
                    .and_then(|value| value.as_object().cloned())
                    .and_then(|obj| obj.get("origin").cloned())
                    .and_then(|value| value.as_str().map(|value| value.to_owned()))
                    .as_deref(),
                Some("AE")
            );
            assert_eq!(remove_box.key.to_string(), "grade");
        });
    }
    #[test]
    fn sorafs_gateway_fetch_py_rejects_single_gateway_provider() {
        ensure_python();
        let payload = vec![0x41; 128];
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json =
            sorafs_car::fetch_plan::chunk_fetch_plan_to_string(&plan).expect("serialise plan");
        let providers = vec![PyGatewayProviderSpec {
            name: "alpha".to_string(),
            provider_id_hex: "55".repeat(32),
            gateway_public_key_hex: "11".repeat(32),
            base_url: "https://gateway.test".to_string(),
            stream_token_b64: "dG9rZW4=".to_string(),
            privacy_events_url: None,
        }];
        Python::attach(|py| {
            let result = sorafs_gateway_fetch_py(
                py,
                &"aa".repeat(32),
                "sorafs.sf1@1.0.0",
                &plan_json,
                providers,
                None,
            );
            match result {
                Ok(_) => panic!("single gateway provider must be rejected"),
                Err(err) => assert!(
                    err.to_string()
                        .contains("at least two unique gateway providers"),
                    "{err}"
                ),
            }
        });
    }
    #[test]
    fn canonical_gateway_provider_preserves_trust_inputs() {
        ensure_python();
        let spec = PyGatewayProviderSpec {
            name: "alpha_1".to_string(),
            provider_id_hex: "55".repeat(32),
            gateway_public_key_hex: "11".repeat(32),
            base_url: "https://gateway.test/".to_string(),
            stream_token_b64: "dG9rZW4=".to_string(),
            privacy_events_url: Some("https://gateway.test/privacy/events".to_string()),
        };
        let provider = canonical_gateway_provider(spec).expect("canonical provider");
        assert_eq!(provider.provider_id_hex, "55".repeat(32));
        assert_eq!(provider.gateway_public_key_hex, "11".repeat(32));
        assert_eq!(provider.base_url, "https://gateway.test/");
        assert_eq!(provider.stream_token_b64, "dG9rZW4=");
        assert_eq!(
            provider.privacy_events_url.as_deref(),
            Some("https://gateway.test/privacy/events")
        );
    }
    #[test]
    fn canonical_gateway_provider_rejects_adversarial_trust_inputs() {
        ensure_python();
        let base = PyGatewayProviderSpec {
            name: "alpha".to_string(),
            provider_id_hex: "55".repeat(32),
            gateway_public_key_hex: "11".repeat(32),
            base_url: "https://gateway.test/".to_string(),
            stream_token_b64: "dG9rZW4=".to_string(),
            privacy_events_url: None,
        };
        for key in [
            "00".repeat(32),
            "AA".repeat(32),
            format!("0x{}", "11".repeat(32)),
            format!(" {}", "11".repeat(32)),
            "11".repeat(31),
        ] {
            let mut spec = base.clone();
            spec.gateway_public_key_hex = key;
            assert!(canonical_gateway_provider(spec).is_err());
        }
        for url in [
            "http://gateway.test/",
            "https://user@gateway.test/",
            "https://gateway.test:443/",
            "https://gateway.test:444/",
            "https://gateway.test/path",
            "https://gateway.test/?query=1",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://192.0.2.1/",
            "https://[::1]/",
            "https://[2001:db8::1]/",
        ] {
            let mut spec = base.clone();
            spec.base_url = url.to_string();
            assert!(canonical_gateway_provider(spec).is_err(), "{url}");
        }
        for token in ["", " dG9rZW4=", "dG9rZW4", "dG9rZW4=\n", "YR==", "-w=="] {
            let mut spec = base.clone();
            spec.stream_token_b64 = token.to_string();
            assert!(canonical_gateway_provider(spec).is_err(), "{token:?}");
        }
        let mut invalid_privacy = base.clone();
        invalid_privacy.privacy_events_url = Some("https://gateway.test/privacy".to_string());
        assert!(canonical_gateway_provider(invalid_privacy).is_err());
    }
    #[test]
    fn parse_time_trigger_kwargs_handles_known_arguments() {
        ensure_python();
        Python::attach(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("period_ms", 150_u64).unwrap();
            kwargs.set_item("repeats", 3_u32).unwrap();
            kwargs.set_item("metadata", py.None()).unwrap();
            let parsed = parse_time_trigger_kwargs(Some(&kwargs)).expect("kwargs parse");
            assert_eq!(parsed.period_ms, Some(150));
            assert_eq!(parsed.repeats, Some(3));
            assert!(parsed.metadata.is_some());
        });
    }
    #[test]
    fn parse_time_trigger_kwargs_rejects_unknown_keys() {
        ensure_python();
        Python::attach(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("unexpected", 1).unwrap();
            let err = parse_time_trigger_kwargs(Some(&kwargs)).expect_err("expect error");
            assert!(err.is_instance_of::<PyTypeError>(py));
        });
    }
    #[test]
    fn repo_cash_leg_parser_validates_fields() {
        ensure_python();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("asset_definition_id", "7EAD8EFYUx1aVKZPUU1fyKvr8dF1")
                .unwrap();
            dict.set_item("quantity", "10").unwrap();
            let leg = parse_repo_cash_leg(py, dict.as_any()).expect("repo cash leg should parse");
            assert_eq!(
                leg.asset_definition_id.to_string(),
                "7EAD8EFYUx1aVKZPUU1fyKvr8dF1"
            );
            assert_eq!(leg.quantity.to_string(), "10");
            let missing = PyDict::new(py);
            missing
                .set_item("asset_definition_id", "7EAD8EFYUx1aVKZPUU1fyKvr8dF1")
                .unwrap();
            let err =
                parse_repo_cash_leg(py, missing.as_any()).expect_err("missing quantity rejected");
            assert!(err.is_instance_of::<PyValueError>(py));
        });
    }
    #[test]
    fn quantity_python_boundaries_reject_lossy_and_noncanonical_inputs() {
        for literal in ["+1", "01", "1.0", "1.2300", "1e0", "-1", " 1", "1 "] {
            parse_asset_quantity(literal, "test quantity")
                .expect_err("alternate quantity spelling must be rejected");
        }
        parse_asset_quantity(&format!("1.{}", "0".repeat(10_000)), "test quantity")
            .expect_err("oversized alternate quantity must be rejected before bigint parsing");
        assert_eq!(
            parse_asset_quantity("1.25", "test quantity")
                .expect("canonical quantity")
                .to_string(),
            "1.25"
        );
        for literal in ["+1", "01", " 1", "1 ", "1.0"] {
            parse_canonical_u128_text(literal, "test amount")
                .expect_err("alternate integer spelling must be rejected");
        }
        parse_canonical_u128_text(&"1".repeat(10_000), "test amount")
            .expect_err("oversized integer must be rejected before parsing");
        assert_eq!(
            parse_canonical_u128_text("1", "test amount").expect("canonical amount"),
            1
        );
        ensure_python();
        Python::attach(|py| {
            let float = pyo3::types::PyFloat::new(py, 1.25);
            let integer = pyo3::types::PyInt::new(py, 1);
            let float_error = quantity_from_py(float.as_any(), "test quantity")
                .expect_err("float input must be rejected");
            let integer_error = quantity_from_py(integer.as_any(), "test quantity")
                .expect_err("untyped integer input must be rejected");
            assert!(float_error.is_instance_of::<PyTypeError>(py));
            assert!(integer_error.is_instance_of::<PyTypeError>(py));
        });
    }
    #[test]
    fn sorafs_xor_quantity_parser_enforces_exact_first_release_domain() {
        const MAX_MANTISSA: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047";
        const MAX_SCALED: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824.503042047";
        assert_eq!(MAX_SCALED.len(), 155);
        for literal in [
            "0",
            "0.000000001",
            "340282366920938463463374607431768211456.000000001",
            MAX_MANTISSA,
            MAX_SCALED,
        ] {
            assert_eq!(
                parse_sorafs_xor_quantity_text_py(literal, "amount")
                    .expect("canonical XOR quantity")
                    .to_string(),
                literal
            );
        }
        for literal in [
            "",
            "+1",
            "-1",
            " 1",
            "1 ",
            "01",
            "1.",
            ".1",
            "1.0",
            "1.000000000",
            "1e0",
            "0.0000000001",
            "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048",
        ] {
            parse_sorafs_xor_quantity_text_py(literal, "amount")
                .expect_err("adversarial XOR quantity must be rejected");
        }
        parse_sorafs_xor_quantity_text_py(&"1".repeat(10_000), "amount")
            .expect_err("oversized XOR quantity must be rejected before bigint parsing");
        parse_sorafs_xor_quantity_text_py(&"1".repeat(156), "amount")
            .expect_err("156-character XOR quantity must exceed the canonical text bound");
    }
    #[test]
    fn asset_quantity_instruction_classmethods_require_canonical_text() {
        ensure_python();
        Python::attach(|py| {
            let instruction_type = py.get_type::<Instruction>();
            let owner = canonical_i105_from_seed(0x45);
            let destination = canonical_i105_from_seed(0x46);
            let asset_id = format!("7MBRDd8cGFBZkFGdDMwV7S6FPwbw#{owner}");
            Instruction::mint_asset_quantity(&instruction_type, &asset_id, "1.25")
                .expect("canonical mint quantity");
            Instruction::burn_asset_quantity(&instruction_type, &asset_id, "1.25")
                .expect("canonical burn quantity");
            Instruction::transfer_asset_quantity(
                &instruction_type,
                &asset_id,
                "1.25",
                &destination,
            )
            .expect("canonical transfer quantity");
            Instruction::set_asset_transfer_availability(
                &instruction_type,
                &owner,
                "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
                0,
                "Disabled",
                "Disabled",
                Some("operator close".to_owned()),
            )
            .expect("asset transfer availability");
            Instruction::set_asset_transfer_blacklist(
                &instruction_type,
                &owner,
                "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
                true,
            )
            .expect("asset transfer blacklist");
            let day_limit = PyDict::new(py);
            day_limit.set_item("window", "DAY").expect("set window");
            day_limit
                .set_item("cap_amount", "50")
                .expect("set cap amount");
            let limits = PyList::new(py, [&day_limit]).expect("asset transfer limit list");
            Instruction::set_asset_transfer_control(
                &instruction_type,
                &owner,
                "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
                limits.as_any(),
            )
            .expect("asset transfer caps");
            Instruction::set_asset_holding_limit(
                &instruction_type,
                &owner,
                "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
                Some("0"),
            )
            .expect("zero asset holding limit");
            Instruction::set_asset_holding_limit(
                &instruction_type,
                &owner,
                "7MBRDd8cGFBZkFGdDMwV7S6FPwbw",
                None,
            )
            .expect("clear asset holding limit");
            for literal in ["+1", "01", "1.0", "1.2500", "-1", " 1"] {
                let result =
                    Instruction::mint_asset_quantity(&instruction_type, &asset_id, literal);
                let error = match result {
                    Ok(_) => panic!("alternate asset quantity spelling must be rejected"),
                    Err(error) => error,
                };
                assert!(error.is_instance_of::<PyValueError>(py));
            }
        });
    }
    #[test]
    fn alias_fixture_defaults_are_canonical_and_reject_overflow() {
        ensure_python();
        Python::attach(|py| {
            let decode_fixture = |fixture: Py<PyDict>| {
                let encoded: String = fixture
                    .bind(py)
                    .get_item("proof_b64")
                    .unwrap()
                    .unwrap()
                    .extract()
                    .unwrap();
                let bytes = BASE64.decode(encoded).unwrap();
                decode_alias_proof_untrusted_signers(&bytes).unwrap()
            };
            let default = decode_fixture(sorafs_alias_proof_fixture_py(py, None).unwrap());
            assert_eq!(
                default.binding.manifest_cid,
                sorafs_manifest::canonical_manifest_root_cid([0xAA; 32])
            );
            assert_eq!(default.binding.bound_at, 1);
            assert_eq!(default.binding.expiry_epoch, 101);
            assert_eq!(
                default.expires_at_unix - default.generated_at_unix,
                sorafs::DEFAULT_ALIAS_POSITIVE_TTL_SECS
            );

            for (field, diagnostic) in [
                ("generated_at_unix", "generated_at_unix overflows"),
                ("bound_at_epoch", "bound_at_epoch overflows"),
            ] {
                let options = PyDict::new(py);
                options.set_item(field, u64::MAX).unwrap();
                let error = sorafs_alias_proof_fixture_py(py, Some(&options)).unwrap_err();
                assert!(error.is_instance_of::<PyValueError>(py));
                assert!(error.to_string().contains(diagnostic));
            }

            let options = PyDict::new(py);
            options.set_item("generated_at_unix", u64::MAX - 1).unwrap();
            options.set_item("expires_at_unix", u64::MAX).unwrap();
            options.set_item("bound_at_epoch", u64::MAX - 1).unwrap();
            options.set_item("expiry_epoch", u64::MAX).unwrap();
            let explicit =
                decode_fixture(sorafs_alias_proof_fixture_py(py, Some(&options)).unwrap());
            assert_eq!(explicit.generated_at_unix, u64::MAX - 1);
            assert_eq!(explicit.expires_at_unix, u64::MAX);
            assert_eq!(explicit.binding.bound_at, u64::MAX - 1);
            assert_eq!(explicit.binding.expiry_epoch, u64::MAX);
        });
    }
    #[test]
    fn verified_transaction_rejection_codes_use_typed_variants() {
        let validation = |error| {
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(error))
        };
        assert_eq!(
            transaction_rejection_code(&validation(
                InstructionExecutionError::AssetTransferAdmission(
                    AssetTransferAdmissionError::IncomingDisabled("incoming closed".into()),
                ),
            )),
            "IncomingDisabled"
        );
        assert_eq!(
            transaction_rejection_code(&validation(
                InstructionExecutionError::AssetTransferAdmission(
                    AssetTransferAdmissionError::HoldingLimitExceeded("limit".into()),
                ),
            )),
            "HoldingLimitExceeded"
        );
        assert_eq!(
            transaction_rejection_code(&validation(InstructionExecutionError::Math(
                MathError::NotEnoughQuantity,
            ))),
            "InsufficientBalance"
        );
        assert_eq!(
            transaction_rejection_code(&TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("permission denied".into()),
            )),
            "NotPermitted"
        );
        assert_eq!(
            transaction_contract_rejection_json(&TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("permission denied".into()),
            )),
            None
        );
        let schema_hash = [0xAB_u8; 32];
        let contract = TransactionRejectionReason::Validation(ValidationFail::ContractRejected(
            iroha_data_model::executor::ContractRejection {
                contract: "BoiFiLiquidity".into(),
                error_type: "example/boifi@1::BoiFiLiquidity::FiLiquidityError".into(),
                schema_hash,
                name: "BelowMinimum".into(),
                code: 18,
                message: None,
            },
        ));
        assert_eq!(transaction_rejection_code(&contract), "BelowMinimum");
        assert_eq!(
            transaction_contract_rejection_json(&contract),
            Some(norito::json!({
                "contract": "BoiFiLiquidity",
                "error_type": "example/boifi@1::BoiFiLiquidity::FiLiquidityError",
                "schema_hash": ("AB".repeat(32)),
                "name": "BelowMinimum",
                "code": 18,
                "message": null,
            }))
        );
    }
    #[test]
    fn ivm_fault_projection_retains_typed_origin_without_presentation() {
        use iroha_data_model::executor::fault::{
            IvmFaultKindV1, IvmFaultPositionV1, IvmFaultSiteV1, IvmFaultV1,
            IvmInvocationSelectorV1, NumericFaultV1,
        };
        let fault = IvmFaultV1 {
            kind: IvmFaultKindV1::Numeric(NumericFaultV1::DivisionByZero),
            site: IvmFaultSiteV1 {
                code_hash: Hash::new(b"origin"),
                selector: IvmInvocationSelectorV1::Entrypoint(3),
                position: IvmFaultPositionV1::Execute {
                    pc_offset: u64::MAX,
                },
            },
        };
        let reason = TransactionRejectionReason::Validation(ValidationFail::IvmFault(fault));
        assert_eq!(transaction_rejection_code(&reason), "IvmFault");
        assert_eq!(
            transaction_ivm_fault_json(&reason),
            Some(norito::json!(fault))
        );
        assert!(transaction_contract_rejection_json(&reason).is_none());
    }
    #[test]
    fn contract_rejection_projection_preserves_boxed_identity_and_message() {
        let reason = TransactionRejectionReason::Validation(ValidationFail::ContractRejected(
            iroha_data_model::executor::ContractRejection {
                contract: "決済".into(),
                error_type: "example/pay@1::Settlement::PaymentError".into(),
                schema_hash: [7; 32],
                name: "BelowMinimum".into(),
                code: 18,
                message: Some("  支払額が不足しています。  ".into()),
            },
        ));
        let value = transaction_contract_rejection_json(&reason).unwrap();
        assert_eq!(
            value.get("contract").and_then(json::Value::as_str),
            Some("決済")
        );
        assert_eq!(
            value.get("message").and_then(json::Value::as_str),
            Some("  支払額が不足しています。  ")
        );
        assert_eq!(
            transaction_contract_rejection_json(&TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("denied".into())
            )),
            None
        );
    }
    #[test]
    fn repo_governance_parser_accepts_mixed_numeric_sources() {
        ensure_python();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("haircut_bps", "250").unwrap();
            dict.set_item("margin_frequency_secs", 60_u64).unwrap();
            let governance =
                parse_repo_governance(dict.as_any()).expect("repo governance should parse");
            assert_eq!(governance.haircut_bps(), 250);
            assert_eq!(governance.margin_frequency_secs(), 60);
        });
    }
    #[test]
    fn multi_source_invalid_plan_has_stable_python_payload() {
        ensure_python();
        Python::attach(|py| {
            let payload = build_multi_fetch_error_payload(
                py,
                MultiSourceError::InvalidPlan(sorafs_car::CarPlanError::EmptyInput),
            )
            .expect("build invalid-plan payload");
            let payload = payload.bind(py);
            let kind: String = payload
                .get_item("kind")
                .expect("kind lookup")
                .expect("kind field")
                .extract()
                .expect("kind string");
            let reason: String = payload
                .get_item("reason")
                .expect("reason lookup")
                .expect("reason field")
                .extract()
                .expect("reason string");
            assert_eq!(kind, "invalid_plan");
            assert_eq!(reason, "input payload is empty");
        });
    }
    #[test]
    fn multi_source_policy_exclusion_has_stable_python_payload() {
        ensure_python();
        Python::attach(|py| {
            let payload = build_multi_fetch_error_payload(
                py,
                MultiSourceError::NoPolicyEligibleProviders {
                    chunk_index: 3,
                    providers: vec![
                        sorafs_car::multi_fetch::ProviderId::new("alpha"),
                        sorafs_car::multi_fetch::ProviderId::new("beta"),
                    ],
                },
            )
            .expect("build policy-exclusion payload");
            let payload = payload.bind(py);
            let kind: String = payload
                .get_item("kind")
                .expect("kind lookup")
                .expect("kind field")
                .extract()
                .expect("kind string");
            let chunk_index: usize = payload
                .get_item("chunk_index")
                .expect("chunk-index lookup")
                .expect("chunk-index field")
                .extract()
                .expect("chunk-index integer");
            let providers: Vec<String> = payload
                .get_item("providers")
                .expect("providers lookup")
                .expect("providers field")
                .extract()
                .expect("provider strings");
            assert_eq!(kind, "no_policy_eligible_providers");
            assert_eq!(chunk_index, 3);
            assert_eq!(providers, ["alpha", "beta"]);
        });
    }
    #[test]
    fn sorafs_multi_fetch_local_executes_plan() {
        ensure_python();
        let tempdir = tempdir().expect("tempdir");
        let payload = (0..(8 * 1024))
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();
        let alpha_path = tempdir.path().join("alpha.bin");
        let beta_path = tempdir.path().join("beta.bin");
        fs::write(&alpha_path, &payload).expect("write alpha payload");
        fs::write(&beta_path, &payload).expect("write beta payload");
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json =
            sorafs_car::fetch_plan::chunk_fetch_plan_to_string(&plan).expect("serialise plan");
        let providers = vec![
            PyLocalProviderSpec {
                name: "alpha".to_owned(),
                path: alpha_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
            PyLocalProviderSpec {
                name: "beta".to_owned(),
                path: beta_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
        ];
        Python::attach(|py| {
            let result = sorafs_multi_fetch_local_py(
                py,
                &plan_json,
                providers.clone(),
                Some(PyMultiFetchOptions {
                    max_peers: Some(1),
                    ..Default::default()
                }),
            )
            .expect("multi-fetch succeeds");
            let dict = result.bind(py);
            let payload_obj = dict
                .get_item("payload")
                .expect("payload key")
                .expect("payload missing");
            let payload_value = payload_obj.cast::<PyBytes>().expect("payload bytes");
            assert_eq!(payload_value.as_bytes(), payload.as_slice());
            let reports_obj = dict
                .get_item("provider_reports")
                .expect("provider_reports key")
                .expect("provider_reports missing");
            let reports = reports_obj.cast::<PyList>().expect("provider_reports list");
            assert_eq!(reports.len(), 1);
            let report_item = reports.get_item(0).expect("provider report entry");
            let report = report_item.cast::<PyDict>().expect("provider report dict");
            let provider_name: String = report
                .get_item("provider")
                .expect("provider field lookup failed")
                .expect("provider field")
                .extract()
                .expect("provider str");
            assert_eq!(provider_name, "alpha");
            let receipts_obj = dict
                .get_item("chunk_receipts")
                .expect("chunk_receipts key")
                .expect("chunk_receipts missing");
            let receipts = receipts_obj.cast::<PyList>().expect("chunk_receipts list");
            assert_eq!(
                receipts.len(),
                plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
            );
            assert!(receipts.iter().all(|entry| {
                entry
                    .cast::<PyDict>()
                    .ok()
                    .and_then(|mapping| {
                        mapping
                            .get_item("provider")
                            .ok()
                            .and_then(|opt| opt)
                            .and_then(|value| value.extract::<String>().ok())
                    })
                    .map(|value| value == "alpha")
                    .unwrap_or(false)
            }));
        });
    }
    #[test]
    fn sorafs_telemetry_reputation_score_rejects_out_of_range_bps() {
        ensure_python();
        let entries = [PyTelemetryEntry {
            provider_id: "alpha-id".to_string(),
            qos_score: Some(95.0),
            latency_p95_ms: Some(45.0),
            failure_rate_ewma: Some(0.05),
            token_health: Some(0.9),
            staking_weight: Some(1.1),
            reputation_score_bps: Some(10_001),
            penalty: Some(false),
            last_updated_unix: Some(1_700_000_000),
        }];
        let err = match telemetry_snapshot_from_py(&entries) {
            Ok(_) => panic!("out-of-range reputation_score_bps should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("reputation_score_bps"));
    }
    #[test]
    fn sorafs_multi_fetch_local_returns_scoreboard_and_filters_providers() {
        ensure_python();
        let tempdir = tempdir().expect("tempdir");
        let payload = (0..(4 * 1024))
            .map(|idx| (idx % 191) as u8)
            .collect::<Vec<_>>();
        let alpha_path = tempdir.path().join("alpha.bin");
        let beta_path = tempdir.path().join("beta.bin");
        fs::write(&alpha_path, &payload).expect("write alpha payload");
        fs::write(&beta_path, &payload).expect("write beta payload");
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json =
            sorafs_car::fetch_plan::chunk_fetch_plan_to_string(&plan).expect("serialise plan");
        let providers = vec![
            PyLocalProviderSpec {
                name: "alpha".to_owned(),
                path: alpha_path.to_string_lossy().into_owned(),
                max_concurrent: Some(2),
                weight: None,
                metadata: Some(provider_metadata("alpha-id")),
            },
            PyLocalProviderSpec {
                name: "beta".to_owned(),
                path: beta_path.to_string_lossy().into_owned(),
                max_concurrent: Some(2),
                weight: None,
                metadata: Some(provider_metadata("beta-id")),
            },
        ];
        Python::attach(|py| {
            let telemetry = vec![
                PyTelemetryEntry {
                    provider_id: "alpha-id".to_string(),
                    qos_score: Some(95.0),
                    latency_p95_ms: Some(45.0),
                    failure_rate_ewma: Some(0.05),
                    token_health: Some(0.9),
                    staking_weight: Some(1.1),
                    reputation_score_bps: Some(9_200),
                    penalty: Some(false),
                    last_updated_unix: Some(u64::MAX / 2),
                },
                PyTelemetryEntry {
                    provider_id: "beta-id".to_string(),
                    qos_score: Some(80.0),
                    latency_p95_ms: Some(120.0),
                    failure_rate_ewma: Some(0.2),
                    token_health: Some(0.6),
                    staking_weight: Some(1.0),
                    reputation_score_bps: Some(3_000),
                    penalty: Some(true),
                    last_updated_unix: Some(u64::MAX / 2),
                },
            ];
            let result = sorafs_multi_fetch_local_py(
                py,
                &plan_json,
                providers.clone(),
                Some(PyMultiFetchOptions {
                    use_scoreboard: Some(true),
                    return_scoreboard: Some(true),
                    telemetry: Some(telemetry),
                    ..Default::default()
                }),
            )
            .expect("multi-fetch with scoreboard succeeds");
            let dict = result.bind(py);
            let scoreboard_obj = dict
                .get_item("scoreboard")
                .expect("scoreboard key")
                .expect("scoreboard missing");
            let scoreboard = scoreboard_obj.cast::<PyList>().expect("scoreboard list");
            assert_eq!(scoreboard.len(), 2);
            let alpha_item = scoreboard.get_item(0).expect("alpha scoreboard entry");
            let alpha = alpha_item.cast::<PyDict>().expect("alpha scoreboard entry");
            let alpha_id: String = alpha
                .get_item("provider_id")
                .expect("provider_id lookup failed")
                .expect("provider_id")
                .extract()
                .expect("alpha provider id");
            assert_eq!(alpha_id, "alpha-id");
            let alpha_alias: String = alpha
                .get_item("alias")
                .expect("alias lookup failed")
                .expect("alias")
                .extract()
                .expect("alpha alias");
            assert_eq!(alpha_alias, "alpha");
            let alpha_status: String = alpha
                .get_item("eligibility")
                .expect("eligibility lookup failed")
                .expect("eligibility")
                .extract()
                .expect("alpha eligibility");
            assert_eq!(alpha_status, "eligible");
            let alpha_weight: f64 = alpha
                .get_item("normalized_weight")
                .expect("normalized_weight lookup failed")
                .expect("normalized_weight")
                .extract()
                .expect("alpha weight");
            assert!(alpha_weight > 0.0);
            let beta_item = scoreboard.get_item(1).expect("beta scoreboard entry");
            let beta = beta_item.cast::<PyDict>().expect("beta scoreboard entry");
            let beta_id: String = beta
                .get_item("provider_id")
                .expect("provider_id lookup failed")
                .expect("provider_id")
                .extract()
                .expect("beta provider id");
            assert_eq!(beta_id, "beta-id");
            let beta_status: String = beta
                .get_item("eligibility")
                .expect("eligibility lookup failed")
                .expect("eligibility")
                .extract()
                .expect("beta eligibility");
            assert_eq!(beta_status, "telemetry penalty active");
            let reports_obj = dict
                .get_item("provider_reports")
                .expect("provider_reports")
                .expect("provider_reports missing");
            let reports = reports_obj.cast::<PyList>().expect("provider_reports list");
            assert_eq!(reports.len(), 1);
            let provider_item = reports.get_item(0).expect("provider report entry");
            let provider = provider_item.cast::<PyDict>().expect("provider report");
            let provider_name: String = provider
                .get_item("provider")
                .expect("provider field lookup failed")
                .expect("provider field")
                .extract()
                .expect("provider str");
            assert_eq!(provider_name, "alpha");
            let receipts_obj = dict
                .get_item("chunk_receipts")
                .expect("chunk_receipts")
                .expect("chunk_receipts missing");
            let receipts = receipts_obj.cast::<PyList>().expect("chunk_receipts list");
            assert_eq!(
                receipts.len(),
                plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
            );
            assert!(receipts.iter().all(|entry| {
                entry
                    .cast::<PyDict>()
                    .ok()
                    .and_then(|mapping| {
                        mapping
                            .get_item("provider")
                            .ok()
                            .and_then(|opt| opt)
                            .and_then(|value| value.extract::<String>().ok())
                    })
                    .map(|value| value == "alpha")
                    .unwrap_or(false)
            }));
        });
    }
    #[test]
    fn sorafs_multi_fetch_local_applies_score_policy() {
        ensure_python();
        let tempdir = tempdir().expect("tempdir");
        let payload = (0..256).map(|idx| (idx % 127) as u8).collect::<Vec<_>>();
        let alpha_path = tempdir.path().join("alpha_policy.bin");
        let beta_path = tempdir.path().join("beta_policy.bin");
        fs::write(&alpha_path, &payload).expect("write alpha payload");
        fs::write(&beta_path, &payload).expect("write beta payload");
        let plan =
            CarBuildPlan::single_file_with_profile(&payload, ChunkProfile::DEFAULT).expect("plan");
        let plan_json =
            sorafs_car::fetch_plan::chunk_fetch_plan_to_string(&plan).expect("serialise plan");
        let chunk_count = plan.try_chunk_fetch_specs().expect("valid CAR plan").len() as u64;
        let providers = vec![
            PyLocalProviderSpec {
                name: "alpha".to_owned(),
                path: alpha_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
            PyLocalProviderSpec {
                name: "beta".to_owned(),
                path: beta_path.to_string_lossy().into_owned(),
                max_concurrent: Some(1),
                weight: None,
                metadata: None,
            },
        ];
        Python::attach(|py| {
            let denied = sorafs_multi_fetch_local_py(
                py,
                &plan_json,
                providers.clone(),
                Some(PyMultiFetchOptions {
                    deny_providers: Some(vec!["alpha".to_string()]),
                    ..Default::default()
                }),
            )
            .expect("multi-fetch with deny policy succeeds");
            let denied_dict = denied.bind(py);
            let denied_reports_obj = denied_dict
                .get_item("provider_reports")
                .expect("provider_reports")
                .expect("provider_reports missing");
            let denied_reports = denied_reports_obj
                .cast::<PyList>()
                .expect("provider_reports list");
            let mut alpha_successes = None;
            let mut beta_successes = None;
            for report in denied_reports.iter() {
                let report = report.cast::<PyDict>().expect("provider report");
                let provider: String = report
                    .get_item("provider")
                    .expect("provider field lookup failed")
                    .expect("provider field")
                    .extract()
                    .expect("provider str");
                let successes: u64 = report
                    .get_item("successes")
                    .expect("successes field lookup failed")
                    .expect("successes field")
                    .extract()
                    .expect("successes count");
                match provider.as_str() {
                    "alpha" => alpha_successes = Some(successes),
                    "beta" => beta_successes = Some(successes),
                    _ => {}
                }
            }
            assert_eq!(alpha_successes.unwrap_or_default(), 0);
            assert_eq!(beta_successes, Some(chunk_count));
            let denied_receipts_obj = denied_dict
                .get_item("chunk_receipts")
                .expect("chunk_receipts")
                .expect("chunk_receipts missing");
            let denied_receipts = denied_receipts_obj
                .cast::<PyList>()
                .expect("chunk_receipts list");
            assert!(denied_receipts.iter().all(|entry| {
                entry
                    .cast::<PyDict>()
                    .ok()
                    .and_then(|mapping| {
                        mapping
                            .get_item("provider")
                            .ok()
                            .and_then(|opt| opt)
                            .and_then(|value| value.extract::<String>().ok())
                    })
                    .map(|value| value == "beta")
                    .unwrap_or(false)
            }));
            let boosted = sorafs_multi_fetch_local_py(
                py,
                &plan_json,
                providers,
                Some(PyMultiFetchOptions {
                    boost_providers: Some(vec![PyProviderBoost {
                        provider: "beta".to_string(),
                        delta: 50,
                    }]),
                    ..Default::default()
                }),
            )
            .expect("multi-fetch with boost policy succeeds");
            let boosted_dict = boosted.bind(py);
            let boosted_receipts_obj = boosted_dict
                .get_item("chunk_receipts")
                .expect("chunk_receipts")
                .expect("chunk_receipts missing");
            let boosted_receipts = boosted_receipts_obj
                .cast::<PyList>()
                .expect("chunk_receipts list");
            assert!(boosted_receipts.iter().all(|entry| {
                entry
                    .cast::<PyDict>()
                    .ok()
                    .and_then(|mapping| {
                        mapping
                            .get_item("provider")
                            .ok()
                            .and_then(|opt| opt)
                            .and_then(|value| value.extract::<String>().ok())
                    })
                    .map(|value| value == "beta")
                    .unwrap_or(false)
            }));
        });
    }
    fn expect_poseidon2(a: u64, b: u64, gpu: Option<u64>) {
        let expected = ivm::poseidon2(a, b);
        match gpu {
            Some(value) => assert_eq!(value, expected),
            None => assert!(!super::cuda_available_py() || super::cuda_disabled_py()),
        }
    }
    fn expect_poseidon6(inputs: [u64; 6], gpu: Option<u64>) {
        let expected = ivm::poseidon6(inputs);
        match gpu {
            Some(value) => assert_eq!(value, expected),
            None => assert!(!super::cuda_available_py() || super::cuda_disabled_py()),
        }
    }
    fn expect_bn254<F>(a: [u64; 4], b: [u64; 4], gpu: Option<[u64; 4]>, reference_impl: F)
    where
        F: Fn(FieldElem, FieldElem) -> FieldElem,
    {
        let expected = reference_impl(FieldElem(a), FieldElem(b)).0;
        match gpu {
            Some(value) => assert_eq!(value, expected),
            None => assert!(!super::cuda_available_py() || super::cuda_disabled_py()),
        }
    }
    fn expect_bn254_many<F>(
        py: Python<'_>,
        lhs: &[[u64; 4]],
        rhs: &[[u64; 4]],
        result: PyResult<Py<PyTuple>>,
        reference_impl: F,
    ) where
        F: Fn(FieldElem, FieldElem) -> FieldElem,
    {
        let expected: Vec<[u64; 4]> = lhs
            .iter()
            .copied()
            .zip(rhs.iter().copied())
            .map(|(a, b)| reference_impl(FieldElem(a), FieldElem(b)).0)
            .collect();
        let value = result.expect("automatic BN254 batch");
        let value: Vec<[u64; 4]> = value
            .bind(py)
            .extract()
            .expect("canonical Python field rows");
        assert_eq!(value, expected);
    }
    #[test]
    fn cuda_probes_reflect_ivm_state() {
        assert_eq!(super::cuda_available_py(), ivm::cuda_available());
        assert_eq!(super::cuda_disabled_py(), ivm::cuda_disabled());
    }
    #[test]
    fn poseidon2_wrapper_matches_cpu() {
        expect_poseidon2(1, 2, super::poseidon2_cuda_py(1, 2));
    }
    #[test]
    fn poseidon6_wrapper_matches_cpu() {
        expect_poseidon6(
            [1, 2, 3, 4, 5, 6],
            super::poseidon6_cuda_py([1, 2, 3, 4, 5, 6]),
        );
    }
    #[test]
    fn bn254_add_wrapper_matches_cpu() {
        let a = [1, 0, 0, 0];
        let b = [2, 0, 0, 0];
        expect_bn254(a, b, super::bn254_add_cuda_py(a, b), bn254_vec::add);
    }
    #[test]
    fn bn254_sub_wrapper_matches_cpu() {
        let a = [5, 0, 0, 0];
        let b = [3, 0, 0, 0];
        expect_bn254(a, b, super::bn254_sub_cuda_py(a, b), bn254_vec::sub);
    }
    #[test]
    fn bn254_mul_wrapper_matches_cpu() {
        let a = [7, 0, 0, 0];
        let b = [11, 0, 0, 0];
        expect_bn254(a, b, super::bn254_mul_cuda_py(a, b), bn254_vec::mul);
    }
    #[test]
    fn bn254_add_many_wrapper_matches_cpu() {
        let lhs = vec![[1, 0, 0, 0], [2, 0, 0, 0], [9, 0, 0, 0]];
        let rhs = vec![[2, 0, 0, 0], [3, 0, 0, 0], [4, 0, 0, 0]];
        ensure_python();
        Python::attach(|py| {
            let left = PyList::new(py, &lhs).unwrap();
            let right = PyList::new(py, &rhs).unwrap();
            expect_bn254_many(
                py,
                &lhs,
                &rhs,
                super::bn254_add_many(
                    py,
                    left.as_any().cast().unwrap(),
                    right.as_any().cast().unwrap(),
                ),
                bn254_vec::add_scalar,
            );
            let empty = PyList::empty(py);
            let empty = super::bn254_add_many(
                py,
                empty.as_any().cast().unwrap(),
                empty.as_any().cast().unwrap(),
            )
            .unwrap();
            assert!(
                empty
                    .bind(py)
                    .extract::<Vec<[u64; 4]>>()
                    .unwrap()
                    .is_empty()
            );
        });
    }
    #[test]
    fn bn254_sub_many_wrapper_matches_cpu() {
        let lhs = vec![[5, 0, 0, 0], [8, 0, 0, 0], [13, 0, 0, 0]];
        let rhs = vec![[3, 0, 0, 0], [2, 0, 0, 0], [6, 0, 0, 0]];
        ensure_python();
        Python::attach(|py| {
            let left = PyList::new(py, &lhs).unwrap();
            let right = PyList::new(py, &rhs).unwrap();
            expect_bn254_many(
                py,
                &lhs,
                &rhs,
                super::bn254_sub_many(
                    py,
                    left.as_any().cast().unwrap(),
                    right.as_any().cast().unwrap(),
                ),
                bn254_vec::sub_scalar,
            );
        });
    }
    #[test]
    fn bn254_mul_many_wrapper_matches_cpu() {
        let lhs = vec![[7, 0, 0, 0], [11, 0, 0, 0], [5, 0, 0, 0]];
        let rhs = vec![[11, 0, 0, 0], [7, 0, 0, 0], [9, 0, 0, 0]];
        ensure_python();
        Python::attach(|py| {
            let left = PyList::new(py, &lhs).unwrap();
            let right = PyList::new(py, &rhs).unwrap();
            expect_bn254_many(
                py,
                &lhs,
                &rhs,
                super::bn254_mul_many(
                    py,
                    left.as_any().cast().unwrap(),
                    right.as_any().cast().unwrap(),
                ),
                bn254_vec::mul_scalar,
            );
        });
    }
    #[test]
    fn attempt_failure_payload_renders_policy_block() {
        ensure_python();
        let evidence = PolicyBlockEvidence {
            observed_status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            code: "gateway_compliance_denied".to_owned(),
            source: "baseline".to_owned(),
            catalog_digest_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        Python::attach(|py| {
            let payload = attempt_failure_payload(
                py,
                AttemptFailure::Provider {
                    message: "blocked".to_owned(),
                    policy_block: Some(evidence.clone()),
                },
            )
            .expect("payload");
            let payload = payload.bind(py);
            let policy = payload
                .get_item("policy_block")
                .expect("policy block entry")
                .expect("policy block entry");
            let policy = policy.cast::<PyDict>().expect("policy dict");
            assert_eq!(
                policy
                    .get_item("observed_status")
                    .expect("observed")
                    .expect("observed")
                    .extract::<u16>()
                    .expect("status code"),
                evidence.observed_status.as_u16()
            );
            assert_eq!(
                policy
                    .get_item("code")
                    .expect("code")
                    .expect("code")
                    .extract::<String>()
                    .expect("code"),
                evidence.code
            );
            assert_eq!(
                policy
                    .get_item("source")
                    .expect("source")
                    .expect("source")
                    .extract::<String>()
                    .expect("source"),
                evidence.source
            );
            assert_eq!(
                policy
                    .get_item("catalog_digest_hex")
                    .expect("catalog digest")
                    .expect("catalog digest")
                    .extract::<String>()
                    .expect("catalog digest"),
                evidence.catalog_digest_hex
            );
            assert_eq!(policy.len(), 4);
            for removed in [
                "canonical_status",
                "cache_version",
                "denylist_version",
                "proof_token_present",
                "message",
            ] {
                assert!(
                    policy
                        .get_item(removed)
                        .expect("removed field lookup")
                        .is_none(),
                    "removed policy evidence field `{removed}` must stay absent"
                );
            }
        });
    }
    #[test]
    fn transaction_builder_signs_only_the_exact_quoted_payer_and_gas_bound() {
        ensure_python();
        let signing = SigningKey::from_bytes(&[0x31; 32]);
        let public_key = PublicKey::from(parse_private_key(signing.as_bytes()).expect("private"));
        let authority = AccountId::new(public_key)
            .canonical_i105()
            .expect("canonical I105 authority");
        let intent = r#"{"payer":"authority","value":{"charge_limits":[],"gas_limit":100}}"#;
        let mut builder = TransactionBuilder::new(&python_test_network_id(), &authority, intent)
            .expect("builder constructs");
        builder.set_creation_time_ms(42).expect("creation time");
        let draft = builder.payload_json().expect("payload JSON");
        let envelope = builder
            .sign_quoted_payload(&draft, intent, signing.as_bytes())
            .expect("exact quote signs");
        assert_eq!(envelope.authority, authority);
        let mut substituted =
            TransactionBuilder::new(&python_test_network_id(), &authority, intent)
                .expect("builder constructs");
        substituted.set_creation_time_ms(42).expect("creation time");
        let draft = substituted.payload_json().expect("payload JSON");
        let changed_gas = r#"{"payer":"authority","value":{"charge_limits":[],"gas_limit":101}}"#;
        let error = match substituted.sign_quoted_payload(&draft, changed_gas, signing.as_bytes()) {
            Ok(_) => panic!("quote must not substitute the executable gas bound"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("fee quote changed the selected payer, sponsor revision, or gas bound")
        );
    }
    #[test]
    fn transaction_builder_rejects_invalid_fee_payment_replacement() {
        ensure_python();
        let signing = SigningKey::from_bytes(&[0x32; 32]);
        let public_key = PublicKey::from(parse_private_key(signing.as_bytes()).expect("private"));
        let authority = AccountId::new(public_key)
            .canonical_i105()
            .expect("canonical I105 authority");
        let mut builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs");
        let error = builder
            .set_fee_payment_json(
                r#"{"payer":"sponsor","value":{"charge_limits":[],"gas_limit":null,"program_revision":0}}"#,
            )
            .expect_err("malformed sponsor intent must reject");
        assert!(
            error
                .to_string()
                .contains("invalid fee payment intent JSON")
        );
    }
    fn batch_test_instruction(message: &str) -> Instruction {
        Instruction::new(
            iroha_data_model::isi::Log::new(iroha_data_model::Level::INFO, message.into()).into(),
        )
    }
    const BATCH_TEST_CONTRACT_ADDRESS: &str =
        "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh";
    #[test]
    fn transaction_builder_preserves_mixed_batch_order_and_wire_tags() {
        ensure_python();
        let authority = canonical_i105_from_seed(0x41);
        let mut builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            r#"{"payer":"authority","value":{"charge_limits":[],"gas_limit":1000}}"#,
        )
        .expect("builder constructs");
        let first = batch_test_instruction("before");
        let last = batch_test_instruction("after");
        let code_hash = Hash::new(b"python-mixed-batch-code");
        let mut arguments = vec![0xA5, 0x5A];
        builder.add_instruction(&first).expect("first instruction");
        builder
            .add_contract_call(
                BATCH_TEST_CONTRACT_ADDRESS,
                &code_hash.to_string(),
                "run",
                Some(arguments.as_slice()),
            )
            .expect("contract call");
        arguments.fill(0);
        builder.add_instruction(&last).expect("last instruction");
        builder.validate_executable().expect("valid mixed batch");
        let model = builder.to_model_builder();
        let executable = &model.payload().instructions;
        let encoded = norito::codec::Encode::encode(executable);
        assert_eq!(&encoded[..4], &4_u32.to_le_bytes());
        let Executable::Batch(items) = executable else {
            panic!("contract calls must select the batch executable")
        };
        assert!(matches!(items[0], ExecutableBatchItem::Instruction(_)));
        let ExecutableBatchItem::ContractCall(call) = &items[1] else {
            panic!("second item must remain the contract call")
        };
        assert_eq!(
            call.arguments.as_ref().expect("arguments").as_bytes(),
            &[0xA5, 0x5A],
            "bridge must defensively copy argument bytes"
        );
        assert!(matches!(items[2], ExecutableBatchItem::Instruction(_)));
        assert_eq!(
            &norito::codec::Encode::encode(&items[0])[..4],
            &0_u32.to_le_bytes()
        );
        assert_eq!(
            &norito::codec::Encode::encode(&items[1])[..4],
            &1_u32.to_le_bytes()
        );
    }
    #[test]
    fn transaction_builder_signs_ordinary_admission_and_preserves_instruction_carriers() {
        ensure_python();
        let authority = canonical_i105_from_seed(0x42);
        let mut instruction_builder = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("instruction builder constructs");
        instruction_builder
            .add_instruction(&batch_test_instruction("instruction"))
            .expect("instruction");
        let instruction_model = instruction_builder.to_model_builder();

        let instruction_executable = &instruction_model.payload().instructions;
        assert!(matches!(
            instruction_executable,
            Executable::Instructions(_)
        ));
        assert_eq!(
            &norito::codec::Encode::encode(instruction_executable)[..4],
            &0_u32.to_le_bytes()
        );
        let expected_payload = instruction_model.encode_payload();
        let envelope = instruction_builder
            .sign(&[0x42; 32])
            .expect("ordinary instruction signs");
        let signed = decode_canonical_signed_transaction_v1(&envelope.signed_transaction_versioned)
            .expect("exact signed instruction wire");
        signed
            .verify_signature()
            .expect("ordinary instruction signature");

        assert_eq!(codec::encode_adaptive(signed.payload()), expected_payload);
        let mut explicit = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("batch builder constructs");
        explicit.use_executable_batch().expect("select batch");
        explicit
            .add_instruction(&batch_test_instruction("explicit"))
            .expect("instruction");
        explicit.validate_executable().expect("non-empty batch");
        let expected_batch = explicit.to_model_builder().encode_payload();
        let batch_envelope = explicit.sign(&[0x42; 32]).expect("ordinary batch signs");
        let batch_signed =
            decode_canonical_signed_transaction_v1(&batch_envelope.signed_transaction_versioned)
                .expect("exact signed batch wire");
        batch_signed
            .verify_signature()
            .expect("ordinary batch signature");

        assert_eq!(
            codec::encode_adaptive(batch_signed.payload()),
            expected_batch
        );
        let explicit_executable = batch_signed.instructions();
        assert!(matches!(explicit_executable, Executable::Batch(_)));
        assert_eq!(
            &norito::codec::Encode::encode(explicit_executable)[..4],
            &4_u32.to_le_bytes()
        );
    }
    #[test]
    fn transaction_builder_rejects_invalid_batch_shapes_and_contract_inputs() {
        ensure_python();
        let authority = canonical_i105_from_seed(0x43);
        let code_hash = Hash::new(b"python-invalid-batch-code").to_string();
        let mut empty = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs");
        empty.use_executable_batch().expect("select batch");
        assert!(
            empty
                .validate_executable()
                .expect_err("empty batch must reject")
                .to_string()
                .contains("requires at least one item")
        );
        let mut without_gas = TransactionBuilder::new(
            &python_test_network_id(),
            &authority,
            authority_fee_payment_json(),
        )
        .expect("builder constructs");
        without_gas
            .add_contract_call(BATCH_TEST_CONTRACT_ADDRESS, &code_hash, "run", None)
            .expect("call input is valid");
        assert!(
            without_gas
                .validate_executable()
                .expect_err("missing gas limit must reject")
                .to_string()
                .contains("requires a transaction gas_limit")
        );
        let gas_intent = r#"{"payer":"authority","value":{"charge_limits":[],"gas_limit":1000}}"#;
        let mut invalid =
            TransactionBuilder::new(&python_test_network_id(), &authority, gas_intent)
                .expect("builder");
        assert!(
            invalid
                .add_contract_call("bad", &code_hash, "run", None)
                .is_err()
        );
        assert!(
            invalid
                .add_contract_call(BATCH_TEST_CONTRACT_ADDRESS, "00", "run", None)
                .is_err()
        );
        assert!(
            invalid
                .add_contract_call(BATCH_TEST_CONTRACT_ADDRESS, &code_hash, " ", None)
                .is_err()
        );
        let oversized = vec![0_u8; MAX_CONTRACT_ARGUMENT_RECORD_BYTES + 1];
        assert!(
            invalid
                .add_contract_call(
                    BATCH_TEST_CONTRACT_ADDRESS,
                    &code_hash,
                    "run",
                    Some(oversized.as_slice()),
                )
                .is_err()
        );
        let mut ivm = TransactionBuilder::new(&python_test_network_id(), &authority, gas_intent)
            .expect("builder");
        ivm.set_bytecode_hex("00").expect("bytecode");
        assert!(
            ivm.add_instruction(&batch_test_instruction("mixed"))
                .is_err()
        );
        let mut items = TransactionBuilder::new(&python_test_network_id(), &authority, gas_intent)
            .expect("builder");
        items
            .add_instruction(&batch_test_instruction("mixed"))
            .expect("instruction");
        assert!(items.set_bytecode_hex("00").is_err());
    }
}
fn py_to_metadata(py: Python<'_>, value: Option<&Bound<'_, PyAny>>) -> PyResult<Metadata> {
    match value {
        None => Ok(Metadata::default()),
        Some(obj) => {
            let dumped = py_to_json_string(py, obj, "metadata")?;
            json::from_str::<Metadata>(&dumped)
                .map_err(|err| PyValueError::new_err(format!("invalid metadata value: {err}")))
        }
    }
}
fn py_to_json_string(py: Python<'_>, value: &Bound<'_, PyAny>, context: &str) -> PyResult<String> {
    let json_module = py
        .import("json")
        .map_err(|err| PyValueError::new_err(format!("failed to import json module: {err}")))?;
    let dumped = json_module.call_method1("dumps", (value,)).map_err(|err| {
        PyValueError::new_err(format!("{context} must be JSON serializable: {err}"))
    })?;
    dumped
        .extract()
        .map_err(|err| PyValueError::new_err(format!("expected JSON string: {err}")))
}
fn py_to_json_model<T>(py: Python<'_>, value: &Bound<'_, PyAny>, context: &str) -> PyResult<T>
where
    T: norito::json::JsonDeserialize,
{
    let dumped = py_to_json_string(py, value, context)?;
    json::from_str::<T>(&dumped)
        .map_err(|err| PyValueError::new_err(format!("invalid {context} value: {err}")))
}
fn json_required_value(
    fields: &mut std::collections::BTreeMap<String, json::Value>,
    key: &str,
    context: &str,
) -> PyResult<json::Value> {
    fields
        .remove(key)
        .ok_or_else(|| PyValueError::new_err(format!("{context}.{key} is required")))
}
fn json_string_value(value: json::Value, context: &str) -> PyResult<String> {
    match value {
        json::Value::String(value) => Ok(value),
        _ => Err(PyValueError::new_err(format!("{context} must be a string"))),
    }
}
fn json_rwa_id_value(value: json::Value, context: &str) -> PyResult<RwaId> {
    let literal = json_string_value(value, context)?;
    literal
        .parse()
        .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{literal}`: {err}")))
}
fn json_rwa_parent_refs_value(value: json::Value, context: &str) -> PyResult<Vec<RwaParentRef>> {
    let json::Value::Array(entries) = value else {
        return Err(PyValueError::new_err(format!("{context} must be an array")));
    };
    let mut parents = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let entry_context = format!("{context}[{index}]");
        let json::Value::Object(mut fields) = entry else {
            return Err(PyValueError::new_err(format!(
                "{entry_context} must be an object"
            )));
        };
        let rwa = json_rwa_id_value(
            json_required_value(&mut fields, "rwa", &entry_context)?,
            &format!("{entry_context}.rwa"),
        )?;
        let quantity_context = format!("{entry_context}.quantity");
        let quantity_literal = json_string_value(
            json_required_value(&mut fields, "quantity", &entry_context)?,
            &quantity_context,
        )?;
        let quantity = parse_typed_quantity(&quantity_literal, &quantity_context)?;
        parents.push(RwaParentRef::new(rwa, quantity));
    }
    Ok(parents)
}
fn parse_new_rwa_payload(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<NewRwa> {
    let dumped = py_to_json_string(py, value, "rwa")?;
    let json::Value::Object(mut fields) = json::from_str::<json::Value>(&dumped)
        .map_err(|err| PyValueError::new_err(format!("invalid rwa value: {err}")))?
    else {
        return Err(PyValueError::new_err("rwa must be a JSON object"));
    };
    let domain =
        json::from_value::<DomainId>(json_required_value(&mut fields, "domain", "rwa")?)
            .map_err(|err| PyValueError::new_err(format!("invalid rwa.domain value: {err}")))?;
    let quantity_literal = json_string_value(
        json_required_value(&mut fields, "quantity", "rwa")?,
        "rwa.quantity",
    )?;
    let quantity = parse_typed_quantity(&quantity_literal, "rwa.quantity")?;
    let spec = json::from_value::<NumericSpec>(json_required_value(&mut fields, "spec", "rwa")?)
        .map_err(|err| PyValueError::new_err(format!("invalid rwa.spec value: {err}")))?;
    let primary_reference = json_string_value(
        json_required_value(&mut fields, "primary_reference", "rwa")?,
        "rwa.primary_reference",
    )?;
    let status = fields
        .remove("status")
        .map_or(Ok(None), |value| match value {
            json::Value::Null => Ok(None),
            other => json::from_value(other)
                .map(Some)
                .map_err(|err| PyValueError::new_err(format!("invalid rwa.status value: {err}"))),
        })?;
    let metadata = fields
        .remove("metadata")
        .map_or(Ok(Metadata::default()), |value| {
            json::from_value(value)
                .map_err(|err| PyValueError::new_err(format!("invalid rwa.metadata value: {err}")))
        })?;
    let parents = fields.remove("parents").map_or(Ok(Vec::new()), |value| {
        json_rwa_parent_refs_value(value, "rwa.parents")
    })?;
    let controls = fields
        .remove("controls")
        .map_or(Ok(RwaControlPolicy::default()), |value| {
            json::from_value(value)
                .map_err(|err| PyValueError::new_err(format!("invalid rwa.controls value: {err}")))
        })?;
    Ok(NewRwa::new(
        domain,
        quantity,
        spec,
        primary_reference,
        status,
        metadata,
        parents,
        controls,
    ))
}
fn parse_merge_rwas_payload(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
) -> PyResult<iroha_data_model::isi::rwa::MergeRwas> {
    let dumped = py_to_json_string(py, value, "merge")?;
    let json::Value::Object(mut fields) = json::from_str::<json::Value>(&dumped)
        .map_err(|err| PyValueError::new_err(format!("invalid merge value: {err}")))?
    else {
        return Err(PyValueError::new_err("merge must be a JSON object"));
    };
    let parents = json_rwa_parent_refs_value(
        json_required_value(&mut fields, "parents", "merge")?,
        "merge.parents",
    )?;
    let primary_reference = json_string_value(
        json_required_value(&mut fields, "primary_reference", "merge")?,
        "merge.primary_reference",
    )?;
    let status = fields
        .remove("status")
        .map_or(Ok(None), |value| match value {
            json::Value::Null => Ok(None),
            other => json::from_value(other)
                .map(Some)
                .map_err(|err| PyValueError::new_err(format!("invalid merge.status value: {err}"))),
        })?;
    let metadata = fields
        .remove("metadata")
        .map_or(Ok(Metadata::default()), |value| {
            json::from_value(value).map_err(|err| {
                PyValueError::new_err(format!("invalid merge.metadata value: {err}"))
            })
        })?;
    Ok(iroha_data_model::isi::rwa::MergeRwas {
        parents,
        primary_reference,
        status,
        metadata,
    })
}
fn py_to_json_value(py: Python<'_>, value: Option<&Bound<'_, PyAny>>) -> PyResult<Json> {
    match value {
        None => Ok(Json::default()),
        Some(obj) => {
            let dumped = py_to_json_string(py, obj, "trigger arguments")?;
            let value = json::from_str::<json::Value>(&dumped)
                .map_err(|err| PyValueError::new_err(format!("invalid JSON payload: {err}")))?;
            Json::from_norito_value_ref(&value)
                .map_err(|err| PyValueError::new_err(format!("invalid JSON payload: {err}")))
        }
    }
}
fn parse_asset_quantity(quantity: &str, context: &str) -> PyResult<Quantity> {
    if quantity.len() > 155 {
        return Err(PyValueError::new_err(format!(
            "{context} exceeds the canonical quantity text bound"
        )));
    }
    let parsed = Quantity::from_str(quantity)
        .map_err(|err| PyValueError::new_err(format!("invalid {context} `{quantity}`: {err}")))?;
    if parsed.to_string() != quantity {
        return Err(PyValueError::new_err(format!(
            "{context} must use canonical quantity spelling"
        )));
    }
    Ok(parsed)
}
fn parse_typed_quantity(quantity: &str, context: &str) -> PyResult<Quantity> {
    parse_asset_quantity(quantity, context)
}
fn parse_asset_transfer_limits(value: &Bound<'_, PyAny>) -> PyResult<Vec<AssetTransferLimit>> {
    let items = if let Ok(items) = value.cast::<PyList>() {
        items.iter().collect::<Vec<_>>()
    } else if let Ok(items) = value.cast::<PyTuple>() {
        items.iter().collect::<Vec<_>>()
    } else {
        return Err(PyTypeError::new_err(
            "limits must be a list or tuple of window/cap_amount mappings",
        ));
    };
    if items.len() > 3 {
        return Err(PyValueError::new_err(
            "limits may contain at most DAY, WEEK, and MONTH",
        ));
    }
    let mut parsed = Vec::with_capacity(items.len());
    let mut windows = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let context = format!("limits[{index}]");
        let mapping = item.cast::<PyDict>().map_err(|_| {
            PyTypeError::new_err(format!(
                "{context} must be a mapping with window/cap_amount fields"
            ))
        })?;
        ensure_allowed_kwargs(mapping, &["window", "cap_amount"], &context)?;
        let window_literal = dict_require(mapping, "window", || {
            PyValueError::new_err(format!("{context}.window is required"))
        })?
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err(format!("{context}.window must be a string")))?;
        let window = AssetTransferControlWindow::from_str(&window_literal).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid {context}.window `{window_literal}`: {error}"
            ))
        })?;
        if windows.contains(&window) {
            return Err(PyValueError::new_err(format!(
                "{context}.window duplicates an earlier window"
            )));
        }
        windows.push(window);
        let cap_amount = match mapping.get_item("cap_amount")? {
            None => {
                return Err(PyValueError::new_err(format!(
                    "{context}.cap_amount is required"
                )));
            }
            Some(value) if value.is_none() => None,
            Some(value) => Some(quantity_from_py(&value, &format!("{context}.cap_amount"))?),
        };
        parsed.push(AssetTransferLimit { window, cap_amount });
    }
    Ok(parsed)
}
fn parse_escrow_id(value: &str, context: &str) -> PyResult<EscrowId> {
    let text = value.trim();
    if text.is_empty() {
        return Err(PyValueError::new_err(format!(
            "{context} must be non-empty"
        )));
    }
    Ok(EscrowId::new(Hash::new(text.as_bytes())))
}
fn json_object_string(fields: &mut json::Map, key: &str, context: &str) -> PyResult<String> {
    let value = fields
        .remove(key)
        .ok_or_else(|| PyValueError::new_err(format!("{context} requires `{key}`")))?;
    match value {
        json::Value::String(value) if !value.is_empty() && value.trim() == value => Ok(value),
        _ => Err(PyValueError::new_err(format!(
            "{context}.{key} must be a non-empty unpadded string"
        ))),
    }
}
fn parse_transfer_asset_batch_entries(
    raw: &str,
    source: &AccountId,
    asset_definition: &AssetDefinitionId,
) -> PyResult<Vec<TransferAssetBatchEntry>> {
    let value = json::from_str::<json::Value>(raw)
        .map_err(|error| PyValueError::new_err(format!("invalid payments JSON: {error}")))?;
    let json::Value::Array(values) = value else {
        return Err(PyValueError::new_err("payments JSON must be an array"));
    };
    if values.is_empty() {
        return Err(PyValueError::new_err(
            "payments must contain at least one payment",
        ));
    }
    let mut leg_ids = HashSet::new();
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let json::Value::Object(mut fields) = value else {
                return Err(PyValueError::new_err(format!(
                    "payments[{index}] must be an object"
                )));
            };
            let context = format!("payments[{index}]");
            let leg_id = json_object_string(&mut fields, "id", &context)?;
            if !leg_ids.insert(leg_id.clone()) {
                return Err(PyValueError::new_err(format!(
                    "duplicate payment id `{leg_id}`"
                )));
            }
            let destination = parse_account_id(&json_object_string(&mut fields, "to", &context)?)?;
            let amount = parse_typed_quantity(
                &json_object_string(&mut fields, "amount", &context)?,
                "payment amount",
            )?;
            if amount.is_zero() {
                return Err(PyValueError::new_err(format!(
                    "{context}.amount must be positive"
                )));
            }
            if !fields.is_empty() {
                return Err(PyValueError::new_err(format!(
                    "{context} contains unknown fields"
                )));
            }
            Ok(TransferAssetBatchEntry::with_leg_id(
                leg_id,
                source.clone(),
                destination,
                asset_definition.clone(),
                amount,
            ))
        })
        .collect()
}
fn parse_optional_hashes(value: Option<&Bound<'_, PyAny>>, context: &str) -> PyResult<Vec<Hash>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    py_fixed_array_list(value, context)
        .map(|items| items.into_iter().map(Hash::prehashed).collect())
}
fn conditional_escrow_evidence_hash_from_py(
    value: &Bound<'_, PyAny>,
    context: &str,
) -> PyResult<Hash> {
    let raw_digest = py_fixed_array::<32>(value, context)?;
    Ok(hash_conditional_escrow_evidence_digest(&raw_digest))
}
fn parse_optional_conditional_evidence_digest(
    value: Option<&Bound<'_, PyAny>>,
    context: &str,
) -> PyResult<Option<Hash>> {
    value
        .filter(|value| !value.is_none())
        .map(|value| conditional_escrow_evidence_hash_from_py(value, context))
        .transpose()
}
fn parse_optional_conditional_evidence_digests(
    value: Option<&Bound<'_, PyAny>>,
    context: &str,
) -> PyResult<Vec<Hash>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    py_fixed_array_list(value, context).map(|digests| {
        digests
            .iter()
            .map(hash_conditional_escrow_evidence_digest)
            .collect()
    })
}
fn quantity_from_py(value: &Bound<'_, PyAny>, context: &str) -> PyResult<Quantity> {
    let literal = value.extract::<String>().map_err(|_| {
        PyTypeError::new_err(format!("{context} must be a canonical quantity string"))
    })?;
    parse_typed_quantity(&literal, context)
}
fn parse_repo_cash_leg(_py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<RepoCashLeg> {
    let dict = value.cast::<PyDict>().map_err(|_| {
        PyTypeError::new_err("cash_leg must be a mapping with asset_definition_id/quantity fields")
    })?;
    let asset_obj = dict
        .get_item("asset_definition_id")?
        .ok_or_else(|| PyValueError::new_err("cash_leg requires `asset_definition_id`"))?;
    let asset_str: String = asset_obj
        .extract()
        .map_err(|_| PyValueError::new_err("cash_leg `asset_definition_id` must be a string"))?;
    let asset_definition_id = asset_str.parse().map_err(|err| {
        PyValueError::new_err(format!(
            "invalid cash_leg asset definition `{asset_str}`: {err}"
        ))
    })?;
    let quantity_obj = dict
        .get_item("quantity")?
        .ok_or_else(|| PyValueError::new_err("cash_leg requires `quantity`"))?;
    let quantity = quantity_from_py(&quantity_obj, "cash_leg.quantity")?;
    Ok(RepoCashLeg {
        asset_definition_id,
        quantity,
    })
}
fn parse_repo_collateral_leg(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
) -> PyResult<RepoCollateralLeg> {
    let dict = value.cast::<PyDict>().map_err(|_| {
        PyTypeError::new_err(
            "collateral_leg must be a mapping with asset_definition_id/quantity fields",
        )
    })?;
    let asset_obj = dict
        .get_item("asset_definition_id")?
        .ok_or_else(|| PyValueError::new_err("collateral_leg requires `asset_definition_id`"))?;
    let asset_str: String = asset_obj.extract().map_err(|_| {
        PyValueError::new_err("collateral_leg `asset_definition_id` must be a string")
    })?;
    let asset_definition_id = asset_str.parse().map_err(|err| {
        PyValueError::new_err(format!(
            "invalid collateral asset definition `{asset_str}`: {err}"
        ))
    })?;
    let quantity_obj = dict
        .get_item("quantity")?
        .ok_or_else(|| PyValueError::new_err("collateral_leg requires `quantity`"))?;
    let quantity = quantity_from_py(&quantity_obj, "collateral_leg.quantity")?;
    let metadata = match dict.get_item("metadata")? {
        Some(meta) => py_to_metadata(py, Some(&meta))?,
        None => Metadata::default(),
    };
    Ok(RepoCollateralLeg {
        asset_definition_id,
        quantity,
        metadata,
    })
}
fn parse_settlement_leg(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<SettlementLeg> {
    let dict = value.cast::<PyDict>().map_err(|_| {
        PyTypeError::new_err(format!(
            "{name} must be a mapping with asset_definition_id, quantity, from, and to fields"
        ))
    })?;
    let asset_obj = dict
        .get_item("asset_definition_id")?
        .ok_or_else(|| PyValueError::new_err(format!("{name} requires `asset_definition_id`")))?;
    let asset_str: String = asset_obj.extract().map_err(|_| {
        PyValueError::new_err(format!("{name} `asset_definition_id` must be a string"))
    })?;
    let asset_definition_id = asset_str.parse().map_err(|err| {
        PyValueError::new_err(format!(
            "invalid {name} asset definition `{asset_str}`: {err}"
        ))
    })?;
    let quantity_obj = dict
        .get_item("quantity")?
        .ok_or_else(|| PyValueError::new_err(format!("{name} requires `quantity`")))?;
    let quantity = quantity_from_py(&quantity_obj, &format!("{name}.quantity"))?;
    let from_obj = dict
        .get_item("from")?
        .ok_or_else(|| PyValueError::new_err(format!("{name} requires `from`")))?;
    let from_str: String = from_obj
        .extract()
        .map_err(|_| PyValueError::new_err(format!("{name} `from` must be a string")))?;
    let from_account = parse_account_id(&from_str).map_err(|err| {
        PyValueError::new_err(format!("invalid {name} `from` account `{from_str}`: {err}"))
    })?;
    let to_obj = dict
        .get_item("to")?
        .ok_or_else(|| PyValueError::new_err(format!("{name} requires `to`")))?;
    let to_str: String = to_obj
        .extract()
        .map_err(|_| PyValueError::new_err(format!("{name} `to` must be a string")))?;
    let to_account = parse_account_id(&to_str).map_err(|err| {
        PyValueError::new_err(format!("invalid {name} `to` account `{to_str}`: {err}"))
    })?;
    let metadata = match dict.get_item("metadata")? {
        Some(meta) => py_to_metadata(py, Some(&meta))?,
        None => Metadata::default(),
    };
    Ok(SettlementLeg {
        asset_definition_id,
        quantity,
        from: from_account,
        to: to_account,
        metadata,
    })
}
fn parse_settlement_order(value: &str) -> PyResult<SettlementExecutionOrder> {
    let normalized = value.replace('-', "_").to_ascii_lowercase();
    match normalized.as_str() {
        "delivery_then_payment" => Ok(SettlementExecutionOrder::DeliveryThenPayment),
        "payment_then_delivery" => Ok(SettlementExecutionOrder::PaymentThenDelivery),
        _ => Err(PyValueError::new_err(format!(
            "unknown settlement order `{value}` (expected `delivery_then_payment` or `payment_then_delivery`)"
        ))),
    }
}
fn parse_settlement_atomicity(value: &str) -> PyResult<SettlementAtomicity> {
    let normalized = value.replace('-', "_").to_ascii_lowercase();
    match normalized.as_str() {
        "all_or_nothing" => Ok(SettlementAtomicity::AllOrNothing),
        _ => Err(PyValueError::new_err(format!(
            "unknown settlement atomicity `{value}` (expected `all_or_nothing`)"
        ))),
    }
}
fn parse_u16_field(value: &Bound<'_, PyAny>, field: &str) -> PyResult<u16> {
    if let Ok(v) = value.extract::<u16>() {
        return Ok(v);
    }
    if let Ok(s) = value.extract::<String>() {
        return s
            .parse::<u16>()
            .map_err(|err| PyValueError::new_err(format!("invalid `{field}` value `{s}`: {err}")));
    }
    Err(PyValueError::new_err(format!(
        "`{field}` must be an unsigned 16-bit integer"
    )))
}
fn parse_u64_field(value: &Bound<'_, PyAny>, field: &str) -> PyResult<u64> {
    if let Ok(v) = value.extract::<u64>() {
        return Ok(v);
    }
    if let Ok(s) = value.extract::<String>() {
        return s
            .parse::<u64>()
            .map_err(|err| PyValueError::new_err(format!("invalid `{field}` value `{s}`: {err}")));
    }
    Err(PyValueError::new_err(format!(
        "`{field}` must be an unsigned 64-bit integer"
    )))
}
fn parse_repo_governance(value: &Bound<'_, PyAny>) -> PyResult<RepoGovernance> {
    let dict = value.cast::<PyDict>().map_err(|_| {
        PyTypeError::new_err(
            "governance must be a mapping with `haircut_bps`, `margin_frequency_secs` and `allow_early_repayment` fields",
        )
    })?;
    let haircut_obj = dict
        .get_item("haircut_bps")?
        .ok_or_else(|| PyValueError::new_err("governance requires `haircut_bps`"))?;
    let margin_obj = dict
        .get_item("margin_frequency_secs")?
        .ok_or_else(|| PyValueError::new_err("governance requires `margin_frequency_secs`"))?;
    let early_obj = dict
        .get_item("allow_early_repayment")?
        .ok_or_else(|| PyValueError::new_err("governance requires `allow_early_repayment`"))?;
    let haircut_bps = parse_u16_field(&haircut_obj, "haircut_bps")?;
    let margin_frequency_secs = parse_u64_field(&margin_obj, "margin_frequency_secs")?;
    // Require an actual bool; Python truthiness would silently accept 0/1 or strings.
    if !early_obj.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err(
            "`allow_early_repayment` must be a boolean",
        ));
    }
    let allow_early_repayment: bool = early_obj.extract()?;
    Ok(RepoGovernance::new(
        haircut_bps,
        margin_frequency_secs,
        allow_early_repayment,
    ))
}
fn parse_mintable(mode: Option<&str>) -> PyResult<Mintable> {
    let label = mode.unwrap_or("Infinitely");
    match label {
        "Infinitely" => Ok(Mintable::Infinitely),
        "Once" => Ok(Mintable::Once),
        "Not" => Ok(Mintable::Not),
        other if other.starts_with("Limited(") && other.ends_with(')') => {
            let inner = &other["Limited(".len()..other.len() - 1];
            let tokens = inner.parse::<u32>().map_err(|_| {
                PyValueError::new_err(format!("invalid Limited token count `{inner}`"))
            })?;
            Mintable::limited_from_u32(tokens).map_err(|err| PyValueError::new_err(err.to_string()))
        }
        other => Err(PyValueError::new_err(format!(
            "invalid mintable value `{other}`; expected Infinitely/Once/Not/Limited(n)"
        ))),
    }
}
fn parse_balance_scope_policy(mode: &str) -> PyResult<AssetBalancePolicy> {
    let policy = match mode {
        "Global" => AssetBalancePolicy::Global,
        "DataspaceRestricted" => AssetBalancePolicy::DataspaceRestricted,
        other => {
            return Err(PyValueError::new_err(format!(
                "invalid balance scope policy `{other}`; expected Global/DataspaceRestricted"
            )));
        }
    };
    Ok(policy)
}
fn account_id_to_py(py: Python<'_>, id: &AccountId) -> PyResult<Py<PyAccountId>> {
    Py::new(py, PyAccountId { inner: id.clone() })
}
fn asset_definition_id_to_py(
    py: Python<'_>,
    id: &AssetDefinitionId,
) -> PyResult<Py<PyAssetDefinitionId>> {
    Py::new(py, PyAssetDefinitionId { inner: id.clone() })
}
#[pyclass(
    from_py_object,
    frozen,
    name = "NetworkId",
    module = "iroha_native._crypto"
)]
#[derive(Clone, Copy)]
pub(crate) struct PyNetworkId {
    inner: NetworkId,
}
impl PyNetworkId {
    pub(crate) const fn as_inner(&self) -> &NetworkId {
        &self.inner
    }
    fn from_exact_bytes(value: &[u8]) -> PyResult<Self> {
        let bytes = fixed_array::<{ Hash::LENGTH }>(value, "NetworkId")?;
        if bytes[Hash::LENGTH - 1] & 1 == 0 {
            return Err(PyValueError::new_err(
                "NetworkId must carry the canonical Iroha hash marker bit",
            ));
        }
        Ok(Self {
            inner: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                Hash::prehashed(bytes),
            )),
        })
    }
}
fn canonical_network_id_literal(network_id: &NetworkId) -> String {
    network_id.to_string()
}
#[pymethods]
impl PyNetworkId {
    /// Parse one exact canonical checksummed genesis-header hash literal.
    #[staticmethod]
    fn parse(value: &str) -> PyResult<Self> {
        let inner = value.parse::<NetworkId>().map_err(|_| {
            PyValueError::new_err(
                "NetworkId must be an exact canonical checksummed 32-byte Iroha hash literal",
            )
        })?;
        if canonical_network_id_literal(&inner) != value {
            return Err(PyValueError::new_err(
                "NetworkId must be an exact canonical checksummed 32-byte Iroha hash literal",
            ));
        }
        Ok(Self { inner })
    }
    /// Construct one exact NetworkId from marked genesis-header hash bytes.
    #[staticmethod]
    fn from_bytes(value: &[u8]) -> PyResult<Self> {
        Self::from_exact_bytes(value)
    }
    /// Return the canonical checksummed hash literal.
    #[getter]
    fn literal(&self) -> PyResult<String> {
        Ok(canonical_network_id_literal(&self.inner))
    }
    /// Return a defensive copy of the exact genesis-header hash bytes.
    #[expect(clippy::wrong_self_convention, reason = "PyO3 borrowed receiver")]
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.as_bytes())
    }
    fn __str__(&self) -> PyResult<String> {
        self.literal()
    }
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "NetworkId('{}')",
            canonical_network_id_literal(&self.inner)
        ))
    }
    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
    fn __hash__(&self) -> u64 {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&self.inner.as_bytes()[..8]);
        u64::from_le_bytes(prefix)
    }
    fn __copy__(&self) -> Self {
        *self
    }
    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> Self {
        *self
    }
}
#[pyclass(from_py_object, name = "DomainId", module = "iroha_native._crypto")]
#[derive(Clone)]
struct PyDomainId {
    inner: DomainId,
}
#[pymethods]
impl PyDomainId {
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        let inner = DomainId::parse_fully_qualified(value)
            .map_err(|err| PyValueError::new_err(format!("invalid domain id `{value}`: {err}")))?;
        Ok(Self { inner })
    }
    #[getter]
    fn value(&self) -> String {
        self.inner.to_string()
    }
    fn __str__(&self) -> String {
        self.value()
    }
    fn __repr__(&self) -> String {
        format!("DomainId('{}')", self.value())
    }
    fn __copy__(&self) -> Self {
        self.clone()
    }
    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> Self {
        self.clone()
    }
}
#[pyclass(from_py_object, name = "AccountId", module = "iroha_native._crypto")]
#[derive(Clone)]
struct PyAccountId {
    inner: AccountId,
}
#[pymethods]
impl PyAccountId {
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        let id = parse_exact_i105_account_id(value, "AccountId")?;
        Ok(Self { inner: id })
    }
    #[getter]
    fn value(&self) -> String {
        self.inner.to_string()
    }
    #[getter]
    fn public_key_hex(&self) -> PyResult<String> {
        let signatory = require_single_signatory(&self.inner, "AccountId")?;
        let (_, bytes) = public_key_to_bytes(signatory, "account signatory public key")?;
        Ok(hex::encode(bytes))
    }
    fn __str__(&self) -> String {
        self.value()
    }
    fn __repr__(&self) -> String {
        format!("AccountId('{}')", self.value())
    }
    fn __copy__(&self) -> Self {
        self.clone()
    }
    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> Self {
        self.clone()
    }
}
#[pyclass(
    from_py_object,
    name = "AssetDefinitionId",
    module = "iroha_native._crypto"
)]
#[derive(Clone)]
struct PyAssetDefinitionId {
    inner: AssetDefinitionId,
}
#[pymethods]
impl PyAssetDefinitionId {
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        let inner = value.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid asset definition id `{value}`: {err}"))
        })?;
        Ok(Self { inner })
    }
    #[staticmethod]
    fn from_domain_and_name(domain_id: &str, name: &str) -> PyResult<Self> {
        let domain = DomainId::parse_fully_qualified(domain_id).map_err(|err| {
            PyValueError::new_err(format!("invalid domain id `{domain_id}`: {err}"))
        })?;
        let name: Name = name
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid asset name `{name}`: {err}")))?;
        Ok(Self {
            inner: AssetDefinitionId::derive_from_components(domain, name),
        })
    }
    #[getter]
    fn value(&self) -> String {
        self.inner.to_string()
    }
    fn canonical_address(&self) -> String {
        self.inner.canonical_address().to_string()
    }
    fn __str__(&self) -> String {
        self.value()
    }
    fn __repr__(&self) -> String {
        format!("AssetDefinitionId('{}')", self.value())
    }
    fn __copy__(&self) -> Self {
        self.clone()
    }
    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> Self {
        self.clone()
    }
}
#[pyclass(from_py_object, name = "AssetId", module = "iroha_native._crypto")]
#[derive(Clone)]
struct PyAssetId {
    inner: AssetId,
}
#[pymethods]
impl PyAssetId {
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        let inner = parse_asset_id(value)?;
        Ok(Self { inner })
    }
    #[classmethod]
    fn from_parts(
        _cls: &Bound<'_, PyType>,
        definition: &PyAssetDefinitionId,
        account: &PyAccountId,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: AssetId::new(definition.inner.clone(), account.inner.clone()),
        })
    }
    #[getter]
    fn value(&self) -> String {
        self.inner.to_string()
    }
    #[getter]
    fn definition<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAssetDefinitionId>> {
        asset_definition_id_to_py(py, self.inner.definition())
    }
    #[getter]
    fn account<'py>(&self, py: Python<'py>) -> PyResult<Py<PyAccountId>> {
        account_id_to_py(py, self.inner.account())
    }
    fn __str__(&self) -> String {
        self.value()
    }
    fn __repr__(&self) -> String {
        format!("AssetId('{}')", self.value())
    }
    fn __copy__(&self) -> Self {
        self.clone()
    }
    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> Self {
        self.clone()
    }
}
fn numeric_spec_from_optional_scale(scale: Option<u32>) -> PyResult<NumericSpec> {
    match scale {
        Some(scale) => NumericSpec::try_fractional(scale).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid asset numeric scale `{scale}`; expected 0..={}: {error}",
                iroha_primitives::numeric::MAX_DECIMAL_SCALE
            ))
        }),
        None => Ok(NumericSpec::unconstrained()),
    }
}
#[pyclass(from_py_object, module = "iroha_native._crypto")]
#[derive(Clone)]
struct Instruction {
    inner: InstructionBox,
}
impl Instruction {
    fn new(inner: InstructionBox) -> Self {
        Self { inner }
    }
}
#[pymethods]
impl Instruction {
    #[classmethod]
    fn from_json(_cls: &Bound<'_, PyType>, payload: &str) -> PyResult<Self> {
        let instruction = json::from_str::<InstructionBox>(payload)
            .map_err(|err| PyValueError::new_err(format!("invalid instruction JSON: {err}")))?;
        Ok(Instruction::new(instruction))
    }
    /// Build the choice-free update of one existing public standalone ballot.
    #[classmethod]
    fn update_plain_conviction(
        _cls: &Bound<'_, PyType>,
        referendum_id: &str,
        owner: &str,
        amount: &str,
        duration_blocks: u64,
    ) -> PyResult<Self> {
        if !iroha_data_model::governance::is_valid_governance_selector_v1(referendum_id) {
            return Err(PyValueError::new_err(
                "referendum_id must be a canonical governance selector V1",
            ));
        }
        let instruction = UpdatePlainConviction {
            referendum_id: referendum_id.to_owned(),
            owner: parse_exact_i105_account_id(owner, "owner")?,
            amount: parse_asset_quantity(amount, "amount")?,
            duration_blocks,
        };
        Ok(Self::new(instruction.into()))
    }
    /// Construct one canonical native SoraFS replication-order issue.
    #[classmethod]
    #[pyo3(signature = (order_id, order_payload_base64, issued_epoch, deadline_epoch, musubi_archive=None))]
    fn issue_replication_order(
        _cls: &Bound<'_, PyType>,
        order_id: &str,
        order_payload_base64: &str,
        issued_epoch: u64,
        deadline_epoch: u64,
        musubi_archive: Option<&str>,
    ) -> PyResult<Self> {
        let order_id = parse_nonzero_lower_hex_32(order_id, "order_id")?;
        if deadline_epoch <= issued_epoch {
            return Err(PyValueError::new_err(
                "deadline_epoch must be greater than issued_epoch",
            ));
        }
        if order_payload_base64.is_empty()
            || order_payload_base64.trim() != order_payload_base64
            || order_payload_base64.chars().any(char::is_whitespace)
        {
            return Err(PyValueError::new_err(
                "order_payload must be exact canonical standard base64",
            ));
        }
        let order_payload = BASE64.decode(order_payload_base64).map_err(|err| {
            PyValueError::new_err(format!(
                "order_payload must be exact canonical standard base64: {err}"
            ))
        })?;
        if order_payload.is_empty()
            || order_payload.len() > 1_048_576
            || BASE64.encode(&order_payload) != order_payload_base64
        {
            return Err(PyValueError::new_err(
                "order_payload must be 1..=1048576 bytes of exact canonical standard base64",
            ));
        }
        let decoded: ReplicationOrderV1 = decode_from_bytes(&order_payload).map_err(|err| {
            PyValueError::new_err(format!(
                "order_payload must be a canonical ReplicationOrderV1 archive: {err}"
            ))
        })?;
        decoded.validate().map_err(|err| {
            PyValueError::new_err(format!("invalid ReplicationOrderV1 policy: {err}"))
        })?;
        if decoded.order_id != order_id {
            return Err(PyValueError::new_err(
                "order_id must match ReplicationOrderV1.order_id",
            ));
        }
        let canonical = norito::to_bytes(&decoded).map_err(|err| {
            PyValueError::new_err(format!(
                "failed to re-encode canonical ReplicationOrderV1: {err}"
            ))
        })?;
        if canonical != order_payload {
            return Err(PyValueError::new_err(
                "order_payload must use the canonical ReplicationOrderV1 encoding",
            ));
        }
        let instruction = IssueReplicationOrder::new(
            ReplicationOrderId::new(order_id),
            order_payload,
            issued_epoch,
            deadline_epoch,
        );
        let instruction = if let Some(archive_id) = musubi_archive {
            instruction.for_musubi_archive(ArchiveId::new(parse_nonzero_lower_hex_32(
                archive_id,
                "musubi_archive",
            )?))
        } else {
            instruction
        };
        Ok(Self::new(instruction.into()))
    }
    /// Construct one exact six-field SoraFS provider completion.
    #[classmethod]
    fn complete_replication_order(
        _cls: &Bound<'_, PyType>,
        order_id: &str,
        provider_id: &str,
        completion_epoch: u64,
        expected_authority: &Bound<'_, PyDict>,
        expected_assignment_revision: u64,
        finalized_anchor: &Bound<'_, PyDict>,
    ) -> PyResult<Self> {
        if expected_assignment_revision == 0 {
            return Err(PyValueError::new_err(
                "expected_assignment_revision must be greater than zero",
            ));
        }
        Ok(Self::new(
            CompleteReplicationOrder::new(
                ReplicationOrderId::new(parse_nonzero_lower_hex_32(order_id, "order_id")?),
                ProviderId(parse_nonzero_lower_hex_32(provider_id, "provider_id")?),
                completion_epoch,
                parse_provider_ingest_completion_authority(expected_authority)?,
                expected_assignment_revision,
                parse_provider_ingest_finalized_anchor(finalized_anchor)?,
            )
            .into(),
        ))
    }
    /// Construct one canonical native SoraFS replication-order expiration.
    #[classmethod]
    fn expire_replication_order(
        _cls: &Bound<'_, PyType>,
        order_id: &str,
        expiration_epoch: u64,
    ) -> PyResult<Self> {
        Ok(Self::new(
            ExpireReplicationOrder::new(
                ReplicationOrderId::new(parse_nonzero_lower_hex_32(order_id, "order_id")?),
                expiration_epoch,
            )
            .into(),
        ))
    }
    /// Construct the atomic smart-contract deployment commit instruction.
    #[classmethod]
    #[pyo3(signature = (expected_deploy_nonce, contract_address, code_hash_hex, contract_alias, lease_expiry_ms=None, expected_previous_contract_address=None))]
    fn commit_contract_deployment(
        _cls: &Bound<'_, PyType>,
        expected_deploy_nonce: u64,
        contract_address: &str,
        code_hash_hex: &str,
        contract_alias: &str,
        lease_expiry_ms: Option<u64>,
        expected_previous_contract_address: Option<&str>,
    ) -> PyResult<Self> {
        let instruction = CommitContractDeployment {
            expected_deploy_nonce,
            contract_address: ContractAddress::from_str(contract_address).map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid contract_address `{contract_address}`: {error}"
                ))
            })?,
            code_hash: Hash::from_str(code_hash_hex).map_err(|error| {
                PyValueError::new_err(format!("invalid code_hash_hex `{code_hash_hex}`: {error}"))
            })?,
            contract_alias: ContractAlias::from_str(contract_alias).map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid contract_alias `{contract_alias}`: {error}"
                ))
            })?,
            lease_expiry_ms,
            expected_previous_contract_address: expected_previous_contract_address
                .map(|value| {
                    ContractAddress::from_str(value).map_err(|error| {
                        PyValueError::new_err(format!(
                            "invalid expected_previous_contract_address `{value}`: {error}"
                        ))
                    })
                })
                .transpose()?,
        };
        Ok(Self::new(instruction.into()))
    }
    /// Construct the signed-transaction instruction for a Nexus lane lifecycle update.
    ///
    /// `status_json` must be an unmodified response from
    /// `GET /v1/nexus/lifecycle`; its version, canonical catalog, and catalog
    /// commitment are validated before the optimistic `SetParameter` payload is
    /// constructed. `plan_json` is the JSON representation of
    /// `LaneLifecyclePlan`.
    #[classmethod]
    fn nexus_lane_lifecycle(
        _cls: &Bound<'_, PyType>,
        status_json: &str,
        plan_json: &str,
    ) -> PyResult<Self> {
        let status = json::from_str::<LaneLifecycleStatusV1>(status_json).map_err(|err| {
            PyValueError::new_err(format!("invalid Nexus lane lifecycle status JSON: {err}"))
        })?;
        let catalog = status.validate().map_err(|err| {
            PyValueError::new_err(format!("invalid Nexus lane lifecycle status: {err}"))
        })?;
        let plan = json::from_str::<LaneLifecyclePlan>(plan_json).map_err(|err| {
            PyValueError::new_err(format!("invalid Nexus lane lifecycle plan JSON: {err}"))
        })?;
        catalog.apply_lifecycle(&plan).map_err(|err| {
            PyValueError::new_err(format!("invalid Nexus lane lifecycle plan: {err}"))
        })?;
        let custom = LaneLifecycleParameterV1::new(&catalog, &status.incarnations, plan)
            .map_err(|err| {
                PyValueError::new_err(format!("invalid Nexus lane incarnation binding: {err}"))
            })?
            .into_custom_parameter();
        Ok(Instruction::new(
            SetParameter::new(Parameter::Custom(custom)).into(),
        ))
    }
    fn to_json(&self) -> PyResult<String> {
        let mut output = String::new();
        self.inner.json_serialize(&mut output);
        Ok(output)
    }
    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Py<PyDict>> {
        let json_str = self.to_json()?;
        let json_module = py.import("json")?;
        let loads = json_module.getattr("loads")?;
        let value = loads.call1((json_str,))?;
        let dict: Py<PyDict> = value.extract()?;
        Ok(dict)
    }
    /// Return the canonical framed Norito `InstructionBox`.
    fn to_norito_bytes<'py>(&self, py: Python<'py>) -> PyResult<Py<PyBytes>> {
        let bytes = norito::to_bytes(&self.inner).map_err(|err| {
            PyValueError::new_err(format!("failed to encode canonical InstructionBox: {err}"))
        })?;
        Ok(Py::from(PyBytes::new(py, &bytes)))
    }
    /// Return the stable registry identity used by canonical instruction framing.
    fn wire_id(&self) -> PyResult<String> {
        iroha_data_model::isi::instruction_wire_id(&self.inner)
            .map(str::to_owned)
            .ok_or_else(|| PyValueError::new_err("instruction is not registered"))
    }
    /// Create a new fail-closed fee sponsor program.
    #[classmethod]
    #[pyo3(signature = (sponsor, payout_account, program_name = "default"))]
    fn create_fee_sponsor_program(
        _cls: &Bound<'_, PyType>,
        sponsor: &str,
        payout_account: &str,
        program_name: &str,
    ) -> PyResult<Self> {
        let sponsor: AccountId = parse_account_id(sponsor).map_err(|err| {
            PyValueError::new_err(format!("invalid fee sponsor account `{sponsor}`: {err}"))
        })?;
        let payout_account = parse_account_id(payout_account).map_err(|err| {
            PyValueError::new_err(format!(
                "invalid fee sponsor payout account `{payout_account}`: {err}"
            ))
        })?;
        let program_name: Name = program_name.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid fee sponsor program `{program_name}`: {err}"
            ))
        })?;
        let program = FeeSponsorProgram::new(
            FeeSponsorProgramId::new(sponsor, program_name),
            payout_account,
        );
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::CreateFeeSponsorProgram { program }.into(),
        ))
    }
    /// Stage an immutable fee sponsor program revision from canonical Norito JSON.
    #[classmethod]
    fn stage_fee_sponsor_program_revision(
        _cls: &Bound<'_, PyType>,
        revision_json: &str,
    ) -> PyResult<Self> {
        let revision =
            json::from_str::<FeeSponsorProgramRevision>(revision_json).map_err(|err| {
                PyValueError::new_err(format!("invalid fee sponsor program revision JSON: {err}"))
            })?;
        revision.validate().map_err(|err| {
            PyValueError::new_err(format!("invalid fee sponsor program revision: {err}"))
        })?;
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::StageFeeSponsorProgramRevision { revision }.into(),
        ))
    }
    /// Schedule an exact staged fee sponsor program revision for activation.
    #[classmethod]
    fn activate_fee_sponsor_program_revision(
        _cls: &Bound<'_, PyType>,
        program_id: &str,
        revision: u64,
        activate_at_height: u64,
    ) -> PyResult<Self> {
        if revision == 0 {
            return Err(PyValueError::new_err(
                "fee sponsor program revision must be non-zero",
            ));
        }
        let program_id = parse_fee_sponsor_program_id(program_id)?;
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::ActivateFeeSponsorProgramRevision {
                program_id,
                revision,
                activate_at_height,
            }
            .into(),
        ))
    }
    /// Pause an active fee sponsor program.
    #[classmethod]
    fn pause_fee_sponsor_program(_cls: &Bound<'_, PyType>, program_id: &str) -> PyResult<Self> {
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::PauseFeeSponsorProgram {
                program_id: parse_fee_sponsor_program_id(program_id)?,
            }
            .into(),
        ))
    }
    /// Begin the fail-closed drain phase for a fee sponsor program.
    #[classmethod]
    fn begin_close_fee_sponsor_program(
        _cls: &Bound<'_, PyType>,
        program_id: &str,
    ) -> PyResult<Self> {
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::BeginCloseFeeSponsorProgram {
                program_id: parse_fee_sponsor_program_id(program_id)?,
            }
            .into(),
        ))
    }
    /// Permanently close a fully drained fee sponsor program.
    #[classmethod]
    fn close_fee_sponsor_program(_cls: &Bound<'_, PyType>, program_id: &str) -> PyResult<Self> {
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::CloseFeeSponsorProgram {
                program_id: parse_fee_sponsor_program_id(program_id)?,
            }
            .into(),
        ))
    }
    /// Enroll one exact canonical account in a fee sponsor program.
    #[classmethod]
    fn enroll_fee_sponsor_beneficiary(
        _cls: &Bound<'_, PyType>,
        program_id: &str,
        beneficiary: &str,
    ) -> PyResult<Self> {
        let beneficiary = parse_account_id(beneficiary)?;
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::EnrollFeeSponsorBeneficiary {
                program_id: parse_fee_sponsor_program_id(program_id)?,
                beneficiary,
            }
            .into(),
        ))
    }
    /// Remove one exact canonical account from a fee sponsor program.
    #[classmethod]
    fn unenroll_fee_sponsor_beneficiary(
        _cls: &Bound<'_, PyType>,
        program_id: &str,
        beneficiary: &str,
    ) -> PyResult<Self> {
        let beneficiary = parse_account_id(beneficiary)?;
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::UnenrollFeeSponsorBeneficiary {
                program_id: parse_fee_sponsor_program_id(program_id)?,
                beneficiary,
            }
            .into(),
        ))
    }
    /// Allocate a positive asset amount to one program-isolated fee vault.
    #[classmethod]
    fn fund_fee_sponsor_program(
        _cls: &Bound<'_, PyType>,
        program_id: &str,
        asset_definition_id: &str,
        amount: &str,
    ) -> PyResult<Self> {
        let amount = parse_asset_quantity(amount, "fee sponsor funding amount")?;
        if amount.is_zero() {
            return Err(PyValueError::new_err(
                "fee sponsor funding amount must be positive",
            ));
        }
        let asset_definition_id = asset_definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid fee sponsor asset definition `{asset_definition_id}`: {err}"
            ))
        })?;
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::FundFeeSponsorProgram {
                program_id: parse_fee_sponsor_program_id(program_id)?,
                asset_definition_id,
                amount,
            }
            .into(),
        ))
    }
    /// Withdraw a positive asset amount from a paused or closing program vault.
    #[classmethod]
    fn withdraw_fee_sponsor_program(
        _cls: &Bound<'_, PyType>,
        program_id: &str,
        asset_definition_id: &str,
        amount: &str,
    ) -> PyResult<Self> {
        let amount = parse_asset_quantity(amount, "fee sponsor withdrawal amount")?;
        if amount.is_zero() {
            return Err(PyValueError::new_err(
                "fee sponsor withdrawal amount must be positive",
            ));
        }
        let asset_definition_id = asset_definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid fee sponsor asset definition `{asset_definition_id}`: {err}"
            ))
        })?;
        Ok(Instruction::new(
            iroha_data_model::isi::nexus::WithdrawFeeSponsorProgram {
                program_id: parse_fee_sponsor_program_id(program_id)?,
                asset_definition_id,
                amount,
            }
            .into(),
        ))
    }
    #[classmethod]
    fn register_domain<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        domain_id: &str,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let domain_id = DomainId::parse_fully_qualified(domain_id).map_err(|err| {
            PyValueError::new_err(format!("invalid domain id `{domain_id}`: {err}"))
        })?;
        let metadata = py_to_metadata(py, metadata)?;
        let new_domain = Domain::new(domain_id).with_metadata(metadata);
        let instruction = Register::<Domain>::domain(new_domain);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn register_account<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        account_id: &str,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let account_id: AccountId = parse_account_id(account_id)?;
        let metadata = py_to_metadata(py, metadata)?;
        let mut new_account = Account::new(account_id);
        new_account.metadata = metadata;
        let instruction = Register::<Account>::account(new_account);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (definition_id, *, owning_domain, balance_scope_policy, name, description=None, alias=None, scale=None, mintable=None, metadata=None))]
    #[allow(clippy::too_many_arguments)] // PyO3 signature mirrors the Python surface and requires explicit keyword params
    fn register_asset_definition<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        definition_id: &str,
        owning_domain: Option<&str>,
        balance_scope_policy: &str,
        name: &str,
        description: Option<&str>,
        alias: Option<&str>,
        scale: Option<u32>,
        mintable: Option<&str>,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let definition_id: AssetDefinitionId = definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{definition_id}`: {err}"
            ))
        })?;
        let owning_domain = owning_domain
            .map(|domain| {
                DomainId::parse_fully_qualified(domain).map_err(|err| {
                    PyValueError::new_err(format!("invalid owning domain `{domain}`: {err}"))
                })
            })
            .transpose()?;
        let parsed_balance_scope_policy = parse_balance_scope_policy(balance_scope_policy)?;
        validate_asset_name(name).map_err(|err| {
            PyValueError::new_err(format!("invalid asset definition name `{name}`: {err}"))
        })?;
        if parsed_balance_scope_policy == AssetBalancePolicy::DataspaceRestricted
            && owning_domain.is_none()
        {
            return Err(PyValueError::new_err(
                "owning_domain is required for DataspaceRestricted balances",
            ));
        }
        let spec = numeric_spec_from_optional_scale(scale)?;
        let mut new_asset = AssetDefinition::new(
            definition_id,
            name.to_owned(),
            spec,
            parsed_balance_scope_policy,
            owning_domain,
        );
        if let Some(description) = description {
            new_asset = new_asset.with_description(Some(description.to_owned()));
        }
        if let Some(alias) = alias {
            let alias = alias.parse::<AssetDefinitionAlias>().map_err(|err| {
                PyValueError::new_err(format!("invalid asset definition alias `{alias}`: {err}"))
            })?;
            new_asset = new_asset.with_alias(Some(alias));
        }
        if let Some(meta) = metadata {
            let metadata = py_to_metadata(py, Some(meta))?;
            new_asset = new_asset.with_metadata(metadata);
        }
        let mintable_mode = parse_mintable(mintable)?;
        new_asset = match mintable_mode {
            Mintable::Infinitely => new_asset,
            Mintable::Once => new_asset.mintable_once(),
            Mintable::Limited(tokens) => new_asset.mintable_limited(tokens),
            Mintable::Not => new_asset.with_mintable(Mintable::Not),
        };
        let instruction = Register::<AssetDefinition>::asset_definition(new_asset);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (definition_id, *, dataspace_id, balance_scope_policy, name, description=None, alias=None, scale=None, mintable=None, metadata=None))]
    #[allow(clippy::too_many_arguments)] // PyO3 signature mirrors the Python surface and requires explicit keyword params
    fn register_dataspace_asset_definition<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        definition_id: &str,
        dataspace_id: &Bound<'py, PyAny>,
        balance_scope_policy: &str,
        name: &str,
        description: Option<&str>,
        alias: Option<&str>,
        scale: Option<u32>,
        mintable: Option<&str>,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        if dataspace_id.is_instance_of::<PyBool>()
            || !dataspace_id.is_instance_of::<pyo3::types::PyInt>()
        {
            return Err(PyTypeError::new_err(
                "dataspace_id must be an exact integer",
            ));
        }
        let dataspace_id = dataspace_id
            .extract::<u64>()
            .map_err(|_| PyValueError::new_err("dataspace_id must be a nonzero u64"))?;
        if dataspace_id == 0 {
            return Err(PyValueError::new_err("dataspace_id must be a nonzero u64"));
        }
        let definition_id: AssetDefinitionId = definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{definition_id}`: {err}"
            ))
        })?;
        let parsed_balance_scope_policy = parse_balance_scope_policy(balance_scope_policy)?;
        validate_asset_name(name).map_err(|err| {
            PyValueError::new_err(format!("invalid asset definition name `{name}`: {err}"))
        })?;
        let spec = numeric_spec_from_optional_scale(scale)?;
        let mut new_asset = AssetDefinition::new(
            definition_id,
            name.to_owned(),
            spec,
            parsed_balance_scope_policy,
            None,
        );
        if let Some(description) = description {
            new_asset = new_asset.with_description(Some(description.to_owned()));
        }
        if let Some(alias) = alias {
            let alias = alias.parse::<AssetDefinitionAlias>().map_err(|err| {
                PyValueError::new_err(format!("invalid asset definition alias `{alias}`: {err}"))
            })?;
            new_asset = new_asset.with_alias(Some(alias));
        }
        if let Some(meta) = metadata {
            let metadata = py_to_metadata(py, Some(meta))?;
            new_asset = new_asset.with_metadata(metadata);
        }
        let mintable_mode = parse_mintable(mintable)?;
        new_asset = match mintable_mode {
            Mintable::Infinitely => new_asset,
            Mintable::Once => new_asset.mintable_once(),
            Mintable::Limited(tokens) => new_asset.mintable_limited(tokens),
            Mintable::Not => new_asset.with_mintable(Mintable::Not),
        };
        let instruction = iroha_data_model::isi::RegisterDataspaceAssetDefinition::new(
            DataSpaceId::new(dataspace_id),
            new_asset,
        )
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (asset_definition_id, *, vk_unshield=None))]
    fn register_zk_asset<'py>(
        _cls: &Bound<'py, PyType>,
        asset_definition_id: &str,
        vk_unshield: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let asset: AssetDefinitionId = asset_definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{asset_definition_id}`: {err}"
            ))
        })?;
        let vk_unshield = parse_verifying_key_id_py(vk_unshield, "vk_unshield")?;
        let instruction = RegisterZkAsset::new(asset, vk_unshield);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (proof))]
    fn verify_proof<'py>(_cls: &Bound<'py, PyType>, proof: &Bound<'py, PyAny>) -> PyResult<Self> {
        let instruction = VerifyProof::new(parse_zk_proof_attachment(proof, "proof")?);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn mint_asset_quantity(
        _cls: &Bound<'_, PyType>,
        asset_id: &str,
        quantity: &str,
    ) -> PyResult<Self> {
        let asset_id = parse_asset_id(asset_id)?;
        let quantity = parse_asset_quantity(quantity, "asset quantity")?;
        let instruction = Mint::asset_quantity(quantity, asset_id);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn burn_asset_quantity(
        _cls: &Bound<'_, PyType>,
        asset_id: &str,
        quantity: &str,
    ) -> PyResult<Self> {
        let asset_id = parse_asset_id(asset_id)?;
        let quantity = parse_asset_quantity(quantity, "asset quantity")?;
        let instruction = Burn::asset_quantity(quantity, asset_id);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn transfer_asset_quantity(
        _cls: &Bound<'_, PyType>,
        asset_id: &str,
        quantity: &str,
        destination: &str,
    ) -> PyResult<Self> {
        let asset_id = parse_asset_id(asset_id)?;
        let destination: AccountId = parse_account_id(destination)?;
        let quantity = parse_asset_quantity(quantity, "asset quantity")?;
        let instruction = Transfer::asset_quantity(asset_id, quantity, destination);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (source_account, asset_definition_id, payments_json, *, mode="Independent"))]
    fn transfer_asset_batch(
        _cls: &Bound<'_, PyType>,
        source_account: &str,
        asset_definition_id: &str,
        payments_json: &str,
        mode: &str,
    ) -> PyResult<Self> {
        let source = parse_account_id(source_account)?;
        let asset_definition: AssetDefinitionId = asset_definition_id.parse().map_err(|error| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{asset_definition_id}`: {error}"
            ))
        })?;
        let entries =
            parse_transfer_asset_batch_entries(payments_json, &source, &asset_definition)?;
        let mode = match mode {
            "Atomic" | "atomic" => BatchMode::Atomic,
            "Independent" | "independent" => BatchMode::Independent,
            _ => {
                return Err(PyValueError::new_err(
                    "batch mode must be Atomic or Independent",
                ));
            }
        };
        Ok(Instruction::new(
            TransferAssetBatch::new(entries).with_mode(mode).into(),
        ))
    }
    #[classmethod]
    #[pyo3(signature = (account_id, asset_definition_id, expected_revision, incoming, outgoing, *, reason=None))]
    fn set_asset_transfer_availability(
        _cls: &Bound<'_, PyType>,
        account_id: &str,
        asset_definition_id: &str,
        expected_revision: u64,
        incoming: &str,
        outgoing: &str,
        reason: Option<String>,
    ) -> PyResult<Self> {
        let account_id = parse_account_id(account_id)?;
        let asset_definition_id: AssetDefinitionId =
            asset_definition_id.parse().map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid asset definition id `{asset_definition_id}`: {error}"
                ))
            })?;
        iroha_data_model::asset::validate_asset_transfer_availability_reason(reason.as_deref())
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        let parse_availability = |value: &str, field: &str| match value {
            "Enabled" => Ok(AssetTransferAvailability::Enabled),
            "Disabled" => Ok(AssetTransferAvailability::Disabled),
            _ => Err(PyValueError::new_err(format!(
                "{field} must be Enabled or Disabled"
            ))),
        };
        let incoming = parse_availability(incoming, "incoming")?;
        let outgoing = parse_availability(outgoing, "outgoing")?;
        Ok(Instruction::new(
            SetAssetTransferAvailability::new(
                account_id,
                asset_definition_id,
                expected_revision,
                incoming,
                outgoing,
                reason,
            )
            .into(),
        ))
    }
    #[classmethod]
    fn set_asset_transfer_blacklist(
        _cls: &Bound<'_, PyType>,
        account_id: &str,
        asset_definition_id: &str,
        blacklisted: bool,
    ) -> PyResult<Self> {
        let account_id = parse_account_id(account_id)?;
        let asset_definition_id: AssetDefinitionId =
            asset_definition_id.parse().map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid asset definition id `{asset_definition_id}`: {error}"
                ))
            })?;
        Ok(Instruction::new(
            SetAssetTransferBlacklist::new(account_id, asset_definition_id, blacklisted).into(),
        ))
    }
    #[classmethod]
    fn set_asset_transfer_control(
        _cls: &Bound<'_, PyType>,
        account_id: &str,
        asset_definition_id: &str,
        limits: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let account_id = parse_account_id(account_id)?;
        let asset_definition_id: AssetDefinitionId =
            asset_definition_id.parse().map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid asset definition id `{asset_definition_id}`: {error}"
                ))
            })?;
        Ok(Instruction::new(
            SetAssetTransferControl::new(
                account_id,
                asset_definition_id,
                parse_asset_transfer_limits(limits)?,
            )
            .into(),
        ))
    }
    #[classmethod]
    fn set_asset_holding_limit(
        _cls: &Bound<'_, PyType>,
        account_id: &str,
        asset_definition_id: &str,
        holding_limit: Option<&str>,
    ) -> PyResult<Self> {
        let account_id = parse_account_id(account_id)?;
        let asset_definition_id: AssetDefinitionId =
            asset_definition_id.parse().map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid asset definition id `{asset_definition_id}`: {error}"
                ))
            })?;
        let holding_limit = holding_limit
            .map(|value| parse_typed_quantity(value, "asset holding limit"))
            .transpose()?;
        Ok(Instruction::new(
            SetAssetHoldingLimit::new(account_id, asset_definition_id, holding_limit).into(),
        ))
    }
    #[classmethod]
    #[pyo3(signature = (escrow_id, asset_definition_id, destination, amount, *, release_authority=None, expires_at_ms=None, evidence_hashes=None))]
    #[allow(clippy::too_many_arguments)]
    fn open_asset_lock<'py>(
        _cls: &Bound<'py, PyType>,
        escrow_id: &str,
        asset_definition_id: &str,
        destination: &str,
        amount: &str,
        release_authority: Option<&str>,
        expires_at_ms: Option<u64>,
        evidence_hashes: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let escrow_id = parse_escrow_id(escrow_id, "escrow_id")?;
        let asset_definition: AssetDefinitionId = asset_definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{asset_definition_id}`: {err}"
            ))
        })?;
        let destination = parse_account_id(destination)?;
        let release_authority = match release_authority {
            Some(value) => {
                let account = parse_account_id(value)?;
                Some(account)
            }
            None => None,
        };
        let amount = parse_typed_quantity(amount, "asset lock amount")?;
        let evidence_hashes = parse_optional_hashes(evidence_hashes, "evidence_hashes")?;
        let instruction = OpenAssetLock::with_options(
            escrow_id,
            asset_definition,
            destination,
            amount,
            release_authority,
            expires_at_ms,
            evidence_hashes,
        );
        Ok(Instruction::new(instruction.into()))
    }
    /// Open an ordered, all-of conditional escrow with an immutable on-chain policy.
    #[classmethod]
    #[pyo3(signature = (escrow_id, asset_definition_id, beneficiary, amount, conditions, expires_at_ms, *, evidence_digests=None))]
    #[allow(clippy::too_many_arguments)]
    fn open_conditional_escrow<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        escrow_id: &str,
        asset_definition_id: &str,
        beneficiary: &str,
        amount: &str,
        conditions: &Bound<'py, PyAny>,
        expires_at_ms: u64,
        evidence_digests: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        if expires_at_ms == 0 {
            return Err(PyValueError::new_err(
                "conditional escrow expires_at_ms must be greater than zero",
            ));
        }
        let escrow_id = parse_escrow_id(escrow_id, "escrow_id")?;
        let asset_definition: AssetDefinitionId = asset_definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{asset_definition_id}`: {err}"
            ))
        })?;
        let beneficiary = parse_account_id(beneficiary)?;
        let amount = parse_typed_quantity(amount, "conditional escrow amount")?;
        if amount.is_zero() {
            return Err(PyValueError::new_err(
                "conditional escrow amount must be positive",
            ));
        }
        let conditions: Vec<ConditionalEscrowCondition> =
            py_to_json_model(py, conditions, "conditional escrow conditions")?;
        if conditions.is_empty() {
            return Err(PyValueError::new_err(
                "conditional escrow conditions must not be empty",
            ));
        }
        let evidence_hashes =
            parse_optional_conditional_evidence_digests(evidence_digests, "evidence_digests")?;
        let instruction = OpenConditionalEscrow::with_evidence_hashes(
            escrow_id,
            asset_definition,
            beneficiary,
            amount,
            conditions,
            expires_at_ms,
            evidence_hashes,
        );
        Ok(Instruction::new(instruction.into()))
    }
    /// Attest the next ordered predicate in a native conditional escrow.
    #[classmethod]
    #[pyo3(signature = (escrow_id, condition_id, value, *, evidence_digest=None))]
    fn attest_escrow_condition<'py>(
        _cls: &Bound<'py, PyType>,
        py: Python<'py>,
        escrow_id: &str,
        condition_id: &str,
        value: &Bound<'py, PyAny>,
        evidence_digest: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let condition_id: Name = condition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid conditional escrow condition_id `{condition_id}`: {err}"
            ))
        })?;
        let value: ConditionalEscrowValue =
            py_to_json_model(py, value, "conditional escrow attestation value")?;
        let evidence_hash =
            parse_optional_conditional_evidence_digest(evidence_digest, "evidence_digest")?;
        Ok(Instruction::new(
            AttestEscrowCondition::new(
                parse_escrow_id(escrow_id, "escrow_id")?,
                condition_id,
                value,
                evidence_hash,
            )
            .into(),
        ))
    }
    /// Expire and refund a native conditional escrow after its authoritative deadline.
    #[classmethod]
    fn expire_conditional_escrow(_cls: &Bound<'_, PyType>, escrow_id: &str) -> PyResult<Self> {
        Ok(Instruction::new(
            ExpireConditionalEscrow::new(parse_escrow_id(escrow_id, "escrow_id")?).into(),
        ))
    }
    #[classmethod]
    fn drawdown_asset_lock(
        _cls: &Bound<'_, PyType>,
        escrow_id: &str,
        amount: &str,
        expected_remaining_amount: &str,
    ) -> PyResult<Self> {
        let instruction = DrawdownAssetLock::new(
            parse_escrow_id(escrow_id, "escrow_id")?,
            parse_typed_quantity(amount, "asset lock amount")?,
            parse_typed_quantity(
                expected_remaining_amount,
                "asset lock expected remaining amount",
            )?,
        );
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn cancel_asset_lock(
        _cls: &Bound<'_, PyType>,
        escrow_id: &str,
        expected_remaining_amount: &str,
    ) -> PyResult<Self> {
        let expected_remaining_amount = parse_typed_quantity(
            expected_remaining_amount,
            "asset lock expected remaining amount",
        )?;
        if expected_remaining_amount.is_zero() {
            return Err(PyValueError::new_err(
                "asset lock expected remaining amount must be positive",
            ));
        }
        let instruction = CancelAssetLock::new(
            parse_escrow_id(escrow_id, "escrow_id")?,
            expected_remaining_amount,
        );
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn expire_asset_lock(_cls: &Bound<'_, PyType>, escrow_id: &str) -> PyResult<Self> {
        let instruction = ExpireAssetLock::new(parse_escrow_id(escrow_id, "escrow_id")?);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (destination, name, *, payload=None))]
    fn grant_account_permission<'py>(
        cls: &Bound<'py, PyType>,
        destination: &str,
        name: &str,
        payload: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let destination: AccountId = parse_account_id(destination)?;
        let permission_name: Ident = name.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid permission name `{name}`: {err}"))
        })?;
        let payload = py_to_json_value(cls.py(), payload)?;
        let permission = Permission::new(permission_name, payload);
        let instruction = Grant::account_permission(permission, destination);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (destination, name, *, payload=None))]
    fn revoke_account_permission<'py>(
        cls: &Bound<'py, PyType>,
        destination: &str,
        name: &str,
        payload: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let destination: AccountId = parse_account_id(destination)?;
        let permission_name: Ident = name.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid permission name `{name}`: {err}"))
        })?;
        let payload = py_to_json_value(cls.py(), payload)?;
        let permission = Permission::new(permission_name, payload);
        let instruction = Revoke::account_permission(permission, destination);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (account_id, key, value=None))]
    fn set_account_key_value<'py>(
        cls: &Bound<'py, PyType>,
        account_id: &str,
        key: &str,
        value: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let account_id = parse_account_id(account_id)?;
        let key: Name = key
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid metadata key `{key}`: {err}")))?;
        let json_value = py_to_json_value(cls.py(), value)?;
        let instruction = SetKeyValue::account(account_id, key, json_value);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn remove_account_key_value(
        _cls: &Bound<'_, PyType>,
        account_id: &str,
        key: &str,
    ) -> PyResult<Self> {
        let account_id = parse_account_id(account_id)?;
        let key: Name = key
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid metadata key `{key}`: {err}")))?;
        let instruction = RemoveKeyValue::account(account_id, key);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn register_rwa<'py>(cls: &Bound<'py, PyType>, rwa: &Bound<'py, PyAny>) -> PyResult<Self> {
        let rwa = parse_new_rwa_payload(cls.py(), rwa)?;
        let instruction = iroha_data_model::isi::rwa::RegisterRwa { rwa };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn merge_rwas<'py>(cls: &Bound<'py, PyType>, merge: &Bound<'py, PyAny>) -> PyResult<Self> {
        let instruction = parse_merge_rwas_payload(cls.py(), merge)?;
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (agreement_id, initiator, counterparty, *, custodian=None, cash_leg, collateral_leg, rate_bps, maturity_timestamp_ms, governance))]
    #[allow(clippy::too_many_arguments)]
    fn repo_initiate<'py>(
        cls: &Bound<'py, PyType>,
        agreement_id: &str,
        initiator: &str,
        counterparty: &str,
        custodian: Option<&str>,
        cash_leg: &Bound<'py, PyAny>,
        collateral_leg: &Bound<'py, PyAny>,
        rate_bps: u16,
        maturity_timestamp_ms: u64,
        governance: &Bound<'py, PyAny>,
    ) -> PyResult<Self> {
        let agreement_id = RepoAgreementId::from_str(agreement_id).map_err(|err| {
            PyValueError::new_err(format!("invalid repo agreement id `{agreement_id}`: {err}"))
        })?;
        let initiator = parse_account_id(initiator)?;
        let counterparty = parse_account_id(counterparty)?;
        let custodian = match custodian {
            Some(value) => {
                let account = parse_account_id(value)?;
                Some(account)
            }
            None => None,
        };
        let py = cls.py();
        let cash_leg = parse_repo_cash_leg(py, cash_leg)?;
        let collateral_leg = parse_repo_collateral_leg(py, collateral_leg)?;
        let governance = parse_repo_governance(governance)?;
        let instruction = RepoIsi::new(
            agreement_id,
            initiator,
            counterparty,
            custodian,
            cash_leg,
            collateral_leg,
            rate_bps,
            maturity_timestamp_ms,
            governance,
        );
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (agreement_id))]
    fn repo_unwind(_cls: &Bound<'_, PyType>, agreement_id: &str) -> PyResult<Self> {
        let agreement_id = RepoAgreementId::from_str(agreement_id).map_err(|err| {
            PyValueError::new_err(format!("invalid repo agreement id `{agreement_id}`: {err}"))
        })?;
        let instruction = ReverseRepoIsi::new(agreement_id);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn repo_margin_call(_cls: &Bound<'_, PyType>, agreement_id: &str) -> PyResult<Self> {
        let agreement_id = RepoAgreementId::from_str(agreement_id).map_err(|err| {
            PyValueError::new_err(format!("invalid repo agreement id `{agreement_id}`: {err}"))
        })?;
        let instruction = RepoMarginCallIsi::new(agreement_id);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (settlement_id, delivery_leg, payment_leg, *, order="delivery_then_payment", atomicity="all_or_nothing", metadata=None))]
    #[allow(clippy::too_many_arguments)]
    fn settlement_dvp<'py>(
        cls: &Bound<'py, PyType>,
        settlement_id: &str,
        delivery_leg: &Bound<'py, PyAny>,
        payment_leg: &Bound<'py, PyAny>,
        order: &str,
        atomicity: &str,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let settlement_id = SettlementId::from_str(settlement_id).map_err(|err| {
            PyValueError::new_err(format!("invalid settlement id `{settlement_id}`: {err}"))
        })?;
        let py = cls.py();
        let delivery_leg = parse_settlement_leg(py, delivery_leg, "delivery_leg")?;
        let payment_leg = parse_settlement_leg(py, payment_leg, "payment_leg")?;
        if settlement_id.owner() != delivery_leg.from()
            && settlement_id.owner() != payment_leg.from()
        {
            return Err(PyValueError::new_err(
                "settlement identity owner must authorize an actual debit",
            ));
        }
        let order = parse_settlement_order(order)?;
        let atomicity = parse_settlement_atomicity(atomicity)?;
        let plan = SettlementPlan::new(order, atomicity);
        let metadata = match metadata {
            Some(value) => py_to_metadata(py, Some(value))?,
            None => Metadata::default(),
        };
        let instruction = DvpIsi {
            settlement_id,
            delivery_leg,
            payment_leg,
            plan,
            metadata,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (settlement_id, primary_leg, counter_leg, *, order="delivery_then_payment", atomicity="all_or_nothing", metadata=None))]
    #[allow(clippy::too_many_arguments)]
    fn settlement_pvp<'py>(
        cls: &Bound<'py, PyType>,
        settlement_id: &str,
        primary_leg: &Bound<'py, PyAny>,
        counter_leg: &Bound<'py, PyAny>,
        order: &str,
        atomicity: &str,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let settlement_id = SettlementId::from_str(settlement_id).map_err(|err| {
            PyValueError::new_err(format!("invalid settlement id `{settlement_id}`: {err}"))
        })?;
        let py = cls.py();
        let primary_leg = parse_settlement_leg(py, primary_leg, "primary_leg")?;
        let counter_leg = parse_settlement_leg(py, counter_leg, "counter_leg")?;
        if settlement_id.owner() != primary_leg.from()
            && settlement_id.owner() != counter_leg.from()
        {
            return Err(PyValueError::new_err(
                "settlement identity owner must authorize an actual debit",
            ));
        }
        let order = parse_settlement_order(order)?;
        let atomicity = parse_settlement_atomicity(atomicity)?;
        let plan = SettlementPlan::new(order, atomicity);
        let metadata = match metadata {
            Some(value) => py_to_metadata(py, Some(value))?,
            None => Metadata::default(),
        };
        let instruction = PvpIsi {
            settlement_id,
            primary_leg,
            counter_leg,
            plan,
            metadata,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn transfer_domain(
        _cls: &Bound<'_, PyType>,
        source: &str,
        domain_id: &str,
        destination: &str,
    ) -> PyResult<Self> {
        let source = parse_account_id(source)?;
        let destination = parse_account_id(destination)?;
        let domain_id = DomainId::parse_fully_qualified(domain_id).map_err(|err| {
            PyValueError::new_err(format!("invalid domain id `{domain_id}`: {err}"))
        })?;
        let instruction = Transfer::domain(source, domain_id, destination);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn transfer_asset_definition(
        _cls: &Bound<'_, PyType>,
        source: &str,
        definition_id: &str,
        destination: &str,
    ) -> PyResult<Self> {
        let source = parse_account_id(source)?;
        let destination = parse_account_id(destination)?;
        let definition_id: AssetDefinitionId = definition_id.parse().map_err(|err| {
            PyValueError::new_err(format!(
                "invalid asset definition id `{definition_id}`: {err}"
            ))
        })?;
        let instruction = Transfer::asset_definition(source, definition_id, destination);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn transfer_nft(
        _cls: &Bound<'_, PyType>,
        source: &str,
        nft_id: &str,
        destination: &str,
    ) -> PyResult<Self> {
        let source = parse_account_id(source)?;
        let destination = parse_account_id(destination)?;
        let nft_id: NftId = nft_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid NFT id `{nft_id}`: {err}")))?;
        let instruction = Transfer::nft(source, nft_id, destination);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn transfer_rwa(
        _cls: &Bound<'_, PyType>,
        source: &str,
        rwa_id: &str,
        quantity: &str,
        destination: &str,
    ) -> PyResult<Self> {
        let source = parse_account_id(source)?;
        let destination = parse_account_id(destination)?;
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let quantity = parse_typed_quantity(quantity, "RWA transfer quantity")?;
        let instruction = iroha_data_model::isi::rwa::TransferRwa {
            source,
            rwa: rwa_id,
            quantity,
            destination,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn redeem_rwa(_cls: &Bound<'_, PyType>, rwa_id: &str, quantity: &str) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let quantity = parse_typed_quantity(quantity, "RWA redeem quantity")?;
        let instruction = iroha_data_model::isi::rwa::RedeemRwa {
            rwa: rwa_id,
            quantity,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn freeze_rwa(_cls: &Bound<'_, PyType>, rwa_id: &str) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let instruction = iroha_data_model::isi::rwa::FreezeRwa { rwa: rwa_id };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn unfreeze_rwa(_cls: &Bound<'_, PyType>, rwa_id: &str) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let instruction = iroha_data_model::isi::rwa::UnfreezeRwa { rwa: rwa_id };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn hold_rwa(_cls: &Bound<'_, PyType>, rwa_id: &str, quantity: &str) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let quantity = parse_typed_quantity(quantity, "RWA hold quantity")?;
        let instruction = iroha_data_model::isi::rwa::HoldRwa {
            rwa: rwa_id,
            quantity,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn release_rwa(_cls: &Bound<'_, PyType>, rwa_id: &str, quantity: &str) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let quantity = parse_typed_quantity(quantity, "RWA release quantity")?;
        let instruction = iroha_data_model::isi::rwa::ReleaseRwa {
            rwa: rwa_id,
            quantity,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn force_transfer_rwa(
        _cls: &Bound<'_, PyType>,
        rwa_id: &str,
        quantity: &str,
        destination: &str,
    ) -> PyResult<Self> {
        let destination = parse_account_id(destination)?;
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let quantity = parse_typed_quantity(quantity, "RWA force-transfer quantity")?;
        let instruction = iroha_data_model::isi::rwa::ForceTransferRwa {
            rwa: rwa_id,
            quantity,
            destination,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn set_rwa_controls<'py>(
        cls: &Bound<'py, PyType>,
        rwa_id: &str,
        controls: &Bound<'py, PyAny>,
    ) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let controls = py_to_json_model::<RwaControlPolicy>(cls.py(), controls, "controls")?;
        let instruction = iroha_data_model::isi::rwa::SetRwaControls {
            rwa: rwa_id,
            controls,
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (rwa_id, key, value=None))]
    fn set_rwa_key_value<'py>(
        cls: &Bound<'py, PyType>,
        rwa_id: &str,
        key: &str,
        value: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let key: Name = key
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid metadata key `{key}`: {err}")))?;
        let json_value = py_to_json_value(cls.py(), value)?;
        let instruction = SetKeyValue::rwa(rwa_id, key, json_value);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn remove_rwa_key_value(_cls: &Bound<'_, PyType>, rwa_id: &str, key: &str) -> PyResult<Self> {
        let rwa_id: RwaId = rwa_id
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid RWA id `{rwa_id}`: {err}")))?;
        let key: Name = key
            .parse()
            .map_err(|err| PyValueError::new_err(format!("invalid metadata key `{key}`: {err}")))?;
        let instruction = RemoveKeyValue::rwa(rwa_id, key);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (trigger_id, authority, instructions, *, start_ms, **kwargs))]
    fn register_time_trigger<'py>(
        cls: &Bound<'py, PyType>,
        trigger_id: &str,
        authority: &str,
        instructions: Vec<Bound<'py, Instruction>>,
        start_ms: u64,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Self> {
        if instructions.is_empty() {
            return Err(PyValueError::new_err(
                "time trigger requires at least one instruction",
            ));
        }
        let trigger_id: TriggerId = trigger_id.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid trigger id `{trigger_id}`: {err}"))
        })?;
        let authority = parse_account_id(authority)?;
        if start_ms == 0 {
            return Err(PyValueError::new_err("start_ms must be greater than zero"));
        }
        let py = cls.py();
        let TimeTriggerKwargsParsed {
            period_ms,
            repeats: repeats_kwarg,
            metadata: metadata_obj,
        } = parse_time_trigger_kwargs(kwargs)?;
        let mut schedule = TimeSchedule::starting_at(Duration::from_millis(start_ms));
        if let Some(period_ms) = period_ms {
            if period_ms == 0 {
                return Err(PyValueError::new_err("period_ms must be greater than zero"));
            }
            schedule = schedule.with_period(Duration::from_millis(period_ms));
        }
        let repeats = match repeats_kwarg {
            Some(0) => {
                return Err(PyValueError::new_err(
                    "repeats must be greater than zero when provided",
                ));
            }
            Some(value) => Repeats::Exactly(value),
            None => Repeats::Indefinitely,
        };
        let metadata = py_to_metadata(py, metadata_obj.as_ref())?;
        let mut instruction_boxes = Vec::with_capacity(instructions.len());
        for instr in instructions {
            let instruction = instr.borrow();
            instruction_boxes.push(instruction.inner.clone());
        }
        let executable = Executable::from(instruction_boxes);
        let action = TriggerAction::new(
            executable,
            repeats,
            authority.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
        )
        .map_err(|error| PyValueError::new_err(error.to_string()))?
        .with_metadata(metadata);
        let trigger = Trigger::new(trigger_id, action);
        let instruction = Register::trigger(trigger);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (trigger_id, authority, instructions, *, repeats=None, metadata=None))]
    fn register_precommit_trigger<'py>(
        cls: &Bound<'py, PyType>,
        trigger_id: &str,
        authority: &str,
        instructions: Vec<Bound<'py, Instruction>>,
        repeats: Option<u32>,
        metadata: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        if instructions.is_empty() {
            return Err(PyValueError::new_err(
                "pre-commit trigger requires at least one instruction",
            ));
        }
        let trigger_id: TriggerId = trigger_id.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid trigger id `{trigger_id}`: {err}"))
        })?;
        let authority = parse_account_id(authority)?;
        let repeats = match repeats {
            Some(0) => {
                return Err(PyValueError::new_err(
                    "repeats must be greater than zero when provided",
                ));
            }
            Some(value) => Repeats::Exactly(value),
            None => Repeats::Indefinitely,
        };
        let py = cls.py();
        let metadata = py_to_metadata(py, metadata)?;
        let mut instruction_boxes = Vec::with_capacity(instructions.len());
        for instr in instructions {
            let instruction = instr.borrow();
            instruction_boxes.push(instruction.inner.clone());
        }
        let executable = Executable::from(instruction_boxes);
        let action = TriggerAction::new(
            executable,
            repeats,
            authority.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )
        .map_err(|error| PyValueError::new_err(error.to_string()))?
        .with_metadata(metadata);
        let trigger = Trigger::new(trigger_id, action);
        let instruction = Register::trigger(trigger);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    #[pyo3(signature = (trigger_id, *, args=None))]
    fn execute_trigger<'py>(
        cls: &Bound<'py, PyType>,
        trigger_id: &str,
        args: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let trigger_id: TriggerId = trigger_id.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid trigger id `{trigger_id}`: {err}"))
        })?;
        let instruction = ExecuteTrigger::new(trigger_id);
        let py = cls.py();
        let instruction = match args {
            None => instruction,
            Some(payload) => {
                let json_value = py_to_json_value(py, Some(payload))?;
                instruction.with_args(json_value)
            }
        };
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn unregister_trigger(_cls: &Bound<'_, PyType>, trigger_id: &str) -> PyResult<Self> {
        let trigger_id: TriggerId = trigger_id.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid trigger id `{trigger_id}`: {err}"))
        })?;
        let instruction = Unregister::trigger(trigger_id);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn mint_trigger_repetitions(
        _cls: &Bound<'_, PyType>,
        trigger_id: &str,
        repetitions: u32,
    ) -> PyResult<Self> {
        if repetitions == 0 {
            return Err(PyValueError::new_err(
                "repetitions must be greater than zero",
            ));
        }
        let trigger_id: TriggerId = trigger_id.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid trigger id `{trigger_id}`: {err}"))
        })?;
        let instruction = Mint::trigger_repetitions(repetitions, trigger_id);
        Ok(Instruction::new(instruction.into()))
    }
    #[classmethod]
    fn burn_trigger_repetitions(
        _cls: &Bound<'_, PyType>,
        trigger_id: &str,
        repetitions: u32,
    ) -> PyResult<Self> {
        if repetitions == 0 {
            return Err(PyValueError::new_err(
                "repetitions must be greater than zero",
            ));
        }
        let trigger_id: TriggerId = trigger_id.parse().map_err(|err| {
            PyValueError::new_err(format!("invalid trigger id `{trigger_id}`: {err}"))
        })?;
        let instruction = Burn::trigger_repetitions(repetitions, trigger_id);
        Ok(Instruction::new(instruction.into()))
    }
    fn __copy__(&self) -> Self {
        self.clone()
    }
    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> Self {
        self.clone()
    }
}
fn python_zk_x509_statement_archive_v1(
    canonical_statement_archive: &[u8],
) -> PyResult<IrohaZkX509StarkP256StatementV1> {
    let maximum = crate::privacy_native_actions::PRIVACY_ZK_X509_MAX_STATEMENT_ARCHIVE_BYTES_V1;
    if canonical_statement_archive.is_empty() || canonical_statement_archive.len() > maximum {
        return Err(PyValueError::new_err(format!(
            "canonical_statement_archive must contain between 1 and {maximum} bytes"
        )));
    }
    norito::decode_canonical::<IrohaZkX509StarkP256StatementV1>(canonical_statement_archive)
        .map_err(|_| {
            PyValueError::new_err(
                "canonical_statement_archive is not the exact canonical ZK-X509 statement wire",
            )
        })
}
#[derive(Clone)]
struct PythonPrivacyActionTransactionContextV1 {
    network_id: NetworkId,
    authority: AccountId,
    creation_time: Duration,
    time_to_live: Option<Duration>,
    nonce: Option<NonZeroU32>,
    fee_payment: FeePaymentIntent,
    metadata: Metadata,
}
fn python_compiled_privacy_profile_v1(
    protocol_id: PrivacyProtocolIdV1,
    protocol_label: &str,
) -> PyResult<CompiledPrivacyProfileV1> {
    compiled_privacy_profile_v1(protocol_id).map_err(|error| {
        PyRuntimeError::new_err(format!(
            "compiled {protocol_label} privacy profile is unavailable: {error}"
        ))
    })
}
fn python_nonzero_privacy_digest_v1(value: &[u8], field: &str) -> PyResult<[u8; 32]> {
    let digest = fixed_array::<32>(value, field)?;
    if digest == [0; 32] {
        return Err(PyValueError::new_err(format!(
            "{field} must not be the all-zero sentinel"
        )));
    }
    Ok(digest)
}
fn python_bind_vega_device_authentication_digest_v1(
    mut statement: VegaExistingCredentialStatementV1,
    canonical_genesis_hash: [u8; 32],
) -> PyResult<VegaExistingCredentialStatementV1> {
    let digest = {
        let binding =
            VegaMdlConsensusBindingV1::from_context(&statement.context, canonical_genesis_hash);
        derive_device_authentication_digest_v1(&statement, &binding).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid Vega public device-authentication statement: {error}"
            ))
        })?
    };
    statement.device_authentication_digest = digest;
    Ok(statement)
}
#[expect(
    clippy::too_many_arguments,
    reason = "explicit consensus statement fields"
)]
fn python_vega_statement_v1(
    context: PrivacyStatementContextV1,
    canonical_genesis_hash: [u8; 32],
    issuer_id: [u8; 32],
    issuer_record_epoch: u64,
    issuer_record_digest: [u8; 32],
    issuer_public_key: [u8; 33],
    presentation_year: u16,
    presentation_month: u8,
    presentation_day: u8,
    minimum_age_years: u8,
    reader_challenge: [u8; 32],
    session_transcript_digest: [u8; 32],
) -> PyResult<VegaExistingCredentialStatementV1> {
    python_bind_vega_device_authentication_digest_v1(
        VegaExistingCredentialStatementV1 {
            context,
            issuer_id: PrivacyIssuerIdV1::new(issuer_id),
            issuer_record_epoch,
            issuer_record_digest: PrivacyVegaIssuerRecordDigestV1::new(issuer_record_digest),
            document_type: PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
            namespace: PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
            digest_algorithm: PrivacyVegaMdlDigestAlgorithmV1::Sha256,
            issuer_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            device_authentication_algorithm: PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            issuer_public_key: PrivacyP256PointV1::new(issuer_public_key),
            device_authentication_digest: PrivacyVegaDeviceAuthenticationDigestV1::new([0; 32]),
            presentation_date: PrivacyVegaMdlDateV1 {
                year: presentation_year,
                month: presentation_month,
                day: presentation_day,
            },
            minimum_age_years,
            reader_challenge: PrivacyChallengeV1::new(reader_challenge),
            session_transcript_digest: PrivacySessionTranscriptDigestV1::new(
                session_transcript_digest,
            ),
        },
        canonical_genesis_hash,
    )
}
/// Native transaction builder with JSON instruction support.
///
/// Generic privacy proving is intentionally absent: the Rust-owned wallet
/// worker accepts an owner-only credential path and returns signed public wire.
#[pyclass(from_py_object, module = "iroha_native._crypto")]
#[derive(Clone)]
struct TransactionBuilder {
    network_id: NetworkId,
    authority: AccountId,
    fee_payment: FeePaymentIntent,
    creation_time: Option<Duration>,
    ttl: Option<Duration>,
    nonce: Option<NonZeroU32>,
    executable_items: Vec<ExecutableBatchItem>,
    explicit_batch: bool,
    metadata: Metadata,
    executable_override: Option<Executable>,
    attachments: Option<ProofAttachmentList>,
    privacy_capability_manifest:
        Option<privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1>,
}
impl TransactionBuilder {
    fn try_add_proof_attachment(&mut self, attachment: ProofAttachment) -> PyResult<()> {
        // Each staged attachment travels as one transaction-level proof
        // carrier; refuse here what the signed attachment schema refuses.
        iroha_data_model::transaction::signed_attachments::PlannedActionV1::transaction_proof(
            &attachment,
        )
        .map_err(|error| PyValueError::new_err(format!("invalid proof attachment: {error}")))?;
        match &mut self.attachments {
            Some(attachments) => attachments.try_push(attachment),
            None => ProofAttachmentList::try_from(vec![attachment]).map(|attachments| {
                self.attachments = Some(attachments);
            }),
        }
        .map_err(|error| PyValueError::new_err(format!("invalid proof attachment list: {error}")))
    }
    fn require_empty_privacy_action_builder_v1(
        &self,
        protocol_id: PrivacyProtocolIdV1,
        protocol_label: &str,
    ) -> PyResult<()> {
        if self.explicit_batch
            || !self.executable_items.is_empty()
            || self.executable_override.is_some()
            || self.attachments.is_some()
        {
            return Err(PyValueError::new_err(format!(
                "native {protocol_label} action requires an otherwise empty transaction builder"
            )));
        }
        let manifest = self.privacy_capability_manifest.as_ref().ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "native {protocol_label} construction requires a validated Torii Exact12 capability manifest"
            ))
        })?;
        manifest.require_authenticated_network(self.network_id)?;
        manifest.require_network_profile(protocol_id)?;
        Ok(())
    }
    fn privacy_action_transaction_context_v1(&self) -> PythonPrivacyActionTransactionContextV1 {
        // Resolve the default clock exactly once. Both intent construction and
        // final signing must use this same signature-bound millisecond value.
        let resolved_builder = self.to_model_builder();
        PythonPrivacyActionTransactionContextV1 {
            network_id: self.network_id,
            authority: self.authority.clone(),
            creation_time: Duration::from_millis(resolved_builder.payload().creation_time_ms),
            time_to_live: self.ttl,
            nonce: self.nonce,
            fee_payment: self.fee_payment.clone(),
            metadata: self.metadata.clone(),
        }
    }
    fn privacy_native_action_transaction_context_v1(
        &self,
    ) -> crate::privacy_native_actions::PrivacyActionTransactionContextV1 {
        let context = self.privacy_action_transaction_context_v1();
        crate::privacy_native_actions::PrivacyActionTransactionContextV1 {
            network_id: context.network_id,
            authority: context.authority,
            creation_time: context.creation_time,
            time_to_live: context.time_to_live,
            nonce: context.nonce,
            fee_payment: context.fee_payment,
            metadata: context.metadata,
        }
    }
    fn validate_privacy_action_signing_authority_v1(
        &self,
        private_key: &PrivateKey,
    ) -> PyResult<()> {
        let expected = self.authority.try_signatory().ok_or_else(|| {
            PyValueError::new_err(
                "native privacy actions require a direct single-signatory authority",
            )
        })?;
        let derived = PublicKey::from(private_key.clone());
        if expected != &derived {
            return Err(PyValueError::new_err(
                "privacy action private key does not match the transaction authority",
            ));
        }
        Ok(())
    }
    fn privacy_native_action_build_result_v1(
        &self,
        py: Python<'_>,
        signed: &crate::privacy_native_actions::SignedPrivacyActionV1,
    ) -> PyResult<PrivacyNativeActionBuildResultV1> {
        let envelope = signed_transaction_envelope_from_model_v1(signed.signed_transaction())?;
        Ok(PrivacyNativeActionBuildResultV1 {
            envelope: Py::new(py, envelope)?,
            protocol_id: signed.protocol_id().canonical_label().to_owned(),
            operation_schema:
                crate::privacy_native_actions::privacy_native_action_capability_for_protocol_v1(
                    signed.protocol_id(),
                )
                .expect("dispatcher result has a retained capability")
                .operation_schema,
            transaction_hash: signed.transaction_hash(),
            transaction_intent_digest: signed.transaction_intent_digest(),
            statement_digest: signed.statement_digest(),
            proof_envelope_hash: signed.proof_envelope_hash(),
            statement_bytes: signed.statement_bytes(),
            proof_bytes: signed.proof_bytes(),
            encoded_proof_envelope_bytes: signed.encoded_proof_envelope_bytes(),
            adaptive_signed_transaction_bytes: signed.adaptive_signed_transaction_bytes(),
            versioned_signed_transaction_bytes: signed.versioned_signed_transaction_bytes(),
        })
    }
    fn validate_executable(&self) -> PyResult<()> {
        if self.executable_override.is_some()
            && (self.explicit_batch || !self.executable_items.is_empty())
        {
            return Err(PyValueError::new_err(
                "raw IVM bytecode cannot be mixed with an executable batch",
            ));
        }
        if self.explicit_batch && self.executable_items.is_empty() {
            return Err(PyValueError::new_err(
                "executable batch requires at least one item",
            ));
        }
        if self
            .executable_items
            .iter()
            .any(|item| matches!(item, ExecutableBatchItem::ContractCall(_)))
            && self.fee_payment.gas_limit().is_none()
        {
            return Err(PyValueError::new_err(
                "contract call executable requires a transaction gas_limit",
            ));
        }
        Ok(())
    }
    fn to_model_builder(&self) -> ModelTransactionBuilder {
        let mut builder = ModelTransactionBuilder::new(
            self.network_id,
            self.authority.clone(),
            self.fee_payment.clone(),
        );
        if let Some(creation_time) = self.creation_time {
            builder.set_creation_time(creation_time);
        }
        if let Some(ttl) = self.ttl {
            builder.set_ttl(ttl);
        }
        if let Some(nonce) = self.nonce {
            builder.set_nonce(nonce);
        }
        if let Some(ref executable) = self.executable_override {
            builder = builder.with_executable(executable.clone());
        } else if self.explicit_batch {
            builder = builder.with_executable_batch(self.executable_items.clone());
        } else if !self.executable_items.is_empty() {
            builder = builder.with_instructions(self.executable_items.iter().map(|item| {
                let ExecutableBatchItem::Instruction(instruction) = item else {
                    unreachable!("contract calls always select the executable batch form")
                };
                instruction.clone()
            }));
        }
        builder = builder.with_metadata(self.metadata.clone());
        if let Some(attachments) = &self.attachments {
            // Staging validated every attachment and the list bounds are below
            // the signed attachment bounds, so the plan is complete. The
            // statement digests are bound to the payload here and admission
            // validates the result again.
            let plan = iroha_data_model::transaction::SignedAttachmentPlanV1::transaction_proofs(
                attachments.as_slice(),
            )
            .expect("staged proof attachments were validated when they were added");
            builder = builder.with_signed_attachments(plan.declare());
        }
        builder
    }
    fn envelope_from_signed(
        &self,
        signed: &SignedTransaction,
    ) -> PyResult<SignedTransactionEnvelope> {
        let signature: Signature = signed.signature().payload().clone();
        let signature_bytes = signature.payload().to_vec();
        let hash: HashOf<SignedTransaction> = signed.hash();
        let hash_bytes: [u8; Hash::LENGTH] = *hash.as_ref();
        let signed_bytes = codec::encode_adaptive(signed);
        let signed_versioned = signed.encode_versioned();
        let signatory = require_single_signatory(signed.authority(), "transaction authority")?;
        let (_, public_key_bytes) = public_key_to_bytes(signatory, "authority public key")?;
        Ok(SignedTransactionEnvelope {
            network_id: self.network_id,
            authority: self.authority.to_string(),
            signed_transaction: signed_bytes,
            signed_transaction_versioned: signed_versioned,
            hash: hash_bytes,
            signature: signature_bytes,
            public_key: public_key_bytes.to_vec(),
        })
    }
    fn clear_transaction_state(&mut self) {
        self.executable_items.clear();
        self.explicit_batch = false;
        self.executable_override = None;
        self.attachments = None;
        self.privacy_capability_manifest = None;
    }
}
#[pymethods]
impl TransactionBuilder {
    #[new]
    fn new(network_id: &PyNetworkId, authority: &str, fee_payment_json: &str) -> PyResult<Self> {
        require_non_blank_unpadded(authority, "authority")?;
        let authority = parse_account_id(authority)?;
        let fee_payment = parse_fee_payment_intent_json(fee_payment_json)?;
        let creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                PyValueError::new_err(format!("system clock precedes UNIX epoch: {err}"))
            })?;
        Ok(Self {
            network_id: network_id.inner,
            authority,
            fee_payment,
            creation_time: Some(creation_time),
            ttl: None,
            nonce: None,
            executable_items: Vec::new(),
            explicit_batch: false,
            metadata: Metadata::default(),
            executable_override: None,
            attachments: None,
            privacy_capability_manifest: None,
        })
    }
    /// Bind the exact canonical manifest fetched from authenticated Torii state.
    ///
    /// Every native privacy constructor consumes this binding and rejects a
    /// locally available profile unless its complete tuple is active and
    /// byte-for-byte equal to the committed manifest row.
    fn bind_privacy_exact12_capability_manifest_v1(
        &mut self,
        manifest: PyRef<'_, privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1>,
    ) -> PyResult<()> {
        manifest.require_authenticated_network(self.network_id)?;
        if self.privacy_capability_manifest.is_some() {
            return Err(PyValueError::new_err(
                "transaction builder already has an Exact12 capability manifest binding",
            ));
        }
        self.privacy_capability_manifest = Some(manifest.clone());
        Ok(())
    }
    /// Replace the exact signature-bound fee payment intent.
    fn set_fee_payment_json(&mut self, fee_payment_json: &str) -> PyResult<()> {
        self.fee_payment = parse_fee_payment_intent_json(fee_payment_json)?;
        Ok(())
    }
    /// Set a deterministic creation timestamp (milliseconds since UNIX epoch).
    fn set_creation_time_ms(&mut self, timestamp_ms: u64) -> PyResult<()> {
        self.creation_time = Some(Duration::from_millis(timestamp_ms));
        Ok(())
    }
    /// Set the transaction time-to-live in milliseconds.
    fn set_ttl_ms(&mut self, ttl_ms: u64) -> PyResult<()> {
        self.ttl = Some(Duration::from_millis(ttl_ms));
        Ok(())
    }
    /// Set the transaction nonce.
    fn set_nonce(&mut self, nonce: u32) -> PyResult<()> {
        let Some(nonce) = NonZeroU32::new(nonce) else {
            return Err(PyValueError::new_err("nonce must be non-zero"));
        };
        self.nonce = Some(nonce);
        Ok(())
    }
    /// Replace metadata using a Norito-compatible JSON string.
    fn set_metadata_json(&mut self, json_payload: &str) -> PyResult<()> {
        self.metadata = json::from_str::<Metadata>(json_payload)
            .map_err(|err| PyValueError::new_err(format!("invalid metadata JSON: {err}")))?;
        Ok(())
    }
    /// Replace metadata using a Python mapping (converted via `json.dumps`).
    fn set_metadata(&mut self, py: Python<'_>, metadata: &Bound<'_, PyAny>) -> PyResult<()> {
        self.metadata = py_to_metadata(py, Some(metadata))?;
        Ok(())
    }
    /// Remove all staged proof attachments.
    fn clear_attachments(&mut self) {
        self.attachments = None;
    }
    /// Add a Merkle-based lane privacy proof attachment for Nexus private lanes.
    ///
    /// `leaf` and `audit_path` entries are treated as pre-hashed 32-byte digests.
    /// The first-release witness is complete: every path level must carry a sibling.
    #[allow(clippy::too_many_arguments)]
    fn add_lane_privacy_merkle_attachment(
        &mut self,
        commitment_id: &Bound<'_, PyAny>,
        leaf: &[u8],
        leaf_index: &Bound<'_, PyAny>,
        audit_path: &Bound<'_, PyAny>,
        proof_backend: &str,
        proof_bytes: &[u8],
        verifying_key_name: &str,
    ) -> PyResult<()> {
        let commitment_id = py_exact_u16(commitment_id, "commitment_id")?;
        let leaf_index = py_exact_u32(leaf_index, "leaf_index")?;
        if leaf.len() != 32 {
            return Err(PyValueError::new_err(
                "leaf must be a 32-byte hash (pre-hashed commitment leaf)",
            ));
        }
        if !verifying_key_id_field_is_portable(proof_backend) {
            return Err(PyValueError::new_err(
                "proof_backend must use the bounded portable verifier-key registry grammar",
            ));
        }
        if !verifying_key_id_field_is_portable(verifying_key_name) {
            return Err(PyValueError::new_err(
                "verifying_key_name must use the bounded portable verifier-key registry grammar",
            ));
        }
        if proof_bytes.is_empty() {
            return Err(PyValueError::new_err("proof_bytes must be non-empty"));
        }
        let maximum_proof_bytes = proof_box_max_proof_bytes_v1(proof_backend).ok_or_else(|| {
            PyValueError::new_err(
                "proof_backend and canonical framing exceed the 64 MiB ProofBox limit",
            )
        })?;
        if proof_bytes.len() > maximum_proof_bytes {
            return Err(PyValueError::new_err(format!(
                "proof_bytes exceeds the {maximum_proof_bytes}-byte limit for this backend"
            )));
        }
        let backend = Ident::from_str(proof_backend).map_err(|err| {
            PyValueError::new_err(format!("invalid proof backend identifier: {err}"))
        })?;
        let leaf_arr: [u8; 32] = leaf
            .try_into()
            .map_err(|_| PyValueError::new_err("leaf must be exactly 32 bytes"))?;
        let audit_path = audit_path.cast::<PyList>().map_err(|_| {
            PyTypeError::new_err("audit_path must be a list of complete 32-byte siblings")
        })?;
        if audit_path.is_empty() || audit_path.len() > LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 {
            return Err(PyValueError::new_err(format!(
                "audit_path must contain between 1 and {LANE_PRIVACY_MAX_MERKLE_DEPTH_V1} siblings"
            )));
        }
        let mut audit_bytes = Vec::with_capacity(audit_path.len());
        for (index, bytes) in audit_path.iter().enumerate() {
            if bytes.is_none() {
                return Err(PyValueError::new_err(format!(
                    "audit_path[{index}] must contain a sibling"
                )));
            }
            let arr = py_exact_fixed_bytes::<32>(&bytes, &format!("audit_path[{index}]"))?;
            audit_bytes.push(Some(arr));
        }
        let privacy_proof = LanePrivacyProof::merkle_from_raw_path(
            LaneCommitmentId::new(commitment_id),
            leaf_arr,
            leaf_index,
            audit_bytes,
        )
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let mut attachment = ProofAttachment::new_ref(
            backend.clone(),
            ProofBox::new(backend.clone(), proof_bytes.to_vec()),
            VerifyingKeyId::new(backend, verifying_key_name),
        );
        attachment.lane_privacy = Some(privacy_proof);
        if let Some((field, message)) = attachment.structural_error() {
            return Err(PyValueError::new_err(format!(
                "lane privacy attachment {field} {message}"
            )));
        }
        self.try_add_proof_attachment(attachment)?;
        Ok(())
    }
    /// Add an instruction described by `norito::json` syntax.
    fn add_instruction_json(&mut self, instruction_json: &str) -> PyResult<()> {
        if self.executable_override.is_some() {
            return Err(PyValueError::new_err(
                "raw IVM bytecode cannot be mixed with executable batch items",
            ));
        }
        let instruction = json::from_str::<InstructionBox>(instruction_json)
            .map_err(|err| PyValueError::new_err(format!("invalid instruction JSON: {err}")))?;
        self.executable_items
            .push(ExecutableBatchItem::Instruction(instruction));
        Ok(())
    }
    /// Append a pre-built instruction.
    fn add_instruction(&mut self, instruction: &Instruction) -> PyResult<()> {
        if self.executable_override.is_some() {
            return Err(PyValueError::new_err(
                "raw IVM bytecode cannot be mixed with executable batch items",
            ));
        }
        self.executable_items
            .push(ExecutableBatchItem::Instruction(instruction.inner.clone()));
        Ok(())
    }
    /// Select the ordered executable-batch representation explicitly.
    ///
    /// Finalization rejects the batch until at least one instruction or contract call is added.
    fn use_executable_batch(&mut self) -> PyResult<()> {
        if self.executable_override.is_some() {
            return Err(PyValueError::new_err(
                "raw IVM bytecode cannot be mixed with an executable batch",
            ));
        }
        self.explicit_batch = true;
        Ok(())
    }
    /// Append a deployed-contract call to the ordered executable batch.
    #[pyo3(signature = (contract_address, expected_code_hash_hex, entrypoint, arguments=None))]
    fn add_contract_call(
        &mut self,
        contract_address: &str,
        expected_code_hash_hex: &str,
        entrypoint: &str,
        arguments: Option<&[u8]>,
    ) -> PyResult<()> {
        if self.executable_override.is_some() {
            return Err(PyValueError::new_err(
                "raw IVM bytecode cannot be mixed with executable batch items",
            ));
        }
        require_non_blank_unpadded(contract_address, "contract_address")?;
        require_non_blank_unpadded(expected_code_hash_hex, "expected_code_hash_hex")?;
        require_non_blank_unpadded(entrypoint, "entrypoint")?;
        let contract_address = ContractAddress::from_str(contract_address).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid contract_address `{contract_address}`: {error}"
            ))
        })?;
        let expected_code_hash = Hash::from_str(expected_code_hash_hex).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid expected_code_hash_hex `{expected_code_hash_hex}`: {error}"
            ))
        })?;
        let arguments = arguments
            .map(|bytes| ContractArgumentRecord::try_new(bytes.to_vec()))
            .transpose()
            .map_err(|error| {
                PyValueError::new_err(format!(
                    "contract arguments exceed the {MAX_CONTRACT_ARGUMENT_RECORD_BYTES}-byte limit: {error}"
                ))
            })?;
        self.executable_items
            .push(ExecutableBatchItem::ContractCall(ContractInvocation {
                contract_address,
                expected_code_hash,
                entrypoint: entrypoint.to_owned(),
                arguments,
            }));
        self.explicit_batch = true;
        Ok(())
    }
    /// Encode the canonical transaction payload bytes without signing.
    fn encode_payload<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self.validate_executable()?;
        let payload_bytes = self.to_model_builder().encode_payload();
        Ok(PyBytes::new(py, &payload_bytes))
    }
    /// Return the exact unsigned payload submitted to `/v1/fees/quote`.
    fn payload_json(&self) -> PyResult<String> {
        self.validate_executable()?;
        let payload = self
            .to_model_builder()
            .into_payload()
            .map_err(|err| PyValueError::new_err(format!("invalid transaction payload: {err}")))?;
        json::to_json(&payload)
            .map_err(|err| PyValueError::new_err(format!("encode transaction payload JSON: {err}")))
    }
    /// Return the canonical Iroha transaction payload prehash bytes.
    fn payload_hash<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self.validate_executable()?;
        let payload_hash = self.to_model_builder().payload_hash_bytes();
        Ok(PyBytes::new(py, &payload_hash))
    }
    /// Return the canonical Iroha transaction payload prehash as lowercase hex.
    fn payload_hash_hex(&self) -> PyResult<String> {
        self.validate_executable()?;
        Ok(hex_encode(self.to_model_builder().payload_hash_bytes()))
    }
    /// Override the executable with raw IVM bytecode (Norito-encoded hex string).
    fn set_bytecode_hex(&mut self, hex_payload: &str) -> PyResult<()> {
        if self.explicit_batch || !self.executable_items.is_empty() {
            return Err(PyValueError::new_err(
                "raw IVM bytecode cannot be mixed with executable batch items",
            ));
        }
        let bytes = hex::decode(hex_payload)
            .map_err(|err| PyValueError::new_err(format!("invalid hex bytecode: {err}")))?;
        let bytecode = IvmBytecode::from_compiled(bytes);
        self.executable_override = Some(Executable::Ivm(bytecode));
        Ok(())
    }
    /// Sign the transaction, returning an envelope with Norito payloads and hash.
    fn sign(&mut self, private_key: &[u8]) -> PyResult<SignedTransactionEnvelope> {
        ensure_ed25519_account(&self.authority)?;
        self.validate_executable()?;
        let private_key = parse_private_key(private_key)?;
        let signed = self
            .to_model_builder()
            .try_sign(&private_key)
            .map_err(|err| PyValueError::new_err(format!("transaction signing failed: {err}")))?;
        let envelope = self.envelope_from_signed(&signed)?;
        // Reset executable entries for the next transaction while keeping metadata.
        self.clear_transaction_state();
        Ok(envelope)
    }
    /// Derive the sole transaction intent that an isolated ZK-X509 prover worker must bind.
    ///
    /// The canonical statement archive must contain the exact public action
    /// with an all-zero transaction intent. This method performs no proving or
    /// signing and leaves the builder unchanged.
    fn prepare_privacy_zk_x509_identity_presentation_action_v1<'py>(
        &self,
        py: Python<'py>,
        canonical_statement_archive: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.require_empty_privacy_action_builder_v1(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            "ZK-X509",
        )?;
        let canonical_genesis_hash = *self.network_id.as_bytes();
        let statement = python_zk_x509_statement_archive_v1(canonical_statement_archive)?;
        let context = self.privacy_native_action_transaction_context_v1();
        let intent =
            crate::privacy_native_actions::prepare_zk_x509_identity_presentation_action_intent_v1(
                &context,
                canonical_genesis_hash,
                &statement,
            )
            .map_err(|error| {
                PyValueError::new_err(format!(
                    "native ZK-X509 action preparation failed at {}",
                    error.stage()
                ))
            })?;
        let mut resolved_statement = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement);
        resolved_statement.context_mut().transaction_intent_digest = intent;
        self.privacy_capability_manifest
            .as_ref()
            .ok_or_else(|| {
                PyRuntimeError::new_err("privacy preparation requires an admitted manifest")
            })?
            .require_governed_statement(&resolved_statement)?;
        Ok(PyBytes::new(py, intent.as_bytes()))
    }
    /// Validate and sign one canonical, intent-bound ZK-X509 identity presentation.
    ///
    /// The profile-owned worker returns only a typed public statement and its fixed-capacity `X5S1`
    /// proof. Native code authenticates their exact transaction/genesis binding before the
    /// transaction is signed. Signing remains unavailable until the production compiled profile
    /// passes every release-readiness gate.
    fn sign_privacy_zk_x509_identity_presentation_action_v1(
        &mut self,
        py: Python<'_>,
        private_key: &[u8],
        canonical_statement_archive: &[u8],
        credential_proof: &[u8],
    ) -> PyResult<PrivacyNativeActionBuildResultV1> {
        self.require_empty_privacy_action_builder_v1(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            "ZK-X509",
        )?;
        let maximum = crate::privacy_native_actions::PRIVACY_ZK_X509_MAX_PROOF_BYTES_V1;
        if credential_proof.is_empty() || credential_proof.len() > maximum {
            return Err(PyValueError::new_err(format!(
                "credential_proof must contain between 1 and {maximum} bytes"
            )));
        }
        let canonical_genesis_hash = *self.network_id.as_bytes();
        let statement = python_zk_x509_statement_archive_v1(canonical_statement_archive)?;
        self.privacy_capability_manifest
            .as_ref()
            .ok_or_else(|| {
                PyRuntimeError::new_err("privacy signing requires an admitted manifest")
            })?
            .require_governed_x509_action(&statement, credential_proof)?;
        let private_key = parse_private_key(private_key)?;
        self.validate_privacy_action_signing_authority_v1(&private_key)?;
        let proof = crate::privacy_native_actions::ZkX509CredentialProofBytesV1::try_new(
            credential_proof.to_vec(),
        )
        .map_err(|error| {
            PyValueError::new_err(format!("native ZK-X509 action failed at {}", error.stage()))
        })?;
        let context = self.privacy_native_action_transaction_context_v1();
        let signed =
            crate::privacy_native_actions::build_signed_zk_x509_identity_presentation_action_v1(
                context,
                crate::privacy_native_actions::ZkX509IdentityPresentationActionRequestV1 {
                    statement,
                    proof,
                },
                canonical_genesis_hash,
                &private_key,
            )
            .map_err(|error| {
                PyValueError::new_err(format!("native ZK-X509 action failed at {}", error.stage()))
            })?;
        let result = self.privacy_native_action_build_result_v1(py, &signed)?;
        self.clear_transaction_state();
        Ok(result)
    }
    /// Replace only fee maxima using a quote, then sign the exact quoted draft.
    fn sign_quoted_payload(
        &mut self,
        draft_payload_json: &str,
        quoted_fee_payment_json: &str,
        private_key: &[u8],
    ) -> PyResult<SignedTransactionEnvelope> {
        ensure_ed25519_account(&self.authority)?;
        self.validate_executable()?;
        let mut draft =
            json::from_str::<TransactionPayload>(draft_payload_json).map_err(|err| {
                PyValueError::new_err(format!("invalid quoted transaction payload JSON: {err}"))
            })?;
        let expected = self
            .to_model_builder()
            .into_payload()
            .map_err(|err| PyValueError::new_err(format!("invalid transaction payload: {err}")))?;
        if draft != expected {
            return Err(PyValueError::new_err(
                "quoted transaction payload does not match this builder's exact draft",
            ));
        }
        let quoted_fee_payment = parse_fee_payment_intent_json(quoted_fee_payment_json)?;
        if !draft
            .fee_payment
            .has_same_payer_and_gas_bound(&quoted_fee_payment)
        {
            return Err(PyValueError::new_err(
                "fee quote changed the selected payer, sponsor revision, or gas bound",
            ));
        }
        draft.fee_payment = quoted_fee_payment;
        let private_key = parse_private_key(private_key)?;
        let signed = ModelTransactionBuilder::from_payload(draft)
            .map_err(|err| PyValueError::new_err(format!("invalid quoted payload: {err}")))?
            .try_sign(&private_key)
            .map_err(|err| PyValueError::new_err(format!("transaction signing failed: {err}")))?;
        let envelope = self.envelope_from_signed(&signed)?;
        self.clear_transaction_state();
        Ok(envelope)
    }
    /// Finalize the transaction using a wallet-provided external signature.
    fn build_with_signature(&mut self, signature: &[u8]) -> PyResult<SignedTransactionEnvelope> {
        ensure_ed25519_account(&self.authority)?;
        self.validate_executable()?;
        if signature.len() != 64 {
            return Err(PyValueError::new_err(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }
        let signed = self.to_model_builder().build_with_signature(
            checked_signature_from_bytes_for_algorithm(
                signature,
                Algorithm::Ed25519,
                "Ed25519 signature",
            )?,
        );
        signed.verify_signature().map_err(|err| {
            PyValueError::new_err(format!("signature verification failed: {err}"))
        })?;
        let envelope = self.envelope_from_signed(&signed)?;
        self.clear_transaction_state();
        Ok(envelope)
    }
}
const ZK_ACE_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "authorization_action";
const ZK_ACE_TRANSFER_LEDGER_EFFECT_V1: &str = "zk_ace_transparent_transfer";
const VERANGE_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "action_verification_and_finality_only";
const VEGA_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "action_verification_and_finality_only";
const ZK_AMS_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "admission_action";
const ZK_AMS_BATCH_ADMISSION_LEDGER_EFFECT_V1: &str = "zk_ams_batch_admission";
const ZK_AMS_PROVISION_ACCOUNT_LEDGER_EFFECT_V1: &str = "zk_ams_provision_account";
const BOOTLE_LANTERN_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "presentation_action";
const ANONYMOUS_PGC_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "payment_action";
const ANONYMOUS_PGC_LEDGER_EFFECT_V1: &str = "anonymous_pgc_account_state_transition";
const ORCHARD_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "note_action";
const ORCHARD_LEDGER_EFFECT_V1: &str = "orchard_note_state_transition";
const FCMP_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "payment_action";
const FCMP_LEDGER_EFFECT_V1: &str = "fcmp_membership_payment";
const IVM_PRIVATE_NOTE_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "note_action";
const IVM_PRIVATE_NOTE_LEDGER_EFFECT_V1: &str = "ivm_private_note_state_transition";
const PQ_MASP_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "note_action";
const PQ_MASP_LEDGER_EFFECT_V1: &str = "pq_masp_note_state_transition";
const ZK_X509_ACTION_EXECUTION_CLASSIFICATION_V1: &str = "presentation_action";
const ZK_X509_LEDGER_EFFECT_V1: &str = "zk_x509_certificate_nullifier";
/// Common signed result for typed native privacy action bindings.
///
/// Secret-bearing bundle buffers are held in zeroizing storage around their
/// decoder boundary. The result exposes only the authenticated public
/// envelope, digests, and byte counts; witness material is never returned.
#[pyclass(frozen, module = "iroha_native._crypto")]
struct PrivacyNativeActionBuildResultV1 {
    envelope: Py<SignedTransactionEnvelope>,
    protocol_id: String,
    operation_schema: &'static str,
    transaction_hash: [u8; 32],
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    adaptive_signed_transaction_bytes: u32,
    versioned_signed_transaction_bytes: u32,
}
#[pymethods]
impl PrivacyNativeActionBuildResultV1 {
    #[getter]
    fn envelope(&self, py: Python<'_>) -> Py<SignedTransactionEnvelope> {
        self.envelope.clone_ref(py)
    }
    #[getter]
    fn protocol_id(&self) -> &str {
        &self.protocol_id
    }
    #[getter]
    const fn operation_schema(&self) -> &'static str {
        self.operation_schema
    }
    #[getter]
    fn transaction_hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.transaction_hash)
    }
    #[getter]
    fn transaction_intent_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.transaction_intent_digest)
    }
    #[getter]
    fn statement_digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.statement_digest)
    }
    #[getter]
    fn proof_envelope_hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.proof_envelope_hash)
    }
    #[getter]
    const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    #[getter]
    const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    #[getter]
    const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    #[getter]
    const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
    #[getter]
    const fn versioned_signed_transaction_bytes(&self) -> u32 {
        self.versioned_signed_transaction_bytes
    }
}
/// Signed transaction outputs exposed to Python.
#[pyclass(module = "iroha_native._crypto")]
struct SignedTransactionEnvelope {
    network_id: NetworkId,
    authority: String,
    signed_transaction: Vec<u8>,
    signed_transaction_versioned: Vec<u8>,
    hash: [u8; Hash::LENGTH],
    signature: Vec<u8>,
    public_key: Vec<u8>,
}
#[pymethods]
impl SignedTransactionEnvelope {
    /// Construct an envelope from its JSON representation produced by `to_json`.
    #[classmethod]
    fn from_json(_cls: &Bound<'_, PyType>, json_str: &str) -> PyResult<Self> {
        let value: norito::json::Value = norito::json::from_str(json_str).map_err(|err| {
            PyValueError::new_err(format!("failed to parse envelope JSON: {err}"))
        })?;
        let obj = value
            .as_object()
            .ok_or_else(|| PyValueError::new_err("expected JSON object"))?;
        const RETIRED_NETWORK_FIELDS: [&str; 7] = [
            "chain",
            "chainId",
            "chain_id",
            "canonicalGenesisHash",
            "canonical_genesis_hash",
            "genesisHash",
            "genesis_hash",
        ];
        if let Some(field) = RETIRED_NETWORK_FIELDS
            .iter()
            .find(|&&field| obj.contains_key::<str>(field))
        {
            return Err(PyValueError::new_err(format!(
                "retired `{field}` envelope field is not accepted"
            )));
        }
        const ENVELOPE_FIELDS: [&str; 9] = [
            "network_id",
            "authority",
            "signed_transaction_b64",
            "signed_transaction_versioned_b64",
            "hash_hex",
            "signature_b64",
            "signature_hex",
            "public_key_b64",
            "public_key_hex",
        ];
        if let Some(field) = obj
            .keys()
            .find(|field| !ENVELOPE_FIELDS.contains(&field.as_str()))
        {
            return Err(PyValueError::new_err(format!(
                "unsupported `{field}` envelope field"
            )));
        }
        let network_id_literal = obj
            .get("network_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `network_id` field"))?;
        let network_id = PyNetworkId::parse(network_id_literal)?.inner;
        let authority = obj
            .get("authority")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `authority` field"))?
            .to_string();
        let signed_b64 = obj
            .get("signed_transaction_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `signed_transaction_b64` field"))?;
        let signed_versioned_b64 = obj
            .get("signed_transaction_versioned_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PyValueError::new_err("missing `signed_transaction_versioned_b64` field")
            })?;
        let signature_b64 = obj
            .get("signature_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `signature_b64` field"))?;
        let public_key_b64 = obj
            .get("public_key_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `public_key_b64` field"))?;
        let signature_hex = obj
            .get("signature_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `signature_hex` field"))?;
        let public_key_hex = obj
            .get("public_key_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `public_key_hex` field"))?;
        let hash_hex = obj
            .get("hash_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("missing `hash_hex` field"))?;
        let signed_transaction = BASE64.decode(signed_b64.as_bytes()).map_err(|err| {
            PyValueError::new_err(format!("invalid signed_transaction_b64: {err}"))
        })?;
        let signed_transaction_versioned =
            BASE64
                .decode(signed_versioned_b64.as_bytes())
                .map_err(|err| {
                    PyValueError::new_err(format!(
                        "invalid signed_transaction_versioned_b64: {err}"
                    ))
                })?;
        let signature = BASE64
            .decode(signature_b64.as_bytes())
            .map_err(|err| PyValueError::new_err(format!("invalid signature_b64: {err}")))?;
        let public_key = BASE64
            .decode(public_key_b64.as_bytes())
            .map_err(|err| PyValueError::new_err(format!("invalid public_key_b64: {err}")))?;
        for (field, encoded, decoded) in [
            (
                "signed_transaction_b64",
                signed_b64,
                signed_transaction.as_slice(),
            ),
            (
                "signed_transaction_versioned_b64",
                signed_versioned_b64,
                signed_transaction_versioned.as_slice(),
            ),
            ("signature_b64", signature_b64, signature.as_slice()),
            ("public_key_b64", public_key_b64, public_key.as_slice()),
        ] {
            if BASE64.encode(decoded) != encoded {
                return Err(PyValueError::new_err(format!(
                    "{field} must use exact canonical base64"
                )));
            }
        }
        let mut hash = [0u8; Hash::LENGTH];
        let hash_bytes = hex::decode(hash_hex).map_err(|err| {
            PyValueError::new_err(format!("invalid hash_hex value `{hash_hex}`: {err}"))
        })?;
        if hash_bytes.len() != Hash::LENGTH {
            return Err(PyValueError::new_err(format!(
                "hash must be {} bytes, got {}",
                Hash::LENGTH,
                hash_bytes.len()
            )));
        }
        hash.copy_from_slice(&hash_bytes);
        if hex::encode(hash) != hash_hex {
            return Err(PyValueError::new_err(
                "hash_hex must use exact lowercase hexadecimal",
            ));
        }
        if hex::encode(&signature) != signature_hex {
            return Err(PyValueError::new_err(
                "signature_hex does not match signature_b64",
            ));
        }
        if hex::encode(&public_key) != public_key_hex {
            return Err(PyValueError::new_err(
                "public_key_hex does not match public_key_b64",
            ));
        }
        let decoded = decode_canonical_signed_transaction_v1(&signed_transaction_versioned)?;
        let signatory = require_single_signatory(decoded.authority(), "transaction authority")?;
        let (algorithm, _) = public_key_to_bytes(signatory, "authority public key")?;
        let expected_signature_len = algorithm.signature_payload_len();
        if signature.len() != expected_signature_len {
            return Err(PyValueError::new_err(format!(
                "{algorithm} signature must be {expected_signature_len} bytes, got {}",
                signature.len()
            )));
        }
        checked_signature_from_bytes_for_algorithm(&signature, algorithm, "envelope signature")?;
        parse_public_key_for_algorithm(algorithm, &public_key)?;
        if decoded.network_id() != Some(&network_id) {
            return Err(PyValueError::new_err(
                "envelope network_id does not match the signed transaction NetworkId",
            ));
        }
        let authenticated = signed_transaction_envelope_from_model_v1(&decoded)?;
        if authenticated.authority != authority
            || authenticated.signed_transaction != signed_transaction
            || authenticated.hash != hash
            || authenticated.signature != signature
            || authenticated.public_key != public_key
        {
            return Err(PyValueError::new_err(
                "envelope metadata does not match the authenticated signed transaction",
            ));
        }
        Ok(authenticated)
    }
    #[getter]
    fn network_id(&self) -> PyNetworkId {
        PyNetworkId {
            inner: self.network_id,
        }
    }
    #[getter]
    fn authority(&self) -> &str {
        &self.authority
    }
    #[getter]
    fn signed_transaction<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signed_transaction)
    }
    #[getter]
    fn signed_transaction_versioned<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signed_transaction_versioned)
    }
    #[getter]
    fn hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.hash)
    }
    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signature)
    }
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public_key)
    }
    /// Return the transaction hash as a hex string.
    fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }
    /// Return the attached signature as a hex string.
    fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }
    /// Return the authority public key as a hex string.
    fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
    /// Return a Python dict summarising the envelope contents.
    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("network_id", canonical_network_id_literal(&self.network_id))?;
        dict.set_item("authority", &self.authority)?;
        dict.set_item(
            "signed_transaction",
            PyBytes::new(py, &self.signed_transaction),
        )?;
        dict.set_item(
            "signed_transaction_versioned",
            PyBytes::new(py, &self.signed_transaction_versioned),
        )?;
        dict.set_item("hash", PyBytes::new(py, &self.hash))?;
        dict.set_item("hash_hex", self.hash_hex())?;
        dict.set_item("signature", PyBytes::new(py, &self.signature))?;
        dict.set_item("signature_hex", self.signature_hex())?;
        dict.set_item("public_key", PyBytes::new(py, &self.public_key))?;
        dict.set_item("public_key_hex", self.public_key_hex())?;
        Ok(dict.unbind())
    }
    /// Decode proof attachments (if present) into a Norito JSON string.
    fn attachments_json(&self) -> PyResult<Option<String>> {
        let signed = SignedTransaction::decode_all_versioned(&self.signed_transaction_versioned)
            .map_err(|err| {
                PyValueError::new_err(format!("failed to decode signed transaction: {err}"))
            })?;
        if signed.attachments().is_none() {
            return Ok(None);
        }
        // The wrapped proof attachments of the transaction-level carriers, as
        // the bounded proof attachment list this boundary has always returned.
        let carriers = signed.proof_attachments_v1().map_err(|err| {
            PyValueError::new_err(format!("failed to decode proof attachments: {err}"))
        })?;
        let list = ProofAttachmentList::try_from(carriers).map_err(|err| {
            PyValueError::new_err(format!("failed to serialize attachments: {err}"))
        })?;
        let value = norito::json::to_value(&list).map_err(|err| {
            PyValueError::new_err(format!("failed to serialize attachments: {err}"))
        })?;
        norito::json::to_string(&value)
            .map(Some)
            .map_err(|err| PyValueError::new_err(format!("failed to serialize attachments: {err}")))
    }
    /// Return a JSON string representation with base64-encoded binary fields.
    fn to_json(&self) -> PyResult<String> {
        let mut map = norito::json::Map::new();
        map.insert(
            "network_id".into(),
            norito::json::Value::String(canonical_network_id_literal(&self.network_id)),
        );
        map.insert(
            "authority".into(),
            norito::json::Value::String(self.authority.clone()),
        );
        map.insert(
            "signed_transaction_b64".into(),
            norito::json::Value::String(BASE64.encode(&self.signed_transaction)),
        );
        map.insert(
            "signed_transaction_versioned_b64".into(),
            norito::json::Value::String(BASE64.encode(&self.signed_transaction_versioned)),
        );
        map.insert(
            "hash_hex".into(),
            norito::json::Value::String(self.hash_hex()),
        );
        map.insert(
            "signature_b64".into(),
            norito::json::Value::String(BASE64.encode(&self.signature)),
        );
        map.insert(
            "signature_hex".into(),
            norito::json::Value::String(self.signature_hex()),
        );
        map.insert(
            "public_key_b64".into(),
            norito::json::Value::String(BASE64.encode(&self.public_key)),
        );
        map.insert(
            "public_key_hex".into(),
            norito::json::Value::String(self.public_key_hex()),
        );
        let value = norito::json::Value::Object(map);
        norito::json::to_string(&value)
            .map_err(|err| PyValueError::new_err(format!("failed to serialize envelope: {err}")))
    }
}
#[pyfunction]
#[pyo3(name = "supported_crypto_algorithms")]
/// Return the canonical names of signature algorithms compiled into the Python SDK.
fn supported_crypto_algorithms_py() -> Vec<String> {
    supported_crypto_algorithms()
        .into_iter()
        .map(|algorithm| algorithm.as_static_str().to_owned())
        .collect()
}
#[pyfunction]
#[pyo3(name = "normalize_crypto_algorithm")]
/// Normalize a crypto algorithm alias to the canonical `iroha_crypto` label.
fn normalize_crypto_algorithm_py(algorithm: &str) -> PyResult<String> {
    parse_algorithm_arg(algorithm).map(|algorithm| algorithm.as_static_str().to_owned())
}
#[pyfunction]
#[pyo3(name = "generate_keypair")]
/// Generate a random key pair for any signature algorithm compiled into the SDK.
fn generate_keypair_py(py: Python<'_>, algorithm: &str) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let key_pair = KeyPair::random_with_algorithm(algorithm);
    keypair_to_py(py, key_pair)
}
#[pyfunction]
#[pyo3(name = "derive_keypair_from_seed")]
/// Derive a key pair for any supported algorithm from arbitrary seed material.
fn derive_keypair_from_seed_py(
    py: Python<'_>,
    seed: &[u8],
    algorithm: &str,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let key_pair = KeyPair::try_from_seed(seed.to_vec(), algorithm)
        .map_err(|err| PyValueError::new_err(format!("failed to derive key pair: {err}")))?;
    keypair_to_py(py, key_pair)
}
#[pyfunction]
#[pyo3(name = "load_keypair")]
/// Reconstruct a key pair for any supported algorithm from raw private-key payload bytes.
fn load_keypair_py(
    py: Python<'_>,
    private_key: &[u8],
    algorithm: &str,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let private = parse_private_key_for_algorithm(algorithm, private_key)?;
    let key_pair = KeyPair::from_private_key(private)
        .map_err(|err| PyValueError::new_err(format!("failed to reconstruct key pair: {err}")))?;
    keypair_to_py(py, key_pair)
}
#[pyfunction]
#[pyo3(name = "sign")]
/// Sign `message` with the private-key payload for any supported signature algorithm.
fn sign_py(
    py: Python<'_>,
    algorithm: &str,
    private_key: &[u8],
    message: &[u8],
) -> PyResult<Py<PyBytes>> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let private_key = parse_private_key_for_algorithm(algorithm, private_key)?;
    let signature = Signature::try_new(&private_key, message)
        .map_err(|err| PyValueError::new_err(format!("failed to sign message: {err}")))?;
    Ok(Py::from(PyBytes::new(py, signature.payload())))
}
fn sign_query_request(
    authority: &str,
    private_key: &[u8],
    network_id: &NetworkId,
    request: QueryRequest,
) -> PyResult<Vec<u8>> {
    let authority = parse_account_id(authority)?;
    ensure_ed25519_account(&authority)?;
    let private = parse_private_key(private_key)?;
    let key_pair = KeyPair::from_private_key(private).map_err(|error| {
        PyValueError::new_err(format!("failed to reconstruct key pair: {error}"))
    })?;
    let authority_signatory = require_single_signatory(&authority, "query authority")?;
    if key_pair.public_key() != authority_signatory {
        return Err(PyValueError::new_err(
            "query private key does not match the authority account",
        ));
    }
    let creation_time_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            PyValueError::new_err(format!("system clock precedes UNIX epoch: {error}"))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| PyValueError::new_err("query creation time exceeds u64"))?;
    const QUERY_TIME_TO_LIVE_MS: u64 = 100_000;
    let time_to_live_ms =
        NonZeroU64::new(QUERY_TIME_TO_LIVE_MS).expect("query TTL constant is nonzero");
    let mut nonce = [0_u8; 32];
    OsRng06
        .try_fill_bytes(&mut nonce)
        .map_err(|error| PyValueError::new_err(format!("query nonce OS RNG failed: {error}")))?;
    request
        .with_authority(
            *network_id,
            authority,
            creation_time_ms,
            time_to_live_ms,
            nonce,
        )
        .try_sign(&key_pair)
        .map(|signed| signed.encode_versioned())
        .map_err(|error| PyValueError::new_err(format!("query signing failed: {error}")))
}
fn parse_typed_hash<T>(value: &str, context: &str) -> PyResult<HashOf<T>> {
    let normalized = value.strip_prefix("0x").unwrap_or(value);
    let hash = Hash::from_str(normalized)
        .map_err(|error| PyValueError::new_err(format!("invalid {context}: {error}")))?;
    Ok(HashOf::from_untyped_unchecked(hash))
}
#[pyfunction]
#[pyo3(name = "build_find_asset_escrow_query")]
/// Build the exact versioned Norito signed query for one native escrow record.
fn build_find_asset_escrow_query_py(
    py: Python<'_>,
    authority: &str,
    private_key: &[u8],
    network_id: &PyNetworkId,
    escrow_id: &str,
) -> PyResult<Py<PyBytes>> {
    let request = QueryRequest::Singular(SingularQueryBox::FindAssetEscrowById(
        FindAssetEscrowById::new(parse_escrow_id(escrow_id, "escrow_id")?),
    ));
    let signed = sign_query_request(authority, private_key, network_id.as_inner(), request)?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
fn build_find_asset_escrows_by_party_query(
    py: Python<'_>,
    authority: &str,
    private_key: &[u8],
    network_id: &PyNetworkId,
    item: QueryItemKind,
    query_payload: Vec<u8>,
) -> PyResult<Py<PyBytes>> {
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload,
        item,
        predicate_bytes: norito::codec::Encode::encode(
            &CompoundPredicate::<AssetEscrowRecord>::PASS,
        ),
        selector_bytes: norito::codec::Encode::encode(
            &SelectorTuple::<AssetEscrowRecord>::default(),
        ),
        params: QueryParams::default(),
    });
    let signed = sign_query_request(authority, private_key, network_id.as_inner(), request)?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
#[pyfunction]
#[pyo3(name = "build_find_asset_escrows_by_seller_query")]
/// Build a signed iterable query for native escrows funded by one account.
fn build_find_asset_escrows_by_seller_query_py(
    py: Python<'_>,
    authority: &str,
    private_key: &[u8],
    network_id: &PyNetworkId,
    seller: &str,
) -> PyResult<Py<PyBytes>> {
    let query = FindAssetEscrowsBySeller {
        seller: parse_account_id(seller)?,
    };
    build_find_asset_escrows_by_party_query(
        py,
        authority,
        private_key,
        network_id,
        QueryItemKind::AssetEscrowsBySeller,
        norito::codec::Encode::encode(&query),
    )
}
#[pyfunction]
#[pyo3(name = "build_find_asset_escrows_by_buyer_query")]
/// Build a signed iterable query for native escrows benefiting one account.
fn build_find_asset_escrows_by_buyer_query_py(
    py: Python<'_>,
    authority: &str,
    private_key: &[u8],
    network_id: &PyNetworkId,
    buyer: &str,
) -> PyResult<Py<PyBytes>> {
    let query = FindAssetEscrowsByBuyer {
        buyer: parse_account_id(buyer)?,
    };
    build_find_asset_escrows_by_party_query(
        py,
        authority,
        private_key,
        network_id,
        QueryItemKind::AssetEscrowsByBuyer,
        norito::codec::Encode::encode(&query),
    )
}
#[pyfunction]
#[pyo3(name = "build_find_committed_transaction_query")]
/// Build a signed `FindTransactions` query for one canonical transaction hash.
fn build_find_committed_transaction_query_py(
    py: Python<'_>,
    authority: &str,
    private_key: &[u8],
    network_id: &PyNetworkId,
    transaction_hash: &str,
) -> PyResult<Py<PyBytes>> {
    let transaction_hash =
        parse_typed_hash::<TransactionEntrypoint>(transaction_hash, "transaction hash")?;
    // First-release Torii permits the narrow wallet-self recovery scope only
    // when the exact transaction authority and entrypoint hash are both bound.
    let predicate = CompoundPredicate::<CommittedTransaction>::from_filters(CommittedTxFilters {
        authority_eq: Some(parse_account_id(authority)?),
        entry_eq: Some(transaction_hash),
        ..CommittedTxFilters::default()
    });
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindTransactions),
        item: QueryItemKind::CommittedTransaction,
        predicate_bytes: norito::codec::Encode::encode(&predicate),
        selector_bytes: norito::codec::Encode::encode(
            &SelectorTuple::<CommittedTransaction>::default(),
        ),
        params: QueryParams::default(),
    });
    let signed = sign_query_request(authority, private_key, network_id.as_inner(), request)?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
#[pyfunction]
#[pyo3(name = "build_find_block_by_hash_query")]
/// Build a signed `FindBlocks` query for one canonical carrier block hash.
fn build_find_block_by_hash_query_py(
    py: Python<'_>,
    authority: &str,
    private_key: &[u8],
    network_id: &PyNetworkId,
    block_hash: &str,
) -> PyResult<Py<PyBytes>> {
    let block_hash = parse_typed_hash::<BlockHeader>(block_hash, "block hash")?;
    let predicate =
        CompoundPredicate::<SignedBlock>::build(|prototype| prototype.equals("hash", block_hash));
    let request = QueryRequest::Start(QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&FindBlocks),
        item: QueryItemKind::SignedBlock,
        predicate_bytes: norito::codec::Encode::encode(&predicate),
        selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<SignedBlock>::default()),
        params: QueryParams::default(),
    });
    let signed = sign_query_request(authority, private_key, network_id.as_inner(), request)?;
    Ok(Py::from(PyBytes::new(py, &signed)))
}
fn decode_single_committed_transaction(response_bytes: &[u8]) -> PyResult<CommittedTransaction> {
    let response = decode_from_bytes::<QueryResponse>(response_bytes).map_err(|error| {
        PyValueError::new_err(format!(
            "failed to decode committed transaction query response: {error}"
        ))
    })?;
    let QueryResponse::Iterable(output) = response else {
        return Err(PyValueError::new_err(
            "committed transaction query returned a singular response",
        ));
    };
    if output.has_more || output.continue_cursor.is_some() {
        return Err(PyValueError::new_err(
            "committed transaction query returned more than one page",
        ));
    }
    let mut transactions = Vec::new();
    for batch in output.batch {
        let QueryOutputBatchBox::CommittedTransaction(mut batch) = batch else {
            return Err(PyValueError::new_err(
                "committed transaction query returned an unexpected batch type",
            ));
        };
        transactions.append(&mut batch);
    }
    if transactions.len() != 1 {
        return Err(PyValueError::new_err(format!(
            "committed transaction query must return exactly one record, got {}",
            transactions.len()
        )));
    }
    Ok(transactions.remove(0))
}
#[pyfunction]
#[pyo3(name = "committed_transaction_carrier_block_hash")]
/// Extract and validate the carrier block hash from an exact transaction query response.
fn committed_transaction_carrier_block_hash_py(
    transaction_hash: &str,
    response_bytes: &[u8],
) -> PyResult<String> {
    let expected = parse_typed_hash::<TransactionEntrypoint>(transaction_hash, "transaction hash")?;
    let committed = decode_single_committed_transaction(response_bytes)?;
    if committed.entrypoint_hash != expected {
        return Err(PyValueError::new_err(
            "committed transaction response does not match the requested transaction hash",
        ));
    }
    Ok(hex_encode(committed.block_hash.as_ref()))
}
fn instruction_execution_rejection_code(error: &InstructionExecutionError) -> &'static str {
    match error {
        InstructionExecutionError::AssetTransferAdmission(admission) => match admission {
            AssetTransferAdmissionError::HoldingLimitExceeded(_) => "HoldingLimitExceeded",
            AssetTransferAdmissionError::IncomingDisabled(_) => "IncomingDisabled",
            AssetTransferAdmissionError::OutgoingDisabled(_) => "OutgoingDisabled",
            AssetTransferAdmissionError::AvailabilityRevisionMismatch(_) => {
                "AvailabilityRevisionMismatch"
            }
            AssetTransferAdmissionError::Blacklisted(_) => "Blacklisted",
            AssetTransferAdmissionError::PolicyRejected(_) => "PolicyRejected",
        },
        InstructionExecutionError::Math(MathError::NotEnoughQuantity) => "InsufficientBalance",
        InstructionExecutionError::Math(_) => "MathError",
        InstructionExecutionError::Evaluate(_) => "InstructionEvaluationFailed",
        InstructionExecutionError::Query(_) => "QueryFailed",
        InstructionExecutionError::Conversion(_) => "ConversionFailed",
        InstructionExecutionError::Find(_) => "NotFound",
        InstructionExecutionError::Repetition(_) => "Repetition",
        InstructionExecutionError::Mintability(_) => "Mintability",
        InstructionExecutionError::InvalidParameter(_) => "InvalidParameter",
        InstructionExecutionError::AccountAdmission(_) => "AccountAdmission",
        InstructionExecutionError::InvariantViolation(_) => "InvariantViolation",
    }
}
fn transaction_rejection_code(reason: &TransactionRejectionReason) -> &str {
    match reason {
        TransactionRejectionReason::AccountDoesNotExist(_) => "AccountDoesNotExist",
        TransactionRejectionReason::LimitCheck(_) => "LimitCheck",
        TransactionRejectionReason::Validation(validation) => match validation {
            ValidationFail::NotPermitted(_) => "NotPermitted",
            ValidationFail::IvmAdmission(_) => "IvmAdmission",
            ValidationFail::IvmFault(_) => "IvmFault",
            ValidationFail::InstructionFailed(error) => instruction_execution_rejection_code(error),
            ValidationFail::ContractRejected(rejection) => rejection.name.as_str(),
            ValidationFail::QueryFailed(_) => "QueryFailed",
            ValidationFail::AxtReject(_) => "AxtRejected",
            ValidationFail::SettlementReplay(_) => "SettlementReplay",
            ValidationFail::TooComplex => "TooComplex",
            ValidationFail::InternalError(_) => "InternalError",
        },
        TransactionRejectionReason::InstructionExecution(_) => "InstructionExecutionFailed",
        TransactionRejectionReason::TriggerExecution(_) => "TriggerExecutionFailed",
    }
}
fn transaction_ivm_fault_json(reason: &TransactionRejectionReason) -> Option<json::Value> {
    let TransactionRejectionReason::Validation(ValidationFail::IvmFault(fault)) = reason else {
        return None;
    };
    Some(norito::json!(fault))
}
fn transaction_contract_rejection_json(reason: &TransactionRejectionReason) -> Option<json::Value> {
    let TransactionRejectionReason::Validation(ValidationFail::ContractRejected(rejection)) =
        reason
    else {
        return None;
    };
    let mut value = json::Map::new();
    value.insert(
        "contract".into(),
        json::Value::String(rejection.contract.to_string()),
    );
    value.insert(
        "error_type".into(),
        json::Value::String(rejection.error_type.clone()),
    );
    value.insert("schema_hash".into(), norito::json!(rejection.schema_hash));
    value.insert("name".into(), json::Value::String(rejection.name.clone()));
    value.insert("code".into(), json::Value::from(rejection.code));
    value.insert(
        "message".into(),
        rejection
            .message
            .as_deref()
            .map_or(json::Value::Null, |message| {
                json::Value::String(message.to_owned())
            }),
    );
    Some(json::Value::Object(value))
}
fn batch_rejection_code(code: AssetBatchTransferRejectionCode) -> &'static str {
    match code {
        AssetBatchTransferRejectionCode::InsufficientFunds => "InsufficientFunds",
        AssetBatchTransferRejectionCode::HoldingLimitExceeded => "HoldingLimitExceeded",
        AssetBatchTransferRejectionCode::IncomingDisabled => "IncomingDisabled",
        AssetBatchTransferRejectionCode::OutgoingDisabled => "OutgoingDisabled",
        AssetBatchTransferRejectionCode::Blacklisted => "Blacklisted",
        AssetBatchTransferRejectionCode::PolicyRejected => "PolicyRejected",
    }
}
fn batch_outcome_json(outcome: &AssetBatchTransferOutcome) -> PyResult<json::Value> {
    let (status, rejection_code, rejection_message) = match &outcome.status {
        AssetBatchTransferLegStatus::Applied => ("Applied", None, None),
        AssetBatchTransferLegStatus::Rejected(rejection) => (
            "Rejected",
            Some(batch_rejection_code(rejection.code)),
            Some(rejection.message.as_str()),
        ),
    };
    let mut result = json::Map::new();
    result.insert("leg_index".into(), json::Value::from(outcome.leg_index));
    result.insert("leg_id".into(), json::Value::String(outcome.leg_id.clone()));
    result.insert(
        "asset".into(),
        json::to_value(&outcome.asset).map_err(|error| {
            PyValueError::new_err(format!("failed to serialize batch outcome asset: {error}"))
        })?,
    );
    result.insert(
        "destination".into(),
        json::to_value(&outcome.destination).map_err(|error| {
            PyValueError::new_err(format!(
                "failed to serialize batch outcome destination: {error}"
            ))
        })?,
    );
    result.insert(
        "amount".into(),
        json::Value::String(outcome.amount.to_string()),
    );
    result.insert("status".into(), json::Value::String(status.to_owned()));
    result.insert(
        "rejection_code".into(),
        rejection_code.map_or(json::Value::Null, |code| {
            json::Value::String(code.to_owned())
        }),
    );
    result.insert(
        "rejection_message".into(),
        rejection_message.map_or(json::Value::Null, |message| {
            json::Value::String(message.to_owned())
        }),
    );
    Ok(json::Value::Object(result))
}
#[pyfunction]
#[pyo3(name = "verify_committed_transaction_inclusion")]
/// Authenticate a selected full output against an independently anchored finality chain.
fn verify_committed_transaction_inclusion_py(
    py: Python<'_>,
    transaction_hash: &str,
    transaction_response_bytes: &[u8],
    native_finality_proof_chain_json: &str,
    expected_network_id: &PyNetworkId,
    expected_chain: &str,
    trusted_checkpoint: &[u8],
) -> PyResult<(String, Py<PyBytes>)> {
    let expected = parse_typed_hash::<TransactionEntrypoint>(transaction_hash, "transaction hash")?;
    let (committed, page) = committed_transaction_verification::authenticate_committed_transaction(
        expected,
        transaction_response_bytes,
        native_finality_proof_chain_json,
        *expected_network_id.as_inner(),
        expected_chain,
        trusted_checkpoint,
    )?;
    let tip = page.tip();
    let execution_commitment = tip.execution();
    let entrypoint_kind = match &committed.entrypoint {
        TransactionEntrypoint::External(_) => "External",
        TransactionEntrypoint::SealedCommitment(_) => "SealedCommitment",
        TransactionEntrypoint::SealedReveal(_) => "SealedReveal",
    };
    let external_transaction = match &committed.entrypoint {
        TransactionEntrypoint::External(transaction) => Some(transaction),
        _ => None,
    };
    let authority = committed
        .entrypoint
        .authority_opt()
        .map(|authority| {
            json::to_value(authority).map_err(|error| {
                PyValueError::new_err(format!(
                    "failed to serialize verified transaction authority: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(json::Value::Null);
    let metadata = committed
        .entrypoint
        .metadata()
        .map(|metadata| {
            json::to_value(metadata).map_err(|error| {
                PyValueError::new_err(format!(
                    "failed to serialize verified transaction metadata: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(json::Value::Null);
    let executable = external_transaction
        .map(|transaction| {
            json::to_value(transaction.instructions()).map_err(|error| {
                PyValueError::new_err(format!(
                    "failed to serialize verified transaction executable: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(json::Value::Null);
    let signer_public_key_hex = external_transaction
        .and_then(|transaction| transaction.authority().controller().single_signatory())
        .map(|public_key| {
            let (_, bytes) =
                public_key_to_bytes(public_key, "verified transaction signer public key")?;
            Ok::<_, PyErr>(hex_encode(bytes))
        })
        .transpose()?;
    let (result_ok, rejection_code, rejection_message, contract_rejection) =
        match &committed.result().0 {
            Ok(_) => (true, None, None, None),
            Err(reason) => (
                false,
                Some(transaction_rejection_code(reason)),
                Some(reason.to_string()),
                transaction_contract_rejection_json(reason),
            ),
        };
    let ivm_fault = committed
        .result()
        .0
        .as_ref()
        .err()
        .and_then(transaction_ivm_fault_json);
    let batch_outcomes = committed
        .result()
        .batch_transfer_outcomes()
        .iter()
        .map(batch_outcome_json)
        .collect::<PyResult<Vec<_>>>()?;
    let committed_json = norito::json::to_value(&committed).map_err(|error| {
        PyValueError::new_err(format!(
            "failed to serialize verified committed transaction: {error}"
        ))
    })?;
    let mut result = norito::json::Map::new();
    result.insert(
        "proof_kind".into(),
        json::Value::String("selective-v1".into()),
    );
    result.insert(
        "network_id".into(),
        json::to_value(expected_network_id.as_inner())
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    result.insert(
        "context_id".into(),
        json::to_value(&tip.context_id())
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    let mut execution_json = json::Map::new();
    execution_json.insert(
        "parent_state_root".into(),
        json::to_value(&execution_commitment.parent_state_root)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    execution_json.insert(
        "post_state_root".into(),
        json::to_value(&execution_commitment.post_state_root)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    execution_json.insert(
        "ordinary_writes_root".into(),
        json::to_value(&execution_commitment.ordinary_writes_root)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    execution_json.insert(
        "executed_block_wire_len".into(),
        json::to_value(&execution_commitment.executed_block_wire_len)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    execution_json.insert(
        "executed_block_wire_hash".into(),
        json::to_value(&execution_commitment.executed_block_wire_hash)
            .map_err(|error| PyValueError::new_err(error.to_string()))?,
    );
    let transaction_input_commitment =
        match execution_commitment.transaction_input_commitment.as_ref() {
            None => json::Value::Null,
            Some(tree) => {
                let mut value = json::Map::new();
                value.insert(
                    "root".into(),
                    json::to_value(&tree.root())
                        .map_err(|error| PyValueError::new_err(error.to_string()))?,
                );
                value.insert(
                    "leaf_count".into(),
                    json::to_value(&tree.leaf_count().get())
                        .map_err(|error| PyValueError::new_err(error.to_string()))?,
                );
                json::Value::Object(value)
            }
        };
    execution_json.insert(
        "transaction_input_commitment".into(),
        transaction_input_commitment,
    );
    let transaction_output_commitment =
        match execution_commitment.transaction_output_commitment.as_ref() {
            None => json::Value::Null,
            Some(tree) => {
                let mut value = json::Map::new();
                value.insert(
                    "root".into(),
                    json::to_value(&tree.root())
                        .map_err(|error| PyValueError::new_err(error.to_string()))?,
                );
                value.insert(
                    "leaf_count".into(),
                    json::to_value(&tree.leaf_count().get())
                        .map_err(|error| PyValueError::new_err(error.to_string()))?,
                );
                json::Value::Object(value)
            }
        };
    execution_json.insert(
        "transaction_output_commitment".into(),
        transaction_output_commitment,
    );
    result.insert(
        "execution_commitment".into(),
        json::Value::Object(execution_json),
    );
    result.insert(
        "executed_block_wire_hash".into(),
        json::Value::String(hex_encode(
            execution_commitment.executed_block_wire_hash.as_ref(),
        )),
    );
    result.insert(
        "executed_block_wire_len".into(),
        json::Value::from(execution_commitment.executed_block_wire_len),
    );
    result.insert(
        "transaction_hash".into(),
        norito::json::Value::String(hex_encode(committed.entrypoint_hash.as_ref())),
    );
    result.insert(
        "block_hash".into(),
        norito::json::Value::String(hex_encode(committed.block_hash.as_ref())),
    );
    result.insert(
        "block_height".into(),
        norito::json::Value::from(tip.height()),
    );
    result.insert(
        "output_hash".into(),
        norito::json::Value::String(hex_encode(committed.output_hash.as_ref())),
    );
    result.insert(
        "entrypoint_kind".into(),
        norito::json::Value::String(entrypoint_kind.to_owned()),
    );
    result.insert("authority".into(), authority);
    result.insert(
        "signer_public_key_hex".into(),
        signer_public_key_hex.map_or(norito::json::Value::Null, norito::json::Value::String),
    );
    result.insert("metadata".into(), metadata);
    result.insert("executable".into(), executable);
    result.insert("result_ok".into(), norito::json::Value::Bool(result_ok));
    result.insert(
        "rejection_code".into(),
        rejection_code.map_or(norito::json::Value::Null, |code| {
            norito::json::Value::String(code.to_owned())
        }),
    );
    result.insert(
        "rejection_message".into(),
        rejection_message.map_or(norito::json::Value::Null, norito::json::Value::String),
    );
    result.insert(
        "ivm_fault".into(),
        ivm_fault.unwrap_or(norito::json::Value::Null),
    );
    result.insert(
        "contract_rejection".into(),
        contract_rejection.unwrap_or(norito::json::Value::Null),
    );
    result.insert(
        "batch_outcomes".into(),
        norito::json::Value::Array(batch_outcomes),
    );
    result.insert("committed_transaction".into(), committed_json);
    let projection =
        norito::json::to_string(&norito::json::Value::Object(result)).map_err(|error| {
            PyValueError::new_err(format!(
                "failed to encode verified committed transaction JSON: {error}"
            ))
        })?;
    let promoted = page
        .checkpoint()
        .encode_canonical()
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok((projection, Py::from(PyBytes::new(py, &promoted))))
}
#[pyfunction]
#[pyo3(name = "verify")]
/// Verify a raw signature against a public-key payload for any supported signature algorithm.
fn verify_py(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let public_key = parse_public_key_for_algorithm(algorithm, public_key)?;
    let signature = match match algorithm {
        Algorithm::Ed25519 => ed25519_parse_signature(signature),
        Algorithm::MlDsa => mldsa65_parse_signature(signature),
        _ => Signature::try_from_bytes(signature).map_err(Into::into),
    } {
        Ok(signature) => signature,
        Err(_) => return Ok(false),
    };
    Ok(signature.verify(&public_key, message).is_ok())
}
#[pyfunction]
#[pyo3(name = "public_key_multihash", signature = (algorithm, public_key, prefixed=false))]
/// Return the canonical multihash encoding for a public-key payload.
fn public_key_multihash_py(algorithm: &str, public_key: &[u8], prefixed: bool) -> PyResult<String> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let public_key = parse_public_key_for_algorithm(algorithm, public_key)?;
    public_key_multihash_string(&public_key, prefixed, "public key multihash")
}
#[pyfunction]
#[pyo3(name = "private_key_multihash", signature = (algorithm, private_key, prefixed=false))]
/// Return the canonical multihash encoding for a private-key payload.
fn private_key_multihash_py(
    algorithm: &str,
    private_key: &[u8],
    prefixed: bool,
) -> PyResult<String> {
    let algorithm = parse_algorithm_arg(algorithm)?;
    let private_key = parse_private_key_for_algorithm(algorithm, private_key)?;
    let exposed = ExposedPrivateKey(private_key);
    private_key_multihash_string(&exposed, prefixed, "private key multihash")
}
#[pyfunction]
#[pyo3(name = "parse_public_key_multihash")]
/// Decode a public key from a bare or algorithm-prefixed multihash string.
fn parse_public_key_multihash_py(py: Python<'_>, encoded: &str) -> PyResult<(String, Py<PyBytes>)> {
    let public_key = encoded.parse::<PublicKey>().map_err(|err| {
        PyValueError::new_err(format!("failed to parse public key multihash: {err}"))
    })?;
    let (algorithm, payload) = public_key_to_bytes(&public_key, "public key multihash")?;
    Ok((
        algorithm.as_static_str().to_owned(),
        Py::from(PyBytes::new(py, payload)),
    ))
}
#[pyfunction]
#[pyo3(name = "parse_private_key_multihash")]
/// Decode a private key from a bare or algorithm-prefixed multihash string.
fn parse_private_key_multihash_py(
    py: Python<'_>,
    encoded: &str,
) -> PyResult<(String, Py<PyBytes>)> {
    let exposed = encoded.parse::<ExposedPrivateKey>().map_err(|err| {
        PyValueError::new_err(format!("failed to parse private key multihash: {err}"))
    })?;
    let (algorithm, mut payload) = exposed.0.to_bytes();
    let bytes = Py::from(PyBytes::new(py, payload.as_slice()));
    payload.fill(0);
    Ok((algorithm.as_static_str().to_owned(), bytes))
}
#[pyfunction]
#[pyo3(name = "load_keypair_from_multihash")]
/// Reconstruct a key pair from a private-key multihash string.
fn load_keypair_from_multihash_py(
    py: Python<'_>,
    encoded: &str,
) -> PyResult<(String, Py<PyBytes>, Py<PyBytes>)> {
    let exposed = encoded.parse::<ExposedPrivateKey>().map_err(|err| {
        PyValueError::new_err(format!("failed to parse private key multihash: {err}"))
    })?;
    let algorithm = exposed.0.algorithm();
    let key_pair = KeyPair::from_private_key(exposed.0)
        .map_err(|err| PyValueError::new_err(format!("failed to reconstruct key pair: {err}")))?;
    let (private, public) = keypair_to_py(py, key_pair)?;
    Ok((algorithm.as_static_str().to_owned(), private, public))
}
#[pyfunction]
#[pyo3(name = "generate_ed25519_keypair")]
/// Generate a random Ed25519 key pair using `iroha_crypto` defaults.
fn generate_ed25519_keypair_py(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let key_pair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
    keypair_to_py(py, key_pair)
}
#[pyfunction]
#[pyo3(name = "derive_ed25519_keypair_from_seed")]
/// Derive an Ed25519 key pair from an arbitrary seed (hashed internally to 32 bytes).
fn derive_ed25519_keypair_from_seed_py(
    py: Python<'_>,
    seed: &[u8],
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let key_pair = KeyPair::try_from_seed(seed.to_vec(), Algorithm::Ed25519).map_err(|err| {
        PyValueError::new_err(format!("failed to derive Ed25519 key pair: {err}"))
    })?;
    keypair_to_py(py, key_pair)
}
#[pyfunction]
#[pyo3(name = "load_ed25519_keypair")]
/// Reconstruct an Ed25519 key pair from raw private key bytes.
fn load_ed25519_keypair_py(
    py: Python<'_>,
    private_key: &[u8],
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let private = parse_private_key(private_key)?;
    let key_pair = KeyPair::from_private_key(private)
        .map_err(|err| PyValueError::new_err(format!("failed to reconstruct key pair: {err}")))?;
    keypair_to_py(py, key_pair)
}
#[pyfunction]
#[pyo3(name = "sign_ed25519")]
/// Sign `message` using the given Ed25519 private key; returns the raw signature bytes.
fn sign_ed25519_py(py: Python<'_>, private_key: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    let private_key = parse_private_key(private_key)?;
    let signature = Signature::try_new(&private_key, message)
        .map_err(|err| PyValueError::new_err(format!("failed to sign Ed25519 message: {err}")))?;
    Ok(Py::from(PyBytes::new(py, signature.payload())))
}
#[pyfunction]
#[pyo3(name = "verify_ed25519")]
/// Verify `signature` against `message` and the provided Ed25519 public key.
fn verify_ed25519_py(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let public_key = parse_public_key(public_key)?;
    let signature = match ed25519_parse_signature(signature) {
        Ok(signature) => signature,
        Err(_) => return Ok(false),
    };
    Ok(signature.verify(&public_key, message).is_ok())
}
#[pyfunction]
#[pyo3(name = "sm2_default_distid")]
/// Return the default SM2 distinguishing identifier.
fn sm2_default_distid_py() -> String {
    Sm2PublicKey::default_distid()
}
#[pyfunction]
#[pyo3(name = "generate_sm2_keypair", signature = (distid=None))]
/// Generate a random SM2 key pair; returns the 32-byte private scalar and 65-byte SEC1 public key.
fn generate_sm2_keypair_py(
    py: Python<'_>,
    distid: Option<&str>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let distid = sm2_distid_arg(distid);
    let private = Sm2PrivateKey::try_random_from_os(distid)
        .map_err(|err| PyValueError::new_err(format!("failed to generate SM2 key pair: {err}")))?;
    let public = private.public_key();
    let private_bytes = private.secret_bytes();
    let public_bytes = public.to_sec1_bytes(false);
    Ok((
        Py::from(PyBytes::new(py, &private_bytes)),
        Py::from(PyBytes::new(py, &public_bytes)),
    ))
}
#[pyfunction]
#[pyo3(name = "derive_sm2_keypair_from_seed", signature = (seed, distid=None))]
/// Deterministically derive an SM2 key pair from `seed`.
fn derive_sm2_keypair_from_seed_py(
    py: Python<'_>,
    seed: &[u8],
    distid: Option<&str>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let distid = sm2_distid_arg(distid);
    let private = Sm2PrivateKey::from_seed(distid, seed).map_err(|err| {
        PyValueError::new_err(format!("failed to derive SM2 key from seed: {err}"))
    })?;
    let public = private.public_key();
    let private_bytes = private.secret_bytes();
    let public_bytes = public.to_sec1_bytes(false);
    Ok((
        Py::from(PyBytes::new(py, &private_bytes)),
        Py::from(PyBytes::new(py, &public_bytes)),
    ))
}
#[pyfunction]
#[pyo3(name = "load_sm2_keypair", signature = (private_key, distid=None))]
/// Reconstruct an SM2 key pair from raw private-key bytes.
fn load_sm2_keypair_py(
    py: Python<'_>,
    private_key: &[u8],
    distid: Option<&str>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let private = parse_sm2_private_key(distid, private_key)?;
    let public = private.public_key();
    let private_bytes = private.secret_bytes();
    let public_bytes = public.to_sec1_bytes(false);
    Ok((
        Py::from(PyBytes::new(py, &private_bytes)),
        Py::from(PyBytes::new(py, &public_bytes)),
    ))
}
#[pyfunction]
#[pyo3(name = "sm2_public_key_multihash", signature = (public_key, distid=None))]
/// Return the canonical multihash encoding for an SM2 public key.
fn sm2_public_key_multihash_py(public_key: &[u8], distid: Option<&str>) -> PyResult<String> {
    let distid = sm2_distid_arg(distid);
    let _ = parse_sm2_public_key(Some(distid.as_str()), public_key)?;
    let payload = encode_sm2_public_key_payload(&distid, public_key).map_err(|err| {
        PyValueError::new_err(format!("failed to encode SM2 public key payload: {err}"))
    })?;
    PublicKey::from_bytes(Algorithm::Sm2, &payload)
        .map_err(|err| PyValueError::new_err(format!("failed to construct SM2 public key: {err}")))
        .and_then(|pk| public_key_multihash_string(&pk, false, "SM2 public key multihash"))
}
fn sm2_fixture_public_key_multihashes(public_key: &PublicKey) -> PyResult<(String, String)> {
    let multihash = public_key_multihash_string(public_key, false, "SM2 fixture public key")?;
    let prefixed = public_key_multihash_string(public_key, true, "SM2 fixture public key")?;
    Ok((multihash, prefixed))
}
#[pyfunction]
#[pyo3(name = "sign_sm2", signature = (private_key, message, distid=None))]
/// Sign `message` with the provided SM2 private key.
fn sign_sm2_py(
    py: Python<'_>,
    private_key: &[u8],
    message: &[u8],
    distid: Option<&str>,
) -> PyResult<Py<PyBytes>> {
    let private = parse_sm2_private_key(distid, private_key)?;
    let signature = private.sign(message).to_bytes();
    Ok(Py::from(PyBytes::new(py, &signature)))
}
#[pyfunction]
#[pyo3(name = "verify_sm2", signature = (public_key, message, signature, distid=None))]
/// Verify an SM2 signature against `message` and the provided public key.
fn verify_sm2_py(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    distid: Option<&str>,
) -> PyResult<bool> {
    let public = parse_sm2_public_key(distid, public_key)?;
    let signature = parse_sm2_signature(signature)?;
    Ok(public.verify(message, &signature).is_ok())
}
#[pyfunction]
#[pyo3(name = "hash_blake2b_32")]
/// Compute the canonical Iroha Blake2b-256 hash for the given bytes.
fn hash_blake2b_32_py(py: Python<'_>, payload: &[u8]) -> PyResult<Py<PyBytes>> {
    let hash = Hash::new(payload);
    let bytes: [u8; Hash::LENGTH] = hash.into();
    Ok(Py::from(PyBytes::new(py, &bytes)))
}
fn require_canonical_signed_transaction_wire_size_v1(bytes: &[u8]) -> PyResult<()> {
    let maximum = usize::try_from(
        iroha_data_model::parameter::system::TransactionParameters::default()
            .max_tx_bytes()
            .get(),
    )
    .map_err(|_| {
        PyRuntimeError::new_err("canonical transaction byte limit does not fit this platform")
    })?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(PyValueError::new_err(format!(
            "signed_transaction_versioned must contain between 1 and {maximum} bytes"
        )));
    }
    Ok(())
}
fn decode_canonical_signed_transaction_v1(bytes: &[u8]) -> PyResult<SignedTransaction> {
    require_canonical_signed_transaction_wire_size_v1(bytes)?;
    let signed = SignedTransaction::decode_all_versioned(bytes).map_err(|_| {
        PyValueError::new_err(
            "signed_transaction_versioned is not a valid current signed transaction",
        )
    })?;
    if signed.encode_versioned() != bytes {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned is not the exact canonical wire",
        ));
    }
    Ok(signed)
}
fn signed_transaction_envelope_from_model_v1(
    signed: &SignedTransaction,
) -> PyResult<SignedTransactionEnvelope> {
    signed.verify_signature().map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned has an invalid authority signature")
    })?;
    let signature: Signature = signed.signature().payload().clone();
    let hash: HashOf<SignedTransaction> = signed.hash();
    let signatory = require_single_signatory(signed.authority(), "transaction authority")?;
    let (_, public_key_bytes) = public_key_to_bytes(signatory, "authority public key")?;
    let network_id = signed.network_id().copied().ok_or_else(|| {
        PyValueError::new_err(
            "genesis-domain transactions cannot be represented as client envelopes",
        )
    })?;
    Ok(SignedTransactionEnvelope {
        network_id,
        authority: signed.authority().to_string(),
        signed_transaction: codec::encode_adaptive(signed),
        signed_transaction_versioned: signed.encode_versioned(),
        hash: *hash.as_ref(),
        signature: signature.payload().to_vec(),
        public_key: public_key_bytes.to_vec(),
    })
}
#[pyfunction]
#[pyo3(name = "signed_transaction_envelope_from_versioned_v1")]
/// Decode one exact current signed wire and reconstruct its authenticated public envelope.
fn signed_transaction_envelope_from_versioned_v1_py(
    signed_transaction_versioned: &[u8],
    network_id: &PyNetworkId,
) -> PyResult<SignedTransactionEnvelope> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    if signed.network_id() != Some(&network_id.inner) {
        return Err(PyValueError::new_err(
            "signed transaction network does not match NetworkId",
        ));
    }
    signed_transaction_envelope_from_model_v1(&signed)
}
fn canonical_signed_transaction_hash_v1(bytes: &[u8]) -> PyResult<[u8; Hash::LENGTH]> {
    let signed = decode_canonical_signed_transaction_v1(bytes)?;
    signed.verify_signature().map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned has an invalid authority signature")
    })?;
    Ok(*signed.hash().as_ref())
}
#[pyfunction]
#[pyo3(name = "canonical_signed_transaction_hash_v1")]
/// Decode, authenticate, and recompute the current transaction hash.
fn canonical_signed_transaction_hash_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyBytes>> {
    let hash = canonical_signed_transaction_hash_v1(signed_transaction_versioned)?;
    Ok(Py::from(PyBytes::new(py, &hash)))
}

const ACCOUNT_ONBOARDING_RECEIPT_HASH_DOMAIN_V1: &[u8] =
    b"iroha:account-onboarding-plan-receipt:v1\0";

#[derive(Clone, Debug, NEnc, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PythonAccountOnboardingPlanRequestV1 {
    version: u8,
    alias: String,
    account_id: String,
    permissions: Vec<String>,
}

#[derive(Clone, Debug, NEnc, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PythonAccountOnboardingPlanBodyV1 {
    version: u8,
    request: PythonAccountOnboardingPlanRequestV1,
    authority: AccountId,
    network_id: NetworkId,
    anchor: AliasPlanAnchorV1,
    resource: AliasPlanResourceV1,
    acquisition: AliasLeaseAcquisitionV1,
    quote_guard: AliasQuoteGuardV1,
    instructions: Vec<AliasFramedInstructionV1>,
    owner_auto_renew_instruction: Option<AliasFramedInstructionV1>,
    valid_until_ms: u64,
}

impl PythonAccountOnboardingPlanBodyV1 {
    fn canonical_hash(&self) -> Hash {
        use norito::codec::Encode as _;

        let encoded = self.encode();
        Hash::new_from_chunks(&[
            ACCOUNT_ONBOARDING_RECEIPT_HASH_DOMAIN_V1,
            encoded.as_slice(),
        ])
    }
}

#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PythonAccountOnboardingPlanReceiptV1 {
    body: PythonAccountOnboardingPlanBodyV1,
    plan_hash: Hash,
    signature: Signature,
}

fn verify_python_account_onboarding_receipt_v1(
    receipt: &PythonAccountOnboardingPlanReceiptV1,
    expected_network_id: &NetworkId,
    expected_authority: &AccountId,
    expected_account_id: &AccountId,
    expected_account_literal: &str,
    expected_alias: &str,
    expected_permissions: &[String],
) -> PyResult<(Hash, Vec<InstructionBox>)> {
    let body = &receipt.body;
    if body.version != 1
        || body.request.version != 1
        || &body.network_id != expected_network_id
        || &body.authority != expected_authority
        || body.request.account_id != expected_account_literal
        || body.request.alias != expected_alias
        || body.request.permissions != expected_permissions
        || body.valid_until_ms == 0
        || body.valid_until_ms == u64::MAX
        || body.quote_guard.valid_until_ms != body.valid_until_ms
        || body.resource.disposition == AliasPlanDispositionV1::Conflict
    {
        return Err(PyValueError::new_err(
            "account onboarding receipt differs from its exact trust pins",
        ));
    }
    let parsed_alias = body
        .request
        .alias
        .parse::<AccountAliasName>()
        .map_err(|_| PyValueError::new_err("account onboarding receipt alias is noncanonical"))?;
    if parsed_alias.to_string() != body.request.alias {
        return Err(PyValueError::new_err(
            "account onboarding receipt alias is noncanonical",
        ));
    }
    let mut previous_permission: Option<&str> = None;
    for permission in &body.request.permissions {
        let parsed = permission.parse::<Name>().map_err(|_| {
            PyValueError::new_err("account onboarding receipt permission is noncanonical")
        })?;
        if parsed.to_string() != *permission
            || previous_permission.is_some_and(|previous| previous >= permission.as_str())
        {
            return Err(PyValueError::new_err(
                "account onboarding receipt permissions are not strictly canonical",
            ));
        }
        previous_permission = Some(permission);
    }
    let AliasIntentV1::AccountAlias(intent) = &body.resource.intent else {
        return Err(PyValueError::new_err(
            "account onboarding receipt resource is not an account alias",
        ));
    };
    if intent.alias.canonical_text() != body.request.alias
        || &intent.target_account != expected_account_id
        || intent.provision != AccountProvisionV1::Create
        || intent.role != AccountAliasRoleV1::Primary
    {
        return Err(PyValueError::new_err(
            "account onboarding receipt resource differs from its request",
        ));
    }
    match (body.resource.disposition, &body.resource.quote) {
        (AliasPlanDispositionV1::Create, Some(quote))
            if quote.target == body.resource.intent.target()
                && quote.guard == body.quote_guard
                && quote.exact_amount <= quote.guard.max_amount => {}
        (AliasPlanDispositionV1::Create, _) => {
            return Err(PyValueError::new_err(
                "account onboarding create receipt has an invalid quote",
            ));
        }
        (_, None) => {}
        (_, Some(_)) => {
            return Err(PyValueError::new_err(
                "account onboarding no-op or repair receipt carries a quote",
            ));
        }
    }
    if body.instructions.is_empty() {
        if body.resource.disposition != AliasPlanDispositionV1::NoOp
            || body.resource.instruction_index.is_some()
        {
            return Err(PyValueError::new_err(
                "account onboarding receipt has an invalid empty instruction plan",
            ));
        }
    } else if body.resource.instruction_index != Some(0) {
        return Err(PyValueError::new_err(
            "account onboarding receipt must reference instruction zero",
        ));
    }
    let mut decoded_instructions = Vec::with_capacity(body.instructions.len());
    for frame in &body.instructions {
        let instruction = iroha_data_model::isi::decode_instruction_from_pair(
            &frame.wire_id,
            &frame.framed_payload,
        )
        .map_err(|_| PyValueError::new_err("account onboarding receipt instruction is invalid"))?;
        let (wire_id, canonical_payload) =
            iroha_data_model::isi::framed_instruction_payload(&instruction).ok_or_else(|| {
                PyValueError::new_err("account onboarding receipt instruction is unregistered")
            })?;
        if wire_id != frame.wire_id || canonical_payload != frame.framed_payload {
            return Err(PyValueError::new_err(
                "account onboarding receipt instruction is noncanonical",
            ));
        }
        decoded_instructions.push(instruction);
    }
    if let Some(first) = decoded_instructions.first() {
        let ensure = first
            .as_any()
            .downcast_ref::<iroha_data_model::isi::alias_setup::EnsureAlias>()
            .ok_or_else(|| {
                PyValueError::new_err(
                    "account onboarding receipt first instruction is not EnsureAlias",
                )
            })?;
        if ensure.intent != body.resource.intent
            || ensure.acquisition != body.acquisition
            || ensure.quote_guard != body.quote_guard
        {
            return Err(PyValueError::new_err(
                "account onboarding EnsureAlias differs from the receipt body",
            ));
        }
    }
    if let Some(frame) = &body.owner_auto_renew_instruction {
        let instruction = iroha_data_model::isi::decode_instruction_from_pair(
            &frame.wire_id,
            &frame.framed_payload,
        )
        .map_err(|_| {
            PyValueError::new_err("account onboarding owner auto-renew instruction is invalid")
        })?;
        let (wire_id, canonical_payload) =
            iroha_data_model::isi::framed_instruction_payload(&instruction).ok_or_else(|| {
                PyValueError::new_err(
                    "account onboarding owner auto-renew instruction is unregistered",
                )
            })?;
        let configuration = instruction
            .as_any()
            .downcast_ref::<iroha_data_model::isi::alias_setup::ConfigureAliasAutoRenew>()
            .ok_or_else(|| {
                PyValueError::new_err(
                    "account onboarding owner auto-renew instruction has the wrong type",
                )
            })?;
        if wire_id != frame.wire_id
            || canonical_payload != frame.framed_payload
            || configuration.target != body.resource.intent.target()
        {
            return Err(PyValueError::new_err(
                "account onboarding owner auto-renew instruction is noncanonical",
            ));
        }
    }
    let canonical_hash = body.canonical_hash();
    let signatory = expected_authority.try_signatory().ok_or_else(|| {
        PyValueError::new_err("account onboarding authority must have one signatory")
    })?;
    if receipt.plan_hash != canonical_hash
        || receipt
            .signature
            .verify(signatory, canonical_hash.as_ref())
            .is_err()
    {
        return Err(PyValueError::new_err(
            "account onboarding receipt hash or signature is invalid",
        ));
    }
    Ok((canonical_hash, decoded_instructions))
}

#[pyfunction]
#[pyo3(name = "verify_account_onboarding_receipt_v1")]
/// Authenticate one exact canonical V1 onboarding receipt and its trust pins.
fn verify_account_onboarding_receipt_v1_py(
    receipt_json: &str,
    network_id: &PyNetworkId,
    expected_authority: &str,
    expected_account_id: &str,
    expected_alias: &str,
    expected_permissions_json: &str,
) -> PyResult<String> {
    let receipt =
        json::from_str::<PythonAccountOnboardingPlanReceiptV1>(receipt_json).map_err(|error| {
            PyValueError::new_err(format!("invalid account onboarding receipt JSON: {error}"))
        })?;
    let expected_authority =
        parse_exact_i105_account_id(expected_authority, "account onboarding expected authority")?;
    let expected_account =
        parse_exact_i105_account_id(expected_account_id, "account onboarding expected account")?;
    let expected_permissions =
        json::from_str::<Vec<String>>(expected_permissions_json).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid account onboarding expected permissions JSON: {error}"
            ))
        })?;
    let (hash, _) = verify_python_account_onboarding_receipt_v1(
        &receipt,
        network_id.as_inner(),
        &expected_authority,
        &expected_account,
        expected_account_id,
        expected_alias,
        &expected_permissions,
    )?;
    Ok(hex_encode(hash.as_ref()))
}

fn require_prepared_binding_json_v1(
    binding_json: &str,
    expected_operation: &str,
) -> PyResult<norito::json::Value> {
    const SCHEMA: &str = "iroha.prepared-operation.binding.v1";
    const FIELDS: [&str; 5] = [
        "schema",
        "semantic_hash_hex",
        "kind",
        "request_id",
        "execution_expires_at_unix_ms",
    ];
    let value = json::from_str::<norito::json::Value>(binding_json).map_err(|error| {
        PyValueError::new_err(format!("invalid prepared mutation binding JSON: {error}"))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| PyValueError::new_err("prepared mutation binding JSON must be an object"))?;
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(PyValueError::new_err(
            "prepared mutation binding must contain exactly the V1 fields",
        ));
    }
    let exact_string = |field: &str| -> PyResult<&str> {
        object
            .get(field)
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| {
                PyValueError::new_err(format!(
                    "prepared mutation binding `{field}` must be a string"
                ))
            })
    };
    if exact_string("schema")? != SCHEMA || exact_string("kind")? != expected_operation {
        return Err(PyValueError::new_err(
            "prepared mutation binding schema or operation is invalid",
        ));
    }
    for field in ["semantic_hash_hex", "request_id"] {
        let value = exact_string(field)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PyValueError::new_err(format!(
                "prepared mutation binding `{field}` must be 64 lowercase hex characters"
            )));
        }
    }
    if object
        .get("execution_expires_at_unix_ms")
        .and_then(norito::json::Value::as_u64)
        .is_none_or(|value| value == 0)
    {
        return Err(PyValueError::new_err(
            "prepared mutation binding execution deadline must be a positive u64",
        ));
    }
    Ok(value)
}

const ACCOUNT_FAUCET_CLAIM_HASH_DOMAIN_V1: &[u8] = b"iroha:accounts:faucet:claim:v1\0";

#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PythonPreparedOnboardingContextV1 {
    receipt: PythonAccountOnboardingPlanReceiptV1,
    account_id: String,
    alias: String,
    disposition: AliasPlanDispositionV1,
}

#[derive(Clone, Debug, PartialEq, Eq, NEnc, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PythonAccountFaucetClaimV1 {
    account_id: String,
    pow_anchor_height: u64,
    pow_nonce_hex: String,
}

#[derive(Clone, Debug, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PythonPreparedFaucetContextV1 {
    claim: PythonAccountFaucetClaimV1,
    account_id: String,
    asset_definition_id: String,
    asset_id: String,
    amount: Quantity,
}

fn python_instructions_are_ordered_subset(
    actual: &[InstructionBox],
    planned: &[InstructionBox],
) -> bool {
    let mut actual = actual.iter();
    let mut next = actual.next();
    for instruction in planned {
        if next.is_some_and(|candidate| candidate == instruction) {
            next = actual.next();
        }
    }
    next.is_none()
}

fn python_onboarding_disposition_transition_allowed(
    planned: AliasPlanDispositionV1,
    prepared: AliasPlanDispositionV1,
) -> bool {
    use AliasPlanDispositionV1::{Create, NoOp, Repair};
    matches!(
        (planned, prepared),
        (Create, Create | Repair | NoOp) | (Repair, Repair | NoOp) | (NoOp, NoOp)
    )
}

fn verify_python_prepared_onboarding_context_v1(
    context: &PythonPreparedOnboardingContextV1,
    signed: &SignedTransaction,
    expected_network_id: &NetworkId,
    expected_authority: &AccountId,
    expected_semantic_hash: &[u8; Hash::LENGTH],
) -> PyResult<()> {
    let expected_account_id =
        parse_exact_i105_account_id(&context.account_id, "prepared onboarding account_id")?;
    let (receipt_hash, planned_instructions) = verify_python_account_onboarding_receipt_v1(
        &context.receipt,
        expected_network_id,
        expected_authority,
        &expected_account_id,
        &context.account_id,
        &context.alias,
        &context.receipt.body.request.permissions,
    )?;
    if receipt_hash.as_ref() != expected_semantic_hash
        || !python_onboarding_disposition_transition_allowed(
            context.receipt.body.resource.disposition,
            context.disposition,
        )
    {
        return Err(PyValueError::new_err(
            "prepared onboarding semantic receipt or live disposition was substituted",
        ));
    }
    let Executable::Instructions(instructions) = signed.instructions() else {
        return Err(PyValueError::new_err(
            "prepared onboarding transaction must contain direct instructions",
        ));
    };
    if instructions.is_empty()
        || !python_instructions_are_ordered_subset(instructions.as_ref(), &planned_instructions)
    {
        return Err(PyValueError::new_err(
            "prepared onboarding instructions differ from the authenticated receipt",
        ));
    }
    Ok(())
}

fn canonical_python_account_faucet_claim_v1(
    claim: &PythonAccountFaucetClaimV1,
) -> PyResult<(AccountId, Hash)> {
    let account_id = parse_exact_i105_account_id(&claim.account_id, "faucet claim account_id")?;
    if claim.pow_anchor_height == 0 {
        return Err(PyValueError::new_err(
            "faucet claim proof anchor height must be a positive u64",
        ));
    }
    let nonce = claim.pow_nonce_hex.as_str();
    if nonce.is_empty()
        || nonce.len() > 64
        || !nonce.len().is_multiple_of(2)
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PyValueError::new_err(
            "faucet claim proof nonce must be 1..32 bytes of canonical lowercase hexadecimal",
        ));
    }
    use norito::codec::Encode as _;
    let encoded_claim = claim.encode();
    let claim_hash = Hash::new_from_chunks(&[
        ACCOUNT_FAUCET_CLAIM_HASH_DOMAIN_V1,
        encoded_claim.as_slice(),
    ]);
    Ok((account_id, claim_hash))
}

#[pyfunction]
#[pyo3(name = "account_faucet_claim_hash_v1")]
/// Hash the exact canonical solved faucet claim for its prepared-operation binding.
fn account_faucet_claim_hash_v1_py(
    account_id: &str,
    pow_anchor_height: u64,
    pow_nonce_hex: &str,
) -> PyResult<String> {
    let claim = PythonAccountFaucetClaimV1 {
        account_id: account_id.to_owned(),
        pow_anchor_height,
        pow_nonce_hex: pow_nonce_hex.to_owned(),
    };
    let (_, hash) = canonical_python_account_faucet_claim_v1(&claim)?;
    Ok(hex_encode(hash.as_ref()))
}
fn verify_python_prepared_faucet_context_v1(
    context: &PythonPreparedFaucetContextV1,
    signed: &SignedTransaction,
    expected_semantic_hash: &[u8; Hash::LENGTH],
) -> PyResult<()> {
    if context.claim.account_id != context.account_id {
        return Err(PyValueError::new_err(
            "prepared faucet account differs from its exact claim",
        ));
    }
    let (account_id, claim_hash) = canonical_python_account_faucet_claim_v1(&context.claim)?;
    if claim_hash.as_ref() != expected_semantic_hash {
        return Err(PyValueError::new_err(
            "prepared faucet semantic hash differs from its exact claim",
        ));
    }
    let asset_definition_id = context
        .asset_definition_id
        .parse::<AssetDefinitionId>()
        .map_err(|error| {
            PyValueError::new_err(format!(
                "prepared faucet asset_definition_id is invalid: {error}"
            ))
        })?;
    if asset_definition_id.to_string() != context.asset_definition_id {
        return Err(PyValueError::new_err(
            "prepared faucet asset_definition_id is not canonical",
        ));
    }
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let parsed_destination_asset_id = context.asset_id.parse::<AssetId>().map_err(|error| {
        PyValueError::new_err(format!("prepared faucet asset_id is invalid: {error}"))
    })?;
    let expected_asset_literal = format!("{}#{}", context.asset_definition_id, context.account_id);
    if context.asset_id != expected_asset_literal
        || parsed_destination_asset_id != destination_asset_id
    {
        return Err(PyValueError::new_err(
            "prepared faucet destination asset differs from its exact claim",
        ));
    }
    let source_asset_id = AssetId::new(asset_definition_id, signed.authority().clone());
    let transfer: InstructionBox =
        Transfer::asset_quantity(source_asset_id, context.amount.clone(), account_id.clone())
            .into();
    let without_registration = vec![transfer.clone()];
    let with_registration = vec![
        InstructionBox::from(Register::account(Account::new(account_id))),
        transfer,
    ];
    let Executable::Instructions(instructions) = signed.instructions() else {
        return Err(PyValueError::new_err(
            "prepared faucet transaction must contain direct instructions",
        ));
    };
    if instructions.as_ref() != without_registration.as_slice()
        && instructions.as_ref() != with_registration.as_slice()
    {
        return Err(PyValueError::new_err(
            "prepared faucet instructions differ from its exact claim",
        ));
    }
    Ok(())
}

#[pyfunction]
#[pyo3(name = "verify_prepared_transaction_context_v1")]
/// Authenticate one fixed-V1 prepared transaction and its exact public operation context.
#[expect(
    clippy::too_many_arguments,
    reason = "the Python verification boundary binds each independently supplied prepared context field"
)]
fn verify_prepared_transaction_context_v1_py(
    signed_transaction_versioned: &[u8],
    network_id: &PyNetworkId,
    expected_authority: &str,
    binding_json: &str,
    operation: &str,
    semantic_hash_hex: &str,
    fee_payment_json: &str,
    operation_context_json: &str,
) -> PyResult<SignedTransactionEnvelope> {
    if !matches!(operation, "onboarding" | "faucet") {
        return Err(PyValueError::new_err(
            "prepared transaction operation must be onboarding or faucet",
        ));
    }
    let semantic_hash = parse_lower_hex_32(semantic_hash_hex, "prepared semantic hash")?;
    let expected_authority = parse_exact_i105_account_id(
        expected_authority,
        "prepared transaction expected authority",
    )?;
    let binding_value = require_prepared_binding_json_v1(binding_json, operation)?;
    if binding_value
        .get("semantic_hash_hex")
        .and_then(norito::json::Value::as_str)
        != Some(semantic_hash_hex)
    {
        return Err(PyValueError::new_err(
            "prepared binding semantic hash differs from its envelope",
        ));
    }
    let binding = Json::from_norito_value_ref(&binding_value).map_err(|error| {
        PyValueError::new_err(format!("invalid prepared mutation binding: {error}"))
    })?;
    let expected_fee_payment = parse_fee_payment_intent_json(fee_payment_json)?;
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    signed.verify_signature().map_err(|_| {
        PyValueError::new_err("prepared transaction has an invalid authority signature")
    })?;
    if signed.network_id() != Some(network_id.as_inner())
        || signed.authority() != &expected_authority
        || signed.payload().fee_payment != expected_fee_payment
    {
        return Err(PyValueError::new_err(
            "prepared transaction network, authority, or fee payment was substituted",
        ));
    }
    let deadline = binding_value
        .get("execution_expires_at_unix_ms")
        .and_then(norito::json::Value::as_u64)
        .expect("prepared binding parser requires positive u64 deadline");
    let transaction_expiry = signed
        .payload()
        .time_to_live_ms
        .and_then(|ttl| signed.payload().creation_time_ms.checked_add(ttl.get()));
    if transaction_expiry.is_none_or(|expiry| expiry > deadline) {
        return Err(PyValueError::new_err(
            "prepared transaction outlives its operation binding",
        ));
    }
    let mut expected_metadata = Metadata::default();
    expected_metadata.insert(
        "prepared_operation_binding"
            .parse::<Name>()
            .expect("static prepared binding metadata key"),
        binding,
    );
    expected_metadata.insert(
        "prepared_operation"
            .parse::<Name>()
            .expect("static prepared operation metadata key"),
        Json::new(operation.to_owned()),
    );
    expected_metadata.insert(
        "prepared_semantic_hash"
            .parse::<Name>()
            .expect("static prepared semantic-hash metadata key"),
        Json::new(semantic_hash_hex.to_owned()),
    );
    if operation == "faucet" {
        expected_metadata.insert(
            iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY
                .parse::<Name>()
                .expect("static faucet claim marker metadata key"),
            Json::new(iroha_data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_V1),
        );
    }
    if signed.metadata() != &expected_metadata {
        return Err(PyValueError::new_err(
            "prepared transaction metadata differs from its exact binding",
        ));
    }
    match operation {
        "onboarding" => {
            let context =
                json::from_str::<PythonPreparedOnboardingContextV1>(operation_context_json)
                    .map_err(|error| {
                        PyValueError::new_err(format!(
                            "invalid prepared onboarding operation context JSON: {error}"
                        ))
                    })?;
            if binding_value
                .get("execution_expires_at_unix_ms")
                .and_then(norito::json::Value::as_u64)
                .is_none_or(|deadline| deadline > context.receipt.body.valid_until_ms)
            {
                return Err(PyValueError::new_err(
                    "prepared binding deadline exceeds receipt validity",
                ));
            }
            verify_python_prepared_onboarding_context_v1(
                &context,
                &signed,
                network_id.as_inner(),
                &expected_authority,
                &semantic_hash,
            )?;
        }
        "faucet" => {
            let context = json::from_str::<PythonPreparedFaucetContextV1>(operation_context_json)
                .map_err(|error| {
                PyValueError::new_err(format!(
                    "invalid prepared faucet operation context JSON: {error}"
                ))
            })?;
            verify_python_prepared_faucet_context_v1(&context, &signed, &semantic_hash)?;
        }
        _ => unreachable!("operation was closed above"),
    }
    signed_transaction_envelope_from_model_v1(&signed)
}
const PRIVACY_EXACT12_ACTION_DRIVER_SEED_DOMAIN_V1: &[u8] =
    b"iroha.taira.privacy_action_driver_seed.v1\0";
fn privacy_exact12_action_driver_signing_seed_v1(
    candidate_binding_sha256: [u8; 32],
    request_id: [u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(PRIVACY_EXACT12_ACTION_DRIVER_SEED_DOMAIN_V1);
    hash.update(candidate_binding_sha256);
    hash.update(request_id);
    hash.update([0]);
    let mut seed = Zeroizing::<[u8; 32]>::new(hash.finalize().into());
    if seed.iter().all(|byte| *byte == 0) {
        seed[0] = 1;
    }
    seed
}
#[pyfunction]
#[pyo3(name = "inspect_privacy_exact12_action_driver_transaction_context_v1")]
/// Authenticate one action-driver transaction and enforce its complete public request context.
#[allow(clippy::too_many_arguments)]
fn inspect_privacy_exact12_action_driver_transaction_context_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
    candidate_binding_sha256: &[u8],
    request_id: &[u8],
    expected_network_id: &PyNetworkId,
    expected_creation_time_millis: u64,
    expected_ttl_millis: u64,
    expected_nonce: u32,
) -> PyResult<Py<PyDict>> {
    let candidate_binding_sha256 =
        fixed_array::<32>(candidate_binding_sha256, "candidate_binding_sha256")?;
    let request_id = fixed_array::<32>(request_id, "request_id")?;
    if candidate_binding_sha256 == [0; 32] || request_id == [0; 32] {
        return Err(PyValueError::new_err(
            "candidate_binding_sha256 and request_id must be nonzero",
        ));
    }
    let expected_nonce = NonZeroU32::new(expected_nonce)
        .ok_or_else(|| PyValueError::new_err("expected_nonce must be nonzero"))?;
    if expected_creation_time_millis == 0 || expected_ttl_millis == 0 {
        return Err(PyValueError::new_err(
            "expected transaction time fields must be nonzero",
        ));
    }
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    signed.verify_signature().map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned has an invalid authority signature")
    })?;
    if signed.network_id() != Some(&expected_network_id.inner) {
        return Err(PyValueError::new_err(
            "signed transaction does not match the expected NetworkId",
        ));
    }
    let signing_seed =
        privacy_exact12_action_driver_signing_seed_v1(candidate_binding_sha256, request_id);
    let private_key = PrivateKey::from_bytes(Algorithm::Ed25519, signing_seed.as_ref())
        .map_err(|_| PyRuntimeError::new_err("could not derive the expected action-driver key"))?;
    let expected_public_key = PublicKey::from(private_key);
    let expected_authority = AccountId::new(expected_public_key.clone());
    if signed.authority() != &expected_authority {
        return Err(PyValueError::new_err(
            "signed transaction authority does not match candidate and request",
        ));
    }
    if signed.creation_time().as_millis() != u128::from(expected_creation_time_millis)
        || signed.time_to_live().map(|ttl| ttl.as_millis()) != Some(u128::from(expected_ttl_millis))
        || signed.nonce() != Some(expected_nonce)
    {
        return Err(PyValueError::new_err(
            "signed transaction time or nonce differs from the exact request",
        ));
    }
    if !matches!(
        signed.fee_payment_intent(),
        FeePaymentIntent::Authority(payment)
            if payment.charge_limits.is_empty() && payment.gas_limit.is_none()
    ) {
        return Err(PyValueError::new_err(
            "signed transaction fee intent is not the empty authority-paid qualification intent",
        ));
    }
    if !signed.metadata().is_empty() {
        return Err(PyValueError::new_err(
            "signed transaction metadata is not the empty qualification metadata",
        ));
    }
    if signed.multisig_signatures().is_some() {
        return Err(PyValueError::new_err(
            "signed action-driver transaction must use one direct authority signature",
        ));
    }
    let (intent, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| {
            PyValueError::new_err(
                "signed transaction has an invalid privacy transaction-intent binding",
            )
        })?
        .ok_or_else(|| PyValueError::new_err("signed transaction has no direct privacy action"))?;
    let statement_context = submission.envelope.statement.context();
    if statement_context.network_id != expected_network_id.inner
        || statement_context.action_index != 0
        || statement_context.transaction_intent_digest != intent
    {
        return Err(PyValueError::new_err(
            "signed privacy statement context differs from the exact transaction context",
        ));
    }
    let (_, expected_public_key_bytes) =
        public_key_to_bytes(&expected_public_key, "action-driver public key")?;
    let transaction_hash = signed.hash();
    let result = PyDict::new(py);
    result.set_item(
        "transaction_hash",
        PyBytes::new(py, transaction_hash.as_ref()),
    )?;
    result.set_item(
        "network_id",
        PyBytes::new(py, expected_network_id.inner.as_bytes()),
    )?;
    result.set_item(
        "statement_network_id",
        PyBytes::new(py, statement_context.network_id.as_bytes()),
    )?;
    result.set_item("statement_action_index", statement_context.action_index)?;
    result.set_item("authority", expected_authority.to_string())?;
    result.set_item(
        "authority_public_key",
        PyBytes::new(py, expected_public_key_bytes),
    )?;
    result.set_item("creation_time_millis", expected_creation_time_millis)?;
    result.set_item("ttl_millis", expected_ttl_millis)?;
    result.set_item("nonce", expected_nonce.get())?;
    result.set_item("fee_payment", "authority-empty-v1")?;
    result.set_item("metadata", "empty-v1")?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "privacy_vega_device_authentication_digest_v1")]
/// Request `H_dev` for an already prepared, explicit nonzero transaction intent.
///
/// This public entry point fails closed with `RuntimeError` while the exact Vega compiled profile
/// is not governance-available; it never derives against candidate or placeholder profile material.
#[allow(clippy::too_many_arguments)]
fn privacy_vega_device_authentication_digest_v1_py(
    py: Python<'_>,
    network_id: &PyNetworkId,
    transaction_intent_digest: &[u8],
    issuer_id: &[u8],
    issuer_record_epoch: u64,
    issuer_record_digest: &[u8],
    issuer_public_key: &[u8],
    presentation_year: u16,
    presentation_month: u8,
    presentation_day: u8,
    minimum_age_years: u8,
    reader_challenge: &[u8],
    session_transcript_digest: &[u8],
) -> PyResult<Py<PyBytes>> {
    let transaction_intent_digest = PrivacyTransactionIntentDigestV1::new(
        python_nonzero_privacy_digest_v1(transaction_intent_digest, "transaction_intent_digest")?,
    );
    let issuer_id = python_nonzero_privacy_digest_v1(issuer_id, "issuer_id")?;
    if issuer_record_epoch == 0 {
        return Err(PyValueError::new_err(
            "issuer_record_epoch must be non-zero",
        ));
    }
    let issuer_record_digest =
        python_nonzero_privacy_digest_v1(issuer_record_digest, "issuer_record_digest")?;
    let issuer_public_key = fixed_array::<33>(issuer_public_key, "issuer_public_key")?;
    let reader_challenge = python_nonzero_privacy_digest_v1(reader_challenge, "reader_challenge")?;
    let session_transcript_digest =
        python_nonzero_privacy_digest_v1(session_transcript_digest, "session_transcript_digest")?;
    let profile = python_compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        "Vega",
    )?;
    let statement = python_vega_statement_v1(
        PrivacyStatementContextV1 {
            network_id: network_id.inner,
            action_index: 0,
            transaction_intent_digest,
            parameter_id: profile.parameter_id,
            parameter_digest: profile.parameter_digest,
            verifier_digest: profile.verifier_digest,
            statement_schema_digest: profile.statement_schema_digest,
            engine_manifest_digest: profile.engine_manifest_digest,
        },
        *network_id.inner.as_bytes(),
        issuer_id,
        issuer_record_epoch,
        issuer_record_digest,
        issuer_public_key,
        presentation_year,
        presentation_month,
        presentation_day,
        minimum_age_years,
        reader_challenge,
        session_transcript_digest,
    )?;
    Ok(Py::from(PyBytes::new(
        py,
        statement.device_authentication_digest.as_bytes(),
    )))
}
fn python_authenticated_privacy_action_envelope_v1<'a>(
    signed: &'a SignedTransaction,
    expected_protocol_id: PrivacyProtocolIdV1,
    protocol_label: &str,
) -> PyResult<(PrivacyTransactionIntentDigestV1, &'a PrivacyProofEnvelopeV1)> {
    signed.verify_signature().map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned has an invalid authority signature")
    })?;
    let (transaction_intent_digest, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| {
            PyValueError::new_err(
                "signed_transaction_versioned has an invalid privacy intent binding",
            )
        })?
        .ok_or_else(|| {
            PyValueError::new_err("signed_transaction_versioned contains no direct privacy action")
        })?;
    let envelope = &submission.envelope;
    if envelope.protocol_id != expected_protocol_id {
        return Err(PyValueError::new_err(format!(
            "signed_transaction_versioned is not a {protocol_label} action"
        )));
    }
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| {
            PyValueError::new_err(format!(
                "signed_transaction_versioned has an invalid {protocol_label} proof envelope"
            ))
        })?;
    Ok((transaction_intent_digest, envelope))
}
fn python_privacy_action_inspection_result_v1<'py>(
    py: Python<'py>,
    signed: &SignedTransaction,
    signed_transaction_versioned: &[u8],
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
    envelope: &PrivacyProofEnvelopeV1,
    execution_classification: &str,
    ledger_effect: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    let statement_encoding = norito::to_bytes(&envelope.statement).map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned privacy statement could not be encoded")
    })?;
    let envelope_encoding = norito::to_bytes(envelope).map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned privacy envelope could not be encoded")
    })?;
    let statement_bytes = u32::try_from(statement_encoding.len())
        .map_err(|_| PyValueError::new_err("privacy statement byte length overflowed"))?;
    let proof_bytes = u32::try_from(envelope.proof.bytes().as_bytes().len())
        .map_err(|_| PyValueError::new_err("privacy proof byte length overflowed"))?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| PyValueError::new_err("privacy envelope byte length overflowed"))?;
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(signed).len())
            .map_err(|_| PyValueError::new_err("adaptive transaction byte length overflowed"))?;
    let submitted_versioned_transaction_bytes =
        u32::try_from(signed_transaction_versioned.len())
            .map_err(|_| PyValueError::new_err("versioned transaction byte length overflowed"))?;
    let proof_envelope_hash = Hash::new(&envelope_encoding);
    let transaction_hash = signed.hash();
    let result = PyDict::new(py);
    result.set_item(
        "transaction_hash",
        PyBytes::new(py, transaction_hash.as_ref()),
    )?;
    result.set_item(
        "transaction_intent_digest",
        PyBytes::new(py, transaction_intent_digest.as_bytes()),
    )?;
    result.set_item(
        "statement_digest",
        PyBytes::new(py, envelope.statement_digest.as_bytes()),
    )?;
    result.set_item(
        "proof_envelope_hash",
        PyBytes::new(py, proof_envelope_hash.as_ref()),
    )?;
    result.set_item("protocol_id", envelope.protocol_id.canonical_label())?;
    result.set_item("statement_bytes", statement_bytes)?;
    result.set_item("proof_bytes", proof_bytes)?;
    result.set_item("encoded_proof_envelope_bytes", encoded_proof_envelope_bytes)?;
    result.set_item(
        "adaptive_signed_transaction_bytes",
        adaptive_signed_transaction_bytes,
    )?;
    result.set_item(
        "submitted_versioned_transaction_bytes",
        submitted_versioned_transaction_bytes,
    )?;
    result.set_item("execution_classification", execution_classification)?;
    match ledger_effect {
        Some(effect) => result.set_item("ledger_effect", effect)?,
        None => result.set_item("ledger_effect", py.None())?,
    }
    Ok(result)
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_zk_ace_transfer_action_v1")]
/// Authenticate and inspect exactly one native ZK-ACE transparent transfer.
fn inspect_signed_privacy_zk_ace_transfer_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    let (transaction_intent_digest, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        "ZK-ACE",
    )?;
    let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-ACE statement",
        ));
    };
    if !matches!(&envelope.proof, PrivacyProofV1::ZkAcePqAuthorizationV1(_)) {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-ACE proof variant",
        ));
    }
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        ZK_ACE_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(ZK_ACE_TRANSFER_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "transparent_transfer")?;
    result.set_item(
        "identity_commitment",
        PyBytes::new(py, statement.identity_commitment.as_bytes()),
    )?;
    result.set_item(
        "policy_id",
        PyBytes::new(py, statement.policy_id.as_bytes()),
    )?;
    result.set_item(
        "policy_digest",
        PyBytes::new(py, statement.policy_digest.as_bytes()),
    )?;
    result.set_item("source_account_id", statement.source.to_string())?;
    result.set_item("destination_account_id", statement.destination.to_string())?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item(
        "public_balance_scope",
        canonical_public_balance_scope_py(statement.public_balance_scope)?,
    )?;
    result.set_item("amount", statement.amount.to_string())?;
    result.set_item("authorization_epoch", statement.authorization_epoch)?;
    result.set_item(
        "replay_nullifier",
        PyBytes::new(py, statement.replay_nullifier.as_bytes()),
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_jindo_action_v1")]
/// Authenticate and inspect the exact public metadata carried by one Jindo action.
fn inspect_signed_privacy_jindo_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    signed.verify_signature().map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned has an invalid authority signature")
    })?;
    let (transaction_intent_digest, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| {
            PyValueError::new_err(
                "signed_transaction_versioned has an invalid privacy intent binding",
            )
        })?
        .ok_or_else(|| {
            PyValueError::new_err("signed_transaction_versioned contains no direct privacy action")
        })?;
    let envelope = &submission.envelope;
    if envelope.protocol_id != PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1 {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned is not a Jindo action",
        ));
    }
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| {
            PyValueError::new_err(
                "signed_transaction_versioned has an invalid Jindo proof envelope",
            )
        })?;
    let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) = &envelope.statement
    else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched Jindo statement",
        ));
    };
    let statement_encoding = norito::to_bytes(&envelope.statement).map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned Jindo statement could not be encoded")
    })?;
    let envelope_encoding = norito::to_bytes(envelope).map_err(|_| {
        PyValueError::new_err("signed_transaction_versioned Jindo envelope could not be encoded")
    })?;
    let statement_bytes = u32::try_from(statement_encoding.len())
        .map_err(|_| PyValueError::new_err("Jindo statement byte length overflowed"))?;
    let proof_bytes = u32::try_from(envelope.proof.bytes().as_bytes().len())
        .map_err(|_| PyValueError::new_err("Jindo proof byte length overflowed"))?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| PyValueError::new_err("Jindo envelope byte length overflowed"))?;
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(&signed).len())
            .map_err(|_| PyValueError::new_err("adaptive transaction byte length overflowed"))?;
    let submitted_versioned_transaction_bytes =
        u32::try_from(signed_transaction_versioned.len())
            .map_err(|_| PyValueError::new_err("versioned transaction byte length overflowed"))?;
    let polynomial_count = u32::try_from(statement.polynomial_commitments.len())
        .map_err(|_| PyValueError::new_err("Jindo polynomial count overflowed"))?;
    let proof_envelope_hash = Hash::new(&envelope_encoding);
    let transaction_hash = signed.hash();
    let result = PyDict::new(py);
    result.set_item(
        "transaction_hash",
        PyBytes::new(py, transaction_hash.as_ref()),
    )?;
    result.set_item(
        "transaction_intent_digest",
        PyBytes::new(py, transaction_intent_digest.as_bytes()),
    )?;
    result.set_item(
        "statement_digest",
        PyBytes::new(py, envelope.statement_digest.as_bytes()),
    )?;
    result.set_item(
        "proof_envelope_hash",
        PyBytes::new(py, proof_envelope_hash.as_ref()),
    )?;
    result.set_item("statement_bytes", statement_bytes)?;
    result.set_item("proof_bytes", proof_bytes)?;
    result.set_item("encoded_proof_envelope_bytes", encoded_proof_envelope_bytes)?;
    result.set_item(
        "adaptive_signed_transaction_bytes",
        adaptive_signed_transaction_bytes,
    )?;
    result.set_item(
        "submitted_versioned_transaction_bytes",
        submitted_versioned_transaction_bytes,
    )?;
    result.set_item("polynomial_count", polynomial_count)?;
    result.set_item("construction_state", "constructed")?;
    result.set_item(
        "missing_evidence",
        PyList::new(py, ["MissingDistributionWideKnowledgeSoundnessEvidence"])?,
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_verange_action_v1")]
/// Authenticate and inspect the exact public metadata carried by one VeRange action.
fn inspect_signed_privacy_verange_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    let (transaction_intent_digest, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
        "VeRange",
    )?;
    let PrivacyStatementV1::VeRangeTransparentRangeV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched VeRange statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        VERANGE_ACTION_EXECUTION_CLASSIFICATION_V1,
        None,
    )?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item(
        "policy_id",
        PyBytes::new(py, statement.policy_id.as_bytes()),
    )?;
    result.set_item("bit_length", statement.bit_length.bits())?;
    result.set_item("aggregation_count", statement.aggregation_count)?;
    let commitments = PyList::empty(py);
    for commitment in &statement.value_commitments {
        commitments.append(PyBytes::new(py, commitment.as_bytes()))?;
    }
    result.set_item("value_commitments", commitments)?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_vega_action_v1")]
/// Authenticate and inspect the exact public metadata carried by one Vega action.
fn inspect_signed_privacy_vega_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    let (transaction_intent_digest, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        "Vega",
    )?;
    let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched Vega statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        VEGA_ACTION_EXECUTION_CLASSIFICATION_V1,
        None,
    )?;
    result.set_item("document_type", "org.iso.18013.5.1.mDL")?;
    result.set_item("namespace", "org.iso.18013.5.1")?;
    result.set_item("digest_algorithm", "SHA-256")?;
    result.set_item("issuer_authentication_algorithm", "COSE_Sign1/ES256")?;
    result.set_item("device_authentication_algorithm", "COSE_Sign1/ES256")?;
    result.set_item(
        "issuer_id",
        PyBytes::new(py, statement.issuer_id.as_bytes()),
    )?;
    result.set_item("issuer_record_epoch", statement.issuer_record_epoch)?;
    result.set_item(
        "issuer_record_digest",
        PyBytes::new(py, statement.issuer_record_digest.as_bytes()),
    )?;
    result.set_item(
        "issuer_public_key",
        PyBytes::new(py, statement.issuer_public_key.as_bytes()),
    )?;
    result.set_item(
        "device_authentication_digest",
        PyBytes::new(py, statement.device_authentication_digest.as_bytes()),
    )?;
    result.set_item("presentation_year", statement.presentation_date.year)?;
    result.set_item("presentation_month", statement.presentation_date.month)?;
    result.set_item("presentation_day", statement.presentation_date.day)?;
    result.set_item("minimum_age_years", statement.minimum_age_years)?;
    result.set_item(
        "reader_challenge",
        PyBytes::new(py, statement.reader_challenge.as_bytes()),
    )?;
    result.set_item(
        "session_transcript_digest",
        PyBytes::new(py, statement.session_transcript_digest.as_bytes()),
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_zk_x509_identity_presentation_action_v1")]
/// Authenticate and inspect one exact ZK-X509 identity presentation.
fn inspect_signed_privacy_zk_x509_identity_presentation_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
    network_id: &PyNetworkId,
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    crate::privacy_native_actions::inspect_signed_privacy_zk_x509_identity_presentation_action_v1(
        &signed,
        *network_id.inner.as_bytes(),
    )
    .map_err(|error| {
        PyValueError::new_err(format!(
            "invalid ZK-X509 signed action at {}",
            error.stage()
        ))
    })?;
    let (intent, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        "ZK-X509",
    )?;
    let PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-X509 statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        intent,
        envelope,
        ZK_X509_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(ZK_X509_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "identity_presentation")?;
    result.set_item(
        "trust_anchor_id",
        PyBytes::new(py, statement.trust_anchor_id.as_bytes()),
    )?;
    result.set_item(
        "certificate_policy_id",
        PyBytes::new(py, statement.certificate_policy_id.as_bytes()),
    )?;
    result.set_item(
        "trust_anchor_record_digest",
        PyBytes::new(py, statement.trust_anchor_record_digest.as_bytes()),
    )?;
    result.set_item(
        "trust_anchor_record_epoch",
        statement.trust_anchor_record_epoch,
    )?;
    result.set_item(
        "certificate_policy_record_digest",
        PyBytes::new(py, statement.certificate_policy_record_digest.as_bytes()),
    )?;
    result.set_item(
        "certificate_policy_record_epoch",
        statement.certificate_policy_record_epoch,
    )?;
    result.set_item(
        "crl_record_digest",
        PyBytes::new(py, statement.crl_record_digest.as_bytes()),
    )?;
    result.set_item("crl_record_epoch", statement.crl_record_epoch)?;
    result.set_item(
        "subject_public_key_digest",
        PyBytes::new(py, statement.subject_public_key_digest.as_bytes()),
    )?;
    result.set_item(
        "ca_membership_root",
        PyBytes::new(py, statement.ca_membership_root.as_bytes()),
    )?;
    result.set_item(
        "ca_membership_root_epoch",
        statement.ca_membership_root_epoch,
    )?;
    let key_usage = PyDict::new(py);
    key_usage.set_item(
        "digital_signature",
        statement.key_usage.digital_signature.is_required(),
    )?;
    key_usage.set_item(
        "content_commitment",
        statement.key_usage.content_commitment.is_required(),
    )?;
    key_usage.set_item(
        "key_encipherment",
        statement.key_usage.key_encipherment.is_required(),
    )?;
    key_usage.set_item(
        "key_agreement",
        statement.key_usage.key_agreement.is_required(),
    )?;
    result.set_item("key_usage", key_usage)?;
    let extended_key_usages = PyList::empty(py);
    for usage in &statement.extended_key_usages {
        let label = match usage {
            PrivacyX509ExtendedKeyUsageV1::ClientAuthentication => "client_authentication",
            PrivacyX509ExtendedKeyUsageV1::DocumentSigning => "document_signing",
            PrivacyX509ExtendedKeyUsageV1::WalletIdentity => "wallet_identity",
        };
        extended_key_usages.append(label)?;
    }
    result.set_item("extended_key_usages", extended_key_usages)?;
    let disclosed_attributes = PyList::empty(py);
    for disclosed in &statement.disclosed_attributes {
        let item = PyDict::new(py);
        item.set_item("index", disclosed.index)?;
        item.set_item(
            "attribute_digest",
            PyBytes::new(py, disclosed.attribute_digest.as_bytes()),
        )?;
        disclosed_attributes.append(item)?;
    }
    result.set_item("disclosed_attributes", disclosed_attributes)?;
    result.set_item(
        "presentation_not_before_unix_seconds",
        statement.presentation_not_before_unix_seconds,
    )?;
    result.set_item(
        "presentation_not_after_unix_seconds",
        statement.presentation_not_after_unix_seconds,
    )?;
    result.set_item("wallet_account", statement.wallet_account.to_string())?;
    result.set_item(
        "wallet_challenge",
        PyBytes::new(py, statement.wallet_challenge.as_bytes()),
    )?;
    result.set_item(
        "certificate_nullifier",
        PyBytes::new(py, statement.certificate_nullifier.as_bytes()),
    )?;
    Ok(result.unbind())
}
fn python_zk_ams_action_inspection_result_v1<'py>(
    py: Python<'py>,
    signed: &SignedTransaction,
    signed_transaction_versioned: &[u8],
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
    envelope: &PrivacyProofEnvelopeV1,
    statement: &IrohaZkAmsStatementV1,
    ledger_effect: &'static str,
) -> PyResult<Bound<'py, PyDict>> {
    let result = python_privacy_action_inspection_result_v1(
        py,
        signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        ZK_AMS_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(ledger_effect),
    )?;
    result.set_item(
        "issuer_id",
        PyBytes::new(py, statement.issuer_id.as_bytes()),
    )?;
    result.set_item(
        "issuer_public_key",
        PyBytes::new(py, statement.issuer_public_key.as_bytes()),
    )?;
    result.set_item(
        "issuer_policy_record_digest",
        PyBytes::new(py, statement.issuer_policy_record_digest.as_bytes()),
    )?;
    result.set_item(
        "registry_id",
        PyBytes::new(py, statement.registry_id.as_bytes()),
    )?;
    result.set_item(
        "registry_record_digest",
        PyBytes::new(py, statement.registry_record_digest.as_bytes()),
    )?;
    result.set_item(
        "policy_id",
        PyBytes::new(py, statement.policy_id.as_bytes()),
    )?;
    result.set_item(
        "policy_digest",
        PyBytes::new(py, statement.policy_digest.as_bytes()),
    )?;
    Ok(result)
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_zk_ams_batch_admission_action_v1")]
/// Authenticate and inspect exactly one ZK-AMS batch-admission action.
fn inspect_signed_privacy_zk_ams_batch_admission_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    let (transaction_intent_digest, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        "ZK-AMS",
    )?;
    let PrivacyStatementV1::IrohaZkAmsV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-AMS statement",
        ));
    };
    let PrivacyZkAmsActionV1::BatchAdmission(batch) = &statement.action else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned is not a ZK-AMS batch-admission action",
        ));
    };
    if !matches!(
        &envelope.proof,
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(_))
    ) {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-AMS batch-admission proof variant",
        ));
    }
    let result = python_zk_ams_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        statement,
        ZK_AMS_BATCH_ADMISSION_LEDGER_EFFECT_V1,
    )?;
    result.set_item("action_kind", "batch_admission")?;
    result.set_item(
        "account_registry_root",
        PyBytes::new(py, batch.account_registry_root.as_bytes()),
    )?;
    result.set_item(
        "account_registry_root_epoch",
        batch.account_registry_root_epoch,
    )?;
    result.set_item(
        "next_account_registry_root",
        PyBytes::new(py, batch.next_account_registry_root.as_bytes()),
    )?;
    result.set_item(
        "next_account_registry_root_epoch",
        batch.next_account_registry_root_epoch,
    )?;
    result.set_item(
        "anchor_count",
        u32::try_from(batch.anchors.len())
            .map_err(|_| PyValueError::new_err("ZK-AMS anchor count overflowed"))?,
    )?;
    let phc_hashes = PyList::empty(py);
    let seed_public_keys = PyList::empty(py);
    for anchor in &batch.anchors {
        phc_hashes.append(PyBytes::new(py, anchor.phc_hash.as_bytes()))?;
        seed_public_keys.append(PyBytes::new(py, anchor.seed_public_key.as_bytes()))?;
    }
    result.set_item("phc_hashes", phc_hashes)?;
    result.set_item("seed_public_keys", seed_public_keys)?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_zk_ams_provision_account_action_v1")]
/// Authenticate and inspect exactly one ZK-AMS account-provisioning action.
fn inspect_signed_privacy_zk_ams_provision_account_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    let (transaction_intent_digest, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::IrohaZkAmsV1,
        "ZK-AMS",
    )?;
    let PrivacyStatementV1::IrohaZkAmsV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-AMS statement",
        ));
    };
    let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &statement.action else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned is not a ZK-AMS account-provisioning action",
        ));
    };
    if !matches!(
        &envelope.proof,
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(_))
    ) {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched ZK-AMS account-provisioning proof variant",
        ));
    }
    let result = python_zk_ams_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        statement,
        ZK_AMS_PROVISION_ACCOUNT_LEDGER_EFFECT_V1,
    )?;
    result.set_item("action_kind", "provision_account")?;
    result.set_item(
        "account_registry_root",
        PyBytes::new(py, provision.account_registry_root.as_bytes()),
    )?;
    result.set_item(
        "account_registry_root_epoch",
        provision.account_registry_root_epoch,
    )?;
    result.set_item(
        "ring_size",
        u32::try_from(provision.admitted_seed_key_ring.len())
            .map_err(|_| PyValueError::new_err("ZK-AMS ring size overflowed"))?,
    )?;
    let ring = PyList::empty(py);
    for key in &provision.admitted_seed_key_ring {
        ring.append(PyBytes::new(py, key.as_bytes()))?;
    }
    result.set_item("admitted_seed_key_ring", ring)?;
    result.set_item("account_id", provision.account_id.to_string())?;
    result.set_item(
        "key_image",
        PyBytes::new(py, provision.key_image.as_bytes()),
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_bootle_lantern_presentation_action_v1")]
/// Authenticate and inspect exactly one Bootle/Lantern presentation action.
fn inspect_signed_privacy_bootle_lantern_presentation_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    let (transaction_intent_digest, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        "Bootle/Lantern",
    )?;
    let PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched Bootle/Lantern statement",
        ));
    };
    if !matches!(
        &envelope.proof,
        PrivacyProofV1::IrohaBootleLanternAnoncredV1(_)
    ) {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched Bootle/Lantern proof variant",
        ));
    }
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        transaction_intent_digest,
        envelope,
        BOOTLE_LANTERN_ACTION_EXECUTION_CLASSIFICATION_V1,
        None,
    )?;
    result.set_item("action_kind", "presentation")?;
    result.set_item(
        "issuer_id",
        PyBytes::new(py, statement.issuer_id.as_bytes()),
    )?;
    result.set_item(
        "policy_id",
        PyBytes::new(py, statement.policy_id.as_bytes()),
    )?;
    result.set_item("issuer_policy_epoch", statement.issuer_policy_epoch)?;
    result.set_item(
        "issuer_policy_record_digest",
        PyBytes::new(py, statement.issuer_policy_record_digest.as_bytes()),
    )?;
    result.set_item(
        "issuer_parameter_id",
        PyBytes::new(py, statement.issuer_parameter_id.as_bytes()),
    )?;
    result.set_item(
        "issuer_parameter_digest",
        PyBytes::new(py, statement.issuer_parameter_digest.as_bytes()),
    )?;
    result.set_item(
        "disclosure_indices",
        statement
            .disclosures
            .iter()
            .map(|disclosure| disclosure.index)
            .collect::<Vec<_>>(),
    )?;
    let disclosed_values = PyList::empty(py);
    for disclosure in &statement.disclosures {
        disclosed_values.append(PyBytes::new(py, disclosure.value.as_bytes()))?;
    }
    result.set_item("disclosed_attribute_values", disclosed_values)?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_anonymous_pgc_payment_action_v1")]
/// Authenticate and inspect exactly one Anonymous-PGC payment action.
fn inspect_signed_privacy_anonymous_pgc_payment_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    crate::privacy_native_actions::inspect_signed_privacy_anonymous_pgc_payment_action_v1(&signed)
        .map_err(|error| {
            PyValueError::new_err(format!(
                "invalid Anonymous-PGC signed action at {}",
                error.stage()
            ))
        })?;
    let (intent, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        "Anonymous-PGC",
    )?;
    let PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched Anonymous-PGC statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        intent,
        envelope,
        ANONYMOUS_PGC_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(ANONYMOUS_PGC_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "payment")?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item("pool_id", PyBytes::new(py, statement.pool_id.as_bytes()))?;
    result.set_item(
        "account_state_root",
        PyBytes::new(py, statement.account_state_root.as_bytes()),
    )?;
    result.set_item(
        "account_state_root_epoch",
        statement.account_state_root_epoch,
    )?;
    result.set_item(
        "next_account_state_root",
        PyBytes::new(py, statement.next_account_state_root.as_bytes()),
    )?;
    result.set_item(
        "next_account_state_root_epoch",
        statement.next_account_state_root_epoch,
    )?;
    result.set_item("recipient_count", statement.recipient_count)?;
    result.set_item(
        "anonymity_set_size",
        u32::try_from(statement.anonymity_set_public_keys.len())
            .map_err(|_| PyValueError::new_err("Anonymous-PGC account count overflowed"))?,
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_orchard_note_action_v1")]
/// Authenticate and inspect exactly one Orchard note action.
fn inspect_signed_privacy_orchard_note_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    crate::privacy_native_actions::inspect_signed_privacy_orchard_note_action_v1(&signed).map_err(
        |error| {
            PyValueError::new_err(format!(
                "invalid Orchard signed action at {}",
                error.stage()
            ))
        },
    )?;
    let (intent, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        "Orchard",
    )?;
    let PrivacyStatementV1::OrchardHalo2ActionsV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched Orchard statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        intent,
        envelope,
        ORCHARD_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(ORCHARD_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "note_action")?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item(
        "public_balance_scope",
        canonical_public_balance_scope_py(statement.public_balance_scope)?,
    )?;
    result.set_item("pool_id", PyBytes::new(py, statement.pool_id.as_bytes()))?;
    result.set_item("anchor", PyBytes::new(py, statement.anchor.as_bytes()))?;
    result.set_item("anchor_epoch", statement.anchor_epoch)?;
    result.set_item("expiry_height", statement.expiry_height)?;
    result.set_item(
        "action_count",
        u32::try_from(statement.actions.len())
            .map_err(|_| PyValueError::new_err("Orchard action count overflowed"))?,
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_fcmp_membership_payment_action_v1")]
/// Authenticate and inspect exactly one FCMP++ membership payment.
fn inspect_signed_privacy_fcmp_membership_payment_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    crate::privacy_native_actions::inspect_signed_privacy_fcmp_membership_payment_action_v1(
        &signed,
    )
    .map_err(|error| {
        PyValueError::new_err(format!("invalid FCMP++ signed action at {}", error.stage()))
    })?;
    let (intent, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        "FCMP++",
    )?;
    let PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched FCMP++ statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        intent,
        envelope,
        FCMP_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(FCMP_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "membership_payment")?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item("pool_id", PyBytes::new(py, statement.pool_id.as_bytes()))?;
    result.set_item("root_epoch", statement.root_epoch)?;
    result.set_item(
        "input_count",
        u32::try_from(statement.inputs.len())
            .map_err(|_| PyValueError::new_err("FCMP++ input count overflowed"))?,
    )?;
    result.set_item(
        "output_count",
        u32::try_from(statement.outputs.len())
            .map_err(|_| PyValueError::new_err("FCMP++ output count overflowed"))?,
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_ivm_private_note_action_v1")]
/// Authenticate and inspect exactly one native private-IVM note action.
fn inspect_signed_privacy_ivm_private_note_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    crate::privacy_native_actions::inspect_signed_privacy_ivm_private_note_action_v1(&signed)
        .map_err(|error| {
            PyValueError::new_err(format!(
                "invalid private-IVM signed action at {}",
                error.stage()
            ))
        })?;
    let (intent, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        "private-IVM note",
    )?;
    let PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched private-IVM statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        intent,
        envelope,
        IVM_PRIVATE_NOTE_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(IVM_PRIVATE_NOTE_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "note_action")?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item(
        "public_balance_scope",
        canonical_public_balance_scope_py(statement.public_balance_scope)?,
    )?;
    result.set_item("pool_id", PyBytes::new(py, statement.pool_id.as_bytes()))?;
    result.set_item(
        "program_id",
        PyBytes::new(py, statement.program_id.as_bytes()),
    )?;
    result.set_item(
        "action_digest",
        PyBytes::new(py, statement.action_digest.as_bytes()),
    )?;
    result.set_item(
        "state_root",
        PyBytes::new(py, statement.state_root.as_bytes()),
    )?;
    result.set_item("root_epoch", statement.root_epoch)?;
    result.set_item("execution_epoch", statement.execution_epoch)?;
    result.set_item(
        "nullifier_count",
        u32::try_from(statement.nullifiers.len())
            .map_err(|_| PyValueError::new_err("private-IVM nullifier count overflowed"))?,
    )?;
    result.set_item(
        "output_count",
        u32::try_from(statement.output_commitments.len())
            .map_err(|_| PyValueError::new_err("private-IVM output count overflowed"))?,
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "inspect_signed_privacy_pq_masp_note_action_v1")]
/// Authenticate and inspect exactly one PQ-MASP note action.
fn inspect_signed_privacy_pq_masp_note_action_v1_py(
    py: Python<'_>,
    signed_transaction_versioned: &[u8],
) -> PyResult<Py<PyDict>> {
    let signed = decode_canonical_signed_transaction_v1(signed_transaction_versioned)?;
    crate::privacy_native_actions::inspect_signed_privacy_pq_masp_note_action_v1(&signed).map_err(
        |error| {
            PyValueError::new_err(format!(
                "invalid PQ-MASP signed action at {}",
                error.stage()
            ))
        },
    )?;
    let (intent, envelope) = python_authenticated_privacy_action_envelope_v1(
        &signed,
        PrivacyProtocolIdV1::PqMaspStarkV1,
        "PQ-MASP",
    )?;
    let PrivacyStatementV1::PqMaspStarkV1(statement) = &envelope.statement else {
        return Err(PyValueError::new_err(
            "signed_transaction_versioned has a mismatched PQ-MASP statement",
        ));
    };
    let result = python_privacy_action_inspection_result_v1(
        py,
        &signed,
        signed_transaction_versioned,
        intent,
        envelope,
        PQ_MASP_ACTION_EXECUTION_CLASSIFICATION_V1,
        Some(PQ_MASP_LEDGER_EFFECT_V1),
    )?;
    result.set_item("action_kind", "note_action")?;
    result.set_item(
        "asset_definition_id",
        statement.asset_definition_id.to_string(),
    )?;
    result.set_item("pool_id", PyBytes::new(py, statement.pool_id.as_bytes()))?;
    result.set_item("anchor", PyBytes::new(py, statement.anchor.as_bytes()))?;
    result.set_item("anchor_epoch", statement.anchor_epoch)?;
    result.set_item("authorization_epoch", statement.authorization_epoch)?;
    result.set_item(
        "authorization_key_digest",
        PyBytes::new(py, statement.authorization_key_digest.as_bytes()),
    )?;
    result.set_item(
        "note_encryption_key_digest",
        PyBytes::new(py, statement.note_encryption_key_digest.as_bytes()),
    )?;
    result.set_item(
        "nullifier_count",
        u32::try_from(statement.nullifiers.len())
            .map_err(|_| PyValueError::new_err("PQ-MASP nullifier count overflowed"))?,
    )?;
    result.set_item(
        "output_count",
        u32::try_from(statement.output_commitments.len())
            .map_err(|_| PyValueError::new_err("PQ-MASP output count overflowed"))?,
    )?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "verify_signed_transaction_versioned")]
/// Decode a versioned signed transaction and verify its signature.
fn verify_signed_transaction_versioned_py(bytes: &[u8]) -> PyResult<bool> {
    let signed = decode_canonical_signed_transaction_v1(bytes)?;
    Ok(signed.verify_signature().is_ok())
}
#[pyfunction]
#[pyo3(name = "derive_confidential_keyset")]
/// Derive the confidential key hierarchy from a 32-byte spend key.
fn derive_confidential_keyset_py(py: Python<'_>, spend_key: &[u8]) -> PyResult<Py<PyDict>> {
    let keyset = derive_keyset_from_slice(spend_key)
        .map_err(|err| PyValueError::new_err(format!("invalid confidential spend key: {err}")))?;
    let as_dict = PyDict::new(py);
    as_dict.set_item("sk_spend", PyBytes::new(py, keyset.spend_key()))?;
    as_dict.set_item("nk", PyBytes::new(py, keyset.nullifier_key()))?;
    as_dict.set_item("ivk", PyBytes::new(py, keyset.incoming_view_key()))?;
    as_dict.set_item("ovk", PyBytes::new(py, keyset.outgoing_view_key()))?;
    as_dict.set_item("fvk", PyBytes::new(py, keyset.full_view_key()))?;
    Ok(as_dict.unbind())
}
#[pyfunction]
#[pyo3(name = "sm2_fixture_from_seed")]
/// Compute the canonical SM2 fixture values for the given distinguishing ID, seed, and message.
fn sm2_fixture_from_seed_py(
    py: Python<'_>,
    distid: &str,
    seed: &[u8],
    message: &[u8],
) -> PyResult<Py<PyDict>> {
    let private = Sm2PrivateKey::from_seed(distid, seed).map_err(|err| {
        PyValueError::new_err(format!("failed to derive SM2 private key from seed: {err}"))
    })?;
    let public = private.public_key();
    let secret_hex = hex::encode_upper(private.secret_bytes());
    let public_bytes = public.to_sec1_bytes(false);
    let public_hex = hex::encode_upper(&public_bytes);
    let payload = encode_sm2_public_key_payload(distid, &public_bytes).map_err(|err| {
        PyValueError::new_err(format!("failed to encode SM2 public key payload: {err}"))
    })?;
    let public_key = PublicKey::from_bytes(Algorithm::Sm2, &payload).map_err(|err| {
        PyValueError::new_err(format!("failed to construct SM2 public key: {err}"))
    })?;
    let (multihash, prefixed) = sm2_fixture_public_key_multihashes(&public_key)?;
    let za = public
        .compute_z(distid)
        .map_err(|err| PyValueError::new_err(format!("failed to compute SM2 ZA: {err}")))?;
    let za_hex = hex::encode_upper(za);
    let signature = private.sign(message);
    let signature_bytes = signature.as_bytes();
    let signature_hex = hex::encode_upper(signature_bytes);
    let r_hex = hex::encode_upper(signature.r);
    let s_hex = hex::encode_upper(signature.s);
    let seed_hex = hex::encode_upper(seed);
    let message_hex = hex::encode_upper(message);
    let result = PyDict::new(py);
    result.set_item("distid", distid)?;
    result.set_item("seed_hex", seed_hex)?;
    result.set_item("message_hex", message_hex)?;
    result.set_item("private_key_hex", secret_hex)?;
    result.set_item("public_key_sec1_hex", public_hex)?;
    result.set_item("public_key_multihash", multihash)?;
    result.set_item("public_key_prefixed", prefixed)?;
    result.set_item("za", za_hex)?;
    result.set_item("signature", signature_hex)?;
    result.set_item("r", r_hex)?;
    result.set_item("s", s_hex)?;
    Ok(result.unbind())
}
#[pyfunction]
#[pyo3(name = "encode_connect_frame")]
/// Encode a connect frame described by a Python dictionary into Norito bytes.
fn encode_connect_frame_py(py: Python<'_>, frame: &Bound<'_, PyDict>) -> PyResult<Py<PyBytes>> {
    let sid_bytes = dict_require(frame, "sid", || {
        PyValueError::new_err("connect frame `sid` is required")
    })?
    .extract::<Vec<u8>>()?;
    let sid = fixed_array::<32>(&sid_bytes, "sid")?;
    let dir_str = dict_require(frame, "direction", || {
        PyValueError::new_err("connect frame `direction` is required")
    })?
    .extract::<String>()?;
    let dir = parse_connect_direction(&dir_str)?;
    let seq = dict_require(frame, "sequence", || {
        PyValueError::new_err("connect frame `sequence` is required")
    })?
    .extract::<u64>()?;
    let kind_obj = dict_require(frame, "kind", || {
        PyValueError::new_err("connect frame `kind` is required")
    })?;
    let kind_mapping = kind_obj
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("connect frame `kind` must be a dict"))?;
    let kind = parse_frame_kind(kind_mapping)?;
    let proto_frame = ConnectFrameV1 {
        sid,
        dir,
        seq,
        kind,
    };
    let encoded = norito::codec::Encode::encode(&proto_frame);
    Ok(Py::from(PyBytes::new(py, encoded.as_slice())))
}
#[pyfunction]
#[pyo3(name = "decode_connect_frame")]
/// Decode Norito-encoded connect frame bytes into a Python dictionary.
fn decode_connect_frame_py(py: Python<'_>, payload: &[u8]) -> PyResult<Py<PyDict>> {
    let frame = decode_connect_frame_bytes(payload)?;
    let mapping = PyDict::new(py);
    mapping.set_item("sid", PyBytes::new(py, &frame.sid))?;
    mapping.set_item("direction", connect_direction_str(frame.dir))?;
    mapping.set_item("sequence", frame.seq)?;
    mapping.set_item("kind", encode_frame_kind(py, &frame.kind)?)?;
    Ok(mapping.unbind())
}
#[pyfunction]
/// Return `True` when the CUDA backend initialised successfully for the current process.
fn cuda_available_py() -> bool {
    ivm::cuda_available()
}
#[pyfunction]
/// Return `True` when the CUDA backend has been disabled after an error or self-test failure.
fn cuda_disabled_py() -> bool {
    ivm::cuda_disabled()
}
#[pyfunction]
/// Execute the Poseidon2 permutation on the CUDA backend when available.
///
/// Returns `None` when CUDA support is unavailable or disabled at runtime.
fn poseidon2_cuda_py(a: u64, b: u64) -> Option<u64> {
    ivm::poseidon2_cuda(a, b)
}
#[pyfunction]
/// Execute the Poseidon6 permutation on the CUDA backend when available.
///
/// Returns `None` when CUDA support is unavailable or disabled at runtime.
fn poseidon6_cuda_py(inputs: [u64; 6]) -> Option<u64> {
    ivm::poseidon6_cuda(inputs)
}
#[pyfunction]
/// Add two BN254 field elements using the CUDA backend when available.
///
/// Returns `None` when CUDA support is unavailable or disabled at runtime.
fn bn254_add_cuda_py(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    ivm::bn254_add_cuda(a, b)
}
#[pyfunction]
/// Subtract two BN254 field elements using the CUDA backend when available.
///
/// Returns `None` when CUDA support is unavailable or disabled at runtime.
fn bn254_sub_cuda_py(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    ivm::bn254_sub_cuda(a, b)
}
#[pyfunction]
/// Multiply two BN254 field elements using the CUDA backend when available.
///
/// Returns `None` when CUDA support is unavailable or disabled at runtime.
fn bn254_mul_cuda_py(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    ivm::bn254_mul_cuda(a, b)
}
fn privacy_compiled_profile_catalog() -> PyResult<PrivacyCompiledProfileCatalogV1> {
    let catalog = compiled_privacy_profile_catalog_v1().map_err(|error| {
        PyRuntimeError::new_err(format!(
            "build local privacy compiled-profile catalog: {error}"
        ))
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
fn encode_privacy_compiled_profile_catalog_archive_py(
    py: Python<'_>,
    value: &PrivacyCompiledProfileCatalogV1,
    context: &str,
) -> PyResult<Py<PyBytes>> {
    let mut bytes = norito::encode_canonical(value)
        .map_err(|err| PyRuntimeError::new_err(format!("{context}: {err}")))?;
    if bytes.len() > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1 {
        bytes.fill(0);
        return Err(PyRuntimeError::new_err(format!(
            "{context}: encoded privacy compiled-profile catalog exceeds {PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1} bytes"
        )));
    }
    let status = validate_local_privacy_compiled_profile_catalog_archive_v1(&bytes);
    if !status.is_valid() {
        bytes.fill(0);
        return Err(PyRuntimeError::new_err(format!(
            "{context}: native archive validation failed with status {}",
            status.code()
        )));
    }
    let output = Py::from(PyBytes::new(py, &bytes));
    bytes.fill(0);
    Ok(output)
}
#[pyfunction]
#[pyo3(name = "privacy_compiled_profile_catalog_v1")]
fn privacy_compiled_profile_catalog_v1_py(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let catalog = privacy_compiled_profile_catalog()?;
    encode_privacy_compiled_profile_catalog_archive_py(
        py,
        &catalog,
        "encode local privacy compiled-profile catalog",
    )
}
#[pyfunction]
#[pyo3(name = "privacy_validate_compiled_profile_catalog_v1")]
fn privacy_validate_compiled_profile_catalog_v1_py(archive: &[u8]) -> i32 {
    validate_local_privacy_compiled_profile_catalog_archive_v1(archive).code()
}

const PRIVATE_SETTLEMENT_RESPONSE_JSON_MAX_BYTES_V1: usize = 32 * 1024 * 1024;
const PRIVATE_SETTLEMENT_APPROVAL_REQUEST_JSON_MAX_BYTES_V1: usize = 1024 * 1024;
const PRIVATE_SETTLEMENT_AUDITOR_KEY_MAX_BYTES_V1: usize = 1024;

fn private_settlement_expected_network_id_v1(bytes: &[u8]) -> PyResult<NetworkId> {
    let bytes = fixed_array::<32>(bytes, "expected_network_id")?;
    Ok(NetworkId::from_genesis_hash(
        HashOf::from_untyped_unchecked(Hash::prehashed(bytes)),
    ))
}

fn private_settlement_requested_payload_digest_v1(bytes: &[u8]) -> PyResult<Hash> {
    fixed_array::<32>(bytes, "requested_payload_digest").map(Hash::prehashed)
}

fn private_settlement_auditor_signing_key_v1(literal: &str) -> PyResult<PublicKey> {
    if literal.is_empty()
        || literal.trim() != literal
        || literal.len() > PRIVATE_SETTLEMENT_AUDITOR_KEY_MAX_BYTES_V1
        || literal.contains('\0')
    {
        return Err(PyValueError::new_err(
            "atomic private settlement response is invalid",
        ));
    }
    let key = PublicKey::from_str(literal)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    if key.to_string() != literal {
        return Err(PyValueError::new_err(
            "atomic private settlement response is invalid",
        ));
    }
    Ok(key)
}

fn private_settlement_response_bytes_v1(bytes: &[u8], maximum: usize) -> PyResult<&[u8]> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(PyValueError::new_err(
            "atomic private settlement response is invalid",
        ));
    }
    Ok(bytes)
}

#[pyfunction]
#[pyo3(name = "private_settlement_verify_committee_proof_response_v1")]
fn private_settlement_verify_committee_proof_response_v1_py(
    response_json: &[u8],
    expected_network_id: &[u8],
    requested_payload_digest: &[u8],
) -> PyResult<()> {
    let response_json = private_settlement_response_bytes_v1(
        response_json,
        PRIVATE_SETTLEMENT_RESPONSE_JSON_MAX_BYTES_V1,
    )?;
    let expected_network = private_settlement_expected_network_id_v1(expected_network_id)?;
    let requested = private_settlement_requested_payload_digest_v1(requested_payload_digest)?;
    let response: PrivateSettlementCommitteeProofResponseV1 = json::from_slice(response_json)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    validate_private_settlement_committee_proof_response_v1(&expected_network, requested, &response)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))
}

#[pyfunction]
#[pyo3(name = "private_settlement_verify_auditor_capsule_response_with_request_v1")]
fn private_settlement_verify_auditor_capsule_response_with_request_v1_py(
    response_json: &[u8],
    request_json: &[u8],
    expected_network_id: &[u8],
    requested_payload_digest: &[u8],
    auditor_signing_key: &str,
) -> PyResult<()> {
    let response_json = private_settlement_response_bytes_v1(
        response_json,
        PRIVATE_SETTLEMENT_RESPONSE_JSON_MAX_BYTES_V1,
    )?;
    let request_json = private_settlement_response_bytes_v1(
        request_json,
        PRIVATE_SETTLEMENT_APPROVAL_REQUEST_JSON_MAX_BYTES_V1,
    )?;
    let expected_network = private_settlement_expected_network_id_v1(expected_network_id)?;
    let requested = private_settlement_requested_payload_digest_v1(requested_payload_digest)?;
    let auditor_key = private_settlement_auditor_signing_key_v1(auditor_signing_key)?;
    let request: PrivateSettlementAuditorCapsuleRequestV1 = json::from_slice(request_json)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    let response: PrivateSettlementAuditorCapsuleResponseV1 = json::from_slice(response_json)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    validate_private_settlement_auditor_capsule_response_v1(
        &expected_network,
        requested,
        &request,
        &response,
    )
    .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    validate_private_settlement_auditor_identity_v1(&auditor_key, &response)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))
}

#[pyfunction]
#[pyo3(name = "private_settlement_verify_audit_approval_response_v1")]
fn private_settlement_verify_audit_approval_response_v1_py(
    response_json: &[u8],
    request_json: &[u8],
    expected_network_id: &[u8],
    requested_payload_digest: &[u8],
    auditor_signing_key: &str,
) -> PyResult<()> {
    let response_json = private_settlement_response_bytes_v1(
        response_json,
        PRIVATE_SETTLEMENT_RESPONSE_JSON_MAX_BYTES_V1,
    )?;
    let request_json = private_settlement_response_bytes_v1(
        request_json,
        PRIVATE_SETTLEMENT_APPROVAL_REQUEST_JSON_MAX_BYTES_V1,
    )?;
    let expected_network = private_settlement_expected_network_id_v1(expected_network_id)?;
    let requested = private_settlement_requested_payload_digest_v1(requested_payload_digest)?;
    let auditor_key = private_settlement_auditor_signing_key_v1(auditor_signing_key)?;
    let request: PrivateSettlementAuditApprovalRequestV1 = json::from_slice(request_json)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    if request.approval.body.version != ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1
        || request.approval.body.network_id != expected_network
        || request
            .approval
            .signature
            .verify(&auditor_key, &request.approval.body)
            .is_err()
    {
        return Err(PyValueError::new_err(
            "atomic private settlement response is invalid",
        ));
    }
    let response: PrivateSettlementAuditApprovalResponseV1 = json::from_slice(response_json)
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))?;
    validate_private_settlement_audit_approval_response_v1(requested, &request, &response)
        .map(|_| ())
        .map_err(|_| PyValueError::new_err("atomic private settlement response is invalid"))
}

#[pyfunction]
#[pyo3(name = "privacy_bridge_abi_version")]
fn privacy_bridge_abi_version_py() -> u32 {
    PRIVACY_BRIDGE_ABI_VERSION_V1
}
#[pyfunction]
#[pyo3(name = "connect_norito_bridge_abi_version")]
fn connect_norito_bridge_abi_version_py() -> u32 {
    PRIVACY_BRIDGE_ABI_VERSION_V1
}
#[pyfunction]
#[pyo3(name = "canonical_genesis_header_hash_v1")]
fn canonical_genesis_header_hash_v1_py(
    py: Python<'_>,
    framed_signed_genesis: &[u8],
) -> PyResult<Py<PyBytes>> {
    const MAX_GENESIS_FRAME_BYTES: usize = 64 * 1024 * 1024;
    if framed_signed_genesis.is_empty() || framed_signed_genesis.len() > MAX_GENESIS_FRAME_BYTES {
        return Err(PyValueError::new_err(
            "framed_signed_genesis must be non-empty and at most 64 MiB",
        ));
    }
    let block = decode_framed_signed_block(framed_signed_genesis)
        .map_err(|_| PyValueError::new_err("framed_signed_genesis is not a valid Norito frame"))?;
    let canonical = block.encode_wire().map_err(|_| {
        PyValueError::new_err("framed_signed_genesis could not be canonically re-encoded")
    })?;
    if canonical != framed_signed_genesis {
        return Err(PyValueError::new_err(
            "framed_signed_genesis is not the exact canonical block wire",
        ));
    }
    let header = block.header();
    if !header.is_genesis() {
        return Err(PyValueError::new_err(
            "framed_signed_genesis is not a genesis block",
        ));
    }
    let hash = header.hash();
    Ok(Py::from(PyBytes::new(py, hash.as_ref())))
}
#[pymodule]
fn _crypto(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    confidential_wallet::register(module)?;
    identity_codec_v1::register(module)?;
    module.add(
        "SorafsMultiFetchError",
        _py.get_type::<SorafsMultiFetchError>(),
    )?;
    module.add_class::<PyDomainId>()?;
    module.add_class::<PyNetworkId>()?;
    module.add_class::<PyAccountId>()?;
    module.add_class::<PyAssetDefinitionId>()?;
    module.add_class::<PyAssetId>()?;
    module.add_class::<Instruction>()?;
    module.add_class::<TransactionBuilder>()?;
    module.add_class::<privacy_capability_manifest::PyPrivacyExact12CapabilityManifestV1>()?;
    module.add_class::<PrivacyNativeActionBuildResultV1>()?;
    module.add_class::<SignedTransactionEnvelope>()?;
    module.add_function(wrap_pyfunction!(supported_crypto_algorithms_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        zk_vk_draft::decode_zk_vk_transaction_payload_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(normalize_crypto_algorithm_py, module)?)?;
    module.add_function(wrap_pyfunction!(generate_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(derive_keypair_from_seed_py, module)?)?;
    module.add_function(wrap_pyfunction!(load_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(sign_py, module)?)?;
    module.add_function(wrap_pyfunction!(build_find_asset_escrow_query_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        build_find_asset_escrows_by_seller_query_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        build_find_asset_escrows_by_buyer_query_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        build_find_committed_transaction_query_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(build_find_block_by_hash_query_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        committed_transaction_carrier_block_hash_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        verify_committed_transaction_inclusion_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(verify_py, module)?)?;
    module.add_function(wrap_pyfunction!(public_key_multihash_py, module)?)?;
    module.add_function(wrap_pyfunction!(private_key_multihash_py, module)?)?;
    module.add_function(wrap_pyfunction!(parse_public_key_multihash_py, module)?)?;
    module.add_function(wrap_pyfunction!(parse_private_key_multihash_py, module)?)?;
    module.add_function(wrap_pyfunction!(load_keypair_from_multihash_py, module)?)?;
    module.add_function(wrap_pyfunction!(generate_ed25519_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        derive_ed25519_keypair_from_seed_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(load_ed25519_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(sign_ed25519_py, module)?)?;
    module.add_function(wrap_pyfunction!(verify_ed25519_py, module)?)?;
    module.add_function(wrap_pyfunction!(sm2_default_distid_py, module)?)?;
    module.add_function(wrap_pyfunction!(generate_sm2_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(derive_sm2_keypair_from_seed_py, module)?)?;
    module.add_function(wrap_pyfunction!(load_sm2_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(sm2_public_key_multihash_py, module)?)?;
    module.add_function(wrap_pyfunction!(sign_sm2_py, module)?)?;
    module.add_function(wrap_pyfunction!(verify_sm2_py, module)?)?;
    module.add_function(wrap_pyfunction!(hash_blake2b_32_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        canonical_signed_transaction_hash_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        signed_transaction_envelope_from_versioned_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(account_faucet_claim_hash_v1_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        verify_prepared_transaction_context_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        verify_account_onboarding_receipt_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_privacy_exact12_action_driver_transaction_context_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        privacy_vega_device_authentication_digest_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_zk_ace_transfer_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_jindo_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_verange_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_vega_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_zk_x509_identity_presentation_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_zk_ams_batch_admission_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_zk_ams_provision_account_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_bootle_lantern_presentation_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_anonymous_pgc_payment_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_orchard_note_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_fcmp_membership_payment_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_ivm_private_note_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        inspect_signed_privacy_pq_masp_note_action_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        verify_signed_transaction_versioned_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        canonical_genesis_header_hash_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(derive_confidential_keyset_py, module)?)?;
    module.add_function(wrap_pyfunction!(sm2_fixture_from_seed_py, module)?)?;
    module.add_function(wrap_pyfunction!(encode_connect_frame_py, module)?)?;
    module.add_function(wrap_pyfunction!(decode_connect_frame_py, module)?)?;
    connect_key_bindings::register(module)?;
    module.add_function(wrap_pyfunction!(seal_connect_payload_py, module)?)?;
    module.add_function(wrap_pyfunction!(open_connect_payload_py, module)?)?;
    module.add_function(wrap_pyfunction!(sorafs_alias_policy_defaults_py, module)?)?;
    module.add_function(wrap_pyfunction!(sorafs_evaluate_alias_proof_py, module)?)?;
    module.add_function(wrap_pyfunction!(sorafs_alias_proof_fixture_py, module)?)?;
    module.add_function(wrap_pyfunction!(sorafs_multi_fetch_local_py, module)?)?;
    module.add_function(wrap_pyfunction!(sorafs_gateway_fetch_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_decode_replication_order_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_orderbook_payload_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_appeal_finance_cancel_asset_lock_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(sorafs_sign_orderbook_payload_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_derive_orderbook_order_id_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_build_signed_orderbook_order_request_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_build_signed_orderbook_order_cancel_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_build_signed_orderbook_settlement_receipt_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_pdp_payload_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_pdp_commitment_challenge_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_pdp_challenge_proof_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_pdp_bundle_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_fixture_bundle_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_governance_log_node_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_governance_dag_block_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_validate_governance_dag_head_chain_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_orderbook_submission::decode_transaction_receipt_json_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_orderbook_submission::inspect_transaction_submission_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_orderbook_submission::verify_transaction_submission_receipt_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_orderbook_submission::inspect_sorafs_orderbook_submission_for_discriminant_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        sorafs_orderbook_submission::verify_sorafs_orderbook_submission_receipt_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        confidential_transfer_v2_verifying_key_registration_payload_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        confidential_unshield_v3_verifying_key_registration_payload_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(compute_confidential_root_v2_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        derive_confidential_next_zero_path_v2_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        default_confidential_diversifier_v2_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        derive_confidential_diversifier_v2_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        derive_confidential_owner_tag_v2_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(derive_confidential_note_v2_py, module)?)?;
    module.add_function(wrap_pyfunction!(privacy_bridge_abi_version_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        privacy_capability_manifest::privacy_exact12_capability_manifest_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        privacy_capability_manifest::privacy_fetch_exact12_capability_manifest_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        privacy_capability_manifest::privacy_validate_exact12_capability_manifest_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        connect_norito_bridge_abi_version_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        privacy_compiled_profile_catalog_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        privacy_validate_compiled_profile_catalog_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        private_settlement_verify_committee_proof_response_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        private_settlement_verify_auditor_capsule_response_with_request_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        private_settlement_verify_audit_approval_response_v1_py,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(cuda_available_py, module)?)?;
    module.add_function(wrap_pyfunction!(cuda_disabled_py, module)?)?;
    module.add_function(wrap_pyfunction!(poseidon2_cuda_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        acceleration_poseidon::poseidon2_many,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(poseidon6_cuda_py, module)?)?;
    module.add_function(wrap_pyfunction!(
        acceleration_poseidon::poseidon6_many,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(bn254_add_cuda_py, module)?)?;
    module.add_function(wrap_pyfunction!(bn254_add_many, module)?)?;
    module.add_function(wrap_pyfunction!(bn254_sub_cuda_py, module)?)?;
    module.add_function(wrap_pyfunction!(bn254_sub_many, module)?)?;
    module.add_function(wrap_pyfunction!(bn254_mul_cuda_py, module)?)?;
    module.add_function(wrap_pyfunction!(bn254_mul_many, module)?)?;
    module.add(
        "__doc__",
        "Iroha crypto and transaction helpers exposed to Python via PyO3.",
    )?;
    Ok(())
}
