//! FFI bridge exposing Norito/Connect helpers for the mobile SDKs and bridge targets.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

// The locked pqcrypto-internals build emits both static and unqualified links.
// With the current Rust toolchain its rlib does not retain the common/Keccak
// objects. Own their Apple static bundling explicitly so this bridge archive is
// self-contained. The Apple packager still authenticates every reference member
// and removes only byte-identical second copies before its all-load consumer.
#[cfg(target_vendor = "apple")]
#[link(name = "pqclean_common", kind = "static", modifiers = "+bundle")]
unsafe extern "C" {}

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[link(name = "keccak2x", kind = "static", modifiers = "+bundle")]
unsafe extern "C" {}

#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
#[link(name = "keccak4x", kind = "static", modifiers = "+bundle")]
unsafe extern "C" {}

use base64::{Engine as _, engine::general_purpose as b64gp};
use blake3::hash as blake3_hash;
#[cfg(test)]
use core::ffi::c_void;
use iroha_core_privacy::privacy_profiles::{
    compiled_privacy_profile_catalog_v1, validate_local_privacy_compiled_profile_catalog_archive_v1,
};
use iroha_crypto::{
    Algorithm, EcdsaSecp256k1Sha256, Error as CryptoError, Hash, KeyGenOption, KeyPair, PrivateKey,
    PublicKey, RamLfeBackend, RamLfeVerificationMode, Signature, SignatureOf,
    confidential_memo::{ConfidentialMemoKemSuiteV1, generate_confidential_memo_keypair_v1},
    kex::KeyExchangeScheme,
    sm::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature},
};
use iroha_data_model::{
    NetworkId,
    account::{
        AccountId,
        address::{AccountAddress, AccountAddressError, ChainDiscriminantGuard},
    },
    asset::id::{AssetBalanceScope, AssetDefinitionId, AssetId},
    confidential::{
        CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1, CONFIDENTIAL_MEMO_MAX_WIRE_BYTES_V1,
        CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1, ConfidentialMemoEnvelopeV1,
    },
    da::manifest::DaManifestV1,
    governance::{
        is_valid_governance_selector_v1,
        types::{AbiVersion, ContractAbiHash, ContractCodeHash},
    },
    identifier::{IdentifierResolutionReceipt, IdentifierResolutionReceiptPayload},
    isi::{
        Grant, InstructionBox, RemoveAssetKeyValue, RemoveKeyValue, Revoke, SetAssetKeyValue,
        SetKeyValue, decode_instruction_from_pair, framed_instruction_payload,
        governance::{CastPlainBallot, CastZkBallot, ProposeDeployContract, UpdatePlainConviction},
        identifier::ClaimIdentifier,
        mint_burn::{Burn, Mint},
        transfer::Transfer,
        zk,
    },
    privacy::{
        PRIVACY_BRIDGE_ABI_VERSION_V1, PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1,
        PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1,
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1, PrivacyCapabilityArchiveValidationStatusV1,
        PrivacyCompiledProfileCatalogArchiveValidationStatusV1, PrivacyCompiledProfileCatalogV1,
        PrivacyExact12FixtureBundleValidationStatusV1, PrivacyProtocolIdV1,
        privacy_exact12_fixture_bundle_bytes_v1, validate_privacy_capability_archive_v1,
        validate_privacy_exact12_fixture_bundle_v1,
    },
    proof::{ProofBox, VerifyingKeyId},
    ram_lfe::RamLfeReceiptAttestation,
    ram_lfe::{RamLfeExecutionReceiptPayload, RamLfeProgramId},
    rwa::RwaId,
    smart_contract::manifest::ManifestProvenance,
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionSubmissionReceipt,
        signed::{MultisigSignature, MultisigSignatures, TransactionBuilder},
    },
    validation_fee::{RetailFeeAssessmentV1, RetailFeeQuoteRequestV1, honiara_month_bounds},
};
use iroha_executor_data_model::isi::multisig::{MultisigRegister, MultisigSpec};
use iroha_executor_data_model::permission::query::CanReadAccountData;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_torii_shared::{
    connect as proto, connect_sdk,
    validation_fee_api::{
        VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES, VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
        ValidationFeeCurrentPolicyProofRequestV1, ValidationFeeCurrentPolicyProofV1,
    },
};
use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};
use ivm::{AccelerationConfig, BackendRuntimeStatus};
use libc::{c_char, c_int, c_uchar, c_ulong, free, malloc};
use norito::decode_from_bytes;
use norito::json::{Map as JsonMap, Value as JsonValue};
use sorafs_car::{
    ChunkStore, ChunkStoreError, InMemoryPayload, PorProof, build_plan_from_da_manifest,
    local_fetch::{
        self, LocalFetchError, LocalFetchOptions, LocalFetchResult, LocalProviderInput,
        ProviderMetadataInput, RangeCapabilityInput, StreamBudgetInput, TelemetryEntryInput,
        TransportHintInput,
    },
};
use sorafs_manifest::{
    ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1, OrderCancelReasonV1, OrderSideV1, OrderTierV1,
    OrderbookOrderCancelFieldsV1, OrderbookOrderRequestFieldsV1, OrderbookPayloadSigningError,
    OrderbookSettlementReceiptFieldsV1, OrderbookValidationPayloadKindV1, ValidationContextFieldV1,
    ValidationOutcomeV1, XorQuantity, build_signed_orderbook_order_cancel_bytes_ed25519_v1,
    build_signed_orderbook_order_request_bytes_ed25519_v1,
    build_signed_orderbook_settlement_receipt_bytes_ed25519_v1, derive_orderbook_order_id_v1,
    reference_ffi as sorafs_reference_ffi, sign_orderbook_payload_bytes_ed25519_v1,
};
#[cfg(test)]
use std::sync::Arc;
use std::{
    cell::RefCell,
    collections::HashSet,
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
    ptr, slice,
    str::FromStr as _,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};
mod account_onboarding;
pub use account_onboarding::connect_norito_encode_account_onboarding_plan_body_v1;
mod committed_transaction_inclusion;
pub use committed_transaction_inclusion::{
    connect_norito_committed_transaction_candidate_block_hash_v1,
    connect_norito_verify_committed_transaction_inclusion_v1,
};
mod committed_transaction_query;
pub use committed_transaction_query::{
    connect_norito_committed_transaction_query_finalize_v1,
    connect_norito_committed_transaction_query_payload_hash_v1,
};
mod parliament_timed_ovn_ffi;
#[cfg(test)]
mod privacy_capability_ffi_tests;
pub use parliament_timed_ovn_ffi::{
    CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_MAX_BYTES_V1,
    CONNECT_NORITO_PARLIAMENT_TIMED_OVN_CASTING_PROOF_PAGE_SUMMARY_BYTES_V1,
    CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1,
    CONNECT_NORITO_PARLIAMENT_TIMED_OVN_TRUST_ANCHOR_BYTES_V1,
    connect_norito_parliament_timed_ovn_ballot_from_proof_v1,
    connect_norito_parliament_timed_ovn_registration_from_proof_v1,
    connect_norito_parliament_timed_ovn_verify_casting_proof_page_v1,
    connect_norito_parliament_timed_ovn_verify_casting_proof_v1,
};
mod connect_approval_ffi;
#[cfg(test)]
use connect_approval_ffi::{
    connect_norito_connect_approval_preimage, connect_norito_connect_verify_approval,
    parse_connect_wallet_signature_algorithm_label,
};
use connect_approval_ffi::{
    connect_signature_from_algorithm_bytes, connect_wallet_signature_from_algorithm_bytes,
    parse_algorithm_cstr, validate_exact_connect_identity,
};
mod confidential_note_ffi;
mod confidential_prover_ffi;
#[cfg(not(unix))]
compile_error!(
    "Native KAGEMUSHA wallet storage is not implemented for non-Unix targets; \
     a genuine platform custody backend is required."
);
/// Native KAGEMUSHA custody callbacks and exclusive shared-wallet ownership.
pub mod kagemusha_wallet_ffi;
mod kagemusha_wallet_load_original;
pub use kagemusha_wallet_load_original::connect_norito_kagemusha_wallet_load_original_validate_v1;
mod private_settlement_ffi;
pub use private_settlement_ffi::{
    CONNECT_NORITO_PRIVATE_SETTLEMENT_REQUEST_MAX_BYTES_V1,
    CONNECT_NORITO_PRIVATE_SETTLEMENT_RESPONSE_MAX_BYTES_V1,
    connect_norito_private_settlement_audit_approval_response_verify_v1,
    connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1,
    connect_norito_private_settlement_committee_proof_response_verify_v1,
};
const CONNECT_NORITO_BRIDGE_ABI_VERSION: u32 = PRIVACY_BRIDGE_ABI_VERSION_V1;
// Increment for NativeSignerBridge JNI descriptor changes that the bridge-wide ABI cannot distinguish.
// Revision 4 narrowed RegisterZkAsset bindings; revision 5 replaced the chain label with the exact
// 32-byte genesis-derived NetworkId; revision 6 hard-cut reporting permissions; revision 7
// removes the retired shield verifier parameter.
#[cfg(any(
    test,
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
const NATIVE_SIGNER_JNI_CONTRACT_REVISION: u32 = 7;
const CANONICAL_NETWORK_ID_LITERAL_BYTES: usize = 74;
const DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES: usize = 16 * 1024 * 1024;
const DETACHED_TRANSACTION_JSON_MAX_BYTES: usize = 16 * 1024 * 1024;
const SORAFS_ORDERBOOK_SIDE_BID: u32 = 1;
const SORAFS_ORDERBOOK_SIDE_ASK: u32 = 2;
const SORAFS_ORDERBOOK_TIER_HOT: u32 = 1;
const SORAFS_ORDERBOOK_TIER_WARM: u32 = 2;
const SORAFS_ORDERBOOK_TIER_ARCHIVE: u32 = 3;
const SORAFS_ORDERBOOK_CANCEL_REASON_OWNER_REQUESTED: u32 = 1;
const SORAFS_ORDERBOOK_CANCEL_REASON_EXPIRED: u32 = 2;
const SORAFS_ORDERBOOK_CANCEL_REASON_GOVERNANCE: u32 = 3;
const SORAFS_ORDERBOOK_CANCEL_REASON_REPLACED: u32 = 4;
const SORAFS_REFERENCE_PDP_KIND_COMMITMENT: u32 = 1;
const SORAFS_REFERENCE_PDP_KIND_CHALLENGE: u32 = 2;
const SORAFS_REFERENCE_PDP_KIND_PROOF: u32 = 3;
/// Payload/label descriptor used by the SoraFS governance head-chain C ABI.
pub type ConnectNoritoSorafsReferenceInput = sorafs_reference_ffi::SorafsReferenceFfiInput;
/// Typed payload descriptor used by the SoraFS fixture-bundle C ABI.
pub type ConnectNoritoSorafsReferenceBundlePayload =
    sorafs_reference_ffi::SorafsReferenceFfiBundlePayload;
/// Maximum governance DAG block descriptors accepted by the bridge.
pub const CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1: u32 = 64;
/// Exact byte length of every first-release Governance DAG CID.
pub const CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1: u32 = 32;
/// Maximum aggregate SoraFS reference input bytes accepted by the bridge.
pub const CONNECT_NORITO_SORAFS_REFERENCE_MAX_INPUT_BYTES_V1: u32 = 67108864;
/// Maximum UTF-8 SoraFS reference label bytes accepted by the bridge.
pub const CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1: u32 = 1024;
/// Maximum payload count accepted by the SoraFS fixture-bundle bridge.
pub const CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_PAYLOADS_V1: u32 = 64;
/// Maximum aggregate payload and label bytes accepted by a fixture-bundle call.
pub const CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_TOTAL_BYTES_V1: u32 = 67108864;
const _: () = assert!(
    CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1
        == sorafs_reference_ffi::SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1
);
const _: () = assert!(
    CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1
        == sorafs_reference_ffi::SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1
);
const _: () = assert!(
    CONNECT_NORITO_SORAFS_REFERENCE_MAX_INPUT_BYTES_V1
        == sorafs_reference_ffi::SORAFS_REFERENCE_FFI_MAX_INPUT_BYTES_V1
);
const _: () = assert!(
    CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1
        == sorafs_reference_ffi::SORAFS_REFERENCE_FFI_MAX_LABEL_BYTES_V1
);
const _: () = assert!(
    CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_PAYLOADS_V1
        == sorafs_reference_ffi::SORAFS_REFERENCE_FFI_MAX_BUNDLE_PAYLOADS_V1
);
const _: () = assert!(
    CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_TOTAL_BYTES_V1
        == sorafs_reference_ffi::SORAFS_REFERENCE_FFI_MAX_BUNDLE_TOTAL_BYTES_V1
);
const ERR_NULL_PTR: c_int = -1;
const ERR_UTF8: c_int = -2;
const ERR_NETWORK_ID_PARSE: c_int = -3;
const ERR_AUTHORITY_PARSE: c_int = -4;
const ERR_ASSET_DEFINITION_PARSE: c_int = -5;
const ERR_DESTINATION_PARSE: c_int = -6;
const ERR_QUANTITY_PARSE: c_int = -7;
const ERR_INVALID_TTL: c_int = -8;
const ERR_PRIVATE_KEY_PARSE: c_int = -9;
const ERR_ALLOC: c_int = -10;
const ERR_HASH_OUT_LEN: c_int = -11;
const ERR_BUFFER_TOO_SMALL: c_int = -12;
const ERR_SM2_DERIVE: c_int = -13;
const ERR_SM2_VERIFY: c_int = -16;
const ERR_SM2_PARSE: c_int = -17;
const ERR_UNSUPPORTED_ALGORITHM: c_int = -21;
const ERR_SECP_PARSE: c_int = -22;
const ERR_SECP_SIGN: c_int = -23;
const ERR_SECP_VERIFY: c_int = -24;
const ERR_METADATA_TARGET: c_int = -25;
const ERR_METADATA_KEY: c_int = -26;
const ERR_METADATA_VALUE: c_int = -27;
const ERR_GOVERNANCE: c_int = -28;
const ERR_INVALID_NONCE: c_int = -31;
const ERR_TRANSACTION_SIGN: c_int = -32;
const ERR_SM2_SIGN: c_int = -33;
const ERR_FEE_PAYMENT: c_int = -34;
const ERR_FETCH_PLAN_JSON: c_int = -100;
const ERR_FETCH_PROVIDERS_JSON: c_int = -101;
const ERR_FETCH_OPTIONS_JSON: c_int = -102;
const ERR_FETCH_NO_PROVIDERS: c_int = -103;
const ERR_FETCH_DUPLICATE_PROVIDER: c_int = -104;
const ERR_FETCH_PROVIDER_PATH_MISSING: c_int = -105;
const ERR_FETCH_PROVIDER_PATH_NOT_FILE: c_int = -106;
const ERR_FETCH_INVALID_MAX_CONCURRENT: c_int = -107;
const ERR_FETCH_INVALID_WEIGHT: c_int = -108;
const ERR_FETCH_SCOREBOARD_METADATA: c_int = -109;
const ERR_FETCH_SCOREBOARD_EXCLUDED: c_int = -110;
const ERR_FETCH_SCOREBOARD_BUILD: c_int = -111;
const ERR_FETCH_EXECUTION: c_int = -112;
const ERR_FETCH_UNKNOWN_CHUNKER: c_int = -113;
const ERR_SORAFS_REFERENCE: c_int = -114;
const ERR_ACCOUNT_ADDRESS: c_int = -200;
const ERR_ASSET_ID_PARSE: c_int = -301;
const ERR_JSON_SERIALIZE: c_int = -304;
const ERR_DA_PROOF_SUMMARY: c_int = -401;
const ERR_MULTISIG_SPEC: c_int = -402;
const ERR_VERIFYING_KEY_ID: c_int = -403;
const ERR_CONNECT_ENCODE: c_int = -405;
const ERR_IDENTIFIER_RECEIPT: c_int = -406;
const ERR_CONNECT_KEYPAIR: c_int = -407;
const ERR_ACCOUNT_ONBOARDING_BODY: c_int = -408;
const ERR_ALIAS_INSTRUCTION: c_int = -409;
const ERR_CONNECT_IDENTITY: c_int = -410;
const ERR_CONNECT_APPROVAL: c_int = -411;
const ERR_DETACHED_TRANSACTION_SCAFFOLD: c_int = -501;
const ERR_DETACHED_TRANSACTION_SIGNATURE: c_int = -502;
const ERR_CANONICAL_JSON: c_int = -503;
const ERR_VALIDATION_FEE_POLICY_PROOF: c_int = -504;
const ERR_PARLIAMENT_TIMED_OVN: c_int = -505;
const ERR_RETAIL_FEE_ASSESSMENT: c_int = -506;
const ERR_PRIVATE_SETTLEMENT_RESPONSE: c_int = -507;

#[derive(Debug, Clone, Copy)]
enum BridgeError {
    NullPtr,
    Utf8,
    NetworkId,
    Authority,
    AssetDefinition,
    Destination,
    Quantity,
    InvalidTtl,
    InvalidNonce,
    PrivateKey,
    Alloc,
    HashOutBuffer,
    AssetId,
    JsonSerialize,
    UnsupportedAlgorithm,
    MetadataTarget,
    MetadataKey,
    MetadataValue,
    Governance,
    MultisigSpec,
    IdentifierReceipt,
    VerifyingKeyId,
    SecpSign,
    TransactionSign,
    FeePayment,
    ConnectKeypair,
    AccountOnboardingBody,
    AliasInstruction,
    DetachedTransactionScaffold,
    DetachedTransactionSignature,
    CanonicalJson,
    ValidationFeePolicyProof,
    ParliamentTimedOvn,
    RetailFeeAssessment,
    PrivateSettlementResponse,
}
impl BridgeError {
    const fn code(self) -> c_int {
        match self {
            BridgeError::NullPtr => ERR_NULL_PTR,
            BridgeError::Utf8 => ERR_UTF8,
            BridgeError::NetworkId => ERR_NETWORK_ID_PARSE,
            BridgeError::Authority => ERR_AUTHORITY_PARSE,
            BridgeError::AssetDefinition => ERR_ASSET_DEFINITION_PARSE,
            BridgeError::Destination => ERR_DESTINATION_PARSE,
            BridgeError::Quantity => ERR_QUANTITY_PARSE,
            BridgeError::InvalidTtl => ERR_INVALID_TTL,
            BridgeError::InvalidNonce => ERR_INVALID_NONCE,
            BridgeError::PrivateKey => ERR_PRIVATE_KEY_PARSE,
            BridgeError::Alloc => ERR_ALLOC,
            BridgeError::HashOutBuffer => ERR_HASH_OUT_LEN,
            BridgeError::AssetId => ERR_ASSET_ID_PARSE,
            BridgeError::JsonSerialize => ERR_JSON_SERIALIZE,
            BridgeError::UnsupportedAlgorithm => ERR_UNSUPPORTED_ALGORITHM,
            BridgeError::MetadataTarget => ERR_METADATA_TARGET,
            BridgeError::MetadataKey => ERR_METADATA_KEY,
            BridgeError::MetadataValue => ERR_METADATA_VALUE,
            BridgeError::Governance => ERR_GOVERNANCE,
            BridgeError::MultisigSpec => ERR_MULTISIG_SPEC,
            BridgeError::IdentifierReceipt => ERR_IDENTIFIER_RECEIPT,
            BridgeError::VerifyingKeyId => ERR_VERIFYING_KEY_ID,
            BridgeError::SecpSign => ERR_SECP_SIGN,
            BridgeError::TransactionSign => ERR_TRANSACTION_SIGN,
            BridgeError::FeePayment => ERR_FEE_PAYMENT,
            BridgeError::ConnectKeypair => ERR_CONNECT_KEYPAIR,
            BridgeError::AccountOnboardingBody => ERR_ACCOUNT_ONBOARDING_BODY,
            BridgeError::AliasInstruction => ERR_ALIAS_INSTRUCTION,
            BridgeError::DetachedTransactionScaffold => ERR_DETACHED_TRANSACTION_SCAFFOLD,
            BridgeError::DetachedTransactionSignature => ERR_DETACHED_TRANSACTION_SIGNATURE,
            BridgeError::CanonicalJson => ERR_CANONICAL_JSON,
            BridgeError::ValidationFeePolicyProof => ERR_VALIDATION_FEE_POLICY_PROOF,
            BridgeError::ParliamentTimedOvn => ERR_PARLIAMENT_TIMED_OVN,
            BridgeError::RetailFeeAssessment => ERR_RETAIL_FEE_ASSESSMENT,
            BridgeError::PrivateSettlementResponse => ERR_PRIVATE_SETTLEMENT_RESPONSE,
        }
    }
}
type BridgeResult<T> = Result<T, BridgeError>;
/// Return the native C ABI version, which dynamic clients must check before other entrypoints so a
/// stale artifact cannot crash before Rust receives enough arguments to validate the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_bridge_abi_version() -> u32 {
    CONNECT_NORITO_BRIDGE_ABI_VERSION
}

#[cfg(any(
    test,
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
fn native_signer_jni_contract_revision() -> u32 {
    NATIVE_SIGNER_JNI_CONTRACT_REVISION
}
fn account_address_error_fields(err: &AccountAddressError) -> Option<JsonMap> {
    use AccountAddressError::*;
    let mut fields = JsonMap::new();
    match err {
        UnsupportedAlgorithm(algorithm) => {
            fields.insert("algorithm".into(), JsonValue::from(algorithm.to_string()));
        }
        KeyPayloadTooLong(len) => {
            fields.insert("length".into(), JsonValue::from(u64::from(*len)));
        }
        InvalidHeaderVersion(value) => {
            fields.insert("value".into(), JsonValue::from(u64::from(*value)));
        }
        InvalidNormVersion(value) => {
            fields.insert("value".into(), JsonValue::from(u64::from(*value)));
        }
        UnexpectedNetworkPrefix { expected, found } => {
            fields.insert("expected".into(), JsonValue::from(u64::from(*expected)));
            fields.insert("found".into(), JsonValue::from(u64::from(*found)));
        }
        UnknownAddressClass(value) | UnknownControllerTag(value) => {
            fields.insert("value".into(), JsonValue::from(u64::from(*value)));
        }
        UnknownCurve(value) => {
            fields.insert("value".into(), JsonValue::from(u64::from(*value)));
        }
        InvalidI105Char(ch) => {
            fields.insert("char".into(), JsonValue::from(ch.to_string()));
        }
        MultisigMemberOverflow(count) => {
            fields.insert("count".into(), JsonValue::from(*count as u64));
        }
        InvalidMultisigPolicy(policy) => {
            fields.insert("policy_error".into(), JsonValue::from(policy.to_string()));
        }
        _ => {}
    }
    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}
fn encode_account_address_error(err: AccountAddressError) -> Vec<u8> {
    let mut map = JsonMap::new();
    map.insert("code".into(), JsonValue::from(err.code_str()));
    map.insert("message".into(), JsonValue::from(err.to_string()));
    if let Some(fields) = account_address_error_fields(&err) {
        map.insert("fields".into(), JsonValue::Object(fields));
    }
    norito::json::to_vec(&JsonValue::Object(map))
        .unwrap_or_else(|_| b"{\"code\":\"ERR_ADDRESS_PARSE\"}".to_vec())
}
fn write_account_address_error(
    err: AccountAddressError,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if !out_ptr.is_null() {
        unsafe { *out_ptr = ptr::null_mut() };
    }
    if !out_len.is_null() {
        unsafe { *out_len = 0 };
    }
    if out_ptr.is_null() || out_len.is_null() {
        return ERR_ACCOUNT_ADDRESS;
    }
    let payload = encode_account_address_error(err);
    match unsafe { write_bytes(out_ptr, out_len, &payload) } {
        Ok(()) => ERR_ACCOUNT_ADDRESS,
        Err(code) => code,
    }
}
unsafe fn read_string_bridge(ptr: *const c_char, len: c_ulong) -> BridgeResult<String> {
    if ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    let slice = unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) };
    let s = std::str::from_utf8(slice).map_err(|_| BridgeError::Utf8)?;
    Ok(s.to_owned())
}
unsafe fn read_network_id_bridge(ptr: *const c_char, len: c_ulong) -> BridgeResult<NetworkId> {
    if usize::try_from(len).ok() != Some(CANONICAL_NETWORK_ID_LITERAL_BYTES) {
        return Err(BridgeError::NetworkId);
    }
    let literal = unsafe { read_string_bridge(ptr, len) }?;
    let network_id: NetworkId = norito::json::from_value(JsonValue::String(literal.clone()))
        .map_err(|_| BridgeError::NetworkId)?;
    let canonical = norito::json::to_value(&network_id).map_err(|_| BridgeError::NetworkId)?;
    if canonical.as_str() != Some(literal.as_str()) {
        return Err(BridgeError::NetworkId);
    }
    Ok(network_id)
}
fn network_id_from_raw_bytes(bytes: &[u8]) -> Result<NetworkId, &'static str> {
    if bytes.len() != Hash::LENGTH {
        return Err("networkId must contain exactly 32 raw genesis-hash bytes");
    }
    let hash = hex::encode(bytes)
        .parse::<Hash>()
        .map_err(|_| "networkId must be an exact marked Iroha hash")?;
    Ok(NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(
        hash
    )))
}
unsafe fn read_governance_selector_bridge(
    ptr: *const c_char,
    len: c_ulong,
) -> BridgeResult<String> {
    let selector = unsafe { read_string_bridge(ptr, len) }.map_err(|error| {
        if matches!(error, BridgeError::Utf8) {
            BridgeError::Governance
        } else {
            error
        }
    })?;
    if !is_valid_governance_selector_v1(&selector) {
        return Err(BridgeError::Governance);
    }
    Ok(selector)
}
unsafe fn read_governance_hash32_bridge(
    ptr: *const c_uchar,
    len: c_ulong,
) -> BridgeResult<[u8; 32]> {
    if usize::try_from(len).ok() != Some(ContractCodeHash::LENGTH) {
        return Err(BridgeError::Governance);
    }
    if ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    let bytes = unsafe { slice::from_raw_parts(ptr, ContractCodeHash::LENGTH) };
    bytes.try_into().map_err(|_| BridgeError::Governance)
}
unsafe fn read_manifest_provenance_bridge(
    signer_ptr: *const c_char,
    signer_len: c_ulong,
    signature_ptr: *const c_char,
    signature_len: c_ulong,
    present: c_uchar,
) -> BridgeResult<Option<ManifestProvenance>> {
    match present {
        0 if signer_len == 0 && signature_len == 0 => Ok(None),
        0 => Err(BridgeError::Governance),
        1 if signer_len == 0 || signature_len == 0 => Err(BridgeError::Governance),
        1 => {
            let signer = unsafe { read_string_bridge(signer_ptr, signer_len) }?
                .parse::<PublicKey>()
                .map_err(|_| BridgeError::Governance)?;
            let signature_hex = unsafe { read_string_bridge(signature_ptr, signature_len) }?;
            let signature =
                Signature::try_from_hex(signature_hex).map_err(|_| BridgeError::Governance)?;
            Ok(Some(ManifestProvenance { signer, signature }))
        }
        _ => Err(BridgeError::Governance),
    }
}
unsafe fn write_bytes(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
    bytes: &[u8],
) -> Result<(), c_int> {
    if out_ptr.is_null() || out_len.is_null() {
        return Err(ERR_NULL_PTR);
    }
    let len = bytes.len();
    if len == 0 {
        unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        }
        return Ok(());
    }
    let mem = unsafe { malloc(len) };
    if mem.is_null() {
        return Err(ERR_ALLOC);
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), mem as *mut u8, len);
        *out_ptr = mem as *mut u8;
        *out_len = len as c_ulong;
    }
    Ok(())
}
unsafe fn write_bytes_usize(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut usize,
    bytes: &[u8],
) -> Result<(), c_int> {
    if out_ptr.is_null() || out_len.is_null() {
        return Err(ERR_NULL_PTR);
    }
    let len = bytes.len();
    if len == 0 {
        unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        }
        return Ok(());
    }
    let mem = unsafe { malloc(len) };
    if mem.is_null() {
        return Err(ERR_ALLOC);
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), mem.cast::<u8>(), len);
        *out_ptr = mem.cast::<u8>();
        *out_len = len;
    }
    Ok(())
}
unsafe fn write_bytes_bridge(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
    bytes: &[u8],
) -> BridgeResult<()> {
    unsafe { write_bytes(out_ptr, out_len, bytes) }.map_err(|code| match code {
        ERR_NULL_PTR => BridgeError::NullPtr,
        ERR_ALLOC => BridgeError::Alloc,
        _ => BridgeError::Alloc,
    })
}
fn parse_account_id(value: String) -> BridgeResult<AccountId> {
    AccountId::parse_encoded(&value).map_err(|_| BridgeError::Authority)
}
fn parse_account_id_for_chain(value: String, chain_discriminant: u16) -> BridgeResult<AccountId> {
    let _chain_discriminant = ChainDiscriminantGuard::enter(chain_discriminant);
    parse_account_id(value)
}
fn parse_destination(value: String) -> BridgeResult<AccountId> {
    AccountId::parse_encoded(&value).map_err(|_| BridgeError::Destination)
}
fn parse_asset_definition(value: String) -> BridgeResult<AssetDefinitionId> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::AssetDefinition);
    }
    AssetDefinitionId::parse_address_literal(trimmed).map_err(|_| BridgeError::AssetDefinition)
}
fn parse_asset_definition_with_balance_scope(
    value: String,
) -> BridgeResult<(AssetDefinitionId, AssetBalanceScope)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::AssetDefinition);
    }
    let Some((definition_literal, scope_literal)) = trimmed.split_once("#dataspace:") else {
        return parse_asset_definition(trimmed.to_owned())
            .map(|definition| (definition, AssetBalanceScope::Global));
    };
    if definition_literal.is_empty() || scope_literal.is_empty() || scope_literal.contains('#') {
        return Err(BridgeError::AssetDefinition);
    }
    let definition = parse_asset_definition(definition_literal.to_owned())?;
    let dataspace_id = scope_literal
        .parse::<u64>()
        .map(DataSpaceId::new)
        .map_err(|_| BridgeError::AssetDefinition)?;
    Ok((definition, AssetBalanceScope::Dataspace(dataspace_id)))
}
fn parse_quantity(value: String) -> BridgeResult<Quantity> {
    Quantity::from_str(&value).map_err(|_| BridgeError::Quantity)
}
fn parse_public_quantity(value: String) -> BridgeResult<Quantity> {
    let quantity = parse_quantity(value.clone())?;
    if quantity.to_string() != value {
        return Err(BridgeError::Quantity);
    }
    Ok(quantity)
}
fn parse_private_key_with_algorithm(
    bytes: &[u8],
    algorithm: Algorithm,
) -> BridgeResult<PrivateKey> {
    PrivateKey::from_bytes(algorithm, bytes).map_err(|_| BridgeError::PrivateKey)
}
fn parse_algorithm_code(code: u8) -> BridgeResult<Algorithm> {
    Algorithm::try_from(code).map_err(|_| BridgeError::UnsupportedAlgorithm)
}
macro_rules! define_ed25519_signed_transaction_wrapper {
    (
        $default:ident => $with_algorithm:ident (
            $($argument:ident: $argument_type:ty,)*
        )
        identifiers: ($algorithm_code:ident, $signed_bytes:ident, $hash_bytes:ident);
        $(clear_outputs: $clear_outputs:ident;)?
        {
            $($body:tt)*
        }
    ) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $default(
            $($argument: $argument_type,)*
            out_signed_ptr: *mut *mut c_uchar,
            out_signed_len: *mut c_ulong,
            out_hash_ptr: *mut c_uchar,
            out_hash_len: c_ulong,
        ) -> c_int {
            unsafe {
                $with_algorithm(
                    $($argument,)*
                    Algorithm::Ed25519 as u8,
                    out_signed_ptr,
                    out_signed_len,
                    out_hash_ptr,
                    out_hash_len,
                )
            }
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $with_algorithm(
            $($argument: $argument_type,)*
            $algorithm_code: u8,
            out_signed_ptr: *mut *mut c_uchar,
            out_signed_len: *mut c_ulong,
            out_hash_ptr: *mut c_uchar,
            out_hash_len: c_ulong,
        ) -> c_int {
            $(
                $clear_outputs(
                    out_signed_ptr,
                    out_signed_len,
                    out_hash_ptr,
                    out_hash_len,
                );
            )?
            let result = (|| {
                if out_signed_ptr.is_null() || out_signed_len.is_null() || out_hash_ptr.is_null() {
                    return Err(BridgeError::NullPtr);
                }
                $($body)*
                write_hash(out_hash_ptr, out_hash_len, &$hash_bytes)?;
                unsafe { write_bytes_bridge(out_signed_ptr, out_signed_len, &$signed_bytes) }?;
                Ok(())
            })();
            bridge_result_to_code(result)
        }
    };
}
fn checked_public_key_payload(public_key: &PublicKey) -> BridgeResult<&[u8]> {
    public_key
        .try_to_bytes()
        .map(|(_algorithm, payload)| payload)
        .map_err(|_| BridgeError::PrivateKey)
}
fn parse_ttl(ttl_ms: u64, present: bool) -> BridgeResult<Option<NonZeroU64>> {
    if !present {
        return Ok(None);
    }
    NonZeroU64::new(ttl_ms)
        .map(Some)
        .ok_or(BridgeError::InvalidTtl)
}
fn parse_nonce(nonce: u32, present: bool) -> BridgeResult<Option<NonZeroU32>> {
    if !present {
        return Ok(None);
    }
    NonZeroU32::new(nonce)
        .map(Some)
        .ok_or(BridgeError::InvalidNonce)
}
fn parse_name(value: String) -> BridgeResult<Name> {
    Name::from_str(&value).map_err(|_| BridgeError::MetadataKey)
}
unsafe fn parse_fee_payment_intent_bridge(
    ptr: *const c_uchar,
    len: c_ulong,
) -> BridgeResult<FeePaymentIntent> {
    if ptr.is_null() || len == 0 {
        return Err(BridgeError::FeePayment);
    }
    let bytes = unsafe { slice::from_raw_parts(ptr, len as usize) };
    let intent =
        norito::json::from_slice::<FeePaymentIntent>(bytes).map_err(|_| BridgeError::FeePayment)?;
    intent.validate().map_err(|_| BridgeError::FeePayment)?;
    Ok(intent)
}
fn parse_json_value(bytes: &[u8]) -> BridgeResult<Json> {
    let value: norito::json::Value =
        norito::json::from_slice(bytes).map_err(|_| BridgeError::MetadataValue)?;
    Json::from_norito_value_ref(&value).map_err(|_| BridgeError::MetadataValue)
}
fn normalize_zk_ballot_public_inputs(value: &mut JsonValue) -> BridgeResult<()> {
    let map = match value {
        JsonValue::Object(map) => map,
        _ => return Err(BridgeError::Governance),
    };
    reject_zk_public_input_key(map, "durationBlocks", "duration_blocks")?;
    reject_zk_public_input_key(map, "root_hint_hex", "root_hint")?;
    reject_zk_public_input_key(map, "rootHintHex", "root_hint")?;
    reject_zk_public_input_key(map, "rootHint", "root_hint")?;
    reject_zk_public_input_key(map, "nullifier_hex", "nullifier")?;
    reject_zk_public_input_key(map, "nullifierHex", "nullifier")?;
    canonicalize_hex32_public_input(map, "root_hint")?;
    canonicalize_hex32_public_input(map, "nullifier")?;
    let has_owner = zk_hint_present(map, "owner");
    let has_amount = zk_hint_present(map, "amount");
    let has_duration = zk_hint_present(map, "duration_blocks");
    let any = has_owner || has_amount || has_duration;
    if any && !(has_owner && has_amount && has_duration) {
        return Err(BridgeError::Governance);
    }
    ensure_zk_public_input_owner_canonical(map)?;
    ensure_zk_public_input_amount_canonical(map)?;
    Ok(())
}
fn reject_zk_public_input_key(map: &JsonMap, key: &str, _canonical: &str) -> BridgeResult<()> {
    if map.contains_key(key) {
        return Err(BridgeError::Governance);
    }
    Ok(())
}
fn ensure_zk_public_input_owner_canonical(map: &JsonMap) -> BridgeResult<()> {
    let Some(value) = map.get("owner") else {
        return Ok(());
    };
    if matches!(value, JsonValue::Null) {
        return Ok(());
    }
    let owner = value.as_str().ok_or(BridgeError::Governance)?;
    let canonical = AccountId::canonicalize(owner).map_err(|_| BridgeError::Governance)?;
    if canonical != owner {
        return Err(BridgeError::Governance);
    }
    Ok(())
}
fn ensure_zk_public_input_amount_canonical(map: &JsonMap) -> BridgeResult<()> {
    let Some(value) = map.get("amount") else {
        return Ok(());
    };
    if matches!(value, JsonValue::Null) {
        return Ok(());
    }
    let amount = value.as_str().ok_or(BridgeError::Governance)?;
    parse_public_quantity(amount.to_owned())
        .map(|_| ())
        .map_err(|_| BridgeError::Governance)
}
fn canonicalize_hex32_public_input(map: &mut JsonMap, key: &str) -> BridgeResult<()> {
    let Some(value) = map.get_mut(key) else {
        return Ok(());
    };
    if matches!(value, JsonValue::Null) {
        return Ok(());
    }
    let raw = value.as_str().ok_or(BridgeError::Governance)?;
    let canonical = canonicalize_hex32_value(raw).ok_or(BridgeError::Governance)?;
    *value = JsonValue::String(canonical);
    Ok(())
}
fn canonicalize_hex32_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let without_scheme = if let Some((scheme, rest)) = trimmed.split_once(':') {
        if scheme.is_empty() || scheme.eq_ignore_ascii_case("blake2b32") {
            rest
        } else {
            return None;
        }
    } else {
        trimmed
    };
    let body = without_scheme.trim();
    let body = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body)
        .trim();
    if body.len() != 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(body.to_ascii_lowercase())
}
fn zk_hint_present(map: &JsonMap, key: &str) -> bool {
    map.get(key)
        .map(|value| !matches!(value, JsonValue::Null))
        .unwrap_or(false)
}
enum MetadataTarget {
    Domain(DomainId),
    Account(AccountId),
    Rwa(RwaId),
    AssetDefinition(AssetDefinitionId),
    Asset(AssetId),
}
fn parse_metadata_target(kind: u8, object: String) -> BridgeResult<MetadataTarget> {
    match kind {
        0 => DomainId::parse_fully_qualified(&object)
            .map(MetadataTarget::Domain)
            .map_err(|_| BridgeError::MetadataTarget),
        1 => parse_account_id(object).map(MetadataTarget::Account),
        4 => object
            .parse::<RwaId>()
            .map(MetadataTarget::Rwa)
            .map_err(|_| BridgeError::MetadataTarget),
        2 => parse_asset_definition(object).map(MetadataTarget::AssetDefinition),
        3 => AssetId::parse_literal(&object)
            .map(MetadataTarget::Asset)
            .map_err(|_| BridgeError::MetadataTarget),
        _ => Err(BridgeError::MetadataTarget),
    }
}
fn build_set_metadata_instruction(
    target: MetadataTarget,
    key: Name,
    value: Json,
) -> InstructionBox {
    match target {
        MetadataTarget::Domain(id) => InstructionBox::from(SetKeyValue::domain(id, key, value)),
        MetadataTarget::Account(id) => InstructionBox::from(SetKeyValue::account(id, key, value)),
        MetadataTarget::Rwa(id) => InstructionBox::from(SetKeyValue::rwa(id, key, value)),
        MetadataTarget::AssetDefinition(id) => {
            InstructionBox::from(SetKeyValue::asset_definition(id, key, value))
        }
        MetadataTarget::Asset(id) => InstructionBox::from(SetAssetKeyValue::new(id, key, value)),
    }
}
fn build_remove_metadata_instruction(target: MetadataTarget, key: Name) -> InstructionBox {
    match target {
        MetadataTarget::Domain(id) => InstructionBox::from(RemoveKeyValue::domain(id, key)),
        MetadataTarget::Account(id) => InstructionBox::from(RemoveKeyValue::account(id, key)),
        MetadataTarget::Rwa(id) => InstructionBox::from(RemoveKeyValue::rwa(id, key)),
        MetadataTarget::AssetDefinition(id) => {
            InstructionBox::from(RemoveKeyValue::asset_definition(id, key))
        }
        MetadataTarget::Asset(id) => InstructionBox::from(RemoveAssetKeyValue::new(id, key)),
    }
}
fn parse_verifying_key_id_value(value: &str) -> BridgeResult<VerifyingKeyId> {
    let trimmed = value.trim();
    let (backend, name) = trimmed.split_once(':').ok_or(BridgeError::VerifyingKeyId)?;
    if backend.is_empty() || name.is_empty() {
        return Err(BridgeError::VerifyingKeyId);
    }
    Ok(VerifyingKeyId::new(backend, name))
}
unsafe fn parse_optional_verifying_key_id(
    ptr: *const c_char,
    len: c_ulong,
    present: c_uchar,
) -> BridgeResult<Option<VerifyingKeyId>> {
    if present == 0 {
        return Ok(None);
    }
    let raw = unsafe { read_string_bridge(ptr, len) }?;
    if raw.trim().is_empty() {
        return Err(BridgeError::VerifyingKeyId);
    }
    parse_verifying_key_id_value(&raw).map(Some)
}
fn write_hash(
    out_hash_ptr: *mut c_uchar,
    out_hash_len: c_ulong,
    hash: &[u8; 32],
) -> BridgeResult<()> {
    if out_hash_ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    if out_hash_len < hash.len() as c_ulong {
        return Err(BridgeError::HashOutBuffer);
    }
    unsafe {
        ptr::copy_nonoverlapping(hash.as_ptr(), out_hash_ptr, hash.len());
    }
    Ok(())
}
fn clear_bridge_output(out_ptr: *mut *mut c_uchar, out_len: *mut c_ulong) {
    if !out_ptr.is_null() {
        unsafe {
            *out_ptr = ptr::null_mut();
        }
    }
    if !out_len.is_null() {
        unsafe {
            *out_len = 0;
        }
    }
}
fn clear_bridge_output_or_null(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> BridgeResult<()> {
    clear_bridge_output(out_ptr, out_len);
    if out_ptr.is_null() || out_len.is_null() {
        return Err(BridgeError::NullPtr);
    }
    Ok(())
}
fn clear_signed_transaction_outputs(
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
    out_hash_ptr: *mut c_uchar,
    out_hash_len: c_ulong,
) {
    clear_bridge_output(out_signed_ptr, out_signed_len);
    if !out_hash_ptr.is_null() {
        let clear_len = usize::try_from(out_hash_len)
            .unwrap_or(usize::MAX)
            .min(Hash::LENGTH);
        unsafe { ptr::write_bytes(out_hash_ptr, 0, clear_len) };
    }
}
fn bridge_result_to_code(result: BridgeResult<()>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(err) => err.code(),
    }
}
const PRIVACY_BUFFER_HEADER_MAGIC: u64 = 0x4952_5041_484f_5249;
const PRIVACY_BUFFER_HEADER_BYTES: usize = std::mem::size_of::<PrivacyBufferHeader>();
const PRIVACY_COMPILED_PROFILE_CATALOG_WORKER_STACK_BYTES_V1: usize = 8 * 1024 * 1024;
const PRIVACY_NATIVE_OUTPUT_MAX_BYTES_V1: usize =
    if PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1
        > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1
    {
        PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1
    } else {
        PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1
    };
#[repr(C)]
#[derive(Clone, Copy)]
struct PrivacyBufferHeader {
    magic: u64,
    len: usize,
}
static PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_V1: OnceLock<Result<Vec<u8>, c_int>> =
    OnceLock::new();
#[cfg(test)]
static PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_INITIALIZATIONS_V1: AtomicU64 = AtomicU64::new(0);
fn privacy_compiled_profile_catalog() -> Result<PrivacyCompiledProfileCatalogV1, c_int> {
    let catalog = compiled_privacy_profile_catalog_v1().map_err(|_| ERR_CONNECT_ENCODE)?;
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
fn build_privacy_compiled_profile_catalog_archive_v1() -> Result<Vec<u8>, c_int> {
    let catalog = privacy_compiled_profile_catalog()?;
    let bytes = norito::encode_canonical(&catalog).map_err(|_| ERR_CONNECT_ENCODE)?;
    if bytes.len() > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1
        || !validate_local_privacy_compiled_profile_catalog_archive_v1(&bytes).is_valid()
    {
        return Err(ERR_CONNECT_ENCODE);
    }
    Ok(bytes)
}
fn privacy_compiled_profile_catalog_archive_v1() -> Result<&'static [u8], c_int> {
    // The catalog is immutable build metadata, but its first derivation
    // initializes several native cryptographic profiles. Own that one-time
    // stack budget at the FFI boundary instead of inheriting an arbitrary
    // mobile/runtime caller stack. Initialization, including deterministic
    // failure, is serialized and cached so concurrent cold callers cannot
    // amplify the owned worker-stack allocation.
    let archive = PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_V1.get_or_init(|| {
        #[cfg(test)]
        PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_INITIALIZATIONS_V1.fetch_add(1, Ordering::Relaxed);
        let worker = std::thread::Builder::new()
            .name("iroha-privacy-profile-catalog-v1".to_owned())
            .stack_size(PRIVACY_COMPILED_PROFILE_CATALOG_WORKER_STACK_BYTES_V1)
            .spawn(build_privacy_compiled_profile_catalog_archive_v1)
            .map_err(|_| ERR_CONNECT_ENCODE)?;
        worker.join().map_err(|_| ERR_CONNECT_ENCODE)?
    });
    archive.as_ref().map(Vec::as_slice).map_err(|code| *code)
}
fn clear_privacy_output(out_ptr: *mut *mut c_uchar, out_len: *mut c_ulong) {
    if !out_ptr.is_null() {
        unsafe {
            *out_ptr = ptr::null_mut();
        }
    }
    if !out_len.is_null() {
        unsafe {
            *out_len = 0;
        }
    }
}
unsafe fn write_privacy_bytes(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
    bytes: &[u8],
) -> Result<(), c_int> {
    if out_ptr.is_null() || out_len.is_null() {
        return Err(ERR_NULL_PTR);
    }
    let len = bytes.len();
    if len == 0 {
        unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        }
        return Ok(());
    }
    if len > PRIVACY_NATIVE_OUTPUT_MAX_BYTES_V1 {
        return Err(ERR_CONNECT_ENCODE);
    }
    let total = PRIVACY_BUFFER_HEADER_BYTES
        .checked_add(len)
        .ok_or(ERR_ALLOC)?;
    let mem = unsafe { malloc(total) };
    if mem.is_null() {
        return Err(ERR_ALLOC);
    }
    unsafe {
        let header = mem.cast::<PrivacyBufferHeader>();
        ptr::write(
            header,
            PrivacyBufferHeader {
                magic: PRIVACY_BUFFER_HEADER_MAGIC,
                len,
            },
        );
        let payload = (mem.cast::<u8>()).add(PRIVACY_BUFFER_HEADER_BYTES);
        ptr::copy_nonoverlapping(bytes.as_ptr(), payload, len);
        *out_ptr = payload;
        *out_len = len as c_ulong;
    }
    Ok(())
}
unsafe fn privacy_buffer_header_from_payload(ptr_: *mut c_uchar) -> *mut PrivacyBufferHeader {
    unsafe {
        ptr_.sub(PRIVACY_BUFFER_HEADER_BYTES)
            .cast::<PrivacyBufferHeader>()
    }
}
unsafe fn clear_privacy_allocated_buffer(ptr_: *mut c_uchar) -> *mut c_uchar {
    if ptr_.is_null() {
        return ptr_;
    }
    let header = unsafe { privacy_buffer_header_from_payload(ptr_) };
    let valid = unsafe {
        (*header).magic == PRIVACY_BUFFER_HEADER_MAGIC
            && (*header).len > 0
            && (*header).len <= PRIVACY_NATIVE_OUTPUT_MAX_BYTES_V1
    };
    if !valid {
        return ptr_;
    }
    let len = unsafe { (*header).len };
    unsafe {
        ptr::write_bytes(ptr_, 0, len);
        ptr::write_bytes(header.cast::<u8>(), 0, PRIVACY_BUFFER_HEADER_BYTES);
    }
    header.cast::<c_uchar>()
}
fn write_privacy_compiled_profile_catalog(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    clear_privacy_output(out_ptr, out_len);
    if out_ptr.is_null() || out_len.is_null() {
        return ERR_NULL_PTR;
    }
    let Ok(bytes) = privacy_compiled_profile_catalog_archive_v1() else {
        return ERR_CONNECT_ENCODE;
    };
    match unsafe { write_privacy_bytes(out_ptr, out_len, bytes) } {
        Ok(()) => 0,
        Err(code) => code,
    }
}
/// Return this binary's canonical local compiled-profile catalog.
///
/// The catalog contains no committed height, consensus policy, activation, or
/// readiness state. A client must fetch an authoritative capability snapshot
/// from live Torii before treating any protocol as ready for proof submission.
/// The output must be released with [`iroha_privacy_free_buffer`].
///
/// # Safety
///
/// `out_ptr` and `out_len` must be valid writable pointers for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iroha_privacy_compiled_profile_catalog_v1(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    write_privacy_compiled_profile_catalog(out_ptr, out_len)
}
/// Validate one archive as this binary's exact local compiled-profile catalog.
///
/// The return value is a stable
/// [`PrivacyCompiledProfileCatalogArchiveValidationStatusV1`] discriminant.
/// Only zero means the archive matches this binary. Success says nothing about
/// committed governance state or network readiness.
///
/// # Safety
///
/// For a non-zero `archive_len`, `archive_ptr` must reference at least that
/// many readable bytes for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iroha_privacy_validate_compiled_profile_catalog_v1(
    archive_ptr: *const c_uchar,
    archive_len: c_ulong,
) -> c_int {
    if archive_ptr.is_null() {
        return PrivacyCompiledProfileCatalogArchiveValidationStatusV1::NullPointer.code();
    }
    let Ok(archive_len) = usize::try_from(archive_len) else {
        return PrivacyCompiledProfileCatalogArchiveValidationStatusV1::ArchiveTooLarge.code();
    };
    if archive_len > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1 {
        return PrivacyCompiledProfileCatalogArchiveValidationStatusV1::ArchiveTooLarge.code();
    }
    let archive = unsafe { slice::from_raw_parts(archive_ptr, archive_len) };
    validate_local_privacy_compiled_profile_catalog_archive_v1(archive).code()
}
/// Validate canonical Exact12 capability evidence with the authoritative Rust verifier.
///
/// Returns the stable [`PrivacyCapabilityArchiveValidationStatusV1`] code. Only zero accepts the
/// complete archive, including release/audit signatures, deployment signatures, exact evidence
/// counts, and recomputed digests. Callers must additionally compare the committed compiled
/// tuples to their local catalog and obtain network state through authenticated Torii transport.
///
/// # Safety
///
/// For a non-zero `archive_len`, `archive_ptr` must reference at least that many readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iroha_privacy_validate_exact12_capability_manifest_v1(
    archive_ptr: *const c_uchar,
    archive_len: c_ulong,
) -> c_int {
    if archive_ptr.is_null() {
        return PrivacyCapabilityArchiveValidationStatusV1::NullPointer.code();
    }
    let Ok(archive_len) = usize::try_from(archive_len) else {
        return PrivacyCapabilityArchiveValidationStatusV1::ArchiveTooLarge.code();
    };
    if archive_len > PRIVACY_CAPABILITY_ARCHIVE_MAX_BYTES_V1 {
        return PrivacyCapabilityArchiveValidationStatusV1::ArchiveTooLarge.code();
    }
    let archive = unsafe { slice::from_raw_parts(archive_ptr, archive_len) };
    validate_privacy_capability_archive_v1(archive).code()
}
/// Return the complete Rust-derived exact-12 transaction-layer KAT bundle.
///
/// The output is canonical Norito and must be released with
/// [`iroha_privacy_free_buffer`].
///
/// # Safety
///
/// `out_ptr` and `out_len` must be valid writable pointers for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iroha_privacy_exact12_fixture_bundle_v1(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    clear_privacy_output(out_ptr, out_len);
    if out_ptr.is_null() || out_len.is_null() {
        return ERR_NULL_PTR;
    }
    let Ok(mut bytes) = privacy_exact12_fixture_bundle_bytes_v1() else {
        return ERR_CONNECT_ENCODE;
    };
    let result = if bytes.len() > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1
        || !validate_privacy_exact12_fixture_bundle_v1(&bytes).is_valid()
    {
        ERR_CONNECT_ENCODE
    } else {
        match unsafe { write_privacy_bytes(out_ptr, out_len, &bytes) } {
            Ok(()) => 0,
            Err(code) => code,
        }
    };
    bytes.fill(0);
    result
}
/// Validate one untrusted canonical exact-12 transaction-layer KAT bundle.
///
/// # Safety
///
/// For a non-zero `archive_len`, `archive_ptr` must reference at least that
/// many readable bytes for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iroha_privacy_validate_exact12_fixture_bundle_v1(
    archive_ptr: *const c_uchar,
    archive_len: c_ulong,
) -> c_int {
    if archive_ptr.is_null() {
        return PrivacyExact12FixtureBundleValidationStatusV1::NullPointer.code();
    }
    let Ok(archive_len) = usize::try_from(archive_len) else {
        return PrivacyExact12FixtureBundleValidationStatusV1::ArchiveTooLarge.code();
    };
    if archive_len > PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 {
        return PrivacyExact12FixtureBundleValidationStatusV1::ArchiveTooLarge.code();
    }
    let archive = unsafe { slice::from_raw_parts(archive_ptr, archive_len) };
    validate_privacy_exact12_fixture_bundle_v1(archive).code()
}
fn parse_multisig_spec_bytes(ptr: *const c_char, len: c_ulong) -> BridgeResult<MultisigSpec> {
    if ptr.is_null() || len == 0 {
        return Err(BridgeError::MultisigSpec);
    }
    let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) };
    norito::json::from_slice::<MultisigSpec>(bytes).map_err(|_| BridgeError::MultisigSpec)
}
fn parse_identifier_receipt_bytes(
    ptr: *const c_char,
    len: c_ulong,
) -> BridgeResult<IdentifierResolutionReceipt> {
    if ptr.is_null() || len == 0 {
        return Err(BridgeError::IdentifierReceipt);
    }
    let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) };
    let value =
        norito::json::from_slice::<JsonValue>(bytes).map_err(|_| BridgeError::IdentifierReceipt)?;
    parse_identifier_receipt_value(value)
}
fn parse_identifier_receipt_value(value: JsonValue) -> BridgeResult<IdentifierResolutionReceipt> {
    let JsonValue::Object(object) = value else {
        return Err(BridgeError::IdentifierReceipt);
    };
    let payload = parse_identifier_receipt_payload_value(
        object
            .get("payload")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let attestation = parse_identifier_receipt_attestation(
        object
            .get("attestation")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let phone_retail_canonicality = match object.get("phone_retail_canonicality") {
        None | Some(JsonValue::Null) => None,
        Some(value) => Some(
            norito::json::from_value(value.clone()).map_err(|_| BridgeError::IdentifierReceipt)?,
        ),
    };
    Ok(IdentifierResolutionReceipt {
        payload,
        attestation,
        phone_retail_canonicality,
    })
}
fn validate_identifier_claim_account(
    account: &AccountId,
    receipt: &IdentifierResolutionReceipt,
) -> BridgeResult<()> {
    if &receipt.payload.account_id != account {
        return Err(BridgeError::IdentifierReceipt);
    }
    Ok(())
}
fn parse_identifier_receipt_attestation(
    value: &JsonValue,
) -> BridgeResult<RamLfeReceiptAttestation> {
    let object = value.as_object().ok_or(BridgeError::IdentifierReceipt)?;
    let kind =
        parse_identifier_exact_str(object.get("kind").ok_or(BridgeError::IdentifierReceipt)?)?;
    match kind.as_str() {
        "signed" => {
            if object.len() != 2 {
                return Err(BridgeError::IdentifierReceipt);
            }
            // The current public DTO carries no caller-selected algorithm. The
            // pinned key selects canonical algorithm admission during verification.
            parse_identifier_receipt_signature(object.get("signature"), true)
                .map(RamLfeReceiptAttestation::Signed)
        }
        "proof" => {
            if object.len() != 3 {
                return Err(BridgeError::IdentifierReceipt);
            }
            let proof_backend = parse_identifier_exact_str(
                object
                    .get("proof_backend")
                    .ok_or(BridgeError::IdentifierReceipt)?,
            )?;
            let proof_b64 = parse_identifier_exact_str(
                object
                    .get("proof_b64")
                    .ok_or(BridgeError::IdentifierReceipt)?,
            )?;
            let bytes = b64gp::STANDARD
                .decode(proof_b64)
                .map_err(|_| BridgeError::IdentifierReceipt)?;
            Ok(RamLfeReceiptAttestation::Proof(ProofBox::new(
                proof_backend,
                bytes,
            )))
        }
        _ => Err(BridgeError::IdentifierReceipt),
    }
}
fn parse_identifier_receipt_signature(
    value: Option<&JsonValue>,
    uppercase: bool,
) -> BridgeResult<Signature> {
    let signature_hex = value
        .and_then(JsonValue::as_str)
        .ok_or(BridgeError::IdentifierReceipt)?;
    if !signature_hex.bytes().all(|byte| {
        byte.is_ascii_digit()
            || if uppercase {
                (b'A'..=b'F').contains(&byte)
            } else {
                (b'a'..=b'f').contains(&byte)
            }
    }) {
        return Err(BridgeError::IdentifierReceipt);
    }
    let signature_bytes = decode_identifier_receipt_hex(signature_hex)?;
    Signature::try_from_bytes(&signature_bytes).map_err(|_| BridgeError::IdentifierReceipt)
}
fn parse_identifier_receipt_payload_value(
    value: &JsonValue,
) -> BridgeResult<IdentifierResolutionReceiptPayload> {
    let object = value.as_object().ok_or(BridgeError::IdentifierReceipt)?;
    if object.len() != 8 {
        return Err(BridgeError::IdentifierReceipt);
    }
    let network_literal = object
        .get("network_id")
        .and_then(JsonValue::as_str)
        .ok_or(BridgeError::IdentifierReceipt)?;
    if network_literal.len() != 64
        || !network_literal
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BridgeError::IdentifierReceipt);
    }
    let network_hash = network_literal
        .parse::<Hash>()
        .map_err(|_| BridgeError::IdentifierReceipt)?;
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(network_hash),
    );
    let policy_id = parse_identifier_policy_id_value(
        object
            .get("policy_id")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let execution = parse_identifier_execution_payload_value(
        object
            .get("execution")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let opening = parse_identifier_output_opening_value(
        object
            .get("opening")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let opaque_id = parse_identifier_opaque_id_value(
        object
            .get("opaque_id")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let receipt_hash = parse_identifier_hash_value(
        object
            .get("receipt_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let uaid =
        parse_identifier_uaid_value(object.get("uaid").ok_or(BridgeError::IdentifierReceipt)?)?;
    let account_id = parse_identifier_exact_str(
        object
            .get("account_id")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )
    .and_then(|value| parse_account_id(value).map_err(|_| BridgeError::IdentifierReceipt))?;
    Ok(IdentifierResolutionReceiptPayload {
        network_id,
        policy_id,
        execution,
        opening,
        opaque_id,
        receipt_hash,
        uaid,
        account_id,
    })
}
fn parse_identifier_output_opening_value(
    value: &JsonValue,
) -> BridgeResult<iroha_data_model::ram_lfe::RamLfeOutputOpening> {
    let object = value.as_object().ok_or(BridgeError::IdentifierReceipt)?;
    let payload_value = object
        .get("payload")
        .ok_or(BridgeError::IdentifierReceipt)?;
    let payload_object = payload_value
        .as_object()
        .ok_or(BridgeError::IdentifierReceipt)?;
    let program_id = parse_identifier_program_id_value(
        payload_object
            .get("program_id")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let input_ciphertext_hash = parse_identifier_hash_value(
        payload_object
            .get("input_ciphertext_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let output_ciphertext_hash = parse_identifier_hash_value(
        payload_object
            .get("output_ciphertext_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let parameter_digest = parse_identifier_hash_value(
        payload_object
            .get("parameter_digest")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let evaluation_key_digest = parse_identifier_hash_value(
        payload_object
            .get("evaluation_key_digest")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let opened_output_hash = parse_identifier_hash_value(
        payload_object
            .get("opened_output_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let opened_at_ms = payload_object
        .get("opened_at_ms")
        .and_then(JsonValue::as_u64)
        .ok_or(BridgeError::IdentifierReceipt)?;
    let expires_at_ms = payload_object
        .get("expires_at_ms")
        .and_then(JsonValue::as_u64);
    let signature = parse_identifier_receipt_signature(object.get("signature"), false)?;
    Ok(iroha_data_model::ram_lfe::RamLfeOutputOpening {
        payload: iroha_data_model::ram_lfe::RamLfeOutputOpeningPayload {
            program_id,
            input_ciphertext_hash,
            output_ciphertext_hash,
            parameter_digest,
            evaluation_key_digest,
            opened_output_hash,
            opened_at_ms,
            expires_at_ms,
        },
        signature,
    })
}
fn parse_identifier_policy_id_value(
    value: &JsonValue,
) -> BridgeResult<iroha_data_model::identifier::IdentifierPolicyId> {
    parse_identifier_exact_str(value)?
        .parse()
        .map_err(|_| BridgeError::IdentifierReceipt)
}
fn parse_identifier_program_id_value(value: &JsonValue) -> BridgeResult<RamLfeProgramId> {
    parse_identifier_exact_str(value)?
        .parse()
        .map_err(|_| BridgeError::IdentifierReceipt)
}
fn parse_identifier_receipt_backend(value: &JsonValue) -> BridgeResult<RamLfeBackend> {
    let backend = parse_identifier_exact_str(value)?;
    match backend.as_str() {
        "hkdf-sha3-512-prf-v1" => Ok(RamLfeBackend::HkdfSha3_512PrfV1),
        "bfv-affine-v1" => Ok(RamLfeBackend::BfvAffineV1),
        "bfv-programmed-v1" => Ok(RamLfeBackend::BfvProgrammedV1),
        _ => Err(BridgeError::IdentifierReceipt),
    }
}
fn parse_identifier_receipt_verification_mode(
    value: &JsonValue,
) -> BridgeResult<RamLfeVerificationMode> {
    match parse_identifier_exact_str(value)?.as_str() {
        "signed" => Ok(RamLfeVerificationMode::Signed),
        "proof" => Ok(RamLfeVerificationMode::Proof),
        _ => Err(BridgeError::IdentifierReceipt),
    }
}
fn parse_identifier_exact_str(value: &JsonValue) -> BridgeResult<String> {
    let raw = value.as_str().ok_or(BridgeError::IdentifierReceipt)?;
    if raw.is_empty() || raw.trim() != raw {
        return Err(BridgeError::IdentifierReceipt);
    }
    Ok(raw.to_owned())
}
fn parse_identifier_hash_str(value: &str) -> BridgeResult<Hash> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BridgeError::IdentifierReceipt);
    }
    Hash::from_str(value).map_err(|_| BridgeError::IdentifierReceipt)
}
fn parse_identifier_hash_value(value: &JsonValue) -> BridgeResult<Hash> {
    value
        .as_str()
        .ok_or(BridgeError::IdentifierReceipt)
        .and_then(parse_identifier_hash_str)
}
fn parse_identifier_opaque_id_value(
    value: &JsonValue,
) -> BridgeResult<iroha_data_model::account::OpaqueAccountId> {
    parse_identifier_exact_str(value)?
        .parse()
        .map_err(|_| BridgeError::IdentifierReceipt)
}
fn parse_identifier_uaid_value(
    value: &JsonValue,
) -> BridgeResult<iroha_data_model::nexus::UniversalAccountId> {
    parse_identifier_exact_str(value)?
        .parse()
        .map_err(|_| BridgeError::IdentifierReceipt)
}
fn parse_identifier_execution_payload_value(
    value: &JsonValue,
) -> BridgeResult<RamLfeExecutionReceiptPayload> {
    let object = value.as_object().ok_or(BridgeError::IdentifierReceipt)?;
    let program_id = parse_identifier_program_id_value(
        object
            .get("program_id")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let program_digest = parse_identifier_hash_value(
        object
            .get("program_digest")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let backend = parse_identifier_receipt_backend(
        object
            .get("backend")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let verification_mode = parse_identifier_receipt_verification_mode(
        object
            .get("verification_mode")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let output_hash = parse_identifier_hash_value(
        object
            .get("output_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let input_ciphertext_hash = parse_identifier_hash_value(
        object
            .get("input_ciphertext_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let output_ciphertext_hash = parse_identifier_hash_value(
        object
            .get("output_ciphertext_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let parameter_digest = parse_identifier_hash_value(
        object
            .get("parameter_digest")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let evaluation_key_digest = parse_identifier_hash_value(
        object
            .get("evaluation_key_digest")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let associated_data_hash = parse_identifier_hash_value(
        object
            .get("associated_data_hash")
            .ok_or(BridgeError::IdentifierReceipt)?,
    )?;
    let executed_at_ms = object
        .get("executed_at_ms")
        .and_then(JsonValue::as_u64)
        .ok_or(BridgeError::IdentifierReceipt)?;
    let expires_at_ms = object.get("expires_at_ms").and_then(JsonValue::as_u64);
    Ok(RamLfeExecutionReceiptPayload {
        program_id,
        program_digest,
        backend,
        verification_mode,
        input_ciphertext_hash,
        output_ciphertext_hash,
        parameter_digest,
        evaluation_key_digest,
        output_hash,
        associated_data_hash,
        executed_at_ms,
        expires_at_ms,
    })
}
fn decode_identifier_receipt_hex(value: &str) -> BridgeResult<Vec<u8>> {
    if value.is_empty() || value.trim() != value {
        return Err(BridgeError::IdentifierReceipt);
    }
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err(BridgeError::IdentifierReceipt);
    }
    hex::decode(value).map_err(|_| BridgeError::IdentifierReceipt)
}
fn write_optional_error(out_ptr: *mut *mut c_uchar, out_len: *mut c_ulong) {
    if !out_ptr.is_null() {
        unsafe { *out_ptr = ptr::null_mut() };
    }
    if !out_len.is_null() {
        unsafe { *out_len = 0 };
    }
}
// ---------------- Signing helpers ----------------
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_public_key_from_private(
    algorithm_code: u8,
    private_ptr: *const c_uchar,
    private_len: c_ulong,
    out_public_ptr: *mut *mut c_uchar,
    out_public_len: *mut c_ulong,
) -> c_int {
    let result = (|| {
        if private_ptr.is_null() || out_public_ptr.is_null() || out_public_len.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let private_bytes = unsafe { slice::from_raw_parts(private_ptr, private_len as usize) };
        let private_key = parse_private_key_with_algorithm(private_bytes, algorithm)?;
        let key_pair =
            KeyPair::from_private_key(private_key).map_err(|_| BridgeError::PrivateKey)?;
        let public_bytes = checked_public_key_payload(key_pair.public_key())?;
        unsafe { write_bytes_bridge(out_public_ptr, out_public_len, public_bytes) }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_keypair_from_seed(
    algorithm_code: u8,
    seed_ptr: *const c_uchar,
    seed_len: c_ulong,
    out_private_ptr: *mut *mut c_uchar,
    out_private_len: *mut c_ulong,
    out_public_ptr: *mut *mut c_uchar,
    out_public_len: *mut c_ulong,
) -> c_int {
    let result = (|| {
        if seed_ptr.is_null()
            || out_private_ptr.is_null()
            || out_private_len.is_null()
            || out_public_ptr.is_null()
            || out_public_len.is_null()
        {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let seed_bytes = unsafe { slice::from_raw_parts(seed_ptr, seed_len as usize) };
        let key_pair = KeyPair::try_from_seed(seed_bytes.to_vec(), algorithm)
            .map_err(|_| BridgeError::ConnectKeypair)?;
        let (public_key, private_key) = key_pair.into_parts();
        let (_alg, private_bytes) = private_key.to_bytes();
        let private_bytes = Zeroizing::new(private_bytes);
        let public_bytes = checked_public_key_payload(&public_key)?;
        match unsafe { write_bytes(out_private_ptr, out_private_len, private_bytes.as_slice()) } {
            Ok(()) => {}
            Err(code) => {
                return Err(match code {
                    ERR_NULL_PTR => BridgeError::NullPtr,
                    _ => BridgeError::Alloc,
                });
            }
        }
        match unsafe { write_bytes(out_public_ptr, out_public_len, public_bytes) } {
            Ok(()) => Ok(()),
            Err(code) => {
                unsafe {
                    free(*out_private_ptr as *mut _);
                    *out_private_ptr = ptr::null_mut();
                    *out_private_len = 0;
                }
                Err(match code {
                    ERR_NULL_PTR => BridgeError::NullPtr,
                    _ => BridgeError::Alloc,
                })
            }
        }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sign_detached(
    algorithm_code: u8,
    private_ptr: *const c_uchar,
    private_len: c_ulong,
    message_ptr: *const c_uchar,
    message_len: c_ulong,
    out_signature_ptr: *mut *mut c_uchar,
    out_signature_len: *mut c_ulong,
) -> c_int {
    let result = (|| {
        if private_ptr.is_null()
            || message_ptr.is_null()
            || out_signature_ptr.is_null()
            || out_signature_len.is_null()
        {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let private_bytes = unsafe { slice::from_raw_parts(private_ptr, private_len as usize) };
        let message = unsafe { slice::from_raw_parts(message_ptr, message_len as usize) };
        let private_key = parse_private_key_with_algorithm(private_bytes, algorithm)?;
        let signature =
            Signature::try_new(&private_key, message).map_err(|_| BridgeError::SecpSign)?;
        unsafe { write_bytes_bridge(out_signature_ptr, out_signature_len, signature.payload()) }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_verify_detached(
    algorithm_code: u8,
    public_ptr: *const c_uchar,
    public_len: c_ulong,
    message_ptr: *const c_uchar,
    message_len: c_ulong,
    signature_ptr: *const c_uchar,
    signature_len: c_ulong,
    out_valid: *mut c_uchar,
) -> c_int {
    let result = (|| {
        if public_ptr.is_null()
            || message_ptr.is_null()
            || signature_ptr.is_null()
            || out_valid.is_null()
        {
            return Err(BridgeError::NullPtr);
        }
        unsafe { *out_valid = 0 };
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let public_bytes = unsafe { slice::from_raw_parts(public_ptr, public_len as usize) };
        let public_key =
            PublicKey::from_bytes(algorithm, public_bytes).map_err(|_| BridgeError::PrivateKey)?;
        let message = unsafe { slice::from_raw_parts(message_ptr, message_len as usize) };
        let signature_bytes =
            unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };
        let signature = match connect_signature_from_algorithm_bytes(algorithm, signature_bytes) {
            Some(signature) => signature,
            None => return Ok(()),
        };
        match signature.verify(&public_key, message) {
            Ok(()) => {
                unsafe { *out_valid = 1 };
                Ok(())
            }
            Err(CryptoError::BadSignature) => Ok(()),
            Err(_) => Err(BridgeError::UnsupportedAlgorithm),
        }
    })();
    bridge_result_to_code(result)
}
// ---------------- Chain discriminant helpers ----------------
static NEXT_CHAIN_DISCRIMINANT_SCOPE_TOKEN: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static CHAIN_DISCRIMINANT_SCOPES: RefCell<Vec<(u64, ChainDiscriminantGuard)>> =
        const { RefCell::new(Vec::new()) };
}
/// Enter a chain-discriminant override scoped to the current native thread.
///
/// The returned non-zero token must be exited on the same thread and in LIFO
/// order. A zero token means that the scope could not be entered.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_chain_discriminant_scope_enter(discriminant: u16) -> u64 {
    let token = NEXT_CHAIN_DISCRIMINANT_SCOPE_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .unwrap_or(0);
    if token == 0 {
        return 0;
    }
    let guard = ChainDiscriminantGuard::enter(discriminant);
    CHAIN_DISCRIMINANT_SCOPES.with(|scopes| {
        let Ok(mut scopes) = scopes.try_borrow_mut() else {
            return 0;
        };
        scopes.push((token, guard));
        token
    })
}
/// Exit a current-thread chain-discriminant override.
///
/// Returns zero on success and `-1` for a zero, wrong-thread, underflow, or
/// non-LIFO token. On failure the active scope stack is left unchanged.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_chain_discriminant_scope_exit(token: u64) -> c_int {
    if token == 0 {
        return -1;
    }
    CHAIN_DISCRIMINANT_SCOPES.with(|scopes| {
        let Ok(mut scopes) = scopes.try_borrow_mut() else {
            return -1;
        };
        if scopes.last().map(|(active, _)| *active) != Some(token) {
            return -1;
        }
        scopes.pop();
        0
    })
}
// ---------------- Canonical domain identity ----------------
/// Validate an already canonical ASCII `domain.dataspace` identity.
///
/// This calls the same pinned UTS-46 owner as native `DomainId` wire decoding
/// and requires byte-exact canonical spelling. It never normalizes caller input.
/// Each DNS label is bounded to 63 bytes, for a total of at most 127 bytes.
/// Returns zero for valid input, one for invalid/noncanonical input, `-1` for
/// a null pointer, `-2` for invalid UTF-8 and `-3` for a native panic.
///
/// # Safety
/// A non-null `input_ptr` with a length in `1..=127` must point to that many
/// readable bytes, which must remain unchanged for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_domain_id_validate_v1(
    input_ptr: *const c_char,
    input_len: c_ulong,
) -> c_int {
    if input_ptr.is_null() {
        return -1;
    }
    if !(1..=127).contains(&input_len) {
        return 1;
    }
    // The public length bound is checked before dereferencing or allocating.
    let bytes = unsafe { slice::from_raw_parts(input_ptr.cast::<u8>(), input_len as usize) };
    let Ok(input) = std::str::from_utf8(bytes) else {
        return -2;
    };
    if !input.is_ascii() {
        return 1;
    }
    std::panic::catch_unwind(|| match DomainId::parse_fully_qualified(input) {
        Ok(domain) if domain.to_string() == input => 0,
        _ => 1,
    })
    .unwrap_or(-3)
}

#[cfg(test)]
mod domain_id_ffi_tests {
    use super::*;

    fn validate(input: &str) -> c_int {
        // SAFETY: input remains borrowed and provides exactly its byte length.
        unsafe {
            connect_norito_domain_id_validate_v1(input.as_ptr().cast(), input.len() as c_ulong)
        }
    }

    #[test]
    fn canonical_domains_match_native_wire_admission() {
        for input in [
            "banka.universal".to_owned(),
            "xn--bcher-kva.universal".to_owned(),
            "banka.xn--bcher-kva".to_owned(),
            "bank_a.universal".to_owned(),
            "_banka.universal".to_owned(),
            "banka_.universal".to_owned(),
            format!("{}.universal", "a".repeat(63)),
            format!("{}.{}", "a".repeat(63), "b".repeat(63)),
        ] {
            assert_eq!(validate(&input), 0, "{input}");
            let domain = DomainId::parse_fully_qualified(&input).unwrap();
            let frame = norito::to_bytes(&domain).unwrap();
            let decoded: DomainId = norito::decode_from_bytes(&frame).unwrap();
            assert_eq!(decoded.to_string(), input);
        }
    }

    #[test]
    fn invalid_and_noncanonical_domains_are_rejected_without_normalizing() {
        for input in [
            "",
            "banka",
            ".universal",
            "banka.",
            "a.b.c",
            "BANKA.universal",
            "banka.UNIVERSAL",
            "bad!.universal",
            "-banka.universal",
            "banka-.universal",
            "ab--cd.universal",
            "xn--.universal",
            "xn--a.universal",
            "xn--abc.universal",
            "bücher.universal",
            " bank.universal",
            "bank.universal ",
            "bank\0.universal",
        ] {
            assert_eq!(validate(input), 1, "{input:?}");
        }
        assert_eq!(validate(&format!("{}.universal", "a".repeat(64))), 1);
        assert_eq!(validate(&format!("banka.{}", "b".repeat(64))), 1);
    }

    #[test]
    fn ffi_rejects_null_utf8_and_excess_length_before_dereference() {
        // SAFETY: null is explicitly accepted for rejection; the two valid
        // buffers below are readable for their declared lengths. Oversized
        // lengths must be rejected before reading any byte from the pointer.
        unsafe {
            assert_eq!(
                connect_norito_domain_id_validate_v1(std::ptr::null(), 0),
                -1
            );
            let invalid_utf8 = [0xff_u8];
            assert_eq!(
                connect_norito_domain_id_validate_v1(invalid_utf8.as_ptr().cast(), 1),
                -2
            );
            let one_byte = b"a";
            assert_eq!(
                connect_norito_domain_id_validate_v1(one_byte.as_ptr().cast(), 0),
                1
            );
            assert_eq!(
                connect_norito_domain_id_validate_v1(one_byte.as_ptr().cast(), 128),
                1
            );
            assert_eq!(
                connect_norito_domain_id_validate_v1(one_byte.as_ptr().cast(), c_ulong::MAX),
                1
            );
        }
    }
}

// ---------------- Account address helpers ----------------
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_account_address_parse(
    input_ptr: *const c_char,
    input_len: c_ulong,
    expected_prefix: u16,
    expected_prefix_present: c_uchar,
    out_canonical_ptr: *mut *mut c_uchar,
    out_canonical_len: *mut c_ulong,
    out_network_prefix: *mut u16,
    out_error_json_ptr: *mut *mut c_uchar,
    out_error_json_len: *mut c_ulong,
) -> c_int {
    if input_ptr.is_null()
        || out_canonical_ptr.is_null()
        || out_canonical_len.is_null()
        || out_network_prefix.is_null()
    {
        return ERR_NULL_PTR;
    }
    write_optional_error(out_error_json_ptr, out_error_json_len);
    let input = match unsafe { read_string_bridge(input_ptr, input_len) } {
        Ok(value) => value,
        Err(err) => return err.code(),
    };
    let expect_prefix = if expected_prefix_present != 0 {
        Some(expected_prefix)
    } else {
        None
    };
    let address = match AccountAddress::parse_encoded(&input, expect_prefix) {
        Ok(value) => value,
        Err(err) => {
            return write_account_address_error(err, out_error_json_ptr, out_error_json_len);
        }
    };
    let canonical_hex = match address.canonical_hex() {
        Ok(value) => value,
        Err(err) => {
            return write_account_address_error(err, out_error_json_ptr, out_error_json_len);
        }
    };
    let hex_body = canonical_hex
        .strip_prefix("0x")
        .unwrap_or(canonical_hex.as_str());
    let canonical = match hex::decode(hex_body) {
        Ok(bytes) => bytes,
        Err(_) => {
            return write_account_address_error(
                AccountAddressError::InvalidHexAddress,
                out_error_json_ptr,
                out_error_json_len,
            );
        }
    };
    unsafe {
        if let Err(code) = write_bytes(out_canonical_ptr, out_canonical_len, &canonical) {
            return code;
        }
    }
    let prefix =
        expect_prefix.unwrap_or_else(iroha_data_model::account::address::chain_discriminant);
    unsafe {
        *out_network_prefix = prefix;
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_account_address_render(
    canonical_ptr: *const c_uchar,
    canonical_len: c_ulong,
    network_prefix: u16,
    out_hex_ptr: *mut *mut c_uchar,
    out_hex_len: *mut c_ulong,
    out_i105_ptr: *mut *mut c_uchar,
    out_i105_len: *mut c_ulong,
    out_error_json_ptr: *mut *mut c_uchar,
    out_error_json_len: *mut c_ulong,
) -> c_int {
    if canonical_ptr.is_null()
        || out_hex_ptr.is_null()
        || out_hex_len.is_null()
        || out_i105_ptr.is_null()
        || out_i105_len.is_null()
    {
        return ERR_NULL_PTR;
    }
    write_optional_error(out_error_json_ptr, out_error_json_len);
    let canonical = unsafe { slice::from_raw_parts(canonical_ptr, canonical_len as usize) };
    let address = match AccountAddress::from_canonical_bytes(canonical) {
        Ok(value) => value,
        Err(err) => {
            return write_account_address_error(err, out_error_json_ptr, out_error_json_len);
        }
    };
    let canonical_hex = match address.canonical_hex() {
        Ok(value) => value,
        Err(err) => {
            return write_account_address_error(err, out_error_json_ptr, out_error_json_len);
        }
    };
    let i105 = match address.to_i105_for_discriminant(network_prefix) {
        Ok(value) => value,
        Err(err) => {
            return write_account_address_error(err, out_error_json_ptr, out_error_json_len);
        }
    };
    unsafe {
        if let Err(code) = write_bytes(out_hex_ptr, out_hex_len, canonical_hex.as_bytes()) {
            return code;
        }
        if let Err(code) = write_bytes(out_i105_ptr, out_i105_len, i105.as_bytes()) {
            return code;
        }
    }
    0
}
unsafe fn read_distid_or_default(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
) -> BridgeResult<String> {
    if distid_len == 0 {
        return Ok(Sm2PublicKey::default_distid());
    }
    if distid_ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    let len = distid_len as usize;
    let slice = unsafe { slice::from_raw_parts(distid_ptr as *const u8, len) };
    let distid = std::str::from_utf8(slice).map_err(|_| BridgeError::Utf8)?;
    Ok(distid.to_owned())
}
struct AssetTxInputs {
    network_id: NetworkId,
    authority: AccountId,
    asset_definition: AssetDefinitionId,
    asset_scope: AssetBalanceScope,
    destination: AccountId,
    quantity: Quantity,
    ttl: Option<NonZeroU64>,
    private_key: PrivateKey,
}
struct AssetInputPointers {
    network_id_ptr: *const c_char,
    network_id_len: c_ulong,
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    asset_definition_ptr: *const c_char,
    asset_definition_len: c_ulong,
    quantity_ptr: *const c_char,
    quantity_len: c_ulong,
    destination_ptr: *const c_char,
    destination_len: c_ulong,
    ttl_ms: u64,
    ttl_present: c_uchar,
    private_key_ptr: *const c_uchar,
    private_key_len: c_ulong,
}
unsafe fn gather_asset_tx_inputs_with_parser<F>(
    ptrs: AssetInputPointers,
    parse_key: F,
) -> BridgeResult<AssetTxInputs>
where
    F: Fn(&[u8]) -> BridgeResult<PrivateKey>,
{
    let AssetInputPointers {
        network_id_ptr,
        network_id_len,
        authority_ptr,
        authority_len,
        asset_definition_ptr,
        asset_definition_len,
        quantity_ptr,
        quantity_len,
        destination_ptr,
        destination_len,
        ttl_ms,
        ttl_present,
        private_key_ptr,
        private_key_len,
    } = ptrs;
    let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
    let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
    let asset_definition_str =
        unsafe { read_string_bridge(asset_definition_ptr, asset_definition_len) }?;
    let quantity_str = unsafe { read_string_bridge(quantity_ptr, quantity_len) }?;
    let destination_str = unsafe { read_string_bridge(destination_ptr, destination_len) }?;
    if private_key_ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
    let (asset_definition, asset_scope) =
        parse_asset_definition_with_balance_scope(asset_definition_str)?;
    Ok(AssetTxInputs {
        network_id,
        authority: parse_account_id(authority_str)?,
        asset_definition,
        asset_scope,
        destination: parse_destination(destination_str)?,
        quantity: parse_public_quantity(quantity_str)?,
        ttl: parse_ttl(ttl_ms, ttl_present != 0)?,
        private_key: parse_key(key_slice)?,
    })
}
unsafe fn read_fixed_array<const N: usize>(
    ptr: *const c_uchar,
    len: c_ulong,
    err: BridgeError,
) -> BridgeResult<[u8; N]> {
    if ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    if len as usize != N {
        return Err(err);
    }
    let slice = unsafe { slice::from_raw_parts(ptr, N) };
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}
unsafe fn read_vec_bytes(ptr: *const c_uchar, len: c_ulong) -> BridgeResult<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(BridgeError::NullPtr);
    }
    let slice = unsafe { slice::from_raw_parts(ptr, len as usize) };
    Ok(slice.to_vec())
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_validate_confidential_memo_envelope_v1(
    envelope_ptr: *const c_uchar,
    envelope_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if envelope_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
        return -1;
    }
    unsafe {
        *out_ptr = ptr::null_mut();
        *out_len = 0;
    }
    if envelope_len as usize > CONFIDENTIAL_MEMO_MAX_WIRE_BYTES_V1 {
        return -2;
    }
    // Safety: caller guarantees the input buffer is valid for the declared length.
    let input = unsafe { slice::from_raw_parts(envelope_ptr, envelope_len as usize) };
    let envelope = match ConfidentialMemoEnvelopeV1::decode_wire(input) {
        Ok(envelope) => envelope,
        Err(_) => return -3,
    };
    let encoded = match envelope.encode_wire() {
        Ok(encoded) => encoded,
        Err(_) => return -3,
    };
    unsafe { write_bytes(out_ptr, out_len, &encoded) }.map_or_else(|err| err, |_| 0)
}

fn confidential_memo_suite_v1(tag: c_uchar) -> Option<ConfidentialMemoKemSuiteV1> {
    match tag {
        0 => Some(ConfidentialMemoKemSuiteV1::MlKem768),
        1 => Some(ConfidentialMemoKemSuiteV1::MlKem1024),
        _ => None,
    }
}

fn confidential_memo_data_suite_v1(
    suite: ConfidentialMemoKemSuiteV1,
) -> iroha_data_model::confidential::ConfidentialMemoSuiteV1 {
    match suite {
        ConfidentialMemoKemSuiteV1::MlKem768 => {
            iroha_data_model::confidential::ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305
        }
        ConfidentialMemoKemSuiteV1::MlKem1024 => {
            iroha_data_model::confidential::ConfidentialMemoSuiteV1::MlKem1024XChaCha20Poly1305
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_generate_confidential_memo_keypair_v1(
    suite_tag: c_uchar,
    public_key_out: *mut *mut c_uchar,
    public_key_len_out: *mut c_ulong,
    secret_key_out: *mut *mut c_uchar,
    secret_key_len_out: *mut c_ulong,
) -> c_int {
    if public_key_out.is_null()
        || public_key_len_out.is_null()
        || secret_key_out.is_null()
        || secret_key_len_out.is_null()
    {
        return -1;
    }
    unsafe {
        *public_key_out = ptr::null_mut();
        *public_key_len_out = 0;
        *secret_key_out = ptr::null_mut();
        *secret_key_len_out = 0;
    }
    let Some(suite) = confidential_memo_suite_v1(suite_tag) else {
        return -3;
    };
    let keypair = match generate_confidential_memo_keypair_v1(suite) {
        Ok(keypair) => keypair,
        Err(_) => return -3,
    };
    if let Err(error) =
        unsafe { write_bytes(public_key_out, public_key_len_out, keypair.public_key()) }
    {
        return error;
    }
    if let Err(error) =
        unsafe { write_bytes(secret_key_out, secret_key_len_out, keypair.secret_key()) }
    {
        unsafe {
            free((*public_key_out).cast());
            *public_key_out = ptr::null_mut();
            *public_key_len_out = 0;
        }
        return error;
    }
    0
}

/// Zeroize and release one confidential-memo secret output.
///
/// # Safety
///
/// `secret_key` must be null or the exact live secret-key/plaintext pointer
/// returned by a confidential-memo entrypoint, and `secret_key_len` must be the
/// unchanged returned length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_confidential_memo_secret_free_v1(
    secret_key: *mut c_uchar,
    secret_key_len: c_ulong,
) {
    if secret_key.is_null() {
        return;
    }
    let secret = unsafe { slice::from_raw_parts_mut(secret_key, secret_key_len as usize) };
    secret.zeroize();
    unsafe { free(secret_key.cast()) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_seal_confidential_memo_v1(
    suite_tag: c_uchar,
    recipient_public_keys: *const c_uchar,
    recipient_public_keys_len: c_ulong,
    recipient_count: c_uchar,
    plaintext: *const c_uchar,
    plaintext_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if recipient_public_keys.is_null()
        || (plaintext.is_null() && plaintext_len != 0)
        || out_ptr.is_null()
        || out_len.is_null()
    {
        return -1;
    }
    let Some(suite) = confidential_memo_suite_v1(suite_tag) else {
        return -3;
    };
    if plaintext_len as usize
        > CONFIDENTIAL_MEMO_MAX_CIPHERTEXT_BYTES_V1 - CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1
    {
        return -2;
    }
    unsafe {
        *out_ptr = ptr::null_mut();
        *out_len = 0;
    }
    let count = usize::from(recipient_count);
    if !(1..=8).contains(&count) {
        return -3;
    }
    let key_bytes = suite.mlkem_suite().public_key_len();
    if recipient_public_keys_len as usize != count.saturating_mul(key_bytes) {
        return -3;
    }
    let packed =
        unsafe { slice::from_raw_parts(recipient_public_keys, recipient_public_keys_len as usize) };
    let recipients = packed
        .chunks_exact(key_bytes)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let plaintext = if plaintext_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(plaintext, plaintext_len as usize) }
    };
    let envelope = match ConfidentialMemoEnvelopeV1::seal(
        confidential_memo_data_suite_v1(suite),
        &recipients,
        plaintext,
    ) {
        Ok(envelope) => envelope,
        Err(_) => return -3,
    };
    let encoded = match envelope.encode_wire() {
        Ok(encoded) => encoded,
        Err(_) => return -3,
    };
    unsafe { write_bytes(out_ptr, out_len, &encoded) }.map_or_else(|error| error, |_| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_open_confidential_memo_v1(
    suite_tag: c_uchar,
    recipient_secret_key: *const c_uchar,
    recipient_secret_key_len: c_ulong,
    envelope: *const c_uchar,
    envelope_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if recipient_secret_key.is_null()
        || envelope.is_null()
        || out_ptr.is_null()
        || out_len.is_null()
    {
        return -1;
    }
    if envelope_len as usize > CONFIDENTIAL_MEMO_MAX_WIRE_BYTES_V1 {
        return -2;
    }
    unsafe {
        *out_ptr = ptr::null_mut();
        *out_len = 0;
    }
    let Some(suite) = confidential_memo_suite_v1(suite_tag) else {
        return -3;
    };
    if recipient_secret_key_len as usize != suite.mlkem_suite().secret_key_len() {
        return -3;
    }
    let secret_key =
        unsafe { slice::from_raw_parts(recipient_secret_key, recipient_secret_key_len as usize) };
    let wire = unsafe { slice::from_raw_parts(envelope, envelope_len as usize) };
    let envelope = match ConfidentialMemoEnvelopeV1::decode_wire(wire) {
        Ok(envelope) => envelope,
        Err(_) => return -3,
    };
    let plaintext = match envelope.open(confidential_memo_data_suite_v1(suite), secret_key) {
        Ok(plaintext) => Zeroizing::new(plaintext),
        Err(_) => return -3,
    };
    unsafe { write_bytes(out_ptr, out_len, &plaintext) }.map_or_else(|error| error, |_| 0)
}
fn encode_connect_frame(frame: &proto::ConnectFrameV1) -> Result<Vec<u8>, norito::core::Error> {
    proto::encode_connect_frame_bare(frame)
}
fn decode_connect_frame(bytes: &[u8]) -> Result<proto::ConnectFrameV1, norito::core::Error> {
    proto::decode_connect_frame_bare(bytes)
}
fn decode_envelope(bytes: &[u8]) -> Result<proto::EnvelopeV1, norito::core::Error> {
    proto::decode_connect_envelope_framed(bytes)
}
fn encode_envelope_framed(env: &proto::EnvelopeV1) -> Result<Vec<u8>, norito::core::Error> {
    proto::encode_connect_envelope_framed(env)
}
unsafe fn write_output_result<E>(
    encoded: Result<Vec<u8>, E>,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
    encoding_error: c_int,
    allocation_error: c_int,
) -> c_int {
    let bytes = match encoded {
        Ok(bytes) => bytes,
        Err(_) => return encoding_error,
    };
    let len = bytes.len();
    let mem = unsafe { malloc(len) };
    if mem.is_null() {
        return allocation_error;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), mem.cast::<u8>(), len);
        *out_ptr = mem.cast::<u8>();
        *out_len = len as c_ulong;
    }
    0
}
unsafe fn write_encoded_result(
    encoded: Result<Vec<u8>, norito::core::Error>,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
    allocation_error: c_int,
) -> c_int {
    unsafe {
        write_output_result(
            encoded,
            out_ptr,
            out_len,
            ERR_CONNECT_ENCODE,
            allocation_error,
        )
    }
}
fn decode_signed_transaction(bytes: &[u8]) -> Result<SignedTransaction, norito::core::Error> {
    let transaction = SignedTransaction::decode_all_versioned(bytes)
        .map_err(|err| norito::core::Error::Message(err.to_string()))?;
    let canonical = transaction.encode_wire_v1()?;
    if canonical != bytes {
        return Err(norito::core::Error::Message(
            "signed transaction wire is not canonical V1".to_owned(),
        ));
    }
    Ok(transaction)
}
fn detached_transaction_hash_hex(bytes: &[u8; 32]) -> JsonValue {
    JsonValue::from(hex::encode(bytes))
}
fn detached_asset_transfer_json(instruction: &InstructionBox) -> BridgeResult<JsonValue> {
    use iroha_data_model::prelude::TransferBox;
    let transfer_box = instruction
        .as_any()
        .downcast_ref::<TransferBox>()
        .ok_or(BridgeError::DetachedTransactionScaffold)?;
    let TransferBox::Asset(transfer) = transfer_box else {
        return Err(BridgeError::DetachedTransactionScaffold);
    };
    let scope = match transfer.source.scope() {
        AssetBalanceScope::Global => JsonValue::Object(JsonMap::from_iter([(
            "kind".into(),
            JsonValue::from("global"),
        )])),
        AssetBalanceScope::Dataspace(dataspace_id) => JsonValue::Object(JsonMap::from_iter([
            ("kind".into(), JsonValue::from("dataspace")),
            (
                "dataspace_id".into(),
                JsonValue::from(dataspace_id.as_u64()),
            ),
        ])),
    };
    Ok(JsonValue::Object(JsonMap::from_iter([
        ("kind".into(), JsonValue::from("asset_transfer")),
        (
            "asset_definition_id".into(),
            JsonValue::from(transfer.source.definition().to_string()),
        ),
        ("asset_scope".into(), scope),
        (
            "source_asset_id".into(),
            JsonValue::from(transfer.source.canonical_literal()),
        ),
        (
            "source_account_id".into(),
            JsonValue::from(transfer.source.account().to_string()),
        ),
        (
            "destination_account_id".into(),
            JsonValue::from(transfer.destination.to_string()),
        ),
        (
            "amount".into(),
            JsonValue::from(transfer.object.to_string()),
        ),
    ])))
}

fn detached_transaction_executable_json(tx: &SignedTransaction) -> BridgeResult<JsonValue> {
    match tx.instructions() {
        Executable::ContractCall(invocation) => {
            let arguments = invocation
                .arguments
                .as_ref()
                .map_or(JsonValue::Null, |record| {
                    JsonValue::from(b64_encode(record.as_bytes()))
                });
            Ok(JsonValue::Object(JsonMap::from_iter([
                ("kind".into(), JsonValue::from("contract_call")),
                (
                    "contract_address".into(),
                    JsonValue::from(invocation.contract_address.to_string()),
                ),
                (
                    "expected_code_hash".into(),
                    JsonValue::from(invocation.expected_code_hash.to_string()),
                ),
                (
                    "entrypoint".into(),
                    JsonValue::from(invocation.entrypoint.clone()),
                ),
                ("arguments_b64".into(), arguments),
            ])))
        }
        Executable::Instructions(instructions) if instructions.len() == 1 => {
            let instruction = instructions
                .iter()
                .next()
                .ok_or(BridgeError::DetachedTransactionScaffold)?;
            detached_asset_transfer_json(instruction)
        }
        Executable::Batch(entries) if entries.len() == 2 => {
            let transfers = entries
                .iter()
                .map(|entry| {
                    let iroha_data_model::transaction::ExecutableBatchItem::Instruction(
                        instruction,
                    ) = entry
                    else {
                        return Err(BridgeError::DetachedTransactionScaffold);
                    };
                    detached_asset_transfer_json(instruction)
                })
                .collect::<BridgeResult<Vec<_>>>()?;
            Ok(JsonValue::Object(JsonMap::from_iter([
                ("kind".into(), JsonValue::from("asset_transfer_batch")),
                ("transfers".into(), JsonValue::Array(transfers)),
            ])))
        }
        _ => Err(BridgeError::DetachedTransactionScaffold),
    }
}
fn inspect_detached_transaction_scaffold(
    bytes: &[u8],
) -> BridgeResult<(SignedTransaction, Vec<u8>)> {
    if bytes.is_empty() || bytes.len() > DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES {
        return Err(BridgeError::DetachedTransactionScaffold);
    }
    let tx =
        decode_signed_transaction(bytes).map_err(|_| BridgeError::DetachedTransactionScaffold)?;
    if tx.encode_versioned() != bytes {
        return Err(BridgeError::DetachedTransactionScaffold);
    }
    let signatory = tx
        .authority()
        .try_signatory()
        .ok_or(BridgeError::DetachedTransactionScaffold)?;
    if signatory.try_algorithm().ok() != Some(Algorithm::Ed25519)
        || tx.signature_count() != 1
        || tx.multisig_signatures().is_some()
        || tx.attachments().is_some()
        || tx.nonce().is_some()
        || iroha_crypto::ed25519_parse_signature(tx.signature().0.payload()).is_err()
    {
        return Err(BridgeError::DetachedTransactionScaffold);
    }
    let executable = detached_transaction_executable_json(&tx)?;
    let metadata = norito::json::to_value(tx.metadata())
        .map_err(|_| BridgeError::DetachedTransactionScaffold)?;
    if !matches!(metadata, JsonValue::Object(_)) {
        return Err(BridgeError::DetachedTransactionScaffold);
    }
    let payload_signing_hash = iroha_crypto::HashOf::new(tx.payload());
    let entrypoint_hash = tx.hash_as_entrypoint();
    let creation_time_ms = u64::try_from(tx.creation_time().as_millis())
        .map_err(|_| BridgeError::DetachedTransactionScaffold)?;
    let time_to_live_ms = tx.time_to_live().map_or(Ok(JsonValue::Null), |ttl| {
        u64::try_from(ttl.as_millis())
            .map(JsonValue::from)
            .map_err(|_| BridgeError::DetachedTransactionScaffold)
    })?;
    let network_id = tx
        .network_id()
        .ok_or(BridgeError::DetachedTransactionScaffold)?;
    let network_id =
        norito::json::to_value(network_id).map_err(|_| BridgeError::DetachedTransactionScaffold)?;
    let json = JsonValue::Object(JsonMap::from_iter([
        (
            "schema".into(),
            JsonValue::from("iroha.detached_transaction_scaffold.v1"),
        ),
        (
            "payload_signing_hash_hex".into(),
            detached_transaction_hash_hex(payload_signing_hash.as_ref()),
        ),
        (
            "authority".into(),
            JsonValue::from(tx.authority().to_string()),
        ),
        ("network_id".into(), network_id),
        ("creation_time_ms".into(), JsonValue::from(creation_time_ms)),
        ("time_to_live_ms".into(), time_to_live_ms),
        ("metadata".into(), metadata),
        (
            "entrypoint_hash_hex".into(),
            detached_transaction_hash_hex(entrypoint_hash.as_ref()),
        ),
        ("executable".into(), executable),
    ]));
    let json = norito::json::to_vec(&json).map_err(|_| BridgeError::DetachedTransactionScaffold)?;
    if json.len() > DETACHED_TRANSACTION_JSON_MAX_BYTES {
        return Err(BridgeError::DetachedTransactionScaffold);
    }
    Ok((tx, json))
}
unsafe fn write_detached_transaction_pair(
    first_ptr: *mut *mut c_uchar,
    first_len: *mut c_ulong,
    first: &[u8],
    second_ptr: *mut *mut c_uchar,
    second_len: *mut c_ulong,
    second: &[u8],
) -> BridgeResult<()> {
    clear_bridge_output_or_null(first_ptr, first_len)?;
    clear_bridge_output_or_null(second_ptr, second_len)?;
    if first_ptr == second_ptr || first_len == second_len {
        return Err(BridgeError::NullPtr);
    }
    unsafe { write_bytes_bridge(first_ptr, first_len, first) }?;
    if let Err(error) = unsafe { write_bytes_bridge(second_ptr, second_len, second) } {
        let allocated = unsafe { *first_ptr };
        connect_norito_free(allocated);
        clear_bridge_output(first_ptr, first_len);
        return Err(error);
    }
    Ok(())
}
/// Inspect and type-bind one exact canonical versioned detached transaction scaffold.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_detached_transaction_scaffold_inspect_v1(
    tx_ptr: *const c_uchar,
    tx_len: c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let result = (|| {
        clear_bridge_output_or_null(out_json_ptr, out_json_len)?;
        let tx_len =
            usize::try_from(tx_len).map_err(|_| BridgeError::DetachedTransactionScaffold)?;
        if tx_ptr.is_null() || tx_len == 0 || tx_len > DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES {
            return Err(BridgeError::DetachedTransactionScaffold);
        }
        let bytes = unsafe { slice::from_raw_parts(tx_ptr, tx_len) };
        let (_, json) = inspect_detached_transaction_scaffold(bytes)?;
        unsafe { write_bytes_bridge(out_json_ptr, out_json_len, &json) }
    })();
    bridge_result_to_code(result)
}
/// Replace a detached scaffold's sole signature with one verified Ed25519 signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
    tx_ptr: *const c_uchar,
    tx_len: c_ulong,
    public_key_ptr: *const c_uchar,
    public_key_len: c_ulong,
    signature_ptr: *const c_uchar,
    signature_len: c_ulong,
    out_signed_tx_ptr: *mut *mut c_uchar,
    out_signed_tx_len: *mut c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_signed_tx_ptr, out_signed_tx_len);
    clear_bridge_output(out_json_ptr, out_json_len);
    let result = (|| {
        if out_signed_tx_ptr.is_null()
            || out_signed_tx_len.is_null()
            || out_json_ptr.is_null()
            || out_json_len.is_null()
        {
            return Err(BridgeError::NullPtr);
        }
        let tx_len =
            usize::try_from(tx_len).map_err(|_| BridgeError::DetachedTransactionScaffold)?;
        if tx_ptr.is_null() || tx_len == 0 || tx_len > DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES {
            return Err(BridgeError::DetachedTransactionScaffold);
        }
        if public_key_ptr.is_null() || public_key_len != 32 {
            return Err(BridgeError::DetachedTransactionSignature);
        }
        if signature_ptr.is_null() || signature_len != 64 {
            return Err(BridgeError::DetachedTransactionSignature);
        }
        let scaffold = unsafe { slice::from_raw_parts(tx_ptr, tx_len) };
        let (tx, _) = inspect_detached_transaction_scaffold(scaffold)?;
        let public_key_bytes = unsafe { slice::from_raw_parts(public_key_ptr, 32) };
        let public_key = PublicKey::from_bytes(Algorithm::Ed25519, public_key_bytes)
            .map_err(|_| BridgeError::DetachedTransactionSignature)?;
        if tx.authority().try_signatory() != Some(&public_key) {
            return Err(BridgeError::DetachedTransactionSignature);
        }
        let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, 64) };
        let signature = iroha_crypto::ed25519_parse_signature(signature_bytes)
            .map_err(|_| BridgeError::DetachedTransactionSignature)?;
        let payload = norito::codec::encode_adaptive(tx.payload());
        let signed = TransactionBuilder::decode_payload(&payload)
            .map_err(|_| BridgeError::DetachedTransactionScaffold)?
            .build_with_signature(signature);
        signed
            .verify_signature()
            .map_err(|_| BridgeError::DetachedTransactionSignature)?;
        let signed_bytes = signed.encode_versioned();
        let payload_signing_hash = iroha_crypto::HashOf::new(signed.payload());
        let transaction_hash = signed.hash();
        let entrypoint_hash = signed.hash_as_entrypoint();
        let json = JsonValue::Object(JsonMap::from_iter([
            (
                "schema".into(),
                JsonValue::from("iroha.detached_transaction_finalization.v1"),
            ),
            (
                "payload_signing_hash_hex".into(),
                detached_transaction_hash_hex(payload_signing_hash.as_ref()),
            ),
            (
                "transaction_hash_hex".into(),
                detached_transaction_hash_hex(transaction_hash.as_ref()),
            ),
            (
                "entrypoint_hash_hex".into(),
                detached_transaction_hash_hex(entrypoint_hash.as_ref()),
            ),
        ]));
        let json =
            norito::json::to_vec(&json).map_err(|_| BridgeError::DetachedTransactionScaffold)?;
        unsafe {
            write_detached_transaction_pair(
                out_signed_tx_ptr,
                out_signed_tx_len,
                &signed_bytes,
                out_json_ptr,
                out_json_len,
                &json,
            )
        }
    })();
    bridge_result_to_code(result)
}
fn alias_instruction_json(instruction: &InstructionBox, wire_id: &str) -> BridgeResult<Vec<u8>> {
    use iroha_data_model::isi::alias_setup::{
        CompareAndSetPrimaryAccountAlias, ConfigureAliasAutoRenew, EnsureAlias, RebindAccountAlias,
        RenewAliasLease,
    };
    let value = match wire_id {
        EnsureAlias::WIRE_ID => norito::json::to_value(
            instruction
                .as_any()
                .downcast_ref::<EnsureAlias>()
                .ok_or(BridgeError::AliasInstruction)?,
        ),
        RenewAliasLease::WIRE_ID => norito::json::to_value(
            instruction
                .as_any()
                .downcast_ref::<RenewAliasLease>()
                .ok_or(BridgeError::AliasInstruction)?,
        ),
        ConfigureAliasAutoRenew::WIRE_ID => norito::json::to_value(
            instruction
                .as_any()
                .downcast_ref::<ConfigureAliasAutoRenew>()
                .ok_or(BridgeError::AliasInstruction)?,
        ),
        // These lifecycle operations are registry-validated and canonically
        // re-encoded even though the current Swift setup planner does not need
        // their typed payloads.
        RebindAccountAlias::WIRE_ID => {
            instruction
                .as_any()
                .downcast_ref::<RebindAccountAlias>()
                .ok_or(BridgeError::AliasInstruction)?;
            Ok(JsonValue::Null)
        }
        CompareAndSetPrimaryAccountAlias::WIRE_ID => {
            instruction
                .as_any()
                .downcast_ref::<CompareAndSetPrimaryAccountAlias>()
                .ok_or(BridgeError::AliasInstruction)?;
            Ok(JsonValue::Null)
        }
        _ => return Err(BridgeError::AliasInstruction),
    }
    .map_err(|_| BridgeError::AliasInstruction)?;
    let envelope = JsonValue::Object(JsonMap::from_iter([
        (
            "schema".into(),
            JsonValue::from("iroha.alias_instruction_round_trip.v1"),
        ),
        ("wire_id".into(), JsonValue::from(wire_id)),
        ("instruction".into(), value),
    ]));
    norito::json::to_vec(&envelope).map_err(|_| BridgeError::AliasInstruction)
}
/// Registry-decode and canonically re-encode one alias instruction frame.
///
/// The frame is accepted only under its exact stable alias wire ID. The first
/// output is the complete canonical Norito frame; the second is a bounded JSON
/// envelope carrying the decoded typed payload for Swift-side request binding.
/// Both outputs are released with [`connect_norito_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_alias_instruction_round_trip_v1(
    wire_id_ptr: *const c_uchar,
    wire_id_len: c_ulong,
    framed_payload_ptr: *const c_uchar,
    framed_payload_len: c_ulong,
    out_framed_payload_ptr: *mut *mut c_uchar,
    out_framed_payload_len: *mut c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_framed_payload_ptr, out_framed_payload_len);
    clear_bridge_output(out_json_ptr, out_json_len);
    let result = (|| {
        let wire_id_len =
            usize::try_from(wire_id_len).map_err(|_| BridgeError::AliasInstruction)?;
        let framed_payload_len =
            usize::try_from(framed_payload_len).map_err(|_| BridgeError::AliasInstruction)?;
        if wire_id_ptr.is_null()
            || wire_id_len == 0
            || wire_id_len > 256
            || framed_payload_ptr.is_null()
            || framed_payload_len == 0
            || framed_payload_len > DETACHED_TRANSACTION_SCAFFOLD_MAX_BYTES
        {
            return Err(BridgeError::AliasInstruction);
        }
        let wire_id_bytes = unsafe { slice::from_raw_parts(wire_id_ptr, wire_id_len) };
        let wire_id =
            std::str::from_utf8(wire_id_bytes).map_err(|_| BridgeError::AliasInstruction)?;
        let framed_payload =
            unsafe { slice::from_raw_parts(framed_payload_ptr, framed_payload_len) };
        let instruction = decode_instruction_from_pair(wire_id, framed_payload)
            .map_err(|_| BridgeError::AliasInstruction)?;
        let (canonical_wire_id, canonical_frame) =
            framed_instruction_payload(&instruction).ok_or(BridgeError::AliasInstruction)?;
        if canonical_wire_id != wire_id || canonical_frame.is_empty() {
            return Err(BridgeError::AliasInstruction);
        }
        let json = alias_instruction_json(&instruction, wire_id)?;
        if json.is_empty() || json.len() > DETACHED_TRANSACTION_JSON_MAX_BYTES {
            return Err(BridgeError::AliasInstruction);
        }
        unsafe {
            write_detached_transaction_pair(
                out_framed_payload_ptr,
                out_framed_payload_len,
                &canonical_frame,
                out_json_ptr,
                out_json_len,
                &json,
            )
        }
    })();
    bridge_result_to_code(result)
}
/// Canonicalize strict JSON and return BLAKE3 over the exact canonical bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_canonical_json_blake3_v1(
    json_ptr: *const c_uchar,
    json_len: c_ulong,
    out_canonical_json_ptr: *mut *mut c_uchar,
    out_canonical_json_len: *mut c_ulong,
    out_hash_ptr: *mut c_uchar,
    out_hash_len: c_ulong,
) -> c_int {
    clear_bridge_output(out_canonical_json_ptr, out_canonical_json_len);
    let result = (|| {
        if out_canonical_json_ptr.is_null()
            || out_canonical_json_len.is_null()
            || out_hash_ptr.is_null()
        {
            return Err(BridgeError::NullPtr);
        }
        if out_hash_len != 32 {
            return Err(BridgeError::HashOutBuffer);
        }
        unsafe { ptr::write_bytes(out_hash_ptr, 0, 32) };
        let json_len = usize::try_from(json_len).map_err(|_| BridgeError::CanonicalJson)?;
        if json_len > DETACHED_TRANSACTION_JSON_MAX_BYTES {
            return Err(BridgeError::CanonicalJson);
        }
        let canonical = if json_len == 0 {
            Vec::new()
        } else {
            if json_ptr.is_null() {
                return Err(BridgeError::NullPtr);
            }
            let input = unsafe { slice::from_raw_parts(json_ptr, json_len) };
            let value =
                norito::json::from_slice_value(input).map_err(|_| BridgeError::CanonicalJson)?;
            norito::json::to_vec(&value).map_err(|_| BridgeError::CanonicalJson)?
        };
        let digest = blake3_hash(&canonical);
        unsafe { write_bytes_bridge(out_canonical_json_ptr, out_canonical_json_len, &canonical) }?;
        unsafe { ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), out_hash_ptr, 32) };
        Ok(())
    })();
    bridge_result_to_code(result)
}
fn validation_fee_is_canonical_iroha_hash(value: &[u8; 32]) -> bool {
    value[31] & 1 == 1
}
fn validation_fee_current_policy_proof_request_v1(
    trusted_checkpoint: &[u8],
) -> BridgeResult<Vec<u8>> {
    let checkpoint =
        iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint::decode_canonical(
            trusted_checkpoint,
        )
        .map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    norito::to_bytes(&ValidationFeeCurrentPolicyProofRequestV1 {
        version: VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
        trusted_checkpoint_height: checkpoint.height(),
    })
    .map_err(|_| BridgeError::ValidationFeePolicyProof)
}
fn validation_fee_current_policy_proof_verify_v1(
    proof_archive: &[u8],
    network_id: NetworkId,
    policy_chain_genesis_hash: [u8; 32],
    trusted_checkpoint: &[u8],
) -> BridgeResult<(Vec<u8>, Vec<u8>)> {
    if proof_archive.is_empty()
        || proof_archive.len() > VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES
        || !validation_fee_is_canonical_iroha_hash(network_id.as_bytes())
        || !validation_fee_is_canonical_iroha_hash(&policy_chain_genesis_hash)
    {
        return Err(BridgeError::ValidationFeePolicyProof);
    }
    let checkpoint =
        iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint::decode_canonical(
            trusted_checkpoint,
        )
        .map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    let proof: ValidationFeeCurrentPolicyProofV1 =
        decode_from_bytes(proof_archive).map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    let canonical = norito::to_bytes(&proof).map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    if canonical != proof_archive {
        return Err(BridgeError::ValidationFeePolicyProof);
    }
    let (projection, promoted) = proof
        .verify_with_immutable_binding(network_id, policy_chain_genesis_hash, &checkpoint)
        .map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    let json =
        norito::json::to_vec(&projection).map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    if json.is_empty() || json.len() > DETACHED_TRANSACTION_JSON_MAX_BYTES {
        return Err(BridgeError::ValidationFeePolicyProof);
    }
    let promoted = promoted
        .encode_canonical()
        .map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    Ok((json, promoted))
}
unsafe fn validation_fee_checkpoint_bytes<'a>(
    checkpoint_ptr: *const c_uchar,
    checkpoint_len: c_ulong,
) -> BridgeResult<&'a [u8]> {
    let length =
        usize::try_from(checkpoint_len).map_err(|_| BridgeError::ValidationFeePolicyProof)?;
    if checkpoint_ptr.is_null()
        || length == 0
        || length > iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES
    {
        return Err(BridgeError::ValidationFeePolicyProof);
    }
    // SAFETY: the C caller supplies a readable range; null and size were checked above.
    Ok(unsafe { slice::from_raw_parts(checkpoint_ptr, length) })
}
const RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES: usize = 262_144;
const RETAIL_FEE_ASSESSMENT_MAX_BYTES: usize = 4_096;
const RETAIL_FEE_MARKER_MAX_BYTES: usize = 4_096;
const RETAIL_FEE_MARKER_PREFIX: &str = "iroha:retail_fee:assessment:v1:";
fn retail_fee_intent_hash_v1(input: &[u8]) -> BridgeResult<Vec<u8>> {
    if input.is_empty() || input.len() > RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES {
        return Err(BridgeError::RetailFeeAssessment);
    }
    let request: RetailFeeQuoteRequestV1 =
        norito::json::from_slice(input).map_err(|_| BridgeError::RetailFeeAssessment)?;
    if request.transfers.is_empty()
        || request.transfers.len() > 1_000
        || request
            .transfers
            .iter()
            .any(|leg| leg.amount_minor_units == 0)
    {
        return Err(BridgeError::RetailFeeAssessment);
    }
    request
        .intent_hash()
        .map(|hash| hash.to_vec())
        .map_err(|_| BridgeError::RetailFeeAssessment)
}
// This codec checks canonical shape. Ledger admission authenticates the policy,
// enrollment, counter commitment, exact intent, and freshness at execution.
fn retail_fee_validate_assessment(value: &RetailFeeAssessmentV1) -> BridgeResult<()> {
    let (start, end) = honiara_month_bounds(value.billing_month_start_ms)
        .map_err(|_| BridgeError::RetailFeeAssessment)?;
    if start != value.billing_month_start_ms
        || value.policy_revision == 0
        || value.qualifying_payments > 1_000
        || value
            .payments_used_before
            .checked_add(value.qualifying_payments)
            .is_none()
        || value.expires_at_ms <= start
        || value.expires_at_ms > end
        || !validation_fee_is_canonical_iroha_hash(&value.state_commitment)
        || !validation_fee_is_canonical_iroha_hash(&value.intent_hash)
        || (value.qualifying_payments == 0 && value.fee_minor != 0)
    {
        return Err(BridgeError::RetailFeeAssessment);
    }
    Ok(())
}
fn retail_fee_assessment_marker_v1(input: &[u8]) -> BridgeResult<Vec<u8>> {
    if input.is_empty() || input.len() > RETAIL_FEE_ASSESSMENT_MAX_BYTES {
        return Err(BridgeError::RetailFeeAssessment);
    }
    let value: RetailFeeAssessmentV1 =
        norito::json::from_slice(input).map_err(|_| BridgeError::RetailFeeAssessment)?;
    retail_fee_validate_assessment(&value)?;
    let bytes = norito::encode_canonical(&value).map_err(|_| BridgeError::RetailFeeAssessment)?;
    // Every emitted marker must fit the same bound accepted by the decoder.
    if bytes.is_empty()
        || bytes.len() > (RETAIL_FEE_MARKER_MAX_BYTES - RETAIL_FEE_MARKER_PREFIX.len()) / 2
    {
        return Err(BridgeError::RetailFeeAssessment);
    }
    Ok(format!("{RETAIL_FEE_MARKER_PREFIX}{}", hex::encode(bytes)).into_bytes())
}
fn retail_fee_assessment_decode_v1(input: &[u8]) -> BridgeResult<Vec<u8>> {
    if input.is_empty() || input.len() > RETAIL_FEE_MARKER_MAX_BYTES {
        return Err(BridgeError::RetailFeeAssessment);
    }
    let encoded = std::str::from_utf8(input)
        .ok()
        .and_then(|s| s.strip_prefix(RETAIL_FEE_MARKER_PREFIX))
        .ok_or(BridgeError::RetailFeeAssessment)?;
    if encoded.is_empty()
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::RetailFeeAssessment);
    }
    let bytes = hex::decode(encoded).map_err(|_| BridgeError::RetailFeeAssessment)?;
    let value: RetailFeeAssessmentV1 =
        decode_from_bytes(&bytes).map_err(|_| BridgeError::RetailFeeAssessment)?;
    retail_fee_validate_assessment(&value)?;
    if norito::encode_canonical(&value).map_err(|_| BridgeError::RetailFeeAssessment)? != bytes {
        return Err(BridgeError::RetailFeeAssessment);
    }
    let json = norito::json::to_vec(&value).map_err(|_| BridgeError::RetailFeeAssessment)?;
    if json.is_empty() || json.len() > RETAIL_FEE_ASSESSMENT_MAX_BYTES {
        return Err(BridgeError::RetailFeeAssessment);
    }
    Ok(json)
}
/// Encode one bounded current-policy proof request from a complete canonical checkpoint.
///
/// The caller independently selects and retains the checkpoint; request construction only
/// validates its canonical structure and derives the requested height. Verification consumes
/// the same complete checkpoint and returns its authenticated successor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_validation_fee_current_policy_proof_request_v1(
    trusted_checkpoint_ptr: *const c_uchar,
    trusted_checkpoint_len: c_ulong,
    out_request_ptr: *mut *mut c_uchar,
    out_request_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_request_ptr, out_request_len);
    let result = (|| {
        clear_bridge_output_or_null(out_request_ptr, out_request_len)?;
        let checkpoint = unsafe {
            validation_fee_checkpoint_bytes(trusted_checkpoint_ptr, trusted_checkpoint_len)
        }?;
        let request = validation_fee_current_policy_proof_request_v1(checkpoint)?;
        unsafe { write_bytes_bridge(out_request_ptr, out_request_len, &request) }
    })();
    bridge_result_to_code(result)
}
/// Verify a canonical proof under immutable network/policy pins and a complete checkpoint.
///
/// Success returns canonical projection JSON and the promoted canonical checkpoint together.
/// Persist both atomically before requesting another page. Both outputs are cleared on failure;
/// each successful allocation must be released with `connect_norito_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_validation_fee_current_policy_proof_verify_v1(
    proof_norito_ptr: *const c_uchar,
    proof_norito_len: c_ulong,
    network_id_ptr: *const c_uchar,
    network_id_len: c_ulong,
    policy_chain_genesis_hash_ptr: *const c_uchar,
    policy_chain_genesis_hash_len: c_ulong,
    trusted_checkpoint_ptr: *const c_uchar,
    trusted_checkpoint_len: c_ulong,
    out_projection_json_ptr: *mut *mut c_uchar,
    out_projection_json_len: *mut c_ulong,
    out_promoted_checkpoint_ptr: *mut *mut c_uchar,
    out_promoted_checkpoint_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_projection_json_ptr, out_projection_json_len);
    clear_bridge_output(out_promoted_checkpoint_ptr, out_promoted_checkpoint_len);
    let result = (|| {
        clear_bridge_output_or_null(out_projection_json_ptr, out_projection_json_len)?;
        clear_bridge_output_or_null(out_promoted_checkpoint_ptr, out_promoted_checkpoint_len)?;
        if out_projection_json_ptr == out_promoted_checkpoint_ptr
            || out_projection_json_len == out_promoted_checkpoint_len
        {
            return Err(BridgeError::NullPtr);
        }
        let proof_len =
            usize::try_from(proof_norito_len).map_err(|_| BridgeError::ValidationFeePolicyProof)?;
        if proof_norito_ptr.is_null()
            || proof_len == 0
            || proof_len > VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES
        {
            return Err(BridgeError::ValidationFeePolicyProof);
        }
        let proof = unsafe { slice::from_raw_parts(proof_norito_ptr, proof_len) };
        let network_id = unsafe {
            read_fixed_array::<32>(
                network_id_ptr,
                network_id_len,
                BridgeError::ValidationFeePolicyProof,
            )
        }?;
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::prehashed(network_id)),
        );
        let policy_chain_genesis_hash = unsafe {
            read_fixed_array::<32>(
                policy_chain_genesis_hash_ptr,
                policy_chain_genesis_hash_len,
                BridgeError::ValidationFeePolicyProof,
            )
        }?;
        let checkpoint = unsafe {
            validation_fee_checkpoint_bytes(trusted_checkpoint_ptr, trusted_checkpoint_len)
        }?;
        let (projection, promoted) = validation_fee_current_policy_proof_verify_v1(
            proof,
            network_id,
            policy_chain_genesis_hash,
            checkpoint,
        )?;
        unsafe {
            write_detached_transaction_pair(
                out_projection_json_ptr,
                out_projection_json_len,
                &projection,
                out_promoted_checkpoint_ptr,
                out_promoted_checkpoint_len,
                &promoted,
            )
        }
    })();
    bridge_result_to_code(result)
}
unsafe fn retail_fee_bridge_call(
    input_ptr: *const c_uchar,
    input_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
    maximum_input_bytes: usize,
    operation: fn(&[u8]) -> BridgeResult<Vec<u8>>,
) -> c_int {
    clear_bridge_output(out_ptr, out_len);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        clear_bridge_output_or_null(out_ptr, out_len)?;
        let length = usize::try_from(input_len).map_err(|_| BridgeError::RetailFeeAssessment)?;
        if input_ptr.is_null() || length == 0 || length > maximum_input_bytes {
            return Err(BridgeError::RetailFeeAssessment);
        }
        let input = unsafe { slice::from_raw_parts(input_ptr, length) };
        let bytes = operation(input)?;
        unsafe { write_bytes_bridge(out_ptr, out_len, &bytes) }
    }));
    result.map_or_else(
        |_| BridgeError::RetailFeeAssessment.code(),
        bridge_result_to_code,
    )
}
/// Hash the exact ordered payment request using native canonical Norito.
/// Output is cleared on failure and must be released with `connect_norito_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_retail_fee_intent_hash_v1(
    input_ptr: *const c_uchar,
    input_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        retail_fee_bridge_call(
            input_ptr,
            input_len,
            out_ptr,
            out_len,
            RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES,
            retail_fee_intent_hash_v1,
        )
    }
}
/// Encode a canonical TRACE marker for a reviewed fee assessment.
/// Output is cleared on failure and must be released with `connect_norito_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_retail_fee_assessment_marker_v1(
    input_ptr: *const c_uchar,
    input_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        retail_fee_bridge_call(
            input_ptr,
            input_len,
            out_ptr,
            out_len,
            RETAIL_FEE_ASSESSMENT_MAX_BYTES,
            retail_fee_assessment_marker_v1,
        )
    }
}
/// Decode an exact canonical fee marker into typed assessment JSON.
/// Output is cleared on failure and must be released with `connect_norito_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_retail_fee_assessment_decode_v1(
    input_ptr: *const c_uchar,
    input_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        retail_fee_bridge_call(
            input_ptr,
            input_len,
            out_ptr,
            out_len,
            RETAIL_FEE_MARKER_MAX_BYTES,
            retail_fee_assessment_decode_v1,
        )
    }
}
fn signed_transaction_bridge_debug_json(tx: &SignedTransaction) -> JsonValue {
    use iroha_data_model::prelude::TransferBox;
    let mut transfer_asset_scopes = Vec::new();
    for instruction in tx.instructions().explicit_instructions() {
        let Some(transfer_box) = instruction.as_any().downcast_ref::<TransferBox>() else {
            continue;
        };
        let TransferBox::Asset(transfer) = transfer_box else {
            continue;
        };
        let mut scope = JsonMap::new();
        scope.insert("instruction".into(), JsonValue::from("transfer_asset"));
        scope.insert(
            "source_asset_definition_id".into(),
            JsonValue::from(transfer.source.definition().to_string()),
        );
        match transfer.source.scope() {
            AssetBalanceScope::Global => {
                scope.insert("source_scope".into(), JsonValue::from("global"));
            }
            AssetBalanceScope::Dataspace(dataspace_id) => {
                scope.insert("source_scope".into(), JsonValue::from("dataspace"));
                scope.insert(
                    "source_dataspace_id".into(),
                    JsonValue::from(dataspace_id.as_u64()),
                );
            }
        }
        transfer_asset_scopes.push(JsonValue::Object(scope));
    }
    JsonValue::Object(JsonMap::from_iter([(
        "transfer_asset_scopes".into(),
        JsonValue::Array(transfer_asset_scopes),
    )]))
}
fn encode_asset_transaction<F>(
    network_id: NetworkId,
    authority: AccountId,
    creation_time_ms: u64,
    ttl_option: Option<NonZeroU64>,
    fee_payment: FeePaymentIntent,
    private_key: PrivateKey,
    build_executable: F,
) -> BridgeResult<(Vec<u8>, [u8; 32])>
where
    F: FnOnce() -> Executable,
{
    encode_asset_transaction_with_nonce(
        network_id,
        authority,
        AssetTransactionTiming {
            creation_time_ms,
            ttl: ttl_option,
            nonce: None,
        },
        fee_payment,
        private_key,
        build_executable,
    )
}
#[derive(Clone, Copy)]
struct AssetTransactionTiming {
    creation_time_ms: u64,
    ttl: Option<NonZeroU64>,
    nonce: Option<NonZeroU32>,
}
fn encode_asset_transaction_with_nonce<F>(
    network_id: NetworkId,
    authority: AccountId,
    timing: AssetTransactionTiming,
    fee_payment: FeePaymentIntent,
    private_key: PrivateKey,
    build_executable: F,
) -> BridgeResult<(Vec<u8>, [u8; 32])>
where
    F: FnOnce() -> Executable,
{
    encode_asset_transaction_with_nonce_and_metadata(
        network_id,
        authority,
        timing.creation_time_ms,
        timing.ttl,
        timing.nonce,
        fee_payment,
        Metadata::default(),
        private_key,
        build_executable,
    )
}
#[allow(clippy::too_many_arguments)]
fn encode_asset_transaction_with_nonce_and_metadata<F>(
    network_id: NetworkId,
    authority: AccountId,
    creation_time_ms: u64,
    ttl_option: Option<NonZeroU64>,
    nonce_option: Option<NonZeroU32>,
    fee_payment: FeePaymentIntent,
    metadata: Metadata,
    private_key: PrivateKey,
    build_executable: F,
) -> BridgeResult<(Vec<u8>, [u8; 32])>
where
    F: FnOnce() -> Executable,
{
    let ttl_duration = ttl_option.map(|ttl| Duration::from_millis(ttl.get()));
    let mut builder = TransactionBuilder::new(network_id, authority, fee_payment);
    builder = builder.with_executable(build_executable());
    if !metadata.is_empty() {
        builder = builder.with_metadata(metadata);
    }
    if let Some(ttl) = ttl_duration {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = nonce_option {
        builder.set_nonce(nonce);
    }
    builder.set_creation_time(Duration::from_millis(creation_time_ms));
    let signed = builder
        .try_sign(&private_key)
        .map_err(|_| BridgeError::TransactionSign)?;
    let signed_bytes = signed.encode_versioned();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(signed.hash().as_ref());
    Ok((signed_bytes, hash))
}
#[allow(clippy::too_many_arguments)]
fn encode_asset_transaction_with_nonce_fee_payment_and_metadata<F>(
    network_id: NetworkId,
    authority: AccountId,
    creation_time_ms: u64,
    ttl_option: Option<NonZeroU64>,
    nonce_option: Option<NonZeroU32>,
    fee_payment: FeePaymentIntent,
    metadata: Metadata,
    private_key: PrivateKey,
    build_executable: F,
) -> BridgeResult<(Vec<u8>, [u8; 32])>
where
    F: FnOnce() -> Executable,
{
    encode_asset_transaction_with_nonce_and_metadata(
        network_id,
        authority,
        creation_time_ms,
        ttl_option,
        nonce_option,
        fee_payment,
        metadata,
        private_key,
        build_executable,
    )
}
fn encode_instruction_transaction(
    network_id: NetworkId,
    authority: AccountId,
    creation_time_ms: u64,
    ttl_option: Option<NonZeroU64>,
    fee_payment: FeePaymentIntent,
    private_key: PrivateKey,
    instruction: InstructionBox,
) -> BridgeResult<(Vec<u8>, [u8; 32])> {
    encode_asset_transaction(
        network_id,
        authority,
        creation_time_ms,
        ttl_option,
        fee_payment,
        private_key,
        move || Executable::from([instruction]),
    )
}
fn b64_encode(bytes: &[u8]) -> String {
    let eng = b64gp::STANDARD;
    let len = bytes.len().div_ceil(3) * 4;
    let mut out = vec![0u8; len];
    let wrote = eng.encode_slice(bytes, &mut out).expect("encode");
    out.truncate(wrote);
    String::from_utf8(out).expect("utf8")
}
fn json_object(pairs: impl IntoIterator<Item = (&'static str, JsonValue)>) -> JsonValue {
    let mut map = JsonMap::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    JsonValue::Object(map)
}
fn json_string_array(values: &[String]) -> JsonValue {
    JsonValue::Array(values.iter().map(|s| JsonValue::from(s.as_str())).collect())
}
fn json_option_string_array(values: &Option<Vec<String>>) -> JsonValue {
    match values {
        Some(list) => json_string_array(list),
        None => JsonValue::Null,
    }
}
fn bool_to_u8(value: bool) -> u8 {
    if value { 1 } else { 0 }
}
fn option_to_ffi(value: Option<usize>) -> (u64, u8) {
    match value {
        Some(v) => (v as u64, 1),
        None => (0, 0),
    }
}
unsafe fn parse_permissions_bytes(
    permissions_ptr: *const u8,
    permissions_len: c_ulong,
) -> Result<Option<proto::PermissionsV1>, c_int> {
    if permissions_ptr.is_null() || permissions_len == 0 {
        return Ok(None);
    }
    let json = unsafe { std::slice::from_raw_parts(permissions_ptr, permissions_len as usize) };
    if json.is_empty() {
        return Ok(None);
    }
    let val = norito::json::from_slice::<JsonValue>(json).map_err(|_| -4)?;
    match val {
        JsonValue::Null => Ok(None),
        JsonValue::Object(map) => {
            if map
                .keys()
                .any(|key| !matches!(key.as_str(), "methods" | "events" | "resources"))
            {
                return Err(-4);
            }
            let parse_strings = |field: &str| -> Result<Vec<String>, c_int> {
                let Some(value) = map.get(field) else {
                    return Ok(Vec::new());
                };
                value
                    .as_array()
                    .ok_or(-4)?
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned).ok_or(-4))
                    .collect()
            };
            let methods = parse_strings("methods")?;
            let events = parse_strings("events")?;
            let resources = match map.get("resources") {
                None | Some(JsonValue::Null) => None,
                Some(value) => Some(
                    value
                        .as_array()
                        .ok_or(-4)?
                        .iter()
                        .map(|value| value.as_str().map(str::to_owned).ok_or(-4))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            };
            Ok(Some(proto::PermissionsV1 {
                methods,
                events,
                resources,
            }))
        }
        _ => Err(-4),
    }
}
unsafe fn parse_app_meta_bytes(
    app_meta_ptr: *const u8,
    app_meta_len: c_ulong,
) -> Result<Option<proto::AppMeta>, c_int> {
    if app_meta_ptr.is_null() || app_meta_len == 0 {
        return Ok(None);
    }
    let json = unsafe { std::slice::from_raw_parts(app_meta_ptr, app_meta_len as usize) };
    if json.is_empty() {
        return Ok(None);
    }
    let val = norito::json::from_slice::<JsonValue>(json).map_err(|_| -4)?;
    match val {
        JsonValue::Null => Ok(None),
        JsonValue::Object(map) => {
            if map
                .keys()
                .any(|key| !matches!(key.as_str(), "name" | "url" | "icon_hash"))
            {
                return Err(-4);
            }
            let name = map
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty() && value.trim() == *value);
            let Some(name) = name else {
                return Err(-4);
            };
            let optional_string = |field: &str| -> Result<Option<String>, c_int> {
                match map.get(field) {
                    None | Some(JsonValue::Null) => Ok(None),
                    Some(value) => value.as_str().map(str::to_owned).map(Some).ok_or(-4),
                }
            };
            let url = optional_string("url")?;
            let icon_hash = optional_string("icon_hash")?;
            Ok(Some(proto::AppMeta {
                name: name.to_string(),
                url,
                icon_hash,
            }))
        }
        _ => Err(-4),
    }
}
unsafe fn parse_proof_bytes(
    proof_ptr: *const u8,
    proof_len: c_ulong,
) -> Result<Option<proto::SignInProofV1>, c_int> {
    if proof_ptr.is_null() || proof_len == 0 {
        return Ok(None);
    }
    let json = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len as usize) };
    if json.is_empty() {
        return Ok(None);
    }
    let val = norito::json::from_slice::<JsonValue>(json).map_err(|_| -4)?;
    match val {
        JsonValue::Null => Ok(None),
        JsonValue::Object(map) => {
            if map.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "domain" | "uri" | "statement" | "issued_at" | "nonce"
                )
            }) {
                return Err(-4);
            }
            let required_string = |field: &str| -> Result<String, c_int> {
                map.get(field)
                    .and_then(JsonValue::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or(-4)
            };
            let domain = required_string("domain")?;
            let uri = required_string("uri")?;
            let statement = required_string("statement")?;
            let issued_at = required_string("issued_at")?;
            let nonce = required_string("nonce")?;
            Ok(Some(proto::SignInProofV1 {
                domain,
                uri,
                statement,
                issued_at,
                nonce,
            }))
        }
        _ => Err(-4),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_ciphertext_frame(
    sid_ptr: *const c_uchar,  // 32 bytes
    dir: c_uchar,             // 0 = AppToWallet, 1 = WalletToApp
    seq: u64,                 // little-endian in header
    aead_ptr: *const c_uchar, // ChaChaPoly combined (ct||tag)
    aead_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sid_ptr.is_null() || aead_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let sid = std::slice::from_raw_parts(sid_ptr, 32);
        let aead = std::slice::from_raw_parts(aead_ptr, aead_len as usize);
        let mut sid_arr = [0u8; 32];
        sid_arr.copy_from_slice(sid);
        let dir = match dir {
            0 => proto::Dir::AppToWallet,
            1 => proto::Dir::WalletToApp,
            _ => return -2,
        };
        let ct = proto::ConnectCiphertextV1 {
            dir,
            aead: aead.to_vec(),
        };
        let frame = proto::ConnectFrameV1 {
            sid: sid_arr,
            dir,
            seq,
            kind: proto::FrameKind::Ciphertext(ct),
        };
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -4)
    }
}
fn read_32_bytes(ptr: *const c_uchar) -> Result<[u8; 32], c_int> {
    if ptr.is_null() {
        return Err(-1);
    }
    let slice = unsafe { slice::from_raw_parts(ptr, 32) };
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_connect_generate_keypair(
    out_pk: *mut c_uchar,
    out_sk: *mut c_uchar,
) -> c_int {
    unsafe {
        if out_pk.is_null() || out_sk.is_null() {
            return -1;
        }
        let scheme = iroha_crypto::kex::X25519Sha256::new();
        let (pk, sk) = match scheme.try_keypair(KeyGenOption::Random) {
            Ok(keypair) => keypair,
            Err(_) => return ERR_CONNECT_KEYPAIR,
        };
        ptr::copy_nonoverlapping(pk.as_bytes().as_ptr(), out_pk, 32);
        let sk_bytes = Zeroizing::new(sk.to_bytes());
        ptr::copy_nonoverlapping(sk_bytes.as_ref().as_ptr(), out_sk, 32);
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_connect_public_from_private(
    sk_ptr: *const c_uchar,
    out_pk: *mut c_uchar,
) -> c_int {
    unsafe {
        if sk_ptr.is_null() || out_pk.is_null() {
            return -1;
        }
        let sk_bytes = match read_32_bytes(sk_ptr) {
            Ok(b) => b,
            Err(code) => return code,
        };
        let scheme = iroha_crypto::kex::X25519Sha256::new();
        let sk = x25519_dalek::StaticSecret::from(sk_bytes);
        let (derived_pk, _) = scheme.keypair(KeyGenOption::FromPrivateKey(sk));
        let pk = iroha_crypto::kex::X25519Sha256::encode_public_key(&derived_pk);
        let pk_slice: &[u8] = pk.as_ref();
        debug_assert_eq!(pk_slice.len(), 32);
        ptr::copy_nonoverlapping(pk_slice.as_ptr(), out_pk, pk_slice.len());
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_connect_derive_keys(
    sk_ptr: *const c_uchar,
    peer_pk_ptr: *const c_uchar,
    sid_ptr: *const c_uchar,
    out_app_ptr: *mut c_uchar,
    out_wallet_ptr: *mut c_uchar,
) -> c_int {
    unsafe {
        if sk_ptr.is_null()
            || peer_pk_ptr.is_null()
            || sid_ptr.is_null()
            || out_app_ptr.is_null()
            || out_wallet_ptr.is_null()
        {
            return -1;
        }
        let local_sk = match read_32_bytes(sk_ptr) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let peer_pk = match read_32_bytes(peer_pk_ptr) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let sid = match read_32_bytes(sid_ptr) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let (app_key, wallet_key) = match connect_sdk::x25519_derive_keys(&local_sk, &peer_pk, &sid)
        {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        ptr::copy_nonoverlapping(app_key.as_ptr(), out_app_ptr, 32);
        ptr::copy_nonoverlapping(wallet_key.as_ptr(), out_wallet_ptr, 32);
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_connect_encrypt_envelope(
    key_ptr: *const c_uchar,
    sid_ptr: *const c_uchar,
    dir: c_uchar,
    env_ptr: *const c_uchar,
    env_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if key_ptr.is_null()
            || sid_ptr.is_null()
            || env_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
        {
            return -1;
        }
        let key = match read_32_bytes(key_ptr) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let sid = match read_32_bytes(sid_ptr) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let direction = match dir {
            0 => proto::Dir::AppToWallet,
            1 => proto::Dir::WalletToApp,
            _ => return -2,
        };
        let env_bytes = std::slice::from_raw_parts(env_ptr, env_len as usize);
        let envelope = match decode_envelope(env_bytes) {
            Ok(env) => env,
            Err(_) => return -3,
        };
        let frame =
            connect_sdk::seal_envelope(&key, &sid, direction, envelope.seq, envelope.payload);
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, ERR_ALLOC)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_connect_decrypt_ciphertext(
    key_ptr: *const c_uchar,
    frame_ptr: *const c_uchar,
    frame_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if key_ptr.is_null() || frame_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let key = match read_32_bytes(key_ptr) {
            Ok(bytes) => bytes,
            Err(code) => return code,
        };
        let frame_bytes = std::slice::from_raw_parts(frame_ptr, frame_len as usize);
        let frame = match decode_connect_frame(frame_bytes) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let envelope = match connect_sdk::open_envelope(&key, &frame) {
            Ok(env) => env,
            Err(_) => return -3,
        };
        write_encoded_result(
            encode_envelope_framed(&envelope),
            out_ptr,
            out_len,
            ERR_ALLOC,
        )
    }
}
// ---------------- Control frame decode helpers ----------------
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_kind(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_sid_ptr: *mut c_uchar, // 32 bytes
    out_dir: *mut c_uchar,     // 0/1
    out_seq: *mut u64,
    out_kind: *mut u16,
) -> c_int {
    unsafe {
        if inp_ptr.is_null()
            || out_sid_ptr.is_null()
            || out_dir.is_null()
            || out_seq.is_null()
            || out_kind.is_null()
        {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let kind: u16 = match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Open { .. }) => 1,
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { .. }) => 2,
            proto::FrameKind::Control(proto::ConnectControlV1::Reject { .. }) => 3,
            proto::FrameKind::Control(proto::ConnectControlV1::Close { .. }) => 4,
            proto::FrameKind::Control(proto::ConnectControlV1::Ping { .. }) => 5,
            proto::FrameKind::Control(proto::ConnectControlV1::Pong { .. }) => 6,
            proto::FrameKind::Control(proto::ConnectControlV1::ServerEvent { .. }) => 7,
            proto::FrameKind::Ciphertext(_) => 100,
        };
        ptr::copy_nonoverlapping(frame.sid.as_ptr(), out_sid_ptr, 32);
        *out_dir = match frame.dir {
            proto::Dir::AppToWallet => 0,
            proto::Dir::WalletToApp => 1,
        };
        *out_seq = frame.seq;
        *out_kind = kind;
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_open_pub(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_pk: *mut c_uchar,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_pk.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Open { app_pk, .. }) => {
                ptr::copy_nonoverlapping(app_pk.as_ptr(), out_pk, 32);
                0
            }
            _ => -3,
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_approve_pub(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_pk: *mut c_uchar,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_pk.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { wallet_pk, .. }) => {
                ptr::copy_nonoverlapping(wallet_pk.as_ptr(), out_pk, 32);
                0
            }
            _ => -3,
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_approve_account(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { account_id, .. }) => {
                let bytes = account_id.as_bytes();
                let len = bytes.len();
                let mem = malloc(len);
                if mem.is_null() {
                    return -3;
                }
                ptr::copy_nonoverlapping(bytes.as_ptr(), mem as *mut u8, len);
                *out_ptr = mem as *mut u8;
                *out_len = len as c_ulong;
                0
            }
            _ => -4,
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_approve_sig(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_sig: *mut c_uchar,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_sig.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { sig_wallet, .. }) => {
                match sig_wallet.algorithm {
                    Algorithm::Ed25519 => {
                        let bytes = sig_wallet.bytes();
                        if bytes.len() != 64 {
                            return -3;
                        }
                        ptr::copy_nonoverlapping(bytes.as_ptr(), out_sig, 64);
                        0
                    }
                    _ => -5,
                }
            }
            _ => -4,
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_open_network_id(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let network_id = match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Open { constraints, .. }) => {
                constraints.network_id
            }
            _ => return -3,
        };
        if let Err(code) = write_bytes(out_ptr, out_len, network_id.as_bytes()) {
            return code;
        }
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_approve_sig_alg(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_alg_ptr: *mut *mut c_char,
    out_alg_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_alg_ptr.is_null() || out_alg_len.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let alg_str = match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Approve { sig_wallet, .. }) => {
                sig_wallet.algorithm.as_static_str()
            }
            _ => return -3,
        };
        write_bytes(
            out_alg_ptr.cast::<*mut c_uchar>(),
            out_alg_len,
            alg_str.as_bytes(),
        )
        .map_or(-4, |()| 0)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_close(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_role: *mut c_uchar,
    out_code: *mut u16,
    out_retryable: *mut c_uchar,
    out_reason_ptr: *mut *mut c_uchar,
    out_reason_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null()
            || out_role.is_null()
            || out_code.is_null()
            || out_retryable.is_null()
            || out_reason_ptr.is_null()
            || out_reason_len.is_null()
        {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let (who, code, reason, retryable) = match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Close {
                who,
                code,
                reason,
                retryable,
            }) => (who, code, reason, retryable),
            _ => return -3,
        };
        *out_role = match who {
            proto::Role::App => 0,
            proto::Role::Wallet => 1,
        };
        *out_code = code;
        *out_retryable = if retryable { 1 } else { 0 };
        if let Err(code) = write_bytes(out_reason_ptr, out_reason_len, reason.as_bytes()) {
            return code;
        }
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_control_reject(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_code: *mut u16,
    out_code_id_ptr: *mut *mut c_uchar,
    out_code_id_len: *mut c_ulong,
    out_reason_ptr: *mut *mut c_uchar,
    out_reason_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null()
            || out_code.is_null()
            || out_code_id_ptr.is_null()
            || out_code_id_len.is_null()
            || out_reason_ptr.is_null()
            || out_reason_len.is_null()
        {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let (code, code_id, reason) = match frame.kind {
            proto::FrameKind::Control(proto::ConnectControlV1::Reject {
                code,
                code_id,
                reason,
            }) => (code, code_id, reason),
            _ => return -3,
        };
        *out_code = code;
        if let Err(code) = write_bytes(out_code_id_ptr, out_code_id_len, code_id.as_bytes()) {
            return code;
        }
        if let Err(code) = write_bytes(out_reason_ptr, out_reason_len, reason.as_bytes()) {
            return code;
        }
        0
    }
}
macro_rules! define_control_nonce_decoder {
    ($name:ident, $variant:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            inp_ptr: *const c_uchar,
            inp_len: c_ulong,
            out_nonce: *mut u64,
        ) -> c_int {
            unsafe {
                if inp_ptr.is_null() || out_nonce.is_null() {
                    return -1;
                }
                let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
                let frame = match decode_connect_frame(inp) {
                    Ok(frame) => frame,
                    Err(_) => return -2,
                };
                let nonce = match frame.kind {
                    proto::FrameKind::Control(proto::ConnectControlV1::$variant { nonce }) => nonce,
                    _ => return -3,
                };
                *out_nonce = nonce;
                0
            }
        }
    };
}
define_control_nonce_decoder!(connect_norito_decode_control_ping, Ping);
define_control_nonce_decoder!(connect_norito_decode_control_pong, Pong);
macro_rules! define_control_json_decoder {
    (
        $name:ident,
        $variant:ident { $field:ident } => $value:expr $(,)?
    ) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            inp_ptr: *const c_uchar,
            inp_len: c_ulong,
            out_ptr: *mut *mut c_uchar,
            out_len: *mut c_ulong,
        ) -> c_int {
            unsafe {
                if inp_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
                    return -1;
                }
                let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
                let frame = match decode_connect_frame(inp) {
                    Ok(frame) => frame,
                    Err(_) => return -2,
                };
                let $field = match frame.kind {
                    proto::FrameKind::Control(proto::ConnectControlV1::$variant {
                        ref $field,
                        ..
                    }) => $field,
                    _ => return -3,
                };
                let value: JsonValue = $value;
                write_output_result(norito::json::to_vec(&value), out_ptr, out_len, -4, -5)
            }
        }
    };
}
define_control_json_decoder!(
    connect_norito_decode_control_approve_account_json,
    Approve { account_id } => json_object([("account_id", ::norito::json!(account_id.clone()))]),
);
// ---------------- Permissions/Proof JSON helpers ----------------
define_control_json_decoder!(
    connect_norito_decode_control_open_app_metadata_json,
    Open { app_meta } => if let Some(meta) = app_meta {
        let url = meta
            .url
            .as_ref()
            .map(|value| JsonValue::from(value.as_str()))
            .unwrap_or(JsonValue::Null);
        let icon_hash = meta
            .icon_hash
            .as_ref()
            .map(|value| JsonValue::from(value.as_str()))
            .unwrap_or(JsonValue::Null);
        json_object([
            ("name", JsonValue::from(meta.name.as_str())),
            ("url", url),
            ("icon_hash", icon_hash),
        ])
    } else {
        json_object([])
    },
);
define_control_json_decoder!(
    connect_norito_decode_control_open_permissions_json,
    Open { permissions } => if let Some(p) = permissions {
        json_object([
            ("methods", json_string_array(&p.methods)),
            ("events", json_string_array(&p.events)),
            ("resources", json_option_string_array(&p.resources)),
        ])
    } else {
        json_object([])
    },
);
define_control_json_decoder!(
    connect_norito_decode_control_approve_permissions_json,
    Approve { permissions } => if let Some(p) = permissions {
        json_object([
            ("methods", json_string_array(&p.methods)),
            ("events", json_string_array(&p.events)),
            ("resources", json_option_string_array(&p.resources)),
        ])
    } else {
        json_object([])
    },
);
define_control_json_decoder!(
    connect_norito_decode_control_approve_proof_json,
    Approve { proof } => if let Some(p) = proof {
        json_object([
            ("domain", ::norito::json!(p.domain.clone())),
            ("uri", ::norito::json!(p.uri.clone())),
            ("statement", ::norito::json!(p.statement.clone())),
            ("issued_at", ::norito::json!(p.issued_at.clone())),
            ("nonce", ::norito::json!(p.nonce.clone())),
        ])
    } else {
        json_object([])
    },
);
// ---------------- Extended control encoders ----------------
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_control_open_ext(
    sid_ptr: *const c_uchar,
    dir: c_uchar,
    seq: u64,
    app_pk_ptr: *const c_uchar,
    app_pk_len: c_ulong,
    nonce_ptr: *const c_uchar,
    nonce_len: c_ulong,
    app_meta_ptr: *const c_uchar,
    app_meta_len: c_ulong,
    network_id_ptr: *const c_uchar,
    network_id_len: c_ulong,
    perms_ptr: *const c_uchar,
    perms_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sid_ptr.is_null()
            || app_pk_ptr.is_null()
            || nonce_ptr.is_null()
            || network_id_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
            || (app_meta_len > 0 && app_meta_ptr.is_null())
            || (perms_len > 0 && perms_ptr.is_null())
        {
            return -1;
        }
        *out_ptr = ptr::null_mut();
        *out_len = 0;
        if app_pk_len != 32
            || nonce_len != 16
            || network_id_len != Hash::LENGTH as c_ulong
            || dir != 0
            || seq != 1
        {
            return -2;
        }
        let (network_id, sid_arr, app_pk, _) = match validate_exact_connect_identity(
            std::slice::from_raw_parts(network_id_ptr, network_id_len as usize),
            std::slice::from_raw_parts(sid_ptr, 32),
            std::slice::from_raw_parts(app_pk_ptr, app_pk_len as usize),
            std::slice::from_raw_parts(nonce_ptr, nonce_len as usize),
        ) {
            Ok(identity) => identity,
            Err(code) => return code,
        };
        let dir = proto::Dir::AppToWallet;
        let app_meta = match parse_app_meta_bytes(app_meta_ptr, app_meta_len) {
            Ok(meta) => meta,
            Err(code) => return code,
        };
        let permissions = match parse_permissions_bytes(perms_ptr, perms_len) {
            Ok(permissions) => permissions,
            Err(code) => return code,
        };
        let ctrl = proto::ConnectControlV1::Open {
            app_pk,
            app_meta,
            constraints: proto::Constraints { network_id },
            permissions,
        };
        let frame = proto::ConnectFrameV1 {
            sid: sid_arr,
            dir,
            seq,
            kind: proto::FrameKind::Control(ctrl),
        };
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -5)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_control_approve_ext(
    sid_ptr: *const c_uchar,
    dir: c_uchar,
    seq: u64,
    wallet_pk_ptr: *const c_uchar,
    wallet_pk_len: c_ulong,
    account_cstr: *const c_char,
    perms_ptr: *const c_uchar,
    perms_len: c_ulong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulong,
    sig_ptr: *const c_uchar,
    sig_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sid_ptr.is_null()
            || wallet_pk_ptr.is_null()
            || account_cstr.is_null()
            || sig_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
        {
            return -1;
        }
        if wallet_pk_len != 32 {
            return -2;
        }
        let sid = std::slice::from_raw_parts(sid_ptr, 32);
        let mut sid_arr = [0u8; 32];
        sid_arr.copy_from_slice(sid);
        let dir = match dir {
            0 => proto::Dir::AppToWallet,
            1 => proto::Dir::WalletToApp,
            _ => return -3,
        };
        let wallet_pk = {
            let pk = std::slice::from_raw_parts(wallet_pk_ptr, 32);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(pk);
            arr
        };
        let account_id = std::ffi::CStr::from_ptr(account_cstr)
            .to_string_lossy()
            .to_string();
        let permissions = match parse_permissions_bytes(perms_ptr, perms_len) {
            Ok(p) => p,
            Err(code) => return code,
        };
        let proof = match parse_proof_bytes(proof_ptr, proof_len) {
            Ok(p) => p,
            Err(code) => return code,
        };
        let sig_bytes = std::slice::from_raw_parts(sig_ptr, sig_len as usize);
        let sig_wallet = match proto::WalletSignatureV1::from_ed25519_bytes(sig_bytes) {
            Some(sig) => sig,
            None => return -4,
        };
        let ctrl = proto::ConnectControlV1::Approve {
            wallet_pk,
            account_id,
            permissions,
            proof,
            sig_wallet,
        };
        let frame = proto::ConnectFrameV1 {
            sid: sid_arr,
            dir,
            seq,
            kind: proto::FrameKind::Control(ctrl),
        };
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -5)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_control_approve_ext_with_alg(
    sid_ptr: *const c_uchar,
    dir: c_uchar,
    seq: u64,
    wallet_pk_ptr: *const c_uchar,
    account_ptr: *const c_char,
    account_len: c_ulong,
    permissions_json_ptr: *const c_char,
    permissions_json_len: c_ulong,
    proof_json_ptr: *const c_char,
    proof_json_len: c_ulong,
    alg_ptr: *const c_char,
    alg_len: c_ulong,
    sig_ptr: *const c_uchar,
    sig_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sid_ptr.is_null()
            || wallet_pk_ptr.is_null()
            || account_ptr.is_null()
            || sig_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
        {
            return -1;
        }
        let sid = std::slice::from_raw_parts(sid_ptr, 32);
        let mut sid_arr = [0u8; 32];
        sid_arr.copy_from_slice(sid);
        let dir = match dir {
            0 => proto::Dir::AppToWallet,
            1 => proto::Dir::WalletToApp,
            _ => return -2,
        };
        let wallet_pk = std::slice::from_raw_parts(wallet_pk_ptr, 32);
        let mut wallet_pk_arr = [0u8; 32];
        wallet_pk_arr.copy_from_slice(wallet_pk);
        let account_id = match std::str::from_utf8(std::slice::from_raw_parts(
            account_ptr as *const u8,
            account_len as usize,
        )) {
            Ok(s) => s.to_string(),
            Err(_) => return -3,
        };
        let permissions = match parse_permissions_bytes(
            permissions_json_ptr as *const u8,
            permissions_json_len,
        ) {
            Ok(p) => p,
            Err(code) => return code,
        };
        let proof = match parse_proof_bytes(proof_json_ptr as *const u8, proof_json_len) {
            Ok(p) => p,
            Err(code) => return code,
        };
        let algorithm = match parse_algorithm_cstr(alg_ptr, alg_len) {
            Ok(a) => a,
            Err(code) => return code,
        };
        let sig_bytes = std::slice::from_raw_parts(sig_ptr, sig_len as usize);
        let sig_wallet = match connect_wallet_signature_from_algorithm_bytes(algorithm, sig_bytes) {
            Some(signature) => signature,
            None => return -4,
        };
        let ctrl = proto::ConnectControlV1::Approve {
            wallet_pk: wallet_pk_arr,
            account_id,
            permissions,
            proof,
            sig_wallet,
        };
        let frame = proto::ConnectFrameV1 {
            sid: sid_arr,
            dir,
            seq,
            kind: proto::FrameKind::Control(ctrl),
        };
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -5)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_control_reject(
    sid_ptr: *const c_uchar,
    dir: c_uchar,
    seq: u64,
    code: u16,
    code_id_ptr: *const c_char,
    code_id_len: c_ulong,
    reason_ptr: *const c_char,
    reason_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sid_ptr.is_null() || code_id_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let sid = std::slice::from_raw_parts(sid_ptr, 32);
        let mut sid_arr = [0u8; 32];
        sid_arr.copy_from_slice(sid);
        let dir = match dir {
            0 => proto::Dir::AppToWallet,
            1 => proto::Dir::WalletToApp,
            _ => return -2,
        };
        let code_id_bytes =
            std::slice::from_raw_parts(code_id_ptr as *const u8, code_id_len as usize);
        let code_id = match std::str::from_utf8(code_id_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => return -3,
        };
        let reason = if !reason_ptr.is_null() && reason_len > 0 {
            let bytes = std::slice::from_raw_parts(reason_ptr as *const u8, reason_len as usize);
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => return -4,
            }
        } else {
            String::new()
        };
        let ctrl = proto::ConnectControlV1::Reject {
            code,
            code_id,
            reason,
        };
        let frame = proto::ConnectFrameV1 {
            sid: sid_arr,
            dir,
            seq,
            kind: proto::FrameKind::Control(ctrl),
        };
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -5)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_control_close(
    sid_ptr: *const c_uchar,
    dir: c_uchar,
    seq: u64,
    who_raw: c_uchar,
    code: u16,
    reason_ptr: *const c_char,
    reason_len: c_ulong,
    retryable: c_uchar,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sid_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let sid = std::slice::from_raw_parts(sid_ptr, 32);
        let mut sid_arr = [0u8; 32];
        sid_arr.copy_from_slice(sid);
        let dir = match dir {
            0 => proto::Dir::AppToWallet,
            1 => proto::Dir::WalletToApp,
            _ => return -2,
        };
        let who = match who_raw {
            0 => proto::Role::App,
            1 => proto::Role::Wallet,
            _ => return -3,
        };
        let reason = if !reason_ptr.is_null() && reason_len > 0 {
            let bytes = std::slice::from_raw_parts(reason_ptr as *const u8, reason_len as usize);
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => return -4,
            }
        } else {
            String::new()
        };
        let ctrl = proto::ConnectControlV1::Close {
            who,
            code,
            reason,
            retryable: retryable != 0,
        };
        let frame = proto::ConnectFrameV1 {
            sid: sid_arr,
            dir,
            seq,
            kind: proto::FrameKind::Control(ctrl),
        };
        write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -5)
    }
}
macro_rules! define_control_nonce_encoder {
    ($name:ident, $variant:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            sid_ptr: *const c_uchar,
            dir: c_uchar,
            seq: u64,
            nonce: u64,
            out_ptr: *mut *mut c_uchar,
            out_len: *mut c_ulong,
        ) -> c_int {
            unsafe {
                if sid_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
                    return -1;
                }
                let sid = std::slice::from_raw_parts(sid_ptr, 32);
                let mut sid_arr = [0u8; 32];
                sid_arr.copy_from_slice(sid);
                let dir = match dir {
                    0 => proto::Dir::AppToWallet,
                    1 => proto::Dir::WalletToApp,
                    _ => return -2,
                };
                let ctrl = proto::ConnectControlV1::$variant { nonce };
                let frame = proto::ConnectFrameV1 {
                    sid: sid_arr,
                    dir,
                    seq,
                    kind: proto::FrameKind::Control(ctrl),
                };
                write_encoded_result(encode_connect_frame(&frame), out_ptr, out_len, -3)
            }
        }
    };
}
define_control_nonce_encoder!(connect_norito_encode_control_ping, Ping);
define_control_nonce_encoder!(connect_norito_encode_control_pong, Pong);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_ciphertext_frame(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_sid_ptr: *mut c_uchar, // must point to 32 bytes
    out_dir: *mut c_uchar,     // 0 or 1
    out_seq: *mut u64,
    out_aead_ptr: *mut *mut c_uchar,
    out_aead_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null()
            || out_sid_ptr.is_null()
            || out_dir.is_null()
            || out_seq.is_null()
            || out_aead_ptr.is_null()
            || out_aead_len.is_null()
        {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let frame = match decode_connect_frame(inp) {
            Ok(f) => f,
            Err(_) => return -2,
        };
        let (dir, seq, ct) = match frame.kind {
            proto::FrameKind::Ciphertext(ct) => (frame.dir, frame.seq, ct),
            _ => return -3,
        };
        ptr::copy_nonoverlapping(frame.sid.as_ptr(), out_sid_ptr, 32);
        *out_dir = match dir {
            proto::Dir::AppToWallet => 0,
            proto::Dir::WalletToApp => 1,
        };
        *out_seq = seq;
        let len = ct.aead.len();
        let mem = malloc(len);
        if mem.is_null() {
            return -4;
        }
        ptr::copy_nonoverlapping(ct.aead.as_ptr(), mem as *mut u8, len);
        *out_aead_ptr = mem as *mut u8;
        *out_aead_len = len as c_ulong;
        0
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_free(ptr_: *mut c_uchar) {
    if !ptr_.is_null() {
        unsafe {
            free(ptr_ as *mut _);
        }
    }
}
include!("validation_fee_policy_proof_bridge_tests.rs");
#[cfg(test)]
fn bridge_source() -> &'static str {
    static SOURCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SOURCE.get_or_init(|| {
        let platform_source = [
            include_str!("platform_jni.rs"),
            include_str!("platform_jni/part_1.rs"),
            include_str!("platform_jni/part_2.rs"),
            include_str!("platform_jni/part_3.rs"),
        ]
        .concat();
        include_str!("./lib.rs").replacen("mod platform_jni;\n", &platform_source, 1)
    })
}
#[cfg(test)]
mod detached_transaction_scaffold_tests {
    use super::*;
    use iroha_data_model::{
        asset::AssetId,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        smart_contract::ContractAddress,
        transaction::{
            executable::{ContractArgumentRecord, ContractInvocation, IvmBytecode},
            signed::{MultisigSignatures, TransactionBuilder},
        },
    };
    use iroha_model_base::topology::DataSpaceId;
    use std::{num::NonZeroU32, ptr};
    fn detached_test_network_id() -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(Hash::new(
            b"detached-bridge-test",
        )))
    }
    fn fixture_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("valid deterministic Ed25519 fixture")
    }
    fn scaffold_transaction(
        authority_keypair: &KeyPair,
        executable: Executable,
        configure: impl FnOnce(&mut TransactionBuilder),
    ) -> SignedTransaction {
        let authority = AccountId::new(authority_keypair.public_key().clone());
        let mut builder = TransactionBuilder::new(
            detached_test_network_id(),
            authority,
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(9_000_000)),
        )
        .with_executable(executable)
        .with_metadata({
            let mut metadata = Metadata::default();
            metadata.insert(
                "nested".parse().expect("metadata key"),
                Json::from_raw_json("{\"a\":[true,null],\"z\":2}".to_owned())
                    .expect("valid nested JSON fixture"),
            );
            metadata
        });
        builder.set_creation_time(Duration::from_millis(1_700_000_000_123));
        builder.set_ttl(Duration::from_millis(60_000));
        configure(&mut builder);
        let placeholder = fixture_keypair(0xA1);
        let payload = builder
            .into_payload()
            .expect("valid detached scaffold payload");
        let placeholder_signature = Signature::try_new(
            placeholder.private_key(),
            iroha_crypto::HashOf::new(&payload).as_ref(),
        )
        .expect("placeholder scaffold signature");
        TransactionBuilder::from_payload(payload)
            .expect("valid detached scaffold payload")
            .build_with_signature(placeholder_signature)
    }
    fn contract_scaffold(authority_keypair: &KeyPair) -> SignedTransaction {
        let authority = AccountId::new(authority_keypair.public_key().clone());
        let contract_address = ContractAddress::derive(
            &detached_test_network_id(),
            &authority,
            7,
            DataSpaceId::UNIVERSAL,
        )
        .expect("contract address");
        let invocation = ContractInvocation {
            contract_address,
            expected_code_hash: iroha_crypto::Hash::new(b"detached-contract-code"),
            entrypoint: "pay".to_owned(),
            arguments: Some(
                ContractArgumentRecord::try_new(vec![0x01, 0x02, 0x03])
                    .expect("bounded contract arguments"),
            ),
        };
        scaffold_transaction(
            authority_keypair,
            Executable::ContractCall(invocation),
            |_| {},
        )
    }
    fn transfer_scaffold(authority_keypair: &KeyPair, scoped: bool) -> SignedTransaction {
        let authority = AccountId::new(authority_keypair.public_key().clone());
        let destination = AccountId::new(fixture_keypair(0xB2).public_key().clone());
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wallet", "universal").expect("domain"),
            "coin".parse().expect("asset name"),
        );
        let asset = if scoped {
            AssetId::with_scope(
                definition,
                authority,
                AssetBalanceScope::Dataspace(DataSpaceId::new(42)),
            )
        } else {
            AssetId::new(definition, authority)
        };
        let transfer: InstructionBox = Transfer::asset_quantity(
            asset,
            "1.25".parse::<Quantity>().expect("quantity"),
            destination,
        )
        .into();
        scaffold_transaction(authority_keypair, Executable::from([transfer]), |_| {})
    }
    fn inspect_value(tx: &SignedTransaction) -> JsonValue {
        let (_, json) = inspect_detached_transaction_scaffold(&tx.encode_versioned())
            .expect("valid detached scaffold");
        norito::json::from_slice_value(&json).expect("inspection JSON")
    }
    #[test]
    fn atomic_transfer_batch_inspection_binds_two_exact_ordered_native_transfers() {
        use iroha_data_model::transaction::ExecutableBatchItem;
        let keypair = fixture_keypair(0x41);
        let principal = transfer_scaffold(&keypair, true);
        let fee = transfer_scaffold(&keypair, false);
        let Executable::Instructions(principal) = principal.instructions() else {
            panic!("transfer fixture");
        };
        let Executable::Instructions(fee) = fee.instructions() else {
            panic!("transfer fixture");
        };
        let entries = vec![
            ExecutableBatchItem::Instruction(principal[0].clone()),
            ExecutableBatchItem::Instruction(fee[0].clone()),
        ];
        let tx = scaffold_transaction(&keypair, Executable::Batch(entries.clone().into()), |_| {});
        let value = inspect_value(&tx);
        let executable = value
            .as_object()
            .unwrap()
            .get("executable")
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(
            executable.get("kind").and_then(JsonValue::as_str),
            Some("asset_transfer_batch")
        );
        let transfers = executable.get("transfers").unwrap().as_array().unwrap();
        assert_eq!(transfers.len(), 2);
        assert_ne!(
            transfers[0], transfers[1],
            "native balance scope is retained on each ordered leg"
        );
        let payload_hash = iroha_crypto::HashOf::new(tx.payload());
        let mut reversed = entries.clone();
        reversed.reverse();
        let reverse_tx = scaffold_transaction(&keypair, Executable::Batch(reversed.into()), |_| {});
        assert_ne!(
            payload_hash,
            iroha_crypto::HashOf::new(reverse_tx.payload())
        );
        for invalid in [vec![], entries[..1].to_vec(), vec![entries[0].clone(); 3]] {
            let invalid = scaffold_transaction(&keypair, Executable::Batch(invalid.into()), |_| {});
            assert!(inspect_detached_transaction_scaffold(&invalid.encode_versioned()).is_err());
        }
        let wrong_kind = InstructionBox::from(iroha_data_model::isi::Log::new(
            iroha_data_model::Level::INFO,
            "not a transfer".to_owned(),
        ));
        let invalid = scaffold_transaction(
            &keypair,
            Executable::Batch(
                vec![
                    entries[0].clone(),
                    ExecutableBatchItem::Instruction(wrong_kind),
                ]
                .into(),
            ),
            |_| {},
        );
        assert!(inspect_detached_transaction_scaffold(&invalid.encode_versioned()).is_err());
        let (wire_id, frame) = framed_instruction_payload(&principal[0]).unwrap();
        assert_eq!(
            decode_instruction_from_pair(wire_id, &frame).unwrap(),
            principal[0]
        );
    }

    #[test]
    fn inspector_binds_every_contract_call_field_and_exact_metadata() {
        let keypair = fixture_keypair(0x31);
        let tx = contract_scaffold(&keypair);
        let value = inspect_value(&tx);
        let object = value.as_object().expect("inspection object");
        assert_eq!(
            object.get("schema").and_then(JsonValue::as_str),
            Some("iroha.detached_transaction_scaffold.v1")
        );
        assert_eq!(
            object.get("authority").and_then(JsonValue::as_str),
            Some(tx.authority().to_string().as_str())
        );
        let expected_network_id = norito::json::to_value(
            tx.network_id()
                .expect("detached scaffold must use the network transaction domain"),
        )
        .expect("NetworkId JSON projection");
        assert_eq!(object.get("network_id"), Some(&expected_network_id));
        let network_literal = expected_network_id
            .as_str()
            .expect("NetworkId JSON must be a string");
        assert_eq!(network_literal.len(), CANONICAL_NETWORK_ID_LITERAL_BYTES);
        let reparsed = unsafe {
            read_network_id_bridge(
                network_literal.as_ptr().cast::<c_char>(),
                network_literal.len() as c_ulong,
            )
        }
        .expect("detached scaffold must expose canonical checksummed NetworkId text");
        assert_eq!(tx.network_id(), Some(&reparsed));
        for retired_key in ["chain", "chain_id", "chainId"] {
            assert!(
                object.get(retired_key).is_none(),
                "detached scaffold must not expose retired identity key {retired_key}"
            );
        }
        assert_eq!(
            object
                .get("payload_signing_hash_hex")
                .and_then(JsonValue::as_str),
            Some(hex::encode(iroha_crypto::HashOf::new(tx.payload()).as_ref()).as_str())
        );
        assert_eq!(
            object.get("metadata"),
            Some(&norito::json::to_value(tx.metadata()).unwrap())
        );
        let executable = object
            .get("executable")
            .and_then(JsonValue::as_object)
            .expect("typed executable");
        assert_eq!(
            executable.get("kind").and_then(JsonValue::as_str),
            Some("contract_call")
        );
        assert_eq!(
            executable.get("entrypoint").and_then(JsonValue::as_str),
            Some("pay")
        );
        let expected_code_hash = iroha_crypto::Hash::new(b"detached-contract-code").to_string();
        assert_eq!(
            executable
                .get("expected_code_hash")
                .and_then(JsonValue::as_str),
            Some(expected_code_hash.as_str())
        );
        assert_eq!(
            executable.get("arguments_b64").and_then(JsonValue::as_str),
            Some("AQID")
        );
    }
    #[test]
    fn inspector_binds_global_and_dataspace_asset_transfer_scopes() {
        let keypair = fixture_keypair(0x32);
        for (scoped, expected_kind) in [(false, "global"), (true, "dataspace")] {
            let tx = transfer_scaffold(&keypair, scoped);
            let value = inspect_value(&tx);
            let executable = value
                .as_object()
                .and_then(|object| object.get("executable"))
                .and_then(JsonValue::as_object)
                .expect("typed transfer executable");
            assert_eq!(
                executable.get("kind").and_then(JsonValue::as_str),
                Some("asset_transfer")
            );
            assert_eq!(
                executable.get("amount").and_then(JsonValue::as_str),
                Some("1.25")
            );
            let scope = executable
                .get("asset_scope")
                .and_then(JsonValue::as_object)
                .expect("asset scope");
            assert_eq!(
                scope.get("kind").and_then(JsonValue::as_str),
                Some(expected_kind)
            );
            assert_eq!(
                scope.get("dataspace_id").and_then(JsonValue::as_u64),
                scoped.then_some(42)
            );
        }
    }
    #[test]
    fn inspector_rejects_nonversioned_trailing_and_malformed_archives() {
        let tx = contract_scaffold(&fixture_keypair(0x33));
        assert!(
            inspect_detached_transaction_scaffold(&norito::codec::Encode::encode(&tx)).is_err()
        );
        let mut trailing = tx.encode_versioned();
        trailing.push(0);
        assert!(inspect_detached_transaction_scaffold(&trailing).is_err());
        assert!(inspect_detached_transaction_scaffold(b"not norito").is_err());
        assert!(inspect_detached_transaction_scaffold(&[]).is_err());
    }
    #[test]
    fn inspector_rejects_genesis_domain() {
        let keypair = fixture_keypair(0x39);
        let authority = AccountId::new(keypair.public_key().clone());
        let executable = contract_scaffold(&keypair).instructions().clone();
        let transaction = TransactionBuilder::new_genesis(
            authority,
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(9_000_000)),
        )
        .with_executable(executable)
        .sign(keypair.private_key());
        assert!(
            inspect_detached_transaction_scaffold(&transaction.encode_versioned()).is_err(),
            "detached transaction scaffolds must use the network transaction domain"
        );
    }
    #[test]
    fn inspector_rejects_nonce_attachments_and_multisig_sidecars() {
        let keypair = fixture_keypair(0x34);
        let with_nonce = scaffold_transaction(
            &keypair,
            contract_scaffold(&keypair).instructions().clone(),
            |builder| {
                builder.set_nonce(NonZeroU32::new(1).unwrap());
            },
        );
        assert!(inspect_detached_transaction_scaffold(&with_nonce.encode_versioned()).is_err());
        let mut with_multisig = contract_scaffold(&keypair);
        with_multisig.set_multisig_signatures(MultisigSignatures::new(Vec::new()));
        assert!(inspect_detached_transaction_scaffold(&with_multisig.encode_versioned()).is_err());
        let authority = AccountId::new(keypair.public_key().clone());
        let contract = contract_scaffold(&keypair).instructions().clone();
        let with_attachments = TransactionBuilder::new(
            detached_test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(contract)
        .with_proof_attachments(vec![ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            ProofBox::new("pipa-r/pasta".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("pipa-r/pasta", "detached-scaffold-vk"),
        )])
        .expect("valid proof carriers")
        .try_sign(keypair.private_key())
        .unwrap();
        assert!(
            inspect_detached_transaction_scaffold(&with_attachments.encode_versioned()).is_err()
        );
    }
    #[test]
    fn inspector_rejects_unsupported_executables_and_instruction_cardinality() {
        let keypair = fixture_keypair(0x35);
        let ivm = scaffold_transaction(
            &keypair,
            Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3])),
            |_| {},
        );
        assert!(inspect_detached_transaction_scaffold(&ivm.encode_versioned()).is_err());
        let one = transfer_scaffold(&keypair, false);
        let Executable::Instructions(instructions) = one.instructions() else {
            unreachable!()
        };
        let instruction = instructions.iter().next().unwrap().clone();
        let two = scaffold_transaction(
            &keypair,
            Executable::from([instruction.clone(), instruction]),
            |_| {},
        );
        assert!(inspect_detached_transaction_scaffold(&two.encode_versioned()).is_err());
        let empty = scaffold_transaction(
            &keypair,
            Executable::from(Vec::<InstructionBox>::new()),
            |_| {},
        );
        assert!(inspect_detached_transaction_scaffold(&empty.encode_versioned()).is_err());
    }
    fn atomic_transfer_batch_scaffold(keypair: &KeyPair) -> SignedTransaction {
        use iroha_data_model::transaction::ExecutableBatchItem;
        let single = transfer_scaffold(keypair, true);
        let Executable::Instructions(instructions) = single.instructions() else {
            panic!("transfer fixture");
        };
        scaffold_transaction(
            keypair,
            Executable::Batch(
                vec![
                    ExecutableBatchItem::Instruction(instructions[0].clone()),
                    ExecutableBatchItem::Instruction(instructions[0].clone()),
                ]
                .into(),
            ),
            |_| {},
        )
    }

    #[test]
    fn finalizer_binds_key_verifies_signature_and_emits_versioned_transaction() {
        let keypair = fixture_keypair(0x36);
        let scaffold = contract_scaffold(&keypair);
        let scaffold_bytes = scaffold.encode_versioned();
        let signing_hash = iroha_crypto::HashOf::new(scaffold.payload());
        let signature = Signature::try_new(keypair.private_key(), signing_hash.as_ref())
            .expect("detached signature");
        let public_key = keypair.public_key().to_bytes().1;
        let mut signed_ptr = ptr::null_mut();
        let mut signed_len = 0;
        let mut json_ptr = ptr::null_mut();
        let mut json_len = 0;
        let status = unsafe {
            connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                scaffold_bytes.as_ptr(),
                scaffold_bytes.len() as c_ulong,
                public_key.as_ptr(),
                public_key.len() as c_ulong,
                signature.payload().as_ptr(),
                signature.payload().len() as c_ulong,
                &mut signed_ptr,
                &mut signed_len,
                &mut json_ptr,
                &mut json_len,
            )
        };
        assert_eq!(status, 0);
        let signed_bytes =
            unsafe { slice::from_raw_parts(signed_ptr, signed_len as usize) }.to_vec();
        let json = unsafe { slice::from_raw_parts(json_ptr, json_len as usize) }.to_vec();
        connect_norito_free(signed_ptr);
        connect_norito_free(json_ptr);
        let signed =
            SignedTransaction::decode_all_versioned(&signed_bytes).expect("versioned signed tx");
        signed.verify_signature().expect("verified final signature");
        assert_eq!(signed.authority(), scaffold.authority());
        assert_eq!(signed.payload(), scaffold.payload());
        let value = norito::json::from_slice_value(&json).expect("finalization JSON");
        assert_eq!(
            value
                .as_object()
                .and_then(|object| object.get("transaction_hash_hex"))
                .and_then(JsonValue::as_str),
            Some(hex::encode(signed.hash().as_ref()).as_str())
        );
    }
    #[test]
    fn atomic_batch_finalizer_binds_key_verifies_signature_and_exact_payload() {
        let keypair = fixture_keypair(0x36);
        let scaffold = atomic_transfer_batch_scaffold(&keypair);
        let scaffold_bytes = scaffold.encode_versioned();
        let signing_hash = iroha_crypto::HashOf::new(scaffold.payload());
        let signature = Signature::try_new(keypair.private_key(), signing_hash.as_ref())
            .expect("detached signature");
        let public_key = keypair.public_key().to_bytes().1;
        let mut signed_ptr = ptr::null_mut();
        let mut signed_len = 0;
        let mut json_ptr = ptr::null_mut();
        let mut json_len = 0;
        let status = unsafe {
            connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                scaffold_bytes.as_ptr(),
                scaffold_bytes.len() as c_ulong,
                public_key.as_ptr(),
                public_key.len() as c_ulong,
                signature.payload().as_ptr(),
                signature.payload().len() as c_ulong,
                &mut signed_ptr,
                &mut signed_len,
                &mut json_ptr,
                &mut json_len,
            )
        };
        assert_eq!(status, 0);
        let signed_bytes =
            unsafe { slice::from_raw_parts(signed_ptr, signed_len as usize) }.to_vec();
        let json = unsafe { slice::from_raw_parts(json_ptr, json_len as usize) }.to_vec();
        connect_norito_free(signed_ptr);
        connect_norito_free(json_ptr);
        let signed =
            SignedTransaction::decode_all_versioned(&signed_bytes).expect("versioned signed tx");
        signed.verify_signature().expect("verified final signature");
        assert_eq!(signed.authority(), scaffold.authority());
        assert_eq!(signed.payload(), scaffold.payload());
        let value = norito::json::from_slice_value(&json).expect("finalization JSON");
        assert_eq!(
            value
                .as_object()
                .and_then(|object| object.get("transaction_hash_hex"))
                .and_then(JsonValue::as_str),
            Some(hex::encode(signed.hash().as_ref()).as_str())
        );
    }
    #[test]
    fn finalizer_rejects_wrong_key_tampering_and_malformed_signature_without_outputs() {
        let keypair = fixture_keypair(0x37);
        let wrong = fixture_keypair(0x38);
        let scaffold = contract_scaffold(&keypair);
        let scaffold_bytes = scaffold.encode_versioned();
        let signing_hash = iroha_crypto::HashOf::new(scaffold.payload());
        let mut signature = Signature::try_new(keypair.private_key(), signing_hash.as_ref())
            .unwrap()
            .payload()
            .to_vec();
        let invoke = |public_key: &[u8], signature: &[u8]| {
            let mut signed_ptr = ptr::dangling_mut::<u8>();
            let mut signed_len = 99;
            let mut json_ptr = ptr::dangling_mut::<u8>();
            let mut json_len = 99;
            let status = unsafe {
                connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                    scaffold_bytes.as_ptr(),
                    scaffold_bytes.len() as c_ulong,
                    public_key.as_ptr(),
                    public_key.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                    &mut signed_ptr,
                    &mut signed_len,
                    &mut json_ptr,
                    &mut json_len,
                )
            };
            assert_ne!(status, 0);
            assert!(signed_ptr.is_null());
            assert_eq!(signed_len, 0);
            assert!(json_ptr.is_null());
            assert_eq!(json_len, 0);
        };
        invoke(wrong.public_key().to_bytes().1, &signature);
        signature[17] ^= 0x80;
        invoke(keypair.public_key().to_bytes().1, &signature);
        invoke(keypair.public_key().to_bytes().1, &[1; 63]);
        invoke(keypair.public_key().to_bytes().1, &[0; 64]);
    }
    #[test]
    fn atomic_batch_finalizer_rejects_wrong_key_tampering_and_malformed_signature_without_outputs()
    {
        let keypair = fixture_keypair(0x37);
        let wrong = fixture_keypair(0x38);
        let scaffold = atomic_transfer_batch_scaffold(&keypair);
        let scaffold_bytes = scaffold.encode_versioned();
        let signing_hash = iroha_crypto::HashOf::new(scaffold.payload());
        let mut signature = Signature::try_new(keypair.private_key(), signing_hash.as_ref())
            .unwrap()
            .payload()
            .to_vec();
        let invoke = |public_key: &[u8], signature: &[u8]| {
            let mut signed_ptr = ptr::dangling_mut::<u8>();
            let mut signed_len = 99;
            let mut json_ptr = ptr::dangling_mut::<u8>();
            let mut json_len = 99;
            let status = unsafe {
                connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                    scaffold_bytes.as_ptr(),
                    scaffold_bytes.len() as c_ulong,
                    public_key.as_ptr(),
                    public_key.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                    &mut signed_ptr,
                    &mut signed_len,
                    &mut json_ptr,
                    &mut json_len,
                )
            };
            assert_ne!(status, 0);
            assert!(signed_ptr.is_null());
            assert_eq!(signed_len, 0);
            assert!(json_ptr.is_null());
            assert_eq!(json_len, 0);
        };
        invoke(wrong.public_key().to_bytes().1, &signature);
        signature[17] ^= 0x80;
        invoke(keypair.public_key().to_bytes().1, &signature);
        invoke(keypair.public_key().to_bytes().1, &[1; 63]);
        invoke(keypair.public_key().to_bytes().1, &[0; 64]);
    }
    #[test]
    fn canonical_json_is_sorted_compact_and_permutation_invariant() {
        fn canonicalize(input: &[u8]) -> (Vec<u8>, [u8; 32]) {
            let mut out_ptr = ptr::null_mut();
            let mut out_len = 0;
            let mut hash = [0_u8; 32];
            let status = unsafe {
                connect_norito_canonical_json_blake3_v1(
                    input.as_ptr(),
                    input.len() as c_ulong,
                    &mut out_ptr,
                    &mut out_len,
                    hash.as_mut_ptr(),
                    hash.len() as c_ulong,
                )
            };
            assert_eq!(status, 0);
            let output = if out_ptr.is_null() {
                Vec::new()
            } else {
                unsafe { slice::from_raw_parts(out_ptr, out_len as usize) }.to_vec()
            };
            connect_norito_free(out_ptr);
            (output, hash)
        }
        let first = canonicalize(br#"{ "z": [3,2,1], "a": {"y":true,"x":null} }"#);
        let second = canonicalize(br#"{"a":{"x":null,"y":true},"z":[3,2,1]}"#);
        assert_eq!(first, second);
        assert_eq!(first.0, br#"{"a":{"x":null,"y":true},"z":[3,2,1]}"#);
        assert_eq!(first.1, *blake3_hash(&first.0).as_bytes());
        let empty = canonicalize(&[]);
        assert!(empty.0.is_empty());
        assert_eq!(empty.1, *blake3_hash(&[]).as_bytes());
    }
    #[test]
    fn canonical_json_rejects_duplicates_trailing_invalid_utf8_and_bad_hash_buffer() {
        for hostile in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"outer":{"a":1,"a":2}}"#.as_slice(),
            br#"{"a":1} true"#.as_slice(),
            br#"{"a":01}"#.as_slice(),
            br#"{"a":NaN}"#.as_slice(),
            br#"{"a":Infinity}"#.as_slice(),
            b"{\"a\":\"\x00\"}".as_slice(),
            &[0xFF, 0xFE][..],
        ] {
            let mut out_ptr = ptr::dangling_mut::<u8>();
            let mut out_len = 99;
            let mut hash = [0xA5_u8; 32];
            let status = unsafe {
                connect_norito_canonical_json_blake3_v1(
                    hostile.as_ptr(),
                    hostile.len() as c_ulong,
                    &mut out_ptr,
                    &mut out_len,
                    hash.as_mut_ptr(),
                    hash.len() as c_ulong,
                )
            };
            assert_eq!(status, ERR_CANONICAL_JSON);
            assert!(out_ptr.is_null());
            assert_eq!(out_len, 0);
            assert_eq!(hash, [0; 32]);
        }
        let mut out_ptr = ptr::null_mut();
        let mut out_len = 0;
        let mut short_hash = [0_u8; 31];
        let status = unsafe {
            connect_norito_canonical_json_blake3_v1(
                b"null".as_ptr(),
                4,
                &mut out_ptr,
                &mut out_len,
                short_hash.as_mut_ptr(),
                short_hash.len() as c_ulong,
            )
        };
        assert_eq!(status, ERR_HASH_OUT_LEN);
        assert!(out_ptr.is_null());
        assert_eq!(out_len, 0);
    }
    #[test]
    fn inspector_ffi_rejects_null_and_oversized_inputs_and_clears_outputs() {
        let tx = contract_scaffold(&fixture_keypair(0x39)).encode_versioned();
        for (input, length, expected_status) in [
            (ptr::null(), 0, ERR_DETACHED_TRANSACTION_SCAFFOLD),
            (tx.as_ptr(), c_ulong::MAX, ERR_DETACHED_TRANSACTION_SCAFFOLD),
        ] {
            let mut out_ptr = ptr::dangling_mut::<u8>();
            let mut out_len = 99;
            let status = unsafe {
                connect_norito_detached_transaction_scaffold_inspect_v1(
                    input,
                    length,
                    &mut out_ptr,
                    &mut out_len,
                )
            };
            assert_eq!(status, expected_status);
            assert!(out_ptr.is_null());
            assert_eq!(out_len, 0);
        }
        let mut out_len = 99;
        let status = unsafe {
            connect_norito_detached_transaction_scaffold_inspect_v1(
                tx.as_ptr(),
                tx.len() as c_ulong,
                ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(status, ERR_NULL_PTR);
        assert_eq!(out_len, 0);
    }
    #[test]
    fn finalizer_ffi_rejects_invalid_lengths_and_null_outputs_without_stale_state() {
        let keypair = fixture_keypair(0x3A);
        let scaffold = contract_scaffold(&keypair);
        let scaffold_bytes = scaffold.encode_versioned();
        let signing_hash = iroha_crypto::HashOf::new(scaffold.payload());
        let signature = Signature::try_new(keypair.private_key(), signing_hash.as_ref()).unwrap();
        let public_key = keypair.public_key().to_bytes().1;
        let invoke = |tx_len: c_ulong, public_key_len: c_ulong, signature_len: c_ulong| {
            let mut signed_ptr = ptr::dangling_mut::<u8>();
            let mut signed_len = 99;
            let mut json_ptr = ptr::dangling_mut::<u8>();
            let mut json_len = 99;
            let status = unsafe {
                connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                    scaffold_bytes.as_ptr(),
                    tx_len,
                    public_key.as_ptr(),
                    public_key_len,
                    signature.payload().as_ptr(),
                    signature_len,
                    &mut signed_ptr,
                    &mut signed_len,
                    &mut json_ptr,
                    &mut json_len,
                )
            };
            assert_ne!(status, 0);
            assert!(signed_ptr.is_null());
            assert_eq!(signed_len, 0);
            assert!(json_ptr.is_null());
            assert_eq!(json_len, 0);
            status
        };
        assert_eq!(
            invoke(c_ulong::MAX, public_key.len() as c_ulong, 64),
            ERR_DETACHED_TRANSACTION_SCAFFOLD
        );
        assert_eq!(
            invoke(scaffold_bytes.len() as c_ulong, 31, 64),
            ERR_DETACHED_TRANSACTION_SIGNATURE
        );
        assert_eq!(
            invoke(scaffold_bytes.len() as c_ulong, 32, 65),
            ERR_DETACHED_TRANSACTION_SIGNATURE
        );
        let mut signed_len = 99;
        let mut json_ptr = ptr::dangling_mut::<u8>();
        let mut json_len = 99;
        let status = unsafe {
            connect_norito_detached_transaction_scaffold_finalize_ed25519_v1(
                scaffold_bytes.as_ptr(),
                scaffold_bytes.len() as c_ulong,
                public_key.as_ptr(),
                public_key.len() as c_ulong,
                signature.payload().as_ptr(),
                signature.payload().len() as c_ulong,
                ptr::null_mut(),
                &mut signed_len,
                &mut json_ptr,
                &mut json_len,
            )
        };
        assert_eq!(status, ERR_NULL_PTR);
        assert_eq!(signed_len, 0);
        assert!(json_ptr.is_null());
        assert_eq!(json_len, 0);
    }
    #[test]
    fn canonical_json_ffi_rejects_null_and_oversized_inputs_without_hash_state() {
        for (input, length, expected_status) in [
            (ptr::null(), 1, ERR_NULL_PTR),
            (b"null".as_ptr(), c_ulong::MAX, ERR_CANONICAL_JSON),
        ] {
            let mut out_ptr = ptr::dangling_mut::<u8>();
            let mut out_len = 99;
            let mut hash = [0xA5_u8; 32];
            let status = unsafe {
                connect_norito_canonical_json_blake3_v1(
                    input,
                    length,
                    &mut out_ptr,
                    &mut out_len,
                    hash.as_mut_ptr(),
                    hash.len() as c_ulong,
                )
            };
            assert_eq!(status, expected_status);
            assert!(out_ptr.is_null());
            assert_eq!(out_len, 0);
            assert_eq!(hash, [0; 32]);
        }
    }
}
#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn iroha_privacy_free_buffer(ptr_: *mut c_uchar) {
    if !ptr_.is_null() {
        unsafe {
            let base = clear_privacy_allocated_buffer(ptr_);
            free(base as *mut _);
        }
    }
}
// ---------------- EnvelopeV1 encode helpers (selected variants) ----------------
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_sign_result_ok(
    seq: u64,
    sig_ptr: *const c_uchar,
    sig_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sig_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let sig_bytes = std::slice::from_raw_parts(sig_ptr, sig_len as usize);
        let signature = match proto::WalletSignatureV1::from_ed25519_bytes(sig_bytes) {
            Some(sig) => sig,
            None => return -2,
        };
        let env = proto::EnvelopeV1 {
            seq,
            payload: proto::ConnectPayloadV1::SignResultOk { signature },
        };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -3)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_sign_result_ok_with_alg(
    seq: u64,
    alg_ptr: *const c_char,
    alg_len: c_ulong,
    sig_ptr: *const c_uchar,
    sig_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if sig_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let algorithm = match parse_algorithm_cstr(alg_ptr, alg_len) {
            Ok(a) => a,
            Err(code) => return code,
        };
        let sig_bytes = std::slice::from_raw_parts(sig_ptr, sig_len as usize);
        let signature = match connect_wallet_signature_from_algorithm_bytes(algorithm, sig_bytes) {
            Some(signature) => signature,
            None => return -2,
        };
        let env = proto::EnvelopeV1 {
            seq,
            payload: proto::ConnectPayloadV1::SignResultOk { signature },
        };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -3)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_control_close(
    seq: u64,
    who: c_uchar, // 0=App,1=Wallet
    code: u16,
    reason_ptr: *const c_uchar,
    reason_len: c_ulong,
    retryable: c_uchar, // 0/1
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if reason_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let reason =
            String::from_utf8(std::slice::from_raw_parts(reason_ptr, reason_len as usize).to_vec())
                .map_err(|_| ())
                .unwrap_or_default();
        let who = match who {
            0 => proto::Role::App,
            1 => proto::Role::Wallet,
            _ => return -2,
        };
        let payload = proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Close {
            who,
            code,
            reason,
            retryable: retryable != 0,
        });
        let env = proto::EnvelopeV1 { seq, payload };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -4)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_control_reject(
    seq: u64,
    code: u16,
    code_id_ptr: *const c_uchar,
    code_id_len: c_ulong,
    reason_ptr: *const c_uchar,
    reason_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if code_id_ptr.is_null() || reason_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let code_id = String::from_utf8(
            std::slice::from_raw_parts(code_id_ptr, code_id_len as usize).to_vec(),
        )
        .map_err(|_| ())
        .unwrap_or_default();
        let reason =
            String::from_utf8(std::slice::from_raw_parts(reason_ptr, reason_len as usize).to_vec())
                .map_err(|_| ())
                .unwrap_or_default();
        let payload = proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Reject {
            code,
            code_id,
            reason,
        });
        let env = proto::EnvelopeV1 { seq, payload };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -3)
    }
}
// ---------------- EnvelopeV1 decode helpers (selected variants) ----------------
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_envelope_kind(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_seq: *mut u64,
    out_kind: *mut u16,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_seq.is_null() || out_kind.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let env = match decode_envelope(inp) {
            Ok(e) => e,
            Err(_) => return -2,
        };
        *out_seq = env.seq;
        let kind = match env.payload {
            proto::ConnectPayloadV1::SignRequestTx { .. } => 1,
            proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Close { .. }) => 2,
            proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Reject { .. }) => 3,
            proto::ConnectPayloadV1::SignResultOk { .. } => 4,
            proto::ConnectPayloadV1::SignRequestRaw { .. } => 5,
            proto::ConnectPayloadV1::SignResultErr { .. } => 6,
            proto::ConnectPayloadV1::DisplayRequest { .. } => 7,
        };
        *out_kind = kind;
        0
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_envelope_json(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let env = match decode_envelope(inp) {
            Ok(e) => e,
            Err(_) => return -2,
        };
        let payload_json = match env.payload {
            proto::ConnectPayloadV1::SignRequestTx { tx_bytes } => {
                let s = b64_encode(&tx_bytes);
                json_object([(
                    "SignRequestTx",
                    json_object([("tx_bytes_b64", ::norito::json!(s))]),
                )])
            }
            proto::ConnectPayloadV1::SignRequestRaw { domain_tag, bytes } => {
                let s = b64_encode(&bytes);
                json_object([(
                    "SignRequestRaw",
                    json_object([
                        ("domain_tag", ::norito::json!(domain_tag)),
                        ("bytes_b64", ::norito::json!(s)),
                    ]),
                )])
            }
            proto::ConnectPayloadV1::SignResultOk { signature } => {
                let alg = signature.algorithm.as_static_str();
                let s = b64_encode(signature.bytes());
                json_object([(
                    "SignResultOk",
                    json_object([
                        ("algorithm", ::norito::json!(alg)),
                        ("signature_b64", ::norito::json!(s)),
                    ]),
                )])
            }
            proto::ConnectPayloadV1::SignResultErr { code, message } => json_object([(
                "SignResultErr",
                json_object([
                    ("code", ::norito::json!(code)),
                    ("message", ::norito::json!(message.clone())),
                ]),
            )]),
            proto::ConnectPayloadV1::DisplayRequest { title, body } => json_object([(
                "DisplayRequest",
                json_object([
                    ("title", ::norito::json!(title.clone())),
                    ("body", ::norito::json!(body.clone())),
                ]),
            )]),
            proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Close {
                who,
                code,
                reason,
                retryable,
            }) => {
                let who_label = match who {
                    proto::Role::App => "App",
                    proto::Role::Wallet => "Wallet",
                };
                json_object([(
                    "Control",
                    json_object([(
                        "Close",
                        json_object([
                            ("who", ::norito::json!(who_label)),
                            ("code", ::norito::json!(code)),
                            ("reason", ::norito::json!(reason.clone())),
                            ("retryable", ::norito::json!(retryable)),
                        ]),
                    )]),
                )])
            }
            proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Reject {
                code,
                code_id,
                reason,
            }) => json_object([(
                "Control",
                json_object([(
                    "Reject",
                    json_object([
                        ("code", ::norito::json!(code)),
                        ("code_id", ::norito::json!(code_id)),
                        ("reason", ::norito::json!(reason.clone())),
                    ]),
                )]),
            )]),
        };
        let obj = json_object([("seq", ::norito::json!(env.seq)), ("payload", payload_json)]);
        write_output_result(norito::json::to_vec(&obj), out_ptr, out_len, -3, -4)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_envelope_sign_result_alg(
    inp_ptr: *const c_uchar,
    inp_len: c_ulong,
    out_alg_ptr: *mut *mut c_char,
    out_alg_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if inp_ptr.is_null() || out_alg_ptr.is_null() || out_alg_len.is_null() {
            return -1;
        }
        let inp = std::slice::from_raw_parts(inp_ptr, inp_len as usize);
        let env = match decode_envelope(inp) {
            Ok(e) => e,
            Err(_) => return -2,
        };
        let alg_str = match env.payload {
            proto::ConnectPayloadV1::SignResultOk { signature } => {
                signature.algorithm.as_static_str()
            }
            _ => return -3,
        };
        write_bytes(
            out_alg_ptr.cast::<*mut c_uchar>(),
            out_alg_len,
            alg_str.as_bytes(),
        )
        .map_or(-4, |()| 0)
    }
}
// Additional envelope encoders for parity
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_sign_request_tx(
    seq: u64,
    tx_ptr: *const c_uchar,
    tx_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if tx_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let tx = std::slice::from_raw_parts(tx_ptr, tx_len as usize).to_vec();
        let env = proto::EnvelopeV1 {
            seq,
            payload: proto::ConnectPayloadV1::SignRequestTx { tx_bytes: tx },
        };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -3)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_sign_request_raw(
    seq: u64,
    tag_ptr: *const c_uchar,
    tag_len: c_ulong,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if tag_ptr.is_null() || bytes_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let domain_tag =
            String::from_utf8(std::slice::from_raw_parts(tag_ptr, tag_len as usize).to_vec())
                .map_err(|_| ())
                .unwrap_or_default();
        let bytes = std::slice::from_raw_parts(bytes_ptr, bytes_len as usize).to_vec();
        let env = proto::EnvelopeV1 {
            seq,
            payload: proto::ConnectPayloadV1::SignRequestRaw { domain_tag, bytes },
        };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -3)
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_envelope_sign_result_err(
    seq: u64,
    code_ptr: *const c_uchar,
    code_len: c_ulong,
    msg_ptr: *const c_uchar,
    msg_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if code_ptr.is_null() || msg_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let code =
            String::from_utf8(std::slice::from_raw_parts(code_ptr, code_len as usize).to_vec())
                .map_err(|_| ())
                .unwrap_or_default();
        let message =
            String::from_utf8(std::slice::from_raw_parts(msg_ptr, msg_len as usize).to_vec())
                .map_err(|_| ())
                .unwrap_or_default();
        let env = proto::EnvelopeV1 {
            seq,
            payload: proto::ConnectPayloadV1::SignResultErr { code, message },
        };
        write_encoded_result(encode_envelope_framed(&env), out_ptr, out_len, -3)
    }
}
fn account_read_permission_multisig_builder(
    network_id: NetworkId,
    authority: AccountId,
    reporting: AccountId,
    change: u8,
    creation_time_ms: u64,
    fee_payment: FeePaymentIntent,
) -> BridgeResult<TransactionBuilder> {
    if creation_time_ms == 0 || reporting == authority {
        return Err(BridgeError::Authority);
    }
    let policy = authority.multisig_policy().ok_or(BridgeError::Authority)?;
    if policy.threshold() != 1 || policy.members().len() != 1 {
        return Err(BridgeError::Authority);
    }
    if fee_payment.charge_limits().is_empty() {
        return Err(BridgeError::FeePayment);
    }
    let permission = CanReadAccountData {
        account: authority.clone(),
    };
    let instruction = match change {
        1 => InstructionBox::from(Grant::account_permission(permission, reporting)),
        2 => InstructionBox::from(Revoke::account_permission(permission, reporting)),
        _ => return Err(BridgeError::Authority),
    };
    let mut builder = TransactionBuilder::new(network_id, authority, fee_payment)
        .with_instructions([instruction]);
    builder.set_creation_time(Duration::from_millis(creation_time_ms));
    builder.set_ttl(Duration::from_millis(120_000));
    Ok(builder)
}
#[expect(
    clippy::too_many_arguments,
    reason = "Projects the exact C ABI pointer/length pairs into native owners."
)]
unsafe fn account_read_permission_multisig_builder_from_c(
    network_id_ptr: *const c_char,
    network_id_len: c_ulong,
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    reporting_account_ptr: *const c_char,
    reporting_account_len: c_ulong,
    change: c_uchar,
    creation_time_ms: u64,
    fee_payment_json_ptr: *const c_uchar,
    fee_payment_json_len: c_ulong,
) -> BridgeResult<TransactionBuilder> {
    let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
    let authority = parse_account_id(unsafe { read_string_bridge(authority_ptr, authority_len) }?)?;
    let reporting = parse_account_id(unsafe {
        read_string_bridge(reporting_account_ptr, reporting_account_len)
    }?)?;
    let fee_payment =
        unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len) }?;
    account_read_permission_multisig_builder(
        network_id,
        authority,
        reporting,
        change,
        creation_time_ms,
        fee_payment,
    )
}
/// Prepare the exact payload prehash for a wallet-controlled 1-of-1 multisig
/// permission change. The application must independently authenticate the
/// reporter identity before passing it here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_account_read_permission_multisig_payload_hash(
    network_id_ptr: *const c_char,
    network_id_len: c_ulong,
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    reporting_account_ptr: *const c_char,
    reporting_account_len: c_ulong,
    change: c_uchar,
    creation_time_ms: u64,
    fee_payment_json_ptr: *const c_uchar,
    fee_payment_json_len: c_ulong,
    out_hash_ptr: *mut c_uchar,
    out_hash_len: c_ulong,
) -> c_int {
    if !out_hash_ptr.is_null() {
        let clear_len = usize::try_from(out_hash_len)
            .unwrap_or(usize::MAX)
            .min(Hash::LENGTH);
        unsafe { ptr::write_bytes(out_hash_ptr, 0, clear_len) };
    }
    let result = (|| {
        let builder = unsafe {
            account_read_permission_multisig_builder_from_c(
                network_id_ptr,
                network_id_len,
                authority_ptr,
                authority_len,
                reporting_account_ptr,
                reporting_account_len,
                change,
                creation_time_ms,
                fee_payment_json_ptr,
                fee_payment_json_len,
            )
        }?;
        write_hash(out_hash_ptr, out_hash_len, &builder.payload_hash_bytes())
    })();
    bridge_result_to_code(result)
}
/// Finalize one exact wallet permission change from an external Ed25519
/// signature over the prehash above. The signer key comes solely from the
/// authority's encoded one-member policy; verification is mandatory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_account_read_permission_multisig_finalize(
    network_id_ptr: *const c_char,
    network_id_len: c_ulong,
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    reporting_account_ptr: *const c_char,
    reporting_account_len: c_ulong,
    change: c_uchar,
    creation_time_ms: u64,
    fee_payment_json_ptr: *const c_uchar,
    fee_payment_json_len: c_ulong,
    signature_ptr: *const c_uchar,
    signature_len: c_ulong,
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
    out_hash_ptr: *mut c_uchar,
    out_hash_len: c_ulong,
) -> c_int {
    clear_signed_transaction_outputs(out_signed_ptr, out_signed_len, out_hash_ptr, out_hash_len);
    let result = (|| {
        if out_signed_ptr.is_null() || out_signed_len.is_null() || signature_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        if signature_len != 64 {
            return Err(BridgeError::TransactionSign);
        }
        let builder = unsafe {
            account_read_permission_multisig_builder_from_c(
                network_id_ptr,
                network_id_len,
                authority_ptr,
                authority_len,
                reporting_account_ptr,
                reporting_account_len,
                change,
                creation_time_ms,
                fee_payment_json_ptr,
                fee_payment_json_len,
            )
        }?;
        let signer = builder
            .payload()
            .authority
            .multisig_policy()
            .ok_or(BridgeError::Authority)?
            .members()[0]
            .public_key()
            .clone();
        if signer.algorithm() != Algorithm::Ed25519 {
            return Err(BridgeError::UnsupportedAlgorithm);
        }
        let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, 64) };
        let signature = Signature::from_bytes(signature_bytes);
        let multisig_signatures = MultisigSignatures::new(vec![MultisigSignature::new(
            signer,
            SignatureOf::from_signature(signature.clone()),
        )]);
        let signed = builder
            .with_multisig_signatures(multisig_signatures)
            .build_with_signature(signature);
        signed
            .verify_signature()
            .map_err(|_| BridgeError::TransactionSign)?;
        let signed_bytes = signed.encode_versioned();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(signed.hash().as_ref());
        write_hash(out_hash_ptr, out_hash_len, &hash)?;
        unsafe { write_bytes_bridge(out_signed_ptr, out_signed_len, &signed_bytes) }
    })();
    bridge_result_to_code(result)
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_account_read_permission_multisig_signed_transaction =>
        connect_norito_encode_account_read_permission_multisig_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            reporting_account_ptr: *const c_char,
            reporting_account_len: c_ulong,
            change: c_uchar,
            creation_time_ms: u64,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    clear_outputs: clear_signed_transaction_outputs;
    {
        if private_key_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        if algorithm != Algorithm::Ed25519 {
            return Err(BridgeError::UnsupportedAlgorithm);
        }
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority =
            parse_account_id(unsafe { read_string_bridge(authority_ptr, authority_len) }?)?;
        let reporting = parse_account_id(unsafe {
            read_string_bridge(reporting_account_ptr, reporting_account_len)
        }?)?;
        let private_key_len =
            usize::try_from(private_key_len).map_err(|_| BridgeError::PrivateKey)?;
        if private_key_len != 32 && private_key_len != 64 {
            return Err(BridgeError::PrivateKey);
        }
        let private_key_bytes = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len) };
        let private_key = parse_private_key_with_algorithm(private_key_bytes, algorithm)?;
        let fee_payment = unsafe {
            parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)
        }?;
        let builder = account_read_permission_multisig_builder(
            network_id,
            authority,
            reporting,
            change,
            creation_time_ms,
            fee_payment,
        )?;
        let policy = builder.payload().authority.multisig_policy().ok_or(BridgeError::Authority)?;
        if policy.members()[0].public_key() != &PublicKey::from(private_key.clone()) {
            return Err(BridgeError::Authority);
        }
        let signed = builder
            .try_sign_multisig([&private_key])
            .map_err(|_| BridgeError::TransactionSign)?;
        let signed_bytes = signed.encode_versioned();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(signed.hash().as_ref());
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_transfer_signed_transaction =>
        connect_norito_encode_transfer_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            nonce: u32,
            nonce_present: c_uchar,
            asset_definition_ptr: *const c_char,
            asset_definition_len: c_ulong,
            quantity_ptr: *const c_char,
            quantity_len: c_ulong,
            destination_ptr: *const c_char,
            destination_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let inputs = unsafe {
            gather_asset_tx_inputs_with_parser(
                AssetInputPointers {
                    network_id_ptr,
                    network_id_len,
                    authority_ptr,
                    authority_len,
                    asset_definition_ptr,
                    asset_definition_len,
                    quantity_ptr,
                    quantity_len,
                    destination_ptr,
                    destination_len,
                    ttl_ms,
                    ttl_present,
                    private_key_ptr,
                    private_key_len,
                },
                |bytes| parse_private_key_with_algorithm(bytes, algorithm),
            )?
        };
        let AssetTxInputs {
            network_id,
            authority,
            asset_definition,
            asset_scope,
            destination,
            quantity,
            ttl,
            private_key,
        } = inputs;
        let nonce = parse_nonce(nonce, nonce_present != 0)?;
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let asset_id =
            AssetId::with_scope(asset_definition.clone(), authority.clone(), asset_scope);
        let (signed_bytes, hash_bytes) =
            encode_asset_transaction_with_nonce_fee_payment_and_metadata(
                network_id,
                authority,
                creation_time_ms,
                ttl,
                nonce,
                fee_payment,
                Metadata::default(),
                private_key,
                || {
                    let transfer = Transfer::asset_quantity(asset_id, quantity, destination);
                    Executable::from([InstructionBox::from(transfer)])
                },
            )?;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_transfer_instruction_box(
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    asset_definition_ptr: *const c_char,
    asset_definition_len: c_ulong,
    quantity_ptr: *const c_char,
    quantity_len: c_ulong,
    destination_ptr: *const c_char,
    destination_len: c_ulong,
    out_instruction_ptr: *mut *mut c_uchar,
    out_instruction_len: *mut c_ulong,
) -> c_int {
    let result = (|| {
        if out_instruction_ptr.is_null() || out_instruction_len.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let authority =
            parse_account_id(unsafe { read_string_bridge(authority_ptr, authority_len) }?)?;
        let asset_definition =
            unsafe { read_string_bridge(asset_definition_ptr, asset_definition_len) }?;
        let quantity =
            parse_public_quantity(unsafe { read_string_bridge(quantity_ptr, quantity_len) }?)?;
        let destination =
            parse_destination(unsafe { read_string_bridge(destination_ptr, destination_len) }?)?;
        let (asset_definition, asset_scope) =
            parse_asset_definition_with_balance_scope(asset_definition)?;
        let asset_id = AssetId::with_scope(asset_definition, authority, asset_scope);
        let instruction =
            InstructionBox::from(Transfer::asset_quantity(asset_id, quantity, destination));
        let instruction_bytes =
            norito::core::to_bytes(&instruction).map_err(|_| BridgeError::JsonSerialize)?;
        unsafe {
            write_bytes_bridge(out_instruction_ptr, out_instruction_len, &instruction_bytes)
        }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_transfer_instruction_frame_v1(
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    asset_definition_ptr: *const c_char,
    asset_definition_len: c_ulong,
    quantity_ptr: *const c_char,
    quantity_len: c_ulong,
    destination_ptr: *const c_char,
    destination_len: c_ulong,
    out_instruction_ptr: *mut *mut c_uchar,
    out_instruction_len: *mut c_ulong,
) -> c_int {
    let result = (|| {
        clear_bridge_output_or_null(out_instruction_ptr, out_instruction_len)?;
        let authority =
            parse_account_id(unsafe { read_string_bridge(authority_ptr, authority_len) }?)?;
        let asset_definition =
            unsafe { read_string_bridge(asset_definition_ptr, asset_definition_len) }?;
        let quantity =
            parse_public_quantity(unsafe { read_string_bridge(quantity_ptr, quantity_len) }?)?;
        let destination =
            parse_destination(unsafe { read_string_bridge(destination_ptr, destination_len) }?)?;
        let (asset_definition, asset_scope) =
            parse_asset_definition_with_balance_scope(asset_definition)?;
        let asset_id = AssetId::with_scope(asset_definition, authority, asset_scope);
        let instruction =
            InstructionBox::from(Transfer::asset_quantity(asset_id, quantity, destination));
        let (wire_name, frame) =
            framed_instruction_payload(&instruction).ok_or(BridgeError::JsonSerialize)?;
        let value = JsonValue::Object(JsonMap::from_iter([
            (
                "schema".into(),
                JsonValue::from("iroha.transfer_instruction_frame.v1"),
            ),
            ("wire_name".into(), JsonValue::from(wire_name)),
            (
                "framed_payload_b64".into(),
                JsonValue::from(b64_encode(&frame)),
            ),
        ]));
        let instruction_bytes =
            norito::json::to_vec(&value).map_err(|_| BridgeError::JsonSerialize)?;
        unsafe {
            write_bytes_bridge(out_instruction_ptr, out_instruction_len, &instruction_bytes)
        }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_register_zk_asset_signed_transaction =>
        connect_norito_encode_register_zk_asset_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            asset_definition_ptr: *const c_char,
            asset_definition_len: c_ulong,
            vk_unshield_ptr: *const c_char,
            vk_unshield_len: c_ulong,
            vk_unshield_present: c_uchar,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        if private_key_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let asset_definition_str =
            unsafe { read_string_bridge(asset_definition_ptr, asset_definition_len) }?;
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let asset_definition = parse_asset_definition(asset_definition_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let vk_unshield = unsafe {
            parse_optional_verifying_key_id(vk_unshield_ptr, vk_unshield_len, vk_unshield_present)
        }?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let register = zk::RegisterZkAsset::new(asset_definition, vk_unshield);
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_asset_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            {
                let register = register.clone();
                move || Executable::from([InstructionBox::from(register.clone())])
            },
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_set_key_value_signed_transaction =>
        connect_norito_encode_set_key_value_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            target_kind: u8,
            object_ptr: *const c_char,
            object_len: c_ulong,
            key_ptr: *const c_char,
            key_len: c_ulong,
            value_ptr: *const c_uchar,
            value_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        if private_key_ptr.is_null() || value_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let object_str = unsafe { read_string_bridge(object_ptr, object_len) }?;
        let key_str = unsafe { read_string_bridge(key_ptr, key_len) }?;
        let value_slice = unsafe { slice::from_raw_parts(value_ptr, value_len as usize) };
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let target = parse_metadata_target(target_kind, object_str)?;
        let key = parse_name(key_str)?;
        let value = parse_json_value(value_slice)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let instruction = build_set_metadata_instruction(target, key, value);
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            instruction,
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_remove_key_value_signed_transaction =>
        connect_norito_encode_remove_key_value_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            target_kind: u8,
            object_ptr: *const c_char,
            object_len: c_ulong,
            key_ptr: *const c_char,
            key_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        if private_key_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let object_str = unsafe { read_string_bridge(object_ptr, object_len) }?;
        let key_str = unsafe { read_string_bridge(key_ptr, key_len) }?;
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let target = parse_metadata_target(target_kind, object_str)?;
        let key = parse_name(key_str)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let instruction = build_remove_metadata_instruction(target, key);
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            instruction,
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_governance_propose_deploy_v1_signed_transaction =>
        connect_norito_encode_governance_propose_deploy_v1_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            contract_address_ptr: *const c_char,
            contract_address_len: c_ulong,
            code_hash_ptr: *const c_uchar,
            code_hash_len: c_ulong,
            abi_hash_ptr: *const c_uchar,
            abi_hash_len: c_ulong,
            abi_version: u16,
            provenance_signer_ptr: *const c_char,
            provenance_signer_len: c_ulong,
            provenance_signature_ptr: *const c_char,
            provenance_signature_len: c_ulong,
            provenance_present: c_uchar,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        if private_key_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let contract_address_raw =
            unsafe { read_string_bridge(contract_address_ptr, contract_address_len) }?;
        let code_hash = ContractCodeHash::new(unsafe {
            read_governance_hash32_bridge(code_hash_ptr, code_hash_len)?
        });
        let abi_hash = ContractAbiHash::new(unsafe {
            read_governance_hash32_bridge(abi_hash_ptr, abi_hash_len)?
        });
        if abi_version != 1 {
            return Err(BridgeError::Governance);
        }
        let abi_version = AbiVersion::new(abi_version);
        let manifest_provenance = unsafe {
            read_manifest_provenance_bridge(
                provenance_signer_ptr,
                provenance_signer_len,
                provenance_signature_ptr,
                provenance_signature_len,
                provenance_present,
            )?
        };
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let contract_address = contract_address_raw
            .parse()
            .map_err(|_| BridgeError::Governance)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let proposal = ProposeDeployContract {
            contract_address,
            code_hash,
            abi_hash,
            abi_version,
            manifest_provenance,
        };
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            InstructionBox::from(proposal),
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_governance_cast_plain_ballot_signed_transaction =>
        connect_norito_encode_governance_cast_plain_ballot_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            referendum_id_ptr: *const c_char,
            referendum_id_len: c_ulong,
            owner_ptr: *const c_char,
            owner_len: c_ulong,
            amount_ptr: *const c_char,
            amount_len: c_ulong,
            duration_blocks: u64,
            direction: u8,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    clear_outputs: clear_signed_transaction_outputs;
    {
        if private_key_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        if direction > 2 {
            return Err(BridgeError::Governance);
        }
        let referendum_id =
            unsafe { read_governance_selector_bridge(referendum_id_ptr, referendum_id_len) }?;
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let owner_str = unsafe { read_string_bridge(owner_ptr, owner_len) }?;
        let amount_str = unsafe { read_string_bridge(amount_ptr, amount_len) }?;
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let owner = parse_account_id(owner_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let amount = parse_public_quantity(amount_str)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let ballot = CastPlainBallot {
            referendum_id,
            owner,
            amount,
            duration_blocks,
            direction,
        };
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            InstructionBox::from(ballot),
        )?;
    }
}
/// Encode one choice-preserving public conviction update with its exact V1 fields.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg(
    network_id_ptr: *const c_char,
    network_id_len: c_ulong,
    authority_ptr: *const c_char,
    authority_len: c_ulong,
    creation_time_ms: u64,
    ttl_ms: u64,
    ttl_present: c_uchar,
    referendum_id_ptr: *const c_char,
    referendum_id_len: c_ulong,
    owner_ptr: *const c_char,
    owner_len: c_ulong,
    amount_ptr: *const c_char,
    amount_len: c_ulong,
    duration_blocks: u64,
    fee_payment_json_ptr: *const c_uchar,
    fee_payment_json_len: c_ulong,
    private_key_ptr: *const c_uchar,
    private_key_len: c_ulong,
    algorithm_code: u8,
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
    out_hash_ptr: *mut c_uchar,
    out_hash_len: c_ulong,
) -> c_int {
    clear_signed_transaction_outputs(out_signed_ptr, out_signed_len, out_hash_ptr, out_hash_len);
    let result = (|| {
        if out_signed_ptr.is_null()
            || out_signed_len.is_null()
            || out_hash_ptr.is_null()
            || private_key_ptr.is_null()
        {
            return Err(BridgeError::NullPtr);
        }
        let referendum_id =
            unsafe { read_governance_selector_bridge(referendum_id_ptr, referendum_id_len) }?;
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let owner_str = unsafe { read_string_bridge(owner_ptr, owner_len) }?;
        let amount_str = unsafe { read_string_bridge(amount_ptr, amount_len) }?;
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let owner = parse_account_id(owner_str)?;
        if owner != authority {
            return Err(BridgeError::Governance);
        }
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let amount = parse_public_quantity(amount_str)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let update = UpdatePlainConviction {
            referendum_id,
            owner,
            amount,
            duration_blocks,
        };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            InstructionBox::from(update),
        )?;
        write_hash(out_hash_ptr, out_hash_len, &hash_bytes)?;
        unsafe { write_bytes_bridge(out_signed_ptr, out_signed_len, &signed_bytes) }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_governance_cast_zk_ballot_signed_transaction =>
        connect_norito_encode_governance_cast_zk_ballot_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            election_id_ptr: *const c_char,
            election_id_len: c_ulong,
            proof_b64_ptr: *const c_char,
            proof_b64_len: c_ulong,
            public_inputs_ptr: *const c_uchar,
            public_inputs_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    clear_outputs: clear_signed_transaction_outputs;
    {
        if private_key_ptr.is_null() || public_inputs_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let election_id =
            unsafe { read_governance_selector_bridge(election_id_ptr, election_id_len) }?;
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let proof_raw = unsafe { read_string_bridge(proof_b64_ptr, proof_b64_len) }?;
        let inputs_slice =
            unsafe { slice::from_raw_parts(public_inputs_ptr, public_inputs_len as usize) };
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let proof_bytes = b64gp::STANDARD
            .decode(proof_raw)
            .map_err(|_| BridgeError::Governance)?;
        let proof_b64 = b64gp::STANDARD.encode(proof_bytes);
        let mut public_inputs_value: norito::json::Value =
            norito::json::from_slice(inputs_slice).map_err(|_| BridgeError::Governance)?;
        normalize_zk_ballot_public_inputs(&mut public_inputs_value)?;
        let public_inputs_json =
            norito::json::to_string(&public_inputs_value).map_err(|_| BridgeError::Governance)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let ballot = CastZkBallot {
            election_id,
            proof_b64,
            public_inputs_json,
        };
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            InstructionBox::from(ballot),
        )?;
    }
}
const SECP256K1_PRIVATE_LEN: usize = 32;
const SECP256K1_PUBLIC_LEN: usize = 33;
const SECP256K1_SIGNATURE_LEN: usize = 64;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_secp256k1_public_key(
    private_ptr: *const c_uchar,
    private_len: c_ulong,
    out_public_ptr: *mut c_uchar,
    out_public_len: c_ulong,
) -> c_int {
    if private_ptr.is_null() || out_public_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if private_len != SECP256K1_PRIVATE_LEN as c_ulong {
        return ERR_SECP_PARSE;
    }
    let private_bytes = unsafe { slice::from_raw_parts(private_ptr, private_len as usize) };
    let private_key = match EcdsaSecp256k1Sha256::parse_private_key(private_bytes) {
        Ok(key) => key,
        Err(_) => return ERR_SECP_PARSE,
    };
    let encoded = private_key.public_key().to_sec1_bytes();
    let encoded_bytes = encoded.as_ref();
    if encoded_bytes.len() != SECP256K1_PUBLIC_LEN
        || out_public_len < encoded_bytes.len() as c_ulong
    {
        return ERR_BUFFER_TOO_SMALL;
    }
    unsafe {
        ptr::copy_nonoverlapping(encoded_bytes.as_ptr(), out_public_ptr, encoded_bytes.len());
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_secp256k1_sign(
    private_ptr: *const c_uchar,
    private_len: c_ulong,
    message_ptr: *const c_uchar,
    message_len: c_ulong,
    out_signature_ptr: *mut c_uchar,
    out_signature_len: c_ulong,
) -> c_int {
    if private_ptr.is_null() || message_ptr.is_null() || out_signature_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if private_len != SECP256K1_PRIVATE_LEN as c_ulong {
        return ERR_SECP_PARSE;
    }
    let private_bytes = unsafe { slice::from_raw_parts(private_ptr, private_len as usize) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len as usize) };
    let private_key = match EcdsaSecp256k1Sha256::parse_private_key(private_bytes) {
        Ok(key) => key,
        Err(_) => return ERR_SECP_PARSE,
    };
    let signature = match EcdsaSecp256k1Sha256::try_sign(message, &private_key) {
        Ok(signature) => signature,
        Err(_) => return ERR_SECP_SIGN,
    };
    if signature.len() != SECP256K1_SIGNATURE_LEN {
        return ERR_SECP_SIGN;
    }
    if out_signature_len < signature.len() as c_ulong {
        return ERR_BUFFER_TOO_SMALL;
    }
    unsafe {
        ptr::copy_nonoverlapping(
            signature.as_ptr(),
            out_signature_ptr,
            SECP256K1_SIGNATURE_LEN,
        );
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_secp256k1_verify(
    public_ptr: *const c_uchar,
    public_len: c_ulong,
    message_ptr: *const c_uchar,
    message_len: c_ulong,
    signature_ptr: *const c_uchar,
    signature_len: c_ulong,
) -> c_int {
    if public_ptr.is_null() || message_ptr.is_null() || signature_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if public_len != SECP256K1_PUBLIC_LEN as c_ulong
        || signature_len != SECP256K1_SIGNATURE_LEN as c_ulong
    {
        return ERR_SECP_PARSE;
    }
    let public_bytes = unsafe { slice::from_raw_parts(public_ptr, public_len as usize) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len as usize) };
    let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };
    let public_key = match EcdsaSecp256k1Sha256::parse_public_key(public_bytes) {
        Ok(pk) => pk,
        Err(_) => return ERR_SECP_PARSE,
    };
    match EcdsaSecp256k1Sha256::verify(message, signature_bytes, &public_key) {
        Ok(()) => 1,
        Err(CryptoError::BadSignature) => 0,
        Err(_) => ERR_SECP_VERIFY,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_default_distid(
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    let distid = Sm2PublicKey::default_distid();
    match unsafe { write_bytes(out_ptr, out_len, distid.as_bytes()) } {
        Ok(()) => 0,
        Err(code) => code,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_keypair_from_seed(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
    seed_ptr: *const c_uchar,
    seed_len: c_ulong,
    out_private_ptr: *mut c_uchar,
    out_private_len: c_ulong,
    out_public_ptr: *mut c_uchar,
    out_public_len: c_ulong,
) -> c_int {
    if seed_ptr.is_null() || out_private_ptr.is_null() || out_public_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if out_private_len < 32 || out_public_len < 65 {
        return ERR_BUFFER_TOO_SMALL;
    }
    let distid = match unsafe { read_distid_or_default(distid_ptr, distid_len) } {
        Ok(d) => d,
        Err(err) => return err.code(),
    };
    let seed = unsafe { slice::from_raw_parts(seed_ptr, seed_len as usize) };
    let key = match Sm2PrivateKey::from_seed(distid, seed) {
        Ok(k) => k,
        Err(_) => return ERR_SM2_DERIVE,
    };
    let private_bytes = Zeroizing::new(key.secret_bytes());
    let private_bytes_slice: &[u8] = private_bytes.as_ref();
    let public_bytes = key.public_key().to_sec1_bytes(false);
    unsafe {
        ptr::copy_nonoverlapping(
            private_bytes_slice.as_ptr(),
            out_private_ptr,
            private_bytes_slice.len(),
        );
        ptr::copy_nonoverlapping(public_bytes.as_ptr(), out_public_ptr, public_bytes.len());
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_sign(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
    private_ptr: *const c_uchar,
    private_len: c_ulong,
    message_ptr: *const c_uchar,
    message_len: c_ulong,
    out_signature_ptr: *mut c_uchar,
    out_signature_len: c_ulong,
) -> c_int {
    if private_ptr.is_null() || message_ptr.is_null() || out_signature_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if private_len != 32 || out_signature_len < Sm2Signature::LENGTH as c_ulong {
        return ERR_SM2_PARSE;
    }
    let distid = match unsafe { read_distid_or_default(distid_ptr, distid_len) } {
        Ok(d) => d,
        Err(err) => return err.code(),
    };
    let private_bytes = unsafe { slice::from_raw_parts(private_ptr, private_len as usize) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len as usize) };
    let key = match Sm2PrivateKey::from_bytes(distid, private_bytes) {
        Ok(k) => k,
        Err(_) => return ERR_SM2_PARSE,
    };
    let signature = match key.try_sign(message) {
        Ok(signature) => signature,
        Err(_) => return ERR_SM2_SIGN,
    };
    let sig_bytes = signature.to_bytes();
    unsafe {
        ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_signature_ptr, Sm2Signature::LENGTH);
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_verify(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
    public_ptr: *const c_uchar,
    public_len: c_ulong,
    message_ptr: *const c_uchar,
    message_len: c_ulong,
    signature_ptr: *const c_uchar,
    signature_len: c_ulong,
) -> c_int {
    if public_ptr.is_null() || message_ptr.is_null() || signature_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if public_len != 65 || signature_len != Sm2Signature::LENGTH as c_ulong {
        return ERR_SM2_PARSE;
    }
    let distid = match unsafe { read_distid_or_default(distid_ptr, distid_len) } {
        Ok(d) => d,
        Err(err) => return err.code(),
    };
    let public_bytes = unsafe { slice::from_raw_parts(public_ptr, public_len as usize) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len as usize) };
    let signature_bytes = unsafe { slice::from_raw_parts(signature_ptr, signature_len as usize) };
    let public = match Sm2PublicKey::from_sec1_bytes(&distid, public_bytes) {
        Ok(pk) => pk,
        Err(_) => return ERR_SM2_PARSE,
    };
    let mut sig_raw = [0u8; Sm2Signature::LENGTH];
    sig_raw.copy_from_slice(signature_bytes);
    let signature = match Sm2Signature::from_bytes(&sig_raw) {
        Ok(sig) => sig,
        Err(_) => return ERR_SM2_PARSE,
    };
    match public.verify(message, &signature) {
        Ok(()) => 1,
        Err(CryptoError::BadSignature) => 0,
        Err(_) => ERR_SM2_VERIFY,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_public_key_prefixed(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
    public_ptr: *const c_uchar,
    public_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    if public_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
        return ERR_NULL_PTR;
    }
    if public_len != 65 {
        return ERR_SM2_PARSE;
    }
    let distid = match unsafe { read_distid_or_default(distid_ptr, distid_len) } {
        Ok(d) => d,
        Err(err) => return err.code(),
    };
    let public_bytes = unsafe { slice::from_raw_parts(public_ptr, public_len as usize) };
    let public = match Sm2PublicKey::from_sec1_bytes(&distid, public_bytes) {
        Ok(pk) => pk,
        Err(_) => return ERR_SM2_PARSE,
    };
    let prefixed = match public.try_to_prefixed_string() {
        Ok(value) => value,
        Err(_) => return ERR_SM2_PARSE,
    };
    match unsafe { write_bytes(out_ptr, out_len, prefixed.as_bytes()) } {
        Ok(()) => 0,
        Err(code) => code,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_public_key_multihash(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
    public_ptr: *const c_uchar,
    public_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    let status = unsafe {
        connect_norito_sm2_public_key_prefixed(
            distid_ptr, distid_len, public_ptr, public_len, out_ptr, out_len,
        )
    };
    if status != 0 {
        return status;
    }
    if out_ptr.is_null() || out_len.is_null() {
        return ERR_NULL_PTR;
    }
    unsafe {
        let ptr = *out_ptr;
        if ptr.is_null() {
            return ERR_ALLOC;
        }
        let len = *out_len as usize;
        let slice = slice::from_raw_parts_mut(ptr, len);
        let mut string = match std::str::from_utf8(slice) {
            Ok(s) => s.to_owned(),
            Err(_) => return ERR_UTF8,
        };
        if let Some(stripped) = string.strip_prefix("sm2:") {
            string = stripped.to_owned();
        }
        free(ptr as *mut _);
        match write_bytes(out_ptr, out_len, string.as_bytes()) {
            Ok(()) => 0,
            Err(code) => code,
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sm2_compute_za(
    distid_ptr: *const c_char,
    distid_len: c_ulong,
    public_ptr: *const c_uchar,
    public_len: c_ulong,
    out_za_ptr: *mut c_uchar,
    out_za_len: c_ulong,
) -> c_int {
    if public_ptr.is_null() || out_za_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if public_len != 65 || out_za_len < 32 {
        return ERR_BUFFER_TOO_SMALL;
    }
    let distid = match unsafe { read_distid_or_default(distid_ptr, distid_len) } {
        Ok(d) => d,
        Err(err) => return err.code(),
    };
    let public_bytes = unsafe { slice::from_raw_parts(public_ptr, public_len as usize) };
    let public = match Sm2PublicKey::from_sec1_bytes(&distid, public_bytes) {
        Ok(pk) => pk,
        Err(_) => return ERR_SM2_PARSE,
    };
    let za = match public.compute_z(&distid) {
        Ok(za) => za,
        Err(_) => return ERR_SM2_PARSE,
    };
    unsafe {
        ptr::copy_nonoverlapping(za.as_ptr(), out_za_ptr, za.len());
    }
    0
}
#[cfg(test)]
mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};
    static CHAIN_DISCRIMINANT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    pub(super) fn chain_discriminant_guard() -> MutexGuard<'static, ()> {
        CHAIN_DISCRIMINANT_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(super) struct ChainDiscriminantScope {
        token: u64,
        _guard: MutexGuard<'static, ()>,
    }
    impl ChainDiscriminantScope {
        pub(super) fn enter(discriminant: u16) -> Self {
            let guard = chain_discriminant_guard();
            let token = super::connect_norito_chain_discriminant_scope_enter(discriminant);
            assert_ne!(token, 0, "test chain-discriminant scope must be entered");
            Self {
                token,
                _guard: guard,
            }
        }
    }
    impl Drop for ChainDiscriminantScope {
        fn drop(&mut self) {
            assert_eq!(
                super::connect_norito_chain_discriminant_scope_exit(self.token),
                0,
                "test chain-discriminant scope must exit on its entry thread"
            );
        }
    }
}
#[cfg(test)]
mod accel_tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use iroha_data_model::prelude::TransferBox;
    use std::{
        collections::BTreeMap,
        ffi::CString,
        num::{NonZeroU16, NonZeroU32, NonZeroU64},
        ptr, slice,
    };
    const AUTHORITY_FEE_PAYMENT_JSON: &[u8] =
        br#"{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}}"#;
    fn fixture_key_pair(seed: u8) -> KeyPair {
        let mut material = [0u8; 32];
        let domain = b"connect-accel-test-seed";
        material[..domain.len()].copy_from_slice(domain);
        material[31] = seed;
        KeyPair::try_from_seed(material.to_vec(), Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    #[test]
    fn fixture_key_pair_uses_checked_seed_derivation() {
        assert_eq!(fixture_key_pair(0).algorithm(), Algorithm::Ed25519);
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    pub(super) fn sample_account(_domain: &str, seed: u8) -> (CString, Vec<u8>) {
        let keypair = fixture_key_pair(seed);
        let (public_key, private_key) = keypair.into_parts();
        let account_id = AccountId::new(public_key);
        let account = CString::new(account_id.to_string()).expect("valid cstring");
        let (_, bytes) = private_key.to_bytes();
        (account, bytes)
    }
    pub(super) fn sample_destination(_domain: &str, seed: u8) -> CString {
        let keypair = fixture_key_pair(seed);
        let (public_key, _) = keypair.into_parts();
        let account_id = AccountId::new(public_key);
        CString::new(account_id.to_string()).expect("valid cstring")
    }
    pub(super) fn cstring(s: &str) -> CString {
        CString::new(s).expect("valid cstring")
    }
    fn network_id_cstring(_test_case: &str) -> CString {
        cstring("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0")
    }
    fn chain_guard() -> std::sync::MutexGuard<'static, ()> {
        super::test_support::chain_discriminant_guard()
    }
    fn decode_signed(ptr: *mut u8, len: c_ulong) -> SignedTransaction {
        let bytes = unsafe { slice::from_raw_parts(ptr, len as usize) };
        decode_signed_transaction(bytes).expect("decode signed transaction")
    }
    fn asset_definition_literal(domain: &str, name: &str) -> String {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new(domain, "universal").expect("domain"),
            Name::from_str(name).expect("name"),
        )
        .to_string()
    }
    fn asset_definition_cstring(domain: &str, name: &str) -> CString {
        cstring(&asset_definition_literal(domain, name))
    }
    fn compact_c_declaration(header: &str, symbol: &str) -> String {
        let marker = format!("int32_t {symbol}(");
        let start = header
            .find(marker.as_str())
            .unwrap_or_else(|| panic!("missing C declaration for {symbol}"));
        let end = start
            + header[start..]
                .find(");")
                .unwrap_or_else(|| panic!("unterminated C declaration for {symbol}"))
            + 2;
        header[start..end].split_whitespace().collect()
    }
    #[test]
    fn ed25519_signed_transaction_wrapper_inventory_preserves_the_c_abi() {
        let compact_source: String = bridge_source().split_whitespace().collect();
        let header = include_str!("../include/connect_norito_bridge.h");
        let families = [
            "account_read_permission_multisig",
            "transfer",
            "register_zk_asset",
            "set_key_value",
            "remove_key_value",
            "governance_propose_deploy_v1",
            "governance_cast_plain_ballot",
            "governance_cast_zk_ballot",
            "mint",
            "multisig_register",
            "burn",
            "claim_identifier",
        ];
        let macro_marker = ["define_ed25519_signed_", "transaction_wrapper!{"].concat();
        assert_eq!(compact_source.matches(macro_marker.as_str()).count(), 12);
        for family in families {
            let default = format!("connect_norito_encode_{family}_signed_transaction");
            let with_algorithm = format!("{default}_alg");
            let invocation = format!("{default}=>{with_algorithm}(");
            assert_eq!(
                compact_source.matches(invocation.as_str()).count(),
                1,
                "missing or duplicate Ed25519 wrapper for {family}",
            );
            let default_declaration = compact_c_declaration(header, default.as_str());
            let algorithm_declaration = compact_c_declaration(header, with_algorithm.as_str())
                .replacen(with_algorithm.as_str(), default.as_str(), 1)
                .replacen("uint8_talgorithm,", "", 1);
            assert_eq!(
                default_declaration, algorithm_declaration,
                "C ABI pair differs by more than algorithm_code for {family}",
            );
        }
    }
    #[test]
    fn account_read_permission_multisig_signer_emits_only_exact_wallet_grant_or_revoke() {
        use iroha_data_model::{
            account::{MultisigMember, MultisigPolicy},
            asset::AssetDefinitionId,
            nexus::FeeSponsorProgramId,
            transaction::{FeeChargeKind, FeeChargeLimit},
        };

        let _chain = super::test_support::ChainDiscriminantScope::enter(0xA2F0);
        let network = network_id_cstring("account-read-permission");
        let signer = fixture_key_pair(72);
        let member = MultisigMember::new(signer.public_key().clone(), 1).expect("member");
        let wallet = AccountId::new_multisig(MultisigPolicy::new(1, vec![member]).expect("policy"));
        let wallet_literal = cstring(&wallet.to_string());
        let reporter = AccountId::new(fixture_key_pair(73).public_key().clone());
        let reporter_literal = cstring(&reporter.to_string());
        let (_, private_key) = signer.private_key().to_bytes();
        let mut fee_asset_bytes = [0_u8; 16];
        fee_asset_bytes[6] = 0x40;
        fee_asset_bytes[8] = 0x80;
        let fee_payment = FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                AssetDefinitionId::from_uuid_bytes(fee_asset_bytes).expect("fee asset"),
                Quantity::from(10_u64),
            )],
            None,
        );
        let fee_payment_json = norito::json::to_vec(&fee_payment).expect("fee payment JSON");

        for change in [1_u8, 2_u8] {
            let mut signed_ptr = ptr::null_mut();
            let mut signed_len = 0;
            let mut hash = [0_u8; 32];
            let code = unsafe {
                connect_norito_encode_account_read_permission_multisig_signed_transaction(
                    network.as_ptr(),
                    network.as_bytes().len() as c_ulong,
                    wallet_literal.as_ptr(),
                    wallet_literal.as_bytes().len() as c_ulong,
                    reporter_literal.as_ptr(),
                    reporter_literal.as_bytes().len() as c_ulong,
                    change,
                    1_700_000_000_000,
                    fee_payment_json.as_ptr(),
                    fee_payment_json.len() as c_ulong,
                    private_key.as_ptr(),
                    private_key.len() as c_ulong,
                    &mut signed_ptr,
                    &mut signed_len,
                    hash.as_mut_ptr(),
                    hash.len() as c_ulong,
                )
            };
            assert_eq!(code, 0, "exact wallet permission signer failed");
            let bytes = unsafe { slice::from_raw_parts(signed_ptr, signed_len as usize) };
            let signed = decode_signed_transaction(bytes).expect("current signed transaction");
            assert_eq!(signed.encode_versioned(), bytes);
            assert_eq!(signed.authority(), &wallet);
            assert_eq!(signed.signature_count(), 1);
            assert_eq!(signed.fee_payment_intent(), &fee_payment);
            signed.verify_signature().expect("wallet signature");
            assert_eq!(signed.hash().as_ref(), hash.as_slice());
            let permission = CanReadAccountData {
                account: wallet.clone(),
            };
            let expected = if change == 1 {
                InstructionBox::from(Grant::account_permission(permission, reporter.clone()))
            } else {
                InstructionBox::from(Revoke::account_permission(permission, reporter.clone()))
            };
            let Executable::Instructions(instructions) = signed.instructions() else {
                panic!("permission transaction must be a native instruction");
            };
            assert_eq!(instructions.len(), 1);
            assert_eq!(instructions[0], expected);
            let expected_wire = bytes.to_vec();
            let mut payload_hash = [0_u8; 32];
            let prepared = unsafe {
                connect_norito_account_read_permission_multisig_payload_hash(
                    network.as_ptr(),
                    network.as_bytes().len() as c_ulong,
                    wallet_literal.as_ptr(),
                    wallet_literal.as_bytes().len() as c_ulong,
                    reporter_literal.as_ptr(),
                    reporter_literal.as_bytes().len() as c_ulong,
                    change,
                    1_700_000_000_000,
                    fee_payment_json.as_ptr(),
                    fee_payment_json.len() as c_ulong,
                    payload_hash.as_mut_ptr(),
                    payload_hash.len() as c_ulong,
                )
            };
            assert_eq!(prepared, 0);
            let external_signature = Signature::try_new(signer.private_key(), &payload_hash)
                .expect("external signer can sign the exact prehash");
            let mut external_ptr = ptr::null_mut();
            let mut external_len = 0;
            let mut external_hash = [0_u8; 32];
            let finalized = unsafe {
                connect_norito_account_read_permission_multisig_finalize(
                    network.as_ptr(),
                    network.as_bytes().len() as c_ulong,
                    wallet_literal.as_ptr(),
                    wallet_literal.as_bytes().len() as c_ulong,
                    reporter_literal.as_ptr(),
                    reporter_literal.as_bytes().len() as c_ulong,
                    change,
                    1_700_000_000_000,
                    fee_payment_json.as_ptr(),
                    fee_payment_json.len() as c_ulong,
                    external_signature.payload().as_ptr(),
                    external_signature.payload().len() as c_ulong,
                    &mut external_ptr,
                    &mut external_len,
                    external_hash.as_mut_ptr(),
                    external_hash.len() as c_ulong,
                )
            };
            assert_eq!(finalized, 0);
            let external_wire =
                unsafe { slice::from_raw_parts(external_ptr, external_len as usize) };
            assert_eq!(external_wire, expected_wire.as_slice());
            assert_eq!(external_hash, hash);
            connect_norito_free(external_ptr);

            let mut altered_signature = external_signature.payload().to_vec();
            altered_signature[0] ^= 1;
            let mut rejected_ptr = ptr::dangling_mut();
            let mut rejected_len = c_ulong::MAX;
            let mut rejected_hash = [0xA5_u8; 32];
            let rejected = unsafe {
                connect_norito_account_read_permission_multisig_finalize(
                    network.as_ptr(),
                    network.as_bytes().len() as c_ulong,
                    wallet_literal.as_ptr(),
                    wallet_literal.as_bytes().len() as c_ulong,
                    reporter_literal.as_ptr(),
                    reporter_literal.as_bytes().len() as c_ulong,
                    change,
                    1_700_000_000_000,
                    fee_payment_json.as_ptr(),
                    fee_payment_json.len() as c_ulong,
                    altered_signature.as_ptr(),
                    altered_signature.len() as c_ulong,
                    &mut rejected_ptr,
                    &mut rejected_len,
                    rejected_hash.as_mut_ptr(),
                    rejected_hash.len() as c_ulong,
                )
            };
            assert_ne!(
                rejected, 0,
                "altered signature must not become a signed grant"
            );
            assert!(rejected_ptr.is_null());
            assert_eq!(rejected_len, 0);
            assert_eq!(rejected_hash, [0_u8; 32]);
            connect_norito_free(signed_ptr);
        }

        let mut signed_ptr = ptr::dangling_mut();
        let mut signed_len = c_ulong::MAX;
        let mut hash = [0xA5_u8; 32];
        let bad_change = unsafe {
            connect_norito_encode_account_read_permission_multisig_signed_transaction(
                network.as_ptr(),
                network.as_bytes().len() as c_ulong,
                wallet_literal.as_ptr(),
                wallet_literal.as_bytes().len() as c_ulong,
                reporter_literal.as_ptr(),
                reporter_literal.as_bytes().len() as c_ulong,
                0,
                1_700_000_000_000,
                fee_payment_json.as_ptr(),
                fee_payment_json.len() as c_ulong,
                private_key.as_ptr(),
                private_key.len() as c_ulong,
                &mut signed_ptr,
                &mut signed_len,
                hash.as_mut_ptr(),
                hash.len() as c_ulong,
            )
        };
        assert_ne!(bad_change, 0);
        assert!(signed_ptr.is_null());
        assert_eq!(signed_len, 0);
        assert_eq!(hash, [0_u8; 32]);

        let empty_fee_payment_json =
            norito::json::to_vec(&FeePaymentIntent::authority(Vec::new(), None))
                .expect("empty fee payment JSON");
        let mut rejected_hash = [0xA5_u8; 32];
        let missing_cap = unsafe {
            connect_norito_account_read_permission_multisig_payload_hash(
                network.as_ptr(),
                network.as_bytes().len() as c_ulong,
                wallet_literal.as_ptr(),
                wallet_literal.as_bytes().len() as c_ulong,
                reporter_literal.as_ptr(),
                reporter_literal.as_bytes().len() as c_ulong,
                1,
                1_700_000_000_000,
                empty_fee_payment_json.as_ptr(),
                empty_fee_payment_json.len() as c_ulong,
                rejected_hash.as_mut_ptr(),
                rejected_hash.len() as c_ulong,
            )
        };
        assert_ne!(missing_cap, 0, "wallet permission requires signed fee caps");
        assert_eq!(rejected_hash, [0_u8; 32]);

        let sponsored_fee_payment = FeePaymentIntent::sponsor(
            FeeSponsorProgramId::new(reporter, "retail".parse().expect("program name")),
            1,
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                AssetDefinitionId::from_uuid_bytes(fee_asset_bytes).expect("fee asset"),
                Quantity::from(10_u64),
            )],
            None,
        );
        let sponsored_fee_json =
            norito::json::to_vec(&sponsored_fee_payment).expect("sponsor fee JSON");
        let mut authority_prehash = [0_u8; 32];
        let mut sponsor_prehash = [0_u8; 32];
        for (fee_json, result) in [
            (&fee_payment_json, &mut authority_prehash),
            (&sponsored_fee_json, &mut sponsor_prehash),
        ] {
            let code = unsafe {
                connect_norito_account_read_permission_multisig_payload_hash(
                    network.as_ptr(),
                    network.as_bytes().len() as c_ulong,
                    wallet_literal.as_ptr(),
                    wallet_literal.as_bytes().len() as c_ulong,
                    reporter_literal.as_ptr(),
                    reporter_literal.as_bytes().len() as c_ulong,
                    1,
                    1_700_000_000_000,
                    fee_json.as_ptr(),
                    fee_json.len() as c_ulong,
                    result.as_mut_ptr(),
                    result.len() as c_ulong,
                )
            };
            assert_eq!(code, 0);
        }
        assert_ne!(authority_prehash, sponsor_prehash);
    }
    #[test]
    fn governance_deploy_v1_boundary_requires_exact_hashes_and_explicit_provenance() {
        let hash = [0xA5_u8; 32];
        assert_eq!(
            unsafe { read_governance_hash32_bridge(hash.as_ptr(), hash.len() as c_ulong) }
                .expect("exact raw hash"),
            hash
        );
        assert!(matches!(
            unsafe { read_governance_hash32_bridge(hash.as_ptr(), 31) },
            Err(BridgeError::Governance)
        ));

        assert!(
            unsafe { read_manifest_provenance_bridge(ptr::null(), 0, ptr::null(), 0, 0) }
                .expect("explicitly absent provenance")
                .is_none()
        );
        let signer = cstring(&fixture_key_pair(33).public_key().to_string());
        let signature = cstring(&"11".repeat(64));
        let provenance = unsafe {
            read_manifest_provenance_bridge(
                signer.as_ptr(),
                signer.as_bytes().len() as c_ulong,
                signature.as_ptr(),
                signature.as_bytes().len() as c_ulong,
                1,
            )
        }
        .expect("explicitly present provenance")
        .expect("present provenance value");
        assert_eq!(provenance.signer, fixture_key_pair(33).public_key().clone());
        assert_eq!(provenance.signature.payload(), &[0x11_u8; 64]);

        for result in [
            unsafe {
                read_manifest_provenance_bridge(
                    signer.as_ptr(),
                    signer.as_bytes().len() as c_ulong,
                    ptr::null(),
                    0,
                    1,
                )
            },
            unsafe {
                read_manifest_provenance_bridge(
                    signer.as_ptr(),
                    signer.as_bytes().len() as c_ulong,
                    ptr::null(),
                    0,
                    0,
                )
            },
            unsafe { read_manifest_provenance_bridge(ptr::null(), 0, ptr::null(), 0, 2) },
        ] {
            assert!(matches!(result, Err(BridgeError::Governance)));
        }
    }
    macro_rules! call_signed_transaction_encoder_pair {
        ($algorithm:expr, $default:path, $with_algorithm:path, ($($argument:expr,)*)) => {{
            let algorithm = $algorithm;
            let mut out_signed_ptr: *mut u8 = ptr::dangling_mut();
            let mut out_signed_len: c_ulong = c_ulong::MAX;
            let mut out_hash = [0xA5_u8; 32];
            let result = unsafe {
                if let Some(algorithm) = algorithm {
                    $with_algorithm(
                        $($argument,)*
                        algorithm as u8,
                        &mut out_signed_ptr,
                        &mut out_signed_len,
                        out_hash.as_mut_ptr(),
                        out_hash.len() as c_ulong,
                    )
                } else {
                    $default(
                        $($argument,)*
                        &mut out_signed_ptr,
                        &mut out_signed_len,
                        out_hash.as_mut_ptr(),
                        out_hash.len() as c_ulong,
                    )
                }
            };
            (result, out_signed_ptr, out_signed_len, out_hash)
        }};
    }
    fn call_plain_ballot_encoder(
        referendum_id: &str,
        amount: &str,
        algorithm: Option<Algorithm>,
        valid_private_key: bool,
    ) -> (c_int, *mut u8, c_ulong, [u8; 32]) {
        let chain = network_id_cstring("governance-plain-ballot");
        let (authority, private) = sample_account("governance", 30);
        let owner = sample_destination("governance", 31);
        let amount = cstring(amount);
        let invalid_private = [0xFF_u8];
        let private = if valid_private_key {
            private.as_slice()
        } else {
            invalid_private.as_slice()
        };
        call_signed_transaction_encoder_pair!(
            algorithm,
            connect_norito_encode_governance_cast_plain_ballot_signed_transaction,
            connect_norito_encode_governance_cast_plain_ballot_signed_transaction_alg,
            (
                chain.as_ptr(),
                chain.as_bytes().len() as c_ulong,
                authority.as_ptr(),
                authority.as_bytes().len() as c_ulong,
                1,
                0,
                0,
                referendum_id.as_ptr().cast::<c_char>(),
                referendum_id.len() as c_ulong,
                owner.as_ptr(),
                owner.as_bytes().len() as c_ulong,
                amount.as_ptr(),
                amount.as_bytes().len() as c_ulong,
                42,
                1,
                AUTHORITY_FEE_PAYMENT_JSON.as_ptr(),
                AUTHORITY_FEE_PAYMENT_JSON.len() as c_ulong,
                private.as_ptr(),
                private.len() as c_ulong,
            )
        )
    }
    fn own_signed_transaction_output(
        (status, ptr, len, hash): (c_int, *mut u8, c_ulong, [u8; 32]),
    ) -> (c_int, Vec<u8>, [u8; 32]) {
        if status != 0 {
            return (status, Vec::new(), hash);
        }
        assert!(!ptr.is_null());
        let bytes = unsafe { slice::from_raw_parts(ptr, len as usize) }.to_vec();
        unsafe { free(ptr.cast()) };
        (status, bytes, hash)
    }
    #[test]
    fn ed25519_default_wrapper_matches_algorithm_path_under_input_mutation() {
        let _guard = chain_guard();
        for (case, selector, amount, valid_private_key, expected_status) in [
            ("valid", "ref-plain", "1", true, 0),
            (
                "selector mutation",
                "bad/selector",
                "1",
                false,
                ERR_GOVERNANCE,
            ),
            (
                "quantity mutation",
                "ref-plain",
                "01",
                true,
                ERR_QUANTITY_PARSE,
            ),
            (
                "private-key mutation",
                "ref-plain",
                "1",
                false,
                ERR_PRIVATE_KEY_PARSE,
            ),
        ] {
            let default = own_signed_transaction_output(call_plain_ballot_encoder(
                selector,
                amount,
                None,
                valid_private_key,
            ));
            let with_algorithm = own_signed_transaction_output(call_plain_ballot_encoder(
                selector,
                amount,
                Some(Algorithm::Ed25519),
                valid_private_key,
            ));
            assert_eq!(default.0, expected_status, "{case}");
            assert_eq!(default, with_algorithm, "{case}");
        }
    }
    fn call_zk_ballot_encoder(
        election_id: &str,
        algorithm: Option<Algorithm>,
        valid_private_key: bool,
    ) -> (c_int, *mut u8, c_ulong, [u8; 32]) {
        let chain = network_id_cstring("governance-zk-ballot");
        let (authority, private) = sample_account("governance", 32);
        let proof = b"AQ==";
        let public_inputs = b"{}";
        let invalid_private = [0xFF_u8];
        let private = if valid_private_key {
            private.as_slice()
        } else {
            invalid_private.as_slice()
        };
        call_signed_transaction_encoder_pair!(
            algorithm,
            connect_norito_encode_governance_cast_zk_ballot_signed_transaction,
            connect_norito_encode_governance_cast_zk_ballot_signed_transaction_alg,
            (
                chain.as_ptr(),
                chain.as_bytes().len() as c_ulong,
                authority.as_ptr(),
                authority.as_bytes().len() as c_ulong,
                1,
                0,
                0,
                election_id.as_ptr().cast::<c_char>(),
                election_id.len() as c_ulong,
                proof.as_ptr().cast::<c_char>(),
                proof.len() as c_ulong,
                public_inputs.as_ptr(),
                public_inputs.len() as c_ulong,
                AUTHORITY_FEE_PAYMENT_JSON.as_ptr(),
                AUTHORITY_FEE_PAYMENT_JSON.len() as c_ulong,
                private.as_ptr(),
                private.len() as c_ulong,
            )
        )
    }
    type GovernanceSelectorEncoder =
        fn(&str, Option<Algorithm>, bool) -> (c_int, *mut u8, c_ulong, [u8; 32]);
    fn call_plain_ballot_selector_encoder(
        selector: &str,
        algorithm: Option<Algorithm>,
        valid_private_key: bool,
    ) -> (c_int, *mut u8, c_ulong, [u8; 32]) {
        call_plain_ballot_encoder(selector, "1", algorithm, valid_private_key)
    }
    fn governance_selector_encoders() -> [(&'static str, GovernanceSelectorEncoder); 2] {
        [
            ("CastPlainBallot", call_plain_ballot_selector_encoder),
            ("CastZkBallot", call_zk_ballot_encoder),
        ]
    }
    #[test]
    fn governance_selector_encoders_accept_exact_length_boundaries() {
        let _guard = chain_guard();
        let maximum = "a".repeat(128);
        for selector in ["a", maximum.as_str()] {
            for algorithm in [None, Some(Algorithm::Ed25519)] {
                for (instruction, encode) in governance_selector_encoders() {
                    let (result, out_signed_ptr, out_signed_len, out_hash) =
                        encode(selector, algorithm, true);
                    assert_eq!(
                        result,
                        0,
                        "{instruction} selector length {} must encode",
                        selector.len()
                    );
                    assert!(!out_signed_ptr.is_null());
                    assert_signed_hash_matches(out_hash, out_signed_ptr, out_signed_len);
                    unsafe { free(out_signed_ptr.cast()) };
                }
            }
        }
    }
    #[test]
    fn governance_selector_encoders_reject_aliases_before_crypto_without_outputs() {
        let _guard = chain_guard();
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
            for algorithm in [None, Some(Algorithm::Ed25519)] {
                for (instruction, encode) in governance_selector_encoders() {
                    let (result, out_signed_ptr, out_signed_len, out_hash) =
                        encode(selector, algorithm, false);
                    assert_eq!(
                        result, ERR_GOVERNANCE,
                        "{instruction} must reject {case} before parsing the poisoned private key"
                    );
                    assert!(out_signed_ptr.is_null(), "{instruction} {case}");
                    assert_eq!(out_signed_len, 0, "{instruction} {case}");
                    assert_eq!(out_hash, [0_u8; 32], "{instruction} {case}");
                }
            }
        }
    }
    #[test]
    fn governance_plain_ballot_encoders_preserve_canonical_quantity_amounts() {
        let _guard = chain_guard();
        let wide = "340282366920938463463374607431768211456.25";
        for algorithm in [None, Some(Algorithm::Ed25519)] {
            for amount in ["1.25", wide] {
                let (result, out_signed_ptr, out_signed_len, out_hash) =
                    call_plain_ballot_encoder("ref-plain", amount, algorithm, true);
                assert_eq!(result, 0, "canonical Quantity {amount:?} must encode");
                assert!(!out_signed_ptr.is_null());
                assert_signed_hash_matches(out_hash, out_signed_ptr, out_signed_len);
                let signed = decode_signed(out_signed_ptr, out_signed_len);
                let ballot = match signed.instructions() {
                    Executable::Instructions(instructions) => instructions
                        .first()
                        .and_then(|instruction| {
                            instruction.as_any().downcast_ref::<CastPlainBallot>()
                        })
                        .expect("plain ballot instruction"),
                    other => panic!("unexpected executable: {other:?}"),
                };
                assert_eq!(ballot.amount.to_string(), amount);
                unsafe {
                    free(out_signed_ptr.cast());
                }
            }
        }
    }
    #[test]
    fn governance_plain_ballot_encoders_reject_noncanonical_quantities() {
        let _guard = chain_guard();
        for algorithm in [None, Some(Algorithm::Ed25519)] {
            for amount in ["", "-1", "01", "1.0", "+1", " 1", "1 ", "1e3"] {
                let (result, out_signed_ptr, out_signed_len, out_hash) =
                    call_plain_ballot_encoder("ref-plain", amount, algorithm, true);
                assert_eq!(
                    result, ERR_QUANTITY_PARSE,
                    "invalid public Quantity {amount:?} must be rejected"
                );
                assert!(out_signed_ptr.is_null());
                assert_eq!(out_signed_len, 0);
                assert_eq!(out_hash, [0_u8; 32]);
            }
        }
    }
    fn call_update_plain_conviction_encoder(
        referendum_id: &str,
        amount: &str,
        owner_matches_authority: bool,
        valid_private_key: bool,
    ) -> (c_int, *mut u8, c_ulong, [u8; 32]) {
        let network_id = network_id_cstring("governance-conviction-update");
        let (authority, private) = sample_account("governance", 30);
        let other_owner = sample_destination("governance", 31);
        let owner = if owner_matches_authority {
            &authority
        } else {
            &other_owner
        };
        let invalid_private = [0xFF_u8];
        let private = if valid_private_key {
            private.as_slice()
        } else {
            invalid_private.as_slice()
        };
        let mut out_signed_ptr = ptr::null_mut();
        let mut out_signed_len = 0;
        let mut out_hash = [0_u8; 32];
        let status = unsafe {
            connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg(
                network_id.as_ptr(),
                network_id.as_bytes().len() as c_ulong,
                authority.as_ptr(),
                authority.as_bytes().len() as c_ulong,
                1,
                0,
                0,
                referendum_id.as_ptr().cast(),
                referendum_id.len() as c_ulong,
                owner.as_ptr(),
                owner.as_bytes().len() as c_ulong,
                amount.as_ptr().cast(),
                amount.len() as c_ulong,
                42,
                AUTHORITY_FEE_PAYMENT_JSON.as_ptr(),
                AUTHORITY_FEE_PAYMENT_JSON.len() as c_ulong,
                private.as_ptr(),
                private.len() as c_ulong,
                Algorithm::Ed25519 as u8,
                &mut out_signed_ptr,
                &mut out_signed_len,
                out_hash.as_mut_ptr(),
                out_hash.len() as c_ulong,
            )
        };
        (status, out_signed_ptr, out_signed_len, out_hash)
    }
    #[test]
    fn governance_update_plain_conviction_encodes_exact_choice_free_fields() {
        let _guard = chain_guard();
        let header = include_str!("../include/connect_norito_bridge.h");
        let declaration = compact_c_declaration(
            header,
            "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg",
        );
        assert!(declaration.contains("duration_blocks"));
        assert!(!declaration.contains("direction"));
        for referendum_id in ["ref-update".to_owned(), "a".repeat(128)] {
            for amount in ["1.25", "340282366920938463463374607431768211456.25"] {
                let (status, ptr, len, hash) =
                    call_update_plain_conviction_encoder(&referendum_id, amount, true, true);
                assert_eq!(status, 0, "canonical update must encode");
                assert_signed_hash_matches(hash, ptr, len);
                let signed = decode_signed(ptr, len);
                let update = match signed.instructions() {
                    Executable::Instructions(instructions) if instructions.len() == 1 => {
                        instructions
                            .first()
                            .and_then(|instruction| {
                                instruction.as_any().downcast_ref::<UpdatePlainConviction>()
                            })
                            .expect("choice-free conviction update")
                    }
                    other => panic!("unexpected executable: {other:?}"),
                };
                assert_eq!(update.referendum_id, referendum_id);
                assert_eq!(update.amount.to_string(), amount);
                assert_eq!(update.duration_blocks, 42);
                assert_eq!(&update.owner, signed.authority());
                unsafe { free(ptr.cast()) };
            }
        }
    }
    #[test]
    fn governance_update_plain_conviction_rejects_invalid_input_before_signing() {
        let _guard = chain_guard();
        for (selector, amount, owner_matches, expected) in [
            ("bad/ref", "1", true, ERR_GOVERNANCE),
            ("ref-update", "1", false, ERR_GOVERNANCE),
            ("ref-update", "01", true, ERR_QUANTITY_PARSE),
        ] {
            let (status, ptr, len, hash) =
                call_update_plain_conviction_encoder(selector, amount, owner_matches, false);
            assert_eq!(status, expected);
            assert!(ptr.is_null());
            assert_eq!(len, 0);
            assert_eq!(hash, [0_u8; 32]);
        }
    }
    fn call_confidential_memo_validator(wire: &[u8]) -> (c_int, *mut u8, c_ulong) {
        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let result = unsafe {
            connect_norito_validate_confidential_memo_envelope_v1(
                wire.as_ptr(),
                wire.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        (result, out_ptr, out_len)
    }
    #[test]
    fn decode_asset_id_json_returns_canonical_fields() {
        let _guard = chain_guard();
        let (account_cstr, _) = sample_account("bank", 0);
        let account_literal = account_cstr.to_str().expect("account literal");
        let account_id = AccountId::parse_encoded(account_literal).expect("parse account");
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("bank", "universal").expect("domain"),
            "usd".parse().expect("asset name"),
        );
        let asset = AssetId::new(definition.clone(), account_id.clone());
        let asset_literal = cstring(&asset.canonical_literal());
        let mut out_json_ptr: *mut u8 = ptr::null_mut();
        let mut out_json_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_decode_asset_id_json(
                asset_literal.as_ptr(),
                asset_literal.as_bytes().len() as c_ulong,
                &mut out_json_ptr,
                &mut out_json_len,
            )
        };
        assert_eq!(status, 0, "expected successful decode");
        assert!(
            !out_json_ptr.is_null(),
            "decoder should return JSON payload"
        );
        let body = unsafe { slice::from_raw_parts(out_json_ptr, out_json_len as usize) };
        let parsed: JsonValue = norito::json::from_slice(body).expect("decode bridge payload");
        connect_norito_free(out_json_ptr);
        let object = parsed.as_object().expect("json object");
        assert_eq!(
            object.get("asset_id").and_then(JsonValue::as_str),
            Some(asset.canonical_literal().as_str())
        );
        assert_eq!(
            object
                .get("asset_definition_id")
                .and_then(JsonValue::as_str),
            Some(definition.to_string().as_str())
        );
        assert_eq!(
            object.get("account_id").and_then(JsonValue::as_str),
            Some(account_id.to_string().as_str())
        );
    }
    #[test]
    fn chain_discriminant_scopes_restore_nested_context_and_reject_misordered_exit() {
        let _guard = super::test_support::chain_discriminant_guard();
        let baseline = iroha_data_model::account::address::chain_discriminant();
        let outer = connect_norito_chain_discriminant_scope_enter(369);
        assert_ne!(outer, 0);
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            369
        );
        let inner = connect_norito_chain_discriminant_scope_enter(753);
        assert_ne!(inner, 0);
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            753
        );
        assert_eq!(
            connect_norito_chain_discriminant_scope_exit(outer),
            -1,
            "non-LIFO exit must fail closed"
        );
        assert_eq!(
            connect_norito_chain_discriminant_scope_exit(0),
            -1,
            "zero-token underflow must fail closed"
        );
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            753
        );
        assert_eq!(connect_norito_chain_discriminant_scope_exit(inner), 0);
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            369
        );
        assert_eq!(connect_norito_chain_discriminant_scope_exit(outer), 0);
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            baseline
        );
    }
    #[test]
    fn chain_discriminant_scope_rejects_wrong_thread_without_consuming_guard() {
        let _guard = super::test_support::chain_discriminant_guard();
        let baseline = iroha_data_model::account::address::chain_discriminant();
        let token = connect_norito_chain_discriminant_scope_enter(369);
        assert_ne!(token, 0);
        assert_eq!(
            std::thread::spawn(move || connect_norito_chain_discriminant_scope_exit(token))
                .join()
                .expect("wrong-thread exit worker"),
            -1
        );
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            369
        );
        assert_eq!(connect_norito_chain_discriminant_scope_exit(token), 0);
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            baseline
        );
    }
    #[test]
    fn chain_discriminant_scopes_isolate_concurrent_taira_and_sora_account_parsing() {
        let _guard = super::test_support::chain_discriminant_guard();
        let key_pair = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let account_id = AccountId::new(key_pair.public_key().clone());
        let address = AccountAddress::from_account_id(&account_id).expect("account address");
        let taira = address
            .to_i105_for_discriminant(369)
            .expect("Taira account");
        let sora = address.to_i105_for_discriminant(753).expect("Sora account");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers = [(369, taira), (753, sora)].map(|(discriminant, literal)| {
            let barrier = Arc::clone(&barrier);
            let account_id = account_id.clone();
            std::thread::spawn(move || {
                let token = connect_norito_chain_discriminant_scope_enter(discriminant);
                assert_ne!(token, 0);
                barrier.wait();
                for _ in 0..512 {
                    assert_eq!(
                        parse_account_id(literal.clone()).expect("scoped account parse"),
                        account_id
                    );
                    std::thread::yield_now();
                }
                barrier.wait();
                assert_eq!(connect_norito_chain_discriminant_scope_exit(token), 0);
            })
        });
        for worker in workers {
            worker.join().expect("chain-discriminant scope worker");
        }
    }
    struct KeypairFromSeedOutput {
        status: c_int,
        private_ptr: *mut u8,
        private_len: c_ulong,
        public_ptr: *mut u8,
        public_len: c_ulong,
    }
    impl KeypairFromSeedOutput {
        fn private_bytes(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.private_ptr, self.private_len as usize) }
        }
        fn public_bytes(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.public_ptr, self.public_len as usize) }
        }
    }
    impl Drop for KeypairFromSeedOutput {
        fn drop(&mut self) {
            unsafe {
                if !self.private_ptr.is_null() {
                    free(self.private_ptr.cast());
                }
                if !self.public_ptr.is_null() {
                    free(self.public_ptr.cast());
                }
            }
        }
    }
    fn call_keypair_from_seed(algorithm: Algorithm, seed: &[u8]) -> KeypairFromSeedOutput {
        let mut output = KeypairFromSeedOutput {
            status: 0,
            private_ptr: ptr::null_mut(),
            private_len: 0,
            public_ptr: ptr::null_mut(),
            public_len: 0,
        };
        output.status = unsafe {
            connect_norito_keypair_from_seed(
                algorithm as u8,
                seed.as_ptr(),
                seed.len() as c_ulong,
                &mut output.private_ptr,
                &mut output.private_len,
                &mut output.public_ptr,
                &mut output.public_len,
            )
        };
        output
    }
    #[test]
    fn keypair_from_seed_roundtrip() {
        let _guard = chain_guard();
        let seed = vec![0xA5; 32];
        let expected = KeyPair::try_from_seed(seed.clone(), Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let (expected_public, expected_private) = expected.into_parts();
        let (_alg, expected_private_bytes) = expected_private.to_bytes();
        let (_alg, expected_public_bytes) = expected_public
            .try_to_bytes()
            .expect("checked public bytes");
        let output = call_keypair_from_seed(Algorithm::Ed25519, &seed);
        assert_eq!(output.status, 0, "expected success");
        assert!(!output.private_ptr.is_null());
        assert!(!output.public_ptr.is_null());
        assert_eq!(output.private_bytes(), expected_private_bytes.as_slice());
        assert_eq!(output.public_bytes(), expected_public_bytes);
    }
    #[test]
    fn keypair_from_seed_private_output_derives_public_key() {
        let _guard = chain_guard();
        let seed = [0x5C; 32];
        let output = call_keypair_from_seed(Algorithm::Ed25519, &seed);
        assert_eq!(output.status, 0, "expected success");
        assert!(!output.private_ptr.is_null());
        assert!(!output.public_ptr.is_null());
        let private_key =
            parse_private_key_with_algorithm(output.private_bytes(), Algorithm::Ed25519)
                .expect("private");
        let derived = KeyPair::from_private_key(private_key).expect("derive public key");
        let derived_public = checked_public_key_payload(derived.public_key())
            .expect("checked public bytes")
            .to_vec();
        assert_eq!(derived_public.as_slice(), output.public_bytes());
    }
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    #[test]
    fn java_keypair_from_seed_private_output_derives_public_key() {
        let seed = [0x6D; 32];
        let (private_bytes, public_bytes) =
            java_keypair_from_seed_bytes(Algorithm::Ed25519 as jni::sys::jint, &seed)
                .expect("java keypair from seed");
        let private_key =
            parse_private_key_with_algorithm(private_bytes.as_slice(), Algorithm::Ed25519)
                .expect("private");
        let derived = KeyPair::from_private_key(private_key).expect("derive public key");
        let derived_public = checked_public_key_payload(derived.public_key())
            .expect("checked public bytes")
            .to_vec();
        assert_eq!(derived_public.as_slice(), public_bytes.as_slice());
    }
    #[test]
    fn keypair_from_seed_fixture_vector() {
        let _guard = chain_guard();
        let seed = hex::decode("616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032")
            .expect("valid seed hex");
        let expected_public =
            hex::decode("1f857fe980524a2ee4fe65e5d346f7aaadcb636a640f1d191d1c6e158607ba1e")
                .expect("valid public key hex");
        let output = call_keypair_from_seed(Algorithm::Ed25519, &seed);
        assert_eq!(output.status, 0, "expected success");
        assert!(!output.public_ptr.is_null());
        assert_eq!(output.public_bytes(), expected_public.as_slice());
    }
    #[test]
    fn keypair_from_seed_mldsa_roundtrip() {
        let _guard = chain_guard();
        let seed = b"bridge-mldsa-seed-vector".to_vec();
        let expected = KeyPair::try_from_seed(seed.clone(), Algorithm::MlDsa)
            .expect("fixture seed must derive a valid ML-DSA keypair");
        let (expected_public, expected_private) = expected.into_parts();
        let (_alg, expected_private_bytes) = expected_private.to_bytes();
        let (_alg, expected_public_bytes) = expected_public
            .try_to_bytes()
            .expect("checked public bytes");
        let output = call_keypair_from_seed(Algorithm::MlDsa, &seed);
        assert_eq!(output.status, 0, "expected success");
        assert_eq!(output.private_bytes(), expected_private_bytes.as_slice());
        assert_eq!(output.public_bytes(), expected_public_bytes);
    }
    #[test]
    fn keypair_from_empty_mldsa_seed_fails_without_outputs() {
        let _guard = chain_guard();
        let output = call_keypair_from_seed(Algorithm::MlDsa, &[]);
        assert_eq!(output.status, ERR_CONNECT_KEYPAIR);
        assert!(output.private_ptr.is_null());
        assert_eq!(output.private_len, 0);
        assert!(output.public_ptr.is_null());
        assert_eq!(output.public_len, 0);
    }
    #[test]
    fn connect_open_app_metadata_roundtrip() {
        let _guard = chain_guard();
        let app_pk = [0x22u8; 32];
        let nonce = [0x33u8; 16];
        let network_id = Hash::new(b"connect-open-bridge-genesis");
        let exact_network = network_id_from_raw_bytes(network_id.as_ref()).expect("network id");
        let sid = connect_sdk::derive_session_id(&exact_network, &app_pk, &nonce);
        let app_meta = json_object([
            ("name", JsonValue::from("demo")),
            ("url", JsonValue::from("https://example.test")),
            ("icon_hash", JsonValue::from("deadbeef")),
        ]);
        let app_meta_bytes = norito::json::to_vec(&app_meta).expect("encode app metadata");
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_encode_control_open_ext(
                sid.as_ptr(),
                0,
                1,
                app_pk.as_ptr(),
                app_pk.len() as c_ulong,
                nonce.as_ptr(),
                nonce.len() as c_ulong,
                app_meta_bytes.as_ptr(),
                app_meta_bytes.len() as c_ulong,
                network_id.as_ref().as_ptr(),
                Hash::LENGTH as c_ulong,
                ptr::null::<c_uchar>(),
                0,
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(status, 0, "expected open frame encode success");
        assert!(!out_ptr.is_null());
        let mut meta_ptr: *mut c_uchar = ptr::null_mut();
        let mut meta_len: c_ulong = 0;
        let meta_status = unsafe {
            connect_norito_decode_control_open_app_metadata_json(
                out_ptr,
                out_len,
                &mut meta_ptr,
                &mut meta_len,
            )
        };
        assert_eq!(meta_status, 0, "expected app metadata decode success");
        assert!(!meta_ptr.is_null());
        let mut network_ptr: *mut c_uchar = ptr::null_mut();
        let mut network_len: c_ulong = 0;
        let network_status = unsafe {
            connect_norito_decode_control_open_network_id(
                out_ptr,
                out_len,
                &mut network_ptr,
                &mut network_len,
            )
        };
        assert_eq!(network_status, 0, "expected exact network decode success");
        assert_eq!(network_len as usize, Hash::LENGTH);
        assert_eq!(
            unsafe { slice::from_raw_parts(network_ptr, network_len as usize) },
            network_id.as_ref()
        );
        let meta_bytes = unsafe { slice::from_raw_parts(meta_ptr, meta_len as usize) };
        let parsed: JsonValue =
            norito::json::from_slice(meta_bytes).expect("parse app metadata json");
        let obj = parsed.as_object().expect("app metadata object");
        assert_eq!(obj.get("name").and_then(|v| v.as_str()), Some("demo"));
        assert_eq!(
            obj.get("url").and_then(|v| v.as_str()),
            Some("https://example.test")
        );
        assert_eq!(
            obj.get("icon_hash").and_then(|v| v.as_str()),
            Some("deadbeef")
        );
        unsafe {
            if !meta_ptr.is_null() {
                free(meta_ptr as *mut _);
            }
            if !network_ptr.is_null() {
                free(network_ptr as *mut _);
            }
            if !out_ptr.is_null() {
                free(out_ptr as *mut _);
            }
        }
    }
    include!("connect_approval_ffi_tests.rs");
    include!("current_admission_bridge_tests.rs");
    fn fixture_signing_key_pair() -> KeyPair {
        let seed = hex::decode("616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032")
            .expect("fixture seed hex");
        KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    fn fixture_private_key() -> Vec<u8> {
        let (_alg, private_bytes) = fixture_signing_key_pair().private_key().to_bytes();
        private_bytes
    }
    fn fixture_authority(_domain: &str) -> CString {
        let (public_key, _) = fixture_signing_key_pair().into_parts();
        let account = AccountId::new(public_key);
        CString::new(account.to_string()).expect("valid cstring")
    }
    fn assert_signed_hash_matches(out_hash: [u8; 32], signed_ptr: *mut u8, signed_len: c_ulong) {
        let signed_bytes = unsafe { slice::from_raw_parts(signed_ptr, signed_len as usize) };
        let signed = decode_signed_transaction(signed_bytes).expect("decode signed transaction");
        assert_eq!(out_hash, *signed.hash().as_ref());
    }
    struct AssetSignedEncoderFixture {
        chain: CString,
        authority: CString,
        asset_definition: CString,
        quantity: CString,
        destination: CString,
        private_key: Vec<u8>,
    }
    impl AssetSignedEncoderFixture {
        fn swift(test_case: &str, quantity: &str) -> Self {
            let authority = fixture_authority("wonderland");
            Self {
                chain: network_id_cstring(test_case),
                asset_definition: asset_definition_cstring("wonderland", "rose"),
                quantity: cstring(quantity),
                destination: authority.clone(),
                private_key: fixture_private_key(),
                authority,
            }
        }
        fn bank(test_case: &str, authority_seed: u8, quantity: &str) -> Self {
            let (authority, private_key) = sample_account("bank", authority_seed);
            Self {
                chain: network_id_cstring(test_case),
                authority,
                asset_definition: asset_definition_cstring("bank", "usd"),
                quantity: cstring(quantity),
                destination: sample_destination("bank", 1),
                private_key,
            }
        }
    }
    macro_rules! call_asset_signed_encoder {
        (
            $encoder:path,
            $fixture:expr,
            creation_time_ms: $creation_time_ms:expr,
            ttl_ms: $ttl_ms:expr,
            ttl_present: $ttl_present:expr,
            nonce: $nonce:expr,
            nonce_present: $nonce_present:expr,
            fee_payment: $fee_payment:expr
            $(, algorithm: $algorithm:expr)?
            $(,)?
        ) => {{
            let fixture = &$fixture;
            let fee_payment: &[u8] = $fee_payment;
            let mut out_signed_ptr: *mut u8 = ptr::null_mut();
            let mut out_signed_len: c_ulong = 0;
            let mut out_hash = [0u8; 32];
            let result = unsafe {
                $encoder(
                    fixture.chain.as_ptr(),
                    fixture.chain.as_bytes().len() as c_ulong,
                    fixture.authority.as_ptr(),
                    fixture.authority.as_bytes().len() as c_ulong,
                    $creation_time_ms,
                    $ttl_ms,
                    $ttl_present,
                    $nonce,
                    $nonce_present,
                    fixture.asset_definition.as_ptr(),
                    fixture.asset_definition.as_bytes().len() as c_ulong,
                    fixture.quantity.as_ptr(),
                    fixture.quantity.as_bytes().len() as c_ulong,
                    fixture.destination.as_ptr(),
                    fixture.destination.as_bytes().len() as c_ulong,
                    fee_payment.as_ptr(),
                    fee_payment.len() as c_ulong,
                    fixture.private_key.as_ptr(),
                    fixture.private_key.len() as c_ulong,
                    $($algorithm as u8,)?
                    &mut out_signed_ptr,
                    &mut out_signed_len,
                    out_hash.as_mut_ptr(),
                    out_hash.len() as c_ulong,
                )
            };
            (result, out_signed_ptr, out_signed_len, out_hash)
        }};
    }
    macro_rules! swift_parity_asset_encoder_test {
        (
            $name:ident,
            $test_case:literal,
            $encoder:path,
            $quantity:literal,
            $creation_time_ms:expr,
            $ttl_ms:expr,
            $nonce:expr,
        ) => {
            #[test]
            fn $name() {
                let _scope = super::test_support::ChainDiscriminantScope::enter(42);
                let fixture = AssetSignedEncoderFixture::swift($test_case, $quantity);
                let (result, out_signed_ptr, out_signed_len, out_hash) =
                    call_asset_signed_encoder!(
                        $encoder,
                        fixture,
                        creation_time_ms: $creation_time_ms,
                        ttl_ms: $ttl_ms,
                        ttl_present: 1,
                        nonce: $nonce,
                        nonce_present: 1,
                        fee_payment: AUTHORITY_FEE_PAYMENT_JSON,
                    );
                assert_eq!(result, 0, "expected success");
                assert_signed_hash_matches(out_hash, out_signed_ptr, out_signed_len);
                unsafe { free(out_signed_ptr.cast()) };
            }
        };
    }
    macro_rules! asset_encoder_nonce_roundtrip_test {
        (
            $name:ident,
            $test_case:literal,
            $encoder:path,
            $quantity:literal,
            $nonce:expr
            $(, algorithm: $algorithm:expr)?
            $(, message: $message:literal)?
            $(,)?
        ) => {
            #[test]
            fn $name() {
                let _guard = chain_guard();
                let fixture = AssetSignedEncoderFixture::bank($test_case, 0, $quantity);
                let (result, out_signed_ptr, out_signed_len, _out_hash) =
                    call_asset_signed_encoder!(
                        $encoder,
                        fixture,
                        creation_time_ms: 1,
                        ttl_ms: 0,
                        ttl_present: 0,
                        nonce: $nonce,
                        nonce_present: 1,
                        fee_payment: AUTHORITY_FEE_PAYMENT_JSON
                        $(, algorithm: $algorithm)?
                    );
                assert_eq!(result, 0, "expected success");
                let signed = decode_signed(out_signed_ptr, out_signed_len);
                assert_eq!(
                    signed.payload().nonce,
                    NonZeroU32::new($nonce)
                    $(, $message)?
                );
                unsafe { free(out_signed_ptr.cast()) };
            }
        };
    }
    #[test]
    fn parse_asset_definition_rejects_noncanonical_textual_literal() {
        let err = parse_asset_definition("usd#bank".to_owned())
            .expect_err("noncanonical textual asset definition should fail");
        assert!(matches!(err, BridgeError::AssetDefinition));
    }
    #[test]
    fn parse_asset_definition_accepts_canonical_base58_literal() {
        let canonical = asset_definition_literal("wonderland", "rose");
        let parsed = parse_asset_definition(canonical.clone())
            .expect("canonical base58 asset definition should parse");
        let expected = AssetDefinitionId::parse_address_literal(&canonical)
            .expect("canonical base58 should parse");
        assert_eq!(parsed, expected);
    }
    #[test]
    fn parse_asset_definition_accepts_dataspace_balance_scope_suffix() {
        let canonical = asset_definition_literal("wonderland", "rose");
        let (parsed, scope) =
            parse_asset_definition_with_balance_scope(format!("{canonical}#dataspace:10"))
                .expect("canonical base58 asset definition with dataspace scope should parse");
        let expected = AssetDefinitionId::parse_address_literal(&canonical)
            .expect("canonical base58 should parse");
        assert_eq!(parsed, expected);
        assert_eq!(scope, AssetBalanceScope::Dataspace(DataSpaceId::new(10)));
    }
    #[test]
    fn encode_transfer_preserves_dataspace_balance_scope_suffix() {
        let _scope = super::test_support::ChainDiscriminantScope::enter(42);
        let mut fixture = AssetSignedEncoderFixture::swift("swift-parity-transfer", "15.75");
        fixture.asset_definition = cstring(&format!(
            "{}#dataspace:10",
            asset_definition_literal("wonderland", "rose")
        ));
        let (result, out_signed_ptr, out_signed_len, _out_hash) = call_asset_signed_encoder!(
            connect_norito_encode_transfer_signed_transaction,
            fixture,
            creation_time_ms: 1_736_000_000_000,
            ttl_ms: 3_500,
            ttl_present: 1,
            nonce: 17,
            nonce_present: 1,
            fee_payment: AUTHORITY_FEE_PAYMENT_JSON,
        );
        assert_eq!(result, 0, "expected success");
        let signed = decode_signed(out_signed_ptr, out_signed_len);
        match signed.instructions() {
            Executable::Instructions(instructions) => {
                let transfer = instructions
                    .first()
                    .and_then(|instruction| instruction.as_any().downcast_ref::<TransferBox>())
                    .expect("transfer instruction");
                let TransferBox::Asset(transfer) = transfer else {
                    panic!("expected asset transfer");
                };
                assert_eq!(
                    transfer.source.scope(),
                    &AssetBalanceScope::Dataspace(DataSpaceId::new(10))
                );
            }
            other => panic!("unexpected executable: {other:?}"),
        }
        let mut out_json_ptr: *mut u8 = ptr::null_mut();
        let mut out_json_len: c_ulong = 0;
        let decode_status = unsafe {
            connect_norito_decode_signed_transaction_json(
                out_signed_ptr,
                out_signed_len,
                &mut out_json_ptr,
                &mut out_json_len,
            )
        };
        assert_eq!(decode_status, 0, "expected debug JSON decode");
        let json_body = unsafe { slice::from_raw_parts(out_json_ptr, out_json_len as usize) };
        let parsed: JsonValue = norito::json::from_slice(json_body).expect("decode transfer JSON");
        let bridge_debug = parsed
            .as_object()
            .and_then(|object| object.get("bridge_debug"))
            .and_then(JsonValue::as_object)
            .expect("bridge debug object");
        let transfer_scopes = bridge_debug
            .get("transfer_asset_scopes")
            .and_then(JsonValue::as_array)
            .expect("transfer scope array");
        let scope = transfer_scopes
            .first()
            .and_then(JsonValue::as_object)
            .expect("first transfer scope object");
        assert_eq!(
            scope.get("source_scope").and_then(JsonValue::as_str),
            Some("dataspace")
        );
        assert_eq!(
            scope.get("source_dataspace_id").and_then(JsonValue::as_u64),
            Some(10)
        );
        connect_norito_free(out_json_ptr);
        unsafe { free(out_signed_ptr.cast()) };
    }
    swift_parity_asset_encoder_test!(
        swift_parity_transfer_hash_matches_fixture,
        "swift-parity-transfer",
        connect_norito_encode_transfer_signed_transaction,
        "15.75",
        1_736_000_000_000,
        3_500,
        17,
    );
    swift_parity_asset_encoder_test!(
        swift_parity_mint_hash_matches_fixture,
        "swift-parity-mint",
        connect_norito_encode_mint_signed_transaction,
        "42.01",
        1_736_001_000_000,
        2_000,
        19,
    );
    swift_parity_asset_encoder_test!(
        swift_parity_burn_hash_matches_fixture,
        "swift-parity-burn",
        connect_norito_encode_burn_signed_transaction,
        "5.25",
        1_736_002_000_000,
        1_800,
        23,
    );
    #[test]
    fn transfer_encoder_constructs_exact_network_domain_for_every_canonical_quantity() {
        let _guard = chain_guard();
        let mut fixture = AssetSignedEncoderFixture::bank("transfer-success", 1, "10");
        let expected_network_id = unsafe {
            read_network_id_bridge(
                fixture.chain.as_ptr(),
                fixture.chain.as_bytes().len() as c_ulong,
            )
        }
        .expect("canonical test NetworkId must parse");
        let wide = "340282366920938463463374607431768211456.25";
        for amount in ["10", "1.25", wide] {
            fixture.quantity = cstring(amount);
            let (result, out_signed_ptr, out_signed_len, out_hash) = call_asset_signed_encoder!(
                connect_norito_encode_transfer_signed_transaction,
                fixture,
                creation_time_ms: 1,
                ttl_ms: 0,
                ttl_present: 0,
                nonce: 0,
                nonce_present: 0,
                fee_payment: AUTHORITY_FEE_PAYMENT_JSON,
            );
            assert_eq!(result, 0, "canonical Quantity {amount:?} must encode");
            assert!(!out_signed_ptr.is_null());
            assert!(out_signed_len > 0);
            assert_ne!(out_hash, [0u8; 32], "hash should be populated");
            let signed = decode_signed(out_signed_ptr, out_signed_len);
            assert_eq!(signed.network_id(), Some(&expected_network_id));
            let payload_json = norito::json::to_value(signed.payload())
                .expect("signed payload must project to canonical JSON");
            let payload = payload_json.as_object().expect("payload JSON object");
            let domain = payload
                .get("domain")
                .and_then(JsonValue::as_object)
                .expect("closed transaction domain object");
            assert_eq!(
                domain.get("kind").and_then(JsonValue::as_str),
                Some("network")
            );
            assert_eq!(
                domain.get("value").and_then(JsonValue::as_str),
                Some(fixture.chain.to_str().expect("NetworkId is UTF-8"))
            );
            for retired_key in ["chain", "chain_id", "chainId"] {
                assert!(
                    payload.get(retired_key).is_none() && domain.get(retired_key).is_none(),
                    "ordinary transaction JSON must not expose retired identity key {retired_key}"
                );
            }
            unsafe { free(out_signed_ptr.cast()) };
        }
    }
    asset_encoder_nonce_roundtrip_test!(
        transfer_encoder_nonce_roundtrip,
        "transfer-nonce",
        connect_norito_encode_transfer_signed_transaction,
        "10",
        17,
        message: "nonce should be encoded",
    );
    #[test]
    fn transfer_encoder_invalid_nonce() {
        let _guard = chain_guard();
        let fixture = AssetSignedEncoderFixture::bank("transfer-invalid-nonce", 0, "10");
        let (result, out_signed_ptr, out_signed_len, _out_hash) = call_asset_signed_encoder!(
            connect_norito_encode_transfer_signed_transaction,
            fixture,
            creation_time_ms: 1,
            ttl_ms: 0,
            ttl_present: 0,
            nonce: 0,
            nonce_present: 1,
            fee_payment: AUTHORITY_FEE_PAYMENT_JSON,
        );
        assert_eq!(result, ERR_INVALID_NONCE);
        assert!(out_signed_ptr.is_null());
        assert_eq!(out_signed_len, 0);
    }
    asset_encoder_nonce_roundtrip_test!(
        transfer_encoder_nonce_roundtrip_alg,
        "transfer-nonce-alg",
        connect_norito_encode_transfer_signed_transaction_alg,
        "10",
        9,
        algorithm: Algorithm::Ed25519,
        message: "nonce should be encoded",
    );
    #[test]
    fn transfer_encoder_requires_typed_sponsor_payment() {
        let _guard = chain_guard();
        let fixture = AssetSignedEncoderFixture::bank("transfer-sponsor-payment", 0, "10");
        let sponsor_account = sample_destination("paynet", 2);
        let sponsor_literal = sponsor_account.to_str().expect("utf8 sponsor account");
        let fee_payment = format!(
            r#"{{"payer":"sponsor","value":{{"program_id":{{"sponsor":"{sponsor_literal}","name":"wallet"}},"program_revision":3,"charge_limits":[],"gas_limit":null}}}}"#
        );
        let (result, out_signed_ptr, out_signed_len, _out_hash) = call_asset_signed_encoder!(
            connect_norito_encode_transfer_signed_transaction,
            fixture,
            creation_time_ms: 1,
            ttl_ms: 0,
            ttl_present: 0,
            nonce: 0,
            nonce_present: 0,
            fee_payment: fee_payment.as_bytes(),
        );
        assert_eq!(result, 0, "expected success");
        let signed = decode_signed(out_signed_ptr, out_signed_len);
        let (program_id, revision) = signed
            .fee_payment_intent()
            .sponsor_program()
            .expect("typed sponsor program");
        assert_eq!(program_id.to_string(), format!("{sponsor_literal}/wallet"));
        assert_eq!(revision, 3);
        assert!(signed.metadata().is_empty());
        unsafe { free(out_signed_ptr.cast()) };
    }
    asset_encoder_nonce_roundtrip_test!(
        mint_encoder_nonce_roundtrip,
        "mint-nonce",
        connect_norito_encode_mint_signed_transaction,
        "5",
        21,
    );
    asset_encoder_nonce_roundtrip_test!(
        mint_encoder_nonce_roundtrip_alg,
        "mint-nonce-alg",
        connect_norito_encode_mint_signed_transaction_alg,
        "5",
        22,
        algorithm: Algorithm::Ed25519,
    );
    asset_encoder_nonce_roundtrip_test!(
        burn_encoder_nonce_roundtrip,
        "burn-nonce",
        connect_norito_encode_burn_signed_transaction,
        "3",
        23,
    );
    asset_encoder_nonce_roundtrip_test!(
        burn_encoder_nonce_roundtrip_alg,
        "burn-nonce-alg",
        connect_norito_encode_burn_signed_transaction_alg,
        "3",
        24,
        algorithm: Algorithm::Ed25519,
    );
    #[test]
    fn confidential_memo_validator_accepts_canonical_v1_wire() {
        use iroha_data_model::confidential::{
            CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1, CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1,
            CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1, ConfidentialMemoRecipientSlotV1,
            ConfidentialMemoSuiteV1,
        };
        let envelope = ConfidentialMemoEnvelopeV1::new(
            core::array::from_fn(|index| {
                let suite = ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305;
                let index = u8::try_from(index).expect("slot index fits u8");
                ConfidentialMemoRecipientSlotV1::new(
                    suite,
                    vec![index + 1; suite.encapsulation_bytes()],
                    [index + 17; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
                    [index + 33; CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
                )
                .expect("canonical memo slot")
            }),
            [0xA5; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            vec![0x5A; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1],
        )
        .expect("canonical memo envelope");
        let wire = envelope.encode_wire().expect("encode canonical memo wire");
        let (result, out_ptr, out_len) = call_confidential_memo_validator(&wire);
        assert_eq!(result, 0);
        assert!(!out_ptr.is_null());
        let encoded = unsafe { slice::from_raw_parts(out_ptr, out_len as usize) };
        assert_eq!(encoded, wire);
        unsafe {
            free(out_ptr as *mut _);
        }
    }
    #[test]
    fn confidential_memo_validator_rejects_legacy_wire() {
        let mut old_wire = vec![1];
        old_wire.extend_from_slice(&[7; 32]);
        old_wire.extend_from_slice(&[2; 24]);
        old_wire.extend_from_slice(&[16, 0x5A]);
        let (result, out_ptr, out_len) = call_confidential_memo_validator(&old_wire);
        assert_eq!(result, -3);
        assert!(out_ptr.is_null());
        assert_eq!(out_len, 0);
    }
    #[test]
    fn confidential_memo_validator_rejects_trailing_bytes() {
        let wire = [
            iroha_data_model::confidential::CONFIDENTIAL_MEMO_WIRE_MAGIC_V1.as_slice(),
            &[0xFF],
        ]
        .concat();
        let (result, out_ptr, out_len) = call_confidential_memo_validator(&wire);
        assert_eq!(result, -3);
        assert!(out_ptr.is_null());
        assert_eq!(out_len, 0);
    }

    #[test]
    fn confidential_memo_keygen_seal_and_open_roundtrip() {
        let mut public_key_ptr = ptr::null_mut();
        let mut public_key_len = 0;
        let mut secret_key_ptr = ptr::null_mut();
        let mut secret_key_len = 0;
        let keygen = unsafe {
            connect_norito_generate_confidential_memo_keypair_v1(
                0,
                &mut public_key_ptr,
                &mut public_key_len,
                &mut secret_key_ptr,
                &mut secret_key_len,
            )
        };
        assert_eq!(keygen, 0);
        assert!(!public_key_ptr.is_null());
        assert!(!secret_key_ptr.is_null());

        let plaintext = b"native exact-eight-slot memo";
        let mut envelope_ptr = ptr::null_mut();
        let mut envelope_len = 0;
        let seal = unsafe {
            connect_norito_seal_confidential_memo_v1(
                0,
                public_key_ptr,
                public_key_len,
                1,
                plaintext.as_ptr(),
                plaintext.len() as c_ulong,
                &mut envelope_ptr,
                &mut envelope_len,
            )
        };
        assert_eq!(seal, 0);
        assert!(!envelope_ptr.is_null());

        let mut opened_ptr = ptr::null_mut();
        let mut opened_len = 0;
        let open = unsafe {
            connect_norito_open_confidential_memo_v1(
                0,
                secret_key_ptr,
                secret_key_len,
                envelope_ptr,
                envelope_len,
                &mut opened_ptr,
                &mut opened_len,
            )
        };
        assert_eq!(open, 0);
        assert_eq!(opened_len as usize, plaintext.len());
        assert_eq!(
            unsafe { slice::from_raw_parts(opened_ptr, opened_len as usize) },
            plaintext
        );

        connect_norito_free(public_key_ptr);
        unsafe { connect_norito_confidential_memo_secret_free_v1(secret_key_ptr, secret_key_len) };
        connect_norito_free(envelope_ptr);
        unsafe { connect_norito_confidential_memo_secret_free_v1(opened_ptr, opened_len) };
    }

    #[test]
    fn confidential_memo_native_boundary_rejects_unknown_suite() {
        let mut public_key_ptr = ptr::null_mut();
        let mut public_key_len = 0;
        let mut secret_key_ptr = ptr::null_mut();
        let mut secret_key_len = 0;
        assert_eq!(
            unsafe {
                connect_norito_generate_confidential_memo_keypair_v1(
                    0xFF,
                    &mut public_key_ptr,
                    &mut public_key_len,
                    &mut secret_key_ptr,
                    &mut secret_key_len,
                )
            },
            -3
        );
        assert!(public_key_ptr.is_null());
        assert!(secret_key_ptr.is_null());
    }
    #[test]
    fn connect_generate_keypair_private_output_derives_public_key() {
        let mut public_key = [0_u8; 32];
        let mut private_key = [0_u8; 32];
        let result = unsafe {
            connect_norito_connect_generate_keypair(
                public_key.as_mut_ptr(),
                private_key.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
        assert!(public_key.iter().any(|&byte| byte != 0));
        assert!(private_key.iter().any(|&byte| byte != 0));
        let mut derived_public_key = [0_u8; 32];
        let result = unsafe {
            connect_norito_connect_public_from_private(
                private_key.as_ptr(),
                derived_public_key.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
        assert_eq!(derived_public_key, public_key);
    }
    #[test]
    fn connect_derive_keys_rejects_low_order_peer_public_key() {
        let local_private_key = [0x01_u8; 32];
        let low_order_peer_public_key = [0x00_u8; 32];
        let session_id = [0x02_u8; 32];
        let mut app_key = [0xA5_u8; 32];
        let mut wallet_key = [0x5A_u8; 32];
        let result = unsafe {
            connect_norito_connect_derive_keys(
                local_private_key.as_ptr(),
                low_order_peer_public_key.as_ptr(),
                session_id.as_ptr(),
                app_key.as_mut_ptr(),
                wallet_key.as_mut_ptr(),
            )
        };
        assert_eq!(result, -2);
        assert_eq!(app_key, [0xA5_u8; 32]);
        assert_eq!(wallet_key, [0x5A_u8; 32]);
    }
    #[test]
    fn generic_privacy_transaction_encoders_are_absent_from_the_c_abi() {
        let source = bridge_source();
        let header = include_str!("../include/connect_norito_bridge.h");
        let retired_c_symbols = [
            ["connect_norito_encode_", "shield", "_signed_transaction"].concat(),
            [
                "connect_norito_encode_",
                "shield",
                "_signed_transaction_alg",
            ]
            .concat(),
            ["connect_norito_encode_", "unshield", "_signed_transaction"].concat(),
            [
                "connect_norito_encode_",
                "unshield",
                "_signed_transaction_alg",
            ]
            .concat(),
            [
                "connect_norito_encode_",
                "zk_transfer",
                "_signed_transaction",
            ]
            .concat(),
            [
                "connect_norito_encode_",
                "zk_transfer",
                "_signed_transaction_alg",
            ]
            .concat(),
        ];
        for (label, contents) in [("Rust source", source), ("C header", header)] {
            for symbol in &retired_c_symbols {
                assert!(
                    !contents.contains(symbol),
                    "{label} must not expose retired generic encoder {symbol}"
                );
            }
        }
        for retired_constructor in [
            ["zk::", "Sh", "ield::new"].concat(),
            ["zk::", "Zk", "Transfer::new"].concat(),
            ["zk::", "Un", "shield::new"].concat(),
        ] {
            assert!(
                !source.contains(&retired_constructor),
                "bridge must not compile retired constructor {retired_constructor}"
            );
        }
        assert!(header.contains("connect_norito_encode_register_zk_asset_signed_transaction"));
        assert!(header.contains("vk_unshield"));
        let retired_shield_parameter = ["vk_", "shield"].concat();
        assert!(!header.contains(&retired_shield_parameter));
        assert!(!source.contains(&retired_shield_parameter));
        assert_eq!(
            crate::confidential_note_ffi::connect_norito_confidential_note_derivation_revision_v3(),
            1,
            "the retained mobile boundary exposes note derivation, not proof construction"
        );
    }
    #[test]
    fn transfer_encoder_invalid_quantity() {
        let _guard = chain_guard();
        let mut fixture = AssetSignedEncoderFixture::bank("transfer-invalid-quantity", 0, "NaN");
        let oversized = format!("1{}", "0".repeat(200));
        for amount in ["NaN", "-1", "01", "1.0", "+1", " 1", "1 ", "1e3"]
            .into_iter()
            .map(str::to_owned)
            .chain(core::iter::once(oversized))
        {
            fixture.quantity = cstring(&amount);
            let (result, out_signed_ptr, out_signed_len, out_hash) = call_asset_signed_encoder!(
                connect_norito_encode_transfer_signed_transaction,
                fixture,
                creation_time_ms: 1,
                ttl_ms: 0,
                ttl_present: 0,
                nonce: 0,
                nonce_present: 0,
                fee_payment: AUTHORITY_FEE_PAYMENT_JSON,
            );
            assert_eq!(
                result, ERR_QUANTITY_PARSE,
                "invalid public Quantity {amount:?} must be rejected"
            );
            assert!(out_signed_ptr.is_null());
            assert_eq!(out_signed_len, 0);
            assert_eq!(out_hash, [0u8; 32], "hash should remain unchanged");
        }
    }
    #[test]
    fn multisig_register_encoder_success() {
        let _guard = chain_guard();
        let chain = network_id_cstring("multisig-register");
        let (authority, private) = sample_account("default", 0);
        let scoped_account = cstring(authority.to_str().unwrap());
        let member_a_str = sample_destination("default", 2);
        let member_b_str = sample_destination("default", 3);
        let member_a =
            AccountId::parse_encoded(member_a_str.to_str().unwrap()).expect("member A account id");
        let member_b =
            AccountId::parse_encoded(member_b_str.to_str().unwrap()).expect("member B account id");
        let mut members = BTreeMap::new();
        members.insert(member_a, 2);
        members.insert(member_b, 1);
        let spec = MultisigSpec::new(
            members,
            NonZeroU16::new(2).unwrap(),
            NonZeroU64::new(60_000).unwrap(),
        );
        let spec_json = norito::json::to_string(
            &norito::json::value::to_value(&spec).expect("spec json value"),
        )
        .expect("spec json");
        let spec_c = cstring(&spec_json);
        let mut out_signed_ptr: *mut u8 = ptr::null_mut();
        let mut out_signed_len: c_ulong = 0;
        let mut out_hash = [0u8; 32];
        let result = unsafe {
            connect_norito_encode_multisig_register_signed_transaction(
                chain.as_ptr(),
                chain.as_bytes().len() as c_ulong,
                authority.as_ptr(),
                authority.as_bytes().len() as c_ulong,
                1,
                0,
                0,
                spec_c.as_ptr(),
                spec_c.as_bytes().len() as c_ulong,
                scoped_account.as_ptr(),
                scoped_account.as_bytes().len() as c_ulong,
                AUTHORITY_FEE_PAYMENT_JSON.as_ptr(),
                AUTHORITY_FEE_PAYMENT_JSON.len() as c_ulong,
                private.as_ptr(),
                private.len() as c_ulong,
                &mut out_signed_ptr,
                &mut out_signed_len,
                out_hash.as_mut_ptr(),
                out_hash.len() as c_ulong,
            )
        };
        assert_eq!(result, 0, "expected success");
        assert!(!out_signed_ptr.is_null());
        assert!(out_signed_len > 0);
        unsafe { free(out_signed_ptr as *mut _) };
    }
    #[test]
    fn multisig_register_encoder_invalid_spec() {
        let _guard = chain_guard();
        let chain = network_id_cstring("multisig-register-invalid");
        let (authority, private) = sample_account("bank", 0);
        let mut out_signed_ptr: *mut u8 = ptr::null_mut();
        let mut out_signed_len: c_ulong = 0;
        let mut out_hash = [0u8; 32];
        let invalid_spec = cstring("{}");
        let result = unsafe {
            connect_norito_encode_multisig_register_signed_transaction(
                chain.as_ptr(),
                chain.as_bytes().len() as c_ulong,
                authority.as_ptr(),
                authority.as_bytes().len() as c_ulong,
                1,
                0,
                0,
                invalid_spec.as_ptr(),
                invalid_spec.as_bytes().len() as c_ulong,
                authority.as_ptr(),
                authority.as_bytes().len() as c_ulong,
                AUTHORITY_FEE_PAYMENT_JSON.as_ptr(),
                AUTHORITY_FEE_PAYMENT_JSON.len() as c_ulong,
                private.as_ptr(),
                private.len() as c_ulong,
                &mut out_signed_ptr,
                &mut out_signed_len,
                out_hash.as_mut_ptr(),
                out_hash.len() as c_ulong,
            )
        };
        assert_ne!(result, 0, "expected failure for invalid spec");
        assert!(out_signed_ptr.is_null());
    }
}
#[cfg(test)]
mod secp256k1_tests {
    use super::*;
    use hex::decode;
    const PRIVATE_KEY: &str = "e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713";
    const PUBLIC_KEY: &str = "0242c1e1f775237a26da4fd51b8d75ee2709711f6e90303e511169a324ef0789c0";
    const SIGNATURE: &str = "0aab347be3530a3fd7d91c354956561101e6f273b8a1ea3d414f82fbd5939db34b99c54c16c45bf4cde8193b58d718e7efa8c055e7add7d9c9cbe8935e849200";
    const MESSAGE: &[u8] = b"This is a dummy message for use with tests";
    #[test]
    fn secp256k1_signs_and_verifies() {
        let private = decode(PRIVATE_KEY).expect("valid private key hex");
        let expected_public = decode(PUBLIC_KEY).expect("valid public key hex");
        let expected_signature = decode(SIGNATURE).expect("valid signature hex");
        let mut public_out = [0u8; 33];
        let mut signature_out = [0u8; 64];
        let public_status = unsafe {
            connect_norito_secp256k1_public_key(
                private.as_ptr(),
                private.len() as c_ulong,
                public_out.as_mut_ptr(),
                public_out.len() as c_ulong,
            )
        };
        assert_eq!(public_status, 0, "public key derivation failed");
        assert_eq!(public_out.as_slice(), expected_public.as_slice());
        let sign_status = unsafe {
            connect_norito_secp256k1_sign(
                private.as_ptr(),
                private.len() as c_ulong,
                MESSAGE.as_ptr(),
                MESSAGE.len() as c_ulong,
                signature_out.as_mut_ptr(),
                signature_out.len() as c_ulong,
            )
        };
        assert_eq!(sign_status, 0, "signing failed");
        assert_eq!(signature_out.as_slice(), expected_signature.as_slice());
        let verify_status = unsafe {
            connect_norito_secp256k1_verify(
                public_out.as_ptr(),
                public_out.len() as c_ulong,
                MESSAGE.as_ptr(),
                MESSAGE.len() as c_ulong,
                signature_out.as_ptr(),
                signature_out.len() as c_ulong,
            )
        };
        assert_eq!(verify_status, 1, "signature did not verify");
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_mint_signed_transaction =>
        connect_norito_encode_mint_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            nonce: u32,
            nonce_present: c_uchar,
            asset_definition_ptr: *const c_char,
            asset_definition_len: c_ulong,
            quantity_ptr: *const c_char,
            quantity_len: c_ulong,
            destination_ptr: *const c_char,
            destination_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let inputs = unsafe {
            gather_asset_tx_inputs_with_parser(
                AssetInputPointers {
                    network_id_ptr,
                    network_id_len,
                    authority_ptr,
                    authority_len,
                    asset_definition_ptr,
                    asset_definition_len,
                    quantity_ptr,
                    quantity_len,
                    destination_ptr,
                    destination_len,
                    ttl_ms,
                    ttl_present,
                    private_key_ptr,
                    private_key_len,
                },
                |bytes| parse_private_key_with_algorithm(bytes, algorithm),
            )?
        };
        let AssetTxInputs {
            network_id,
            authority,
            asset_definition,
            asset_scope,
            destination,
            quantity,
            ttl,
            private_key,
        } = inputs;
        let nonce = parse_nonce(nonce, nonce_present != 0)?;
        let asset_id =
            AssetId::with_scope(asset_definition.clone(), destination.clone(), asset_scope);
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_asset_transaction_with_nonce(
            network_id,
            authority,
            AssetTransactionTiming {
                creation_time_ms,
                ttl,
                nonce,
            },
            fee_payment,
            private_key,
            || {
                let mint = Mint::asset_quantity(quantity, asset_id);
                Executable::from([InstructionBox::from(mint)])
            },
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_multisig_register_signed_transaction =>
        connect_norito_encode_multisig_register_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            spec_ptr: *const c_char,
            spec_len: c_ulong,
            account_ptr: *const c_char,
            account_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        if private_key_ptr.is_null() || account_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let account_str = unsafe { read_string_bridge(account_ptr, account_len) }?;
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let account = parse_account_id(account_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let spec = parse_multisig_spec_bytes(spec_ptr, spec_len)?;
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_asset_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            {
                let spec = spec.clone();
                let account = account.clone();
                move || {
                    let register = MultisigRegister::with_account(
                        account.clone(),
                        None::<DomainId>,
                        spec.clone(),
                    );
                    Executable::from([InstructionBox::from(register)])
                }
            },
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_burn_signed_transaction =>
        connect_norito_encode_burn_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            nonce: u32,
            nonce_present: c_uchar,
            asset_definition_ptr: *const c_char,
            asset_definition_len: c_ulong,
            quantity_ptr: *const c_char,
            quantity_len: c_ulong,
            destination_ptr: *const c_char,
            destination_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let inputs = unsafe {
            gather_asset_tx_inputs_with_parser(
                AssetInputPointers {
                    network_id_ptr,
                    network_id_len,
                    authority_ptr,
                    authority_len,
                    asset_definition_ptr,
                    asset_definition_len,
                    quantity_ptr,
                    quantity_len,
                    destination_ptr,
                    destination_len,
                    ttl_ms,
                    ttl_present,
                    private_key_ptr,
                    private_key_len,
                },
                |bytes| parse_private_key_with_algorithm(bytes, algorithm),
            )?
        };
        let AssetTxInputs {
            network_id,
            authority,
            asset_definition,
            asset_scope,
            destination,
            quantity,
            ttl,
            private_key,
        } = inputs;
        let nonce = parse_nonce(nonce, nonce_present != 0)?;
        let asset_id = AssetId::with_scope(asset_definition, destination.clone(), asset_scope);
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_asset_transaction_with_nonce(
            network_id,
            authority,
            AssetTransactionTiming {
                creation_time_ms,
                ttl,
                nonce,
            },
            fee_payment,
            private_key,
            || {
                let burn = Burn::asset_quantity(quantity, asset_id);
                Executable::from([InstructionBox::from(burn)])
            },
        )?;
    }
}
define_ed25519_signed_transaction_wrapper! {
    connect_norito_encode_claim_identifier_signed_transaction =>
        connect_norito_encode_claim_identifier_signed_transaction_alg(
            network_id_ptr: *const c_char,
            network_id_len: c_ulong,
            authority_ptr: *const c_char,
            authority_len: c_ulong,
            creation_time_ms: u64,
            ttl_ms: u64,
            ttl_present: c_uchar,
            account_ptr: *const c_char,
            account_len: c_ulong,
            receipt_ptr: *const c_char,
            receipt_len: c_ulong,
            fee_payment_json_ptr: *const c_uchar,
            fee_payment_json_len: c_ulong,
            private_key_ptr: *const c_uchar,
            private_key_len: c_ulong,
        )
    identifiers: (algorithm_code, signed_bytes, hash_bytes);
    {
        if private_key_ptr.is_null() || account_ptr.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let algorithm = parse_algorithm_code(algorithm_code)?;
        let authority_str = unsafe { read_string_bridge(authority_ptr, authority_len) }?;
        let account_str = unsafe { read_string_bridge(account_ptr, account_len) }?;
        let network_id = unsafe { read_network_id_bridge(network_id_ptr, network_id_len) }?;
        let authority = parse_account_id(authority_str)?;
        let account = parse_account_id(account_str)?;
        let ttl = parse_ttl(ttl_ms, ttl_present != 0)?;
        let key_slice = unsafe { slice::from_raw_parts(private_key_ptr, private_key_len as usize) };
        let private_key = parse_private_key_with_algorithm(key_slice, algorithm)?;
        let receipt = parse_identifier_receipt_bytes(receipt_ptr, receipt_len)?;
        validate_identifier_claim_account(&account, &receipt)?;
        let fee_payment =
            unsafe { parse_fee_payment_intent_bridge(fee_payment_json_ptr, fee_payment_json_len)? };
        let (signed_bytes, hash_bytes) = encode_instruction_transaction(
            network_id,
            authority,
            creation_time_ms,
            ttl,
            fee_payment,
            private_key,
            InstructionBox::from(ClaimIdentifier { account, receipt }),
        )?;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_signed_transaction_json(
    signed_ptr: *const c_uchar,
    signed_len: c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if signed_ptr.is_null() || out_json_ptr.is_null() || out_json_len.is_null() {
            return -1;
        }
        let bytes = slice::from_raw_parts(signed_ptr, signed_len as usize);
        let tx = match decode_signed_transaction(bytes) {
            Ok(v) => v,
            Err(_) => return -2,
        };
        let mut json_value = match norito::json::value::to_value(&tx) {
            Ok(value) => value,
            Err(_) => return -3,
        };
        if let JsonValue::Object(root) = &mut json_value {
            root.insert(
                "bridge_debug".into(),
                signed_transaction_bridge_debug_json(&tx),
            );
        }
        write_output_result(
            norito::json::to_vec(&json_value),
            out_json_ptr,
            out_json_len,
            -3,
            ERR_ALLOC,
        )
    }
}
/// Decode a canonical internal `AssetId` balance-bucket literal into readable JSON fields.
///
/// Response JSON object fields:
/// - `asset_id`: canonical internal asset balance-bucket literal
///   (`<base58-asset-definition-id>#<i105-account-id>`)
/// - `asset_definition_id`: canonical asset definition id (unprefixed Base58 address)
/// - `account_id`: canonical I105 account id (i105 literal)
///
/// # Safety
/// All pointer arguments must be valid and non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_asset_id_json(
    asset_ptr: *const c_char,
    asset_len: c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let result = (|| -> BridgeResult<()> {
        if out_json_ptr.is_null() || out_json_len.is_null() {
            return Err(BridgeError::NullPtr);
        }
        let asset_literal = unsafe { read_string_bridge(asset_ptr, asset_len) }?;
        let asset = AssetId::parse_literal(&asset_literal).map_err(|_| BridgeError::AssetId)?;
        let payload = JsonValue::Object(JsonMap::from_iter([
            (
                "asset_id".to_owned(),
                JsonValue::String(asset.canonical_literal()),
            ),
            (
                "asset_definition_id".to_owned(),
                JsonValue::String(asset.definition().to_string()),
            ),
            (
                "account_id".to_owned(),
                JsonValue::String(asset.account().to_string()),
            ),
        ]));
        let json_bytes = norito::json::to_vec(&payload).map_err(|_| BridgeError::JsonSerialize)?;
        unsafe { write_bytes_bridge(out_json_ptr, out_json_len, &json_bytes) }?;
        Ok(())
    })();
    bridge_result_to_code(result)
}
/// Decode a Norito-encoded `TransactionSubmissionReceipt` into JSON.
///
/// # Safety
/// All pointer arguments must be valid and non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_decode_transaction_receipt_json(
    receipt_ptr: *const c_uchar,
    receipt_len: c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    unsafe {
        if receipt_ptr.is_null() || out_json_ptr.is_null() || out_json_len.is_null() {
            return -1;
        }
        let bytes = slice::from_raw_parts(receipt_ptr, receipt_len as usize);
        let receipt: TransactionSubmissionReceipt = match norito::decode_from_bytes(bytes) {
            Ok(v) => v,
            Err(_) => return -2,
        };
        write_output_result(
            norito::json::to_vec(&receipt),
            out_json_ptr,
            out_json_len,
            -3,
            ERR_ALLOC,
        )
    }
}
/// Separate process acceleration attempt envelope. Zero is a real ceiling.
/// Caller-owned State execution destinations retain their original lease.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct connect_norito_acceleration_resource_limits {
    /// Aggregate ordinary host backing bytes.
    pub host_bytes: u64,
    /// Aggregate pinned host backing bytes.
    pub pinned_bytes: u64,
    /// Aggregate requested device backing bytes.
    pub device_bytes: u64,
    /// Complete attempted-work owner count.
    pub in_flight: u64,
    /// Variable Rust control backing bytes.
    pub metadata_bytes: u64,
    /// Lifetime-observed physical device records.
    pub observed_devices: u64,
    /// Ordinal probes per discovery pass; must fit u32.
    pub discovery_ordinals: u64,
    /// Aggregate native module owner count.
    pub modules: u64,
    /// Aggregate native stream owner count.
    pub streams: u64,
    /// Immutable artifact bytes per module, including its NUL.
    pub artifact_bytes: u64,
}
impl Default for connect_norito_acceleration_resource_limits {
    fn default() -> Self {
        encode_acceleration_resource_limits(iroha_accel::RegistryLimits::STANDARD)
    }
}

fn encode_acceleration_resource_limits(
    limits: iroha_accel::RegistryLimits,
) -> connect_norito_acceleration_resource_limits {
    connect_norito_acceleration_resource_limits {
        host_bytes: limits.work.host_bytes as u64,
        pinned_bytes: limits.work.pinned_bytes as u64,
        device_bytes: limits.work.device_bytes as u64,
        in_flight: limits.work.in_flight as u64,
        metadata_bytes: limits.metadata_bytes as u64,
        observed_devices: limits.devices as u64,
        discovery_ordinals: limits.discovery_ordinals as u64,
        modules: limits.modules as u64,
        streams: limits.streams as u64,
        artifact_bytes: limits.artifact_bytes as u64,
    }
}

fn decode_acceleration_resource_limits(
    limits: connect_norito_acceleration_resource_limits,
) -> Result<iroha_accel::RegistryLimits, ()> {
    let size = |value| usize::try_from(value).map_err(|_| ());
    Ok(iroha_accel::RegistryLimits {
        metadata_bytes: size(limits.metadata_bytes)?,
        devices: size(limits.observed_devices)?,
        discovery_ordinals: u32::try_from(limits.discovery_ordinals).map_err(|_| ())?,
        modules: size(limits.modules)?,
        streams: size(limits.streams)?,
        artifact_bytes: size(limits.artifact_bytes)?,
        work: iroha_accel::GpuResourceLimits {
            host_bytes: size(limits.host_bytes)?,
            pinned_bytes: size(limits.pinned_bytes)?,
            device_bytes: size(limits.device_bytes)?,
            in_flight: size(limits.in_flight)?,
        },
    })
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct connect_norito_acceleration_config {
    pub enable_simd: u8,
    pub enable_metal: u8,
    pub enable_cuda: u8,
    pub max_gpus: u64,
    pub max_gpus_present: u8,
    pub merkle_min_leaves_gpu: u64,
    pub merkle_min_leaves_gpu_present: u8,
    pub merkle_min_leaves_metal: u64,
    pub merkle_min_leaves_metal_present: u8,
    pub merkle_min_leaves_cuda: u64,
    pub merkle_min_leaves_cuda_present: u8,
    pub prefer_cpu_sha2_max_leaves_aarch64: u64,
    pub prefer_cpu_sha2_max_leaves_aarch64_present: u8,
    pub prefer_cpu_sha2_max_leaves_x86: u64,
    pub prefer_cpu_sha2_max_leaves_x86_present: u8,
    /// Complete process attempt envelope, independent of State destination funding.
    pub resource_limits: connect_norito_acceleration_resource_limits,
}
impl Default for connect_norito_acceleration_config {
    fn default() -> Self {
        encode_acceleration_config(AccelerationConfig::default())
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct connect_norito_acceleration_backend_status {
    pub supported: u8,
    pub configured: u8,
    pub available: u8,
    pub parity_ok: u8,
    pub last_error_ptr: *mut c_uchar,
    pub last_error_len: c_ulong,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct connect_norito_acceleration_state {
    pub config: connect_norito_acceleration_config,
    pub simd: connect_norito_acceleration_backend_status,
    pub metal: connect_norito_acceleration_backend_status,
    pub cuda: connect_norito_acceleration_backend_status,
}
fn encode_acceleration_config(cfg: AccelerationConfig) -> connect_norito_acceleration_config {
    let (max_gpus, max_gpus_present) = option_to_ffi(cfg.max_gpus);
    let (merkle_min_leaves_gpu, merkle_min_leaves_gpu_present) =
        option_to_ffi(cfg.merkle_min_leaves_gpu);
    let (merkle_min_leaves_metal, merkle_min_leaves_metal_present) =
        option_to_ffi(cfg.merkle_min_leaves_metal);
    let (merkle_min_leaves_cuda, merkle_min_leaves_cuda_present) =
        option_to_ffi(cfg.merkle_min_leaves_cuda);
    let (prefer_cpu_sha2_max_leaves_aarch64, prefer_cpu_sha2_max_leaves_aarch64_present) =
        option_to_ffi(cfg.prefer_cpu_sha2_max_leaves_aarch64);
    let (prefer_cpu_sha2_max_leaves_x86, prefer_cpu_sha2_max_leaves_x86_present) =
        option_to_ffi(cfg.prefer_cpu_sha2_max_leaves_x86);
    connect_norito_acceleration_config {
        enable_simd: bool_to_u8(cfg.enable_simd),
        enable_metal: bool_to_u8(cfg.enable_metal),
        enable_cuda: bool_to_u8(cfg.enable_cuda),
        max_gpus,
        max_gpus_present,
        merkle_min_leaves_gpu,
        merkle_min_leaves_gpu_present,
        merkle_min_leaves_metal,
        merkle_min_leaves_metal_present,
        merkle_min_leaves_cuda,
        merkle_min_leaves_cuda_present,
        prefer_cpu_sha2_max_leaves_aarch64,
        prefer_cpu_sha2_max_leaves_aarch64_present,
        prefer_cpu_sha2_max_leaves_x86,
        prefer_cpu_sha2_max_leaves_x86_present,
        resource_limits: encode_acceleration_resource_limits(cfg.resource_limits),
    }
}
fn encode_backend_status(
    status: BackendRuntimeStatus,
    last_error: Option<String>,
) -> connect_norito_acceleration_backend_status {
    let (last_error_ptr, last_error_len) = if let Some(message) = last_error {
        let bytes = message.into_bytes();
        if bytes.is_empty() {
            (ptr::null_mut(), 0)
        } else {
            let len = bytes.len();
            let mem = unsafe { malloc(len) };
            if mem.is_null() {
                (ptr::null_mut(), 0)
            } else {
                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), mem as *mut u8, len);
                }
                (mem as *mut u8, len as c_ulong)
            }
        }
    } else {
        (ptr::null_mut(), 0)
    };
    connect_norito_acceleration_backend_status {
        supported: bool_to_u8(status.supported),
        configured: bool_to_u8(status.configured),
        available: bool_to_u8(status.available),
        parity_ok: bool_to_u8(status.parity_ok),
        last_error_ptr,
        last_error_len,
    }
}
fn decode_acceleration_config(
    cfg: &connect_norito_acceleration_config,
) -> Result<AccelerationConfig, ()> {
    let boolean = |value| match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(()),
    };
    let optional = |present, value| match (present, value) {
        (0, 0) => Ok(None),
        (1, value) => usize::try_from(value).map(Some).map_err(|_| ()),
        _ => Err(()),
    };
    Ok(AccelerationConfig {
        resource_limits: decode_acceleration_resource_limits(cfg.resource_limits)?,
        enable_simd: boolean(cfg.enable_simd)?,
        enable_metal: boolean(cfg.enable_metal)?,
        enable_cuda: boolean(cfg.enable_cuda)?,
        max_gpus: optional(cfg.max_gpus_present, cfg.max_gpus)?,
        merkle_min_leaves_gpu: optional(
            cfg.merkle_min_leaves_gpu_present,
            cfg.merkle_min_leaves_gpu,
        )?,
        merkle_min_leaves_metal: optional(
            cfg.merkle_min_leaves_metal_present,
            cfg.merkle_min_leaves_metal,
        )?,
        merkle_min_leaves_cuda: optional(
            cfg.merkle_min_leaves_cuda_present,
            cfg.merkle_min_leaves_cuda,
        )?,
        prefer_cpu_sha2_max_leaves_aarch64: optional(
            cfg.prefer_cpu_sha2_max_leaves_aarch64_present,
            cfg.prefer_cpu_sha2_max_leaves_aarch64,
        )?,
        prefer_cpu_sha2_max_leaves_x86: optional(
            cfg.prefer_cpu_sha2_max_leaves_x86_present,
            cfg.prefer_cpu_sha2_max_leaves_x86,
        )?,
    })
}

/// Apply the complete first-release record, or restore defaults for a null pointer.
/// Returns zero on application, -2 for malformed flags/counts, or -3 for an
/// incorrect record length. Rejections occur before configuration mutation.
///
/// # Safety
/// For an exact nonzero length, the pointer must reference a readable complete
/// current record. Null plus length zero restores defaults. All other lengths
/// are rejected before accessing the pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_acceleration_config_set_v1(
    cfg: *const connect_norito_acceleration_config,
    cfg_len: usize,
) -> c_int {
    if cfg_len
        != if cfg.is_null() {
            0
        } else {
            std::mem::size_of::<connect_norito_acceleration_config>()
        }
    {
        return -3;
    }
    let rust_cfg = match unsafe { cfg.as_ref() } {
        None => AccelerationConfig::default(),
        Some(cfg) => match decode_acceleration_config(cfg) {
            Ok(value) => value,
            Err(()) => return -2,
        },
    };
    ivm::set_acceleration_config(rust_cfg);
    0
}
/// Write the current requested acceleration configuration into an exact V1 record.
/// Returns `0` on success, `-1` for a null output with the exact current size,
/// or `-3` for any other size, before pointer access or output mutation.
///
/// # Safety
/// With the exact record size and a non-null pointer, `out_cfg` must be aligned
/// and valid for writing one complete [`connect_norito_acceleration_config`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_acceleration_config_get_v1(
    out_cfg: *mut connect_norito_acceleration_config,
    out_len: usize,
) -> c_int {
    if out_len != std::mem::size_of::<connect_norito_acceleration_config>() {
        return -3;
    }
    unsafe {
        if out_cfg.is_null() {
            return -1;
        }
        let cfg = ivm::acceleration_config();
        let encoded = encode_acceleration_config(cfg);
        ptr::write(out_cfg, encoded);
        0
    }
}
/// Write current requested policy and backend diagnostics into an exact V1 record.
/// Returns `0` on success, `-1` for a null output with the exact current size,
/// or `-3` for any other size, before pointer access or diagnostic allocation.
/// Each non-null diagnostic byte pointer in the returned backend records is
/// caller-owned and must be released exactly once with [`connect_norito_free`]
/// after use. The bytes remain valid until that release.
///
/// # Safety
/// With the exact record size and a non-null pointer, `out_state` must be aligned
/// and valid for writing one complete [`connect_norito_acceleration_state`].
/// Release diagnostics from a previous record before overwriting its storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_acceleration_state_get_v1(
    out_state: *mut connect_norito_acceleration_state,
    out_len: usize,
) -> c_int {
    if out_len != std::mem::size_of::<connect_norito_acceleration_state>() {
        return -3;
    }
    unsafe {
        if out_state.is_null() {
            return -1;
        }
        let cfg = ivm::acceleration_config();
        let runtime = ivm::acceleration_runtime_status();
        let errors = ivm::acceleration_runtime_errors();
        let ivm::AccelerationErrorStatus { simd, metal, cuda } = errors;
        let state = connect_norito_acceleration_state {
            config: encode_acceleration_config(cfg),
            simd: encode_backend_status(runtime.simd, simd),
            metal: encode_backend_status(runtime.metal, metal),
            cuda: encode_backend_status(runtime.cuda, cuda),
        };
        ptr::write(out_state, state);
        0
    }
}
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
mod platform_jni;
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]
#[allow(unused_imports)]
pub use platform_jni::*;
fn providers_from_json(value: &JsonValue) -> Result<Vec<LocalProviderInput>, c_int> {
    let arr = value.as_array().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let mut providers = Vec::with_capacity(arr.len());
    for entry in arr {
        let obj = entry.as_object().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
        let name = obj
            .get("name")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
        let path = obj
            .get("path")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
        let max_concurrent = obj
            .get("max_concurrent")
            .and_then(JsonValue::as_u64)
            .map(|value| {
                let converted =
                    u32::try_from(value).map_err(|_| ERR_FETCH_INVALID_MAX_CONCURRENT)?;
                if converted == 0 {
                    Err(ERR_FETCH_INVALID_MAX_CONCURRENT)
                } else {
                    Ok(converted)
                }
            })
            .transpose()?;
        let weight = obj
            .get("weight")
            .and_then(JsonValue::as_u64)
            .map(|value| u32::try_from(value).map_err(|_| ERR_FETCH_INVALID_WEIGHT))
            .transpose()?;
        let metadata = obj
            .get("metadata")
            .map(|value| provider_metadata_from_json(value, &name))
            .transpose()?;
        providers.push(LocalProviderInput {
            name,
            path: PathBuf::from(path),
            max_concurrent,
            weight,
            metadata,
        });
    }
    Ok(providers)
}
fn provider_metadata_from_json(
    value: &JsonValue,
    alias: &str,
) -> Result<ProviderMetadataInput, c_int> {
    let obj = value.as_object().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let provider_id = Some(
        obj.get("provider_id")
            .and_then(JsonValue::as_str)
            .unwrap_or(alias)
            .to_owned(),
    );
    let profile_id = obj
        .get("profile_id")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let profile_aliases =
        if let Some(aliases) = obj.get("profile_aliases").and_then(JsonValue::as_array) {
            let mut list = Vec::with_capacity(aliases.len());
            for alias in aliases {
                list.push(alias.as_str().ok_or(ERR_FETCH_PROVIDERS_JSON)?.to_owned());
            }
            Some(list)
        } else {
            None
        };
    let availability = obj
        .get("availability")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let stake_amount = obj
        .get("stake_amount")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let max_streams = obj
        .get("max_streams")
        .and_then(JsonValue::as_u64)
        .map(|value| u32::try_from(value).map_err(|_| ERR_FETCH_PROVIDERS_JSON))
        .transpose()?;
    let refresh_deadline = obj.get("refresh_deadline").and_then(JsonValue::as_u64);
    let expires_at = obj.get("expires_at").and_then(JsonValue::as_u64);
    let ttl_secs = obj.get("ttl_secs").and_then(JsonValue::as_u64);
    let allow_unknown_capabilities = obj
        .get("allow_unknown_capabilities")
        .and_then(JsonValue::as_bool);
    let capability_names =
        if let Some(names) = obj.get("capability_names").and_then(JsonValue::as_array) {
            let mut list = Vec::with_capacity(names.len());
            for name in names {
                list.push(name.as_str().ok_or(ERR_FETCH_PROVIDERS_JSON)?.to_owned());
            }
            Some(list)
        } else {
            None
        };
    let rendezvous_topics =
        if let Some(topics) = obj.get("rendezvous_topics").and_then(JsonValue::as_array) {
            let mut list = Vec::with_capacity(topics.len());
            for topic in topics {
                list.push(topic.as_str().ok_or(ERR_FETCH_PROVIDERS_JSON)?.to_owned());
            }
            Some(list)
        } else {
            None
        };
    let notes = obj
        .get("notes")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let range_capability = obj
        .get("range_capability")
        .map(range_capability_from_json)
        .transpose()?;
    let stream_budget = obj
        .get("stream_budget")
        .map(stream_budget_from_json)
        .transpose()?;
    let transport_hints = obj
        .get("transport_hints")
        .map(transport_hints_from_json)
        .transpose()?;
    Ok(ProviderMetadataInput {
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
    })
}
fn range_capability_from_json(value: &JsonValue) -> Result<RangeCapabilityInput, c_int> {
    let obj = value.as_object().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let max_chunk_span = obj
        .get("max_chunk_span")
        .and_then(JsonValue::as_u64)
        .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let min_granularity = obj
        .get("min_granularity")
        .and_then(JsonValue::as_u64)
        .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    Ok(RangeCapabilityInput {
        max_chunk_span: u32::try_from(max_chunk_span).map_err(|_| ERR_FETCH_PROVIDERS_JSON)?,
        min_granularity: u32::try_from(min_granularity).map_err(|_| ERR_FETCH_PROVIDERS_JSON)?,
        supports_sparse_offsets: obj
            .get("supports_sparse_offsets")
            .and_then(JsonValue::as_bool),
        requires_alignment: obj.get("requires_alignment").and_then(JsonValue::as_bool),
        supports_merkle_proof: obj
            .get("supports_merkle_proof")
            .and_then(JsonValue::as_bool),
    })
}
fn stream_budget_from_json(value: &JsonValue) -> Result<StreamBudgetInput, c_int> {
    let obj = value.as_object().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let max_in_flight = obj
        .get("max_in_flight")
        .and_then(JsonValue::as_u64)
        .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let max_bytes_per_sec = obj
        .get("max_bytes_per_sec")
        .and_then(JsonValue::as_u64)
        .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let burst_bytes = obj.get("burst_bytes").and_then(JsonValue::as_u64);
    Ok(StreamBudgetInput {
        max_in_flight: u16::try_from(max_in_flight).map_err(|_| ERR_FETCH_PROVIDERS_JSON)?,
        max_bytes_per_sec,
        burst_bytes,
    })
}
fn transport_hints_from_json(value: &JsonValue) -> Result<Vec<TransportHintInput>, c_int> {
    let arr = value.as_array().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
    let mut hints = Vec::with_capacity(arr.len());
    for entry in arr {
        let obj = entry.as_object().ok_or(ERR_FETCH_PROVIDERS_JSON)?;
        let protocol = obj
            .get("protocol")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
        let protocol_id = obj
            .get("protocol_id")
            .and_then(JsonValue::as_u64)
            .map(|value| u8::try_from(value).map_err(|_| ERR_FETCH_PROVIDERS_JSON))
            .transpose()?
            .ok_or(ERR_FETCH_PROVIDERS_JSON)?;
        let priority = obj
            .get("priority")
            .map(|value| value.as_u64().ok_or(ERR_FETCH_PROVIDERS_JSON))
            .transpose()?
            .unwrap_or(0);
        hints.push(TransportHintInput {
            protocol,
            protocol_id,
            priority: u8::try_from(priority).map_err(|_| ERR_FETCH_PROVIDERS_JSON)?,
        });
    }
    Ok(hints)
}
fn telemetry_from_json(value: &JsonValue) -> Result<TelemetryEntryInput, c_int> {
    let obj = value.as_object().ok_or(ERR_FETCH_OPTIONS_JSON)?;
    let provider_id = obj
        .get("provider_id")
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(ERR_FETCH_OPTIONS_JSON)?;
    let reputation_score_bps = match obj.get("reputation_score_bps") {
        Some(value) => {
            let score = value.as_u64().ok_or(ERR_FETCH_OPTIONS_JSON)?;
            if score > 10_000 {
                return Err(ERR_FETCH_OPTIONS_JSON);
            }
            Some(u16::try_from(score).map_err(|_| ERR_FETCH_OPTIONS_JSON)?)
        }
        None => None,
    };
    Ok(TelemetryEntryInput {
        provider_id,
        qos_score: obj.get("qos_score").and_then(JsonValue::as_f64),
        latency_p95_ms: obj.get("latency_p95_ms").and_then(JsonValue::as_f64),
        failure_rate_ewma: obj.get("failure_rate_ewma").and_then(JsonValue::as_f64),
        token_health: obj.get("token_health").and_then(JsonValue::as_f64),
        staking_weight: obj.get("staking_weight").and_then(JsonValue::as_f64),
        reputation_score_bps,
        penalty: obj.get("penalty").and_then(JsonValue::as_bool),
        last_updated_unix: obj.get("last_updated_unix").and_then(JsonValue::as_u64),
    })
}
fn options_from_json(value: &JsonValue) -> Result<LocalFetchOptions, c_int> {
    let obj = value.as_object().ok_or(ERR_FETCH_OPTIONS_JSON)?;
    let verify_digests = obj.get("verify_digests").and_then(JsonValue::as_bool);
    let verify_lengths = obj.get("verify_lengths").and_then(JsonValue::as_bool);
    let retry_budget = obj
        .get("retry_budget")
        .and_then(JsonValue::as_u64)
        .map(|value| u32::try_from(value).map_err(|_| ERR_FETCH_OPTIONS_JSON))
        .transpose()?;
    let provider_failure_threshold = obj
        .get("provider_failure_threshold")
        .and_then(JsonValue::as_u64)
        .map(|value| u32::try_from(value).map_err(|_| ERR_FETCH_OPTIONS_JSON))
        .transpose()?;
    let max_parallel = obj
        .get("max_parallel")
        .and_then(JsonValue::as_u64)
        .map(|value| u32::try_from(value).map_err(|_| ERR_FETCH_OPTIONS_JSON))
        .transpose()?;
    let max_peers = obj
        .get("max_peers")
        .and_then(JsonValue::as_u64)
        .map(|value| u32::try_from(value).map_err(|_| ERR_FETCH_OPTIONS_JSON))
        .transpose()?;
    let chunker_handle = obj
        .get("chunker_handle")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let telemetry_region = obj
        .get("telemetry_region")
        .and_then(JsonValue::as_str)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let telemetry = if let Some(telemetry) = obj.get("telemetry").and_then(JsonValue::as_array) {
        let mut entries = Vec::with_capacity(telemetry.len());
        for entry in telemetry {
            entries.push(telemetry_from_json(entry)?);
        }
        entries
    } else {
        Vec::new()
    };
    let use_scoreboard = obj.get("use_scoreboard").and_then(JsonValue::as_bool);
    let scoreboard_now_unix_secs = obj
        .get("scoreboard_now_unix_secs")
        .and_then(JsonValue::as_u64);
    let deny_providers = if let Some(deny) = obj.get("deny_providers").and_then(JsonValue::as_array)
    {
        let mut list = Vec::with_capacity(deny.len());
        for entry in deny {
            list.push(entry.as_str().ok_or(ERR_FETCH_OPTIONS_JSON)?.to_owned());
        }
        list
    } else {
        Vec::new()
    };
    let boost_providers =
        if let Some(boosts) = obj.get("boost_providers").and_then(JsonValue::as_array) {
            let mut list = Vec::with_capacity(boosts.len());
            for entry in boosts {
                let boost_obj = entry.as_object().ok_or(ERR_FETCH_OPTIONS_JSON)?;
                let provider = boost_obj
                    .get("provider")
                    .and_then(JsonValue::as_str)
                    .map(str::to_owned)
                    .ok_or(ERR_FETCH_OPTIONS_JSON)?;
                let delta = boost_obj
                    .get("delta")
                    .and_then(JsonValue::as_i64)
                    .ok_or(ERR_FETCH_OPTIONS_JSON)?;
                list.push((provider, delta));
            }
            list
        } else {
            Vec::new()
        };
    let return_scoreboard = obj.get("return_scoreboard").and_then(JsonValue::as_bool);
    Ok(LocalFetchOptions {
        verify_digests,
        verify_lengths,
        retry_budget,
        provider_failure_threshold,
        max_parallel,
        max_peers,
        chunker_handle,
        telemetry_region,
        telemetry,
        use_scoreboard,
        scoreboard_now_unix_secs,
        deny_providers,
        boost_providers,
        return_scoreboard,
    })
}
fn local_fetch_result_to_json(result: &LocalFetchResult) -> JsonValue {
    let mut root = JsonMap::new();
    root.insert(
        "chunk_count".into(),
        JsonValue::from(result.chunk_count as u64),
    );
    let provider_reports = result
        .outcome
        .provider_reports
        .iter()
        .map(|report| {
            let mut obj = JsonMap::new();
            obj.insert(
                "provider".into(),
                JsonValue::from(report.provider.id().as_str().to_owned()),
            );
            obj.insert("successes".into(), JsonValue::from(report.successes as u64));
            obj.insert("failures".into(), JsonValue::from(report.failures as u64));
            obj.insert("disabled".into(), JsonValue::from(report.disabled));
            JsonValue::Object(obj)
        })
        .collect::<Vec<_>>();
    root.insert(
        "provider_reports".into(),
        JsonValue::Array(provider_reports),
    );
    let receipts = result
        .outcome
        .chunk_receipts
        .iter()
        .map(|receipt| {
            let mut obj = JsonMap::new();
            obj.insert(
                "chunk_index".into(),
                JsonValue::from(receipt.chunk_index as u64),
            );
            obj.insert(
                "provider".into(),
                JsonValue::from(receipt.provider.as_str().to_owned()),
            );
            obj.insert("attempts".into(), JsonValue::from(receipt.attempts as u64));
            obj.insert("latency_ms".into(), JsonValue::from(receipt.latency_ms));
            obj.insert("bytes".into(), JsonValue::from(receipt.bytes as u64));
            JsonValue::Object(obj)
        })
        .collect::<Vec<_>>();
    root.insert("chunk_receipts".into(), JsonValue::Array(receipts));
    if let Some(scoreboard) = result.scoreboard.as_ref() {
        let entries = scoreboard
            .iter()
            .map(|entry| {
                let mut obj = JsonMap::new();
                obj.insert(
                    "provider_id".into(),
                    JsonValue::from(entry.provider_id.clone()),
                );
                obj.insert("alias".into(), JsonValue::from(entry.alias.clone()));
                obj.insert("raw_score".into(), JsonValue::from(entry.raw_score));
                obj.insert(
                    "normalized_weight".into(),
                    JsonValue::from(entry.normalized_weight),
                );
                obj.insert(
                    "eligibility".into(),
                    JsonValue::from(entry.eligibility.clone()),
                );
                JsonValue::Object(obj)
            })
            .collect::<Vec<_>>();
        root.insert("scoreboard".into(), JsonValue::Array(entries));
    } else {
        root.insert("scoreboard".into(), JsonValue::Null);
    }
    if let Some(region) = result.telemetry_region.as_deref() {
        root.insert("telemetry_region".into(), JsonValue::from(region));
    } else {
        root.insert("telemetry_region".into(), JsonValue::Null);
    }
    JsonValue::Object(root)
}
fn write_json_value(out_ptr: *mut *mut c_uchar, out_len: *mut c_ulong, value: &JsonValue) -> c_int {
    match norito::json::to_vec(value) {
        Ok(bytes) => unsafe { write_bytes(out_ptr, out_len, &bytes) }.map_or_else(|err| err, |_| 0),
        Err(_) => ERR_FETCH_EXECUTION,
    }
}
fn map_local_fetch_error(err: LocalFetchError) -> c_int {
    match err {
        LocalFetchError::NoProviders => ERR_FETCH_NO_PROVIDERS,
        LocalFetchError::DuplicateProvider(_) => ERR_FETCH_DUPLICATE_PROVIDER,
        LocalFetchError::ProviderPathMissing { .. } => ERR_FETCH_PROVIDER_PATH_MISSING,
        LocalFetchError::ProviderPathNotFile { .. } => ERR_FETCH_PROVIDER_PATH_NOT_FILE,
        LocalFetchError::InvalidMaxConcurrent => ERR_FETCH_INVALID_MAX_CONCURRENT,
        LocalFetchError::InvalidWeight => ERR_FETCH_INVALID_WEIGHT,
        LocalFetchError::InvalidPlan(_) => ERR_FETCH_PLAN_JSON,
        LocalFetchError::MissingScoreboardMetadata(_) => ERR_FETCH_SCOREBOARD_METADATA,
        LocalFetchError::ScoreboardExcludedAll => ERR_FETCH_SCOREBOARD_EXCLUDED,
        LocalFetchError::ScoreboardBuild(_) => ERR_FETCH_SCOREBOARD_BUILD,
        LocalFetchError::Fetch(_) => ERR_FETCH_EXECUTION,
        LocalFetchError::UnknownChunkerHandle(_) => ERR_FETCH_UNKNOWN_CHUNKER,
        LocalFetchError::IntegrityVerificationDisabled(_) => ERR_FETCH_OPTIONS_JSON,
    }
}
#[derive(Clone)]
struct DaProofSummaryOptions {
    sample_count: usize,
    sample_seed: u64,
    explicit_indexes: Vec<usize>,
}
impl DaProofSummaryOptions {
    fn from_raw(sample_count: c_ulong, sample_seed: u64, indexes: &[usize]) -> Result<Self, c_int> {
        let sample_count = usize::try_from(sample_count).map_err(|_| ERR_DA_PROOF_SUMMARY)?;
        Ok(Self {
            sample_count,
            sample_seed,
            explicit_indexes: indexes.to_vec(),
        })
    }
}
#[derive(Clone, Copy)]
enum ProofOrigin {
    Sampled,
    Explicit,
}
impl ProofOrigin {
    fn as_str(self) -> &'static str {
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
fn da_proof_summary_json(
    manifest_bytes: &[u8],
    payload_bytes: &[u8],
    options: &DaProofSummaryOptions,
) -> Result<JsonValue, c_int> {
    let manifest: DaManifestV1 =
        decode_from_bytes(manifest_bytes).map_err(|_| ERR_DA_PROOF_SUMMARY)?;
    let plan = build_plan_from_da_manifest(&manifest).map_err(|_| ERR_DA_PROOF_SUMMARY)?;
    let mut store = ChunkStore::with_profile(plan.chunk_profile);
    let mut ingest_source = InMemoryPayload::new(payload_bytes);
    store
        .ingest_plan_source(&plan, &mut ingest_source)
        .map_err(|_| ERR_DA_PROOF_SUMMARY)?;
    validate_manifest_consistency(&manifest, &store)?;
    let por_root = *store.por_tree().root();
    let mut reports = collect_sampled_proofs(&store, payload_bytes, options, &por_root)?;
    let mut explicit = collect_explicit_proofs(&store, payload_bytes, options, &por_root)?;
    reports.append(&mut explicit);
    let mut summary = JsonMap::new();
    summary.insert(
        "blob_hash_hex".into(),
        JsonValue::from(hex::encode(manifest.blob_hash.as_ref())),
    );
    summary.insert(
        "chunk_root_hex".into(),
        JsonValue::from(hex::encode(manifest.chunk_root.as_ref())),
    );
    summary.insert(
        "por_root_hex".into(),
        JsonValue::from(hex::encode(store.por_tree().root())),
    );
    summary.insert(
        "leaf_count".into(),
        value_from_usize(store.por_tree().leaf_count()),
    );
    summary.insert(
        "segment_count".into(),
        value_from_usize(store.por_tree().segment_count()),
    );
    summary.insert(
        "chunk_count".into(),
        value_from_usize(store.por_tree().chunks().len()),
    );
    summary.insert(
        "sample_count".into(),
        value_from_usize(options.sample_count),
    );
    summary.insert("sample_seed".into(), JsonValue::from(options.sample_seed));
    summary.insert("proof_count".into(), value_from_usize(reports.len()));
    let proof_values = reports.iter().map(proof_report_to_json).collect::<Vec<_>>();
    summary.insert("proofs".into(), JsonValue::Array(proof_values));
    Ok(JsonValue::Object(summary))
}
fn validate_manifest_consistency(manifest: &DaManifestV1, store: &ChunkStore) -> Result<(), c_int> {
    let blob_hash_bytes = manifest.blob_hash.as_ref();
    if store.payload_digest().as_bytes() != blob_hash_bytes {
        return Err(ERR_DA_PROOF_SUMMARY);
    }
    let chunk_root_bytes = manifest.chunk_root.as_ref();
    if store.por_tree().root() != chunk_root_bytes {
        return Err(ERR_DA_PROOF_SUMMARY);
    }
    Ok(())
}
fn collect_sampled_proofs(
    store: &ChunkStore,
    payload: &[u8],
    options: &DaProofSummaryOptions,
    por_root: &[u8; 32],
) -> Result<Vec<ProofReport>, c_int> {
    if options.sample_count == 0 {
        return Ok(Vec::new());
    }
    let mut source = InMemoryPayload::new(payload);
    let samples = store
        .sample_leaves_with(options.sample_count, options.sample_seed, &mut source)
        .map_err(chunk_store_error_code)?;
    Ok(samples
        .into_iter()
        .map(|(leaf_index, proof)| ProofReport {
            origin: ProofOrigin::Sampled,
            leaf_index,
            verified: proof.verify(por_root),
            proof,
        })
        .collect())
}
fn collect_explicit_proofs(
    store: &ChunkStore,
    payload: &[u8],
    options: &DaProofSummaryOptions,
    por_root: &[u8; 32],
) -> Result<Vec<ProofReport>, c_int> {
    if options.explicit_indexes.is_empty() {
        return Ok(Vec::new());
    }
    let mut source = InMemoryPayload::new(payload);
    let mut reports = Vec::with_capacity(options.explicit_indexes.len());
    let mut seen = HashSet::new();
    for &leaf_index in &options.explicit_indexes {
        if !seen.insert(leaf_index) {
            continue;
        }
        let (chunk_idx, segment_idx, inner_idx) = store
            .por_tree()
            .leaf_path(leaf_index)
            .ok_or(ERR_DA_PROOF_SUMMARY)?;
        let proof = store
            .por_tree()
            .prove_leaf_with(chunk_idx, segment_idx, inner_idx, &mut source)
            .map_err(chunk_store_error_code)?
            .ok_or(ERR_DA_PROOF_SUMMARY)?;
        reports.push(ProofReport {
            origin: ProofOrigin::Explicit,
            leaf_index,
            verified: proof.verify(por_root),
            proof,
        });
    }
    Ok(reports)
}
fn chunk_store_error_code(err: ChunkStoreError) -> c_int {
    tracing::debug!("chunk store error during DA proof summary: {err}");
    ERR_DA_PROOF_SUMMARY
}
fn proof_report_to_json(report: &ProofReport) -> JsonValue {
    let mut map = JsonMap::new();
    map.insert("origin".into(), JsonValue::from(report.origin.as_str()));
    map.insert("leaf_index".into(), value_from_usize(report.leaf_index));
    map.insert(
        "chunk_index".into(),
        value_from_usize(report.proof.chunk_index),
    );
    map.insert(
        "segment_index".into(),
        value_from_usize(report.proof.segment_index),
    );
    map.insert(
        "leaf_offset".into(),
        JsonValue::from(report.proof.leaf_offset),
    );
    map.insert(
        "leaf_length".into(),
        value_from_u32(report.proof.leaf_length),
    );
    map.insert(
        "segment_offset".into(),
        JsonValue::from(report.proof.segment_offset),
    );
    map.insert(
        "segment_length".into(),
        value_from_u32(report.proof.segment_length),
    );
    map.insert(
        "chunk_offset".into(),
        JsonValue::from(report.proof.chunk_offset),
    );
    map.insert(
        "chunk_length".into(),
        value_from_u32(report.proof.chunk_length),
    );
    map.insert(
        "payload_len".into(),
        JsonValue::from(report.proof.payload_len),
    );
    map.insert(
        "chunk_digest_hex".into(),
        JsonValue::from(hex::encode(report.proof.chunk_digest)),
    );
    map.insert(
        "chunk_root_hex".into(),
        JsonValue::from(hex::encode(report.proof.chunk_root)),
    );
    map.insert(
        "segment_digest_hex".into(),
        JsonValue::from(hex::encode(report.proof.segment_digest)),
    );
    map.insert(
        "leaf_digest_hex".into(),
        JsonValue::from(hex::encode(report.proof.leaf_digest)),
    );
    map.insert(
        "leaf_bytes_b64".into(),
        JsonValue::from(b64gp::STANDARD.encode(&report.proof.leaf_bytes)),
    );
    map.insert(
        "segment_leaves_hex".into(),
        JsonValue::Array(
            report
                .proof
                .segment_leaves
                .iter()
                .map(|digest| JsonValue::from(hex::encode(digest)))
                .collect(),
        ),
    );
    map.insert(
        "chunk_segments_hex".into(),
        JsonValue::Array(
            report
                .proof
                .chunk_segments
                .iter()
                .map(|digest| JsonValue::from(hex::encode(digest)))
                .collect(),
        ),
    );
    map.insert(
        "chunk_count".into(),
        JsonValue::from(report.proof.chunk_count),
    );
    map.insert(
        "chunk_merkle_path_hex".into(),
        JsonValue::Array(
            report
                .proof
                .chunk_merkle_path
                .iter()
                .map(|digest| JsonValue::from(hex::encode(digest)))
                .collect(),
        ),
    );
    map.insert("verified".into(), JsonValue::from(report.verified));
    JsonValue::Object(map)
}
fn value_from_usize(value: usize) -> JsonValue {
    JsonValue::from(u64::try_from(value).unwrap_or(u64::MAX))
}
fn value_from_u32(value: u32) -> JsonValue {
    JsonValue::from(u64::from(value))
}
unsafe fn write_sorafs_reference_json_buffer(
    buffer: sorafs_reference_ffi::SorafsReferenceFfiBuffer,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_json_ptr, out_json_len);
    if out_json_ptr.is_null() || out_json_len.is_null() {
        unsafe { sorafs_reference_ffi::sorafs_reference_free_buffer(buffer) };
        return ERR_NULL_PTR;
    }
    let bytes = if buffer.ptr.is_null() || buffer.len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(buffer.ptr.cast_const(), buffer.len) }
    };
    let status =
        unsafe { write_bytes(out_json_ptr, out_json_len, bytes) }.map_or_else(|err| err, |_| 0);
    unsafe { sorafs_reference_ffi::sorafs_reference_free_buffer(buffer) };
    status
}
unsafe fn write_sorafs_reference_json_buffer_usize(
    buffer: sorafs_reference_ffi::SorafsReferenceFfiBuffer,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut usize,
) -> c_int {
    if !out_json_ptr.is_null() {
        unsafe {
            *out_json_ptr = ptr::null_mut();
        }
    }
    if !out_json_len.is_null() {
        unsafe {
            *out_json_len = 0;
        }
    }
    if out_json_ptr.is_null() || out_json_len.is_null() {
        unsafe { sorafs_reference_ffi::sorafs_reference_free_buffer(buffer) };
        return ERR_NULL_PTR;
    }
    let bytes = if buffer.ptr.is_null() || buffer.len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(buffer.ptr.cast_const(), buffer.len) }
    };
    let status = unsafe { write_bytes_usize(out_json_ptr, out_json_len, bytes) }
        .map_or_else(|err| err, |_| 0);
    unsafe { sorafs_reference_ffi::sorafs_reference_free_buffer(buffer) };
    status
}
fn sorafs_reference_json_buffer_from_bytes(
    bytes: Vec<u8>,
) -> sorafs_reference_ffi::SorafsReferenceFfiBuffer {
    let len = bytes.len();
    if len == 0 {
        return sorafs_reference_ffi::SorafsReferenceFfiBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
    }
    let ptr = Box::into_raw(bytes.into_boxed_slice()).cast::<u8>();
    sorafs_reference_ffi::SorafsReferenceFfiBuffer { ptr, len }
}
fn sorafs_reference_invalid_pdp_kind_buffer(
    kind: u32,
    generated_at: u64,
) -> sorafs_reference_ffi::SorafsReferenceFfiBuffer {
    let outcome = ValidationOutcomeV1::error(
        "SFS-FFI-001",
        "internal",
        format!("unsupported pdp_kind selector: {kind}"),
        "Use PDP selector 1 for commitment, 2 for challenge, or 3 for proof.",
        vec![
            "sorafs.reference.ffi".to_owned(),
            "sorafs.reference.code.SFS-FFI-001".to_owned(),
        ],
        vec![ValidationContextFieldV1::new("pdp_kind", kind.to_string())],
        Vec::new(),
        generated_at,
    );
    match norito::json::to_string_pretty(&outcome) {
        Ok(mut rendered) => {
            rendered.push('\n');
            sorafs_reference_json_buffer_from_bytes(rendered.into_bytes())
        }
        Err(_) => sorafs_reference_json_buffer_from_bytes(
            b"{\"status\":\"Error\",\"code\":\"SFS-FFI-001\",\"category\":\"internal\",\"message\":\"unsupported PDP selector\",\"action\":\"Use a supported PDP selector.\",\"docs_url\":\"https://docs.iroha.tech/\",\"telemetry_tags\":[\"sorafs.reference.ffi\",\"sorafs.reference.code.SFS-FFI-001\"],\"context\":[],\"inputs\":[],\"version\":1,\"generated_at\":0}\n".to_vec(),
        ),
    }
}
fn sorafs_reference_orderbook_kind_from_bridge(
    kind: u32,
) -> Result<OrderbookValidationPayloadKindV1, c_int> {
    match kind {
        sorafs_reference_ffi::SORAFS_REFERENCE_ORDERBOOK_KIND_ORDER_REQUEST => {
            Ok(OrderbookValidationPayloadKindV1::OrderRequest)
        }
        sorafs_reference_ffi::SORAFS_REFERENCE_ORDERBOOK_KIND_ORDER_CANCEL => {
            Ok(OrderbookValidationPayloadKindV1::OrderCancel)
        }
        sorafs_reference_ffi::SORAFS_REFERENCE_ORDERBOOK_KIND_TRADE_EVENT => {
            Ok(OrderbookValidationPayloadKindV1::TradeEvent)
        }
        sorafs_reference_ffi::SORAFS_REFERENCE_ORDERBOOK_KIND_SETTLEMENT_CHANNEL => {
            Ok(OrderbookValidationPayloadKindV1::SettlementChannel)
        }
        sorafs_reference_ffi::SORAFS_REFERENCE_ORDERBOOK_KIND_SETTLEMENT_RECEIPT => {
            Ok(OrderbookValidationPayloadKindV1::SettlementReceipt)
        }
        _ => Err(ERR_SORAFS_REFERENCE),
    }
}
fn sorafs_reference_orderbook_signing_error_code(error: &OrderbookPayloadSigningError) -> c_int {
    match error {
        OrderbookPayloadSigningError::InvalidSigningKeyLength { .. }
        | OrderbookPayloadSigningError::InvalidSigningKeyMaterial => ERR_PRIVATE_KEY_PARSE,
        OrderbookPayloadSigningError::UnsupportedPayloadKind { .. }
        | OrderbookPayloadSigningError::Decode { .. }
        | OrderbookPayloadSigningError::Sign { .. }
        | OrderbookPayloadSigningError::Encode { .. } => ERR_SORAFS_REFERENCE,
    }
}
fn sorafs_orderbook_side_from_bridge(code: u32) -> Result<OrderSideV1, c_int> {
    match code {
        SORAFS_ORDERBOOK_SIDE_BID => Ok(OrderSideV1::Bid),
        SORAFS_ORDERBOOK_SIDE_ASK => Ok(OrderSideV1::Ask),
        _ => Err(ERR_SORAFS_REFERENCE),
    }
}
fn sorafs_orderbook_tier_from_bridge(code: u32) -> Result<OrderTierV1, c_int> {
    match code {
        SORAFS_ORDERBOOK_TIER_HOT => Ok(OrderTierV1::Hot),
        SORAFS_ORDERBOOK_TIER_WARM => Ok(OrderTierV1::Warm),
        SORAFS_ORDERBOOK_TIER_ARCHIVE => Ok(OrderTierV1::Archive),
        _ => Err(ERR_SORAFS_REFERENCE),
    }
}
fn sorafs_orderbook_cancel_reason_from_bridge(code: u32) -> Result<OrderCancelReasonV1, c_int> {
    match code {
        SORAFS_ORDERBOOK_CANCEL_REASON_OWNER_REQUESTED => Ok(OrderCancelReasonV1::OwnerRequested),
        SORAFS_ORDERBOOK_CANCEL_REASON_EXPIRED => Ok(OrderCancelReasonV1::Expired),
        SORAFS_ORDERBOOK_CANCEL_REASON_GOVERNANCE => Ok(OrderCancelReasonV1::Governance),
        SORAFS_ORDERBOOK_CANCEL_REASON_REPLACED => Ok(OrderCancelReasonV1::Replaced),
        _ => Err(ERR_SORAFS_REFERENCE),
    }
}
fn sorafs_fee_bps_from_bridge(value: u32) -> Result<u16, c_int> {
    u16::try_from(value).map_err(|_| ERR_SORAFS_REFERENCE)
}
fn sorafs_xor_quantity_from_bytes(bytes: &[u8]) -> Result<XorQuantity, c_int> {
    if bytes.len() > 155 {
        return Err(ERR_SORAFS_REFERENCE);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ERR_UTF8)?;
    let quantity = text
        .parse::<XorQuantity>()
        .map_err(|_| ERR_SORAFS_REFERENCE)?;
    if quantity.to_string() != text {
        return Err(ERR_SORAFS_REFERENCE);
    }
    Ok(quantity)
}
unsafe fn sorafs_read_fixed32(ptr_: *const c_uchar, len: c_ulong) -> Result<[u8; 32], c_int> {
    if ptr_.is_null() || len as usize != 32 {
        return Err(ERR_SORAFS_REFERENCE);
    }
    let bytes = unsafe { slice::from_raw_parts(ptr_, 32) };
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
unsafe fn sorafs_read_orderbook_provider_id(
    ptr_: *const c_uchar,
    len: c_ulong,
) -> Result<Option<[u8; 32]>, c_int> {
    if len == 0 {
        return Ok(None);
    }
    let provider_id = unsafe { sorafs_read_fixed32(ptr_, len) }?;
    if provider_id == [0; 32] {
        return Err(ERR_SORAFS_REFERENCE);
    }
    Ok(Some(provider_id))
}
unsafe fn sorafs_read_orderbook_owner_account(
    ptr_: *const c_uchar,
    len: c_ulong,
) -> Result<Vec<u8>, c_int> {
    let len_usize = usize::try_from(len).map_err(|_| ERR_SORAFS_REFERENCE)?;
    if len_usize == 0 || len_usize > ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 {
        return Err(ERR_SORAFS_REFERENCE);
    }
    let bytes = unsafe { read_vec_bytes(ptr_, len) }.map_err(|err| err.code())?;
    Ok(bytes)
}
unsafe fn sorafs_read_xor_quantity(
    ptr_: *const c_uchar,
    len: c_ulong,
) -> Result<XorQuantity, c_int> {
    let bytes = unsafe { read_vec_bytes(ptr_, len) }.map_err(|err| err.code())?;
    sorafs_xor_quantity_from_bytes(&bytes)
}
unsafe fn sorafs_reference_validate_pdp_payload_buffer(
    kind: u32,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    label_ptr: *const c_uchar,
    label_len: c_ulong,
    generated_at: u64,
) -> sorafs_reference_ffi::SorafsReferenceFfiBuffer {
    let bytes_len = bytes_len as usize;
    let label_len = label_len as usize;
    match kind {
        SORAFS_REFERENCE_PDP_KIND_COMMITMENT => unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pdp_commitment_json(
                bytes_ptr,
                bytes_len,
                label_ptr,
                label_len,
                generated_at,
            )
        },
        SORAFS_REFERENCE_PDP_KIND_CHALLENGE => unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pdp_challenge_json(
                bytes_ptr,
                bytes_len,
                label_ptr,
                label_len,
                generated_at,
            )
        },
        SORAFS_REFERENCE_PDP_KIND_PROOF => unsafe {
            sorafs_reference_ffi::sorafs_reference_validate_pdp_proof_json(
                bytes_ptr,
                bytes_len,
                label_ptr,
                label_len,
                generated_at,
            )
        },
        other => sorafs_reference_invalid_pdp_kind_buffer(other, generated_at),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_orderbook_json(
    kind: u32,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    label_ptr: *const c_uchar,
    label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_orderbook_json(
            kind,
            bytes_ptr,
            bytes_len as usize,
            label_ptr,
            label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_pop_json(
    kind: u32,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    label_ptr: *const c_uchar,
    label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_pop_json(
            kind,
            bytes_ptr,
            bytes_len as usize,
            label_ptr,
            label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_hedging_json(
    kind: u32,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    label_ptr: *const c_uchar,
    label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_hedging_json(
            kind,
            bytes_ptr,
            bytes_len as usize,
            label_ptr,
            label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
/// Validate one canonical appeal-finance `CancelAssetLock` V1 payload.
///
/// The returned `ValidationOutcomeV1` JSON allocation must be released with
/// [`connect_norito_free`].
///
/// # Safety
/// Every non-null input pointer must remain valid for its corresponding length
/// until this function returns. Output pointers must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json(
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    label_ptr: *const c_uchar,
    label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_appeal_finance_cancel_asset_lock_json(
            bytes_ptr,
            bytes_len as usize,
            label_ptr,
            label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
/// Validate a bounded heterogeneous SoraFS fixture bundle and all supported
/// manifest, provider, challenge, proof, repair, and orderbook cross-links.
///
/// The returned `ValidationOutcomeV1` JSON allocation must be released with
/// [`connect_norito_free`].
///
/// # Safety
/// Every non-null descriptor and nested pointer must remain valid for its
/// corresponding length until this function returns. Output pointers must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_bundle_json(
    payloads_ptr: *const ConnectNoritoSorafsReferenceBundlePayload,
    payloads_len: usize,
    now: u64,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut usize,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_bundle_json(
            payloads_ptr,
            payloads_len,
            now,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer_usize(buffer, out_json_ptr, out_json_len) }
}
/// Validate one canonical SoraFS governance log node against its expected CID.
///
/// The expected node CID is required and must contain exactly 32 bytes. The
/// returned `ValidationOutcomeV1` JSON allocation must be released with
/// [`connect_norito_free`].
///
/// # Safety
/// Every non-null input pointer must remain valid for its corresponding length
/// until this function returns. Output pointers must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_governance_json(
    bytes_ptr: *const c_uchar,
    bytes_len: usize,
    label_ptr: *const c_uchar,
    label_len: usize,
    expected_node_cid_ptr: *const c_uchar,
    expected_node_cid_len: usize,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut usize,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_governance_json(
            bytes_ptr,
            bytes_len,
            label_ptr,
            label_len,
            expected_node_cid_ptr,
            expected_node_cid_len,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer_usize(buffer, out_json_ptr, out_json_len) }
}
/// Validate one canonical SoraFS governance DAG block.
///
/// The returned `ValidationOutcomeV1` JSON allocation must be released with
/// [`connect_norito_free`].
///
/// # Safety
/// Every non-null input pointer must remain valid for its corresponding length
/// until this function returns. Output pointers must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_governance_dag_block_json(
    bytes_ptr: *const c_uchar,
    bytes_len: usize,
    label_ptr: *const c_uchar,
    label_len: usize,
    expected_block_cid_ptr: *const c_uchar,
    expected_block_cid_len: usize,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut usize,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_governance_dag_block_json(
            bytes_ptr,
            bytes_len,
            label_ptr,
            label_len,
            expected_block_cid_ptr,
            expected_block_cid_len,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer_usize(buffer, out_json_ptr, out_json_len) }
}
/// Validate a signed SoraFS governance DAG head against an ordered root history
/// or exact checkpoint-anchored tail.
///
/// The returned `ValidationOutcomeV1` JSON allocation must be released with
/// [`connect_norito_free`].
///
/// # Safety
/// Every non-null input pointer, descriptor, and nested descriptor pointer must
/// remain valid for its corresponding length until this function returns.
/// Output pointers must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_governance_dag_head_chain_json(
    head_ptr: *const c_uchar,
    head_len: usize,
    head_label_ptr: *const c_uchar,
    head_label_len: usize,
    blocks_ptr: *const ConnectNoritoSorafsReferenceInput,
    blocks_len: usize,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut usize,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_governance_dag_head_chain_json(
            head_ptr,
            head_len,
            head_label_ptr,
            head_label_len,
            blocks_ptr,
            blocks_len,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer_usize(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_sign_orderbook_payload(
    kind: u32,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    private_key_ptr: *const c_uchar,
    private_key_len: c_ulong,
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_signed_ptr, out_signed_len);
    if out_signed_ptr.is_null() || out_signed_len.is_null() {
        return ERR_NULL_PTR;
    }
    let kind = match sorafs_reference_orderbook_kind_from_bridge(kind) {
        Ok(kind) => kind,
        Err(code) => return code,
    };
    let payload = match unsafe { read_vec_bytes(bytes_ptr, bytes_len) } {
        Ok(payload) => payload,
        Err(err) => return err.code(),
    };
    let private_key = match unsafe { read_vec_bytes(private_key_ptr, private_key_len) } {
        Ok(private_key) => Zeroizing::new(private_key),
        Err(err) => return err.code(),
    };
    let signed =
        match sign_orderbook_payload_bytes_ed25519_v1(kind, &payload, private_key.as_slice()) {
            Ok(signed) => signed,
            Err(error) => return sorafs_reference_orderbook_signing_error_code(&error),
        };
    unsafe { write_bytes(out_signed_ptr, out_signed_len, &signed) }.map_or_else(|err| err, |_| 0)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_derive_orderbook_order_id(
    owner_account_ptr: *const c_uchar,
    owner_account_len: c_ulong,
    nonce: u64,
    out_order_id_ptr: *mut c_uchar,
    out_order_id_len: c_ulong,
) -> c_int {
    if out_order_id_ptr.is_null() || out_order_id_len as usize != 32 || nonce == 0 {
        return ERR_SORAFS_REFERENCE;
    }
    let owner_account = match unsafe {
        sorafs_read_orderbook_owner_account(owner_account_ptr, owner_account_len)
    } {
        Ok(value) => value,
        Err(code) => return code,
    };
    let order_id = derive_orderbook_order_id_v1(&owner_account, nonce);
    unsafe {
        ptr::copy_nonoverlapping(order_id.as_ptr(), out_order_id_ptr, order_id.len());
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_build_signed_orderbook_order_request(
    order_id_ptr: *const c_uchar,
    order_id_len: c_ulong,
    side: u32,
    tier: u32,
    price_per_gib_ptr: *const c_uchar,
    price_per_gib_len: c_ulong,
    quantity_gib: u64,
    remaining_gib: u64,
    owner_account_ptr: *const c_uchar,
    owner_account_len: c_ulong,
    provider_id_ptr: *const c_uchar,
    provider_id_len: c_ulong,
    expiry_unix: u64,
    nonce: u64,
    maker_fee_bps: u32,
    taker_fee_bps: u32,
    private_key_ptr: *const c_uchar,
    private_key_len: c_ulong,
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_signed_ptr, out_signed_len);
    if out_signed_ptr.is_null() || out_signed_len.is_null() {
        return ERR_NULL_PTR;
    }
    let private_key = match unsafe { read_vec_bytes(private_key_ptr, private_key_len) } {
        Ok(private_key) => Zeroizing::new(private_key),
        Err(err) => return err.code(),
    };
    let supplied_order_id = match unsafe { sorafs_read_fixed32(order_id_ptr, order_id_len) } {
        Ok(value) => value,
        Err(code) => return code,
    };
    let owner_account = match unsafe {
        sorafs_read_orderbook_owner_account(owner_account_ptr, owner_account_len)
    } {
        Ok(value) => value,
        Err(code) => return code,
    };
    if nonce == 0 {
        return ERR_SORAFS_REFERENCE;
    }
    if supplied_order_id != derive_orderbook_order_id_v1(&owner_account, nonce) {
        return ERR_SORAFS_REFERENCE;
    }
    let fields = OrderbookOrderRequestFieldsV1 {
        side: match sorafs_orderbook_side_from_bridge(side) {
            Ok(value) => value,
            Err(code) => return code,
        },
        tier: match sorafs_orderbook_tier_from_bridge(tier) {
            Ok(value) => value,
            Err(code) => return code,
        },
        price_per_gib: match unsafe {
            sorafs_read_xor_quantity(price_per_gib_ptr, price_per_gib_len)
        } {
            Ok(value) => value,
            Err(code) => return code,
        },
        quantity_gib,
        remaining_gib,
        owner_account,
        provider_id: match unsafe {
            sorafs_read_orderbook_provider_id(provider_id_ptr, provider_id_len)
        } {
            Ok(value) => value,
            Err(code) => return code,
        },
        expiry_unix,
        nonce,
        maker_fee_bps: match sorafs_fee_bps_from_bridge(maker_fee_bps) {
            Ok(value) => value,
            Err(code) => return code,
        },
        taker_fee_bps: match sorafs_fee_bps_from_bridge(taker_fee_bps) {
            Ok(value) => value,
            Err(code) => return code,
        },
    };
    let signed =
        match build_signed_orderbook_order_request_bytes_ed25519_v1(fields, private_key.as_slice())
        {
            Ok(signed) => signed,
            Err(error) => return sorafs_reference_orderbook_signing_error_code(&error),
        };
    unsafe { write_bytes(out_signed_ptr, out_signed_len, &signed) }.map_or_else(|err| err, |_| 0)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_build_signed_orderbook_order_cancel(
    order_id_ptr: *const c_uchar,
    order_id_len: c_ulong,
    owner_account_ptr: *const c_uchar,
    owner_account_len: c_ulong,
    reason: u32,
    nonce: u64,
    private_key_ptr: *const c_uchar,
    private_key_len: c_ulong,
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_signed_ptr, out_signed_len);
    if out_signed_ptr.is_null() || out_signed_len.is_null() {
        return ERR_NULL_PTR;
    }
    let private_key = match unsafe { read_vec_bytes(private_key_ptr, private_key_len) } {
        Ok(private_key) => Zeroizing::new(private_key),
        Err(err) => return err.code(),
    };
    let fields = OrderbookOrderCancelFieldsV1 {
        order_id: match unsafe { sorafs_read_fixed32(order_id_ptr, order_id_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        owner_account: match unsafe {
            sorafs_read_orderbook_owner_account(owner_account_ptr, owner_account_len)
        } {
            Ok(value) => value,
            Err(code) => return code,
        },
        reason: match sorafs_orderbook_cancel_reason_from_bridge(reason) {
            Ok(value) => value,
            Err(code) => return code,
        },
        nonce,
    };
    let signed = match build_signed_orderbook_order_cancel_bytes_ed25519_v1(
        fields,
        private_key.as_slice(),
    ) {
        Ok(signed) => signed,
        Err(error) => return sorafs_reference_orderbook_signing_error_code(&error),
    };
    unsafe { write_bytes(out_signed_ptr, out_signed_len, &signed) }.map_or_else(|err| err, |_| 0)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_build_signed_orderbook_settlement_receipt(
    receipt_id_ptr: *const c_uchar,
    receipt_id_len: c_ulong,
    channel_id_ptr: *const c_uchar,
    channel_id_len: c_ulong,
    trade_id_ptr: *const c_uchar,
    trade_id_len: c_ulong,
    range_start: u64,
    range_end: u64,
    chunk_hash_ptr: *const c_uchar,
    chunk_hash_len: c_ulong,
    bytes_delivered: u64,
    xor_debited_ptr: *const c_uchar,
    xor_debited_len: c_ulong,
    provider_credit_ptr: *const c_uchar,
    provider_credit_len: c_ulong,
    fee_amount_ptr: *const c_uchar,
    fee_amount_len: c_ulong,
    issued_at_unix: u64,
    private_key_ptr: *const c_uchar,
    private_key_len: c_ulong,
    out_signed_ptr: *mut *mut c_uchar,
    out_signed_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_signed_ptr, out_signed_len);
    if out_signed_ptr.is_null() || out_signed_len.is_null() {
        return ERR_NULL_PTR;
    }
    let private_key = match unsafe { read_vec_bytes(private_key_ptr, private_key_len) } {
        Ok(private_key) => Zeroizing::new(private_key),
        Err(err) => return err.code(),
    };
    let fields = OrderbookSettlementReceiptFieldsV1 {
        receipt_id: match unsafe { sorafs_read_fixed32(receipt_id_ptr, receipt_id_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        channel_id: match unsafe { sorafs_read_fixed32(channel_id_ptr, channel_id_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        trade_id: match unsafe { sorafs_read_fixed32(trade_id_ptr, trade_id_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        range_start,
        range_end,
        chunk_hash: match unsafe { sorafs_read_fixed32(chunk_hash_ptr, chunk_hash_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        bytes_delivered,
        xor_debited: match unsafe { sorafs_read_xor_quantity(xor_debited_ptr, xor_debited_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        provider_credit: match unsafe {
            sorafs_read_xor_quantity(provider_credit_ptr, provider_credit_len)
        } {
            Ok(value) => value,
            Err(code) => return code,
        },
        fee_amount: match unsafe { sorafs_read_xor_quantity(fee_amount_ptr, fee_amount_len) } {
            Ok(value) => value,
            Err(code) => return code,
        },
        issued_at_unix,
    };
    let signed = match build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(
        fields,
        private_key.as_slice(),
    ) {
        Ok(signed) => signed,
        Err(error) => return sorafs_reference_orderbook_signing_error_code(&error),
    };
    unsafe { write_bytes(out_signed_ptr, out_signed_len, &signed) }.map_or_else(|err| err, |_| 0)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_pdp_payload_json(
    kind: u32,
    bytes_ptr: *const c_uchar,
    bytes_len: c_ulong,
    label_ptr: *const c_uchar,
    label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_validate_pdp_payload_buffer(
            kind,
            bytes_ptr,
            bytes_len,
            label_ptr,
            label_len,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_pdp_commitment_challenge_json(
    commitment_ptr: *const c_uchar,
    commitment_len: c_ulong,
    commitment_label_ptr: *const c_uchar,
    commitment_label_len: c_ulong,
    challenge_ptr: *const c_uchar,
    challenge_len: c_ulong,
    challenge_label_ptr: *const c_uchar,
    challenge_label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_pdp_commitment_challenge_json(
            commitment_ptr,
            commitment_len as usize,
            commitment_label_ptr,
            commitment_label_len as usize,
            challenge_ptr,
            challenge_len as usize,
            challenge_label_ptr,
            challenge_label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_pdp_challenge_proof_json(
    challenge_ptr: *const c_uchar,
    challenge_len: c_ulong,
    challenge_label_ptr: *const c_uchar,
    challenge_label_len: c_ulong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulong,
    proof_label_ptr: *const c_uchar,
    proof_label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_pdp_challenge_proof_json(
            challenge_ptr,
            challenge_len as usize,
            challenge_label_ptr,
            challenge_label_len as usize,
            proof_ptr,
            proof_len as usize,
            proof_label_ptr,
            proof_label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_pdp_bundle_json(
    commitment_ptr: *const c_uchar,
    commitment_len: c_ulong,
    commitment_label_ptr: *const c_uchar,
    commitment_label_len: c_ulong,
    challenge_ptr: *const c_uchar,
    challenge_len: c_ulong,
    challenge_label_ptr: *const c_uchar,
    challenge_label_len: c_ulong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulong,
    proof_label_ptr: *const c_uchar,
    proof_label_len: c_ulong,
    generated_at: u64,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    let buffer = unsafe {
        sorafs_reference_ffi::sorafs_reference_validate_pdp_json(
            commitment_ptr,
            commitment_len as usize,
            commitment_label_ptr,
            commitment_label_len as usize,
            challenge_ptr,
            challenge_len as usize,
            challenge_label_ptr,
            challenge_label_len as usize,
            proof_ptr,
            proof_len as usize,
            proof_label_ptr,
            proof_label_len as usize,
            generated_at,
        )
    };
    unsafe { write_sorafs_reference_json_buffer(buffer, out_json_ptr, out_json_len) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_sorafs_local_fetch(
    plan_ptr: *const c_char,
    plan_len: c_ulong,
    providers_ptr: *const c_char,
    providers_len: c_ulong,
    options_ptr: *const c_char,
    options_len: c_ulong,
    out_payload_ptr: *mut *mut c_uchar,
    out_payload_len: *mut c_ulong,
    out_report_ptr: *mut *mut c_uchar,
    out_report_len: *mut c_ulong,
) -> c_int {
    if out_payload_ptr.is_null()
        || out_payload_len.is_null()
        || out_report_ptr.is_null()
        || out_report_len.is_null()
    {
        return ERR_NULL_PTR;
    }
    let plan_str = match unsafe { read_string_bridge(plan_ptr, plan_len) } {
        Ok(value) => value,
        Err(err) => return err.code(),
    };
    let plan_json: JsonValue = match norito::json::from_str(&plan_str) {
        Ok(value) => value,
        Err(_) => return ERR_FETCH_PLAN_JSON,
    };
    let providers_str = match unsafe { read_string_bridge(providers_ptr, providers_len) } {
        Ok(value) => value,
        Err(err) => return err.code(),
    };
    let providers_json: JsonValue = match norito::json::from_str(&providers_str) {
        Ok(value) => value,
        Err(_) => return ERR_FETCH_PROVIDERS_JSON,
    };
    let providers = match providers_from_json(&providers_json) {
        Ok(list) => list,
        Err(code) => return code,
    };
    let options = if options_ptr.is_null() || options_len == 0 {
        LocalFetchOptions::default()
    } else {
        let options_str = match unsafe { read_string_bridge(options_ptr, options_len) } {
            Ok(value) => value,
            Err(err) => return err.code(),
        };
        let options_json: JsonValue = match norito::json::from_str(&options_str) {
            Ok(value) => value,
            Err(_) => return ERR_FETCH_OPTIONS_JSON,
        };
        match options_from_json(&options_json) {
            Ok(opts) => opts,
            Err(code) => return code,
        }
    };
    let result = match local_fetch::execute_local_fetch(&plan_json, providers, options) {
        Ok(result) => result,
        Err(err) => return map_local_fetch_error(err),
    };
    let payload = result.outcome.assemble_payload();
    let report_json = local_fetch_result_to_json(&result);
    let payload_code = unsafe { write_bytes(out_payload_ptr, out_payload_len, &payload) }
        .map_or_else(|err| err, |_| 0);
    if payload_code != 0 {
        return payload_code;
    }
    write_json_value(out_report_ptr, out_report_len, &report_json)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_da_proof_summary(
    manifest_ptr: *const c_uchar,
    manifest_len: c_ulong,
    payload_ptr: *const c_uchar,
    payload_len: c_ulong,
    sample_count: c_ulong,
    sample_seed: u64,
    leaf_indexes_ptr: *const c_ulong,
    leaf_indexes_len: c_ulong,
    out_json_ptr: *mut *mut c_uchar,
    out_json_len: *mut c_ulong,
) -> c_int {
    if out_json_ptr.is_null() || out_json_len.is_null() {
        return ERR_NULL_PTR;
    }
    if manifest_ptr.is_null() || payload_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if manifest_len == 0 || payload_len == 0 {
        return ERR_DA_PROOF_SUMMARY;
    }
    let manifest_bytes = unsafe { slice::from_raw_parts(manifest_ptr, manifest_len as usize) };
    let payload_bytes = unsafe { slice::from_raw_parts(payload_ptr, payload_len as usize) };
    let mut explicit_indexes = Vec::new();
    if leaf_indexes_len > 0 {
        if leaf_indexes_ptr.is_null() {
            return ERR_NULL_PTR;
        }
        let raw = unsafe { slice::from_raw_parts(leaf_indexes_ptr, leaf_indexes_len as usize) };
        explicit_indexes.reserve(raw.len());
        for value in raw {
            match usize::try_from(*value) {
                Ok(idx) => explicit_indexes.push(idx),
                Err(_) => return ERR_DA_PROOF_SUMMARY,
            }
        }
    }
    let options =
        match DaProofSummaryOptions::from_raw(sample_count, sample_seed, &explicit_indexes) {
            Ok(opts) => opts,
            Err(code) => return code,
        };
    match da_proof_summary_json(manifest_bytes, payload_bytes, &options) {
        Ok(json) => write_json_value(out_json_ptr, out_json_len, &json),
        Err(code) => code,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_blake3_hash(
    payload_ptr: *const c_uchar,
    payload_len: c_ulong,
    out_digest_ptr: *mut *mut c_uchar,
    out_digest_len: *mut c_ulong,
) -> c_int {
    if out_digest_ptr.is_null() || out_digest_len.is_null() {
        return ERR_NULL_PTR;
    }
    let payload = if payload_len == 0 {
        &[]
    } else {
        if payload_ptr.is_null() {
            return ERR_NULL_PTR;
        }
        unsafe { slice::from_raw_parts(payload_ptr, payload_len as usize) }
    };
    let digest = blake3_hash(payload);
    match unsafe { write_bytes(out_digest_ptr, out_digest_len, digest.as_bytes()) } {
        Ok(()) => 0,
        Err(code) => code,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
    use iroha_data_model::isi::rwa::RwaInstructionBox;
    use std::{ffi::CString, mem::MaybeUninit};

    #[test]
    fn native_signer_jni_contract_revision_is_the_v7_shield_verifier_hard_cut() {
        assert_eq!(native_signer_jni_contract_revision(), 7);
    }

    #[test]
    fn c_and_jni_transaction_network_ids_require_exact_canonical_encodings() {
        const NETWORK_ID: &str =
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
        let canonical = CString::new(NETWORK_ID).expect("canonical network id has no NUL");
        let parsed =
            unsafe { read_network_id_bridge(canonical.as_ptr(), NETWORK_ID.len() as c_ulong) }
                .expect("canonical checksummed NetworkId must parse");
        assert_eq!(parsed.as_bytes().len(), Hash::LENGTH);
        assert_eq!(
            network_id_from_raw_bytes(parsed.as_bytes())
                .expect("JNI raw bytes must reconstruct the same NetworkId"),
            parsed
        );
        assert!(network_id_from_raw_bytes(&parsed.as_bytes()[..31]).is_err());
        let mut too_long = parsed.as_bytes().to_vec();
        too_long.push(0);
        assert!(network_id_from_raw_bytes(&too_long).is_err());
        assert!(network_id_from_raw_bytes(NETWORK_ID.as_bytes()).is_err());
        let mut unmarked = *parsed.as_bytes();
        unmarked[Hash::LENGTH - 1] &= !1;
        assert!(network_id_from_raw_bytes(&unmarked).is_err());
        let lowercase = NETWORK_ID.to_ascii_lowercase();
        for retired in [
            &NETWORK_ID[5..69],
            lowercase.as_str(),
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F1",
            "00000042",
        ] {
            let retired = CString::new(retired).expect("fixture has no NUL");
            assert!(matches!(
                unsafe {
                    read_network_id_bridge(retired.as_ptr(), retired.as_bytes().len() as c_ulong)
                },
                Err(BridgeError::NetworkId)
            ));
        }
    }
    #[test]
    fn retired_generic_privacy_jni_entrypoints_are_absent() {
        let source = bridge_source();
        for helper_stem in ["shield", "zk_transfer", "unshield"] {
            let retired_helper =
                ["java_native_encode_", helper_stem, "_signed_transaction"].concat();
            assert!(
                !source.contains(&retired_helper),
                "retired JNI helper must not remain: {retired_helper}"
            );
        }
        for method_name in [
            ["nativeEncode", "Sh", "ieldSignedTransaction"].concat(),
            ["nativeEncode", "Zk", "TransferSignedTransaction"].concat(),
            ["nativeEncode", "Un", "shieldSignedTransaction"].concat(),
        ] {
            for namespace in [
                "Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_",
                "Java_org_hyperledger_iroha_android_crypto_NativeSignerBridge_",
            ] {
                let export = format!("{namespace}{method_name}");
                assert!(
                    !source.contains(&export),
                    "retired JNI export must not remain: {export}"
                );
            }
        }
        assert!(source.contains("nativeEncodeRegisterZkAssetSignedTransaction"));
    }
    #[test]
    fn disabled_local_fetch_integrity_maps_to_options_error() {
        for field in ["verify_digests", "verify_lengths"] {
            assert_eq!(
                map_local_fetch_error(LocalFetchError::IntegrityVerificationDisabled(field)),
                ERR_FETCH_OPTIONS_JSON,
            );
        }
    }
    #[test]
    fn public_zk_quantity_parser_is_canonical_and_not_u128_bounded() {
        let wide = "340282366920938463463374607431768211456.25";
        assert_eq!(
            parse_public_quantity(wide.to_owned())
                .expect("public Quantity above u128 remains representable")
                .to_string(),
            wide
        );
        for malformed in ["01", "1.0", "-1"] {
            assert!(
                parse_public_quantity(malformed.to_owned()).is_err(),
                "noncanonical or negative public Quantity {malformed:?} must fail"
            );
        }
    }
    #[test]
    fn account_recipient_parser_requires_the_explicit_taira_discriminant() {
        const TAIRA_CHAIN_DISCRIMINANT: u16 = 369;
        const SORA_CHAIN_DISCRIMINANT: u16 = 753;
        let key_pair = KeyPair::try_from_seed(vec![0x39; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let account_id = AccountId::new(key_pair.public_key().clone());
        let address = AccountAddress::from_account_id(&account_id).expect("account address");
        let taira_recipient = address
            .to_i105_for_discriminant(TAIRA_CHAIN_DISCRIMINANT)
            .expect("Taira recipient");
        let sora_recipient = address
            .to_i105_for_discriminant(SORA_CHAIN_DISCRIMINANT)
            .expect("Sora recipient");
        assert_eq!(
            parse_account_id_for_chain(taira_recipient, TAIRA_CHAIN_DISCRIMINANT)
                .expect("canonical 369 recipient must parse under the scoped guard"),
            account_id
        );
        assert!(
            parse_account_id_for_chain(sora_recipient, TAIRA_CHAIN_DISCRIMINANT).is_err(),
            "a valid 753 recipient must fail when the JNI caller requires Taira 369"
        );
    }
    #[test]
    fn account_onboarding_body_bridge_returns_exact_bare_norito() {
        use crate::account_onboarding::{
            ConnectAccountOnboardingPlanBodyV1, ConnectAccountOnboardingPlanRequestV1,
        };
        use iroha_data_model::alias_setup::{
            AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasIntentV1,
            AliasLeaseAcquisitionV1, AliasPlanAnchorV1, AliasPlanDispositionV1,
            AliasPlanResourceV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
        };
        use norito::codec::Encode as _;
        let key_pair = KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519)
            .expect("derive onboarding bridge authority");
        let authority = AccountId::new(key_pair.public_key().clone());
        let alias = ResolvedAccountAliasV1::new(
            "merchant@paynet".parse().expect("account alias"),
            DataSpaceId::new(7),
        );
        let intent = AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias,
            target_account: authority.clone(),
            provision: AccountProvisionV1::Create,
            role: AccountAliasRoleV1::Primary,
        });
        let body = ConnectAccountOnboardingPlanBodyV1 {
            version: 1,
            request: ConnectAccountOnboardingPlanRequestV1 {
                version: 1,
                alias: "merchant@paynet".to_owned(),
                account_id: authority.to_string(),
                permissions: vec!["CanManageAlias".to_owned()],
            },
            authority,
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::new([0xA1])
            )),
            anchor: AliasPlanAnchorV1 {
                block_height: 9,
                block_hash: Hash::new(b"onboarding-bridge-anchor"),
            },
            resource: AliasPlanResourceV1 {
                intent,
                disposition: AliasPlanDispositionV1::NoOp,
                quote: None,
                instruction_index: None,
            },
            acquisition: AliasLeaseAcquisitionV1::new(1, None),
            quote_guard: AliasQuoteGuardV1 {
                expected_policy_version: 2,
                expected_payment_asset: "4rPeAP6jAjiLVZThZYwwPRBuQagt"
                    .parse()
                    .expect("payment asset"),
                max_amount: "10".parse::<Quantity>().expect("quantity"),
                valid_until_ms: 50_000,
            },
            instructions: Vec::new(),
            owner_auto_renew_instruction: None,
            valid_until_ms: 50_000,
        };
        let expected = body.encode();
        let json = norito::json::to_vec(&body).expect("onboarding body JSON");
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_encode_account_onboarding_plan_body_v1(
                json.as_ptr(),
                c_ulong::try_from(json.len()).expect("JSON length"),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(status, 0);
        assert!(!out_ptr.is_null());
        let actual = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        connect_norito_free(out_ptr);
        assert_eq!(actual, expected);
        let encoded_json = norito::json::to_json(&body).expect("onboarding body JSON text");
        let network_id_json =
            norito::json::to_value(&body.network_id).expect("NetworkId JSON value");
        let network_id = network_id_json
            .as_str()
            .expect("NetworkId JSON must be a string");
        let exact_field = format!("\"network_id\":\"{network_id}\"");
        assert!(encoded_json.contains(&exact_field));
        let genesis = encoded_json.replacen(&exact_field, "\"network_id\":\"genesis\"", 1);
        assert!(norito::json::from_str::<ConnectAccountOnboardingPlanBodyV1>(&genesis).is_err());
        let missing_owner_auto_renew =
            encoded_json.replacen("\"owner_auto_renew_instruction\":null,", "", 1);
        assert_ne!(missing_owner_auto_renew, encoded_json);
        assert!(
            norito::json::from_str::<ConnectAccountOnboardingPlanBodyV1>(
                &missing_owner_auto_renew,
            )
            .is_err(),
            "the exact V1 owner_auto_renew_instruction slot must be present even when null"
        );
        for retired in ["chain", "chainId", "chain_id"] {
            let replaced = encoded_json.replacen(
                &exact_field,
                &format!("\"{retired}\":\"onboarding-bridge-test\""),
                1,
            );
            assert!(
                norito::json::from_str::<ConnectAccountOnboardingPlanBodyV1>(&replaced).is_err(),
                "retired onboarding receipt key {retired} must fail closed"
            );
        }
    }
    #[test]
    fn alias_instruction_bridge_registry_decodes_and_reencodes_exact_frame() {
        use iroha_data_model::{
            alias_setup::{
                AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasIntentV1,
                AliasLeaseAcquisitionV1, AliasQuoteGuardV1, ResolvedAccountAliasV1,
            },
            isi::alias_setup::{EnsureAlias, RenewAliasLease},
        };
        let key_pair = KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519)
            .expect("derive alias bridge account");
        let instruction = EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: ResolvedAccountAliasV1::new(
                    "merchant@paynet".parse().expect("account alias"),
                    DataSpaceId::new(7),
                ),
                target_account: AccountId::new(key_pair.public_key().clone()),
                provision: AccountProvisionV1::Existing,
                role: AccountAliasRoleV1::Additional,
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: 2,
                expected_payment_asset: "4rPeAP6jAjiLVZThZYwwPRBuQagt"
                    .parse()
                    .expect("payment asset"),
                max_amount: "10".parse::<Quantity>().expect("quantity"),
                valid_until_ms: 50_000,
            },
        );
        let boxed: InstructionBox = instruction.into();
        let (wire_id, framed) = framed_instruction_payload(&boxed).expect("frame EnsureAlias");
        assert_eq!(wire_id, EnsureAlias::WIRE_ID);
        let mut out_frame_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_frame_len: c_ulong = 0;
        let mut out_json_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_json_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_alias_instruction_round_trip_v1(
                wire_id.as_ptr(),
                c_ulong::try_from(wire_id.len()).expect("wire ID length"),
                framed.as_ptr(),
                c_ulong::try_from(framed.len()).expect("frame length"),
                &mut out_frame_ptr,
                &mut out_frame_len,
                &mut out_json_ptr,
                &mut out_json_len,
            )
        };
        assert_eq!(status, 0);
        assert!(!out_frame_ptr.is_null());
        assert!(!out_json_ptr.is_null());
        let actual_frame =
            unsafe { slice::from_raw_parts(out_frame_ptr, out_frame_len as usize).to_vec() };
        let actual_json =
            unsafe { slice::from_raw_parts(out_json_ptr, out_json_len as usize).to_vec() };
        connect_norito_free(out_frame_ptr);
        connect_norito_free(out_json_ptr);
        assert_eq!(actual_frame, framed);
        let decoded_json: JsonValue =
            norito::json::from_slice(&actual_json).expect("typed alias bridge JSON");
        assert!(matches!(decoded_json, JsonValue::Object(_)));
        let wrong_wire_id = RenewAliasLease::WIRE_ID;
        let mut rejected_frame_ptr: *mut c_uchar = ptr::null_mut();
        let mut rejected_frame_len: c_ulong = 0;
        let mut rejected_json_ptr: *mut c_uchar = ptr::null_mut();
        let mut rejected_json_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_alias_instruction_round_trip_v1(
                wrong_wire_id.as_ptr(),
                c_ulong::try_from(wrong_wire_id.len()).expect("wire ID length"),
                framed.as_ptr(),
                c_ulong::try_from(framed.len()).expect("frame length"),
                &mut rejected_frame_ptr,
                &mut rejected_frame_len,
                &mut rejected_json_ptr,
                &mut rejected_json_len,
            )
        };
        assert_eq!(status, ERR_ALIAS_INSTRUCTION);
        assert!(rejected_frame_ptr.is_null());
        assert_eq!(rejected_frame_len, 0);
        assert!(rejected_json_ptr.is_null());
        assert_eq!(rejected_json_len, 0);
    }
    struct ResetConfig(AccelerationConfig);
    impl Drop for ResetConfig {
        fn drop(&mut self) {
            ivm::set_acceleration_config(self.0);
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
    fn take_privacy_compiled_profile_catalog_output(
        out_ptr: *mut c_uchar,
        out_len: c_ulong,
    ) -> PrivacyCompiledProfileCatalogV1 {
        assert!(!out_ptr.is_null());
        let bytes = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        iroha_privacy_free_buffer(out_ptr);
        norito::decode_from_bytes(&bytes).expect("decode canonical compiled-profile catalog")
    }
    #[test]
    fn privacy_compiled_profile_catalog_ffi_round_trips_and_rejects_adversaries() {
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status =
            unsafe { iroha_privacy_compiled_profile_catalog_v1(&mut out_ptr, &mut out_len) };
        assert_eq!(status, 0);
        assert_eq!(
            unsafe { iroha_privacy_validate_compiled_profile_catalog_v1(out_ptr, out_len) },
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid.code()
        );
        assert_eq!(
            unsafe { iroha_privacy_validate_compiled_profile_catalog_v1(ptr::null(), out_len) },
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::NullPointer.code()
        );
        assert_eq!(
            unsafe { iroha_privacy_validate_compiled_profile_catalog_v1(out_ptr, 0) },
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Empty.code()
        );
        let archive = unsafe { slice::from_raw_parts(out_ptr, out_len as usize) };
        let mut one_byte_fake = norito::encode_canonical(&0_u8).expect("encode one-byte fake");
        one_byte_fake[6..22].copy_from_slice(&archive[6..22]);
        assert_ne!(
            unsafe {
                iroha_privacy_validate_compiled_profile_catalog_v1(
                    one_byte_fake.as_ptr(),
                    c_ulong::try_from(one_byte_fake.len()).expect("one-byte fake length"),
                )
            },
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid.code()
        );
        for truncated in [
            &archive[..archive.len() - 1],
            &archive[1..],
            &archive[..archive.len() / 2],
        ] {
            assert_ne!(
                unsafe {
                    iroha_privacy_validate_compiled_profile_catalog_v1(
                        truncated.as_ptr(),
                        c_ulong::try_from(truncated.len()).expect("truncated length"),
                    )
                },
                PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid.code()
            );
        }
        let mut trailing = archive.to_vec();
        trailing.push(0);
        assert_ne!(
            unsafe {
                iroha_privacy_validate_compiled_profile_catalog_v1(
                    trailing.as_ptr(),
                    c_ulong::try_from(trailing.len()).expect("trailing length"),
                )
            },
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid.code()
        );
        let catalog = take_privacy_compiled_profile_catalog_output(out_ptr, out_len);
        catalog.validate().expect("FFI compiled-profile catalog");
        assert_eq!(catalog.protocols.len(), PrivacyProtocolIdV1::COUNT);
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
            .expect("at least one available profile");
        let mut digest = *profile.verifier_digest.as_bytes();
        digest[0] ^= 0x80;
        profile.verifier_digest = iroha_data_model::privacy::PrivacyVerifierDigestV1::new(digest);
        let substituted =
            norito::encode_canonical(&substituted).expect("canonical substituted catalog");
        assert_eq!(
            unsafe {
                iroha_privacy_validate_compiled_profile_catalog_v1(
                    substituted.as_ptr(),
                    c_ulong::try_from(substituted.len()).expect("substituted length"),
                )
            },
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::InvalidCatalog.code()
        );
    }
    #[test]
    fn privacy_compiled_profile_catalog_ffi_initializes_from_small_stack_in_fresh_process() {
        const CHILD_ENV: &str = "IROHA_TEST_PRIVACY_CATALOG_SMALL_STACK_CHILD_V1";
        const CALLER_STACK_BYTES: usize = 512 * 1024;
        const CONCURRENT_CALLERS: usize = 8;
        const TEST_NAME: &str = "tests::privacy_compiled_profile_catalog_ffi_initializes_from_small_stack_in_fresh_process";
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("resolve the current Rust test executable"),
            )
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("launch a fresh catalog-export test process");
            assert!(
                output.status.success(),
                "fresh small-stack catalog export failed with {status}; stdout:\n{stdout}\nstderr:\n{stderr}",
                status = output.status,
                stdout = String::from_utf8_lossy(&output.stdout),
                stderr = String::from_utf8_lossy(&output.stderr),
            );
            return;
        }
        assert!(
            PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_V1.get().is_none(),
            "the child process must exercise first initialization, not a warmed archive cache"
        );
        std::thread::Builder::new()
            .name("privacy-catalog-ffi-null-small-stack-caller".to_owned())
            .stack_size(CALLER_STACK_BYTES)
            .spawn(|| {
                let mut cleared_ptr = ptr::dangling_mut::<c_uchar>();
                let mut cleared_len = c_ulong::MAX;
                assert_eq!(
                    unsafe {
                        iroha_privacy_compiled_profile_catalog_v1(ptr::null_mut(), &mut cleared_len)
                    },
                    ERR_NULL_PTR
                );
                assert_eq!(cleared_len, 0);
                assert_eq!(
                    unsafe {
                        iroha_privacy_compiled_profile_catalog_v1(&mut cleared_ptr, ptr::null_mut())
                    },
                    ERR_NULL_PTR
                );
                assert!(cleared_ptr.is_null());
                assert!(
                    PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_V1.get().is_none(),
                    "null outputs must reject before initializing the catalog"
                );
            })
            .expect("spawn the 512 KiB null-output caller thread")
            .join()
            .expect("null-output rejection must not exhaust the 512 KiB caller stack");
        let start = Arc::new(std::sync::Barrier::new(CONCURRENT_CALLERS));
        let callers = (0..CONCURRENT_CALLERS)
            .map(|index| {
                let start = Arc::clone(&start);
                std::thread::Builder::new()
                    .name(format!("privacy-catalog-ffi-small-stack-caller-{index}"))
                    .stack_size(CALLER_STACK_BYTES)
                    .spawn(move || {
                        start.wait();
                        let mut out_ptr = ptr::null_mut();
                        let mut out_len = 0;
                        assert_eq!(
                            unsafe {
                                iroha_privacy_compiled_profile_catalog_v1(
                                    &mut out_ptr,
                                    &mut out_len,
                                )
                            },
                            0
                        );
                        assert!(!out_ptr.is_null());
                        assert!(out_len > 0);
                        let out_len = usize::try_from(out_len).expect("catalog length fits usize");
                        assert!(out_len <= PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES_V1);
                        assert_eq!(
                            unsafe {
                                iroha_privacy_validate_compiled_profile_catalog_v1(
                                    out_ptr,
                                    c_ulong::try_from(out_len)
                                        .expect("catalog length fits c_ulong"),
                                )
                            },
                            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid.code()
                        );
                        let archive = unsafe { slice::from_raw_parts(out_ptr, out_len).to_vec() };
                        (out_ptr as usize, archive)
                    })
                    .expect("spawn a 512 KiB concurrent catalog caller")
            })
            .collect::<Vec<_>>();
        let outputs = callers
            .into_iter()
            .map(|caller| {
                caller
                    .join()
                    .expect("catalog export must not exhaust a 512 KiB caller stack")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_INITIALIZATIONS_V1.load(Ordering::Relaxed),
            1,
            "concurrent cold callers must serialize one owned-stack initialization"
        );
        let cached = PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_V1
            .get()
            .expect("successful first export initializes the bounded archive cache")
            .as_ref()
            .expect("the catalog archive must initialize successfully");
        assert!(outputs.iter().all(|(_, archive)| archive == cached));
        assert_eq!(
            outputs
                .iter()
                .map(|(address, _)| *address)
                .collect::<HashSet<_>>()
                .len(),
            CONCURRENT_CALLERS,
            "each simultaneous FFI caller must own an independent output allocation"
        );
        for (address, _) in outputs {
            iroha_privacy_free_buffer(address as *mut c_uchar);
        }
    }
    #[test]
    fn privacy_compiled_profile_catalog_c_and_java_archives_are_byte_identical() {
        let mut out_ptr = ptr::null_mut();
        let mut out_len = 0;
        assert_eq!(
            unsafe { iroha_privacy_compiled_profile_catalog_v1(&mut out_ptr, &mut out_len) },
            0
        );
        assert!(!out_ptr.is_null());
        let c_archive = unsafe {
            slice::from_raw_parts(
                out_ptr,
                usize::try_from(out_len).expect("C catalog length fits usize"),
            )
            .to_vec()
        };
        iroha_privacy_free_buffer(out_ptr);
        let java_archive = java_privacy_compiled_profile_catalog_archive()
            .expect("Java catalog helper must clone the shared archive");
        assert_eq!(java_archive, c_archive);
        assert_eq!(
            validate_local_privacy_compiled_profile_catalog_archive_v1(&java_archive),
            PrivacyCompiledProfileCatalogArchiveValidationStatusV1::Valid
        );
    }
    #[test]
    fn privacy_exact12_fixture_ffi_returns_and_validates_complete_canonical_bytes() {
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status = unsafe { iroha_privacy_exact12_fixture_bundle_v1(&mut out_ptr, &mut out_len) };
        assert_eq!(status, 0);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        assert_eq!(
            unsafe { iroha_privacy_validate_exact12_fixture_bundle_v1(out_ptr, out_len) },
            PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
        );
        assert_eq!(
            unsafe { iroha_privacy_validate_exact12_fixture_bundle_v1(ptr::null(), out_len) },
            PrivacyExact12FixtureBundleValidationStatusV1::NullPointer.code()
        );
        assert_eq!(
            unsafe { iroha_privacy_validate_exact12_fixture_bundle_v1(out_ptr, 0) },
            PrivacyExact12FixtureBundleValidationStatusV1::Empty.code()
        );
        let archive = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        assert_eq!(
            archive,
            privacy_exact12_fixture_bundle_bytes_v1().expect("compiled exact12 fixture")
        );
        let mut truncated = archive;
        truncated.pop();
        assert_ne!(
            unsafe {
                iroha_privacy_validate_exact12_fixture_bundle_v1(
                    truncated.as_ptr(),
                    c_ulong::try_from(truncated.len()).expect("truncated length"),
                )
            },
            PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
        );
        iroha_privacy_free_buffer(out_ptr);
    }
    #[test]
    fn privacy_exact12_java_archive_is_bounded_deterministic_and_mutation_closed() {
        let archive =
            java_privacy_exact12_fixture_bundle_archive().expect("compiled Java fixture bundle");
        assert_eq!(
            archive,
            privacy_exact12_fixture_bundle_bytes_v1().expect("compiled exact12 fixture")
        );
        assert!(archive.len() <= PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1);
        assert_eq!(
            java_privacy_validate_exact12_fixture_bundle_bytes(Some(&archive)),
            PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
        );
        assert_eq!(
            java_privacy_validate_exact12_fixture_bundle_bytes(None),
            PrivacyExact12FixtureBundleValidationStatusV1::NullPointer.code()
        );
        assert_eq!(
            java_privacy_validate_exact12_fixture_bundle_bytes(Some(&[])),
            PrivacyExact12FixtureBundleValidationStatusV1::Empty.code()
        );
        let oversized = vec![0; PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 + 1];
        assert_eq!(
            java_privacy_validate_exact12_fixture_bundle_bytes(Some(&oversized)),
            PrivacyExact12FixtureBundleValidationStatusV1::ArchiveTooLarge.code()
        );
        for truncated in [
            &archive[..archive.len() - 1],
            &archive[1..],
            &archive[..archive.len() / 2],
        ] {
            assert_ne!(
                java_privacy_validate_exact12_fixture_bundle_bytes(Some(truncated)),
                PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
            );
        }
        let mut trailing = archive.clone();
        trailing.push(0);
        assert_ne!(
            java_privacy_validate_exact12_fixture_bundle_bytes(Some(&trailing)),
            PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
        );
        for index in [0, archive.len() / 2, archive.len() - 1] {
            let mut mutated = archive.clone();
            mutated[index] ^= 0x80;
            assert_ne!(
                java_privacy_validate_exact12_fixture_bundle_bytes(Some(&mutated)),
                PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
            );
        }
        let catalog_archive = norito::encode_canonical(
            &privacy_compiled_profile_catalog().expect("compiled-profile catalog"),
        )
        .expect("catalog archive");
        assert_ne!(
            java_privacy_validate_exact12_fixture_bundle_bytes(Some(&catalog_archive)),
            PrivacyExact12FixtureBundleValidationStatusV1::Valid.code()
        );
    }
    fn canonical_bytes(address: &AccountAddress) -> Vec<u8> {
        let hex = address.canonical_hex().expect("canonical hex");
        let body = hex.strip_prefix("0x").unwrap_or(hex.as_str());
        hex::decode(body).expect("canonical decode")
    }
    fn sign_and_verify_roundtrip(
        algorithm: Algorithm,
        private_key: &[u8],
        message: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut pk_ptr: *mut c_uchar = ptr::null_mut();
        let mut pk_len: c_ulong = 0;
        let rc_pk = unsafe {
            connect_norito_public_key_from_private(
                algorithm as u8,
                private_key.as_ptr(),
                private_key.len() as c_ulong,
                &mut pk_ptr,
                &mut pk_len,
            )
        };
        assert_eq!(rc_pk, 0, "public key derivation must succeed");
        let public_key = unsafe { slice::from_raw_parts(pk_ptr, pk_len as usize).to_vec() };
        connect_norito_free(pk_ptr);
        let mut sig_ptr: *mut c_uchar = ptr::null_mut();
        let mut sig_len: c_ulong = 0;
        let rc_sig = unsafe {
            connect_norito_sign_detached(
                algorithm as u8,
                private_key.as_ptr(),
                private_key.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                &mut sig_ptr,
                &mut sig_len,
            )
        };
        assert_eq!(rc_sig, 0, "signing must succeed");
        let signature = unsafe { slice::from_raw_parts(sig_ptr, sig_len as usize).to_vec() };
        connect_norito_free(sig_ptr);
        let mut valid: c_uchar = 0;
        let rc_verify = unsafe {
            connect_norito_verify_detached(
                algorithm as u8,
                public_key.as_ptr(),
                public_key.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
                &mut valid,
            )
        };
        assert_eq!(rc_verify, 0, "verification call must succeed");
        assert_eq!(valid, 1, "signature must verify");
        (signature, public_key)
    }
    fn checked_identifier_receipt_ed25519_key_fixture() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked identifier receipt Ed25519 fixture keypair")
    }
    const SMALL_ORDER_ED25519_R: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const NONCANONICAL_ED25519_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const SMALL_ORDER_ED25519_PUBLIC_KEY: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    const NONCANONICAL_ED25519_PUBLIC_KEY: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    #[test]
    fn identifier_receipt_fixture_uses_checked_ed25519_key_generation() {
        let key_pair = checked_identifier_receipt_ed25519_key_fixture();
        let algorithm = key_pair
            .public_key()
            .try_algorithm()
            .expect("fixture identifier receipt public key has a valid algorithm");
        assert_eq!(algorithm, Algorithm::Ed25519);
    }
    fn sample_identifier_receipt_payload() -> IdentifierResolutionReceiptPayload {
        let signatory = checked_identifier_receipt_ed25519_key_fixture()
            .public_key()
            .clone();
        let opening_payload = iroha_data_model::ram_lfe::RamLfeOutputOpeningPayload {
            program_id: "identifier_lookup_retail"
                .parse()
                .expect("valid program id"),
            input_ciphertext_hash: Hash::new(b"input-ciphertext"),
            output_ciphertext_hash: Hash::new(b"output-ciphertext"),
            parameter_digest: Hash::new(b"parameters"),
            evaluation_key_digest: Hash::new(b"evaluation-keys"),
            opened_output_hash: Hash::new(b"opened-output"),
            opened_at_ms: 8,
            expires_at_ms: Some(107),
        };
        let opening_signer = checked_identifier_receipt_ed25519_key_fixture();
        IdentifierResolutionReceiptPayload {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"identifier-component-network",
                )),
            ),
            policy_id: "email#retail".parse().expect("valid policy id"),
            execution: iroha_data_model::ram_lfe::RamLfeExecutionReceiptPayload {
                program_id: "identifier_lookup_retail"
                    .parse()
                    .expect("valid program id"),
                program_digest: Hash::new(b"program"),
                backend: iroha_crypto::RamLfeBackend::BfvProgrammedV1,
                verification_mode: iroha_crypto::RamLfeVerificationMode::Signed,
                input_ciphertext_hash: Hash::new(b"input-ciphertext"),
                output_ciphertext_hash: Hash::new(b"output-ciphertext"),
                parameter_digest: Hash::new(b"parameters"),
                evaluation_key_digest: Hash::new(b"evaluation-keys"),
                output_hash: Hash::new(b"output"),
                associated_data_hash: Hash::new(b"associated-data"),
                executed_at_ms: 7,
                expires_at_ms: Some(107),
            },
            opening: iroha_data_model::ram_lfe::RamLfeOutputOpening {
                signature: SignatureOf::try_new(opening_signer.private_key(), &opening_payload)
                    .expect("fixture opening payload must sign")
                    .into(),
                payload: opening_payload,
            },
            opaque_id: iroha_data_model::account::OpaqueAccountId::from_hash(Hash::new(b"opaque")),
            receipt_hash: Hash::new(b"receipt"),
            uaid: iroha_data_model::nexus::UniversalAccountId::from_hash(Hash::new(b"uaid")),
            account_id: AccountId::new(signatory),
        }
    }
    fn sample_identifier_receipt_attestation_signer() -> KeyPair {
        KeyPair::try_from_seed(vec![0x49; 32], Algorithm::Ed25519)
            .expect("derive canonical identifier receipt attestation signer")
    }
    fn sample_identifier_signature_hex(payload: &IdentifierResolutionReceiptPayload) -> String {
        let signer = sample_identifier_receipt_attestation_signer();
        let signature = SignatureOf::try_new(signer.private_key(), payload)
            .expect("sign canonical identifier receipt fixture payload");
        hex::encode(signature.payload())
    }
    fn hex_hash(hash: Hash) -> String {
        hex::encode(&hash.as_ref()[..])
    }
    fn sample_identifier_receipt_json(
        payload: &IdentifierResolutionReceiptPayload,
        attestation: JsonValue,
    ) -> JsonValue {
        json_object([
            (
                "payload",
                json_object([
                    (
                        "network_id",
                        JsonValue::from(hex::encode(payload.network_id.as_bytes())),
                    ),
                    ("policy_id", JsonValue::from("email#retail")),
                    (
                        "execution",
                        json_object([
                            ("program_id", JsonValue::from("identifier_lookup_retail")),
                            (
                                "program_digest",
                                JsonValue::from(hex_hash(payload.execution.program_digest)),
                            ),
                            ("backend", JsonValue::from("bfv-programmed-v1")),
                            ("verification_mode", JsonValue::from("signed")),
                            (
                                "input_ciphertext_hash",
                                JsonValue::from(hex_hash(payload.execution.input_ciphertext_hash)),
                            ),
                            (
                                "output_ciphertext_hash",
                                JsonValue::from(hex_hash(payload.execution.output_ciphertext_hash)),
                            ),
                            (
                                "parameter_digest",
                                JsonValue::from(hex_hash(payload.execution.parameter_digest)),
                            ),
                            (
                                "evaluation_key_digest",
                                JsonValue::from(hex_hash(payload.execution.evaluation_key_digest)),
                            ),
                            (
                                "output_hash",
                                JsonValue::from(hex_hash(payload.execution.output_hash)),
                            ),
                            (
                                "associated_data_hash",
                                JsonValue::from(hex_hash(payload.execution.associated_data_hash)),
                            ),
                            (
                                "executed_at_ms",
                                JsonValue::from(payload.execution.executed_at_ms),
                            ),
                            (
                                "expires_at_ms",
                                JsonValue::from(
                                    payload.execution.expires_at_ms.expect("sample expiry"),
                                ),
                            ),
                        ]),
                    ),
                    (
                        "opening",
                        json_object([
                            (
                                "payload",
                                json_object([
                                    (
                                        "program_id",
                                        JsonValue::from(
                                            payload.opening.payload.program_id.to_string(),
                                        ),
                                    ),
                                    (
                                        "input_ciphertext_hash",
                                        JsonValue::from(hex_hash(
                                            payload.opening.payload.input_ciphertext_hash,
                                        )),
                                    ),
                                    (
                                        "output_ciphertext_hash",
                                        JsonValue::from(hex_hash(
                                            payload.opening.payload.output_ciphertext_hash,
                                        )),
                                    ),
                                    (
                                        "parameter_digest",
                                        JsonValue::from(hex_hash(
                                            payload.opening.payload.parameter_digest,
                                        )),
                                    ),
                                    (
                                        "evaluation_key_digest",
                                        JsonValue::from(hex_hash(
                                            payload.opening.payload.evaluation_key_digest,
                                        )),
                                    ),
                                    (
                                        "opened_output_hash",
                                        JsonValue::from(hex_hash(
                                            payload.opening.payload.opened_output_hash,
                                        )),
                                    ),
                                    (
                                        "opened_at_ms",
                                        JsonValue::from(payload.opening.payload.opened_at_ms),
                                    ),
                                    (
                                        "expires_at_ms",
                                        JsonValue::from(
                                            payload
                                                .opening
                                                .payload
                                                .expires_at_ms
                                                .expect("sample opening expiry"),
                                        ),
                                    ),
                                ]),
                            ),
                            (
                                "signature",
                                JsonValue::from(hex::encode(payload.opening.signature.payload())),
                            ),
                        ]),
                    ),
                    ("opaque_id", JsonValue::from(payload.opaque_id.to_string())),
                    (
                        "receipt_hash",
                        JsonValue::from(hex_hash(payload.receipt_hash)),
                    ),
                    ("uaid", JsonValue::from(payload.uaid.to_string())),
                    (
                        "account_id",
                        JsonValue::from(payload.account_id.to_string()),
                    ),
                ]),
            ),
            ("attestation", attestation),
        ])
    }
    fn sample_identifier_signed_receipt_json(
        payload: &IdentifierResolutionReceiptPayload,
    ) -> JsonValue {
        sample_identifier_receipt_json(
            payload,
            json_object([
                ("kind", JsonValue::from("signed")),
                (
                    "signature",
                    JsonValue::from(sample_identifier_signature_hex(payload).to_uppercase()),
                ),
            ]),
        )
    }
    fn set_json_string_at_path(value: &mut JsonValue, path: &[&str], replacement: String) {
        assert!(!path.is_empty(), "json path must not be empty");
        let mut cursor = value;
        for key in &path[..path.len() - 1] {
            cursor = cursor
                .as_object_mut()
                .expect("path segment must be object")
                .get_mut(*key)
                .expect("path segment must exist");
        }
        cursor
            .as_object_mut()
            .expect("path parent must be object")
            .insert(
                path[path.len() - 1].to_owned(),
                JsonValue::from(replacement),
            );
    }
    fn sample_rwa_id_literal() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities.universal"
            .to_owned()
    }
    #[test]
    fn parse_identifier_receipt_accepts_canonical_payload_attestation() {
        let payload = sample_identifier_receipt_payload();
        let receipt =
            parse_identifier_receipt_value(sample_identifier_signed_receipt_json(&payload))
                .expect("parse structured torii receipt");
        assert_eq!(receipt.payload, payload);
        let RamLfeReceiptAttestation::Signed(signature) = receipt.attestation else {
            panic!("receipt attestation must be signed");
        };
        assert_eq!(
            hex::encode(signature.payload()),
            sample_identifier_signature_hex(&payload)
        );
    }
    #[test]
    fn parse_identifier_receipt_requires_exact_raw_marked_network() {
        let payload = sample_identifier_receipt_payload();
        let raw = hex::encode(payload.network_id.as_bytes());
        let mut unmarked = payload.network_id.as_bytes().to_vec();
        *unmarked.last_mut().expect("network bytes") &= 0xFE;
        for literal in [
            raw.to_uppercase(),
            format!(" {raw}"),
            format!("hash:{raw}"),
            hex::encode(unmarked),
            "00".repeat(31),
        ] {
            let mut value = sample_identifier_signed_receipt_json(&payload);
            set_json_string_at_path(&mut value, &["payload", "network_id"], literal);
            assert!(matches!(
                parse_identifier_receipt_value(value),
                Err(BridgeError::IdentifierReceipt)
            ));
        }
        let mut value = sample_identifier_signed_receipt_json(&payload);
        value
            .as_object_mut()
            .expect("receipt")
            .get_mut("payload")
            .expect("payload")
            .as_object_mut()
            .expect("payload object")
            .remove("network_id");
        assert!(matches!(
            parse_identifier_receipt_value(value),
            Err(BridgeError::IdentifierReceipt)
        ));
    }
    #[test]
    fn parse_identifier_receipt_rejects_signature_case_aliases() {
        let payload = sample_identifier_receipt_payload();
        for (path, replacement) in [
            (
                vec!["attestation", "signature"],
                sample_identifier_signature_hex(&payload),
            ),
            (
                vec!["payload", "opening", "signature"],
                hex::encode_upper(payload.opening.signature.payload()),
            ),
        ] {
            let mut value = sample_identifier_signed_receipt_json(&payload);
            set_json_string_at_path(&mut value, &path, replacement);
            assert!(matches!(
                parse_identifier_receipt_value(value),
                Err(BridgeError::IdentifierReceipt)
            ));
        }
    }
    #[test]
    fn parse_identifier_receipt_accepts_mldsa_signed_attestation() {
        let payload = sample_identifier_receipt_payload();
        let signer = KeyPair::try_from_seed(b"identifier-receipt-mldsa".to_vec(), Algorithm::MlDsa)
            .expect("derive ML-DSA identifier receipt attestation signer");
        let signature = SignatureOf::try_new(signer.private_key(), &payload)
            .expect("sign ML-DSA identifier receipt fixture payload");
        let signature_hex = hex::encode(signature.payload());
        let receipt = parse_identifier_receipt_value(sample_identifier_receipt_json(
            &payload,
            json_object([
                ("kind", JsonValue::from("signed")),
                ("signature", JsonValue::from(signature_hex.to_uppercase())),
            ]),
        ))
        .expect("parse ML-DSA signed structured torii receipt");
        assert_eq!(receipt.payload, payload);
        let RamLfeReceiptAttestation::Signed(signature) = &receipt.attestation else {
            panic!("receipt attestation must be signed");
        };
        assert_eq!(hex::encode(signature.payload()), signature_hex);
        receipt
            .verify(signer.public_key())
            .expect("ML-DSA identifier receipt signature should verify");
    }
    #[test]
    fn parse_identifier_receipt_rejects_malformed_mldsa_signed_attestation_lengths() {
        let payload = sample_identifier_receipt_payload();
        let signer = KeyPair::try_from_seed(
            b"identifier-receipt-mldsa-length".to_vec(),
            Algorithm::MlDsa,
        )
        .expect("derive ML-DSA identifier receipt attestation signer");
        let signature = SignatureOf::try_new(signer.private_key(), &payload)
            .expect("sign ML-DSA identifier receipt fixture payload");
        for label in ["short", "overlong"] {
            let mut signature_bytes = signature.payload().to_vec();
            match label {
                "short" => {
                    signature_bytes
                        .pop()
                        .expect("ML-DSA fixture signature is non-empty");
                }
                "overlong" => signature_bytes.push(0xA5),
                _ => unreachable!("covered labels"),
            }
            let receipt = sample_identifier_receipt_json(
                &payload,
                json_object([
                    ("kind", JsonValue::from("signed")),
                    (
                        "signature",
                        JsonValue::from(hex::encode_upper(signature_bytes)),
                    ),
                ]),
            );
            let receipt = parse_identifier_receipt_value(receipt)
                .expect("retain nonzero envelope before pinned algorithm admission");
            assert!(
                receipt.verify(signer.public_key()).is_err(),
                "{label} ML-DSA signature length must reject under the pinned key"
            );
        }
    }
    #[test]
    fn parse_identifier_receipt_rejects_all_zero_signed_attestation() {
        let payload = sample_identifier_receipt_payload();
        let mut value = sample_identifier_signed_receipt_json(&payload);
        set_json_string_at_path(&mut value, &["attestation", "signature"], "00".repeat(64));
        let err = parse_identifier_receipt_value(value)
            .expect_err("all-zero identifier receipt signature must reject");
        assert!(matches!(err, BridgeError::IdentifierReceipt));
    }
    #[test]
    fn parse_identifier_receipt_rejects_retired_signed_attestation_algorithm() {
        let payload = sample_identifier_receipt_payload();
        let mut value = sample_identifier_signed_receipt_json(&payload);
        value
            .as_object_mut()
            .expect("receipt object")
            .get_mut("attestation")
            .expect("attestation")
            .as_object_mut()
            .expect("attestation object")
            .insert("algorithm".into(), JsonValue::from("ed25519"));
        let err = parse_identifier_receipt_value(value)
            .expect_err("current public Signed DTO has exactly kind and signature");
        assert!(matches!(err, BridgeError::IdentifierReceipt));
    }
    #[test]
    fn parse_identifier_receipt_rejects_malformed_ed25519_signed_attestation_r() {
        let payload = sample_identifier_receipt_payload();
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let mut signature_bytes =
                hex::decode(sample_identifier_signature_hex(&payload)).expect("signature hex");
            signature_bytes[..replacement_r.len()].copy_from_slice(&replacement_r);
            let mut value = sample_identifier_signed_receipt_json(&payload);
            set_json_string_at_path(
                &mut value,
                &["attestation", "signature"],
                hex::encode_upper(signature_bytes),
            );
            let receipt = parse_identifier_receipt_value(value)
                .expect("retain nonzero envelope before pinned algorithm admission");
            assert!(
                receipt
                    .verify(sample_identifier_receipt_attestation_signer().public_key())
                    .is_err(),
                "{label} signature R must reject under the pinned resolver key"
            );
        }
    }
    #[test]
    fn parse_identifier_receipt_rejects_malformed_output_opening_signature_r() {
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_ED25519_R),
            ("noncanonical", NONCANONICAL_ED25519_R),
        ] {
            let mut payload = sample_identifier_receipt_payload();
            let mut signature = payload.opening.signature.payload().to_vec();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            payload.opening.signature = Signature::from_bytes(&signature);
            let receipt =
                parse_identifier_receipt_value(sample_identifier_signed_receipt_json(&payload))
                    .expect("retain nonzero opening envelope before pinned algorithm admission");
            assert!(
                receipt
                    .payload
                    .opening
                    .verify_signature(checked_identifier_receipt_ed25519_key_fixture().public_key())
                    .is_err(),
                "{label} output-opening signature R must reject under the pinned opener key"
            );
        }
    }
    #[test]
    fn parse_identifier_receipt_rejects_all_zero_output_opening_signature() {
        let mut payload = sample_identifier_receipt_payload();
        payload.opening.signature = Signature::from_bytes(&[0_u8; 64]);
        let err = parse_identifier_receipt_value(sample_identifier_signed_receipt_json(&payload))
            .expect_err("all-zero output-opening signature must reject while parsing");
        assert!(matches!(err, BridgeError::IdentifierReceipt));
    }
    #[test]
    fn validate_identifier_claim_account_rejects_mismatched_receipt_account() {
        let payload = sample_identifier_receipt_payload();
        let receipt =
            parse_identifier_receipt_value(sample_identifier_signed_receipt_json(&payload))
                .expect("parse structured torii receipt");
        validate_identifier_claim_account(&payload.account_id, &receipt)
            .expect("matching claim account must pass");
        let other_account = AccountId::new(
            checked_identifier_receipt_ed25519_key_fixture()
                .public_key()
                .clone(),
        );
        let err = validate_identifier_claim_account(&other_account, &receipt)
            .expect_err("mismatched claim account must fail before transaction encoding");
        assert!(matches!(err, BridgeError::IdentifierReceipt));
    }
    #[test]
    fn parse_identifier_receipt_rejects_padded_payload_fields() {
        let payload = sample_identifier_receipt_payload();
        let mut cases: Vec<(Vec<&str>, String)> = vec![
            (vec!["payload", "policy_id"], " email#retail".to_owned()),
            (
                vec!["payload", "execution", "program_id"],
                "identifier_lookup_retail ".to_owned(),
            ),
            (
                vec!["payload", "execution", "backend"],
                " bfv-programmed-v1".to_owned(),
            ),
            (
                vec!["payload", "execution", "verification_mode"],
                "signed ".to_owned(),
            ),
            (
                vec!["payload", "execution", "program_digest"],
                format!(" {}", hex_hash(payload.execution.program_digest)),
            ),
            (
                vec!["payload", "execution", "input_ciphertext_hash"],
                format!("{} ", hex_hash(payload.execution.input_ciphertext_hash)),
            ),
            (
                vec!["payload", "opening", "payload", "program_id"],
                " identifier_lookup_retail".to_owned(),
            ),
            (
                vec!["payload", "opening", "payload", "input_ciphertext_hash"],
                format!(
                    "{} ",
                    hex_hash(payload.opening.payload.input_ciphertext_hash)
                ),
            ),
            (
                vec!["payload", "opening", "signature"],
                format!(" {}", hex::encode(payload.opening.signature.payload())),
            ),
            (
                vec!["payload", "receipt_hash"],
                format!("{} ", hex_hash(payload.receipt_hash)),
            ),
            (
                vec!["payload", "opaque_id"],
                format!(" {}", payload.opaque_id),
            ),
            (vec!["payload", "uaid"], format!("{} ", payload.uaid)),
            (
                vec!["payload", "account_id"],
                format!(" {}", payload.account_id),
            ),
            (
                vec!["attestation", "signature"],
                format!("{} ", sample_identifier_signature_hex(&payload)),
            ),
            (vec!["attestation", "kind"], " signed".to_owned()),
        ];
        cases.push((
            vec!["payload", "execution", "associated_data_hash"],
            format!(" {}", hex_hash(payload.execution.associated_data_hash)),
        ));
        for (path, replacement) in cases {
            let mut value = sample_identifier_signed_receipt_json(&payload);
            set_json_string_at_path(&mut value, &path, replacement);
            let err = parse_identifier_receipt_value(value)
                .expect_err("padded identifier receipt field must fail");
            assert!(
                matches!(err, BridgeError::IdentifierReceipt),
                "unexpected error for {path:?}: {err:?}"
            );
        }
        for (kind, business_rule) in [(" email", "retail"), ("email", "retail ")] {
            let mut policy_object_value = sample_identifier_signed_receipt_json(&payload);
            policy_object_value
                .as_object_mut()
                .expect("receipt object")
                .get_mut("payload")
                .expect("payload")
                .as_object_mut()
                .expect("payload object")
                .insert(
                    "policy_id".to_owned(),
                    json_object([
                        ("kind", JsonValue::from(kind)),
                        ("business_rule", JsonValue::from(business_rule)),
                    ]),
                );
            let err = parse_identifier_receipt_value(policy_object_value)
                .expect_err("padded policy-id object fields must fail");
            assert!(matches!(err, BridgeError::IdentifierReceipt));
        }
    }
    #[test]
    fn parse_identifier_receipt_rejects_padded_proof_attestation_fields() {
        let payload = sample_identifier_receipt_payload();
        let canonical = sample_identifier_receipt_json(
            &payload,
            json_object([
                ("kind", JsonValue::from("proof")),
                ("proof_backend", JsonValue::from("pipa-r/pasta")),
                ("proof_b64", JsonValue::from("AQID")),
            ]),
        );
        parse_identifier_receipt_value(canonical)
            .expect("canonical proof attestation receipt must parse");
        for (path, replacement) in [
            (
                vec!["attestation", "proof_backend"],
                " pipa-r/pasta".to_owned(),
            ),
            (vec!["attestation", "proof_b64"], "AQID ".to_owned()),
            (vec!["attestation", "kind"], " proof".to_owned()),
        ] {
            let mut value = sample_identifier_receipt_json(
                &payload,
                json_object([
                    ("kind", JsonValue::from("proof")),
                    ("proof_backend", JsonValue::from("pipa-r/pasta")),
                    ("proof_b64", JsonValue::from("AQID")),
                ]),
            );
            set_json_string_at_path(&mut value, &path, replacement);
            let err = parse_identifier_receipt_value(value)
                .expect_err("padded proof attestation field must fail");
            assert!(
                matches!(err, BridgeError::IdentifierReceipt),
                "unexpected error for {path:?}: {err:?}"
            );
        }
    }
    #[test]
    fn parse_identifier_receipt_rejects_legacy_payload_hex() {
        let err = parse_identifier_receipt_value(json_object([
            (
                "signature",
                JsonValue::from(sample_identifier_signature_hex(
                    &sample_identifier_receipt_payload(),
                )),
            ),
            ("signature_payload_hex", JsonValue::from("01020304A0")),
        ]))
        .expect_err("opaque payload hex is not canonical receipt input");
        assert!(matches!(err, BridgeError::IdentifierReceipt));
    }
    #[test]
    fn parse_identifier_receipt_rejects_legacy_signature_payload() {
        let err = parse_identifier_receipt_value(json_object([
            (
                "signature",
                JsonValue::from(sample_identifier_signature_hex(
                    &sample_identifier_receipt_payload(),
                )),
            ),
            (
                "signature_payload",
                json_object([("policy_id", JsonValue::from("email#retail"))]),
            ),
        ]))
        .expect_err("missing execution payload must fail closed");
        assert!(matches!(err, BridgeError::IdentifierReceipt));
    }
    #[test]
    fn print_sample_claim_identifier_wire_payload_hex() {
        use iroha_crypto::Signature;
        use iroha_data_model::identifier::IdentifierResolutionReceipt;
        use iroha_data_model::isi::{Instruction, InstructionBox, identifier::ClaimIdentifier};
        let payload = sample_identifier_receipt_payload();
        let receipt = IdentifierResolutionReceipt {
            payload: payload.clone(),
            attestation: RamLfeReceiptAttestation::Signed(
                Signature::try_from_hex(sample_identifier_signature_hex(&payload))
                    .expect("valid checked signature hex"),
            ),
            phone_retail_canonicality: None,
        };
        let instruction = ClaimIdentifier {
            account: payload.account_id.clone(),
            receipt,
        };
        let bare = Instruction::dyn_encode(&instruction);
        let boxed = InstructionBox::from(instruction);
        let framed = norito::core::to_bytes(&boxed).expect("serialize instruction");
        let (wire_name, framed_payload) =
            norito::decode_from_bytes::<(String, Vec<u8>)>(&framed).expect("decode wire tuple");
        println!("RUST_CLAIM_WIRE_NAME={wire_name}");
        println!("RUST_CLAIM_BARE_HEX={}", hex::encode_upper(&bare));
        println!(
            "RUST_CLAIM_FRAMED_HEX={}",
            hex::encode_upper(framed_payload)
        );
    }
    #[test]
    fn rwa_metadata_target_parses_kind_four() {
        let literal = sample_rwa_id_literal();
        let target = parse_metadata_target(4, literal.clone()).expect("parse rwa target");
        match target {
            MetadataTarget::Rwa(id) => assert_eq!(id.to_string(), literal),
            _ => panic!("expected rwa metadata target"),
        }
    }
    #[test]
    fn rwa_metadata_target_builds_set_key_value_in_rwa_instruction_box() {
        let literal = sample_rwa_id_literal();
        let target = parse_metadata_target(4, literal.clone()).expect("parse rwa target");
        let key: Name = "serial".parse().expect("valid name");
        let instruction =
            build_set_metadata_instruction(target, key.clone(), Json::from("vault-01"));
        let rwa = instruction
            .as_any()
            .downcast_ref::<RwaInstructionBox>()
            .expect("rwa instruction box");
        match rwa {
            RwaInstructionBox::SetKeyValue(inner) => {
                assert_eq!(inner.object.to_string(), literal);
                assert_eq!(inner.key, key);
                assert_eq!(inner.value, Json::from("vault-01"));
            }
            other => panic!("expected SetKeyValue variant, got {other:?}"),
        }
    }
    #[test]
    fn rwa_metadata_target_builds_remove_key_value_in_rwa_instruction_box() {
        let literal = sample_rwa_id_literal();
        let target = parse_metadata_target(4, literal.clone()).expect("parse rwa target");
        let key: Name = "serial".parse().expect("valid name");
        let instruction = build_remove_metadata_instruction(target, key.clone());
        let rwa = instruction
            .as_any()
            .downcast_ref::<RwaInstructionBox>()
            .expect("rwa instruction box");
        match rwa {
            RwaInstructionBox::RemoveKeyValue(inner) => {
                assert_eq!(inner.object.to_string(), literal);
                assert_eq!(inner.key, key);
            }
            other => panic!("expected RemoveKeyValue variant, got {other:?}"),
        }
    }
    #[test]
    fn zk_ballot_public_inputs_canonicalizes_hex() {
        let mut map = JsonMap::new();
        let root_raw = format!("0x{}", "Aa".repeat(32));
        let nullifier_raw = format!("blake2b32:{}", "BB".repeat(32));
        map.insert("root_hint".to_owned(), JsonValue::from(root_raw));
        map.insert("nullifier".to_owned(), JsonValue::from(nullifier_raw));
        let mut value = JsonValue::Object(map);
        normalize_zk_ballot_public_inputs(&mut value).expect("normalize");
        let JsonValue::Object(map) = value else {
            panic!("normalized value must remain an object");
        };
        let root_expected = "aa".repeat(32);
        let nullifier_expected = "bb".repeat(32);
        assert_eq!(
            map.get("root_hint").and_then(JsonValue::as_str),
            Some(root_expected.as_str())
        );
        assert_eq!(
            map.get("nullifier").and_then(JsonValue::as_str),
            Some(nullifier_expected.as_str())
        );
    }
    #[test]
    fn zk_ballot_public_inputs_rejects_noncanonical_owner() {
        let domain: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
        let keypair = KeyPair::try_from_seed(vec![0xCC; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let account = AccountId::new(keypair.public_key().clone());
        let address_hex = account.to_canonical_hex().expect("canonical hex");
        let noncanonical = format!("{address_hex}@{domain}");
        let mut map = JsonMap::new();
        map.insert("owner".to_owned(), JsonValue::from(noncanonical));
        map.insert("amount".to_owned(), JsonValue::from("10"));
        map.insert("duration_blocks".to_owned(), JsonValue::from(64u64));
        let mut value = JsonValue::Object(map);
        assert!(normalize_zk_ballot_public_inputs(&mut value).is_err());
    }
    #[test]
    fn zk_ballot_public_inputs_accepts_fractional_and_wide_quantity_hints() {
        let keypair = KeyPair::try_from_seed(vec![0xCD; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let owner = AccountId::new(keypair.public_key().clone()).to_string();
        let wide = "340282366920938463463374607431768211456.25";
        for amount in ["1.25", wide] {
            let mut map = JsonMap::new();
            map.insert("owner".to_owned(), JsonValue::from(owner.clone()));
            map.insert("amount".to_owned(), JsonValue::from(amount));
            map.insert("duration_blocks".to_owned(), JsonValue::from(64_u64));
            let mut value = JsonValue::Object(map);
            normalize_zk_ballot_public_inputs(&mut value)
                .expect("canonical Quantity lock hint must normalize");
            assert_eq!(
                value
                    .as_object()
                    .and_then(|map| map.get("amount"))
                    .and_then(JsonValue::as_str),
                Some(amount)
            );
        }
    }
    #[test]
    fn zk_ballot_public_inputs_rejects_invalid_quantity_hints() {
        let keypair = KeyPair::try_from_seed(vec![0xCE; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let owner = AccountId::new(keypair.public_key().clone()).to_string();
        let oversized = format!("1{}", "0".repeat(200));
        let invalid = [
            ("negative", JsonValue::from("-1")),
            ("leading zero", JsonValue::from("01")),
            ("trailing fractional zero", JsonValue::from("1.0")),
            ("explicit plus", JsonValue::from("+1")),
            ("leading whitespace", JsonValue::from(" 1")),
            ("trailing whitespace", JsonValue::from("1 ")),
            ("exponent", JsonValue::from("1e3")),
            ("overflow", JsonValue::from(oversized)),
            ("number", JsonValue::from(1_u64)),
            ("boolean", JsonValue::from(true)),
            ("array", JsonValue::Array(Vec::new())),
            ("object", JsonValue::Object(JsonMap::new())),
        ];
        for (case, amount) in invalid {
            let mut map = JsonMap::new();
            map.insert("owner".to_owned(), JsonValue::from(owner.clone()));
            map.insert("amount".to_owned(), amount);
            map.insert("duration_blocks".to_owned(), JsonValue::from(64_u64));
            let mut value = JsonValue::Object(map);
            assert!(
                normalize_zk_ballot_public_inputs(&mut value).is_err(),
                "{case} Quantity hint must be rejected"
            );
        }
    }
    #[test]
    fn zk_ballot_public_inputs_rejects_partial_lock_hints() {
        let mut map = JsonMap::new();
        map.insert(
            "owner".to_owned(),
            JsonValue::from("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
        );
        let mut value = JsonValue::Object(map);
        assert!(normalize_zk_ballot_public_inputs(&mut value).is_err());
    }
    #[test]
    fn zk_ballot_public_inputs_rejects_non_object() {
        let mut value = JsonValue::Array(Vec::new());
        assert!(normalize_zk_ballot_public_inputs(&mut value).is_err());
    }
    #[test]
    fn zk_ballot_public_inputs_rejects_deprecated_keys() {
        let mut map = JsonMap::new();
        map.insert("nullifier_hex".to_owned(), JsonValue::from("aa".repeat(32)));
        let mut value = JsonValue::Object(map);
        assert!(normalize_zk_ballot_public_inputs(&mut value).is_err());
    }
    #[test]
    fn zk_ballot_public_inputs_rejects_invalid_hex() {
        let mut map = JsonMap::new();
        map.insert(
            "owner".to_owned(),
            JsonValue::from("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
        );
        map.insert("amount".to_owned(), JsonValue::from("100"));
        map.insert("duration_blocks".to_owned(), JsonValue::from(64u64));
        map.insert("root_hint".to_owned(), JsonValue::from("not-hex"));
        let mut value = JsonValue::Object(map);
        assert!(normalize_zk_ballot_public_inputs(&mut value).is_err());
    }
    #[test]
    fn ffi_sign_verify_ed25519() {
        let private = [0x11; 32];
        let message = b"ffi-ed25519-signing";
        let (signature, public) = sign_and_verify_roundtrip(Algorithm::Ed25519, &private, message);
        assert_eq!(public.len(), 32);
        assert_eq!(signature.len(), 64);
    }
    const SMALL_ORDER_R: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    const NONCANONICAL_R: [u8; 32] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    #[test]
    fn ffi_verify_detached_rejects_all_zero_signature_material() {
        let private = [0x11; 32];
        let message = b"ffi-ed25519-signing";
        let mut pk_ptr: *mut c_uchar = ptr::null_mut();
        let mut pk_len: c_ulong = 0;
        let rc_pk = unsafe {
            connect_norito_public_key_from_private(
                Algorithm::Ed25519 as u8,
                private.as_ptr(),
                private.len() as c_ulong,
                &mut pk_ptr,
                &mut pk_len,
            )
        };
        assert_eq!(rc_pk, 0, "public key derivation must succeed");
        let public_key = unsafe { slice::from_raw_parts(pk_ptr, pk_len as usize).to_vec() };
        connect_norito_free(pk_ptr);
        let signature = [0_u8; 64];
        let mut valid: c_uchar = 1;
        let rc_verify = unsafe {
            connect_norito_verify_detached(
                Algorithm::Ed25519 as u8,
                public_key.as_ptr(),
                public_key.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
                &mut valid,
            )
        };
        assert_eq!(
            rc_verify, 0,
            "verification call must stay fallible only for API errors"
        );
        assert_eq!(valid, 0, "malformed signature material must not verify");
    }
    #[test]
    fn ffi_verify_detached_rejects_malformed_ed25519_signature_r() {
        let private = vec![0x11; 32];
        let message = b"ffi-ed25519-malformed-r";
        let mut pk_ptr: *mut c_uchar = ptr::null_mut();
        let mut pk_len: c_ulong = 0;
        let rc_pk = unsafe {
            connect_norito_public_key_from_private(
                Algorithm::Ed25519 as u8,
                private.as_ptr(),
                private.len() as c_ulong,
                &mut pk_ptr,
                &mut pk_len,
            )
        };
        assert_eq!(rc_pk, 0, "public key derivation must succeed");
        let public_key = unsafe { slice::from_raw_parts(pk_ptr, pk_len as usize).to_vec() };
        connect_norito_free(pk_ptr);
        let key_pair =
            KeyPair::try_from_seed(private, Algorithm::Ed25519).expect("fixture keypair");
        let valid_signature = Signature::try_new(key_pair.private_key(), message)
            .expect("fixture signature")
            .payload()
            .to_vec();
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut signature = valid_signature.clone();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            let mut valid: c_uchar = 1;
            let rc_verify = unsafe {
                connect_norito_verify_detached(
                    Algorithm::Ed25519 as u8,
                    public_key.as_ptr(),
                    public_key.len() as c_ulong,
                    message.as_ptr(),
                    message.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                    &mut valid,
                )
            };
            assert_eq!(
                rc_verify, 0,
                "verification call must stay fallible only for API errors"
            );
            assert_eq!(valid, 0, "{label} Ed25519 signature R must not verify");
        }
    }
    #[test]
    fn ffi_verify_detached_rejects_weak_or_noncanonical_ed25519_public_key_material() {
        let message = b"ffi-ed25519-malformed-public-key";
        let signature = [0_u8; 64];
        for (label, public_key) in [
            ("all-zero", [0_u8; 32]),
            ("small-order", SMALL_ORDER_ED25519_PUBLIC_KEY),
            ("noncanonical", NONCANONICAL_ED25519_PUBLIC_KEY),
        ] {
            let mut valid: c_uchar = 1;
            let rc_verify = unsafe {
                connect_norito_verify_detached(
                    Algorithm::Ed25519 as u8,
                    public_key.as_ptr(),
                    public_key.len() as c_ulong,
                    message.as_ptr(),
                    message.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                    &mut valid,
                )
            };
            assert_eq!(
                rc_verify, ERR_PRIVATE_KEY_PARSE,
                "{label} Ed25519 public key must be rejected before verification"
            );
            assert_eq!(valid, 0, "{label} Ed25519 public key must clear validity");
        }
    }
    #[test]
    fn ffi_sign_verify_secp256k1() {
        let mut private = [0u8; 32];
        private[31] = 1;
        let message = b"ffi-secp256k1-signing";
        let (signature, public) =
            sign_and_verify_roundtrip(Algorithm::Secp256k1, &private, message);
        assert!(
            public.len() == 33 || public.len() == 65,
            "unexpected secp256k1 public key length {}",
            public.len()
        );
        assert_eq!(signature.len(), 64);
    }
    #[test]
    fn ffi_sign_verify_mldsa() {
        let keypair = KeyPair::try_from_seed(b"ffi-mldsa-signing".to_vec(), Algorithm::MlDsa)
            .expect("fixture seed must derive a valid ML-DSA keypair");
        let (_public_key, private_key) = keypair.into_parts();
        let (_alg, private_bytes) = private_key.to_bytes();
        let message = b"ffi-mldsa-signing";
        let (signature, public) =
            sign_and_verify_roundtrip(Algorithm::MlDsa, &private_bytes, message);
        assert!(!public.is_empty(), "ML-DSA public key must not be empty");
        assert!(!signature.is_empty(), "ML-DSA signature must not be empty");
    }
    #[test]
    fn ffi_verify_detached_rejects_malformed_mldsa_signature_lengths() {
        let keypair =
            KeyPair::try_from_seed(b"ffi-mldsa-malformed-signature".to_vec(), Algorithm::MlDsa)
                .expect("fixture seed must derive a valid ML-DSA keypair");
        let (_public_key, private_key) = keypair.into_parts();
        let (_alg, private_bytes) = private_key.to_bytes();
        let message = b"ffi-mldsa-malformed-signature";
        let (signature, public) =
            sign_and_verify_roundtrip(Algorithm::MlDsa, &private_bytes, message);
        let mut short = signature.clone();
        short.pop();
        let mut overlong = signature.clone();
        overlong.push(0x42);
        for (label, malformed) in [
            ("short", short),
            ("overlong", overlong),
            ("all-zero", vec![0_u8; signature.len()]),
        ] {
            let mut valid: c_uchar = 1;
            let rc_verify = unsafe {
                connect_norito_verify_detached(
                    Algorithm::MlDsa as u8,
                    public.as_ptr(),
                    public.len() as c_ulong,
                    message.as_ptr(),
                    message.len() as c_ulong,
                    malformed.as_ptr(),
                    malformed.len() as c_ulong,
                    &mut valid,
                )
            };
            assert_eq!(
                rc_verify, 0,
                "{label} malformed ML-DSA signature must not become an API error"
            );
            assert_eq!(
                valid, 0,
                "{label} malformed ML-DSA signature must not verify"
            );
        }
    }
    #[test]
    fn java_detached_signing_helper_signs_and_verifies() {
        let private = [0x21; 32];
        let message = b"java-helper-detached-signing";
        let algorithm = Algorithm::Ed25519 as jni::sys::jint;
        let public = java_public_key_from_private_bytes(algorithm, &private)
            .expect("Java public-key helper derives key");
        let signature = java_sign_detached_bytes(algorithm, &private, message)
            .expect("Java signing helper signs");
        assert_eq!(signature.len(), 64);
        assert!(
            java_verify_detached_bytes(algorithm, &public, message, &signature)
                .expect("Java verify helper runs"),
            "Java helper signature must verify"
        );
    }
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    #[test]
    fn java_integer_codes_rejects_u8_wrapping() {
        let algorithm = Algorithm::Ed25519 as jni::sys::jint;
        assert!(matches!(
            java_algorithm_from_code(algorithm),
            Ok(Algorithm::Ed25519)
        ));
        for invalid in [-1, algorithm + 256] {
            assert!(
                java_algorithm_from_code(invalid).is_err(),
                "algorithm code {invalid} must not alias through u8"
            );
        }
    }
    #[test]
    fn java_detached_verify_helper_rejects_malformed_mldsa_signature_lengths() {
        let keypair = KeyPair::try_from_seed(
            b"java-helper-mldsa-malformed-signature".to_vec(),
            Algorithm::MlDsa,
        )
        .expect("fixture seed must derive a valid ML-DSA keypair");
        let (_, public) = keypair
            .public_key()
            .try_to_bytes()
            .expect("checked ML-DSA public key");
        let (_alg, private) = keypair.private_key().to_bytes();
        let public = public.to_vec();
        let message = b"java-helper-mldsa-malformed-signature";
        let algorithm = Algorithm::MlDsa as jni::sys::jint;
        let signature =
            java_sign_detached_bytes(algorithm, &private, message).expect("Java helper signs");
        assert!(
            java_verify_detached_bytes(algorithm, &public, message, &signature)
                .expect("Java verify helper runs"),
            "valid ML-DSA signature must verify"
        );
        let mut short = signature.clone();
        short.pop();
        let mut overlong = signature.clone();
        overlong.push(0x42);
        for (label, malformed) in [
            ("short", short),
            ("overlong", overlong),
            ("all-zero", vec![0_u8; signature.len()]),
        ] {
            assert!(
                !java_verify_detached_bytes(algorithm, &public, message, &malformed)
                    .expect("Java verify helper runs"),
                "{label} malformed ML-DSA signature must not verify"
            );
        }
    }
    #[test]
    fn java_detached_verify_helper_rejects_all_zero_signature_material() {
        let private = [0x21; 32];
        let message = b"java-helper-detached-signing";
        let algorithm = Algorithm::Ed25519 as jni::sys::jint;
        let public = java_public_key_from_private_bytes(algorithm, &private)
            .expect("Java public-key helper derives key");
        let signature = [0_u8; 64];
        assert!(
            !java_verify_detached_bytes(algorithm, &public, message, &signature)
                .expect("Java verify helper runs"),
            "all-zero signature material must not verify"
        );
    }
    #[test]
    fn java_detached_verify_helper_rejects_weak_or_noncanonical_ed25519_public_key_material() {
        let message = b"java-helper-detached-malformed-public-key";
        let algorithm = Algorithm::Ed25519 as jni::sys::jint;
        let signature = [0_u8; 64];
        for (label, public_key) in [
            ("all-zero", [0_u8; 32]),
            ("small-order", SMALL_ORDER_ED25519_PUBLIC_KEY),
            ("noncanonical", NONCANONICAL_ED25519_PUBLIC_KEY),
        ] {
            let err = java_verify_detached_bytes(algorithm, &public_key, message, &signature)
                .expect_err("weak Ed25519 public key material must fail parsing");
            assert!(
                err.contains("invalid public key bytes"),
                "{label} Ed25519 public key produced unexpected error: {err}"
            );
        }
    }
    #[test]
    fn java_detached_verify_helper_rejects_malformed_ed25519_signature_r() {
        let private = vec![0x21; 32];
        let message = b"java-helper-detached-malformed-r";
        let algorithm = Algorithm::Ed25519 as jni::sys::jint;
        let public = java_public_key_from_private_bytes(algorithm, &private)
            .expect("Java public-key helper derives key");
        let key_pair =
            KeyPair::try_from_seed(private, Algorithm::Ed25519).expect("fixture keypair");
        let valid_signature = Signature::try_new(key_pair.private_key(), message)
            .expect("fixture signature")
            .payload()
            .to_vec();
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut signature = valid_signature.clone();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            assert!(
                !java_verify_detached_bytes(algorithm, &public, message, &signature)
                    .expect("Java verify helper runs"),
                "{label} Ed25519 signature R must not verify"
            );
        }
    }
    #[test]
    fn encode_control_approve_ext_with_alg_rejects_all_zero_signature_material() {
        let sid = [0x11_u8; 32];
        let wallet_pk = [0x22_u8; 32];
        let account = b"wallet-account";
        let algorithm = b"ed25519";
        let signature = [0_u8; 64];
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let rc = unsafe {
            connect_norito_encode_control_approve_ext_with_alg(
                sid.as_ptr(),
                1,
                7,
                wallet_pk.as_ptr(),
                account.as_ptr().cast::<c_char>(),
                account.len() as c_ulong,
                ptr::null(),
                0,
                ptr::null(),
                0,
                algorithm.as_ptr().cast::<c_char>(),
                algorithm.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        if !out_ptr.is_null() {
            connect_norito_free(out_ptr);
        }
        assert_eq!(rc, -4);
        assert_eq!(out_len, 0);
    }
    #[test]
    fn encode_control_approve_ext_with_alg_rejects_malformed_ed25519_signature_r() {
        let sid = [0x11_u8; 32];
        let wallet_pk = [0x22_u8; 32];
        let account = b"wallet-account";
        let algorithm = b"ed25519";
        let key_pair =
            KeyPair::try_from_seed(vec![0x62; 32], Algorithm::Ed25519).expect("fixture keypair");
        let valid_signature = Signature::try_new(
            key_pair.private_key(),
            b"connect approve ext with alg malformed R",
        )
        .expect("fixture signature")
        .payload()
        .to_vec();
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut signature = valid_signature.clone();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            let mut out_ptr: *mut c_uchar = ptr::null_mut();
            let mut out_len: c_ulong = 0;
            let rc = unsafe {
                connect_norito_encode_control_approve_ext_with_alg(
                    sid.as_ptr(),
                    1,
                    7,
                    wallet_pk.as_ptr(),
                    account.as_ptr().cast::<c_char>(),
                    account.len() as c_ulong,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    algorithm.as_ptr().cast::<c_char>(),
                    algorithm.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                    &mut out_ptr,
                    &mut out_len,
                )
            };
            if !out_ptr.is_null() {
                connect_norito_free(out_ptr);
            }
            assert_eq!(rc, -4, "{label} signature R must be rejected");
            assert_eq!(out_len, 0, "{label} signature R must not produce output");
        }
    }
    #[test]
    fn encode_envelope_sign_result_ok_with_alg_rejects_all_zero_signature_material() {
        let algorithm = b"ed25519";
        let signature = [0_u8; 64];
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let rc = unsafe {
            connect_norito_encode_envelope_sign_result_ok_with_alg(
                9,
                algorithm.as_ptr().cast::<c_char>(),
                algorithm.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        if !out_ptr.is_null() {
            connect_norito_free(out_ptr);
        }
        assert_eq!(rc, -2);
        assert_eq!(out_len, 0);
    }
    #[test]
    fn encode_envelope_sign_result_ok_with_alg_rejects_malformed_ed25519_signature_r() {
        let algorithm = b"ed25519";
        let key_pair =
            KeyPair::try_from_seed(vec![0x63; 32], Algorithm::Ed25519).expect("fixture keypair");
        let valid_signature = Signature::try_new(
            key_pair.private_key(),
            b"connect envelope sign result malformed R",
        )
        .expect("fixture signature")
        .payload()
        .to_vec();
        for (label, replacement_r) in [
            ("small-order", SMALL_ORDER_R),
            ("noncanonical", NONCANONICAL_R),
        ] {
            let mut signature = valid_signature.clone();
            signature[..replacement_r.len()].copy_from_slice(&replacement_r);
            let mut out_ptr: *mut c_uchar = ptr::null_mut();
            let mut out_len: c_ulong = 0;
            let rc = unsafe {
                connect_norito_encode_envelope_sign_result_ok_with_alg(
                    9,
                    algorithm.as_ptr().cast::<c_char>(),
                    algorithm.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                    &mut out_ptr,
                    &mut out_len,
                )
            };
            if !out_ptr.is_null() {
                connect_norito_free(out_ptr);
            }
            assert_eq!(rc, -2, "{label} signature R must be rejected");
            assert_eq!(out_len, 0, "{label} signature R must not produce output");
        }
    }
    #[test]
    fn connect_wallet_signature_algorithm_parser_rejects_confusables() {
        assert_eq!(
            parse_connect_wallet_signature_algorithm_label("ed25519"),
            Ok(Algorithm::Ed25519),
        );
        for algorithm in [
            " Ed25519 ",
            "Ed25519",
            "secp256k1",
            "ed\t25519",
            "ed\u{200B}25519",
            "\u{0435}d25519",
            "ed\u{FF0D}25519",
            "",
        ] {
            assert!(
                parse_connect_wallet_signature_algorithm_label(algorithm).is_err(),
                "{algorithm:?} must be rejected",
            );
        }
    }
    #[test]
    fn sm2_keypair_from_seed_private_output_derives_public_key() {
        let distid = "connect-sm2-keypair-from-seed";
        let distid_c = CString::new(distid).expect("distid c string");
        let seed = b"connect-sm2-keypair-from-seed";
        let mut private = [0_u8; 32];
        let mut public = [0_u8; 65];
        let rc = unsafe {
            connect_norito_sm2_keypair_from_seed(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                seed.as_ptr(),
                seed.len() as c_ulong,
                private.as_mut_ptr(),
                private.len() as c_ulong,
                public.as_mut_ptr(),
                public.len() as c_ulong,
            )
        };
        assert_eq!(rc, 0, "SM2 keypair derivation must succeed");
        assert!(private.iter().any(|&byte| byte != 0));
        assert!(public.iter().any(|&byte| byte != 0));
        let parsed_private =
            Sm2PrivateKey::from_bytes(distid, &private).expect("parse returned private key");
        let derived_public = parsed_private.public_key().to_sec1_bytes(false);
        assert_eq!(derived_public.as_slice(), public.as_slice());
    }
    #[test]
    fn sm2_public_key_prefixed_ffi_uses_checked_formatter() {
        let distid = "connect-sm2-prefixed";
        let private =
            Sm2PrivateKey::from_seed(distid, b"connect-sm2-prefixed-seed").expect("derive SM2 key");
        let public = private.public_key();
        let public_bytes = public.to_sec1_bytes(false);
        let distid_c = CString::new(distid).expect("distid c string");
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let rc = unsafe {
            connect_norito_sm2_public_key_prefixed(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                public_bytes.as_ptr(),
                public_bytes.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0, "SM2 prefixed formatting must succeed");
        let formatted = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        connect_norito_free(out_ptr);
        let formatted = String::from_utf8(formatted).expect("prefixed UTF-8");
        assert_eq!(
            formatted,
            public
                .try_to_prefixed_string()
                .expect("checked SM2 prefixed formatter")
        );
    }
    #[test]
    fn sm2_public_key_prefixed_ffi_rejects_zero_coordinate_material() {
        let distid = "connect-sm2-zero-coordinate-prefixed";
        let distid_c = CString::new(distid).expect("distid c string");
        let mut public_bytes = [0u8; 65];
        public_bytes[0] = 0x04;
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let rc = unsafe {
            connect_norito_sm2_public_key_prefixed(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                public_bytes.as_ptr(),
                public_bytes.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, ERR_SM2_PARSE);
        assert!(out_ptr.is_null());
        assert_eq!(out_len, 0);
    }
    #[test]
    fn sm2_sign_ffi_uses_checked_signing_and_verifies() {
        let distid = "connect-sm2-checked-signing";
        let distid_c = CString::new(distid).expect("distid c string");
        let private = Sm2PrivateKey::from_seed(distid, b"connect-sm2-checked-signing-seed")
            .expect("derive SM2 key");
        let private_bytes = private.secret_bytes();
        let public_bytes = private.public_key().to_sec1_bytes(false);
        let message = b"connect-sm2-checked-signing";
        let mut signature = [0_u8; Sm2Signature::LENGTH];
        let rc_sign = unsafe {
            connect_norito_sm2_sign(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                private_bytes.as_ptr(),
                private_bytes.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature.as_mut_ptr(),
                signature.len() as c_ulong,
            )
        };
        assert_eq!(rc_sign, 0, "SM2 checked signing must succeed");
        let rc_verify = unsafe {
            connect_norito_sm2_verify(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                public_bytes.as_ptr(),
                public_bytes.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
            )
        };
        assert_eq!(rc_verify, 1, "SM2 checked signature must verify");
        let mut tampered = signature;
        tampered[0] ^= 0xFF;
        let rc_bad = unsafe {
            connect_norito_sm2_verify(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                public_bytes.as_ptr(),
                public_bytes.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                tampered.as_ptr(),
                tampered.len() as c_ulong,
            )
        };
        assert_eq!(rc_bad, 0, "tampered SM2 signature must fail cleanly");
    }
    #[test]
    fn sm2_verify_ffi_rejects_zero_coordinate_public_key_material() {
        let distid = "connect-sm2-zero-coordinate-verify";
        let distid_c = CString::new(distid).expect("distid c string");
        let private = Sm2PrivateKey::from_seed(distid, b"connect-sm2-zero-coordinate-verify-seed")
            .expect("derive SM2 key");
        let message = b"connect-sm2-zero-coordinate-verify";
        let signature = private
            .try_sign(message)
            .expect("fixture SM2 signature")
            .to_bytes();
        let mut public_bytes = [0u8; 65];
        public_bytes[0] = 0x04;
        let rc = unsafe {
            connect_norito_sm2_verify(
                distid_c.as_ptr(),
                distid_c.as_bytes().len() as c_ulong,
                public_bytes.as_ptr(),
                public_bytes.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature.as_ptr(),
                signature.len() as c_ulong,
            )
        };
        assert_eq!(rc, ERR_SM2_PARSE);
    }
    #[test]
    fn sm2_verify_ffi_rejects_zero_scalar_signature_material() {
        let distid = "connect-sm2-zero-scalar-signature";
        let distid_c = CString::new(distid).expect("distid c string");
        let private = Sm2PrivateKey::from_seed(distid, b"connect-sm2-zero-scalar-seed")
            .expect("derive SM2 key");
        let public_bytes = private.public_key().to_sec1_bytes(false);
        let message = b"connect-sm2-zero-scalar-signature";
        let mut zero_r = [0u8; Sm2Signature::LENGTH];
        zero_r[Sm2Signature::LENGTH - 1] = 1;
        let mut zero_s = [0u8; Sm2Signature::LENGTH];
        zero_s[31] = 1;
        for (label, signature) in [
            ("all-zero", [0u8; Sm2Signature::LENGTH]),
            ("zero-r", zero_r),
            ("zero-s", zero_s),
        ] {
            let rc = unsafe {
                connect_norito_sm2_verify(
                    distid_c.as_ptr(),
                    distid_c.as_bytes().len() as c_ulong,
                    public_bytes.as_ptr(),
                    public_bytes.len() as c_ulong,
                    message.as_ptr(),
                    message.len() as c_ulong,
                    signature.as_ptr(),
                    signature.len() as c_ulong,
                )
            };
            assert_eq!(rc, ERR_SM2_PARSE, "{label} signature must fail parsing");
        }
    }
    #[test]
    fn secp256k1_helpers_expose_sign_and_verify() {
        let private =
            hex::decode("e4f21b38e005d4f895a29e84948d7cc83eac79041aeb644ee4fab8d9da42f713")
                .expect("hex decode");
        let message = b"bridge-secp256k1-roundtrip";
        let mut public_out = [0u8; SECP256K1_PUBLIC_LEN];
        let rc_public = unsafe {
            connect_norito_secp256k1_public_key(
                private.as_ptr(),
                private.len() as c_ulong,
                public_out.as_mut_ptr(),
                public_out.len() as c_ulong,
            )
        };
        assert_eq!(rc_public, 0);
        let mut signature_out = [0u8; SECP256K1_SIGNATURE_LEN];
        let rc_sign = unsafe {
            connect_norito_secp256k1_sign(
                private.as_ptr(),
                private.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature_out.as_mut_ptr(),
                signature_out.len() as c_ulong,
            )
        };
        assert_eq!(rc_sign, 0);
        let rc_verify = unsafe {
            connect_norito_secp256k1_verify(
                public_out.as_ptr(),
                public_out.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                signature_out.as_ptr(),
                signature_out.len() as c_ulong,
            )
        };
        assert_eq!(rc_verify, 1);
        let mut tampered = signature_out;
        tampered[0] ^= 0xFF;
        let rc_bad = unsafe {
            connect_norito_secp256k1_verify(
                public_out.as_ptr(),
                public_out.len() as c_ulong,
                message.as_ptr(),
                message.len() as c_ulong,
                tampered.as_ptr(),
                tampered.len() as c_ulong,
            )
        };
        assert_eq!(rc_bad, 0);
    }
    #[test]
    fn connect_encrypt_envelope_accepts_framed() {
        let key = [0x11_u8; 32];
        let session_id = [0x22_u8; 32];
        let env = proto::EnvelopeV1 {
            seq: 7,
            payload: proto::ConnectPayloadV1::Control(proto::ControlAfterKeyV1::Close {
                who: proto::Role::App,
                code: 1,
                reason: String::from("bye"),
                retryable: false,
            }),
        };
        let env_bytes = encode_envelope_framed(&env).expect("encode envelope");
        let decoded_env = decode_envelope(&env_bytes).expect("decode envelope");
        assert_eq!(decoded_env.seq, env.seq);
        assert_eq!(decoded_env.payload, env.payload);
        let direct_frame = connect_sdk::seal_envelope(
            &key,
            &session_id,
            proto::Dir::AppToWallet,
            env.seq,
            env.payload.clone(),
        );
        let direct_frame_bytes = encode_connect_frame(&direct_frame).expect("encode sealed frame");
        let decoded_direct_frame =
            decode_connect_frame(&direct_frame_bytes).expect("decode sealed frame");
        assert_eq!(decoded_direct_frame, direct_frame);
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_connect_encrypt_envelope(
                key.as_ptr(),
                session_id.as_ptr(),
                0,
                env_bytes.as_ptr(),
                env_bytes.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(status, 0);
        assert!(!out_ptr.is_null());
        let frame_bytes = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        connect_norito_free(out_ptr);
        let mut dec_ptr: *mut c_uchar = ptr::null_mut();
        let mut dec_len: c_ulong = 0;
        let status_dec = unsafe {
            connect_norito_connect_decrypt_ciphertext(
                key.as_ptr(),
                frame_bytes.as_ptr(),
                frame_bytes.len() as c_ulong,
                &mut dec_ptr,
                &mut dec_len,
            )
        };
        assert_eq!(status_dec, 0);
        assert!(!dec_ptr.is_null());
        let decrypted = unsafe { slice::from_raw_parts(dec_ptr, dec_len as usize).to_vec() };
        connect_norito_free(dec_ptr);
        let decoded = decode_envelope(&decrypted).expect("decode envelope");
        assert_eq!(decoded.seq, env.seq);
        assert_eq!(decoded.payload, env.payload);
    }
    #[test]
    fn connect_frame_roundtrip_uses_canonical_layout() {
        let frame = proto::ConnectFrameV1 {
            sid: [0xAB; 32],
            dir: proto::Dir::AppToWallet,
            seq: 5,
            kind: proto::FrameKind::Control(proto::ConnectControlV1::Ping { nonce: 55 }),
        };
        let encoded = encode_connect_frame(&frame).expect("encode frame");
        let decoded = decode_connect_frame(&encoded).expect("decode frame");
        assert_eq!(decoded, frame);
    }
    #[test]
    fn account_address_parse_render_via_ffi() {
        let key_pair = KeyPair::try_from_seed(vec![0x11; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        let account_id = AccountId::new(key_pair.public_key().clone());
        let address = AccountAddress::from_account_id(&account_id).expect("address");
        let canonical = canonical_bytes(&address);
        let i105 = address.to_i105_for_discriminant(42).expect("i105 encoding");
        let literal = CString::new(i105.clone()).expect("cstring");
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let mut prefix: u16 = 0;
        let mut err_ptr: *mut c_uchar = ptr::null_mut();
        let mut err_len: c_ulong = 0;
        let rc = unsafe {
            connect_norito_account_address_parse(
                literal.as_ptr(),
                literal.as_bytes().len() as c_ulong,
                42,
                1,
                &mut out_ptr,
                &mut out_len,
                &mut prefix,
                &mut err_ptr,
                &mut err_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(err_ptr.is_null());
        assert_eq!(prefix, 42);
        let parsed_bytes = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        assert_eq!(parsed_bytes, canonical);
        connect_norito_free(out_ptr);
        let mut hex_ptr: *mut c_uchar = ptr::null_mut();
        let mut hex_len: c_ulong = 0;
        let mut i105_ptr: *mut c_uchar = ptr::null_mut();
        let mut i105_len: c_ulong = 0;
        let mut render_err_ptr: *mut c_uchar = ptr::null_mut();
        let mut render_err_len: c_ulong = 0;
        let rc_render = unsafe {
            connect_norito_account_address_render(
                canonical.as_ptr(),
                canonical.len() as c_ulong,
                42,
                &mut hex_ptr,
                &mut hex_len,
                &mut i105_ptr,
                &mut i105_len,
                &mut render_err_ptr,
                &mut render_err_len,
            )
        };
        assert_eq!(rc_render, 0);
        assert!(render_err_ptr.is_null());
        let i105_rendered = unsafe { slice::from_raw_parts(i105_ptr, i105_len as usize) };
        assert_eq!(std::str::from_utf8(i105_rendered).unwrap(), i105);
        connect_norito_free(hex_ptr);
        connect_norito_free(i105_ptr);
        let canonical_literal =
            CString::new(address.canonical_hex().expect("canonical hex")).expect("cstring");
        let mut canonical_err_ptr: *mut c_uchar = ptr::null_mut();
        let mut canonical_err_len: c_ulong = 0;
        let mut canonical_out_ptr: *mut c_uchar = ptr::null_mut();
        let mut canonical_out_len: c_ulong = 0;
        let canonical_rc = unsafe {
            connect_norito_account_address_parse(
                canonical_literal.as_ptr(),
                canonical_literal.as_bytes().len() as c_ulong,
                0,
                0,
                &mut canonical_out_ptr,
                &mut canonical_out_len,
                &mut prefix,
                &mut canonical_err_ptr,
                &mut canonical_err_len,
            )
        };
        assert_eq!(
            canonical_rc, ERR_ACCOUNT_ADDRESS,
            "canonical hex must be rejected"
        );
        assert!(canonical_out_ptr.is_null());
        let canonical_err_value: JsonValue = unsafe {
            let bytes = slice::from_raw_parts(canonical_err_ptr, canonical_err_len as usize);
            norito::json::from_slice(bytes).expect("json")
        };
        assert_eq!(
            canonical_err_value.get("code").and_then(JsonValue::as_str),
            Some("ERR_UNSUPPORTED_ADDRESS_FORMAT")
        );
        connect_norito_free(canonical_err_ptr);
        let mut invalid_chars = i105.chars().collect::<Vec<_>>();
        let last = invalid_chars.len().saturating_sub(1);
        invalid_chars[last] = '0';
        let invalid_i105 = invalid_chars.into_iter().collect::<String>();
        let invalid_literal = CString::new(invalid_i105).expect("cstring");
        let mut invalid_err_ptr: *mut c_uchar = ptr::null_mut();
        let mut invalid_err_len: c_ulong = 0;
        let mut invalid_out_ptr: *mut c_uchar = ptr::null_mut();
        let mut invalid_out_len: c_ulong = 0;
        let invalid_rc = unsafe {
            connect_norito_account_address_parse(
                invalid_literal.as_ptr(),
                invalid_literal.as_bytes().len() as c_ulong,
                42,
                1,
                &mut invalid_out_ptr,
                &mut invalid_out_len,
                &mut prefix,
                &mut invalid_err_ptr,
                &mut invalid_err_len,
            )
        };
        assert_eq!(invalid_rc, ERR_ACCOUNT_ADDRESS);
        assert!(invalid_out_ptr.is_null());
        let invalid_err_value: JsonValue = unsafe {
            let bytes = slice::from_raw_parts(invalid_err_ptr, invalid_err_len as usize);
            norito::json::from_slice(bytes).expect("json")
        };
        assert_eq!(
            invalid_err_value.get("code").and_then(JsonValue::as_str),
            Some("ERR_INVALID_I105_CHAR")
        );
        assert_eq!(
            invalid_err_value
                .get("fields")
                .and_then(JsonValue::as_object)
                .and_then(|fields| fields.get("char"))
                .and_then(JsonValue::as_str),
            Some("0")
        );
        connect_norito_free(invalid_err_ptr);
        let invalid = CString::new("").expect("empty literal");
        let mut err_out_ptr: *mut c_uchar = ptr::null_mut();
        let mut err_out_len: c_ulong = 0;
        out_ptr = ptr::null_mut();
        out_len = 0;
        let rc_err = unsafe {
            connect_norito_account_address_parse(
                invalid.as_ptr(),
                invalid.as_bytes().len() as c_ulong,
                0,
                0,
                &mut out_ptr,
                &mut out_len,
                &mut prefix,
                &mut err_out_ptr,
                &mut err_out_len,
            )
        };
        assert_eq!(rc_err, ERR_ACCOUNT_ADDRESS);
        assert!(out_ptr.is_null());
        let err_value: JsonValue = unsafe {
            let bytes = slice::from_raw_parts(err_out_ptr, err_out_len as usize);
            norito::json::from_slice(bytes).expect("json")
        };
        assert_eq!(
            err_value.get("code").and_then(JsonValue::as_str),
            Some("ERR_INVALID_LENGTH")
        );
        connect_norito_free(err_out_ptr);
    }
    static ACCELERATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn acceleration_resource_limits_defaults_and_zero_roundtrip() {
        let defaults = connect_norito_acceleration_config::default();
        assert_eq!(defaults.enable_cuda, 1);
        assert_eq!(
            decode_acceleration_config(&defaults)
                .unwrap()
                .resource_limits,
            iroha_accel::RegistryLimits::STANDARD
        );
        let zero = connect_norito_acceleration_resource_limits {
            host_bytes: 0,
            pinned_bytes: 0,
            device_bytes: 0,
            in_flight: 0,
            metadata_bytes: 0,
            observed_devices: 0,
            discovery_ordinals: 0,
            modules: 0,
            streams: 0,
            artifact_bytes: 0,
        };
        assert_eq!(
            encode_acceleration_resource_limits(decode_acceleration_resource_limits(zero).unwrap()),
            zero
        );
    }

    #[test]
    fn malformed_acceleration_record_is_rejected_before_configuration_mutation() {
        let _guard = ACCELERATION_TEST_LOCK
            .lock()
            .expect("acceleration test lock");
        let original = ivm::acceleration_config();
        let mut bad = encode_acceleration_config(original);
        bad.resource_limits.discovery_ordinals = u64::from(u32::MAX) + 1;
        assert!(decode_acceleration_config(&bad).is_err());
        assert_eq!(
            unsafe { connect_norito_acceleration_config_set_v1(&bad, std::mem::size_of_val(&bad)) },
            -2
        );
        assert_eq!(
            ivm::acceleration_config().resource_limits,
            original.resource_limits
        );
        bad = encode_acceleration_config(original);
        bad.enable_cuda = 2;
        assert!(decode_acceleration_config(&bad).is_err());
        bad = encode_acceleration_config(original);
        bad.max_gpus_present = 0;
        bad.max_gpus = 1;
        assert!(decode_acceleration_config(&bad).is_err());
        bad.max_gpus_present = 2;
        assert!(decode_acceleration_config(&bad).is_err());
    }

    #[test]
    fn acceleration_rejects_retired_or_truncated_record_sizes_before_access() {
        let config = connect_norito_acceleration_config::default();
        for wrong_size in [
            0,
            104,
            std::mem::size_of_val(&config) - 1,
            std::mem::size_of_val(&config) + 1,
        ] {
            assert_eq!(
                unsafe { connect_norito_acceleration_config_set_v1(&config, wrong_size) },
                -3
            );
            let mut bytes = [0xA5u8; std::mem::size_of::<connect_norito_acceleration_config>()];
            assert_eq!(
                unsafe {
                    connect_norito_acceleration_config_get_v1(bytes.as_mut_ptr().cast(), wrong_size)
                },
                -3
            );
            assert!(bytes.iter().all(|&byte| byte == 0xA5));
        }
        let mut bytes = [0x5Au8; std::mem::size_of::<connect_norito_acceleration_state>()];
        for wrong_size in [0, 176, bytes.len() - 1, bytes.len() + 1] {
            assert_eq!(
                unsafe {
                    connect_norito_acceleration_state_get_v1(bytes.as_mut_ptr().cast(), wrong_size)
                },
                -3
            );
            assert!(bytes.iter().all(|&byte| byte == 0x5A));
        }
        assert_eq!(
            unsafe {
                connect_norito_acceleration_config_set_v1(
                    std::ptr::null(),
                    std::mem::size_of_val(&config),
                )
            },
            -3
        );
    }

    #[test]
    fn acceleration_config_roundtrip() {
        let _guard = ACCELERATION_TEST_LOCK
            .lock()
            .expect("acceleration test lock");
        let previous = ivm::acceleration_config();
        let _reset = ResetConfig(previous);
        let new_cfg = connect_norito_acceleration_config {
            enable_simd: 1,
            enable_metal: 1,
            enable_cuda: 0,
            max_gpus: 2,
            max_gpus_present: 1,
            merkle_min_leaves_gpu: 128,
            merkle_min_leaves_gpu_present: 1,
            merkle_min_leaves_metal: 64,
            merkle_min_leaves_metal_present: 1,
            merkle_min_leaves_cuda: 0,
            merkle_min_leaves_cuda_present: 0,
            prefer_cpu_sha2_max_leaves_aarch64: 0,
            prefer_cpu_sha2_max_leaves_aarch64_present: 0,
            prefer_cpu_sha2_max_leaves_x86: 256,
            prefer_cpu_sha2_max_leaves_x86_present: 1,
            resource_limits: connect_norito_acceleration_resource_limits {
                host_bytes: 71,
                pinned_bytes: 79,
                device_bytes: 83,
                in_flight: 2,
                metadata_bytes: 1024 * 1024,
                observed_devices: 16,
                discovery_ordinals: 47,
                modules: 19,
                streams: 3,
                artifact_bytes: 89,
            },
        };
        unsafe {
            assert_eq!(
                connect_norito_acceleration_config_set_v1(
                    &new_cfg,
                    std::mem::size_of_val(&new_cfg)
                ),
                0
            );
        }
        let mut out_cfg = MaybeUninit::<connect_norito_acceleration_config>::uninit();
        let rc = unsafe {
            connect_norito_acceleration_config_get_v1(
                out_cfg.as_mut_ptr(),
                std::mem::size_of::<connect_norito_acceleration_config>(),
            )
        };
        assert_eq!(rc, 0);
        let out_cfg = unsafe { out_cfg.assume_init() };
        assert_eq!(out_cfg.resource_limits, new_cfg.resource_limits);
        assert_eq!(out_cfg.enable_metal, new_cfg.enable_metal);
        assert_eq!(out_cfg.enable_cuda, new_cfg.enable_cuda);
        assert_eq!(out_cfg.enable_simd, new_cfg.enable_simd);
        assert_eq!(out_cfg.max_gpus, new_cfg.max_gpus);
        assert_eq!(out_cfg.max_gpus_present, new_cfg.max_gpus_present);
        assert_eq!(out_cfg.merkle_min_leaves_gpu, new_cfg.merkle_min_leaves_gpu);
        assert_eq!(
            out_cfg.merkle_min_leaves_gpu_present,
            new_cfg.merkle_min_leaves_gpu_present
        );
        assert_eq!(
            out_cfg.merkle_min_leaves_metal,
            new_cfg.merkle_min_leaves_metal
        );
        assert_eq!(
            out_cfg.merkle_min_leaves_metal_present,
            new_cfg.merkle_min_leaves_metal_present
        );
        assert_eq!(
            out_cfg.merkle_min_leaves_cuda,
            new_cfg.merkle_min_leaves_cuda
        );
        assert_eq!(
            out_cfg.merkle_min_leaves_cuda_present,
            new_cfg.merkle_min_leaves_cuda_present
        );
        assert_eq!(
            out_cfg.prefer_cpu_sha2_max_leaves_aarch64,
            new_cfg.prefer_cpu_sha2_max_leaves_aarch64
        );
        assert_eq!(
            out_cfg.prefer_cpu_sha2_max_leaves_aarch64_present,
            new_cfg.prefer_cpu_sha2_max_leaves_aarch64_present
        );
        assert_eq!(
            out_cfg.prefer_cpu_sha2_max_leaves_x86,
            new_cfg.prefer_cpu_sha2_max_leaves_x86
        );
        assert_eq!(
            out_cfg.prefer_cpu_sha2_max_leaves_x86_present,
            new_cfg.prefer_cpu_sha2_max_leaves_x86_present
        );
        let rc_err = unsafe {
            connect_norito_acceleration_config_get_v1(
                std::ptr::null_mut(),
                std::mem::size_of::<connect_norito_acceleration_config>(),
            )
        };
        assert_eq!(rc_err, -1);
    }
    #[test]
    fn blake3_hash_via_ffi() {
        let payload = b"da-ingest";
        let mut out_ptr: *mut c_uchar = ptr::null_mut();
        let mut out_len: c_ulong = 0;
        let status = unsafe {
            connect_norito_blake3_hash(
                payload.as_ptr(),
                payload.len() as c_ulong,
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(status, 0, "expected success hashing payload");
        assert_eq!(out_len as usize, blake3_hash(payload).as_bytes().len());
        let digest = unsafe { slice::from_raw_parts(out_ptr, out_len as usize).to_vec() };
        assert_eq!(digest, blake3_hash(payload).as_bytes());
        unsafe {
            if !out_ptr.is_null() {
                free(out_ptr as *mut c_void);
            }
        }
    }
}
include!("bridge_tail_tests.rs");
include!("sorafs_tests.rs");

#[cfg(test)]
mod native_execution_capture_tests;

fn multisig_proposal_id_from_json(input: &[u8]) -> BridgeResult<Vec<u8>> {
    let text = std::str::from_utf8(input).map_err(|_| BridgeError::Utf8)?;
    iroha_js_codec::derive_multisig_proposal_id_json(text)
        .map(String::into_bytes).map_err(|_| BridgeError::CanonicalJson)
}
/// Derive the exact proposal occurrence ID; free output with `connect_norito_free`.
///
/// # Safety
/// Input must reference `input_len` readable bytes; output pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_multisig_proposal_id(
    input_ptr: *const c_uchar, input_len: c_ulong,
    out_ptr: *mut *mut c_uchar, out_len: *mut c_ulong,
) -> c_int {
    clear_bridge_output(out_ptr, out_len);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        clear_bridge_output_or_null(out_ptr, out_len)?;
        let length = usize::try_from(input_len).map_err(|_| BridgeError::CanonicalJson)?;
        if input_ptr.is_null() || length == 0 || length > 4096 { return Err(BridgeError::CanonicalJson); }
        let input = unsafe { slice::from_raw_parts(input_ptr, length) };
        let bytes = multisig_proposal_id_from_json(input)?;
        unsafe { write_bytes_bridge(out_ptr, out_len, &bytes) }
    }));
    result.map_or_else(|_| BridgeError::CanonicalJson.code(), bridge_result_to_code)
}
